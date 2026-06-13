/*
 * HTTP/3 (QUIC) protocol for FFmpeg.
 *
 * Copyright (c) 2026 Simon Christ
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 */

/*
 * QUIC transport (ngtcp2) + HTTP/3 client (nghttp3): seekable GETs with Range,
 * response-status handling and redirect following. The TLS crypto backend
 * follows FFmpeg's TLS selection: GnuTLS with --enable-gnutls, otherwise the
 * OpenSSL-family helper -- BoringSSL (OPENSSL_IS_BORINGSSL, the iOS/mobile
 * path) or OpenSSL 3.5+ native QUIC (the ossl helper). All three verified.
 *
 * Connection vs request split: the QUIC/H3 connection lives in a heap H3Conn
 * (stable address — ngtcp2/nghttp3/the TLS lib store a pointer to it as their
 * user_data, and there is no set_user_data to retarget after creation). The
 * per-URLContext request state lives in HTTP3Context; H3Conn->cur points at the
 * request that currently owns the connection. That indirection is what lets a
 * connection be parked in a process-global pool and reused by a later
 * URLContext (e.g. consecutive HLS segments on the same host) without paying a
 * fresh QUIC handshake.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

/* QUIC needs a TLS library with a QUIC interface. The crypto backend follows
   FFmpeg's own TLS selection: --enable-gnutls -> GnuTLS, otherwise the
   OpenSSL-family path (validated against BoringSSL, which is the only
   OpenSSL-API TLS with a QUIC interface usable on e.g. iOS). quictls/OpenSSL
   3.5 native QUIC is a documented follow-up. */
#if CONFIG_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#if defined(OPENSSL_IS_BORINGSSL)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#else
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#endif
#endif
#if defined(__APPLE__)
#include <ctype.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#endif
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>

#include "libavutil/avstring.h"
#include "libavutil/base64.h"
#include "libavutil/error.h"
#include "libavutil/log.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/thread.h"
#include "libavutil/time.h"
#include "avformat.h"
#include "url.h"

#define H3_ALPN  "h3"
#define H3_DGRAM 65536

typedef struct HTTP3Context HTTP3Context;

/* Connection-level, poolable, stable heap address. */
typedef struct H3Conn {
    int fd;
    ngtcp2_conn *conn;
    nghttp3_conn *h3conn;
    ngtcp2_crypto_conn_ref conn_ref;
#if CONFIG_GNUTLS
    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;
#else
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#if !defined(OPENSSL_IS_BORINGSSL)
    ngtcp2_crypto_ossl_ctx *ossl_ctx;   /* OpenSSL 3.5 native QUIC */
#endif
#endif

    struct sockaddr_storage local_addr, remote_addr;
    socklen_t local_addrlen, remote_addrlen;
    uint8_t sr_secret[32];

    char host[1024];
    char vhost[1024];      /* host to verify the cert name against */
    char ca_file[1024];    /* extra CA anchor file (PEM), "" if none */
    int  port;

    HTTP3Context *cur; /* request currently driving this connection */
} H3Conn;

/* native TLS handle ngtcp2 drives, per backend */
#if CONFIG_GNUTLS
#define H3_TLS_HANDLE(hc) ((hc)->session)
#elif defined(OPENSSL_IS_BORINGSSL)
#define H3_TLS_HANDLE(hc) ((hc)->ssl)
#else
#define H3_TLS_HANDLE(hc) ((hc)->ossl_ctx)
#endif

#if !CONFIG_GNUTLS && !defined(OPENSSL_IS_BORINGSSL)
static AVOnce h3_ossl_once = AV_ONCE_INIT;
static void h3_ossl_global_init(void) { ngtcp2_crypto_ossl_init(); }
#endif

/* Per-URLContext request state. */
struct HTTP3Context {
    const AVClass *class;
    H3Conn *hc;

    char path[2048];

    int64_t stream_id;
    int     stream_done;
    int     status;
    int     headers_done;
    char    location[2048];

    int64_t off;
    int64_t filesize;

    unsigned char *rb;
    size_t rb_size, rb_len, rb_off;
    size_t total_recv;

    int64_t open_timeout_us;
    int altsvc;            /* AVOption: discover h3 via Alt-Svc before connecting */
    int tls_verify;        /* AVOption: verify the server certificate (default on) */
    char *ca_file;         /* AVOption: extra CA bundle (PEM) */
    char *verifyhost;      /* AVOption: cert name to verify against */
};

/* ---- connection pool (host-keyed, N slots, FIFO eviction) ---- */

#define H3_POOL_MAX 8
static AVMutex h3_pool_mutex = AV_MUTEX_INITIALIZER;
static H3Conn *h3_pool[H3_POOL_MAX];

/* ---- helpers ---- */

static uint64_t h3_timestamp(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * NGTCP2_SECONDS + (uint64_t)t.tv_nsec;
}

static ngtcp2_conn *h3_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return ((H3Conn *)ref->user_data)->conn;
}

/* backend-neutral CSPRNG; 0 on success, <0 on failure */
static int h3_random(uint8_t *dst, size_t len)
{
#if CONFIG_GNUTLS
    return gnutls_rnd(GNUTLS_RND_RANDOM, dst, len) == 0 ? 0 : -1;
#else
    return RAND_bytes(dst, len) == 1 ? 0 : -1;
#endif
}

static int h3_buf_append(HTTP3Context *c, const uint8_t *data, size_t len)
{
    if (c->rb_len + len > c->rb_size) {
        size_t ns = FFMAX(c->rb_size * 2, c->rb_len + len);
        unsigned char *nb = av_realloc(c->rb, ns);
        if (!nb)
            return AVERROR(ENOMEM);
        c->rb = nb;
        c->rb_size = ns;
    }
    memcpy(c->rb + c->rb_len, data, len);
    c->rb_len += len;
    c->total_recv += len;
    return 0;
}

/* ---- ngtcp2 callbacks (user_data = H3Conn*) ---- */

static void h3_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
    h3_random(dest, destlen);
}

static int h3_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                             size_t cidlen, void *user_data)
{
    H3Conn *hc = user_data;
    if (h3_random(cid->data, cidlen) < 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, hc->sr_secret, sizeof(hc->sr_secret), cid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int h3_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                  int64_t stream_id, uint64_t offset,
                                  const uint8_t *data, size_t datalen,
                                  void *user_data, void *stream_user_data)
{
    H3Conn *hc = user_data;
    nghttp3_ssize n;
    if (!hc->h3conn)
        return 0;
    n = nghttp3_conn_read_stream(hc->h3conn, stream_id, data, datalen,
                                 flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    if (n < 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, (uint64_t)n);
    ngtcp2_conn_extend_max_offset(conn, (uint64_t)n);
    return 0;
}

static int h3_acked_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
                                   uint64_t offset, uint64_t datalen,
                                   void *user_data, void *stream_user_data)
{
    H3Conn *hc = user_data;
    if (hc->h3conn)
        nghttp3_conn_add_ack_offset(hc->h3conn, stream_id, datalen);
    return 0;
}

static int h3_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                              int64_t stream_id, uint64_t app_error_code,
                              void *user_data, void *stream_user_data)
{
    H3Conn *hc = user_data;
    if (hc->h3conn) {
        if (!app_error_code)
            app_error_code = NGHTTP3_H3_NO_ERROR;
        nghttp3_conn_close_stream(hc->h3conn, stream_id, app_error_code);
    }
    if (hc->cur && stream_id == hc->cur->stream_id)
        hc->cur->stream_done = 1;
    return 0;
}

static int h3_extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
                                        uint64_t max_data, void *user_data,
                                        void *stream_user_data)
{
    H3Conn *hc = user_data;
    if (hc->h3conn)
        nghttp3_conn_unblock_stream(hc->h3conn, stream_id);
    return 0;
}

/* ---- nghttp3 callbacks (user_data = H3Conn*) ---- */

static int h3_http_recv_data_cb(nghttp3_conn *conn, int64_t stream_id,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    H3Conn *hc = user_data;
    HTTP3Context *c = hc->cur;
    if (!c || stream_id != c->stream_id)
        return 0;
    return h3_buf_append(c, data, datalen) < 0 ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int h3_recv_header_cb(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                             nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
    H3Conn *hc = user_data;
    HTTP3Context *c = hc->cur;
    nghttp3_vec n, v;
    char vb[2048];
    size_t vn;

    if (!c || stream_id != c->stream_id)
        return 0;
    n = nghttp3_rcbuf_get_buf(name);
    v = nghttp3_rcbuf_get_buf(value);
    vn = FFMIN(v.len, sizeof(vb) - 1);
    memcpy(vb, v.base, vn);
    vb[vn] = 0;

    if (n.len == 7 && !av_strncasecmp((const char *)n.base, ":status", 7))
        c->status = atoi(vb);
    else if (n.len == 8 && !av_strncasecmp((const char *)n.base, "location", 8))
        av_strlcpy(c->location, vb, sizeof(c->location));
    else if (n.len == 13 && !av_strncasecmp((const char *)n.base, "content-range", 13)) {
        char *slash = strchr(vb, '/');
        if (slash && slash[1] && slash[1] != '*')
            c->filesize = strtoll(slash + 1, NULL, 10);
    } else if (n.len == 14 && !av_strncasecmp((const char *)n.base, "content-length", 14)) {
        if (c->status == 200)
            c->filesize = strtoll(vb, NULL, 10);
    }
    return 0;
}

static int h3_end_headers_cb(nghttp3_conn *conn, int64_t stream_id, int fin,
                             void *user_data, void *stream_user_data)
{
    H3Conn *hc = user_data;
    if (hc->cur && stream_id == hc->cur->stream_id)
        hc->cur->headers_done = 1;
    return 0;
}

/* ---- connection bring-up ---- */

#if CONFIG_GNUTLS && defined(__APPLE__)
/* Verify the peer's DER certificate chain against the system keychain via
   SecTrust. On iOS there is no /etc/ssl/certs nor SSL_CERT_FILE, so this is
   how the chain (incl. a user-trusted local CA) is validated. */
/* Load PEM CA certificates from a file into a CFArray of SecCertificateRef
   for use as extra SecTrust anchors. iOS has no SecItemImport, so parse the
   PEM blocks ourselves and base64-decode each to DER. NULL on empty/error. */
static CFArrayRef h3_apple_load_anchors(const char *path)
{
    static const char *BEG = "-----BEGIN CERTIFICATE-----";
    static const char *END = "-----END CERTIFICATE-----";
    CFMutableArrayRef arr;
    char *buf, *p;
    long sz;
    FILE *f = fopen(path, "rb");

    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    buf = av_malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    sz = fread(buf, 1, sz, f);
    fclose(f);
    buf[sz] = 0;

    arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    p = buf;
    while ((p = strstr(p, BEG))) {
        char *end = strstr(p += strlen(BEG), END);
        int blen, j = 0, dl, i;
        char *b64; uint8_t *der;
        if (!end)
            break;
        blen = (int)(end - p);
        b64 = av_malloc(blen + 1);
        der = av_malloc(blen);
        if (b64 && der) {
            for (i = 0; i < blen; i++)
                if (!isspace((unsigned char)p[i]))
                    b64[j++] = p[i];
            b64[j] = 0;
            dl = av_base64_decode(der, b64, blen);
            if (dl > 0) {
                CFDataRef d = CFDataCreate(NULL, der, dl);
                SecCertificateRef cert = d ? SecCertificateCreateWithData(NULL, d) : NULL;
                if (d) CFRelease(d);
                if (cert) { CFArrayAppendValue(arr, cert); CFRelease(cert); }
            }
        }
        av_free(b64); av_free(der);
        p = end + strlen(END);
    }
    av_free(buf);
    if (CFArrayGetCount(arr) == 0) { CFRelease(arr); return NULL; }
    return arr;
}

static int h3_apple_verify(const uint8_t **der, const size_t *der_len,
                           size_t n, const char *host, const char *ca_file)
{
    CFMutableArrayRef certs;
    CFStringRef cfhost;
    SecPolicyRef policy;
    SecTrustRef trust = NULL;
    OSStatus st;
    bool ok;
    size_t i;

    if (!n)
        return -1;
    certs = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
    if (!certs)
        return -1;
    for (i = 0; i < n; i++) {
        CFDataRef d = CFDataCreate(NULL, der[i], der_len[i]);
        SecCertificateRef c = d ? SecCertificateCreateWithData(NULL, d) : NULL;
        if (d)
            CFRelease(d);
        if (!c) {
            CFRelease(certs);
            return -1;
        }
        CFArrayAppendValue(certs, c);
        CFRelease(c);
    }
    cfhost = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    policy = SecPolicyCreateSSL(true, cfhost);
    if (cfhost)
        CFRelease(cfhost);
    st = SecTrustCreateWithCertificates(certs, policy, &trust);
    if (policy)
        CFRelease(policy);
    CFRelease(certs);
    if (st != errSecSuccess || !trust) {
        if (trust)
            CFRelease(trust);
        return -1;
    }
    if (ca_file && *ca_file) {
        CFArrayRef anchors = h3_apple_load_anchors(ca_file);
        if (anchors) {
            SecTrustSetAnchorCertificates(trust, anchors);
            /* keep the system anchors in addition to ours */
            SecTrustSetAnchorCertificatesOnly(trust, false);
            CFRelease(anchors);
        }
    }
    ok = SecTrustEvaluateWithError(trust, NULL);
    CFRelease(trust);
    return ok ? 0 : -1;
}

/* gnutls per-session verify hook: pull the peer DER chain and hand it to
   SecTrust (replaces gnutls_session_set_verify_cert on Apple). */
static int h3_gnutls_verify(gnutls_session_t session)
{
    ngtcp2_crypto_conn_ref *ref = gnutls_session_get_ptr(session);
    H3Conn *hc = ref ? ref->user_data : NULL;
    const gnutls_datum_t *peers;
    const uint8_t *der[16];
    size_t len[16];
    unsigned int n = 0, i;

    peers = gnutls_certificate_get_peers(session, &n);
    if (!hc || !peers || !n)
        return GNUTLS_E_CERTIFICATE_ERROR;
    if (n > 16)
        n = 16;
    for (i = 0; i < n; i++) {
        der[i] = peers[i].data;
        len[i] = peers[i].size;
    }
    return h3_apple_verify(der, len, n, hc->vhost, hc->ca_file) == 0
               ? 0 : GNUTLS_E_CERTIFICATE_ERROR;
}
#endif

static int h3_init_tls(URLContext *h, H3Conn *hc, const char *host)
{
    HTTP3Context *c = h->priv_data;
    int verify = c->tls_verify;
    const char *vhost = c->verifyhost && *c->verifyhost ? c->verifyhost : host;

    hc->conn_ref.get_conn  = h3_get_conn;
    hc->conn_ref.user_data = hc;
    av_strlcpy(hc->vhost, vhost, sizeof(hc->vhost));
    av_strlcpy(hc->ca_file, c->ca_file ? c->ca_file : "", sizeof(hc->ca_file));

#if CONFIG_GNUTLS
    {
        int rv;
        /* TLS 1.3 only, QUIC-compatible cipher/group set */
        static const char priority[] =
            "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:"
            "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:"
            "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1:"
            "+GROUP-X25519:+GROUP-X448";
        gnutls_datum_t alpn = { (unsigned char *)H3_ALPN, sizeof(H3_ALPN) - 1 };

        if (gnutls_certificate_allocate_credentials(&hc->cred) != 0)
            return AVERROR_EXTERNAL;
        gnutls_certificate_set_x509_system_trust(hc->cred);

        if (gnutls_init(&hc->session, GNUTLS_CLIENT) != 0)
            return AVERROR_EXTERNAL;
        if ((rv = gnutls_priority_set_direct(hc->session, priority, NULL)) != 0) {
            av_log(h, AV_LOG_ERROR, "gnutls priority: %s\n", gnutls_strerror(rv));
            return AVERROR_EXTERNAL;
        }
        if (ngtcp2_crypto_gnutls_configure_client_session(hc->session) != 0)
            return AVERROR_EXTERNAL;

        gnutls_session_set_ptr(hc->session, &hc->conn_ref);
        if (gnutls_credentials_set(hc->session, GNUTLS_CRD_CERTIFICATE, hc->cred) != 0)
            return AVERROR_EXTERNAL;
        gnutls_alpn_set_protocols(hc->session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
        gnutls_server_name_set(hc->session, GNUTLS_NAME_DNS, host, strlen(host)); /* SNI */
        /* verify the server cert chain + match the hostname; the handshake
           fails on an invalid/mismatched cert. */
        if (verify) {
            if (c->ca_file && *c->ca_file)
                gnutls_certificate_set_x509_trust_file(hc->cred, c->ca_file,
                                                       GNUTLS_X509_FMT_PEM);
#if defined(__APPLE__)
            /* validate via SecTrust (system keychain + optional ca_file anchor) */
            gnutls_session_set_verify_function(hc->session, h3_gnutls_verify);
#else
            gnutls_session_set_verify_cert(hc->session, vhost, 0);
#endif
        }
    }
#else
    {
        static const uint8_t alpn[] = { 2, 'h', '3' }; /* wire format: len + "h3" */

        hc->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!hc->ssl_ctx)
            return AVERROR_EXTERNAL;
#if defined(OPENSSL_IS_BORINGSSL)
        if (ngtcp2_crypto_boringssl_configure_client_context(hc->ssl_ctx) != 0)
            return AVERROR_EXTERNAL;
#endif
        SSL_CTX_set_default_verify_paths(hc->ssl_ctx); /* system trust store */
#if !defined(OPENSSL_IS_BORINGSSL)
        /* OpenSSL 3.5 has no ngtcp2 *context* configure (unlike BoringSSL);
           set the QUIC-compatible TLS 1.3 ciphersuites + key-exchange groups
           the ossl helper expects, or the handshake fails with ERR_CRYPTO. */
        if (SSL_CTX_set_ciphersuites(hc->ssl_ctx,
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256") != 1 ||
            SSL_CTX_set1_groups_list(hc->ssl_ctx,
                "X25519:P-256:P-384:P-521:X25519MLKEM768") != 1)
            return AVERROR_EXTERNAL;
#endif

        hc->ssl = SSL_new(hc->ssl_ctx);
        if (!hc->ssl)
            return AVERROR_EXTERNAL;

#if !defined(OPENSSL_IS_BORINGSSL)
        /* OpenSSL 3.5 native QUIC: per-session crypto ctx bound to the SSL */
        ff_thread_once(&h3_ossl_once, h3_ossl_global_init);
        if (ngtcp2_crypto_ossl_ctx_new(&hc->ossl_ctx, NULL) != 0)
            return AVERROR_EXTERNAL;
        ngtcp2_crypto_ossl_ctx_set_ssl(hc->ossl_ctx, hc->ssl);
        if (ngtcp2_crypto_ossl_configure_client_session(hc->ssl) != 0)
            return AVERROR_EXTERNAL;
#endif

        SSL_set_app_data(hc->ssl, &hc->conn_ref); /* crypto helper finds the conn here */
        SSL_set_connect_state(hc->ssl);
        SSL_set_alpn_protos(hc->ssl, alpn, sizeof(alpn));
        SSL_set_tlsext_host_name(hc->ssl, host);  /* SNI */
        /* verify the server cert chain + match the hostname; the handshake
           fails on an invalid/mismatched cert. */
        SSL_set_verify(hc->ssl, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
        if (verify) {
            if (c->ca_file && *c->ca_file)
                SSL_CTX_load_verify_locations(hc->ssl_ctx, c->ca_file, NULL);
            SSL_set1_host(hc->ssl, vhost);
        }
    }
#endif
    return 0;
}

static int h3_connect_udp(URLContext *h, H3Conn *hc, const char *host, const char *port)
{
    struct addrinfo hints = { 0 }, *res = NULL, *ai;
    int fd = -1, rv;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if ((rv = getaddrinfo(host, port, &hints, &res)) != 0) {
        av_log(h, AV_LOG_ERROR, "getaddrinfo(%s:%s): %s\n", host, port, gai_strerror(rv));
        return AVERROR(EIO);
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            memcpy(&hc->remote_addr, ai->ai_addr, ai->ai_addrlen);
            hc->remote_addrlen = ai->ai_addrlen;
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return AVERROR(EIO);
    hc->local_addrlen = sizeof(hc->local_addr);
    getsockname(fd, (struct sockaddr *)&hc->local_addr, &hc->local_addrlen);
    hc->fd = fd;
    return 0;
}

static int h3_init_quic(URLContext *h, H3Conn *hc)
{
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid scid, dcid;
    ngtcp2_path path;
    int rv;

    static const ngtcp2_callbacks callbacks = {
        .client_initial           = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt                  = ngtcp2_crypto_encrypt_cb,
        .decrypt                  = ngtcp2_crypto_decrypt_cb,
        .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
        .recv_retry               = ngtcp2_crypto_recv_retry_cb,
        .update_key               = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
        .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
        .rand                     = h3_rand_cb,
        .get_new_connection_id    = h3_get_new_cid_cb,
        .recv_stream_data         = h3_recv_stream_data_cb,
        .acked_stream_data_offset = h3_acked_stream_data_cb,
        .stream_close             = h3_stream_close_cb,
        .extend_max_stream_data   = h3_extend_max_stream_data_cb,
    };

    h3_random(hc->sr_secret, sizeof(hc->sr_secret));
    scid.datalen = 17;
    h3_random(scid.data, scid.datalen);
    dcid.datalen = 18;
    h3_random(dcid.data, dcid.datalen);

    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni            = 3;
    params.initial_max_stream_data_bidi_local = 1024 * 1024;
    params.initial_max_stream_data_uni        = 256 * 1024;
    params.initial_max_data                   = 8 * 1024 * 1024;
    params.max_idle_timeout                   = 30 * NGTCP2_SECONDS;
    params.active_connection_id_limit         = 7;

    path.local.addr     = (struct sockaddr *)&hc->local_addr;
    path.local.addrlen  = hc->local_addrlen;
    path.remote.addr    = (struct sockaddr *)&hc->remote_addr;
    path.remote.addrlen = hc->remote_addrlen;
    path.user_data      = NULL;

    rv = ngtcp2_conn_client_new(&hc->conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1, &callbacks,
                                &settings, &params, NULL, hc);
    if (rv != 0) {
        av_log(h, AV_LOG_ERROR, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    ngtcp2_conn_set_tls_native_handle(hc->conn, H3_TLS_HANDLE(hc));
    /* let ngtcp2 emit keep-alive packets once idle 15s; the pool reaper pumps
       parked connections so these actually go out and the conn survives the
       30s idle timeout for reuse by a later request. */
    ngtcp2_conn_set_keep_alive_timeout(hc->conn, 15 * NGTCP2_SECONDS);
    return 0;
}

static int h3_setup_http3(URLContext *h, H3Conn *hc)
{
    nghttp3_settings settings;
    int64_t ctrl_id, enc_id, dec_id;
    int rv;
    static const nghttp3_callbacks callbacks = {
        .recv_data    = h3_http_recv_data_cb,
        .recv_header  = h3_recv_header_cb,
        .end_headers  = h3_end_headers_cb,
        .stream_close = NULL,
    };

    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams     = 100;

    rv = nghttp3_conn_client_new(&hc->h3conn, &callbacks, &settings,
                                 nghttp3_mem_default(), hc);
    if (rv != 0) {
        av_log(h, AV_LOG_ERROR, "nghttp3_conn_client_new: %s\n", nghttp3_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    if (ngtcp2_conn_open_uni_stream(hc->conn, &ctrl_id, NULL) != 0 ||
        nghttp3_conn_bind_control_stream(hc->h3conn, ctrl_id) != 0)
        return AVERROR_EXTERNAL;
    if (ngtcp2_conn_open_uni_stream(hc->conn, &enc_id, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(hc->conn, &dec_id, NULL) != 0 ||
        nghttp3_conn_bind_qpack_streams(hc->h3conn, enc_id, dec_id) != 0)
        return AVERROR_EXTERNAL;
    return 0;
}

/* ---- I/O pump (operates on H3Conn) ---- */

static int h3_write(URLContext *h, H3Conn *hc)
{
    uint8_t buf[1452];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    nghttp3_vec vec[16];

    ngtcp2_path_storage_zero(&ps);
    for (;;) {
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_ssize sveccnt = 0;
        ngtcp2_ssize ndatalen, nwrite;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

        if (hc->h3conn) {
            sveccnt = nghttp3_conn_writev_stream(hc->h3conn, &stream_id, &fin,
                                                 vec, FF_ARRAY_ELEMS(vec));
            if (sveccnt < 0)
                return AVERROR_EXTERNAL;
        }
        if (fin)
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        nwrite = ngtcp2_conn_writev_stream(hc->conn, &ps.path, &pi, buf, sizeof(buf),
                                           &ndatalen, flags, stream_id,
                                           (const ngtcp2_vec *)vec,
                                           (size_t)sveccnt, h3_timestamp());
        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                nghttp3_conn_block_stream(hc->h3conn, stream_id);
                continue;
            }
            if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
                nghttp3_conn_shutdown_stream_write(hc->h3conn, stream_id);
                continue;
            }
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                nghttp3_conn_add_write_offset(hc->h3conn, stream_id, ndatalen);
                continue;
            }
            av_log(h, AV_LOG_ERROR, "writev_stream: %s\n", ngtcp2_strerror((int)nwrite));
            return AVERROR_EXTERNAL;
        }
        if (ndatalen >= 0)
            nghttp3_conn_add_write_offset(hc->h3conn, stream_id, ndatalen);
        if (nwrite == 0)
            return 0;
        if (send(hc->fd, buf, nwrite, 0) < 0)
            return AVERROR(EIO);
    }
}

static int h3_read_socket(URLContext *h, H3Conn *hc)
{
    uint8_t buf[H3_DGRAM];
    ngtcp2_path path;
    ngtcp2_pkt_info pi = { 0 };
    ssize_t nread;
    int rv;

    nread = recv(hc->fd, buf, sizeof(buf), 0);
    if (nread < 0)
        return AVERROR(EIO);

    path.local.addr     = (struct sockaddr *)&hc->local_addr;
    path.local.addrlen  = hc->local_addrlen;
    path.remote.addr    = (struct sockaddr *)&hc->remote_addr;
    path.remote.addrlen = hc->remote_addrlen;
    path.user_data      = NULL;

    rv = ngtcp2_conn_read_pkt(hc->conn, &path, &pi, buf, nread, h3_timestamp());
    if (rv != 0) {
        const ngtcp2_ccerr *e = ngtcp2_conn_get_ccerr(hc->conn);
        av_log(h, AV_LOG_ERROR, "read_pkt: %s; ccerr 0x%"PRIx64" %.*s\n",
               ngtcp2_strerror(rv), e ? (uint64_t)e->error_code : 0,
               e ? (int)e->reasonlen : 0, e ? (const char *)e->reason : "");
        return AVERROR_EXTERNAL;
    }
    return 0;
}

static int h3_pump(URLContext *h, H3Conn *hc, int timeout_ms)
{
    struct pollfd pfd = { .fd = hc->fd, .events = POLLIN };
    ngtcp2_tstamp expiry;
    uint64_t now;
    int pr, d;

    /* Honor the ffmpeg interrupt callback (e.g. mpv player teardown) so a
       blocking read returns promptly with AVERROR_EXIT instead of hanging the
       demux thread in poll() until the timeout -- which would deadlock the
       caller's pthread_join on shutdown. h is NULL for the keep-alive reaper. */
    if (h && ff_check_interrupt(&h->interrupt_callback))
        return AVERROR_EXIT;

    if (h3_write(h, hc) < 0)
        return AVERROR_EXTERNAL;

    expiry = ngtcp2_conn_get_expiry(hc->conn);
    now = h3_timestamp();
    if (expiry != UINT64_MAX) {
        d = (int)(expiry > now ? (expiry - now) / 1000000 : 0);
        if (d < timeout_ms)
            timeout_ms = d;
    }
    /* cap the wait so an interrupt arriving mid-poll is noticed within ~250ms
       (callers loop on h3_pump until their own deadline) */
    if (timeout_ms > 250)
        timeout_ms = 250;

    pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0)
        return AVERROR(EIO);
    if (pr > 0 && (pfd.revents & POLLIN)) {
        int rv = h3_read_socket(h, hc);
        if (rv < 0)
            return rv;
    } else if (ngtcp2_conn_handle_expiry(hc->conn, h3_timestamp()) != 0) {
        return AVERROR_EXTERNAL;
    }
    return h3_write(h, hc);
}

static int h3_handshake(URLContext *h, H3Conn *hc, int64_t timeout_us)
{
    int64_t deadline = av_gettime_relative() + timeout_us;
    while (!ngtcp2_conn_get_handshake_completed(hc->conn)) {
        int rv;
        if (av_gettime_relative() > deadline)
            return AVERROR(ETIMEDOUT);
        if ((rv = h3_pump(h, hc, 1000)) < 0)
            return rv;
    }
    return 0;
}

static int h3_conn_alive(H3Conn *hc)
{
    return hc->conn &&
           ngtcp2_conn_get_handshake_completed(hc->conn) &&
           !ngtcp2_conn_in_closing_period2(hc->conn) &&
           !ngtcp2_conn_in_draining_period2(hc->conn);
}

static H3Conn *h3conn_alloc(void)
{
    H3Conn *hc = av_mallocz(sizeof(*hc));
    if (hc)
        hc->fd = -1;
    return hc;
}

static void h3conn_free(H3Conn *hc)
{
    if (!hc)
        return;
    if (hc->h3conn)  nghttp3_conn_del(hc->h3conn);
    if (hc->conn)    ngtcp2_conn_del(hc->conn);
#if CONFIG_GNUTLS
    if (hc->session) gnutls_deinit(hc->session);
    if (hc->cred)    gnutls_certificate_free_credentials(hc->cred);
#else
#if !defined(OPENSSL_IS_BORINGSSL)
    if (hc->ossl_ctx) ngtcp2_crypto_ossl_ctx_del(hc->ossl_ctx);
#endif
    if (hc->ssl)     SSL_free(hc->ssl);
    if (hc->ssl_ctx) SSL_CTX_free(hc->ssl_ctx);
#endif
    if (hc->fd >= 0) close(hc->fd);
    av_free(hc);
}

static int h3_dial(URLContext *h, H3Conn *hc, const char *portstr, int64_t timeout_us)
{
    int ret;
    if ((ret = h3_connect_udp(h, hc, hc->host, portstr)) < 0) return ret;
    if ((ret = h3_init_tls(h, hc, hc->host)) < 0)             return ret;
    if ((ret = h3_init_quic(h, hc)) < 0)                      return ret;
    if ((ret = h3_handshake(h, hc, timeout_us)) < 0)          return ret;
    if ((ret = h3_setup_http3(h, hc)) < 0)                    return ret;
    return 0;
}

/* ---- pool ---- */

/* Background reaper: pumps parked connections so ngtcp2 sends keep-alive PINGs
   (keeping them alive past the idle timeout for reuse) and evicts dead ones. */
static void *h3_reaper(void *arg)
{
    for (;;) {
        int i;
        av_usleep(3 * 1000000);
        ff_mutex_lock(&h3_pool_mutex);
        for (i = 0; i < H3_POOL_MAX; i++) {
            H3Conn *hc = h3_pool[i];
            if (!hc)
                continue;
            if (h3_pump(NULL, hc, 0) < 0 || !h3_conn_alive(hc)) {
                h3conn_free(hc);
                h3_pool[i] = NULL;
            }
        }
        ff_mutex_unlock(&h3_pool_mutex);
    }
    return NULL;
}

static void h3_start_reaper(void)
{
    pthread_t t;
    if (pthread_create(&t, NULL, h3_reaper, NULL) == 0)
        pthread_detach(t);
}

static H3Conn *h3_pool_take(const char *host, int port)
{
    H3Conn *hc = NULL;
    int i;
    ff_mutex_lock(&h3_pool_mutex);
    for (i = 0; i < H3_POOL_MAX; i++) {
        if (h3_pool[i] && h3_pool[i]->port == port &&
            !strcmp(h3_pool[i]->host, host)) {
            hc = h3_pool[i];
            h3_pool[i] = NULL;
            break;
        }
    }
    ff_mutex_unlock(&h3_pool_mutex);
    return hc;
}

static void h3_pool_put(H3Conn *hc)
{
    static AVOnce reaper_once = AV_ONCE_INIT;
    H3Conn *evict = NULL;
    int i;
    ff_thread_once(&reaper_once, h3_start_reaper);
    ff_mutex_lock(&h3_pool_mutex);
    for (i = 0; i < H3_POOL_MAX; i++) {
        if (!h3_pool[i]) {
            h3_pool[i] = hc;
            hc = NULL;
            break;
        }
    }
    if (hc) {
        /* full: evict the oldest (slot 0), shift down, append the new one */
        evict = h3_pool[0];
        for (i = 1; i < H3_POOL_MAX; i++)
            h3_pool[i - 1] = h3_pool[i];
        h3_pool[H3_POOL_MAX - 1] = hc;
    }
    ff_mutex_unlock(&h3_pool_mutex);
    h3conn_free(evict);
}

/* ---- request ---- */

static int h3_start_request(URLContext *h, HTTP3Context *c, int64_t range_start)
{
    H3Conn *hc = c->hc;
    int rv;
    char rangebuf[64];
    size_t nvlen;
#define MK_NV(N, V) { (uint8_t *)(N), (uint8_t *)(V), sizeof(N) - 1, strlen(V), NGHTTP3_NV_FLAG_NONE }
    nghttp3_nv nva[6] = {
        MK_NV(":method", "GET"),
        MK_NV(":scheme", "https"),
        { (uint8_t *)":authority", (uint8_t *)hc->host, sizeof(":authority") - 1, strlen(hc->host), NGHTTP3_NV_FLAG_NONE },
        { (uint8_t *)":path",      (uint8_t *)c->path,  sizeof(":path") - 1,      strlen(c->path),  NGHTTP3_NV_FLAG_NONE },
        MK_NV("user-agent", "ffmpeg-http3/0.1"),
    };
    nvlen = 5;

    hc->cur = c;
    if (c->stream_id >= 0 && !c->stream_done)
        ngtcp2_conn_shutdown_stream(hc->conn, 0, c->stream_id, NGHTTP3_H3_REQUEST_CANCELLED);

    c->rb_len = c->rb_off = 0;
    c->stream_done = c->headers_done = c->status = 0;

    if (range_start > 0) {
        snprintf(rangebuf, sizeof(rangebuf), "bytes=%"PRId64"-", range_start);
        nva[nvlen].name = (uint8_t *)"range";   nva[nvlen].namelen = 5;
        nva[nvlen].value = (uint8_t *)rangebuf;  nva[nvlen].valuelen = strlen(rangebuf);
        nva[nvlen].flags = NGHTTP3_NV_FLAG_NONE;
        nvlen++;
    }

    if (ngtcp2_conn_open_bidi_stream(hc->conn, &c->stream_id, NULL) != 0)
        return AVERROR_EXTERNAL;
    rv = nghttp3_conn_submit_request(hc->h3conn, c->stream_id, nva, nvlen, NULL, hc);
    if (rv != 0) {
        av_log(h, AV_LOG_ERROR, "submit_request: %s\n", nghttp3_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    return 0;
}

static int h3_await_headers(URLContext *h, HTTP3Context *c)
{
    int64_t deadline = av_gettime_relative() + c->open_timeout_us;
    while (!c->headers_done && !c->stream_done) {
        int rv;
        if (av_gettime_relative() > deadline)
            return AVERROR(ETIMEDOUT);
        if ((rv = h3_pump(h, c->hc, 1000)) < 0)
            return rv;
    }
    return 0;
}

static int h3_status_error(int s)
{
    switch (s) {
    case 400: return AVERROR_HTTP_BAD_REQUEST;
    case 401: return AVERROR_HTTP_UNAUTHORIZED;
    case 403: return AVERROR_HTTP_FORBIDDEN;
    case 404: return AVERROR_HTTP_NOT_FOUND;
    case 429: return AVERROR_HTTP_TOO_MANY_REQUESTS;
    default:  return s >= 500 ? AVERROR_HTTP_SERVER_ERROR : AVERROR_HTTP_OTHER_4XX;
    }
}

/* ---- URLProtocol ---- */

/* Alt-Svc discovery: a plain TLS-over-TCP HTTP/1.1 HEAD to learn whether the
   origin advertises HTTP/3 and on which port (RFC 9114 §3.1.1). Returns the
   advertised h3 port, or <0 if none. This is the "upgrade" path: instead of
   blindly assuming h3 (prior knowledge), confirm + discover the port first. */
static int h3_altsvc_probe(URLContext *h, const char *host, int port)
{
    struct addrinfo hints = { 0 }, *res = NULL, *ai;
#if CONFIG_GNUTLS
    gnutls_session_t s = NULL;
    gnutls_certificate_credentials_t cred = NULL;
#else
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    static const uint8_t alpn[] = { 8, 'h','t','t','p','/','1','.','1' };
#endif
    char portstr[12], req[512], buf[8192];
    int fd = -1, ret = AVERROR(EIO), n, off = 0;
    char *as, *eol, *h3, *v, *end, *colon;

    snprintf(portstr, sizeof(portstr), "%d", port);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return AVERROR(EIO);
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return AVERROR(EIO);

#if CONFIG_GNUTLS
    if (gnutls_certificate_allocate_credentials(&cred) != 0) goto out;
    gnutls_certificate_set_x509_system_trust(cred);
    if (gnutls_init(&s, GNUTLS_CLIENT) != 0) goto out;
    gnutls_set_default_priority(s);
    gnutls_credentials_set(s, GNUTLS_CRD_CERTIFICATE, cred);
    gnutls_server_name_set(s, GNUTLS_NAME_DNS, host, strlen(host));
    gnutls_session_set_verify_cert(s, host, 0);
    gnutls_transport_set_int(s, fd);
    gnutls_handshake_set_timeout(s, 5000);
    do { n = gnutls_handshake(s); } while (n < 0 && !gnutls_error_is_fatal(n));
    if (n < 0) {
        av_log(h, AV_LOG_WARNING, "alt-svc probe TLS: %s\n", gnutls_strerror(n));
        goto out;
    }
#else
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) goto out;
    SSL_CTX_set_default_verify_paths(ctx);
    ssl = SSL_new(ctx);
    if (!ssl) goto out;
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set1_host(ssl, host);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));
    if (SSL_connect(ssl) != 1) {
        av_log(h, AV_LOG_WARNING, "alt-svc probe TLS handshake failed\n");
        goto out;
    }
#endif

    snprintf(req, sizeof(req),
             "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ffmpeg-http3/0.1\r\nConnection: close\r\n\r\n",
             host);
#if CONFIG_GNUTLS
    gnutls_record_send(s, req, strlen(req));
    while (off < (int)sizeof(buf) - 1) {
        n = gnutls_record_recv(s, buf + off, sizeof(buf) - 1 - off);
        if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) continue;
        if (n <= 0) break;
        off += n;
        buf[off] = 0;
        if (strstr(buf, "\r\n\r\n")) break; /* headers complete */
    }
#else
    SSL_write(ssl, req, strlen(req));
    while (off < (int)sizeof(buf) - 1) {
        n = SSL_read(ssl, buf + off, sizeof(buf) - 1 - off);
        if (n <= 0) break;
        off += n;
        buf[off] = 0;
        if (strstr(buf, "\r\n\r\n")) break; /* headers complete */
    }
#endif
    buf[off] = 0;

    as = av_stristr(buf, "alt-svc:");
    if (!as) { ret = AVERROR(EPROTONOSUPPORT); goto out; }
    if ((eol = strstr(as, "\r\n"))) *eol = 0;
    h3 = av_stristr(as, "h3=");
    if (!h3) { ret = AVERROR(EPROTONOSUPPORT); goto out; }
    v = h3 + 3;
    if (*v == '"') v++;
    end = v;
    while (*end && *end != '"' && *end != ';' && *end != ',') end++;
    *end = 0;
    colon = strrchr(v, ':');
    ret = colon ? atoi(colon + 1) : port;
    if (ret <= 0) ret = port;
    av_log(h, AV_LOG_INFO, "http3: Alt-Svc advertises h3 on port %d\n", ret);

out:
#if CONFIG_GNUTLS
    if (s)    { gnutls_bye(s, GNUTLS_SHUT_WR); gnutls_deinit(s); }
    if (cred) gnutls_certificate_free_credentials(cred);
#else
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
#endif
    if (fd >= 0) close(fd);
    return ret;
}

static int http3_open(URLContext *h, const char *uri, int flags)
{
    HTTP3Context *c = h->priv_data;
    int port, ret, redirects = 0, reused;
    char portstr[12], nexturi[4096], host[1024];

    c->stream_id = -1;
    c->off = 0;
    c->open_timeout_us = 15 * 1000000;

    av_strlcpy(nexturi, uri, sizeof(nexturi));
    for (;;) {
        port = -1;
        c->filesize = -1;
        av_url_split(NULL, 0, NULL, 0, host, sizeof(host), &port,
                     c->path, sizeof(c->path), nexturi);
        if (port < 0)
            port = 443;
        if (!c->path[0])
            av_strlcpy(c->path, "/", sizeof(c->path));
        snprintf(portstr, sizeof(portstr), "%d", port);

        if (c->altsvc) {
            int p3 = h3_altsvc_probe(h, host, port);
            if (p3 < 0) {
                av_log(h, AV_LOG_ERROR, "http3: %s:%d does not advertise HTTP/3\n", host, port);
                ret = p3;
                goto fail;
            }
            if (p3 != port) {
                port = p3;
                snprintf(portstr, sizeof(portstr), "%d", port);
            }
        }

        reused = 0;
        c->hc = h3_pool_take(host, port);
        if (c->hc) {
            c->hc->cur = c;
            /* liveness: process any pending packets, then validate */
            if (h3_pump(h, c->hc, 0) == 0 && h3_conn_alive(c->hc)) {
                reused = 1;
                av_log(h, AV_LOG_VERBOSE, "http3: reusing pooled connection to %s:%d\n", host, port);
            } else {
                h3conn_free(c->hc);
                c->hc = NULL;
            }
        }
        if (!c->hc) {
            c->hc = h3conn_alloc();
            if (!c->hc) { ret = AVERROR(ENOMEM); goto fail; }
            c->hc->cur = c;
            av_strlcpy(c->hc->host, host, sizeof(c->hc->host));
            c->hc->port = port;
            if ((ret = h3_dial(h, c->hc, portstr, c->open_timeout_us)) < 0)
                goto fail;
        }

        if ((ret = h3_start_request(h, c, 0)) < 0) goto fail;
        if ((ret = h3_await_headers(h, c)) < 0)    goto fail;

        if (c->status >= 300 && c->status < 400 && c->location[0]) {
            if (++redirects > 8) { ret = AVERROR(ELOOP); goto fail; }
            av_log(h, AV_LOG_VERBOSE, "http3: %d redirect -> %s\n", c->status, c->location);
            if (av_strstart(c->location, "http", NULL))
                av_strlcpy(nexturi, c->location, sizeof(nexturi));
            else
                snprintf(nexturi, sizeof(nexturi), "http3://%s:%d%s", host, port, c->location);
            h3conn_free(c->hc);   /* don't pool a redirect source */
            c->hc = NULL;
            c->location[0] = 0;
            continue;
        }
        if (c->status >= 400) { ret = h3_status_error(c->status); goto fail; }
        break; /* 2xx */
    }

    av_log(h, AV_LOG_INFO, "http3: GET https://%s%s -> %d over HTTP/3%s\n",
           host, c->path, c->status, reused ? " (reused conn)" : "");
    return 0;
fail:
    h3conn_free(c->hc);
    c->hc = NULL;
    return ret;
}

static int http3_read(URLContext *h, unsigned char *buf, int size)
{
    HTTP3Context *c = h->priv_data;
    int64_t deadline = av_gettime_relative() + c->open_timeout_us;

    while (c->rb_off >= c->rb_len) {
        int rv;
        if (c->stream_done)
            return AVERROR_EOF;
        if (av_gettime_relative() > deadline)
            return AVERROR(ETIMEDOUT);
        if ((rv = h3_pump(h, c->hc, 1000)) < 0)
            return rv;
    }
    {
        int n = (int)FFMIN((size_t)size, c->rb_len - c->rb_off);
        memcpy(buf, c->rb + c->rb_off, n);
        c->rb_off += n;
        c->off += n;
        if (c->rb_off >= c->rb_len)
            c->rb_off = c->rb_len = 0;
        return n;
    }
}

static int64_t http3_seek(URLContext *h, int64_t pos, int whence)
{
    HTTP3Context *c = h->priv_data;
    int64_t newpos;
    int ret;

    if (whence == AVSEEK_SIZE)
        return c->filesize >= 0 ? c->filesize : AVERROR(ENOSYS);
    if (whence == SEEK_CUR)
        newpos = c->off + pos;
    else if (whence == SEEK_END) {
        if (c->filesize < 0)
            return AVERROR(ENOSYS);
        newpos = c->filesize + pos;
    } else
        newpos = pos;
    if (newpos < 0)
        return AVERROR(EINVAL);
    if (newpos == c->off)
        return c->off;
    if ((ret = h3_start_request(h, c, newpos)) < 0)
        return ret;
    c->off = newpos;
    return newpos;
}

static int http3_close(URLContext *h)
{
    HTTP3Context *c = h->priv_data;
    H3Conn *hc = c->hc;

    if (hc) {
        /* a clean, finished 2xx connection can be parked for reuse */
        int poolable = c->stream_done && c->status >= 200 && c->status < 300 &&
                       h3_conn_alive(hc);
        if (poolable) {
            hc->cur = NULL;
            h3_pump(h, hc, 0);     /* flush any pending acks */
            h3_pool_put(hc);
        } else {
            h3conn_free(hc);
        }
        c->hc = NULL;
    }
    av_freep(&c->rb);
    return 0;
}

static const AVOption http3_options[] = {
    { "altsvc", "discover HTTP/3 via the Alt-Svc header before connecting",
      offsetof(HTTP3Context, altsvc), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1,
      AV_OPT_FLAG_DECODING_PARAM },
    { "tls_verify", "verify the server certificate (0 to disable)",
      offsetof(HTTP3Context, tls_verify), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1,
      AV_OPT_FLAG_DECODING_PARAM },
    { "ca_file", "additional CA certificate file (PEM) to trust",
      offsetof(HTTP3Context, ca_file), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0,
      AV_OPT_FLAG_DECODING_PARAM },
    { "verifyhost", "hostname to verify the certificate against (default: URL host)",
      offsetof(HTTP3Context, verifyhost), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0,
      AV_OPT_FLAG_DECODING_PARAM },
    { NULL }
};

static const AVClass http3_class = {
    .class_name = "http3",
    .item_name  = av_default_item_name,
    .option     = http3_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_http3_protocol = {
    .name            = "http3",
    .url_open        = http3_open,
    .url_read        = http3_read,
    .url_seek        = http3_seek,
    .url_close       = http3_close,
    .priv_data_size  = sizeof(HTTP3Context),
    .priv_data_class = &http3_class,
    .flags           = URL_PROTOCOL_FLAG_NETWORK,
};
