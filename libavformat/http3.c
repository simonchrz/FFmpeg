/*
 * HTTP/3 (QUIC) protocol for FFmpeg — work in progress.
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
 * Milestone 2 / stage B2: QUIC transport (ngtcp2 + GnuTLS crypto helper) plus
 * an HTTP/3 client (nghttp3): open a bidi stream, submit a GET, pump the
 * connection and deliver the response body through url_read. A minimal but real
 * HTTP/3 GET from inside libavformat. Range/seek + connection reuse + HLS wiring
 * are later milestones.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>

#include "libavutil/avstring.h"
#include "libavutil/error.h"
#include "libavutil/log.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "avformat.h"
#include "url.h"

#define H3_ALPN     "h3"
#define H3_DGRAM    65536

typedef struct HTTP3Context {
    const AVClass *class;

    int fd;
    ngtcp2_conn *conn;
    nghttp3_conn *h3conn;
    ngtcp2_crypto_conn_ref conn_ref;

    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;

    struct sockaddr_storage local_addr;
    socklen_t              local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t              remote_addrlen;

    uint8_t sr_secret[32];

    char host[1024];
    char path[2048];

    int64_t stream_id;     /* current request stream */
    int     stream_done;   /* response stream finished */
    int     status;        /* HTTP :status of the current response */
    int     headers_done;  /* response header section complete */
    char    location[2048];/* Location header (for redirects) */
    int64_t off;           /* logical read position (bytes delivered) */
    int64_t filesize;      /* total resource size, -1 if unknown */

    /* response body buffer */
    unsigned char *rb;
    size_t rb_size, rb_len, rb_off;
    size_t total_recv;

    int64_t open_timeout_us;
} HTTP3Context;

/* ---- helpers ---- */

static uint64_t h3_timestamp(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * NGTCP2_SECONDS + (uint64_t)t.tv_nsec;
}

static ngtcp2_conn *h3_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    HTTP3Context *c = ref->user_data;
    return c->conn;
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

/* ---- ngtcp2 callbacks (mostly crypto defaults; a few custom) ---- */

static void h3_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
    gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int h3_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                             size_t cidlen, void *user_data)
{
    HTTP3Context *c = user_data;
    if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, c->sr_secret, sizeof(c->sr_secret), cid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int h3_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                  int64_t stream_id, uint64_t offset,
                                  const uint8_t *data, size_t datalen,
                                  void *user_data, void *stream_user_data)
{
    HTTP3Context *c = user_data;
    nghttp3_ssize n;

    if (!c->h3conn)
        return 0;
    n = nghttp3_conn_read_stream(c->h3conn, stream_id, data, datalen,
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
    HTTP3Context *c = user_data;
    if (c->h3conn)
        nghttp3_conn_add_ack_offset(c->h3conn, stream_id, datalen);
    return 0;
}

static int h3_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                              int64_t stream_id, uint64_t app_error_code,
                              void *user_data, void *stream_user_data)
{
    HTTP3Context *c = user_data;
    if (c->h3conn) {
        if (!app_error_code)
            app_error_code = NGHTTP3_H3_NO_ERROR;
        nghttp3_conn_close_stream(c->h3conn, stream_id, app_error_code);
    }
    if (stream_id == c->stream_id)
        c->stream_done = 1;
    return 0;
}

static int h3_extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
                                        uint64_t max_data, void *user_data,
                                        void *stream_user_data)
{
    HTTP3Context *c = user_data;
    if (c->h3conn)
        nghttp3_conn_unblock_stream(c->h3conn, stream_id);
    return 0;
}

/* ---- nghttp3 callback: response body ---- */

static int h3_http_recv_data_cb(nghttp3_conn *conn, int64_t stream_id,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    HTTP3Context *c = user_data;
    if (stream_id != c->stream_id)   /* stale data from a cancelled (pre-seek) stream */
        return 0;
    return h3_buf_append(c, data, datalen) < 0 ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int h3_recv_header_cb(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                             nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
    HTTP3Context *c = user_data;
    nghttp3_vec n, v;
    char vb[2048];
    size_t vn;

    if (stream_id != c->stream_id)
        return 0;
    n = nghttp3_rcbuf_get_buf(name);
    v = nghttp3_rcbuf_get_buf(value);
    vn = FFMIN(v.len, sizeof(vb) - 1);
    memcpy(vb, v.base, vn);
    vb[vn] = 0;

    if (n.len == 7 && !av_strncasecmp((const char *)n.base, ":status", 7)) {
        c->status = atoi(vb);
    } else if (n.len == 8 && !av_strncasecmp((const char *)n.base, "location", 8)) {
        av_strlcpy(c->location, vb, sizeof(c->location));
    } else if (n.len == 13 && !av_strncasecmp((const char *)n.base, "content-range", 13)) {
        /* "bytes X-Y/Z" -> total Z */
        char *slash = strchr(vb, '/');
        if (slash && slash[1] && slash[1] != '*')
            c->filesize = strtoll(slash + 1, NULL, 10);
    } else if (n.len == 14 && !av_strncasecmp((const char *)n.base, "content-length", 14)) {
        if (c->status == 200)            /* full response: length == total size */
            c->filesize = strtoll(vb, NULL, 10);
    }
    return 0;
}

static int h3_http_stream_close_cb(nghttp3_conn *conn, int64_t stream_id,
                                   uint64_t app_error_code, void *user_data,
                                   void *stream_user_data)
{
    HTTP3Context *c = user_data;
    if (stream_id == c->stream_id)
        c->stream_done = 1;
    return 0;
}

static int h3_end_headers_cb(nghttp3_conn *conn, int64_t stream_id, int fin,
                             void *user_data, void *stream_user_data)
{
    HTTP3Context *c = user_data;
    if (stream_id == c->stream_id)
        c->headers_done = 1;
    return 0;
}

/* ---- gnutls TLS session ---- */

static int h3_init_gnutls(URLContext *h, HTTP3Context *c, const char *host)
{
    int rv;
    static const char priority[] =
        "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:"
        "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:"
        "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1:"
        "+GROUP-X25519:+GROUP-X448";
    gnutls_datum_t alpn = { (unsigned char *)H3_ALPN, sizeof(H3_ALPN) - 1 };

    if ((rv = gnutls_certificate_allocate_credentials(&c->cred)) != 0)
        return AVERROR_EXTERNAL;
    gnutls_certificate_set_x509_system_trust(c->cred);

    if ((rv = gnutls_init(&c->session, GNUTLS_CLIENT)) != 0)
        return AVERROR_EXTERNAL;
    if ((rv = gnutls_priority_set_direct(c->session, priority, NULL)) != 0) {
        av_log(h, AV_LOG_ERROR, "gnutls priority: %s\n", gnutls_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    if (ngtcp2_crypto_gnutls_configure_client_session(c->session) != 0)
        return AVERROR_EXTERNAL;

    c->conn_ref.get_conn  = h3_get_conn;
    c->conn_ref.user_data = c;
    gnutls_session_set_ptr(c->session, &c->conn_ref);

    if ((rv = gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, c->cred)) != 0)
        return AVERROR_EXTERNAL;
    gnutls_alpn_set_protocols(c->session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
    gnutls_server_name_set(c->session, GNUTLS_NAME_DNS, host, strlen(host));
    return 0;
}

/* ---- UDP socket ---- */

static int h3_connect_udp(URLContext *h, HTTP3Context *c,
                          const char *host, const char *port)
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
            memcpy(&c->remote_addr, ai->ai_addr, ai->ai_addrlen);
            c->remote_addrlen = ai->ai_addrlen;
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return AVERROR(EIO);
    c->local_addrlen = sizeof(c->local_addr);
    getsockname(fd, (struct sockaddr *)&c->local_addr, &c->local_addrlen);
    c->fd = fd;
    return 0;
}

/* ---- ngtcp2 connection ---- */

static int h3_init_quic(URLContext *h, HTTP3Context *c)
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

    gnutls_rnd(GNUTLS_RND_RANDOM, c->sr_secret, sizeof(c->sr_secret));
    scid.datalen = 17;
    gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
    dcid.datalen = 18;
    gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);

    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni            = 3;
    params.initial_max_stream_data_bidi_local = 1024 * 1024;
    /* The server's control + QPACK streams are unidirectional and send to us;
       without a non-zero uni stream-data limit it can't write its control stream
       (server closes with H3_INTERNAL_ERROR "Error opening control stream"). */
    params.initial_max_stream_data_uni        = 256 * 1024;
    params.initial_max_data                   = 4 * 1024 * 1024;
    params.max_idle_timeout                   = 30 * NGTCP2_SECONDS;
    params.active_connection_id_limit         = 7;

    path.local.addr     = (struct sockaddr *)&c->local_addr;
    path.local.addrlen  = c->local_addrlen;
    path.remote.addr    = (struct sockaddr *)&c->remote_addr;
    path.remote.addrlen = c->remote_addrlen;
    path.user_data      = NULL;

    rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1, &callbacks,
                                &settings, &params, NULL, c);
    if (rv != 0) {
        av_log(h, AV_LOG_ERROR, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    ngtcp2_conn_set_tls_native_handle(c->conn, c->session);
    return 0;
}

/* ---- HTTP/3 layer ---- */

static int h3_setup_http3(URLContext *h, HTTP3Context *c)
{
    nghttp3_settings settings;
    int64_t ctrl_id, enc_id, dec_id;
    int rv;
    static const nghttp3_callbacks callbacks = {
        .recv_data    = h3_http_recv_data_cb,
        .recv_header  = h3_recv_header_cb,
        .end_headers  = h3_end_headers_cb,
        .stream_close = h3_http_stream_close_cb,
    };

    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams     = 100;

    rv = nghttp3_conn_client_new(&c->h3conn, &callbacks, &settings,
                                 nghttp3_mem_default(), c);
    if (rv != 0) {
        av_log(h, AV_LOG_ERROR, "nghttp3_conn_client_new: %s\n", nghttp3_strerror(rv));
        return AVERROR_EXTERNAL;
    }

    if (ngtcp2_conn_open_uni_stream(c->conn, &ctrl_id, NULL) != 0 ||
        nghttp3_conn_bind_control_stream(c->h3conn, ctrl_id) != 0)
        return AVERROR_EXTERNAL;
    if (ngtcp2_conn_open_uni_stream(c->conn, &enc_id, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(c->conn, &dec_id, NULL) != 0 ||
        nghttp3_conn_bind_qpack_streams(c->h3conn, enc_id, dec_id) != 0)
        return AVERROR_EXTERNAL;
    return 0;
}

/* Start a GET on a fresh bidi stream; range_start>0 adds a Range header (for
   seeking). Any previous request stream is cancelled and the body buffer reset. */
static int h3_start_request(URLContext *h, HTTP3Context *c, int64_t range_start)
{
    int rv;
    char rangebuf[64];
    size_t nvlen;
#define MK_NV(N, V) { (uint8_t *)(N), (uint8_t *)(V), sizeof(N) - 1, strlen(V), NGHTTP3_NV_FLAG_NONE }
    nghttp3_nv nva[6] = {
        MK_NV(":method", "GET"),
        MK_NV(":scheme", "https"),
        { (uint8_t *)":authority", (uint8_t *)c->host, sizeof(":authority") - 1, strlen(c->host), NGHTTP3_NV_FLAG_NONE },
        { (uint8_t *)":path",      (uint8_t *)c->path, sizeof(":path") - 1,      strlen(c->path), NGHTTP3_NV_FLAG_NONE },
        MK_NV("user-agent", "ffmpeg-http3/0.1"),
    };
    nvlen = 5;

    /* cancel a previous (e.g. pre-seek) request stream */
    if (c->stream_id >= 0 && !c->stream_done)
        ngtcp2_conn_shutdown_stream(c->conn, 0, c->stream_id, NGHTTP3_H3_REQUEST_CANCELLED);

    c->rb_len = c->rb_off = 0;
    c->stream_done = 0;
    c->status = 0;
    c->headers_done = 0;

    if (range_start > 0) {
        snprintf(rangebuf, sizeof(rangebuf), "bytes=%"PRId64"-", range_start);
        nva[nvlen].name     = (uint8_t *)"range";
        nva[nvlen].value    = (uint8_t *)rangebuf;
        nva[nvlen].namelen  = 5;
        nva[nvlen].valuelen = strlen(rangebuf);
        nva[nvlen].flags    = NGHTTP3_NV_FLAG_NONE;
        nvlen++;
    }

    if (ngtcp2_conn_open_bidi_stream(c->conn, &c->stream_id, NULL) != 0)
        return AVERROR_EXTERNAL;
    rv = nghttp3_conn_submit_request(c->h3conn, c->stream_id, nva, nvlen, NULL, c);
    if (rv != 0) {
        av_log(h, AV_LOG_ERROR, "submit_request: %s\n", nghttp3_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    return 0;
}

/* ---- I/O pump ---- */

static int h3_write(URLContext *h, HTTP3Context *c)
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

        if (c->h3conn) {
            sveccnt = nghttp3_conn_writev_stream(c->h3conn, &stream_id, &fin,
                                                 vec, FF_ARRAY_ELEMS(vec));
            if (sveccnt < 0)
                return AVERROR_EXTERNAL;
        }
        if (fin)
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                           &ndatalen, flags, stream_id,
                                           (const ngtcp2_vec *)vec,
                                           (size_t)sveccnt, h3_timestamp());
        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                nghttp3_conn_block_stream(c->h3conn, stream_id);
                continue;
            }
            if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
                nghttp3_conn_shutdown_stream_write(c->h3conn, stream_id);
                continue;
            }
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                nghttp3_conn_add_write_offset(c->h3conn, stream_id, ndatalen);
                continue;
            }
            av_log(h, AV_LOG_ERROR, "writev_stream: %s\n", ngtcp2_strerror((int)nwrite));
            return AVERROR_EXTERNAL;
        }
        if (ndatalen >= 0)
            nghttp3_conn_add_write_offset(c->h3conn, stream_id, ndatalen);
        if (nwrite == 0)
            return 0;
        if (send(c->fd, buf, nwrite, 0) < 0)
            return AVERROR(EIO);
    }
}

static int h3_read_socket(URLContext *h, HTTP3Context *c)
{
    uint8_t buf[H3_DGRAM];
    ngtcp2_path path;
    ngtcp2_pkt_info pi = { 0 };
    ssize_t nread;
    int rv;

    nread = recv(c->fd, buf, sizeof(buf), 0);
    if (nread < 0)
        return AVERROR(EIO);

    path.local.addr     = (struct sockaddr *)&c->local_addr;
    path.local.addrlen  = c->local_addrlen;
    path.remote.addr    = (struct sockaddr *)&c->remote_addr;
    path.remote.addrlen = c->remote_addrlen;
    path.user_data      = NULL;

    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, nread, h3_timestamp());
    if (rv != 0) {
        const ngtcp2_ccerr *e = ngtcp2_conn_get_ccerr(c->conn);
        av_log(h, AV_LOG_ERROR, "read_pkt: %s; ccerr type=%d code=0x%"PRIx64" reason=%.*s\n",
               ngtcp2_strerror(rv), e ? e->type : -1,
               e ? (uint64_t)e->error_code : 0,
               e ? (int)e->reasonlen : 0, e ? (const char *)e->reason : "");
        return AVERROR_EXTERNAL;
    }
    return 0;
}

/* One pump cycle: send pending, wait, receive. */
static int h3_pump(URLContext *h, HTTP3Context *c, int timeout_ms)
{
    struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
    ngtcp2_tstamp expiry;
    uint64_t now;
    int pr, d;

    if (h3_write(h, c) < 0)
        return AVERROR_EXTERNAL;

    expiry = ngtcp2_conn_get_expiry(c->conn);
    now = h3_timestamp();
    if (expiry != UINT64_MAX) {
        d = (int)(expiry > now ? (expiry - now) / 1000000 : 0);
        if (d < timeout_ms)
            timeout_ms = d;
    }

    pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0)
        return AVERROR(EIO);
    if (pr > 0 && (pfd.revents & POLLIN)) {
        int rv = h3_read_socket(h, c);
        if (rv < 0)
            return rv;
    } else if (ngtcp2_conn_handle_expiry(c->conn, h3_timestamp()) != 0) {
        return AVERROR_EXTERNAL;
    }
    return h3_write(h, c);
}

static int h3_handshake(URLContext *h, HTTP3Context *c)
{
    int64_t deadline = av_gettime_relative() + c->open_timeout_us;
    while (!ngtcp2_conn_get_handshake_completed(c->conn)) {
        int rv;
        if (av_gettime_relative() > deadline)
            return AVERROR(ETIMEDOUT);
        rv = h3_pump(h, c, 1000);
        if (rv < 0)
            return rv;
    }
    return 0;
}

/* ---- URLProtocol callbacks ---- */

/* Pump until the response header section is complete (status known). */
static int h3_await_headers(URLContext *h, HTTP3Context *c)
{
    int64_t deadline = av_gettime_relative() + c->open_timeout_us;
    while (!c->headers_done && !c->stream_done) {
        int rv;
        if (av_gettime_relative() > deadline)
            return AVERROR(ETIMEDOUT);
        if ((rv = h3_pump(h, c, 1000)) < 0)
            return rv;
    }
    return 0;
}

/* Bring up one QUIC connection + HTTP/3 to c->host. */
static int h3_dial(URLContext *h, HTTP3Context *c, const char *portstr)
{
    int ret;
    if ((ret = h3_connect_udp(h, c, c->host, portstr)) < 0) return ret;
    if ((ret = h3_init_gnutls(h, c, c->host)) < 0)          return ret;
    if ((ret = h3_init_quic(h, c)) < 0)                      return ret;
    if ((ret = h3_handshake(h, c)) < 0)                      return ret;
    if ((ret = h3_setup_http3(h, c)) < 0)                    return ret;
    return 0;
}

static void h3_teardown(HTTP3Context *c)
{
    if (c->h3conn)  { nghttp3_conn_del(c->h3conn); c->h3conn = NULL; }
    if (c->conn)    { ngtcp2_conn_del(c->conn);    c->conn = NULL; }
    if (c->session) { gnutls_deinit(c->session);   c->session = NULL; }
    if (c->cred)    { gnutls_certificate_free_credentials(c->cred); c->cred = NULL; }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    c->stream_id = -1;
    c->stream_done = c->headers_done = c->status = 0;
    c->rb_len = c->rb_off = 0;
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

static int http3_open(URLContext *h, const char *uri, int flags)
{
    HTTP3Context *c = h->priv_data;
    int port, ret, redirects = 0;
    char portstr[12], nexturi[4096];

    c->fd = -1;
    c->stream_id = -1;
    c->off = 0;
    c->open_timeout_us = 15 * 1000000;

    if (gnutls_global_init() != 0)
        return AVERROR_EXTERNAL;

    av_strlcpy(nexturi, uri, sizeof(nexturi));
    for (;;) {
        port = -1;
        c->filesize = -1;
        av_url_split(NULL, 0, NULL, 0, c->host, sizeof(c->host), &port,
                     c->path, sizeof(c->path), nexturi);
        if (port < 0)
            port = 443;
        if (!c->path[0])
            av_strlcpy(c->path, "/", sizeof(c->path));
        snprintf(portstr, sizeof(portstr), "%d", port);

        if ((ret = h3_dial(h, c, portstr)) < 0)            goto fail;
        if ((ret = h3_start_request(h, c, 0)) < 0)         goto fail;
        if ((ret = h3_await_headers(h, c)) < 0)            goto fail;

        if (c->status >= 300 && c->status < 400 && c->location[0]) {
            if (++redirects > 8) { ret = AVERROR(ELOOP); goto fail; }
            av_log(h, AV_LOG_VERBOSE, "http3: %d redirect -> %s\n", c->status, c->location);
            if (av_strstart(c->location, "http", NULL))
                av_strlcpy(nexturi, c->location, sizeof(nexturi));
            else /* relative */
                snprintf(nexturi, sizeof(nexturi), "http3://%s:%d%s", c->host, port, c->location);
            h3_teardown(c);
            continue;
        }
        if (c->status >= 400) { ret = h3_status_error(c->status); goto fail; }
        break; /* 2xx */
    }

    av_log(h, AV_LOG_INFO, "http3: GET https://%s%s -> %d over HTTP/3\n",
           c->host, c->path, c->status);
    return 0;
fail:
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
        rv = h3_pump(h, c, 1000);
        if (rv < 0)
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
    } else {
        newpos = pos; /* SEEK_SET */
    }
    if (newpos < 0)
        return AVERROR(EINVAL);
    if (newpos == c->off)
        return c->off;

    /* re-issue the GET with a Range starting at the new position */
    if ((ret = h3_start_request(h, c, newpos)) < 0)
        return ret;
    c->off = newpos;
    return newpos;
}

static int http3_close(URLContext *h)
{
    HTTP3Context *c = h->priv_data;
    av_log(h, AV_LOG_INFO, "http3: received %zu body bytes over HTTP/3\n", c->total_recv);
    if (c->h3conn)
        nghttp3_conn_del(c->h3conn);
    if (c->conn)
        ngtcp2_conn_del(c->conn);
    if (c->session)
        gnutls_deinit(c->session);
    if (c->cred)
        gnutls_certificate_free_credentials(c->cred);
    if (c->fd >= 0)
        close(c->fd);
    av_freep(&c->rb);
    return 0;
}

static const AVClass http3_class = {
    .class_name = "http3",
    .item_name  = av_default_item_name,
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
