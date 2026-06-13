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
 * Milestone 2 / stage B1: establish a QUIC connection (UDP + ngtcp2 transport +
 * TLS1.3 via the GnuTLS crypto helper) to an HTTP/3 origin and complete the
 * handshake. No HTTP/3 request/body yet (nghttp3 comes in B2) — url_read returns
 * EOF. Proves the transport + TLS + event-pump bridge from inside libavformat.
 */

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

#include "libavutil/avstring.h"
#include "libavutil/error.h"
#include "libavutil/log.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "avformat.h"
#include "url.h"

#define H3_ALPN "h3"
#define H3_RECV_BUF 65536

typedef struct HTTP3Context {
    const AVClass *class;

    int fd;
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref conn_ref;

    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;

    struct sockaddr_storage local_addr;
    socklen_t              local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t              remote_addrlen;

    uint8_t sr_secret[32]; /* stateless-reset token secret */

    int handshake_done;
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

/* ---- gnutls TLS session ---- */

static int h3_init_gnutls(URLContext *h, HTTP3Context *c, const char *host)
{
    int rv;
    /* QUIC requires TLS1.3 only; this is ngtcp2's canonical client priority. */
    static const char priority[] =
        "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:"
        "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:"
        "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1:"
        "+GROUP-X25519:+GROUP-X448";
    gnutls_datum_t alpn = { (unsigned char *)H3_ALPN, sizeof(H3_ALPN) - 1 };

    if ((rv = gnutls_certificate_allocate_credentials(&c->cred)) != 0) {
        av_log(h, AV_LOG_ERROR, "gnutls cred alloc: %s\n", gnutls_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    gnutls_certificate_set_x509_system_trust(c->cred);

    if ((rv = gnutls_init(&c->session, GNUTLS_CLIENT)) != 0) {
        av_log(h, AV_LOG_ERROR, "gnutls_init: %s\n", gnutls_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    if ((rv = gnutls_priority_set_direct(c->session, priority, NULL)) != 0) {
        av_log(h, AV_LOG_ERROR, "gnutls priority: %s\n", gnutls_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    if (ngtcp2_crypto_gnutls_configure_client_session(c->session) != 0) {
        av_log(h, AV_LOG_ERROR, "ngtcp2 gnutls client session config failed\n");
        return AVERROR_EXTERNAL;
    }

    c->conn_ref.get_conn  = h3_get_conn;
    c->conn_ref.user_data = c;
    gnutls_session_set_ptr(c->session, &c->conn_ref);

    if ((rv = gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, c->cred)) != 0) {
        av_log(h, AV_LOG_ERROR, "gnutls creds set: %s\n", gnutls_strerror(rv));
        return AVERROR_EXTERNAL;
    }
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
    if (fd < 0) {
        av_log(h, AV_LOG_ERROR, "could not connect UDP socket to %s:%s\n", host, port);
        return AVERROR(EIO);
    }
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
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_data                   = 1024 * 1024;
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

/* ---- I/O pump ---- */

/* Drain all packets ngtcp2 wants to send. */
static int h3_write_packets(URLContext *h, HTTP3Context *c)
{
    uint8_t buf[1452];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize n;

    ngtcp2_path_storage_zero(&ps);
    for (;;) {
        n = ngtcp2_conn_write_pkt(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                  h3_timestamp());
        if (n < 0) {
            av_log(h, AV_LOG_ERROR, "write_pkt: %s\n", ngtcp2_strerror((int)n));
            return AVERROR_EXTERNAL;
        }
        if (n == 0)
            return 0; /* nothing more to send right now */
        if (send(c->fd, buf, n, 0) < 0)
            return AVERROR(EIO);
    }
}

/* Feed one or more received datagrams into ngtcp2. */
static int h3_read_packet(URLContext *h, HTTP3Context *c)
{
    uint8_t buf[H3_RECV_BUF];
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
        av_log(h, AV_LOG_ERROR, "read_pkt: %s\n", ngtcp2_strerror(rv));
        return AVERROR_EXTERNAL;
    }
    return 0;
}

/* Run the event loop until the QUIC handshake completes (or timeout/error). */
static int h3_handshake(URLContext *h, HTTP3Context *c)
{
    int64_t deadline = av_gettime_relative() + c->open_timeout_us;

    if (h3_write_packets(h, c) < 0)
        return AVERROR_EXTERNAL;

    while (!ngtcp2_conn_get_handshake_completed(c->conn)) {
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->conn);
        uint64_t now = h3_timestamp();
        int timeout_ms = 1000;
        struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
        int pr;

        if (expiry != UINT64_MAX) {
            int64_t d = (int64_t)(expiry > now ? (expiry - now) / 1000000 : 0);
            if (d < timeout_ms)
                timeout_ms = (int)d;
        }
        if (av_gettime_relative() > deadline) {
            av_log(h, AV_LOG_ERROR, "QUIC handshake timed out\n");
            return AVERROR(ETIMEDOUT);
        }

        pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0)
            return AVERROR(EIO);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            int rv = h3_read_packet(h, c);
            if (rv < 0)
                return rv;
        } else {
            /* timer fired */
            if (ngtcp2_conn_handle_expiry(c->conn, h3_timestamp()) != 0)
                return AVERROR_EXTERNAL;
        }
        if (h3_write_packets(h, c) < 0)
            return AVERROR_EXTERNAL;
    }
    return 0;
}

/* ---- URLProtocol callbacks ---- */

static int http3_open(URLContext *h, const char *uri, int flags)
{
    HTTP3Context *c = h->priv_data;
    char host[1024], path[2048];
    int port = -1;
    char portstr[12];
    int ret;

    c->fd = -1;
    c->open_timeout_us = 10 * 1000000;

    av_url_split(NULL, 0, NULL, 0, host, sizeof(host), &port,
                 path, sizeof(path), uri);
    if (port < 0)
        port = 443;
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (gnutls_global_init() != 0)
        return AVERROR_EXTERNAL;

    if ((ret = h3_connect_udp(h, c, host, portstr)) < 0)
        goto fail;
    if ((ret = h3_init_gnutls(h, c, host)) < 0)
        goto fail;
    if ((ret = h3_init_quic(h, c)) < 0)
        goto fail;
    if ((ret = h3_handshake(h, c)) < 0)
        goto fail;

    c->handshake_done = 1;
    av_log(h, AV_LOG_INFO,
           "http3: QUIC handshake completed to %s:%d (B1 — no HTTP/3 body yet)\n",
           host, port);
    return 0;

fail:
    return ret;
}

static int http3_read(URLContext *h, unsigned char *buf, int size)
{
    /* B1: transport only — body fetch (nghttp3) lands in B2. */
    return AVERROR_EOF;
}

static int http3_close(URLContext *h)
{
    HTTP3Context *c = h->priv_data;
    if (c->conn)
        ngtcp2_conn_del(c->conn);
    if (c->session)
        gnutls_deinit(c->session);
    if (c->cred)
        gnutls_certificate_free_credentials(c->cred);
    if (c->fd >= 0)
        close(c->fd);
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
    .url_close       = http3_close,
    .priv_data_size  = sizeof(HTTP3Context),
    .priv_data_class = &http3_class,
    .flags           = URL_PROTOCOL_FLAG_NETWORK,
};
