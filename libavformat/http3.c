/*
 * HTTP/3 (QUIC) protocol for FFmpeg — work in progress.
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Milestone 2 (skeleton): registers the "http3" URLProtocol and links against
 * ngtcp2 (QUIC transport) + nghttp3 (HTTP/3 framing). The real QUIC connect +
 * GET (UDP socket, ngtcp2 handshake via the GnuTLS crypto helper, nghttp3
 * request, and the event-pump bridging QUIC to a blocking url_read) lands in
 * the next step. For now url_open reports the linked library versions and
 * returns ENOSYS, which proves the build/link/registration end-to-end.
 */

#include "libavutil/log.h"
#include "libavutil/opt.h"
#include "url.h"
#include "avformat.h"

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

typedef struct HTTP3Context {
    const AVClass *class;
    int placeholder;
} HTTP3Context;

static int http3_open(URLContext *h, const char *uri, int flags)
{
    const ngtcp2_info  *qi = ngtcp2_version(0);
    const nghttp3_info *hi = nghttp3_version(0);

    av_log(h, AV_LOG_WARNING,
           "http3: skeleton only — linked ngtcp2 %s, nghttp3 %s; QUIC client not yet implemented\n",
           qi ? qi->version_str : "?", hi ? hi->version_str : "?");

    return AVERROR(ENOSYS);
}

static int http3_read(URLContext *h, unsigned char *buf, int size)
{
    /* M2 skeleton: a real protocol must expose url_read (else avio rejects a
       read-open before url_open and -protocols won't list it). Real body pump
       comes with the QUIC client. */
    return AVERROR_EOF;
}

static int http3_close(URLContext *h)
{
    return 0;
}

static const AVClass http3_class = {
    .class_name = "http3",
    .item_name  = av_default_item_name,
    .option     = NULL,
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
