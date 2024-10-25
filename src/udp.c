/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "logging.h"
#include "proto/gre.h"
#include "proto/protocol_gre.h"
#include "udp-private.h"
#include "rist-private.h"
#include "log-private.h"
#include "socket-shim.h"
#include "endian-shim.h"
#include "proto/rist_time.h"
#include "proto/protocol_rtp.h"
#if HAVE_SRP_SUPPORT
#include "proto/eap.h"
#endif
#include "crypto/psk.h"
#include "mpegts.h"
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>

void rist_clean_sender_enqueue(struct rist_sender *ctx)
{
	int delete_count = 1;

	// Delete old packets (max 10 entries per function call)
	while (delete_count++ < 10) {
		struct rist_buffer *b = ctx->sender_queue[ctx->sender_queue_delete_index];

		/* our buffer size is zero, it must be just building up */
		if ((size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) == ctx->sender_queue_delete_index) {
			break;
		}

		size_t safety_counter = 0;
		while (!b && ((ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1)) != atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire)) {
			ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1);
			// This should never happen!
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
				"Moving delete index to %zu\n",
				ctx->sender_queue_delete_index);
			b = ctx->sender_queue[ctx->sender_queue_delete_index];
			if (safety_counter++ > 1000)
				return;
		}
		if (!b)
			return;

		/* perform the deletion based on the buffer size plus twice the configured/measured avg_rtt */
		uint64_t delay = (timestampNTP_u64() - b->time) / RIST_CLOCK;
		if (delay < ctx->sender_recover_min_time) {
			break;
		}

		//rist_log_priv(&ctx->common, RIST_LOG_WARN,
		//		"\tDeleting %"PRIu32" (%zu bytes) after %"PRIu64" (%zu) ms\n",
		//		b->seq, b->size, delay, ctx->sender_recover_min_time);

		/* now delete it */
		ctx->sender_queue_bytesize -= b->size;
		free_rist_buffer(&ctx->common, b);
		ctx->sender_queue[ctx->sender_queue_delete_index] = NULL;
		ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1);

	}

}

size_t rist_send_seq_rtcp(struct rist_peer *p, uint16_t seq_rtp, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, bool retry)
{
	struct rist_common_ctx *ctx = get_cctx(p);
	uint8_t *data;
	size_t len;
	size_t hdr_len = 0;
	ssize_t ret = 0;

	uint8_t *_payload = NULL;
	_payload = payload;

	// TODO: write directly on the payload to make it faster
	uint8_t header_buf[RIST_MAX_HEADER_SIZE] = {0};
	uint16_t proto_type;
	if (RIST_UNLIKELY(payload_type == RIST_PAYLOAD_TYPE_DATA_OOB)) {
		proto_type = RIST_GRE_PROTOCOL_TYPE_FULL;
	} else {
		proto_type = RIST_GRE_PROTOCOL_TYPE_REDUCED;
		struct rist_protocol_hdr *hdr = (void *) (header_buf);
		hdr->src_port = htobe16(src_port);
		hdr->dst_port = htobe16(dst_port);
		if (payload_type == RIST_PAYLOAD_TYPE_RTCP || payload_type == RIST_PAYLOAD_TYPE_RTCP_NACK)
		{
			hdr_len = RIST_GRE_PROTOCOL_REDUCED_SIZE;
		}
		else
		{
			hdr_len = sizeof(*hdr);
			// RTP header for data packets
			hdr->rtp.flags = RTP_MPEGTS_FLAGS;
			if (payload_type == RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT)
				SET_BIT(hdr->rtp.flags, 4);
			hdr->rtp.ssrc = htobe32(p->adv_flow_id);
			hdr->rtp.seq = htobe16(seq_rtp);
			if (retry)
			{
				// This is a retransmission
				//rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\tResending: %"PRIu32"/%"PRIu16"/%"PRIu32"\n", seq, seq_rtp, ctx->seq);
				/* Mark SSRC for retransmission (change the last bit of the ssrc to 1) */
				//hdr->rtp.ssrc |= (1 << 31);
				hdr->rtp.ssrc = htobe32(p->adv_flow_id | 0x01);
			}
			hdr->rtp.payload_type = RTP_PTYPE_MPEGTS;
			hdr->rtp.ts = htobe32(timestampRTP_u32(0, source_time));
		}
		// copy the rtp header data (needed for encryption)
		memcpy(_payload - hdr_len, hdr, hdr_len);
	}

	{
		len =  hdr_len + payload_len - RIST_GRE_PROTOCOL_REDUCED_SIZE;
		data = _payload - hdr_len + RIST_GRE_PROTOCOL_REDUCED_SIZE;
	}


	// TODO: compare p->sender_ctx->sender_queue_read_index and p->sender_ctx->sender_queue_write_index
	// and warn when the difference is a multiple of 10 (slow CPU or overtaxed algorithm)
	// The difference should always stay very low < 10

	if (RIST_UNLIKELY((p->sender_ctx && p->sender_ctx->simulate_loss) || (p->receiver_ctx && p->receiver_ctx->simulate_loss))) {
		uint16_t loss_percentage = p->sender_ctx? p->sender_ctx->loss_percentage : p->receiver_ctx->loss_percentage;
		/* very crude calculation to see if we "randomly" drop packets, good enough for testing */
		uint16_t compare = rand() % 1001;
		if (compare <= loss_percentage) {
			ret = len;
			goto out;
		}
	}

	if (ctx->profile == RIST_PROFILE_SIMPLE)
		ret = sendto(p->sd,(const char*)data, len, 0, &(p->u.address), p->address_len);
	else
		ret = _librist_proto_gre_send_data(p, payload_type, proto_type, data, len, src_port, dst_port, p->rist_gre_version);

out:
	if (RIST_UNLIKELY(ret <= 0)) {
		rist_log_priv(ctx, RIST_LOG_ERROR, "\tSend failed: errno=%d, ret=%d, socket=%d\n", errno, ret, p->sd);
	} else {
		p->stats_sender_instant.sent++;
		p->stats_receiver_instant.sent_rtcp++;
	}

	return ret;
}

/* This function is used by receiver for all and by sender only for rist-data and oob-data */
int rist_send_common_rtcp(struct rist_peer *p, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp)
{
	// This can only and will most likely be zero for data packets. RTCP should always have a value.
	assert(payload_type != RIST_PAYLOAD_TYPE_DATA_RAW && payload_type != RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT && payload_type != RIST_PAYLOAD_TYPE_DATA_OOB ? dst_port != 0 : 1);
	if (dst_port == 0)
		dst_port = p->config.virt_dst_port;
	if (src_port == 0)
		src_port = 32768 + p->adv_peer_id;

	struct rist_common_ctx *cctx = get_cctx(p);
	if (p->sd < 0 || !p->address_len) {
		rist_log_priv(cctx, RIST_LOG_ERROR, "rist_send_common_rtcp failed\n");
		return -1;
	}

	if (payload_type == RIST_PAYLOAD_TYPE_DATA_RAW || payload_type == RIST_PAYLOAD_TYPE_DATA_OOB)
	{
		if (cctx->oob_current_peer == NULL || cctx->oob_current_peer->dead)
			cctx->oob_current_peer = p;
	}

	if (RIST_UNLIKELY(p->config.timing_mode == RIST_TIMING_MODE_ARRIVAL) && !p->receiver_mode)
		source_time = timestampNTP_u64();

	size_t ret = rist_send_seq_rtcp(p, (uint16_t)seq_rtp, payload_type, payload, payload_len, source_time, src_port, dst_port, false);

	if ((!p->compression && ret < payload_len) || ret <= 0)
	{
		if (p->address_family == AF_INET6) {
			// TODO: print IP and port (and error number?)
			rist_log_priv(cctx, RIST_LOG_ERROR,
				"\tError on transmission sendto for seq #%"PRIu32"\n", seq_rtp);
		} else {
			struct sockaddr_in *sin4 = (struct sockaddr_in *)&p->u.address;
			unsigned char *ip = (unsigned char *)&sin4->sin_addr.s_addr;
			rist_log_priv(cctx, RIST_LOG_ERROR,
				"\tError on transmission sendto, ret=%d to %d.%d.%d.%d:%d/%d, seq #%"PRIu32", %d bytes\n",
					ret, ip[0], ip[1], ip[2], ip[3], htons(sin4->sin_port),
					p->local_port, seq_rtp, payload_len);
		}
	}
	else
	{
		// update bandwidth value
		rist_calculate_bitrate(ret, &p->bw);
	}

	// TODO:
	// This should return something meaningful, however ret is always >= 0 by virtue of being unsigned.
	/*if (ret >= 0)
	 *	return 0;
	 * else
	 *	return -1;
	 */
	return 0;
}

int rist_set_url(struct rist_peer *peer)
{
	char host[512];
	uint16_t port;
	int local;
	if (!peer->url) {
		if (peer->local_port > 0) {
			/* Put sender in IPv4 learning mode */
			peer->address_family = AF_INET;
			peer->address_len = sizeof(struct sockaddr_in);
			memset(&peer->u.address, 0, sizeof(struct sockaddr_in));
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Sender: in learning mode\n");
		}
		return 1;
	}
	if (udpsocket_parse_url(peer->url, host, 512, &port, &local) != 0) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "%s / %s\n", strerror(errno), peer->url);
		return -1;
	} else {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %hu\n",
				(char *) host, port);
	}
	if (udpsocket_resolve_host(host, port, &peer->u.address) < 0) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Host %s cannot be resolved\n",
				(char *) host);
		return -1;
	}
	if (peer->u.inaddr6.sin6_family == AF_INET6) {
		peer->address_family = AF_INET6;
		peer->address_len = sizeof(struct sockaddr_in6);
	} else {
		peer->address_family = AF_INET;
		peer->address_len = sizeof(struct sockaddr_in);
	}
	if (local) {
		peer->listening = 1;
		peer->local_port = port;
	} else {
		peer->listening = 0;
		peer->remote_port = port;
	}
	if (peer->address_family == AF_INET) {
		peer->u.inaddr.sin_port = htons(port);
	} else {
		peer->u.inaddr6.sin6_port = htons(port);
	}
	return 0;
}

void rist_populate_cname(struct rist_peer *peer)
{
	int fd = peer->sd;
	char *identifier = peer->cname;
	struct rist_common_ctx *ctx = get_cctx(peer);
	if (strlen((char *)ctx->cname) != 0)
	{
		strncpy(identifier, (char * )ctx->cname, RIST_MAX_HOSTNAME);
		return;
	}
	/* Set the CNAME Identifier as host@ip:port and fallback to hostname if needed */
	char hostname[RIST_MAX_HOSTNAME];
	struct sockaddr_storage peer_sockaddr;
	peer_sockaddr.ss_family = AF_UNSPEC;
	int name_length = 0;
	socklen_t peer_socklen = sizeof(peer_sockaddr);
	int ret_hostname = gethostname(hostname, RIST_MAX_HOSTNAME);
	if (ret_hostname == -1) {
		snprintf(hostname, RIST_MAX_HOSTNAME, "UnknownHost");
	}

	int ret_sockname = getsockname(fd, (struct sockaddr *)&peer_sockaddr, &peer_socklen);
	if (ret_sockname == 0)
	{
		struct sockaddr *xsa = (struct sockaddr *)&peer_sockaddr;
		// TODO: why is this returning non-sense?
		if (xsa->sa_family == AF_INET) {
			char addr[INET_ADDRSTRLEN] = {'\0'};
			struct sockaddr_in *xin = (struct sockaddr_in*)&peer_sockaddr;
			inet_ntop(AF_INET, &xin->sin_addr, addr, INET_ADDRSTRLEN);
			if (strcmp(addr, "0.0.0.0") != 0) {
				name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s@%s:%u", hostname,
										addr, ntohs(xin->sin_port));
				if (name_length >= RIST_MAX_HOSTNAME)
					identifier[RIST_MAX_HOSTNAME-1] = 0;
			}
		}/* else if (xsa->sa_family == AF_INET6) {
			struct sockaddr_in6 *xin6 = (void*)peer;
			char str[INET6_ADDRSTRLEN];
			inet_ntop(xin6->sin6_family, &xin6->sin6_addr, str, sizeof(struct in6_addr));
			name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s@%s:%u", hostname,
							str, ntohs(xin6->sin6_port));
			if (name_length >= RIST_MAX_HOSTNAME)
				identifier[RIST_MAX_HOSTNAME-1] = 0;
		}*/
	}

	if (name_length == 0)
	{
		name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s", hostname);
		if (name_length >= RIST_MAX_HOSTNAME)
			identifier[RIST_MAX_HOSTNAME-1] = 0;
	}
}

void rist_create_socket(struct rist_peer *peer)
{
	if(!peer->address_family && rist_set_url(peer)) {
		return;
	}

	if (peer->listening) {
		const char* host;
		uint16_t port;

		char buffer[256];
		if (peer->u.address.sa_family == AF_INET) {
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			host = inet_ntop(AF_INET, &(addrv4->sin_addr), buffer, sizeof(buffer));
			port = htons(addrv4->sin_port);
		} else {
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			host = inet_ntop(AF_INET6, &(addrv6->sin6_addr), buffer, sizeof(buffer));
			port = htons(addrv6->sin6_port);
		}
		if (!host) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "failed to convert address to string (errno=%d)", errno);
			return;
		}

		if (peer->u.address.sa_family == AF_INET)
		{
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			peer->multicast_receiver = IN_MULTICAST(ntohl(addrv4->sin_addr.s_addr));
		}
		else
		{
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			peer->multicast_receiver = IN6_IS_ADDR_MULTICAST(&addrv6->sin6_addr);
		}

		peer->sd = udpsocket_open_bind(host, port, peer->miface);
		if (peer->sd >= 0) {
			if (port == 0)
			{
				// Populate peer->local_port with ephemeral port assigned
				struct sockaddr_storage local_addr;
				socklen_t n = sizeof( struct sockaddr_storage );
				if( getsockname( peer->sd, (struct sockaddr *) &local_addr, &n ) != 0)
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Could not find assigned port (socket# %d)\n", peer->sd);
				else
				{
					if (local_addr.ss_family == AF_INET) {
						struct sockaddr_in *a = (struct sockaddr_in *)&local_addr;
						port = a->sin_port;
					} else {
						/* ipv6 */
						struct sockaddr_in6 *a = (struct sockaddr_in6 *)&local_addr;
						port = a->sin6_port;
					}
					peer->local_port = port;
				}
			}
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Starting in URL listening mode (socket# %d)\n", peer->sd);
		} else {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not start in URL listening mode. %s\n", strerror(errno));
		}

		// Set non-blocking only for receive sockets
		udpsocket_set_nonblocking(peer->sd);
	}
	else {
		if (peer->u.address.sa_family == AF_INET)
		{
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			peer->multicast_sender = IN_MULTICAST(ntohl(addrv4->sin_addr.s_addr));
		}
		else
		{
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			peer->multicast_sender = IN6_IS_ADDR_MULTICAST(&addrv6->sin6_addr);
		}
		if (peer->multicast_sender) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Peer configured for multicast\n");
		}
		// We use sendto ... so, no need to connect directly here
		peer->sd = udpsocket_open(peer->address_family);
		// TODO : set max hops
		if (peer->sd >= 0)
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Starting in URL connect mode (%d)\n", peer->sd);
		else {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not start in URL connect mode. %s\n", strerror(errno));
		}
		if (peer->miface[0] != '\0') {
			struct sockaddr_storage ss = {0};
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Binding socket to %s\n", peer->miface);
			if (inet_pton(AF_INET, peer->miface,  &((struct sockaddr_in *)&ss)->sin_addr) != 0) {
				((struct sockaddr_in *)&ss)->sin_family = AF_INET;
				if (bind(peer->sd, (struct sockaddr*)&ss, sizeof(struct sockaddr_in)) != 0) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s: %s\n", peer->miface, strerror(errno));
				}
			}
			else if (inet_pton(AF_INET6, peer->miface, &((struct sockaddr_in6 *)&ss)->sin6_addr) != 0) {
				((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
				((struct sockaddr_in6 *)&ss)->sin6_port =0;
				if (bind(peer->sd, (struct sockaddr*)&ss, sizeof(struct sockaddr_in6)) != 0) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s: %s\n", peer->miface, strerror(errno));
				}
			}
#ifdef __linux__
			else {
				struct ifreq ifr = {0};
				memcpy(ifr.ifr_name, peer->miface, IF_NAMESIZE);
				if (setsockopt(peer->sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) != 0) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s: %s\n", peer->miface, strerror(errno));
				}
			}
#elif defined(__APPLE__)
			else {
				int idx = if_nametoindex(peer->miface);
				if (idx == 0) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't get device %s index: %s\n", peer->miface, strerror(errno));
				} else {
					int proto = peer->u.address.sa_family == AF_INET? IPPROTO_IP : IPPROTO_IPV6;
					int bound = peer->u.address.sa_family == AF_INET? IP_BOUND_IF : IPV6_BOUND_IF;
					if (setsockopt(peer->sd, proto, bound, &idx, sizeof(idx)) != 0) {
						rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s: %s\n", peer->miface, strerror(errno));
					}
				}
			}
#else
			else {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "No method available to bind to %s please supply an IP to bind to\n", peer->miface);
			}
#endif
		}
		peer->local_port = 32768 + (get_cctx(peer)->peer_counter % 28232);
	}

	// Increase default OS udp receive buffer size
	if (udpsocket_set_optimal_buffer_size(peer->sd)) {
		rist_log_priv(get_cctx(peer), RIST_LOG_WARN, "Unable to set the socket receive buffer size to %d Bytes. %s\n",
			UDPSOCKET_SOCK_BUFSIZE, strerror(errno));
	} else {
		uint32_t current_recvbuf = udpsocket_get_buffer_size(peer->sd);
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Configured the starting socket receive buffer size to %d Bytes.\n",
			current_recvbuf);
	}
	// Increase default OS udp send buffer size
	if (udpsocket_set_optimal_buffer_send_size(peer->sd)) {
		rist_log_priv(get_cctx(peer), RIST_LOG_WARN, "Unable to set the socket send buffer size to %d Bytes. %s\n",
			UDPSOCKET_SOCK_BUFSIZE, strerror(errno));
	} else {
		uint32_t current_sendbuf = udpsocket_get_buffer_send_size(peer->sd);
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Configured the starting socket send buffer size to %d Bytes.\n",
			current_sendbuf);
	}

	if (peer->cname[0] == 0)
		rist_populate_cname(peer);
	rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Peer cname is %s\n", peer->cname);
#ifndef _WIN32
	if (fcntl(peer->sd, F_SETFD, FD_CLOEXEC) == -1) {
		udpsocket_close(peer->sd);
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not set close-on-exec\n");
		peer->sd = -1;
	}
#endif
}

int rist_receiver_periodic_rtcp(struct rist_peer *peer) {
	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;

	int payload_len = 0;
	rist_rtcp_write_rr(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (peer->echo_enabled == false)
		rist_rtcp_write_xr_echoreq(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->peer_ssrc);
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0);
}

int rist_receiver_send_nacks(struct rist_peer *peer, uint32_t seq_array[], size_t array_len)
{
	if (get_cctx(peer)->debug)
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Sending %d nacks starting with %"PRIu32"\n",
		array_len, seq_array[0]);
	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;

	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (RIST_LIKELY(array_len > 0)) {
		// Add nack requests (if any)
		struct rist_rtp_nack_record *rec;
		uint32_t fci_count = 1;

		// Now the NACK message
		if (peer->receiver_ctx->nack_type == RIST_NACK_BITMASK)
		{
			struct rist_rtcp_nack_bitmask *rtcp = (struct rist_rtcp_nack_bitmask *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len);
			rtcp->flags = RTCP_NACK_BITMASK_FLAGS;
			rtcp->ptype = PTYPE_NACK_BITMASK;
			rtcp->ssrc_source = 0; // TODO
			rtcp->ssrc = htobe32(peer->adv_flow_id);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + RTCP_FB_HEADER_SIZE);
			uint32_t last_seq, tmp_seq;
			tmp_seq = last_seq = seq_array[0];
			uint32_t boundary = tmp_seq +16;
			rec->start = htons((uint16_t)tmp_seq);
			uint16_t extra = 0;
			for (size_t i = 1; i < array_len; i++)
			{
				tmp_seq = seq_array[i];
				if (last_seq < tmp_seq && tmp_seq <= boundary) {
					uint32_t bitnum = tmp_seq - last_seq;
					SET_BIT(extra, (bitnum -1));
				} else {
					rec->extra = htons(extra);
					rec++;
					fci_count++;
					extra = 0;
					rec->start = htons((uint16_t)tmp_seq);
					last_seq = tmp_seq;
					boundary = tmp_seq + 16;
				}
			}
			rec->extra = htons(extra);
			rtcp->len = htons((uint16_t)(2 + fci_count));
		}
		else // PTYPE_NACK_CUSTOM
		{
			struct rist_rtcp_nack_range *rtcp = (struct rist_rtcp_nack_range *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len);
			rtcp->flags = RTCP_NACK_RANGE_FLAGS;
			rtcp->ptype = PTYPE_NACK_CUSTOM;
			rtcp->ssrc_source = htobe32(peer->adv_flow_id);
			memcpy(rtcp->name, "RIST", 4);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + RTCP_FB_HEADER_SIZE);
			uint16_t tmp_seq = (uint16_t)seq_array[0];
			uint16_t last_seq = tmp_seq;
			rec->start = htons(tmp_seq);
			uint16_t extra = 0;
			for (size_t i = 1; i < array_len; i++)
			{
				tmp_seq = (uint16_t)seq_array[i];
				if (RIST_UNLIKELY(extra == UINT16_MAX)) {
					rec->extra = htons(extra);
					rec++;
					fci_count++;
					rec->start = htons(tmp_seq);
					extra = 0;
				} else if (tmp_seq == last_seq +1) {
					extra++;
				} else {
					rec->extra = htons(extra);
					rec++;
					fci_count++;
					rec->start = htons(tmp_seq);
					extra = 0;
				}
				last_seq = tmp_seq;
			}
			rec->extra = htons(extra);
			rtcp->len = htons((uint16_t)(2 + fci_count));
		}
		int nack_bufsize = RTCP_FB_HEADER_SIZE + RTCP_FB_FCI_GENERIC_NACK_SIZE * fci_count;
		payload_len += nack_bufsize;
		payload_type = RIST_PAYLOAD_TYPE_RTCP_NACK;
	}

	// We use direct send from receiver to sender (no fifo to keep track of seq/idx)
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0);
}

static void rist_sender_send_rtcp(uint8_t *rtcp_buf, int payload_len, struct rist_peer *peer) {
	rist_send_common_rtcp(peer, RIST_PAYLOAD_TYPE_RTCP, rtcp_buf, payload_len, 0, peer->local_port, peer->remote_port, 0);
}

void rist_sender_periodic_rtcp(struct rist_peer *peer) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;

	rist_rtcp_write_sr(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (peer->echo_enabled)
		rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->peer_ssrc);
	// Push it to the FIFO buffer to be sent ASAP (even in the simple profile case)
	rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
	return;
}

int rist_respond_echoreq(struct rist_peer *peer, const uint64_t echo_request_time, uint32_t ssrc) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	rist_rtcp_write_echoresp(rtcp_buf, &payload_len, echo_request_time, ssrc);
	if (peer->receiver_mode) {
		uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
		return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0);
	} else {
		/* I do this to not break advanced mode, however echo responses should really NOT be resend when lost ymmv */
		rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
		return 0;
	}
}

int rist_request_echo(struct rist_peer *peer) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->peer_ssrc);
	if (peer->receiver_mode)
	{
		uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
		return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0);
	}
	else
	{
		rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
		return 0;
	}
}

int rist_sender_enqueue(struct rist_sender *ctx, const void *data, size_t len, uint64_t datagram_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp)
{
	uint8_t payload_type = RIST_PAYLOAD_TYPE_DATA_RAW;
	const void * payload = data;
	if (ctx->common.PEERS == NULL) {
		// Do not cache data if the lib user has not added peers
		return -1;
	}

	ctx->last_datagram_time = datagram_time;
	uint8_t tmp_buf[6 * 204 + 4];//Max size needed with at least 1 pkt suppressed
	if (ctx->null_packet_suppression && len <= 7 * 204)
	{

		struct rist_rtp_hdr_ext *hdr_ext = (struct rist_rtp_hdr_ext *)&tmp_buf;
		memset(tmp_buf, 0, sizeof(*hdr_ext));//hdr_ext
		if (suppress_null_packets(data, &tmp_buf[sizeof(*hdr_ext)], &len, hdr_ext) > 0)
		{
			memcpy(&hdr_ext->identifier, "RI", 2);
			hdr_ext->length = htobe16(1);
			len += sizeof(*hdr_ext);
			payload = tmp_buf;
			payload_type = RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT;
		}
	}

	/* insert into sender fifo queue */
	pthread_mutex_lock(&ctx->queue_lock);
	size_t sender_write_index = atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire);
	ctx->sender_queue[sender_write_index] = rist_new_buffer(&ctx->common, payload, len, payload_type, 0, datagram_time, src_port, dst_port);
	if (RIST_UNLIKELY(!ctx->sender_queue[sender_write_index])) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\t Could not create packet buffer inside sender buffer, OOM, decrease max bitrate or buffer time length\n");
		pthread_mutex_unlock(&ctx->queue_lock);
		return -1;
	}
	ctx->sender_queue[sender_write_index]->seq_rtp = (uint16_t)seq_rtp;
	ctx->sender_queue_bytesize += len;
	atomic_store_explicit(&ctx->sender_queue_write_index, (sender_write_index + 1) & (ctx->sender_queue_max - 1), memory_order_release);
	pthread_mutex_unlock(&ctx->queue_lock);

	return 0;
}

void rist_sender_send_data_balanced(struct rist_sender *ctx, struct rist_buffer *buffer)
{
	struct rist_peer *peer;
	struct rist_peer *selected_peer_by_weight = NULL;
	uint32_t max_remainder = 0;
	int peercnt;
	bool looped = false;

	//We can do it safely here, since this function is only to be called once per packet
	buffer->seq = ctx->common.seq++;
	uint64_t now = timestampNTP_u64();

peer_select:

	peercnt = 0;
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {

		if (!peer->is_data || peer->parent)
			continue;
#if HAVE_SRP_SUPPORT
		if (!peer->listening && !peer->multicast_sender && !eap_is_authenticated(peer->eap_ctx))
			continue;
#endif
		if ((!peer->listening && !peer->authenticated) || peer->dead
			|| (peer->listening && !peer->child_alive_count)) {
			ctx->weight_counter -= peer->config.weight;
			if (ctx->weight_counter <= 0) {
				ctx->weight_counter = ctx->total_weight;
			}
			peer->w_count = peer->config.weight;
			continue;
		}
		peercnt++;

		/*************************************/
		/* * * * * * * * * * * * * * * * * * */
		/** Heuristics for sender goes here **/
		/* * * * * * * * * * * * * * * * * * */
		/*************************************/

		if (peer->config.weight == 0 && !looped) {
			if (peer->listening) {
				struct rist_peer *child = peer->child;
				while (child) {
#if HAVE_SRP_SUPPORT
					if (!eap_is_authenticated(child->eap_ctx))
					{
						//do nothing
					} else
#endif
					if (child->authenticated && child->is_data && (!child->dead || (child->dead && (child->dead_since + peer->recovery_buffer_ticks) < now))) {
						uint8_t *payload = buffer->data;
						rist_send_common_rtcp(child, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq_rtp);
					}
					child = child->sibling_next;
				}
			} else if (!peer->dead || (peer->dead && (peer->dead_since + peer->recovery_buffer_ticks) < now)) {
				uint8_t *payload = buffer->data;
				rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq_rtp);
			}
		} else {
			/* Election of next peer */
			// printf("peer election: considering %p, count=%d (wc: %d)\n",
			// peer, peer->w_count, ctx->weight_counter);
			if (peer->w_count > max_remainder) {
				max_remainder = peer->w_count;
				selected_peer_by_weight = peer;
			}
		}
	}
	looped = true;
	if (selected_peer_by_weight) {
		peer = selected_peer_by_weight;
		if (peer->listening) {
			struct rist_peer *child = peer->child;
			while (child) {
#if HAVE_SRP_SUPPORT
					if (!eap_is_authenticated(child->eap_ctx))
					{
						//do nothing
					} else
#endif
				if (child->authenticated && child->is_data && (!child->dead || (child->dead && (child->dead_since + peer->recovery_buffer_ticks) < now))) {
					uint8_t *payload = buffer->data;
					rist_send_common_rtcp(child, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port,  buffer->seq_rtp);
				}
				child = child->sibling_next;
			}
		} else if (!peer->dead || (peer->dead && (peer->dead_since + peer->recovery_buffer_ticks) < now)) {
			uint8_t *payload = buffer->data;
			rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq_rtp);
		}
		ctx->weight_counter--;
		peer->w_count--;
	}

	if (ctx->total_weight > 0 && (ctx->weight_counter == 0 || !selected_peer_by_weight)) {
		peer = ctx->common.PEERS;
		ctx->weight_counter = ctx->total_weight;
		for (; peer; peer = peer->next) {
			peer->w_count = peer->config.weight;
		}
		if (!looped && !selected_peer_by_weight && peercnt > 0)
			goto peer_select;
	}
}

static size_t rist_sender_index_get(struct rist_sender *ctx, uint32_t seq)
{
	size_t idx = ctx->seq_index[(uint16_t)seq];
	return idx;
}

size_t rist_get_sender_retry_queue_size(struct rist_sender *ctx)
{
	size_t retry_queue_size = (ctx->sender_retry_queue_write_index - ctx->sender_retry_queue_read_index)
							& (ctx->sender_retry_queue_size - 1);
	return retry_queue_size;
}

/* This function must return, 0 when there is nothing to send, < 0 on error and > 0 for bytes sent */
ssize_t rist_retry_dequeue(struct rist_sender *ctx)
{
	size_t sender_retry_queue_read_index = (ctx->sender_retry_queue_read_index + 1)& (ctx->sender_retry_queue_size -1);

	if (sender_retry_queue_read_index == ctx->sender_retry_queue_write_index) {
		return 0;
	}

	ctx->sender_retry_queue_read_index = sender_retry_queue_read_index;
	struct rist_retry *retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_read_index];

	// If they request a non-sense seq number, we will catch it when we check the seq number against
	// the one on that buffer position and it does not match

	size_t idx = rist_sender_index_get(ctx, retry->seq);
	if (RIST_UNLIKELY(ctx->sender_queue[idx] == NULL)) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			" Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), consider increasing the buffer size\n",
			retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx));
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	} else if (RIST_UNLIKELY((uint16_t)retry->seq != ctx->sender_queue[idx]->seq_rtp)) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			" Couldn't find block %" PRIu16 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), found an old one instead %" PRIu32 " (%" PRIu64 "), bitrate is too high\n",
			(uint16_t)retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx), ctx->sender_queue[idx]->seq_rtp, ctx->sender_queue_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}
	/* we're consuming the retry for an existing buffer, set it to false to allow new retries to come in */
	ctx->sender_queue[idx]->retry_queued = false;
	retry->active = false;

	// TODO: re-enable rist_send_data_allowed (cooldown feature)

	struct rist_bandwidth_estimation *retry_bw = &retry->peer->retry_bw;
	struct rist_bandwidth_estimation *cli_bw = &retry->peer->bw;
	if (retry->peer->peer_data)
	{
		retry_bw = &retry->peer->peer_data->retry_bw;
	}
	// update bandwidth values
	rist_calculate_bitrate(0, cli_bw);
	rist_calculate_bitrate(0, retry_bw);

	// Make sure we do not flood the network with retries
	size_t current_bitrate = 0;
	size_t data_bitrate = 0;
	size_t retry_bitrate = 0;
	if (retry->peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
		data_bitrate = cli_bw->eight_times_bitrate_fast / 8;
		retry_bitrate = retry_bw->eight_times_bitrate_fast / 8;
	} else if (retry->peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_NORMAL) {
		data_bitrate = cli_bw->eight_times_bitrate / 8;
		retry_bitrate = retry_bw->eight_times_bitrate_fast / 8;
	} else {
		data_bitrate = cli_bw->eight_times_bitrate / 8;
		retry_bitrate = retry_bw->eight_times_bitrate / 8;
	}
	current_bitrate =  data_bitrate + retry_bitrate;
	size_t max_bitrate = retry->peer->config.recovery_maxbitrate * 1000;
	if (current_bitrate > max_bitrate) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG, "Max bandwidth exceeded: (%zu + %zu) > %zu, not resending packet %"PRIu64".\n",
			data_bitrate, retry_bitrate, max_bitrate, idx);
		retry->peer->stats_sender_instant.bandwidth_skip++;
		return -2;
	}

	// Check buffer element age
	uint64_t now = timestampNTP_u64();
	/* queue_time holds the original insertion time for this seq */
	uint64_t data_age = (now - ctx->sender_queue[idx]->time) / RIST_CLOCK;
	uint64_t retry_age = (now - retry->insert_time) / RIST_CLOCK;
	if (RIST_UNLIKELY(retry_age > retry->peer->config.recovery_length_max)) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Retry-request of element %" PRIu32 " (idx %zu) that was sent %" PRIu64
				"ms ago has been in the queue too long to matter: %"PRIu64"ms > %ums\n",
			retry->seq, idx, data_age, retry_age, retry->peer->config.recovery_length_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	struct rist_buffer *buffer = ctx->sender_queue[idx];
	if (ctx->common.debug)
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Resending %"PRIu32"/%"PRIu32"/%"PRIu16" (idx %zu) after %" PRIu64
			"ms of first transmission and %"PRIu64"ms in queue, bitrate is %zu + %zu, %zu\n",
			retry->seq, buffer->seq, buffer->seq_rtp, idx, data_age, retry_age, data_bitrate,
			retry_bitrate, current_bitrate);

	uint8_t *payload = buffer->data;

	size_t ret = 0;
	if (buffer->transmit_count >= retry->peer->config.max_retries) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Datagram %"PRIu32
			" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu\n",
			retry->seq, buffer->transmit_count, data_age, buffer->transmit_count);
			retry->peer->stats_sender_instant.retrans_skip++;
			return -1;
	}

	uint16_t src_port = buffer->src_port;
	if (src_port == 0)
		src_port = 32768 + retry->peer->peer_data->adv_peer_id;
	ret = (size_t)rist_send_seq_rtcp(retry->peer->peer_data, buffer->seq_rtp, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, src_port, (retry->peer->peer_data->config.virt_dst_port & ~1UL), true);
	// update bandwidth value
	rist_calculate_bitrate(ret, retry_bw);

	if (ret < buffer->size) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Resending of packet failed %zu != %zu for seq %"PRIu32"\n", ret, buffer->size, retry->seq);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	buffer->transmit_count++;
	if (retry->peer->peer_data)
		retry->peer->peer_data->stats_sender_instant.retrans++;
	else
		retry->peer->stats_sender_instant.retrans++;
	return ret;
}

void rist_retry_enqueue(struct rist_sender *ctx, uint32_t seq, struct rist_peer *peer)
{
	uint64_t now = timestampNTP_u64();
	size_t idx = rist_sender_index_get(ctx, seq);
	struct rist_buffer *buffer = ctx->sender_queue[idx];
	struct rist_retry *retry;

	// Even though all the checks are on the dequeue function, we leave one here
	// to prevent the flooding of our fifo .. It is based on the date of the
	// last queued item with the same seq for this peer.
	// The policy of whether to allow or not allow duplicate inactive seq entries in the retry queue
	// is dependent on the bloat_mode.
	// No duplicate unhandled (i.e.: still queued) retries are accepted.
	// bloat_mode disabled mode = unlimited duplicates
	// bloat_mode normal mode = we enforce rtt spacing and allow duplicates
	// bloat_mode aggressive mode = we enforce 2*rtt spacing and allow duplicates
	// This is a safety check to protect against buggy or non compliant receivers that request the
	// same seq number without waiting one RTT.

	if (peer->config.recovery_mode == RIST_RECOVERY_MODE_DISABLED) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Nack request for seq %"PRIu32" but nack processing is disabled for this peer\n", seq);
			peer->stats_sender_instant.retrans_skip++;
		return;
	}
	else if (!buffer) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Nack request for seq %"PRIu32" but we do not have it in the buffer (%zu ms)\n", seq,
			ctx->sender_recover_min_time);
			peer->stats_sender_instant.retrans_skip++;
		return;
	} else {
		uint64_t age_ticks =  (now - buffer->time);
		if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_OFF) {
			// All duplicates allowed, just report it
			if (ctx->common.debug)
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Nack request for seq %" PRIu32 " with age %" PRIu64 "ms and rtt_min %" PRIu64 " for peer #%d\n",
					seq, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min / RIST_CLOCK, peer->adv_peer_id);
		} else if (ctx->peer_lst_len == 1) {
			/* there is a retry outstanding for this buffer, no need to add another */
			if (buffer->retry_queued)
				return;
			// Only one peer (faster algorithm with no lookups)
			if (buffer->last_retry_request != 0)
			{
				// This is a safety check to protect against buggy or non compliant receivers that request the
				// same seq number without waiting one RTT.
				uint64_t delta = (now - buffer->last_retry_request);
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms, age %" PRIu64 "ms and rtt_min %" PRIu64 "\n",
						seq, delta /RIST_CLOCK, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min / RIST_CLOCK);
				uint64_t rtt = peer->last_rtt;
				if (peer->config.recovery_rtt_min > rtt)
					rtt = peer->config.recovery_rtt_min;
				if (peer->config.recovery_rtt_max < rtt)
					rtt = peer->config.recovery_rtt_max;
				if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
					// Aggressive congestion control only allows every two RTTs
					rtt = rtt * 2;
				}
				if (delta < rtt)
				{
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 ", age %"PRIu64"ms, is already queued (too soon to add another one), skipped, %" PRIu64 " < %" PRIu64 " ms\n",
						seq, age_ticks / RIST_CLOCK, delta / RIST_CLOCK, rtt);
					peer->stats_sender_instant.bloat_skip++;
					return;
				}
				buffer->retry_queued = true;
			}
			else
			{
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"First nack request for seq %"PRIu32", age %"PRIu64"ms\n", seq, age_ticks / RIST_CLOCK);
			}
		} else {
			// Multiple peers, we need to search for other retries in the queue for comparison
			uint64_t delta = 0;
			//We work backwards from the write index till we either find a retry with same peer & seq
			//or it's too old to matter,looking up to 8 RTT's ago (4 in normal mode, 8 in aggressive)
			size_t index = (ctx->sender_retry_queue_write_index -1) & (ctx->sender_retry_queue_size -1);
			uint64_t rtt = peer->last_rtt;
			if (peer->config.recovery_length_min > rtt)
				rtt = peer->config.recovery_length_min;
			// Aggressive congestion control only allows every two RTTs
			if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE)
				rtt *= 2;
			struct rist_retry *lookup = NULL;
			uint64_t search_period = rtt * 4;
			while (index != ctx->sender_retry_queue_write_index) {
				lookup = &ctx->sender_retry_queue[index];
				if (lookup->seq == seq && lookup->peer == peer)
					break;
				if (lookup->insert_time < (now - search_period))
					break;
				index = (index -1 ) & (ctx->sender_retry_queue_size -1);
			}
			retry = &ctx->sender_retry_queue[index];
			if (retry->seq == seq && retry->peer == peer) {
				delta = (now - retry->insert_time);
				/* this retry hasn't been handled yet, it makes no sense to insert a duplicate */
				if (retry->active)
					return;
				if (delta < rtt)
				{
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) is already queued (too soon to add another one), skipped, peer #%d '%s'\n",
						seq, delta / RIST_CLOCK, age_ticks / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
					peer->stats_sender_instant.bloat_skip++;
					return;
				}
			}
			if (ctx->common.debug) {
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) and rtt_min %" PRIu64 " for peer #%"PRIu32" '%s'\n",
					seq, delta / RIST_CLOCK, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
			}
		}
	}
	// Now insert into the missing queue
	buffer->last_retry_request = now;
	retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_write_index];
	retry->seq = seq;
	retry->peer = peer;
	retry->insert_time = now;
	retry->active = true;
	if (++ctx->sender_retry_queue_write_index >= ctx->sender_retry_queue_size) {
		ctx->sender_retry_queue_write_index = 0;
	}
}

void rist_print_inet_info(char *prefix, struct rist_peer *peer)
{
	char ipstr[INET6_ADDRSTRLEN];
	uint32_t port;
	// deal with both IPv4 and IPv6:
	struct sockaddr_in6 *s = (struct sockaddr_in6 *) &peer->u.address;
	inet_ntop(peer->address_family, &s->sin6_addr, ipstr, sizeof ipstr);
	if (peer->address_family == AF_INET6) {
		port = ntohs(s->sin6_port);
	} else {
		struct sockaddr_in *addr = (void *) &peer->u.address;
		port = ntohs(addr->sin_port);
	}

	struct rist_common_ctx *ctx = get_cctx(peer);
	if (ctx->profile == RIST_PROFILE_SIMPLE)
	{
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			"%sPeer Information, IP:Port => %s:%u (%d), id: %"PRIu32", simple profile\n",
			prefix, ipstr, port, peer->listening, peer->adv_peer_id);
	}
	else
	{
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			"%sPeer Information, IP:Port => %s:%u (%d), id: %"PRIu32", ports: %u->%u\n",
			prefix, ipstr, port, peer->listening, peer->adv_peer_id,
			peer->local_port, peer->remote_port);
	}

}

