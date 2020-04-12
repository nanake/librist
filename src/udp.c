/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "udp-private.h"
#include "rist-private.h"
#include "aes.h"
#include "fastpbkdf2.h"
#include "crypto-private.h"
#include "log-private.h"
#include "socket-shim.h"
#include "endian-shim.h"
#include "lz4/lz4.h"
#include "network.h"
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

/*
bool url_params_parse(char* url, srt_params_t* params)
{
    char* query = NULL;
    struct parsed_param local_params[32];
    int num_params = 0;
    int i = 0;
    bool rc = false;

    if (!url || !url[0] || !params)
        return false;

    // initialize params 
    params->latency = -1;
    params->passphrase = NULL;
    params->key_length = -1;
    params->payload_size = -1;
    params->bandwidth_overhead_limit = -1;

    // Parse URL parameters
    query = find( url, '?' );
    if (query) {
        num_params = srt_url_parse_query( query, "&", local_params,
                sizeof(local_params) / sizeof(struct parsed_param) );
        if (num_params > 0) {
            rc = true;
            for (i = 0; i < num_params; ++i) {
                char* val = local_params[i].val;
                if (!val)
                    continue;

                if (strcmp( local_params[i].key, SRT_PARAM_LATENCY ) == 0) {
                    int temp = atoi( val );
                    if (temp >= 0)
                        params->latency = temp;
                } else if (strcmp( local_params[i].key, SRT_PARAM_PASSPHRASE )
                        == 0) {
                    params->passphrase = val;
                } else if (strcmp( local_params[i].key, SRT_PARAM_PAYLOAD_SIZE )
                        == 0) {
                    int temp = atoi( val );
                    if (temp >= 0)
                        params->payload_size = temp;
                } else if (strcmp( local_params[i].key, SRT_PARAM_KEY_LENGTH )
                        == 0) {
                    int temp = atoi( val );
                    if (temp == srt_key_lengths[0] || temp == srt_key_lengths[1]
                            || temp == srt_key_lengths[2]) {
                        params->key_length = temp;
                    }
                } else if (strcmp( local_params[i].key,
                SRT_PARAM_BANDWIDTH_OVERHEAD_LIMIT ) == 0) {
                    int temp = atoi( val );
                    if (temp >= 0)
                        params->bandwidth_overhead_limit = temp;

                }
            }
        }
    }

    return rc;
}
*/

void rist_clean_sender_enqueue(struct rist_sender *ctx)
{
	int delete_count = 1;

	// Delete old packets (max 10 entries per function call)
	while (delete_count++ < 10) {
		struct rist_buffer *b = ctx->sender_queue[ctx->sender_queue_delete_index];

		size_t safety_counter = 0;
		while (!b) {
			ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1) % ctx->sender_queue_max;
			// This should never happen!
			msg(0, ctx->id, RIST_LOG_ERROR,
				"[ERROR] Moving delete index to %zu\n",
				ctx->sender_queue_delete_index);
			b = ctx->sender_queue[ctx->sender_queue_delete_index];
			if (safety_counter++ > 1000)
				return;
		}

		/* our buffer size is zero, it must be just building up */
		if (ctx->sender_queue_write_index == ctx->sender_queue_delete_index) {
			break;
		}

		/* perform the deletion based on the buffer size plus twice the configured/measured avg_rtt */
		uint64_t delay = (timestampNTP_u64() - b->time) / RIST_CLOCK;
		if (delay < ctx->sender_recover_min_time) {
			break;
		}

		//msg(0, ctx->id, RIST_LOG_WARN,
		//		"\tDeleting %"PRIu32" (%zu bytes) after %"PRIu64" (%zu) ms\n",
		//		b->seq, b->size, delay, ctx->sender_recover_min_time);

		/* now delete it */
		ctx->sender_queue_bytesize -= b->size;
		free(b->data);
		free(b);
		ctx->sender_queue[ctx->sender_queue_delete_index] = NULL;
		ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1) % ctx->sender_queue_max;

	}

}

static uint32_t rand_u32(void)
{
	uint32_t u32;
	uint8_t *u8 = (void *) &u32;

	for (size_t i = 0; i < sizeof(u32); i++) {
		u8[i] = rand() % 256;
	}

	return u32;
}

static void _ensure_key_is_valid(struct rist_key *key)
{
	bool new_nonce = false;

	if (!key->gre_nonce) {
		// Generate new nonce as we do not have any
		new_nonce = true;
	} else if (key->used_times > RIST_AES_KEY_REUSE_TIMES) {
		// Key can only be used upto certain times
		new_nonce = true;
	}

	if (new_nonce) {
		do {
			key->gre_nonce = rand_u32();
		} while (!key->gre_nonce);

		key->used_times = 0;

		// The nonce MUST be fed to the function in network byte order
		uint32_t nonce_be = be32toh(key->gre_nonce);
		uint8_t aes_key[256 / 8];
		fastpbkdf2_hmac_sha256(
			(const void *) key->password, strlen(key->password),
			(const void *) &nonce_be, sizeof(nonce_be),
			RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
			aes_key, key->key_size / 8);
/*
		int i=0;
		fprintf(stderr, "KEY: nonce %"PRIu32", size %d, pwd=%s : ", key->gre_nonce, 
		key->key_size, key->password);
		while (i < key->key_size/8)
		{
			fprintf(stderr, "%02X ",(int)aes_key[i]);
			i++;
		}
		fprintf(stderr, "\n");
*/
		aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
	}
}

size_t rist_send_seq_rtcp(struct rist_peer *p, uint32_t seq, uint16_t seq_rtp, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	intptr_t receiver_id = p->receiver_ctx ? p->receiver_ctx->id : 0;
	intptr_t sender_id = p->sender_ctx ? p->sender_ctx->id : 0;

	struct rist_common_ctx *ctx = get_cctx(p);
	struct rist_key *k = &ctx->SECRET;
	uint8_t *data;
	size_t len, gre_len;
	size_t hdr_len = 0;
	size_t ret = 0;

	//if (p->receiver_mode)
	//	msg(receiver_id, sender_id, RIST_LOG_ERROR, "Sending seq %"PRIu32" and rtp_seq %"PRIu16" payload is %d\n", 
	//		seq, seq_rtp, payload_type);
	//else
	//	msg(receiver_id, sender_id, RIST_LOG_ERROR, "Sending seq %"PRIu32" and idx is %zu/%zu/%zu (read/write/delete) and payload is %d\n", 
	//		seq, p->sender_ctx->sender_queue_read_index, 
	//		p->sender_ctx->sender_queue_write_index, 
	//		p->sender_ctx->sender_queue_delete_index,
	//		payload_type);

	// TODO: write directly on the payload to make it faster
	uint8_t header_buf[RIST_MAX_HEADER_SIZE] = {0};
	if (k->key_size) {
		gre_len = sizeof(struct rist_gre_key_seq);
	} else {
		gre_len = sizeof(struct rist_gre_seq);
	}

	uint16_t proto_type;
	if (RIST_UNLIKELY(payload_type == RIST_PAYLOAD_TYPE_DATA_OOB)) {
		proto_type = RIST_GRE_PROTOCOL_TYPE_FULL;
	} else {
		proto_type = RIST_GRE_PROTOCOL_TYPE_REDUCED;
		struct rist_protocol_hdr *hdr = (void *) (header_buf + gre_len);
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
			hdr->rtp.ssrc = htobe32(p->adv_flow_id);

			if (seq != ctx->seq)
			{
				// This is a retranmission
				//msg(receiver_id, sender_id, RIST_LOG_ERROR, "\tResending: %"PRIu32"/%"PRIu16"\n", seq, seq_rtp);
				/* Mark SSID for retransmission (change the last bit of the ssrc to 1) */
				//hdr->rtp.ssrc |= (1 << 31);
				// TODO: fix this with an OR instead
				hdr->rtp.ssrc = htobe32(p->adv_flow_id + 1);
			}
			hdr->rtp.payload_type = MPEG_II_TRANSPORT_STREAM;
			hdr->rtp.ts = htobe32(timestampRTP_u32(source_time));
			hdr->rtp.seq = htobe16(seq_rtp);
		}
		// copy the rtp header data (needed for encryption)
		memcpy(payload - hdr_len, hdr, hdr_len);
	}

	if (ctx->profile > RIST_PROFILE_SIMPLE) {
		/* Encrypt everything except GRE */
		if (k->key_size) {
			_ensure_key_is_valid(k);

			// Prepare GRE header
			struct rist_gre_key_seq *gre_key_seq = (void *) header_buf;
			SET_BIT(gre_key_seq->flags1, 7); // set checksum bit
			SET_BIT(gre_key_seq->flags1, 5); // set key flag
			SET_BIT(gre_key_seq->flags1, 4); // set seq bit
			// Peer ID (TODO: do it more elegantly)
			if (CHECK_BIT(p->adv_peer_id, 0)) SET_BIT(gre_key_seq->flags1, 3);
			if (CHECK_BIT(p->adv_peer_id, 1)) SET_BIT(gre_key_seq->flags1, 2);
			if (CHECK_BIT(p->adv_peer_id, 2)) SET_BIT(gre_key_seq->flags1, 1);
			if (CHECK_BIT(p->adv_peer_id, 3)) SET_BIT(gre_key_seq->flags1, 0);
			// Payload type (TODO: do it more elegantly)
			if (CHECK_BIT(payload_type, 0)) SET_BIT(gre_key_seq->flags2, 7);
			if (CHECK_BIT(payload_type, 1)) SET_BIT(gre_key_seq->flags2, 6);
			if (CHECK_BIT(payload_type, 2)) SET_BIT(gre_key_seq->flags2, 5);
			if (CHECK_BIT(payload_type, 3)) SET_BIT(gre_key_seq->flags2, 4);
			SET_BIT(gre_key_seq->flags2, 3); // set advanced protocol identifier

			gre_key_seq->prot_type = htobe16(proto_type);
			gre_key_seq->checksum_reserved1 = htobe32((uint32_t)(source_time >> 32));
			gre_key_seq->nonce = htobe32(k->gre_nonce);
			gre_key_seq->seq = htobe32(seq);

			/* Prepare AES IV */
			uint8_t IV[AES_BLOCK_SIZE];
			// The byte array needs to be zeroes and then the seq in network byte order
			uint32_t seq_be = gre_key_seq->seq;
			memset(IV, 0, 12);
			memcpy(IV + 12, &seq_be, sizeof(seq_be));

			// Encrypt everything other than GRE
			k->used_times++;
	/*
			int i=0;
			fprintf(stderr, "IV: seq %"PRIu32"(%d): ", seq,  k->key_size);
			while (i < sizeof(IV))
			{
				fprintf(stderr, "%02X ",(int)IV[i]);
				i++;
			}
			fprintf(stderr, "\n");
	*/
			aes_encrypt_ctr((const void *) (payload - hdr_len), hdr_len + payload_len, 
				(void *) (payload - hdr_len), k->aes_key_sched, k->key_size, IV);

		} else {
			struct rist_gre_seq *gre_seq = (struct rist_gre_seq *) header_buf;
			SET_BIT(gre_seq->flags1, 7); // set checksum bit
			SET_BIT(gre_seq->flags1, 4); // set seq bit
			// Peer ID (TODO: do it more elegantly)
			if (CHECK_BIT(p->adv_peer_id, 0)) SET_BIT(gre_seq->flags1, 3);
			if (CHECK_BIT(p->adv_peer_id, 1)) SET_BIT(gre_seq->flags1, 2);
			if (CHECK_BIT(p->adv_peer_id, 2)) SET_BIT(gre_seq->flags1, 1);
			if (CHECK_BIT(p->adv_peer_id, 3)) SET_BIT(gre_seq->flags1, 0);
			// Payload type (TODO: do it more elegantly)
			if (CHECK_BIT(payload_type, 0)) SET_BIT(gre_seq->flags2, 7);
			if (CHECK_BIT(payload_type, 1)) SET_BIT(gre_seq->flags2, 6);
			if (CHECK_BIT(payload_type, 2)) SET_BIT(gre_seq->flags2, 5);
			if (CHECK_BIT(payload_type, 3)) SET_BIT(gre_seq->flags2, 4);
			SET_BIT(gre_seq->flags2, 3); // set advanced protocol identifier
		
			gre_seq->prot_type = htobe16(proto_type);
			gre_seq->checksum_reserved1 = htobe32((uint32_t)(source_time >> 32));
			gre_seq->seq = htobe32(seq);
		}

		// now copy the GRE header data
		len = gre_len + hdr_len + payload_len;
		data = payload - gre_len - hdr_len;
		memcpy(data, header_buf, gre_len);
	}
	else
	{
		len =  hdr_len + payload_len - RIST_GRE_PROTOCOL_REDUCED_SIZE;
		data = payload - hdr_len + RIST_GRE_PROTOCOL_REDUCED_SIZE;
	}

	// TODO: compare p->sender_ctx->sender_queue_read_index and p->sender_ctx->sender_queue_write_index
	// and warn when the difference is a multiple of 10 (slow CPU or overtaxed algortihm)
	// The difference should always stay very low < 10

	ret = sendto(p->sd, data, len, 0, &(p->u.address), p->address_len);
	if (ret < 0) {
		msg(receiver_id, sender_id, RIST_LOG_ERROR, "\tSend failed: %d\n", ret);
	} else {
		rist_calculate_bitrate_sender(len, &p->bw);
		p->stats_sender_instant.sent++;
	}

	return ret;
}

/* This function is used by receiver for all and by sender only for rist-data and oob-data */
int rist_send_common_rtcp(struct rist_peer *p, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, bool duplicate)
{
	intptr_t receiver_id = p->receiver_ctx ? p->receiver_ctx->id : 0;
	intptr_t sender_id = p->sender_ctx ? p->sender_ctx->id : 0;

	// This can only and will most likely be zero for data packets. RTCP should always have value.
	// TODO: add warning message if it is zero for non data packet
	if (dst_port == 0)
		dst_port = p->config.virt_dst_port;

	struct rist_common_ctx *ctx = get_cctx(p);

	if (p->sd < 0 || !p->address_len) {
		msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] rist_send_common_rtcp failed\n");		
		return -1;
	}

	if (!duplicate)
		ctx->seq++;

	if (!duplicate && payload_type == RIST_PAYLOAD_TYPE_DATA_RAW)
		ctx->seq_rtp++;

	size_t ret = 0;
	if (p->sender_ctx && p->sender_ctx->simulate_loss && !(ctx->seq % 1000)) {
	//if (p->sender_ctx && !(ctx->seq % 1000)) {// && payload_type == RIST_PAYLOAD_TYPE_RTCP) {
		ret = payload_len;
		//msg(receiver_id, sender_id, RIST_LOG_ERROR,
		//	"\tSimulating lost packet for seq #%"PRIu32"\n", ctx->seq);
	} else {
		ret = rist_send_seq_rtcp(p, ctx->seq, ctx->seq_rtp, payload_type, payload, payload_len, source_time, src_port, dst_port);
	}

	if (ret < payload_len) 
	{
		if (p->address_family == AF_INET6) {
			// TODO: print IP and port (and error number?)
			msg(receiver_id, sender_id, RIST_LOG_ERROR,
				"\tError on transmission sendto for seq #%"PRIu32"\n", ctx->seq);
		} else {
			struct sockaddr_in *sin4 = (struct sockaddr_in *)&p->u.address;
			unsigned char *ip = (unsigned char *)&sin4->sin_addr.s_addr;
			msg(receiver_id, sender_id, RIST_LOG_ERROR,
				"\tError on transmission sendto, ret=%d to %d.%d.%d.%d:%d/%d, seq #%"PRIu32", %d bytes\n",
					ret, ip[0], ip[1], ip[2], ip[3], htons(sin4->sin_port),
					p->local_port, ctx->seq, payload_len);
		}
	}

	if (ret >= 0)
		return 0;
	else
		return -1;
}

int rist_set_url(struct rist_peer *peer)
{
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	if (!peer->url) {
		if (peer->local_port > 0) {
			/* Put sender in IPv4 learning mode */
			peer->address_family = AF_INET;
			peer->address_len = sizeof(struct sockaddr_in);
			memset(&peer->u.address, 0, sizeof(struct sockaddr_in));
			msg(receiver_id, sender_id, RIST_LOG_INFO,
				"[INIT] Sender: in learning mode\n");
		}

		return 1;
	}

	struct network_url parsed_url;
	if (parse_url(peer->url, &parsed_url) != 0) {
		msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] %s / %s\n", parsed_url.error, peer->url);
		return -1;
	} else {
		msg(receiver_id, sender_id, RIST_LOG_INFO, "[INFO] URL parsed successfully: Host %s, Port %d\n",
			(char *) parsed_url.hostname, parsed_url.port);
	}

	peer->address_family = parsed_url.address_family;
	peer->address_len = parsed_url.address_len;
	peer->listening = parsed_url.listening;

	if (parsed_url.address_family == AF_INET) {
		peer->address_len = sizeof(struct sockaddr_in);
		((struct sockaddr_in *)&peer->u.address)->sin_family = AF_INET;
		memcpy(&peer->u.address, &parsed_url.u.address, peer->address_len);
	}

	if (parsed_url.address_family == AF_INET6) {
		peer->address_len = sizeof(struct sockaddr_in6);
		((struct sockaddr_in6 *)&peer->u.address)->sin6_family = AF_INET6;
		memcpy(&peer->u.address, &parsed_url.u.address, peer->address_len);
	}

	if (parsed_url.listening) {
		peer->local_port = parsed_url.port;
	}
	else {
		peer->remote_port = parsed_url.port;
	}

	if (peer->address_family == AF_INET) {
		((struct sockaddr_in*)&peer->u.address)->sin_port = htons(parsed_url.port);
	}

	if (peer->address_family == AF_INET6) {
		((struct sockaddr_in6*)&peer->u.address)->sin6_port = htons(parsed_url.port);
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
	int name_length = 0;
	socklen_t peer_socklen = 0;
	int ret_hostname = gethostname(hostname, RIST_MAX_HOSTNAME);
	if (ret_hostname == -1) {
		snprintf(hostname, RIST_MAX_HOSTNAME, "UnknownHost");
	}
	int ret_sockname = getsockname(fd, (struct sockaddr *)&peer_sockaddr, &peer_socklen);
	if (ret_sockname == 0)
	{
		struct sockaddr *peer = (struct sockaddr *)&peer_sockaddr;
		// TODO: why is this returning non-sense?
		if (peer->sa_family == AF_INET) {
			struct sockaddr_in *xin = (struct sockaddr_in*)&peer_sockaddr;
			name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s@%s:%u", hostname,
							inet_ntoa(xin->sin_addr), ntohs(xin->sin_port));
			if (name_length >= RIST_MAX_HOSTNAME)
				identifier[RIST_MAX_HOSTNAME-1] = 0;
		} else if (peer->sa_family == AF_INET6) {
			struct sockaddr_in6 *xin6 = (void*)peer;
			char str[INET6_ADDRSTRLEN];
			inet_ntop(xin6->sin6_family, &xin6->sin6_addr, str, sizeof(struct in6_addr));
			name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s@%s:%u", hostname,
							str, ntohs(xin6->sin6_port));
			if (name_length >= RIST_MAX_HOSTNAME)
				identifier[RIST_MAX_HOSTNAME-1] = 0;
		}
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
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	if(rist_set_url(peer)) {
		return;
	}

	// TODO: implement multicast interface selection
	if (peer->local_port) {
		const char* host;
		int port;

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
			msg(receiver_id, sender_id, RIST_LOG_INFO, "[ERROR] failed to convert address to string (errno=%d)", errno);
			return;
		}

		peer->sd = udp_Open(host, port, NULL, 0, 0, NULL);
		if (peer->sd > 0) {
			msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] Starting in URL listening mode (socket# %d)\n", peer->sd);
		} else {
			char *msgbuf = malloc(256);
			msgbuf = udp_GetErrorDescription(peer->sd, msgbuf);
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Error starting in URL listening mode. %s\n", msgbuf);
			free(msgbuf);
		}
	}
	else {
		// We use sendto ... so, no need to connect directly here
		peer->sd = udp_Connect_Simple(peer->address_family, 32, NULL);
		if (peer->sd > 0)
			msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] Starting in URL connect mode (%d)\n", peer->sd);
		else {
			char *msgbuf = malloc(256);
			msgbuf = udp_GetErrorDescription(peer->sd, msgbuf);
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Starting in URL connect mode. %s\n", msgbuf);
			free(msgbuf);
		}
		peer->local_port = 32768 + (get_cctx(peer)->peer_counter % 28232);
	}

	rist_populate_cname(peer);
	msg(receiver_id, sender_id, RIST_LOG_INFO, "[INFO] Our cname is %s\n", peer->cname);

}

int rist_send_receiver_rtcp(struct rist_peer *peer, uint32_t seq_array[], int array_len)
{
	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;

	uint16_t namelen = strlen(peer->cname) + 3;
	// It has to be a multiple of 4
	namelen = (((namelen - 2) >> 2) + 1) << 2;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = sizeof(struct rist_rtcp_rr_empty_pkt) + sizeof(struct rist_rtcp_hdr) + namelen;
	struct rist_rtcp_rr_empty_pkt *rr = (struct rist_rtcp_rr_empty_pkt *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET);
	struct rist_rtcp_sdes_pkt *sdes = (struct rist_rtcp_sdes_pkt *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + sizeof(struct rist_rtcp_rr_empty_pkt));

	// TODO: when array_len == 0, send the full RR report (every 200ms)
	/* Populate empty RR for receiver */
	rr->rtcp.flags = RTCP_SR_FLAGS;
	rr->rtcp.ptype = PTYPE_RR;
	rr->rtcp.ssrc = htobe32(peer->adv_flow_id);
	rr->rtcp.len = htons(1);

	/* Populate SDES for sender description */
	sdes->rtcp.flags = RTCP_SDES_FLAGS;
	sdes->rtcp.ptype = PTYPE_SDES;
	sdes->rtcp.len = htons((namelen >> 2)+1);
	sdes->rtcp.ssrc = htobe32(peer->adv_flow_id);
	sdes->cname = 1;
	sdes->name_len = strlen(peer->cname);
	strcpy(sdes->udn, peer->cname);
	// TODO: make sure the padding bytes are zeroes (they are random bytes now)

	if (array_len > 0)
	{
		// Add nack requests (if any)
		struct rist_rtp_nack_record *rec;

		// First the sequence extension message (to transmit the upper 16 bits of the seq)
		struct rist_rtcp_seqext *seqext_buf = (struct rist_rtcp_seqext *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len);
		seqext_buf->flags = RTCP_NACK_SEQEXT_FLAGS;
		seqext_buf->ptype = PTYPE_NACK_CUSTOM;
		seqext_buf->ssrc = htobe32(peer->adv_flow_id);
		seqext_buf->len = htons(3);
		uint32_t seq = seq_array[0];
		seqext_buf->seq_msb = htobe16(seq >> 16);

		// Now the NACK message
		if (peer->receiver_ctx->nack_type == RIST_NACK_BITMASK)
		{
			struct rist_rtcp_nack_bitmask *rtcp = (struct rist_rtcp_nack_bitmask *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext));
			rtcp->flags = RTCP_NACK_BITMASK_FLAGS;
			rtcp->ptype = PTYPE_NACK_BITMASK;
			rtcp->len = htons(2 + array_len);
			rtcp->ssrc_source = 0; // TODO
			rtcp->ssrc = htobe32(peer->adv_flow_id);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext) + RTCP_FB_HEADER_SIZE);
			for (int i = 0; i < array_len; i++) {
				rec->start = htons(seq_array[i]);
				rec->extra = htons(0);
				rec++;
			}
		}
		else // PTYPE_NACK_CUSTOM
		{
			struct rist_rtcp_nack_range *rtcp = (struct rist_rtcp_nack_range *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext));
			rtcp->flags = RTCP_NACK_RANGE_FLAGS;
			rtcp->ptype = PTYPE_NACK_CUSTOM;
			rtcp->len = htons(2 + array_len);
			rtcp->ssrc_source = htobe32(peer->adv_flow_id);
			memcpy(rtcp->name, "RIST", 4);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext) + RTCP_FB_HEADER_SIZE);
			for (int i = 0; i < array_len; i++) {
				uint16_t tmp_seq = (uint16_t)seq_array[i];
				//fprintf(stderr, "sending nack for seq %d\n", tmp_seq);
				rec->start = htons(tmp_seq);
				rec->extra = htons(0);
				rec++;
			}
		}
		int nack_bufsize = sizeof(struct rist_rtcp_seqext) + RTCP_FB_HEADER_SIZE + RTCP_FB_FCI_GENERIC_NACK_SIZE * array_len;
		payload_len += nack_bufsize;
		payload_type = RIST_PAYLOAD_TYPE_RTCP_NACK;
	}

	// We use direct send from receiver to sender (no fifo to keep track of seq/idx)
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, false);
}

void rist_send_sender_rtcp(struct rist_peer *peer)
{
	uint16_t namelen = strlen(peer->cname) + 3;
	// It has to be a multiple of 4
	namelen = (((namelen - 2) >> 2) + 1) << 2;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = sizeof(struct rist_rtcp_sr_pkt) + sizeof(struct rist_rtcp_hdr) + namelen;
	struct rist_rtcp_sr_pkt *sr = (struct rist_rtcp_sr_pkt *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET);
	struct rist_rtcp_sdes_pkt *sdes = (struct rist_rtcp_sdes_pkt *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + sizeof(struct rist_rtcp_sr_pkt));

	/* Populate SR for sender */
	sr->rtcp.flags = RTCP_SR_FLAGS;
	sr->rtcp.ptype = PTYPE_SR;
	sr->rtcp.ssrc = htobe32(peer->adv_flow_id);
	sr->rtcp.len = htons(6);
	uint64_t now = timestampNTP_u64();
	timespec_t ts;
#ifdef __APPLE__
	clock_gettime_osx(&ts);
#elif	defined _WIN32
	clock_gettime(CLOCK_MONOTONIC, &ts);
#else
	clock_gettime(CLOCK_REALTIME, &ts);
#endif
	// Convert nanoseconds to 32-bits fraction (232 picosecond units)
	uint32_t ntp_lsw = (uint32_t)ts.tv_nsec;
	// There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
	// No leap seconds during that period since they were not invented yet.
	uint32_t ntp_msw = (70LL * 365 + 17) * 24 * 60 * 60 + ts.tv_sec;
	sr->ntp_msw = htobe32(ntp_msw);
	sr->ntp_lsw = htobe32(ntp_lsw);
	sr->rtp_ts = htobe32(timestampRTP_u32(now));
	sr->sender_pkts = 0;//htonl(f->packets_count);
	sr->sender_bytes = 0;//htonl(f->bytes_count);

	/* Populate SDES for sender description */
	sdes->rtcp.flags = RTCP_SDES_FLAGS;
	sdes->rtcp.ptype = PTYPE_SDES;
	sdes->rtcp.len = htons((namelen >> 2)+1);
	sdes->rtcp.ssrc = htobe32(peer->adv_flow_id);
	sdes->cname = 1;
	sdes->name_len = strlen(peer->cname);
	strcpy(sdes->udn, peer->cname);
	// TODO: make sure the padding bytes are zeroes (they are random bytes now)

	// Push it to the FIFO buffer to be sent ASAP (even in the simple profile case)
	// Enqueue it to not misalign the buffer and to resend lost handshakes in the case of advanced mode
	struct rist_sender *ctx = peer->sender_ctx;
	pthread_rwlock_wrlock(&ctx->queue_lock);
	ctx->sender_queue[ctx->sender_queue_write_index] = rist_new_buffer(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, RIST_PAYLOAD_TYPE_RTCP, 0, 0, peer->local_port, peer->remote_port);
	if (RIST_UNLIKELY(!ctx->sender_queue[ctx->sender_queue_write_index])) {
		msg(0, ctx->id, RIST_LOG_ERROR, "\t Could not create packet buffer inside sender buffer, OOM, decrease max bitrate or buffer time length\n");
		pthread_rwlock_unlock(&ctx->queue_lock);
		return;
	}
	ctx->sender_queue[ctx->sender_queue_write_index]->peer = peer;
	ctx->sender_queue_bytesize += payload_len;
	ctx->sender_queue_write_index = (ctx->sender_queue_write_index + 1) % ctx->sender_queue_max;
	pthread_rwlock_unlock(&ctx->queue_lock);
	return;
}

static void rist_send_peer_nacks(struct rist_flow *f, struct rist_peer *peer)
{
	struct rist_peer *outputpeer = peer;
	if (outputpeer->dead)
	{
		// original peer source is dead, use with the peer with the best rtt within this flow instead
		outputpeer = f->peer_lst[rist_best_rtt_index(f)];
	}

	if (outputpeer) {
		if (get_cctx(peer)->debug)
			msg(0, 0, RIST_LOG_DEBUG, "[DEBUG] Sending %d nacks starting with %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n",
			peer->nacks.counter, peer->nacks.array[0],peer->nacks.array[1],peer->nacks.array[2],peer->nacks.array[3]);
		if (rist_send_receiver_rtcp(outputpeer->peer_rtcp, peer->nacks.array, peer->nacks.counter) == 0)
			peer->nacks.counter = 0;
		else
			msg(0, 0, RIST_LOG_ERROR, "\tCould not send nacks, will try again\n");
	} else {
		msg(0, 0, RIST_LOG_ERROR, "\tCannot send nack, all peers are dead\n");
	}
}

void rist_send_nacks(struct rist_flow *f, struct rist_peer *peer)
{
	if (peer)
	{
		// Only a single peer was requested
		rist_send_peer_nacks(f, peer);
		return;
	}

	// Loop through all peers for the flow and empty the queues
	for (size_t j = 0; j < f->peer_lst_len; j++) {
		struct rist_peer *outputpeer = f->peer_lst[j];
		if (outputpeer->nacks.counter > 0) {
			rist_send_peer_nacks(f, outputpeer);
		}
	}
}

int rist_sender_enqueue(struct rist_sender *ctx, const void *data, int len, uint64_t datagram_time, uint16_t src_port, uint16_t dst_port)
{
	uint8_t payload_type = RIST_PAYLOAD_TYPE_DATA_RAW;

	if (ctx->common.PEERS == NULL) {
		// Do not cache data if the lib user has not added peers
		return -1;
	}

	/* Compress the data packets */
	if (ctx->compression) {
		int clen;
		void *cbuf = ctx->common.buf.dec;

		clen = LZ4_compress_default(data, cbuf, len, RIST_MAX_PACKET_SIZE);
		if (clen < 0) {
			msg(0, ctx->id, RIST_LOG_ERROR,
				"\tCompression failed (%d), not sending\n", clen);
			return -1;
		}

		if (clen < len) {
			len = clen;
			data = cbuf;
			payload_type = RIST_PAYLOAD_TYPE_DATA_LZ4;
		} else {
			//msg(receiver_id, ctx->id, DEBUG,
			//    "compressed %d to %lu\n", len, compressed_len);
			// Use origin data AS IS becauce compression bloated it
		}
	}

	ctx->last_datagram_time = datagram_time;

	/* insert into sender fifo queue */
	pthread_rwlock_wrlock(&ctx->queue_lock);
	ctx->sender_queue[ctx->sender_queue_write_index] = rist_new_buffer(data, len, payload_type, 0, datagram_time, src_port, dst_port);
	if (RIST_UNLIKELY(!ctx->sender_queue[ctx->sender_queue_write_index])) {
		msg(0, ctx->id, RIST_LOG_ERROR, "\t Could not create packet buffer inside sender buffer, OOM, decrease max bitrate or buffer time length\n");
		pthread_rwlock_unlock(&ctx->queue_lock);
		return -1;
	}
	ctx->sender_queue_write_index = (ctx->sender_queue_write_index + 1) % ctx->sender_queue_max;
	ctx->sender_queue_bytesize += len;
	pthread_rwlock_unlock(&ctx->queue_lock);

	return 0;
}

void rist_sender_send_data_balanced(struct rist_sender *ctx, struct rist_buffer *buffer)
{
	struct rist_peer *peer;
	struct rist_peer *selected_peer_by_weight = NULL;
	uint32_t max_remainder = 0;
	bool duplicate = false;

	for (peer = ctx->common.PEERS; peer; peer = peer->next) {

		if (peer->listening || !peer->is_data || peer->dead)
			continue;

		if (peer->state_local != RIST_PEER_STATE_CONNECT) {
			ctx->weight_counter -= peer->config.weight;
			if (ctx->weight_counter <= 0) {
				ctx->weight_counter = ctx->total_weight;
			}
			peer->w_count = peer->config.weight;
			continue;
		}

		/*************************************/
		/* * * * * * * * * * * * * * * * * * */
		/** Heuristics for sender goes here **/
		/* * * * * * * * * * * * * * * * * * */
		/*************************************/

		if (peer->config.weight == 0) {
			uint8_t *payload = buffer->data;
			rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, duplicate);
			duplicate = true;
			buffer->seq = ctx->common.seq;
			buffer->seq_rtp = ctx->common.seq_rtp;
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

	if (selected_peer_by_weight) {
		peer = selected_peer_by_weight;
		uint8_t *payload = buffer->data;
		rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, duplicate);
		duplicate = true;
		buffer->seq = ctx->common.seq;
		buffer->seq_rtp = ctx->common.seq_rtp;
		ctx->weight_counter--;
		peer->w_count--;
	}

	if (ctx->weight_counter == 0 || !selected_peer_by_weight) {
		peer = ctx->common.PEERS;
		ctx->weight_counter = ctx->total_weight;
		for (; peer; peer = peer->next) {
			if (peer->listening || !peer->is_data)
				continue;
			peer->w_count = peer->config.weight;
		}
	}
}

static size_t rist_sender_index_get(struct rist_sender *ctx, uint32_t seq, struct rist_peer *peer)
{
	// This is by design in advanced mode, that is why we push all output data and handshakes 
	// through the sender_queue, so we can keep the seq and idx in sync
	size_t idx = (seq + 1) % (uint64_t)ctx->sender_queue_max;
	if (!peer->advanced) {
		// For simple profile and main profile without extended seq numbers, we use a conversion table
		idx = ctx->seq_index[(uint16_t)seq];
	}
	return idx;
}

int rist_retry_dequeue(struct rist_sender *ctx)
{
//	msg(0, ctx->id, RIST_LOG_ERROR,
//			"\tCurrent read/write index are %zu/%zu \n", ctx->sender_retry_queue_read_index,
//			ctx->sender_retry_queue_write_index);

	// TODO: Is this logic flawed and we are always one unit behind (look at oob_dequee)
	size_t sender_retry_queue_read_index = (ctx->sender_retry_queue_read_index + 1) % ctx->sender_retry_queue_size;

	if (sender_retry_queue_read_index == ctx->sender_retry_queue_write_index) {
		//msg(0, ctx->id, RIST_LOG_ERROR,
		//	"\t[GOOD] We are all up to date, index is %" PRIu64 "\n",
		//	ctx->sender_retry_queue_read_index);
		return 0;
	}

	ctx->sender_retry_queue_read_index = sender_retry_queue_read_index;
	struct rist_retry *retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_read_index];

	// If they request a non-sense seq number, we will catch it when we check the seq number against
	// the one on that buffer position and it does not match

	size_t idx = rist_sender_index_get(ctx, retry->seq, retry->peer);
	if (ctx->sender_queue[idx] == NULL) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"[LOST] Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu), consider increasing the buffer size\n",
			retry->seq, idx, ctx->sender_queue_read_index, ctx->sender_queue_write_index, ctx->sender_queue_delete_index);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	} else if (retry->peer->advanced && ctx->sender_queue[idx]->seq != retry->seq) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"[LOST] Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu), found an old one instead %" PRIu32 " (%"PRIu64"), something is very wrong!\n",
			retry->seq, idx, ctx->sender_queue_read_index, ctx->sender_queue_write_index, ctx->sender_queue_delete_index,
			ctx->sender_queue[idx]->seq, ctx->sender_queue_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}
	else if (!retry->peer->advanced && (uint16_t)retry->seq != ctx->sender_queue[idx]->seq_rtp) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"[LOST] Couldn't find block %" PRIu16 " (i=%zu/r=%zu/w=%zu/d=%zu), found an old one instead %" PRIu32 " (%"PRIu64"), bitrate is too high, use advanced profile instead\n",
			(uint16_t)retry->seq, idx, ctx->sender_queue_read_index, ctx->sender_queue_write_index, ctx->sender_queue_delete_index,
			ctx->sender_queue[idx]->seq_rtp, ctx->sender_queue_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	// TODO: re-enable rist_send_data_allowed (cooldown feature)

	// Make sure we do not flood the network with retries
	struct rist_bandwidth_estimation *retry_bw = &retry->peer->retry_bw;
	struct rist_bandwidth_estimation *cli_bw = &retry->peer->bw;
	size_t current_bitrate = cli_bw->bitrate + retry_bw->bitrate;
	size_t max_bitrate = retry->peer->config.recovery_maxbitrate * 1000;

	if (current_bitrate > max_bitrate) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Bandwidth exceeded: (%zu + %zu) > %d, not resending packet %"PRIu64".\n",
			cli_bw->bitrate, retry_bw->bitrate, max_bitrate, idx);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	// For timing debugging
	uint64_t now = timestampNTP_u64();
	uint64_t data_age = (now - ctx->sender_queue[idx]->time) / RIST_CLOCK;
	uint64_t retry_age = (now - retry->insert_time) / RIST_CLOCK;
	if (retry_age > retry->peer->config.recovery_length_max) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"[ERROR] Retry-request of element %" PRIu32 " (idx %zu) that was sent %" PRIu64
				"ms ago has been in the queue too long to matter: %"PRIu64"ms > %ums\n",
			retry->seq, idx, data_age, retry_age, retry->peer->config.recovery_length_max);
		return -1;
	}

	struct rist_buffer *buffer = ctx->sender_queue[idx];
	/* queue_time holds the original insertion time for this seq */
	if (ctx->common.debug)
		msg(0, ctx->id, RIST_LOG_DEBUG,
			"[DEBUG] Resending %"PRIu32"/%"PRIu32"/%"PRIu16" (idx %zu) after %" PRIu64
			"ms of first transmission and %"PRIu64"ms in queue, bitrate is %zu + %zu, %zu\n",
			retry->seq, buffer->seq, buffer->seq_rtp, idx, data_age, retry_age, retry->peer->bw.bitrate, 
			retry_bw->bitrate, retry->peer->bw.bitrate + retry_bw->bitrate);

	uint8_t *payload = buffer->data;

	// TODO: I do not think this check is needed anymore ... we fixed the bug that was causing
	// this scenario ... and we have thread-locking to prevent this
	if (!payload)
	{
		msg(0, ctx->id, RIST_LOG_ERROR,
			"[ERROR] Someone deleted my buffer when resending %" PRIu32 " (idx %zu) after %" PRIu64
			"ms of first transmission and %"PRIu64"ms in queue, bitrate is %zu + %zu, %zu\n",
			retry->seq, idx, data_age, retry_age, retry->peer->bw.bitrate, retry_bw->bitrate,
			retry->peer->bw.bitrate + retry_bw->bitrate);
	}

	buffer->transmit_count++;
	uint32_t ret = 0;
	if (buffer->transmit_count >= retry->peer->config.buffer_bloat_hard_limit) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Datagram %"PRIu32
			" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu\n",
			buffer->seq, buffer->transmit_count, data_age, buffer->transmit_count);
	}
	else {
		ret = rist_send_seq_rtcp(retry->peer->peer_data, buffer->seq, buffer->seq_rtp, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port);
	}

	// update bandwidh value
	rist_calculate_bitrate_sender(ret, retry_bw);

	if (ret < buffer->size) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"[ERROR] Resending of packet failed %zu != %zu for seq %"PRIu32"\n", ret, buffer->size, buffer->seq);
		retry->peer->stats_sender_instant.retrans_skip++;
	} else {
		retry->peer->stats_sender_instant.retrans++;
	}

	if (ret >= 0)
		return 0;
	else
		return -1;
}

void rist_retry_enqueue(struct rist_sender *ctx, uint32_t seq, struct rist_peer *peer)
{
	// Even though all the checks are on the dequeue function, we leave this one here
	// to prevent the flodding of our fifo .. It is only based on the date of the
	// last queued item with the same seq.
	// This is a safety check to protect against buggy or non compliant receivers that request the
	// same seq number without waiting one RTT. We are lenient and even allow 1/2 RTT
	uint64_t now = timestampNTP_u64();
	size_t idx = rist_sender_index_get(ctx, seq, peer);
	struct rist_buffer *buffer = ctx->sender_queue[idx];
	if (buffer)
	{
		if (buffer->last_retry_request != 0)
		{
			uint64_t delta = 2 * (now - buffer->last_retry_request) / RIST_CLOCK;
			//msg(0, ctx->id, RIST_LOG_WARN,
			//	"[ERROR] Nack request for seq %"PRIu32" with delta %"PRIu64" and rtt_min %"PRIu32"\n", 
			//	buffer->seq, delta, peer->config.recovery_rtt_min);
			if (delta < peer->config.recovery_rtt_min)
			{
				msg(0, ctx->id, RIST_LOG_WARN,
					"[ERROR] Nack request for seq %"PRIu32"/%"PRIu32" is already queued, %"PRIu64" < %"PRIu32"\n",
					buffer->seq, idx, delta, peer->config.recovery_rtt_min);
				// TODO: stats?
				return;
			}
		}
		else
		{
			buffer->last_retry_request = now;
		}
	}
	else
	{
		msg(0, ctx->id, RIST_LOG_WARN,
			"[ERROR] Nack request for seq %"PRIu32" but we do not have it in the buffer (%zu ms)\n", seq,
			ctx->sender_recover_min_time);
		return;
	}

	// Now insert into the missing queue
	struct rist_retry *retry;
	retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_write_index];
	retry->seq = seq;
	retry->peer = peer;
	retry->insert_time = now;
	if (++ctx->sender_retry_queue_write_index >= ctx->sender_retry_queue_size) {
		ctx->sender_retry_queue_write_index = 0;
	}
}

void rist_print_inet_info(char *prefix, struct rist_peer *peer)
{
	char ipstr[INET6_ADDRSTRLEN];
	uint32_t port;
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	// deal with both IPv4 and IPv6:
	if (peer->address_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *) &peer->u.address;
		port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
	} else {
		struct sockaddr_in *addr = (void *) &peer->u.address;
		port = ntohs(addr->sin_port);
		snprintf(ipstr, INET6_ADDRSTRLEN, "%s", inet_ntoa(addr->sin_addr));
	}

	msg(receiver_id, sender_id, RIST_LOG_INFO,
		"[INFO] %sPeer Information, IP:Port => %s:%u (%d), id: %"PRIu32", ports: %u->%u\n",
		prefix, ipstr, port, peer->listening, peer->adv_peer_id,
		peer->local_port, peer->remote_port);
}
