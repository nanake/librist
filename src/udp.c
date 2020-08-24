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
#include "lz4.h"
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#ifdef LINUX_CRYPTO
#include <linux-crypto.h>
#endif

uint64_t timestampNTP_u64(void)
{

	// We use clock_gettime instead of gettimeofday even though we only need microseconds
	// because gettimeofday implementation under linux is dependent on the kernel clock
	// and can produce duplicate times (too close to kernel timer)

	// We use the NTP time standard: rfc5905 (https://tools.ietf.org/html/rfc5905#section-6)
	// The 64-bit timestamps used by NTP consist of a 32-bit part for seconds 
	// and a 32-bit part for fractional second, giving a time scale that rolls 
	// over every 232 seconds (136 years) and a theoretical resolution of 
	// 2−32 seconds (233 picoseconds). NTP uses an epoch of January 1, 1900. 
	// Therefore, the first rollover occurs on February 7, 2036.

	timespec_t ts;
#ifdef __APPLE__
	clock_gettime_osx(&ts);
#else
	clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
	// Convert nanoseconds to 32-bits fraction (232 picosecond units)
	uint64_t t = (uint64_t)(ts.tv_nsec) << 32;
	t /= 1000000000;
	// There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
	// No leap seconds during that period since they were not invented yet.
	t |= ((70LL * 365 + 17) * 24 * 60 * 60 + ts.tv_sec) << 32;
	return t; // nanoseconds (technically, 232.831 picosecond units)
}

uint64_t timestampNTP_RTC_u64(void) {
	timespec_t ts;
#ifdef __APPLE__
	clock_gettime_osx(&ts);
#elif defined _WIN32
	clock_gettime(CLOCK_MONOTONIC, &ts);
#else
	clock_gettime(CLOCK_REALTIME, &ts);
#endif
	// Convert nanoseconds to 32-bits fraction (232 picosecond units)
	uint64_t t = (uint64_t)(ts.tv_nsec) << 32;
	t /= 1000000000;
	// There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
	// No leap seconds during that period since they were not invented yet.
	t |= (70LL * 365 + 17) * 24 * 60 * 60 + ts.tv_sec;
	return t;
}

uint32_t timestampRTP_u32( int advanced, uint64_t i_ntp )
{
	if (!advanced) {
		i_ntp *= RTP_PTYPE_MPEGTS_CLOCKHZ;
		i_ntp = i_ntp >> 32;
		return (uint32_t)i_ntp;
	}
	else
	{
		// We just need the middle 32 bits, i.e. 65536Hz clock
		i_ntp = i_ntp >> 16;
		return (uint32_t)i_ntp;
	}
}

uint64_t convertRTPtoNTP(uint8_t ptype, uint32_t time_extension, uint32_t i_rtp)
{
	uint64_t i_ntp;
	if (ptype == RTP_PTYPE_RIST) {
		// Convert rtp to 64 bit and shift it 16 bits
		uint64_t part2 = (uint64_t)i_rtp;
		part2 = part2 << 16;
		// rebuild source_time (lower and upper 16 bits)
		uint64_t part3 = (uint64_t)(time_extension & 0xffff);
		uint64_t part1 = ((uint64_t)(time_extension & 0xffff0000)) << 32;
		i_ntp = part1 | part2 | part3;
		//fprintf(stderr,"source time %"PRIu64", rtp time %"PRIu32"\n", source_time, rtp_time);
	} else {
		int32_t clock = get_rtp_ts_clock(ptype);
		if (RIST_UNLIKELY(!clock)){
				clock = RTP_PTYPE_MPEGTS_CLOCKHZ;
				// Insert a new timestamp (not ideal but better than failing)
				i_rtp = htobe32(timestampRTP_u32(0, timestampNTP_u64()));
		}
		i_ntp = (uint64_t)i_rtp << 32;
		i_ntp /= clock;
	}
	return i_ntp;
}

uint64_t calculate_rtt_delay(uint64_t request, uint64_t response, uint32_t delay) {
	/* both request and response are NTP timestamps, delay is in microseconds */
	uint64_t rtt = response - request;
	if (RIST_UNLIKELY(delay))
		rtt -= (((uint64_t)delay) << 32)/1000000;
	return rtt;
}

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

static uint32_t rand_u32(void)
{
	uint32_t u32;
	uint8_t *u8 = (void *) &u32;

	for (size_t i = 0; i < sizeof(u32); i++) {
		u8[i] = rand() % 256;
	}

	return u32;
}

static void _ensure_key_is_valid(struct rist_key *key, struct rist_peer *peer)
{
	RIST_MARK_UNUSED(peer);

	bool new_nonce = false;

	if (!key->gre_nonce) {
		// Generate new nonce as we do not have any
		new_nonce = true;
	} else if (key->used_times > RIST_AES_KEY_REUSE_TIMES) {
		// Key can only be used upto certain times
		new_nonce = true;
	} else if (key->key_rotation > 0 && key->used_times >= key->key_rotation) {
		// custom rotation
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
#ifndef LINUX_CRYPTO
		aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#else
		if (peer->cryptoctx_tx)
			linux_crypto_set_key(aes_key, key->key_size/8, peer->cryptoctx_tx);
		else
			aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#endif
	}
}

size_t rist_send_seq_rtcp(struct rist_peer *p, uint32_t seq, uint16_t seq_rtp, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	struct rist_common_ctx *ctx = get_cctx(p);
	struct rist_key *k = &p->key_tx;
	uint8_t *data;
	size_t len, gre_len;
	size_t hdr_len = 0;
	ssize_t ret = 0;
	/* Our encryption and compression operations directly modify the payload buffer we receive as a pointer
	   so we create a local pointer that points to the payload pointer, if we would either encrypt or compress we instead
	   malloc and mempcy, to ensure our source stays clean. We only do this with RAW data as these buffers are the only
	   assumed to be reused by retransmits */
	uint8_t *_payload = NULL;
	bool compressed = false;
	bool retry = false;
	
	bool modifyingbuffer = (ctx->profile > RIST_PROFILE_SIMPLE 
							&& payload_type == RIST_PAYLOAD_TYPE_DATA_RAW 
							&& (k->key_size || p->compression));

	assert(payload != NULL);

	if (modifyingbuffer) {
		_payload = malloc(payload_len + RIST_MAX_PAYLOAD_OFFSET);
		_payload  = _payload + RIST_MAX_PAYLOAD_OFFSET;
		memcpy(_payload, payload, payload_len);
	} else {
		_payload = payload;
	}

	//if (p->receiver_mode)
	//	rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Sending seq %"PRIu32" and rtp_seq %"PRIu16" payload is %d\n",
	//		seq, seq_rtp, payload_type);
	//else
	//	rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Sending seq %"PRIu32" and idx is %zu/%zu/%zu (read/write/delete) and payload is %d\n",
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
			hdr->rtp.seq = htobe16(seq_rtp);
			if ((seq + 1) != ctx->seq)
			{
				// This is a retransmission
				//rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\tResending: %"PRIu32"/%"PRIu16"/%"PRIu32"\n", seq, seq_rtp, ctx->seq);
				/* Mark SSID for retransmission (change the last bit of the ssrc to 1) */
				//hdr->rtp.ssrc |= (1 << 31);
				hdr->rtp.ssrc = htobe32(p->adv_flow_id | 0x01);
				retry = true;
			}
			if (ctx->profile == RIST_PROFILE_ADVANCED) {
				hdr->rtp.payload_type = RTP_PTYPE_RIST;
				hdr->rtp.ts = htobe32(timestampRTP_u32(1, source_time));
			} else {
				hdr->rtp.payload_type = RTP_PTYPE_MPEGTS;
				if (!ctx->birthtime_rtp_offset) {
					// Force a 32bit timestamp wrap-around 60 seconds after startup. It will break 
					// crappy implementations and/or will guarantee 13 hours of clean stream.
					ctx->birthtime_rtp_offset = UINT32_MAX - timestampRTP_u32(0, source_time) - (90000*60);
				}
				hdr->rtp.ts = htobe32(ctx->birthtime_rtp_offset + timestampRTP_u32(0, source_time));
			}
		}
		// copy the rtp header data (needed for encryption)
		memcpy(_payload - hdr_len, hdr, hdr_len);
	}

	if (ctx->profile > RIST_PROFILE_SIMPLE) {

		/* Compress the data packets */
		if (p->compression) {
			int clen;
			void *cbuf = ctx->buf.dec;
			clen = LZ4_compress_default((const char *)_payload, cbuf, (int)payload_len, RIST_MAX_PACKET_SIZE);
			if (clen < 0) {
				rist_log_priv(ctx, RIST_LOG_ERROR,
					"Compression failed (%d), not sending\n", clen);
			}
			else {
				if ((size_t)clen < payload_len) {
					payload_len = clen;
					_payload = cbuf;
					compressed = true;
				} else {
					//msg(receiver_id, ctx->id, DEBUG,
					//    "compressed %d to %lu\n", len, compressed_len);
					// Use origin data AS IS becauce compression bloated it
				}
			}
		}

		/* Encrypt everything except GRE */
		if (k->key_size) {
			_ensure_key_is_valid(k, p);

			// Prepare GRE header
			struct rist_gre_key_seq *gre_key_seq = (void *) header_buf;
			SET_BIT(gre_key_seq->flags1, 7); // set checksum bit
			SET_BIT(gre_key_seq->flags1, 5); // set key flag
			SET_BIT(gre_key_seq->flags1, 4); // set seq bit

			if (ctx->profile == RIST_PROFILE_ADVANCED) {
				SET_BIT(gre_key_seq->flags2, 0); // set advanced protocol identifier
				if (compressed)
					SET_BIT(gre_key_seq->flags1, 3); // set compression bit
				if (retry)
					SET_BIT(gre_key_seq->flags1, 2); // set retry bit
				// TODO: implement fragmentation and fill in this data 
				// (fragmentation to be done at API data entry point)
				uint8_t fragment_final = 0;
				uint8_t fragment_number = 0;
				if (CHECK_BIT(fragment_final, 0)) SET_BIT(gre_key_seq->flags1, 1);
				// fragment_number (max is 64)
				if (CHECK_BIT(fragment_number, 0)) SET_BIT(gre_key_seq->flags1, 0);
				if (CHECK_BIT(fragment_number, 1)) SET_BIT(gre_key_seq->flags2, 7);
				if (CHECK_BIT(fragment_number, 2)) SET_BIT(gre_key_seq->flags2, 6);
				if (CHECK_BIT(fragment_number, 3)) SET_BIT(gre_key_seq->flags2, 5);
				if (CHECK_BIT(fragment_number, 4)) SET_BIT(gre_key_seq->flags2, 4);
				if (CHECK_BIT(fragment_number, 5)) SET_BIT(gre_key_seq->flags2, 3);
				//SET_BIT(gre_key_seq->flags2, 2) is free for future use (version)
				//SET_BIT(gre_key_seq->flags2, 1) is free for future use (version)
			}

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
#ifndef LINUX_CRYPTO
			aes_encrypt_ctr((const void *) (_payload - hdr_len), hdr_len + payload_len, 
				(void *) (_payload - hdr_len), k->aes_key_sched, k->key_size, IV);
#else
			if (p->cryptoctx_tx)
				linux_crypto_encrypt((void *) (_payload - hdr_len), (int)(hdr_len + payload_len), IV, p->cryptoctx_tx);
			else
				aes_encrypt_ctr((const void *) (_payload - hdr_len), hdr_len + payload_len, 
					(void *) (_payload - hdr_len), k->aes_key_sched, k->key_size, IV);
#endif
		} else {
			struct rist_gre_seq *gre_seq = (struct rist_gre_seq *) header_buf;
			SET_BIT(gre_seq->flags1, 7); // set checksum bit
			SET_BIT(gre_seq->flags1, 4); // set seq bit

			if (ctx->profile == RIST_PROFILE_ADVANCED) {
				SET_BIT(gre_seq->flags2, 0); // set advanced protocol identifier
				if (compressed)
					SET_BIT(gre_seq->flags1, 3); // set compression bit
				if (retry)
					SET_BIT(gre_seq->flags1, 2); // set retry bit
				uint8_t fragment_final = 0;
				uint8_t fragment_number = 0;
				if (CHECK_BIT(fragment_final, 0)) SET_BIT(gre_seq->flags1, 1);
				if (CHECK_BIT(fragment_number, 0)) SET_BIT(gre_seq->flags1, 0);
				if (CHECK_BIT(fragment_number, 1)) SET_BIT(gre_seq->flags2, 7);
				if (CHECK_BIT(fragment_number, 2)) SET_BIT(gre_seq->flags2, 6);
				if (CHECK_BIT(fragment_number, 3)) SET_BIT(gre_seq->flags2, 5);
				if (CHECK_BIT(fragment_number, 4)) SET_BIT(gre_seq->flags2, 4);
				if (CHECK_BIT(fragment_number, 5)) SET_BIT(gre_seq->flags2, 3);
			}
		
			gre_seq->prot_type = htobe16(proto_type);
			gre_seq->checksum_reserved1 = htobe32((uint32_t)(source_time >> 32));
			gre_seq->seq = htobe32(seq);
		}

		// now copy the GRE header data
		len = gre_len + hdr_len + payload_len;
		data = _payload - gre_len - hdr_len;
		memcpy(data, header_buf, gre_len);
	}
	else
	{
		len =  hdr_len + payload_len - RIST_GRE_PROTOCOL_REDUCED_SIZE;
		data = _payload - hdr_len + RIST_GRE_PROTOCOL_REDUCED_SIZE;
	}


	// TODO: compare p->sender_ctx->sender_queue_read_index and p->sender_ctx->sender_queue_write_index
	// and warn when the difference is a multiple of 10 (slow CPU or overtaxed algortihm)
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

	ret = sendto(p->sd,(const char*)data, len, MSG_DONTWAIT, &(p->u.address), p->address_len);

out:
	if (RIST_UNLIKELY(ret <= 0)) {
		rist_log_priv(ctx, RIST_LOG_ERROR, "\tSend failed: errno=%d, ret=%d, socket=%d\n", errno, ret, p->sd);
	} else {
		rist_calculate_bitrate_sender(len, &p->bw);
		p->stats_sender_instant.sent++;
		p->stats_receiver_instant.sent++;
	}

	if (modifyingbuffer) {
		free(_payload - RIST_MAX_PAYLOAD_OFFSET);
	}

	return ret;
}

/* This function is used by receiver for all and by sender only for rist-data and oob-data */
int rist_send_common_rtcp(struct rist_peer *p, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_gre, uint32_t seq_rtp)
{
	// This can only and will most likely be zero for data packets. RTCP should always have a value.
	assert(payload_type != RIST_PAYLOAD_TYPE_DATA_RAW && payload_type != RIST_PAYLOAD_TYPE_DATA_OOB ? dst_port != 0 : 1);
	if (dst_port == 0)
		dst_port = p->config.virt_dst_port;
	if (src_port == 0)
		src_port = 32768 + p->adv_peer_id;

	if (p->sd < 0 || !p->address_len) {
		rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "rist_send_common_rtcp failed\n");
		return -1;
	}

	if (RIST_UNLIKELY(p->config.timing_mode == RIST_TIMING_MODE_ARRIVAL) && !p->receiver_mode)
		source_time = timestampNTP_u64();

	size_t ret = rist_send_seq_rtcp(p, seq_gre, (uint16_t)seq_rtp, payload_type, payload, payload_len, source_time, src_port, dst_port);

	if ((!p->compression && ret < payload_len) || ret <= 0)
	{
		if (p->address_family == AF_INET6) {
			// TODO: print IP and port (and error number?)
			rist_log_priv(get_cctx(p), RIST_LOG_ERROR,
				"\tError on transmission sendto for seq #%"PRIu32"\n", seq_gre);
		} else {
			struct sockaddr_in *sin4 = (struct sockaddr_in *)&p->u.address;
			unsigned char *ip = (unsigned char *)&sin4->sin_addr.s_addr;
			rist_log_priv(get_cctx(p), RIST_LOG_ERROR,
				"\tError on transmission sendto, ret=%d to %d.%d.%d.%d:%d/%d, seq #%"PRIu32", %d bytes\n",
					ret, ip[0], ip[1], ip[2], ip[3], htons(sin4->sin_port),
					p->local_port, seq_gre, payload_len);
		}
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
			struct sockaddr_in *xin = (struct sockaddr_in*)&peer_sockaddr;
			char *addr = inet_ntoa(xin->sin_addr);
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

	if (peer->local_port) {
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

		peer->sd = udpsocket_open_bind(host, port, &peer->miface[0]);
		if (peer->sd > 0) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Starting in URL listening mode (socket# %d)\n", peer->sd);
		} else {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not start in URL listening mode. %s\n", strerror(errno));
		}
	}
	else {
		if (peer->u.address.sa_family == AF_INET)
		{
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			peer->multicast = IN_MULTICAST(ntohl(addrv4->sin_addr.s_addr));
		}
		else
		{
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			peer->multicast = IN6_IS_ADDR_MULTICAST(&addrv6->sin6_addr);
		}
		if (peer->multicast) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Peer configured for multicast");
		}
		// We use sendto ... so, no need to connect directly here
		peer->sd = udpsocket_open(peer->address_family);
		// TODO : set max hops
		if (peer->sd > 0)
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Starting in URL connect mode (%d)\n", peer->sd);
		else {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not start in URL connect mode. %s\n", strerror(errno));
		}
		peer->local_port = 32768 + (get_cctx(peer)->peer_counter % 28232);
	}

	udpsocket_set_nonblocking(peer->sd);
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

}

static inline void rist_rtcp_write_empty_rr(uint8_t *buf, int *offset, const uint32_t flow_id) {
	struct rist_rtcp_rr_empty_pkt *rr = (struct rist_rtcp_rr_empty_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
	*offset += sizeof(struct rist_rtcp_rr_empty_pkt);
	rr->rtcp.flags = RTCP_SR_FLAGS;
	rr->rtcp.ptype = PTYPE_RR;
	rr->rtcp.ssrc = htobe32(flow_id);
	rr->rtcp.len = htons(1);
}

static inline void rist_rtcp_write_rr(uint8_t *buf, int *offset, const struct rist_peer *peer)
{
	struct rist_rtcp_rr_pkt *rr = (struct rist_rtcp_rr_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
	*offset += sizeof(struct rist_rtcp_rr_pkt);
	rr->rtcp.flags = RTCP_RR_FULL_FLAGS;
	rr->rtcp.ptype = PTYPE_RR;
	rr->rtcp.ssrc = htobe32(peer->adv_flow_id);
	rr->rtcp.len = htons(7);
	/* TODO fix these variables */
	rr->fraction_lost = 0;
	rr->cumulative_pkt_loss_msb = 0;
	rr->cumulative_pkt_loss_lshw = 0;
	rr->highest_seq = 0;
	rr->jitter = 0;
	rr->lsr = htobe32((uint32_t)(peer->last_sender_report_time >> 16));
	/*  expressed in units of 1/65536  == middle 16 bits?!? */
	rr->dlsr = htobe32((uint32_t)((timestampNTP_u64() - peer->last_sender_report_ts) >> 16));
}

static inline void rist_rtcp_write_sr(uint8_t *buf, int *offset, struct rist_peer *peer) {
	struct rist_rtcp_sr_pkt *sr = (struct rist_rtcp_sr_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
	*offset += sizeof(struct rist_rtcp_sr_pkt);
	/* Populate SR for sender */
	sr->rtcp.flags = RTCP_SR_FLAGS;
	sr->rtcp.ptype = PTYPE_SR;
	sr->rtcp.ssrc = htobe32(peer->adv_flow_id);
	sr->rtcp.len = htons(6);
	uint64_t now = timestampNTP_u64();
	uint64_t now_rtc = timestampNTP_RTC_u64();
	peer->last_sender_report_time = now_rtc;
	peer->last_sender_report_ts = now;
	uint32_t ntp_lsw = (uint32_t)now_rtc;
	// There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
	// No leap seconds during that period since they were not invented yet.
	uint32_t ntp_msw = now_rtc >> 32;
	sr->ntp_msw = htobe32(ntp_msw);
	sr->ntp_lsw = htobe32(ntp_lsw);
	struct rist_common_ctx *ctx = get_cctx(peer);
	int advanced = ctx->profile == RIST_PROFILE_ADVANCED ? 1 : 0;
	sr->rtp_ts = htobe32(timestampRTP_u32(advanced, now));
	sr->sender_pkts = 0;  //htonl(f->packets_count);
	sr->sender_bytes = 0; //htonl(f->bytes_count);
}

static inline void rist_rtcp_write_sdes(uint8_t *buf, int *offset, const char *name, const uint32_t flow_id)
{
	size_t namelen = strlen(name);
	size_t sdes_size = ((10 + namelen + 1) + 3) & ~3;
	size_t padding = sdes_size - namelen - 10;
	struct rist_rtcp_sdes_pkt *sdes = (struct rist_rtcp_sdes_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
	*offset += sdes_size;
	/* Populate SDES for sender description */
	sdes->rtcp.flags = RTCP_SDES_FLAGS;
	sdes->rtcp.ptype = PTYPE_SDES;
	sdes->rtcp.len = htons((uint16_t)((sdes_size - 1) >> 2));
	sdes->rtcp.ssrc = htobe32(flow_id);
	sdes->cname = 1;
	sdes->name_len = (uint8_t)namelen;
	// We copy the extra padding bytes from the source because it is a preallocated buffer
	// of size 128 with all zeroes
	memcpy(sdes->udn, name, namelen + padding);
}

static inline void rist_rtcp_write_echoreq(uint8_t *buf, int *offset, const uint32_t flow_id)
{
	struct rist_rtcp_echoext *echo = (struct rist_rtcp_echoext *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
	*offset += sizeof(struct rist_rtcp_echoext);
	echo->flags = RTCP_ECHOEXT_REQ_FLAGS;
	echo->ptype = PTYPE_NACK_CUSTOM;
	echo->ssrc = htobe32(flow_id);
	echo->len = htons(5);
	memcpy(echo->name, "RIST", 4);
	uint64_t now = timestampNTP_u64();
	echo->ntp_msw = htobe32((uint32_t)(now >> 32));
	echo->ntp_lsw = htobe32((uint32_t)(now & 0x000000000FFFFFFFF));
}

static inline void rist_rtcp_write_echoresp(uint8_t *buf,int *offset, const uint64_t request_time, const uint32_t flow_id) {
	struct rist_rtcp_echoext *echo = (struct rist_rtcp_echoext *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
	*offset += sizeof(struct rist_rtcp_echoext);
	echo->flags = RTCP_ECHOEXT_RESP_FLAGS;
	echo->ptype = PTYPE_NACK_CUSTOM;
	echo->len = htons(5);
	echo->ssrc = htobe32(flow_id);
	memcpy(echo->name, "RIST", 4);
	echo->ntp_msw = htobe32((uint32_t)(request_time >> 32));
	echo->ntp_lsw = htobe32((uint32_t)(request_time & 0x000000000FFFFFFFF));
	echo->delay = 0;
}

int rist_receiver_periodic_rtcp(struct rist_peer *peer) {
	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;

	int payload_len = 0;
	rist_rtcp_write_rr(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->adv_flow_id);
	struct rist_common_ctx *cctx = get_cctx(peer);
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, cctx->seq++, 0);
}

int rist_receiver_send_nacks(struct rist_peer *peer, uint32_t seq_array[], size_t array_len)
{
	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;

	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (RIST_LIKELY(array_len > 0)) {
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
		uint32_t fci_count = 1;

		// Now the NACK message
		if (peer->receiver_ctx->nack_type == RIST_NACK_BITMASK)
		{
			struct rist_rtcp_nack_bitmask *rtcp = (struct rist_rtcp_nack_bitmask *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext));
			rtcp->flags = RTCP_NACK_BITMASK_FLAGS;
			rtcp->ptype = PTYPE_NACK_BITMASK;
			rtcp->ssrc_source = 0; // TODO
			rtcp->ssrc = htobe32(peer->adv_flow_id);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext) + RTCP_FB_HEADER_SIZE);
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
			struct rist_rtcp_nack_range *rtcp = (struct rist_rtcp_nack_range *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext));
			rtcp->flags = RTCP_NACK_RANGE_FLAGS;
			rtcp->ptype = PTYPE_NACK_CUSTOM;
			rtcp->ssrc_source = htobe32(peer->adv_flow_id);
			memcpy(rtcp->name, "RIST", 4);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + sizeof(struct rist_rtcp_seqext) + RTCP_FB_HEADER_SIZE);
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
		int nack_bufsize = sizeof(struct rist_rtcp_seqext) + RTCP_FB_HEADER_SIZE + RTCP_FB_FCI_GENERIC_NACK_SIZE * fci_count;
		payload_len += nack_bufsize;
		payload_type = RIST_PAYLOAD_TYPE_RTCP_NACK;
	}

	// We use direct send from receiver to sender (no fifo to keep track of seq/idx)
	struct rist_common_ctx *cctx = get_cctx(peer);
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, cctx->seq++, 0);
}

static void rist_sender_send_rtcp(uint8_t *rtcp_buf, int payload_len, struct rist_peer *peer) {
	struct rist_common_ctx *cctx = get_cctx(peer);
	if (cctx->profile == RIST_PROFILE_ADVANCED) {
		struct rist_sender *ctx = peer->sender_ctx;
		pthread_mutex_lock(&ctx->queue_lock);
		size_t sender_write_index = atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire);
		ctx->sender_queue[sender_write_index] = rist_new_buffer(cctx, rtcp_buf, payload_len, RIST_PAYLOAD_TYPE_RTCP, 0, 0, peer->local_port, peer->remote_port);
		if (RIST_UNLIKELY(!ctx->sender_queue[sender_write_index]))
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\t Could not create packet buffer inside sender buffer, OOM, decrease max bitrate or buffer time length\n");
			pthread_mutex_unlock(&ctx->queue_lock);
			return;
		}
		ctx->sender_queue[sender_write_index]->peer = peer;
		ctx->sender_queue_bytesize += payload_len;
		atomic_store_explicit(&ctx->sender_queue_write_index, (sender_write_index + 1) & (ctx->sender_queue_max - 1), memory_order_release);
		pthread_mutex_unlock(&ctx->queue_lock);
		return;
	}
	rist_send_common_rtcp(peer, RIST_PAYLOAD_TYPE_RTCP, rtcp_buf, payload_len, 0, peer->local_port, peer->remote_port, cctx->seq++, 0);
}

void rist_sender_periodic_rtcp(struct rist_peer *peer) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;

	rist_rtcp_write_sr(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	// Push it to the FIFO buffer to be sent ASAP (even in the simple profile case)
	// Enqueue it to not misalign the buffer and to resend lost handshakes in the case of advanced mode
	rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
	return;
}

int rist_respond_echoreq(struct rist_peer *peer, const uint64_t echo_request_time) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	rist_rtcp_write_echoresp(rtcp_buf, &payload_len, echo_request_time, peer->adv_flow_id);
	if (peer->receiver_mode) {
		uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
		struct rist_common_ctx *cctx = get_cctx(peer);
		return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, cctx->seq++, 0);
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
	rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->adv_flow_id);
	if (peer->receiver_mode)
	{
		uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
		struct rist_common_ctx *cctx = get_cctx(peer);
		return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, cctx->seq++, 0);
	}
	else
	{
		/* I do this to not break advanced mode, however echo responses should really NOT be resend when lost ymmv */
		rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
		return 0;
	}
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
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Sending %d nacks starting with %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n",
			peer->nacks.counter, peer->nacks.array[0],peer->nacks.array[1],peer->nacks.array[2],peer->nacks.array[3]);
		if (rist_receiver_send_nacks(outputpeer->peer_rtcp, peer->nacks.array, peer->nacks.counter) == 0)
			peer->nacks.counter = 0;
		else
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "\tCould not send nacks, will try again\n");
	} else {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "\tCannot send nack, all peers are dead\n");
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
		if (!outputpeer->is_data)
			outputpeer = outputpeer->peer_data;
		if (outputpeer->nacks.counter > 0) {
			rist_send_peer_nacks(f, outputpeer);
		}
	}
}

int rist_sender_enqueue(struct rist_sender *ctx, const void *data, size_t len, uint64_t datagram_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp)
{
	uint8_t payload_type = RIST_PAYLOAD_TYPE_DATA_RAW;

	if (ctx->common.PEERS == NULL) {
		// Do not cache data if the lib user has not added peers
		return -1;
	}

	ctx->last_datagram_time = datagram_time;

	/* insert into sender fifo queue */
	pthread_mutex_lock(&ctx->queue_lock);
	size_t sender_write_index = atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire);
	ctx->sender_queue[sender_write_index] = rist_new_buffer(&ctx->common, data, len, payload_type, 0, datagram_time, src_port, dst_port);
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
	
peer_select:

	peercnt = 0;
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {

		if (!peer->is_data || peer->parent)
			continue;

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
					if (child->is_data && !child->dead) {
					uint8_t *payload = buffer->data;
					rist_send_common_rtcp(child, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq, buffer->seq_rtp);
					}
					child = child->sibling_next;
				}
			} else {
				uint8_t *payload = buffer->data;
				rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq, buffer->seq_rtp);
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
				if (child->is_data && !child->dead) {
					uint8_t *payload = buffer->data;
					rist_send_common_rtcp(child, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq, buffer->seq_rtp);
				}
				child = child->sibling_next;
			}
		} else {
			uint8_t *payload = buffer->data;
			rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, buffer->seq, buffer->seq_rtp);
			ctx->weight_counter--;
			peer->w_count--;
		}
	}

	if (ctx->total_weight > 0 && (ctx->weight_counter == 0 || !selected_peer_by_weight)) {
		peer = ctx->common.PEERS;
		ctx->weight_counter = ctx->total_weight;
		for (; peer; peer = peer->next) {
			if (peer->listening || !peer->is_data)
				continue;
			peer->w_count = peer->config.weight;
		}
		if (!selected_peer_by_weight && peercnt > 0)
			goto peer_select;
	}
}

static size_t rist_sender_index_get(struct rist_sender *ctx, uint32_t seq)
{
	// This is by design in advanced mode, that is why we push all output data and handshakes 
	// through the sender_queue, so we can keep the seq and idx in sync
	size_t idx = (seq + 1)& (ctx->sender_queue_max -1);
	if (ctx->common.profile < RIST_PROFILE_ADVANCED) {
		// For simple profile and main profile without extended seq numbers, we use a conversion table
		idx = ctx->seq_index[(uint16_t)seq];
	}
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
//	rist_log_priv(&ctx->common, RIST_LOG_ERROR,
//			"\tCurrent read/write index are %zu/%zu \n", ctx->sender_retry_queue_read_index,
//			ctx->sender_retry_queue_write_index);

	// TODO: Is this logic flawed and we are always one unit behind (look at oob_dequee)
	size_t sender_retry_queue_read_index = (ctx->sender_retry_queue_read_index + 1)& (ctx->sender_retry_queue_size -1);

	if (sender_retry_queue_read_index == ctx->sender_retry_queue_write_index) {
		//rist_log_priv(&ctx->common, RIST_LOG_ERROR,
		//	"\t[GOOD] We are all up to date, index is %" PRIu64 "\n",
		//	ctx->sender_retry_queue_read_index);
		return 0;
	}

	ctx->sender_retry_queue_read_index = sender_retry_queue_read_index;
	struct rist_retry *retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_read_index];

	// If they request a non-sense seq number, we will catch it when we check the seq number against
	// the one on that buffer position and it does not match

	size_t idx = rist_sender_index_get(ctx, retry->seq);
	if (ctx->sender_queue[idx] == NULL) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			" Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), consider increasing the buffer size\n",
			retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx));
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	} else if (ctx->common.profile == RIST_PROFILE_ADVANCED && ctx->sender_queue[idx]->seq != retry->seq) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			" Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), found an old one instead %" PRIu32 " (%" PRIu64 "), something is very wrong!\n",
			retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx), ctx->sender_queue[idx]->seq, ctx->sender_queue_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}
	else if (ctx->common.profile < RIST_PROFILE_ADVANCED && (uint16_t)retry->seq != ctx->sender_queue[idx]->seq_rtp) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			" Couldn't find block %" PRIu16 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), found an old one instead %" PRIu32 " (%" PRIu64 "), bitrate is too high, use advanced profile instead\n",
			(uint16_t)retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx), ctx->sender_queue[idx]->seq_rtp, ctx->sender_queue_max);
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
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Bandwidth exceeded: (%zu + %zu) > %d, not resending packet %"PRIu64".\n",
			cli_bw->bitrate, retry_bw->bitrate, max_bitrate, idx);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	// For timing debugging
	uint64_t now = timestampNTP_u64();
	uint64_t data_age = (now - ctx->sender_queue[idx]->time) / RIST_CLOCK;
	uint64_t retry_age = (now - retry->insert_time) / RIST_CLOCK;
	if (retry_age > retry->peer->config.recovery_length_max) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Retry-request of element %" PRIu32 " (idx %zu) that was sent %" PRIu64
				"ms ago has been in the queue too long to matter: %"PRIu64"ms > %ums\n",
			retry->seq, idx, data_age, retry_age, retry->peer->config.recovery_length_max);
		return -1;
	}

	struct rist_buffer *buffer = ctx->sender_queue[idx];
	/* queue_time holds the original insertion time for this seq */
	if (ctx->common.debug)
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Resending %"PRIu32"/%"PRIu32"/%"PRIu16" (idx %zu) after %" PRIu64
			"ms of first transmission and %"PRIu64"ms in queue, bitrate is %zu + %zu, %zu\n",
			retry->seq, buffer->seq, buffer->seq_rtp, idx, data_age, retry_age, retry->peer->bw.bitrate, 
			retry_bw->bitrate, retry->peer->bw.bitrate + retry_bw->bitrate);

	uint8_t *payload = buffer->data;

	// TODO: I do not think this check is needed anymore ... we fixed the bug that was causing
	// this scenario ... and we have thread-locking to prevent this
	if (!payload)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Someone deleted my buffer when resending %" PRIu32 " (idx %zu) after %" PRIu64
			"ms of first transmission and %"PRIu64"ms in queue, bitrate is %zu + %zu, %zu\n",
			retry->seq, idx, data_age, retry_age, retry->peer->bw.bitrate, retry_bw->bitrate,
			retry->peer->bw.bitrate + retry_bw->bitrate);
	}

	buffer->transmit_count++;
	size_t ret = 0;
	if (buffer->transmit_count >= retry->peer->config.max_retries) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Datagram %"PRIu32
			" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu\n",
			buffer->seq, buffer->transmit_count, data_age, buffer->transmit_count);
	}
	else {
		ret = (size_t)rist_send_seq_rtcp(retry->peer->peer_data, buffer->seq, buffer->seq_rtp, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port);
	}

	// update bandwidh value
	rist_calculate_bitrate_sender(ret, retry_bw);
	if (ret < buffer->size) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Resending of packet failed %zu != %zu for seq %"PRIu32"\n", ret, buffer->size, buffer->seq);
		retry->peer->stats_sender_instant.retrans_skip++;
	} else {
		retry->peer->stats_sender_instant.retrans++;
	}

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
	// The policy of whether to allow or not allow duplicate seq entries in the retry queue
	// is dependent on the bloat_mode.
	// bloat_mode disabled mode = unlimited duplicates
	// bloat_mode normal mode = we enforce spacing but allow duplicates
	// bloat_mode aggresive mode = no duplicates allowed
	// This is a safety check to protect against buggy or non compliant receivers that request the
	// same seq number without waiting one RTT.

	if (!buffer)
	{
		rist_log_priv(&ctx->common, RIST_LOG_WARN,
			"Nack request for seq %"PRIu32" but we do not have it in the buffer (%zu ms)\n", seq,
			ctx->sender_recover_min_time);
		return;
	} else {
		uint64_t age_ticks =  (now - buffer->time);
		if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_OFF) {
			// All duplicates allowed, just report it
			if (ctx->common.debug)
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Nack request for seq %" PRIu32 " with age %" PRIu64 "ms and rtt_min %" PRIu32 " for peer #%d\n",
					buffer->seq, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min, peer->adv_peer_id);
		} else if (ctx->peer_lst_len == 1) {
			// Only one peer (faster algorithm with no lookups)
			if (buffer->last_retry_request != 0)
			{
				// This is a safety check to protect against buggy or non compliant receivers that request the
				// same seq number without waiting one RTT.
				uint64_t delta = (now - buffer->last_retry_request) / RIST_CLOCK;
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms, age %" PRIu64 "ms and rtt_min %" PRIu32 "\n",
						buffer->seq, delta, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min);
				if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_NORMAL) {
					if (delta < peer->config.recovery_rtt_min)
					{
						rist_log_priv(&ctx->common, RIST_LOG_WARN,
							"Nack request for seq %" PRIu32 ", age %"PRIu64"ms, is already queued (too soon to add another one), skipped, %" PRIu64 " < %" PRIu32 " ms\n",
							buffer->seq, age_ticks / RIST_CLOCK, delta, peer->config.recovery_rtt_min);
						peer->stats_sender_instant.bloat_skip++;
						return;
					}
				}
				else
				{
					rist_log_priv(&ctx->common, RIST_LOG_WARN,
						"Nack request for seq %" PRIu32 ", delta/age %"PRIu64"ms/%"PRIu64"ms is already queued, skipped\n",
						buffer->seq, delta, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min);
						peer->stats_sender_instant.bloat_skip++;
					return;
				}
			}
			else
			{
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"First nack request for seq %"PRIu32", age %"PRIu64"ms\n", buffer->seq, age_ticks / RIST_CLOCK);
			}
		} else {
			// Multiple peers, we need to search for other retries in the queue for comparison
			uint64_t delta = 0;
			size_t index_end = 0;
			size_t index = 0;
			// We search forward for aggressive mode and backwards for normal
			if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
				index = ctx->sender_retry_queue_read_index;
				index_end = ctx->sender_retry_queue_write_index;
			} else {
				index = ctx->sender_retry_queue_write_index;
				index_end = ctx->sender_retry_queue_read_index;
			}
			uint64_t rist_max_jitter_ticks = (uint64_t)ctx->common.rist_max_jitter;
			while (index != index_end) {
				if ((index % 10) == 0) {
					// We will completely bypass this check if/when it takes too long as we are
					// blocking the protocol thread (it could happen when the queue gets too big)
					uint64_t loop_time = timestampNTP_u64() - now;
					if (loop_time > rist_max_jitter_ticks) {
						size_t retry_queue_size = rist_get_sender_retry_queue_size(ctx);
						rist_log_priv(&ctx->common, RIST_LOG_WARN,
							"Bypassing duplicate nack request check for seq %"PRIu32" after %"PRIu64"us, age %"PRIu64"ms, q_size = %zu (taking too long)\n",
							buffer->seq, 1000 * loop_time / RIST_CLOCK, age_ticks / RIST_CLOCK, retry_queue_size);
						break;
					}
				}
				retry = &ctx->sender_retry_queue[index];
				if (retry->seq == seq && retry->peer == peer) {
					delta = (now - retry->insert_time) / RIST_CLOCK;
					if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_NORMAL) {
						if (delta < peer->config.recovery_rtt_min)
						{
							rist_log_priv(&ctx->common, RIST_LOG_WARN,
								"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) is already queued (too soon to add another one), skipped, peer #%d '%s'\n",
								buffer->seq, delta, age_ticks / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
							peer->stats_sender_instant.bloat_skip++;
							return;
						}
						else {
							// There is only one in the queue for bloat_mode agresive
							// and we area only interested on the last one queued for bloat_mode normal
							break;
						}
					} else {
						rist_log_priv(&ctx->common, RIST_LOG_WARN,
							"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) is already queued, skipped, peer #%d '%s'\n",
							buffer->seq, delta, age_ticks / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
						peer->stats_sender_instant.bloat_skip++;
						return;
					}
				}
				// We search forward for aggressive mode and backwards for normal
				if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE)
				{
					if (++index >= ctx->sender_retry_queue_size)
						index= 0;
				}
				else
				{
					if (index == 0)
						index = ctx->sender_retry_queue_size;
					index--;
				}
			}
			if (ctx->common.debug) {
				if (delta) {
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) and rtt_min %" PRIu32 " for peer #%d '%s'\n",
						buffer->seq, delta, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min, peer->adv_peer_id, peer->receiver_name);
				} else {
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"First nack request for seq %"PRIu32", age %"PRIu64"ms, peer #%d '%s'\n",
						buffer->seq, age_ticks / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
				}
			}
		}
	}
	// Now insert into the missing queue
	buffer->last_retry_request = now;
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
