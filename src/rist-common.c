/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Antonio Cardace <anto.cardace@gmail.com>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "rist-private.h"
#include "log-private.h"
#include "crypto/psk.h"
#include "udp-private.h"
#include "udpsocket.h"
#include "endian-shim.h"
#include "time-shim.h"
#include "eap.h"
#include "mpegts.h"
#include "rist_ref.h"
#include "config.h"
#include <stdbool.h>
#include "stdio-shim.h"
#include <assert.h>


static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static PTHREAD_START_FUNC(receiver_pthread_dataout,arg);
static void store_peer_settings(const struct rist_peer_config *settings, struct rist_peer *peer);
static struct rist_peer *peer_initialize(const char *url, struct rist_sender *sender_ctx,
										struct rist_receiver *receiver_ctx);
void remove_peer_from_flow(struct rist_peer *peer);

int parse_url_udp_options(const char* url, struct rist_udp_config *output_udp_config)
{
	uint32_t clean_url_len = 0;
	char* query = NULL;
	uint32_t prefix_len = 0;
	struct udpsocket_url_param url_params[32];
	int num_params = 0;
	int i = 0;
	int ret = 0;

	if (!url || !url[0] || !output_udp_config)
		return -1;

	query = strchr( url, '/' );
	if (query != NULL) {
		prefix_len = (uint32_t)(query - url);
		strncpy((void *)output_udp_config->prefix, url, prefix_len >= 16 ? 15 : prefix_len - 1);
		output_udp_config->prefix[prefix_len] = '\0';
		// Convert to lower
		char *p =(char *)output_udp_config->prefix;
		for(i = 0; i < 16; i++)
			p[i] = p[i] > 0x40 && p[i] < 0x5b ? p[i] | 0x60 : p[i];
		if (!strncmp(output_udp_config->prefix, "rtp", 3))
			output_udp_config->rtp = true;
		else
			output_udp_config->rtp = false;
	} else {
		// default is udp
		char src[] = "udp";
		strcpy((void *)output_udp_config->prefix, src);
		output_udp_config->rtp = false;
	}

	// Parse URL parameters
	num_params = udpsocket_parse_url_parameters( url, url_params,
			sizeof(url_params) / sizeof(struct udpsocket_url_param), &clean_url_len );
	if (num_params > 0) {
		for (i = 0; i < num_params; ++i) {
			char* val = url_params[i].val;
			if (!val)
				continue;

			if (strcmp( url_params[i].key, RIST_URL_PARAM_MIFACE ) == 0) {
				strncpy((void *)output_udp_config->miface, val, 128-1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_STREAM_ID ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_udp_config->stream_id = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTP_TIMESTAMP ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->rtp_timestamp = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTP_SEQUENCE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->rtp_sequence = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAP_RTP_OUTPUT_PTYPE) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->rtp_ptype = (uint8_t)temp;
			} else {
				ret = -1;
				fprintf(stderr, "Unknown or invalid parameter %s\n", url_params[i].key);
			}
		}
	}
	strncpy((void *)output_udp_config->address, url, clean_url_len >= RIST_MAX_STRING_LONG ? RIST_MAX_STRING_LONG-1 : clean_url_len - 1);

	if (ret != 0)
		return num_params;
	else
		return 0;
}

int parse_url_options(const char* url, struct rist_peer_config *output_peer_config)
{
	uint32_t clean_url_len = 0;
	struct udpsocket_url_param url_params[32];
	int num_params = 0;
	int i = 0;
	int ret = 0;

	if (!url || !url[0] || !output_peer_config)
		return -1;

	// Parse URL parameters
	num_params = udpsocket_parse_url_parameters( url, url_params,
			sizeof(url_params) / sizeof(struct udpsocket_url_param), &clean_url_len );
	if (num_params > 0) {
		for (i = 0; i < num_params; ++i) {
			char* val = url_params[i].val;
			if (!val)
				continue;

			if (strcmp( url_params[i].key, RIST_URL_PARAM_BUFFER_SIZE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0) {
					output_peer_config->recovery_length_min = temp;
					output_peer_config->recovery_length_max = temp;
				}
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_BUFFER_SIZE_MIN ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_length_min = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_BUFFER_SIZE_MAX ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_length_max = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MIFACE ) == 0) {
				strncpy((void *)output_peer_config->miface, val, 128-1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SECRET ) == 0) {
				strncpy((void *)output_peer_config->secret, val, 128-1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SRP_USERNAME) == 0) {
				strncpy((void *)output_peer_config->srp_username, val, 256 -1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SRP_PASSWORD) == 0) {
				strncpy((void *)output_peer_config->srp_password, val, 256 -1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_CNAME ) == 0) {
				strncpy((void *)output_peer_config->cname, val, 128-1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_AES_TYPE ) == 0) {
				int temp = atoi( val );
				if (temp == 0 || temp == 128 || temp == 192 || temp == 256) {
					output_peer_config->key_size = temp;
				}
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_AES_KEY_ROTATION ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->key_rotation = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_BANDWIDTH ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->recovery_maxbitrate = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RET_BANDWIDTH ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_maxbitrate_return = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT ) == 0) {
				int temp = atoi( val );
				if (temp >= 0) {
					output_peer_config->recovery_rtt_min = temp;
					output_peer_config->recovery_rtt_max = temp;
				}
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_MIN ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_rtt_min = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_MAX ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_rtt_max = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_REORDER_BUFFER ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_reorder_buffer = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_COMPRESSION ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->compression = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_VIRT_DST_PORT ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->virt_dst_port = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_WEIGHT ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->weight = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SESSION_TIMEOUT ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->session_timeout = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_KEEPALIVE_INT ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->keepalive_interval = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_CONGESTION_CONTROL ) == 0) {
				int temp = atoi( val );
				if (temp >= 0 && temp <= 2)
					output_peer_config->congestion_control_mode = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_TIMING_MODE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0 && temp <= 2)
					output_peer_config->timing_mode = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MIN_RETRIES ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->min_retries = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MAX_RETRIES ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->max_retries = temp;
			} else {
				ret = -1;
				fprintf(stderr, "Unknown or invalid parameter %s\n", url_params[i].key);
			}
		}
	}
	strncpy((void *)output_peer_config->address, url, clean_url_len >= RIST_MAX_STRING_LONG ? RIST_MAX_STRING_LONG-1 : clean_url_len - 1);

	if (ret != 0)
		return num_params;
	else
		return 0;
}

struct rist_common_ctx *get_cctx(struct rist_peer *peer)
{
	if (peer->sender_ctx) {
		return &peer->sender_ctx->common;
	} else {
		return &peer->receiver_ctx->common;
	}
}

int rist_max_jitter_set(struct rist_common_ctx *ctx, int t)
{
	if (t > 0) {
		ctx->rist_max_jitter = t * RIST_CLOCK;
		return 0;
	}

	return -1;
}

static void init_peer_settings(struct rist_peer *peer)
{
	if (peer->receiver_mode) {
		assert(peer->receiver_ctx != NULL);
		uint32_t recovery_maxbitrate_mbps = peer->config.recovery_maxbitrate < 1000 ? 1 : peer->config.recovery_maxbitrate / 1000;
		// Initial value for some variables
		peer->recovery_buffer_ticks =
			(peer->config.recovery_length_max - peer->config.recovery_length_min) / 2 + peer->config.recovery_length_min;
		peer->recovery_buffer_ticks = peer->recovery_buffer_ticks * RIST_CLOCK;
		peer->missing_counter_max =
			(uint32_t)(peer->recovery_buffer_ticks / RIST_CLOCK) * recovery_maxbitrate_mbps /
			(sizeof(struct rist_gre_seq) + sizeof(struct rist_rtp_hdr) + sizeof(uint32_t));
		peer->eight_times_rtt = peer->config.recovery_rtt_min * 8;

		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"New peer with id #%"PRIu32" was configured with maxrate=%d/%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d congestion_control=%d min_retries=%d max_retries=%d\n",
				peer->adv_peer_id, peer->config.recovery_maxbitrate, peer->config.recovery_maxbitrate_return, peer->config.recovery_length_min, peer->config.recovery_length_max, peer->config.recovery_reorder_buffer,
				peer->config.recovery_rtt_min, peer->config.recovery_rtt_max, peer->config.congestion_control_mode, peer->config.min_retries, peer->config.max_retries);
	}
	else {
		assert(peer->sender_ctx != NULL);
		struct rist_sender *ctx = peer->sender_ctx;
		/* Global context settings */
		if (peer->config.recovery_maxbitrate > ctx->recovery_maxbitrate_max) {
			ctx->recovery_maxbitrate_max = peer->config.recovery_maxbitrate;
			int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
			// Asume MTU of 1400 for now
			uint32_t max_nacksperloop = ctx->recovery_maxbitrate_max * max_jitter_ms / (8*1400);
			// Normalize against the total buffer size
			max_nacksperloop = max_nacksperloop * 1000 / peer->config.recovery_length_max;
			// Anything less that 2240Kbps at 5ms will round down to zero (100Mbps is 44)
			if (max_nacksperloop == 0)
				max_nacksperloop = 1;
			// The effective buffer is 50% the total buffer size
			max_nacksperloop = max_nacksperloop  * 2;
			if (max_nacksperloop > ctx->max_nacksperloop) {
				ctx->max_nacksperloop = (uint32_t)max_nacksperloop;
				rist_log_priv(&ctx->common, RIST_LOG_INFO, "Setting max nacks per cycle to %"PRIu32"\n",
				max_nacksperloop);
			}
		}

		if (peer->config.weight > 0) {
			ctx->total_weight += peer->config.weight;
			rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peer weight: %lu\n", peer->config.weight);
		}

		/* Set target recover size (buffer) */
		if ((peer->config.recovery_length_max + (2 * peer->config.recovery_rtt_max)) > ctx->sender_recover_min_time) {
			ctx->sender_recover_min_time = peer->config.recovery_length_max + (2 * peer->config.recovery_rtt_max);
			rist_log_priv(&ctx->common, RIST_LOG_INFO, "Setting buffer size to %zums (Max buffer size + 2 * Max RTT)\n", ctx->sender_recover_min_time);
			// TODO: adjust this size based on the dynamic RTT measurement
		}

	}
}

struct rist_buffer *rist_new_buffer(struct rist_common_ctx *ctx, const void *buf, size_t len, uint8_t type, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	RIST_MARK_UNUSED(ctx);
	// TODO: we will ran out of stack before heap and when that happens malloc will crash not just
	// return NULL ... We need to find and remove all heap allocations
	struct rist_buffer *b;
	b = malloc(sizeof(*b));
	if (!b) {
		fprintf(stderr, "OOM\n");
		return NULL;
	}

	if (buf != NULL && len > 0)
	{
		b->data = malloc(len + RIST_MAX_PAYLOAD_OFFSET);
		if (!b->data) {
			free(b);
			fprintf(stderr, "OOM\n");
			return NULL;
		}
	}
	b->alloc_size = len;
	if (buf != NULL && len > 0)
	{
		memcpy((uint8_t *)b->data + RIST_MAX_PAYLOAD_OFFSET, buf, len);
	}
	b->alloc_size = len;
	b->next_free = NULL;
	b->free = false;
	b->size = len;
	b->source_time = source_time;
	b->seq = seq;
	b->time = timestampNTP_u64();
	b->type = type;
	b->src_port = src_port;
	b->dst_port = dst_port;
	b->last_retry_request = 0;
	b->transmit_count = 0;
	b->use_seq = 0;
	return b;
}

void free_rist_buffer(struct rist_common_ctx *ctx, struct rist_buffer *b)
{
	RIST_MARK_UNUSED(ctx);
	free(b->data);
	free(b);

}

static uint64_t receiver_calculate_packet_time(struct rist_flow *f, const uint64_t source_time, uint64_t now, bool retry, uint8_t payload_type)
{
	//Check and correct timing
	uint64_t packet_time = source_time + f->time_offset;
	if (RIST_UNLIKELY(!retry && source_time < f->max_source_time && ((f->max_source_time - source_time) > (UINT32_MAX /2)) && (now - f->time_offset_changed_ts) > 3 * f->recovery_buffer_ticks))
	{
		int64_t new_offset = (int64_t)now - (int64_t)source_time;
		int64_t offset_diff = llabs(new_offset - f->time_offset);
		//Make sure the new and old offsets differ atleast by 10 hrs, otherwise something is wrong.
		if (offset_diff > (int64_t)(10LL * 3600LL * 1000LL * RIST_CLOCK)) {
			f->time_offset_old = f->time_offset;
			//Calculate new offset by getting max time for payload type and adding it to old offset
			//Fast path for mpegts payload type with clock of 90khz
			if (RIST_UNLIKELY(payload_type != RTP_PTYPE_RIST))
				f->time_offset += convertRTPtoNTP(payload_type, 0, UINT32_MAX);
			else
				f->time_offset += ((uint64_t)UINT32_MAX << 32) / RTP_PTYPE_MPEGTS_CLOCKHZ;
			rist_log_priv(get_cctx(f->peer_lst[0]), RIST_LOG_INFO, "Clock wrapped, old offset: %" PRId64 " new offset %" PRId64 "\n", f->time_offset / RIST_CLOCK, f->time_offset_old / RIST_CLOCK);
			f->offset_recalc_sample_count = 0;
			f->max_source_time = 0;
			f->time_offset_changed_ts = now;
		}
		packet_time = source_time + f->time_offset;
		//Packets with old clock will be too big due to the wrong offset.
	} else 	if (RIST_UNLIKELY(packet_time > f->last_packet_ts && ((packet_time - f->last_packet_ts) > UINT32_MAX / 2) && (now - f->time_offset_changed_ts) < 3 * f->recovery_buffer_ticks))
	{
		packet_time = source_time + f->time_offset_old;
	} else if (source_time > f->max_source_time)
	{
		f->last_packet_ts = packet_time;
		f->max_source_time = source_time;
	}
	return packet_time;
}

static int receiver_insert_queue_packet(struct rist_flow *f, struct rist_peer *peer, size_t idx, const void *buf, size_t len, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port, uint64_t packet_time)
{
	/*
	   rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
	   "Inserting seq %"PRIu32" len %zu source_time %"PRIu32" at idx %zu\n",
	   seq, len, source_time, idx);
	   */
	f->receiver_queue[idx] = rist_new_buffer(get_cctx(peer), buf, len, RIST_PAYLOAD_TYPE_DATA_RAW, seq, source_time, src_port, dst_port);
	if (RIST_UNLIKELY(!f->receiver_queue[idx])) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not create packet buffer inside receiver buffer, OOM, decrease max bitrate or buffer time length\n");
		return -1;
	}
	f->receiver_queue[idx]->peer = peer;
	f->receiver_queue[idx]->packet_time = packet_time;
	f->receiver_queue[idx]->target_output_time = packet_time + f->recovery_buffer_ticks;
	atomic_fetch_add_explicit(&f->receiver_queue_size, len, memory_order_release);

	return 0;
}

static inline void receiver_mark_missing(struct rist_flow *f, struct rist_peer *peer, uint32_t current_seq, uint32_t rtt) {
	uint32_t counter = 1;
	uint64_t packet_time_last = 0;
	if (RIST_UNLIKELY(!f->receiver_queue[f->last_seq_found]))
		if (RIST_LIKELY(!f->rtc_timing_mode))
			packet_time_last = timestampNTP_u64();
		else
			packet_time_last = timestampNTP_RTC_u64();
	else
		packet_time_last = f->receiver_queue[f->last_seq_found]->packet_time;
	uint64_t packet_time_now = f->receiver_queue[current_seq]->packet_time;
	uint32_t missing_count = (current_seq - f->last_seq_found) & UINT16_MAX;
	//arbitrary large number to prevent incorrectly marking packets as missing when wrap-around occurs & we did not correctly detect as out of order
	if (missing_count > 32768)
		return;
	uint64_t interpacket_time = (packet_time_now - packet_time_last) / (missing_count +1);
	uint32_t missing_seq = (f->last_seq_found + counter);

	if (f->short_seq)
		missing_seq = (uint16_t)missing_seq;

	uint64_t nack_time = packet_time_last;
	while (missing_seq != current_seq)
	{
		nack_time += interpacket_time;
		if (RIST_UNLIKELY(peer->buffer_bloat_active || f->missing_counter > peer->missing_counter_max))
		{
			if (f->missing_counter > peer->missing_counter_max)
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
					"Retry buffer is already too large (%d) for the configured "
					"bandwidth ... ignoring missing packet(s).\n",
					f->missing_counter);
			if (peer->buffer_bloat_active)
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
					"Link has collapsed. Not queuing new retries until it recovers.\n");
			break;
		}
		rist_receiver_missing(f, peer, nack_time, missing_seq, rtt);
		if (RIST_UNLIKELY(counter == f->receiver_queue_max))
			break;
		counter++;
		missing_seq = (f->last_seq_found + counter);
		if (f->short_seq)
			missing_seq = (uint16_t)missing_seq;
	}
}

int compare(const void *a, const void *b)
{
	return ( *(uint64_t*)a < *(uint64_t*)b);
}

static void recalculate_clock_offset(struct rist_flow *flow)
{
	//arbitrarily chosen minimal sample count
	if (flow->offset_recalc_sample_count < 100)
		return;

	/* to counter clock drift we are recalculating our offset every 2048 inserted
	   packets. Every "correctly" (in-order, no-discontinuities) packet's clock offset
	   is inserted into an array. Of which we will take the median. */
	qsort(flow->offset_recalc_samples, flow->offset_recalc_sample_count, sizeof(uint64_t), compare);
	size_t middle = (flow->offset_recalc_sample_count +1)/2 +1;
	uint64_t median_offset = flow->offset_recalc_samples[middle];
	flow->offset_recalc_sample_count = 0;
	uint64_t diff = 0;
	uint64_t negative = (median_offset < (uint64_t)flow->time_offset);
	if (negative)
		diff = flow->time_offset - median_offset;
	else
		diff = median_offset - flow->time_offset;
	rist_log_priv2(flow->logging_settings, RIST_LOG_DEBUG, "Recalculated clock offset, old offset: %lu, new offset: %lu difference: %c%lu usec\n",
							flow->time_offset, median_offset, negative? '-': '+', (diff * 1000 / RIST_CLOCK));
	flow->time_offset = median_offset;
}


static int receiver_enqueue(struct rist_peer *peer, uint64_t source_time, uint64_t packet_recv_time, const void *buf, size_t len, uint32_t seq, uint32_t rtt, bool retry, uint16_t src_port, uint16_t dst_port, uint8_t payload_type)
{
	struct rist_flow *f = peer->flow;

	//	fprintf(stderr,"receiver enqueue seq is %"PRIu32", source_time %"PRIu64"\n",
	//	seq, source_time);
	uint64_t now;
	uint64_t now_monotonic = packet_recv_time;
	if (RIST_LIKELY(!f->rtc_timing_mode))
		now = now_monotonic;
	else
		now = timestampNTP_RTC_u64();
	//fprintf(stderr, "Offset would've been: %llu\n", now - source_time);
	if (RIST_UNLIKELY((!f->receiver_queue_has_items && retry) || (f->rtc_timing_mode && f->time_offset == 0)))
		return -1;
	if (RIST_UNLIKELY(!f->receiver_queue_has_items)) {
		/* we just received our first packet for this flow */
		pthread_mutex_lock(&f->mutex);
		if (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) > 0)
		{
			/* Clear the queue if the queue had data */
			/* f->receiver_queue_has_items can be reset to false when the output queue is emptied */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Clearing up old %zu bytes of old buffer data\n", atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
			/* Delete all buffer data (if any) */
			empty_receiver_queue(f, get_cctx(peer));
		}
		rist_flush_missing_flow_queue(f);
		/* Initialize flow session timeout and stats timers */
		f->flag_flow_buffer_start = true;
		f->last_recv_ts = now_monotonic;
		f->checks_next_time = now_monotonic;
		/* Calculate and store clock offset with respect to source */
		if (!f->rtc_timing_mode)
			f->time_offset = (int64_t)now_monotonic - (int64_t)source_time;
		/* This ensures the next packet does not trigger nacks */
		f->last_seq_output = seq - 1;
		f->last_seq_found = seq;
		f->max_source_time = source_time;
		/* This will synchronize idx and seq so we can insert packets into receiver buffer based on seq number */
		size_t idx_initial = seq & (f->receiver_queue_max -1);
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"Storing first packet seq %" PRIu32 ", idx %zu, %" PRIu64 ", offset %" PRId64 " ms, output_idx %zu\n",
				seq, idx_initial, source_time, peer->flow->time_offset / RIST_CLOCK, idx_initial);
		uint64_t packet_time = source_time + f->time_offset;

		receiver_insert_queue_packet(f, peer, idx_initial, buf, len, seq, source_time, src_port, dst_port, packet_time);
		atomic_store_explicit(&f->receiver_queue_output_idx, idx_initial, memory_order_release);

		/* reset stats */
		pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
		memset(&f->stats_instant, 0, sizeof(f->stats_instant));
		pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
		f->receiver_queue_has_items = true;
		pthread_mutex_unlock(&f->mutex);
		return 0; // not a dupe
	}

	uint64_t packet_time = receiver_calculate_packet_time(f, source_time, now, retry, payload_type);
    size_t idx = seq & (f->receiver_queue_max - 1);
    if (RIST_UNLIKELY(peer->config.timing_mode == RIST_TIMING_MODE_ARRIVAL && retry))
	{
		//arrival packet time would be incorrect for a retry packet, so instead we interpolate between packets.
		//this does assume CBR
		struct rist_buffer *previous = NULL;
		size_t index = (idx -1)& (f->receiver_queue_max - 1);
		while (previous == NULL && index != idx)
		{
			previous = f->receiver_queue[index];
			index = (index -1)& (f->receiver_queue_max - 1);
		}
		struct rist_buffer *next = NULL;
		index = (idx +1)& (f->receiver_queue_max -1);
		while (next == NULL && index != idx)
		{
			next = f->receiver_queue[index];
			index = (index +1)& (f->receiver_queue_max -1);
		}
		//interpolate the arrival time, assuming CBR
		if (next && previous)
		{
			uint32_t steps = (next->seq - previous->seq);
			if (f->short_seq)
				steps = (uint16_t)steps;
			uint64_t time_per_step = (next->packet_time - previous->packet_time) / steps;
			uint32_t steps_since_previous = seq - previous->seq;
			if (f->short_seq)
				steps_since_previous = (uint16_t)steps_since_previous;
			packet_time = previous->packet_time + (time_per_step * steps_since_previous);
			assert(packet_time < next->packet_time);
		} else if (next)
		{
			packet_time = next->packet_time;
		}
	}

	// Now, get the new position and check what is there
	/* We need to check if the reader queue has progressed passed this packet, if
	   this is the case we silently drop the packet as it would not be output in a
	   valid way anyway.
	   We only check this for packets that arrive out of order (i.e.: with a lower
	   output time than the highest known output time) */
	size_t reader_idx;
	bool out_of_order = false;
	uint32_t expected_seq = (f->last_seq_found +1) & (UINT16_MAX -1);
	if (RIST_UNLIKELY(packet_time < f->last_packet_ts && seq != expected_seq)) {
		if (now > (packet_time + (f->recovery_buffer_ticks *1.1)))
		{
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Packet %"PRIu32" too late, dropping!\n", seq);
			pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
			f->stats_instant.dropped_late++;
			pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
			return -1;
		}
		if (!retry) {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
				"Out of order packet received, seq %" PRIu32 " / age %" PRIu64 " ms\n",
				seq, (timestampNTP_u64() - packet_time) / RIST_CLOCK);
			out_of_order = true;
		}
	}
	reader_idx = atomic_load_explicit(&f->receiver_queue_output_idx, memory_order_acquire);
	if (RIST_UNLIKELY(idx == ((reader_idx -1) &(f->receiver_queue_max -1))))
	{
		//Buffer full!
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Buffer is full, dropping packet %"PRIu32"/%zu\n", seq, idx);
		if (packet_time > f->last_packet_ts)
			f->last_seq_found  = seq;
		pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
		f->stats_instant.dropped_full++;
		pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
		//Something is wrong, and we should reset
		if (f->stats_instant.dropped_full > 100) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Buffer is full, resetting buffer\n");
			f->receiver_queue_has_items = false;
		}
		return -1;
	}
	if (RIST_UNLIKELY(f->receiver_queue[idx])) {
		// TODO: record stats
		struct rist_buffer *b = f->receiver_queue[idx];
		if (b->source_time == source_time) {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Dupe! %"PRIu32"/%zu\n", seq, idx);
			pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
			f->stats_instant.dupe++;
			pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
			return 1;
		}
		else {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Invalid Dupe (possible seq discontinuity)! %"PRIu32", freeing buffer ...\n", seq);
			free_rist_buffer(get_cctx(peer), b);
			f->receiver_queue[idx] = NULL;
		}
	}


	/* Now, we insert the packet into receiver queue */
	if (receiver_insert_queue_packet(f, peer, idx, buf, len, seq, source_time, src_port, dst_port, packet_time)) {
		// only error is OOM, safe to exit here ...
		return 0;
	}
	pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
	if (out_of_order)
		f->stats_instant.reordered++;
	f->stats_instant.received++;
	pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
	// Check for missing data and queue retries
	if (!retry) {
		/* check for missing packets */
		// We start at the last known good packet, and look forwards till we hit this seq
		uint32_t missing_seq = seq - 1;
		if (f->short_seq)
			missing_seq = (uint16_t)missing_seq;

		if (!out_of_order && missing_seq != f->last_seq_found)
		{
			receiver_mark_missing(f, peer, seq, rtt);
		} else if (RIST_LIKELY(!f->rtc_timing_mode && !out_of_order))
		{
			//packet received in order, use it's offset as a sample in calculation to
			//correct clock drift
			f->offset_recalc_samples[f->offset_recalc_sample_count] = (int64_t)now - (int64_t)source_time;
			f->offset_recalc_sample_count++;
			if (f->offset_recalc_sample_count == 2048)
				recalculate_clock_offset(f);
		}
		//If we stopped due to bloat or missing count max this will be incorrect.
		if (!out_of_order)
			f->last_seq_found = seq;
	}
	return 0;
}

static int rist_process_nack(struct rist_flow *f, struct rist_missing_buffer *b)
{
	uint64_t now;
	if (RIST_LIKELY(!f->rtc_timing_mode))
		now = timestampNTP_u64();
	else
		now = timestampNTP_RTC_u64();
	struct rist_peer *peer = b->peer;

	if (b->nack_count >= peer->config.max_retries) {
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Datagram %"PRIu32
				" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu, max_retries %d, congestion_control_mode %d, stats_receiver_total.recovered_average %d\n",
				b->seq,
				b->nack_count,
				(now - b->insertion_time) / RIST_CLOCK,
				b->nack_count,
				peer->config.max_retries,
				peer->config.congestion_control_mode,
				f->stats_total.recovered_average);
		return 8;
	} else {
		if ((uint64_t)(now - b->insertion_time) > (peer->recovery_buffer_ticks *1.1)) {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
					"Datagram %" PRIu32 " is missing but it is too late (%" PRIu64
					"ms) to send NACK!, retry #%lu, retry queue %d, max time %"PRIu64"\n",
					b->seq, (now - b->insertion_time)/RIST_CLOCK, b->nack_count,
					f->missing_counter, peer->recovery_buffer_ticks / RIST_CLOCK);
			return 9;
		} else if (now >= b->next_nack) {
			uint64_t rtt = (peer->eight_times_rtt / 8);
			if (rtt < peer->config.recovery_rtt_min) {
				rtt = peer->config.recovery_rtt_min;
			} else if (rtt > peer->config.recovery_rtt_max) {
				rtt = peer->config.recovery_rtt_max;
			}
			if (b->nack_count == 0) {
				f->missing_counter++;
				pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
				f->stats_instant.missing++;
				pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
			}

			// TODO: make this 10% overhead configurable?
			// retry more when we are running out of time (proportional)
			/* start with 1.1 * 1000 and go down from there */
			//uint32_t ratio = 1100 - (b->nack_count * 1100)/(2*b->peer->config.max_retries);
			//b->next_nack = now + (uint64_t)rtt * (uint64_t)ratio * (uint64_t)RIST_CLOCK;
			b->next_nack = now + ((uint64_t)rtt * (uint64_t)1100 * (uint64_t)RIST_CLOCK) / 1000;
			b->nack_count++;

			if (get_cctx(peer)->debug)
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Datagram %" PRIu32 " is missing, sending NACK!, next retry in %" PRIu64 "ms, age is %" PRIu64 "ms, retry #%lu, max_size is %" PRIu64 "ms\n",
					b->seq, (b->next_nack - now) / RIST_CLOCK,
					(now - b->insertion_time) / RIST_CLOCK,
					b->nack_count,
					peer->recovery_buffer_ticks / RIST_CLOCK);

			// update peer information
			f->nacks.array[f->nacks.counter] = b->seq;
			f->nacks.counter++;
			pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
			f->stats_instant.retries++;
			pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
		}
	}

	return 0;
}

void free_data_block(struct rist_data_block **const block)
{
	assert(block != NULL);
	struct rist_data_block *b = *block;
	if (!b)
		return;

	if (atomic_fetch_sub(&b->ref->refcnt, 1) == 1)
	{
		assert(b->ref->ptr == b);
		uint8_t *payload = ((uint8_t*)b->payload - RIST_MAX_PAYLOAD_OFFSET);//this is extremely ugly, though these offsets will stop existing in next release
		free(payload);
		free((void *)b->ref);
		free(b);
	}
	*block = NULL;
}

static struct rist_data_block *new_data_block(struct rist_data_block *output_buffer_current, struct rist_buffer *b, uint8_t *payload, uint32_t flow_id, uint32_t flags)
{
	struct rist_data_block *output_buffer;
	if (output_buffer_current) {
		if (rist_ref_iswritable(output_buffer_current->ref)) {
			output_buffer = output_buffer_current;
			uint8_t *p = ((uint8_t*)output_buffer_current->payload - RIST_MAX_PAYLOAD_OFFSET);
			free(p);
		} else {
			free_data_block(&output_buffer_current);
			output_buffer = calloc(1, sizeof(*output_buffer));
		}
	}
	else
		output_buffer = calloc(1, sizeof(struct rist_data_block));
	if (!output_buffer) {
		rist_log_priv2(get_cctx(b->peer)->logging_settings, RIST_LOG_ERROR, "Error (re)allocating rist_data_block.");
		return NULL;
	}
	if (!output_buffer->ref) {
		output_buffer->ref = rist_ref_create(output_buffer);
		if (!output_buffer->ref) {
			rist_log_priv2(get_cctx(b->peer)->logging_settings, RIST_LOG_ERROR, "Error allocating rist_ref.");
			free(output_buffer);
			return NULL;
		}
	}
	output_buffer->peer = b->peer;
	output_buffer->flow_id = flow_id;
	output_buffer->payload = payload;
	output_buffer->payload_len = b->size;
	output_buffer->virt_src_port = b->src_port;
	output_buffer->virt_dst_port = b->dst_port;
	output_buffer->ts_ntp = b->source_time;
	output_buffer->seq = b->seq;
	output_buffer->flags = flags;
	return output_buffer;
}

static void receiver_output(struct rist_receiver *ctx, struct rist_flow *f)
{

	uint64_t recovery_buffer_ticks = f->recovery_buffer_ticks;
	uint64_t now;
	if (RIST_LIKELY(!f->rtc_timing_mode))
		now = timestampNTP_u64();
	else
		now = timestampNTP_RTC_u64();
	size_t output_idx = atomic_load_explicit(&f->receiver_queue_output_idx, memory_order_acquire);
	while (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) > 0) {
		// Find the first non-null packet in the queuecounter loop
		struct rist_buffer *b = f->receiver_queue[output_idx];
		size_t holes = 0;
		if (!b) {
			//rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\tLooking for first non-null packet (%zu)\n", f->receiver_queue_size);
			size_t counter = 0;
			counter = output_idx;
			while (!b) {
				counter = (counter + 1)& (f->receiver_queue_max -1);
				holes++;
				b = f->receiver_queue[counter];
				if (counter == output_idx) {
					// TODO: with the check below, this should never happen
					rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Did not find any data after a full counter loop (%zu)\n", atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
					// if the entire buffer is empty, something is very wrong, reset the queue ...
					f->receiver_queue_has_items = false;
					atomic_store_explicit(&f->receiver_queue_size, 0, memory_order_release);
					// exit the function and wait 5ms (max jitter time)
					return;
				}
				if (holes > f->missing_counter_max)
				{
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG, "Did not find any data after %zu holes (%zu bytes in queue)\n",
							holes, atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
					break;
				}
			}
			if (b) {
				uint64_t delay1 = (now - b->time);
				if (RIST_UNLIKELY(delay1 > (2LLU * recovery_buffer_ticks))) {
					// According to the real time clock, it is too late, continue.
				} else if (b->target_output_time > now) {
					// The block we found is not ready for output, so we wait.
					break;
				}
			}
			pthread_mutex_lock(&ctx->common.stats_lock);
			f->stats_instant.lost += holes;
			pthread_mutex_unlock(&ctx->common.stats_lock);
			output_idx = counter;
			rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Empty buffer element, flushing %"PRIu32" hole(s), now at index %zu, size is %zu\n",
					holes, counter, atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
		}
		if (b) {
			if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {

				now = timestampNTP_u64();
				uint64_t delay_rtc = (now - b->time);

				if (RIST_UNLIKELY(delay_rtc > (1.1 * recovery_buffer_ticks))) {
					// Double check the age of the packet within our receiver queue
					// Safety net for discontinuities in source timestamp, clock drift or improperly scaled timestamp
					uint64_t delay = now > b->packet_time ? (now - b->packet_time) : 0;
					bool drop = false;
					//This should be impossible as we should catch it with the normal case
					if (RIST_UNLIKELY(delay_rtc > (2ULL * recovery_buffer_ticks))) {
						f->too_late_ctr++;
						drop = true;
						goto next;
					}
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
							"Packet %"PRIu32" (%zu bytes) is too old %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", offset = %"PRId64" ms, %s data\n",
							b->seq, b->size,
							delay_rtc / RIST_CLOCK, delay / RIST_CLOCK,
							recovery_buffer_ticks / RIST_CLOCK, f->time_offset / RIST_CLOCK,
							drop? "dropping" : "releasing");
					if (f->too_late_ctr > 100) {
						rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Too many old packets, resetting buffer\n");
						f->receiver_queue_has_items = false;
						return;
					}
				}
				else if (b->target_output_time >= now) {
					// This is how we keep the buffer at the correct level
					//rist_log_priv(&ctx->common, RIST_LOG_WARN, "age is %"PRIu64"/%"PRIu64" < %"PRIu64", size %zu\n",
					//	delay_rtc / RIST_CLOCK , delay / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK, f->receiver_queue_size);
					break;
				}
				//Reset the counter if our delay is correct
				if (RIST_LIKELY(delay_rtc < recovery_buffer_ticks))
					f->too_late_ctr = 0;
				// Check sequence number and report lost packet
				uint32_t next_seq = f->last_seq_output + 1;
				if (f->short_seq)
					next_seq = (uint16_t)next_seq;
				if (b->seq != next_seq && !holes) {
					rist_log_priv(&ctx->common, RIST_LOG_ERROR,
							"Discontinuity, expected %" PRIu32 " got %" PRIu32 "\n",
							f->last_seq_output + 1, b->seq);
					pthread_mutex_lock(&ctx->common.stats_lock);
					f->stats_instant.lost++;
					pthread_mutex_unlock(&ctx->common.stats_lock);
					holes = 1;
				}
				if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {
					uint32_t flags = 0;
					if (holes)
						flags = RIST_DATA_FLAGS_DISCONTINUITY;
					if (f->flag_flow_buffer_start) {
						f->flag_flow_buffer_start = false;
						flags |= RIST_DATA_FLAGS_FLOW_BUFFER_START;
					}
					/* insert into fifo queue */
					uint8_t *payload = b->data;
					struct rist_data_block *block = new_data_block(
							NULL, b,
							&payload[RIST_MAX_PAYLOAD_OFFSET], f->flow_id, flags);
					b->data = NULL;
					if (ctx->receiver_data_callback && block) {
						rist_ref_inc(block->ref);
						// send to callback synchronously
						ctx->receiver_data_callback(ctx->receiver_data_callback_argument,
								block);
					}

					size_t dataout_fifo_write_index = atomic_load_explicit(&f->dataout_fifo_queue_write_index, memory_order_relaxed);
					size_t dataout_fifo_read_index = atomic_load_explicit(&f->dataout_fifo_queue_read_index, memory_order_acquire);
					uint32_t fifo_count = (dataout_fifo_write_index - dataout_fifo_read_index)&(ctx->fifo_queue_size -1);
					if (fifo_count +1 == ctx->fifo_queue_size || !ctx->fifo_queue_size) {
						if (!ctx->receiver_data_callback)
							rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Rist data out fifo queue overflow\n");
						rist_receiver_data_block_free2(&block);
					} else
					{
						f->dataout_fifo_queue[dataout_fifo_write_index] = block;
						atomic_store_explicit(&f->dataout_fifo_queue_write_index, (dataout_fifo_write_index + 1)& (ctx->fifo_queue_size-1), memory_order_relaxed);
						// Wake up the fifo read thread (poll)
						if (ctx->receiver_data_ready_notify_fd) {
							// send a data ready signal by writing a single byte of value 0
							char empty = '\0';
							if(write(ctx->receiver_data_ready_notify_fd, &empty, 1) == -1)
							{
								// We ignore the error condition as missing data is not harmful here
								// It is only a signaling mechanism
							}
						}
					}
					pthread_mutex_lock(&ctx->common.stats_lock);
					if (f->stats_instant.buffer_duration_count < 2048)
					{
						f->stats_instant.buffer_duration[f->stats_instant.buffer_duration_count] = (uint32_t)(delay_rtc / RIST_CLOCK);
						f->stats_instant.buffer_duration_count++;
					}
					pthread_mutex_unlock(&ctx->common.stats_lock);
					if (pthread_cond_signal(&(ctx->condition)))
						rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");
				}
				// Track this one only for data
				f->last_seq_output_source_time = b->source_time;
			}
			//else
			//	fprintf(stderr, "rtcp skip at %"PRIu32", just removing it from queue\n", b->seq);

			f->last_seq_output = b->seq;
next:
			atomic_fetch_sub_explicit(&f->receiver_queue_size, b->size, memory_order_relaxed);
			f->receiver_queue[output_idx] = NULL;
			free_rist_buffer(&ctx->common, b);
			output_idx = (output_idx + 1)& (f->receiver_queue_max -1);
			atomic_store_explicit(&f->receiver_queue_output_idx, output_idx, memory_order_release);
			if (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) == 0) {
				if (f->last_output_time == 0)
					f->last_output_time = now;
				uint64_t delta = now - f->last_output_time;
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG, "Buffer is empty, it has been for %"PRIu64" < %"PRIu64" (ms)!\n",
						delta / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK);
				// if the entire buffer is empty, something is very wrong, reset the queue ...
				if (delta > recovery_buffer_ticks)
				{
					rist_log_priv(&ctx->common, RIST_LOG_ERROR, "stream is dead (%"PRIu64" ms), re-initializing flow\n",
						delta/ RIST_CLOCK);
					f->receiver_queue_has_items = false;
				}
				// exit the function and wait 5ms (max jitter time)
				return;
			}
			f->last_output_time = now;
		}
	}

}

static void send_nack_group(struct rist_receiver *ctx, struct rist_flow *f)
{
	// Now actually send all the nack IP packets for this flow (the above routing will process/group them)
	if (f->nacks.counter == 0)
		return;
	pthread_mutex_lock(&ctx->common.peerlist_lock);
	struct rist_peer *peer = NULL;
	uint64_t last_rtt = UINT64_MAX;
	if (f->peer_lst_len == 0 || f->peer_lst == NULL)
		goto out;
	for (size_t i = 0; i < f->peer_lst_len; i++)
	{
		struct rist_peer *check = f->peer_lst[i];
		if (check->is_rtcp && !check->dead && check->last_mrtt < last_rtt)
		{
			peer = check;
			last_rtt = peer->last_mrtt;
		}
	}
	if (peer != NULL)
		rist_receiver_send_nacks(peer,f->nacks.array, f->nacks.counter);
	else
	{
		for (size_t i = 0; i < f->peer_lst_len; i++)
		{
			struct rist_peer *check = f->peer_lst[i];
			uint64_t dead_since = 0;
			if (check->is_rtcp && check->dead_since > dead_since)
			{
				peer = check;
			}
			if (peer != NULL)
				rist_receiver_send_nacks(peer,f->nacks.array, f->nacks.counter);
		}
	}
	f->nacks.counter = 0;
out:
	pthread_mutex_unlock(&ctx->common.peerlist_lock);
}

void receiver_nack_output(struct rist_receiver *ctx, struct rist_flow *f)
{

	if (!f->authenticated) {
		return;
	}

	const size_t maxcounter = RIST_MAX_NACKS;

	/* Now loop through missing queue and process items */
	struct rist_missing_buffer *mb = f->missing;
	struct rist_missing_buffer **prev = &f->missing;
	struct rist_missing_buffer *previous = NULL;
	int empty = 0;
	uint32_t seq_msb = 0;
	if (mb)
		seq_msb = mb->seq >> 16;

	while (mb) {
		int remove_from_queue_reason = 0;
		struct rist_peer *peer = mb->peer;
		ssize_t idx = mb->seq& (f->receiver_queue_max -1);
		if (peer->config.recovery_mode == RIST_RECOVERY_MODE_DISABLED) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
					"Nack processing is disabled for this peer, removing seq %"PRIu32" from queue ...\n",
					mb->seq);
			remove_from_queue_reason = 10;
			f->stats_instant.missing--;
			goto nack_loop_continue;
		} else if (f->receiver_queue[idx]) {
			if (f->receiver_queue[idx]->seq == mb->seq) {
				pthread_mutex_lock(&ctx->common.stats_lock);
				// We filled in the hole already ... packet has been recovered
				remove_from_queue_reason = 3;
				if (mb->nack_count > 0)
					f->stats_instant.recovered++;
				switch(mb->nack_count) {
					case 0:
						break;
					case 1:
						f->stats_instant.recovered_0nack++;
						break;
					case 2:
						f->stats_instant.recovered_1nack++;
						break;
					case 3:
						f->stats_instant.recovered_2nack++;
						break;
					case 4:
						f->stats_instant.recovered_3nack++;
						break;
					default:
						f->stats_instant.recovered_morenack++;
						break;
				}
				f->stats_instant.recovered_sum += mb->nack_count;
				pthread_mutex_unlock(&ctx->common.stats_lock);
			}
			else {
				// Message with wrong seq!!!
				rist_log_priv(&ctx->common, RIST_LOG_ERROR,
						"Retry queue has the wrong seq %"PRIu32" != %"PRIu32", removing ...\n",
						f->receiver_queue[idx]->seq, mb->seq);
				remove_from_queue_reason = 4;
				pthread_mutex_lock(&ctx->common.stats_lock);
				f->stats_instant.missing--;
				pthread_mutex_unlock(&ctx->common.stats_lock);
				goto nack_loop_continue;
			}
		} else if (peer->buffer_bloat_active) {
			if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
				if (empty == 0) {
					rist_log_priv(&ctx->common, RIST_LOG_ERROR,
							"Retry queue is too large, %d, collapsed link (%u), flushing all nacks ...\n", f->missing_counter,
							f->stats_total.recovered_average/8);
				}
				remove_from_queue_reason = 5;
				empty = 1;
			} else if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_NORMAL) {
				if (mb->nack_count > 4) {
					if (empty == 0) {
						rist_log_priv(&ctx->common, RIST_LOG_ERROR,
								"Retry queue is too large, %d, collapsed link (%u), flushing old nacks (%u > %u) ...\n",
								f->missing_counter, f->stats_total.recovered_average/8, mb->nack_count, 4);
					}
					remove_from_queue_reason = 6;
					empty = 1;
				}
			}
		} else {
			// Packet is still missing, re-stamp the expiration time so we can re-add to queue
			// We reject the next retry for a number of reasons checked inside the function,
			// in which case the nack will never be resent and we signal a queue removal
			if (seq_msb != (mb->seq >> 16))
			{
				// We do not mix/group missing sequence numbers with different upper 2 bytes
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
							"seq-msb changed from %"PRIu32" to %"PRIu32" (%"PRIu32", %zu, %"PRIu32")\n",
							seq_msb, mb->seq >> 16, mb->seq, f->nacks.counter,
							f->missing_counter);
				send_nack_group(ctx, f);
			}
			else if (f->nacks.counter == (maxcounter - 1)) {
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"nack max counter per packet (%d) exceeded. Skipping the rest\n",
						maxcounter);
				send_nack_group(ctx, f);
			}
			else if (f->nacks.counter >= maxcounter) {
				rist_log_priv(&ctx->common, RIST_LOG_ERROR,
						"nack max counter per packet (%zu) exceeded. Something is very wrong and"
						" there is a strong chance memory is corrupt because we wrote past the end"
						"of the nacks.array max size!!!\n", f->nacks.counter );
				f->nacks.counter = 0;
				//TODO: maybe assert is more appropriate here?
			}
			remove_from_queue_reason = rist_process_nack(f, mb);
		}
nack_loop_continue:
		if (remove_from_queue_reason != 0) {
			if (ctx->common.debug)
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Removing seq %" PRIu32 " from missing, queue size is %d, retry #%u, age %"PRIu64"ms, reason %d\n",
						mb->seq, f->missing_counter, mb->nack_count, (timestampNTP_u64() - mb->insertion_time) / RIST_CLOCK, remove_from_queue_reason);
			struct rist_missing_buffer *next = mb->next;
			if (!next)
				f->missing_tail = previous;
			*prev = next;
			if (mb->nack_count != 0)
				f->missing_counter--;
			free(mb);
			mb = next;
		} else {
			/* Move it to the end of the queue */
			// TODO: I think this is wrong and we loose nacks when we get here
			previous = mb;
			prev = &mb->next;
			mb = mb->next;
		}
	}

	// Empty all peer nack queues, i.e. send them
	send_nack_group(ctx, f);

}

static int rist_set_manual_sockdata(struct rist_peer *peer, const struct rist_peer_config *config)
{
	peer->address_family = (uint16_t)config->address_family;//TODO: should it not just be a uint16_t then?
	peer->listening = !config->initiate_conn;
	const char *hostname = config->address;
	int ret;
	if ((!hostname || !*hostname) && peer->listening) {
		if (peer->address_family == AF_INET) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "No hostname specified: listening to 0.0.0.0\n");
			peer->address_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)&peer->u.address)->sin_family = AF_INET;
			((struct sockaddr_in *)&peer->u.address)->sin_addr.s_addr = INADDR_ANY;
		} else {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "No hostname specified: listening to [::0]\n");
			peer->address_len = sizeof(struct sockaddr_in6);
			((struct sockaddr_in6 *)&peer->u.address)->sin6_family = AF_INET6;
			((struct sockaddr_in6 *)&peer->u.address)->sin6_addr = in6addr_any;
		}
	} else {
		ret = udpsocket_resolve_host(hostname, config->physical_port, &peer->u.address);
		if (ret != 0) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Error trying to resolve hostname %s\n", hostname);
			goto err;
		}
		peer->address_family = ((struct sockaddr_in *)&peer->u.address)->sin_family;
		if (peer->address_family == AF_INET)
			peer->address_len = sizeof(struct sockaddr_in);
		else
			peer->address_len = sizeof(struct sockaddr_in6);
	}
	if (peer->listening)
		peer->local_port = config->physical_port;
	else
		peer->remote_port = config->physical_port;

	return 0;

err:
	peer->address_family = AF_LOCAL;
	peer->address_len = 0;
	return -1;
}

struct rist_peer *rist_receiver_peer_insert_local(struct rist_receiver *ctx,
		const struct rist_peer_config *config)
{
	if (config->key_size) {
		if (config->key_size != 128 && config->key_size != 192 && config->key_size != 256) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Invalid encryption key length: %d\n", config->key_size);
			return NULL;
		}
		if (!strlen(config->secret)) {

			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Invalid secret passphrase\n");
			return NULL;
		}
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Using %d bits secret key\n", config->key_size);
	}
	else {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Encryption is disabled for this peer\n");
	}

	/* Initialize peer */
	struct rist_peer *p = peer_initialize(config->address, NULL, ctx);
	if (!p) {
		return NULL;
	}

	strncpy(&p->miface[0], config->miface, RIST_MAX_STRING_SHORT);
	strncpy(&p->cname[0], config->cname, RIST_MAX_STRING_SHORT);
	if (config->address_family && rist_set_manual_sockdata(p, config)) {
		free(p);
		return NULL;
	}

	if (config->key_size) {
		_librist_crypto_psk_rist_key_init(&p->key_tx, config->key_size, config->key_rotation, config->secret);
		_librist_crypto_psk_rist_key_clone(&p->key_tx, &p->key_rx);
	}

	if (config->keepalive_interval > 0) {
		p->rtcp_keepalive_interval = config->keepalive_interval * RIST_CLOCK;
	}

	if (config->session_timeout > 0) {
		if (config->session_timeout < 250) {
			rist_log_priv(&ctx->common, RIST_LOG_WARN, "The configured (%d ms) peer session timeout is too small, using %d ms instead\n",
				config->session_timeout, 250);
			p->session_timeout = 250 * RIST_CLOCK;
		}
		else
			p->session_timeout = config->session_timeout * RIST_CLOCK;
	}
	else {
		p->session_timeout = 250 * RIST_CLOCK;
	}

	/* Initialize socket */
	rist_create_socket(p);
	if (p->sd < 0) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create socket\n");
		free(p);
		return NULL;
	}

	if (config->virt_dst_port != 0) {
		p->remote_port = config->virt_dst_port + 1;
	}

	p->adv_peer_id = ++ctx->common.peer_counter;
	store_peer_settings(config, p);

	return p;
}

/* PEERS are created at startup. The default state is RIST_PEER_STATE_IDLE
 * This function will initiate the connection to the peer if a peer address is available.
 * If no address is configured for the endpoint, the peer is put in wait mode.
 */
void rist_fsm_init_comm(struct rist_peer *peer)
{

	peer->authenticated = false;

	if (!peer->receiver_mode) {
		if (peer->listening) {
			/* sender mode listening/waiting for receiver */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Sender Peer, listening mode ...\n");
		} else {
			/* sender mode connecting to receiver */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Sender Peer, connecting to receiver ...\n");
		}
	} else {
		if (peer->listening) {
			/* receiver mode listening/waiting for sender */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Receiver Peer, listening mode ...\n");
		} else {
			/* receiver mode connecting to sender */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Receiver Peer, connecting to sender ...\n");
		}
	}
	peer->authenticated = false;
	rist_print_inet_info("Active ", peer);

	/* Start the timer that reads data from this peer */
	if (!peer->event_recv) {
		struct evsocket_ctx *evctx = get_cctx(peer)->evctx;
		peer->event_recv = evsocket_addevent(evctx, peer->sd, EVSOCKET_EV_READ,
				rist_peer_recv, rist_peer_sockerr, peer);
	}

	/* Enable RTCP timer and jump start it */
	if (!peer->listening && peer->is_rtcp) {
		if (!peer->send_keepalive) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling keepalive for peer %"PRIu32"\n", peer->adv_peer_id);
			peer->send_keepalive = true;
		}

		/* call it the first time manually to speed up the handshake */
		rist_peer_rtcp(NULL, peer);
		/* send 3 echo requests to jumpstart accurate RTT calculation */
		rist_request_echo(peer);
		rist_request_echo(peer);
		rist_request_echo(peer);
	}
}

void rist_peer_authenticate(struct rist_peer *peer)
{
	peer->authenticated = true;

	rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			"Successfully Authenticated peer %"PRIu32"\n", peer->adv_peer_id);
}

void rist_calculate_bitrate(size_t len, struct rist_bandwidth_estimation *bw)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = tv.tv_sec * 1000000;
	now += tv.tv_usec;
	uint64_t time = now - bw->last_bitrate_calctime;
	uint64_t time_fast = now - bw->last_bitrate_calctime_fast;

	if (!bw->last_bitrate_calctime) {
		bw->last_bitrate_calctime = now;
		bw->last_bitrate_calctime_fast = now;
		bw->eight_times_bitrate = 0;
		bw->eight_times_bitrate_fast = 0;
		bw->bytes = 0;
		bw->bytes_fast = 0;
		bw->bitrate = 0;
		bw->bitrate_fast = 0;
		return;
	}

	if (time_fast < 100000 /* 100 ms */) {
		bw->bytes_fast += len;
	}
	else {
		bw->bytes_fast += len;
		bw->bitrate_fast = (size_t)((8 * bw->bytes_fast * 1000000) / time_fast);
		bw->eight_times_bitrate_fast += bw->bitrate_fast - bw->eight_times_bitrate_fast / 8;
		bw->last_bitrate_calctime_fast = now;
		bw->bytes_fast = 0;
	}

	if (time < 1000000 /* 1 second */) {
		bw->bytes += len;
		return;
	}
	else {
		bw->bytes += len;
		bw->bitrate = (size_t)((8 * bw->bytes * 1000000) / time);
		bw->eight_times_bitrate += bw->bitrate - bw->eight_times_bitrate / 8;
		bw->last_bitrate_calctime = now;
		bw->bytes = 0;
	}
}

static void rist_calculate_flow_bitrate(struct rist_flow *flow, size_t len, struct rist_bandwidth_estimation *bw)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = tv.tv_sec * 1000000;
	now += tv.tv_usec;
	uint64_t time = now - bw->last_bitrate_calctime;
	uint64_t time_fast = now - bw->last_bitrate_calctime_fast;

	if (!bw->last_bitrate_calctime) {
		bw->last_bitrate_calctime = now;
		bw->eight_times_bitrate = 0;
		bw->bitrate = 0;
		bw->bytes = 0;
		bw->eight_times_bitrate_fast = 0;
		bw->bitrate_fast = 0;
		bw->bytes_fast = 0;
		return;
	}

	if (flow->last_ipstats_time == 0ULL) {
		// Initial values
		flow->stats_instant.cur_ips = 0ULL;
		flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;
		flow->stats_instant.max_ips = 0ULL;
		flow->stats_instant.avg_count = 0UL;
	} else {
		flow->stats_instant.cur_ips = now - flow->last_ipstats_time;
		/* Set new min */
		if (flow->stats_instant.cur_ips < flow->stats_instant.min_ips)
			flow->stats_instant.min_ips = flow->stats_instant.cur_ips;
		/* Set new max */
		if (flow->stats_instant.cur_ips > flow->stats_instant.max_ips)
			flow->stats_instant.max_ips = flow->stats_instant.cur_ips;

		/* Avg calculation */
		flow->stats_instant.total_ips += flow->stats_instant.cur_ips;
		flow->stats_instant.avg_count++;
	}
	flow->last_ipstats_time = now;


	if (time_fast < 100000 /* 100 ms */) {
		bw->bytes_fast += len;
	}
	else {
		bw->bitrate_fast = (size_t)((8 * bw->bytes_fast * 1000000) / time_fast);
		bw->eight_times_bitrate_fast += bw->bitrate_fast - bw->eight_times_bitrate_fast / 8;
		bw->last_bitrate_calctime_fast = now;
		bw->bytes_fast = 0;
	}

	if (time < 1000000 /* 1 second */) {
		bw->bytes += len;
		return;
	}
	else {
		bw->bitrate = (size_t)((8 * bw->bytes * 1000000) / time);
		bw->eight_times_bitrate += bw->bitrate - bw->eight_times_bitrate / 8;
		bw->last_bitrate_calctime = now;
		bw->bytes = 0;
	}
}

static void rist_sender_recv_nack(struct rist_peer *peer,
		uint32_t flow_id, uint16_t src_port, uint16_t dst_port, const uint8_t *payload,
		size_t payload_len, uint32_t nack_seq_msb)
{
	RIST_MARK_UNUSED(flow_id);
	RIST_MARK_UNUSED(src_port);
	RIST_MARK_UNUSED(dst_port);

	assert(payload_len >= sizeof(struct rist_rtcp_hdr));

	if (peer->receiver_mode) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
				"Received nack packet on receiver, ignoring ...\n");
		return;
	} else if (!peer->authenticated) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
				"Received nack packet but handshake is still pending, ignoring ...\n");
		return;
	}
	assert(peer->sender_ctx != NULL);

	struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *) payload;
	uint32_t i,j;

	if ((rtcp->flags & 0xc0) != 0x80) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Malformed nack packet flags=%d.\n", rtcp->flags);
		return;
	}

	if (rtcp->ptype == PTYPE_NACK_CUSTOM) {
		struct rist_rtcp_nack_range *rtcp_nack = (struct rist_rtcp_nack_range *) payload;
		if (memcmp(rtcp_nack->name, "RIST", 4) != 0) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Non-Rist nack packet (%s).\n", rtcp_nack->name);
			return; /* Ignore app-type not RIST */
		}
		uint16_t nrecords =	ntohs(rtcp->len) - 2;
		//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Nack (RbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t additional;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_range) + i * sizeof(struct rist_rtp_nack_record));
			missing =  ntohs(nr->start);
			additional = ntohs(nr->extra);
			rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Record %"PRIu32": base packet: %"PRIu32" range len: %d\n", i, nack_seq_msb + missing, additional);
			for (j = 0; j < additional; j++) {
				rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing + j + 1, peer);
			}
		}
	} else if (rtcp->ptype == PTYPE_NACK_BITMASK) {
		struct rist_rtcp_nack_bitmask *rtcp_nack = (struct rist_rtcp_nack_bitmask *) payload;
		(void)rtcp_nack;
		uint16_t nrecords =	ntohs(rtcp->len) - 2;
		//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Nack (BbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t bitmask;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_bitmask) + i * sizeof(struct rist_rtp_nack_record));
			missing = ntohs(nr->start);
			bitmask = ntohs(nr->extra);
			rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Record %"PRIu32": base packet: %"PRIu32" bitmask: %04x\n", i, nack_seq_msb + missing, bitmask);
			for (j = 0; j < 16; j++) {
				if ((bitmask & (1 << j)) == (1 << j))
					rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + missing + j + 1, peer);
			}
		}
	} else {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Unsupported Type %d\n", rtcp->ptype);
	}

}

static bool address_compare(struct sockaddr* addr1, struct sockaddr* addr2) {
	if (addr1->sa_family != addr2->sa_family)
		return false;
	if (addr1->sa_family == AF_INET) {
		struct sockaddr_in *sa, *sb;
		sa = (struct sockaddr_in *)addr1;
		sb = (struct sockaddr_in *)addr2;
		return !(sa->sin_addr.s_addr - sb->sin_addr.s_addr);
	} else if (addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *sa, *sb;
		sa = (struct sockaddr_in6 *)addr1;
		sb = (struct sockaddr_in6 *)addr2;
		return !(memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(sa->sin6_addr)));
	}
	return false;
}

static bool rist_receiver_data_authenticate(struct rist_peer *peer,uint64_t packet_recv_time, uint32_t flow_id)
{
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (ctx->common.profile == RIST_PROFILE_SIMPLE && !peer->authenticated)
	{
		//assert(0);
		if (peer->parent->peer_rtcp->authenticated) {
			peer->flow = peer->parent->peer_rtcp->flow;
			/* find correct rtcp */
			peer->peer_rtcp = NULL;
			struct rist_peer *tmp = peer->parent->peer_rtcp->child;
			uint16_t rtcp_port = peer->local_port+1;
			while (tmp) {
				if (tmp->is_rtcp) {
					if (tmp->local_port == rtcp_port && peer->adv_flow_id == tmp->adv_flow_id && address_compare(&peer->u.address, &tmp->u.address)) {
						if (tmp->dead)
						{
							tmp = tmp->sibling_next;
							continue;
						}
						peer->peer_rtcp = tmp;
						tmp->peer_data = peer;
						break;
					}
				}
				tmp = tmp->sibling_next;
			}
			if (!peer->peer_rtcp) {
				tmp = peer->parent->peer_rtcp->child;
				while (tmp) {
					if (tmp->is_rtcp) {
						if (tmp->local_port == rtcp_port && address_compare(&peer->u.address, &tmp->u.address)) {
							if (tmp->dead)
							{
								tmp = tmp->sibling_next;
								continue;
							}
							peer->peer_rtcp = tmp;
							tmp->peer_data = peer;
							break;
						}
					}
					tmp = tmp->sibling_next;
				}
			}
			peer->adv_flow_id = flow_id; // store the original ssrc here
			rist_peer_authenticate(peer);
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
				"Authenticated RTP peer %d and ssrc %"PRIu32" for connection with flowid %"PRIu32"\n",
					peer->adv_peer_id, peer->adv_flow_id, peer->flow->flow_id);
		} else {
			if (packet_recv_time > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
				rist_log_priv(&ctx->common, RIST_LOG_WARN,
					"Received data packet (%"PRIu32") but handshake is still pending (waiting for an RTCP packet with SDES on it), ignoring ...\n",
						flow_id);
					peer->log_repeat_timer = packet_recv_time;
			}
			return false;
		}
	}
	else if (ctx->common.profile > RIST_PROFILE_SIMPLE) {
		if (!peer->authenticated) {
			// rist_peer_authenticate is done during rtcp authentication (same peer)
			rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"Received data packet (%"PRIu32") but handshake is still pending (waiting for an RTCP packet with SDES on it), ignoring ...\n",
					flow_id);
			return false;
		} else if (!peer->peer_rtcp) {
			peer->peer_rtcp = peer;
			peer->adv_flow_id = flow_id; // store the original ssrc here
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
				"Authenticated RTP peer %d and ssrc %"PRIu32" for connection with flowid %"PRIu32"\n",
					peer->adv_peer_id, peer->adv_flow_id, peer->peer_rtcp->adv_flow_id);
		}
	}

	if (!peer->flow) {
		rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"Received data packet but this peer (%d) is not associated with a flow, ignoring ...\n",
				peer->adv_peer_id);
		return false;
	} else if (!peer->flow->authenticated) {
		rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"Flow %"PRIu32" has not yet been authenticated by an RTCP peer, %"PRIu32"!\n", flow_id);
		return false;
	}
	if (peer->parent && ctx->common.profile == RIST_PROFILE_SIMPLE)
		peer->parent->authenticated = true;
	return true;
}

static bool rist_receiver_rtcp_authenticate(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id)
{
	RIST_MARK_UNUSED(seq);
	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (!strlen(peer->receiver_name)) {
		snprintf(peer->receiver_name, 128, "empty-sdes-name peer id#%i", peer->adv_peer_id);
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peer has empty cname in SDES packet, generating default name");
	}

	// Check to see if this peer's flowid changed
	// (sender was restarted and we are in callback mode or sender happened to reuse the same port)
	if (peer->flow && (flow_id != peer->flow->flow_id)) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Updating peer's flowid %"PRIu32"->%"PRIu32" (%zu)\n", peer->flow->flow_id, flow_id, peer->flow->peer_lst_len);
		if (peer->flow->peer_lst_len > 1) {
			remove_peer_from_flow(peer);
		}
		else {
			// Delete the flow and all of its resources
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Old flow (%"PRIu32") has no peers left, deleting ...\n", peer->flow->flow_id);
			rist_delete_flow(ctx, peer->flow);
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Old flow deletion complete\n");
		}
		// Reset the peer parameters
		peer->authenticated = false;
		peer->flow = NULL;
	}

	if (!peer->authenticated) {

		// the peer could already be part of a flow and it came back after timing out
		if (!peer->flow) {
			if (rist_receiver_associate_flow(peer, flow_id) != 1) {
				rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create/associate peer to flow.\n");
				return false;
			}
			if (ctx->common.profile == RIST_PROFILE_SIMPLE && peer->parent->peer_data->authenticated)
			{
				/* find correct data */
				struct rist_peer *tmp = peer->parent->peer_data->child;
				peer->is_data = false;
				peer->peer_data = NULL;
				peer->is_rtcp = true;
				uint16_t data_port = peer->local_port -1;
				while (tmp) {
					if (tmp->is_data) {
						if (tmp->local_port == data_port && peer->adv_flow_id == tmp->adv_flow_id && address_compare(&peer->u.address, &tmp->u.address)) {
							if (tmp->dead)
							{
								tmp = tmp->sibling_next;
								continue;
							}
							peer->peer_data = tmp;
							tmp->peer_rtcp = peer;
							break;
						}
					}
					tmp = tmp->sibling_next;
				}
				if (!peer->peer_data) {
					tmp = peer->parent->peer_data->child;
					while (tmp) {
						if (tmp->is_data) {
							if (tmp->local_port == data_port && address_compare(&peer->u.address, &tmp->u.address)) {
								if (tmp->dead)
								{
									tmp = tmp->sibling_next;
									continue;
								}
								peer->peer_data = tmp;
								tmp->peer_rtcp = peer;
								break;
							}
						}
						tmp = tmp->sibling_next;
					}
				}
				//randomly associate with first data peer without rtcp peer (ignores IP matching requirement)
				if (!peer->peer_data) {
					tmp = peer->parent->peer_data->child;
					while (tmp) {
						if (tmp->is_data) {
							if (tmp->local_port == data_port && tmp->peer_rtcp == NULL) {
								peer->peer_data = tmp;
								tmp->peer_rtcp = peer;
								break;
							}
						}
						tmp = tmp->sibling_next;
					}
				}
				peer->authenticated = true;
				return true;
			}
		}

		if (peer->flow) {
			// We do multiple ifs to make these checks stateless
			pthread_mutex_lock(&peer->flow->mutex);
			if (!peer->flow->receiver_thread_running) {
				// Make sure this data out thread is created only once per flow
				if (pthread_create(&peer->flow->receiver_thread, NULL, receiver_pthread_dataout, (void *)peer->flow) != 0) {
					rist_log_priv(&ctx->common, RIST_LOG_ERROR,
							"Could not created receiver data output thread.\n");
					return false;
				}
				peer->flow->receiver_thread_running = true;
			}
			pthread_mutex_unlock(&peer->flow->mutex);
			rist_peer_authenticate(peer);
			peer->flow->authenticated = true;
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Authenticated RTCP peer %d and flow %"PRIu32" for connection with cname: %s\n",
					peer->adv_peer_id, peer->adv_flow_id, peer->receiver_name);
			if (ctx->common.profile == RIST_PROFILE_SIMPLE)
			{
				peer->parent->authenticated = true;
				if (peer->parent->flow == NULL) {
					peer->parent->flow = peer->flow;
					peer->parent->flow->authenticated = true;
				}
			}
		}
	}

	// The flow is added after we completed authentication
	if (peer->flow) {
		return true;
	} else {
		return false;
	}
}

static void rist_receiver_recv_data(struct rist_peer *peer, uint32_t seq, uint32_t flow_id,
		uint64_t source_time, uint64_t packet_recv_time, struct rist_buffer *payload, uint8_t retry, uint8_t payload_type)
{
	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (!rist_receiver_data_authenticate(peer, packet_recv_time, flow_id)) {
		// Error logging happens inside the function
		return;
	}

	//rist_log_priv(&ctx->common, RIST_LOG_ERROR,
	//	"rist_recv_data, seq %"PRIu32", retry=%d\n", seq, retry);

	//	Just some debug output
	//	if ((seq - peer->flow->last_seq_output) != 1)
	//		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Received seq %"PRIu32" and last %"PRIu32"\n\n\n", seq, peer->flow->last_seq_output);

	/**************** WIP *****************/
	/* * * * * * * * * * * * * * * * * * * */
	/** Heuristics for receiver  * * * * * */
	/* * * * * * * * * * * * * * * * * * * */
	/**************** WIP *****************/
	peer->stats_receiver_instant.received++;

	uint32_t rtt;
	rtt = peer->eight_times_rtt / 8;
	if (rtt < peer->config.recovery_rtt_min) {
		rtt = peer->config.recovery_rtt_min;
	}
	else if (rtt > peer->config.recovery_rtt_max) {
		rtt = peer->config.recovery_rtt_max;
	}
	// Optimal dynamic time for first retry (reorder bufer) is rtt/2
	rtt = rtt / 2;
	if (rtt < peer->config.recovery_reorder_buffer)
	{
		rtt = peer->config.recovery_reorder_buffer;
	}

	if (peer->peer_rtcp != NULL &&
		peer->peer_ssrc != peer->peer_rtcp->peer_ssrc &&
		peer->flow->flow_id_actual != flow_id)
	{
          rist_log_priv(&ctx->common, RIST_LOG_NOTICE,
                        "Detected flow id change, old flow id: %u new id: %u, "
                        "resetting state\n",
                        peer->flow->flow_id_actual, flow_id);
        peer->flow->receiver_queue_has_items = false;
        peer->flow->flow_id_actual = flow_id;
	}

	// Wake up output thread when data comes in
	if (pthread_cond_signal(&(peer->flow->condition)))
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");
	if (!receiver_enqueue(peer, source_time, packet_recv_time, payload->data, payload->size, seq, rtt, retry, payload->src_port, payload->dst_port, payload_type)) {
		pthread_mutex_lock(&ctx->common.stats_lock);
		rist_calculate_flow_bitrate(peer->flow, payload->size, &peer->flow->bw); // update bitrate only if not a dupe
		pthread_mutex_unlock(&ctx->common.stats_lock);

	}
}

static void rist_recv_oob_data(struct rist_peer *peer, struct rist_buffer *payload)
{
	// TODO: if the calling app locks the thread for long, the protocol management thread will suffer
	// either use a new thread with a fifo or write warning on documentation
	struct rist_common_ctx *ctx = get_cctx(peer);
	if (ctx->oob_data_enabled && ctx->oob_data_callback)
	{
		struct rist_oob_block oob_block;
		oob_block.peer = peer;
		oob_block.payload = payload->data;
		oob_block.payload_len = payload->size;
		ctx->oob_data_callback(ctx->oob_data_callback_argument, &oob_block);
	}
}

static void rist_rtcp_handle_echo_request(struct rist_peer *peer, struct rist_rtcp_echoext *echoreq) {
	if (RIST_UNLIKELY(!peer->echo_enabled))
		peer->echo_enabled = true;
	uint64_t echo_request_time = ((uint64_t)be32toh(echoreq->ntp_msw) << 32) | be32toh(echoreq->ntp_lsw);
	uint32_t ssrc = be32toh(echoreq->ssrc);
	rist_respond_echoreq(peer, echo_request_time, ssrc);
}

static void rist_rtcp_handle_echo_response(struct rist_peer *peer, struct rist_rtcp_echoext *echoreq) {
	peer->echo_enabled = true;
	if (be32toh(echoreq->ssrc) != peer->peer_ssrc)
		return;
	uint64_t request_time = ((uint64_t)be32toh(echoreq->ntp_msw) << 32) | be32toh(echoreq->ntp_lsw);
	uint64_t rtt = calculate_rtt_delay(request_time, timestampNTP_u64(), be32toh(echoreq->delay));
	peer->last_mrtt = (uint32_t)rtt / RIST_CLOCK;
	peer->eight_times_rtt -= peer->eight_times_rtt / 8;
	peer->eight_times_rtt += peer->last_mrtt;
	if (peer->peer_data && peer->peer_data != peer)
	{
		peer->peer_data->last_mrtt = peer->last_mrtt;
		peer->peer_data->eight_times_rtt = peer->eight_times_rtt;
	}
}

static void rist_handle_sr_pkt(struct rist_peer *peer, struct rist_rtcp_sr_pkt *sr) {
	uint64_t ntp_time = ((uint64_t)be32toh(sr->ntp_msw) << 32) | be32toh(sr->ntp_lsw);
	peer->last_sender_report_time = ntp_time;
	peer->last_sender_report_ts = timestampNTP_u64();
	if (peer->config.timing_mode == RIST_TIMING_MODE_RTC)
	{
		if (peer->flow && peer->flow->time_offset == 0)
		{
			uint64_t packet_timestamp = convertRTPtoNTP(RTP_PTYPE_MPEGTS, 0, be32toh(sr->rtp_ts));
			peer->flow->time_offset = ntp_time - packet_timestamp;
		}
	}
}

static void rist_handle_rr_pkt(struct rist_peer *peer, struct rist_rtcp_rr_pkt *rr) {
	if (peer->echo_enabled)
		return;
	uint64_t lsr_tmp = (peer->last_sender_report_time >> 16) & 0xFFFFFFFF;
	uint64_t lsr_ntp = be32toh(rr->lsr);
	uint64_t rtt;
	if (lsr_ntp == lsr_tmp) {
		uint64_t now = timestampNTP_u64();
		rtt = now - peer->last_sender_report_ts - ((uint64_t)be32toh(rr->dlsr) << 16);

	} else {
		if (!lsr_ntp)//this can happen on the first time
			return;
		//Slightly less accurate, needed when RTT is bigger than our RTCP interval.
		uint64_t now = timestampNTP_u64();
		lsr_ntp = lsr_ntp << 16;
		lsr_ntp |= (now & 0xFFFF000000000000);
		if (lsr_ntp > now)
			return;
		rtt  = now - lsr_ntp  - ((uint64_t)be32toh(rr->dlsr) << 16);
	}
	peer->last_mrtt = (uint32_t)(rtt / RIST_CLOCK);
	peer->eight_times_rtt -= peer->eight_times_rtt / 8;
	peer->eight_times_rtt += peer->last_mrtt;
	if (peer->peer_data && peer->peer_data != peer)
	{
		peer->peer_data->last_mrtt = peer->last_mrtt;
		peer->peer_data->eight_times_rtt = peer->eight_times_rtt;
	}
}

static void rist_handle_xr_pkt(struct rist_peer *peer, uint8_t xr_pkt[])
{
	size_t offset = 0;
	struct rist_rtcp_hdr *hdr = (struct rist_rtcp_hdr *)&xr_pkt[offset];
	size_t payload_len = (be16toh(hdr->len) +1) * 4;
	ssize_t bytes_remaining = payload_len - sizeof(struct rist_rtcp_hdr);
	offset += sizeof(struct rist_rtcp_hdr);
	while (bytes_remaining > 0)
	{
		struct rist_rtcp_xr_block_hdr *block = (struct rist_rtcp_xr_block_hdr *)&xr_pkt[offset];
		uint8_t block_type = block->type;
		uint16_t block_length = (be16toh(block->length)+1) * 4;
		if (block_type == 5)
		{
			struct rist_rtcp_xr_dlrr *dlrr = (struct rist_rtcp_xr_dlrr *)&xr_pkt[offset];
			uint32_t ssrc  = be32toh(dlrr->ssrc);
			if (ssrc != peer->peer_ssrc)
				return;
			uint64_t lrr_tmp = (peer->last_sender_report_ts >> 16) & 0xFFFFFFFF;
			uint64_t lrr = be32toh(dlrr->lrr);
			uint64_t rtt;
			if (lrr == lrr_tmp)
			{
				rtt = timestampNTP_u64() - peer->last_sender_report_ts - ((uint64_t)be32toh(dlrr->delay) << 16);

			} else {
				//Slightly less accurate, needed when RTT is bigger than our RTCP interval.
				uint64_t now = timestampNTP_u64();
				lrr = (lrr << 16) & 0x0000FFFFFFFF0000;
				lrr |= (now & 0xFFFF000000000000);
				if (lrr > now)
					return;
				rtt  = now - lrr  - ((uint64_t)be32toh(dlrr->delay) << 16);
			}
			peer->last_mrtt = (uint32_t)(rtt / RIST_CLOCK);
			peer->eight_times_rtt -= peer->eight_times_rtt /8;
			peer->eight_times_rtt += peer->last_mrtt;
			if (peer->peer_data && peer->peer_data != peer)
			{
				peer->peer_data->last_mrtt = peer->last_mrtt;
				peer->peer_data->eight_times_rtt = peer->eight_times_rtt;
			}
		}
		offset += block_length;
		bytes_remaining -= block_length;
	}
}

static char *get_ip_str(struct sockaddr *sa, char *s, uint16_t *port, size_t maxlen)
{
	switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
					s, (socklen_t)maxlen);
			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
						s, (socklen_t)maxlen);
			break;

		default:
			strncpy(s, "Unknown AF", maxlen);
			return NULL;
	}

	struct sockaddr_in *sin = (struct sockaddr_in *)s;
	*port = htons (sin->sin_port);

	return s;
}

static void rist_recv_rtcp(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, struct rist_buffer *payload)
{
	uint8_t *pkt;
	uint8_t  ptype;
	uint16_t processed_bytes = 0;
	uint16_t records;
	uint8_t subtype;
	uint32_t nack_seq_msb = 0;
	peer->stats_receiver_instant.received_rtcp++;
	struct rist_common_ctx *ctx = get_cctx(peer);

	while (processed_bytes < payload->size) {
		pkt = (uint8_t*)payload->data + processed_bytes;
		struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)pkt;
		/* safety checks */
		size_t bytes_left = payload->size - processed_bytes + 1;

		if ( bytes_left < 4 )
		{
			/* we must have at least 4 bytes */
			rist_log_priv(ctx, RIST_LOG_ERROR, "Rist rtcp packet must have at least 4 bytes, we have %d\n",
					bytes_left);
			return;
		}

		ptype = rtcp->ptype;
		subtype = rtcp->flags & 0x1f;
		records = be16toh(rtcp->len);
		uint16_t bytes = (uint16_t)(4 * (1 + records));
		if (bytes > bytes_left)
		{
			/* check for a sane number of bytes */
			rist_log_priv(ctx, RIST_LOG_ERROR, "Malformed feedback packet, expecting %u bytes in the" \
					" packet, got a buffer of %u bytes. ptype = %d\n", bytes,
					bytes_left, ptype);
			return;
		}

		switch(ptype) {
			case PTYPE_NACK_CUSTOM:
				if (subtype == NACK_FMT_SEQEXT)
				{
					struct rist_rtcp_seqext *seq_ext = (struct rist_rtcp_seqext *) pkt;
					nack_seq_msb = ((uint32_t)be16toh(seq_ext->seq_msb)) << 16;
					break;
				}
				else if (subtype == ECHO_RESPONSE) {
					struct rist_rtcp_echoext *echoresponse = (struct rist_rtcp_echoext *) pkt;
					rist_rtcp_handle_echo_response(peer, echoresponse);
					break;
				}
				else if (subtype == ECHO_REQUEST) {
					struct rist_rtcp_echoext *echorequest = (struct rist_rtcp_echoext *)pkt;
					rist_rtcp_handle_echo_request(peer, echorequest);
					break;
				}
				else if (subtype == NACK_FMT_RANGE)	{
					//Fallthrough
					RIST_FALLTHROUGH;
				}
				else {
					rist_log_priv(ctx, RIST_LOG_DEBUG, "Unsupported rtcp custom subtype %d, ignoring ...\n", subtype);
					break;
				}
			case PTYPE_NACK_BITMASK:
				//Also FMT Range
				rist_sender_recv_nack(peer, flow_id, payload->src_port, payload->dst_port, pkt, bytes_left, nack_seq_msb);
				break;
			case PTYPE_RR:
				if (ntohs(rtcp->len) == 7) {
					struct rist_rtcp_rr_pkt *rr = (struct rist_rtcp_rr_pkt *)pkt;
					rist_handle_rr_pkt(peer, rr);
				}
				break;

			case PTYPE_SDES:
				{
					peer->stats_sender_instant.received++;
					uint8_t name_length = pkt[9];
					if (name_length > bytes_left)
					{
						/* check for a sane number of bytes */
						rist_log_priv(ctx, RIST_LOG_ERROR, "Malformed SDES packet, wrong cname len %u, got a " \
								"buffer of %u bytes.\n", name_length, bytes_left);
						return;
					}
					if (memcmp(pkt + RTCP_SDES_SIZE, peer->receiver_name, name_length) != 0)
					{
						memcpy(peer->receiver_name, pkt + RTCP_SDES_SIZE, name_length);
						rist_log_priv(ctx, RIST_LOG_INFO, "Peer %"PRIu32" receiver name is now: %s\n",
								peer->adv_peer_id, peer->receiver_name);
					}
					bool peer_authenticated = peer->authenticated;
					int connection_message = 0;
					if (peer->receiver_mode) {
						rist_receiver_rtcp_authenticate(peer, seq, flow_id);
						connection_message = RIST_CLIENT_CONNECTED;
					} else if (peer->sender_ctx && peer->listening) {
						// TODO: create rist_sender_recv_rtcp
						if (!peer->authenticated) {
							rist_peer_authenticate(peer);
						}
						connection_message = RIST_CLIENT_CONNECTED;
					}
					else {
						connection_message = RIST_CONNECTION_ESTABLISHED;
					}
					if (peer->timed_out || !peer->send_first_connection_event || (!peer_authenticated && peer->authenticated)) {
						if (!peer->send_first_connection_event)
							rist_log_priv(ctx, RIST_LOG_INFO, "Peer %"PRIu32" receiver with name %s reconnected\n",
								peer->adv_peer_id, peer->receiver_name);
						peer->timed_out = 0;
						peer->send_first_connection_event = true;
						if (ctx->connection_status_callback)
							ctx->connection_status_callback(ctx->connection_status_callback_argument, peer, connection_message);
					}
				break;
			}
			case PTYPE_SR:;
				struct rist_rtcp_sr_pkt *sr = (struct rist_rtcp_sr_pkt *)pkt;
				rist_handle_sr_pkt(peer, sr);
				break;
			case PTYPE_XR:
				rist_handle_xr_pkt(peer, pkt);
				break;
			default:
				rist_log_priv(ctx, RIST_LOG_DEBUG, "Unrecognized RTCP packet with PTYPE=%02x!!\n", ptype);
		}
		processed_bytes += bytes;
	}

}

void rist_peer_rtcp(struct evsocket_ctx *evctx, void *arg)
{
	RIST_MARK_UNUSED(evctx);
	struct rist_peer *peer = (struct rist_peer *)arg;
	//struct rist_common_ctx *ctx = get_cctx(peer);

	if (!peer || peer->shutdown || !peer->is_rtcp) {
		return;
	}

	if (peer->dead && peer->parent != NULL)
		return;//Don't send to peers that connect to us and have dropped silent

	else { //if (ctx->profile <= RIST_PROFILE_MAIN) {
		if (peer->receiver_mode) {
			rist_receiver_periodic_rtcp(peer);
		} else {
			rist_sender_periodic_rtcp(peer);
			//if (peer->echo_enabled)
			//	rist_request_echo(peer);
		}
	}
}

	static inline bool equal_address(uint16_t family, struct sockaddr *A_, struct rist_peer *p)
	{
		bool result = false;

		if (!p) {
			return result;
		}

		if (p->address_family != family) {
			return result;
		}

		struct sockaddr *B_ = &p->u.address;

		if (family == AF_INET) {
			struct sockaddr_in *a = (struct sockaddr_in *)A_;
			struct sockaddr_in *b = (struct sockaddr_in *)B_;
			result = (a->sin_port == b->sin_port) &&
				((!p->receiver_mode && p->listening) ||
				 (a->sin_addr.s_addr == b->sin_addr.s_addr));
			if (result && !p->remote_port)
				p->remote_port = a->sin_port;
		} else {
			/* ipv6 */
			struct sockaddr_in6 *a = (struct sockaddr_in6 *)A_;
			struct sockaddr_in6 *b = (struct sockaddr_in6 *)B_;
			result = a->sin6_port == b->sin6_port &&
				((!p->receiver_mode && p->listening) ||
				 !memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(struct in6_addr)));
			if (result && !p->remote_port)
				p->remote_port = a->sin6_port;
		}

		return result;
	}

	static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
	{
		RIST_MARK_UNUSED(evctx);
		RIST_MARK_UNUSED(fd);
		RIST_MARK_UNUSED(revents);
		struct rist_peer *peer = (struct rist_peer *) arg;

		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "\tSocket error!\n");

		//rist_peer_remove(get_cctx(peer), peer, NULL);
	}

	void sender_peer_append(struct rist_sender *ctx, struct rist_peer *peer)
	{
		/* Add a reference to ctx->peer_lst */
		ctx->peer_lst = realloc(ctx->peer_lst, (ctx->peer_lst_len + 1) * sizeof(*ctx->peer_lst));
		ctx->peer_lst[ctx->peer_lst_len] = peer;
		ctx->peer_lst_len++;
	}

	static void peer_copy_settings(struct rist_peer *peer_src, struct rist_peer *peer)
	{
		_librist_crypto_psk_rist_key_clone(&peer_src->key_rx, &peer->key_rx);
		_librist_crypto_psk_rist_key_clone(&peer_src->key_tx, &peer->key_tx);
		strncpy(&peer->cname[0], &peer_src->cname[0], RIST_MAX_STRING_SHORT);
		strncpy(&peer->miface[0], &peer_src->miface[0], RIST_MAX_STRING_SHORT);
		peer->config.weight = peer_src->config.weight;
		peer->config.virt_dst_port = peer_src->config.virt_dst_port;
		peer->config.recovery_mode = peer_src->config.recovery_mode;
		peer->config.recovery_maxbitrate = peer_src->config.recovery_maxbitrate;
		peer->config.recovery_maxbitrate_return = peer_src->config.recovery_maxbitrate_return;
		peer->config.recovery_length_min = peer_src->config.recovery_length_min;
		peer->config.recovery_length_max = peer_src->config.recovery_length_max;
		peer->config.recovery_reorder_buffer = peer_src->config.recovery_reorder_buffer;
		peer->config.recovery_rtt_min = peer_src->config.recovery_rtt_min;
		peer->config.recovery_rtt_max = peer_src->config.recovery_rtt_max;
		peer->config.congestion_control_mode = peer_src->config.congestion_control_mode;
		peer->config.min_retries = peer_src->config.min_retries;
		peer->config.max_retries = peer_src->config.max_retries;
		peer->config.timing_mode = peer_src->config.timing_mode;
		peer->rtcp_keepalive_interval = peer_src->rtcp_keepalive_interval;
		peer->peer_ssrc = peer_src->peer_ssrc;
		peer->session_timeout = peer_src->session_timeout;
		peer->rist_gre_version = 1;

		init_peer_settings(peer);
	}

	static void kill_peer(struct rist_peer *peer)
	{
		bool current_state = peer->dead;
		peer->dead = true;
		if (peer->peer_data && (current_state != peer->peer_data->dead && peer->peer_data->parent))
			--peer->peer_data->parent->child_alive_count;
		peer->dead_since = timestampNTP_u64();
	}

	static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
	{
		RIST_MARK_UNUSED(evctx);
		RIST_MARK_UNUSED(revents);
		RIST_MARK_UNUSED(fd);

		struct rist_peer *peer = (struct rist_peer *) arg;
		if (peer->shutdown) {
			return;
		}

		uint64_t now = timestampNTP_u64();
		struct rist_common_ctx *cctx = get_cctx(peer);

		socklen_t addrlen = peer->address_len;
		ssize_t recv_bufsize = -1;
		uint16_t family = AF_INET;
		struct sockaddr_in addr4 = {0};
		struct sockaddr_in6 addr6 = {0};
		struct sockaddr *addr;
		struct rist_peer *p = peer;
		uint8_t *recv_buf = cctx->buf.recv;
		size_t buffer_offset = 0;

		if (cctx->profile == RIST_PROFILE_SIMPLE)
			buffer_offset = RIST_GRE_PROTOCOL_REDUCED_SIZE;

		if (peer->address_family == AF_INET6) {
			recv_bufsize = recvfrom(peer->sd, (char*)recv_buf + buffer_offset, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *) &addr6, &addrlen);
			family = AF_INET6;
			addr = (struct sockaddr *) &addr6;
		} else {
			recv_bufsize = recvfrom(peer->sd, (char *)recv_buf + buffer_offset, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *)&addr4, &addrlen);
			addr = (struct sockaddr *) &addr4;
		}
#ifndef _WIN32
		if (recv_bufsize <= 0) {
			int errorcode = errno;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
					return;
#else
		if (recv_bufsize == SOCKET_ERROR) {
			int errorcode = WSAGetLastError();
			if (errorcode == WSAEWOULDBLOCK)
				return;
#endif
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Receive failed: errno=%d, ret=%d, socket=%d\n", errorcode, recv_bufsize, fd);
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "%s\n", strerror(errorcode));
			return;
		}

		struct rist_key *k = &peer->key_rx;
		struct rist_gre *gre = NULL;
		uint32_t seq = 0;
		uint32_t time_extension = 0;
		struct rist_protocol_hdr *proto_hdr = NULL;
		uint8_t retry = 0;
		struct rist_buffer payload = { .data = NULL, .size = 0, .type = 0 };
		size_t gre_size = 0;
		uint32_t flow_id = 0;

		if (cctx->profile > RIST_PROFILE_SIMPLE)
		{
			// Make sure we have enought bytes
			if (recv_bufsize < (int)sizeof(struct rist_gre)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
				return;
			}


			gre = (void *) recv_buf;
			if (gre->prot_type != htobe16(RIST_GRE_PROTOCOL_TYPE_REDUCED) && gre->prot_type != htobe16(RIST_GRE_PROTOCOL_TYPE_FULL) &&
				gre->prot_type != htobe16(RIST_GRE_PROTOCOL_TYPE_EAPOL)) {

				if (htobe16(gre->prot_type) == RIST_GRE_PROTOCOL_TYPE_KEEPALIVE)
				{
					struct rist_gre_keepalive *gre_keepalive = (void *) recv_buf;
					(void)gre_keepalive->capabilities1;
					payload.type = RIST_PAYLOAD_TYPE_UNKNOWN;
					// TODO: parse the capabilities and do something with it?
				}
				else
				{
					if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
						rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Protocol %d not supported (wrong profile?)\n", gre->prot_type);
						peer->log_repeat_timer = now;
					}
					return;
				}
				goto protocol_bypass;
			}

			uint8_t has_checksum = CHECK_BIT(gre->flags1, 7);
			uint8_t has_key = CHECK_BIT(gre->flags1, 5);
			uint8_t has_seq = CHECK_BIT(gre->flags1, 4);
			uint8_t rist_gre_version = (gre->flags2 >> 3) & 0x7;

			if (has_seq && has_key && be16toh(gre->prot_type) != RIST_GRE_PROTOCOL_TYPE_EAPOL) {
				// Key bit is set, that means the other side want to send
				// encrypted data.
				//
				// make sure we have a key before attempting to decrypt
				if (!k->key_size) {
					if (now > (p->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
						rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Receiving encrypted data, but configured without keysize!\n");
						p->log_repeat_timer = now;
					}
					return;
				}


				while (p) {
					if (equal_address(family, addr, p))
						break;
					p = p->next;
				}
				if (!p)
					p = peer;
#if ALLOW_INSECURE_IV_FALLBACK == 1
				if (rist_gre_version < 1)
					p->rist_gre_version = rist_gre_version;
#endif
				k = &p->key_rx;
				//Read H bit and set keysize accordingly
				if (p->rist_gre_version)
				{
					int bits = (CHECK_BIT(gre->flags2, 6))? 256 : 128;
					k->key_size = bits;
				}
				p = peer;

				// GRE
				uint32_t nonce = 0;
				struct rist_gre_key_seq *gre_key_seq = (void *) recv_buf;
				gre_size = sizeof(*gre_key_seq);
				if (has_checksum) {
					seq = be32toh(gre_key_seq->seq);
					nonce = gre_key_seq->nonce;
				} else {
					// shifted by 4 missing checksum bytes (non-librist senders)
					seq = be32toh(gre_key_seq->nonce);
					nonce = gre_key_seq->checksum_reserved1;
					gre_size -= 4;
				}
				_librist_crypto_psk_decrypt(k, nonce, htobe32(seq), rist_gre_version,(unsigned char *)(recv_buf + gre_size),  (unsigned char *)(recv_buf + gre_size), (recv_bufsize - gre_size));
				if (k->bad_decryption)
					return;
			} else if (has_seq) {
				// Key bit is not set, that means the other side does not want to send
				//  encrypted data
				//
				// make sure we do not have a key
				// (ie also interested in unencrypted communication)
				if (k->key_size && be16toh(gre->prot_type) != RIST_GRE_PROTOCOL_TYPE_EAPOL) {
					if (now > (p->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
						rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
								"We expect encrypted data and the peer sent clear communication, ignoring ...\n");
						p->log_repeat_timer = now;
					}
					return;
				}

				struct rist_gre_seq *gre_seq = (void *) recv_buf;
				gre_size = sizeof(*gre_seq);
				if (has_checksum) {
					seq = be32toh(gre_seq->seq);
				} else {
					// shifted by 4 missing checksum bytes (non-librist senders)
					seq = be32toh(gre_seq->checksum_reserved1);
					gre_size -= 4;
				}

			} else {
				// No sequence and no key (checksum is optional)
				gre_size = sizeof(*gre) - !has_checksum * 4;
				seq = 0;
			}
			if (gre->prot_type == htobe16(RIST_GRE_PROTOCOL_TYPE_FULL))
			{
				payload.type = RIST_PAYLOAD_TYPE_DATA_OOB;
				goto protocol_bypass;
			}
			if (gre->prot_type == htobe16(RIST_GRE_PROTOCOL_TYPE_EAPOL))
			{
				payload.type = RIST_PAYLOAD_TYPE_EAPOL;
				goto protocol_bypass;
			}
			// Make sure we have enought bytes
			if (recv_bufsize < (int)(sizeof(struct rist_protocol_hdr)+gre_size)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
				return;
			}
			/* Map the first subheader and rtp payload area to our structure */
			proto_hdr = (struct rist_protocol_hdr *)(recv_buf + gre_size);
			payload.src_port = be16toh(proto_hdr->src_port);
			payload.dst_port = be16toh(proto_hdr->dst_port);
		}
		else
		{
			// Simple profile support (not too elegant, but simple profile should not be used anymore)
			seq = 0;
			gre_size = 0;
			recv_bufsize += buffer_offset; // pretend the REDUCED_HEADER was read (needed for payload_len calculation below)
			// Make sure we have enought bytes
			if (recv_bufsize < (int)sizeof(struct rist_protocol_hdr)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
				return;
			}
			/* Map the first subheader and rtp payload area to our structure */
			proto_hdr = (struct rist_protocol_hdr *)recv_buf;
		}

		/* Double check for a valid rtp header */
		if ((proto_hdr->rtp.flags & 0xc0) != 0x80)
		{
			if (now > (p->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Malformed packet, rtp flag value is %02x instead of 0x80.\n",
						proto_hdr->rtp.flags);
						p->log_repeat_timer = now;
			}

			if (k && k->key_size > 0) {
				if (k->bad_count++ > 5) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Disabling packet processing till new NONCE\n");
					k->bad_decryption = true;
				}
			}
			return;
		}

		uint32_t rtp_time = 0;
		uint64_t source_time = 0;

		// Finish defining the payload (we assume reduced header)
		if(proto_hdr->rtp.payload_type < 200) {
			flow_id = be32toh(proto_hdr->rtp.ssrc);
			// If this is a retry, extract the information and restore correct flow_id
			if (flow_id & 1UL)
			{
				flow_id ^= 1UL;
				retry = 1;
			}
			uint8_t *data_payload = (recv_buf + gre_size + sizeof(*proto_hdr));
			payload.size = recv_bufsize - gre_size - sizeof(*proto_hdr);
			if (CHECK_BIT(proto_hdr->rtp.flags, 4)) {
				//RTP extension header
				struct rist_rtp_hdr_ext * hdr_ext = (struct rist_rtp_hdr_ext *)(recv_buf + gre_size + sizeof(*proto_hdr));
				if (memcmp(&hdr_ext->identifier, "RI", 2) == 0 && be16toh(hdr_ext->length) == 1)
				{
					payload.size -= 8;
					data_payload += sizeof(*hdr_ext);
					if (CHECK_BIT(hdr_ext->flags, 7))
						expand_null_packets(data_payload, &payload.size, hdr_ext->npd_bits);
				}
			}
			payload.data = (void *)data_payload;
			payload.type = RIST_PAYLOAD_TYPE_DATA_RAW;
		} else {
			// remap the rtp payload to the correct rtcp header
			struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)(&proto_hdr->rtp);
			flow_id = be32toh(rtcp->ssrc);
			payload.size = recv_bufsize - gre_size - RIST_GRE_PROTOCOL_REDUCED_SIZE;
			payload.data = (void *)(recv_buf + gre_size + RIST_GRE_PROTOCOL_REDUCED_SIZE);
			// Null this pointer to prevent code use below
			// as only the first 8 bytes have valid data for RTCP packets
			proto_hdr = NULL;
			payload.type = RIST_PAYLOAD_TYPE_RTCP;
		}

		//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
		//			"HTF gre_seq %"PRIu32" "
		//			"flow_id %"PRIu32", peer_id %"PRIu32", gre_size %zu, ptype %u\n",
		//			seq, flow_id, peer_id, gre_size, payload_type);

protocol_bypass:
		// We need this protocol bypass to manage keepalives of any kind,
		// they need to trigger peering at the bottom of this function

		;
		bool inchild = false;
		bool failed_eap = false;
		while (p) {
			if (equal_address(family, addr, p)) {
				if (p->eap_authentication_state != 1 && p->dead) {
					uint64_t dead_time = (now - p->last_rtcp_received);
					p->dead = false;
					//Only used on main profile
					if (p->parent)
						++p->parent->child_alive_count;
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
							"Peer %d was dead for %"PRIu64" ms and it is now alive again\n",
								dead_time / RIST_CLOCK, p->adv_peer_id);
				}
				p->last_rtcp_received = now;
				if (p->flow)
					p->flow->last_recv_ts = now;
				payload.peer = p;
				if (cctx->profile == RIST_PROFILE_SIMPLE)
				{
					payload.src_port = p->remote_port;
					payload.dst_port = p->local_port;
				}
				//rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Port is %d !!!!!\n", addr4.sin_port);
#ifdef USE_MBEDTLS
				if (payload.type != RIST_PAYLOAD_TYPE_EAPOL && p->eap_ctx && p->eap_ctx->authentication_state < EAP_AUTH_STATE_SUCCESS)
				{
					if (now > (p->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
						rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Waiting for EAP authentication to happen for peer connecting on port %d\n", addr4.sin_port);
						p->log_repeat_timer = now;
					}
					// Do not process non EAP packets until the peer has been authenticated!
					return;
				}
#endif
				switch(payload.type) {
					case RIST_PAYLOAD_TYPE_UNKNOWN:
						// Do nothing ...TODO: check for port changes?
						break;
					case RIST_PAYLOAD_TYPE_DATA_OOB:
						payload.size = recv_bufsize - gre_size;
						payload.data = (void *)(recv_buf + gre_size);
						rist_recv_oob_data(p, &payload);
						break;
					case RIST_PAYLOAD_TYPE_RTCP:
					case RIST_PAYLOAD_TYPE_RTCP_NACK:
					/* Need this for interop, we should move this to a per flow level eventually once we support multiple flows on a single peer*/
						if (RIST_UNLIKELY(p->receiver_ctx && p->local_port != payload.dst_port)) {
							rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Updating peer virt dst port to match remote source port: %u", payload.src_port);
							p->local_port = payload.dst_port;
							p->remote_port = payload.src_port;
						}
						rist_recv_rtcp(p, seq, flow_id, &payload);
						break;
					case RIST_PAYLOAD_TYPE_DATA_RAW:
						rtp_time = be32toh(proto_hdr->rtp.ts);
						if (RIST_UNLIKELY(p->config.timing_mode == RIST_TIMING_MODE_ARRIVAL))
							source_time = timestampNTP_u64();
						else
							source_time = convertRTPtoNTP(proto_hdr->rtp.payload_type, time_extension, rtp_time);
						seq = (uint32_t)be16toh(proto_hdr->rtp.seq);
						if (RIST_UNLIKELY(!p->receiver_mode))
							rist_log_priv(get_cctx(peer), RIST_LOG_WARN,
									"Received data packet on sender, ignoring (%d bytes)...\n", payload.size);
						else {
							rist_calculate_bitrate((recv_bufsize - gre_size - sizeof(*proto_hdr)), &p->bw);//use the unexpanded size to show real BW
							rist_receiver_recv_data(p, seq, flow_id, source_time, now, &payload, retry, proto_hdr->rtp.payload_type);
						}
						break;
					case RIST_PAYLOAD_TYPE_EAPOL:
#ifdef USE_MBEDTLS
						if (p->eap_ctx == NULL) {
							rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "EAP authentication requested but credentials have not been configured!\n");
						}
						else {
							int eapret = 0;
							if ((eapret = eap_process_eapol(p->eap_ctx,
															(void *)(recv_buf + gre_size),
															(recv_bufsize - gre_size))) < 0) {
								rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "Failed to process EAPOL pkt, return code: %i\n", eapret);
								if (eapret == 255)//permanent failure, we allow a few retries
									failed_eap = true;
							}
							else if (p->eap_authentication_state != 2 && p->eap_ctx->authentication_state == 1) {
								rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
									"Peer %d EAP Authentication suceeded\n", peer->adv_peer_id);
								p->eap_authentication_state = 2;

							}
						}
#else
						if (peer->eap_ctx == NULL) {
							rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "EAP authentication requested but EAP support not available!\n");
							failed_eap = true;
						}
#endif
						if (failed_eap) {
							p->eap_authentication_state = 1;
							kill_peer(p);
						}
						// Never create new peers using EAP packets (exit loop here)
						return;
						break;
					default:
						rist_recv_rtcp(p, seq, flow_id, &payload);
						break;
				}
				return;
			}
			if (p->listening) {
				if (!inchild)
					p = p->child;
				else
					p = p->sibling_next;
			} else
				p = p->next;
		}

		// Peer was not found, create a new one
		if ((peer->listening || peer->multicast) && (payload.type == RIST_PAYLOAD_TYPE_RTCP || cctx->profile == RIST_PROFILE_SIMPLE)) {
			/* No match, new peer creation when on listening mode */
			p = peer_initialize(NULL, peer->sender_ctx, peer->receiver_ctx);
			p->adv_peer_id = ++cctx->peer_counter;
			// Copy settings and init/update global variables that depend on settings
			peer_copy_settings(peer, p);
			if (cctx->profile == RIST_PROFILE_SIMPLE) {
				if (peer->address_family == AF_INET) {
					p->remote_port = htons(addr4.sin_port);
				} else {
					p->remote_port = htons(addr6.sin6_port);
				}
				p->local_port = peer->local_port;
			}
			else if (peer->receiver_ctx){
				// TODO: what happens if the first packet is a keepalive?? are we caching the wrong port?
				p->remote_port = payload.src_port;
				p->local_port = payload.dst_port;
			} else {
				p->remote_port = peer->remote_port;
				p->local_port = peer->local_port;
			}
			char peer_type[5];
			char id_name[8];
			if (peer->is_rtcp) {
				strcpy(peer_type, "RTCP");
				strcpy(id_name, "flow_id");
			} else if (peer->is_data) {
				strcpy(peer_type, "RTP");
				strcpy(id_name, "ssrc");
			}
			if (peer->receiver_mode) {
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "New %s peer connecting, %s %"PRIu32", peer_id %"PRIu32", ports %u <- %u\n",
					&peer_type, &id_name, flow_id, p->adv_peer_id, p->local_port, p->remote_port);
				p->adv_flow_id = flow_id;
			}
			else {
				if (flow_id) {
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "New reverse %s peer connecting with old flow_id %"PRIu32", peer_id %"PRIu32", ports %u <- %u\n",
							&peer_type, flow_id, p->adv_peer_id, p->local_port, p->remote_port);
				} else {
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "New reverse %s peer connecting, peer_id %"PRIu32", ports %u <- %u\n",
							&peer_type, p->adv_peer_id, p->local_port, p->remote_port);
				}
				p->peer_ssrc = p->adv_flow_id = p->sender_ctx->adv_flow_id;
			}
			// TODO: what if sender mode and flow_id != 0 and p->adv_flow_id != flow_id
			p->address_family = family;
			p->address_len = addrlen;
			p->listening = 0;
			p->is_rtcp = peer->is_rtcp;
			p->is_data = peer->is_data;
			p->peer_data = p;
			if (peer->multicast)
				p->peer_data = peer->peer_data;
			memcpy(&p->u.address, addr, addrlen);
			p->sd = peer->sd;
			p->parent = peer;
			p->authenticated = false;
			// Copy the event handler reference to prevent the creation of a new one (they are per socket)
			p->event_recv = peer->event_recv;
			uint16_t port = 0;
			char incoming_ip_string_buffer[INET6_ADDRSTRLEN];
			char *incoming_ip_string = get_ip_str(&p->u.address, &incoming_ip_string_buffer[0], &port, INET6_ADDRSTRLEN);
#ifdef USE_MBEDTLS
			eap_clone_ctx(peer->eap_ctx, p);
			eap_set_ip_string(p->eap_ctx, incoming_ip_string_buffer);
#endif
			// Optional validation of connecting sender
			if (cctx->auth.conn_cb) {

				char parent_ip_string_buffer[INET6_ADDRSTRLEN];

				uint16_t dummyport;

				char *parent_ip_string =
					get_ip_str(&p->parent->u.address, &parent_ip_string_buffer[0], &dummyport, INET6_ADDRSTRLEN);
				if (!parent_ip_string){
					parent_ip_string = "";
				}
				// Real source port vs virtual source port
				if (cctx->profile == RIST_PROFILE_SIMPLE)
					port = p->remote_port;
				if (incoming_ip_string) {
					if (cctx->auth.conn_cb(cctx->auth.arg,
								incoming_ip_string,
								port,
								parent_ip_string,
								p->parent->local_port,
								p)) {
						free(p);
						return;
					}
				}
			}

			if (payload.type == RIST_PAYLOAD_TYPE_RTCP && p->is_rtcp) {
				if (peer->receiver_mode)
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling keepalive for peer %d\n", p->adv_peer_id);
				else {
					// only profile > simple
					sender_peer_append(peer->sender_ctx, p);
					// authenticate sender now that we have an address
					rist_peer_authenticate(p);
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling reverse keepalive for peer %d\n", p->adv_peer_id);
				}
				p->send_keepalive = true;
			}
			peer_append(p);
			// Final states happens during settings parsing event on next ping packet
		} else {
			if (!p) {
				if (payload.type != RIST_PAYLOAD_TYPE_DATA_RAW) {
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "\tOrphan rist_peer_recv %x (%d)\n",
							 payload.type, peer->authenticated);
					rist_print_inet_info("Orphan ", peer);
				}
			} else {
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "\tRogue rist_peer_recv %x (%d)\n",
						 payload.type, p->authenticated);
				rist_print_inet_info("Orphan ", p);
			}
		}
	}

	int rist_oob_enqueue(struct rist_common_ctx *ctx, struct rist_peer *peer, const void *buf, size_t len)
	{
		if (RIST_UNLIKELY(!ctx->oob_data_enabled)) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
					"Trying to send oob but oob was not enabled\n");
			return -1;
		}
		else if ((ctx->oob_queue_write_index + 1) == ctx->oob_queue_read_index)
		{
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
					"oob queue is full (%zu bytes), try again later\n", ctx->oob_queue_bytesize);
			return -1;
		}

		/* insert into oob fifo queue */
		pthread_rwlock_wrlock(&ctx->oob_queue_lock);
		ctx->oob_queue[ctx->oob_queue_write_index] = rist_new_buffer(ctx, buf, len, RIST_PAYLOAD_TYPE_DATA_OOB, 0, 0, 0, 0);
		if (RIST_UNLIKELY(!ctx->oob_queue[ctx->oob_queue_write_index])) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "\t Could not create oob packet buffer, OOM\n");
			pthread_rwlock_unlock(&ctx->oob_queue_lock);
			return -1;
		}
		ctx->oob_queue[ctx->oob_queue_write_index]->peer = peer;
		ctx->oob_queue_write_index = (ctx->oob_queue_write_index + 1);
		ctx->oob_queue_bytesize += len;
		pthread_rwlock_unlock(&ctx->oob_queue_lock);

		return 0;
	}

	static void rist_oob_dequeue(struct rist_common_ctx *ctx, int maxcount)
	{
		int counter = 0;

		while (1) {
			// If we fall behind, only empty 100 every 5ms (master loop)
			if (counter++ > maxcount) {
				break;
			}

			if (ctx->oob_queue_read_index == ctx->oob_queue_write_index) {
				//rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				//	"\tWe are all up to date, index is %u/%u and bytes = %zu\n",
				//	ctx->oob_queue_read_index, ctx->oob_queue_write_index, ctx->oob_queue_bytesize);
				break;
			}

			struct rist_buffer *oob_buffer = ctx->oob_queue[ctx->oob_queue_read_index];
			if (!oob_buffer->data) {
				rist_log_priv(ctx, RIST_LOG_ERROR, "\tNull oob buffer, skipping!!!\n");
				ctx->oob_queue_read_index++;
				continue;
			}

			uint8_t *payload = oob_buffer->data;
			rist_send_common_rtcp(oob_buffer->peer, RIST_PAYLOAD_TYPE_DATA_OOB, &payload[RIST_MAX_PAYLOAD_OFFSET],
					oob_buffer->size, 0, 0, 0, 0);
			ctx->oob_queue_bytesize -= oob_buffer->size;
			ctx->oob_queue_read_index++;
		}

		return;
	}

	static void sender_send_nacks(struct rist_sender *ctx)
	{
		// Send retries from the queue (if any)
		uint32_t counter = 1;
		int errors = 0;
		size_t total_bytes = 0;

		if (ctx->max_nacksperloop == 0)
			return; // No peers yet

		// Send nack retries. Stop when the retry queue is empty or when the data in the
		// send fifo queue grows to 10 packets (we do not want to harm real-time data)
		// We also stop on maxcounter (jitter control and max bandwidth protection)
		size_t queued_items = (atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) - atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire)) &ctx->sender_queue_max;
		uint64_t start_time = timestampNTP_u64();
		while (queued_items < 10) {
			ssize_t ret = rist_retry_dequeue(ctx);
			if (ret == 0) {
				// ret == 0 is valid (nothing to send)
				break;
			} else if (ret < 0) {
				errors++;
			} else {
				total_bytes += ret;
				counter++;
			}
			if (counter > ctx->max_nacksperloop) {
				break;
			}
			if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 100)
			{
				rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Nack processing loop took longer than 100ms. Something is wrong!\n");
				// TODO: clear out the nack queue here?
				break;
			}
			queued_items = (atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) - atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire)) & ctx->sender_queue_max;
		}
		if (ctx->common.debug && 2 * (counter - 1) > ctx->max_nacksperloop)
		{
			rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Had to process multiple fifo nacks: c=%d, e=%d, b=%zu, s=%zu, m=%zu\n",
					counter - 1, errors, total_bytes, rist_get_sender_retry_queue_size(ctx),
					ctx->max_nacksperloop);
		}

	}

	static void sender_send_data(struct rist_sender *ctx, int maxcount)
	{
		int counter = 0;

		while (1) {
			// If we fall behind, only empty 100 every 5ms (master loop)
			if (counter++ > maxcount) {
				break;
			}

			size_t idx = ((size_t)atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire) + 1)& (ctx->sender_queue_max-1);

			if (idx == (size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_relaxed)) {
				//rist_log_priv(&ctx->common, RIST_LOG_ERROR,
				//    "\t[GOOD] We are all up to date, index is %d\n",
				//    ctx->sender_queue_read_index);
				break;
			}

			atomic_store_explicit(&ctx->sender_queue_read_index, idx, memory_order_release);
			if (RIST_UNLIKELY(ctx->sender_queue[idx] == NULL)) {
				// This should never happen!
				rist_log_priv(&ctx->common, RIST_LOG_ERROR,
						"FIFO data block was null (read/write) (%zu/%zu)\n",
						idx, atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_relaxed));
				continue;
			} else {
				struct rist_buffer *buffer =  ctx->sender_queue[idx];
				// Send  fifo data (handshake and data payloads)
				if (buffer->type == RIST_PAYLOAD_TYPE_RTCP) {
					// TODO can we ever have a null or dead buffer->peer?
					uint8_t *payload = buffer->data;
					rist_send_common_rtcp(buffer->peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, 0);
					buffer->seq = ctx->common.seq;
					buffer->seq_rtp = ctx->common.seq_rtp;
				}
				else {
					rist_sender_send_data_balanced(ctx, buffer);
					// For non-advanced mode seq to index mapping
					ctx->seq_index[buffer->seq_rtp] = (uint32_t)idx;
				}
			}

		}
	}

	static struct rist_peer *peer_initialize(const char *url, struct rist_sender *sender_ctx,
			struct rist_receiver *receiver_ctx)
	{
		struct rist_common_ctx *cctx;
		if (receiver_ctx)
			cctx = &receiver_ctx->common;
		else
			cctx = &sender_ctx->common;

		struct rist_peer *p = calloc(1, sizeof(*p));
		if (!p) {
			rist_log_priv(cctx, RIST_LOG_ERROR, "\tNot enough memory creating peer!\n");
			return NULL;
		}

		if (url) {
			p->url = strdup(url);
		}

		p->receiver_mode = (receiver_ctx != NULL);
		p->config.recovery_mode = RIST_RECOVERY_MODE_UNCONFIGURED;
		p->rtcp_keepalive_interval = RIST_PING_INTERVAL * RIST_CLOCK;
		p->sender_ctx = sender_ctx;
		p->receiver_ctx = receiver_ctx;
		p->birthtime_local = timestampNTP_u64();

		return p;
	}

	static PTHREAD_START_FUNC(receiver_pthread_dataout, arg)
	{
		struct rist_flow *flow = (struct rist_flow *)arg;
		struct rist_receiver *receiver_ctx = (void *)flow->receiver_id;

#ifndef _WIN32
		int prio_max = sched_get_priority_max(SCHED_RR);
		struct sched_param param = { 0 };
		param.sched_priority = prio_max;
		if (pthread_setschedparam(pthread_self(), SCHED_RR, &param) != 0)
			rist_log_priv(&receiver_ctx->common, RIST_LOG_WARN, "Failed to set data output thread to RR scheduler with prio of %i\n", prio_max);
#else
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#endif
		// Default max jitter is 5ms
		int max_output_jitter_ms = flow->max_output_jitter / RIST_CLOCK;
		if (max_output_jitter_ms > 100)
			max_output_jitter_ms = 100;

		rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO, "Starting data output thread with %d ms max output jitter\n", max_output_jitter_ms);

		while (true) {
			pthread_mutex_lock(&(flow->mutex));
			int ret = pthread_cond_timedwait_ms(&flow->condition, &flow->mutex, max_output_jitter_ms);
			if (ret && ret != ETIMEDOUT)
				rist_log_priv(&receiver_ctx->common, RIST_LOG_ERROR, "Error %d in receiver data out loop\n", ret);
			if (flow->shutdown > 0)
				break;
			if (atomic_load_explicit(&flow->receiver_queue_size, memory_order_acquire) > 0) {
				receiver_output(receiver_ctx, flow);
			}
			pthread_mutex_unlock(&(flow->mutex));
		}
		rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO, "Data output thread shutting down\n");
		flow->shutdown = 2;
		pthread_mutex_unlock(&flow->mutex);
		return 0;
	}

	static void sender_peer_events(struct rist_sender *ctx, uint64_t now)
	{
		pthread_mutex_lock(&ctx->common.peerlist_lock);
		for (size_t j = 0; j < ctx->peer_lst_len; j++) {
			struct rist_peer *peer = ctx->peer_lst[j];
			if (peer->send_keepalive) {
				if (now > peer->keepalive_next_time) {
					peer->keepalive_next_time = now + peer->rtcp_keepalive_interval;
					rist_peer_rtcp(NULL, peer);
				}
			}
#ifdef USE_MBEDTLS
			if (!peer->listening || peer->parent)
				eap_periodic(peer->eap_ctx);
#endif
		}

		pthread_mutex_unlock(&ctx->common.peerlist_lock);
	}


	void rist_timeout_check(struct rist_common_ctx *cctx, uint64_t now)
	{
		struct rist_peer *peer = cctx->PEERS;
		while (peer)
		{
			struct rist_peer *next = peer->next;
			if (!peer->dead && now > peer->last_rtcp_received && peer->last_rtcp_received > 0)
			{
				if ((now - peer->last_rtcp_received) > peer->session_timeout)
				{
					rist_log_priv2(cctx->logging_settings, RIST_LOG_WARN, "Listening peer %u timed out after %"PRIu64" ms\n", peer->adv_peer_id,
						(now - peer->last_rtcp_received)/ RIST_CLOCK);
					kill_peer(peer);
				}
			} else if (peer->dead && peer->parent)
			{
				if ( peer->dead_since < now && (now - peer->dead_since) > 5000 * RIST_CLOCK)
				{
					rist_log_priv2(cctx->logging_settings, RIST_LOG_INFO, "Removing timed-out peer %u\n", peer->adv_peer_id);
					rist_peer_remove(cctx, peer, NULL);
				}
			}
			peer = next;
		}
	}

	PTHREAD_START_FUNC(sender_pthread_protocol, arg)
	{
		struct rist_sender *ctx = (struct rist_sender *) arg;
		// loop behavior parameters
		int max_dataperloop = 100;
		int max_oobperloop = 100;

		int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
		uint64_t rist_stats_interval = ctx->common.stats_report_time; // 1 second

		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting master sender loop at %d ms max jitter\n",
				max_jitter_ms);

		uint64_t now  = timestampNTP_u64();
		ctx->stats_next_time = now;
		ctx->checks_next_time = now;
		uint64_t nacks_next_time = now;
		while(!ctx->common.shutdown) {
			// Conditional 5ms sleep that is woken by data coming in
			pthread_mutex_lock(&(ctx->mutex));
			int ret = pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), max_jitter_ms);
			if (RIST_UNLIKELY(!ctx->common.startup_complete)) {
				pthread_mutex_unlock(&(ctx->mutex));
				continue;
			}
			pthread_mutex_unlock(&(ctx->mutex));
			if (ret && ret != ETIMEDOUT)
				rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d in sender protocol loop, loop time was %d us\n", ret, (timestampNTP_u64() - now));

			now  = timestampNTP_u64();

			/* marks peer as dead, run every second */
			if (now > ctx->checks_next_time)
			{
				ctx->checks_next_time += (uint64_t)1000 * (uint64_t)RIST_CLOCK;
				pthread_mutex_lock(&ctx->common.peerlist_lock);
				rist_timeout_check(&ctx->common, now);
				pthread_mutex_unlock(&ctx->common.peerlist_lock);
			}

			// stats timer
			if (now > ctx->stats_next_time) {
				ctx->stats_next_time += rist_stats_interval;

				pthread_mutex_lock(&ctx->common.peerlist_lock);
				for (size_t j = 0; j < ctx->peer_lst_len; j++) {
					struct rist_peer *peer = ctx->peer_lst[j];
					// TODO: print warning if the peer is dead?, i.e. no stats
					if (!peer->dead) {
						rist_sender_peer_statistics(peer);
					}
				}
				pthread_mutex_unlock(&ctx->common.peerlist_lock);
				// TODO: remove dead peers after stale flow time (both sender list and peer chain)
				// sender_peer_delete(peer->sender_ctx, peer);
			}

			// socket polls (returns as fast as possible and processes the next 100 socket events)
			pthread_mutex_lock(&ctx->common.peerlist_lock);
			evsocket_loop_single(ctx->common.evctx, 0, 100);
			pthread_mutex_unlock(&ctx->common.peerlist_lock);

			// keepalive timer
			sender_peer_events(ctx, now);


			// Send data and process nacks
			pthread_mutex_lock(&ctx->queue_lock);
			if (ctx->sender_queue_bytesize > 0) {
				sender_send_data(ctx, max_dataperloop);
				// Group nacks and send them all at rist_max_jitter intervals
				if (now > nacks_next_time) {
					sender_send_nacks(ctx);
					nacks_next_time += ctx->common.rist_max_jitter;
				}
				/* perform queue cleanup */
				rist_clean_sender_enqueue(ctx);
			}
			pthread_mutex_unlock(&ctx->queue_lock);
			// Send oob data
			if (ctx->common.oob_queue_bytesize > 0)
				rist_oob_dequeue(&ctx->common, max_oobperloop);

		}

#ifdef _WIN32
		WSACleanup();
#endif
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Exiting master sender loop\n");
		ctx->common.shutdown = 2;

		return 0;
	}

	int init_common_ctx(struct rist_common_ctx *ctx, enum rist_profile profile)
	{
#ifdef _WIN32
		int ret;
		WSADATA wsaData;
		ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (ret < 0) {
			rist_log_priv3(RIST_LOG_ERROR, "Failed to initialize WSA\n");
			return -1;
		}
#endif
		ctx->evctx = evsocket_create();
		ctx->rist_max_jitter = RIST_MAX_JITTER * RIST_CLOCK;
		if (profile > RIST_PROFILE_ADVANCED) {
			rist_log_priv3( RIST_LOG_ERROR, "Profile not supported (%d), using main profile instead\n", profile);
			profile = RIST_PROFILE_MAIN;
		}
		if (profile == RIST_PROFILE_SIMPLE)
			rist_log_priv3( RIST_LOG_INFO, "Starting in Simple Profile Mode\n");
		else if (profile == RIST_PROFILE_MAIN)
			rist_log_priv3( RIST_LOG_INFO, "Starting in Main Profile Mode\n");
		else if (profile == RIST_PROFILE_ADVANCED)
			rist_log_priv3( RIST_LOG_INFO, "Starting in Advanced Profile Mode\n");

		ctx->profile = profile;
		ctx->stats_report_time = 0;

		if (pthread_mutex_init(&ctx->peerlist_lock, NULL) != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->peerlist_lock\n");
			return -1;
		}
		if (pthread_mutex_init(&ctx->rist_free_buffer_mutex, NULL) != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->rist_free_buffer_mutex\n");
			return -1;
		}
		if (pthread_mutex_init(&ctx->flows_lock, NULL) != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->flows_lock\n");
			return -1;
		}
		if (pthread_mutex_init(&ctx->stats_lock, NULL) != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->stats_lock\n");
			return -1;
		}
		return 0;
	}

static inline void peer_remove_child(struct rist_peer *peer) {
	assert(peer->parent);
	//head
	if (!peer->sibling_prev) {
		peer->parent->child = peer->sibling_next;
	//middle or tail
	} else {
		peer->sibling_prev->sibling_next = peer->sibling_next;
	}
	if (peer->sibling_next)
		peer->sibling_next->sibling_prev = peer->sibling_prev;
	return;
}

static inline void peer_remove_linked_list(struct rist_peer *peer) {
	assert(peer);
	struct rist_common_ctx *ctx = get_cctx(peer);
	if (!peer->prev) {
		ctx->PEERS = peer->next;
	} else {
		peer->prev->next = peer->next;
	}
	if (peer->next)
		peer->next->prev = peer->prev;
	return;
}


void remove_peer_from_flow(struct rist_peer *peer)
{
	bool found = false;
	for (size_t i = 0; i < peer->flow->peer_lst_len; i++)
	{
		if (peer->flow->peer_lst[i] == peer)
		{
			peer->flow->peer_lst[i] = peer->flow->peer_lst[(peer->flow->peer_lst_len -1)];
			found = true;
			break;
		}
	}
	if (found)
	{
		if (peer->flow->peer_lst_len > 1)
		{
			peer->flow->peer_lst = realloc(peer->flow->peer_lst, sizeof(peer) * (peer->flow->peer_lst_len -1));
			peer->flow->peer_lst_len--;
		} else
		{
			free(peer->flow->peer_lst);
			peer->flow->peer_lst_len = 0;
			peer->flow->peer_lst = NULL;
		}
	}
}

int rist_peer_remove(struct rist_common_ctx *ctx, struct rist_peer *peer, struct rist_peer **next)
{
	if (peer == NULL) {
		return -1;
		if (next)
			*next = NULL;
	}
	peer->shutdown = true;
	if (peer->send_first_connection_event && ctx->connection_status_callback && (ctx->profile != RIST_PROFILE_SIMPLE || peer->is_rtcp))
		ctx->connection_status_callback(ctx->connection_status_callback_argument, peer, RIST_CONNECTION_TIMED_OUT);
	if (peer->child)
	{
		while (peer->child) {
			rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] removing child peer %u from peer %u\n", peer->child->adv_peer_id, peer->adv_peer_id);
			rist_peer_remove(ctx, peer->child, NULL);
		}
	}

	struct rist_peer *check = ctx->PEERS;
	while (check)
	{
		if (check->peer_data == peer)
			check->peer_data = NULL;
		if (check->peer_rtcp == peer)
			check->peer_rtcp = NULL;
		check = check->next;
	}
	if (peer->parent) {
		peer_remove_child(peer);
		if (peer->parent->child == NULL) {
			peer->parent->authenticated = false;
		}
	}
	peer_remove_linked_list(peer);

	if (peer->parent && peer->flow && peer->flow->peer_lst_len > 0 && peer->flow->peer_lst != NULL) {
		remove_peer_from_flow(peer);
	}

	if (peer->sender_ctx && peer->sender_ctx->peer_lst_len > 0) {
		bool found = false;
        for (size_t i = 0; i < peer->sender_ctx->peer_lst_len; i++) {
            if (peer->sender_ctx->peer_lst[i] == peer) {
              peer->sender_ctx->peer_lst[i] = peer->sender_ctx->peer_lst[(peer->sender_ctx->peer_lst_len -1)];
              found = true;
              break;
            }
		}
		if (found) {
			if (peer->sender_ctx->peer_lst_len > 1)
			{
				peer->sender_ctx->peer_lst = realloc(peer->sender_ctx->peer_lst, sizeof(peer) * (peer->sender_ctx->peer_lst_len -1));
				peer->sender_ctx->peer_lst_len--;
			} else
			{
				free(peer->sender_ctx->peer_lst);
				peer->sender_ctx->peer_lst_len = 0;
				peer->sender_ctx->peer_lst = NULL;
			}
		}
    }


	/* data receive event */
	if (!peer->parent && peer->event_recv)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] Removing peer data received event\n");
		struct evsocket_ctx *evctx = ctx->evctx;
		evsocket_delevent(evctx, peer->event_recv);
	}

	/* rtcp timer */
	if (peer->send_keepalive)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] Removing peer handshake/ping timer\n");
		peer->send_keepalive = false;
	}


	if (!peer->parent && peer->sd > -1)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] Closing peer socket on port %d\n", peer->local_port);
		udpsocket_close(peer->sd);
		peer->sd = -1;
	}
	_librist_crypto_psk_rist_key_destroy(&peer->key_rx);
	_librist_crypto_psk_rist_key_destroy(&peer->key_tx);
#ifdef USE_MBEDTLS
	eap_delete_ctx(&peer->eap_ctx);
#endif
	if (peer->url)
		free(peer->url);

	if (ctx->auth.arg) {
		ctx->auth.disconn_cb(ctx->auth.arg, peer);
	}
	if (next != NULL)
		*next = peer->next;
	rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] cleanup done for peer %u\n", peer->adv_peer_id);
	free(peer);
	return 0;
}

int rist_auth_handler(struct rist_common_ctx *ctx,
		int (*conn_cb)(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer),
		int (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg)
{
	ctx->auth.conn_cb = conn_cb;
	ctx->auth.disconn_cb = disconn_cb;
	ctx->auth.arg = arg;
	return 0;
}

static void store_peer_settings(const struct rist_peer_config *settings, struct rist_peer *peer)
{
	uint32_t recovery_rtt_min;
	uint32_t min_retries;
	uint32_t max_retries;

	// TODO: Consolidate the two settings objects into one

	/* Set recovery options */
	peer->config.recovery_mode = settings->recovery_mode;
	peer->config.recovery_maxbitrate = settings->recovery_maxbitrate;
	peer->config.recovery_maxbitrate_return = settings->recovery_maxbitrate_return;
	peer->config.recovery_length_min = settings->recovery_length_min;
	peer->config.recovery_length_max = settings->recovery_length_max;
	peer->config.recovery_reorder_buffer = settings->recovery_reorder_buffer;
	if (settings->recovery_rtt_min < RIST_RTT_MIN) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "rtt_min is too small (%u), using %dms instead\n",
				settings->recovery_rtt_min, RIST_RTT_MIN);
		recovery_rtt_min = RIST_RTT_MIN;
	} else {
		recovery_rtt_min = settings->recovery_rtt_min;
	}
	peer->config.recovery_rtt_min = recovery_rtt_min;
	peer->config.recovery_rtt_max = settings->recovery_rtt_max;
	/* Set buffer-bloating */
	if (settings->min_retries < 2 || settings->min_retries > 100) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"The configured value for min_retries 2 <= %u <= 100 is invalid, using %u instead\n",
				settings->min_retries, 6);
		min_retries = 6;
	} else {
		min_retries = settings->min_retries;
	}
	if (settings->max_retries < 2 || settings->max_retries > 100) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"The configured value for max_retries 2 <= %u <= 100 is invalid, using %u instead\n",
				settings->max_retries, 20);
		max_retries = 20;
	} else {
		max_retries = settings->max_retries;
	}
	peer->config.congestion_control_mode = settings->congestion_control_mode;
	peer->config.min_retries = min_retries;
	peer->config.max_retries = max_retries;
	peer->config.weight = settings->weight;
	peer->config.timing_mode = settings->timing_mode;
	peer->config.virt_dst_port = settings->virt_dst_port;

	init_peer_settings(peer);
}

struct rist_peer *rist_sender_peer_insert_local(struct rist_sender *ctx,
		const struct rist_peer_config *config, bool b_rtcp)
{
	if (config->key_size) {
		if (config->key_size != 128 && config->key_size != 192 && config->key_size != 256) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Invalid encryption key length: %d\n", config->key_size);
			return NULL;
		}
		if (!strlen(config->secret)) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Invalid secret passphrase\n");
			return NULL;
		}
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Using %d bits secret key\n", config->key_size);
	}
	else {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Encryption is disabled for this peer\n");
	}

	/* Initialize peer */
	struct rist_peer *newpeer = peer_initialize(config->address, ctx, NULL);
	if (!newpeer) {
		return NULL;
	}

	strncpy(&newpeer->miface[0], config->miface, RIST_MAX_STRING_SHORT);
	strncpy(&newpeer->cname[0], config->cname, RIST_MAX_STRING_SHORT);
	if (config->address_family && rist_set_manual_sockdata(newpeer, config)) {
		free(newpeer);
		return NULL;
	}

	if (config->key_size) {
		_librist_crypto_psk_rist_key_init(&newpeer->key_tx, config->key_size, config->key_rotation, config->secret);
		_librist_crypto_psk_rist_key_clone(&newpeer->key_tx, &newpeer->key_rx);
	}

	if (config->keepalive_interval > 0) {
		newpeer->rtcp_keepalive_interval = config->keepalive_interval * RIST_CLOCK;
	}

	if (config->session_timeout > 0) {
		newpeer->session_timeout = config->session_timeout * RIST_CLOCK;
	}
	else {
		newpeer->session_timeout = 250 * RIST_CLOCK;//default to 250ms, which is 2,5 RTCP periods
	}

	/* Initialize socket */
	rist_create_socket(newpeer);
	if (newpeer->sd < 0) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create socket\n");
		free(newpeer);
		return NULL;
	}

	if (b_rtcp)
	{
		if (newpeer->u.address.sa_family == AF_INET) {
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(newpeer->u);
			newpeer->remote_port = htons(addrv4->sin_port) + 1;
			addrv4->sin_port = be16toh(newpeer->remote_port);
		} else {
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(newpeer->u);
			newpeer->remote_port = htons(addrv6->sin6_port) + 1;
			addrv6->sin6_port = be16toh(newpeer->remote_port);
		}
	}
	else
	{
		newpeer->local_port = 32768 + (ctx->common.peer_counter % 28232);
		// This overrides the physical port populate in rist_create_socket with the gre dst port
		if (ctx->common.profile != RIST_PROFILE_SIMPLE && config->virt_dst_port != 0)
			newpeer->remote_port = config->virt_dst_port + 1;
	}

	newpeer->cooldown_time = 0;
	newpeer->is_rtcp = b_rtcp;
	newpeer->adv_peer_id = ++ctx->common.peer_counter;
	newpeer->peer_ssrc = newpeer->adv_flow_id = ctx->adv_flow_id;

	store_peer_settings(config, newpeer);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Advertising flow_id  %" PRIu64 " and peer_id %u, %u/%u\n",
			newpeer->adv_flow_id, newpeer->adv_peer_id, newpeer->local_port, newpeer->remote_port);

	return newpeer;

}

void receiver_peer_events(struct rist_receiver *ctx, uint64_t now)
{
	pthread_mutex_lock(&ctx->common.peerlist_lock);

	for (struct rist_peer *p = ctx->common.PEERS; p != NULL; p = p->next) {
		if (p->send_keepalive) {
			if (now > p->keepalive_next_time) {
				p->keepalive_next_time = now + p->rtcp_keepalive_interval;
				rist_peer_rtcp(NULL, p);
			}
		}
#ifdef USE_MBEDTLS
		if (!p->listening && p->parent)
			eap_periodic(p->eap_ctx);
#endif
	}

	pthread_mutex_unlock(&ctx->common.peerlist_lock);
}

void rist_empty_oob_queue(struct rist_common_ctx *ctx)
{
	uint16_t index = 0;
	while (1) {
		if (index == ctx->oob_queue_write_index) {
			break;
		}
		struct rist_buffer *oob_buffer = ctx->oob_queue[index];
		if (oob_buffer->data) {
			free(oob_buffer->data);
			oob_buffer->data = NULL;
		}
		if (oob_buffer) {
			free(oob_buffer);
			oob_buffer = NULL;
		}
		index++;
	}
	ctx->oob_queue_bytesize = 0;
}

void rist_receiver_destroy_local(struct rist_receiver *ctx)
{

	pthread_mutex_lock(&ctx->common.peerlist_lock);

	// Destroy all flows
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting Flows cleanup\n");
	struct rist_flow *f = ctx->common.FLOWS;
	while (f) {
		struct rist_flow *nextflow = f->next;
		rist_delete_flow(ctx, f);
		f = nextflow;
	}
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Flows cleanup complete\n");

	// Destroy all peers
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting Peers cleanup\n");
	struct rist_peer *peer, *next;
	peer = ctx->common.PEERS;
	for (;;) {
		if (!peer)
			break;
		rist_peer_remove(&ctx->common, peer, &next);
		peer = next;
	}
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peers cleanup complete\n");

	pthread_mutex_unlock(&ctx->common.peerlist_lock);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing main data buffers\n");
	struct rist_buffer *b = ctx->common.rist_free_buffer;
	struct rist_buffer *next_buf;
	while (b) {
		next_buf = b->next_free;
		free_rist_buffer(&ctx->common, b);
		b = next_buf;
	}
	evsocket_destroy(ctx->common.evctx);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing peerlist_lock\n");
	pthread_mutex_destroy(&ctx->common.peerlist_lock);
	if (ctx->common.oob_data_enabled) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing oob fifo queue\n");
		rist_empty_oob_queue(&ctx->common);
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing oob_queue_lock\n");
		pthread_rwlock_destroy(&ctx->common.oob_queue_lock);
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing data fifo signaling variables (condition and mutex)\n");
	pthread_cond_destroy(&ctx->condition);
	pthread_mutex_destroy(&ctx->mutex);

	free(ctx);
	ctx = NULL;
}

PTHREAD_START_FUNC(receiver_pthread_protocol, arg)
{
	struct rist_receiver *ctx = (struct rist_receiver *) arg;
	uint64_t now = timestampNTP_u64();
	int max_oobperloop = 100;

	uint64_t rist_nack_interval = (uint64_t)ctx->common.rist_max_jitter;
	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
	ctx->common.nacks_next_time = timestampNTP_u64();
	uint64_t checks_next_time = now;
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting receiver protocol loop with %d ms timer\n", max_jitter_ms);

	while (!ctx->common.shutdown) {
		now  = timestampNTP_u64();
		pthread_mutex_lock(&ctx->common.peerlist_lock);
		if (ctx->common.PEERS == NULL) {
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
			usleep(5000);
			continue;
		}
		pthread_mutex_unlock(&ctx->common.peerlist_lock);

		// Limit scope of `struct rist_flow *f` for clarity since it is used again later in this loop.
		{
			// stats and session timeout timer
			struct rist_flow *f = ctx->common.FLOWS;
			while (f) {
				if (!f->receiver_queue_has_items) {
					f = f->next;
					continue;
				}
				if (now > f->checks_next_time) {
					if (f->last_recv_ts == 0)
						f->last_recv_ts = now;
					uint64_t flow_age = (now - f->last_recv_ts);
					f->checks_next_time += f->recovery_buffer_ticks;
					if (flow_age > f->flow_timeout) {
						if (f->dead != 1) {
							f->dead = 1;
							rist_log_priv(&ctx->common, RIST_LOG_WARN,
								"Flow with id %"PRIu32" is dead, age is %"PRIu64"ms\n",
									f->flow_id, flow_age / RIST_CLOCK);
						}
					}
					else {
						if (f->dead != 0) {
							f->dead = 0;
							rist_log_priv(&ctx->common, RIST_LOG_INFO,
								"Flow with id %"PRIu32" was dead and is now alive again\n", f->flow_id);
						}
					}
					if (flow_age > f->session_timeout) {
						f->dead = 2;
						struct rist_flow *next = f->next;
						rist_receiver_flow_statistics(ctx, f);
						rist_log_priv(&ctx->common, RIST_LOG_INFO,
								"\t************** Session Timeout after %" PRIu64 "s of no data, deleting flow with id %"PRIu32" ***************\n",
								flow_age / RIST_CLOCK / 1000, f->flow_id);
						pthread_mutex_lock(&ctx->common.peerlist_lock);
						for (size_t i = 0; i < f->peer_lst_len; i++) {
							struct rist_peer *peer = f->peer_lst[i];
							peer->flow = NULL;
						}
						rist_delete_flow(ctx, f);
						pthread_mutex_unlock(&ctx->common.peerlist_lock);
						f = next;
						continue;
					}
				}
				if (now > f->stats_next_time) {
					f->stats_next_time += f->stats_report_time;
					rist_receiver_flow_statistics(ctx, f);
				}
				f = f->next;
			}
		}

		// TODO: rist_max_jitter should be proportional to the max bitrate according to the
		// following table
		//Mbps  ms
		//125	8.00
		//250	4.00
		//520	1.92
		//1000	1.00

		// socket polls (returns in max_jitter_ms max and processes the next 100 socket events)
		pthread_mutex_lock(&ctx->common.peerlist_lock);
		evsocket_loop_single(ctx->common.evctx, max_jitter_ms, 100);
		pthread_mutex_unlock(&ctx->common.peerlist_lock);
		// keepalive timer
		receiver_peer_events(ctx, now);

		// nacks timer
		if (now > ctx->common.nacks_next_time) {
			ctx->common.nacks_next_time += rist_nack_interval;
			// process nacks on every loop (5 ms interval max)
			struct rist_flow *f = ctx->common.FLOWS;
			while (f) {
				receiver_nack_output(ctx, f);
				f = f->next;
			}
		}
		/* marks peer as dead, run every second */
		if (now > checks_next_time)
		{
			checks_next_time += (uint64_t)50 * (uint64_t)RIST_CLOCK;
			pthread_mutex_lock(&ctx->common.peerlist_lock);
			rist_timeout_check(&ctx->common, now);
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
		}
		// Send oob data
		if (ctx->common.oob_queue_bytesize > 0)
			rist_oob_dequeue(&ctx->common, max_oobperloop);

	}
#ifdef _WIN32
	WSACleanup();
#endif
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Exiting master receiver loop\n");
	ctx->common.shutdown = 2;

	return 0;
}

void rist_sender_destroy_local(struct rist_sender *ctx)
{
	rist_log_priv(&ctx->common, RIST_LOG_INFO,
			"Starting peers cleanup, count %d\n",
			(unsigned) ctx->peer_lst_len);

	pthread_mutex_lock(&ctx->common.peerlist_lock);	// Destroy all peers
	while (ctx->peer_lst_len > 0) {
		rist_peer_remove(&ctx->common, ctx->peer_lst[0], NULL);
	}
	struct rist_peer *peer, *next;
	peer = ctx->common.PEERS;
	for (;;) {
		if (!peer)
			break;
		rist_peer_remove(&ctx->common, peer, &next);
		peer = next;
	}
	evsocket_destroy(ctx->common.evctx);

	pthread_mutex_unlock(&ctx->common.peerlist_lock);
	pthread_mutex_destroy(&ctx->common.peerlist_lock);
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peers cleanup complete\n");

	if (ctx->common.oob_data_enabled) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing oob fifo queue\n");
		rist_empty_oob_queue(&ctx->common);
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing oob_queue_lock\n");
		pthread_rwlock_destroy(&ctx->common.oob_queue_lock);
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing up context memory allocations\n");
	free(ctx->sender_retry_queue);
	struct rist_buffer *b = NULL;
	while(1) {
		b = ctx->sender_queue[ctx->sender_queue_delete_index];
		while (!b) {
			ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1);
			b = ctx->sender_queue[ctx->sender_queue_delete_index];
			if ((size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_relaxed) == ctx->sender_queue_delete_index)
				break;
		}
		if (b) {
			ctx->sender_queue_bytesize -= b->size;
			free_rist_buffer(&ctx->common, b);
			ctx->sender_queue[ctx->sender_queue_delete_index] = NULL;
		}
		if ((size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) == ctx->sender_queue_delete_index) {
			break;
		}
		ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1);
	}
	free(ctx);
	ctx = NULL;
	}
