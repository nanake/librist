/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Antonio Cardace <anto.cardace@gmail.com>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "rist-private.h"
#include "aes.h"
#include "fastpbkdf2.h"
#include "crypto-private.h"
#include "log-private.h"
#include "udp-private.h"
#include "network.h"
#include "endian-shim.h"
#include "time-shim.h"
#include "lz4/lz4.h"
#include <stdbool.h>
#include "stdio-shim.h"

#ifdef _WIN32
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef signed int ssize_t;
#endif
#endif

static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static PTHREAD_START_FUNC(server_pthread_protocol,arg);
static PTHREAD_START_FUNC(server_pthread_dataout,arg);
static void rist_fsm_init_comm(struct rist_peer *peer);

static struct rist_peer *peer_initialize(const char *url, const char *localport,
										struct rist_client *client_ctx,
										struct rist_server *server_ctx);

struct rist_common_ctx *get_cctx(struct rist_peer *peer)
{
	if (peer->client_ctx) {
		return &peer->client_ctx->common;
	} else {
		return &peer->server_ctx->common;
	}
}

/* t is in ms */
static int rist_set_session_timeout(struct rist_common_ctx *ctx, int t)
{
	(void) ctx;
	(void) t;

	return 0;
}

int rist_client_set_session_timeout(struct rist_client *ctx, int t)
{
	return rist_set_session_timeout(&ctx->common, t);
}

int rist_server_set_session_timeout(struct rist_server *ctx, int t)
{
	return rist_set_session_timeout(&ctx->common, t);
}

static int rist_set_keepalive_timeout(struct rist_common_ctx *ctx, int t)
{
	if (t > 0) {
		ctx->rist_keepalive_interval = t * RIST_CLOCK;
		return 0;
	}

	return -1;
}

int rist_client_set_keepalive_timeout(struct rist_client *ctx, int t)
{
	return rist_set_keepalive_timeout(&ctx->common, t);
}

int rist_server_set_keepalive_timeout(struct rist_server *ctx, int t)
{
	return rist_set_keepalive_timeout(&ctx->common, t);
}

static int rist_set_max_jitter(struct rist_common_ctx *ctx, int t)
{
	if (t > 0) {
		ctx->rist_max_jitter = t * RIST_CLOCK;
		return 0;
	}

	return -1;
}

int rist_client_set_max_jitter(struct rist_client *ctx, int t)
{
	return rist_set_max_jitter(&ctx->common, t);
}

int rist_server_set_max_jitter(struct rist_server *ctx, int t)
{
	return rist_set_max_jitter(&ctx->common, t);
}

static void server_store_settings(struct rist_peer *peer, const struct rist_settings *settings)
{

	peer->recovery_mode = settings->recovery_mode;
	peer->recover_maxbitrate = settings->recover_maxbitrate;
	peer->recover_maxbitrate_return = settings->recover_maxbitrate_return;
	peer->recover_buffer_min = settings->recover_buffer_min;
	peer->recover_buffer_max = settings->recover_buffer_max;
	peer->recover_reorder_buffer = settings->recover_reorder_buffer;
	peer->recover_rtt_min = settings->recover_rtt_min;
	peer->recover_rtt_max = settings->recover_rtt_max;
	peer->bufferbloat_mode = settings->bufferbloat_mode;
	peer->bufferbloat_limit = settings->bufferbloat_limit;
	peer->bufferbloat_hard_limit = settings->bufferbloat_hard_limit;

	// Initial value for some variables
	peer->recover_buffer_ticks =
		(peer->recover_buffer_max - peer->recover_buffer_min) / 2 + peer->recover_buffer_min;

	if (settings->recovery_mode == RIST_RECOVERY_MODE_TIME)
		peer->recover_buffer_ticks = peer->recover_buffer_ticks * RIST_CLOCK;

	switch (peer->recovery_mode) {
	case RIST_RECOVERY_MODE_BYTES:
		peer->missing_counter_max = peer->recover_buffer_ticks /
			(sizeof(struct rist_gre_seq) + sizeof(struct rist_rtp_hdr) + sizeof(uint32_t));
	break;
	case RIST_RECOVERY_MODE_TIME:
		peer->missing_counter_max =
			(peer->recover_buffer_ticks / RIST_CLOCK) * peer->recover_maxbitrate /
			(sizeof(struct rist_gre_seq) + sizeof(struct rist_rtp_hdr) + sizeof(uint32_t));
		peer->eight_times_rtt = settings->recover_rtt_min * 8;
	break;
	case RIST_RECOVERY_MODE_DISABLED:
	case RIST_RECOVERY_MODE_UNCONFIGURED:
		msg(peer->server_ctx->id, 0, RIST_LOG_ERROR,
			"[ERROR] Client sent wrong recovery setting.\n");
	break;
	}

	msg(peer->server_ctx->id, 0, RIST_LOG_INFO,
		"[INFO] Peer with id #%"PRIu32" was configured with maxrate=%d/%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d buffer_bloat=%d (limit:%d, hardlimit:%d)\n",
		peer->adv_peer_id, peer->recover_maxbitrate, peer->recover_maxbitrate_return, peer->recover_buffer_min, peer->recover_buffer_max, peer->recover_reorder_buffer,
		peer->recover_rtt_min, peer->recover_rtt_max, peer->bufferbloat_mode, peer->bufferbloat_limit, peer->bufferbloat_hard_limit);

}

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

struct rist_buffer *rist_new_buffer(const void *buf, size_t len, uint8_t type, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	// TODO: we will ran out of stack before heap and when that happens malloc will crash not just
	// return NULL ... We need to find and remove all heap allocations
	struct rist_buffer *b = malloc(sizeof(*b));
	if (!b) {
		fprintf(stderr, "OOM\n");
		return NULL;
	}

	if (len > 0)
	{
		b->data = malloc(len + RIST_MAX_PAYLOAD_OFFSET);
		if (!b->data) {
			free(b);
			fprintf(stderr, "OOM\n");
			return NULL;
		}
		memcpy(b->data + RIST_MAX_PAYLOAD_OFFSET, buf, len);
	}

	uint64_t now = timestampNTP_u64();
	b->size = len;
	b->source_time = source_time;
	b->seq = seq;
	b->time = now;
	b->type = type;
	b->src_port = src_port;
	b->dst_port = dst_port;
	b->last_retry_request = 0;
	b->transmit_count = 0;

	return b;
}

static int server_insert_queue_packet(struct rist_flow *f, struct rist_peer *peer, size_t idx, const void *buf, size_t len, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	/*
		msg(f->server_id, f->client_id, RIST_LOG_INFO,
		"Inserting seq %"PRIu32" len %zu source_time %"PRIu32" at idx %zu\n",
			seq, len, source_time, idx);
	*/
	f->server_queue[idx] = rist_new_buffer(buf, len, RIST_PAYLOAD_TYPE_DATA_RAW, seq, source_time, src_port, dst_port);
	f->server_queue[idx]->peer = peer;
	if (RIST_UNLIKELY(!f->server_queue[idx])) {
		msg(f->server_id, f->client_id, RIST_LOG_ERROR, "[ERROR] Could not create packet buffer inside server buffer, OOM, decrease max bitrate or buffer time length\n");
		return -1;
	}
	f->server_queue_size += len;
	return 0;
}

static size_t rist_index_dec(struct rist_flow *f,size_t idx)
{
	if (!idx) {
		idx = f->server_queue_max;
	}
	return idx - 1;
}

static int check_valid_seq(struct rist_peer * peer, uint32_t seq)
{
	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;
	int ret = 0;
	return ret;
	// TODO: Is this entire test really worth it or are we better off letting anything in
	// and let the buffer reset when something goes wrong ...
	// What are the chances of an outlier vs a discontinuity? This test is only usefull
	// for outliers, i.e. perhaps data corruption?

	// TODO: Move this calculation to the peer initialization so that it does 
	// not happen for every packet
	// I could use RIST_MAX_PACKET_SIZE but the most likely scenario is 1300 bytes (double it)
	size_t packets_per_second = (peer->recover_maxbitrate * 1000000 / 8) / 1300;
	size_t max_packets = packets_per_second * peer->recover_buffer_ticks / RIST_CLOCK;

	// We base the server queue index only in the sequence number so we have to check
	// if the position makes sense (protect against discontinuities)
	// We still recover from discontinuities because when we reach an empty buffer
	// the output will reset its state to server_queue_has_items = false
	// This could be seq_output as well
	uint32_t max_seq = peer->flow->last_seq_found;
	uint32_t diff = 0;
	if (seq >= max_seq) {
		diff = seq - max_seq;
		if (diff > (UINT32_MAX / 2)) {
			diff = (UINT32_MAX - seq) + max_seq;
			msg(server_id, client_id, RIST_LOG_ERROR,
				"[ERROR] YELLOW %"PRIu32", %"PRIu32", %"PRIu32"\n", diff, seq, max_seq);
		}

	} else {
		diff = max_seq - seq;
		if (diff > (UINT32_MAX / 2)) {
			diff = (UINT32_MAX - max_seq) + seq;
			msg(server_id, client_id, RIST_LOG_ERROR,
				"[ERROR] GREEN %"PRIu32", %"PRIu32", %"PRIu32"\n", diff, seq, max_seq);
		}
	}
	if (diff > max_packets)
	{
		msg(server_id, client_id, RIST_LOG_ERROR,
				"[ERROR] The received sequence %"PRIu32" does not belong in this buffer, delta = %" PRIu32
					" > max_packets = %zu, max_seq %"PRIu32", discarding.\n",
			seq, diff, max_packets, max_seq);
		ret = -2;
	}
	else
	{
		//fprintf(stderr,"diff %"PRIu32"\n", diff);
	}
	
	return ret;
}

static int server_enqueue(struct rist_peer *peer, uint64_t source_time, const void *buf, size_t len, uint32_t seq, uint32_t rtt, bool retry, uint16_t src_port, uint16_t dst_port)
{
	struct rist_flow *f = peer->flow;

//	fprintf(stderr,"server enqueue seq is %"PRIu32", source_time %"PRIu64"\n", 
//	seq, source_time);

	if (!f->server_queue_has_items) {
		/* we just received our first packet for this flow */
		if (f->server_queue_size > 0)
		{
			/* Clear the queue if the queue had data */
			/* f->server_queue_has_items can be reset to false when the output queue is emptied */
			msg(f->server_id, f->client_id, RIST_LOG_INFO, 
				"[INFO] Clearing up old %zu bytes of old buffer data\n", f->server_queue_size);
			/* Delete all buffer data (if any) */
			empty_server_queue(f);
		}
		/* These are used for seq msw extrapolation */
		f->rtp_last_change_time = 0;
		f->rtp_msw = 0;
		/* Calculate and store clock offset with respect to source */
		f->time_offset = (int64_t)RIST_CLOCK + (int64_t)timestampNTP_u64() - (int64_t)source_time;
		/* This ensures the next packet does not trigger nacks */
		f->last_seq_output = seq - 1;
		f->last_seq_found = seq;
		/* This will synchronize idx and seq so we can insert packets into server buffer based on seq number */
		size_t idx_initial = seq % f->server_queue_max;
		f->server_queue_output_idx = idx_initial;
		msg(f->server_id, f->client_id, RIST_LOG_INFO,
			"[INIT] Storing first packet seq %"PRIu32", idx %zu, offset %"PRId64" ms\n", seq, idx_initial, peer->flow->time_offset/RIST_CLOCK);
		server_insert_queue_packet(f, peer, idx_initial, buf, len, seq, source_time, src_port, dst_port);
		/* reset stats */
		memset(&f->stats_instant, 0, sizeof(f->stats_instant));
		f->server_queue_has_items = true;
		return 0; // not a dupe
	}

	// Now, get the new position and check what is there
	size_t idx = seq % f->server_queue_max;
	int ret = check_valid_seq(peer, seq);
	if (ret < 0) {
		// seq too far from where we are in the buffer!
		msg(f->server_id, f->client_id, RIST_LOG_ERROR, "[ERROR] Invalid seq %"PRIu32" sent with DATA packet, discarding ...\n", seq);
		return 0;
	}
	else if (f->server_queue[idx]) {
		// TODO: record stats
		struct rist_buffer *b = f->server_queue[idx];
		if (b->seq == seq) {
			msg(f->server_id, f->client_id, RIST_LOG_ERROR, "Dupe! %"PRIu32"/%zu\n", seq, idx);
			peer->stats_server_instant.dups++;
			return 1;
		}
		else {
			msg(f->server_id, f->client_id, RIST_LOG_ERROR, "Invalid Dupe (possible seq discontinuity)! %"PRIu32", freeing buffer ...\n", seq);
			free(b->data);
			free(b);
			f->server_queue[idx] = NULL;
		}
	}

	/* Now, we insert the packet into server queue */
	if (server_insert_queue_packet(f, peer, idx, buf, len, seq, source_time, src_port, dst_port)) {
		// only error is OOM, safe to exit here ...
		return 0;
	}

	// Check for missing data and queue retries
	if (!retry) {
		uint32_t current_seq = seq - 1;
		if (f->short_seq)
			current_seq = (uint16_t)current_seq;

		// We would just need to check if the current_seq is larger than the last_seq_found and
		// not too far from it.
		// However, because of the 32 bit wrap-around this becomes a complex mathematical problem.
		// What we do is always assume it is is ahead (even when it is less) and calculate
		// the distance to it. Then, we make sure it is not too far (the ones that are less
		// will automatically be very far, almost UINT32_MAX far) and skip it if it is ...
		uint32_t diff = 0;
		if (current_seq >= f->last_seq_found) {
			diff = current_seq - f->last_seq_found;
		} else {
			if (!f->short_seq)
				diff = (UINT32_MAX - f->last_seq_found) + current_seq;
			else
				diff = (UINT16_MAX - f->last_seq_found) + current_seq;
		}
		if (diff > peer->missing_counter_max) {
			msg(f->server_id, f->client_id, RIST_LOG_ERROR,
				"[ERROR] Received sequence %"PRIu32" is too far from last missing seq index %"PRIu32" > %"PRIu32", (%"PRIu32"/%"PRIu32")\n", 
				current_seq, diff, peer->missing_counter_max,
				f->last_seq_found, f->last_seq_output);
			// Detect and correct discontinuties in seq by resetting the last_seq_found when it is
			// too far from last_seq_output
			uint32_t diff2 = 0;
			if (f->last_seq_found >= f->last_seq_output) {
				diff2 = f->last_seq_found - f->last_seq_output;
			} else {
				if (!f->short_seq)
					diff2 = (UINT32_MAX - f->last_seq_found) + f->last_seq_output;
				else
					diff2 = (UINT16_MAX - f->last_seq_found) + f->last_seq_output;				
			}
			// TODO: should we use a different/faster criteria?
			if (diff2 > peer->missing_counter_max) {
				msg(f->server_id, f->client_id, RIST_LOG_ERROR,
					"[ERROR] Our output index %"PRIu32" and missing search index %"PRIu32" are too far from each other (%"PRIu32"), resetting the missing seach index\n",
					f->last_seq_output, f->last_seq_found, diff2);
				f->last_seq_found = seq;
			}
			return 0;
		}

		/* check for missing packets */
		// We start looking at the point of this insert and work our way backwards until we reach
		// the last checkpoint (seq #). Any holes encountered are queued in missing array.
		size_t current_idx = rist_index_dec(f, idx);
		struct rist_buffer *b = f->server_queue[current_idx];
		while (!b || f->last_seq_found != current_seq) {
			if (f->missing_counter > peer->missing_counter_max) {
				msg(f->server_id, f->client_id, RIST_LOG_ERROR,
					"[ERROR] Retry buffer is already too large (%d) for the configured "
							"bandwidth ... ignoring missing packet(s).\n",
					f->missing_counter);
				break;
			} else if (!b) {
				if (!peer->bufferbloat_active) {
					rist_server_missing(f, peer, current_seq, rtt);
				} else {
					msg(f->server_id, f->client_id, RIST_LOG_ERROR,
						"[ERROR] Link has collapsed. Not queuing new retries until it recovers.\n");
					break;
				}
			}
			current_seq--;
			if (f->short_seq)
				current_seq = (uint16_t)current_seq;
			current_idx = rist_index_dec(f, current_idx);
			b = f->server_queue[current_idx];
			if (current_idx == idx) {
				msg(f->server_id, f->client_id, RIST_LOG_ERROR, "[ERROR] Did not find any data after a full counter loop (missing loop) (%zu)\n", f->server_queue_size);
				// if the entire buffer is empty, something is very wrong ....
				break;
			}
		}
		// TODO: when we break on the conditions above, will setting this value "mess-up" the index?
		f->last_seq_found = seq;
	}
	return 0;
}

static inline void peer_append(struct rist_peer *p)
{
	struct rist_peer **PEERS = &get_cctx(p)->PEERS;
	pthread_rwlock_t *peerlist_lock = &get_cctx(p)->peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	struct rist_peer *plist = *PEERS;
	if (!plist) {
		*PEERS = p;
		pthread_rwlock_unlock(peerlist_lock);
		return;
	}
	while (plist) {
		if (!plist->next) {
			p->prev = plist;
			plist->next = p;
			pthread_rwlock_unlock(peerlist_lock);
			return;
		}
		plist = plist->next;
	}
	pthread_rwlock_unlock(peerlist_lock);
}

static int rist_process_nack(struct rist_flow *f, struct rist_missing_buffer *b)
{
	uint64_t now = timestampNTP_u64();
	struct rist_peer *peer = b->peer;

	if (check_valid_seq(peer, b->seq) < 0) {
		/* too late for this block, drop it */
		msg(f->server_id, f->client_id, RIST_LOG_ERROR, 
		"[ERROR] Datagram %"PRIu32" is missing but we cannot send the NACK (%d), age is %"PRIu64"ms\n",
		b->seq, f->last_seq_output, f->missing_counter,
		(now - b->insertion_time) / RIST_CLOCK);
		return 7;
	} else if (b->nack_count >= peer->bufferbloat_hard_limit) {
		msg(f->server_id, f->client_id, RIST_LOG_ERROR, "[ERROR] Datagram %"PRIu32
				" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu, bufferbloat_hard_limit %d, bufferbloat_mode %d, stats_server_total.recovered_average %d\n",
					b->seq,
					b->nack_count,
					(now - b->insertion_time) / RIST_CLOCK,
					b->nack_count,
					peer->bufferbloat_hard_limit,
					peer->bufferbloat_mode,
					peer->stats_server_total.recovered_average);
		return 8;
	} else {
		if ((uint64_t)(now - b->insertion_time) > peer->recover_buffer_ticks) {
			msg(f->server_id, f->client_id, RIST_LOG_ERROR,
				"[ERROR] Datagram %" PRIu32 " is missing but it is too late (%" PRIu64
				"ms) to send NACK!, retry #%lu, retry queue %d, max time %"PRIu64"\n",
				b->seq, (now - b->insertion_time)/RIST_CLOCK, b->nack_count,
				f->missing_counter, peer->recover_buffer_ticks / RIST_CLOCK);
			return 9;
		} else if (now >= b->next_nack) {
			uint64_t rtt = (peer->eight_times_rtt / 8);
			if (rtt < peer->recover_rtt_min) {
				rtt = peer->recover_rtt_min;
			} else if (rtt > peer->recover_rtt_max) {
				rtt = peer->recover_rtt_max;
			}

			// TODO: make this 10% overhead configurable?
			// retry more when we are running out of time (proportional)
			/* start with 1.1 * 1000 and go down from there */
			//uint32_t ratio = 1100 - (b->nack_count * 1100)/(2*b->peer->bufferbloat_hard_limit);
			//b->next_nack = now + (uint64_t)rtt * (uint64_t)ratio * (uint64_t)RIST_CLOCK;
			b->next_nack = now + ((uint64_t)rtt * (uint64_t)1100 * (uint64_t)RIST_CLOCK) / 1000;
			b->nack_count++;

			if (get_cctx(peer)->debug)
				msg(f->server_id, f->client_id, RIST_LOG_DEBUG, "[DEBUG] Datagram %"PRIu32
					" is missing, sending NACK!, next retry in %"PRIu64"ms, age is %"PRIu64"ms, retry #%lu, max_size is %"PRIu64"ms\n",
					b->seq, (b->next_nack - now) / RIST_CLOCK,
					(now - b->insertion_time) / RIST_CLOCK,
					b->nack_count,
					peer->recover_buffer_ticks / RIST_CLOCK);

			// update peer information
			peer->nacks.array[peer->nacks.counter] = b->seq;
			peer->nacks.counter ++;
			peer->stats_server_instant.retries++;
		}
	}

	return 0;
}

static void server_output(struct rist_server *ctx, struct rist_flow *f)
{

	uint64_t recover_buffer_ticks = f->recover_buffer_ticks;
	while (f->server_queue_size > 0) {
		// Find the first non-null packet in the queuecounter loop
		struct rist_buffer *b = f->server_queue[f->server_queue_output_idx];
		if (!b) {
			//msg(ctx->id, 0, RIST_LOG_ERROR, "\tLooking for first non-null packet (%zu)\n", f->server_queue_size);
			size_t holes = 0;
			size_t counter = 0;
			counter = f->server_queue_output_idx;
			while (!b) {
				counter = (counter + 1) % f->server_queue_max;
				holes++;
				b = f->server_queue[counter];
				if (counter == f->server_queue_output_idx) {
					// TODO: with the check below, this should never happen
					msg(ctx->id, 0, RIST_LOG_WARN, "[ERROR] Did not find any data after a full counter loop (%zu)\n", f->server_queue_size);
					// if the entire buffer is empty, something is very wrong, reset the queue ...
					f->server_queue_has_items = false;
					// exit the function and wait 5ms (max jitter time)
					return;
				}
				if (holes > f->missing_counter_max)
				{
					msg(ctx->id, 0, RIST_LOG_WARN, "[ERROR] Did not find any data after %zu holes (%zu bytes in queue)\n",
						holes, f->server_queue_size);
					break;
				}
			}
			f->stats_instant.lost += holes;
			f->server_queue_output_idx = counter;
			msg(ctx->id, 0, RIST_LOG_ERROR,
				"**** [LOST] Empty buffer element, flushing %"PRIu32" hole(s), now at index %zu, size is %zu\n", 
				holes, counter, f->server_queue_size);
		}
		if (b) {

			uint64_t now = timestampNTP_u64();
			if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {

				uint64_t delay = (now - b->time);
				int64_t target_time = (int64_t)b->source_time + f->time_offset;
				uint64_t delay_rtc = now > (uint64_t)target_time ? (now - (uint64_t)target_time) : 0;

				// Warning for a possible timing bug (the source has an improperly scaled timestamp)
				if ((delay * 10) < recover_buffer_ticks)
				{
					// TODO: quiet this down based on some other parameter that measures proper behavior,
					// i.e. buffer filling up after it has been initialized. Perhaps print them
					// only after one buffer length post flow initialization
					msg(ctx->id, 0, RIST_LOG_WARN,
						"**** [WARNING] Packet %"PRIu32" is too young %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", is buffer building up?\n",
						b->seq, delay / RIST_CLOCK, delay_rtc / RIST_CLOCK, recover_buffer_ticks / RIST_CLOCK);
				}
				//else
				//	msg(ctx->id, 0, RIST_LOG_WARN,
				//		"**** [WARNING] Packet %"PRIu32" is ok %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", is buffer building up?\n",
				//		b->seq, delay / RIST_CLOCK, delay_rtc / RIST_CLOCK, recover_buffer_ticks / RIST_CLOCK);

				if (RIST_UNLIKELY(delay > (2 * recover_buffer_ticks))) {
					// Double check the age of the packet within our server queue and empty if necessary
					// Safety net for discontinuities in source timestamp or sequence numbers
					msg(ctx->id, 0, RIST_LOG_WARN,
						"**** [WARNING] Packet %"PRIu32" (%zu bytes) is too old %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", offset = %"PRId64" ms, releasing from output queue ...\n",
						b->seq, b->size, delay / RIST_CLOCK, delay_rtc / RIST_CLOCK, recover_buffer_ticks / RIST_CLOCK, f->time_offset / RIST_CLOCK);
				}
				else if (delay_rtc <= recover_buffer_ticks) {
					// This is how we keep the buffer at the correct level
					//msg(ctx->id, 0, RIST_LOG_WARN, "age is %"PRIu64"/%"PRIu64" < %"PRIu64", size %zu\n", 
					//	delay_rtc / RIST_CLOCK , delay / RIST_CLOCK, recover_buffer_ticks / RIST_CLOCK, f->server_queue_size);
					break;
				}

				// Check sequence number and report lost packet
				uint32_t next_seq = f->last_seq_output + 1;
				if (f->short_seq)
					next_seq = (uint16_t)next_seq;
				if (b->seq != next_seq) {
					msg(ctx->id, 0, RIST_LOG_ERROR,
						"**** [LOST] Expected %" PRIu32 " got %" PRIu32 "\n",
						f->last_seq_output + 1, b->seq);
					f->stats_instant.lost++;
				}
				if (ctx->server_receive_callback && b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {
					uint8_t *payload = b->data;
					ctx->server_receive_callback(ctx->server_receive_callback_argument, b->peer, f->flow_id, &payload[RIST_MAX_PAYLOAD_OFFSET], b->size, b->src_port, b->dst_port);
				}
			}
			//else
			//	fprintf(stderr, "rtcp skip at %"PRIu32", just removing it from queue\n", b->seq);

			f->last_seq_output = b->seq;
			f->server_queue_size -= b->size;
			f->server_queue[f->server_queue_output_idx] = NULL;
			f->server_queue_output_idx = (f->server_queue_output_idx + 1) % f->server_queue_max;
			if (b->size)
				free(b->data);
			free(b);
			if (f->server_queue_size == 0) {
				uint64_t delta = now - f->last_output_time;
				msg(ctx->id, 0, RIST_LOG_WARN, "[WARNING] Buffer is empty, it has been for %"PRIu64" < %"PRIu64" (ms)!\n",
				delta / RIST_CLOCK, recover_buffer_ticks / RIST_CLOCK);
				// if the entire buffer is empty, something is very wrong, reset the queue ...
				if (delta > recover_buffer_ticks)
				{
					msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] stream is dead, re-initializing flow\n");
					f->server_queue_has_items = false;
				}
				// exit the function and wait 5ms (max jitter time)
				return;
			}
			f->last_output_time = now;
		}
	}
}

static void send_nack_group(struct rist_server *ctx, struct rist_flow *f, struct rist_peer *peer)
{
	// Now actually send all the nack IP packets for this flow (the above routing will process/group them)
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	rist_send_nacks(f, peer);
	pthread_rwlock_unlock(peerlist_lock);
	// TODO: this lock should be by flow ... not global!
}

void server_nack_output(struct rist_server *ctx, struct rist_flow *f)
{

	if (!f->authenticated) {
		return;
	}

	int maxcounter = RIST_MAX_NACKS;

	/* Now loop through missing queue and process items */
	struct rist_missing_buffer *mb = f->missing;
	struct rist_missing_buffer **prev = &f->missing;
	int empty = 0;
	uint32_t seq_msb = 0;
	if (mb)
		seq_msb = mb->seq >> 16;

	while (mb) {
		int remove_from_queue_reason = 0;
		struct rist_peer *peer = mb->peer;
		ssize_t idx = mb->seq % f->server_queue_max;
		if (f->server_queue[idx]) {
			if (f->server_queue[idx]->seq == mb->seq) {
				// We filled in the hole already ... packet has been recovered
				remove_from_queue_reason = 3;
				peer->stats_server_instant.recovered++;
				switch(mb->nack_count) {
				case 0:
					peer->stats_server_instant.reordered++;
				break;
				case 1:
					peer->stats_server_instant.recovered_0nack++;
				break;
				case 2:
					peer->stats_server_instant.recovered_1nack++;
				break;
				case 3:
					peer->stats_server_instant.recovered_2nack++;
				break;
				case 4:
					peer->stats_server_instant.recovered_3nack++;
				break;
				default:
					peer->stats_server_instant.recovered_morenack++;
				break;
				}
				peer->stats_server_instant.recovered_sum += mb->nack_count;
			}
			else {
				// Message with wrong seq!!!
				msg(ctx->id, 0, RIST_LOG_ERROR,
					"[ERROR] Retry queue has the wrong seq %"PRIu32" != %"PRIu32", removing ...\n", 
					f->server_queue[idx]->seq, mb->seq);
				remove_from_queue_reason = 4;
				peer->stats_server_instant.missing--;
				goto nack_loop_continue;
			}
		} else if (peer->bufferbloat_active) {
			if (peer->bufferbloat_mode == RIST_BUFFER_BLOAT_MODE_AGGRESSIVE) {
				if (empty == 0) {
					msg(ctx->id, 0, RIST_LOG_ERROR,
						"[ERROR] Retry queue is too large, %d, collapsed link (%u), flushing all nacks ...\n", f->missing_counter,
						peer->stats_server_total.recovered_average/8);
				}
				remove_from_queue_reason = 5;
				empty = 1;
			} else if (peer->bufferbloat_mode == RIST_BUFFER_BLOAT_MODE_NORMAL) {
				if (mb->nack_count > 4) {
					if (empty == 0) {
						msg(ctx->id, 0, RIST_LOG_ERROR,
							"[ERROR] Retry queue is too large, %d, collapsed link (%u), flushing old nacks (%u > %u) ...\n",
								f->missing_counter, peer->stats_server_total.recovered_average/8, mb->nack_count, 4);
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
					msg(ctx->id, 0, RIST_LOG_DEBUG,
						"[DEBUG] seq-msb changed from %"PRIu32" to %"PRIu32" (%"PRIu32", %zu, %"PRIu32")\n", 
						seq_msb, mb->seq >> 16, mb->seq, mb->peer->nacks.counter,
						f->missing_counter);
				send_nack_group(ctx, f, NULL);
			}
			else if (mb->peer->nacks.counter == (maxcounter - 1)) {
				msg(ctx->id, 0, RIST_LOG_ERROR,
					"[ERROR] nack max counter per packet (%d) exceeded. Skipping the rest\n",
						maxcounter);
				send_nack_group(ctx, f, mb->peer);
			}
			else if (mb->peer->nacks.counter >= maxcounter) {
				msg(ctx->id, 0, RIST_LOG_ERROR,
					"[ERROR] nack max counter per packet (%zu) exceeded. Something is very wrong and"
					" there is a strong chance memory is corrupt because we wrote past the end"
					"of the nacks.array max size!!!\n", mb->peer->nacks.counter );
				mb->peer->nacks.counter = 0;
				//TODO: maybe assert is more appropriate here?
			}
			remove_from_queue_reason = rist_process_nack(f, mb);
		}
nack_loop_continue:
		if (remove_from_queue_reason != 0) {
			if (ctx->common.debug)
				msg(ctx->id, 0, RIST_LOG_DEBUG,
					"[DEBUG] Removing seq %" PRIu32 " from missing, queue size is %d, retry #%u, age %"PRIu64"ms, reason %d\n",
					mb->seq, f->missing_counter, mb->nack_count, (timestampNTP_u64() - mb->insertion_time) / RIST_CLOCK, remove_from_queue_reason);
			struct rist_missing_buffer *next = mb->next;
			*prev = next;
			free(mb);
			mb = next;
			f->missing_counter--;
		} else {
			/* Move it to the end of the queue */
			// TODO: I think this is wrong and we loose nacks when we get here
			prev = &mb->next;
			mb = mb->next;
		}
	}

	// Empty all peer nack queues, i.e. send them
	send_nack_group(ctx, f, NULL);

}

static struct rist_peer *rist_server_add_peer_local(struct rist_server *ctx, const char *url)
{
	/* Initialize peer */
	struct rist_peer *p = peer_initialize(url, NULL, NULL, ctx);
	if (!p) {
		return NULL;
	}

	/* Initialize socket */
	rist_create_socket(p);
	if (p->sd <= 0) {
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create socket\n");
		free(p);
		return NULL;
	}

	if (!p->listening)
		p->adv_peer_id = ++ctx->common.peer_counter;

	return p;
}

int rist_server_add_peer(struct rist_server *ctx, const char *url)
{
	struct rist_peer *p_rtcp;
	struct rist_peer *p = rist_server_add_peer_local(ctx, url);
	if (!p)
		return -1;

	if (ctx->common.profile == RIST_SIMPLE)
	{
		if (p->local_port % 2 != 0) {
			// TODO: remove peer from timer
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create peer, port must be even!\n");
			udp_Close(p->sd);
			free(p);
			return -1;
		}

		char new_url[500];
		sprintf(new_url, "%s:%d", p->url, p->local_port + 1); 
		p_rtcp = rist_server_add_peer_local(ctx, new_url);
		if (!p_rtcp)
		{
			// TODO: remove peer from timer
			udp_Close(p->sd);
			free(p);
			return -1;
		}
		p_rtcp->is_rtcp = true;
		msg(ctx->id, 0, RIST_LOG_INFO, "[INFO] Created RTCP peer: host %s, port %d, new_url %s, %"PRIu32"\n", p->url, p->local_port, new_url, p->adv_peer_id);
		peer_append(p_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(p_rtcp);
	}
	else {
		p->is_rtcp = true;
	}

	p->is_data = true;
	peer_append(p);
	/* jumpstart communication */
	rist_fsm_init_comm(p);

	return 0;
}

/* PEERS are created at startup. The default state is RIST_PEER_STATE_IDLE
 * This function will initiate the connection to the peer if a peer address is available.
 * If no address is configured for the endpoint, the peer is put in wait mode.
 */
static void rist_fsm_init_comm(struct rist_peer *peer)
{
	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;

	peer->state_peer = RIST_PEER_STATE_PING;

	if (!peer->server_mode) {
		if (peer->listening) {
			/* client mode listening/waiting for server */
			msg(server_id, client_id, RIST_LOG_INFO,
				"[INIT] Initialized Client Peer, listening mode ...\n");
		} else {
			/* client mode connecting to server */
			msg(server_id, client_id, RIST_LOG_INFO,
				"[INIT] Initialized Client Peer, connecting to server ...\n");
		}
	} else {
		if (peer->listening) {
			/* server mode listening/waiting for client */
			msg(server_id, client_id, RIST_LOG_INFO,
				"[INIT] Initialized Server Peer, listening mode ...\n");
		} else {
			/* server mode connecting to client */
			msg(server_id, client_id, RIST_LOG_INFO,
				"[INIT] Initialized Server Peer, connecting to client ...\n");
		}
	}
	peer->state_local = RIST_PEER_STATE_PING;
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
			msg(server_id, client_id, RIST_LOG_INFO, "[INIT] Enabling keepalive\n");
			peer->send_keepalive = true;
		}

		/* call it the first time manually to speed up the handshake */
		rist_peer_rtcp(NULL, peer);
	}
}

void rist_shutdown_peer(struct rist_peer *peer)
{
	// TODO: this function is incomplete ...

	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;

	msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Shutting down peer\n");
	peer->sd = -1;
	peer->state_local = RIST_PEER_STATE_IDLE;
	peer->state_peer = RIST_PEER_STATE_IDLE;
	peer->retries = 0;
	struct evsocket_ctx *evctx = get_cctx(peer)->evctx;
	if (peer->event_recv) {
		evsocket_delevent(evctx, peer->event_recv);
		peer->event_recv = NULL;
	}

	if (peer->send_keepalive) {
		peer->send_keepalive = false;
	}
	// TODO: remove from the peer list and from the flow list
	// TODO: delete peer and or flow and other timers?
}

void rist_fsm_recv_connect(struct rist_peer *peer)
{
	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;

	peer->state_peer = RIST_PEER_STATE_CONNECT;
	peer->state_local = RIST_PEER_STATE_CONNECT;

	msg(server_id, client_id, RIST_LOG_INFO,
		"[INIT] Successfully authenticated to peer %"PRIu32", peer/local (%d/%d)\n",
		peer->adv_peer_id, peer->state_peer, peer->state_local);
}

void rist_calculate_bitrate(struct rist_peer *peer, size_t len, struct rist_bandwidth_estimation *bw)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = tv.tv_sec * 1000000;
	now += tv.tv_usec;
	uint64_t time = now - bw->last_bitrate_calctime;

	if (!bw->last_bitrate_calctime) {
		bw->last_bitrate_calctime = now;
		bw->eight_times_bitrate = 0;
		bw->bytes = 0;
		return;
	}

	if (peer->flow) {
		struct rist_flow *f = peer->flow;
		if (f->last_ipstats_time == 0ULL) {
			// Initial values
			f->stats_instant.cur_ips = 0ULL;
			f->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;
			f->stats_instant.max_ips = 0ULL;
			f->stats_instant.avg_count = 0UL;
			f->stats_total.cur_ips = 0ULL;
			f->stats_total.min_ips = 0xFFFFFFFFFFFFFFFFULL;
			f->stats_total.max_ips = 0ULL;
			f->stats_total.avg_count = 0UL;
		} else {
			f->stats_instant.cur_ips = now - f->last_ipstats_time;
			/* Set new min */
			if (f->stats_instant.cur_ips < f->stats_instant.min_ips)
				f->stats_instant.min_ips = f->stats_instant.cur_ips;
			/* Set new max */
			if (f->stats_instant.cur_ips > f->stats_instant.max_ips)
				f->stats_instant.max_ips = f->stats_instant.cur_ips;

			/* Avg calculation */
			f->stats_instant.total_ips += f->stats_instant.cur_ips;
			f->stats_total.total_ips += f->stats_instant.cur_ips;
			f->stats_instant.avg_count++;
			f->stats_total.avg_count++;
		}
		f->last_ipstats_time = now;
	}

	if (time < 1000000 /* 1 second */) {
		bw->bytes += len;
		return;
	}

	bw->bitrate = (8 * bw->bytes * 1000000) / time;
	bw->eight_times_bitrate = bw->bitrate + bw->eight_times_bitrate - bw->eight_times_bitrate / 8;
	bw->last_bitrate_calctime = now;

	bw->bytes = 0;
}

void rist_calculate_bitrate_client(size_t len, struct rist_bandwidth_estimation *bw)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = tv.tv_sec * 1000000;
	now += tv.tv_usec;
	uint64_t time = now - bw->last_bitrate_calctime;

	if (bw->last_bitrate_calctime == 0) {
		bw->last_bitrate_calctime = now;
		bw->bitrate = 0;
		bw->bytes = 0;
		return;
	}

	if (time < 1000000 /* 1000 miliseconds */) {
		bw->bytes += len;
		return;
	}

	bw->bitrate = (8 * bw->bytes * 1000000) / time;
	bw->eight_times_bitrate = 8 * bw->bitrate;
	bw->last_bitrate_calctime = now;
	bw->bytes = 0;
}

static void rist_client_recv_nack(struct rist_peer *peer,
		uint32_t flow_id, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, 
		size_t payload_len, uint32_t nack_seq_msb)
{
	intptr_t client_id = peer->client_ctx->id;

	if (peer->server_mode) {
		msg(0, client_id, RIST_LOG_ERROR,
			"[ERROR] Received nack packet on server, ignoring ...\n");
		return;
	} else if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {
		msg(0, client_id, RIST_LOG_ERROR,
			"[ERROR] Received nack packet but handshake is still pending, ignoring ...\n");
		return;
	}

	struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *) payload;
	uint32_t i,j;

	if ((rtcp->flags & 0xc0) != 0x80) {
		msg(0, client_id, RIST_LOG_ERROR, "[ERROR] Malformed nack packet flags=%d.\n", rtcp->flags);
		return;
	}

	if (rtcp->ptype == PTYPE_NACK_CUSTOM) {
		struct rist_rtcp_nack_range *rtcp_nack = (struct rist_rtcp_nack_range *) payload;
		if (memcmp(rtcp_nack->name, "RIST", 4) != 0) {
			msg(0, client_id, RIST_LOG_ERROR, "[NACK] Non-Rist nack packet (%s).\n", rtcp_nack->name);
			return; /* Ignore app-type not RIST */
		}
		uint16_t nrecords =	nrecords = ntohs(rtcp->len) - 2;
		//msg(0, client_id, RIST_LOG_ERROR, "[ERROR] Nack (RbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t additional;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_range) + i * sizeof(struct rist_rtp_nack_record));
			missing =  ntohs(nr->start);
			additional = ntohs(nr->extra);
			rist_retry_enqueue(peer->client_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//msg(0, client_id, RIST_LOG_ERROR, "[ERROR] Record %"PRIu32": base packet: %"PRIu32" range len: %d\n", i, nack_seq_msb + missing, additional);
			for (j = 0; j < additional; j++) {
				rist_retry_enqueue(peer->client_ctx, nack_seq_msb + (uint32_t)missing + j + 1, peer);
			}
		}
	} else if (rtcp->ptype == PTYPE_NACK_BITMASK) {
		struct rist_rtcp_nack_bitmask *rtcp_nack = (struct rist_rtcp_nack_bitmask *) payload;
		(void)rtcp_nack;
		uint16_t nrecords =	nrecords = ntohs(rtcp->len) - 2;
		//msg(0, client_id, RIST_LOG_ERROR, "[ERROR] Nack (BbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t bitmask;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_bitmask) + i * sizeof(struct rist_rtp_nack_record));
			missing = ntohs(nr->start);
			bitmask = ntohs(nr->extra);
			rist_retry_enqueue(peer->client_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//msg(0, client_id, RIST_LOG_ERROR, "[ERROR] Record %"PRIu32": base packet: %"PRIu32" bitmask: %04x\n", i, nack_seq_msb + missing, bitmask);
			for (j = 0; j < 16; j++) {
				if ((bitmask & (1 << j)) == (1 << j))
					rist_retry_enqueue(peer->client_ctx, nack_seq_msb + missing + j + 1, peer);
			}
		}
	} else {
		msg(0, client_id, RIST_LOG_ERROR, "[ERROR] Unsupported Type %d\n", rtcp->ptype);
	}

}

static struct rist_peer *rist_find_rtcp_peer(struct rist_server *ctx, struct rist_flow *f, uint16_t data_port)
{
	uint16_t rtcp_port = data_port + 1;
	for (size_t i = 0; i < f->peer_lst_len; i++) {
		if (!f->peer_lst[i]->is_rtcp)
			continue;
		if (rtcp_port == f->peer_lst[i]->local_port) {
			return f->peer_lst[i];
		}
	}
	return NULL;
}

static bool rist_server_authenticate(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, struct rist_buffer *payload)
{
	struct rist_server *ctx = peer->server_ctx;

	if (peer->recovery_mode == RIST_RECOVERY_MODE_UNCONFIGURED)
	{
		// TODO: get the settings from the flow itself when in basic profile
		// Transfer default values into peer
		const struct rist_settings peer_config = {
			.recovery_mode = ctx->recovery_mode,
			.recover_maxbitrate = ctx->recovery_maxbitrate,
			.recover_maxbitrate_return = ctx->recovery_maxbitrate_return,
			.recover_buffer_min = ctx->recovery_length_min,
			.recover_buffer_max = ctx->recovery_length_max,
			.recover_reorder_buffer = ctx->recovery_reorder_buffer,
			.recover_rtt_min = ctx->recovery_rtt_min,
			.recover_rtt_max = ctx->recovery_rtt_max,
			.bufferbloat_mode = ctx->bufferbloat_mode,
			.bufferbloat_limit = ctx->bufferbloat_limit,
			.bufferbloat_hard_limit = ctx->bufferbloat_hard_limit
		};
		// TODO: copy settings from special rtcp packet if it exists
		server_store_settings(peer, &peer_config);
	}

	// Check to see if this peer's flowid changed
	// (client was restarted and we are in callback mode or client happened to reuse the same port)
	if (peer->flow && (flow_id != peer->flow->flow_id)) {
		msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Updating peer's flowid %"PRIu32"->%"PRIu32" (%zu)\n", peer->flow->flow_id, flow_id, peer->flow->peer_lst_len);
		if (peer->flow->peer_lst_len > 1) {
			// Remove it from the old flow list but leave the flow intact
			uint32_t i = 0;
			for (size_t j = 0; j < peer->flow->peer_lst_len; j++) {
				if (peer->flow->peer_lst[j] == peer) {
					msg(ctx->id, 0, RIST_LOG_INFO,
						"[INIT] Removing peer from old flow (%"PRIu32")\n",
						peer->flow->flow_id);
				} else {
					i++;
				}
				peer->flow->peer_lst[i] = peer->flow->peer_lst[j];
			}
			peer->flow->peer_lst = realloc(peer->flow->peer_lst,
				(peer->flow->peer_lst_len - 1) * sizeof(*peer->flow->peer_lst));
			peer->flow->peer_lst_len--;
		}
		else {
			// Delete the flow and all of its resources
			msg(ctx->id, 0, RIST_LOG_INFO,
				"[INIT] Old flow (%"PRIu32") has no peers left, deleting ...\n", peer->flow->flow_id);
			rist_delete_flow(ctx, peer->flow);
			msg(ctx->id, 0, RIST_LOG_INFO,
				"[INIT] Old flow deletion complete\n");
		}
		// Reset the peer parameters
		peer->state_local = peer->state_peer = RIST_PEER_STATE_PING;
		peer->recovery_mode = RIST_RECOVERY_MODE_UNCONFIGURED;
		peer->flow = NULL;
	}

	if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {

		// the peer could already be part of a flow and it came back after timing out
		if (!peer->flow) {
			if (rist_server_associate_flow(peer, flow_id) != 1) {
				msg(ctx->id, 0, RIST_LOG_ERROR,
					"[ERROR] Could not created/associate peer to flow.\n");
				return false;
			}
		}

		if (peer->flow) {
			// We do multiple ifs to make these checks stateless
			if (!peer->flow->server_thread) {
				// Make sure this data out thread is created only once per flow
				if (pthread_create(&(peer->flow->server_thread), NULL, server_pthread_dataout, (void *)peer->flow) != 0) {
					msg(ctx->id, 0, RIST_LOG_ERROR,
						"[ERROR] Could not created server data output thread.\n");
					return false;
				}
			}

			if (payload->type == RIST_PAYLOAD_TYPE_DATA_RAW) {
				if (peer->flow->authenticated) {
					// This path is only taken by simple profile data peer
					peer->peer_rtcp = rist_find_rtcp_peer(ctx, peer->flow, peer->local_port);
					rist_fsm_recv_connect(peer);
				} else
					msg(ctx->id, 0, RIST_LOG_WARN,
						"[WARNING] Flow %"PRIu32" has not yet been authenticated by an RTCP peer!\n", flow_id);
			}
			else {
				// Only RTCP messages can authenticate a stream ...
				if (strlen(peer->receiver_name)) {
					if (ctx->common.profile > RIST_SIMPLE)
						peer->peer_rtcp = peer;
					rist_fsm_recv_connect(peer);
					peer->flow->authenticated = true;
					msg(ctx->id, 0, RIST_LOG_INFO,
						"[INFO] Authenticated peer %d and flow %"PRIu32" for connection with cname: %s\n", 
							peer->adv_peer_id, peer->adv_flow_id,
							peer->receiver_name);
				}
				else {
					msg(ctx->id, 0, RIST_LOG_ERROR,
						"[ERROR] RTCP message does not have a cname, we cannot authenticate/allow this flow!\n");
				}
			}
		}
	}

	// The flow is added after we completed authentication
	if (peer->flow) {
		peer->flow->stats_total.last_recv_ts = timestampNTP_u64();
		return true;
	}
	else
	{
		return false;
	}
}

static void rist_server_recv_data(struct rist_peer *peer, uint32_t seq, uint32_t flow_id,
		uint64_t source_time, struct rist_buffer *payload, bool retry)
{
	struct rist_server *ctx = peer->server_ctx;

	if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {
		if (!rist_server_authenticate(peer, seq, flow_id, payload)) {
			msg(ctx->id, 0, RIST_LOG_WARN,
				"[WARNING] Received data packet but handshake is still pending, ignoring ...\n");
			return;
		}
	} 

	if (peer->retries > 0) {
		msg(ctx->id, 0, RIST_LOG_WARN,
			"[WARNING] Received data packet but passphrase is wrong for this peer (%d), ignoring ...\n",
			peer->adv_peer_id);
		return;
	} else if (peer->recovery_mode == RIST_RECOVERY_MODE_UNCONFIGURED) {
		msg(ctx->id, 0, RIST_LOG_WARN,
			"[WARNING] Received data packet but no settings have been received for this peer (%d), ignoring ...\n",
			peer->adv_peer_id);
		return;
	} else if (!peer->flow) {
		msg(ctx->id, 0, RIST_LOG_WARN,
			"[WARNING] Received data packet but this peer (%d) is not associated with a flow, ignoring ...\n",
			peer->adv_peer_id);
		return;
	} else if (!peer->peer_rtcp) {
		msg(ctx->id, 0, RIST_LOG_WARN,
			"[WARNING] Received data packet but this peer (%d) does not have an associated rtcp channel, ignoring ...\n",
			peer->adv_peer_id);
		return;
	}

	//msg(ctx->id, 0, RIST_LOG_ERROR,
	//	"[DEBUG] rist_recv_data, seq %"PRIu32"\n", seq);

	/* Decompress payload */
	// TODO: restore compression
	//if ((hdr->rtp.flags & 0x0F) == RIST_PAYLOAD_TYPE_DATA_LZ4) {
	if (0) {
		int dlen;
		void *dbuf = get_cctx(peer)->buf.dec;

		dlen = LZ4_decompress_safe((const void *) payload->data, dbuf, payload->size, RIST_MAX_PACKET_SIZE);
		if (dlen < 0) {
			msg(ctx->id, 0, RIST_LOG_ERROR,
				"[ERROR] Could not decompress data packet (%d), ignoring ...\n", dlen);
			return;
		}

		// msg(server_id, 0, DEBUG,
		//      "decompressed %d to %lu\n",
		//      payload_len, decompressed_len);
		payload->size = dlen;
		payload->data = dbuf;
	}

//	Just some debug output
//	if ((seq - peer->flow->last_seq_output) != 1)
//		msg(server_id, client_id, RIST_LOG_ERROR, "Received seq %"PRIu32" and last %"PRIu32"\n\n\n", seq, peer->flow->last_seq_output);

	/**************** WIP *****************/
	/* * * * * * * * * * * * * * * * * * * */
	/** Heuristics for receiver  * * * * * */
	/* * * * * * * * * * * * * * * * * * * */
	/**************** WIP *****************/
	peer->stats_server_instant.recv++;

	uint32_t rtt;
	rtt = peer->eight_times_rtt / 8;
	if (rtt < peer->recover_rtt_min) {
		rtt = peer->recover_rtt_min;
	}
	else if (rtt > peer->recover_rtt_max) {
		rtt = peer->recover_rtt_max;
	}
	// Optimal dynamic time for first retry (reorder bufer) is rtt/2
	rtt = rtt / 2;
	if (rtt < peer->recover_reorder_buffer)
	{
		rtt = peer->recover_reorder_buffer;
	}

	// Wake up output thread when data comes in
	if (pthread_cond_signal(&(peer->flow->condition)))
		msg(ctx->id, 0, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");

	pthread_rwlock_wrlock(&(peer->flow->queue_lock));
	if (!server_enqueue(peer, source_time, payload->data, payload->size, seq, rtt, retry, payload->src_port, payload->dst_port)) {
		rist_calculate_bitrate(peer, payload->size, &peer->bw); // update bitrate only if not a dupe
	}
	pthread_rwlock_unlock(&(peer->flow->queue_lock));
}

static void rist_server_recv_rtcp(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, uint16_t src_port, uint16_t dst_port)
{
	struct rist_server *ctx = peer->server_ctx;

	if (peer->flow && peer->advanced) {
		// We must insert a placeholder into the queue to prevent counting it as a hole during missing packet search
		if (check_valid_seq(peer, seq) < 0) {
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Invalid seq %"PRIu32" sent with RTCP packet, discarding ...\n", seq);
			return;
		}
		else {
			size_t idx = seq % peer->flow->server_queue_max;
			struct rist_buffer *b = peer->flow->server_queue[idx];
			if (b)
			{
				msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] RTCP buffer placeholder had data!!! seq=%"PRIu32", buf_seq=%"PRIu32"\n",
					seq, b->seq);
				free(b->data);
				free(b);
				peer->flow->server_queue[idx] = NULL;
			}
			peer->flow->server_queue[idx] = rist_new_buffer(NULL, 0, RIST_PAYLOAD_TYPE_RTCP, seq, 0, 0, 0);
			if (RIST_UNLIKELY(!peer->flow->server_queue[idx])) {
				msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create packet buffer inside server buffer, OOM, decrease max bitrate or buffer time length\n");
				return;
			}
		}
	}
}

static void rist_recv_rtcp(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, struct rist_buffer *payload)
{
	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;

	uint8_t *pkt = payload->data;
	uint8_t  ptype;
	uint16_t processed_bytes = 0;
	uint16_t records;
	uint8_t subtype;
	uint32_t nack_seq_msb = 0;

	while (processed_bytes < payload->size) {
		pkt = payload->data + processed_bytes;
		struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)pkt;
		/* safety checks */
		uint16_t bytes_left = payload->size - processed_bytes + 1;

		if ( bytes_left < 4 )
		{
			/* we must have at least 4 bytes */
			msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Rist rtcp packet must have at least 4 bytes, we have %d\n", 
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
			msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Malformed feedback packet, expecting %u bytes in the" \
				" packet, got a buffer of %u bytes. ptype = %d\n", bytes, 
				bytes_left, ptype);
			// TODO: replace the 0 above with rtcp_get_length(pkt)
			return;
		}

		switch(ptype) {
			case PTYPE_NACK_CUSTOM:
				if (subtype == NACK_FMT_SEQEXT)
				{
					struct rist_rtcp_seqext *seq_ext = (struct rist_rtcp_seqext *) payload;
					nack_seq_msb = ((uint32_t)htobe16(seq_ext->seq_msb)) << 16;
					break;
				}
				else if (subtype != NACK_FMT_RANGE) {
					// TODO: this should be debug
					msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Unsupported rtcp custom subtype %d, ignoring ...\n", subtype);
					break;
				}
			case PTYPE_NACK_BITMASK:
				rist_client_recv_nack(peer, flow_id, payload->src_port, payload->dst_port, pkt, bytes_left, nack_seq_msb);
				break;
			case PTYPE_RR:
				/*
				if (p_sys->b_ismulticast == false)
					process_rr(f, pkt, len);
				*/
				break;

			case PTYPE_SDES:
			{
				peer->stats_client_instant.received++;
				if (peer->dead) {
					peer->dead = false;
					msg(server_id, client_id, RIST_LOG_INFO,
						"[INFO] Peer %d was dead and it is now alive again\n", peer->adv_peer_id);
				}
				//if (p_sys->b_ismulticast == false)
				//{
					int8_t name_length = pkt[9];
					if (name_length > bytes_left)
					{
						/* check for a sane number of bytes */
						msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Malformed SDES packet, wrong cname len %u, got a " \
							"buffer of %u bytes.\n", name_length, bytes_left);
						return;
					}
					if (memcmp(pkt + RTCP_SDES_SIZE, peer->receiver_name, name_length) != 0)
					{
						memcpy(peer->receiver_name, pkt + RTCP_SDES_SIZE, name_length);
						msg(server_id, client_id, RIST_LOG_INFO, "[INFO] Peer %"PRIu32" receiver name is now: %s\n", 
							peer->adv_peer_id, peer->receiver_name);
					}
				//}
				if (peer->server_mode) {
					if (rist_server_authenticate(peer, seq, flow_id, payload))
						rist_server_recv_rtcp(peer, seq, flow_id, payload->src_port, payload->dst_port);
				} else if (peer->client_ctx && peer->listening) {
					// TODO: create rist_client_recv_rtcp
					if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {
						rist_fsm_recv_connect(peer);
					}
				}

				break;
			}
			case PTYPE_SR:
				break;

			default:
				msg(server_id, client_id, RIST_LOG_WARN, "[WARNING] Unrecognized RTCP packet with PTYPE=%02x!!\n", ptype);
		}
		processed_bytes += bytes;
	}

}

void rist_peer_rtcp(struct evsocket_ctx *evctx, void *arg)
{
	(void)evctx;
	struct rist_peer *peer = (struct rist_peer *)arg;
	//struct rist_common_ctx *ctx = get_cctx(peer);

	if (!peer || peer->shutdown) {
		return;
	}
	else { //if (ctx->profile <= RIST_MAIN) {
		//msg(0, 0, RIST_LOG_ERROR, "\tSent rctp message! peer/local (%d/%d)\n", peer->state_peer, peer->state_local);
		if (peer->server_mode) {
			rist_send_server_rtcp(peer, NULL, 0);
		} else {
			rist_send_client_rtcp(peer);
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
					((!p->server_mode && p->listening) ||
					(a->sin_addr.s_addr == b->sin_addr.s_addr));
		if (result && !p->remote_port)
			p->remote_port = a->sin_port;
	} else {
		/* ipv6 */
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)A_;
		struct sockaddr_in6 *b = (struct sockaddr_in6 *)B_;
		result = a->sin6_port == b->sin6_port &&
				((!p->server_mode && p->listening) ||
				!memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(struct in6_addr)));
		if (result && !p->remote_port)
			p->remote_port = a->sin6_port;
	}

	return result;
}

static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	(void)evctx;
	(void)fd;
	(void)revents;
	struct rist_peer *peer = (struct rist_peer *) arg;
	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;

	msg(server_id, client_id, RIST_LOG_ERROR, "\tSocket error!\n");

	rist_shutdown_peer(peer);
}

static uint64_t timeRTPtoNTP( struct rist_peer *peer, uint32_t time_extension, uint32_t i_rtp )
{
	// We are missing the lower 16 bits and the higher 16 bits for full NTP info and accuracy
	uint64_t i_ntp = (uint64_t)i_rtp;
	i_ntp = i_ntp << 16;
	if (time_extension > 0)
	{
		// rebuild source_time (lower and upper 16 bits)
		uint64_t part3 = (uint64_t)(time_extension & 0xffff);
		uint64_t part1 = ((uint64_t)(time_extension & 0xffff0000)) << 32;
		i_ntp = part1 | i_ntp | part3;
		//fprintf(stderr,"source time %"PRIu64", rtp time %"PRIu32"\n", source_time, rtp_time);
	}
	else if (peer->flow)
	{
		// TODO: Extrapolate upper bits to avoid uint32_t timestamp rollover issues
	}
	return i_ntp;
}

static void client_peer_append(struct rist_client *ctx, struct rist_peer *peer)
{
	/* Add a reference to ctx->peer_lst */
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	ctx->peer_lst = realloc(ctx->peer_lst, (ctx->peer_lst_len + 1) * sizeof(*ctx->peer_lst));
	ctx->peer_lst[ctx->peer_lst_len] = peer;
	ctx->peer_lst_len++;
	pthread_rwlock_unlock(peerlist_lock);
}

/* for later use
static void client_peer_delete(struct rist_client *ctx, struct rist_peer *peer)
{
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	uint32_t i = 0;
	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		if (ctx->peer_lst[j] == peer) {
			msg(ctx->id, 0, RIST_LOG_INFO,
				"[INIT] Removing peer (%"PRIu32")\n",
				peer->adv_peer_id);
		} else {
			i++;
		}
		ctx->peer_lst[i] = ctx->peer_lst[j];
	}
	ctx->peer_lst = realloc(ctx->peer_lst,
		(ctx->peer_lst_len - 1) * sizeof(*ctx->peer_lst));
	ctx->peer_lst_len--;
	pthread_rwlock_unlock(peerlist_lock);
}
*/

static void client_peer_copy_settings(struct rist_peer *peer_src, struct rist_peer *peer)
{
	peer->recovery_mode = peer_src->recovery_mode;
	peer->recover_maxbitrate = peer_src->recover_maxbitrate;
	peer->recover_maxbitrate_return = peer_src->recover_maxbitrate_return;
	peer->recover_buffer_min = peer_src->recover_buffer_min;
	peer->recover_buffer_max = peer_src->recover_buffer_max;
	peer->recover_reorder_buffer = peer_src->recover_reorder_buffer;
	peer->recover_rtt_min = peer_src->recover_rtt_min;
	peer->recover_rtt_max = peer_src->recover_rtt_max;
	peer->bufferbloat_mode = peer_src->bufferbloat_mode;
	peer->bufferbloat_limit = peer_src->bufferbloat_limit;
	peer->bufferbloat_hard_limit = peer_src->bufferbloat_hard_limit;
}

static char *get_ip_str(struct sockaddr *sa, char *s, uint16_t *port, size_t maxlen)
{
	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
					s, maxlen);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
					s, maxlen);
		break;

	default:
		strncpy(s, "Unknown AF", maxlen);
		return NULL;
	}

	struct sockaddr_in *sin = (struct sockaddr_in *)s;
	*port = htons (sin->sin_port);

	return s;
}

static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	(void) evctx;
	(void) revents;
	struct rist_peer *peer = (struct rist_peer *) arg;
	if (peer->shutdown) {
		return;
	}

	intptr_t server_id = peer->server_ctx ? peer->server_ctx->id : 0;
	intptr_t client_id = peer->client_ctx ? peer->client_ctx->id : 0;

	struct rist_common_ctx *cctx = get_cctx(peer);

	pthread_rwlock_t *peerlist_lock = &cctx->peerlist_lock;
	socklen_t addrlen = peer->address_len;
	int ret = -1;
	uint16_t family = AF_INET;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	struct rist_peer *p = peer;
	uint8_t *recv_buf = cctx->buf.recv;
	size_t buffer_offset = 0;

	if (cctx->profile == RIST_SIMPLE)
		buffer_offset = RIST_GRE_PROTOCOL_REDUCED_SIZE;

	if (peer->address_family == AF_INET6) {
		ret = recvfrom(peer->sd, recv_buf + buffer_offset, RIST_MAX_PACKET_SIZE, 0, (struct sockaddr *) &addr6, &addrlen);
		family = AF_INET6;
		addr = (struct sockaddr *) &addr6;
	} else {
		ret = recvfrom(peer->sd, recv_buf + buffer_offset, RIST_MAX_PACKET_SIZE, 0, (struct sockaddr *) &addr4, &addrlen);
		addr = (struct sockaddr *) &addr4;
	}

	if (ret <= 0) {
		// TODO: should we close these sockets? who reopens them?
#if defined (__unix__) || defined(__APPLE__)
		msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Peer recvfrom returned zero bytes (%d), closing socket (%d)\n", ret, peer->sd);
		//udp_Close(peer->sd);
#else
		int neterror = WSAGetLastError();
		// We get WSAECONNRESET on receive from the OS when we we have sent data and there is no receiver listening.
		// i.e. the receiver OS sent back an ICMP packet to let the sender know the receiver is unavailable
		// TODO: we can leverage this error to report on the GUI that we are not reaching the other side
		if (neterror != WSAECONNRESET) {
			msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Peer recvfrom returned zero bytes (%d), closing socket (%d), error %d\n",
				ret, peer->sd, neterror);
		}
#endif
		return;
	}

	struct rist_key *k = &peer->key_secret;
	struct rist_gre *gre;
	uint32_t seq;
	uint32_t time_extension = 0;
	struct rist_protocol_hdr *proto_hdr;
	uint8_t peer_id = 0;
	struct rist_buffer payload = { .data = NULL, .size = 0, .type = 0 };
	size_t gre_size;
	uint8_t advanced = 0;

	if (cctx->profile > RIST_SIMPLE)
	{

		// Make sure we have enought bytes
		if (ret < sizeof(*gre)) {
			msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Packet too small: %d bytes, ignoring ...\n", ret);
			return;
		}

		gre = (void *) recv_buf;
		if (gre->prot_type != htobe16(RIST_GRE_PROTOCOL_TYPE_REDUCED)) {

			if (htobe16(gre->prot_type) == RIST_GRE_PROTOCOL_TYPE_KEEPALIVE)
			{
				struct rist_gre_keepalive *gre_keepalive = (void *) recv_buf;
				(void)gre_keepalive->capabilities1;
				payload.type = RIST_PAYLOAD_TYPE_UNKNOWN;
				// TODO: parse the capabilities and do something with it?
			}
			else
			{
				// Protocol not supported, TODO: support full IP header on receive?
				msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Protocol %d not supported (wrong profile?)\n", gre->prot_type);
			}
			goto protocol_bypass;
		}

		uint8_t has_checksum = CHECK_BIT(gre->flags1, 7);
		uint8_t has_key = CHECK_BIT(gre->flags1, 5);
		uint8_t has_seq = CHECK_BIT(gre->flags1, 4);
		advanced = 0;//CHECK_BIT(gre->flags2, 3);

		if (advanced)
		{
			// Peer ID (TODO: do it more elegantly?)
			if (CHECK_BIT(gre->flags1, 3)) SET_BIT(peer_id, 0);
			if (CHECK_BIT(gre->flags1, 2)) SET_BIT(peer_id, 1);
			if (CHECK_BIT(gre->flags1, 1)) SET_BIT(peer_id, 2);
			if (CHECK_BIT(gre->flags1, 0)) SET_BIT(peer_id, 3);
			// Payload type (TODO: do it more elegantly)
			if (CHECK_BIT(gre->flags2, 4)) SET_BIT(payload.type, 3);
			if (CHECK_BIT(gre->flags2, 5)) SET_BIT(payload.type, 2);
			if (CHECK_BIT(gre->flags2, 6)) SET_BIT(payload.type, 1);
			if (CHECK_BIT(gre->flags2, 7)) SET_BIT(payload.type, 0);
		}

		if (has_checksum) {
			time_extension = be32toh(gre->checksum_reserved1);
		}

		if (has_seq && has_key) {
			// Key bit is set, that means the other side want to send
			// encrypted data.
			//
			// make sure we have a key before attempting to decrypt
			if (!k->key_size) {
				// TODO log
				return;
			}

			// GRE
			uint32_t nonce = 0;
			struct rist_gre_key_seq *gre_key_seq = (void *) recv_buf;
			gre_size = sizeof(*gre_key_seq);
			if (has_checksum) {
				seq = be32toh(gre_key_seq->seq);
				nonce = be32toh(gre_key_seq->nonce);
			} else {
				// shifted by 4 missing checksum bytes (non-librist senders)
				seq = be32toh(gre_key_seq->nonce);
				nonce = be32toh(gre_key_seq->checksum_reserved1);
				gre_size -= 4;
			}

			if (!nonce) {
				// there is no nonce provided (all zeroes), this means unencrypted
				// Ignore it!
				return;
			}

			// Regenerate AES key if nonce do not match
			if (k->gre_nonce != nonce) {
				// What if the peer sends a dummy packet with nonce every time?
				// How to prevent from this abuse?
				k->used_times = 0;
				k->gre_nonce = nonce;
				// The nonce MUST be fed to the function in network byte order
				uint32_t nonce_be = htobe32(k->gre_nonce);
				uint8_t aes_key[256 / 8];
				fastpbkdf2_hmac_sha256(
					(const void *) k->password, strlen(k->password),
					(const void *) &nonce_be, sizeof(nonce_be),
					RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
					aes_key, k->key_size / 8);

				aes_key_setup(aes_key, k->aes_key_sched, k->key_size);
			}

			if (k->used_times > RIST_AES_KEY_REUSE_TIMES) {
				// Peer is reusing nonce for more than specified times
				// This is breach of security measure. Ignore!
				// This will prevent incorrect implementation from being designed.
				return;
			}

			/* Prepare AES IV */
			uint8_t IV[AES_BLOCK_SIZE];
			// The byte array needs to be zeroes and then the seq in network byte order
			uint32_t seq_be = htobe32(seq);
			memset(IV, 0, 12);
			memcpy(IV + 12, &seq_be, sizeof(seq_be));

			// Decrypt everything
			k->used_times++;
			aes_decrypt_ctr((const void *) (recv_buf + gre_size), ret - gre_size, (void *) (recv_buf + gre_size),
				k->aes_key_sched, k->key_size, IV);

		} else if (has_seq) {
			// Key bit is not set, that means the other side does not want to send
			//  encrypted data
			//
			// make sure we do not have a key
			// (ie also interested in unencrypted communication)
			if (k->key_size) {
				msg(server_id, client_id, RIST_LOG_ERROR,
					"[ERROR] We expect encrypted data and the peer sent clear communication, ignoring ...\n");
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
		/* Map the first subheader and rtp payload area to our structure */
		proto_hdr = (void *)(recv_buf + gre_size);
		payload.src_port = be16toh(proto_hdr->src_port);
		payload.dst_port = be16toh(proto_hdr->dst_port);
	}
	else
	{
		// Simple profile support (not too elegant, but simple profile should not be used anymore)
		seq = 0;
		gre_size = 0;
		ret += buffer_offset; // pretend the REDUCED_HEADER was read (needed for payload_len calculation below)
		/* Map the first subheader and rtp payload area to our structure */
		proto_hdr = (void *)recv_buf;
		// Make sure we have enought bytes
		if (ret < sizeof(*proto_hdr)) {
			msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Packet too small: %d bytes, ignoring ...\n", ret);
			return;
		}
	}

	/* Double check for a valid rtp header */
	if ((proto_hdr->rtp.flags & 0xc0) != 0x80)
	{
		msg(server_id, client_id, RIST_LOG_ERROR, "[ERROR] Malformed packet, rtp flag value is %02x instead of 0x80.\n", 
			proto_hdr->rtp.flags);
		return;
	}

	uint32_t flow_id = 0;
	bool retry = false;
	uint32_t rtp_time = 0;
	uint64_t source_time = 0;

	// Finish defining the payload (we assume reduced header for now)
	// TODO: support full IP header on receive
	if(proto_hdr->rtp.payload_type == MPEG_II_TRANSPORT_STREAM) {
		flow_id = be32toh(proto_hdr->rtp.ssrc);
		// If this is a retry, extract the information and restore correct flow_id
		if (flow_id & 1UL)
		{
			flow_id ^= 1UL;
			retry = true;
		}
		payload.size = ret - gre_size - sizeof(*proto_hdr);
		payload.data = (void *)(recv_buf + gre_size + sizeof(*proto_hdr));
		if (!advanced)
			payload.type = RIST_PAYLOAD_TYPE_DATA_RAW;
	} else {
		// remap the rtp payload to the correct rtcp header
		struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)(&proto_hdr->rtp);
		flow_id = be32toh(rtcp->ssrc);
		payload.size = ret - gre_size - RIST_GRE_PROTOCOL_REDUCED_SIZE;
		payload.data = (void *)(recv_buf + gre_size + RIST_GRE_PROTOCOL_REDUCED_SIZE);
		// Null this pointer to prevent code use below 
		// as only the first 8 bytes have valid data for RTCP packets
		proto_hdr = NULL;
		// The payload_type is not populated on non-librist senders
		if (!advanced)
			payload.type = RIST_PAYLOAD_TYPE_RTCP;
	}

	//msg(0, 0, RIST_LOG_ERROR,
	//			"[ERROR] HTF gre_seq %"PRIu32" "
	//			"flow_id %"PRIu32", peer_id %"PRIu32", gre_size %zu, ptype %u\n", 
	//			seq, flow_id, peer_id, gre_size, payload_type);

protocol_bypass:
// We need this protocol bypass to manage keepalives of any kind,
// they need to trigger peering at the bottom of this function

	pthread_rwlock_rdlock(peerlist_lock);
	while (p) {
		if (equal_address(family, addr, p)) {
			payload.peer = p;
			if (cctx->profile == RIST_SIMPLE)
			{
				payload.src_port = p->remote_port;
				payload.dst_port = p->local_port;
			}
			//msg(0, 0, RIST_LOG_INFO, "[INIT] Port is %d !!!!!\n", addr4.sin_port);
			switch(payload.type) {
				case RIST_PAYLOAD_TYPE_UNKNOWN:
					// Do nothing ...TODO: check for port changes?
				break;
				case RIST_PAYLOAD_TYPE_RTCP:
				case RIST_PAYLOAD_TYPE_RTCP_NACK:
					rist_recv_rtcp(p, seq, flow_id, &payload);
				break;
				case RIST_PAYLOAD_TYPE_DATA_LZ4:
				case RIST_PAYLOAD_TYPE_DATA_RAW:
					rtp_time = be32toh(proto_hdr->rtp.ts);
					source_time = timeRTPtoNTP(p, time_extension, rtp_time);
					if (!advanced)
					{
						// Get the sequence from the rtp header for queue management
						seq = (uint32_t)be16toh(proto_hdr->rtp.seq);
						// TODO: add support for seq number extension? ...
						if (!p->short_seq)
							p->short_seq = true;
					}
					if (RIST_UNLIKELY(!p->server_mode))
						msg(server_id, client_id, RIST_LOG_WARN,
						"[WARNING] Received data packet on sender, ignoring (%d bytes)...\n", payload.size);
					else
						rist_server_recv_data(p, seq, flow_id, source_time, &payload, retry);
				break;
				default:
					rist_recv_rtcp(p, seq, flow_id, &payload);
				break;
			}
			pthread_rwlock_unlock(peerlist_lock);
			return;
		}
		p = p->next;
	}
	pthread_rwlock_unlock(peerlist_lock);

	// Peer was not found ...

	// Create/update peers if necessary
	if (peer->listening &&
		 (payload.type == RIST_PAYLOAD_TYPE_RTCP || cctx->profile == RIST_SIMPLE)) {
		/* No match, new peer creation when on listening mode */
		uint32_t new_peer_id = 0;
		if (advanced)
			new_peer_id = peer_id;
		else
			new_peer_id = ++cctx->peer_counter;
		msg(server_id, client_id, RIST_LOG_INFO, "[INIT] New RTCP peer connecting, flow_id %"PRIu32", peer_id %"PRIu32"\n", flow_id, new_peer_id);
		p = peer_initialize(NULL, NULL, peer->client_ctx, peer->server_ctx);
		p->local_port = peer->local_port;
		p->remote_port = peer->remote_port;
		if (peer->server_mode)
			p->adv_flow_id = flow_id;
		else
			p->adv_flow_id = p->client_ctx->adv_flow_id;
		// TODO: what if client mode and flow_id != 0 and p->adv_flow_id != flow_id
		p->address_family = family;
		p->address_len = addrlen;
		p->listening = 0;
		p->advanced = advanced;
		p->is_rtcp = peer->is_rtcp;
		p->is_data = peer->is_data;
		p->peer_data = p;
		memcpy(&p->u.address, addr, addrlen);
		p->sd = peer->sd;
		p->parent = peer;
		p->adv_peer_id = new_peer_id;
		p->state_local = p->state_peer = RIST_PEER_STATE_PING;
		rist_populate_cname(p->sd, p->cname);

		// Optional validation of connecting client
		if (cctx->auth_connect_callback) {
			char incoming_ip_string_buffer[INET6_ADDRSTRLEN];
			char parent_ip_string_buffer[INET6_ADDRSTRLEN];
			uint16_t port;
			uint16_t dummyport;
			char *incoming_ip_string = get_ip_str(&p->u.address, &incoming_ip_string_buffer[0], &port, INET6_ADDRSTRLEN);
			char *parent_ip_string =
				get_ip_str(&p->parent->u.address, &parent_ip_string_buffer[0], &dummyport, INET6_ADDRSTRLEN);
			if (!parent_ip_string){
				parent_ip_string = "";
			}
			if (incoming_ip_string) {
				if (!cctx->auth_connect_callback(cctx->auth_connect_callback_argument,
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
			if (peer->server_mode)
				msg(server_id, client_id, RIST_LOG_INFO, "[INIT] Enabling keepalive for peer %d\n", p->adv_peer_id);
			else {
				// only profile > simple
				client_peer_copy_settings(peer, p);
				client_peer_append(peer->client_ctx, p);
				// authenticate client now that we have an address
				rist_fsm_recv_connect(p);
				msg(server_id, client_id, RIST_LOG_INFO, "[INIT] Enabling reverse keepalive for peer %d\n", p->adv_peer_id);
			}
			p->send_keepalive = true;
		}
		peer_append(p);
		// Final states happens during settings parsing event on next ping packet
	} else {
		if (!p) {
			if (payload.type != 7) {
				msg(0, 0, RIST_LOG_INFO, "\tOrphan rist_peer_recv %x (%d/%d)\n",
					payload.type, peer->state_peer, peer->state_local);
				rist_print_inet_info("Orphan ", peer);
			}
		} else {
			msg(0, 0, RIST_LOG_INFO, "\tRogue rist_peer_recv %x (%d/%d)\n",
				payload.type, p->state_peer, p->state_local);
			rist_print_inet_info("Orphan ", p);
		}
	}
}

int rist_client_write(struct rist_client *ctx, const void *buf, size_t len, uint16_t src_port, uint16_t dst_port)
{
	// max protocol overhead for data is gre-header plus gre-reduced-mode-header plus rtp-header
	// 16 + 4 + 12 = 32

	if (len <= 0 || len > (RIST_MAX_PACKET_SIZE-32)) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"Dropping pipe packet of size %d, max is %d.\n", len, RIST_MAX_PACKET_SIZE-32);
		return -1;
	}

	// TODO: add an API where the lib user can give us the timestamp
	int ret = rist_client_enqueue(ctx, buf, len, timestampNTP_u64(), src_port, dst_port);
	// Wake up data/nack output thread when data comes in
	if (pthread_cond_signal(&ctx->condition))
		msg(0, ctx->id, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");

	return ret;
}

static void client_send_nacks(struct rist_client *ctx, int maxcounter)
{
	// Send retries from the queue (if any)
	int maxCounter = 10;
	// Send no more than 10 retries for every packet/loop (for uniform spacing)
	size_t total_bytes = 0;

	while (1) {
		int ret = rist_retry_dequeue(ctx);

		if (ret == -1 || ret == 0) {
			// Skipped, too many or up to date
			break;
		} else {
			// Sent a retry succesfully, now, send another one
			total_bytes += ret;
		}
		if (maxCounter++ > maxcounter) {
			break;
		}
	}
}

static void client_send_data(struct rist_client *ctx, int maxcount)
{
	int counter = 0;

	while (1) {
		// If we fall behind, only empty 100 every 5ms (master loop)
		if (counter++ > maxcount) {
			break;
		}

		size_t idx = (ctx->client_queue_read_index + 1) % ctx->client_queue_max;

		if (idx == ctx->client_queue_write_index) {
			//msg(0, ctx->id, RIST_LOG_ERROR,
			//    "\t[GOOD] We are all up to date, index is %d\n",
			//    ctx->client_queue_read_index);
			break;
		}

		ctx->client_queue_read_index = idx;
		if (RIST_UNLIKELY(ctx->client_queue[idx] == NULL)) {
			// This should never happen!
			msg(0, ctx->id, RIST_LOG_ERROR,
				"[ERROR] FIFO data block was null (read/write) (%zu/%zu)\n",
				ctx->client_queue_read_index, ctx->client_queue_write_index);
			continue;
		} else {
			struct rist_buffer *buffer =  ctx->client_queue[idx];
			// Send  fifo data (handshake and data payloads)
			if (buffer->type == RIST_PAYLOAD_TYPE_RTCP) {
				// TODO can we ever have a null or dead buffer->peer?
				uint8_t *payload = buffer->data;
				rist_send_common_rtcp(buffer->peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, false);
				buffer->seq = ctx->common.seq;
				buffer->seq_rtp = ctx->common.seq_rtp;
			}
			else {
				rist_client_send_data_balanced(ctx, buffer);
				// For non-advanced mode seq to index mapping
				ctx->seq_index[buffer->seq_rtp] = idx;
			}
		}

	}
}

static struct rist_peer *peer_initialize(const char *url, const char *localport,
										struct rist_client *client_ctx,
										struct rist_server *server_ctx)
{
	intptr_t server_id = server_ctx ? server_ctx->id : 0;
	intptr_t client_id = client_ctx ? client_ctx->id : 0;

	struct rist_peer *p = calloc(1, sizeof(*p));
	if (!p) {
		msg(server_id, client_id, RIST_LOG_ERROR, "\tNot enough memory creating peer!\n");
		return NULL;
	}

	if (localport) {
		p->local_port = (uint16_t)atoi(localport);
	}

	if (url) {
		p->url = strdup(url);
	}

	struct rist_key *k = (server_ctx != NULL) ?
			&server_ctx->common.SECRET :
			&client_ctx->common.SECRET;

	p->server_mode = (server_ctx != NULL);
	p->key_secret.key_size = k->key_size;
	p->key_secret.password = k->password;

	p->recovery_mode = RIST_RECOVERY_MODE_UNCONFIGURED;
	p->client_ctx = client_ctx;
	p->server_ctx = server_ctx;
	p->birthtime_local = timestampNTP_u64();

	return p;
}

static PTHREAD_START_FUNC(server_pthread_dataout, arg)
{
	struct rist_flow *flow = (struct rist_flow *)arg;
	struct rist_server *server_ctx = (void *)flow->server_id;
	// Default max jitter is 5ms
	int max_output_jitter_ms = flow->max_output_jitter / RIST_CLOCK;
	msg(flow->server_id, 0, RIST_LOG_INFO, "[INFO] Starting data output thread with %d ms max output jitter\n", max_output_jitter_ms);

	//uint64_t now = timestampNTP_u64();
	while (!flow->shutdown) {
		pthread_rwlock_wrlock(&(flow->queue_lock));
		if (flow->peer_lst) {
			server_output(server_ctx, flow);
		}
		pthread_rwlock_unlock(&(flow->queue_lock));
		pthread_mutex_lock(&(flow->mutex));
		int ret = pthread_cond_timedwait_ms(&(flow->condition), &(flow->mutex), max_output_jitter_ms);
		pthread_mutex_unlock(&(flow->mutex));
		if (ret && ret != ETIMEDOUT)
			msg(flow->server_id, 0, RIST_LOG_ERROR, "[ERROR] Error %d in server data out loop\n", ret);
		//msg(flow->server_id, 0, RIST_LOG_INFO, "[INFO] LOOP TIME is %"PRIu64" us\n", (timestampNTP_u64() - now) * 1000 / RIST_CLOCK);
		//now = timestampNTP_u64();
	}
	flow->shutdown = 2;

	return 0;
}

static void client_peer_events(struct rist_client *ctx)
{
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;

	pthread_rwlock_wrlock(peerlist_lock);

	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		struct rist_peer *peer = ctx->peer_lst[j];
		// TODO: check last time sent and skip it
		if (peer->send_keepalive) {
			rist_peer_rtcp(NULL, peer);
		}
	}

	pthread_rwlock_unlock(peerlist_lock);
}

static PTHREAD_START_FUNC(client_pthread_protocol, arg)
{
	struct rist_client *ctx = (struct rist_client *) arg;
	// loop behavior parameters
	int max_dataperloop = 100;
	int max_nacksperloop = RIST_RETRY_RATIO;

	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
	uint64_t rist_stats_interval = (uint64_t)1000 * (uint64_t)RIST_CLOCK; // 1 second
	uint64_t rist_keepalive_interval = (uint64_t)ctx->common.rist_keepalive_interval;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting master client loop at %d ms max jitter\n",
				max_jitter_ms);

	uint64_t now  = timestampNTP_u64();
	ctx->common.nacks_next_time = now;
	ctx->stats_next_time = now;
	ctx->common.keepalive_next_time = now;
	while(!ctx->common.shutdown) {

		// Conditional 5ms sleep that is woken by data coming in
		pthread_mutex_lock(&(ctx->mutex));
		int ret = pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), max_jitter_ms);
		pthread_mutex_unlock(&(ctx->mutex));
		if (ret && ret != ETIMEDOUT)
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d in client protocol loop, loop time was %d us\n", ret, (timestampNTP_u64() - now));

		if (RIST_UNLIKELY(!ctx->common.startup_complete)) {
			continue;
		}

		now  = timestampNTP_u64();

		// stats timer
		if (now > ctx->stats_next_time) {
			ctx->stats_next_time += rist_stats_interval;

			pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
			pthread_rwlock_wrlock(peerlist_lock);
			for (size_t j = 0; j < ctx->peer_lst_len; j++) {
				struct rist_peer *peer = ctx->peer_lst[j];
				// TODO: print warning if the peer is dead?, i.e. no stats
				if (!peer->dead) {
					rist_client_peer_statistics(peer);
				}
			}
			pthread_rwlock_unlock(peerlist_lock);
			// TODO: remove dead peers after stale flow time (both client list and peer chain)
			//client_peer_delete(peer->client_ctx, peer);
		}

		// socket polls
		evsocket_loop_single(ctx->common.evctx, 0);

		// keepalive timer
		if (now > ctx->common.keepalive_next_time) {
			ctx->common.keepalive_next_time += rist_keepalive_interval;
			client_peer_events(ctx);
		}

		// Send data and process nacks
		if (ctx->client_queue_bytesize > 0) {
			client_send_data(ctx, max_dataperloop);
			// TODO: put a minimum on the nack and cleanup sending (maybe group them every 1ms)
			// otherwise for higher bitrates our CPU will not keep up (20Mbps is about 0.5ms spacing)
			// because of the tight loop
			client_send_nacks(ctx, max_nacksperloop);
			/* perform queue cleanup */
			rist_clean_client_enqueue(ctx);
		}

	}
	evsocket_loop_finalize(ctx->common.evctx);

#ifdef _WIN32
	WSACleanup();
#endif
	msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Exiting master client loop\n");
	msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Freeing up peers memory allocations\n");
	struct rist_peer *peer = ctx->common.PEERS;
	while (peer) {
		struct rist_peer *nextpeer = peer->next;
		free(peer);
		peer = nextpeer;
	}
	msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Freeing up context memory allocations\n");
	free(ctx->client_retry_queue);
	free(ctx->client_queue);
	ctx->client_thread = 0;
	free(ctx);

	return 0;
}

static void init_common_ctx(struct rist_common_ctx *ctx, enum rist_profile profile)
{
	init_socket_subsystem();
	ctx->evctx = evsocket_init();
	ctx->rist_keepalive_interval = RIST_PING_INTERVAL * RIST_CLOCK;
	ctx->rist_max_jitter = RIST_MAX_JITTER * RIST_CLOCK;
	if (profile > RIST_MAIN) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Profile not supported (%d), using main profile instead\n", profile);
		profile = RIST_MAIN;
	}
	ctx->profile = profile;

	if (pthread_rwlock_init(&ctx->peerlist_lock, NULL) != 0) {
		perror("pthread_rwlock_init()");
		// TODO: this error cannot be handled with exit!
		exit(1);
	}
}

int rist_server_create(struct rist_server **_ctx, enum rist_profile profile)
{
	struct rist_server *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "OOM!\n");
		return -1;
	}

	// Default values
	ctx->recovery_mode = RIST_RECOVERY_MODE_TIME;
	ctx->recovery_maxbitrate = 100;
	ctx->recovery_maxbitrate_return = 0;
	ctx->recovery_length_min = 1000;
	ctx->recovery_length_max = 1000;
	ctx->recovery_reorder_buffer = 70;
	ctx->recovery_rtt_min = 50;
	ctx->recovery_rtt_max = 500;
	ctx->bufferbloat_mode = RIST_BUFFER_BLOAT_MODE_OFF;
	ctx->bufferbloat_limit = 6;
	ctx->bufferbloat_hard_limit = 20;

	init_common_ctx(&ctx->common, profile);
	ctx->id = (intptr_t)ctx;
	*_ctx = ctx;
	return 0;
}

int rist_client_create(struct rist_client **_ctx, enum rist_profile profile)
{
	struct rist_client *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Could not create ctx object, OOM!\n");
		return -1;
	}

	init_common_ctx(&ctx->common, profile);
	ctx->id = (intptr_t)ctx;
	//ctx->common.seq = 9159579;
	//ctx->common.seq = RIST_SERVER_QUEUE_BUFFERS - 25000;

	if (!ctx->client_retry_queue) {
		ctx->client_retry_queue = calloc(RIST_RETRY_QUEUE_BUFFERS, sizeof(*ctx->client_retry_queue));
		if (RIST_UNLIKELY(!ctx->client_retry_queue)) {
			fprintf(stderr, "Could not create client retry buffer of size %u MB, OOM\n",
				(unsigned)(RIST_SERVER_QUEUE_BUFFERS * sizeof(ctx->client_retry_queue[0])) / 1000000);
			free(ctx);
			return -1;
		}

		ctx->client_retry_queue_write_index = 1;
		ctx->client_retry_queue_read_index = 0;
		ctx->client_retry_queue_size = RIST_RETRY_QUEUE_BUFFERS;
	}

	ctx->client_queue_read_index = 0;
	ctx->client_queue_write_index = 0;
	ctx->client_queue_delete_index = 0;
	ctx->client_queue_max = RIST_SERVER_QUEUE_BUFFERS;

	*_ctx = ctx;
	return 0;
}

int rist_client_init(struct rist_client *ctx, uint32_t flow_id, enum rist_log_level log_level,
		int (*auth_connect_callback)(void *arg, char* connecting_ip, uint16_t connecting_port, char* local_ip, uint16_t local_port, struct rist_peer *peer))
{
	msg(0, ctx->id, RIST_LOG_INFO, "[INIT] RIST Client Library v%d.%d.%d\n",
			RIST_PROTOCOL_VERSION, RIST_API_VERSION, RIST_SUBVERSION);

	set_loglevel(log_level);
	if (log_level == RIST_LOG_SIMULATE) {
		ctx->simulate_loss = true;
	}
	if (log_level >= RIST_LOG_DEBUG)
		ctx->common.debug = true;

	ctx->adv_flow_id = flow_id;

	int ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d initializing pthread_condition\n",ret);
		return ret;
	}

	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d initializing pthread_mutex\n",ret);
		return ret;
	}

	ctx->common.auth_connect_callback = auth_connect_callback;
	ctx->client_initialized = true;

	if (pthread_create(&ctx->client_thread, NULL, client_pthread_protocol, (void *)ctx) != 0) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Could not created client thread.\n");
		return -3;
	}

	return 0;
}

int rist_client_start(struct rist_client *ctx)
{
	if (!ctx->client_initialized) {
		return -1;
	}

	if (ctx->total_weight > 0) {
		ctx->weight_counter = ctx->total_weight;
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Total weight: %lu\n", ctx->total_weight);
	}

	ctx->common.startup_complete = true;
	return 0;
}

int rist_client_pause(struct rist_client *ctx)
{
	if (!ctx->client_initialized) {
		return -1;
	}

	ctx->common.startup_complete = false;
	return 0;
}

int rist_client_unpause(struct rist_client *ctx)
{
	if (!ctx->client_initialized) {
		return -1;
	}

	ctx->common.startup_complete = true;
	return 0;
}

int rist_client_remove_peer(struct rist_client *ctx, struct rist_peer *d_peer)
{
	pthread_rwlock_wrlock(&ctx->common.peerlist_lock);

	if (d_peer == NULL) {
		return -1;
	}

	if (d_peer) {
		/* middle */
		if (d_peer->prev && d_peer->next) {
			d_peer->prev->next = d_peer->next;
			d_peer->next->prev = d_peer->prev;
		} else if (!d_peer->prev) {
			/* head */
			if (d_peer->next) {
				d_peer->next->prev = NULL;
			}

			ctx->common.PEERS = d_peer->next;
		} else if (!d_peer->next) {
			/* tail */
			d_peer->prev->next = NULL;
		} else {
			pthread_rwlock_unlock(&ctx->common.peerlist_lock);
			return -1;
		}
	} else {
		pthread_rwlock_unlock(&ctx->common.peerlist_lock);
		return -1;
	}

	free(d_peer);
	pthread_rwlock_unlock(&ctx->common.peerlist_lock);
	return 0;
}

static void client_store_settings(struct rist_client *ctx,
		const struct rist_peer_config *settings, struct rist_peer *peer)
{
	uint32_t recovery_rtt_min;
	uint32_t bufferbloat_limit;
	uint32_t bufferbloat_hard_limit;

	// TODO: Consolidate the two settings objects into one

	/* Set recovery options */
	peer->recovery_mode = settings->recovery_mode;
	peer->recover_maxbitrate = settings->recovery_maxbitrate;
	peer->recover_maxbitrate_return = settings->recovery_maxbitrate_return;
	peer->recover_buffer_min = settings->recovery_length_min;
	peer->recover_buffer_max = settings->recovery_length_max;
	peer->recover_reorder_buffer = settings->recover_reorder_buffer;
	if (settings->recovery_rtt_min < RIST_RTT_MIN) {
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] rtt_min is too small (%u), using %dms instead\n",
			settings->recovery_rtt_min, RIST_RTT_MIN);
		recovery_rtt_min = RIST_RTT_MIN;
	} else {
		recovery_rtt_min = settings->recovery_rtt_min;
	}
	peer->recover_rtt_min = recovery_rtt_min;
	peer->recover_rtt_max = settings->recovery_rtt_max;
	/* Set buffer-bloating */
	if (settings->bufferbloat_limit < 2 || settings->bufferbloat_limit > 100) {
		msg(0, ctx->id, RIST_LOG_INFO,
			"[INIT] The configured value for bufferbloat_limit 2 <= %u <= 100 is invalid, using %u instead\n",
			settings->bufferbloat_limit, 6);
		bufferbloat_limit = 6;
	} else {
		bufferbloat_limit = settings->bufferbloat_limit;
	}
	if (settings->bufferbloat_hard_limit < 2 || settings->bufferbloat_hard_limit > 100) {
		msg(0, ctx->id, RIST_LOG_INFO,
			"[INIT] The configured value for bufferbloat_hard_limit 2 <= %u <= 100 is invalid, using %u instead\n",
			settings->bufferbloat_hard_limit, 20);
		bufferbloat_hard_limit = 20;
	} else {
		bufferbloat_hard_limit = settings->bufferbloat_hard_limit;
	}
	peer->bufferbloat_mode = settings->bufferbloat_mode;
	peer->bufferbloat_limit = bufferbloat_limit;
	peer->bufferbloat_hard_limit = bufferbloat_hard_limit;

	/* Global context settings */

	if (settings->recovery_maxbitrate > ctx->recovery_maxbitrate_max) {
		ctx->recovery_maxbitrate_max = settings->recovery_maxbitrate;
	}

	if (settings->weight > 0) {
		peer->weight = settings->weight;
		ctx->total_weight += settings->weight;
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Peer weight: %lu\n", peer->weight);
	}

	/* Set target recover size (buffer) */
	if ((settings->recovery_length_max + (2 * settings->recovery_rtt_max)) > ctx->client_recover_min_time) {
		ctx->client_recover_min_time = settings->recovery_length_max + (2 * settings->recovery_rtt_max);
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Setting buffer size to %zu\n", ctx->client_recover_min_time);
	}

}

static struct rist_peer *rist_client_add_peer_local(struct rist_client *ctx,
		const struct rist_peer_config *config, bool b_rtcp)
{

	/* Initialize peer */
	struct rist_peer *newpeer = peer_initialize(config->address, config->localport, ctx, NULL);
	if (!newpeer) {
		return NULL;
	}

	/* Initialize socket */
	rist_create_socket(newpeer);
	if (newpeer->sd <= 0) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERRORS] Could not create socket\n");
		free(newpeer);
		return NULL;
	}

	newpeer->cooldown_time = 0;
	newpeer->is_rtcp = b_rtcp;
	newpeer->adv_peer_id = ctx->common.peer_counter++;

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

	client_store_settings(ctx, config, newpeer);

	msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Advertising flow_id : %" PRIu64 " and peer_id %u\n",
		newpeer->adv_flow_id, newpeer->adv_peer_id);

	return newpeer;

}

// TODO: Remove peer from here and the remove function and just return peer_id (or allow a secific one to be specified)
int rist_client_add_peer(struct rist_client *ctx,
		const struct rist_peer_config *config, struct rist_peer **peer)
{
	struct rist_peer *newpeer = rist_client_add_peer_local(ctx, config, false);

	if (!newpeer)
		return -1;

	newpeer->is_data = true;
	peer_append(newpeer);

	if (ctx->common.profile == RIST_SIMPLE)
	{
		struct rist_peer *peer_rtcp = rist_client_add_peer_local(ctx, config, true);
		if (!peer_rtcp)
		{
			// TODO: remove from peerlist (create client_delete peer function)
			free(newpeer);
			return -1;
		}
		peer_rtcp->peer_data = newpeer;
		peer_append(peer_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(peer_rtcp);
		/* Authenticate right away */
		if (!peer_rtcp->listening) {
			client_peer_append(ctx, newpeer);
			rist_fsm_recv_connect(peer_rtcp);
		}
	}
	else {
		newpeer->peer_data = newpeer;
		newpeer->is_rtcp = true;
	}

	/* jumpstart communication */
	rist_fsm_init_comm(newpeer);
	/* Authenticate right away */
	if (!newpeer->listening) {
		client_peer_append(ctx, newpeer);
		rist_fsm_recv_connect(newpeer);
	}

	// TODO: get rid of this peer object reference and use peer id instead
	// This reference is used when the calling app wants to remove a peer
	*peer = newpeer;

	return 0;
}

int rist_server_init(struct rist_server *ctx, const struct rist_peer_config *default_peer_config, enum rist_log_level log_level,
		int (*auth_connect_callback)(void *arg, char* connecting_ip, uint16_t connecting_port, char* local_ip, uint16_t local_port, struct rist_peer *peer))
{

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] RIST Server Library v%d.%d.%d\n",
		RIST_PROTOCOL_VERSION, RIST_API_VERSION, RIST_SUBVERSION);

	set_loglevel(log_level);
	if (log_level >= RIST_LOG_DEBUG)
		ctx->common.debug = true;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting in server mode: %s\n", default_peer_config->address);

	ctx->common.auth_connect_callback = auth_connect_callback;

	if (default_peer_config) {
		msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Processing default configuration values\n");
		/* Process default flow/peer configuration */
		ctx->recovery_mode = default_peer_config->recovery_mode;
		ctx->recovery_maxbitrate = default_peer_config->recovery_maxbitrate;
		ctx->recovery_maxbitrate_return = default_peer_config->recovery_maxbitrate_return;
		ctx->recovery_length_min = default_peer_config->recovery_length_min;
		ctx->recovery_length_max = default_peer_config->recovery_length_max;
		ctx->recovery_reorder_buffer = default_peer_config->recover_reorder_buffer;
		ctx->recovery_rtt_min = default_peer_config->recovery_rtt_min;
		ctx->recovery_rtt_max = default_peer_config->recovery_rtt_max;
		ctx->weight = default_peer_config->weight;
		/* Set buffer-bloating */
		ctx->bufferbloat_mode = default_peer_config->bufferbloat_mode;
		uint32_t bufferbloat_limit;
		uint32_t bufferbloat_hard_limit;
		if (default_peer_config->bufferbloat_limit < 2 || default_peer_config->bufferbloat_limit > 100) {
			msg(ctx->id, 0, RIST_LOG_INFO,
				"[INIT] The configured value for bufferbloat_limit 2 <= %u <= 100 is invalid, using %u instead\n",
				default_peer_config->bufferbloat_limit, 6);
			bufferbloat_limit = 6;
		} else {
			bufferbloat_limit = default_peer_config->bufferbloat_limit;
		}
		if (default_peer_config->bufferbloat_hard_limit < 2 || default_peer_config->bufferbloat_hard_limit > 100) {
			msg(ctx->id, 0,  RIST_LOG_INFO,
				"[INIT] The configured value for bufferbloat_hard_limit 2 <= %u <= 100 is invalid, using %u instead\n",
				default_peer_config->bufferbloat_hard_limit, 20);
			bufferbloat_hard_limit = 20;
		} else {
			bufferbloat_hard_limit = default_peer_config->bufferbloat_hard_limit;
		}
		ctx->bufferbloat_limit = bufferbloat_limit;
		ctx->bufferbloat_hard_limit = bufferbloat_hard_limit;
	}

	return 0;
}

static int rist_encrypt_enable(struct rist_common_ctx *ctx,
								const char *secret, int key_size,
								intptr_t server_id, intptr_t client_id)
{
	int ret;

	if (!key_size) {
		msg(server_id, client_id, RIST_LOG_ERROR,
			"\tKey length is zero, disabling encryption\n");
		key_size = 0;
		secret = NULL;
		ret = 0;
		goto perform_update;
	}

	if (!secret || !strlen(secret)) {
		msg(server_id, client_id, RIST_LOG_ERROR,
			"\tInvalid secret key, disabling encryption\n");
		key_size = 0;
		secret = NULL;
		ret = -1;
		goto perform_update;
	}

	msg(server_id, client_id, RIST_LOG_INFO,
		"[INIT] Using %d bits secret key\n", key_size);
	ret = 0;

	perform_update:
	memset(&ctx->SECRET, 0, sizeof(ctx->SECRET));
	ctx->SECRET.key_size = key_size;
	ctx->SECRET.password = secret;

	/* update peer list (in case this was set after the peer was added) */
	for (struct rist_peer *peer = ctx->PEERS; peer; peer = peer->next) {
		peer->key_secret = ctx->SECRET;
	}

	return ret;
}

int rist_client_encrypt_enable(struct rist_client *ctx, const char *secret,
								int key_size)
{
	return rist_encrypt_enable(&ctx->common, secret, key_size, 0, ctx->id);
}

int rist_client_compress_enable(struct rist_client *ctx, int compression)
{
	ctx->compression = !!compression;
	return 0;
}

int rist_server_encrypt_enable(struct rist_server *ctx, const char *secret, int key_size)
{
	return rist_encrypt_enable(&ctx->common, secret, key_size, ctx->id, 0);
}

int rist_server_set_nack_type(struct rist_server *ctx, enum rist_nack_type nack_type)
{
	ctx->nack_type = nack_type;
	return 0;
}

void server_peer_events(struct rist_server *ctx)
{
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);

	for (struct rist_peer *p = ctx->common.PEERS; p != NULL; p = p->next) {
		// TODO: check last time sent and skip it
		if (p->send_keepalive) {
			rist_peer_rtcp(NULL, p);
		}
	}

	pthread_rwlock_unlock(peerlist_lock);
}

static void rist_server_destroy(struct rist_server *ctx)
{
	struct evsocket_ctx *evctx = ctx->common.evctx;

	msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Starting Flows cleanup\n");

	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;

	pthread_rwlock_wrlock(peerlist_lock);
	struct rist_flow *f = ctx->common.FLOWS;
	while (f) {
		struct rist_flow *nextflow = f->next;
		rist_delete_flow(ctx, f);
		f = nextflow;
	}
	msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Flows cleanup complete\n");
	pthread_rwlock_unlock(peerlist_lock);

	msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Starting peers cleanup\n");
	/* now use the peer list to destroy all peers and timers */
	struct rist_peer **PEERS = &ctx->common.PEERS;
	pthread_rwlock_wrlock(peerlist_lock);
	struct rist_peer *peer = *PEERS;
	if (!peer) {
		pthread_rwlock_unlock(peerlist_lock);
	} else {
		while (peer) {
			struct rist_peer *nextpeer = peer->next;
			msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Removing peer data received event\n");
			/* data receive event */
			if (peer->event_recv) {
				evsocket_delevent(evctx, peer->event_recv);
				peer->event_recv = NULL;
			}

			msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Removing peer handshake/ping timer\n");
			/* rtcp timer */
			peer->send_keepalive = false;

			msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Closing peer socket on port %d\n", peer->local_port);
			if (peer->sd > -1) {
				udp_Close(peer->sd);
				peer->sd = -1;
			}

			// Do not free the peer here, do it at the end of the protocol main loop
			//free(peer);
			peer = nextpeer;
		}
		ctx->common.PEERS = NULL;
		pthread_rwlock_unlock(peerlist_lock);
	}
	msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Peers cleanup complete\n");

	msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Removing peerlist_lock\n");
	pthread_rwlock_destroy(&ctx->common.peerlist_lock);
	ctx->common.shutdown = true;
	// This last one is not done here but at the exit of server_loop
	//free(ctx);
}

static PTHREAD_START_FUNC(server_pthread_protocol, arg)
{
	struct rist_server *ctx = (struct rist_server *) arg;
	uint64_t now = timestampNTP_u64();
	ctx->common.keepalive_next_time = now;

	uint64_t rist_nack_interval = (uint64_t)ctx->common.rist_max_jitter;
	uint64_t rist_keepalive_interval = (uint64_t)ctx->common.rist_keepalive_interval;
	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting server protocol loop with %d ms timer\n", max_jitter_ms);

	while (!ctx->common.shutdown) {
		now  = timestampNTP_u64();

		// stats timer
		struct rist_flow *f = ctx->common.FLOWS;
		while (f) {
			if (now > f->stats_next_time) {
				f->stats_next_time += f->recover_buffer_ticks; // equal to the buffer size
				// we move the f cursor inside because we can detect and delete stale flows
				// inside, thus skipping it
				f = rist_server_flow_statistics(ctx, f);
			}
			else
			{
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

		// socket polls
		evsocket_loop_single(ctx->common.evctx, max_jitter_ms);

		// keepalive timer
		if (now > ctx->common.keepalive_next_time) {
			ctx->common.keepalive_next_time += rist_keepalive_interval;
			server_peer_events(ctx);
		}

		// nacks timer
		if (now > ctx->common.nacks_next_time) {
			ctx->common.nacks_next_time += rist_nack_interval;
			// process nacks on every loop (5 ms interval max)
			struct rist_flow *f = ctx->common.FLOWS;
			while (f) {
				server_nack_output(ctx, f);
				f = f->next;
			}
		}
	}
	rist_server_destroy(ctx);
	evsocket_loop_finalize(ctx->common.evctx);
#ifdef _WIN32
	WSACleanup();
#endif
	msg(ctx->id, 0, RIST_LOG_INFO, "[SHUTDOWN] Exiting master server loop\n");

	msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Freeing up peers memory allocations\n");
	struct rist_peer *peer = ctx->common.PEERS;
	while (peer) {
		struct rist_peer *nextpeer = peer->next;
		free(peer);
		peer = nextpeer;
	}

	ctx->server_thread = 0;
	free(ctx);

	return 0;
}

int rist_server_start(struct rist_server *ctx,
	void(*receive_callback)(void *arg, struct rist_peer *peer, uint64_t flow_id, const void *buffer, size_t len, uint16_t src_port, uint16_t dst_port),
	void *arg)
{
	ctx->server_receive_callback = receive_callback;
	ctx->server_receive_callback_argument = arg;

	if (!ctx->server_thread) {
		if (pthread_create(&ctx->server_thread, NULL, server_pthread_protocol, (void *)ctx) != 0) {
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create server protocol thread.\n");
			return -1;
		}
	}

	return 0;
}

static char *rist_get_status(struct rist_common_ctx *ctx)
{
	char *str;

	for (struct rist_peer *p = ctx->PEERS; p != NULL; p = p->next) {
		asprintf(&str, "[STATUS] peer flow id : %d\n"
						"[STATUS] local peer : %d\n"
						"[STATUS] remote peer : %d",
				p->adv_flow_id, p->state_local, p->state_peer);
	}

	return str;
}

char *rist_client_get_status(struct rist_client *ctx)
{
	return rist_get_status(&ctx->common);
}

char *rist_server_get_status(struct rist_server *ctx)
{
	return rist_get_status(&ctx->common);
}

int rist_client_destroy(struct rist_client *ctx)
{
	msg(0, ctx->id, RIST_LOG_INFO,
		"[SHUTDOWN] Starting peers cleanup, count %d\n",
		(unsigned) ctx->peer_lst_len);

	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		struct rist_peer *peer = ctx->peer_lst[j];
		peer->shutdown = true;

		msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Removing peer data received event\n");
		/* data receive event */
		if (peer->event_recv) {
			struct evsocket_ctx *evctx = ctx->common.evctx;
			evsocket_delevent(evctx, peer->event_recv);
		}

		msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Removing peer handshake/ping timer\n");
		/* rtcp timer */
		if (peer->send_keepalive) {
			peer->send_keepalive = false;
		}

		msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Closing peer socket on port %d\n", peer->local_port);
		if (peer->sd > -1) {
			udp_Close(peer->sd);
			peer->sd = -1;
		}
		// Do not free the peer here, do it at the end of the rtcp main loop
		//free(peer);
	}

	pthread_rwlock_unlock(peerlist_lock);
	msg(0, ctx->id, RIST_LOG_INFO, "[SHUTDOWN] Peers cleanup complete\n");

	ctx->common.shutdown = true;
	// This last one is not done here but at the exit of client_loop
	//free(ctx);

	return 0;
}

int rist_client_shutdown(struct rist_client *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	rist_client_destroy(ctx);
	return 0;
}

int rist_server_shutdown(struct rist_server *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	ctx->common.shutdown = true;
	return 0;
}
