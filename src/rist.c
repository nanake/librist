/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
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
#include <assert.h>
#ifdef __linux
#include "linux-crypto.h"
#endif

#ifdef _WIN32
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef signed int ssize_t;
#endif
#endif

static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static PTHREAD_START_FUNC(receiver_pthread_protocol,arg);
static PTHREAD_START_FUNC(receiver_pthread_dataout,arg);
static void rist_fsm_init_comm(struct rist_peer *peer);
static void store_peer_settings(const struct rist_peer_config *settings, struct rist_peer *peer);
static struct rist_peer *peer_initialize(const char *url, struct rist_sender *sender_ctx,
										struct rist_receiver *receiver_ctx);

typedef struct rist_url_param {
	char *key;
	char *val;
} rist_url_param_t;


int rist_logs_set(int fd, char *address)
{
	char * url = NULL;
	int ret = rist_set_stats_fd(fd);
	if (ret)
		fprintf(stderr, "[ERROR] Could not set file descriptor to %d\n", fd);

	if (address)
	{
		struct network_url parsed_url;
		url = strdup(address);
		if (parse_url(url, &parsed_url)) {
			msg(0, 0, RIST_LOG_ERROR, "[ERROR] %s / %s\n", parsed_url.error, address);
			ret = -1;
		}
		else
		{
			if (rist_set_stats_socket(parsed_url.hostname, parsed_url.port)) {
				msg(0, 0, RIST_LOG_ERROR, "[ERROR] Could not set socket to: hostname-> %s, port-> %d\n",
					parsed_url.hostname, parsed_url.port);
				ret = -1;
			}
		}
	}

	if (url)
		free(url);
	return ret;
}

static inline char* find(const char *str, char value)
{
	str = strchr( str, value );
	return str != NULL ? (char *)(str + 1) : NULL;
}

static int url_parse_query(char *query, const char* delimiter,
		rist_url_param_t *params, int max_params)
{
	int i = 0;
	char *token = NULL;

	if (!query || *query == '\0')
		return -1;
	if (!params || max_params == 0)
		return 0;

	token = strtok( query, delimiter );
	while (token != NULL && i < max_params) {
		params[i].key = token;
		params[i].val = NULL;
		if ((params[i].val = strchr( params[i].key, '=' )) != NULL) {
			size_t val_len = strlen( params[i].val );
			*(params[i].val) = '\0';
			if (val_len > 1) {
				params[i].val++;
				if (params[i].key[0])
					i++;
			};
		}
		token = strtok( NULL, delimiter );
	}
	return i;
}

static int parse_url_options(const char* url, 	struct rist_peer_config *output_peer_config)
	{
	char* query = NULL;
	struct rist_url_param url_params[32];
	int num_params = 0;
	int i = 0;
	int ret = 0;

	if (!url || !url[0] || !output_peer_config)
		return -1;

	// Parse URL parameters
	query = find( url, '?' );
	if (query) {
		uint32_t clean_url_len = query - url;
		num_params = url_parse_query( query, "&", url_params,
				sizeof(url_params) / sizeof(struct rist_url_param) );
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
				} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MIFACE ) == 0) {
					strncpy((void *)output_peer_config->miface, val, 128-1);
				} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SECRET ) == 0) {
					strncpy((void *)output_peer_config->secret, val, 128-1);
				} else if (strcmp( url_params[i].key, RIST_URL_PARAM_CNAME ) == 0) {
					strncpy((void *)output_peer_config->cname, val, 128-1);
				} else if (strcmp( url_params[i].key, RIST_URL_PARAM_AES_TYPE ) == 0) {
					int temp = atoi( val );
					if (temp == 0 || temp == 128 || temp == 192 || temp == 256) {
						output_peer_config->key_size = temp;
					}
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
						output_peer_config->virt_dst_port = temp;
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
				} else {
					ret = -1;
					fprintf(stderr, "Unknown parameter %s\n", url_params[i].key);
				}
			}
		}
		strncpy((void *)output_peer_config->address, url, clean_url_len >= RIST_MAX_STRING_LONG ? RIST_MAX_STRING_LONG-1 : clean_url_len);
	} else {
		strncpy((void *)output_peer_config->address, url, RIST_MAX_STRING_LONG-1);
	}

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

static int rist_max_jitter_set(struct rist_common_ctx *ctx, int t)
{
	if (t > 0) {
		ctx->rist_max_jitter = t * RIST_CLOCK;
		return 0;
	}

	return -1;
}

int rist_sender_jitter_max_set(struct rist_sender *ctx, int t)
{
	return rist_max_jitter_set(&ctx->common, t);
}

int rist_receiver_jitter_max_set(struct rist_receiver *ctx, int t)
{
	return rist_max_jitter_set(&ctx->common, t);
}

static void init_peer_settings(struct rist_peer *peer)
{
	if (peer->receiver_mode) {
		assert(peer->receiver_ctx != NULL);
		uint32_t recovery_maxbitrate_mbps = peer->config.recovery_maxbitrate < 1000 ? 1 : peer->config.recovery_maxbitrate / 1000;
		// Initial value for some variables
		peer->recovery_buffer_ticks =
			(peer->config.recovery_length_max - peer->config.recovery_length_min) / 2 + peer->config.recovery_length_min;

		if (peer->config.recovery_mode == RIST_RECOVERY_MODE_TIME)
			peer->recovery_buffer_ticks = peer->recovery_buffer_ticks * RIST_CLOCK;

		switch (peer->config.recovery_mode) {
		case RIST_RECOVERY_MODE_BYTES:
			peer->missing_counter_max = peer->recovery_buffer_ticks /
				(sizeof(struct rist_gre_seq) + sizeof(struct rist_rtp_hdr) + sizeof(uint32_t));
		break;
		case RIST_RECOVERY_MODE_TIME:
			peer->missing_counter_max =
				(peer->recovery_buffer_ticks / RIST_CLOCK) * recovery_maxbitrate_mbps /
				(sizeof(struct rist_gre_seq) + sizeof(struct rist_rtp_hdr) + sizeof(uint32_t));
			peer->eight_times_rtt = peer->config.recovery_rtt_min * 8;
		break;
		case RIST_RECOVERY_MODE_DISABLED:
		case RIST_RECOVERY_MODE_UNCONFIGURED:
			msg(peer->receiver_ctx->id, 0, RIST_LOG_ERROR,
				"[ERROR] Sender sent wrong recovery setting.\n");
		break;
		}

		msg(peer->receiver_ctx->id, 0, RIST_LOG_INFO,
			"[INFO] Peer with id #%"PRIu32" was configured with maxrate=%d/%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d buffer_bloat=%d (limit:%d, hardlimit:%d)\n",
			peer->adv_peer_id, peer->config.recovery_maxbitrate, peer->config.recovery_maxbitrate_return, peer->config.recovery_length_min, peer->config.recovery_length_max, peer->config.recovery_reorder_buffer,
			peer->config.recovery_rtt_min, peer->config.recovery_rtt_max, peer->config.buffer_bloat_mode, peer->config.buffer_bloat_limit, peer->config.buffer_bloat_hard_limit);
	}
	else {
		assert(peer->sender_ctx != NULL);
		struct rist_sender *ctx = peer->sender_ctx;
		/* Global context settings */
		if (peer->config.recovery_maxbitrate > ctx->recovery_maxbitrate_max) {
			ctx->recovery_maxbitrate_max = peer->config.recovery_maxbitrate;
		}

		if (peer->config.weight > 0) {
			ctx->total_weight += peer->config.weight;
			msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Peer weight: %lu\n", peer->config.weight);
		}

		/* Set target recover size (buffer) */
		if ((peer->config.recovery_length_max + (2 * peer->config.recovery_rtt_max)) > ctx->sender_recover_min_time) {
			ctx->sender_recover_min_time = peer->config.recovery_length_max + (2 * peer->config.recovery_rtt_max);
			msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Setting buffer size to %zu\n", ctx->sender_recover_min_time);
		}
	}
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

	if (buf != NULL && len > 0)
	{
		b->data = malloc(len + RIST_MAX_PAYLOAD_OFFSET);
		if (!b->data) {
			free(b);
			fprintf(stderr, "OOM\n");
			return NULL;
		}
		memcpy((uint8_t*)b->data + RIST_MAX_PAYLOAD_OFFSET, buf, len);
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
	b->use_seq = 0;

	return b;
}

static int receiver_insert_queue_packet(struct rist_flow *f, struct rist_peer *peer, size_t idx, const void *buf, size_t len, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	/*
		msg(f->receiver_id, f->sender_id, RIST_LOG_INFO,
		"Inserting seq %"PRIu32" len %zu source_time %"PRIu32" at idx %zu\n",
			seq, len, source_time, idx);
	*/
	f->receiver_queue[idx] = rist_new_buffer(buf, len, RIST_PAYLOAD_TYPE_DATA_RAW, seq, source_time, src_port, dst_port);
	if (RIST_UNLIKELY(!f->receiver_queue[idx])) {
		msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR, "[ERROR] Could not create packet buffer inside receiver buffer, OOM, decrease max bitrate or buffer time length\n");
		return -1;
	}
	f->receiver_queue[idx]->peer = peer;
	f->receiver_queue_size += len;
	return 0;
}

static size_t rist_index_dec(struct rist_flow *f,size_t idx)
{
	if (!idx) {
		idx = f->receiver_queue_max;
	}
	return idx - 1;
}

static int receiver_enqueue(struct rist_peer *peer, uint64_t source_time, const void *buf, size_t len, uint32_t seq, uint32_t rtt, bool retry, uint16_t src_port, uint16_t dst_port)
{
	struct rist_flow *f = peer->flow;

//	fprintf(stderr,"receiver enqueue seq is %"PRIu32", source_time %"PRIu64"\n", 
//	seq, source_time);

	if (!f->receiver_queue_has_items) {
		/* we just received our first packet for this flow */
		if (f->receiver_queue_size > 0)
		{
			/* Clear the queue if the queue had data */
			/* f->receiver_queue_has_items can be reset to false when the output queue is emptied */
			msg(f->receiver_id, f->sender_id, RIST_LOG_INFO, 
				"[INFO] Clearing up old %zu bytes of old buffer data\n", f->receiver_queue_size);
			/* Delete all buffer data (if any) */
			empty_receiver_queue(f);
		}
		/* These are used for seq msw extrapolation */
		f->rtp_last_change_time = 0;
		f->rtp_msw = 0;
		/* Calculate and store clock offset with respect to source */
		f->time_offset = (int64_t)RIST_CLOCK + (int64_t)timestampNTP_u64() - (int64_t)source_time;
		/* This ensures the next packet does not trigger nacks */
		f->last_seq_output = seq - 1;
		f->last_seq_found = seq;
		/* This will synchronize idx and seq so we can insert packets into receiver buffer based on seq number */
		size_t idx_initial = seq % f->receiver_queue_max;
		f->receiver_queue_output_idx = idx_initial;
		msg(f->receiver_id, f->sender_id, RIST_LOG_INFO,
			"[INIT] Storing first packet seq %"PRIu32", idx %zu, %"PRIu64", offset %"PRId64" ms\n", 
			seq, idx_initial, source_time, peer->flow->time_offset/RIST_CLOCK);
		receiver_insert_queue_packet(f, peer, idx_initial, buf, len, seq, source_time, src_port, dst_port);
		/* reset stats */
		memset(&f->stats_instant, 0, sizeof(f->stats_instant));
		f->receiver_queue_has_items = true;
		return 0; // not a dupe
	}

	// Now, get the new position and check what is there
	size_t idx = seq % f->receiver_queue_max;
	if (f->receiver_queue[idx]) {
		// TODO: record stats
		struct rist_buffer *b = f->receiver_queue[idx];
		if (b->seq == seq) {
			msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR, "Dupe! %"PRIu32"/%zu\n", seq, idx);
			peer->stats_receiver_instant.dups++;
			return 1;
		}
		else {
			msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR, "Invalid Dupe (possible seq discontinuity)! %"PRIu32", freeing buffer ...\n", seq);
			free(b->data);
			free(b);
			f->receiver_queue[idx] = NULL;
		}
	}

	/* Now, we insert the packet into receiver queue */
	if (receiver_insert_queue_packet(f, peer, idx, buf, len, seq, source_time, src_port, dst_port)) {
		// only error is OOM, safe to exit here ...
		return 0;
	}

	// Check for missing data and queue retries
	if (!retry) {
		uint32_t current_seq = seq - 1;
		if (f->short_seq)
			current_seq = current_seq & (UINT16_MAX);

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
		if (source_time > f->max_source_time)
			f->max_source_time = source_time;
		if (diff > peer->missing_counter_max) {
			// This triggers false positives when there is packet reordering. 
			// Use the timestamp as a secondary check and ignore packets in the past, i.e. reordered straglers
			if (source_time < f->max_source_time) {
				// Only print this message when they are older than 10% buffer size
				if (((f->max_source_time - source_time) * 10) > f->recovery_buffer_ticks) {
					uint64_t age = (f->max_source_time - source_time)/RIST_CLOCK;
					msg(f->receiver_id, f->sender_id, RIST_LOG_WARN,
						"[WARNING] Old out of order packet received, seq %"PRIu32" / age %"PRIu64" ms\n",
						current_seq, age);
				}
			}
			else {
				msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR,
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
					msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR,
						"[ERROR] Our output index %"PRIu32" and missing search index %"PRIu32" are too far from each other (%"PRIu32"), resetting the missing search index\n",
						f->last_seq_output, f->last_seq_found, diff2);
					f->last_seq_found = seq;
				}
			}
			return 0;
		}

		/* check for missing packets */
		// We start looking at the point of this insert and work our way backwards until we reach
		// the last checkpoint (seq #). Any holes encountered are queued in missing array.
		size_t current_idx = rist_index_dec(f, idx);
		struct rist_buffer *b = f->receiver_queue[current_idx];
		while (!b || f->last_seq_found != current_seq) {
			if (f->missing_counter > peer->missing_counter_max) {
				msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR,
					"[ERROR] Retry buffer is already too large (%d) for the configured "
							"bandwidth ... ignoring missing packet(s).\n",
					f->missing_counter);
				break;
			} else if (!b) {
				if (!peer->buffer_bloat_active) {
					rist_receiver_missing(f, peer, current_seq, rtt);
				} else {
					msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR,
						"[ERROR] Link has collapsed. Not queuing new retries until it recovers.\n");
					break;
				}
			}
			current_seq--;
			if (f->short_seq)
				current_seq = (uint16_t)current_seq;
			current_idx = rist_index_dec(f, current_idx);
			b = f->receiver_queue[current_idx];
			if (current_idx == idx) {
				msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR, "[ERROR] Did not find any data after a full counter loop (missing loop) (%zu)\n", f->receiver_queue_size);
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
	if (p->parent) {
		struct rist_peer *peer = p->parent;
		if (!peer->child)
			peer->child = p;
		else
		{
			struct rist_peer *child = peer->child;
			while (child)
			{
				if (!child->sibling_next)
				{
					child->sibling_next = p;
					p->sibling_prev = child;
					break;
				}
				child = child->sibling_next;
			}
		}
		++peer->child_alive_count;
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

	if (b->nack_count >= peer->config.buffer_bloat_hard_limit) {
		msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR, "[ERROR] Datagram %"PRIu32
				" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu, buffer_bloat_hard_limit %d, buffer_bloat_mode %d, stats_receiver_total.recovered_average %d\n",
					b->seq,
					b->nack_count,
					(now - b->insertion_time) / RIST_CLOCK,
					b->nack_count,
					peer->config.buffer_bloat_hard_limit,
					peer->config.buffer_bloat_mode,
					peer->stats_receiver_total.recovered_average);
		return 8;
	} else {
		if ((uint64_t)(now - b->insertion_time) > peer->recovery_buffer_ticks) {
			msg(f->receiver_id, f->sender_id, RIST_LOG_ERROR,
				"[ERROR] Datagram %" PRIu32 " is missing but it is too late (%" PRIu64
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

			// TODO: make this 10% overhead configurable?
			// retry more when we are running out of time (proportional)
			/* start with 1.1 * 1000 and go down from there */
			//uint32_t ratio = 1100 - (b->nack_count * 1100)/(2*b->peer->config.buffer_bloat_hard_limit);
			//b->next_nack = now + (uint64_t)rtt * (uint64_t)ratio * (uint64_t)RIST_CLOCK;
			b->next_nack = now + ((uint64_t)rtt * (uint64_t)1100 * (uint64_t)RIST_CLOCK) / 1000;
			b->nack_count++;

			if (get_cctx(peer)->debug)
				msg(f->receiver_id, f->sender_id, RIST_LOG_DEBUG, "[DEBUG] Datagram %"PRIu32
					" is missing, sending NACK!, next retry in %"PRIu64"ms, age is %"PRIu64"ms, retry #%lu, max_size is %"PRIu64"ms\n",
					b->seq, (b->next_nack - now) / RIST_CLOCK,
					(now - b->insertion_time) / RIST_CLOCK,
					b->nack_count,
					peer->recovery_buffer_ticks / RIST_CLOCK);

			// update peer information
			peer->nacks.array[peer->nacks.counter] = b->seq;
			peer->nacks.counter ++;
			peer->stats_receiver_instant.retries++;
		}
	}

	return 0;
}

int rist_receiver_oob_read(struct rist_receiver *ctx, const struct rist_oob_block **oob_block)
{
	RIST_MARK_UNUSED(oob_block);
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null on rist_receiver_oob_read call!\n");
		return -1;
	}
	msg(0, 0, RIST_LOG_ERROR, "[ERROR] rist_receiver_oob_read not implemented!\n");
	return 0;
}

int rist_parse_address(const char *url, const struct rist_peer_config **peer_config)
{

	int ret = 0;
	if (*peer_config == NULL)
	{
		// Default options on new struct
		struct rist_peer_config *output_peer_config = calloc(1, sizeof(struct rist_peer_config));
		output_peer_config->version = RIST_PEER_CONFIG_VERSION;
		output_peer_config->virt_dst_port = RIST_DEFAULT_VIRT_DST_PORT;
		output_peer_config->recovery_mode = RIST_DEFAULT_RECOVERY_MODE;
		output_peer_config->recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE;
		output_peer_config->recovery_maxbitrate_return = RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN;
		output_peer_config->recovery_length_min = RIST_DEFAULT_RECOVERY_LENGHT_MIN;
		output_peer_config->recovery_length_max = RIST_DEFAULT_RECOVERY_LENGHT_MAX;
		output_peer_config->recovery_reorder_buffer = RIST_DEFAULT_RECOVERY_REORDER_BUFFER;
		output_peer_config->recovery_rtt_min = RIST_DEFAULT_RECOVERY_RTT_MIN;
		output_peer_config->recovery_rtt_max = RIST_DEFAULT_RECOVERY_RTT_MAX;
		output_peer_config->buffer_bloat_mode = RIST_DEFAULT_BUFFER_BLOAT_MODE;
		output_peer_config->buffer_bloat_limit = RIST_DEFAULT_BUFFER_BLOAT_LIMIT;
		output_peer_config->buffer_bloat_hard_limit = RIST_DEFAULT_BUFFER_BLOAT_HARD_LIMIT;
		ret = parse_url_options(url, output_peer_config);
		*peer_config = output_peer_config;
	}
	else
	{
		// Update incoming object with url data
		struct rist_peer_config *existing_peer_config = (void *)*peer_config;
		ret = parse_url_options(url, existing_peer_config);
		*peer_config = existing_peer_config;
	}

	return ret;
}

int rist_receiver_data_read(struct rist_receiver *ctx, const struct rist_data_block **data_buffer, int timeout)
{
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null on rist_receiver_data_read call!\n");
		return -1;
	}

	const struct rist_data_block *data_block = NULL;

	pthread_rwlock_wrlock(&ctx->dataout_fifo_queue_lock);
	if (ctx->dataout_fifo_queue_read_index != ctx->dataout_fifo_queue_write_index) {
		data_block = ctx->dataout_fifo_queue[ctx->dataout_fifo_queue_read_index];
		ctx->dataout_fifo_queue_read_index = (ctx->dataout_fifo_queue_read_index + 1) % RIST_DATAOUT_QUEUE_BUFFERS;
		if (data_block) {
			//msg(0, 0, RIST_LOG_INFO, "[INFO]data queue level %u -> %zu bytes, index %u!\n", ctx->dataout_fifo_queue_counter,
			//		ctx->dataout_fifo_queue_bytesize, ctx->dataout_fifo_queue_read_index);
			ctx->dataout_fifo_queue_counter--;
			ctx->dataout_fifo_queue_bytesize -= data_block->payload_len;
		}
	}
	pthread_rwlock_unlock(&ctx->dataout_fifo_queue_lock);

	if (data_block == NULL && timeout > 0) {
		pthread_mutex_lock(&(ctx->mutex));
		pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), timeout);
		pthread_mutex_unlock(&(ctx->mutex));
	}

	*data_buffer = data_block;

	return 0;
}

static struct rist_data_block *new_data_block(struct rist_data_block *output_buffer_current, struct rist_buffer *b, uint8_t *payload, uint32_t flow_id, uint32_t flags)
{
	struct rist_data_block *output_buffer;
	if (output_buffer_current)
		output_buffer = output_buffer_current;
	else
		output_buffer = calloc(1, sizeof(struct rist_data_block));
	output_buffer->peer = b->peer;
	output_buffer->flow_id = flow_id;
	uint8_t *newbuffer;
	if (output_buffer->payload && b->size != output_buffer->payload_len) {
		newbuffer = realloc((void *)output_buffer->payload, b->size);
	} else if (!output_buffer->payload) {
		newbuffer = malloc(b->size);
	}
	else {
		newbuffer = (void *)output_buffer->payload;
	}

	memcpy(newbuffer, payload, b->size);
	output_buffer->payload = newbuffer;
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
	while (f->receiver_queue_size > 0) {
		// Find the first non-null packet in the queuecounter loop
		struct rist_buffer *b = f->receiver_queue[f->receiver_queue_output_idx];
		if (!b) {
			//msg(ctx->id, 0, RIST_LOG_ERROR, "\tLooking for first non-null packet (%zu)\n", f->receiver_queue_size);
			size_t holes = 0;
			size_t counter = 0;
			counter = f->receiver_queue_output_idx;
			while (!b) {
				counter = (counter + 1) % f->receiver_queue_max;
				holes++;
				b = f->receiver_queue[counter];
				if (counter == f->receiver_queue_output_idx) {
					// TODO: with the check below, this should never happen
					msg(ctx->id, 0, RIST_LOG_WARN, "[ERROR] Did not find any data after a full counter loop (%zu)\n", f->receiver_queue_size);
					// if the entire buffer is empty, something is very wrong, reset the queue ...
					f->receiver_queue_has_items = false;
					// exit the function and wait 5ms (max jitter time)
					return;
				}
				if (holes > f->missing_counter_max)
				{
					msg(ctx->id, 0, RIST_LOG_WARN, "[ERROR] Did not find any data after %zu holes (%zu bytes in queue)\n",
						holes, f->receiver_queue_size);
					break;
				}
			}
			f->stats_instant.lost += holes;
			f->receiver_queue_output_idx = counter;
			msg(ctx->id, 0, RIST_LOG_ERROR,
				"**** [LOST] Empty buffer element, flushing %"PRIu32" hole(s), now at index %zu, size is %zu\n", 
				holes, counter, f->receiver_queue_size);
		}
		if (b) {

			uint64_t now = timestampNTP_u64();
			if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {

				uint64_t delay = (now - b->time);
				int64_t target_time = (int64_t)b->source_time + f->time_offset;
				uint64_t delay_rtc = now > (uint64_t)target_time ? (now - (uint64_t)target_time) : 0;

				// Warning for a possible timing bug (the source has an improperly scaled timestamp)
				if ((delay * 10) < recovery_buffer_ticks)
				{
					// TODO: quiet this down based on some other parameter that measures proper behavior,
					// i.e. buffer filling up after it has been initialized. Perhaps print them
					// only after one buffer length post flow initialization
					msg(ctx->id, 0, RIST_LOG_WARN,
						"**** [WARNING] Packet %"PRIu32" is too young %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", is buffer building up?\n",
						b->seq, delay / RIST_CLOCK, delay_rtc / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK);
				}
				//else
				//	msg(ctx->id, 0, RIST_LOG_WARN,
				//		"**** [WARNING] Packet %"PRIu32" is ok %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", is buffer building up?\n",
				//		b->seq, delay / RIST_CLOCK, delay_rtc / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK);

				if (RIST_UNLIKELY(delay > (2 * recovery_buffer_ticks))) {
					// Double check the age of the packet within our receiver queue and empty if necessary
					// Safety net for discontinuities in source timestamp or sequence numbers
					msg(ctx->id, 0, RIST_LOG_WARN,
						"**** [WARNING] Packet %"PRIu32" (%zu bytes) is too old %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", offset = %"PRId64" ms, releasing from output queue ...\n",
						b->seq, b->size, delay / RIST_CLOCK, delay_rtc / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK, f->time_offset / RIST_CLOCK);
				}
				else if (delay_rtc <= recovery_buffer_ticks) {
					// This is how we keep the buffer at the correct level
					//msg(ctx->id, 0, RIST_LOG_WARN, "age is %"PRIu64"/%"PRIu64" < %"PRIu64", size %zu\n", 
					//	delay_rtc / RIST_CLOCK , delay / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK, f->receiver_queue_size);
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
				if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {
					// TODO: support passing of discontinuities (missing seq)
					// flags |= BLOCK_FLAG_DISCONTINUITY where BLOCK_FLAG_DISCONTINUITY = 1
					uint32_t flags = 0;
					/* insert into fifo queue */
					uint8_t *payload = b->data;
					pthread_rwlock_wrlock(&ctx->dataout_fifo_queue_lock);
					ctx->dataout_fifo_queue[ctx->dataout_fifo_queue_write_index] = new_data_block(
							ctx->dataout_fifo_queue[ctx->dataout_fifo_queue_write_index], b, 
							&payload[RIST_MAX_PAYLOAD_OFFSET], f->flow_id, flags);
					if (ctx->receiver_data_callback) {
						// send to callback synchronously
						ctx->receiver_data_callback(ctx->receiver_data_callback_argument, 
							ctx->dataout_fifo_queue[ctx->dataout_fifo_queue_write_index]);
					}
					ctx->dataout_fifo_queue_write_index = (ctx->dataout_fifo_queue_write_index + 1) % RIST_DATAOUT_QUEUE_BUFFERS;
					ctx->dataout_fifo_queue_bytesize += b->size;
					ctx->dataout_fifo_queue_counter = (ctx->dataout_fifo_queue_counter + 1) % RIST_DATAOUT_QUEUE_BUFFERS;
					pthread_rwlock_unlock(&ctx->dataout_fifo_queue_lock);
					// Wake up the fifo read thread (poll)
					if (pthread_cond_signal(&(ctx->condition)))
						msg(ctx->id, 0, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");
				}
			}
			//else
			//	fprintf(stderr, "rtcp skip at %"PRIu32", just removing it from queue\n", b->seq);

			f->last_seq_output = b->seq;
			f->receiver_queue_size -= b->size;
			f->receiver_queue[f->receiver_queue_output_idx] = NULL;
			f->receiver_queue_output_idx = (f->receiver_queue_output_idx + 1) % f->receiver_queue_max;
			if (b->size)
				free(b->data);
			free(b);
			if (f->receiver_queue_size == 0) {
				uint64_t delta = now - f->last_output_time;
				msg(ctx->id, 0, RIST_LOG_WARN, "[WARNING] Buffer is empty, it has been for %"PRIu64" < %"PRIu64" (ms)!\n",
				delta / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK);
				// if the entire buffer is empty, something is very wrong, reset the queue ...
				if (delta > recovery_buffer_ticks)
				{
					msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] stream is dead, re-initializing flow\n");
					f->receiver_queue_has_items = false;
				}
				// exit the function and wait 5ms (max jitter time)
				return;
			}
			f->last_output_time = now;
		}
	}
}

static void send_nack_group(struct rist_receiver *ctx, struct rist_flow *f, struct rist_peer *peer)
{
	// Now actually send all the nack IP packets for this flow (the above routing will process/group them)
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	rist_send_nacks(f, peer);
	pthread_rwlock_unlock(peerlist_lock);
	// TODO: this lock should be by flow ... not global!
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
	int empty = 0;
	uint32_t seq_msb = 0;
	if (mb)
		seq_msb = mb->seq >> 16;

	while (mb) {
		int remove_from_queue_reason = 0;
		struct rist_peer *peer = mb->peer;
		ssize_t idx = mb->seq % f->receiver_queue_max;
		if (f->receiver_queue[idx]) {
			if (f->receiver_queue[idx]->seq == mb->seq) {
				// We filled in the hole already ... packet has been recovered
				remove_from_queue_reason = 3;
				peer->stats_receiver_instant.recovered++;
				switch(mb->nack_count) {
				case 0:
					peer->stats_receiver_instant.reordered++;
				break;
				case 1:
					peer->stats_receiver_instant.recovered_0nack++;
				break;
				case 2:
					peer->stats_receiver_instant.recovered_1nack++;
				break;
				case 3:
					peer->stats_receiver_instant.recovered_2nack++;
				break;
				case 4:
					peer->stats_receiver_instant.recovered_3nack++;
				break;
				default:
					peer->stats_receiver_instant.recovered_morenack++;
				break;
				}
				peer->stats_receiver_instant.recovered_sum += mb->nack_count;
			}
			else {
				// Message with wrong seq!!!
				msg(ctx->id, 0, RIST_LOG_ERROR,
					"[ERROR] Retry queue has the wrong seq %"PRIu32" != %"PRIu32", removing ...\n", 
					f->receiver_queue[idx]->seq, mb->seq);
				remove_from_queue_reason = 4;
				peer->stats_receiver_instant.missing--;
				goto nack_loop_continue;
			}
		} else if (peer->buffer_bloat_active) {
			if (peer->config.buffer_bloat_mode == RIST_BUFFER_BLOAT_MODE_AGGRESSIVE) {
				if (empty == 0) {
					msg(ctx->id, 0, RIST_LOG_ERROR,
						"[ERROR] Retry queue is too large, %d, collapsed link (%u), flushing all nacks ...\n", f->missing_counter,
						peer->stats_receiver_total.recovered_average/8);
				}
				remove_from_queue_reason = 5;
				empty = 1;
			} else if (peer->config.buffer_bloat_mode == RIST_BUFFER_BLOAT_MODE_NORMAL) {
				if (mb->nack_count > 4) {
					if (empty == 0) {
						msg(ctx->id, 0, RIST_LOG_ERROR,
							"[ERROR] Retry queue is too large, %d, collapsed link (%u), flushing old nacks (%u > %u) ...\n",
								f->missing_counter, peer->stats_receiver_total.recovered_average/8, mb->nack_count, 4);
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

static int rist_set_manual_sockdata(struct rist_peer *peer, const struct rist_peer_config *config)
{
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	peer->address_family = config->address_family;
	peer->listening = !config->initiate_conn;
	const char *hostname = config->address;
	struct addrinfo *ai, *orig;
	struct sockaddr *res = NULL;
	int ret;
	if ((!hostname || !*hostname) && peer->listening) {
		if (peer->address_family == AF_INET) {
			msg(receiver_id, sender_id, RIST_LOG_INFO, "[INFO] No hostname specified: listening to 0.0.0.0\n");
			peer->address_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)&peer->u.address)->sin_family = AF_INET;
			((struct sockaddr_in *)&peer->u.address)->sin_addr.s_addr = INADDR_ANY;
		} else {
			msg(receiver_id, sender_id, RIST_LOG_INFO, "[INFO] No hostname specified: listening to [::0]\n");
			peer->address_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in6 *)&peer->u.address)->sin6_family = AF_INET6;
			((struct sockaddr_in6 *)&peer->u.address)->sin6_addr = in6addr_any;
		}
	} else {
		ret = getaddrinfo(hostname, NULL, NULL, &orig);
		if (ret != 0) {
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Error trying to resolve hostname %s\n", hostname);
			goto err;
		}
		for (ai = orig; ai != NULL; ai = ai->ai_next) {
			if (peer->address_family == AF_LOCAL) {
				peer->address_family = ai->ai_family;
				((struct sockaddr_in *)&peer->u.address)->sin_family = ai->ai_family;
			}
			if (peer->address_family == ai->ai_family) {
				res = ai->ai_addr;
				if (ai->ai_family == AF_INET) {
					peer->address_len = sizeof(struct sockaddr_in);
					((struct sockaddr_in *)&peer->u.address)->sin_family = AF_INET;
					memcpy(&peer->u.address, res, peer->address_len);
					break;
				}
				if (ai->ai_family == AF_INET6) {
					peer->address_len = sizeof(struct sockaddr_in6);
					((struct sockaddr_in6 *)&peer->u.address)->sin6_family = AF_INET6;
					memcpy(&peer->u.address, res, peer->address_len);
					break;
				}
			}
			// This loops until it finds the last non-null entry
		}
		freeaddrinfo(orig);
		if (!res || (peer->address_family == AF_LOCAL)) {
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Could not find IPv4/6 (%d) for hostname\n", peer->address_family);
			goto err;
		}
	}

	if (config->address_family == AF_INET) {
		((struct sockaddr_in*)&peer->u.address)->sin_port = htons(config->physical_port);
	}
	else if (config->address_family == AF_INET6) {
		((struct sockaddr_in6*)&peer->u.address)->sin6_port = htons(config->physical_port);
	}
	if (peer->listening) {
		peer->local_port = config->physical_port;
	}
	else {
		peer->remote_port = config->physical_port;
	}

	return 0;

err:
	peer->address_family = AF_LOCAL;
	peer->address_len = 0;
	return -1;
}

static struct rist_peer *rist_receiver_peer_insert_local(struct rist_receiver *ctx, 
		const struct rist_peer_config *config)
{
	if (config->key_size) { 
		if (config->key_size != 128 && config->key_size != 192 && config->key_size != 256) {
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Invalid encryption key length: %d\n", config->key_size);
			return NULL;
		}
		if (!strlen(config->secret)) {

			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Invalid secret passphrase\n");
			return NULL;
		}
		msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Using %d bits secret key\n", config->key_size);
	}
	else {
		msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Encryption is disabled for this peer\n");
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
		p->key_secret.key_size = config->key_size;
		strncpy(&p->key_secret.password[0], config->secret, RIST_MAX_STRING_SHORT);
		p->key_secret.key_rotation = config->key_rotation;
#ifdef __linux
		linux_crypto_init(&p->cryptoctx);
		if (p->cryptoctx)
			msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Crypto AES-NI found and activated\n");
#endif
	}

	if (config->keepalive_interval > 0) {
		p->rtcp_keepalive_interval = config->keepalive_interval * RIST_CLOCK;
	}

	if (config->session_timeout > 0) {
		p->session_timeout = config->session_timeout * RIST_CLOCK;
	}
	else {
		p->session_timeout = config->recovery_length_max * RIST_CLOCK;
	}

	/* Initialize socket */
	rist_create_socket(p);
	if (p->sd <= 0) {
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create socket\n");
		free(p);
		return NULL;
	}

	if (config->virt_dst_port != 0) {
		p->remote_port = config->virt_dst_port + 1;
	}

	store_peer_settings(config, p);

	if (!p->listening)
		p->adv_peer_id = ++ctx->common.peer_counter;

	return p;
}

int rist_receiver_peer_create(struct rist_receiver *ctx, 
		struct rist_peer **peer, const struct rist_peer_config *config)
{
	struct rist_peer *p_rtcp;
	struct rist_peer *p = rist_receiver_peer_insert_local(ctx, config);
	if (!p)
		return -1;

	if (ctx->common.profile == RIST_PROFILE_SIMPLE)
	{
		if (p->local_port % 2 != 0) {
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create peer, port must be even!\n");
			udp_Close(p->sd);
			free(p);
			return -1;
		}

		sprintf((char *)config->address, "%s:%d", p->url, p->local_port + 1);
		p_rtcp = rist_receiver_peer_insert_local(ctx, config);
		if (!p_rtcp)
		{
			udp_Close(p->sd);
			free(p);
			return -1;
		}
		p_rtcp->is_rtcp = true;
		msg(ctx->id, 0, RIST_LOG_INFO, "[INFO] Created RTCP peer: host %s, port %d, new_url %s, %"PRIu32"\n", p_rtcp->url, p_rtcp->local_port, config->address, p_rtcp->adv_peer_id);
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

	*peer = p;

	return 0;
}

/* PEERS are created at startup. The default state is RIST_PEER_STATE_IDLE
 * This function will initiate the connection to the peer if a peer address is available.
 * If no address is configured for the endpoint, the peer is put in wait mode.
 */
static void rist_fsm_init_comm(struct rist_peer *peer)
{
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	peer->state_peer = RIST_PEER_STATE_PING;

	if (!peer->receiver_mode) {
		if (peer->listening) {
			/* sender mode listening/waiting for receiver */
			msg(receiver_id, sender_id, RIST_LOG_INFO,
				"[INIT] Initialized Sender Peer, listening mode ...\n");
		} else {
			/* sender mode connecting to receiver */
			msg(receiver_id, sender_id, RIST_LOG_INFO,
				"[INIT] Initialized Sender Peer, connecting to receiver ...\n");
		}
	} else {
		if (peer->listening) {
			/* receiver mode listening/waiting for sender */
			msg(receiver_id, sender_id, RIST_LOG_INFO,
				"[INIT] Initialized Receiver Peer, listening mode ...\n");
		} else {
			/* receiver mode connecting to sender */
			msg(receiver_id, sender_id, RIST_LOG_INFO,
				"[INIT] Initialized Receiver Peer, connecting to sender ...\n");
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
			msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] Enabling keepalive for peer %"PRIu32"\n", peer->adv_peer_id);
			peer->send_keepalive = true;
		}

		/* call it the first time manually to speed up the handshake */
		rist_peer_rtcp(NULL, peer);
	}
}

void rist_shutdown_peer(struct rist_peer *peer)
{
	// TODO: this function is incomplete ...

	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Shutting down peer\n");
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
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	peer->state_peer = RIST_PEER_STATE_CONNECT;
	peer->state_local = RIST_PEER_STATE_CONNECT;

	msg(receiver_id, sender_id, RIST_LOG_INFO,
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
			f->stats_instant.avg_count++;
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

void rist_calculate_bitrate_sender(size_t len, struct rist_bandwidth_estimation *bw)
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

static void rist_sender_recv_nack(struct rist_peer *peer,
		uint32_t flow_id, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, 
		size_t payload_len, uint32_t nack_seq_msb)
{
	RIST_MARK_UNUSED(flow_id);
	RIST_MARK_UNUSED(src_port);
	RIST_MARK_UNUSED(dst_port);

	assert(payload_len >= sizeof(struct rist_rtcp_hdr));
	assert(peer->sender_ctx != NULL);
	intptr_t sender_id = peer->sender_ctx->id;

	if (peer->receiver_mode) {
		msg(0, sender_id, RIST_LOG_ERROR,
			"[ERROR] Received nack packet on receiver, ignoring ...\n");
		return;
	} else if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {
		msg(0, sender_id, RIST_LOG_ERROR,
			"[ERROR] Received nack packet but handshake is still pending, ignoring ...\n");
		return;
	}

	struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *) payload;
	uint32_t i,j;

	if ((rtcp->flags & 0xc0) != 0x80) {
		msg(0, sender_id, RIST_LOG_ERROR, "[ERROR] Malformed nack packet flags=%d.\n", rtcp->flags);
		return;
	}

	if (rtcp->ptype == PTYPE_NACK_CUSTOM) {
		struct rist_rtcp_nack_range *rtcp_nack = (struct rist_rtcp_nack_range *) payload;
		if (memcmp(rtcp_nack->name, "RIST", 4) != 0) {
			msg(0, sender_id, RIST_LOG_ERROR, "[NACK] Non-Rist nack packet (%s).\n", rtcp_nack->name);
			return; /* Ignore app-type not RIST */
		}
		uint16_t nrecords =	ntohs(rtcp->len) - 2;
		//msg(0, sender_id, RIST_LOG_ERROR, "[ERROR] Nack (RbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t additional;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_range) + i * sizeof(struct rist_rtp_nack_record));
			missing =  ntohs(nr->start);
			additional = ntohs(nr->extra);
			rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//msg(0, sender_id, RIST_LOG_ERROR, "[ERROR] Record %"PRIu32": base packet: %"PRIu32" range len: %d\n", i, nack_seq_msb + missing, additional);
			for (j = 0; j < additional; j++) {
				rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing + j + 1, peer);
			}
		}
	} else if (rtcp->ptype == PTYPE_NACK_BITMASK) {
		struct rist_rtcp_nack_bitmask *rtcp_nack = (struct rist_rtcp_nack_bitmask *) payload;
		(void)rtcp_nack;
		uint16_t nrecords =	ntohs(rtcp->len) - 2;
		//msg(0, sender_id, RIST_LOG_ERROR, "[ERROR] Nack (BbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t bitmask;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_bitmask) + i * sizeof(struct rist_rtp_nack_record));
			missing = ntohs(nr->start);
			bitmask = ntohs(nr->extra);
			rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//msg(0, sender_id, RIST_LOG_ERROR, "[ERROR] Record %"PRIu32": base packet: %"PRIu32" bitmask: %04x\n", i, nack_seq_msb + missing, bitmask);
			for (j = 0; j < 16; j++) {
				if ((bitmask & (1 << j)) == (1 << j))
					rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + missing + j + 1, peer);
			}
		}
	} else {
		msg(0, sender_id, RIST_LOG_ERROR, "[ERROR] Unsupported Type %d\n", rtcp->ptype);
	}

}

static struct rist_peer *rist_find_rtcp_peer(struct rist_receiver *ctx, struct rist_flow *f, uint16_t data_port)
{
	RIST_MARK_UNUSED(ctx);
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

static bool rist_receiver_authenticate(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, struct rist_buffer *payload)
{
	RIST_MARK_UNUSED(seq);
	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (peer->config.recovery_mode == RIST_RECOVERY_MODE_UNCONFIGURED) {
		// TODO: copy settings from special rtcp packet if it exists instead of peer parent (advanced mode)
	}

	// Check to see if this peer's flowid changed
	// (sender was restarted and we are in callback mode or sender happened to reuse the same port)
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
		peer->flow = NULL;
	}

	if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {

		// the peer could already be part of a flow and it came back after timing out
		if (!peer->flow) {
			if (rist_receiver_associate_flow(peer, flow_id) != 1) {
				msg(ctx->id, 0, RIST_LOG_ERROR,
					"[ERROR] Could not created/associate peer to flow.\n");
				return false;
			}
		}

		if (peer->flow) {
			// We do multiple ifs to make these checks stateless
			if (!peer->flow->receiver_thread) {
				// Make sure this data out thread is created only once per flow
				if (pthread_create(&(peer->flow->receiver_thread), NULL, receiver_pthread_dataout, (void *)peer->flow) != 0) {
					msg(ctx->id, 0, RIST_LOG_ERROR,
						"[ERROR] Could not created receiver data output thread.\n");
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
					if (ctx->common.profile > RIST_PROFILE_SIMPLE)
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

static void rist_receiver_recv_data(struct rist_peer *peer, uint32_t seq, uint32_t flow_id,
		uint64_t source_time, struct rist_buffer *payload, bool retry)
{
	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {
		if (!rist_receiver_authenticate(peer, seq, flow_id, payload)) {
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
	} else if (peer->config.recovery_mode == RIST_RECOVERY_MODE_UNCONFIGURED) {
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

	//	Just some debug output
	//	if ((seq - peer->flow->last_seq_output) != 1)
	//		msg(receiver_id, sender_id, RIST_LOG_ERROR, "Received seq %"PRIu32" and last %"PRIu32"\n\n\n", seq, peer->flow->last_seq_output);

	/**************** WIP *****************/
	/* * * * * * * * * * * * * * * * * * * */
	/** Heuristics for receiver  * * * * * */
	/* * * * * * * * * * * * * * * * * * * */
	/**************** WIP *****************/
	peer->stats_receiver_instant.recv++;

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

	// Wake up output thread when data comes in
	if (pthread_cond_signal(&(peer->flow->condition)))
		msg(ctx->id, 0, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");

	pthread_rwlock_wrlock(&(peer->flow->queue_lock));
	if (!receiver_enqueue(peer, source_time, payload->data, payload->size, seq, rtt, retry, payload->src_port, payload->dst_port)) {
		rist_calculate_bitrate(peer, payload->size, &peer->bw); // update bitrate only if not a dupe
	}
	pthread_rwlock_unlock(&(peer->flow->queue_lock));
}

static void rist_receiver_recv_rtcp(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, uint16_t src_port, uint16_t dst_port)
{
	RIST_MARK_UNUSED(flow_id);
	RIST_MARK_UNUSED(src_port);
	RIST_MARK_UNUSED(dst_port);

	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (peer->flow && peer->advanced) {
		// We must insert a placeholder into the queue to prevent counting it as a hole during missing packet search
		size_t idx = seq % peer->flow->receiver_queue_max;
		struct rist_buffer *b = peer->flow->receiver_queue[idx];
		if (b)
		{
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] RTCP buffer placeholder had data!!! seq=%"PRIu32", buf_seq=%"PRIu32"\n",
				seq, b->seq);
			free(b->data);
			free(b);
			peer->flow->receiver_queue[idx] = NULL;
		}
		peer->flow->receiver_queue[idx] = rist_new_buffer(NULL, 0, RIST_PAYLOAD_TYPE_RTCP, seq, 0, 0, 0);
		if (RIST_UNLIKELY(!peer->flow->receiver_queue[idx])) {
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create packet buffer inside receiver buffer, OOM, decrease max bitrate or buffer time length\n");
			return;
		}
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

static void rist_recv_rtcp(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, struct rist_buffer *payload)
{
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	uint8_t *pkt;
	uint8_t  ptype;
	uint16_t processed_bytes = 0;
	uint16_t records;
	uint8_t subtype;
	uint32_t nack_seq_msb = 0;

	while (processed_bytes < payload->size) {
		pkt = (uint8_t*)payload->data + processed_bytes;
		struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)pkt;
		/* safety checks */
		uint16_t bytes_left = payload->size - processed_bytes + 1;

		if ( bytes_left < 4 )
		{
			/* we must have at least 4 bytes */
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Rist rtcp packet must have at least 4 bytes, we have %d\n", 
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
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Malformed feedback packet, expecting %u bytes in the" \
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
				else if (subtype != NACK_FMT_RANGE) {
					msg(receiver_id, sender_id, RIST_LOG_DEBUG, "[DEBUG] Unsupported rtcp custom subtype %d, ignoring ...\n", subtype);
					break;
				}
				RIST_FALLTHROUGH;
			case PTYPE_NACK_BITMASK:
				rist_sender_recv_nack(peer, flow_id, payload->src_port, payload->dst_port, pkt, bytes_left, nack_seq_msb);
				break;
			case PTYPE_RR:
				/*
				if (p_sys->b_ismulticast == false)
					process_rr(f, pkt, len);
				*/
				break;

			case PTYPE_SDES:
			{
				peer->stats_sender_instant.received++;
				peer->last_rtcp_received = timestampNTP_u64();
				if (peer->dead) {
					pthread_rwlock_t *peerlist_lock = &get_cctx(peer)->peerlist_lock;
					pthread_rwlock_wrlock(peerlist_lock);
					peer->dead = false;
					if (peer->parent)
						++peer->parent->child_alive_count;
					pthread_rwlock_unlock(peerlist_lock);
					msg(receiver_id, sender_id, RIST_LOG_INFO,
						"[INFO] Peer %d was dead and it is now alive again\n", peer->adv_peer_id);
				}
				//if (p_sys->b_ismulticast == false)
				//{
					int8_t name_length = pkt[9];
					if (name_length > bytes_left)
					{
						/* check for a sane number of bytes */
						msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Malformed SDES packet, wrong cname len %u, got a " \
							"buffer of %u bytes.\n", name_length, bytes_left);
						return;
					}
					if (memcmp(pkt + RTCP_SDES_SIZE, peer->receiver_name, name_length) != 0)
					{
						memcpy(peer->receiver_name, pkt + RTCP_SDES_SIZE, name_length);
						msg(receiver_id, sender_id, RIST_LOG_INFO, "[INFO] Peer %"PRIu32" receiver name is now: %s\n", 
							peer->adv_peer_id, peer->receiver_name);
					}
				//}
				if (peer->receiver_mode) {
					if (rist_receiver_authenticate(peer, seq, flow_id, payload))
						rist_receiver_recv_rtcp(peer, seq, flow_id, payload->src_port, payload->dst_port);
				} else if (peer->sender_ctx && peer->listening) {
					// TODO: create rist_sender_recv_rtcp
					if (peer->state_peer < RIST_PEER_STATE_CONNECT || peer->state_local < RIST_PEER_STATE_CONNECT) {
						rist_fsm_recv_connect(peer);
					}
				}

				break;
			}
			case PTYPE_SR:
				break;

			default:
				msg(receiver_id, sender_id, RIST_LOG_WARN, "[WARNING] Unrecognized RTCP packet with PTYPE=%02x!!\n", ptype);
		}
		processed_bytes += bytes;
	}

}

void rist_peer_rtcp(struct evsocket_ctx *evctx, void *arg)
{
	RIST_MARK_UNUSED(evctx);
	struct rist_peer *peer = (struct rist_peer *)arg;
	//struct rist_common_ctx *ctx = get_cctx(peer);

	if (!peer || peer->shutdown) {
		return;
	}
	else { //if (ctx->profile <= RIST_PROFILE_MAIN) {
		//msg(0, 0, RIST_LOG_ERROR, "\tSent rctp message! peer/local (%d/%d)\n", peer->state_peer, peer->state_local);
		if (peer->receiver_mode) {
			rist_send_receiver_rtcp(peer, NULL, 0);
		} else {
			rist_send_sender_rtcp(peer);
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
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	msg(receiver_id, sender_id, RIST_LOG_ERROR, "\tSocket error!\n");

	rist_shutdown_peer(peer);
}

static void sender_peer_append(struct rist_sender *ctx, struct rist_peer *peer)
{
	/* Add a reference to ctx->peer_lst */
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	ctx->peer_lst = realloc(ctx->peer_lst, (ctx->peer_lst_len + 1) * sizeof(*ctx->peer_lst));
	ctx->peer_lst[ctx->peer_lst_len] = peer;
	ctx->peer_lst_len++;
	pthread_rwlock_unlock(peerlist_lock);
}

static void peer_copy_settings(struct rist_peer *peer_src, struct rist_peer *peer)
{
	peer->key_secret.key_size = peer_src->key_secret.key_size;
	peer->key_secret.key_rotation = peer_src->key_secret.key_rotation;
#ifdef __linux
	peer->cryptoctx = peer_src->cryptoctx;
#endif
	strncpy(&peer->key_secret.password[0], &peer_src->key_secret.password[0], RIST_MAX_STRING_SHORT);
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
	peer->config.buffer_bloat_mode = peer_src->config.buffer_bloat_mode;
	peer->config.buffer_bloat_limit = peer_src->config.buffer_bloat_limit;
	peer->config.buffer_bloat_hard_limit = peer_src->config.buffer_bloat_hard_limit;
	peer->rtcp_keepalive_interval = peer_src->rtcp_keepalive_interval;
	peer->session_timeout = peer_src->session_timeout;

	init_peer_settings(peer);
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
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(revents);
	RIST_MARK_UNUSED(fd);

	struct rist_peer *peer = (struct rist_peer *) arg;
	if (peer->shutdown) {
		return;
	}

	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	struct rist_common_ctx *cctx = get_cctx(peer);

	pthread_rwlock_t *peerlist_lock = &cctx->peerlist_lock;
	socklen_t addrlen = peer->address_len;
	int recv_bufsize = -1;
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
		recv_bufsize = recvfrom(peer->sd, recv_buf + buffer_offset, RIST_MAX_PACKET_SIZE, 0, (struct sockaddr *) &addr6, &addrlen);
		family = AF_INET6;
		addr = (struct sockaddr *) &addr6;
	} else {
		recv_bufsize = recvfrom(peer->sd, recv_buf + buffer_offset, RIST_MAX_PACKET_SIZE, 0, (struct sockaddr *) &addr4, &addrlen);
		addr = (struct sockaddr *) &addr4;
	}

	if (recv_bufsize <= 0) {
		// TODO: should we close these sockets? who reopens them?
#if defined (__unix__) || defined(__APPLE__)
		msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Peer recvfrom returned zero bytes (%d), closing socket (%d)\n", recv_bufsize, peer->sd);
		//udp_Close(peer->sd);
#else
		int neterror = WSAGetLastError();
		// We get WSAECONNRESET on receive from the OS when we we have sent data and there is no receiver listening.
		// i.e. the receiver OS sent back an ICMP packet to let the sender know the receiver is unavailable
		// TODO: we can leverage this error to report on the GUI that we are not reaching the other side
		if (neterror != WSAECONNRESET) {
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Peer recvfrom returned zero bytes (%d), closing socket (%d), error %d\n",
				recv_bufsize, peer->sd, neterror);
		}
#endif
		return;
	}

	struct rist_key *k = &peer->key_secret;
	struct rist_gre *gre = NULL;
	uint32_t seq = 0;
	uint32_t time_extension = 0;
	struct rist_protocol_hdr *proto_hdr = NULL;
	uint8_t peer_id = 0;
	struct rist_buffer payload = { .data = NULL, .size = 0, .type = 0 };
	size_t gre_size = 0;
	uint8_t advanced = 0;
	uint32_t flow_id = 0;
	bool retry = false;

	if (cctx->profile > RIST_PROFILE_SIMPLE)
	{

		// Make sure we have enought bytes
		if (recv_bufsize < (int)sizeof(struct rist_gre)) {
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
			return;
		}

		gre = (void *) recv_buf;
		if (gre->prot_type != htobe16(RIST_GRE_PROTOCOL_TYPE_REDUCED) && gre->prot_type != htobe16(RIST_GRE_PROTOCOL_TYPE_FULL)) {

			if (htobe16(gre->prot_type) == RIST_GRE_PROTOCOL_TYPE_KEEPALIVE)
			{
				struct rist_gre_keepalive *gre_keepalive = (void *) recv_buf;
				(void)gre_keepalive->capabilities1;
				payload.type = RIST_PAYLOAD_TYPE_UNKNOWN;
				// TODO: parse the capabilities and do something with it?
			}
			else
			{
				msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Protocol %d not supported (wrong profile?)\n", gre->prot_type);
			}
			goto protocol_bypass;
		}

		uint8_t has_checksum = CHECK_BIT(gre->flags1, 7);
		uint8_t has_key = CHECK_BIT(gre->flags1, 5);
		uint8_t has_seq = CHECK_BIT(gre->flags1, 4);

		//advanced = CHECK_BIT(gre->flags2, 3);
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
#ifndef __linux
				aes_key_setup(aes_key, k->aes_key_sched, k->key_size);
#else
				if (peer->cryptoctx)
					linux_crypto_set_key(aes_key, k->key_size / 8, peer->cryptoctx);
				else
					aes_key_setup(aes_key, k->aes_key_sched, k->key_size);
#endif
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
#ifndef __linux
			aes_decrypt_ctr((const void *) (recv_buf + gre_size), recv_bufsize - gre_size, (void *) (recv_buf + gre_size),
				k->aes_key_sched, k->key_size, IV);
#else
			if (peer->cryptoctx)
				linux_crypto_decrypt((void *)(recv_buf + gre_size), recv_bufsize - gre_size, IV, peer->cryptoctx);
			else
				aes_decrypt_ctr((const void *) (recv_buf + gre_size), recv_bufsize - gre_size, (void *) (recv_buf + gre_size),
					k->aes_key_sched, k->key_size, IV);
#endif
		} else if (has_seq) {
			// Key bit is not set, that means the other side does not want to send
			//  encrypted data
			//
			// make sure we do not have a key
			// (ie also interested in unencrypted communication)
			if (k->key_size) {
				msg(receiver_id, sender_id, RIST_LOG_ERROR,
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
		if (gre->prot_type == htobe16(RIST_GRE_PROTOCOL_TYPE_FULL))
		{
			payload.type = RIST_PAYLOAD_TYPE_DATA_OOB;
			goto protocol_bypass;
		}
		// Decompress if necessary
		if (payload.type == RIST_PAYLOAD_TYPE_DATA_LZ4) {
			int dlen;
			void *dbuf = get_cctx(p)->buf.dec;
			dlen = LZ4_decompress_safe((const void *)(recv_buf + gre_size), dbuf, payload.size, RIST_MAX_PACKET_SIZE);
			if (dlen < 0) {
				msg(receiver_id, sender_id, RIST_LOG_ERROR,
					"[ERROR] Could not decompress data packet (%d), assuming normal data ...\n", dlen);
			}
			else {
				// msg(receiver_id, 0, DEBUG,
				//      "decompressed %d to %lu\n",
				//      payload_len, decompressed_len);
				payload.size = dlen;
				payload.data = dbuf;
			}
			// Restore normal payload type
			payload.type = RIST_PAYLOAD_TYPE_DATA_RAW;
		}
		// Make sure we have enought bytes
		if (recv_bufsize < (int)(sizeof(struct rist_protocol_hdr)+gre_size)) {
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
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
			msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
			return;
		}
		/* Map the first subheader and rtp payload area to our structure */
		proto_hdr = (struct rist_protocol_hdr *)recv_buf;
	}

	/* Double check for a valid rtp header */
	if ((proto_hdr->rtp.flags & 0xc0) != 0x80)
	{
		msg(receiver_id, sender_id, RIST_LOG_ERROR, "[ERROR] Malformed packet, rtp flag value is %02x instead of 0x80.\n", 
			proto_hdr->rtp.flags);
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
			retry = true;
		}
		payload.size = recv_bufsize - gre_size - sizeof(*proto_hdr);
		payload.data = (void *)(recv_buf + gre_size + sizeof(*proto_hdr));
		if (!advanced)
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
			if (cctx->profile == RIST_PROFILE_SIMPLE)
			{
				payload.src_port = p->remote_port;
				payload.dst_port = p->local_port;
			}
			//msg(0, 0, RIST_LOG_INFO, "[INIT] Port is %d !!!!!\n", addr4.sin_port);
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
					rist_recv_rtcp(p, seq, flow_id, &payload);
				break;
				case RIST_PAYLOAD_TYPE_DATA_RAW:
					rtp_time = be32toh(proto_hdr->rtp.ts);
					source_time = convertRTPtoNTP(proto_hdr->rtp.payload_type, time_extension, rtp_time);
					if (!advanced)
					{
						// Get the sequence from the rtp header for queue management
						seq = (uint32_t)be16toh(proto_hdr->rtp.seq);
						// TODO: add support for seq number extension? ...
						if (!p->short_seq)
							p->short_seq = true;
					}
					if (RIST_UNLIKELY(!p->receiver_mode))
						msg(receiver_id, sender_id, RIST_LOG_WARN,
						"[WARNING] Received data packet on sender, ignoring (%d bytes)...\n", payload.size);
					else 
						rist_receiver_recv_data(p, seq, flow_id, source_time, &payload, retry);
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

	// Peer was not found, create a new one
	if (peer->listening &&
		 (payload.type == RIST_PAYLOAD_TYPE_RTCP || cctx->profile == RIST_PROFILE_SIMPLE)) {
		/* No match, new peer creation when on listening mode */
		uint32_t new_peer_id = 0;
		if (advanced)
			new_peer_id = peer_id;
		else
			new_peer_id = ++cctx->peer_counter;
		p = peer_initialize(NULL, peer->sender_ctx, peer->receiver_ctx);
		// Copy settings and init/update global variables that depend on settings
		peer_copy_settings(peer, p);
		if (cctx->profile == RIST_PROFILE_SIMPLE) {
			p->remote_port = peer->remote_port;
			p->local_port = peer->local_port;
		}
		else {
			// TODO: what happens if the first packet is a keepalive??
			p->remote_port = payload.src_port;
			p->local_port = payload.dst_port;
		}
		msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] New RTCP peer connecting, flow_id %"PRIu32", peer_id %"PRIu32", ports %u<-%u\n", 
			flow_id, new_peer_id, p->local_port, p->remote_port);
		if (peer->receiver_mode)
			p->adv_flow_id = flow_id;
		else
			p->adv_flow_id = p->sender_ctx->adv_flow_id;
		// TODO: what if sender mode and flow_id != 0 and p->adv_flow_id != flow_id
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

		// Optional validation of connecting sender
		if (cctx->auth.conn_cb) {
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
				msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] Enabling keepalive for peer %d\n", p->adv_peer_id);
			else {
				// only profile > simple
				sender_peer_append(peer->sender_ctx, p);
				// authenticate sender now that we have an address
				rist_fsm_recv_connect(p);
				msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] Enabling reverse keepalive for peer %d\n", p->adv_peer_id);
			}
			p->send_keepalive = true;
		}
		peer_append(p);
		// Final states happens during settings parsing event on next ping packet
	} else {
		if (!p) {
			if (payload.type != RIST_PAYLOAD_TYPE_DATA_RAW) {
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

int rist_sender_data_write(struct rist_sender *ctx, const struct rist_data_block *data_block)
{
	// max protocol overhead for data is gre-header plus gre-reduced-mode-header plus rtp-header
	// 16 + 4 + 12 = 32

	if (data_block->payload_len <= 0 || data_block->payload_len > (RIST_MAX_PACKET_SIZE-32)) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"Dropping pipe packet of size %d, max is %d.\n", data_block->payload_len, RIST_MAX_PACKET_SIZE-32);
		return -1;
	}

	uint64_t ts_ntp = data_block->ts_ntp == 0 ? timestampNTP_u64() : data_block->ts_ntp;
	uint32_t seq_rtp;
	if (data_block->flags & RIST_DATA_FLAGS_USE_SEQ)
		seq_rtp = data_block->seq;
	else 
		seq_rtp = ctx->common.seq_rtp++;
	//When we support 32bit seq this should be changed
	seq_rtp = seq_rtp & (UINT16_MAX);
	
	int ret = rist_sender_enqueue(ctx, data_block->payload, data_block->payload_len, ts_ntp, data_block->virt_src_port, data_block->virt_dst_port, seq_rtp);
	// Wake up data/nack output thread when data comes in
	if (pthread_cond_signal(&ctx->condition))
		msg(0, ctx->id, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");

	return ret;
}

int rist_sender_oob_read(struct rist_sender *ctx, const struct rist_oob_block **oob_block)
{
	RIST_MARK_UNUSED(oob_block);
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null on rist_sender_oob_read call!\n");
		return -1;
	}
	msg(0, 0, RIST_LOG_ERROR, "[ERROR] rist_sender_oob_read not implemented!\n");
	return 0;
}

static int rist_oob_enqueue(struct rist_common_ctx *ctx, struct rist_peer *peer, const void *buf, size_t len)
{
	if (RIST_UNLIKELY(!ctx->oob_data_enabled)) {
		msg(0, 0, RIST_LOG_ERROR,
			"Trying to send oob but oob was not enabled\n");
		return -1;
	}
	else if ((ctx->oob_queue_write_index + 1) == ctx->oob_queue_read_index)
	{
		msg(0, 0, RIST_LOG_ERROR,
			"oob queue is full (%zu bytes), try again later\n", ctx->oob_queue_bytesize);
		return -1;
	}

	/* insert into oob fifo queue */
	pthread_rwlock_wrlock(&ctx->oob_queue_lock);
	ctx->oob_queue[ctx->oob_queue_write_index] = rist_new_buffer(buf, len, RIST_PAYLOAD_TYPE_DATA_OOB, 0, 0, 0, 0);
	if (RIST_UNLIKELY(!ctx->oob_queue[ctx->oob_queue_write_index])) {
		msg(0, 0, RIST_LOG_ERROR, "\t Could not create oob packet buffer, OOM\n");
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
			//msg(0, 0, RIST_LOG_INFO,
			//	"\t[INFO] We are all up to date, index is %u/%u and bytes = %zu\n",
			//	ctx->oob_queue_read_index, ctx->oob_queue_write_index, ctx->oob_queue_bytesize);
			break;
		}

		struct rist_buffer *oob_buffer = ctx->oob_queue[ctx->oob_queue_read_index];
		if (!oob_buffer->data) {
			msg(0, 0, RIST_LOG_ERROR, "\t[ERROR] Null oob buffer, skipping!!!\n");
			ctx->oob_queue_read_index++;
			continue;
		}

		uint8_t *payload = oob_buffer->data;
		rist_send_common_rtcp(oob_buffer->peer, RIST_PAYLOAD_TYPE_DATA_OOB, &payload[RIST_MAX_PAYLOAD_OFFSET],
					oob_buffer->size, 0, 0, 0, ctx->seq++, 0);
		ctx->oob_queue_bytesize -= oob_buffer->size;
		ctx->oob_queue_read_index++;
	}

	return;
}

int rist_sender_oob_write(struct rist_sender *ctx, const struct rist_oob_block *oob_block)
{
	// max protocol overhead for data is gre-header, 16 max
	if (oob_block->payload_len <= 0 || oob_block->payload_len > (RIST_MAX_PACKET_SIZE-16)) {
		msg(0, ctx->id, RIST_LOG_ERROR,
			"Dropping oob packet of size %d, max is %d.\n", oob_block->payload_len, RIST_MAX_PACKET_SIZE-16);
		return -1;
	}
	return rist_oob_enqueue(&ctx->common, oob_block->peer, oob_block->payload, oob_block->payload_len);
}

int rist_receiver_oob_write(struct rist_receiver *ctx, const struct rist_oob_block *oob_block)
{
	// max protocol overhead for data is gre-header, 16 max
	if (oob_block->payload_len <= 0 || oob_block->payload_len > (RIST_MAX_PACKET_SIZE-16)) {
		msg(ctx->id, 0, RIST_LOG_ERROR,
			"Dropping oob packet of size %d, max is %d.\n", oob_block->payload_len, RIST_MAX_PACKET_SIZE-16);
		return -1;
	}
	return rist_oob_enqueue(&ctx->common, oob_block->peer, oob_block->payload, oob_block->payload_len);
}

static void sender_send_nacks(struct rist_sender *ctx, int maxcounter)
{
	// Send retries from the queue (if any)
	int counter = 1;
	int errors = 0;
	size_t total_bytes = 0;

	// Send no more than maxcounter retries for every packet/loop (for uniform spacing)
	while (1) {
		int ret = rist_retry_dequeue(ctx);
		if (ret == 0) {
			// ret == 0 is valid (nothing to send)
			break;
		} else if (ret < 0) {
			errors++;
		} else {
			total_bytes += ret;
		}
		if (++counter > maxcounter) {
			break;
		}
	}
	if (counter > (maxcounter / 2))
	{
		msg(ctx->id, 0, RIST_LOG_WARN,
			"[WARNING] Had to process multiple fifo nacks: c=%d, e=%d, b=%zu, s=%zu\n",
			counter - 1, errors, total_bytes, rist_get_sender_retry_queue_size(ctx));
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

		size_t idx = (ctx->sender_queue_read_index + 1) % ctx->sender_queue_max;

		if (idx == ctx->sender_queue_write_index) {
			//msg(0, ctx->id, RIST_LOG_ERROR,
			//    "\t[GOOD] We are all up to date, index is %d\n",
			//    ctx->sender_queue_read_index);
			break;
		}

		ctx->sender_queue_read_index = idx;
		if (RIST_UNLIKELY(ctx->sender_queue[idx] == NULL)) {
			// This should never happen!
			msg(0, ctx->id, RIST_LOG_ERROR,
				"[ERROR] FIFO data block was null (read/write) (%zu/%zu)\n",
				ctx->sender_queue_read_index, ctx->sender_queue_write_index);
			continue;
		} else {
			struct rist_buffer *buffer =  ctx->sender_queue[idx];
			// Send  fifo data (handshake and data payloads)
			if (buffer->type == RIST_PAYLOAD_TYPE_RTCP) {
				// TODO can we ever have a null or dead buffer->peer?
				uint8_t *payload = buffer->data;
				rist_send_common_rtcp(buffer->peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, ctx->common.seq++, 0);
				buffer->seq = ctx->common.seq;
				buffer->seq_rtp = ctx->common.seq_rtp;
			}
			else {
				rist_sender_send_data_balanced(ctx, buffer);
				// For non-advanced mode seq to index mapping
				ctx->seq_index[buffer->seq_rtp] = idx;
			}
		}

	}
}

static struct rist_peer *peer_initialize(const char *url, struct rist_sender *sender_ctx,
										struct rist_receiver *receiver_ctx)
{
	intptr_t receiver_id = receiver_ctx ? receiver_ctx->id : 0;
	intptr_t sender_id = sender_ctx ? sender_ctx->id : 0;

	struct rist_peer *p = calloc(1, sizeof(*p));
	if (!p) {
		msg(receiver_id, sender_id, RIST_LOG_ERROR, "\tNot enough memory creating peer!\n");
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
	// Default max jitter is 5ms
	int max_output_jitter_ms = flow->max_output_jitter / RIST_CLOCK;
	msg(flow->receiver_id, 0, RIST_LOG_INFO, "[INFO] Starting data output thread with %d ms max output jitter\n", max_output_jitter_ms);

	//uint64_t now = timestampNTP_u64();
	while (!flow->shutdown) {
		pthread_rwlock_wrlock(&(flow->queue_lock));
		if (flow->peer_lst) {
			receiver_output(receiver_ctx, flow);
		}
		pthread_rwlock_unlock(&(flow->queue_lock));
		pthread_mutex_lock(&(flow->mutex));
		int ret = pthread_cond_timedwait_ms(&(flow->condition), &(flow->mutex), max_output_jitter_ms);
		pthread_mutex_unlock(&(flow->mutex));
		if (ret && ret != ETIMEDOUT)
			msg(flow->receiver_id, 0, RIST_LOG_ERROR, "[ERROR] Error %d in receiver data out loop\n", ret);
		//msg(flow->receiver_id, 0, RIST_LOG_INFO, "[INFO] LOOP TIME is %"PRIu64" us\n", (timestampNTP_u64() - now) * 1000 / RIST_CLOCK);
		//now = timestampNTP_u64();
	}
	flow->shutdown = 2;

	return 0;
}

static void sender_peer_events(struct rist_sender *ctx, uint64_t now)
{
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;

	pthread_rwlock_wrlock(peerlist_lock);

	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		struct rist_peer *peer = ctx->peer_lst[j];
		if (peer->send_keepalive) {
			if (now > peer->keepalive_next_time) {
				peer->keepalive_next_time = now + peer->rtcp_keepalive_interval;
				rist_peer_rtcp(NULL, peer);
			}
		}
	}

	pthread_rwlock_unlock(peerlist_lock);
}

static PTHREAD_START_FUNC(sender_pthread_protocol, arg)
{
	struct rist_sender *ctx = (struct rist_sender *) arg;
	// loop behavior parameters
	int max_dataperloop = 100;
	int max_oobperloop = 100;
	int max_nacksperloop = RIST_MAX_NACKS;

	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
	uint64_t rist_stats_interval = ctx->common.stats_report_time; // 1 second

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting master sender loop at %d ms max jitter\n",
				max_jitter_ms);

	uint64_t now  = timestampNTP_u64();
	ctx->common.nacks_next_time = now;
	ctx->stats_next_time = now;
	ctx->checks_next_time = now;
	while(!ctx->common.shutdown) {

		// Conditional 5ms sleep that is woken by data coming in
		pthread_mutex_lock(&(ctx->mutex));
		int ret = pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), max_jitter_ms);
		pthread_mutex_unlock(&(ctx->mutex));
		if (ret && ret != ETIMEDOUT)
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d in sender protocol loop, loop time was %d us\n", ret, (timestampNTP_u64() - now));

		if (RIST_UNLIKELY(!ctx->common.startup_complete)) {
			continue;
		}

		now  = timestampNTP_u64();

		/* marks peer as dead, run every second */
		if (now > ctx->checks_next_time)
		{
			ctx->checks_next_time += (uint64_t)1000 * (uint64_t)RIST_CLOCK;
			pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
			pthread_rwlock_wrlock(peerlist_lock);
			for (size_t j = 0; j < ctx->peer_lst_len; j++)
			{
				struct rist_peer *peer = ctx->peer_lst[j];
				// TODO: print warning if the peer is dead?, i.e. no stats
				if (!peer->dead)
				{
					if (peer->is_rtcp == true && (timestampNTP_u64() - peer->last_rtcp_received) > peer->session_timeout &&
						peer->last_rtcp_received > 0)
					{
						msg(0, peer->sender_ctx->id, RIST_LOG_WARN, 
							"[WARNING] Peer with id %zu is dead, stopping stream ...\n", peer->adv_peer_id);
						bool current_state = peer->dead;
						peer->dead = true;
						peer->peer_data->dead = true;
						if (current_state != peer->peer_data->dead && peer->peer_data->parent)
							--peer->peer_data->parent->child_alive_count;
					}
				}
			}
			pthread_rwlock_unlock(peerlist_lock);
		}
		
		// stats timer
		if (now > ctx->stats_next_time) {
			ctx->stats_next_time += rist_stats_interval;

			pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
			pthread_rwlock_wrlock(peerlist_lock);
			for (size_t j = 0; j < ctx->peer_lst_len; j++) {
				struct rist_peer *peer = ctx->peer_lst[j];
				// TODO: print warning if the peer is dead?, i.e. no stats
				if (!peer->dead) {
					rist_sender_peer_statistics(peer);
				}
			}
			pthread_rwlock_unlock(peerlist_lock);
			// TODO: remove dead peers after stale flow time (both sender list and peer chain)
			//sender_peer_delete(peer->sender_ctx, peer);
		}

		// socket polls
		evsocket_loop_single(ctx->common.evctx, 0);

		// keepalive timer
		sender_peer_events(ctx, now);

		// Send data and process nacks
		if (ctx->sender_queue_bytesize > 0) {
			sender_send_data(ctx, max_dataperloop);
			// TODO: put a minimum on the nack and cleanup sending (maybe group them every 1ms)
			// otherwise for higher bitrates our CPU will not keep up (20Mbps is about 0.5ms spacing)
			// because of the tight loop
			sender_send_nacks(ctx, max_nacksperloop);
			/* perform queue cleanup */
			rist_clean_sender_enqueue(ctx);
		}
		// Send oob data
		if (ctx->common.oob_queue_bytesize > 0)
			rist_oob_dequeue(&ctx->common, max_oobperloop);

	}
	evsocket_loop_finalize(ctx->common.evctx);

#ifdef _WIN32
	WSACleanup();
#endif
	msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Exiting master sender loop\n");
	ctx->common.shutdown = 2;
	
	return 0;
}

static int init_common_ctx(struct rist_common_ctx *ctx, enum rist_profile profile)
{
	init_socket_subsystem();
	ctx->evctx = evsocket_init();
	ctx->rist_max_jitter = RIST_MAX_JITTER * RIST_CLOCK;
	if (profile > RIST_PROFILE_MAIN) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Profile not supported (%d), using main profile instead\n", profile);
		profile = RIST_PROFILE_MAIN;
	}
	ctx->profile = profile;
	ctx->stats_report_time = 0;

	if (pthread_rwlock_init(&ctx->peerlist_lock, NULL) != 0) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Failed to init ctx->peerlist_lock\n");
		return -1;
	}
	return 0;
}

int rist_receiver_create(struct rist_receiver **_ctx, enum rist_profile profile,
		enum rist_log_level log_level)
{
	struct rist_receiver *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Could not create ctx object, OOM!\n");
		return -1;
	}

	if (init_common_ctx(&ctx->common, profile))
		goto fail;

	ctx->id = (intptr_t)ctx;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] RIST Receiver Library v%d.%d.%d\n",
		RIST_PROTOCOL_VERSION, RIST_API_VERSION, RIST_SUBVERSION);

	set_loglevel(log_level);
	if (log_level >= RIST_LOG_DEBUG)
		ctx->common.debug = true;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting in receiver mode\n");

	int ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret) {
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Error %d calling pthread_cond_init\n", ret);
		goto fail;
	}
	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret){
		pthread_cond_destroy(&ctx->condition);
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Error %d calling pthread_mutex_init\n", ret);
		goto fail;
	}

	*_ctx = ctx;
	return 0;

fail:
	free(ctx);
	ctx = NULL;
	return -1;
}

int rist_sender_flow_id_get(struct rist_sender *ctx, uint32_t *flow_id)
{
	*flow_id = ctx->adv_flow_id;
	return 0;
}

int rist_sender_flow_id_set(struct rist_sender *ctx, uint32_t flow_id)
{
	ctx->adv_flow_id = flow_id;
	for (size_t i =0; i < ctx->peer_lst_len; i++) {
		ctx->peer_lst[i]->adv_flow_id = flow_id;
	}
	return 0;
}

int rist_sender_create(struct rist_sender **_ctx, enum rist_profile profile,
			uint32_t flow_id, enum rist_log_level log_level)
 {
	int ret;

	if (flow_id % 2 != 0) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Flow ID must be an even number!\n");
		return -1;
	}

	struct rist_sender *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Could not create ctx object, OOM!\n");
		return -1;
	}

	if (init_common_ctx(&ctx->common, profile))
	{
		free(ctx);
		ctx = NULL;
		return -1;
	}
	ctx->common.stats_report_time = (uint64_t)1000 * (uint64_t)RIST_CLOCK;
	ctx->id = (intptr_t)ctx;
	//ctx->common.seq = 9159579;
	//ctx->common.seq = RIST_SERVER_QUEUE_BUFFERS - 25000;

	if (!ctx->sender_retry_queue) {
		ctx->sender_retry_queue = calloc(RIST_RETRY_QUEUE_BUFFERS, sizeof(*ctx->sender_retry_queue));
		if (RIST_UNLIKELY(!ctx->sender_retry_queue)) {
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Could not create sender retry buffer of size %u MB, OOM\n",
				(unsigned)(RIST_SERVER_QUEUE_BUFFERS * sizeof(ctx->sender_retry_queue[0])) / 1000000);
			ret = -1;
			goto free_ctx_and_ret;
		}

		ctx->sender_retry_queue_write_index = 1;
		ctx->sender_retry_queue_read_index = 0;
		ctx->sender_retry_queue_size = RIST_RETRY_QUEUE_BUFFERS;
	}

	ctx->sender_queue_read_index = 0;
	ctx->sender_queue_write_index = 0;
	ctx->sender_queue_delete_index = 0;
	ctx->sender_queue_max = RIST_SERVER_QUEUE_BUFFERS;

	msg(0, ctx->id, RIST_LOG_INFO, "[INIT] RIST Sender Library v%d.%d.%d\n",
			RIST_PROTOCOL_VERSION, RIST_API_VERSION, RIST_SUBVERSION);

	set_loglevel(log_level);

	if (log_level == RIST_LOG_SIMULATE) {
		ctx->simulate_loss = true;
	}

	if (log_level >= RIST_LOG_DEBUG) {
		ctx->common.debug = true;
	}

	if (flow_id == 0) {
		uint64_t now;
		struct timeval time;
		gettimeofday(&time, NULL);
		now = time.tv_sec * 1000000;
		now += time.tv_usec;
		flow_id = (uint32_t)(now >> 16);
		// It must me an even number
		flow_id &= ~(1UL << 0);
	}

	ctx->adv_flow_id = flow_id;

	ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d initializing pthread_condition\n",ret);
		goto free_ctx_and_ret;
	}

	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d initializing pthread_mutex\n",ret);
		goto free_ctx_and_ret;
	}

	ctx->sender_initialized = true;

	if (pthread_create(&ctx->sender_thread, NULL, sender_pthread_protocol, (void *)ctx) != 0) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Could not created sender thread.\n");
		ret = -3;
		goto free_ctx_and_ret;
	}

	*_ctx = ctx;
	return 0;

	// Failed!
free_ctx_and_ret:
	free(ctx);
	return ret;
}

static int rist_peer_remove(struct rist_common_ctx *ctx, struct rist_peer *peer)
{
	RIST_MARK_UNUSED(ctx);
	RIST_MARK_UNUSED(peer);
	// TODO: test remove from sender list and peer linked list and
	// perform proper cleanup

	return 0;

/*
	pthread_rwlock_wrlock(&ctx->common.peerlist_lock);

	if (d_peer == NULL) {
		return -1;
	}

	if (d_peer) {
		// middle
		if (d_peer->prev && d_peer->next) {
			d_peer->prev->next = d_peer->next;
			d_peer->next->prev = d_peer->prev;
		} else if (!d_peer->prev) {
			// head
			if (d_peer->next) {
				d_peer->next->prev = NULL;
			}

			ctx->common.PEERS = d_peer->next;
		} else if (!d_peer->next) {
			// tail
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

*/

	//intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	//intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	// TODO: finish/test this code for proper cleanup of peer
	/* work in progress 

	pthread_rwlock_t *peerlist_lock = &ctx->peerlist_lock;
	struct evsocket_ctx *evctx = ctx->evctx;

	pthread_rwlock_wrlock(peerlist_lock);

	if (!peer->receiver_mode)

	struct rist_peer *nextpeer = peer->next;
	msg(receiver_id, sender_id, RIST_LOG_INFO, "[CLEANUP] Removing peer data received event\n");
	// data receive event
	if (peer->event_recv) {
		evsocket_delevent(evctx, peer->event_recv);
		peer->event_recv = NULL;
	}

	msg(receiver_id, sender_id, RIST_LOG_INFO, "[CLEANUP] Removing peer handshake/ping timer\n");
	/ rtcp timer
	peer->send_keepalive = false;

	msg(receiver_id, sender_id, RIST_LOG_INFO, "[CLEANUP] Closing peer socket on port %d\n", peer->local_port);
	if (peer->sd > -1) {
		udp_Close(peer->sd);
		peer->sd = -1;
	}

	struct rist_peer *deleted_peer = peer;
	peer = nextpeer;

	// Do not free the listening peers here, we do it at the end of the protocol main loop
	if (!peer->listening)
		free(deleted_peer);
	}

	ctx->PEERS = NULL;
	pthread_rwlock_unlock(peerlist_lock);

	if (ctx->auth.arg) {
		ctx->auth.disconn_cb(ctx->auth.arg, peer);
	}

	*/
}

int rist_sender_peer_destroy(struct rist_sender *ctx, struct rist_peer *peer)
{
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	}
	else if (!peer) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Missing peer pointer\n");
		return -1;
	}

	peer->dead = true;
	rist_peer_remove(&ctx->common, peer);
	msg(0, ctx->id, RIST_LOG_WARN, "[WARNING] rist_sender_peer_remove not fully implemented!\n");
	return 0;
}

int rist_receiver_peer_destroy(struct rist_receiver *ctx, struct rist_peer *peer)
{
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	}
	else if (!peer) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Missing peer pointer\n");
		return -1;
	}

	peer->dead = true;
	rist_peer_remove(&ctx->common, peer);
	msg(ctx->id, 0, RIST_LOG_WARN, "[WARNING] rist_receiver_peer_remove not fully implemented!\n");
	return 0;
}

static int rist_auth_handler(struct rist_common_ctx *ctx,
		int (*conn_cb)(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer),
		int (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg)
{
	ctx->auth.conn_cb = conn_cb;
	ctx->auth.disconn_cb = disconn_cb;
	ctx->auth.arg = arg;
	return 0;
}

int rist_sender_auth_handler_set(struct rist_sender *ctx,
		int (*conn_cb)(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer),
		int (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg)
{
	return rist_auth_handler(&ctx->common, conn_cb, disconn_cb, arg);
}

int rist_sender_start(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized) {
		return -1;
	}

	if (ctx->total_weight > 0) {
		ctx->weight_counter = ctx->total_weight;
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Total weight: %lu\n", ctx->total_weight);
	}

	ctx->common.startup_complete = true;
	return 0;
}

int rist_sender_pause(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized) {
		return -1;
	}

	ctx->common.startup_complete = false;
	return 0;
}

int rist_sender_unpause(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized) {
		return -1;
	}

	ctx->common.startup_complete = true;
	return 0;
}

static void store_peer_settings(const struct rist_peer_config *settings, struct rist_peer *peer)
{
	intptr_t receiver_id = peer->receiver_ctx ? peer->receiver_ctx->id : 0;
	intptr_t sender_id = peer->sender_ctx ? peer->sender_ctx->id : 0;

	uint32_t recovery_rtt_min;
	uint32_t buffer_bloat_limit;
	uint32_t buffer_bloat_hard_limit;

	// TODO: Consolidate the two settings objects into one

	/* Set recovery options */
	peer->config.recovery_mode = settings->recovery_mode;
	peer->config.recovery_maxbitrate = settings->recovery_maxbitrate;
	peer->config.recovery_maxbitrate_return = settings->recovery_maxbitrate_return;
	peer->config.recovery_length_min = settings->recovery_length_min;
	peer->config.recovery_length_max = settings->recovery_length_max;
	peer->config.recovery_reorder_buffer = settings->recovery_reorder_buffer;
	if (settings->recovery_rtt_min < RIST_RTT_MIN) {
		msg(receiver_id, sender_id, RIST_LOG_INFO, "[INIT] rtt_min is too small (%u), using %dms instead\n",
			settings->recovery_rtt_min, RIST_RTT_MIN);
		recovery_rtt_min = RIST_RTT_MIN;
	} else {
		recovery_rtt_min = settings->recovery_rtt_min;
	}
	peer->config.recovery_rtt_min = recovery_rtt_min;
	peer->config.recovery_rtt_max = settings->recovery_rtt_max;
	/* Set buffer-bloating */
	if (settings->buffer_bloat_limit < 2 || settings->buffer_bloat_limit > 100) {
		msg(receiver_id, sender_id, RIST_LOG_INFO,
			"[INIT] The configured value for buffer_bloat_limit 2 <= %u <= 100 is invalid, using %u instead\n",
			settings->buffer_bloat_limit, 6);
		buffer_bloat_limit = 6;
	} else {
		buffer_bloat_limit = settings->buffer_bloat_limit;
	}
	if (settings->buffer_bloat_hard_limit < 2 || settings->buffer_bloat_hard_limit > 100) {
		msg(receiver_id, sender_id, RIST_LOG_INFO,
			"[INIT] The configured value for buffer_bloat_hard_limit 2 <= %u <= 100 is invalid, using %u instead\n",
			settings->buffer_bloat_hard_limit, 20);
		buffer_bloat_hard_limit = 20;
	} else {
		buffer_bloat_hard_limit = settings->buffer_bloat_hard_limit;
	}
	peer->config.buffer_bloat_mode = settings->buffer_bloat_mode;
	peer->config.buffer_bloat_limit = buffer_bloat_limit;
	peer->config.buffer_bloat_hard_limit = buffer_bloat_hard_limit;
	peer->config.weight = settings->weight;

	init_peer_settings(peer);
}

static struct rist_peer *rist_sender_peer_insert_local(struct rist_sender *ctx,
		const struct rist_peer_config *config, bool b_rtcp)
{
	if (config->key_size) { 
		if (config->key_size != 128 && config->key_size != 192 && config->key_size != 256) {
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Invalid encryption key length: %d\n", config->key_size);
			return NULL;
		}
		if (!strlen(config->secret)) {
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Invalid secret passphrase\n");
			return NULL;
		}
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Using %d bits secret key\n", config->key_size);
	}
	else {
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Encryption is disabled for this peer\n");
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
		newpeer->key_secret.key_size = config->key_size;
		strncpy(&newpeer->key_secret.password[0], config->secret, RIST_MAX_STRING_SHORT);
		newpeer->key_secret.key_rotation = config->key_rotation;
#ifdef __linux
		linux_crypto_init(&newpeer->cryptoctx);
		if (newpeer->cryptoctx)
			msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Crypto AES-NI found and activated\n");
#endif
	}

	if (config->keepalive_interval > 0) {
		newpeer->rtcp_keepalive_interval = config->keepalive_interval * RIST_CLOCK;
	}

	if (config->session_timeout > 0) {
		newpeer->session_timeout = config->session_timeout * RIST_CLOCK;
	}
	else {
		newpeer->session_timeout = config->recovery_length_max * RIST_CLOCK;
	}

	/* Initialize socket */
	rist_create_socket(newpeer);
	if (newpeer->sd <= 0) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERRORS] Could not create socket\n");
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
	newpeer->adv_peer_id = ctx->common.peer_counter++;
	newpeer->adv_flow_id = ctx->adv_flow_id;

	store_peer_settings(config, newpeer);

	msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Advertising flow_id  %" PRIu64 " and peer_id %u, %u/%u\n",
		newpeer->adv_flow_id, newpeer->adv_peer_id, newpeer->local_port, newpeer->remote_port);

	return newpeer;

}

int rist_sender_peer_create(struct rist_sender *ctx,
		struct rist_peer **peer, const struct rist_peer_config *config)
{
	struct rist_peer *newpeer = rist_sender_peer_insert_local(ctx, config, false);

	if (!newpeer)
		return -1;

	// TODO: Validate config data (virt_dst_port != 0 for example)

	newpeer->is_data = true;
	peer_append(newpeer);

	if (ctx->common.profile == RIST_PROFILE_SIMPLE)
	{
		struct rist_peer *peer_rtcp = rist_sender_peer_insert_local(ctx, config, true);
		if (!peer_rtcp)
		{
			// TODO: remove from peerlist (create sender_delete peer function)
			free(newpeer);
			return -1;
		}
		peer_rtcp->peer_data = newpeer;
		peer_append(peer_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(peer_rtcp);
		/* Authenticate right away */
		if (!peer_rtcp->listening) {
			sender_peer_append(ctx, peer_rtcp);
			rist_fsm_recv_connect(peer_rtcp);
		}
	}
	else {
		newpeer->peer_data = newpeer;
		newpeer->is_rtcp = true;
		newpeer->compression = config->compression;
	}

	/* jumpstart communication */
	rist_fsm_init_comm(newpeer);
	/* Authenticate right away */
	if (!newpeer->listening) {
		sender_peer_append(ctx, newpeer);
		rist_fsm_recv_connect(newpeer);
	}

	*peer = newpeer;

	return 0;
}

int rist_receiver_auth_handler_set(struct rist_receiver *ctx,
		int (*conn_cb)(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer),
		int (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg)
{
	return rist_auth_handler(&ctx->common, conn_cb, disconn_cb, arg);
}

int rist_sender_oob_callback_set(struct rist_sender *ctx, 
		int (*oob_callback)(void *arg, const struct rist_oob_block *oob_block),
		void *arg)
{
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	} else if (ctx->common.profile == RIST_PROFILE_SIMPLE) {
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Out-of-band data is not support for simple profile\n");
		return -1;
	}
	if (pthread_rwlock_init(&ctx->common.oob_queue_lock, NULL) != 0) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Failed to init ctx->common.oob_queue_lock\n");
		return -1;
	}
	ctx->common.oob_data_enabled = true;
	ctx->common.oob_data_callback = oob_callback;
	ctx->common.oob_data_callback_argument = arg;
	ctx->common.oob_queue_write_index = 0;
	ctx->common.oob_queue_read_index = 0;

	return 0;
}

int rist_receiver_oob_callback_set(struct rist_receiver *ctx, 
		int (*oob_data_callback)(void *arg, const struct rist_oob_block *oob_block),
		void *arg)
{
	if (!ctx) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	} else if (ctx->common.profile == RIST_PROFILE_SIMPLE) {
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Out-of-band data is not support for simple profile\n");
		return -1;
	}
	ctx->common.oob_data_enabled = true;
	ctx->common.oob_data_callback = oob_data_callback;
	ctx->common.oob_data_callback_argument = arg;
	return 0;
}

int rist_receiver_nack_type_set(struct rist_receiver *ctx, enum rist_nack_type nack_type)
{
	ctx->nack_type = nack_type;
	return 0;
}

void receiver_peer_events(struct rist_receiver *ctx, uint64_t now)
{
	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);

	for (struct rist_peer *p = ctx->common.PEERS; p != NULL; p = p->next) {
		if (p->send_keepalive) {
			if (now > p->keepalive_next_time) {
				p->keepalive_next_time = now + p->rtcp_keepalive_interval;
				rist_peer_rtcp(NULL, p);
			}
		}
	}

	pthread_rwlock_unlock(peerlist_lock);
}

static void rist_receiver_destroy_local(struct rist_receiver *ctx)
{
	struct evsocket_ctx *evctx = ctx->common.evctx;

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Starting Flows cleanup\n");

	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;

	pthread_rwlock_wrlock(peerlist_lock);
	struct rist_flow *f = ctx->common.FLOWS;
	while (f) {
		struct rist_flow *nextflow = f->next;
		rist_delete_flow(ctx, f);
		f = nextflow;
	}
	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Flows cleanup complete\n");
	pthread_rwlock_unlock(peerlist_lock);

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Starting peers cleanup\n");
	/* now use the peer list to destroy all peers and timers */
	struct rist_peer **PEERS = &ctx->common.PEERS;
	pthread_rwlock_wrlock(peerlist_lock);
	struct rist_peer *peer = *PEERS;
	if (!peer) {
		pthread_rwlock_unlock(peerlist_lock);
	} else {
		while (peer) {
			struct rist_peer *nextpeer = peer->next;
			msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing peer data received event\n");
			/* data receive event */
			if (peer->event_recv) {
				evsocket_delevent(evctx, peer->event_recv);
				peer->event_recv = NULL;
			}

			msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing peer handshake/ping timer\n");
			/* rtcp timer */
			peer->send_keepalive = false;

			msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Closing peer socket on port %d\n", peer->local_port);
			if (peer->sd > -1) {
				udp_Close(peer->sd);
				peer->sd = -1;
			}

#ifdef __linux
			if (peer->cryptoctx)
				free(peer->cryptoctx);
#endif

			msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Freeing up peer memory allocation\n");
			free(peer);
			peer = nextpeer;
		}
		ctx->common.PEERS = NULL;
		pthread_rwlock_unlock(peerlist_lock);
	}
	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Peers cleanup complete\n");

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing peerlist_lock\n");
	pthread_rwlock_destroy(&ctx->common.peerlist_lock);

	if (ctx->common.oob_data_enabled) {
		// TODO: Are we missing more OOB cleanup?
		msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing oob_queue_lock\n");
		pthread_rwlock_destroy(&ctx->common.oob_queue_lock);
	}

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Freeing data output fifo\n");
	pthread_rwlock_wrlock(&ctx->dataout_fifo_queue_lock);
	for (int i = 0; i < RIST_DATAOUT_QUEUE_BUFFERS; i++)
	{
		if (ctx->dataout_fifo_queue[i])
		{
			const uint8_t *payload = ctx->dataout_fifo_queue[i]->payload;
			if (payload) {
				// TODO: why does this crash
				//free(payload);
				payload = NULL;
			}
			free(ctx->dataout_fifo_queue[i]);
			ctx->dataout_fifo_queue[i] = NULL;
		}
	}
	pthread_rwlock_unlock(&ctx->dataout_fifo_queue_lock);

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing data fifo signaling variables (condition and mutex)\n");
	pthread_cond_destroy(&ctx->condition);
	pthread_mutex_destroy(&ctx->mutex);

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing dataout_fifo_queue_lock\n");
	pthread_rwlock_destroy(&ctx->dataout_fifo_queue_lock);

	free(ctx);
	ctx = NULL;
}

static PTHREAD_START_FUNC(receiver_pthread_protocol, arg)
{
	struct rist_receiver *ctx = (struct rist_receiver *) arg;
	uint64_t now;
	int max_oobperloop = 100;

	uint64_t rist_nack_interval = (uint64_t)ctx->common.rist_max_jitter;
	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting receiver protocol loop with %d ms timer\n", max_jitter_ms);

	while (!ctx->common.shutdown) {
		now  = timestampNTP_u64();
		// Limit scope of `struct rist_flow *f` for clarity since it is used again later in this loop.
		{
			// stats timer
			struct rist_flow *f = ctx->common.FLOWS;
			while (f) {
				if (now > f->checks_next_time) {
					f->checks_next_time += f->recovery_buffer_ticks;
					// TODO: use the new setting per peer called session_timeout instead
					// TODO: STALE_FLOW_TIME or buffer size in us ... which ever is greater
					if ((f->stats_total.last_recv_ts != 0) && (now - f->stats_total.last_recv_ts > (uint64_t)STALE_FLOW_TIME))
					{
						if ((now- f->stats_total.last_recv_ts) < (1.5 * (uint64_t)STALE_FLOW_TIME))
						{
							struct rist_flow *next = f->next;
							// Do nothing
							msg(f->receiver_id, f->sender_id, RIST_LOG_INFO,
								"\t************** STALE FLOW:%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 ", Deleting! ***************\n",
								now,
								f->stats_total.last_recv_ts,
								now - f->stats_total.last_recv_ts,
								(uint64_t)STALE_FLOW_TIME);
							pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
							pthread_rwlock_wrlock(peerlist_lock);
							rist_delete_flow(ctx, f);
							pthread_rwlock_unlock(peerlist_lock);
							f = next;
							continue;
						}
					}
				} 
				if (now > f->stats_next_time) {
					f->stats_next_time += f->stats_report_time; 
					f = rist_receiver_flow_statistics(ctx, f);
				}
				else
				{
					f = f->next;
				}
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

		// Send oob data
		if (ctx->common.oob_queue_bytesize > 0)
			rist_oob_dequeue(&ctx->common, max_oobperloop);

	}
	evsocket_loop_finalize(ctx->common.evctx);
#ifdef _WIN32
	WSACleanup();
#endif
	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Exiting master receiver loop\n");
	ctx->common.shutdown = 2;

	return 0;
}

int rist_receiver_data_callback_set(struct rist_receiver *ctx,
	int (*data_callback)(void *arg, const struct rist_data_block *data_block),
	void *arg)
{
	ctx->receiver_data_callback = data_callback;
	ctx->receiver_data_callback_argument = arg;
	return 0;
}

int rist_receiver_start(struct rist_receiver *ctx)
{
	if (pthread_rwlock_init(&ctx->dataout_fifo_queue_lock, NULL) != 0) {
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Failed to init dataout_fifo_queue_lock\n");
		return -1;
	}

	if (!ctx->receiver_thread) {
		if (pthread_create(&ctx->receiver_thread, NULL, receiver_pthread_protocol, (void *)ctx) != 0) {
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create receiver protocol thread.\n");
			return -1;
		}
	}

	return 0;
}

static void rist_sender_destroy_local(struct rist_sender *ctx)
{
	msg(0, ctx->id, RIST_LOG_INFO,
		"[CLEANUP] Starting peers cleanup, count %d\n",
		(unsigned) ctx->peer_lst_len);

	pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
	pthread_rwlock_wrlock(peerlist_lock);
	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		struct rist_peer *peer = ctx->peer_lst[j];
		peer->shutdown = true;

		msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Removing peer data received event\n");
		/* data receive event */
		if (peer->event_recv) {
			struct evsocket_ctx *evctx = ctx->common.evctx;
			evsocket_delevent(evctx, peer->event_recv);
		}

		msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Removing peer handshake/ping timer\n");
		/* rtcp timer */
		if (peer->send_keepalive) {
			peer->send_keepalive = false;
		}

		msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Closing peer socket on port %d\n", peer->local_port);
		if (peer->sd > -1) {
			udp_Close(peer->sd);
			peer->sd = -1;
		}

#ifdef __linux
		if (peer->cryptoctx)
			free(peer->cryptoctx);
#endif

		free(peer);
	}

	pthread_rwlock_unlock(peerlist_lock);
	pthread_rwlock_destroy(peerlist_lock);
	msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Peers cleanup complete\n");

	if (ctx->common.oob_data_enabled) {
		// TODO: Are we missing more OOB cleanup?
		msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing oob_queue_lock\n");
		pthread_rwlock_destroy(&ctx->common.oob_queue_lock);
	}

	msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Freeing up context memory allocations\n");
	free(ctx->sender_retry_queue);
	//free(ctx->sender_queue); // TODO: this array does not need to be freed?
	free(ctx);
	ctx = NULL;
}

int rist_sender_destroy(struct rist_sender *ctx)
{
	if (!ctx) {
		return -1;
	}

	msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Triggering protocol loop termination\n");
	ctx->common.shutdown = 1;
	uint64_t start_time = timestampNTP_u64();
	while (ctx->sender_thread && ctx->common.shutdown != 2) {
		msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Waiting for protocol loop to exit\n");
		usleep(5000);
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 10000)
		{
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Protocol loop took more than 10 seconds to exit. Something is wrong!\n");
			assert(0);
		}
	}
	rist_sender_destroy_local(ctx);

	return 0;
}

int rist_receiver_destroy(struct rist_receiver *ctx)
{
	if (!ctx) {
		return -1;
	}

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Triggering protocol loop termination\n");
	ctx->common.shutdown = 1;
	uint64_t start_time = timestampNTP_u64();
	while (ctx->receiver_thread && ctx->common.shutdown != 2) {
		msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Waiting for protocol loop to exit\n");
		usleep(5000);
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 10000)
		{
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Protocol loop took more than 10 seconds to exit. Something is wrong!\n");
			assert(0);
		}
	}
	rist_receiver_destroy_local(ctx);

	return 0;
}

int rist_sender_stats_callback_set(struct rist_sender *ctx, int statsinterval, int (*stats_cb)(void *arg, struct rist_stats *stats), void *arg)
{
	if (stats_cb == NULL) {
		return -1;
	}
	ctx->common.stats_callback = stats_cb;
	ctx->common.stats_callback_argument = arg;
	if (statsinterval != 0) {
		ctx->common.stats_report_time = statsinterval * RIST_CLOCK;
	}
	return 0;
}
int rist_receiver_stats_callback_set(struct rist_receiver *ctx, int statsinterval, int (*stats_cb)(void *arg, struct rist_stats *stats), void *arg)
{
	if (stats_cb == NULL) {
		return -1;
	}
	ctx->common.stats_callback = stats_cb;
	ctx->common.stats_callback_argument = arg;
	if (statsinterval != 0) {
		ctx->common.stats_report_time = statsinterval * RIST_CLOCK;
		struct rist_flow *f = ctx->common.FLOWS;
		while (f) {
			f->stats_report_time = statsinterval * RIST_CLOCK;
			f = f->next;
		}
	}
	return 0;
}
