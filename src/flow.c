/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 */

#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"

#define STALE_FLOW_TIME (60L * 1000L * RIST_CLOCK) /* in milliseconds */

void rist_server_missing(struct rist_flow *f, struct rist_peer *peer, uint32_t seq, uint32_t rtt)
{
	uint64_t now = timestampNTP_u64();

	struct rist_missing_buffer *m = calloc(1, sizeof(*m));
	m->seq = seq;
	m->insertion_time = now;

	m->next_nack = now + (uint64_t)rtt * (uint64_t)RIST_CLOCK;
	m->peer = peer;

	f->missing_counter++;
	peer->stats_server_instant.missing++;
	if (get_cctx(peer)->debug)
		msg(f->server_id, 0, RIST_LOG_DEBUG,
			"[DEBUG] Datagram %" PRIu32 " is missing, inserting into the missing queue "
			"with deadline in %" PRIu64 "ms (queue=%d), last_seq_found %"PRIu32"\n",
		seq, (m->next_nack - now) / RIST_CLOCK, f->missing_counter, f->last_seq_found);

	m->next = f->missing ? f->missing : NULL;
	// Insert it at the end of the queue
	f->missing = m;
}

void empty_server_queue(struct rist_flow *f)
{
	size_t counter = f->server_queue_output_idx;
	pthread_rwlock_wrlock(&f->queue_lock);
	while (f->server_queue_size > 0) {
		struct rist_buffer *b = f->server_queue[counter];
		if (b)
		{
			if (b->size)
				free(b->data);
			f->server_queue_size -= b->size;
			free(b);
		}
		counter = (counter + 1) % f->server_queue_max;
		if (counter == f->server_queue_output_idx) {
			// full loop complete
			break;
		}
	}
	pthread_rwlock_unlock(&f->queue_lock);
}

static void rist_flush_missing_flow_queue(struct rist_flow *flow)
{
	struct rist_missing_buffer *current = flow->missing;
	while (current)
	{
		struct rist_missing_buffer *delme = current;
		current = current->next;
		free(delme);
		delme = NULL;
	}
	flow->missing = NULL;
	flow->missing_counter = 0;
}

void rist_delete_flow(struct rist_server *ctx, struct rist_flow *f)
{
	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Triggering data output thread termination\n");
	f->shutdown = 1;
	while (f->shutdown != 2) {
		msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Waiting for data output thread to exit\n");
#ifdef WIN32
		Sleep(5);
#else
		usleep(5000);
#endif
	}
	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Exiting data output thread\n");
	f->server_thread = 0;

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Removing all peers from flow list\n");
	for (size_t i = 0; i < f->peer_lst_len; i++) {
		struct rist_peer *peer = f->peer_lst[i];
		peer->state_local = peer->state_peer = RIST_PEER_STATE_PING;
		peer->flow = NULL;
	}
	f->peer_lst_len = 0;
	free(f->peer_lst);
	f->peer_lst = NULL;

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Deleting missing queue elements\n");
	/* Delete all missing queue elements (if any) */
	rist_flush_missing_flow_queue(f);

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Deleting output buffer data\n");
	/* Delete all buffer data (if any) */
	empty_server_queue(f);

	// Delete flow
	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Deleting flow\n");
	struct rist_flow **prev_flow = &ctx->common.FLOWS;
	struct rist_flow *current_flow = *prev_flow;
	while (current_flow)
	{
		if (current_flow->flow_id == f->flow_id) {
			*prev_flow = current_flow->next;
			free(current_flow);
			current_flow = NULL;
			break;
		}
		prev_flow = &current_flow->next;
		current_flow = current_flow->next;
	}

}

static void rist_flow_append(struct rist_flow **FLOWS, struct rist_flow *f)
{
	if (*FLOWS == NULL) {
		// First entry
		*FLOWS = f;
		return;
	}

	// Append
	struct rist_flow *last = *FLOWS;
	while (last->next) {
		last = last->next;
	}

	last->next = f;
}

static struct rist_flow *create_flow(struct rist_server *ctx, uint64_t flow_id)
{
	struct rist_flow *f = calloc(1, sizeof(*f));
	if (!f) {
		msg(ctx->id, 0, RIST_LOG_ERROR,
			"[ERROR] Could not create server buffer of size %d MB, OOM\n", sizeof(*f) / 1000000);
		return NULL;
	}

	f->flow_id = flow_id;
	f->server_id = ctx->id;
	f->stats_next_time = timestampNTP_u64();
	f->max_output_jitter = ctx->common.rist_max_jitter;
	int ret = pthread_cond_init(&f->condition, NULL);
	if (ret) {
		free(f);
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Error %d calling pthread_cond_init\n", ret);
		return NULL;
	}

	ret = pthread_mutex_init(&f->mutex, NULL);
	if (ret){
		pthread_cond_destroy(&f->condition);
		free(f);
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Error %d calling pthread_mutex_init\n", ret);
		return NULL;
	}

	/* Append flow to list */
	rist_flow_append(&ctx->common.FLOWS, f);

	return f;
}

void rist_client_peer_statistics(struct rist_peer *peer)
{
	// TODO: print warning here?? stale flow?
	if (peer->state_local != RIST_PEER_STATE_CONNECT) {
		return;
	}

	if (peer->stats_client_instant.received == 0 && peer->stats_client_total.received > 0)
	{
		msg(0, peer->client_ctx->id, RIST_LOG_WARN, "[WARNING] Peer with id %zu is dead, stopping stream ...\n",
			peer->adv_peer_id);
		peer->dead = true;
		return;
	}

	peer->stats_client_total.sent += peer->stats_client_instant.sent;
	peer->stats_client_total.retrans += peer->stats_client_instant.retrans;
	peer->stats_client_total.bloat_skip += peer->stats_client_instant.bloat_skip;
	peer->stats_client_total.retrans_skip += peer->stats_client_instant.retrans_skip;
	peer->stats_client_total.received += peer->stats_client_instant.received;

	size_t retry_buf_size = 0;
	if (peer->client_ctx->client_retry_queue_write_index > peer->client_ctx->client_retry_queue_read_index) {
		retry_buf_size = peer->client_ctx->client_retry_queue_write_index -
							peer->client_ctx->client_retry_queue_read_index - 1;
	} else {
		retry_buf_size = peer->client_ctx->client_retry_queue_size + peer->client_ctx->client_retry_queue_write_index -
							peer->client_ctx->client_retry_queue_read_index - 1;
	}

	struct rist_bandwidth_estimation *cli_bw = &peer->bw;
	struct rist_bandwidth_estimation *retry_bw = &peer->retry_bw;
	// Refresh stats value just in case
	rist_calculate_bitrate_client(0, cli_bw);
	rist_calculate_bitrate_client(0, retry_bw);

	double Q = 100;
	if (peer->stats_client_instant.sent > 0) {
		Q = (double)((peer->stats_client_instant.sent) * 100.0) /
			(double)(peer->stats_client_instant.sent + peer->stats_client_instant.bloat_skip + peer->stats_client_instant.retrans_skip + peer->stats_client_instant.retrans);
	}

	uint32_t time_left = 0;
	if (peer->client_ctx->cooldown_time > 0) {
		time_left = (timestampNTP_u64() - peer->client_ctx->cooldown_time) / 1000;
	}

	uint32_t avg_rtt = (peer->eight_times_rtt / 8);
	msg(0, peer->client_ctx->id, RIST_LOG_INFO, "\t[STATS]type=instant,id=%u,bitrate=%" PRIu32 ",r_bitrate=%" PRIu32 ",sent=%" PRIu64 ",received=%" PRIu32 ",retransmits=%" PRIu32 ",bloat_skipped=%" PRIu32 ",retrans_skipped=%" PRIu32 ",Q=%.02lf,rtt=%d(us),avg_rtt=%" PRIu32 "(ms),retry_buf_size=%" PRIu32 ",cooldown=%" PRIu32 "(ms)\n",
		peer->adv_peer_id,
		cli_bw->bitrate,
		retry_bw->bitrate,
		peer->stats_client_instant.sent,
		peer->stats_client_instant.received,
		peer->stats_client_instant.retrans,
		peer->stats_client_instant.bloat_skip,
		peer->stats_client_instant.retrans_skip,
		Q,
		peer->last_mrtt,
		avg_rtt,
		retry_buf_size,
		time_left);

	msg(0, peer->client_ctx->id, RIST_LOG_INFO, "\t[STATS]type=total,id=%u,sent=%" PRIu64 ",received=%" PRIu32 ",retransmits=%" PRIu32 ",bloat_skipped=%" PRIu32 ",retrans_skipped=%" PRIu32 ",seq=%"PRIu32"\n",
		peer->adv_peer_id, peer->stats_client_total.sent, peer->stats_client_total.received, peer->stats_client_total.retrans,
		peer->stats_client_total.bloat_skip, peer->stats_client_total.retrans_skip,
		peer->client_ctx->common.seq);

	memset(&peer->stats_client_instant, 0, sizeof(peer->stats_client_instant));
}

struct rist_flow *rist_server_flow_statistics(struct rist_server *ctx, struct rist_flow *flow)
{
	if (!flow) {
		return NULL;
	}

	struct rist_flow *nextflow = flow->next;

	flow->stats_total.lost += flow->stats_instant.lost;

	if (flow->stats_total.min_ips > flow->stats_instant.min_ips) {
		flow->stats_total.min_ips = flow->stats_instant.min_ips;
	}

	if (flow->stats_total.max_ips < flow->stats_instant.max_ips) {
		flow->stats_total.max_ips = flow->stats_instant.max_ips;
	}

	if (flow->stats_total.avg_count) {
		flow->stats_total.cur_ips = (flow->stats_total.total_ips / flow->stats_total.avg_count);
	}

	if (flow->stats_instant.avg_count) {
		flow->stats_instant.cur_ips = (flow->stats_instant.total_ips / flow->stats_instant.avg_count);
	}

	// TODO: STALE_FLOW_TIME or buffer size in us ... which ever is greater
	if ((flow->stats_total.last_recv_ts != 0) && (timestampNTP_u64() - flow->stats_total.last_recv_ts > (uint64_t)STALE_FLOW_TIME)) {
		if ((timestampNTP_u64() - flow->stats_total.last_recv_ts) < (1.5*(uint64_t)STALE_FLOW_TIME)) {
			// Do nothing
			msg(flow->server_id, flow->client_id, RIST_LOG_INFO,
				"\t************** STALE FLOW:%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64", Deleting! ***************\n",
				timestampNTP_u64(),
				flow->stats_total.last_recv_ts,
				timestampNTP_u64() - flow->stats_total.last_recv_ts,
				(uint64_t)STALE_FLOW_TIME);
			pthread_rwlock_t *peerlist_lock = &ctx->common.peerlist_lock;
			pthread_rwlock_wrlock(peerlist_lock);
			rist_delete_flow(ctx, flow);
			pthread_rwlock_unlock(peerlist_lock);
		}

		return nextflow;
	}

	uint64_t flow_recv_instant = 0;
	uint32_t flow_missing_instant = 0;
	uint32_t flow_recovered_instant = 0;
	uint32_t flow_retries_instant = 0;
	uint32_t flow_dups_instant = 0;
	uint32_t flow_recovered_0nack_instant = 0;
	uint32_t flow_recovered_1nack_instant = 0;
	uint32_t flow_recovered_2nack_instant = 0;
	uint32_t flow_recovered_3nack_instant = 0;
	uint32_t flow_recovered_morenack_instant = 0;
	uint32_t flow_reordered_instant = 0;

	uint64_t flow_recv_total = 0;
	uint32_t flow_missing_total = 0;
	uint32_t flow_recovered_total = 0;
	uint32_t flow_retries_total = 0;
	uint32_t flow_dups_total = 0;
	uint32_t flow_recovered_0nack_total = 0;
	uint32_t flow_recovered_1nack_total = 0;
	uint32_t flow_recovered_2nack_total = 0;
	uint32_t flow_recovered_3nack_total = 0;
	uint32_t flow_recovered_morenack_total = 0;
	uint32_t flow_reordered_total = 0;

	for (size_t i = 0; i < flow->peer_lst_len; i++) {
		struct rist_peer *peer = flow->peer_lst[i];
		uint32_t avg_rtt = (peer->eight_times_rtt / 8);
		uint32_t bitrate;
		uint32_t eight_times_bitrate;

		bitrate = peer->bw.bitrate;
		eight_times_bitrate = peer->bw.eight_times_bitrate;

		double QpeerInstant = 100;
		if (peer->stats_server_instant.recv > 0) {
			QpeerInstant = (double)((peer->stats_server_instant.recv) * 100.0) /
							(double)(peer->stats_server_instant.recv + peer->stats_server_instant.missing);
		}

		if ((peer->stats_server_instant.recovered - peer->stats_server_instant.reordered) > 0) {
			peer->stats_server_instant.recovered_average =
				(peer->stats_server_instant.recovered_sum * 100) /
					(peer->stats_server_instant.recovered - peer->stats_server_instant.reordered);
		} else {
			peer->stats_server_instant.recovered_average = 100;
		}

		peer->stats_server_instant.recovered_slope =
				peer->stats_server_instant.recovered_3nack -
				peer->stats_server_instant.recovered_0nack;

		if ((int32_t)(peer->stats_server_instant.recovered_1nack - peer->stats_server_instant.recovered_0nack) > 0 &&
			peer->stats_server_instant.recovered_1nack != 0 && peer->stats_server_instant.recovered_0nack != 0) {
			peer->stats_server_instant.recovered_slope_inverted++;
		}

		if ((int32_t)(peer->stats_server_instant.recovered_2nack - peer->stats_server_instant.recovered_1nack) > 0 &&
			peer->stats_server_instant.recovered_2nack != 0 && peer->stats_server_instant.recovered_1nack != 0){
			peer->stats_server_instant.recovered_slope_inverted++;
		}

		if ((int32_t)(peer->stats_server_instant.recovered_3nack - peer->stats_server_instant.recovered_2nack) > 0 &&
			peer->stats_server_instant.recovered_3nack != 0 && peer->stats_server_instant.recovered_2nack != 0) {
				peer->stats_server_instant.recovered_slope_inverted++;
		}

		msg(flow->server_id, flow->client_id, RIST_LOG_INFO, "\t[STATS]type=peerinstant,flowid=%" PRIu64 ",dead=%d,peer=%u/%u(%u),received=%" PRIu64 ",missing=%" PRIu32 ",Q=%.02lf,recovered=%" PRIu32 ",n0=%" PRIu32 ",n1=%" PRIu32 ",n2=%" PRIu32 ",n3=%" PRIu32 ",n=%" PRIu32 ",n_avg=%" PRIu32 ",n_slope=%" PRId32 ",n_inverted=%" PRIu32 ",reordered=%" PRIu32 ",dups=%" PRIu32 ",retries=%" PRIu32 ",recover_buffer_length=%" PRIu32 "(ms),missing_queue_size=%" PRIu32 "/%" PRIu32 ",rtt=%d(us),avg_rtt=%" PRIu32 "(ms),bitrate=%" PRIu32 "(bps),avg_bitrate=%" PRIu32 "(bps)\n",
			flow->flow_id,
			peer->dead,
			(uint32_t)(i + 1),
			flow->peer_lst_len,
			peer->adv_peer_id,
			peer->stats_server_instant.recv,
			peer->stats_server_instant.missing,
			QpeerInstant,
			peer->stats_server_instant.recovered,
			peer->stats_server_instant.recovered_0nack,
			peer->stats_server_instant.recovered_1nack,
			peer->stats_server_instant.recovered_2nack,
			peer->stats_server_instant.recovered_3nack,
			peer->stats_server_instant.recovered_morenack,
			peer->stats_server_instant.recovered_average,
			peer->stats_server_instant.recovered_slope,
			peer->stats_server_instant.recovered_slope_inverted,
			peer->stats_server_instant.reordered,
			peer->stats_server_instant.dups,
			peer->stats_server_instant.retries,
			peer->recover_buffer_ticks / RIST_CLOCK,
			peer->flow->missing_counter,
			peer->missing_counter_max,
			peer->last_mrtt,
			avg_rtt,
			bitrate,
			eight_times_bitrate / 8);

		// Calculate peer totals
		peer->stats_server_total.recv += peer->stats_server_instant.recv;
		peer->stats_server_total.missing += peer->stats_server_instant.missing;
		peer->stats_server_total.recovered += peer->stats_server_instant.recovered;
		peer->stats_server_total.retries += peer->stats_server_instant.retries;
		peer->stats_server_total.dups += peer->stats_server_instant.dups;
		peer->stats_server_total.recovered_0nack += peer->stats_server_instant.recovered_0nack;
		peer->stats_server_total.recovered_1nack += peer->stats_server_instant.recovered_1nack;
		peer->stats_server_total.recovered_2nack += peer->stats_server_instant.recovered_2nack;
		peer->stats_server_total.recovered_3nack += peer->stats_server_instant.recovered_3nack;
		peer->stats_server_total.recovered_morenack += peer->stats_server_instant.recovered_morenack;
		peer->stats_server_total.reordered += peer->stats_server_instant.reordered;
		peer->stats_server_total.recovered_sum += peer->stats_server_instant.recovered_sum;
		peer->stats_server_total.recovered_average = peer->stats_server_instant.recovered_average +
								peer->stats_server_total.recovered_average -
								(peer->stats_server_total.recovered_average / 8);
		peer->stats_server_total.recovered_slope =
					peer->stats_server_instant.recovered_slope + peer->stats_server_total.recovered_slope -
					(peer->stats_server_total.recovered_slope / 8);

		double QpeerTotal = 100;
		if (peer->stats_server_total.recv > 0) {
			QpeerTotal = (double)((peer->stats_server_total.recv) * 100.0) /
							(double)(peer->stats_server_total.recv + peer->stats_server_total.missing);
		}

		msg(flow->server_id, flow->client_id, RIST_LOG_INFO, "\t[STATS]type=peertotal,flowid=%" PRIu64 ",dead=%d,peer=%u/%u(%u),received=%" PRIu64 ",missing=%" PRIu32 ",Q=%.02lf,recovered=%" PRIu32 ",n0=%" PRIu32 ",n1=%" PRIu32 ",n2=%" PRIu32 ",n3=%" PRIu32 ",n=%" PRIu32 ",n_avg=%" PRIu32 ",n_slope=%" PRId32 ",reordered=%" PRIu32 ",dups=%" PRIu32 ",retries=%" PRIu32 "\n",
			flow->flow_id,
			peer->dead,
			(uint32_t)(i + 1),
			flow->peer_lst_len,
			peer->adv_peer_id,
			peer->stats_server_total.recv,
			peer->stats_server_total.missing,
			QpeerTotal,
			peer->stats_server_total.recovered,
			peer->stats_server_total.recovered_0nack,
			peer->stats_server_total.recovered_1nack,
			peer->stats_server_total.recovered_2nack,
			peer->stats_server_total.recovered_3nack,
			peer->stats_server_total.recovered_morenack,
			peer->stats_server_total.recovered_average / 8,
			peer->stats_server_total.recovered_slope / 8,
			peer->stats_server_total.reordered,
			peer->stats_server_total.dups,
			peer->stats_server_total.retries);

		// Calculate flow instant stats
		flow_recv_instant += peer->stats_server_instant.recv;
		flow_missing_instant += peer->stats_server_instant.missing;
		flow_recovered_instant += peer->stats_server_instant.recovered;
		flow_retries_instant += peer->stats_server_instant.retries;
		flow_dups_instant += peer->stats_server_instant.dups;
		flow_recovered_0nack_instant += peer->stats_server_instant.recovered_0nack;
		flow_recovered_1nack_instant += peer->stats_server_instant.recovered_1nack;
		flow_recovered_2nack_instant += peer->stats_server_instant.recovered_2nack;
		flow_recovered_3nack_instant += peer->stats_server_instant.recovered_3nack;
		flow_recovered_morenack_instant += peer->stats_server_instant.recovered_morenack;
		flow_reordered_instant += peer->stats_server_instant.reordered;

		// Calculate flow total stats
		flow_recv_total += peer->stats_server_total.recv;
		flow_missing_total += peer->stats_server_total.missing;
		flow_recovered_total += peer->stats_server_total.recovered;
		flow_retries_total += peer->stats_server_total.retries;
		flow_dups_total += peer->stats_server_total.dups;
		flow_recovered_0nack_total += peer->stats_server_total.recovered_0nack;
		flow_recovered_1nack_total += peer->stats_server_total.recovered_1nack;
		flow_recovered_2nack_total += peer->stats_server_total.recovered_2nack;
		flow_recovered_3nack_total += peer->stats_server_total.recovered_3nack;
		flow_recovered_morenack_total += peer->stats_server_total.recovered_morenack;
		flow_reordered_total += peer->stats_server_total.reordered;

		// bufferbloat protection flags
		if (peer->bufferbloat_mode != RIST_BUFFER_BLOAT_MODE_OFF) {
			if (peer->stats_server_instant.recovered_slope_inverted >= 3) {
				if (!peer->bufferbloat_active) {
					msg(flow->server_id, flow->client_id, RIST_LOG_INFO,
						"\t[INFO] Activating buffer protection for peer %d, avg_slope=%d, avg_inverted=%d (%u/%u)\n",
						peer->adv_peer_id,
						peer->stats_server_instant.recovered_slope,
						peer->stats_server_instant.recovered_slope_inverted,
						peer->stats_server_instant.recovered_average,
						peer->stats_server_total.recovered_average/8);
					peer->bufferbloat_active = true;
				}
			}
			else if (peer->stats_server_instant.recovered_slope_inverted == 0) {
				if (peer->bufferbloat_active) {
					msg(flow->server_id, flow->client_id, RIST_LOG_INFO,
						"\t[INFO] Deactivating buffer protection for peer %d, avg_slope=%d, avg_inverted=%d (%u/%u)\n",
						peer->adv_peer_id,
						peer->stats_server_instant.recovered_slope,
						peer->stats_server_instant.recovered_slope_inverted,
						peer->stats_server_instant.recovered_average,
						peer->stats_server_total.recovered_average/8);
					peer->bufferbloat_active = false;
				}
			}
		}

		// Clear peer instant stats
		memset(&peer->stats_server_instant, 0, sizeof(peer->stats_server_instant));
	}

	double Q = 100;
	if (flow_recv_instant > 0) {
		Q = (double)((flow_recv_instant)*100.0) /
			(double)(flow_recv_instant + flow_missing_instant);
	}

	// This last one should trigger buffer protection immediately
	if ((flow->missing_counter == 0 || flow_recovered_instant == 0 || 
	(flow_recovered_instant * 10) < flow_missing_instant) && flow_recv_instant > 10 &&
		flow_recv_instant < flow_missing_instant)
	{
		msg(flow->server_id, flow->client_id, RIST_LOG_INFO, "\t[STATS]The flow link is dead %"PRIu32" > %"PRIu64", deleting all missing queue elements!\n",
		flow_missing_instant, flow_recv_instant);
		/* Delete all missing queue elements (if any) */
		rist_flush_missing_flow_queue(flow);
	}

	msg(flow->server_id, flow->client_id, RIST_LOG_INFO, "\t[STATS]type=flowinstant,flowid=%" PRIu64 ",received=%" PRIu64 ",missing=%" PRIu32 ",Q=%.02lf,recovered=%" PRIu32 ",n0=%" PRIu32 ",n1=%" PRIu32 ",n2=%" PRIu32 ",n3=%" PRIu32 ",n=%" PRIu32 ",lost=%" PRIu32 ",reordered=%" PRIu32 ",dups=%" PRIu32 ",retries=%" PRIu32 ",min_ips=%" PRIu64 ",cur_ips=%" PRIu64 ",max_ips=%" PRIu64 "\n",
		flow->flow_id,
		flow_recv_instant,
		flow_missing_instant,
		Q,
		flow_recovered_instant,
		flow_recovered_0nack_instant,
		flow_recovered_1nack_instant,
		flow_recovered_2nack_instant,
		flow_recovered_3nack_instant,
		flow_recovered_morenack_instant,
		flow->stats_instant.lost,
		flow_reordered_instant,
		flow_dups_instant,
		flow_retries_instant,
		flow->stats_instant.min_ips == 0xFFFFFFFFFFFFFFFF ? (uint64_t)0ULL : flow->stats_instant.min_ips,
		flow->stats_instant.cur_ips,
		flow->stats_instant.max_ips);

	Q = 100;
	if (flow_recv_total > 0) {
		Q = (double)((flow_recv_total)*100.0) / (double)(flow_recv_total + flow_missing_total);
	}

	msg(flow->server_id, flow->client_id, RIST_LOG_INFO, "\t[STATS]type=flowtotal,flowid=%" PRIu64 ",received=%" PRIu64 ",missing=%" PRIu32 ",Q=%.02lf,recovered=%" PRIu32 ",n0=%" PRIu32 ",n1=%" PRIu32 ",n2=%" PRIu32 ",n3=%" PRIu32 ",n+=%" PRIu32 ",lost=%" PRIu32 ",reordered=%" PRIu32 ",dups=%" PRIu32 ",retries=%" PRIu32 ",min_ips=%" PRIu64 ",cur_ips=%" PRIu64 ",max_ips=%" PRIu64 "\n",
		flow->flow_id,
		flow_recv_total,
		flow_missing_total,
		Q,
		flow_recovered_total,
		flow_recovered_0nack_total,
		flow_recovered_1nack_total,
		flow_recovered_2nack_total,
		flow_recovered_3nack_total,
		flow_recovered_morenack_total,
		flow->stats_total.lost,
		flow_reordered_total,
		flow_dups_total,
		flow_retries_total,
		(flow->stats_total.min_ips == 0xFFFFFFFFFFFFFFFF) ? (uint64_t) 0ULL : flow->stats_total.min_ips,
		flow->stats_total.cur_ips,
		flow->stats_total.max_ips);

	memset(&flow->stats_instant, 0, sizeof(flow->stats_instant));
	flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;

	printf("\n"); // just for GUI log

//	msg(flow->server_id, flow->client_id, RIST_LOG_INFO, "\t[STATS] last_seq_found %"PRIu32", last_seq_output %"PRIu32", missing_counter %"PRIu32"\n", 
//		flow->last_seq_found, flow->last_seq_output, flow->missing_counter, flow->missing_counter);

	return nextflow;
}

static bool flow_has_peer(struct rist_flow *f, uint64_t flow_id, uint32_t peer_id)
{
	for (size_t j = 0; j < f->peer_lst_len; j++) {
		struct rist_peer *p = f->peer_lst[j];
		if (p->adv_flow_id == flow_id && p->adv_peer_id == peer_id) {
			return true;
		}
	}

	return false;
}

int rist_server_associate_flow(struct rist_peer *p, uint32_t flow_id)
{
	struct rist_server *ctx = p->server_ctx;
	int ret = 0;

	// Find the flow based on the flow_id
	struct rist_flow *f;
	for (f = ctx->common.FLOWS; f != NULL; f = f->next) {
		if (f->flow_id == flow_id) {
			break;
		}
	}

	/* create flow if necessary */
	if (!f) {
		f = create_flow(ctx, flow_id);
		ret = 1;
		if (!f) {
			return -1;
		}

		if (p->short_seq) {
			f->short_seq = true;
			f->server_queue_max = UINT16_SIZE;
		}
		else
			f->server_queue_max = RIST_SERVER_QUEUE_BUFFERS;

		msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] FLOW #%"PRIu32" created\n", flow_id);
	} else {
		/* double check that this peer is not a member of this flow already */
		if (flow_has_peer(f, flow_id, p->adv_peer_id)) {
			msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] FLOW #%"PRIu32", Existing peer (id=%"PRIu32") re-joining existing flow ...\n",
				flow_id, p);
			ret = 2;
		} else {
			msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] FLOW #%"PRIu32": New peer (id=%u) joining existing flow ...\n",
				flow_id, p->adv_peer_id);
			ret = 1;
		}
	}

	// Transfer variables from peer to flow
	// Set/update max flow buffer size
	if (f->recover_buffer_ticks < p->recover_buffer_ticks)
		f->recover_buffer_ticks = p->recover_buffer_ticks;
	// Set/update max missing counter
	if (f->missing_counter_max < p->missing_counter_max)
		f->missing_counter_max = p->missing_counter_max;

	/* now assign flow to peer and add to list */
	p->flow = f;
	p->adv_flow_id = flow_id;
	if (ret == 1) {
		// TODO: lock the list?
		f->peer_lst = realloc(f->peer_lst, (f->peer_lst_len + 1) * sizeof(*f->peer_lst));
		f->peer_lst[f->peer_lst_len] = p;
		f->peer_lst_len++;
	}

	msg(ctx->id, 0, RIST_LOG_INFO,
		"[INIT] Peer with id #%u associated with flow #%" PRIu64 "\n", p->adv_peer_id, flow_id);

	msg(ctx->id, 0, RIST_LOG_INFO,
		"[INIT] Flow #%" PRIu64 " has now %d peers.\n", flow_id, f->peer_lst_len);

	return ret;
}

uint32_t rist_best_rtt_index(struct rist_flow *f)
{
	uint32_t index = 0;
	uint32_t rtt = UINT32_MAX;
	for (size_t i = 0; i < f->peer_lst_len; i++) {
		if (!f->peer_lst[i]->is_rtcp)
			continue;
		if (rtt > f->peer_lst[i]->eight_times_rtt) {
			index = i;
			rtt = f->peer_lst[i]->eight_times_rtt;
		}
	}

	return index;
}
