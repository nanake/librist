/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 * Author: Gijs Peskens <gijs@in2inip.nl>
 */

#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"
#include <string.h>

void rist_sender_peer_statistics(struct rist_peer *peer)
{
	// TODO: print warning here?? stale flow?
	if (peer->state_local != RIST_PEER_STATE_CONNECT)
	{
		return;
	}

	peer->stats_sender_total.received += peer->stats_sender_instant.received;

	size_t retry_buf_size = 0;
	if (peer->sender_ctx->sender_retry_queue_write_index > peer->sender_ctx->sender_retry_queue_read_index)
	{
		retry_buf_size = peer->sender_ctx->sender_retry_queue_write_index -
						 peer->sender_ctx->sender_retry_queue_read_index - 1;
	}
	else
	{
		retry_buf_size = peer->sender_ctx->sender_retry_queue_size + peer->sender_ctx->sender_retry_queue_write_index -
						 peer->sender_ctx->sender_retry_queue_read_index - 1;
	}

	struct rist_bandwidth_estimation *cli_bw = &peer->bw;
	struct rist_bandwidth_estimation *retry_bw = &peer->retry_bw;
	// Refresh stats value just in case
	rist_calculate_bitrate_sender(0, cli_bw);
	rist_calculate_bitrate_sender(0, retry_bw);

	double Q = 100;
	if (peer->stats_sender_instant.sent > 0)
	{
		Q = (double)((peer->stats_sender_instant.sent) * 100.0) /
			(double)(peer->stats_sender_instant.sent + peer->stats_sender_instant.bloat_skip + peer->stats_sender_instant.retrans_skip + peer->stats_sender_instant.retrans);
	}

	uint32_t time_left = 0;
	if (peer->sender_ctx->cooldown_time > 0)
	{
		time_left = (timestampNTP_u64() - peer->sender_ctx->cooldown_time) / 1000;
	}

	uint32_t avg_rtt = (peer->eight_times_rtt / 8);

	struct rist_common_ctx *cctx = get_cctx(peer);
	struct rist_stats *rist_stats = malloc(sizeof(struct rist_stats));
	rist_stats->stats_type = RIST_STATS_SENDER_PEER;
	struct rist_stats_sender_peer *peer_stats = &rist_stats->stats.rist_stats_sender_peer;
	strncpy(peer_stats->cname, peer->receiver_name, 128 );
	peer_stats->peer_id = peer->adv_peer_id;
	peer_stats->bandwidth = cli_bw->bitrate;
	peer_stats->retry_bandwidth = retry_bw->bitrate;
	peer_stats->sent = peer->stats_sender_instant.sent;
	peer_stats->received = peer->stats_sender_instant.received;
	peer_stats->retransmitted = peer->stats_sender_instant.retrans;
	peer_stats->bloat_skipped = peer->stats_sender_instant.bloat_skip;
	peer_stats->retransmit_skipped = peer->stats_sender_instant.retrans_skip;
	peer_stats->quality = Q;
	peer_stats->rtt = peer->last_mrtt;
	peer_stats->avg_rtt = avg_rtt;
	peer_stats->retry_buffer_size = retry_buf_size;
	peer_stats->cooldown_time = time_left;

	if (cctx->stats_callback != NULL)
		cctx->stats_callback(cctx->stats_callback_argument, rist_stats);
	else
		free(rist_stats);

	memset(&peer->stats_sender_instant, 0, sizeof(peer->stats_sender_instant));
}

struct rist_flow *rist_receiver_flow_statistics(struct rist_receiver *ctx, struct rist_flow *flow)
{
	if (!flow)
	{
		return NULL;
	}

	struct rist_flow *nextflow = flow->next;

	if (flow->stats_instant.avg_count)
	{
		flow->stats_instant.cur_ips = (flow->stats_instant.total_ips / flow->stats_instant.avg_count);
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

	struct rist_stats *rist_stats = malloc(sizeof(struct rist_stats)+ sizeof(struct rist_stats_receiver_flow_peer) * (flow->peer_lst_len -1));
	rist_stats->stats_type = RIST_STATS_RECEIVER_FLOW;
	struct rist_stats_receiver_flow *stats = &rist_stats->stats.rist_stats_receiver_flow;

	for (size_t i = 0; i < flow->peer_lst_len; i++)
	{
		struct rist_peer *peer = flow->peer_lst[i];
		uint32_t avg_rtt = (peer->eight_times_rtt / 8);
		uint32_t bitrate;
		uint32_t eight_times_bitrate;

		bitrate = peer->bw.bitrate;
		eight_times_bitrate = peer->bw.eight_times_bitrate;

		double QpeerInstant = 100;
		if (peer->stats_receiver_instant.recv > 0)
		{
			QpeerInstant = (double)((peer->stats_receiver_instant.recv) * 100.0) /
						   (double)(peer->stats_receiver_instant.recv + peer->stats_receiver_instant.missing);
		}

		if ((peer->stats_receiver_instant.recovered - peer->stats_receiver_instant.reordered) > 0)
		{
			peer->stats_receiver_instant.recovered_average =
				(peer->stats_receiver_instant.recovered_sum * 100) /
				(peer->stats_receiver_instant.recovered - peer->stats_receiver_instant.reordered);
		}
		else
		{
			peer->stats_receiver_instant.recovered_average = 100;
		}

		peer->stats_receiver_instant.recovered_slope =
			peer->stats_receiver_instant.recovered_3nack -
			peer->stats_receiver_instant.recovered_0nack;

		if ((int32_t)(peer->stats_receiver_instant.recovered_1nack - peer->stats_receiver_instant.recovered_0nack) > 0 &&
			peer->stats_receiver_instant.recovered_1nack != 0 && peer->stats_receiver_instant.recovered_0nack != 0)
		{
			peer->stats_receiver_instant.recovered_slope_inverted++;
		}

		if ((int32_t)(peer->stats_receiver_instant.recovered_2nack - peer->stats_receiver_instant.recovered_1nack) > 0 &&
			peer->stats_receiver_instant.recovered_2nack != 0 && peer->stats_receiver_instant.recovered_1nack != 0)
		{
			peer->stats_receiver_instant.recovered_slope_inverted++;
		}

		if ((int32_t)(peer->stats_receiver_instant.recovered_3nack - peer->stats_receiver_instant.recovered_2nack) > 0 &&
			peer->stats_receiver_instant.recovered_3nack != 0 && peer->stats_receiver_instant.recovered_2nack != 0)
		{
			peer->stats_receiver_instant.recovered_slope_inverted++;
		}

		// Calculate peer totals
		peer->stats_receiver_total.recovered_average = peer->stats_receiver_instant.recovered_average +
													   peer->stats_receiver_total.recovered_average -
													   (peer->stats_receiver_total.recovered_average / 8);

		strncpy(stats->peers[i].cname, peer->receiver_name, 128);
		stats->peers[i].flow_id = flow->flow_id;
		stats->peers[i].dead = peer->dead;
		stats->peers[i].peer_id = peer->adv_peer_id;
		stats->peers[i].peer_num = (uint32_t)(i + 1);
		stats->peers[i].flow_peer_list_len = flow->peer_lst_len;
		stats->peers[i].received = peer->stats_receiver_instant.recv;
		stats->peers[i].missing = peer->stats_receiver_instant.missing;
		stats->peers[i].quality = QpeerInstant;
		stats->peers[i].recovered_total = peer->stats_receiver_instant.recovered;
		stats->peers[i].recovered_no_nack = peer->stats_receiver_instant.recovered_0nack;
		stats->peers[i].recovered_one_nack = peer->stats_receiver_instant.recovered_1nack;
		stats->peers[i].recovered_two_nacks = peer->stats_receiver_instant.recovered_2nack;
		stats->peers[i].recovered_three_nacks = peer->stats_receiver_instant.recovered_3nack;
		stats->peers[i].recovered_more_nacks = peer->stats_receiver_instant.recovered_morenack;
		stats->peers[i].recovered_average = peer->stats_receiver_instant.recovered_average;
		stats->peers[i].recovered_slope = peer->stats_receiver_instant.recovered_slope;
		stats->peers[i].recovered_slope_inverse = peer->stats_receiver_instant.recovered_slope_inverted;
		stats->peers[i].reordered = peer->stats_receiver_instant.reordered;
		stats->peers[i].duplicates = peer->stats_receiver_instant.dups;
		stats->peers[i].retries = peer->stats_receiver_instant.retries;
		stats->peers[i].recovery_buffer_length = peer->recovery_buffer_ticks / RIST_CLOCK;
		stats->peers[i].missing_queue = peer->flow->missing_counter;
		stats->peers[i].missing_queue_max = peer->missing_counter_max;
		stats->peers[i].rtt = peer->last_mrtt;
		stats->peers[i].avg_rtt = avg_rtt;
		stats->peers[i].bitrate = bitrate;
		stats->peers[i].avg_bitrate = eight_times_bitrate / 8;
		
		// Calculate flow instant stats
		flow_recv_instant += peer->stats_receiver_instant.recv;
		flow_missing_instant += peer->stats_receiver_instant.missing;
		flow_recovered_instant += peer->stats_receiver_instant.recovered;
		flow_retries_instant += peer->stats_receiver_instant.retries;
		flow_dups_instant += peer->stats_receiver_instant.dups;
		flow_recovered_0nack_instant += peer->stats_receiver_instant.recovered_0nack;
		flow_recovered_1nack_instant += peer->stats_receiver_instant.recovered_1nack;
		flow_recovered_2nack_instant += peer->stats_receiver_instant.recovered_2nack;
		flow_recovered_3nack_instant += peer->stats_receiver_instant.recovered_3nack;
		flow_recovered_morenack_instant += peer->stats_receiver_instant.recovered_morenack;
		flow_reordered_instant += peer->stats_receiver_instant.reordered;

		// buffer_bloat protection flags
		if (peer->config.buffer_bloat_mode != RIST_BUFFER_BLOAT_MODE_OFF)
		{
			if (peer->stats_receiver_instant.recovered_slope_inverted >= 3)
			{
				if (!peer->buffer_bloat_active)
				{
					msg(flow->receiver_id, flow->sender_id, RIST_LOG_INFO,
						"\t[INFO] Activating buffer protection for peer %d, avg_slope=%d, avg_inverted=%d (%u/%u)\n",
						peer->adv_peer_id,
						peer->stats_receiver_instant.recovered_slope,
						peer->stats_receiver_instant.recovered_slope_inverted,
						peer->stats_receiver_instant.recovered_average,
						peer->stats_receiver_total.recovered_average / 8);
					peer->buffer_bloat_active = true;
				}
			}
			else if (peer->stats_receiver_instant.recovered_slope_inverted == 0)
			{
				if (peer->buffer_bloat_active)
				{
					msg(flow->receiver_id, flow->sender_id, RIST_LOG_INFO,
						"\t[INFO] Deactivating buffer protection for peer %d, avg_slope=%d, avg_inverted=%d (%u/%u)\n",
						peer->adv_peer_id,
						peer->stats_receiver_instant.recovered_slope,
						peer->stats_receiver_instant.recovered_slope_inverted,
						peer->stats_receiver_instant.recovered_average,
						peer->stats_receiver_total.recovered_average / 8);
					peer->buffer_bloat_active = false;
				}
			}
		}

		// Clear peer instant stats
		memset(&peer->stats_receiver_instant, 0, sizeof(peer->stats_receiver_instant));
	}

	double Q = 100;
	if (flow_recv_instant > 0)
	{
		Q = (double)((flow_recv_instant)*100.0) /
			(double)(flow_recv_instant + flow_missing_instant);
	}

	// This last one should trigger buffer protection immediately
	if ((flow->missing_counter == 0 || flow_recovered_instant == 0 ||
		 (flow_recovered_instant * 10) < flow_missing_instant) &&
		flow_recv_instant > 10 &&
		flow_recv_instant < flow_missing_instant)
	{
		msg(flow->receiver_id, flow->sender_id, RIST_LOG_INFO, "\t[STATS]The flow link is dead %" PRIu32 " > %" PRIu64 ", deleting all missing queue elements!\n",
			flow_missing_instant, flow_recv_instant);
		/* Delete all missing queue elements (if any) */
		rist_flush_missing_flow_queue(flow);
	}
	stats->flow_id = flow->flow_id;
	stats->received = flow_recv_instant;
	stats->missing = flow_missing_instant;
	stats->quality = Q;
	stats->recovered_total = flow_recovered_instant;
	stats->recovered_no_nack = flow_recovered_0nack_instant;
	stats->recovered_one_nack = flow_recovered_1nack_instant;
	stats->recovered_two_nacks = flow_recovered_2nack_instant;
	stats->recovered_three_nacks = flow_recovered_3nack_instant;
	stats->recovered_more_nacks = flow_recovered_morenack_instant;
	stats->lost = flow->stats_instant.lost;
	stats->reordered = flow_reordered_instant;
	stats->duplicates = flow_dups_instant;
	stats->retries = flow_retries_instant;
	stats->min_inter_packet_spacing = flow->stats_instant.min_ips;
	stats->cur_inter_packet_spacing = flow->stats_instant.cur_ips;
	stats->max_inter_packet_spacing = flow->stats_instant.max_ips;
	stats->peer_list_len = flow->peer_lst_len;

	/* CALLBACK CALL */
	if (ctx->common.stats_callback != NULL)
		ctx->common.stats_callback(ctx->common.stats_callback_argument, rist_stats);
	else
		free(rist_stats);

	memset(&flow->stats_instant, 0, sizeof(flow->stats_instant));
	flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;

	return nextflow;
}
