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
#include "cjson/cJSON.h"

static double round_two_digits(double number)
{
	long new_number = (long)(number * 100);
	return (double)(new_number) / 100;
}

void rist_sender_peer_statistics(struct rist_peer *peer)
{
	// TODO: print warning here?? stale flow?
	if (peer->state_local != RIST_PEER_STATE_CONNECT)
	{
		return;
	}

	peer->stats_sender_total.received += peer->stats_sender_instant.received;

	size_t retry_buf_size = rist_get_sender_retry_queue_size(peer->sender_ctx);

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
		Q = round_two_digits(Q);
	}

	uint32_t time_left = 0;
	if (peer->sender_ctx->cooldown_time > 0)
	{
		time_left = (uint32_t)(timestampNTP_u64() - peer->sender_ctx->cooldown_time) / 1000;
	}

	uint32_t avg_rtt = (peer->eight_times_rtt / 8);

	struct rist_common_ctx *cctx = get_cctx(peer);

	cJSON *stats = cJSON_CreateObject();
	cJSON *rist_sender_stats = cJSON_AddObjectToObject(stats, "sender-stats");
	cJSON *peer_obj = cJSON_AddObjectToObject(rist_sender_stats, "peer");
	cJSON_AddNumberToObject(peer_obj, "id", peer->adv_peer_id);
	cJSON_AddStringToObject(peer_obj, "cname", peer->receiver_name);
	cJSON *peer_stats = cJSON_AddObjectToObject(peer_obj, "stats");
	cJSON_AddNumberToObject(peer_stats, "quality", Q);
	cJSON_AddNumberToObject(peer_stats, "sent", (double)peer->stats_sender_instant.sent);
	cJSON_AddNumberToObject(peer_stats, "received", (double)peer->stats_sender_instant.received);
	cJSON_AddNumberToObject(peer_stats, "retransmitted", (double)peer->stats_sender_instant.retrans);
	cJSON_AddNumberToObject(peer_stats, "bandwidth", (double)cli_bw->bitrate);
	cJSON_AddNumberToObject(peer_stats, "retry_bandwidth", (double)retry_bw->bitrate);
	cJSON_AddNumberToObject(peer_stats, "bloat_skipped", (double)peer->stats_sender_instant.bloat_skip);
	cJSON_AddNumberToObject(peer_stats, "retransmit_skipped", (double)peer->stats_sender_instant.retrans_skip);
	cJSON_AddNumberToObject(peer_stats, "rtt", (double)peer->last_mrtt);
	cJSON_AddNumberToObject(peer_stats, "avg_rtt", (double)avg_rtt);
	cJSON_AddNumberToObject(peer_stats, "retry_buffer_size", (double)retry_buf_size);
	cJSON_AddNumberToObject(peer_stats, "cooldown_time", (double)time_left);
	char *stats_string = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);
	if (cctx->stats_callback != NULL)
		cctx->stats_callback(cctx->stats_callback_argument, stats_string);
	else 
		free(stats_string);
	
	memset(&peer->stats_sender_instant, 0, sizeof(peer->stats_sender_instant));
}

void rist_receiver_flow_statistics(struct rist_receiver *ctx, struct rist_flow *flow)
{
	if (!flow)
		return;

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

	cJSON *stats = cJSON_CreateObject();
	cJSON *stats_obj = cJSON_AddObjectToObject(stats, "receiver-stats");
	cJSON *flow_obj = cJSON_AddObjectToObject(stats_obj, "flowinstant");
	cJSON_AddNumberToObject(flow_obj, "flow_id", flow->flow_id);
	cJSON_AddNumberToObject(flow_obj, "dead",  flow->dead);
	cJSON *flow_stats = cJSON_AddObjectToObject(flow_obj, "stats");
	cJSON *peers = cJSON_AddArrayToObject(flow_obj, "peers");
	for (size_t i = 0; i < flow->peer_lst_len; i++)
	{
		struct rist_peer *peer = flow->peer_lst[i];
		uint32_t avg_rtt = (peer->eight_times_rtt / 8);
		uint32_t bitrate;
		size_t eight_times_bitrate;

		bitrate = (uint32_t)peer->bw.bitrate;
		eight_times_bitrate = peer->bw.eight_times_bitrate;

		double QpeerInstant = 100;
		if (peer->stats_receiver_instant.recv > 0)
		{
			QpeerInstant = (double)((peer->stats_receiver_instant.recv) * 100.0) /
						   (double)(peer->stats_receiver_instant.recv + peer->stats_receiver_instant.missing);
			QpeerInstant = round_two_digits(QpeerInstant);
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

		cJSON *peer_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(peer_obj, "id", peer->adv_peer_id);
		cJSON_AddNumberToObject(peer_obj, "dead", peer->dead);
		cJSON *peer_stats = cJSON_AddObjectToObject(peer_obj, "stats");
		cJSON_AddNumberToObject(peer_stats, "quality", QpeerInstant);
		cJSON_AddNumberToObject(peer_stats, "received", (double)peer->stats_receiver_instant.recv);
		cJSON_AddNumberToObject(peer_stats, "missing", (double)peer->stats_receiver_instant.missing);
		cJSON_AddNumberToObject(peer_stats, "recovered_total", (double)peer->stats_receiver_instant.recovered);
		cJSON_AddNumberToObject(peer_stats, "reordered", (double)peer->stats_receiver_instant.reordered);
		cJSON_AddNumberToObject(peer_stats, "retries", (double)peer->stats_receiver_instant.retries);
		cJSON_AddNumberToObject(peer_stats, "recovered_one_nack", (double)peer->stats_receiver_instant.recovered_0nack);
		cJSON_AddNumberToObject(peer_stats, "recovered_two_nacks", (double)peer->stats_receiver_instant.recovered_1nack);
		cJSON_AddNumberToObject(peer_stats, "recovered_three_nacks", (double)peer->stats_receiver_instant.recovered_2nack);
		cJSON_AddNumberToObject(peer_stats, "recovered_four_nacks", (double)peer->stats_receiver_instant.recovered_3nack);
		cJSON_AddNumberToObject(peer_stats, "recovered_more_nacks", (double)peer->stats_receiver_instant.recovered_morenack);
		cJSON_AddNumberToObject(peer_stats, "recovered_average", (double)peer->stats_receiver_instant.recovered_average);
		cJSON_AddNumberToObject(peer_stats, "recovered_slope", (double)peer->stats_receiver_instant.recovered_slope);
		cJSON_AddNumberToObject(peer_stats, "recovered_slope_inverse", (double)peer->stats_receiver_instant.recovered_slope_inverted);
		cJSON_AddNumberToObject(peer_stats, "duplicates", (double)peer->stats_receiver_instant.dups);
		cJSON_AddNumberToObject(peer_stats, "recovery_buffer_length", (double)peer->recovery_buffer_ticks / RIST_CLOCK);
		cJSON_AddNumberToObject(peer_stats, "rtt", (double)peer->last_mrtt);
		cJSON_AddNumberToObject(peer_stats, "avg_rtt", (double)avg_rtt);
		cJSON_AddNumberToObject(peer_stats, "bitrate", (double)bitrate);
		cJSON_AddNumberToObject(peer_stats, "avg_bitrate", (double)eight_times_bitrate / 8);
		cJSON_AddItemToArray(peers, peer_obj);
	
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
		if (peer->config.congestion_control_mode != RIST_CONGESTION_CONTROL_MODE_OFF)
		{
			if (peer->stats_receiver_instant.recovered_slope_inverted >= 3)
			{
				if (!peer->buffer_bloat_active)
				{
					rist_log_priv(&ctx->common, RIST_LOG_INFO,
						"\tActivating buffer protection for peer %d, avg_slope=%d, avg_inverted=%d (%u/%u)\n",
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
					rist_log_priv(&ctx->common, RIST_LOG_INFO,
						"\tDeactivating buffer protection for peer %d, avg_slope=%d, avg_inverted=%d (%u/%u)\n",
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
		Q = round_two_digits(Q);
	}

	// This last one should trigger buffer protection immediately
	if ((flow->missing_counter == 0 || flow_recovered_instant == 0 ||
		 (flow_recovered_instant * 10) < flow_missing_instant) &&
		flow_recv_instant > 10 &&
		flow_recv_instant < flow_missing_instant)
	{
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "\tThe flow link is dead %" PRIu32 " > %" PRIu64 ", deleting all missing queue elements!\n",
			flow_missing_instant, flow_recv_instant);
		/* Delete all missing queue elements (if any) */
		rist_flush_missing_flow_queue(flow);
	}

	cJSON_AddNumberToObject(flow_stats, "quality", Q);
	cJSON_AddNumberToObject(flow_stats, "received", (double)flow_recv_instant);
	cJSON_AddNumberToObject(flow_stats, "missing", (double)flow_missing_instant);
	cJSON_AddNumberToObject(flow_stats, "recovered_total", (double)flow_recovered_instant);
	cJSON_AddNumberToObject(flow_stats, "reordered", (double)flow_reordered_instant);
	cJSON_AddNumberToObject(flow_stats, "retries", (double)flow_retries_instant);
	cJSON_AddNumberToObject(flow_stats, "recovered_one_nack", (double)flow_recovered_0nack_instant);
	cJSON_AddNumberToObject(flow_stats, "recovered_two_nacks", (double)flow_recovered_1nack_instant);
	cJSON_AddNumberToObject(flow_stats, "recovered_three_nacks", (double)flow_recovered_2nack_instant);
	cJSON_AddNumberToObject(flow_stats, "recovered_four_nacks", (double)flow_recovered_3nack_instant);
	cJSON_AddNumberToObject(flow_stats, "recovered_more_nacks", (double)flow_recovered_morenack_instant);
	cJSON_AddNumberToObject(flow_stats, "lost", (double)flow->stats_instant.lost);
	cJSON_AddNumberToObject(flow_stats, "duplicates", (double)flow_dups_instant);
	cJSON_AddNumberToObject(flow_stats, "missing_queue", (double)flow->missing_counter);
	cJSON_AddNumberToObject(flow_stats, "missing_queue_max", (double)flow->missing_counter_max);
	cJSON_AddNumberToObject(flow_stats, "min_inter_packet_spacing", (double)flow->stats_instant.min_ips);
	cJSON_AddNumberToObject(flow_stats, "cur_inter_packet_spacing", (double)flow->stats_instant.cur_ips);
	cJSON_AddNumberToObject(flow_stats, "max_inter_packet_spacing", (double)flow->stats_instant.max_ips);
	
	char *stats_string = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);

	/* CALLBACK CALL */
	if (ctx->common.stats_callback != NULL)
		ctx->common.stats_callback(ctx->common.stats_callback_argument, stats_string);
	else
		free(stats_string);

	memset(&flow->stats_instant, 0, sizeof(flow->stats_instant));
	flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;

}
