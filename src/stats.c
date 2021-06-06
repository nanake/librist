/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 * Author: Gijs Peskens <gijs@in2inip.nl>
 *
 * SPDX-License-Identifier: BSD-2-Clause
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
	if (!peer->authenticated)
	{
		return;
	}
	pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
	struct rist_stats *stats_container = malloc(sizeof(struct rist_stats));
	stats_container->stats_type = RIST_STATS_SENDER_PEER;
	stats_container->version = RIST_STATS_VERSION;

	peer->stats_sender_total.received += peer->stats_sender_instant.received;

	size_t retry_buf_size = rist_get_sender_retry_queue_size(peer->sender_ctx);

	struct rist_bandwidth_estimation *cli_bw = &peer->bw;
	struct rist_bandwidth_estimation *retry_bw = &peer->retry_bw;
	// Refresh stats value just in case
	rist_calculate_bitrate(0, cli_bw);
	rist_calculate_bitrate(0, retry_bw);

	double Q = 100;
	if (peer->stats_sender_instant.sent > 0)
	{
		Q = (double)((peer->stats_sender_instant.sent) * 100.0) /
			(double)(peer->stats_sender_instant.sent + peer->stats_sender_instant.bloat_skip + peer->stats_sender_instant.bandwidth_skip + peer->stats_sender_instant.retrans_skip + peer->stats_sender_instant.retrans);
		Q = round_two_digits(Q);
	}

	uint32_t time_left = 0;
	if (peer->sender_ctx->cooldown_time > 0)
	{
		time_left = (uint32_t)(timestampNTP_u64() - peer->sender_ctx->cooldown_time) / 1000;
	}

	size_t bitrate = cli_bw->eight_times_bitrate_fast / 8;
	size_t retry_bitrate = retry_bw->eight_times_bitrate_fast / 8;
	uint32_t avg_rtt = (peer->eight_times_rtt / 8);

	struct rist_common_ctx *cctx = get_cctx(peer);

	cJSON *stats = cJSON_CreateObject();
	cJSON *rist_sender_stats = cJSON_AddObjectToObject(stats, "sender-stats");
	cJSON *peer_obj = cJSON_AddObjectToObject(rist_sender_stats, "peer");
	cJSON_AddNumberToObject(peer_obj, "flow_id", peer->adv_flow_id);
	cJSON_AddNumberToObject(peer_obj, "id", peer->adv_peer_id);
	cJSON_AddStringToObject(peer_obj, "cname", peer->receiver_name);
	cJSON_AddStringToObject(peer_obj, "type", peer->is_data ? "data" : "rtcp");
	cJSON *json_stats = cJSON_AddObjectToObject(peer_obj, "stats");
	cJSON_AddNumberToObject(json_stats, "quality", Q);
	cJSON_AddNumberToObject(json_stats, "sent", (double)peer->stats_sender_instant.sent);
	cJSON_AddNumberToObject(json_stats, "received", (double)peer->stats_sender_instant.received);
	cJSON_AddNumberToObject(json_stats, "retransmitted", (double)peer->stats_sender_instant.retrans);
	cJSON_AddNumberToObject(json_stats, "bandwidth", (double)bitrate);
	cJSON_AddNumberToObject(json_stats, "retry_bandwidth", (double)retry_bitrate);
	cJSON_AddNumberToObject(json_stats, "bandwidth_skipped", (double)peer->stats_sender_instant.bandwidth_skip);
	cJSON_AddNumberToObject(json_stats, "bloat_skipped", (double)peer->stats_sender_instant.bloat_skip);
	cJSON_AddNumberToObject(json_stats, "retransmit_skipped", (double)peer->stats_sender_instant.retrans_skip);
	cJSON_AddNumberToObject(json_stats, "rtt", (double)peer->last_mrtt);
	cJSON_AddNumberToObject(json_stats, "avg_rtt", (double)avg_rtt);
	cJSON_AddNumberToObject(json_stats, "retry_buffer_size", (double)retry_buf_size);
	cJSON_AddNumberToObject(json_stats, "cooldown_time", (double)time_left);
	char *stats_string = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);

	stats_container->stats_json = stats_string;
	stats_container->json_size = (uint32_t)strlen(stats_string);
	stats_container->stats.sender_peer.cname[0] = '\0';
	strncpy(stats_container->stats.sender_peer.cname, peer->receiver_name, RIST_MAX_STRING_SHORT);
	stats_container->stats.sender_peer.peer_id = peer->adv_peer_id;
	stats_container->stats.sender_peer.bandwidth = bitrate;
	stats_container->stats.sender_peer.retry_bandwidth = retry_bitrate;
	stats_container->stats.sender_peer.sent = peer->stats_sender_instant.sent;
	stats_container->stats.sender_peer.received = peer->stats_sender_instant.received;
	stats_container->stats.sender_peer.retransmitted = peer->stats_sender_instant.retrans;
	stats_container->stats.sender_peer.quality = Q;
	stats_container->stats.sender_peer.rtt = avg_rtt;

	if (cctx->stats_callback != NULL)
		cctx->stats_callback(cctx->stats_callback_argument, stats_container);
	else
		rist_stats_free(stats_container);

	memset(&peer->stats_sender_instant, 0, sizeof(peer->stats_sender_instant));
	pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
}

void rist_receiver_flow_statistics(struct rist_receiver *ctx, struct rist_flow *flow)
{
	if (!flow)
		return;
	pthread_mutex_lock(&ctx->common.stats_lock);
	//Log errors that used to be packet
	if (flow->stats_instant.dropped_full)
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Dropped %u packets due to buffers being full\n", flow->stats_instant.dropped_full );
	if (flow->stats_instant.dropped_late)
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Dropped %u late packets\n", flow->stats_instant.dropped_late);
	if (flow->stats_instant.lost)
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Lost %u packets\n", flow->stats_instant.lost);

	struct rist_stats *stats_container = malloc(sizeof(struct rist_stats));
	stats_container->stats_type = RIST_STATS_RECEIVER_FLOW;
	stats_container->version = RIST_STATS_VERSION;

	if (flow->stats_instant.avg_count)
	{
		flow->stats_instant.cur_ips = (flow->stats_instant.total_ips / flow->stats_instant.avg_count);
	}

	cJSON *stats = cJSON_CreateObject();
	cJSON *stats_obj = cJSON_AddObjectToObject(stats, "receiver-stats");
	cJSON *flow_obj = cJSON_AddObjectToObject(stats_obj, "flowinstant");
	cJSON_AddNumberToObject(flow_obj, "flow_id", flow->flow_id);
	cJSON_AddNumberToObject(flow_obj, "dead",  flow->dead);
	cJSON *json_stats = cJSON_AddObjectToObject(flow_obj, "stats");
	cJSON *peers = cJSON_AddArrayToObject(flow_obj, "peers");
	uint32_t flow_rtt = 0;
	uint32_t flow_sent_instant = 0;
	for (size_t i = 0; i < flow->peer_lst_len; i++)
	{
		struct rist_peer *peer = flow->peer_lst[i];
		if (!peer->is_data && peer->peer_data)
			peer = peer->peer_data;
		uint32_t avg_rtt = (peer->eight_times_rtt / 8);

		size_t bitrate = peer->bw.eight_times_bitrate_fast / 8;
		size_t avg_bitrate = peer->bw.eight_times_bitrate / 8;
		flow_sent_instant += peer->stats_receiver_instant.sent_rtcp;
		flow_rtt =+ peer->eight_times_rtt / 8;

		cJSON *peer_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(peer_obj, "id", peer->adv_peer_id);
		cJSON_AddNumberToObject(peer_obj, "dead", peer->dead);
		cJSON *peer_stats = cJSON_AddObjectToObject(peer_obj, "stats");
		cJSON_AddNumberToObject(peer_stats, "received_data", (double)peer->stats_receiver_instant.received);
		cJSON_AddNumberToObject(peer_stats, "received_rtcp", (double)peer->stats_receiver_instant.received_rtcp);
		cJSON_AddNumberToObject(peer_stats, "sent_rtcp", (double)peer->stats_receiver_instant.sent_rtcp);
		cJSON_AddNumberToObject(peer_stats, "rtt", (double)peer->last_mrtt);
		cJSON_AddNumberToObject(peer_stats, "avg_rtt", (double)avg_rtt);
		cJSON_AddNumberToObject(peer_stats, "bitrate", (double)bitrate);
		cJSON_AddNumberToObject(peer_stats, "avg_bitrate", (double)avg_bitrate);
		cJSON_AddItemToArray(peers, peer_obj);
		// Clear peer instant stats
		memset(&peer->stats_receiver_instant, 0, sizeof(peer->stats_receiver_instant));
	}

	flow->stats_instant.recovered_average = (flow->stats_instant.recovered_sum * 100) - flow->stats_instant.recovered;
	flow->stats_instant.recovered_slope = flow->stats_instant.recovered_3nack - flow->stats_instant.recovered_0nack;
	if ((int32_t)(flow->stats_instant.recovered_1nack - flow->stats_instant.recovered_0nack) > 0 &&
		flow->stats_instant.recovered_1nack != 0 && flow->stats_instant.recovered_0nack != 0)
	{
		flow->stats_instant.recovered_slope_inverted++;
	}

	if ((int32_t)(flow->stats_instant.recovered_2nack - flow->stats_instant.recovered_1nack) > 0 &&
		flow->stats_instant.recovered_2nack != 0 && flow->stats_instant.recovered_1nack != 0)
	{
		flow->stats_instant.recovered_slope_inverted++;
	}

	if ((int32_t)(flow->stats_instant.recovered_3nack - flow->stats_instant.recovered_2nack) > 0 &&
		flow->stats_instant.recovered_3nack != 0 && flow->stats_instant.recovered_2nack != 0)
	{
		flow->stats_instant.recovered_slope_inverted++;
	}

	double Q = 100;
	if (flow->stats_instant.received > 0)
	{
		Q = (double)((flow->stats_instant.received)*100.0) /
			(double)(flow->stats_instant.received + flow->stats_instant.missing);
		Q = round_two_digits(Q);
	}

	// This last one should trigger buffer protection immediately
	if ((flow->missing_counter == 0 || flow->stats_instant.recovered == 0 ||
		 (flow->stats_instant.recovered * 10) < flow->stats_instant.missing) &&
		flow->stats_instant.received > 10 &&
		flow->stats_instant.received < flow->stats_instant.missing)
	{
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "\tThe flow link is dead %" PRIu32 " > %" PRIu64 ", deleting all missing queue elements!\n",
			flow->stats_instant.missing, flow->stats_instant.received);
		/* Delete all missing queue elements (if any) */
		rist_flush_missing_flow_queue(flow);
	}

	uint64_t avg_buffer_duration = 0;
	if (flow->stats_instant.buffer_duration_count > 0)
	{

		for (size_t i = 0; i < flow->stats_instant.buffer_duration_count; i++)
		{
			avg_buffer_duration += flow->stats_instant.buffer_duration[i];
		}
		avg_buffer_duration /= flow->stats_instant.buffer_duration_count;
		flow->stats_instant.buffer_duration_count = 0;
	}
	cJSON_AddNumberToObject(json_stats, "quality", Q);
	cJSON_AddNumberToObject(json_stats, "received", (double)flow->stats_instant.received);
	cJSON_AddNumberToObject(json_stats, "dropped_late", (double)flow->stats_instant.dropped_late);
	cJSON_AddNumberToObject(json_stats, "dropped_full", (double)flow->stats_instant.dropped_full);
	cJSON_AddNumberToObject(json_stats, "missing", (double)flow->stats_instant.missing);
	cJSON_AddNumberToObject(json_stats, "recovered_total", (double)flow->stats_instant.recovered);
	cJSON_AddNumberToObject(json_stats, "reordered", (double)flow->stats_instant.reordered);
	cJSON_AddNumberToObject(json_stats, "retries", (double)flow->stats_instant.retries);
	cJSON_AddNumberToObject(json_stats, "recovered_one_nack", (double)flow->stats_instant.recovered_0nack);
	cJSON_AddNumberToObject(json_stats, "recovered_two_nacks", (double)flow->stats_instant.recovered_1nack);
	cJSON_AddNumberToObject(json_stats, "recovered_three_nacks", (double)flow->stats_instant.recovered_2nack);
	cJSON_AddNumberToObject(json_stats, "recovered_four_nacks", (double)flow->stats_instant.recovered_3nack);
	cJSON_AddNumberToObject(json_stats, "recovered_more_nacks", (double)flow->stats_instant.recovered_morenack);
	cJSON_AddNumberToObject(json_stats, "lost", (double)flow->stats_instant.lost);
	cJSON_AddNumberToObject(json_stats, "avg_buffer_time", (double)avg_buffer_duration);
	cJSON_AddNumberToObject(json_stats, "duplicates", (double)flow->stats_instant.dupe);
	cJSON_AddNumberToObject(json_stats, "missing_queue", (double)flow->missing_counter);
	cJSON_AddNumberToObject(json_stats, "missing_queue_max", (double)flow->missing_counter_max);
	cJSON_AddNumberToObject(json_stats, "min_inter_packet_spacing", (double)flow->stats_instant.min_ips);
	cJSON_AddNumberToObject(json_stats, "cur_inter_packet_spacing", (double)flow->stats_instant.cur_ips);
	cJSON_AddNumberToObject(json_stats, "max_inter_packet_spacing", (double)flow->stats_instant.max_ips);
	cJSON_AddNumberToObject(json_stats, "bitrate", (double)flow->bw.bitrate);

	char *stats_string = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);

	stats_container->stats_json = stats_string;
	stats_container->json_size = (uint32_t)strlen(stats_string);

	stats_container->stats.receiver_flow.peer_count = (uint32_t)flow->peer_lst_len;
	// TODO: populate stats_receiver_flow->cname
	stats_container->stats.receiver_flow.cname[0] = '\0';
	stats_container->stats.receiver_flow.flow_id = flow->flow_id;
	stats_container->stats.receiver_flow.status = flow->dead;
	stats_container->stats.receiver_flow.bandwidth = flow->bw.bitrate;
	//TODO: populate retry_bandwidth;
	stats_container->stats.receiver_flow.retry_bandwidth = 0;
	stats_container->stats.receiver_flow.sent = flow->peer_lst_len ? flow_sent_instant / flow->peer_lst_len : 0;
	stats_container->stats.receiver_flow.received = flow->stats_instant.received;
	stats_container->stats.receiver_flow.missing = flow->stats_instant.missing;
	stats_container->stats.receiver_flow.reordered = flow->stats_instant.reordered;
	stats_container->stats.receiver_flow.recovered = flow->stats_instant.recovered;
	stats_container->stats.receiver_flow.recovered_one_retry = flow->stats_instant.recovered_0nack;
	stats_container->stats.receiver_flow.lost = flow->stats_instant.lost;
	stats_container->stats.receiver_flow.quality = Q;
	stats_container->stats.receiver_flow.min_inter_packet_spacing = flow->stats_instant.min_ips;
	stats_container->stats.receiver_flow.cur_inter_packet_spacing = flow->stats_instant.cur_ips;
	stats_container->stats.receiver_flow.max_inter_packet_spacing = flow->stats_instant.max_ips;
	stats_container->stats.receiver_flow.rtt = flow->peer_lst_len ? flow_rtt / flow->peer_lst_len : 0;

	/* CALLBACK CALL */
	if (ctx->common.stats_callback != NULL)
		ctx->common.stats_callback(ctx->common.stats_callback_argument, stats_container);
	else
		rist_stats_free(stats_container);

	memset(&flow->stats_instant, 0, sizeof(flow->stats_instant));
	flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;
	pthread_mutex_unlock(&ctx->common.stats_lock);
}
