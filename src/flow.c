/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 */

#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"

void rist_receiver_missing(struct rist_flow *f, struct rist_peer *peer, uint32_t seq, uint32_t rtt)
{
	uint64_t now = timestampNTP_u64();

	struct rist_missing_buffer *m = calloc(1, sizeof(*m));
	m->seq = seq;
	m->insertion_time = now;

	m->next_nack = now + (uint64_t)rtt * (uint64_t)RIST_CLOCK;
	m->peer = peer;

	f->missing_counter++;
	peer->stats_receiver_instant.missing++;
	if (get_cctx(peer)->debug)
		rist_log(get_cctx(peer), RIST_LOG_DEBUG,
			"Datagram %" PRIu32 " is missing, inserting into the missing queue "
			"with deadline in %" PRIu64 "ms (queue=%d), last_seq_found %"PRIu32"\n",
		seq, (m->next_nack - now) / RIST_CLOCK, f->missing_counter, f->last_seq_found);

	m->next = NULL;
	// Insert it at the end of the queue
	if (!f->missing) {
		f->missing = m;
		f->missing_tail = m;
	} else {
		f->missing_tail->next = m;
		f->missing_tail = m;
	}
}

void empty_receiver_queue(struct rist_flow *f, struct rist_common_ctx *ctx)
{
	size_t output_queue_idx = atomic_load_explicit(&f->receiver_queue_output_idx, memory_order_acquire);
	size_t counter = output_queue_idx;
	while (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) > 0) {
		struct rist_buffer *b = f->receiver_queue[counter];
		if (b)
		{
			f->receiver_queue[counter] = NULL;
			free_rist_buffer(ctx, b);
			atomic_fetch_sub_explicit(&f->receiver_queue_size, b->size, memory_order_release);
		}
		counter = (counter + 1) % f->receiver_queue_max;
		if (counter == output_queue_idx) {
			// full loop complete
			break;
		}
	}
}

void rist_flush_missing_flow_queue(struct rist_flow *flow)
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

void rist_delete_flow(struct rist_receiver *ctx, struct rist_flow *f)
{
	rist_log(&ctx->common, RIST_LOG_INFO, "Triggering data output thread termination\n");
	f->shutdown = 1;
	while (f->shutdown != 2) {
		rist_log(&ctx->common, RIST_LOG_INFO, "Waiting for data output thread to exit\n");
		usleep(5000);
	}

	rist_log(&ctx->common, RIST_LOG_INFO, "Removing all peers from flow list\n");
	for (size_t i = 0; i < f->peer_lst_len; i++) {
		struct rist_peer *peer = f->peer_lst[i];
		peer->state_local = peer->state_peer = RIST_PEER_STATE_PING;
		peer->flow = NULL;
		peer->adv_flow_id = 0;
	}
	f->peer_lst_len = 0;
	free(f->peer_lst);
	f->peer_lst = NULL;

	rist_log(&ctx->common, RIST_LOG_INFO, "Deleting missing queue elements\n");
	/* Delete all missing queue elements (if any) */
	rist_flush_missing_flow_queue(f);

	rist_log(&ctx->common, RIST_LOG_INFO, "Deleting output buffer data\n");
	/* Delete all buffer data (if any) */
	empty_receiver_queue(f, &ctx->common);

	// Delete flow
	rist_log(&ctx->common, RIST_LOG_INFO, "Deleting flow\n");
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

static struct rist_flow *create_flow(struct rist_receiver *ctx, uint32_t flow_id)
{
	struct rist_flow *f = calloc(1, sizeof(*f));
	if (!f) {
		rist_log(&ctx->common, RIST_LOG_ERROR,
			"Could not create receiver buffer of size %d MB, OOM\n", sizeof(*f) / 1000000);
		return NULL;
	}

	f->flow_id = flow_id;
	f->receiver_id = ctx->id;
	f->stats_next_time = timestampNTP_u64();
	f->max_output_jitter = ctx->common.rist_max_jitter;
	int ret = pthread_cond_init(&f->condition, NULL);
	if (ret) {
		free(f);
		rist_log(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_cond_init\n", ret);
		return NULL;
	}

	ret = pthread_mutex_init(&f->mutex, NULL);
	if (ret){
		pthread_cond_destroy(&f->condition);
		free(f);
		rist_log(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_mutex_init\n", ret);
		return NULL;
	}

	atomic_init(&f->receiver_queue_size, 0);
	atomic_init(&f->receiver_queue_output_idx, 0);

	f->session_timeout = RIST_DEFAULT_SESSION_TIMEOUT * RIST_CLOCK;

	/* Append flow to list */
	rist_flow_append(&ctx->common.FLOWS, f);

	return f;
}

static bool flow_has_peer(struct rist_flow *f, uint32_t flow_id, uint32_t peer_id)
{
	for (size_t j = 0; j < f->peer_lst_len; j++) {
		struct rist_peer *p = f->peer_lst[j];
		if (p->adv_flow_id == flow_id && p->adv_peer_id == peer_id) {
			return true;
		}
	}

	return false;
}

int rist_receiver_associate_flow(struct rist_peer *p, uint32_t flow_id)
{
	struct rist_receiver *ctx = p->receiver_ctx;
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

		if (ctx->common.profile < RIST_PROFILE_ADVANCED) {
			f->short_seq = true;
			f->receiver_queue_max = UINT16_SIZE;
		}
		else
			f->receiver_queue_max = RIST_SERVER_QUEUE_BUFFERS;

		rist_log(&ctx->common, RIST_LOG_INFO, "FLOW #%"PRIu32" created (short=%d)\n", flow_id, f->short_seq);
	} else {
		/* double check that this peer is not a member of this flow already */
		if (flow_has_peer(f, flow_id, p->adv_peer_id)) {
			rist_log(&ctx->common, RIST_LOG_INFO, "FLOW #%"PRIu32", Existing peer (id=%"PRIu32") re-joining existing flow ...\n",
				flow_id, p);
			ret = 2;
		} else {
			rist_log(&ctx->common, RIST_LOG_INFO, "FLOW #%"PRIu32": New peer (id=%u) joining existing flow ...\n",
				flow_id, p->adv_peer_id);
			ret = 1;
		}
	}

	// Transfer variables from peer to flow
	// Set/update max flow buffer size
	if (f->recovery_buffer_ticks < p->recovery_buffer_ticks) {
		if (f->stats_report_time == f->recovery_buffer_ticks)
			f->stats_report_time = p->recovery_buffer_ticks;
		f->recovery_buffer_ticks = p->recovery_buffer_ticks;
		// This only happens when the buffer is greater than 60 seconds
		if (f->recovery_buffer_ticks > f->session_timeout)
			f->session_timeout = 2ULL * f->recovery_buffer_ticks;
	}
	uint64_t stats_report_time = get_cctx(p)->stats_report_time;
	if (stats_report_time != 0 && stats_report_time != f->stats_report_time) 
		f->stats_report_time = stats_report_time;

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

	rist_log(&ctx->common, RIST_LOG_INFO,
		"Peer with id #%u associated with flow #%" PRIu64 "\n", p->adv_peer_id, flow_id);

	rist_log(&ctx->common, RIST_LOG_INFO,
		"Flow #%" PRIu64 " has now %d peers.\n", flow_id, f->peer_lst_len);

	return ret;
}

size_t rist_best_rtt_index(struct rist_flow *f)
{
	size_t index = 0;
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
