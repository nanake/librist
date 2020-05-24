#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"
#include <assert.h>

extern uint32_t generate_flowid(uint64_t birthtime, uint32_t pid, const char *phrase);

int rist_sender_jitter_max_set(struct rist_sender *ctx, int t)
{
	return rist_max_jitter_set(&ctx->common, t);
}

int rist_receiver_jitter_max_set(struct rist_receiver *ctx, int t)
{
	return rist_max_jitter_set(&ctx->common, t);
}

int rist_receiver_oob_read(struct rist_receiver *ctx, const struct rist_oob_block **oob_block)
{
	RIST_MARK_UNUSED(oob_block);
	if (!ctx)
	{
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
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null on rist_receiver_data_read call!\n");
		return -1;
	}

	const struct rist_data_block *data_block = NULL;
	/* We could enter the lock now, to read the counter. However performance penalties apply.
	   The risks for not entering the lock are either sleeping too much (a packet gets added while we read)
	   or not at all when we should (i.e.: the calling application is reading from multiple threads). Both
	   risks are tolerable */
	uint16_t num = ctx->dataout_fifo_queue_counter;
	if (!num && timeout > 0) {
		pthread_mutex_lock(&(ctx->mutex));
		pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), timeout);
		pthread_mutex_unlock(&(ctx->mutex));
	}

	pthread_rwlock_wrlock(&ctx->dataout_fifo_queue_lock);
	if (ctx->dataout_fifo_queue_read_index != ctx->dataout_fifo_queue_write_index)
	{
		data_block = ctx->dataout_fifo_queue[ctx->dataout_fifo_queue_read_index];
		//Now we are inside the lock, so the counter is now guarenteed to remain the same
		num = ctx->dataout_fifo_queue_counter;
		ctx->dataout_fifo_queue_read_index = (ctx->dataout_fifo_queue_read_index + 1) % RIST_DATAOUT_QUEUE_BUFFERS;
		if (data_block)
		{
			//msg(0, 0, RIST_LOG_INFO, "[INFO]data queue level %u -> %zu bytes, index %u!\n", ctx->dataout_fifo_queue_counter,
			//		ctx->dataout_fifo_queue_bytesize, ctx->dataout_fifo_queue_read_index);
			ctx->dataout_fifo_queue_counter--;
			ctx->dataout_fifo_queue_bytesize -= data_block->payload_len;
		}
	}
	pthread_rwlock_unlock(&ctx->dataout_fifo_queue_lock);

	if (RIST_UNLIKELY(data_block == NULL && num > 0))
	{
		//I think this should never happen, should we consider this an error (-1 return code)?
		num = 0;
	}

	*data_buffer = data_block;

	return num;
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
		if (p->local_port % 2 != 0)
		{
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create peer, port must be even!\n");
			udpsocket_close(p->sd);
			free(p);
			return -1;
		}

		sprintf((char *)config->address, "%s:%d", p->url, p->local_port + 1);
		p_rtcp = rist_receiver_peer_insert_local(ctx, config);
		if (!p_rtcp)
		{
			udpsocket_close(p->sd);
			free(p);
			return -1;
		}
		p_rtcp->is_rtcp = true;
		msg(ctx->id, 0, RIST_LOG_INFO, "[INFO] Created RTCP peer: host %s, port %d, new_url %s, %" PRIu32 "\n", p_rtcp->url, p_rtcp->local_port, config->address, p_rtcp->adv_peer_id);
		peer_append(p_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(p_rtcp);
	}
	else
	{
		p->is_rtcp = true;
	}

	p->is_data = true;
	peer_append(p);
	/* jumpstart communication */
	rist_fsm_init_comm(p);

	*peer = p;

	return 0;
}

int rist_sender_data_write(struct rist_sender *ctx, const struct rist_data_block *data_block)
{
	// max protocol overhead for data is gre-header plus gre-reduced-mode-header plus rtp-header
	// 16 + 4 + 12 = 32

	if (data_block->payload_len <= 0 || data_block->payload_len > (RIST_MAX_PACKET_SIZE - 32))
	{
		msg(0, ctx->id, RIST_LOG_ERROR,
			"Dropping pipe packet of size %d, max is %d.\n", data_block->payload_len, RIST_MAX_PACKET_SIZE - 32);
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
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null on rist_sender_oob_read call!\n");
		return -1;
	}
	msg(0, 0, RIST_LOG_ERROR, "[ERROR] rist_sender_oob_read not implemented!\n");
	return 0;
}

int rist_sender_oob_write(struct rist_sender *ctx, const struct rist_oob_block *oob_block)
{
	// max protocol overhead for data is gre-header, 16 max
	if (oob_block->payload_len <= 0 || oob_block->payload_len > (RIST_MAX_PACKET_SIZE - 16))
	{
		msg(0, ctx->id, RIST_LOG_ERROR,
			"Dropping oob packet of size %d, max is %d.\n", oob_block->payload_len, RIST_MAX_PACKET_SIZE - 16);
		return -1;
	}
	return rist_oob_enqueue(&ctx->common, oob_block->peer, oob_block->payload, oob_block->payload_len);
}

int rist_receiver_oob_write(struct rist_receiver *ctx, const struct rist_oob_block *oob_block)
{
	// max protocol overhead for data is gre-header, 16 max
	if (oob_block->payload_len <= 0 || oob_block->payload_len > (RIST_MAX_PACKET_SIZE - 16))
	{
		msg(ctx->id, 0, RIST_LOG_ERROR,
			"Dropping oob packet of size %d, max is %d.\n", oob_block->payload_len, RIST_MAX_PACKET_SIZE - 16);
		return -1;
	}
	return rist_oob_enqueue(&ctx->common, oob_block->peer, oob_block->payload, oob_block->payload_len);
}

int rist_receiver_create(struct rist_receiver **_ctx, enum rist_profile profile,
						 enum rist_log_level log_level)
{
	struct rist_receiver *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Could not create ctx object, OOM!\n");
		return -1;
	}

	ctx->id = (intptr_t)ctx;
	if (init_common_ctx(ctx, NULL, &ctx->common, profile))
		goto fail;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] RIST Receiver Library v%d.%d.%d\n",
		RIST_PROTOCOL_VERSION, RIST_API_VERSION, RIST_SUBVERSION);

	set_loglevel(log_level);
	if (log_level >= RIST_LOG_DEBUG)
		ctx->common.debug = true;

	msg(ctx->id, 0, RIST_LOG_INFO, "[INIT] Starting in receiver mode\n");

	int ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret)
	{
		msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Error %d calling pthread_cond_init\n", ret);
		goto fail;
	}
	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret)
	{
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
	//Make sure LSB = 0
	flow_id &= ~1UL;
	ctx->adv_flow_id = flow_id;
	for (size_t i = 0; i < ctx->peer_lst_len; i++)
	{
		ctx->peer_lst[i]->adv_flow_id = flow_id;
	}
	return 0;
}

int rist_sender_create(struct rist_sender **_ctx, enum rist_profile profile,
					   uint32_t flow_id, enum rist_log_level log_level)
{
	int ret;

	if (flow_id % 2 != 0)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Flow ID must be an even number!\n");
		return -1;
	}

	struct rist_sender *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Could not create ctx object, OOM!\n");
		return -1;
	}

	ctx->id = (intptr_t)ctx;
	if (init_common_ctx(NULL, ctx, &ctx->common, profile))
	{
		free(ctx);
		ctx = NULL;
		return -1;
	}
	ctx->common.stats_report_time = (uint64_t)1000 * (uint64_t)RIST_CLOCK;
	//ctx->common.seq = 9159579;
	//ctx->common.seq = RIST_SERVER_QUEUE_BUFFERS - 25000;

	if (!ctx->sender_retry_queue)
	{
		ctx->sender_retry_queue = calloc(RIST_RETRY_QUEUE_BUFFERS, sizeof(*ctx->sender_retry_queue));
		if (RIST_UNLIKELY(!ctx->sender_retry_queue))
		{
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
	atomic_init(&ctx->sender_queue_delete_index, 0);
	atomic_init(&ctx->sender_queue_write_index, 0);

	msg(0, ctx->id, RIST_LOG_INFO, "[INIT] RIST Sender Library v%d.%d.%d\n",
		RIST_PROTOCOL_VERSION, RIST_API_VERSION, RIST_SUBVERSION);

	set_loglevel(log_level);

	if (log_level == RIST_LOG_SIMULATE)
	{
		ctx->simulate_loss = true;
	}

	if (log_level >= RIST_LOG_DEBUG)
	{
		ctx->common.debug = true;
	}

	if (flow_id == 0)
	{
		char hostname[RIST_MAX_HOSTNAME];
		int ret_hostname = gethostname(hostname, RIST_MAX_HOSTNAME);
		if (ret_hostname == -1) {
			snprintf(hostname, RIST_MAX_HOSTNAME, "UnknownHost%d", rand());
		}
		flow_id = generate_flowid(timestampNTP_u64(), getpid(), hostname);
	}

	ctx->adv_flow_id = flow_id;

	ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret)
	{
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d initializing pthread_condition\n", ret);
		goto free_ctx_and_ret;
	}

	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret)
	{
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Error %d initializing pthread_mutex\n", ret);
		goto free_ctx_and_ret;
	}

	ctx->sender_initialized = true;

	if (pthread_create(&ctx->sender_thread, NULL, sender_pthread_protocol, (void *)ctx) != 0)
	{
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

int rist_sender_peer_destroy(struct rist_sender *ctx, struct rist_peer *peer)
{
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	}
	else if (!peer)
	{
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
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	}
	else if (!peer)
	{
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Missing peer pointer\n");
		return -1;
	}

	peer->dead = true;
	rist_peer_remove(&ctx->common, peer);
	msg(ctx->id, 0, RIST_LOG_WARN, "[WARNING] rist_receiver_peer_remove not fully implemented!\n");
	return 0;
}

int rist_sender_auth_handler_set(struct rist_sender *ctx,
								 int (*conn_cb)(void *arg, const char *connecting_ip, uint16_t connecting_port, const char *local_ip, uint16_t local_port, struct rist_peer *peer),
								 int (*disconn_cb)(void *arg, struct rist_peer *peer),
								 void *arg)
{
	return rist_auth_handler(&ctx->common, conn_cb, disconn_cb, arg);
}

int rist_sender_start(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized)
	{
		return -1;
	}

	if (ctx->total_weight > 0)
	{
		ctx->weight_counter = ctx->total_weight;
		msg(0, ctx->id, RIST_LOG_INFO, "[INIT] Total weight: %lu\n", ctx->total_weight);
	}

	ctx->common.startup_complete = true;
	return 0;
}

int rist_sender_pause(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized)
	{
		return -1;
	}

	ctx->common.startup_complete = false;
	return 0;
}

int rist_sender_unpause(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized)
	{
		return -1;
	}

	ctx->common.startup_complete = true;
	return 0;
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
		if (!peer_rtcp->listening)
		{
			sender_peer_append(ctx, peer_rtcp);
			rist_fsm_recv_connect(peer_rtcp);
		}
	}
	else
	{
		newpeer->peer_data = newpeer;
		newpeer->is_rtcp = true;
		newpeer->compression = config->compression;
	}

	/* jumpstart communication */
	rist_fsm_init_comm(newpeer);
	/* Authenticate right away */
	if (!newpeer->listening)
	{
		sender_peer_append(ctx, newpeer);
		rist_fsm_recv_connect(newpeer);
	}

	*peer = newpeer;

	return 0;
}

int rist_receiver_auth_handler_set(struct rist_receiver *ctx,
								   int (*conn_cb)(void *arg, const char *connecting_ip, uint16_t connecting_port, const char *local_ip, uint16_t local_port, struct rist_peer *peer),
								   int (*disconn_cb)(void *arg, struct rist_peer *peer),
								   void *arg)
{
	return rist_auth_handler(&ctx->common, conn_cb, disconn_cb, arg);
}

int rist_sender_oob_callback_set(struct rist_sender *ctx,
								 int (*oob_callback)(void *arg, const struct rist_oob_block *oob_block),
								 void *arg)
{
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	}
	else if (ctx->common.profile == RIST_PROFILE_SIMPLE)
	{
		msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Out-of-band data is not support for simple profile\n");
		return -1;
	}
	if (pthread_rwlock_init(&ctx->common.oob_queue_lock, NULL) != 0)
	{
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
	if (!ctx)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] ctx is null!\n");
		return -1;
	}
	else if (ctx->common.profile == RIST_PROFILE_SIMPLE)
	{
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
	if (pthread_rwlock_init(&ctx->dataout_fifo_queue_lock, NULL) != 0)
	{
		msg(0, 0, RIST_LOG_ERROR, "[ERROR] Failed to init dataout_fifo_queue_lock\n");
		return -1;
	}

	if (!ctx->receiver_thread)
	{
		if (pthread_create(&ctx->receiver_thread, NULL, receiver_pthread_protocol, (void *)ctx) != 0)
		{
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Could not create receiver protocol thread.\n");
			return -1;
		}
	}

	return 0;
}

int rist_sender_destroy(struct rist_sender *ctx)
{
	if (!ctx)
	{
		return -1;
	}

	msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Triggering protocol loop termination\n");
	ctx->common.shutdown = 1;
	uint64_t start_time = timestampNTP_u64();
	while (ctx->sender_thread && ctx->common.shutdown != 2)
	{
		msg(0, ctx->id, RIST_LOG_INFO, "[CLEANUP] Waiting for protocol loop to exit\n");
		usleep(5000);
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 10000)
		{
			msg(0, ctx->id, RIST_LOG_ERROR, "[ERROR] Protocol loop took more than 10 seconds to exit. Something is wrong!\n");
			assert(0);
		}
	}
	pthread_join(ctx->sender_thread, NULL);
	rist_sender_destroy_local(ctx);

	return 0;
}

int rist_receiver_destroy(struct rist_receiver *ctx)
{
	if (!ctx)
	{
		return -1;
	}

	msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Triggering protocol loop termination\n");
	ctx->common.shutdown = 1;
	uint64_t start_time = timestampNTP_u64();
	while (ctx->receiver_thread && ctx->common.shutdown != 2)
	{
		msg(ctx->id, 0, RIST_LOG_INFO, "[CLEANUP] Waiting for protocol loop to exit\n");
		usleep(5000);
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 10000)
		{
			msg(ctx->id, 0, RIST_LOG_ERROR, "[ERROR] Protocol loop took more than 10 seconds to exit. Something is wrong!\n");
			assert(0);
		}
	}
	pthread_join(ctx->receiver_thread, NULL);
	rist_receiver_destroy_local(ctx);

	return 0;
}

int rist_sender_stats_callback_set(struct rist_sender *ctx, int statsinterval, int (*stats_cb)(void *arg, struct rist_stats *stats), void *arg)
{
	if (stats_cb == NULL)
	{
		return -1;
	}
	ctx->common.stats_callback = stats_cb;
	ctx->common.stats_callback_argument = arg;
	if (statsinterval != 0)
	{
		ctx->common.stats_report_time = statsinterval * RIST_CLOCK;
	}
	return 0;
}
int rist_receiver_stats_callback_set(struct rist_receiver *ctx, int statsinterval, int (*stats_cb)(void *arg, struct rist_stats *stats), void *arg)
{
	if (stats_cb == NULL)
	{
		return -1;
	}
	ctx->common.stats_callback = stats_cb;
	ctx->common.stats_callback_argument = arg;
	if (statsinterval != 0)
	{
		ctx->common.stats_report_time = statsinterval * RIST_CLOCK;
		struct rist_flow *f = ctx->common.FLOWS;
		while (f)
		{
			f->stats_report_time = statsinterval * RIST_CLOCK;
			f = f->next;
		}
	}
	return 0;
}
