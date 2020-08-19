#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"
#include "vcs_version.h"
#include <assert.h>
#ifdef _WIN32
#include <processthreadsapi.h>
#endif

extern uint32_t generate_flowid(uint64_t birthtime, uint32_t pid, const char *phrase);

/* Receiver functions */

int rist_receiver_create(struct rist_ctx **_ctx, enum rist_profile profile,
						 struct rist_logging_settings *logging_settings)
{
	if (!logging_settings)
		logging_settings = rist_get_global_logging_settings();
	struct rist_ctx *rist_ctx = calloc(1, sizeof(*rist_ctx));
	if (!rist_ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		return -1;
	}
	if (profile == RIST_PROFILE_ADVANCED)
	{
		rist_log_priv2(logging_settings, RIST_LOG_WARN, "Advanced profile not implemented yet, using main profile instead\n");
		profile = RIST_PROFILE_MAIN;
	}
	struct rist_receiver *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		free(rist_ctx);
		return -1;
	}
	rist_ctx->mode = RIST_RECEIVER_MODE;
	rist_ctx->receiver_ctx = ctx;
	ctx->id = (intptr_t)ctx;
	if (init_common_ctx(&ctx->common, profile))
		goto fail;

	ctx->common.logging_settings = logging_settings;
	ctx->common.stats_report_time = (uint64_t)1000 * (uint64_t)RIST_CLOCK;

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "RIST Receiver Library version:%s \n", LIBRIST_VERSION);

	ctx->common.receiver_id = ctx->id;
	ctx->common.sender_id = 0;

	if (logging_settings && logging_settings->log_level >= RIST_LOG_DEBUG)
		ctx->common.debug = true;

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting in receiver mode\n");

	int ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_cond_init\n", ret);
		goto fail;
	}
	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret)
	{
		pthread_cond_destroy(&ctx->condition);
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_mutex_init\n", ret);
		goto fail;
	}

	*_ctx = rist_ctx;

	atomic_init(&ctx->dataout_fifo_queue_counter, 0);
	atomic_init(&ctx->dataout_fifo_queue_write_index, 0);
	atomic_init(&ctx->dataout_fifo_queue_read_index, 0);
	return 0;

fail:
	free(ctx);
	free(rist_ctx);
	ctx = NULL;
	return -1;
}

int rist_receiver_nack_type_set(struct rist_ctx *rist_ctx, enum rist_nack_type nack_type)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_nack_type_set call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_nack_type_set call with CTX not set up for receiving\n");
		return -1;
	}
	struct rist_receiver *ctx = rist_ctx->receiver_ctx;
	ctx->nack_type = nack_type;
	return 0;
}

int rist_receiver_data_read(struct rist_ctx *rist_ctx, const struct rist_data_block **data_buffer, int timeout)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_data_read call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_data_read call with CTX not set up for receiving\n");
		return -1;
	}

	struct rist_receiver *ctx = rist_ctx->receiver_ctx;

	const struct rist_data_block *data_block = NULL;
	/* We could enter the lock now, to read the counter. However performance penalties apply.
	   The risks for not entering the lock are either sleeping too much (a packet gets added while we read)
	   or not at all when we should (i.e.: the calling application is reading from multiple threads). Both
	   risks are tolerable */
	ssize_t num = atomic_load_explicit(&ctx->dataout_fifo_queue_counter, memory_order_acquire);
	if (!num && timeout > 0)
	{
		pthread_mutex_lock(&(ctx->mutex));
		pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), timeout);
		pthread_mutex_unlock(&(ctx->mutex));
	}

	size_t dataout_read_index = atomic_load_explicit(&ctx->dataout_fifo_queue_read_index, memory_order_relaxed);
	if ((size_t)atomic_load_explicit(&ctx->dataout_fifo_queue_write_index, memory_order_acquire) != dataout_read_index)
	{
		data_block = ctx->dataout_fifo_queue[dataout_read_index];
		num = atomic_load_explicit(&ctx->dataout_fifo_queue_counter, memory_order_acquire);
		atomic_store_explicit(&ctx->dataout_fifo_queue_read_index, (dataout_read_index + 1) & (RIST_DATAOUT_QUEUE_BUFFERS - 1), memory_order_release);
		if (data_block)
		{
			//rist_log_priv(&ctx->common, RIST_LOG_INFO, "[INFO]data queue level %u -> %zu bytes, index %u!\n", ctx->dataout_fifo_queue_counter,
			//		ctx->dataout_fifo_queue_bytesize, ctx->dataout_fifo_queue_read_index);
			ctx->dataout_fifo_queue_bytesize -= data_block->payload_len;
			atomic_fetch_sub_explicit(&ctx->dataout_fifo_queue_counter, 1, memory_order_release);
		}
	}

	if (RIST_UNLIKELY(data_block == NULL && num > 0))
	{
		//I think this should never happen, should we consider this an error (-1 return code)?
		num = 0;
	}

	*data_buffer = data_block;

	return (int)num;
}

int rist_receiver_data_callback_set(struct rist_ctx *rist_ctx,
									int (*data_callback)(void *arg, const struct rist_data_block *data_block),
									void *arg)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_data_callback_set call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_data_callback_set call with CTX not set up for receiving\n");
		return -1;
	}
	struct rist_receiver *ctx = rist_ctx->receiver_ctx;
	ctx->receiver_data_callback = data_callback;
	ctx->receiver_data_callback_argument = arg;
	return 0;
}

/* Sender functions */
int rist_sender_create(struct rist_ctx **_ctx, enum rist_profile profile,
					   uint32_t flow_id, struct rist_logging_settings *logging_settings)
{
	if (!logging_settings)
		logging_settings = rist_get_global_logging_settings();
	int ret;

	if (profile == RIST_PROFILE_ADVANCED)
	{
		rist_log_priv2(logging_settings, RIST_LOG_WARN, "Advanced profile not implemented yet, using main profile instead\n");
		profile = RIST_PROFILE_MAIN;
	}

	if (flow_id % 2 != 0)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Flow ID must be an even number!\n");
		return -1;
	}

	struct rist_ctx *rist_ctx = calloc(1, sizeof(*rist_ctx));
	if (!rist_ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		return -1;
	}
	struct rist_sender *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		free(rist_ctx);
		return -1;
	}
	rist_ctx->mode = RIST_SENDER_MODE;
	rist_ctx->sender_ctx = ctx;

	ctx->id = (intptr_t)ctx;
	if (init_common_ctx(&ctx->common, profile))
	{
		free(ctx);
		ctx = NULL;
		return -1;
	}

	ctx->common.logging_settings = logging_settings;
	ctx->common.stats_report_time = (uint64_t)1000 * (uint64_t)RIST_CLOCK;
	//ctx->common.seq = 9159579;
	//ctx->common.seq = RIST_SERVER_QUEUE_BUFFERS - 25000;

	if (!ctx->sender_retry_queue)
	{
		ctx->sender_retry_queue = calloc(RIST_RETRY_QUEUE_BUFFERS, sizeof(*ctx->sender_retry_queue));
		if (RIST_UNLIKELY(!ctx->sender_retry_queue))
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create sender retry buffer of size %u MB, OOM\n",
						  (unsigned)(RIST_SERVER_QUEUE_BUFFERS * sizeof(ctx->sender_retry_queue[0])) / 1000000);
			ret = -1;
			goto free_ctx_and_ret;
		}

		ctx->sender_retry_queue_write_index = 1;
		ctx->sender_retry_queue_read_index = 0;
		ctx->sender_retry_queue_size = RIST_RETRY_QUEUE_BUFFERS;
	}

	ctx->sender_queue_delete_index = 1;
	ctx->sender_queue_max = RIST_SERVER_QUEUE_BUFFERS;
	atomic_init(&ctx->sender_queue_write_index, 1);
	atomic_init(&ctx->sender_queue_read_index, 0);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "RIST Sender Library %s\n", LIBRIST_VERSION);

	ctx->common.sender_id = ctx->id;
	ctx->common.receiver_id = 0;

	if (logging_settings && logging_settings->log_level == RIST_LOG_SIMULATE)
	{
		ctx->simulate_loss = true;
		rist_log_priv(&ctx->common, RIST_LOG_WARN, "RIST Sender has been configured with self-imposed packet loss (1 in 1000)\n");
	}

	if (logging_settings && logging_settings->log_level >= RIST_LOG_DEBUG)
	{
		ctx->common.debug = true;
	}

	if (flow_id == 0)
	{
		char hostname[RIST_MAX_HOSTNAME];
		int ret_hostname = gethostname(hostname, RIST_MAX_HOSTNAME);
		if (ret_hostname == -1)
		{
			snprintf(hostname, RIST_MAX_HOSTNAME, "UnknownHost%d", rand());
		}
#ifndef _WIN32
		flow_id = generate_flowid(timestampNTP_u64(), getpid(), hostname);
#else
		flow_id = generate_flowid(timestampNTP_u64(), GetCurrentProcessId(), hostname);
#endif
	}

	ctx->adv_flow_id = flow_id;

	ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d initializing pthread_condition\n", ret);
		goto free_ctx_and_ret;
	}

	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d initializing pthread_mutex\n", ret);
		goto free_ctx_and_ret;
	}

	ret = pthread_mutex_init(&ctx->queue_lock, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d initializing pthread_mutex\n", ret);
		goto free_ctx_and_ret;
	}

	ctx->sender_initialized = true;

	if (pthread_create(&ctx->sender_thread, NULL, sender_pthread_protocol, (void *)ctx) != 0)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not created sender thread.\n");
		ret = -3;
		goto free_ctx_and_ret;
	}

	*_ctx = rist_ctx;
	return 0;

	// Failed!
free_ctx_and_ret:
	free(ctx);
	free(rist_ctx);
	return ret;
}

int rist_sender_flow_id_get(struct rist_ctx *rist_ctx, uint32_t *flow_id)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_get call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_get call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	*flow_id = ctx->adv_flow_id;
	return 0;
}

int rist_sender_flow_id_set(struct rist_ctx *rist_ctx, uint32_t flow_id)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_set call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_set call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	//Make sure LSB = 0
	flow_id &= ~1UL;
	ctx->adv_flow_id = flow_id;
	for (size_t i = 0; i < ctx->peer_lst_len; i++)
	{
		ctx->peer_lst[i]->adv_flow_id = flow_id;
	}
	return 0;
}

int rist_sender_data_write(struct rist_ctx *rist_ctx, const struct rist_data_block *data_block)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_data_write call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_data_write call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	// max protocol overhead for data is gre-header plus gre-reduced-mode-header plus rtp-header
	// 16 + 4 + 12 = 32

	if (data_block->payload_len <= 0 || data_block->payload_len > (RIST_MAX_PACKET_SIZE - 32))
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
					  "Dropping pipe packet of size %d, max is %d.\n", data_block->payload_len, RIST_MAX_PACKET_SIZE - 32);
		return -1;
	}

	uint64_t ts_ntp = data_block->ts_ntp == 0 ? timestampNTP_u64() : data_block->ts_ntp;
	uint32_t seq_rtp;
	if (data_block->flags & RIST_DATA_FLAGS_USE_SEQ)
		seq_rtp = (uint32_t)data_block->seq;
	else
		seq_rtp = ctx->common.seq_rtp++;
	//When we support 32bit seq this should be changed
	seq_rtp = seq_rtp & (UINT16_MAX);

	int ret = rist_sender_enqueue(ctx, data_block->payload, data_block->payload_len, ts_ntp, data_block->virt_src_port, data_block->virt_dst_port, seq_rtp);
	// Wake up data/nack output thread when data comes in
	if (pthread_cond_signal(&ctx->condition))
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");

	return ret;
}

/* Shared OOB functions -> Tunneled IP packets within GRE */
int rist_oob_read(struct rist_ctx *ctx, const struct rist_oob_block **oob_block)
{
	RIST_MARK_UNUSED(oob_block);
	if (!ctx)
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_oob_read call!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;

	rist_log_priv(cctx, RIST_LOG_ERROR, "rist_receiver_oob_read not implemented!\n");
	return 0;
}

int rist_oob_write(struct rist_ctx *ctx, const struct rist_oob_block *oob_block)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_oob_write call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	// max protocol overhead for data is gre-header, 16 max
	if (oob_block->payload_len <= 0 || oob_block->payload_len > (RIST_MAX_PACKET_SIZE - 16))
	{
		rist_log_priv(cctx, RIST_LOG_ERROR,
					  "Dropping oob packet of size %d, max is %d.\n", oob_block->payload_len, RIST_MAX_PACKET_SIZE - 16);
		return -1;
	}
	return rist_oob_enqueue(cctx, oob_block->peer, oob_block->payload, oob_block->payload_len);
}

int rist_oob_callback_set(struct rist_ctx *ctx,
						  int (*oob_callback)(void *arg, const struct rist_oob_block *oob_block),
						  void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_oob_callback_set call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	else if (cctx->profile == RIST_PROFILE_SIMPLE)
	{
		rist_log_priv(cctx, RIST_LOG_ERROR, "Out-of-band data is not support for simple profile\n");
		return -1;
	}
	if (pthread_rwlock_init(&cctx->oob_queue_lock, NULL) != 0)
	{
		rist_log_priv(cctx, RIST_LOG_ERROR, "Failed to init ctx->common.oob_queue_lock\n");
		return -1;
	}
	cctx->oob_data_enabled = true;
	cctx->oob_data_callback = oob_callback;
	cctx->oob_data_callback_argument = arg;
	cctx->oob_queue_write_index = 0;
	cctx->oob_queue_read_index = 0;

	return 0;
}

/* Shared functions */

int rist_jitter_max_set(struct rist_ctx *ctx, int t)
{
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;
	return rist_max_jitter_set(cctx, t);
}

int rist_auth_handler_set(struct rist_ctx *ctx,
						  int (*conn_cb)(void *arg, const char *connecting_ip, uint16_t connecting_port, const char *local_ip, uint16_t local_port, struct rist_peer *peer),
						  int (*disconn_cb)(void *arg, struct rist_peer *peer),
						  void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_auth_handler_set call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	return rist_auth_handler(cctx, conn_cb, disconn_cb, arg);
}

int rist_stats_free(const struct rist_stats *stats_container)
{
	if (!stats_container)
		return -1;
	if (stats_container->stats_json)
		free(stats_container->stats_json);
	free((void *)stats_container);
	return 0;
}

int rist_stats_callback_set(struct rist_ctx *ctx, int statsinterval, int (*stats_cb)(void *arg, const struct rist_stats *stats_container), void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_stats_callback_set call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;

	if (stats_cb == NULL)
	{
		return -1;
	}
	if (statsinterval != 0)
	{
		cctx->stats_callback = stats_cb;
		cctx->stats_callback_argument = arg;
		cctx->stats_report_time = statsinterval * RIST_CLOCK;
		if (ctx->mode == RIST_RECEIVER_MODE)
		{
			struct rist_flow *f = cctx->FLOWS;
			while (f)
			{
				f->stats_report_time = statsinterval * RIST_CLOCK;
				f = f->next;
			}
		}
	}

	return 0;
}

/* Utility functions */
const char *librist_version(void)
{
	return LIBRIST_VERSION;
}

int rist_parse_udp_address(const char *url, const struct rist_udp_config **udp_config)
{

	int ret = 0;
	if (*udp_config == NULL)
	{
		// Default options on new struct (specific for udp url)
		struct rist_udp_config *output_udp_config = calloc(1, sizeof(struct rist_udp_config));
		output_udp_config->version = RIST_UDP_CONFIG_VERSION;
		output_udp_config->stream_id = 0; // Accept all on receiver, auto-generate on sender
		ret = parse_url_udp_options(url, output_udp_config);
		*udp_config = output_udp_config;
	}
	else
	{
		// Update incoming object with url data
		struct rist_udp_config *existing_udp_config = (void *)*udp_config;
		ret = parse_url_udp_options(url, existing_udp_config);
		*udp_config = existing_udp_config;
	}

	return ret;
}

int rist_parse_address(const char *url, const struct rist_peer_config **peer_config)
{

	int ret = 0;
	if (*peer_config == NULL)
	{
		// Default options on new struct (rist url)
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
		output_peer_config->congestion_control_mode = RIST_DEFAULT_CONGESTION_CONTROL_MODE;
		output_peer_config->min_retries = RIST_DEFAULT_MIN_RETRIES;
		output_peer_config->max_retries = RIST_DEFAULT_MAX_RETRIES;
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


/* Shared functions with specific implementations, implementations first */
static int rist_receiver_peer_create(struct rist_receiver *ctx,
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
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create peer, port must be even!\n");
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
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Created RTCP peer: host %s, port %d, new_url %s, %" PRIu32 "\n", p_rtcp->url, p_rtcp->local_port, config->address, p_rtcp->adv_peer_id);

		p->peer_rtcp = p_rtcp;

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

static int rist_sender_peer_create(struct rist_sender *ctx,
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
		newpeer->peer_rtcp = peer_rtcp;
		peer_append(peer_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(peer_rtcp);
		/* Authenticate right away */
		if (!peer_rtcp->listening)
		{
			sender_peer_append(ctx, peer_rtcp);
			rist_peer_authenticate(peer_rtcp);
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
		rist_peer_authenticate(newpeer);
	}

	*peer = newpeer;

	return 0;
}

int rist_peer_create(struct rist_ctx *ctx, struct rist_peer **peer, const struct rist_peer_config *config) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_peer_create call with null ctx\n");
		return -1;
	}
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		return rist_receiver_peer_create(ctx->receiver_ctx, peer, config);
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		return rist_sender_peer_create(ctx->sender_ctx, peer, config);
	else
		return -1;
}

static int rist_sender_peer_destroy(struct rist_sender *ctx, struct rist_peer *peer)
{
	if (!ctx)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "ctx is null!\n");
		return -1;
	}
	else if (!peer)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Missing peer pointer\n");
		return -1;
	}

	peer->dead = true;
	rist_peer_remove(&ctx->common, peer);
	rist_log_priv(&ctx->common, RIST_LOG_WARN, "rist_sender_peer_remove not fully implemented!\n");
	return 0;
}

static int rist_receiver_peer_destroy(struct rist_receiver *ctx, struct rist_peer *peer)
{
	if (!ctx)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "ctx is null!\n");
		return -1;
	}
	else if (!peer)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Missing peer pointer\n");
		return -1;
	}

	peer->dead = true;
	rist_peer_remove(&ctx->common, peer);
	rist_log_priv(&ctx->common, RIST_LOG_WARN, "rist_receiver_peer_remove not fully implemented!\n");
	return 0;
}

int rist_peer_destroy(struct rist_ctx *ctx, struct rist_peer *peer) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_peer_destroy call with null ctx\n");
		return -1;
	}
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		return rist_receiver_peer_destroy(ctx->receiver_ctx, peer);
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		return rist_sender_peer_destroy(ctx->sender_ctx, peer);
	else
		return -1;
}

static int rist_sender_start(struct rist_sender *ctx)
{
	if (!ctx->sender_initialized)
	{
		return -1;
	}

	if (ctx->total_weight > 0)
	{
		ctx->weight_counter = ctx->total_weight;
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Total weight: %lu\n", ctx->total_weight);
	}

	ctx->common.startup_complete = true;
	return 0;
}

static int rist_receiver_start(struct rist_receiver *ctx)
{
	if (!ctx->receiver_thread)
	{
		if (pthread_create(&ctx->receiver_thread, NULL, receiver_pthread_protocol, (void *)ctx) != 0)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create receiver protocol thread.\n");
			return -1;
		}
	}

	return 0;
}

int rist_start(struct rist_ctx *ctx) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_start call with null ctx\n");
		return -1;
	}
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		return rist_receiver_start(ctx->receiver_ctx);
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		return rist_sender_start(ctx->sender_ctx);
	else
		return -1;
}

static int rist_sender_destroy(struct rist_sender *ctx)
{
	if (!ctx)
	{
		return -1;
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Triggering protocol loop termination\n");
	ctx->common.shutdown = 1;
	uint64_t start_time = timestampNTP_u64();
	while (ctx->sender_thread && ctx->common.shutdown != 2)
	{
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Waiting for protocol loop to exit\n");
		usleep(5000);
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 10000)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Protocol loop took more than 10 seconds to exit. Something is wrong!\n");
			assert(0);
		}
	}
	pthread_join(ctx->sender_thread, NULL);
	rist_sender_destroy_local(ctx);

	return 0;
}

static int rist_receiver_destroy(struct rist_receiver *ctx)
{
	if (!ctx)
	{
		return -1;
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Triggering protocol loop termination\n");
	ctx->common.shutdown = 1;
	uint64_t start_time = timestampNTP_u64();
	while (ctx->receiver_thread && ctx->common.shutdown != 2)
	{
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Waiting for protocol loop to exit\n");
		usleep(5000);
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 10000)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Protocol loop took more than 10 seconds to exit. Something is wrong!\n");
			assert(0);
		}
	}
	pthread_join(ctx->receiver_thread, NULL);
	rist_receiver_destroy_local(ctx);

	return 0;
}

int rist_destroy(struct rist_ctx *ctx) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_destroy call with null ctx\n");
		return -1;
	}
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		rist_receiver_destroy(ctx->receiver_ctx);
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		rist_sender_destroy(ctx->sender_ctx);
	else
		return -1;
	free(ctx);
	return 0;
}

