#include "prometheus-exporter.h"

#include "common/attributes.h"
#include "time-shim.h"
#include "pthread-shim.h"
#include "socket-shim.h"
#include "config.h"
#include <errno.h>
#include <stdbool.h>
#if HAVE_SOCK_UN_H
#include <sys/un.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <librist/logging.h>
#include <librist/stats.h>

#if HAVE_LIBMICROHTTPD
#include <microhttpd.h>

#if !MICROHTTPD_HAS_RESULT_ENUM
#define MHD_OUT int
#else
#define MHD_OUT enum MHD_Result
#endif /* MICROHTTPD_HAS_RESULT_ENUM */

#if !MICROHTTPD_HAS_AUTO_INTERNAL_THREAD
#define MHD_START_FLAGS MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_POLL | MHD_USE_EPOLL
#else
#define MHD_START_FLAGS MHD_USE_AUTO_INTERNAL_THREAD
#endif /* MICROHTTPD_HAS_AUTO_INTERNAL_THREAD */

#endif

struct rist_prometheus_client_flow_stats {
	char *tags;
	uint64_t created;
	uint64_t last_updated;
	uint64_t receiver_id;

	struct {
		double rist_client_flow_sent_packets;
		double rist_client_flow_received_packets;
		double rist_client_flow_missing_packets;
		double rist_client_flow_reordered_packets;
		double rist_client_flow_recovered_packets;
		double rist_client_flow_recovered_one_retry_packets;
		double rist_client_flow_lost_packets;
	} counters;

	struct {
		uint64_t updated;
		double rist_client_flow_peers;
		double rist_client_flow_bandwidth_bps;
		double rist_client_flow_retry_bandwidth_bps;
		double rist_client_flow_sent_packets;
		double rist_client_flow_received_packets;
		double rist_client_flow_missing_packets;
		double rist_client_flow_reordered_packets;
		double rist_client_flow_recovered_packets;
		double rist_client_flow_recovered_one_retry_packets;
		double rist_client_flow_lost_packets;
		double rist_client_flow_min_iat_seconds;
		double rist_client_flow_cur_iat_seconds;
		double rist_client_flow_max_iat_seconds;
		double rist_client_flow_rtt_seconds;
		double rist_client_flow_quality;
	} container[16];

	int container_count;
	int container_offset;
	uint32_t flowid;
	char cname[RIST_MAX_STRING_LONG];
};

struct rist_prometheus_sender_peer_stats {
	uint32_t peer_id;
	char *tags;
	uint64_t created;
	uint64_t last_updated;
	uint64_t sender_id;

	struct {
		double rist_sender_peer_sent_packets;
		double rist_sender_peer_received_packets;
		double rist_sender_peer_retransmitted_packets;
	} counters;

	struct {
		uint64_t updated;
		double rist_sender_peer_bandwidth_bps;
		double rist_sender_peer_retry_bandwidth_bps;
		double rist_sender_peer_sent_packets;
		double rist_sender_peer_received_packets;
		double rist_sender_peer_retransmitted_packets;
		double rist_sender_peer_rtt_seconds;
		double rist_sender_peer_quality;
	} container[16];
	int container_count;
	int container_offset;

	char cname[RIST_MAX_STRING_SHORT];
	char *url;
	char *local_url;
	bool from_callback;
};


struct rist_prometheus_stats {
	uint64_t last_cleanup;
	pthread_mutex_t lock;
	int fd;
	pthread_t unix_socket_thread;
	bool started;
	bool single_stat_point;
	bool no_created;
	char *tags;
	char *format_buf;
	size_t format_buf_len;
	struct rist_prometheus_client_flow_stats **clients;
	size_t client_cnt;
	struct rist_prometheus_sender_peer_stats **sender_peers;
	size_t sender_peer_cnt;
#if HAVE_LIBMICROHTTPD
	struct MHD_Daemon *httpd;
#endif
};

uint64_t get_timestamp(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

#define str(s) #s
#define PROMETHEUS_METRIC(name, help, unit, type) \
"# HELP "str(name)" "help"\n" \
"# TYPE "str(name)" "type"\n" \
"# UNIT "str(name)" "unit"\n"

#define PROMETHEUS_GAUGE(name, help, unit) \
PROMETHEUS_METRIC(name, help, unit, "gauge")

#define PROMETHEUS_COUNTER(name, help, unit) \
PROMETHEUS_METRIC(name, help, unit, "counter")

//These translate to snprintf style format + arguments
#define PROMETHEUS_GAUGE_PRINT(name) str(name)"%s %.22lg", s->tags, s->container[i].name
#define PROMETHEUS_COUNTER_PRINT_TOTAL(name) str(name)"_total%s %.22lg", s->tags, s->container[i].name
#define PROMETHEUS_COUNTER_PRINT_CREATED(name) str(name)"_created%s %"PRIu64"\n", s->tags, s->created

#define MAX(a,b) (((a)>(b))?(a):(b))
#define PROMETHEUS_GAUGE_PRINT_R(name, help, unit, type, objs, cnt) \
offset += snprintf(out + offset * (out != NULL), remaining, PROMETHEUS_GAUGE(name, help, unit)); \
remaining = MAX((out_size - offset), 0); \
for (size_t c=0; c < ctx->cnt; c++) { \
	struct type *s = ctx->objs[c]; \
	if (s->container_count == 0) continue; \
	for (int i=0; i < s->container_count; i++) { \
		offset += snprintf(out + offset * (out != NULL), remaining, PROMETHEUS_GAUGE_PRINT(name)); \
		remaining = MAX((out_size - offset), 0);\
		if (ctx->single_stat_point) { \
			offset += snprintf(out + offset * (out != NULL), remaining, "\n"); \
		} else { \
			offset += snprintf(out + offset * (out != NULL), remaining, " %"PRIu64"\n", s->container[i].updated); \
		} \
		remaining = MAX((out_size - offset), 0); \
	} \
}


#define PROMETHEUS_COUNTER_PRINT_R(name, help, unit, type, objs, cnt) \
offset += snprintf(out + offset * (out != NULL), remaining, PROMETHEUS_COUNTER(name, help, unit)); \
remaining = MAX((out_size - offset), 0); \
for (size_t c=0; c < ctx->cnt; c++) { \
	struct type *s = ctx->objs[c]; \
	if (s->container_count == 0) continue; \
	for (int i=0; i < s->container_count; i++) { \
		offset += snprintf(out + offset * (out != NULL), remaining, PROMETHEUS_COUNTER_PRINT_TOTAL(name)); \
		remaining = MAX((out_size - offset), 0); \
		if (ctx->single_stat_point) { \
			offset += snprintf(out + offset * (out != NULL), remaining, "\n"); \
		} else { \
			offset += snprintf(out + offset * (out != NULL), remaining, "%"PRIu64"\n", s->container[i].updated); \
		} \
		remaining = MAX((out_size - offset), 0); \
	} \
	if (ctx->no_created) { continue;} \
	offset += snprintf(out + offset * (out != NULL), remaining, PROMETHEUS_COUNTER_PRINT_CREATED(name)); \
	remaining = MAX((out_size - offset), 0); \
}

#define PROMETHEUS_GAUGE_PRINT_CLIENT(name, help, unit) PROMETHEUS_GAUGE_PRINT_R(name, help, unit, rist_prometheus_client_flow_stats, clients, client_cnt)
#define PROMETHEUS_COUNTER_PRINT_CLIENT(name, help, unit) PROMETHEUS_COUNTER_PRINT_R(name, help, unit, rist_prometheus_client_flow_stats, clients, client_cnt)

#define PROMETHEUS_GAUGE_PRINT_SENDER_PEER(name, help, unit) PROMETHEUS_GAUGE_PRINT_R(name, help, unit, rist_prometheus_sender_peer_stats, sender_peers, sender_peer_cnt)
#define PROMETHEUS_COUNTER_PRINT_SENDER_PEER(name, help, unit) PROMETHEUS_COUNTER_PRINT_R(name, help, unit, rist_prometheus_sender_peer_stats, sender_peers, sender_peer_cnt)


static int rist_prometheus_format_client_flow_stats(struct rist_prometheus_stats *ctx, char *out, int out_size) {
	if (ctx->client_cnt == 0)
		return 0;
	int offset = 0;
	int remaining =out_size;
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_peers, "The current number of connected peers", "peers")
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_bandwidth_bps, "The current bandwidth of the flow", "bps")
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_retry_bandwidth_bps, "The current retry bandwidth of the flow", "bps")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_sent_packets, "Total number of packets sent", "packets")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_received_packets, "Total number of packets received", "packets")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_missing_packets, "Total number of missing packets", "packets")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_reordered_packets, "Total number of reordered packets", "packets")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_recovered_packets, "Total number of recovered packets", "packets")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_recovered_one_retry_packets, "Total number of recovered after one retry packets", "packets")
	PROMETHEUS_COUNTER_PRINT_CLIENT(rist_client_flow_lost_packets, "Total number of lost packets", "packets")
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_min_iat_seconds, "Minimum inter arrival time in seconds", "seconds")
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_cur_iat_seconds, "Current inter arrival time in seconds", "seconds")
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_max_iat_seconds, "Maximum inter arrival time in seconds", "seconds")
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_rtt_seconds, "Current RTT in seconds", "seconds");
	PROMETHEUS_GAUGE_PRINT_CLIENT(rist_client_flow_quality, "Current connection quality percentage", "ratio");
	return offset;
}

static int rist_prometheus_format_sender_peer_stats(struct rist_prometheus_stats *ctx, char *out, int out_size) {
	if (ctx->sender_peer_cnt == 0)
		return 0;
	int offset = 0;
	int remaining =out_size;
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_bandwidth_bps, "The current bandwidth transmitted to the peer", "bps")
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_retry_bandwidth_bps, "The current retry bandwidth transmitted to the peer", "bps")
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_sent_packets, "Total number of packets sent", "packets")
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_retransmitted_packets, "Total number of packets retransmitted", "packets")
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_received_packets, "Total number of packets received (rtcp)", "packets")
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_rtt_seconds, "Current RTT in seconds", "seconds");
	PROMETHEUS_GAUGE_PRINT_SENDER_PEER(rist_sender_peer_quality, "Current connection quality percentage", "ratio");
	return offset;
}

void rist_prometheus_handle_client_stats(struct rist_prometheus_stats *ctx, const struct rist_stats_receiver_flow *stats, uint64_t now, uint64_t receiver_id) {
	struct rist_prometheus_client_flow_stats *s = NULL;
	for (size_t i=0; i < ctx->client_cnt; i++) {
		if (ctx->clients[i]->flowid == stats->flow_id && ctx->clients[i]->receiver_id == receiver_id) {
			s = ctx->clients[i];
			if (now <= s->last_updated) {
				return;
			}
			break;
		}
	}
	if (s == NULL) {
		if (ctx->clients == NULL) {
			ctx->clients = malloc(sizeof(*ctx->clients));
		} else {
			struct rist_prometheus_client_flow_stats **tmp = realloc(ctx->clients, sizeof(*ctx->clients) * (ctx->client_cnt+1));
			if (tmp == NULL) {
				fprintf(stderr, "failed to realloc aborting\n");
				abort();
			}
			ctx->clients = tmp;
		}
		ctx->clients[ctx->client_cnt] = calloc(1, sizeof(*ctx->clients[ctx->client_cnt]));
		int res = snprintf(NULL, 0, "{%sflow_id=\"%"PRIu32"\",receiver_id=\"%"PRIu64"\"}",ctx->tags, stats->flow_id, receiver_id);
		if (res < 0) {
			return;
		}
		size_t len = res+1;
		ctx->clients[ctx->client_cnt]->tags = calloc(1, len);
		ctx->clients[ctx->client_cnt]->created = now;
		ctx->clients[ctx->client_cnt]->flowid = stats->flow_id;
		ctx->clients[ctx->client_cnt]->receiver_id = receiver_id;
		res = snprintf(ctx->clients[ctx->client_cnt]->tags, len, "{%sflow_id=\"%"PRIu32"\",receiver_id=\"%"PRIu64"\"}",ctx->tags, stats->flow_id, receiver_id);
		assert(res >= 0);
		s = ctx->clients[ctx->client_cnt];
		ctx->client_cnt++;
	}
	s->container[s->container_offset].rist_client_flow_peers = stats->peer_count;
	s->container[s->container_offset].rist_client_flow_bandwidth_bps = stats->bandwidth;
	s->container[s->container_offset].rist_client_flow_retry_bandwidth_bps = stats->retry_bandwidth;
	s->container[s->container_offset].rist_client_flow_sent_packets = s->counters.rist_client_flow_sent_packets += stats->sent;
	s->container[s->container_offset].rist_client_flow_received_packets = s->counters.rist_client_flow_received_packets += stats->received;
	s->container[s->container_offset].rist_client_flow_missing_packets = s->counters.rist_client_flow_missing_packets += stats->missing;
	s->container[s->container_offset].rist_client_flow_reordered_packets = s->counters.rist_client_flow_reordered_packets += stats->reordered;
	s->container[s->container_offset].rist_client_flow_recovered_packets = s->counters.rist_client_flow_recovered_packets += stats->recovered;
	s->container[s->container_offset].rist_client_flow_recovered_one_retry_packets = s->counters.rist_client_flow_recovered_one_retry_packets += stats->recovered_one_retry;
	s->container[s->container_offset].rist_client_flow_lost_packets = s->counters.rist_client_flow_lost_packets += stats->lost;
	s->container[s->container_offset].rist_client_flow_min_iat_seconds = ((double)1 / (double)1000000) * stats->min_inter_packet_spacing;
	s->container[s->container_offset].rist_client_flow_cur_iat_seconds = ((double)1 / (double)1000000) * stats->cur_inter_packet_spacing;
	s->container[s->container_offset].rist_client_flow_max_iat_seconds = ((double)1 / (double)1000000) * stats->max_inter_packet_spacing;
	s->container[s->container_offset].rist_client_flow_rtt_seconds = ((double)1 / (double)1000) * stats->rtt;
	s->container[s->container_offset].rist_client_flow_quality = stats->quality;
	s->container[s->container_offset].updated = now;
	s->last_updated = now;
	if (!ctx->single_stat_point) {
		s->container_offset = (s->container_offset+1) %16;
		if (s->container_count < 16) {
			s->container_count++;
		}
	} else {
		s->container_offset = 1;
		s->container_count = 1;
	}
}

void rist_prometheus_handle_sender_peer_stats(struct rist_prometheus_stats *ctx, const struct rist_stats_sender_peer *stats, uint64_t now, uint64_t sender_id) {
	struct rist_prometheus_sender_peer_stats *s = NULL;
	for (size_t i = 0; i < ctx->sender_peer_cnt; i++) {
		if (ctx->sender_peers[i]->peer_id == stats->peer_id && ctx->sender_peers[i]->sender_id == sender_id) {
			s = ctx->sender_peers[i];
			break;
		}
	}
	if (s == NULL)
		return;

	if (s->tags == NULL) {
		memcpy(s->cname, stats->cname, sizeof(s->cname)-1);
		if (s->local_url == NULL) {
			int res = snprintf(NULL, 0, "{%speer_id=\"%"PRIu32"\",peer_url=\"%s\",cname=\"%s\",sender_id=\"%"PRIu64"\"}",ctx->tags, s->peer_id, s->url, s->cname, sender_id);
			if (res < 0) {
				return;
			}
			size_t len = res+1;
			s->tags = calloc(1, len);
			res = snprintf(s->tags, len, "{%speer_id=\"%"PRIu32"\",peer_url=\"%s\",cname=\"%s\",sender_id=\"%"PRIu64"\"}",ctx->tags, s->peer_id, s->url, s->cname, sender_id);
			assert(res >=0);
		} else {
			int res = snprintf(NULL, 0, "{%speer_id=\"%"PRIu32"\",listening=\"%s\",peer_url=\"%s\",cname=\"%s\",sender_id=\"%"PRIu64"\"}",ctx->tags, s->peer_id,s->local_url, s->url, s->cname, sender_id);
			if (res < 0) {
				return;
			}
			size_t len = res+1;
			s->tags = calloc(1, len);
			res = snprintf(s->tags, len, "{%speer_id=\"%"PRIu32"\",listening=\"%s\",peer_url=\"%s\",cname=\"%s\",sender_id=\"%"PRIu64"\"}",ctx->tags, s->peer_id,s->local_url, s->url, s->cname, sender_id);
			assert(res >=0);
		}
	}
	s->container[s->container_offset].rist_sender_peer_sent_packets = s->counters.rist_sender_peer_sent_packets += stats->sent;
	s->container[s->container_offset].rist_sender_peer_received_packets = s->counters.rist_sender_peer_received_packets += stats->received;
	s->container[s->container_offset].rist_sender_peer_retransmitted_packets = s->counters.rist_sender_peer_retransmitted_packets += stats->retransmitted;
	s->container[s->container_offset].rist_sender_peer_bandwidth_bps = stats->bandwidth;
	s->container[s->container_offset].rist_sender_peer_retry_bandwidth_bps = stats->retry_bandwidth;
	s->container[s->container_offset].rist_sender_peer_rtt_seconds= ((double)1 / (double)1000) * stats->rtt;
	s->container[s->container_offset].rist_sender_peer_quality = stats->quality;
	s->container[s->container_offset].updated = now;
	s->last_updated = now;
	if (!ctx->single_stat_point) {
		s->container_offset = (s->container_offset+1) %16;
		if (s->container_count < 16) {
			s->container_count++;
		}
	} else {
		s->container_offset = 1;
		s->container_count = 1;
	}
}

void rist_prometheus_parse_stats(struct rist_prometheus_stats *ctx, const struct rist_stats *stats_container, uintptr_t id) {
	pthread_mutex_lock(&ctx->lock);
	uint64_t now = get_timestamp();
	if (stats_container->stats_type == RIST_STATS_RECEIVER_FLOW) {
		rist_prometheus_handle_client_stats(ctx, &stats_container->stats.receiver_flow, now, id);
	} else if (stats_container->stats_type == RIST_STATS_SENDER_PEER) {
		rist_prometheus_handle_sender_peer_stats(ctx, &stats_container->stats.sender_peer, now, id);
	}
	if (now > ctx->last_cleanup && (now - ctx->last_cleanup) >10) {
		{//clean expired receiver clients
			size_t clnt_cnt_start = ctx->client_cnt;
			for (size_t i = 0; i < ctx->client_cnt;) {
				if (ctx->clients[i]->last_updated < now && (now - ctx->clients[i]->last_updated) > 15) {
					free(ctx->clients[i]->tags);
					free(ctx->clients[i]);
					//We don't really care for the order, so just shuffle the last item forward
					ctx->clients[i] = ctx->clients[ctx->client_cnt-1];
					ctx->client_cnt--;
					continue;
				}
				i++;
			}
			if (clnt_cnt_start != ctx->client_cnt) {
				if (ctx->client_cnt == 0) {
					free(ctx->clients);
					ctx->clients = NULL;
				} else {
					struct rist_prometheus_client_flow_stats **tmp = realloc(ctx->clients, sizeof(*ctx->clients) * ctx->client_cnt);
					if (tmp == NULL) {
						fprintf(stderr, "realloc failed aborting\n");
						abort();
					}
					ctx->clients = tmp;
				}
			}
		}
		{//clean expired sender peers
			size_t sender_peer_cnt_start = ctx->sender_peer_cnt;
			for (size_t i =0; i < ctx->sender_peer_cnt;) {
				if (ctx->sender_peers[i]->from_callback && now > ctx->sender_peers[i]->last_updated && (now - ctx->sender_peers[i]->last_updated) > 15) {
					free(ctx->sender_peers[i]->url);
					free(ctx->sender_peers[i]->local_url);
					free(ctx->sender_peers[i]->tags);
					free(ctx->sender_peers[i]);

					ctx->sender_peers[i] = ctx->sender_peers[ctx->sender_peer_cnt -1];
					ctx->sender_peer_cnt--;
					continue;
				}
				i++;
			}
			if (sender_peer_cnt_start != ctx->sender_peer_cnt) {
				if (ctx->sender_peer_cnt == 0) {
					free(ctx->sender_peers);
					ctx->sender_peers = NULL;
				} else {
					struct rist_prometheus_sender_peer_stats **tmp = realloc(ctx->sender_peers, sizeof(*ctx->sender_peers) * ctx->sender_peer_cnt);
					if (tmp == NULL) {
						fprintf(stderr, "realloc failed aborting\n");
						abort();
					}
					ctx->sender_peers = tmp;
				}
			}
		}
		ctx->last_cleanup = now;
	}
	pthread_mutex_unlock(&ctx->lock);
}

static int rist_prometheus_stats_format(struct rist_prometheus_stats *ctx) {
	int req_size = rist_prometheus_format_client_flow_stats(ctx, NULL, 0);
	if (req_size < 0) {
		return 0;
	}
	req_size += rist_prometheus_format_sender_peer_stats(ctx, NULL, 0);

	if ((size_t)(req_size+1) > ctx->format_buf_len) {
		ctx->format_buf = realloc(ctx->format_buf, ((req_size + 1023) & -1024));
		ctx->format_buf_len = ((req_size + 1023) & -1024);
	}
	int size = rist_prometheus_format_client_flow_stats(ctx, ctx->format_buf, ctx->format_buf_len);

	size += rist_prometheus_format_sender_peer_stats(ctx, &ctx->format_buf[size], ctx->format_buf_len - size);
	for (size_t i=0; i < ctx->client_cnt; i++) {
		ctx->clients[i]->container_count = 0;
		ctx->clients[i]->container_offset = 0;
	}
	for (size_t i=0; i < ctx->sender_peer_cnt; i++) {
		ctx->sender_peers[i]->container_count = 0;
		ctx->sender_peers[i]->container_offset = 0;
	}
	return size;
}

#if HAVE_LIBMICROHTTPD
static MHD_OUT rist_prometheus_httpd_handler(void *cls, struct MHD_Connection *connection,
                             const char *url, const char *method, const char *version,
							 const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	RIST_MARK_UNUSED(version);
	RIST_MARK_UNUSED(upload_data);
	RIST_MARK_UNUSED(upload_data_size);
	RIST_MARK_UNUSED(con_cls);
	if (strcmp(method, "GET") != 0) {
		char *buf = "Invalid HTTP Method\n";
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response(response);
		return ret;
	}
	if (strcmp(url, "/") == 0) {
		char *buf = "OK\n";
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	}
	if (strcmp(url, "/metrics") == 0) {
		struct rist_prometheus_stats *ctx = cls;
		pthread_mutex_lock(&ctx->lock);
		int size = rist_prometheus_stats_format(ctx);
		struct MHD_Response *response = MHD_create_response_from_buffer(size, (void *)ctx->format_buf, MHD_RESPMEM_MUST_COPY);
		MHD_add_response_header(response, "Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8; produces=text/plain");
		int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		pthread_mutex_unlock(&ctx->lock);
		return ret;
	}
	char *buf = "Bad Request\n";
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
	int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
	MHD_destroy_response(response);
	return ret;
}
#endif

void rist_prometheus_stats_print(struct rist_prometheus_stats *ctx, FILE* out) {
	pthread_mutex_lock(&ctx->lock);
	rist_prometheus_stats_format(ctx);
	fprintf(out, "%s", ctx->format_buf);
	pthread_mutex_unlock(&ctx->lock);
}

void rist_prometheus_sender_add_peer(struct rist_prometheus_stats *ctx, uint64_t sender_id, uint32_t peer_id, const char *url, const char *local_url, bool from_callback) {
	pthread_mutex_lock(&ctx->lock);
	struct rist_prometheus_sender_peer_stats *p;
	if (ctx->sender_peer_cnt == 0) {
		ctx->sender_peers = malloc(sizeof(*ctx->sender_peers));
		p = ctx->sender_peers[0] = calloc(1, sizeof(*ctx->sender_peers[0]));
		ctx->sender_peer_cnt++;
	} else {
		struct rist_prometheus_sender_peer_stats **tmp = realloc(ctx->sender_peers, (ctx->sender_peer_cnt+1) * sizeof(*ctx->sender_peers));
		if (tmp == NULL) {
			fprintf(stderr, "realloc failed, aborting");
			abort();
		}
		ctx->sender_peers = tmp;
		p = ctx->sender_peers[ctx->sender_peer_cnt] = calloc(1, sizeof(*ctx->sender_peers[ctx->sender_peer_cnt]));
		ctx->sender_peer_cnt++;
	}

	p->peer_id = peer_id;
	p->sender_id = sender_id;
	p->last_updated = p->created = get_timestamp();
	p->url = strdup(url);
	if (local_url != NULL)
		p->local_url = strdup(local_url);
	p->from_callback = from_callback;
	pthread_mutex_unlock(&ctx->lock);
}

#if HAVE_SOCK_UN_H
void *rist_prometheus_stats_unix_socket_thread(void *arg) {
	struct rist_prometheus_stats * ctx = (struct rist_prometheus_stats *)arg;
	fprintf(stderr, "Starting unix socket thread\n");
	int ret = listen(ctx->fd, 1);
	if (ret != 0) {
		fprintf(stderr, "Error %s listening on unix socket\n", strerror(errno));
		return NULL;
	}
	while (true) {
		int fd = accept(ctx->fd, NULL, NULL);
		if (fd < 0) {
			break;
		}
		pthread_mutex_lock(&ctx->lock);
		int size = rist_prometheus_stats_format(ctx);
		(void)! write(fd, ctx->format_buf, size);
		pthread_mutex_unlock(&ctx->lock);
		shutdown(fd, SHUT_RDWR);
#ifndef _WIN32
		close(fd);
#else
		closesocket(fd);
#endif
	}
	fprintf(stderr, "Stopping unix socket thread\n");
	return NULL;
}
#endif


//Ensure the tags input by the user are in the correct format and end on a comma
//meaning: tag1="value",tag2="value",
static char *rist_prometheus_user_tags(const char *tags) {
	if (strchr(tags, '=') == NULL) {
		return NULL;//Doesn't contain an =, we cannot parse this
	}
	int len_s = strlen(tags);
	int len = len_s +2;//keep room for nullbyte & ending comma
	char *out = NULL;
	if (strchr(tags, '"') == NULL) {
		int count = 0;
		for (const char *t = tags; *t != '\0'; t++) {
			if (*t == '=')
				count++;
		}
		len += 2 *count;
		len_s += 2*count;
		out = calloc(len, 1);
		char *p = out;
		bool invar = false;
		for (const char *t = tags; *t != '\0'; t++) {
			if (*t == ',') {
				if (invar) {
					*p = '"';
					p++;
					invar = false;
				} else {
					free(out);
					return NULL;
				}
			}
			*p = *t;
			p++;
			if (*t == '=') {
				if (!invar) {
					*p = '"';
					p++;
					invar = true;
				} else {
					free(out);
					return NULL;
				}
			}
		}
		if (*(p-1) != ',') {
			*p = '"';
			len_s++;
		}
	} else {
		out = calloc(len, 1);
		memcpy(out, tags, len_s);
	}

	out[len_s -1] = ',';
	return out;
}

struct rist_prometheus_stats *rist_setup_prometheus_stats(struct rist_logging_settings *logging_settings, const char* tags, bool multiple_metric_datapoints, bool skipcreated, struct prometheus_httpd_options *httpd_opt, char *unix_socket) {
	int fd = -1;
#if HAVE_SOCK_UN_H
	if (unix_socket) {
		unlink(unix_socket);
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Prometheus: error %s opening unix socket: %s\n", strerror(errno), unix_socket);
			return NULL;
		}
		struct sockaddr_un su = {0};
		su.sun_family = AF_UNIX;
		strncpy(su.sun_path, unix_socket, sizeof(su.sun_path)-1);
		int ret = bind(fd, (struct sockaddr *)&su, sizeof(su));
		if (ret != 0) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Prometheus error %s binding to unix socket: %s\n", strerror(errno), unix_socket);
			close(fd);
			return NULL;
		}
	}
#else
	(void)(unix_socket);
#endif
	struct rist_prometheus_stats *stats = calloc(1, sizeof(*stats));
	stats->fd = fd;
	if (tags == 0) {
		stats->tags = calloc(1, 1);
	} else {
		stats->tags = rist_prometheus_user_tags(tags);
		if (stats->tags == NULL) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Prometheus: error couldn't parse user supplied tag value %s expected format: tag1=value,tag2=value OR tag1=\"value\",tag2=\"value\"\n", tags);
			free(stats);
			return NULL;
		}
	}
	stats->format_buf = calloc(4096, 1);
	stats->format_buf_len = 4096;
	pthread_mutex_init(&stats->lock, NULL);
	if (httpd_opt != NULL && httpd_opt->enabled) {
#if HAVE_LIBMICROHTTPD
		if (httpd_opt->ip != NULL) {
			struct sockaddr_storage ss;
			int fam;
			int flags = MHD_START_FLAGS;
			if (inet_pton(AF_INET, httpd_opt->ip, &((struct sockaddr_in *)&ss)->sin_addr) != 0) {
				fam = AF_INET;
				((struct sockaddr_in *)&ss)->sin_family = AF_INET;
				((struct sockaddr_in *)&ss)->sin_port = htons(httpd_opt->port);
			} else if (inet_pton(AF_INET6, httpd_opt->ip, &((struct sockaddr_in6 *)&ss)->sin6_addr) != 0) {
				fam = AF_INET6;
				((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
				((struct sockaddr_in6 *)&ss)->sin6_port = htons(httpd_opt->port);
				flags |= MHD_USE_IPv6;
			} else {
				rist_log(logging_settings, RIST_LOG_ERROR, "Prometheus error: prometheus failed to parse IP address: %s\n", httpd_opt->ip);
				rist_prometheus_stats_destroy(stats);
				return NULL;
			}
			if (fam == AF_INET)
				rist_log(logging_settings, RIST_LOG_INFO, "Prometheus HTTPD: exposing stats on: http://%s:%u/metrics\n", httpd_opt->ip, httpd_opt->port);
			else
				rist_log(logging_settings, RIST_LOG_INFO, "Prometheus HTTPD IPv6: exposing stats on: http://[%s]:%u/metrics\n", httpd_opt->ip, httpd_opt->port);
			stats->httpd = MHD_start_daemon(flags, httpd_opt->port, NULL, NULL, rist_prometheus_httpd_handler, stats, MHD_OPTION_SOCK_ADDR, &ss, MHD_OPTION_END);
			if (stats->httpd == NULL) {
				rist_log(logging_settings, RIST_LOG_ERROR, "Prometheus error: failed to start HTTPD Server\n");
				rist_prometheus_stats_destroy(stats);
				return NULL;
			}
		} else {
			fprintf(stderr, "Prometheus HTTPD: exposing stats on: http://0.0.0.0:%u/metrics\n", httpd_opt->port);
			stats->httpd = MHD_start_daemon(MHD_START_FLAGS, httpd_opt->port, NULL, NULL, rist_prometheus_httpd_handler, stats, MHD_OPTION_END);
			if (stats->httpd == NULL) {
				rist_log(logging_settings, RIST_LOG_ERROR, "Prometheus error: failed to start HTTPD Server\n");
				rist_prometheus_stats_destroy(stats);
				return NULL;
			}
		}
#else
		(void)(logging_settings);
		fprintf(stderr, "ERROR: Prometheus HTTPD requested but not compiled in\n");
#endif
	}
	stats->single_stat_point = !multiple_metric_datapoints;
	stats->no_created = skipcreated;
#if HAVE_SOCK_UN_H
	if (unix_socket) {
		if (pthread_create(&stats->unix_socket_thread, NULL, rist_prometheus_stats_unix_socket_thread, stats) != 0) {
			rist_prometheus_stats_destroy(stats);
			return NULL;
		}
		stats->started = true;
	}
#endif
	return stats;
}

void rist_prometheus_stats_destroy(struct rist_prometheus_stats *ctx) {
	if (ctx == NULL)
		return;
	if (ctx->fd >=0) {
		assert(HAVE_SOCK_UN_H);
		shutdown(ctx->fd, SHUT_RDWR);
#ifndef _WIN32
		close(ctx->fd);
#else
		closesocket(ctx->fd);
#endif
		if (ctx->started)
			pthread_join(ctx->unix_socket_thread, NULL);
	}
	for (size_t i=0; i < ctx->client_cnt; i++) {
		free(ctx->clients[i]->tags);
		free(ctx->clients[i]);
	}
	free(ctx->clients);
	for (size_t i=0; i < ctx->sender_peer_cnt; i++) {
		free(ctx->sender_peers[i]->url);
		free(ctx->sender_peers[i]->local_url);
		free(ctx->sender_peers[i]->tags);
		free(ctx->sender_peers[i]);
	}
	free(ctx->sender_peers);

#if HAVE_LIBMICROHTTPD
	if (ctx->httpd != NULL)
		MHD_stop_daemon(ctx->httpd);
#endif
	free(ctx->format_buf);
	free(ctx->tags);
	free(ctx);
}
