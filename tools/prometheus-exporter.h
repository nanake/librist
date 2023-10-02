#include <stdio.h>
#include <stdint.h>
#include <librist/stats.h>
#include <librist/logging.h>

struct rist_prometheus_stats;

struct prometheus_httpd_options {
	bool enabled;
	uint16_t port;
	bool bind_sockaddr;
	char *ip;
};

struct rist_prometheus_stats *rist_setup_prometheus_stats(struct rist_logging_settings *logging_settings, const char* tags, bool multiple_metric_datapoints, bool skipcreated, struct prometheus_httpd_options *httpd_opt, char *unix_socket);
void rist_prometheus_parse_stats(struct rist_prometheus_stats *ctx, const struct rist_stats *stats_container, uintptr_t id);
void rist_prometheus_sender_add_peer(struct rist_prometheus_stats *ctx, uint64_t sender_id, uint32_t peer_id, const char *url, const char *local_url, bool from_callback);
void rist_prometheus_stats_print(struct rist_prometheus_stats *ctx, FILE* out);
void rist_prometheus_stats_destroy(struct rist_prometheus_stats *ctx);

