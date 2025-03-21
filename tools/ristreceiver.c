/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <librist/librist.h>
#include <librist/udpsocket.h>
#include <stdint.h>
#include "headers.h"
#include "librist/version.h"
#include "config.h"
#if HAVE_SRP_SUPPORT
#include "librist/librist_srp.h"
#include "srp_shared.h"
#endif
#include "vcs_version.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "getopt-shim.h"
#include "pthread-shim.h"
#include <stdbool.h>
#include <signal.h>
#include "risturlhelp.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "oob_shared.h"
#include "prometheus-exporter.h"
#ifdef USE_TUN
#include "rist-private.h"
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#endif
#include "yamlparse.h"

#if defined(_WIN32) || defined(_WIN64)
# define strtok_r strtok_s
#endif

#define RISTRECEIVER_VERSION "30"

#define MAX_INPUT_COUNT 20
#define MAX_OUTPUT_COUNT 20
#define ReadEnd  0
#define WriteEnd 1
#define DATA_READ_MODE_CALLBACK 0
#define DATA_READ_MODE_POLL 1
#define DATA_READ_MODE_API 2

pthread_mutex_t signal_lock;
static int signalReceived = 0;
static struct rist_logging_settings logging_settings = LOGGING_SETTINGS_INITIALIZER;
enum rist_profile profile = RIST_PROFILE_MAIN;
static int peer_connected_count = 0;

#if HAVE_PROMETHEUS_SUPPORT
struct rist_prometheus_stats *prom_stats_ctx;
bool prometheus_multipoint = false;
bool prometheus_nocreated = false;
bool prometheus_httpd = false;
bool enable_prometheus = false;
char *prometheus_tags = NULL;
uint16_t prometheus_port = 9100;
char *prometheus_ip = NULL;
char *prometheus_unix_sock = NULL;
#endif

static struct option long_options[] = {
{ "inputurl",        required_argument, NULL, 'i' },
{ "outputurl",       required_argument, NULL, 'o' },
{ "buffer",          required_argument, NULL, 'b' },
{ "secret",          required_argument, NULL, 's' },
{ "encryption-type", required_argument, NULL, 'e' },
{ "profile",         required_argument, NULL, 'p' },
#ifdef USE_TUN
{ "tun",             required_argument, NULL, 't' },
{ "tun-mode",        required_argument, NULL, 'm' },
#endif
{ "stats",           required_argument, NULL, 'S' },
{ "verbose-level",   required_argument, NULL, 'v' },
{ "remote-logging",  required_argument, NULL, 'r' },
#if HAVE_SRP_SUPPORT
{ "srpfile",         required_argument, NULL, 'F' },
#endif
{ "config",          required_argument, NULL, 'c' },
{ "session-timeout-exit",  no_argument, NULL, 'x' },
{ "help",            no_argument,       NULL, 'h' },
{ "help-url",        no_argument,       NULL, 'u' },
#if HAVE_PROMETHEUS_SUPPORT
{ "enable-metrics",  no_argument,       NULL, 'M' },
{ "metrics-tags",    required_argument, NULL, 1 },
{ "metrics-multipoint",no_argument,     (int*)&prometheus_multipoint, true },
{ "metrics-nocreated",no_argument,      (int*)&prometheus_nocreated, true },
#if HAVE_LIBMICROHTTPD
{ "metrics-http",    no_argument,      (int*)&prometheus_httpd, true },
{ "metrics-port",    required_argument, NULL, 2 },
{ "metrics-ip",      required_argument, NULL, 3 },
#endif //HAVE_LIBMICROHTTPD
#if HAVE_SOCK_UN_H
{ "metrics-unix",    required_argument, NULL, 4 },
#endif //HAVE_SOCK_UN_H
#endif //HAVE_PROMETHEUS_SUPPORT
{ 0, 0, 0, 0 },
};

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -i | --inputurl  rist://...             * | Comma separated list of input rist URLs                  |\n"
"       -o | --outputurl udp://... or rtp://... * | Comma separated list of output udp or rtp URLs           |\n"
#ifdef USE_TUN
"                                                 | Use tun://@ to write udp data to a tun device defined    |\n"
"                                                 | using the -t option                                      |\n"
#endif
"       -b | --buffer value                       | Default buffer size for packet retransmissions           |\n"
"       -s | --secret PWD                         | Default pre-shared encryption secret                     |\n"
"       -e | --encryption-type TYPE               | Default Encryption type (0, 128 = AES-128, 256 = AES-256)|\n"
"       -p | --profile number                     | Rist profile (0 = simple, 1 = main, 2 = advanced)        |\n"
"       -S | --statsinterval value (ms)           | Interval at which stats get printed, 0 to disable        |\n"
"       -c | --config name.yaml                   | YAML config file                                         |\n"
"       -v | --verbose-level value                | To disable logging: -1, log levels match syslog levels   |\n"
"       -r | --remote-logging IP:PORT             | Send logs and stats to this IP:PORT using udp messages   |\n"
#if HAVE_SRP_SUPPORT
"       -F | --srpfile filepath                   | When in listening mode, use this file to hold the list   |\n"
"                                                 | of usernames and passwords to validate against. Use the  |\n"
"                                                 | ristsrppasswd tool to create the line entries.           |\n"
#endif
#ifdef USE_TUN
"       -t | --tun name                           | Create a tun device and use it for data communications   |\n"
"       -m | --tun-mode number                    | Data management on the tun interface:                    |\n"
"                                                 | 0 = all tun data is accepted into or out of oob channel  |\n"
"                                                 | 1 = only non udp data is accepted (default)              |\n"
"                                                 | 2 = no data goes into or out of oob channel              |\n"
#endif
#if HAVE_PROMETHEUS_SUPPORT
"       -M | --enable-metrics                     | Enable OpenMetrics/Prometheus compatible metrics         |\n"
"          | --metrics-tags                       | Additional tags to add to the metrics                    |\n"
"          | --metrics-multipoint                 | Metrics return multiple timestamped data points          |\n"
"          | --metrics-nocreated                  | Metrics skip the created metric for Prometheus compat    |\n"
#if HAVE_LIBMICROHTTPD
"          | --metrics-http                       | Start HTTP Server to expose metrics on                   |\n"
"                                                 | defaults to http://0.0.0.0:9100/metrics                  |\n"
"          | --metrics-port                       | Port for metrics HTTP server to listen on                |\n"
"          | --metrics-ip                         | IP for metrics HTTP server to listen on                  |\n"
#endif //HAVE_LIBMICROHTTPD
#if HAVE_SOCK_UN_H
"          | --metrics-unix                       | Unix socket to expose metrics on                         |\n"
#endif //HAVE_SOCK_UN_H
#endif //HAVE_PROMETHEUS_SUPPORT
"       -x | --session-timeout-exit               | Exit on Session Timeout                                  |\n"
"       -h | --help                               | Show this help                                           |\n"
"       -u | --help-url                           | Show all the possible url options                        |\n"
"   * == mandatory value \n"
"Default values: %s \n"
"       --profile 1               \\\n"
"       --statsinterval 1000      \\\n"
"       --verbose-level 6         \n";

static void usage(char *cmd)
{
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n%s version %s libRIST library: %s API version: %s\n", cmd, help_str, RISTRECEIVER_VERSION, librist_version(), librist_api_version());
	exit(1);
}

struct rist_callback_object {
	int mpeg[MAX_OUTPUT_COUNT];
	struct rist_udp_config *udp_config[MAX_OUTPUT_COUNT];
	uint16_t i_seqnum[MAX_OUTPUT_COUNT];
	struct rist_ctx *receiver_ctx;
#ifdef USE_TUN
	int tun;
	int tun_mode;
#endif
	int session_timeout_exit;
};

static inline void risttools_rtp_set_hdr(uint8_t *p_rtp, uint8_t i_type, uint16_t i_seqnum, uint32_t i_timestamp, uint32_t i_ssrc)
{
	p_rtp[0] = 0x80;
	p_rtp[1] = i_type & 0x7f;
	p_rtp[2] = i_seqnum >> 8;
	p_rtp[3] = i_seqnum & 0xff;
    p_rtp[4] = (i_timestamp >> 24) & 0xff;
    p_rtp[5] = (i_timestamp >> 16) & 0xff;
    p_rtp[6] = (i_timestamp >> 8) & 0xff;
    p_rtp[7] = i_timestamp & 0xff;
	p_rtp[8] = (i_ssrc >> 24) & 0xff;
	p_rtp[9] = (i_ssrc >> 16) & 0xff;
	p_rtp[10] = (i_ssrc >> 8) & 0xff;
	p_rtp[11] = i_ssrc & 0xff;
}

static uint32_t risttools_convertNTPtoRTP(uint64_t i_ntp)
{
	i_ntp *= 90000;
	i_ntp = i_ntp >> 32;
	return (uint32_t)i_ntp;
}

static void connection_status_callback(void *arg, struct rist_peer *peer, enum rist_connection_status peer_connection_status)
{
	(void)arg;
	if (peer_connection_status == RIST_CONNECTION_ESTABLISHED || peer_connection_status == RIST_CLIENT_CONNECTED) {
		peer_connected_count++;
	}
	else {
		peer_connected_count--;
	}
	rist_log(&logging_settings, RIST_LOG_INFO,"Connection Status changed for Peer %"PRIu64", new status is %d, peer connected count is %d\n",
				peer, peer_connection_status, peer_connected_count);
}

static int cb_recv(void *arg, struct rist_data_block *b)
{
	struct rist_callback_object *callback_object = (void *) arg;
	int found = 0;
	int i = 0;
	for (i = 0; i < MAX_OUTPUT_COUNT; i++) {
		if (!callback_object->udp_config[i])
			continue;
		struct rist_udp_config *udp_config = callback_object->udp_config[i];
		bool found_it = false;
		int mux_mode = 0;
		if (udp_config->version == 1)
			mux_mode = udp_config->multiplex_mode;
		// The stream-id on the udp url gets translated into the virtual destination port of the GRE tunnel
		// and we match on that. The other two muxing modes are not spec compliant and are only
		// guaranteed to work from librist to librist
		if (profile == RIST_PROFILE_SIMPLE || udp_config->stream_id == 0 ||
				(mux_mode == LIBRIST_MULTIPLEX_MODE_VIRT_DESTINATION_PORT && udp_config->stream_id == b->virt_dst_port) ||
				(mux_mode == LIBRIST_MULTIPLEX_MODE_VIRT_SOURCE_PORT && udp_config->stream_id == b->virt_src_port) ||
				(mux_mode == LIBRIST_MULTIPLEX_MODE_IPV4))
		{
			// Normal manual match
			found_it = true;
		}
		else if (mux_mode == LIBRIST_MULTIPLEX_MODE_AUTO)
		{
			// Auto-detect (librist to librist)
			if (b->virt_src_port == UINT16_MAX) {
				mux_mode = LIBRIST_MULTIPLEX_MODE_IPV4;
				found_it = true;
			}
			if (b->virt_src_port < 32768 && udp_config->stream_id == b->virt_src_port) {
				mux_mode = LIBRIST_MULTIPLEX_MODE_VIRT_SOURCE_PORT;
				found_it = true;
			}
			else if (b->virt_src_port >= 32768 && udp_config->stream_id == b->virt_dst_port) {
				mux_mode = LIBRIST_MULTIPLEX_MODE_VIRT_DESTINATION_PORT;
				found_it = true;
			}
		}

		if (found_it) {
			if (callback_object->mpeg[i] > 0) {
				uint8_t *payload = NULL;
				size_t payload_len = 0;
				if (udp_config->rtp) {
					payload = malloc(12 + b->payload_len);
					payload_len = 12 + b->payload_len;
					// Transfer payload
					memcpy(payload + 12, b->payload, b->payload_len);
					// Set RTP header (mpegts)
					uint16_t i_seqnum = udp_config->rtp_sequence ? (uint16_t)b->seq : callback_object->i_seqnum[i]++;
					uint32_t i_timestamp = risttools_convertNTPtoRTP(b->ts_ntp);
					uint8_t ptype = 0x21;
					if (udp_config->rtp_ptype != 0)
						ptype = udp_config->rtp_ptype;
					risttools_rtp_set_hdr(payload, ptype, i_seqnum, i_timestamp, b->flow_id);
				}
				else if (mux_mode == LIBRIST_MULTIPLEX_MODE_IPV4) {
					// TODO: filtering based on ip header?
					// with an input string for destination ip and port
					// for now, forward it all
					// use output_udp_config->mux_filter
					size_t ipheader_bytes = sizeof(struct ipheader) + sizeof(struct udpheader);
					payload = (uint8_t *)b->payload;
					payload += ipheader_bytes;
					payload_len = b->payload_len - ipheader_bytes;
				}
				else {
					payload = (uint8_t *)b->payload;
					payload_len = b->payload_len;
				}
				int ret = udpsocket_send(callback_object->mpeg[i], payload, payload_len);
				if (udp_config->rtp)
					free(payload);
				if (ret <= 0 && errno != ECONNREFUSED)
					rist_log(&logging_settings, RIST_LOG_ERROR, "Error %d sending udp packet to socket %d\n", errno, callback_object->mpeg[i]);
				found = 1;
			}
		}
	}

#ifdef USE_TUN
	if (b->virt_src_port == 1 && found == 0)
	{
		// This is a tun mux
		if (callback_object->tun) {
			if (write(callback_object->tun, b->payload, b->payload_len) < 0) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Error %d writing %d rist bytes to output tun\n", errno, b->payload_len);
			}
		}
		rist_receiver_data_block_free2(&b);
		return 0;
	}
#endif

	if (found == 0)
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Destination port mismatch, no output found for %d\n", b->virt_dst_port);
		rist_receiver_data_block_free2(&b);
		return -1;
	}
	rist_receiver_data_block_free2(&b);
	return 0;
}

static void intHandler(int signal) {
	pthread_mutex_lock(&signal_lock);
	signalReceived = signal;
	pthread_mutex_unlock(&signal_lock);
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_callback_object *callback_object = (void *) arg;
	uint16_t buffer[250];
	char message[200];
	int message_len = snprintf(message, 200, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	// To be compliant with the spec, the message must have an ipv4 header
	int ret = oob_build_api_payload(buffer, (char *)connecting_ip, (char *)local_ip, message, message_len);
	rist_log(&logging_settings, RIST_LOG_INFO,"Peer has been authenticated, sending oob/api message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = buffer;
	oob_block.payload_len = ret;
	rist_oob_write(callback_object->receiver_ctx, &oob_block);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	(void)peer;
	struct rist_callback_object *callback_object = (void *) arg;
	(void)callback_object;
	return 0;
}

#ifdef USE_TUN
static int rist_validate_tun_data(uint8_t *buffer, ssize_t buffer_len)
{
	struct ipheader *ip = (struct ipheader *) buffer;
	int protocol = 0;
	ssize_t payload_len = 0;
	// Double check the validity of the packet and get the protocol number
	if (RIST_IPH_GET_VER(ip->iph_verlen) == 4) {
		protocol = (int) ip->iph_protocol;
		payload_len = (ssize_t)be16toh(ip->iph_len);
		if (payload_len != buffer_len) {
			rist_log(&logging_settings, RIST_LOG_INFO, "Malformed ipv4 packet %d != %d\n",
				payload_len != buffer_len);
			return -1;
		}
	}
	else if (RIST_IPH_GET_VER(ip->iph_verlen) == 6) {
		// TODO: how do I get the protocol?
		// For now, send all IPv6 over OOB channel
	}
	else {
		rist_log(&logging_settings, RIST_LOG_INFO, "Unknown ipv? payload %d\n",
			RIST_IPH_GET_VER(ip->iph_verlen));
		return -1;
	}
	return protocol;
}

static int cb_recv_oob(void *arg, const struct rist_oob_block *oob_block)
{
	struct rist_callback_object *callback_object = (void *) arg;
	int message_len = 0;
	char *message = oob_process_api_message((int)oob_block->payload_len, (char *)oob_block->payload, &message_len);
	if (message) {
		rist_log(&logging_settings, RIST_LOG_INFO,"Out-of-band api data received: %.*s\n", message_len, message);
	}
	else if (callback_object->tun)
	{
		// Process non-api based data
		int protocol = rist_validate_tun_data((uint8_t *)oob_block->payload, oob_block->payload_len);
		if (protocol >= 0)
		{
			if (callback_object->tun_mode == 0 ||
				(callback_object->tun_mode == 1 && protocol != 17)) {
				if (write(callback_object->tun, oob_block->payload, oob_block->payload_len) < 0) {
					rist_log(&logging_settings, RIST_LOG_ERROR, "Error %d writing %d bytes to output tun\n", errno, oob_block->payload_len);
				}
			}
		}
	}
	return 0;
}
#else
static int cb_recv_oob(void *arg, const struct rist_oob_block *oob_block)
{
	struct rist_ctx *ctx = (struct rist_ctx *)arg;
	(void)ctx;
	int message_len = 0;
	char *message = oob_process_api_message((int)oob_block->payload_len, (char *)oob_block->payload, &message_len);
	if (message) {
		rist_log(&logging_settings, RIST_LOG_INFO,"Out-of-band api data received: %.*s\n", message_len, message);
	}
	return 0;
}
#endif

struct ristreceiver_flow_cumulative_stats {
	uint32_t flow_id;
	uint64_t received;
	uint64_t recovered;
	uint64_t lost;
	struct ristreceiver_flow_cumulative_stats *next;
};

struct ristreceiver_flow_cumulative_stats *stats_list;

static int session_timeout_callback(void *arg, uint32_t flow_id) {
	struct rist_callback_object *callback_object = (void *) arg;
	rist_log(&logging_settings, RIST_LOG_INFO, "Flow with id %"PRIu32" has timed out\n",  flow_id);
	if (callback_object->session_timeout_exit)
		exit(1);
	return 0;
}

static int cb_stats(void *arg, const struct rist_stats *stats_container) {
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n",  stats_container->stats_json);
	if (stats_container->stats_type == RIST_STATS_RECEIVER_FLOW)
	{
		struct ristreceiver_flow_cumulative_stats *stats = stats_list;
		struct ristreceiver_flow_cumulative_stats **prev = &stats_list;
		while (stats && stats->flow_id != stats_container->stats.receiver_flow.flow_id)
		{
			prev = &stats->next;
			stats = stats->next;
		}
		if (!stats) {
			stats = calloc(1, sizeof(*stats));
			stats->flow_id = stats_container->stats.receiver_flow.flow_id;
			*prev = stats;
		}
		stats->received += stats_container->stats.receiver_flow.received;
		stats->lost += stats_container->stats.receiver_flow.lost;
		stats->recovered += stats_container->stats.receiver_flow.recovered;
		//Bit ugly, but linking in cJSON seems a bit excessive for this 4 variable JSON string
		rist_log(&logging_settings, RIST_LOG_INFO,
				 "{\"flow_cumulative_stats\":{\"flow_id\":%"PRIu32",\"received\":%"PRIu64",\"recovered\":%"PRIu64",\"lost\":%"PRIu64"}}\n",
				 stats->flow_id, stats->received, stats->recovered, stats->lost);
#if HAVE_PROMETHEUS_SUPPORT
		if (prom_stats_ctx != NULL)
			rist_prometheus_parse_stats(prom_stats_ctx, stats_container, (uintptr_t)arg);
#else
		(void)arg;
#endif
	}
	rist_stats_free(stats_container);
	return 0;
}

#ifdef USE_TUN
static void rist_process_tun_data(struct rist_callback_object *callback_object, uint8_t *buffer, ssize_t buffer_len)
{
	int protocol = rist_validate_tun_data(buffer, buffer_len);
	if (protocol >=0) {
		// Send data through oob channel
		if (callback_object->tun_mode == 0 ||
				(callback_object->tun_mode == 1 && protocol != 17)) {
			struct rist_oob_block oob_block = { 0 };
			oob_block.peer = NULL;
			oob_block.payload = &buffer[0];
			oob_block.payload_len = buffer_len;
			if (rist_oob_write(callback_object->receiver_ctx, &oob_block) < 0)
				rist_log(&logging_settings, RIST_LOG_INFO, "Error writing %d bytes to rist_oob_write\n", buffer_len);
		}
	}
}

static PTHREAD_START_FUNC(tun_loop, arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	while (!signalReceived) {
		uint8_t buffer[RIST_MAX_PACKET_SIZE];
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(callback_object->tun, &read_fds);
		// Set timeout to 100 ms
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;
		// Wait for input to become ready or until the time out;
		if (select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout) == 1)
		{
			ssize_t r = read(callback_object->tun, &buffer[0], RIST_MAX_PACKET_SIZE);
			if (r > 0) {
				rist_process_tun_data(callback_object, &buffer[0], r);
			}
			else
				break;
		}
	}
	return 0;
}
#endif

int main(int argc, char *argv[])
{
	int option_index;
	int c;
	int data_read_mode = DATA_READ_MODE_CALLBACK;
	const struct rist_peer_config *peer_input_config[MAX_INPUT_COUNT];
	char *inputurl = NULL;
	char *outputurl = NULL;
#ifdef USE_TUN
	char *oobtun = NULL;
#endif
	char *shared_secret = NULL;
	int buffer = 0;
	int encryption_type = 0;
	struct rist_callback_object callback_object = { 0 };
	enum rist_log_level loglevel = RIST_LOG_INFO;
	int statsinterval = 1000;
	char *remote_log_address = NULL;
	if (pthread_mutex_init(&signal_lock, NULL) != 0)
	{
		fprintf(stderr, "Could not initialize signal lock\n");
		exit(1);
	}
#ifndef _WIN32
	/* Receiver pipe handle */
	int receiver_pipe[2];
#endif
	rist_tools_config_object *yaml_config = NULL;
	char *yamlfile = NULL;

#if HAVE_SRP_SUPPORT
	char *srpfile = NULL;
#endif

	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++)
	{
		callback_object.mpeg[i] = 0;
		callback_object.udp_config[i] = NULL;
	}
#ifdef _WIN32
#define STDERR_FILENO 2
	signal(SIGINT, intHandler);
	signal(SIGTERM, intHandler);
	signal(SIGABRT, intHandler);
#else
	struct sigaction act = { {0} };
	act.sa_handler = intHandler;
	sigaction(SIGINT, &act, NULL);
#endif
	// Default log settings
    struct rist_logging_settings *log_ptr = &logging_settings;
    if (rist_logging_set(&log_ptr, loglevel, NULL, NULL, NULL,
                         stderr) != 0) {
      fprintf(stderr, "Failed to setup default logging!\n");
      exit(1);
	}

	rist_log(&logging_settings, RIST_LOG_INFO, "Starting ristreceiver version: %s libRIST library: %s API version: %s\n", RISTRECEIVER_VERSION, librist_version(), librist_api_version());

	while ((c = getopt_long(argc, argv, "r:i:o:b:s:e:t:m:p:S:v:F:c:h:uMx", long_options, &option_index)) != -1) {
		switch (c) {
		case 'i':
			inputurl = strdup(optarg);
		break;
		case 'o':
			outputurl = strdup(optarg);
		break;
		case 'b':
			buffer = atoi(optarg);
		break;
		case 's':
			shared_secret = strdup(optarg);
		break;
		case 'e':
			encryption_type = atoi(optarg);
		break;
#ifdef USE_TUN
		case 't':
			oobtun = strdup(optarg);
		break;
		case 'm':
			callback_object.tun_mode = atoi(optarg);
		break;
#endif
		case 'p':
			profile = atoi(optarg);
		break;
		case 'S':
			statsinterval = atoi(optarg);
		break;
		case 'v':
			loglevel = atoi(optarg);
		break;
		case 'r':
			remote_log_address = strdup(optarg);
		break;
#if HAVE_SRP_SUPPORT
		case 'F': {
			FILE* f = fopen(optarg, "r");
			if (!f) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Could not open srp file %s\n", optarg);
				return 1;
			}
			srpfile = strdup(optarg);
		}
		break;
#endif
		case 'u':
			rist_log(&logging_settings, RIST_LOG_INFO, "%s", help_urlstr);
			exit(1);
		break;
#if HAVE_PROMETHEUS_SUPPORT
		case 'M':
			enable_prometheus = true;
			break;
		case 0:
			//long option, value get's set directly
			break;
		case 1:
			//long option metric tags
			prometheus_tags = strdup(optarg);
			break;
		case 2:
			//prometheus port long opt
			prometheus_httpd = true;
			prometheus_port = atoi(optarg);
			break;
		case 3:
			//prometheus IP long opt
			prometheus_httpd = true;
			prometheus_ip = strdup(optarg);
			break;
		case 4:
			//prometheus unix socket long opt
			enable_prometheus = true;
			prometheus_unix_sock = strdup(optarg);
			break;
#endif
		case 'c':
			yamlfile = strdup(optarg);
			yaml_config = parse_yaml(yamlfile);
			free(yamlfile);
			if (!yaml_config){
				fprintf(stderr,"Could not import yaml file %s\n",optarg);
				cleanup_tools_config(yaml_config);
				exit(1);
			}
			if (yaml_config->input_url)
				inputurl = strdup(yaml_config->input_url);
			if (yaml_config->output_url)
				outputurl = strdup(yaml_config->output_url);
			buffer = yaml_config->buffer;
			if (yaml_config->secret)
				shared_secret = strdup(yaml_config->secret);
			encryption_type = yaml_config->encryption_type;
			loglevel = yaml_config->verbose_level;
			if (yaml_config->remote_log_address)
				remote_log_address = strdup(yaml_config->remote_log_address);
			profile = yaml_config->profile;
			statsinterval = yaml_config->stats_interval;
#ifdef USE_TUN
			// hardcoded mode for now
			// callback_tun_object.tun_mode = 1; (yaml_config->tun_mode)
			if (yaml_config->tunnel_interface)
				oobtun = strdup(yaml_config->tunnel_interface);
#endif
#if HAVE_SRP_SUPPORT
			if (yaml_config->srp_file)
				srpfile = strdup(yaml_config->srp_file);
#endif
#if HAVE_PROMETHEUS_SUPPORT
			enable_prometheus = yaml_config->enable_metrics;
			if (yaml_config->metrics_tags)
				prometheus_tags = strdup(yaml_config->metrics_tags);
			prometheus_multipoint = yaml_config->metrics_multipoint;
			prometheus_nocreated = yaml_config->metrics_nocreated;
#if HAVE_LIBMICROHTTPD
        	prometheus_httpd = yaml_config->metrics_http;
        	prometheus_port = yaml_config->metrics_port;
			if (yaml_config->metrics_ip)
	        	prometheus_ip = strdup(yaml_config->metrics_ip);
#endif
#if HAVE_SOCK_UN_H
			if (yaml_config->metrics_unix)
	        	prometheus_unix_sock = strdup(yaml_config->metrics_unix);
#endif
#endif
			cleanup_tools_config(yaml_config);
			break;
		case 'x':
			callback_object.session_timeout_exit = 1;
			break;
		case 'h':
			/* Fall through */
		default:
			usage(argv[0]);
		break;
		}
	}

	if (inputurl == NULL || outputurl == NULL) {
		usage(argv[0]);
	}

	if (argc < 2) {
		usage(argv[0]);
	}

	// Update log settings with custom loglevel and remote address if necessary
	if (rist_logging_set(&log_ptr, loglevel, NULL, NULL, remote_log_address, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging!\n");
		exit(1);
	}

#if HAVE_PROMETHEUS_SUPPORT
	if (enable_prometheus || prometheus_httpd) {
		rist_log(log_ptr, RIST_LOG_INFO, "Enabling Metrics output\n");
		struct prometheus_httpd_options httpd_opt;
		httpd_opt.enabled = prometheus_httpd;
		httpd_opt.port = prometheus_port;
		httpd_opt.ip = prometheus_ip;
		prom_stats_ctx = rist_setup_prometheus_stats(log_ptr, prometheus_tags,prometheus_multipoint, prometheus_nocreated, &httpd_opt, prometheus_unix_sock);
		if (prom_stats_ctx == NULL) {
			rist_log(log_ptr, RIST_LOG_ERROR, "Failed to setup Metrics output\n");
			exit(1);
		}
	}
#endif
	/* rist side */

	struct rist_ctx *ctx;
	if (rist_receiver_create(&ctx, profile, &logging_settings) != 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not create rist receiver context\n");
		exit(1);
	}

	callback_object.receiver_ctx = ctx;

	if (rist_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, (void *)&callback_object) != 0) {

		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not init rist auth handler\n");
		exit(1);
	}

	if (rist_connection_status_callback_set(ctx, connection_status_callback, NULL) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not initialize rist connection status callback\n");
		exit(1);
	}

	if (profile != RIST_PROFILE_SIMPLE) {
		if (rist_oob_callback_set(ctx, cb_recv_oob, (void *)&callback_object) == -1) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not add enable out-of-band data\n");
			exit(1);
		}
	}

	if (rist_stats_callback_set(ctx, statsinterval, cb_stats, (void*)0) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not enable stats callback\n");
		exit(1);
	}

	double api_version = strtod(librist_api_version(), NULL);
	if (api_version > 4.5)
	{
		if (rist_receiver_session_timeout_callback_set(ctx, session_timeout_callback, (void *)&callback_object) == -1) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not enable session timeout callback\n");
			exit(1);
		}
	}

#ifdef USE_TUN
	// Setup tun device
	if (oobtun) {
		callback_object.tun = oob_setup_tun_device(oobtun);
		if (callback_object.tun == -1)
			rist_log(&logging_settings, RIST_LOG_ERROR, "tun open error: %s\n", strerror(errno));
		else if (callback_object.tun < 0)
			rist_log(&logging_settings, RIST_LOG_ERROR, "tun ioctl error: %s (%d)\n", strerror(errno), callback_object.tun);
		if (callback_object.tun < 0)
			exit(1);
	}
#endif

	char *saveptr1;
	char *inputtoken = strtok_r(inputurl, ",", &saveptr1);
	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		if (!inputtoken)
			break;

		// Rely on the library to parse the url
		struct rist_peer_config *peer_config = NULL;
		if (rist_parse_address2(inputtoken, &peer_config))
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse peer options for receiver #%d\n", (int)(i + 1));
			exit(1);
		}

		/* Process overrides */
		struct rist_peer_config *overrides_peer_config = peer_config;
		if (shared_secret && peer_config->secret[0] == 0) {
			strncpy(overrides_peer_config->secret, shared_secret, RIST_MAX_STRING_SHORT -1);
			if (encryption_type)
				overrides_peer_config->key_size = encryption_type;
			else if (!overrides_peer_config->key_size)
				overrides_peer_config->key_size = 128;
		}
		if (buffer) {
			overrides_peer_config->recovery_length_min = buffer;
			overrides_peer_config->recovery_length_max = buffer;
		}

		/* Print config */
		rist_log(&logging_settings, RIST_LOG_INFO, "Link configured with maxrate=%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d congestion_control=%d min_retries=%d max_retries=%d\n",
			peer_config->recovery_maxbitrate, peer_config->recovery_length_min, peer_config->recovery_length_max,
			peer_config->recovery_reorder_buffer, peer_config->recovery_rtt_min,peer_config->recovery_rtt_max,
			peer_config->congestion_control_mode, peer_config->min_retries, peer_config->max_retries);

		peer_input_config[i] = peer_config;

		struct rist_peer *peer;
		if (rist_peer_create(ctx, &peer, peer_input_config[i]) == -1) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not add peer connector to receiver #%i\n", (int)(i + 1));
			exit(1);
		}
#if HAVE_SRP_SUPPORT
		int srp_error = 0;
		if (profile != RIST_PROFILE_SIMPLE) {
			if (strlen(peer_config->srp_username) > 0 && strlen(peer_config->srp_password) > 0)
			{
				srp_error = rist_enable_eap_srp_2(peer, peer_config->srp_username, peer_config->srp_password, NULL, NULL);
				if (srp_error)
					rist_log(&logging_settings, RIST_LOG_WARN, "Error %d trying to enable SRP for peer\n", srp_error);
			}
			if (srpfile)
			{
				srp_error = rist_enable_eap_srp_2(peer, NULL, NULL, user_verifier_lookup, srpfile);
				if (srp_error)
					rist_log(&logging_settings, RIST_LOG_WARN, "Error %d trying to enable SRP global authenticator, file %s\n", srp_error, srpfile);
			}
		}
		else
			rist_log(&logging_settings, RIST_LOG_WARN, "SRP Authentication is not available for Rist Simple Profile\n");
#endif

		rist_peer_config_free2(&peer_config);
		inputtoken = strtok_r(NULL, ",", &saveptr1);
	}

	/* Mpeg side */
	bool atleast_one_socket_opened = false;
	char *saveptr2;
	char *outputtoken = strtok_r(outputurl, ",", &saveptr2);
	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++) {

		if (!outputtoken)
			break;

		// First parse extra parameters (?miface=lo&stream-id=1971) and separate the address
		// We are using the rist_parse_address function to create a config object that does not really
		// belong to the udp output. We do this only to avoid writing another parser for the two url
		// parameters available to the udp input/output url
		struct rist_udp_config *udp_config = NULL;
		if (rist_parse_udp_address2(outputtoken, &udp_config)) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse outputurl %s\n", outputtoken);
			goto next;
		}

#ifdef USE_TUN
		if (strcmp(udp_config->prefix, "tun") == 0) {
			if (!callback_object.tun) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Detected 'tun://' usage in output url but '--tun' argument was not given\n");
				exit(1);
			}
			atleast_one_socket_opened = true;
			goto next;
		}
#endif

		// Now parse the address 127.0.0.1:5000
		char hostname[200] = {0};
		int outputlisten;
		uint16_t outputport;
		if (udpsocket_parse_url((void *)udp_config->address, hostname, 200, &outputport, &outputlisten) || !outputport || strlen(hostname) == 0) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse output url %s\n", outputtoken);
			goto next;
		}
		rist_log(&logging_settings, RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %d\n", (char *) hostname, outputport);

		// Open the output socket
		callback_object.mpeg[i] = udpsocket_open_connect(hostname, outputport, udp_config->miface);
		if (callback_object.mpeg[i] < 0) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not connect to: Host %s, Port %d\n", (char *) hostname, outputport);
			goto next;
		} else {
			rist_log(&logging_settings, RIST_LOG_INFO, "Output socket is open and bound %s:%d\n", (char *) hostname, outputport);
			atleast_one_socket_opened = true;
		}
		callback_object.udp_config[i] = udp_config;

next:
		outputtoken = strtok_r(NULL, ",", &saveptr2);
	}

	if (!atleast_one_socket_opened) {
		exit(1);
	}

#ifdef USE_TUN
	pthread_t thread_tun_loop = { 0 };
	if (callback_object.tun && pthread_create(&thread_tun_loop, NULL, tun_loop, (void *)&callback_object) != 0)
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start tun read thread\n");
		exit(1);
	}
#endif

	if (data_read_mode == DATA_READ_MODE_CALLBACK) {
		if (rist_receiver_data_callback_set2(ctx, cb_recv, &callback_object))
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not set data_callback pointer\n");
			exit(1);
		}
	}
#ifndef _WIN32
	else if (data_read_mode == DATA_READ_MODE_POLL) {
		if (pipe(receiver_pipe))
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not create pipe for file descriptor channel\n");
			exit(1);
		}
		if (fcntl(receiver_pipe[WriteEnd], F_SETFL, O_NONBLOCK) < 0)
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not set pipe to non blocking mode\n");
 			exit(1);
 		}
		if (fcntl(receiver_pipe[ReadEnd], F_SETFL, O_NONBLOCK) < 0)
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not set pipe to non blocking mode\n");
 			exit(1);
 		}
		if (rist_receiver_data_notify_fd_set(ctx, receiver_pipe[WriteEnd]))
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not set file descriptor channel\n");
			exit(1);
		}
	}
#endif

	if (rist_start(ctx)) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start rist receiver\n");
		exit(1);
	}
	/* Start the rist protocol thread */
	if (data_read_mode == DATA_READ_MODE_CALLBACK) {
#ifdef _WIN32
		system("pause");
#else
		pause();
#endif
	}
	else if (data_read_mode == DATA_READ_MODE_API) {
#ifndef _WIN32
		int prio_max = sched_get_priority_max(SCHED_RR);
		struct sched_param param = { 0 };
		param.sched_priority = prio_max;
		if (pthread_setschedparam(pthread_self(), SCHED_RR, &param) != 0)
			rist_log(&logging_settings, RIST_LOG_WARN, "Failed to set data output thread to RR scheduler with prio of %i\n", prio_max);
#else
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#endif
		// Master loop
		while (true)
		{
			struct rist_data_block *b = NULL;
			int queue_size = rist_receiver_data_read2(ctx, &b, 5);
			if (queue_size > 0) {
				if (queue_size % 10 == 0 || queue_size > 50) {
					// We need a better way to report on this
					uint32_t flow_id = b ? b->flow_id : 0;
					rist_log(&logging_settings, RIST_LOG_WARN, "Falling behind on rist_receiver_data_read: count %d, flow id %u\n", queue_size, flow_id);
				}
				if (b && b->payload) cb_recv(&callback_object, b);
			}
			pthread_mutex_lock(&signal_lock);
			if (signalReceived)
			{
				rist_log(&logging_settings, RIST_LOG_INFO, "Signal %d received\n", signal);
				break;
			}
			pthread_mutex_unlock(&signal_lock);
		}
	}
#ifndef _WIN32
	else if (data_read_mode == DATA_READ_MODE_POLL) {
		char pipebuffer[256];
		fd_set readfds;
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 5000;
		while (true) {
			FD_ZERO(&readfds);
			FD_SET(receiver_pipe[ReadEnd], &readfds);
			int ret = select(FD_SETSIZE, &readfds, NULL, NULL, &timeout);
			if (ret == -1 && errno != EINTR) {
				fprintf(stderr, "Pipe read error %d, exiting\n", errno);
				break;
			}
			else if (ret == 0) {
				// Normal timeout (loop and wait)
				continue;
			}
			/* Consume bytes from pipe (irrelevant data) */
			for (;;) {
				if (read(receiver_pipe[ReadEnd], &pipebuffer, sizeof(pipebuffer)) <= 0) {
					if (errno != EAGAIN)
						fprintf(stderr, "Error reading data from pipe: %d\n", errno);
					break;
				}
			}
			/* Consume data from library */
			struct rist_data_block *b = NULL;
			int queue_size = 0;
			for (;;) {
				queue_size = rist_receiver_data_read2(ctx, &b, 0);
				if (queue_size > 0) {
					if (queue_size % 10 == 0 || queue_size > 50) {
						// We need a better way to report on this
						uint32_t flow_id = b ? b->flow_id : 0;
						rist_log(&logging_settings, RIST_LOG_WARN, "Falling behind on rist_receiver_data_read: count %d, flow id %u\n", queue_size, flow_id);
					}
					if (b && b->payload) cb_recv(&callback_object, b);
				}
				else
					break;
			}
			pthread_mutex_lock(&signal_lock);
			if (signalReceived)
			{
				rist_log(&logging_settings, RIST_LOG_INFO, "Signal %d received\n", signal);
				break;
			}
			pthread_mutex_unlock(&signal_lock);
		}
	}
#endif
	rist_destroy(ctx);

	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++) {
		// Free udp_config object
		if ((void *)callback_object.udp_config[i])
			rist_udp_config_free2(&callback_object.udp_config[i]);
	}

	rist_logging_unset_global();
	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);
#ifdef USE_TUN
	if (thread_tun_loop)
		pthread_join(thread_tun_loop, NULL);
	if (oobtun)
		free(oobtun);
	if (callback_object.tun)
		close(callback_object.tun);
#endif
	if (shared_secret)
		free(shared_secret);

	struct ristreceiver_flow_cumulative_stats *stats, *next;
	stats = stats_list;
	while (stats)
	{
		next = stats->next;
		free(stats);
		stats = next;
	}
#if HAVE_PROMETHEUS_SUPPORT
	rist_prometheus_stats_destroy(prom_stats_ctx);
	free(prometheus_ip);
	free(prometheus_tags);
	free(prometheus_unix_sock);
#endif
	return 0;
}
