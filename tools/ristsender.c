/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <librist/librist.h>
#include <librist/udpsocket.h>
#include <stdint.h>
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
#include <stdbool.h>
#include <signal.h>
#include "common/attributes.h"
#include "risturlhelp.h"
#include "rist-private.h"
#include <stdatomic.h>
#include "oob_shared.h"
#include "prometheus-exporter.h"
#ifdef USE_TUN
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#define strtok_r strtok_s
#define MSG_DONTWAIT (0)
#endif

#define RIST_MARK_UNUSED(unused_param) ((void)(unused_param))

#define RISTSENDER_VERSION "2"

#define MAX_INPUT_COUNT 20
#define MAX_OUTPUT_COUNT 20

static int signalReceived = 0;
static int peer_connected_count = 0;
static struct rist_logging_settings logging_settings = LOGGING_SETTINGS_INITIALIZER;

uint64_t prometheus_id = 0;

struct rist_ctx_wrap {
	struct rist_ctx *ctx;
	uintptr_t id;
	bool sender;
};

struct rist_callback_object {
	int sd;
	struct evsocket_ctx *evctx;
	struct rist_ctx_wrap *receiver_ctx;
	struct rist_ctx_wrap *sender_ctx;
	struct rist_udp_config *udp_config;
	uint8_t recv[RIST_MAX_PACKET_SIZE + 100];
};

#ifdef USE_TUN
struct rist_callback_tun_object {
	struct rist_ctx *sender_ctx;
	int tun;
	int tun_mode;
	bool send_rist;
};
#endif

struct receive_thread_object {
	int sd;
	struct rist_ctx *ctx[MAX_OUTPUT_COUNT];
	struct rist_udp_config *udp_config;
	uint8_t recv[RIST_MAX_PACKET_SIZE];
};

struct rist_sender_args {
	char* token;
	int profile;
	enum rist_log_level loglevel;
	int encryption_type;
	char* shared_secret;
	int buffer_size;
	int statsinterval;
	uint16_t stream_id;
#ifdef USE_TUN
	struct rist_callback_tun_object *callback_tun_object;
#endif
};

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
{ "null-packet-deletion",  no_argument, NULL, 'n' },
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
{ "fast-start",      required_argument, NULL, 'f' },
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
"       -i | --inputurl  udp://... or rtp://... * | Comma separated list of input udp or rtp URLs            |\n"
#ifdef USE_TUN
"                                                 | Use tun://@ to read udp data from a tun device defined   |\n"
"                                                 | using the -t option                                      |\n"
#endif
"       -o | --outputurl rist://...             * | Comma separated list of output rist URLs                 |\n"
"       -b | --buffer value                       | Default buffer size for packet retransmissions           |\n"
"       -s | --secret PWD                         | Default pre-shared encryption secret                     |\n"
"       -e | --encryption-type TYPE               | Default Encryption type (0, 128 = AES-128, 256 = AES-256)|\n"
"       -p | --profile number                     | Rist profile (0 = simple, 1 = main, 2 = advanced)        |\n"
"       -n | --null-packet-deletion               | Enable NPD, receiver needs to support this!              |\n"
"       -S | --statsinterval value (ms)           | Interval at which stats get printed, 0 to disable        |\n"
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
"                                                 | 0 = all data is accepted into and out of oob channel     |\n"
"                                                 | 1 = only non udp data is accepted (default)              |\n"
"                                                 | 2 = no data goes into or out of oob channel              |\n"
#endif
"       -f | --fast-start value                   | Controls data output flow before handshake is completed  |\n"
//"                                                 | -1 = hold data out and igmp source joins                 |\n"
"                                                 |  0 = hold data out                                       |\n"
"                                                 |  1 = start to send data immediately                      |\n"
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
"       -h | --help                               | Show this help                                           |\n"
"       -u | --help-url                           | Show all the possible url options                        |\n"
"   * == mandatory value \n"
"Default values: %s \n"
"       --profile 1               \\\n"
"       --statsinterval 1000      \\\n"
"       --verbose-level 6         \n";

/*
static uint64_t risttools_convertRTPtoNTP(uint32_t i_rtp)
{
	uint64_t i_ntp;
    int32_t clock = 90000;
    i_ntp = (uint64_t)i_rtp << 32;
    i_ntp /= clock;
	return i_ntp;
}
*/

#if HAVE_SRP_SUPPORT
	char *srpfile = NULL;
#endif

static void input_udp_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(revents);
	RIST_MARK_UNUSED(fd);

	ssize_t recv_bufsize = -1;
	struct sockaddr_in addr4 = {0};
	struct sockaddr_in6 addr6 = {0};
	struct sockaddr *addr;
	uint8_t *recv_buf = callback_object->recv;
	struct ipheader ipv4hdr;
	struct udpheader udphdr;
	size_t ipheader_bytes = sizeof(ipv4hdr) + sizeof(udphdr);
	socklen_t addrlen = 0;

	uint16_t address_family = (uint16_t)callback_object->udp_config->address_family;
	if (address_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		recv_bufsize = udpsocket_recvfrom(callback_object->sd, recv_buf + ipheader_bytes, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *) &addr6, &addrlen);
		addr = (struct sockaddr *) &addr6;
	} else {
		addrlen = sizeof(struct sockaddr_in);
		recv_bufsize = udpsocket_recvfrom(callback_object->sd, recv_buf + ipheader_bytes, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *) &addr4, &addrlen);
		addr = (struct sockaddr *) &addr4;
	}

	if (recv_bufsize > 0) {
		ssize_t offset = 0;
		struct rist_data_block data_block = { 0 };
		// Delegate ts_ntp to the library by default.
		// If we wanted to be more accurate, we could use the kernel nic capture timestamp (linux)
		data_block.ts_ntp = 0;
		data_block.flags = 0;
		if (callback_object->udp_config->rtp_timestamp && recv_bufsize > 12)
		{
			// Extract timestamp from rtp header
			//uint32_t rtp_time = (recv_buf[4] << 24) | (recv_buf[5] << 16) | (recv_buf[6] << 8) | recv_buf[7];
			// Convert to NTP (assumes 90Khz)
			//data_block.ts_ntp = risttools_convertRTPtoNTP(rtp_time);
			// TODO: Figure out why this does not work (commenting out for now)
		}
		if (callback_object->udp_config->rtp_sequence && recv_bufsize > 12)
		{
			// Extract sequence number from rtp header
			//data_block.seq = (uint64_t)((recv_buf[2] << 8) | recv_buf[3]);
			//data_block.flags = RIST_DATA_FLAGS_USE_SEQ;
			// TODO: Figure out why this does not work (commenting out for now)
		}
		if (callback_object->udp_config->version == 1 && callback_object->udp_config->multiplex_mode == LIBRIST_MULTIPLEX_MODE_IPV4) {
			data_block.virt_src_port = UINT16_MAX;
			data_block.payload = recv_buf + offset;
			data_block.payload_len = recv_bufsize - offset + ipheader_bytes;
			populate_ipv4_rist_header(address_family, recv_buf, recv_bufsize, addr, addrlen);
		}
		else {
			// rtp header will not be stripped out in IPV4 mux mode
			if (callback_object->udp_config->rtp && recv_bufsize > 12)
				offset = 12; // TODO: check for header extensions and remove them as well
			if (callback_object->udp_config->version == 1 && callback_object->udp_config->multiplex_mode == LIBRIST_MULTIPLEX_MODE_VIRT_SOURCE_PORT) {
				data_block.virt_src_port = callback_object->udp_config->stream_id;
			}
			data_block.payload = recv_buf + offset + ipheader_bytes;
			data_block.payload_len = recv_bufsize - offset;
		}
		if (peer_connected_count) {
			if (rist_sender_data_write(callback_object->sender_ctx->ctx, &data_block) < 0)
				rist_log(&logging_settings, RIST_LOG_ERROR, "Error writing data in input_udp_recv, socket=%d\n", callback_object->sd);
		}
	}
	else
	{
		// EWOULDBLOCK = EAGAIN = 11 would be the most common recoverable error (if any)
		if (errno != EWOULDBLOCK)
			rist_log(&logging_settings, RIST_LOG_ERROR, "Input receive failed: errno=%d, ret=%d, socket=%d\n", errno, recv_bufsize, callback_object->sd);
	}
}

static void input_udp_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(revents);
	RIST_MARK_UNUSED(fd);
	rist_log(&logging_settings, RIST_LOG_ERROR, "Socket error on sd=%d, stream-id=%d !\n", callback_object->sd, callback_object->udp_config->stream_id);
}

static void usage(char *cmd)
{
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n%s version %s libRIST library: %s API version: %s\n", cmd, help_str, LIBRIST_VERSION, librist_version(), librist_api_version());
	exit(1);
}

static void connection_status_callback(void *arg, struct rist_peer *peer, enum rist_connection_status peer_connection_status)
{
	(void)arg;
	if (peer_connection_status == RIST_CONNECTION_ESTABLISHED || peer_connection_status == RIST_CLIENT_CONNECTED)
		peer_connected_count++;
	else
		peer_connected_count--;
	rist_log(&logging_settings, RIST_LOG_INFO,"Connection Status changed for Peer %"PRIu64", new status is %d, peer connected count is %d\n",
				peer, peer_connection_status, peer_connected_count);
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_ctx_wrap *w = (struct rist_ctx_wrap *)arg;
#if HAVE_PROMETHEUS_SUPPORT
	if (w->sender && prom_stats_ctx != NULL) {
		uint32_t id = rist_peer_get_id(peer);
		char url[256];
		snprintf(url, sizeof(url), "%s:%u", connecting_ip, connecting_port);
		char local_url[256];
		snprintf(local_url, sizeof(local_url), "%s:%u", local_ip, local_port);
		rist_prometheus_sender_add_peer(prom_stats_ctx, w->id, id, url, local_url, true);
	}
#endif
	struct rist_ctx *ctx = w->ctx;
	uint16_t buffer[250];
	char message[200];
	int message_len = snprintf(message, 200, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	// To be compliant with the spec, the message must have an ipv4 header
	int ret = oob_build_api_payload(buffer, (char *)connecting_ip, (char *)local_ip, message, message_len);
	rist_log(&logging_settings, RIST_LOG_INFO,"Peer has been peer_connected_count, sending oob/api message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = buffer;
	oob_block.payload_len = ret;
	rist_oob_write(ctx, &oob_block);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	struct rist_ctx *ctx = (struct rist_ctx *)arg;
	(void)ctx;
	(void)peer;
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
	struct rist_callback_tun_object *callback_tun_object = (void *) arg;
	int message_len = 0;
	char *message = oob_process_api_message((int)oob_block->payload_len, (char *)oob_block->payload, &message_len);
	if (message) {
		rist_log(&logging_settings, RIST_LOG_INFO,"Out-of-band api data received: %.*s\n", message_len, message);
	}
	else if (callback_tun_object->tun)
	{
		// Process non-api based data
		int protocol = rist_validate_tun_data((uint8_t *)oob_block->payload, oob_block->payload_len);
		if (protocol >= 0)
		{
			if (callback_tun_object->tun_mode == 0 ||
				(callback_tun_object->tun_mode == 1 && protocol != 17)) {
				if (write(callback_tun_object->tun, oob_block->payload, oob_block->payload_len) < 0) {
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

static int cb_stats(void *arg, const struct rist_stats *stats_container)
{
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n\n", stats_container->stats_json);
#if HAVE_PROMETHEUS_SUPPORT
	if (prom_stats_ctx != NULL)
		rist_prometheus_parse_stats(prom_stats_ctx, stats_container, (uintptr_t)arg);
#else
	(void)arg;
#endif
	rist_stats_free(stats_container);
	return 0;
}

static void intHandler(int signal)
{
	rist_log(&logging_settings, RIST_LOG_INFO, "Signal %d received\n", signal);
	signalReceived = signal;
}

static struct rist_peer* setup_rist_peer(struct rist_ctx_wrap *w, struct rist_sender_args *setup)
{
	struct rist_ctx *ctx = w->ctx;
	if (rist_stats_callback_set(ctx, setup->statsinterval, cb_stats, (void*)w->id) == -1) {

		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not enable stats callback\n");
		return NULL;
	}

	if (rist_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, w) < 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not initialize rist auth handler\n");
		return NULL;
	}

	if (rist_connection_status_callback_set(ctx, connection_status_callback, NULL) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not initialize rist connection status callback\n");
		return NULL;
	}

	if (setup->profile != RIST_PROFILE_SIMPLE) {
#ifdef USE_TUN
		if (rist_oob_callback_set(ctx, cb_recv_oob, setup->callback_tun_object) == -1) {
#else
		if (rist_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
#endif
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not enable out-of-band data\n");
			return NULL;
		}
	}

	if (rist_stats_callback_set(ctx, setup->statsinterval, cb_stats, NULL) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not enable stats callback\n");
		return NULL;
	}

	// Rely on the library to parse the url
	struct rist_peer_config *peer_config_link = NULL;
	if (rist_parse_address2(setup->token, (void *)&peer_config_link))
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse peer options for sender: %s\n", setup->token);
		return NULL;
	}

	/* Process overrides */
	struct rist_peer_config *overrides_peer_config = (void *)peer_config_link;
	if (setup->shared_secret && peer_config_link->secret[0] == 0) {
		strncpy(overrides_peer_config->secret, setup->shared_secret, RIST_MAX_STRING_SHORT -1);
		if (setup->encryption_type)
			overrides_peer_config->key_size = setup->encryption_type;
		else if (!overrides_peer_config->key_size)
			overrides_peer_config->key_size = 128;
	}
	if (setup->buffer_size) {
		overrides_peer_config->recovery_length_min = setup->buffer_size;
		overrides_peer_config->recovery_length_max = setup->buffer_size;
	}
	if (setup->stream_id) {
		if (setup->stream_id % 2 != 0) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Error parsing peer options for sender: %s, stream-id (%d) must be even!\n\n", setup->token, setup->stream_id);
			return NULL;
		}
		else {
			overrides_peer_config->virt_dst_port = setup->stream_id;
		}
	}

	/* Print config */
	rist_log(&logging_settings, RIST_LOG_INFO, "Link configured with maxrate=%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d congestion_control=%d min_retries=%d max_retries=%d\n",
		peer_config_link->recovery_maxbitrate, peer_config_link->recovery_length_min, peer_config_link->recovery_length_max,
		peer_config_link->recovery_reorder_buffer, peer_config_link->recovery_rtt_min, peer_config_link->recovery_rtt_max,
		peer_config_link->congestion_control_mode, peer_config_link->min_retries, peer_config_link->max_retries);

	struct rist_peer *peer;
	if (rist_peer_create(ctx, &peer, peer_config_link) == -1) {

		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not add peer connector to %s\n", peer_config_link->address);
		free((void *)peer_config_link);
		return NULL;
	}

#if HAVE_PROMETHEUS_SUPPORT
	if (w->sender && prom_stats_ctx != NULL) {
		char *p = strchr(overrides_peer_config->address, '@');
		if (p == NULL) {
			p = strstr(overrides_peer_config->address, "://");
			if (p == NULL) {
				p = overrides_peer_config->address;
			} else {
				p+= strlen("://");
			}
			uint32_t id = rist_peer_get_id(peer);
			rist_prometheus_sender_add_peer(prom_stats_ctx, w->id, id, p, NULL, false);
		}
	}
#endif
#if HAVE_SRP_SUPPORT
	int srp_error = 0;
	if (setup->profile != RIST_PROFILE_SIMPLE) {
		if (strlen(peer_config_link->srp_username) > 0 && strlen(peer_config_link->srp_password) > 0)
		{
			srp_error = rist_enable_eap_srp_2(peer, peer_config_link->srp_username, peer_config_link->srp_password, NULL, NULL);
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

	rist_peer_config_free2(&peer_config_link);

	return peer;
}

#ifdef USE_TUN
static void rist_process_tun_data(struct rist_callback_tun_object *callback_tun_object, uint8_t *buffer, ssize_t buffer_len)
{
	int protocol = rist_validate_tun_data(buffer, buffer_len);
	if (protocol >=0) {
		// Send data through oob channel
		if (callback_tun_object->tun_mode == 0 ||
				(callback_tun_object->tun_mode == 1 && protocol != 17)) {
			struct rist_oob_block oob_block = { 0 };
			oob_block.peer = NULL;
			oob_block.payload = &buffer[0];
			oob_block.payload_len = buffer_len;
			if (rist_oob_write(callback_tun_object->sender_ctx, &oob_block) < 0)
				rist_log(&logging_settings, RIST_LOG_ERROR, "Error writing %d bytes to rist_oob_write\n", buffer_len);
		}
		// Send data through rist channel
		if (callback_tun_object->send_rist == true &&
				callback_tun_object->tun_mode != 0 && protocol == 17) {
			struct rist_data_block data_block = { 0 };
			// We use this source port to signal a non standard stream, i.e. tun mux
			data_block.virt_src_port = 1;
			// Delegate ts_ntp to the library by default.
			// If we wanted to be more accurate, we could use the kernel nic capture timestamp (linux)
			data_block.ts_ntp = 0;
			data_block.flags = 0;
			data_block.payload = &buffer[0];
			data_block.payload_len = buffer_len;
			if (rist_sender_data_write(callback_tun_object->sender_ctx, &data_block) < 0)
				rist_log(&logging_settings, RIST_LOG_ERROR, "Error writing %d bytes to rist_sender_data_write\n", buffer_len);
		}
	}
}

static PTHREAD_START_FUNC(tun_loop, arg)
{
	struct rist_callback_tun_object *callback_tun_object = (void *) arg;
	while (!signalReceived) {
		uint8_t buffer[RIST_MAX_PACKET_SIZE];
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(callback_tun_object->tun, &read_fds);
		// Set timeout to 100 ms
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;
		// Wait for input to become ready or until the time out;
		if (select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout) == 1)
		{
			ssize_t r = read(callback_tun_object->tun, &buffer[0], RIST_MAX_PACKET_SIZE);
			if (r > 0) {
				rist_process_tun_data(callback_tun_object, &buffer[0], r);
			}
			else
				break;
		}
	}
	return 0;
}
#endif

static PTHREAD_START_FUNC(input_loop, arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	// This is my main loop (one thread per receiver)
	while (!signalReceived) {
		if (callback_object->receiver_ctx)
		{
			// RIST receiver
			struct rist_data_block *b = NULL;
			int queue_size = rist_receiver_data_read2(callback_object->receiver_ctx->ctx, &b, 5);
			if (queue_size > 0) {
				if (queue_size % 10 == 0 || queue_size > 50)
					rist_log(&logging_settings, RIST_LOG_WARN, "Falling behind on rist_receiver_data_read: %d\n", queue_size);
				if (b && b->payload) {
					if (peer_connected_count) {
						int w = rist_sender_data_write(callback_object->sender_ctx->ctx, b);
						// TODO: report error?
						(void) w;
					}
					rist_receiver_data_block_free2(&b);
				}
			}
		}
		else
		{
			// UDP receiver. Infinite wait, 100 socket events
			evsocket_loop_single(callback_object->evctx, 5, 100);
		}
	}
	return 0;
}

static struct rist_ctx_wrap *configure_rist_output_context(char* outputurl,
	struct rist_sender_args *peer_args, const struct rist_udp_config *udp_config,
	bool npd, enum rist_profile profile)
{
	struct rist_ctx *sender_ctx;
	// Setup the output rist objects (a brand new instance per receiver)
	char *saveptroutput;
	char *tmpoutputurl = malloc(strlen(outputurl) +1);
	strcpy(tmpoutputurl, outputurl);
	char *outputtoken = strtok_r(tmpoutputurl, ",", &saveptroutput);

	// All output peers should be on the same context per receiver
	if (rist_sender_create(&sender_ctx, peer_args->profile, 0, &logging_settings) != 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not create rist sender context\n");
		goto fail;
	}
	struct rist_ctx_wrap *w = malloc(sizeof(*w));
	w->ctx = sender_ctx;
	w->id = prometheus_id++;
	w->sender = true;
	if (npd) {
		if (profile == RIST_PROFILE_SIMPLE)
			rist_log(&logging_settings, RIST_LOG_INFO, "NULL packet deletion enabled on SIMPLE profile. This is non-compliant but might work if receiver supports it (librist does)\n");
		else
			rist_log(&logging_settings, RIST_LOG_INFO, "NULL packet deletion enabled. Support for this feature is not guaranteed to be present on receivers. Please make sure the receiver supports it (librist does)\n");
		if (rist_sender_npd_enable(sender_ctx) != 0) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Failed to enable null packet deletion\n");
		}
	}
	for (size_t j = 0; j < MAX_OUTPUT_COUNT; j++) {
		peer_args->token = outputtoken;
		peer_args->stream_id = udp_config->stream_id;
		struct rist_peer *peer = setup_rist_peer(w, peer_args);
		if (peer == NULL)
			goto fail;
		outputtoken = strtok_r(NULL, ",", &saveptroutput);
		if (!outputtoken)
			break;
	}
	free(tmpoutputurl);

	return w;
fail:
	return  NULL;
}

int main(int argc, char *argv[])
{
	int c;
	int option_index;
	struct rist_callback_object callback_object[MAX_INPUT_COUNT] = { {0} };
	struct evsocket_event *event[MAX_INPUT_COUNT];
	char *inputurl = NULL;
	char *outputurl = NULL;
#ifdef USE_TUN
	struct rist_callback_tun_object callback_tun_object = {0};
	callback_tun_object.tun_mode = 1;
	char *oobtun = NULL;
#endif
	char *shared_secret = NULL;
	int buffer_size = 0;
	int encryption_type = 0;
	int statsinterval = 1000;
	enum rist_profile profile = RIST_PROFILE_MAIN;
	enum rist_log_level loglevel = RIST_LOG_INFO;
	bool npd = false;
	int faststart = 0;
	struct rist_sender_args peer_args;
	char *remote_log_address = NULL;
	bool thread_started[MAX_INPUT_COUNT +1] = {false};
#ifdef USE_TUN
	pthread_t thread_main_loop[MAX_INPUT_COUNT+2] = { 0 };
#else
	pthread_t thread_main_loop[MAX_INPUT_COUNT+1] = { 0 };
#endif

	for (size_t i = 0; i < MAX_INPUT_COUNT; i++)
		event[i] = NULL;

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

	rist_log(&logging_settings, RIST_LOG_INFO, "Starting ristsender version: %s libRIST library: %s API version: %s\n", LIBRIST_VERSION, librist_version(), librist_api_version());

	while ((c = getopt_long(argc, argv, "r:i:o:b:s:e:t:m:p:S:F:f:v:hunM", long_options, &option_index)) != -1) {
		switch (c) {
		case 'i':
			inputurl = strdup(optarg);
		break;
		case 'o':
			outputurl = strdup(optarg);
		break;
		case 'b':
			buffer_size = atoi(optarg);
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
			callback_tun_object.tun_mode = atoi(optarg);
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
		case 'f':
			faststart = atoi(optarg);
			break;
		case 'n':
			npd = true;
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

	if (faststart < 0 || faststart > 1) {
		fprintf(stderr,"Invalid or not implemented fast-start mode %d\n", faststart);
		exit(1);
	}

	if (profile == RIST_PROFILE_SIMPLE || faststart > 0)
		peer_connected_count = 1;

	// Update log settings with custom loglevel and remote address if necessary
	if (rist_logging_set(&log_ptr, loglevel, NULL, NULL, remote_log_address, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging\n");
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
	peer_args.loglevel = loglevel;
	peer_args.profile = profile;
	peer_args.encryption_type = encryption_type;
	peer_args.shared_secret = shared_secret;
	peer_args.buffer_size = buffer_size;
	peer_args.statsinterval = statsinterval;

#ifdef USE_TUN
	// Setup tun device
	if (oobtun) {
		callback_tun_object.tun = oob_setup_tun_device(oobtun);
		if (callback_tun_object.tun == -1)
			rist_log(&logging_settings, RIST_LOG_ERROR, "tun open error: %s\n", strerror(errno));
		else if (callback_tun_object.tun < 0)
			rist_log(&logging_settings, RIST_LOG_ERROR, "tun ioctl error: %s (%d)\n", strerror(errno), callback_tun_object.tun);
		if (callback_tun_object.tun < 0)
			exit(1);
	}
#endif

	bool rist_listens = false;
	if (strstr(outputurl, "://@") != NULL) {
		rist_listens = true;
	}

	// Setup the input udp/rist objects: listen to the given address(es)
	int32_t stream_id_check[MAX_INPUT_COUNT ];
	for (size_t j = 0; j < MAX_INPUT_COUNT; j++)
		stream_id_check[j] = -1;
	struct evsocket_ctx *evctx = NULL;
	bool atleast_one_socket_opened = false;
	char *saveptrinput;
	char *inputtoken = strtok_r(inputurl, ",", &saveptrinput);
	struct rist_udp_config *udp_config = NULL;
	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		if (!inputtoken)
			break;

		// First parse extra url and parameters
		if (rist_parse_udp_address2(inputtoken, &udp_config)) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse inputurl %s\n", inputtoken);
			goto next;
		}

		// Check for duplicate stream-ids and reject the entire config if we have any dups
		bool found_empty = false;
		for (size_t j = 0; j < MAX_INPUT_COUNT; j++) {
			if (stream_id_check[j] == -1 && !found_empty) {
				stream_id_check[j] = (int32_t)udp_config->stream_id;
				rist_log(&logging_settings, RIST_LOG_INFO, "Assigning stream-id %d to this input\n", udp_config->stream_id);
				found_empty = true;
			} else if ((uint16_t)stream_id_check[j] == udp_config->stream_id) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Every input must have a unique stream-id (%d) when you multiplex\n", udp_config->stream_id);
				goto shutdown;
			}
		}

#ifdef USE_TUN
		peer_args.callback_tun_object = &callback_tun_object;
#endif

		// Setup the output rist objects
		if (rist_listens && i > 0) {
			if (callback_object[0].udp_config->version == 1 && (callback_object[0].udp_config->multiplex_mode == LIBRIST_MULTIPLEX_MODE_VIRT_DESTINATION_PORT || udp_config->multiplex_mode == LIBRIST_MULTIPLEX_MODE_VIRT_DESTINATION_PORT)) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Multiplexing is not allowed when any peer is in listening mode unless you enable non standard muxing on all inputs\n");
				goto shutdown;
			}
			else {
				// Single context for all inputs, we multiplex on the payload
				callback_object[i].sender_ctx = callback_object[0].sender_ctx;
			}
		}
		else
		{
			// A brand new instance/context per receiver
			callback_object[i].sender_ctx = configure_rist_output_context(outputurl, &peer_args, udp_config, npd, profile);
			if (callback_object[i].sender_ctx == NULL)
				goto shutdown;
		}
#ifdef USE_TUN
		for (size_t j = 0; j < MAX_OUTPUT_COUNT; j++) {
			// Use the first context for OOB tun context
			if (!callback_tun_object.sender_ctx) {
				callback_tun_object.sender_ctx = callback_object[i].sender_ctx->ctx;
			}
		}
#endif

		if (strcmp(udp_config->prefix, "rist") == 0) {
			// This is a rist input (new context for each listener)
			struct rist_ctx_wrap *w = calloc(1, sizeof(*w));
			w->id = prometheus_id++;
			callback_object[i].receiver_ctx = w;
			if (rist_receiver_create(&callback_object[i].receiver_ctx->ctx, peer_args.profile, &logging_settings) != 0) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Could not create rist receiver context\n");
				goto next;
			}
			peer_args.token = inputtoken;
			struct rist_peer *peer = setup_rist_peer(callback_object[i].receiver_ctx, &peer_args);
			if (peer == NULL)
				atleast_one_socket_opened = true;
			rist_udp_config_free2(&udp_config);
			udp_config = NULL;
		}
#ifdef USE_TUN
		else if (strcmp(udp_config->prefix, "tun") == 0) {
			atleast_one_socket_opened = true;
			callback_tun_object.send_rist = true;
		}
#endif
		else {
			if(!evctx)
				evctx = evsocket_create();
			// This is a udp input, i.e. 127.0.0.1:5000
			char hostname[200] = {0};
			int inputlisten;
			uint16_t inputport;
			if (udpsocket_parse_url((void *)udp_config->address, hostname, 200, &inputport, &inputlisten) || !inputport || strlen(hostname) == 0) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse input url %s\n", inputtoken);
				goto next;
			}
			rist_log(&logging_settings, RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %d\n", (char *) hostname, inputport);

			callback_object[i].sd = udpsocket_open_bind(hostname, inputport, udp_config->miface);
			if (callback_object[i].sd < 0) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Could not bind to: Host %s, Port %d, miface %s.\n",
					(char *) hostname, inputport, udp_config->miface);
				goto next;
			} else {
				udpsocket_set_nonblocking(callback_object[i].sd);
				rist_log(&logging_settings, RIST_LOG_INFO, "Input socket is open and bound %s:%d\n", (char *) hostname, inputport);
				atleast_one_socket_opened = true;
			}
			callback_object[i].udp_config = udp_config;
			udp_config = NULL;
			callback_object[i].evctx = evctx;
			event[i] = evsocket_addevent(callback_object[i].evctx, callback_object[i].sd, EVSOCKET_EV_READ, input_udp_recv, input_udp_sockerr,
				(void *)&callback_object[i]);
		}

next:
		inputtoken = strtok_r(NULL, ",", &saveptrinput);
	}

#ifdef USE_TUN
	if (!atleast_one_socket_opened && !callback_tun_object.tun) {
		goto shutdown;
	}
#else
 	if (!atleast_one_socket_opened) {
 		goto shutdown;
 	}
#endif

	if (evctx && pthread_create(&thread_main_loop[0], NULL, input_loop, (void *)callback_object) != 0)
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start udp receiver thread\n");
		goto shutdown;
	}
	thread_started[0] = true;

	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		if (((rist_listens && i == 0) || !rist_listens) &&
			 callback_object[i].sender_ctx && rist_start(callback_object[i].sender_ctx->ctx) == -1) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start rist sender\n");
			goto shutdown;
		}
		if (callback_object[i].receiver_ctx && rist_start(callback_object[i].receiver_ctx->ctx) == -1) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start rist receiver\n");
			goto shutdown;
		}
		if (callback_object[i].receiver_ctx && pthread_create(&thread_main_loop[i+1], NULL, input_loop, (void *)&callback_object[i]) != 0)
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start send rist receiver thread\n");
			goto shutdown;
		} else if (callback_object[i].receiver_ctx) {
			thread_started[i+1] = true;
		}
	}

#ifdef USE_TUN
	if (callback_tun_object.tun && pthread_create(&thread_main_loop[MAX_INPUT_COUNT + 1], NULL, tun_loop, (void *)&callback_tun_object) != 0)
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start tun read thread\n");
		goto shutdown;
	}
#endif

#ifdef _WIN32
		system("pause");
#else
		pause();
#endif

shutdown:
	if (udp_config) {
		rist_udp_config_free2(&udp_config);
	}
	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		// Remove socket events
		if (event[i])
			evsocket_delevent(callback_object[i].evctx, event[i]);
		// Free udp_config object
		if ((void *)callback_object[i].udp_config)
			rist_udp_config_free2(&callback_object[i].udp_config);
		// Cleanup rist listeners
		if (callback_object[i].receiver_ctx) {
			rist_destroy(callback_object[i].receiver_ctx->ctx);
			free(callback_object[i].receiver_ctx);
		}
		// Cleanup rist sender and their peers
		if (callback_object[i].sender_ctx) {
			rist_destroy(callback_object[i].sender_ctx->ctx);
			free(callback_object[i].sender_ctx);
		}
	}

	for (size_t i = 0; i <= MAX_INPUT_COUNT; i++) {
		if (thread_started[i])
			pthread_join(thread_main_loop[i], NULL);
	}

	rist_logging_unset_global();
	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);
#ifdef USE_TUN
	if (thread_main_loop[MAX_INPUT_COUNT+1])
		pthread_join(thread_main_loop[MAX_INPUT_COUNT+1], NULL);
	if (oobtun)
		free(oobtun);
	if (callback_tun_object.tun)
		close(callback_tun_object.tun);
#endif
	if (shared_secret)
		free(shared_secret);

#if HAVE_PROMETHEUS_SUPPORT
	rist_prometheus_stats_destroy(prom_stats_ctx);
	free(prometheus_ip);
	free(prometheus_tags);
	free(prometheus_unix_sock);
#endif
	return 0;
}
