/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <librist/librist.h>
#include <librist/udpsocket.h>
#include <stdint.h>
#include "librist/version.h"
#include "config.h"
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
#include "yamlparse.h"

#if defined(_WIN32) || defined(_WIN64)
#define strtok_r strtok_s
#define MSG_DONTWAIT (0)
#endif

#define RIST_MARK_UNUSED(unused_param) ((void)(unused_param))

#define UDP2UDP_VERSION "1"

#define MAX_OUTPUT_COUNT 20

static int signalReceived = 0;
static struct rist_logging_settings logging_settings = LOGGING_SETTINGS_INITIALIZER;

uint64_t prometheus_id = 0;

struct rist_callback_object {
	int sd;
	struct evsocket_ctx *evctx;
	struct rist_udp_config *udp_config;
	uint8_t recv[RIST_MAX_PACKET_SIZE + 100];
	int out_sd[MAX_OUTPUT_COUNT];
	struct rist_udp_config *output_udp_config[MAX_OUTPUT_COUNT];
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
{ "verbose-level",   required_argument, NULL, 'v' },
{ "remote-logging",  required_argument, NULL, 'r' },
{ "config",          required_argument, NULL, 'c' },
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
"       -i | --inputurl  udp://...              * | Input udp URL                                            |\n"
"       -o | --outputurl udp://...              * | Comma separated list of output udp URLs                  |\n"
"       -v | --verbose-level value                | To disable logging: -1, log levels match syslog levels   |\n"
"       -r | --remote-logging IP:PORT             | Send logs and stats to this IP:PORT using udp messages   |\n"
"       -c | --config name.yaml                   | YAML config file                                         |\n"
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
"       --verbose-level 6         \n";

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
	socklen_t addrlen = 0;
	RIST_MARK_UNUSED(addr);

	uint16_t address_family = (uint16_t)callback_object->udp_config->address_family;
	if (address_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		recv_bufsize = udpsocket_recvfrom(callback_object->sd, recv_buf, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *) &addr6, &addrlen);
		addr = (struct sockaddr *) &addr6;
	} else {
		addrlen = sizeof(struct sockaddr_in);
		recv_bufsize = udpsocket_recvfrom(callback_object->sd, recv_buf, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *) &addr4, &addrlen);
		addr = (struct sockaddr *) &addr4;
	}

	if (recv_bufsize > 0) {
		int i = 0;
		for (i = 0; i < MAX_OUTPUT_COUNT; i++) {
			if (!callback_object->output_udp_config[i])
				continue;
			struct rist_udp_config *udp_config = callback_object->output_udp_config[i];
			RIST_MARK_UNUSED(udp_config);
			if (callback_object->out_sd[i] > 0) {
				int ret = udpsocket_send_nonblocking(callback_object->out_sd[i], recv_buf, recv_bufsize);
				if (ret <= 0 && errno != ECONNREFUSED)
					rist_log(&logging_settings, RIST_LOG_ERROR, "Error %d sending udp packet to socket %d\n", errno, callback_object->out_sd[i]);
			}
		}
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
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n%s version %s libRIST library: %s API version: %s\n", cmd, help_str, UDP2UDP_VERSION, librist_version(), librist_api_version());
	exit(1);
}

static void intHandler(int signal)
{
	rist_log(&logging_settings, RIST_LOG_INFO, "Signal %d received\n", signal);
	signalReceived = signal;
}

static PTHREAD_START_FUNC(input_loop, arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	// This is my main loop
	while (!signalReceived) {		
		// UDP receiver. Infinite wait, 100 socket events
		evsocket_loop_single(callback_object->evctx, 5, 100);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int c;
	int option_index;
	struct rist_callback_object callback_object = { 0 };
	struct evsocket_event *event;
	char *inputurl = NULL;
	char *outputurl = NULL;
	enum rist_log_level loglevel = RIST_LOG_INFO;
	char *remote_log_address = NULL;
	bool thread_started = {false};
	pthread_t thread_main_loop = { 0 };
	rist_tools_config_object *yaml_config = NULL;
	char *yamlfile = NULL;
	unsigned i = 0;

	event = NULL;

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

	rist_log(&logging_settings, RIST_LOG_INFO, "Starting udp2udp version: %s libRIST library: %s API version: %s\n", UDP2UDP_VERSION, librist_version(), librist_api_version());

	while ((c = getopt_long(argc, argv, "r:i:o:c:v:hunM", long_options, &option_index)) != -1) {
		switch (c) {
		case 'i':
			inputurl = strdup(optarg);
		break;
		case 'o':
			outputurl = strdup(optarg);
		break;
		case 'v':
			loglevel = atoi(optarg);
		break;
		case 'r':
			remote_log_address = strdup(optarg);
		break;
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
			loglevel = yaml_config->verbose_level;
			if (yaml_config->remote_log_address)
				remote_log_address = strdup(yaml_config->remote_log_address);
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

	for (i = 0; i < MAX_OUTPUT_COUNT; i++)
	{
		callback_object.out_sd[i] = 0;
		callback_object.output_udp_config[i] = NULL;
	}

	struct evsocket_ctx *evctx = NULL;
	bool atleast_one_socket_opened = false;
	struct rist_udp_config *udp_config = NULL;

	// Setup udp input
	if(!evctx)
		evctx = evsocket_create();
	char hostname[200] = {0};
	int inputlisten;
	uint16_t inputport;
	// First parse extra parameters (?miface=lo) and separate the address
	// We are using the rist_parse_address function to create a config object that does not really
	// belong to the udp output. We do this only to avoid writing another parser for the two url
	// parameters available to the udp input/output url
	if (rist_parse_udp_address2(inputurl, &udp_config)) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse inputurl %s\n", inputurl);
		goto next;
	}
	// Now parse host and port
	if (udpsocket_parse_url((void *)udp_config->address, hostname, 200, &inputport, &inputlisten) || !inputport || strlen(hostname) == 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse input url %s\n", inputurl);
		goto next;
	}
	rist_log(&logging_settings, RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %d\n", (char *) hostname, inputport);
	// Open and/or bind ip and port
	callback_object.sd = udpsocket_open_bind(hostname, inputport, udp_config->miface);
	if (callback_object.sd < 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not bind to: Host %s, Port %d, miface %s.\n",
			(char *) hostname, inputport, udp_config->miface);
		goto next;
	} else {
		udpsocket_set_nonblocking(callback_object.sd);
		rist_log(&logging_settings, RIST_LOG_INFO, "Input socket is open and bound %s:%d\n", (char *) hostname, inputport);
		atleast_one_socket_opened = true;
	}
	// Increase default OS udp receive buffer size
	if (udpsocket_set_optimal_buffer_size(callback_object.sd)) {
		rist_log(&logging_settings, RIST_LOG_WARN, "Unable to set the socket receive buffer size to %d Bytes. %s\n",
			UDPSOCKET_SOCK_BUFSIZE, strerror(errno));
	} else {
		uint32_t current_recvbuf = udpsocket_get_buffer_size(callback_object.sd);
		rist_log(&logging_settings, RIST_LOG_INFO, "Configured the starting socket receive buffer size to %d Bytes.\n",
			current_recvbuf);
	}
	callback_object.udp_config = udp_config;
	udp_config = NULL;
	callback_object.evctx = evctx;
	event = evsocket_addevent(callback_object.evctx, callback_object.sd, EVSOCKET_EV_READ, input_udp_recv, input_udp_sockerr,
		(void *)&callback_object);

	if (!atleast_one_socket_opened)
	{
		rist_log(&logging_settings, RIST_LOG_INFO, "Input socket could not be oppened\n");
		goto shutdown;
	}

	/* Setup udp output */
	atleast_one_socket_opened = false;
	char *saveptr2;
	char *outputtoken = strtok_r(outputurl, ",", &saveptr2);
	for (i = 0; i < MAX_OUTPUT_COUNT; i++) {

		if (!outputtoken)
			break;
		// First parse extra parameters
		struct rist_udp_config *output_udp_config = NULL;
		if (rist_parse_udp_address2(outputtoken, &output_udp_config)) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse outputurl %s\n", outputtoken);
			goto next;
		}
		// Now parse the host and port
		memset(&hostname, 0, sizeof(hostname));

		int outputlisten;
		uint16_t outputport;
		if (udpsocket_parse_url((void *)output_udp_config->address, hostname, 200, &outputport, &outputlisten) || !outputport || strlen(hostname) == 0) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse output url %s\n", outputtoken);
			goto next;
		}
		rist_log(&logging_settings, RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %d\n", (char *) hostname, outputport);

		// Open the output socket
		callback_object.out_sd[i] = udpsocket_open_connect(hostname, outputport, output_udp_config->miface);
		if (callback_object.out_sd[i] < 0) {
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not connect to: Host %s, Port %d\n", (char *) hostname, outputport);
			goto next;
		} else {
			rist_log(&logging_settings, RIST_LOG_INFO, "Output socket is open and bound %s:%d\n", (char *) hostname, outputport);
			atleast_one_socket_opened = true;
		}
		// Increase default OS udp send buffer size
		if (udpsocket_set_optimal_buffer_send_size(callback_object.out_sd[i])) {
			rist_log(&logging_settings, RIST_LOG_WARN, "Unable to set the socket send buffer size to %d Bytes. %s\n",
				UDPSOCKET_SOCK_BUFSIZE, strerror(errno));
		} else {
			uint32_t current_sendbuf = udpsocket_get_buffer_send_size(callback_object.out_sd[i]);
			rist_log(&logging_settings, RIST_LOG_INFO, "Configured the starting socket send buffer size to %d Bytes.\n",
				current_sendbuf);
		}
		callback_object.output_udp_config[i] = output_udp_config;

next:
		outputtoken = strtok_r(NULL, ",", &saveptr2);
	}

	if (!atleast_one_socket_opened) {
		rist_log(&logging_settings, RIST_LOG_INFO, "Output sockets could not be oppened\n");
		goto shutdown;
	}

	// Now start main listener thread
	if (evctx && pthread_create(&thread_main_loop, NULL, input_loop, (void *)&callback_object) != 0)
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start udp receiver thread\n");
		goto shutdown;
	}
	thread_started = true;

#ifdef _WIN32
		system("pause");
#else
		pause();
#endif

shutdown:
	// Cleanup for input
	if (udp_config) {
		rist_udp_config_free2(&udp_config);
	}
	// Remove input socket event
	if (event)
		evsocket_delevent(callback_object.evctx, event);
	// Free udp_config object
	if ((void *)callback_object.udp_config)
		rist_udp_config_free2(&callback_object.udp_config);

	// Cleanup for output
	for (i = 0; i < MAX_OUTPUT_COUNT; i++) {
		// Free output_udp_config object
		if ((void *)callback_object.output_udp_config[i])
			rist_udp_config_free2(&callback_object.output_udp_config[i]);
	}

	// Wait for main input thread
	if (thread_started)
		pthread_join(thread_main_loop, NULL);

	rist_logging_unset_global();
	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);

#if HAVE_PROMETHEUS_SUPPORT
	rist_prometheus_stats_destroy(prom_stats_ctx);
	free(prometheus_ip);
	free(prometheus_tags);
	free(prometheus_unix_sock);
#endif
	return 0;
}
