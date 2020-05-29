/* librist. Copyright 2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include <librist/librist.h>
#include <librist/udpsocket.h>
#include "version.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "getopt-shim.h"
#include <stdbool.h>
#include <signal.h>

#if defined(_WIN32) || defined(_WIN64)
# define strtok_r strtok_s
#endif

#define RIST_MARK_UNUSED(unused_param) ((void)(unused_param))

#define RISTSENDER_VERSION "2"

#define MAX_INPUT_COUNT 10
#define MAX_OUTPUT_COUNT 10
#define RIST_MAX_PACKET_SIZE 10000

static int signalReceived = 0;
static struct rist_logging_settings *logging_settings;

struct rist_callback_object {
	int sd;
	struct rist_sender *ctx;
	uint16_t virt_src_port;
	uint16_t virt_dst_port;
	uint16_t address_family;
	uint8_t recv[RIST_MAX_PACKET_SIZE];
};

static struct option long_options[] = {
{ "inputurl",        required_argument, NULL, 'i' },
{ "outputurl",       required_argument, NULL, 'o' },
{ "buffer",          required_argument, NULL, 'b' },
{ "secret",          required_argument, NULL, 's' },
{ "encryption-type", required_argument, NULL, 'e' },
{ "profile",         required_argument, NULL, 'p' },
{ "tun",             required_argument, NULL, 't' },
{ "stats",           required_argument, NULL, 'S' },
{ "verbose-level",   required_argument, NULL, 'v' },
{ "help",            no_argument,       NULL, 'h' },
{ 0, 0, 0, 0 },
};

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -i | --inputurl  udp://...            * | Comma separated list of input udp URLs                   |\n"
"       -o | --outputurl rist://...           * | Comma separated list of output rist URLs                 |\n"
"       -b | --buffer value                     | Default buffer size for packet retransmissions           |\n"
"       -s | --secret PWD                       | Default pre-shared encryption secret                     |\n"
"       -e | --encryption-type TYPE             | Default Encryption type (0, 128 = AES-128, 256 = AES-256)|\n"
"       -p | --profile number                   | Rist profile (0 = simple, 1 = main, 2 = advanced)        |\n"
"       -t | --tun IfName                       | TUN interface name for oob data input                    |\n"
"       -S | --statsinterval value (ms)         | Interval at which stats get printed, 0 to disable        |\n"
"       -v | --verbose-level value              | To disable logging: -1, log levels match syslog levels   |\n"
"       -h | --help                             | Show this help                                           |\n"
"   * == mandatory value \n"
"Default values: %s \n"
"       --profile 1               \\\n"
"       --stats 1000              \\\n"
"       --verbose-level 6         \n";

static void input_udp_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(revents);
	RIST_MARK_UNUSED(fd);

	int recv_bufsize = -1;
	struct sockaddr_in addr4 = {0};
	struct sockaddr_in6 addr6 = {0};
	//struct sockaddr *addr;
	uint8_t *recv_buf = callback_object->recv;

	if (callback_object->address_family == AF_INET6) {
		socklen_t addrlen = sizeof(struct sockaddr_in6);
		recv_bufsize = recvfrom(callback_object->sd, recv_buf, RIST_MAX_PACKET_SIZE, 0, (struct sockaddr *) &addr6, &addrlen);
		//addr = (struct sockaddr *) &addr6;
	} else {
		socklen_t addrlen = sizeof(struct sockaddr_in);
		recv_bufsize = recvfrom(callback_object->sd, recv_buf, RIST_MAX_PACKET_SIZE, 0, (struct sockaddr *) &addr4, &addrlen);
		//addr = (struct sockaddr *) &addr4;
	}

	if (recv_bufsize > 0) {
		struct rist_data_block data_block;
		data_block.payload = recv_buf;
		data_block.payload_len = recv_bufsize;
		data_block.virt_src_port = callback_object->virt_src_port;
		data_block.virt_dst_port = callback_object->virt_dst_port;
		data_block.ts_ntp = 0; // delegate this to the library in this case
		data_block.flags = 0;
		int w = rist_sender_data_write(callback_object->ctx, &data_block);
		// TODO: report error?
		(void) w;
	}
}

static void input_udp_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	struct rist_callback_object *callback_object = (void *) arg;
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(revents);
	RIST_MARK_UNUSED(fd);
	rist_log(logging_settings, RIST_LOG_ERROR, "Socket error on sd=%d, source-port=%d !\n", callback_object->sd, callback_object->virt_src_port);
}

static void usage(char *cmd)
{
	fprintf(stderr, "%s%s version %d.%d.%d.%s\n", help_str, cmd, LIBRIST_API_VERSION_MAJOR,
			LIBRIST_API_VERSION_MINOR, LIBRIST_API_VERSION_PATCH, RISTSENDER_VERSION);
	exit(1);
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_sender *ctx = (struct rist_sender *)arg;
	char message[500];
	int ret = snprintf(message, 500, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	rist_log(logging_settings, RIST_LOG_INFO,"Peer has been authenticated, sending auth message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = message;
	oob_block.payload_len = ret;
	rist_sender_oob_write(ctx, &oob_block);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	struct rist_sender *ctx = (struct rist_sender *)arg;
	(void)ctx;
	return 0;
}

static int cb_recv_oob(void *arg, const struct rist_oob_block *oob_block)
{
	struct rist_sender *ctx = (struct rist_sender *)arg;
	(void)ctx;
	if (oob_block->payload_len > 4 && strncmp(oob_block->payload, "auth,", 5) == 0) {
		rist_log(logging_settings, RIST_LOG_INFO,"Out-of-band data received: %.*s\n", (int)oob_block->payload_len, (char *)oob_block->payload);
	}
	return 0;
}

static int cb_stats(void *arg, const char *rist_stats) {
	rist_log(logging_settings, RIST_LOG_INFO, "%s\n\n", rist_stats);
	free((void*)rist_stats);
	return 0;
}

static void intHandler(int signal) {
	rist_log(logging_settings, RIST_LOG_INFO, "Signal %d received\n", signal);
	signalReceived = signal;
}

int main(int argc, char *argv[])
{
	int rist;
	char c;
	int option_index;
	struct rist_callback_object callback_object[MAX_INPUT_COUNT];
	struct evsocket_event *event[MAX_INPUT_COUNT];
	char *inputurl = NULL;
	char *outputurl = NULL;
	char *oobtun = NULL;
	char *shared_secret = NULL;
	int buffer = 0;
	int encryption_type = 0;
	struct rist_sender *ctx;
	int statsinterval = 1000;
	enum rist_profile profile = RIST_PROFILE_MAIN;
	enum rist_log_level loglevel = RIST_LOG_INFO;

	for (size_t i = 0; i < MAX_INPUT_COUNT; i++)
		event[i] = NULL;

#ifdef _WIN32
#define STDERR_FILENO 2
    signal(SIGINT, intHandler);
    signal(SIGTERM, intHandler);
    signal(SIGABRT, intHandler);
#else
	struct sigaction act = {0};
	act.sa_handler = intHandler;
	sigaction(SIGINT, &act, NULL);
#endif

	if (rist_logging_set(&logging_settings, loglevel, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging!\n");
		exit(1);
	}

	rist_log(logging_settings, RIST_LOG_INFO, "Starting ristsender version: %d.%d.%d.%s\n", LIBRIST_API_VERSION_MAJOR,
			LIBRIST_API_VERSION_MINOR, LIBRIST_API_VERSION_PATCH, RISTSENDER_VERSION);

	while ((c = getopt_long(argc, argv, "i:o:b:s:e:t:p:S:v:h", long_options, &option_index)) != -1) {
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
		case 't':
			oobtun = strdup(optarg);
		break;
		case 'p':
			profile = atoi(optarg);
		break;
		case 'S':
			statsinterval = atoi(optarg);
		break;
		case 'v':
			loglevel = atoi(optarg);
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

	if (rist_sender_create(&ctx, profile, 0, logging_settings) != 0) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not create rist sender context\n");
		exit(1);
	}

	/* MPEG Side: listen to the given addresses */
	struct evsocket_ctx *evctx = evsocket_create();
	bool atleast_one_socket_opened = false;
	char *saveptr1;
	char *inputtoken = strtok_r(inputurl, ",", &saveptr1);
	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		if (!inputtoken)
			break;

		// First parse extra parameters (?miface=lo) and separate the address
		const struct rist_peer_config *peer_config_udp = NULL;
		if (rist_parse_address(inputtoken, &peer_config_udp)) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse inputurl %s\n", inputtoken);
			goto next;
		}

		// Now parse the address 127.0.0.1:5000
		char hostname[200] = {0};
		int inputlisten;
		uint16_t inputport;
		if (udpsocket_parse_url((void *)peer_config_udp->address, hostname, 200, &inputport, &inputlisten) || !inputport || strlen(hostname) == 0) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse input url %s\n", inputtoken);
			goto next;
		}
		rist_log(logging_settings, RIST_LOG_INFO, "[INFO] URL parsed successfully: Host %s, Port %d\n", (char *) hostname, inputport);

		callback_object[i].sd = udpsocket_open_bind(hostname, inputport, peer_config_udp->miface);
		if (callback_object[i].sd <= 0) {
			rist_log(logging_settings, RIST_LOG_ERROR, "[ERROR] Could not bind to: Host %s, Port %d, miface %s.\n",
				(char *) hostname, inputport, peer_config_udp->miface);
			goto next;
		} else {
			rist_log(logging_settings, RIST_LOG_INFO, "[INFO] Input socket is open and bound %s:%d\n", (char *) hostname, inputport);
			atleast_one_socket_opened = true;
		}
		callback_object[i].virt_src_port = peer_config_udp->virt_dst_port;
		callback_object[i].virt_dst_port = 0;//why does it asset on non zero; TODO ???
		callback_object[i].ctx = ctx;
		callback_object[i].address_family = peer_config_udp->address_family;

		evsocket_addevent(evctx, callback_object[i].sd, EVSOCKET_EV_READ, input_udp_recv, input_udp_sockerr, 
			(void *)&callback_object[i]);

next:
		free((void *)peer_config_udp);
		inputtoken = strtok_r(NULL, ",", &saveptr1);
	}

	if (!atleast_one_socket_opened) {
		exit(1);
	}

	rist = rist_sender_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, ctx);
	if (rist < 0) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not initialize rist auth handler\n");
		exit(1);
	}

	if (profile != RIST_PROFILE_SIMPLE) {
		if (rist_sender_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not enable out-of-band data\n");
			exit(1);
		}
	}

	if (rist_sender_stats_callback_set(ctx, statsinterval, cb_stats, NULL) == -1) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not enable stats callback\n");
		exit(1);
	}

	char *saveptr2;
	char *outputtoken = strtok_r(outputurl, ",", &saveptr2);
	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++) {

		// Rely on the library to parse the url
		const struct rist_peer_config *peer_config_link = NULL;
		if (rist_parse_address(outputtoken, (void *)&peer_config_link))
		{
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse peer options for sender #%d\n", (int)(i + 1));
			exit(1);
		}

		/* Process overrides */
		struct rist_peer_config *overrides_peer_config = (void *)peer_config_link;
		if (shared_secret && peer_config_link->secret[0] == 0) {
			strncpy(overrides_peer_config->secret, shared_secret, RIST_MAX_STRING_SHORT);
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
		rist_log(logging_settings, RIST_LOG_INFO, "Link configured with maxrate=%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d buffer_bloat=%d (limit:%d, hardlimit:%d)\n",
			peer_config_link->recovery_maxbitrate, peer_config_link->recovery_length_min, peer_config_link->recovery_length_max, 
			peer_config_link->recovery_reorder_buffer, peer_config_link->recovery_rtt_min, peer_config_link->recovery_rtt_max,
			peer_config_link->buffer_bloat_mode, peer_config_link->buffer_bloat_limit, peer_config_link->buffer_bloat_hard_limit);

		struct rist_peer *peer;
		if (rist_sender_peer_create(ctx, &peer, peer_config_link) == -1) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not add peer connector to sender #%i\n", (int)(i + 1));
			exit(1);
		}

		free((void *)peer_config_link);
		outputtoken = strtok_r(NULL, ",", &saveptr2);
		if (!outputtoken)
			break;
	}

	if (rist_sender_start(ctx) == -1) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not start rist sender\n");
		exit(1);
	}

	while (!signalReceived) {
		// This is my main loop (Infinite wait)
		evsocket_loop_single(evctx, -1);
	}

	// Remove socket events
	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		if (event[i])
			evsocket_delevent(evctx, event[i]);
	}

	// Shut down sockets and rist contexts
	evsocket_destroy(evctx);
	rist_sender_destroy(ctx);

	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);
	if (oobtun)
		free(oobtun);
	if (shared_secret)
		free(shared_secret);
	free(logging_settings);

	return 0;
}
