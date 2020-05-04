/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include <librist.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdbool.h>
#include <signal.h>
#include "network.h"

#define INPUT_COUNT 2
#define OUTPUT_COUNT 4

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -u | --url ADDRESS:PORT                                         * | Output IP address and port                          |\n"
"       -f | --miface name/index                                        * | Multicast Interface name (linux) or index (win)     |\n"
"       -T | --recovery-type TYPE                                       * | Type of recovery (off, bytes, time)                 |\n"
"       -x | --url2 ADDRESS:PORT                                        * | Second Output IP address and port                   |\n"
"       -q | --miface2 name/index                                       * | Multicast Interface2 name (linux) or index (win)    |\n"
"       -s | --receiver  rist://@ADDRESS:PORT or rist6://@ADDRESS:PORT  * | Address of local rist receiver                      |\n"
"       -b | --receiver2 rist://@ADDRESS:PORT or rist6://@ADDRESS:PORT    | Address of second local rist receiver               |\n"
"       -c | --receiver3 rist://@ADDRESS:PORT or rist6://@ADDRESS:PORT    | Address of third local rist receiver                |\n"
"       -d | --receiver4 rist://@ADDRESS:PORT or rist6://@ADDRESS:PORT    | Address of fourth local rist receiver               |\n"
"       -S | --statsinterval value (ms)                                   | Interval at which stats get printed, 0 to disable      |\n"
"       -e | --encryption-password PWD                                    | Pre-shared encryption password                      |\n"
"       -t | --encryption-type TYPE                                       | Encryption type (1 = AES-128, 2 = AES-256)          |\n"
"       -p | --profile number                                             | Rist profile (0 = simple, 1 = main)                 |\n"
"       -n | --gre-src-port port                                          | Reduced profile src port to filter (0 = no filter)  |\n"
"       -N | --gre-dst-port port                                          | Reduced profile dst port to filter (0 = no filter)  |\n"
"       -C | --cname identifier                                           | Manually configured identifier                      |\n"
"       -v | --verbose-level value                                        | QUIET=-1,INFO=0,ERROR=1,WARN=2,DEBUG=3,SIMULATE=4   |\n"
"       -h | --help                                                       | Show this help                                      |\n"
"       -m | --min-buf ms                                               * | Minimum rist recovery buffer size                   |\n"
"       -M | --max-buf ms                                               * | Maximum rist recovery buffer size                   |\n"
"       -o | --reorder-buf ms                                           * | Reorder buffer size                                 |\n"
"       -r | --min-rtt RTT                                              * | Minimum RTT                                         |\n"
"       -R | --max-rtt RTT                                              * | Maximum RTT                                         |\n"
"       -B | --bloat-mode MODE                                          * | Buffer bloat mitigation mode (slow, fast, fixed)    |\n"
"       -l | --bloat-limit NACK_COUNT                                   * | Buffer bloat min nack count for random discard      |\n"
"       -L | --bloat-hardlimit NACK_COUNT                               * | Buffer bloat max nack count for hard limit discard  |\n"
"       -W | --max-bitrate Kbps                                         * | rist recovery max bitrate (Kbit/s)                  |\n"
"   * == mandatory value \n"
"Default values: %s \n"
"       --recovery-type time      \\\n"
"       --min-buf 1000            \\\n"
"       --max-buf 1000            \\\n"
"       --reorder-buf 25          \\\n"
"       --min-rtt 50              \\\n"
"       --max-rtt 500             \\\n"
"       --max-bitrate 100000      \\\n"
"       --encryption-type 0       \\\n"
"       --profile 1               \\\n"
"       --gre-src-port 0          \\\n"
"       --gre-dst-port 0          \\\n"
"       --json 1                  \\\n"
"       --verbose-level 2         \n";

static struct option long_options[] = {
	{ "url",             required_argument, NULL, 'u' },
	{ "miface",          required_argument, NULL, 'f' },
	{ "url2",            required_argument, NULL, 'x' },
	{ "miface2",         required_argument, NULL, 'q' },
	{ "receiver",          required_argument, NULL, 's' },
	{ "receiver2",         required_argument, NULL, 'b' },
	{ "receiver3",         required_argument, NULL, 'c' },
	{ "receiver4",         required_argument, NULL, 'd' },
	{ "recovery-type",   required_argument, NULL, 'T' },
	{ "min-buf",         required_argument, NULL, 'm' },
	{ "max-buf",         required_argument, NULL, 'M' },
	{ "reorder-buf",     required_argument, NULL, 'o' },
	{ "min-rtt",         required_argument, NULL, 'r' },
	{ "max-rtt",         required_argument, NULL, 'R' },
	{ "bloat-mode",      required_argument, NULL, 'B' },
	{ "bloat-limit",     required_argument, NULL, 'l' },
	{ "bloat-hardlimit", required_argument, NULL, 'L' },
	{ "max-bitrate",     required_argument, NULL, 'W' },
	{ "encryption-password", required_argument, NULL, 'e' },
	{ "encryption-type", required_argument, NULL, 't' },
	{ "profile",         required_argument, NULL, 'p' },
	{ "gre-src-port",    required_argument, NULL, 'n' },
	{ "gre-dst-port",    required_argument, NULL, 'N' },
	{ "cname",           required_argument, NULL, 'C' },
	{ "statsinterval",   required_argument, NULL, 'S' },
	{ "verbose-level",   required_argument, NULL, 'v' },
	{ "help",            no_argument,       NULL, 'h' },
	{ 0, 0, 0, 0 },
};

void usage(char *name)
{
	fprintf(stderr, "%s%s", help_str, name);
	exit(1);
}

static int mpeg[INPUT_COUNT];
static int keep_running = 1;
static struct network_url parsed_url[INPUT_COUNT];

struct rist_port_filter {
	uint16_t virt_src_port;
	uint16_t virt_dst_port;
};

static int cb_recv(void *arg, const struct rist_data_block *b)
{
	struct rist_port_filter *port_filter = (void *) arg;


	printf("rtp_seq =%u\n",b->seq_rtp);
	if (port_filter->virt_src_port && port_filter->virt_src_port != b->virt_src_port) {
		fprintf(stderr, "Source port mismatch %d != %d\n", port_filter->virt_src_port, b->virt_src_port);
		return -1;
	}

	if (port_filter->virt_dst_port && port_filter->virt_dst_port != b->virt_dst_port) {
		fprintf(stderr, "Destination port mismatch %d != %d\n", port_filter->virt_dst_port, b->virt_dst_port);
		return -1;
	}

	for (size_t i = 0; i < OUTPUT_COUNT; i++) {
		if (mpeg[i] > 0) {
			sendto(mpeg[i], b->payload, b->payload_len, 0, (struct sockaddr *)&(parsed_url[i].u),
				sizeof(struct sockaddr_in));
		}
	}

	return 0;
}

static void intHandler(int signal) {
	fprintf(stderr, "Signal %d received\n", signal);
	keep_running = 0;
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_receiver *ctx = (struct rist_receiver *)arg;
	char message[500];
	int ret = snprintf(message, 500, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	fprintf(stderr,"Peer has been authenticated, sending auth message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = message;
	oob_block.payload_len = ret;
	rist_receiver_oob_write(ctx, &oob_block);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	struct rist_receiver *ctx = (struct rist_receiver *)arg;
	(void)ctx;
	return 0;
}

static int cb_recv_oob(void *arg, const struct rist_oob_block *oob_block)
{
	struct rist_receiver *ctx = (struct rist_receiver *)arg;
	(void)ctx;
	if (oob_block->payload_len > 4 && strncmp(oob_block->payload, "auth,", 5) == 0) {
		fprintf(stderr,"Out-of-band data received: %.*s\n", (int)oob_block->payload_len, (char *)oob_block->payload);
	}
	return 0;
}

static int cb_stats(void *arg, struct rist_stats *rist_stats) {
	const char* json = stats_to_json(rist_stats);
	fprintf(stderr, "%s\n\n", json);
	free(rist_stats);
	return 0;
}

int main(int argc, char *argv[])
{
	int option_index;
	char *url[INPUT_COUNT];
	char *miface[INPUT_COUNT];
	char *addr[OUTPUT_COUNT];
	char *shared_secret = NULL;
	char *cname = NULL;
	char c;
	int enable_data_callback = 1;
	int statsinterval = 1000;
	enum rist_profile profile = RIST_PROFILE_MAIN;
	enum rist_log_level loglevel = RIST_LOG_WARN;
	uint8_t encryption_type = 0;
	enum rist_recovery_mode recovery_mode = RIST_DEFAULT_RECOVERY_MODE;
	uint32_t recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE;
	uint32_t recovery_maxbitrate_return = RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN;
	uint32_t recovery_length_min = RIST_DEFAULT_RECOVERY_LENGHT_MIN;
	uint32_t recovery_length_max = RIST_DEFAULT_RECOVERY_LENGHT_MAX;
	uint32_t recovery_reorder_buffer = RIST_DEFAULT_RECOVERY_REORDER_BUFFER;
	uint32_t recovery_rtt_min = RIST_DEFAULT_RECOVERY_RTT_MIN;
	uint32_t recovery_rtt_max = RIST_DEFAULT_RECOVERY_RTT_MAX;
	enum rist_buffer_bloat_mode buffer_bloat_mode = RIST_DEFAULT_BUFFER_BLOAT_MODE;
	uint32_t buffer_bloat_limit = RIST_DEFAULT_BUFFER_BLOAT_LIMIT;
	uint32_t buffer_bloat_hard_limit = RIST_DEFAULT_BUFFER_BLOAT_HARD_LIMIT;
	struct rist_port_filter port_filter;
	port_filter.virt_src_port = 0;
	port_filter.virt_dst_port = 0;
	struct sigaction act;
	act.sa_handler = intHandler;
	sigaction(SIGINT, &act, NULL);

	for (size_t i = 0; i < INPUT_COUNT; i++) {
		url[i] = NULL;
		miface[i] = NULL;
		mpeg[i] = 0;
	}

	for (size_t i = 0; i < OUTPUT_COUNT; i++) {
		addr[i] = NULL;
	}

	while ((c = getopt_long(argc, argv, "u:x:q:v:f:n:e:s:b:c:d:m:M:o:r:R:B:l:L:W:t:p:n:N:C:h:S:", long_options, &option_index)) != -1) {
		switch (c) {
		case 'u':
			url[0] = strdup(optarg);
		break;
		case 'x':
			url[1] = strdup(optarg);
		break;
		case 'f':
			miface[0] = strdup(optarg);
		break;
		case 'q':
			miface[1] = strdup(optarg);
		break;
		case 's':
			addr[0] = strdup(optarg);
		break;
		case 'b':
			addr[1] = strdup(optarg);
		break;
		case 'c':
			addr[2] = strdup(optarg);
		break;
		case 'd':
			addr[3] = strdup(optarg);
		break;
		case 'm':
			recovery_length_min = atoi(optarg);
		break;
		case 'M':
			recovery_length_max = atoi(optarg);
		break;
		case 'o':
			recovery_reorder_buffer = atoi(optarg);
		break;
		case 'r':
			recovery_rtt_min = atoi(optarg);
		break;
		case 'R':
			recovery_rtt_max = atoi(optarg);
		break;
		case 'B':
			if (!strcmp(optarg, "off")) {
				buffer_bloat_mode = RIST_BUFFER_BLOAT_MODE_OFF;
			} else if (!strcmp(optarg, "normal")) {
				buffer_bloat_mode = RIST_BUFFER_BLOAT_MODE_NORMAL;
			} else if (!strcmp(optarg, "aggressive")) {
				buffer_bloat_mode = RIST_BUFFER_BLOAT_MODE_AGGRESSIVE;
			} else {
				usage(argv[0]);
			}
		break;
		case 'l':
			buffer_bloat_limit = atoi(optarg);
		break;
		case 'L':
			buffer_bloat_hard_limit = atoi(optarg);
		break;
		case 'W':
			recovery_maxbitrate = atoi(optarg);
		break;
		case 't':
			encryption_type = atoi(optarg);
		break;
		case 'p':
			profile = atoi(optarg);
		break;
		case 'n':
			port_filter.virt_src_port = atoi(optarg);
		break;
		case 'N':
			port_filter.virt_dst_port = atoi(optarg);
		break;
		case 'C':
			cname = strdup(optarg);
		break;
		case 'e':
			shared_secret = strdup(optarg);
		break;
		case 'v':
			loglevel = atoi(optarg);
		break;
		case 'S':
			statsinterval = atoi(optarg);
		break;
		case 'h':
			/* Fall through */
		default:
			usage(argv[0]);
		break;
		}
	}

	// For some reason under windows the empty len is 1

	bool all_url_null = true;
	for (size_t i = 0; i < INPUT_COUNT; i++) {
		if (url[i] != NULL) {
			all_url_null = false;
			break;
		}
	}

	if (all_url_null) {
		fprintf(stderr, "No address provided\n");
		usage(argv[0]);
	}

	// minimum, first addr need to be provided
	if (addr[0] == NULL) {
		usage(argv[0]);
	}

	if (argc < 3) {
		usage(argv[0]);
	}

	/* rist side */
	fprintf(stderr, "Configured with maxrate=%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d buffer_bloat=%d (limit:%d, hardlimit:%d)\n",
			recovery_maxbitrate, recovery_length_min, recovery_length_max, recovery_reorder_buffer, recovery_rtt_min,
			recovery_rtt_max, buffer_bloat_mode, buffer_bloat_limit, buffer_bloat_hard_limit);

	/* Turn on stderr (2) logs */
	if (rist_logs_set(STDERR_FILENO, NULL) != 0) {
		fprintf(stderr, "Could not set logging\n");
		exit(1);
	}

	struct rist_receiver *ctx;

	if (rist_receiver_create(&ctx, profile, loglevel) != 0) {
		fprintf(stderr, "Could not create rist receiver context\n");
		exit(1);
	}

	if (rist_receiver_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, ctx) == -1) {
		fprintf(stderr, "Could not init rist auth handler\n");
		exit(1);
	}

	if (profile != RIST_PROFILE_SIMPLE) {
		if (rist_receiver_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
			fprintf(stderr, "Could not add enable out-of-band data\n");
			exit(1);
		}
	}
	if (statsinterval) {
		rist_receiver_stats_callback_set(ctx, statsinterval, cb_stats, NULL);
	}

	for (size_t i = 0; i < OUTPUT_COUNT; i++) {
		if (addr[i] == NULL) {
			continue;
		}

		// TODO: make the RIST_DEFAULT_VIRT_DST_PORT configurable 
		// (used for reverse connection gre-dst-port inside main profile)
		// Applications defaults and/or command line options
		int keysize = encryption_type * 128;
		const struct rist_peer_config app_peer_config = {
			.version = RIST_PEER_CONFIG_VERSION,
			.virt_dst_port = RIST_DEFAULT_VIRT_DST_PORT,
			.recovery_mode = recovery_mode,
			.recovery_maxbitrate = recovery_maxbitrate,
			.recovery_maxbitrate_return = recovery_maxbitrate_return,
			.recovery_length_min = recovery_length_min,
			.recovery_length_max = recovery_length_max,
			.recovery_reorder_buffer = recovery_reorder_buffer,
			.recovery_rtt_min = recovery_rtt_min,
			.recovery_rtt_max = recovery_rtt_max,
			.weight = 5,
			.buffer_bloat_mode = buffer_bloat_mode,
			.buffer_bloat_limit = buffer_bloat_limit,
			.buffer_bloat_hard_limit = buffer_bloat_hard_limit,
			.key_size = keysize
		};

		if (shared_secret != NULL) {
			strncpy((void *)&app_peer_config.secret[0], shared_secret, 128);
		}

		if (cname != NULL) {
			strncpy((void *)&app_peer_config.cname[0], cname, 128);
		}

		// URL overrides (also cleans up the URL)
		const struct rist_peer_config *peer_config = &app_peer_config;
		if (rist_parse_address(addr[i], (void *)&peer_config))
		{
			fprintf(stderr, "Could not parse peer options for receiver #%d\n", (int)(i + 1));
			exit(1);
		}

		struct rist_peer *peer;
		if (rist_receiver_peer_create(ctx, &peer, peer_config) == -1) {
			fprintf(stderr, "Could not add peer connector to receiver #%i\n", (int)(i + 1));
			exit(1);
		}
	}

	/* Mpeg side */
	bool atleast_one_socket_opened = false;
	for (size_t i = 0; i < INPUT_COUNT; i++) {
		if (url[i] == NULL) {
			continue;
		}

		// TODO: support ipv6 destinations
		if (parse_url(url[i], &parsed_url[i]) != 0) {
			fprintf(stderr, "[ERROR] %s / %s\n", parsed_url[i].error, url[i]);
			continue;
		} {
			fprintf(stderr, "[INFO] URL parsed successfully: Host %s, Port %d\n",
				(char *) parsed_url[i].hostname, parsed_url[i].port);
		}

		mpeg[i] = udp_Connect_Simple(AF_INET, -1, miface[i]);
		if (mpeg <= 0) {
			char *msgbuf = malloc(256);
			msgbuf = udp_GetErrorDescription(mpeg[i], msgbuf);
			fprintf(stderr, "[ERROR] Could not connect to: Host %s, Port %d. %s\n",
				(char *) parsed_url[i].hostname, parsed_url[i].port, msgbuf);
			free(msgbuf);
			exit(1);
		}

		fprintf(stderr, "Socket %i is open\n", (int)(i + 1));
		atleast_one_socket_opened = true;
	}

	if (!atleast_one_socket_opened) {
		exit(1);
	}

	if (enable_data_callback == 1) {
		if (rist_receiver_data_callback_set(ctx, cb_recv, &port_filter))
		{
			fprintf(stderr, "Could not set data_callback pointer");
			exit(1);
		}
	}

	if (rist_receiver_start(ctx)) {
		fprintf(stderr, "Could not start rist receiver\n");
		exit(1);
	}
	/* Start the rist protocol thread */
	if (enable_data_callback == 1) {
		pause();
	}
	else {
		// Master loop
		while (keep_running)
		{
			const struct rist_data_block *b;
			int ret = rist_receiver_data_read(ctx, &b, 5);
			if (!ret && b && b->payload) cb_recv(&port_filter, b);
		}
	}

	rist_receiver_destroy(ctx);

	if (shared_secret)
		free(shared_secret);
	if (cname)
		free(cname);

	return 0;
}
