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
#include <sys/time.h>
#include <signal.h>
#include "network.h"

#define PEER_COUNT 4
#define MPEG_BUFFER_SIZE 10000

static struct option long_options[] = {
{ "url",             required_argument, NULL, 'u' },
{ "miface",          required_argument, NULL, 'f' },
{ "recovery-type",   required_argument, NULL, 'T' },
{ "receiver",          required_argument, NULL, 's' },
{ "receiver2",         required_argument, NULL, 'b' },
{ "receiver3",         required_argument, NULL, 'c' },
{ "receiver4",         required_argument, NULL, 'd' },
{ "weight2",         required_argument, NULL, 'i' },
{ "weight3",         required_argument, NULL, 'j' },
{ "weight4",         required_argument, NULL, 'k' },
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
{ "verbose-level",   required_argument, NULL, 'v' },
{ "help",            no_argument,       NULL, 'h' },
{ "json",            no_argument,       NULL, 'J' },

{ 0, 0, 0, 0 },
};

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -u | --url ADDRESS:PORT              * | Input IP address and port                              |\n"
"       -f | --miface name/index             * | Input Multicast Interface name (linux) or index (win)  |\n"
"       -T | --recovery-type TYPE              | Type of recovery (off, bytes, time)                    |\n"
"       -s | --receiver  rist://ADDRESS:PORT   * | Address of remote rist receiver                          |\n"
"       -b | --receiver2 rist://ADDRESS:PORT     | Address of second remote rist receiver                   |\n"
"       -c | --receiver3 rist://ADDRESS:PORT     | Address of third remote rist receiver                    |\n"
"       -d | --receiver4 rist://ADDRESS:PORT     | Address of fourth remote rist receiver                   |\n"
"          |  The weight of the primary remote rist is always 5 and the other load balancing outputs    |\n"
"          |  are relative to it. Use a value of zero for duplicate output.                             |\n"
"       -i | --weight2 value                   | Load balancing weight of this output                   |\n"
"       -j | --weight3 value                   | Load balancing weight of this output                   |\n"
"       -k | --weight4 value                   | Load balancing weight of this output                   |\n"
"       -m | --min-buf ms                      | Minimum rist recovery buffer size                      |\n"
"       -M | --max-buf ms                      | Maximum rist recovery buffer size                      |\n"
"       -o | --reorder-buf ms                  | Reorder buffer size                                    |\n"
"       -r | --min-rtt RTT                     | Minimum RTT                                            |\n"
"       -R | --max-rtt RTT                     | Maximum RTT                                            |\n"
"       -B | --bloat-mode MODE                 | Buffer bloat mitigation mode (slow, fast, fixed)       |\n"
"       -l | --bloat-limit NACK_COUNT          | Buffer bloat min nack count for random discard         |\n"
"       -L | --bloat-hardlimit NACK_COUNT      | Buffer bloat max nack count for hard limit discard     |\n"
"       -W | --max-bitrate Kbps                | Rist recovery max bitrate (Kbit/s)                     |\n"
"       -e | --encryption-password PWD         | Pre-shared encryption password                         |\n"
"       -t | --encryption-type TYPE            | Encryption type (0 = none, 1 = AES-128, 2 = AES-256)   |\n"
"       -p | --profile number                  | Rist profile (0 = simple, 1 = main)                    |\n"
"       -n | --gre-src-port port               | Reduced profile src port to forward                    |\n"
"       -N | --gre-dst-port port               | Reduced profile dst port to forward                    |\n"
"       -C | --cname identifier                | Manually configured identifier                         |\n"
"       -v | --verbose-level value             | QUIET=-1,INFO=0,ERROR=1,WARN=2,DEBUG=3,SIMULATE=4      |\n"
"       -h | --help                            | Show this help                                         |\n"
"		-J | --json														  | JSON Formatted stats output							|\n"
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
"       --gre-src-port 1971       \\\n"
"       --gre-dst-port 1968       \\\n"
"       --verbose-level 2         \n";

static void usage(char *cmd)
{
	fprintf(stderr, "%s%s", help_str, cmd);
	exit(1);
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_sender *ctx = (struct rist_sender *)arg;
	char message[500];
	int ret = snprintf(message, 500, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	fprintf(stderr,"Peer has been authenticated, sending auth message: %s\n", message);
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
		fprintf(stderr,"Out-of-band data received: %.*s\n", (int)oob_block->payload_len, (char *)oob_block->payload);
	}
	return 0;
}

static int cb_stats(void *arg, struct rist_stats *rist_stats) {
	const char* json = stats_to_json(rist_stats);
	fprintf(stderr, "%s\n", json);
	free(rist_stats);
	return 0;
}

static int signalReceived = 0;
static void intHandler(int signal) {
	fprintf(stderr, "Signal %d received\n", signal);
	signalReceived = signal;
}

int main(int argc, char *argv[])
{
	int rist;
	char c;
	int option_index;
	int mpeg;
	int w, r;
	char *url = NULL;
	char *miface = NULL;
	char *shared_secret = NULL;
	char *cname = NULL;
	char *address[PEER_COUNT];
	int json_out = 0;
	uint32_t weight[PEER_COUNT];
	enum rist_profile profile = RIST_PROFILE_MAIN;
	enum rist_log_level loglevel = RIST_LOG_WARN;
	uint16_t virt_src_port = 1971;
	uint16_t virt_dst_port = RIST_DEFAULT_VIRT_DST_PORT;
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
	struct sigaction act;
	act.sa_handler = intHandler;
	sigaction(SIGINT, &act, NULL);

	for (size_t i = 0; i < PEER_COUNT; i++) {
		address[i] = NULL;
		weight[i] = 0;
	}

	while ((c = getopt_long(argc, argv, "W:v:u:f:T:e:b:c:d:s:i:j:k:m:M:r:o:R:B:l:L:t:p:n:N:C:h:J:", long_options, &option_index)) != -1) {
		switch (c) {
		case 'u':
			url = strdup(optarg);
		break;
		case 'f':
			miface = strdup(optarg);
		break;
		case 'T':
			if (!strcmp(optarg, "off")) {
				recovery_mode = RIST_RECOVERY_MODE_DISABLED;
			} else if (!strcmp(optarg, "bytes")) {
				recovery_mode = RIST_RECOVERY_MODE_BYTES;
			} else if (!strcmp(optarg, "time")) {
				recovery_mode = RIST_RECOVERY_MODE_TIME;
			} else {
				usage(argv[0]);
			}
		break;
		case 's':
			address[0] = strdup(optarg);
		break;
		case 'b':
			address[1] = strdup(optarg);
		break;
		case 'c':
			address[2] = strdup(optarg);
		break;
		case 'd':
			address[3] = strdup(optarg);
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
		case 'e':
			shared_secret = strdup(optarg);
		break;
		case 'i':
			weight[1] = atoi(optarg);
		break;
		case 'j':
			weight[2] = atoi(optarg);
		break;
		case 'k':
			weight[3] = atoi(optarg);
		break;
		case 't':
			encryption_type = atoi(optarg);
		break;
		case 'p':
			profile = atoi(optarg);
		break;
		case 'n':
			virt_src_port = atoi(optarg);
		break;
		case 'N':
			virt_dst_port = atoi(optarg);
		break;
		case 'C':
			cname = strdup(optarg);
		break;
		case 'v':
			loglevel = atoi(optarg);
		break;
		case 'J':
			json_out = 1;
		break;
		case 'h':
			/* Fall through */
		default:
			usage(argv[0]);
		break;
		}
	}

	if (url == NULL) {
		usage(argv[0]);
	}

	if (address[0] == NULL) {
		usage(argv[0]);
	}

	for (size_t i = 1; i < PEER_COUNT; i++) {
		if (weight[i] > 0) {
			weight[0] = 5;
			break;
		}
	}

	/* MPEG Side: listen to the given address */
	struct network_url parsed_url;
	if (parse_url(url, &parsed_url) != 0) {
		fprintf(stderr, "[ERROR] %s / %s\n", parsed_url.error, url);
		exit(1);
	} else {
		fprintf(stderr, "[INFO] URL parsed successfully: Host %s, Port %d\n",
			(char *) parsed_url.hostname, parsed_url.port);
	}

	mpeg = udp_Open(parsed_url.hostname, parsed_url.port, NULL, 0, 0, miface);
	if (mpeg <= 0) {
		char *msgbuf = malloc(256);
		msgbuf = udp_GetErrorDescription(mpeg, msgbuf);
		fprintf(stderr, "[ERROR] Could not connect to: Host %s, Port %d. %s\n",
			(char *) parsed_url.hostname, parsed_url.port, msgbuf);
		free(msgbuf);
		exit(1);
	} else {
		fprintf(stderr, "Input socket is open and bound\n");
	}

	/* rist side */
	fprintf(stderr, "Configured with maxrate=%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d buffer_bloat=%d (limit:%d, hardlimit:%d)\n",
			recovery_maxbitrate, recovery_length_min, recovery_length_max, recovery_reorder_buffer, recovery_rtt_min,
			recovery_rtt_max, buffer_bloat_mode, buffer_bloat_limit, buffer_bloat_hard_limit);

	for (size_t i = 0; i < PEER_COUNT; i++) {
		if (address[i] != NULL) {
			fprintf(stderr, "Connecting to Peer %i: %s\n", (int)(i + 1), address[i]);
		}
	}

	/* Turn on stderr (2) logs */
	if (rist_logs_set(STDERR_FILENO, NULL) != 0) {
		fprintf(stderr, "Could not set logging\n");
		exit(1);
	}

	struct rist_sender *ctx;
	if (rist_sender_create(&ctx, profile, 0, loglevel) != 0) {
		fprintf(stderr, "Could not create rist sender context\n");
		exit(1);
	}

	rist = rist_sender_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, ctx);
	if (rist < 0) {
		fprintf(stderr, "Could not initialize rist auth handler\n");
		exit(1);
	}

	if (json_out) {
		rist_sender_stats_callback_set(ctx, 1000, cb_stats, NULL);
	}

	if (profile != RIST_PROFILE_SIMPLE) {
		if (rist_sender_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
			fprintf(stderr, "Could not add enable out-of-band data\n");
			exit(1);
		}
	}

	for (size_t i = 0; i < PEER_COUNT; i++) {
		if (address[i] == NULL) {
			continue;
		}

		// Applications defaults and/or command line options
		int keysize =  encryption_type * 128;
		const struct rist_peer_config app_peer_config = {
			.version = RIST_PEER_CONFIG_VERSION,
			.virt_dst_port = virt_dst_port,
			.recovery_mode = recovery_mode,
			.recovery_maxbitrate = recovery_maxbitrate,
			.recovery_maxbitrate_return = recovery_maxbitrate_return,
			.recovery_length_min = recovery_length_min,
			.recovery_length_max = recovery_length_max,
			.recovery_reorder_buffer = recovery_reorder_buffer,
			.recovery_rtt_min = recovery_rtt_min,
			.recovery_rtt_max = recovery_rtt_max,
			.weight = weight[i],
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
		if (rist_parse_address(address[i], &peer_config))
		{
			fprintf(stderr, "Could not parse peer options for sender #%d\n", (int)(i + 1));
			exit(1);
		}

		struct rist_peer *peer;
		if (rist_sender_peer_create(ctx, &peer, peer_config) == -1) {
			fprintf(stderr, "Could not add peer connector to sender #%d\n", (int)(i + 1));
			exit(1);
		}
	}

	/* Setting rist timeouts (in ms)*/
	//rist_sender_set_retry_timeout(ctx, 10000);
	//rist_sender_keepalive_timeout_set(ctx, 5000);

	if (rist_sender_start(ctx) == -1) {
		fprintf(stderr, "Could not start rist sender\n");
		exit(1);
	}

	uint8_t buffer[MPEG_BUFFER_SIZE];
	while (!signalReceived) {
		r = recv(mpeg, buffer, MPEG_BUFFER_SIZE, 0);
		if (r > 0) {
			struct rist_data_block data_block;
			data_block.payload = buffer;
			data_block.payload_len = r;
			data_block.virt_src_port = virt_src_port;
			data_block.ts_ntp = 0; // delegate this to the library in this case
			w = rist_sender_data_write(ctx, &data_block);
			(void) w;
		}
	}

	rist_sender_destroy(ctx);

	if (shared_secret)
		free(shared_secret);
	if (cname)
		free(cname);

	return 0;
}
