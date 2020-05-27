/**
 * rist2rist receive simple profile rist and expose it as main profile
 * author: Gijs Peskens
 */

#include <librist/librist.h>
#include <stdio.h>
#include <string.h>
#include "getopt-shim.h"
#include <assert.h>
#include <signal.h>
#ifdef __unix
#include <unistd.h>
#endif

extern char* stats_to_json(struct rist_stats *stats);

struct rist_sender_args {
	char* cname;
	char* shared_secret;
	char* outputurl;
	uint16_t dst_port;
	enum rist_log_level loglevel;
	uint8_t encryption_type;
	uint32_t flow_id;
	int statsinterval;
};

struct rist_cb_arg {
	uint16_t src_port;
	uint16_t dst_port;
	struct rist_sender *sender_ctx;
	struct rist_sender_args *client_args;
};

static int keep_running = 1;

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -u | --inurl ADDRESS:PORT              * | Input IP address and port                              |\n"
"       -o | --outurl ADDRESS:PORT             * | Output IP address and port                             |\n"
"       -S | --statsinterval value (ms)          | Interval at which stats get printed, 0 to disable      |\n"
"       -e | --encryption-password PWD           | Pre-shared encryption password                         |\n"
"       -t | --encryption-type TYPE              | Encryption type (0 = none, 1 = AES-128, 2 = AES-256)   |\n"
"       -C | --cname identifier                  | Manually configured identifier                         |\n"
"       -v | --verbose-level value               | To disable logging: -1, log levels match syslog levels |\n"
"       -h | --help                              | Show this help                                         |\n"
;

static struct option long_options[] = {
{ "inurl",             required_argument, NULL, 'u' },
{ "outurl",             required_argument, NULL, 'o' },
{ "encryption-password", required_argument, NULL, 'e' },
{ "encryption-type", required_argument, NULL, 't' },
{ "cname",           required_argument, NULL, 'N' },
{ "statsinterval",   required_argument, NULL, 'S' },
{ "verbose-level",   required_argument, NULL, 'l' },
{ "help",            no_argument,       NULL, 'h' },

{ 0, 0, 0, 0 },
};

static void usage(char *cmd)
{
	fprintf(stderr, "%s%s", help_str, cmd);
	exit(1);
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_receiver *receiver_ctx = (struct rist_receiver *)arg;
	char message[500];
	int ret = snprintf(message, 500, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	fprintf(stderr,"Peer has been authenticated, sending auth message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = message;
	oob_block.payload_len = ret;
	rist_receiver_oob_write(receiver_ctx, &oob_block);
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
	free((void*)json);
	return 0;
}

static struct rist_sender* setup_rist_sender(struct rist_sender_args *setup) {
	struct rist_sender *ctx;
	printf("CName: %s\n", setup->cname);
	printf("Outurl: %s\n", setup->outputurl);
	int rist;
	if (rist_sender_create(&ctx, 1, setup->flow_id, setup->loglevel) != 0) {
		fprintf(stderr, "Could not create rist sender context\n");
		exit(1);
	}

	if (rist_sender_logging_set(ctx, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr, "Could not set logging\n");
		exit(1);
	}

	rist = rist_sender_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, ctx);
	if (rist < 0) {
		fprintf(stderr, "Could not initialize rist auth handler\n");
		exit(1);
	}

	if (rist_sender_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
		fprintf(stderr, "Could not add enable out-of-band data\n");
		exit(1);
	}

	if (setup->statsinterval) {
		rist_sender_stats_callback_set(ctx, setup->statsinterval, cb_stats, NULL);
	}

	// Applications defaults and/or command line options
	int keysize =  setup->encryption_type * 128;
	struct rist_peer_config app_peer_config = {
		.version = RIST_PEER_CONFIG_VERSION,
		.virt_dst_port = setup->dst_port+1,
		.recovery_mode = RIST_DEFAULT_RECOVERY_MODE,
		.recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE,
		.recovery_maxbitrate_return = RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN,
		.recovery_length_min = RIST_DEFAULT_RECOVERY_LENGHT_MIN,
		.recovery_length_max = RIST_DEFAULT_RECOVERY_LENGHT_MAX,
		.recovery_reorder_buffer = RIST_DEFAULT_RECOVERY_REORDER_BUFFER,
		.recovery_rtt_min = RIST_DEFAULT_RECOVERY_RTT_MIN,
		.recovery_rtt_max = RIST_DEFAULT_RECOVERY_RTT_MAX,
		.weight = 5,
		.buffer_bloat_mode = RIST_DEFAULT_BUFFER_BLOAT_MODE,
		.buffer_bloat_limit = RIST_DEFAULT_BUFFER_BLOAT_LIMIT,
		.buffer_bloat_hard_limit = RIST_DEFAULT_BUFFER_BLOAT_HARD_LIMIT,
		.key_size = keysize,
	};

	if (setup->shared_secret != NULL) {
		strncpy(app_peer_config.secret, setup->shared_secret, 128);
	}

	if (setup->cname != NULL) {
		strncpy(app_peer_config.cname, setup->cname, 128);
	}

	// URL overrides (also cleans up the URL)
	const struct rist_peer_config *peer_config = &app_peer_config;
	if (rist_parse_address(setup->outputurl, &peer_config))
	{
		fprintf(stderr, "Could not parse peer options for sender\n");
		exit(1);
	}

	struct rist_peer *peer;
	if (rist_sender_peer_create(ctx, &peer, peer_config) == -1) {
		fprintf(stderr, "Could not add peer connector to sender\n");
		exit(1);
	}

	/* Setting rist timeouts (in ms)*/
	//rist_sender_set_retry_timeout(ctx, 10000);
	//rist_sender_keepalive_timeout_set(ctx, 5000);

	if (rist_sender_start(ctx) == -1) {
		fprintf(stderr, "Could not start rist sender\n");
		exit(1);
	}
	return ctx;
}

static int cb_recv(void *arg, const struct rist_data_block *b)
{
	struct rist_cb_arg *cb_arg = (struct rist_cb_arg *) arg;
	struct rist_data_block *block = (struct rist_data_block*)b;
	if (cb_arg->client_args->flow_id != b->flow_id) {
		printf("Flow ID %ud\n",b->flow_id);
		cb_arg->client_args->flow_id = b->flow_id;
		assert(cb_arg->sender_ctx != NULL);
		rist_sender_flow_id_set(cb_arg->sender_ctx, b->flow_id);
	}
	//b->virt_src_port = cb_arg->src_port;
	//b->virt_dst_port = cb_arg->dst_port; 
	block->flags = RIST_DATA_FLAGS_USE_SEQ;//We only need this flag set, this way we don't have to null it beforehand.
	return rist_sender_data_write(cb_arg->sender_ctx, b);

	return 0;
}

static void intHandler(int signal) {
	fprintf(stderr, "Signal %d received\n", signal);
	keep_running = 0;
}

int main (int argc, char **argv) {
	char *inputurl = NULL;
	char *cname = NULL;
	char *outputurl = NULL;
	struct rist_cb_arg cb_arg;
	struct rist_sender_args client_args;
	cb_arg.client_args = &client_args;
	cb_arg.src_port = 1971;
	cb_arg.dst_port = 1968;
	client_args.dst_port = 1968;
	client_args.encryption_type = 0;
	client_args.shared_secret = NULL;
	client_args.flow_id = 0;
	int statsinterval = 1000;
	enum rist_log_level loglevel = RIST_LOG_INFO;
#ifdef _WIN32
#define STDERR_FILENO 2
	signal(SIGINT, intHandler);
	signal(SIGTERM, intHandler);
	signal(SIGABRT, intHandler);
#else
	struct sigaction act;
	act.sa_handler = intHandler;
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
#endif

	int option_index;
	char c;
	while ((c = getopt_long(argc, argv, "u:o:e:C:v:t:S:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'u':
			inputurl = strdup(optarg); 
			break;
		case 'o':
			outputurl = strdup(optarg); 
			break;
		case 'e':
			client_args.shared_secret = strdup(optarg); 
			break;
		case 't':
			client_args.encryption_type = atoi(optarg);
			break;
		case 'N':
			cname = strdup(optarg); 
			break;
		case 'l':
			loglevel = atoi(optarg);
			break;
		case 'S':
			statsinterval = atoi(optarg);
			break;
		case 'h':
			//
		default:
			usage(argv[0]);
			break;
		}
	}
	client_args.cname = cname;
	client_args.loglevel = loglevel;
	client_args.outputurl = outputurl;
	client_args.statsinterval = statsinterval;

	struct rist_receiver *receiver_ctx;

	if (rist_receiver_create(&receiver_ctx, 0, loglevel) != 0) {
		fprintf(stderr, "Could not create rist receiver context\n");
		exit(1);
	}

	if (rist_receiver_auth_handler_set(receiver_ctx, cb_auth_connect, cb_auth_disconnect, receiver_ctx) == -1) {
		fprintf(stderr, "Could not init rist auth handler\n");
		exit(1);
	}

	struct rist_peer_config app_peer_config = {
		.version = RIST_PEER_CONFIG_VERSION,
		.virt_dst_port = RIST_DEFAULT_VIRT_DST_PORT,
		.recovery_mode = RIST_DEFAULT_RECOVERY_MODE,
		.recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE,
		.recovery_maxbitrate_return = RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN,
		.recovery_length_min = RIST_DEFAULT_RECOVERY_LENGHT_MIN,
		.recovery_length_max = RIST_DEFAULT_RECOVERY_LENGHT_MAX,
		.recovery_reorder_buffer = RIST_DEFAULT_RECOVERY_REORDER_BUFFER,
		.recovery_rtt_min = RIST_DEFAULT_RECOVERY_RTT_MIN,
		.recovery_rtt_max = RIST_DEFAULT_RECOVERY_RTT_MAX,
		.weight = 5,
		.buffer_bloat_mode = RIST_DEFAULT_BUFFER_BLOAT_MODE,
		.buffer_bloat_limit = RIST_DEFAULT_BUFFER_BLOAT_LIMIT,
		.buffer_bloat_hard_limit = RIST_DEFAULT_BUFFER_BLOAT_HARD_LIMIT,
		.key_size = 0
	};

	if (cname != NULL) {
		strncpy(app_peer_config.cname, cname, 128);
	}

	if (statsinterval) {
		rist_receiver_stats_callback_set(receiver_ctx, statsinterval, cb_stats, NULL);
	}

	// URL overrides (also cleans up the URL)
	const struct rist_peer_config *peer_config = &app_peer_config;
	if (rist_parse_address(inputurl, &peer_config))
	{
		fprintf(stderr, "Could not parse peer options for receiver \n");
		exit(1);
	}

	struct rist_peer *peer;
	if (rist_receiver_peer_create(receiver_ctx, &peer, peer_config) == -1) {
		fprintf(stderr, "Could not add peer connector to receiver \n");
		exit(1);
	}


	// callback is best unless you are using the timestamps passed with the buffer
	int enable_data_callback = 0;

	if (enable_data_callback == 1) {
		if (rist_receiver_data_callback_set(receiver_ctx, cb_recv, &cb_arg))
		{
			fprintf(stderr, "Could not set data_callback pointer");
			exit(1);
		}
	}
	cb_arg.sender_ctx = setup_rist_sender(&client_args);
	if (rist_receiver_start(receiver_ctx)) {
		fprintf(stderr, "Could not start rist receiver\n");
		exit(1);
	}
	/* Start the rist protocol thread */
	if (enable_data_callback == 1) {
#ifdef _WIN32
		system("pause");
#else
		pause();
#endif
	}
	else {
		// Master loop
		while (keep_running)
		{
			const struct rist_data_block *b;
			int ret = rist_receiver_data_read(receiver_ctx, &b, 5);
			if (ret && b && b->payload) cb_recv(&cb_arg, b);
		}
	}

	rist_receiver_destroy(receiver_ctx);
	rist_sender_destroy(cb_arg.sender_ctx);

	if (client_args.shared_secret)
		free(client_args.shared_secret);
	if (cname)
		free(cname);
	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);
	


	return 0;
}
