/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* rist2rist receive simple profile rist and expose it as main profile */

#include <librist/librist.h>
#include "librist/version.h"
#include "risturlhelp.h"
#ifdef USE_MBEDTLS
#include "librist/librist_srp.h"
#include "srp_shared.h"
#endif
#include "vcs_version.h"
#include <stdio.h>
#include <string.h>
#include "getopt-shim.h"
#include <assert.h>
#include <signal.h>
#ifdef __unix
#include <unistd.h>
#endif
#include "oob_shared.h"

struct rist_sender_args {
	char* cname;
	char* shared_secret;
	char* outputurl;
	uint16_t dst_port;
	enum rist_log_level loglevel;
	int encryption_type;
	uint32_t flow_id;
	int statsinterval;
};

struct rist_cb_arg {
	uint16_t src_port;
	uint16_t dst_port;
	struct rist_ctx *sender_ctx;
	struct rist_sender_args *client_args;
};

static int keep_running = 1;
static struct rist_logging_settings logging_settings = LOGGING_SETTINGS_INITIALIZER;

static struct option long_options[] = {
{ "inurl",           required_argument, NULL, 'i' },
{ "outurl",          required_argument, NULL, 'o' },
{ "secret",          required_argument, NULL, 's' },
{ "encryption-type", required_argument, NULL, 'e' },
{ "cname",           required_argument, NULL, 'N' },
{ "statsinterval",   required_argument, NULL, 'S' },
{ "verbose-level",   required_argument, NULL, 'v' },
{ "remote-logging",  required_argument, NULL, 'r' },
#ifdef USE_MBEDTLS
{ "srpfile",         required_argument, NULL, 'F' },
#endif
{ "help",            no_argument,       NULL, 'h' },
{ 0, 0, 0, 0 },
};

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -i | --inputurl ADDRESS:PORT            * | Input IP address and port                                |\n"
"       -o | --outputurl ADDRESS:PORT           * | Output IP address and port                               |\n"
"       -s | --secret PWD                         | Pre-shared encryption secret                             |\n"
"       -e | --encryption-type TYPE               | Encryption type (0 = none, 1 = AES-128, 2 = AES-256)     |\n"
"       -S | --statsinterval value (ms)           | Interval at which stats get printed, 0 to disable        |\n"
"       -N | --cname identifier                   | Manually configured identifier                           |\n"
"       -v | --verbose-level value                | To disable logging: -1, log levels match syslog levels   |\n"
"       -r | --remote-logging IP:PORT             | Send logs and stats to this IP:PORT using udp messages   |\n"
#ifdef USE_MBEDTLS
"       -F | --srpfile filepath                   | When in listening mode, use this file to hold the list   |\n"
"                                                 | of usernames and passwords to validate against. Use the  |\n"
"                                                 | ristsrppasswd tool to create the line entries.           |\n"
#endif
"       -h | --help                               | Show this help                                           |\n"
"       -u | --help-url                           | Show all the possible url options                        |\n"
"   * == mandatory value \n"
"Default values: %s \n"
"       --statsinterval 1000      \\\n"
"       --verbose-level 6         \n";

#ifdef USE_MBEDTLS
	FILE *srpfile = NULL;
#endif

static void usage(char *cmd)
{
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n%s version %s libRIST library: %s API version: %s\n", cmd, help_str, LIBRIST_VERSION, librist_version(), librist_api_version());
	exit(1);
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	struct rist_ctx *receiver_ctx = (struct rist_ctx *)arg;
	char buffer[500];
	char message[200];
	int message_len = snprintf(message, 200, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	// To be compliant with the spec, the message must have an ipv4 header
	int ret = oob_build_api_payload(buffer, (char *)connecting_ip, (char *)local_ip, message, message_len);
	rist_log(&logging_settings, RIST_LOG_INFO,"Peer has been authenticated, sending oob/api message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = buffer;
	oob_block.payload_len = ret;
	rist_oob_write(receiver_ctx, &oob_block);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	(void)peer;
	struct rist_ctx *ctx = (struct rist_ctx *)arg;
	(void)ctx;
	return 0;
}

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

static int cb_stats(void *arg, const struct rist_stats *stats_container) {
	(void)arg;
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n\n", stats_container->stats_json);
	rist_stats_free(stats_container);
	return 0;
}

static struct rist_ctx* setup_rist_sender(struct rist_sender_args *setup) {
	struct rist_ctx *ctx;
	printf("CName: %s\n", setup->cname);
	printf("Outurl: %s\n", setup->outputurl);
	int rist;
	if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, setup->flow_id, &logging_settings) != 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not create rist sender context\n");
		exit(1);
	}

	rist = rist_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, ctx);
	if (rist < 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not initialize rist auth handler\n");
		exit(1);
	}

	if (rist_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not add enable out-of-band data\n");
		exit(1);
	}

	if (setup->statsinterval) {
		rist_stats_callback_set(ctx, setup->statsinterval, cb_stats, NULL);
	}

	// Applications defaults and/or command line options
	int keysize =  setup->encryption_type * 128;
	struct rist_peer_config app_peer_config = {
		.version = RIST_PEER_CONFIG_VERSION,
		.virt_dst_port = 1968,
		.recovery_mode = RIST_DEFAULT_RECOVERY_MODE,
		.recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE,
		.recovery_maxbitrate_return = RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN,
		.recovery_length_min = RIST_DEFAULT_RECOVERY_LENGHT_MIN,
		.recovery_length_max = RIST_DEFAULT_RECOVERY_LENGHT_MAX,
		.recovery_reorder_buffer = RIST_DEFAULT_RECOVERY_REORDER_BUFFER,
		.recovery_rtt_min = RIST_DEFAULT_RECOVERY_RTT_MIN,
		.recovery_rtt_max = RIST_DEFAULT_RECOVERY_RTT_MAX,
		.weight = 5,
		.congestion_control_mode = RIST_DEFAULT_CONGESTION_CONTROL_MODE,
		.min_retries = RIST_DEFAULT_MIN_RETRIES,
		.max_retries = RIST_DEFAULT_MAX_RETRIES,
		.key_size = 0,
	};

	app_peer_config.virt_dst_port = setup->dst_port;
	app_peer_config.key_size = keysize;

	if (setup->shared_secret != NULL) {
		strncpy(app_peer_config.secret, setup->shared_secret, RIST_MAX_STRING_SHORT -1);
	}

	if (setup->cname != NULL) {
		strncpy(app_peer_config.cname, setup->cname, RIST_MAX_STRING_SHORT -1);
	}

	// URL overrides (also cleans up the URL)
	struct rist_peer_config *peer_config = &app_peer_config;
	if (rist_parse_address2(setup->outputurl, &peer_config))
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse peer options for sender\n");
		exit(1);
	}

	struct rist_peer *peer;
	if (rist_peer_create(ctx, &peer, peer_config) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not add peer connector to sender\n");
		exit(1);
	}

#ifdef USE_MBEDTLS
	int srp_error = 0;
	if (strlen(peer_config->srp_username) > 0 && strlen(peer_config->srp_password) > 0)
	{
		srp_error = rist_enable_eap_srp(peer, peer_config->srp_username, peer_config->srp_password, NULL, NULL);
		if (srp_error)
			rist_log(&logging_settings, RIST_LOG_WARN, "Error %d trying to enable SRP for peer\n", srp_error);
	}
	if (srpfile)
	{
		srp_error = rist_enable_eap_srp(peer, NULL, NULL, user_verifier_lookup, srpfile);
		if (srp_error)
			rist_log(&logging_settings, RIST_LOG_WARN, "Error %d trying to enable SRP global authenticator, file %s\n", srp_error, srpfile);
	}
#endif

	/* Setting rist timeouts (in ms)*/
	//rist_sender_set_retry_timeout(ctx, 10000);
	//rist_sender_keepalive_timeout_set(ctx, 5000);

	if (rist_start(ctx) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start rist sender\n");
		exit(1);
	}
	return ctx;
}

static int cb_recv(void *arg, struct rist_data_block *b)
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
	int ret = rist_sender_data_write(cb_arg->sender_ctx, b);
	rist_receiver_data_block_free2(&b);
	return ret;
}

static void intHandler(int signal) {
	rist_log(&logging_settings, RIST_LOG_NOTICE, "Signal %d received\n", signal);
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
	char *remote_log_address = NULL;
	int exitcode = 0;
#ifdef _WIN32
#define STDERR_FILENO 2
	signal(SIGINT, intHandler);
	signal(SIGTERM, intHandler);
	signal(SIGABRT, intHandler);
#else
	struct sigaction act = { {0} };
	act.sa_handler = intHandler;
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
#endif

	// Default log settings
	struct rist_logging_settings *log_ptr = &logging_settings;
	if (rist_logging_set(&log_ptr, loglevel, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr,"Failed to setup default logging!\n");
		exit(1);
	}

	rist_log(&logging_settings, RIST_LOG_INFO, "Starting rist2rist version: %s libRIST library: %s API version: %s\n", LIBRIST_VERSION, librist_version(), librist_api_version());

	int option_index;
	int c;
	while ((c = getopt_long(argc, argv, "r:i:o:s:e:N:v:S:h:u", long_options, &option_index)) != -1) {
		switch (c) {
		case 'i':
			if (inputurl != NULL)
				goto usage;
			inputurl = strdup(optarg); 
			break;
		case 'o':
			if (outputurl != NULL)
				goto usage;
			outputurl = strdup(optarg); 
			break;
		case 's':
			if (client_args.shared_secret != NULL)
				goto usage;
			client_args.shared_secret = strdup(optarg); 
			break;
		case 'e':
			client_args.encryption_type =atoi(optarg);
			break;
		case 'N':
			if (cname != NULL)
				goto usage;
			cname = strdup(optarg); 
			break;
		case 'v':
			loglevel = (enum rist_log_level) atoi(optarg);
			break;
		case 'r':
			if (remote_log_address != NULL)
				goto usage;
			remote_log_address = strdup(optarg);
		break;
#ifdef USE_MBEDTLS
		case 'F':
			srpfile = fopen(optarg, "r");
			if (!srpfile) {
				rist_log(&logging_settings, RIST_LOG_ERROR, "Could not open srp file %s\n", optarg);
				exitcode = 1;
				goto out;
			}
		break;
#endif
		case 'S':
			statsinterval = atoi(optarg);
			break;
		case 'u':
			rist_log(&logging_settings, RIST_LOG_INFO, "%s", help_urlstr);
			exit(1);
		case 'h':
			//
		default:
usage:
			usage(argv[0]);
			break;
		}
	}
	client_args.cname = cname;
	client_args.loglevel = loglevel;
	client_args.outputurl = outputurl;
	client_args.statsinterval = statsinterval;

	if (inputurl == NULL || outputurl == NULL) {
		usage(argv[0]);
	}

	if (argc < 2) {
		usage(argv[0]);
	}

	if (rist_logging_set(&log_ptr, loglevel, NULL, NULL, remote_log_address, stderr) != 0) {
		fprintf(stderr, "Failed to setup logging!\n");
		exitcode = 1;
		goto out;;
	}

	struct rist_ctx *receiver_ctx;

	if (rist_receiver_create(&receiver_ctx, RIST_PROFILE_SIMPLE, &logging_settings) != 0) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not create rist receiver context\n");
		exitcode = 1;
		goto out;
	}

	if (rist_auth_handler_set(receiver_ctx, cb_auth_connect, cb_auth_disconnect, receiver_ctx) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not init rist auth handler\n");
		exitcode = 1;
		goto out;
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
		.congestion_control_mode = RIST_DEFAULT_CONGESTION_CONTROL_MODE,
		.min_retries = RIST_DEFAULT_MIN_RETRIES,
		.max_retries = RIST_DEFAULT_MAX_RETRIES,
		.key_size = 0
	};

	if (cname != NULL) {
		strncpy(app_peer_config.cname, cname, RIST_MAX_STRING_SHORT -1);
	}

	if (statsinterval) {
		rist_stats_callback_set(receiver_ctx, statsinterval, cb_stats, NULL);
	}

	// URL overrides (also cleans up the URL)
	struct rist_peer_config *peer_config = &app_peer_config;
	if (rist_parse_address2(inputurl, &peer_config))
	{
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not parse peer options for receiver \n");
		exitcode = 1;
		goto out;
	}

	struct rist_peer *peer;
	if (rist_peer_create(receiver_ctx, &peer, peer_config) == -1) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not add peer connector to receiver \n");
		exitcode = 1;
		goto out;
	}


	// callback is best unless you are using the timestamps passed with the buffer
	int enable_data_callback = 0;

	if (enable_data_callback == 1) {
		if (rist_receiver_data_callback_set2(receiver_ctx, cb_recv, &cb_arg))
		{
			rist_log(&logging_settings, RIST_LOG_ERROR, "Could not set data_callback pointer");
			exitcode = 1;
			goto out;
		}
	}
	cb_arg.sender_ctx = setup_rist_sender(&client_args);
	if (rist_start(receiver_ctx)) {
		rist_log(&logging_settings, RIST_LOG_ERROR, "Could not start rist receiver\n");
		exitcode = 1;
		goto out;
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
			struct rist_data_block *b;
			int ret = rist_receiver_data_read2(receiver_ctx, &b, 5);
			if (ret && b && b->payload) cb_recv(&cb_arg, b);
		}
	}

	rist_destroy(receiver_ctx);
	rist_destroy(cb_arg.sender_ctx);
out:
	rist_logging_unset_global();
	if (client_args.shared_secret)
		free(client_args.shared_secret);
	if (cname)
		free(cname);
	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);
	if (remote_log_address)
		free(remote_log_address);
	


	return exitcode;
}
