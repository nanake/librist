/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "librist/librist.h"
#include "rist-private.h"
#include <stdatomic.h>

#ifdef _WIN32
#include <windows.h>
#endif

atomic_ulong failed;
atomic_ulong stop;

struct rist_logging_settings *logging_settings_sender = NULL;
struct rist_logging_settings *logging_settings_receiver = NULL;
char* senderstring = "sender";
char* receiverstring = "receiver";

int log_callback(void *arg, int level, const char *msg) {
    if (level > RIST_LOG_ERROR)
        fprintf(stdout, "[%s] %s",(char*)arg, msg);
    if (level <= RIST_LOG_ERROR) {
	fprintf(stdout, "[%s] [ERROR] %s", (char* )arg, msg);
	/* This SHOULD fail the test, I've disabled it so that we pass the encryption tests.
	   in the encryption test we are hitting a condition where the linux crypto stuff seems
	   to not be initialized quickly enough, and we print error messages because decryption
	   is not working correctly, however this is an intermittent issue and solves itself.
	   Furthermore it is not triggered by the CLI tools.
	   This should be investigated and fixed */
        atomic_store(&failed, 1);
        atomic_store(&stop, 1);
    }
    return 0;
}

struct rist_ctx *setup_rist_receiver(int profile, const char *url) {
    struct rist_ctx *ctx;
	if (rist_receiver_create(&ctx, profile, logging_settings_receiver) != 0) {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not create rist receiver context\n");
		return NULL;
	}
    // Rely on the library to parse the url
    struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config))
    {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not parse peer options for receiver\n");
		return NULL;
	}
    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config) == -1) {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not add peer connector to receiver\n");
		return NULL;
	}
    free((void *)peer_config);
	if (rist_start(ctx) == -1) {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not start rist sender\n");
		return NULL;
	}
    return ctx;

}

struct rist_ctx *setup_rist_sender(int profile, const char *url) {
    struct rist_ctx *ctx;
    if (rist_sender_create(&ctx, profile, 0, logging_settings_sender) != 0) {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not create rist sender context\n");
		return NULL;
	}

    const struct rist_peer_config *peer_config_link = NULL;
    if (rist_parse_address2(url, (void *)&peer_config_link))
    {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not parse peer options for sender\n");
		return NULL;
	}

    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config_link) == -1) {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not add peer connector to sender\n");
		return NULL;
	}
	free((void *)peer_config_link);
	if (rist_start(ctx) == -1) {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not start rist sender\n");
		return NULL;
	}
    return ctx;
}

static PTHREAD_START_FUNC(send_data, arg) {
    struct rist_ctx *rist_sender = arg;
    int send_counter = 0;
    char buffer[1316] = { 0 };
    struct rist_data_block data = { 0 };
    /* we just try to send some string at ~20mbs for ~8 seconds */
    while (send_counter < 16000) {
        if (atomic_load(&stop))
            break;
        sprintf(buffer, "DEADBEAF TEST PACKET #%i", send_counter);
        data.payload = &buffer;
        data.payload_len = 1316;
        int ret = rist_sender_data_write(rist_sender, &data);
        if (ret < 0) {
            fprintf(stderr, "Failed to send test packet with error code %d!\n", ret);
            atomic_store(&failed, 1);
            atomic_store(&stop, 1);
            break;
        }
        else if (ret != (int)data.payload_len) {
            fprintf(stderr, "Failed to send test packet %d != %d !\n", ret, (int)data.payload_len);
            atomic_store(&failed, 1);
            atomic_store(&stop, 1);
            break;
        }
        send_counter++;
#ifdef _WIN32
		Sleep(1);
#else
        usleep(500);
#endif
    }

#ifdef _WIN32
	Sleep(2);
#else
    usleep(1500);
#endif

    atomic_store(&stop, 1);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        return 99;
    }
    int profile = atoi(argv[1]);
    char *url1 = strdup(argv[2]);
    char *url2 = strdup(argv[3]);
    int losspercent = atoi(argv[4]) * 10;
	int ret = 0;

    struct rist_ctx *receiver_ctx = NULL;
    struct rist_ctx *sender_ctx = NULL;

    atomic_init(&failed, 0);
    atomic_init(&stop, 0);


    fprintf(stdout, "Testing profile %i with receiver url %s and sender url %s and losspercentage: %i\n", profile, url1, url2, losspercent);

    if (rist_logging_set(&logging_settings_sender, RIST_LOG_DEBUG, log_callback, senderstring, NULL, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging!\n");
		ret = 99;
		goto out;
	}

	if (rist_logging_set(&logging_settings_receiver, RIST_LOG_DEBUG, log_callback, receiverstring, NULL, stderr) != 0)
	{
		fprintf(stderr, "Failed to setup logging!\n");
		ret = 99;
		goto out;
	}
	receiver_ctx = setup_rist_receiver(profile, url1);
    sender_ctx = setup_rist_sender(profile, url2);
	if (!sender_ctx || !receiver_ctx) {
		ret = 99;
		goto out;
	}

    if (losspercent > 0) {
        receiver_ctx->receiver_ctx->simulate_loss = true;
        receiver_ctx->receiver_ctx->loss_percentage = losspercent;
        sender_ctx->sender_ctx->simulate_loss = true;
        sender_ctx->sender_ctx->loss_percentage = losspercent;
    }
    pthread_t send_loop;
    if (pthread_create(&send_loop, NULL, send_data, (void *)sender_ctx) != 0)
    {
        fprintf(stderr, "Could not start send data thread\n");
		ret = 99;
		goto out;
	}

    struct rist_data_block *b = NULL;
    char rcompare[1316];
    int receive_count = 1;
    bool got_first = false;
    while (receive_count < 16000) {
        if (atomic_load(&stop))
            break;
        int queue_length = rist_receiver_data_read2(receiver_ctx, &b, 5);
        if (queue_length > 0) {
            if (!got_first) {
                receive_count = (int)b->seq;
				got_first = true;
			}
            sprintf(rcompare, "DEADBEAF TEST PACKET #%i", receive_count);
            if (strcmp(rcompare, b->payload)) {
                fprintf(stderr, "Packet contents not as expected!\n");
                fprintf(stderr, "Got : %s\n", (char*)b->payload);
                fprintf(stderr, "Expected : %s\n", (char*)rcompare);
                atomic_store(&failed, 1);
                atomic_store(&stop, 1);
                break;
            }
            receive_count++;
            rist_receiver_data_block_free2((struct rist_data_block **const)&b);
        }
    }
	if (!got_first || receive_count < 12500)
		atomic_store(&failed, 1);
	if (atomic_load(&failed))
		ret = 1;
	pthread_join(send_loop, NULL);
out:
	free(url1);
	free(url2);
	if (sender_ctx)
		rist_destroy(sender_ctx);
	if (receiver_ctx)
		rist_destroy(receiver_ctx);
	free(logging_settings_receiver);
	free(logging_settings_sender);
	if (ret > 0)
		return ret;

	fprintf(stdout, "OK\n");
    return 0;
}
