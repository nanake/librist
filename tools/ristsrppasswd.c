/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"
#include "crypto/srp.h"
#include "crypto/srp_constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_MBEDTLS
#include <mbedtls/base64.h>
#elif HAVE_NETTLE
#include <nettle/base64.h>
#endif

int create_and_print(const char *username, const char *password, const char *n_hex, const char* g_hex, bool correct) {
	uint8_t *salt = NULL;
	size_t salt_len = 0;
	uint8_t *verifier = NULL;
	size_t verifier_len = 0;
	int ret = librist_crypto_srp_create_verifier(n_hex, g_hex, username, password, &salt, &salt_len, &verifier, &verifier_len, correct);
	if (ret != 0)
		return ret;

	char salt64[1024] = {0};
	char verifier64[1024] = {0};
#if HAVE_MBEDTLS
	size_t salt_written_len = 0;
	mbedtls_base64_encode((unsigned char*)salt64, sizeof(salt64), &salt_written_len, salt, salt_len);
	size_t verifier_written_len = 0;
	mbedtls_base64_encode((unsigned char*)verifier64, sizeof(verifier64), &verifier_written_len, verifier, verifier_len);
#elif HAVE_NETTLE
	nettle_base64_encode_raw(salt64, salt_len, salt);
	nettle_base64_encode_raw(verifier64, verifier_len, verifier);
#endif
	free(salt);
	free(verifier);
	printf("%s:%s:%s:3:%d\n", username, verifier64, salt64, correct? 1 :0);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [username] [password]\n", argv[0]);
		return 1;
	}

	const char *username = argv[1];
	const char *password = argv[2];
	const char *n_hex = NULL;
	const char *g_hex = NULL;

	librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &n_hex, &g_hex);
#if HAVE_MBEDTLS
	create_and_print(username, password, n_hex, g_hex, false);
#endif
	create_and_print(username, password, n_hex, g_hex, true);
}
