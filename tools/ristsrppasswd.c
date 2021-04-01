/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "srp.h"
#include <stdio.h>
#include <string.h>
#include <mbedtls/base64.h>

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [username] [password]\n", argv[0]);
		return 1;
	}

	struct SRPSession * session = srp_session_new(SRP_SHA256, SRP_NG_2048, NULL, NULL);
	const char *username = argv[1];
	const char *password = argv[2];
	size_t len_s = 0;
	size_t len_v = 0;
	char *bytes_s = NULL;
	char *bytes_v = NULL;
	srp_create_salted_verification_key(session, username,
									   (const unsigned char *)password, strlen(password),
									   (const unsigned char **)&bytes_s, &len_s,
									   (const unsigned char **)&bytes_v, &len_v);
	unsigned char verifier[512] = { 0 };
	size_t olen_v = 0;
	unsigned char salt[512] = { 0 };
	size_t olen_s = 0;
	mbedtls_base64_encode(verifier, 512, &olen_v, (const unsigned char *)bytes_v, len_v);
	unsigned char *test = &verifier[0];
	while (*test != '\0')
	{
		if (*test == '=')
		{
			*test = '\0';
			break;
		}
		test++;
	}
	mbedtls_base64_encode(salt, 512, &olen_s, (const unsigned char *)bytes_s, len_s);
	test = &salt[0];
	while (*test != '\0')
	{
		if (*test == '=')
		{
			*test = '\0';
			break;
		}
		test++;
	}
	printf("%s:%s:%s:3\n", username, verifier, salt);
}
