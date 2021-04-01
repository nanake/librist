/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <mbedtls/base64.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void user_verifier_lookup(char * username,
							size_t *verifier_len, char **verifier,
							size_t *salt_len, char **salt,
							bool *use_default_2048_bit_n_modulus,
							char **n_modulus_ascii,
							char **generator_ascii,
							void *user_data)
{
	(void)n_modulus_ascii;
	(void)generator_ascii;
	if (user_data == NULL)
		return;
	FILE *fh = (FILE *)user_data;
	size_t username_offset = 0;

	size_t read_verifier_len = 0;
	char *read_verifier = malloc(1024);
	size_t read_salt_len = 0;
	char *read_salt = malloc(1024);

	int reading = 0;//0 = username, 1 = verifier, 2 = salt
	bool skipnextline = false;
	int read = getc(fh);
	//expected format: username:verifier:salt:3
	while (read != EOF)
	{
		if (skipnextline)
		{
			if (read == '\n')
				skipnextline = false;
		} else if (read == ':')
		{
			if (reading == 0 && username_offset != (strlen(username))) {
				skipnextline = true;
				username_offset = 0;
				continue;
			}
			if (reading == 1)
				read_verifier[read_verifier_len+1] = '\0';
			else if (reading == 2)
			{
				read_salt[read_salt_len +1] = '\0';
				break;
			}
			reading++;
		}
		else if (reading == 0)
		{
			if (username[username_offset] != read)
			{
				username_offset = 0;
				skipnextline = true;
			}
			 else
				username_offset++;
		} else if (reading == 1)
		{
			if (read_verifier_len == 1024)
				goto out;
			read_verifier[read_verifier_len] = read;
			read_verifier_len++;
		} else if (reading == 2)
		{
			if (read_salt_len == 1024)
				goto out;
			read_salt[read_salt_len] = read;
			read_salt_len++;
		}
		read = getc(fh);
	}
	if (reading != 2)
		goto out;
	//PAD with ==
	if ((read_verifier_len % 4) != 0)
	{
		size_t needed_padding = 4 - (read_verifier_len % 4);
		for (size_t i = 0; i < needed_padding; i++)
			read_verifier[(read_verifier_len + i)] = '=';
		read_verifier_len += needed_padding;
		read_verifier[read_verifier_len] = '\0';
	}
	if ((read_salt_len % 4) != 0)
	{
		size_t needed_padding = 4 - (read_salt_len % 4);
		for (size_t i = 0; i < needed_padding; i++)
			read_salt[(read_salt_len + i)] = '=';
		read_salt_len += needed_padding;
		read_salt[read_salt_len] = '\0';
	}
	char *decoded_verifier = malloc(1024);
	char *decoded_salt = malloc(1024);
	if (mbedtls_base64_decode((unsigned char *)decoded_verifier, 1024, verifier_len, (unsigned char *)read_verifier, read_verifier_len) != 0)
		goto fail_decode;

	if (mbedtls_base64_decode((unsigned char *)decoded_salt, 1024, salt_len, (unsigned char *)read_salt, read_salt_len) != 0)
		goto fail_decode;

	*verifier = decoded_verifier;
	*salt = decoded_salt;
	*use_default_2048_bit_n_modulus = true;
	goto out;

fail_decode:
	*verifier_len = 0;
	*salt_len = 0;
	free(decoded_verifier);
	free(decoded_salt);
out:
	free(read_verifier);
	free(read_salt);
	rewind(fh);
	return;
}
