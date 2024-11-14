/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"
#include "srp_shared.h"
#include <librist/librist_config.h>
#if HAVE_MBEDTLS
#include <mbedtls/base64.h>
#elif HAVE_NETTLE
#include <nettle/base64.h>
#endif
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#endif

#if defined(_WIN32) && !defined(stat)
#define stat _stat
#endif

typedef enum {
	IN_USERNAME = 0,
	IN_VERIFIER,
	IN_SALT,
	IN_HASH_ALGO,
	IN_HASH_VERSION,
} user_verifier_state_e;

#define READ_VERIFIER_LEN 1025
#define READ_SALT_LEN 1025
#define MAX_LINE_LEN (READ_VERIFIER_LEN + READ_SALT_LEN + 1)

int srp_base64_decode(char *string, size_t string_len, size_t *out_len, uint8_t **out) {
	//Add padding if needed
	if ((string_len % 4) != 0)
	{
		size_t needed_padding = 4 - (string_len % 4);
		for (size_t i = 0; i < needed_padding; i++)
			string[(string_len + i)] = '=';
		string_len += needed_padding;
		string[string_len] = '\0';
	}
#if HAVE_MBEDTLS
	size_t len = 0;

	int ret =mbedtls_base64_decode(NULL, 0, &len, (unsigned char *)string, string_len);
	if (ret != 0 && ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
		return -1;

	*out = malloc(len);
	if (mbedtls_base64_decode(*out, len, out_len, (unsigned char *)string, string_len) != 0)
		goto fail_decode;

	return 0;
#elif HAVE_NETTLE
	struct base64_decode_ctx ctx;
	nettle_base64_decode_init(&ctx);
	size_t len = BASE64_ENCODE_LENGTH(string_len);
	*out = malloc(len);
	if (nettle_base64_decode_update(&ctx, out_len, *out, string_len, string) != 1)
		goto fail_decode;
	if (nettle_base64_decode_final(&ctx) != 1)
		goto fail_decode;
	return 0;
#endif

fail_decode:
	free(*out);
	*out = NULL;
	return -1;
}

int parse_line(const char *line, size_t line_len, uint8_t **decoded_verifier, size_t *decoded_verifier_len, uint8_t **decoded_salt, size_t *decoded_salt_len) {
	char read = '\0';
	user_verifier_state_e state = IN_VERIFIER;
	int ret = -1;
	size_t read_verifier_len = 0;
	char *read_verifier = calloc(READ_VERIFIER_LEN, 1);
	size_t read_salt_len = 0;
	char *read_salt = calloc(READ_SALT_LEN, 1);
	if (!read_salt || !read_verifier)
		goto out;
	for (size_t i=0; i < line_len; i++) {
		read = line[i];
		if (read == ':')
		{
			if (state >= IN_SALT && read == '\n')
				break;
			if (state == IN_VERIFIER)
				read_verifier[read_verifier_len+1] = '\0';
			else if (state == IN_SALT)
			{
				read_salt[read_salt_len +1] = '\0';
			}
			state++;
		} else if (state == IN_VERIFIER)
		{
			if (read_verifier_len == READ_VERIFIER_LEN)
				return -1;
			read_verifier[read_verifier_len] = read;
			read_verifier_len++;
		} else if (state == IN_SALT)
		{
			if (read_salt_len == READ_SALT_LEN)
				return -1;
			read_salt[read_salt_len] = read;
			read_salt_len++;
		}
	}
	ret = srp_base64_decode(read_verifier, read_verifier_len, decoded_verifier_len, decoded_verifier);
	if (ret != 0)
		goto out;
	ret = srp_base64_decode(read_salt, read_salt_len, decoded_salt_len, decoded_salt);
	if (ret != 0)
		free(*decoded_verifier);
out:
	free(read_verifier);
	free(read_salt);
	return ret;
}


void user_verifier_lookup(char * username,
							librist_verifier_lookup_data_t *lookup_data,
							int *hashversion,
							uint64_t *generation,
							void *user_data)
{
#if HAVE_NETTLE
	struct base64_decode_ctx ctx;
	nettle_base64_decode_init(&ctx);
#endif

	if (user_data == NULL)
		return;

	char *srpfile = user_data;
	if (!generation)
		return;

#ifdef _WIN32
	HANDLE hfile = CreateFile(
		srpfile,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	FILETIME mtime;

	if (hfile == INVALID_HANDLE_VALUE)
		return;

	if (!GetFileTime(hfile, NULL, NULL, &mtime))
		return;

	CloseHandle(hfile);
	*generation = ((uint64_t)mtime.dwHighDateTime << 32) | mtime.dwLowDateTime;
#else
	struct stat buf;
	if (stat(srpfile, &buf) != 0)
		return;
	#ifdef _DARWIN_C_SOURCE
		*generation = ((uint64_t)buf.st_mtimespec.tv_sec << 32) | buf.st_mtimespec.tv_nsec;
	#else
		*generation = ((uint64_t)buf.st_mtim.tv_sec << 32) | buf.st_mtim.tv_nsec;
	#endif
#endif

	if (!lookup_data || !hashversion)
		return;

	FILE *fh = fopen(srpfile, "r");
	if (!fh)
		return;

	size_t username_offset = 0;

	char read_hashver[3] = {0};
	int read_hashver_len = 0;
	user_verifier_state_e state = IN_USERNAME;
	bool skipnextline = false;
	int read = getc(fh);
	//expected format: username:verifier:salt:3
	int maxhashversion = *hashversion;
	size_t username_len = strlen(username);
	char *line_even = malloc(MAX_LINE_LEN);
	size_t line_even_len =0;
	bool line_one_done = false;
	char *line_odd = malloc(MAX_LINE_LEN);
	size_t line_odd_len = 0;

	size_t line_len = 0;
	while (read != EOF)
	{
		char *line = line_one_done? line_odd : line_even;
		if (skipnextline)
		{
			if (read == '\n')
				skipnextline = false;
		}
		else if (state >= IN_SALT && read == '\n') {
			if (state >= IN_HASH_VERSION) {
				state = IN_USERNAME;
				username_offset = 0;
				*hashversion = atoi(read_hashver);
				if (line_one_done) {
					line_odd_len = line_len;
				} else {
					line_even_len = line_len;
					line_len = 0;
					line_one_done = true;
					if (*hashversion < maxhashversion) {
						read = getc(fh);
						continue;
					}
				}
			}
			break;
		} else if (read == ':')
		{
			if (state == IN_VERIFIER)
				line[line_len++] = read;
			if (state == IN_USERNAME && username_offset != username_len) {
				if (line_one_done) {
					break;
				}
				skipnextline = true;
				username_offset = 0;
				continue;
			}
			state++;
		}
		else if (state == IN_USERNAME)
		{
			if (username_offset == username_len) {
				username_offset = 0;
				skipnextline = true;
				continue;
			}
			if (username[username_offset] != read)
			{
				username_offset = 0;
				skipnextline = true;
			} else
				username_offset++;
		} else if (state >= IN_VERIFIER && state <= IN_SALT) {
			if (line_len >= MAX_LINE_LEN) {
				if (!line_one_done)
					goto out;
				break;
			}
			line[line_len++] = read;
		} else if (state == IN_HASH_VERSION && read_hashver_len < 3) {
			read_hashver[read_hashver_len] = read;
			read_hashver_len++;
		}
		read = getc(fh);
	}

	*hashversion = atoi(read_hashver);
	if (state < IN_SALT && !line_one_done)
		goto out;

	char *line = line_even;
	line_len = line_even_len;
	if (line_one_done && line_odd_len != 0) {
		line = line_odd;
		line_len = line_odd_len;
	}

	parse_line(line, line_len, &lookup_data->verifier, &lookup_data->verifier_len, &lookup_data->salt, &lookup_data->salt_len);
	lookup_data->default_ng = true;

out:
	free(line_even);
	free(line_odd);
	fclose(fh);
	return;
}
