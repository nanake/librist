/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_CRYPTO_PSK_H
#define RIST_CRYPTO_PSK_H

#include "config.h"
#include "common/attributes.h"
#include "librist/librist_config.h"
#if HAVE_MBEDTLS
#include "mbedtls/aes.h"
#elif HAVE_NETTLE
#include <nettle/aes.h>
#else
#ifdef LINUX_CRYPTO
#include "linux-crypto.h"
#endif
#include "contrib/aes.h"
#endif
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

struct rist_key {
	uint32_t key_size;
	uint8_t gre_nonce[4];
	uint8_t iv[AES_BLOCK_SIZE];
#if HAVE_MBEDTLS
	size_t aes_offset;
	unsigned char strean_block[16];
	mbedtls_aes_context mbedtls_aes_ctx;
#elif HAVE_NETTLE
	struct aes_ctx nettle_ctx;
#elif defined(LINUX_CRYPTO)
	struct linux_crypto *linux_crypto_ctx;
#endif
	uint32_t aes_key_sched[60];//Do we still need this fallback?
	uint32_t key_rotation;
    uint64_t used_times;
	uint8_t password[128];
	size_t password_len;
    bool bad_decryption;
    int bad_count;
	bool odd;
};

RIST_PRIV int _librist_crypto_psk_rist_key_init(struct rist_key *key, uint32_t key_size, uint32_t rotation, const char *password, bool odd);
RIST_PRIV int _librist_crypto_psk_rist_key_destroy(struct rist_key *key);
RIST_PRIV int _librist_crypto_psk_rist_key_clone(struct rist_key *key_in, struct rist_key *key_out);
RIST_PRIV void _librist_crypto_psk_decrypt(struct rist_key *key, uint8_t nonce[4], uint32_t seq_nbe, uint8_t gre_version, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len);
RIST_PRIV void _librist_crypto_psk_encrypt(struct rist_key *key, uint32_t seq_nbe, uint8_t gre_version, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len);
RIST_PRIV void _librist_crypto_psk_encrypt_continue(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len);
RIST_PRIV int _librist_crypto_psk_set_passphrase(struct rist_key *key, const uint8_t *passsphrase, size_t passphrase_len);
RIST_PRIV void _librist_crypto_psk_get_passphrase(struct rist_key *key, const uint8_t **passphrase, size_t *passphrase_len);
RIST_PRIV void _librist_crypto_aes_ctr(const uint8_t key[], int key_size, uint8_t iv[], const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len);
#endif
