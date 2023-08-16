/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"
#include "psk.h"
#include "log-private.h"
#include "crypto-private.h"
#include <string.h>

#if HAVE_MBEDTLS
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#elif HAVE_NETTLE
#include <nettle/pbkdf2.h>
#include <nettle/aes.h>
#include <nettle/ctr.h>
#elif defined(LINUX_CRYPTO)
#include "linux-crypto.h"
#endif
#if !HAVE_MBEDTLS
#include "fastpbkdf2.h"
#endif

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#include <stdint.h>

//TODO: handle failures?
int _librist_crypto_psk_rist_key_init(struct rist_key *key, uint32_t key_size, uint32_t rotation, const char *password, bool odd)
{
	key->password_len = strlen(password);
	memcpy(key->password, password, key->password_len);
	key->key_size = key_size;
	key->key_rotation = rotation;
#if HAVE_MBEDTLS
	mbedtls_aes_init(&key->mbedtls_aes_ctx);
#elif HAVE_NETTLE
	memset(&key->nettle_ctx, 0, sizeof(key->nettle_ctx));
#elif defined(LINUX_CRYPTO)
	linux_crypto_init(&key->linux_crypto_ctx);
#endif
	key->odd = odd;
	return 0;
}

int _librist_crypto_psk_rist_key_destroy(struct rist_key *key)
{
    if (key->key_size) {
#if HAVE_MBEDTLS
	    mbedtls_aes_free(&key->mbedtls_aes_ctx);
#elif HAVE_NETTLE
	//nothing to do here
#elif defined(LINUX_CRYPTO)
	    linux_crypto_free(&key->linux_crypto_ctx);
#endif
    }
	return 0;
}

int _librist_crypto_psk_rist_key_clone(struct rist_key *key_in, struct rist_key *key_out)
{
	key_out->password_len = key_in->password_len;
    memcpy(key_out->password, key_in->password, key_in->password_len);
    key_out->key_size = key_in->key_size;
    key_out->key_rotation = key_in->key_rotation;
#if HAVE_MBEDTLS
	mbedtls_aes_init(&key_out->mbedtls_aes_ctx);
#elif HAVE_NETTLE
    memset(&key_out->nettle_ctx, 0, sizeof(key_out->nettle_ctx));
#elif defined(LINUX_CRYPTO)
	linux_crypto_init(&key_out->linux_crypto_ctx);
#endif
	key_out->odd = key_in->odd;
	return 0;
}

static void _librist_crypto_aes_key(struct rist_key *key)
{
    uint8_t aes_key[256 / 8];
#if HAVE_MBEDTLS
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t *info_sha;
    int ret = -1;
    /* Setup the hash/HMAC function, for the PBKDF2 function. */
    mbedtls_md_init(&sha_ctx);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == NULL) {
            // rist_log_priv(cctx, RIST_LOG_ERROR, "Failed to setup Mbed TLS
            // hash info\n");
    }

    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0) {
            // rist_log_priv(cctx, RIST_LOG_ERROR, "Failed to setup Mbed TLS MD
            // ctx");
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &sha_ctx, (const unsigned char *)key->password, key->password_len,
        key->gre_nonce, sizeof(key->gre_nonce),
        RIST_PBKDF2_HMAC_SHA256_ITERATIONS, key->key_size / 8, aes_key);
    if (ret != 0) {
            // rist_log_priv(cctx, RIST_LOG_ERROR, "Mbed TLS pbkdf2 function
            // failed\n");
    }
    mbedtls_md_free(&sha_ctx);
#elif HAVE_NETTLE
    nettle_pbkdf2_hmac_sha256(key->password_len,(const uint8_t*)key->password,
							  RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
							  sizeof(key->gre_nonce), key->gre_nonce,
							  key->key_size/8, aes_key);
#else
    fastpbkdf2_hmac_sha256(
            (const void *) key->password, key->password_len,
            (const void *) key->gre_nonce, sizeof(key->gre_nonce),
            RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
            aes_key, key->key_size / 8);
#endif


#if HAVE_MBEDTLS
    mbedtls_aes_setkey_enc(&key->mbedtls_aes_ctx, aes_key, key->key_size);
#elif HAVE_NETTLE
	switch(key->key_size) {
	case 256:
        nettle_aes256_set_encrypt_key(&key->nettle_ctx.u.ctx256, aes_key);
        break;
	case 192:
        nettle_aes192_set_encrypt_key(&key->nettle_ctx.u.ctx192, aes_key);
        break;
	case 128:
		RIST_FALLTHROUGH;
	default:
		nettle_aes128_set_encrypt_key(&key->nettle_ctx.u.ctx128, aes_key);
    }
#elif defined(LINUX_CRYPTO)
    if (key->linux_crypto_ctx)
		linux_crypto_set_key(aes_key, key->key_size / 8, key->linux_crypto_ctx);
    else
        aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#else
    aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#endif
    key->used_times = 0;
}

//This doesn't really belong here (not PSK related), but since all other crypto interop stuff is here it goes in here..
void _librist_crypto_aes_ctr(const uint8_t key[], int key_size, uint8_t iv[], const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len) {
#if HAVE_MBEDTLS
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, key_size);
	uint8_t stream_block[AES_BLOCK_SIZE] = {0};
	size_t nc_off = 0;
	mbedtls_aes_crypt_ctr(&ctx, payload_len, &nc_off, iv, stream_block, inbuf, outbuf);
	mbedtls_aes_free(&ctx);
#elif HAVE_NETTLE
    struct aes_ctx aes_ctx;
    memset(&aes_ctx, 0, sizeof(aes_ctx));
    nettle_cipher_func *f;
    switch (key_size) {
    case 256:
		nettle_aes256_set_encrypt_key(&aes_ctx.u.ctx256, key);
		f = (nettle_cipher_func *)nettle_aes256_encrypt;
		break;
	case 128:
		nettle_aes128_set_encrypt_key(&aes_ctx.u.ctx128, key);
		f = (nettle_cipher_func *)nettle_aes192_encrypt;
		break;
	}
	nettle_ctr_crypt(&aes_ctx.u, f, AES_BLOCK_SIZE, iv, payload_len, outbuf, inbuf);
#else
    uint32_t aes_key_sched[60];
    aes_key_setup(key, aes_key_sched, key_size);
    aes_decrypt_ctr(inbuf, payload_len, outbuf, aes_key_sched, key_size, iv);
#endif
}

static void _librist_crypto_psk_aes_ctr(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
#if HAVE_MBEDTLS
	mbedtls_aes_crypt_ctr(&key->mbedtls_aes_ctx, payload_len, &key->aes_offset, key->iv, key->strean_block, inbuf, outbuf);
#elif HAVE_NETTLE
	nettle_cipher_func *f;
	switch(key->key_size) {
	case 256:
		f = (nettle_cipher_func *)nettle_aes256_encrypt;
		break;
	case 192:
		f = (nettle_cipher_func *)nettle_aes192_encrypt;
		break;
	case 128:
		RIST_FALLTHROUGH;
	default:
		f = (nettle_cipher_func *)nettle_aes128_encrypt;
	}
	nettle_ctr_crypt(&key->nettle_ctx.u, f, AES_BLOCK_SIZE, key->iv,payload_len, outbuf, inbuf);
#elif defined(LINUX_CRYPTO)
	if (key->linux_crypto_ctx)
		linux_crypto_decrypt(inbuf, outbuf, payload_len, key->iv, key->linux_crypto_ctx);
	else
		aes_decrypt_ctr(inbuf, payload_len, outbuf,	key->aes_key_sched, key->key_size, key->iv);
#else
	aes_decrypt_ctr(inbuf, payload_len, outbuf, key->aes_key_sched, key->key_size, key->iv);
#endif
    key->used_times++;
}

static void _librist_crypto_psk_prepare_iv(struct rist_key *key, uint8_t gre_version, uint32_t seq_nbe) {
    /* Prepare AES iv */
    // The byte array needs to be zeroes and then the seq in network byte order
    uint8_t copy_offset = gre_version >= 1 ? 0 : 12;
    memset(key->iv, 0, 16);
    memcpy(key->iv + copy_offset, &seq_nbe, sizeof(seq_nbe));
}

static void _librist_crypto_psk_generate_nonce(struct rist_key *key) {
	uint32_t nonce_val;
	do {
		nonce_val = prand_u32();
	} while (!nonce_val);

	memcpy(key->gre_nonce, &nonce_val, sizeof(key->gre_nonce));

    UNSET_BIT(key->gre_nonce[0], 7);
    if (key->odd)
        SET_BIT(key->gre_nonce[0], 7);
}

void _librist_crypto_psk_decrypt(struct rist_key *key, uint8_t nonce[4], uint32_t seq_nbe, uint8_t gre_version, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
	uint32_t nonce_val = *((uint32_t *)nonce);
    if (!nonce_val)
        return;

    if (memcmp(nonce, key->gre_nonce, sizeof(key->gre_nonce)) != 0) {
        memcpy(key->gre_nonce, nonce, sizeof(key->gre_nonce));
        _librist_crypto_aes_key(key);
        key->bad_decryption = false;
        key->bad_count = 0;
    }

    if (key->used_times > RIST_AES_KEY_REUSE_TIMES)
        return;

    _librist_crypto_psk_prepare_iv(key, gre_version, seq_nbe);
#if HAVE_MBEDTLS
    key->aes_offset = 0;
#endif
    _librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
    return;
}

void _librist_crypto_psk_encrypt(struct rist_key *key, uint32_t seq_nbe, uint8_t gre_version,const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
    uint32_t nonce_val = *((uint32_t *)key->gre_nonce);
    if (!nonce_val || (key->used_times +1) > RIST_AES_KEY_REUSE_TIMES || (key->key_rotation > 0 && key->used_times >= key->key_rotation)) {
        _librist_crypto_psk_generate_nonce(key);
        _librist_crypto_aes_key(key);
    }
    _librist_crypto_psk_prepare_iv(key, gre_version, seq_nbe);
#if HAVE_MBEDTLS
    key->aes_offset = 0;
#endif
    _librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
    return;
}

int _librist_crypto_psk_set_passphrase(struct rist_key *key, const uint8_t *passsphrase, size_t passphrase_len) {
	if (passphrase_len > sizeof(key->password) -1) {
		return -1;
	}
	if (key->key_size == 0)
		key->key_size = 256;
	memcpy(key->password, passsphrase, passphrase_len);
	key->password_len = passphrase_len;
	key->used_times = 0;
	_librist_crypto_psk_generate_nonce(key);
	_librist_crypto_aes_key(key);
	return 0;
}

void _librist_crypto_psk_get_passphrase(struct rist_key *key, const uint8_t **passphrase, size_t *passphrase_len) {
	*passphrase = key->password;
	*passphrase_len = key->password_len;
}

void _librist_crypto_psk_encrypt_continue(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len) {
	_librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
}
