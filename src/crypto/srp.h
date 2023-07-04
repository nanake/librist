#ifndef LIBRIST_CRYPTO_SRH_H
#define LIBRIST_CRYPTO_SRH_H

#include <librist/common.h>
#include "common/attributes.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define SHA256_DIGEST_LENGTH 32

struct librist_crypto_srp_authenticator_ctx;
struct librist_crypto_srp_client_ctx;

//Marked as public because we want to use it in ristsrppassword. NOT (yet) intended for public use, so zero API/ABI guarantees/promises.
RIST_API int librist_crypto_srp_create_verifier(const char *n_hex, const char *g_hex,
                                       const char *username,
                                       const char *password,
                                       unsigned char **bytes_s, size_t *len_s,
                                       unsigned char **bytes_v, size_t *len_v, bool correct);

RIST_PRIV struct librist_crypto_srp_authenticator_ctx *librist_crypto_srp_authenticator_ctx_create(const char* n_hex, const char *g_hex, const uint8_t *v_bytes, size_t v_len, const uint8_t *s_bytes, size_t s_len, bool correct);
RIST_PRIV void librist_crypto_srp_authenticator_ctx_free(struct librist_crypto_srp_authenticator_ctx *ctx);
RIST_PRIV int librist_crypto_srp_authenticator_write_g_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t *g_buf, size_t g_buf_len);
RIST_PRIV int librist_crypto_srp_authenticator_write_n_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t *n_buf, size_t n_buf_len);
RIST_PRIV int librist_crypto_srp_authenticator_handle_A(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t *A_buf, size_t A_buf_len);
RIST_PRIV int librist_crypto_srp_authenticator_write_B_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t* B_buf, size_t B_buf_len);
RIST_PRIV int librist_crypto_srp_authenticator_verify_m1(struct librist_crypto_srp_authenticator_ctx *ctx,const char *username,  uint8_t *client_m1_buf);
RIST_PRIV void librist_crypto_srp_authenticator_write_M2_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t* m2_buf);
RIST_PRIV const uint8_t *librist_crypto_srp_authenticator_get_key(struct librist_crypto_srp_authenticator_ctx *ctx);

RIST_PRIV struct librist_crypto_srp_client_ctx *librist_crypto_srp_client_ctx_create(bool default_ng, uint8_t *N_bytes, size_t N_len, uint8_t *g_bytes, size_t g_len, uint8_t *s_bytes, size_t s_len, bool correct);
RIST_PRIV void librist_crypto_srp_client_ctx_free(struct librist_crypto_srp_client_ctx *ctx);
RIST_PRIV int librist_crypto_srp_client_write_A_bytes(struct librist_crypto_srp_client_ctx *ctx, uint8_t *A_buf, size_t A_buf_len);
RIST_PRIV int librist_crypto_srp_client_handle_B(struct librist_crypto_srp_client_ctx *ctx, uint8_t *B_bytes, size_t B_len, const char *username, const char *password);
RIST_PRIV void librist_crypto_srp_client_write_M1_bytes(struct librist_crypto_srp_client_ctx *ctx, uint8_t M1_buf[SHA256_DIGEST_LENGTH]);
RIST_PRIV int librist_crypto_srp_client_verify_m2(struct librist_crypto_srp_client_ctx *ctx, uint8_t *m2);
RIST_PRIV const uint8_t *librist_crypto_srp_client_get_key(struct librist_crypto_srp_client_ctx *ctx);
#endif /* LIBRIST_CRYPTO_SRH_H */
