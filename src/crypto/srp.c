#include "srp.h"

#include "config.h"
#include "random.h"
#include "crypto/srp_constants.h"
#include "vcs_version.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef WINAPI
#define WINAPI
#endif

#define DEBUG_EXTRACT_SRP_EXCHANGE 0
#ifndef DEBUG_USE_EXAMPLE_CONSTANTS
#define DEBUG_USE_EXAMPLE_CONSTANTS 0
#endif

#if DEBUG_EXTRACT_SRP_EXCHANGE
static void print_hash(const uint8_t *buf, char *specifier) {
	char outbuf[SHA256_DIGEST_LENGTH*2 +1];
	size_t j;
	for (j = 0; j < SHA256_DIGEST_LENGTH; j++) {
		outbuf[2 * j] = (buf[j] >> 4) + 48;
		outbuf[2 * j + 1] = (buf[j] & 15) + 48;
		if (outbuf[2 * j] > 57)
			outbuf[2 * j] += 7;
		if (outbuf[2 * j + 1] > 57)
			outbuf[2 * j + 1] += 7;
	}
	outbuf[2 * j] = '\0';

	fprintf(stderr, "%s%s\n", specifier, outbuf);
}
#endif

#if HAVE_MBEDTLS
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER > 0x02070000
#define USE_SHA_RET 1
#else
#define USE_SHA_RET 0
#endif

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#include <mbedtls/compat-2.x.h>
#endif

int _librist_srp_mbedtls_wrap_random(void *unused, unsigned char * buf, size_t size) {
	RIST_MARK_UNUSED(unused);
	return _librist_crypto_ramdom_get_bytes(buf, size);
}

#define BIGNUM mbedtls_mpi
#define BIGNUM_INIT(num) mbedtls_mpi_init(num)
#define BIGNUM_FREE(num) mbedtls_mpi_free(num)
#define BIGNUM_GET_BINARY_SIZE(num) mbedtls_mpi_size(num)
#define BIGNUM_FROM_ARRAY(num, array, size) ret = mbedtls_mpi_read_binary(num, array, size)
#define BIGNUM_FROM_STRING(num, str) ret = mbedtls_mpi_read_string(num, 16, str)
#if MBEDTLS_HAS_MPI_RANDOM
#define BIGNUM_RANDOM(num, max) ret = mbedtls_mpi_random(num, 0, max, _librist_srp_mbedtls_wrap_random, NULL);
#else
#define BIGNUM_RANDOM(num, max) ret = mbedtls_mpi_fill_random(num, 32, _librist_srp_mbedtls_wrap_random, NULL);
#endif
#define BIGNUM_MOD_RED(out, a, b) ret = mbedtls_mpi_mod_mpi(out, a, b)
#define BIGNUM_EXP_MOD(out, base, exp, mod) ret = mbedtls_mpi_exp_mod(out, base, exp, mod, NULL)
#define BIGNUM_MULT_BIG(prod, a, b) ret = mbedtls_mpi_mul_mpi(prod, a, b)
#define BIGNUM_ADD_BIG(prod, a, b) ret = mbedtls_mpi_add_mpi(prod, a, b)
#define BIGNUM_SUB_BIG(prod, a, b) ret = mbedtls_mpi_sub_mpi(prod, a, b)
#define BIGNUM_EQUALS(num, comp) (mbedtls_mpi_cmp_int(num, comp) == 0)
#define BIGNUM_WRITE_BYTES(num, bytes, bytes_size) if (mbedtls_mpi_write_binary(num, bytes, bytes_size) != 0) {return -1; }
#define BIGNUM_WRITE_BYTES_ALLOC(num, bytes_pp, len_p, lbl) do {\
	*len_p = mbedtls_mpi_size(num); \
	*bytes_pp = malloc(*len_p); \
	if (!*bytes_pp) { goto lbl; } \
	if (mbedtls_mpi_write_binary(num, *bytes_pp, *len_p) != 0) {goto lbl; } \
} while(false)
#define BIGNUM_PRINT(prefix, num) mbedtls_mpi_write_file(prefix, num, 16, stderr)
#define HASH_CONTEXT mbedtls_sha256_context

void librist_crypto_srp_mbedtls_hash_init(HASH_CONTEXT *ctx, bool correct_init) {
    mbedtls_sha256_init(ctx);
	if (correct_init) {
#if USE_SHA_RET
		mbedtls_sha256_starts_ret(ctx, 0);
#else
		mbedtls_sha256_starts(ctx, 0);
#endif
	}
}

#define HASH_CONTEXT_INIT(ctx, correct) librist_crypto_srp_mbedtls_hash_init(ctx, correct)
#define HASH_CONTEXT_FREE(ctx) mbedtls_sha256_free(ctx)

#elif HAVE_NETTLE
#include <nettle/sha2.h>
#include <nettle/bignum.h>
#define BIGNUM MP_INT
#define BIGNUM_INIT(num) mpz_init(num)
#define BIGNUM_FREE(num) mpz_clear(num)
#define BIGNUM_GET_BINARY_SIZE(num) ((mpz_sizeinbase(num, 2) +7) /8)
#define BIGNUM_FROM_ARRAY(num, array, size) mpz_import(num, size, 1, 1, 0, 0, array)
#define BIGNUM_FROM_STRING(num, str) ret = mpz_set_str(num, str, 16)
#define BIGNUM_RANDOM(num, max) nettle_mpz_random(num, NULL, _librist_srp_nettle_wrap_random, max);
#define BIGNUM_MOD_RED(out, a, b) mpz_mod(out, a, b)
#define BIGNUM_EXP_MOD(out, base, exp, mod) mpz_powm(out, base, exp, mod)
#define BIGNUM_MULT_BIG(prod, a, b) mpz_mul(prod, a, b)
#define BIGNUM_ADD_BIG(prod, a, b) mpz_add(prod, a, b)
#define BIGNUM_SUB_BIG(prod, a, b) mpz_sub(prod, a, b)
#define BIGNUM_EQUALS(num, comp) (mpz_cmp_ui(num, comp) == 0)
#define BIGNUM_WRITE_BYTES(num, bytes, bytes_size) mpz_export(bytes, NULL, 1, 1, 0, 0, num)
#define BIGNUM_WRITE_BYTES_ALLOC(num, bytes_pp, len_p, lbl) do {\
	*bytes_pp = mpz_export(NULL, len_p, 1, 1, 0, 0, num); \
	if (!*bytes_pp) { goto lbl; } \
} while (false)
#define BIGNUM_PRINT(prefix, num) do { \
	fprintf(stderr, prefix); \
	mpz_out_str(stderr, 16, num); \
	fprintf(stderr, "\n"); \
} while(false)
#define HASH_CONTEXT struct sha256_ctx
#define HASH_CONTEXT_INIT(ctx, correct) (void)(correct); nettle_sha256_init(ctx)
#define HASH_CONTEXT_FREE(ctx)

void _librist_srp_nettle_wrap_random(void *unused, size_t size, uint8_t* buf) {
	RIST_MARK_UNUSED(unused);
	_librist_crypto_ramdom_get_bytes(buf, size);
}

#endif

static int librist_crypto_srp_hash_update(HASH_CONTEXT *hash_ctx, const void *data, size_t len)
{
#if HAVE_MBEDTLS
#if !USE_SHA_RET
	mbedtls_sha256_update( hash_ctx, data, len );
#else
	return mbedtls_sha256_update_ret( hash_ctx, data, len );
#endif
#else
	nettle_sha256_update( hash_ctx, len, data);
	return 0;
#endif
}

static int librist_crypto_srp_hash_update_bignum(HASH_CONTEXT *hash_ctx, const BIGNUM *num) {
	uint8_t bytes[1024];
	size_t size = BIGNUM_GET_BINARY_SIZE(num);
	if (size > sizeof(bytes))
		return -1;

	BIGNUM_WRITE_BYTES(num, bytes, size);

	return librist_crypto_srp_hash_update(hash_ctx, bytes, size);
}

static int librist_crypto_srp_hash_final(HASH_CONTEXT *hash_ctx, uint8_t *data)
{
#if HAVE_MBEDTLS
#if !USE_SHA_RET
	mbedtls_sha256_finish( hash_ctx, data);
#else
	return mbedtls_sha256_finish_ret( hash_ctx, data);
#endif
#else
	nettle_sha256_digest( hash_ctx, SHA256_DIGEST_LENGTH, data);
#endif
	return 0;
}

static int librist_crypto_srp_hash(const uint8_t *indata, size_t inlen, uint8_t outdata[SHA256_DIGEST_LENGTH])
{
#if HAVE_MBEDTLS
#if !USE_SHA_RET
	mbedtls_sha256(hash_data, salt_len + SHA256_DIGEST_LENGTH, x_hash, 0)
#else
	return mbedtls_sha256_ret(indata, inlen, outdata, 0);
#endif
#else
	HASH_CONTEXT hash_ctx;
	HASH_CONTEXT_INIT(&hash_ctx, true);
	librist_crypto_srp_hash_update(&hash_ctx, indata, inlen);
	librist_crypto_srp_hash_final(&hash_ctx, outdata);
#endif
	return 0;
}

//Calculates the value of x as follows: x = SHA256(s, SHA256(I | “:” | P))
static int librist_crypto_srp_calc_x(BIGNUM *salt, const char * username, const char * password, size_t password_len, BIGNUM *x, bool correct)
{
	HASH_CONTEXT hash_ctx;
	HASH_CONTEXT_INIT(&hash_ctx, correct);
	int ret = 0;

	if (librist_crypto_srp_hash_update(&hash_ctx, username, strlen(username)) != 0)
		return -1;
	if (librist_crypto_srp_hash_update(&hash_ctx, ":", 1) != 0)
		return -1;
	if (librist_crypto_srp_hash_update(&hash_ctx, password, password_len) != 0)
		return -1;

	size_t salt_len = BIGNUM_GET_BINARY_SIZE(salt);
	uint8_t *hash_data = malloc(salt_len + SHA256_DIGEST_LENGTH);
	if (!hash_data)
		return -1;

	if (librist_crypto_srp_hash_final(&hash_ctx, &hash_data[salt_len]) != 0)
		goto failed;

	BIGNUM_WRITE_BYTES(salt, hash_data, salt_len);
	if (ret != 0)
		goto failed;

	HASH_CONTEXT_FREE(&hash_ctx);

	uint8_t x_hash[SHA256_DIGEST_LENGTH];

	if (librist_crypto_srp_hash( hash_data, salt_len + SHA256_DIGEST_LENGTH, x_hash) != 0)
		goto failed;

	BIGNUM_FROM_ARRAY(x, x_hash, SHA256_DIGEST_LENGTH);
	if (ret != 0)
		goto failed;

	free(hash_data);
	return 0;

failed:
	free(hash_data);
	return -1;
}

static int librist_crypto_srp_hash_2_bignum(BIGNUM *A, BIGNUM *B, uint8_t hash_out[SHA256_DIGEST_LENGTH])
{
	size_t A_size = BIGNUM_GET_BINARY_SIZE(A);
	size_t B_size = BIGNUM_GET_BINARY_SIZE(B);
	uint8_t AB[2048];

	if (A_size + B_size > sizeof(AB))
		return -1;
	BIGNUM_WRITE_BYTES(A, AB, A_size);
	BIGNUM_WRITE_BYTES(B, &AB[A_size], B_size);

	return librist_crypto_srp_hash(AB, A_size+B_size, hash_out);
}

static int librist_crypto_srp_hash_bignum(BIGNUM *in, uint8_t hash_out[SHA256_DIGEST_LENGTH])
{
	size_t size = BIGNUM_GET_BINARY_SIZE(in);
	uint8_t in_bytes[1024];
	if (size > sizeof(in_bytes))
		return -1;
	BIGNUM_WRITE_BYTES(in, in_bytes, size);
	return librist_crypto_srp_hash(in_bytes, size, hash_out);
}

static int librist_crypto_srp_calculate_m(BIGNUM *N, BIGNUM *g, const char *I, BIGNUM *s, BIGNUM *A, BIGNUM *B, const uint8_t K[SHA256_DIGEST_LENGTH], uint8_t m1_out[SHA256_DIGEST_LENGTH], bool correct) {
#if DEBUG_EXTRACT_SRP_EXCHANGE
	fprintf(stderr, "\n\n%s\n", __func__);
	fprintf(stderr, "DOING CORRECT? %d\n", correct);
	BIGNUM_PRINT("N: ", N);
	BIGNUM_PRINT("g: ", g);
	fprintf(stderr, "I: %s\n", I);
	BIGNUM_PRINT("s: ",s);
	BIGNUM_PRINT("A: ", A);
	BIGNUM_PRINT("B: ", B);
	print_hash(K, "K: ");
#endif
	uint8_t hash_tmp[SHA256_DIGEST_LENGTH];
	{
		uint8_t hash_N[SHA256_DIGEST_LENGTH];
		uint8_t hash_g[SHA256_DIGEST_LENGTH];

		librist_crypto_srp_hash_bignum(N, hash_N);
		librist_crypto_srp_hash_bignum(g, hash_g);

		for (size_t i=0; i < sizeof(hash_tmp); i++)
			hash_tmp[i] = hash_N[i] ^ hash_g[i];
	}

#if DEBUG_EXTRACT_SRP_EXCHANGE
	print_hash(hash_tmp, "XOR: ");
#endif


	int ret = -1;
	HASH_CONTEXT hash_ctx;
	HASH_CONTEXT_INIT(&hash_ctx, correct);

	if (librist_crypto_srp_hash_update(&hash_ctx, hash_tmp, sizeof(hash_tmp)) != 0)
		goto out;

	if (librist_crypto_srp_hash((const uint8_t *)I, strlen(I), hash_tmp) != 0)
		goto out;

	if (librist_crypto_srp_hash_update(&hash_ctx, hash_tmp, sizeof(hash_tmp)) != 0)
		goto out;

	if (librist_crypto_srp_hash_update_bignum(&hash_ctx, s) != 0)
		goto out;

	if (librist_crypto_srp_hash_update_bignum(&hash_ctx, A) != 0)
		goto out;

	if (librist_crypto_srp_hash_update_bignum(&hash_ctx, B) != 0)
		goto out;

	if (librist_crypto_srp_hash_update(&hash_ctx, K, SHA256_DIGEST_LENGTH) != 0)
		goto out;

	if (librist_crypto_srp_hash_final(&hash_ctx, m1_out) != 0)
		goto out;

	ret = 0;

#if DEBUG_EXTRACT_SRP_EXCHANGE
	print_hash(m1_out, "M1: ");
	fprintf(stderr, "\n\n");
#endif

out:
	HASH_CONTEXT_FREE(&hash_ctx);
	return ret;
}

static int librist_crypto_srp_calculate_m2(const BIGNUM *A,const uint8_t M1[SHA256_DIGEST_LENGTH],const uint8_t K[SHA256_DIGEST_LENGTH], uint8_t M2_OUT[SHA256_DIGEST_LENGTH], bool correct) {
	HASH_CONTEXT hash_ctx;
	HASH_CONTEXT_INIT(&hash_ctx, correct);
	int ret;
	ret = librist_crypto_srp_hash_update_bignum(&hash_ctx, A);
	if (ret != 0)
		goto out;

	ret = librist_crypto_srp_hash_update(&hash_ctx, M1, SHA256_DIGEST_LENGTH);
	if (ret != 0)
		goto out;

	ret = librist_crypto_srp_hash_update(&hash_ctx, K, SHA256_DIGEST_LENGTH);
	if (ret != 0)
		goto out;

	ret = librist_crypto_srp_hash_final(&hash_ctx, M2_OUT);

out:
	HASH_CONTEXT_FREE(&hash_ctx);

	return ret;
}


struct librist_crypto_srp_authenticator_ctx {
	//Static values once created
	BIGNUM N;
	BIGNUM g;
	BIGNUM v;
	BIGNUM s;

	//Supplied by client
	BIGNUM A;

	//Random number in range 0, N-1
	BIGNUM b;
	BIGNUM k;
	BIGNUM B;

	//Session key
	uint8_t key[SHA256_DIGEST_LENGTH];

	uint8_t m2[SHA256_DIGEST_LENGTH];

	bool correct_hashing_init;
};

struct librist_crypto_srp_authenticator_ctx *librist_crypto_srp_authenticator_ctx_create(const char* n_hex, const char *g_hex, const uint8_t *v_bytes, size_t v_len, const uint8_t *s_bytes, size_t s_len, bool correct) {
	if (!v_bytes || !s_bytes || v_len == 0 || s_len == 0)
		return NULL;
	struct librist_crypto_srp_authenticator_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->correct_hashing_init = correct;
	BIGNUM_INIT(&ctx->N);
	BIGNUM_INIT(&ctx->g);
	BIGNUM_INIT(&ctx->v);
	BIGNUM_INIT(&ctx->s);

	int ret = 0;
	BIGNUM_FROM_STRING(&ctx->N, n_hex);
	if (ret != 0)
		goto fail;

	BIGNUM_FROM_STRING(&ctx->g, g_hex);
	if (ret != 0)
		goto fail;

	BIGNUM_FROM_ARRAY(&ctx->v, v_bytes, v_len);
	if (ret != 0)
		goto fail;

	BIGNUM_FROM_ARRAY(&ctx->s, s_bytes, s_len);
	if (ret != 0)
		goto fail;


	BIGNUM_INIT(&ctx->A);
	BIGNUM_INIT(&ctx->b);
	return ctx;

fail:
	BIGNUM_FREE(&ctx->N);
	BIGNUM_FREE(&ctx->g);
	BIGNUM_FREE(&ctx->v);
	BIGNUM_FREE(&ctx->s);
	free(ctx);
	return NULL;
}

void librist_crypto_srp_authenticator_ctx_free(struct librist_crypto_srp_authenticator_ctx *ctx) {
	if (ctx == NULL)
		return;
	BIGNUM_FREE(&ctx->N);
	BIGNUM_FREE(&ctx->g);
	BIGNUM_FREE(&ctx->v);
	BIGNUM_FREE(&ctx->s);

	BIGNUM_FREE(&ctx->A);
	BIGNUM_FREE(&ctx->b);
	BIGNUM_FREE(&ctx->k);
	BIGNUM_FREE(&ctx->B);

	free(ctx);
}

int librist_crypto_srp_authenticator_write_g_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t *g_buf, size_t g_buf_len) {
	size_t size = BIGNUM_GET_BINARY_SIZE(&ctx->g);
	if (g_buf_len < size)
		return -1;

	BIGNUM_WRITE_BYTES(&ctx->g, g_buf, size);
	return (int)size;
}

int librist_crypto_srp_authenticator_write_n_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t *n_buf, size_t n_buf_len) {
	size_t size = BIGNUM_GET_BINARY_SIZE(&ctx->N);
	if (n_buf_len < size)
		return -1;

	BIGNUM_WRITE_BYTES(&ctx->N, n_buf, size);
	return (int)size;
}

int librist_crypto_srp_authenticator_write_B_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t* B_buf, size_t B_buf_len) {
	size_t size = BIGNUM_GET_BINARY_SIZE(&ctx->B);
	if (B_buf_len < size)
		return -1;

	BIGNUM_WRITE_BYTES(&ctx->B, B_buf, size);
	return (int)size;
}

void librist_crypto_srp_authenticator_write_M2_bytes(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t* m2_buf) {
	memcpy(m2_buf, ctx->m2, sizeof(ctx->m2));
}

const uint8_t *librist_crypto_srp_authenticator_get_key(struct librist_crypto_srp_authenticator_ctx *ctx) {
	return ctx->key;
}

//We received A, verify that it's secure, set b and then calculate:
//k=SHA256(N,g)
//B=(kv + g^b) % N
int librist_crypto_srp_authenticator_handle_A(struct librist_crypto_srp_authenticator_ctx *ctx, uint8_t *A_buf, size_t A_buf_len) {
	int ret = 0;
	BIGNUM_FROM_ARRAY(&ctx->A, A_buf, A_buf_len);
	if (ret != 0)
		return -1;

	BIGNUM tmp;
	BIGNUM_INIT(&tmp);
	BIGNUM_MOD_RED(&tmp, &ctx->A, &ctx->N);
	if (ret != 0)
		goto out;

	if (BIGNUM_EQUALS(&tmp, 0))
		goto out;



	//Set b
#if DEBUG_USE_EXAMPLE_CONSTANTS
	const char b_hex[] = "ED0D58FF861A1FC75A0829BEA5F1392D2B13AB2B05CBCD6ED1E71AAAD761E856";
	BIGNUM_FROM_STRING(&ctx->b, b_hex);
#else
	BIGNUM_RANDOM(&ctx->b, &ctx->N);
	if (ret != 0)
		goto out;
#endif


	//calc k
	uint8_t k_hash[SHA256_DIGEST_LENGTH];
	librist_crypto_srp_hash_2_bignum(&ctx->N, &ctx->g, k_hash);
	BIGNUM_FROM_ARRAY(&ctx->k, k_hash, sizeof(k_hash));
	if (ret != 0)
		goto out;

	BIGNUM tmp2;
	BIGNUM_INIT(&tmp2);

	//calc B
	BIGNUM_MULT_BIG(&tmp, &ctx->k, &ctx->v);
	if (ret != 0)
		goto b_out;

	BIGNUM_EXP_MOD(&tmp2, &ctx->g, &ctx->b, &ctx->N);
	if (ret != 0)
		goto b_out;

	BIGNUM_ADD_BIG(&tmp, &tmp, &tmp2);
	if (ret != 0)
		goto b_out;

	BIGNUM_MOD_RED(&ctx->B, &tmp, &ctx->N);
	if (ret != 0)
		goto b_out;

#if DEBUG_EXTRACT_SRP_EXCHANGE
	fprintf(stderr, "%s\n", __func__);
	BIGNUM_PRINT("b: ", &ctx->b);
	BIGNUM_PRINT("k: ", &ctx->k);
	BIGNUM_PRINT("B: ", &ctx->B);
#endif


b_out:
	BIGNUM_FREE(&tmp2);

out:
	BIGNUM_FREE(&tmp);
	return ret;
}

//Calculate M1 & verify against client supplied M1 value
//u = SHA256(A, B)
//S = ((Av^u) ^ b) % N
//K = SHA256(S)
//M1 = SHA256(SHA256(N) xor SHA256(g), SHA256(I, s, A, B, K)
//Verify that client supplied M1 matches our calculation
//Then calculate M2:
//M2 = SHA256(A, M1, K)
int librist_crypto_srp_authenticator_verify_m1(struct librist_crypto_srp_authenticator_ctx *ctx, const char *username,  uint8_t *client_m1_buf) {
	uint8_t u_hash[SHA256_DIGEST_LENGTH];
	if (librist_crypto_srp_hash_2_bignum(&ctx->A, &ctx->B, u_hash) != 0) {
		return -1;
	}

	int ret = 0;
	BIGNUM u;
	BIGNUM tmp1;
	BIGNUM tmp2;
	BIGNUM_INIT(&u);
	BIGNUM_INIT(&tmp1);
	BIGNUM_INIT(&tmp2);

	BIGNUM_FROM_ARRAY(&u, u_hash, sizeof(u_hash));
	if (ret != 0)
		goto out;

	BIGNUM_EXP_MOD(&tmp1, &ctx->v, &u, &ctx->N);
	if (ret != 0)
		goto out;

	BIGNUM_MULT_BIG(&tmp2, &ctx->A, &tmp1);
	if (ret != 0)
		goto out;

	//tmp1 -> S
	BIGNUM_EXP_MOD(&tmp1, &tmp2, &ctx->b, &ctx->N);

    librist_crypto_srp_hash_bignum(&tmp1, ctx->key);

#if DEBUG_EXTRACT_SRP_EXCHANGE
    fprintf(stderr, "%s\n", __func__);
    BIGNUM_PRINT("u: ", &u);
    BIGNUM_PRINT("S: ", &tmp1);
	print_hash(ctx->key, "K: ");
#endif

	uint8_t m1_buf[SHA256_DIGEST_LENGTH];
	ret = librist_crypto_srp_calculate_m(&ctx->N, &ctx->g, username, &ctx->s, &ctx->A, &ctx->B, ctx->key, m1_buf, ctx->correct_hashing_init);
	if (ret != 0)
		goto out;

#if DEBUG_EXTRACT_SRP_EXCHANGE
	print_hash(m1_buf, "M1: ");
#endif

	ret = memcmp(m1_buf, client_m1_buf, sizeof(m1_buf));
	if (ret != 0)
		goto out;

	ret = librist_crypto_srp_calculate_m2(&ctx->A, m1_buf, ctx->key, ctx->m2, ctx->correct_hashing_init);

#if DEBUG_EXTRACT_SRP_EXCHANGE
	print_hash(ctx->key, "M2: ");
#endif
out:
	BIGNUM_FREE(&u);
	BIGNUM_FREE(&tmp1);
	BIGNUM_FREE(&tmp2);

	return ret;
}

struct librist_crypto_srp_client_ctx {
	//Static values once created
	BIGNUM N;
	BIGNUM g;
	BIGNUM s;
	BIGNUM a;
	BIGNUM A;

	//Supplied by server
	BIGNUM B;

	BIGNUM k;

	//Session key
	uint8_t key[SHA256_DIGEST_LENGTH];

	uint8_t m1[SHA256_DIGEST_LENGTH];

	bool correct_hashing_init;
};

int librist_crypto_srp_client_write_A_bytes(struct librist_crypto_srp_client_ctx *ctx, uint8_t *A_buf, size_t A_buf_len) {
	size_t size = BIGNUM_GET_BINARY_SIZE(&ctx->A);
	if (A_buf_len < size)
		return -1;

	BIGNUM_WRITE_BYTES(&ctx->A, A_buf, size);
	return (int)size;
}

void librist_crypto_srp_client_write_M1_bytes(struct librist_crypto_srp_client_ctx *ctx, uint8_t M1_buf[SHA256_DIGEST_LENGTH]) {
	memcpy(M1_buf, ctx->m1, sizeof(ctx->m1));
}


//We've received B from the server so now we compute:
//x = SHA256(s, SHA256(I, “:”, P))
//k = SHA256(N, g)
//u = SHA256(A, B)
//S = ((B – kg^x) ^ (a +ux)) % N
//K = SHA256(S)
//M1 = SHA256(SHA256(N) xor SHA256(g), SHA256(I, s, A, B, K))
int librist_crypto_srp_client_handle_B(struct librist_crypto_srp_client_ctx *ctx, uint8_t *B_bytes, size_t B_len, const char *username, const char *password) {
	int ret = 0;

	BIGNUM_FROM_ARRAY(&ctx->B, B_bytes, B_len);
	if (ret != 0)
		return -1;

	BIGNUM u;
	BIGNUM x;
	BIGNUM tmp1;
	BIGNUM tmp2;
	BIGNUM tmp3;
	BIGNUM tmp4;

	BIGNUM_INIT(&u);
	BIGNUM_INIT(&x);
	BIGNUM_INIT(&tmp1);
	BIGNUM_INIT(&tmp2);
	BIGNUM_INIT(&tmp3);
	BIGNUM_INIT(&tmp4);

	//Safety check: exit early if B mod N equals 0
	BIGNUM_MOD_RED(&tmp1, &ctx->B, &ctx->N);
	if (ret != 0)
		goto out;

	if (BIGNUM_EQUALS(&tmp1, 0))
		goto out;

	//Calculate u & execute safety check
	{
		uint8_t u_hash[SHA256_DIGEST_LENGTH];
		ret =librist_crypto_srp_hash_2_bignum(&ctx->A, &ctx->B, u_hash);
		if (ret != 0)
			goto out;


		BIGNUM_FROM_ARRAY(&u, u_hash, sizeof(u_hash));
		//Safety check: exit early if u mod N equals 0
		BIGNUM_MOD_RED(&tmp1, &u, &ctx->N);
		if (ret != 0)
			goto out;

		if (BIGNUM_EQUALS(&tmp1, 0))
			goto out;
	}

	//Calculate k
	{
		uint8_t k_hash[SHA256_DIGEST_LENGTH];
		ret = librist_crypto_srp_hash_2_bignum(&ctx->N, &ctx->g, k_hash);
		if (ret != 0)
			goto out;

		BIGNUM_FROM_ARRAY(&tmp4, k_hash, sizeof(k_hash));
	}

	ret = librist_crypto_srp_calc_x(&ctx->s, username, password, strlen(password), &x, ctx->correct_hashing_init);
	if (ret != 0)
		goto out;

#if DEBUG_EXTRACT_SRP_EXCHANGE
	fprintf(stderr, "%s\n", __func__);
    BIGNUM_PRINT("u: ", &u);
    BIGNUM_PRINT("k: ", &tmp4);
    BIGNUM_PRINT("x: ", &x);
#endif

	//Calculate 'v' (g^x)
	BIGNUM_EXP_MOD(&tmp2, &ctx->g, &x, &ctx->N);
	if (ret != 0)
		goto out;

	// k (tmp4) * g^x (tmp2)
	BIGNUM_MULT_BIG(&tmp3, &tmp4, &tmp2);
	if (ret != 0)
		goto out;

	// B - kg^x (tmp3)
	BIGNUM_SUB_BIG(&tmp1, &ctx->B, &tmp3);
	if (ret != 0)
		goto out;

	//u * x
	BIGNUM_MULT_BIG(&tmp3, &u, &x);
	if (ret != 0)
		goto out;

	//a + ux (tmp3)
	BIGNUM_ADD_BIG(&tmp2, &ctx->a, &tmp3);
	if (ret != 0)
		goto out;

	//S = ((B – kg^x) (tmp1) ^ (a +ux)) (tmp2) % N
	BIGNUM_EXP_MOD(&tmp3, &tmp1, &tmp2, &ctx->N);
	if (ret != 0)
		goto out;

	ret = librist_crypto_srp_hash_bignum(&tmp3, ctx->key);
	if (ret != 0)
		goto out;

#if DEBUG_EXTRACT_SRP_EXCHANGE
    BIGNUM_PRINT("S: ", &tmp3);
    print_hash(ctx->key, "K: ");
#endif

	ret = librist_crypto_srp_calculate_m(&ctx->N, &ctx->g, username, &ctx->s, &ctx->A, &ctx->B, ctx->key, ctx->m1, ctx->correct_hashing_init);

out:
	BIGNUM_FREE(&u);
	BIGNUM_FREE(&x);
	BIGNUM_FREE(&tmp4);
	BIGNUM_FREE(&tmp1);
	BIGNUM_FREE(&tmp2);
	BIGNUM_FREE(&tmp3);
	return ret;
}

int librist_crypto_srp_client_verify_m2(struct librist_crypto_srp_client_ctx *ctx, uint8_t *m2) {
	uint8_t calc_m2[SHA256_DIGEST_LENGTH];
	int ret = librist_crypto_srp_calculate_m2(&ctx->A, ctx->m1, ctx->key, calc_m2, ctx->correct_hashing_init);
	if (ret != 0)
		return ret;

	return memcmp(m2, calc_m2, sizeof(calc_m2));
}

const uint8_t *librist_crypto_srp_client_get_key(struct librist_crypto_srp_client_ctx *ctx) {
	return ctx->key;
}

struct librist_crypto_srp_client_ctx *librist_crypto_srp_client_ctx_create(bool default_ng, uint8_t *N_bytes, size_t N_len, uint8_t *g_bytes, size_t g_len, uint8_t *s_bytes, size_t s_len, bool correct) {
	if (!s_bytes || s_len == 0 || (!default_ng && (!N_bytes || N_len == 0 || !g_bytes || g_len == 0)))
		return NULL;

	struct librist_crypto_srp_client_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->correct_hashing_init = correct;
	BIGNUM_INIT(&ctx->N);
	BIGNUM_INIT(&ctx->g);
	BIGNUM_INIT(&ctx->s);
	BIGNUM_INIT(&ctx->a);
	BIGNUM_INIT(&ctx->A);
	BIGNUM_INIT(&ctx->B);
	BIGNUM_INIT(&ctx->k);

	int ret = 0;
	BIGNUM_FROM_ARRAY(&ctx->s, s_bytes, s_len);
	if (ret != 0)
		goto fail;

	if (default_ng) {
		const char *N = NULL;
		const char *g = NULL;
		librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &N, &g);
		BIGNUM_FROM_STRING(&ctx->N, N);
		if (ret != 0)
			goto fail;

		BIGNUM_FROM_STRING(&ctx->g, g);
		if (ret != 0)
			goto fail;
	} else {
		BIGNUM_FROM_ARRAY(&ctx->g, g_bytes,g_len);
		if (ret != 0)
			goto fail;

		BIGNUM_FROM_ARRAY(&ctx->N, N_bytes, N_len);
		if (ret != 0)
			goto fail;
	}

#if DEBUG_USE_EXAMPLE_CONSTANTS
	const char a_hex[] = "138AB4045633AD14961CB1AD0720B1989104151C0708794491113302CCCC27D5";
	BIGNUM_FROM_STRING(&ctx->a, a_hex);
#else
	BIGNUM_RANDOM(&ctx->a, &ctx->N);
	if (ret != 0)
		goto fail;
#endif

	BIGNUM_EXP_MOD(&ctx->A, &ctx->g, &ctx->a, &ctx->N);
	if (ret != 0)
		goto fail;

#if DEBUG_EXTRACT_SRP_EXCHANGE
	fprintf(stderr, "%s\n", __func__);
	BIGNUM_PRINT("N: ", &ctx->N);
	BIGNUM_PRINT("g: ", &ctx->g);
	BIGNUM_PRINT("s: ", &ctx->s);
	BIGNUM_PRINT("a: ", &ctx->a);
	BIGNUM_PRINT("A: ", &ctx->A);
#endif

	return ctx;
fail:
	librist_crypto_srp_client_ctx_free(ctx);
	return NULL;
}

void librist_crypto_srp_client_ctx_free(struct librist_crypto_srp_client_ctx *ctx) {
	if (!ctx)
		return;
	BIGNUM_FREE(&ctx->N);
	BIGNUM_FREE(&ctx->g);
	BIGNUM_FREE(&ctx->s);
	BIGNUM_FREE(&ctx->a);
	BIGNUM_FREE(&ctx->A);
	BIGNUM_FREE(&ctx->B);
	BIGNUM_FREE(&ctx->k);

	free(ctx);
}

//Creates a verifier & salt as follows:
//salt 32 byte random
//v: v = g^x
int librist_crypto_srp_create_verifier(
    const char *n_hex, const char *g_hex,
	const char *username, const char *password,
	unsigned char **bytes_s, size_t *len_s,
	unsigned char **bytes_v, size_t *len_v,
	bool correct)

{
	if (*bytes_s != NULL || *bytes_v != NULL)
		return -1;

	int ret = 0;
	BIGNUM s;
	BIGNUM v;
	BIGNUM x;
	BIGNUM n;
	BIGNUM g;

	BIGNUM_INIT(&s);
	BIGNUM_INIT(&v);
	BIGNUM_INIT(&x);
	BIGNUM_INIT(&n);
	BIGNUM_INIT(&g);

	BIGNUM_FROM_STRING(&n, n_hex);
	if (ret != 0)
		goto failed;

	BIGNUM_FROM_STRING(&g, g_hex);
	if (ret != 0)
		goto failed;

	//Fill the salt
#if DEBUG_USE_EXAMPLE_CONSTANTS
	const char salt_hex[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
	BIGNUM_FROM_STRING(&s, salt_hex);
#else
#if HAVE_MBEDTLS
	mbedtls_mpi_fill_random(&s, 32, _librist_srp_mbedtls_wrap_random, NULL);
#elif HAVE_NETTLE
	nettle_mpz_random_size(&s, NULL, _librist_srp_nettle_wrap_random, 8 * 32);
#endif
	if (ret != 0)
		goto failed;
#endif

	// Calculate x
	if (librist_crypto_srp_calc_x(&s, username, password, strlen(password),
									&x, correct) != 0) goto failed;

	BIGNUM_EXP_MOD(&v, &g, &x, &n);
	if (ret != 0)
		goto failed;

	BIGNUM_WRITE_BYTES_ALLOC(&s, bytes_s, len_s, failed);
	BIGNUM_WRITE_BYTES_ALLOC(&v, bytes_v, len_v, failed);

#if DEBUG_EXTRACT_SRP_EXCHANGE
	fprintf(stderr, "%s\n", __func__);
	BIGNUM_PRINT("N: ", &n);
	BIGNUM_PRINT("G: ", &g);
	BIGNUM_PRINT("s: ", &s);
	BIGNUM_PRINT("v: ", &v);
	BIGNUM_PRINT("x: ", &x);
#endif

	BIGNUM_FREE(&s);
	BIGNUM_FREE(&v);
	BIGNUM_FREE(&x);
	BIGNUM_FREE(&n);
	BIGNUM_FREE(&g);
	return 0;

failed:
	BIGNUM_FREE(&s);
	BIGNUM_FREE(&v);
	BIGNUM_FREE(&x);
	BIGNUM_FREE(&n);
	BIGNUM_FREE(&g);

	free(*bytes_s);
	free(*bytes_v);

	return -1;
}
