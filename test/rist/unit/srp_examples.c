//This set of unit tests covers the entire SRP flow verified against the example in the VSF document

#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <assert.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include "librist/librist_config.h"

#include "src/crypto/srp.h"
#include "src/crypto/srp_constants.h"
#define DEBUG_USE_EXAMPLE_CONSTANTS 1

#if HAVE_MBEDTLS
// musl's sched.h includes a prototype for calloc, so we need to make
// sure it's already been included before we redefine it to something
// that won't expand to a valid prototype.
#include <sched.h>

#define malloc(size) _test_malloc(size, __FILE__, __LINE__)
#define calloc(num, size) _test_calloc(num, size, __FILE__, __LINE__)
#define free(obj) _test_free(obj, __FILE__, __LINE__)
#endif

#include "src/crypto/srp.c"
#include "src/crypto/srp_constants.c"

static void hexstr_to_uint(const char *hexstr, uint8_t *buf, size_t buf_len) {
	for (size_t i = 0, j = 0; j < buf_len; i += 2, j++)
		buf[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
}

static void uint_to_hex(const uint8_t *buf, size_t buf_len, char *outbuf) {
	size_t j;
	for (j = 0; j < buf_len; j++) {
		outbuf[2 * j] = (buf[j] >> 4) + 48;
		outbuf[2 * j + 1] = (buf[j] & 15) + 48;
		if (outbuf[2 * j] > 57)
			outbuf[2 * j] += 7;
		if (outbuf[2 * j + 1] > 57)
			outbuf[2 * j + 1] += 7;
	}
	outbuf[2 * j] = '\0';
}

struct srp_test_state {
	const char *n;
	const char *g;
	uint8_t *salt;
	size_t salt_len;
	uint8_t *incorrect_hash_verifier;
	uint8_t *correct_hash_verifier;
	size_t verifier_len;
	struct librist_crypto_srp_authenticator_ctx *wrong_hash_authenticator;
	struct librist_crypto_srp_authenticator_ctx *correct_hash_authenticator;
	struct librist_crypto_srp_client_ctx *wrong_hash_client;
	struct librist_crypto_srp_client_ctx *correct_hash_client;
};

static int srp_test_state_setup(void **state) {
	*state = calloc(sizeof(struct srp_test_state), 1);
	struct srp_test_state *s = *state;
	librist_get_ng_constants(LIBRIST_SRP_NG_512, &s->n, &s->g);
#if HAVE_MBEDTLS
	librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &s->salt, &s->salt_len, &s->incorrect_hash_verifier, &s->verifier_len, false);
	s->wrong_hash_authenticator = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->incorrect_hash_verifier, s->verifier_len, s->salt, s->salt_len, false);
	size_t v_len = s->verifier_len;
	free(s->salt);
	s->salt = NULL;
#endif
	librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &s->salt, &s->salt_len, &s->correct_hash_verifier, &s->verifier_len, true);
#if HAVE_MBEDTLS
	assert(v_len == s->verifier_len);
#endif
	s->correct_hash_authenticator = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->correct_hash_verifier, s->verifier_len, s->salt, s->salt_len, true);


    const char N_hex[] = "D66AAFE8E245F9AC245A199F62CE61AB8FA90A4D80C71CD2ADFD0B9DA163B29F2A34AFBDB3B1B5D0102559CE63D8B6E86B0AA59C14E79D4AA62D1748E4249DF3";
	uint8_t N[(sizeof(N_hex) -1)/2];
	hexstr_to_uint(N_hex, N, sizeof(N));
	uint8_t g[1] = {0x02};
#if HAVE_MBEDTLS
	s->wrong_hash_client = librist_crypto_srp_client_ctx_create(false, N, sizeof(N), g, sizeof(g), s->salt, s->salt_len, false);
#endif
	s->correct_hash_client = librist_crypto_srp_client_ctx_create(false, N, sizeof(N), g, sizeof(g), s->salt, s->salt_len, true);
	return 0;
}

static int srp_test_state_teardown(void **state) {
	struct srp_test_state *s = *state;
	free(s->salt);
	free(s->incorrect_hash_verifier);
	free(s->correct_hash_verifier);
	librist_crypto_srp_authenticator_ctx_free(s->wrong_hash_authenticator);
	librist_crypto_srp_authenticator_ctx_free(s->correct_hash_authenticator);
	librist_crypto_srp_client_ctx_free(s->wrong_hash_client);
	librist_crypto_srp_client_ctx_free(s->correct_hash_client);
	free(s);
	return 0;
}

static void test_hash_func(void **state) {
	(void)(state);
	//expected hash gather via: `echo -n "rist:mainprofile" | sha256sum | awk '{print toupper($1)}'`
	const char expected_hash[] = "8427F6E0E69DC9B99DFE1052DDAF7E50D4FEA316C63C6AD23FE197C9C1DA2AF1";
	const char test_string[] = "rist:mainprofile";
	uint8_t hash_data[SHA256_DIGEST_LENGTH];
	assert_int_equal(librist_crypto_srp_hash((const uint8_t *)test_string, sizeof(test_string) -1, hash_data), 0);
	char outhash[sizeof(expected_hash)];
	uint_to_hex(hash_data, sizeof(hash_data), outhash);
	assert_string_equal(outhash, expected_hash);
}

static void test_hash_update_func(void **state) {
	(void)(state);
	const char expected_hash[] = "8427F6E0E69DC9B99DFE1052DDAF7E50D4FEA316C63C6AD23FE197C9C1DA2AF1";
	HASH_CONTEXT ctx;
	HASH_CONTEXT_INIT(&ctx, true);
	assert_int_equal(librist_crypto_srp_hash_update(&ctx, "rist", strlen("rist")), 0);
	assert_int_equal(librist_crypto_srp_hash_update(&ctx, ":", 1), 0);
	assert_int_equal(librist_crypto_srp_hash_update(&ctx, "mainprofile", strlen("mainprofile")), 0);
	uint8_t hash_data[SHA256_DIGEST_LENGTH];
	assert_int_equal(librist_crypto_srp_hash_final(&ctx, hash_data), 0);
	char outhash[sizeof(expected_hash)];
	uint_to_hex(hash_data, sizeof(hash_data), outhash);
	assert_string_equal(outhash, expected_hash);
}

static void test_get_default_ng(void **state) {
	(void)(state);
	const char *n = NULL;
	const char *g = NULL;
	assert_int_equal(librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &n, &g), 0);
	assert_string_equal(n,
		"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
   		"A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
		"95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
		"747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
		"8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
		"60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
		"FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
	);
   	assert_string_equal(g, "2");

	//This N,g pair is used in the VSF example flow.
	n = NULL;
	g = NULL;
	assert_int_equal(librist_get_ng_constants(LIBRIST_SRP_NG_512, &n, &g), 0);
	assert_string_equal(n, "D66AAFE8E245F9AC245A199F62CE61AB8FA90A4D80C71CD2ADFD0B9DA163B29F2A34AFBDB3B1B5D0102559CE63D8B6E86B0AA59C14E79D4AA62D1748E4249DF3");
	assert_string_equal(g, "2");
}

#if HAVE_MBEDTLS
static void test_srp_wrong_hashing_verifier_create(void **state) {
	struct srp_test_state *s = *state;
	const char sample_salt[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
	const char sample_verifier[] = "557EA208F87A23C28936423EC16ABE6BD959933DFBEFC0B36EBD9335DE3997C97DDFA081D64CFBC6EFBFD5BE19F2ED9F77922FD7E88BBA6C6B310A9018EC4305";

	uint8_t *salt = NULL;
	size_t salt_len = 0;
	uint8_t *verifier = NULL;
	size_t verifier_len = 0;
	assert_int_equal(librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &salt, &salt_len, &verifier, &verifier_len, false), 0);

	assert_int_equal(verifier_len, (sizeof(sample_verifier) -1)/2);
	assert_int_equal(salt_len, (sizeof(sample_salt) -1)/2);

	char salt_hex[sizeof(sample_salt)];
	uint_to_hex(salt, salt_len, salt_hex);
	assert_string_equal(salt_hex, sample_salt);

	char verifier_hex[sizeof(sample_verifier)];
	uint_to_hex(verifier, verifier_len, verifier_hex);
	assert_string_equal(sample_verifier, verifier_hex);
	free(verifier);
	free(salt);
}

static void test_srp_wrong_hashing_auth_ctx_create(void **state) {
	struct srp_test_state *s = *state;
	struct librist_crypto_srp_authenticator_ctx * ctx = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->incorrect_hash_verifier, s->verifier_len, s->salt, s->salt_len, false);
	assert_non_null(ctx);

	const char well_known_n[] = "D66AAFE8E245F9AC245A199F62CE61AB8FA90A4D80C71CD2ADFD0B9DA163B29F2A34AFBDB3B1B5D0102559CE63D8B6E86B0AA59C14E79D4AA62D1748E4249DF3";
	uint8_t n[(sizeof(well_known_n) -1)/2];
	uint8_t g[1];

	assert_int_equal(librist_crypto_srp_authenticator_write_n_bytes(ctx, n, sizeof(n)), sizeof(n));
	assert_int_equal(librist_crypto_srp_authenticator_write_g_bytes(ctx, g, sizeof(g)), sizeof(g));

	char n_hex[sizeof(well_known_n)];
	char g_hex[sizeof("02")];

	uint_to_hex(n, sizeof(n), n_hex);
	assert_string_equal(n_hex, well_known_n);

	uint_to_hex(g, sizeof(g), g_hex);
	assert_string_equal(g_hex, "02");

	librist_crypto_srp_authenticator_ctx_free(ctx);
}

static void test_srp_wrong_hashing_auth_handle_A(void **state) {
	struct srp_test_state *s = *state;
	const char client_A_hex[] = "92C4CEFB95A1AE2E576A252B19273FD4613F44FDA4AC8CC84A089D5740756223943882BAD34CB55F35139CDDB60E0D19ACD2B884CFB27F53C8EA969269ABE014";
	uint8_t client_A[(sizeof(client_A_hex) -1)/2];
	hexstr_to_uint(client_A_hex, client_A, sizeof(client_A));
	assert_int_equal(librist_crypto_srp_authenticator_handle_A(s->wrong_hash_authenticator, client_A, sizeof(client_A)), 0);

	const char expected_B[] = "85CAE0C578E6927B78BEB173FB0F9BFC8ECB4C13542BB8BE3B0F3447B3764A234177E22D180DCAD21F33302248B7452916DC58ABD309C8A77440A228B8516A4E";

	uint8_t B[(sizeof(expected_B) -1)/2];
	assert_int_equal(librist_crypto_srp_authenticator_write_B_bytes(s->wrong_hash_authenticator, B, sizeof(B)), sizeof(B));

	char B_hex[sizeof(expected_B)];
	uint_to_hex(B, sizeof(B), B_hex);
	assert_string_equal(expected_B, B_hex);
}

static void test_srp_wrong_hashing_auth_verify_M1(void **state) {
	struct srp_test_state *s = *state;
	const char client_M1_hex[] = "EBFC2D79BEB3CBF7BA83C27E2B51524F8CD3F3B2C4804815AD2516D465DF80C9";
	uint8_t client_M1[(sizeof(client_M1_hex) -1)/2];
	hexstr_to_uint(client_M1_hex, client_M1, sizeof(client_M1));

	assert_int_equal(librist_crypto_srp_authenticator_verify_m1(s->wrong_hash_authenticator, "rist", client_M1), 0);

	const char expected_m2[] = "FB14D73B5ACBBA101E5A799F80EBCBB43D83890E23DED979110EEFF109C0441A";
	char m2_hex[sizeof(expected_m2)];
	uint8_t m2[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_authenticator_write_M2_bytes(s->wrong_hash_authenticator, m2);

	uint_to_hex(m2, sizeof(m2), m2_hex);

	assert_string_equal(m2_hex, expected_m2);
}
#endif

//Nothing in client creation relies on hashing, hence this test isn't doubled
static void test_srp_client_ctx_create(void **state) {
	(void)(state);
	const char salt_hex[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";

	uint8_t salt[(sizeof(salt_hex) -1)/2];
	hexstr_to_uint(salt_hex, salt, sizeof(salt));

	struct librist_crypto_srp_client_ctx *ctx = librist_crypto_srp_client_ctx_create(true, NULL, 0, NULL, 0, salt, sizeof(salt), true);
	assert_non_null(ctx);
	librist_crypto_srp_client_ctx_free(ctx);

    const char N_hex[] = "D66AAFE8E245F9AC245A199F62CE61AB8FA90A4D80C71CD2ADFD0B9DA163B29F2A34AFBDB3B1B5D0102559CE63D8B6E86B0AA59C14E79D4AA62D1748E4249DF3";
	uint8_t N[(sizeof(N_hex) -1)/2];
	hexstr_to_uint(N_hex, N, sizeof(N));
	uint8_t g[1] = {0x02};
	ctx = librist_crypto_srp_client_ctx_create(false, N, sizeof(N), g, sizeof(g), salt, sizeof(salt), true);

	const char expected_A[] = "92C4CEFB95A1AE2E576A252B19273FD4613F44FDA4AC8CC84A089D5740756223943882BAD34CB55F35139CDDB60E0D19ACD2B884CFB27F53C8EA969269ABE014";
	uint8_t A[(sizeof(expected_A)-1)/2];
	assert_int_equal(librist_crypto_srp_client_write_A_bytes(ctx, A, sizeof(A)), sizeof(A));

	char a_hex[sizeof(expected_A)];
	uint_to_hex(A, sizeof(A), a_hex);
	assert_string_equal(a_hex, expected_A);
	librist_crypto_srp_client_ctx_free(ctx);
}

#if HAVE_MBEDTLS

static void test_srp_wrong_hashing_client_handle_B(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_B[] = "85CAE0C578E6927B78BEB173FB0F9BFC8ECB4C13542BB8BE3B0F3447B3764A234177E22D180DCAD21F33302248B7452916DC58ABD309C8A77440A228B8516A4E";
	uint8_t B[(sizeof(server_B) -1)/2];
	hexstr_to_uint(server_B, B, sizeof(B));

	assert_int_equal(librist_crypto_srp_client_handle_B(ctx->wrong_hash_client, B, sizeof(B), "rist", "mainprofile"), 0);

	const char expected_M1[] = "EBFC2D79BEB3CBF7BA83C27E2B51524F8CD3F3B2C4804815AD2516D465DF80C9";
	uint8_t m1[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_client_write_M1_bytes(ctx->wrong_hash_client, m1);

	char m1_hex[sizeof(expected_M1)];
	uint_to_hex(m1, sizeof(m1), m1_hex);
	assert_string_equal(m1_hex, expected_M1);
}

static void test_srp_wrong_hashing_client_verify_M2(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_M2[] = "FB14D73B5ACBBA101E5A799F80EBCBB43D83890E23DED979110EEFF109C0441A";
	uint8_t M2[(sizeof(server_M2)-1)/2];
	hexstr_to_uint(server_M2, M2, sizeof(M2));
	assert_int_equal(librist_crypto_srp_client_verify_m2(ctx->wrong_hash_client, M2), 0);
}

#endif

static void test_srp_correct_hashing_verifier_create(void **state) {
	struct srp_test_state *s = *state;
	const char sample_salt[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
	const char sample_verifier[] = "2E06FEA163D6E9FF0FA7ED6C59233389D0DBA0C08C0F72F6DAD1E2A3D8B92A772F070439D1C11B87FA990D2DAF04EB830CC77D61ACC4B253297379CD8E6DC3AF";

	uint8_t *salt = NULL;
	size_t salt_len = 0;
	uint8_t *verifier = NULL;
	size_t verifier_len = 0;
	assert_int_equal(librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &salt, &salt_len, &verifier, &verifier_len, true), 0);

	assert_int_equal(verifier_len, (sizeof(sample_verifier) -1)/2);
	assert_int_equal(salt_len, (sizeof(sample_salt) -1)/2);

	char salt_hex[sizeof(sample_salt)];
	uint_to_hex(salt, salt_len, salt_hex);
	assert_string_equal(salt_hex, sample_salt);

	char verifier_hex[sizeof(sample_verifier)];
	uint_to_hex(verifier, verifier_len, verifier_hex);
	assert_string_equal(sample_verifier, verifier_hex);
	free(verifier);
	free(salt);
}

static void test_srp_correct_hashing_auth_ctx_create(void **state) {
	struct srp_test_state *s = *state;
	struct librist_crypto_srp_authenticator_ctx * ctx = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->correct_hash_verifier, s->verifier_len, s->salt, s->salt_len, true);
	assert_non_null(ctx);

	const char well_known_n[] = "D66AAFE8E245F9AC245A199F62CE61AB8FA90A4D80C71CD2ADFD0B9DA163B29F2A34AFBDB3B1B5D0102559CE63D8B6E86B0AA59C14E79D4AA62D1748E4249DF3";
	uint8_t n[(sizeof(well_known_n) -1)/2];
	uint8_t g[1];

	assert_int_equal(librist_crypto_srp_authenticator_write_n_bytes(ctx, n, sizeof(n)), sizeof(n));
	assert_int_equal(librist_crypto_srp_authenticator_write_g_bytes(ctx, g, sizeof(g)), sizeof(g));

	char n_hex[sizeof(well_known_n)];
	char g_hex[sizeof("02")];

	uint_to_hex(n, sizeof(n), n_hex);
	assert_string_equal(n_hex, well_known_n);

	uint_to_hex(g, sizeof(g), g_hex);
	assert_string_equal(g_hex, "02");

	librist_crypto_srp_authenticator_ctx_free(ctx);
}

static void test_srp_correct_hashing_auth_handle_A(void **state) {
	struct srp_test_state *s = *state;
	const char client_A_hex[] = "92C4CEFB95A1AE2E576A252B19273FD4613F44FDA4AC8CC84A089D5740756223943882BAD34CB55F35139CDDB60E0D19ACD2B884CFB27F53C8EA969269ABE014";
	uint8_t client_A[(sizeof(client_A_hex) -1)/2];
	hexstr_to_uint(client_A_hex, client_A, sizeof(client_A));
	assert_int_equal(librist_crypto_srp_authenticator_handle_A(s->correct_hash_authenticator, client_A, sizeof(client_A)), 0);

	const char expected_B[] = "858CDC811B5EEAA7F58C12767D309EBD2DF1D46F59EF5686052E6511CF853CA4E66910BDBD28CBEAE2F2DEE7F6BF3756757BD69E88D48C77B5371A82EF52AD84";

	uint8_t B[(sizeof(expected_B) -1)/2];
	assert_int_equal(librist_crypto_srp_authenticator_write_B_bytes(s->correct_hash_authenticator, B, sizeof(B)), sizeof(B));

	char B_hex[sizeof(expected_B)];
	uint_to_hex(B, sizeof(B), B_hex);
	assert_string_equal(expected_B, B_hex);
}

static void test_srp_correct_hashing_auth_verify_M1(void **state) {
	struct srp_test_state *s = *state;
	const char client_M1_hex[] = "E28147C801BAB9C37647C1FF4A29FA720E3F5676434FB85EA9A752CC1F9B1AD4";
	uint8_t client_M1[(sizeof(client_M1_hex) -1)/2];
	hexstr_to_uint(client_M1_hex, client_M1, sizeof(client_M1));

	assert_int_equal(librist_crypto_srp_authenticator_verify_m1(s->correct_hash_authenticator, "rist", client_M1), 0);

	const char expected_m2[] = "84F19797916FBDCAB1321CA78B575B145B586150248AFAA156361B8BCB139B32";
	char m2_hex[sizeof(expected_m2)];
	uint8_t m2[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_authenticator_write_M2_bytes(s->correct_hash_authenticator, m2);

	uint_to_hex(m2, sizeof(m2), m2_hex);

	assert_string_equal(m2_hex, expected_m2);
}

static void test_srp_correct_hashing_client_handle_B(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_B[] = "858CDC811B5EEAA7F58C12767D309EBD2DF1D46F59EF5686052E6511CF853CA4E66910BDBD28CBEAE2F2DEE7F6BF3756757BD69E88D48C77B5371A82EF52AD84";
	uint8_t B[(sizeof(server_B) -1)/2];
	hexstr_to_uint(server_B, B, sizeof(B));

	assert_int_equal(librist_crypto_srp_client_handle_B(ctx->correct_hash_client, B, sizeof(B), "rist", "mainprofile"), 0);

	const char expected_M1[] = "E28147C801BAB9C37647C1FF4A29FA720E3F5676434FB85EA9A752CC1F9B1AD4";
	uint8_t m1[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_client_write_M1_bytes(ctx->correct_hash_client, m1);

	char m1_hex[sizeof(expected_M1)];
	uint_to_hex(m1, sizeof(m1), m1_hex);
	assert_string_equal(m1_hex, expected_M1);
}

static void test_srp_correct_hashing_client_verify_M2(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_M2[] = "84F19797916FBDCAB1321CA78B575B145B586150248AFAA156361B8BCB139B32";
	uint8_t M2[(sizeof(server_M2)-1)/2];
	hexstr_to_uint(server_M2, M2, sizeof(M2));
	assert_int_equal(librist_crypto_srp_client_verify_m2(ctx->correct_hash_client, M2), 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_func),
		cmocka_unit_test(test_hash_update_func),
		cmocka_unit_test(test_get_default_ng),
#if HAVE_MBEDTLS
		cmocka_unit_test(test_srp_wrong_hashing_auth_handle_A),
		cmocka_unit_test(test_srp_wrong_hashing_auth_verify_M1),
		cmocka_unit_test(test_srp_wrong_hashing_verifier_create),
		cmocka_unit_test(test_srp_wrong_hashing_auth_ctx_create),
#endif
		cmocka_unit_test(test_srp_correct_hashing_verifier_create),
		cmocka_unit_test(test_srp_correct_hashing_auth_ctx_create),
		cmocka_unit_test(test_srp_correct_hashing_auth_handle_A),
		cmocka_unit_test(test_srp_correct_hashing_auth_verify_M1),
		cmocka_unit_test(test_srp_client_ctx_create),
#if HAVE_MBEDTLS
		cmocka_unit_test(test_srp_wrong_hashing_client_handle_B),
		cmocka_unit_test(test_srp_wrong_hashing_client_verify_M2),
#endif
		cmocka_unit_test(test_srp_correct_hashing_client_handle_B),
		cmocka_unit_test(test_srp_correct_hashing_client_verify_M2),
	};

    return cmocka_run_group_tests(tests, srp_test_state_setup, srp_test_state_teardown);
}
