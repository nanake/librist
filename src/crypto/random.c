#include "random.h"
#include "config.h"

#if HAVE_MBEDTLS
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "pthread-shim.h"
#include "vcs_version.h"

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;

#if !defined(_WIN32) || HAVE_PTHREADS
//For some reason GNU Hurd complains that PTHREAD_ONCE_INIT isn't a constant
#if defined(__GNU__)
static pthread_once_t entropy_init_once = {__PTHREAD_ONCE_INIT};
#else
static pthread_once_t entropy_init_once = PTHREAD_ONCE_INIT;
#endif
#endif
#if defined(_WIN32) && !HAVE_PTHREADS
static INIT_ONCE entropy_init_once = INIT_ONCE_STATIC_INIT;
#endif


#if HAVE_PTHREADS
static void _librist_crypto_random_init_func(void)
#else
static BOOL WINAPI librist_crypto_srp_init_random_func(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
#endif
{
#if HAVE_MBEDTLS
	mbedtls_entropy_init(&entropy_ctx);
	mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
	//ctr_drbg_ctx is threadsafe, so can be used by multiple threads freely, seeding isn't though.
	const char user_custom[] = "libRIST librist_crypto_random_init_func "LIBRIST_VERSION;
	mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, (const unsigned char  *)user_custom, sizeof(user_custom));
#endif
#if !HAVE_PTHREADS
	return 1;
#endif
}

static void _librist_crypto_random_init(void) {
#if HAVE_PTHREADS
	pthread_once(&entropy_init_once, _librist_crypto_random_init_func);
#else
	InitOnceExecuteOnce(&entropy_init_once, librist_crypto_srp_init_random_func, NULL, NULL);
#endif
}

#elif HAVE_NETTLE
#include <gnutls/crypto.h>
static void _librist_crypto_random_init(void) {
	return;
}
#endif

int _librist_crypto_ramdom_get_bytes(uint8_t buf[], size_t buflen) {
	_librist_crypto_random_init();
	int ret;
#if HAVE_MBEDTLS
	ret = mbedtls_ctr_drbg_random(&ctr_drbg_ctx, buf, buflen);
#elif HAVE_NETTLE
	int i=0;
	do {
		ret = gnutls_rnd(GNUTLS_RND_NONCE, buf, buflen);//This call is thread-safe
		i++;
	} while (ret != 0 && i < 10);
#endif
	return ret;
}

int _librist_crypto_random_get_string(char buf[], size_t len) {
	char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";//Cut to 64 characters to deal with modulo bias
	uint8_t rand_buf[128];
	int ret = _librist_crypto_ramdom_get_bytes(rand_buf, len);
	if (ret != 0)
		return ret;
	for (size_t i=0; i< len; i++) {
		buf[i] = charset[rand_buf[i] % sizeof(charset) -1];
	}
	return 0;
}
