/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "librist.h"
#include "rist-private.h"
#include "log-private.h"
#include "crypto-private.h"
#include "udp-private.h"
#include "sha256.h"

// This is intended for verifying that the peer has the same passphrase
// Usecase: "reply attack protection"
uint64_t rist_siphash(uint64_t birthtime, uint32_t seq, const char *phrase)
{
	uint8_t tmp[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	uint64_t out;

	if (!birthtime) {
		// This is an expected scenario and
		//  happens until the peer receives the first ping/pong
		return 0;
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (void *) &birthtime, sizeof(birthtime));
	SHA256_Update(&ctx, (void *) &seq, sizeof(seq));

	if ((phrase != NULL) && strlen(phrase)) {
		SHA256_Update(&ctx, (const void *) phrase, strlen(phrase));
	}

	SHA256_Final(&ctx, tmp);

	memcpy(&out, tmp, sizeof(out));

	return out;
}

static bool seeded = false;
//Generate pseudo-random 32 bit
uint32_t prand_u32() {
	if (!seeded) {
		srand(timestampNTP_u64());
		seeded = true;
	}
	uint32_t u32;
	uint8_t *u8 = (void *) &u32;
	for (size_t i = 0; i < sizeof(u32); i++) {
		u8[i] = rand() % 256;//Use the lowest byte of rand()
	}
	return u32;
}
