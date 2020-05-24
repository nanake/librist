/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "librist.h"
#include "rist-private.h"
#include "log-private.h"
#include "crypto-private.h"
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

// Generate a unique flowid
uint32_t generate_flowid(uint64_t birthtime, uint32_t pid, const char *phrase)
{
	uint8_t tmp[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	uint32_t out;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (void *) &birthtime, sizeof(birthtime));
	SHA256_Update(&ctx, (void *) &pid, sizeof(pid));
	SHA256_Update(&ctx, (const void *) phrase, strlen(phrase));

	SHA256_Final(&ctx, tmp);

	memcpy(&out, tmp, sizeof(out));

	// It must me an even number
	out &= ~(1UL << 0);

	return out;
}
