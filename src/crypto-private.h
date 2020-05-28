/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef RIST_CRYPTO_PRIVATE_H
#define RIST_CRYPTO_PRIVATE_H

#include "common/attributes.h"

__BEGIN_DECLS

#include <stdint.h>

RIST_PRIV uint64_t rist_siphash(uint64_t birthtime, uint32_t seq, const char *phrase);

__END_DECLS

#endif
