#ifndef LIBRIST_CRYPTO_RANDOM_H
#define LIBRIST_CRYPTO_RANDOM_H

#include <stdint.h>
#include <stddef.h>
#include "common/attributes.h"

RIST_PRIV int _librist_crypto_ramdom_get_bytes(uint8_t buf[], size_t buflen);
RIST_PRIV int _librist_crypto_random_get_string(char buf[], size_t len);
#endif /* LIBRIST_CRYPTO_RANDOM_H */
