/* librist. Copyright 2020 in2ip B.V. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 */

#ifndef __LINUX_CRYPTO_H
#define __LINUX_CRYPTO_H

#include "common.h"

#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h> 
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/if_alg.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct linux_crypto;


int linux_crypto_init(struct linux_crypto **ctx);
int linux_crypto_set_key(const uint8_t *key, int keylen,struct linux_crypto *ctx);
int linux_crypto_decrypt(uint8_t buf[], int buflen, uint8_t iv[], struct linux_crypto *ctx);
int linux_crypto_encrypt(uint8_t buf[], int buflen, uint8_t iv[], struct linux_crypto *ctx);

#endif
