/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

void user_verifier_lookup(char *username, size_t *verifier_len, char **verifier,
                          size_t *salt_len, char **salt,
                          bool *use_default_2048_bit_n_modulus,
                          char **n_modulus_ascii, char **generator_ascii,
                          int *hashversion, uint64_t *generation,
                          void *user_data);
