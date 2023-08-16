/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <librist/librist_srp.h>


void user_verifier_lookup(char * username,
							librist_verifier_lookup_data_t *lookup_data,
							int *hashversion,
							uint64_t *generation,
							void *user_data);
