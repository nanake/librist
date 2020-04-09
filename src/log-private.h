/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef RIST_LOG_PRIVATE_H
#define RIST_LOG_PRIVATE_H

#include "common.h"
#include "rist-private.h"

__BEGIN_DECLS

RIST_PRIV void msg(intptr_t receiver_ctx, intptr_t sender_ctx, enum rist_log_level level, const char *format, ...);
RIST_PRIV void set_loglevel(enum rist_log_level level);

__END_DECLS

#endif
