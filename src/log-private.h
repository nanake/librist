/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef RIST_LOG_PRIVATE_H
#define RIST_LOG_PRIVATE_H

#include "common.h"
#include "rist-private.h"

__BEGIN_DECLS

RIST_PRIV void rist_log(struct rist_common_ctx *cctx, enum rist_log_level level, const char *format, ...);
RIST_PRIV int rist_set_logging_options(struct rist_common_ctx *cctx, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp);

__END_DECLS

#endif
