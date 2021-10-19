#include "rist-private.h"

RIST_PRIV int rist_thread_create(struct rist_common_ctx *cctx,
                       pthread_t *thread, pthread_attr_t *attr, pthread_start_func_t thread_func, void *thread_arg);
