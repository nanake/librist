/*
 * Copyright © 2021, VideoLAN and librist authors
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "pthread-shim.h"
#include "rist-private.h"
#include "config.h"

#include <assert.h>

struct thread_wrapper {
    struct rist_common_ctx *cctx;
    pthread_start_func_t thread_func;
    void *thread_arg;
};

/*
    This is a bit of a hack, it allows us to do a callback to the calling application with the thread handle
    when creating a thread, and when the wrapped function exits
*/
static PTHREAD_START_FUNC(thread_wrapper, arg)
{
    struct thread_wrapper *tw = arg;
    void *handle = NULL;
#ifndef _WIN32
    void *ret = NULL;
    pthread_t p_id = pthread_self();
    handle = &p_id;
#else //_WIN32
#if HAVE_PTHREADS
    void *ret = NULL;
#else // HAVE_PTHREADS
    DWORD ret = 0;
#endif // HAVE_PTHREADS
    HANDLE h = GetCurrentThread();
    handle = &h;
#endif //_WIN32
    tw->cctx->thread_callback(handle, true, 0, tw->cctx->thread_callback_arg);
    ret = tw->thread_func(tw->thread_arg);
    tw->cctx->thread_callback(handle, false, 0, tw->cctx->thread_callback_arg);
    free(arg);
    return ret;
}

int rist_thread_create(struct rist_common_ctx *cctx, 
                       pthread_t *thread, pthread_attr_t *attr, pthread_start_func_t thread_func, void *thread_arg)
{
    if (cctx->thread_callback == NULL)
        return pthread_create(thread, attr, thread_func, thread_arg);
    struct thread_wrapper *tw = malloc(sizeof(*tw));
    assert(tw != NULL);
    tw->cctx = cctx;
    tw->thread_func = thread_func;
    tw->thread_arg = thread_arg;
    int ret = pthread_create(thread, attr, thread_wrapper, tw);
    if (ret != 0)
        free(tw);
    return ret;
}
