/*
 * Copyright © 2018, VideoLAN and dav1d authors
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef GCCVER_STDATOMIC_H_
#define GCCVER_STDATOMIC_H_

#include <stdbool.h>

#if !defined(__cplusplus)

typedef int atomic_int;
typedef unsigned int atomic_uint;
typedef unsigned long atomic_ulong;

#define memory_order_relaxed __ATOMIC_RELAXED
#define memory_order_acquire __ATOMIC_ACQUIRE
#define memory_order_release __ATOMIC_RELEASE

#define atomic_init(p_a, v)           __atomic_store_n(p_a, v, memory_order_relaxed)
#define atomic_store(p_a, v)          __atomic_store_n(p_a, v, __ATOMIC_SEQ_CST)
#define atomic_load(p_a)              __atomic_load_n(p_a, __ATOMIC_SEQ_CST)
#define atomic_load_explicit(p_a, mo) __atomic_load_n(p_a, mo)
#define atomic_store_explicit(p_a, v, mo) __atomic_store_n(p_a, v, mo)
#define atomic_fetch_add(p_a, inc)    __atomic_fetch_add(p_a, inc, __ATOMIC_SEQ_CST)
#define atomic_fetch_add_explicit(p_a, inc, mo) __atomic_fetch_add(p_a, inc, mo)
#define atomic_fetch_sub(p_a, dec)    __atomic_fetch_sub(p_a, dec, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub_explicit(p_a, dec, mo) __atomic_fetch_sub(p_a, dec, mo)
#define atomic_compare_exchange_weak(object, expected, desired) __atomic_compare_exchange_n(object, expected, desired, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#endif /* !defined(__cplusplus) */

#endif /* GCCVER_STDATOMIC_H_ */
