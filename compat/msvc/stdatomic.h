/*
 * Copyright © 2018, VideoLAN and dav1d authors
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MSCVER_STDATOMIC_H_
#define MSCVER_STDATOMIC_H_

#if !defined(__cplusplus) && defined(_MSC_VER)

#pragma warning(push)
#pragma warning(disable:4067)    /* newline for __has_include_next */

#if defined(__clang__) && __has_include_next(<stdatomic.h>)
   /* use the clang stdatomic.h with clang-cl*/
#  include_next <stdatomic.h>
#else /* ! stdatomic.h */

#include <windows.h>

#include <stddef.h>
#include <stdint.h>

typedef volatile LONG  __declspec(align(32)) atomic_int;
typedef volatile ULONG __declspec(align(32)) atomic_uint;
typedef volatile ULONG __declspec(align(32)) atomic_ulong;
typedef volatile USHORT _declspec(align(16)) atomic_uint_fast16_t;

typedef enum {
    memory_order_relaxed,
    memory_order_acquire,
    memory_order_release
} msvc_atomic_memory_order;

#define atomic_init(p_a, v)           atomic_store(p_a, v)
#define atomic_store(p_a, v)          InterlockedExchange((LONG*)p_a, v)
#define atomic_load(p_a)              InterlockedCompareExchange((LONG*)p_a, 0, 0)
#define atomic_load_explicit(p_a, mo) atomic_load(p_a)
#define atomic_store_explicit(p_a, v, mo) atomic_store(p_a, v)

/*
 * TODO use a special call to increment/decrement
 * using InterlockedIncrement/InterlockedDecrement
 */
#define atomic_fetch_add(p_a, inc)    InterlockedExchangeAdd((LPLONG)p_a, inc)
#define atomic_fetch_sub(p_a, dec)    InterlockedExchangeAdd((LPLONG)p_a, -(int)(dec))
#define atomic_fetch_add_explicit(p_a, inc, mo)   atomic_fetch_add(p_a, inc)
#define atomic_fetch_sub_explicit(p_a, inc, mo)   atomic_fetch_sub(p_a, inc)
#define atomic_compare_exchange_weak(object, expected, desired) InterlockedCompareExchange((LONG*)object, expected, desired)


#endif /* ! stdatomic.h */

#pragma warning(pop)

#endif /* !defined(__cplusplus) && defined(_MSC_VER) */

#endif /* MSCVER_STDATOMIC_H_ */
