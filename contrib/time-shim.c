/* librist. Copyright 2019 SipRadius LLC. All right reserved.
* Author: Antonio Cardce <anto.cardace@gmail.com>
* Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
* Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
*/

#include "time-shim.h"

#ifdef _WIN32
#define _WINSOCKAPI_
# include <windows.h>
# include <errno.h>
# include <stdlib.h>
# include <limits.h>
# include <stdint.h>
#include "common/attributes.h"


//(un)graciously taken & modified from mingw-w64/misc/gettimeofday.c
/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */


#define FILETIME_1970 116444736000000000ull /* seconds between 1/1/1601 and 1/1/1970 */
#define HECTONANOSEC_PER_SEC 10000000ull

int gettimeofday(struct timeval *tv, void * not_implemented)
{
	RIST_MARK_UNUSED(not_implemented);

	union {
		unsigned long long ns100; /*time since 1 Jan 1601 in 100ns units */
		FILETIME ft;
	}  _now;

	if (tv != NULL)
	{
		struct timespec tp;
		GetSystemTimeAsFileTime (&_now.ft);  /* 100-nanoseconds since 1-1-1601 */
		/* The actual accuracy on XP seems to be 125,000 nanoseconds = 125 microseconds = 0.125 milliseconds */
		_now.ns100 -= FILETIME_1970;        /* 100 nano-seconds since 1-1-1970 */
		tp.tv_sec = _now.ns100 / HECTONANOSEC_PER_SEC;     /* seconds since 1-1-1970 */
		tp.tv_nsec = (long) (_now.ns100 % HECTONANOSEC_PER_SEC) * 100; /* nanoseconds */
		tv->tv_sec = tp.tv_sec;
		tv->tv_usec = tp.tv_nsec/1000;
	}
	return 0;
}


//(un)graciously copied from mingw-w64/winpthreads/src/clock.c
/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the w64 mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */


#define POW10_7                 10000000
#define POW10_9                 1000000000


/* Number of 100ns-seconds between the beginning of the Windows epoch
 * (Jan. 1, 1601) and the Unix epoch (Jan. 1, 1970)
 */
#define DELTA_EPOCH_IN_100NS    INT64_C(116444736000000000)

static inline int lc_set_errno(int result)
{
    if (result != 0) {
        errno = result;
        return -1;
    }
    return 0;
}

int clock_gettime(clockid_t clock_id, struct timespec *tp)
{
    unsigned __int64 t;
    LARGE_INTEGER pf, pc;
    union {
        unsigned __int64 u64;
        FILETIME ft;
    }  ct, et, kt, ut;

    switch(clock_id) {
    case CLOCK_REALTIME:
        {
            GetSystemTimeAsFileTime(&ct.ft);
            t = ct.u64 - DELTA_EPOCH_IN_100NS;
            tp->tv_sec = t / POW10_7;
            tp->tv_nsec = ((int) (t % POW10_7)) * 100;

            return 0;
        }

    case CLOCK_MONOTONIC:
        {
            if (QueryPerformanceFrequency(&pf) == 0)
                return lc_set_errno(EINVAL);

            if (QueryPerformanceCounter(&pc) == 0)
                return lc_set_errno(EINVAL);

            tp->tv_sec = pc.QuadPart / pf.QuadPart;
            tp->tv_nsec = (int) (((pc.QuadPart % pf.QuadPart) * POW10_9 + (pf.QuadPart >> 1)) / pf.QuadPart);
            if (tp->tv_nsec >= POW10_9) {
                tp->tv_sec ++;
                tp->tv_nsec -= POW10_9;
            }

            return 0;
        }

    case CLOCK_PROCESS_CPUTIME_ID:
        {
        if(0 == GetProcessTimes(GetCurrentProcess(), &ct.ft, &et.ft, &kt.ft, &ut.ft))
            return lc_set_errno(EINVAL);
        t = kt.u64 + ut.u64;
        tp->tv_sec = t / POW10_7;
        tp->tv_nsec = ((int) (t % POW10_7)) * 100;

        return 0;
        }

    case CLOCK_THREAD_CPUTIME_ID: 
        {
            if(0 == GetThreadTimes(GetCurrentThread(), &ct.ft, &et.ft, &kt.ft, &ut.ft))
                return lc_set_errno(EINVAL);
            t = kt.u64 + ut.u64;
            tp->tv_sec = t / POW10_7;
            tp->tv_nsec = ((int) (t % POW10_7)) * 100;

            return 0;
        }

    default:
        break;
    }

    return lc_set_errno(EINVAL);
}

#endif

#ifdef __APPLE__
int clock_gettime_osx(timespec_t *ts)
{
	mach_timebase_info_data_t info;
	mach_timebase_info(&info);
	uint64_t elapsed = mach_absolute_time();
	uint64_t now_ns = (elapsed * info.numer / info.denom);
	ts->tv_sec = (int)(now_ns /   1000000000);
	ts->tv_nsec = (int)(now_ns %  1000000000);
	return 0;
}

#endif
