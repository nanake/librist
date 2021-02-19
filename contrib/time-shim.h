/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef __TIME_SHIM_H
#define __TIME_SHIM_H

# include "../../config.h"

#if defined(_WIN32)
#define usleep(a)	Sleep((a)/1000)
# include <winsock2.h>
# include <time.h>

# define CLOCK_MONOTONIC 1

typedef int clockid_t;
int gettimeofday(struct timeval *tv, void * not_implemented);

typedef struct timespec timespec_t;
int clock_gettime(clockid_t clock, timespec_t *tp);

#elif defined(__APPLE__)
#  define CLOCK_REALTIME_OSX 0
#  define CLOCK_MONOTONIC_OSX 1
#ifndef HAVE_CLOCK_GETTIME
typedef int clockid_t;
#else
#ifndef CLOCK_REALTIME
#  define CLOCK_REALTIME CALENDAR_CLOCK
# endif
# ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC SYSTEM_CLOCK
# endif
#endif
#include <mach/mach_time.h>
#include <time.h>
typedef __darwin_time_t time_t;
#ifndef _STRUCT_TIMESPEC
struct timespec {
  time_t tv_sec;
  long   tv_nsec;
};
#endif
typedef struct timespec timespec_t;
int clock_gettime_osx(clock_id_t clock_id, timespec_t *tp);
#else
# include <sys/time.h>
# include <time.h>
typedef struct timespec timespec_t;
#endif

#endif
