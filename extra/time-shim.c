/* librist. Copyright 2019 SipRadius LLC. All right reserved.
* Author: Antonio Cardce <anto.cardace@gmail.com>
* Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
* Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
*/

#include "time-shim.h"

#ifdef _WIN32
# include <windows.h>
# include <errno.h>
# include <stdlib.h>
# include <limits.h>

int gettimeofday(struct timeval *tv, void * not_implemented)
{
	static struct timeval epoch;
	LARGE_INTEGER now, frequency;

	if (!tv) {
		errno = EFAULT;
		return -1;
	}

	/* Windows QPC returns the elapsed number of ticks.
	   Its frequency is ticks-per-second.
	*/
	if (QueryPerformanceFrequency(&frequency)) {
		QueryPerformanceCounter(&now);
		/* fill in the timeval structure */
		tv->tv_sec = (now.QuadPart / frequency.QuadPart);
		tv->tv_usec = (now.QuadPart * 1000000 / frequency.QuadPart) - (tv->tv_sec * 1000000);
		if (epoch.tv_sec == 0) {
			epoch.tv_sec = tv->tv_sec;
			epoch.tv_usec = tv->tv_usec;
			const unsigned __int64 epochval = ((unsigned __int64)116444736000000000ULL);
			FILETIME file_time;
			SYSTEMTIME system_time;
			ULARGE_INTEGER ularge;
			GetSystemTime(&system_time);
			SystemTimeToFileTime(&system_time, &file_time);
			ularge.LowPart = file_time.dwLowDateTime;
			ularge.HighPart = file_time.dwHighDateTime;
			epoch.tv_sec -= (long)((ularge.QuadPart - epochval) / 10000000L);
		}
		tv->tv_sec -= epoch.tv_sec;
		tv->tv_usec -= epoch.tv_usec;
		if (tv->tv_usec < 0) {
			tv->tv_usec += 1000000;
			tv->tv_sec--;
		}
	} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int clock_gettime(clockid_t clock, timespec_t *tp)
{
	(void)tp;

	if (clock != CLOCK_MONOTONIC) {
		errno = EINVAL;
		return -1;
	}

	LARGE_INTEGER now, frequency;
	if (QueryPerformanceFrequency(&frequency)) {
		QueryPerformanceCounter(&now);
		/* fill in the timespec structure */
		tp->tv_sec = now.QuadPart / frequency.QuadPart;
		tp->tv_nsec = (now.QuadPart * 1000000000 / frequency.QuadPart) - (tp->tv_sec * 1000000000);
	} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

#endif

#ifdef __MACH__
int clock_gettime(clockid_t clock, timespec_t *ts)
{
  clock_serv_t cclock;
  mach_timespec_t mts;
  host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
  clock_get_time(cclock, &mts);
  mach_port_deallocate(mach_task_self(), cclock);
  ts->tv_sec = mts.tv_sec;
  ts->tv_nsec = mts.tv_nsec;
  return 0;
}
#endif
