/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef __STDIO_SHIM_H
#define __STDIO_SHIM_H

#include "common.h"
#include <stdio.h>
#include <stdarg.h>

#ifdef _MSC_VER
RIST_PRIV int vasprintf(char** strp, const char* fmt, va_list ap);
RIST_PRIV int asprintf(char** strp, const char* fmt, ...);
#endif

#endif
