/*
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_COMMON_H
#define RIST_COMMON_H

#if defined _WIN32
    #if defined LIBRIST_BUILDING_DLL
    #define RIST_API __declspec(dllexport)
    #else
    #define RIST_API
    #endif
#else
    #if __GNUC__ >= 4
    #define RIST_API __attribute__ ((visibility ("default")))
    #else
    #define RIST_API
    #endif
#endif

#endif
