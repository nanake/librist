/*
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_LOGGING_H
#define RIST_LOGGING_H
#include "headers.h"
#include "common.h"
#include <stdio.h>

struct rist_logging_settings {
	enum rist_log_level log_level;
	int (*log_cb)(void* arg, enum rist_log_level, const char* msg);
	void *log_cb_arg;
	int log_socket;
	FILE *log_stream;
};

/* public interfaces in logging.c */
RIST_API void rist_log(struct rist_logging_settings *logging_settings, enum rist_log_level level, const char *format, ...);
RIST_API int rist_logging_set(struct rist_logging_settings **logging_settings, enum rist_log_level log_level, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp);

#endif
