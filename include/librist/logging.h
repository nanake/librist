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

/**
 * The recommended way to use the logging settings is to stack/heap alloc
 * and 0 initialize the rist_logging_settings struct, and set it's members.
 *
 * Then call rist_logging_set_global to have the settings copied in for the
 * global log settings (used by udpsocket_ functions).
 **/

struct rist_logging_settings {
	enum rist_log_level log_level;///<minimum log level, ignored when callback is used
	/**
	 * @brief Log callback function
	 * When set this function is called by the libRIST library whenever a
	 * log message is available. NULL to disable log callback
	 *
	 * @param arg, user data
	 * @param level log level
	 * @param msg log message
	 */
    int (*log_cb)(void* arg, enum rist_log_level, const char* msg);
	void *log_cb_arg;///< user data passed to log callback function
	int log_socket;///< socket to which log messages are written via send call
	FILE *log_stream;///< FILE to which log messages are written via fputs call
};

/* public interfaces in logging.c */
RIST_API void rist_log(struct rist_logging_settings *logging_settings, enum rist_log_level level, const char *format, ...);

/**
 * @brief populates and creates logging settings struct with log settings
 *
 * This also sets the global logging settings if they were not set before.
 *
 * @param logging_settings if pointed to pointer is NULL struct will be allocated, otherwise pointed to struct will have it's values updated by given values, closing and opening sockets as needed.
 * @param log_level log level to filter at when other outputs besides CB are defined.
 * @param log_cb log callback , NULL to disable
 * @param cb_args user data passed to log callback function, NULL when unused
 * @param address destination address for UDP log messages, NULL when unused
 * @param logfp log file to write to, NULL when unused
 **/
RIST_API int rist_logging_set(struct rist_logging_settings **logging_settings, enum rist_log_level log_level, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp);

/**
 * @brief Set global log settings
 * Set the global log settings that are used by the udpsocket_ functions
 * @param logging_settings struct containing log settings from wich log settings will be copied from
 * @return 0 for succes
 **/
RIST_API int rist_logging_set_global(struct rist_logging_settings *logging_settings);
#endif
