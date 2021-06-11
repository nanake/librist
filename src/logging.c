/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "librist/librist.h"
#include "log-private.h"
#include "time-shim.h"
#include "stdio-shim.h"
#include "udpsocket.h"
#include "librist/logging.h"
#include "pthread-shim.h"
#include "config.h"
#include <assert.h>
#if defined(_WIN32) && !defined(HAVE_PTHREADS)
#include <windows.h>
#endif

static struct {
	struct rist_logging_settings settings;
	bool logs_set;
	pthread_mutex_t global_logs_lock;
} global_logging_settings = {
	.settings = LOGGING_SETTINGS_INITIALIZER,
	.logs_set = false,
#if !defined(_WIN32) || defined(HAVE_PTHREADS)
	.global_logs_lock = PTHREAD_MUTEX_INITIALIZER,
#endif
};

#if defined(_WIN32) && !defined(HAVE_PTHREADS)
static INIT_ONCE once_var = INIT_ONCE_STATIC_INIT;
#endif

static inline void rist_log_impl(struct rist_logging_settings *log_settings,
				 enum rist_log_level level, intptr_t sender_id,
				 intptr_t receiver_id, const char *format,
				 va_list argp)
{
	if (level > log_settings->log_level ||
	    (!log_settings->log_cb && (log_settings->log_socket < 0) &&
	     !log_settings->log_stream))
		return;

	char *msg;
	int ret = vasprintf(&msg, format, argp);
	if (ret <= 0) {
		fprintf(stderr, "[ERROR] Could not format log message!\n");
		return;
	}

	if (log_settings->log_cb) {
		log_settings->log_cb(log_settings->log_cb_arg, level, msg);
		free(msg);
		return;
	}
	const char *prefix;
	switch (level) {
	case RIST_LOG_DEBUG:
		prefix = "[DEBUG]";
		break;
	case RIST_LOG_INFO:
		prefix = "[INFO]";
		break;
	case RIST_LOG_NOTICE:
		prefix = "[NOTICE]";
		break;
	case RIST_LOG_WARN:
		prefix = "[WARNING]";
		break;
	case RIST_LOG_ERROR:
		RIST_FALLTHROUGH;
	default:
		prefix = "[ERROR]";
		break;
	}
	char *logmsg;

	ssize_t msglen;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	msglen = asprintf(&logmsg, "%d.%6.6d|%"PRIdPTR".%"PRIdPTR"|%s %s", (int)tv.tv_sec,
			 (int)tv.tv_usec, receiver_id, sender_id, prefix, msg);
	if (RIST_UNLIKELY(msglen <= 0)) {
		fprintf(stderr, "[ERROR] Failed to format log message\n");
		goto out;
	}
	if (log_settings->log_socket)
		udpsocket_send_nonblocking(log_settings->log_socket, logmsg, msglen);
	if (log_settings->log_stream) {
		fputs(logmsg, log_settings->log_stream);
		fflush(log_settings->log_stream);
	}
	free(logmsg);
out:
	free(msg);
}

//For places where we have access to common ctx
void rist_log_priv(struct rist_common_ctx *cctx, enum rist_log_level level, const char *format, ...)
{
	if (RIST_UNLIKELY(cctx->logging_settings == NULL))
		return;
	va_list argp;
	va_start(argp, format);
	rist_log_impl(cctx->logging_settings, level, cctx->sender_id, cctx->receiver_id, format, argp);
	va_end(argp);
}

void rist_log_priv2(struct rist_logging_settings *logging_settings, enum rist_log_level level, const char *format, ...) {
	if (RIST_UNLIKELY(logging_settings == NULL ))
		return;
	va_list argp;
	va_start(argp, format);
	rist_log_impl(logging_settings, level, 0, 0, format, argp);
	va_end(argp);
}

//Public interface
void rist_log(struct rist_logging_settings *logging_settings, enum rist_log_level level, const char *format, ...)
{
	if (RIST_UNLIKELY(logging_settings == NULL))
		return;
	va_list argp;
	va_start(argp, format);
	rist_log_impl(logging_settings, level, 0, 0, format, argp);
	va_end(argp);
}

//Where we don't have access to either logging settings or common ctx (i.e.: udpsocket)
void rist_log_priv3(enum rist_log_level level, const char *format, ...)
{
	va_list argp;
	va_start(argp, format);
	pthread_mutex_lock(&global_logging_settings.global_logs_lock);
    if (RIST_LIKELY(global_logging_settings.logs_set))
    {
        rist_log_impl(&global_logging_settings.settings, level, 0, 0, format,
                      argp);
    }
    pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
    va_end(argp);
}

static int init_once_global()
{
	#if defined(_WIN32) && !defined(HAVE_PTHREADS)
	return init_mutex_once(&global_logging_settings.global_logs_lock, &once_var);
	#endif
	return 0;
}

static int
logging_set_global_unlocked(struct rist_logging_settings *logging_settings)
{
	if (global_logging_settings.settings.log_socket >= 0)
	{
		udpsocket_close(global_logging_settings.settings.log_socket);
	}
	global_logging_settings.settings = *logging_settings;
	if (logging_settings->log_socket >= 0)
	{
		global_logging_settings.settings.log_socket =
			dup(logging_settings->log_socket);
	}
	global_logging_settings.logs_set = true;
	return 0;
}

int rist_logging_set_global(struct rist_logging_settings *logging_settings)
{
	if (!logging_settings)
	{
		return -1;
	}
	if (init_once_global() != 0)
	{
		return -1;
	}
	pthread_mutex_lock(&global_logging_settings.global_logs_lock);
	int ret = logging_set_global_unlocked(logging_settings);
	pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
	return ret;
}

void rist_logging_unset_global(void)
{
	if (init_once_global() != 0)
	{
		return;
	}
	pthread_mutex_lock(&global_logging_settings.global_logs_lock);
	if (global_logging_settings.settings.log_socket >= 0)
	{
		udpsocket_close(global_logging_settings.settings.log_socket);
	}
	global_logging_settings.settings =
		(struct rist_logging_settings)LOGGING_SETTINGS_INITIALIZER;
	global_logging_settings.logs_set = false;
	pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
}

int rist_logging_set(struct rist_logging_settings **logging_settings, enum rist_log_level log_level, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp)
{
	if (!logging_settings)
		return -1;
	struct rist_logging_settings *settings = *logging_settings;
	bool alloc = false;
	if (!settings) {
		settings = malloc(sizeof(*settings));
		*settings = (struct rist_logging_settings)
			LOGGING_SETTINGS_INITIALIZER;
		*logging_settings = settings;
		alloc = true;
	}

	settings->log_level = log_level;
	settings->log_cb = log_cb;
	settings->log_cb_arg = cb_arg;
	settings->log_stream = logfp;
	if (address && address[0] != '\0') {
		if (settings->log_socket >= 0) {
			rist_log_priv3(RIST_LOG_NOTICE, "Closing old logsocket\n");
			udpsocket_close(settings->log_socket);
			settings->log_socket = -1;
		}
		char host[200];
		uint16_t port;
		int local;
		if (udpsocket_parse_url(address, host, sizeof(host), &port, &local) != 0 || local == 1) {
			rist_log_priv3(RIST_LOG_ERROR, "Failed to parse logsocket address\n");
			goto err;
		}
		settings->log_socket = udpsocket_open_connect(host, port, NULL);
		if (settings->log_socket < 0) {
			rist_log_priv3(RIST_LOG_ERROR, "Failed to open logsocket\n");
			goto err;
		}
		udpsocket_set_nonblocking(settings->log_socket);
		return 0;
	} else if (settings->log_socket >= 0) {
		rist_log_priv3(RIST_LOG_NOTICE, "Closing old logsocket\n");
		udpsocket_close(settings->log_socket);
		settings->log_socket = -1;
	}

	if (init_once_global() != 0)
		goto err;

	int ret = 0;
	pthread_mutex_lock(&global_logging_settings.global_logs_lock);
	if (!global_logging_settings.logs_set)
		ret = logging_set_global_unlocked(settings);
	pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
	if (ret)
		goto err;
	return 0;

err:
	if (alloc) {
		free(settings);
		*logging_settings = NULL;
	}
	return -1;
}
