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
	volatile bool logs_set;
	pthread_mutex_t global_logs_lock;
} global_logging_settings;

#if defined(_WIN32) && !defined(HAVE_PTHREADS)
INIT_ONCE once_var = INIT_ONCE_STATIC_INIT;
static BOOL init_mutex(PINIT_ONCE once_var, PVOID param, PVOID *param2)
{
	RIST_MARK_UNUSED(once_var);
	RIST_MARK_UNUSED(param);
    RIST_MARK_UNUSED(param2);
	if (pthread_mutex_init(&global_logging_settings.global_logs_lock, NULL) != 0)
	{
		return FALSE;
	}
	return TRUE;
}
#else
pthread_once_t once_var = PTHREAD_ONCE_INIT;
static void init_mutex(void)
{
	int ret = pthread_mutex_init(&global_logging_settings.global_logs_lock, NULL);
	//we cannot log or fail graciously here, and it should "never" happen anyway, so an
	//assert is OK here (it will get compiled away if NDEBUG is undefined)
	assert(ret == 0);
}
#endif
static inline void rist_log_impl(struct rist_logging_settings *log_settings, enum rist_log_level level, intptr_t sender_id, intptr_t receiver_id, const char *format, va_list argp) {
	if (level > log_settings->log_level || (!log_settings->log_cb && !log_settings->log_socket && !log_settings->log_stream)) {
		return;
	}
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
	if (RIST_UNLIKELY(!global_logging_settings.logs_set))
		return;
	va_list argp;
	va_start(argp, format);
	pthread_mutex_lock(&global_logging_settings.global_logs_lock);
	rist_log_impl(&global_logging_settings.settings, level, 0, 0, format, argp);
	pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
	va_end(argp);
}

struct rist_logging_settings *rist_get_global_logging_settings() {
	if (global_logging_settings.logs_set)
		return &global_logging_settings.settings;
	return NULL;
}

static int init_once_global()
{
	#if defined(_WIN32) && !defined(HAVE_PTHREADS)
	BOOL success = InitOnceExecuteOnce(&once_var, init_mutex, NULL, NULL);
	if (!success)
	{
		return -1;
	}
	#else
	pthread_once(&once_var, init_mutex);
	#endif
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
	global_logging_settings.settings.log_cb = logging_settings->log_cb;
	global_logging_settings.settings.log_cb_arg = logging_settings->log_cb_arg;
	global_logging_settings.settings.log_level = logging_settings->log_level;
	if (global_logging_settings.settings.log_socket)
	{
		udpsocket_close(global_logging_settings.settings.log_socket);
	}
	if (logging_settings->log_socket)
	{
		global_logging_settings.settings.log_socket = dup(logging_settings->log_socket);
	}
	global_logging_settings.settings.log_stream = logging_settings->log_stream;
	global_logging_settings.logs_set = true;
	pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
	return 0;
}

void rist_logging_unset_global(void)
{
	if (init_once_global() != 0)
	{
		return;
	}
	pthread_mutex_lock(&global_logging_settings.global_logs_lock);
	if (global_logging_settings.settings.log_socket)
	{
		udpsocket_close(global_logging_settings.settings.log_socket);
	}
	memset(&global_logging_settings.settings, 0, sizeof(global_logging_settings.settings));
	global_logging_settings.logs_set = false;
	pthread_mutex_unlock(&global_logging_settings.global_logs_lock);
}

int rist_logging_set(struct rist_logging_settings **logging_settings, enum rist_log_level log_level, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp)
{
	if (!logging_settings)
		return -1;
	struct rist_logging_settings *settings = *logging_settings;
	if (!settings) {
		settings = calloc(1, sizeof(*settings));
		*logging_settings = settings;
	}

	settings->log_level = log_level;
	settings->log_cb = log_cb;
	settings->log_cb_arg = cb_arg;
	settings->log_stream = logfp;
	if (address && address[0] != '\0') {
		if (settings->log_socket) {
			rist_log_priv3(RIST_LOG_NOTICE, "Closing old logsocket\n");
			udpsocket_close(settings->log_socket);
			settings->log_socket = 0;
		}
		char host[200];
		uint16_t port;
		int local;
		if (udpsocket_parse_url(address, host, 200, &port, &local) != 0 || local == 1) {
			rist_log_priv3(RIST_LOG_ERROR, "Failed to parse logsocket address\n");
			return -1;
		}
		settings->log_socket = udpsocket_open_connect(host, port, NULL);
		if (settings->log_socket <= 0) {
			settings->log_socket = 0;
			rist_log_priv3(RIST_LOG_ERROR, "Failed to open logsocket\n");
			return -1;
		}
		udpsocket_set_nonblocking(settings->log_socket);
		return 0;
	} else if (settings->log_socket) {
		rist_log_priv3(RIST_LOG_NOTICE, "Closing old logsocket\n");
		udpsocket_close(settings->log_socket);
		settings->log_socket = 0;
	}
	if (!global_logging_settings.logs_set)
	{
		rist_logging_set_global(settings);
	}
	return 0;
}
