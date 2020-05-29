/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "librist/librist.h"
#include "log-private.h"
#include "time-shim.h"
#include "stdio-shim.h"
#include "udpsocket.h"
#include "librist/logging.h"

static struct rist_logging_settings *g_logging_settings;

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
	msglen = asprintf(&logmsg, "%d.%6.6d|%ld.%ld|%s %s", (int)tv.tv_sec,
			 (int)tv.tv_usec, receiver_id, sender_id, prefix, msg);
	if (RIST_UNLIKELY(msglen <= 0)) {
		fprintf(stderr, "[ERROR] Failed to format log message\n");
		goto out;
	}
	if (log_settings->log_socket)
		udpsocket_send(log_settings->log_socket, logmsg, msglen);
	if (log_settings->log_stream)
		fputs(logmsg, log_settings->log_stream);

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
	if (RIST_UNLIKELY(g_logging_settings == NULL))
		return;
	va_list argp;
	va_start(argp, format);
	rist_log_impl(g_logging_settings, level, 0, 0, format, argp);
	va_end(argp);
}

struct rist_logging_settings *rist_get_global_logging_settings() {
	return g_logging_settings;
}

int rist_logging_set(struct rist_logging_settings **logging_settings, enum rist_log_level log_level, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp)
{
	struct rist_logging_settings *settings = *logging_settings;
	if (!settings) {
		settings = malloc(sizeof(*settings));
		*logging_settings = settings;
	}

	if (!g_logging_settings)
		g_logging_settings = settings;

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
		char url[200];
		uint16_t port;
		int local;
		if (udpsocket_parse_url(url, address, 200, &port, &local) != 0 || local == 1) {
			rist_log_priv3(RIST_LOG_ERROR, "Failed to parse logsocket address\n");
			return -1;
		}
		settings->log_socket = udpsocket_open_connect(url, port, NULL);
		if (settings->log_socket <= 0) {
			settings->log_socket = 0;
			rist_log_priv3(RIST_LOG_ERROR, "Failed to open logsocket\n");
			return -1;
		}
		return 0;
	} else if (settings->log_socket) {
		rist_log_priv3(RIST_LOG_NOTICE, "Closing old logsocket\n");
		udpsocket_close(settings->log_socket);
		settings->log_socket = 0;
	}
	return 0;
}
