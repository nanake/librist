/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "librist.h"
#include "log-private.h"
#include "time-shim.h"
#include "stdio-shim.h"
#include "librist_udpsocket.h"

void rist_log(struct rist_common_ctx *cctx, enum rist_log_level level, const char *format, ...) {
	if ((cctx && level > cctx->log_level) || (cctx && !cctx->log_cb && !cctx->log_socket && !cctx->log_stream)) {
		return;
	}
	va_list args;
	char *msg;
	va_start(args, format);
	{
		int ret = vasprintf(&msg, format, args);
		if (ret <= 0) {
			fprintf(stderr, "[ERROR] Could not format log message!\n");
			return;
		}
	}
	va_end(args);
	if (cctx && cctx->log_cb) {
		cctx->log_cb(cctx->log_cb_arg, level, msg);
		goto out;
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
	if (RIST_UNLIKELY(!cctx))
		goto unconfigured;
	ssize_t msglen;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	msglen = asprintf(&logmsg, "%d.%6.6d|%ld.%ld|%s %s", (int)tv.tv_sec,
			 (int)tv.tv_usec, cctx->receiver_id, cctx->sender_id, prefix, msg);
	if (RIST_UNLIKELY(msglen <= 0)) {
		fprintf(stderr, "[ERROR] Failed to format log message\n");
		goto out;
	}
	if (cctx->log_socket)
		udpsocket_send(cctx->log_socket, logmsg, msglen);
	if (cctx->log_stream)
		fputs(logmsg, cctx->log_stream);
	
unconfigured:
	if (RIST_UNLIKELY(!cctx)) {
		msglen = asprintf(&logmsg, "%s %s", prefix, msg);
		if (RIST_UNLIKELY(msglen <= 0)) {
			fprintf(stderr, "[ERROR] Failed to format log message\n");
			goto out;
		}
		fputs(logmsg, stderr);
	}
	free(logmsg);
out:
	free(msg);
}

int rist_set_logging_options(struct rist_common_ctx *cctx, int (*log_cb)(void *arg, enum rist_log_level, const char *msg), void *cb_arg, char *address, FILE *logfp) {
	if (!cctx) {
		return -1;
	}
	cctx->log_cb = log_cb;
	cctx->log_cb_arg = cb_arg;
	cctx->log_stream = logfp;
	if (address && address[0] != '\0') {
		if (cctx->log_socket) {
			rist_log(cctx, RIST_LOG_NOTICE, "Closing old logsocket\n");
			udpsocket_close(cctx->log_socket);
			cctx->log_socket = 0;
		}
		char url[200];
		uint16_t port;
		int local;
		if (udpsocket_parse_url(url, address, 200, &port, &local) != 0 || local == 1) {
			rist_log(cctx, RIST_LOG_ERROR, "Failed to parse logsocket address\n");
			return -1;
		}
		cctx->log_socket = udpsocket_open_connect(url, port, NULL);
		if (cctx->log_socket <= 0) {
			cctx->log_socket = 0;
			rist_log(cctx, RIST_LOG_ERROR, "Failed to open logsocket\n");
			return -1;
		}
		return 0;
	} else if (cctx->log_socket) {
		rist_log(cctx, RIST_LOG_NOTICE, "Closing old logsocket\n");
		udpsocket_close(cctx->log_socket);
		cctx->log_socket = 0;
	}
	return 0;
}