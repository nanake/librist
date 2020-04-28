/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "network.h"
#include <librist.h>
#include "log-private.h"
#include "time-shim.h"
#include "stdio-shim.h"

static int loglevel = RIST_LOG_WARN;

// Default is no stats printed
static int stats_fd = -1;
static int stats_socket = 0;

void set_loglevel(int level)
{
	loglevel = level;
}

int rist_set_stats_fd(int fd)
{
	if (fd > -1) {
		stats_fd = fd;
		fprintf(stderr, "Logs custom file handle set, #%d\n", stats_fd);
	}

	return 0;
}

int rist_set_stats_socket(char * hostname, int port)
{
	if (!port) {
		fprintf(stderr, "Invalid logs socket port %d requested\n", port);
		return -1;
	}

	if (!stats_socket) {
		stats_socket = udp_Connect(hostname, port, -1, 0, NULL);
		fprintf(stderr, "Logs socket created on %s : %d (#%d)\n", hostname, port, stats_socket);
	} else {
		fprintf(stderr, "Sorry, logs socket was already created, socket #%d\n", stats_socket);
	}

	return 0;
}

void msg(intptr_t receiver_ctx, intptr_t sender_ctx, int level, const char *format, ...)
{
	struct timeval tv;
	char *str_content;
	char *str_udp;

#ifdef _WIN32
	if (stats_fd == -1) {
		stats_fd = _fileno(stderr);
	}
#endif
	if (level > loglevel) {
		return;
	}

	gettimeofday(&tv, NULL);

	va_list args;
	va_start(args, format);
	{
		int ret = vasprintf(&str_content, format, args);
		(void)ret;
	}
	va_end(args);
	int udplen = asprintf(&str_udp, "%d.%6.6d|%ld.%ld|%d|%s", (int)tv.tv_sec,
		(int)tv.tv_usec, receiver_ctx, sender_ctx, level, str_content);
	{
		ssize_t ret = write(stats_fd, str_udp, udplen + 1);
		(void)ret;
	}
	if (stats_socket > 0) {
		udp_Write(stats_socket, str_udp, udplen);
	}

	free(str_udp);
	free(str_content);
}
