/* librist. Copyright 2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */
#ifndef UDPSOCKET_H
#define UDPSOCKET_H
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "common.h"

/* TODO: check errno on windows */
#include <errno.h>

#define UDPSOCKET_MAX_HOPS 32

#ifndef SOL_IP
#define SOL_IP 0x0
#define SOL_IPV6 0x29
#endif

/* Windows */
#ifdef _WIN32
#include <winsock2.h>
#define _WINSOCKAPI_
#include <windows.h>
#include <ws2tcpip.h>
#define AF_LOCAL AF_UNSPEC
#define if_nametoindex(name)  atoi(name)
#define close(s) closesocket(s)
typedef int socklen_t;

/* POSIX */
#else 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <net/if.h>
#include <poll.h>
#endif /* Windows / POSIX */

/*** Public API ***/
#define UDPSOCKET_SOCK_BUFSIZE 0x80000

typedef struct udpsocket_url_param {
	char *key;
	char *val;
} udpsocket_url_param_t;

/* Open a udp socket of family [af]
 *
 * Returns: socket descriptor, -1 for error (errno is set)
 *
 */
RIST_API int udpsocket_open(uint16_t af);

/* Open a udp socket and binds it to local [host] + [port].
 *
 * binds to multicast interface [mciface], (if not NULL).
 *
 * Returns: socket descriptor, -1 for error (errno is set)
 * (In case of gai_error, -1 is returned, errno is not set, check gai_error)
 *
 */
RIST_API int udpsocket_open_bind(const char *host, uint16_t port, const char *mciface);

/*
 * Explicitly set TX/RX buffer size for [sd] to [bufsize], in bytes.
 * Returns -1 on error, 0 on success.
 */
RIST_API int udpsocket_set_buffer_size(int sd, uint32_t bufsize);

/*
 *
 * Retrieve current RX buffer size for [sd].
 * Returns 0 on error, current RX bufsize on success.
 */
RIST_API uint32_t udpsocket_get_buffer_size(int sd);

/*
 * Explicitly set the mcast interface for the socket [sd] to [mciface] for address
 * family [family].
 * Returns 0 on success, -1 on error (errno is set accordingly).
 */
RIST_API int udpsocket_set_mcast_iface(int sd, const char *mciface, uint16_t family);

/* Open a udp socket and connect it to remote [host] + [port].
 *
 * binds to multicast interface [mciface], (if not NULL).
 *
 * Returns: socket descriptor, -1 for error (errno is set)
 * (In case of gai_error, -1 is returned, errno is not set, check gai_error)
 *
 */
RIST_API int udpsocket_open_connect(const char *host, uint16_t port, const char *mciface);

RIST_API int udpsocket_resolve_host(const char *host, uint16_t port, struct sockaddr *addr);

RIST_API int udpsocket_send(int sd, const void *buf, size_t size);
RIST_API int udpsocket_sendto(int sd, const void *buf, size_t size, const char *host, uint16_t port);
RIST_API int udpsocket_recv(int sd, void *buf, size_t size);
RIST_API int udpsocket_recvfrom(int sd, void *buf, size_t size, int flags, struct sockaddr *addr, socklen_t *addr_len);
RIST_API int udpsocket_close(int sd);
RIST_API int udpsocket_parse_url(char *url, char *address, int address_maxlen, uint16_t *port, int *local);
RIST_API int udpsocket_parse_url_parameters(const char *url, udpsocket_url_param_t *params,
         int max_params, uint32_t *clean_url_len);


/* evsocket related functions */

#define EVSOCKET_EV_READ POLLIN
#define EVSOCKET_EV_WRITE POLLOUT

struct evsocket_event;
struct evsocket_ctx;

RIST_API struct evsocket_ctx *evsocket_create(void);
RIST_API void evsocket_loop(struct evsocket_ctx *ctx);
RIST_API void evsocket_loop_single(struct evsocket_ctx *ctx, int timeout);
RIST_API void evsocket_loop_finalize(struct evsocket_ctx *ctx);
RIST_API void evsocket_destroy(struct evsocket_ctx *ctx);
RIST_API struct evsocket_event *evsocket_addevent(struct evsocket_ctx *ctx, int fd, short events,
			void (*callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg),
			void (*err_callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg),
			void *arg);

RIST_API void evsocket_delevent(struct evsocket_ctx *ctx, struct evsocket_event *e);

#endif /* ifndef UDPSOCKET_H */
