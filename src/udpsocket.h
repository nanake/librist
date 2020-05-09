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

/* TODO: check errno on windows */
#include <errno.h>

#define UDPSOCKET_MAX_HOPS 32

#ifndef SOL_IP
#define SOL_IP 0x0
#define SOL_IPV6 0x29
#endif

/* Windows */
#ifdef _WIN32
#include <WinSock2.h>
#define _WINSOCKAPI_
#include <Windows.h>
#include <ws2tcpip.h>
#define AF_LOCAL AF_UNSPEC
#define if_nametoindex(name)  atoi(name)
#define close(s) closesocket(s)
typedef uint32_t socklen_t;

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
#endif /* Windows / POSIX */


/*** Public API ***/

/* Open a udp socket of family [af]
 *
 * Returns: socket descriptor, -1 for error (errno is set)
 *
 */
int udpsocket_open(uint16_t af);

/* Open a udp socket and binds it to local [host] + [port].
 *
 * binds to multicast interface [mciface], (if not NULL).
 *
 * Returns: socket descriptor, -1 for error (errno is set)
 * (In case of gai_error, -1 is returned, errno is not set, check gai_error)
 *
 */
int udpsocket_open_bind(const char *host, uint16_t port, const char *mciface);

/*
 * Explicitly set TX/RX buffer size for [sd] to [bufsize], in bytes.
 * Returns -1 on error, 0 on success.
 */
int udpsocket_set_buffer_size(int sd, uint32_t bufsize);

/*
 *
 * Retrieve current RX buffer size for [sd].
 * Returns 0 on error, current RX bufsize on success.
 */
uint32_t udpsocket_get_buffer_size(int sd);

/*
 * Explicitly set the mcast interface for the socket [sd] to [mciface] for address
 * family [family].
 * Returns 0 on success, -1 on error (errno is set accordingly).
 */
int udpsocket_set_mcast_iface(int sd, const char *mciface, uint16_t family);

/* Open a udp socket and connect it to remote [host] + [port].
 *
 * binds to multicast interface [mciface], (if not NULL).
 *
 * Returns: socket descriptor, -1 for error (errno is set)
 * (In case of gai_error, -1 is returned, errno is not set, check gai_error)
 *
 */
int udpsocket_open_connect(const char *host, uint16_t port, const char *mciface);

int udpsocket_resolve_host(const char *host, uint16_t port, struct sockaddr *addr);

int udpsocket_send(int sd, const void *buf, size_t size);
int udpsocket_sendto(int sd, const void *buf, size_t size, const char *host, uint16_t port);
int udpsocket_recv(int sd, void *buf, size_t size);
int udpsocket_close(int sd);
int udpsocket_parse_url(char *url, char *address, int address_maxlen, uint16_t *port, int *local);


#endif /* ifndef UDPSOCKET_H */
