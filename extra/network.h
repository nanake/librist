/* Copyright © 2006-2007 Rémi Denis-Courmont
 * Authors: Laurent Aimar <fenrir@videolan.org>
 *          Rémi Denis-Courmont
 * librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef NETWORK_HEADER__
#define NETWORK_HEADER__

#include "common.h"

__BEGIN_DECLS

#include <stddef.h>
#include "socket-shim.h"

struct network_url {
	char url[256];
	union {
		struct sockaddr address;
		struct sockaddr_storage storage;
	} u;
	socklen_t address_len;
	int address_family;
	int listening;

	char hostname[128];
	int port;
	char error[128];
};

RIST_PRIV int parse_url(char *url, struct network_url *parsed_url);

RIST_PRIV int init_socket_subsystem(void);

RIST_PRIV char *udp_GetErrorDescription(int err, char *bufferout);

/*****************************************************************************
 * udp_Close
 *****************************************************************************
 * Close an opened socket
 *****************************************************************************/
RIST_PRIV int udp_Close(int fd);

/*****************************************************************************
 * udp_Connect_Simple
 *****************************************************************************
 * Open a Datagram socket for sending data with an optional hop limit
 *****************************************************************************/
RIST_PRIV int udp_Connect_Simple(int family, int hlim, const char *miface);

/*****************************************************************************
 * udp_Connect
 *****************************************************************************
 * Open a Datagram socket for sending data to a defined destination with
 * an optional hop limit
 *****************************************************************************/
RIST_PRIV int udp_Connect(const char *host, int port, int hlim, int proto, const char *miface);

/*****************************************************************************
 * udp_Open and udp_Open2:
 *****************************************************************************
 * Open a datagram socket for receiving data and return a handle
 *****************************************************************************/
RIST_PRIV int udp_Open(const char *psz_bind, int i_bind,
             const char *psz_server, int i_server, int protocol, const char *miface);

/*****************************************************************************
 * udp_Read:
 *****************************************************************************
 * Read from an UDP socket
 * Returns -1 on error, on success the number of bytes read
 *****************************************************************************/
RIST_PRIV size_t udp_Read(int fd, void *buf, size_t len);

/*****************************************************************************
 * udp_Write:
 *****************************************************************************
 * Write to an UDP socket
 * Returns -1 on error, on success the number of bytes written
 *****************************************************************************/
RIST_PRIV size_t udp_Write(int fd, const void *buf, size_t len);

__END_DECLS

#endif
