/* Copyright © 2006-2007 Rémi Denis-Courmont
 * Authors: Laurent Aimar <fenrir@videolan.org>
 *          Rémi Denis-Courmont
 * librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include "network.h"
#include <stdio.h>
#include <string.h>
#include "socket-shim.h"

int parse_url(char *url, struct network_url *parsed_url)
{
	char *hostname, *cut, *p, *portstr = NULL;
	char *listening = NULL;
	long int port = 0;
	int ret;
	struct addrinfo *ai, *orig;
	struct sockaddr *res = NULL;

	if (!url) {
		snprintf(parsed_url->error, sizeof(parsed_url->error), "Invalid URL: (null)");
		goto err;
	} else if (strstr(url, " ") != NULL) {
		snprintf(parsed_url->error, sizeof(parsed_url->error), "Invalid space in url: %s", url);
		goto err;
	} else if (strlen(url) > sizeof(parsed_url->url)) {
		snprintf(parsed_url->error, sizeof(parsed_url->error), "url is too long (>%zu): %s", sizeof(parsed_url->url), url);
		goto err;
	}

	snprintf(parsed_url->url, sizeof(parsed_url->url), "%s", url);
	parsed_url->address_family = AF_LOCAL; /* means "unknown/autoselect" */

	cut = strstr(url, "://");
	if (cut && cut > url && ((char *)(cut - 1))[0] == '6') {
		parsed_url->address_family = AF_INET6;
		hostname = cut + 3;
		((struct sockaddr_in6 *)&parsed_url->u.address)->sin6_family = AF_INET6;
		p = strstr(hostname, "[");
		if (p) { /* IPv6 starts with "[" */
			hostname = p + 1;
			p = strstr(hostname, "]");
			if (!p) {
				snprintf(parsed_url->error, sizeof(parsed_url->error), "IPv6 must start with [");
				goto err;
			}

			if (*p) {
				*(p++) = (char)0;
			} else {
				snprintf(parsed_url->error, sizeof(parsed_url->error), "No port specified");
				goto err;
			}
		}
	} else if (cut) {
		parsed_url->address_family = AF_INET;
		parsed_url->address_len = sizeof(struct sockaddr_in);
		hostname = cut +3;
		p = hostname;
	} else { /* No prefix, assume ipv4 */
		parsed_url->address_family = AF_INET;
		hostname = url;
		p = hostname;
	}

	listening = strstr(hostname, "@");
	parsed_url->listening = (listening != NULL);
	if (listening) {
		hostname = listening + 1;
	}

	if (p) {
		p = strstr(p, ":");
		if (p && *(p + 1)) {
			*p = '\0'; /* Terminate hostname */
			portstr = ++p;
			port = strtol(portstr, NULL, 10);
			if ((port <= 0) || (port > 65535)) {
				snprintf(parsed_url->error, sizeof(parsed_url->error), "Invalid port '%s'", portstr);
				goto err;
			}
		} else {
			snprintf(parsed_url->error, sizeof(parsed_url->error), "No port specified");
			goto err;
		}
	}

	if ((!hostname || !*hostname) && listening) {
		if (parsed_url->address_family == AF_INET) {
			fprintf(stderr, "[INIT] No hostname specified: listening to 0.0.0.0");
			parsed_url->address_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)&parsed_url->u.address)->sin_family = AF_INET;
			((struct sockaddr_in *)&parsed_url->u.address)->sin_addr.s_addr = INADDR_ANY;
		} else {
			fprintf(stderr, "[INIT] No hostname specified: listening to [::0]");
			parsed_url->address_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in6 *)&parsed_url->u.address)->sin6_family = AF_INET6;
			((struct sockaddr_in6 *)&parsed_url->u.address)->sin6_addr = in6addr_any;
		}
	} else {
		ret = getaddrinfo(hostname, NULL, NULL, &orig);
		if (ret != 0) {
			snprintf(parsed_url->error, sizeof(parsed_url->error), "Error trying to resolve hostname %s", hostname);
			goto err;
		}

		for (ai = orig; ai != NULL; ai = ai->ai_next) {
			if (parsed_url->address_family == AF_LOCAL) {
				parsed_url->address_family = ai->ai_family;
				((struct sockaddr_in *)&parsed_url->u.address)->sin_family = ai->ai_family;
			}
			if (parsed_url->address_family == ai->ai_family) {
				res = ai->ai_addr;
				if (ai->ai_family == AF_INET) {
					parsed_url->address_len = sizeof(struct sockaddr_in);
					((struct sockaddr_in *)&parsed_url->u.address)->sin_family = AF_INET;
					memcpy(&parsed_url->u.address, res, parsed_url->address_len);
					break;
				}
				if (ai->ai_family == AF_INET6) {
					parsed_url->address_len = sizeof(struct sockaddr_in6);
					((struct sockaddr_in6 *)&parsed_url->u.address)->sin6_family = AF_INET6;
					memcpy(&parsed_url->u.address, res, parsed_url->address_len);
					break;
				}
			}
			// This loops until it finds the last non-null entry
		}
		freeaddrinfo(orig);
		if (!res || (parsed_url->address_family == AF_LOCAL)) {
			snprintf(parsed_url->error, sizeof(parsed_url->error), "Could not resolve hostname");
			goto err;
		}
	}

	if (parsed_url->address_family == AF_INET) {
		((struct sockaddr_in*)&parsed_url->u.address)->sin_port = htons(port);
	}

	if (parsed_url->address_family == AF_INET6) {
		((struct sockaddr_in6*)&parsed_url->u.address)->sin6_port = htons(port);
	}

	snprintf(parsed_url->hostname, sizeof(parsed_url->hostname), "%s", hostname);
	parsed_url->port = port;
	return 0;

err:
	parsed_url->address_family = AF_LOCAL;
	parsed_url->address_len = 0;
	return -1;
}

#define UDP_SOCK_BUFSIZE (30 * 1024 * 1024)

static int SetBroadcast(int s)
{
	return setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char *)&(int){ 1 }, sizeof(int));
}

static int SetReuseAddress(int s)
{
#if defined(SO_REUSEPORT)
	return setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&(int){ 1 }, sizeof(int));
#else
	return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&(int){ 1 }, sizeof(int));
#endif
}

static inline bool udp_SockAddrIsMulticast(const struct sockaddr *addr, socklen_t len)
{
	switch (addr->sa_family) {
#ifdef IN_MULTICAST
	case AF_INET: {
		const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
		if ((size_t)len < sizeof (*v4)) {
			return false;
		}

		return IN_MULTICAST(ntohl (v4->sin_addr.s_addr)) != 0;
	}
#endif

#ifdef IN6_IS_ADDR_MULTICAST
	case AF_INET6: {
		const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
		if ((size_t)len < sizeof (*v6)) {
			return false;
		}

		return IN6_IS_ADDR_MULTICAST(&v6->sin6_addr) != 0;
	} break;
#endif
	}

	return false;
}

static int SetMulticastHopLimit(int s, int family, int hop)
{
	int proto, cmd;

	switch (family) {
#ifdef IP_MULTICAST_TTL
	case AF_INET:
		proto = IPPROTO_IP;
		cmd = IP_MULTICAST_TTL;
	break;
#endif
#ifdef IPV6_MULTICAST_HOPS
	case AF_INET6:
		proto = IPPROTO_IPV6;
		cmd = IPV6_MULTICAST_HOPS;
	break;
#endif
	default:
		errno = EAFNOSUPPORT;
		return -1;
	break;
	}

	if (setsockopt(s, proto, cmd, (const char *)&hop, sizeof(hop)) == 0) {
		return 0;
	}

	/* Fallback for BSD compatibility */
	unsigned char buf;
	buf = (unsigned char)((hop > 255) ? 255 : hop);
	if (setsockopt(s, proto, cmd, &buf, sizeof(buf)) == 0) {
		return 0;
	}

	fprintf(stderr, "cannot set hop limit (%d): %s\n", hop, gai_strerror(errno));
	return -1;
}

static int SetMulticastInterface(int s, int family, const char *intf)
{
	//inet_aton

	int scope = if_nametoindex(intf);
	if (!scope) {
		return -1;
	}

	switch(family) {
#ifdef IPV6_MULTICAST_IF
	case AF_INET6:
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&scope, sizeof(scope)) == 0) {
			return 0;
		}
	break;
#endif

	case AF_INET:
#ifdef _WIN32
		if (setsockopt(s, SOL_IP, IP_MULTICAST_IF, (char *)&scope, sizeof(scope)) == 0) {
			return 0;
		}
#else
	{
		struct ip_mreqn req = { .imr_ifindex = scope };
		if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (char *)&req, sizeof(req)) == 0) {
			return 0;
		}
	}
#endif
	break;

	default:
		errno = EAFNOSUPPORT;
	break;
	}
	return -1;
}

/* Init Window socket subsystem */
int init_socket_subsystem(void)
{
#ifdef _WIN32
	int iResult;
	WSADATA wsaData;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", iResult);
		return -1;
	}
#endif

	return 0;
}

/**
 * Resolves a host name to a list of socket addresses (like getaddrinfo()).
 *
 * @param node host name to resolve (encoded as UTF-8), or NULL
 * @param i_port port number for the socket addresses
 * @param p_hints parameters (see getaddrinfo() manual page)
 * @param res pointer set to the resulting chained list.
 * @return 0 on success, a getaddrinfo() error otherwise.
 * On failure, *res is undefined. On success, it must be freed with
 * freeaddrinfo().
 */
static int udp_getaddrinfo(const char *node, int i_port,
							const struct addrinfo *p_hints,
							struct addrinfo **res)
{
	struct addrinfo hints;
	char psz_buf[NI_MAXHOST], psz_service[6];

	if ((i_port > 65535) || (i_port < 0)) {
		fprintf(stderr, "invalid port number %d specified\n", i_port);
		return EAI_SERVICE;
	}

	/* Convert integer to char * - cannot overflow */
	snprintf(psz_service, 6, "%d", i_port);

	/* Check if we have to force ipv4 or ipv6 */
	memset(&hints, 0, sizeof (hints));
	if (p_hints != NULL) {
		const int safe_flags =
			AI_PASSIVE |
			AI_CANONNAME |
			AI_NUMERICHOST |
			AI_NUMERICSERV |
#ifdef AI_ALL
			AI_ALL |
#endif
#ifdef AI_ADDRCONFIG
			AI_ADDRCONFIG |
#endif
#ifdef AI_V4MAPPED
			AI_V4MAPPED |
#endif
			0;

		hints.ai_family = p_hints->ai_family;
		hints.ai_socktype = p_hints->ai_socktype;
		hints.ai_protocol = p_hints->ai_protocol;
		/* Unfortunately, some flags chang the layout of struct addrinfo, so
		 * they cannot be copied blindly from p_hints to &hints. Therefore, we
		 * only copy flags that we know for sure are "safe".
		 */
		hints.ai_flags = p_hints->ai_flags & safe_flags;
	}
	/* We only ever use port *numbers* */
	hints.ai_flags |= AI_NUMERICSERV;

	/*
	 * Fixup node to allow more representations :
	 * - accept "" as NULL
	 * - ignore square brackets
	 */
	if (node != NULL) {
		if (node[0] == '[') {
			size_t len = strlen (node + 1);
			if ((len <= sizeof(psz_buf)) && (node[len] == ']')) {
				assert(len > 0);
				memcpy(psz_buf, node + 1, len - 1);
				psz_buf[len - 1] = '\0';
				node = psz_buf;
			}
		}

		if (node[0] == '\0') {
			node = NULL;
		}
	}

	int ret;
#ifdef WIN32
	/*
	 * Winsock tries to resolve numerical IPv4 addresses as AAAA
	 * and IPv6 addresses as A... There comes the bug-to-bug fix.
	 */
	if (!(hints.ai_flags & AI_NUMERICHOST)) {
		hints.ai_flags |= AI_NUMERICHOST;
		ret = getaddrinfo (node, psz_service, &hints, res);
		if (!ret) {
			goto out;
		}

		hints.ai_flags &= ~AI_NUMERICHOST;
	}
#endif
#ifdef AI_IDN
	/* Run-time I18n Domain Names support */
	hints.ai_flags |= AI_IDN;
	ret = getaddrinfo (node, psz_service, &hints, res);
	if (ret != EAI_BADFLAGS) {
		goto out;
	}

	/* IDN not available: disable and retry without it */
	hints.ai_flags &= ~AI_IDN;
#endif
	ret = getaddrinfo (node, psz_service, &hints, res);

#if defined(AI_IDN) || defined(WIN32)
out:
#endif
	return ret;
}

/*****************************************************************************
 * udp_Socket
 *****************************************************************************
 * Create a network socket of mentioned family and type for defined protocol.
 *****************************************************************************/
static int udp_Socket(int family, int socktype, int protocol)
{
	int sock = socket(family, socktype, protocol);
	if (sock == -1) {
		if (errno != EAFNOSUPPORT) {
			fprintf(stderr, "cannot create socket: %s\n", gai_strerror(errno));
		}

		return -1;
	}

	SetReuseAddress(sock);

#ifdef IPV6_V6ONLY
	/* Accepts only IPv6 connections on IPv6 sockets. */
	if (family == AF_INET6) {
		setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&(int){ 1 }, sizeof (int));
	}
#endif

#if defined (WIN32)
# ifndef IPV6_PROTECTION_LEVEL
#  warning Please update your C library headers.
#  define IPV6_PROTECTION_LEVEL 23
#  define PROTECTION_LEVEL_UNRESTRICTED 10
# endif
	if (family == AF_INET6) {
		setsockopt(sock, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL,
		(const char *)&(int){ PROTECTION_LEVEL_UNRESTRICTED }, sizeof (int));
	}
#endif

	return sock;
}

static int getSO_ERROR(int fd)
{
	int err = 1;
	socklen_t len = sizeof err;

	if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len)) {
		fprintf(stderr, "getSO_ERROR\n");
	}

	if (err) {
		errno = err; // set errno to the socket SO_ERROR
	}

	return err;
}

/*****************************************************************************
 * udp_Close
 *****************************************************************************
 * Close a network socket
 *****************************************************************************/
int udp_Close(int sock)
{
	int ret = 0;
	if (sock >= 0) {
		getSO_ERROR(sock); // first clear any errors, which can cause close to fail
		if (shutdown(sock, 2) < 0) { // secondly, terminate the 'reliable' delivery
			if (errno != ENOTCONN && errno != EINVAL) { // SGI causes EINVAL
				fprintf(stderr, "shutdown\n");
			}
		}
#ifdef _WIN32
		ret = closesocket(sock); // finally call close()
#else
		ret = close(sock); // finally call close()
#endif
	}
	return ret;
}

/*****************************************************************************
 * udp_GetIntfIndex
 *****************************************************************************
 * Get interface index.
 *****************************************************************************/
static unsigned int udp_GetIntfIndex(const char *miface)
{
	unsigned int ifindex = if_nametoindex(miface);
	if (!ifindex) {
		fprintf(stderr, "invalid multicast interface: %s\n", miface);
	}

	return ifindex;
}

/*****************************************************************************
 * udp_Subscribe
 *****************************************************************************
 * multicast join the old way
 *****************************************************************************/
static int udp_Subscribe(int fd, const char *miface,
						 const struct sockaddr *grp, socklen_t grplen)
{
	RIST_MARK_UNUSED(miface);
/* MCAST_JOIN_GROUP was introduced to OS X in v10.7, but it doesn't work,
 * so ignore it to use the same code as on 10.5 or 10.6 */
#if defined (MCAST_JOIN_GROUP) && !defined (__APPLE__)
	/* Agnostic SSM multicast join */
	int level;
	struct group_req gr;

	memset(&gr, 0, sizeof (gr));
	gr.gr_interface = udp_GetIntfIndex(miface);

#ifdef __unix__
	if (!gr.gr_interface) {
		int err = errno;
		fprintf(stderr, "cannot join multicast group for %s: %s (%d)\n", miface, strerror(err), err);
		return -1 * err;
	}
#endif

	switch (grp->sa_family) {
#ifdef AF_INET6
	case AF_INET6: {
		const struct sockaddr_in6 *g6 = (const struct sockaddr_in6 *)grp;
		level = SOL_IPV6;
		assert (grplen >= sizeof(struct sockaddr_in6));
		if (g6->sin6_scope_id != 0) {
			gr.gr_interface = g6->sin6_scope_id;
		}
	} break;
#endif
	case AF_INET:
		level = SOL_IP;
	break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	break;
	}

	assert(grplen <= sizeof (gr.gr_group));
	memcpy(&gr.gr_group, grp, grplen);
	if (setsockopt(fd, level, MCAST_JOIN_GROUP, (const char *)&gr, sizeof(gr)) == 0) {
		return 0;
	}
#else
	switch (grp->sa_family) {
 # ifdef IPV6_JOIN_GROUP
	case AF_INET6: {
		struct ipv6_mreq ipv6mr;
		const struct sockaddr_in6 *g6 = (const struct sockaddr_in6 *) grp;

		memset(&ipv6mr, 0, sizeof (ipv6mr));
		assert(grplen >= sizeof (struct sockaddr_in6));
		ipv6mr.ipv6mr_multiaddr = g6->sin6_addr;
		ipv6mr.ipv6mr_interface = g6->sin6_scope_id;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &ipv6mr, sizeof (ipv6mr)) == 0) {
			return 0;
		}
	} break;
 # endif
 # ifdef IP_ADD_MEMBERSHIP
	case AF_INET: {
		 struct ip_mreq imr;

		 memset(&imr, 0, sizeof (imr));
		 assert(grplen >= sizeof (struct sockaddr_in));
		 imr.imr_multiaddr = ((const struct sockaddr_in *)grp)->sin_addr;
		 if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof (imr)) == 0)
			 return 0;
	} break;
 # endif
	default:
		 errno = EAFNOSUPPORT;
	break;
	}
 #endif

	fprintf(stderr, "cannot join multicast group: %s\n", strerror(errno));
	return -1;
 }

/*****************************************************************************
 * udp_SourceSubscribe
 *****************************************************************************
 * multicast join, with fallback to old APIs, and fallback from SSM to ASM.
 *****************************************************************************/
static int udp_SourceSubscribe(int fd, const char *miface,
					 const struct sockaddr *src, socklen_t srclen,
					 const struct sockaddr *grp, socklen_t grplen)
{
#ifdef MCAST_JOIN_SOURCE_GROUP
	/* Agnostic SSM multicast join */
	int level;
	struct group_source_req gsr;

	memset(&gsr, 0, sizeof (gsr));
	gsr.gsr_interface = udp_GetIntfIndex(miface);

	switch (grp->sa_family) {
#ifdef AF_INET6
		case AF_INET6: {
			const struct sockaddr_in6 *g6 = (const struct sockaddr_in6 *)grp;
			level = IPPROTO_IPV6;
			assert(grplen >= sizeof (struct sockaddr_in6));
			if (g6->sin6_scope_id != 0) {
				gsr.gsr_interface = g6->sin6_scope_id;
			}
		} break;
#endif
		case AF_INET:
			level = IPPROTO_IP;
		break;
		default:
			errno = EAFNOSUPPORT;
			return -1;
		break;
	}

	assert(grplen <= sizeof (gsr.gsr_group));
	memcpy(&gsr.gsr_source, src, srclen);
	assert(srclen <= sizeof (gsr.gsr_source));
	memcpy(&gsr.gsr_group,  grp, grplen);
	if (setsockopt(fd, level, MCAST_JOIN_SOURCE_GROUP, (const char *)&gsr, sizeof (gsr)) == 0) {
		return 0;
	}

#else
	if (src->sa_family != grp->sa_family) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	switch (grp->sa_family) {
# ifdef IP_ADD_SOURCE_MEMBERSHIP
	/* IPv4-specific API */
	case AF_INET: {
		struct ip_mreq_source imr;

		memset(&imr, 0, sizeof (imr));
		assert(grplen >= sizeof (struct sockaddr_in));
		imr.imr_multiaddr = ((const struct sockaddr_in *)grp)->sin_addr;
		assert(srclen >= sizeof (struct sockaddr_in));
		imr.imr_sourceaddr = ((const struct sockaddr_in *)src)->sin_addr;
		if (setsockopt(fd, SOL_IP, IP_ADD_SOURCE_MEMBERSHIP, &imr, sizeof (imr)) == 0)
			return 0;
	} break;
# endif
	default:
		errno = EAFNOSUPPORT;
	break;
	}

#endif
	fprintf(stderr, "cannot join source multicast group: %s\n", gai_strerror(errno));
	fprintf(stderr, "trying ASM instead of SSM...\n");
	return udp_Subscribe(fd, miface, grp, grplen);
}

/*****************************************************************************
 * udp_SetupDgramSocket
 *****************************************************************************
 * Setup an UDP datagram socket
 *****************************************************************************/
static int udp_SetupDgramSocket(int fd, const struct addrinfo *ptr )
{
	SetReuseAddress(fd);

#ifdef SO_RCVBUF
	/* Increase the receive buffer size to UDP_SOCK_BUFSIZE
	 * to avoid packet loss caused in case of scheduling hiccups */
	setsockopt (fd, SOL_SOCKET, SO_RCVBUF,
				(void *)&(int){ UDP_SOCK_BUFSIZE }, sizeof (int));
	setsockopt (fd, SOL_SOCKET, SO_SNDBUF,
				(void *)&(int){ UDP_SOCK_BUFSIZE }, sizeof (int));
#endif

#if defined (WIN32)
	if (udp_SockAddrIsMulticast(ptr->ai_addr, ptr->ai_addrlen) &&
		(sizeof(struct sockaddr_storage) >= ptr->ai_addrlen)) {
		// This works for IPv4 too - don't worry!
		struct sockaddr_in6 dumb = {
			.sin6_family = ptr->ai_addr->sa_family,
			.sin6_port =  ((struct sockaddr_in *)(ptr->ai_addr))->sin_port
		};

		bind(fd, (struct sockaddr *)&dumb, ptr->ai_addrlen);
	}
	else
#endif
	if (bind(fd, ptr->ai_addr, ptr->ai_addrlen)) {
#if defined (WIN32)
		int err = WSAGetLastError();
#else
		int err = errno;
#endif
		udp_Close(fd);
		fprintf(stderr, "bind error: %d\n", err);
		return -1 * err;
	}

	return fd;
}

char *udp_GetErrorDescription(int err, char *bufferout)
{
	char msgbuf[256]; // for a message up to 255 bytes.
	err = -1 * err;
	msgbuf[0] = '\0'; // Microsoft doesn't guarantee this on man page.
#if defined (WIN32)
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, // flags
		NULL,                // lpsource
		err,                 // message id
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),    // languageid
		msgbuf,              // output buffer
		sizeof(msgbuf),     // size of msgbuf, bytes
		NULL);               // va_list of arguments
	if (msgbuf[0] == '\0') {
		sprintf(bufferout, "%d", err);  // provide error # if no string available
	}
#else
	if (err < 135) { //sys_nerr
		snprintf(msgbuf, sizeof(msgbuf), "%s", strerror(err));
	} else {
		snprintf(msgbuf, sizeof(msgbuf), "%s", gai_strerror(err));
	}
#endif
	snprintf(bufferout, sizeof(msgbuf), "%s", msgbuf);
	return bufferout;
}

/*****************************************************************************
 * udp_ListenSimple
 *****************************************************************************
 * Open a network socket for receiving data
 *****************************************************************************/
static int udp_ListenSimple(const char *host, int port, int protocol, const char *miface)
{
	struct addrinfo hints, *res;
	char service[6];

	if ((port > 65535) || (port < 0)) {
		fprintf(stderr, "invalid port number %d specified\n", port);
		return EAI_SERVICE;
	}

	/* Convert port to string - cannot overflow */
	snprintf(service, 6, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;

	if (host && !*host) {
		host = NULL;
	}

	fprintf(stderr, "network: opening %s datagram port %d\n",
					host ? host : "any", port);

	int val = udp_getaddrinfo(host, port, &hints, &res);
	if (val) {
		fprintf(stderr, "Cannot resolve %s port %d: %s\n"
				, host, port, gai_strerror (val));
		return -1;
	}

	val = -1;
	int ret = 0;

	for (const struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next) {
		int fd = udp_Socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (fd == -1) {
			fprintf(stderr, "socket error: %s\n", gai_strerror(errno));
			continue;
		}

#ifdef IPV6_V6ONLY
		/* Try dual-mode IPv6 if available. */
		if (ptr->ai_family == AF_INET6) {
			setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&(int){ 0 }, sizeof (int));
		}
#endif

		fd = udp_SetupDgramSocket(fd, ptr);
		if (fd < 0) {
			val = fd;
			continue;
		}

		if (miface) {
			if (udp_SockAddrIsMulticast(ptr->ai_addr, ptr->ai_addrlen)) {
				ret = udp_Subscribe(fd, miface, ptr->ai_addr, ptr->ai_addrlen);
				if (ret != 0) {
					udp_Close(fd);
					continue;
				}
			}
		}

		val = fd;
		break;
	}

	freeaddrinfo(res);
	if (val == -1 && ret < 0) {
		return ret;
	} else {
		return val;
	}
}

/*****************************************************************************
 * udp_Connect
 *****************************************************************************
 * Open a Datagram socket for sending data to a defined destination with
 * an optional hop limit
 *****************************************************************************/
int udp_Connect(const char *host, int port, int hlim, int proto, const char *miface)
{
	struct addrinfo hints, *res, *ptr;
	int val, sock = -1;
	bool b_unreach = false;

	if( hlim < 0 ) {
		hlim = 0;
	}

	memset(&hints, 0, sizeof( hints ));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = proto;

	fprintf(stderr, "net: connecting to [%s]:%d\n", host, port );

	val = udp_getaddrinfo(host, port, &hints, &res);
	if (val) {
		fprintf(stderr, "cannot resolve [%s]:%d : %s\n", host, port,
				 gai_strerror(val));
		return -1;
	}

	for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
		int fd = udp_Socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (fd == -1) {
			continue;
		}

#ifdef SO_RCVBUF
		/* Increase the receive buffer size to UDP_SOCK_BUFSIZE
		 * to avoid packet loss caused by scheduling problems */
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&(int){ UDP_SOCK_BUFSIZE }, sizeof (int));
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&(int){ UDP_SOCK_BUFSIZE }, sizeof (int));
#endif

		/* Allow broadcast sending */
		SetBroadcast(fd);

		if (hlim >= 0) {
			SetMulticastHopLimit(fd, ptr->ai_family, hlim);
		}

		if (miface != NULL) {
			SetMulticastInterface(fd, ptr->ai_family, miface);
		}

		if (!connect(fd, ptr->ai_addr, ptr->ai_addrlen)) {
			/* success */
			sock = fd;
			break;
		}

#if defined( WIN32 ) || defined( UNDER_CE )
		if( WSAGetLastError() == WSAENETUNREACH ) {
#else
		if( errno == ENETUNREACH ) {
#endif
			b_unreach = true;
		} else {
			fprintf(stderr, "Warning %s port %d: %s\n", host, port,
					gai_strerror(errno));
			udp_Close(fd);
			continue;
		}
	}
	freeaddrinfo(res);

	if (sock == -1) {
		if (b_unreach) {
			fprintf(stderr, "Host %s port %d is unreachable\n", host, port);
#if defined( WIN32 ) || defined( UNDER_CE )
			return -1 * WSAENETUNREACH;
#else
			return -1 * ENETUNREACH;
#endif
		}
		return -1;
	}

	return sock;
}

/*****************************************************************************
 * udp_Connect_simple
 *****************************************************************************
 * Open a Datagram socket for sending data with an optional hop limit
 *****************************************************************************/
int udp_Connect_Simple(int family, int hlim, const char *miface)
{
	int fd = udp_Socket(family, SOCK_DGRAM, 0);
	if (fd != -1) {
#ifdef SO_RCVBUF
		/* Incportrease the transmit and receive buffer size to UDP_SOCK_BUFSIZE
			* to avoid packet loss caused by scheduling problems */
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&(int){ UDP_SOCK_BUFSIZE }, sizeof (int));
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&(int){ UDP_SOCK_BUFSIZE }, sizeof (int));
#endif

		/* Allow broadcast sending */
		SetBroadcast(fd);

		if (hlim >= 0) {
			SetMulticastHopLimit(fd, family, hlim);
		}

		if (miface != NULL) {
			SetMulticastInterface(fd, family, miface);
		}
	}

	return fd;
}

/*****************************************************************************
 * udp_Open:
 *****************************************************************************
 * Open a datagram socket for receiving data and return a handle
 *****************************************************************************/
int udp_Open(const char *psz_bind, int i_bind,
			 const char *psz_server, int i_server, int protocol, const char *miface)
{
	if ((psz_server == NULL) || (psz_server[0] == '\0')) {
		return udp_ListenSimple(psz_bind, i_bind, protocol, miface);
	}

	fprintf(stderr, "net: connecting to [%s]:%d from [%s]:%d\n",
					psz_server, i_server, psz_bind, i_bind);

	struct addrinfo hints, *loc, *rem;
	int val;

	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = protocol;

	val = udp_getaddrinfo(psz_server, i_server, &hints, &rem);
	if (val) {
		fprintf(stderr, "cannot resolve %s port %d : %s\n",
			psz_server, i_server, gai_strerror(val));
		return -1 * val;
	}

	hints.ai_flags = AI_PASSIVE;
	val = udp_getaddrinfo(psz_bind, i_bind, &hints, &loc);
	if (val) {
		fprintf(stderr, "cannot resolve %s port %d : %s\n",
				psz_bind, i_bind, gai_strerror(val));
		freeaddrinfo (rem);
		return -1 * val;
	}

	val = -1;
	for (struct addrinfo *ptr = loc; ptr != NULL; ptr = ptr->ai_next) {
		int fd = udp_Socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (fd == -1) {
			continue; // usually, address family not supported
		}

		fd = udp_SetupDgramSocket(fd, ptr);
		if (fd <= 0) {
			continue;
		}

		for (struct addrinfo *ptr2 = rem; ptr2 != NULL; ptr2 = ptr2->ai_next) {
			if ((ptr2->ai_family != ptr->ai_family) ||
				(ptr2->ai_socktype != ptr->ai_socktype) ||
				(ptr2->ai_protocol != ptr->ai_protocol)) {
				continue;
			}

			if (miface) {
				if (udp_SockAddrIsMulticast(ptr->ai_addr, ptr->ai_addrlen)) {
					int ret = udp_SourceSubscribe(fd, miface,
											ptr2->ai_addr, ptr2->ai_addrlen,
											ptr->ai_addr, ptr->ai_addrlen);
					if (!ret) {
						if (connect(fd, ptr2->ai_addr, ptr2->ai_addrlen)) {
							fprintf(stderr, "cannot connect to %s port %d (%s): %s\n",
									psz_server, i_server, miface, gai_strerror(errno));
							continue;
						}
					}
				}
			} else {
				if (connect(fd, ptr2->ai_addr, ptr2->ai_addrlen)) {
					fprintf(stderr, "cannot connect to %s port %d: %s\n",
							psz_server, i_server, gai_strerror(errno));
					continue;
				}
			}
			val = fd;
			break;
		}

		if (val > 0)
			break;

		udp_Close (fd);
	}

	freeaddrinfo (rem);
	freeaddrinfo (loc);
	return val;
}

/*****************************************************************************
 * udp_Read:
 *****************************************************************************
 * Read from an UDP socket
 *****************************************************************************/
size_t udp_Read(int fd, void *buf, size_t len)
{
	int ret = -1;

retry:
	ret = recv(fd, buf, len, 0);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
			/* retry */
			goto retry;
		break;
		case EBADF:
		case ENOTSOCK:
			fprintf(stderr, "invalid socket %d\n", fd);
		break;
		case ECONNRESET:
			fprintf(stderr, "peer reset connection %d\n", fd);
		break;
		case EINTR:
			/* try again */
			goto retry;
		break;
		case ENOTCONN:
			fprintf(stderr, "socket %d is not connected\n", fd);
		break;
		default:
			fprintf(stderr, "socket %d error: %s\n", fd, gai_strerror(errno));
		break;
		}
	}

	return ret;
}

/*****************************************************************************
 * udp_Write:
 *****************************************************************************
 * Write to an UDP socket
 *****************************************************************************/
size_t udp_Write(int fd, const void *buf, size_t len)
{
	int ret = -1;
	int retries = 0;

retry:
	if (++retries > 5)
		return -1;
	ret = send(fd, buf, len, 0);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
			/* retry */
			goto retry;
		break;
		case EBADF:
		case ENOTSOCK:
			fprintf(stderr, "invalid socket %d\n", fd);
		break;
		case ECONNRESET:
			fprintf(stderr, "peer reset connection %d\n", fd);
		break;
		case EINTR:
			/* try again */
			goto retry;
		break;
		case ECONNREFUSED:
			// Ignore, we do not care if no one is listening
		break;
		case ENOTCONN:
			fprintf(stderr, "socket %d is not connected\n", fd);
		break;
		default:
			if (errno < 135) { //sys_nerr
				fprintf(stderr, "socket %d error: %d / %s\n", fd, errno, strerror(errno));
			} else {
				fprintf(stderr, "socket %d error: %d / %s\n", fd, errno, gai_strerror(errno));
			}
		break;
		}
	}

	return ret;
}
