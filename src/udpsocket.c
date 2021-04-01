/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "librist/udpsocket.h"
#include "log-private.h"
#ifdef _WIN32
#include <ws2ipdef.h>
#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP 41
#endif
#endif

/* Private functions */
static const int yes = 1; // no = 0;

/* Public API */

int udpsocket_resolve_host(const char *host, uint16_t port, struct sockaddr *addr)
{
	struct sockaddr_in *a4 = (struct sockaddr_in *)addr;
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)addr;

	/* Pre-check for numeric IPv6 */
	if (inet_pton(AF_INET6, host, &a6->sin6_addr) > 0) {
		a6->sin6_family = AF_INET6;
		a6->sin6_port = htons(port);
	}
	/* Pre-check for numeric IPv4 */
	else if (inet_pton(AF_INET, host, &a4->sin_addr) > 0) {
		a4->sin_family = AF_INET;
		a4->sin_port = htons(port);
		/* Try to resolve host */
	} else {
		struct addrinfo *res;
		int gai_ret = getaddrinfo(host, NULL, NULL, &res);
		if (gai_ret != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Failure resolving host %s: %s\n", host, gai_strerror(gai_ret));
			return -1;
		}
		if (res[0].ai_family == AF_INET6) {
			memcpy(a6, res[0].ai_addr, sizeof(struct sockaddr_in6));
			a6->sin6_port = htons(port);
		} else {
			memcpy(a4, res[0].ai_addr, sizeof(struct sockaddr_in));
			a4->sin_port = htons(port);
		}
		freeaddrinfo(res);
	}
	return 0;
}

int udpsocket_open(uint16_t af)
{
	int sd = socket(af, SOCK_DGRAM, 0);
	if (sd < 0) {
#ifdef _WIN32
		sd = -1 * WSAGetLastError();
#endif
	}
	return sd;
}

int udpsocket_set_optimal_buffer_size(int sd)
{
	uint32_t bufsize = UDPSOCKET_SOCK_BUFSIZE;
	uint32_t current_recvbuf = udpsocket_get_buffer_size(sd);
	if (current_recvbuf < bufsize){
		setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(uint32_t));
		current_recvbuf = udpsocket_get_buffer_size(sd);
#if defined(SO_RCVBUFFORCE)
		if (current_recvbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_RCVBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_recvbuf = udpsocket_get_buffer_size(sd);
		}
#endif
	}
	if (current_recvbuf < bufsize){
		// Settle for a smaller size
		bufsize = UDPSOCKET_SOCK_BUFSIZE/5;
		setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(uint32_t));
		current_recvbuf = udpsocket_get_buffer_size(sd);
#if defined(SO_RCVBUFFORCE)
		if (current_recvbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_RCVBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_recvbuf = udpsocket_get_buffer_size(sd);
		}
#endif
	}
	if (current_recvbuf < bufsize){
		rist_log_priv3( RIST_LOG_ERROR, "Your UDP receive buffer is set < 200 kbytes (%"PRIu32") and the kernel denied our request for an increase. It's recommended to set your net.core.rmem_max setting to at least 200 kbyte for best results.", current_recvbuf);
		return -1;
	}
	return 0;
}

int udpsocket_set_optimal_buffer_send_size(int sd)
{
	uint32_t bufsize = UDPSOCKET_SOCK_BUFSIZE;
	uint32_t current_sendbuf = udpsocket_get_buffer_send_size(sd);
	if (current_sendbuf < bufsize){
		setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(uint32_t));
		current_sendbuf = udpsocket_get_buffer_send_size(sd);
#if defined(SO_SNDBUFFORCE)
		if (current_sendbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_SNDBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_sendbuf = udpsocket_get_buffer_send_size(sd);
		}
#endif
	}
	if (current_sendbuf < bufsize){
		// Settle for a smaller size
		bufsize = UDPSOCKET_SOCK_BUFSIZE/5;
		setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(uint32_t));
		current_sendbuf = udpsocket_get_buffer_send_size(sd);
#if defined(SO_SNDBUFFORCE)
		if (current_sendbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_SNDBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_sendbuf = udpsocket_get_buffer_send_size(sd);
		}
#endif
	}
	if (current_sendbuf < bufsize){
		rist_log_priv3( RIST_LOG_ERROR, "Your UDP send buffer is set < 200 kbytes (%"PRIu32") and the kernel denied our request for an increase. It's recommended to set your net.core.rmem_max setting to at least 200 kbyte for best results.", current_sendbuf);
		return -1;
	}
	return 0;
}

int udpsocket_set_buffer_size(int sd, uint32_t bufsize)
{
	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(uint32_t)) < 0)
		return -1;
	return 0;
}

int udpsocket_set_buffer_send_size(int sd, uint32_t bufsize)
{
	if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(uint32_t)) < 0)
		return -1;
	return 0;
}

uint32_t udpsocket_get_buffer_size(int sd)
{
	uint32_t bufsize;
	socklen_t val_size = sizeof(uint32_t);
	if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, &val_size) < 0)
		return 0;
	return bufsize;
}

uint32_t udpsocket_get_buffer_send_size(int sd)
{
	uint32_t bufsize;
	socklen_t val_size = sizeof(uint32_t);
	if (getsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, &val_size) < 0)
		return 0;
	return bufsize;
}

int udpsocket_set_mcast_iface(int sd, const char *mciface, uint16_t family)
{
#ifndef _WIN32
	int scope = if_nametoindex(mciface);
#else
	int scope = atoi(mciface);
#endif
	if (scope == 0)
		return -1;
#ifdef _WIN32
	RIST_MARK_UNUSED(family);
	return setsockopt(sd, SOL_IP, IP_MULTICAST_IF, (char *)&scope, sizeof(scope));
#else
	if (family == AF_INET6) {
		return setsockopt(sd, SOL_IPV6, IPV6_MULTICAST_IF, &scope, sizeof(scope));
	} else {
		struct ip_mreqn req = { .imr_ifindex = scope };
		return setsockopt(sd, SOL_IP, IP_MULTICAST_IF, &req, sizeof(req));
	}
	return -1;
#endif
}

bool is_ip_address(const char *ipaddress, int family) {
	struct sockaddr_in sa;
	int result = inet_pton(family, ipaddress, &(sa.sin_addr));
	return result == 1;
}

int udpsocket_join_mcast_group(int sd, const char* miface, struct sockaddr* sa, uint16_t family) {
	if (family != AF_INET)
		return -1;
	char address[INET6_ADDRSTRLEN];
	char mcastaddress[INET6_ADDRSTRLEN];
	struct sockaddr_in *mcast_v4 = (struct sockaddr_in *)sa;
	inet_ntop(AF_INET, &(mcast_v4->sin_addr), mcastaddress, INET_ADDRSTRLEN);
	uint32_t src_addr = htonl(INADDR_ANY);
	int ifindex = 0;

	if (is_ip_address(miface, AF_INET))	{
		src_addr = inet_addr(miface);
	} else if (miface != NULL && miface[0] != '\0') {
#ifndef _WIN32
		ifindex = if_nametoindex(miface);
#else
		ifindex = atoi(miface);
#endif
		if (!ifindex) {
			rist_log_priv3(RIST_LOG_ERROR, "Failed to get interface index error: %s\n", strerror(errno));
			rist_log_priv3(RIST_LOG_INFO, "Falling back to joining via default route\n");
		}
	}
#ifdef MCAST_JOIN_GROUP
	if (ifindex) {
		struct group_req gr;
		gr.gr_interface = ifindex;
		memcpy(&gr.gr_group, mcast_v4, sizeof(*mcast_v4));
		rist_log_priv3(RIST_LOG_INFO, "Joining multicast address: %s with %s\n", mcastaddress, miface);
		if (setsockopt(sd, SOL_IP, MCAST_JOIN_GROUP, (const char *)&gr, sizeof(gr)) == 0) {
			return 0;
		}
	}
#endif
	inet_ntop(AF_INET, &(src_addr), address, INET_ADDRSTRLEN);
	rist_log_priv3(RIST_LOG_INFO, "Joining multicast address: %s from IP %s\n", mcastaddress, address);
	struct ip_mreq group;
	group.imr_multiaddr.s_addr = mcast_v4->sin_addr.s_addr;
	group.imr_interface.s_addr = src_addr;
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
		rist_log_priv3( RIST_LOG_ERROR, "Failed to join multicast group\n");
		goto fail;
	}
	return 0;

fail:
	return -1;
}

int udpsocket_open_connect(const char *host, uint16_t port, const char *mciface)
{
	int sd;
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	uint16_t proto;
	uint32_t ttlcmd;
	const uint32_t ttl = UDPSOCKET_MAX_HOPS;

	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	sd = udpsocket_open(raw.sin6_family);
	if (sd < 0)
		return sd;

	if (raw.sin6_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		proto = IPPROTO_IPV6;
		ttlcmd = IPV6_MULTICAST_HOPS;
	} else {
		addrlen = sizeof(struct sockaddr_in);
		proto = IPPROTO_IP;
		ttlcmd = IP_MULTICAST_TTL;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(int)) < 0) {
		/* Non-critical error */
		rist_log_priv3( RIST_LOG_ERROR,"Cannot set SO_REUSEADDR: %s\n", strerror(errno));
	}
	if (setsockopt(sd, proto, ttlcmd, (char *)&ttl, sizeof(ttl)) < 0) {
		/* Non-critical error */
		rist_log_priv3( RIST_LOG_ERROR,"Cannot set socket MAX HOPS: %s\n", strerror(errno));
	}
	if (mciface && mciface[0] != '\0')
		udpsocket_set_mcast_iface(sd, mciface, raw.sin6_family);

	if (connect(sd, (struct sockaddr *)&raw, addrlen) < 0) {
		int err = errno;
		close(sd);
		errno = err;
		return -1;
	}

	return sd;
}

int udpsocket_open_bind(const char *host, uint16_t port, const char *mciface)
{
	int sd;
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	sd = udpsocket_open(raw.sin6_family);
	if (sd < 0)
		return sd;

	int is_multicast = 0;
	if (raw.sin6_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		is_multicast = IN6_IS_ADDR_MULTICAST(&raw.sin6_addr);
	} else {
		struct sockaddr_in *tmp = (struct sockaddr_in*)&raw;
		addrlen = sizeof(struct sockaddr_in);
		is_multicast = IN_MULTICAST(ntohl(tmp->sin_addr.s_addr));
	}
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(int)) < 0) {
		/* Non-critical error */
		rist_log_priv3( RIST_LOG_ERROR, "Cannot set SO_REUSEADDR: %s\n", strerror(errno));
	}
#if defined(_WIN32) || defined(__APPLE__)
	if (is_multicast) {
		struct sockaddr_in6 sa = { .sin6_family = raw.sin6_family, .sin6_port = raw.sin6_port };
		if (bind(sd, (struct sockaddr *)&sa, addrlen) < 0)	{
			rist_log_priv3(RIST_LOG_ERROR, "Could not bind to interface: %s\n", strerror(errno));
			close(sd);
			return -1;
		}
	} else
#endif
	if (bind(sd, (struct sockaddr *)&raw, addrlen) < 0)	{
		rist_log_priv3( RIST_LOG_ERROR, "Could not bind to interface: %s\n", strerror(errno));
		close(sd);
		return -1;
	}
	if (is_multicast) {
		if (udpsocket_join_mcast_group(sd, mciface, (struct sockaddr *)&raw, raw.sin6_family) != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Could not join multicast group: %s on %s\n", host, mciface);
			return -1;
		}
	}

	return sd;
}

int udpsocket_set_nonblocking(int sd)
{
#ifdef _WIN32
	u_long iMode=1;
	ioctlsocket(sd, FIONBIO, &iMode);
#else
	RIST_MARK_UNUSED(sd);
#endif
	return 0;
}

int udpsocket_send_nonblocking(int sd, const void *buf, size_t size)
{
	return (int)send(sd, buf, size, MSG_DONTWAIT);
}

int udpsocket_send(int sd, const void *buf, size_t size)
{
	return (int)send(sd, buf, size, 0);
}

int udpsocket_sendto(int sd, const void *buf, size_t size, const char *host, uint16_t port)
{
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	if (raw.sin6_family == AF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else
		addrlen = sizeof(struct sockaddr_in);
	return (int)sendto(sd, buf, size, 0, (struct sockaddr *)(&raw), addrlen);
}

int udpsocket_recv(int sd, void *buf, size_t size)
{
	return (int)recv(sd, buf, size, 0);
}

int udpsocket_recvfrom(int sd, void *buf, size_t size, int flags, struct sockaddr *addr, socklen_t *addr_len)
{
	return (int)recvfrom(sd, buf, size, flags, addr, addr_len);
}

int udpsocket_close(int sd)
{
	return close(sd);
}

int udpsocket_parse_url_parameters(const char *url, udpsocket_url_param_t *params, int max_params,
	uint32_t *clean_url_len)
{
	char* query = NULL;
	int i = 0;
	char *token = NULL;

	query = strchr( url, '?' );
	if (query != NULL)
		*clean_url_len = (uint32_t)(query - url + 1);
	else
		*clean_url_len = (uint32_t)(strlen(url) + 1);

	if (!query || *query == '\0')
		return -1;
	if (!params || max_params == 0)
		return 0;

	const char amp[2] = "&";
	token = strtok( query + 1, amp );
	while (token != NULL && i < max_params) {
		params[i].key = token;
		params[i].val = NULL;
		if ((params[i].val = strchr( params[i].key, '=' )) != NULL) {
			size_t val_len = strlen( params[i].val );
			*(params[i].val) = '\0';
			if (val_len > 1) {
				params[i].val++;
				if (params[i].key[0])
					i++;
			};
		}
		token = strtok( NULL, amp );
	}
	return i;
}

int udpsocket_parse_url(char *url, char *address, int address_maxlen, uint16_t *port, int *local)
{
	char *p_port = NULL, *p_addr = (char *)url;
	int using_sqbrkts = 0;
	char *p;
	if (!url)
		return -1;

	p = url;
	if (strlen(p) < 1)
		return -1;

	while (1) {
		char *p_slash;
		p_slash = strchr(p, '/');
		if (!p_slash)
			break;
		p = p_slash + 1;
	}
	p_addr = p;
	if (*p_addr == '@') {
		*local = 1;
		p_addr++;
	} else
		*local = 0;

	if (*p_addr == '[') {
		using_sqbrkts = 1;
		p_addr++;
	}
	p = p_addr;
	if (using_sqbrkts) {
		char *p_end;
		p_end = strchr(p, ']');
		if (!p_end)
			return -1;
		*p_end = 0;
		p = p_end + 1;
	}
	p_port = strchr(p, ':');
	if (p_port) {
		*p_port = 0;
		p_port++;
	}
	if (p_port && (strlen(p_port) > 0))
		*port = (uint16_t)atoi(p_port);

	if (strlen(p_addr) > 0) {
		strncpy(address, p_addr, address_maxlen);
	} else if ( !using_sqbrkts) {
		sprintf(address, "0.0.0.0");
	} else {
		sprintf(address, "::");
	}
	return 0;
}
