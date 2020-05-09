/* librist. Copyright 2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */
#include "udpsocket.h"


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
		if (gai_ret < 0) {
			fprintf(stderr, "Failure resolving host %s: %s\n", host, gai_strerror(gai_ret));
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
	return socket(af, SOCK_DGRAM, 0);
}

int udpsocket_set_buffer_size(int sd, uint32_t bufsize)
{
	if ((setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(uint32_t)) < 0) ||
			(setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(uint32_t)) < 0))
		return -1;
	return 0;
}

uint32_t udpsocket_get_buffer_size(int sd)
{
	uint32_t bufsize;
	uint32_t val_size = sizeof(uint32_t);
	if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &bufsize, &val_size) < 0)
		return 0;
	return bufsize;
}

int udpsocket_set_mcast_iface(int sd, const char *mciface, uint16_t family)
{
	int scope = if_nametoindex(mciface);
	if (scope == 0)
		return -1;
#ifdef _WIN32
	return setsockopt(s, SOL_IP, IP_MULTICAST_IF, (char *)&scope, sizeof(scope));
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

	sd = socket(raw.sin6_family, SOCK_DGRAM, 0);
	if (sd < 0)
		return sd;

	if (raw.sin6_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		proto = IPPROTO_IP;
		ttlcmd = IP_MULTICAST_TTL;
	} else {
		addrlen = sizeof(struct sockaddr_in);
		proto = IPPROTO_IPV6;
		ttlcmd = IPV6_MULTICAST_HOPS;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		/* Non-critical error */
		fprintf(stderr, "Cannot set SO_REUSEADDR: %s\n", strerror(errno));
	}
	if (setsockopt(sd, proto, ttlcmd, &ttl, sizeof(ttl)) == 0) {
		/* Non-critical error */
		fprintf(stderr, "Cannot set socket MAX HOPS: %s\n", strerror(errno));
	}
	if (mciface)
		udpsocket_set_mcast_iface(sd, mciface, raw.sin6_family);

	if (connect(sd, (struct sockaddr *)&raw, addrlen) < 0)
		return -1;


	return sd;
}

int udpsocket_open_bind(const char *host, uint16_t port, const char *mciface)
{
	int sd;
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	sd = socket(raw.sin6_family, SOCK_DGRAM, 0);
	if (sd < 0)
		return sd;

	if (raw.sin6_family == AF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else
		addrlen = sizeof(struct sockaddr_in);

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		/* Non-critical error */
		fprintf(stderr, "Cannot set SO_REUSEADDR: %s\n", strerror(errno));
	}
	if (mciface)
		udpsocket_set_mcast_iface(sd, mciface, raw.sin6_family);

	if (bind(sd, (struct sockaddr *)&raw, addrlen) < 0)
		return -1;

	return sd;
}

int udpsocket_send(int sd, const void *buf, size_t size)
{
	return send(sd, buf, size, 0);

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
	return sendto(sd, buf, size, 0, (struct sockaddr *)(&raw), addrlen);
}

int udpsocket_recv(int sd, void *buf, size_t size)
{
	return recv(sd, buf, size, 0);
}

int udpsocket_close(int sd)
{
	return close(sd);
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
	if (*p_addr == '@')
		*local = 1;
	else
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
		*port = atoi(p_port);

	if (strlen(p_addr) > 0) {
		strncpy(address, p_addr, address_maxlen);
	} else {
		sprintf(address, "::1");
	}
	return 0;
}
