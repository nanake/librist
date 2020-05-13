/* librist. Copyright 2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */
#include "udpsocket.h"
#include <ifaddrs.h>

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

int udpsocket_join_mcast_group(int sd, const char* miface, struct sockaddr* sa, uint16_t family) {
#ifdef __linux
	if (family != AF_INET)
		return -1;
	char address[INET6_ADDRSTRLEN];
	char mcastaddress[INET6_ADDRSTRLEN];
	struct ifaddrs *ifaddr, *ifa, *found = NULL;
	struct sockaddr_in *mcast_v4 = (struct sockaddr_in *)sa;
	inet_ntop(AF_INET, &(mcast_v4->sin_addr), mcastaddress, INET_ADDRSTRLEN);

	if (getifaddrs(&ifaddr) == -1)
		return -1;

	// We need to get a local address to join the group from.
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (miface != NULL && miface[0] != '\0' && strcmp(miface, ifa->ifa_name) != 0) {
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (miface != NULL && miface[0] != '\0') {
				// If we have an miface we use it's address.
				found = ifa;
				break;
			}
			else {
				// We use the first non loopback address we find.
				struct sockaddr_in *v4 = (struct sockaddr_in *)ifa->ifa_addr;
				uint32_t msb = ((ntohl(v4->sin_addr.s_addr) & 0xFF000000) >> 24);
				if (msb != 127)	{
					found = ifa;
					break;
				}
			}
		}
	}

	if (!found)
		goto fail;
	struct sockaddr_in *v4 = (struct sockaddr_in *)found->ifa_addr;
	inet_ntop(AF_INET, &(v4->sin_addr), address, INET_ADDRSTRLEN);
	fprintf(stderr, "Joining multicast address:%s from IP %s on interface %s\n", mcastaddress, address, found->ifa_name);
	struct ip_mreq group;
	group.imr_multiaddr.s_addr = mcast_v4->sin_addr.s_addr;
	group.imr_interface.s_addr = v4->sin_addr.s_addr;
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group))< 0) {
		fprintf(stderr, "Failed to join multicast group\n");
		goto fail;
	}
	freeifaddrs(ifaddr);
	return 0;

fail:
	freeifaddrs(ifaddr);
	return -1;
#else
	return 0;
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

	sd = socket(raw.sin6_family, SOCK_DGRAM, 0);
	if (sd < 0)
		return sd;

	int is_multicast = 0;
	if (raw.sin6_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		is_multicast = IN6_IS_ADDR_MULTICAST(&raw.sin6_addr);
	}
	else {
		struct sockaddr_in *tmp = (struct sockaddr_in*)&raw;
		addrlen = sizeof(struct sockaddr_in);
		is_multicast = IN_MULTICAST(ntohl(tmp->sin_addr.s_addr));
	}
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		/* Non-critical error */
		fprintf(stderr, "Cannot set SO_REUSEADDR: %s\n", strerror(errno));
	}

	if (bind(sd, (struct sockaddr *)&raw, addrlen) < 0) {
        int err = errno;
        close(sd);
        errno = err;
		return -1;
    }

	if (is_multicast) {
		if (udpsocket_join_mcast_group(sd, mciface, (struct sockaddr *)&raw, raw.sin6_family) != 0)
			return -1;
	}

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
		*port = atoi(p_port);

	if (strlen(p_addr) > 0) {
		strncpy(address, p_addr, address_maxlen);
	} else {
		sprintf(address, "::1");
	}
	return 0;
}
