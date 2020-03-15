/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef __ENDIAN_SHIM_H
#define __ENDIAN_SHIM_H

#if defined(_WIN32)

#include <winsock2.h>

#define be16toh(x) ntohs(x)
#define htobe16(x) htons(x)

#define be32toh(x) ntohl(x)
#define htobe32(x) htons(x)

/* Endianess utils */
#if BYTE_ORDER == LITTLE_ENDIAN
# define htobe64(x) htonll(x)
# define be64toh(x) ntohll(x)
#else
#error byte order not supported
#endif

#elif defined(__APPLE__)
# include <libkern/OSByteOrder.h>
//# define be64toh(x) OSSwapBigToHostInt64(x)
//# define htobe64(x) OSSwapHostToBigInt64(x)
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#else
# include <endian.h>
# if (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 9))
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define htobe64(x) __bswap_64(x)
#   define be64toh(x) __bswap_64(x)
#  else
#   define htobe64(x) (x)
#   define be64toh(x) (x)
#  endif
# endif
#endif


#endif
