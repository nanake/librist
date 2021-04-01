/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common/attributes.h"

#define RIST_OOB_API_IP_PROTOCOL 252
#define RIST_OOB_API_IP_IDENT_AUTH 54321
#define RIST_OOB_ERROR_INVALID_LENGTH -1
#define RIST_OOB_ERROR_INVALID_PROTO -2
#define RIST_OOB_ERROR_INVALID_IDENT -3

// The IP header's structure (20 bytes)
RIST_PACKED_STRUCT(ipheader, {
	unsigned char      iph_verlen;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flags;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	unsigned int       iph_sourceip;
	unsigned int       iph_destip;
})

// UDP header's structure (8 bytes)
RIST_PACKED_STRUCT(udpheader, {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
})

int oob_build_api_payload(char *buffer, char *sourceip, char *destip, char *message, int message_len);
char *oob_process_api_message(int buffer_len, char *buffer, int *message_len);
