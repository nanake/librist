/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef RIST_UDP_PRIVATE_H
#define RIST_UDP_PRIVATE_H

#include "common.h"
#include "rist-private.h"

__BEGIN_DECLS

#define SET_BIT(value, pos) (value |= (1U<< pos))

#define RIST_GRE_PROTOCOL_TYPE_KEEPALIVE 0x88B5
#define RIST_GRE_PROTOCOL_TYPE_REDUCED 0x88B6
#define RIST_GRE_PROTOCOL_TYPE_FULL 0x0800
#define RIST_GRE_PROTOCOL_REDUCED_SIZE 4

#define RIST_GRE_FLAGS_KEY_SEQ 0x000C
#define RIST_GRE_FLAGS_SEQ     0x0008

#define RIST_PAYLOAD_TYPE_UNKNOWN           0x0
#define RIST_PAYLOAD_TYPE_PING              0x1
#define RIST_PAYLOAD_TYPE_PING_RESP         0x2
#define RIST_PAYLOAD_TYPE_RTCP              0x3
#define RIST_PAYLOAD_TYPE_RTCP_NACK         0x4
#define RIST_PAYLOAD_TYPE_DATA_RAW          0x5 // Raw
#define RIST_PAYLOAD_TYPE_DATA_LZ4          0x6 // Compressed with LZ4

// RTCP constants
#define RTCP_FB_HEADER_SIZE 12

#define PTYPE_SR 200
#define PTYPE_RR 201
#define PTYPE_SDES 202
#define PTYPE_NACK_CUSTOM  204
#define PTYPE_NACK_BITMASK 205

#define NACK_FMT_BITMASK 1
#define NACK_FMT_RANGE 0
#define NACK_FMT_SEQEXT 1

#define MPEG_II_TRANSPORT_STREAM (0x21)
#define RTCP_SDES_SIZE 10
#define RTP_MPEGTS_FLAGS 0x80
#define RTCP_SR_FLAGS 0x80
#define RTCP_SDES_FLAGS 0x81
#define RTCP_NACK_RANGE_FLAGS 0x80
#define RTCP_NACK_BITMASK_FLAGS 0x81
#define RTCP_NACK_SEQEXT_FLAGS 0x81

// Maximum offset before the payload that the code can use to put in headers
#define RIST_MAX_PAYLOAD_OFFSET (sizeof(struct rist_gre_key_seq) + sizeof(struct rist_protocol_hdr))

/* Time conversion */
#define SEVENTY_YEARS_OFFSET (2208988800ULL)

/*

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |0|0| Reserved0       | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 1: GRE header with no options



+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |0|1| Reserved0       | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Figure 2: GRE header with sequence number



+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |1|1| Reserved0       | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Key/Nonce                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Figure 5: GRE header with Key/Nonce

The sequence number will become the heigher 4byte of AES IV.
So, that on increment - the lower bits (which are zero) get incremented

*/

/*

Reduce overhead GRE payload header (only one supported for now)

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        source port            |      destination port         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/*

RTP header format (RFC 3550)
The RTP header is always present on data packets

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers             |
|                             ....                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/*

[  GRE header  ]
[  RTP header ]
[  Payload     ]

*/

RIST_PACKED_STRUCT(rist_gre_keepalive,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
	uint8_t mac_array[6];
	uint8_t capabilities1;
	uint8_t capabilities2;
})

RIST_PACKED_STRUCT(rist_gre,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
	uint32_t checksum_reserved1;
})

RIST_PACKED_STRUCT(rist_gre_seq,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
	uint32_t checksum_reserved1;
	uint32_t seq;
})

RIST_PACKED_STRUCT(rist_gre_key_seq,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
	uint32_t checksum_reserved1;
	uint32_t nonce;
	uint32_t seq;
})

RIST_PACKED_STRUCT(rist_rtp_hdr,{
	uint8_t flags;
	uint8_t payload_type;
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
})

RIST_PACKED_STRUCT(rist_protocol_hdr,{
	uint16_t src_port;
	uint16_t dst_port;
	struct rist_rtp_hdr rtp;
})

RIST_PACKED_STRUCT(rist_rtp_nack_record,{
	uint16_t start;
	uint16_t extra;
})

RIST_PACKED_STRUCT(rist_rtcp_hdr,{
	uint8_t flags;
	uint8_t ptype;
	uint16_t len;
	uint32_t ssrc;
})

RIST_PACKED_STRUCT(rist_rtcp_nack_range,{
	uint8_t flags;
	uint8_t ptype;
	uint16_t len;
	uint32_t ssrc_source;
	uint8_t name[4];
})

RIST_PACKED_STRUCT(rist_rtcp_nack_bitmask,{
	uint8_t flags;
	uint8_t ptype;
	uint16_t len;
	uint32_t ssrc_source;
	uint32_t ssrc;
})

RIST_PACKED_STRUCT(rist_rtcp_seqext,{
	uint8_t flags;
	uint8_t ptype;
	uint16_t len;
	uint32_t ssrc;
	uint8_t  name[4];
	uint16_t seq_msb;
	uint16_t reserved0;
})

RIST_PACKED_STRUCT(rist_rtcp_sr_pkt,{
	struct rist_rtcp_hdr rtcp;
	uint32_t ntp_msw;
	uint32_t ntp_lsw;
	uint32_t rtp_ts;
	uint32_t sender_pkts;
	uint32_t sender_bytes;
})

RIST_PACKED_STRUCT(rist_rtcp_rr_pkt,{
	struct rist_rtcp_hdr rtcp;
	uint32_t recv_ssrc;
	uint8_t fraction_lost;
	uint8_t cumulative_pkt_loss_msb;
	uint16_t cumulative_pkt_loss_lshw;
	uint32_t highest_seq;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t dlsr;
})

RIST_PACKED_STRUCT(rist_rtcp_rr_empty_pkt,{
	struct rist_rtcp_hdr rtcp;
})

RIST_PACKED_STRUCT(rist_rtcp_sdes_pkt,{
	struct rist_rtcp_hdr rtcp;
	uint8_t cname;
	uint8_t name_len;
	char udn[0];
})

static inline uint32_t timestampRTP_u32( uint64_t i_ntp )
{
	// We just need the middle 32 bits
	return (uint32_t)(i_ntp >> 16);
}

/* shared functions in udp.c */
RIST_PRIV void rist_send_nacks(struct rist_flow *f, struct rist_peer *peer);
RIST_PRIV bool rist_send_server_rtcp(struct rist_peer *peer, uint32_t seq_array[], int array_len);
RIST_PRIV uint32_t rist_send_client_rtcp(struct rist_peer *peer);
RIST_PRIV bool rist_send_common_rtcp(struct rist_peer *p, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, bool duplicate);
RIST_PRIV uint32_t rist_send_seq_rtcp(struct rist_peer *p, uint32_t seq, uint16_t seq_rtp, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port);
RIST_PRIV void rist_client_send_data_balanced(struct rist_client *ctx, struct rist_buffer *buffer);
RIST_PRIV int rist_client_enqueue(struct rist_client *ctx, const void *data, int len, uint64_t datagram_time, uint16_t src_port, uint16_t dst_port);
RIST_PRIV void rist_clean_client_enqueue(struct rist_client *ctx);
RIST_PRIV void rist_retry_enqueue(struct rist_client *ctx, uint32_t seq, struct rist_peer *peer);
RIST_PRIV int rist_retry_dequeue(struct rist_client *ctx);
RIST_PRIV int rist_set_url(struct rist_peer *peer);
RIST_PRIV void rist_create_socket(struct rist_peer *peer);

__END_DECLS

#endif
