#ifndef RIST_PROTO_PROTO_RTP_H
#define RIST_PROTO_PROTO_RTP_H

#include "common/attributes.h"
#include <stdint.h>

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
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|0| Subtype |   PT=APP=204  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  SSRC of media source                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         name (ASCII)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Timestamp, most significant word               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Timestamp, least significant word               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Processing Delay (microseconds)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Padding bytes                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Padding bytes                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/*
RTP header extension format (RFC 3550)

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      defined by profile       |           length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        header extension                       |
|                             ....                              |

RIST implementation of header extension format used for null packet
deletion and sequence number extension (VSF TR-06-02, 8.3)

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    0x52 (R)   |    0x49 (I)   |          Length=1             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|N|E|Size |0 0 0|T|  NPD bits   |   Sequence Number Extension   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
RTCP Control Channel:

[  GRE header  ]
[  Reduced overhead header. ]
[  RTCP payload .]

*/


// RTCP constants
#define RTCP_FB_HEADER_SIZE 12

#define PTYPE_SR 200
#define PTYPE_RR 201
#define PTYPE_SDES 202
#define PTYPE_XR 207
#define PTYPE_NACK_CUSTOM  204
#define PTYPE_NACK_BITMASK 205

#define NACK_FMT_BITMASK 1
#define NACK_FMT_RANGE 0
#define NACK_FMT_SEQEXT 1

#define ECHO_REQUEST 2
#define ECHO_RESPONSE 3

#define RTCP_SDES_SIZE 10
#define RTP_MPEGTS_FLAGS 0x80
#define RTCP_SR_FLAGS 0x80
#define RTCP_RR_FULL_FLAGS 0x81
#define RTCP_SDES_FLAGS 0x81
#define RTCP_NACK_RANGE_FLAGS 0x80
#define RTCP_NACK_BITMASK_FLAGS 0x81
#define RTCP_NACK_SEQEXT_FLAGS 0x81
#define RTCP_ECHOEXT_REQ_FLAGS 0x82
#define RTCP_ECHOEXT_RESP_FLAGS 0x83

// RTP Payload types and clocks
// March 1995 (page 9): https://tools.ietf.org/html/draft-ietf-avt-profile-04
// Nov 2019 (page 2): https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
#define RTP_PTYPE_MPEGTS (0x21)
#define RTP_PTYPE_MPEGTS_CLOCKHZ (90000)
#define RTP_PTYPE_RIST (21)
#define RTP_PTYPE_RIST_CLOCKHZ (UINT16_MAX + 1)

RIST_PACKED_STRUCT(rist_rtp_hdr,{
	uint8_t flags;
	uint8_t payload_type;
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
})

RIST_PACKED_STRUCT(rist_rtp_hdr_ext, {
	uint16_t identifier; /* set to 0x5249 */
	uint16_t length; /*shall be set to 1 */
	uint8_t	 flags;
	uint8_t  npd_bits;
	uint16_t seq_ext;
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

RIST_PACKED_STRUCT(rist_rtcp_echoext, {
	uint8_t flags;
	uint8_t ptype;
	uint16_t len;
	uint32_t ssrc;
	uint8_t name[4];
	uint32_t ntp_msw;
	uint32_t ntp_lsw;
	uint32_t delay;
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
	char udn[1];
})

RIST_PACKED_STRUCT(rist_rtcp_xr_block_hdr, {
	uint8_t type;
	uint8_t reserved;
	uint16_t length;
})
//Receiver reference time report block
RIST_PACKED_STRUCT(rist_rtcp_xr_rrtrb, {
	uint8_t block_type;
	uint8_t reserved;
	uint16_t length;
	uint32_t ntp_msw;
	uint32_t ntp_lsw;
})

RIST_PACKED_STRUCT(rist_rtcp_xr_dlrr, {
	uint8_t block_type;
	uint8_t reserved;
	uint16_t length;
	uint32_t ssrc;
	uint32_t lrr;
	uint32_t delay;
})

static inline uint32_t get_rtp_ts_clock(uint8_t ptype) {
	uint32_t clock = 0;
	switch(ptype) {
		case RTP_PTYPE_MPEGTS:
		case 14: // MPA
		case 25: // CelB
		case 26: // JPEG
		case 28: // nv
		case 31: // H261
		case 32: // MPV
		case 34: // H263
			clock = RTP_PTYPE_MPEGTS_CLOCKHZ;
			break;
		case 0: // PCMU
		case 3: // GSM
		case 4: // G723
		case 5: // DVI4
		case 7: // LPC
		case 8: // PCMA
		case 9: // G722
		case 12: // QCELP
		case 13: // CN
		case 15: // G728
		case 18: // G729
			clock = 8000;
			break;
		case 16: // DVI4
			clock = 11025;
			break;
		case 6: // DVI4
			clock = 16000;
			break;
		case 17: // DVI4
			clock = 22050;
			break;
		case 10: // L16
		case 11: // L16
			clock = 44100;
			break;
		default:
			clock = 0;
			break;
	}
	return clock;
}

#endif /* RIST_PROTO_PROTO_RTP_H */
