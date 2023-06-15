#ifndef RIST_PROTO_GRE_H
#define RIST_PROTO_GRE_H

#include "common/attributes.h"
#include <stdint.h>

#define RIST_GRE_PROTOCOL_TYPE_KEEPALIVE 0x88B5
#define RIST_GRE_PROTOCOL_TYPE_REDUCED 0x88B6
#define RIST_GRE_PROTOCOL_TYPE_FULL 0x0800
#define RIST_GRE_PROTOCOL_TYPE_EAPOL 0x888E
#define RIST_GRE_PROTOCOL_TYPE_VSF 0xCCE0
#define RIST_GRE_PROTOCOL_REDUCED_SIZE 4

#define RIST_GRE_FLAGS_KEY_SEQ 0x000C
#define RIST_GRE_FLAGS_SEQ     0x0008

#define RIST_VSF_PROTOCOL_TYPE_RIST 0x0000

#define RIST_VSF_PROTOCOL_SUBTYPE_REDUCED 0x0000
#define RIST_VSF_PROTOCOL_SUBTYPE_KEEPALIVE 0x8000
#define RIST_VSF_PROTOCOL_SUBTYPE_FUTURE_NONCE 0x8001

/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |0|0|Reserved0|H|RVer | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Figure 1: GRE header with no options


+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |0|1|Reserved0|H|RVer | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Figure 2: GRE header with sequence number


+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |1|1|Reserved0|H|RVer | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Key/Nonce                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Figure 5: GRE header with Key/Nonce

The sequence number will become the higher 4byte of AES IV.
So, that on increment - the lower bits (which are zero) get incremented


Reduce overhead GRE payload header (only one supported for now)

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        source port            |      destination port         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Keep alive message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| |1|1| Reserved0       | Ver |     Protocol Type = 0x88B5    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|																|
| 48-bit MAC Address            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   					        |X|R|B|A|P|E|L|N|D|T|V|J|F|Rsvd1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 			  Message Payload (JSON format)						|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Data Channel:

[  GRE header  ]
[  Reduced overhead header .]
[  RTP header .]
[  User payload  ]

*/

RIST_PACKED_STRUCT(rist_gre_keepalive,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
	uint8_t mac_array[6];
	uint8_t capabilities1;
	uint8_t capabilities2;
})

RIST_PACKED_STRUCT(rist_gre_hdr,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
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

RIST_PACKED_STRUCT(rist_gre_key_seq_real,{
	uint8_t flags1;
	uint8_t flags2;
	uint16_t prot_type;
	uint32_t nonce;
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

RIST_PACKED_STRUCT(rist_vsf_proto,{
	uint16_t type;
	uint16_t subtype;
})

#endif /* RIST_PROTO_GRE_H */
