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
#define RIST_VSF_PROTOCOL_SUBTYPE_BUFFER_NEGOTIATION 0x8002

#define RIST_GRE_VERSION_CUR 2
#define RIST_GRE_VERSION_MIN 1

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

Buffer negotiation message
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Sender Max allowed buffer ms  |  Receiver current buffer MS   |
|          Protocol type        |    protocol specific data ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
The buffer negotiation message can be used by sender and receiver
to negotiate the configure the desired buffer duration.
Either side may send the message unsollicited. How the receiver
decides on it's current buffer value is implementation defined.
Implementations capable of buffer negotiation shall respond with
their (scoped) values.
Sender max allowed buffer MS (16bit): the maximum buffer value a sender allows
  this value /not/ allowed to be decreased during a session.
  This value shall be set to 0 if the device isn't capable or configured
  for sending data.
Receiver current buffer MS (16bit): the current buffer duration the client
  is configured for. The client is free to change this value during
  the session up to the senders maximum value. When changing it's
  configured buffer duration setting it will notify the sender
  via this message.
  This value shall be set to 0 if the device isn't capable or configured
  for receiving data.

Protocol type (16bit): setting this value to anything but 0 allows scoping
  the buffer configuration protocol to a single stream in a main
  profile multiplex.
  Allowed values:
   0, no protocol specific data follows. The message
      applies to all flows in the session.
	  Devices not capable of setting a single buffer value to all
	  flows in a session shall respond with sender and receiver
	  buffer values set to 0.
   0x88B6, reduced overhead header follows. The message is taken
      to apply to the single flow specified by the reduced overhead
	  header parameters.
	  Devices not capable of scoping buffer settings to a single flow
	  shall respond to this message with their buffer values set to 0,
	  while copying the received protocol type and protocol data
	0x0800, ip + udp header follows. Same logic applies as with reduced
	  overhead type.


Data Channel:

[  GRE header  ]
[  Reduced overhead header .]
[  RTP header .]
[  User payload  ]

*/

#define SIZEOF_GRE_KEEPALIVE 8

RIST_PACKED_STRUCT(rist_gre_keepalive,{
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

RIST_PACKED_STRUCT(rist_reduced,{
	uint16_t src_port;
	uint16_t dst_port;
})

RIST_PACKED_STRUCT(rist_buffer_negotiation, {
	uint16_t sender_max_buffer_size_ms;
	uint16_t receiver_current_buffer_size_ms;
	uint16_t protocol_type;
})

#define MAX_GRE_SIZE (sizeof(struct rist_gre_key_seq_real) + sizeof(struct rist_vsf_proto) + sizeof(struct rist_reduced))

#endif /* RIST_PROTO_GRE_H */
