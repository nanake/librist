#ifndef RIST_PROTO_PROTOCOL_GRE_H
#define RIST_PROTO_PROTOCOL_GRE_H

#include "common/attributes.h"
#include <stdint.h>
#include <stddef.h>
#include "rist-private.h"
#include "proto/gre.h"

struct rist_keepalive_info {
	uint8_t ka[SIZEOF_GRE_KEEPALIVE];
	uint8_t mac[6];
	bool x : 1;
	bool r : 1;
	bool b : 1;
	bool a : 1;
	bool p : 1;
	bool e : 1;
	bool l : 1;
	bool n : 1;
	bool d : 1;
	bool t : 1;
	bool v : 1;
	bool j : 1;
	bool f : 1;
	size_t json_len;
	const char *json;
};

RIST_PRIV ssize_t _librist_proto_gre_send_data(struct rist_peer *p, uint8_t payload_type, uint16_t proto, uint8_t *payload, size_t payload_len, uint16_t src_port, uint16_t dst_port, uint8_t gre_version);
RIST_PRIV void _librist_proto_gre_send_keepalive(struct rist_peer *p, uint8_t gre_version);
RIST_PRIV int _librist_proto_gre_parse_keepalive(const uint8_t buf[], size_t buflen, struct rist_keepalive_info  *info);
RIST_PRIV void _librist_proto_gre_send_buffer_negotiation(struct rist_peer *p, uint16_t sender_max_buffer, uint16_t receiver_current_buffer);
RIST_PRIV int _librist_proto_gre_parse_buffer_negotiation(struct rist_peer *p, uint8_t buf[], size_t buflen, uint16_t *sender_max_buffer, uint16_t *receiver_current_buffer);
#endif /* RIST_PROTO_PROTOCOL_GRE_H */
