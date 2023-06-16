#ifndef RIST_PROTO_PROTOCOL_GRE_H
#define RIST_PROTO_PROTOCOL_GRE_H

#include "common/attributes.h"
#include <stdint.h>
#include <stddef.h>
#include "rist-private.h"

RIST_PRIV ssize_t rist_send_data_main_profile(struct rist_peer *p, uint8_t payload_type, uint16_t proto, uint8_t *payload, size_t payload_len, uint16_t src_port, uint16_t dst_port);

#endif /* RIST_PROTO_PROTOCOL_GRE_H */
