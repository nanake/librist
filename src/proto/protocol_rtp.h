#ifndef RIST_PROTO_PROTOCOL_RTP_H
#define RIST_PROTO_PROTOCOL_RTP_H

#include <stdint.h>

#include "rist-private.h"

void rist_rtcp_write_empty_rr(uint8_t *buf, int *offset, const uint32_t flow_id);
void rist_rtcp_write_rr(uint8_t *buf, int *offset, const struct rist_peer *peer);
void rist_rtcp_write_sr(uint8_t *buf, int *offset, struct rist_peer *peer);
void rist_rtcp_write_sdes(uint8_t *buf, int *offset, const char *name, const uint32_t flow_id);
void rist_rtcp_write_echoreq(uint8_t *buf, int *offset, const uint32_t flow_id);
void rist_rtcp_write_echoresp(uint8_t *buf, int *offset, const uint64_t request_time, const uint32_t flow_id);
void rist_rtcp_write_xr_echoreq(uint8_t *buf, int *offset, struct rist_peer *peer) ;
#endif /* RIST_PROTO_PROTOCOL_RTP_H */
