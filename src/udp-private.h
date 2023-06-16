/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_UDP_PRIVATE_H
#define RIST_UDP_PRIVATE_H

#include "common/attributes.h"
#include "rist-private.h"
#include "proto/gre.h"
#include "proto/rtp.h"
#include "proto/proto_rtp.h"

#define SET_BIT(value, pos) (value |= (1U<< pos))
#define UNSET_BIT(value, pos) (value &= (1U << pos))

#define RIST_PAYLOAD_TYPE_UNKNOWN           0x0
#define RIST_PAYLOAD_TYPE_PING              0x1
#define RIST_PAYLOAD_TYPE_PING_RESP         0x2
#define RIST_PAYLOAD_TYPE_RTCP              0x3
#define RIST_PAYLOAD_TYPE_RTCP_NACK         0x4
#define RIST_PAYLOAD_TYPE_DATA_RAW          0x5
#define RIST_PAYLOAD_TYPE_DATA_OOB          0x6 // Out-of-band data
#define RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT  0x7
#define RIST_PAYLOAD_TYPE_EAPOL				0x8

// Maximum offset before the payload that the code can use to put in headers
#define RIST_MAX_PAYLOAD_OFFSET (sizeof(struct rist_gre_key_seq) + sizeof(struct rist_protocol_hdr))

/* shared functions in udp.c */
RIST_PRIV void rist_send_nacks(struct rist_flow *f, struct rist_peer *peer);
RIST_PRIV int rist_receiver_send_nacks(struct rist_peer *peer, uint32_t seq_array[], size_t array_len);
RIST_PRIV int rist_receiver_periodic_rtcp(struct rist_peer *peer);
RIST_PRIV void rist_sender_periodic_rtcp(struct rist_peer *peer);
RIST_PRIV int rist_respond_echoreq(struct rist_peer *peer, const uint64_t echo_request_time, uint32_t ssrc);
RIST_PRIV int rist_request_echo(struct rist_peer *peer);
RIST_PRIV int rist_send_common_rtcp(struct rist_peer *p, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp);
RIST_PRIV void rist_sender_send_data_balanced(struct rist_sender *ctx, struct rist_buffer *buffer);
RIST_PRIV int rist_sender_enqueue(struct rist_sender *ctx, const void *data, size_t len, uint64_t datagram_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp);
RIST_PRIV void rist_clean_sender_enqueue(struct rist_sender *ctx);
RIST_PRIV void rist_retry_enqueue(struct rist_sender *ctx, uint32_t seq, struct rist_peer *peer);
RIST_PRIV ssize_t rist_retry_dequeue(struct rist_sender *ctx);
RIST_PRIV int rist_set_url(struct rist_peer *peer);
RIST_PRIV void rist_create_socket(struct rist_peer *peer);
RIST_PRIV size_t rist_get_sender_retry_queue_size(struct rist_sender *ctx);


#endif
