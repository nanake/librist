
#include "proto_rtp.h"
#include "rtp.h"
#include "rist_time.h"

#include "endian-shim.h"
#include "rist-private.h"
#include "udp-private.h"

void rist_rtcp_write_empty_rr(uint8_t *buf, int *offset,
                                            const uint32_t flow_id) {
  struct rist_rtcp_rr_empty_pkt *rr =
      (struct rist_rtcp_rr_empty_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET +
                                        *offset);
  *offset += sizeof(struct rist_rtcp_rr_empty_pkt);
  rr->rtcp.flags = RTCP_SR_FLAGS;
  rr->rtcp.ptype = PTYPE_RR;
  rr->rtcp.ssrc = htobe32(flow_id);
  rr->rtcp.len = htons(1);
}

void rist_rtcp_write_rr(uint8_t *buf, int *offset,
                                      const struct rist_peer *peer) {
  struct rist_rtcp_rr_pkt *rr =
      (struct rist_rtcp_rr_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sizeof(struct rist_rtcp_rr_pkt);
  rr->rtcp.flags = RTCP_RR_FULL_FLAGS;
  rr->rtcp.ptype = PTYPE_RR;
  rr->rtcp.ssrc = htobe32(peer->adv_flow_id);
  rr->rtcp.len = htons(7);
  /* TODO fix these variables */
  rr->fraction_lost = 0;
  rr->cumulative_pkt_loss_msb = 0;
  rr->cumulative_pkt_loss_lshw = 0;
  rr->highest_seq = 0;
  rr->jitter = 0;
  rr->lsr = htobe32((uint32_t)(peer->last_sender_report_time >> 16));
  /*  expressed in units of 1/65536  == middle 16 bits?!? */
  rr->dlsr = htobe32(
      (uint32_t)((timestampNTP_u64() - peer->last_sender_report_ts) >> 16));
}

void rist_rtcp_write_sr(uint8_t *buf, int *offset,
                                      struct rist_peer *peer) {
  struct rist_rtcp_sr_pkt *sr =
      (struct rist_rtcp_sr_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sizeof(struct rist_rtcp_sr_pkt);
  /* Populate SR for sender */
  sr->rtcp.flags = RTCP_SR_FLAGS;
  sr->rtcp.ptype = PTYPE_SR;
  sr->rtcp.ssrc = htobe32(peer->adv_flow_id);
  sr->rtcp.len = htons(6);
  uint64_t now = timestampNTP_u64();
  uint64_t now_rtc = timestampNTP_RTC_u64();
  peer->last_sender_report_time = now_rtc;
  peer->last_sender_report_ts = now;
  uint32_t ntp_lsw = (uint32_t)now_rtc;
  // There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
  // No leap seconds during that period since they were not invented yet.
  uint32_t ntp_msw = now_rtc >> 32;
  sr->ntp_msw = htobe32(ntp_msw);
  sr->ntp_lsw = htobe32(ntp_lsw);
  sr->rtp_ts = htobe32(timestampRTP_u32(0, now));
  sr->sender_pkts = 0;  // htonl(f->packets_count);
  sr->sender_bytes = 0; // htonl(f->bytes_count);
}

void rist_rtcp_write_sdes(uint8_t *buf, int *offset,
                                        const char *name,
                                        const uint32_t flow_id) {
  size_t namelen = strlen(name);
  size_t sdes_size = ((10 + namelen + 1) + 3) & ~3;
  size_t padding = sdes_size - namelen - 10;
  struct rist_rtcp_sdes_pkt *sdes =
      (struct rist_rtcp_sdes_pkt *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sdes_size;
  /* Populate SDES for sender description */
  sdes->rtcp.flags = RTCP_SDES_FLAGS;
  sdes->rtcp.ptype = PTYPE_SDES;
  sdes->rtcp.len = htons((uint16_t)((sdes_size - 1) >> 2));
  sdes->rtcp.ssrc = htobe32(flow_id);
  sdes->cname = 1;
  sdes->name_len = (uint8_t)namelen;
  // We copy the extra padding bytes from the source because it is a
  // preallocated buffer of size 128 with all zeroes
  memcpy(sdes->udn, name, namelen + padding);
}

void rist_rtcp_write_echoreq(uint8_t *buf, int *offset,
                                           const uint32_t flow_id) {
  struct rist_rtcp_echoext *echo =
      (struct rist_rtcp_echoext *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sizeof(struct rist_rtcp_echoext);
  echo->flags = RTCP_ECHOEXT_REQ_FLAGS;
  echo->ptype = PTYPE_NACK_CUSTOM;
  echo->ssrc = htobe32(flow_id);
  echo->len = htons(5);
  memcpy(echo->name, "RIST", 4);
  uint64_t now = timestampNTP_u64();
  echo->ntp_msw = htobe32((uint32_t)(now >> 32));
  echo->ntp_lsw = htobe32((uint32_t)(now & 0x000000000FFFFFFFF));
}

void rist_rtcp_write_echoresp(uint8_t *buf, int *offset,
                                            const uint64_t request_time,
                                            const uint32_t flow_id) {
  struct rist_rtcp_echoext *echo =
      (struct rist_rtcp_echoext *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sizeof(struct rist_rtcp_echoext);
  echo->flags = RTCP_ECHOEXT_RESP_FLAGS;
  echo->ptype = PTYPE_NACK_CUSTOM;
  echo->len = htons(5);
  echo->ssrc = htobe32(flow_id);
  memcpy(echo->name, "RIST", 4);
  echo->ntp_msw = htobe32((uint32_t)(request_time >> 32));
  echo->ntp_lsw = htobe32((uint32_t)(request_time & 0x000000000FFFFFFFF));
  echo->delay = 0;
}

void rist_rtcp_write_xr_echoreq(uint8_t *buf, int *offset,
                                              struct rist_peer *peer) {
  struct rist_rtcp_hdr *xr_hdr =
      (struct rist_rtcp_hdr *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sizeof(*xr_hdr);
  xr_hdr->flags = 0x80; // v=2;p=0;
  xr_hdr->ptype = PTYPE_XR;
  xr_hdr->ssrc = htobe32(peer->peer_ssrc);
  struct rist_rtcp_xr_rrtrb *block =
      (struct rist_rtcp_xr_rrtrb *)(buf + RIST_MAX_PAYLOAD_OFFSET + *offset);
  *offset += sizeof(*block);
  block->block_type = 4;
  block->length = htobe16(2);
  block->reserved = 0;
  uint64_t now = timestampNTP_u64();
  peer->last_sender_report_ts = now;
  block->ntp_msw = htobe32((uint32_t)(now >> 32));
  block->ntp_lsw = htobe32((uint32_t)(now & 0x000000000FFFFFFFF));
  xr_hdr->len = htobe16(1 + sizeof(*block) / 4);
}
