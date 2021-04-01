/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "mpegts.h"
#include "udp-private.h"
#include "endian-shim.h"

int suppress_null_packets(const uint8_t payload_in[],uint8_t payload_out[], size_t *payload_len, struct rist_rtp_hdr_ext *header_ext) {
	size_t packet_size = 188;
	if (RIST_UNLIKELY(*payload_len % packet_size !=0)) {
		packet_size = 204;
		if (RIST_UNLIKELY(*payload_len % packet_size != 0)) {
			return -1;
		}
		SET_BIT(header_ext->npd_bits, 7);
	}
	size_t count = *payload_len / packet_size;
	if (RIST_UNLIKELY(count > 7))
		return -1;
	SET_BIT(header_ext->flags, 7);
	size_t offset = 0;
	size_t output_offset = 0;
	size_t bytes_remaining = *payload_len - packet_size;
	struct mpegts_header *hdr = (struct mpegts_header *)&payload_in[offset];
	int suppressed = 0;
	if (RIST_UNLIKELY(hdr->syncbyte  != 0x47))
		goto fail;
	for (int i = (int)count -1; i >= 0; i--) {
		if (be16toh(hdr->flags1) == 0x1FFF) {
			*payload_len -= packet_size;
			SET_BIT(header_ext->npd_bits, i);
			suppressed++;
		} else {
			if (i == 0 && suppressed == 0)
				return 0;
			memcpy(&payload_out[output_offset], &payload_in[offset], packet_size);
			output_offset += packet_size;
		}
		offset += packet_size;
		bytes_remaining -= packet_size;
		hdr = (struct mpegts_header *)&payload_in[offset];
	}
	return suppressed;
fail:
	UNSET_BIT(header_ext->flags, 7);
	return -1;
}

int expand_null_packets(uint8_t payload[], size_t *payload_len, uint8_t npd_bits) {
	size_t packet_size = CHECK_BIT(npd_bits, 7) == 0? 188: 204;
	size_t offset = 0;
	ssize_t remaining_bytes = *payload_len;
	//We will be modifying the payload in a 10k byte pre-allocated buffer, so we should be able to get away without any memory management
	int counter = 0;
	for (int i = 6; i >= 0; i--)
	{
		if (CHECK_BIT(npd_bits, i))
		{
			if (remaining_bytes > 0)
				memmove(&payload[offset + packet_size], &payload[offset], remaining_bytes);
			struct mpegts_header * hdr = (struct mpegts_header *)&payload[offset];
			memset(hdr, 0, sizeof(*hdr));
			hdr->syncbyte = 0x47;
			hdr->flags1 = htobe16(0x1FFF);
			SET_BIT(hdr->flags2,4);
			memset(&payload[offset + sizeof(*hdr)], 0xff, (packet_size - sizeof(*hdr)));
			*payload_len += packet_size;
			counter++;
		} else
			remaining_bytes -= packet_size;//Use this packet, so decrease remaining bytes to move
		offset += packet_size;
	}
	return counter;
}
