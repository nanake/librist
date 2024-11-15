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
	int suppressed = 0;
	struct mpegts_header *hdr = (struct mpegts_header *)&payload_in[offset];
	if (RIST_UNLIKELY(hdr->syncbyte != 0x47))
		goto fail;

	for (int i = 0; i <= (int)count-1; i++) {
		if (be16toh(hdr->flags1) == 0x1FFF) {
			*payload_len -= packet_size;
			SET_BIT(header_ext->npd_bits, (6 - i));
			suppressed++;
		}
		offset += packet_size;
		hdr = (struct mpegts_header *)&payload_in[offset];
	}

	if (suppressed == 0)
		return 0;

	offset = 0;
	size_t output_offset = 0;
	for (int i = 0; i <= (int)count-1; i++) {
		if (CHECK_BIT(header_ext->npd_bits, (6 - i)) == 0) {
			memcpy(&payload_out[output_offset], &payload_in[offset], packet_size);
			output_offset += packet_size;
		}
		offset += packet_size;
	}

	return suppressed;
fail:
	UNSET_BIT(header_ext->flags, 7);
	return -1;
}

int expand_null_packets(uint8_t payload_in[], uint8_t payload_out[], size_t *payload_len, uint8_t npd_bits) {
	size_t packet_size = CHECK_BIT(npd_bits, 7) == 0? 188: 204;

	// Non-null date 
	int ts_count = *payload_len / packet_size;
	// Null packets defined in header
	int null_count = CHECK_BIT(npd_bits, 6) + CHECK_BIT(npd_bits, 5) + CHECK_BIT(npd_bits, 4) + CHECK_BIT(npd_bits, 3) + CHECK_BIT(npd_bits, 2) + CHECK_BIT(npd_bits, 1) + CHECK_BIT(npd_bits, 0);

	if (null_count == 0)
		return 0;

	size_t offset = 0;
	ts_count += null_count;
	*payload_len = ts_count * packet_size;
	size_t input_offset = 0;
	for (int i = 0; i <= (int)ts_count-1; i++) {
		if (CHECK_BIT(npd_bits, (6 - i)) == 0) {
			memcpy(&payload_out[offset], &payload_in[input_offset], packet_size);
			input_offset += packet_size;
		}
		else {
			struct mpegts_header * hdr = (struct mpegts_header *)&payload_out[offset];
			memset(hdr, 0, sizeof(*hdr));
			hdr->syncbyte = 0x47;
			hdr->flags1 = htobe16(0x1FFF);
			SET_BIT(hdr->flags2,4);
			memset(&payload_out[offset + sizeof(*hdr)], 0xff, (packet_size - sizeof(*hdr)));
		}
		offset += packet_size;
	}

	return *payload_len;
}
