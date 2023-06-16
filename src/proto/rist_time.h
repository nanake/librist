#ifndef RIST_TIME_H
#define RIST_TIME_H

#include "common/attributes.h"

#include <stdint.h>
/* Time conversion */
// this value is UINT32_MAX 4294967.296
#define RIST_CLOCK (4294967LL)
#define ONE_SECOND (1000 * RIST_CLOCK)
#define RIST_LOG_QUIESCE_TIMER  ONE_SECOND
#define SEVENTY_YEARS_OFFSET (2208988800ULL)

RIST_PRIV uint64_t timestampNTP_u64(void);
RIST_PRIV uint64_t timestampNTP_RTC_u64(void);
RIST_PRIV uint32_t timestampRTP_u32(int advanced, uint64_t i_ntp);
RIST_PRIV uint64_t convertRTPtoNTP(uint8_t ptype, uint32_t time_extension, uint32_t i_rtp);
RIST_PRIV uint64_t calculate_rtt_delay(uint64_t request, uint64_t response, uint32_t delay);

#endif /* RIST_TIME_H */
