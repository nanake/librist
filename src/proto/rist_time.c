#include "rist_time.h"

#include "endian-shim.h"
#include "rtp.h"
#include "time-shim.h"

#include <stdint.h>

uint64_t timestampNTP_u64(void) {
  // We use clock_gettime instead of gettimeofday even though we only need
  // microseconds because gettimeofday implementation under linux is dependent
  // on the kernel clock and can produce duplicate times (too close to kernel
  // timer)

  // We use the NTP time standard: rfc5905
  // (https://tools.ietf.org/html/rfc5905#section-6) The 64-bit timestamps used
  // by NTP consist of a 32-bit part for seconds and a 32-bit part for
  // fractional second, giving a time scale that rolls over every 232 seconds
  // (136 years) and a theoretical resolution of 2−32 seconds (233 picoseconds).
  // NTP uses an epoch of January 1, 1900. Therefore, the first rollover occurs
  // on February 7, 2036.
  timespec_t ts;
#if defined(__APPLE__)
  clock_gettime_osx(CLOCK_MONOTONIC_OSX, &ts);
#else
  clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
  // Convert nanoseconds to 32-bits fraction (232 picosecond units)
  uint64_t t = (uint64_t)(ts.tv_nsec) << 32;
  t /= 1000000000;
  // There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
  // No leap seconds during that period since they were not invented yet.
  t |= (uint64_t)((70LL * 365 + 17) * 24 * 60 * 60 + ts.tv_sec) << 32;
  return t; // nanoseconds (technically, 232.831 picosecond units)
}

uint64_t timestampNTP_RTC_u64(void) {
  timespec_t ts;
#if defined(__APPLE__)
  clock_gettime_osx(CLOCK_REALTIME_OSX, &ts);
#else
  clock_gettime(CLOCK_REALTIME, &ts);
#endif
  // Convert nanoseconds to 32-bits fraction (232 picosecond units)
  uint64_t t = (uint64_t)(ts.tv_nsec) << 32;
  t /= 1000000000;
  // There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
  // No leap seconds during that period since they were not invented yet.
  t |= (uint64_t)((70LL * 365 + 17) * 24 * 60 * 60 + ts.tv_sec) << 32;
  return t;
}

uint32_t timestampRTP_u32(int advanced, uint64_t i_ntp) {
  if (!advanced) {
    i_ntp *= RTP_PTYPE_MPEGTS_CLOCKHZ;
    i_ntp = i_ntp >> 32;
    return (uint32_t)i_ntp;
  } else {
    // We just need the middle 32 bits, i.e. 65536Hz clock
    i_ntp = i_ntp >> 16;
    return (uint32_t)i_ntp;
  }
}

uint64_t convertRTPtoNTP(uint8_t ptype, uint32_t time_extension,
                         uint32_t i_rtp) {
  uint64_t i_ntp;
  if (ptype == RTP_PTYPE_RIST) {
    // Convert rtp to 64 bit and shift it 16 bits
    uint64_t part2 = (uint64_t)i_rtp;
    part2 = part2 << 16;
    // rebuild source_time (lower and upper 16 bits)
    uint64_t part3 = (uint64_t)(time_extension & 0xffff);
    uint64_t part1 = ((uint64_t)(time_extension & 0xffff0000)) << 32;
    i_ntp = part1 | part2 | part3;
    // fprintf(stderr,"source time %"PRIu64", rtp time %"PRIu32"\n",
    // source_time, rtp_time);
  } else {
    int32_t clock = get_rtp_ts_clock(ptype);
    if (RIST_UNLIKELY(!clock)) {
      clock = RTP_PTYPE_MPEGTS_CLOCKHZ;
      // Insert a new timestamp (not ideal but better than failing)
      i_rtp = htobe32(timestampRTP_u32(0, timestampNTP_u64()));
    }
    i_ntp = (uint64_t)i_rtp << 32;
    i_ntp /= clock;
  }
  return i_ntp;
}

uint64_t calculate_rtt_delay(uint64_t request, uint64_t response,
                             uint32_t delay) {
  /* both request and response are NTP timestamps, delay is in microseconds */
  uint64_t rtt = response - request;
  if (RIST_UNLIKELY(delay))
    rtt -= (((uint64_t)delay) << 32) / 1000000;
  return rtt;
}
