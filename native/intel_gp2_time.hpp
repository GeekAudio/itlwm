// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_INTEL_GP2_TIME_HPP
#define NATIVE_INTEL_GP2_TIME_HPP

#include <stdint.h>

namespace IntelGp2Time {

// GP2 is a 32-bit microsecond counter. The signed modular delta is only
// unambiguous when both samples belong to the same firmware clock epoch and
// their true separation is less than half the counter range.
constexpr uint32_t kHalfRangeUs = 0x80000000u;
constexpr uint64_t kCounterRangeUs = 0x100000000ULL;

// Return the nearest signed delta (later - earlier) in the GP2 domain.
// Exactly half a wrap has no unique signed interpretation and is rejected.
// This does not convert GP2 to host monotonic time, TSF, or AWDL peer time.
inline bool nearestDeltaUs(uint32_t later, uint32_t earlier,
                           int64_t *deltaUs)
{
    if (!deltaUs)
        return false;

    const uint32_t modular = later - earlier;
    if (modular == kHalfRangeUs)
        return false;

    *deltaUs = modular < kHalfRangeUs ?
        static_cast<int64_t>(modular) :
        static_cast<int64_t>(modular) -
            static_cast<int64_t>(kCounterRangeUs);
    return true;
}

} // namespace IntelGp2Time

#endif // NATIVE_INTEL_GP2_TIME_HPP
