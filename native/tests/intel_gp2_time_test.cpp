// SPDX-License-Identifier: GPL-2.0-only
#include "native/intel_gp2_time.hpp"

#include <cassert>
#include <cstdint>

int main()
{
    int64_t delta = 0;

    assert(IntelGp2Time::nearestDeltaUs(1100, 1000, &delta));
    assert(delta == 100);

    // A short forward interval across the 32-bit GP2 wrap remains positive.
    assert(IntelGp2Time::nearestDeltaUs(0x00000010u, 0xfffffff0u, &delta));
    assert(delta == 32);

    // A short out-of-order sample remains a negative delta.
    assert(IntelGp2Time::nearestDeltaUs(0xfffffff0u, 0x00000010u, &delta));
    assert(delta == -32);

    assert(IntelGp2Time::nearestDeltaUs(42, 42, &delta));
    assert(delta == 0);

    // Half a wrap has two equally valid signed interpretations.
    assert(!IntelGp2Time::nearestDeltaUs(0x80000000u, 0, &delta));
    assert(!IntelGp2Time::nearestDeltaUs(0, 42, nullptr));
    return 0;
}
