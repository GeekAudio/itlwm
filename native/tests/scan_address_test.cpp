// SPDX-License-Identifier: GPL-2.0-only
#include "../scan_address.hpp"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint8_t samples[4][6];
static unsigned reads;
extern "C" void read_random(void *output, unsigned int size)
{
    assert(size == 6 && reads < 4);
    memcpy(output, samples[reads++], 6);
}

int main()
{
    uint8_t primary[6] = {2,1,2,3,4,5};
    uint8_t previous[6] = {2,6,7,8,9,10};
    uint8_t out[6];
    memcpy(samples[0], primary, 6);
    memcpy(samples[1], previous, 6);
    const uint8_t next[6] = {0xff,11,12,13,14,15};
    memcpy(samples[2], next, 6);
    assert(NativeWifi::secureRandomScanAddress(out, primary, previous));
    assert(reads == 3 && (out[0] & 3) == 2 && !memcmp(out + 1, next + 1, 5));
    assert(memcmp(out, primary, 6) && memcmp(out, previous, 6));
    for (auto &sample : samples) memcpy(sample, primary, 6);
    reads = 0;
    assert(!NativeWifi::secureRandomScanAddress(out, primary, previous) && reads == 4);
    for (uint8_t b : out) assert(b == 0);
    memset(samples, 0, sizeof(samples)); reads = 0;
    assert(!NativeWifi::secureRandomScanAddress(out, primary, previous) && reads == 4);
    for (uint8_t b : out) assert(b == 0);
    reads = 0;
    assert(!NativeWifi::secureRandomScanAddress(nullptr, primary, previous));
    assert(!NativeWifi::secureRandomScanAddress(out, nullptr, previous));
    assert(!NativeWifi::secureRandomScanAddress(out, primary, nullptr));
    assert(reads == 0);
}
