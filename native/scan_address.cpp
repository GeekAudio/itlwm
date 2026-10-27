// SPDX-License-Identifier: GPL-2.0-only
#include "scan_address.hpp"
#include <sys/types.h>
#include <sys/random.h>

namespace NativeWifi {
namespace {
bool equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t difference = 0;
    for (unsigned i = 0; i < 6; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}
void clear(uint8_t *address)
{
    for (unsigned i = 0; i < 6; ++i) address[i] = 0;
}
}

bool secureRandomScanAddress(uint8_t out[6], const uint8_t primary[6],
                              const uint8_t previous[6])
{
    if (!out) return false;
    clear(out);
    if (!primary || !previous) return false;
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        read_random(out, 6);
        out[0] = (out[0] & 0xfc) | 2; // locally administered, unicast
        uint8_t entropyBits = out[0] & 0xfc;
        for (unsigned i = 1; i < 6; ++i) entropyBits |= out[i];
        if (entropyBits && !equal(out, primary) && !equal(out, previous))
            return true;
    }
    clear(out);
    return false;
}
}
