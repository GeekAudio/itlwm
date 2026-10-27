// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>

namespace NativeWifi {
// All arrays have six bytes and must not alias. Failure clears out; it never
// falls back to a station address. The caller holds the real driver gate.
bool secureRandomScanAddress(uint8_t out[6], const uint8_t primary[6],
                              const uint8_t previous[6]);
}
