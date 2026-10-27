// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace NativeWifi {
// Inputs must not alias the 32-byte output. Failure clears the output.
bool deriveWPA2Pmk(const uint8_t *key, size_t keyLength, const uint8_t *ssid,
                   size_t ssidLength, uint8_t out[32]);
}
