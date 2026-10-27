// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>

class IO80211SkywalkInterface;

namespace NativeWifi {
// Metadata for the upstream BSD data path, not a registered Skywalk queue set.
// Native code borrows this prefix while the derived interface exists. It must
// be detached before any native stop/free/deregister operation can own it.
struct RegistrationState {
    alignas(8) uint8_t networkInfo[0x108] {};
    bool published {false};
};

bool prepareRegistration(IO80211SkywalkInterface *, const uint8_t *address,
                         RegistrationState &);
void detachRegistration(IO80211SkywalkInterface *, RegistrationState &);
// Called under the same driver gate as the address transaction and READY check.
bool updateRegistrationAddress(IO80211SkywalkInterface *, RegistrationState &,
                               const uint8_t *address);
bool registrationAddressMatches(IO80211SkywalkInterface *,
                                const RegistrationState &, const uint8_t *address);
}
