// SPDX-License-Identifier: GPL-2.0-only
#include "registration.hpp"
#include "runtime_guard.hpp"
#include "../include/Tahoe/IO80211SkywalkInterface.h"
#include <libkern/libkern.h>

namespace NativeWifi {
namespace {
// Independently checked against the pinned Apple 25G241 image. These are the
// expansion pointers, followed by the registration pointer at expansion + 0.
constexpr size_t networkExpansionOffset = 0xc0;
constexpr size_t ethernetExpansionOffset = 0x118;
constexpr size_t ethernetAddressOffset = 0x108;
constexpr size_t interfaceFamilyOffset = 0x8;
constexpr size_t interfaceSubfamilyOffset = 0xc;
constexpr uint32_t ethernetFamily = 2;
constexpr uint32_t wifiSubfamily = 3;

void *expansion(IO80211SkywalkInterface *interface, size_t offset)
{
    void *value = nullptr;
    if (interface)
        memcpy(&value, reinterpret_cast<uint8_t *>(interface) + offset,
               sizeof(value));
    return value;
}

void *cachedInfo(void *data)
{
    void *value = nullptr;
    if (data)
        memcpy(&value, data, sizeof(value));
    return value;
}

void publish(void *data, const void *value)
{
    memcpy(data, &value, sizeof(value));
}

bool validAddress(const uint8_t *address)
{
    if (!address || (address[0] & 1))
        return false;
    uint8_t combined = 0;
    for (unsigned int i = 0; i < 6; ++i)
        combined |= address[i];
    return combined != 0;
}

uint8_t *ethernetInfo(IO80211SkywalkInterface *interface,
                      const RegistrationState &state)
{
    if (!interface || !state.published ||
        cachedInfo(expansion(interface, networkExpansionOffset)) != state.networkInfo)
        return nullptr;
    auto info = static_cast<uint8_t *>(cachedInfo(
        expansion(interface, ethernetExpansionOffset)));
    if (!info)
        return nullptr;
    uint32_t version = 0, length = 0;
    memcpy(&version, info, sizeof(version));
    memcpy(&length, info + sizeof(version), sizeof(length));
    return version == 1 && length >= 0x130 ? info : nullptr;
}
}

bool prepareRegistration(IO80211SkywalkInterface *interface,
                         const uint8_t *address, RegistrationState &state)
{
    if (!interface || !validAddress(address) || state.published ||
        !verifyTahoeRuntime())
        return false;

    void *network = expansion(interface, networkExpansionOffset);
    void *ethernet = expansion(interface, ethernetExpansionOffset);
    if (!network || !ethernet || cachedInfo(network) || cachedInfo(ethernet))
        return false;

    IOSkywalkEthernetInterface::RegistrationInfo info {};
    if (!interface->initRegistrationInfo(&info, 1, sizeof(info)))
        return false;
    uint32_t family = 0;
    memcpy(&family, info.opaque + interfaceFamilyOffset, sizeof(family));
    if (family != ethernetFamily)
        return false;
    // Actual Apple25G241 Core::createSkywalkInterface writes the Wi-Fi
    // subfamily at +0xc after the native Ethernet initializer. This is
    // metadata only; the separate BSD interface must set its subtype before
    // ifnet allocation through IONetworkInterface::setInterfaceSubType(3).
    memcpy(info.opaque + interfaceSubfamilyOffset, &wifiSubfamily,
           sizeof(wifiSubfamily));
    memcpy(info.opaque + ethernetAddressOffset, address, 6);

    // Let the native Ethernet allocator create the cache its native free()
    // expects. Never substitute a generic IOMalloc buffer for that ownership.
    if (interface->copyRegistrationInfo(&info) != kIOReturnSuccess)
        return false;
    const uint8_t *copy = static_cast<const uint8_t *>(cachedInfo(ethernet));
    if (!copy || memcmp(copy + ethernetAddressOffset, address, 6) ||
        memcmp(copy + interfaceSubfamilyOffset, &wifiSubfamily,
               sizeof(wifiSubfamily)))
        return false;

    memcpy(state.networkInfo, &info, sizeof(state.networkInfo));
    publish(network, state.networkInfo);
    state.published = true;
    return true;
}

void detachRegistration(IO80211SkywalkInterface *interface,
                        RegistrationState &state)
{
    if (!state.published)
        return;
    void *network = expansion(interface, networkExpansionOffset);
    if (network && cachedInfo(network) == state.networkInfo)
        publish(network, nullptr);
    state.published = false;
}

bool updateRegistrationAddress(IO80211SkywalkInterface *interface,
                               RegistrationState &state, const uint8_t *address)
{
    uint8_t *info = ethernetInfo(interface, state);
    if (!info || !validAddress(address))
        return false;
    memcpy(info + ethernetAddressOffset, address, 6);
    return !memcmp(info + ethernetAddressOffset, address, 6);
}

bool registrationAddressMatches(IO80211SkywalkInterface *interface,
                                const RegistrationState &state,
                                const uint8_t *address)
{
    const uint8_t *info = ethernetInfo(interface, state);
    return info && validAddress(address) &&
        !memcmp(info + ethernetAddressOffset, address, 6);
}
}
