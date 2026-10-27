// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_NATIVE_WCL_WIRE_HPP
#define GEEK_NATIVE_WCL_WIRE_HPP

#include <stddef.h>
#include <stdint.h>

// Original bounded views of the 25G241 driver requests. These are kernel
// buffers supplied by native IO80211, not user pointers or packed C++ objects.
namespace NativeWifi {
constexpr size_t ScanWireSize = 0x1550;
constexpr size_t JoinWireSize = 0x6f8;
constexpr size_t MaximumIEBytes = 2048;
enum class DecodeResult { Ok, Malformed, Unsupported };

struct ScanPlan {
    uint32_t identifier;
    uint32_t type;
    uint32_t homeTime, activeTime, passiveTime, restTime;
    uint16_t flags;
    bool privateAddressRequired;
    bool restricted;
    uint8_t ssidLength;
    uint8_t ssid[32];
    uint8_t channels[32];
};

struct JoinPlan {
    uint32_t lowerAuth, upperAuth, allowedAuth;
    uint8_t ssidLength;
    uint8_t ssid[32];
    uint8_t bssid[6];
    uint16_t channelSpec;
    uint16_t rsnLength;
    uint8_t rsn[257];
    uint8_t pmk[32];
    uint8_t password[64], passwordLength;
    bool secured, derivePmk;
};

DecodeResult decodeScan(const void *, size_t, ScanPlan &, uint32_t *rejectedField = nullptr);
DecodeResult decodeJoin(const void *, size_t, JoinPlan &, uint32_t *rejectedField = nullptr);
bool validateIEs(const uint8_t *, size_t);
bool selectedChannel(const ScanPlan &, unsigned);
void erase(void *, size_t);
uint16_t read16(const uint8_t *);
uint32_t read32(const uint8_t *);
void write16(uint8_t *, uint16_t);
void write32(uint8_t *, uint32_t);

// Published payload contracts are checked against the running Apple image;
// no C++ layout, padding, kernel pointer, or borrowed RX storage is exported.
enum NativeEvent : uint32_t {
    ScanBeacon = 201, Deauthentication = 203, Association = 211,
    FirstBeacon = 212, Connection = 213, JoinAborted = 214,
    Link = 216, ScanFinished = 237, DriverReset = 49,
    DriverAvailability = 55, BeaconLqm = 39
};
constexpr size_t BeaconPrefixSize = 0x44;
constexpr size_t AssociationEventSize = 0x1c;
constexpr size_t FirstBeaconEventSize = 0x14;
constexpr size_t ConnectionEventSize = 0xa4;
constexpr size_t LinkEventSize = 0x10;
constexpr size_t BeaconLqmSize = 0x1dc;
}
#endif
