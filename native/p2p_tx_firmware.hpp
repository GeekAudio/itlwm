// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>

namespace IntelP2PFirmware {

// Transport families, not the radio's retail name. AX201 radios on a So
// transport use the AX210-family TX command layout.
enum class DeviceFamily : uint8_t { kUnknown = 0, k22000 = 1, kAX210 = 2 };
enum class TxLayout : uint8_t { kUnsupported = 0, kGen2 = 1, kGen3 = 2 };

inline TxLayout txLayout(DeviceFamily family, uint8_t command,
                          uint8_t notification)
{
    if (notification != 7)
        return TxLayout::kUnsupported;
    if (family == DeviceFamily::k22000 && command == 9)
        return TxLayout::kGen2;
    if (family == DeviceFamily::kAX210 && command == 10)
        return TxLayout::kGen3;
    return TxLayout::kUnsupported;
}

// An absent modern queue command is significant: these firmware generations
// retire TVQM queues with their station, rather than a separate REMOVE opcode.
struct Profile {
    DeviceFamily deviceFamily;
    uint8_t txCommand;
    uint8_t txNotification;
    uint8_t queueCommand;
    uint8_t queueResponse;
    uint8_t modernQueueCommand;
    uint8_t flushCommand;
    uint8_t flushResponse;
    uint8_t removeStationCommand;
    bool dqa;
    bool rateValid;
};

enum Rejection : uint32_t {
    kFamily = 1U << 0,
    kTxCommand = 1U << 1,
    kTxNotification = 1U << 2,
    kQueueCommand = 1U << 3,
    kQueueResponse = 1U << 4,
    kModernQueuePresent = 1U << 5,
    kFlushCommand = 1U << 6,
    kFlushResponse = 1U << 7,
    kRemoveStation = 1U << 8,
    // Bit 9 is intentionally unused. CAPA_DQA describes the older static
    // queue setup; gen2 TVQM does not require it (fw68 leaves it clear).
    kRate = 1U << 10
};

inline uint32_t rejectionMask(const Profile &p, uint8_t unknownVersion)
{
    const bool knownFamily = p.deviceFamily == DeviceFamily::k22000 ||
        p.deviceFamily == DeviceFamily::kAX210;
    const bool commandMatchesFamily =
        (p.deviceFamily == DeviceFamily::k22000 && p.txCommand == 9) ||
        (p.deviceFamily == DeviceFamily::kAX210 && p.txCommand == 10);
    return (knownFamily ? 0U : kFamily) |
        (commandMatchesFamily ? 0U : kTxCommand) |
        (p.txNotification == 7 ? 0U : kTxNotification) |
        (p.queueCommand == 2 ? 0U : kQueueCommand) |
        (p.queueResponse == 2 ? 0U : kQueueResponse) |
        (p.modernQueueCommand == unknownVersion ? 0U : kModernQueuePresent) |
        (p.flushCommand == 2 ? 0U : kFlushCommand) |
        (p.flushResponse == 1 ? 0U : kFlushResponse) |
        (p.removeStationCommand == 2 ? 0U : kRemoveStation) |
        (p.rateValid ? 0U : kRate);
}

} // namespace IntelP2PFirmware
