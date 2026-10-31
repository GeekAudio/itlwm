// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_RX149_LIVE_START_SNAPSHOT_HPP
#define NATIVE_RX149_LIVE_START_SNAPSHOT_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeRx149LiveStart {

constexpr uint32_t kMagic = 0x39584952u; // "RIX9" in little-endian bytes.
constexpr uint32_t kSchemaVersion = 1;
constexpr uint32_t kRx149ArmMode = 2;
constexpr uint32_t kChannel = 149;
constexpr uint32_t kDurationMs = 100;
constexpr uint32_t kDeviceDiscoveryConfiguration = 2;
constexpr uint64_t kDurationUs = 100000ULL;
constexpr size_t kRunTokenBytes = 16;
constexpr size_t kWordCount = 29;
constexpr size_t kWireBytes = kWordCount * sizeof(uint32_t);

struct Snapshot {
    uint32_t magic;
    uint32_t schemaVersion;
    uint32_t revision;
    uint32_t valid;
    uint8_t runToken[kRunTokenBytes];
    uint32_t profileMode;
    uint32_t channel;
    uint32_t durationMs;
    uint32_t configuration;
    int32_t commandResult;
    uint32_t startSeen;
    uint32_t startStatus;
    uint32_t endSeen;
    uint32_t outcomeUnknown;
    uint64_t ownerSerial;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
    uint64_t startObservedUs;
    uint64_t hardDeadlineUs;
    uint64_t publishedUs;
};

inline void putU32(uint8_t *out, size_t offset, uint32_t value)
{
    out[offset + 0] = static_cast<uint8_t>(value);
    out[offset + 1] = static_cast<uint8_t>(value >> 8);
    out[offset + 2] = static_cast<uint8_t>(value >> 16);
    out[offset + 3] = static_cast<uint8_t>(value >> 24);
}

inline void putU64(uint8_t *out, size_t offset, uint64_t value)
{
    putU32(out, offset, static_cast<uint32_t>(value));
    putU32(out, offset + sizeof(uint32_t),
           static_cast<uint32_t>(value >> 32));
}

inline uint32_t getU32(const uint8_t *bytes, size_t offset)
{
    return uint32_t(bytes[offset]) | (uint32_t(bytes[offset + 1]) << 8) |
        (uint32_t(bytes[offset + 2]) << 16) |
        (uint32_t(bytes[offset + 3]) << 24);
}

inline uint64_t getU64(const uint8_t *bytes, size_t offset)
{
    return uint64_t(getU32(bytes, offset)) |
        (uint64_t(getU32(bytes, offset + sizeof(uint32_t))) << 32);
}

inline bool tokenPresent(const Snapshot &value)
{
    uint8_t any = 0;
    for (size_t index = 0; index < kRunTokenBytes; ++index)
        any |= value.runToken[index];
    return any != 0;
}

inline bool currentStarted(const Snapshot &value, uint64_t nowUs,
                           uint64_t minimumRemainingUs)
{
    if (value.magic != kMagic || value.schemaVersion != kSchemaVersion ||
        value.revision == 0 || (value.revision & 1u) != 0 ||
        value.valid != 1 || !tokenPresent(value) ||
        value.profileMode != kRx149ArmMode || value.channel != kChannel ||
        value.durationMs != kDurationMs ||
        value.configuration != kDeviceDiscoveryConfiguration ||
        value.commandResult != 0 || value.startSeen != 1 ||
        value.startStatus != 1 || value.endSeen != 0 ||
        value.outcomeUnknown != 0 || value.ownerSerial == 0 ||
        value.contextGeneration == 0 || value.powerGeneration == 0 ||
        value.stationGeneration == 0 || value.rocGeneration == 0 ||
        value.rocGeneration != value.contextGeneration ||
        value.startObservedUs == 0 || value.hardDeadlineUs <= value.startObservedUs ||
        value.startObservedUs > UINT64_MAX - kDurationUs ||
        value.hardDeadlineUs != value.startObservedUs + kDurationUs ||
        value.publishedUs < value.startObservedUs || nowUs < value.publishedUs ||
        nowUs < value.startObservedUs || nowUs >= value.hardDeadlineUs)
        return false;
    return value.hardDeadlineUs - nowUs >= minimumRemainingUs;
}

inline bool encode(const Snapshot &value, uint8_t *out, size_t capacity)
{
    if (!out || capacity < kWireBytes || value.magic != kMagic ||
        value.schemaVersion != kSchemaVersion || value.revision == 0 ||
        (value.revision & 1u) != 0)
        return false;
    size_t offset = 0;
    putU32(out, offset, value.magic); offset += 4;
    putU32(out, offset, value.schemaVersion); offset += 4;
    putU32(out, offset, value.revision); offset += 4;
    putU32(out, offset, value.valid); offset += 4;
    for (size_t index = 0; index < kRunTokenBytes; index += 4) {
        const uint32_t word = uint32_t(value.runToken[index]) |
            (uint32_t(value.runToken[index + 1]) << 8) |
            (uint32_t(value.runToken[index + 2]) << 16) |
            (uint32_t(value.runToken[index + 3]) << 24);
        putU32(out, offset, word); offset += 4;
    }
    putU32(out, offset, value.profileMode); offset += 4;
    putU32(out, offset, value.channel); offset += 4;
    putU32(out, offset, value.durationMs); offset += 4;
    putU32(out, offset, value.configuration); offset += 4;
    putU32(out, offset, static_cast<uint32_t>(value.commandResult)); offset += 4;
    putU32(out, offset, value.startSeen); offset += 4;
    putU32(out, offset, value.startStatus); offset += 4;
    putU32(out, offset, value.endSeen); offset += 4;
    putU32(out, offset, value.outcomeUnknown); offset += 4;
    putU64(out, offset, value.ownerSerial); offset += 8;
    putU32(out, offset, value.contextGeneration); offset += 4;
    putU32(out, offset, value.powerGeneration); offset += 4;
    putU32(out, offset, value.stationGeneration); offset += 4;
    putU32(out, offset, value.rocGeneration); offset += 4;
    putU64(out, offset, value.startObservedUs); offset += 8;
    putU64(out, offset, value.hardDeadlineUs); offset += 8;
    putU64(out, offset, value.publishedUs); offset += 8;
    return offset == kWireBytes;
}

inline bool decode(const uint8_t *bytes, size_t length, Snapshot *out)
{
    if (!bytes || !out || length != kWireBytes)
        return false;
    Snapshot value{};
    size_t offset = 0;
    value.magic = getU32(bytes, offset); offset += 4;
    value.schemaVersion = getU32(bytes, offset); offset += 4;
    value.revision = getU32(bytes, offset); offset += 4;
    value.valid = getU32(bytes, offset); offset += 4;
    for (size_t index = 0; index < kRunTokenBytes; index += 4) {
        const uint32_t word = getU32(bytes, offset); offset += 4;
        value.runToken[index] = static_cast<uint8_t>(word);
        value.runToken[index + 1] = static_cast<uint8_t>(word >> 8);
        value.runToken[index + 2] = static_cast<uint8_t>(word >> 16);
        value.runToken[index + 3] = static_cast<uint8_t>(word >> 24);
    }
    value.profileMode = getU32(bytes, offset); offset += 4;
    value.channel = getU32(bytes, offset); offset += 4;
    value.durationMs = getU32(bytes, offset); offset += 4;
    value.configuration = getU32(bytes, offset); offset += 4;
    value.commandResult = static_cast<int32_t>(getU32(bytes, offset)); offset += 4;
    value.startSeen = getU32(bytes, offset); offset += 4;
    value.startStatus = getU32(bytes, offset); offset += 4;
    value.endSeen = getU32(bytes, offset); offset += 4;
    value.outcomeUnknown = getU32(bytes, offset); offset += 4;
    value.ownerSerial = getU64(bytes, offset); offset += 8;
    value.contextGeneration = getU32(bytes, offset); offset += 4;
    value.powerGeneration = getU32(bytes, offset); offset += 4;
    value.stationGeneration = getU32(bytes, offset); offset += 4;
    value.rocGeneration = getU32(bytes, offset); offset += 4;
    value.startObservedUs = getU64(bytes, offset); offset += 8;
    value.hardDeadlineUs = getU64(bytes, offset); offset += 8;
    value.publishedUs = getU64(bytes, offset); offset += 8;
    if (offset != kWireBytes || value.magic != kMagic ||
        value.schemaVersion != kSchemaVersion || value.revision == 0 ||
        (value.revision & 1u) != 0 || value.valid > 1 ||
        value.startSeen > 1 || value.endSeen > 1 || value.outcomeUnknown > 1)
        return false;
    *out = value;
    return true;
}

} // namespace NativeRx149LiveStart

#endif // NATIVE_RX149_LIVE_START_SNAPSHOT_HPP
