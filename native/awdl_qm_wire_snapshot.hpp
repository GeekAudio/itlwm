// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_QM_WIRE_SNAPSHOT_HPP
#define NATIVE_AWDL_QM_WIRE_SNAPSHOT_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Address-free facts about one native Qm TX. No packet/address pointers are
// retained; the serialized form is a fixed little-endian array of integers.
namespace NativeAwdlQmWireSnapshot {

enum RoleFlag : uint32_t {
    kHeaderValid = 1u << 0,
    kNoDs = 1u << 1,
    kAddress1Multicast = 1u << 2,
    kAddress1Broadcast = 1u << 3,
    kAddress2MatchesLocal = 1u << 4,
    kAddress3MatchesAwdlBssid = 1u << 5,
    kAddress1MatchesAirdropMdnsMapping = 1u << 6,
    kIpv6DestinationIsAirdropMdnsGroup = 1u << 7
};

enum Field : size_t {
    kSchemaVersion = 0,
    kToken,
    kContextGeneration,
    kPowerGeneration,
    kStationGeneration,
    kRocToken,
    kStationId,
    kQueueId,
    kRingSize,
    kDescriptorIndex,
    kFrameControl,
    kSequenceControl,
    kMpduLength,
    kHeaderLength,
    kDsBits,
    kAddressRoleFlags,
    kHeaderIsValid,
    kDriverFrameType,
    kTxLayout,
    kTxCommandApi,
    kTxNotificationApi,
    kTxFlags,
    kRateNFlags,
    kOffloadAssist,
    kMhSizeWords,
    kTfdCount,
    kFirstTbBytes,
    kCommandTailBytes,
    kPayloadSegmentCount,
    kPayloadBytes,
    kChannel,
    kFrequencyMhz,
    kHostPreDoorbellUs,
    kWindowNotBeforeUs,
    kWindowDeadlineUs,
    kCurrentGp2Valid,
    kFieldCount
};

static constexpr uint64_t kSchemaVersionValue = 1;
static constexpr size_t kSerializedSize = kFieldCount * sizeof(uint64_t);

struct HeaderSnapshot {
    uint16_t frameControl;
    uint16_t sequenceControl;
    uint16_t mpduLength;
    uint8_t dsBits;
    uint8_t headerLength;
    uint32_t roleFlags;
    bool valid;
};

struct Record {
    HeaderSnapshot header;
    uint64_t token;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocToken;
    uint64_t stationId;
    uint64_t queueId;
    uint64_t ringSize;
    uint64_t descriptorIndex;
    uint64_t frameType;
    uint64_t txLayout;
    uint64_t txCommandApi;
    uint64_t txNotificationApi;
    uint64_t txFlags;
    uint64_t rateNFlags;
    uint64_t offloadAssist;
    uint64_t mhSizeWords;
    uint64_t tfdCount;
    uint64_t firstTbBytes;
    uint64_t commandTailBytes;
    uint64_t payloadSegmentCount;
    uint64_t payloadBytes;
    uint64_t channel;
    uint64_t frequencyMhz;
    uint64_t hostPreDoorbellUs;
    uint64_t estimatedNotBeforeUs;
    uint64_t estimatedDeadlineUs;
};

struct EncodedSnapshot {
    uint8_t bytes[kSerializedSize];
};

inline uint16_t readLe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

inline bool equalAddress(const uint8_t *left, const uint8_t *right)
{
    if (!left || !right)
        return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < 6; ++i)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

inline bool isBroadcastAddress(const uint8_t *address)
{
    if (!address)
        return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < 6; ++i)
        difference |= address[i] ^ 0xff;
    return difference == 0;
}

inline bool isAirdropMdnsGroupDestination(const uint8_t *destination)
{
    if (!destination || destination[0] != 0xff || destination[1] != 0x02 ||
        destination[15] != 0xfb)
        return false;
    for (size_t i = 2; i < 15; ++i)
        if (destination[i] != 0)
            return false;
    return true;
}

inline HeaderSnapshot inspectHeader(const uint8_t *header,
                                   size_t availableHeaderLength,
                                   size_t mpduLength,
                                   const uint8_t localAddress[6],
                                   const uint8_t awdlBssid[6],
                                   bool ipv6DestinationIsAirdropMdns)
{
    HeaderSnapshot result{};
    if (!header || !localAddress || !awdlBssid ||
        availableHeaderLength < 24 || mpduLength < 24 ||
        mpduLength > UINT16_MAX)
        return result;

    result.frameControl = readLe16(header);
    result.sequenceControl = readLe16(header + 22);
    result.mpduLength = static_cast<uint16_t>(mpduLength);
    result.dsBits = static_cast<uint8_t>((result.frameControl >> 8) & 0x3u);
    result.headerLength = 24;
    result.roleFlags = kHeaderValid;
    if (result.dsBits == 0)
        result.roleFlags |= kNoDs;
    if (header[4] & 0x01u)
        result.roleFlags |= kAddress1Multicast;
    if (isBroadcastAddress(header + 4))
        result.roleFlags |= kAddress1Broadcast;
    if (equalAddress(header + 10, localAddress))
        result.roleFlags |= kAddress2MatchesLocal;
    if (equalAddress(header + 16, awdlBssid))
        result.roleFlags |= kAddress3MatchesAwdlBssid;

    if (ipv6DestinationIsAirdropMdns) {
        static const uint8_t airdropMdnsMapping[6] = {
            0x33, 0x33, 0x00, 0x00, 0x00, 0xfb
        };
        result.roleFlags |= kIpv6DestinationIsAirdropMdnsGroup;
        if (equalAddress(header + 4, airdropMdnsMapping))
            result.roleFlags |= kAddress1MatchesAirdropMdnsMapping;
    }

    result.valid = true;
    return result;
}

inline void writeLe64(uint8_t *bytes, uint64_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
}

inline uint64_t fieldValue(const Record &record, Field field)
{
    switch (field) {
    case kSchemaVersion: return kSchemaVersionValue;
    case kToken: return record.token;
    case kContextGeneration: return record.contextGeneration;
    case kPowerGeneration: return record.powerGeneration;
    case kStationGeneration: return record.stationGeneration;
    case kRocToken: return record.rocToken;
    case kStationId: return record.stationId;
    case kQueueId: return record.queueId;
    case kRingSize: return record.ringSize;
    case kDescriptorIndex: return record.descriptorIndex;
    case kFrameControl: return record.header.frameControl;
    case kSequenceControl: return record.header.sequenceControl;
    case kMpduLength: return record.header.mpduLength;
    case kHeaderLength: return record.header.headerLength;
    case kDsBits: return record.header.dsBits;
    case kAddressRoleFlags: return record.header.roleFlags;
    case kHeaderIsValid: return record.header.valid ? 1 : 0;
    case kDriverFrameType: return record.frameType;
    case kTxLayout: return record.txLayout;
    case kTxCommandApi: return record.txCommandApi;
    case kTxNotificationApi: return record.txNotificationApi;
    case kTxFlags: return record.txFlags;
    case kRateNFlags: return record.rateNFlags;
    case kOffloadAssist: return record.offloadAssist;
    case kMhSizeWords: return record.mhSizeWords;
    case kTfdCount: return record.tfdCount;
    case kFirstTbBytes: return record.firstTbBytes;
    case kCommandTailBytes: return record.commandTailBytes;
    case kPayloadSegmentCount: return record.payloadSegmentCount;
    case kPayloadBytes: return record.payloadBytes;
    case kChannel: return record.channel;
    case kFrequencyMhz: return record.frequencyMhz;
    case kHostPreDoorbellUs: return record.hostPreDoorbellUs;
    case kWindowNotBeforeUs: return record.estimatedNotBeforeUs;
    case kWindowDeadlineUs: return record.estimatedDeadlineUs;
    case kCurrentGp2Valid: return 0; // Never sampled in the submit path.
    case kFieldCount: break;
    }
    return 0;
}

inline EncodedSnapshot encode(const Record &record)
{
    EncodedSnapshot encoded{};
    for (size_t field = 0; field < kFieldCount; ++field)
        writeLe64(encoded.bytes + field * sizeof(uint64_t),
                   fieldValue(record, static_cast<Field>(field)));
    return encoded;
}

inline uint64_t readLe64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    return value;
}

} // namespace NativeAwdlQmWireSnapshot

#endif // NATIVE_AWDL_QM_WIRE_SNAPSHOT_HPP
