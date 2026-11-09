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

// Private, bounded copy of the exact target QM command and MPDU. The serialized
// form contains no pointers, DMA addresses, or host descriptors. The command
// source is the fully populated device command header + TX_CMD + MAC header;
// the MPDU is that command's actual MAC header followed by the mapped mbuf
// payload after mbuf_adj().
namespace Raw {

static constexpr uint32_t kMagic = 0x31525751u; // "QWR1" little endian
static constexpr uint32_t kStatusMagic = 0x31535751u; // "QWS1"
static constexpr uint16_t kSchemaVersion = 1;
static constexpr size_t kHeaderSize = 112;
static constexpr size_t kCommandCapacity = 64;
static constexpr size_t kMpduCapacity = 2048;
static constexpr size_t kCommandOffset = kHeaderSize;
static constexpr size_t kMpduOffset = kCommandOffset + kCommandCapacity;
static constexpr size_t kSerializedSize = kMpduOffset + kMpduCapacity;
static constexpr size_t kStatusSerializedSize = 56;

enum Flag : uint32_t {
    kCandidate = 1u << 0,
    kCommandCaptured = 1u << 1,
    kMpduCaptured = 1u << 2,
    kCommandTruncated = 1u << 3,
    kMpduTruncated = 1u << 4,
    kStageAccepted = 1u << 5,
    kRawResponseCaptured = 1u << 6
};

enum class Stage : uint32_t {
    kNone = 0,
    kCandidate = 1,
    kHeaderOrCopyRejected = 2,
    kCapturedAwaitingFinish = 3,
    kFinishFailed = 4,
    kStageCasFailed = 5,
    kStagedAwaitingPublish = 6,
    kAllocationFailed = 7,
    kRawPropertyFailed = 8,
    kFactsPropertyFailed = 9,
    kPublished = 10
};

struct Identity {
    uint64_t token;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocToken;
};

struct Record {
    Identity identity;
    uint16_t stationId;
    uint16_t queueId;
    uint16_t ringSize;
    uint16_t descriptorIndex;
    uint16_t sequenceControl;
    uint16_t frameControl;
    uint32_t flags;
    uint32_t commandActualLength;
    uint32_t commandCopiedLength;
    uint32_t mpduActualLength;
    uint32_t mpduCopiedLength;
    int32_t commandCopyResult;
    int32_t mpduCopyResult;
    Stage stage;
    uint64_t doorbellUs;
    uint64_t finishUs;
    uint8_t commandBytes[kCommandCapacity];
    uint8_t mpduBytes[kMpduCapacity];
};

struct EncodedSnapshot {
    uint8_t bytes[kSerializedSize];
};

struct StatusRecord {
    Stage stage;
    Identity identity;
};

struct EncodedStatus {
    uint8_t bytes[kStatusSerializedSize];
};

inline bool sameIdentity(const Identity &left, const Identity &right)
{
    return left.token == right.token &&
        left.contextGeneration == right.contextGeneration &&
        left.powerGeneration == right.powerGeneration &&
        left.stationGeneration == right.stationGeneration &&
        left.rocToken == right.rocToken;
}

// The target collector is intentionally first-write-wins. A later eligible
// packet cannot replace the identity of the first staged receipt.
inline bool claimFirstSlot(uint32_t *state)
{
    if (!state)
        return false;
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(state, &expected, 1u, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

inline void writeLe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

inline void writeLe32(uint8_t *bytes, uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
}

inline uint32_t readLe32(const uint8_t *bytes)
{
    uint32_t value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<uint32_t>(bytes[i]) << (i * 8);
    return value;
}

inline void writeIdentity(uint8_t *bytes, const Identity &identity)
{
    writeLe64(bytes, identity.token);
    writeLe64(bytes + 8, identity.contextGeneration);
    writeLe64(bytes + 16, identity.powerGeneration);
    writeLe64(bytes + 24, identity.stationGeneration);
    writeLe64(bytes + 32, identity.rocToken);
}

inline bool beginCapture(Record *record, size_t commandLength,
                         size_t mpduHeaderLength, size_t payloadLength)
{
    if (!record || commandLength > UINT32_MAX ||
        mpduHeaderLength > UINT32_MAX || payloadLength > UINT32_MAX ||
        mpduHeaderLength > UINT32_MAX - payloadLength)
        return false;

    record->flags |= kCandidate;
    record->commandActualLength = static_cast<uint32_t>(commandLength);
    record->mpduActualLength = static_cast<uint32_t>(
        mpduHeaderLength + payloadLength);
    record->commandCopiedLength = 0;
    record->mpduCopiedLength = 0;
    record->commandCopyResult = 0;
    record->mpduCopyResult = 0;
    memset(record->commandBytes, 0, sizeof(record->commandBytes));
    memset(record->mpduBytes, 0, sizeof(record->mpduBytes));
    record->stage = Stage::kCandidate;
    return true;
}

inline bool finishCapture(Record *record, size_t commandCopiedLength,
                          size_t mpduCopiedLength, int32_t commandCopyResult,
                          int32_t mpduCopyResult)
{
    if (!record || commandCopiedLength > record->commandActualLength ||
        mpduCopiedLength > record->mpduActualLength)
        return false;
    record->commandCopiedLength = static_cast<uint32_t>(commandCopiedLength);
    record->mpduCopiedLength = static_cast<uint32_t>(mpduCopiedLength);
    record->commandCopyResult = commandCopyResult;
    record->mpduCopyResult = mpduCopyResult;
    if (record->commandActualLength > kCommandCapacity)
        record->flags |= kCommandTruncated;
    else if (commandCopyResult == 0 && commandCopiedLength ==
             record->commandActualLength)
        record->flags |= kCommandCaptured;
    if (record->mpduActualLength > kMpduCapacity)
        record->flags |= kMpduTruncated;
    else if (mpduCopyResult == 0 && mpduCopiedLength ==
             record->mpduActualLength)
        record->flags |= kMpduCaptured;

    const bool complete = (record->flags & (kCommandCaptured | kMpduCaptured)) ==
        (kCommandCaptured | kMpduCaptured) &&
        record->commandCopyResult == 0 && record->mpduCopyResult == 0;
    record->stage = complete ? Stage::kCapturedAwaitingFinish :
                               Stage::kHeaderOrCopyRejected;
    return complete;
}

// Host-test convenience wrapper over the same begin/finish bookkeeping used
// by the production direct-to-record mbuf copy path.
inline bool captureBytes(Record *record,
                         const uint8_t *command, size_t commandLength,
                         const uint8_t *mpduHeader, size_t mpduHeaderLength,
                         const uint8_t *payload, size_t payloadLength,
                         int32_t payloadCopyResult)
{
    if (!beginCapture(record, commandLength, mpduHeaderLength, payloadLength))
        return false;

    const size_t commandCopied = command ?
        (commandLength < kCommandCapacity ? commandLength : kCommandCapacity) : 0;
    if (commandCopied && command)
        memcpy(record->commandBytes, command, commandCopied);
    const size_t headerCopied = mpduHeader ?
        (mpduHeaderLength < kMpduCapacity ? mpduHeaderLength : kMpduCapacity) : 0;
    if (headerCopied && mpduHeader)
        memcpy(record->mpduBytes, mpduHeader, headerCopied);
    size_t mpduCopied = headerCopied;
    int32_t commandResult = commandLength && !command ? -1 : 0;
    int32_t mpduResult = payloadCopyResult;
    if (headerCopied != mpduHeaderLength)
        mpduResult = -1;
    const size_t remaining = kMpduCapacity - headerCopied;
    if (mpduResult == 0 && payloadLength && !payload)
        mpduResult = -1;
    else if (mpduResult == 0 && payloadLength && remaining) {
        const size_t payloadCopied = payloadLength < remaining ?
            payloadLength : remaining;
        memcpy(record->mpduBytes + headerCopied, payload, payloadCopied);
        mpduCopied += payloadCopied;
    }
    if (commandCopied != commandLength)
        record->flags |= kCommandTruncated;
    return finishCapture(record, commandCopied, mpduCopied, commandResult,
                         mpduResult);
}

inline EncodedSnapshot encode(const Record &record)
{
    EncodedSnapshot encoded{};
    uint8_t *bytes = encoded.bytes;
    writeLe32(bytes, kMagic);
    writeLe16(bytes + 4, kSchemaVersion);
    writeLe16(bytes + 6, static_cast<uint16_t>(kHeaderSize));
    writeLe32(bytes + 8, static_cast<uint32_t>(kSerializedSize));
    writeLe32(bytes + 12, record.flags);
    writeIdentity(bytes + 16, record.identity);
    writeLe16(bytes + 56, record.stationId);
    writeLe16(bytes + 58, record.queueId);
    writeLe16(bytes + 60, record.ringSize);
    writeLe16(bytes + 62, record.descriptorIndex);
    writeLe16(bytes + 64, record.sequenceControl);
    writeLe16(bytes + 66, record.frameControl);
    writeLe32(bytes + 68, record.commandActualLength);
    writeLe32(bytes + 72, record.commandCopiedLength);
    writeLe32(bytes + 76, record.mpduActualLength);
    writeLe32(bytes + 80, record.mpduCopiedLength);
    writeLe32(bytes + 84, static_cast<uint32_t>(record.commandCopyResult));
    writeLe32(bytes + 88, static_cast<uint32_t>(record.mpduCopyResult));
    writeLe32(bytes + 92, static_cast<uint32_t>(record.stage));
    writeLe64(bytes + 96, record.doorbellUs);
    writeLe64(bytes + 104, record.finishUs);
    memcpy(bytes + kCommandOffset, record.commandBytes,
           sizeof(record.commandBytes));
    memcpy(bytes + kMpduOffset, record.mpduBytes,
           sizeof(record.mpduBytes));
    return encoded;
}

inline EncodedStatus encodeStatus(const StatusRecord &record)
{
    EncodedStatus encoded{};
    uint8_t *bytes = encoded.bytes;
    writeLe32(bytes, kStatusMagic);
    writeLe16(bytes + 4, kSchemaVersion);
    writeLe16(bytes + 6, static_cast<uint16_t>(kStatusSerializedSize));
    writeLe32(bytes + 8, static_cast<uint32_t>(record.stage));
    writeLe32(bytes + 12, 0);
    writeIdentity(bytes + 16, record.identity);
    return encoded;
}

} // namespace Raw

} // namespace NativeAwdlQmWireSnapshot

#endif // NATIVE_AWDL_QM_WIRE_SNAPSHOT_HPP
