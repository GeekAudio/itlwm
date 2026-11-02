// SPDX-License-Identifier: GPL-2.0-only
#ifndef TEST110_OPENWRT_ECHO_CHANNEL_HPP
#define TEST110_OPENWRT_ECHO_CHANNEL_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Bounded, read-only parser for the single replies to nl80211 GETFAMILY and
// GET_INTERFACE. Netlink scalar fields are native-endian; this helper is
// intentionally limited to the little-endian Linux targets used by Test110.
namespace Test110Channel {

constexpr uint16_t kNlctrlFamilyId = 0x10;
constexpr uint8_t kCtrlCmdNewFamily = 1;
constexpr uint16_t kCtrlAttrFamilyId = 1;
constexpr uint16_t kCtrlAttrFamilyName = 2;
constexpr uint8_t kNl80211CmdNewInterface = 7;
constexpr uint16_t kNl80211AttrIfindex = 3;
constexpr uint16_t kNl80211AttrIfname = 4;
constexpr uint16_t kNl80211AttrWiphyFreq = 38;
constexpr uint16_t kNl80211AttrWiphyFreqOffset = 290;
constexpr uint32_t kChannel6FrequencyMhz = 2437;
constexpr size_t kNetlinkHeaderBytes = 16;
constexpr size_t kGenericHeaderBytes = 4;
constexpr size_t kMaximumReplyBytes = 4096;

enum class Status : uint8_t {
    kOk = 0,
    kInvalidArgument,
    kInvalidLength,
    kWrongSource,
    kWrongSequence,
    kWrongPortId,
    kWrongMessageType,
    kWrongCommand,
    kMalformedAttribute,
    kDuplicateAttribute,
    kMissingAttribute,
    kFamilyNameMismatch,
    kFamilyIdInvalid,
    kIfindexMismatch,
    kIfnameMismatch,
    kFrequencyMismatch
};

struct SourceAddress {
    uint32_t portId;
    uint32_t groups;
};

inline uint16_t readLe16(const uint8_t *p)
{
    return static_cast<uint16_t>(p[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t readLe32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
}

inline bool parseEnvelope(const uint8_t *bytes, size_t length,
                          const SourceAddress &source,
                          uint16_t expectedType, uint8_t expectedCommand,
                          uint32_t expectedSequence, uint32_t localPortId,
                          const uint8_t **attributes, size_t *attributesLength)
{
    if (!bytes || !attributes || !attributesLength || localPortId == 0 ||
        expectedSequence == 0)
        return false;
    if (length < kNetlinkHeaderBytes + kGenericHeaderBytes ||
        length > kMaximumReplyBytes)
        return false;
    if (source.portId != 0 || source.groups != 0)
        return false;

    const uint32_t messageLength = readLe32(bytes);
    const uint16_t messageType = readLe16(bytes + 4);
    const uint16_t messageFlags = readLe16(bytes + 6);
    const uint32_t sequence = readLe32(bytes + 8);
    const uint32_t portId = readLe32(bytes + 12);
    if (messageLength != length || messageFlags != 0)
        return false;
    if (sequence != expectedSequence)
        return false;
    // The kernel's generic-netlink reply builder places the requester port ID
    // in nlmsg_pid. The sockaddr_nl sender above must independently be kernel 0.
    if (portId != localPortId)
        return false;
    if (messageType != expectedType)
        return false;

    const uint8_t *generic = bytes + kNetlinkHeaderBytes;
    if (generic[0] != expectedCommand || generic[2] != 0 || generic[3] != 0)
        return false;
    *attributes = generic + kGenericHeaderBytes;
    *attributesLength = length - kNetlinkHeaderBytes - kGenericHeaderBytes;
    return true;
}

struct Attribute {
    uint16_t type;
    const uint8_t *value;
    size_t valueLength;
};

inline Status findAttributes(const uint8_t *bytes, size_t length,
                             const uint16_t *wanted, size_t wantedCount,
                             Attribute *found)
{
    if ((!bytes && length != 0) || (!wanted && wantedCount != 0) ||
        (!found && wantedCount != 0))
        return Status::kInvalidArgument;
    for (size_t i = 0; i < wantedCount; ++i)
        found[i] = Attribute{wanted[i], nullptr, 0};

    size_t offset = 0;
    while (offset < length) {
        const size_t remaining = length - offset;
        if (remaining < 4)
            return Status::kMalformedAttribute;
        const uint16_t attributeLength = readLe16(bytes + offset);
        const uint16_t rawType = readLe16(bytes + offset + 2);
        if (attributeLength < 4 || attributeLength > remaining)
            return Status::kMalformedAttribute;
        const uint16_t type = static_cast<uint16_t>(rawType & 0x3fffU);
        const size_t valueLength = attributeLength - 4;
        for (size_t i = 0; i < wantedCount; ++i) {
            if (type != wanted[i])
                continue;
            // Do not accept nested or network-byte-order encodings for fields
            // that are specified as scalar/string attributes.
            if (rawType != type)
                return Status::kMalformedAttribute;
            if (found[i].value != nullptr)
                return Status::kDuplicateAttribute;
            found[i].value = bytes + offset + 4;
            found[i].valueLength = valueLength;
        }
        const size_t alignedLength = (static_cast<size_t>(attributeLength) + 3U) & ~size_t(3U);
        if (alignedLength > remaining)
            return Status::kMalformedAttribute;
        offset += alignedLength;
    }
    return Status::kOk;
}

inline Status parseFamilyReply(const uint8_t *bytes, size_t length,
                               const SourceAddress &source,
                               uint32_t expectedSequence, uint32_t localPortId,
                               const char *expectedName, uint16_t *familyId)
{
    if (!expectedName || !*expectedName || !familyId)
        return Status::kInvalidArgument;
    const uint8_t *attributes = nullptr;
    size_t attributesLength = 0;
    if (!parseEnvelope(bytes, length, source, kNlctrlFamilyId,
                       kCtrlCmdNewFamily, expectedSequence, localPortId,
                       &attributes, &attributesLength)) {
        if (!bytes || length < kNetlinkHeaderBytes + kGenericHeaderBytes ||
            length > kMaximumReplyBytes)
            return Status::kInvalidLength;
        if (source.portId != 0 || source.groups != 0)
            return Status::kWrongSource;
        if (readLe32(bytes + 8) != expectedSequence)
            return Status::kWrongSequence;
        if (readLe32(bytes + 12) != localPortId)
            return Status::kWrongPortId;
        if (readLe16(bytes + 4) != kNlctrlFamilyId)
            return Status::kWrongMessageType;
        if (bytes[kNetlinkHeaderBytes] != kCtrlCmdNewFamily)
            return Status::kWrongCommand;
        return Status::kInvalidLength;
    }

    const uint16_t wanted[] = {kCtrlAttrFamilyId, kCtrlAttrFamilyName};
    Attribute found[2]{};
    Status status = findAttributes(attributes, attributesLength, wanted, 2, found);
    if (status != Status::kOk)
        return status;
    if (!found[0].value || !found[1].value)
        return Status::kMissingAttribute;
    if (found[0].valueLength != 2)
        return Status::kMalformedAttribute;
    if (found[1].valueLength != strlen(expectedName) + 1 ||
        found[1].value[found[1].valueLength - 1] != 0 ||
        memchr(found[1].value, 0, found[1].valueLength - 1) != nullptr ||
        memcmp(found[1].value, expectedName, strlen(expectedName)) != 0)
        return Status::kFamilyNameMismatch;
    const uint16_t parsedId = readLe16(found[0].value);
    if (parsedId <= kNlctrlFamilyId)
        return Status::kFamilyIdInvalid;
    *familyId = parsedId;
    return Status::kOk;
}

inline Status parseInterfaceReply(const uint8_t *bytes, size_t length,
                                  const SourceAddress &source,
                                  uint16_t nl80211FamilyId,
                                  uint32_t expectedSequence,
                                  uint32_t localPortId,
                                  uint32_t expectedIfindex,
                                  const char *expectedIfname,
                                  uint32_t *frequencyMhz,
                                  uint32_t *frequencyOffsetKhz)
{
    if (nl80211FamilyId <= kNlctrlFamilyId || expectedIfindex == 0 ||
        !expectedIfname || !*expectedIfname || !frequencyMhz ||
        !frequencyOffsetKhz)
        return Status::kInvalidArgument;
    const uint8_t *attributes = nullptr;
    size_t attributesLength = 0;
    if (!parseEnvelope(bytes, length, source, nl80211FamilyId,
                       kNl80211CmdNewInterface, expectedSequence, localPortId,
                       &attributes, &attributesLength)) {
        if (!bytes || length < kNetlinkHeaderBytes + kGenericHeaderBytes ||
            length > kMaximumReplyBytes)
            return Status::kInvalidLength;
        if (source.portId != 0 || source.groups != 0)
            return Status::kWrongSource;
        if (readLe32(bytes + 8) != expectedSequence)
            return Status::kWrongSequence;
        if (readLe32(bytes + 12) != localPortId)
            return Status::kWrongPortId;
        if (readLe16(bytes + 4) != nl80211FamilyId)
            return Status::kWrongMessageType;
        if (bytes[kNetlinkHeaderBytes] != kNl80211CmdNewInterface)
            return Status::kWrongCommand;
        return Status::kInvalidLength;
    }

    const uint16_t wanted[] = {kNl80211AttrIfindex, kNl80211AttrIfname,
        kNl80211AttrWiphyFreq, kNl80211AttrWiphyFreqOffset};
    Attribute found[4]{};
    Status status = findAttributes(attributes, attributesLength, wanted, 4, found);
    if (status != Status::kOk)
        return status;
    for (size_t i = 0; i < 3; ++i)
        if (!found[i].value)
            return Status::kMissingAttribute;
    if (found[0].valueLength != 4 || found[1].valueLength != strlen(expectedIfname) + 1 ||
        found[1].value[found[1].valueLength - 1] != 0 ||
        memchr(found[1].value, 0, found[1].valueLength - 1) != nullptr)
        return Status::kMalformedAttribute;
    if (readLe32(found[0].value) != expectedIfindex)
        return Status::kIfindexMismatch;
    if (memcmp(found[1].value, expectedIfname, strlen(expectedIfname)) != 0)
        return Status::kIfnameMismatch;
    if (found[2].valueLength != 4 ||
        (found[3].value && found[3].valueLength != 4))
        return Status::kMalformedAttribute;
    const uint32_t parsedFrequency = readLe32(found[2].value);
    const uint32_t parsedOffset = found[3].value
        ? readLe32(found[3].value) : 0U;
    if (parsedFrequency != kChannel6FrequencyMhz || parsedOffset != 0)
        return Status::kFrequencyMismatch;
    *frequencyMhz = parsedFrequency;
    *frequencyOffsetKhz = parsedOffset;
    return Status::kOk;
}

inline bool nonceUsable(const uint8_t nonce[8])
{
    static const uint8_t oldMarker[8] = {'T','0','8','6','R','X','0','1'};
    if (!nonce)
        return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 8; ++i)
        any |= nonce[i];
    return any != 0 && memcmp(nonce, oldMarker, sizeof(oldMarker)) != 0;
}

} // namespace Test110Channel

#endif
