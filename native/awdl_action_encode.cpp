// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_action_encode.hpp"
#include "awdl_action_frame.hpp"

#include <string.h>

namespace NativeAwdl {
namespace {

constexpr size_t kSyncParamsLength = 57;
constexpr size_t kElectionParamsLength = 21;
constexpr size_t kChannelSequenceLength = 25;
constexpr size_t kElectionParamsV2Length = 40;
constexpr size_t kServiceParamsLength = 9;
constexpr uint8_t kBroadcastAddress[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
constexpr uint8_t kAwdlBssid[6] = {
    0x00, 0x25, 0x00, 0xff, 0x94, 0x73
};

bool isValidUnicastAddress(const uint8_t address[6])
{
    if (!address || (address[0] & 0x01))
        return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 6; ++i)
        any |= address[i];
    return any != 0;
}

bool isSocialChannel(uint8_t channel)
{
    return channel == 6 || channel == 44 || channel == 149;
}

bool isAllowedSlot(uint8_t channel)
{
    return channel == 0 || isSocialChannel(channel);
}

void putLe16(uint8_t *output, size_t *offset, uint16_t value)
{
    output[(*offset)++] = static_cast<uint8_t>(value);
    output[(*offset)++] = static_cast<uint8_t>(value >> 8);
}

void putLe32(uint8_t *output, size_t *offset, uint32_t value)
{
    output[(*offset)++] = static_cast<uint8_t>(value);
    output[(*offset)++] = static_cast<uint8_t>(value >> 8);
    output[(*offset)++] = static_cast<uint8_t>(value >> 16);
    output[(*offset)++] = static_cast<uint8_t>(value >> 24);
}

void putBytes(uint8_t *output, size_t *offset, const uint8_t *bytes,
              size_t length)
{
    memcpy(output + *offset, bytes, length);
    *offset += length;
}

void putTlvHeader(uint8_t *output, size_t *offset, uint8_t type,
                  uint16_t length)
{
    output[(*offset)++] = type;
    putLe16(output, offset, length);
}

void putSequenceBody(uint8_t *output, size_t *offset,
                     const uint8_t channelSlots[16])
{
    // AWDL-10 simple channel encoding; this 6-byte sequence header is also
    // embedded in Synchronization Parameters (4).
    output[(*offset)++] = 15; // sixteen slots minus one
    output[(*offset)++] = 0;  // simple encoding: one byte per channel
    output[(*offset)++] = 0;  // duplicate count
    output[(*offset)++] = 3;  // four AWs per slot minus one
    output[(*offset)++] = 0xff;
    output[(*offset)++] = 0xff; // fill channel
    putBytes(output, offset, channelSlots, 16);
}

EncodeStatus validate(const PsfInput &input)
{
    if (!isValidUnicastAddress(input.sourceAddress))
        return EncodeStatus::InvalidSourceAddress;
    if (!isValidUnicastAddress(input.masterAddress) ||
        !isValidUnicastAddress(input.syncAddress))
        return EncodeStatus::InvalidElectionAddress;
    if (input.sequenceNumber > 0x0fff)
        return EncodeStatus::InvalidArgument;

    bool hasSocialChannel = false;
    bool hasNextChannel = false;
    bool hasMasterChannel = false;
    for (size_t i = 0; i < 16; ++i) {
        const uint8_t channel = input.channelSlots[i];
        if (!isAllowedSlot(channel))
            return EncodeStatus::InvalidChannelSequence;
        hasSocialChannel = hasSocialChannel || isSocialChannel(channel);
        hasNextChannel = hasNextChannel || channel == input.nextAwChannel;
        hasMasterChannel = hasMasterChannel || channel == input.masterChannel;
    }
    if (!hasSocialChannel || !isAllowedSlot(input.nextAwChannel) ||
        !isSocialChannel(input.masterChannel) || !hasNextChannel ||
        !hasMasterChannel)
        return EncodeStatus::InvalidChannelSequence;

    if (input.txDownCounterTu > 64 || input.remainingAwLengthTu > 16)
        return EncodeStatus::InvalidSyncFields;
    if (input.distanceToMaster > 0xff)
        return EncodeStatus::InvalidElectionFields;
    if (input.rxMcsLength == 0 || input.rxMcsLength > sizeof(input.rxMcsMask))
        return EncodeStatus::InvalidHtCapabilities;
    if ((input.awdlVersion & 0xf0) == 0 || input.deviceClass != 1)
        return EncodeStatus::InvalidVersion;
    return EncodeStatus::Ok;
}

} // namespace

EncodeStatus encodePsf(const PsfInput *input, uint8_t *output,
                       size_t capacity, size_t *written)
{
    if (written)
        *written = 0;
    if (!input || !output || !written)
        return EncodeStatus::InvalidArgument;

    const EncodeStatus validation = validate(*input);
    if (validation != EncodeStatus::Ok)
        return validation;

    const size_t htValueLength = 7 + input->rxMcsLength;
    const size_t requiredLength = kActionMacHeaderLength + kAwdlActionHeaderLength +
        (3 + kSyncParamsLength) + (3 + kElectionParamsLength) +
        (3 + kChannelSequenceLength) + (3 + kElectionParamsV2Length) +
        (3 + kServiceParamsLength) + (3 + htValueLength) + (3 + 2) +
        (3 + (input->advertiseAwdlAddress ? 8 : 2));
    if (capacity < requiredLength)
        return EncodeStatus::BufferTooSmall;

    uint8_t frame[kMaximumEncodedPsfLength] = {};
    size_t offset = 0;

    // 802.11 Management Action header, no HT Control or FCS.
    frame[offset++] = 0xd0;
    frame[offset++] = 0x00;
    putLe16(frame, &offset, 0); // Duration
    putBytes(frame, &offset, kBroadcastAddress, sizeof(kBroadcastAddress));
    putBytes(frame, &offset, input->sourceAddress,
             sizeof(input->sourceAddress));
    putBytes(frame, &offset, kAwdlBssid, sizeof(kAwdlBssid));
    putLe16(frame, &offset,
            static_cast<uint16_t>(input->sequenceNumber << 4));

    // Vendor action header, version 1.0 / PSF. The two timestamps are copied
    // exactly from the caller; the observation probe supplies host monotonic time.
    frame[offset++] = 127;
    frame[offset++] = 0x00;
    frame[offset++] = 0x17;
    frame[offset++] = 0xf2;
    frame[offset++] = 8;
    frame[offset++] = 0x10;
    frame[offset++] = 0;
    frame[offset++] = 0;
    putLe32(frame, &offset, input->phyTxTimestampUs);
    putLe32(frame, &offset, input->targetTxTimestampUs);

    // Synchronization Parameters (4), including the embedded channel
    // sequence and its two-byte zero pad.
    putTlvHeader(frame, &offset, 4, kSyncParamsLength);
    frame[offset++] = input->nextAwChannel;
    putLe16(frame, &offset, input->txDownCounterTu);
    frame[offset++] = input->masterChannel;
    frame[offset++] = 0; // guard time
    putLe16(frame, &offset, 16);  // AW period in TU
    putLe16(frame, &offset, 110); // PSF interval in TU
    putLe16(frame, &offset, 0x1800);
    putLe16(frame, &offset, 16); // extended AW length
    putLe16(frame, &offset, 16); // common AW length
    putLe16(frame, &offset, input->remainingAwLengthTu);
    frame[offset++] = 3;
    frame[offset++] = 3;
    frame[offset++] = 3;
    frame[offset++] = 3;
    putBytes(frame, &offset, input->masterAddress,
             sizeof(input->masterAddress));
    frame[offset++] = 4; // presence mode: four AWs per slot
    frame[offset++] = 0; // reserved
    putLe16(frame, &offset, input->nextAwSequenceNumber);
    putLe16(frame, &offset, input->apAlignment);
    putSequenceBody(frame, &offset, input->channelSlots);
    frame[offset++] = 0;
    frame[offset++] = 0;

    // Election Parameters (5), coherent with the v2 record below.
    putTlvHeader(frame, &offset, 5, kElectionParamsLength);
    frame[offset++] = 0; // flags
    putLe16(frame, &offset, 0); // ID
    frame[offset++] = static_cast<uint8_t>(input->distanceToMaster);
    frame[offset++] = 0; // reserved
    putBytes(frame, &offset, input->masterAddress,
             sizeof(input->masterAddress));
    putLe32(frame, &offset, input->masterMetric);
    putLe32(frame, &offset, input->ownMetric);
    frame[offset++] = 0;
    frame[offset++] = 0; // padding

    // Channel Sequence (18), with the three required trailing pad bytes.
    putTlvHeader(frame, &offset, 18, kChannelSequenceLength);
    putSequenceBody(frame, &offset, input->channelSlots);
    frame[offset++] = 0;
    frame[offset++] = 0;
    frame[offset++] = 0;

    // Election Parameters v2 (24).
    putTlvHeader(frame, &offset, 24, kElectionParamsV2Length);
    putBytes(frame, &offset, input->masterAddress,
             sizeof(input->masterAddress));
    putBytes(frame, &offset, input->syncAddress,
             sizeof(input->syncAddress));
    putLe32(frame, &offset, input->masterCounter);
    putLe32(frame, &offset, input->distanceToMaster);
    putLe32(frame, &offset, input->masterMetric);
    putLe32(frame, &offset, input->ownMetric);
    putLe32(frame, &offset, 0);
    putLe32(frame, &offset, 0);
    putLe32(frame, &offset, input->ownCounter);

    // Service Parameters (6) are reserved zeros in the specified profile.
    putTlvHeader(frame, &offset, 6, kServiceParamsLength);
    memset(frame + offset, 0, kServiceParamsLength);
    offset += kServiceParamsLength;

    // HT Capabilities (7), with explicit hardware values and zero reserved
    // bytes. At most MCS 0..31 is supported by this bounded serializer.
    putTlvHeader(frame, &offset, 7,
                 static_cast<uint16_t>(htValueLength));
    frame[offset++] = 0;
    frame[offset++] = 0;
    putLe16(frame, &offset, input->htCapabilityInfo);
    frame[offset++] = input->ampduParameters;
    putBytes(frame, &offset, input->rxMcsMask, input->rxMcsLength);
    frame[offset++] = 0;
    frame[offset++] = 0;

    // Legacy frames keep the exact empty two-byte value. The optional address
    // profile reuses Addr2; it carries no independent MAC or readiness claim.
    const uint16_t dataPathFlags = input->advertiseAwdlAddress ? 0x0004 : 0;
    const uint16_t dataPathLength = input->advertiseAwdlAddress ? 8 : 2;
    putTlvHeader(frame, &offset, 12, dataPathLength);
    putLe16(frame, &offset, dataPathFlags);
    if (input->advertiseAwdlAddress)
        putBytes(frame, &offset, input->sourceAddress,
                 sizeof(input->sourceAddress));

    putTlvHeader(frame, &offset, 21, 2);
    frame[offset++] = input->awdlVersion;
    frame[offset++] = input->deviceClass;

    if (offset != requiredLength) {
        // Keep output untouched if the internal wire-size calculation drifts.
        return EncodeStatus::InvalidArgument;
    }
    memcpy(output, frame, offset);
    *written = offset;
    return EncodeStatus::Ok;
}

} // namespace NativeAwdl
