// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_data_frame.hpp"

#include <string.h>

namespace NativeAwdlData {
namespace {

constexpr size_t kMacHeaderLength = 24;
constexpr size_t kQosControlLength = 2;
constexpr size_t kSnapHeaderLength = 8;
constexpr size_t kAwdlDataHeaderLength = 8;
constexpr size_t kAwdlPayloadPrefixLength =
    kSnapHeaderLength + kAwdlDataHeaderLength;
constexpr size_t kUnaggregatedPrefixLength =
    kMacHeaderLength + kAwdlPayloadPrefixLength;
constexpr uint16_t kFrameControlVersionMask = 0x0003;
constexpr uint16_t kFrameControlTypeMask = 0x000c;
constexpr uint16_t kFrameControlSubtypeMask = 0x00f0;
constexpr uint16_t kFrameControlToDs = 0x0100;
constexpr uint16_t kFrameControlFromDs = 0x0200;
constexpr uint16_t kFrameControlMoreFragments = 0x0400;
constexpr uint16_t kFrameControlProtected = 0x4000;
constexpr uint16_t kFrameControlOrder = 0x8000;
constexpr uint16_t kQosAmsduPresent = 0x0080;
constexpr uint16_t kQosMeshControlPresent = 0x0100;
constexpr uint16_t kDataFrameType = 0x0008;
constexpr uint16_t kDataSubtype = 0x0000;
constexpr uint16_t kQosDataSubtype = 0x0080;
constexpr uint8_t kSnapPrefix[6] = {0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2};
constexpr uint8_t kAwdlHeadLittleEndian[2] = {0x03, 0x04};
constexpr uint8_t kAwdlPadLittleEndian[2] = {0x00, 0x00};

uint16_t readLe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

uint16_t readBe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

void putLe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

bool isNonzeroAddress(const uint8_t *address)
{
    uint8_t combined = 0;
    for (size_t i = 0; i < 6; ++i)
        combined |= address[i];
    return combined != 0;
}

bool isUnicastAddress(const uint8_t *address)
{
    return isNonzeroAddress(address) && (address[0] & 0x01) == 0;
}

Status validateIpv6Packet(const uint8_t *packet, size_t length)
{
    if (!packet || length < kIpv6HeaderLength)
        return Status::InvalidIpv6Packet;
    if ((packet[0] >> 4) != 6)
        return Status::InvalidIpv6Packet;

    const size_t payloadLength = readBe16(packet + 4);
    if (length != kIpv6HeaderLength + payloadLength)
        return Status::InvalidIpv6Packet;
    return Status::Ok;
}

Status decodeAwdlPayload(const uint8_t *body, size_t bodyLength,
                         const uint8_t *destination, const uint8_t *source,
                         PacketView *packet)
{
    if (!body || !destination || !source || !packet)
        return Status::InvalidArgument;
    if (bodyLength < kAwdlPayloadPrefixLength)
        return Status::InvalidLength;
    if (memcmp(body, kSnapPrefix, sizeof(kSnapPrefix)) != 0 ||
        body[6] != 0x08 || body[7] != 0x00)
        return Status::InvalidSnapHeader;

    const uint8_t *awdl = body + kSnapHeaderLength;
    if (memcmp(awdl, kAwdlHeadLittleEndian,
               sizeof(kAwdlHeadLittleEndian)) != 0 ||
        memcmp(awdl + 4, kAwdlPadLittleEndian,
               sizeof(kAwdlPadLittleEndian)) != 0)
        return Status::InvalidAwdlHeader;
    if (awdl[6] != 0x86 || awdl[7] != 0xdd)
        return Status::UnsupportedEthertype;

    const uint8_t *ipv6 = awdl + kAwdlDataHeaderLength;
    const size_t ipv6Length = bodyLength - kAwdlPayloadPrefixLength;
    const Status ipv6Status = validateIpv6Packet(ipv6, ipv6Length);
    if (ipv6Status != Status::Ok)
        return ipv6Status;

    PacketView parsed = {};
    memcpy(parsed.destinationAddress, destination, 6);
    memcpy(parsed.sourceAddress, source, 6);
    parsed.awdlSequenceNumber = readLe16(awdl + 2);
    parsed.ipv6Packet = ipv6;
    parsed.ipv6Length = ipv6Length;
    *packet = parsed;
    return Status::Ok;
}

Status parseAmsdu(const uint8_t *body, size_t bodyLength,
                  DecodedFrame *parsed)
{
    size_t offset = 0;
    while (offset < bodyLength) {
        if (parsed->packetCount == kMaximumAmsduSubframes)
            return Status::TooManySubframes;

        const size_t remaining = bodyLength - offset;
        if (remaining < 14)
            return Status::InvalidAmsdu;

        const uint8_t *subframe = body + offset;
        const size_t subframeBodyLength = readBe16(subframe + 12);
        if (subframeBodyLength > remaining - 14)
            return Status::InvalidAmsdu;
        if (!isNonzeroAddress(subframe) ||
            !isUnicastAddress(subframe + 6))
            return Status::InvalidAddress;

        PacketView packet = {};
        const Status payloadStatus = decodeAwdlPayload(
            subframe + 14, subframeBodyLength, subframe, subframe + 6,
            &packet);
        if (payloadStatus != Status::Ok)
            return payloadStatus;
        parsed->packets[parsed->packetCount++] = packet;

        const size_t consumed = 14 + subframeBodyLength;
        offset += consumed;
        if (offset == bodyLength)
            break;

        const size_t padding = (4 - (consumed & 3)) & 3;
        if (padding >= bodyLength - offset)
            return Status::InvalidAmsdu;
        offset += padding;
    }

    return parsed->packetCount == 0 ? Status::InvalidAmsdu : Status::Ok;
}

} // namespace

Status encodeIpv6DataMpdu(const EncodeInput *input, uint8_t *output,
                          size_t capacity, size_t *written)
{
    if (!input || !output || !written)
        return Status::InvalidArgument;
    if (!isNonzeroAddress(input->destinationAddress) ||
        !isUnicastAddress(input->sourceAddress))
        return Status::InvalidAddress;
    if (input->wifiSequenceNumber > 0x0fff)
        return Status::InvalidSequence;

    const Status ipv6Status =
        validateIpv6Packet(input->ipv6Packet, input->ipv6Length);
    if (ipv6Status != Status::Ok)
        return ipv6Status;

    if (input->ipv6Length > static_cast<size_t>(-1) -
                                 kUnaggregatedPrefixLength)
        return Status::InvalidLength;
    const size_t frameLength = kUnaggregatedPrefixLength + input->ipv6Length;
    if (capacity < frameLength)
        return Status::BufferTooSmall;

    // All validation is complete. The remaining writes cannot fail, preserving
    // the byte-for-byte unchanged output guarantee for every error path.
    output[0] = static_cast<uint8_t>(kDataFrameType | kDataSubtype);
    output[1] = 0;
    output[2] = 0;
    output[3] = 0;
    memcpy(output + 4, input->destinationAddress, 6);
    memcpy(output + 10, input->sourceAddress, 6);
    memcpy(output + 16, kAwdlBssid, sizeof(kAwdlBssid));
    putLe16(output + 22,
            static_cast<uint16_t>(input->wifiSequenceNumber << 4));

    size_t offset = kMacHeaderLength;
    memcpy(output + offset, kSnapPrefix, sizeof(kSnapPrefix));
    output[offset + 6] = 0x08;
    output[offset + 7] = 0x00;
    offset += kSnapHeaderLength;
    memcpy(output + offset, kAwdlHeadLittleEndian,
           sizeof(kAwdlHeadLittleEndian));
    putLe16(output + offset + 2, input->awdlSequenceNumber);
    memcpy(output + offset + 4, kAwdlPadLittleEndian,
           sizeof(kAwdlPadLittleEndian));
    output[offset + 6] = 0x86;
    output[offset + 7] = 0xdd;
    offset += kAwdlDataHeaderLength;
    memcpy(output + offset, input->ipv6Packet, input->ipv6Length);
    *written = frameLength;
    return Status::Ok;
}

Status decodeIpv6DataMpdu(const uint8_t *frame, size_t frameLength,
                          DecodedFrame *output)
{
    if (!frame || !output)
        return Status::InvalidArgument;
    if (frameLength < kMacHeaderLength)
        return Status::TruncatedFrame;

    const uint16_t frameControl = readLe16(frame);
    if ((frameControl & kFrameControlVersionMask) != 0 ||
        (frameControl & kFrameControlTypeMask) != kDataFrameType)
        return Status::UnsupportedFrame;

    const uint16_t subtype = frameControl & kFrameControlSubtypeMask;
    const bool qosData = subtype == kQosDataSubtype;
    if (subtype != kDataSubtype && !qosData)
        return Status::UnsupportedFrame;
    if ((frameControl & (kFrameControlToDs | kFrameControlFromDs |
                         kFrameControlOrder)) != 0)
        return Status::UnsupportedFrame;
    if ((frameControl & kFrameControlMoreFragments) != 0)
        return Status::FragmentedFrame;
    if ((frameControl & kFrameControlProtected) != 0)
        return Status::ProtectedFrame;

    if ((readLe16(frame + 22) & 0x000f) != 0)
        return Status::FragmentedFrame;

    if (memcmp(frame + 16, kAwdlBssid, sizeof(kAwdlBssid)) != 0)
        return Status::WrongBssid;
    if (!isNonzeroAddress(frame + 4) || !isUnicastAddress(frame + 10))
        return Status::InvalidAddress;

    DecodedFrame parsed = {};
    parsed.frameControl = frameControl;
    parsed.wifiSequenceNumber = readLe16(frame + 22) >> 4;
    memcpy(parsed.destinationAddress, frame + 4, 6);
    memcpy(parsed.sourceAddress, frame + 10, 6);
    parsed.qosData = qosData ? 1 : 0;

    size_t bodyOffset = kMacHeaderLength;
    if (qosData) {
        if (frameLength - bodyOffset < kQosControlLength)
            return Status::TruncatedFrame;
        parsed.qosControl = readLe16(frame + bodyOffset);
        bodyOffset += kQosControlLength;
        if ((parsed.qosControl & kQosMeshControlPresent) != 0)
            return Status::UnsupportedFrame;
        parsed.amsdu = (parsed.qosControl & kQosAmsduPresent) != 0 ? 1 : 0;
    }

    const uint8_t *body = frame + bodyOffset;
    const size_t bodyLength = frameLength - bodyOffset;
    if (parsed.amsdu) {
        const Status status = parseAmsdu(body, bodyLength, &parsed);
        if (status != Status::Ok)
            return status;
    } else {
        PacketView packet = {};
        const Status status = decodeAwdlPayload(
            body, bodyLength, parsed.destinationAddress,
            parsed.sourceAddress, &packet);
        if (status != Status::Ok)
            return status;
        parsed.packets[0] = packet;
        parsed.packetCount = 1;
    }

    *output = parsed;
    return Status::Ok;
}

bool isAwdlDataCandidate(const uint8_t *frame, size_t frameLength)
{
    // This is deliberately a header-only discriminator. Protected frames are
    // still candidates because the MAC header/BSSID remain visible; callers
    // must not interpret this as a successfully decoded AWDL data frame.
    if (!frame || frameLength < kMacHeaderLength)
        return false;

    const uint16_t frameControl = readLe16(frame);
    const uint16_t subtype = frameControl & kFrameControlSubtypeMask;
    if ((frameControl & kFrameControlVersionMask) != 0 ||
        (frameControl & kFrameControlTypeMask) != kDataFrameType ||
        (subtype != kDataSubtype && subtype != kQosDataSubtype) ||
        (frameControl & (kFrameControlToDs | kFrameControlFromDs)) != 0 ||
        (subtype == kQosDataSubtype && frameLength <
            kMacHeaderLength + kQosControlLength))
        return false;

    return memcmp(frame + 16, kAwdlBssid, sizeof(kAwdlBssid)) == 0;
}

} // namespace NativeAwdlData
