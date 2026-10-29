// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_mif_encode.hpp"

#include "awdl_action_frame.hpp"

#include <string.h>

namespace NativeAwdl {
namespace {

constexpr size_t kTlvStart = kActionMacHeaderLength + kAwdlActionHeaderLength;
constexpr size_t kAwdlSubtypeOffset = kActionMacHeaderLength + 6;
constexpr uint8_t kArpaTlvType = 16;
constexpr uint8_t kArpaFlags = 3;
constexpr uint8_t kLocalSuffixPointer[] = {0xc0, 0x0c};

bool isAsciiAlphaNumeric(uint8_t value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9');
}

bool isValidHostname(const char *hostname, size_t length)
{
    if (!hostname || length == 0 || length > kMaximumArpaHostLabelLength)
        return false;
    if (!isAsciiAlphaNumeric(static_cast<uint8_t>(hostname[0])) ||
        !isAsciiAlphaNumeric(static_cast<uint8_t>(hostname[length - 1])))
        return false;

    for (size_t i = 0; i < length; ++i) {
        const uint8_t value = static_cast<uint8_t>(hostname[i]);
        if (!isAsciiAlphaNumeric(value) && value != '-')
            return false;
    }
    return true;
}

MifEncodeStatus mapPsfStatus(EncodeStatus status)
{
    switch (status) {
        case EncodeStatus::Ok: return MifEncodeStatus::Ok;
        case EncodeStatus::InvalidArgument:
            return MifEncodeStatus::InvalidArgument;
        case EncodeStatus::InvalidSourceAddress:
            return MifEncodeStatus::InvalidSourceAddress;
        case EncodeStatus::InvalidElectionAddress:
            return MifEncodeStatus::InvalidElectionAddress;
        case EncodeStatus::InvalidChannelSequence:
            return MifEncodeStatus::InvalidChannelSequence;
        case EncodeStatus::InvalidSyncFields:
            return MifEncodeStatus::InvalidSyncFields;
        case EncodeStatus::InvalidElectionFields:
            return MifEncodeStatus::InvalidElectionFields;
        case EncodeStatus::InvalidHtCapabilities:
            return MifEncodeStatus::InvalidHtCapabilities;
        case EncodeStatus::InvalidVersion:
            return MifEncodeStatus::InvalidVersion;
        case EncodeStatus::BufferTooSmall:
            return MifEncodeStatus::BufferTooSmall;
    }
    return MifEncodeStatus::InvalidArgument;
}

uint16_t readLe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

void putLe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

// Locate one of the two supported Data Path State TLVs after HT capabilities.
// parseActionFrame has validated the bounded field shape; this walk additionally
// restricts the MIF encoder to legacy-empty or exact Addr2-advertisement form.
bool findArpaInsertionPoint(const uint8_t *frame, size_t length,
                           size_t *insertionOffset)
{
    if (!frame || !insertionOffset || length < kTlvStart)
        return false;

    size_t offset = kTlvStart;
    bool sawHtCapabilities = false;
    while (offset < length) {
        const size_t remaining = length - offset;
        if (remaining < 3)
            return false;

        const size_t valueLength = readLe16(frame + offset + 1);
        if (valueLength > remaining - 3)
            return false;

        if (frame[offset] == 7)
            sawHtCapabilities = true;
        if (frame[offset] == 12) {
            if (!sawHtCapabilities ||
                !detail::isSupportedMifDataPathTlv(frame, length, offset))
                return false;
            *insertionOffset = offset;
            return true;
        }
        offset += 3 + valueLength;
    }
    return false;
}

} // namespace

bool detail::isSupportedMifDataPathTlv(const uint8_t *frame, size_t length,
                                       size_t tlvOffset)
{
    if (!frame || length < kActionMacHeaderLength || tlvOffset > length ||
        length - tlvOffset < 3 || frame[tlvOffset] != 12)
        return false;
    const size_t valueLength = readLe16(frame + tlvOffset + 1);
    if (valueLength > length - tlvOffset - 3 || valueLength < 2)
        return false;

    const uint16_t flags = readLe16(frame + tlvOffset + 3);
    if (valueLength == 2 && flags == 0)
        return true;
    return valueLength == 8 && flags == 0x0004 &&
           memcmp(frame + tlvOffset + 5, frame + 10, 6) == 0;
}

MifEncodeStatus encodeMif(const MifInput *input, uint8_t *output,
                          size_t capacity, size_t *written)
{
    if (written)
        *written = 0;
    if (!input || !output || !written)
        return MifEncodeStatus::InvalidArgument;
    if (!isValidHostname(input->hostname, input->hostnameLength))
        return MifEncodeStatus::InvalidHostname;

    uint8_t psf[kMaximumEncodedPsfLength] = {};
    size_t psfLength = 0;
    const MifEncodeStatus psfStatus =
        mapPsfStatus(encodePsf(&input->psf, psf, sizeof(psf), &psfLength));
    if (psfStatus != MifEncodeStatus::Ok)
        return psfStatus;

    ActionFrameInfo psfInfo = {};
    if (parseActionFrame(psf, psfLength, &psfInfo) != ParseStatus::Ok ||
        psfInfo.subtype != 0)
        return MifEncodeStatus::InvalidBaseFrame;

    size_t insertionOffset = 0;
    if (!findArpaInsertionPoint(psf, psfLength, &insertionOffset))
        return MifEncodeStatus::InvalidBaseFrame;

    const size_t arpaValueLength = input->hostnameLength + 4;
    const size_t arpaTlvLength = 3 + arpaValueLength;
    const size_t mifLength = psfLength + arpaTlvLength;
    if (mifLength > kMaximumEncodedMifLength)
        return MifEncodeStatus::InvalidBaseFrame;

    uint8_t frame[kMaximumEncodedMifLength] = {};
    memcpy(frame, psf, insertionOffset);

    size_t offset = insertionOffset;
    frame[offset++] = kArpaTlvType;
    putLe16(frame + offset, static_cast<uint16_t>(arpaValueLength));
    offset += 2;
    frame[offset++] = kArpaFlags;
    frame[offset++] = static_cast<uint8_t>(input->hostnameLength);
    memcpy(frame + offset, input->hostname, input->hostnameLength);
    offset += input->hostnameLength;
    memcpy(frame + offset, kLocalSuffixPointer, sizeof(kLocalSuffixPointer));
    offset += sizeof(kLocalSuffixPointer);
    memcpy(frame + offset, psf + insertionOffset, psfLength - insertionOffset);
    offset += psfLength - insertionOffset;
    frame[kAwdlSubtypeOffset] = 3;

    ActionFrameInfo mifInfo = {};
    if (offset != mifLength ||
        parseActionFrame(frame, mifLength, &mifInfo) != ParseStatus::Ok ||
        mifInfo.subtype != 3 || mifInfo.tlvCount != psfInfo.tlvCount + 1)
        return MifEncodeStatus::InvalidBaseFrame;

    if (capacity < mifLength)
        return MifEncodeStatus::BufferTooSmall;

    memcpy(output, frame, mifLength);
    *written = mifLength;
    return MifEncodeStatus::Ok;
}

} // namespace NativeAwdl
