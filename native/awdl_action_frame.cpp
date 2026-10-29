// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_action_frame.hpp"

#include <string.h>

namespace NativeAwdl {
namespace {

constexpr size_t kMacHeaderLength = kActionMacHeaderLength;
constexpr size_t kHtControlLength = kActionHtControlLength;
constexpr uint8_t kMaximumTlvs = 128;

constexpr uint32_t kRequiredPsfTypes[] = {4, 5, 18, 24, 6, 7, 12, 21};
constexpr uint32_t kRequiredMifTypes[] = {4, 5, 18, 24, 6, 7, 16, 12, 21};

uint16_t readLe16(const uint8_t *p)
{
    return static_cast<uint16_t>(p[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

uint32_t readLe32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool allZero(const uint8_t *p, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

bool validateChannelSequence(const uint8_t *value, size_t length,
                             size_t trailingPadding)
{
    if (length < 6 + trailingPadding)
        return false;

    const uint8_t count = value[0];
    const uint8_t encoding = value[1];
    const uint8_t duplicateCount = value[2];
    const uint8_t stepCount = value[3];
    const uint16_t fillChannel = readLe16(value + 4);

    size_t bytesPerSlot = 0;
    switch (encoding) {
        case 0: bytesPerSlot = 1; break;
        case 1:
        case 3: bytesPerSlot = 2; break;
        default: return false;
    }

    // The wire protocol describes 16 slots; count is encoded as N - 1.
    if (count != 15 || duplicateCount != 0 || stepCount != 3 ||
        fillChannel != 0xffff)
        return false;

    const size_t expected = 6 + 16 * bytesPerSlot + trailingPadding;
    if (length != expected)
        return false;

    return trailingPadding == 0 || allZero(value + expected - trailingPadding,
                                            trailingPadding);
}

void setDataPathStage(ParseDiagnostics *diagnostics,
                      DataPathRejectStage stage, size_t offset)
{
    if (!diagnostics)
        return;
    diagnostics->dataPathRejectStage = stage;
    diagnostics->dataPathOffset = static_cast<uint16_t>(offset);
}

bool consumeDataPathField(size_t valueLength, size_t *offset, size_t fieldLength,
                          ParseDiagnostics *diagnostics,
                          DataPathRejectStage stage)
{
    if (*offset > valueLength || fieldLength > valueLength - *offset) {
        setDataPathStage(diagnostics, stage, *offset);
        return false;
    }
    *offset += fieldLength;
    setDataPathStage(diagnostics, DataPathRejectStage::None, *offset);
    return true;
}

bool validateDataPathState(const uint8_t *value, size_t length,
                           ParseDiagnostics *diagnostics)
{
    size_t offset = 0;
    if (length < 2) {
        setDataPathStage(diagnostics, DataPathRejectStage::Flags, offset);
        return false;
    }

    const uint16_t flags = readLe16(value);
    offset += 2;
    if (diagnostics) {
        diagnostics->dataPathFlags = flags;
        diagnostics->dataPathFlagsPresent = 1;
    }
    setDataPathStage(diagnostics, DataPathRejectStage::None, offset);

    // Field order and lengths follow the Wireshark AWDL Data Path State
    // dissector. Capability bits with no associated payload only affect the
    // flags word. No field bytes are copied or interpreted as addresses.
    if ((flags & 0x0100) &&
        !consumeDataPathField(length, &offset, 3, diagnostics,
                              DataPathRejectStage::CountryCode))
        return false;
    if ((flags & 0x0200) &&
        !consumeDataPathField(length, &offset, 2, diagnostics,
                              DataPathRejectStage::SocialChannels))
        return false;
    if ((flags & 0x0001) &&
        !consumeDataPathField(length, &offset, 8, diagnostics,
                              DataPathRejectStage::InfrastructureInfo))
        return false;
    if ((flags & 0x0002) &&
        !consumeDataPathField(length, &offset, 6, diagnostics,
                              DataPathRejectStage::InfrastructureAddress))
        return false;
    if ((flags & 0x0004) &&
        !consumeDataPathField(length, &offset, 6, diagnostics,
                              DataPathRejectStage::AwdlAddress))
        return false;
    if ((flags & 0x0010) &&
        !consumeDataPathField(length, &offset, 2, diagnostics,
                              DataPathRejectStage::Umi))
        return false;

    if (flags & 0x1000) {
        if (offset > length || length - offset < 2) {
            setDataPathStage(diagnostics, DataPathRejectStage::OptionsLength,
                             offset);
            return false;
        }
        const uint16_t optionsLength = readLe16(value + offset);
        offset += 2;
        if (diagnostics) {
            diagnostics->dataPathOptionsLength = optionsLength;
            diagnostics->dataPathOptionsLengthPresent = 1;
        }
        setDataPathStage(diagnostics, DataPathRejectStage::None, offset);
        if (optionsLength > length - offset) {
            setDataPathStage(diagnostics, DataPathRejectStage::OptionsData,
                             offset);
            return false;
        }
        offset += optionsLength;
        setDataPathStage(diagnostics, DataPathRejectStage::None, offset);
    }

    if (flags & 0x8000) {
        if (offset > length || length - offset < 2) {
            setDataPathStage(diagnostics, DataPathRejectStage::ExtendedFlags,
                             offset);
            return false;
        }
        const uint16_t extFlags = readLe16(value + offset);
        offset += 2;
        if (diagnostics) {
            diagnostics->dataPathExtFlags = extFlags;
            diagnostics->dataPathExtFlagsPresent = 1;
        }
        setDataPathStage(diagnostics, DataPathRejectStage::None, offset);

        // Wireshark labels 0x20 "Misc" and describes it as indicating that
        // the RLFC and active-time/counter fields are present. Those bytes
        // remain selected and consumed by 0x04 and 0x40 below; 0x20 itself is
        // a recognized marker and selects no additional payload. Keep
        // rejecting bits with no protocol name/contract (0x80, 0xc000).
        constexpr uint16_t knownExtensionFlags = 0x3f7f;
        if (extFlags & static_cast<uint16_t>(~knownExtensionFlags)) {
            setDataPathStage(diagnostics,
                             DataPathRejectStage::UnsupportedExtFlags, offset);
            return false;
        }
        if ((extFlags & 0x0001) &&
            !consumeDataPathField(length, &offset, 2, diagnostics,
                                  DataPathRejectStage::LogTrigger))
            return false;
        if ((extFlags & 0x0004) &&
            !consumeDataPathField(length, &offset, 4, diagnostics,
                                  DataPathRejectStage::Rlfc))
            return false;
        if ((extFlags & 0x0040) &&
            !consumeDataPathField(length, &offset, 12, diagnostics,
                                  DataPathRejectStage::ActiveTimeCounters))
            return false;
    }

    if (offset != length) {
        // Owly's type-12 layout also documents a trailing two-byte reserved
        // extension word. Accept only the exact zero-valued form when the
        // extension-flags-present bit was not set; nonzero data stays closed.
        if ((flags & 0x8000) || length - offset != 2 ||
            readLe16(value + offset) != 0) {
            setDataPathStage(diagnostics, DataPathRejectStage::TrailingBytes,
                             offset);
            return false;
        }
        offset += 2;
    }
    setDataPathStage(diagnostics, DataPathRejectStage::None, offset);
    return true;
}

bool validateTlvValue(uint8_t type, const uint8_t *value, size_t length,
                      ParseDiagnostics *diagnostics)
{
    switch (type) {
        case 4: // Synchronization parameters; the parser consumes fields 0..30.
            return length >= 31;
        case 5: // Election parameters including the two reserved pad bytes.
            return length == 21;
        case 6: { // Service parameters: 3-byte header + SUI + bitmask + values.
            if (length < 9)
                return false;
            const uint32_t valueMask = readLe32(value + 5);
            uint32_t remaining = valueMask;
            size_t valueCount = 0;
            while (remaining != 0) {
                remaining &= remaining - 1;
                ++valueCount;
            }
            // One encoded value byte follows for each set bit in the mask.
            // The enclosing TLV boundary is checked before this helper runs.
            return length == 9 + valueCount;
        }
        case 7: // HT capabilities: fixed fields, an MCS mask, two trailing bytes.
            return length >= 8;
        case 12: // Data Path State; validate every flag-selected field boundary.
            return validateDataPathState(value, length, diagnostics);
        case 16: { // ARPA name: flags, length, name bytes, compressed suffix.
            if (length < 4 || value[0] != 3)
                return false;
            const size_t nameLength = value[1];
            if (length != nameLength + 4)
                return false;
            return value[2 + nameLength] == 0xc0 &&
                   value[3 + nameLength] == 0x0c;
        }
        case 17:
            // The container is opaque here; its bounded outer TLV length was
            // checked by parseActionFrame, so skip it without decoding it.
            return true;
        case 18: // Channel sequence; three zero pad bytes follow the slots.
            return validateChannelSequence(value, length, 3);
        case 21: // AWDL version and device class.
            return length == 2;
        case 24: // Election parameters v2.
            return length == 40;
        default:
            // Other and future TLVs are opaque; their outer length is checked
            // before they can be skipped.
            return true;
    }
}

int requiredTypeIndex(uint8_t subtype, uint8_t type)
{
    const uint32_t *required = subtype == 3 ? kRequiredMifTypes : kRequiredPsfTypes;
    const size_t count = subtype == 3
        ? sizeof(kRequiredMifTypes) / sizeof(kRequiredMifTypes[0])
        : sizeof(kRequiredPsfTypes) / sizeof(kRequiredPsfTypes[0]);
    for (size_t i = 0; i < count; ++i) {
        if (required[i] == type)
            return static_cast<int>(i);
    }
    return -1;
}

uint16_t requiredTypeMask(uint8_t subtype)
{
    const uint32_t *required = subtype == 3 ? kRequiredMifTypes : kRequiredPsfTypes;
    const size_t count = subtype == 3
        ? sizeof(kRequiredMifTypes) / sizeof(kRequiredMifTypes[0])
        : sizeof(kRequiredPsfTypes) / sizeof(kRequiredPsfTypes[0]);
    uint16_t mask = 0;
    for (size_t i = 0; i < count; ++i) {
        // Election Parameters v2 is an optional capability advertisement;
        // type 5 remains required, and this parser does not accept v2-only.
        if (required[i] != 24)
            mask |= static_cast<uint16_t>(1u << i);
    }
    return mask;
}

uint8_t firstMissingRequiredType(uint8_t subtype, uint16_t seenMask,
                                 uint16_t requiredMask)
{
    const uint32_t *required = subtype == 3 ? kRequiredMifTypes : kRequiredPsfTypes;
    const size_t count = subtype == 3
        ? sizeof(kRequiredMifTypes) / sizeof(kRequiredMifTypes[0])
        : sizeof(kRequiredPsfTypes) / sizeof(kRequiredPsfTypes[0]);
    for (size_t i = 0; i < count; ++i) {
        const uint16_t bit = static_cast<uint16_t>(1u << i);
        if ((requiredMask & bit) == 0)
            continue;
        if ((seenMask & bit) == 0)
            return static_cast<uint8_t>(required[i]);
    }
    return 0xff;
}

void clearDiagnostics(ParseDiagnostics *diagnostics)
{
    if (!diagnostics)
        return;
    memset(diagnostics, 0, sizeof(*diagnostics));
    diagnostics->tlvType = 0xff;
    diagnostics->expectedType = 0xff;
    diagnostics->dataPathRejectStage = DataPathRejectStage::None;
}

void appendTlvTypeTrace(ParseDiagnostics *diagnostics, uint8_t type)
{
    if (!diagnostics)
        return;
    const uint16_t index = diagnostics->traceCount;
    if (index < 8) {
        diagnostics->tlvTypeTraceLo |=
            static_cast<uint64_t>(type) << (index * 8);
    } else if (index < 16) {
        diagnostics->tlvTypeTraceHi |=
            static_cast<uint64_t>(type) << ((index - 8) * 8);
    }
    ++diagnostics->traceCount;
}

void traceTlvHeaders(const uint8_t *frame, size_t length, size_t tlvStart,
                     ParseDiagnostics *diagnostics)
{
    if (!diagnostics)
        return;
    size_t offset = tlvStart;
    uint8_t count = 0;
    while (offset < length && count < kMaximumTlvs) {
        const size_t remaining = length - offset;
        if (remaining < 3)
            break;
        const uint8_t type = frame[offset];
        const size_t valueLength = readLe16(frame + offset + 1);
        const size_t availableLength = remaining - 3;
        appendTlvTypeTrace(diagnostics, type);
        ++count;
        if (valueLength > availableLength)
            break;
        offset += 3 + valueLength;
    }
}

void setTlvDiagnostics(ParseDiagnostics *diagnostics,
                       TlvRejectReason reason, uint8_t subtype,
                       uint8_t tlvType, uint8_t expectedType,
                       size_t tlvOffset, size_t declaredLen,
                       size_t availableLen, uint16_t seenMask,
                       uint16_t requiredMask)
{
    if (!diagnostics)
        return;
    diagnostics->reason = reason;
    diagnostics->subtype = subtype;
    diagnostics->tlvType = tlvType;
    diagnostics->expectedType = expectedType;
    diagnostics->tlvOffset = tlvOffset;
    diagnostics->declaredLen = declaredLen;
    diagnostics->availableLen = availableLen;
    diagnostics->seenMask = seenMask;
    diagnostics->requiredMask = requiredMask;
}

} // namespace

ParseStatus parseActionFrame(const uint8_t *frame, size_t length,
                             ActionFrameInfo *out,
                             ParseDiagnostics *diagnostics)
{
    clearDiagnostics(diagnostics);
    if (!out)
        return ParseStatus::InvalidArgument;
    memset(out, 0, sizeof(*out));
    if (!frame)
        return ParseStatus::InvalidArgument;
    if (length < 2)
        return ParseStatus::TruncatedFrame;

    const uint16_t frameControl = readLe16(frame);
    const uint8_t version = static_cast<uint8_t>(frameControl & 0x3);
    const uint8_t type = static_cast<uint8_t>((frameControl >> 2) & 0x3);
    const uint8_t subtype = static_cast<uint8_t>((frameControl >> 4) & 0xf);
    if (type != 0 || subtype != 13)
        return ParseStatus::NotManagementAction;
    if (version != 0 || (frameControl & 0x0300))
        return ParseStatus::Invalid80211Header;
    if (length < kMacHeaderLength)
        return ParseStatus::TruncatedFrame;
    if (frameControl & 0x4000)
        return ParseStatus::ProtectedAction;

    const size_t macHeaderLength = kMacHeaderLength +
        ((frameControl & 0x8000) ? kHtControlLength : 0);
    if (length < macHeaderLength + kAwdlActionHeaderLength)
        return ParseStatus::TruncatedFrame;

    const uint8_t *body = frame + macHeaderLength;
    if (body[0] != 127 || body[1] != 0x00 || body[2] != 0x17 ||
        body[3] != 0xf2 || body[4] != 8 || body[5] != 0x10 ||
        (body[6] != 0 && body[6] != 3))
        return ParseStatus::NotAwdlAction;
    if (body[7] != 0)
        return ParseStatus::InvalidAwdlHeader;

    const uint8_t awdlSubtype = body[6];
    const size_t tlvStart = macHeaderLength + kAwdlActionHeaderLength;
    size_t offset = tlvStart;
    uint8_t tlvCount = 0;
    const uint16_t requiredMask = requiredTypeMask(awdlSubtype);
    uint16_t seenMask = 0;
    if (diagnostics) {
        diagnostics->subtype = awdlSubtype;
        diagnostics->requiredMask = requiredMask;
        // Snapshot the bounded header trajectory before semantic validation,
        // so the first bad value/order cannot hide later well-bounded types.
        traceTlvHeaders(frame, length, tlvStart, diagnostics);
    }

    while (offset < length) {
        const size_t remaining = length - offset;
        if (remaining < 3) {
            if (allZero(frame + offset, remaining))
                break;
            return ParseStatus::InvalidPadding;
        }
        if (tlvCount >= kMaximumTlvs)
            return ParseStatus::TooManyTlvs;

        const uint8_t tlvType = frame[offset];
        const size_t valueLength = readLe16(frame + offset + 1);
        const size_t valueOffset = offset + 3;
        const size_t availableLength = length - valueOffset;
        const uint8_t expectedType = firstMissingRequiredType(awdlSubtype,
                                                               seenMask,
                                                               requiredMask);
        if (valueLength > availableLength) {
            setTlvDiagnostics(diagnostics, TlvRejectReason::LengthOverrun,
                              awdlSubtype, tlvType, expectedType, offset,
                              valueLength, availableLength, seenMask,
                              requiredMask);
            return ParseStatus::InvalidTlv;
        }

        const int index = requiredTypeIndex(awdlSubtype, tlvType);
        if (tlvType == 16 && awdlSubtype != 3) {
            setTlvDiagnostics(diagnostics, TlvRejectReason::ArpaInPsf,
                              awdlSubtype, tlvType, expectedType, offset,
                              valueLength, availableLength, seenMask,
                              requiredMask);
            return ParseStatus::InvalidTlv;
        }
        if (index >= 0) {
            const uint16_t bit = static_cast<uint16_t>(1u << index);
            if (seenMask & bit) {
                setTlvDiagnostics(diagnostics,
                                  TlvRejectReason::DuplicateRequired,
                                  awdlSubtype, tlvType,
                                  expectedType, offset, valueLength,
                                  availableLength, seenMask, requiredMask);
                return ParseStatus::InvalidTlv;
            }
            seenMask |= bit;
        }
        setTlvDiagnostics(diagnostics, TlvRejectReason::None, awdlSubtype,
                          tlvType, expectedType, offset, valueLength,
                          availableLength, seenMask, requiredMask);
        if (!validateTlvValue(tlvType, frame + valueOffset, valueLength,
                              diagnostics)) {
            setTlvDiagnostics(diagnostics, TlvRejectReason::InvalidValue,
                              awdlSubtype, tlvType, expectedType, offset,
                              valueLength, availableLength, seenMask,
                              requiredMask);
            return ParseStatus::InvalidTlvValue;
        }

        ++tlvCount;
        offset = valueOffset + valueLength;
    }

    if (tlvCount == 0 || (seenMask & requiredMask) != requiredMask) {
        const TlvRejectReason reason = tlvCount == 0
            ? TlvRejectReason::EmptyList
            : TlvRejectReason::MissingRequired;
        const uint8_t expectedType = firstMissingRequiredType(awdlSubtype,
                                                               seenMask,
                                                               requiredMask);
        setTlvDiagnostics(diagnostics, reason, awdlSubtype, 0xff,
                          expectedType, length, 0, 0, seenMask,
                          requiredMask);
        return ParseStatus::InvalidTlv;
    }

    out->frameControl = frameControl;
    out->phyTx = readLe32(body + 8);
    out->targetTx = readLe32(body + 12);
    out->subtype = awdlSubtype;
    out->version = body[5];
    out->tlvCount = tlvCount;
    return ParseStatus::Ok;
}

} // namespace NativeAwdl
