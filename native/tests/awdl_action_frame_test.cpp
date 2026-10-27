// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_frame.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>

using NativeAwdl::ActionFrameInfo;
using NativeAwdl::DataPathRejectStage;
using NativeAwdl::ParseDiagnostics;
using NativeAwdl::ParseStatus;
using NativeAwdl::TlvRejectReason;

static void appendTlv(std::vector<uint8_t> &frame, uint8_t type,
                      const std::vector<uint8_t> &value)
{
    assert(value.size() <= 0xffff);
    frame.push_back(type);
    frame.push_back(static_cast<uint8_t>(value.size()));
    frame.push_back(static_cast<uint8_t>(value.size() >> 8));
    frame.insert(frame.end(), value.begin(), value.end());
}

static std::vector<uint8_t> zeros(size_t length)
{
    return std::vector<uint8_t>(length, 0);
}

static std::vector<uint8_t> legacyDataPathState()
{
    // Fresh synthetic legacy layout: flags, X0 country, one social channel,
    // an AWDL MAC, and a zero-valued Extension Flags word.
    return {0x24, 0x8f, 'X', '0', 0, 0x01, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
}

static std::vector<uint8_t> extendedDataPathState47()
{
    // Synthetic only: known base fields plus the Wireshark-defined 0x1, 0x4,
    // and 0x40 extension payloads. This length-compatible fixture is not a
    // reconstruction of Test038's uncaptured value bytes or flags.
    std::vector<uint8_t> value = {0x07, 0x83, 'U', 'S', 0,
                                  0x07, 0x00}; // flags 0x8307
    value.insert(value.end(), 8, 0);  // infrastructure BSSID and channel
    value.insert(value.end(), 6, 0);  // infrastructure address
    value.insert(value.end(), 6, 0);  // AWDL address
    value.insert(value.end(), {0x45, 0x00}); // extension flags 0x0045
    value.insert(value.end(), 2, 0);  // logtrigger ID
    value.insert(value.end(), 4, 0);  // RLFC
    value.insert(value.end(), 12, 0); // active time and counters
    assert(value.size() == 47);
    return value;
}

static std::vector<uint8_t> syntheticTest039NumericHeaderDataPath()
{
    // Synthetic reconstruction from Test039's numeric header only. The
    // reported value length (47), flags (0x9f23), options length (4),
    // extension flags (0x197d), and selected-field lengths are reproduced;
    // none of the original captured field bytes are available or replayed.
    std::vector<uint8_t> value = {0x23, 0x9f}; // base flags 0x9f23
    value.insert(value.end(), {'U', 'S', 0}); // country code (0x0100)
    value.insert(value.end(), {0x06, 0x00}); // social channel map (0x0200)
    value.insert(value.end(), 8, 0); // infrastructure BSSID and channel (0x0001)
    value.insert(value.end(), 6, 0); // infrastructure address (0x0002)
    value.insert(value.end(), {0x04, 0x00}); // unicast options length (0x1000)
    value.insert(value.end(), {0xa1, 0xb2, 0xc3, 0xd4}); // opaque options
    value.insert(value.end(), {0x7d, 0x19}); // extension flags 0x197d
    value.insert(value.end(), 2, 0); // logtrigger ID (0x0001)
    value.insert(value.end(), 4, 0); // RLFC (0x0004)
    value.insert(value.end(), 12, 0); // active time and counters (0x0040)
    assert(value.size() == 47);
    return value;
}

static size_t findTlvOffset(const std::vector<uint8_t> &frame, uint8_t type)
{
    if (frame.size() < 2)
        return frame.size();
    size_t offset = 24 + ((frame[1] & 0x80) ? 4 : 0) + 16;
    while (offset + 3 <= frame.size()) {
        const size_t length = frame[offset + 1] |
            (static_cast<size_t>(frame[offset + 2]) << 8);
        if (length > frame.size() - offset - 3)
            return frame.size();
        if (frame[offset] == type)
            return offset;
        offset += 3 + length;
    }
    return frame.size();
}

static bool replaceTlvValue(std::vector<uint8_t> &frame, uint8_t type,
                            const std::vector<uint8_t> &value)
{
    const size_t offset = findTlvOffset(frame, type);
    if (offset == frame.size() || value.size() > 0xffff)
        return false;

    const size_t oldLength = frame[offset + 1] |
        (static_cast<size_t>(frame[offset + 2]) << 8);
    std::vector<uint8_t> replacement = {
        type,
        static_cast<uint8_t>(value.size()),
        static_cast<uint8_t>(value.size() >> 8)
    };
    replacement.insert(replacement.end(), value.begin(), value.end());
    frame.erase(frame.begin() + offset, frame.begin() + offset + 3 + oldLength);
    frame.insert(frame.begin() + offset, replacement.begin(), replacement.end());
    return true;
}

static std::vector<uint8_t> validFrame(uint8_t subtype, bool htc = false,
                                       bool includeContainer = false)
{
    const size_t macHeader = htc ? 28 : 24;
    std::vector<uint8_t> frame(macHeader, 0);
    frame[0] = 0xd0; // Management Action.
    if (htc)
        frame[1] = 0x80; // Order bit: four-byte HT Control follows the MAC header.

    const uint8_t actionHeader[] = {
        127, 0x00, 0x17, 0xf2, 8, 0x10, subtype, 0,
        0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05
    };
    frame.insert(frame.end(), actionHeader, actionHeader + sizeof(actionHeader));

    appendTlv(frame, 4, zeros(31));
    appendTlv(frame, 5, zeros(21));
    std::vector<uint8_t> channelSequence = {15, 0, 0, 3, 0xff, 0xff};
    channelSequence.insert(channelSequence.end(), 16, 6);
    channelSequence.insert(channelSequence.end(), 3, 0);
    appendTlv(frame, 18, channelSequence);
    appendTlv(frame, 24, zeros(40));
    appendTlv(frame, 6, zeros(9));
    appendTlv(frame, 7, zeros(8));
    if (subtype == 3)
        appendTlv(frame, 16, {3, 1, 'h', 0xc0, 0x0c});
    if (includeContainer)
        appendTlv(frame, 17, {0x7f, 0x00, 0xa5, 0x5a});
    appendTlv(frame, 12, {0, 0});
    appendTlv(frame, 21, {0x10, 1});
    return frame;
}

static std::vector<uint8_t> syntheticTest035NumericTrace()
{
    // Synthetic fixture reproducing only the observed numeric trajectory
    // [4, 5, 18, 19, 6] and type-6 declared length 15. Values are generated
    // here; this is not a captured or reconstructed peer frame.
    std::vector<uint8_t> frame(24, 0);
    frame[0] = 0xd0;
    const uint8_t actionHeader[] = {
        127, 0x00, 0x17, 0xf2, 8, 0x10, 0, 0,
        0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05
    };
    frame.insert(frame.end(), actionHeader, actionHeader + sizeof(actionHeader));
    appendTlv(frame, 4, zeros(31));
    appendTlv(frame, 5, zeros(21));
    std::vector<uint8_t> channelSequence = {15, 0, 0, 3, 0xff, 0xff};
    channelSequence.insert(channelSequence.end(), 16, 6);
    channelSequence.insert(channelSequence.end(), 3, 0);
    appendTlv(frame, 18, channelSequence);
    appendTlv(frame, 19, {0xa5, 0x5a}); // Opaque synthetic unknown TLV.
    appendTlv(frame, 6, {0, 0, 0, 0, 0, 0x3f, 0, 0, 0,
                         1, 2, 4, 8, 16, 32}); // 9-byte base + 6 mask values.
    appendTlv(frame, 24, zeros(40));
    appendTlv(frame, 7, zeros(8));
    appendTlv(frame, 12, {0, 0});
    appendTlv(frame, 21, {0x10, 1});
    return frame;
}

static ParseStatus parse(const std::vector<uint8_t> &frame, ActionFrameInfo *out,
                         ParseDiagnostics *diagnostics = nullptr)
{
    return NativeAwdl::parseActionFrame(frame.empty() ? nullptr : frame.data(),
                                         frame.size(), out, diagnostics);
}

static void assertCleared(const ActionFrameInfo &info)
{
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&info);
    for (size_t i = 0; i < sizeof(info); ++i)
        assert(bytes[i] == 0);
}

int main()
{
    ActionFrameInfo info;
    ParseDiagnostics diagnostics{};
    std::vector<uint8_t> psf = validFrame(0);
    assert(parse(psf, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.reason == TlvRejectReason::None);
    assert(info.subtype == 0 && info.version == 0x10 && info.tlvCount == 8);
    assert(info.phyTx == 0x01020304 && info.targetTx == 0x05060708);

    std::vector<uint8_t> mif = validFrame(3, true);
    assert(parse(mif, &info, &diagnostics) == ParseStatus::Ok);
    assert(info.subtype == 3 && info.tlvCount == 9);
    assert(diagnostics.reason == TlvRejectReason::None);
    assert(diagnostics.seenMask == 0x01ff &&
           diagnostics.requiredMask == 0x01f7);
    assert(diagnostics.traceCount == 9 &&
           diagnostics.tlvTypeTraceLo == 0x0c10070618120504ULL &&
           diagnostics.tlvTypeTraceHi == 0x15);

    // InvalidTlv diagnostics identify the exact structural rejection using
    // numeric metadata only; they never copy a TLV value into the result.
    std::vector<uint8_t> invalidTlv = psf;
    const size_t firstTlvOffset = 24 + 16;
    invalidTlv[firstTlvOffset + 1] = 0xff;
    invalidTlv[firstTlvOffset + 2] = 0xff;
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::LengthOverrun);
    assert(diagnostics.subtype == 0 && diagnostics.tlvType == 4);
    assert(diagnostics.expectedType == 4 &&
           diagnostics.tlvOffset == firstTlvOffset);
    assert(diagnostics.declaredLen == 0xffff &&
           diagnostics.availableLen == invalidTlv.size() - firstTlvOffset - 3);
    assert(diagnostics.seenMask == 0 && diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 1 && diagnostics.tlvTypeTraceLo == 4 &&
           diagnostics.tlvTypeTraceHi == 0);
    assertCleared(info);

    invalidTlv = psf;
    appendTlv(invalidTlv, 16, {3, 1, 'x', 0xc0, 0x0c});
    const size_t arpaPsfOffset = psf.size();
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::ArpaInPsf);
    assert(diagnostics.subtype == 0 && diagnostics.tlvType == 16 &&
           diagnostics.expectedType == 0xff);
    assert(diagnostics.tlvOffset == arpaPsfOffset &&
           diagnostics.declaredLen == 5 && diagnostics.availableLen == 5);
    assert(diagnostics.seenMask == 0x00ff &&
           diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 9 &&
           (diagnostics.tlvTypeTraceHi & 0xff) == 16);
    assertCleared(info);

    std::vector<uint8_t> test035 = syntheticTest035NumericTrace();
    assert(parse(test035, &info, &diagnostics) == ParseStatus::Ok);
    assert(info.subtype == 0 && info.tlvCount == 9);
    assert(diagnostics.reason == TlvRejectReason::None);
    assert(diagnostics.seenMask == 0x00ff &&
           diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 9 &&
           diagnostics.tlvTypeTraceLo == 0x0c07180613120504ULL &&
           diagnostics.tlvTypeTraceHi == 0x15);

    invalidTlv = psf;
    const size_t secondTlvOffset = firstTlvOffset + 3 + 31;
    invalidTlv[secondTlvOffset] = 4; // Duplicate required type 4.
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::DuplicateRequired);
    assert(diagnostics.tlvType == 4 && diagnostics.expectedType == 5 &&
           diagnostics.seenMask == 0x0001 &&
           diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 8 &&
           diagnostics.tlvTypeTraceLo == 0x150c070618120404ULL);
    assertCleared(info);

    invalidTlv = psf;
    const size_t versionOffset = findTlvOffset(invalidTlv, 21);
    assert(versionOffset < invalidTlv.size());
    invalidTlv.erase(invalidTlv.begin() + versionOffset,
                     invalidTlv.begin() + versionOffset + 5);
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::MissingRequired);
    assert(diagnostics.subtype == 0 && diagnostics.tlvType == 0xff &&
           diagnostics.expectedType == 21);
    assert(diagnostics.tlvOffset == invalidTlv.size() &&
           diagnostics.declaredLen == 0 && diagnostics.availableLen == 0);
    assert(diagnostics.seenMask == 0x007f &&
           diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 7);
    assertCleared(info);

    // Type 24 is optional when the peer advertises v1 election parameters.
    invalidTlv = psf;
    const size_t electionV2Offset = findTlvOffset(invalidTlv, 24);
    assert(electionV2Offset < invalidTlv.size());
    invalidTlv.erase(invalidTlv.begin() + electionV2Offset,
                     invalidTlv.begin() + electionV2Offset + 43);
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.reason == TlvRejectReason::None);
    assert(diagnostics.seenMask == 0x00f7 &&
           diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 7);

    // This implementation retains the v1 requirement; v2-only peers are not
    // claimed as supported just because type 24 is valid in isolation.
    invalidTlv = psf;
    const size_t electionV1Offset = findTlvOffset(invalidTlv, 5);
    assert(electionV1Offset < invalidTlv.size());
    invalidTlv.erase(invalidTlv.begin() + electionV1Offset,
                     invalidTlv.begin() + electionV1Offset + 24);
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::MissingRequired);
    assert(diagnostics.expectedType == 5 && diagnostics.seenMask == 0x00fd &&
           diagnostics.requiredMask == 0x00f7);

    std::vector<uint8_t> malformedElectionV2 = psf;
    assert(replaceTlvValue(malformedElectionV2, 24, zeros(39)));
    assert(parse(malformedElectionV2, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.reason == TlvRejectReason::InvalidValue &&
           diagnostics.tlvType == 24 && diagnostics.declaredLen == 39 &&
           diagnostics.requiredMask == 0x00f7);

    std::vector<uint8_t> duplicateElectionV2 = psf;
    appendTlv(duplicateElectionV2, 24, zeros(40));
    assert(parse(duplicateElectionV2, &info, &diagnostics) ==
           ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::DuplicateRequired &&
           diagnostics.tlvType == 24 && diagnostics.requiredMask == 0x00f7);

    invalidTlv = psf;
    invalidTlv.resize(24 + 16);
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlv);
    assert(diagnostics.reason == TlvRejectReason::EmptyList);
    assert(diagnostics.tlvType == 0xff && diagnostics.expectedType == 4 &&
           diagnostics.tlvOffset == invalidTlv.size());
    assert(diagnostics.seenMask == 0 && diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 0 && diagnostics.tlvTypeTraceLo == 0 &&
           diagnostics.tlvTypeTraceHi == 0);
    assertCleared(info);

    invalidTlv = psf;
    const size_t channelSequenceOffset = findTlvOffset(invalidTlv, 18);
    assert(channelSequenceOffset < invalidTlv.size());
    invalidTlv[channelSequenceOffset + 4] = 2; // Unsupported encoding.
    assert(parse(invalidTlv, &info, &diagnostics) == ParseStatus::InvalidTlvValue);
    assert(diagnostics.reason == TlvRejectReason::InvalidValue);
    assert(diagnostics.subtype == 0 && diagnostics.tlvType == 18 &&
           diagnostics.expectedType == 18);
    assert(diagnostics.tlvOffset == channelSequenceOffset &&
           diagnostics.declaredLen == 25 &&
           diagnostics.availableLen == invalidTlv.size() - channelSequenceOffset - 3);
    assert(diagnostics.seenMask == 0x0007 &&
           diagnostics.requiredMask == 0x00f7);
    assert(diagnostics.traceCount == 8 &&
           diagnostics.tlvTypeTraceLo == 0x150c070618120504ULL &&
           diagnostics.tlvTypeTraceHi == 0);
    assertCleared(info);

    // Type trace keeps only the first 16 values, packs one type per byte,
    // and reports the full number of encountered TLV headers.
    std::vector<uint8_t> traced = psf;
    for (unsigned i = 0; i < 9; ++i)
        appendTlv(traced, 0xfe, {});
    assert(parse(traced, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.reason == TlvRejectReason::None);
    assert(diagnostics.traceCount == 17);
    assert(diagnostics.tlvTypeTraceLo == 0x150c070618120504ULL);
    assert(diagnostics.tlvTypeTraceHi == 0xfefefefefefefefeULL);

    // Header pre-scan is bounded to the parser's 128-TLV ceiling even if the
    // input contains more complete opaque headers. It records no payload.
    std::vector<uint8_t> tooMany = psf;
    for (unsigned i = 0; i < 121; ++i)
        appendTlv(tooMany, 0xfe, {});
    assert(parse(tooMany, &info, &diagnostics) == ParseStatus::TooManyTlvs);
    assert(diagnostics.traceCount == 128);
    assert(diagnostics.tlvTypeTraceLo == 0x150c070618120504ULL);
    assert(diagnostics.tlvTypeTraceHi == 0xfefefefefefefefeULL);
    assertCleared(info);

    // Unknown TLVs are opaque but must have a complete, bounded length.
    std::vector<uint8_t> withUnknown = validFrame(0);
    const size_t insertAt = 24 + 16 + 3 + 31;
    withUnknown.insert(withUnknown.begin() + insertAt,
                       {0xfe, 2, 0, 0xaa, 0xbb});
    assert(parse(withUnknown, &info) == ParseStatus::Ok && info.tlvCount == 9);

    std::vector<uint8_t> padded = psf;
    padded.push_back(0);
    padded.push_back(0);
    assert(parse(padded, &info) == ParseStatus::Ok);
    padded.back() = 1;
    assert(parse(padded, &info) == ParseStatus::InvalidPadding);
    assertCleared(info);

    std::vector<uint8_t> truncated = psf;
    truncated.resize(24 + 15);
    assert(parse(truncated, &info) == ParseStatus::TruncatedFrame);
    assertCleared(info);

    truncated = psf;
    truncated[24 + 16 + 1] = 0xff; // first TLV claims bytes past the MPDU
    truncated[24 + 16 + 2] = 0xff;
    assert(parse(truncated, &info) == ParseStatus::InvalidTlv);
    assertCleared(info);

    std::vector<uint8_t> bad = psf;
    bad[24 + 6] = 2; // unknown AWDL action subtype
    assert(parse(bad, &info) == ParseStatus::NotAwdlAction);
    bad = psf;
    bad[24 + 5] = 0x20; // unsupported AWDL version
    assert(parse(bad, &info) == ParseStatus::NotAwdlAction);
    bad = psf;
    bad[24 + 7] = 1; // reserved byte
    assert(parse(bad, &info) == ParseStatus::InvalidAwdlHeader);
    bad = psf;
    bad[24 + 2] ^= 1; // non-AWDL OUI
    assert(parse(bad, &info) == ParseStatus::NotAwdlAction);

    bad = psf;
    bad[24 + 16 + (3 + 31) + (3 + 21) + 3 + 1] = 2;
    assert(parse(bad, &info) == ParseStatus::InvalidTlvValue);
    bad = validFrame(3);
    // ARPA name length exceeds its enclosing TLV.
    const size_t arpaOffset = 24 + 16 + (3 + 31) + (3 + 21) +
        (3 + 25) + (3 + 40) + (3 + 9) + (3 + 8);
    bad[arpaOffset + 3 + 1] = 0xff;
    assert(parse(bad, &info) == ParseStatus::InvalidTlvValue);
    bad = psf;
    const size_t dataPathOffset = 24 + 16 + (3 + 31) + (3 + 21) +
        (3 + 25) + (3 + 40) + (3 + 9) + (3 + 8);
    bad[dataPathOffset + 3] = 0x10; // UMI requires two following bytes.
    assert(parse(bad, &info, &diagnostics) == ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathFlagsPresent &&
           diagnostics.dataPathFlags == 0x0010 &&
           diagnostics.dataPathRejectStage == DataPathRejectStage::Umi &&
           diagnostics.dataPathOffset == 2);

    bad = psf;
    bad.erase(bad.begin() + dataPathOffset,
              bad.begin() + dataPathOffset + 5); // required TLV absent
    assert(parse(bad, &info) == ParseStatus::InvalidTlv);

    std::vector<uint8_t> container = validFrame(0);
    appendTlv(container, 17, {0x7f, 0x00, 0xa5, 0x5a});
    const ParseStatus standaloneContainerStatus = parse(container, &info);

    // OWL/Owly's legacy DataPathState flags include bits outside the field
    // mask parsed here. Both subtype fixtures use synthetic
    // bytes and exercise the production router's bounded outer-frame parser.
    ParseStatus legacyPsfStatus = ParseStatus::InvalidArgument;
    ParseStatus legacyMifStatus = ParseStatus::InvalidArgument;
    ParseStatus containerPsfStatus = ParseStatus::InvalidArgument;
    ParseStatus containerMifStatus = ParseStatus::InvalidArgument;
    for (uint8_t subtype : {0, 3}) {
        std::vector<uint8_t> legacy = validFrame(subtype, subtype == 3);
        assert(replaceTlvValue(legacy, 12, legacyDataPathState()));
        const ParseStatus legacyStatus = parse(legacy, &info);
        if (subtype == 0)
            legacyPsfStatus = legacyStatus;
        else
            legacyMifStatus = legacyStatus;

        std::vector<uint8_t> opaque = validFrame(subtype, subtype == 3, true);
        assert(replaceTlvValue(opaque, 12, legacyDataPathState()));
        const ParseStatus opaqueStatus = parse(opaque, &info);
        if (subtype == 0)
            containerPsfStatus = opaqueStatus;
        else
            containerMifStatus = opaqueStatus;
    }
    assert(standaloneContainerStatus == ParseStatus::Ok);
    assert(legacyPsfStatus == ParseStatus::Ok);
    assert(legacyMifStatus == ParseStatus::Ok);
    assert(containerPsfStatus == ParseStatus::Ok);
    assert(containerMifStatus == ParseStatus::Ok);

    // The Data Path State layout has conditional fields in wire order. A
    // 47-byte value is structurally valid for this exact synthetic flags and
    // extension-flags combination; length alone does not identify a peer's
    // actual flag words or field contents.
    std::vector<uint8_t> extendedDataPath = validFrame(3, true);
    assert(replaceTlvValue(extendedDataPath, 12, extendedDataPathState47()));
    assert(parse(extendedDataPath, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.dataPathFlagsPresent &&
           diagnostics.dataPathFlags == 0x8307 &&
           diagnostics.dataPathExtFlagsPresent &&
           diagnostics.dataPathExtFlags == 0x0045 &&
           !diagnostics.dataPathOptionsLengthPresent &&
           diagnostics.dataPathOffset == 47 &&
           diagnostics.dataPathRejectStage == DataPathRejectStage::None);

    // Test039 reported these numeric values, but its original TLV bytes are
    // not present. This synthetic fixture checks the compatible field layout
    // and that the named 0x20 Misc marker contributes no separate bytes.
    std::vector<uint8_t> test039Shape =
        syntheticTest039NumericHeaderDataPath();
    std::vector<uint8_t> test039ShapeFrame = validFrame(0);
    assert(replaceTlvValue(test039ShapeFrame, 12, test039Shape));
    assert(parse(test039ShapeFrame, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.dataPathFlagsPresent &&
           diagnostics.dataPathFlags == 0x9f23 &&
           diagnostics.dataPathOptionsLengthPresent &&
           diagnostics.dataPathOptionsLength == 4 &&
           diagnostics.dataPathExtFlagsPresent &&
           diagnostics.dataPathExtFlags == 0x197d &&
           diagnostics.dataPathOffset == 47 &&
           diagnostics.dataPathRejectStage == DataPathRejectStage::None);

    // The Wireshark-named Misc/capability marker has no payload of its own.
    std::vector<uint8_t> miscOnly = validFrame(0);
    assert(replaceTlvValue(miscOnly, 12, {0x00, 0x80, 0x20, 0x00}));
    assert(parse(miscOnly, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.dataPathExtFlagsPresent &&
           diagnostics.dataPathExtFlags == 0x0020 &&
           diagnostics.dataPathOffset == 4 &&
           diagnostics.dataPathRejectStage == DataPathRejectStage::None);

    std::vector<uint8_t> truncatedTest039Shape = test039Shape;
    truncatedTest039Shape.pop_back();
    std::vector<uint8_t> truncatedTest039ShapeFrame = validFrame(0);
    assert(replaceTlvValue(truncatedTest039ShapeFrame, 12,
                           truncatedTest039Shape));
    assert(parse(truncatedTest039ShapeFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathExtFlags == 0x197d &&
           diagnostics.dataPathRejectStage ==
               DataPathRejectStage::ActiveTimeCounters &&
           diagnostics.dataPathOffset == 35);

    std::vector<uint8_t> trailingTest039Shape = test039Shape;
    trailingTest039Shape.push_back(0);
    std::vector<uint8_t> trailingTest039ShapeFrame = validFrame(0);
    assert(replaceTlvValue(trailingTest039ShapeFrame, 12,
                           trailingTest039Shape));
    assert(parse(trailingTest039ShapeFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage == DataPathRejectStage::TrailingBytes &&
           diagnostics.dataPathOffset == 47);

    // A named bit does not relax the unknown-bit policy or make an unknown
    // flag consume arbitrary data.
    test039Shape[27] |= 0x80; // unsupported Extension Flags bit 7
    std::vector<uint8_t> unknownTest039ShapeFrame = validFrame(0);
    assert(replaceTlvValue(unknownTest039ShapeFrame, 12, test039Shape));
    assert(parse(unknownTest039ShapeFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathExtFlags == 0x19fd &&
           diagnostics.dataPathRejectStage ==
               DataPathRejectStage::UnsupportedExtFlags &&
           diagnostics.dataPathOffset == 29);

    // Unicast Options is a bounded length-prefixed opaque field. Its content
    // is not copied or interpreted by the parser.
    const std::vector<uint8_t> optionsValue = {
        0x00, 0x10, 3, 0, 0xa1, 0xb2, 0xc3
    };
    std::vector<uint8_t> optionsFrame = validFrame(0);
    assert(replaceTlvValue(optionsFrame, 12, optionsValue));
    assert(parse(optionsFrame, &info, &diagnostics) == ParseStatus::Ok);
    assert(diagnostics.dataPathFlags == 0x1000 &&
           diagnostics.dataPathOptionsLengthPresent &&
           diagnostics.dataPathOptionsLength == 3 &&
           diagnostics.dataPathOffset == optionsValue.size());

    std::vector<uint8_t> reservedExtension = validFrame(0);
    assert(replaceTlvValue(reservedExtension, 12, {0, 0, 0, 0}));
    assert(parse(reservedExtension, &info, &diagnostics) == ParseStatus::Ok);
    assert(!diagnostics.dataPathExtFlagsPresent &&
           diagnostics.dataPathOffset == 4 &&
           diagnostics.dataPathRejectStage == DataPathRejectStage::None);

    std::vector<uint8_t> nonzeroReservedExtension = validFrame(0);
    assert(replaceTlvValue(nonzeroReservedExtension, 12,
                          {0, 0, 1, 0}));
    assert(parse(nonzeroReservedExtension, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage == DataPathRejectStage::TrailingBytes &&
           diagnostics.dataPathOffset == 2);

    std::vector<uint8_t> shortOptions = {0x00, 0x10, 4, 0, 0xa1, 0xb2};
    std::vector<uint8_t> shortOptionsFrame = validFrame(0);
    assert(replaceTlvValue(shortOptionsFrame, 12, shortOptions));
    assert(parse(shortOptionsFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage == DataPathRejectStage::OptionsData &&
           diagnostics.dataPathOptionsLengthPresent &&
           diagnostics.dataPathOptionsLength == 4 &&
           diagnostics.dataPathOffset == 4);

    std::vector<uint8_t> shortExtendedFlags = {0x00, 0x80};
    std::vector<uint8_t> shortExtendedFlagsFrame = validFrame(0);
    assert(replaceTlvValue(shortExtendedFlagsFrame, 12, shortExtendedFlags));
    assert(parse(shortExtendedFlagsFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage == DataPathRejectStage::ExtendedFlags &&
           diagnostics.dataPathFlags == 0x8000 &&
           diagnostics.dataPathOffset == 2 &&
           !diagnostics.dataPathExtFlagsPresent);

    std::vector<uint8_t> unsupportedExtendedFlags = {0x00, 0x80, 0x80, 0x00};
    std::vector<uint8_t> unsupportedExtendedFlagsFrame = validFrame(0);
    assert(replaceTlvValue(unsupportedExtendedFlagsFrame, 12,
                           unsupportedExtendedFlags));
    assert(parse(unsupportedExtendedFlagsFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage ==
               DataPathRejectStage::UnsupportedExtFlags &&
           diagnostics.dataPathExtFlagsPresent &&
           diagnostics.dataPathExtFlags == 0x0080 &&
           diagnostics.dataPathOffset == 4);

    std::vector<uint8_t> trailingDataPath = {0, 0, 0};
    std::vector<uint8_t> trailingDataPathFrame = validFrame(0);
    assert(replaceTlvValue(trailingDataPathFrame, 12, trailingDataPath));
    assert(parse(trailingDataPathFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage == DataPathRejectStage::TrailingBytes &&
           diagnostics.dataPathOffset == 2);

    std::vector<uint8_t> shortFlags = validFrame(0);
    assert(replaceTlvValue(shortFlags, 12, {0x24}));
    assert(parse(shortFlags, &info) == ParseStatus::InvalidTlvValue);

    std::vector<uint8_t> shortServiceParams = validFrame(0);
    assert(replaceTlvValue(shortServiceParams, 6, zeros(8)));
    assert(parse(shortServiceParams, &info) == ParseStatus::InvalidTlvValue);

    std::vector<uint8_t> badServiceParams = validFrame(0);
    assert(replaceTlvValue(badServiceParams, 6, {0, 0, 0, 0, 0, 0x03, 0, 0, 0,
                                                 1})); // Two mask bits need two values.
    assert(parse(badServiceParams, &info) == ParseStatus::InvalidTlvValue);

    std::vector<uint8_t> truncatedFields = legacyDataPathState();
    truncatedFields.resize(12); // One byte short of the announced AWDL address.
    std::vector<uint8_t> truncatedDataPath = validFrame(0);
    assert(replaceTlvValue(truncatedDataPath, 12, truncatedFields));
    assert(parse(truncatedDataPath, &info) == ParseStatus::InvalidTlvValue);

    std::vector<uint8_t> truncatedKnownField = legacyDataPathState();
    truncatedKnownField[0] |= 0x10; // UMI bit but no UMI bytes before extflags.
    std::vector<uint8_t> truncatedKnownFieldFrame = validFrame(0);
    assert(replaceTlvValue(truncatedKnownFieldFrame, 12, truncatedKnownField));
    assert(parse(truncatedKnownFieldFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage == DataPathRejectStage::ExtendedFlags);

    std::vector<uint8_t> unsupportedExtension = legacyDataPathState();
    unsupportedExtension[13] = 0x80;
    unsupportedExtension[14] = 0x00; // Unknown extension-flag bit 7.
    std::vector<uint8_t> badExtensionFrame = validFrame(0);
    assert(replaceTlvValue(badExtensionFrame, 12, unsupportedExtension));
    assert(parse(badExtensionFrame, &info, &diagnostics) ==
           ParseStatus::InvalidTlvValue);
    assert(diagnostics.dataPathRejectStage ==
               DataPathRejectStage::UnsupportedExtFlags &&
           diagnostics.dataPathExtFlags == 0x0080);

    std::vector<uint8_t> oversizedContainer = validFrame(0, false, true);
    const size_t containerOffset = findTlvOffset(oversizedContainer, 17);
    assert(containerOffset < oversizedContainer.size());
    oversizedContainer[containerOffset + 1] = 0xff;
    oversizedContainer[containerOffset + 2] = 0xff;
    assert(parse(oversizedContainer, &info) == ParseStatus::InvalidTlv);

    bad = psf;
    bad[0] = 0x08; // data frame
    assert(parse(bad, &info) == ParseStatus::NotManagementAction);
    bad = psf;
    bad[1] = 0x40; // Protected bit: body is not parsed as plaintext.
    assert(parse(bad, &info) == ParseStatus::ProtectedAction);
    bad = psf;
    bad[1] = 0x01; // unsupported 802.11 protocol version
    assert(parse(bad, &info) == ParseStatus::Invalid80211Header);

    assert(NativeAwdl::parseActionFrame(nullptr, 0, &info) == ParseStatus::InvalidArgument);
    assert(NativeAwdl::parseActionFrame(psf.data(), psf.size(), nullptr) == ParseStatus::InvalidArgument);

    // Deterministic mutation fuzzing over a known valid PSF and arbitrary
    // lengths catches unchecked offsets without needing a captured user frame.
    for (size_t i = 0; i < psf.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> mutated = psf;
            mutated[i] ^= static_cast<uint8_t>(1U << bit);
            const ParseStatus status = parse(mutated, &info);
            if (status == ParseStatus::Ok) {
                assert(info.subtype == 0 && info.version == 0x10 && info.tlvCount >= 8);
            } else {
                assertCleared(info);
            }
        }
    }
    uint32_t rng = 0x6d2b79f5;
    for (unsigned sample = 0; sample < 20000; ++sample) {
        const size_t length = sample % 512;
        std::vector<uint8_t> randomFrame(length);
        for (size_t i = 0; i < length; ++i) {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            randomFrame[i] = static_cast<uint8_t>(rng);
        }
        const ParseStatus status = parse(randomFrame, &info);
        if (status != ParseStatus::Ok)
            assertCleared(info);
        else
            assert(info.subtype == 0 || info.subtype == 3);
    }
}
