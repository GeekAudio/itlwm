// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_frame.hpp"
#include "../awdl_mif_encode.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using NativeAwdl::ActionFrameInfo;
using NativeAwdl::MifEncodeStatus;
using NativeAwdl::MifInput;
using NativeAwdl::ParseStatus;
using NativeAwdl::PsfInput;

static PsfInput validPsfInput()
{
    PsfInput input = {};
    const uint8_t source[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t master[] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
    const uint8_t sync[] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02};
    memcpy(input.sourceAddress, source, sizeof(source));
    memcpy(input.masterAddress, master, sizeof(master));
    memcpy(input.syncAddress, sync, sizeof(sync));
    input.sequenceNumber = 0x123;
    input.phyTxTimestampUs = 0x12345678;
    input.targetTxTimestampUs = 0x90abcdef;
    const uint8_t slots[16] = {6, 6, 6, 6, 44, 44, 44, 44,
                               149, 149, 149, 149, 6, 6, 44, 149};
    memcpy(input.channelSlots, slots, sizeof(slots));
    input.nextAwChannel = 44;
    input.txDownCounterTu = 12;
    input.masterChannel = 6;
    input.remainingAwLengthTu = 8;
    input.nextAwSequenceNumber = 7;
    input.apAlignment = 9;
    input.masterCounter = 2;
    input.distanceToMaster = 1;
    input.masterMetric = 100;
    input.ownMetric = 200;
    input.ownCounter = 3;
    input.htCapabilityInfo = 0x11ce;
    input.ampduParameters = 0x1b;
    input.rxMcsMask[0] = 0xff;
    input.rxMcsLength = 1;
    input.awdlVersion = 0x34;
    input.deviceClass = 1;
    return input;
}

static uint16_t readLe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

static uint32_t readLe32(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

static size_t findTlv(const uint8_t *frame, size_t length, uint8_t wanted)
{
    const size_t start = 24 + 16;
    if (!frame || length < start)
        return length;
    size_t offset = start;
    while (offset < length) {
        if (length - offset < 3)
            return length;
        const size_t valueLength = readLe16(frame + offset + 1);
        if (valueLength > length - offset - 3)
            return length;
        if (frame[offset] == wanted)
            return offset;
        offset += 3 + valueLength;
    }
    return length;
}

static void assertOutputUnchangedOnFailure(const MifInput &input,
                                           MifEncodeStatus expected,
                                           size_t capacity)
{
    uint8_t output[NativeAwdl::kMaximumEncodedMifLength];
    memset(output, 0xa5, sizeof(output));
    uint8_t before[sizeof(output)];
    memcpy(before, output, sizeof(output));
    size_t written = 999;
    assert(NativeAwdl::encodeMif(&input, output, capacity, &written) == expected);
    assert(written == 0);
    assert(memcmp(output, before, sizeof(output)) == 0);
}

static void testRoundTripAndFieldLayout()
{
    const char hostname[] = "ax201-test";
    MifInput input = {validPsfInput(), hostname, sizeof(hostname) - 1};
    uint8_t psf[NativeAwdl::kMaximumEncodedPsfLength] = {};
    size_t psfLength = 0;
    assert(NativeAwdl::encodePsf(&input.psf, psf, sizeof(psf), &psfLength) ==
           NativeAwdl::EncodeStatus::Ok);

    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength] = {};
    size_t written = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &written) ==
           MifEncodeStatus::Ok);
    assert(written == psfLength + input.hostnameLength + 7);
    assert(written <= NativeAwdl::kMaximumEncodedMifLength);

    ActionFrameInfo info = {};
    assert(NativeAwdl::parseActionFrame(frame, written, &info) == ParseStatus::Ok);
    assert(info.subtype == 3 && info.version == 0x10 && info.tlvCount == 9);

    // Independently check the outer 802.11 and AWDL header fields.
    assert(frame[0] == 0xd0 && frame[1] == 0x00);
    for (size_t i = 0; i < 6; ++i)
        assert(frame[4 + i] == 0xff);
    assert(memcmp(frame + 10, input.psf.sourceAddress, 6) == 0);
    const uint8_t bssid[] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    assert(memcmp(frame + 16, bssid, sizeof(bssid)) == 0);
    assert(readLe16(frame + 22) == (input.psf.sequenceNumber << 4));
    const uint8_t awdlHeader[] = {127, 0x00, 0x17, 0xf2, 8, 0x10, 3, 0};
    assert(memcmp(frame + 24, awdlHeader, sizeof(awdlHeader)) == 0);
    assert(readLe32(frame + 32) == input.psf.phyTxTimestampUs);
    assert(readLe32(frame + 36) == input.psf.targetTxTimestampUs);

    // Verify the required TLV order and every checked outer value boundary.
    const uint8_t expectedTypes[] = {4, 5, 18, 24, 6, 7, 16, 12, 21};
    size_t offset = 40;
    size_t arpaOffset = written;
    for (size_t i = 0; i < sizeof(expectedTypes); ++i) {
        assert(written - offset >= 3);
        assert(frame[offset] == expectedTypes[i]);
        const size_t valueLength = readLe16(frame + offset + 1);
        assert(valueLength <= written - offset - 3);
        if (frame[offset] == 16)
            arpaOffset = offset;
        offset += 3 + valueLength;
    }
    assert(offset == written);
    assert(arpaOffset < written);

    const size_t arpaValueLength = input.hostnameLength + 4;
    assert(readLe16(frame + arpaOffset + 1) == arpaValueLength);
    const uint8_t *arpa = frame + arpaOffset + 3;
    assert(arpa[0] == 3);
    assert(arpa[1] == input.hostnameLength);
    assert(memcmp(arpa + 2, hostname, input.hostnameLength) == 0);
    assert(arpa[2 + input.hostnameLength] == 0xc0);
    assert(arpa[3 + input.hostnameLength] == 0x0c);

    // The Data Path State is deliberately empty and advertises no capabilities.
    const size_t dataPathOffset = findTlv(frame, written, 12);
    assert(dataPathOffset < written);
    assert(readLe16(frame + dataPathOffset + 1) == 2);
    assert(frame[dataPathOffset + 3] == 0 && frame[dataPathOffset + 4] == 0);

    // Shared serialization is byte-identical around the inserted ARPA TLV,
    // except for the one subtype byte.
    assert(memcmp(frame, psf, 30) == 0);
    assert(frame[30] == 3 && psf[30] == 0);
    const size_t insert = findTlv(psf, psfLength, 12);
    assert(insert < psfLength);
    assert(memcmp(frame + 31, psf + 31, insert - 31) == 0);
    assert(memcmp(frame + insert + input.hostnameLength + 7,
                  psf + insert, psfLength - insert) == 0);
}

static void testAddressProfileAndStrictInsertionShapes()
{
    const char hostname[] = "native-awdl";
    MifInput input = {validPsfInput(), hostname, sizeof(hostname) - 1};
    input.psf.advertiseAwdlAddress = true;

    uint8_t psf[NativeAwdl::kMaximumEncodedPsfLength] = {};
    size_t psfLength = 0;
    assert(NativeAwdl::encodePsf(&input.psf, psf, sizeof(psf), &psfLength) ==
           NativeAwdl::EncodeStatus::Ok);
    assert(psfLength == 234);

    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength] = {};
    size_t written = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &written) ==
           MifEncodeStatus::Ok);
    assert(written == psfLength + input.hostnameLength + 7);
    ActionFrameInfo info{};
    assert(NativeAwdl::parseActionFrame(frame, written, &info) == ParseStatus::Ok);
    assert(info.subtype == 3 && info.tlvCount == 9);

    const size_t arpaOffset = findTlv(frame, written, 16);
    const size_t dataPathOffset = findTlv(frame, written, 12);
    assert(arpaOffset < dataPathOffset && dataPathOffset < written);
    assert(arpaOffset == 218); // ARPA stays at the legacy insertion point.
    const size_t arpaTlvLength = input.hostnameLength + 7;
    assert(readLe16(frame + dataPathOffset + 1) == 8);
    assert(frame[dataPathOffset + 3] == 0x04 &&
           frame[dataPathOffset + 4] == 0x00);
    assert(memcmp(frame + dataPathOffset + 5, frame + 10, 6) == 0);
    assert(memcmp(frame + dataPathOffset + 5,
                  input.psf.sourceAddress, 6) == 0);

    // The ARPA TLV is inserted immediately before the original Data Path TLV;
    // no address is regenerated, duplicated, or changed by MIF conversion.
    const size_t psfDataPathOffset = findTlv(psf, psfLength, 12);
    assert(psfDataPathOffset == arpaOffset);
    assert(memcmp(frame, psf, 30) == 0);
    assert(frame[30] == 3 && psf[30] == 0);
    assert(memcmp(frame + 31, psf + 31, arpaOffset - 31) == 0);
    assert(memcmp(frame + dataPathOffset,
                  psf + psfDataPathOffset,
                  psfLength - psfDataPathOffset) == 0);
    assert(dataPathOffset == psfDataPathOffset + arpaTlvLength);

    // Exercise the same strict predicate used by the insertion scanner: only
    // exact legacy-empty and exact source-address forms are accepted.
    assert(NativeAwdl::detail::isSupportedMifDataPathTlv(
        frame, written, dataPathOffset));
    uint8_t malformed[NativeAwdl::kMaximumEncodedMifLength];
    memcpy(malformed, frame, written);
    malformed[dataPathOffset + 3] = 0x05; // Additional flag bit.
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        malformed, written, dataPathOffset));
    memcpy(malformed, frame, written);
    malformed[dataPathOffset + 1] = 7; // Truncated advertised address.
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        malformed, written, dataPathOffset));
    memcpy(malformed, frame, written);
    malformed[dataPathOffset + 1] = 2; // Address flag without address bytes.
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        malformed, written, dataPathOffset));
    memcpy(malformed, frame, written);
    malformed[dataPathOffset + 1] = 9; // Unsupported trailing byte.
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        malformed, written, dataPathOffset));
    memcpy(malformed, frame, written);
    malformed[dataPathOffset + 10] ^= 0x80; // Address must match Addr2.
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        malformed, written, dataPathOffset));
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        frame, dataPathOffset + 10, dataPathOffset)); // Truncated final address byte.

    // Check the legacy form independently as a second accepted shape.
    input.psf.advertiseAwdlAddress = false;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &written) ==
           MifEncodeStatus::Ok);
    const size_t legacyDataPathOffset = findTlv(frame, written, 12);
    assert(legacyDataPathOffset < written);
    assert(readLe16(frame + legacyDataPathOffset + 1) == 2);
    assert(frame[legacyDataPathOffset + 3] == 0 &&
           frame[legacyDataPathOffset + 4] == 0);
    assert(NativeAwdl::detail::isSupportedMifDataPathTlv(
        frame, written, legacyDataPathOffset));
    memcpy(malformed, frame, written);
    malformed[legacyDataPathOffset + 1] = 8;
    assert(!NativeAwdl::detail::isSupportedMifDataPathTlv(
        malformed, written, legacyDataPathOffset));
}

static void testHostnameRejections()
{
    PsfInput psf = validPsfInput();
    const char good[] = "valid-host";
    char tooLong[64];
    memset(tooLong, 'a', sizeof(tooLong));
    const char dot[] = "two.labels";
    const char leadingHyphen[] = "-host";
    const char trailingHyphen[] = "host-";
    const char underscore[] = "host_name";
    const char embeddedNul[] = {'h', '\0', 'x'};
    const char nonAscii[] = {static_cast<char>(0xc3), static_cast<char>(0xa9)};

    const MifInput cases[] = {
        {psf, nullptr, 1},
        {psf, good, 0},
        {psf, tooLong, sizeof(tooLong)},
        {psf, dot, sizeof(dot) - 1},
        {psf, leadingHyphen, sizeof(leadingHyphen) - 1},
        {psf, trailingHyphen, sizeof(trailingHyphen) - 1},
        {psf, underscore, sizeof(underscore) - 1},
        {psf, embeddedNul, sizeof(embeddedNul)},
        {psf, nonAscii, sizeof(nonAscii)}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        assertOutputUnchangedOnFailure(cases[i], MifEncodeStatus::InvalidHostname,
                                       NativeAwdl::kMaximumEncodedMifLength);

    uint8_t output[NativeAwdl::kMaximumEncodedMifLength];
    uint8_t before[sizeof(output)];
    memset(output, 0x5a, sizeof(output));
    memcpy(before, output, sizeof(output));
    size_t written = 88;
    assert(NativeAwdl::encodeMif(nullptr, output, sizeof(output), &written) ==
           MifEncodeStatus::InvalidArgument);
    assert(written == 0 && memcmp(output, before, sizeof(output)) == 0);
}

static void testInputAndCapacityFailures()
{
    const char hostname[] = "node";
    MifInput input = {validPsfInput(), hostname, sizeof(hostname) - 1};
    memset(input.psf.sourceAddress, 0xff, sizeof(input.psf.sourceAddress));
    assertOutputUnchangedOnFailure(input, MifEncodeStatus::InvalidSourceAddress,
                                   NativeAwdl::kMaximumEncodedMifLength);

    input.psf = validPsfInput();
    uint8_t full[NativeAwdl::kMaximumEncodedMifLength];
    memset(full, 0x7c, sizeof(full));
    size_t written = 123;
    assert(NativeAwdl::encodeMif(&input, full, sizeof(full), &written) ==
           MifEncodeStatus::Ok);
    const size_t required = written;
    assertOutputUnchangedOnFailure(input, MifEncodeStatus::BufferTooSmall,
                                   required - 1);

    // A 63-byte label plus the largest PSF HT mask reaches the public bound.
    char maximumLabel[NativeAwdl::kMaximumArpaHostLabelLength];
    memset(maximumLabel, 'a', sizeof(maximumLabel));
    input.hostname = maximumLabel;
    input.hostnameLength = sizeof(maximumLabel);
    input.psf.rxMcsLength = 4;
    input.psf.rxMcsMask[1] = 0xff;
    input.psf.rxMcsMask[2] = 0xff;
    input.psf.rxMcsMask[3] = 0xff;
    assert(NativeAwdl::encodeMif(&input, full, sizeof(full), &written) ==
           MifEncodeStatus::Ok);
    assert(written == 301); // Legacy MCS4 + 63-byte host label.
    ActionFrameInfo info = {};
    assert(NativeAwdl::parseActionFrame(full, written, &info) == ParseStatus::Ok);
    assert(info.subtype == 3 && info.tlvCount == 9);

    input.psf.advertiseAwdlAddress = true;
    assertOutputUnchangedOnFailure(input, MifEncodeStatus::BufferTooSmall, 306);
    assert(NativeAwdl::encodeMif(&input, full, sizeof(full), &written) ==
           MifEncodeStatus::Ok);
    assert(written == 307 && written == NativeAwdl::kMaximumEncodedMifLength);
    assert(NativeAwdl::parseActionFrame(full, written, &info) == ParseStatus::Ok);
    const size_t dataPathOffset = findTlv(full, written, 12);
    assert(readLe16(full + dataPathOffset + 1) == 8);
    assert(memcmp(full + dataPathOffset + 5, full + 10, 6) == 0);
}

int main()
{
    testRoundTripAndFieldLayout();
    testAddressProfileAndStrictInsertionShapes();
    testHostnameRejections();
    testInputAndCapacityFailures();
    return 0;
}
