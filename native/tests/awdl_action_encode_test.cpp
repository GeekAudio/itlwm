// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_encode.hpp"
#include "../awdl_action_frame.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using NativeAwdl::ActionFrameInfo;
using NativeAwdl::EncodeStatus;
using NativeAwdl::PsfInput;
using NativeAwdl::ParseStatus;

static PsfInput validInput()
{
    PsfInput input{};
    const uint8_t source[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t master[] = {0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4};
    const uint8_t sync[] = {0x02, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5};
    memcpy(input.sourceAddress, source, sizeof(source));
    memcpy(input.masterAddress, master, sizeof(master));
    memcpy(input.syncAddress, sync, sizeof(sync));

    const uint8_t slots[16] = {
        6, 6, 6, 6, 44, 44, 44, 44, 149, 149, 149, 149, 0, 0, 0, 0
    };
    memcpy(input.channelSlots, slots, sizeof(slots));
    input.sequenceNumber = 0x0123;
    input.phyTxTimestampUs = 0x01020304;
    input.targetTxTimestampUs = 0x05060708;
    input.nextAwChannel = 6;
    input.txDownCounterTu = 37;
    input.masterChannel = 6;
    input.remainingAwLengthTu = 5;
    input.nextAwSequenceNumber = 0x2345;
    input.apAlignment = 0x6789;
    input.masterCounter = 0x11223344;
    input.distanceToMaster = 7;
    input.masterMetric = 60;
    input.ownMetric = 60;
    input.ownCounter = 0x55667788;
    input.htCapabilityInfo = 0x1234;
    input.ampduParameters = 0x56;
    input.rxMcsMask[0] = 0x3f;
    input.rxMcsLength = 1;
    input.awdlVersion = 0x34;
    input.deviceClass = 1;
    return input;
}

static void assertBytes(const uint8_t *actual, const uint8_t *expected,
                        size_t length)
{
    static unsigned checkNumber = 0;
    ++checkNumber;
    for (size_t i = 0; i < length; ++i) {
        if (actual[i] != expected[i]) {
            fprintf(stderr, "check %u byte mismatch at %zu: got %02x expected %02x\n",
                    checkNumber, i, actual[i], expected[i]);
            assert(false);
        }
    }
}

static void assertUnchangedFailure(PsfInput input, EncodeStatus expectedStatus)
{
    uint8_t output[NativeAwdl::kMaximumEncodedPsfLength];
    memset(output, 0xa5, sizeof(output));
    uint8_t before[sizeof(output)];
    memcpy(before, output, sizeof(output));
    size_t written = 99;
    const EncodeStatus actualStatus =
        NativeAwdl::encodePsf(&input, output, sizeof(output), &written);
    if (actualStatus != expectedStatus) {
        fprintf(stderr, "status mismatch: got %u expected %u\n",
                static_cast<unsigned>(actualStatus),
                static_cast<unsigned>(expectedStatus));
        assert(false);
    }
    assert(written == 0);
    assertBytes(output, before, sizeof(output));
}

static void checkGoldenPsf()
{
    const PsfInput input = validInput();
    uint8_t output[NativeAwdl::kMaximumEncodedPsfLength];
    memset(output, 0xa5, sizeof(output));
    size_t written = 0;
    assert(NativeAwdl::encodePsf(&input, output, sizeof(output), &written) ==
           EncodeStatus::Ok);
    assert(written == 228);

    // Hand-checked against the pinned wire tables: 802.11 header, AWDL action
    // prefix, fixed AWDL BSSID, and LE timestamp fields.
    const uint8_t goldenPrefix[40] = {
        0xd0, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x25, 0x00, 0xff, 0x94, 0x73,
        0x30, 0x12,
        0x7f, 0x00, 0x17, 0xf2, 0x08, 0x10, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05
    };
    assertBytes(output, goldenPrefix, sizeof(goldenPrefix));

    // Independent type/length goldens and offsets from PSF's required order.
    const uint8_t tlvHeaders[8][3] = {
        {4, 57, 0}, {5, 21, 0}, {18, 25, 0}, {24, 40, 0},
        {6, 9, 0}, {7, 8, 0}, {12, 2, 0}, {21, 2, 0}
    };
    const size_t tlvOffsets[8] = {40, 100, 124, 152, 195, 207, 218, 223};
    for (size_t i = 0; i < 8; ++i)
        assertBytes(output + tlvOffsets[i], tlvHeaders[i], 3);

    const uint8_t goldenSlots[16] = {
        6, 6, 6, 6, 44, 44, 44, 44, 149, 149, 149, 149, 0, 0, 0, 0
    };
    const uint8_t goldenSync[57] = {
        6, 0x25, 0x00, 6, 0, 0x10, 0, 0x6e, 0, 0x00, 0x18,
        0x10, 0, 0x10, 0, 5, 0, 3, 3, 3, 3,
        0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 4, 0, 0x45, 0x23,
        0x89, 0x67, 15, 0, 0, 3, 0xff, 0xff,
        6, 6, 6, 6, 44, 44, 44, 44, 149, 149, 149, 149, 0, 0, 0, 0,
        0, 0
    };
    assertBytes(output + 43, goldenSync, sizeof(goldenSync));
    assertBytes(output + 43 + 33 + 6, goldenSlots, sizeof(goldenSlots));

    const uint8_t goldenElectionV1[21] = {
        0, 0, 0, 7, 0,
        0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4,
        60, 0, 0, 0, 60, 0, 0, 0, 0, 0
    };
    assertBytes(output + 103, goldenElectionV1, sizeof(goldenElectionV1));

    const uint8_t goldenSequence[25] = {
        15, 0, 0, 3, 0xff, 0xff,
        6, 6, 6, 6, 44, 44, 44, 44, 149, 149, 149, 149, 0, 0, 0, 0,
        0, 0, 0
    };
    assertBytes(output + 127, goldenSequence, sizeof(goldenSequence));

    const uint8_t goldenElectionV2[40] = {
        0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4,
        0x02, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5,
        0x44, 0x33, 0x22, 0x11,
        7, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x88, 0x77, 0x66, 0x55
    };
    assertBytes(output + 155, goldenElectionV2, sizeof(goldenElectionV2));

    const uint8_t goldenService[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t goldenHt[8] = {0, 0, 0x34, 0x12, 0x56, 0x3f, 0, 0};
    const uint8_t goldenDataPath[2] = {0, 0};
    const uint8_t goldenVersion[2] = {0x34, 1};
    assertBytes(output + 198, goldenService, sizeof(goldenService));
    assertBytes(output + 210, goldenHt, sizeof(goldenHt));
    assertBytes(output + 221, goldenDataPath, sizeof(goldenDataPath));
    assertBytes(output + 226, goldenVersion, sizeof(goldenVersion));

    // The existing parser is a second check. Golden bytes above remain the
    // independent oracle; this assertion is not the only validation.
    ActionFrameInfo parsed{};
    assert(NativeAwdl::parseActionFrame(output, written, &parsed) ==
           ParseStatus::Ok);
    assert(parsed.subtype == 0 && parsed.version == 0x10 &&
           parsed.tlvCount == 8);
    assert(parsed.phyTx == input.phyTxTimestampUs &&
           parsed.targetTx == input.targetTxTimestampUs);
}

static void checkAddressProfileRawGoldenAndMcsBounds()
{
    PsfInput input = validInput();
    input.advertiseAwdlAddress = true;
    uint8_t output[NativeAwdl::kMaximumEncodedPsfLength] = {};
    size_t written = 0;
    assert(NativeAwdl::encodePsf(&input, output, sizeof(output), &written) ==
           EncodeStatus::Ok);

    // Independent raw PSF golden for MCS length 1. This fixture is fixed
    // bytes, not generated by encodePsf or accepted solely by the parser.
    static const uint8_t addressGolden[] = {
        0xd0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x00, 0x25, 0x00, 0xff, 0x94, 0x73, 0x30, 0x12,
        0x7f, 0x00, 0x17, 0xf2, 0x08, 0x10, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x39, 0x00, 0x06, 0x25, 0x00, 0x06, 0x00,
        0x10, 0x00, 0x6e, 0x00, 0x00, 0x18, 0x10, 0x00, 0x10, 0x00, 0x05, 0x00,
        0x03, 0x03, 0x03, 0x03, 0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0x04, 0x00,
        0x45, 0x23, 0x89, 0x67, 0x0f, 0x00, 0x00, 0x03, 0xff, 0xff, 0x06, 0x06,
        0x06, 0x06, 0x2c, 0x2c, 0x2c, 0x2c, 0x95, 0x95, 0x95, 0x95, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
        0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0x3c, 0x00, 0x00, 0x00, 0x3c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x19, 0x00, 0x0f, 0x00, 0x00, 0x03, 0xff,
        0xff, 0x06, 0x06, 0x06, 0x06, 0x2c, 0x2c, 0x2c, 0x2c, 0x95, 0x95, 0x95,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x28, 0x00, 0x02,
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0x02, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0x44,
        0x33, 0x22, 0x11, 0x07, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x3c,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x88, 0x77, 0x66,
        0x55, 0x06, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x34, 0x12, 0x56, 0x3f, 0x00, 0x00,
        0x0c, 0x08, 0x00, 0x04, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x15,
        0x02, 0x00, 0x34, 0x01
    };
    assert(written == sizeof(addressGolden));
    assertBytes(output, addressGolden, sizeof(addressGolden));

    ActionFrameInfo parsed{};
    assert(NativeAwdl::parseActionFrame(output, written, &parsed) ==
           ParseStatus::Ok);
    assert(parsed.subtype == 0 && parsed.tlvCount == 8);

    // The new profile changes only the type-12 value and shifts its suffix by
    // six bytes. Bytes before the Data Path TLV and after its value stay exact.
    PsfInput legacyInput = validInput();
    uint8_t legacy[NativeAwdl::kMaximumEncodedPsfLength] = {};
    size_t legacyLength = 0;
    assert(NativeAwdl::encodePsf(&legacyInput, legacy, sizeof(legacy),
                                 &legacyLength) == EncodeStatus::Ok);
    constexpr size_t kMcs1DataPathOffset = 218;
    assert(legacyLength == 228 && written == legacyLength + 6);
    assertBytes(legacy, output, kMcs1DataPathOffset);
    assert(legacy[kMcs1DataPathOffset] == 12 &&
           legacy[kMcs1DataPathOffset + 1] == 2 &&
           legacy[kMcs1DataPathOffset + 2] == 0 &&
           legacy[kMcs1DataPathOffset + 3] == 0 &&
           legacy[kMcs1DataPathOffset + 4] == 0);
    assert(output[kMcs1DataPathOffset] == 12 &&
           output[kMcs1DataPathOffset + 1] == 8 &&
           output[kMcs1DataPathOffset + 2] == 0 &&
           output[kMcs1DataPathOffset + 3] == 4 &&
           output[kMcs1DataPathOffset + 4] == 0);
    assertBytes(output + kMcs1DataPathOffset + 5, input.sourceAddress, 6);
    assertBytes(legacy + kMcs1DataPathOffset + 5,
                output + kMcs1DataPathOffset + 11,
                legacyLength - kMcs1DataPathOffset - 5);

    // Preserve legacy 228..231-byte output lengths; the expanded bound applies
    // only to the address profile. Every MCS mask length has exact-fit coverage.
    for (uint8_t mcsLength = 1; mcsLength <= 4; ++mcsLength) {
        PsfInput profile = validInput();
        profile.rxMcsLength = mcsLength;
        uint8_t frame[NativeAwdl::kMaximumEncodedPsfLength];
        size_t frameLength = 0;
        assert(NativeAwdl::encodePsf(&profile, frame, sizeof(frame),
                                     &frameLength) == EncodeStatus::Ok);
        const size_t expectedLegacyLength = 227 + mcsLength;
        assert(frameLength == expectedLegacyLength);
        assert(NativeAwdl::encodePsf(&profile, frame, expectedLegacyLength,
                                     &frameLength) == EncodeStatus::Ok);
        assert(frameLength == expectedLegacyLength);

        profile.advertiseAwdlAddress = true;
        const size_t expectedAddressLength = expectedLegacyLength + 6;
        memset(frame, 0x6d, sizeof(frame));
        uint8_t before[sizeof(frame)];
        memcpy(before, frame, sizeof(frame));
        frameLength = 1;
        assert(NativeAwdl::encodePsf(&profile, frame, expectedAddressLength - 1,
                                     &frameLength) == EncodeStatus::BufferTooSmall);
        assert(frameLength == 0);
        assertBytes(frame, before, sizeof(frame));
        assert(NativeAwdl::encodePsf(&profile, frame, expectedAddressLength,
                                     &frameLength) == EncodeStatus::Ok);
        assert(frameLength == expectedAddressLength);
    }
    assert(NativeAwdl::kMaximumEncodedPsfLength == 237);
}

static void checkBoundsAndStrictInputs()
{
    PsfInput input = validInput();

    uint8_t output[NativeAwdl::kMaximumEncodedPsfLength];
    memset(output, 0x5a, sizeof(output));
    uint8_t before[sizeof(output)];
    memcpy(before, output, sizeof(output));
    size_t written = 1;
    assert(NativeAwdl::encodePsf(&input, output, 227, &written) ==
           EncodeStatus::BufferTooSmall);
    assert(written == 0);
    assertBytes(output, before, sizeof(output));

    input = validInput();
    input.sourceAddress[0] = 0x03;
    assertUnchangedFailure(input, EncodeStatus::InvalidSourceAddress);
    input = validInput();
    memset(input.masterAddress, 0, sizeof(input.masterAddress));
    assertUnchangedFailure(input, EncodeStatus::InvalidElectionAddress);
    input = validInput();
    input.channelSlots[0] = 1;
    assertUnchangedFailure(input, EncodeStatus::InvalidChannelSequence);
    input = validInput();
    memset(input.channelSlots, 0, sizeof(input.channelSlots));
    assertUnchangedFailure(input, EncodeStatus::InvalidChannelSequence);
    input = validInput();
    for (size_t i = 4; i < 8; ++i)
        input.channelSlots[i] = 0;
    input.nextAwChannel = 44; // not present in the supplied schedule
    assertUnchangedFailure(input, EncodeStatus::InvalidChannelSequence);
    input = validInput();
    input.txDownCounterTu = 65;
    assertUnchangedFailure(input, EncodeStatus::InvalidSyncFields);
    input = validInput();
    input.remainingAwLengthTu = 17;
    assertUnchangedFailure(input, EncodeStatus::InvalidSyncFields);
    input = validInput();
    input.distanceToMaster = 256; // v1 TLV cannot represent this value.
    assertUnchangedFailure(input, EncodeStatus::InvalidElectionFields);
    input = validInput();
    input.rxMcsLength = 0;
    assertUnchangedFailure(input, EncodeStatus::InvalidHtCapabilities);
    input = validInput();
    input.rxMcsLength = 5;
    assertUnchangedFailure(input, EncodeStatus::InvalidHtCapabilities);
    input = validInput();
    input.awdlVersion = 0x03;
    assertUnchangedFailure(input, EncodeStatus::InvalidVersion);
    input = validInput();
    input.deviceClass = 2;
    assertUnchangedFailure(input, EncodeStatus::InvalidVersion);
    input = validInput();
    input.sequenceNumber = 0x1000;
    assertUnchangedFailure(input, EncodeStatus::InvalidArgument);

    input = validInput();
    input.rxMcsLength = 4;
    input.rxMcsMask[1] = 0x80;
    input.rxMcsMask[2] = 0x01;
    input.rxMcsMask[3] = 0x02;
    written = 0;
    assert(NativeAwdl::encodePsf(&input, output, sizeof(output), &written) ==
           EncodeStatus::Ok);
    assert(written == 231); // Legacy MCS4 stays 231; address mode reaches 237.
    ActionFrameInfo parsed{};
    assert(NativeAwdl::parseActionFrame(output, written, &parsed) ==
           ParseStatus::Ok);
}

static void checkNullArguments()
{
    PsfInput input = validInput();
    uint8_t output[NativeAwdl::kMaximumEncodedPsfLength];
    memset(output, 0x6b, sizeof(output));
    uint8_t before[sizeof(output)];
    memcpy(before, output, sizeof(output));
    size_t written = 77;
    assert(NativeAwdl::encodePsf(nullptr, output, sizeof(output), &written) ==
           EncodeStatus::InvalidArgument);
    assert(written == 0);
    assertBytes(output, before, sizeof(output));
    assert(NativeAwdl::encodePsf(&input, nullptr, sizeof(output), &written) ==
           EncodeStatus::InvalidArgument);
    assert(written == 0);
    assert(NativeAwdl::encodePsf(&input, output, sizeof(output), nullptr) ==
           EncodeStatus::InvalidArgument);
}

int main()
{
    checkGoldenPsf();
    checkAddressProfileRawGoldenAndMcsBounds();
    checkBoundsAndStrictInputs();
    checkNullArguments();
    return 0;
}
