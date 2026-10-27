// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_peer_election.hpp"
#include "../awdl_mif_encode.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <initializer_list>

using IntelAwdlElection::Address;
using IntelAwdlElection::Advertisement;
using IntelAwdlElection::DecodeStatus;
using IntelAwdlElection::LocalState;
using IntelAwdlElection::Ranking;
using IntelAwdlElection::Selection;

static void setAddress(Address *address, uint8_t last)
{
    const uint8_t value[6] = {0x02, 0, 0, 0, 0, last};
    memcpy(address->bytes, value, sizeof(value));
}

static void setSyncValueLength(uint8_t *frame, size_t *length,
                               uint16_t newLength)
{
    assert(frame != nullptr && length != nullptr);
    constexpr size_t syncTlvOffset = 24 + 16;
    const size_t oldLength = static_cast<size_t>(frame[syncTlvOffset + 1]) |
        (static_cast<size_t>(frame[syncTlvOffset + 2]) << 8);
    assert(newLength <= oldLength);
    const size_t oldEnd = syncTlvOffset + 3 + oldLength;
    const size_t newEnd = syncTlvOffset + 3 + newLength;
    memmove(frame + newEnd, frame + oldEnd, *length - oldEnd);
    *length -= oldLength - newLength;
    frame[syncTlvOffset + 1] = static_cast<uint8_t>(newLength);
    frame[syncTlvOffset + 2] = static_cast<uint8_t>(newLength >> 8);
    NativeAwdl::ActionFrameInfo parsed{};
    assert(NativeAwdl::parseActionFrame(frame, *length, &parsed) ==
           NativeAwdl::ParseStatus::Ok);
}

static NativeAwdl::MifInput validInput()
{
    NativeAwdl::MifInput input{};
    const uint8_t peer[6] = {0x02, 1, 2, 3, 4, 5};
    const uint8_t master[6] = {0x02, 10, 11, 12, 13, 14};
    const uint8_t sync[6] = {0x02, 20, 21, 22, 23, 24};
    memcpy(input.psf.sourceAddress, peer, sizeof(peer));
    memcpy(input.psf.masterAddress, master, sizeof(master));
    memcpy(input.psf.syncAddress, sync, sizeof(sync));
    const uint8_t slots[16] = {6, 6, 6, 6, 44, 44, 44, 44,
                               149, 149, 149, 149, 0, 0, 0, 0};
    memcpy(input.psf.channelSlots, slots, sizeof(slots));
    input.psf.sequenceNumber = 1;
    input.psf.phyTxTimestampUs = 1000;
    input.psf.targetTxTimestampUs = 1000;
    input.psf.nextAwChannel = 6;
    input.psf.txDownCounterTu = 32;
    input.psf.masterChannel = 6;
    input.psf.remainingAwLengthTu = 8;
    input.psf.nextAwSequenceNumber = 4;
    input.psf.apAlignment = 4;
    input.psf.masterCounter = 77;
    input.psf.distanceToMaster = 2;
    input.psf.masterMetric = 500;
    input.psf.ownMetric = 450;
    input.psf.ownCounter = 33;
    input.psf.htCapabilityInfo = 0x11ce;
    input.psf.ampduParameters = 0x1b;
    input.psf.rxMcsMask[0] = 0xff;
    input.psf.rxMcsLength = 1;
    input.psf.awdlVersion = 0x34;
    input.psf.deviceClass = 1;
    input.hostname = "phone";
    input.hostnameLength = 5;
    return input;
}

static Advertisement peer(uint8_t id, uint32_t metric, uint32_t counter,
                          uint32_t height, uint8_t syncId)
{
    Advertisement out{};
    setAddress(&out.peer, id);
    setAddress(&out.master, static_cast<uint8_t>(id + 20));
    setAddress(&out.sync, syncId);
    out.masterMetric = metric;
    out.masterCounter = counter;
    out.height = height;
    out.syncConsistent = true;
    out.electionV2 = true;
    return out;
}

static void testDecodeV2AndV1Fallback()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);

    Advertisement decoded{};
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded) ==
           DecodeStatus::Ok);
    assert(decoded.peer.bytes[5] == 5);
    assert(decoded.master.bytes[5] == 14);
    assert(decoded.sync.bytes[5] == 24);
    assert(decoded.height == 2 && decoded.masterMetric == 500);
    assert(decoded.masterCounter == 77 && decoded.ownCounter == 33);
    assert(decoded.electionV2 && decoded.syncConsistent);
    assert(decoded.nextAwChannel == 6 && decoded.txDownCounterTu == 32);
    assert(decoded.awPeriodTu == 16 && decoded.actionFramePeriodTu == 110);
    assert(decoded.nextAwSequence == 4);
    assert(decoded.channelSlots[0] == 6 && decoded.channelSlots[4] == 44 &&
           decoded.channelSlots[8] == 149 && decoded.channelSlots[12] == 0);
    assert(decoded.phyTxTimestampUs == 1000 &&
           decoded.targetTxTimestampUs == 1000);
    assert(decoded.syncParameterLength == 57 && decoded.syncTailLength == 24);
    assert(decoded.embeddedSequencePresent &&
           decoded.embeddedSequenceRecognized &&
           decoded.embeddedSequenceVerified);

    // Type 24 is optional in a PSF/MIF. Replace it with an unknown optional
    // TLV: v1 then applies, with counters absent and sync defaulting to sender.
    const size_t v2Header = 152;
    frame[v2Header] = 23;
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded) ==
           DecodeStatus::Ok);
    assert(!decoded.electionV2);
    assert(decoded.sync.bytes[5] == 5);
    assert(decoded.masterCounter == 0 && decoded.ownCounter == 0);
}

static void testDecodePsfAdvertisementAndSubtypeGuards()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodePsf(&input.psf, frame, sizeof(frame), &length) ==
           NativeAwdl::EncodeStatus::Ok);

    Advertisement decoded{};
    IntelAwdlElection::DecodeDiagnostics diagnostics{};
    assert(IntelAwdlElection::decodePsf(frame, length, &decoded,
                                        &diagnostics) == DecodeStatus::Ok);
    assert(decoded.peer.bytes[5] == 5 && decoded.master.bytes[5] == 14 &&
           decoded.sync.bytes[5] == 24);
    assert(decoded.syncConsistent && decoded.electionV2 &&
           decoded.version == 0x34 && decoded.deviceClass == 1);
    assert(decoded.nextAwChannel == 6 && decoded.txDownCounterTu == 32 &&
           decoded.awPeriodTu == 16 && decoded.actionFramePeriodTu == 110 &&
           decoded.nextAwSequence == 4);
    assert(decoded.channelSlots[0] == 6 && decoded.channelSlots[4] == 44 &&
           decoded.channelSlots[8] == 149 && decoded.channelSlots[12] == 0);
    assert(decoded.phyTxTimestampUs == 1000 &&
           decoded.targetTxTimestampUs == 1000);
    assert(decoded.syncParameterLength == 57 && decoded.syncTailLength == 24 &&
           decoded.embeddedSequencePresent &&
           decoded.embeddedSequenceRecognized &&
           decoded.embeddedSequenceVerified);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);

    assert(IntelAwdlElection::decodeMif(frame, length, &decoded) ==
           DecodeStatus::NotMif);

    // Type 24 remains optional for PSF just as for MIF; v1 fallback uses the
    // sender as sync and leaves both counters at their defined zero values.
    frame[152] = 23;
    assert(IntelAwdlElection::decodePsf(frame, length, &decoded) ==
           DecodeStatus::Ok);
    assert(!decoded.electionV2 && decoded.sync.bytes[5] == 5 &&
           decoded.masterCounter == 0 && decoded.ownCounter == 0);

    NativeAwdl::MifInput mif = validInput();
    assert(NativeAwdl::encodeMif(&mif, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    assert(IntelAwdlElection::decodePsf(frame, length, &decoded) ==
           DecodeStatus::NotPsf);
}

static void testMasterMismatchAndInvalidVersionFailClosed()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    Advertisement decoded{};
    frame[155] = 0x04; // valid unicast, but differs from Sync TLV's master.
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded) ==
           DecodeStatus::MasterMismatch);

    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    frame[238] = 0; // MIF's Version value follows the inserted ARPA TLV.
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded) ==
           DecodeStatus::InvalidVersion);
}

static void testEmbeddedCopyMismatchUsesCanonicalType18()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    Advertisement decoded{};
    IntelAwdlElection::DecodeDiagnostics diagnostics{};
    frame[133] = 149; // Type 18 slot 0; still structurally valid.
    frame[134] = 44;  // A later mismatch must not replace the first diff.
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded,
                                        &diagnostics) == DecodeStatus::Ok);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(diagnostics.embeddedSequenceRecognized &&
           !diagnostics.embeddedSequenceVerified &&
           diagnostics.embeddedSequenceMismatch &&
           diagnostics.embeddedMismatchIndex == 0 &&
           diagnostics.embeddedMismatchChannel == 6 &&
           diagnostics.canonicalMismatchChannel == 149);
    assert(decoded.syncConsistent && decoded.embeddedSequenceMismatch &&
           decoded.embeddedMismatchIndex == 0 &&
           decoded.embeddedMismatchChannel == 6 &&
           decoded.canonicalMismatchChannel == 149 &&
           decoded.channelSlots[0] == 149);

    // A mismatch in the other direction is diagnosed the same way; type 18
    // remains the channel schedule returned to callers.
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    constexpr size_t embeddedSlot0 = 24 + 16 + 3 + 33 + 6;
    frame[embeddedSlot0] = 149;
    frame[embeddedSlot0 + 1] = 44;
    diagnostics = IntelAwdlElection::DecodeDiagnostics{};
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded,
                                        &diagnostics) == DecodeStatus::Ok);
    assert(decoded.embeddedSequenceMismatch &&
           decoded.embeddedMismatchIndex == 0 &&
           decoded.embeddedMismatchChannel == 149 &&
           decoded.canonicalMismatchChannel == 6 &&
           decoded.channelSlots[0] == 6);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone &&
           diagnostics.embeddedSequenceMismatch);
}

static void testPsfEmbeddedCopyMismatchUsesCanonicalType18()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodePsf(&input.psf, frame, sizeof(frame), &length) ==
           NativeAwdl::EncodeStatus::Ok);
    frame[133] = 149; // Type 18 slot 0; still structurally valid.
    Advertisement decoded{};
    IntelAwdlElection::DecodeDiagnostics diagnostics{};
    assert(IntelAwdlElection::decodePsf(frame, length, &decoded,
                                        &diagnostics) == DecodeStatus::Ok);
    assert(decoded.channelSlots[0] == 149 && decoded.syncConsistent &&
           decoded.embeddedSequenceMismatch &&
           decoded.embeddedMismatchIndex == 0 &&
           decoded.embeddedMismatchChannel == 6 &&
           decoded.canonicalMismatchChannel == 149);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone &&
           diagnostics.embeddedSequenceMismatch &&
           diagnostics.embeddedMismatchIndex == 0);
}

static void testIndependentType18WorksWithoutEmbeddedCopy()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    setSyncValueLength(frame, &length, 31);

    Advertisement decoded{};
    IntelAwdlElection::DecodeDiagnostics diagnostics{};
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded,
                                        &diagnostics) == DecodeStatus::Ok);
    assert(decoded.channelSlots[0] == 6 && decoded.channelSlots[4] == 44 &&
           decoded.channelSlots[8] == 149);
    assert(decoded.syncParameterLength == 31 && decoded.syncTailLength == 0);
    assert(!decoded.embeddedSequencePresent &&
           !decoded.embeddedSequenceRecognized &&
           !decoded.embeddedSequenceVerified);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(diagnostics.syncParameterLength == 31 &&
           diagnostics.syncTailLength == 0 &&
           !diagnostics.embeddedSequenceVerified);
}

static void testUnknownSyncTailIsSkippedButNotVerified()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    setSyncValueLength(frame, &length, 41);
    const size_t embeddedOffset = 24 + 16 + 3 + 33;
    const uint8_t unknownTail[8] = {
        15, 2, 0, 3, 0xff, 0xff, 0x66, 0x66
    }; // Has a count byte, but not a complete recognized AWDL sequence header.
    memcpy(frame + embeddedOffset, unknownTail, sizeof(unknownTail));
    NativeAwdl::ActionFrameInfo parsed{};
    assert(NativeAwdl::parseActionFrame(frame, length, &parsed) ==
           NativeAwdl::ParseStatus::Ok);

    Advertisement decoded{};
    IntelAwdlElection::DecodeDiagnostics diagnostics{};
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded,
                                        &diagnostics) == DecodeStatus::Ok);
    assert(decoded.syncParameterLength == 41 && decoded.syncTailLength == 8);
    assert(decoded.embeddedSequencePresent &&
           !decoded.embeddedSequenceRecognized &&
           !decoded.embeddedSequenceVerified);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(diagnostics.syncParameterLength == 41 &&
           diagnostics.syncTailLength == 8 &&
           diagnostics.embeddedSequencePresent &&
           !diagnostics.embeddedSequenceRecognized &&
           !diagnostics.embeddedSequenceVerified);
}

static void testRecognizedButTruncatedEmbeddedSequenceIsRejected()
{
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    setSyncValueLength(frame, &length, 40); // Header plus only one slot byte.

    Advertisement decoded{};
    IntelAwdlElection::DecodeDiagnostics diagnostics{};
    assert(IntelAwdlElection::decodeMif(frame, length, &decoded,
                                        &diagnostics) ==
           DecodeStatus::InvalidSync);
    assert(diagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kEmbeddedSequenceMalformed);
    assert(diagnostics.offendingTlvType == 4 &&
           diagnostics.syncParameterLength == 40 &&
           diagnostics.syncTailLength == 7 &&
           diagnostics.embeddedSequencePresent &&
           diagnostics.embeddedSequenceRecognized &&
           !diagnostics.embeddedSequenceVerified);
}

static void testPrefixAndRequiredFieldBoundaries()
{
    for (unsigned n : {30u, 32u, 33u}) {
        NativeAwdl::MifInput input = validInput();
        uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
        size_t length = 0;
        assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) == NativeAwdl::MifEncodeStatus::Ok);
        const size_t oldLength = frame[41] | size_t(frame[42]) << 8;
        const size_t end = 43 + oldLength;
        memmove(frame + 43 + n, frame + end, length - end);
        length -= oldLength - n;
        frame[41] = n; frame[42] = 0;
        Advertisement out{};
        const auto status = IntelAwdlElection::decodeMif(frame, length, &out);
        if (n == 30) assert(status != DecodeStatus::Ok);
        else assert(status == DecodeStatus::Ok && !out.embeddedSequenceVerified);
    }
    for (unsigned field : {0u, 1u, 2u}) {
        NativeAwdl::MifInput input = validInput();
        uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
        size_t length = 0;
        assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) == NativeAwdl::MifEncodeStatus::Ok);
        for (size_t pos = 40; pos + 3 <= length;) {
            const size_t size = frame[pos + 1] | size_t(frame[pos + 2]) << 8;
            if ((field == 0 && frame[pos] == 18) || (field != 0 && frame[pos] == 21)) {
                if (field == 0) { memmove(frame + pos, frame + pos + 3 + size, length - pos - 3 - size); length -= 3 + size; }
                else frame[pos + 3 + field - 1] = 0;
                break;
            }
            pos += 3 + size;
        }
        Advertisement out{};
        assert(IntelAwdlElection::decodeMif(frame, length, &out) != DecodeStatus::Ok);
    }
    // A recognized copy verifies its own header and slot values, not an
    // unrelated bounded suffix following that copy.
    NativeAwdl::MifInput input = validInput();
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, frame, sizeof(frame), &length) == NativeAwdl::MifEncodeStatus::Ok);
    const size_t oldLength = frame[41] | size_t(frame[42]) << 8;
    const size_t end = 43 + oldLength;
    memmove(frame + end + 2, frame + end, length - end);
    frame[end] = 0x77; frame[end + 1] = 0x88; length += 2;
    frame[41] = oldLength + 2; frame[42] = 0;
    Advertisement out{};
    assert(IntelAwdlElection::decodeMif(frame, length, &out) == DecodeStatus::Ok);
    assert(out.embeddedSequenceVerified && out.syncTailLength == 26);
}

static void testAppleMetricFirstAndTieBreakers()
{
    LocalState local{};
    setAddress(&local.own, 1);
    local.ownMetric = 60;
    local.ownCounter = 0;

    Advertisement peers[4] = {
        peer(2, 510, 3214, 0, 9),
        peer(3, 522, 393, 0, 9),
        peer(4, 522, 393, 1, 9),
        peer(5, 522, 393, 0, 9),
    };
    Selection selected{};
    assert(IntelAwdlElection::selectMaster(&local, peers, 4,
                                          Ranking::MetricFirst, &selected));
    // Equal metric/counter peers choose the shorter path, then higher MAC.
    assert(selected.followsPeer && selected.sync.bytes[5] == 5);
    assert(selected.master.bytes[5] == 25 && selected.height == 1);

    assert(IntelAwdlElection::selectMaster(&local, peers, 4,
                                          Ranking::CounterFirst, &selected));
    assert(selected.sync.bytes[5] == 2);
}

static void testCyclesAndExcessHeightAreIgnored()
{
    LocalState local{};
    setAddress(&local.own, 1);
    local.ownMetric = 60;
    local.ownCounter = 0;
    Advertisement peers[2] = {
        peer(8, 1000, 1000, 0, 1), // Follows us: cycle.
        peer(9, 1000, 1000, 10, 1), // Above bounded follow height.
    };
    Selection selected{};
    assert(IntelAwdlElection::selectMaster(&local, peers, 2,
                                          Ranking::MetricFirst, &selected));
    assert(!selected.followsPeer && selected.sync.bytes[5] == 1);
}

int main()
{
    testDecodeV2AndV1Fallback();
    testDecodePsfAdvertisementAndSubtypeGuards();
    testMasterMismatchAndInvalidVersionFailClosed();
    testEmbeddedCopyMismatchUsesCanonicalType18();
    testPsfEmbeddedCopyMismatchUsesCanonicalType18();
    testIndependentType18WorksWithoutEmbeddedCopy();
    testPrefixAndRequiredFieldBoundaries();
    testUnknownSyncTailIsSkippedButNotVerified();
    testRecognizedButTruncatedEmbeddedSequenceIsRejected();
    testAppleMetricFirstAndTieBreakers();
    testCyclesAndExcessHeightAreIgnored();
}
