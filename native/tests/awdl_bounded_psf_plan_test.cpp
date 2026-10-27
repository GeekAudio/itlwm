// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_encode.hpp"
#include "../awdl_action_frame.hpp"
#include "../awdl_bounded_psf_plan.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using NativeAwdl::ActionFrameInfo;
using NativeAwdl::EncodeStatus;
using NativeAwdl::PsfInput;
using NativeAwdl::ParseStatus;
using NativeAwdlProbe::PlanStatus;
using NativeAwdlProbe::Request;
using NativeAwdlProbe::RocWitness;
using NativeAwdlProbe::Summary;

static constexpr uint64_t kSlotUs = 65536;
static constexpr uint64_t kSequenceUs = 1048576;

static Request requestAt(uint64_t sampleUs)
{
    Request request{};
    const uint8_t p2pMac[6] = {0x02, 0x19, 0x28, 0x37, 0x46, 0x55};
    memcpy(request.p2pMac.bytes, p2pMac, sizeof(p2pMac));
    request.monotonicSampleUs = sampleUs;
    request.ieee80211SequenceNumber = 0x321;
    request.ht.capabilityInfo = 0x1234;
    request.ht.ampduParameters = 0x56;
    request.ht.rxMcsMask[0] = 0x3f;
    request.ht.rxMcsLength = 1;
    request.ht.confirmed = true;
    return request;
}

static RocWitness roc(uint8_t channel, uint64_t start, uint64_t deadline)
{
    RocWitness witness{};
    witness.channel = channel;
    witness.startUs = start;
    witness.deadlineUs = deadline;
    witness.startConfirmed = true;
    witness.activeAtSampleConfirmed = true;
    return witness;
}

static void checkNineHundredMillisecondWindow()
{
    // Exercise the 32-bit PSF timestamp wrap while preserving one 64-bit
    // monotonic sample for both timestamp fields.
    const uint64_t sample = 0x1ffff0000ULL;
    Request request = requestAt(sample);
    RocWitness window = roc(6, sample, sample + 900000);
    PsfInput input{};
    Summary summary{};

    assert(NativeAwdlProbe::buildObservationOnlyPsfInput(
               &request, &window, &input, &summary) ==
           PlanStatus::ObservationOnly);
    assert(input.phyTxTimestampUs == 0xffff0000U);
    assert(input.targetTxTimestampUs == input.phyTxTimestampUs);
    assert(input.sequenceNumber == 0x321);
    assert(input.nextAwChannel == 6 && input.masterChannel == 6);
    assert(input.txDownCounterTu == 64 && input.remainingAwLengthTu == 16);
    assert(input.nextAwSequenceNumber == 0 && input.apAlignment == 0);

    for (size_t i = 0; i < 13; ++i)
        assert(input.channelSlots[i] == 6);
    for (size_t i = 13; i < 16; ++i)
        assert(input.channelSlots[i] == 0);
    assert(summary.fullyCoveredSlots == 13);
    assert(summary.rocRemainingUs == 900000);
    assert(summary.channelAdvertisedUs == 13 * kSlotUs);
    assert(summary.partialTailNotAdvertisedUs == 48032);
    assert(summary.sequenceDurationUs == kSequenceUs);
    assert(summary.experimentPhaseOriginUs == sample);
    assert(!summary.p2pAddressIsNativeAwdlIdentity);
    assert(summary.dataPathFlagsZero);

    // Self-master seed and explicit HT capabilities are carried through.
    assert(memcmp(input.sourceAddress, request.p2pMac.bytes, 6) == 0);
    assert(memcmp(input.masterAddress, request.p2pMac.bytes, 6) == 0);
    assert(memcmp(input.syncAddress, request.p2pMac.bytes, 6) == 0);
    assert(input.masterCounter == 0 && input.ownCounter == 0);
    assert(input.distanceToMaster == 0);
    assert(input.masterMetric == 60 && input.ownMetric == 60);
    assert(input.htCapabilityInfo == request.ht.capabilityInfo);
    assert(input.ampduParameters == request.ht.ampduParameters);
    assert(input.rxMcsLength == 1 && input.rxMcsMask[0] == 0x3f);

    uint8_t frame[NativeAwdl::kMaximumEncodedPsfLength] = {};
    size_t written = 0;
    assert(NativeAwdl::encodePsf(&input, frame, sizeof(frame), &written) ==
           EncodeStatus::Ok);
    ActionFrameInfo parsed{};
    assert(NativeAwdl::parseActionFrame(frame, written, &parsed) ==
           ParseStatus::Ok);
    assert(parsed.phyTx == input.phyTxTimestampUs);
    assert(parsed.targetTx == input.targetTxTimestampUs);
    // Type 12 is at this fixed offset in the one-byte-MCS profile; flags=0
    // means the control-only probe advertises no AWDL data path.
    assert(frame[221] == 0 && frame[222] == 0);
}

static void checkExactSlotBoundaries()
{
    Request request = requestAt(1000000);
    RocWitness window = roc(44, request.monotonicSampleUs,
                            request.monotonicSampleUs + kSlotUs);
    PsfInput input{};
    Summary summary{};
    assert(NativeAwdlProbe::buildObservationOnlyPsfInput(
               &request, &window, &input, &summary) ==
           PlanStatus::ObservationOnly);
    assert(input.channelSlots[0] == 44);
    for (size_t i = 1; i < 16; ++i)
        assert(input.channelSlots[i] == 0);
    assert(summary.fullyCoveredSlots == 1);
    assert(summary.partialTailNotAdvertisedUs == 0);

    window.deadlineUs = request.monotonicSampleUs + kSequenceUs;
    assert(NativeAwdlProbe::buildObservationOnlyPsfInput(
               &request, &window, &input, &summary) ==
           PlanStatus::ObservationOnly);
    for (size_t i = 0; i < 16; ++i)
        assert(input.channelSlots[i] == 44);
    assert(summary.fullyCoveredSlots == 16);
    assert(summary.partialTailNotAdvertisedUs == 0);
}

static void assertFailureLeavesOutputsUntouched(
    Request request, RocWitness window, PlanStatus expected)
{
    PsfInput input;
    memset(&input, 0xa5, sizeof(input));
    PsfInput beforeInput;
    memcpy(&beforeInput, &input, sizeof(input));
    Summary summary;
    memset(&summary, 0x5a, sizeof(summary));
    Summary beforeSummary;
    memcpy(&beforeSummary, &summary, sizeof(summary));

    assert(NativeAwdlProbe::buildObservationOnlyPsfInput(
               &request, &window, &input, &summary) == expected);
    assert(memcmp(&input, &beforeInput, sizeof(input)) == 0);
    assert(memcmp(&summary, &beforeSummary, sizeof(summary)) == 0);
}

static void checkRefusals()
{
    const uint64_t start = 5000000;
    Request request = requestAt(start);
    RocWitness window = roc(6, start, start + 900000);

    RocWitness unconfirmed = window;
    unconfirmed.startConfirmed = false;
    assertFailureLeavesOutputsUntouched(request, unconfirmed,
                                       PlanStatus::InvalidRocEvidence);
    unconfirmed = window;
    unconfirmed.activeAtSampleConfirmed = false;
    assertFailureLeavesOutputsUntouched(request, unconfirmed,
                                       PlanStatus::InvalidRocEvidence);

    RocWitness invalid = window;
    invalid.channel = 1;
    assertFailureLeavesOutputsUntouched(request, invalid,
                                       PlanStatus::InvalidRocChannel);
    invalid = window;
    invalid.deadlineUs = invalid.startUs;
    assertFailureLeavesOutputsUntouched(request, invalid,
                                       PlanStatus::InvalidRocInterval);
    invalid = window;
    invalid.deadlineUs = start + kSlotUs - 1;
    assertFailureLeavesOutputsUntouched(request, invalid,
                                       PlanStatus::RocTooShortForCompleteSlot);
    invalid = window;
    invalid.deadlineUs = start + kSequenceUs + 1;
    assertFailureLeavesOutputsUntouched(request, invalid,
                                       PlanStatus::RocExceedsOneSequence);

    Request invalidRequest = request;
    invalidRequest.monotonicSampleUs = start - 1;
    assertFailureLeavesOutputsUntouched(invalidRequest, window,
                                       PlanStatus::SampleOutsideRoc);
    invalidRequest = request;
    invalidRequest.monotonicSampleUs = window.deadlineUs;
    assertFailureLeavesOutputsUntouched(invalidRequest, window,
                                       PlanStatus::SampleOutsideRoc);
    invalidRequest = request;
    invalidRequest.p2pMac.bytes[0] = 0x03;
    assertFailureLeavesOutputsUntouched(invalidRequest, window,
                                       PlanStatus::InvalidP2pAddress);
    invalidRequest = request;
    invalidRequest.ht.confirmed = false;
    assertFailureLeavesOutputsUntouched(invalidRequest, window,
                                       PlanStatus::InvalidHtCapabilities);
    invalidRequest = request;
    invalidRequest.ieee80211SequenceNumber = 0x1000;
    assertFailureLeavesOutputsUntouched(invalidRequest, window,
                                       PlanStatus::InvalidSequenceNumber);
}

int main()
{
    checkNineHundredMillisecondWindow();
    checkExactSlotBoundaries();
    checkRefusals();
    puts("PASS: bounded observation-only PSF input and 900 ms slot coverage");
    return 0;
}
