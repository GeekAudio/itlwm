// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_host_phase.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using NativeAwdlProbe::HostPhaseFields;
using NativeAwdlProbe::HostPhaseInput;
using NativeAwdlProbe::HostPhaseStatus;

static HostPhaseInput inputAt(uint64_t sampleUs)
{
    HostPhaseInput input{};
    input.phaseOriginUs = 1000000;
    input.sampleUs = sampleUs;
    input.rocStartUs = 990000;
    input.hardDeadlineUs = input.phaseOriginUs + 900000;
    input.rocChannel = 6;
    for (size_t i = 0; i < 13; ++i)
        input.channelSlots[i] = 6;
    return input;
}

static HostPhaseFields build(const HostPhaseInput &input)
{
    HostPhaseFields fields{};
    assert(NativeAwdlProbe::buildHostPhaseFields(&input, &fields) ==
           HostPhaseStatus::Ok);
    return fields;
}

static void testOriginAndSequentialSamples()
{
    HostPhaseInput input = inputAt(1000000);
    HostPhaseFields origin = build(input);
    assert(origin.phyTxTimestampUs == static_cast<uint32_t>(input.phaseOriginUs));
    assert(origin.targetTxTimestampUs == origin.phyTxTimestampUs);
    assert(origin.nextAwChannel == 6 && origin.currentSlotIndex == 0);
    // OWL's next-AW counter is a full 64-TU interval at the exact boundary.
    assert(origin.txDownCounterTu == 64);
    assert(origin.remainingAwLengthTu == 16);
    assert(origin.nextAwSequenceNumber == 0 && origin.apAlignment == 0);

    input.sampleUs = input.phaseOriginUs + 1023;
    HostPhaseFields beforeTu = build(input);
    assert(beforeTu.txDownCounterTu == 64);
    assert(beforeTu.remainingAwLengthTu == 16);
    assert(beforeTu.nextAwSequenceNumber == 0);

    input.sampleUs = input.phaseOriginUs + 1024;
    HostPhaseFields oneTu = build(input);
    assert(oneTu.txDownCounterTu == 63);
    assert(oneTu.remainingAwLengthTu == 15);
    assert(oneTu.nextAwSequenceNumber == 0 && oneTu.apAlignment == 0);

    input.sampleUs = input.phaseOriginUs + 16 * 1024;
    HostPhaseFields oneAw = build(input);
    assert(oneAw.txDownCounterTu == 48);
    assert(oneAw.remainingAwLengthTu == 0);
    assert(oneAw.nextAwSequenceNumber == 1 && oneAw.apAlignment == 1);
    assert(oneAw.currentSlotIndex == 0 && oneAw.nextAwChannel == 6);

    // Four AWs share the first slot; the next slot begins at 64 TU.
    input.sampleUs = input.phaseOriginUs +
        NativeAwdlProbe::kHostPhaseSlotDurationUs;
    HostPhaseFields nextSlot = build(input);
    assert(nextSlot.txDownCounterTu == 64);
    assert(nextSlot.remainingAwLengthTu == 16);
    assert(nextSlot.nextAwSequenceNumber == 4 && nextSlot.apAlignment == 4);
    assert(nextSlot.currentSlotIndex == 1 && nextSlot.nextAwChannel == 6);
    assert(memcmp(nextSlot.channelSlots, input.channelSlots,
                  sizeof(input.channelSlots)) == 0);
}

static void expectFailureUnchanged(HostPhaseInput input,
                                   HostPhaseStatus expected)
{
    HostPhaseFields output;
    memset(&output, 0xa5, sizeof(output));
    HostPhaseFields before;
    memcpy(&before, &output, sizeof(before));
    const HostPhaseStatus actual =
        NativeAwdlProbe::buildHostPhaseFields(&input, &output);
    if (actual != expected) {
        fprintf(stderr, "host phase status expected=%u actual=%u\n",
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual));
    }
    assert(actual == expected);
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

static void testSlotCoverageAndLeaseBoundaries()
{
    HostPhaseInput input = inputAt(1000000);
    input.sampleUs = input.phaseOriginUs + 12 *
        NativeAwdlProbe::kHostPhaseSlotDurationUs;
    HostPhaseFields lastCovered = build(input);
    assert(lastCovered.currentSlotIndex == 12 && lastCovered.nextAwChannel == 6);

    input.sampleUs = input.phaseOriginUs + 13 *
        NativeAwdlProbe::kHostPhaseSlotDurationUs;
    expectFailureUnchanged(input, HostPhaseStatus::CurrentSlotUnadvertised);

    input = inputAt(1000000);
    input.hardDeadlineUs = input.phaseOriginUs +
        NativeAwdlProbe::kHostPhaseSlotDurationUs;
    expectFailureUnchanged(input,
        HostPhaseStatus::AdvertisedScheduleOutlivesLease);

    input = inputAt(1000000);
    input.hardDeadlineUs = input.phaseOriginUs +
        NativeAwdlProbe::kHostPhaseSlotDurationUs - 1;
    memset(input.channelSlots + 1, 0, sizeof(input.channelSlots) - 1);
    input.sampleUs = input.phaseOriginUs;
    expectFailureUnchanged(input,
        HostPhaseStatus::AdvertisedScheduleOutlivesLease);

    input = inputAt(1000000);
    input.sampleUs = input.hardDeadlineUs;
    expectFailureUnchanged(input, HostPhaseStatus::SampleOutsideRoc);

    input = inputAt(1000000);
    input.sampleUs = input.phaseOriginUs - 1;
    expectFailureUnchanged(input, HostPhaseStatus::SampleBeforeOrigin);

    input = inputAt(1000000);
    input.sampleUs = input.phaseOriginUs +
        NativeAwdlProbe::kHostPhaseSequenceDurationUs;
    input.hardDeadlineUs = input.sampleUs + 1;
    expectFailureUnchanged(input, HostPhaseStatus::RocExceedsOneSequence);
}

static void testInputAndScheduleRejections()
{
    HostPhaseFields output{};
    assert(NativeAwdlProbe::buildHostPhaseFields(nullptr, &output) ==
           HostPhaseStatus::InvalidArgument);
    HostPhaseInput input = inputAt(1000000);
    assert(NativeAwdlProbe::buildHostPhaseFields(&input, nullptr) ==
           HostPhaseStatus::InvalidArgument);

    input = inputAt(1000000);
    input.phaseOriginUs = input.rocStartUs - 1;
    expectFailureUnchanged(input, HostPhaseStatus::OriginOutsideRoc);

    input = inputAt(1000000);
    input.rocStartUs = input.hardDeadlineUs;
    expectFailureUnchanged(input, HostPhaseStatus::InvalidRocInterval);

    input = inputAt(1000000);
    input.channelSlots[3] = 0;
    input.channelSlots[4] = 6;
    expectFailureUnchanged(input, HostPhaseStatus::InvalidChannelSchedule);

    input = inputAt(1000000);
    input.channelSlots[1] = 44;
    expectFailureUnchanged(input, HostPhaseStatus::InvalidChannelSchedule);

    input = inputAt(1000000);
    input.rocChannel = 44;
    expectFailureUnchanged(input, HostPhaseStatus::InvalidChannelSchedule);
}

int main()
{
    testOriginAndSequentialSamples();
    testSlotCoverageAndLeaseBoundaries();
    testInputAndScheduleRejections();
    puts("PASS: OWL host-phase math and first-cycle lease bounds");
    return 0;
}
