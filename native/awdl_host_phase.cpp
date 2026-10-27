// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_host_phase.hpp"

#include <string.h>

namespace NativeAwdlProbe {
namespace {

constexpr uint64_t kPresenceMode = 4;
constexpr uint64_t kEawPeriodTu = kHostPhaseAwPeriodTu * kPresenceMode;
constexpr uint64_t kCommonAwLengthTu = 16;

bool isSocialChannel(uint8_t channel)
{
    return channel == 6 || channel == 44 || channel == 149;
}

bool validateFirstCycleSchedule(const HostPhaseInput &input,
                                size_t *advertisedSlotCount)
{
    if (!advertisedSlotCount)
        return false;
    bool sawUnused = false;
    size_t advertised = 0;
    for (size_t i = 0; i < kHostPhaseSlotCount; ++i) {
        const uint8_t channel = input.channelSlots[i];
        if (channel == 0) {
            sawUnused = true;
            continue;
        }
        if (!isSocialChannel(channel) || channel != input.rocChannel ||
            sawUnused)
            return false;
        ++advertised;
    }
    if (advertised == 0)
        return false;
    *advertisedSlotCount = advertised;
    return true;
}

} // namespace

HostPhaseStatus buildHostPhaseFields(const HostPhaseInput *input,
                                     HostPhaseFields *output)
{
    if (!input || !output)
        return HostPhaseStatus::InvalidArgument;
    if (!isSocialChannel(input->rocChannel) ||
        input->rocStartUs >= input->hardDeadlineUs)
        return HostPhaseStatus::InvalidRocInterval;
    if (input->phaseOriginUs < input->rocStartUs ||
        input->phaseOriginUs >= input->hardDeadlineUs)
        return HostPhaseStatus::OriginOutsideRoc;
    if (input->sampleUs < input->phaseOriginUs)
        return HostPhaseStatus::SampleBeforeOrigin;
    if (input->sampleUs >= input->hardDeadlineUs)
        return HostPhaseStatus::SampleOutsideRoc;
    if (input->hardDeadlineUs - input->phaseOriginUs >
        kHostPhaseSequenceDurationUs)
        return HostPhaseStatus::RocExceedsOneSequence;
    size_t advertisedSlotCount = 0;
    if (!validateFirstCycleSchedule(*input, &advertisedSlotCount))
        return HostPhaseStatus::InvalidChannelSchedule;
    const uint64_t advertisedEndOffset =
        static_cast<uint64_t>(advertisedSlotCount) *
        kHostPhaseSlotDurationUs;
    if (advertisedEndOffset > UINT64_MAX - input->phaseOriginUs ||
        input->phaseOriginUs + advertisedEndOffset > input->hardDeadlineUs)
        return HostPhaseStatus::AdvertisedScheduleOutlivesLease;

    const uint64_t elapsedUs = input->sampleUs - input->phaseOriginUs;
    if (elapsedUs >= kHostPhaseSequenceDurationUs)
        return HostPhaseStatus::SequenceExpired;

    const uint64_t elapsedTu = elapsedUs / kHostPhaseTuUs;
    // These are OWL's awdl_sync_next_aw_tu() and awdl_sync_current_aw()
    // equations with the explicit local seed aw_counter=0,
    // last_update=phaseOriginUs, aw_period=16 TU, presence_mode=4.
    const uint64_t elapsedWithinEawTu = elapsedTu % kEawPeriodTu;
    const uint64_t txDownCounterTu = kEawPeriodTu - elapsedWithinEawTu;
    const uint64_t currentAwSequence =
        (elapsedWithinEawTu / kHostPhaseAwPeriodTu) +
        kPresenceMode * (elapsedTu / kEawPeriodTu);
    const uint64_t currentSlot =
        (currentAwSequence / kHostPhaseAwPerSlot) % kHostPhaseSlotCount;
    const uint64_t elapsedInCurrentEawTu =
        kEawPeriodTu - txDownCounterTu;

    // OWL's tx.c uses the 16-TU common AW length and clamps the field to zero
    // after that current common window has elapsed.
    uint64_t remainingAwLengthTu = 0;
    if (elapsedInCurrentEawTu < kCommonAwLengthTu)
        remainingAwLengthTu = kCommonAwLengthTu - elapsedInCurrentEawTu;

    if (input->channelSlots[currentSlot] == 0)
        return HostPhaseStatus::CurrentSlotUnadvertised;
    if (input->channelSlots[currentSlot] != input->rocChannel)
        return HostPhaseStatus::RadioChannelMismatch;

    const uint64_t slotEndOffset = (currentSlot + 1) *
        kHostPhaseSlotDurationUs;
    if (slotEndOffset > UINT64_MAX - input->phaseOriginUs ||
        input->phaseOriginUs + slotEndOffset > input->hardDeadlineUs)
        return HostPhaseStatus::CurrentSlotOutlivesLease;

    HostPhaseFields fields{};
    fields.phyTxTimestampUs = static_cast<uint32_t>(input->sampleUs);
    fields.targetTxTimestampUs = fields.phyTxTimestampUs;
    fields.nextAwChannel = input->channelSlots[currentSlot];
    fields.currentSlotIndex = static_cast<uint8_t>(currentSlot);
    fields.txDownCounterTu = static_cast<uint16_t>(txDownCounterTu);
    fields.remainingAwLengthTu = static_cast<uint16_t>(remainingAwLengthTu);
    fields.nextAwSequenceNumber =
        static_cast<uint16_t>(currentAwSequence);
    // The pinned OWL TX builder copies the current AW sequence into AP alignment.
    fields.apAlignment = fields.nextAwSequenceNumber;
    fields.elapsedUs = elapsedUs;
    fields.elapsedTu = elapsedTu;
    fields.remainingLeaseUs = input->hardDeadlineUs - input->sampleUs;
    memcpy(fields.channelSlots, input->channelSlots,
           sizeof(fields.channelSlots));
    *output = fields;
    return HostPhaseStatus::Ok;
}

} // namespace NativeAwdlProbe
