// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_HOST_PHASE_HPP
#define NATIVE_AWDL_HOST_PHASE_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdlProbe {

constexpr size_t kHostPhaseSlotCount = 16;
constexpr uint64_t kHostPhaseTuUs = 1024;
constexpr uint64_t kHostPhaseAwPeriodTu = 16;
constexpr uint64_t kHostPhaseAwPerSlot = 4;
constexpr uint64_t kHostPhaseSlotDurationUs =
    kHostPhaseTuUs * kHostPhaseAwPeriodTu * kHostPhaseAwPerSlot;
constexpr uint64_t kHostPhaseSequenceDurationUs =
    kHostPhaseSlotDurationUs * kHostPhaseSlotCount;

struct HostPhaseInput {
    // One fixed local experiment origin. This helper models the OWL
    // initialization seed aw_counter=0 and last_update=origin.
    uint64_t phaseOriginUs;
    uint64_t sampleUs;
    uint64_t rocStartUs;
    uint64_t hardDeadlineUs;
    uint8_t rocChannel;
    uint8_t channelSlots[kHostPhaseSlotCount];
};

struct HostPhaseFields {
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    uint8_t nextAwChannel;
    uint8_t currentSlotIndex;
    uint16_t txDownCounterTu;
    uint16_t remainingAwLengthTu;
    uint16_t nextAwSequenceNumber;
    uint16_t apAlignment;
    uint64_t elapsedUs;
    uint64_t elapsedTu;
    uint64_t remainingLeaseUs;
    // Copy of the original first-cycle plan; later frames must retain it.
    uint8_t channelSlots[kHostPhaseSlotCount];
};

enum class HostPhaseStatus : uint8_t {
    Ok,
    InvalidArgument,
    InvalidRocInterval,
    OriginOutsideRoc,
    SampleBeforeOrigin,
    SampleOutsideRoc,
    RocExceedsOneSequence,
    InvalidChannelSchedule,
    AdvertisedScheduleOutlivesLease,
    SequenceExpired,
    CurrentSlotUnadvertised,
    RadioChannelMismatch,
    CurrentSlotOutlivesLease
};

// Calculate OWL-compatible host-monotonic phase fields from one stable
// origin and the original first-cycle channel table. It does not map host time
// to firmware GP2/TSF, establish actual AWDL synchronization, or prove that
// firmware served the advertised channel schedule. Failure leaves output
// untouched. The caller supplies a confirmed, conservative ROC window.
HostPhaseStatus buildHostPhaseFields(const HostPhaseInput *input,
                                     HostPhaseFields *output);

} // namespace NativeAwdlProbe

#endif
