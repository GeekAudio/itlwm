// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_bounded_psf_plan.hpp"

#include "awdl_host_phase.hpp"

#include <string.h>

namespace NativeAwdlProbe {
namespace {

constexpr uint64_t kSlotDurationUs = kHostPhaseSlotDurationUs;
constexpr uint64_t kSequenceDurationUs = kHostPhaseSequenceDurationUs;

bool isUnicastAddress(const uint8_t address[6])
{
    if (address[0] & 1)
        return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 6; ++i)
        any |= address[i];
    return any != 0;
}

bool isSocialChannel(uint8_t channel)
{
    return channel == 6 || channel == 44 || channel == 149;
}

} // namespace

PlanStatus buildObservationOnlyPsfInput(const Request *request,
                                        const RocWitness *roc,
                                        NativeAwdl::PsfInput *output,
                                        Summary *summary)
{
    if (!request || !roc || !output || !summary)
        return PlanStatus::InvalidArgument;
    if (!isUnicastAddress(request->p2pMac.bytes))
        return PlanStatus::InvalidP2pAddress;
    if (!roc->startConfirmed || !roc->activeAtSampleConfirmed)
        return PlanStatus::InvalidRocEvidence;
    if (!isSocialChannel(roc->channel))
        return PlanStatus::InvalidRocChannel;
    if (roc->startUs >= roc->deadlineUs)
        return PlanStatus::InvalidRocInterval;
    if (request->monotonicSampleUs < roc->startUs ||
        request->monotonicSampleUs >= roc->deadlineUs)
        return PlanStatus::SampleOutsideRoc;
    if (request->ieee80211SequenceNumber > 0x0fff)
        return PlanStatus::InvalidSequenceNumber;
    if (!request->ht.confirmed || request->ht.rxMcsLength == 0 ||
        request->ht.rxMcsLength > sizeof(request->ht.rxMcsMask))
        return PlanStatus::InvalidHtCapabilities;

    const uint64_t remainingUs =
        roc->deadlineUs - request->monotonicSampleUs;
    if (remainingUs < kSlotDurationUs)
        return PlanStatus::RocTooShortForCompleteSlot;
    if (remainingUs > kSequenceDurationUs)
        return PlanStatus::RocExceedsOneSequence;

    NativeAwdl::PsfInput planned{};
    Summary details{};
    memcpy(planned.sourceAddress, request->p2pMac.bytes,
           sizeof(planned.sourceAddress));
    planned.sequenceNumber = request->ieee80211SequenceNumber;

    // The pinned OWL experiment samples host monotonic time once and places
    // that low 32-bit value in both PSF timestamps. This is only a bounded
    // observation convention; it is not an Intel firmware-clock mapping.
    const uint32_t timestamp =
        static_cast<uint32_t>(request->monotonicSampleUs);
    planned.phyTxTimestampUs = timestamp;
    planned.targetTxTimestampUs = timestamp;

    // A local experiment phase begins at the sample. Slot i covers four
    // 16-TU AWs. Advertise a channel only when the whole slot fits inside the
    // remaining ROC lease; do not round a partial slot up.
    const uint64_t fullSlots = remainingUs / kSlotDurationUs;
    for (uint64_t i = 0; i < fullSlots; ++i)
        planned.channelSlots[i] = roc->channel;
    planned.nextAwChannel = roc->channel;
    planned.masterChannel = roc->channel;

    HostPhaseInput phaseInput{};
    phaseInput.phaseOriginUs = request->monotonicSampleUs;
    phaseInput.sampleUs = request->monotonicSampleUs;
    phaseInput.rocStartUs = roc->startUs;
    phaseInput.hardDeadlineUs = roc->deadlineUs;
    phaseInput.rocChannel = roc->channel;
    memcpy(phaseInput.channelSlots, planned.channelSlots,
           sizeof(phaseInput.channelSlots));
    HostPhaseFields phase{};
    if (buildHostPhaseFields(&phaseInput, &phase) != HostPhaseStatus::Ok)
        return PlanStatus::InvalidHostPhase;
    planned.phyTxTimestampUs = phase.phyTxTimestampUs;
    planned.targetTxTimestampUs = phase.targetTxTimestampUs;
    planned.nextAwChannel = phase.nextAwChannel;
    planned.txDownCounterTu = phase.txDownCounterTu;
    planned.remainingAwLengthTu = phase.remainingAwLengthTu;
    planned.nextAwSequenceNumber = phase.nextAwSequenceNumber;
    planned.apAlignment = phase.apAlignment;

    // Source-backed one-node self-master seed: the experimental P2P address
    // is used consistently, distance/counters start at zero, and both metrics
    // use the AWDL-recommended 60 value. This does not replace live election.
    memcpy(planned.masterAddress, request->p2pMac.bytes,
           sizeof(planned.masterAddress));
    memcpy(planned.syncAddress, request->p2pMac.bytes,
           sizeof(planned.syncAddress));
    planned.masterCounter = 0;
    planned.distanceToMaster = 0;
    planned.masterMetric = 60;
    planned.ownMetric = 60;
    planned.ownCounter = 0;

    planned.htCapabilityInfo = request->ht.capabilityInfo;
    planned.ampduParameters = request->ht.ampduParameters;
    memcpy(planned.rxMcsMask, request->ht.rxMcsMask,
           sizeof(planned.rxMcsMask));
    planned.rxMcsLength = request->ht.rxMcsLength;
    planned.awdlVersion = 0x34;
    planned.deviceClass = 1;
    planned.advertiseAwdlAddress = request->nativeAddressVerified;

    details.fullyCoveredSlots = static_cast<uint8_t>(fullSlots);
    details.rocRemainingUs = remainingUs;
    details.channelAdvertisedUs = fullSlots * kSlotDurationUs;
    details.partialTailNotAdvertisedUs =
        remainingUs - details.channelAdvertisedUs;
    details.sequenceDurationUs = kSequenceDurationUs;
    details.experimentPhaseOriginUs = request->monotonicSampleUs;
    details.dataPathFlags = planned.advertiseAwdlAddress ? 0x0004 : 0;
    details.p2pAddressIsNativeAwdlIdentity = request->nativeAddressVerified;
    details.dataPathFlagsZero = details.dataPathFlags == 0;
    details.addressFieldPresent = planned.advertiseAwdlAddress;
    // The encoder copies planned.sourceAddress into the advertised field.
    details.addressMatchesSource = planned.advertiseAwdlAddress;
    details.dataPathReady = false;

    *output = planned;
    *summary = details;
    return PlanStatus::ObservationOnly;
}

} // namespace NativeAwdlProbe
