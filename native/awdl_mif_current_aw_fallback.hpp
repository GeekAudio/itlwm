// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_CURRENT_AW_FALLBACK_HPP
#define NATIVE_AWDL_MIF_CURRENT_AW_FALLBACK_HPP

#include "awdl_mif_current_phase_test066.hpp"

#include <stdint.h>

// Pure geometry fallback around the pinned Test076 planner. This header performs
// no I/O and grants no transmit permission; the caller owns one-shot, MIF
// consumption, queue, ROC, lease, and actual-submit-time authorization.
namespace NativeAwdlMifCurrentAw {

namespace Legacy = Test066MifCurrentPhase;

constexpr uint64_t kTuUs = Legacy::kTuUs;
constexpr uint64_t kCurrentAwInnerStartUs = 4ULL * kTuUs;
constexpr uint64_t kCurrentAwInnerEndUs = 12ULL * kTuUs;
constexpr uint64_t kCurrentAwPeriodUs = 16ULL * kTuUs;

enum class RejectReason : uint8_t {
    kNotAttempted = 0,
    kLegacyStatus26NotProven,
    kProjectedRxIntervalInvalid,
    kProjectedRxSubtractionUnderflow,
    kTimeAdditionOverflow,
    kCurrentAwWindowEmpty,
    kOwnMifCompletionMissing,
    kOwnMifCompletionNotBeforeWindow,
    kLeaseReserve,
    kOutsideLease,
    kExpired
};

enum class TargetAwRelation : uint8_t {
    kNotApplicable = 0,
    kFutureFromMifRx,
    kCurrentAwStartedBeforeMifRx
};

struct Input {
    Legacy::Input timing;
};

// Inherits the pinned Test066 candidate so legacy fields remain byte-for-byte
// identical on legacy success. Consumers must inspect the explicit relation
// and validity fields before interpreting the legacy unsigned delta.
struct Candidate : Legacy::Candidate {
    bool fallbackUsed;
    TargetAwRelation targetAwRelation;
    bool targetAwStartForwardDeltaValid;
    int32_t targetAwStartOffsetUs;
    uint64_t beforeRxUs;
};

struct Window {
    uint64_t earliestSubmitUs;
    uint64_t latestSubmitUs; // Exclusive.
};

struct Geometry {
    uint64_t receiveHostEarliestUs;
    uint64_t receiveHostLatestUs;
    uint64_t nextAwStartDeltaUs;
    uint64_t elapsedWithinCurrentAwUs;
    uint32_t nextEawGp2Us;
    uint32_t currentEawStartGp2Us;
    uint32_t currentAwStartGp2Us;
    uint8_t currentSlot;
};

// Read-only scalar description for diagnostics. A valid candidate here is
// still only planner output; it never grants TX permission or mutates caller
// state. Values are meaningful only when their corresponding validity flag is
// true.
struct PlanObservation {
    Legacy::Status status;
    RejectReason why;
    uint64_t plannerNowUs;
    uint64_t receiveHostEarliestUs;
    uint64_t receiveHostLatestUs;
    uint64_t freshnessUntilUs;
    uint64_t earliestSubmitUs;
    uint64_t latestSubmitUs;
    int32_t targetAwStartOffsetUs;
    uint64_t beforeRxUs;
    TargetAwRelation selectedRelation;
    bool plannerNowValid;
    bool geometryValid;
    bool freshnessUntilValid;
    bool windowValid;
    bool selectedRelationValid;
    bool forwardDeltaValid;
    bool candidateAvailable;
    bool fallbackAttempted;
};

inline bool proofEpochs(const Legacy::Input &in)
{
    return Legacy::nonzeroEpochs(in.currentEpochs) &&
           Legacy::nonzeroEpochs(in.mif.epochs) &&
           Legacy::nonzeroEpochs(in.anchor.epochs) &&
           Legacy::nonzeroEpochs(in.binding.epochs) &&
           Legacy::sameEpochs(in.currentEpochs, in.mif.epochs) &&
           Legacy::sameEpochs(in.currentEpochs, in.anchor.epochs) &&
           Legacy::sameEpochs(in.currentEpochs, in.binding.epochs);
}

// Re-prove the exact path to Test066::kNoConservativeWindow before changing
// geometry. This duplicates the pinned planner's gates and its old-window
// comparison so a future early return or enum reuse cannot unlock fallback.
inline bool proveLegacyStatus26(const Legacy::Input &in, Geometry &geometry)
{
    const Legacy::MifTimingWitness &mif = in.mif;
    const Legacy::PreRocGp2Anchor &anchor = in.anchor;
    if (!in.nowUs || !in.leaseStartUs || in.leaseStartUs >= in.leaseEndUs ||
        in.nowUs < in.leaseStartUs || in.nowUs >= in.leaseEndUs ||
        in.localRocChannel != Legacy::kLocalChannel)
        return false;
    if (!in.gates.explicitlyEnabled ||
        !in.gates.hostMonotonicDomainVerified ||
        !in.gates.ownMifTxSucceeded || !in.gates.rocActive ||
        !in.gates.rocChannel6Confirmed ||
        !in.gates.peerMifRxChannel6Confirmed || in.gates.closing ||
        !in.gates.ringIdle || !in.gates.strictQmHeadStable)
        return false;
    if (!proofEpochs(in))
        return false;
    if (!in.binding.sameEntryVerified ||
        !in.binding.historicalPsfSameEntryPresent ||
        !mif.peerIncarnation || !mif.mifRevision ||
        in.binding.peerIncarnation != mif.peerIncarnation ||
        in.binding.mifRevision != mif.mifRevision)
        return false;
    if (!mif.present || !mif.complete || !mif.type18Present ||
        !mif.type18Valid || !mif.presenceModePresent ||
        !mif.awCounterSemanticVerified)
        return false;
    if (!mif.syncConsistent || !mif.rxGp2Present || !mif.fresh ||
        !mif.rxMonotonicUs || mif.rxMonotonicUs > in.nowUs ||
        in.nowUs - mif.rxMonotonicUs > Legacy::kMaximumMifAgeUs)
        return false;
    if (!anchor.directReadBracket || !anchor.occurredBeforeRoc ||
        !anchor.firmwareResourcesAbsent || !anchor.hostBeforeUs ||
        !anchor.hostAfterUs || anchor.hostAfterUs < anchor.hostBeforeUs ||
        anchor.hostAfterUs - anchor.hostBeforeUs >
            Legacy::kMaximumAnchorBracketUs ||
        anchor.hostAfterUs > mif.rxMonotonicUs ||
        mif.rxMonotonicUs > in.nowUs)
        return false;

    const uint32_t anchorToRxUs =
        Legacy::forwardDeltaGp2(mif.rxGp2Us, anchor.rawGp2Us);
    if (anchorToRxUs >= Legacy::kGp2HalfRangeUs ||
        anchorToRxUs >= Legacy::kMaximumAnchorToMifUs)
        return false;
    if (mif.presenceMode != Legacy::kExpectedPresenceMode ||
        mif.awPeriodTu != Legacy::kExpectedAwPeriodTu ||
        !mif.txDownCounterTu || mif.txDownCounterTu > Legacy::kEawPeriodTu)
        return false;

    const uint32_t phyMinusTarget =
        mif.phyTxTimestampUs - mif.targetTxTimestampUs;
    const uint64_t downUs =
        static_cast<uint64_t>(mif.txDownCounterTu) * kTuUs;
    if (phyMinusTarget >= Legacy::kGp2HalfRangeUs ||
        phyMinusTarget >= 65536U || phyMinusTarget > downUs)
        return false;

    const uint8_t currentSlot = static_cast<uint8_t>(
        (mif.awCounter / Legacy::kAwPerEaw) % Legacy::kSlotCount);
    for (uint8_t slot = 0; slot < Legacy::kSlotCount; ++slot) {
        if (mif.canonicalSlots[slot] > 233)
            return false;
    }
    if (mif.canonicalSlots[currentSlot] != Legacy::kLocalChannel ||
        currentSlot >= Legacy::kSlotCount)
        return false;
    const uint8_t awWithinEaw =
        static_cast<uint8_t>(mif.awCounter % Legacy::kAwPerEaw);
    if (awWithinEaw + 1U >= Legacy::kAwPerEaw)
        return false;
    const uint16_t downCounterAwIndex = static_cast<uint16_t>(
        (Legacy::kEawPeriodTu - mif.txDownCounterTu) /
        Legacy::kExpectedAwPeriodTu);
    if (awWithinEaw != downCounterAwIndex)
        return false;

    const uint64_t correctedDownUs = downUs - phyMinusTarget;
    const uint32_t nextEawGp2 = mif.rxGp2Us +
        static_cast<uint32_t>(correctedDownUs);
    const uint32_t currentEawStartGp2 = nextEawGp2 -
        static_cast<uint32_t>(Legacy::kEawPeriodTu * kTuUs);
    const uint8_t nextAwIndex = static_cast<uint8_t>(awWithinEaw + 1U);
    const uint32_t nextAwStartGp2 = currentEawStartGp2 +
        static_cast<uint32_t>(nextAwIndex * Legacy::kExpectedAwPeriodTu * kTuUs);
    const uint32_t nextAwStartDeltaUs =
        Legacy::forwardDeltaGp2(nextAwStartGp2, mif.rxGp2Us);
    if (nextAwStartDeltaUs >= Legacy::kGp2HalfRangeUs ||
        nextAwStartDeltaUs >= kCurrentAwPeriodUs)
        return false;

    const uint64_t candidateStartDeltaUs =
        static_cast<uint64_t>(nextAwStartDeltaUs) +
        Legacy::kEdgeGuardTu * kTuUs +
        Legacy::kQuantizationGuardTu * kTuUs;
    const uint64_t candidateEndDeltaUs =
        static_cast<uint64_t>(nextAwStartDeltaUs) +
        (Legacy::kExpectedAwPeriodTu - Legacy::kEdgeGuardTu -
         Legacy::kQuantizationGuardTu) * kTuUs;
    if (anchor.hostAfterUs > UINT64_MAX - anchorToRxUs ||
        anchor.hostBeforeUs > UINT64_MAX - anchorToRxUs)
        return false;
    const uint64_t receiveHostEarliestUs =
        anchor.hostBeforeUs + anchorToRxUs;
    const uint64_t receiveHostLatestUs =
        anchor.hostAfterUs + anchorToRxUs;
    if (receiveHostLatestUs > mif.rxMonotonicUs ||
        receiveHostLatestUs > UINT64_MAX - candidateStartDeltaUs ||
        receiveHostEarliestUs > UINT64_MAX - candidateEndDeltaUs ||
        receiveHostEarliestUs > UINT64_MAX - Legacy::kMifFreshnessUs)
        return false;

    const uint64_t oldEarliest =
        receiveHostLatestUs + candidateStartDeltaUs;
    const uint64_t oldPhaseLatest =
        receiveHostEarliestUs + candidateEndDeltaUs;
    const uint64_t oldFreshUntil =
        receiveHostEarliestUs + Legacy::kMifFreshnessUs;
    const uint64_t oldLatest = oldPhaseLatest < oldFreshUntil ?
        oldPhaseLatest : oldFreshUntil;
    if (oldEarliest < oldLatest)
        return false; // It was not the exact old no-window condition.

    const uint64_t elapsedWithinCurrentAwUs =
        kCurrentAwPeriodUs - nextAwStartDeltaUs;
    const uint32_t currentAwStartGp2 = nextAwStartGp2 -
        static_cast<uint32_t>(kCurrentAwPeriodUs);
    if (currentAwStartGp2 != mif.rxGp2Us -
            static_cast<uint32_t>(elapsedWithinCurrentAwUs))
        return false;

    Geometry candidate{};
    candidate.receiveHostEarliestUs = receiveHostEarliestUs;
    candidate.receiveHostLatestUs = receiveHostLatestUs;
    candidate.nextAwStartDeltaUs = nextAwStartDeltaUs;
    candidate.elapsedWithinCurrentAwUs = elapsedWithinCurrentAwUs;
    candidate.nextEawGp2Us = nextEawGp2;
    candidate.currentEawStartGp2Us = currentEawStartGp2;
    candidate.currentAwStartGp2Us = currentAwStartGp2;
    candidate.currentSlot = currentSlot;
    geometry = candidate;
    return true;
}

inline bool calculateWindow(uint64_t receiveHostEarliestUs,
                            uint64_t receiveHostLatestUs,
                            uint64_t elapsedWithinCurrentAwUs,
                            Window &output,
                            RejectReason &rejectReason)
{
    if (receiveHostEarliestUs > receiveHostLatestUs) {
        rejectReason = RejectReason::kProjectedRxIntervalInvalid;
        return false;
    }
    if (elapsedWithinCurrentAwUs > receiveHostEarliestUs ||
        elapsedWithinCurrentAwUs > receiveHostLatestUs) {
        rejectReason = RejectReason::kProjectedRxSubtractionUnderflow;
        return false;
    }
    const uint64_t earliestAwStart =
        receiveHostLatestUs - elapsedWithinCurrentAwUs;
    const uint64_t latestAwStart =
        receiveHostEarliestUs - elapsedWithinCurrentAwUs;
    if (earliestAwStart > UINT64_MAX - kCurrentAwInnerStartUs ||
        latestAwStart > UINT64_MAX - kCurrentAwInnerEndUs ||
        receiveHostEarliestUs > UINT64_MAX - Legacy::kMifFreshnessUs) {
        rejectReason = RejectReason::kTimeAdditionOverflow;
        return false;
    }

    const uint64_t earliestSubmitUs =
        earliestAwStart + kCurrentAwInnerStartUs;
    const uint64_t phaseLatestUs = latestAwStart + kCurrentAwInnerEndUs;
    const uint64_t freshUntilUs =
        receiveHostEarliestUs + Legacy::kMifFreshnessUs;
    const uint64_t latestSubmitUs = phaseLatestUs < freshUntilUs ?
        phaseLatestUs : freshUntilUs;
    if (earliestSubmitUs >= latestSubmitUs) {
        rejectReason = RejectReason::kCurrentAwWindowEmpty;
        return false;
    }

    Window candidate{};
    candidate.earliestSubmitUs = earliestSubmitUs;
    candidate.latestSubmitUs = latestSubmitUs;
    output = candidate;
    rejectReason = RejectReason::kNotAttempted;
    return true;
}

inline Legacy::Status plan(const Input &in, Candidate &output,
                           RejectReason *rejectReason = nullptr)
{
    if (rejectReason)
        *rejectReason = RejectReason::kNotAttempted;
    Legacy::Candidate legacyCandidate{};
    const Legacy::Status legacyStatus = Legacy::plan(in.timing, legacyCandidate);
    if (legacyStatus != Legacy::Status::kNoConservativeWindow) {
        if (legacyStatus == Legacy::Status::kCandidate) {
            Candidate candidate{};
            static_cast<Legacy::Candidate &>(candidate) = legacyCandidate;
            candidate.fallbackUsed = false;
            candidate.targetAwRelation = TargetAwRelation::kFutureFromMifRx;
            candidate.targetAwStartForwardDeltaValid = true;
            candidate.targetAwStartOffsetUs =
                static_cast<int32_t>(legacyCandidate.targetAwStartDeltaUs);
            candidate.beforeRxUs = 0;
            output = candidate;
        }
        return legacyStatus;
    }

    Geometry geometry{};
    if (!proveLegacyStatus26(in.timing, geometry)) {
        if (rejectReason)
            *rejectReason = RejectReason::kLegacyStatus26NotProven;
        return legacyStatus;
    }

    Window window{};
    RejectReason reason = RejectReason::kNotAttempted;
    if (!calculateWindow(geometry.receiveHostEarliestUs,
                         geometry.receiveHostLatestUs,
                         geometry.elapsedWithinCurrentAwUs,
                         window, reason)) {
        if (rejectReason)
            *rejectReason = reason;
        return legacyStatus;
    }
    const Legacy::Input &timing = in.timing;
    if (!timing.gates.firstOwnMifCompletionUs) {
        if (rejectReason)
            *rejectReason = RejectReason::kOwnMifCompletionMissing;
        return legacyStatus;
    }
    if (timing.gates.firstOwnMifCompletionUs >= window.earliestSubmitUs) {
        if (rejectReason)
            *rejectReason = RejectReason::kOwnMifCompletionNotBeforeWindow;
        return legacyStatus;
    }

    if (timing.leaseEndUs <= Legacy::kLeaseReserveUs ||
        timing.leaseEndUs - timing.nowUs <= Legacy::kLeaseReserveUs) {
        if (rejectReason)
            *rejectReason = RejectReason::kLeaseReserve;
        return legacyStatus;
    }
    const uint64_t usableLeaseEndUs =
        timing.leaseEndUs - Legacy::kLeaseReserveUs;
    if (window.earliestSubmitUs < timing.leaseStartUs ||
        window.latestSubmitUs > usableLeaseEndUs) {
        if (rejectReason)
            *rejectReason = RejectReason::kOutsideLease;
        return legacyStatus;
    }
    if (timing.nowUs >= window.latestSubmitUs) {
        if (rejectReason)
            *rejectReason = RejectReason::kExpired;
        return legacyStatus;
    }

    Candidate candidate{};
    candidate.earliestSubmitUs = window.earliestSubmitUs;
    candidate.latestSubmitUs = window.latestSubmitUs;
    candidate.receiveHostEarliestUs = geometry.receiveHostEarliestUs;
    candidate.receiveHostLatestUs = geometry.receiveHostLatestUs;
    // The legacy unsigned forward-delta field is not applicable here. Keep
    // its zero initialization only alongside the explicit invalid marker and
    // the signed/past relation fields below.
    candidate.targetAwStartDeltaUs = 0;
    candidate.targetAwStartGp2Us = geometry.currentAwStartGp2Us;
    candidate.nextEawGp2Us = geometry.nextEawGp2Us;
    candidate.currentEawStartGp2Us = geometry.currentEawStartGp2Us;
    candidate.currentSlot = geometry.currentSlot;
    candidate.targetAwCounter = timing.mif.awCounter; // Raw current AW counter.
    candidate.peerIncarnation = timing.mif.peerIncarnation;
    candidate.mifRevision = timing.mif.mifRevision;
    candidate.epochs = timing.mif.epochs;
    candidate.status = Legacy::Status::kCandidate;
    candidate.clockMappingVerified = false;
    candidate.airtimeVerified = false;
    candidate.experimentalOnly = true;
    candidate.fallbackUsed = true;
    candidate.targetAwRelation = TargetAwRelation::kCurrentAwStartedBeforeMifRx;
    candidate.targetAwStartForwardDeltaValid = false;
    candidate.targetAwStartOffsetUs =
        -static_cast<int32_t>(geometry.elapsedWithinCurrentAwUs);
    candidate.beforeRxUs = geometry.elapsedWithinCurrentAwUs;
    output = candidate;
    return Legacy::Status::kCandidate;
}

// Pure observation view for a caller-side trace. The helper accepts const
// input, builds only a local candidate, and never returns an authorization
// decision. `candidateAvailable` says only that the timing planner found a
// candidate; the caller must still consume the MIF and recheck actual submit
// time, queue head, one-shot binding, ROC, and lease immediately before send.
inline PlanObservation describe(const Input &in)
{
    PlanObservation observation{};
    observation.status = Legacy::Status::kInvalidInput;
    observation.why = RejectReason::kNotAttempted;
    observation.selectedRelation = TargetAwRelation::kNotApplicable;
    observation.plannerNowUs = in.timing.nowUs;
    observation.plannerNowValid = in.timing.nowUs != 0;

    Candidate candidate{};
    RejectReason reason = RejectReason::kNotAttempted;
    observation.status = plan(in, candidate, &reason);
    observation.why = reason;
    observation.fallbackAttempted =
        observation.status == Legacy::Status::kNoConservativeWindow;

    if (observation.status == Legacy::Status::kCandidate) {
        observation.fallbackAttempted = candidate.fallbackUsed;
        observation.geometryValid = true;
        observation.receiveHostEarliestUs = candidate.receiveHostEarliestUs;
        observation.receiveHostLatestUs = candidate.receiveHostLatestUs;
        observation.earliestSubmitUs = candidate.earliestSubmitUs;
        observation.latestSubmitUs = candidate.latestSubmitUs;
        observation.targetAwStartOffsetUs = candidate.targetAwStartOffsetUs;
        observation.beforeRxUs = candidate.beforeRxUs;
        observation.selectedRelation = candidate.targetAwRelation;
        observation.selectedRelationValid = true;
        observation.forwardDeltaValid =
            candidate.targetAwStartForwardDeltaValid;
        observation.windowValid =
            candidate.earliestSubmitUs < candidate.latestSubmitUs;
        observation.candidateAvailable = observation.windowValid;
        if (candidate.receiveHostEarliestUs <=
            UINT64_MAX - Legacy::kMifFreshnessUs) {
            observation.freshnessUntilUs = candidate.receiveHostEarliestUs +
                Legacy::kMifFreshnessUs;
            observation.freshnessUntilValid = true;
        }
        return observation;
    }

    if (observation.status != Legacy::Status::kNoConservativeWindow)
        return observation;

    Geometry geometry{};
    if (!proveLegacyStatus26(in.timing, geometry))
        return observation;
    observation.geometryValid = true;
    observation.receiveHostEarliestUs = geometry.receiveHostEarliestUs;
    observation.receiveHostLatestUs = geometry.receiveHostLatestUs;
    observation.targetAwStartOffsetUs =
        -static_cast<int32_t>(geometry.elapsedWithinCurrentAwUs);
    observation.beforeRxUs = geometry.elapsedWithinCurrentAwUs;
    observation.selectedRelation =
        TargetAwRelation::kCurrentAwStartedBeforeMifRx;
    observation.selectedRelationValid = true;
    observation.forwardDeltaValid = false;
    if (geometry.receiveHostEarliestUs <=
        UINT64_MAX - Legacy::kMifFreshnessUs) {
        observation.freshnessUntilUs = geometry.receiveHostEarliestUs +
            Legacy::kMifFreshnessUs;
        observation.freshnessUntilValid = true;
    }

    Window window{};
    RejectReason windowReason = RejectReason::kNotAttempted;
    if (calculateWindow(geometry.receiveHostEarliestUs,
                        geometry.receiveHostLatestUs,
                        geometry.elapsedWithinCurrentAwUs,
                        window, windowReason)) {
        observation.earliestSubmitUs = window.earliestSubmitUs;
        observation.latestSubmitUs = window.latestSubmitUs;
        observation.windowValid = true;
    } else if (observation.why == RejectReason::kNotAttempted) {
        observation.why = windowReason;
    }
    // `candidateAvailable` deliberately remains false for every status-26
    // rejection, even when the diagnostic geometry/window itself is valid.
    return observation;
}

} // namespace NativeAwdlMifCurrentAw

#endif // NATIVE_AWDL_MIF_CURRENT_AW_FALLBACK_HPP
