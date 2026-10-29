// SPDX-License-Identifier: GPL-2.0-only
#ifndef TEST066_AWDL_MIF_CURRENT_PHASE_HPP
#define TEST066_AWDL_MIF_CURRENT_PHASE_HPP

#include <stdint.h>

// Private, pure estimate-only timing candidate for Test066. This is not wired
// into the driver and is deliberately independent of the legacy PSF-next-slot
// estimator. The caller must supply one coherent same-entry MIF snapshot and
// separately retain the existing admission, ROC, queue, and one-shot gates.
namespace Test066MifCurrentPhase {

constexpr uint64_t kTuUs = 1024ULL;
constexpr uint64_t kMifFreshnessUs = 16ULL * kTuUs;
constexpr uint64_t kMaximumMifAgeUs = 5000000ULL;
constexpr uint32_t kMaximumAnchorToMifUs = 900000U;
constexpr uint32_t kGp2HalfRangeUs = 0x80000000U;
constexpr uint64_t kMaximumAnchorBracketUs = 5000ULL;
constexpr uint64_t kLeaseReserveUs = 20000ULL;
constexpr uint16_t kExpectedAwPeriodTu = 16;
constexpr uint8_t kExpectedPresenceMode = 4;
constexpr uint8_t kSlotCount = 16;
constexpr uint8_t kLocalChannel = 6;
constexpr uint8_t kAwPerEaw = 4;
constexpr uint16_t kEawPeriodTu = 64;
constexpr uint16_t kEdgeGuardTu = 3;
constexpr uint16_t kQuantizationGuardTu = 1;

struct Epochs {
    uint64_t context;
    uint64_t power;
    uint64_t station;
    uint64_t roc;
};

struct MifTimingWitness {
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    uint64_t rxMonotonicUs;
    Epochs epochs;
    uint32_t rxGp2Us;
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    // Test fixture maps decoded MIF nextAwSequence to this current AW counter.
    // The caller must set awCounterSemanticVerified only after verifying that
    // source mapping; the helper never derives it from PSF or nextAwChannel.
    uint16_t awCounter;
    uint16_t txDownCounterTu;
    uint16_t awPeriodTu;
    uint8_t presenceMode;
    uint16_t rxChannel; // Raw channel index; mapped-to-6 proof is separate.
    uint8_t canonicalSlots[kSlotCount];
    bool present;
    bool complete;
    bool syncConsistent;
    bool fresh;
    bool rxGp2Present;
    bool presenceModePresent;
    bool awCounterSemanticVerified;
    bool type18Present;
    bool type18Valid;
};

struct PreRocGp2Anchor {
    uint64_t hostBeforeUs;
    uint64_t hostAfterUs;
    uint32_t rawGp2Us;
    Epochs epochs;
    bool directReadBracket;
    bool occurredBeforeRoc;
    bool firmwareResourcesAbsent;
};

struct RuntimeMifBinding {
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    Epochs epochs;
    bool sameEntryVerified;
    bool historicalPsfSameEntryPresent;
};

struct ModeGates {
    bool explicitlyEnabled;
    bool hostMonotonicDomainVerified;
    bool ownMifTxSucceeded;
    bool rocActive;
    bool rocChannel6Confirmed;
    bool peerMifRxChannel6Confirmed;
    bool closing;
    bool ringIdle;
    bool strictQmHeadStable;
    uint64_t firstOwnMifCompletionUs;
};

struct Input {
    MifTimingWitness mif;
    PreRocGp2Anchor anchor;
    RuntimeMifBinding binding;
    Epochs currentEpochs;
    ModeGates gates;
    uint64_t nowUs;
    uint64_t leaseStartUs;
    uint64_t leaseEndUs;
    uint8_t localRocChannel;
};

enum class Status : uint8_t {
    kCandidate = 0,
    kInvalidInput,
    kModeNotEnabled,
    kTimeSourceUnverified,
    kPrerequisiteMissing,
    kInvalidEpoch,
    kEpochMismatch,
    kMissingBinding,
    kBindingMismatch,
    kMissingMif,
    kIncompleteMif,
    kInvalidMif,
    kStaleMif,
    kInvalidAnchor,
    kAnchorBracket,
    kAnchorTooWide,
    kAnchorAfterMif,
    kProjectedRxAfterTap,
    kGp2HalfRange,
    kAnchorToMifTooOld,
    kInvalidTiming,
    kInvalidSchedule,
    kWrongCurrentSlotChannel,
    kNoFollowingAwInCurrentSlot,
    kFutureAwOutOfRange,
    kArithmeticOverflow,
    kNoConservativeWindow,
    kLeaseInvalid,
    kLeaseReserve,
    kCandidateOutsideLease,
    kCandidateExpired,
    kOwnMifNotCompletedBeforeWindow
};

struct Candidate {
    uint64_t earliestSubmitUs;
    uint64_t latestSubmitUs; // Exclusive.
    uint64_t receiveHostEarliestUs;
    uint64_t receiveHostLatestUs;
    uint64_t targetAwStartDeltaUs;
    uint32_t targetAwStartGp2Us;
    uint32_t nextEawGp2Us;
    uint32_t currentEawStartGp2Us;
    uint8_t currentSlot;
    uint16_t targetAwCounter;
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    Epochs epochs;
    Status status;
    bool clockMappingVerified;
    bool airtimeVerified;
    bool experimentalOnly;
};

inline bool sameEpochs(const Epochs &a, const Epochs &b)
{
    return a.context == b.context && a.power == b.power &&
           a.station == b.station && a.roc == b.roc;
}

inline bool nonzeroEpochs(const Epochs &e)
{
    return e.context != 0 && e.power != 0 && e.station != 0 && e.roc != 0;
}

inline uint32_t forwardDeltaGp2(uint32_t later, uint32_t earlier)
{
    return later - earlier;
}

// Compute the conservative current-MIF-slot window for the next AW, only when
// that AW remains inside the same slot. The resulting interval is half-open.
// The helper fails closed and leaves `output` untouched on every rejection.
inline Status plan(const Input &in, Candidate &output)
{
    const MifTimingWitness &mif = in.mif;
    const PreRocGp2Anchor &anchor = in.anchor;

    if (!in.nowUs || !in.leaseStartUs || in.leaseStartUs >= in.leaseEndUs ||
        in.nowUs < in.leaseStartUs || in.nowUs >= in.leaseEndUs ||
        in.localRocChannel != kLocalChannel)
        return Status::kInvalidInput;
    if (!in.gates.explicitlyEnabled)
        return Status::kModeNotEnabled;
    if (!in.gates.hostMonotonicDomainVerified)
        return Status::kTimeSourceUnverified;
    if (!in.gates.ownMifTxSucceeded || !in.gates.rocActive ||
        !in.gates.rocChannel6Confirmed ||
        !in.gates.peerMifRxChannel6Confirmed || in.gates.closing ||
        !in.gates.ringIdle || !in.gates.strictQmHeadStable)
        return Status::kPrerequisiteMissing;
    if (!nonzeroEpochs(in.currentEpochs) || !nonzeroEpochs(mif.epochs) ||
        !nonzeroEpochs(anchor.epochs) || !nonzeroEpochs(in.binding.epochs))
        return Status::kInvalidEpoch;
    if (!sameEpochs(in.currentEpochs, mif.epochs) ||
        !sameEpochs(in.currentEpochs, anchor.epochs) ||
        !sameEpochs(in.currentEpochs, in.binding.epochs))
        return Status::kEpochMismatch;
    if (!in.binding.sameEntryVerified ||
        !in.binding.historicalPsfSameEntryPresent)
        return Status::kMissingBinding;
    if (!mif.peerIncarnation || !mif.mifRevision ||
        in.binding.peerIncarnation != mif.peerIncarnation ||
        in.binding.mifRevision != mif.mifRevision)
        return Status::kBindingMismatch;
    if (!mif.present)
        return Status::kMissingMif;
    if (!mif.complete || !mif.type18Present || !mif.type18Valid ||
        !mif.presenceModePresent || !mif.awCounterSemanticVerified)
        return Status::kIncompleteMif;
    if (!mif.syncConsistent || !mif.rxGp2Present || !mif.fresh ||
        !mif.rxMonotonicUs || mif.rxMonotonicUs > in.nowUs ||
        in.nowUs - mif.rxMonotonicUs > kMaximumMifAgeUs)
        return Status::kStaleMif;
    if (!anchor.directReadBracket || !anchor.occurredBeforeRoc ||
        !anchor.firmwareResourcesAbsent || !anchor.hostBeforeUs ||
        !anchor.hostAfterUs)
        return Status::kInvalidAnchor;
    if (anchor.hostAfterUs < anchor.hostBeforeUs)
        return Status::kAnchorBracket;
    if (anchor.hostAfterUs - anchor.hostBeforeUs > kMaximumAnchorBracketUs)
        return Status::kAnchorTooWide;
    if (anchor.hostAfterUs > mif.rxMonotonicUs ||
        mif.rxMonotonicUs > in.nowUs)
        return Status::kAnchorAfterMif;

    const uint32_t anchorToRxUs =
        forwardDeltaGp2(mif.rxGp2Us, anchor.rawGp2Us);
    if (anchorToRxUs >= kGp2HalfRangeUs)
        return Status::kGp2HalfRange;
    if (anchorToRxUs >= kMaximumAnchorToMifUs)
        return Status::kAnchorToMifTooOld;

    if (mif.presenceMode != kExpectedPresenceMode ||
        mif.awPeriodTu != kExpectedAwPeriodTu ||
        mif.txDownCounterTu == 0 || mif.txDownCounterTu > kEawPeriodTu)
        return Status::kInvalidTiming;
    const uint32_t phyMinusTarget =
        mif.phyTxTimestampUs - mif.targetTxTimestampUs;
    const uint64_t downUs =
        static_cast<uint64_t>(mif.txDownCounterTu) * kTuUs;
    if (phyMinusTarget >= kGp2HalfRangeUs || phyMinusTarget >= 65536U ||
        phyMinusTarget > downUs)
        return Status::kInvalidTiming;

    const uint8_t currentSlot = static_cast<uint8_t>(
        (mif.awCounter / kAwPerEaw) % kSlotCount);
    for (uint8_t slot = 0; slot < kSlotCount; ++slot) {
        if (mif.canonicalSlots[slot] > 233)
            return Status::kInvalidSchedule;
    }
    if (mif.canonicalSlots[currentSlot] != kLocalChannel)
        return Status::kWrongCurrentSlotChannel;
    const uint8_t awWithinEaw = static_cast<uint8_t>(mif.awCounter % kAwPerEaw);
    if (awWithinEaw + 1U >= kAwPerEaw)
        return Status::kNoFollowingAwInCurrentSlot;

    const uint64_t correctedDownUs = downUs - phyMinusTarget;
    const uint32_t nextEawGp2 = mif.rxGp2Us +
        static_cast<uint32_t>(correctedDownUs);
    const uint32_t currentEawStartGp2 = nextEawGp2 -
        static_cast<uint32_t>(kEawPeriodTu * kTuUs);
    const uint8_t nextAwIndex = static_cast<uint8_t>(awWithinEaw + 1U);
    const uint32_t targetAwStartGp2 = currentEawStartGp2 +
        static_cast<uint32_t>(nextAwIndex * kExpectedAwPeriodTu * kTuUs);
    const uint32_t targetAwStartDeltaUs =
        forwardDeltaGp2(targetAwStartGp2, mif.rxGp2Us);
    if (targetAwStartDeltaUs >= kGp2HalfRangeUs ||
        targetAwStartDeltaUs >= kExpectedAwPeriodTu * kTuUs)
        return Status::kFutureAwOutOfRange;

    const uint64_t innerStartUs = static_cast<uint64_t>(
        kEdgeGuardTu + kQuantizationGuardTu) * kTuUs;
    const uint64_t innerEndUs = static_cast<uint64_t>(
        kExpectedAwPeriodTu - kEdgeGuardTu - kQuantizationGuardTu) * kTuUs;
    const uint64_t candidateStartDeltaUs =
        static_cast<uint64_t>(targetAwStartDeltaUs) + innerStartUs;
    const uint64_t candidateEndDeltaUs =
        static_cast<uint64_t>(targetAwStartDeltaUs) + innerEndUs;

    if (anchor.hostAfterUs > UINT64_MAX - anchorToRxUs ||
        anchor.hostBeforeUs > UINT64_MAX - anchorToRxUs)
        return Status::kArithmeticOverflow;
    const uint64_t receiveHostEarliestUs =
        anchor.hostBeforeUs + anchorToRxUs;
    const uint64_t receiveHostLatestUs =
        anchor.hostAfterUs + anchorToRxUs;
    // Every host time in this bracket is a possible projected RX time. The
    // RX tap is recorded after reception, so even the conservative latest
    // projection must not be later than that same-domain tap.
    if (receiveHostLatestUs > mif.rxMonotonicUs)
        return Status::kProjectedRxAfterTap;
    if (receiveHostLatestUs > UINT64_MAX - candidateStartDeltaUs ||
        receiveHostEarliestUs > UINT64_MAX - candidateEndDeltaUs ||
        receiveHostEarliestUs > UINT64_MAX - kMifFreshnessUs)
        return Status::kArithmeticOverflow;

    const uint64_t earliestSubmitUs =
        receiveHostLatestUs + candidateStartDeltaUs;
    const uint64_t phaseLatestUs =
        receiveHostEarliestUs + candidateEndDeltaUs;
    const uint64_t freshUntilUs = receiveHostEarliestUs + kMifFreshnessUs;
    const uint64_t latestSubmitUs = phaseLatestUs < freshUntilUs ?
        phaseLatestUs : freshUntilUs;
    if (earliestSubmitUs >= latestSubmitUs)
        return Status::kNoConservativeWindow;
    if (!in.gates.firstOwnMifCompletionUs ||
        in.gates.firstOwnMifCompletionUs >= earliestSubmitUs)
        return Status::kOwnMifNotCompletedBeforeWindow;

    if (in.leaseEndUs <= kLeaseReserveUs ||
        in.leaseEndUs - in.nowUs <= kLeaseReserveUs)
        return Status::kLeaseReserve;
    const uint64_t usableLeaseEndUs = in.leaseEndUs - kLeaseReserveUs;
    if (earliestSubmitUs < in.leaseStartUs ||
        latestSubmitUs > usableLeaseEndUs)
        return Status::kCandidateOutsideLease;
    if (in.nowUs >= latestSubmitUs)
        return Status::kCandidateExpired;

    Candidate candidate{};
    candidate.earliestSubmitUs = earliestSubmitUs;
    candidate.latestSubmitUs = latestSubmitUs;
    candidate.receiveHostEarliestUs = receiveHostEarliestUs;
    candidate.receiveHostLatestUs = receiveHostLatestUs;
    candidate.targetAwStartDeltaUs = targetAwStartDeltaUs;
    candidate.targetAwStartGp2Us = targetAwStartGp2;
    candidate.nextEawGp2Us = nextEawGp2;
    candidate.currentEawStartGp2Us = currentEawStartGp2;
    candidate.currentSlot = currentSlot;
    candidate.targetAwCounter = static_cast<uint16_t>(mif.awCounter + 1U);
    candidate.peerIncarnation = mif.peerIncarnation;
    candidate.mifRevision = mif.mifRevision;
    candidate.epochs = mif.epochs;
    candidate.status = Status::kCandidate;
    candidate.clockMappingVerified = false;
    candidate.airtimeVerified = false;
    candidate.experimentalOnly = true;
    output = candidate;
    return Status::kCandidate;
}

} // namespace Test066MifCurrentPhase

#endif // TEST066_AWDL_MIF_CURRENT_PHASE_HPP
