// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DISCOVERY_PHASE_EXPERIMENT_HPP
#define NATIVE_AWDL_DISCOVERY_PHASE_EXPERIMENT_HPP

#include <stdint.h>

namespace NativeAwdlDiscoveryPhase {

constexpr uint64_t kTuUs = 1024ULL;
constexpr uint64_t kMaximumPsfAgeUs = 200000ULL;
constexpr uint32_t kMaximumAnchorToRxUs = 900000U;
constexpr uint64_t kMaximumAnchorBracketUs = 5000ULL;
constexpr uint64_t kLeaseReserveUs = 20000ULL;
constexpr uint32_t kGp2HalfRangeUs = 0x80000000U;
constexpr uint8_t kSlotCount = 16;
constexpr uint8_t kRequiredPresenceMode = 4;
constexpr uint16_t kRequiredAwPeriodTu = 16;
constexpr uint16_t kFirstAwLengthTu = 16;
constexpr uint16_t kAwEdgeGuardTu = 3;
constexpr uint8_t kLocalSocialChannel = 6;

struct Epochs {
    uint64_t context;
    uint64_t power;
    uint64_t station;
    uint64_t roc;
};

// A complete PSF snapshot belongs to one tracked peer incarnation and one
// canonical schedule revision. The caller supplies the provenance; this
// header does not parse frames, inspect a device, or infer peer identity.
struct PsfWitness {
    uint64_t peerToken;
    uint64_t scheduleRevision;
    Epochs epochs;
    uint64_t rxHostUs;
    uint32_t rxGp2;
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    uint16_t awCounter;
    uint16_t txDownTu;
    uint16_t awPeriodTu;
    uint8_t presenceMode;
    uint8_t rxChannel;
    uint8_t canonicalChannels[kSlotCount];
    bool complete;
};

// These opaque scalar identifiers must be minted by the caller's peer table.
// They are observation-scoped incarnation/revision tags, not addresses.
// `snapshot` is re-read under the caller's serialization gate and compared
// field-for-field with the PSF used to estimate the candidate.
struct PeerSnapshotWitness {
    PsfWitness snapshot;
    bool peerStillCurrent;
};

// Must describe a direct GP2 register read taken before ROC activation while
// firmware resources were absent. The matching epochs are caller witnesses.
struct PreRocGp2Anchor {
    uint64_t hostBeforeUs;
    uint64_t hostAfterUs;
    uint32_t rawGp2;
    Epochs epochs;
    bool directReadBracket;
    bool occurredBeforeRoc;
    bool firmwareResourcesAbsent;
};

struct Input {
    PsfWitness psf;
    PeerSnapshotWitness current;
    PreRocGp2Anchor preRocAnchor;
    uint64_t nowUs;
    uint64_t leaseStartUs;
    uint64_t leaseEndUs;
    uint8_t localRocChannel;
};

enum class Status : uint8_t {
    kEstimatedCandidate = 0,
    kInvalidArgument,
    kIncompletePsf,
    kStalePsf,
    kPeerIncarnationMismatch,
    kScheduleRevisionMismatch,
    kEpochMismatch,
    kCurrentSnapshotMismatch,
    kInvalidPreRocAnchor,
    kResourcesPresentAtAnchor,
    kInvalidAnchorBracket,
    kAnchorBracketTooWide,
    kAnchorAfterPsf,
    kGp2HalfRangeAmbiguous,
    kAnchorToRxTooOld,
    kInvalidPsfTiming,
    kInvalidSchedule,
    kNoLocalChannel6NextSlot,
    kArithmeticOverflow,
    kNoConservativeWindow,
    kLeaseTooShort,
    kCandidateNotInLease,
    kCandidateAlreadyExpired,
    kZeroEpoch
};

inline bool samePsfWitness(const PsfWitness &left,
                           const PsfWitness &right)
{
    if (left.peerToken != right.peerToken ||
        left.scheduleRevision != right.scheduleRevision ||
        left.epochs.context != right.epochs.context ||
        left.epochs.power != right.epochs.power ||
        left.epochs.station != right.epochs.station ||
        left.epochs.roc != right.epochs.roc ||
        left.rxHostUs != right.rxHostUs || left.rxGp2 != right.rxGp2 ||
        left.phyTxTimestampUs != right.phyTxTimestampUs ||
        left.targetTxTimestampUs != right.targetTxTimestampUs ||
        left.awCounter != right.awCounter ||
        left.txDownTu != right.txDownTu ||
        left.awPeriodTu != right.awPeriodTu ||
        left.presenceMode != right.presenceMode ||
        left.rxChannel != right.rxChannel || left.complete != right.complete)
        return false;
    for (uint8_t slot = 0; slot < kSlotCount; ++slot) {
        if (left.canonicalChannels[slot] != right.canonicalChannels[slot])
            return false;
    }
    return true;
}

// The interval is half-open [earliestSubmitUs, latestSubmitUs). It is an
// estimated candidate only. In particular, the helper does not establish a
// verified GP2/host clock map, peer synchronization, an RF airtime bound, or
// delivery. The caller must keep its existing peer, ROC, DMA, unicast, and
// kernel-safety gates in force.
struct EstimatedTarget {
    uint64_t earliestSubmitUs;
    uint64_t latestSubmitUs;
    uint32_t targetGp2Raw;
    uint64_t peerToken;
    uint64_t scheduleRevision;
    Epochs epochs;
    Status status;
    bool clockMappingVerified;
    bool airtimeVerified;
    bool experimentalOnly;
};

// Estimates one candidate for the first 16-TU AW at the next EAW boundary.
// The schedule's next slot is floor(awCounter/4)+1 modulo 16; next-AW channel
// hints are intentionally not part of this API. `output` is untouched on all
// failures. The GP2 anchor is only consumed as immutable input and must have
// been sampled before ROC with firmware resources absent; callers must never
// read GP2 while ROC is active for this experiment.
inline Status estimateTarget(const Input &input, EstimatedTarget &output)
{
    const PsfWitness &psf = input.psf;
    const PeerSnapshotWitness &current = input.current;
    const PsfWitness &currentPsf = current.snapshot;
    const PreRocGp2Anchor &anchor = input.preRocAnchor;

    if (!current.peerStillCurrent || currentPsf.peerToken == 0 ||
        currentPsf.scheduleRevision == 0 || input.nowUs == 0 ||
        input.leaseStartUs >= input.leaseEndUs ||
        input.localRocChannel != kLocalSocialChannel)
        return Status::kInvalidArgument;
    if (currentPsf.epochs.context == 0 || currentPsf.epochs.power == 0 ||
        currentPsf.epochs.station == 0 || currentPsf.epochs.roc == 0)
        return Status::kZeroEpoch;

    if (!psf.complete)
        return Status::kIncompletePsf;
    if (psf.peerToken == 0 || psf.scheduleRevision == 0 ||
        psf.rxHostUs == 0 || psf.rxHostUs > input.nowUs ||
        input.nowUs - psf.rxHostUs > kMaximumPsfAgeUs)
        return Status::kStalePsf;
    if (psf.peerToken != currentPsf.peerToken)
        return Status::kPeerIncarnationMismatch;
    if (psf.scheduleRevision != currentPsf.scheduleRevision)
        return Status::kScheduleRevisionMismatch;
    if (psf.epochs.context != currentPsf.epochs.context ||
        psf.epochs.power != currentPsf.epochs.power ||
        psf.epochs.station != currentPsf.epochs.station ||
        psf.epochs.roc != currentPsf.epochs.roc ||
        anchor.epochs.context != currentPsf.epochs.context ||
        anchor.epochs.power != currentPsf.epochs.power ||
        anchor.epochs.station != currentPsf.epochs.station ||
        anchor.epochs.roc != currentPsf.epochs.roc)
        return Status::kEpochMismatch;
    if (!samePsfWitness(psf, currentPsf))
        return Status::kCurrentSnapshotMismatch;

    if (!anchor.directReadBracket || !anchor.occurredBeforeRoc)
        return Status::kInvalidPreRocAnchor;
    if (!anchor.firmwareResourcesAbsent)
        return Status::kResourcesPresentAtAnchor;
    if (anchor.hostAfterUs < anchor.hostBeforeUs)
        return Status::kInvalidAnchorBracket;
    if (anchor.hostAfterUs - anchor.hostBeforeUs >
        kMaximumAnchorBracketUs)
        return Status::kAnchorBracketTooWide;
    if (anchor.hostAfterUs > psf.rxHostUs || anchor.hostAfterUs > input.nowUs)
        return Status::kAnchorAfterPsf;

    const uint32_t anchorToRxUs = psf.rxGp2 - anchor.rawGp2;
    if (anchorToRxUs >= kGp2HalfRangeUs)
        return Status::kGp2HalfRangeAmbiguous;
    if (anchorToRxUs >= kMaximumAnchorToRxUs)
        return Status::kAnchorToRxTooOld;

    if (psf.presenceMode != kRequiredPresenceMode ||
        psf.awPeriodTu != kRequiredAwPeriodTu || psf.txDownTu == 0 ||
        psf.txDownTu > 64 || psf.rxChannel != kLocalSocialChannel)
        return Status::kInvalidPsfTiming;

    // Modular subtraction allows the timestamps themselves to wrap, while
    // rejecting a backwards/ambiguous delta and implausibly distant fields.
    const uint32_t phyMinusTarget =
        psf.phyTxTimestampUs - psf.targetTxTimestampUs;
    if (phyMinusTarget >= kGp2HalfRangeUs || phyMinusTarget >= 65536U ||
        static_cast<uint64_t>(psf.txDownTu) * kTuUs < phyMinusTarget)
        return Status::kInvalidPsfTiming;

    const uint8_t nextSlot = static_cast<uint8_t>(
        ((psf.awCounter / kRequiredPresenceMode) + 1U) % kSlotCount);
    for (uint8_t slot = 0; slot < kSlotCount; ++slot) {
        // Channel zero denotes an unserved canonical slot. Other entries are
        // IEEE 802.11 channel numbers; reject out-of-domain byte values.
        if (psf.canonicalChannels[slot] > 233)
            return Status::kInvalidSchedule;
    }
    if (psf.canonicalChannels[nextSlot] != kLocalSocialChannel)
        return Status::kNoLocalChannel6NextSlot;

    const uint64_t downUs = static_cast<uint64_t>(psf.txDownTu) * kTuUs;
    const uint64_t correctedDownUs = downUs - phyMinusTarget;
    const uint64_t boundaryDeltaUs =
        static_cast<uint64_t>(anchorToRxUs) + correctedDownUs;
    const uint64_t firstAwStartDeltaUs =
        boundaryDeltaUs +
        static_cast<uint64_t>(kAwEdgeGuardTu + 1U) * kTuUs;
    const uint64_t firstAwEndDeltaUs =
        boundaryDeltaUs +
        static_cast<uint64_t>(kFirstAwLengthTu - kAwEdgeGuardTu - 1U) *
            kTuUs;
    if (firstAwStartDeltaUs < boundaryDeltaUs ||
        firstAwEndDeltaUs < boundaryDeltaUs)
        return Status::kArithmeticOverflow;

    uint64_t earliestSubmitUs = 0;
    uint64_t latestSubmitUs = 0;
    if (anchor.hostAfterUs > UINT64_MAX - firstAwStartDeltaUs ||
        anchor.hostBeforeUs > UINT64_MAX - firstAwEndDeltaUs)
        return Status::kArithmeticOverflow;

    // Conservative interval arithmetic: latest possible boundary for the
    // earliest submit bound; earliest possible boundary for the exclusive
    // upper bound. The extra TU on each side represents an explicit, unproven
    // +/- one-TU quantization assumption.
    earliestSubmitUs = anchor.hostAfterUs + firstAwStartDeltaUs;
    latestSubmitUs = anchor.hostBeforeUs + firstAwEndDeltaUs;
    if (earliestSubmitUs >= latestSubmitUs)
        return Status::kNoConservativeWindow;

    // Check the entire candidate against the strict half-open lease, retaining
    // the fixed 20 ms reserve for the existing caller-side ROC/DMA guards.
    if (input.leaseEndUs < kLeaseReserveUs)
        return Status::kLeaseTooShort;
    const uint64_t usableLeaseEndUs = input.leaseEndUs - kLeaseReserveUs;
    if (input.leaseStartUs >= usableLeaseEndUs)
        return Status::kLeaseTooShort;
    if (earliestSubmitUs < input.leaseStartUs ||
        latestSubmitUs > usableLeaseEndUs)
        return Status::kCandidateNotInLease;
    if (input.nowUs >= latestSubmitUs)
        return Status::kCandidateAlreadyExpired;

    EstimatedTarget candidate{};
    candidate.earliestSubmitUs = earliestSubmitUs;
    candidate.latestSubmitUs = latestSubmitUs;
    candidate.targetGp2Raw = psf.rxGp2 +
        static_cast<uint32_t>(correctedDownUs +
            static_cast<uint64_t>(kFirstAwLengthTu / 2U) * kTuUs);
    candidate.peerToken = psf.peerToken;
    candidate.scheduleRevision = psf.scheduleRevision;
    candidate.epochs = psf.epochs;
    candidate.status = Status::kEstimatedCandidate;
    candidate.clockMappingVerified = false;
    candidate.airtimeVerified = false;
    candidate.experimentalOnly = true;
    output = candidate;
    return Status::kEstimatedCandidate;
}

} // namespace NativeAwdlDiscoveryPhase

#endif // NATIVE_AWDL_DISCOVERY_PHASE_EXPERIMENT_HPP
