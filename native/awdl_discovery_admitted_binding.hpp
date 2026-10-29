// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DISCOVERY_ADMITTED_BINDING_HPP
#define NATIVE_AWDL_DISCOVERY_ADMITTED_BINDING_HPP

#include "awdl_data_tx_observation.hpp"
#include "awdl_discovery_phase_experiment.hpp"

#include <stdint.h>

namespace NativeAwdlDiscoveryBinding {

constexpr uint64_t kPsfLeaseUs = NativeAwdlDiscoveryPhase::kMaximumPsfAgeUs;
constexpr uint64_t kPsfHistoryLeaseUs = 60ULL * 1000ULL * 1000ULL;
constexpr uint64_t kMifLeaseUs = 5000000ULL;
constexpr uint8_t kSocialChannel6 = 6;

struct Epochs {
    uint64_t context;
    uint64_t power;
    uint64_t station;
    uint64_t roc;
};

enum class Mode : uint8_t {
    kPsfNextSlot = 0,
    kMifCurrentSlot = 1
};

// Runtime-verified MIF pairing fields copied from one private table Entry.
// The ROC epoch is bound by the serialized consumer for its current window;
// the other three epochs are copied from that same Entry.
struct MifWitness {
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    uint64_t rxMonotonicUs;
    uint64_t rxAgeUs;
    Epochs epochs;
    uint32_t rxGp2Us;
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;
    uint16_t awCounter;
    uint16_t txDownCounterTu;
    uint16_t awPeriodTu;
    uint8_t presenceMode;
    uint16_t rxChannel;
    uint8_t canonicalSlots[16];
    bool present;
    bool complete;
    bool syncConsistent;
    bool fresh;
    bool rxGp2Present;
    bool presenceModePresent;
    bool awCounterSemanticVerified;
    bool type18Present;
    bool type18Valid;
    bool peerMifRxChannel6Confirmed; // Consumer maps raw driver RX index.
};

// One immutable read from the private runtime table. MIF and PSF details are
// copied from the same internal Entry; no source address crosses this API.
struct Snapshot {
    Mode mode;
    bool psfHistorySameEntryPresent;
    bool historyCompatible;
    NativeAwdlDiscoveryPhase::PsfWitness psf;
    MifWitness mif;
    uint64_t peerIncarnation;
    uint64_t psfRevision;
    uint64_t mifRevision;
    uint64_t mifRxMonotonicUs;
    uint64_t mifAgeUs;
    uint64_t psfAgeUs;
    bool hasMif;
    bool mifFresh;
    bool mifSyncConsistent;
    bool mifRxChannel6;
};

struct QueueHead {
    uint64_t token;
    uint64_t bornUs;
    uint32_t generation;
    uint8_t queryClass;
    bool eligible;
};

struct Window {
    Mode mode;
    Epochs epochs;
    uint64_t nowUs;
    uint64_t leaseStartUs;
    uint64_t leaseEndUs;
    uint64_t phaseEarliestUs;
    uint64_t phaseLatestUs;
    bool requireRuntimeMifBinding;
    bool phaseCandidateValid;
    bool rocActive;
    bool windowOpen;
    bool closing;
};

enum class Decision : uint8_t {
    kReady = 0,
    kInvalidSnapshot = 1,
    kModeMismatch = 2,
    kMissingMifBinding = 3,
    kIncompleteMifWitness = 4,
    kMifWitnessMismatch = 5,
    kWindowChanged = 6,
    kStalePsf = 7,
    kStaleMif = 8,
    kEpochMismatch = 9,
    kChannelMismatch = 10,
    kNoChannel6NextSlot = 11,
    kQueueHeadInvalid = 12,
    kWindowClosed = 13,
    kRocInactive = 14,
    kLeaseOutside = 15,
    kPhaseNotYetOpen = 16,
    kPhaseExpired = 17,
    kInvalidPhaseCandidate = 18,
    kNotLocked = 19,
    kPeerIncarnationChanged = 20,
    kPsfRevisionChanged = 21,
    kMifRevisionChanged = 22,
    kPsfWitnessChanged = 23,
    kQueueHeadChanged = 24,
    kAlreadyAttempted = 25,
    kHistoryIncompatible = 26
};

inline bool sameEpochs(const Epochs &left, const Epochs &right)
{
    return left.context == right.context && left.power == right.power &&
           left.station == right.station && left.roc == right.roc;
}

inline bool nonzeroEpochs(const Epochs &epochs)
{
    return epochs.context != 0 && epochs.power != 0 &&
           epochs.station != 0 && epochs.roc != 0;
}

inline bool sameQueueHead(const QueueHead &left, const QueueHead &right)
{
    return left.token == right.token && left.bornUs == right.bornUs &&
           left.generation == right.generation &&
           left.queryClass == right.queryClass &&
           left.eligible == right.eligible;
}

inline bool sameMifWitness(const MifWitness &left, const MifWitness &right)
{
    if (left.peerIncarnation != right.peerIncarnation ||
        left.mifRevision != right.mifRevision ||
        left.rxMonotonicUs != right.rxMonotonicUs ||
        left.epochs.context != right.epochs.context ||
        left.epochs.power != right.epochs.power ||
        left.epochs.station != right.epochs.station ||
        left.epochs.roc != right.epochs.roc ||
        left.rxGp2Us != right.rxGp2Us ||
        left.phyTxTimestampUs != right.phyTxTimestampUs ||
        left.targetTxTimestampUs != right.targetTxTimestampUs ||
        left.awCounter != right.awCounter ||
        left.txDownCounterTu != right.txDownCounterTu ||
        left.awPeriodTu != right.awPeriodTu ||
        left.presenceMode != right.presenceMode ||
        left.rxChannel != right.rxChannel ||
        left.present != right.present || left.complete != right.complete ||
        left.syncConsistent != right.syncConsistent ||
        left.fresh != right.fresh ||
        left.rxGp2Present != right.rxGp2Present ||
        left.presenceModePresent != right.presenceModePresent ||
        left.awCounterSemanticVerified != right.awCounterSemanticVerified ||
        left.type18Present != right.type18Present ||
        left.type18Valid != right.type18Valid ||
        left.peerMifRxChannel6Confirmed != right.peerMifRxChannel6Confirmed)
        return false;
    for (uint8_t slot = 0; slot < 16; ++slot) {
        if (left.canonicalSlots[slot] != right.canonicalSlots[slot])
            return false;
    }
    return true;
}

inline bool sameLockedSnapshot(const Snapshot &left, const Snapshot &right,
                               Mode mode, bool requireRuntimeMifBinding)
{
    if (left.mode != right.mode || left.mode != mode ||
        left.psfHistorySameEntryPresent != right.psfHistorySameEntryPresent ||
        left.peerIncarnation != right.peerIncarnation ||
        left.psfRevision != right.psfRevision ||
        left.psf.peerToken != right.psf.peerToken ||
        left.psf.scheduleRevision != right.psf.scheduleRevision ||
        !NativeAwdlDiscoveryPhase::samePsfWitness(left.psf, right.psf))
        return false;
    if (mode == Mode::kPsfNextSlot && !requireRuntimeMifBinding)
        return true;
    if (mode == Mode::kMifCurrentSlot &&
        left.historyCompatible != right.historyCompatible)
        return false;
    if (!left.psfHistorySameEntryPresent ||
        !right.psfHistorySameEntryPresent || !left.hasMif || !right.hasMif ||
        left.mifRevision == 0 || left.mifRevision != right.mifRevision ||
        left.mifRxMonotonicUs != right.mifRxMonotonicUs)
        return false;
    if (mode == Mode::kPsfNextSlot)
        return true;
    return sameMifWitness(left.mif, right.mif);
}

inline bool sameLockedWindow(const Window &left, const Window &right)
{
    return left.mode == right.mode && sameEpochs(left.epochs, right.epochs) &&
           left.leaseStartUs == right.leaseStartUs &&
           left.leaseEndUs == right.leaseEndUs &&
           left.phaseEarliestUs == right.phaseEarliestUs &&
           left.phaseLatestUs == right.phaseLatestUs &&
           left.requireRuntimeMifBinding == right.requireRuntimeMifBinding &&
           left.phaseCandidateValid == right.phaseCandidateValid &&
           left.rocActive == right.rocActive &&
           left.windowOpen == right.windowOpen &&
           left.closing == right.closing;
}

inline Decision validate(const Snapshot &snapshot, const QueueHead &head,
                         const Window &window,
                         bool requirePhaseNow = true)
{
    if (!window.windowOpen || window.closing)
        return Decision::kWindowClosed;
    if (snapshot.mode != window.mode)
        return Decision::kModeMismatch;
    if (!window.rocActive)
        return Decision::kRocInactive;
    if (!window.phaseCandidateValid)
        return Decision::kInvalidPhaseCandidate;
    if (!nonzeroEpochs(window.epochs) ||
        snapshot.psf.epochs.context != window.epochs.context ||
        snapshot.psf.epochs.power != window.epochs.power ||
        snapshot.psf.epochs.station != window.epochs.station ||
        snapshot.psf.epochs.roc != window.epochs.roc)
        return Decision::kEpochMismatch;
    if (snapshot.peerIncarnation == 0 || snapshot.psfRevision == 0 ||
        snapshot.psf.peerToken != snapshot.peerIncarnation ||
        snapshot.psf.scheduleRevision != snapshot.psfRevision ||
        (snapshot.mode == Mode::kPsfNextSlot && !snapshot.psf.complete) ||
        snapshot.psf.rxHostUs == 0 ||
        snapshot.psf.rxHostUs > window.nowUs)
        return Decision::kInvalidSnapshot;
    if (window.nowUs - snapshot.psf.rxHostUs != snapshot.psfAgeUs)
        return snapshot.mode == Mode::kPsfNextSlot
            ? Decision::kStalePsf : Decision::kInvalidSnapshot;
    if (snapshot.mode == Mode::kPsfNextSlot) {
        if (snapshot.psfAgeUs > kPsfLeaseUs)
            return Decision::kStalePsf;
        if (snapshot.psf.rxChannel != kSocialChannel6)
            return Decision::kChannelMismatch;
        const uint8_t nextSlot = static_cast<uint8_t>(
            ((snapshot.psf.awCounter / 4u) + 1u) %
            NativeAwdlDiscoveryPhase::kSlotCount);
        if (snapshot.psf.canonicalChannels[nextSlot] != kSocialChannel6)
            return Decision::kNoChannel6NextSlot;
    } else {
        // Here PSF proves only that this opaque peer entry has history. Its
        // timing fields do not enter the MIF phase calculation or 200 ms gate.
        if (!snapshot.psfHistorySameEntryPresent ||
            snapshot.psfAgeUs > kPsfHistoryLeaseUs)
            return Decision::kInvalidSnapshot;
        if (!window.requireRuntimeMifBinding)
            return Decision::kMissingMifBinding;
    }
    if (snapshot.mode == Mode::kPsfNextSlot &&
        window.requireRuntimeMifBinding) {
        if (!snapshot.hasMif || !snapshot.mifFresh ||
            !snapshot.mifSyncConsistent || snapshot.mifRevision == 0 ||
            snapshot.mifRxMonotonicUs == 0 ||
            snapshot.mifRxMonotonicUs > window.nowUs)
            return Decision::kMissingMifBinding;
        if (window.nowUs - snapshot.mifRxMonotonicUs != snapshot.mifAgeUs ||
            snapshot.mifAgeUs > kMifLeaseUs)
            return Decision::kStaleMif;
        if (!snapshot.mifRxChannel6)
            return Decision::kChannelMismatch;
    }
    if (snapshot.mode == Mode::kMifCurrentSlot) {
        const MifWitness &mif = snapshot.mif;
        if (!snapshot.hasMif || !snapshot.psfHistorySameEntryPresent ||
            !mif.present || mif.peerIncarnation != snapshot.peerIncarnation ||
            mif.mifRevision == 0 || mif.mifRevision != snapshot.mifRevision ||
            mif.rxMonotonicUs != snapshot.mifRxMonotonicUs)
            return Decision::kMissingMifBinding;
        if (!snapshot.historyCompatible)
            return Decision::kHistoryIncompatible;
        if (!mif.complete || !mif.syncConsistent || !mif.fresh ||
            !mif.rxGp2Present || !mif.presenceModePresent ||
            !mif.awCounterSemanticVerified || !mif.type18Present ||
            !mif.type18Valid || mif.presenceMode != 4 ||
            mif.awPeriodTu != NativeAwdlDiscoveryPhase::kRequiredAwPeriodTu)
            return Decision::kIncompleteMifWitness;
        if (!mif.peerMifRxChannel6Confirmed)
            return Decision::kChannelMismatch;
        if (mif.rxMonotonicUs == 0 || mif.rxMonotonicUs > window.nowUs ||
            window.nowUs - mif.rxMonotonicUs != snapshot.mifAgeUs ||
            mif.rxAgeUs != snapshot.mifAgeUs ||
            snapshot.mifAgeUs > kMifLeaseUs)
            return Decision::kStaleMif;
        if (!sameEpochs(mif.epochs, window.epochs))
            return Decision::kEpochMismatch;
        if (mif.epochs.context != snapshot.psf.epochs.context ||
            mif.epochs.power != snapshot.psf.epochs.power ||
            mif.epochs.station != snapshot.psf.epochs.station ||
            mif.epochs.roc != snapshot.psf.epochs.roc)
            return Decision::kMifWitnessMismatch;
    }
    if (!head.token || !head.bornUs || !head.generation || !head.eligible ||
        head.queryClass != static_cast<uint8_t>(
            NativeAwdlData::MdnsQueryClass::QmMulticast) ||
        uint64_t(head.generation) != window.epochs.power)
        return Decision::kQueueHeadInvalid;
    if (window.nowUs < window.leaseStartUs ||
        window.nowUs >= window.leaseEndUs ||
        window.leaseStartUs >= window.leaseEndUs)
        return Decision::kLeaseOutside;
    if (window.phaseEarliestUs >= window.phaseLatestUs ||
        window.nowUs >= window.phaseLatestUs)
        return Decision::kPhaseExpired;
    if (requirePhaseNow && window.nowUs < window.phaseEarliestUs)
        return Decision::kPhaseNotYetOpen;
    return Decision::kReady;
}

// Host-testable transaction guard used around the existing exact-head dequeue.
// It reserves no packet and proves no RF result; after one successful reserve,
// no second call can authorize another dequeue in this diagnostic run.
class OneShot {
public:
    OneShot() : locked_(false), attempted_(false), closed_(false),
                requireRuntimeMifBinding_(false), mode_(Mode::kPsfNextSlot),
                snapshot_{}, head_{}, window_{} {}

    Decision lock(const Snapshot &snapshot, const QueueHead &head,
                  const Window &window)
    {
        if (closed_)
            return Decision::kWindowClosed;
        if (locked_ || attempted_)
            return Decision::kAlreadyAttempted;
        const Decision decision = validate(snapshot, head, window, false);
        if (decision != Decision::kReady)
            return decision;
        locked_ = true;
        requireRuntimeMifBinding_ = window.requireRuntimeMifBinding;
        mode_ = window.mode;
        snapshot_ = snapshot;
        head_ = head;
        window_ = window;
        return Decision::kReady;
    }

    Decision authorizeTake(const Snapshot &current, const QueueHead &head,
                           const Window &window)
    {
        if (!locked_)
            return Decision::kNotLocked;
        if (attempted_)
            return Decision::kAlreadyAttempted;
        if (closed_)
            return Decision::kWindowClosed;
        if (window.requireRuntimeMifBinding != requireRuntimeMifBinding_) {
            closed_ = true;
            return Decision::kMissingMifBinding;
        }
        if (window.mode != mode_ || current.mode != mode_) {
            closed_ = true;
            return Decision::kModeMismatch;
        }
        const Decision decision = validate(current, head, window);
        if (decision != Decision::kReady) {
            if (decision != Decision::kPhaseNotYetOpen)
                closed_ = true;
            return decision;
        }
        if (!sameLockedWindow(window_, window)) {
            closed_ = true;
            return Decision::kWindowChanged;
        }
        if (!sameLockedSnapshot(snapshot_, current, mode_,
                                requireRuntimeMifBinding_)) {
            closed_ = true;
            if (snapshot_.peerIncarnation != current.peerIncarnation)
                return Decision::kPeerIncarnationChanged;
            if (snapshot_.psfRevision != current.psfRevision)
                return Decision::kPsfRevisionChanged;
            if (requireRuntimeMifBinding_ && snapshot_.mifRevision != current.mifRevision)
                return Decision::kMifRevisionChanged;
            if (mode_ == Mode::kMifCurrentSlot &&
                !sameMifWitness(snapshot_.mif, current.mif))
                return Decision::kMifWitnessMismatch;
            return Decision::kPsfWitnessChanged;
        }
        if (!sameQueueHead(head_, head)) {
            closed_ = true;
            return Decision::kQueueHeadChanged;
        }
        attempted_ = true;
        closed_ = true;
        return Decision::kReady;
    }

    bool attempted() const { return attempted_; }

    // A phase-not-yet-open check keeps the exact reservation pending. Once it
    // is consumed, rejected, or closed, callers must stop treating it as held.
    bool hasPendingReservation() const
    {
        return locked_ && !attempted_ && !closed_;
    }

private:
    bool locked_;
    bool attempted_;
    bool closed_;
    bool requireRuntimeMifBinding_;
    Mode mode_;
    Snapshot snapshot_;
    QueueHead head_;
    Window window_;
};

} // namespace NativeAwdlDiscoveryBinding

#endif // NATIVE_AWDL_DISCOVERY_ADMITTED_BINDING_HPP
