// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_BOOTSTRAP_PAIR_TRANSITION_HPP
#define NATIVE_AWDL_BOOTSTRAP_PAIR_TRANSITION_HPP

#include <stdint.h>

// Test079's pure gate from the one-shot presence-control MIF bootstrap to the
// existing normal paired-MIF path. This policy never prepares/submits a frame,
// records a TX completion, chooses a schedule, or authorizes a QM/data dequeue.
// A caller may use `permitExistingNormalMifPath` only as an additional gate;
// the established full preparation, submit, completion, and QM checks remain
// authoritative.
namespace Test079BootstrapPairTransition {

// Pair-upgrade evidence must be recent at the same 16-TU bound used by the
// presence-only MIF bootstrap. This is only an additional freshness limit;
// it does not replace normal MIF phase geometry or its full prepare/submit
// checks.
constexpr uint64_t kMaximumFreshPsfAgeUs = 16ULL * 1024ULL;
constexpr uint64_t kMaximumFreshMifAgeUs = 16ULL * 1024ULL;
constexpr uint16_t kSocialChannel6 = 6;
constexpr uint8_t kPeerSlotCapacity = 16;

struct Epochs {
    uint64_t context;
    uint64_t power;
    uint64_t station;
    uint64_t roc;
};

// Immutable facts captured for the selected bootstrap peer/run. The PSF
// baseline may be zero when no PSF existed at bootstrap selection time.
struct BootstrapAnchor {
    Epochs epochs;
    uint64_t completedUs;
    uint64_t upgradeDeadlineUs; // Existing half-open MIF/PSF lease deadline.
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    uint64_t psfRevision;
    uint8_t slot;
    bool selected;
    bool submitted;
    bool succeeded;
};

// Live local facts copied under the caller's serialization gate. `ticketReclaimed`
// means the successful bootstrap completion has actually been retired and the
// action ring is safe to reuse; an ACK or completion timestamp alone is not
// enough.
struct LiveState {
    Epochs epochs;
    uint64_t nowUs;
    bool ownerCurrent;
    bool rocActive;
    bool rocClosing;
    bool rocAckedChannel6;
    bool queueLeaseActive;
    bool ticketReclaimed;
    bool txRingEmpty;
    bool ringIndicesConsistent;
};

// One atomic, address-free peer-table snapshot. The caller maps raw receive
// channel indices before setting the channel fields and must source all
// revisions, timestamps, history, and epochs from the same table entry.
struct PeerSnapshot {
    Epochs epochs;
    uint64_t peerIncarnation;
    uint64_t psfRevision;
    uint64_t mifRevision;
    uint64_t psfRxUs;
    uint64_t mifRxUs;
    uint16_t psfChannel;
    uint16_t mifChannel;
    uint8_t slot;
    bool tracked;
    bool hasPsf;
    bool hasMif;
    bool psfComplete;
    bool mifComplete;
    bool psfFresh;
    bool mifFresh;
    bool mifSyncConsistent;
    bool historyCompatible;
};

struct Input {
    BootstrapAnchor bootstrap;
    LiveState live;
    PeerSnapshot peer;
    bool normalMifAlreadyAttempted;
};

enum Blocker : uint64_t {
    kNoBlocker = 0,
    kBootstrapNotSelected = 1ULL << 0,
    kBootstrapNotSubmitted = 1ULL << 1,
    kBootstrapNotSucceeded = 1ULL << 2,
    kCompletionMissing = 1ULL << 3,
    kTicketNotReclaimed = 1ULL << 4,
    kRingBusy = 1ULL << 5,
    kRingIndicesInconsistent = 1ULL << 6,
    kOwnerNotCurrent = 1ULL << 7,
    kRocInactive = 1ULL << 8,
    kRocClosing = 1ULL << 9,
    kRocNotAckedChannel6 = 1ULL << 10,
    kQueueLeaseMissing = 1ULL << 11,
    kInvalidWindow = 1ULL << 12,
    kWindowNotOpen = 1ULL << 13,
    kWindowExpired = 1ULL << 14,
    kAttemptAlreadyUsed = 1ULL << 15,
    kPeerMissing = 1ULL << 16,
    kPeerSlotChanged = 1ULL << 17,
    kPeerIncarnationChanged = 1ULL << 18,
    kInvalidEpoch = 1ULL << 19,
    kEpochMismatch = 1ULL << 20,
    kPsfMissingOrIncomplete = 1ULL << 21,
    kMifMissingOrIncomplete = 1ULL << 22,
    kPsfNotFresh = 1ULL << 23,
    kMifNotFresh = 1ULL << 24,
    kHistoryIncompatible = 1ULL << 25,
    kPsfRevisionNotNew = 1ULL << 26,
    kMifRevisionNotNew = 1ULL << 27,
    kPsfBeforeBootstrapCompletion = 1ULL << 28,
    kMifBeforeBootstrapCompletion = 1ULL << 29,
    kInvalidPeerTimestamp = 1ULL << 30,
    kPsfChannelMismatch = 1ULL << 31,
    kMifChannelMismatch = 1ULL << 32
};

struct Plan {
    uint64_t blockers;
    bool permitExistingNormalMifPath;
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

inline Plan evaluate(const Input &input)
{
    const BootstrapAnchor &bootstrap = input.bootstrap;
    const LiveState &live = input.live;
    const PeerSnapshot &peer = input.peer;
    Plan plan{};

    if (!bootstrap.selected)
        plan.blockers |= kBootstrapNotSelected;
    if (!bootstrap.submitted)
        plan.blockers |= kBootstrapNotSubmitted;
    if (!bootstrap.succeeded)
        plan.blockers |= kBootstrapNotSucceeded;
    if (bootstrap.completedUs == 0)
        plan.blockers |= kCompletionMissing;
    if (!live.ticketReclaimed)
        plan.blockers |= kTicketNotReclaimed;
    if (!live.txRingEmpty)
        plan.blockers |= kRingBusy;
    if (!live.ringIndicesConsistent)
        plan.blockers |= kRingIndicesInconsistent;
    if (!live.ownerCurrent)
        plan.blockers |= kOwnerNotCurrent;
    if (!live.rocActive)
        plan.blockers |= kRocInactive;
    if (live.rocClosing)
        plan.blockers |= kRocClosing;
    if (!live.rocAckedChannel6)
        plan.blockers |= kRocNotAckedChannel6;
    if (!live.queueLeaseActive)
        plan.blockers |= kQueueLeaseMissing;
    if (input.normalMifAlreadyAttempted)
        plan.blockers |= kAttemptAlreadyUsed;

    if (bootstrap.completedUs == 0 ||
        bootstrap.upgradeDeadlineUs <= bootstrap.completedUs) {
        plan.blockers |= kInvalidWindow;
    } else if (live.nowUs < bootstrap.completedUs) {
        plan.blockers |= kWindowNotOpen;
    } else if (live.nowUs >= bootstrap.upgradeDeadlineUs) {
        plan.blockers |= kWindowExpired;
    }

    if (!peer.tracked || peer.slot >= kPeerSlotCapacity ||
        bootstrap.slot >= kPeerSlotCapacity || peer.peerIncarnation == 0 ||
        peer.mifRevision == 0 || peer.mifRxUs == 0)
        plan.blockers |= kPeerMissing;
    if (peer.slot != bootstrap.slot)
        plan.blockers |= kPeerSlotChanged;
    if (peer.peerIncarnation != bootstrap.peerIncarnation)
        plan.blockers |= kPeerIncarnationChanged;

    if (!nonzeroEpochs(bootstrap.epochs) || !nonzeroEpochs(live.epochs) ||
        !nonzeroEpochs(peer.epochs))
        plan.blockers |= kInvalidEpoch;
    if (!sameEpochs(bootstrap.epochs, live.epochs) ||
        !sameEpochs(bootstrap.epochs, peer.epochs))
        plan.blockers |= kEpochMismatch;

    if (!peer.hasPsf || !peer.psfComplete || peer.psfRevision == 0 ||
        peer.psfRxUs == 0)
        plan.blockers |= kPsfMissingOrIncomplete;
    if (!peer.hasMif || !peer.mifComplete || !peer.mifSyncConsistent)
        plan.blockers |= kMifMissingOrIncomplete;
    if (!peer.psfFresh)
        plan.blockers |= kPsfNotFresh;
    if (!peer.mifFresh)
        plan.blockers |= kMifNotFresh;
    if (!peer.historyCompatible)
        plan.blockers |= kHistoryIncompatible;
    if (peer.psfRevision <= bootstrap.psfRevision)
        plan.blockers |= kPsfRevisionNotNew;
    if (peer.mifRevision <= bootstrap.mifRevision)
        plan.blockers |= kMifRevisionNotNew;

    if (bootstrap.completedUs != 0 &&
        peer.psfRxUs != 0 && peer.psfRxUs <= bootstrap.completedUs)
        plan.blockers |= kPsfBeforeBootstrapCompletion;
    if (bootstrap.completedUs != 0 &&
        peer.mifRxUs != 0 && peer.mifRxUs <= bootstrap.completedUs)
        plan.blockers |= kMifBeforeBootstrapCompletion;
    if (live.nowUs == 0 || peer.psfRxUs == 0 || peer.mifRxUs == 0 ||
        peer.psfRxUs > live.nowUs || peer.mifRxUs > live.nowUs)
        plan.blockers |= kInvalidPeerTimestamp;
    if (live.nowUs != 0 && peer.psfRxUs <= live.nowUs &&
        live.nowUs - peer.psfRxUs > kMaximumFreshPsfAgeUs)
        plan.blockers |= kPsfNotFresh;
    if (live.nowUs != 0 && peer.mifRxUs <= live.nowUs &&
        live.nowUs - peer.mifRxUs > kMaximumFreshMifAgeUs)
        plan.blockers |= kMifNotFresh;

    if (peer.psfChannel != kSocialChannel6)
        plan.blockers |= kPsfChannelMismatch;
    if (peer.mifChannel != kSocialChannel6)
        plan.blockers |= kMifChannelMismatch;

    plan.permitExistingNormalMifPath = plan.blockers == kNoBlocker;
    return plan;
}

} // namespace Test079BootstrapPairTransition

#endif // NATIVE_AWDL_BOOTSTRAP_PAIR_TRANSITION_HPP
