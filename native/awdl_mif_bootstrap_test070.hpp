// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_BOOTSTRAP_TEST070_HPP
#define NATIVE_AWDL_MIF_BOOTSTRAP_TEST070_HPP

#include "awdl_peer_runtime_table.hpp"

#include <stdint.h>

// A Test070-only, single control-MIF bootstrap. The peer MIF is treated only
// as a recent receive-time presence event. It never supplies PHY/GP2 timing,
// a channel schedule, PSF authority, QM authorization, or a data-path gate.
namespace Test070MifBootstrap {

constexpr uint64_t kMifFreshnessLimitUs = 16ULL * 1024ULL;
constexpr uint64_t kMinimumLeaseReserveUs = 20ULL * 1000ULL;
constexpr uint8_t kPeerSlotCount =
    static_cast<uint8_t>(IntelAwdlPeerRuntime::kPeerCapacity);

enum class Status : uint32_t {
    NotChecked = 0,
    Waiting = 1,
    Ready = 2,
    Blocked = 3
};

enum Blocker : uint32_t {
    kNoBlocker = 0,
    kProbeDisabled = 1u << 0,
    kWrongOrdinal = 1u << 1,
    kAlreadyUsed = 1u << 2,
    kFirstPsfIncomplete = 1u << 3,
    kFirstPsfFailed = 1u << 4,
    kQueueLeaseMissing = 1u << 5,
    kTxRingNotEmpty = 1u << 6,
    kRingIndicesInconsistent = 1u << 7,
    kRocInactive = 1u << 8,
    kRocClosing = 1u << 9,
    kRocChannelMismatch = 1u << 10,
    kPeerMissing = 1u << 11,
    kPeerNotMifOnly = 1u << 12,
    kPeerSyncInconsistent = 1u << 13,
    kPeerMifStale = 1u << 14,
    kPeerChannelMismatch = 1u << 15,
    kEpochMismatch = 1u << 16,
    kPeerRxTimeInvalid = 1u << 17,
    kMifBeforePhaseOrigin = 1u << 18,
    kPhaseNotOpen = 1u << 19,
    kWindowExpired = 1u << 20,
    kInsufficientLease = 1u << 21,
    kInvalidWindow = 1u << 22,
    kDataAlreadyStarted = 1u << 23,
    kBindingSlotMismatch = 1u << 24,
    kBindingIncarnationMismatch = 1u << 25,
    kBindingRevisionMismatch = 1u << 26,
    kBindingTimestampMismatch = 1u << 27,
    kBindingChannelMismatch = 1u << 28,
    kBindingRocMismatch = 1u << 29,
    kBindingEpochMismatch = 1u << 30,
    kCandidatePreparationFailed = 1u << 31
};

// Address-free copy of the selected runtime table MIF entry. A valid MIF can
// appear here before any PSF exists for the peer.
struct PeerMif {
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    uint64_t rxMonotonicUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint16_t rxChannel;
    uint8_t slot;
    bool tracked;
    bool hasMif;
    bool hasPsf;
    bool mifFresh;
    bool complete;
    bool syncConsistent;
    bool rxChannel6Confirmed;
};

struct LocalState {
    uint64_t phaseOriginUs;
    uint64_t windowEndUs;
    uint64_t hardDeadlineUs;
    uint64_t nowUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
    uint32_t ordinal;
    bool probeEnabled;
    bool alreadyUsed;
    bool firstPsfCompleted;
    bool firstPsfSucceeded;
    bool queueLeaseActive;
    bool txRingEmpty;
    bool ringIndicesConsistent;
    bool rocActive;
    bool rocClosing;
    bool rocChannel6Confirmed;
    bool dataAlreadyStarted;
};

struct Binding {
    uint64_t peerIncarnation;
    uint64_t mifRevision;
    uint64_t rxMonotonicUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
    uint16_t rxChannel;
    uint8_t slot;
};

struct Plan {
    Status status;
    uint32_t blockers;
    uint64_t mifAgeUs;
    uint64_t effectiveEndUs;
    Binding binding;
};

inline bool sameEpochs(const LocalState &local, const PeerMif &peer)
{
    return local.contextGeneration == peer.contextGeneration &&
           local.powerGeneration == peer.powerGeneration &&
           local.stationGeneration == peer.stationGeneration;
}

inline uint32_t bindingMismatch(const Binding &expected,
                                const PeerMif &current,
                                uint64_t currentRocGeneration)
{
    uint32_t blockers = kNoBlocker;
    if (expected.slot != current.slot)
        blockers |= kBindingSlotMismatch;
    if (expected.peerIncarnation != current.peerIncarnation)
        blockers |= kBindingIncarnationMismatch;
    if (expected.mifRevision != current.mifRevision)
        blockers |= kBindingRevisionMismatch;
    if (expected.rxMonotonicUs != current.rxMonotonicUs)
        blockers |= kBindingTimestampMismatch;
    if (expected.rxChannel != current.rxChannel)
        blockers |= kBindingChannelMismatch;
    if (expected.contextGeneration != current.contextGeneration ||
        expected.powerGeneration != current.powerGeneration ||
        expected.stationGeneration != current.stationGeneration)
        blockers |= kBindingEpochMismatch;
    if (expected.rocGeneration != currentRocGeneration)
        blockers |= kBindingRocMismatch;
    return blockers;
}

inline Plan evaluate(const LocalState &local, const PeerMif &peer)
{
    Plan plan{};
    plan.status = Status::Blocked;
    plan.binding.slot = 0xff;

    if (!local.probeEnabled)
        plan.blockers |= kProbeDisabled;
    if (local.ordinal != 0)
        plan.blockers |= kWrongOrdinal;
    if (local.alreadyUsed)
        plan.blockers |= kAlreadyUsed;
    if (!local.firstPsfCompleted)
        plan.blockers |= kFirstPsfIncomplete;
    if (!local.firstPsfSucceeded)
        plan.blockers |= kFirstPsfFailed;
    if (!local.queueLeaseActive)
        plan.blockers |= kQueueLeaseMissing;
    if (!local.txRingEmpty)
        plan.blockers |= kTxRingNotEmpty;
    if (!local.ringIndicesConsistent)
        plan.blockers |= kRingIndicesInconsistent;
    if (!local.rocActive)
        plan.blockers |= kRocInactive;
    if (local.rocClosing)
        plan.blockers |= kRocClosing;
    if (!local.rocChannel6Confirmed)
        plan.blockers |= kRocChannelMismatch;
    if (!peer.tracked || peer.slot >= kPeerSlotCount ||
        peer.peerIncarnation == 0 || peer.mifRevision == 0 ||
        peer.rxMonotonicUs == 0)
        plan.blockers |= kPeerMissing;
    if (!peer.hasMif || peer.hasPsf)
        plan.blockers |= kPeerNotMifOnly;
    if (!peer.syncConsistent || !peer.complete)
        plan.blockers |= kPeerSyncInconsistent;
    if (!peer.mifFresh)
        plan.blockers |= kPeerMifStale;
    if (!peer.rxChannel6Confirmed)
        plan.blockers |= kPeerChannelMismatch;
    if (!local.contextGeneration || !local.powerGeneration ||
        !local.stationGeneration || !local.rocGeneration ||
        !peer.contextGeneration || !peer.powerGeneration ||
        !peer.stationGeneration || !sameEpochs(local, peer))
        plan.blockers |= kEpochMismatch;
    if (local.dataAlreadyStarted)
        plan.blockers |= kDataAlreadyStarted;

    if (local.phaseOriginUs == 0 || local.windowEndUs <= local.phaseOriginUs ||
        local.hardDeadlineUs <= local.phaseOriginUs) {
        plan.blockers |= kInvalidWindow;
    } else {
        plan.effectiveEndUs = local.windowEndUs < local.hardDeadlineUs ?
            local.windowEndUs : local.hardDeadlineUs;
        if (local.nowUs < local.phaseOriginUs)
            plan.blockers |= kPhaseNotOpen;
        if (local.nowUs >= plan.effectiveEndUs)
            plan.blockers |= kWindowExpired;
        else if (plan.effectiveEndUs - local.nowUs <=
                 kMinimumLeaseReserveUs)
            plan.blockers |= kInsufficientLease;
    }

    if (local.nowUs == 0 || peer.rxMonotonicUs == 0 ||
        peer.rxMonotonicUs > local.nowUs) {
        plan.blockers |= kPeerRxTimeInvalid;
    } else {
        plan.mifAgeUs = local.nowUs - peer.rxMonotonicUs;
        if (plan.mifAgeUs > kMifFreshnessLimitUs)
            plan.blockers |= kPeerMifStale;
        if (peer.rxMonotonicUs < local.phaseOriginUs)
            plan.blockers |= kMifBeforePhaseOrigin;
    }

    if (plan.blockers != kNoBlocker)
        return plan;

    plan.status = Status::Ready;
    plan.binding.peerIncarnation = peer.peerIncarnation;
    plan.binding.mifRevision = peer.mifRevision;
    plan.binding.rxMonotonicUs = peer.rxMonotonicUs;
    plan.binding.contextGeneration = peer.contextGeneration;
    plan.binding.powerGeneration = peer.powerGeneration;
    plan.binding.stationGeneration = peer.stationGeneration;
    plan.binding.rocGeneration = local.rocGeneration;
    plan.binding.rxChannel = peer.rxChannel;
    plan.binding.slot = peer.slot;
    return plan;
}

} // namespace Test070MifBootstrap

#endif // NATIVE_AWDL_MIF_BOOTSTRAP_TEST070_HPP
