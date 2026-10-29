// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_mif_bootstrap_test070.hpp"

#include <assert.h>
#include <stdint.h>

using namespace Test070MifBootstrap;

namespace {

constexpr uint64_t kReplayPhaseOriginUs = 444898111ULL;
constexpr uint64_t kReplayMifRxUs = 445020367ULL;
constexpr uint64_t kReplayWindowEndUs =
    kReplayPhaseOriginUs + 13ULL * 65536ULL;

LocalState replayLocal()
{
    LocalState local{};
    local.phaseOriginUs = kReplayPhaseOriginUs;
    local.windowEndUs = kReplayWindowEndUs;
    local.hardDeadlineUs = 445770250ULL;
    local.nowUs = kReplayMifRxUs + 10000ULL;
    local.contextGeneration = 9;
    local.powerGeneration = 10;
    local.stationGeneration = 11;
    local.rocGeneration = 9;
    local.ordinal = 0;
    local.probeEnabled = true;
    local.firstPsfCompleted = true;
    local.firstPsfSucceeded = true;
    local.queueLeaseActive = true;
    local.txRingEmpty = true;
    local.ringIndicesConsistent = true;
    local.rocActive = true;
    local.rocChannel6Confirmed = true;
    return local;
}

PeerMif replayPeer()
{
    PeerMif peer{};
    peer.peerIncarnation = 3; // opaque test token, not a device identity
    peer.mifRevision = 1;
    peer.rxMonotonicUs = kReplayMifRxUs;
    peer.contextGeneration = 9;
    peer.powerGeneration = 10;
    peer.stationGeneration = 11;
    peer.rxChannel = 6;
    peer.slot = 1;
    peer.tracked = true;
    peer.hasMif = true;
    peer.hasPsf = false;
    peer.mifFresh = true;
    peer.complete = true;
    peer.syncConsistent = true;
    peer.rxChannel6Confirmed = true;
    return peer;
}

void testTest069NumericReplayUsesOnlyFreshMifPresence()
{
    auto local = replayLocal();
    const auto peer = replayPeer();
    const auto plan = evaluate(local, peer);
    assert(plan.status == Status::Ready);
    assert(plan.blockers == kNoBlocker);
    assert(plan.mifAgeUs == 10000ULL);
    assert(plan.effectiveEndUs == kReplayWindowEndUs);
    assert(plan.binding.slot == peer.slot);
    assert(plan.binding.peerIncarnation == peer.peerIncarnation);
    assert(plan.binding.mifRevision == peer.mifRevision);
    assert(plan.binding.rxMonotonicUs == kReplayMifRxUs);
    assert(plan.binding.rocGeneration == local.rocGeneration);
}

void testFreshnessAndLeaseBoundaries()
{
    auto local = replayLocal();
    auto peer = replayPeer();
    local.nowUs = peer.rxMonotonicUs + kMifFreshnessLimitUs;
    assert(evaluate(local, peer).status == Status::Ready);

    ++local.nowUs;
    auto plan = evaluate(local, peer);
    assert(plan.status == Status::Blocked);
    assert(plan.blockers & kPeerMifStale);

    local = replayLocal();
    local.nowUs = kReplayWindowEndUs - kMinimumLeaseReserveUs;
    peer = replayPeer();
    peer.rxMonotonicUs = local.nowUs - kMifFreshnessLimitUs;
    plan = evaluate(local, peer);
    assert(plan.status == Status::Blocked);
    assert(plan.blockers & kInsufficientLease);
    local.nowUs = kReplayWindowEndUs - kMinimumLeaseReserveUs - 1;
    peer.rxMonotonicUs = local.nowUs - kMifFreshnessLimitUs;
    assert(evaluate(local, peer).status == Status::Ready);
}

void testRejectsUntrustedOrOutOfWindowPeer()
{
    auto local = replayLocal();
    auto peer = replayPeer();

    peer.hasPsf = true;
    assert(evaluate(local, peer).blockers & kPeerNotMifOnly);
    peer = replayPeer();
    peer.syncConsistent = false;
    assert(evaluate(local, peer).blockers & kPeerSyncInconsistent);
    peer = replayPeer();
    peer.complete = false;
    assert(evaluate(local, peer).blockers & kPeerSyncInconsistent);
    peer = replayPeer();
    peer.rxChannel6Confirmed = false;
    assert(evaluate(local, peer).blockers & kPeerChannelMismatch);
    peer = replayPeer();
    peer.powerGeneration++;
    assert(evaluate(local, peer).blockers & kEpochMismatch);
    peer = replayPeer();
    peer.slot = kPeerSlotCount;
    assert(evaluate(local, peer).blockers & kPeerMissing);
    peer = replayPeer();
    peer.rxMonotonicUs = local.phaseOriginUs - 1;
    assert(evaluate(local, peer).blockers & kMifBeforePhaseOrigin);
    peer.rxMonotonicUs = local.nowUs + 1;
    assert(evaluate(local, peer).blockers & kPeerRxTimeInvalid);
}

void testRequiresLocalTicketQueueRocAndOneShot()
{
    auto local = replayLocal();
    const auto peer = replayPeer();
    local.ordinal = 1;
    assert(evaluate(local, peer).blockers & kWrongOrdinal);
    local = replayLocal();
    local.alreadyUsed = true;
    assert(evaluate(local, peer).blockers & kAlreadyUsed);
    local = replayLocal();
    local.firstPsfSucceeded = false;
    assert(evaluate(local, peer).blockers & kFirstPsfFailed);
    local = replayLocal();
    local.txRingEmpty = false;
    assert(evaluate(local, peer).blockers & kTxRingNotEmpty);
    local = replayLocal();
    local.ringIndicesConsistent = false;
    assert(evaluate(local, peer).blockers & kRingIndicesInconsistent);
    local = replayLocal();
    local.rocClosing = true;
    assert(evaluate(local, peer).blockers & kRocClosing);
    local = replayLocal();
    local.dataAlreadyStarted = true;
    assert(evaluate(local, peer).blockers & kDataAlreadyStarted);
    local = replayLocal();
    local.rocGeneration = 0;
    assert(evaluate(local, peer).blockers & kEpochMismatch);
}

void testExactBindingRejectsReplacementAndNewEpoch()
{
    const auto local = replayLocal();
    const auto peer = replayPeer();
    const auto plan = evaluate(local, peer);
    assert(plan.status == Status::Ready);
    assert(bindingMismatch(plan.binding, peer, local.rocGeneration) == 0);

    auto changed = peer;
    ++changed.slot;
    assert(bindingMismatch(plan.binding, changed, local.rocGeneration) &
           kBindingSlotMismatch);
    changed = peer;
    ++changed.peerIncarnation;
    assert(bindingMismatch(plan.binding, changed, local.rocGeneration) &
           kBindingIncarnationMismatch);
    changed = peer;
    ++changed.mifRevision;
    assert(bindingMismatch(plan.binding, changed, local.rocGeneration) &
           kBindingRevisionMismatch);
    changed = peer;
    ++changed.rxMonotonicUs;
    assert(bindingMismatch(plan.binding, changed, local.rocGeneration) &
           kBindingTimestampMismatch);
    changed = peer;
    ++changed.rxChannel;
    assert(bindingMismatch(plan.binding, changed, local.rocGeneration) &
           kBindingChannelMismatch);
    changed = peer;
    ++changed.contextGeneration;
    assert(bindingMismatch(plan.binding, changed, local.rocGeneration) &
           kBindingEpochMismatch);
    assert(bindingMismatch(plan.binding, peer, local.rocGeneration + 1) &
           kBindingRocMismatch);
}

} // namespace

int main()
{
    testTest069NumericReplayUsesOnlyFreshMifPresence();
    testFreshnessAndLeaseBoundaries();
    testRejectsUntrustedOrOutOfWindowPeer();
    testRequiresLocalTicketQueueRocAndOneShot();
    testExactBindingRejectsReplacementAndNewEpoch();
    return 0;
}
