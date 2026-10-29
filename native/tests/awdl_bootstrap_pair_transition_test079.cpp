// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_bootstrap_pair_transition.hpp"

#include <assert.h>
#include <stdint.h>

using namespace Test079BootstrapPairTransition;

namespace {

Epochs replayEpochs()
{
    Epochs epochs{};
    epochs.context = 3;
    epochs.power = 4;
    epochs.station = 5;
    epochs.roc = 6;
    return epochs;
}

Input eligibleReplay()
{
    Input input{};
    input.bootstrap.epochs = replayEpochs();
    input.bootstrap.completedUs = 1000000ULL;
    input.bootstrap.upgradeDeadlineUs = 1500000ULL;
    input.bootstrap.peerIncarnation = 17;
    input.bootstrap.mifRevision = 8;
    input.bootstrap.psfRevision = 0; // Bootstrap selected a MIF-only entry.
    input.bootstrap.slot = 2;
    input.bootstrap.selected = true;
    input.bootstrap.submitted = true;
    input.bootstrap.succeeded = true;

    input.live.epochs = replayEpochs();
    input.live.nowUs = 1100000ULL;
    input.live.ownerCurrent = true;
    input.live.rocActive = true;
    input.live.rocAckedChannel6 = true;
    input.live.queueLeaseActive = true;
    input.live.ticketReclaimed = true;
    input.live.txRingEmpty = true;
    input.live.ringIndicesConsistent = true;

    input.peer.epochs = replayEpochs();
    input.peer.peerIncarnation = 17;
    input.peer.psfRevision = 1;
    input.peer.mifRevision = 9;
    input.peer.psfRxUs = 1099000ULL;
    input.peer.mifRxUs = 1090000ULL;
    input.peer.psfChannel = kSocialChannel6;
    input.peer.mifChannel = kSocialChannel6;
    input.peer.slot = 2;
    input.peer.tracked = true;
    input.peer.hasPsf = true;
    input.peer.hasMif = true;
    input.peer.psfComplete = true;
    input.peer.mifComplete = true;
    input.peer.psfFresh = true;
    input.peer.mifFresh = true;
    input.peer.mifSyncConsistent = true;
    input.peer.historyCompatible = true;
    return input;
}

void testFreshSameEntryPairOpensOnlyExistingMifPath()
{
    const Input input = eligibleReplay();
    const Plan plan = evaluate(input);
    assert(plan.blockers == kNoBlocker);
    assert(plan.permitExistingNormalMifPath);
}

void testBootstrapOnlyAndOldMifWithNewPsfStayClosed()
{
    Input input = eligibleReplay();
    input.peer.psfRevision = 1;
    input.peer.psfRxUs = 1050000ULL;
    input.peer.mifRevision = input.bootstrap.mifRevision;
    input.peer.mifRxUs = input.bootstrap.completedUs - 1;

    const Plan plan = evaluate(input);
    assert(!plan.permitExistingNormalMifPath);
    assert(plan.blockers & kMifRevisionNotNew);
    assert(plan.blockers & kMifBeforeBootstrapCompletion);
    // The output is only a gate for existing normal-MIF preparation. It has
    // no field that could assert a normal TX completion or authorize a QM.
}

void testBootstrapMustActuallySucceedAndBeReclaimed()
{
    Input input = eligibleReplay();
    input.bootstrap.succeeded = false;
    assert(evaluate(input).blockers & kBootstrapNotSucceeded);

    input = eligibleReplay();
    input.live.ticketReclaimed = false;
    assert(evaluate(input).blockers & kTicketNotReclaimed);

    input = eligibleReplay();
    input.live.txRingEmpty = false;
    assert(evaluate(input).blockers & kRingBusy);

    input = eligibleReplay();
    input.live.ringIndicesConsistent = false;
    assert(evaluate(input).blockers & kRingIndicesInconsistent);
}

void testActiveOwnerAckedRocAndQueueLeaseAreRequired()
{
    Input input = eligibleReplay();
    input.live.rocActive = false;
    assert(evaluate(input).blockers & kRocInactive);

    input = eligibleReplay();
    input.live.rocClosing = true;
    assert(evaluate(input).blockers & kRocClosing);

    input = eligibleReplay();
    input.live.rocAckedChannel6 = false;
    assert(evaluate(input).blockers & kRocNotAckedChannel6);

    input = eligibleReplay();
    input.live.ownerCurrent = false;
    assert(evaluate(input).blockers & kOwnerNotCurrent);

    input = eligibleReplay();
    input.live.queueLeaseActive = false;
    assert(evaluate(input).blockers & kQueueLeaseMissing);
}

void testPeerReplacementAndEpochChangesAreRejected()
{
    Input input = eligibleReplay();
    ++input.peer.slot;
    Plan plan = evaluate(input);
    assert(!plan.permitExistingNormalMifPath);
    assert(plan.blockers & kPeerSlotChanged);

    input = eligibleReplay();
    ++input.peer.peerIncarnation;
    plan = evaluate(input);
    assert(plan.blockers & kPeerIncarnationChanged);

    input = eligibleReplay();
    ++input.peer.epochs.power;
    plan = evaluate(input);
    assert(plan.blockers & kEpochMismatch);

    input = eligibleReplay();
    input.live.epochs.roc = 0;
    plan = evaluate(input);
    assert(plan.blockers & kInvalidEpoch);
}

void testUnknownStaleOrMismatchedPairIsRejected()
{
    Input input = eligibleReplay();
    input.peer.hasPsf = false;
    assert(evaluate(input).blockers & kPsfMissingOrIncomplete);

    input = eligibleReplay();
    input.peer.historyCompatible = false;
    assert(evaluate(input).blockers & kHistoryIncompatible);

    input = eligibleReplay();
    input.peer.psfRevision = input.bootstrap.psfRevision;
    assert(evaluate(input).blockers & kPsfRevisionNotNew);

    input = eligibleReplay();
    input.peer.mifChannel = 149;
    assert(evaluate(input).blockers & kMifChannelMismatch);

    input = eligibleReplay();
    input.peer.psfRxUs = input.live.nowUs + 1;
    assert(evaluate(input).blockers & kInvalidPeerTimestamp);

    input = eligibleReplay();
    input.peer.psfRxUs = input.live.nowUs - kMaximumFreshPsfAgeUs - 1;
    assert(evaluate(input).blockers & kPsfNotFresh);
}

void testFreshnessBoundariesAreSixteenTu()
{
    Input input = eligibleReplay();
    input.peer.psfRxUs = input.live.nowUs - kMaximumFreshPsfAgeUs;
    input.peer.mifRxUs = input.live.nowUs - kMaximumFreshMifAgeUs;
    assert(evaluate(input).permitExistingNormalMifPath);

    input = eligibleReplay();
    input.peer.psfRxUs = input.live.nowUs - kMaximumFreshPsfAgeUs - 1;
    Plan plan = evaluate(input);
    assert(!plan.permitExistingNormalMifPath);
    assert(plan.blockers & kPsfNotFresh);

    input = eligibleReplay();
    input.peer.mifRxUs = input.live.nowUs - kMaximumFreshMifAgeUs - 1;
    plan = evaluate(input);
    assert(!plan.permitExistingNormalMifPath);
    assert(plan.blockers & kMifNotFresh);

    input = eligibleReplay();
    input.peer.psfRxUs = input.live.nowUs + 1;
    plan = evaluate(input);
    assert(plan.blockers & kInvalidPeerTimestamp);
    input.peer.psfRxUs = input.live.nowUs;
    input.peer.mifRxUs = input.live.nowUs + 1;
    plan = evaluate(input);
    assert(plan.blockers & kInvalidPeerTimestamp);
}

void testUpgradeWindowAndOneShotBudget()
{
    Input input = eligibleReplay();
    input.live.nowUs = input.bootstrap.completedUs - 1;
    assert(evaluate(input).blockers & kWindowNotOpen);

    input = eligibleReplay();
    input.live.nowUs = input.bootstrap.upgradeDeadlineUs;
    assert(evaluate(input).blockers & kWindowExpired);

    input = eligibleReplay();
    input.normalMifAlreadyAttempted = true;
    const Plan plan = evaluate(input);
    assert(!plan.permitExistingNormalMifPath);
    assert(plan.blockers & kAttemptAlreadyUsed);
}

} // namespace

int main()
{
    testFreshSameEntryPairOpensOnlyExistingMifPath();
    testBootstrapOnlyAndOldMifWithNewPsfStayClosed();
    testBootstrapMustActuallySucceedAndBeReclaimed();
    testActiveOwnerAckedRocAndQueueLeaseAreRequired();
    testPeerReplacementAndEpochChangesAreRejected();
    testUnknownStaleOrMismatchedPairIsRejected();
    testFreshnessBoundariesAreSixteenTu();
    testUpgradeWindowAndOneShotBudget();
    return 0;
}
