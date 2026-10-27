// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_mif_burst.hpp"

#include <assert.h>

using namespace NativeAwdlProbe;

static MifBurstRepeatState eligibleState()
{
    MifBurstRepeatState state{};
    state.preparedFrames = 1;
    state.submittedFrames = 1;
    state.nowUs = 200000;
    state.lastCompletionUs = state.nowUs - kMifBurstRepeatIntervalUs;
    state.sameEpoch = true;
    state.rocActive = true;
    state.previousMifSucceeded = true;
    state.ticketCompleted = true;
    state.ticketSucceeded = true;
    state.actionIdle = true;
    state.queueLeaseActive = true;
    state.ringEmpty = true;
    state.ringIndicesConsistent = true;
    state.frameEmpty = true;
    return state;
}

int main()
{
    auto state = eligibleState();
    auto plan = planMifBurstRepeat(state);
    assert(plan.decision == MifBurstDecision::Prepare);

    state.nowUs = state.lastCompletionUs + kMifBurstRepeatIntervalUs - 1;
    plan = planMifBurstRepeat(state);
    assert(plan.decision == MifBurstDecision::Wait);
    state.nowUs++;
    plan = planMifBurstRepeat(state);
    assert(plan.decision == MifBurstDecision::Prepare);

    state = eligibleState(); state.preparedFrames = 3;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::FrameLimit);
    state = eligibleState(); state.preparedFrames = 3;
    state.submittedFrames = 2; state.candidateAlreadyPrepared = true;
    assert(planMifBurstRepeat(state).decision == MifBurstDecision::Prepare);
    state.submittedFrames = 3;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::FrameLimit);
    state = eligibleState(); state.submittedFrames = 3;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::FrameLimit);
    state = eligibleState(); state.sameEpoch = false;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::EpochMismatch);
    state = eligibleState(); state.endSeen = true;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::RocEnded);
    state = eligibleState(); state.outcomeUnknown = true;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::RocUnknown);
    state = eligibleState(); state.previousMifSucceeded = false;
    assert(planMifBurstRepeat(state).reason ==
           MifBurstStopReason::PreviousTicketFailed);
    state = eligibleState(); state.ticketSucceeded = false;
    assert(planMifBurstRepeat(state).reason ==
           MifBurstStopReason::PreviousTicketFailed);
    state = eligibleState(); state.ticketCompleted = false;
    assert(planMifBurstRepeat(state).reason ==
           MifBurstStopReason::PreviousTicketIncomplete);
    state = eligibleState(); state.actionIdle = false;
    assert(planMifBurstRepeat(state).reason ==
           MifBurstStopReason::PreviousTicketIncomplete);
    state = eligibleState(); state.ringEmpty = false;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::QueueNotIdle);
    state = eligibleState(); state.nativeDataAttempts = 1;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::DataStarted);
    state = eligibleState(); state.frameEmpty = false;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::FrameNotEmpty);
    state = eligibleState(); state.nowUs = state.lastCompletionUs - 1;
    assert(planMifBurstRepeat(state).reason == MifBurstStopReason::InvalidTime);
}
