// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_data_tx_publish_gate.hpp"

#include <assert.h>

using NativeAwdlDataTxPublication::LifecycleSnapshot;
using NativeAwdlDataTxPublication::shouldDeferBulkProperties;

static LifecycleSnapshot cleanPreflight()
{
    LifecycleSnapshot state{};
    state.probeCleanPreflight = true;
    return state;
}

static LifecycleSnapshot completedSession()
{
    LifecycleSnapshot state{};
    state.timelineOwnerPresent = true;
    state.timelineProducerClosed = true;
    state.timelineEpochsMatchSession = true;
    state.sessionSubmitted = true;
    state.sessionCommandReturned = true;
    state.sessionCommandSucceeded = true;
    state.sessionStartSeen = true;
    state.sessionEndSeen = true;
    state.sessionCleanupAllowed = true;
    state.sessionGeneration = 17;
    state.probeCompletedAndReleased = true;
    return state;
}

int main()
{
    // An owner=0 preflight is safe only before the one-shot command was
    // attempted and when the canonical reducer has no session.
    assert(!shouldDeferBulkProperties(cleanPreflight()));
    auto state = cleanPreflight();
    state.probeCleanPreflight = false;
    assert(shouldDeferBulkProperties(state));

    // Owner absence must never hide a live, submitted, or unknown session.
    state = cleanPreflight();
    state.sessionSubmitted = true;
    state.sessionGeneration = 17;
    assert(shouldDeferBulkProperties(state));
    state = cleanPreflight();
    state.sessionOutcomeUnknown = true;
    assert(shouldDeferBulkProperties(state));
    state = cleanPreflight();
    state.probeCleanPreflight = false;
    state.probeCompletedAndReleased = true;
    assert(shouldDeferBulkProperties(state));

    // The only post-session release requires canonical END, matching epochs,
    // a completed/released one-shot owner, and a producer-closed timeline.
    assert(!shouldDeferBulkProperties(completedSession()));
    state = completedSession();
    state.sessionEndSeen = false;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.sessionCommandSucceeded = false;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.probeCompletedAndReleased = false;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.timelineEpochsMatchSession = false;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.timelineProducerClosed = false;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.timelineActive = true;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.timelineDrainsPending = true;
    assert(shouldDeferBulkProperties(state));

    // Any live probe, lease, submit, unsettled queue, or uncompleted probe
    // holds bulk publication even if the timeline looks closed.
    state = completedSession();
    state.probeBusy = true;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.rxLeaseActive = true;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.txSubmissionBusy = true;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.txResourcesUnsettled = true;
    assert(shouldDeferBulkProperties(state));
    state = completedSession();
    state.sessionCleanupAllowed = false;
    assert(shouldDeferBulkProperties(state));
    return 0;
}
