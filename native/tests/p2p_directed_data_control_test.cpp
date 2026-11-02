// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_directed_data_control.hpp"
#include <assert.h>

using namespace NativeP2PDirectedDataControl;

static StartGateState readyState()
{
    StartGateState state{};
    state.startUs = 1000;
    state.deadlineUs = 101000; // Keep the production 100 ms ceiling.
    state.sessionMatches = true;
    state.ownerCurrent = true;
    state.resourcesCurrent = true;
    state.radioReady = true;
    state.profileReady = true;
    state.mccReady = true;
    return state;
}

static void testGateSamplesTimeAfterQueueDelay()
{
    const StartGateState state = readyState();
    // The worker sampled at 1001 before queueing; the main gate actually runs
    // at 100999 and may still accept, while the exact deadline is rejected.
    assert(checkStartGate(state, 100999) == StartGateResult::Ready);
    assert(checkStartGate(state, 101000) == StartGateResult::OutsideWindow);
    assert(checkStartGate(state, 999) == StartGateResult::OutsideWindow);

    auto changed = state;
    changed.ownerCurrent = false; // Owner/epoch changed before gate entry.
    assert(checkStartGate(changed, 100999) == StartGateResult::OwnerStale);
    changed = state;
    changed.resourcesCurrent = false;
    assert(checkStartGate(changed, 100999) ==
           StartGateResult::ResourcesStale);
    changed = state;
    changed.sessionMatches = false; // END or foreign ROC replaced START.
    assert(checkStartGate(changed, 100999) ==
           StartGateResult::SessionMismatch);
}

static void testMainGateValidatesExactWorkerWithoutAllowingCommands()
{
    static const int workerToken = 1;
    static const int otherWorkerToken = 2;
    MainGateOwnerState state{};
    state.executingOnMainGate = true;
    state.probeBusy = true;
    state.cancelRequested = false;
    state.currentWorkerThread = &workerToken;
    state.armedWorkerThread = &workerToken;
    state.currentContextGeneration = 37;
    state.bindingContextGeneration = 37;
    state.currentPowerGeneration = 8;
    state.bindingPowerGeneration = 8;
    state.currentStationGeneration = 19;
    state.bindingStationGeneration = 19;
    assert(mainGateOwnerCurrent(state));

    auto stale = state;
    stale.executingOnMainGate = false;
    assert(!mainGateOwnerCurrent(stale));
    stale = state;
    stale.currentWorkerThread = &otherWorkerToken;
    assert(!mainGateOwnerCurrent(stale));
    stale = state;
    stale.cancelRequested = true;
    assert(!mainGateOwnerCurrent(stale));
    stale = state;
    stale.probeBusy = false;
    assert(!mainGateOwnerCurrent(stale));
    stale = state;
    ++stale.currentContextGeneration;
    assert(!mainGateOwnerCurrent(stale));
    stale = state;
    ++stale.currentPowerGeneration;
    assert(!mainGateOwnerCurrent(stale));
    stale = state;
    ++stale.currentStationGeneration;
    assert(!mainGateOwnerCurrent(stale));
}

static void testMainGateArmRequiresExecutingWorker()
{
    static const int workerToken = 1;
    static const int otherThreadToken = 2;
    MainGateArmOwnerState state{};
    state.executingOnMainGate = true;
    state.probeBusy = true;
    state.cancelRequested = false;
    state.executingThread = &workerToken;
    state.currentWorkerThread = &workerToken;
    state.currentContextGeneration = 37;
    state.bindingContextGeneration = 37;
    state.currentPowerGeneration = 8;
    state.bindingPowerGeneration = 8;
    state.currentStationGeneration = 19;
    state.bindingStationGeneration = 19;
    assert(mainGateArmOwnerCurrent(state));

    auto rejected = state;
    rejected.executingThread = &otherThreadToken;
    assert(!mainGateArmOwnerCurrent(rejected));
    rejected = state;
    rejected.executingOnMainGate = false;
    assert(!mainGateArmOwnerCurrent(rejected));
    rejected = state;
    rejected.cancelRequested = true;
    assert(!mainGateArmOwnerCurrent(rejected));
    rejected = state;
    rejected.probeBusy = false;
    assert(!mainGateArmOwnerCurrent(rejected));
    rejected = state;
    ++rejected.currentContextGeneration;
    assert(!mainGateArmOwnerCurrent(rejected));
    rejected = state;
    ++rejected.currentPowerGeneration;
    assert(!mainGateArmOwnerCurrent(rejected));
    rejected = state;
    ++rejected.currentStationGeneration;
    assert(!mainGateArmOwnerCurrent(rejected));
}

static void testFirstFailureIsWriteOnce()
{
    FirstFailure first{};
    captureFirstFailure(&first, FailureSite::StartGateWindow, 70, 99000);
    captureFirstFailure(&first, FailureSite::Cleanup, 16, 120000);
    assert(first.captured);
    assert(first.site == FailureSite::StartGateWindow);
    assert(first.error == 70 && first.observedUs == 99000);
}

static void testOnlyHelperHandshakeIsFastPublished()
{
    assert(publicationForStage(1) == Publication::FastStateOnly);
    assert(publicationForStage(2) == Publication::FastStateOnly);
    assert(publicationForStage(3) == Publication::FastStateOnly);
    assert(publicationForStage(4) == Publication::FastStateOnly);
    assert(publicationForStage(7) == Publication::FastStateOnly);
    assert(publicationForStage(8) == Publication::Full);
    assert(publicationForStage(9) == Publication::Full);
    assert(publicationForStage(10) == Publication::Full);
}

static CleanupEvidence safeAfterEnd()
{
    CleanupEvidence evidence{};
    evidence.sessionSubmitted = true;
    evidence.canonicalEnd = true;
    evidence.cleanupAllowed = true;
    evidence.outcomeUnknown = false;
    evidence.ownerCurrent = true;
    evidence.epochsCurrent = true;
    evidence.ticketExact = true;
    evidence.noDoorbell = true;
    evidence.noMbufHeld = true;
    evidence.noCompletionPending = true;
    return evidence;
}

static void testCleanupIsAllowedOnlyAfterKnownEndWithoutDma()
{
    const CleanupEvidence safe = safeAfterEnd();
    assert(mayCleanupAfterEnd(safe));
    const auto reject = [](CleanupEvidence changed) {
        assert(!mayCleanupAfterEnd(changed));
    };
    { auto e = safe; e.canonicalEnd = false; reject(e); }
    { auto e = safe; e.cleanupAllowed = false; reject(e); }
    { auto e = safe; e.outcomeUnknown = true; reject(e); }
    { auto e = safe; e.ownerCurrent = false; reject(e); }
    { auto e = safe; e.epochsCurrent = false; reject(e); }
    { auto e = safe; e.ticketExact = false; reject(e); }
    { auto e = safe; e.noDoorbell = false; reject(e); }
    { auto e = safe; e.noMbufHeld = false; reject(e); }
    { auto e = safe; e.noCompletionPending = false; reject(e); }
    { auto e = safe; e.sessionSubmitted = false; reject(e); }
}

static void testPriorClosedOriginTicketDoesNotBlockCurrentPreTicketCleanup()
{
    using namespace NativeAwdlDirectedOriginTx;
    Snapshot prior{};
    prior.ticketPresent = true;
    prior.state = State::Closed;
    prior.ticketSerial = 11;
    prior.ownerSerial = 21;
    prior.runSerial = 31;
    prior.interfaceIncarnation = 4;
    Ticket noCurrentTicket{};
    assert(originTicketSafeForCleanup(prior, noCurrentTicket, 22, 32));

    auto reject = [&](Snapshot changed, uint64_t currentOwner = 22,
                      uint64_t currentRun = 32) {
        assert(!originTicketSafeForCleanup(
            changed, noCurrentTicket, currentOwner, currentRun));
    };
    { auto value = prior; value.state = State::Open; reject(value); }
    { auto value = prior; value.state = State::Queued;
      value.packetQueued = true; reject(value); }
    { auto value = prior; value.state = State::Popping;
      value.packetPopping = true; reject(value); }
    { auto value = prior; value.packetQueued = true; reject(value); }
    { auto value = prior; value.runSerial = 32; reject(value); }
    { auto value = prior; value.ownerSerial = 22; reject(value); }
    { auto value = prior; value.state = static_cast<State>(99); reject(value); }
    reject(prior, 0, 32);

    Snapshot initial{};
    assert(originTicketSafeForCleanup(initial, noCurrentTicket, 22, 32));
    initial.ticketPresent = true;
    assert(!originTicketSafeForCleanup(initial, noCurrentTicket, 22, 32));

    Ticket current{};
    current.ticketSerial = 12;
    current.ownerSerial = 22;
    current.runSerial = 32;
    current.interfaceIncarnation = 4;
    current.rocStartUs = 100;
    current.deadlineUs = 200;
    current.ifindex = 7;
    current.epochs = {22, 5, 6, 22};
    Snapshot matching{};
    matching.ticketPresent = true;
    matching.state = State::Closed;
    matching.ticketSerial = 12;
    matching.ownerSerial = 22;
    matching.runSerial = 32;
    matching.interfaceIncarnation = 4;
    matching.rocStartUs = 100;
    matching.deadlineUs = 200;
    matching.ifindex = 7;
    matching.epochs = current.epochs;
    assert(originTicketSafeForCleanup(matching, current, 22, 32));
    matching.epochs.power++;
    assert(!originTicketSafeForCleanup(matching, current, 22, 32));
}

static void testRxLeasePropertiesPublishOnlyOnIdentityChanges()
{
    using NativeP2PDirectedDataControl::shouldPublishRxLeaseProperties;
    bool published = false;
    assert(shouldPublishRxLeaseProperties(true, published, false));
    published = true; // First valid ROC lease has reached IORegistry.
    assert(!shouldPublishRxLeaseProperties(true, published, true));
    assert(shouldPublishRxLeaseProperties(true, published, false));
    assert(shouldPublishRxLeaseProperties(false, published, false));
    published = false; // Terminal/invalid lease revokes the publication.
    assert(!shouldPublishRxLeaseProperties(false, published, false));
}

int main()
{
    testGateSamplesTimeAfterQueueDelay();
    testMainGateValidatesExactWorkerWithoutAllowingCommands();
    testMainGateArmRequiresExecutingWorker();
    testFirstFailureIsWriteOnce();
    testOnlyHelperHandshakeIsFastPublished();
    testCleanupIsAllowedOnlyAfterKnownEndWithoutDma();
    testPriorClosedOriginTicketDoesNotBlockCurrentPreTicketCleanup();
    testRxLeasePropertiesPublishOnlyOnIdentityChanges();
}
