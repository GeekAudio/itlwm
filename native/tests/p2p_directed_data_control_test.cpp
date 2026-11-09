// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_directed_data_control.hpp"
#include "../p2p_directed_complete_cleanup.hpp"
#include "../awdl_directed_origin_tx.hpp"
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

static NativeP2PDirectedDataControl::RxLeaseGateEvidence validRxLeaseGate()
{
    using NativeP2PDirectedDataControl::RxLeaseGateEvidence;
    RxLeaseGateEvidence evidence{};
    evidence.rxEpochCurrent = true;
    evidence.resourcesCurrent = true;
    evidence.dataSnapshotCurrent = true;
    evidence.ownerCurrent = true;
    evidence.traceCurrent = true;
    evidence.radioReady = true;
    evidence.profileReady = true;
    evidence.mccCurrent = true;
    evidence.sessionCurrent = true;
    evidence.windowCurrent = true;
    evidence.channelCurrent = true;
    evidence.addressCurrent = true;
    evidence.leasePolicyCurrent = true;
    evidence.outputValid = true;
    evidence.mainGateCurrent = true;
    return evidence;
}

static void testRxLeaseRejectMaskNamesOnlyFailedGates()
{
    using namespace NativeP2PDirectedDataControl;
    assert(rxLeaseRejectMask(RxLeaseGateEvidence{}) ==
        (kRxLeaseRejectRxEpoch | kRxLeaseRejectResources |
         kRxLeaseRejectDataSnapshot | kRxLeaseRejectOwner |
         kRxLeaseRejectTrace | kRxLeaseRejectRadio |
         kRxLeaseRejectProfile | kRxLeaseRejectMcc |
         kRxLeaseRejectSession | kRxLeaseRejectWindow |
         kRxLeaseRejectChannel | kRxLeaseRejectAddress |
         kRxLeaseRejectPolicy | kRxLeaseRejectOutput |
         kRxLeaseRejectMainGate));
    auto evidence = validRxLeaseGate();
    assert(rxLeaseRejectMask(evidence) == 0);
    evidence.rxEpochCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectRxEpoch);
    evidence = validRxLeaseGate(); evidence.resourcesCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectResources);
    evidence = validRxLeaseGate(); evidence.dataSnapshotCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectDataSnapshot);
    evidence = validRxLeaseGate(); evidence.ownerCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectOwner);
    evidence = validRxLeaseGate(); evidence.traceCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectTrace);
    evidence = validRxLeaseGate(); evidence.radioReady = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectRadio);
    evidence = validRxLeaseGate(); evidence.profileReady = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectProfile);
    evidence = validRxLeaseGate(); evidence.mccCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectMcc);
    evidence = validRxLeaseGate(); evidence.sessionCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectSession);
    evidence = validRxLeaseGate(); evidence.windowCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectWindow);
    evidence = validRxLeaseGate(); evidence.channelCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectChannel);
    evidence = validRxLeaseGate(); evidence.addressCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectAddress);
    evidence = validRxLeaseGate(); evidence.leasePolicyCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectPolicy);
    evidence = validRxLeaseGate(); evidence.outputValid = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectOutput);
    evidence = validRxLeaseGate(); evidence.mainGateCurrent = false;
    assert(rxLeaseRejectMask(evidence) == kRxLeaseRejectMainGate);

    evidence = validRxLeaseGate();
    evidence.resourcesCurrent = false;
    evidence.mccCurrent = false;
    assert(rxLeaseRejectMask(evidence) ==
        (kRxLeaseRejectResources | kRxLeaseRejectMcc));
}

static NativeP2PDirectedDataControl::ReadyHandshakeEvidence readyHandshake()
{
    using NativeP2PDirectedDataControl::ReadyHandshakeEvidence;
    ReadyHandshakeEvidence evidence{};
    evidence.ownerCurrent = true;
    evidence.originWindowBound = true;
    evidence.originTicketBound = true;
    evidence.leaseCurrent = true;
    evidence.leasePropertiesPublished = true;
    evidence.leaseIdentityMatches = true;
    evidence.rocSessionCurrent = true;
    evidence.rocMirrorPublished = true;
    evidence.rocMirrorMatches = true;
    evidence.stagePublicationSucceeded = true;
    evidence.startUs = 100000;
    evidence.deadlineUs = 200000;
    evidence.nowUs = 199999;
    return evidence;
}

static void testReadyRequiresSameOwnerLeaseAndCurrentRocMirror()
{
    using namespace NativeP2PDirectedDataControl;
    const auto valid = readyHandshake();
    assert(mayPublishReady(valid));
    const auto reject = [](ReadyHandshakeEvidence changed,
                           uint32_t expectedBit) {
        const uint32_t mask = readyHandshakeRejectMask(changed);
        assert((mask & expectedBit) != 0);
        assert(!mayPublishReady(changed));
    };
    { auto e = valid; e.ownerCurrent = false;
      reject(e, kReadyRejectOwner); }
    { auto e = valid; e.originWindowBound = false;
      reject(e, kReadyRejectOriginWindow); }
    { auto e = valid; e.originTicketBound = false;
      reject(e, kReadyRejectOriginTicket); }
    { auto e = valid; e.leaseCurrent = false;
      reject(e, kReadyRejectLease); }
    { auto e = valid; e.leasePropertiesPublished = false;
      reject(e, kReadyRejectLeasePublication); }
    { auto e = valid; e.leaseIdentityMatches = false;
      reject(e, kReadyRejectLeaseIdentity); }
    { auto e = valid; e.rocSessionCurrent = false;
      reject(e, kReadyRejectRocSession); }
    { auto e = valid; e.rocMirrorPublished = false;
      reject(e, kReadyRejectRocMirrorPublication); }
    { auto e = valid; e.rocMirrorMatches = false;
      reject(e, kReadyRejectRocMirrorIdentity); }
    { auto e = valid; e.stagePublicationSucceeded = false;
      reject(e, kReadyRejectStagePublication); }
    { auto e = valid; e.nowUs = e.startUs - 1;
      reject(e, kReadyRejectWindow); }
    { auto e = valid; e.nowUs = e.deadlineUs;
      reject(e, kReadyRejectWindow); }
    { auto e = valid; e.deadlineUs++;
      reject(e, kReadyRejectWindow); }
    { auto e = valid; e.startUs = UINT64_MAX - 10;
      reject(e, kReadyRejectWindow); }
}

struct ReadyOriginPathModel {
    ReadyBindingView halBinding{};
    ReadyBindingView probeArmCopy{};
    NativeAwdlDirectedOriginTx::Ticket halTicket{};
    NativeAwdlDirectedOriginTx::Ticket probeTicket{};
    bool contextTicketBoundState = false;
    bool originWindowBound = false;
    bool contextTicketBound = false;
    bool probeTicketBound = false;
    bool originClosed = true;
};

static ReadyOriginPathModel armBindReadyOriginPath()
{
    ReadyOriginPathModel path{};
    path.halBinding.ownerSerial = 22;
    path.halBinding.runSerial = 32;
    path.halBinding.epochs = {37, 8, 19, 37};
    path.halBinding.generation = 8;
    path.halBinding.p2pFirmwareGeneration = 9;
    // Arm returns a copy before ROC START. Both window fields remain zero.
    path.probeArmCopy = path.halBinding;
    assert(path.probeArmCopy.rocToken == 0);
    assert(path.probeArmCopy.rocStartUs == 0);
    assert(path.probeArmCopy.deadlineUs == 0);

    // Mirror the HAL bind_origin_window write: only the canonical context is
    // updated after the matching START, never the probe's arm-time copy.
    path.halBinding.rocToken = 37;
    path.halBinding.rocStartUs = 100000;
    path.halBinding.deadlineUs = 200000;
    path.contextTicketBoundState = true;
    path.originWindowBound = true;
    path.contextTicketBound = true;
    path.probeTicketBound = true;
    path.originClosed = false;

    auto &ticket = path.halTicket;
    ticket.ticketSerial = 12;
    ticket.ownerSerial = 22;
    ticket.runSerial = 32;
    ticket.interfaceIncarnation = 4;
    ticket.rocStartUs = 100000;
    ticket.deadlineUs = 200000;
    ticket.ifindex = 7;
    ticket.sourceMac[0] = 2;
    ticket.sourceMac[5] = 1;
    ticket.epochs = {37, 8, 19, 37};
    path.probeTicket = path.halTicket;
    return path;
}

static ReadyOriginWindowWitness readyOriginWitness(
    const ReadyOriginPathModel &path)
{
    ReadyOriginWindowWitness witness{};
    witness.onMainGate = true;
    witness.contextTicketBoundState = path.contextTicketBoundState;
    witness.originWindowBound = path.originWindowBound;
    witness.contextTicketBound = path.contextTicketBound;
    witness.probeTicketBound = path.probeTicketBound;
    witness.originClosed = path.originClosed;
    witness.rocSessionCurrent = true;
    witness.armBinding = path.probeArmCopy;
    witness.canonicalBinding = path.halBinding;
    witness.currentEpochs = {37, 8, 19, 37};
    witness.currentPowerGeneration = 8;
    witness.currentFirmwareGeneration = 9;
    witness.currentOwnerSerial = 22;
    witness.currentRocToken = 37;
    witness.sessionRocToken = 37;
    witness.sessionStartUs = 100000;
    witness.rxLeaseStartUs = 100000;
    witness.rxLeaseDeadlineUs = 200000;
    witness.nowUs = 199999;
    witness.contextTicket = &path.halTicket;
    witness.probeTicket = &path.probeTicket;
    return witness;
}

static void testReadyProducerUsesCanonicalPostStartBinding()
{
    auto path = armBindReadyOriginPath();
    auto witness = readyOriginWitness(path);
    // The old producer expression read this immutable, pre-START copy and
    // therefore rejected even though HAL had bound the exact live RX window.
    assert(path.probeArmCopy.rocToken == 0);
    assert(path.probeArmCopy.rocStartUs != witness.rxLeaseStartUs);
    assert(path.probeArmCopy.deadlineUs != witness.rxLeaseDeadlineUs);
    assert(readyOriginWindowCurrent(witness));
    auto handshake = readyHandshake();
    handshake.originWindowBound = path.probeArmCopy.rocToken ==
            witness.sessionRocToken &&
        path.probeArmCopy.rocStartUs == witness.rxLeaseStartUs &&
        path.probeArmCopy.deadlineUs == witness.rxLeaseDeadlineUs;
    assert(readyHandshakeRejectMask(handshake) ==
           kReadyRejectOriginWindow);
    handshake.originWindowBound = readyOriginWindowCurrent(witness);
    assert(readyHandshakeRejectMask(handshake) == 0);

    const auto reject = [](ReadyOriginWindowWitness changed) {
        assert(!readyOriginWindowCurrent(changed));
    };
    { auto e = witness; e.currentOwnerSerial++; reject(e); }
    { auto e = witness; ++e.canonicalBinding.epochs.power; reject(e); }
    { auto e = witness; auto ticket = *e.probeTicket;
      ++ticket.runSerial; e.probeTicket = &ticket; reject(e); }
    { auto e = witness; e.nowUs = e.canonicalBinding.deadlineUs; reject(e); }
    { auto e = witness; e.nowUs = e.canonicalBinding.rocStartUs - 1; reject(e); }
    { auto e = witness; e.contextTicketBoundState = false; reject(e); }
    { auto e = witness; e.originWindowBound = false; reject(e); }
    { auto e = witness; e.contextTicketBound = false; reject(e); }
    { auto e = witness; e.originClosed = true; reject(e); }
    { auto e = witness; ++e.canonicalBinding.deadlineUs; reject(e); }
    { auto e = witness; ++e.currentRocToken; reject(e); }
    { auto e = witness; e.rocSessionCurrent = false; reject(e); }
}

static void testNoDoorbellProofReportsUnknownAndOwnershipBits()
{
    using namespace NativeP2PDirectedDataControl;
    NoDoorbellEvidence evidence{};
    evidence.snapshotValid = true;
    assert(provesNoDoorbell(evidence));
    evidence.doorbellIssued = true;
    assert(noDoorbellRejectMask(evidence) == kNoDoorbellRejectDoorbell);
    evidence = {};
    evidence.snapshotValid = true;
    evidence.mbufHeldByRing = true;
    assert(noDoorbellRejectMask(evidence) == kNoDoorbellRejectMbufHeld);
    evidence = {};
    evidence.snapshotValid = true;
    evidence.completionArmed = true;
    assert(noDoorbellRejectMask(evidence) ==
           kNoDoorbellRejectCompletionArmed);
    evidence = {};
    assert(noDoorbellRejectMask(evidence) == kNoDoorbellRejectSnapshot);
    evidence.snapshotValid = true;
    evidence.doorbellIssued = true;
    evidence.mbufHeldByRing = true;
    evidence.completionArmed = true;
    assert(noDoorbellRejectMask(evidence) ==
        (kNoDoorbellRejectDoorbell | kNoDoorbellRejectMbufHeld |
         kNoDoorbellRejectCompletionArmed));
}

static void testDirectedCompleteCleanupRequiresCurrentProofAndOuterRemove()
{
    using namespace NativeP2PDirectedCompleteCleanup;
    InnerProof inner{};
    inner.mainGate = true;
    inner.ownerCurrent = true;
    inner.contextGenerationMatches = true;
    inner.powerGenerationMatches = true;
    inner.stationGenerationMatches = true;
    inner.firmwareGenerationMatches = true;
    inner.p2pFirmwareGenerationMatches = true;
    inner.canonicalEnd = true;
    inner.rocTokenMatches = true;
    inner.rocComplete = true;
    inner.bindingAbsent = true;
    inner.phyUnleased = true;
    inner.originalChannelRestored = true;
    inner.stationQueueDataAbsent = true;
    inner.originTicketMatches = true;
    inner.originNoPendingPackets = true;
    inner.originTerminalAccepted = true;
    assert(innerProofComplete(inner));

    auto stale = inner;
    stale.contextGenerationMatches = false;
    assert(!innerProofComplete(stale));
    stale = inner;
    stale.ownerCurrent = false;
    assert(!innerProofComplete(stale));
    stale = inner;
    stale.stationQueueDataAbsent = false;
    assert(!innerProofComplete(stale));
    stale = inner;
    stale.rocComplete = false;
    stale.rocTokenMatches = false;
    assert(!innerProofComplete(stale));

    OuterProof outer{true, true, true, true};
    assert(outerProofComplete(outer));
    outer.removeResultZero = false;
    assert(!outerProofComplete(outer));
    outer.removeResultZero = true;
    outer.matchingRemoveResponse = false;
    assert(!outerProofComplete(outer));
    outer.matchingRemoveResponse = true;
    outer.outerResourcesAbsent = false;
    assert(!outerProofComplete(outer));
}

static void testRealOriginLedgerSpentCloseFeedsCompleteCleanupProof()
{
    using namespace NativeAwdlDirectedOriginTx;
    using namespace NativeP2PDirectedCompleteCleanup;

    const uint8_t ownMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t peerMac[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const uint8_t linkLocal[16] = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55};
    OpenRequest request{};
    request.ownerSerial = 700;
    request.runSerial = 900;
    request.rocStartUs = 1000000;
    request.deadlineUs = 1050000;
    request.epochs = {21, 22, 23, 21};
    request.rocChannelIndex = kRocChannelIndex;
    memcpy(request.sourceIPv6, linkLocal, sizeof(linkLocal));
    memcpy(request.peerMac, peerMac, sizeof(peerMac));
    const uint8_t nonce[kNonceLength] =
        {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87};
    memcpy(request.nonce, nonce, sizeof(nonce));

    Ledger ledger;
    Ticket ticket{};
    assert(ledger.open(request, request.rocStartUs,
                       request.epochs.power, 44, 7, ownMac, linkLocal,
                       &ticket));
    assert(ledger.acceptsOutput(ticket, request.rocStartUs + 1,
                                true, request.epochs.power, 44));
    assert(ledger.beginPop(ticket, request.rocStartUs + 2,
                           true, request.epochs.power, 44));
    assert(ledger.finishPop(ticket, request.rocStartUs + 3,
                            true, request.epochs.power, 44, true));
    // Production close succeeds for Spent but leaves its terminal state
    // unchanged; requiring Closed would reject valid transmit completion.
    assert(ledger.close(ticket, request.rocStartUs + 4));
    const Snapshot spent = ledger.snapshot(request.rocStartUs + 5, true);
    assert(spent.state == State::Spent && spent.packetSpent);
    assert(!spent.packetQueued && !spent.packetPopping);

    const auto originProof = evaluateOriginProof(
        spent, ticket, request.ownerSerial, request.runSerial,
        true, false, true, false);
    assert(originProof.ticketMatches && originProof.noPendingPackets &&
           originProof.terminalAccepted);

    InnerProof inner{};
    inner.mainGate = inner.ownerCurrent = true;
    inner.contextGenerationMatches = inner.powerGenerationMatches = true;
    inner.stationGenerationMatches = inner.firmwareGenerationMatches = true;
    inner.p2pFirmwareGenerationMatches = inner.canonicalEnd = true;
    inner.rocTokenMatches = inner.rocComplete = true;
    inner.bindingAbsent = inner.phyUnleased = true;
    inner.originalChannelRestored = inner.stationQueueDataAbsent = true;
    inner.originTicketMatches = originProof.ticketMatches;
    inner.originNoPendingPackets = originProof.noPendingPackets;
    inner.originTerminalAccepted = originProof.terminalAccepted;
    assert(innerProofComplete(inner));

    auto rejectOrigin = [&](const Snapshot &snapshot, const Ticket &candidate,
                            bool originClosed, bool ticketBound,
                            bool halComplete, bool noDoorbell) {
        const auto proof = evaluateOriginProof(snapshot, candidate,
            request.ownerSerial, request.runSerial, originClosed, ticketBound,
            halComplete, noDoorbell);
        auto changed = inner;
        changed.originTicketMatches = proof.ticketMatches;
        changed.originNoPendingPackets = proof.noPendingPackets;
        changed.originTerminalAccepted = proof.terminalAccepted;
        assert(!innerProofComplete(changed));
    };

    rejectOrigin(spent, ticket, false, false, true, false);
    rejectOrigin(spent, ticket, true, true, true, false);
    rejectOrigin(spent, ticket, true, false, false, false);
    auto staleTicket = ticket;
    ++staleTicket.runSerial;
    rejectOrigin(spent, staleTicket, true, false, true, false);
    auto active = spent;
    active.state = State::Popping;
    active.packetSpent = false;
    active.packetPopping = true;
    rejectOrigin(active, ticket, true, false, true, false);
    auto expired = spent;
    expired.state = State::Expired;
    expired.packetSpent = false;
    rejectOrigin(expired, ticket, true, false, true, false);
    const auto expiredProof = evaluateOriginProof(
        expired, ticket, request.ownerSerial, request.runSerial,
        true, false, false, true);
    assert(expiredProof.ticketMatches && expiredProof.noPendingPackets &&
           expiredProof.terminalAccepted);
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
    testRxLeaseRejectMaskNamesOnlyFailedGates();
    testReadyRequiresSameOwnerLeaseAndCurrentRocMirror();
    testReadyProducerUsesCanonicalPostStartBinding();
    testNoDoorbellProofReportsUnknownAndOwnershipBits();
    testDirectedCompleteCleanupRequiresCurrentProofAndOuterRemove();
    testRealOriginLedgerSpentCloseFeedsCompleteCleanupProof();
}
