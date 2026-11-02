// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>
#include "awdl_directed_origin_tx.hpp"

namespace NativeP2PDirectedDataControl {

enum class FailureSite : uint32_t {
    None = 0,
    Other = 1,
    StartGateSession = 2,
    StartGateWindow = 3,
    StartGateOwner = 4,
    StartGateResources = 5,
    StartGateRadio = 6,
    StartGateProfile = 7,
    StartGateMcc = 8,
    BindWindow = 9,
    OpenOrigin = 10,
    BindOrigin = 11,
    EndWait = 12,
    Cleanup = 13
};

struct FirstFailure {
    FailureSite site = FailureSite::None;
    int32_t error = 0;
    uint64_t observedUs = 0;
    bool captured = false;
};

inline void captureFirstFailure(FirstFailure *first, FailureSite site,
                                int32_t error, uint64_t observedUs)
{
    if (!first || first->captured || error == 0 ||
        site == FailureSite::None || observedUs == 0)
        return;
    first->site = site;
    first->error = error;
    first->observedUs = observedUs;
    first->captured = true;
}

enum class StartGateResult : uint8_t {
    Ready,
    SessionMismatch,
    OutsideWindow,
    OwnerStale,
    ResourcesStale,
    RadioUnavailable,
    ProfileUnavailable,
    MccUnavailable
};

struct StartGateState {
    uint64_t startUs = 0;
    uint64_t deadlineUs = 0;
    bool sessionMatches = false;
    bool ownerCurrent = false;
    bool resourcesCurrent = false;
    bool radioReady = false;
    bool profileReady = false;
    bool mccReady = false;
};

// Read-only owner proof for predicates sampled while executing on the main
// command gate. This is deliberately separate from commandOwnerAllowed(): a
// gate callback may validate the worker that owns a run, but it must never be
// treated as permission to submit a blocking firmware command from that gate.
struct MainGateOwnerState {
    bool executingOnMainGate = false;
    bool probeBusy = false;
    bool cancelRequested = true;
    const void *currentWorkerThread = nullptr;
    const void *armedWorkerThread = nullptr;
    uint32_t currentContextGeneration = 0;
    uint32_t bindingContextGeneration = 0;
    uint32_t currentPowerGeneration = 0;
    uint32_t bindingPowerGeneration = 0;
    uint32_t currentStationGeneration = 0;
    uint32_t bindingStationGeneration = 0;
};

inline bool mainGateOwnerCurrent(const MainGateOwnerState &state)
{
    return state.executingOnMainGate && state.probeBusy &&
        !state.cancelRequested &&
        state.currentWorkerThread != nullptr &&
        state.currentWorkerThread == state.armedWorkerThread &&
        state.currentContextGeneration != 0 &&
        state.currentContextGeneration == state.bindingContextGeneration &&
        state.currentPowerGeneration != 0 &&
        state.currentPowerGeneration == state.bindingPowerGeneration &&
        state.currentStationGeneration != 0 &&
        state.currentStationGeneration == state.bindingStationGeneration;
}

// Arming establishes the worker identity used by later read-only gate
// checks, so the thread executing the arm callback must itself be that
// already-published worker. Keep this stronger admission rule separate from
// mainGateOwnerCurrent(), whose callbacks may run on another gate caller.
struct MainGateArmOwnerState {
    bool executingOnMainGate = false;
    bool probeBusy = false;
    bool cancelRequested = true;
    const void *executingThread = nullptr;
    const void *currentWorkerThread = nullptr;
    uint32_t currentContextGeneration = 0;
    uint32_t bindingContextGeneration = 0;
    uint32_t currentPowerGeneration = 0;
    uint32_t bindingPowerGeneration = 0;
    uint32_t currentStationGeneration = 0;
    uint32_t bindingStationGeneration = 0;
};

inline bool mainGateArmOwnerCurrent(const MainGateArmOwnerState &state)
{
    return state.executingOnMainGate && state.probeBusy &&
        !state.cancelRequested && state.executingThread != nullptr &&
        state.currentWorkerThread != nullptr &&
        state.executingThread == state.currentWorkerThread &&
        state.currentContextGeneration != 0 &&
        state.currentContextGeneration == state.bindingContextGeneration &&
        state.currentPowerGeneration != 0 &&
        state.currentPowerGeneration == state.bindingPowerGeneration &&
        state.currentStationGeneration != 0 &&
        state.currentStationGeneration == state.bindingStationGeneration;
}

// Call only after sampling nowUs on the same main gate which reads the current
// owner, epochs, ROC event, station, queue, and channel state. A worker-side
// timestamp is not a substitute: runAction may have queued past the ROC END.
inline StartGateResult checkStartGate(const StartGateState &state,
                                      uint64_t nowUs)
{
    if (!state.sessionMatches)
        return StartGateResult::SessionMismatch;
    if (!state.startUs || state.deadlineUs <= state.startUs ||
        nowUs < state.startUs || nowUs >= state.deadlineUs)
        return StartGateResult::OutsideWindow;
    if (!state.ownerCurrent)
        return StartGateResult::OwnerStale;
    if (!state.resourcesCurrent)
        return StartGateResult::ResourcesStale;
    if (!state.radioReady)
        return StartGateResult::RadioUnavailable;
    if (!state.profileReady)
        return StartGateResult::ProfileUnavailable;
    if (!state.mccReady)
        return StartGateResult::MccUnavailable;
    return StartGateResult::Ready;
}

inline FailureSite failureSite(StartGateResult result)
{
    switch (result) {
    case StartGateResult::Ready: return FailureSite::None;
    case StartGateResult::SessionMismatch:
        return FailureSite::StartGateSession;
    case StartGateResult::OutsideWindow:
        return FailureSite::StartGateWindow;
    case StartGateResult::OwnerStale:
        return FailureSite::StartGateOwner;
    case StartGateResult::ResourcesStale:
        return FailureSite::StartGateResources;
    case StartGateResult::RadioUnavailable:
        return FailureSite::StartGateRadio;
    case StartGateResult::ProfileUnavailable:
        return FailureSite::StartGateProfile;
    case StartGateResult::MccUnavailable:
        return FailureSite::StartGateMcc;
    }
    return FailureSite::Other;
}

enum class Publication : uint8_t {
    Full,
    FastStateOnly
};

inline Publication publicationForStage(uint32_t stage)
{
    // The one-shot userspace helper polls Stage/Ready. Keep all nonterminal
    // states small; detailed telemetry is emitted after the bounded window.
    return stage < 8 ? Publication::FastStateOnly : Publication::Full;
}

struct CleanupEvidence {
    bool sessionSubmitted = false;
    bool canonicalEnd = false;
    bool cleanupAllowed = false;
    bool outcomeUnknown = true;
    bool ownerCurrent = false;
    bool epochsCurrent = false;
    bool ticketExact = false;
    bool noDoorbell = false;
    bool noMbufHeld = false;
    bool noCompletionPending = false;
};

// A directed session may release resources after failure only when its exact
// scheduled END is canonical and the matching owner/epoch still has no TX
// ownership. Unknown results and any possible DMA remain quarantined.
inline bool mayCleanupAfterEnd(const CleanupEvidence &evidence)
{
    return evidence.sessionSubmitted && evidence.canonicalEnd &&
        evidence.cleanupAllowed && !evidence.outcomeUnknown &&
        evidence.ownerCurrent && evidence.epochsCurrent &&
        evidence.ticketExact && evidence.noDoorbell &&
        evidence.noMbufHeld && evidence.noCompletionPending;
}

// Cleanup may observe a Closed ticket retained by an older run. It is safe
// only when that ticket is terminal, has no queued/popping packet, and its
// owner/run identity is distinct from this run. Unknown identity stays closed.
inline bool originTicketSafeForCleanup(
    const NativeAwdlDirectedOriginTx::Snapshot &snapshot,
    const NativeAwdlDirectedOriginTx::Ticket &runTicket,
    uint64_t currentOwnerSerial, uint64_t currentRunSerial)
{
    using namespace NativeAwdlDirectedOriginTx;
    const bool packetIdle = !snapshot.packetQueued && !snapshot.packetPopping;
    if (runTicket.ticketSerial != 0) {
        const bool openOrClosed = snapshot.state == State::Open ||
            snapshot.state == State::Closed;
        return snapshot.ticketPresent && packetIdle && openOrClosed &&
            currentOwnerSerial != 0 && currentRunSerial != 0 &&
            runTicket.ownerSerial == currentOwnerSerial &&
            runTicket.runSerial == currentRunSerial &&
            snapshot.ticketSerial == runTicket.ticketSerial &&
            snapshot.ownerSerial == runTicket.ownerSerial &&
            snapshot.runSerial == runTicket.runSerial &&
            snapshot.interfaceIncarnation == runTicket.interfaceIncarnation &&
            snapshot.rocStartUs == runTicket.rocStartUs &&
            snapshot.deadlineUs == runTicket.deadlineUs &&
            snapshot.ifindex == runTicket.ifindex &&
            sameEpochs(snapshot.epochs, runTicket.epochs);
    }

    if (!snapshot.ticketPresent)
        return snapshot.state == State::Closed && packetIdle &&
            snapshot.ticketSerial == 0 && snapshot.ownerSerial == 0 &&
            snapshot.runSerial == 0 && snapshot.interfaceIncarnation == 0;

    const bool terminal = snapshot.state == State::Closed ||
        snapshot.state == State::Spent || snapshot.state == State::Expired ||
        snapshot.state == State::Revoked;
    return terminal && packetIdle && snapshot.ticketSerial != 0 &&
        snapshot.ownerSerial != 0 && snapshot.runSerial != 0 &&
        snapshot.interfaceIncarnation != 0 && currentOwnerSerial != 0 &&
        currentRunSerial != 0 &&
        snapshot.ownerSerial != currentOwnerSerial &&
        snapshot.runSerial != currentRunSerial;
}

// The controller lease is a userspace handshake, while the BSD bridge needs
// a fresh `nowUs` on each ROC read. Refreshing that in-memory lease does not
// require rewriting identical IORegistry fields on every poll.
inline bool shouldPublishRxLeaseProperties(bool leaseValid,
                                           bool previouslyPublished,
                                           bool sameIdentity)
{
    return leaseValid ? (!previouslyPublished || !sameIdentity) :
                        previouslyPublished;
}

enum RxLeaseReject : uint32_t {
    kRxLeaseRejectRxEpoch = 1u << 0,
    kRxLeaseRejectResources = 1u << 1,
    kRxLeaseRejectDataSnapshot = 1u << 2,
    kRxLeaseRejectOwner = 1u << 3,
    kRxLeaseRejectTrace = 1u << 4,
    kRxLeaseRejectRadio = 1u << 5,
    kRxLeaseRejectProfile = 1u << 6,
    kRxLeaseRejectMcc = 1u << 7,
    kRxLeaseRejectSession = 1u << 8,
    kRxLeaseRejectWindow = 1u << 9,
    kRxLeaseRejectChannel = 1u << 10,
    kRxLeaseRejectAddress = 1u << 11,
    kRxLeaseRejectPolicy = 1u << 12,
    kRxLeaseRejectOutput = 1u << 13,
    kRxLeaseRejectMainGate = 1u << 14
};

struct RxLeaseGateEvidence {
    bool rxEpochCurrent = false;
    bool resourcesCurrent = false;
    bool dataSnapshotCurrent = false;
    bool ownerCurrent = false;
    bool traceCurrent = false;
    bool radioReady = false;
    bool profileReady = false;
    bool mccCurrent = false;
    bool sessionCurrent = false;
    bool windowCurrent = false;
    bool channelCurrent = false;
    bool addressCurrent = false;
    bool leasePolicyCurrent = false;
    bool outputValid = false;
    bool mainGateCurrent = false;
};

inline uint32_t rxLeaseRejectMask(const RxLeaseGateEvidence &evidence)
{
    uint32_t mask = 0;
    if (!evidence.rxEpochCurrent) mask |= kRxLeaseRejectRxEpoch;
    if (!evidence.resourcesCurrent) mask |= kRxLeaseRejectResources;
    if (!evidence.dataSnapshotCurrent) mask |= kRxLeaseRejectDataSnapshot;
    if (!evidence.ownerCurrent) mask |= kRxLeaseRejectOwner;
    if (!evidence.traceCurrent) mask |= kRxLeaseRejectTrace;
    if (!evidence.radioReady) mask |= kRxLeaseRejectRadio;
    if (!evidence.profileReady) mask |= kRxLeaseRejectProfile;
    if (!evidence.mccCurrent) mask |= kRxLeaseRejectMcc;
    if (!evidence.sessionCurrent) mask |= kRxLeaseRejectSession;
    if (!evidence.windowCurrent) mask |= kRxLeaseRejectWindow;
    if (!evidence.channelCurrent) mask |= kRxLeaseRejectChannel;
    if (!evidence.addressCurrent) mask |= kRxLeaseRejectAddress;
    if (!evidence.leasePolicyCurrent) mask |= kRxLeaseRejectPolicy;
    if (!evidence.outputValid) mask |= kRxLeaseRejectOutput;
    if (!evidence.mainGateCurrent) mask |= kRxLeaseRejectMainGate;
    return mask;
}

enum ReadyHandshakeReject : uint32_t {
    kReadyRejectOwner = 1u << 0,
    kReadyRejectOriginWindow = 1u << 1,
    kReadyRejectOriginTicket = 1u << 2,
    kReadyRejectLease = 1u << 3,
    kReadyRejectLeasePublication = 1u << 4,
    kReadyRejectLeaseIdentity = 1u << 5,
    kReadyRejectRocSession = 1u << 6,
    kReadyRejectRocMirrorPublication = 1u << 7,
    kReadyRejectRocMirrorIdentity = 1u << 8,
    kReadyRejectWindow = 1u << 9,
    kReadyRejectStagePublication = 1u << 10
};

// A probe retains the immutable identity copied at arm time, while HAL owns
// the canonical origin window written after ROC START. Compare their identity
// fields, but read window/ticket state only from the canonical HAL context.
struct ReadyBindingView {
    uint64_t ownerSerial = 0;
    uint64_t runSerial = 0;
    NativeAwdlDirectedOriginTx::Epochs epochs{};
    uint32_t generation = 0;
    uint32_t p2pFirmwareGeneration = 0;
    uint64_t rocToken = 0;
    uint64_t rocStartUs = 0;
    uint64_t deadlineUs = 0;
};

struct ReadyOriginWindowWitness {
    bool onMainGate = false;
    bool contextTicketBoundState = false;
    bool originWindowBound = false;
    bool contextTicketBound = false;
    bool probeTicketBound = false;
    bool originClosed = true;
    bool rocSessionCurrent = false;
    ReadyBindingView armBinding{};
    ReadyBindingView canonicalBinding{};
    NativeAwdlDirectedOriginTx::Epochs currentEpochs{};
    uint32_t currentPowerGeneration = 0;
    uint32_t currentFirmwareGeneration = 0;
    uint64_t currentOwnerSerial = 0;
    uint64_t currentRocToken = 0;
    uint64_t sessionRocToken = 0;
    uint64_t sessionStartUs = 0;
    uint64_t rxLeaseStartUs = 0;
    uint64_t rxLeaseDeadlineUs = 0;
    uint64_t nowUs = 0;
    const NativeAwdlDirectedOriginTx::Ticket *contextTicket = nullptr;
    const NativeAwdlDirectedOriginTx::Ticket *probeTicket = nullptr;
};

inline bool readyOriginTicketMatchesBinding(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    const ReadyBindingView &binding)
{
    return ticket.ticketSerial != 0 && ticket.interfaceIncarnation != 0 &&
        ticket.ifindex != 0 && binding.ownerSerial != 0 &&
        binding.runSerial != 0 &&
        ticket.ownerSerial == binding.ownerSerial &&
        ticket.runSerial == binding.runSerial &&
        NativeAwdlDirectedOriginTx::sameEpochs(
            ticket.epochs, binding.epochs) &&
        ticket.rocStartUs == binding.rocStartUs &&
        ticket.deadlineUs == binding.deadlineUs &&
        NativeAwdlDirectedOriginTx::validUnicastMac(ticket.sourceMac);
}

// Called only by the main-gate ROC producer. The probe copy is intentionally
// not required to contain START/deadline: it predates HAL's post-START bind.
// It contributes only the original run identity; the canonical context,
// current ROC session, exact ticket pair, and fresh clock own window proof.
inline bool readyOriginWindowCurrent(
    const ReadyOriginWindowWitness &witness)
{
    using NativeAwdlDirectedOriginTx::validEpochs;
    using NativeAwdlDirectedOriginTx::sameEpochs;
    const auto &arm = witness.armBinding;
    const auto &canonical = witness.canonicalBinding;
    if (!witness.onMainGate || !witness.contextTicketBoundState ||
        !witness.originWindowBound || !witness.contextTicketBound ||
        !witness.probeTicketBound || witness.originClosed ||
        !witness.rocSessionCurrent || !arm.ownerSerial || !arm.runSerial ||
        arm.ownerSerial != canonical.ownerSerial ||
        arm.runSerial != canonical.runSerial ||
        !validEpochs(arm.epochs) || !validEpochs(canonical.epochs) ||
        !validEpochs(witness.currentEpochs) ||
        !sameEpochs(arm.epochs, canonical.epochs) ||
        !sameEpochs(canonical.epochs, witness.currentEpochs) ||
        !arm.generation || arm.generation != canonical.generation ||
        arm.generation != witness.currentPowerGeneration ||
        !arm.p2pFirmwareGeneration ||
        arm.p2pFirmwareGeneration != canonical.p2pFirmwareGeneration ||
        arm.p2pFirmwareGeneration != witness.currentFirmwareGeneration ||
        witness.currentOwnerSerial != canonical.ownerSerial ||
        !canonical.rocToken ||
        canonical.rocToken != witness.currentRocToken ||
        canonical.rocToken != witness.sessionRocToken ||
        !canonical.rocStartUs ||
        canonical.rocStartUs > UINT64_MAX -
            NativeAwdlDirectedOriginTx::kMaximumWindowUs ||
        canonical.deadlineUs != canonical.rocStartUs +
            NativeAwdlDirectedOriginTx::kMaximumWindowUs ||
        witness.sessionStartUs != canonical.rocStartUs ||
        witness.rxLeaseStartUs != canonical.rocStartUs ||
        witness.rxLeaseDeadlineUs != canonical.deadlineUs ||
        witness.nowUs < canonical.rocStartUs ||
        witness.nowUs >= canonical.deadlineUs ||
        !witness.contextTicket || !witness.probeTicket ||
        !NativeAwdlDirectedOriginTx::sameTicket(
            *witness.contextTicket, *witness.probeTicket) ||
        !readyOriginTicketMatchesBinding(
            *witness.contextTicket, canonical))
        return false;
    return true;
}

struct ReadyHandshakeEvidence {
    bool ownerCurrent = false;
    bool originWindowBound = false;
    bool originTicketBound = false;
    bool leaseCurrent = false;
    bool leasePropertiesPublished = false;
    bool leaseIdentityMatches = false;
    bool rocSessionCurrent = false;
    bool rocMirrorPublished = false;
    bool rocMirrorMatches = false;
    bool stagePublicationSucceeded = false;
    uint64_t nowUs = 0;
    uint64_t startUs = 0;
    uint64_t deadlineUs = 0;
};

inline uint32_t readyHandshakeRejectMask(
    const ReadyHandshakeEvidence &evidence)
{
    uint32_t mask = 0;
    if (!evidence.ownerCurrent) mask |= kReadyRejectOwner;
    if (!evidence.originWindowBound) mask |= kReadyRejectOriginWindow;
    if (!evidence.originTicketBound) mask |= kReadyRejectOriginTicket;
    if (!evidence.leaseCurrent) mask |= kReadyRejectLease;
    if (!evidence.leasePropertiesPublished)
        mask |= kReadyRejectLeasePublication;
    if (!evidence.leaseIdentityMatches)
        mask |= kReadyRejectLeaseIdentity;
    if (!evidence.rocSessionCurrent) mask |= kReadyRejectRocSession;
    if (!evidence.rocMirrorPublished)
        mask |= kReadyRejectRocMirrorPublication;
    if (!evidence.rocMirrorMatches)
        mask |= kReadyRejectRocMirrorIdentity;
    if (!evidence.startUs || evidence.startUs > UINT64_MAX - 100000ULL ||
        evidence.deadlineUs != evidence.startUs + 100000ULL ||
        evidence.nowUs < evidence.startUs ||
        evidence.nowUs >= evidence.deadlineUs)
        mask |= kReadyRejectWindow;
    if (!evidence.stagePublicationSucceeded)
        mask |= kReadyRejectStagePublication;
    return mask;
}

inline bool mayPublishReady(const ReadyHandshakeEvidence &evidence)
{
    return readyHandshakeRejectMask(evidence) == 0;
}

enum NoDoorbellReject : uint32_t {
    kNoDoorbellRejectSnapshot = 1u << 0,
    kNoDoorbellRejectDoorbell = 1u << 1,
    kNoDoorbellRejectMbufHeld = 1u << 2,
    kNoDoorbellRejectCompletionArmed = 1u << 3
};

struct NoDoorbellEvidence {
    bool snapshotValid = false;
    bool doorbellIssued = false;
    bool mbufHeldByRing = false;
    bool completionArmed = false;
};

inline uint32_t noDoorbellRejectMask(const NoDoorbellEvidence &evidence)
{
    uint32_t mask = 0;
    if (!evidence.snapshotValid) mask |= kNoDoorbellRejectSnapshot;
    if (evidence.doorbellIssued) mask |= kNoDoorbellRejectDoorbell;
    if (evidence.mbufHeldByRing) mask |= kNoDoorbellRejectMbufHeld;
    if (evidence.completionArmed)
        mask |= kNoDoorbellRejectCompletionArmed;
    return mask;
}

inline bool provesNoDoorbell(const NoDoorbellEvidence &evidence)
{
    return noDoorbellRejectMask(evidence) == 0;
}

} // namespace NativeP2PDirectedDataControl
