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

} // namespace NativeP2PDirectedDataControl
