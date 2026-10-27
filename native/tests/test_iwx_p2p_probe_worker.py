#!/usr/bin/env python3
"""Fault-test the production ROC worker gate loop and reset retention guard.

The extracted worker runs against a mock IOCommandGate and a paced-MIF fixture;
Test058 separately exercises the real portable pacing helper and source contract.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
ITL = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
MIF_BURST = (ROOT / "native/awdl_mif_burst.hpp").read_text()
MIF_PACING = (ROOT / "native/awdl_mif_pacing.hpp").read_text()


def extract(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def extract_declaration(source, marker):
    start = source.index(marker)
    return source[start:source.index(";", start) + 1]


session_helpers = "\n\n".join((
    extract_declaration(PROBE, "static constexpr uint64_t kP2PProbeStartBudgetNs"),
    extract_declaration(PROBE, "static constexpr uint64_t kP2PProbeNsPerMs"),
    extract_declaration(PROBE, "static constexpr uint32_t kP2PProbeEndMarginMs"),
    extract_declaration(PROBE, "static constexpr uint32_t kP2PProbeSleepSliceMs"),
    extract(PROBE, "static uint64_t p2pProbeMonotonicNanoseconds()"),
    extract(PROBE, "static uint32_t p2pRocDurationTu("),
    extract(PROBE, "struct P2PProbeObservationWindow {") + ";",
    extract(PROBE, "static bool mifBurstTicketMatchesPreviousCompletion("),
    extract(PROBE, "static NativeAwdlProbe::MifBurstRepeatState mifBurstRepeatState("),
    extract(PROBE, "static NativeAwdlProbe::MifBurstRepeatPlan mifBurstDoorbellPlan("),
    extract(PROBE, "static int readRocState("),
    extract(PROBE, "static bool psfQueueProvenUnused("),
    extract(PROBE, "static int runTxProbeSession("),
))

session_shim = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <vector>

using mbuf_t = void *;
using IOReturn = int;
using OSObject = void;
using AbsoluteTime = uint64_t;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnNotReady = 1;
static constexpr IOReturn kIOReturnBadArgument = 2;
static constexpr uint32_t kTxProbeSessionSubmitted = 22;
static constexpr uint32_t kTxProbeWaitingForStart = 23;
static constexpr uint32_t kTxProbeActionSubmitted = 24;
static constexpr uint32_t kTxProbeWaitingForCompletionAndEnd = 25;
static constexpr uint32_t IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION = 3;
static unsigned gElapsedMs = 0;
static void clock_get_uptime(AbsoluteTime *uptime) {
    *uptime = static_cast<AbsoluteTime>(gElapsedMs) * 1000000ULL;
}
static void absolutetime_to_nanoseconds(AbsoluteTime uptime,
                                        uint64_t *nanoseconds) {
    *nanoseconds = uptime;
}

namespace IntelROCEvent {
struct SessionSnapshot {
    uint32_t generation = 0;
    uint32_t configuration = 0;
    int commandResult = 0;
    uint32_t startStatus = 0;
    bool commandReturned = false;
    bool startSeen = false;
    bool endSeen = false;
    bool cleanupAllowed = false;
    bool outcomeUnknown = false;
    uint64_t startObservedMonotonicUs = 0;
};
}

enum class TahoeP2PActionTxState : uint8_t { kIdle, kInFlight, kQuarantined };
struct P2PTxDiagnosticSnapshot {
    uint32_t actionState = 0;
    uint32_t outstandingTx = 0;
    uint32_t ticketStatus = 0;
    uint32_t ticketSequenceControl = 0;
    uint32_t ticketByteCount = 0;
    uint32_t ticketFrameControl = 0;
    uint32_t nativeDataAttempts = 0;
    bool ticketArmed = false;
    bool ticketCompleted = false;
    uint16_t nextSequenceNumber = 0;
    bool frameAttemptSucceeded = false;
    bool peerAcknowledged = false;
    bool queueLeaseActive = false;
    bool queueDoorbelled = true;
    bool txRingEmpty = false;
    bool ringIndicesConsistent = false;
};
struct ItlIwx;
struct iwx_softc {
    uint32_t sc_generation = 88;
    uint32_t sc_tx_rate_generation = 99;
};
struct TestPsfWitness { uint64_t startObservedUs = 1000; };
struct TestPsfCandidate { uint8_t bytes[4]{}; size_t length = 0; uint32_t blockers = 0; };
struct P2PProbeRun {
    ItlIwx *owner = nullptr;
    uint32_t contextGeneration = 77;
    uint32_t powerGeneration = 88;
    uint32_t stationGeneration = 99;
    bool actionTxAttempted = false;
    bool actionTxRequired = false;
    bool awdlPsfProbeEnabled = false;
    bool awdlMifFollowupEnabled = false;
    bool psfCandidatePrepared = false;
    bool mifCandidatePrepared = false;
    uint32_t psfStatus = 0;
    uint32_t psfBlockers = 0;
    TestPsfCandidate psfCandidate{};
    bool psfFrameSubmitted = false;
    bool psfResultCaptured = false;
    bool psfTxCompleted = false;
    bool psfTxSucceeded = false;
    bool psfPeerAcknowledged = false;
    uint32_t psfTicketStatus = 0;
    uint32_t mifStatus = 0;
    uint32_t mifBlockers = 0;
    uint32_t mifTicketStatus = 0;
    size_t mifCandidateLength = 0;
    bool mifTxAttempted = false;
    bool mifFrameSubmitted = false;
    bool mifResultCaptured = false;
    bool mifTxCompleted = false;
    bool mifTxSucceeded = false;
    bool mifPeerAcknowledged = false;
    bool mifBurstStopped = false;
    bool mifBurstCandidateIsRepeat = false;
    uint32_t mifPacingReason = 0;
    uint32_t actionFramesSubmitted = 0;
    uint32_t actionFramesCompleted = 0;
    uint32_t actionFramesSucceeded = 0;
    uint32_t nativeDataAttempts = 0;
    uint32_t mifBurstPreparedFrames = 0;
    uint32_t mifBurstAttemptedFrames = 0;
    uint32_t mifBurstSubmittedFrames = 0;
    uint32_t mifBurstCompletedFrames = 0;
    uint32_t mifBurstSucceededFrames = 0;
    uint32_t mifBurstStopReason = 0;
    uint32_t mifBurstEpoch = 0;
    uint32_t mifBurstLastTicketStatus = 0;
    uint32_t mifBurstLastTicketSequenceControl = 0;
    uint32_t mifBurstLastTicketByteCount = 0;
    uint32_t mifBurstLastTicketFrameControl = 0;
    uint16_t mifBurstLastNextSequenceNumber = 0;
    uint64_t mifBurstLastCompletionUs = 0;
    TestPsfWitness psfWitness{};
    uint32_t pendingFrameKind = 0;
    int txSubmitResult = 0;
};
enum PsfProbeStatus : uint32_t {
    kPsfProbeWaitingForStart = 1,
    kPsfProbeCandidateEncodedBlocked = 2,
    kPsfProbeCandidateRejected = 3,
    kPsfProbeFrameSubmissionAttempted = 4,
    kPsfProbeFrameBecameStale = 5,
    kPsfProbeEndedBeforeSubmit = 6,
    kPsfProbeCandidateEncodedReady = 7,
    kPsfProbeStartObservedNoCandidate = 8,
    kPsfProbeFrameTxCompleted = 9,
    kPsfProbeFrameTxFailed = 10
};
enum P2PFrameKind : uint32_t {
    kP2PFrameLegacyVendorAction = 1,
    kP2PFrameAwdlPsf = 2,
    kP2PFrameAwdlMif = 3
};
enum MifProbeStatus : uint32_t {
    kMifProbeNotRequested = 0,
    kMifProbeWaitingForPsfCompletion = 1,
    kMifProbeCandidateEncodedReady = 2,
    kMifProbePreflightRejected = 3,
    kMifProbeFirstPsfFailed = 4,
    kMifProbeEndedBeforeSubmit = 5,
    kMifProbeFrameSubmissionAttempted = 6,
    kMifProbeFrameBecameStale = 7,
    kMifProbeFrameTxCompleted = 8,
    kMifProbeFrameTxFailed = 9,
    kMifProbeQuarantined = 10,
    kMifProbePsfNotSubmitted = 11,
    kMifProbeWaitingForPeerPsf = 13
};
namespace NativeAwdlProbe {
static constexpr uint32_t kMifTxNoBlocker = 0;
static constexpr uint32_t kPsfTxNoBlocker = 0;
static constexpr uint32_t kPsfTxTxResourcesUnavailable = 1u << 12;
static constexpr uint32_t kPsfTxFrameAllocationFailed = 1u << 13;
static constexpr uint32_t kMifTxFirstPsfFailed = 1u << 2;
static constexpr uint32_t kMifTxFirstPsfNotCompleted = 1u << 1;
static constexpr uint32_t kMifTxRocEnded = 1u << 6;
static constexpr uint32_t kMifTxRocUnknown = 1u << 7;
static constexpr uint32_t kMifTxInvalidCandidate = 1u << 0;
}
static unsigned gPsfPrepareCalls = 0;
static unsigned gMifPrepareCalls = 0;
static unsigned gMifRepeatPrepareCalls = 0;
static bool gMifPrepareFails = false;
static bool gMifRepeatPrepareFails = false;
static bool gMifSubmitFails = false;
static bool gFailRepeatMifSubmit = false;
static bool gMifGateNotAdmitted = false;
static bool gPsfGateNotAdmitted = false;
static unsigned gAcceptedSubmitCalls = 0;
static unsigned gPublishedPsfKinds = 0;
static void mbuf_freem(mbuf_t) {}
static int gPsfFrameStorage = 0;
static int gMifFrameStorage = 0;
static int gMifRepeatFrameStorage[3] = {0, 0, 0};
static unsigned gMifRepeatFrameIndex = 0;
static std::vector<uint64_t> gMifRepeatSampleTimes;
static std::vector<uint16_t> gMifRepeatSequences;
static std::vector<const void *> gMifRepeatFramePointers;
static mbuf_t makeActionFrameFromBytes(const uint8_t *bytes, size_t length) {
    assert(bytes && length > 0);
    return length > 1 ? &gMifFrameStorage : &gPsfFrameStorage;
}
static bool preparePsfCandidateAfterStart(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &, uint32_t,
    uint16_t, uint64_t) {
    ++gPsfPrepareCalls;
    probe->psfCandidate.length = 1;
    probe->psfCandidate.bytes[0] = 0xd0;
    probe->psfBlockers = NativeAwdlProbe::kPsfTxNoBlocker;
    return true;
}
static void publishPsfProbeDetails(ItlIwx *, P2PProbeRun *, uint32_t kind) {
    gPublishedPsfKinds = kind;
}
static void publishMifProbeDetails(ItlIwx *, P2PProbeRun *) {}
static bool prepareMifCandidateAfterPsfCompletion(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &,
    const P2PTxDiagnosticSnapshot &, uint64_t, mbuf_t *frame) {
    assert(probe && probe->awdlMifFollowupEnabled && frame && !*frame);
    probe->mifCandidatePrepared = false;
    probe->mifBurstEpoch = probe->contextGeneration;
    probe->mifBurstCandidateIsRepeat = false;
    probe->mifBurstPreparedFrames = 0;
    probe->mifStatus = kMifProbeWaitingForPeerPsf;
    return false;
}
static NativeAwdlProbe::MifBurstRepeatState mifBurstRepeatState(
    const P2PProbeRun *, const IntelROCEvent::SessionSnapshot &,
    const P2PTxDiagnosticSnapshot &, uint64_t, bool, bool);
static NativeAwdlProbe::MifBurstRepeatPlan mifBurstDoorbellPlan(
    const P2PProbeRun *, const IntelROCEvent::SessionSnapshot &,
    const P2PTxDiagnosticSnapshot &, uint64_t);
static void resetMifFrameStateForRepeat(P2PProbeRun *);
static bool prepareMifCandidateAfterPreviousMif(
    P2PProbeRun *, const IntelROCEvent::SessionSnapshot &,
    const P2PTxDiagnosticSnapshot &, uint64_t, mbuf_t *);
static bool tryPrepareMifAtPacingPoint(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t sampleUs, mbuf_t *frame) {
    assert(probe && probe->awdlMifFollowupEnabled && frame && !*frame);
    // This mock worker fixture admits one MIF after its gate fixture says the
    // first PSF ticket is complete. Exact pacing/PSF evidence gates are tested
    // by native/tests/test058_mif_pacing.py.
    if (!probe->psfResultCaptured || !probe->psfTxSucceeded ||
        probe->mifCandidatePrepared)
        return false;
    if (probe->mifBurstSubmittedFrames != 0) {
        const auto repeatPlan = NativeAwdlProbe::planMifBurstRepeat(
            mifBurstRepeatState(probe, session, tx, sampleUs,
                                *frame == nullptr, false));
        if (!probe->mifResultCaptured || !probe->mifTxSucceeded)
            return false;
        if (repeatPlan.decision == NativeAwdlProbe::MifBurstDecision::Stop) {
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                repeatPlan.reason);
            return false;
        }
        if (repeatPlan.decision != NativeAwdlProbe::MifBurstDecision::Prepare)
            return false;
        resetMifFrameStateForRepeat(probe);
        if (!prepareMifCandidateAfterPreviousMif(
                probe, session, tx, sampleUs, frame)) {
            probe->mifBurstStopped = true;
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
            return false;
        }
        return true;
    }
    ++gMifPrepareCalls;
    if (gMifPrepareFails) {
        probe->mifCandidatePrepared = false;
        probe->mifStatus = kMifProbePreflightRejected;
        probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
        probe->mifBurstStopped = true;
        return false;
    }
    probe->mifCandidatePrepared = true;
    probe->mifStatus = kMifProbeCandidateEncodedReady;
    probe->mifBurstEpoch = probe->contextGeneration;
    probe->mifBurstPreparedFrames = 1;
    probe->mifBurstCandidateIsRepeat = false;
    *frame = &gMifFrameStorage;
    return true;
}
static bool prepareMifCandidateAfterPreviousMif(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t sampleUs, mbuf_t *frame) {
    assert(probe && frame && !*frame && session.startSeen &&
           !session.endSeen && !session.outcomeUnknown &&
           tx.ticketCompleted && tx.frameAttemptSucceeded &&
           tx.actionState == static_cast<uint32_t>(
               TahoeP2PActionTxState::kIdle));
    ++gMifRepeatPrepareCalls;
    gMifRepeatSampleTimes.push_back(sampleUs);
    gMifRepeatSequences.push_back(tx.nextSequenceNumber);
    if (gMifRepeatPrepareFails) return false;
    assert(gMifRepeatFrameIndex < 3);
    auto *storage = &gMifRepeatFrameStorage[gMifRepeatFrameIndex++];
    gMifRepeatFramePointers.push_back(storage);
    *frame = storage;
    probe->mifCandidatePrepared = true;
    probe->mifCandidateLength = 42;
    probe->mifStatus = kMifProbeCandidateEncodedReady;
    probe->mifBlockers = NativeAwdlProbe::kMifTxNoBlocker;
    ++probe->mifBurstPreparedFrames;
    return true;
}
static void resetMifFrameStateForRepeat(P2PProbeRun *probe) {
    assert(probe && probe->mifResultCaptured && probe->mifTxSucceeded);
    probe->mifCandidatePrepared = false;
    probe->mifTxAttempted = false;
    probe->mifFrameSubmitted = false;
    probe->mifResultCaptured = false;
    probe->mifTxCompleted = false;
    probe->mifTxSucceeded = false;
    probe->mifPeerAcknowledged = false;
    probe->mifTicketStatus = 0;
    probe->mifCandidateLength = 0;
    probe->mifStatus = kMifProbeWaitingForPsfCompletion;
    probe->mifBlockers = NativeAwdlProbe::kMifTxNoBlocker;
    probe->mifBurstCandidateIsRepeat = true;
}
enum RocEventOperation { kRocCommandReturned, kRocRead };
struct RocEventRun {
    P2PProbeRun *probe = nullptr;
    RocEventOperation operation = kRocRead;
    int commandResult = 0;
    IntelROCEvent::SessionSnapshot snapshot{};
    P2PTxDiagnosticSnapshot txSnapshot{};
    bool txSnapshotValid = false;
};
struct P2PTxSubmitRun {
    P2PProbeRun *probe = nullptr;
    mbuf_t frame = nullptr;
    bool frameConsumed = false;
    bool frameStale = false;
    bool psfFrame = false;
    bool mifFrame = false;
    int result = EBUSY;
};
using GateAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);

class IOCommandGate {
public:
    IOReturn runAction(GateAction action, void *context);
};

struct ReadFrame {
    IntelROCEvent::SessionSnapshot session{};
    P2PTxDiagnosticSnapshot tx{};
};
using TahoeP2pRocArmTracker = bool (*)(void *, uint32_t, uint32_t, uint32_t);

struct ItlIwx {
    IOCommandGate gate;
    iwx_softc com{};
    uint32_t nativeP2pProbeGeneration_ = 77;
    int commandResult = 0;
    bool epochValid = true;
    unsigned invalidateEpochAfterRead = 0;
    unsigned readIndex = 0;
    std::vector<uint32_t> submittedConfigurations;
    std::vector<uint32_t> submittedDurations;
    std::vector<ReadFrame> reads;

    IOCommandGate *tahoeP2pCommandGate() { return &gate; }
    int tahoeP2pRocSubmit(void *, uint32_t, uint32_t configuration, uint32_t durationMs,
                          TahoeP2pRocArmTracker, void *) {
        assert(durationMs == (configuration == 3 ? 900u : 100u));
        submittedConfigurations.push_back(configuration);
        submittedDurations.push_back(durationMs);
        return commandResult;
    }
    static bool tahoeP2pArmRoc(void *, uint32_t, uint32_t, uint32_t) {
        return true;
    }
    static IOReturn tahoeP2pRocEventAction(
        OSObject *, void *, void *, void *, void *);
};

static unsigned gSubmitCalls = 0;
static int gSubmitResult = 0;
static std::vector<uint32_t> gPublishedStages;
static void IOSleep(unsigned milliseconds) { gElapsedMs += milliseconds; }
static void publishP2PTxStage(ItlIwx *, uint32_t stage, int) {
    gPublishedStages.push_back(stage);
}

static IOReturn tahoeP2pSubmitActionInGate(
    OSObject *, void *opaque, void *, void *, void *) {
    auto *submit = static_cast<P2PTxSubmitRun *>(opaque);
    if (!submit || !submit->probe || !submit->frame)
        return kIOReturnBadArgument;
    ++gSubmitCalls;
    if (submit->psfFrame && gPsfGateNotAdmitted)
        return kIOReturnNotReady;
    if (submit->mifFrame && gMifGateNotAdmitted)
        return kIOReturnNotReady;
    if (submit->mifFrame && gMifSubmitFails) {
        submit->frameStale = true;
        return kIOReturnNotReady;
    }
    if (submit->mifFrame && gFailRepeatMifSubmit &&
        submit->probe->mifBurstSubmittedFrames >= 1) {
        submit->frameStale = true;
        return kIOReturnNotReady;
    }
    ++gAcceptedSubmitCalls;
    submit->probe->actionTxAttempted = true;
    submit->probe->actionTxRequired = true;
    ++submit->probe->actionFramesSubmitted;
    if (submit->psfFrame) {
        submit->probe->psfFrameSubmitted = true;
        submit->probe->pendingFrameKind = kP2PFrameAwdlPsf;
    }
    if (submit->mifFrame) {
        submit->probe->mifTxAttempted = true;
        assert(submit->probe->mifBurstAttemptedFrames <
               NativeAwdlProbe::kMifBurstMaximumFrames);
        ++submit->probe->mifBurstAttemptedFrames;
        submit->probe->mifFrameSubmitted = true;
        submit->probe->mifStatus = kMifProbeFrameSubmissionAttempted;
        submit->probe->pendingFrameKind = kP2PFrameAwdlMif;
        assert(submit->probe->mifBurstSubmittedFrames <
               NativeAwdlProbe::kMifBurstMaximumFrames);
        ++submit->probe->mifBurstSubmittedFrames;
    }
    submit->frame = nullptr;
    submit->frameConsumed = true;
    submit->result = gSubmitResult;
    return kIOReturnSuccess;
}

IOReturn IOCommandGate::runAction(GateAction action, void *context) {
    return action ? action(nullptr, context, nullptr, nullptr, nullptr) :
                    kIOReturnBadArgument;
}

IOReturn ItlIwx::tahoeP2pRocEventAction(
    OSObject *, void *opaque, void *, void *, void *) {
    auto *event = static_cast<RocEventRun *>(opaque);
    if (!event || !event->probe || !event->probe->owner)
        return kIOReturnBadArgument;
    ItlIwx *owner = event->probe->owner;
    if (event->operation == kRocCommandReturned)
        return kIOReturnSuccess;
    if (!owner->epochValid)
        return kIOReturnNotReady; // Simulate generation/owner mismatch.
    if (owner->reads.empty())
        return kIOReturnNotReady;
    const size_t index = owner->readIndex < owner->reads.size()
        ? owner->readIndex : owner->reads.size() - 1;
    event->snapshot = owner->reads[index].session;
    event->txSnapshot = owner->reads[index].tx;
    event->txSnapshotValid = true;
    event->probe->nativeDataAttempts =
        event->txSnapshot.nativeDataAttempts;
    ++owner->readIndex;
    if (owner->invalidateEpochAfterRead != 0 &&
        owner->readIndex == owner->invalidateEpochAfterRead)
        owner->epochValid = false;
    return kIOReturnSuccess;
}

"""

session_body = r"""
static IntelROCEvent::SessionSnapshot session(bool start, bool end,
                                               uint32_t configuration) {
    IntelROCEvent::SessionSnapshot value{};
    value.configuration = configuration;
    value.commandReturned = true;
    value.commandResult = 0;
    value.startSeen = start;
    value.startStatus = start ? 1 : 0;
    value.endSeen = end;
    value.cleanupAllowed = end;
    value.generation = 77;
    value.startObservedMonotonicUs = 1000;
    return value;
}
static P2PTxDiagnosticSnapshot tx(bool complete, bool success = true,
                                  uint32_t status = 1) {
    P2PTxDiagnosticSnapshot value{};
    value.ticketCompleted = complete;
    value.ticketStatus = status;
    value.ticketSequenceControl = 0x10;
    value.ticketByteCount = 36;
    value.ticketFrameControl = 0x00d0;
    value.nextSequenceNumber = 2;
    value.frameAttemptSucceeded = complete && success;
    value.queueLeaseActive = true;
    value.outstandingTx = 0;
    value.txRingEmpty = true;
    value.ringIndicesConsistent = true;
    value.actionState = static_cast<uint32_t>(complete ?
        TahoeP2PActionTxState::kIdle : TahoeP2PActionTxState::kInFlight);
    return value;
}
static P2PTxDiagnosticSnapshot txMif(uint16_t sequence, bool complete,
                                     bool success = true, uint32_t status = 1,
                                     uint32_t dataAttempts = 0) {
    auto value = tx(complete, success, status);
    value.ticketSequenceControl = static_cast<uint32_t>(sequence << 4);
    value.ticketByteCount = 42;
    value.ticketFrameControl = 0x00d0;
    value.nextSequenceNumber = static_cast<uint16_t>((sequence + 1u) & 0x0fffu);
    value.nativeDataAttempts = dataAttempts;
    return value;
}
static void resetMocks() {
    gSubmitCalls = 0; gAcceptedSubmitCalls = 0; gSubmitResult = 0;
    gPublishedStages.clear(); gElapsedMs = 0; gPsfPrepareCalls = 0;
    gMifPrepareCalls = 0; gMifRepeatPrepareCalls = 0;
    gMifPrepareFails = false; gMifRepeatPrepareFails = false;
    gMifSubmitFails = false; gFailRepeatMifSubmit = false;
    gMifGateNotAdmitted = false;
    gPsfGateNotAdmitted = false; gPublishedPsfKinds = 0;
    gMifRepeatFrameIndex = 0; gMifRepeatSampleTimes.clear();
    gMifRepeatSequences.clear(); gMifRepeatFramePointers.clear();
}

int main() {
    {
        P2PProbeRun probe{}; probe.awdlPsfProbeEnabled = true;
        probe.actionTxAttempted = true;
        P2PTxDiagnosticSnapshot snapshot{};
        snapshot.queueLeaseActive = snapshot.txRingEmpty = snapshot.ringIndicesConsistent = true;
        snapshot.queueDoorbelled = false;
        snapshot.actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kIdle);
        assert(psfQueueProvenUnused(&probe, &snapshot));
        snapshot.actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kQuarantined);
        assert(psfQueueProvenUnused(&probe, &snapshot));
        snapshot.actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kInFlight);
        assert(!psfQueueProvenUnused(&probe, &snapshot));
        snapshot.actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kIdle);
        snapshot.queueDoorbelled = true;
        assert(!psfQueueProvenUnused(&probe, &snapshot));
        snapshot.queueDoorbelled = false; snapshot.ticketArmed = true;
        assert(!psfQueueProvenUnused(&probe, &snapshot));
        snapshot.ticketArmed = false; snapshot.queueLeaseActive = false;
        assert(!psfQueueProvenUnused(&probe, &snapshot));
    }
    assert(p2pRocDurationTu(900) == 878);
    assert(static_cast<uint64_t>(p2pRocDurationTu(900)) * 1024ULL == 899072ULL);

    // Exercise the actual production pre-doorbell recheck with candidate 3
    // already prepared: prepared=3/submitted=2 must remain admissible, while
    // submitted=3 must be rejected before another doorbell.
    {
        ItlIwx owner;
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.mifBurstEpoch = probe.contextGeneration;
        probe.mifBurstPreparedFrames = 3;
        probe.mifBurstSubmittedFrames = 2;
        probe.mifBurstCompletedFrames = 2;
        probe.mifBurstSucceededFrames = 2;
        probe.mifBurstLastCompletionUs = 100000;
        probe.mifBurstLastTicketStatus = 1;
        probe.mifBurstLastTicketSequenceControl = 0x40;
        probe.mifBurstLastTicketByteCount = 42;
        probe.mifBurstLastTicketFrameControl = 0x00d0;
        probe.mifBurstLastNextSequenceNumber = 5;
        auto ticket = tx(true);
        ticket.ticketStatus = 1;
        ticket.ticketSequenceControl = 0x40;
        ticket.ticketByteCount = 42;
        ticket.ticketFrameControl = 0x00d0;
        ticket.nextSequenceNumber = 5;
        ticket.queueLeaseActive = true;
        ticket.txRingEmpty = true;
        ticket.ringIndicesConsistent = true;
        ticket.actionState = static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle);
        auto plan = mifBurstDoorbellPlan(&probe, session(true, false, 3),
            ticket, probe.mifBurstLastCompletionUs +
                NativeAwdlProbe::kMifBurstRepeatIntervalUs);
        assert(plan.decision == NativeAwdlProbe::MifBurstDecision::Prepare);
        probe.mifBurstSubmittedFrames = 3;
        plan = mifBurstDoorbellPlan(&probe, session(true, false, 3),
            ticket, probe.mifBurstLastCompletionUs +
                NativeAwdlProbe::kMifBurstRepeatIntervalUs);
        assert(plan.decision == NativeAwdlProbe::MifBurstDecision::Stop &&
               plan.reason == NativeAwdlProbe::MifBurstStopReason::FrameLimit);
    }

    // The PSF diagnostic builds only after the matching START and does not
    // send a frame when the current lease cannot prove safe transmission.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, true, 3), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, false, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gPsfPrepareCalls == 1);
        assert(gPublishedPsfKinds == kP2PFrameAwdlPsf);
        assert(gSubmitCalls == 0 && frame == nullptr);
        assert(!probe.actionTxAttempted);
    }

    // Real worker helper: START gates one submit; completion and END together
    // are required before the helper returns success for queue teardown.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(false, false, 3), tx(false)},
                       {session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, true, 3), tx(true)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(probe.actionTxAttempted && gSubmitCalls == 1);
        assert(owner.submittedConfigurations.size() == 1 &&
               owner.submittedConfigurations[0] == 3);
        assert(frame == nullptr && sessionOut.cleanupAllowed);
        assert(sessionOut.configuration == 3);
        assert(txOut.ticketCompleted && txOut.actionState ==
            static_cast<uint32_t>(TahoeP2PActionTxState::kIdle));
        assert(gPublishedStages.front() == kTxProbeSessionSubmitted);
    }

    // The successful START begins the 900 ms session window plus 100 ms
    // notification margin. Early TX completion alone must not end the wait.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads.push_back({session(true, false, 3), tx(false)});
        for (unsigned i = 1; i < 190; ++i)
            owner.reads.push_back({session(true, false, 3), tx(true)});
        owner.reads.push_back({session(true, true, 3), tx(true)});
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gElapsedMs >= 900 && gElapsedMs <= 1000);
        assert(gSubmitCalls == 1 && txOut.ticketCompleted && sessionOut.cleanupAllowed);
    }

    // START may arrive near the end of its 800 ms budget; a fresh bounded
    // session window then follows that first successful observation.
    {
        resetMocks();
        ItlIwx owner;
        for (unsigned i = 0; i < 159; ++i)
            owner.reads.push_back({session(false, false, 3), tx(false)});
        owner.reads.push_back({session(true, false, 3), tx(false)});
        for (unsigned i = 0; i < 189; ++i)
            owner.reads.push_back({session(true, false, 3), tx(true)});
        owner.reads.push_back({session(true, true, 3), tx(true)});
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gElapsedMs >= 1700 && gElapsedMs <= 1800);
        assert(gSubmitCalls == 1 && txOut.ticketCompleted && sessionOut.cleanupAllowed);
    }

    // No successful START by the 800 ms phase deadline times out without TX.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(false, false, 3), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(gElapsedMs == 800 && gSubmitCalls == 0 &&
               !probe.actionTxAttempted && frame == &frameStorage);
    }

    // Missing END remains a timeout even when TX becomes idle; elapsed time
    // never authorizes release or cleanup.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads.push_back({session(true, false, 3), tx(false)});
        for (unsigned i = 1; i <= 201; ++i)
            owner.reads.push_back({session(true, false, 3), tx(true)});
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(gElapsedMs == 1000 && txOut.ticketCompleted &&
               !sessionOut.cleanupAllowed);
    }

    // END without START must never submit; the active queue is retained.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(false, true, 3), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(!probe.actionTxAttempted && gSubmitCalls == 0);
        assert(frame == &frameStorage);
    }

    // A missing TX completion is not treated as queue drain even after END;
    // it remains quarantined through the bounded post-START window.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, true, 3), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(probe.actionTxAttempted && gSubmitCalls == 1);
        assert(!txOut.ticketCompleted && gElapsedMs == 1000);
    }

    // An epoch/gate mismatch is a hard failure; the frame is not sent.
    {
        resetMocks();
        ItlIwx owner; owner.epochValid = false;
        owner.reads = {{session(true, false, 3), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == EBUSY);
        assert(!probe.actionTxAttempted && gSubmitCalls == 0);
    }

    // The no-TX path remains discovery/listen mode (conf 2).
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(false, false, 2), tx(false)},
                       {session(true, false, 2), tx(false)},
                       {session(true, true, 2), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, false, 2,
                                 &sessionOut, &txOut) == 0);
        assert(!probe.actionTxAttempted && gSubmitCalls == 0);
        assert(owner.submittedConfigurations.size() == 1 &&
               owner.submittedConfigurations[0] == 2);
        assert(owner.submittedDurations.size() == 1 &&
               owner.submittedDurations[0] == 100);
        assert(sessionOut.configuration == 2 && sessionOut.cleanupAllowed);
    }

    // A mismatched notification configuration fails closed before TX.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 2), tx(false)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        int frameStorage = 0; mbuf_t frame = &frameStorage;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == EBUSY);
        assert(owner.submittedConfigurations.size() == 1 &&
               owner.submittedConfigurations[0] == 3);
        assert(!probe.actionTxAttempted && gSubmitCalls == 0);
        assert(frame == &frameStorage);
    }

    // Same-session two-frame result capture: PSF completion is frozen before
    // the MIF submit can replace the low-level completion ticket.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true, true, 1)},
                       {session(true, true, 3), tx(false, false, 2)},
                       {session(true, true, 3), tx(true, true, 1)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 2 && gMifPrepareCalls == 1);
        assert(probe.psfResultCaptured && probe.psfTxSucceeded &&
               probe.psfTicketStatus == 1);
        assert(probe.mifResultCaptured && probe.mifTxSucceeded &&
               probe.mifTicketStatus == 1);
        assert(probe.actionFramesSubmitted == 2 &&
               probe.actionFramesCompleted == 2 &&
               probe.actionFramesSucceeded == 2);
        assert(probe.pendingFrameKind == kP2PFrameAwdlMif);
        assert(frame == nullptr && sessionOut.cleanupAllowed);
    }

    // A MIF candidate preflight failure is terminal for this one burst. It
    // cannot fall back to the unrelated legacy vendor-action frame.
    {
        resetMocks(); gMifPrepareFails = true;
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, true, 3), tx(true)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 1 && gMifPrepareCalls == 1);
        assert(probe.psfTxSucceeded && !probe.mifTxAttempted &&
               probe.mifStatus == kMifProbePreflightRejected);
        assert(probe.actionFramesSubmitted == 1 &&
               probe.actionFramesCompleted == 1);
    }

    // A failed first PSF completion never prepares or submits a MIF.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true, false, 2)},
                       {session(true, true, 3), tx(true, false, 2)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 1 && gMifPrepareCalls == 0);
        assert(probe.psfResultCaptured && !probe.psfTxSucceeded &&
               probe.mifStatus == kMifProbeFirstPsfFailed);
        assert(probe.actionFramesSubmitted == 1 &&
               probe.actionFramesCompleted == 1 &&
               probe.actionFramesSucceeded == 0);
    }

    // END in the same sample as the successful PSF means the MIF is skipped.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, true, 3), tx(true)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 1 && gMifPrepareCalls == 0);
        assert(probe.psfTxSucceeded &&
               probe.mifStatus == kMifProbeEndedBeforeSubmit);
        assert(!probe.mifTxAttempted && !probe.mifResultCaptured);
    }

    // The MIF candidate is ready, but its second gate admission is declined.
    // END on the next sample must mark it skipped before the early safe-cleanup
    // break. Keep the successful first result and prove no MIF TX was accepted.
    {
        resetMocks(); gMifGateNotAdmitted = true;
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, true, 3), tx(true)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gMifPrepareCalls == 1 && gSubmitCalls == 2 &&
               gAcceptedSubmitCalls == 1);
        assert(probe.psfResultCaptured && probe.psfTxSucceeded &&
               probe.psfTicketStatus == 1);
        assert(probe.mifCandidatePrepared &&
               probe.mifStatus == kMifProbeEndedBeforeSubmit &&
               (probe.mifBlockers & NativeAwdlProbe::kMifTxRocEnded));
        assert(!probe.mifTxAttempted && !probe.mifFrameSubmitted &&
               !probe.mifResultCaptured);
        assert(probe.actionFramesSubmitted == 1 &&
               probe.actionFramesCompleted == 1 &&
               probe.actionFramesSucceeded == 1);
        assert(frame != nullptr && sessionOut.cleanupAllowed &&
               txOut.ticketCompleted && txOut.actionState ==
                   static_cast<uint32_t>(TahoeP2PActionTxState::kIdle));
    }

    // If START never arrives and no TX queue is allocated, END must finish
    // both pending profile statuses without inventing a candidate or TX.
    {
        resetMocks();
        ItlIwx owner;
        auto idleWithoutTx = tx(false);
        idleWithoutTx.queueDoorbelled = false;
        idleWithoutTx.actionState = static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle);
        owner.reads = {{session(false, false, 3), idleWithoutTx},
                       {session(false, true, 3), idleWithoutTx}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, false, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gPsfPrepareCalls == 0 && gMifPrepareCalls == 0 &&
               gSubmitCalls == 0 && gAcceptedSubmitCalls == 0);
        assert(probe.psfStatus == kPsfProbeEndedBeforeSubmit &&
               probe.mifStatus == kMifProbePsfNotSubmitted);
        assert(probe.actionFramesSubmitted == 0 &&
               probe.actionFramesCompleted == 0 &&
               probe.actionFramesSucceeded == 0);
        assert(!probe.psfFrameSubmitted && !probe.mifFrameSubmitted &&
               !txOut.ticketArmed && !txOut.ticketCompleted &&
               txOut.outstandingTx == 0 && sessionOut.cleanupAllowed);
    }

    // A ready PSF candidate rejected before its first submit is terminalized
    // on END. The already-prepared PSF buffer remains caller-owned for cleanup.
    {
        resetMocks(); gPsfGateNotAdmitted = true;
        ItlIwx owner;
        auto idleWithoutTx = tx(false);
        idleWithoutTx.queueDoorbelled = false;
        idleWithoutTx.actionState = static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle);
        owner.reads = {{session(true, false, 3), idleWithoutTx},
                       {session(true, true, 3), idleWithoutTx}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gPsfPrepareCalls == 1 && gMifPrepareCalls == 0 &&
               gSubmitCalls == 1 && gAcceptedSubmitCalls == 0);
        assert(probe.psfCandidatePrepared &&
               probe.psfStatus == kPsfProbeEndedBeforeSubmit &&
               probe.mifStatus == kMifProbePsfNotSubmitted);
        assert(!probe.actionTxAttempted && !probe.psfFrameSubmitted &&
               !probe.mifTxAttempted && !probe.mifFrameSubmitted);
        assert(probe.actionFramesSubmitted == 0 &&
               probe.actionFramesCompleted == 0 &&
               probe.actionFramesSucceeded == 0);
        assert(frame != nullptr && !txOut.ticketArmed &&
               !txOut.ticketCompleted && txOut.outstandingTx == 0 &&
               txOut.actionState ==
                   static_cast<uint32_t>(TahoeP2PActionTxState::kIdle) &&
               sessionOut.cleanupAllowed);
    }

    // Unknown END keeps the same truthful pre-submit result while retaining
    // the unknown-outcome blocker and returning a quarantine timeout.
    {
        resetMocks();
        ItlIwx owner;
        auto unknownEnd = session(false, true, 3);
        unknownEnd.cleanupAllowed = false;
        unknownEnd.outcomeUnknown = true;
        auto idleWithoutTx = tx(false);
        idleWithoutTx.queueDoorbelled = false;
        idleWithoutTx.actionState = static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle);
        owner.reads = {{session(false, false, 3), idleWithoutTx},
                       {unknownEnd, idleWithoutTx}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, false, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(gPsfPrepareCalls == 0 && gMifPrepareCalls == 0 &&
               gSubmitCalls == 0 && gAcceptedSubmitCalls == 0);
        assert(probe.psfStatus == kPsfProbeEndedBeforeSubmit &&
               probe.mifStatus == kMifProbePsfNotSubmitted);
        assert((probe.mifBlockers & NativeAwdlProbe::kMifTxFirstPsfNotCompleted) &&
               (probe.mifBlockers & NativeAwdlProbe::kMifTxRocUnknown) &&
               !(probe.mifBlockers & NativeAwdlProbe::kMifTxRocEnded));
        assert(probe.actionFramesSubmitted == 0 &&
               probe.actionFramesCompleted == 0 &&
               probe.actionFramesSucceeded == 0);
    }

    // END during the in-flight MIF does not end the worker early. A valid
    // TX_RSP is awaited and both per-frame results survive ticket rearming.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, true, 3), tx(false, false, 2)},
                       {session(true, true, 3), tx(true, true, 1)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 2 && probe.psfTicketStatus == 1 &&
               probe.mifTicketStatus == 1);
        assert(probe.psfTxCompleted && probe.mifTxCompleted &&
               probe.actionFramesCompleted == 2);
    }

    // An unknown MIF completion after END remains quarantined; it is never
    // reported as a two-frame completion or success.
    {
        resetMocks();
        ItlIwx owner;
        auto unknown = session(true, true, 3);
        unknown.outcomeUnknown = true;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {unknown, tx(false, false, 2)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(gSubmitCalls == 2 && probe.psfResultCaptured &&
               probe.psfTxSucceeded && !probe.mifResultCaptured &&
               !probe.mifTxSucceeded);
    }

    // Test057: three successful MIFs fit in the original 900 ms ROC. Each
    // repeat waits at least 64 TU from the prior MIF completion, uses a fresh
    // frame object and next sequence, and preserves cumulative ticket counts.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads.push_back({session(true, false, 3), tx(false)});
        owner.reads.push_back({session(true, false, 3), tx(true)}); // PSF
        owner.reads.push_back({session(true, false, 3), txMif(2, true)});
        for (unsigned i = 0; i < 13; ++i)
            owner.reads.push_back({session(true, false, 3), txMif(2, true)});
        owner.reads.push_back({session(true, false, 3), txMif(2, true)});
        owner.reads.push_back({session(true, false, 3), txMif(3, false)});
        owner.reads.push_back({session(true, false, 3), txMif(3, true)});
        for (unsigned i = 0; i < 13; ++i)
            owner.reads.push_back({session(true, false, 3), txMif(3, true)});
        owner.reads.push_back({session(true, false, 3), txMif(3, true)});
        owner.reads.push_back({session(true, false, 3), txMif(4, false)});
        owner.reads.push_back({session(true, false, 3), txMif(4, true)});
        owner.reads.push_back({session(true, true, 3), txMif(4, true)});
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        probe.psfStatus = kPsfProbeWaitingForStart;
        probe.mifStatus = kMifProbeWaitingForPsfCompletion;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 4 && gAcceptedSubmitCalls == 4);
        assert(gMifPrepareCalls == 1 && gMifRepeatPrepareCalls == 2);
        assert(gMifRepeatSequences.size() == 2 &&
               gMifRepeatSequences[0] == 3 &&
               gMifRepeatSequences[1] == 4);
        assert(gMifRepeatSampleTimes.size() == 2 &&
               gMifRepeatSampleTimes[0] >= 10'000 +
                   NativeAwdlProbe::kMifBurstRepeatIntervalUs &&
               gMifRepeatSampleTimes[1] - gMifRepeatSampleTimes[0] >=
                   NativeAwdlProbe::kMifBurstRepeatIntervalUs);
        assert(gMifRepeatFramePointers.size() == 2 &&
               gMifRepeatFramePointers[0] != gMifRepeatFramePointers[1]);
        assert(probe.mifBurstPreparedFrames == 3 &&
               probe.mifBurstAttemptedFrames == 3 &&
               probe.mifBurstSubmittedFrames == 3 &&
               probe.mifBurstCompletedFrames == 3 &&
               probe.mifBurstSucceededFrames == 3);
        assert(probe.actionFramesSubmitted == 4 &&
               probe.actionFramesCompleted == 4 &&
               probe.actionFramesSucceeded == 4);
        assert(probe.mifResultCaptured && probe.mifTxSucceeded &&
               frame == nullptr && sessionOut.cleanupAllowed);
    }

    // A repeat is never prepared after an END or unknown ROC outcome.
    {
        resetMocks();
        ItlIwx owner;
        auto unknown = session(true, true, 3);
        unknown.cleanupAllowed = false;
        unknown.outcomeUnknown = true;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {unknown, txMif(2, true)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == ETIMEDOUT);
        assert(gSubmitCalls == 2 && gMifRepeatPrepareCalls == 0 &&
               probe.mifBurstStopReason == static_cast<uint32_t>(
                   NativeAwdlProbe::MifBurstStopReason::RocUnknown));
    }

    // A failed MIF ticket terminates the burst before any repeat can be built.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, true, 3), txMif(2, true, false, 2)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gSubmitCalls == 2 && gMifRepeatPrepareCalls == 0 &&
               probe.mifBurstCompletedFrames == 1 &&
               probe.mifBurstSucceededFrames == 0 &&
               probe.mifBurstStopReason == static_cast<uint32_t>(
                   NativeAwdlProbe::MifBurstStopReason::PreviousTicketFailed));
    }

    // Any native data attempt suppresses later MIF controls in the same ROC.
    {
        resetMocks();
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, false, 3), txMif(2, true, true, 1, 1)},
                       {session(true, true, 3), txMif(2, true, true, 1, 1)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(probe.nativeDataAttempts == 1 && gSubmitCalls == 2 &&
               gMifRepeatPrepareCalls == 0 &&
               probe.mifBurstStopReason == static_cast<uint32_t>(
                   NativeAwdlProbe::MifBurstStopReason::DataStarted));
    }

    // Losing the epoch between MIF completion and the interval check fails
    // closed; it cannot schedule another candidate.
    {
        resetMocks();
        ItlIwx owner;
        owner.invalidateEpochAfterRead = 3;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, false, 3), txMif(2, true)}};
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == EBUSY);
        assert(gSubmitCalls == 2 && gMifRepeatPrepareCalls == 0);
    }

    // Candidate rebuild failure is terminal and does not retry or extend ROC.
    {
        resetMocks(); gMifRepeatPrepareFails = true;
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, false, 3), txMif(2, true)}};
        for (unsigned i = 0; i < 14; ++i)
            owner.reads.push_back({session(true, false, 3), txMif(2, true)});
        owner.reads.push_back({session(true, true, 3), txMif(2, true)});
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gMifRepeatPrepareCalls == 1 && gSubmitCalls == 2 &&
               probe.mifBurstPreparedFrames == 1 &&
               probe.mifBurstStopReason == static_cast<uint32_t>(
                   NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed));
    }

    // A repeat rejected by the existing main-gate admission/doorbell path is
    // terminal; it is not retried on later worker iterations.
    {
        resetMocks(); gFailRepeatMifSubmit = true;
        ItlIwx owner;
        owner.reads = {{session(true, false, 3), tx(false)},
                       {session(true, false, 3), tx(true)},
                       {session(true, false, 3), txMif(2, true)}};
        for (unsigned i = 0; i < 14; ++i)
            owner.reads.push_back({session(true, false, 3), txMif(2, true)});
        owner.reads.push_back({session(true, true, 3), txMif(2, true)});
        P2PProbeRun probe{}; probe.owner = &owner;
        probe.awdlPsfProbeEnabled = true;
        probe.awdlMifFollowupEnabled = true;
        mbuf_t frame = nullptr;
        IntelROCEvent::SessionSnapshot sessionOut{};
        P2PTxDiagnosticSnapshot txOut{};
        assert(runTxProbeSession(&probe, &frame, true, 3,
                                 &sessionOut, &txOut) == 0);
        assert(gMifRepeatPrepareCalls == 1 && gSubmitCalls == 3 &&
               gAcceptedSubmitCalls == 2 && frame == nullptr);
        assert(probe.mifBurstPreparedFrames == 2 &&
               probe.mifBurstAttemptedFrames == 1 &&
               probe.mifBurstSubmittedFrames == 1 &&
               probe.mifBurstCompletedFrames == 1 &&
               probe.mifBurstStopReason == static_cast<uint32_t>(
                   NativeAwdlProbe::MifBurstStopReason::DoorbellRejected));
    }
}
"""

stop_shim = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <map>
#include <string>
#define IOLog(...) do {} while (0)

using IOReturn = int;
using OSObject = void;
static constexpr IOReturn kIOReturnSuccess = 0;
enum { IWX_P2P_RESOURCE_ABSENT = 0 };
enum class TahoeP2PResourceState : uint8_t {
    kAbsent, kPending, kActive, kRemoving, kReleasing, kUnknown
};
struct TahoeP2PStationLease {
    uint8_t stationId = 0;
    uint32_t generation = 0;
    TahoeP2PResourceState state = TahoeP2PResourceState::kAbsent;
};
struct IOSimpleLock {};
using IOInterruptState = unsigned;
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *) { return 0; }
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *, IOInterruptState) {}
struct TahoeP2PTxQueueLease {
    TahoeP2PResourceState state = TahoeP2PResourceState::kAbsent;
    uint16_t queueId = 0;
    uint32_t generation = 0;
    IOSimpleLock *stateLock = nullptr;
    bool submissionBusy = false;
    void *pendingRing = nullptr;
};
struct iwx_p2p_context {
    int mac_state = 0, binding_state = 0;
    bool phy_leased = false;
    uint32_t fw_generation = 0;
};
struct taskq {};
struct task {};
struct iwx_softc {
    iwx_p2p_context sc_p2p{};
    taskq *sc_nswq = nullptr;
    int sc_generation = 0;
};
struct IOEthernetController {
    std::map<std::string, uint32_t> properties;
    void setProperty(const char *key, uint32_t value, unsigned bits) {
        assert(bits == 32); properties[key] = value;
    }
};
struct P2PProbeRun { struct ItlIwx *owner = nullptr; bool canceled = false; };
using GateAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);
struct IOWorkLoop { bool inGate() const { return false; } };
class IOCommandGate {
public:
    IOReturn runAction(GateAction action, void *context) {
        return action ? action(nullptr, context, nullptr, nullptr, nullptr) : EIO;
    }
};
static taskq *systq = nullptr;
static bool task_del(taskq *, task *) { return true; }
void taskq_resume(taskq *) {}

struct ItlIwx {
    iwx_softc com{};
    TahoeP2PStationLease nativeP2pStation_{};
    TahoeP2PTxQueueLease nativeP2pTxQueue_{};
    IOSimpleLock txLock_{};
    IOSimpleLock *nativeP2pTxLock_ = &txLock_;
    uint64_t nativeP2pStopRejectFingerprint_ = 0;
    IOEthernetController controller_{};
    uint32_t nativeP2pProbeQueued_ = 0;
    uint32_t nativeP2pNswqPaused_ = 0;
    uint32_t nativeP2pCancelRequested_ = 0;
    uint32_t tahoe_p2p_probe_task_initialized_ = 0;
    void *nativeP2pProbeOwner_ = nullptr;
    bool busy = false;
    task tahoe_p2p_probe_task_{};
    IOCommandGate gate{};
    IOWorkLoop loop{};

    bool nativeP2pBusy() { return busy; }
    bool nativeP2pResourcesRetained();
    IOEthernetController *getController() { return &controller_; }
    IOCommandGate *getMainCommandGate() { return &gate; }
    IOWorkLoop *getMainWorkLoop() { return &loop; }
    int tahoeP2pStopBeforeReset(iwx_softc *);
    static IOReturn tahoeP2pCancelAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeP2pFinishAction(OSObject *, void *, void *, void *, void *);
};

IOReturn ItlIwx::tahoeP2pCancelAction(OSObject *, void *, void *, void *, void *) {
    return kIOReturnSuccess;
}
IOReturn ItlIwx::tahoeP2pFinishAction(OSObject *, void *, void *, void *, void *) {
    return kIOReturnSuccess;
}
"""

stop_functions = "\n\n".join((
    extract(ITL, "bool ItlIwx::nativeP2pResourcesRetained()"),
    extract(PROBE, "int ItlIwx::tahoeP2pStopBeforeReset("),
))

stop_body = r"""
static void assertStopBlocked(ItlIwx &owner) {
    assert(owner.nativeP2pResourcesRetained());
    assert(owner.controller_.properties["NativeP2PLastStopRejectStage"] == 1);
    assert(owner.controller_.properties["NativeP2PLastStopRejectError"] == EBUSY);
    assert(owner.tahoeP2pStopBeforeReset(&owner.com) == EBUSY);
}
int main() {
    { ItlIwx owner; owner.busy = true; assertStopBlocked(owner); }
    { ItlIwx owner; owner.nativeP2pTxQueue_.state = TahoeP2PResourceState::kUnknown; assertStopBlocked(owner); }
    { ItlIwx owner; owner.nativeP2pStation_.state = TahoeP2PResourceState::kUnknown; assertStopBlocked(owner); }
    { ItlIwx owner; owner.com.sc_p2p.mac_state = 1; assertStopBlocked(owner); }
    { ItlIwx owner; owner.com.sc_p2p.binding_state = 1; assertStopBlocked(owner); }
    { ItlIwx owner; owner.com.sc_p2p.phy_leased = true; assertStopBlocked(owner); }
    { ItlIwx owner; assert(!owner.nativeP2pResourcesRetained()); assert(owner.tahoeP2pStopBeforeReset(&owner.com) == 0); }
    { ItlIwx owner; assert(owner.tahoeP2pStopBeforeReset(nullptr) == EINVAL); }
}
"""


def compile_and_run(name, source, extra_sources=(), include_dirs=()):
    with tempfile.TemporaryDirectory(prefix=f"itlwm-{name}-") as directory:
        cpp = Path(directory) / f"{name}.cpp"
        exe = Path(directory) / name
        cpp.write_text(source)
        command = [
            "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
        ]
        for include_dir in include_dirs:
            command.extend(["-I", str(include_dir)])
        command.extend([str(cpp), *(str(path) for path in extra_sources), "-o", str(exe)])
        subprocess.run([
            *command,
        ], check=True)
        subprocess.run([str(exe)], check=True)


compile_and_run("p2p_probe_session_worker",
                MIF_BURST + "\n" + MIF_PACING + "\n" + session_shim + "\n" +
                session_helpers + "\n" + session_body)
compile_and_run("awdl_mif_burst_planner",
                MIF_BURST + "\n" +
                (ROOT / "native/tests/awdl_mif_burst_test.cpp").read_text()
                .replace('#include "awdl_mif_burst.hpp"', ""))
candidate_fixture = (ROOT / "native/tests/awdl_mif_burst_candidate_test.cpp").read_text()
production_candidate_helpers = "\n\n".join((
    extract(PROBE, "static bool mifBurstTicketMatchesPreviousCompletion("),
    extract(PROBE, "static NativeAwdlProbe::MifBurstRepeatState mifBurstRepeatState("),
    extract(PROBE, "static NativeAwdlProbe::MifBurstRepeatPlan mifBurstDoorbellPlan("),
    extract(PROBE, "static bool buildFreshMifBurstCandidate("),
))
assert "// PRODUCTION_MIF_BURST_HELPERS" in candidate_fixture
candidate_fixture = candidate_fixture.replace(
    "// PRODUCTION_MIF_BURST_HELPERS", production_candidate_helpers)
compile_and_run(
    "awdl_mif_burst_production_candidate", candidate_fixture,
    extra_sources=[
        ROOT / "native/awdl_host_phase.cpp",
        ROOT / "native/awdl_action_frame.cpp",
        ROOT / "native/awdl_action_encode.cpp",
        ROOT / "native/awdl_bounded_psf_plan.cpp",
        ROOT / "native/awdl_mif_encode.cpp",
        ROOT / "native/awdl_mif_tx_gate.cpp",
    ],
    include_dirs=[ROOT / "native"],
)
compile_and_run("p2p_probe_stop_guard",
                stop_shim + "\n" + stop_functions + "\n" + stop_body)
print("PASS: production ROC worker, bounded MIF burst planner, and retained-resource stop guard")
