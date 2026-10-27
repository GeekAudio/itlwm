// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwx.hpp"

#ifdef AIRPORT_TAHOE

#include "../../native/p2p_tx_firmware.hpp"
#include "../../native/awdl_action_frame.hpp"
#include "../../native/awdl_mif_tx_gate.hpp"
#include "../../native/awdl_mif_burst.hpp"
#include "../../native/awdl_mif_pacing.hpp"
#include "../../native/awdl_psf_tx_gate.hpp"
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
#include "../../native/awdl_native_lifecycle_25G332.hpp"
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../../native/awdl_native_bsd_data_25G332.hpp"
#include "../../native/awdl_data_roc_gate.hpp"
#endif
#endif
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
#include "../../native/awdl_native_init_probe_25G332.hpp"
#endif
#include <kern/clock.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <libkern/c++/OSBoolean.h>

namespace {

static_assert(static_cast<uint8_t>(IntelP2PFirmware::DeviceFamily::k22000) ==
              IWX_DEVICE_FAMILY_22000, "22000 transport family changed");
static_assert(static_cast<uint8_t>(IntelP2PFirmware::DeviceFamily::kAX210) ==
              IWX_DEVICE_FAMILY_AX210, "AX210 transport family changed");

struct P2PProbeRun {
    ItlIwx *owner;
    thread_t workerThread;
    bool callerOutsideMainWorkLoop;
    bool admitted;
    bool canceled;
    bool leaseValue;
    bool leasePublished;
    bool addAcknowledged;
    bool txProbeEnabled;
    uint32_t nativeDataAttempts;
    bool awdlPsfProbeEnabled;
    bool awdlMifFollowupEnabled;
    bool psfCandidatePrepared;
    bool mifCandidatePrepared;
    bool actionTxAttempted;
    bool actionTxRequired;
    bool txQueueReady;
    bool psfFrameSubmitted;
    bool psfResultCaptured;
    bool psfTxCompleted;
    bool psfTxSucceeded;
    bool psfPeerAcknowledged;
    bool mifTxAttempted;
    bool mifFrameSubmitted;
    bool mifResultCaptured;
    bool mifTxCompleted;
    bool mifTxSucceeded;
    bool mifPeerAcknowledged;
    bool burstEndedAfterMif;
    bool mifBurstStopped;
    bool mifBurstCandidateIsRepeat;
    uint64_t psfHostGateUs;
    uint64_t psfHostLeaseRemainingAtGateUs;
    int txSubmitResult;
    uint32_t psfStatus;
    uint32_t psfBlockers;
    size_t psfCandidateLength;
    uint32_t psfTicketStatus;
    uint32_t mifStatus;
    uint32_t mifBlockers;
    size_t mifCandidateLength;
    uint32_t mifTicketStatus;
    uint32_t actionFramesSubmitted;
    uint32_t actionFramesCompleted;
    uint32_t actionFramesSucceeded;
    uint32_t mifBurstPreparedFrames;
    uint32_t mifBurstAttemptedFrames;
    uint32_t mifBurstSubmittedFrames;
    uint32_t mifBurstCompletedFrames;
    uint32_t mifBurstSucceededFrames;
    uint32_t mifBurstStopReason;
    uint32_t mifBurstEpoch;
    uint32_t mifBurstLastTicketStatus;
    uint32_t mifBurstLastTicketSequenceControl;
    uint32_t mifBurstLastTicketByteCount;
    uint32_t mifBurstLastTicketFrameControl;
    uint16_t mifBurstLastNextSequenceNumber;
    uint64_t mifBurstLastCompletionUs;
    uint64_t mifPacingWindowEndUs;
    uint64_t mifPacingCandidateAnchorRxUs;
    uint64_t mifPacingLastConsumedAnchorRxUs;
    uint64_t mifPacingEarliestUs;
    uint64_t mifPacingLatestUs;
    uint32_t mifPacingReason;
    uint32_t mifPacingAnchorCount;
    bool mifPacingCandidateAnchorComplete;
    bool mifPacingCandidateAnchorSyncConsistent;
    bool mifPacingCandidateAnchorChannel6Confirmed;
    uint64_t mifPacingCandidateContextGeneration;
    uint64_t mifPacingCandidatePowerGeneration;
    uint64_t mifPacingCandidateStationGeneration;
    uint16_t mifPacingCandidateRxChannelIndex;
    uint32_t mifPacingCandidateOrdinal;
    uint32_t pendingFrameKind;
    NativeAwdlProbe::PsfCandidate psfCandidate;
    NativeAwdlProbe::PsfRuntimeWitness psfWitness;
    NativeAwdlProbe::MifCandidate mifCandidate;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint8_t address[6];
    NativeP2PProbe::BlockedReason blocked;
};

enum P2PTxProbeStage : uint32_t {
    kTxProbeRocPrepare = 20,
    kTxProbeResourcesReady = 21,
    kTxProbeSessionSubmitted = 22,
    kTxProbeWaitingForStart = 23,
    kTxProbeActionSubmitted = 24,
    kTxProbeWaitingForCompletionAndEnd = 25,
    kTxProbeCleanup = 26,
    kTxProbeComplete = 27,
    kTxProbeCleanedWithoutTx = 28,
    kTxProbeQuarantined = 29
};

static constexpr uint64_t kP2PProbeStartBudgetNs = 800000000ULL;
static constexpr uint64_t kP2PProbeNsPerMs = 1000000ULL;
static constexpr uint32_t kP2PProbeEndMarginMs = 100;
static constexpr uint32_t kP2PProbeSleepSliceMs = 5;

static uint64_t p2pProbeMonotonicNanoseconds()
{
    uint64_t uptime = 0, nanoseconds = 0;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &nanoseconds);
    return nanoseconds;
}

static uint32_t p2pRocDurationTu(uint32_t milliseconds)
{
    // Keep this identical to ItlIwxP2PRoc.cpp's programmed duration_tu.
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(milliseconds) * 1000u) / 1024u);
}

struct P2PProbeObservationWindow {
    uint64_t deadlineNs;
    uint32_t configuration;
    uint32_t durationMs;
    bool successfulStartObserved;

    P2PProbeObservationWindow(uint64_t nowNs, uint32_t sessionConfiguration,
                              uint32_t sessionDurationMs)
        : deadlineNs(nowNs + kP2PProbeStartBudgetNs),
          configuration(sessionConfiguration), durationMs(sessionDurationMs),
          successfulStartObserved(false)
    {
    }

    bool observeSuccessfulStart(uint64_t nowNs)
    {
        if (successfulStartObserved)
            return true;
        if (nowNs > deadlineNs)
            return false;

        successfulStartObserved = true;
        if (configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION) {
            deadlineNs = nowNs +
                (static_cast<uint64_t>(durationMs) + kP2PProbeEndMarginMs) *
                kP2PProbeNsPerMs;
        }
        return true;
    }

    bool expired(uint64_t nowNs) const
    {
        return nowNs > deadlineNs;
    }

    uint32_t nextSleepMilliseconds(uint64_t nowNs) const
    {
        if (nowNs >= deadlineNs)
            return 0;
        const uint64_t remainingNs = deadlineNs - nowNs;
        const uint64_t sliceNs =
            static_cast<uint64_t>(kP2PProbeSleepSliceMs) * kP2PProbeNsPerMs;
        if (remainingNs >= sliceNs)
            return kP2PProbeSleepSliceMs;
        return static_cast<uint32_t>(
            (remainingNs + kP2PProbeNsPerMs - 1) / kP2PProbeNsPerMs);
    }
};

static IntelP2PFirmware::Profile txFirmwareProfile(ItlIwx *owner,
                                                   struct iwx_softc *sc)
{
    uint32_t testRate = 0;
    return {
        static_cast<IntelP2PFirmware::DeviceFamily>(sc->sc_device_family),
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_TX_CMD),
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_TX_CMD),
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_SCD_QUEUE_CFG),
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_SCD_QUEUE_CFG),
        owner->iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP, 0x17),
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_TXPATH_FLUSH),
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_TXPATH_FLUSH),
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_REMOVE_STA),
        isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_DQA_SUPPORT) != 0,
        IntelP2PActionTx::encodeLegacyOfdmRateV2(
            IWX_RATE_6M_INDEX, IWX_FIRST_OFDM_RATE,
            owner->iwx_fw_valid_tx_ant(sc), IWX_RATE_MCS_ANT_NUM,
            IWX_RATE_MCS_ANT_POS, IWX_RATE_MCS_LEGACY_OFDM_MSK,
            &testRate)
    };
}

static void publishTxFirmwareProfile(ItlIwx *owner,
                                      const IntelP2PFirmware::Profile &profile,
                                      uint32_t rejection)
{
    IOEthernetController *controller = owner->tahoeP2pController();
    if (!controller)
        return;
    controller->setProperty("NativeP2PTxPreflightRejectMask", rejection, 32);
    controller->setProperty("NativeP2PTxDeviceFamily",
        static_cast<uint32_t>(profile.deviceFamily), 32);
    controller->setProperty("NativeP2PTxCommandLayout",
        static_cast<uint32_t>(IntelP2PFirmware::txLayout(
            profile.deviceFamily, profile.txCommand, profile.txNotification)), 32);
    if (owner->com.sc_fwname)
        controller->setProperty("NativeP2PTxFirmwareFile", owner->com.sc_fwname);
    controller->setProperty("NativeP2PTxHardwareRevision", owner->com.sc_hw_rev, 32);
    controller->setProperty("NativeP2PTxRadioId", owner->com.sc_hw_rf_id, 32);
    controller->setProperty("NativeP2PTxFwCommandVersion", profile.txCommand, 32);
    controller->setProperty("NativeP2PTxFwNotificationVersion", profile.txNotification, 32);
    controller->setProperty("NativeP2PTxQueueCommandVersion", profile.queueCommand, 32);
    controller->setProperty("NativeP2PTxQueueResponseVersion", profile.queueResponse, 32);
    controller->setProperty("NativeP2PTxModernQueueCommandVersion", profile.modernQueueCommand, 32);
    controller->setProperty("NativeP2PTxFlushCommandVersion", profile.flushCommand, 32);
    controller->setProperty("NativeP2PTxFlushResponseVersion", profile.flushResponse, 32);
    controller->setProperty("NativeP2PTxRemoveStationCommandVersion", profile.removeStationCommand, 32);
    controller->setProperty("NativeP2PTxLegacyDqaCapability", uint32_t(profile.dqa), 32);
}

struct P2PTxDiagnosticSnapshot {
    uint32_t stationId;
    uint32_t stationState;
    uint32_t queueId;
    uint32_t queueState;
    uint32_t outstandingTx;
    uint32_t actionState;
    uint32_t ticketStatus;
    uint32_t ticketByteCount;
    uint32_t ticketSequenceControl;
    uint32_t ticketFrameControl;
    uint32_t ringQueued;
    uint32_t ringCur;
    uint32_t ringTail;
    uint32_t ringCount;
    bool ringMayExist;
    bool queueDoorbelled;
    bool queueLeaseActive;
    bool txRingEmpty;
    bool ringIndicesConsistent;
    bool ticketArmed;
    bool ticketCompleted;
    bool frameAttemptSucceeded;
    bool peerAcknowledged;
    uint16_t nextSequenceNumber;
};

struct P2PProbeReset {
    ItlIwx *owner;
    struct iwx_softc *softc;
    uint32_t drainedGeneration;
    int result;
};

enum RocEventOperation { kRocArm, kRocCommandReturned, kRocRead, kRocExpire };
struct RocEventRun {
    P2PProbeRun *probe;
    RocEventOperation operation;
    uint32_t firmwareGeneration;
    uint32_t macIdAndColor;
    uint32_t configuration;
    int commandResult;
    bool armed;
    IntelROCEvent::SessionSnapshot snapshot;
    P2PTxDiagnosticSnapshot txSnapshot;
    bool txSnapshotValid;
};

enum P2PFrameKind : uint32_t {
    kP2PFrameNone = 0,
    kP2PFrameLegacyVendorAction = 1,
    kP2PFrameAwdlPsf = 2,
    kP2PFrameAwdlMif = 3
};

struct P2PTxSubmitRun {
    P2PProbeRun *probe;
    mbuf_t frame;
    bool frameConsumed;
    bool frameStale;
    bool psfFrame;
    bool mifFrame;
    int result;
};

enum PsfProbeStatus : uint32_t {
    kPsfProbeNotRequested = 0,
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
    kMifProbeFrameSubmissionFailed = 12,
    kMifProbeWaitingForPeerPsf = 13
};

static void storeRocSnapshot(ItlIwx *owner,
                             const IntelROCEvent::SessionSnapshot &snapshot)
{
    __atomic_store_n(&owner->nativeP2pRocConfiguration_,
                     snapshot.configuration, __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocStartSeen_, uint32_t(snapshot.startSeen), __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocEndSeen_, uint32_t(snapshot.endSeen), __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocStartStatus_, snapshot.startStatus, __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocEndStatus_, snapshot.endStatus, __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocCommandResult_, uint32_t(snapshot.commandResult), __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocObserved_, uint32_t(snapshot.observedScheduledPair), __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocCleanupAllowed_, uint32_t(snapshot.cleanupAllowed), __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocUnknown_, uint32_t(snapshot.outcomeUnknown), __ATOMIC_RELAXED);
}

static uint32_t nextGeneration(uint32_t generation)
{
    ++generation;
    return generation == 0 ? 1 : generation;
}

static bool manualProbeGateOpen(ItlIwx *owner, IOEthernetController *controller)
{
    return owner && controller &&
        (controller->getProperty("NativeP2PManualTrigger") != kOSBooleanTrue ||
         __atomic_load_n(&owner->nativeP2pManualArmRequested_,
                         __ATOMIC_ACQUIRE) != 0);
}

static bool psfObservationProfileEnabled(IOEthernetController *controller)
{
    return controller &&
        controller->getProperty("NativeP2PManualTrigger") == kOSBooleanTrue &&
        controller->getProperty("NativeP2PProbe") == kOSBooleanTrue &&
        controller->getProperty("NativeP2PRocProbe") == kOSBooleanTrue &&
        controller->getProperty("NativeP2PTxProbe") == kOSBooleanTrue &&
        controller->getProperty("NativeP2PAwdlPsfObservationOnly") ==
            kOSBooleanTrue;
}

static bool mifFollowupProfileEnabled(IOEthernetController *controller)
{
    return psfObservationProfileEnabled(controller) &&
        controller->getProperty("NativeP2PAwdlMifFollowup") ==
            kOSBooleanTrue;
}

static bool probeEnabled(ItlIwx *owner, IOEthernetController *controller)
{
    const bool observationRequested = controller &&
        controller->getProperty("NativeP2PAwdlPsfObservationOnly") ==
            kOSBooleanTrue;
    const bool mifRequested = controller &&
        controller->getProperty("NativeP2PAwdlMifFollowup") ==
            kOSBooleanTrue;
    if (mifRequested && !mifFollowupProfileEnabled(controller))
        return false;
    if (observationRequested &&
        !psfObservationProfileEnabled(controller))
        return false;
    return manualProbeGateOpen(owner, controller) &&
        controller->getProperty("NativeP2PProbe") == kOSBooleanTrue;
}

static bool txProbeEnabled(ItlIwx *owner, IOEthernetController *controller)
{
    if (!manualProbeGateOpen(owner, controller))
        return false;
    if (controller->getProperty("NativeP2PAwdlMifFollowup") ==
            kOSBooleanTrue)
        return mifFollowupProfileEnabled(controller);
    const bool observationRequested = controller->getProperty(
        "NativeP2PAwdlPsfObservationOnly") == kOSBooleanTrue;
    if (observationRequested)
        return psfObservationProfileEnabled(controller);
    return controller->getProperty("NativeP2PTxProbe") == kOSBooleanTrue;
}

static bool awdlPsfProbeEnabled(ItlIwx *owner,
                                IOEthernetController *controller)
{
    const bool mifRequested = controller &&
        controller->getProperty("NativeP2PAwdlMifFollowup") ==
            kOSBooleanTrue;
    return manualProbeGateOpen(owner, controller) &&
        psfObservationProfileEnabled(controller) &&
        (!mifRequested || mifFollowupProfileEnabled(controller));
}

static int initializeTxStationRegistry(ItlIwx *owner, struct iwx_softc *sc)
{
    if (!owner || !sc || !owner->nativeP2pTxLock_ ||
        sc->sc_capa_num_stations < 4 || sc->sc_capa_num_stations > 32)
        return EOPNOTSUPP;
    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        owner->nativeP2pTxLock_);
    const auto current = owner->nativeP2pStationRegistry_.snapshot();
    if (current.generation == generation &&
        current.count == static_cast<uint8_t>(sc->sc_capa_num_stations)) {
        IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                          interruptState);
        return 0;
    }
    if (current.generation != 0 || current.count != 0) {
        IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                          interruptState);
        return ESTALE;
    }

    // IDs 0/1/2 are fixed STA/AUX/MONITOR roles in this driver. Reserve all
    // three for the run so an implicit AUX role or mode transition cannot
    // collide with the broadcast station lease.
    const auto result = owner->nativeP2pStationRegistry_.initialize(
        static_cast<uint8_t>(sc->sc_capa_num_stations), generation,
        true, true, true);
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                      interruptState);
    return result == IntelP2PTx::Result::kSuccess ? 0 : EBUSY;
}

static bool captureP2PTxSnapshot(ItlIwx *owner,
                                 P2PTxDiagnosticSnapshot *output)
{
    if (!owner || !output || !owner->tahoeP2pOnMainGate() ||
        !owner->nativeP2pTxLock_)
        return false;
    IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        owner->nativeP2pTxLock_);
    const auto queue = owner->nativeP2pTxQueue_.lifecycle.snapshot();
    const auto ticket = owner->nativeP2pActionTx_.completion.snapshot();
    output->stationId = owner->nativeP2pStation_.state ==
            TahoeP2PResourceState::kAbsent ? 0xffffu :
            owner->nativeP2pStation_.stationId;
    output->stationState = static_cast<uint32_t>(
        owner->nativeP2pStation_.state);
    output->queueId = owner->nativeP2pTxQueue_.state ==
            TahoeP2PResourceState::kAbsent ? 0xffffu :
            owner->nativeP2pTxQueue_.queueId;
    output->queueState = static_cast<uint32_t>(
        owner->nativeP2pTxQueue_.state);
    output->outstandingTx = queue.outstandingTx;
    output->queueDoorbelled = owner->nativeP2pTxQueue_.everDoorbelled;
    output->ringMayExist = queue.ringMustRemainOwned ||
        owner->nativeP2pTxQueue_.pendingRing != nullptr ||
        owner->nativeP2pTxQueue_.submissionBusy ||
        queue.state != IntelP2PTx::QueueState::kAbsent;
    output->actionState = static_cast<uint32_t>(
        owner->nativeP2pActionTx_.state);
    output->ticketStatus = ticket.status;
    output->ticketByteCount = ticket.byteCount;
    output->ticketSequenceControl = ticket.sequenceControl;
    output->ticketFrameControl = ticket.frameControl;
    output->ticketArmed = ticket.armed;
    output->ticketCompleted = ticket.completed;
    output->frameAttemptSucceeded = ticket.frameAttemptSucceeded;
    output->peerAcknowledged = ticket.peerAcknowledged;
    output->nextSequenceNumber = owner->nativeP2pActionTx_.nextSequenceNumber;
    output->ringQueued = UINT32_MAX;
    output->ringCur = UINT32_MAX;
    output->ringTail = UINT32_MAX;
    output->ringCount = 0;
    output->queueLeaseActive = false;
    output->txRingEmpty = false;
    output->ringIndicesConsistent = false;
    if (queue.state == IntelP2PTx::QueueState::kActive &&
        queue.queueId < nitems(owner->com.txq) &&
        owner->nativeP2pTxQueue_.state == TahoeP2PResourceState::kActive &&
        owner->nativeP2pTxQueue_.generation == queue.generation &&
        owner->nativeP2pTxQueue_.queueId == queue.queueId &&
        !owner->nativeP2pTxQueue_.submissionBusy &&
        owner->nativeP2pTxQueue_.pendingRing == nullptr) {
        const struct iwx_tx_ring *ring = &owner->com.txq[queue.queueId];
        output->ringQueued = ring->queued < 0 ? UINT32_MAX :
            static_cast<uint32_t>(ring->queued);
        output->ringCur = ring->cur < 0 ? UINT32_MAX :
            static_cast<uint32_t>(ring->cur);
        output->ringTail = ring->tail < 0 ? UINT32_MAX :
            static_cast<uint32_t>(ring->tail);
        output->ringCount = ring->ring_count;
        const bool indicesInRange = ring->ring_count != 0 &&
            ring->cur >= 0 && ring->tail >= 0 && ring->queued >= 0 &&
            static_cast<uint32_t>(ring->cur) < ring->ring_count &&
            static_cast<uint32_t>(ring->tail) < ring->ring_count &&
            static_cast<uint32_t>(ring->queued) <= ring->ring_count;
        output->queueLeaseActive = true;
        output->ringIndicesConsistent = indicesInRange &&
            (ring->queued != 0 || ring->cur == ring->tail);
        output->txRingEmpty = indicesInRange && ring->queued == 0 &&
            ring->cur == ring->tail && queue.outstandingTx == 0;
    }
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                      interruptState);
    return true;
}

static void publishP2PTxStage(ItlIwx *owner, uint32_t stage, int result)
{
    if (!owner)
        return;
    __atomic_store_n(&owner->nativeP2pRocResult_, static_cast<uint32_t>(result),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocStage_, stage, __ATOMIC_RELEASE);
    if (stage == kTxProbeComplete || stage == kTxProbeCleanedWithoutTx ||
        stage == kTxProbeQuarantined) {
        TahoeP2PTxRxDiagnostics &diagnostics =
            owner->nativeP2pActionTx_.rxDiagnostics;
        __atomic_store_n(&diagnostics.armed, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&diagnostics.dirty, 1u, __ATOMIC_RELEASE);
    }
    IOEthernetController *controller = owner->tahoeP2pController();
    if (controller) {
        controller->setProperty("NativeP2PTxProbeStage", stage, 32);
        controller->setProperty("NativeP2PTxProbeResult",
                                static_cast<uint32_t>(result), 32);
    }
}

// Retain the last setup operation across ROC completion and cleanup. The
// final resource snapshot alone cannot distinguish ADD_STA from queue rejection.
static void publishP2PTxSetup(ItlIwx *owner, uint32_t step, int result)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (controller) {
        controller->setProperty("NativeP2PTxSetupStep", step, 32);
        controller->setProperty("NativeP2PTxSetupResult",
                                static_cast<uint32_t>(result), 32);
    }
}

static void publishP2PTxDetails(ItlIwx *owner,
                               const P2PTxDiagnosticSnapshot &snapshot)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PTxProbeStationId",
                            snapshot.stationId, 32);
    controller->setProperty("NativeP2PTxProbeStationState",
                            snapshot.stationState, 32);
    controller->setProperty("NativeP2PTxProbeQueueId", snapshot.queueId, 32);
    controller->setProperty("NativeP2PTxProbeQueueState",
                            snapshot.queueState, 32);
    controller->setProperty("NativeP2PTxProbeOutstandingTx",
                            snapshot.outstandingTx, 32);
    controller->setProperty("NativeP2PTxProbeRingMayExist",
                            snapshot.ringMayExist ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxProbeActionState",
                            snapshot.actionState, 32);
    controller->setProperty("NativeP2PTxProbeEverDoorbelled",
                            snapshot.queueDoorbelled ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxProbeTicketArmed",
                            snapshot.ticketArmed ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxProbeTicketCompleted",
                            snapshot.ticketCompleted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxProbeAttemptSucceeded",
                            snapshot.frameAttemptSucceeded ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxProbePeerAcknowledged",
                            snapshot.peerAcknowledged ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxProbeStatus",
                            snapshot.ticketStatus, 32);
}

static void publishPsfProbeDetails(ItlIwx *owner, const P2PProbeRun *probe,
                                   uint32_t frameKind)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller || !probe)
        return;
    controller->setProperty("NativeP2PTxFrameKind", frameKind, 32);
    controller->setProperty("NativeP2PAwdlPsfObservationOnlyRequested",
        probe->awdlPsfProbeEnabled ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfObservationOnlyStatus",
                            probe->psfStatus, 32);
    controller->setProperty("NativeP2PAwdlPsfTxBlockers",
                            probe->psfBlockers, 32);
    controller->setProperty("NativeP2PAwdlPsfProductionBlockers",
        probe->psfCandidate.blockers, 32);
    controller->setProperty("NativeP2PAwdlPsfFrameLength",
        static_cast<uint32_t>(probe->psfCandidateLength), 32);
    controller->setProperty("NativeP2PAwdlPsfObservationOnlyActive",
        probe->awdlPsfProbeEnabled ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfClockMappingProven",
        probe->psfWitness.clockMappingConfirmed ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfScheduleExpiryProven",
        probe->psfWitness.cyclicExpiryRepresentable ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfDataPathAdvertised", uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlPsfTxComplete",
        probe->psfTxCompleted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfTxSucceeded",
        probe->psfTxSucceeded ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfTxStatus",
        probe->psfTicketStatus, 32);
    controller->setProperty("NativeP2PAwdlPsfFrameSubmitted",
        probe->psfFrameSubmitted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfPeerAcknowledged",
        probe->psfPeerAcknowledged ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfAdvertisedCoverageProven",
        uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlPsfStartObservedMonotonicUs",
        probe->psfWitness.startObservedUs, 64);
    controller->setProperty("NativeP2PAwdlPsfCandidateBuiltMonotonicUs",
        probe->psfWitness.sampleUs, 64);
    controller->setProperty("NativeP2PAwdlPsfHardDeadlineMonotonicUs",
        probe->psfWitness.hardDeadlineUs, 64);
    controller->setProperty("NativeP2PAwdlPsfHostTxGateMonotonicUs",
        probe->psfHostGateUs, 64);
    controller->setProperty("NativeP2PAwdlPsfHostLeaseRemainingAtGateUs",
        probe->psfHostLeaseRemainingAtGateUs, 64);
}

static void publishMifProbeDetails(ItlIwx *owner, const P2PProbeRun *probe)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller || !probe)
        return;
    controller->setProperty("NativeP2PAwdlMifFollowupRequested",
        probe->awdlMifFollowupEnabled ? 1u : 0u, 32);
    controller->setProperty("NativeP2PTxFrameKind", kP2PFrameAwdlMif, 32);
    controller->setProperty("NativeP2PAwdlMifFollowupStatus",
        probe->mifStatus, 32);
    controller->setProperty("NativeP2PAwdlMifTxBlockers",
        probe->mifBlockers, 32);
    controller->setProperty("NativeP2PAwdlMifFrameLength",
        static_cast<uint32_t>(probe->mifCandidateLength), 32);
    controller->setProperty("NativeP2PAwdlMifFrameSubmitted",
        probe->mifFrameSubmitted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifTxAttempted",
        probe->mifTxAttempted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifTxComplete",
        probe->mifTxCompleted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifTxSucceeded",
        probe->mifTxSucceeded ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifTxStatus",
        probe->mifTicketStatus, 32);
    controller->setProperty("NativeP2PAwdlMifPeerAcknowledged",
        probe->mifPeerAcknowledged ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifDataPathAdvertised",
        uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlMifClockMappingProven",
        uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlMifScheduleExpiryProven",
        uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlMifAdvertisedCoverageProven",
        uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlMifBurstLimit",
        NativeAwdlProbe::kMifBurstMaximumFrames, 32);
    controller->setProperty("NativeP2PAwdlMifBurstPrepared",
        probe->mifBurstPreparedFrames, 32);
    controller->setProperty("NativeP2PAwdlMifBurstAttempted",
        probe->mifBurstAttemptedFrames, 32);
    controller->setProperty("NativeP2PAwdlMifBurstSubmitted",
        probe->mifBurstSubmittedFrames, 32);
    controller->setProperty("NativeP2PAwdlMifBurstCompleted",
        probe->mifBurstCompletedFrames, 32);
    controller->setProperty("NativeP2PAwdlMifBurstSucceeded",
        probe->mifBurstSucceededFrames, 32);
    controller->setProperty("NativeP2PAwdlMifBurstStopReason",
        probe->mifBurstStopReason, 32);
    controller->setProperty("NativeP2PAwdlMifBurstLastCompletionUs",
        probe->mifBurstLastCompletionUs, 64);
    controller->setProperty("NativeP2PAwdlMifPacingReason",
        probe->mifPacingReason, 32);
    controller->setProperty("NativeP2PAwdlMifPacingAnchorRxUs",
        probe->mifPacingCandidateAnchorRxUs, 64);
    controller->setProperty("NativeP2PAwdlMifPacingAnchorCount",
        probe->mifPacingAnchorCount, 32);
    controller->setProperty("NativeP2PAwdlMifPacingNoMifSubmitted",
        probe->awdlMifFollowupEnabled &&
            probe->mifBurstSubmittedFrames == 0 ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifPacingSubmitFailed",
        probe->awdlMifFollowupEnabled &&
            probe->mifBurstAttemptedFrames >
                probe->mifBurstSubmittedFrames ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifPacingEarliestUs",
        probe->mifPacingEarliestUs, 64);
    controller->setProperty("NativeP2PAwdlMifPacingLatestUs",
        probe->mifPacingLatestUs, 64);
    controller->setProperty("NativeP2PAwdlActionFramesSubmitted",
        probe->actionFramesSubmitted, 32);
    controller->setProperty("NativeP2PAwdlActionFramesCompleted",
        probe->actionFramesCompleted, 32);
    controller->setProperty("NativeP2PAwdlActionFramesSucceeded",
        probe->actionFramesSucceeded, 32);
    controller->setProperty("NativeP2PAwdlPsfMifTwoFrameComplete",
        probe->psfResultCaptured && probe->mifResultCaptured ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfMifTwoFrameSucceeded",
        probe->psfResultCaptured && probe->psfTxSucceeded &&
        probe->mifResultCaptured && probe->mifTxSucceeded ? 1u : 0u, 32);
}

static mbuf_t makeActionFrameFromBytes(const uint8_t *bytes, size_t length);

static bool preparePsfCandidateAfterStart(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    uint32_t durationMs, uint16_t sequenceNumber,
    uint64_t commandSubmittedUs)
{
    if (!probe || !probe->owner || !probe->awdlPsfProbeEnabled)
        return false;
    struct iwx_softc *sc = &probe->owner->com;
    struct ieee80211com *ic = &sc->sc_ic;
    NativeAwdlProbe::Request request{};
    memcpy(request.p2pMac.bytes, sc->sc_p2p.mac_address,
           sizeof(request.p2pMac.bytes));
    request.monotonicSampleUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    request.ieee80211SequenceNumber = sequenceNumber;
    request.ht.capabilityInfo = ic->ic_htcaps;
    request.ht.ampduParameters = ic->ic_ampdu_params;
    request.ht.rxMcsLength = sizeof(request.ht.rxMcsMask);
    memcpy(request.ht.rxMcsMask, ic->ic_sup_mcs,
           request.ht.rxMcsLength);
    uint8_t anyMcs = 0;
    for (size_t i = 0; i < request.ht.rxMcsLength; ++i)
        anyMcs |= request.ht.rxMcsMask[i];
    request.ht.confirmed = ic->ic_htcaps != 0 && anyMcs != 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.commandReturned && session.commandResult == 0 &&
        session.startSeen && session.startStatus == 1 &&
        !session.endSeen && !session.outcomeUnknown &&
        session.startObservedMonotonicUs != 0 && durationMs != 0;

    auto &witness = probe->psfWitness;
    witness = {};
    witness.expectedGeneration = probe->contextGeneration;
    witness.sessionGeneration = session.generation;
    witness.startObservedUs = session.startObservedMonotonicUs;
    witness.matchingSuccessfulStart = request.ht.confirmed;
    witness.activeAtSample = request.monotonicSampleUs >
            session.startObservedMonotonicUs && !session.endSeen &&
        !session.outcomeUnknown;
    witness.sampleUs = request.monotonicSampleUs;
    const uint64_t durationTu = p2pRocDurationTu(durationMs);
    const uint64_t durationUs = durationTu * 1024ULL;
    if (!commandSubmittedUs ||
        commandSubmittedUs > UINT64_MAX - durationUs ||
        durationUs <= NativeAwdlProbe::kPsfLeaseSafetyMarginUs) {
        probe->psfStatus = kPsfProbeCandidateRejected;
        probe->psfBlockers = NativeAwdlProbe::kPsfTxInvalidMonotonicWitness;
        return false;
    }
    // The command issue time precedes firmware dwell start; using it as the
    // duration origin is conservative even if START notification delivery is
    // delayed. The RX notification timestamp is still retained separately as
    // the start witness.
    witness.hardDeadlineUs = commandSubmittedUs + durationUs -
        NativeAwdlProbe::kPsfLeaseSafetyMarginUs;
    // This explicit observation-only experiment does not prove Intel/host
    // time maps to AWDL time or that a cyclic schedule can expire safely.
    witness.clockMappingConfirmed = false;
    witness.cyclicExpiryRepresentable = false;

    NativeAwdlProbe::PsfCandidate candidate{};
    const auto status = NativeAwdlProbe::prepareExperimentalPsfCandidate(
        &request, &witness, &candidate);
    if (status != NativeAwdlProbe::PsfCandidateStatus::Encoded) {
        probe->psfStatus = kPsfProbeCandidateRejected;
        probe->psfBlockers = NativeAwdlProbe::kPsfTxInvalidMonotonicWitness;
        return false;
    }
    probe->psfCandidate = candidate;
    probe->psfCandidateLength = candidate.length;
    probe->psfBlockers = NativeAwdlProbe::p2pPsfObservationTxBlockers(
        &candidate, &witness, request.monotonicSampleUs);
    probe->psfStatus = probe->psfBlockers == NativeAwdlProbe::kPsfTxNoBlocker ?
        kPsfProbeCandidateEncodedReady : kPsfProbeCandidateEncodedBlocked;
    return true;
}

static NativeAwdlProbe::MifFollowupWitness makeMifFollowupWitness(
    const P2PProbeRun *probe,
    const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t sampleUs)
{
    NativeAwdlProbe::MifFollowupWitness witness{};
    if (!probe)
        return witness;
    witness.roc = probe->psfWitness;
    witness.roc.sessionGeneration = session.generation;
    witness.roc.startObservedUs = session.startObservedMonotonicUs;
    witness.roc.sampleUs = sampleUs;
    witness.roc.matchingSuccessfulStart = session.commandReturned &&
        session.commandResult == 0 && session.startSeen &&
        session.startStatus == 1 && session.configuration ==
            IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION;
    witness.roc.activeAtSample = witness.roc.matchingSuccessfulStart &&
        sampleUs > session.startObservedMonotonicUs && !session.endSeen &&
        !session.outcomeUnknown;
    witness.roc.endSeen = session.endSeen;
    witness.roc.outcomeUnknown = session.outcomeUnknown;
    witness.nextSequenceNumber = tx.nextSequenceNumber;
    witness.firstPsfTicketStatus = static_cast<uint16_t>(tx.ticketStatus);
    witness.firstPsfTicketSequenceControl = static_cast<uint16_t>(
        tx.ticketSequenceControl);
    witness.firstPsfTicketByteCount = static_cast<uint16_t>(
        tx.ticketByteCount);
    witness.firstPsfTicketFrameControl = static_cast<uint16_t>(
        tx.ticketFrameControl);
    witness.firstPsfTicketCompleted = tx.ticketCompleted &&
        tx.actionState == static_cast<uint32_t>(TahoeP2PActionTxState::kIdle);
    witness.firstPsfTicketSucceeded = witness.firstPsfTicketCompleted &&
        tx.frameAttemptSucceeded && (tx.ticketStatus & 0xffu) == 1u;
    witness.queueLeaseActive = tx.queueLeaseActive;
    witness.txRingEmpty = tx.txRingEmpty;
    witness.ringIndicesConsistent = tx.ringIndicesConsistent;
    return witness;
}

struct MifPacingPeerView {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rxMonotonicUs;
    uint64_t sampleUs;
    uint16_t rxChannelIndex;
    bool rocActive;
    bool rocChannel6Confirmed;
    bool endSeen;
    bool outcomeUnknown;
    bool complete;
    bool syncConsistent;
    bool fresh;
    bool rxChannel6Confirmed;
};

struct MifPacingPeerRead {
    ItlIwx *owner;
    P2PProbeRun *probe;
    MifPacingPeerView view;
};

static bool isCurrentIeeeChannel6(struct ieee80211com *ic,
                                 struct ieee80211_channel *channel)
{
    if (!ic || !channel)
        return false;
    const size_t count = sizeof(ic->ic_channels) / sizeof(ic->ic_channels[0]);
    for (size_t i = 0; i < count; ++i) {
        if (&ic->ic_channels[i] == channel)
            return ieee80211_chan2ieee(ic, channel) == 6;
    }
    return false;
}

static IOReturn readMifPacingPeerInGate(OSObject *, void *opaque,
                                        void *, void *, void *)
{
    auto *read = static_cast<MifPacingPeerRead *>(opaque);
    auto *owner = read ? read->owner : nullptr;
    auto *probe = read ? read->probe : nullptr;
    if (!owner || !probe || !owner->tahoeP2pOnMainGate())
        return kIOReturnNotReady;

    auto &sc = owner->com;
    auto &ic = sc.sc_ic;
    const auto session = owner->nativeP2pRocEvents_.snapshot();
    auto &view = read->view;
    view.endSeen = session.endSeen;
    view.outcomeUnknown = session.outcomeUnknown;
    view.rocActive = session.commandReturned && session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == probe->contextGeneration &&
        !session.endSeen && !session.outcomeUnknown &&
        owner->nativeP2pProbeGeneration_ == probe->contextGeneration &&
        sc.sc_p2p_roc.token == probe->contextGeneration &&
        sc.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED;
    view.rocChannel6Confirmed = isCurrentIeeeChannel6(
        &ic, sc.sc_p2p_roc.roc_channel);

    owner->tahoeP2pRxDrain();
    const uint64_t nowUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    view.sampleUs = nowUs;
    IntelAwdlPeer::RuntimeEpochs epochs{
        owner->nativeP2pProbeGeneration_,
        uint64_t(uint32_t(sc.sc_generation)),
        __atomic_load_n(&sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE),
        owner->nativeP2pProbeGeneration_ != 0 &&
            ic.ic_state == IEEE80211_S_RUN &&
            (sc.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) == 0
    };
    view.contextGeneration = epochs.contextGeneration;
    view.powerGeneration = epochs.powerGeneration;
    view.stationGeneration = epochs.stationGeneration;
    if (!epochs.active || epochs.contextGeneration != probe->contextGeneration ||
        epochs.powerGeneration != probe->powerGeneration ||
        epochs.stationGeneration != probe->stationGeneration ||
        !view.rocActive || !view.rocChannel6Confirmed || nowUs == 0)
        return kIOReturnSuccess;

    IntelAwdlPeerRuntime::PsfPeerSnapshot newest{};
    bool found = false;
    for (uint8_t slot = 0; slot < IntelAwdlPeerRuntime::kPeerCapacity;
         ++slot) {
        IntelAwdlPeerRuntime::PsfPeerSnapshot candidate{};
        if (!owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(
                slot, epochs, nowUs, &candidate) || !candidate.tracked ||
            !candidate.hasPsf || !candidate.psfFresh ||
            candidate.contextGeneration != epochs.contextGeneration ||
            candidate.powerGeneration != epochs.powerGeneration ||
            candidate.stationGeneration != epochs.stationGeneration)
            continue;
        if (!found || candidate.psfRxMonotonicUs >
                          newest.psfRxMonotonicUs) {
            newest = candidate;
            found = true;
        }
    }
    if (!found)
        return kIOReturnSuccess;

    view.complete = newest.tracked && newest.hasPsf &&
        newest.contextGeneration == epochs.contextGeneration &&
        newest.powerGeneration == epochs.powerGeneration &&
        newest.stationGeneration == epochs.stationGeneration;
    view.syncConsistent = newest.syncConsistent;
    view.fresh = newest.psfFresh;
    view.rxMonotonicUs = newest.psfRxMonotonicUs;
    view.rxChannelIndex = newest.rxChannel;
    view.rxChannel6Confirmed = newest.rxChannel <
            sizeof(ic.ic_channels) / sizeof(ic.ic_channels[0]) &&
        ieee80211_chan2ieee(&ic, &ic.ic_channels[newest.rxChannel]) == 6;
    return kIOReturnSuccess;
}

static bool readMifPacingPeer(P2PProbeRun *probe, MifPacingPeerView *output)
{
    if (!probe || !probe->owner || !output)
        return false;
    auto *gate = probe->owner->tahoeP2pCommandGate();
    if (!gate)
        return false;
    MifPacingPeerRead read{};
    read.owner = probe->owner;
    read.probe = probe;
    if (gate->runAction(readMifPacingPeerInGate, &read) != kIOReturnSuccess)
        return false;
    *output = read.view;
    return true;
}

static NativeAwdlProbe::MifPacingInput makeMifPacingInput(
    const P2PProbeRun *probe, const MifPacingPeerView &peer,
    uint64_t nowUs, uint32_t ordinal, uint64_t lastUsedAnchorUs)
{
    NativeAwdlProbe::MifPacingInput input{};
    if (!probe)
        return input;
    input.phaseOriginUs = probe->psfCandidate.sampleUs;
    input.announcedWindowEndUs = probe->mifPacingWindowEndUs;
    input.hardDeadlineUs = probe->psfCandidate.hardDeadlineUs;
    input.nowUs = nowUs;
    input.peerPsfRxUs = peer.rxMonotonicUs;
    input.lastUsedPeerPsfRxUs = lastUsedAnchorUs;
    input.contextGeneration = probe->contextGeneration;
    input.powerGeneration = probe->powerGeneration;
    input.stationGeneration = probe->stationGeneration;
    input.peerContextGeneration = peer.contextGeneration;
    input.peerPowerGeneration = peer.powerGeneration;
    input.peerStationGeneration = peer.stationGeneration;
    input.frameOrdinal = ordinal;
    input.peerRxChannelIndex = peer.rxChannelIndex;
    input.rocActive = peer.rocActive;
    input.rocChannel6Confirmed = peer.rocChannel6Confirmed;
    input.endSeen = peer.endSeen;
    input.outcomeUnknown = peer.outcomeUnknown;
    input.peerPsfComplete = peer.complete;
    input.peerPsfSyncConsistent = peer.syncConsistent;
    input.peerPsfFresh = peer.fresh;
    input.peerPsfRxChannel6Confirmed = peer.rxChannel6Confirmed;
    return input;
}

static NativeAwdlProbe::MifPacingPlan refreshMifPacingAnchorInGate(
    P2PProbeRun *probe, uint64_t *sampleUs)
{
    if (!probe || !probe->owner || !sampleUs ||
        !probe->owner->tahoeP2pOnMainGate())
        return {NativeAwdlProbe::MifPacingDecision::Stop,
                NativeAwdlProbe::MifPacingReason::InvalidInput,
                0, 0, 0, 0};
    MifPacingPeerRead read{};
    read.owner = probe->owner;
    read.probe = probe;
    if (readMifPacingPeerInGate(nullptr, &read, nullptr, nullptr, nullptr) !=
        kIOReturnSuccess)
        return {NativeAwdlProbe::MifPacingDecision::Stop,
                NativeAwdlProbe::MifPacingReason::InvalidInput,
                0, probe->mifPacingWindowEndUs, 0, 0};
    const uint64_t afterDrainUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    *sampleUs = afterDrainUs > read.view.sampleUs ? afterDrainUs :
                read.view.sampleUs;
    const auto plan = NativeAwdlProbe::planMifPacing(makeMifPacingInput(
        probe, read.view, *sampleUs, probe->mifPacingCandidateOrdinal,
        probe->mifPacingLastConsumedAnchorRxUs));
    if (plan.decision == NativeAwdlProbe::MifPacingDecision::Ready) {
        probe->mifPacingCandidateAnchorRxUs = plan.anchorRxUs;
        probe->mifPacingCandidateAnchorComplete = read.view.complete;
        probe->mifPacingCandidateAnchorSyncConsistent =
            read.view.syncConsistent;
        probe->mifPacingCandidateAnchorChannel6Confirmed =
            read.view.rxChannel6Confirmed;
        probe->mifPacingCandidateContextGeneration =
            read.view.contextGeneration;
        probe->mifPacingCandidatePowerGeneration =
            read.view.powerGeneration;
        probe->mifPacingCandidateStationGeneration =
            read.view.stationGeneration;
        probe->mifPacingCandidateRxChannelIndex = read.view.rxChannelIndex;
        probe->mifPacingReason = static_cast<uint32_t>(plan.reason);
        probe->mifPacingEarliestUs = plan.earliestUs;
        probe->mifPacingLatestUs = plan.latestUs;
    }
    return plan;
}

static NativeAwdlProbe::MifPacingPlan finalCheckMifPacingAnchorInGate(
    const P2PProbeRun *probe, uint64_t nowUs)
{
    if (!probe || !probe->owner ||
        !probe->owner->tahoeP2pOnMainGate())
        return {NativeAwdlProbe::MifPacingDecision::Stop,
                NativeAwdlProbe::MifPacingReason::InvalidInput,
                0, 0, 0, 0};
    auto *owner = probe->owner;
    auto &sc = owner->com;
    auto &ic = sc.sc_ic;
    const auto session = owner->nativeP2pRocEvents_.snapshot();
    MifPacingPeerView peer{};
    peer.contextGeneration = probe->mifPacingCandidateContextGeneration;
    peer.powerGeneration = probe->mifPacingCandidatePowerGeneration;
    peer.stationGeneration = probe->mifPacingCandidateStationGeneration;
    peer.rxMonotonicUs = probe->mifPacingCandidateAnchorRxUs;
    peer.rxChannelIndex = probe->mifPacingCandidateRxChannelIndex;
    peer.complete = probe->mifPacingCandidateAnchorComplete;
    peer.syncConsistent = probe->mifPacingCandidateAnchorSyncConsistent;
    peer.fresh = peer.complete && peer.syncConsistent;
    peer.rxChannel6Confirmed =
        probe->mifPacingCandidateAnchorChannel6Confirmed &&
        peer.rxChannelIndex <
            sizeof(ic.ic_channels) / sizeof(ic.ic_channels[0]) &&
        ieee80211_chan2ieee(&ic, &ic.ic_channels[peer.rxChannelIndex]) == 6;
    peer.endSeen = session.endSeen;
    peer.outcomeUnknown = session.outcomeUnknown;
    peer.rocActive = session.commandReturned && session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == probe->contextGeneration &&
        owner->nativeP2pProbeGeneration_ == probe->contextGeneration &&
        sc.sc_p2p_roc.token == probe->contextGeneration &&
        sc.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED &&
        !session.endSeen && !session.outcomeUnknown;
    peer.rocChannel6Confirmed = isCurrentIeeeChannel6(
        &ic, sc.sc_p2p_roc.roc_channel);
    auto input = makeMifPacingInput(
        probe, peer, nowUs, probe->mifPacingCandidateOrdinal,
        probe->mifPacingLastConsumedAnchorRxUs);
    // A reset or station generation change can be published asynchronously
    // while the final gate path builds the fresh descriptor. Compare against
    // the live values again at the last pre-submit check.
    input.contextGeneration = owner->nativeP2pProbeGeneration_;
    input.powerGeneration = uint64_t(uint32_t(sc.sc_generation));
    input.stationGeneration = __atomic_load_n(
        &sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    return NativeAwdlProbe::planMifPacing(input);
}

static uint32_t mifCandidateStatusBlocker(
    NativeAwdlProbe::MifCandidateStatus status)
{
    using NativeAwdlProbe::MifCandidateStatus;
    switch (status) {
        case MifCandidateStatus::FirstPsfNotCompleted:
            return NativeAwdlProbe::kMifTxFirstPsfNotCompleted;
        case MifCandidateStatus::FirstPsfFailed:
            return NativeAwdlProbe::kMifTxFirstPsfFailed;
        case MifCandidateStatus::QueueNotIdle:
            return NativeAwdlProbe::kMifTxQueueNotIdle;
        case MifCandidateStatus::PhaseRejected:
            return NativeAwdlProbe::kMifTxPhaseRejected;
        case MifCandidateStatus::InvalidRocWitness:
            return NativeAwdlProbe::kMifTxInvalidMonotonicWitness;
        case MifCandidateStatus::Encoded:
            return NativeAwdlProbe::kMifTxNoBlocker;
        default:
            return NativeAwdlProbe::kMifTxInvalidCandidate;
    }
}

static bool mifBurstTicketMatchesPreviousCompletion(
    const P2PProbeRun *probe, const P2PTxDiagnosticSnapshot &tx)
{
    if (!probe || !tx.ticketCompleted ||
        tx.actionState != static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle) ||
        !tx.frameAttemptSucceeded || (tx.ticketStatus & 0xffu) != 1u ||
        tx.ticketStatus != probe->mifBurstLastTicketStatus ||
        tx.ticketSequenceControl !=
            probe->mifBurstLastTicketSequenceControl ||
        tx.ticketByteCount != probe->mifBurstLastTicketByteCount ||
        tx.ticketFrameControl != probe->mifBurstLastTicketFrameControl ||
        tx.nextSequenceNumber != probe->mifBurstLastNextSequenceNumber ||
        (tx.ticketSequenceControl & 0x000fu) != 0 ||
        tx.ticketFrameControl != 0x00d0u || tx.ticketByteCount == 0)
        return false;
    const uint16_t completedSequence = static_cast<uint16_t>(
        (tx.ticketSequenceControl >> 4) & 0x0fffu);
    const uint16_t expectedNext = static_cast<uint16_t>(
        (completedSequence + 1u) & 0x0fffu);
    return tx.nextSequenceNumber == expectedNext;
}

static NativeAwdlProbe::MifBurstRepeatState mifBurstRepeatState(
    const P2PProbeRun *probe,
    const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t nowUs, bool frameEmpty,
    bool candidateAlreadyPrepared = false)
{
    NativeAwdlProbe::MifBurstRepeatState state{};
    if (!probe || !probe->owner)
        return state;
    const ItlIwx *owner = probe->owner;
    const struct iwx_softc *sc = &owner->com;
    state.preparedFrames = probe->mifBurstPreparedFrames;
    state.submittedFrames = probe->mifBurstSubmittedFrames;
    state.nativeDataAttempts = probe->nativeDataAttempts;
    state.nowUs = nowUs;
    state.lastCompletionUs = probe->mifBurstLastCompletionUs;
    state.sameEpoch = probe->mifBurstEpoch != 0 &&
        probe->mifBurstEpoch == probe->contextGeneration &&
        session.generation == probe->contextGeneration &&
        owner->nativeP2pProbeGeneration_ == probe->contextGeneration &&
        uint32_t(sc->sc_generation) == probe->powerGeneration &&
        __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) ==
            probe->stationGeneration;
    state.rocActive = session.commandReturned && session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.startObservedMonotonicUs == probe->psfWitness.startObservedUs &&
        !session.endSeen && !session.outcomeUnknown;
    state.endSeen = session.endSeen;
    state.outcomeUnknown = session.outcomeUnknown;
    state.previousMifSucceeded = probe->mifBurstCompletedFrames != 0 &&
        probe->mifBurstCompletedFrames == probe->mifBurstSucceededFrames;
    state.ticketCompleted = tx.ticketCompleted;
    state.ticketSucceeded = mifBurstTicketMatchesPreviousCompletion(probe, tx);
    state.actionIdle = tx.actionState == static_cast<uint32_t>(
        TahoeP2PActionTxState::kIdle);
    // The tracker keeps `armed` set for its completed ticket. It is safe to
    // reuse only when that armed ticket is complete and ActionIdle with no
    // outstanding/ring work; a live armed ticket still blocks reuse.
    state.queueLeaseActive = tx.queueLeaseActive && tx.outstandingTx == 0 &&
        (!tx.ticketArmed || tx.ticketCompleted);
    state.ringEmpty = tx.txRingEmpty;
    state.ringIndicesConsistent = tx.ringIndicesConsistent;
    state.frameEmpty = frameEmpty;
    state.candidateAlreadyPrepared = candidateAlreadyPrepared;
    return state;
}

static NativeAwdlProbe::MifBurstRepeatPlan mifBurstDoorbellPlan(
    const P2PProbeRun *probe,
    const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t nowUs)
{
    // The candidate already occupies one prepared slot in the cap. The
    // third prepared frame may still be submitted while submitted remains 2.
    return NativeAwdlProbe::planMifBurstRepeat(
        mifBurstRepeatState(probe, session, tx, nowUs, true, true));
}

static bool buildFreshMifBurstCandidate(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t sampleUs,
    NativeAwdlProbe::MifCandidate *output, bool candidateAlreadyPrepared)
{
    if (!probe || !probe->owner || !output ||
        !probe->mifBurstCandidateIsRepeat ||
        probe->mifBurstPreparedFrames < (candidateAlreadyPrepared ? 2u : 1u) ||
        probe->mifBurstSubmittedFrames == 0 ||
        sampleUs < probe->mifBurstLastCompletionUs ||
        sampleUs - probe->mifBurstLastCompletionUs <
            NativeAwdlProbe::kMifBurstRepeatIntervalUs)
        return false;

    const auto plan = NativeAwdlProbe::planMifBurstRepeat(
        mifBurstRepeatState(probe, session, tx, sampleUs, true,
                            candidateAlreadyPrepared));
    if (plan.decision != NativeAwdlProbe::MifBurstDecision::Prepare)
        return false;
    if (!probe->psfCandidate.length ||
        probe->psfCandidate.length > sizeof(probe->psfCandidate.bytes) ||
        probe->mifCandidate.hostnameLength == 0 ||
        probe->mifCandidate.hostnameLength >
            sizeof(probe->mifCandidate.hostname) ||
        tx.nextSequenceNumber > 0x0fffu)
        return false;

    NativeAwdlProbe::MifCandidate candidate{};
    candidate.input = probe->psfCandidate.input;
    candidate.input.sequenceNumber = tx.nextSequenceNumber;
    candidate.contextGeneration = probe->contextGeneration;
    candidate.phaseOriginUs = probe->psfCandidate.sampleUs;
    candidate.startObservedUs = probe->psfCandidate.startObservedUs;
    candidate.sampleUs = sampleUs;
    candidate.hardDeadlineUs = probe->psfCandidate.hardDeadlineUs;
    candidate.firstPsfTicketStatus = probe->mifBurstLastTicketStatus;
    candidate.firstPsfTicketSequenceControl = static_cast<uint16_t>(
        probe->mifBurstLastTicketSequenceControl);
    candidate.firstPsfTicketByteCount = static_cast<uint16_t>(
        probe->mifBurstLastTicketByteCount);
    candidate.firstPsfTicketFrameControl = static_cast<uint16_t>(
        probe->mifBurstLastTicketFrameControl);
    candidate.hostnameLength = probe->mifCandidate.hostnameLength;
    memcpy(candidate.hostname, probe->mifCandidate.hostname,
           candidate.hostnameLength);

    NativeAwdlProbe::HostPhaseInput phaseInput{};
    phaseInput.phaseOriginUs = candidate.phaseOriginUs;
    phaseInput.sampleUs = sampleUs;
    phaseInput.rocStartUs = candidate.startObservedUs;
    phaseInput.hardDeadlineUs = candidate.hardDeadlineUs;
    phaseInput.rocChannel = candidate.input.masterChannel;
    memcpy(phaseInput.channelSlots, candidate.input.channelSlots,
           sizeof(phaseInput.channelSlots));
    if (NativeAwdlProbe::buildHostPhaseFields(
            &phaseInput, &candidate.phase) !=
        NativeAwdlProbe::HostPhaseStatus::Ok)
        return false;
    candidate.input.phyTxTimestampUs = candidate.phase.phyTxTimestampUs;
    candidate.input.targetTxTimestampUs = candidate.phase.targetTxTimestampUs;
    candidate.input.nextAwChannel = candidate.phase.nextAwChannel;
    candidate.input.txDownCounterTu = candidate.phase.txDownCounterTu;
    candidate.input.remainingAwLengthTu =
        candidate.phase.remainingAwLengthTu;
    candidate.input.nextAwSequenceNumber =
        candidate.phase.nextAwSequenceNumber;
    candidate.input.apAlignment = candidate.phase.apAlignment;
    memcpy(candidate.input.channelSlots, candidate.phase.channelSlots,
           sizeof(candidate.input.channelSlots));

    NativeAwdl::MifInput mifInput{};
    mifInput.psf = candidate.input;
    mifInput.hostname = candidate.hostname;
    mifInput.hostnameLength = candidate.hostnameLength;
    size_t written = 0;
    if (NativeAwdl::encodeMif(&mifInput, candidate.bytes,
            sizeof(candidate.bytes), &written) !=
            NativeAwdl::MifEncodeStatus::Ok || written == 0 ||
        written > sizeof(candidate.bytes))
        return false;
    NativeAwdl::ActionFrameInfo info{};
    if (NativeAwdl::parseActionFrame(candidate.bytes, written, &info) !=
            NativeAwdl::ParseStatus::Ok || info.subtype != 3 ||
        info.version != 0x10 ||
        info.phyTx != candidate.input.phyTxTimestampUs ||
        info.targetTx != candidate.input.targetTxTimestampUs)
        return false;
    candidate.length = written;
    *output = candidate;
    return true;
}

static bool prepareMifCandidateAfterPreviousMif(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t sampleUs, mbuf_t *frame)
{
    if (!probe || !frame || *frame)
        return false;
    NativeAwdlProbe::MifCandidate candidate{};
    if (!buildFreshMifBurstCandidate(probe, session, tx, sampleUs,
                                     &candidate, false))
        return false;
    mbuf_t freshFrame = makeActionFrameFromBytes(candidate.bytes,
                                                 candidate.length);
    if (!freshFrame)
        return false;
    probe->mifCandidate = candidate;
    probe->mifCandidateLength = candidate.length;
    probe->mifCandidatePrepared = true;
    probe->mifBurstPreparedFrames =
        probe->mifBurstPreparedFrames <
            NativeAwdlProbe::kMifBurstMaximumFrames ?
        probe->mifBurstPreparedFrames + 1 :
        NativeAwdlProbe::kMifBurstMaximumFrames;
    probe->mifStatus = kMifProbeCandidateEncodedReady;
    probe->mifBlockers = NativeAwdlProbe::kMifTxNoBlocker;
    *frame = freshFrame;
    publishMifProbeDetails(probe->owner, probe);
    return true;
}

static uint32_t mifBurstPlanTxBlocker(
    NativeAwdlProbe::MifBurstStopReason reason)
{
    switch (reason) {
        case NativeAwdlProbe::MifBurstStopReason::RocEnded:
            return NativeAwdlProbe::kMifTxRocEnded;
        case NativeAwdlProbe::MifBurstStopReason::RocUnknown:
            return NativeAwdlProbe::kMifTxRocUnknown;
        case NativeAwdlProbe::MifBurstStopReason::EpochMismatch:
            return NativeAwdlProbe::kMifTxGenerationMismatch;
        case NativeAwdlProbe::MifBurstStopReason::QueueNotIdle:
        case NativeAwdlProbe::MifBurstStopReason::PreviousTicketIncomplete:
            return NativeAwdlProbe::kMifTxQueueNotIdle;
        case NativeAwdlProbe::MifBurstStopReason::InvalidTime:
            return NativeAwdlProbe::kMifTxInvalidMonotonicWitness;
        case NativeAwdlProbe::MifBurstStopReason::None:
        case NativeAwdlProbe::MifBurstStopReason::FrameLimit:
        case NativeAwdlProbe::MifBurstStopReason::DataStarted:
        case NativeAwdlProbe::MifBurstStopReason::FrameNotEmpty:
        case NativeAwdlProbe::MifBurstStopReason::RocInactive:
        case NativeAwdlProbe::MifBurstStopReason::PreviousTicketFailed:
        case NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed:
        case NativeAwdlProbe::MifBurstStopReason::DoorbellRejected:
        case NativeAwdlProbe::MifBurstStopReason::FrameSubmissionFailed:
            return NativeAwdlProbe::kMifTxInvalidCandidate;
    }
    return NativeAwdlProbe::kMifTxInvalidCandidate;
}

static void resetMifFrameStateForRepeat(P2PProbeRun *probe)
{
    if (!probe)
        return;
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

static bool configureMifPacingWindow(P2PProbeRun *probe)
{
    if (!probe || !probe->psfCandidate.sampleUs ||
        !probe->psfCandidate.hardDeadlineUs)
        return false;
    uint64_t fullSlots = 0;
    bool sawEmpty = false;
    for (size_t i = 0; i < NativeAwdlProbe::kHostPhaseSlotCount; ++i) {
        if (probe->psfCandidate.input.channelSlots[i] == 0) {
            sawEmpty = true;
            continue;
        }
        if (sawEmpty || probe->psfCandidate.input.channelSlots[i] != 6)
            return false;
        ++fullSlots;
    }
    if (!fullSlots || fullSlots >
            UINT64_MAX / NativeAwdlProbe::kHostPhaseSlotDurationUs)
        return false;
    const uint64_t spanUs =
        fullSlots * NativeAwdlProbe::kHostPhaseSlotDurationUs;
    if (probe->psfCandidate.sampleUs > UINT64_MAX - spanUs)
        return false;
    const uint64_t endUs = probe->psfCandidate.sampleUs + spanUs;
    if (endUs <= probe->psfCandidate.sampleUs ||
        endUs > probe->psfCandidate.hardDeadlineUs)
        return false;
    probe->mifPacingWindowEndUs = endUs;
    return true;
}

static bool prepareMifCandidateAfterPsfCompletion(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t sampleUs, mbuf_t *frame)
{
    if (!probe || !probe->awdlMifFollowupEnabled || !frame || *frame ||
        !probe->psfResultCaptured || !probe->psfTxSucceeded ||
        probe->mifCandidatePrepared)
        return false;

    probe->mifBurstEpoch = probe->contextGeneration;
    probe->mifBurstCandidateIsRepeat = false;
    if (!configureMifPacingWindow(probe)) {
        probe->mifStatus = kMifProbePreflightRejected;
        probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
        probe->mifBurstStopped = true;
        probe->mifBurstStopReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
        probe->mifPacingReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifPacingReason::InvalidInput);
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }
    (void)session;
    (void)tx;
    (void)sampleUs;
    probe->mifBurstPreparedFrames = 0;
    probe->mifStatus = kMifProbeWaitingForPeerPsf;
    probe->mifPacingReason = static_cast<uint32_t>(
        NativeAwdlProbe::MifPacingReason::BeforeNotBefore);
    probe->mifPacingEarliestUs = 0;
    probe->mifPacingLatestUs = probe->mifPacingWindowEndUs;
    publishMifProbeDetails(probe->owner, probe);
    return false;
}

static void recordMifPacingPlan(P2PProbeRun *probe,
                                const NativeAwdlProbe::MifPacingPlan &plan,
                                bool stop)
{
    if (!probe)
        return;
    const bool changed = probe->mifPacingReason !=
            static_cast<uint32_t>(plan.reason) ||
        probe->mifPacingEarliestUs != plan.earliestUs ||
        probe->mifPacingLatestUs != plan.latestUs ||
        probe->mifPacingCandidateAnchorRxUs != plan.anchorRxUs;
    probe->mifPacingReason = static_cast<uint32_t>(plan.reason);
    probe->mifPacingEarliestUs = plan.earliestUs;
    probe->mifPacingLatestUs = plan.latestUs;
    if (stop) {
        probe->mifBurstStopped = true;
        probe->mifStatus = kMifProbePreflightRejected;
        probe->mifBlockers |= NativeAwdlProbe::kMifTxInvalidCandidate;
        if (probe->mifBurstStopReason == static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::None))
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
    } else {
        probe->mifStatus = kMifProbeWaitingForPeerPsf;
    }
    if (changed || stop)
        publishMifProbeDetails(probe->owner, probe);
}

static bool tryPrepareMifAtPacingPoint(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t nowUs, mbuf_t *frame)
{
    if (!probe || !frame || *frame || probe->mifBurstStopped ||
        probe->mifCandidatePrepared || !probe->psfResultCaptured ||
        !probe->psfTxSucceeded ||
        probe->mifBurstPreparedFrames >=
            NativeAwdlProbe::kMifPacingMaximumFrames)
        return false;

    const uint32_t ordinal = probe->mifBurstPreparedFrames;
    uint64_t earliestUs = 0;
    if (!NativeAwdlProbe::mifPacingNotBeforeUs(
            probe->psfCandidate.sampleUs, probe->mifPacingWindowEndUs,
            ordinal, &earliestUs)) {
        const NativeAwdlProbe::MifPacingPlan plan{
            NativeAwdlProbe::MifPacingDecision::Stop,
            NativeAwdlProbe::MifPacingReason::InvalidInput,
            0, probe->mifPacingWindowEndUs, 0, 0};
        recordMifPacingPlan(probe, plan, true);
        return false;
    }
    const uint64_t effectiveEndUs = probe->mifPacingWindowEndUs <
        probe->psfCandidate.hardDeadlineUs ? probe->mifPacingWindowEndUs :
        probe->psfCandidate.hardDeadlineUs;
    if (nowUs >= effectiveEndUs || effectiveEndUs - nowUs <=
            NativeAwdlProbe::kMifPacingMinimumLeaseReserveUs) {
        const auto reason = nowUs >= effectiveEndUs ?
            NativeAwdlProbe::MifPacingReason::Deadline :
            NativeAwdlProbe::MifPacingReason::InsufficientLease;
        const NativeAwdlProbe::MifPacingPlan plan{
            NativeAwdlProbe::MifPacingDecision::Stop, reason, earliestUs,
            effectiveEndUs, 0, 0};
        recordMifPacingPlan(probe, plan, true);
        return false;
    }
    if (nowUs < earliestUs) {
        const NativeAwdlProbe::MifPacingPlan plan{
            NativeAwdlProbe::MifPacingDecision::Wait,
            NativeAwdlProbe::MifPacingReason::BeforeNotBefore,
            earliestUs, effectiveEndUs, 0, 0};
        recordMifPacingPlan(probe, plan, false);
        return false;
    }

    MifPacingPeerView peer{};
    if (!readMifPacingPeer(probe, &peer)) {
        const NativeAwdlProbe::MifPacingPlan plan{
            NativeAwdlProbe::MifPacingDecision::Wait,
            NativeAwdlProbe::MifPacingReason::WaitingForFreshPsf,
            earliestUs, effectiveEndUs, 0, 0};
        recordMifPacingPlan(probe, plan, false);
        return false;
    }
    const uint64_t afterGateUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    const uint64_t planNowUs = afterGateUs > peer.sampleUs ? afterGateUs :
                               peer.sampleUs;
    const auto pacing = NativeAwdlProbe::planMifPacing(
        makeMifPacingInput(probe, peer, planNowUs, ordinal,
                           probe->mifPacingLastConsumedAnchorRxUs));
    if (pacing.decision != NativeAwdlProbe::MifPacingDecision::Ready) {
        recordMifPacingPlan(probe, pacing,
            pacing.decision == NativeAwdlProbe::MifPacingDecision::Stop);
        return false;
    }

    const bool repeat = probe->mifBurstSubmittedFrames != 0;
    if (repeat) {
        const auto repeatPlan = NativeAwdlProbe::planMifBurstRepeat(
            mifBurstRepeatState(probe, session, tx, planNowUs, *frame == nullptr));
        if (repeatPlan.decision == NativeAwdlProbe::MifBurstDecision::Stop) {
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                repeatPlan.reason);
            recordMifPacingPlan(probe, pacing, true);
            return false;
        }
        if (repeatPlan.decision != NativeAwdlProbe::MifBurstDecision::Prepare)
            return false;
        probe->mifBurstCandidateIsRepeat = true;
        resetMifFrameStateForRepeat(probe);
        if (!prepareMifCandidateAfterPreviousMif(
                probe, session, tx, planNowUs, frame)) {
            probe->mifBurstStopped = true;
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
            recordMifPacingPlan(probe, pacing, true);
            return false;
        }
    } else {
        const auto witness = makeMifFollowupWitness(probe, session, tx,
                                                     planNowUs);
        static const char hostname[] = "intel-awdl-probe";
        NativeAwdlProbe::MifCandidate candidate{};
        const auto status =
            NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
                &probe->psfCandidate, &witness, tx.ticketStatus, hostname,
                sizeof(hostname) - 1, &candidate);
        if (status != NativeAwdlProbe::MifCandidateStatus::Encoded) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = mifCandidateStatusBlocker(status);
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
            recordMifPacingPlan(probe, pacing, true);
            return false;
        }
        probe->mifBlockers = NativeAwdlProbe::mifFollowupTxBlockers(
            &candidate, &witness, planNowUs);
        if (probe->mifBlockers != NativeAwdlProbe::kMifTxNoBlocker) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
            recordMifPacingPlan(probe, pacing, true);
            return false;
        }
        *frame = makeActionFrameFromBytes(candidate.bytes, candidate.length);
        if (!*frame) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
            recordMifPacingPlan(probe, pacing, true);
            return false;
        }
        probe->mifCandidate = candidate;
        probe->mifCandidateLength = candidate.length;
        probe->mifCandidatePrepared = true;
        probe->mifBurstPreparedFrames = 1;
        probe->mifBurstCandidateIsRepeat = false;
        probe->mifStatus = kMifProbeCandidateEncodedReady;
    }

    probe->mifPacingCandidateAnchorRxUs = pacing.anchorRxUs;
    probe->mifPacingCandidateOrdinal = ordinal;
    probe->mifPacingCandidateAnchorComplete = peer.complete;
    probe->mifPacingCandidateAnchorSyncConsistent = peer.syncConsistent;
    probe->mifPacingCandidateAnchorChannel6Confirmed =
        peer.rxChannel6Confirmed;
    probe->mifPacingCandidateContextGeneration = peer.contextGeneration;
    probe->mifPacingCandidatePowerGeneration = peer.powerGeneration;
    probe->mifPacingCandidateStationGeneration = peer.stationGeneration;
    probe->mifPacingCandidateRxChannelIndex = peer.rxChannelIndex;
    probe->mifPacingReason = static_cast<uint32_t>(pacing.reason);
    probe->mifPacingEarliestUs = pacing.earliestUs;
    probe->mifPacingLatestUs = pacing.latestUs;
    publishMifProbeDetails(probe->owner, probe);
    return true;
}

static mbuf_t makeActionFrameFromBytes(const uint8_t *bytes, size_t length)
{
    if (!bytes || length == 0 || length > 0xffff)
        return nullptr;
    unsigned int chunks = 1;
    mbuf_t frame = nullptr;
    if (mbuf_allocpacket(MBUF_DONTWAIT, length, &chunks, &frame) != 0 ||
        !frame) {
        if (frame)
            mbuf_freem(frame);
        return nullptr;
    }
    mbuf_setlen(frame, static_cast<int>(length));
    mbuf_pkthdr_setlen(frame, static_cast<int>(length));
    if (mbuf_len(frame) != static_cast<int>(length) ||
        mbuf_pkthdr_len(frame) != static_cast<int>(length)) {
        mbuf_freem(frame);
        return nullptr;
    }
    memcpy(mbuf_data(frame), bytes, length);
    return frame;
}

static mbuf_t makeExperimentalActionFrame(const uint8_t source[6],
                                         uint16_t sequence)
{
    static const uint8_t payload[] = "ITL-P2P-PROBE";
    uint8_t bytes[64] = {};
    size_t length = 0;
    if (!IntelP2PActionFrame::encodeVendorSpecificAction(
            source, sequence, payload, sizeof(payload) - 1,
            bytes, sizeof(bytes), &length))
        return nullptr;
    return makeActionFrameFromBytes(bytes, length);
}

static IOReturn tahoeP2pSubmitActionInGate(OSObject *, void *opaque,
                                           void *, void *, void *)
{
    auto action = static_cast<P2PTxSubmitRun *>(opaque);
    auto probe = action ? action->probe : nullptr;
    auto owner = probe ? probe->owner : nullptr;
    const bool psfFrame = action && action->psfFrame;
    const bool mifFrame = action && action->mifFrame;
    const bool firstPsfSubmit = psfFrame && probe &&
        probe->awdlPsfProbeEnabled && !probe->actionTxAttempted;
    const bool mifFollowupSubmit = mifFrame && probe &&
        probe->awdlMifFollowupEnabled && probe->actionTxAttempted &&
        probe->psfFrameSubmitted && probe->psfResultCaptured &&
        probe->psfTxSucceeded && probe->mifCandidatePrepared &&
        !probe->mifBurstStopped && !probe->mifTxAttempted &&
        probe->mifBurstPreparedFrames <=
            NativeAwdlProbe::kMifBurstMaximumFrames &&
        probe->mifBurstSubmittedFrames <
            NativeAwdlProbe::kMifBurstMaximumFrames &&
        probe->mifStatus == kMifProbeCandidateEncodedReady;
    const bool legacySubmit = action && !psfFrame && !mifFrame && probe &&
        !probe->awdlPsfProbeEnabled && !probe->actionTxAttempted;
    if (!action || !probe || !owner || !action->frame ||
        !owner->tahoeP2pOnMainGate() || !probe->txProbeEnabled ||
        !(firstPsfSubmit || mifFollowupSubmit || legacySubmit) ||
        !owner->nativeP2pBusy() ||
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) !=
            reinterpret_cast<void *>(probe->workerThread) ||
        owner->nativeP2pProbeGeneration_ != probe->contextGeneration ||
        uint32_t(owner->com.sc_generation) != probe->powerGeneration ||
        __atomic_load_n(&owner->com.sc_tx_rate_generation, __ATOMIC_ACQUIRE) !=
            probe->stationGeneration)
        return kIOReturnNotReady;

    const auto session = owner->nativeP2pRocEvents_.snapshot();
    if (!session.commandReturned || session.commandResult != 0 ||
        session.configuration != owner->com.sc_p2p_roc.session_conf_id ||
        !session.startSeen || session.startStatus != 1 || session.endSeen ||
        session.outcomeUnknown ||
        owner->com.sc_p2p_roc.token != probe->contextGeneration ||
        owner->com.sc_p2p_roc.phase != IWX_P2P_ROC_SESSION_ACKED)
        return kIOReturnNotReady;

    if (psfFrame) {
        auto currentWitness = probe->psfWitness;
        currentWitness.sessionGeneration = session.generation;
        currentWitness.matchingSuccessfulStart = session.startSeen &&
            session.startStatus == 1;
        currentWitness.activeAtSample = currentWitness.matchingSuccessfulStart &&
            !session.endSeen && !session.outcomeUnknown;
        currentWitness.endSeen = session.endSeen;
        currentWitness.outcomeUnknown = session.outcomeUnknown;
        const uint64_t submitUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
        probe->psfHostGateUs = submitUs;
        probe->psfHostLeaseRemainingAtGateUs =
            submitUs < currentWitness.hardDeadlineUs ?
            currentWitness.hardDeadlineUs - submitUs : 0;
        if (session.startObservedMonotonicUs !=
            currentWitness.startObservedUs) {
            probe->psfBlockers |=
                NativeAwdlProbe::kPsfTxInvalidMonotonicWitness;
            action->frameStale = true;
            return kIOReturnNotReady;
        }
        const uint32_t blockers = NativeAwdlProbe::p2pPsfObservationTxBlockers(
            &probe->psfCandidate, &currentWitness, submitUs);
        if (blockers != NativeAwdlProbe::kPsfTxNoBlocker) {
            action->frameStale = (blockers &
                (NativeAwdlProbe::kPsfTxPreparedFrameStale |
                 NativeAwdlProbe::kPsfTxLeaseExpired)) != 0;
            probe->psfBlockers |= blockers;
            return kIOReturnNotReady;
        }
    }

    if (mifFrame) {
        P2PTxDiagnosticSnapshot txSnapshot{};
        if (!captureP2PTxSnapshot(owner, &txSnapshot)) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = NativeAwdlProbe::kMifTxQueueNotIdle;
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        uint64_t submitUs = 0;
        const auto pacingPlan = refreshMifPacingAnchorInGate(
            probe, &submitUs);
        if (pacingPlan.decision !=
                NativeAwdlProbe::MifPacingDecision::Ready ||
            pacingPlan.anchorRxUs == 0) {
            recordMifPacingPlan(probe, pacingPlan, true);
            probe->mifBlockers |=
                NativeAwdlProbe::kMifTxPreparedFrameStale;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        if (submitUs < probe->mifCandidate.sampleUs ||
            submitUs - probe->mifCandidate.sampleUs >
                NativeAwdlProbe::kMaximumPreparedPsfAgeUs) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = NativeAwdlProbe::kMifTxPreparedFrameStale;
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        NativeAwdlProbe::MifCandidate refreshed{};
        uint32_t candidateBlockers = 0;
        if (probe->mifBurstCandidateIsRepeat) {
            const auto plan = mifBurstDoorbellPlan(
                probe, session, txSnapshot, submitUs);
            if (plan.decision != NativeAwdlProbe::MifBurstDecision::Prepare ||
                !buildFreshMifBurstCandidate(probe, session, txSnapshot,
                                             submitUs, &refreshed, true)) {
                const auto stopReason = plan.reason !=
                    NativeAwdlProbe::MifBurstStopReason::None ? plan.reason :
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(stopReason);
                candidateBlockers = mifBurstPlanTxBlocker(stopReason);
            }
        } else {
            auto currentWitness = makeMifFollowupWitness(
                probe, session, txSnapshot, submitUs);
            static const char hostname[] = "intel-awdl-probe";
            const auto candidateStatus =
                NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
                    &probe->psfCandidate, &currentWitness,
                    txSnapshot.ticketStatus, hostname, sizeof(hostname) - 1,
                    &refreshed);
            if (candidateStatus !=
                NativeAwdlProbe::MifCandidateStatus::Encoded) {
                probe->mifStatus = kMifProbePreflightRejected;
                probe->mifBlockers = mifCandidateStatusBlocker(candidateStatus);
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
                action->frameStale = true;
                publishMifProbeDetails(owner, probe);
                return kIOReturnNotReady;
            }
            candidateBlockers = NativeAwdlProbe::mifFollowupTxBlockers(
                &refreshed, &currentWitness, submitUs);
        }
        if (candidateBlockers != 0) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers |= candidateBlockers;
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        // The worker built a validated MIF candidate before entering the gate.
        // Refresh the timestamps/phase from this exact gate sample, then swap
        // the mbuf immediately before the single doorbell submission.
        mbuf_t refreshedFrame = makeActionFrameFromBytes(
            refreshed.bytes, refreshed.length);
        if (!refreshedFrame) {
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        P2PTxDiagnosticSnapshot doorbellSnapshot{};
        uint64_t doorbellUs = 0;
        uint32_t doorbellBlockers = 0;
        if (!captureP2PTxSnapshot(owner, &doorbellSnapshot)) {
            doorbellBlockers = NativeAwdlProbe::kMifTxQueueNotIdle;
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
        } else {
            const auto pacingPlan = refreshMifPacingAnchorInGate(
                probe, &doorbellUs);
            if (pacingPlan.decision !=
                    NativeAwdlProbe::MifPacingDecision::Ready ||
                pacingPlan.anchorRxUs == 0) {
                recordMifPacingPlan(probe, pacingPlan, true);
                doorbellBlockers =
                    NativeAwdlProbe::kMifTxPreparedFrameStale;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            } else if (probe->mifBurstCandidateIsRepeat) {
            const auto plan = mifBurstDoorbellPlan(
                probe, session, doorbellSnapshot, doorbellUs);
            NativeAwdlProbe::MifCandidate doorbellCandidate{};
            if (plan.decision != NativeAwdlProbe::MifBurstDecision::Prepare ||
                !buildFreshMifBurstCandidate(probe, session, doorbellSnapshot,
                    doorbellUs, &doorbellCandidate, true)) {
                const auto stopReason = plan.reason !=
                    NativeAwdlProbe::MifBurstStopReason::None ? plan.reason :
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(stopReason);
                doorbellBlockers = mifBurstPlanTxBlocker(stopReason);
            } else {
                mbuf_t doorbellFrame = makeActionFrameFromBytes(
                    doorbellCandidate.bytes, doorbellCandidate.length);
                if (!doorbellFrame) {
                    doorbellBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
                    probe->mifBurstStopped = true;
                    probe->mifBurstStopReason = static_cast<uint32_t>(
                        NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
                } else {
                    mbuf_freem(refreshedFrame);
                    refreshedFrame = doorbellFrame;
                    refreshed = doorbellCandidate;
                }
            }
            } else {
            const auto freshDoorbellWitness = makeMifFollowupWitness(
                probe, session, doorbellSnapshot, doorbellUs);
            doorbellBlockers = NativeAwdlProbe::mifFollowupTxBlockers(
                &refreshed, &freshDoorbellWitness, doorbellUs);
            }
        }
        if (doorbellBlockers != NativeAwdlProbe::kMifTxNoBlocker) {
            mbuf_freem(refreshedFrame);
            probe->mifStatus = kMifProbePreflightRejected;
            probe->mifBlockers |= doorbellBlockers;
            probe->mifBurstStopped = true;
            if (probe->mifBurstStopReason == 0)
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        const uint64_t finalDoorbellUs =
            p2pProbeMonotonicNanoseconds() / 1000ULL;
        const auto finalPacingPlan = finalCheckMifPacingAnchorInGate(
            probe, finalDoorbellUs);
        const bool preparedFrameFresh =
            finalDoorbellUs >= refreshed.sampleUs &&
            finalDoorbellUs - refreshed.sampleUs <=
                NativeAwdlProbe::kMaximumPreparedPsfAgeUs;
        if (finalPacingPlan.decision !=
                NativeAwdlProbe::MifPacingDecision::Ready ||
            finalPacingPlan.anchorRxUs !=
                probe->mifPacingCandidateAnchorRxUs || !preparedFrameFresh) {
            auto failClosedPlan = finalPacingPlan;
            if (finalPacingPlan.decision ==
                    NativeAwdlProbe::MifPacingDecision::Ready &&
                !preparedFrameFresh) {
                failClosedPlan.decision =
                    NativeAwdlProbe::MifPacingDecision::Stop;
                failClosedPlan.reason =
                    NativeAwdlProbe::MifPacingReason::PreparedFrameStale;
            }
            recordMifPacingPlan(probe, failClosedPlan, true);
            mbuf_freem(refreshedFrame);
            probe->mifBlockers |=
                NativeAwdlProbe::kMifTxPreparedFrameStale;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        probe->mifPacingReason = static_cast<uint32_t>(
            finalPacingPlan.reason);
        probe->mifPacingLatestUs = finalPacingPlan.latestUs;
        mbuf_freem(action->frame);
        action->frame = refreshedFrame;
        probe->mifCandidate = refreshed;
        probe->mifCandidateLength = refreshed.length;
        probe->mifBlockers = NativeAwdlProbe::kMifTxNoBlocker;
    }

    probe->actionTxAttempted = true;
    probe->actionTxRequired = true;
    if (mifFrame) {
        probe->mifTxAttempted = true;
        if (probe->mifBurstAttemptedFrames <
            NativeAwdlProbe::kMifBurstMaximumFrames)
            ++probe->mifBurstAttemptedFrames;
    }
    mbuf_t frame = action->frame;
    action->frame = nullptr;
    action->frameConsumed = true;
    action->result = iwx_tahoe_p2p_action_tx_submit(
        owner, &owner->com, &owner->nativeP2pTxQueue_,
        &owner->nativeP2pActionTx_, probe->contextGeneration,
        session.startSeen, session.endSeen, frame);
    if (action->result == 0) {
        ++probe->actionFramesSubmitted;
        probe->pendingFrameKind = psfFrame ? kP2PFrameAwdlPsf :
            (mifFrame ? kP2PFrameAwdlMif : kP2PFrameLegacyVendorAction);
        if (psfFrame)
            probe->psfFrameSubmitted = true;
        if (mifFrame) {
            probe->mifFrameSubmitted = true;
            probe->mifPacingLastConsumedAnchorRxUs =
                probe->mifPacingCandidateAnchorRxUs;
            if (probe->mifPacingAnchorCount <
                NativeAwdlProbe::kMifPacingMaximumFrames)
                ++probe->mifPacingAnchorCount;
            if (probe->mifBurstSubmittedFrames <
                NativeAwdlProbe::kMifBurstMaximumFrames)
                ++probe->mifBurstSubmittedFrames;
        }
    } else if (mifFrame) {
        probe->mifBurstStopped = true;
        probe->mifBurstStopReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifBurstStopReason::FrameSubmissionFailed);
    }
    if (psfFrame) {
        probe->psfStatus = kPsfProbeFrameSubmissionAttempted;
        publishPsfProbeDetails(owner, probe, kP2PFrameAwdlPsf);
    }
    if (mifFrame) {
        probe->mifStatus = action->result == 0 ?
            kMifProbeFrameSubmissionAttempted :
            kMifProbeFrameSubmissionFailed;
        if (action->result != 0)
            probe->mifBlockers |= NativeAwdlProbe::kMifTxInvalidCandidate;
        publishMifProbeDetails(owner, probe);
    }
    return kIOReturnSuccess;
}

static void recordBlocked(ItlIwx *owner, NativeP2PProbe::BlockedReason reason)
{
    NativeP2PProbe::Admission admission{};
    admission.enabled = true;
    owner->nativeP2pProbe_.tryQueue(admission, reason);
}

static bool commandQueueIdle(struct iwx_softc *sc)
{
    if (!sc || sc->txq[IWX_DQA_CMD_QUEUE].queued != 0)
        return false;
    for (unsigned int i = 0; i < nitems(sc->sc_cmd_resp_pkt); ++i) {
        if (sc->sc_cmd_resp_pkt[i] != nullptr)
            return false;
    }
    return true;
}

static bool p2pCapabilityAvailable(ItlIwx *owner, struct iwx_softc *sc)
{
    return owner && sc &&
        (sc->sc_capaflags & IWX_UCODE_TLV_FLAGS_P2P) != 0 &&
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP,
                                  IWX_MAC_CONTEXT_CMD) == 5;
}

static void deriveProbeAddress(const uint8_t primary[6], uint8_t output[6])
{
    memcpy(output, primary, 6);
    output[0] = uint8_t((output[0] & 0xfc) | 0x02); // locally administered unicast
    output[5] ^= 0x01;                              // guaranteed distinct
}

static NativeP2PProbe::BlockedReason admissionFailure(
    ItlIwx *owner, struct iwx_softc *sc, P2PProbeRun *run,
    NativeP2PProbe::Admission *admission, bool enabled, bool gateAvailable)
{
    auto ic = sc ? &sc->sc_ic : nullptr;
    auto ifp = ic ? &ic->ic_ac.ac_if : nullptr;
    admission->enabled = enabled;
    admission->mainGateAvailable = gateAvailable;
    // This records where the runAction caller was before entering the gate.
    // The callback may execute on the caller thread in this IOWorkLoop build.
    admission->mainGateNotOnThread = run && run->callerOutsideMainWorkLoop;
    admission->driverRunning = ic && ifp &&
        ic->ic_state == IEEE80211_S_RUN &&
        (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING) &&
        (sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0;
    admission->associated = ic && ic->ic_bss != nullptr &&
        ic->ic_bss->ni_associd != 0;
    admission->portAuthorized = ic && ic->ic_bss != nullptr &&
        ic->ic_bss->ni_port_valid != 0;
    admission->scanIdle = sc &&
        (sc->sc_flags & (IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN)) == 0 &&
        owner->tahoeScanState(ic) == ITL_TAHOE_SCAN_IDLE;
    admission->commandQueueIdle = commandQueueIdle(sc);
    admission->stateQueuePaused = false;
    admission->noPendingNewstate = sc && !task_pending(&sc->newstate_task) &&
        sc->ns_nstate == ic->ic_state && sc->sc_newstate_pending == 0;
    admission->radioAvailable = sc && (sc->sc_flags & IWX_FLAG_RFKILL) == 0;
    admission->firmwareHealthy = sc &&
        (sc->sc_flags & (IWX_FLAG_HW_ERR | IWX_FLAG_SHUTDOWN)) == 0 &&
        (sc->sc_init_complete & IWX_INIT_COMPLETE) != 0;
    admission->p2pContextAbsent = sc && !sc->sc_p2p.initialized &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ABSENT &&
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT;
    admission->p2pCapabilityAvailable = p2pCapabilityAvailable(owner, sc);
    admission->contextGeneration = owner ?
        nextGeneration(owner->nativeP2pProbeGeneration_) : 0;
    admission->powerGeneration = sc ? uint32_t(sc->sc_generation) : 0;
    admission->stationGeneration = sc ? __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) : 0;

    return NativeP2PProbe::admissionBlockReason(*admission, false);
}

static NativeP2PProbe::BlockedReason validateCurrentState(
    P2PProbeRun *run, bool afterAdd)
{
    if (!run || !run->owner)
        return NativeP2PProbe::kGateActionFailed;
    ItlIwx *owner = run->owner;
    struct iwx_softc *sc = &owner->com;
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_ac.ac_if;
    NativeP2PProbe::Revalidation state{};
    state.generationMatches =
        owner->nativeP2pProbeGeneration_ == run->contextGeneration &&
        uint32_t(sc->sc_generation) == run->powerGeneration &&
        __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) ==
            run->stationGeneration;
    state.radioAvailable = (sc->sc_flags & IWX_FLAG_RFKILL) == 0;
    state.firmwareHealthy =
        (sc->sc_flags & (IWX_FLAG_HW_ERR | IWX_FLAG_SHUTDOWN)) == 0;
    state.driverRunning = ic->ic_state == IEEE80211_S_RUN &&
        (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
    state.associated = ic->ic_bss && ic->ic_bss->ni_associd != 0;
    state.portAuthorized = ic->ic_bss && ic->ic_bss->ni_port_valid != 0;
    state.scanIdle = (sc->sc_flags & (IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN)) == 0 &&
        owner->tahoeScanState(ic) == ITL_TAHOE_SCAN_IDLE;
    state.commandQueueIdle = commandQueueIdle(sc);
    state.stateQueuePaused = __atomic_load_n(
        &owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) != 0;
    state.noPendingNewstate = !task_pending(&sc->newstate_task) &&
        sc->ns_nstate == ic->ic_state && sc->sc_newstate_pending == 0;
    state.p2pContextInitialized = sc->sc_p2p.initialized != 0;
    state.p2pGenerationMatches =
        sc->sc_p2p.fw_generation == run->powerGeneration;
    state.addAcknowledged = run->addAcknowledged;
    state.p2pMacAbsent = sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ABSENT;
    state.p2pMacActive = sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE;
    state.p2pBindingAbsent =
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT;
    return NativeP2PProbe::revalidationBlockReason(state, afterAdd);
}

static int configure(void *opaque)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || !run->owner->nativeP2pCommandAllowed())
        return EBUSY;
    return run->owner->iwx_p2p_mac_context_configure(
        &run->owner->com, 1, 0, 1, run->address);
}

static int add(void *opaque)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || !run->owner->nativeP2pCommandAllowed())
        return EBUSY;
    const int result = run->owner->iwx_p2p_mac_context_add(&run->owner->com);
    run->addAcknowledged = result == 0;
    return result;
}

static int remove(void *opaque)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || !run->owner->nativeP2pCommandAllowed())
        return EBUSY;
    return run->owner->iwx_p2p_mac_context_remove(&run->owner->com);
}

static bool snapshotEqual(const NativeP2PProbe::Snapshot &a,
                          const NativeP2PProbe::Snapshot &b)
{
    return a.state == b.state && a.attempted == b.attempted &&
        a.addResult == b.addResult && a.removeResult == b.removeResult &&
        a.blocked == b.blocked &&
        a.contextGeneration == b.contextGeneration &&
        a.powerGeneration == b.powerGeneration &&
        a.stationGeneration == b.stationGeneration &&
        a.resourceMayExist == b.resourceMayExist;
}

static int readRocState(P2PProbeRun *probe, RocEventRun *event)
{
    if (!probe || !probe->owner || !event)
        return EINVAL;
    event->probe = probe;
    event->operation = kRocRead;
    IOCommandGate *gate = probe->owner->tahoeP2pCommandGate();
    if (!gate || gate->runAction(ItlIwx::tahoeP2pRocEventAction, event) !=
                     kIOReturnSuccess || !event->txSnapshotValid)
        return EBUSY;
    return 0;
}

static int reserveP2PStation(ItlIwx *owner, uint32_t generation,
                             uint8_t *stationId)
{
    if (!owner || !stationId || !owner->nativeP2pTxLock_)
        return EINVAL;
    IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        owner->nativeP2pTxLock_);
    const auto result = owner->nativeP2pStationRegistry_.reserveP2p(
        generation, stationId);
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                      interruptState);
    if (result == IntelP2PTx::Result::kSuccess)
        return 0;
    return result == IntelP2PTx::Result::kNoCapacity ? ENOSPC : EBUSY;
}

static int changeP2PStationReservation(ItlIwx *owner, uint32_t generation,
                                      uint8_t stationId, uint8_t operation)
{
    if (!owner || !owner->nativeP2pTxLock_)
        return EINVAL;
    IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        owner->nativeP2pTxLock_);
    IntelP2PTx::Result result = IntelP2PTx::Result::kInvalid;
    switch (operation) {
        case 0:
            result = owner->nativeP2pStationRegistry_.addAcknowledged(
                generation, stationId);
            break;
        case 1:
            result = owner->nativeP2pStationRegistry_.addOutcomeUnknown(
                generation, stationId);
            break;
        case 2:
            result = owner->nativeP2pStationRegistry_.removeAcknowledged(
                generation, stationId);
            break;
        case 3:
            result = owner->nativeP2pStationRegistry_.releaseKnownAbsent(
                generation, stationId);
            break;
    }
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                      interruptState);
    return result == IntelP2PTx::Result::kSuccess ? 0 : EBUSY;
}

static int publishTxTerminal(ItlIwx *owner, P2PProbeRun *probe,
                             uint32_t stage, int result)
{
    RocEventRun event{};
    event.probe = probe;
    if (readRocState(probe, &event) == 0)
        publishP2PTxDetails(owner, event.txSnapshot);
    publishP2PTxStage(owner, stage, result);
    return stage == kTxProbeQuarantined ? (result ? result : EIO) : 0;
}

static bool psfQueueProvenUnused(const P2PProbeRun *probe,
                                 const P2PTxDiagnosticSnapshot *snapshot)
{
    // A helper call is not a doorbell. Require the explicit monotonic
    // transport witness plus a current, empty, installed lease snapshot.
    return probe && probe->awdlPsfProbeEnabled && snapshot &&
        snapshot->queueLeaseActive && snapshot->txRingEmpty &&
        snapshot->ringIndicesConsistent && !snapshot->queueDoorbelled &&
        snapshot->outstandingTx == 0 && !snapshot->ticketArmed &&
        !snapshot->ticketCompleted &&
        snapshot->actionState != static_cast<uint32_t>(
            TahoeP2PActionTxState::kInFlight);
}

static int runTxProbeSession(P2PProbeRun *probe, mbuf_t *frame,
                             bool queueReady, uint32_t configuration,
                             IntelROCEvent::SessionSnapshot *sessionOut,
                             P2PTxDiagnosticSnapshot *txOut)
{
    if (!probe || !probe->owner || !frame || !sessionOut || !txOut ||
        (!*frame && !probe->awdlPsfProbeEnabled))
        return EINVAL;
    ItlIwx *owner = probe->owner;
    struct iwx_softc *sc = &owner->com;
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    if (!gate)
        return EBUSY;

    publishP2PTxStage(owner, kTxProbeSessionSubmitted, 0);
    // Keep ordinary sessions at 100 ms. A single GO-negotiation session uses
    // 900 ms only after ROC submission has validated the live social channel.
    const uint32_t durationMs = configuration ==
        IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION ? 900u : 100u;
    const uint64_t commandSubmittedUs =
        p2pProbeMonotonicNanoseconds() / 1000ULL;
    const int commandResult = owner->tahoeP2pRocSubmit(
        sc, probe->contextGeneration, configuration, durationMs,
        ItlIwx::tahoeP2pArmRoc, probe);
    RocEventRun event{};
    event.probe = probe;
    event.operation = kRocCommandReturned;
    event.commandResult = commandResult;
    if (gate->runAction(ItlIwx::tahoeP2pRocEventAction, &event) !=
        kIOReturnSuccess)
        return EBUSY;
    if (commandResult != 0)
        return commandResult;

    publishP2PTxStage(owner, kTxProbeWaitingForStart, 0);
    P2PProbeObservationWindow observationWindow(
        p2pProbeMonotonicNanoseconds(), configuration, durationMs);
    while (!observationWindow.expired(p2pProbeMonotonicNanoseconds())) {
        const int readError = readRocState(probe, &event);
        if (readError)
            return readError;
        if (event.snapshot.configuration != configuration)
            return EBUSY;
        if (probe->awdlPsfProbeEnabled && probe->psfFrameSubmitted &&
            !probe->psfResultCaptured && event.txSnapshot.ticketCompleted &&
            event.txSnapshot.actionState == static_cast<uint32_t>(
                TahoeP2PActionTxState::kIdle)) {
            probe->psfResultCaptured = true;
            probe->psfTxCompleted = true;
            probe->psfTxSucceeded =
                event.txSnapshot.frameAttemptSucceeded &&
                (event.txSnapshot.ticketStatus & 0xffu) == 1u;
            probe->psfPeerAcknowledged = event.txSnapshot.peerAcknowledged;
            probe->psfTicketStatus = event.txSnapshot.ticketStatus;
            ++probe->actionFramesCompleted;
            if (probe->psfTxSucceeded)
                ++probe->actionFramesSucceeded;
            probe->psfStatus = probe->psfTxSucceeded ?
                kPsfProbeFrameTxCompleted : kPsfProbeFrameTxFailed;
            publishPsfProbeDetails(owner, probe, kP2PFrameAwdlPsf);
            if (probe->awdlMifFollowupEnabled) {
                if (!probe->psfTxSucceeded) {
                    probe->mifCandidatePrepared = true;
                    probe->mifStatus = kMifProbeFirstPsfFailed;
                    probe->mifBlockers =
                        NativeAwdlProbe::kMifTxFirstPsfFailed;
                    probe->mifBurstStopped = true;
                    probe->mifBurstStopReason = static_cast<uint32_t>(
                        NativeAwdlProbe::MifBurstStopReason::PreviousTicketFailed);
                    publishMifProbeDetails(owner, probe);
                } else if (event.snapshot.endSeen ||
                           event.snapshot.outcomeUnknown ||
                           !event.snapshot.startSeen) {
                    probe->mifCandidatePrepared = true;
                    probe->mifStatus = kMifProbeEndedBeforeSubmit;
                    probe->mifBlockers = event.snapshot.outcomeUnknown ?
                        NativeAwdlProbe::kMifTxRocUnknown :
                        NativeAwdlProbe::kMifTxRocEnded;
                    probe->mifBurstStopped = true;
                    probe->mifBurstStopReason = static_cast<uint32_t>(
                        event.snapshot.outcomeUnknown ?
                            NativeAwdlProbe::MifBurstStopReason::RocUnknown :
                            NativeAwdlProbe::MifBurstStopReason::RocEnded);
                    publishMifProbeDetails(owner, probe);
                } else {
                    const uint64_t sampleUs =
                        p2pProbeMonotonicNanoseconds() / 1000ULL;
                    prepareMifCandidateAfterPsfCompletion(
                        probe, event.snapshot, event.txSnapshot, sampleUs,
                        frame);
                }
            }
        }
        if (probe->awdlMifFollowupEnabled && probe->mifFrameSubmitted &&
            !probe->mifResultCaptured && event.txSnapshot.ticketCompleted &&
            event.txSnapshot.actionState == static_cast<uint32_t>(
                TahoeP2PActionTxState::kIdle)) {
            probe->mifResultCaptured = true;
            probe->mifTxCompleted = true;
            probe->mifTxSucceeded =
                event.txSnapshot.frameAttemptSucceeded &&
                (event.txSnapshot.ticketStatus & 0xffu) == 1u;
            probe->mifPeerAcknowledged = event.txSnapshot.peerAcknowledged;
            probe->mifTicketStatus = event.txSnapshot.ticketStatus;
            ++probe->actionFramesCompleted;
            if (probe->mifTxSucceeded)
                ++probe->actionFramesSucceeded;
            if (probe->mifBurstCompletedFrames <
                NativeAwdlProbe::kMifBurstMaximumFrames)
                ++probe->mifBurstCompletedFrames;
            if (probe->mifTxSucceeded && probe->mifBurstSucceededFrames <
                NativeAwdlProbe::kMifBurstMaximumFrames)
                ++probe->mifBurstSucceededFrames;
            probe->mifBurstLastCompletionUs =
                p2pProbeMonotonicNanoseconds() / 1000ULL;
            probe->mifBurstLastTicketStatus =
                event.txSnapshot.ticketStatus;
            probe->mifBurstLastTicketSequenceControl =
                event.txSnapshot.ticketSequenceControl;
            probe->mifBurstLastTicketByteCount =
                event.txSnapshot.ticketByteCount;
            probe->mifBurstLastTicketFrameControl =
                event.txSnapshot.ticketFrameControl;
            probe->mifBurstLastNextSequenceNumber =
                event.txSnapshot.nextSequenceNumber;
            if (!probe->mifTxSucceeded) {
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::PreviousTicketFailed);
            }
            probe->mifStatus = probe->mifTxSucceeded ?
                kMifProbeFrameTxCompleted : kMifProbeFrameTxFailed;
            probe->mifCandidatePrepared = false;
            publishMifProbeDetails(owner, probe);
        }

        const uint64_t observedNs = p2pProbeMonotonicNanoseconds();
        const bool successfulStart = event.snapshot.commandReturned &&
            event.snapshot.commandResult == 0 && event.snapshot.startSeen &&
            event.snapshot.startStatus == 1;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
        // Data originates from the real BSD output filter, never a canned
        // packet. Reuse only a completed/idle dedicated P2P ring in this ROC.
        if(successfulStart&&!event.snapshot.endSeen&&!event.snapshot.outcomeUnknown&&
           probe->mifResultCaptured&&probe->mifTxSucceeded&&probe->nativeDataAttempts<4) {
            auto submitData=[](OSObject *,void *ctx,void *,void *,void *)->IOReturn {
                auto run=static_cast<P2PProbeRun *>(ctx);auto self=run->owner;
                const auto session=self->nativeP2pRocEvents_.snapshot();
                const auto ticket=self->nativeP2pActionTx_.completion.snapshot();
                const auto &sc=self->com;const auto ic=&sc.sc_ic;
                const NativeAwdlDataGate::State dataState{
                    self->tahoeP2pOnMainGate()&&self->nativeP2pBusy()&&
                        __atomic_load_n(&self->nativeP2pProbeOwner_,__ATOMIC_ACQUIRE)==reinterpret_cast<void *>(run->workerThread),
                    self->nativeP2pProbeGeneration_==run->contextGeneration&&uint32_t(sc.sc_generation)==run->powerGeneration&&
                        __atomic_load_n(&sc.sc_tx_rate_generation,__ATOMIC_ACQUIRE)==run->stationGeneration&&sc.sc_p2p.fw_generation==run->powerGeneration,
                    ic->ic_state==IEEE80211_S_RUN&&ic->ic_bss&&ic->ic_bss->ni_associd&&ic->ic_bss->ni_port_valid&&
                        !(sc.sc_flags&(IWX_FLAG_RFKILL|IWX_FLAG_HW_ERR|IWX_FLAG_SHUTDOWN)),
                    commandQueueIdle(&self->com)&&!(sc.sc_flags&(IWX_FLAG_SCANNING|IWX_FLAG_BGSCAN))&&
                        __atomic_load_n(&self->nativeP2pNswqPaused_,__ATOMIC_ACQUIRE)&&
                        !task_pending(&self->com.newstate_task)&&!sc.sc_newstate_pending&&sc.ns_nstate==ic->ic_state,
                    sc.sc_p2p.initialized&&run->addAcknowledged&&sc.sc_p2p.mac_state==IWX_P2P_RESOURCE_ACTIVE,
                    sc.sc_p2p.binding_state==IWX_P2P_RESOURCE_ACTIVE,
                    bool(sc.sc_p2p.phy_leased),
                    session.commandReturned&&session.commandResult==0&&session.generation==run->contextGeneration&&
                        session.configuration==sc.sc_p2p_roc.session_conf_id&&session.startSeen&&session.startStatus==1&&
                        !session.endSeen&&!session.outcomeUnknown&&sc.sc_p2p_roc.token==run->contextGeneration&&
                        sc.sc_p2p_roc.phase==IWX_P2P_ROC_SESSION_ACKED,
                    self->nativeP2pActionTx_.state==TahoeP2PActionTxState::kIdle&&ticket.completed
                };
                const uint32_t blockers=NativeAwdlDataGate::blockers(dataState);
                if(blockers){NativeAwdlBSD::gateObservation(blockers);return kIOReturnNotReady;}
                // Do not wait for the periodic timer: this radio lease is
                // shorter than one timer period. Drain real peer/RX records
                // while the matching window is still open.
                self->tahoeP2pRxDrain();
                NativeAwdlBSD::poll(true,uint32_t(self->com.sc_generation));
                IntelAwdlPeer::RuntimeEpochs epochs{run->contextGeneration,run->powerGeneration,run->stationGeneration,true};
                const auto peer=self->tahoe_awdl_peer_observer_.snapshot(epochs,p2pProbeMonotonicNanoseconds()/1000);
                uint32_t peerBlockers=0;
                if(!peer.validPeerCount)peerBlockers|=1u<<9;
                if(peer.latestPeerAgeUs>1000000)peerBlockers|=1u<<10;
                if(peer.nextAwChannel!=6&&peer.masterChannel!=6)peerBlockers|=1u<<11;
                if(peerBlockers){NativeAwdlBSD::gateObservation(peerBlockers);return kIOReturnNotReady;}
                uint64_t token=0;mbuf_t packet=NativeAwdlBSD::nextTx(self->nativeP2pActionTx_.nextSequenceNumber,&token);
                if(!packet){NativeAwdlBSD::gateObservation(1u<<12);return kIOReturnNotReady;}
                NativeAwdlBSD::gateObservation(0);
                ++run->nativeDataAttempts;
                const int result=iwx_tahoe_p2p_action_tx_submit(self,&self->com,&self->nativeP2pTxQueue_,
                    &self->nativeP2pActionTx_,run->contextGeneration,true,false,packet,token);
                // A post-doorbell unknown result retains the token until an
                // actual completion or proven firmware/DMA drain.
                if(result==0||self->nativeP2pActionTx_.state==TahoeP2PActionTxState::kQuarantined)
                    NativeAwdlBSD::submitted(token,0);
                else NativeAwdlBSD::submitted(token,result);
                return kIOReturnSuccess;
            };
            gate->runAction(submitData,probe);
        }
#endif
        // Pacing waits inside the already-announced local channel-6 window.
        // Each MIF needs a new, complete, same-epoch peer PSF received on
        // mapped IEEE channel 6; the MIF gate does not admit peers or follow
        // their advertised schedule.
        if (probe->awdlMifFollowupEnabled && probe->psfResultCaptured &&
            probe->psfTxSucceeded && !probe->mifBurstStopped &&
            !probe->mifCandidatePrepared && *frame == nullptr &&
            (!probe->mifFrameSubmitted || probe->mifResultCaptured) &&
            probe->mifBurstSubmittedFrames <
                NativeAwdlProbe::kMifPacingMaximumFrames) {
            const uint64_t pacingSampleUs =
                p2pProbeMonotonicNanoseconds() / 1000ULL;
            (void)tryPrepareMifAtPacingPoint(probe, event.snapshot,
                event.txSnapshot, pacingSampleUs, frame);
        }
        if (successfulStart &&
            !observationWindow.observeSuccessfulStart(observedNs))
            break;

        // Build one explicitly experimental PSF only from the matching,
        // successful START snapshot. It advertises just the bounded channel-6
        // dwell; clock mapping, cyclic expiry, and future presence remain
        // explicitly unproven and are never treated as native AWDL support.
        if (probe->awdlPsfProbeEnabled && successfulStart &&
            !probe->psfCandidatePrepared && !event.snapshot.endSeen &&
            !event.snapshot.outcomeUnknown) {
            probe->psfCandidatePrepared = true;
            if (!preparePsfCandidateAfterStart(probe, event.snapshot,
                    durationMs, event.txSnapshot.nextSequenceNumber,
                    commandSubmittedUs) &&
                probe->psfStatus == kPsfProbeWaitingForStart)
                probe->psfStatus = kPsfProbeStartObservedNoCandidate;
            if (probe->psfBlockers == NativeAwdlProbe::kPsfTxNoBlocker) {
                if (!queueReady) {
                    probe->psfBlockers |=
                        NativeAwdlProbe::kPsfTxTxResourcesUnavailable;
                    probe->psfStatus = kPsfProbeCandidateEncodedBlocked;
                } else {
                    *frame = makeActionFrameFromBytes(
                        probe->psfCandidate.bytes,
                        probe->psfCandidate.length);
                    if (!*frame) {
                        probe->psfBlockers |=
                            NativeAwdlProbe::kPsfTxFrameAllocationFailed;
                        probe->psfStatus = kPsfProbeCandidateRejected;
                    } else {
                        probe->psfStatus = kPsfProbeCandidateEncodedReady;
                    }
                }
            }
            publishPsfProbeDetails(owner, probe, kP2PFrameAwdlPsf);
        }

        // Submit from a short main-gate callback. The callback re-reads the
        // same START/END tracker and only prepares a descriptor and rings the
        // doorbell; all firmware commands stay on this systq worker.
        const bool psfSubmitReady = probe->awdlPsfProbeEnabled &&
            !probe->actionTxAttempted;
        const bool mifSubmitReady = probe->awdlMifFollowupEnabled &&
            probe->actionTxAttempted && probe->psfResultCaptured &&
            probe->psfTxSucceeded && probe->mifCandidatePrepared &&
            !probe->mifBurstStopped && !probe->mifTxAttempted &&
            probe->mifBurstSubmittedFrames <
                NativeAwdlProbe::kMifBurstMaximumFrames &&
            probe->mifStatus == kMifProbeCandidateEncodedReady;
        const bool legacySubmitReady = !probe->awdlPsfProbeEnabled &&
            !probe->actionTxAttempted;
        if (queueReady && *frame &&
            (psfSubmitReady || mifSubmitReady || legacySubmitReady) &&
            successfulStart && !event.snapshot.endSeen &&
            !event.snapshot.outcomeUnknown) {
            P2PTxSubmitRun submit{probe, *frame, false, false,
                                  psfSubmitReady, mifSubmitReady, EBUSY};
            const IOReturn submitResult = gate->runAction(
                tahoeP2pSubmitActionInGate, &submit);
            if (submit.frameConsumed)
                *frame = nullptr;
            if (submitResult == kIOReturnSuccess) {
                probe->txSubmitResult = submit.result;
                publishP2PTxStage(owner,
                    submit.result == 0 ? kTxProbeActionSubmitted :
                                         kTxProbeWaitingForCompletionAndEnd,
                    submit.result);
            } else if (submitResult != kIOReturnNotReady) {
                return EBUSY;
            } else if (submit.frameStale && *frame) {
                mbuf_freem(*frame);
                *frame = nullptr;
                if (psfSubmitReady) {
                    probe->psfStatus = kPsfProbeFrameBecameStale;
                    publishPsfProbeDetails(owner, probe,
                                           kP2PFrameAwdlPsf);
                }
                if (mifSubmitReady) {
                    if (probe->mifStatus != kMifProbePreflightRejected)
                        probe->mifStatus = kMifProbeFrameBecameStale;
                    probe->mifBurstStopped = true;
                    probe->mifBurstStopReason = static_cast<uint32_t>(
                        NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
                    publishMifProbeDetails(owner, probe);
                }
            }
        }

        const bool psfAwaitingSubmit =
            probe->psfStatus == kPsfProbeWaitingForStart ||
            probe->psfStatus == kPsfProbeCandidateEncodedReady ||
            probe->psfStatus == kPsfProbeStartObservedNoCandidate;
        if (probe->awdlPsfProbeEnabled && event.snapshot.endSeen &&
            !probe->actionTxAttempted && psfAwaitingSubmit) {
            probe->psfStatus = kPsfProbeEndedBeforeSubmit;
            publishPsfProbeDetails(owner, probe, kP2PFrameAwdlPsf);
        }
        if (probe->awdlMifFollowupEnabled &&
            !probe->mifTxAttempted && event.snapshot.endSeen) {
            const uint32_t terminalRocBlocker = event.snapshot.outcomeUnknown ?
                NativeAwdlProbe::kMifTxRocUnknown :
                NativeAwdlProbe::kMifTxRocEnded;
            if (probe->mifStatus == kMifProbeCandidateEncodedReady &&
                probe->psfResultCaptured) {
                probe->mifStatus = kMifProbeEndedBeforeSubmit;
                probe->mifBlockers |= terminalRocBlocker;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    event.snapshot.outcomeUnknown ?
                        NativeAwdlProbe::MifBurstStopReason::RocUnknown :
                        NativeAwdlProbe::MifBurstStopReason::RocEnded);
                publishMifProbeDetails(owner, probe);
            } else if (probe->mifStatus == kMifProbeWaitingForPeerPsf &&
                       probe->psfResultCaptured) {
                probe->mifStatus = kMifProbeEndedBeforeSubmit;
                probe->mifBlockers |= terminalRocBlocker;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    event.snapshot.outcomeUnknown ?
                        NativeAwdlProbe::MifBurstStopReason::RocUnknown :
                        NativeAwdlProbe::MifBurstStopReason::RocEnded);
                probe->mifPacingReason = static_cast<uint32_t>(
                    event.snapshot.outcomeUnknown ?
                        NativeAwdlProbe::MifPacingReason::RocUnknown :
                        NativeAwdlProbe::MifPacingReason::RocEnded);
                publishMifProbeDetails(owner, probe);
            } else if (probe->mifStatus ==
                           kMifProbeWaitingForPsfCompletion &&
                       !probe->psfFrameSubmitted) {
                probe->mifStatus = kMifProbePsfNotSubmitted;
                probe->mifBlockers |=
                    NativeAwdlProbe::kMifTxFirstPsfNotCompleted;
                probe->mifBlockers |= terminalRocBlocker;
                publishMifProbeDetails(owner, probe);
            }
        }
        if (probe->awdlMifFollowupEnabled &&
            (event.snapshot.endSeen || event.snapshot.outcomeUnknown) &&
            !probe->mifBurstStopped) {
            probe->mifBurstStopped = true;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                event.snapshot.outcomeUnknown ?
                    NativeAwdlProbe::MifBurstStopReason::RocUnknown :
                    NativeAwdlProbe::MifBurstStopReason::RocEnded);
            publishMifProbeDetails(owner, probe);
        }

        // Publish terminal pre-submit states before the safe END shortcut.
        // Otherwise a fully-cleaned ROC can leave a prepared MIF displayed as
        // ready even though the second submit gate was never admitted.
        const bool endConfirmed = event.snapshot.cleanupAllowed;
        const bool txCompleted = event.txSnapshot.ticketCompleted &&
            event.txSnapshot.actionState == static_cast<uint32_t>(
                TahoeP2PActionTxState::kIdle);
        const bool unusedPsfQueue = psfQueueProvenUnused(
            probe, &event.txSnapshot);
        if (endConfirmed && (!queueReady || txCompleted || unusedPsfQueue))
            break;
        if (event.snapshot.outcomeUnknown)
            break;

        const uint32_t sleepMs = observationWindow.nextSleepMilliseconds(
            p2pProbeMonotonicNanoseconds());
        if (sleepMs == 0)
            break;
        IOSleep(sleepMs);
    }

    const int readError = readRocState(probe, &event);
    if (readError)
        return readError;
    *sessionOut = event.snapshot;
    *txOut = event.txSnapshot;
    if (sessionOut->configuration != configuration)
        return EBUSY;
    if (!sessionOut->cleanupAllowed || sessionOut->outcomeUnknown)
        return ETIMEDOUT;
    const bool txCompleted = probe->actionTxAttempted &&
        txOut->ticketCompleted && txOut->actionState == static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle);
    if (queueReady && !txCompleted && !psfQueueProvenUnused(probe, txOut))
        return ETIMEDOUT;
    return 0;
}

static int exerciseTxProbe(P2PProbeRun *probe)
{
    ItlIwx *owner = probe ? probe->owner : nullptr;
    if (!owner || !probe->txProbeEnabled || !owner->nativeP2pCommandAllowed())
        return EBUSY;
    struct iwx_softc *sc = &owner->com;
    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    // This path transmits an 802.11 management Action MPDU; mirror Linux's
    // ROC_TYPE_MGMT_TX session configuration instead of DISCOV/listen mode.
    const uint32_t configuration =
        IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION;
    // Test032: one bounded visit to the AWDL social channel. Prepare validates
    // the live regulatory table before any PHY mutation; never rewrite STA
    // channel/address or fall back to an unvalidated channel.
    struct ieee80211_channel *channel = &sc->sc_ic.ic_channels[6];
    __atomic_store_n(&owner->nativeP2pRocChannel_, 6u, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pRocDurationMs_, 900u, __ATOMIC_RELEASE);
    publishP2PTxStage(owner, kTxProbeRocPrepare, 0);
    int error = owner->tahoeP2pRocPrepare(
        sc, channel, probe->contextGeneration,
        configuration);
    publishP2PTxSetup(owner, 1, error);
    if (error) {
        const bool safelyAbsent = !sc->sc_p2p.phy_leased &&
            sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT;
        return publishTxTerminal(owner, probe,
            safelyAbsent ? kTxProbeCleanedWithoutTx : kTxProbeQuarantined,
            error);
    }

    if (probe->awdlPsfProbeEnabled) {
        // Candidate generation waits for a confirmed START in
        // runTxProbeSession(); do not create the legacy vendor test frame.
        probe->psfStatus = kPsfProbeWaitingForStart;
        probe->psfBlockers = 0;
        publishPsfProbeDetails(owner, probe, kP2PFrameAwdlPsf);
    }
    mbuf_t frame = probe->awdlPsfProbeEnabled ? nullptr :
        makeExperimentalActionFrame(sc->sc_p2p.mac_address,
            static_cast<uint16_t>(probe->contextGeneration));
    int setupResult = (probe->awdlPsfProbeEnabled || frame) ? 0 : ENOMEM;
    publishP2PTxSetup(owner, 2, setupResult);
    const IntelP2PFirmware::Profile profile = txFirmwareProfile(owner, sc);
    const uint32_t rejection = IntelP2PFirmware::rejectionMask(
        profile, IWX_FW_CMD_VER_UNKNOWN);
    if (!probe->awdlPsfProbeEnabled)
        publishTxFirmwareProfile(owner, profile, rejection);
    const bool txPrerequisites = rejection == 0;
    if (!txPrerequisites) {
        setupResult = EOPNOTSUPP;
        publishP2PTxSetup(owner, 3, setupResult);
        if (frame) {
            mbuf_freem(frame);
            frame = nullptr;
        }
    }
    bool stationReserved = false;
    bool stationActive = false;
    bool queueReady = false;
    uint8_t stationId = 0;

    // Prepare everything local before adding firmware resources.
    if ((frame || probe->awdlPsfProbeEnabled) && txPrerequisites) {
        error = reserveP2PStation(owner, generation, &stationId);
        publishP2PTxSetup(owner, 4, error);
        if (error) {
            setupResult = error;
        } else {
            stationReserved = true;
            bool stationMayExist = false;
            error = iwx_tahoe_p2p_add_broadcast_station(
                owner, sc, &owner->nativeP2pStation_, stationId,
                &stationMayExist);
            publishP2PTxSetup(owner, 5, error);
            if (error) {
                setupResult = error;
                if (stationMayExist) {
                    (void)changeP2PStationReservation(
                        owner, generation, stationId, 1);
                    if (frame)
                        mbuf_freem(frame);
                    return publishTxTerminal(owner, probe,
                        kTxProbeQuarantined, error);
                }
                if (changeP2PStationReservation(
                        owner, generation, stationId, 3) != 0) {
                    mbuf_freem(frame);
                    return publishTxTerminal(owner, probe,
                        kTxProbeQuarantined, EBUSY);
                }
                stationReserved = false;
            } else {
                stationActive = true;
                if (changeP2PStationReservation(
                        owner, generation, stationId, 0) != 0) {
                    mbuf_freem(frame);
                    return publishTxTerminal(owner, probe,
                        kTxProbeQuarantined, EBUSY);
                }
                uint16_t queueId = 0;
                bool queueMayExist = false;
                error = iwx_tahoe_p2p_tvqm_allocate(
                    owner, sc, &owner->nativeP2pTxQueue_,
                    &owner->nativeP2pStation_, IWX_DEFAULT_QUEUE_SIZE,
                    &queueId, &queueMayExist);
                publishP2PTxSetup(owner, 6, error);
                if (error) {
                    setupResult = error;
                    if (queueMayExist) {
                        // No doorbell has been submitted. A known allocation
                        // may be withdrawn only through acknowledged firmware
                        // flush/removal; an ambiguous reply remains retained.
                        const int abortError =
                            iwx_tahoe_p2p_tvqm_abort_unsubmitted(
                                owner, sc, &owner->nativeP2pStation_,
                                &owner->nativeP2pTxQueue_, &queueMayExist);
                        if (abortError || queueMayExist ||
                            changeP2PStationReservation(
                                owner, generation, stationId, 2) != 0) {
                            if (frame)
                                mbuf_freem(frame);
                            return publishTxTerminal(owner, probe,
                                kTxProbeQuarantined,
                                abortError ? abortError : error);
                        }
                        stationActive = false;
                        stationReserved = false;
                    }
                } else {
                    queueReady = true;
                    probe->txQueueReady = true;
                }
            }
        }
    }

    publishP2PTxStage(owner, queueReady ? kTxProbeResourcesReady :
                      kTxProbeRocPrepare, setupResult);
    if (!queueReady) {
        if (frame)
            mbuf_freem(frame);
        if (stationActive) {
            bool stationMayExist = true;
            error = iwx_tahoe_p2p_remove_broadcast_station(
                owner, sc, &owner->nativeP2pStation_,
                &owner->nativeP2pTxQueue_, &stationMayExist);
            if (error || stationMayExist ||
                changeP2PStationReservation(
                    owner, generation, stationId, 2) != 0)
                return publishTxTerminal(owner, probe,
                    kTxProbeQuarantined, error ? error : EBUSY);
            stationActive = false;
            stationReserved = false;
        }
        if (stationReserved && changeP2PStationReservation(
                owner, generation, stationId, 3) != 0)
            return publishTxTerminal(owner, probe,
                kTxProbeQuarantined, EBUSY);
        const bool resourcesAbsent =
            owner->nativeP2pStation_.state == TahoeP2PResourceState::kAbsent &&
            !iwx_tahoe_p2p_tvqm_may_exist(&owner->nativeP2pTxQueue_) &&
            !probe->actionTxAttempted;
        error = owner->tahoeP2pRocAbortPrepared(
            sc, probe->contextGeneration, configuration, resourcesAbsent);
        return publishTxTerminal(owner, probe,
            error ? kTxProbeQuarantined : kTxProbeCleanedWithoutTx,
            error ? error : setupResult);
    }
    IntelROCEvent::SessionSnapshot session{};
    P2PTxDiagnosticSnapshot tx{};
    error = runTxProbeSession(probe, &frame, queueReady, configuration,
                              &session, &tx);
    if (frame)
        mbuf_freem(frame);
    if (error)
        return publishTxTerminal(owner, probe,
                                 kTxProbeQuarantined, error);

    // The legacy firmware retires queues with REMOVE_STA. A completed TX
    // ticket plus END permits flush, station removal, descriptor release,
    // and ROC cleanup. An ACK alone is never evidence of completed DMA.
    if (queueReady && psfQueueProvenUnused(probe, &tx)) {
        bool queueMayExist = true;
        error = iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            owner, sc, &owner->nativeP2pStation_, &owner->nativeP2pTxQueue_,
            session.cleanupAllowed && session.endSeen && !session.outcomeUnknown,
            !tx.ticketArmed && !tx.ticketCompleted && tx.outstandingTx == 0,
            &queueMayExist);
        if (error || queueMayExist ||
            changeP2PStationReservation(owner, generation, stationId, 2) != 0)
            return publishTxTerminal(owner, probe,
                kTxProbeQuarantined, error ? error : EBUSY);
        // No doorbell or ticket ever existed and firmware has removed the
        // queue/station. Clear only the pre-submit software isolation state.
        __atomic_store_n(reinterpret_cast<uint8_t *>(
            &owner->nativeP2pActionTx_.state),
            static_cast<uint8_t>(TahoeP2PActionTxState::kIdle),
            __ATOMIC_RELEASE);
        stationActive = false;
        stationReserved = false;
    } else if (queueReady) {
        const bool txCompleted = probe->actionTxAttempted &&
            tx.ticketCompleted && tx.actionState == static_cast<uint32_t>(
                TahoeP2PActionTxState::kIdle);
        if (!txCompleted && !psfQueueProvenUnused(probe, &tx))
            return publishTxTerminal(owner, probe,
                                     kTxProbeQuarantined, EIO);
        bool queueMayExist = true;
        error = iwx_tahoe_p2p_tvqm_remove(
            owner, sc, &owner->nativeP2pStation_,
            &owner->nativeP2pTxQueue_, &queueMayExist);
        if (error || !queueMayExist)
            return publishTxTerminal(owner, probe,
                kTxProbeQuarantined, error ? error : EIO);
        error = iwx_tahoe_p2p_tvqm_confirm_drained(
            owner, sc, &owner->nativeP2pTxQueue_, &queueMayExist);
        if (error || queueMayExist)
            return publishTxTerminal(owner, probe,
                kTxProbeQuarantined, error ? error : EIO);
    }

    if (stationActive) {
        bool stationMayExist = true;
        error = iwx_tahoe_p2p_remove_broadcast_station(
            owner, sc, &owner->nativeP2pStation_,
            &owner->nativeP2pTxQueue_, &stationMayExist);
        if (error || stationMayExist)
            return publishTxTerminal(owner, probe,
                kTxProbeQuarantined, error ? error : EIO);
        error = changeP2PStationReservation(
            owner, generation, stationId, 2);
        if (error)
            return publishTxTerminal(owner, probe,
                                     kTxProbeQuarantined, error);
        stationActive = false;
        stationReserved = false;
    }
    if (stationReserved) {
        error = changeP2PStationReservation(
            owner, generation, stationId, 3);
        if (error)
            return publishTxTerminal(owner, probe,
                                     kTxProbeQuarantined, error);
    }

    error = owner->tahoeP2pRocCleanup(
        sc, probe->contextGeneration, configuration,
        session.cleanupAllowed);
    if (error)
        return publishTxTerminal(owner, probe,
                                 kTxProbeQuarantined, error);

    const bool attemptSucceeded = queueReady && tx.ticketCompleted &&
        tx.frameAttemptSucceeded;
    bool frameFailure = false;
    if (probe->awdlPsfProbeEnabled) {
        frameFailure = !probe->psfResultCaptured || !probe->psfTxSucceeded;
        if (probe->awdlMifFollowupEnabled)
            frameFailure = frameFailure || !probe->mifFrameSubmitted ||
                !probe->mifResultCaptured || !probe->mifTxSucceeded;
    } else {
        frameFailure = !attemptSucceeded;
    }
    const int diagnosticResult = !tx.queueDoorbelled && probe->txSubmitResult ?
        probe->txSubmitResult : (queueReady && frameFailure ? EIO : setupResult);
    return publishTxTerminal(owner, probe,
        tx.queueDoorbelled ? kTxProbeComplete : kTxProbeCleanedWithoutTx,
        diagnosticResult);
}

} // namespace

IOReturn ItlIwx::tahoeP2pRocEventAction(OSObject *, void *opaque,
                                      void *, void *, void *)
{
    auto action = static_cast<RocEventRun *>(opaque);
    auto probe = action ? action->probe : nullptr;
    auto owner = probe ? probe->owner : nullptr;
    if (!owner || !owner->nativeP2pBusy() ||
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) !=
            reinterpret_cast<void *>(probe->workerThread) ||
        owner->nativeP2pProbeGeneration_ != probe->contextGeneration ||
        uint32_t(owner->com.sc_generation) != probe->powerGeneration ||
        __atomic_load_n(&owner->com.sc_tx_rate_generation, __ATOMIC_ACQUIRE) !=
            probe->stationGeneration)
        return kIOReturnNotReady;
    auto &tracker = owner->nativeP2pRocEvents_;
    if (action->operation == kRocArm) {
        if (action->firmwareGeneration != probe->powerGeneration ||
            action->macIdAndColor != IWX_FW_CMD_ID_AND_COLOR(1, 0) ||
            action->configuration !=
                owner->com.sc_p2p_roc.session_conf_id)
            return kIOReturnBadArgument;
        action->armed = tracker.begin(probe->contextGeneration, 1,
                                       action->configuration);
        if (action->armed)
            __atomic_store_n(&owner->nativeP2pRocGeneration_,
                             probe->contextGeneration, __ATOMIC_RELEASE);
    } else if (action->operation == kRocCommandReturned) {
        tracker.noteCommandResult(probe->contextGeneration, action->commandResult);
    } else if (action->operation == kRocExpire) {
        tracker.expire(probe->contextGeneration);
    }
    action->snapshot = tracker.snapshot();
    storeRocSnapshot(owner, action->snapshot);
    if (action->operation == kRocRead)
        action->txSnapshotValid = captureP2PTxSnapshot(
            owner, &action->txSnapshot);
    return kIOReturnSuccess;
}

bool ItlIwx::tahoeP2pArmRoc(void *opaque, uint32_t firmwareGeneration,
                            uint32_t macIdAndColor, uint32_t configuration)
{
    auto probe = static_cast<P2PProbeRun *>(opaque);
    if (!probe || !probe->owner || !probe->owner->nativeP2pCommandAllowed())
        return false;
    RocEventRun action{};
    action.probe = probe;
    action.operation = kRocArm;
    action.firmwareGeneration = firmwareGeneration;
    action.macIdAndColor = macIdAndColor;
    action.configuration = configuration;
    return probe->owner->getMainCommandGate()->runAction(
        tahoeP2pRocEventAction, &action) == kIOReturnSuccess && action.armed;
}

void ItlIwx::tahoeP2pTapSessionEvent(struct iwx_softc *sc,
                                   const uint8_t *bytes, size_t length)
{
    if (sc != &com || !getMainWorkLoop() || !getMainWorkLoop()->inGate())
        return;
    const auto &lease = tahoe_p2p_rx_lease_;
    const uint32_t generation = __atomic_load_n(&nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    if (!generation || !lease.active || lease.contextGeneration != generation ||
        lease.currentContextGeneration != generation ||
        lease.powerGeneration != uint32_t(sc->sc_generation) ||
        lease.stationGeneration != __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE))
        return;
    nativeP2pRocEvents_.noteNotification(
        generation, bytes, length,
        p2pProbeMonotonicNanoseconds() / 1000ULL);
}

int ItlIwx::tahoeP2pExerciseRoc(void *opaque)
{
    auto probe = static_cast<P2PProbeRun *>(opaque);
    if (probe && probe->txProbeEnabled)
        return exerciseTxProbe(probe);
    auto owner = probe ? probe->owner : nullptr;
    if (!owner || !owner->nativeP2pCommandAllowed())
        return EBUSY;
    auto sc = &owner->com;
    // This ROC probe only checks discovery/listen residency and sends no frame.
    const uint32_t configuration =
        IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV;
    __atomic_store_n(&owner->nativeP2pRocStage_, 1u, __ATOMIC_RELEASE);
    int error = owner->tahoeP2pRocPrepare(sc, sc->sc_ic.ic_bss->ni_chan,
                                         probe->contextGeneration,
                                         configuration);
    if (error) {
        const bool safelyAbsent = !sc->sc_p2p.phy_leased &&
            sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT;
        __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error), __ATOMIC_RELAXED);
        __atomic_store_n(&owner->nativeP2pRocStage_, safelyAbsent ? 5u : 6u, __ATOMIC_RELEASE);
        return safelyAbsent ? 0 : error;
    }

    __atomic_store_n(&owner->nativeP2pRocStage_, 2u, __ATOMIC_RELEASE);
    const int commandResult = owner->tahoeP2pRocSubmit(sc,
        probe->contextGeneration, configuration, 100,
        tahoeP2pArmRoc, probe);
    RocEventRun action{};
    action.probe = probe;
    action.operation = kRocCommandReturned;
    action.commandResult = commandResult;
    IOCommandGate *gate = owner->getMainCommandGate();
    error = gate->runAction(tahoeP2pRocEventAction, &action) == kIOReturnSuccess ? 0 : EBUSY;
    __atomic_store_n(&owner->nativeP2pRocStage_, 3u, __ATOMIC_RELEASE);
    // Every wait is outside the main IRQ workloop/gate. The interface's state
    // queue is leased for this bounded probe; unrelated command senders fail
    // EBUSY instead of racing the command ring or waiting under the IRQ gate.
    for (unsigned i = 0; !error && i < 160; ++i) {
        if (action.snapshot.cleanupAllowed || action.snapshot.outcomeUnknown)
            break;
        IOSleep(5);
        action.operation = kRocRead;
        if (gate->runAction(tahoeP2pRocEventAction, &action) != kIOReturnSuccess)
            error = EBUSY;
    }
    if (!error && !action.snapshot.cleanupAllowed) {
        action.operation = kRocExpire;
        gate->runAction(tahoeP2pRocEventAction, &action);
        error = commandResult ? commandResult : ETIMEDOUT;
    }
    if (!error && action.snapshot.configuration != configuration)
        error = EBUSY;
    if (error) {
        __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error), __ATOMIC_RELAXED);
        __atomic_store_n(&owner->nativeP2pRocStage_, 6u, __ATOMIC_RELEASE);
        return error; // Retain MAC/PHY/binding until a stronger reset boundary.
    }

    __atomic_store_n(&owner->nativeP2pRocStage_, 4u, __ATOMIC_RELEASE);
    error = owner->tahoeP2pRocCleanup(
        sc, probe->contextGeneration, configuration,
        action.snapshot.cleanupAllowed);
    __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error ? error :
        (action.snapshot.observedScheduledPair ? 0 : EIO)), __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocStage_, error ? 6u : 5u, __ATOMIC_RELEASE);
    return error;
}

void ItlIwx::tahoeP2pPublishRocState()
{
    const uint32_t stage = __atomic_load_n(&nativeP2pRocStage_, __ATOMIC_ACQUIRE);
    auto controller = getController();
    if (!controller || stage == nativeP2pRocPublishedStage_)
        return;
    controller->setProperty("NativeP2PRocStage", stage, 32);
#define PUBLISH_ROC_PROPERTY(name, field) \
    controller->setProperty(name, __atomic_load_n(&field, __ATOMIC_ACQUIRE), 32)
    PUBLISH_ROC_PROPERTY("NativeP2PRocResult", nativeP2pRocResult_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocGeneration", nativeP2pRocGeneration_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocConfiguration", nativeP2pRocConfiguration_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocRequestedChannel", nativeP2pRocChannel_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocRequestedDurationMs", nativeP2pRocDurationMs_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocStartSeen", nativeP2pRocStartSeen_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocEndSeen", nativeP2pRocEndSeen_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocStartStatus", nativeP2pRocStartStatus_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocEndStatus", nativeP2pRocEndStatus_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocCommandResult", nativeP2pRocCommandResult_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocObserved", nativeP2pRocObserved_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocCleanupAllowed", nativeP2pRocCleanupAllowed_);
    PUBLISH_ROC_PROPERTY("NativeP2PRocUnknown", nativeP2pRocUnknown_);
#undef PUBLISH_ROC_PROPERTY
    nativeP2pRocPublishedStage_ = stage;
}

IOReturn ItlIwx::nativeP2pArmProbe()
{
    IOEthernetController *controller = getController();
    const bool observationRequested = controller &&
        controller->getProperty("NativeP2PAwdlPsfObservationOnly") ==
            kOSBooleanTrue;
    const bool mifRequested = controller &&
        controller->getProperty("NativeP2PAwdlMifFollowup") ==
            kOSBooleanTrue;
    if (!controller ||
        controller->getProperty("NativeP2PManualTrigger") != kOSBooleanTrue ||
        controller->getProperty("NativeP2PProbe") != kOSBooleanTrue ||
        controller->getProperty("NativeP2PRocProbe") != kOSBooleanTrue ||
        controller->getProperty("NativeP2PTxProbe") != kOSBooleanTrue ||
        (mifRequested && !mifFollowupProfileEnabled(controller)) ||
        (observationRequested &&
         !psfObservationProfileEnabled(controller)))
        return kIOReturnUnsupported;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&nativeP2pManualArmRequested_, &expected,
                                     1u, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return kIOReturnBusy;
    return kIOReturnSuccess;
}

void ItlIwx::tahoeP2pInitializeTask()
{
    if (__atomic_load_n(&tahoe_p2p_probe_task_initialized_, __ATOMIC_ACQUIRE))
        return;
    static const char taskName[sizeof(tahoe_p2p_probe_task_.name)] =
        "tahoe-p2p-probe";
    task_set(&tahoe_p2p_probe_task_, tahoeP2pProbeTask, this, taskName);
    __atomic_store_n(&tahoe_p2p_probe_task_initialized_, 1u, __ATOMIC_RELEASE);
}

static bool nativeLifecycleObservationHandled(IOEthernetController *controller)
{
    if(!controller || controller->getProperty("NativeAwdlLifecycleObservationOnly")!=kOSBooleanTrue)
        return false;
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
    return (NativeAwdlLifecycle::snapshot().flags & NativeAwdlLifecycle::Attempted)!=0;
#else
    return true;
#endif
}

static bool nativeInitObservationHandled(IOEthernetController *controller)
{
    if (!controller ||
        controller->getProperty("NativeAwdlInitObservationOnly") != kOSBooleanTrue)
        return false;
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
    return (NativeAwdlInit::snapshot().flags & NativeAwdlInit::Attempted) != 0;
#else
    return true; // A mismatched signed profile cannot fall through to RF.
#endif
}

void ItlIwx::nativeP2pTick()
{
    tahoeP2pRxDrain();
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    NativeAwdlBSD::poll(com.sc_ic.ic_state==IEEE80211_S_RUN&&
        !(com.sc_flags&(IWX_FLAG_HW_ERR|IWX_FLAG_SHUTDOWN|IWX_FLAG_RFKILL)),uint32_t(com.sc_generation));
#endif

    IOEthernetController *controller = getController();
    if (controller &&
        controller->getProperty("NativeP2PManualTrigger") == kOSBooleanTrue)
        controller->setProperty("NativeP2PManualArmed",
            __atomic_load_n(&nativeP2pManualArmRequested_, __ATOMIC_ACQUIRE), 32);
    if (nativeLifecycleObservationHandled(controller) || nativeInitObservationHandled(controller)) {
        tahoeP2pPublishProbeState();
        return;
    }
    bool residentStart=false;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    residentStart=NativeAwdlLifecycle::residentPending(controller)&&
        com.sc_ic.ic_state==IEEE80211_S_RUN&&
        !(com.sc_flags&(IWX_FLAG_HW_ERR|IWX_FLAG_SHUTDOWN|IWX_FLAG_RFKILL));
#endif
    if (!residentStart && !probeEnabled(this, controller) && !txProbeEnabled(this, controller)) {
        NativeP2PProbe::Admission disabled{};
        nativeP2pProbe_.tryQueue(disabled);
        tahoeP2pPublishProbeState();
        return;
    }
    if (!__atomic_load_n(&tahoe_p2p_probe_task_initialized_, __ATOMIC_ACQUIRE)) {
        tahoeP2pPublishProbeState();
        return;
    }

    const auto snapshot = nativeP2pProbe_.snapshot();
    if (snapshot.attempted || snapshot.state == NativeP2PProbe::kComplete ||
        snapshot.state == NativeP2PProbe::kQuarantined ||
        snapshot.state == NativeP2PProbe::kResetDrained ||
        snapshot.state == NativeP2PProbe::kQueued ||
        snapshot.state == NativeP2PProbe::kAdding ||
        snapshot.state == NativeP2PProbe::kAdded ||
        snapshot.state == NativeP2PProbe::kRemoving) {
        tahoeP2pPublishProbeState();
        return;
    }

    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&nativeP2pProbeQueued_, &expected, 1u,
                                     false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE)) {
        tahoeP2pPublishProbeState();
        return;
    }
    if (!task_add(systq, &tahoe_p2p_probe_task_)) {
        recordBlocked(this, NativeP2PProbe::kProbeQueueBusy);
        __atomic_store_n(&nativeP2pProbeQueued_, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
    }
    tahoeP2pPublishProbeState();
}

bool ItlIwx::nativeP2pBusy()
{
    return __atomic_load_n(&nativeP2pProbeBusy_, __ATOMIC_ACQUIRE) != 0;
}

bool ItlIwx::nativeP2pCommandAllowed() const
{
    IOWorkLoop *workLoop = const_cast<ItlIwx *>(this)->getMainWorkLoop();
    void *owner = __atomic_load_n(&nativeP2pProbeOwner_, __ATOMIC_ACQUIRE);
    return NativeP2PProbe::commandOwnerAllowed(
        __atomic_load_n(&nativeP2pProbeBusy_, __ATOMIC_ACQUIRE) != 0, owner,
        reinterpret_cast<void *>(current_thread()),
        !workLoop || workLoop->onThread(), !workLoop || workLoop->inGate());
}

NativeP2PProbe::BlockedReason ItlIwx::tahoeP2pRevalidate(
    void *opaque, uint32_t powerGeneration, uint32_t stationGeneration)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner)
        return NativeP2PProbe::kGateActionFailed;
    if (run->powerGeneration != powerGeneration ||
        run->stationGeneration != stationGeneration)
        return NativeP2PProbe::kGenerationChanged;

    IOCommandGate *gate = run->owner->getMainCommandGate();
    IOWorkLoop *workLoop = run->owner->getMainWorkLoop();
    if (!gate || !workLoop || workLoop->onThread() || workLoop->inGate())
        return NativeP2PProbe::kMainGateUnavailable;
    IOReturn result = gate->runAction(tahoeP2pValidateAction, run);
    return result == kIOReturnSuccess ? run->blocked :
        NativeP2PProbe::kGateActionFailed;
}

int ItlIwx::tahoeP2pConfigure(void *opaque)
{
    return configure(opaque);
}

int ItlIwx::tahoeP2pAdd(void *opaque)
{
    return add(opaque);
}

int ItlIwx::tahoeP2pRemove(void *opaque)
{
    return remove(opaque);
}

bool ItlIwx::tahoeP2pPublishLease(void *opaque, bool resourceMayExist)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner)
        return false;
    run->leaseValue = resourceMayExist;
    run->leasePublished = false;
    IOCommandGate *gate = run->owner->getMainCommandGate();
    IOWorkLoop *workLoop = run->owner->getMainWorkLoop();
    if (!gate || !workLoop || workLoop->onThread() || workLoop->inGate())
        return false;
    return gate->runAction(tahoeP2pLeaseAction, run) ==
            kIOReturnSuccess && run->leasePublished;
}

IOReturn ItlIwx::tahoeP2pAdmitAction(OSObject *, void *contextArg,
                                     void *, void *, void *)
{
    auto run = static_cast<P2PProbeRun *>(contextArg);
    if (!run || !run->owner)
        return kIOReturnBadArgument;
    ItlIwx *owner = run->owner;
    struct iwx_softc *sc = &owner->com;
    if (__atomic_load_n(&owner->nativeP2pCancelRequested_, __ATOMIC_ACQUIRE)) {
        run->blocked = NativeP2PProbe::kCanceledBeforeStart;
        recordBlocked(owner, run->blocked);
        return kIOReturnSuccess;
    }
    NativeP2PProbe::Admission admission{};
    run->admitted = false;
    IOCommandGate *gate = owner->getMainCommandGate();
    IOWorkLoop *workLoop = owner->getMainWorkLoop();
    run->blocked = admissionFailure(owner, sc, run, &admission,
        probeEnabled(owner, owner->getController()) || run->txProbeEnabled,
        gate && workLoop);
    if (run->blocked != NativeP2PProbe::kNotBlocked) {
        owner->nativeP2pProbe_.tryQueue(admission, run->blocked);
        return kIOReturnSuccess;
    }

    const int pauseError = taskq_try_pause(sc->sc_nswq);
    if (pauseError != 0) {
        run->blocked = NativeP2PProbe::kStateQueueBusy;
        owner->nativeP2pProbe_.tryQueue(admission, run->blocked);
        return kIOReturnSuccess;
    }
    admission.stateQueuePaused = true;
    admission.noPendingNewstate = !task_pending(&sc->newstate_task) &&
        sc->ns_nstate == sc->sc_ic.ic_state && sc->sc_newstate_pending == 0;
    if (!admission.noPendingNewstate) {
        taskq_resume(sc->sc_nswq);
        run->blocked = NativeP2PProbe::kStateQueueBusy;
        owner->nativeP2pProbe_.tryQueue(admission, run->blocked);
        return kIOReturnSuccess;
    }

    if (run->txProbeEnabled) {
        const int registryError = initializeTxStationRegistry(owner, sc);
        if (registryError != 0) {
            taskq_resume(sc->sc_nswq);
            run->blocked = registryError == EOPNOTSUPP ?
                NativeP2PProbe::kP2pCapabilityUnavailable :
                NativeP2PProbe::kP2pContextOwned;
            owner->nativeP2pProbe_.tryQueue(admission, run->blocked);
            return kIOReturnSuccess;
        }
    }

    // Stop may have requested cancellation while the no-wait pause was being
    // acquired. The stop path and this admission callback serialize on the
    // main command gate, so this check closes that race before ownership.
    if (__atomic_load_n(&owner->nativeP2pCancelRequested_, __ATOMIC_ACQUIRE)) {
        taskq_resume(sc->sc_nswq);
        run->blocked = NativeP2PProbe::kCanceledBeforeStart;
        recordBlocked(owner, run->blocked);
        return kIOReturnSuccess;
    }

    admission.powerGeneration = uint32_t(sc->sc_generation);
    admission.stationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    admission.contextGeneration = nextGeneration(owner->nativeP2pProbeGeneration_);
    if (!owner->nativeP2pProbe_.tryQueue(admission)) {
        taskq_resume(sc->sc_nswq);
        return kIOReturnSuccess;
    }

    owner->nativeP2pProbeGeneration_ = admission.contextGeneration;
    __atomic_store_n(&owner->nativeP2pNswqPaused_, 1u, __ATOMIC_RELEASE);
    auto &lease = owner->tahoe_p2p_rx_lease_;
    lease = {};
    lease.contextGeneration = admission.contextGeneration;
    lease.currentContextGeneration = admission.contextGeneration;
    lease.powerGeneration = admission.powerGeneration;
    lease.currentPowerGeneration = admission.powerGeneration;
    lease.stationGeneration = admission.stationGeneration;
    lease.currentStationGeneration = admission.stationGeneration;
    lease.macIdAndColor = IWX_FW_CMD_ID_AND_COLOR(1, 0);
    lease.active = false;
    lease.timeEventSubmitted = false;
    lease.timeEventUidKnown = false;
    lease.timeEventUid = 0;
    deriveProbeAddress(sc->sc_ic.ic_myaddr, run->address);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    // Firmware and the resident BSD interface must own exactly the same MAC.
    NativeAwdlBSD::address(run->address);
#endif
    run->contextGeneration = admission.contextGeneration;
    run->powerGeneration = admission.powerGeneration;
    run->stationGeneration = admission.stationGeneration;
    __atomic_store_n(&owner->nativeP2pProbeOwner_,
                     reinterpret_cast<void *>(run->workerThread),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pProbeBusy_, 1u, __ATOMIC_RELEASE);
    run->admitted = true;
    return kIOReturnSuccess;
}

IOReturn ItlIwx::tahoeP2pCancelAction(OSObject *, void *contextArg,
                                      void *, void *, void *)
{
    auto owner = static_cast<ItlIwx *>(contextArg);
    if (!owner)
        return kIOReturnBadArgument;
    if (owner->nativeP2pBusy() ||
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) != nullptr ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE))
        return kIOReturnBusy;
    __atomic_store_n(&owner->nativeP2pCancelRequested_, 1u, __ATOMIC_RELEASE);
    return kIOReturnSuccess;
}

IOReturn ItlIwx::tahoeP2pValidateAction(OSObject *, void *contextArg,
                                       void *, void *, void *)
{
    auto run = static_cast<P2PProbeRun *>(contextArg);
    if (!run || !run->owner)
        return kIOReturnBadArgument;
    run->blocked = validateCurrentState(run, run->addAcknowledged);
    return kIOReturnSuccess;
}

IOReturn ItlIwx::tahoeP2pLeaseAction(OSObject *, void *contextArg,
                                     void *, void *, void *)
{
    auto run = static_cast<P2PProbeRun *>(contextArg);
    if (!run || !run->owner ||
        !__atomic_load_n(&run->owner->nativeP2pProbeBusy_, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&run->owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) !=
            reinterpret_cast<void *>(run->workerThread) ||
        run->owner->nativeP2pProbeGeneration_ != run->contextGeneration)
        return kIOReturnNotReady;

    auto &lease = run->owner->tahoe_p2p_rx_lease_;
    lease.contextGeneration = run->contextGeneration;
    lease.currentContextGeneration = run->owner->nativeP2pProbeGeneration_;
    lease.powerGeneration = run->powerGeneration;
    lease.currentPowerGeneration = uint32_t(run->owner->com.sc_generation);
    lease.stationGeneration = run->stationGeneration;
    lease.currentStationGeneration = __atomic_load_n(
        &run->owner->com.sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    lease.macIdAndColor = IWX_FW_CMD_ID_AND_COLOR(1, 0);
    lease.active = run->leaseValue;
    lease.timeEventSubmitted = false;
    lease.timeEventUidKnown = false;
    lease.timeEventUid = 0;
    run->leasePublished = true;
    return kIOReturnSuccess;
}

IOReturn ItlIwx::tahoeP2pFinishAction(OSObject *, void *contextArg,
                                      void *, void *, void *)
{
    auto run = static_cast<P2PProbeRun *>(contextArg);
    if (!run || !run->owner)
        return kIOReturnBadArgument;
    ItlIwx *owner = run->owner;
    if (run->canceled)
        owner->nativeP2pProbe_.cancelQueued();
    __atomic_store_n(&owner->nativeP2pProbeOwner_, nullptr, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pProbeBusy_, 0u, __ATOMIC_RELEASE);
    if (__atomic_exchange_n(&owner->nativeP2pNswqPaused_, 0u,
                            __ATOMIC_ACQ_REL) != 0)
        taskq_resume(owner->com.sc_nswq);
    __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
    return kIOReturnSuccess;
}

IOReturn ItlIwx::tahoeP2pResetAction(OSObject *, void *contextArg,
                                    void *, void *, void *)
{
    auto reset = static_cast<P2PProbeReset *>(contextArg);
    if (!reset || !reset->owner || !reset->softc)
        return kIOReturnBadArgument;
    ItlIwx *owner = reset->owner;
    if (owner->nativeP2pBusy() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&owner->nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) != nullptr) {
        reset->result = EBUSY;
        return kIOReturnBusy;
    }
    const struct iwx_p2p_context &p2p = reset->softc->sc_p2p;
    if (p2p.mac_state != IWX_P2P_RESOURCE_ABSENT ||
        p2p.binding_state != IWX_P2P_RESOURCE_ABSENT || p2p.phy_leased) {
        // iwx_stop_device() currently exposes no hard RX-DMA drain result.
        // Preserve any ACTIVE/UNKNOWN context and its receive lease until a
        // later lifecycle has stronger evidence; a soft-stop is not proof.
        reset->result = EBUSY;
        return kIOReturnBusy;
    }

    if (owner->nativeP2pActionTx_.state != TahoeP2PActionTxState::kIdle ||
        !owner->nativeP2pTxLock_) {
        reset->result = EBUSY;
        return kIOReturnBusy;
    }
    IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        owner->nativeP2pTxLock_);
    auto stationSnapshot = owner->nativeP2pStationRegistry_.snapshot();
    auto queueSnapshot = owner->nativeP2pTxQueue_.lifecycle.snapshot();
    const bool leasesAbsent =
        owner->nativeP2pStation_.state == TahoeP2PResourceState::kAbsent &&
        owner->nativeP2pTxQueue_.state == TahoeP2PResourceState::kAbsent &&
        owner->nativeP2pTxQueue_.pendingRing == nullptr &&
        owner->nativeP2pTxQueue_.retainedRing == nullptr &&
        !owner->nativeP2pTxQueue_.submissionBusy &&
        IntelP2PTx::noP2pResourcesRetained(stationSnapshot, queueSnapshot);
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_, interruptState);
    if (!leasesAbsent) {
        reset->result = EBUSY;
        return kIOReturnBusy;
    }

    reset->result = owner->iwx_p2p_context_reset_after_fw_reset(
        reset->softc, reset->drainedGeneration);
    if (reset->result != 0)
        return kIOReturnError;

    // Reset only the software station bitmap after the real firmware-drain
    // reset path above succeeded and every station/queue/DMA lease is absent.
    // Pending, active, unknown, or retained-ring states remain quarantined.
    interruptState = IOSimpleLockLockDisableInterrupt(owner->nativeP2pTxLock_);
    stationSnapshot = owner->nativeP2pStationRegistry_.snapshot();
    queueSnapshot = owner->nativeP2pTxQueue_.lifecycle.snapshot();
    const bool stillAbsent =
        owner->nativeP2pStation_.state == TahoeP2PResourceState::kAbsent &&
        owner->nativeP2pTxQueue_.state == TahoeP2PResourceState::kAbsent &&
        owner->nativeP2pTxQueue_.pendingRing == nullptr &&
        owner->nativeP2pTxQueue_.retainedRing == nullptr &&
        !owner->nativeP2pTxQueue_.submissionBusy &&
        owner->nativeP2pActionTx_.state == TahoeP2PActionTxState::kIdle &&
        IntelP2PTx::noP2pResourcesRetained(stationSnapshot, queueSnapshot);
    IntelP2PTx::Result registryResult = IntelP2PTx::Result::kSuccess;
    if (stillAbsent && stationSnapshot.generation != 0 &&
        stationSnapshot.generation != reset->drainedGeneration) {
        registryResult = owner->nativeP2pStationRegistry_.resetAfterFirmwareDrain(
            reset->drainedGeneration, stationSnapshot.count, true, true, true);
    }
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_, interruptState);
    if (!stillAbsent || registryResult != IntelP2PTx::Result::kSuccess) {
        reset->result = EBUSY;
        return kIOReturnBusy;
    }

    owner->nativeP2pProbe_.resetDrained(reset->drainedGeneration);
    const auto snapshot = owner->nativeP2pProbe_.snapshot();
    owner->nativeP2pProbeGeneration_ = snapshot.contextGeneration;
    auto &lease = owner->tahoe_p2p_rx_lease_;
    lease = {};
    lease.contextGeneration = snapshot.contextGeneration;
    lease.currentContextGeneration = snapshot.contextGeneration;
    lease.powerGeneration = reset->drainedGeneration;
    lease.currentPowerGeneration = reset->drainedGeneration;
    lease.stationGeneration = __atomic_load_n(
        &reset->softc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    lease.currentStationGeneration = lease.stationGeneration;
    lease.macIdAndColor = IWX_FW_CMD_ID_AND_COLOR(1, 0);
    return kIOReturnSuccess;
}

void ItlIwx::tahoeP2pProbeTask(void *opaque)
{
    auto owner = static_cast<ItlIwx *>(opaque);
    if (!owner)
        return;

    P2PProbeRun run{};
    run.owner = owner;
    run.workerThread = current_thread();
    run.txProbeEnabled = txProbeEnabled(owner, owner->getController());
    run.awdlPsfProbeEnabled = awdlPsfProbeEnabled(
        owner, owner->getController());
    run.awdlMifFollowupEnabled = mifFollowupProfileEnabled(
        owner->getController());
    run.mifStatus = run.awdlMifFollowupEnabled ?
        kMifProbeWaitingForPsfCompletion : kMifProbeNotRequested;
    IOWorkLoop *workLoop = owner->getMainWorkLoop();
    run.callerOutsideMainWorkLoop = workLoop && !workLoop->onThread() &&
        !workLoop->inGate();

    IOCommandGate *gate = owner->getMainCommandGate();
    if (!gate) {
        recordBlocked(owner, NativeP2PProbe::kMainGateUnavailable);
        __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&owner->nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
        return;
    }
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(NativeAwdlLifecycle::residentPending(owner->getController())) {
        uint8_t address[6]{};
        auto copyAddress=[](OSObject *,void *ctx,void *out,void *,void *)->IOReturn {
            auto self=static_cast<ItlIwx *>(ctx);
            if(self->nativeP2pBusy()||self->com.sc_ic.ic_state!=IEEE80211_S_RUN||
               (self->com.sc_flags&(IWX_FLAG_HW_ERR|IWX_FLAG_SHUTDOWN|IWX_FLAG_RFKILL)))return kIOReturnNotReady;
            deriveProbeAddress(self->com.sc_ic.ic_myaddr,static_cast<uint8_t *>(out));return kIOReturnSuccess;
        };
        if(run.callerOutsideMainWorkLoop&&gate->runAction(copyAddress,owner,address)==kIOReturnSuccess)
            NativeAwdlLifecycle::observeOnce(owner->getController(),address);
        __atomic_store_n(&owner->nativeP2pProbeQueued_,0u,__ATOMIC_RELEASE);
        return; // resident creation never consumes or arms the RF diagnostic
    }
#endif
    IOReturn admitResult = gate->runAction(tahoeP2pAdmitAction, &run);
    if (admitResult != kIOReturnSuccess) {
        recordBlocked(owner, NativeP2PProbe::kGateActionFailed);
        run.admitted = false;
    }

    const bool nativeLifecycleOnly = run.admitted &&
        owner->getController()->getProperty("NativeAwdlLifecycleObservationOnly") == kOSBooleanTrue;
    if (nativeLifecycleOnly) {
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
        if(run.callerOutsideMainWorkLoop)
            NativeAwdlLifecycle::observeOnce(owner->getController(),run.address);
#endif
        run.admitted=false; // Never enter firmware/ROC/TX in this profile.
    }
    const bool nativeInitOnly = run.admitted &&
        owner->getController()->getProperty("NativeAwdlInitObservationOnly") == kOSBooleanTrue;
    if (nativeInitOnly) {
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
        // The admission gate has returned. PM deregistration may wait for a
        // callback; never run native init/cleanup on the main workloop/gate.
        if (run.callerOutsideMainWorkLoop) {
            NativeAwdlInit::observeOnce(owner->getController(), run.address);
            for (unsigned int i = 0; i < 250; ++i) {
                const auto flags = NativeAwdlInit::snapshot().flags;
                if (flags & (NativeAwdlInit::FreeReturned | NativeAwdlInit::Quarantined |
                             NativeAwdlInit::AllocationFailed | NativeAwdlInit::IdentityRejected))
                    break;
                IOSleep(1);
            }
        }
#endif
        // This profile always skips configure/add/ROC/TX/remove, even after a
        // successful observation. Resume the queued software-only admission.
        run.admitted = false;
    }
    if (run.admitted) {
        owner->tahoeP2pObserveGp2(run.contextGeneration, run.powerGeneration,
                                  run.stationGeneration, 0);
        NativeP2PProbe::Operations operations{
            &run, tahoeP2pRevalidate, tahoeP2pConfigure, tahoeP2pAdd,
            tahoeP2pRemove, tahoeP2pPublishLease
        };
        if (run.txProbeEnabled ||
            owner->getController()->getProperty("NativeP2PRocProbe") ==
                kOSBooleanTrue)
            operations.exercise = tahoeP2pExerciseRoc;
        owner->nativeP2pProbe_.executeOnce(operations);
        owner->tahoeP2pObserveGp2(run.contextGeneration, run.powerGeneration,
                                  run.stationGeneration, 1);
    }

    run.canceled = nativeInitOnly || nativeLifecycleOnly;
    IOReturn finishResult = gate->runAction(tahoeP2pFinishAction, &run);
    if (finishResult != kIOReturnSuccess) {
        // The task has stopped issuing commands. Release an otherwise stranded
        // state-queue pause even if the command gate itself stopped responding.
        __atomic_store_n(&owner->nativeP2pProbeOwner_, nullptr, __ATOMIC_RELEASE);
        __atomic_store_n(&owner->nativeP2pProbeBusy_, 0u, __ATOMIC_RELEASE);
        if (__atomic_exchange_n(&owner->nativeP2pNswqPaused_, 0u,
                                __ATOMIC_ACQ_REL) != 0)
            taskq_resume(owner->com.sc_nswq);
        __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&owner->nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
    }
}

int ItlIwx::tahoeP2pStopBeforeReset(struct iwx_softc *sc)
{
    if (sc != &com)
        return EINVAL;
    // Any P2P MAC/binding/PHY/station/queue lease may still be referenced by
    // firmware. A soft stop does not prove all associated DMA has drained.
    if (nativeP2pResourcesRetained())
        return EBUSY;
    if (!nativeP2pBusy() &&
        __atomic_load_n(&nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) == 0)
        return 0;
    if (nativeP2pBusy() ||
        __atomic_load_n(&nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) != nullptr ||
        __atomic_load_n(&nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) != 0 ||
        !__atomic_load_n(&tahoe_p2p_probe_task_initialized_, __ATOMIC_ACQUIRE))
        return EBUSY;

    __atomic_store_n(&nativeP2pCancelRequested_, 1u, __ATOMIC_RELEASE);
    IOCommandGate *gate = getMainCommandGate();
    if (!gate)
        return EIO;
    IOWorkLoop *workLoop = getMainWorkLoop();
    IOReturn cancelResult = workLoop && workLoop->inGate() ?
        tahoeP2pCancelAction(this, this, nullptr, nullptr, nullptr) :
        gate->runAction(tahoeP2pCancelAction, this);
    if (cancelResult != kIOReturnSuccess)
        return EBUSY;
    if (!task_del(systq, &tahoe_p2p_probe_task_)) {
        if (!nativeP2pBusy() &&
            __atomic_load_n(&nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) == 0) {
            // The systq worker may have consumed the cancellation and finished
            // between the initial state check and task_del().
            __atomic_store_n(&nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
            return 0;
        }
        return EBUSY; // A popped worker will observe the cancellation token.
    }

    P2PProbeRun canceled{};
    canceled.owner = this;
    canceled.canceled = true;
    workLoop = getMainWorkLoop();
    IOReturn finishResult = workLoop && workLoop->inGate() ?
        tahoeP2pFinishAction(this, &canceled, nullptr, nullptr, nullptr) :
        gate->runAction(tahoeP2pFinishAction, &canceled);
    if (finishResult == kIOReturnSuccess)
        return 0;
    return EIO;
}

void ItlIwx::tahoeP2pResetDrained(struct iwx_softc *sc,
                                 uint32_t drainedGeneration)
{
    if (sc != &com)
        return;
    P2PProbeReset reset{this, sc, drainedGeneration, EIO};
    IOCommandGate *gate = getMainCommandGate();
    if (!gate)
        return;
    IOWorkLoop *workLoop = getMainWorkLoop();
    if (workLoop && workLoop->inGate())
        tahoeP2pResetAction(this, &reset, nullptr, nullptr, nullptr);
    else
        gate->runAction(tahoeP2pResetAction, &reset);
}

void ItlIwx::tahoeP2pPublishProbeState()
{
    tahoeP2pPublishRocState();
    IOEthernetController *controller = getController();
    if (!controller)
        return;

    // Pre-arm events must remain visible before the completion diagnostics
    // have a ticket. Publish only bounded numeric fields, never frame data.
    const auto &pre = nativeP2pActionTx_.preArmDiagnostics;
    const auto &submit = nativeP2pActionTx_.submitDiagnostics;
    const auto &drain = nativeP2pActionTx_.drainDiagnostics;
    const struct { const char *name; const uint32_t *value; } fields[] = {
        {"NativeP2PTxPreArmEventCount", &pre.eventCount},
        {"NativeP2PTxPreArmLastSource", &pre.lastSource},
        {"NativeP2PTxPreArmLastQueueId", &pre.lastQueueId},
        {"NativeP2PTxPreArmLastRaTid", &pre.lastRaTid},
        {"NativeP2PTxPreArmLastLeaseState", &pre.lastLeaseState},
        {"NativeP2PTxPreArmLastActionState", &pre.lastActionState},
        {"NativeP2PTxPreArmLastTicketFlags", &pre.lastTicketFlags},
        {"NativeP2PTxSubmitAttemptCount", &submit.attemptCount},
        {"NativeP2PTxSubmitLastStage", &submit.lastStage},
        {"NativeP2PTxDrainEventCount", &drain.eventCount},
        {"NativeP2PTxDrainLastNewGeneration", &drain.lastNewGeneration},
        {"NativeP2PTxDrainLastContextGeneration", &drain.lastContextGeneration},
        {"NativeP2PTxDrainLastTicketGeneration", &drain.lastTicketGeneration},
        {"NativeP2PTxDrainLastTicketFlags", &drain.lastTicketFlags},
        {"NativeP2PTxDrainLastHardStop", &drain.lastHardStop},
        {"NativeP2PTxDrainLastActionState", &drain.lastActionState}
    };
    for (const auto &field : fields)
        controller->setProperty(field.name,
            __atomic_load_n(field.value, __ATOMIC_ACQUIRE), 32);
    controller->setProperty("NativeP2PTxSubmitLastResult",
        static_cast<uint32_t>(__atomic_load_n(
            &submit.lastResult, __ATOMIC_ACQUIRE)), 32);

    controller->setProperty("NativeP2PTxDrainLastResult",
        static_cast<uint32_t>(__atomic_load_n(
            &drain.lastResult, __ATOMIC_ACQUIRE)), 32);

    TahoeP2PTxRxDiagnostics &txRx = nativeP2pActionTx_.rxDiagnostics;
    if (__atomic_exchange_n(&txRx.dirty, 0u, __ATOMIC_ACQ_REL)) {
        const uint64_t rawPacket = __atomic_load_n(
            &txRx.lastRawPacket, __ATOMIC_ACQUIRE);
        const uint64_t targetRawPacket = __atomic_load_n(
            &txRx.lastTargetRawPacket, __ATOMIC_ACQUIRE);
        const bool hasRawPacket = rawPacket != ~uint64_t(0);
        const bool hasTargetRawPacket = targetRawPacket != ~uint64_t(0);
        const uint32_t rawHeader = static_cast<uint32_t>(rawPacket >> 32);
        const uint32_t targetRawHeader =
            static_cast<uint32_t>(targetRawPacket >> 32);
        const uint32_t rawGroup = hasRawPacket ? rawHeader >> 24 : 0xffffffffu;
        const uint32_t rawOpcode = hasRawPacket ?
            (rawHeader >> 16) & 0xff : 0xffffffffu;
        const uint32_t targetRawGroup = hasTargetRawPacket ?
            targetRawHeader >> 24 : 0xffffffffu;
        const uint32_t targetRawOpcode = hasTargetRawPacket ?
            (targetRawHeader >> 16) & 0xff : 0xffffffffu;
        controller->setProperty("NativeP2PTxRxArmed",
            __atomic_load_n(&txRx.armed, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxTargetQueue",
            __atomic_load_n(&txRx.targetQueue, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxRawTxCmdCount",
            __atomic_load_n(&txRx.rawTxCmdCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxTargetHeaderQueueMatchCount",
            __atomic_load_n(&txRx.rawTargetHeaderCount, __ATOMIC_ACQUIRE), 32);
        // A raw-header queue match is only a clue; it does not prove TX_RSP completion.
        controller->setProperty("NativeP2PTxRxTargetHeaderMatchIsCompletionProof",
                                uint32_t(0), 32);
        controller->setProperty("NativeP2PTxRxTargetRawLastGroup",
            targetRawGroup, 32);
        controller->setProperty("NativeP2PTxRxTargetRawLastCode",
            hasTargetRawPacket ? ((targetRawGroup << 8) | targetRawOpcode) :
                                 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxTargetRawLastHeaderQueue",
            hasTargetRawPacket ? (targetRawHeader >> 8) & 0xff :
                                 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxTargetRawLastIndex",
            hasTargetRawPacket ? targetRawHeader & 0xff : 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxTargetRawLastPayloadLength",
            hasTargetRawPacket ? static_cast<uint32_t>(targetRawPacket) :
                                 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxRawLastGroup", rawGroup, 32);
        controller->setProperty("NativeP2PTxRxRawLastCode",
            hasRawPacket ? ((rawGroup << 8) | rawOpcode) : 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxRawLastHeaderQueue",
            hasRawPacket ? (rawHeader >> 8) & 0xff : 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxRawLastIndex",
            hasRawPacket ? rawHeader & 0xff : 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxRawLastPayloadLength",
            hasRawPacket ? static_cast<uint32_t>(rawPacket) : 0xffffffffu, 32);
        controller->setProperty("NativeP2PTxRxResponseQueueMatchCount",
            __atomic_load_n(&txRx.responseQueueMatchCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxForeignQueueCount",
            __atomic_load_n(&txRx.foreignQueueCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxShortResponseCount",
            __atomic_load_n(&txRx.shortResponseCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxOutOfRangeQueueCount",
            __atomic_load_n(&txRx.outOfRangeQueueCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxHandlerEntryCount",
            __atomic_load_n(&txRx.handlerEntryCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxHandlerQueueMatchCount",
            __atomic_load_n(&txRx.handlerQueueMatchCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxHandlerForeignCount",
            __atomic_load_n(&txRx.handlerForeignCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseQueue",
            __atomic_load_n(&txRx.lastResponseQueue, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxResponseFieldsValidMask",
            __atomic_load_n(&txRx.lastResponseFieldsValidMask,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseFrameCount",
            __atomic_load_n(&txRx.lastResponseFrameCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseStatus",
            __atomic_load_n(&txRx.lastResponseStatus, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseSequenceControl",
            __atomic_load_n(&txRx.lastResponseSequenceControl,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseByteCount",
            __atomic_load_n(&txRx.lastResponseByteCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseFrameControl",
            __atomic_load_n(&txRx.lastResponseFrameControl,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseRaTid",
            __atomic_load_n(&txRx.lastResponseRaTid, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseScdSsn",
            __atomic_load_n(&txRx.lastResponseScdSsn, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseHeaderIndex",
            __atomic_load_n(&txRx.lastResponseHeaderIndex,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty(
            "NativeP2PTxRxLastResponseHeaderIndexMatchesTicket",
            __atomic_load_n(&txRx.lastResponseHeaderIndexMatchesTicket,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseMismatchMask",
            __atomic_load_n(&txRx.lastResponseMismatchMask,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty(
            "NativeP2PTxRxLastResponseExpectedSequenceControl",
            __atomic_load_n(&txRx.lastResponseExpectedSequenceControl,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastResponseExpectedByteCount",
            __atomic_load_n(&txRx.lastResponseExpectedByteCount,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty(
            "NativeP2PTxRxLastResponseExpectedFrameControl",
            __atomic_load_n(&txRx.lastResponseExpectedFrameControl,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty(
            "NativeP2PTxRxLastResponseExpectedDescriptorIndex",
            __atomic_load_n(&txRx.lastResponseExpectedDescriptorIndex,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty(
            "NativeP2PTxRxLastResponseExpectedNextIndex",
            __atomic_load_n(&txRx.lastResponseExpectedNextIndex,
                            __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxRejectCount",
            __atomic_load_n(&txRx.rejectCount, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastRejectReason",
            __atomic_load_n(&txRx.lastRejectReason, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxLastCompletionResult",
            __atomic_load_n(&txRx.lastCompletionResult, __ATOMIC_ACQUIRE), 32);
        controller->setProperty("NativeP2PTxRxCompletionCount",
            __atomic_load_n(&txRx.completionCount, __ATOMIC_ACQUIRE), 32);
    }

    const auto snapshot = nativeP2pProbe_.snapshot();
    if (nativeP2pProbePublishedOnce_ &&
        snapshotEqual(snapshot, nativeP2pProbePublished_))
        return;

    controller->setProperty("NativeP2PProbeState", snapshot.state, 32);
    controller->setProperty("NativeP2PProbeAttempted", snapshot.attempted, 32);
    controller->setProperty("NativeP2PProbeAddResult",
                            uint32_t(snapshot.addResult), 32);
    controller->setProperty("NativeP2PProbeRemoveResult",
                            uint32_t(snapshot.removeResult), 32);
    controller->setProperty("NativeP2PProbeBlocked", snapshot.blocked, 32);
    controller->setProperty("NativeP2PProbeContextGeneration",
                            snapshot.contextGeneration, 32);
    controller->setProperty("NativeP2PProbePowerGeneration",
                            snapshot.powerGeneration, 32);
    controller->setProperty("NativeP2PProbeStationGeneration",
                            snapshot.stationGeneration, 32);
    controller->setProperty("NativeP2PProbeResourceMayExist",
                            snapshot.resourceMayExist, 32);
    nativeP2pProbePublished_ = snapshot;
    nativeP2pProbePublishedOnce_ = true;
}

#endif // AIRPORT_TAHOE
