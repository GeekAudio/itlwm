// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwx.hpp"

#ifdef AIRPORT_TAHOE

#include "../../native/p2p_tx_firmware.hpp"
#include "../../native/p2p_scoped_run_storage.hpp"
#include "../../native/awdl_action_frame.hpp"
#include "../../native/awdl_mif_tx_gate.hpp"
#include "../../native/awdl_mif_burst.hpp"
#include "../../native/awdl_mif_pacing.hpp"
#include "../../native/awdl_psf_tx_gate.hpp"
#include "../../native/p2p_rx149_observation.hpp"
#include "../../native/rx_preowner_wire.hpp"
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
#include "../../native/awdl_native_lifecycle_25G332.hpp"
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../../native/awdl_native_bsd_data_25G332.hpp"
#include "../../native/awdl_data_roc_gate.hpp"
#include "../../native/awdl_data_tx_publish_gate.hpp"
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
#if !defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
#error The discovery experiment requires the signed TX-evidence build profile.
#endif
#include "../../native/awdl_discovery_phase_experiment.hpp"
#include "../../native/awdl_discovery_admitted_binding.hpp"
#include "../../native/awdl_mif_current_phase_test066.hpp"
#include "../../native/awdl_mif_current_aw_fallback.hpp"
#include "../../native/awdl_mif_discovery_hold_test068.hpp"
#include "../../native/awdl_mif_current_admission_test069.hpp"
#include "../../native/awdl_mif_bootstrap_test070.hpp"
#include "../../native/awdl_bootstrap_pair_transition.hpp"
#endif
#endif
#endif
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
#include "../../native/awdl_native_init_probe_25G332.hpp"
#endif
#include <kern/clock.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSymbol.h>

namespace {

static uint32_t tahoeP2pProbeReadLe32(const uint8_t *bytes)
{
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
        (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}

static_assert(static_cast<uint8_t>(IntelP2PFirmware::DeviceFamily::k22000) ==
              IWX_DEVICE_FAMILY_22000, "22000 transport family changed");
static_assert(static_cast<uint8_t>(IntelP2PFirmware::DeviceFamily::kAX210) ==
              IWX_DEVICE_FAMILY_AX210, "AX210 transport family changed");

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
struct CurrentAwPlanRecord {
    NativeAwdlMifCurrentAw::Input input;
    NativeAwdlMifCurrentAw::Candidate candidate;
    uint32_t status;
    uint32_t rejectReason;
    bool recorded;
};

struct CurrentAwTraceRecord {
    CurrentAwPlanRecord initial;
    CurrentAwPlanRecord final;
    uint64_t qmToken;
    uint64_t qmGeneration;
    uint64_t rocGeneration;
    uint64_t peerIncarnation;
    uint64_t psfRevision;
    uint64_t mifRevision;
    uint32_t quietBlockerMask;
    bool fallbackEnabled;
    bool inputValid;
    bool identityCaptured;
    bool identityValid;
    bool finalCompareValid;
    bool finalCompareMatch;
    bool rxProducerClosed;
    bool rxDrainComplete;
    bool published;
};

struct CurrentAwAttemptPlan {
    uint64_t plannerNowUs;
    uint64_t earliestSubmitUs;
    uint64_t latestSubmitUs;
    uint64_t qmToken;
    uint64_t qmGeneration;
    uint32_t status;
    bool recorded;
    bool candidateValid;
    bool fallbackUsed;
};

struct CurrentAwAttemptObservation {
    CurrentAwAttemptPlan initial;
    CurrentAwAttemptPlan final;
    uint64_t qmToken;
    uint64_t qmGeneration;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
    uint32_t plannerCalls;
    bool plannerEpochsStable;
    bool fallbackEnabled;
    bool captured;
    bool published;
};

// OSData wire payload: schema-v1, fixed-size, address-free planner evidence.
// EvidenceClass=1 means attempt-only; peer receipt and RF transmit proof stay 0.
struct __attribute__((packed)) CurrentAwAttemptOnlyPayload {
    uint32_t magic; // little-endian bytes "CAWA"
    uint16_t schema;
    uint8_t evidenceClass;
    uint8_t complete;
    uint8_t peerReceiptProven;
    uint8_t radioTransmitProven;
    uint8_t fallbackEnabled;
    uint8_t initialPresent;
    uint8_t finalPresent;
    uint8_t initialCandidateValid;
    uint8_t finalCandidateValid;
    uint8_t initialFallbackUsed;
    uint8_t finalFallbackUsed;
    uint8_t consistencyFlags; // bit 0: same initial/final QM identity; bit 1: planner epochs stable.
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
    uint64_t qmToken;
    uint64_t qmGeneration;
    uint64_t initialPlannerNowUs;
    uint64_t finalPlannerNowUs;
    uint32_t plannerCalls;
    uint32_t initialStatus;
    uint32_t finalStatus;
    uint64_t initialEarliestSubmitUs;
    uint64_t initialLatestSubmitUs;
    uint64_t finalEarliestSubmitUs;
    uint64_t finalLatestSubmitUs;
};
static_assert(sizeof(CurrentAwAttemptOnlyPayload) == 110,
              "current-AW attempt payload ABI changed");

enum CurrentAwQuietBlocker : uint32_t {
    kCurrentAwQuietBlockerRxProducerOpen = 1u << 0,
    kCurrentAwQuietBlockerRxDrainIncomplete = 1u << 1,
    kCurrentAwQuietBlockerResourcesRetained = 1u << 2,
    kCurrentAwQuietBlockerProbeBusy = 1u << 3,
    kCurrentAwQuietBlockerNswqPaused = 1u << 4,
    kCurrentAwQuietBlockerProbeQueued = 1u << 5,
    kCurrentAwQuietBlockerOwnerPresent = 1u << 6,
};
#endif

struct P2PProbeTicketIdentity {
    uint32_t queueGeneration;
    uint32_t actionGeneration;
    uint32_t queueId;
    uint32_t descriptorIndex;
    uint32_t rocToken;
    uint32_t sequenceControl;
    uint32_t frameControl;
    uint32_t byteCount;
    uint16_t nextSequenceNumber;
    bool valid;
};

struct P2PMifCompletionClassification {
    bool txSucceeded;
    bool grantsOwnFirst;
};

struct P2PProbeRun {
    static void *operator new(size_t size) noexcept { return IOMalloc(size); }
    static void operator delete(void *memory) noexcept {
        if (memory)
            IOFree(memory, sizeof(P2PProbeRun));
    }
    ItlIwx *owner;
    thread_t workerThread;
    bool callerOutsideMainWorkLoop;
    bool admitted;
    bool canceled;
    bool leaseValue;
    bool leasePublished;
    bool addAcknowledged;
    bool rx149ObservationOnly;
    bool txProbeEnabled;
    uint32_t nativeDataAttempts;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    bool discoveryConsumed;
    bool discoveryDoorbelled;
    bool discoveryCandidateLocked;
    bool discoveryWindowClosed;
    bool discoveryBindingLocked;
    bool discoveryModeSelected;
    bool discoveryRuntimeMifRequirementSelected;
    bool discoveryHistoryCompatible;
    NativeAwdlDiscoveryBinding::Mode discoveryMode;
    bool discoveryRequiresRuntimeMifBinding;
    bool discoveryRuntimeMifBound;
    uint8_t discoveryPeerSlot;
    uint16_t discoveryRxChannelIndex;
    uint32_t discoveryStatus;
    uint32_t discoveryPhaseStatus;
    uint32_t discoveryChecks;
    uint32_t discoveryPublishVersion;
    uint32_t discoveryLastPublishedStatus;
    uint32_t discoveryLastPublishedPrerequisiteBlockers;
    uint32_t discoveryLastPublishedBindingFailureReason;
    uint64_t discoveryPacketToken;
    uint64_t discoveryPsfObservedUs;
    uint64_t discoveryPeerIncarnation;
    uint64_t discoveryPsfRevision;
    uint64_t discoveryMifRevision;
    uint32_t discoveryFormalObserverPeerCount;
    uint32_t discoveryBindingFailureReason;
    uint32_t discoveryPrerequisiteBlockers;
    uint32_t discoveryMifTimingStatus;
    uint64_t discoveryOwnFirstMifCompletionUs;
    CurrentAwTraceRecord currentAwTrace;
    CurrentAwAttemptObservation currentAwAttempt;
    bool mifBootstrapSelected;
    bool mifBootstrapCandidatePrepared;
    bool mifBootstrapSubmitted;
    bool mifBootstrapSucceeded;
    bool mifBootstrapPairClaimed;
    bool mifBootstrapPairMifAttempted;
    bool mifBootstrapPairMifCompleted;
    bool mifBootstrapPairMifSucceeded;
    bool mifBootstrapPairDiagnosticsDirty;
    uint32_t mifBootstrapStatus;
    uint32_t mifBootstrapBlockers;
    uint32_t mifBootstrapChecks;
    uint32_t mifBootstrapPairChecks;
    uint32_t mifBootstrapPairStatus;
    uint64_t mifBootstrapPairBlockers;
    uint64_t mifBootstrapCompletedUs;
    uint64_t mifBootstrapPairPeerIncarnation;
    uint64_t mifBootstrapPairPsfRevision;
    uint64_t mifBootstrapPairMifRevision;
    uint64_t mifBootstrapPairPsfRxUs;
    uint64_t mifBootstrapPairMifRxUs;
    uint8_t mifBootstrapPairSlot;
    P2PProbeTicketIdentity mifBootstrapTicketIdentity;
    P2PProbeTicketIdentity mifBootstrapPairTicketIdentity;
    Test070MifBootstrap::Binding mifBootstrapBinding;
    NativeAwdlDiscoveryBinding::OneShot discoveryBinding;
    uint64_t discoverySubmitCallStartUs;
    uint64_t discoverySubmitCallEndUs;
    uint64_t discoveryCompletedBaseline;
    uint64_t discoverySucceededBaseline;
    int discoverySubmitResult;
    NativeAwdlDiscoveryPhase::EstimatedTarget discoveryTarget;
    NativeAwdlMifCurrentAw::Candidate discoveryMifTarget;
    NativeAwdlDiscoveryPhase::PsfWitness discoveryPsfWitness;
    NativeAwdlBSD::DiscoveryTxSnapshot discoveryHead;
#endif
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
    bool nativeAddressCandidateVerified;
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
    // Keep the driver's software power generation and firmware generation in
    // separate fields. They are distinct epochs even when a given boot has
    // assigned them the same numeric value.
    uint32_t scGeneration;
    uint32_t p2pFirmwareGeneration;
    uint32_t prepareTraceSerialBefore;
    uint32_t prepareTraceSerialExpected;
    bool prepareTraceBaselineValid;
    bool sessionSubmitReached;
    uint8_t address[6];
    NativeP2PProbe::BlockedReason blocked;
};

struct P2PExerciseRecoveryAction {
    P2PProbeRun *run;
    int32_t exerciseErrno;
    NativeP2PProbe::ExerciseRecoveryProof *proof;
    bool snapshotRead;
};

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
enum NativeIdentityFailure : uint32_t {
    kNativeIdentityVerified = 0,
    kNativeIdentityMissingContext = 1,
    kNativeIdentityGenerationMismatch = 2,
    kNativeIdentityP2pInactive = 3,
    kNativeIdentityBsdAddressUnavailable = 4,
    kNativeIdentityRunAddressMismatch = 5,
    kNativeIdentityP2pAddressMismatch = 6,
    kNativeIdentityCandidateAddressMismatch = 7,
    kNativeIdentityAdvertisementMissing = 8,
    kNativeIdentityAwaitingP2pAddress = 9,
    kNativeIdentityNotChecked = 10
};

static bool nativeResidentAddressProfileEnabled(ItlIwx *owner);
static void publishNativeIdentityStatus(ItlIwx *owner, bool verified,
                                        uint32_t failure);
static uint32_t verifyNativeIdentity(
    ItlIwx *owner, uint32_t contextGeneration, uint32_t powerGeneration,
    uint32_t stationGeneration, const uint8_t runAddress[6],
    const uint8_t candidateAddress[6], uint8_t liveAddress[6]);
#endif

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
    uint32_t queueGeneration;
    uint32_t queueState;
    uint32_t outstandingTx;
    uint32_t actionState;
    uint32_t ticketStatus;
    uint32_t ticketByteCount;
    uint32_t ticketSequenceControl;
    uint32_t ticketFrameControl;
    uint32_t actionGeneration;
    uint32_t actionQueueId;
    uint32_t actionDescriptorIndex;
    uint32_t actionRocToken;
    uint32_t actionSequenceControl;
    uint32_t actionFrameControl;
    uint32_t actionByteCount;
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

enum RocEventOperation {
    kRocArm,
    kRocCommandReturned,
    kRocRead,
    kRocExpire,
    kRocCloseRx149
};
struct RocEventRun {
    P2PProbeRun *probe;
    RocEventOperation operation;
    uint32_t firmwareGeneration;
    uint32_t macIdAndColor;
    uint32_t configuration;
    int commandResult;
    bool armed;
    bool consumeRxAfterRead;
    IntelROCEvent::SessionSnapshot snapshot;
    P2PTxDiagnosticSnapshot txSnapshot;
    bool txSnapshotValid;
    bool rxDrainComplete;
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    NativeP2PRx149DataInput::Lease rx149DataLease{};
#endif
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

static void reconcileP2PTxSubmitFrame(mbuf_t *workerFrame,
                                      P2PTxSubmitRun *submit)
{
    if (!workerFrame || !submit)
        return;
    if (submit->frameConsumed) {
        *workerFrame = nullptr;
        submit->frame = nullptr;
        return;
    }

    // The gate may replace the worker's frame before a later preflight fails.
    // Return the callback's current owner first, then discard that exact frame
    // when stale; never free the worker's old by-value copy a second time.
    *workerFrame = submit->frame;
    if (submit->frameStale && *workerFrame) {
        mbuf_freem(*workerFrame);
        *workerFrame = nullptr;
        submit->frame = nullptr;
    }
}

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

static uint32_t manualProbeArmMode(ItlIwx *owner)
{
    return owner ? __atomic_load_n(&owner->nativeP2pManualArmRequested_,
                                    __ATOMIC_ACQUIRE) : 0u;
}

static bool rx149ArmModeSelected(ItlIwx *owner)
{
    return NativeP2PRx149Observation::isRx149ArmMode(
        manualProbeArmMode(owner));
}

static bool rx149ObservationOnlyRequested(IOEthernetController *controller)
{
    return controller && controller->getProperty(
        "NativeP2PRx149ObservationOnly") == kOSBooleanTrue;
}

static NativeP2PRx149Observation::ProfileInput rx149ProfileInput(
    ItlIwx *owner, IOEthernetController *controller)
{
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    const bool compiled = true;
#else
    const bool compiled = false;
#endif
    const bool armed = rx149ArmModeSelected(owner);
    return {
        compiled,
        rx149ObservationOnlyRequested(controller),
        controller && controller->getProperty("NativeP2PManualTrigger") ==
            kOSBooleanTrue,
        controller && controller->getProperty("NativeP2PProbe") ==
            kOSBooleanTrue,
        armed,
        controller && controller->getProperty("NativeP2PRocProbe") ==
            kOSBooleanTrue,
        controller && controller->getProperty("NativeP2PTxProbe") ==
            kOSBooleanTrue,
        controller && controller->getProperty(
            "NativeP2PAwdlPsfObservationOnly") == kOSBooleanTrue,
        controller && controller->getProperty(
            "NativeP2PAwdlMifFollowup") == kOSBooleanTrue,
        controller && controller->getProperty(
            "NativeAwdlDiscoveryExperimentEnabled") == kOSBooleanTrue,
        controller && controller->getProperty(
            "NativeAwdlDiscoveryMifCurrentSlotEnabled") == kOSBooleanTrue,
        controller && controller->getProperty(
            "NativeAwdlDiscoveryCurrentAwFallbackEnabled") == kOSBooleanTrue
    };
}

static NativeP2PRx149Observation::ProfileStatus rx149ProfileStatus(
    ItlIwx *owner, IOEthernetController *controller)
{
    return NativeP2PRx149Observation::evaluateProfile(
        rx149ProfileInput(owner, controller));
}

static void publishRx149DataInputAvailability(
    IOEthernetController *controller, bool profileEnabled)
{
    if (!controller)
        return;
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    const bool available = profileEnabled && !NativeAwdlBSD::rx149DataInputBlocked() &&
        controller->getProperty("NativeP2PRx149DataInputExperiment") == kOSBooleanTrue;
#else
    const bool available = false;
    (void)profileEnabled;
#endif
    controller->setProperty("NativeP2PRx149DataInputProfileEnabled",
                            available ? 1u : 0u, 32);
}

static void publishRx149ProfileAvailabilityOnce(
    ItlIwx *owner, IOEthernetController *controller)
{
    if (!owner || !rx149ObservationOnlyRequested(controller))
        return;
    const auto status = rx149ProfileStatus(owner, controller);
    const bool enabled = status ==
            NativeP2PRx149Observation::ProfileStatus::kReadyToArm ||
        status == NativeP2PRx149Observation::ProfileStatus::kSelected;
    const bool selected = rx149ArmModeSelected(owner) &&
        status == NativeP2PRx149Observation::ProfileStatus::kSelected;
    controller->setProperty("NativeP2PRx149ProfileEnabled",
                             enabled ? 1u : 0u, 32);
    controller->setProperty("NativeP2PRx149Selected",
                             selected ? 1u : 0u, 32);
    controller->setProperty("NativeP2PRx149HostTxBlocked", uint32_t(1), 32);
    publishRx149DataInputAvailability(controller, enabled);
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
    return !rx149ObservationOnlyRequested(controller) &&
        psfObservationProfileEnabled(controller) &&
        controller->getProperty("NativeP2PAwdlMifFollowup") ==
            kOSBooleanTrue;
}

static bool probeEnabled(ItlIwx *owner, IOEthernetController *controller)
{
    if (rx149ObservationOnlyRequested(controller) ||
        rx149ArmModeSelected(owner))
        return rx149ProfileStatus(owner, controller) ==
                NativeP2PRx149Observation::ProfileStatus::kSelected &&
            rx149ArmModeSelected(owner) &&
            manualProbeGateOpen(owner, controller);
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
    if (rx149ObservationOnlyRequested(controller) ||
        rx149ArmModeSelected(owner))
        return false;
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
    if (rx149ObservationOnlyRequested(controller) ||
        rx149ArmModeSelected(owner))
        return false;
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
    output->queueGeneration = queue.generation;
    output->queueState = static_cast<uint32_t>(
        owner->nativeP2pTxQueue_.state);
    output->outstandingTx = queue.outstandingTx;
    output->queueDoorbelled = owner->nativeP2pTxQueue_.everDoorbelled;
    output->ringMayExist = queue.ringMustRemainOwned ||
        owner->nativeP2pTxQueue_.pendingRing != nullptr ||
        owner->nativeP2pTxQueue_.retainedRing != nullptr ||
        owner->nativeP2pTxQueue_.submissionBusy ||
        queue.state != IntelP2PTx::QueueState::kAbsent;
    output->actionState = static_cast<uint32_t>(
        owner->nativeP2pActionTx_.state);
    output->ticketStatus = ticket.status;
    output->ticketByteCount = ticket.byteCount;
    output->ticketSequenceControl = ticket.sequenceControl;
    output->ticketFrameControl = ticket.frameControl;
    output->actionGeneration = owner->nativeP2pActionTx_.generation;
    output->actionQueueId = owner->nativeP2pActionTx_.queueId;
    output->actionDescriptorIndex = owner->nativeP2pActionTx_.descriptorIndex;
    output->actionRocToken = owner->nativeP2pActionTx_.rocToken;
    output->actionSequenceControl = owner->nativeP2pActionTx_.sequenceControl;
    output->actionFrameControl = owner->nativeP2pActionTx_.frameControl;
    output->actionByteCount = owner->nativeP2pActionTx_.frameByteCount;
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

static P2PProbeTicketIdentity ticketIdentityFromSnapshot(
    const P2PTxDiagnosticSnapshot &snapshot)
{
    P2PProbeTicketIdentity identity{};
    identity.queueGeneration = snapshot.queueGeneration;
    identity.actionGeneration = snapshot.actionGeneration;
    identity.queueId = snapshot.actionQueueId;
    identity.descriptorIndex = snapshot.actionDescriptorIndex;
    identity.rocToken = snapshot.actionRocToken;
    identity.sequenceControl = snapshot.actionSequenceControl;
    identity.frameControl = snapshot.actionFrameControl;
    identity.byteCount = snapshot.actionByteCount;
    identity.nextSequenceNumber = snapshot.nextSequenceNumber;
    identity.valid = snapshot.queueGeneration != 0 &&
        snapshot.actionGeneration != 0 && snapshot.actionQueueId != 0xffffu &&
        snapshot.actionRocToken != 0 && snapshot.actionByteCount != 0;
    return identity;
}

static bool ticketIdentityFieldsMatch(
    const P2PProbeTicketIdentity &expected,
    const P2PTxDiagnosticSnapshot &snapshot)
{
    if (!expected.valid || !snapshot.ticketArmed ||
        !snapshot.ticketCompleted ||
        snapshot.actionState != static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle))
        return false;
    return snapshot.queueGeneration == expected.queueGeneration &&
        snapshot.actionGeneration == expected.actionGeneration &&
        snapshot.actionQueueId == expected.queueId &&
        snapshot.queueId == expected.queueId &&
        snapshot.actionDescriptorIndex == expected.descriptorIndex &&
        snapshot.actionRocToken == expected.rocToken &&
        snapshot.actionSequenceControl == expected.sequenceControl &&
        snapshot.actionFrameControl == expected.frameControl &&
        snapshot.actionByteCount == expected.byteCount &&
        snapshot.ticketSequenceControl == expected.sequenceControl &&
        snapshot.ticketFrameControl == expected.frameControl &&
        snapshot.ticketByteCount == expected.byteCount &&
        snapshot.nextSequenceNumber == expected.nextSequenceNumber &&
        snapshot.ticketSequenceControl != 0xffffffffu &&
        (snapshot.ticketSequenceControl & 0x000fu) == 0 &&
        snapshot.ticketFrameControl == 0x00d0u;
}

static bool ticketIdentityMatches(const P2PProbeTicketIdentity &expected,
                                  const P2PTxDiagnosticSnapshot &snapshot)
{
    return ticketIdentityFieldsMatch(expected, snapshot) &&
        // A successful firmware TX status proves local completion only.
        // peerAcknowledged is intentionally not inferred from this ticket.
        snapshot.frameAttemptSucceeded &&
        (snapshot.ticketStatus & 0xffu) == 1u;
}

static P2PMifCompletionClassification classifyMifCompletion(
    bool bootstrapSelected, bool pairedMifAttempted,
    const P2PProbeTicketIdentity &bootstrapIdentity,
    const P2PProbeTicketIdentity &pairedIdentity,
    const P2PTxDiagnosticSnapshot &snapshot)
{
    const bool firmwareTxSucceeded = snapshot.frameAttemptSucceeded &&
        (snapshot.ticketStatus & 0xffu) == 1u;
    if (!bootstrapSelected)
        return {firmwareTxSucceeded, firmwareTxSucceeded};

    // After a paired attempt, only its exact submitted ticket may count as a
    // successful MIF or grant own-first. A late bootstrap completion must not
    // promote the normal-MIF phase even if its generic status is successful.
    if (pairedMifAttempted) {
        const bool pairedSucceeded = ticketIdentityMatches(
            pairedIdentity, snapshot);
        return {pairedSucceeded, pairedSucceeded};
    }

    // Before the one normal paired attempt, only the selected bootstrap
    // ticket can count as local TX completion; bootstrap never grants own-first.
    return {ticketIdentityMatches(bootstrapIdentity, snapshot), false};
}

static bool mifBurstTicketMatchesPreviousCompletion(
    const P2PProbeRun *probe, const P2PTxDiagnosticSnapshot &tx);

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

static void publishRx149ProfileState(ItlIwx *owner, bool enabled,
                                     bool selected, bool hostTxBlocked)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() :
                                                nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PRx149ProfileEnabled",
                            enabled ? 1u : 0u, 32);
    controller->setProperty("NativeP2PRx149Selected",
                            selected ? 1u : 0u, 32);
    controller->setProperty("NativeP2PRx149HostTxBlocked",
                            hostTxBlocked ? 1u : 0u, 32);
    publishRx149DataInputAvailability(controller, enabled && hostTxBlocked);
}

static bool rx149PropertyAbsentOrZero(IOEthernetController *controller,
                                      const char *name,
                                      bool *wasAbsent);

static bool rx149TxHistoryQuiescent(
    ItlIwx *owner, P2PTxDiagnosticSnapshot *snapshot)
{
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    bool wasAbsent = false;
    if (!owner || !snapshot ||
        !rx149PropertyAbsentOrZero(controller,
            "NativeP2PTxProbeEverDoorbelled", &wasAbsent) ||
        !captureP2PTxSnapshot(owner, snapshot))
        return false;
    publishP2PTxDetails(owner, *snapshot);
    const NativeP2PRx149Observation::TxQuiescence state{
        snapshot->queueId == 0xffffu && snapshot->queueState ==
            static_cast<uint32_t>(TahoeP2PResourceState::kAbsent),
        !snapshot->ringMayExist,
        snapshot->outstandingTx,
        snapshot->queueDoorbelled,
        snapshot->actionState == static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle),
        snapshot->ticketArmed,
        snapshot->ticketCompleted
    };
    return NativeP2PRx149Observation::txQuiescent(state);
}

static bool rx149PropertyAbsentOrZero(IOEthernetController *controller,
                                      const char *name,
                                      bool *wasAbsent)
{
    if (!controller || !name || !wasAbsent)
        return false;
    OSObject *property = controller->getProperty(name);
    if (!property) {
        *wasAbsent = true;
        return true;
    }
    *wasAbsent = false;
    OSNumber *number = OSDynamicCast(OSNumber, property);
    return number && number->unsigned32BitValue() == 0u;
}

static IOReturn rx149PrearmCounterAction(OSObject *, void *context,
                                         void *, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(context);
    if (!owner || !owner->tahoeP2pOnMainGate())
        return kIOReturnNotReady;
    auto *controller = owner->tahoeP2pController();
    if (!rx149ObservationOnlyRequested(controller) ||
        manualProbeArmMode(owner) != 0 || owner->nativeP2pBusy() ||
        __atomic_load_n(&owner->nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) != 0 ||
        rx149ProfileStatus(owner, controller) !=
            NativeP2PRx149Observation::ProfileStatus::kReadyToArm)
        return kIOReturnNotReady;
    const auto probeSnapshot = owner->nativeP2pProbe_.snapshot();
    if (probeSnapshot.attempted != 0 || probeSnapshot.resourceMayExist != 0)
        return kIOReturnNotReady;

    bool absentAction = false;
    bool absentPsf = false;
    bool absentMif = false;
    bool absentBootstrap = false;
    bool absentDoorbell = false;
    if (!rx149PropertyAbsentOrZero(controller,
            "NativeP2PTxProbeEverDoorbelled", &absentDoorbell))
        return kIOReturnNotReady;
    (void)absentDoorbell;
    if (!rx149PropertyAbsentOrZero(controller,
            "NativeP2PAwdlActionFramesSubmitted", &absentAction) ||
        !rx149PropertyAbsentOrZero(controller,
            "NativeP2PAwdlPsfFrameSubmitted", &absentPsf) ||
        !rx149PropertyAbsentOrZero(controller,
            "NativeP2PAwdlMifFrameSubmitted", &absentMif) ||
        !rx149PropertyAbsentOrZero(controller,
            "NativeP2PAwdlMifBootstrapSubmitted", &absentBootstrap))
        return kIOReturnNotReady;

    P2PTxDiagnosticSnapshot snapshot{};
    if (!rx149TxHistoryQuiescent(owner, &snapshot) ||
        snapshot.queueDoorbelled || snapshot.outstandingTx != 0 ||
        snapshot.ticketArmed || snapshot.ticketCompleted ||
        snapshot.actionState != static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle))
        return kIOReturnNotReady;

    // Only missing run-local fields are initialized. The actual historical
    // doorbell field above came from the live TX snapshot and is never reset.
    if (absentAction && !controller->setProperty(
            "NativeP2PAwdlActionFramesSubmitted", uint32_t(0), 32))
        return kIOReturnNoMemory;
    if (absentPsf && !controller->setProperty(
            "NativeP2PAwdlPsfFrameSubmitted", uint32_t(0), 32))
        return kIOReturnNoMemory;
    if (absentMif && !controller->setProperty(
            "NativeP2PAwdlMifFrameSubmitted", uint32_t(0), 32))
        return kIOReturnNoMemory;
    if (absentBootstrap && !controller->setProperty(
            "NativeP2PAwdlMifBootstrapSubmitted", uint32_t(0), 32))
        return kIOReturnNoMemory;
    return kIOReturnSuccess;
}

static bool initializeRx149PrearmCounters(ItlIwx *owner)
{
    if (!owner)
        return false;
    if (owner->tahoeP2pOnMainGate())
        return rx149PrearmCounterAction(nullptr, owner, nullptr, nullptr,
                                        nullptr) == kIOReturnSuccess;
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    return gate && gate->attemptAction(rx149PrearmCounterAction, owner) ==
        kIOReturnSuccess;
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
    const bool addressCandidate =
        probe->psfCandidate.input.advertiseAwdlAddress;
    controller->setProperty("NativeP2PAwdlPsfDataPathAddressCandidate",
                            addressCandidate ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlPsfDataPathAdvertised",
        probe->psfFrameSubmitted && addressCandidate ? 1u : 0u, 32);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    controller->setProperty("NativeP2PAwdlNativeAddressCandidateVerified",
        probe->nativeAddressCandidateVerified ? 1u : 0u, 32);
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    controller->setProperty("NativeP2PAwdlMifBootstrapStatus",
        probe->mifBootstrapStatus, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapBlockers",
        probe->mifBootstrapBlockers, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapChecks",
        probe->mifBootstrapChecks, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapReady",
        probe->mifBootstrapStatus == static_cast<uint32_t>(
            Test070MifBootstrap::Status::Ready) ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapPrepared",
        probe->mifBootstrapCandidatePrepared ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapSubmitted",
        probe->mifBootstrapSubmitted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapSucceeded",
        probe->mifBootstrapSucceeded ? 1u : 0u, 32);
#endif
    controller->setProperty("NativeP2PAwdlMifTxStatus",
        probe->mifTicketStatus, 32);
    controller->setProperty("NativeP2PAwdlMifPeerAcknowledged",
        probe->mifPeerAcknowledged ? 1u : 0u, 32);
    const bool addressCandidate =
        probe->mifCandidate.input.advertiseAwdlAddress;
    controller->setProperty("NativeP2PAwdlMifDataPathAddressCandidate",
                            addressCandidate ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifDataPathAdvertised",
        probe->mifFrameSubmitted && addressCandidate ? 1u : 0u, 32);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    controller->setProperty("NativeP2PAwdlNativeAddressCandidateVerified",
        probe->nativeAddressCandidateVerified ? 1u : 0u, 32);
#endif
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

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
// Publish the pair-phase summary from the worker/finalizer, outside the TX
// submit callback. The bootstrap ticket remains historical; NoAttempt is an
// explicit outcome when no fresh same-entry pair ever opened the normal path.
static void publishMifBootstrapPairDiagnostics(
    ItlIwx *owner, P2PProbeRun *probe, bool force = false)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() :
                                                nullptr;
    if (!controller || !probe ||
        (!force && !probe->mifBootstrapPairDiagnosticsDirty))
        return;
    controller->setProperty("NativeP2PAwdlMifPairPhase",
        probe->mifBootstrapPairStatus, 32);
    controller->setProperty("NativeP2PAwdlMifPairBlockers",
        probe->mifBootstrapPairBlockers, 64);
    controller->setProperty("NativeP2PAwdlMifPairChecks",
        probe->mifBootstrapPairChecks, 32);
    controller->setProperty("NativeP2PAwdlMifPairNoAttempt",
        probe->mifBootstrapSelected &&
            !probe->mifBootstrapPairMifAttempted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifPairSelected",
        probe->mifBootstrapPairClaimed ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifPairMifAttempted",
        probe->mifBootstrapPairMifAttempted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifPairMifCompleted",
        probe->mifBootstrapPairMifCompleted ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifPairMifSucceeded",
        probe->mifBootstrapPairMifSucceeded ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlMifBootstrapCompletionUs",
        probe->mifBootstrapCompletedUs, 64);
    controller->setProperty("NativeP2PAwdlMifPairPeerSlot",
        probe->mifBootstrapPairClaimed ? probe->mifBootstrapPairSlot : 0xffu,
        32);
    controller->setProperty("NativeP2PAwdlMifPairPeerIncarnation",
        probe->mifBootstrapPairPeerIncarnation, 64);
    controller->setProperty("NativeP2PAwdlMifPairPsfRevision",
        probe->mifBootstrapPairPsfRevision, 64);
    controller->setProperty("NativeP2PAwdlMifPairMifRevision",
        probe->mifBootstrapPairMifRevision, 64);
    controller->setProperty("NativeP2PAwdlMifPairPsfRxUs",
        probe->mifBootstrapPairPsfRxUs, 64);
    controller->setProperty("NativeP2PAwdlMifPairMifRxUs",
        probe->mifBootstrapPairMifRxUs, 64);
    probe->mifBootstrapPairDiagnosticsDirty = false;
}
#endif

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
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeResidentAddressProfileEnabled(probe->owner)) {
        uint8_t liveAddress[6]{};
        const uint32_t identityFailure = verifyNativeIdentity(
            probe->owner, probe->contextGeneration,
            probe->powerGeneration, probe->stationGeneration,
            probe->address, sc->sc_p2p.mac_address, liveAddress);
        if (identityFailure != kNativeIdentityVerified) {
            probe->psfStatus = kPsfProbeCandidateRejected;
            probe->psfBlockers = NativeAwdlProbe::kPsfTxPreparedFrameStale;
            publishNativeIdentityStatus(probe->owner, false, identityFailure);
            return false;
        }
        memcpy(request.p2pMac.bytes, liveAddress,
               sizeof(request.p2pMac.bytes));
        request.nativeAddressVerified = true;
        probe->nativeAddressCandidateVerified = true;
    } else
#endif
    {
        memcpy(request.p2pMac.bytes, sc->sc_p2p.mac_address,
               sizeof(request.p2pMac.bytes));
    }
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
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (request.nativeAddressVerified)
        publishNativeIdentityStatus(probe->owner, true,
                                    kNativeIdentityVerified);
#endif
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
    uint64_t rocGeneration;
    uint64_t rxMonotonicUs;
    uint64_t sampleUs;
    uint64_t peerIncarnation;
    uint64_t psfRevision;
    uint64_t mifRevision;
    uint64_t mifRxMonotonicUs;
    uint16_t rxChannelIndex;
    uint16_t mifRxChannelIndex;
    uint8_t slot;
    bool ownerCurrent;
    bool rocActive;
    bool rocChannel6Confirmed;
    bool endSeen;
    bool outcomeUnknown;
    bool complete;
    bool syncConsistent;
    bool fresh;
    bool rxChannel6Confirmed;
    bool tracked;
    bool hasPsf;
    bool hasMif;
    bool psfComplete;
    bool mifComplete;
    bool mifFresh;
    bool mifSyncConsistent;
    bool historyCompatible;
    bool mifRxChannel6Confirmed;
    bool queueLeaseActive;
    bool ticketReclaimed;
    bool txRingEmpty;
    bool ringIndicesConsistent;
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    const bool bootstrapSelected = probe->mifBootstrapSelected;
    const uint8_t bootstrapSlot = probe->mifBootstrapBinding.slot;
#else
    // Bootstrap peer pinning is a discovery-profile transition. Keep the
    // ordinary/resident profiles on their existing global-newest PSF path.
    const bool bootstrapSelected = false;
    const uint8_t bootstrapSlot = 0xff;
#endif
    const auto session = owner->nativeP2pRocEvents_.snapshot();
    auto &view = read->view;
    view.endSeen = session.endSeen;
    view.outcomeUnknown = session.outcomeUnknown;
    view.rocGeneration = session.generation;
    view.ownerCurrent = owner->nativeP2pBusy() &&
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) ==
            reinterpret_cast<void *>(probe->workerThread) &&
        owner->nativeP2pProbeGeneration_ == probe->contextGeneration &&
        uint32_t(sc.sc_generation) == probe->powerGeneration &&
        __atomic_load_n(&sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE) ==
            probe->stationGeneration;
    view.rocActive = view.ownerCurrent &&
        session.commandReturned && session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == probe->contextGeneration &&
        sc.sc_p2p_roc.token == probe->contextGeneration &&
        sc.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED &&
        !session.endSeen && !session.outcomeUnknown;
    view.rocChannel6Confirmed = isCurrentIeeeChannel6(
        &ic, sc.sc_p2p_roc.roc_channel);

    uint64_t nowUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    view.sampleUs = nowUs;
    P2PTxDiagnosticSnapshot txSnapshot{};
    if (bootstrapSelected && captureP2PTxSnapshot(owner, &txSnapshot)) {
        view.queueLeaseActive = txSnapshot.queueLeaseActive;
        view.txRingEmpty = txSnapshot.txRingEmpty;
        view.ringIndicesConsistent = txSnapshot.ringIndicesConsistent;
        view.ticketReclaimed = txSnapshot.ticketCompleted &&
            txSnapshot.actionState == static_cast<uint32_t>(
                TahoeP2PActionTxState::kIdle) &&
            txSnapshot.outstandingTx == 0 &&
            (!txSnapshot.ticketArmed || txSnapshot.ticketCompleted);
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (bootstrapSelected)
            view.ticketReclaimed =
                mifBurstTicketMatchesPreviousCompletion(probe, txSnapshot) &&
                ticketIdentityMatches(probe->mifBootstrapTicketIdentity,
                                      txSnapshot);
#endif
    }
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

    if (bootstrapSelected && probe->leaseValue &&
        probe->leasePublished && probe->addAcknowledged &&
        sc.sc_p2p.initialized &&
        sc.sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc.sc_p2p.binding_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc.sc_p2p.phy_leased) {
        const auto &rxLease = owner->tahoe_p2p_rx_lease_;
        const bool rxLeaseCurrent = rxLease.active &&
            rxLease.contextGeneration == probe->contextGeneration &&
            rxLease.currentContextGeneration ==
                owner->nativeP2pProbeGeneration_ &&
            rxLease.powerGeneration == probe->powerGeneration &&
            rxLease.currentPowerGeneration == uint32_t(sc.sc_generation) &&
            rxLease.stationGeneration == probe->stationGeneration &&
            rxLease.currentStationGeneration ==
                __atomic_load_n(&sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE);
        if (rxLeaseCurrent) {
            owner->tahoeP2pRxConsume();
            nowUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
            view.sampleUs = nowUs;
        }
    }

    IntelAwdlPeerRuntime::PsfPeerSnapshot newest{};
    uint8_t newestSlot = 0xff;
    bool found = false;
    for (uint8_t slot = 0; slot < IntelAwdlPeerRuntime::kPeerCapacity;
         ++slot) {
        if (bootstrapSelected && slot != bootstrapSlot)
            continue;
        IntelAwdlPeerRuntime::PsfPeerSnapshot candidate{};
        if (!owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(
                slot, epochs, nowUs, &candidate) || !candidate.tracked ||
            !candidate.hasPsf ||
            (!bootstrapSelected && !candidate.psfFresh) ||
            candidate.contextGeneration != epochs.contextGeneration ||
            candidate.powerGeneration != epochs.powerGeneration ||
            candidate.stationGeneration != epochs.stationGeneration)
            continue;
        if (!found || candidate.psfRxMonotonicUs >
                          newest.psfRxMonotonicUs) {
            newest = candidate;
            newestSlot = slot;
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
    view.slot = bootstrapSelected ? bootstrapSlot :
        static_cast<uint8_t>(newestSlot);
    view.peerIncarnation = newest.peerIncarnation;
    view.psfRevision = newest.psfRevision;
    view.mifRevision = newest.mifRevision;
    view.mifRxMonotonicUs = newest.mifRxMonotonicUs;
    view.mifRxChannelIndex = newest.mif.rxChannel;
    view.tracked = newest.tracked;
    view.hasPsf = newest.hasPsf;
    view.hasMif = newest.hasMif;
    view.psfComplete = view.complete && newest.psfRevision != 0 &&
        newest.syncConsistent;
    const bool sameMifEntry = newest.mif.peerIncarnation ==
            newest.peerIncarnation &&
        newest.mif.mifRevision == newest.mifRevision &&
        newest.mif.rxMonotonicUs == newest.mifRxMonotonicUs &&
        newest.mif.contextGeneration == newest.contextGeneration &&
        newest.mif.powerGeneration == newest.powerGeneration &&
        newest.mif.stationGeneration == newest.stationGeneration;
    view.mifComplete = newest.hasMif && newest.mif.present &&
        newest.mif.complete && sameMifEntry;
    view.mifFresh = newest.mifFresh;
    view.mifSyncConsistent = newest.mifSyncConsistent &&
        newest.mif.syncConsistent;
    view.historyCompatible = newest.historyCompatible;
    view.mifRxChannel6Confirmed = newest.mif.rxChannel <
            sizeof(ic.ic_channels) / sizeof(ic.ic_channels[0]) &&
        ieee80211_chan2ieee(&ic,
            &ic.ic_channels[newest.mif.rxChannel]) == 6;
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

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
enum MifBootstrapPairPhase : uint32_t {
    kMifBootstrapPairNotSelected = 0,
    kMifBootstrapPairWaitingForFreshPeer = 1,
    kMifBootstrapPairCandidateSelected = 2,
    kMifBootstrapPairMifAttempted = 3,
    kMifBootstrapPairMifCompleted = 4,
    kMifBootstrapPairMifFailed = 5
};

constexpr uint64_t kMifBootstrapPairPinnedSnapshotChanged = 1ULL << 33;
constexpr uint64_t kMifBootstrapPairTicketMismatch = 1ULL << 34;

static Test079BootstrapPairTransition::Input makeMifBootstrapPairInput(
    const P2PProbeRun *probe, const MifPacingPeerView &peer)
{
    using namespace Test079BootstrapPairTransition;
    Input input{};
    if (!probe)
        return input;

    input.bootstrap.epochs = {
        probe->mifBootstrapBinding.contextGeneration,
        probe->mifBootstrapBinding.powerGeneration,
        probe->mifBootstrapBinding.stationGeneration,
        probe->mifBootstrapBinding.rocGeneration};
    input.bootstrap.completedUs = probe->mifBootstrapCompletedUs;
    input.bootstrap.upgradeDeadlineUs =
        probe->mifPacingWindowEndUs < probe->psfCandidate.hardDeadlineUs ?
            probe->mifPacingWindowEndUs : probe->psfCandidate.hardDeadlineUs;
    input.bootstrap.peerIncarnation =
        probe->mifBootstrapBinding.peerIncarnation;
    input.bootstrap.mifRevision = probe->mifBootstrapBinding.mifRevision;
    // Bootstrap selection is deliberately allowed to start from MIF-only
    // evidence; no PSF revision existed in that binding to anchor against.
    input.bootstrap.psfRevision = 0;
    input.bootstrap.slot = probe->mifBootstrapBinding.slot;
    input.bootstrap.selected = probe->mifBootstrapSelected;
    input.bootstrap.submitted = probe->mifBootstrapSubmitted;
    input.bootstrap.succeeded = probe->mifBootstrapSucceeded;

    input.live.epochs = {peer.contextGeneration, peer.powerGeneration,
        peer.stationGeneration, peer.rocGeneration};
    input.live.nowUs = peer.sampleUs;
    input.live.ownerCurrent = peer.ownerCurrent;
    input.live.rocActive = peer.rocActive;
    input.live.rocClosing = peer.endSeen || peer.outcomeUnknown;
    input.live.rocAckedChannel6 = peer.rocActive &&
        peer.rocChannel6Confirmed;
    input.live.queueLeaseActive = peer.queueLeaseActive;
    input.live.ticketReclaimed = peer.ticketReclaimed;
    input.live.txRingEmpty = peer.txRingEmpty;
    input.live.ringIndicesConsistent = peer.ringIndicesConsistent;

    input.peer.epochs = {peer.contextGeneration, peer.powerGeneration,
        peer.stationGeneration, peer.rocGeneration};
    input.peer.peerIncarnation = peer.peerIncarnation;
    input.peer.psfRevision = peer.psfRevision;
    input.peer.mifRevision = peer.mifRevision;
    input.peer.psfRxUs = peer.rxMonotonicUs;
    input.peer.mifRxUs = peer.mifRxMonotonicUs;
    input.peer.psfChannel = peer.rxChannel6Confirmed ? 6 : 0;
    input.peer.mifChannel = peer.mifRxChannel6Confirmed ? 6 : 0;
    input.peer.slot = peer.slot;
    input.peer.tracked = peer.tracked;
    input.peer.hasPsf = peer.hasPsf;
    input.peer.hasMif = peer.hasMif;
    input.peer.psfComplete = peer.psfComplete;
    input.peer.mifComplete = peer.mifComplete;
    input.peer.psfFresh = peer.fresh;
    input.peer.mifFresh = peer.mifFresh;
    input.peer.mifSyncConsistent = peer.mifSyncConsistent;
    input.peer.historyCompatible = peer.historyCompatible;
    input.normalMifAlreadyAttempted = probe->mifBootstrapPairMifAttempted;
    return input;
}

static bool mifBootstrapPairSnapshotMatches(
    const P2PProbeRun *probe, const MifPacingPeerView &peer);

static bool evaluateMifBootstrapPairTransition(
    P2PProbeRun *probe, const MifPacingPeerView &peer, bool allowClaim)
{
    if (!probe)
        return false;
    if (probe->mifBootstrapPairChecks != UINT32_MAX)
        ++probe->mifBootstrapPairChecks;

    const uint32_t oldStatus = probe->mifBootstrapPairStatus;
    const uint64_t oldBlockers = probe->mifBootstrapPairBlockers;
    const bool wasClaimed = probe->mifBootstrapPairClaimed;
    const auto input = makeMifBootstrapPairInput(probe, peer);
    const auto plan = Test079BootstrapPairTransition::evaluate(input);
    uint64_t blockers = plan.blockers;
    if (plan.permitExistingNormalMifPath) {
        if (!probe->mifBootstrapPairClaimed) {
            if (allowClaim && probe->mifBootstrapPairMifAttempted) {
                blockers |= Test079BootstrapPairTransition::kAttemptAlreadyUsed;
            } else if (allowClaim) {
                probe->mifBootstrapPairClaimed = true;
                probe->mifBootstrapPairSlot = peer.slot;
                probe->mifBootstrapPairPeerIncarnation = peer.peerIncarnation;
                probe->mifBootstrapPairPsfRevision = peer.psfRevision;
                probe->mifBootstrapPairMifRevision = peer.mifRevision;
                probe->mifBootstrapPairPsfRxUs = peer.rxMonotonicUs;
                probe->mifBootstrapPairMifRxUs = peer.mifRxMonotonicUs;
            }
        } else if (!mifBootstrapPairSnapshotMatches(probe, peer)) {
            blockers |= kMifBootstrapPairPinnedSnapshotChanged;
        }
    }

    probe->mifBootstrapPairBlockers = blockers;
    if (blockers == Test079BootstrapPairTransition::kNoBlocker &&
        probe->mifBootstrapPairClaimed) {
        probe->mifBootstrapPairStatus =
            probe->mifBootstrapPairMifAttempted ?
                kMifBootstrapPairMifAttempted :
                kMifBootstrapPairCandidateSelected;
        if (probe->mifBootstrapPairStatus != oldStatus ||
            probe->mifBootstrapPairBlockers != oldBlockers ||
            probe->mifBootstrapPairClaimed != wasClaimed)
            probe->mifBootstrapPairDiagnosticsDirty = true;
        return true;
    }
    probe->mifBootstrapPairStatus = probe->mifBootstrapPairMifCompleted ?
        (probe->mifBootstrapPairMifSucceeded ?
            kMifBootstrapPairMifCompleted : kMifBootstrapPairMifFailed) :
        kMifBootstrapPairWaitingForFreshPeer;
    if (probe->mifBootstrapPairStatus != oldStatus ||
        probe->mifBootstrapPairBlockers != oldBlockers ||
        probe->mifBootstrapPairClaimed != wasClaimed)
        probe->mifBootstrapPairDiagnosticsDirty = true;
    // An eligible, unclaimed preview is not yet a selection. The caller must
    // wait for both pacing and burst-repeat preparation to become Ready before
    // it may pin this peer snapshot.
    return blockers == Test079BootstrapPairTransition::kNoBlocker;
}

static bool claimMifBootstrapPairAfterPreparation(
    P2PProbeRun *probe, const MifPacingPeerView &peer,
    bool pacingReady, bool repeatPrepareReady)
{
    if (!pacingReady || !repeatPrepareReady)
        return false;
    return evaluateMifBootstrapPairTransition(probe, peer, true);
}

static bool mifBootstrapPairSnapshotMatches(
    const P2PProbeRun *probe, const MifPacingPeerView &peer)
{
    return probe && probe->mifBootstrapPairClaimed &&
        probe->mifBootstrapPairSlot == peer.slot &&
        probe->mifBootstrapPairPeerIncarnation == peer.peerIncarnation &&
        probe->mifBootstrapPairPsfRevision == peer.psfRevision &&
        probe->mifBootstrapPairMifRevision == peer.mifRevision &&
        probe->mifBootstrapPairPsfRxUs == peer.rxMonotonicUs &&
        probe->mifBootstrapPairMifRxUs == peer.mifRxMonotonicUs &&
        probe->contextGeneration == peer.contextGeneration &&
        probe->powerGeneration == peer.powerGeneration &&
        probe->stationGeneration == peer.stationGeneration &&
        probe->mifBootstrapBinding.rocGeneration == peer.rocGeneration &&
        peer.ownerCurrent && peer.rocActive &&
        peer.rocChannel6Confirmed && peer.rxChannel6Confirmed &&
        peer.mifRxChannel6Confirmed;
}
#endif

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
struct MifBootstrapPeerView {
    uint64_t sampleUs;
    uint64_t rocGeneration;
    Test070MifBootstrap::PeerMif peer;
    bool ownerCurrent;
    bool rocActive;
    bool rocClosing;
    bool rocChannel6Confirmed;
};

struct MifBootstrapPeerRead {
    ItlIwx *owner;
    P2PProbeRun *probe;
    int32_t requestedSlot; // -1 selects newest current MIF; otherwise exact.
    MifBootstrapPeerView view;
};

static IOReturn readMifBootstrapPeerInGate(OSObject *, void *opaque,
                                           void *, void *, void *)
{
    auto *read = static_cast<MifBootstrapPeerRead *>(opaque);
    auto *owner = read ? read->owner : nullptr;
    auto *probe = read ? read->probe : nullptr;
    if (!owner || !probe || !owner->tahoeP2pOnMainGate())
        return kIOReturnNotReady;

    auto &sc = owner->com;
    auto &ic = sc.sc_ic;
    auto &view = read->view;
    const auto session = owner->nativeP2pRocEvents_.snapshot();
    view.rocGeneration = session.generation;
    view.rocClosing = session.endSeen || session.outcomeUnknown;
    view.ownerCurrent = owner->nativeP2pBusy() &&
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) ==
            reinterpret_cast<void *>(probe->workerThread) &&
        owner->nativeP2pProbeGeneration_ == probe->contextGeneration &&
        uint32_t(sc.sc_generation) == probe->powerGeneration &&
        __atomic_load_n(&sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE) ==
            probe->stationGeneration;
    view.rocActive = view.ownerCurrent &&
        session.commandReturned && session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == probe->contextGeneration && !view.rocClosing &&
        sc.sc_p2p_roc.token == probe->contextGeneration &&
        sc.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED;
    view.rocChannel6Confirmed = isCurrentIeeeChannel6(
        &ic, sc.sc_p2p_roc.roc_channel);

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
    if (!epochs.active || epochs.contextGeneration != probe->contextGeneration ||
        epochs.powerGeneration != probe->powerGeneration ||
        epochs.stationGeneration != probe->stationGeneration ||
        !view.rocActive || !view.rocChannel6Confirmed || nowUs == 0)
        return kIOReturnSuccess;

    const size_t channelCount =
        sizeof(ic.ic_channels) / sizeof(ic.ic_channels[0]);
    auto copyMif = [&](uint8_t slot,
                       const IntelAwdlPeerRuntime::MifPeerSnapshot &snapshot) {
        auto &peer = view.peer;
        peer.slot = slot;
        peer.peerIncarnation = snapshot.peerIncarnation;
        peer.mifRevision = snapshot.mifRevision;
        peer.rxMonotonicUs = snapshot.mifRxMonotonicUs;
        peer.contextGeneration = snapshot.contextGeneration;
        peer.powerGeneration = snapshot.powerGeneration;
        peer.stationGeneration = snapshot.stationGeneration;
        peer.rxChannel = snapshot.rxChannel;
        peer.tracked = snapshot.tracked;
        peer.hasMif = snapshot.hasMif;
        peer.hasPsf = snapshot.hasPsf;
        peer.mifFresh = snapshot.mifFresh;
        peer.complete = snapshot.complete;
        peer.syncConsistent = snapshot.syncConsistent;
        peer.rxChannel6Confirmed = snapshot.rxChannel < channelCount &&
            ieee80211_chan2ieee(&ic, &ic.ic_channels[snapshot.rxChannel]) == 6;
    };

    if (read->requestedSlot >= 0) {
        if (read->requestedSlot >=
            static_cast<int32_t>(IntelAwdlPeerRuntime::kPeerCapacity))
            return kIOReturnSuccess;
        const auto slot = static_cast<uint8_t>(read->requestedSlot);
        IntelAwdlPeerRuntime::MifPeerSnapshot snapshot{};
        if (owner->tahoe_awdl_peer_runtime_.getMifSnapshot(
                slot, epochs, nowUs, &snapshot))
            copyMif(slot, snapshot);
        return kIOReturnSuccess;
    }

    IntelAwdlPeerRuntime::MifPeerSnapshot newest{};
    uint8_t newestSlot = 0xff;
    bool found = false;
    for (uint8_t slot = 0; slot < IntelAwdlPeerRuntime::kPeerCapacity;
         ++slot) {
        IntelAwdlPeerRuntime::MifPeerSnapshot candidate{};
        if (!owner->tahoe_awdl_peer_runtime_.getMifSnapshot(
                slot, epochs, nowUs, &candidate) || !candidate.tracked ||
            !candidate.hasMif)
            continue;
        if (!found || candidate.mifRxMonotonicUs > newest.mifRxMonotonicUs) {
            newest = candidate;
            newestSlot = slot;
            found = true;
        }
    }
    if (found)
        copyMif(newestSlot, newest);
    return kIOReturnSuccess;
}

static bool readMifBootstrapPeer(P2PProbeRun *probe, int32_t requestedSlot,
                                 MifBootstrapPeerView *output)
{
    if (!probe || !probe->owner || !output)
        return false;
    auto *gate = probe->owner->tahoeP2pCommandGate();
    if (!gate)
        return false;
    MifBootstrapPeerRead read{};
    read.owner = probe->owner;
    read.probe = probe;
    read.requestedSlot = requestedSlot;
    if (gate->runAction(readMifBootstrapPeerInGate, &read) !=
        kIOReturnSuccess)
        return false;
    *output = read.view;
    return true;
}

static Test070MifBootstrap::LocalState makeMifBootstrapLocalState(
    const P2PProbeRun *probe,
    const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t nowUs,
    bool ownerCurrent, bool rocChannel6Confirmed)
{
    Test070MifBootstrap::LocalState local{};
    if (!probe)
        return local;
    local.phaseOriginUs = probe->psfCandidate.sampleUs;
    local.windowEndUs = probe->mifPacingWindowEndUs;
    local.hardDeadlineUs = probe->psfCandidate.hardDeadlineUs;
    local.nowUs = nowUs;
    local.contextGeneration = probe->contextGeneration;
    local.powerGeneration = probe->powerGeneration;
    local.stationGeneration = probe->stationGeneration;
    local.rocGeneration = session.generation;
    local.ordinal = 0;
    local.probeEnabled = probe->awdlMifFollowupEnabled &&
        probe->txProbeEnabled && ownerCurrent;
    local.alreadyUsed = probe->mifBootstrapSubmitted;
    local.firstPsfCompleted = probe->psfResultCaptured &&
        probe->psfTxCompleted && tx.ticketCompleted &&
        tx.actionState == static_cast<uint32_t>(TahoeP2PActionTxState::kIdle);
    local.firstPsfSucceeded = local.firstPsfCompleted &&
        probe->psfTxSucceeded && tx.frameAttemptSucceeded &&
        (tx.ticketStatus & 0xffu) == 1u;
    local.queueLeaseActive = tx.queueLeaseActive;
    local.txRingEmpty = tx.txRingEmpty;
    local.ringIndicesConsistent = tx.ringIndicesConsistent;
    local.rocActive = session.commandReturned && session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == probe->contextGeneration && !session.endSeen &&
        !session.outcomeUnknown;
    local.rocClosing = session.endSeen || session.outcomeUnknown;
    local.rocChannel6Confirmed = rocChannel6Confirmed;
    local.dataAlreadyStarted = probe->nativeDataAttempts != 0;
    return local;
}

static Test070MifBootstrap::Plan evaluateMifBootstrapInGate(
    P2PProbeRun *probe, const P2PTxDiagnosticSnapshot &tx,
    uint64_t nowUs, bool requireBoundPeer)
{
    using namespace Test070MifBootstrap;
    Plan blocked{};
    blocked.status = Status::Blocked;
    if (!probe || !probe->owner || !probe->owner->tahoeP2pOnMainGate()) {
        blocked.blockers = kProbeDisabled;
        return blocked;
    }
    auto *owner = probe->owner;
    const auto session = owner->nativeP2pRocEvents_.snapshot();
    MifBootstrapPeerRead read{};
    read.owner = owner;
    read.probe = probe;
    read.requestedSlot = requireBoundPeer ?
        static_cast<int32_t>(probe->mifBootstrapBinding.slot) : -1;
    if (readMifBootstrapPeerInGate(nullptr, &read, nullptr, nullptr, nullptr) !=
        kIOReturnSuccess) {
        blocked.blockers = kPeerMissing;
    } else {
        const uint64_t liveNowUs = read.view.sampleUs > nowUs ?
            read.view.sampleUs : nowUs;
        auto local = makeMifBootstrapLocalState(
            probe, session, tx, liveNowUs, read.view.ownerCurrent,
            read.view.rocChannel6Confirmed);
        // Always re-evaluate all live local/peer gates. Binding comparison is
        // an additional fence, never a substitute for freshness or ROC checks.
        blocked = evaluate(local, read.view.peer);
        if (requireBoundPeer) {
            blocked.blockers |= bindingMismatch(probe->mifBootstrapBinding,
                read.view.peer, session.generation);
            if (blocked.blockers != kNoBlocker)
                blocked.status = Status::Blocked;
        }
    }
    if (probe->mifBootstrapChecks != UINT32_MAX)
        ++probe->mifBootstrapChecks;
    probe->mifBootstrapStatus = static_cast<uint32_t>(blocked.status);
    probe->mifBootstrapBlockers = blocked.blockers;
    return blocked;
}

static bool refreshMifBootstrapCandidateInGate(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t nowUs,
    NativeAwdlProbe::MifCandidate *output)
{
    using namespace Test070MifBootstrap;
    if (!probe || !output)
        return false;
    const auto gatePlan = evaluateMifBootstrapInGate(
        probe, tx, nowUs, true);
    if (gatePlan.status != Status::Ready)
        return false;

    const uint64_t sampleUs = nowUs;
    const auto witness = makeMifFollowupWitness(probe, session, tx, sampleUs);
    static const char hostname[] = "intel-awdl-probe";
    NativeAwdlProbe::MifCandidate candidate{};
    const auto candidateStatus =
        NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
            &probe->psfCandidate, &witness, tx.ticketStatus, hostname,
            sizeof(hostname) - 1, &candidate);
    if (candidateStatus != NativeAwdlProbe::MifCandidateStatus::Encoded) {
        probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Blocked);
        probe->mifBootstrapBlockers = kCandidatePreparationFailed;
        probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
        return false;
    }
    probe->mifBlockers = NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &witness, sampleUs);
    if (probe->mifBlockers != NativeAwdlProbe::kMifTxNoBlocker) {
        probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Blocked);
        probe->mifBootstrapBlockers = kCandidatePreparationFailed;
        return false;
    }
    *output = candidate;
    return true;
}

static bool tryPrepareMifBootstrapAtPacingPoint(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &session,
    const P2PTxDiagnosticSnapshot &tx, uint64_t nowUs, mbuf_t *frame)
{
    using namespace Test070MifBootstrap;
    if (!probe || !frame || *frame || probe->mifBootstrapSelected ||
        probe->mifBurstStopped || probe->mifCandidatePrepared ||
        !probe->psfResultCaptured || !probe->psfTxSucceeded ||
        probe->mifBurstPreparedFrames != 0 ||
        probe->mifBurstSubmittedFrames != 0 || probe->nativeDataAttempts != 0)
        return false;

    MifBootstrapPeerView peerRead{};
    if (!readMifBootstrapPeer(probe, -1, &peerRead)) {
        probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Waiting);
        probe->mifBootstrapBlockers = kPeerMissing;
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }
    const uint64_t sampleUs = peerRead.sampleUs > nowUs ?
        peerRead.sampleUs : nowUs;
    auto local = makeMifBootstrapLocalState(probe, session, tx, sampleUs,
        peerRead.ownerCurrent, peerRead.rocChannel6Confirmed);
    local.rocGeneration = peerRead.rocGeneration;
    local.rocActive = local.rocActive && peerRead.rocActive;
    local.rocClosing = local.rocClosing || peerRead.rocClosing;
    local.rocChannel6Confirmed = local.rocChannel6Confirmed &&
        peerRead.rocChannel6Confirmed;
    auto plan = evaluate(local, peerRead.peer);
    if (probe->mifBootstrapChecks != UINT32_MAX)
        ++probe->mifBootstrapChecks;
    probe->mifBootstrapStatus = static_cast<uint32_t>(plan.status);
    probe->mifBootstrapBlockers = plan.blockers;
    if (plan.status != Status::Ready) {
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }

    // Once a same-entry MIF-only event is selected, later source replacement
    // or candidate failure is terminal for this path: there is no peer or
    // older-MIF fallback.
    probe->mifBootstrapSelected = true;
    probe->mifBootstrapBinding = plan.binding;
    const auto witness = makeMifFollowupWitness(probe, session, tx, sampleUs);
    static const char hostname[] = "intel-awdl-probe";
    NativeAwdlProbe::MifCandidate candidate{};
    const auto candidateStatus =
        NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
            &probe->psfCandidate, &witness, tx.ticketStatus, hostname,
            sizeof(hostname) - 1, &candidate);
    if (candidateStatus != NativeAwdlProbe::MifCandidateStatus::Encoded) {
        probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Blocked);
        probe->mifBootstrapBlockers = kCandidatePreparationFailed;
        probe->mifStatus = kMifProbePreflightRejected;
        probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
        probe->mifBurstStopped = true;
        probe->mifBurstStopReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }
    probe->mifBlockers = NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &witness, sampleUs);
    if (probe->mifBlockers != NativeAwdlProbe::kMifTxNoBlocker) {
        probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Blocked);
        probe->mifBootstrapBlockers = kCandidatePreparationFailed;
        probe->mifStatus = kMifProbePreflightRejected;
        probe->mifBurstStopped = true;
        probe->mifBurstStopReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }
    *frame = makeActionFrameFromBytes(candidate.bytes, candidate.length);
    if (!*frame) {
        probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Blocked);
        probe->mifBootstrapBlockers = kCandidatePreparationFailed;
        probe->mifStatus = kMifProbePreflightRejected;
        probe->mifBlockers = NativeAwdlProbe::kMifTxInvalidCandidate;
        probe->mifBurstStopped = true;
        probe->mifBurstStopReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifBurstStopReason::CandidatePreparationFailed);
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }

    probe->mifCandidate = candidate;
    probe->mifCandidateLength = candidate.length;
    probe->mifCandidatePrepared = true;
    probe->mifBootstrapCandidatePrepared = true;
    probe->mifBurstPreparedFrames = 1;
    probe->mifBurstCandidateIsRepeat = false;
    probe->mifStatus = kMifProbeCandidateEncodedReady;
    probe->mifBootstrapStatus = static_cast<uint32_t>(Status::Ready);
    probe->mifBootstrapBlockers = kNoBlocker;
    publishMifProbeDetails(probe->owner, probe);
    return true;
}
#endif

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
// This is an explicitly estimated, one-QM discovery experiment. It does not
// promote a PSF to an admitted peer, install a neighbor, select a master, or
// grant the production shared-window planner any verified-clock witness.
static bool discoveryExperimentEnabled(ItlIwx *owner)
{
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    return controller && !rx149ObservationOnlyRequested(controller) &&
        !rx149ArmModeSelected(owner) &&
        controller->getProperty("NativeAwdlDiscoveryExperimentEnabled") == kOSBooleanTrue &&
        controller->getProperty("NativeAwdlResidentEnabled") == kOSBooleanTrue &&
        controller->getProperty("NativeP2PGp2Observation") == kOSBooleanTrue &&
        controller->getProperty("NativeP2PManualTrigger") == kOSBooleanTrue;
}

static bool discoveryMifCurrentSlotEnabled(ItlIwx *owner)
{
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    return discoveryExperimentEnabled(owner) && controller &&
        controller->getProperty(
            "NativeAwdlDiscoveryMifCurrentSlotEnabled") == kOSBooleanTrue;
}

static bool discoveryCurrentAwFallbackEnabled(ItlIwx *owner)
{
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    return discoveryMifCurrentSlotEnabled(owner) && controller &&
        controller->getProperty(
            "NativeAwdlDiscoveryCurrentAwFallbackEnabled") == kOSBooleanTrue;
}

static Test066MifCurrentPhase::Status planDiscoveryMifCurrentTarget(
    const Test066MifCurrentPhase::Input &input, bool fallbackEnabled,
    NativeAwdlMifCurrentAw::Candidate &output,
    NativeAwdlMifCurrentAw::RejectReason &rejectReason)
{
    output = {};
    rejectReason = NativeAwdlMifCurrentAw::RejectReason::kNotAttempted;
    if (fallbackEnabled) {
        const NativeAwdlMifCurrentAw::Input wrapped{input};
        return NativeAwdlMifCurrentAw::plan(
            wrapped, output, &rejectReason);
    }

    Test066MifCurrentPhase::Candidate legacyCandidate{};
    const Test066MifCurrentPhase::Status status =
        Test066MifCurrentPhase::plan(input, legacyCandidate);
    if (status == Test066MifCurrentPhase::Status::kCandidate) {
        NativeAwdlMifCurrentAw::Candidate candidate{};
        static_cast<Test066MifCurrentPhase::Candidate &>(candidate) =
            legacyCandidate;
        candidate.fallbackUsed = false;
        candidate.targetAwRelation =
            NativeAwdlMifCurrentAw::TargetAwRelation::kFutureFromMifRx;
        candidate.targetAwStartForwardDeltaValid = true;
        candidate.targetAwStartOffsetUs = static_cast<int32_t>(
            legacyCandidate.targetAwStartDeltaUs);
        candidate.beforeRxUs = 0;
        output = candidate;
    }
    return status;
}

static bool sameDiscoveryMifCandidate(
    const NativeAwdlMifCurrentAw::Candidate &left,
    const NativeAwdlMifCurrentAw::Candidate &right)
{
    const Test066MifCurrentPhase::Candidate &a = left;
    const Test066MifCurrentPhase::Candidate &b = right;
    return a.earliestSubmitUs == b.earliestSubmitUs &&
        a.latestSubmitUs == b.latestSubmitUs &&
        a.receiveHostEarliestUs == b.receiveHostEarliestUs &&
        a.receiveHostLatestUs == b.receiveHostLatestUs &&
        a.targetAwStartDeltaUs == b.targetAwStartDeltaUs &&
        a.targetAwStartGp2Us == b.targetAwStartGp2Us &&
        a.nextEawGp2Us == b.nextEawGp2Us &&
        a.currentEawStartGp2Us == b.currentEawStartGp2Us &&
        a.currentSlot == b.currentSlot &&
        a.targetAwCounter == b.targetAwCounter &&
        a.peerIncarnation == b.peerIncarnation &&
        a.mifRevision == b.mifRevision &&
        Test066MifCurrentPhase::sameEpochs(a.epochs, b.epochs) &&
        a.status == b.status &&
        a.clockMappingVerified == b.clockMappingVerified &&
        a.airtimeVerified == b.airtimeVerified &&
        a.experimentalOnly == b.experimentalOnly &&
        left.fallbackUsed == right.fallbackUsed &&
        left.targetAwRelation == right.targetAwRelation &&
        left.targetAwStartForwardDeltaValid ==
            right.targetAwStartForwardDeltaValid &&
        left.targetAwStartOffsetUs == right.targetAwStartOffsetUs &&
        left.beforeRxUs == right.beforeRxUs;
}

static void recordDiscoveryCurrentAwPlan(
    P2PProbeRun *run, bool final,
    const Test066MifCurrentPhase::Input &input,
    const NativeAwdlMifCurrentAw::Candidate &candidate,
    Test066MifCurrentPhase::Status status,
    NativeAwdlMifCurrentAw::RejectReason rejectReason)
{
    if (!run)
        return;
    if (!final && run->discoveryCandidateLocked)
        return;
    if (final && run->discoveryConsumed)
        return;
    CurrentAwPlanRecord &record = final ? run->currentAwTrace.final :
                                         run->currentAwTrace.initial;
    record.input.timing = input;
    record.candidate = candidate;
    record.status = static_cast<uint32_t>(status);
    record.rejectReason = static_cast<uint32_t>(rejectReason);
    record.recorded = true;
}

static void recordDiscoveryCurrentAwAttempt(
    P2PProbeRun *run, bool final,
    const Test066MifCurrentPhase::Input &input,
    const NativeAwdlMifCurrentAw::Candidate &candidate,
    Test066MifCurrentPhase::Status status,
    uint64_t qmToken, uint64_t qmGeneration)
{
    if (!run || !qmToken || !qmGeneration)
        return;
    auto &observation = run->currentAwAttempt;
    if (!observation.captured) {
        observation.qmToken = qmToken;
        observation.qmGeneration = qmGeneration;
        observation.contextGeneration = input.currentEpochs.context;
        observation.powerGeneration = input.currentEpochs.power;
        observation.stationGeneration = input.currentEpochs.station;
        observation.rocGeneration = input.currentEpochs.roc;
        observation.plannerEpochsStable = true;
        observation.fallbackEnabled = run->currentAwTrace.fallbackEnabled;
        observation.captured = true;
    } else if (observation.contextGeneration != input.currentEpochs.context ||
               observation.powerGeneration != input.currentEpochs.power ||
               observation.stationGeneration != input.currentEpochs.station ||
               observation.rocGeneration != input.currentEpochs.roc) {
        observation.plannerEpochsStable = false;
    }
    if (observation.plannerCalls < 255u)
        ++observation.plannerCalls;

    CurrentAwAttemptPlan &plan = final ? observation.final :
                                         observation.initial;
    if (!final) {
        observation.qmToken = qmToken;
        observation.qmGeneration = qmGeneration;
    }
    plan.plannerNowUs = input.nowUs;
    plan.qmToken = qmToken;
    plan.qmGeneration = qmGeneration;
    plan.status = static_cast<uint32_t>(status);
    plan.candidateValid =
        status == Test066MifCurrentPhase::Status::kCandidate;
    plan.fallbackUsed = plan.candidateValid && candidate.fallbackUsed;
    plan.earliestSubmitUs = plan.candidateValid ? candidate.earliestSubmitUs : 0;
    plan.latestSubmitUs = plan.candidateValid ? candidate.latestSubmitUs : 0;
    plan.recorded = true;
}

static uint64_t discoveryCurrentAwOffsetMagnitude(int32_t offsetUs)
{
    const int64_t signedOffsetUs = static_cast<int64_t>(offsetUs);
    return static_cast<uint64_t>(signedOffsetUs < 0 ?
        -signedOffsetUs : signedOffsetUs);
}

static void bindDiscoveryCurrentAwTrace(
    P2PProbeRun *run, const Test066MifCurrentPhase::Input &input,
    const NativeAwdlBSD::DiscoveryTxSnapshot &head,
    uint64_t psfRevision)
{
    if (!run || run->currentAwTrace.identityCaptured)
        return;
    const auto &timing = input;
    const auto &mif = timing.mif;
    const auto &epochs = timing.currentEpochs;
    auto &trace = run->currentAwTrace;
    trace.qmToken = head.token;
    trace.qmGeneration = head.generation;
    trace.rocGeneration = epochs.roc;
    trace.peerIncarnation = mif.peerIncarnation;
    trace.psfRevision = psfRevision;
    trace.mifRevision = mif.mifRevision;
    trace.identityCaptured = true;
    trace.identityValid = head.token != 0 && head.generation != 0 &&
        head.generation == run->powerGeneration &&
        mif.peerIncarnation != 0 && mif.mifRevision != 0 &&
        timing.binding.sameEntryVerified &&
        timing.binding.historicalPsfSameEntryPresent &&
        psfRevision != 0 &&
        timing.binding.peerIncarnation == mif.peerIncarnation &&
        timing.binding.mifRevision == mif.mifRevision &&
        Test066MifCurrentPhase::sameEpochs(epochs, mif.epochs) &&
        Test066MifCurrentPhase::sameEpochs(epochs, timing.anchor.epochs) &&
        Test066MifCurrentPhase::sameEpochs(epochs, timing.binding.epochs) &&
        epochs.context == run->contextGeneration &&
        epochs.power == run->powerGeneration &&
        epochs.station == run->stationGeneration &&
        epochs.roc == run->contextGeneration;
    trace.inputValid = trace.identityValid && mif.present && mif.complete &&
        mif.type18Present && mif.type18Valid && mif.presenceModePresent &&
        mif.awCounterSemanticVerified && mif.syncConsistent &&
        mif.rxGp2Present && mif.fresh && mif.rxMonotonicUs != 0 &&
        timing.anchor.directReadBracket && timing.anchor.occurredBeforeRoc &&
        timing.anchor.firmwareResourcesAbsent &&
        timing.gates.hostMonotonicDomainVerified &&
        timing.gates.ownMifTxSucceeded && timing.gates.rocActive &&
        timing.gates.rocChannel6Confirmed &&
        timing.gates.peerMifRxChannel6Confirmed && !timing.gates.closing &&
        timing.gates.ringIdle && timing.gates.strictQmHeadStable;
}

struct CurrentAwPublishedPlan {
    NativeAwdlMifCurrentAw::PlanObservation observation;
    uint32_t legacyStatus;
    bool legacyStatusValid;
    bool descriptionValid;
    bool reconstructedReasonEquivalent;
    bool reconstructedGeometryEquivalent;
};

static CurrentAwPublishedPlan describeDiscoveryCurrentAwPlan(
    const CurrentAwPlanRecord &record, bool quiet, bool fallbackEnabled)
{
    CurrentAwPublishedPlan published{};
    if (!quiet || !record.recorded)
        return published;
    Test066MifCurrentPhase::Candidate legacyCandidate{};
    published.legacyStatus = static_cast<uint32_t>(
        Test066MifCurrentPhase::plan(record.input.timing, legacyCandidate));
    published.legacyStatusValid = true;
    if (!fallbackEnabled)
        return published;
    published.observation = NativeAwdlMifCurrentAw::describe(record.input);
    const auto &observation = published.observation;
    published.descriptionValid = observation.plannerNowValid;
    published.reconstructedReasonEquivalent = published.descriptionValid &&
        static_cast<uint32_t>(observation.status) == record.status &&
        static_cast<uint32_t>(observation.why) == record.rejectReason;
    if (record.status == static_cast<uint32_t>(
            Test066MifCurrentPhase::Status::kCandidate)) {
        const auto &candidate = record.candidate;
        const uint32_t reconstructedTargetAwStartGp2 =
            record.input.timing.mif.rxGp2Us + static_cast<uint32_t>(
                candidate.targetAwStartOffsetUs);
        const uint16_t reconstructedTargetAwCounter = static_cast<uint16_t>(
            record.input.timing.mif.awCounter +
            (candidate.fallbackUsed ? 0U : 1U));
        const uint8_t reconstructedCurrentSlot = static_cast<uint8_t>(
            (record.input.timing.mif.awCounter /
             Test066MifCurrentPhase::kAwPerEaw) %
            Test066MifCurrentPhase::kSlotCount);
        published.reconstructedGeometryEquivalent =
            published.reconstructedReasonEquivalent &&
            observation.candidateAvailable &&
            observation.geometryValid && observation.windowValid &&
            observation.receiveHostEarliestUs ==
                candidate.receiveHostEarliestUs &&
            observation.receiveHostLatestUs == candidate.receiveHostLatestUs &&
            observation.earliestSubmitUs == candidate.earliestSubmitUs &&
            observation.latestSubmitUs == candidate.latestSubmitUs &&
            observation.selectedRelationValid &&
            observation.selectedRelation == candidate.targetAwRelation &&
            observation.forwardDeltaValid ==
                candidate.targetAwStartForwardDeltaValid &&
            observation.targetAwStartOffsetUs ==
                candidate.targetAwStartOffsetUs &&
            observation.beforeRxUs == candidate.beforeRxUs &&
            reconstructedTargetAwStartGp2 ==
                candidate.targetAwStartGp2Us &&
            reconstructedTargetAwCounter == candidate.targetAwCounter &&
            reconstructedCurrentSlot == candidate.currentSlot;
    }
    return published;
}

static bool publishDiscoveryCurrentAwPlan(
    IOEthernetController *controller, const char *label,
    const CurrentAwPlanRecord &record, bool quiet,
    const CurrentAwPublishedPlan &published, bool fallbackEnabled)
{
    bool writesOk = true;
    auto set = [controller, label](const char *suffix, uint64_t value) {
        if (!controller)
            return false;
        char key[112];
        snprintf(key, sizeof(key), "NativeP2PCurrentAwTrace%s%s", label,
                 suffix);
        return controller->setProperty(key, value, 64);
    };
    using Status = Test066MifCurrentPhase::Status;
    using Relation = NativeAwdlMifCurrentAw::TargetAwRelation;
    const auto &observation = published.observation;
    const bool recordedCandidate = record.recorded &&
        record.status == static_cast<uint32_t>(Status::kCandidate);
    const bool geometryValid = published.descriptionValid &&
        observation.geometryValid;
    const bool windowValid = published.descriptionValid &&
        observation.windowValid;
    const bool relationValid = published.descriptionValid &&
        observation.selectedRelationValid;
    const bool freshnessValid = published.descriptionValid &&
        observation.freshnessUntilValid;
    const uint64_t offsetMagnitudeUs = discoveryCurrentAwOffsetMagnitude(
        relationValid ? observation.targetAwStartOffsetUs : 0);
    const uint64_t targetAwGp2 = recordedCandidate ?
        record.candidate.targetAwStartGp2Us : 0;
    const uint64_t targetAwCounter = recordedCandidate ?
        record.candidate.targetAwCounter : 0;
    const uint64_t currentSlot = recordedCandidate ?
        record.candidate.currentSlot : 0;

    const auto setChecked = [&writesOk, &set](const char *suffix,
                                              uint64_t value) {
        if (writesOk)
            writesOk = set(suffix, value);
    };
    setChecked("RecordedStatus", record.recorded ? record.status : 0);
    setChecked("RecordedRejectReason", record.recorded ? record.rejectReason : 0);
    setChecked("LegacyStatusValid", published.legacyStatusValid ? 1 : 0);
    setChecked("LegacyStatus", published.legacyStatusValid ?
        published.legacyStatus : 0);
    setChecked("LegacyStatus26", published.legacyStatusValid &&
        published.legacyStatus == static_cast<uint32_t>(
            Status::kNoConservativeWindow) ? 1 : 0);
    setChecked("RecordedCandidateAvailable", recordedCandidate ? 1 : 0);
    setChecked("RecordedFallbackAttempted",
        fallbackEnabled && record.recorded &&
            (record.candidate.fallbackUsed ||
            (record.status == static_cast<uint32_t>(
                Status::kNoConservativeWindow))) ? 1 : 0);
    setChecked("RecordedFallbackUsed",
        recordedCandidate && record.candidate.fallbackUsed ? 1 : 0);
    setChecked("DescriptionValid", published.descriptionValid ? 1 : 0);
    setChecked("DescriptionStatus", published.descriptionValid ?
        static_cast<uint32_t>(observation.status) : 0);
    setChecked("DescriptionRejectReason", published.descriptionValid ?
        static_cast<uint32_t>(observation.why) : 0);
    setChecked("ReconstructedGeometryEquivalent",
        published.reconstructedGeometryEquivalent ? 1 : 0);
    setChecked("ReconstructedReasonEquivalent",
        published.reconstructedReasonEquivalent ? 1 : 0);
    setChecked("FallbackAttempted", published.descriptionValid &&
        observation.fallbackAttempted ? 1 : 0);
    setChecked("FallbackUsed", recordedCandidate &&
        record.candidate.fallbackUsed ? 1 : 0);
    setChecked("Relation", relationValid ?
        static_cast<uint32_t>(observation.selectedRelation) :
        static_cast<uint32_t>(Relation::kNotApplicable));
    setChecked("RelationValid", relationValid ? 1 : 0);
    setChecked("ForwardDeltaValid", published.descriptionValid &&
        observation.forwardDeltaValid ? 1 : 0);
    setChecked("OffsetMagnitudeUs", relationValid ? offsetMagnitudeUs : 0);
    setChecked("BeforeRxUs", relationValid ? observation.beforeRxUs : 0);
    setChecked("GeometryValid", geometryValid ? 1 : 0);
    setChecked("WindowValid", windowValid ? 1 : 0);
    setChecked("RxHostEarliestUs", geometryValid ?
        observation.receiveHostEarliestUs : 0);
    setChecked("RxHostLatestUs", geometryValid ?
        observation.receiveHostLatestUs : 0);
    setChecked("FreshnessUntilValid", freshnessValid ? 1 : 0);
    setChecked("FreshnessUntilUs", freshnessValid ?
        observation.freshnessUntilUs : 0);
    setChecked("EarliestSubmitUs", windowValid ? observation.earliestSubmitUs : 0);
    setChecked("LatestSubmitUs", windowValid ? observation.latestSubmitUs : 0);
    setChecked("TargetAwStartGp2Us", recordedCandidate ? targetAwGp2 : 0);
    setChecked("TargetAwCounter", recordedCandidate ? targetAwCounter : 0);
    setChecked("CurrentSlot", recordedCandidate ? currentSlot : 0);
    (void)quiet;
    return writesOk;
}

static void invalidateDiscoveryCurrentAwTrace(
    IOEthernetController *controller)
{
    if (!controller)
        return;
    // Reuse interned keys only. existingSymbolForCString performs lookup without
    // creating a symbol, so invalidation needs no new allocation after a failed
    // setProperty. Removing the commit marker first makes a stale even payload
    // unpublishable; remove version endpoints and optional diagnostics so a
    // failed write cannot leave a blocker mask from an earlier run.
    const char *keys[] = {
        "NativeP2PCurrentAwTraceComplete",
        "NativeP2PCurrentAwTraceSnapshotVersionBegin",
        "NativeP2PCurrentAwTraceSnapshotVersionEnd",
        "NativeP2PCurrentAwTraceQuiet",
        "NativeP2PCurrentAwTraceQuietBlockerMask",
    };
    for (const char *key : keys) {
        const OSSymbol *symbol = OSSymbol::existingSymbolForCString(key);
        if (symbol) {
            controller->removeProperty(symbol);
            symbol->release();
        }
    }
}

static void invalidateDiscoveryCurrentAwAttempt(IOEthernetController *controller)
{
    if (!controller)
        return;
    const OSSymbol *symbol = OSSymbol::existingSymbolForCString(
        "NativeP2PCurrentAwAttemptOnly");
    if (symbol) {
        controller->removeProperty(symbol);
        symbol->release();
    }
}

static bool publishDiscoveryCurrentAwAttempt(P2PProbeRun *run)
{
    auto *owner = run ? run->owner : nullptr;
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!run || !controller || !owner->tahoeP2pOnMainGate() ||
        !run->discoveryModeSelected || run->discoveryMode !=
            NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot)
        return false;

    auto &observation = run->currentAwAttempt;
    if (!observation.captured || observation.published ||
        (!observation.initial.recorded && !observation.final.recorded))
        return false;
    if (!observation.qmToken || !observation.qmGeneration ||
        observation.contextGeneration != run->contextGeneration ||
        observation.powerGeneration != run->powerGeneration ||
        observation.stationGeneration != run->stationGeneration) {
        invalidateDiscoveryCurrentAwAttempt(controller);
        return false;
    }

    CurrentAwAttemptOnlyPayload snapshot{};
    snapshot.magic = 0x41574143u; // byte order spells "CAWA"
    snapshot.schema = 1;
    snapshot.evidenceClass = 1; // attempt-only; never TX/peer proof
    snapshot.complete = 1;
    snapshot.peerReceiptProven = 0;
    snapshot.radioTransmitProven = 0;
    snapshot.fallbackEnabled = observation.fallbackEnabled ? 1 : 0;
    snapshot.initialPresent = observation.initial.recorded ? 1 : 0;
    snapshot.finalPresent = observation.final.recorded ? 1 : 0;
    snapshot.initialCandidateValid =
        observation.initial.candidateValid ? 1 : 0;
    snapshot.finalCandidateValid = observation.final.candidateValid ? 1 : 0;
    snapshot.initialFallbackUsed = observation.initial.fallbackUsed ? 1 : 0;
    snapshot.finalFallbackUsed = observation.final.fallbackUsed ? 1 : 0;
    const bool sameQmIdentity = observation.initial.recorded &&
        observation.final.recorded &&
        observation.initial.qmToken == observation.final.qmToken &&
        observation.initial.qmGeneration == observation.final.qmGeneration;
    snapshot.consistencyFlags =
        (sameQmIdentity ? 1u : 0u) |
        ((observation.initial.recorded && observation.final.recorded &&
          observation.plannerEpochsStable) ? 2u : 0u);
    snapshot.contextGeneration = observation.contextGeneration;
    snapshot.powerGeneration = observation.powerGeneration;
    snapshot.stationGeneration = observation.stationGeneration;
    snapshot.rocGeneration = observation.rocGeneration;
    snapshot.qmToken = observation.qmToken;
    snapshot.qmGeneration = observation.qmGeneration;
    snapshot.initialPlannerNowUs = observation.initial.plannerNowUs;
    snapshot.finalPlannerNowUs = observation.final.plannerNowUs;
    snapshot.plannerCalls = observation.plannerCalls;
    snapshot.initialStatus = observation.initial.status;
    snapshot.finalStatus = observation.final.status;
    snapshot.initialEarliestSubmitUs =
        observation.initial.earliestSubmitUs;
    snapshot.initialLatestSubmitUs = observation.initial.latestSubmitUs;
    snapshot.finalEarliestSubmitUs = observation.final.earliestSubmitUs;
    snapshot.finalLatestSubmitUs = observation.final.latestSubmitUs;

    OSData *payload = OSData::withBytes(&snapshot, sizeof(snapshot));
    if (!payload) {
        invalidateDiscoveryCurrentAwAttempt(controller);
        return false;
    }
    const bool published = controller->setProperty(
        "NativeP2PCurrentAwAttemptOnly", payload);
    payload->release();
    if (!published) {
        invalidateDiscoveryCurrentAwAttempt(controller);
        return false;
    }
    observation.published = true;
    return true;
}

static void publishDiscoveryCurrentAwTrace(P2PProbeRun *run, bool quiet)
{
    auto *owner = run ? run->owner : nullptr;
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!run || !controller || !owner->tahoeP2pOnMainGate() ||
        !run->discoveryModeSelected || run->discoveryMode !=
            NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot ||
        run->currentAwTrace.published)
        return;

    auto &trace = run->currentAwTrace;
    const uint64_t version = static_cast<uint64_t>(run->contextGeneration) * 2u;
    const uint64_t evenVersion = version ? version : 2u;
    const uint64_t writingVersion = evenVersion - 1u;
    bool writesOk = true;
    auto set = [controller](const char *suffix, uint64_t value) {
        if (!controller)
            return false;
        char key[112];
        snprintf(key, sizeof(key), "NativeP2PCurrentAwTrace%s", suffix);
        return controller->setProperty(key, value, 64);
    };

    // A non-quiet exit has no stable trace to publish. Mark the snapshot
    // incomplete and publish only the bounded cleanup blockers; do not
    // reconstruct planner inputs or write a partial payload.
    if (!quiet) {
        if (!set("SnapshotVersionBegin", writingVersion)) {
            invalidateDiscoveryCurrentAwTrace(controller);
            return;
        }
        if (!set("Complete", 0)) {
            invalidateDiscoveryCurrentAwTrace(controller);
            return;
        }
        if (!set("Quiet", 0) ||
            !set("QuietBlockerMask", trace.quietBlockerMask)) {
            invalidateDiscoveryCurrentAwTrace(controller);
            return;
        }
        return;
    }

    const CurrentAwPublishedPlan initialDescription =
        describeDiscoveryCurrentAwPlan(trace.initial, true,
                                       trace.fallbackEnabled);
    const CurrentAwPublishedPlan finalDescription =
        describeDiscoveryCurrentAwPlan(trace.final, true,
                                      trace.fallbackEnabled);
    auto setChecked = [&writesOk, &set](const char *suffix, uint64_t value) {
        if (writesOk)
            writesOk = set(suffix, value);
    };
    if (!set("SnapshotVersionBegin", writingVersion)) {
        invalidateDiscoveryCurrentAwTrace(controller);
        return;
    }
    writesOk = true;
    setChecked("Schema", 1);
    setChecked("Complete", 0);
    setChecked("Quiet", quiet ? 1 : 0);
    setChecked("QuietBlockerMask", trace.quietBlockerMask);
    setChecked("FallbackEnabled", trace.fallbackEnabled ? 1 : 0);
    setChecked("ContextGeneration", run->contextGeneration);
    setChecked("PowerGeneration", run->powerGeneration);
    setChecked("StationGeneration", run->stationGeneration);
    setChecked("RocGeneration", trace.rocGeneration);
    setChecked("PeerIncarnation", trace.peerIncarnation);
    setChecked("PsfRevision", trace.psfRevision);
    setChecked("MifRevision", trace.mifRevision);
    setChecked("QmToken", trace.qmToken);
    setChecked("QmGeneration", trace.qmGeneration);
    setChecked("IdentityValid", trace.identityValid ? 1 : 0);
    setChecked("InputValid", trace.inputValid ? 1 : 0);
    setChecked("InitialPlanValid", trace.initial.recorded ? 1 : 0);
    setChecked("FinalPlanValid", trace.final.recorded ? 1 : 0);
    setChecked("FinalCompareValid", trace.finalCompareValid ? 1 : 0);
    setChecked("FinalCompareMatch", trace.finalCompareMatch ? 1 : 0);
    setChecked("RxProducerClosed", trace.rxProducerClosed ? 1 : 0);
    setChecked("RxDrainComplete", trace.rxDrainComplete ? 1 : 0);

    if (trace.initial.recorded) {
        const auto &input = trace.initial.input.timing;
        setChecked("PlannerNowUs", input.nowUs);
        setChecked("MifRxHostUs", input.mif.rxMonotonicUs);
        setChecked("MifRxGp2Us", input.mif.rxGp2Us);
        setChecked("MifPhyTxUs", input.mif.phyTxTimestampUs);
        setChecked("MifTargetTxUs", input.mif.targetTxTimestampUs);
        setChecked("MifTxDownCounterTu", input.mif.txDownCounterTu);
        setChecked("MifAwCounter", input.mif.awCounter);
        setChecked("MifCurrentSlot", (input.mif.awCounter /
            Test066MifCurrentPhase::kAwPerEaw) %
            Test066MifCurrentPhase::kSlotCount);
        setChecked("OwnFirstMifCompletionUs",
            input.gates.firstOwnMifCompletionUs);
        setChecked("LeaseStartUs", input.leaseStartUs);
        setChecked("LeaseEndUs", input.leaseEndUs);
    } else {
        setChecked("PlannerNowUs", 0);
        setChecked("MifRxHostUs", 0);
        setChecked("MifRxGp2Us", 0);
        setChecked("MifPhyTxUs", 0);
        setChecked("MifTargetTxUs", 0);
        setChecked("MifTxDownCounterTu", 0);
        setChecked("MifAwCounter", 0);
        setChecked("MifCurrentSlot", 0);
        setChecked("OwnFirstMifCompletionUs", 0);
        setChecked("LeaseStartUs", 0);
        setChecked("LeaseEndUs", 0);
    }
    setChecked("FinalNowUs", trace.final.recorded ?
        trace.final.input.timing.nowUs : 0);
    if (writesOk)
        writesOk = publishDiscoveryCurrentAwPlan(controller, "Initial",
            trace.initial, quiet, initialDescription,
            trace.fallbackEnabled);
    if (writesOk)
        writesOk = publishDiscoveryCurrentAwPlan(controller, "Final",
            trace.final, quiet, finalDescription,
            trace.fallbackEnabled);
    if (!writesOk || !set("Complete", 1) ||
        !set("SnapshotVersionEnd", evenVersion) ||
        !set("SnapshotVersionBegin", evenVersion)) {
        invalidateDiscoveryCurrentAwTrace(controller);
        return;
    }
    trace.published = true;
}

static void publishDiscoveryExperiment(P2PProbeRun *run, bool force = false)
{
    auto *owner = run ? run->owner : nullptr;
    auto *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller || !owner->tahoeP2pOnMainGate() ||
        !discoveryExperimentEnabled(owner) ||
        (!force && run->discoveryPublishVersion != 0 &&
         run->discoveryLastPublishedStatus == run->discoveryStatus &&
         run->discoveryLastPublishedPrerequisiteBlockers ==
             run->discoveryPrerequisiteBlockers &&
         run->discoveryLastPublishedBindingFailureReason ==
             run->discoveryBindingFailureReason))
        return;
    const uint32_t version = run->discoveryPublishVersion + 2;
    auto set = [controller](const char *suffix, uint64_t value) {
        char key[96];
        snprintf(key, sizeof(key), "NativeP2PDiscovery%s", suffix);
        controller->setProperty(key, value, 64);
    };
    set("SnapshotVersionBegin", version - 1);
    // Schema 2 carries numeric, address-free runtime-MIF binding and compact
    // Test069 blocker evidence. Schema-1 fields retain their meanings.
    set("Schema", 2);
    set("ContextGeneration", run->contextGeneration);
    set("PowerGeneration", run->powerGeneration);
    set("StationGeneration", run->stationGeneration);
    set("Status", run->discoveryStatus);
    set("FormalObserverPeerCount", run->discoveryFormalObserverPeerCount);
    set("RuntimeMifBindingRequired", run->discoveryRequiresRuntimeMifBinding);
    set("RuntimeMifBindingValid", run->discoveryRuntimeMifBound);
    set("RuntimePeerIncarnation", run->discoveryPeerIncarnation);
    set("RuntimePsfRevision", run->discoveryPsfRevision);
    set("RuntimeMifRevision", run->discoveryMifRevision);
    set("HistoryCompatible", run->discoveryHistoryCompatible ? 1 : 0);
    set("ModeSelected", run->discoveryModeSelected ? 1 : 0);
    set("Mode", static_cast<uint32_t>(run->discoveryMode));
    set("RuntimeMifRequirementSelected",
        run->discoveryRuntimeMifRequirementSelected ? 1 : 0);
    set("MifTimingStatus", run->discoveryMifTimingStatus);
    set("MifFirstCompletionUs", run->discoveryOwnFirstMifCompletionUs);
    set("MifCurrentSlot", run->discoveryMifTarget.currentSlot);
    set("MifEarliestSubmitUs",
        run->discoveryMifTarget.earliestSubmitUs);
    set("MifLatestSubmitUs", run->discoveryMifTarget.latestSubmitUs);
    set("MifTargetAwStartGp2", run->discoveryMifTarget.targetAwStartGp2Us);
    set("MifTargetAwCounter", run->discoveryMifTarget.targetAwCounter);
    set("BindingFailureReason", run->discoveryBindingFailureReason);
    set("PrerequisiteBlockers", run->discoveryPrerequisiteBlockers);
    set("PhaseStatus", run->discoveryPhaseStatus);
    set("Checks", run->discoveryChecks);
    set("Consumed", run->discoveryConsumed);
    set("CandidateLocked", run->discoveryCandidateLocked);
    set("WindowClosed", run->discoveryWindowClosed);
    set("PacketToken", run->discoveryPacketToken);
    set("PsfObservedUs", run->discoveryPsfObservedUs);
    set("EstimatedEarliestSubmitUs", run->discoveryTarget.earliestSubmitUs);
    set("EstimatedLatestSubmitUs", run->discoveryTarget.latestSubmitUs);
    set("EstimatedTargetGp2", run->discoveryTarget.targetGp2Raw);
    set("ScheduleRevision", run->discoveryTarget.scheduleRevision);
    set("SubmitCallStartUs", run->discoverySubmitCallStartUs);
    set("SubmitCallEndUs", run->discoverySubmitCallEndUs);
    set("Doorbelled", run->discoveryDoorbelled);
    set("SubmitResult", static_cast<uint32_t>(run->discoverySubmitResult));
    set("PacketLimit", 1);
    set("ExperimentalOnly", 1);
    set("ClockMappingVerified", 0);
    set("AirtimeVerified", 0);
    set("FormalPeerPolicyChanged", 0);
    // Once the provisional head is consumed, this experiment sends no other
    // native packet. These final BSD deltas can therefore identify its one
    // local firmware transaction without borrowing a later frame's status.
    const auto data = NativeAwdlBSD::snapshot();
    const uint64_t completed = data.value[NativeAwdlBSD::TxCompleted];
    const uint64_t succeeded = data.value[NativeAwdlBSD::TxSucceeded];
    const bool deltaValid = run->discoveryConsumed &&
        completed >= run->discoveryCompletedBaseline &&
        succeeded >= run->discoverySucceededBaseline &&
        completed - run->discoveryCompletedBaseline <= 1 &&
        succeeded - run->discoverySucceededBaseline <= 1;
    set("LocalCompletionCount", deltaValid ? completed - run->discoveryCompletedBaseline : 0);
    set("LocalSuccessCount", deltaValid ? succeeded - run->discoverySucceededBaseline : 0);
    set("LocalOutcomeKnown", deltaValid && completed - run->discoveryCompletedBaseline == 1);
    set("SnapshotVersionEnd", version);
    set("SnapshotVersionBegin", version);
    run->discoveryPublishVersion = version;
    run->discoveryLastPublishedStatus = run->discoveryStatus;
    run->discoveryLastPublishedPrerequisiteBlockers =
        run->discoveryPrerequisiteBlockers;
    run->discoveryLastPublishedBindingFailureReason =
        run->discoveryBindingFailureReason;
}

static bool discoveryNumber(IOEthernetController *controller,
                             const char *key, uint64_t &out)
{
    auto *number = controller ? OSDynamicCast(OSNumber,
        controller->getProperty(key)) : nullptr;
    if (!number)
        return false;
    out = number->unsigned64BitValue();
    return true;
}

static bool discoveryAnchor(P2PProbeRun *run,
                             NativeAwdlDiscoveryPhase::PreRocGp2Anchor &out)
{
    auto *controller = run->owner->tahoeP2pController();
    uint64_t status = 0, generation = 0, power = 0, station = 0, raw = 0;
    NativeAwdlDiscoveryPhase::PreRocGp2Anchor anchor{};
    if (!discoveryNumber(controller, "NativeP2PGp2PreStatus", status) || status != 1 ||
        !discoveryNumber(controller, "NativeP2PGp2PreGeneration", generation) || generation != run->contextGeneration ||
        !discoveryNumber(controller, "NativeP2PGp2PowerGeneration", power) || power != run->powerGeneration ||
        !discoveryNumber(controller, "NativeP2PGp2StationGeneration", station) || station != run->stationGeneration ||
        !discoveryNumber(controller, "NativeP2PGp2PreValue", raw) || raw > UINT32_MAX ||
        !discoveryNumber(controller, "NativeP2PGp2PreHostBeforeUs", anchor.hostBeforeUs) ||
        !discoveryNumber(controller, "NativeP2PGp2PreHostAfterUs", anchor.hostAfterUs))
        return false;
    anchor.rawGp2 = static_cast<uint32_t>(raw);
    anchor.epochs = {run->contextGeneration, run->powerGeneration,
                     run->stationGeneration, run->contextGeneration};
    // PreStatus==1 is published only by the actual pre-ROC sampler after
    // clockResourcesAbsent() and the matching-epoch recheck. Read only those
    // immutable scalar observations here; never acquire a NIC/PRPH lock.
    anchor.directReadBracket = true;
    anchor.firmwareResourcesAbsent = true;
    anchor.occurredBeforeRoc = anchor.hostAfterUs <= run->psfCandidate.startObservedUs;
    out = anchor;
    return true;
}

static NativeAwdlDiscoveryPhase::PsfWitness discoveryPsf(
    const IntelAwdlPeerRuntime::PsfPeerSnapshot &psf, uint8_t,
    const NativeAwdlDiscoveryPhase::Epochs &epochs)
{
    NativeAwdlDiscoveryPhase::PsfWitness out{};
    // The runtime table assigns this opaque token when its private source-keyed
    // Entry is created/replaced. PSF and MIF snapshots share this incarnation.
    out.peerToken = psf.peerIncarnation;
    out.scheduleRevision = psf.psfRevision;
    out.epochs = epochs;
    out.rxHostUs = psf.psfRxMonotonicUs;
    out.rxGp2 = psf.psfRxGp2TimestampUs;
    out.phyTxTimestampUs = psf.phyTxTimestampUs;
    out.targetTxTimestampUs = psf.targetTxTimestampUs;
    out.awCounter = psf.nextAwSequence;
    out.txDownTu = psf.txDownCounterTu;
    out.awPeriodTu = psf.awPeriodTu;
    // decodePsf rejects every presence mode except 4 before publishing a
    // syncConsistent table entry. Do not take it from a global last-frame TLV.
    out.presenceMode = 4;
    out.rxChannel = 6;
    memcpy(out.canonicalChannels, psf.channelSlots, sizeof(out.canonicalChannels));
    out.complete = psf.tracked && psf.hasPsf && psf.psfFresh &&
        psf.syncConsistent && psf.psfRxGp2TimestampPresent &&
        psf.contextGeneration == epochs.context &&
        psf.powerGeneration == epochs.power &&
        psf.stationGeneration == epochs.station;
    return out;
}

// MIF-current-slot mode keeps PSF only as same-entry history. In particular,
// it must not synthesize a channel-6/fresh PSF witness or feed PSF timing into
// the MIF phase estimator.
static NativeAwdlDiscoveryPhase::PsfWitness discoveryPsfHistory(
    const IntelAwdlPeerRuntime::PsfPeerSnapshot &psf,
    const NativeAwdlDiscoveryPhase::Epochs &epochs)
{
    NativeAwdlDiscoveryPhase::PsfWitness out{};
    out.peerToken = psf.peerIncarnation;
    out.scheduleRevision = psf.psfRevision;
    out.epochs = epochs;
    out.rxHostUs = psf.psfRxMonotonicUs;
    out.rxGp2 = psf.psfRxGp2TimestampUs;
    out.phyTxTimestampUs = psf.phyTxTimestampUs;
    out.targetTxTimestampUs = psf.targetTxTimestampUs;
    out.awCounter = psf.nextAwSequence;
    out.txDownTu = psf.txDownCounterTu;
    out.awPeriodTu = psf.awPeriodTu;
    // The runtime snapshot does not export PSF presence-mode provenance.
    // Zero plus complete=false accurately represents history-only use.
    out.presenceMode = 0;
    out.rxChannel = psf.rxChannel <= UINT8_MAX ?
        static_cast<uint8_t>(psf.rxChannel) : 0xffu;
    memcpy(out.canonicalChannels, psf.channelSlots,
           sizeof(out.canonicalChannels));
    out.complete = false;
    return out;
}

static NativeAwdlDiscoveryBinding::Snapshot discoveryBindingSnapshot(
    const IntelAwdlPeerRuntime::PsfPeerSnapshot &source,
    const NativeAwdlDiscoveryPhase::Epochs &epochs, uint64_t nowUs,
    bool mifRxChannel6, NativeAwdlDiscoveryBinding::Mode mode)
{
    NativeAwdlDiscoveryBinding::Snapshot out{};
    out.mode = mode;
    out.psfHistorySameEntryPresent = source.tracked && source.hasPsf;
    out.historyCompatible = source.historyCompatible;
    out.psf = mode == NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot ?
        discoveryPsfHistory(source, epochs) : discoveryPsf(source, 0, epochs);
    out.peerIncarnation = source.peerIncarnation;
    out.psfRevision = source.psfRevision;
    out.mifRevision = source.mifRevision;
    out.mifRxMonotonicUs = source.mifRxMonotonicUs;
    out.mifAgeUs = source.mifAgeUs;
    out.psfAgeUs = source.psfAgeUs;
    out.hasMif = source.hasMif;
    out.mifFresh = source.mifFresh;
    out.mifSyncConsistent = source.mifSyncConsistent;
    out.mifRxChannel6 = mifRxChannel6;
    out.mif.peerIncarnation = source.mif.peerIncarnation;
    out.mif.mifRevision = source.mif.mifRevision;
    out.mif.rxMonotonicUs = source.mif.rxMonotonicUs;
    out.mif.rxAgeUs = source.mif.rxAgeUs;
    out.mif.epochs = {source.mif.contextGeneration,
                      source.mif.powerGeneration,
                      source.mif.stationGeneration, epochs.roc};
    out.mif.rxGp2Us = source.mif.rxGp2Us;
    out.mif.phyTxTimestampUs = source.mif.phyTxTimestampUs;
    out.mif.targetTxTimestampUs = source.mif.targetTxTimestampUs;
    out.mif.awCounter = source.mif.awCounter;
    out.mif.txDownCounterTu = source.mif.txDownCounterTu;
    out.mif.awPeriodTu = source.mif.awPeriodTu;
    out.mif.presenceMode = source.mif.presenceMode;
    out.mif.rxChannel = source.mif.rxChannel;
    memcpy(out.mif.canonicalSlots, source.mif.canonicalSlots,
           sizeof(out.mif.canonicalSlots));
    out.mif.present = source.mif.present;
    out.mif.complete = source.mif.complete;
    out.mif.syncConsistent = source.mif.syncConsistent;
    out.mif.fresh = source.mif.fresh;
    out.mif.rxGp2Present = source.mif.rxGp2Present;
    out.mif.presenceModePresent = source.mif.presenceModePresent;
    out.mif.awCounterSemanticVerified =
        source.mif.awCounterSemanticVerified;
    out.mif.type18Present = source.mif.type18Present;
    out.mif.type18Valid = source.mif.type18Valid;
    out.mif.peerMifRxChannel6Confirmed = mifRxChannel6;
    (void)nowUs; // Ages were captured by the same serialized table read.
    return out;
}

static Test066MifCurrentPhase::MifTimingWitness discoveryMifTimingWitness(
    const NativeAwdlDiscoveryBinding::MifWitness &source)
{
    Test066MifCurrentPhase::MifTimingWitness out{};
    out.peerIncarnation = source.peerIncarnation;
    out.mifRevision = source.mifRevision;
    out.rxMonotonicUs = source.rxMonotonicUs;
    out.epochs = {source.epochs.context, source.epochs.power,
                  source.epochs.station, source.epochs.roc};
    out.rxGp2Us = source.rxGp2Us;
    out.phyTxTimestampUs = source.phyTxTimestampUs;
    out.targetTxTimestampUs = source.targetTxTimestampUs;
    out.awCounter = source.awCounter;
    out.txDownCounterTu = source.txDownCounterTu;
    out.awPeriodTu = source.awPeriodTu;
    out.presenceMode = source.presenceMode;
    out.rxChannel = source.rxChannel;
    memcpy(out.canonicalSlots, source.canonicalSlots,
           sizeof(out.canonicalSlots));
    out.present = source.present;
    out.complete = source.complete;
    out.syncConsistent = source.syncConsistent;
    out.fresh = source.fresh;
    out.rxGp2Present = source.rxGp2Present;
    out.presenceModePresent = source.presenceModePresent;
    out.awCounterSemanticVerified = source.awCounterSemanticVerified;
    out.type18Present = source.type18Present;
    out.type18Valid = source.type18Valid;
    return out;
}

static bool sameDiscoveryHead(
    const NativeAwdlBSD::DiscoveryTxSnapshot &left,
    const NativeAwdlBSD::DiscoveryTxSnapshot &right)
{
    return left.token == right.token && left.bornUs == right.bornUs &&
        left.generation == right.generation &&
        left.queryClass == right.queryClass && left.eligible == right.eligible;
}

static NativeAwdlDiscoveryBinding::Decision mifCurrentPeerFailure(
    uint32_t blockers)
{
    if (blockers & Test069MifCurrentAdmission::kNoSelectedSlot)
        return NativeAwdlDiscoveryBinding::Decision::kMissingMifBinding;
    if (blockers & Test069MifCurrentAdmission::kPeerIncarnationMismatch)
        return NativeAwdlDiscoveryBinding::Decision::kPeerIncarnationChanged;
    if (blockers & Test069MifCurrentAdmission::kPsfRevisionMismatch)
        return NativeAwdlDiscoveryBinding::Decision::kPsfRevisionChanged;
    if (blockers & Test069MifCurrentAdmission::kMifRevisionMismatch)
        return NativeAwdlDiscoveryBinding::Decision::kMifRevisionChanged;
    if (blockers & Test069MifCurrentAdmission::kEpochMismatch)
        return NativeAwdlDiscoveryBinding::Decision::kEpochMismatch;
    if (blockers & (Test069MifCurrentAdmission::kMifWitnessMismatch |
                    Test069MifCurrentAdmission::kPeerMifChannelMismatch))
        return NativeAwdlDiscoveryBinding::Decision::kMifWitnessMismatch;
    if (blockers & Test069MifCurrentAdmission::kStrictQmHeadUnstable)
        return NativeAwdlDiscoveryBinding::Decision::kQueueHeadChanged;
    return NativeAwdlDiscoveryBinding::Decision::kInvalidSnapshot;
}

static uint32_t mifCurrentDecisionBlocker(
    NativeAwdlDiscoveryBinding::Decision decision)
{
    using Test069MifCurrentAdmission::kClosing;
    using Test069MifCurrentAdmission::kEpochMismatch;
    using Test069MifCurrentAdmission::kMifRevisionMismatch;
    using Test069MifCurrentAdmission::kMifWitnessMismatch;
    using Test069MifCurrentAdmission::kPeerIncarnationMismatch;
    using Test069MifCurrentAdmission::kPeerMifChannelMismatch;
    using Test069MifCurrentAdmission::kPsfRevisionMismatch;
    using Test069MifCurrentAdmission::kRocInactive;
    using Test069MifCurrentAdmission::kStrictQmHeadUnstable;
    using Test069MifCurrentAdmission::kTimingRejected;
    switch (decision) {
    case NativeAwdlDiscoveryBinding::Decision::kPeerIncarnationChanged:
        return kPeerIncarnationMismatch;
    case NativeAwdlDiscoveryBinding::Decision::kPsfRevisionChanged:
        return kPsfRevisionMismatch;
    case NativeAwdlDiscoveryBinding::Decision::kMifRevisionChanged:
        return kMifRevisionMismatch;
    case NativeAwdlDiscoveryBinding::Decision::kMifWitnessMismatch:
    case NativeAwdlDiscoveryBinding::Decision::kIncompleteMifWitness:
    case NativeAwdlDiscoveryBinding::Decision::kMissingMifBinding:
    case NativeAwdlDiscoveryBinding::Decision::kHistoryIncompatible:
        return kMifWitnessMismatch;
    case NativeAwdlDiscoveryBinding::Decision::kEpochMismatch:
        return kEpochMismatch;
    case NativeAwdlDiscoveryBinding::Decision::kChannelMismatch:
        return kPeerMifChannelMismatch;
    case NativeAwdlDiscoveryBinding::Decision::kRocInactive:
        return kRocInactive;
    case NativeAwdlDiscoveryBinding::Decision::kWindowClosed:
        return kClosing;
    case NativeAwdlDiscoveryBinding::Decision::kQueueHeadInvalid:
    case NativeAwdlDiscoveryBinding::Decision::kQueueHeadChanged:
        return kStrictQmHeadUnstable;
    default:
        return kTimingRejected;
    }
}

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
// Record only after the BSD bridge confirms that the exact selected QM
// candidate was consumed. `bornUs` is its enqueue timestamp; the returned
// token may be zero when encoding failed, so the snapshot token remains the
// authoritative identity for that outcome. This recorder is observational:
// status never changes packet ownership, admission, or retry behavior.
static void recordNativeDataTxConsumption(
    P2PProbeRun *run,
    const NativeAwdlBSD::DiscoveryTxSnapshot &head,
    bool encodedMpduAvailable)
{
    ItlIwx *owner = run ? run->owner : nullptr;
    if (!owner || !owner->tahoeP2pOnMainGate() || !head.token ||
        !head.bornUs || !run->contextGeneration || !head.generation ||
        !run->stationGeneration)
        return;

    NativeAwdlDataTxTrace::Identity identity{};
    identity.token = head.token;
    identity.diagnosticGeneration = run->contextGeneration;
    identity.contextGeneration = run->contextGeneration;
    identity.powerGeneration = head.generation;
    identity.stationGeneration = run->stationGeneration;
    identity.rocGeneration = run->contextGeneration;

    TahoeP2PActionTxContext &context = owner->nativeP2pActionTx_;
    NativeAwdlDataTxTrace::Ledger &trace = context.dataTxTrace;
    if (trace.beginToken(identity, head.bornUs, head.queryClass,
                         head.eligible) !=
        NativeAwdlDataTxTrace::Status::Ready)
        return;

    const uint64_t dequeuedAtUs =
        p2pProbeMonotonicNanoseconds() / 1000ULL;
    (void)trace.markDequeued(identity, dequeuedAtUs);
    if (!encodedMpduAvailable) {
        const uint64_t failedAtUs =
            p2pProbeMonotonicNanoseconds() / 1000ULL;
        (void)trace.markEncodeFailure(head.token, EINVAL, failedAtUs);
    }
}
#endif

static mbuf_t takeDiscoveryPacketPsfNextSlot(P2PProbeRun *run,
    const IntelAwdlPeer::RuntimeEpochs &epochs, uint16_t sequence,
    uint64_t *token, bool requireRuntimeMifBinding)
{
    auto *owner = run->owner;
    if (!run->discoveryRuntimeMifRequirementSelected) {
        run->discoveryRuntimeMifRequirementSelected = true;
        run->discoveryRequiresRuntimeMifBinding =
            requireRuntimeMifBinding;
    } else if (requireRuntimeMifBinding !=
               run->discoveryRequiresRuntimeMifBinding) {
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kMissingMifBinding);
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 17;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    const bool selectedRuntimeMifRequirement =
        run->discoveryRequiresRuntimeMifBinding;
    if (run->discoveryCandidateLocked &&
        selectedRuntimeMifRequirement !=
            run->discoveryRequiresRuntimeMifBinding) {
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kMissingMifBinding);
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 17;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (!discoveryExperimentEnabled(owner) || run->discoveryConsumed ||
        run->discoveryWindowClosed ||
        run->nativeDataAttempts != 0 || !owner->tahoeP2pOnMainGate())
        return nullptr;
    ++run->discoveryChecks;
    NativeAwdlBSD::DiscoveryTxSnapshot head{};
    if (!NativeAwdlBSD::peekDiscoveryTx(run->powerGeneration, &head)) {
        run->discoveryStatus = 3; // No current eligible QM candidate in the queue.
        if (run->discoveryCandidateLocked)
            run->discoveryWindowClosed = true;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (run->discoveryCandidateLocked &&
        (head.token != run->discoveryHead.token ||
         head.bornUs != run->discoveryHead.bornUs ||
         head.generation != run->discoveryHead.generation ||
         head.queryClass != run->discoveryHead.queryClass ||
         head.eligible != run->discoveryHead.eligible)) {
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 9;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    NativeAwdlDiscoveryPhase::Input input{};
    if (!discoveryAnchor(run, input.preRocAnchor)) {
        run->discoveryStatus = 4;
        run->discoveryWindowClosed = true;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    input.nowUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    input.leaseStartUs = run->psfCandidate.startObservedUs;
    input.leaseEndUs = run->psfCandidate.hardDeadlineUs < run->mifPacingWindowEndUs ?
        run->psfCandidate.hardDeadlineUs : run->mifPacingWindowEndUs;
    input.localRocChannel = 6;
    const NativeAwdlDiscoveryPhase::Epochs boundEpochs{
        run->contextGeneration, run->powerGeneration,
        run->stationGeneration, run->contextGeneration};
    uint8_t selected = run->discoveryCandidateLocked ? run->discoveryPeerSlot : 0xff;
    uint16_t selectedRxChannel = run->discoveryRxChannelIndex;
    uint64_t selectedMifRevision = run->discoveryMifRevision;
    bool sawFreshPsf = false;
    bool sawRuntimeMifBindingFailure = false;
    uint32_t runtimeMifBindingFailureReason = static_cast<uint32_t>(
        NativeAwdlDiscoveryBinding::Decision::kMissingMifBinding);
    NativeAwdlDiscoveryPhase::EstimatedTarget target{};
    input.psf = run->discoveryPsfWitness;
    for (uint8_t slot = 0; !run->discoveryCandidateLocked &&
         slot < IntelAwdlPeerRuntime::kPeerCapacity; ++slot) {
        IntelAwdlPeerRuntime::PsfPeerSnapshot candidate{};
        if (!owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(slot, epochs,
                input.nowUs, &candidate) || !candidate.syncConsistent ||
            candidate.rxChannel >= sizeof(owner->com.sc_ic.ic_channels) /
                                      sizeof(owner->com.sc_ic.ic_channels[0]) ||
            ieee80211_chan2ieee(&owner->com.sc_ic,
                &owner->com.sc_ic.ic_channels[candidate.rxChannel]) != 6)
            continue;
        const auto witness = discoveryPsf(candidate, slot, boundEpochs);
        if (!witness.complete)
            continue;
        sawFreshPsf = true;
        if (selectedRuntimeMifRequirement &&
            (!candidate.hasMif || !candidate.mifFresh ||
             !candidate.mifSyncConsistent || candidate.peerIncarnation == 0 ||
             candidate.mifRevision == 0 ||
             candidate.mifRxChannel >= sizeof(owner->com.sc_ic.ic_channels) /
                                       sizeof(owner->com.sc_ic.ic_channels[0]) ||
             ieee80211_chan2ieee(&owner->com.sc_ic,
                 &owner->com.sc_ic.ic_channels[candidate.mifRxChannel]) != 6)) {
            sawRuntimeMifBindingFailure = true;
            if (candidate.hasMif && candidate.mifRevision != 0 &&
                (!candidate.mifFresh || !candidate.mifSyncConsistent)) {
                runtimeMifBindingFailureReason = static_cast<uint32_t>(
                    NativeAwdlDiscoveryBinding::Decision::kStaleMif);
            } else if (candidate.hasMif && candidate.mifRevision != 0 &&
                       candidate.mifRxChannel <
                           sizeof(owner->com.sc_ic.ic_channels) /
                           sizeof(owner->com.sc_ic.ic_channels[0]) &&
                       ieee80211_chan2ieee(&owner->com.sc_ic,
                           &owner->com.sc_ic.ic_channels[
                               candidate.mifRxChannel]) != 6) {
                runtimeMifBindingFailureReason = static_cast<uint32_t>(
                    NativeAwdlDiscoveryBinding::Decision::kChannelMismatch);
            }
            continue;
        }
        // Do not filter by the next canonical slot here. The estimator must
        // report a distinct no-channel-6 status for the freshest schedule.
        if (selected == 0xff || witness.rxHostUs > input.psf.rxHostUs) {
            input.psf = witness;
            selected = slot;
            selectedRxChannel = candidate.rxChannel;
            selectedMifRevision = candidate.mifRevision;
        }
    }
    if (selected == 0xff) {
        if (selectedRuntimeMifRequirement && sawFreshPsf &&
            sawRuntimeMifBindingFailure) {
            run->discoveryBindingFailureReason =
                runtimeMifBindingFailureReason;
            run->discoveryStatus = 17; // Same-entry runtime MIF binding absent.
        } else {
            run->discoveryStatus = 5; // No fresh channel-6 PSF candidate.
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (!run->discoveryCandidateLocked) {
        run->discoveryCandidateLocked = true;
        run->discoveryRequiresRuntimeMifBinding =
            selectedRuntimeMifRequirement;
        run->discoveryPeerSlot = selected;
        run->discoveryRxChannelIndex = selectedRxChannel;
        run->discoveryPsfWitness = input.psf;
        run->discoveryPeerIncarnation = input.psf.peerToken;
        run->discoveryPsfRevision = input.psf.scheduleRevision;
        run->discoveryMifRevision = selectedMifRevision;
        run->discoveryRuntimeMifBound = false;
        run->discoveryBindingFailureReason = 0;
        run->discoveryHead = head;
        run->discoveryPsfObservedUs = input.psf.rxHostUs;
    }
    // Re-read the complete observation and time at the actual ownership
    // transfer point. Matching only an unchanged channel hint is insufficient.
    input.nowUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    IntelAwdlPeerRuntime::PsfPeerSnapshot current{};
    if (!owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(selected, epochs,
            input.nowUs, &current) || current.rxChannel != selectedRxChannel ||
        current.peerIncarnation != run->discoveryPeerIncarnation ||
        current.psfRevision != run->discoveryPsfRevision ||
        (selectedRuntimeMifRequirement &&
         (!current.hasMif || !current.mifFresh ||
          !current.mifSyncConsistent ||
          current.mifRevision != run->discoveryMifRevision ||
          current.mifRxChannel >= sizeof(owner->com.sc_ic.ic_channels) /
                                    sizeof(owner->com.sc_ic.ic_channels[0]) ||
          ieee80211_chan2ieee(&owner->com.sc_ic,
              &owner->com.sc_ic.ic_channels[current.mifRxChannel]) != 6))) {
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kPsfWitnessChanged);
        run->discoveryRuntimeMifBound = false;
        run->discoveryStatus = 9;
        run->discoveryWindowClosed = true;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    input.current = {discoveryPsf(current, selected, boundEpochs), true};
    const auto recheck = NativeAwdlDiscoveryPhase::estimateTarget(input, target);
    run->discoveryPhaseStatus = static_cast<uint32_t>(recheck);
    if (recheck != NativeAwdlDiscoveryPhase::Status::kEstimatedCandidate) {
        run->discoveryWindowClosed = true;
        if (recheck == NativeAwdlDiscoveryPhase::Status::kNoLocalChannel6NextSlot) {
            run->discoveryBindingFailureReason = static_cast<uint32_t>(
                NativeAwdlDiscoveryBinding::Decision::kNoChannel6NextSlot);
            run->discoveryStatus = 18; // Current PSF has no channel-6 next slot.
        } else {
            run->discoveryStatus = recheck == NativeAwdlDiscoveryPhase::Status::kCandidateAlreadyExpired ? 8 : 9;
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    run->discoveryTarget = target;
    const bool currentMifChannel6 = current.hasMif &&
        current.mifRxChannel < sizeof(owner->com.sc_ic.ic_channels) /
                                  sizeof(owner->com.sc_ic.ic_channels[0]) &&
        ieee80211_chan2ieee(&owner->com.sc_ic,
            &owner->com.sc_ic.ic_channels[current.mifRxChannel]) == 6;
    const auto bindingSnapshot = discoveryBindingSnapshot(current, boundEpochs,
        input.nowUs, currentMifChannel6,
        NativeAwdlDiscoveryBinding::Mode::kPsfNextSlot);
    const auto session = owner->nativeP2pRocEvents_.snapshot();
    const bool rocActive = session.commandReturned &&
        session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == run->contextGeneration && !session.endSeen &&
        !session.outcomeUnknown &&
        owner->nativeP2pProbeGeneration_ == run->contextGeneration &&
        owner->com.sc_p2p_roc.token == run->contextGeneration &&
        owner->com.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED &&
        isCurrentIeeeChannel6(&owner->com.sc_ic,
                              owner->com.sc_p2p_roc.roc_channel);
    NativeAwdlDiscoveryBinding::Window bindingWindow{};
    bindingWindow.mode = NativeAwdlDiscoveryBinding::Mode::kPsfNextSlot;
    bindingWindow.epochs = {run->contextGeneration, run->powerGeneration,
                            run->stationGeneration, run->contextGeneration};
    bindingWindow.nowUs = input.nowUs;
    bindingWindow.leaseStartUs = input.leaseStartUs;
    bindingWindow.leaseEndUs = input.leaseEndUs;
    bindingWindow.phaseEarliestUs = target.earliestSubmitUs;
    bindingWindow.phaseLatestUs = target.latestSubmitUs;
    bindingWindow.requireRuntimeMifBinding =
        run->discoveryRequiresRuntimeMifBinding;
    bindingWindow.phaseCandidateValid = true;
    bindingWindow.rocActive = rocActive;
    bindingWindow.windowOpen = rocActive && !run->discoveryWindowClosed;
    bindingWindow.closing = run->canceled ||
        (owner->com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) != 0 ||
        session.endSeen || session.outcomeUnknown;
    NativeAwdlDiscoveryBinding::QueueHead bindingHead{head.token, head.bornUs,
        head.generation, head.queryClass, head.eligible};
    if (!run->discoveryBindingLocked) {
        const auto bindingDecision = run->discoveryBinding.lock(
            bindingSnapshot, bindingHead, bindingWindow);
        if (bindingDecision != NativeAwdlDiscoveryBinding::Decision::kReady) {
            run->discoveryBindingFailureReason =
                static_cast<uint32_t>(bindingDecision);
            run->discoveryRuntimeMifBound = false;
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 17;
            publishDiscoveryExperiment(run);
            return nullptr;
        }
        run->discoveryBindingLocked = true;
        run->discoveryRuntimeMifBound =
            run->discoveryRequiresRuntimeMifBinding;
    }
    const auto bindingDecision = run->discoveryBinding.authorizeTake(
        bindingSnapshot, bindingHead, bindingWindow);
    if (bindingDecision ==
        NativeAwdlDiscoveryBinding::Decision::kPhaseNotYetOpen) {
        run->discoveryStatus = 7;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (bindingDecision != NativeAwdlDiscoveryBinding::Decision::kReady) {
        run->discoveryBindingFailureReason =
            static_cast<uint32_t>(bindingDecision);
        run->discoveryRuntimeMifBound = false;
        run->discoveryWindowClosed = true;
        run->discoveryStatus = bindingDecision ==
            NativeAwdlDiscoveryBinding::Decision::kNoChannel6NextSlot ? 18 : 9;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    // Authorization is one-shot even if the BSD queue's own exact-head check
    // later declines consumption; never retry via ordinary nextTx().
    run->discoveryWindowClosed = true;
    const auto before = NativeAwdlBSD::snapshot();
    bool consumed = false;
    mbuf_t packet = NativeAwdlBSD::nextDiscoveryTx(sequence, head, token, &consumed);
    if (consumed) {
        run->discoveryConsumed = true;
        run->discoveryWindowClosed = true;
        run->discoveryPacketToken = head.token;
        run->discoveryCompletedBaseline = before.value[NativeAwdlBSD::TxCompleted];
        run->discoverySucceededBaseline = before.value[NativeAwdlBSD::TxSucceeded];
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
        recordNativeDataTxConsumption(run, head, packet != nullptr);
#endif
    }
    run->discoveryStatus = packet ? 10 : (consumed ? 11 : 9);
    publishDiscoveryExperiment(run);
    return packet;
}

static mbuf_t takeDiscoveryPacketMifCurrent(P2PProbeRun *run,
    const IntelAwdlPeer::RuntimeEpochs &epochs, uint16_t sequence,
    uint64_t *token)
{
    auto *owner = run ? run->owner : nullptr;
    const auto mode = NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot;
    if (!run || !owner || !run->discoveryModeSelected ||
        run->discoveryMode != mode || !discoveryExperimentEnabled(owner) ||
        run->discoveryConsumed || run->discoveryWindowClosed ||
        run->nativeDataAttempts != 0 || !owner->tahoeP2pOnMainGate())
        return nullptr;

    // MIF mode always requires a runtime same-entry MIF/PSF pairing. This is
    // separate from the formal observer's aggregate admission count.
    run->discoveryRuntimeMifRequirementSelected = true;
    run->discoveryRequiresRuntimeMifBinding = true;
    ++run->discoveryChecks;
    if (!run->discoveryCandidateLocked) {
        run->discoveryPrerequisiteBlockers = 0;
        run->discoveryBindingFailureReason = 0;
    }

    NativeAwdlBSD::DiscoveryTxSnapshot head{};
    if (!NativeAwdlBSD::peekDiscoveryTx(run->powerGeneration, &head)) {
        run->discoveryPrerequisiteBlockers =
            Test069MifCurrentAdmission::kStrictQmHeadUnstable;
        if (run->discoveryCandidateLocked)
            run->discoveryBindingFailureReason = static_cast<uint32_t>(
                NativeAwdlDiscoveryBinding::Decision::kQueueHeadChanged);
        run->discoveryStatus = 3;
        if (run->discoveryCandidateLocked)
            run->discoveryWindowClosed = true;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (run->discoveryCandidateLocked &&
        !sameDiscoveryHead(head, run->discoveryHead)) {
        run->discoveryPrerequisiteBlockers =
            Test069MifCurrentAdmission::kStrictQmHeadUnstable;
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kQueueHeadChanged);
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 9;
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    NativeAwdlDiscoveryPhase::PreRocGp2Anchor anchor{};
    if (!discoveryAnchor(run, anchor)) {
        run->discoveryPrerequisiteBlockers =
            Test069MifCurrentAdmission::kTimingRejected;
        run->discoveryStatus = 4;
        run->discoveryWindowClosed = true;
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    const NativeAwdlDiscoveryPhase::Epochs boundEpochs{
        run->contextGeneration, run->powerGeneration,
        run->stationGeneration, run->contextGeneration};
    const uint64_t nowUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    IntelAwdlPeerRuntime::PsfPeerSnapshot selectedSnapshot{};
    uint8_t selectedSlot = run->discoveryCandidateLocked ?
        run->discoveryPeerSlot : 0xff;
    bool found = false;
    if (run->discoveryCandidateLocked) {
        found = owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(
            selectedSlot, epochs, nowUs, &selectedSnapshot);
    } else {
        // Pick the newest same-entry MIF witness once. Do not filter by channel
        // schedule and then fall back to another peer: the phase helper must
        // reject a newest non-channel-6 canonical slot explicitly.
        for (uint8_t slot = 0; slot < IntelAwdlPeerRuntime::kPeerCapacity;
             ++slot) {
            IntelAwdlPeerRuntime::PsfPeerSnapshot candidate{};
            if (!owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(
                    slot, epochs, nowUs, &candidate) || !candidate.tracked ||
                !candidate.hasPsf || !candidate.hasMif ||
                !candidate.peerIncarnation || !candidate.psfRevision ||
                !candidate.mifRevision || !candidate.mif.present ||
                candidate.mif.peerIncarnation != candidate.peerIncarnation ||
                candidate.mif.mifRevision != candidate.mifRevision ||
                !candidate.mif.rxMonotonicUs)
                continue;
            if (!found || candidate.mif.rxMonotonicUs >
                              selectedSnapshot.mif.rxMonotonicUs) {
                found = true;
                selectedSlot = slot;
                selectedSnapshot = candidate;
            }
        }
    }
    if (!found) {
        run->discoveryHistoryCompatible = false;
        run->discoveryPrerequisiteBlockers =
            Test069MifCurrentAdmission::kNoSelectedSlot;
        if (run->discoveryCandidateLocked) {
            run->discoveryBindingFailureReason = static_cast<uint32_t>(
                NativeAwdlDiscoveryBinding::Decision::kMissingMifBinding);
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 21;
        } else {
            run->discoveryHistoryCompatible = false;
            run->discoveryStatus = 19; // Waiting for a same-entry MIF.
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    run->discoveryHistoryCompatible = selectedSnapshot.historyCompatible;
    if (!selectedSnapshot.historyCompatible) {
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kHistoryIncompatible);
        run->discoveryPrerequisiteBlockers =
            Test069MifCurrentAdmission::kMifWitnessMismatch;
        if (run->discoveryCandidateLocked) {
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 20;
        } else {
            run->discoveryStatus = 19; // Wait for compatible same-entry history.
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (!selectedSnapshot.tracked || !selectedSnapshot.hasPsf ||
        !selectedSnapshot.hasMif || !selectedSnapshot.peerIncarnation ||
        !selectedSnapshot.psfRevision || !selectedSnapshot.mifRevision ||
        !selectedSnapshot.mif.present ||
        !selectedSnapshot.mif.rxMonotonicUs ||
        selectedSnapshot.mif.peerIncarnation !=
            selectedSnapshot.peerIncarnation ||
        selectedSnapshot.mif.mifRevision != selectedSnapshot.mifRevision ||
        selectedSnapshot.mif.rxMonotonicUs !=
            selectedSnapshot.mifRxMonotonicUs ||
        selectedSnapshot.mif.contextGeneration != epochs.contextGeneration ||
        selectedSnapshot.mif.powerGeneration != epochs.powerGeneration ||
        selectedSnapshot.mif.stationGeneration != epochs.stationGeneration ||
        selectedSnapshot.contextGeneration != epochs.contextGeneration ||
        selectedSnapshot.powerGeneration != epochs.powerGeneration ||
        selectedSnapshot.stationGeneration != epochs.stationGeneration) {
        uint32_t peerBlockers = 0;
        if (!selectedSnapshot.tracked || !selectedSnapshot.hasPsf ||
            !selectedSnapshot.peerIncarnation)
            peerBlockers |= Test069MifCurrentAdmission::kNoSelectedSlot;
        if (!selectedSnapshot.peerIncarnation ||
            selectedSnapshot.mif.peerIncarnation !=
                selectedSnapshot.peerIncarnation)
            peerBlockers |=
                Test069MifCurrentAdmission::kPeerIncarnationMismatch;
        if (!selectedSnapshot.psfRevision)
            peerBlockers |= Test069MifCurrentAdmission::kPsfRevisionMismatch;
        if (!selectedSnapshot.mifRevision ||
            selectedSnapshot.mif.mifRevision != selectedSnapshot.mifRevision)
            peerBlockers |= Test069MifCurrentAdmission::kMifRevisionMismatch;
        if (!selectedSnapshot.hasMif || !selectedSnapshot.mif.present ||
            !selectedSnapshot.mif.rxMonotonicUs ||
            selectedSnapshot.mif.rxMonotonicUs !=
                selectedSnapshot.mifRxMonotonicUs)
            peerBlockers |= Test069MifCurrentAdmission::kMifWitnessMismatch;
        if (selectedSnapshot.mif.contextGeneration != epochs.contextGeneration ||
            selectedSnapshot.mif.powerGeneration != epochs.powerGeneration ||
            selectedSnapshot.mif.stationGeneration != epochs.stationGeneration)
            peerBlockers |= Test069MifCurrentAdmission::kEpochMismatch;
        if (selectedSnapshot.contextGeneration != epochs.contextGeneration ||
            selectedSnapshot.powerGeneration != epochs.powerGeneration ||
            selectedSnapshot.stationGeneration != epochs.stationGeneration)
            peerBlockers |= Test069MifCurrentAdmission::kEpochMismatch;
        run->discoveryPrerequisiteBlockers = peerBlockers;
        if (run->discoveryCandidateLocked) {
            run->discoveryBindingFailureReason = static_cast<uint32_t>(
                mifCurrentPeerFailure(peerBlockers));
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 21;
        } else {
            run->discoveryStatus = 19; // Waiting for a complete MIF witness.
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    if (run->discoveryCandidateLocked &&
        (selectedSlot != run->discoveryPeerSlot ||
         selectedSnapshot.peerIncarnation != run->discoveryPeerIncarnation ||
         selectedSnapshot.psfRevision != run->discoveryPsfRevision ||
         selectedSnapshot.mifRevision != run->discoveryMifRevision)) {
        uint32_t peerBlockers = 0;
        if (selectedSlot != run->discoveryPeerSlot)
            peerBlockers |= Test069MifCurrentAdmission::kNoSelectedSlot;
        if (selectedSnapshot.peerIncarnation !=
            run->discoveryPeerIncarnation)
            peerBlockers |=
                Test069MifCurrentAdmission::kPeerIncarnationMismatch;
        if (selectedSnapshot.psfRevision != run->discoveryPsfRevision)
            peerBlockers |= Test069MifCurrentAdmission::kPsfRevisionMismatch;
        if (selectedSnapshot.mifRevision != run->discoveryMifRevision)
            peerBlockers |= Test069MifCurrentAdmission::kMifRevisionMismatch;
        run->discoveryPrerequisiteBlockers = peerBlockers;
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            mifCurrentPeerFailure(peerBlockers));
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 21;
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    const auto session = owner->nativeP2pRocEvents_.snapshot();
    const bool closing = run->canceled ||
        (owner->com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) != 0 ||
        session.endSeen || session.outcomeUnknown;
    const bool rocActive = session.commandReturned &&
        session.commandResult == 0 &&
        session.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        session.startSeen && session.startStatus == 1 &&
        session.generation == run->contextGeneration && !session.endSeen &&
        !session.outcomeUnknown &&
        owner->nativeP2pProbeGeneration_ == run->contextGeneration &&
        owner->com.sc_p2p_roc.token == run->contextGeneration &&
        owner->com.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED &&
        isCurrentIeeeChannel6(&owner->com.sc_ic,
                              owner->com.sc_p2p_roc.roc_channel);

    auto makeTimingInput = [&](const IntelAwdlPeerRuntime::PsfPeerSnapshot &peer,
                               uint64_t sampleUs,
                               bool ringIdle,
                               bool strictHeadStable,
                               bool currentRocActive,
                               bool currentClosing) {
        Test066MifCurrentPhase::Input input{};
        const bool mappedPeerMifChannel6 = peer.mif.rxChannel <
                sizeof(owner->com.sc_ic.ic_channels) /
                    sizeof(owner->com.sc_ic.ic_channels[0]) &&
            ieee80211_chan2ieee(&owner->com.sc_ic,
                &owner->com.sc_ic.ic_channels[peer.mif.rxChannel]) == 6;
        const auto sameEntry = discoveryBindingSnapshot(peer, boundEpochs,
            sampleUs, mappedPeerMifChannel6, mode);
        input.mif = discoveryMifTimingWitness(sameEntry.mif);
        input.anchor = {anchor.hostBeforeUs, anchor.hostAfterUs,
            anchor.rawGp2,
            {boundEpochs.context, boundEpochs.power, boundEpochs.station,
             boundEpochs.roc},
            anchor.directReadBracket, anchor.occurredBeforeRoc,
            anchor.firmwareResourcesAbsent};
        input.binding.peerIncarnation = peer.peerIncarnation;
        input.binding.mifRevision = peer.mifRevision;
        input.binding.epochs = {peer.contextGeneration, peer.powerGeneration,
                                peer.stationGeneration, boundEpochs.roc};
        input.binding.sameEntryVerified =
            sameEntry.psfHistorySameEntryPresent &&
            sameEntry.historyCompatible &&
            sameEntry.peerIncarnation == sameEntry.mif.peerIncarnation &&
            sameEntry.mifRevision == sameEntry.mif.mifRevision;
        input.binding.historicalPsfSameEntryPresent =
            sameEntry.psfHistorySameEntryPresent;
        input.currentEpochs = {run->contextGeneration, run->powerGeneration,
                               run->stationGeneration, run->contextGeneration};
        input.gates.explicitlyEnabled = run->discoveryModeSelected &&
            run->discoveryMode == mode && discoveryMifCurrentSlotEnabled(owner);
        // RX tap and this HAL's pre-ROC/current timestamps both use
        // clock_get_uptime() followed by absolutetime_to_nanoseconds(). This
        // proves only a shared host-monotonic domain, not a verified GP2 map.
        input.gates.hostMonotonicDomainVerified = true;
        input.gates.ownMifTxSucceeded = run->mifResultCaptured &&
            run->mifTxCompleted && run->mifTxSucceeded;
        input.gates.rocActive = currentRocActive;
        input.gates.rocChannel6Confirmed = currentRocActive;
        input.gates.peerMifRxChannel6Confirmed =
            peer.mif.rxChannel <
                sizeof(owner->com.sc_ic.ic_channels) /
                    sizeof(owner->com.sc_ic.ic_channels[0]) &&
            ieee80211_chan2ieee(&owner->com.sc_ic,
                &owner->com.sc_ic.ic_channels[peer.mif.rxChannel]) == 6;
        input.gates.closing = currentClosing;
        input.gates.ringIdle = ringIdle;
        input.gates.strictQmHeadStable = strictHeadStable;
        input.gates.firstOwnMifCompletionUs =
            run->discoveryOwnFirstMifCompletionUs;
        input.nowUs = sampleUs;
        input.leaseStartUs = run->psfCandidate.startObservedUs;
        input.leaseEndUs = run->psfCandidate.hardDeadlineUs <
                run->mifPacingWindowEndUs ?
            run->psfCandidate.hardDeadlineUs : run->mifPacingWindowEndUs;
        input.localRocChannel = 6;
        return input;
    };

    auto buildWindow = [&](const Test066MifCurrentPhase::Candidate &target,
                           uint64_t sampleUs, bool windowOpen,
                           bool currentRocActive, bool currentClosing) {
        NativeAwdlDiscoveryBinding::Window window{};
        window.mode = mode;
        window.epochs = {run->contextGeneration, run->powerGeneration,
                         run->stationGeneration, run->contextGeneration};
        window.nowUs = sampleUs;
        window.leaseStartUs = run->psfCandidate.startObservedUs;
        window.leaseEndUs = run->psfCandidate.hardDeadlineUs <
                run->mifPacingWindowEndUs ?
            run->psfCandidate.hardDeadlineUs : run->mifPacingWindowEndUs;
        window.phaseEarliestUs = target.earliestSubmitUs;
        window.phaseLatestUs = target.latestSubmitUs;
        window.requireRuntimeMifBinding = true;
        window.phaseCandidateValid = true;
        window.rocActive = currentRocActive;
        window.windowOpen = windowOpen;
        window.closing = currentClosing;
        return window;
    };

    P2PTxDiagnosticSnapshot txSnapshot{};
    const bool txSnapshotValid = captureP2PTxSnapshot(owner, &txSnapshot);
    const bool ringIdle = txSnapshotValid && txSnapshot.queueLeaseActive &&
        txSnapshot.txRingEmpty && txSnapshot.ringIndicesConsistent &&
        txSnapshot.outstandingTx == 0 &&
        txSnapshot.actionState == static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle) &&
        Test069MifCurrentAdmission::completedTicketHasNoInflight(
            txSnapshot.ticketArmed, txSnapshot.ticketCompleted);
    NativeAwdlBSD::DiscoveryTxSnapshot secondHead{};
    const bool strictHeadStable =
        NativeAwdlBSD::peekDiscoveryTx(run->powerGeneration, &secondHead) &&
        sameDiscoveryHead(head, secondHead);

    // Re-read the selected slot after mode/peer/head selection. This single
    // bundled runtime snapshot is the source for both PSF history and MIF;
    // never pair it with an observer's latest peer or a global latest MIF.
    const uint64_t sampleUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    IntelAwdlPeerRuntime::PsfPeerSnapshot current{};
    const bool currentFound = owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(
        selectedSlot, epochs, sampleUs, &current);
    uint32_t currentPeerBlockers = 0;
    if (!currentFound || !current.tracked || !current.hasPsf ||
        !current.peerIncarnation)
        currentPeerBlockers |= Test069MifCurrentAdmission::kNoSelectedSlot;
    const uint64_t expectedIncarnation = run->discoveryCandidateLocked ?
        run->discoveryPeerIncarnation : selectedSnapshot.peerIncarnation;
    const uint64_t expectedPsfRevision = run->discoveryCandidateLocked ?
        run->discoveryPsfRevision : selectedSnapshot.psfRevision;
    const uint64_t expectedMifRevision = run->discoveryCandidateLocked ?
        run->discoveryMifRevision : selectedSnapshot.mifRevision;
    const uint64_t expectedMifRxUs = run->discoveryCandidateLocked ?
        run->discoveryPsfObservedUs : selectedSnapshot.mifRxMonotonicUs;
    if (currentFound && current.peerIncarnation != expectedIncarnation)
        currentPeerBlockers |=
            Test069MifCurrentAdmission::kPeerIncarnationMismatch;
    if (currentFound && current.psfRevision != expectedPsfRevision)
        currentPeerBlockers |=
            Test069MifCurrentAdmission::kPsfRevisionMismatch;
    if (currentFound && current.mifRevision != expectedMifRevision)
        currentPeerBlockers |=
            Test069MifCurrentAdmission::kMifRevisionMismatch;
    if (currentFound && (!current.hasMif || !current.mif.present ||
        current.mif.peerIncarnation != current.peerIncarnation ||
        current.mif.mifRevision != current.mifRevision ||
        current.mif.rxMonotonicUs != current.mifRxMonotonicUs ||
        current.mifRxMonotonicUs != expectedMifRxUs))
        currentPeerBlockers |=
            Test069MifCurrentAdmission::kMifWitnessMismatch;
    if (currentFound && (current.mif.contextGeneration != epochs.contextGeneration ||
        current.mif.powerGeneration != epochs.powerGeneration ||
        current.mif.stationGeneration != epochs.stationGeneration))
        currentPeerBlockers |= Test069MifCurrentAdmission::kEpochMismatch;
    if (currentPeerBlockers != 0) {
        run->discoveryPrerequisiteBlockers = currentPeerBlockers;
        if (run->discoveryCandidateLocked) {
            run->discoveryBindingFailureReason = static_cast<uint32_t>(
                mifCurrentPeerFailure(currentPeerBlockers));
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 21;
        } else {
            // The candidate has not reached a timing plan or OneShot lock.
            // A table update here is re-evaluated next time; it cannot pin an
            // obsolete peer history or close the discovery window.
            run->discoveryStatus = 19;
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    run->discoveryHistoryCompatible = current.historyCompatible;
    if (!current.historyCompatible) {
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kHistoryIncompatible);
        run->discoveryPrerequisiteBlockers =
            Test069MifCurrentAdmission::kMifWitnessMismatch;
        if (run->discoveryCandidateLocked) {
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 21;
        } else {
            run->discoveryStatus = 19;
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    bool peerMifChannel6 = false;
    if (current.mif.rxChannel <
            sizeof(owner->com.sc_ic.ic_channels) /
                sizeof(owner->com.sc_ic.ic_channels[0])) {
        peerMifChannel6 = ieee80211_chan2ieee(&owner->com.sc_ic,
            &owner->com.sc_ic.ic_channels[current.mif.rxChannel]) == 6;
    }
    auto bindingSnapshot = discoveryBindingSnapshot(current, boundEpochs,
        sampleUs, peerMifChannel6, mode);
    auto timingInput = makeTimingInput(current, sampleUs, ringIdle,
                                       strictHeadStable, rocActive, closing);
    NativeAwdlMifCurrentAw::Candidate target{};
    NativeAwdlMifCurrentAw::RejectReason timingRejectReason{};
    const auto timingStatus = planDiscoveryMifCurrentTarget(
        timingInput, run->currentAwTrace.fallbackEnabled, target,
        timingRejectReason);
    if (timingStatus == Test066MifCurrentPhase::Status::kCandidate ||
        timingStatus ==
            Test066MifCurrentPhase::Status::kNoConservativeWindow) {
        bindDiscoveryCurrentAwTrace(run, timingInput, head,
                                    current.psfRevision);
    }
    recordDiscoveryCurrentAwPlan(run, false, timingInput, target,
                                 timingStatus, timingRejectReason);
    recordDiscoveryCurrentAwAttempt(run, false, timingInput, target,
                                     timingStatus, head.token, head.generation);
    run->discoveryMifTimingStatus = static_cast<uint32_t>(timingStatus);
    if (timingStatus != Test066MifCurrentPhase::Status::kCandidate) {
        uint32_t blockers = 0;
        if (!timingInput.gates.ownMifTxSucceeded)
            blockers |= Test069MifCurrentAdmission::kOwnMifIncomplete;
        if (!ringIdle)
            blockers |= Test069MifCurrentAdmission::kActionRingBusy;
        if (!strictHeadStable)
            blockers |= Test069MifCurrentAdmission::kStrictQmHeadUnstable;
        if (!rocActive)
            blockers |= Test069MifCurrentAdmission::kRocInactive;
        if (closing)
            blockers |= Test069MifCurrentAdmission::kClosing;
        const bool peerEpochsMatch =
            current.contextGeneration == run->contextGeneration &&
            current.powerGeneration == run->powerGeneration &&
            current.stationGeneration == run->stationGeneration &&
            current.mif.contextGeneration == run->contextGeneration &&
            current.mif.powerGeneration == run->powerGeneration &&
            current.mif.stationGeneration == run->stationGeneration;
        if (!peerEpochsMatch)
            blockers |= Test069MifCurrentAdmission::kEpochMismatch;
        if (!peerMifChannel6)
            blockers |= Test069MifCurrentAdmission::kPeerMifChannelMismatch;
        if (timingStatus ==
                Test066MifCurrentPhase::Status::kWrongCurrentSlotChannel ||
            timingStatus ==
                Test066MifCurrentPhase::Status::kNoFollowingAwInCurrentSlot)
            blockers |= Test069MifCurrentAdmission::kScheduleRejected;
        else if (timingStatus ==
                Test066MifCurrentPhase::Status::kOwnMifNotCompletedBeforeWindow)
            blockers |= Test069MifCurrentAdmission::kOwnMifMissedWindow;
        else if (timingStatus !=
                Test066MifCurrentPhase::Status::kPrerequisiteMissing)
            blockers |= Test069MifCurrentAdmission::kTimingRejected;
        else if (blockers == 0)
            blockers |= Test069MifCurrentAdmission::kTimingRejected;
        run->discoveryPrerequisiteBlockers = blockers;
        // Only a still-valid channel-6 peer/epoch inside an active ROC may
        // wait for the bounded local prerequisites. Invalid ROC, close,
        // epoch, peer-channel, schedule, and missed-window states terminate.
        const bool waitable = timingStatus ==
                Test066MifCurrentPhase::Status::kPrerequisiteMissing &&
            Test069MifCurrentAdmission::hasOnlyWaitableBlockers(blockers);
        if (!waitable) {
            if (timingStatus ==
                    Test066MifCurrentPhase::Status::kWrongCurrentSlotChannel)
                run->discoveryBindingFailureReason = static_cast<uint32_t>(
                    NativeAwdlDiscoveryBinding::Decision::kChannelMismatch);
            else if (timingStatus ==
                    Test066MifCurrentPhase::Status::kNoFollowingAwInCurrentSlot)
                run->discoveryBindingFailureReason = static_cast<uint32_t>(
                    NativeAwdlDiscoveryBinding::Decision::kNoChannel6NextSlot);
            else if (blockers & Test069MifCurrentAdmission::kEpochMismatch)
                run->discoveryBindingFailureReason = static_cast<uint32_t>(
                    NativeAwdlDiscoveryBinding::Decision::kEpochMismatch);
            else if (blockers & Test069MifCurrentAdmission::kPeerMifChannelMismatch)
                run->discoveryBindingFailureReason = static_cast<uint32_t>(
                    NativeAwdlDiscoveryBinding::Decision::kChannelMismatch);
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 20; // MIF-current phase rejected.
        } else {
            run->discoveryStatus = 7;
        }
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    run->discoveryPrerequisiteBlockers = 0;
    run->discoveryMifTarget = target;
    run->discoveryTarget.earliestSubmitUs = target.earliestSubmitUs;
    run->discoveryTarget.latestSubmitUs = target.latestSubmitUs;
    run->discoveryTarget.targetGp2Raw = target.targetAwStartGp2Us;
    run->discoveryTarget.peerToken = target.peerIncarnation;
    run->discoveryTarget.scheduleRevision = target.mifRevision;
    run->discoveryTarget.epochs = {target.epochs.context, target.epochs.power,
                                   target.epochs.station, target.epochs.roc};
    run->discoveryTarget.status =
        NativeAwdlDiscoveryPhase::Status::kEstimatedCandidate;
    run->discoveryTarget.clockMappingVerified = false;
    run->discoveryTarget.airtimeVerified = false;
    run->discoveryTarget.experimentalOnly = true;

    NativeAwdlDiscoveryBinding::QueueHead bindingHead{
        head.token, head.bornUs, head.generation, head.queryClass,
        head.eligible};
    auto bindingWindow = buildWindow(target, sampleUs,
                                     rocActive && !closing,
                                     rocActive, closing);
    if (!run->discoveryBindingLocked) {
        const auto lockDecision = run->discoveryBinding.lock(
            bindingSnapshot, bindingHead, bindingWindow);
        if (lockDecision != NativeAwdlDiscoveryBinding::Decision::kReady) {
            run->discoveryBindingFailureReason =
                static_cast<uint32_t>(lockDecision);
            run->discoveryPrerequisiteBlockers =
                mifCurrentDecisionBlocker(lockDecision);
            run->discoveryWindowClosed = true;
            run->discoveryStatus = 17;
            publishDiscoveryExperiment(run);
            return nullptr;
        }
        // Pin the selected peer and QM head only after a real current-slot
        // candidate exists and OneShot accepted the exact same-entry MIF,
        // PSF history, epoch, and selected queue candidate.
        run->discoveryCandidateLocked = true;
        run->discoveryPeerSlot = selectedSlot;
        run->discoveryPeerIncarnation = current.peerIncarnation;
        run->discoveryPsfRevision = current.psfRevision;
        run->discoveryMifRevision = current.mifRevision;
        run->discoveryHistoryCompatible = current.historyCompatible;
        run->discoveryRxChannelIndex = current.mif.rxChannel;
        run->discoveryPsfWitness = discoveryPsfHistory(current, boundEpochs);
        run->discoveryPsfObservedUs = current.mif.rxMonotonicUs;
        run->discoveryHead = head;
        run->discoveryBindingFailureReason = 0;
        run->discoveryPrerequisiteBlockers = 0;
        run->discoveryBindingLocked = true;
        run->discoveryRuntimeMifBound = true;
    }

    // Revalidate the full same-entry MIF witness, source epochs, current ROC,
    // strict selected QM candidate, ring idleness, and identical phase window at
    // the actual ownership transfer point.
    const uint64_t finalNowUs =
        p2pProbeMonotonicNanoseconds() / 1000ULL;
    const auto finalSession = owner->nativeP2pRocEvents_.snapshot();
    const bool finalClosing = run->canceled ||
        (owner->com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) != 0 ||
        finalSession.endSeen || finalSession.outcomeUnknown;
    const bool finalRocActive = finalSession.commandReturned &&
        finalSession.commandResult == 0 &&
        finalSession.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
        finalSession.startSeen && finalSession.startStatus == 1 &&
        finalSession.generation == run->contextGeneration &&
        !finalSession.endSeen && !finalSession.outcomeUnknown &&
        owner->nativeP2pProbeGeneration_ == run->contextGeneration &&
        owner->com.sc_p2p_roc.token == run->contextGeneration &&
        owner->com.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED &&
        isCurrentIeeeChannel6(&owner->com.sc_ic,
                              owner->com.sc_p2p_roc.roc_channel);
    NativeAwdlBSD::DiscoveryTxSnapshot finalHead{};
    const bool finalHeadStable =
        NativeAwdlBSD::peekDiscoveryTx(run->powerGeneration, &finalHead) &&
        sameDiscoveryHead(head, finalHead);
    P2PTxDiagnosticSnapshot finalTx{};
    const bool finalTxValid = captureP2PTxSnapshot(owner, &finalTx);
    const bool finalRingIdle = finalTxValid && finalTx.queueLeaseActive &&
        finalTx.txRingEmpty && finalTx.ringIndicesConsistent &&
        finalTx.outstandingTx == 0 &&
        finalTx.actionState == static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle) &&
        Test069MifCurrentAdmission::completedTicketHasNoInflight(
            finalTx.ticketArmed, finalTx.ticketCompleted);
    IntelAwdlPeerRuntime::PsfPeerSnapshot finalPeer{};
    const bool finalPeerFound = owner->tahoe_awdl_peer_runtime_.getPsfSnapshot(
        selectedSlot, epochs, finalNowUs, &finalPeer);
    uint32_t finalBlockers = 0;
    if (!finalHeadStable)
        finalBlockers |= Test069MifCurrentAdmission::kStrictQmHeadUnstable;
    if (!finalRingIdle)
        finalBlockers |= Test069MifCurrentAdmission::kActionRingBusy;
    if (!finalPeerFound || !finalPeer.tracked || !finalPeer.hasPsf)
        finalBlockers |= Test069MifCurrentAdmission::kNoSelectedSlot;
    if (finalPeerFound && finalPeer.peerIncarnation !=
            run->discoveryPeerIncarnation)
        finalBlockers |=
            Test069MifCurrentAdmission::kPeerIncarnationMismatch;
    if (finalPeerFound && finalPeer.psfRevision != run->discoveryPsfRevision)
        finalBlockers |= Test069MifCurrentAdmission::kPsfRevisionMismatch;
    if (finalPeerFound && finalPeer.mifRevision != run->discoveryMifRevision)
        finalBlockers |= Test069MifCurrentAdmission::kMifRevisionMismatch;
    if (finalPeerFound && (!finalPeer.hasMif || !finalPeer.mif.present ||
        finalPeer.mif.peerIncarnation != finalPeer.peerIncarnation ||
        finalPeer.mif.mifRevision != finalPeer.mifRevision ||
        finalPeer.mif.rxMonotonicUs != finalPeer.mifRxMonotonicUs ||
        !finalPeer.historyCompatible))
        finalBlockers |= Test069MifCurrentAdmission::kMifWitnessMismatch;
    if (finalPeerFound && (finalPeer.contextGeneration != run->contextGeneration ||
        finalPeer.powerGeneration != run->powerGeneration ||
        finalPeer.stationGeneration != run->stationGeneration ||
        finalPeer.mif.contextGeneration != run->contextGeneration ||
        finalPeer.mif.powerGeneration != run->powerGeneration ||
        finalPeer.mif.stationGeneration != run->stationGeneration))
        finalBlockers |= Test069MifCurrentAdmission::kEpochMismatch;
    if (finalBlockers != 0) {
        run->discoveryHistoryCompatible = finalPeer.historyCompatible;
        run->discoveryPrerequisiteBlockers = finalBlockers;
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            !finalPeer.historyCompatible ?
                NativeAwdlDiscoveryBinding::Decision::kHistoryIncompatible :
                mifCurrentPeerFailure(finalBlockers));
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 21;
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    const auto finalBindingSnapshot = discoveryBindingSnapshot(
        finalPeer, boundEpochs, finalNowUs,
        finalPeer.mif.rxChannel <
            sizeof(owner->com.sc_ic.ic_channels) /
                sizeof(owner->com.sc_ic.ic_channels[0]) &&
        ieee80211_chan2ieee(&owner->com.sc_ic,
            &owner->com.sc_ic.ic_channels[finalPeer.mif.rxChannel]) == 6,
        mode);
    auto finalTimingInput = makeTimingInput(finalPeer, finalNowUs,
        finalRingIdle, finalHeadStable, finalRocActive, finalClosing);
    NativeAwdlMifCurrentAw::Candidate finalTarget{};
    NativeAwdlMifCurrentAw::RejectReason finalRejectReason{};
    const auto finalTimingStatus = planDiscoveryMifCurrentTarget(
        finalTimingInput, run->currentAwTrace.fallbackEnabled, finalTarget,
        finalRejectReason);
    recordDiscoveryCurrentAwPlan(run, true, finalTimingInput, finalTarget,
                                 finalTimingStatus, finalRejectReason);
    recordDiscoveryCurrentAwAttempt(run, true, finalTimingInput, finalTarget,
                                     finalTimingStatus, finalHead.token,
                                     finalHead.generation);
    run->discoveryMifTimingStatus =
        static_cast<uint32_t>(finalTimingStatus);
    const bool finalTargetMatches =
        finalTimingStatus == Test066MifCurrentPhase::Status::kCandidate &&
        sameDiscoveryMifCandidate(target, finalTarget);
    run->currentAwTrace.finalCompareValid = true;
    run->currentAwTrace.finalCompareMatch = finalTargetMatches;
    if (!finalTargetMatches) {
        run->discoveryBindingFailureReason = static_cast<uint32_t>(
            NativeAwdlDiscoveryBinding::Decision::kWindowChanged);
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 20;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    auto finalWindow = buildWindow(finalTarget, finalNowUs,
        finalRocActive && !finalClosing, finalRocActive, finalClosing);
    const NativeAwdlDiscoveryBinding::QueueHead finalBindingHead{
        finalHead.token, finalHead.bornUs, finalHead.generation,
        finalHead.queryClass, finalHead.eligible};
    const auto bindingDecision = run->discoveryBinding.authorizeTake(
        finalBindingSnapshot, finalBindingHead, finalWindow);
    if (bindingDecision ==
        NativeAwdlDiscoveryBinding::Decision::kPhaseNotYetOpen) {
        run->discoveryStatus = 7;
        publishDiscoveryExperiment(run);
        return nullptr;
    }
    if (bindingDecision != NativeAwdlDiscoveryBinding::Decision::kReady) {
        run->discoveryBindingFailureReason =
            static_cast<uint32_t>(bindingDecision);
        run->discoveryWindowClosed = true;
        run->discoveryStatus = 21;
        publishDiscoveryExperiment(run);
        return nullptr;
    }

    // One authorization, one exact-head dequeue. Neither failure nor a
    // changed candidate can fall back to ordinary nextTx().
    run->discoveryWindowClosed = true;
    const auto before = NativeAwdlBSD::snapshot();
    bool consumed = false;
    mbuf_t packet = NativeAwdlBSD::nextDiscoveryTx(
        sequence, head, token, &consumed);
    if (consumed) {
        run->discoveryConsumed = true;
        run->discoveryPacketToken = head.token;
        run->discoveryCompletedBaseline =
            before.value[NativeAwdlBSD::TxCompleted];
        run->discoverySucceededBaseline =
            before.value[NativeAwdlBSD::TxSucceeded];
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
        recordNativeDataTxConsumption(run, head, packet != nullptr);
#endif
    }
    run->discoveryStatus = packet ? 10 : (consumed ? 11 : 9);
    publishDiscoveryExperiment(run);
    return packet;
}

static mbuf_t takeDiscoveryPacket(P2PProbeRun *run,
    const IntelAwdlPeer::RuntimeEpochs &epochs, uint16_t sequence,
    uint64_t *token, bool requireRuntimeMifBinding)
{
    if (!run)
        return nullptr;
    if (run->discoveryMode ==
        NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot)
        return takeDiscoveryPacketMifCurrent(run, epochs, sequence, token);
    return takeDiscoveryPacketPsfNextSlot(run, epochs, sequence, token,
                                          requireRuntimeMifBinding);
}
#endif

static NativeAwdlProbe::MifPacingPolicy mifPacingPolicyForProbe(
    const P2PProbeRun *probe)
{
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (probe && probe->discoveryModeSelected &&
        probe->discoveryMode ==
            NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot)
        return NativeAwdlProbe::MifPacingPolicy::Test069EarlyFirstMif;
#else
    (void)probe;
#endif
    return NativeAwdlProbe::MifPacingPolicy::LegacyPsfAfterNotBefore;
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
    input.policy = mifPacingPolicyForProbe(probe);
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (probe->mifBootstrapSelected &&
        (!probe->mifBootstrapPairClaimed ||
         !evaluateMifBootstrapPairTransition(probe, read.view, false)))
        return {NativeAwdlProbe::MifPacingDecision::Stop,
                NativeAwdlProbe::MifPacingReason::PreparedFrameStale,
                0, probe->mifPacingWindowEndUs, 0, 0};
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (probe->mifBootstrapSelected) {
        MifPacingPeerRead read{};
        read.owner = owner;
        read.probe = const_cast<P2PProbeRun *>(probe);
        if (readMifPacingPeerInGate(nullptr, &read, nullptr, nullptr, nullptr) !=
                kIOReturnSuccess ||
            !probe->mifBootstrapPairClaimed ||
            !evaluateMifBootstrapPairTransition(
                const_cast<P2PProbeRun *>(probe), read.view, false))
            return {NativeAwdlProbe::MifPacingDecision::Stop,
                    NativeAwdlProbe::MifPacingReason::PreparedFrameStale,
                    0, probe->mifPacingWindowEndUs, 0, 0};
        const uint64_t sampleUs = nowUs > read.view.sampleUs ?
            nowUs : read.view.sampleUs;
        return NativeAwdlProbe::planMifPacing(makeMifPacingInput(
            probe, read.view, sampleUs, probe->mifPacingCandidateOrdinal,
            probe->mifPacingLastConsumedAnchorRxUs));
    }
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        probe->mifBootstrapPairMifAttempted ||
#endif
        probe->mifCandidatePrepared || !probe->psfResultCaptured ||
        !probe->psfTxSucceeded ||
        probe->mifBurstPreparedFrames >=
            NativeAwdlProbe::kMifPacingMaximumFrames)
        return false;

    const uint32_t ordinal = probe->mifBurstPreparedFrames;
    uint64_t earliestUs = 0;
    if (!NativeAwdlProbe::mifPacingNotBeforeUs(
            probe->psfCandidate.sampleUs, probe->mifPacingWindowEndUs,
            ordinal, &earliestUs, mifPacingPolicyForProbe(probe))) {
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (probe->mifBootstrapSelected &&
        !evaluateMifBootstrapPairTransition(probe, peer, false)) {
        if (probe->mifBootstrapPairClaimed ||
            (probe->mifBootstrapPairBlockers &
                (Test079BootstrapPairTransition::kWindowExpired |
                 kMifBootstrapPairPinnedSnapshotChanged)))
            probe->mifBurstStopped = true;
        probe->mifStatus = kMifProbeWaitingForPeerPsf;
        probe->mifPacingReason = static_cast<uint32_t>(
            NativeAwdlProbe::MifPacingReason::WaitingForFreshPsf);
        probe->mifPacingEarliestUs = 0;
        probe->mifPacingLatestUs = probe->mifPacingWindowEndUs;
        publishMifProbeDetails(probe->owner, probe);
        return false;
    }
#endif
    if (peer.rxMonotonicUs == 0) {
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (probe->mifBootstrapSelected)
            return false;
        return tryPrepareMifBootstrapAtPacingPoint(
            probe, session, tx, nowUs, frame);
#else
        const NativeAwdlProbe::MifPacingPlan plan{
            NativeAwdlProbe::MifPacingDecision::Wait,
            NativeAwdlProbe::MifPacingReason::WaitingForFreshPsf,
            earliestUs, effectiveEndUs, 0, 0};
        recordMifPacingPlan(probe, plan, false);
        return false;
#endif
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
    bool repeatPrepareReady = !repeat;
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
        repeatPrepareReady = true;
    }
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (probe->mifBootstrapSelected) {
        const uint64_t claimNowUs =
            p2pProbeMonotonicNanoseconds() / 1000ULL;
        if (peer.sampleUs < claimNowUs)
            peer.sampleUs = claimNowUs;
        if (!claimMifBootstrapPairAfterPreparation(
                probe, peer,
                pacing.decision == NativeAwdlProbe::MifPacingDecision::Ready,
                repeatPrepareReady)) {
            if (probe->mifBootstrapPairClaimed ||
                (probe->mifBootstrapPairBlockers &
                    (Test079BootstrapPairTransition::kWindowExpired |
                     kMifBootstrapPairPinnedSnapshotChanged)))
                probe->mifBurstStopped = true;
            probe->mifStatus = kMifProbeWaitingForPeerPsf;
            probe->mifPacingReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifPacingReason::WaitingForFreshPsf);
            probe->mifPacingEarliestUs = 0;
            probe->mifPacingLatestUs = probe->mifPacingWindowEndUs;
            publishMifProbeDetails(probe->owner, probe);
            return false;
        }
    }
#endif
    if (repeat) {
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        (!probe->mifBootstrapCandidatePrepared ||
         probe->mifBootstrapSubmitted ||
         (probe->mifBootstrapSelected && !probe->mifBootstrapSubmitted &&
          probe->mifBootstrapStatus == static_cast<uint32_t>(
              Test070MifBootstrap::Status::Ready))) &&
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        const bool bootstrapMif =
            probe->mifBootstrapCandidatePrepared &&
            !probe->mifBootstrapSubmitted;
#else
        const bool bootstrapMif = false;
#endif
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
        uint64_t submitUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
        NativeAwdlProbe::MifCandidate refreshed{};
        uint32_t candidateBlockers = 0;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (bootstrapMif) {
            if (!refreshMifBootstrapCandidateInGate(
                    probe, session, txSnapshot, submitUs, &refreshed)) {
                probe->mifStatus = kMifProbePreflightRejected;
                probe->mifBlockers |=
                    NativeAwdlProbe::kMifTxPreparedFrameStale;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
                action->frameStale = true;
                publishMifProbeDetails(owner, probe);
                return kIOReturnNotReady;
            }
        } else
#endif
        {
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (bootstrapMif) {
            // The exact MIF-only binding and all local ticket/ring/ROC gates
            // were re-evaluated while refreshing this one-shot candidate.
        } else
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (bootstrapMif) {
            doorbellUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
            NativeAwdlProbe::MifCandidate doorbellCandidate{};
            if (!refreshMifBootstrapCandidateInGate(probe, session,
                    doorbellSnapshot, doorbellUs, &doorbellCandidate)) {
                doorbellBlockers =
                    NativeAwdlProbe::kMifTxPreparedFrameStale;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            } else {
                mbuf_t doorbellFrame = makeActionFrameFromBytes(
                    doorbellCandidate.bytes, doorbellCandidate.length);
                if (!doorbellFrame) {
                    doorbellBlockers =
                        NativeAwdlProbe::kMifTxInvalidCandidate;
                    probe->mifBurstStopped = true;
                    probe->mifBurstStopReason = static_cast<uint32_t>(
                        NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
                } else {
                    mbuf_freem(refreshedFrame);
                    refreshedFrame = doorbellFrame;
                    refreshed = doorbellCandidate;
                }
            }
        } else
#endif
        {
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
        uint64_t finalDoorbellUs =
            p2pProbeMonotonicNanoseconds() / 1000ULL;
        NativeAwdlProbe::MifPacingPlan finalPacingPlan{};
        bool finalGateReady = false;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (bootstrapMif) {
            P2PTxDiagnosticSnapshot finalSnapshot{};
            if (!captureP2PTxSnapshot(owner, &finalSnapshot)) {
                probe->mifBootstrapStatus = static_cast<uint32_t>(
                    Test070MifBootstrap::Status::Blocked);
                probe->mifBootstrapBlockers |=
                    Test070MifBootstrap::kQueueLeaseMissing;
            } else {
                const auto bootstrapPlan = evaluateMifBootstrapInGate(
                    probe, finalSnapshot, finalDoorbellUs, true);
                finalGateReady = bootstrapPlan.status ==
                    Test070MifBootstrap::Status::Ready;
            }
            finalDoorbellUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
        } else
#endif
        {
            finalPacingPlan = finalCheckMifPacingAnchorInGate(
                probe, finalDoorbellUs);
            finalGateReady = finalPacingPlan.decision ==
                NativeAwdlProbe::MifPacingDecision::Ready;
        }
        const bool preparedFrameFresh =
            finalDoorbellUs >= refreshed.sampleUs &&
            finalDoorbellUs - refreshed.sampleUs <=
                NativeAwdlProbe::kMaximumPreparedPsfAgeUs;
        if (!finalGateReady ||
            (!bootstrapMif && finalPacingPlan.anchorRxUs !=
                probe->mifPacingCandidateAnchorRxUs) || !preparedFrameFresh) {
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
            if (!bootstrapMif) {
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
            } else {
                probe->mifBootstrapStatus = static_cast<uint32_t>(
                    Test070MifBootstrap::Status::Blocked);
                probe->mifBootstrapBlockers |=
                    Test070MifBootstrap::kPeerRxTimeInvalid;
            }
#else
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
#endif
            mbuf_freem(refreshedFrame);
            probe->mifBlockers |=
                NativeAwdlProbe::kMifTxPreparedFrameStale;
            probe->mifBurstStopReason = static_cast<uint32_t>(
                NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
            action->frameStale = true;
            publishMifProbeDetails(owner, probe);
            return kIOReturnNotReady;
        }
        if (!bootstrapMif) {
            probe->mifPacingReason = static_cast<uint32_t>(
                finalPacingPlan.reason);
            probe->mifPacingLatestUs = finalPacingPlan.latestUs;
        }
        mbuf_freem(action->frame);
        action->frame = refreshedFrame;
        probe->mifCandidate = refreshed;
        probe->mifCandidateLength = refreshed.length;
        probe->mifBlockers = NativeAwdlProbe::kMifTxNoBlocker;
    }

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeResidentAddressProfileEnabled(owner) && (psfFrame || mifFrame)) {
        const NativeAwdl::PsfInput &identityInput = mifFrame ?
            probe->mifCandidate.input : probe->psfCandidate.input;
        uint8_t liveAddress[6]{};
        uint32_t identityFailure = probe->nativeAddressCandidateVerified ?
            verifyNativeIdentity(owner, probe->contextGeneration,
                probe->powerGeneration, probe->stationGeneration,
                probe->address, identityInput.sourceAddress, liveAddress) :
            kNativeIdentityBsdAddressUnavailable;
        if (identityFailure == kNativeIdentityVerified &&
            !identityInput.advertiseAwdlAddress)
            identityFailure = kNativeIdentityAdvertisementMissing;
        if (identityFailure != kNativeIdentityVerified) {
            publishNativeIdentityStatus(owner, false, identityFailure);
            action->frameStale = true;
            if (psfFrame) {
                probe->psfStatus = kPsfProbeCandidateRejected;
                probe->psfBlockers |=
                    NativeAwdlProbe::kPsfTxPreparedFrameStale;
                publishPsfProbeDetails(owner, probe, kP2PFrameAwdlPsf);
            }
            if (mifFrame) {
                probe->mifStatus = kMifProbePreflightRejected;
                probe->mifBlockers |=
                    NativeAwdlProbe::kMifTxPreparedFrameStale;
                probe->mifBurstStopped = true;
                probe->mifBurstStopReason = static_cast<uint32_t>(
                    NativeAwdlProbe::MifBurstStopReason::DoorbellRejected);
                publishMifProbeDetails(owner, probe);
            }
            return kIOReturnNotReady;
        }
        publishNativeIdentityStatus(owner, true, kNativeIdentityVerified);
    }
#endif

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    const bool bootstrapMifSubmit = mifFrame &&
        probe->mifBootstrapCandidatePrepared &&
        !probe->mifBootstrapSubmitted;
    if (mifFrame && probe->mifBootstrapSelected &&
        probe->mifBootstrapPairClaimed && !bootstrapMifSubmit &&
        !probe->mifBootstrapPairMifAttempted) {
        // This is the only normal paired-MIF attempt allowed after bootstrap.
        // Latch before the submit call so a failed prepare/doorbell cannot
        // re-enter using unchanged peer evidence.
        probe->mifBootstrapPairMifAttempted = true;
        probe->mifBootstrapPairStatus = kMifBootstrapPairMifAttempted;
        probe->mifBootstrapPairDiagnosticsDirty = true;
    }
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    TahoeP2PActionTxControlSubmitFence bootstrapSubmitFence{};
    const TahoeP2PActionTxControlSubmitFence *bootstrapSubmitFencePointer =
        nullptr;
    if (mifFrame && probe->mifBootstrapCandidatePrepared &&
        !probe->mifBootstrapSubmitted) {
        bootstrapSubmitFence.phaseOriginUs = probe->psfCandidate.sampleUs;
        bootstrapSubmitFence.peerMifRxUs =
            probe->mifBootstrapBinding.rxMonotonicUs;
        bootstrapSubmitFence.effectiveEndUs =
            probe->mifPacingWindowEndUs <
                probe->psfCandidate.hardDeadlineUs ?
                probe->mifPacingWindowEndUs :
                probe->psfCandidate.hardDeadlineUs;
        bootstrapSubmitFence.preparedFrameUs = probe->mifCandidate.sampleUs;
        bootstrapSubmitFence.preparedFrameMaxAgeUs =
            NativeAwdlProbe::kMaximumPreparedPsfAgeUs;
        bootstrapSubmitFence.contextGeneration =
            probe->mifBootstrapBinding.contextGeneration;
        bootstrapSubmitFence.powerGeneration =
            probe->mifBootstrapBinding.powerGeneration;
        bootstrapSubmitFence.stationGeneration =
            probe->mifBootstrapBinding.stationGeneration;
        bootstrapSubmitFence.rocGeneration =
            probe->mifBootstrapBinding.rocGeneration;
        bootstrapSubmitFencePointer = &bootstrapSubmitFence;
    }
#endif
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    TahoeP2PActionTxSubmitMetadata evidenceMetadata{};
    const TahoeP2PActionTxSubmitMetadata *evidenceMetadataPointer = nullptr;
    if (psfFrame || mifFrame) {
        evidenceMetadata.diagnosticGeneration = probe->contextGeneration;
        evidenceMetadata.epoch = {
            probe->contextGeneration,
            probe->powerGeneration,
            probe->stationGeneration,
            session.generation
        };
        evidenceMetadata.frameKind = psfFrame ?
            NativeAwdlTxWindowEvidence::FrameKind::Psf :
            NativeAwdlTxWindowEvidence::FrameKind::Mif;
        evidenceMetadata.frameOrdinal = psfFrame ? 1u :
            probe->mifBurstAttemptedFrames;
        evidenceMetadataPointer = &evidenceMetadata;
    }
    action->result = iwx_tahoe_p2p_action_tx_submit(
        owner, &owner->com, &owner->nativeP2pTxQueue_,
        &owner->nativeP2pActionTx_, probe->contextGeneration,
        session.startSeen, session.endSeen, frame, 0,
        evidenceMetadataPointer
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        , 0, 0, 0, bootstrapSubmitFencePointer
#endif
        );
#else
    action->result = iwx_tahoe_p2p_action_tx_submit(
        owner, &owner->com, &owner->nativeP2pTxQueue_,
        &owner->nativeP2pActionTx_, probe->contextGeneration,
        session.startSeen, session.endSeen, frame, 0
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        , 0, 0, 0, bootstrapSubmitFencePointer
#endif
        );
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (mifFrame && probe->mifBootstrapCandidatePrepared &&
        !probe->mifBootstrapSubmitted) {
        const uint32_t submitStage = __atomic_load_n(
            &owner->nativeP2pActionTx_.submitDiagnostics.lastStage,
            __ATOMIC_ACQUIRE);
        const bool realDoorbell = action->result == 0 &&
            (submitStage == static_cast<uint32_t>(
                TahoeP2PActionTxSubmitStage::kDoorbellIssued) ||
             submitStage == static_cast<uint32_t>(
                TahoeP2PActionTxSubmitStage::kPostDoorbellFinish));
        if (realDoorbell) {
            probe->mifBootstrapSubmitted = true;
            P2PTxDiagnosticSnapshot submittedSnapshot{};
            if (captureP2PTxSnapshot(owner, &submittedSnapshot))
                probe->mifBootstrapTicketIdentity =
                    ticketIdentityFromSnapshot(submittedSnapshot);
        } else {
            probe->mifBootstrapStatus = static_cast<uint32_t>(
                Test070MifBootstrap::Status::Blocked);
            probe->mifBootstrapBlockers |=
                Test070MifBootstrap::kCandidatePreparationFailed;
        }
    } else if (mifFrame && probe->mifBootstrapSelected &&
        probe->mifBootstrapPairMifAttempted) {
        const uint32_t submitStage = __atomic_load_n(
            &owner->nativeP2pActionTx_.submitDiagnostics.lastStage,
            __ATOMIC_ACQUIRE);
        const bool realDoorbell =
            submitStage == static_cast<uint32_t>(
                TahoeP2PActionTxSubmitStage::kDoorbellIssued) ||
            submitStage == static_cast<uint32_t>(
                TahoeP2PActionTxSubmitStage::kPostDoorbellFinish);
        if (realDoorbell) {
            P2PTxDiagnosticSnapshot submittedSnapshot{};
            if (captureP2PTxSnapshot(owner, &submittedSnapshot))
                probe->mifBootstrapPairTicketIdentity =
                    ticketIdentityFromSnapshot(submittedSnapshot);
        }
    }
#endif
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

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
static bool nativeResidentAddressProfileEnabled(ItlIwx *owner)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    return controller && controller->getProperty("NativeAwdlResidentEnabled") ==
        kOSBooleanTrue;
}

static void publishNativeIdentityStatus(ItlIwx *owner, bool verified,
                                        uint32_t failure)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PAwdlNativeAddressVerified",
                            verified ? 1u : 0u, 32);
    controller->setProperty("NativeP2PAwdlNativeAddressFailure", failure, 32);
}

static uint32_t verifyNativeIdentity(
    ItlIwx *owner, uint32_t contextGeneration, uint32_t powerGeneration,
    uint32_t stationGeneration, const uint8_t runAddress[6],
    const uint8_t candidateAddress[6], uint8_t liveAddress[6])
{
    if (!owner || !liveAddress)
        return kNativeIdentityMissingContext;
    struct iwx_softc *sc = &owner->com;
    if (uint32_t(sc->sc_generation) != powerGeneration ||
        __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) !=
            stationGeneration || sc->sc_p2p.fw_generation != powerGeneration ||
        (contextGeneration && owner->nativeP2pProbeGeneration_ !=
            contextGeneration))
        return kNativeIdentityGenerationMismatch;
    if (!sc->sc_p2p.initialized ||
        sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE)
        return kNativeIdentityP2pInactive;
    if (!NativeAwdlBSD::address(powerGeneration, liveAddress))
        return kNativeIdentityBsdAddressUnavailable;
    if (runAddress && memcmp(liveAddress, runAddress, 6) != 0)
        return kNativeIdentityRunAddressMismatch;
    if (memcmp(liveAddress, sc->sc_p2p.mac_address, 6) != 0)
        return kNativeIdentityP2pAddressMismatch;
    if (candidateAddress && memcmp(liveAddress, candidateAddress, 6) != 0)
        return kNativeIdentityCandidateAddressMismatch;
    return kNativeIdentityVerified;
}
#endif

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
        uint32_t(sc->sc_generation) == run->scGeneration &&
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
    // Capture the P2P firmware epoch independently after MAC configure. The
    // production contract requires it to match the captured sc generation;
    // the HAL snapshot remains a separate revalidation input.
    state.p2pGenerationMatches = run->p2pFirmwareGeneration ==
        run->scGeneration && sc->sc_p2p.fw_generation ==
            run->p2pFirmwareGeneration;
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
        a.resourceMayExist == b.resourceMayExist &&
        a.exerciseResult == b.exerciseResult &&
        a.exerciseRecoveryAttempted == b.exerciseRecoveryAttempted &&
        a.exerciseRecoveryProofAccepted == b.exerciseRecoveryProofAccepted;
}

static bool readPrepareTraceSnapshot(
    struct iwx_softc *sc,
    struct iwx_p2p_roc_prepare_trace_snapshot *snapshot,
    uint32_t *revisionBegin, uint32_t *revisionEnd)
{
    if (!sc || !snapshot || !revisionBegin || !revisionEnd)
        return false;
    *snapshot = {};
    *revisionBegin = __atomic_load_n(
        &sc->sc_p2p_roc_prepare_trace.revision, __ATOMIC_ACQUIRE);
    const int readResult = iwx_p2p_roc_prepare_trace_read_snapshot(
        &sc->sc_p2p_roc_prepare_trace, snapshot);
    *revisionEnd = __atomic_load_n(
        &sc->sc_p2p_roc_prepare_trace.revision, __ATOMIC_ACQUIRE);
    return readResult == 0 && *revisionBegin == *revisionEnd &&
        (*revisionEnd & 1U) == 0;
}

static void publishPrepareTraceSnapshot(
    IOEthernetController *controller,
    const struct iwx_p2p_roc_prepare_trace_snapshot &snapshot,
    uint32_t revisionBegin, uint32_t revisionEnd, bool stable)
{
    if (!controller)
        return;
    controller->setProperty("NativeP2PPrepareTraceSchemaVersion",
                            uint32_t(1), 32);
    // IORegistry properties are separate writes. Hold an odd/invalid marker
    // while copying the field map so the host collector cannot mistake a
    // partially published generation for a stable snapshot.
    const uint32_t publishRevision = stable ? revisionEnd : 0U;
    const uint32_t oddMarker = stable ? (revisionEnd | 1U) : 1U;
    controller->setProperty("NativeP2PPrepareTraceSnapshotValid",
                            uint32_t(0), 32);
    controller->setProperty("NativeP2PPrepareTraceSnapshotVersionBegin",
                            oddMarker, 32);
    controller->setProperty("NativeP2PPrepareTraceSnapshotVersionEnd",
                            uint32_t(0), 32);
    controller->setProperty("NativeP2PPrepareTraceRevision", uint32_t(0), 32);
    controller->setProperty("NativeP2PPrepareTraceAttemptSerial",
                            stable ? snapshot.serial : 0U, 32);
#define IWX_P2P_TRACE_PUBLISH(name) \
    controller->setProperty("NativeP2PPrepareTraceField." #name, \
        stable ? snapshot.name : 0U, 32);
    IWX_P2P_ROC_PREPARE_TRACE_FIELDS(IWX_P2P_TRACE_PUBLISH)
#undef IWX_P2P_TRACE_PUBLISH
    const uint32_t prepareErrno = stable ? snapshot.prepareErrno : 0U;
    const uint32_t cleanupErrno = stable ? snapshot.cleanupErrno : 0U;
    const uint32_t step = stable ? snapshot.step : 0U;
    const uint32_t reason = stable ? snapshot.reason : 0U;
    controller->setProperty("NativeP2PPrepareTracePrepareErrno",
                            prepareErrno, 32);
    controller->setProperty("NativeP2PPrepareTraceCleanupErrno",
                            cleanupErrno, 32);
    controller->setProperty("NativeP2PPrepareTraceStep", step, 32);
    controller->setProperty("NativeP2PPrepareTraceReason", reason, 32);
    if (!stable)
        return;

    controller->setProperty("NativeP2PPrepareTraceSnapshotVersionEnd",
                            publishRevision, 32);
    controller->setProperty("NativeP2PPrepareTraceRevision",
                            publishRevision, 32);
    controller->setProperty("NativeP2PPrepareTraceSnapshotVersionBegin",
                            revisionBegin, 32);
    controller->setProperty("NativeP2PPrepareTraceSnapshotValid",
                            snapshot.valid ? 1U : 0U, 32);
}

static int readRocState(P2PProbeRun *probe, RocEventRun *event,
                        bool consumeRx = false)
{
    if (!probe || !probe->owner || !event)
        return EINVAL;
    event->probe = probe;
    event->operation = kRocRead;
    event->consumeRxAfterRead = consumeRx;
    IOCommandGate *gate = probe->owner->tahoeP2pCommandGate();
    if (!gate || gate->runAction(ItlIwx::tahoeP2pRocEventAction, event) !=
                     kIOReturnSuccess ||
        (!probe->rx149ObservationOnly && !event->txSnapshotValid))
        return EBUSY;
    return 0;
}

static bool rx149ActualRocChannel(struct iwx_softc *sc)
{
    if (!sc || sc->sc_p2p_roc.roc_channel == nullptr ||
        nitems(sc->sc_ic.ic_channels) <=
            NativeP2PRx149Observation::kIeeeChannel)
        return false;
    return sc->sc_p2p_roc.roc_channel ==
            &sc->sc_ic.ic_channels[
                NativeP2PRx149Observation::kIeeeChannel] &&
        ieee80211_chan2ieee(&sc->sc_ic,
                            sc->sc_p2p_roc.roc_channel) ==
            NativeP2PRx149Observation::kIeeeChannel;
}

static bool rx149StationAndPhyOwnerCurrent(const struct iwx_softc *sc)
{
    if (!sc || sc->sc_ic.ic_state != IEEE80211_S_RUN ||
        (sc->sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR |
                         IWX_FLAG_RFKILL)) != 0 ||
        sc->sc_ic.ic_bss == nullptr)
        return false;
    const auto &roc = sc->sc_p2p_roc;
    const uint32_t currentStationEpoch = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    if (roc.fw_generation != static_cast<uint32_t>(sc->sc_generation) ||
        roc.station_epoch != currentStationEpoch ||
        static_cast<void *>(sc->sc_ic.ic_bss) != roc.station_bss ||
        roc.station_phy_id != 0 ||
        roc.station_phy_id >= IWX_NUM_PHY_CTX ||
        roc.station_phy_channel == nullptr || roc.phy_id != 1 ||
        roc.phy_id >= IWX_NUM_PHY_CTX || roc.roc_channel == nullptr)
        return false;
    const auto *station = reinterpret_cast<const struct iwx_node *>(
        sc->sc_ic.ic_bss);
    const auto *stationPhy = &sc->sc_phyctxt[roc.station_phy_id];
    const auto *p2pPhy = &sc->sc_phyctxt[roc.phy_id];
    return station->in_phyctxt == stationPhy &&
        station->in_phyctxt->id == roc.station_phy_id &&
        station->in_phyctxt->color == roc.station_phy_color &&
        station->in_ni.ni_chan == roc.station_phy_channel &&
        stationPhy->id == roc.station_phy_id &&
        stationPhy->color == roc.station_phy_color &&
        stationPhy->channel == roc.station_phy_channel &&
        sc->sc_p2p.initialized &&
        sc->sc_p2p.fw_generation == roc.fw_generation &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.mac_id == 1 && sc->sc_p2p.phy_leased &&
        sc->sc_p2p.phy_id == roc.phy_id &&
        sc->sc_p2p.binding_id == roc.phy_id &&
        sc->sc_p2p.phy_color == roc.phy_color &&
        sc->sc_p2p.binding_color == roc.phy_color &&
        p2pPhy->id == roc.phy_id && p2pPhy->color == roc.phy_color &&
        p2pPhy->channel == roc.roc_channel;
}

static NativeP2PRx149Observation::RocEvidence rx149RocEvidence(
    const P2PProbeRun *probe,
    const IntelROCEvent::SessionSnapshot &session,
    uint16_t rxChannel = 0xffffu)
{
    NativeP2PRx149Observation::RocEvidence evidence{};
    if (!probe || !probe->owner || !probe->rx149ObservationOnly)
        return evidence;
    ItlIwx *owner = probe->owner;
    auto &sc = owner->com;
    IOEthernetController *controller = owner->tahoeP2pController();
    const auto &lease = owner->tahoe_p2p_rx_lease_;
    const uint32_t rocGeneration = __atomic_load_n(
        &owner->nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    evidence.profileSelected = rx149ArmModeSelected(owner) &&
        rx149ObservationOnlyRequested(controller) &&
        rx149ProfileStatus(owner, controller) ==
            NativeP2PRx149Observation::ProfileStatus::kSelected;
    evidence.receiveObservationOnly = __atomic_load_n(
        &sc.sc_p2p_roc.receive_observation_only, __ATOMIC_ACQUIRE) != 0;
    evidence.requestedChannel149 =
        __atomic_load_n(&owner->nativeP2pRocChannel_, __ATOMIC_ACQUIRE) ==
            NativeP2PRx149Observation::kIeeeChannel &&
        __atomic_load_n(&owner->nativeP2pRocDurationMs_, __ATOMIC_ACQUIRE) ==
            NativeP2PRx149Observation::kSessionDurationMs;
    evidence.actualRocChannel149 = rx149ActualRocChannel(&sc);
    evidence.rxChannel149 = rxChannel < nitems(sc.sc_ic.ic_channels) &&
        ieee80211_chan2ieee(&sc.sc_ic,
            &sc.sc_ic.ic_channels[rxChannel]) ==
                NativeP2PRx149Observation::kIeeeChannel;
    evidence.leaseActive = probe->leaseValue && probe->leasePublished &&
        probe->addAcknowledged && lease.active && sc.sc_p2p.initialized &&
        sc.sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc.sc_p2p.binding_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc.sc_p2p.phy_leased;
    evidence.ownerCurrent = owner->nativeP2pBusy() &&
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) ==
            reinterpret_cast<void *>(probe->workerThread) &&
        owner->nativeP2pProbeGeneration_ == probe->contextGeneration;
    evidence.epochsMatch = uint32_t(sc.sc_generation) ==
            probe->powerGeneration &&
        __atomic_load_n(&sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE) ==
            probe->stationGeneration &&
        lease.contextGeneration == probe->contextGeneration &&
        lease.currentContextGeneration == owner->nativeP2pProbeGeneration_ &&
        lease.powerGeneration == probe->powerGeneration &&
        lease.currentPowerGeneration == uint32_t(sc.sc_generation) &&
        lease.stationGeneration == probe->stationGeneration &&
        lease.currentStationGeneration == __atomic_load_n(
            &sc.sc_tx_rate_generation, __ATOMIC_ACQUIRE) &&
        rx149StationAndPhyOwnerCurrent(&sc);
    evidence.tokenMatches = rocGeneration == probe->contextGeneration &&
        session.generation == probe->contextGeneration &&
        sc.sc_p2p_roc.token == probe->contextGeneration;
    evidence.commandReturned = session.commandReturned;
    evidence.commandSucceeded = session.commandReturned &&
        session.commandResult == 0;
    evidence.deviceDiscoveryConfiguration = session.configuration ==
        IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV;
    evidence.startSeen = session.startSeen;
    evidence.startSucceeded = session.startSeen && session.startStatus == 1;
    evidence.endSeen = session.endSeen;
    evidence.endConfirmed = session.endSeen && session.cleanupAllowed &&
        session.endStatus == 1 && !session.outcomeUnknown;
    evidence.outcomeUnknown = session.outcomeUnknown;
    return evidence;
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
        const int readError = readRocState(probe, &event, true);
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
            const auto mifCompletion = classifyMifCompletion(
                probe->mifBootstrapSelected,
                probe->mifBootstrapPairMifAttempted,
                probe->mifBootstrapTicketIdentity,
                probe->mifBootstrapPairTicketIdentity,
                event.txSnapshot);
            probe->mifTxSucceeded = mifCompletion.txSucceeded;
            const uint64_t mifCompletionUs =
                p2pProbeMonotonicNanoseconds() / 1000ULL;
            const bool bootstrapTicketCompletion =
                probe->mifBootstrapSubmitted &&
                !probe->mifBootstrapPairMifAttempted &&
                ticketIdentityFieldsMatch(probe->mifBootstrapTicketIdentity,
                                          event.txSnapshot);
            if (bootstrapTicketCompletion) {
                probe->mifBootstrapCompletedUs = mifCompletionUs;
                probe->mifBootstrapSucceeded =
                    ticketIdentityMatches(probe->mifBootstrapTicketIdentity,
                                          event.txSnapshot);
                probe->mifBootstrapPairDiagnosticsDirty = true;
                if (!probe->mifBootstrapSucceeded) {
                    probe->mifBootstrapStatus = static_cast<uint32_t>(
                        Test070MifBootstrap::Status::Blocked);
                    probe->mifBootstrapBlockers |=
                        Test070MifBootstrap::kCandidatePreparationFailed;
                }
            } else if (probe->mifBootstrapSubmitted &&
                       !probe->mifBootstrapPairMifAttempted &&
                       !probe->mifBootstrapSucceeded) {
                probe->mifBootstrapStatus = static_cast<uint32_t>(
                    Test070MifBootstrap::Status::Blocked);
                probe->mifBootstrapBlockers |=
                    Test070MifBootstrap::kCandidatePreparationFailed;
            }
            if (probe->mifBootstrapSelected &&
                probe->mifBootstrapPairMifAttempted) {
                probe->mifBootstrapPairMifCompleted = true;
                probe->mifBootstrapPairMifSucceeded =
                    mifCompletion.txSucceeded;
                probe->mifBootstrapPairStatus =
                    probe->mifBootstrapPairMifSucceeded ?
                        kMifBootstrapPairMifCompleted :
                        kMifBootstrapPairMifFailed;
                probe->mifBootstrapPairDiagnosticsDirty = true;
                if (!probe->mifBootstrapPairMifSucceeded) {
                    probe->mifBootstrapPairBlockers |=
                        kMifBootstrapPairTicketMismatch;
                    probe->mifBurstStopped = true;
                    probe->mifBurstStopReason = static_cast<uint32_t>(
                        NativeAwdlProbe::MifBurstStopReason::PreviousTicketFailed);
                }
            }
#else
            probe->mifTxSucceeded =
                event.txSnapshot.frameAttemptSucceeded &&
                (event.txSnapshot.ticketStatus & 0xffu) == 1u;
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
            if (probe->mifTxSucceeded &&
                probe->discoveryModeSelected &&
                probe->discoveryMode ==
                    NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot &&
                mifCompletion.grantsOwnFirst &&
                probe->discoveryOwnFirstMifCompletionUs == 0)
                probe->discoveryOwnFirstMifCompletionUs =
                    probe->mifBurstLastCompletionUs;
#endif
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
           probe->mifResultCaptured&&probe->mifTxSucceeded&&probe->nativeDataAttempts<4
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
           && (!probe->mifBootstrapSelected ||
               (probe->mifBootstrapPairMifCompleted &&
                probe->mifBootstrapPairMifSucceeded))
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
           && !probe->discoveryConsumed
#endif
           ) {
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
                // RX has an independent bounded drain on the active main-gate
                // ROC path; data dequeue remains behind its own strict gates.
                NativeAwdlBSD::poll(true,uint32_t(self->com.sc_generation));
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
                if (nativeResidentAddressProfileEnabled(self)) {
                    uint8_t liveAddress[6]{};
                    const uint32_t identityFailure = run->nativeAddressCandidateVerified ?
                        verifyNativeIdentity(self, run->contextGeneration,
                            run->powerGeneration, run->stationGeneration,
                            run->address, sc.sc_p2p.mac_address, liveAddress) :
                        kNativeIdentityBsdAddressUnavailable;
                    if (identityFailure != kNativeIdentityVerified) {
                        publishNativeIdentityStatus(self, false,
                                                    identityFailure);
                        NativeAwdlBSD::gateObservation(1u << 13);
                        return kIOReturnNotReady;
                    }
                }
#endif
                IntelAwdlPeer::RuntimeEpochs epochs{run->contextGeneration,run->powerGeneration,run->stationGeneration,true};
                const auto peer=self->tahoe_awdl_peer_observer_.snapshot(epochs,p2pProbeMonotonicNanoseconds()/1000);
                uint32_t peerBlockers=0;
                if(!peer.validPeerCount)peerBlockers|=1u<<9;
                if(peer.latestPeerAgeUs>1000000)peerBlockers|=1u<<10;
                if(peer.nextAwChannel!=6&&peer.masterChannel!=6)peerBlockers|=1u<<11;
                uint64_t token = 0;
                mbuf_t packet = nullptr;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                bool discoveryPacket = false;
                // The manual run's selected mode is immutable. If its live
                // property is later disabled, the selected discovery path
                // fails closed instead of falling through to ordinary TX.
                const bool discoveryProfile = run->discoveryModeSelected;
                // The observer count only selects a stricter gate; it never
                // identifies or authenticates a runtime-table slot.
                const bool requireRuntimeMifBinding = peer.validPeerCount != 0;
                const bool mifCurrentMode = run->discoveryModeSelected &&
                    run->discoveryMode ==
                        NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot;
                run->discoveryFormalObserverPeerCount = peer.validPeerCount;
                // MIF-current mode authorizes only from a same-entry runtime
                // MIF snapshot and its phase helper; aggregate observer
                // blockers neither select the mode nor identify that entry.
                const bool observerGateClear = mifCurrentMode ||
                    !requireRuntimeMifBinding || peerBlockers == 0;
                if (discoveryProfile && observerGateClear &&
                    run->nativeDataAttempts == 0 && !run->discoveryConsumed &&
                    isCurrentIeeeChannel6(&self->com.sc_ic,
                        self->com.sc_p2p_roc.roc_channel)) {
                    packet = takeDiscoveryPacket(run, epochs,
                        self->nativeP2pActionTx_.nextSequenceNumber, &token,
                        requireRuntimeMifBinding);
                    discoveryPacket = packet != nullptr;
                }
                if (discoveryProfile && !discoveryPacket) {
                    if (!mifCurrentMode && peer.validPeerCount &&
                        !run->discoveryWindowClosed) {
                        if (run->discoveryStatus == 0)
                            run->discoveryStatus = 16; // Observer gate blocked this run.
                        run->discoveryWindowClosed = true;
                        publishDiscoveryExperiment(run);
                    }
                    NativeAwdlBSD::gateObservation(
                        mifCurrentMode ? (1u << 14) :
                        (peerBlockers ? peerBlockers : (1u << 14)));
                    return kIOReturnNotReady;
                }
                if (peerBlockers && !discoveryPacket) {
#else
                if (peerBlockers) {
#endif
                    NativeAwdlBSD::gateObservation(peerBlockers);
                    return kIOReturnNotReady;
                }
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                if (run->mifBootstrapSelected && !discoveryPacket) {
                    NativeAwdlBSD::gateObservation(1u << 14);
                    return kIOReturnNotReady;
                }
#endif
                if (!packet)
                    packet = NativeAwdlBSD::nextTx(
                        self->nativeP2pActionTx_.nextSequenceNumber, &token);
                if(!packet){NativeAwdlBSD::gateObservation(1u<<12);return kIOReturnNotReady;}
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                if (discoveryPacket) {
                    const uint64_t gateUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
                    if (gateUs < run->discoveryTarget.earliestSubmitUs ||
                        gateUs >= run->discoveryTarget.latestSubmitUs) {
                        mbuf_freem(packet);
                        NativeAwdlBSD::submitted(token, ETIMEDOUT);
                        run->discoveryStatus = 15;
                        run->discoverySubmitResult = ETIMEDOUT;
                        publishDiscoveryExperiment(run, true);
                        return kIOReturnNotReady;
                    }
                    run->discoverySubmitCallStartUs = gateUs;
                }
#endif
                NativeAwdlBSD::gateObservation(0);
                ++run->nativeDataAttempts;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332) && \
    defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                if (discoveryPacket) {
                    const uint64_t submitStartUs =
                        p2pProbeMonotonicNanoseconds() / 1000ULL;
                    (void)self->nativeP2pActionTx_.dataTxTrace
                        .markSubmitCallStart(token, submitStartUs);
                }
#endif
                const int result=iwx_tahoe_p2p_action_tx_submit(self,&self->com,&self->nativeP2pTxQueue_,
                    &self->nativeP2pActionTx_,run->contextGeneration,true,false,packet,token
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                    , nullptr,
                    discoveryPacket ? run->discoveryTarget.earliestSubmitUs : 0,
                    discoveryPacket ? run->discoveryTarget.latestSubmitUs : 0,
                    discoveryPacket ? run->stationGeneration : 0
#endif
                    );
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332) && \
    defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                if (discoveryPacket) {
                    const uint64_t submitEndUs =
                        p2pProbeMonotonicNanoseconds() / 1000ULL;
                    (void)self->nativeP2pActionTx_.dataTxTrace
                        .markSubmitCallEnd(token, result, submitEndUs);
                }
#endif
                // Quarantine alone does not prove a doorbell was written:
                // pre-doorbell cancellation can also quarantine the slot.
                // Count submission only after the irreversible MMIO write.
                const uint32_t submitStage=__atomic_load_n(
                    &self->nativeP2pActionTx_.submitDiagnostics.lastStage,
                    __ATOMIC_ACQUIRE);
                const bool doorbellIssued=submitStage==static_cast<uint32_t>(
                    TahoeP2PActionTxSubmitStage::kDoorbellIssued) ||
                    submitStage==static_cast<uint32_t>(
                    TahoeP2PActionTxSubmitStage::kPostDoorbellFinish);
                if(doorbellIssued)
                    NativeAwdlBSD::submitted(token,0);
                else NativeAwdlBSD::submitted(token,result?result:EIO);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332) && \
    defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                if (discoveryPacket && !doorbellIssued && result == 0) {
                    const uint64_t cancelledAtUs =
                        p2pProbeMonotonicNanoseconds() / 1000ULL;
                    (void)self->nativeP2pActionTx_.dataTxTrace
                        .markCancelled(token, EIO, cancelledAtUs);
                }
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                if (discoveryPacket) {
                    run->discoverySubmitCallEndUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
                    run->discoveryDoorbelled = doorbellIssued;
                    run->discoverySubmitResult = result;
                    run->discoveryStatus = doorbellIssued ? 13 : 14;
                    publishDiscoveryExperiment(run, true);
                }
#endif
                return kIOReturnSuccess;
            };
            gate->runAction(submitData,probe);
        }
#endif
        // Pacing waits inside the already-announced local channel-6 window.
        // Each MIF needs a new, complete, same-epoch peer PSF received on
        // mapped IEEE channel 6; the MIF gate does not admit peers or follow
        // their advertised schedule.
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        const uint64_t discoveryHoldNowUs =
            p2pProbeMonotonicNanoseconds() / 1000ULL;
        const uint64_t discoveryLeaseEndUs =
            probe->psfCandidate.hardDeadlineUs <
                    probe->mifPacingWindowEndUs ?
                probe->psfCandidate.hardDeadlineUs :
                probe->mifPacingWindowEndUs;
        const uint64_t discoveryUsableLeaseEndUs =
            discoveryLeaseEndUs > Test066MifCurrentPhase::kLeaseReserveUs ?
                discoveryLeaseEndUs -
                    Test066MifCurrentPhase::kLeaseReserveUs : 0;
        const auto &discoveryHoldTarget = probe->discoveryMifTarget;
        const NativeAwdlMifDiscoveryHoldTest068::Input discoveryHoldInput{
            probe->discoveryModeSelected,
            probe->discoveryMode ==
                NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot,
            probe->discoveryOwnFirstMifCompletionUs != 0,
            probe->discoveryCandidateLocked,
            probe->discoveryRequiresRuntimeMifBinding,
            probe->discoveryRuntimeMifBound,
            probe->discoveryBindingLocked &&
                probe->discoveryBinding.hasPendingReservation(),
            discoveryHoldTarget.status ==
                Test066MifCurrentPhase::Status::kCandidate,
            probe->discoveryConsumed,
            probe->discoveryWindowClosed,
            probe->canceled,
            event.snapshot.commandReturned &&
                event.snapshot.commandResult == 0 &&
                event.snapshot.configuration ==
                    IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
                event.snapshot.startSeen && event.snapshot.startStatus == 1 &&
                event.snapshot.generation == probe->contextGeneration &&
            !event.snapshot.endSeen && !event.snapshot.outcomeUnknown,
            Test066MifCurrentPhase::sameEpochs(
                discoveryHoldTarget.epochs,
                {probe->contextGeneration, probe->powerGeneration,
                 probe->stationGeneration, probe->contextGeneration}),
            discoveryHoldNowUs,
            probe->psfCandidate.startObservedUs,
            discoveryHoldTarget.earliestSubmitUs,
            discoveryHoldTarget.latestSubmitUs,
            discoveryUsableLeaseEndUs};
        const bool holdMifForDiscovery =
            NativeAwdlMifDiscoveryHoldTest068::shouldHoldMifRepeat(
                discoveryHoldInput);
#else
        const bool holdMifForDiscovery = false;
#endif
        if (probe->awdlMifFollowupEnabled && !holdMifForDiscovery &&
            probe->psfResultCaptured &&
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
            reconcileP2PTxSubmitFrame(frame, &submit);
            if (submitResult == kIOReturnSuccess) {
                probe->txSubmitResult = submit.result;
                publishP2PTxStage(owner,
                    submit.result == 0 ? kTxProbeActionSubmitted :
                                         kTxProbeWaitingForCompletionAndEnd,
                    submit.result);
            } else if (submitResult != kIOReturnNotReady) {
                return EBUSY;
            } else if (submit.frameStale) {
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

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        if (probe->mifBootstrapSelected)
            publishMifBootstrapPairDiagnostics(owner, probe);
#endif
        const uint32_t sleepMs = observationWindow.nextSleepMilliseconds(
            p2pProbeMonotonicNanoseconds());
        uint32_t boundedSleepMs = sleepMs;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        // The experimental current-MIF phase is only a 5.243-ms half-open
        // window. Poll at scheduler sleep granularity after the first own MIF
        // completes, but only during the explicitly selected one-shot run.
        if (probe->discoveryModeSelected && probe->discoveryMode ==
                NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot &&
            probe->discoveryOwnFirstMifCompletionUs != 0 &&
            !probe->discoveryConsumed && !probe->discoveryWindowClosed &&
            boundedSleepMs > 1)
            boundedSleepMs = 1;
#endif
        if (boundedSleepMs == 0)
            break;
        IOSleep(boundedSleepMs);
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
        if (action->armed) {
            __atomic_store_n(&owner->nativeP2pRocGeneration_,
                             probe->contextGeneration, __ATOMIC_RELEASE);
            owner->nativeAwdlRxEventOwnerSerial_ = 0;
            if (owner->nativeAwdlRxEventNextOwnerSerial_ != UINT64_MAX) {
                const uint64_t ownerSerial =
                    ++owner->nativeAwdlRxEventNextOwnerSerial_;
                const NativeAwdlRxTrace::Epochs epochs {
                    probe->contextGeneration, probe->powerGeneration,
                    probe->stationGeneration, probe->contextGeneration
                };
                if (owner->nativeAwdlRxEventTimeline_.beginOwner(
                        ownerSerial, epochs))
                    owner->nativeAwdlRxEventOwnerSerial_ = ownerSerial;
            }
        }
    } else if (action->operation == kRocCommandReturned) {
        tracker.noteCommandResult(probe->contextGeneration, action->commandResult);
        // START can arrive before the submitter records the successful ACK.
        // Re-evaluate the same diagnostic-only owner gate after both exist.
        owner->tahoeP2pSyncRxDiagnosticOwner(false);
    } else if (action->operation == kRocExpire) {
        tracker.expire(probe->contextGeneration);
        owner->tahoeP2pSyncRxDiagnosticOwner(true);
    }
    action->snapshot = tracker.snapshot();
    storeRocSnapshot(owner, action->snapshot);
    if (action->operation == kRocCloseRx149) {
        const auto evidence = rx149RocEvidence(probe, action->snapshot);
        if (!probe->rx149ObservationOnly ||
            !NativeP2PRx149Observation::mayReleaseAfterEnd(evidence))
            return kIOReturnNotReady;
        const auto trace = owner->nativeAwdlRxEventTimeline_.snapshot();
        const NativeAwdlRxTrace::Epochs epochs{
            probe->contextGeneration, probe->powerGeneration,
            probe->stationGeneration, probe->contextGeneration
        };
        if (!trace.ownerPresent ||
            trace.ownerSerial != owner->nativeAwdlRxEventOwnerSerial_ ||
            !NativeAwdlRxTrace::sameEpochs(trace.epochs, epochs))
            return kIOReturnNotReady;
        if (!trace.producerClosed &&
            !owner->nativeAwdlRxEventTimeline_.closeProducer(
                owner->nativeAwdlRxEventOwnerSerial_, epochs, 4u))
            return kIOReturnNotReady;
        // The main workloop gate serializes RX ingress. Closing the producer
        // above therefore fixes the last eligible record boundary before this
        // bounded drain; records from before START could never have entered.
        owner->tahoeP2pRxConsume();
        const auto drained = owner->nativeAwdlRxEventTimeline_.snapshot();
        P2PTxDiagnosticSnapshot finalTxSnapshot{};
        const bool txStillQuiescent =
            rx149TxHistoryQuiescent(owner, &finalTxSnapshot);
        action->rxDrainComplete = drained.ownerPresent &&
            drained.ownerSerial == owner->nativeAwdlRxEventOwnerSerial_ &&
            NativeAwdlRxTrace::sameEpochs(drained.epochs, epochs) &&
            !drained.active && drained.producerClosed &&
            drained.pendingDrainCount == 0 &&
            drained.untrackedPendingDrainCount == 0 &&
            drained.untrackedPendingIdentityOverflowCount == 0 &&
            drained.droppedEventCount == 0 &&
            drained.sourceTableFullCount == 0 &&
            drained.sessionBoundaryOrderInvalid == 0 &&
            txStillQuiescent;
        if (auto *controller = owner->tahoeP2pController())
            owner->tahoeP2pPublishRxEventTimeline(controller);
        // A bounded live command/RX trace snapshot at the existing ROC close
        // boundary captures sub-second diagnostics without opening or
        // extending the radio window. A watchdog-frozen trace always wins.
        if (auto *controller = owner->tahoeP2pController())
            (void)owner->tahoePublishFirmwareDiagnostics(
                controller, &owner->com, true);
        if (!action->rxDrainComplete)
            return kIOReturnNotReady;
    } else if (action->operation == kRocRead) {
        if (!probe->rx149ObservationOnly) {
            action->txSnapshotValid = captureP2PTxSnapshot(
                owner, &action->txSnapshot);
        }
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
        action->rx149DataLease = {};
        if (probe->rx149ObservationOnly)
            (void)owner->tahoeP2pRx149DataLease(&action->rx149DataLease);
#endif
        if (action->consumeRxAfterRead && probe->rx149ObservationOnly) {
            const auto evidence = rx149RocEvidence(probe, action->snapshot);
            if (NativeP2PRx149Observation::validStartedOwner(evidence) &&
                !evidence.endSeen)
                owner->tahoeP2pRxConsume();
        } else if (action->consumeRxAfterRead && action->txSnapshotValid) {
            auto &sc = owner->com;
            const auto &session = action->snapshot;
            const auto &rxLease = owner->tahoe_p2p_rx_lease_;
            const bool rxLeaseCurrent = rxLease.active &&
                rxLease.contextGeneration == probe->contextGeneration &&
                rxLease.currentContextGeneration ==
                    owner->nativeP2pProbeGeneration_ &&
                rxLease.powerGeneration == probe->powerGeneration &&
                rxLease.currentPowerGeneration ==
                    uint32_t(sc.sc_generation) &&
                rxLease.stationGeneration == probe->stationGeneration &&
                rxLease.currentStationGeneration ==
                    __atomic_load_n(&sc.sc_tx_rate_generation,
                                    __ATOMIC_ACQUIRE);
            const bool activeAckedRoc = session.commandReturned &&
                session.commandResult == 0 &&
                session.configuration ==
                    IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION &&
                session.generation == probe->contextGeneration &&
                session.startSeen && session.startStatus == 1 &&
                !session.endSeen && !session.outcomeUnknown &&
                sc.sc_p2p_roc.token == probe->contextGeneration &&
                sc.sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED &&
                isCurrentIeeeChannel6(&sc.sc_ic,
                                      sc.sc_p2p_roc.roc_channel);
            const bool p2pOwnerCurrent = probe->leaseValue &&
                probe->leasePublished && probe->addAcknowledged &&
                sc.sc_p2p.initialized &&
                sc.sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
                sc.sc_p2p.binding_state == IWX_P2P_RESOURCE_ACTIVE &&
                sc.sc_p2p.phy_leased;
            if (rxLeaseCurrent && activeAckedRoc && p2pOwnerCurrent)
                owner->tahoeP2pRxConsume();
        }
    }
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
    const uint64_t hostUs = p2pProbeMonotonicNanoseconds() / 1000ULL;
    const NativeAwdlRxTrace::Epochs epochs {
        static_cast<uint32_t>(lease.contextGeneration),
        static_cast<uint32_t>(lease.powerGeneration),
        static_cast<uint32_t>(lease.stationGeneration), generation
    };
    const auto before = nativeP2pRocEvents_.snapshot();
    const bool reducerReturnedTrue = nativeP2pRocEvents_.noteNotification(
        generation, bytes, length, hostUs);
    const auto after = nativeP2pRocEvents_.snapshot();
    const bool canonicalStart = !before.startSeen && after.startSeen;
    const bool canonicalEnd = !before.endSeen && after.endSeen;
#if defined(ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332)
    // Observe actual reducer boundaries independently of per-MPDU owner, MAC,
    // channel and frame classification. This adds no receive qualification.
    tahoeRxRocCorrelationSync(hostUs);
    using namespace NativeIwxRocRxCorrelation;
    RocEpoch correlationEpoch;
    correlationEpoch.contextGeneration = epochs.contextGeneration;
    correlationEpoch.powerGeneration = epochs.powerGeneration;
    correlationEpoch.stationGeneration = epochs.stationGeneration;
    correlationEpoch.rocGeneration = generation;
    correlationEpoch.sessionToken = generation;
    if (canonicalStart && nativeRxRocCorrelation_.state() == State::kArmed) {
        const uint64_t durationUs = uint64_t(__atomic_load_n(
            &nativeP2pRocDurationMs_, __ATOMIC_ACQUIRE)) * 1000ULL;
        if (reducerReturnedTrue && after.startStatus == 1 &&
            after.configuration == IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV &&
            durationUs != 0 && after.startObservedMonotonicUs != 0 &&
            after.startObservedMonotonicUs <= UINT64_MAX - durationUs) {
            const uint64_t deadlineUs = after.startObservedMonotonicUs + durationUs;
            // This reducer runs while iwx_rx_pkt() consumes the current RX
            // ring batch. Its outer interrupt/drain/slot evidence may precede
            // START in that same batch, so stage attribution must stay marked
            // partial even though later notification counts remain observable.
            if (nativeRxRocCorrelation_.beginRoc(correlationEpoch,
                    after.startObservedMonotonicUs, deadlineUs, true)) {
                nativeRxRocEpoch_ = correlationEpoch;
                nativeRxRocDeadlineUs_ = deadlineUs;
            }
        } else {
            (void)nativeRxRocCorrelation_.close(
                CloseReason::kInvalidBoundary, hostUs);
        }
    }
    if (canonicalEnd && (nativeRxRocCorrelation_.state() == State::kActive ||
                         nativeRxRocCorrelation_.state() == State::kArmed)) {
        if (reducerReturnedTrue && after.endStatus == 1 &&
            nativeRxRocCorrelation_.state() == State::kActive)
            (void)nativeRxRocCorrelation_.endRoc(correlationEpoch,
                after.endObservedMonotonicUs, true);
        else
            (void)nativeRxRocCorrelation_.close(
                CloseReason::kInvalidBoundary, hostUs);
    }
#endif
    const auto traceOwner = nativeAwdlRxEventTimeline_.snapshot();
    const bool traceOwnerMatches = nativeAwdlRxEventOwnerSerial_ != 0 &&
        traceOwner.ownerPresent &&
        traceOwner.ownerSerial == nativeAwdlRxEventOwnerSerial_ &&
        NativeAwdlRxTrace::sameEpochs(traceOwner.epochs, epochs);

    if (traceOwnerMatches) {
        NativeAwdlRxTrace::SessionProtection16 notification{};
        notification.hostMonotonicUs = hostUs;
        notification.hostMonotonicPresent = 1;
        notification.rawLength = static_cast<uint32_t>(
            length > UINT32_MAX ? UINT32_MAX : length);
        notification.ownerSessionToken = generation;
        notification.expectedUidKnown = lease.timeEventUidKnown ? 1u : 0u;
        notification.expectedUid = lease.timeEventUid;
        notification.reducerResultPresent = 1;
        notification.reducerReturnedTrue = reducerReturnedTrue ? 1u : 0u;
        notification.reducerResult = reducerReturnedTrue ? 1u : 0u;
        notification.canonicalTransitionPresent = 1;
        notification.canonicalTransition =
            (canonicalStart || canonicalEnd) ? 1u : 0u;

        const bool rawPresent = bytes && length >= 16;
        if (rawPresent) {
            notification.macIdAndColor = tahoeP2pProbeReadLe32(bytes + 0);
            notification.rawStatus = tahoeP2pProbeReadLe32(bytes + 4);
            notification.rawStartFlag = tahoeP2pProbeReadLe32(bytes + 8);
            notification.configuration = tahoeP2pProbeReadLe32(bytes + 12);
        }
        if (!rawPresent || length != 16) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::Malformed;
        } else if (notification.macIdAndColor != lease.macIdAndColor ||
                   notification.configuration !=
                       nativeP2pRocConfiguration_) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::ForeignContext;
        } else if (notification.rawStatus > 1 ||
                   notification.rawStartFlag > 1) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::Malformed;
        } else if (before.endSeen && notification.rawStartFlag == 1) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::LateAfterEnd;
        } else if (notification.rawStartFlag == 1 && before.startSeen) {
            notification.anomalyReason = before.startStatus ==
                    notification.rawStatus
                ? NativeAwdlRxTrace::SessionAnomalyReason::Duplicate
                : NativeAwdlRxTrace::SessionAnomalyReason::Conflicting;
        } else if (notification.rawStartFlag == 0 && before.endSeen) {
            notification.anomalyReason = before.endStatus ==
                    notification.rawStatus
                ? NativeAwdlRxTrace::SessionAnomalyReason::Duplicate
                : NativeAwdlRxTrace::SessionAnomalyReason::Conflicting;
        } else if (notification.rawStartFlag == 0 && !before.startSeen &&
                   canonicalEnd) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::EndBeforeStart;
        } else if (!reducerReturnedTrue &&
                   !canonicalStart && !canonicalEnd) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::ReducerIgnored;
        } else if (reducerReturnedTrue &&
                   !canonicalStart && !canonicalEnd) {
            notification.anomalyReason =
                NativeAwdlRxTrace::SessionAnomalyReason::UnclassifiedNoncanonical;
        }
        (void)nativeAwdlRxEventTimeline_.recordSessionProtection(
            notification, epochs, nativeAwdlRxEventOwnerSerial_);
        if (canonicalStart)
            tahoeP2pSyncRxDiagnosticOwner(false);
        if (canonicalEnd) {
            (void)nativeAwdlRxEventTimeline_.closeProducer(
                nativeAwdlRxEventOwnerSerial_, epochs, 1);
            // Close only an existing matching owner. An END must never create
            // an empty-window owner or retrospectively claim RX coverage.
            tahoeP2pSyncRxDiagnosticOwner(true);
        }
    }
}

static void drainRx149NativeDataOutsideMainGate(
    P2PProbeRun *probe, const RocEventRun &event)
{
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    auto *owner = probe ? probe->owner : nullptr;
    if (!owner || owner->tahoeP2pOnMainGate())
        return;
    const auto &sc = owner->com;
    const bool radioReady = sc.sc_ic.ic_state == IEEE80211_S_RUN &&
        !(sc.sc_flags & (IWX_FLAG_HW_ERR | IWX_FLAG_SHUTDOWN | IWX_FLAG_RFKILL));
    // No firmware command, TX dequeue or main-gate KPI callback. The BSD
    // queue independently checks this permit and its current clock at input.
    NativeAwdlBSD::poll(radioReady, uint32_t(sc.sc_generation),
                        &event.rx149DataLease);
#else
    (void)probe;
    (void)event;
#endif
}

static int exerciseRx149Observation(P2PProbeRun *probe)
{
    if (!probe || !probe->owner || !probe->rx149ObservationOnly ||
        probe->txProbeEnabled || probe->awdlPsfProbeEnabled ||
        probe->awdlMifFollowupEnabled)
        return EINVAL;

    ItlIwx *owner = probe->owner;
    struct iwx_softc *sc = &owner->com;
    IOEthernetController *controller = owner->tahoeP2pController();
    const uint32_t channelNumber =
        NativeP2PRx149Observation::kIeeeChannel;
    const uint32_t durationMs =
        NativeP2PRx149Observation::kSessionDurationMs;
    const uint32_t configuration =
        IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV;
    if (!rx149ArmModeSelected(owner) ||
        !rx149ObservationOnlyRequested(controller) ||
        rx149ProfileStatus(owner, controller) !=
            NativeP2PRx149Observation::ProfileStatus::kSelected ||
        nitems(sc->sc_ic.ic_channels) <= channelNumber ||
        ieee80211_chan2ieee(&sc->sc_ic,
            &sc->sc_ic.ic_channels[channelNumber]) != channelNumber ||
        !owner->nativeP2pCommandAllowed())
        return EOPNOTSUPP;

    struct iwx_p2p_roc_prepare_trace_snapshot traceBefore{};
    uint32_t traceRevisionBegin = 0;
    uint32_t traceRevisionEnd = 0;
    probe->prepareTraceBaselineValid = readPrepareTraceSnapshot(
        sc, &traceBefore, &traceRevisionBegin, &traceRevisionEnd);
    if (probe->prepareTraceBaselineValid) {
        probe->prepareTraceSerialBefore = traceBefore.serial;
        probe->prepareTraceSerialExpected = traceBefore.serial + 1U;
    }

    __atomic_store_n(&owner->nativeP2pRocStage_, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pRocChannel_, channelNumber,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pRocDurationMs_, durationMs,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pRocConfiguration_, configuration,
                     __ATOMIC_RELEASE);
    int error = owner->tahoeP2pRocPrepare(
        sc, &sc->sc_ic.ic_channels[channelNumber],
        probe->contextGeneration, configuration, true);
    if (error) {
        __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error),
                         __ATOMIC_RELAXED);
        __atomic_store_n(&owner->nativeP2pRocStage_, 6u, __ATOMIC_RELEASE);
        return error;
    }

    __atomic_store_n(&owner->nativeP2pRocStage_, 2u, __ATOMIC_RELEASE);
    // From this point onward the Session Protection command may have reached
    // firmware even if the host sees an error. Never treat a later failure as
    // a prepare-only, known-unsubmitted case.
    probe->sessionSubmitReached = true;
    const int commandResult = owner->tahoeP2pRocSubmit(
        sc, probe->contextGeneration, configuration, durationMs,
        ItlIwx::tahoeP2pArmRoc, probe);
    RocEventRun event{};
    event.probe = probe;
    event.operation = kRocCommandReturned;
    event.commandResult = commandResult;
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    error = gate && gate->runAction(ItlIwx::tahoeP2pRocEventAction,
                                   &event) == kIOReturnSuccess ? 0 : EBUSY;
    __atomic_store_n(&owner->nativeP2pRocStage_, 3u, __ATOMIC_RELEASE);
    if (error || commandResult != 0) {
        error = error ? error : commandResult;
        __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error),
                         __ATOMIC_RELAXED);
        __atomic_store_n(&owner->nativeP2pRocStage_, 6u, __ATOMIC_RELEASE);
        return error;
    }

    // The firmware receives one fixed 100 ms listen command. This bounded
    // host wait observes its START/END notifications; it does not extend or
    // reissue the RF session.
    bool ended = false;
    for (unsigned i = 0; i < 80; ++i) {
        event.operation = kRocRead;
        event.consumeRxAfterRead = true;
        error = readRocState(probe, &event, true);
        if (!error)
            drainRx149NativeDataOutsideMainGate(probe, event);
        if (error)
            break;
        if (event.snapshot.endSeen || event.snapshot.outcomeUnknown) {
            ended = event.snapshot.endSeen;
            break;
        }
        IOSleep(5);
    }
    if (!error && !ended) {
        event.operation = kRocRead;
        event.consumeRxAfterRead = true;
        error = readRocState(probe, &event, true);
        if (!error)
            drainRx149NativeDataOutsideMainGate(probe, event);
        ended = !error && event.snapshot.endSeen;
    }
    if (!error && !ended)
        error = ETIMEDOUT;

    const auto evidence = rx149RocEvidence(probe, event.snapshot);
    if (!error && (!event.snapshot.observedScheduledPair ||
        !NativeP2PRx149Observation::validStartedOwner(evidence) ||
        !NativeP2PRx149Observation::mayReleaseAfterEnd(evidence)))
        error = EPROTO;
    if (error) {
        __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error),
                         __ATOMIC_RELAXED);
        __atomic_store_n(&owner->nativeP2pRocStage_, 6u, __ATOMIC_RELEASE);
        return error; // Preserve the P2P/PHY owner after ambiguous END.
    }

    event.operation = kRocCloseRx149;
    event.rxDrainComplete = false;
    if (!gate || gate->runAction(ItlIwx::tahoeP2pRocEventAction,
                                 &event) != kIOReturnSuccess ||
        !event.rxDrainComplete) {
        error = EBUSY;
        __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error),
                         __ATOMIC_RELAXED);
        __atomic_store_n(&owner->nativeP2pRocStage_, 6u, __ATOMIC_RELEASE);
        return error; // No resource release before a complete final drain.
    }

    error = owner->tahoeP2pRocCleanup(
        sc, probe->contextGeneration, configuration,
        event.snapshot.cleanupAllowed);
    __atomic_store_n(&owner->nativeP2pRocResult_, uint32_t(error),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&owner->nativeP2pRocStage_, error ? 6u : 5u,
                     __ATOMIC_RELEASE);
    return error;
}

int ItlIwx::tahoeP2pExerciseRoc(void *opaque)
{
    auto probe = static_cast<P2PProbeRun *>(opaque);
    if (probe && probe->rx149ObservationOnly)
        return exerciseRx149Observation(probe);
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

bool ItlIwx::tahoeP2pExerciseRecovery(
    void *opaque, int32_t exerciseErrno,
    NativeP2PProbe::ExerciseRecoveryProof *proof)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || !proof || exerciseErrno == 0 ||
        !run->rx149ObservationOnly)
        return false;

    P2PExerciseRecoveryAction action{};
    action.run = run;
    action.exerciseErrno = exerciseErrno;
    action.proof = proof;
    IOCommandGate *gate = run->owner->getMainCommandGate();
    IOWorkLoop *workLoop = run->owner->getMainWorkLoop();
    if (!gate || !workLoop || workLoop->onThread() || workLoop->inGate())
        return false;
    const IOReturn result = gate->runAction(
        tahoeP2pExerciseRecoveryAction, &action);
    return result == kIOReturnSuccess && action.snapshotRead;
}

IOReturn ItlIwx::tahoeP2pExerciseRecoveryAction(
    OSObject *, void *opaque, void *, void *, void *)
{
    auto action = static_cast<P2PExerciseRecoveryAction *>(opaque);
    auto run = action ? action->run : nullptr;
    auto proof = action ? action->proof : nullptr;
    ItlIwx *owner = run ? run->owner : nullptr;
    if (!action || !run || !owner || !proof ||
        !owner->tahoeP2pOnMainGate() || !run->rx149ObservationOnly)
        return kIOReturnBadArgument;

    *proof = {};
    action->snapshotRead = false;
    struct iwx_softc *sc = &owner->com;
    struct iwx_p2p_roc_prepare_trace_snapshot trace{};
    uint32_t revisionBegin = 0;
    uint32_t revisionEnd = 0;
    const bool stable = readPrepareTraceSnapshot(
        sc, &trace, &revisionBegin, &revisionEnd);
    publishPrepareTraceSnapshot(owner->tahoeP2pController(), trace,
                                revisionBegin, revisionEnd, stable);
    if (!stable)
        return kIOReturnSuccess;

    const bool ownerCurrent = owner->nativeP2pBusy() &&
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) ==
            reinterpret_cast<void *>(run->workerThread) &&
        owner->nativeP2pProbeGeneration_ == run->contextGeneration &&
        !run->canceled;
    const NativeP2PProbe::Snapshot halSnapshot =
        owner->nativeP2pProbe_.snapshot();
    const bool traceAttemptMatches = run->prepareTraceBaselineValid &&
        run->prepareTraceSerialExpected != 0 && trace.valid == 1 &&
        trace.serial == run->prepareTraceSerialExpected &&
        trace.token == run->contextGeneration &&
        trace.configuration == IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV &&
        trace.receiveObservation149 == 1 && trace.featureCompiled == 1 &&
        trace.requestedChannelPresent == 1 &&
        trace.ieeeChannelNumber == NativeP2PRx149Observation::kIeeeChannel &&
        trace.channelIndex == NativeP2PRx149Observation::kIeeeChannel;
    const bool scGenerationMatches =
        uint32_t(sc->sc_generation) == run->scGeneration &&
        trace.scGenerationEntry == run->scGeneration &&
        trace.scGenerationExit == run->scGeneration;
    const bool p2pFirmwareGenerationMatches =
        run->p2pFirmwareGeneration == run->scGeneration &&
        sc->sc_p2p.fw_generation == run->p2pFirmwareGeneration &&
        trace.p2pFirmwareGenerationEntry == run->p2pFirmwareGeneration &&
        trace.p2pFirmwareGenerationExit == run->p2pFirmwareGeneration;
    const uint32_t currentStationEpoch = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    const bool stationEpochMatches =
        currentStationEpoch == run->stationGeneration &&
        trace.stationEpochEntry == run->stationGeneration &&
        trace.stationEpochExit == run->stationGeneration;
    const bool bindingAbsent = trace.bindingKnownAbsent == 1 &&
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT;
    const bool phyUnleased = trace.phyKnownUnleased == 1 &&
        sc->sc_p2p.phy_leased == 0;
    const bool rocIdle = trace.phaseKnownIdle == 1 &&
        sc->sc_p2p_roc.phase == IWX_P2P_ROC_IDLE;
    const bool rocAtRestoredTerminal =
        sc->sc_p2p_roc.phase == IWX_P2P_ROC_IDLE ||
        sc->sc_p2p_roc.phase == IWX_P2P_ROC_COMPLETE;
    const bool restoreComplete = trace.fullyRestored == 1 &&
        trace.cleanupErrno == 0 && rocAtRestoredTerminal &&
        trace.restoredChannelFrequency == trace.originalChannelFrequency &&
        bindingAbsent && phyUnleased;
    P2PTxDiagnosticSnapshot txSnapshot{};
    const bool txResourcesAbsent = rx149TxHistoryQuiescent(
        owner, &txSnapshot);
    const bool sessionSubmitReached = run->sessionSubmitReached ||
        trace.sessionSubmitAttempted != 0;
    const bool sessionOutcomeUnknown =
        sc->sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN ||
        (sessionSubmitReached && sc->sc_p2p_roc.session_submit_seen == 0);

    proof->snapshotValid = trace.valid == 1;
    proof->snapshotStable = stable && revisionEnd != 0 &&
        revisionBegin == revisionEnd && (revisionEnd & 1U) == 0;
    proof->prepareAttemptMatches = traceAttemptMatches;
    proof->prepareErrorMatches = action->exerciseErrno != 0 &&
        static_cast<int32_t>(trace.prepareErrno) == action->exerciseErrno;
    proof->ownerMatches = ownerCurrent && trace.ownerEpochsUnchanged == 1;
    proof->contextGenerationMatches =
        halSnapshot.contextGeneration == run->contextGeneration &&
        owner->nativeP2pProbeGeneration_ == run->contextGeneration &&
        trace.token == run->contextGeneration;
    // These represent independent gates: the controller's power epoch is
    // compared only with the admitted controller epoch; trace.scGeneration is
    // checked separately against the driver's captured generation.
    proof->powerGenerationMatches = halSnapshot.powerGeneration != 0 &&
        halSnapshot.powerGeneration == run->powerGeneration;
    proof->firmwareGenerationMatches = scGenerationMatches;
    proof->p2pFirmwareGenerationMatches = p2pFirmwareGenerationMatches;
    proof->stationGenerationMatches = stationEpochMatches &&
        halSnapshot.stationGeneration == run->stationGeneration;
    proof->knownNotSubmittedSafeToAbort =
        trace.knownNotSubmittedSafeToAbort == 1 &&
        trace.sessionSubmitAttempted == 0 && !run->sessionSubmitReached;
    proof->fullyRestored = trace.fullyRestored == 1 &&
        trace.cleanupErrno == 0 &&
        trace.originalChannelFrequency == trace.restoredChannelFrequency;
    proof->bindingAbsent = bindingAbsent;
    proof->phyUnleased = phyUnleased;
    proof->rocIdle = rocIdle;
    proof->restoreComplete = restoreComplete;
    proof->sessionProtectionSubmitReached = sessionSubmitReached;
    proof->sessionOutcomeUnknown = sessionOutcomeUnknown;
    proof->txResourcesPresent = !txResourcesAbsent;
    proof->prepareStep = trace.step;
    proof->prepareErrno = static_cast<int32_t>(trace.prepareErrno);
    proof->cleanupErrno = static_cast<int32_t>(trace.cleanupErrno);
    proof->attemptSerial = trace.serial;
    proof->snapshotRevision = revisionEnd;
    action->snapshotRead = true;
    return kIOReturnSuccess;
}

void ItlIwx::tahoeP2pPublishRocState()
{
    const uint32_t stage = __atomic_load_n(&nativeP2pRocStage_, __ATOMIC_ACQUIRE);
    auto controller = getController();
    if (!controller || stage == nativeP2pRocPublishedStage_)
        return;
    controller->setProperty("NativeP2PRocStage", stage, 32);
    uint32_t actualChannel = 0;
    for (u_int index = 0; index < nitems(com.sc_ic.ic_channels); ++index) {
        if (com.sc_p2p_roc.roc_channel == &com.sc_ic.ic_channels[index]) {
            actualChannel = ieee80211_chan2ieee(
                &com.sc_ic, com.sc_p2p_roc.roc_channel);
            break;
        }
    }
    controller->setProperty("NativeP2PRocActualChannel", actualChannel, 32);
    controller->setProperty("NativeP2PRocReceiveObservationOnly",
        __atomic_load_n(&com.sc_p2p_roc.receive_observation_only,
                        __ATOMIC_ACQUIRE), 32);
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
#if defined(ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332)
    const uint64_t observerStopSerial = __atomic_load_n(
        &nativeRxPreOwnerStopSerial_, __ATOMIC_ACQUIRE);
#endif
    if (__atomic_load_n(&nativeP2pProbeRunAllocationFailed_, __ATOMIC_ACQUIRE))
        return kIOReturnNoMemory;
    IOEthernetController *controller = getController();
    if (rx149ObservationOnlyRequested(controller)) {
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
        if (NativeAwdlBSD::rx149DataInputBlocked())
            return kIOReturnNotReady;
#endif
        if (rx149ProfileStatus(this, controller) !=
            NativeP2PRx149Observation::ProfileStatus::kReadyToArm ||
            !initializeRx149PrearmCounters(this))
            return kIOReturnUnsupported;
        uint32_t expected = 0;
        if (!__atomic_compare_exchange_n(&nativeP2pManualArmRequested_,
                                         &expected,
                                         NativeP2PRx149Observation::kRx149ArmMode,
                                         false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return kIOReturnBusy;
#if defined(ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332)
        if (controller->getProperty("NativeRxPreOwnerObservation") == kOSBooleanTrue) {
            uint64_t absolute = 0, nanos = 0;
            clock_get_uptime(&absolute);
            absolutetime_to_nanoseconds(absolute, &nanos);
            const auto observerStopActive = [this]() {
                return __atomic_load_n(&nativeRxPreOwnerStopDepth_, __ATOMIC_ACQUIRE) != 0 ||
                    (__atomic_load_n(&com.sc_flags, __ATOMIC_ACQUIRE) & IWX_FLAG_SHUTDOWN) != 0 ||
                    __atomic_load_n(&nativeLifecycleTearingDown_, __ATOMIC_ACQUIRE) != 0;
            };
            const uint32_t observerArmGeneration = uint32_t(
                __atomic_load_n(&com.sc_generation, __ATOMIC_ACQUIRE));
            const bool observed = !observerStopActive() &&
                nativeRxPreOwner_.begin(nanos / 1000ULL,
                observerArmGeneration);
            if (observed) {
                // Metadata only: the recorder itself is lazily armed and
                // subsequently accessed exclusively under the main gate.
                __atomic_store_n(&nativeRxRocArmUs_, nanos / 1000ULL,
                                 __ATOMIC_RELAXED);
                __atomic_store_n(&nativeRxRocArmStopSerial_, observerStopSerial,
                                 __ATOMIC_RELAXED);
                __atomic_store_n(&nativeRxRocArmGeneration_, observerArmGeneration,
                    __ATOMIC_RELAXED);
                __atomic_store_n(&nativeRxRocArmReady_, 1u, __ATOMIC_RELEASE);
                __atomic_store_n(&nativeRxPreOwnerArmed_, 1u, __ATOMIC_RELEASE);
            }
            if (observed &&
                (observerStopSerial != __atomic_load_n(
                     &nativeRxPreOwnerStopSerial_, __ATOMIC_ACQUIRE) ||
                 observerStopActive()))
                (void)nativeRxPreOwner_.close(nanos / 1000ULL,
                    NativeRxPreOwner::CloseReason::Stop);
            const bool observerReady = observed && nativeRxPreOwner_.enabled();
            controller->setProperty("NativeRxPreOwnerArmAccepted", observerReady ? 1u : 0u, 32);
        }
#endif
        publishRx149ProfileState(this, true, false, true);
        return kIOReturnSuccess;
    }
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
                                     NativeP2PRx149Observation::kLegacyArmMode,
                                     false, __ATOMIC_ACQ_REL,
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

void ItlIwx::tahoeRxPreOwnerPublish(IOEthernetController *controller)
{
#if defined(ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332)
    // The watchdog uses a different workloop. Never wait on the main gate;
    // the observer provides a nonblocking, internally consistent copy.
    if (!controller || nativeRxPreOwnerPublished_ ||
        !__atomic_load_n(&nativeRxPreOwnerArmed_, __ATOMIC_ACQUIRE))
        return;
    uint64_t absolute = 0, nanos = 0;
    clock_get_uptime(&absolute);
    absolutetime_to_nanoseconds(absolute, &nanos);
    const uint64_t nowUs = nanos / 1000ULL;
    auto &snapshot = nativeRxPreOwnerPublishSnapshot_;
    if (!nativeRxPreOwner_.snapshot(nowUs, &snapshot))
        return;
    if (snapshot.active && snapshot.driverGeneration !=
        uint32_t(__atomic_load_n(&com.sc_generation, __ATOMIC_ACQUIRE))) {
        (void)nativeRxPreOwner_.close(nowUs,
            NativeRxPreOwner::CloseReason::GenerationChanged);
        if (!nativeRxPreOwner_.snapshot(nowUs, &snapshot))
            return;
    }
    if (snapshot.active || !snapshot.closed)
        return;
    const size_t words = NativeRxPreOwnerWire::encode(snapshot,
        nativeRxPreOwnerPublishWords_,
        sizeof(nativeRxPreOwnerPublishWords_) / sizeof(uint64_t));
    if (words == 0)
        return;
    // Allocate and publish only after the independent window has closed.
    // The payload contains explicit numeric words, never C++ struct padding.
    OSData *data = OSData::withBytes(nativeRxPreOwnerPublishWords_,
        unsigned(words * sizeof(uint64_t)));
    if (!data)
        return;
    const bool complete =
        controller->setProperty("NativeRxPreOwnerPublished", uint64_t(0), 32) &&
        controller->setProperty("NativeRxPreOwnerRevision", uint64_t(1), 32) &&
        controller->setProperty("NativeRxPreOwnerSchema", uint64_t(1), 32) &&
        controller->setProperty("NativeRxPreOwnerSnapshot", data) &&
        controller->setProperty("NativeRxPreOwnerRevision", uint64_t(2), 32) &&
        controller->setProperty("NativeRxPreOwnerPublished", uint64_t(1), 32);
    data->release();
    nativeRxPreOwnerPublished_ = complete;
#else
    (void)controller;
#endif
}

void ItlIwx::nativeP2pTick()
{
    tahoeP2pRxDrain();
    // A CHUB profile refresh blocked by an active/unknown ROC lease remains
    // pending. Retry the inexpensive queue gate once per watchdog tick; the
    // MCC worker itself never spins while a P2P resource is retained.
    tahoeMccScheduleIfReady(&com);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    NativeAwdlBSD::poll(com.sc_ic.ic_state==IEEE80211_S_RUN&&
        !(com.sc_flags&(IWX_FLAG_HW_ERR|IWX_FLAG_SHUTDOWN|IWX_FLAG_RFKILL)),uint32_t(com.sc_generation));
#endif
    // Recovery uses a main-gate/lifecycle-fenced successful-init proof. It
    // does not create a ROC owner, grant a lease or arm a diagnostic window.
    tahoeRx149RecoverInput();

    IOEthernetController *controller = getController();
    tahoeRxPreOwnerPublish(controller);
#if defined(ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332)
    tahoeRxCompletionPublish(controller);
    tahoeRxRocCorrelationPublish(controller);
#endif
    tahoePublishMccSnapshot(controller);
    publishRx149ProfileAvailabilityOnce(this, controller);
    if (rx149ObservationOnlyRequested(controller))
        (void)initializeRx149PrearmCounters(this);
    if (controller)
        controller->setProperty("NativeP2PProbeRunAllocationFailed",
            __atomic_load_n(&nativeP2pProbeRunAllocationFailed_, __ATOMIC_ACQUIRE), 32);
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
    if (!residentStart && __atomic_load_n(&nativeP2pProbeRunAllocationFailed_, __ATOMIC_ACQUIRE)) {
        tahoeP2pPublishProbeState();
        return; // Keep software resident initialization; never retry RF after OOM.
    }
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
    auto run = static_cast<P2PProbeRun *>(opaque);
    const int result = configure(opaque);
    if (run && run->owner && result == 0)
        run->p2pFirmwareGeneration = run->owner->com.sc_p2p.fw_generation;
    return result;
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    invalidateDiscoveryCurrentAwAttempt(owner->tahoeP2pController());
#endif
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

    if (run->rx149ObservationOnly) {
        P2PTxDiagnosticSnapshot txSnapshot{};
        IOEthernetController *controller = owner->getController();
        const bool profileStillSelected =
            rx149ArmModeSelected(owner) &&
            rx149ObservationOnlyRequested(controller) &&
            rx149ProfileStatus(owner, controller) ==
                NativeP2PRx149Observation::ProfileStatus::kSelected;
        if (!profileStillSelected ||
            !rx149TxHistoryQuiescent(owner, &txSnapshot)) {
            taskq_resume(sc->sc_nswq);
            admission.stateQueuePaused = false;
            run->blocked = NativeP2PProbe::kP2pContextOwned;
            owner->nativeP2pProbe_.tryQueue(admission, run->blocked);
            return kIOReturnSuccess;
        }
    }

    admission.powerGeneration = uint32_t(sc->sc_generation);
    admission.stationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    admission.contextGeneration = nextGeneration(owner->nativeP2pProbeGeneration_);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeResidentAddressProfileEnabled(owner)) {
        uint8_t liveAddress[6]{};
        if (!NativeAwdlBSD::address(admission.powerGeneration, liveAddress)) {
            run->blocked = NativeP2PProbe::kNativeAwdlIdentityUnavailable;
            publishNativeIdentityStatus(owner, false,
                                        kNativeIdentityBsdAddressUnavailable);
            taskq_resume(sc->sc_nswq);
            admission.stateQueuePaused = false;
            owner->nativeP2pProbe_.tryQueue(admission, run->blocked);
            return kIOReturnSuccess;
        }
        memcpy(run->address, liveAddress, sizeof(run->address));
        publishNativeIdentityStatus(owner, false,
                                    kNativeIdentityAwaitingP2pAddress);
    } else {
        deriveProbeAddress(sc->sc_ic.ic_myaddr, run->address);
    }
#else
    deriveProbeAddress(sc->sc_ic.ic_myaddr, run->address);
#endif

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
    run->contextGeneration = admission.contextGeneration;
    run->powerGeneration = admission.powerGeneration;
    run->stationGeneration = admission.stationGeneration;
    run->scGeneration = uint32_t(sc->sc_generation);
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
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    NativeAwdlBSD::revokeRx149DataInput();
#endif
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
    // Publish the low-level Prepare trace for every terminal result, including
    // a successful listen and a quarantined failure. Recovery publication is
    // repeated inside its own gate action so that the caller can validate the
    // same stable snapshot before deciding whether MAC REMOVE is safe.
    if (owner->tahoeP2pOnMainGate()) {
        struct iwx_p2p_roc_prepare_trace_snapshot trace{};
        uint32_t revisionBegin = 0;
        uint32_t revisionEnd = 0;
        const bool stable = readPrepareTraceSnapshot(
            &owner->com, &trace, &revisionBegin, &revisionEnd);
        publishPrepareTraceSnapshot(owner->tahoeP2pController(), trace,
                                    revisionBegin, revisionEnd, stable);
    }
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    // The planner observation is a RAM snapshot captured before authorization;
    // publish its single fixed-size OSData after the operation returned and
    // before finish cleanup or quiet-gated final-trace publication.
    if (owner->tahoeP2pOnMainGate())
        (void)publishDiscoveryCurrentAwAttempt(run);
#endif
    bool rxProducerClosed = false;
    bool rxDrainComplete = false;
    if (owner->tahoeP2pOnMainGate() &&
        owner->nativeAwdlRxEventOwnerSerial_ != 0) {
        const auto trace = owner->nativeAwdlRxEventTimeline_.snapshot();
        const bool sameRunEpoch =
            trace.epochs.contextGeneration == run->contextGeneration &&
            trace.epochs.powerGeneration == run->powerGeneration &&
            trace.epochs.stationGeneration == run->stationGeneration &&
            // This probe's ROC generation is its context token; the active
            // session and resource gates use the same equality throughout.
            trace.epochs.rocGeneration == run->contextGeneration;
        if (trace.ownerPresent && trace.ownerSerial ==
                owner->nativeAwdlRxEventOwnerSerial_ && sameRunEpoch) {
            // Closure is an observation boundary only. It does not gate or
            // change the existing cleanup decision.
            const uint32_t reason = run->canceled ? 3u : 2u;
            rxProducerClosed = owner->nativeAwdlRxEventTimeline_.closeProducer(
                owner->nativeAwdlRxEventOwnerSerial_, trace.epochs, reason);
            if (rxProducerClosed) {
                // Timeout/cancel/unknown can finish without a canonical END.
                // Close only an existing current Entry owner so its numeric
                // evidence remains publishable. This neither proves END nor
                // authorizes radio cleanup, and cannot begin/reopen an owner.
                owner->tahoeP2pSyncRxDiagnosticOwner(true);
                owner->tahoeP2pRxConsume();
            }
            const auto closedTrace =
                owner->nativeAwdlRxEventTimeline_.snapshot();
            rxDrainComplete = rxProducerClosed && closedTrace.producerClosed &&
                closedTrace.pendingDrainCount == 0 &&
                closedTrace.untrackedPendingDrainCount == 0 &&
                closedTrace.untrackedPendingIdentityOverflowCount == 0;
        } else if (!trace.ownerPresent) {
            rxProducerClosed = true;
            rxDrainComplete = trace.pendingDrainCount == 0 &&
                trace.untrackedPendingDrainCount == 0 &&
                trace.untrackedPendingIdentityOverflowCount == 0;
        }
    } else if (owner->tahoeP2pOnMainGate()) {
        const auto trace = owner->nativeAwdlRxEventTimeline_.snapshot();
        rxProducerClosed = !trace.ownerPresent || trace.producerClosed;
        rxDrainComplete = trace.pendingDrainCount == 0 &&
            trace.untrackedPendingDrainCount == 0 &&
            trace.untrackedPendingIdentityOverflowCount == 0;
    }
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    run->currentAwTrace.rxProducerClosed = rxProducerClosed;
    run->currentAwTrace.rxDrainComplete = rxDrainComplete;
    publishDiscoveryExperiment(run, true);
#endif
    if (run->canceled)
        owner->nativeP2pProbe_.cancelQueued();
    __atomic_store_n(&owner->nativeP2pProbeOwner_, nullptr, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pProbeBusy_, 0u, __ATOMIC_RELEASE);
    if (__atomic_exchange_n(&owner->nativeP2pNswqPaused_, 0u,
                            __ATOMIC_ACQ_REL) != 0)
        taskq_resume(owner->com.sc_nswq);
    __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (owner->tahoeP2pOnMainGate()) {
        const bool resourcesQuiet = !owner->nativeP2pResourcesRetained();
        const bool probeBusy = owner->nativeP2pBusy();
        const bool nswqPaused = __atomic_load_n(
            &owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) != 0;
        const bool probeQueued = __atomic_load_n(
            &owner->nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) != 0;
        const bool probeOwnerPresent = __atomic_load_n(
            &owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) != nullptr;
        uint32_t quietBlockerMask = 0;
        if (!rxProducerClosed)
            quietBlockerMask |= kCurrentAwQuietBlockerRxProducerOpen;
        if (!rxDrainComplete)
            quietBlockerMask |= kCurrentAwQuietBlockerRxDrainIncomplete;
        if (!resourcesQuiet)
            quietBlockerMask |= kCurrentAwQuietBlockerResourcesRetained;
        if (probeBusy)
            quietBlockerMask |= kCurrentAwQuietBlockerProbeBusy;
        if (nswqPaused)
            quietBlockerMask |= kCurrentAwQuietBlockerNswqPaused;
        if (probeQueued)
            quietBlockerMask |= kCurrentAwQuietBlockerProbeQueued;
        if (probeOwnerPresent)
            quietBlockerMask |= kCurrentAwQuietBlockerOwnerPresent;
        run->currentAwTrace.quietBlockerMask = quietBlockerMask;
        const bool quiet = quietBlockerMask == 0;
        publishDiscoveryCurrentAwTrace(run, quiet);
    }
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    publishMifBootstrapPairDiagnostics(owner, run, true);
#endif
    return kIOReturnSuccess;
}

IOReturn ItlIwx::tahoeP2pResetAction(OSObject *, void *contextArg,
                                    void *, void *, void *)
{
    auto reset = static_cast<P2PProbeReset *>(contextArg);
    if (!reset || !reset->owner || !reset->softc)
        return kIOReturnBadArgument;
    ItlIwx *owner = reset->owner;
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    NativeAwdlBSD::revokeRx149DataInput();
#endif
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    // ResetDrained is dispatched on the main gate after the caller proved the
    // firmware/RX drain. Retire any unmatched doorbelled evidence here, where
    // the bounded single-consumer ledger is serialized with TX and RX.
    iwx_tahoe_p2p_action_tx_mark_evidence_unknown(
        &owner->nativeP2pActionTx_, 0);
#endif
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

    IOWorkLoop *workLoop = owner->getMainWorkLoop();
    const bool callerOutsideMainWorkLoop = workLoop && !workLoop->onThread() &&
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
        if(callerOutsideMainWorkLoop&&gate->runAction(copyAddress,owner,address)==kIOReturnSuccess)
            NativeAwdlLifecycle::observeOnce(owner->getController(),address);
        __atomic_store_n(&owner->nativeP2pProbeQueued_,0u,__ATOMIC_RELEASE);
        return; // resident creation never consumes or arms the RF diagnostic
    }
#endif
    NativeP2PProbe::ScopedRunStorage<P2PProbeRun> storage;
    if (!storage.get()) {
        __atomic_store_n(&owner->nativeP2pProbeRunAllocationFailed_, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&owner->nativeP2pCancelRequested_, 0u, __ATOMIC_RELEASE);
        return; // No admission, queue pause, firmware command or run pointer.
    }
    P2PProbeRun &run = *storage.get();
    run.owner = owner;
    run.workerThread = current_thread();
    IOEthernetController *controller = owner->getController();
    const uint32_t armMode = manualProbeArmMode(owner);
    const bool rx149Latched =
        NativeP2PRx149Observation::isRx149ArmMode(armMode);
    const bool rx149Requested = rx149ObservationOnlyRequested(controller);
    const bool manualTrigger = controller && controller->getProperty(
        "NativeP2PManualTrigger") == kOSBooleanTrue;
    // The once-per-boot arm latch freezes the selected profile. A mutable
    // property that no longer agrees with this mode is a hard stop, never a
    // request to enter the other profile.
    if (rx149Latched != rx149Requested ||
        (manualTrigger && !rx149Latched &&
         !NativeP2PRx149Observation::isLegacyArmMode(armMode)) ||
        (!manualTrigger && (rx149Latched ||
         NativeP2PRx149Observation::isLegacyArmMode(armMode)))) {
        if (rx149Requested || rx149Latched)
            publishRx149ProfileState(owner, false, false, true);
        __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u,
                         __ATOMIC_RELEASE);
        return;
    }
    run.rx149ObservationOnly = rx149Latched;
    run.txProbeEnabled = txProbeEnabled(owner, owner->getController());
    run.awdlPsfProbeEnabled = awdlPsfProbeEnabled(
        owner, owner->getController());
    run.awdlMifFollowupEnabled = mifFollowupProfileEnabled(
        owner->getController());
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    run.discoveryMode = discoveryMifCurrentSlotEnabled(owner) ?
        NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot :
        NativeAwdlDiscoveryBinding::Mode::kPsfNextSlot;
    run.discoveryModeSelected = discoveryExperimentEnabled(owner);
    run.currentAwTrace.fallbackEnabled =
        discoveryCurrentAwFallbackEnabled(owner);
    if (run.discoveryModeSelected && run.discoveryMode ==
            NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot) {
        run.discoveryRuntimeMifRequirementSelected = true;
        run.discoveryRequiresRuntimeMifBinding = true;
    }
#endif
    run.mifStatus = run.awdlMifFollowupEnabled ?
        kMifProbeWaitingForPsfCompletion : kMifProbeNotRequested;
    if (rx149Latched) {
        if (rx149ProfileStatus(owner, controller) !=
            NativeP2PRx149Observation::ProfileStatus::kSelected) {
            publishRx149ProfileState(owner, false, false, true);
            __atomic_store_n(&owner->nativeP2pProbeQueued_, 0u,
                             __ATOMIC_RELEASE);
            return;
        }
        run.txProbeEnabled = false;
        run.awdlPsfProbeEnabled = false;
        run.awdlMifFollowupEnabled = false;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        run.discoveryModeSelected = false;
        run.currentAwTrace.fallbackEnabled = false;
#endif
        publishRx149ProfileState(owner, true, false, true);
    }
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeResidentAddressProfileEnabled(owner)) {
        publishNativeIdentityStatus(owner, false, kNativeIdentityNotChecked);
        if (IOEthernetController *controller = owner->tahoeP2pController())
            controller->setProperty(
                "NativeP2PAwdlNativeAddressCandidateVerified", uint64_t(0), 32);
    }
#endif
    run.callerOutsideMainWorkLoop = callerOutsideMainWorkLoop;

    IOReturn admitResult = gate->runAction(tahoeP2pAdmitAction, &run);
    if (admitResult != kIOReturnSuccess) {
        recordBlocked(owner, NativeP2PProbe::kGateActionFailed);
        run.admitted = false;
    }

    if (run.rx149ObservationOnly && run.admitted)
        publishRx149ProfileState(owner, true, true, true);

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
        if (run.rx149ObservationOnly || run.txProbeEnabled ||
            owner->getController()->getProperty("NativeP2PRocProbe") ==
                kOSBooleanTrue)
            operations.exercise = tahoeP2pExerciseRoc;
        if (run.rx149ObservationOnly)
            operations.exerciseRecovery = tahoeP2pExerciseRecovery;
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
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    NativeAwdlBSD::revokeRx149DataInput();
#endif
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

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
static bool setNativeP2PTxTimeEvidenceProperty(
    IOEthernetController *controller, const char *name,
    uint64_t value, unsigned int bits)
{
    return controller && controller->setProperty(name, value, bits);
}

static bool setNativeP2PTxTimeEvidenceRecordField(
    IOEthernetController *controller, uint32_t slot, const char *field,
    uint64_t value, unsigned int bits)
{
    char name[96] = {};
    const int length = snprintf(name, sizeof(name),
        "NativeP2PTxTimeEvidenceRecord%u%s", slot, field);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(name))
        return false;
    return setNativeP2PTxTimeEvidenceProperty(
        controller, name, value, bits);
}

static void publishNativeP2PTxTimeEvidenceOnMainGate(ItlIwx *owner)
{
    if (!owner || !owner->tahoeP2pOnMainGate())
        return;

    IOEthernetController *controller = owner->tahoeP2pController();
    TahoeP2PActionTxWindowEvidence &evidence =
        owner->nativeP2pActionTx_.windowEvidence;
    const uint64_t version = __atomic_load_n(
        &evidence.snapshotVersion, __ATOMIC_ACQUIRE);
    if (!controller || !evidence.initialized || version == 0 || (version & 1) ||
        version == __atomic_load_n(&evidence.lastPublishedSnapshotVersion,
                                   __ATOMIC_ACQUIRE))
        return;

    uint32_t count = 0;
    for (size_t index = 0;
         index < NativeAwdlTxWindowEvidence::kTicketCapacity; ++index) {
        NativeAwdlTxWindowEvidence::TicketSnapshot ticket{};
        if (evidence.ledger.snapshotTicket(index, &ticket) && ticket.used)
            ++count;
    }

    if (__atomic_load_n(&evidence.snapshotVersion, __ATOMIC_ACQUIRE) != version)
        return;

    // Keep the previous even End visible while Begin is odd. The collector
    // accepts a snapshot only after End and Begin both become this version.
    const uint64_t writingVersion = version - 1;
    if (!setNativeP2PTxTimeEvidenceProperty(
            controller, "NativeP2PTxTimeEvidenceSnapshotVersionBegin",
            writingVersion, 64))
        return;

    bool complete = true;
    const auto setHeader = [&](const char *name, uint64_t value,
                               unsigned int bits) {
        if (complete)
            complete = setNativeP2PTxTimeEvidenceProperty(
                controller, name, value, bits);
    };
    setHeader("NativeP2PTxTimeEvidenceSchemaVersion", 1, 32);
    setHeader("NativeP2PTxTimeEvidenceDiagnosticGeneration",
              evidence.diagnosticGeneration, 64);
    setHeader("NativeP2PTxTimeEvidenceCount", count, 32);
    setHeader("NativeP2PTxTimeEvidenceDroppedCount",
              evidence.droppedTicketCount, 32);

    for (uint32_t index = 0;
         complete && index < NativeAwdlTxWindowEvidence::kTicketCapacity;
         ++index) {
        NativeAwdlTxWindowEvidence::TicketSnapshot ticket{};
        const bool used = evidence.ledger.snapshotTicket(index, &ticket) &&
            ticket.used;
        uint32_t statusFlags = 0;
        const TahoeP2PActionTxEvidenceSidecar *sidecar = nullptr;
        if (used) {
            for (size_t candidate = 0;
                 candidate < NativeAwdlTxWindowEvidence::kTicketCapacity;
                 ++candidate) {
                const TahoeP2PActionTxEvidenceSidecar &entry =
                    evidence.sidecars[candidate];
                if (entry.used && entry.ticketToken ==
                        ticket.identity.ticketToken) {
                    sidecar = &entry;
                    break;
                }
            }
            statusFlags = sidecar ? sidecar->statusFlags :
                kP2PTxEvidenceInvalidUnknown;
        }

        const NativeAwdlTxWindowEvidence::TicketIdentity emptyIdentity{};
        const NativeAwdlTxWindowEvidence::TicketIdentity &identity = used ?
            ticket.identity : emptyIdentity;
        const uint64_t zero = 0;
        const bool wireInfoPresent = used && identity.wireInfoPresent != 0;
        const bool wirePhyTxPresent = wireInfoPresent &&
            identity.wirePhyTxPresent != 0;
        const bool wireTargetTxPresent = wireInfoPresent &&
            identity.wireTargetTxPresent != 0;
        const auto setRecord = [&](const char *field, uint64_t value,
                                   unsigned int bits) {
            if (complete)
                complete = setNativeP2PTxTimeEvidenceRecordField(
                    controller, index, field, value, bits);
        };
        setRecord("Used", used ? 1 : 0, 32);
        setRecord("DiagnosticGeneration",
                  used ? identity.diagnosticGeneration : zero, 64);
        setRecord("TicketSerial", used ? identity.ticketToken : zero, 64);
        setRecord("FrameKind", used ? static_cast<uint32_t>(identity.frameKind) : zero, 32);
        setRecord("FrameOrdinal", used ? identity.frameOrdinal : zero, 32);
        setRecord("SequenceControl",
                  used ? identity.frameSequenceControl : zero, 32);
        setRecord("ContextGeneration",
                  used ? identity.epoch.contextGeneration : zero, 64);
        setRecord("PowerGeneration",
                  used ? identity.epoch.powerGeneration : zero, 64);
        setRecord("StationGeneration",
                  used ? identity.epoch.stationGeneration : zero, 64);
        setRecord("RocGeneration",
                  used ? identity.epoch.rocGeneration : zero, 64);
        setRecord("QueueId", used ? identity.queueId : zero, 32);
        setRecord("RingSize", used ? identity.ringSize : zero, 32);
        setRecord("DescriptorIndex",
                  used ? identity.descriptorIndex : zero, 32);
        setRecord("CreatedAtUs", used ? ticket.createdAtUs : zero, 64);
        setRecord("ScheduleObservedAtUs",
                  used ? ticket.scheduleObservedAtUs : zero, 64);
        setRecord("ScheduleValidUntilUs",
                  used ? ticket.scheduleValidUntilUs : zero, 64);
        setRecord("PreDoorbellLowerUs",
                  used ? ticket.preDoorbellLowerUs : zero, 64);
        setRecord("NotificationTapUpperUs",
                  used ? ticket.notificationTapUpperUs : zero, 64);
        setRecord("PeerBindingVerified",
                  used && ticket.peerBindingVerified ? 1 : 0, 32);
        setRecord("Submitted", used && ticket.submitted ? 1 : 0, 32);
        setRecord("Completed", used && ticket.completed ? 1 : 0, 32);
        setRecord("ScheduleStale", used && ticket.scheduleStale ? 1 : 0, 32);
        setRecord("Invalidated", used && ticket.invalidated ? 1 : 0, 32);
        setRecord("DeviceFamily", sidecar ? sidecar->deviceFamily : zero, 32);
        setRecord("TxCommandApi", sidecar ? sidecar->txCommandApi : zero, 32);
        setRecord("TxLayout", sidecar ? sidecar->txLayout : zero, 32);
        setRecord("StatusFlags", statusFlags, 32);
        setRecord("WireInfoPresent", wireInfoPresent ? 1 : 0, 32);
        setRecord("WireSubtype",
                  wireInfoPresent ? identity.wireSubtype : zero, 32);
        setRecord("WireMpduLength",
                  wireInfoPresent ? identity.wireMpduLength : zero, 32);
        setRecord("WirePhyTxPresent", wirePhyTxPresent ? 1 : 0, 32);
        setRecord("WirePhyTxUs",
                  wirePhyTxPresent ? identity.wirePhyTxUs : zero, 32);
        setRecord("WireTargetTxPresent", wireTargetTxPresent ? 1 : 0, 32);
        setRecord("WireTargetTxUs",
                  wireTargetTxPresent ? identity.wireTargetTxUs : zero, 32);
    }

    if (!complete || __atomic_load_n(&evidence.snapshotVersion,
                                     __ATOMIC_ACQUIRE) != version)
        return;
    if (!setNativeP2PTxTimeEvidenceProperty(
            controller, "NativeP2PTxTimeEvidenceSnapshotVersionEnd",
            version, 64))
        return;
    if (!setNativeP2PTxTimeEvidenceProperty(
            controller, "NativeP2PTxTimeEvidenceSnapshotVersionBegin",
            version, 64))
        return;

    __atomic_store_n(&evidence.lastPublishedSnapshotVersion, version,
                     __ATOMIC_RELEASE);
}

static IOReturn publishNativeP2PTxTimeEvidenceAction(
    OSObject *, void *halContext, void *, void *, void *)
{
    // IOCommandGate's target is AirportItlwm; its first action argument is
    // the ItlIwx HAL instance passed by runAction below.
    ItlIwx *owner = static_cast<ItlIwx *>(halContext);
    if (!owner || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    publishNativeP2PTxTimeEvidenceOnMainGate(owner);
    return kIOReturnSuccess;
}

static void requestNativeP2PTxTimeEvidencePublish(ItlIwx *owner)
{
    if (!owner)
        return;
    TahoeP2PActionTxWindowEvidence &evidence =
        owner->nativeP2pActionTx_.windowEvidence;
    const uint64_t version = __atomic_load_n(
        &evidence.snapshotVersion, __ATOMIC_ACQUIRE);
    if (version == 0 || (version & 1) || version == __atomic_load_n(
            &evidence.lastPublishedSnapshotVersion, __ATOMIC_ACQUIRE))
        return;
    if (owner->tahoeP2pOnMainGate()) {
        publishNativeP2PTxTimeEvidenceOnMainGate(owner);
        return;
    }
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    if (gate)
        (void)gate->runAction(publishNativeP2PTxTimeEvidenceAction, owner);
}
#endif

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
static bool setNativeP2PDataTxTraceProperty(
    IOEthernetController *controller, const char *name,
    uint64_t value, unsigned int bits)
{
    return controller && controller->setProperty(name, value, bits);
}

static bool setNativeP2PDataTxTraceRecordField(
    IOEthernetController *controller, uint32_t slot, const char *field,
    uint64_t value, unsigned int bits)
{
    char name[96] = {};
    const int length = snprintf(name, sizeof(name),
        "NativeP2PDataTxTraceRecord%u%s", slot, field);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(name))
        return false;
    return setNativeP2PDataTxTraceProperty(controller, name, value, bits);
}

static bool sameNativeDataTxIdentity(
    const NativeAwdlDataTxTrace::Identity &left,
    const NativeAwdlDataTxTrace::Identity &right)
{
    return left.token == right.token &&
        left.diagnosticGeneration == right.diagnosticGeneration &&
        left.contextGeneration == right.contextGeneration &&
        left.powerGeneration == right.powerGeneration &&
        left.stationGeneration == right.stationGeneration &&
        left.rocGeneration == right.rocGeneration;
}

struct NativeP2PPublicationProbeSnapshot {
    NativeP2PProbe::Snapshot probe;
    uint32_t resetSequence;
    uint32_t powerEpoch;
    uint32_t stationGeneration;
};

struct NativeP2PPublicationTxResources {
    bool available;
    bool submissionBusy;
    bool unsettled;
};

static bool nativeP2PPublicationBusy(ItlIwx *owner)
{
    if (!owner)
        return true;
    return __atomic_load_n(&owner->nativeLifecycleTearingDown_,
                           __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&owner->nativeP2pProbeBusy_, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&owner->nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) != nullptr ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&owner->nativeP2pCancelRequested_, __ATOMIC_ACQUIRE) != 0;
}

static bool captureNativeP2PPublicationProbeSnapshot(
    ItlIwx *owner, NativeP2PPublicationProbeSnapshot *snapshot)
{
    if (!owner || !snapshot || nativeP2PPublicationBusy(owner))
        return false;
    IwxResetTrace::Snapshot reset{};
    if (!owner->nativeResetTrace_.read(&reset))
        return false;
    snapshot->probe = owner->nativeP2pProbe_.snapshot();
    snapshot->resetSequence = reset.resetSequence;
    snapshot->powerEpoch = __atomic_load_n(
        &owner->com.sc_tx_output_epoch, __ATOMIC_ACQUIRE);
    snapshot->stationGeneration = __atomic_load_n(
        &owner->com.sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    return !nativeP2PPublicationBusy(owner);
}

static bool sameNativeP2PPublicationProbeSnapshot(
    const NativeP2PPublicationProbeSnapshot &left,
    const NativeP2PPublicationProbeSnapshot &right)
{
    const NativeP2PProbe::Snapshot &a = left.probe;
    const NativeP2PProbe::Snapshot &b = right.probe;
    return a.state == b.state && a.attempted == b.attempted &&
        a.addResult == b.addResult && a.removeResult == b.removeResult &&
        a.contextGeneration == b.contextGeneration &&
        a.powerGeneration == b.powerGeneration &&
        a.stationGeneration == b.stationGeneration &&
        a.resourceMayExist == b.resourceMayExist &&
        left.resetSequence == right.resetSequence &&
        left.powerEpoch == right.powerEpoch &&
        left.stationGeneration == right.stationGeneration;
}

static bool nativeP2PPublicationProbeStateAllowed(
    const NativeP2PProbe::Snapshot &probe, bool *cleanPreflight,
    bool *completedAndReleased)
{
    if (!cleanPreflight || !completedAndReleased)
        return false;
    *cleanPreflight = false;
    *completedAndReleased = false;

    const bool neverAttempted = probe.attempted == 0 &&
        probe.resourceMayExist == 0;
    const bool preflightState = probe.state == NativeP2PProbe::kIdle ||
        probe.state == NativeP2PProbe::kDeferred ||
        probe.state == NativeP2PProbe::kDisabled;
    if (neverAttempted && preflightState) {
        *cleanPreflight = true;
        return true;
    }

    const bool completed = probe.state == NativeP2PProbe::kComplete &&
        probe.attempted == 1 && probe.resourceMayExist == 0 &&
        probe.addResult == 0 && probe.removeResult == 0 &&
        probe.contextGeneration != 0;
    if (completed) {
        *completedAndReleased = true;
        return true;
    }
    return false;
}

static bool captureNativeP2PPublicationTxResources(
    ItlIwx *owner, NativeP2PPublicationTxResources *snapshot)
{
    if (!owner || !snapshot || nativeP2PPublicationBusy(owner))
        return false;
    IORecursiveLock *lifecycleLock = owner->nativeLifecycleLock_;
    if (!lifecycleLock || IORecursiveLockHaveLock(lifecycleLock) ||
        !IORecursiveLockTryLock(lifecycleLock))
        return false;
    if (nativeP2PPublicationBusy(owner)) {
        IORecursiveLockUnlock(lifecycleLock);
        return false;
    }

    IOSimpleLock *txLock = owner->nativeP2pTxLock_;
    if (!txLock) {
        IORecursiveLockUnlock(lifecycleLock);
        return false;
    }
    const IOInterruptState interruptState = ml_set_interrupts_enabled(false);
    if (!IOSimpleLockTryLock(txLock)) {
        ml_set_interrupts_enabled(interruptState);
        IORecursiveLockUnlock(lifecycleLock);
        return false;
    }

    const TahoeP2PTxQueueLease &queue = owner->nativeP2pTxQueue_;
    const bool lockMatches = queue.stateLock == txLock;
    if (lockMatches) {
        const IntelP2PTx::QueueSnapshot lifecycle =
            queue.lifecycle.snapshot();
        snapshot->submissionBusy = queue.submissionBusy;
        snapshot->unsettled = queue.state != TahoeP2PResourceState::kAbsent ||
            queue.pendingRing != nullptr || queue.retainedRing != nullptr ||
            queue.submissionBusy ||
            lifecycle.state != IntelP2PTx::QueueState::kAbsent ||
            lifecycle.ringMustRemainOwned || lifecycle.outstandingTx != 0;
        snapshot->available = true;
    }

    IOSimpleLockUnlock(txLock);
    ml_set_interrupts_enabled(interruptState);
    IORecursiveLockUnlock(lifecycleLock);
    return lockMatches && snapshot->available;
}

static bool sameNativeP2PPublicationTxResources(
    const NativeP2PPublicationTxResources &left,
    const NativeP2PPublicationTxResources &right)
{
    return left.available == right.available &&
        left.submissionBusy == right.submissionBusy &&
        left.unsettled == right.unsettled;
}

static bool nativeP2PPublicationStateStillStable(
    ItlIwx *owner,
    const NativeP2PPublicationProbeSnapshot &probeBefore,
    const NativeP2PPublicationTxResources &txBefore)
{
    NativeP2PPublicationProbeSnapshot probeAfter{};
    if (!captureNativeP2PPublicationProbeSnapshot(owner, &probeAfter) ||
        !sameNativeP2PPublicationProbeSnapshot(probeBefore, probeAfter))
        return false;
    bool cleanPreflight = false;
    bool completedAndReleased = false;
    if (!nativeP2PPublicationProbeStateAllowed(
            probeAfter.probe, &cleanPreflight, &completedAndReleased))
        return false;
    NativeP2PPublicationTxResources txAfter{};
    if (!captureNativeP2PPublicationTxResources(owner, &txAfter) ||
        !sameNativeP2PPublicationTxResources(txBefore, txAfter) ||
        txAfter.submissionBusy || txAfter.unsettled)
        return false;
    return true;
}

static void publishNativeP2PDataTxTraceOnMainGate(ItlIwx *owner)
{
    if (!owner || !owner->tahoeP2pOnMainGate())
        return;

    // The probe worker performs ROC and queue commands off the main gate. Do
    // not inspect any of their state or merge callback taps until all atomic
    // owner/queue/pause flags say that worker is gone.
    NativeP2PPublicationProbeSnapshot probeBefore{};
    if (!captureNativeP2PPublicationProbeSnapshot(owner, &probeBefore))
        return;
    bool cleanPreflight = false;
    bool completedAndReleased = false;
    if (!nativeP2PPublicationProbeStateAllowed(
            probeBefore.probe, &cleanPreflight, &completedAndReleased))
        return;

    IOEthernetController *controller = owner->tahoeP2pController();
    NativeAwdlDataTxTrace::Ledger &trace =
        owner->nativeP2pActionTx_.dataTxTrace;
    if (!controller)
        return;

    // The RX timeline is supplementary diagnostics. SessionTracker and the
    // one-shot probe result are the lifecycle anchors; current power/station
    // epochs come from their existing atomic writers.
    const NativeAwdlRxTrace::Snapshot rxTrace =
        owner->nativeAwdlRxEventTimeline_.snapshot();
    const IntelROCEvent::SessionSnapshot session =
        owner->nativeP2pRocEvents_.snapshot();
    const NativeAwdlRxTrace::Epochs &timelineEpochs = rxTrace.epochs;
    const bool timelineEpochsMatchSession = rxTrace.ownerPresent &&
        session.generation != 0 &&
        probeBefore.probe.contextGeneration == session.generation &&
        timelineEpochs.contextGeneration == session.generation &&
        timelineEpochs.rocGeneration == session.generation &&
        timelineEpochs.powerGeneration == probeBefore.probe.powerGeneration &&
        timelineEpochs.powerGeneration == probeBefore.powerEpoch &&
        timelineEpochs.stationGeneration ==
            probeBefore.probe.stationGeneration &&
        timelineEpochs.stationGeneration == probeBefore.stationGeneration;

    NativeP2PPublicationTxResources txResources{};
    if (!captureNativeP2PPublicationTxResources(owner, &txResources))
        return;

    NativeAwdlDataTxPublication::LifecycleSnapshot lifecycle{};
    lifecycle.timelineOwnerPresent = rxTrace.ownerPresent != 0;
    lifecycle.timelineActive = rxTrace.active != 0;
    lifecycle.timelineProducerClosed = rxTrace.producerClosed != 0;
    lifecycle.timelineDrainsPending = rxTrace.pendingDrainCount != 0 ||
        rxTrace.untrackedPendingDrainCount != 0;
    lifecycle.timelineEpochsMatchSession = timelineEpochsMatchSession;
    lifecycle.probeBusy = nativeP2PPublicationBusy(owner);
    lifecycle.rxLeaseActive = owner->tahoe_p2p_rx_lease_.active;
    lifecycle.txSubmissionBusy = txResources.submissionBusy;
    lifecycle.txResourcesUnsettled = txResources.unsettled;
    lifecycle.probeCleanPreflight = cleanPreflight;
    lifecycle.probeCompletedAndReleased = completedAndReleased;
    lifecycle.sessionSubmitted = session.submitted;
    lifecycle.sessionCommandReturned = session.commandReturned;
    lifecycle.sessionCommandSucceeded = session.commandReturned &&
        session.commandResult == 0;
    lifecycle.sessionStartSeen = session.startSeen;
    lifecycle.sessionEndSeen = session.endSeen;
    lifecycle.sessionCleanupAllowed = session.cleanupAllowed;
    lifecycle.sessionOutcomeUnknown = session.outcomeUnknown;
    lifecycle.sessionGeneration = session.generation;
    if (NativeAwdlDataTxPublication::shouldDeferBulkProperties(lifecycle))
        return;

    // Main-gate admission and RX/session writers cannot run during this
    // action. Recheck off-gate owner flags and atomic epochs after the bounded
    // lock snapshots so a new stop/reset/probe defers publication.
    if (!nativeP2PPublicationStateStillStable(
            owner, probeBefore, txResources))
        return;

    // Callback taps are merged only after the real lifecycle gate and the
    // bounded TX-resource snapshots both prove that bulk IORegistry work is
    // outside a probe/ROC/stop window.
    const NativeAwdlDataTxTrace::Status stopMerge = trace.mergeStopTap();
    const NativeAwdlDataTxTrace::Status responseMerge =
        trace.mergeTxResponseTap();
    NativeAwdlDataTxTrace::PublicationSnapshot publicationBefore{};
    trace.publicationSnapshot(&publicationBefore);
    if (!publicationBefore.revisionStable ||
        !nativeP2PPublicationStateStillStable(
            owner, probeBefore, txResources))
        return;

    const uint64_t sourceVersion = trace.snapshotVersion();
    const uint64_t sourceRevision = publicationBefore.revision;
    if ((sourceVersion & 1u) ||
        trace.revision() != sourceRevision ||
        sourceVersion > UINT64_MAX - 2u)
        return;

    const bool tapsTransient =
        publicationBefore.txResponse.state !=
            NativeAwdlDataTxTrace::TapPublicationState::EmptyOrConsumed ||
        publicationBefore.stop.state !=
            NativeAwdlDataTxTrace::TapPublicationState::EmptyOrConsumed ||
        stopMerge == NativeAwdlDataTxTrace::Status::ResponseTapBusy ||
        stopMerge == NativeAwdlDataTxTrace::Status::ResponseTapUnstable ||
        responseMerge == NativeAwdlDataTxTrace::Status::ResponseTapBusy ||
        responseMerge == NativeAwdlDataTxTrace::Status::ResponseTapUnstable;
    if (tapsTransient) {
        // RF/TX lifecycle is now proven quiescent. Invalidate an older even
        // snapshot so a late callback cannot be mistaken for missing evidence;
        // leave Begin odd and defer the body until the tap is consumed.
        if (!setNativeP2PDataTxTraceProperty(controller,
                "NativeP2PDataTxTraceSnapshotVersionBegin",
                sourceVersion + 1u, 64))
            return;
        (void)setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotComplete", 0, 32);
        return;
    }
    if (trace.hasPublishedSnapshot() && sourceVersion ==
            trace.lastPublishedSnapshotVersion())
        return;

    // The public writer version is independent from Revision. Offset by two
    // so the clean version-0 snapshot is still a nonzero even seqlock version.
    const uint64_t publishedVersion = sourceVersion + 2u;
    const uint64_t writingVersion = publishedVersion - 1u;
    if (!setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotVersionBegin", writingVersion, 64))
        return;

    bool writesOk = setNativeP2PDataTxTraceProperty(controller,
        "NativeP2PDataTxTraceSnapshotComplete", 0, 32);
    if (!writesOk)
        return;
    const auto setHeader = [&](const char *name, uint64_t value,
                               unsigned int bits) {
        if (writesOk)
            writesOk = setNativeP2PDataTxTraceProperty(
                controller, name, value, bits);
    };

    NativeAwdlDataTxTrace::Identity ownerIdentity{};
    const bool ownerPresent = trace.ownerPresent() &&
        trace.ownerSnapshot(&ownerIdentity);
    const uint64_t zero = 0;
    setHeader("NativeP2PDataTxTraceSchemaVersion", 1, 32);
    setHeader("NativeP2PDataTxTraceRevision", sourceRevision, 64);
    setHeader("NativeP2PDataTxTraceOwnerPresent", ownerPresent ? 1 : 0, 32);
    // OwnerSerial is the diagnostic generation for this bounded trace window.
    setHeader("NativeP2PDataTxTraceOwnerSerial",
              ownerPresent ? ownerIdentity.diagnosticGeneration : zero, 64);
    setHeader("NativeP2PDataTxTraceOwnerDiagnosticGeneration",
              ownerPresent ? ownerIdentity.diagnosticGeneration : zero, 64);
    setHeader("NativeP2PDataTxTraceOwnerContextGeneration",
              ownerPresent ? ownerIdentity.contextGeneration : zero, 64);
    setHeader("NativeP2PDataTxTraceOwnerPowerGeneration",
              ownerPresent ? ownerIdentity.powerGeneration : zero, 64);
    setHeader("NativeP2PDataTxTraceOwnerStationGeneration",
              ownerPresent ? ownerIdentity.stationGeneration : zero, 64);
    setHeader("NativeP2PDataTxTraceOwnerRocGeneration",
              ownerPresent ? ownerIdentity.rocGeneration : zero, 64);
    setHeader("NativeP2PDataTxTraceCount", trace.count(), 32);
    setHeader("NativeP2PDataTxTraceDroppedCount", trace.droppedCount(), 64);
    const bool mergeStatusClean =
        (stopMerge == NativeAwdlDataTxTrace::Status::Ready ||
         stopMerge == NativeAwdlDataTxTrace::Status::NoRecord) &&
        (responseMerge == NativeAwdlDataTxTrace::Status::Ready ||
         responseMerge == NativeAwdlDataTxTrace::Status::NoRecord);
    const bool coverageUnknown = publicationBefore.coverageUnknown ||
        !mergeStatusClean;
    const NativeAwdlDataTxTrace::TapPublicationSnapshot &responseTap =
        publicationBefore.txResponse;
    const NativeAwdlDataTxTrace::TapPublicationSnapshot &stopTap =
        publicationBefore.stop;
    setHeader("NativeP2PDataTxTraceCoverageUnknown",
              coverageUnknown ? 1 : 0, 32);
    setHeader("NativeP2PDataTxTraceResponseTapMergeStatus",
              static_cast<uint32_t>(responseMerge), 32);
    setHeader("NativeP2PDataTxTraceStopTapMergeStatus",
              static_cast<uint32_t>(stopMerge), 32);
    setHeader("NativeP2PDataTxTraceTxRspTapState",
              static_cast<uint32_t>(responseTap.state), 32);
    setHeader("NativeP2PDataTxTraceTxRspTapSequence",
              responseTap.sequence, 64);
    setHeader("NativeP2PDataTxTraceTxRspTapConsumedSequence",
              responseTap.consumedSequence, 64);
    setHeader("NativeP2PDataTxTraceTxRspTapDroppedCount",
              responseTap.droppedCount, 64);
    setHeader("NativeP2PDataTxTraceTxRspTapActivePublicationSequence",
              responseTap.activePublicationSequence, 64);
    setHeader("NativeP2PDataTxTraceTxRspTapActiveToken",
              responseTap.activeToken, 64);
    setHeader("NativeP2PDataTxTraceStopTapState",
              static_cast<uint32_t>(stopTap.state), 32);
    setHeader("NativeP2PDataTxTraceStopTapSequence", stopTap.sequence, 64);
    setHeader("NativeP2PDataTxTraceStopTapConsumedSequence",
              stopTap.consumedSequence, 64);
    setHeader("NativeP2PDataTxTraceStopTapDroppedCount",
              stopTap.droppedCount, 64);
    setHeader("NativeP2PDataTxTraceStopTapActivePublicationSequence",
              stopTap.activePublicationSequence, 64);
    setHeader("NativeP2PDataTxTraceStopTapActiveToken", stopTap.activeToken, 64);
    // TX_RSP does not echo the host token or full generation tuple. A local
    // scalar match is deliberately reported as local association only.
    setHeader("NativeP2PDataTxTraceFirmwareEchoesFullIdentity", 0, 32);
    setHeader("NativeP2PDataTxTraceAssociationStrengthCandidateOnly",
              static_cast<uint32_t>(NativeAwdlDataTxTrace::AssociationStrength::CandidateOnly), 32);
    setHeader("NativeP2PDataTxTraceAssociationStrengthLocalScalarMatch",
              static_cast<uint32_t>(NativeAwdlDataTxTrace::AssociationStrength::LocalScalarFieldsMatch), 32);
    setHeader("NativeP2PDataTxTraceAssociationStrengthExistingHandlerAccepted",
              static_cast<uint32_t>(NativeAwdlDataTxTrace::AssociationStrength::ExistingHandlerAccepted), 32);

    for (uint32_t index = 0;
         writesOk && index < NativeAwdlDataTxTrace::kRecordCapacity;
         ++index) {
        NativeAwdlDataTxTrace::RecordSnapshot record{};
        if (!trace.snapshot(index, &record)) {
            writesOk = false;
            break;
        }
        const bool present = record.present;
        const NativeAwdlDataTxTrace::Identity emptyIdentity{};
        const NativeAwdlDataTxTrace::Identity &identity = present ?
            record.identity : emptyIdentity;
        const auto setRecord = [&](const char *field, uint64_t value,
                                   unsigned int bits) {
            if (writesOk)
                writesOk = setNativeP2PDataTxTraceRecordField(
                    controller, index, field, value, bits);
        };
        setRecord("RecordPresent", present ? 1 : 0, 32);
        setRecord("Used", present ? 1 : 0, 32);
        setRecord("RecordSerial", present ? record.recordSerial : zero, 64);
        setRecord("Token", present ? identity.token : zero, 64);
        setRecord("DiagnosticGeneration",
                  present ? identity.diagnosticGeneration : zero, 64);
        setRecord("ContextGeneration",
                  present ? identity.contextGeneration : zero, 64);
        setRecord("PowerGeneration",
                  present ? identity.powerGeneration : zero, 64);
        setRecord("StationGeneration",
                  present ? identity.stationGeneration : zero, 64);
        setRecord("RocGeneration",
                  present ? identity.rocGeneration : zero, 64);
        setRecord("StagePresenceFlags", present ? record.stageMask : zero, 32);
        setRecord("QueueMetadataPresent",
                  present && record.queueMetadataPresent ? 1 : 0, 32);
        setRecord("QueryClass", present ? record.queryClass : zero, 32);
        setRecord("Eligible", present && record.queueEligible ? 1 : 0, 32);
        setRecord("QueueBornUs", present ? record.queueBornUs : zero, 64);
        setRecord("DequeuedUs", present ? record.dequeuedUs : zero, 64);
        setRecord("SubmitCallStartUs", present ? record.submitCallStartUs : zero, 64);
        setRecord("FinalWireUs", present ? record.finalWireUs : zero, 64);
        setRecord("RingReservedUs", present ? record.ringReservedUs : zero, 64);
        setRecord("DescriptorReadyUs", present ? record.descriptorReadyUs : zero, 64);
        setRecord("DoorbellMarkedUs", present ? record.doorbellMarkedUs : zero, 64);
        setRecord("DoorbellIssuedUs", present ? record.doorbellIssuedUs : zero, 64);
        setRecord("TxRspTapUs", present ? record.txRspTapUs : zero, 64);
        setRecord("CompletionUs", present ? record.completionUs : zero, 64);
        setRecord("CancelUs", present ? record.cancelUs : zero, 64);
        setRecord("UnknownUs", present ? record.unknownUs : zero, 64);
        setRecord("EncodeFailureUs", present ? record.encodeFailureUs : zero, 64);
        setRecord("StopUs", present ? record.stopUs : zero, 64);
        setRecord("SubmitCallEndUs", present ? record.submitCallEndUs : zero, 64);
        setRecord("FrameControl", present ? record.frameControl : zero, 32);
        setRecord("SequenceControl", present ? record.sequenceControl : zero, 32);
        setRecord("MpduLength", present ? record.mpduLength : zero, 32);
        setRecord("PacketCount", present ? record.packetCount : zero, 32);
        setRecord("IPv6Length", present ? record.ipv6Length : zero, 32);
        setRecord("QueueId", present ? record.queueId : zero, 32);
        setRecord("RingSize", present ? record.ringSize : zero, 32);
        setRecord("DescriptorIndex", present ? record.descriptorIndex : zero, 32);
        setRecord("TxRspQueueId", present ? record.txRspQueueId : zero, 32);
        setRecord("TxRspRxHeaderIndex",
                  present ? record.txRspRxHeaderIndex : zero, 32);
        setRecord("TxRspSequenceControl", present ? record.txRspSequenceControl : zero, 32);
        setRecord("TxRspByteCount", present ? record.txRspByteCount : zero, 32);
        setRecord("TxRspFrameControl", present ? record.txRspFrameControl : zero, 32);
        setRecord("TxRspStatus", present ? record.txRspStatus : zero, 32);
        setRecord("TxRspRaTid", present ? record.txRspRaTid : zero, 32);
        setRecord("TxRspScdSsn", present ? record.txRspScdSsn : zero, 32);
        setRecord("TxRspValidFields", present ? record.txRspValidFields : zero, 32);
        setRecord("SubmitCallResult", present ? record.submitCallResult : zero, 32);
        setRecord("CompletionResult", present ? record.completionResult : zero, 32);
        setRecord("CancellationReason", present ? record.cancellationReason : zero, 32);
        setRecord("UnknownReason", present ? record.unknownReason : zero, 32);
        setRecord("EncodeFailureResult", present ? record.encodeFailureResult : zero, 32);
        setRecord("StopNewGeneration", present ? record.stopNewGeneration : zero, 32);
        setRecord("StopReason", present ? record.stopReason : zero, 32);
        setRecord("StopProvenDrain",
                  present && record.stopProvenDrain ? 1 : 0, 32);
        setRecord("ResponseMismatchMask", present ? record.responseMismatchMask : zero, 32);
        setRecord("ResponseScalarMatchMask", present ? record.responseScalarMatchMask : zero, 32);
        setRecord("AssociationStrength", present ? record.associationStrength : zero, 32);
        setRecord("TxRspHandlerDisposition",
                  present ? record.txRspHandlerDisposition : zero, 32);
        setRecord("FirmwareEchoesFullIdentity",
                  present && record.firmwareEchoesFullIdentity ? 1 : 0, 32);
        setRecord("AmbiguousLateQueueUnknown",
                  present && record.ambiguousLateQueueUnknown ? 1 : 0, 32);
        setRecord("ResponseCandidateSeen",
                  present && record.responseCandidateSeen ? 1 : 0, 32);
    }

    NativeAwdlDataTxTrace::PublicationSnapshot publicationAfter{};
    trace.publicationSnapshot(&publicationAfter);
    if (!writesOk ||
        !nativeP2PPublicationStateStillStable(
            owner, probeBefore, txResources) ||
        !NativeAwdlDataTxTrace::Ledger::canClosePublication(
            publicationBefore, publicationAfter, sourceRevision) ||
        trace.snapshotVersion() != sourceVersion ||
        trace.revision() != sourceRevision)
        return;

    // SnapshotComplete means every callback tap was observed without drops.
    // A drop can still publish stable known rows, but must remain explicitly
    // incomplete instead of discarding useful local timestamps.
    if (!coverageUnknown && !setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotComplete", 1, 32))
        return;

    if (!setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotVersionEnd", publishedVersion, 64))
        return;
    NativeAwdlDataTxTrace::PublicationSnapshot publicationClosing{};
    trace.publicationSnapshot(&publicationClosing);
    if (!NativeAwdlDataTxTrace::Ledger::canClosePublication(
            publicationBefore, publicationClosing, sourceRevision) ||
        !nativeP2PPublicationStateStillStable(
            owner, probeBefore, txResources) ||
        trace.snapshotVersion() != sourceVersion ||
        trace.revision() != sourceRevision)
        return;
    if (!setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotVersionBegin", publishedVersion, 64))
        return;
    NativeAwdlDataTxTrace::PublicationSnapshot publicationPublished{};
    trace.publicationSnapshot(&publicationPublished);
    if (!NativeAwdlDataTxTrace::Ledger::canClosePublication(
            publicationBefore, publicationPublished, sourceRevision) ||
        !nativeP2PPublicationStateStillStable(
            owner, probeBefore, txResources) ||
        trace.snapshotVersion() != sourceVersion ||
        trace.revision() != sourceRevision) {
        (void)setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotVersionBegin",
            publishedVersion + 1u, 64);
        return;
    }
    if (!trace.markPublishedSnapshotVersion(sourceVersion)) {
        // A source revision raced the final publication despite the main-gate
        // serialization. Re-invalidate the just-closed view so readers cannot
        // treat a now-stale body as a completed snapshot.
        (void)setNativeP2PDataTxTraceProperty(controller,
            "NativeP2PDataTxTraceSnapshotVersionBegin",
            publishedVersion + 1u, 64);
    }
}

static IOReturn publishNativeP2PDataTxTraceAction(
    OSObject *, void *halContext, void *, void *, void *)
{
    ItlIwx *owner = static_cast<ItlIwx *>(halContext);
    if (!owner || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    publishNativeP2PDataTxTraceOnMainGate(owner);
    return kIOReturnSuccess;
}

static void requestNativeP2PDataTxTracePublish(ItlIwx *owner)
{
    if (!owner)
        return;
    if (owner->tahoeP2pOnMainGate()) {
        publishNativeP2PDataTxTraceOnMainGate(owner);
        return;
    }
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    if (gate)
        // The watchdog timer runs on a separate workloop. Do not block that
        // workloop waiting for the main gate: stop may own the main gate while
        // it drains the watchdog timer. A busy gate leaves the trace dirty;
        // the next periodic tick retries publication.
        (void)gate->attemptAction(publishNativeP2PDataTxTraceAction, owner);
}

static IOReturn publishPendingQmWireSnapshotAction(
    OSObject *, void *halContext, void *, void *, void *)
{
    ItlIwx *owner = static_cast<ItlIwx *>(halContext);
    if (!owner || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    // Recheck on the serialized owner gate. A race with a newly admitted probe
    // leaves the one-shot QM record pending for the next watchdog tick.
    if (nativeP2PPublicationBusy(owner))
        return kIOReturnNotReady;
    (void)iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(owner);
    return kIOReturnSuccess;
}

static void requestNativeP2PQmWireSnapshotPublish(ItlIwx *owner)
{
    if (!owner)
        return;
    if (owner->tahoeP2pOnMainGate()) {
        if (!nativeP2PPublicationBusy(owner))
            (void)iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(owner);
        return;
    }
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    if (gate)
        // This is a watchdog-loop request only. Never wait on the main gate;
        // if it is busy, the next periodic tick retries the pending record.
        (void)gate->attemptAction(publishPendingQmWireSnapshotAction, owner);
}
#endif

void ItlIwx::tahoeP2pPublishProbeState()
{
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    // Keep all probe/ROC property publication out of the command owner's
    // active window. nativeP2pTick still drains RX above this function; this
    // only defers diagnostics until the owner has returned and released.
    if (nativeP2PPublicationBusy(this))
        return;
    requestNativeP2PQmWireSnapshotPublish(this);
#endif
    tahoeP2pPublishRocState();
    IOEthernetController *controller = getController();
    if (!controller)
        return;
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    requestNativeP2PTxTimeEvidencePublish(this);
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    requestNativeP2PDataTxTracePublish(this);
#endif

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
    controller->setProperty("NativeP2PProbeExerciseResult",
                            static_cast<uint32_t>(snapshot.exerciseResult), 32);
    controller->setProperty("NativeP2PProbeExerciseRecoveryAttempted",
                            snapshot.exerciseRecoveryAttempted, 32);
    controller->setProperty("NativeP2PProbeExerciseRecoveryProofAccepted",
                            snapshot.exerciseRecoveryProofAccepted, 32);
    nativeP2pProbePublished_ = snapshot;
    nativeP2pProbePublishedOnce_ = true;
}

#endif // AIRPORT_TAHOE
