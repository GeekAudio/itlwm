// Test shim for the production Test134 admission worker and outer gates.
// The Python runner replaces the marker below with extracted production code.
#include <cassert>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "native/awdl_discovery_rx_input.hpp"
#include "native/p2p_hal_probe.hpp"
#include "native/p2p_tx_resources.hpp"
#include "native/tahoe_p2p_mac_ack.hpp"

#define ITL_NATIVE_AWDL_MULTICAST_ADMISSION_25G332 1

using thread_t = void *;
using IOInterruptState = unsigned long;
using IOReturn = int;
enum {
    kIOReturnSuccess = 0,
    kIOReturnNotReady = 1,
    IWX_P2P_RESOURCE_ABSENT = 0,
    IWX_P2P_RESOURCE_ACTIVE = 1,
    IWX_P2P_RESOURCE_UNKNOWN = 2,
    IWX_P2P_ROC_IDLE = 0,
    IWX_P2P_ROC_PREPARED = 1,
    IWX_P2P_ROC_COMPLETE = 2,
    IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION = 3,
    IWX_DEFAULT_QUEUE_SIZE = 256,
    IWX_INVALID_QUEUE = 0xffff,
    kMulticastAdmissionStarting = 1,
    kMulticastAdmissionRocPrepared = 2,
    kMulticastAdmissionStationAcknowledged = 3,
    kMulticastAdmissionQueueConfigured = 4,
    kMulticastAdmissionCleaning = 5,
    kMulticastAdmissionComplete = 6,
    kMulticastAdmissionQuarantined = 7,
};

struct OSObject {};
struct IOSimpleLock { bool held = false; };
static IOSimpleLock *IOSimpleLockAlloc() { return new IOSimpleLock; }
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    assert(lock && !lock->held);
    lock->held = true;
    return 0;
}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock,
                                               IOInterruptState) {
    assert(lock && lock->held);
    lock->held = false;
}

enum class TahoeP2PResourceState : uint8_t {
    kAbsent, kPending, kActive, kRemoving, kReleasing, kUnknown
};
enum class TahoeP2PStationRole : uint8_t {
    kBroadcastGeneralPurpose, kDirectedPeerLink, kMulticastData
};
enum class TahoeP2PQueueUse : uint8_t {
    kManagementTid15, kDirectedNonQosDataTid0, kMulticastNonQosDataTid0
};
enum class TahoeP2PActionTxState : uint8_t { kIdle, kPreparing, kSubmitted };

struct TahoeP2PStationLease {
    uint8_t stationId = 0;
    uint32_t generation = 0;
    TahoeP2PResourceState state = TahoeP2PResourceState::kAbsent;
    TahoeP2PStationRole role = TahoeP2PStationRole::kBroadcastGeneralPurpose;
    uint8_t address[6]{};
    uint32_t macIdAndColor = 0;
    uint8_t stationType = 0, addCommandVersion = 0, addNotificationVersion = 0;
    uint64_t allocationSerial = 0;
};
struct TahoeP2PTxQueueLease {
    uint8_t stationId = 0;
    uint16_t queueId = IWX_INVALID_QUEUE;
    uint32_t generation = 0;
    TahoeP2PResourceState state = TahoeP2PResourceState::kAbsent;
    TahoeP2PStationRole stationRole = TahoeP2PStationRole::kBroadcastGeneralPurpose;
    TahoeP2PQueueUse queueUse = TahoeP2PQueueUse::kManagementTid15;
    uint8_t firmwareTid = 15;
    uint8_t peerAddress[6]{};
    uint32_t macIdAndColor = 0;
    IOSimpleLock *stateLock = nullptr;
    bool submissionBusy = false;
    bool everDoorbelled = false;
    void *pendingRing = nullptr;
    void *retainedRing = nullptr;
    uint32_t retainedRingGeneration = 0;
    uint16_t retainedRingQueueId = IWX_INVALID_QUEUE;
    uint16_t firmwareWritePointer = 0;
    bool queueConfiguredUninstalled = false;
    uint16_t pendingFirmwareQueueId = UINT16_MAX;
    uint16_t pendingFirmwareSsn = 0;
    bool unsubmittedAbortInProgress = false;
    bool idleAbortAfterEndInProgress = false;
    uint64_t allocationSerial = 0;
    IntelP2PTx::QueueLease lifecycle;
};

struct ieee80211_channel { uint16_t channel = 6; };
struct ieee80211com { ieee80211_channel ic_channels[16]{}; };
struct iwx_p2p_context {
    uint8_t mac_state = IWX_P2P_RESOURCE_ACTIVE;
    uint8_t binding_state = IWX_P2P_RESOURCE_ABSENT;
    bool phy_leased = false;
    uint32_t fw_generation = 7;
};
struct iwx_p2p_roc_state {
    uint32_t token = 0, fw_generation = 0;
    int32_t session_submit_result = 0;
    uint8_t phase = IWX_P2P_ROC_IDLE;
    uint8_t session_conf_id = 0;
    uint8_t session_submit_seen = 0;
};
struct iwx_softc {
    uint32_t sc_generation = 7, sc_tx_rate_generation = 9;
    ieee80211com sc_ic{};
    iwx_p2p_context sc_p2p{};
    iwx_p2p_roc_state sc_p2p_roc{};
};

struct TicketSnapshot { bool armed = false, completed = false; };
struct FakeCompletion {
    TicketSnapshot current{};
    TicketSnapshot snapshot() const { return current; }
};
struct FakeActionContext {
    TahoeP2PActionTxState state = TahoeP2PActionTxState::kIdle;
    FakeCompletion completion;
};
struct P2PTxDiagnosticSnapshot {
    uint32_t outstandingTx = 0;
    uint32_t actionState = 0;
    bool ticketArmed = false, ticketCompleted = false, queueDoorbelled = false;
};

struct IOEthernetController {
    std::map<std::string, uint64_t> properties;
    bool setProperty(const char *key, uint32_t value, unsigned bits) {
        assert(bits == 32);
        properties[key] = value;
        return true;
    }
    bool setProperty(const char *key, uint64_t value, unsigned bits) {
        assert(bits == 64);
        properties[key] = value;
        return true;
    }
    uint64_t property(const char *key) const {
        auto it = properties.find(key);
        return it == properties.end() ? UINT64_MAX : it->second;
    }
};

using GateAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);
struct IOCommandGate {
    IOReturn runAction(GateAction action, void *opaque) {
        return action(nullptr, opaque, nullptr, nullptr, nullptr);
    }
};

struct ItlIwx;
struct P2PProbeRun {
    ItlIwx *owner = nullptr;
    thread_t workerThread = nullptr;
    bool multicastAdmissionOnly = true;
    bool sessionSubmitReached = false;
    uint32_t contextGeneration = 11, powerGeneration = 7;
    uint32_t scGeneration = 7, stationGeneration = 9, p2pFirmwareGeneration = 7;
    uint32_t multicastStage = 0;
    int32_t multicastOperationResult = 0, multicastCleanupResult = 0;
    bool multicastStationAddAck = false;
    bool multicastQueueConfiguredUninstalled = false;
    bool multicastNeverDoorbelled = false, multicastResourcesAbsent = false;
    bool multicastOldLeaseInitiallyAbsent = false, multicastOldLeaseUnchanged = false;
    bool multicastRocAbortAcknowledged = false, multicastMacRemoveAttempted = false;
    uint64_t multicastStationAllocationSerial = 0, multicastQueueAllocationSerial = 0;
    NativeAwdlDiscoveryRxInput::RocCleanupWitness multicastPrepareWitness{};
    TahoeP2PMacContextAckReceipt multicastMacRemoveAck{};
};

struct ItlIwx {
    iwx_softc com{};
    IOEthernetController controller{};
    IOCommandGate gate{};
    IOSimpleLock *nativeP2pTxLock_ = IOSimpleLockAlloc();
    IntelP2PTx::StationRegistry nativeP2pStationRegistry_{};
    TahoeP2PStationLease nativeP2pStation_{};
    TahoeP2PTxQueueLease nativeP2pTxQueue_{};
    TahoeP2PStationLease nativeP2pMulticastStation_{};
    TahoeP2PTxQueueLease nativeP2pMulticastTxQueue_{};
    FakeActionContext nativeP2pActionTx_{};
    NativeP2PProbe::Controller nativeP2pProbe_{};
    uint64_t nativeP2pMulticastStationSerialHighWater_ = 0;
    uint64_t nativeP2pMulticastQueueSerialHighWater_ = 0;
    void *nativeP2pProbeOwner_ = nullptr;
    uint32_t nativeP2pProbeGeneration_ = 11;
    uint32_t nativeP2pRocChannel_ = 0, nativeP2pRocDurationMs_ = 0;
    bool commandAllowed = true, mainGate = true, busy = true;
    int prepareResult = 0, abortPreparedResult = 0;
    int addResult = 0, stationRemoveResult = 0, queueResult = 0;
    int queueFlushResult = 0, queueRemoveResult = 0, macRemoveResult = 0;
    bool addMayExist = false, queueMayExist = false;
    unsigned prepareCalls = 0, abortPreparedCalls = 0, addCalls = 0;
    unsigned stationRemoveCalls = 0, queueCalls = 0, queueAbortCalls = 0;
    unsigned macRemoveCalls = 0, legacyMacRemoveCalls = 0;
    std::vector<std::string> events;

    ItlIwx() {
        assert(nativeP2pStationRegistry_.initialize(32, 7, true, true, true) ==
               IntelP2PTx::Result::kSuccess);
        // Keep distinctive but absent legacy management metadata. The
        // production worker must leave this separate lease untouched.
        nativeP2pStation_.stationId = 2;
        nativeP2pStation_.generation = 7;
        nativeP2pStation_.role = TahoeP2PStationRole::kBroadcastGeneralPurpose;
        nativeP2pStation_.address[0] = 0x02;
        nativeP2pStation_.address[5] = 0x6d;
        nativeP2pTxQueue_.stationId = 2;
        nativeP2pTxQueue_.generation = 7;
        nativeP2pTxQueue_.queueUse = TahoeP2PQueueUse::kManagementTid15;
        nativeP2pTxQueue_.firmwareTid = 15;
        nativeP2pTxQueue_.allocationSerial = 0x1234;
    }
    ~ItlIwx() { delete nativeP2pTxLock_; }
    bool nativeP2pCommandAllowed() const { return commandAllowed; }
    bool tahoeP2pOnMainGate() const { return mainGate; }
    bool nativeP2pBusy() const { return busy; }
    IOCommandGate *tahoeP2pCommandGate() { return &gate; }
    IOEthernetController *tahoeP2pController() { return &controller; }
    int tahoeP2pRocPrepare(iwx_softc *, ieee80211_channel *, uint32_t, uint32_t);
    int tahoeP2pRocAbortPrepared(iwx_softc *, uint32_t, uint32_t, bool);
    int iwx_p2p_mac_context_remove_with_ack(
        iwx_softc *, TahoeP2PMacContextAckReceipt *);
    int iwx_p2p_mac_context_remove(iwx_softc *);
};

static bool captureP2PTxSnapshot(ItlIwx *, P2PTxDiagnosticSnapshot *);
static int iwx_tahoe_p2p_add_multicast_data_station(
    ItlIwx *, iwx_softc *, TahoeP2PStationLease *, uint8_t, bool, bool *);
static int iwx_tahoe_p2p_remove_multicast_data_station(
    ItlIwx *, iwx_softc *, TahoeP2PStationLease *, TahoeP2PTxQueueLease *, bool *);
static int iwx_tahoe_p2p_tvqm_allocate(
    ItlIwx *, iwx_softc *, TahoeP2PTxQueueLease *,
    const TahoeP2PStationLease *, uint32_t, uint16_t *, bool *, TahoeP2PQueueUse);
static int iwx_tahoe_p2p_tvqm_bind_allocation_serials(
    iwx_softc *, TahoeP2PStationLease *, TahoeP2PTxQueueLease *, uint64_t, uint64_t);
static int iwx_tahoe_p2p_tvqm_abort_multicast_unsubmitted(
    ItlIwx *, iwx_softc *, TahoeP2PStationLease *, TahoeP2PTxQueueLease *,
    uint64_t, uint64_t, bool *);
static int exerciseMulticastAdmissionOnly(P2PProbeRun *);
static int remove(void *opaque);
static void finalizeMulticastAdmissionState(ItlIwx *, P2PProbeRun *);

/* PRODUCTION_WORKER_AND_REMOVE */

int ItlIwx::tahoeP2pRocPrepare(iwx_softc *sc, ieee80211_channel *channel,
                               uint32_t generation, uint32_t configuration) {
    ++prepareCalls;
    events.push_back("ROC_PREPARE");
    assert(sc == &com && channel == &sc->sc_ic.ic_channels[6]);
    assert(generation == 11 && configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
    if (prepareResult) return prepareResult;
    sc->sc_p2p.binding_state = IWX_P2P_RESOURCE_ACTIVE;
    sc->sc_p2p.phy_leased = true;
    sc->sc_p2p_roc.phase = IWX_P2P_ROC_PREPARED;
    sc->sc_p2p_roc.token = generation;
    sc->sc_p2p_roc.fw_generation = sc->sc_generation;
    sc->sc_p2p_roc.session_conf_id = configuration;
    sc->sc_p2p_roc.session_submit_result = EINPROGRESS;
    return 0;
}

int ItlIwx::tahoeP2pRocAbortPrepared(iwx_softc *sc, uint32_t generation,
                                     uint32_t configuration, bool noSession) {
    ++abortPreparedCalls;
    events.push_back("ROC_ABORT_PREPARED");
    assert(sc == &com && generation == 11 && configuration ==
           IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION && noSession);
    assert(sc->sc_p2p_roc.session_submit_seen == 0);
    if (abortPreparedResult) return abortPreparedResult;
    sc->sc_p2p.binding_state = IWX_P2P_RESOURCE_ABSENT;
    sc->sc_p2p.phy_leased = false;
    sc->sc_p2p_roc.phase = IWX_P2P_ROC_COMPLETE;
    return 0;
}

int ItlIwx::iwx_p2p_mac_context_remove_with_ack(
    iwx_softc *sc, TahoeP2PMacContextAckReceipt *receipt) {
    ++macRemoveCalls;
    events.push_back("MAC_REMOVE_WITH_ACK");
    assert(sc == &com && receipt);
    if (macRemoveResult) return macRemoveResult;
    receipt->accepted = 1;
    receipt->transportResult = 0;
    receipt->observedP2PEpoch = receipt->expectedP2PEpoch;
    receipt->observedRocToken = receipt->expectedRocToken;
    receipt->driverGeneration = receipt->expectedDriverGeneration;
    receipt->observedDriverGeneration = receipt->expectedDriverGeneration;
    receipt->observedP2PFirmwareGeneration = receipt->expectedDriverGeneration;
    sc->sc_p2p.mac_state = IWX_P2P_RESOURCE_ABSENT;
    return 0;
}
int ItlIwx::iwx_p2p_mac_context_remove(iwx_softc *) {
    ++legacyMacRemoveCalls;
    events.push_back("MAC_REMOVE_LEGACY");
    return macRemoveResult;
}

static bool captureP2PTxSnapshot(ItlIwx *owner, P2PTxDiagnosticSnapshot *out) {
    if (!owner || !out || !owner->mainGate) return false;
    out->ticketArmed = owner->nativeP2pActionTx_.completion.current.armed;
    out->ticketCompleted = owner->nativeP2pActionTx_.completion.current.completed;
    out->queueDoorbelled = owner->nativeP2pTxQueue_.everDoorbelled ||
        owner->nativeP2pMulticastTxQueue_.everDoorbelled;
    out->actionState = static_cast<uint32_t>(owner->nativeP2pActionTx_.state);
    out->outstandingTx = 0;
    return true;
}

static int iwx_tahoe_p2p_add_multicast_data_station(
    ItlIwx *owner, iwx_softc *sc, TahoeP2PStationLease *station,
    uint8_t stationId, bool optIn, bool *mayExist) {
    ++owner->addCalls;
    owner->events.push_back("ADD_MULTICAST_STA");
    assert(sc == &owner->com && station && optIn && mayExist);
    *mayExist = owner->addMayExist;
    if (owner->addResult) {
        if (owner->addMayExist) {
            station->stationId = stationId;
            station->generation = sc->sc_generation;
            station->role = TahoeP2PStationRole::kMulticastData;
            station->state = TahoeP2PResourceState::kUnknown;
        }
        return owner->addResult;
    }
    station->stationId = stationId;
    station->generation = sc->sc_generation;
    station->role = TahoeP2PStationRole::kMulticastData;
    station->state = TahoeP2PResourceState::kActive;
    station->macIdAndColor = 0x100;
    station->address[0] = 0x01;
    station->address[5] = 0x13;
    *mayExist = false;
    return 0;
}

static int iwx_tahoe_p2p_remove_multicast_data_station(
    ItlIwx *owner, iwx_softc *, TahoeP2PStationLease *station,
    TahoeP2PTxQueueLease *, bool *mayExist) {
    ++owner->stationRemoveCalls;
    owner->events.push_back("REMOVE_MULTICAST_STA");
    if (owner->stationRemoveResult) {
        station->state = TahoeP2PResourceState::kUnknown;
        *mayExist = true;
        return owner->stationRemoveResult;
    }
    station->state = TahoeP2PResourceState::kAbsent;
    *mayExist = false;
    return 0;
}

static int iwx_tahoe_p2p_tvqm_allocate(
    ItlIwx *owner, iwx_softc *sc, TahoeP2PTxQueueLease *queue,
    const TahoeP2PStationLease *station, uint32_t, uint16_t *queueId,
    bool *mayExist, TahoeP2PQueueUse use) {
    ++owner->queueCalls;
    owner->events.push_back("SCD_QUEUE_CFG_MULTICAST_TID0");
    assert(sc == &owner->com && station && use == TahoeP2PQueueUse::kMulticastNonQosDataTid0);
    assert(station->state == TahoeP2PResourceState::kActive && queue->firmwareTid == 0);
    queue->stationId = station->stationId;
    queue->generation = station->generation;
    queue->stationRole = TahoeP2PStationRole::kMulticastData;
    queue->queueUse = use;
    queue->stateLock = owner->nativeP2pTxLock_;
    *queueId = 5;
    *mayExist = owner->queueMayExist;
    IntelP2PTx::QueueAdmission admission{};
    admission.api = IntelP2PTx::QueueApi::kLegacyDynamicDqa;
    admission.queueCapacity = 32;
    admission.generation = station->generation;
    admission.stationId = station->stationId;
    admission.stationActive = true;
    admission.p2pMacActive = true;
    admission.p2pBindingActive = true;
    admission.phyLeased = true;
    if (queue->lifecycle.begin(admission) != IntelP2PTx::Result::kSuccess)
        return EBUSY;
    if (owner->queueResult) {
        if (owner->queueMayExist) {
            (void)queue->lifecycle.allocationOutcomeUnknown(
                station->generation, station->stationId);
            queue->state = TahoeP2PResourceState::kUnknown;
            queue->pendingFirmwareQueueId = *queueId;
            queue->pendingRing = reinterpret_cast<void *>(0x1341);
        } else {
            (void)queue->lifecycle.allocationRejected(
                station->generation, station->stationId);
            queue->state = TahoeP2PResourceState::kAbsent;
        }
        return owner->queueResult;
    }
    assert(queue->lifecycle.legacyDqaAssigned(
        station->generation, station->stationId, *queueId, 32, true) ==
        IntelP2PTx::Result::kSuccess);
    queue->queueId = IWX_INVALID_QUEUE; // Firmware configured, host uninstalled.
    queue->state = TahoeP2PResourceState::kPending;
    queue->queueConfiguredUninstalled = true;
    queue->pendingFirmwareQueueId = *queueId;
    queue->pendingFirmwareSsn = 4;
    queue->pendingRing = reinterpret_cast<void *>(0x1342);
    *mayExist = false;
    return 0;
}

static int iwx_tahoe_p2p_tvqm_bind_allocation_serials(
    iwx_softc *, TahoeP2PStationLease *station,
    TahoeP2PTxQueueLease *queue, uint64_t stationSerial, uint64_t queueSerial) {
    station->allocationSerial = stationSerial;
    queue->allocationSerial = queueSerial;
    return 0;
}

static int iwx_tahoe_p2p_tvqm_abort_multicast_unsubmitted(
    ItlIwx *owner, iwx_softc *, TahoeP2PStationLease *station,
    TahoeP2PTxQueueLease *queue, uint64_t stationSerial,
    uint64_t queueSerial, bool *mayExist) {
    ++owner->queueAbortCalls;
    owner->events.push_back("TXPATH_FLUSH");
    assert(queue->allocationSerial == queueSerial || queue->allocationSerial == 0);
    assert(station->allocationSerial == stationSerial || station->allocationSerial == 0);
    if (owner->queueFlushResult) {
        queue->state = TahoeP2PResourceState::kUnknown;
        queue->pendingRing = reinterpret_cast<void *>(0x1343);
        station->state = TahoeP2PResourceState::kUnknown;
        *mayExist = true;
        return owner->queueFlushResult;
    }
    owner->events.push_back("REMOVE_STA");
    if (owner->queueRemoveResult) {
        queue->state = TahoeP2PResourceState::kUnknown;
        queue->pendingRing = reinterpret_cast<void *>(0x1343);
        station->state = TahoeP2PResourceState::kUnknown;
        *mayExist = true;
        return owner->queueRemoveResult;
    }
    if (queue->lifecycle.snapshot().state == IntelP2PTx::QueueState::kActive) {
        assert(queue->lifecycle.beginRemoval(queue->generation, 5) ==
            IntelP2PTx::Result::kSuccess);
        assert(queue->lifecycle.stationRemovalAcknowledged(queue->generation, 5) ==
            IntelP2PTx::Result::kSuccess);
        assert(queue->lifecycle.neverSubmittedQueueReleasedAfterStationRemoval(
            queue->generation, 5) == IntelP2PTx::Result::kSuccess);
    }
    queue->state = TahoeP2PResourceState::kAbsent;
    queue->queueId = IWX_INVALID_QUEUE;
    queue->queueConfiguredUninstalled = false;
    queue->pendingFirmwareQueueId = UINT16_MAX;
    queue->pendingRing = nullptr;
    station->state = TahoeP2PResourceState::kAbsent;
    *mayExist = false;
    return 0;
}

static int runExercise(void *opaque) {
    return exerciseMulticastAdmissionOnly(static_cast<P2PProbeRun *>(opaque));
}
static int runConfigure(void *) { return 0; }
static int runAdd(void *) { return 0; }
static NativeP2PProbe::BlockedReason runRevalidate(void *, uint32_t, uint32_t) {
    return NativeP2PProbe::kNotBlocked;
}
static bool runPublishLease(void *, bool) { return true; }
static NativeP2PProbe::Admission readyAdmission() {
    NativeP2PProbe::Admission admission{};
    admission.enabled = admission.mainGateAvailable = admission.mainGateNotOnThread = true;
    admission.driverRunning = admission.associated = admission.portAuthorized = true;
    admission.scanIdle = admission.commandQueueIdle = admission.stateQueuePaused = true;
    admission.noPendingNewstate = admission.radioAvailable = admission.firmwareHealthy = true;
    admission.p2pContextAbsent = admission.p2pCapabilityAvailable = true;
    admission.contextGeneration = 11;
    admission.powerGeneration = 7;
    admission.stationGeneration = 9;
    return admission;
}
static void assertOldManagementLeaseUnchanged(const ItlIwx &owner) {
    assert(owner.nativeP2pStation_.state == TahoeP2PResourceState::kAbsent);
    assert(owner.nativeP2pStation_.stationId == 2 && owner.nativeP2pStation_.generation == 7);
    assert(owner.nativeP2pStation_.role == TahoeP2PStationRole::kBroadcastGeneralPurpose);
    assert(owner.nativeP2pStation_.address[5] == 0x6d);
    assert(owner.nativeP2pTxQueue_.state == TahoeP2PResourceState::kAbsent);
    assert(owner.nativeP2pTxQueue_.queueId == IWX_INVALID_QUEUE);
    assert(owner.nativeP2pTxQueue_.queueUse == TahoeP2PQueueUse::kManagementTid15);
    assert(owner.nativeP2pTxQueue_.firmwareTid == 15);
    assert(owner.nativeP2pTxQueue_.allocationSerial == 0x1234);
}
static NativeP2PProbe::RunResult executeRun(ItlIwx &owner, P2PProbeRun &run) {
    assert(owner.nativeP2pProbe_.tryQueue(readyAdmission()));
    NativeP2PProbe::Operations operations{};
    operations.context = &run;
    operations.revalidate = runRevalidate;
    operations.configure = runConfigure;
    operations.add = runAdd;
    operations.remove = remove;
    operations.publishLease = runPublishLease;
    operations.exercise = runExercise;
    const auto result = owner.nativeP2pProbe_.executeOnce(operations);
    finalizeMulticastAdmissionState(&owner, &run);
    return result;
}
static P2PProbeRun makeRun(ItlIwx &owner) {
    P2PProbeRun run{};
    run.owner = &owner;
    run.workerThread = reinterpret_cast<void *>(0x134);
    owner.nativeP2pProbeOwner_ = run.workerThread;
    owner.nativeP2pProbeGeneration_ = run.contextGeneration;
    return run;
}

static void successfulAdmissionAndCleanup() {
    ItlIwx owner;
    auto run = makeRun(owner);
    assert(executeRun(owner, run) == NativeP2PProbe::RunResult::kCompleted);
    assert(owner.controller.property("NativeP2PMulticastAdmissionStage") == 6);
    assert(owner.controller.property("NativeP2PMulticastAdmissionOperationResult") == 0);
    assert(owner.controller.property("NativeP2PMulticastAdmissionCleanupResult") == 0);
    assert(owner.controller.property("NativeP2PMulticastAdmissionStationAddAck") == 1);
    assert(owner.controller.property("NativeP2PMulticastAdmissionQueueConfiguredUninstalled") == 1);
    assert(owner.controller.property("NativeP2PMulticastAdmissionNeverDoorbelled") == 1);
    assert(owner.controller.property("NativeP2PMulticastAdmissionResourcesAbsent") == 1);
    assert(owner.controller.property("NativeP2PMulticastAdmissionOldLeaseUnchanged") == 1);
    assert(run.multicastMacRemoveAck.accepted == 1 && owner.macRemoveCalls == 1);
    assert(owner.legacyMacRemoveCalls == 0 && owner.abortPreparedCalls == 1);
    assert(owner.nativeP2pMulticastStation_.state == TahoeP2PResourceState::kAbsent);
    assert(owner.nativeP2pMulticastTxQueue_.state == TahoeP2PResourceState::kAbsent);
    assert(owner.com.sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT);
    assert(!owner.com.sc_p2p.phy_leased && owner.com.sc_p2p_roc.session_submit_seen == 0);
    assert(owner.nativeP2pMulticastTxQueue_.queueId == IWX_INVALID_QUEUE);
    assert(!owner.nativeP2pMulticastTxQueue_.everDoorbelled);
    assert(run.multicastStationAllocationSerial != 0 &&
           run.multicastQueueAllocationSerial == ((uint64_t(1) << 63) | 1));
    assertOldManagementLeaseUnchanged(owner);
}

static void knownAddRejectCleansAndAllowsOuterRemove() {
    ItlIwx owner;
    owner.addResult = EOPNOTSUPP;
    auto run = makeRun(owner);
    assert(executeRun(owner, run) == NativeP2PProbe::RunResult::kCompleted);
    assert(owner.controller.property("NativeP2PMulticastAdmissionStage") == 6);
    assert(owner.controller.property("NativeP2PMulticastAdmissionOperationResult") == EOPNOTSUPP);
    assert(owner.controller.property("NativeP2PMulticastAdmissionCleanupResult") == 0);
    assert(owner.controller.property("NativeP2PMulticastAdmissionResourcesAbsent") == 1);
    assert(owner.macRemoveCalls == 1 && run.multicastMacRemoveAck.accepted == 1);
    assert(owner.queueCalls == 0 && owner.abortPreparedCalls == 1);
    assertOldManagementLeaseUnchanged(owner);
}

static void unknownAddQuarantinesBeforeOuterRemove() {
    ItlIwx owner;
    owner.addResult = ETIMEDOUT;
    owner.addMayExist = true;
    auto run = makeRun(owner);
    assert(executeRun(owner, run) == NativeP2PProbe::RunResult::kQuarantined);
    assert(owner.controller.property("NativeP2PMulticastAdmissionStage") == 7);
    assert(owner.nativeP2pMulticastStation_.state == TahoeP2PResourceState::kUnknown);
    assert(owner.macRemoveCalls == 0 && owner.legacyMacRemoveCalls == 0);
    assert(owner.abortPreparedCalls == 0 && owner.queueCalls == 0);
    assertOldManagementLeaseUnchanged(owner);
}

static void knownQueueRejectCleans() {
    ItlIwx owner;
    owner.queueResult = EINVAL;
    owner.queueMayExist = false;
    auto run = makeRun(owner);
    assert(executeRun(owner, run) == NativeP2PProbe::RunResult::kCompleted);
    assert(owner.controller.property("NativeP2PMulticastAdmissionStage") == 6);
    assert(owner.controller.property("NativeP2PMulticastAdmissionOperationResult") == EINVAL);
    assert(owner.controller.property("NativeP2PMulticastAdmissionResourcesAbsent") == 1);
    assert(owner.stationRemoveCalls == 1 && owner.macRemoveCalls == 1);
    assertOldManagementLeaseUnchanged(owner);
}

static void unknownQueueOrFlushFailureRetainsAndBlocksOuterRemove() {
    ItlIwx owner;
    owner.queueResult = ETIMEDOUT;
    owner.queueMayExist = true;
    owner.queueFlushResult = ETIMEDOUT;
    auto run = makeRun(owner);
    assert(executeRun(owner, run) == NativeP2PProbe::RunResult::kQuarantined);
    assert(owner.controller.property("NativeP2PMulticastAdmissionStage") == 7);
    assert(owner.controller.property("NativeP2PMulticastAdmissionResourcesAbsent") == 0);
    assert(owner.nativeP2pMulticastTxQueue_.state == TahoeP2PResourceState::kUnknown);
    assert(owner.macRemoveCalls == 0 && owner.abortPreparedCalls == 0);
    assert(remove(&run) != 0); // The production outer gate independently fails closed.
    assert(owner.macRemoveCalls == 0 && owner.legacyMacRemoveCalls == 0);
    assertOldManagementLeaseUnchanged(owner);
}

static void flushRemoveFailureAfterConfiguredQueueRetainsResources() {
    for (const auto failure : {std::pair<int, int>{ETIMEDOUT, 0},
                               std::pair<int, int>{0, EIO}}) {
        ItlIwx owner;
        owner.queueFlushResult = failure.first;
        owner.queueRemoveResult = failure.second;
        auto run = makeRun(owner);
        assert(executeRun(owner, run) == NativeP2PProbe::RunResult::kQuarantined);
        assert(owner.queueCalls == 1 && owner.queueAbortCalls == 1);
        assert(owner.nativeP2pMulticastTxQueue_.queueConfiguredUninstalled);
        assert(owner.nativeP2pMulticastTxQueue_.pendingRing != nullptr);
        assert(owner.macRemoveCalls == 0 && owner.abortPreparedCalls == 0);
        assert(remove(&run) != 0);
        assert(owner.macRemoveCalls == 0 && owner.legacyMacRemoveCalls == 0);
        assert(std::find(owner.events.begin(), owner.events.end(), "TXPATH_FLUSH") !=
               owner.events.end());
        if (failure.second)
            assert(std::find(owner.events.begin(), owner.events.end(), "REMOVE_STA") !=
                   owner.events.end());
        assertOldManagementLeaseUnchanged(owner);
    }
}

int main() {
    successfulAdmissionAndCleanup();
    knownAddRejectCleansAndAllowsOuterRemove();
    unknownAddQuarantinesBeforeOuterRemove();
    knownQueueRejectCleans();
    unknownQueueOrFlushFailureRetainsAndBlocksOuterRemove();
    flushRemoveFailureAfterConfiguredQueueRetainsResources();
}
