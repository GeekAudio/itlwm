#!/usr/bin/env python3
"""Run the production directed-prepare worker against a fake firmware transport."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()


def extract(marker):
    start = SOURCE.index(marker)
    opening = SOURCE.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    return SOURCE[start:end]


PRODUCTION = "\n".join(extract(marker) for marker in (
    "static bool validDirectedPeerMac(",
    "static bool validDirectedPrepareRunToken(",
    "static int reserveP2PStation(",
    "static int changeP2PStationReservation(",
    "static IOReturn captureDirectedNoTicketProofAction(",
    "static void publishDirectedPrepareState(",
    "static int exerciseDirectedPrepare(",
))

SHIM = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using thread_t = void *;
using IOInterruptState = unsigned long;
using IOReturn = int;
enum { kIOReturnSuccess=0, kIOReturnNotReady=1,
       IWX_P2P_RESOURCE_ABSENT=0, IWX_P2P_RESOURCE_ACTIVE=1,
       IWX_P2P_ROC_IDLE=0, IWX_P2P_ROC_PREPARED=1,
       IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION=3,
       IWX_DEFAULT_QUEUE_SIZE=256 };
struct OSObject {};
struct IOSimpleLock { bool held=false; };
static IOSimpleLock *IOSimpleLockAlloc() { return new IOSimpleLock; }
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    assert(lock && !lock->held); lock->held=true; return 0;
}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock,
                                               IOInterruptState) {
    assert(lock && lock->held); lock->held=false;
}

enum class TahoeP2PResourceState : uint8_t {
    kAbsent, kPending, kActive, kRemoving, kReleasing, kUnknown
};
enum class TahoeP2PStationRole : uint8_t {
    kBroadcastGeneralPurpose, kDirectedPeerLink
};
enum class TahoeP2PQueueUse : uint8_t {
    kManagementTid15, kDirectedNonQosDataTid0
};
enum class TahoeP2PActionTxState : uint8_t { kIdle, kPreparing, kSubmitted };
struct TahoeP2PStationLease {
    uint8_t stationId=0; uint32_t generation=0;
    TahoeP2PResourceState state=TahoeP2PResourceState::kAbsent;
    TahoeP2PStationRole role=TahoeP2PStationRole::kDirectedPeerLink;
    uint8_t address[6]{}; uint32_t macIdAndColor=0;
    uint8_t stationType=0, addCommandVersion=0, addNotificationVersion=0;
};
struct QueueSnapshot { uint32_t outstandingTx=0; };
struct FakeQueueLifecycle {
    QueueSnapshot snapshot() const { return {}; }
};
struct TahoeP2PTxQueueLease {
    uint8_t stationId=0; uint16_t queueId=0xffff; uint32_t generation=0;
    TahoeP2PResourceState state=TahoeP2PResourceState::kAbsent;
    TahoeP2PStationRole stationRole=TahoeP2PStationRole::kDirectedPeerLink;
    uint8_t firmwareTid=0, peerAddress[6]{}; uint32_t macIdAndColor=0;
    IOSimpleLock *stateLock=nullptr; bool submissionBusy=false;
    bool everDoorbelled=false; void *pendingRing=nullptr;
    void *retainedRing=nullptr; FakeQueueLifecycle lifecycle;
};
namespace IntelP2PTx {
enum class Result { kSuccess, kBusy, kNoCapacity, kInvalid, kStale };
class StationRegistry {
public:
    Result reserveP2p(uint32_t generation, uint8_t *id) {
        if (!id || generation != generation_) return Result::kStale;
        for (uint8_t candidate=3; candidate<32; ++candidate)
            if (owners_[candidate] == 0) {
                owners_[candidate]=1; *id=candidate; return Result::kSuccess;
            }
        return Result::kNoCapacity;
    }
    Result addAcknowledged(uint32_t generation,uint8_t id) {
        return change(generation,id,1,2);
    }
    Result addOutcomeUnknown(uint32_t generation,uint8_t id) {
        return change(generation,id,1,3);
    }
    Result removeAcknowledged(uint32_t generation,uint8_t id) {
        return change(generation,id,2,0);
    }
    Result releaseKnownAbsent(uint32_t generation,uint8_t id) {
        return change(generation,id,1,0);
    }
private:
    Result change(uint32_t generation,uint8_t id,uint8_t expected,uint8_t next) {
        if (generation != generation_ || id >= 32 || owners_[id] != expected)
            return Result::kInvalid;
        owners_[id]=next; return Result::kSuccess;
    }
    uint32_t generation_=7; uint8_t owners_[32]{};
};
}
struct ieee80211_channel { uint16_t channel=0; };
struct ieee80211_node { uint8_t ni_macaddr[6]{}; };
struct ieee80211com {
    uint8_t ic_myaddr[6]{2,0,0,0,0,1};
    ieee80211_node *ic_bss=nullptr;
    ieee80211_channel ic_channels[16]{};
};
struct iwx_p2p_context {
    uint8_t mac_state=IWX_P2P_RESOURCE_ACTIVE;
    uint8_t binding_state=IWX_P2P_RESOURCE_ABSENT;
    uint8_t phy_leased=0; uint8_t mac_id=1, mac_color=0;
    uint8_t mac_address[6]{2,0,0,0,0,3};
};
struct iwx_p2p_roc_state {
    uint32_t token=0, fw_generation=0; int32_t session_submit_result=0;
    uint8_t phase=0, session_conf_id=0, session_submit_seen=0;
};
struct iwx_softc {
    uint32_t sc_generation=7, sc_tx_rate_generation=9;
    ieee80211com sc_ic{}; iwx_p2p_context sc_p2p{};
    iwx_p2p_roc_state sc_p2p_roc{};
};
struct TicketSnapshot { bool armed=false, completed=false; };
struct FakeCompletion {
    TicketSnapshot current{};
    TicketSnapshot snapshot() const { return current; }
};
struct FakeActionContext {
    TahoeP2PActionTxState state=TahoeP2PActionTxState::kIdle;
    FakeCompletion completion;
};
struct P2PTxDiagnosticSnapshot {
    uint32_t outstandingTx=0, actionState=0;
    bool ticketArmed=false, ticketCompleted=false, queueDoorbelled=false;
};
struct IOEthernetController {
    std::map<std::string,uint32_t> properties;
    bool setProperty(const char *name,uint32_t value,unsigned) {
        properties[name]=value; return true;
    }
    uint32_t property(const char *name) const {
        auto it=properties.find(name); return it==properties.end()?UINT32_MAX:it->second;
    }
};
using GateAction = IOReturn (*)(OSObject *,void *,void *,void *,void *);
struct IOCommandGate {
    IOReturn runAction(GateAction action,void *opaque) {
        return action(nullptr,opaque,nullptr,nullptr,nullptr);
    }
};
struct ItlIwx;
struct P2PProbeRun {
    ItlIwx *owner=nullptr; thread_t workerThread=nullptr;
    bool directedPrepareOnly=true; uint8_t directedPeerMac[6]{};
    char directedRunToken[33]{}; uint32_t contextGeneration=7;
    uint32_t powerGeneration=7, stationGeneration=9;
};
struct DirectedNoTicketProof {
    P2PProbeRun *probe; bool snapshotValid; bool neverArmed;
};
struct ItlIwx {
    iwx_softc com{}; IOEthernetController controller{}; IOCommandGate gate{};
    IOSimpleLock *nativeP2pTxLock_=IOSimpleLockAlloc();
    IntelP2PTx::StationRegistry nativeP2pStationRegistry_{};
    TahoeP2PStationLease nativeP2pStation_{};
    TahoeP2PTxQueueLease nativeP2pTxQueue_{};
    FakeActionContext nativeP2pActionTx_{};
    uint32_t nativeP2pDirectedPrepareArmed_=1;
    uint8_t nativeP2pDirectedPreparePeer_[6]{2,0,0,0,0,4};
    char nativeP2pDirectedPrepareRunToken_[33]="0123456789abcdef0123456789abcdef";
    void *nativeP2pProbeOwner_=nullptr; uint32_t nativeP2pProbeGeneration_=7;
    uint32_t nativeP2pRocChannel_=0, nativeP2pRocDurationMs_=0;
    bool allowed=true, mainGate=true, busy=true;
    int prepareResult=0, addResult=0, queueResult=0, idleCleanupResult=0;
    bool addUnknown=false, queueUnknown=false;
    unsigned prepareCalls=0, addCalls=0, queueCalls=0, idleCleanupCalls=0,
             abortUnsubmittedCalls=0, removeStationCalls=0, abortPreparedCalls=0,
             sessionSubmitCalls=0, doorbellCalls=0;
    std::vector<std::string> events;
    ItlIwx() {
        com.sc_ic.ic_bss=new ieee80211_node{};
        const uint8_t bss[6]={2,0,0,0,0,2};
        std::memcpy(com.sc_ic.ic_bss->ni_macaddr,bss,6);
        com.sc_ic.ic_channels[6].channel=6;
    }
    ~ItlIwx() { delete com.sc_ic.ic_bss; delete nativeP2pTxLock_; }
    bool nativeP2pCommandAllowed() const { return allowed; }
    bool tahoeP2pOnMainGate() const { return mainGate; }
    bool nativeP2pBusy() const { return busy; }
    IOCommandGate *tahoeP2pCommandGate() { return &gate; }
    IOEthernetController *tahoeP2pController() { return &controller; }
    int tahoeP2pRocPrepare(iwx_softc *sc,ieee80211_channel *channel,
                           uint32_t generation,uint32_t configuration);
    int tahoeP2pRocAbortPrepared(iwx_softc *sc,uint32_t generation,
                                 uint32_t configuration,bool noSession);
};
static bool captureP2PTxSnapshot(ItlIwx *owner,P2PTxDiagnosticSnapshot *out) {
    if (!owner || !out || !owner->mainGate) return false;
    out->ticketArmed=owner->nativeP2pActionTx_.completion.current.armed;
    out->ticketCompleted=owner->nativeP2pActionTx_.completion.current.completed;
    out->queueDoorbelled=owner->nativeP2pTxQueue_.everDoorbelled;
    out->actionState=static_cast<uint32_t>(owner->nativeP2pActionTx_.state);
    out->outstandingTx=0; return true;
}
static void publishP2PTxSetup(ItlIwx *owner,uint32_t stage,int error) {
    owner->controller.setProperty("NativeP2PTxSetupStage",stage,32);
    owner->controller.setProperty("NativeP2PTxSetupResult",static_cast<uint32_t>(error),32);
}
static int iwx_tahoe_p2p_add_directed_peer_station(
    ItlIwx *,iwx_softc *,TahoeP2PStationLease *,uint8_t,const uint8_t[6],bool *);
static int iwx_tahoe_p2p_remove_directed_peer_station(
    ItlIwx *,iwx_softc *,TahoeP2PStationLease *,TahoeP2PTxQueueLease *,bool *);
static int iwx_tahoe_p2p_tvqm_allocate(
    ItlIwx *,iwx_softc *,TahoeP2PTxQueueLease *,const TahoeP2PStationLease *,
    uint32_t,uint16_t *,bool *,TahoeP2PQueueUse);
static int iwx_tahoe_p2p_tvqm_abort_unsubmitted(
    ItlIwx *,iwx_softc *,TahoeP2PStationLease *,TahoeP2PTxQueueLease *,bool *);
static int iwx_tahoe_p2p_tvqm_abort_idle_no_session(
    ItlIwx *,iwx_softc *,TahoeP2PStationLease *,TahoeP2PTxQueueLease *,
    bool,bool,bool *);
'''

TRANSPORT = r'''
int ItlIwx::tahoeP2pRocPrepare(iwx_softc *sc,ieee80211_channel *channel,
                               uint32_t generation,uint32_t configuration) {
    ++prepareCalls; events.push_back("ROC_PREPARE");
    assert(sc==&com && generation==7 && configuration==3);
    assert(channel==&sc->sc_ic.ic_channels[6] && channel->channel==6);
    assert(sc->sc_p2p.mac_state==IWX_P2P_RESOURCE_ACTIVE);
    assert(sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT);
    assert(sc->sc_p2p.phy_leased==0);
    if (prepareResult) return prepareResult; // Refusal leaves no owned resource.
    events.push_back("PHY_CONTEXT_ADD");
    sc->sc_p2p.phy_leased=1;
    events.push_back("BINDING_ADD");
    sc->sc_p2p.binding_state=IWX_P2P_RESOURCE_ACTIVE;
    sc->sc_p2p_roc.phase=IWX_P2P_ROC_PREPARED;
    sc->sc_p2p_roc.token=generation;
    sc->sc_p2p_roc.fw_generation=generation;
    sc->sc_p2p_roc.session_conf_id=static_cast<uint8_t>(configuration);
    sc->sc_p2p_roc.session_submit_result=EINPROGRESS;
    return 0;
}
int ItlIwx::tahoeP2pRocAbortPrepared(iwx_softc *sc,uint32_t generation,
                                     uint32_t configuration,bool noSession) {
    ++abortPreparedCalls; events.push_back("ROC_ABORT_PREPARED");
    assert(sc==&com && generation==7 && configuration==3 && noSession);
    assert(sc->sc_p2p_roc.session_submit_seen==0 && sessionSubmitCalls==0);
    assert(nativeP2pStation_.state==TahoeP2PResourceState::kAbsent);
    assert(nativeP2pTxQueue_.state==TahoeP2PResourceState::kAbsent);
    assert(!nativeP2pTxQueue_.everDoorbelled && doorbellCalls==0);
    events.push_back("BINDING_REMOVE");
    sc->sc_p2p.binding_state=IWX_P2P_RESOURCE_ABSENT;
    events.push_back("PHY_CONTEXT_REMOVE");
    sc->sc_p2p.phy_leased=0; sc->sc_p2p_roc.phase=IWX_P2P_ROC_IDLE;
    sc->sc_p2p_roc.token=0; sc->sc_p2p_roc.fw_generation=0;
    sc->sc_p2p_roc.session_conf_id=0; sc->sc_p2p_roc.session_submit_result=0;
    return 0;
}
static int iwx_tahoe_p2p_add_directed_peer_station(
    ItlIwx *owner,iwx_softc *sc,TahoeP2PStationLease *lease,uint8_t id,
    const uint8_t peer[6],bool *mayExist) {
    ++owner->addCalls; owner->events.push_back("ADD_STA_LINK");
    assert(sc==&owner->com && sc->sc_p2p.binding_state==IWX_P2P_RESOURCE_ACTIVE);
    assert(sc->sc_p2p.phy_leased && id>=3 && peer);
    *mayExist=owner->addUnknown;
    if (owner->addResult) {
        if (owner->addUnknown) {
            lease->stationId=id; lease->generation=7;
            lease->state=TahoeP2PResourceState::kUnknown;
            lease->role=TahoeP2PStationRole::kDirectedPeerLink;
            std::memcpy(lease->address,peer,6);
        }
        return owner->addResult;
    }
    lease->stationId=id; lease->generation=7;
    lease->state=TahoeP2PResourceState::kActive;
    lease->role=TahoeP2PStationRole::kDirectedPeerLink;
    lease->stationType=0; lease->addCommandVersion=12;
    lease->addNotificationVersion=2; lease->macIdAndColor=1;
    std::memcpy(lease->address,peer,6); *mayExist=false; return 0;
}
static int iwx_tahoe_p2p_remove_directed_peer_station(
    ItlIwx *owner,iwx_softc *,TahoeP2PStationLease *station,
    TahoeP2PTxQueueLease *,bool *mayExist) {
    ++owner->removeStationCalls; owner->events.push_back("REMOVE_STA_REJECTED_ADD");
    if (owner->idleCleanupResult) { *mayExist=true; return owner->idleCleanupResult; }
    station->state=TahoeP2PResourceState::kAbsent; *mayExist=false; return 0;
}
static int iwx_tahoe_p2p_tvqm_allocate(
    ItlIwx *owner,iwx_softc *,TahoeP2PTxQueueLease *queue,
    const TahoeP2PStationLease *station,uint32_t,uint16_t *queueId,
    bool *mayExist,TahoeP2PQueueUse use) {
    ++owner->queueCalls; owner->events.push_back("SCD_QUEUE_CFG_TID0");
    assert(use==TahoeP2PQueueUse::kDirectedNonQosDataTid0);
    assert(station->state==TahoeP2PResourceState::kActive);
    assert(queue->firmwareTid==0 && queue->stationId==station->stationId);
    *mayExist=owner->queueUnknown;
    if (owner->queueResult) {
        if (owner->queueUnknown) queue->state=TahoeP2PResourceState::kPending;
        return owner->queueResult;
    }
    *queueId=5; queue->queueId=5; queue->generation=7;
    queue->state=TahoeP2PResourceState::kActive; *mayExist=false; return 0;
}
static int iwx_tahoe_p2p_tvqm_abort_unsubmitted(
    ItlIwx *owner,iwx_softc *,TahoeP2PStationLease *,
    TahoeP2PTxQueueLease *,bool *mayExist) {
    ++owner->abortUnsubmittedCalls; owner->events.push_back("ABORT_UNSUBMITTED");
    *mayExist=true; return ETIMEDOUT;
}
static int iwx_tahoe_p2p_tvqm_abort_idle_no_session(
    ItlIwx *owner,iwx_softc *sc,TahoeP2PStationLease *station,
    TahoeP2PTxQueueLease *queue,bool rocNeverSubmitted,
    bool ticketNeverArmed,bool *mayExist) {
    ++owner->idleCleanupCalls; owner->events.push_back("STRICT_NO_SESSION_CLEANUP");
    assert(sc==&owner->com && rocNeverSubmitted && ticketNeverArmed);
    assert(station->role==TahoeP2PStationRole::kDirectedPeerLink);
    assert(queue->stationRole==station->role && queue->firmwareTid==0);
    assert(queue->state==TahoeP2PResourceState::kActive);
    assert(!queue->everDoorbelled && !owner->nativeP2pActionTx_.completion.current.armed);
    owner->events.push_back("TXPATH_FLUSH");
    if (owner->idleCleanupResult) {
        station->state=TahoeP2PResourceState::kUnknown;
        queue->state=TahoeP2PResourceState::kUnknown; *mayExist=true;
        return owner->idleCleanupResult;
    }
    owner->events.push_back("REMOVE_STA");
    queue->state=TahoeP2PResourceState::kAbsent; queue->queueId=0xffff;
    station->state=TahoeP2PResourceState::kAbsent; *mayExist=false; return 0;
}
'''

BODY = r'''
static P2PProbeRun makeRun(ItlIwx &owner) {
    P2PProbeRun run{}; run.owner=&owner; run.workerThread=reinterpret_cast<void*>(0x105);
    run.directedPrepareOnly=true; run.contextGeneration=7;
    run.powerGeneration=7; run.stationGeneration=9;
    const uint8_t peer[6]={2,0,0,0,0,4};
    const char token[33]="0123456789abcdef0123456789abcdef";
    std::memcpy(run.directedPeerMac,peer,6); std::memcpy(run.directedRunToken,token,33);
    owner.nativeP2pProbeOwner_=run.workerThread;
    owner.nativeP2pProbeGeneration_=7;
    std::memcpy(owner.nativeP2pDirectedPreparePeer_,peer,6);
    std::memcpy(owner.nativeP2pDirectedPrepareRunToken_,token,33);
    return run;
}
static void assertNoDataTransmit(const ItlIwx &owner) {
    assert(owner.sessionSubmitCalls==0 && owner.doorbellCalls==0);
    assert(owner.com.sc_p2p_roc.session_submit_seen==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareDoorbellIssued")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareSessionSubmitted")==0);
}
static void successCase() {
    ItlIwx owner; auto run=makeRun(owner);
    assert(owner.com.sc_p2p.mac_state==IWX_P2P_RESOURCE_ACTIVE);
    assert(owner.com.sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT);
    assert(owner.com.sc_p2p.phy_leased==0);
    assert(exerciseDirectedPrepare(&run)==0);
    const std::vector<std::string> expected={
        "ROC_PREPARE","PHY_CONTEXT_ADD","BINDING_ADD","ADD_STA_LINK",
        "SCD_QUEUE_CFG_TID0","STRICT_NO_SESSION_CLEANUP","TXPATH_FLUSH",
        "REMOVE_STA","ROC_ABORT_PREPARED","BINDING_REMOVE","PHY_CONTEXT_REMOVE"};
    assert(owner.events==expected);
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==5);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareStationAck")==1);
    assert(owner.controller.property("NativeP2PDirectedPrepareQueueAck")==1);
    assert(owner.controller.property("NativeP2PDirectedPrepareCleanupAck")==1);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==1);
    assert(owner.nativeP2pStation_.state==TahoeP2PResourceState::kAbsent);
    assert(owner.nativeP2pTxQueue_.state==TahoeP2PResourceState::kAbsent);
    assert(owner.com.sc_p2p.binding_state==IWX_P2P_RESOURCE_ABSENT);
    assert(owner.com.sc_p2p.phy_leased==0 && owner.nativeP2pRocDurationMs_==0);
    assertNoDataTransmit(owner);
}
static void prepareRefusalCase() {
    ItlIwx owner; auto run=makeRun(owner); owner.prepareResult=EOPNOTSUPP;
    assert(exerciseDirectedPrepare(&run)==0); // Clean refusal lets outer MAC teardown proceed.
    assert((owner.events==std::vector<std::string>{"ROC_PREPARE"}));
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==EOPNOTSUPP);
    assert(owner.controller.property("NativeP2PDirectedPrepareStationAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareQueueAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==1);
    assertNoDataTransmit(owner);
}
static void knownAddRejectCase() {
    ItlIwx owner; auto run=makeRun(owner); owner.addResult=EIO;
    assert(exerciseDirectedPrepare(&run)==0); // Clean rollback, prepare still failed.
    assert(owner.events==std::vector<std::string>({"ROC_PREPARE","PHY_CONTEXT_ADD",
        "BINDING_ADD","ADD_STA_LINK","ROC_ABORT_PREPARED","BINDING_REMOVE",
        "PHY_CONTEXT_REMOVE"}));
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==EIO);
    assert(owner.controller.property("NativeP2PDirectedPrepareStationAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareQueueAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareCleanupAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==1);
    assert(owner.nativeP2pStation_.state==TahoeP2PResourceState::kAbsent);
    assertNoDataTransmit(owner);
}
static void unknownAddRetainsCase() {
    ItlIwx owner; auto run=makeRun(owner); owner.addResult=ETIMEDOUT; owner.addUnknown=true;
    assert(exerciseDirectedPrepare(&run)==ETIMEDOUT);
    assert(owner.events==std::vector<std::string>({"ROC_PREPARE","PHY_CONTEXT_ADD",
        "BINDING_ADD","ADD_STA_LINK"}));
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==ETIMEDOUT);
    assert(owner.controller.property("NativeP2PDirectedPrepareStationAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareQueueAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==0);
    assert(owner.nativeP2pStation_.state==TahoeP2PResourceState::kUnknown);
    assert(owner.com.sc_p2p.binding_state==IWX_P2P_RESOURCE_ACTIVE && owner.com.sc_p2p.phy_leased);
    assertNoDataTransmit(owner);
}
static void queueRejectCleanupCase() {
    ItlIwx owner; auto run=makeRun(owner); owner.queueResult=EINVAL;
    assert(exerciseDirectedPrepare(&run)==0); // Safe rollback; stage 6 preserves failure.
    assert(owner.events==std::vector<std::string>({"ROC_PREPARE","PHY_CONTEXT_ADD",
        "BINDING_ADD","ADD_STA_LINK","SCD_QUEUE_CFG_TID0",
        "REMOVE_STA_REJECTED_ADD","ROC_ABORT_PREPARED","BINDING_REMOVE",
        "PHY_CONTEXT_REMOVE"}));
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==EINVAL);
    assert(owner.controller.property("NativeP2PDirectedPrepareStationAck")==1);
    assert(owner.controller.property("NativeP2PDirectedPrepareQueueAck")==0);
    assert(owner.controller.property("NativeP2PDirectedPrepareCleanupAck")==1);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==1);
    assertNoDataTransmit(owner);
}
static void strictCleanupUnknownRetainsCase() {
    ItlIwx owner; auto run=makeRun(owner); owner.idleCleanupResult=ETIMEDOUT;
    assert(exerciseDirectedPrepare(&run)==ETIMEDOUT);
    assert(owner.events==std::vector<std::string>({"ROC_PREPARE","PHY_CONTEXT_ADD",
        "BINDING_ADD","ADD_STA_LINK","SCD_QUEUE_CFG_TID0",
        "STRICT_NO_SESSION_CLEANUP","TXPATH_FLUSH"}));
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==ETIMEDOUT);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==0);
    assert(owner.nativeP2pStation_.state==TahoeP2PResourceState::kUnknown);
    assert(owner.nativeP2pTxQueue_.state==TahoeP2PResourceState::kUnknown);
    assert(owner.com.sc_p2p.binding_state==IWX_P2P_RESOURCE_ACTIVE && owner.com.sc_p2p.phy_leased);
    assert(owner.abortPreparedCalls==0);
    assertNoDataTransmit(owner);
}
static void queueUnknownRetainsCase() {
    ItlIwx owner; auto run=makeRun(owner); owner.queueResult=ETIMEDOUT; owner.queueUnknown=true;
    assert(exerciseDirectedPrepare(&run)==ETIMEDOUT);
    assert(owner.abortUnsubmittedCalls==1 && owner.abortPreparedCalls==0);
    assert(owner.nativeP2pTxQueue_.state==TahoeP2PResourceState::kPending);
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==0);
    assertNoDataTransmit(owner);
}
static void invalidPeerNoCommandsCase() {
    ItlIwx owner; auto run=makeRun(owner); run.directedPeerMac[0]=1;
    assert(exerciseDirectedPrepare(&run)==EINVAL);
    assert(owner.events.empty());
    assert(owner.controller.property("NativeP2PDirectedPrepareStage")==6);
    assert(owner.controller.property("NativeP2PDirectedPrepareResult")==EINVAL);
    assert(owner.controller.property("NativeP2PDirectedPrepareResourcesAbsent")==0);
    assertNoDataTransmit(owner);
}
int main() {
    successCase(); prepareRefusalCase(); knownAddRejectCase(); unknownAddRetainsCase();
    queueRejectCleanupCase(); strictCleanupUnknownRetainsCase();
    queueUnknownRetainsCase(); invalidPeerNoCommandsCase();
}
'''

FAKE = r'''
'''

with tempfile.TemporaryDirectory(prefix="test105-directed-worker-") as temporary:
    cpp = Path(temporary) / "worker.cpp"
    cpp.write_text(SHIM + "\n" + FAKE + "\n" + PRODUCTION + "\n" +
                   TRANSPORT + "\n" + BODY)
    executable = Path(temporary) / "worker"
    subprocess.run([
        "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-function", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", str(cpp), "-o", str(executable)
    ], check=True)
    subprocess.run([str(executable)], check=True)
