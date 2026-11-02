// SPDX-License-Identifier: GPL-2.0-only
// Portable host-only regressions. The runner extracts the actual HAL getter;
// its surrounding HAL evidence and the KPI/clock are explicit test doubles.
#include "test104_rx149_hal_fixture.hpp"
#include <chrono>

namespace B=NativeAwdlBSD;
namespace P=NativeP2PRx149DataInput;
namespace D=NativeAwdlBSD::Rx149CaptureDiagnostics;

static FakeIf *expectedInputIf=nullptr;
static std::atomic<bool> inputEntered{false},inputReleased{false};
static FakeIf replacementIf;

static void inspectInput(ifnet_t dev,mbuf_t packet) {
    assert(dev==expectedInputIf&&packet->receiveIf==dev);
    assert(B::lock->mutex.try_lock()); // KPI must execute outside the bridge lock.
    assert(B::inputCalls>=2);
    assert(B::Rx149InputGateState::ticketCount(B::rx149InputGateState)==1);
    B::lock->mutex.unlock();
}
static void blockInput(ifnet_t dev,mbuf_t packet) {
    inspectInput(dev,packet);
    inputEntered.store(true,std::memory_order_release);
    const auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(!inputReleased.load(std::memory_order_acquire)) {
        assert(std::chrono::steady_clock::now()<limit);
        std::this_thread::yield();
    }
}
static void waitInput() {
    const auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(!inputEntered.load(std::memory_order_acquire)) {
        assert(std::chrono::steady_clock::now()<limit);
        std::this_thread::yield();
    }
}
static void expireAtPublish(B::Rx149TestHookPoint point) {
    if(point==B::Rx149TestHookPoint::LeaseAuthorization) {
        fakeTime=101000;
        B::setRx149TestHookForTests(nullptr);
    }
}
static void faultAtPublish(B::Rx149TestHookPoint point) {
    if(point==B::Rx149TestHookPoint::LeaseAuthorization) {
        B::invalidateRx149DataInputFast();
        B::setRx149TestHookForTests(nullptr);
    }
}
static void closeLatchBeforeTicket(B::Rx149TestHookPoint point) {
    if(point==B::Rx149TestHookPoint::InputTicketAuthorization) {
        // Same release latch that publishClosing stores before taking lock.
        __atomic_store_n(&B::closingRequested,1u,__ATOMIC_RELEASE);
        B::setRx149TestHookForTests(nullptr);
    }
}
static void replaceIfBeforeTicket(B::Rx149TestHookPoint point) {
    if(point==B::Rx149TestHookPoint::InputTicketAuthorization) {
        B::interface=&replacementIf;
        B::setRx149TestHookForTests(nullptr);
    }
}
static void replaceIncarnationBeforeTicket(B::Rx149TestHookPoint point) {
    if(point==B::Rx149TestHookPoint::InputTicketAuthorization) {
        ++B::interfaceIncarnation;
        B::setRx149TestHookForTests(nullptr);
    }
}

static void flags(P::Lease &lease,unsigned mask) {
    bool *bits[]={&lease.compiled,&lease.runtimeEnabled,&lease.profileEnabled,
        &lease.profileSelected,&lease.receiveObservationOnly,&lease.leaseActive,
        &lease.ownerCurrent,&lease.epochsMatch,&lease.tokenMatches,
        &lease.commandReturned,&lease.commandSucceeded,
        &lease.deviceDiscoveryConfiguration,&lease.startSeen,
        &lease.startSucceeded,&lease.endSeen,&lease.outcomeUnknown};
    for(unsigned i=0;i<16;++i)*bits[i]=(mask&(1u<<i))!=0;
}
static void helperFlagMatrix() {
    auto lease=validLease();lease.startUs=0;
    for(unsigned mask=0;mask<65536;++mask) {
        flags(lease,mask);
        assert(P::waitingForFirstStart(lease)==(mask==0xfff));
        P::Permit permit{};
        assert(!P::makePermit(lease,validDescriptor(),&permit));
    }
    flags(lease,0xfff);
    lease.ownerSerial=0;assert(!P::waitingForFirstStart(lease));
    lease=validLease();flags(lease,0xfff);lease.startUs=0;
    lease.epochs.roc++;assert(!P::waitingForFirstStart(lease));
    lease=validLease();flags(lease,0xfff);
    assert(!P::waitingForFirstStart(lease)); // copied start timestamp is not pending.
}
static void finishClean() {
    fakeInputObserver()=nullptr;
    assert(B::close());
    assert(allocated==freed);
}
static void pendingThenStart() {
    FakeIf dev;prepare(dev);ItlIwx hal;hal.pending();P::Lease lease{};
    const auto before=B::snapshot();
    const auto head=B::rx.head,tail=B::rx.tail;
    for(unsigned i=0;i<100;++i) {
        assert(!hal.tahoeP2pRx149DataLease(&lease));
        assert(P::waitingForFirstStart(lease));
        assert(!B::activeRx149LeaseValid&&B::activeRx149Version==0);
        assert(B::rx149OwnerSerialHighWater==0&&B::rx.count==0);
        P::Permit permit{};assert(!P::makePermit(lease,validDescriptor(),&permit));
    }
    assert(B::rx.head==head&&B::rx.tail==tail);
    const auto after=B::snapshot();
    assert(!memcmp(before.value,after.value,sizeof(before.value)));
    assert(B::rx149ReceiptSequence==0&&B::rx149ReceiptContentRevision==0);
    hal.started();assert(hal.tahoeP2pRx149DataLease(&lease));
    assert(B::activeRx149LeaseValid&&B::activeRx149Version==1);
    assert(B::rx149OwnerSerialHighWater==lease.ownerSerial);
    expectedInputIf=&dev;fakeInputObserver()=inspectInput;
    (void)captureFrame(lease);B::poll(true,72,&lease);
    assert(delivered==1&&B::snapshot().value[B::RxDelivered]==1);
    finishClean();
}
static void rejectedFlag(unsigned bit) {
    FakeIf dev;prepare(dev);ItlIwx hal;hal.pending();
    switch(bit) {
        case 1:hal.controller.experiment=false;break;
        case 2:hal.controller.profile=false;break;
        case 3:hal.evidence.profileSelected=false;break;
        case 4:hal.evidence.receiveObservationOnly=false;break;
        case 5:hal.evidence.leaseActive=false;break;
        case 6:hal.evidence.ownerCurrent=false;break;
        case 7:hal.evidence.epochsMatch=false;break;
        case 8:hal.evidence.tokenMatches=false;break;
        case 9:hal.evidence.commandReturned=false;break;
        case 10:hal.evidence.commandSucceeded=false;break;
        case 11:hal.evidence.deviceDiscoveryConfiguration=false;break;
        case 12:hal.evidence.startSeen=true;break;
        case 13:hal.evidence.startSucceeded=true;break;
        case 14:hal.evidence.endSeen=true;break;
        case 15:hal.evidence.outcomeUnknown=true;break;
        default:assert(false);
    }
    P::Lease lease{};assert(!hal.tahoeP2pRx149DataLease(&lease));
    assert(B::rx149OwnerSerialHighWater==901&&!B::activeRx149LeaseValid);
    hal=ItlIwx{};hal.started();
    assert(!hal.tahoeP2pRx149DataLease(&lease)); // restoring flags cannot revive.
    finishClean();
}
static void terminalBeforeStart() {
    FakeIf dev;prepare(dev);ItlIwx hal;hal.pending();P::Lease lease{};
    const auto old=validLease();B::revokeRx149DataInput(old.ownerSerial,old.epochs);
    assert(!hal.tahoeP2pRx149DataLease(&lease));
    assert(B::rx149OwnerSerialHighWater==901&&B::activeRx149Version==1);
    hal.started();assert(!hal.tahoeP2pRx149DataLease(&lease));
    assert(captureFrameResult(old,nullptr)==B::CaptureResult::Rejected);
    B::poll(true,72,&old);assert(delivered==0);
    hal.nextOwner();assert(hal.tahoeP2pRx149DataLease(&lease));
    expectedInputIf=&dev;fakeInputObserver()=inspectInput;
    (void)captureFrame(lease);B::poll(true,72,&lease);assert(delivered==1);
    assert(!B::publishRx149DataInputLease(old));
    finishClean();
}
static void activeThenPending(bool newer) {
    FakeIf dev;prepare(dev);ItlIwx hal;P::Lease lease{};
    assert(hal.tahoeP2pRx149DataLease(&lease));(void)captureFrame(lease);
    if(newer)hal.nextOwner();
    hal.pending();assert(!hal.tahoeP2pRx149DataLease(&lease));
    assert(!B::activeRx149LeaseValid&&B::rx.count==0);
    assert(B::rx149OwnerSerialHighWater==(newer?902u:901u));
    hal.started();assert(!hal.tahoeP2pRx149DataLease(&lease));
    finishClean();
}
static void stalePendingCannotCloseNewer() {
    FakeIf dev;prepare(dev);ItlIwx newer;newer.nextOwner();P::Lease lease{};
    assert(newer.tahoeP2pRx149DataLease(&lease));
    ItlIwx stale;stale.pending();P::Lease old{};
    assert(!stale.tahoeP2pRx149DataLease(&old));
    assert(B::activeRx149LeaseValid&&B::activeRx149Lease.ownerSerial==902);
    assert(newer.tahoeP2pRx149DataLease(&lease));
    expectedInputIf=&dev;fakeInputObserver()=inspectInput;
    (void)captureFrame(lease);B::poll(true,72,&lease);assert(delivered==1);
    finishClean();
}
static void publishRace(bool fault) {
    FakeIf dev;prepare(dev);ItlIwx hal;P::Lease lease{};
    B::setRx149TestHookForTests(fault?faultAtPublish:expireAtPublish);
    assert(!hal.tahoeP2pRx149DataLease(&lease));
    assert(!B::activeRx149LeaseValid&&B::rx.count==0);
    if(fault)assert(B::rx149DataInputBlocked());
    else assert(B::rx149OwnerSerialHighWater==901);
    assert(delivered==0);finishClean();
}
static void pendingBridgeFailure(const std::string &kind) {
    FakeIf dev;prepare(dev);ItlIwx hal;hal.pending();P::Lease lease{};
    if(kind=="interface")B::interface=nullptr;
    else if(kind=="incarnation")B::interfaceIncarnation=0;
    else if(kind=="closing")B::closing=true;
    else if(kind=="detached")B::detached=true;
    else if(kind=="radio")B::radio=false;
    else if(kind=="generation")B::radioGeneration=73;
    else if(kind=="close_latch")B::closingRequested=1;
    else if(kind=="attached")B::counters[B::Attached]=0;
    else if(kind=="fault")B::invalidateRx149DataInputFast();
    else if(kind=="exhausted")B::activeRx149Version=UINT64_MAX;
    else assert(false);
    assert(!hal.tahoeP2pRx149DataLease(&lease));
    assert(!B::activeRx149LeaseValid&&B::rx149OwnerSerialHighWater==901);
    if(kind=="interface")B::interface=&dev;
    assert(delivered==0);finishClean();
}
static void ticketBindingRace(const std::string &kind) {
    FakeIf dev;prepare(dev);ItlIwx hal;P::Lease lease{};
    assert(hal.tahoeP2pRx149DataLease(&lease));(void)captureFrame(lease);
    if(kind=="interface")B::setRx149TestHookForTests(replaceIfBeforeTicket);
    else if(kind=="incarnation")B::setRx149TestHookForTests(replaceIncarnationBeforeTicket);
    else B::setRx149TestHookForTests(closeLatchBeforeTicket);
    B::poll(true,72,&lease);
    assert(delivered==0&&allocated==freed);
    assert(B::Rx149InputGateState::ticketCount(B::rx149InputGateState)==0);
    assert(B::snapshot().rx149Input.disposition==B::Rx149ReceiptStaleOrInvalid);
    if(kind=="interface")B::interface=&dev;
    finishClean();
}
static void closeAfterTicket() {
    FakeIf dev;prepare(dev);ItlIwx hal;P::Lease lease{};
    assert(hal.tahoeP2pRx149DataLease(&lease));(void)captureFrame(lease);
    expectedInputIf=&dev;fakeInputObserver()=blockInput;
    std::thread worker([&]{B::poll(true,72,&lease);});waitInput();
    assert(!B::close()); // bounded host shim wait expires while input is pinned.
    assert(dev.refs==1&&B::interface==&dev);
    assert(B::Rx149InputGateState::ticketCount(B::rx149InputGateState)==1);
    P::Lease stale{};assert(!hal.tahoeP2pRx149DataLease(&stale));
    inputReleased.store(true,std::memory_order_release);worker.join();
    assert(delivered==1); // a previously issued ticket may finish.
    assert(B::inputCalls==0&&B::Rx149InputGateState::ticketCount(B::rx149InputGateState)==0);
    finishClean();assert(dev.refs==0);
}
static void linkAddressBinding() {
    FakeIf dev;prepare(dev);uint8_t actual[6]{};
    assert(B::address(72,actual)&&!memcmp(actual,dev.lladdr,6));
    dev.lladdr[5]^=1;assert(!B::address(72,actual));dev.lladdr[5]^=1;
    assert(!B::address(73,actual));lladdrFail=true;assert(!B::address(72,actual));
    lladdrFail=false;assert(B::address(72,actual));finishClean();
}
static void pendingVersusRevoke() {
    FakeIf dev;prepare(dev);ItlIwx hal;hal.pending();
    std::atomic<bool> start{false};
    std::thread reader([&] {
        while(!start.load(std::memory_order_acquire))std::this_thread::yield();
        for(unsigned i=0;i<10000;++i) {
            P::Lease lease{};assert(!hal.tahoeP2pRx149DataLease(&lease));
        }
    });
    std::thread revoker([&] {
        while(!start.load(std::memory_order_acquire))std::this_thread::yield();
        const auto lease=validLease();
        B::revokeRx149DataInput(lease.ownerSerial,lease.epochs);
    });
    start.store(true,std::memory_order_release);reader.join();revoker.join();
    assert(B::rx149OwnerSerialHighWater==901&&!B::activeRx149LeaseValid);
    hal.started();P::Lease lease{};assert(!hal.tahoeP2pRx149DataLease(&lease));
    finishClean();
}

int main(int argc,char **argv) {
    assert(argc==2);const std::string name=argv[1];
    if(name=="flag_matrix")helperFlagMatrix();
    else if(name=="pending_then_start")pendingThenStart();
    else if(name.rfind("flag_",0)==0)rejectedFlag(unsigned(atoi(name.c_str()+5)));
    else if(name=="terminal_before_start")terminalBeforeStart();
    else if(name=="active_same_pending")activeThenPending(false);
    else if(name=="active_old_pending_new")activeThenPending(true);
    else if(name=="stale_pending_newer_active")stalePendingCannotCloseNewer();
    else if(name=="publish_expires_under_lock")publishRace(false);
    else if(name=="publish_fault_under_lock")publishRace(true);
    else if(name.rfind("bridge_",0)==0)pendingBridgeFailure(name.substr(7));
    else if(name.rfind("ticket_",0)==0)ticketBindingRace(name.substr(7));
    else if(name=="close_after_ticket")closeAfterTicket();
    else if(name=="address_binding")linkAddressBinding();
    else if(name=="pending_vs_revoke")pendingVersusRevoke();
    else if(name=="no_bridge") {ItlIwx hal;P::Lease lease{};assert(!hal.tahoeP2pRx149DataLease(&lease));}
    else if(name=="off_main_gate") {ItlIwx hal;hal.inMainGate=false;P::Lease lease{};assert(!hal.tahoeP2pRx149DataLease(&lease));}
    else if(name=="publish_version_exhausted") {
        FakeIf dev;prepare(dev);B::activeRx149Version=UINT64_MAX;
        ItlIwx hal;P::Lease lease{};assert(!hal.tahoeP2pRx149DataLease(&lease));finishClean();
    }
    else assert(false);
    printf("{\"case\":\"%s\",\"passed\":true,\"host_only\":true}\n",name.c_str());
    return 0;
}
