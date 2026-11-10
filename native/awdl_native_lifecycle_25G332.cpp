// SPDX-License-Identifier: GPL-2.0-only
// Exact-build, single manually armed lifecycle transaction. Packet callbacks
// accept no traffic. A BSD interface appearing here is not an AWDL data path.
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
#include "awdl_native_lifecycle_25G332.hpp"
#include "awdl_native_concrete_25G332.hpp"
#include "awdl_lifecycle_transaction.hpp"
#include "awdl_unpublished_cleanup.hpp"
#include "runtime_guard.hpp"
#include <Airport/apple80211_ioctl.h>
#include <Airport/apple80211_var.h>
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "awdl_native_bsd_data_25G332.hpp"
#endif
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLib.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <net/kpi_interface.h>
#include <string.h>

// Nonvirtual native factories, reconstructed from exact exported symbols and
// this build's bodies. Opaque pointers never use guessed native vtable slots.
class IOSkywalkTxSubmissionQueue;
class IOSkywalkRxCompletionQueue;
class IOSkywalkPacket;
struct PoolOptions25 { uint32_t packets, buffers, bytes, buffersPerPacket, segmentBytes, flags; uint64_t reserved; };
static_assert(sizeof(PoolOptions25)==32, "Pool options ABI");
using TxAction25=uint32_t (*)(OSObject *, IOSkywalkTxSubmissionQueue *, IOSkywalkPacket *const *, uint32_t, void *);
using RxAction25=uint32_t (*)(OSObject *, IOSkywalkRxCompletionQueue *, IOSkywalkPacket **, uint32_t, void *);
extern "C" IOSkywalkPacketBufferPool *poolWithName25(const char *, OSObject *, uint32_t, const PoolOptions25 *)
 __asm__("__ZN25IOSkywalkPacketBufferPool8withNameEPKcP8OSObjectjPKNS_11PoolOptionsE");
extern "C" IOSkywalkTxSubmissionQueue *txWithPool25(IOSkywalkPacketBufferPool *, uint32_t, uint32_t, OSObject *, TxAction25, void *, uint32_t)
 __asm__("__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PKP15IOSkywalkPacketjPvES9_j");
extern "C" IOSkywalkRxCompletionQueue *rxWithPool25(IOSkywalkPacketBufferPool *, uint32_t, uint32_t, OSObject *, RxAction25, void *, uint32_t)
 __asm__("__ZN26IOSkywalkRxCompletionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PP15IOSkywalkPacketjPvES8_j");
extern "C" IOReturn registerEthernet25(IOSkywalkEthernetInterface *, const IOSkywalkEthernetInterface::RegistrationInfo *, IOSkywalkPacketQueue **, uint32_t, IOSkywalkPacketBufferPool *, IOSkywalkPacketBufferPool *, uint32_t)
 __asm__("__ZN26IOSkywalkEthernetInterface25registerEthernetInterfaceEPKNS_16RegistrationInfoEPP20IOSkywalkPacketQueuejP25IOSkywalkPacketBufferPoolS7_j");
extern "C" IOReturn deregisterEthernet25(IOSkywalkEthernetInterface *, uint32_t)
 __asm__("__ZN26IOSkywalkEthernetInterface27deregisterEthernetInterfaceEj");
extern "C" IO80211VirtualInterface *getAwdl25(IOService *)
 __asm__("__ZN17IO80211Controller16getAwdlInterfaceEv");
extern "C" void setAwdl25(IOService *, IO80211VirtualInterface *)
 __asm__("__ZN17IO80211Controller16setAwdlInterfaceEP23IO80211VirtualInterface");
// Apple XNU kpi_interface.h: Wi-Fi subfamily plus IFEF_AWDL identifies AWDL;
// a BSD name alone does not. This exported KPI is also used by native IO80211.
extern "C" errno_t ifnet_set_eflags(ifnet_t,uint32_t,uint32_t);
extern "C" uint32_t ifnet_eflags(ifnet_t);

namespace {
uint32_t flags25, phase25, result25, startWitness25, classSize25, references25;
uint32_t bsdEflags25, bsdIndex25;
uint32_t failurePhase25, failureResult25;
OSObject *owned25; // Never a worker stack pointer; ambiguous teardown stays owned.
NativeAwdlLifecycle::TransactionState residentState25{};
bool resident25=false;
uint32_t residentStarting25=0,residentClosing25=0;
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
uintptr_t systemControllerKey25=0;
uint32_t systemRuntimeVerified25=0;
uint32_t systemRevision25=0;
uint32_t systemCreateRequests25=0,systemCreateValid25=0,systemCreateRole25=0,systemCreateLastValid25=0;
uint32_t systemInterfaceEnableRequests25=0,systemInterfaceEnabledValid25=0,systemInterfaceEnabled25=0;
uint32_t systemSyncEnableRequests25=0,systemSyncEnabledValid25=0,systemSyncEnabled25=0;
uint32_t systemSequenceRequests25=0,systemSequenceValid25=0;
uint32_t systemSequenceVersion25=0,systemSequenceLength25=0,systemSequenceEncoding25=0;
uint32_t systemSequenceStepCount25=0,systemSequenceDuplicateCount25=0,systemSequenceFillChannel25=0;
uint32_t systemSequenceFlagsHash25=0;
uint64_t systemLastEventUptimeUs25=0;
IOSimpleLock *systemSnapshotLock25=nullptr;
#endif
void note(uint32_t bit) { __atomic_fetch_or(&flags25,bit,__ATOMIC_RELEASE); }
void phase(uint32_t p, IOReturn r=kIOReturnSuccess) {
    __atomic_store_n(&phase25,p,__ATOMIC_RELEASE);
    __atomic_store_n(&result25,uint32_t(r),__ATOMIC_RELEASE);
    uint32_t empty=0;
    if(r!=kIOReturnSuccess && __atomic_compare_exchange_n(&failurePhase25,&empty,p,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        __atomic_store_n(&failureResult25,uint32_t(r),__ATOMIC_RELEASE);
}
template<typename T> T readAt(const void *p,size_t offset) {
    T out{}; if(p) memcpy(&out,static_cast<const uint8_t *>(p)+offset,sizeof(out)); return out;
}
void releaseOpaque(void *p) { if(p) reinterpret_cast<OSObject *>(p)->release(); }
uint32_t txUnavailable(OSObject *,IOSkywalkTxSubmissionQueue *,IOSkywalkPacket *const *,uint32_t,void *) { return 0; }
uint32_t rxUnavailable(OSObject *,IOSkywalkRxCompletionQueue *,IOSkywalkPacket **,uint32_t,void *) { return 0; }

#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
bool propertyTruthy(IOService *controller,const char *name) {
    OSObject *value=controller?controller->copyProperty(name):nullptr;
    bool truthy=true;
    if(!value||value==kOSBooleanFalse)truthy=false;
    else if(auto boolean=OSDynamicCast(OSBoolean,value))truthy=boolean->isTrue();
    else if(auto number=OSDynamicCast(OSNumber,value))truthy=number->unsigned64BitValue()!=0;
    // Unknown types fail closed instead of being treated as an off switch.
    if(value)value->release();
    return truthy;
}
bool diagnosticProfileClear(IOService *controller) {
    static const char *const blocked[]={
        "NativeP2PManualTrigger","NativeP2PManualArmed","NativeP2PProbe",
        "NativeP2PRocProbe","NativeP2PTxProbe","NativeP2PAwdlPsfObservationOnly",
        "NativeP2PAwdlMifFollowup","NativeP2PGp2Observation",
        "NativeP2PRx149ObservationOnly","NativeP2PRx149DataInputExperiment",
        "NativeP2PRx149DataInputProfileEnabled","NativeP2PRx149ProfileEnabled",
        "NativeP2PDirectedPrepareEnabled","NativeP2PDirectedDataEnabled",
        "NativeP2PMulticastAdmissionEnabled","NativeAwdlDiscoveryExperimentEnabled",
        "NativeAwdlDiscoveryMifCurrentSlotEnabled",
        "NativeAwdlDiscoveryCurrentAwFallbackEnabled","NativeAwdlDiscoveryRxInputEnabled"
    };
    for(const char *name:blocked)if(propertyTruthy(controller,name))return false;
    return true;
}
bool systemControllerMatches(IOService *controller) {
    const uintptr_t key=__atomic_load_n(&systemControllerKey25,__ATOMIC_ACQUIRE);
    return controller&&key==reinterpret_cast<uintptr_t>(controller);
}
bool latchSystemController(IOService *controller) {
    if(!controller)return false;
    uintptr_t expected=0;
    const uintptr_t candidate=reinterpret_cast<uintptr_t>(controller);
    if(__atomic_compare_exchange_n(&systemControllerKey25,&expected,candidate,false,
                                  __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return true;
    return expected==candidate||__atomic_load_n(&systemControllerKey25,__ATOMIC_ACQUIRE)==candidate;
}
uint64_t systemUptimeUs() {
    AbsoluteTime uptime=0;uint64_t nanoseconds=0;
    clock_get_uptime(&uptime);absolutetime_to_nanoseconds(uptime,&nanoseconds);
    return nanoseconds/1000ULL;
}
IOSimpleLock *systemSnapshotLock() {
    IOSimpleLock *lock=__atomic_load_n(&systemSnapshotLock25,__ATOMIC_ACQUIRE);
    if(lock)return lock;
    IOSimpleLock *created=IOSimpleLockAlloc();
    if(!created)return nullptr;
    IOSimpleLock *expected=nullptr;
    if(__atomic_compare_exchange_n(&systemSnapshotLock25,&expected,created,false,
                                  __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return created;
    IOSimpleLockFree(created);
    return expected;
}
void systemEventFinished() {
    __atomic_store_n(&systemLastEventUptimeUs25,systemUptimeUs(),__ATOMIC_RELEASE);
    __atomic_add_fetch(&systemRevision25,1u,__ATOMIC_ACQ_REL);
}
bool unicastAddress(const uint8_t address[6]) {
    uint8_t any=0;for(unsigned i=0;i<6;++i)any|=address[i];
    return any&&(address[0]&1)==0;
}
bool verifySystemRuntime25G416() {
    if(!NativeWifi::verifyTahoeAwdlRuntime())return false;
    IORegistryEntry *root=IORegistryEntry::getRegistryRoot();
    if(!root)return false;
    OSObject *buildObject=root->copyProperty("OS Build Version");
    OSObject *kernelObject=root->copyProperty("IOKitBuildVersion");
    OSString *build=OSDynamicCast(OSString,buildObject);
    OSString *kernel=OSDynamicCast(OSString,kernelObject);
    const bool match=build&&kernel&&
        build->isEqualTo("25G416")&&
        kernel->isEqualTo("Darwin Kernel Version 25.6.0: Fri Oct 30 17:30:02 PDT 2026; "
                          "root:xnu-12377.161.15.702.13~1/RELEASE_X86_64");
    if(buildObject)buildObject->release();
    if(kernelObject)kernelObject->release();
    return match;
}
#endif
}

class ItlAwdlLifecycle25G332 final : public ItlAwdlNativeConcreteGate25G332 {
    OSDeclareDefaultStructors(ItlAwdlLifecycle25G332)
public:
    IOService *controller_=nullptr;
    IOSkywalkPacketBufferPool *pool_=nullptr;
    IOSkywalkPacketQueue *queues_[2]{};
    bool nativeStopped_=false, bpfCleaned_=false, canFree_=false;
    bool nativeParent_=false, registrationAttempted_=false, attachAttempted_=false;
    bool initialize(IOService *controller,const uint8_t address[6]);
    bool createQueues();
    bool registerInterface();
    bool verifyStarted();
    bool retire(const NativeAwdlLifecycle::TransactionState &);
    void free() override;
    bool init() override {return false;}
    bool init(OSDictionary *) override {return false;}
    bool init(IOService *,ether_addr *) override {return false;}
    bool init(IO80211Controller *,ether_addr *,unsigned int,const char *) override {return false;}
    bool attach(IOService *p) override {attachAttempted_=true;return IO80211VirtualInterface::attach(p);}
    bool start(IOService *p) override {return IO80211VirtualInterface::start(p);}
    void stop(IOService *p) override;
    // The legacy resident probe keeps its previous status-only behavior. A
    // system-profile callback is recorded but is not acknowledged as an RF
    // operation until the firmware scheduler exists.
    SInt32 setInterfaceEnable(bool enabled) override {
        if(NativeAwdlLifecycle::systemProfileEnabled(controller_)) {
            NativeAwdlLifecycle::observeSystemInterfaceEnable(controller_,enabled);
            return kIOReturnUnsupported;
        }
        return kIOReturnSuccess;
    }
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    Status32 setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *data) override {
        NativeAwdlLifecycle::observeSystemSyncEnabled(controller_,data);
        return kIOReturnUnsupported;
    }
    Status32 setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
        apple80211_awdl_sync_channel_sequence *data) override {
        NativeAwdlLifecycle::observeSystemChannelSequence(controller_,data);
        return kIOReturnUnsupported;
    }
#endif
    IOReturn prepareBSDInterface(ifnet_t interface,unsigned int options) override {
        const IOReturn result=IO80211VirtualInterface::prepareBSDInterface(interface,options);
        if(result!=kIOReturnSuccess)return result;
        return ifnet_set_eflags(interface,0x00100000,0x00100000);
    }
    IOReturn powerStateWillChangeTo(IOPMPowerFlags,unsigned long,IOService *) override {return kIOPMAckImplied;}
    IOReturn powerStateDidChangeTo(IOPMPowerFlags,unsigned long,IOService *) override {return kIOPMAckImplied;}
    IOReturn setPowerState(unsigned long,IOService *) override {return kIOPMAckImplied;}
    const char *getBSDNamePrefix() override {return "awdl";}
    UInt getBSDUnitNumber() override {return 0;}
    uint32_t witness() const;
    bool aliasClear();
};
OSDefineMetaClassAndStructors(ItlAwdlLifecycle25G332,ItlAwdlNativeConcreteGate25G332)

bool ItlAwdlLifecycle25G332::initialize(IOService *controller,const uint8_t address[6]) {
    phase(3); controller_=controller; controller_->retain();
    ether_addr mac{};memcpy(&mac,address,6);
    const bool ok=IO80211VirtualInterface::init(reinterpret_cast<IO80211Controller *>(controller),&mac,6,"awdl");
    nativeParent_=hasNativePrivate25G332();
    if(ok) note(NativeAwdlLifecycle::Initialized); else phase(3,kIOReturnNotReady);
    return ok;
}
bool ItlAwdlLifecycle25G332::createQueues() {
    phase(5);
    const PoolOptions25 options{64,64,2048,1,4096,0,0};
    pool_=poolWithName25("IntelAWDLLifecycle",this,0,&options);
    if(!pool_) return phase(5,kIOReturnNoMemory),false;
    queues_[0]=reinterpret_cast<IOSkywalkPacketQueue *>(txWithPool25(pool_,32,0,this,txUnavailable,nullptr,0));
    queues_[1]=reinterpret_cast<IOSkywalkPacketQueue *>(rxWithPool25(pool_,32,0,this,rxUnavailable,nullptr,0));
    if(!queues_[0]||!queues_[1]) return phase(5,kIOReturnNoMemory),false;
    note(NativeAwdlLifecycle::QueuesCreated);return true;
}
bool ItlAwdlLifecycle25G332::registerInterface() {
    phase(6); IOSkywalkEthernetInterface::RegistrationInfo info{};
    if(!initRegistrationInfo(&info,1,sizeof(info))) return phase(6,kIOReturnBadArgument),false;
    // Public registration record, not private object ivars. Native initializer
    // uses its base defaults, so provide this role's stable prefix and MAC.
    const char *prefix="awdl"; const uint32_t unit=0, wifiSubfamily=3;
    memcpy(info.opaque+0xc,&wifiSubfamily,sizeof(wifiSubfamily));
    memcpy(info.opaque+0x30,&prefix,sizeof(prefix));memcpy(info.opaque+0x38,&unit,sizeof(unit));
    ether_addr mac{};getHardwareAddress(&mac);memcpy(info.opaque+0x108,&mac,6);
    registrationAttempted_=true;
    const IOReturn result=registerEthernet25(this,&info,queues_,2,pool_,pool_,0);
    phase(6,result);if(result!=kIOReturnSuccess)return false;
    note(NativeAwdlLifecycle::Registered);return true;
}
uint32_t ItlAwdlLifecycle25G332::witness() const {
    const void *p=readAt<void *>(this,0x120);if(!p)return 0;
    uint32_t value=1;
    if(readAt<IOService *>(p,0x30)==controller_)value|=2;
    if(readAt<void *>(p,0x38))value|=4;
    if(readAt<void *>(p,0x28))value|=8;
    if(readAt<void *>(p,0xc8))value|=16;
    if(readAt<void *>(p,0x18))value|=32;
    if(readAt<void *>(p,0xa8))value|=64;
    if(readAt<void *>(p,0x50))value|=128;
    if(readAt<uint32_t>(p,0x58)==6)value|=256;
    if(hasVirtualPrivate25G332())value|=512;
    return value;
}
bool ItlAwdlLifecycle25G332::verifyStarted() {
    const uint32_t value=witness();__atomic_store_n(&startWitness25,value,__ATOMIC_RELEASE);
    if(value!=0x3ff || getAwdl25(controller_)!=this) return phase(7,kIOReturnNotReady),false;
    note(NativeAwdlLifecycle::StartComplete);return true;
}
void ItlAwdlLifecycle25G332::stop(IOService *provider) {
    if(nativeStopped_)return;
    // Native role-6 stop unconditionally uses its peer manager and controller.
    if((witness()&0x20b)!=0x20b) {note(NativeAwdlLifecycle::Quarantined);return;}
    nativeStopped_=true;
    IO80211VirtualInterface::stop(provider);
    bpfCleaned_=true;
    note(NativeAwdlLifecycle::NativeStopped|NativeAwdlLifecycle::BpfCleaned);
}
bool ItlAwdlLifecycle25G332::aliasClear() {
    auto loop=controller_->getWorkLoop();if(!loop)return false;
    const auto action=[](OSObject *target,void *arg,void *,void *,void *)->IOReturn {
        auto controller=static_cast<IOService *>(target);
        auto child=static_cast<IO80211VirtualInterface *>(arg);
        if(getAwdl25(controller)==child)setAwdl25(controller,nullptr);
        return getAwdl25(controller)==child?kIOReturnBusy:kIOReturnSuccess;
    };
    const bool ok=loop->runAction(action,controller_,this)==kIOReturnSuccess;
    if(ok)note(NativeAwdlLifecycle::AliasCleared);return ok;
}
bool ItlAwdlLifecycle25G332::retire(const NativeAwdlLifecycle::TransactionState &state) {
    phase(10);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(resident25) {
        auto loop=controller_?controller_->getWorkLoop():nullptr;
        // Startup-failure retirement is initiated by the off-gate observer.
        // Keep the potentially waiting teardown outside the same gate used by
        // P2P submissions, but publish the close bit through that gate first.
        if(!loop||loop->inGate()||loop->onThread()||
           !NativeAwdlLifecycle::publishClosing(controller_)||
           !NativeAwdlBSD::close()) {
            note(NativeAwdlLifecycle::Quarantined);return false;
        }
    }
#endif
    // Native attach first links the IO80211 plane, then tries IOService attach.
    // A false result does not prove absence of the first side effect.
    if(attachAttempted_&&!state.attached) {note(NativeAwdlLifecycle::Quarantined);return false;}
    if(state.startCalled) {
        // No unsafe partial-start fallback. Preserve all references until a
        // future repair path or reboot if native stop prerequisites are absent.
        if((witness()&0x20b)!=0x20b) {phase(10,kIOReturnNotReady);note(NativeAwdlLifecycle::Quarantined);return false;}
        note(NativeAwdlLifecycle::TerminateCalled);
        if(!IO80211VirtualInterface::terminate(kIOServiceSynchronous)) {
            note(NativeAwdlLifecycle::Quarantined);return false;
        }
        note(NativeAwdlLifecycle::TerminateReturned);
        for(unsigned i=0;i<1000 && IOSkywalkNetworkInterface::getBSDInterface();++i)IOSleep(1);
        if(IOSkywalkNetworkInterface::getBSDInterface()) {note(NativeAwdlLifecycle::Quarantined);return false;}
        if(!nativeStopped_)stop(controller_);
        if(!nativeStopped_) {note(NativeAwdlLifecycle::Quarantined);return false;}
    }
    if(!aliasClear()) {note(NativeAwdlLifecycle::Quarantined);return false;}
    if(state.initialized && getProvider()==controller_)IO80211VirtualInterface::detach(controller_);
    if(state.initialized && getProvider()==controller_) {note(NativeAwdlLifecycle::Quarantined);return false;}
    note(NativeAwdlLifecycle::Detached);
    if(registrationAttempted_) {
        const auto result=deregisterEthernet25(this,0);
        if(result!=kIOReturnSuccess) {phase(11,result);note(NativeAwdlLifecycle::Quarantined);return false;}
    }
    note(NativeAwdlLifecycle::RegistrationCleared);
    releaseOpaque(queues_[1]);queues_[1]=nullptr;releaseOpaque(queues_[0]);queues_[0]=nullptr;
    releaseOpaque(pool_);pool_=nullptr;note(NativeAwdlLifecycle::QueuesReleased);
    const IOReturn pm=controller_->deRegisterInterestedDriver(this);
    if(pm!=kIOReturnSuccess && pm!=kIOReturnNotFound && pm!=IOPMNotPowerManaged) {
        phase(11,pm);note(NativeAwdlLifecycle::Quarantined);return false;
    }
    note(NativeAwdlLifecycle::InterestQuiesced);
    if(controller_->isOpen(this))controller_->close(this);
    if(controller_->isOpen(this)) {note(NativeAwdlLifecycle::Quarantined);return false;}
    note(NativeAwdlLifecycle::ControllerClosed);
    if(hasVirtualPrivate25G332()&&!bpfCleaned_) {IO80211VirtualInterface::freeBpfResources();bpfCleaned_=true;}
    if(bpfCleaned_)note(NativeAwdlLifecycle::BpfCleaned);
    if(hasVirtualPrivate25G332()&&!nativeParent_) {note(NativeAwdlLifecycle::Quarantined);return false;}
    canFree_=true;return true;
}
void ItlAwdlLifecycle25G332::free() {
    if(!canFree_) {note(NativeAwdlLifecycle::Quarantined);return;}
    IOService *controller=controller_; const bool parent=nativeParent_;
    controller_=nullptr;
    if(parent)IO80211VirtualInterface::free();else IOService::free();
    if(controller)controller->release();note(NativeAwdlLifecycle::FreeReturned);
}

namespace NativeAwdlLifecycle {
namespace {
IOReturn publishClosingAction(OSObject *target,void *,void *,void *,void *) {
    return publishClosingInGate(static_cast<IOService *>(target))
        ?kIOReturnSuccess:kIOReturnNotReady;
}
}
bool systemProfileEnabled(IOService *controller) {
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    if(!controller||controller->getProperty("NativeAwdlSystemEnabled")!=kOSBooleanTrue||
       controller->getProperty("NativeAwdlResidentEnabled")!=kOSBooleanTrue||
       !diagnosticProfileClear(controller))return false;
    if(!__atomic_load_n(&systemRuntimeVerified25,__ATOMIC_ACQUIRE)&&
       verifySystemRuntime25G416())
        __atomic_store_n(&systemRuntimeVerified25,1u,__ATOMIC_RELEASE);
    return __atomic_load_n(&systemRuntimeVerified25,__ATOMIC_ACQUIRE)!=0;
#else
    (void)controller;
    return false;
#endif
}
void observeSystemCreateRequest(IOService *controller,
                               const apple80211_virt_if_create_data *request) {
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    if(!systemProfileEnabled(controller))return;
    static_assert(sizeof(apple80211_virt_if_create_data)==32,"role-6 request ABI");
    apple80211_virt_if_create_data copy{};
    if(request)memcpy(&copy,request,sizeof(copy));
    const bool valid=request&&copy.version==APPLE80211_VERSION&&
        copy.role==APPLE80211_VIF_AWDL&&unicastAddress(copy.mac);
    IOSimpleLock *lock=systemSnapshotLock();if(!lock)return;
    const IOInterruptState irq=IOSimpleLockLockDisableInterrupt(lock);
    if(!latchSystemController(controller)) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);return;
    }
    ++systemCreateRequests25;systemCreateRole25=request?copy.role:0u;
    systemCreateLastValid25=valid?1u:0u;if(valid)++systemCreateValid25;
    systemEventFinished();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#else
    (void)controller;(void)request;
#endif
}
void observeSystemInterfaceEnable(IOService *controller,bool enabled) {
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    if(!systemProfileEnabled(controller))return;
    IOSimpleLock *lock=systemSnapshotLock();if(!lock)return;
    const IOInterruptState irq=IOSimpleLockLockDisableInterrupt(lock);
    if(!latchSystemController(controller)) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);return;
    }
    ++systemInterfaceEnableRequests25;systemInterfaceEnabled25=enabled?1u:0u;
    systemInterfaceEnabledValid25=1u;systemEventFinished();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#else
    (void)controller;(void)enabled;
#endif
}
void observeSystemSyncEnabled(IOService *controller,
                             const apple80211_awdl_sync_enabled *request) {
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    if(!systemProfileEnabled(controller))return;
    apple80211_awdl_sync_enabled copy{};
    if(request)memcpy(&copy,request,sizeof(copy));
    const bool valid=request&&copy.version==APPLE80211_VERSION&&copy.enabled<=1;
    IOSimpleLock *lock=systemSnapshotLock();if(!lock)return;
    const IOInterruptState irq=IOSimpleLockLockDisableInterrupt(lock);
    if(!latchSystemController(controller)) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);return;
    }
    ++systemSyncEnableRequests25;systemSyncEnabled25=request?copy.enabled:0u;
    systemSyncEnabledValid25=valid?1u:0u;systemEventFinished();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#else
    (void)controller;(void)request;
#endif
}
void observeSystemChannelSequence(IOService *controller,
                                  const apple80211_awdl_sync_channel_sequence *request) {
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    if(!systemProfileEnabled(controller))return;
    apple80211_awdl_sync_channel_sequence copy{};
    if(request)memcpy(&copy,request,sizeof(copy));
    const bool valid=request&&copy.version==APPLE80211_VERSION&&
        copy.length<=APPLE80211_MAX_CHANNELS;
    uint32_t hash=2166136261u;
    if(valid)for(uint32_t i=0;i<copy.length;++i) {
        const auto &entry=copy.seqs[i];
        hash=(hash^uint8_t(entry.flags))*16777619u;
        hash=(hash^uint8_t(entry.flags>>8))*16777619u;
        hash=(hash^entry.pad)*16777619u;
    }
    IOSimpleLock *lock=systemSnapshotLock();if(!lock)return;
    const IOInterruptState irq=IOSimpleLockLockDisableInterrupt(lock);
    if(!latchSystemController(controller)) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);return;
    }
    ++systemSequenceRequests25;systemSequenceValid25=valid?1u:0u;
    systemSequenceVersion25=request?copy.version:0u;
    systemSequenceLength25=request?copy.length:0u;
    systemSequenceEncoding25=request?copy.encoding:0u;
    systemSequenceStepCount25=request?copy.step_count:0u;
    systemSequenceDuplicateCount25=request?copy.duplicate_count:0u;
    systemSequenceFillChannel25=request?copy.fill_channel:0u;
    systemSequenceFlagsHash25=valid?hash:0u;
    systemEventFinished();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#else
    (void)controller;(void)request;
#endif
}
SystemScheduleSnapshot systemScheduleSnapshot(IOService *controller) {
    SystemScheduleSnapshot out{};
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332) && defined(ITL_NATIVE_AWDL_SYSTEM_25G332)
    if(!systemProfileEnabled(controller))return out;
    IOSimpleLock *lock=systemSnapshotLock();if(!lock)return out;
    const IOInterruptState irq=IOSimpleLockLockDisableInterrupt(lock);
    if(!systemControllerMatches(controller)) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);return out;
    }
    out.revision=systemRevision25;
    out.createRequests=systemCreateRequests25;out.createValidRequests=systemCreateValid25;
    out.lastCreateRole=systemCreateRole25;out.lastCreateValid=systemCreateLastValid25;
    out.interfaceEnableRequests=systemInterfaceEnableRequests25;
    out.interfaceEnabledValid=systemInterfaceEnabledValid25;
    out.interfaceEnabled=systemInterfaceEnabled25;
    out.syncEnabledRequests=systemSyncEnableRequests25;
    out.syncEnabledValid=systemSyncEnabledValid25;out.syncEnabled=systemSyncEnabled25;
    out.channelSequenceRequests=systemSequenceRequests25;
    out.channelSequenceValid=systemSequenceValid25;
    out.sequenceVersion=systemSequenceVersion25;out.sequenceLength=systemSequenceLength25;
    out.sequenceEncoding=systemSequenceEncoding25;
    out.sequenceStepCount=systemSequenceStepCount25;
    out.sequenceDuplicateCount=systemSequenceDuplicateCount25;
    out.sequenceFillChannel=systemSequenceFillChannel25;
    out.sequenceFlagsHash=systemSequenceFlagsHash25;
    out.lastEventUptimeUs=systemLastEventUptimeUs25;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#else
    (void)controller;
#endif
    return out;
}
bool publishClosingInGate(IOService *controller) {
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(!controller)return false;
    auto loop=controller->getWorkLoop();
    if(!loop||!loop->inGate())return false;
    __atomic_store_n(&residentClosing25,1u,__ATOMIC_RELEASE);
    NativeAwdlBSD::publishClosing();
    return true;
#else
    return controller!=nullptr;
#endif
}
bool publishClosing(IOService *controller) {
    if(!controller)return false;
    auto loop=controller->getWorkLoop();
    if(!loop)return false;
    if(loop->inGate())return publishClosingInGate(controller);
    // IOWorkLoop::runAction synchronizes with the IOCommandGate actions
    // registered on this same main workloop; it does not dispatch a worker.
    return loop->runAction(publishClosingAction,controller)==kIOReturnSuccess;
}
bool residentPending(IOService *controller) {
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(__atomic_load_n(&residentClosing25,__ATOMIC_ACQUIRE)||!controller||
       controller->getProperty("NativeAwdlResidentEnabled")!=kOSBooleanTrue||
       snapshot().flags!=0)return false;
    // Test144 manual profiles remain independent. The new system profile is
    // admitted only as resident software initialization, never as an RF probe.
    return controller->getProperty("NativeP2PManualTrigger")==kOSBooleanTrue||
        systemProfileEnabled(controller);
#else
    return false;
#endif
}
bool stopResident(IOService *controller) {
    if(!controller||!__atomic_load_n(&residentClosing25,__ATOMIC_ACQUIRE))
        return false;
    auto loop=controller->getWorkLoop();
    if(!loop||loop->inGate()||loop->onThread())return false;
    for(unsigned i=0;i<3000&&__atomic_load_n(&residentStarting25,__ATOMIC_ACQUIRE);++i)IOSleep(1);
    if(__atomic_load_n(&residentStarting25,__ATOMIC_ACQUIRE))return false;
    if(!resident25||!owned25)return true;
    auto object=static_cast<ItlAwdlLifecycle25G332 *>(owned25);
    if(object->controller_!=controller)return false;
    if(!object->retire(residentState25))return false;
    __atomic_store_n(&references25,uint32_t(object->getRetainCount()),__ATOMIC_RELEASE);
    note(ReleaseRequested);owned25=nullptr;object->release();phase(12);return true;
}
void observeOnce(IOService *controller,const uint8_t address[6]) {
    __atomic_add_fetch(&residentStarting25,1u,__ATOMIC_ACQ_REL);
    struct InFlight {~InFlight(){__atomic_sub_fetch(&residentStarting25,1u,__ATOMIC_RELEASE);}} inFlight;
    if(__atomic_load_n(&residentClosing25,__ATOMIC_ACQUIRE))return;
    uint32_t expected=0;
    if(!__atomic_compare_exchange_n(&flags25,&expected,uint32_t(Attempted),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    phase(1);uint8_t any=0;if(address)for(unsigned i=0;i<6;++i)any|=address[i];
    bool resident=false;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    resident=controller&&controller->getProperty("NativeAwdlResidentEnabled")==kOSBooleanTrue;
#endif
    const bool systemResident=resident&&systemProfileEnabled(controller);
    if(systemResident)latchSystemController(controller);
    if(!controller||!address||!any||(address[0]&1)||!NativeWifi::verifyTahoeAwdlRuntime()||
       !controller->metaCast("IO80211Controller")||
       (!resident&&controller->getProperty("NativeAwdlLifecycleObservationOnly")!=kOSBooleanTrue)||
       (controller->getProperty("NativeP2PManualTrigger")!=kOSBooleanTrue&&!systemResident)||
       getAwdl25(controller)) {
        phase(1,kIOReturnNotPermitted);note(Failed);return;
    }
    ifnet_t existing=nullptr;
    if(ifnet_find_by_name("awdl0",&existing)==0) {
        ifnet_release(existing);phase(1,kIOReturnBusy);note(Failed);return;
    }
    note(AliasInitiallyEmpty);phase(2);
    const auto meta=ItlAwdlLifecycle25G332::metaClass;
    if(!meta||meta->getSuperClass()!=ItlAwdlNativeConcreteGate25G332::metaClass||
       meta->getClassSize()!=sizeof(ItlAwdlLifecycle25G332)) {note(Failed);return;}
    __atomic_store_n(&classSize25,meta->getClassSize(),__ATOMIC_RELEASE);
    auto object=static_cast<ItlAwdlLifecycle25G332 *>(meta->alloc());if(!object){phase(2,kIOReturnNoMemory);note(Failed);return;}
    owned25=object;
    struct Operations {
        ItlAwdlLifecycle25G332 *object;IOService *controller;const uint8_t *address;bool retired=false;
        bool initialize(){return object->initialize(controller,address);}
        bool attach(){phase(4);const bool ok=object->attach(controller);if(ok)note(Attached);else phase(4,kIOReturnNotReady);return ok;}
        bool createQueues(){return object->createQueues();}
        bool registerInterface(){return object->registerInterface();}
        bool start(){phase(7);note(StartCalled);const bool ok=object->start(controller);note(StartReturned);if(!ok)phase(7,kIOReturnNotReady);return ok;}
        bool verifyStarted(){return object->verifyStarted();}
        void publish(){phase(8);object->registerService();note(Published);}
        bool observeBSD(){phase(9);for(unsigned i=0;i<2000;++i){
            ifnet_t interface=nullptr;
            if(ifnet_find_by_name("awdl0",&interface)==0){
                const uint32_t eflags=ifnet_eflags(interface),index=ifnet_index(interface);
                __atomic_store_n(&bsdEflags25,eflags,__ATOMIC_RELEASE);
                __atomic_store_n(&bsdIndex25,index,__ATOMIC_RELEASE);
                const bool own=interface==object->IOSkywalkNetworkInterface::getBSDInterface();
                ifnet_release(interface);
                if(own&&(eflags&0x00100000)&&index){note(BSDSeen);return true;}
            }
            IOSleep(1);
        }phase(9,kIOReturnNotReady);return false;}
        bool retire(const TransactionState &state){return retired=object->retire(state);}
    } ops{object,controller,address};
    TransactionState state{};resident25=resident;
    bool complete=resident?NativeAwdlLifecycle::start(ops,state):execute(ops,state);
    if(resident)residentState25=state;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(complete&&resident) {
        ifnet_t interface=nullptr;
        const int lookupResult=ifnet_find_by_name("awdl0",&interface);
        NativeAwdlBSD::noteResidentLookupResult(lookupResult);
        if(lookupResult==0) {
            const bool attached=NativeAwdlBSD::attach(interface,address);ifnet_release(interface);
            if(attached){
                residentState25=state;
                object->IO80211VirtualInterface::setLinkState(kIO80211NetworkLinkUp,0);
                object->IOSkywalkNetworkInterface::setRunningState(true);
                object->reportLinkStatus(3,0x80);
                phase(13);return;
            }
        }
        phase(13,kIOReturnNotReady);complete=false;ops.retire(state);
    }
#endif
    if(!complete)note(Failed);
    if(!ops.retired)return;
    __atomic_store_n(&references25,uint32_t(object->getRetainCount()),__ATOMIC_RELEASE);
    note(ReleaseRequested);owned25=nullptr;object->release();phase(12);
}
Snapshot snapshot(){return {__atomic_load_n(&flags25,__ATOMIC_ACQUIRE),__atomic_load_n(&phase25,__ATOMIC_ACQUIRE),
    __atomic_load_n(&result25,__ATOMIC_ACQUIRE),__atomic_load_n(&startWitness25,__ATOMIC_ACQUIRE),
    __atomic_load_n(&classSize25,__ATOMIC_ACQUIRE),__atomic_load_n(&references25,__ATOMIC_ACQUIRE),
    __atomic_load_n(&bsdEflags25,__ATOMIC_ACQUIRE),__atomic_load_n(&bsdIndex25,__ATOMIC_ACQUIRE),
    __atomic_load_n(&failurePhase25,__ATOMIC_ACQUIRE),__atomic_load_n(&failureResult25,__ATOMIC_ACQUIRE)};}
}
#endif
