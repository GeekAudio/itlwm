#!/usr/bin/env python3
"""Compile actual Tahoe power methods with host KPI shims; no driver or radio IO."""
from pathlib import Path
import subprocess,tempfile,hashlib,json
ROOT=Path(__file__).resolve().parents[2]
source=(ROOT/'AirportItlwm/AirportItlwmV2.cpp').read_text()
def function_from(text,marker):
    start=text.index(marker); opening=text.index('{',start); depth=1; end=opening+1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}'); end+=1
    return text[start:end]
def function(marker): return function_from(source,marker)
methods=[function(s) for s in [
    'bool AirportItlwm::initializeNativePowerLocks(',
    'void AirportItlwm::releaseNativePowerLocks(',
    'void AirportItlwm::releaseNativePowerHAL(',
    'bool AirportItlwm::init(OSDictionary *properties)',
    'IOReturn AirportItlwm::\ngetPOWER(',
    'uint32_t AirportItlwm::updateNativePowerFlags(',
    'uint32_t AirportItlwm::advanceNativePowerEpoch(',
    'bool AirportItlwm::nativePowerStateSnapshot(',
    'IOReturn AirportItlwm::beginNativeAddressRestartNotification(',
    'bool AirportItlwm::commitNativeAddressRestartNotification(',
    'void AirportItlwm::cancelNativeAddressRestartNotification(',
    'NativePowerTrace::AddressRestartDecision\nAirportItlwm::observeNativeAddressRestartEvent(',
    'bool AirportItlwm::tickNativeAddressRestartNotification(',
    'uint32_t AirportItlwm::observeNativePowerEvent(',
    'uint32_t AirportItlwm::beginNativeControlTrace(',
    'void AirportItlwm::recordNativeControlTrace(',
    'void AirportItlwm::publishNativePowerTrace(',
    'bool AirportItlwm::postNativePowerChangedIfNeeded(',
    'void AirportItlwm::publishNativePowerState(',
    'void AirportItlwm::noteNativeAddressRestartOutcome(',
    'void AirportItlwm::publishNativeAddressRestartMetrics(',
    'IOReturn AirportItlwm::nativePowerStopAction(',
    'IOReturn AirportItlwm::nativePowerAction(',
    'IOReturn AirportItlwm::waitForNativePower(',
    'IOReturn AirportItlwm::disableAdapterWithRetry(',
    'void AirportItlwm::wakeNativePowerWaiters(',
    'IOReturn AirportItlwm::\nsetPOWER(',
    'IOReturn AirportItlwm::enable(IO80211SkywalkInterface *netif)',
    'IOReturn AirportItlwm::enableAdapter(',
    'IOReturn AirportItlwm::disableAdapter(',
    'void AirportItlwm::setPowerStateOff(',
    'void AirportItlwm::setPowerStateOn(',
    'void AirportItlwm::setNativePowerStopping(',
    'void AirportItlwm::unregistPM(',
    'bool AirportItlwm::retireNativePMPowerCallouts(',
    'IOReturn AirportItlwm::setPowerState(',
    'static IOReturn dispatchSetPowerStateOff(',
    'static IOReturn dispatchSetPowerStateOn(',
    'static void handleSetPowerStateOff(',
    'static void handleSetPowerStateOn(']]
assert 'thread_call_isactive' not in function('void AirportItlwm::unregistPM()')
for teardown_marker in ['void AirportItlwm::releaseAll()', 'void AirportItlwm::free()']:
    assert 'releaseNativePowerHAL();' in function(teardown_marker), teardown_marker
release_hal_source=function('void AirportItlwm::releaseNativePowerHAL()')
assert release_hal_source.index('IOSimpleLockUnlockEnableInterrupt(lock, irq)') < \
       release_hal_source.index('hal->release()')
publish_power_source=function('void AirportItlwm::publishNativePowerState()')
assert publish_power_source.index('hal->retain()') < \
       publish_power_source.index('IOSimpleLockUnlockEnableInterrupt(stateLock, irq)') < \
       publish_power_source.index('hal->release()')
stop_source=function('void AirportItlwm::stop(IOService *provider)')
stop_latch=stop_source.index('setNativePowerStopping(true);')
stop_barrier=stop_source.index('->stopNative()')
stop_gate=stop_source.index('nativePowerStopAction, nullptr')
stop_disable=stop_source.index('disableAdapter(bsdInterface);')
assert stop_latch < stop_barrier < stop_gate < stop_disable
assert stop_source.index('retireNativePMPowerCallouts())') < stop_disable
assert stop_source.index('retireNativePMPowerCallouts())') < stop_source.index('super::stop(provider);')
assert 'advanceNativePowerEpoch(false);' not in stop_source
assert stop_source.count('disableAdapter(bsdInterface);') == 1
start_source=function('bool AirportItlwm::start(IOService *provider)')
assert '__atomic_store_n(&nativePowerStopping, false, __ATOMIC_RELEASE);' in start_source
set_pm_source=function('IOReturn AirportItlwm::setPowerState(')
assert set_pm_source.index('IOSimpleLockLockDisableInterrupt(stateLock)') < \
       set_pm_source.index('nativePowerStopping') < \
       set_pm_source.index('thread_call_enter(') < \
       set_pm_source.rindex('IOSimpleLockUnlockEnableInterrupt(stateLock, irq)')
release_all_source=function('void AirportItlwm::releaseAll()')
assert release_all_source.index('retireNativePMPowerCallouts())') < \
       release_all_source.index('releaseNativePowerHAL();')
stop_action_source=function('IOReturn AirportItlwm::nativePowerStopAction(')
assert stop_action_source.index('updateNativePowerFlags(1U, 0);') < \
       stop_action_source.index('advanceNativePowerEpoch(false);') < \
       stop_action_source.index('wakeNativePowerWaiters();')
assert 'disableAdapter(' not in stop_action_source
power_action_source=function('IOReturn AirportItlwm::nativePowerAction(')
assert power_action_source.index('nativePowerStopping') < \
       power_action_source.index('kNativeActionBegin')
wait_power_source=function('IOReturn AirportItlwm::waitForNativePower(')
assert wait_power_source.index('nativePowerStopping') < \
       wait_power_source.index('kIOReturnAborted')
shim=r'''
#include <cstdint>
#include <cstring>
#include <cassert>
#include <map>
#include <string>
#include <thread>
#include <cstdio>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <utility>
#include <vector>
#include "native/native_power_trace.hpp"
#define AIRPORT_TAHOE 1
#define XYLog(...) do {} while (0)
#define IOLog(...) do {} while (0)
using IOReturn=int32_t;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnError=int32_t(0xe00002bc),
 kIOReturnBadArgument=int32_t(0xe00002c2),kIOReturnUnsupported=int32_t(0xe00002c7),
 kIOReturnNotReady=int32_t(0xe00002d8),kIOReturnBusy=int32_t(0xe00002d5),
 kIOReturnAborted=int32_t(0xe00002eb),kIOReturnTimeout=int32_t(0xe00002d6);
using AbsoluteTime=uint64_t;
constexpr unsigned kSecondScale=1,kNanosecondScale=2,kMillisecondScale=3,
 THREAD_INTERRUPTIBLE=1;
constexpr IOReturn THREAD_AWAKENED=0,THREAD_TIMED_OUT=1;
static uint64_t g_uptimeNanoseconds=0;
static void clock_interval_to_deadline(unsigned n,unsigned scale,AbsoluteTime*out){
 if(scale==kSecondScale){assert(n==12);*out=g_uptimeNanoseconds+12000000000ULL;}
 else if(scale==kMillisecondScale)*out=g_uptimeNanoseconds+uint64_t(n)*1000000ULL;
 else{assert(scale==kNanosecondScale);*out=g_uptimeNanoseconds+n;}}
static void clock_get_uptime(AbsoluteTime*out){*out=g_uptimeNanoseconds;}
static void absolutetime_to_nanoseconds(AbsoluteTime value,uint64_t*out){*out=value;}
static uint64_t nativePowerUptimeNanoseconds(){AbsoluteTime t=0;uint64_t n=0;
 clock_get_uptime(&t);absolutetime_to_nanoseconds(t,&n);return n;}
constexpr unsigned APPLE80211_VERSION=1,APPLE80211_MAX_RADIO=4,APPLE80211_POWER_ON=1;
constexpr unsigned kPowerStateOff=0,kPowerStateOn=1;
constexpr unsigned APPLE80211_M_POWER_CHANGED=1001;
constexpr IOReturn IOPMAckImplied=0;
constexpr unsigned ITL_TAHOE_EVT_DRIVER_READY=6,ITL_TAHOE_EVT_DRIVER_STOPPED=7,ITL_TAHOE_EVT_RESET_BEGIN=8;
constexpr unsigned IFF_UP=1,IFF_RUNNING=0x40,kWatchDogTimerPeriod=1000;
static thread_local bool irq=false;
static bool ml_at_interrupt_context(){return irq;}
struct OSObject {virtual ~OSObject()=default;};
struct IOService:OSObject {unsigned acknowledgements=0;
 void acknowledgeSetPowerState(){++acknowledgements;}};
#define OSDynamicCast(T,p) dynamic_cast<T*>(p)
struct OSDictionary:OSObject{};
static bool parentInitResult=true;
struct IO80211Controller:OSObject {bool init(OSDictionary*){return parentInitResult;}};
#define super IO80211Controller
#define ITL_STARTUP_RESULT(provider,stage,result) (result)
using IOInterruptState=bool;
struct IOSimpleLock {std::mutex mutex;std::atomic<unsigned> waiters{0};};
static int lockAllocationFailAt=-1,lockAllocationAttempts=0;
static IOSimpleLock*IOSimpleLockAlloc(){const int attempt=lockAllocationAttempts++;
 if(attempt==lockAllocationFailAt)return nullptr;return new IOSimpleLock();}
static void IOSimpleLockFree(IOSimpleLock*p){delete p;}
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock*p){
 const bool previous=irq;irq=true;p->waiters.fetch_add(1,std::memory_order_acq_rel);
 p->mutex.lock();p->waiters.fetch_sub(1,std::memory_order_acq_rel);return previous;}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock*p,IOInterruptState previous){
 p->mutex.unlock();irq=previous;}
static unsigned g_threadCallEnterCount=0;
struct FakeThreadCall {bool pending=false,active=false,freed=false;unsigned enters=0;
 bool pendingAgainAfterCancelWait=false;
 void(*callback)(void*,void*)=nullptr;void*param0=nullptr;};
static bool thread_call_enter(FakeThreadCall*call){++g_threadCallEnterCount;
 if(!call)return false;++call->enters;const bool wasPending=call->pending;
 call->pending=true;return wasPending;}
using thread_call_t=FakeThreadCall*;
using thread_call_param_t=void*;
static void thread_call_enter(void*){++g_threadCallEnterCount;}
static bool thread_call_cancel_wait(FakeThreadCall*call){if(!call)return false;
 if(call->pending){call->pending=false;
  if(call->pendingAgainAfterCancelWait){call->pending=true;
   call->pendingAgainAfterCancelWait=false;}
  return true;}
 if(call->active){call->active=false;
  if(call->callback)call->callback(call->param0,nullptr);}
 return false;}
static bool thread_call_free(FakeThreadCall*call){if(!call||call->pending)return false;
 if(call->active)return false;
 call->freed=true;return true;}
struct OSData:OSObject {std::vector<uint8_t> bytes;
 static OSData*withBytes(const void*p,size_t n){auto*d=new OSData();
 const auto*b=static_cast<const uint8_t*>(p);d->bytes.assign(b,b+n);return d;}
 void release(){delete this;}};
struct apple80211_power_data {uint32_t version,num_radios,power_state[4];};
struct NativePowerActionContext {apple80211_power_data request;uint32_t traceCallId;};
struct IONetworkInterface:OSObject {};
struct FakeIC {struct {uint32_t if_flags=0;} ic_if;uint32_t ic_tahoe_init_stage=0;int32_t ic_tahoe_init_error=0; uint32_t(*ic_tahoe_scan_state)(FakeIC*)=nullptr;};
struct HAL {FakeIC ic;IOReturn result=0,disableResult=0;unsigned enabled=0,disabled=0,disableBusyCount=0;bool stuck=false;
 uint32_t requestEpoch=0,observedPublicEpoch=0,faultSerial=0;bool requestOn=false,
  faultSerialAvailable=true;unsigned requestUpdates=0;
 mutable std::mutex faultReadMutex;mutable std::condition_variable faultReadCondition;
 mutable bool blockFaultRead=false,faultReadEntered=false,allowFaultRead=false;
 std::atomic<unsigned>*destroyCount=nullptr,*releaseCount=nullptr;bool deleteOnRelease=false;
 std::atomic<unsigned> references{1};
 uint32_t*publicEpoch=nullptr;std::vector<std::pair<uint32_t,bool>> requestHistory;
 void setNativePowerRequestState(uint32_t epoch,bool on){requestEpoch=epoch;requestOn=on;
 ++requestUpdates;requestHistory.emplace_back(epoch,on);
 if(publicEpoch)observedPublicEpoch=__atomic_load_n(publicEpoch,__ATOMIC_ACQUIRE);}
 bool readNativePowerFaultSerial(uint32_t*out)const{
  {std::unique_lock<std::mutex> guard(faultReadMutex);
   if(blockFaultRead){faultReadEntered=true;faultReadCondition.notify_all();
    faultReadCondition.wait(guard,[this]{return allowFaultRead;});}}
  if(!out||!faultSerialAvailable)return false;*out=faultSerial;return true;}
 ~HAL(){if(destroyCount)destroyCount->fetch_add(1,std::memory_order_acq_rel);}
 void retain(){if(deleteOnRelease)references.fetch_add(1,std::memory_order_acq_rel);}
 void release(){assert(!irq);if(releaseCount)releaseCount->fetch_add(1,std::memory_order_acq_rel);
  if(deleteOnRelease&&references.fetch_sub(1,std::memory_order_acq_rel)==1)delete this;}
 FakeIC*get80211Controller(){return &ic;}
 IOReturn enable(IONetworkInterface*){++enabled;if(result)return result;ic.ic_if.if_flags|=IFF_UP;return 0;}
 IOReturn disable(IONetworkInterface*){++disabled;if(disableBusyCount){--disableBusyCount;return kIOReturnBusy;}
 if(disableResult)return disableResult;if(!stuck)ic.ic_if.if_flags=0;return 0;}};
using ItlHalService=HAL;
struct Timer {unsigned started=0,stopped=0;void setTimeoutMS(unsigned){}void enable(){++started;}
 void cancelTimeout(){++stopped;}void disable(){}};
struct Queue;
static thread_local Queue*g_activeCommandGate=nullptr;
struct Queue {bool gated=false,worker=false;bool inGate(){return g_activeCommandGate==this;}
 bool onThread(){return worker;}};
struct NativeIF {Queue*q;unsigned messages=0;std::function<void()>onPost;
 Queue*getControllerWorkQueue(){return q;}
 void postMessage(unsigned,void*,unsigned,bool){++messages;if(onPost)onPost();}};
using IO80211SkywalkInterface=NativeIF;
namespace NativeWifi {
struct Beacon {const uint8_t*frame=nullptr;size_t frameLength=0;size_t ssidLength=0;
 const uint8_t*ssid=nullptr;const uint8_t*bssid=nullptr;uint8_t channel=0;
 uint16_t channelSpec=0,interval=0,capability=0;int32_t rssi=0;int16_t noise=0,snr=0;
 const uint8_t*ies=nullptr;size_t ieLength=0;};
struct IngressEntry {unsigned kind=0;uint32_t value=0,detail=0;
 NativePowerTrace::PowerIngressContext powerContext{};uint8_t bssid[6]{};
 uint8_t ssid[32]{},ssidLength=0,channel=0;uint16_t channelSpec=0,interval=0,
 capability=0,frameLength=0;int32_t rssi=0;int16_t noise=0,snr=0;uint8_t frame[2048]{};};
class Ingress {public:
 bool signal(unsigned,uint32_t=0,const uint8_t * = nullptr,uint32_t=0,
  const NativePowerTrace::PowerIngressContext * = nullptr);
 bool append(unsigned,uint32_t,const uint8_t*,const Beacon*,uint32_t=0,
  const NativePowerTrace::PowerIngressContext * = nullptr);
 IOSimpleLock*lock_=nullptr;void*call_=nullptr;bool closing_=false,stopped_=false;
 unsigned first_=0,count_=0;uint64_t overflow_=0;static constexpr unsigned Capacity=32;
 IngressEntry entries_[Capacity]{};
};
}
static Queue*_fWorkloop=nullptr;
struct Gate {using Action=IOReturn(*)(OSObject*,void*,void*,void*,void*);
 OSObject*owner;Queue*q;bool loseGate=false;void enable(){}
 unsigned sleeps=0,wakes=0,retrySleeps=0,earlyWakeCount=0;
 IOReturn sleepResult=THREAD_AWAKENED;std::function<void()> onSleep;
 IOReturn commandSleep(void*,AbsoluteTime deadline,unsigned flags) {
  assert(q->gated&&deadline>g_uptimeNanoseconds&&flags==THREAD_INTERRUPTIBLE);
  const uint64_t delay=deadline-g_uptimeNanoseconds;
  const bool retry=delay<=25000000ULL;if(retry)++retrySleeps;
  ++sleeps;Queue*savedGate=g_activeCommandGate;g_activeCommandGate=nullptr;
  q->gated=false;assert(onSleep);onSleep();assert(!q->gated);q->gated=true;
  g_activeCommandGate=savedGate;
  if(retry&&earlyWakeCount){--earlyWakeCount;g_uptimeNanoseconds+=1000000ULL;
   return THREAD_AWAKENED;}
  if(sleepResult==THREAD_TIMED_OUT)g_uptimeNanoseconds=deadline;
  else g_uptimeNanoseconds+=delay<25000000ULL?delay:25000000ULL;
  return sleepResult;
 }
 void commandWakeup(void*,bool one){assert(q->gated&&!one);++wakes;}
 IOReturn runAction(Action action,void*a){const bool old=q->gated;q->gated=!loseGate;
 Queue*oldGate=g_activeCommandGate;g_activeCommandGate=loseGate?nullptr:q;
 IOReturn r=action(owner,a,nullptr,nullptr,nullptr);q->gated=old;
 g_activeCommandGate=oldGate;return r;}};
static Gate*_fCommandGate=nullptr;
struct AirportItlwm:IO80211Controller {
 HAL*fHalService=nullptr;IONetworkInterface*bsdInterface=nullptr;NativeIF*fNetIf=nullptr;Timer*watchdogTimer=nullptr;
 IOService*pmPolicyMaker=nullptr;
 FakeThreadCall offCall,onCall;FakeThreadCall*powerOffThreadCall=nullptr,*powerOnThreadCall=nullptr;
 uint8_t power_state=0;uint32_t pmPowerState=kPowerStateOn;
 bool nativeActivationAttempted=false,awdlSyncEnable=false,nativePowerStopping=false;
 uint32_t nativePowerPMRequestEpoch=0,nativePowerPMRequestedState=kPowerStateOn;
 uint32_t nativePowerPMOffCalloutEpoch=0,nativePowerPMOnCalloutEpoch=0;
 bool nativePowerPMRequestValid=false;
 uint8_t geo_location_cc[2] {};
 uint32_t nativePowerFlags=0,nativePowerGetCount=0,nativePowerSetCount=0,
 nativePowerLastResult=uint32_t(kIOReturnNotReady),nativePowerLastEvent=0,
 nativePowerReadyCount=0,nativePowerStoppedCount=0,nativePowerResetCount=0,nativePowerEpoch=0,
 nativePowerTracePublishedSequence=0,
 nativePowerOffAttempts=0,nativePowerOffRetries=0,nativePowerOffResult=uint32_t(kIOReturnNotReady);
 uint64_t nativePowerTransitionRevision=0;
 NativePowerTrace::NotificationState nativePowerNotificationState;
 NativePowerTrace::AddressRestartNotification nativeAddressRestartNotification;
 uint64_t nativeAddressRestartPublishedId=0,nativeAddressRestartStartRevision=0;
 uint32_t nativeAddressRestartPublishedEpoch=0,nativeAddressRestartStartedCount=0,
  nativeAddressRestartSuppressedCount=0,nativeAddressRestartCompletedCount=0,
  nativeAddressRestartCancelledCount=0,nativeAddressRestartExpiredCount=0,
  nativeAddressRestartLastOutcome=0;
 IOSimpleLock*nativePowerStateLock=nullptr,*nativePowerTraceLock=nullptr;
 NativePowerTrace::Ledger nativePowerTrace;
 bool nativePowerOffPending=false;
 unsigned properties=0;std::map<std::string,uint64_t> metadata;
 bool offPending()const{return __atomic_load_n(&nativePowerOffPending,__ATOMIC_ACQUIRE);}
 unsigned retained=0,released=0;void retain(){++retained;}void release(){++released;}
 void setProperty(const char*k,uint64_t value,unsigned){assert(!irq);++properties;metadata[k]=value;}
 bool setProperty(const char*k,OSData*d){assert(!irq&&d);++properties;metadata[k]=d->bytes.size();return true;}
 bool init(OSDictionary*);
 bool initializeNativePowerLocks();void releaseNativePowerLocks();
 ~AirportItlwm(){releaseNativePowerLocks();}
 IOReturn getPOWER(OSObject*,apple80211_power_data*);
 IOReturn setPOWER(OSObject*,apple80211_power_data*);
 uint32_t updateNativePowerFlags(uint32_t,uint32_t,bool=false,
  NativePowerTrace::PowerIngressContext * = nullptr);
 bool nativePowerStateSnapshot(uint32_t*,uint64_t*)const;
 uint32_t observeNativePowerEvent(int,
  NativePowerTrace::PowerIngressContext * = nullptr);
 uint32_t beginNativeControlTrace(NativePowerTrace::Operation,NativePowerTrace::Phase,uint32_t,int32_t,uint32_t=0);
 void recordNativeControlTrace(uint32_t,NativePowerTrace::Operation,NativePowerTrace::Phase,uint32_t,int32_t,uint32_t=0);
 uint32_t advanceNativePowerEpoch(bool);
 IOReturn beginNativeAddressRestartNotification(uint64_t*);
 bool commitNativeAddressRestartNotification(uint64_t,bool,bool);
 void cancelNativeAddressRestartNotification(uint64_t=0);
 NativePowerTrace::AddressRestartDecision observeNativeAddressRestartEvent(
  NativePowerTrace::AddressRestartEvent,const NativePowerTrace::PowerIngressContext&);
 bool tickNativeAddressRestartNotification();
 void noteNativeAddressRestartOutcome(NativePowerTrace::AddressRestartOutcome);
 void publishNativeAddressRestartMetrics();
 void releaseNativePowerHAL();
 void publishNativePowerTrace();bool postNativePowerChangedIfNeeded();void publishNativePowerState();
 void setNativePowerStopping(bool);void unregistPM();bool retireNativePMPowerCallouts();
 IOReturn setPowerState(unsigned long,IOService*);
 IOReturn waitForNativePower(uint32_t,uint32_t);void wakeNativePowerWaiters();
 IOReturn disableAdapterWithRetry(uint32_t,uint32_t);
 static IOReturn nativePowerStopAction(OSObject*,void*,void*,void*,void*);
 static IOReturn nativePowerAction(OSObject*,void*,void*,void*,void*);
 IOReturn enable(IO80211SkywalkInterface*);
 IOReturn enableAdapter(IONetworkInterface*);IOReturn disableAdapter(IONetworkInterface*);
 Gate*getCommandGate(){return _fCommandGate;}
 void setPowerStateOff();void setPowerStateOn();
};
struct TestNativeBackend {bool ready=false;unsigned driverStateCalls=0;
 void driverState(bool value){ready=value;++driverStateCalls;}};
struct AirportItlwmSkywalkInterface {AirportItlwm*instance=nullptr;
 TestNativeBackend*nativeBackend=nullptr;};
struct Fixture {AirportItlwm a;HAL hal;Queue q;Gate gate;NativeIF net;IONetworkInterface bsd;Timer timer;
IOService pm;Fixture():gate{&a,&q},net{&q}{_fWorkloop=&q;_fCommandGate=&gate;a.fHalService=&hal;
 a.powerOffThreadCall=&a.offCall;a.powerOnThreadCall=&a.onCall;
 a.pmPolicyMaker=&pm;
 hal.publicEpoch=&a.nativePowerEpoch;
 assert(a.init(nullptr));
 a.fNetIf=&net;a.bsdInterface=&bsd;a.watchdogTimer=&timer;
 gate.onSleep=[this]{assert(!q.gated);ready();q.gated=true;a.wakeNativePowerWaiters();q.gated=false;};}
 apple80211_power_data request(unsigned value){return {1,4,{value,value,value,value}};}
 unsigned state(){apple80211_power_data p{};assert(a.getPOWER(nullptr,&p)==0);
 assert(p.version==1&&p.num_radios==4);for(auto r:p.power_state)assert(r==p.power_state[0]);return p.power_state[0];}
 void pmOff(){Queue*oldGate=g_activeCommandGate;const bool oldGated=q.gated;
  g_activeCommandGate=&q;q.gated=true;a.setPowerStateOff();q.gated=oldGated;g_activeCommandGate=oldGate;}
 void pmOn(){Queue*oldGate=g_activeCommandGate;const bool oldGated=q.gated;
  g_activeCommandGate=&q;q.gated=true;a.setPowerStateOn();q.gated=oldGated;g_activeCommandGate=oldGate;}
 void ready(){hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;irq=true;a.observeNativePowerEvent(6);irq=false;}
};
'''
ingress_source=(ROOT/'native/wcl_backend.cpp').read_text()
methods.extend('\nnamespace NativeWifi {\n'+function_from(ingress_source,marker)+'\n}\n'
 for marker in ['bool Ingress::signal(unsigned','bool Ingress::append(unsigned'])
consumer_source=(ROOT/'AirportItlwm/AirportItlwmSkywalkInterface.cpp').read_text()
consumer_start=consumer_source.index(
    '            const bool staleRetiredTransaction =',
    consumer_source.index('void AirportItlwmSkywalkInterface::consumeNative('))
consumer_end_marker='                self->instance->postNativePowerChangedIfNeeded();'
consumer_end=consumer_source.index(consumer_end_marker,consumer_start)+len(consumer_end_marker)
consumer_snippet=consumer_source[consumer_start:consumer_end]
consumer_shim='''\nstatic void consumePowerDecision(AirportItlwmSkywalkInterface *self, bool ready,\n    NativePowerTrace::AddressRestartDecision decision) {\n    auto backend = self->nativeBackend;\n'''+consumer_snippet+'''\n}\n'''
main=r'''

int main(){unsigned scenarios=0;
 {Fixture f;f.a.nativePowerFlags=1U;f.hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;
  f.pmOff();
  assert(f.a.pmPowerState==kPowerStateOff&&f.hal.ic.ic_if.if_flags==0&&
   f.hal.disabled==1&&f.pm.acknowledgements==1);
  f.pmOn();
  assert(f.a.pmPowerState==kPowerStateOn&&f.hal.enabled==1&&
   f.hal.ic.ic_if.if_flags==IFF_UP&&f.timer.started==1&&
   f.pm.acknowledgements==2);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count==8&&trace.schemaVersion==1&&trace.capacity==32);
  assert(trace.entries[0].operation==uint32_t(NativePowerTrace::Operation::kSystemPower)&&
   trace.entries[0].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerBegin)&&
   trace.entries[0].detail==uint32_t(NativePowerTrace::SystemPowerDetail::kSleep));
  assert(trace.entries[1].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAdapterEnd)&&
   trace.entries[1].result==kIOReturnSuccess&&trace.entries[1].interfaceFlags==0);
  assert(trace.entries[2].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAck));
  assert(trace.entries[3].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerBegin)&&
   trace.entries[3].detail==uint32_t(NativePowerTrace::SystemPowerDetail::kWake));
  assert(trace.entries[4].phase==uint32_t(NativePowerTrace::Phase::kWakeRestoreDecision)&&
   trace.entries[4].detail==uint32_t(NativePowerTrace::SystemPowerDetail::kWakeRestoreAttempt));
  assert(trace.entries[5].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAdapterEnd)&&
   trace.entries[5].result==kIOReturnSuccess&&trace.entries[5].interfaceFlags==IFF_UP);
  assert(trace.entries[6].phase==uint32_t(NativePowerTrace::Phase::kWakeRestoreEnd)&&
   trace.entries[6].detail==uint32_t(
    NativePowerTrace::SystemPowerDetail::kWakeRestoreAttempt)&&
   trace.entries[6].result==kIOReturnSuccess);
  assert(trace.entries[7].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAck));
  assert(trace.entries[0].callId==trace.entries[1].callId&&
   trace.entries[1].callId==trace.entries[2].callId&&
   trace.entries[3].callId==trace.entries[4].callId&&
   trace.entries[4].callId==trace.entries[6].callId&&
   trace.entries[6].callId==trace.entries[7].callId);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=0;f.hal.ic.ic_if.if_flags=0;
  f.pmOn();
  assert(f.hal.enabled==0&&f.hal.ic.ic_if.if_flags==0&&
   f.pm.acknowledgements==1);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1U;f.hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;
  f.pmOn();
  assert(f.hal.enabled==0&&f.pm.acknowledgements==1);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count==4&&trace.entries[1].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kWakeAlreadyActive));++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1U;f.hal.ic.ic_if.if_flags=IFF_UP;
  f.pmOn();
  assert(f.hal.enabled==0&&f.hal.ic.ic_if.if_flags==IFF_UP&&
   f.pm.acknowledgements==1);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count==4&&trace.entries[1].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kWakePartialInterface));++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1U;f.a.nativePowerStopping=true;
  f.pmOn();assert(f.hal.enabled==0&&f.pm.acknowledgements==1);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count==4&&trace.entries[1].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kWakeStopping));++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1U;f.hal.result=kIOReturnError;
  f.pmOn();assert(f.hal.enabled==1&&f.pm.acknowledgements==1&&
   f.hal.ic.ic_if.if_flags==0);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count==5&&trace.entries[1].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kWakeRestoreAttempt)&&
   trace.entries[2].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAdapterEnd)&&
   trace.entries[2].result==kIOReturnError&&
   trace.entries[3].phase==uint32_t(NativePowerTrace::Phase::kWakeRestoreEnd)&&
   trace.entries[3].result==kIOReturnError&&
   trace.entries[4].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAck));++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1U;f.hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;
  auto off=f.request(0);assert(f.a.setPOWER(nullptr,&off)==0);
  assert(f.a.nativePowerFlags==0&&f.hal.disabled==1);
  f.pmOn();assert(f.hal.enabled==0&&f.pm.acknowledgements==1);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count>=7&&trace.entries[trace.count-3].phase==uint32_t(
   NativePowerTrace::Phase::kWakeRestoreDecision)&&
   trace.entries[trace.count-3].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kWakeRequestedOff));++scenarios;}
 {Fixture f;f.a.nativePowerPMRequestValid=true;
  f.a.nativePowerPMRequestedState=kPowerStateOff;f.a.nativePowerPMRequestEpoch=10;
  f.a.pmPowerState=kPowerStateOff;
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==5000000&&f.a.onCall.pending&&
   f.a.retained==1&&f.a.released==0);
  f.a.setNativePowerStopping(true);
  assert(f.a.setPowerState(kPowerStateOff,&f.pm)==IOPMAckImplied&&
   !f.a.offCall.pending&&f.a.onCall.pending);
  Queue*oldGate=g_activeCommandGate;g_activeCommandGate=&f.q;
  f.q.gated=true;assert(!f.a.retireNativePMPowerCallouts());
  assert(f.a.onCall.pending&&f.pm.acknowledgements==0&&f.a.released==0);
  f.q.gated=false;g_activeCommandGate=oldGate;
  assert(f.a.retireNativePMPowerCallouts());
  assert(!f.a.offCall.pending&&!f.a.onCall.pending&&f.a.offCall.freed&&
   f.a.onCall.freed&&f.pm.acknowledgements==1&&
   f.a.retained==1&&f.a.released==1);
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==IOPMAckImplied&&
   f.pm.acknowledgements==1);++scenarios;}
 {Fixture f;f.a.setNativePowerStopping(true);Queue*oldLoop=_fWorkloop;
  f.a.powerOffThreadCall=nullptr;f.a.powerOnThreadCall=nullptr;
  _fWorkloop=nullptr;assert(f.a.retireNativePMPowerCallouts());
  _fWorkloop=oldLoop;++scenarios;}
 {Fixture f;f.a.nativePowerStopping=true;f.a.nativePowerPMRequestValid=true;
  f.a.nativePowerPMRequestedState=kPowerStateOff;f.a.nativePowerPMRequestEpoch=1;
  f.a.nativePowerPMOffCalloutEpoch=1;f.a.retained=2;
  f.a.offCall.active=true;f.a.offCall.pending=true;
  f.a.offCall.callback=(void(*)(void*,void*))handleSetPowerStateOff;
  f.a.offCall.param0=&f.a;
  assert(f.a.retireNativePMPowerCallouts());
  assert(f.a.offCall.freed&&!f.a.offCall.active&&!f.a.offCall.pending&&
   f.pm.acknowledgements==2&&f.a.retained==2&&f.a.released==2);++scenarios;}
 {Fixture f;f.a.nativePowerStopping=true;f.a.nativePowerPMRequestValid=true;
  f.a.nativePowerPMRequestedState=kPowerStateOff;f.a.nativePowerPMRequestEpoch=1;
  f.a.nativePowerPMOffCalloutEpoch=1;f.a.retained=3;
  f.a.offCall.active=true;f.a.offCall.pending=true;
  f.a.offCall.pendingAgainAfterCancelWait=true;
  f.a.offCall.callback=(void(*)(void*,void*))handleSetPowerStateOff;
  f.a.offCall.param0=&f.a;
  assert(!f.a.retireNativePMPowerCallouts());
  assert(f.a.offCall.active&&!f.a.offCall.pending&&!f.a.offCall.freed&&
   f.pm.acknowledgements==2&&f.a.released==2&&f.a.retained==3);
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==IOPMAckImplied&&
   !f.a.onCall.pending);
  assert(f.a.retireNativePMPowerCallouts());
  assert(f.a.offCall.freed&&!f.a.offCall.active&&f.pm.acknowledgements==3&&
   f.a.retained==3&&f.a.released==3);++scenarios;}
 {Fixture f;f.a.nativePowerPMRequestValid=true;
  f.a.nativePowerPMRequestedState=kPowerStateOff;f.a.nativePowerPMRequestEpoch=1;
  f.a.pmPowerState=kPowerStateOff;f.a.nativePowerFlags=1U;
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==5000000);
  const uint32_t onEpoch=f.a.nativePowerPMRequestEpoch;
  assert(f.a.setPowerState(kPowerStateOff,&f.pm)==5000000&&
   f.a.nativePowerPMRequestEpoch==onEpoch+1&&f.a.offCall.pending);
  f.a.onCall.pending=false;handleSetPowerStateOn(&f.a,nullptr);
  assert(f.hal.enabled==0&&f.pm.acknowledgements==1&&
   f.a.nativePowerPMRequestedState==kPowerStateOff&&f.a.released==1);
  f.a.offCall.pending=false;handleSetPowerStateOff(&f.a,nullptr);
  assert(f.hal.disabled==1&&f.hal.ic.ic_if.if_flags==0&&
   f.a.pmPowerState==kPowerStateOff&&f.pm.acknowledgements==2&&
   f.a.retained==2&&f.a.released==2);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.count==7&&trace.entries[0].operation==uint32_t(
   NativePowerTrace::Operation::kSystemPower));
  assert(trace.entries[0].auxiliary==onEpoch&&
   trace.entries[0].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerBegin));
  assert(trace.entries[1].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kWakeSupersededByNewerOff)&&
   trace.entries[1].auxiliary==onEpoch&&trace.entries[1].result==kIOReturnAborted);
  assert(trace.entries[4].auxiliary==onEpoch+1&&
   trace.entries[6].phase==uint32_t(NativePowerTrace::Phase::kSystemPowerAck));++scenarios;}
 {Fixture f;f.a.nativePowerPMRequestValid=true;
  f.a.nativePowerPMRequestedState=kPowerStateOn;f.a.nativePowerPMRequestEpoch=1;
  f.a.nativePowerFlags=1U;f.a.pmPowerState=kPowerStateOn;
  assert(f.a.setPowerState(kPowerStateOff,&f.pm)==5000000);
  const uint32_t offEpoch=f.a.nativePowerPMRequestEpoch;
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==5000000&&
   f.a.nativePowerPMRequestEpoch==offEpoch+1&&f.a.onCall.pending);
  f.a.offCall.pending=false;handleSetPowerStateOff(&f.a,nullptr);
  assert(f.hal.disabled==0&&f.pm.acknowledgements==1&&f.a.released==1);
  f.a.onCall.pending=false;handleSetPowerStateOn(&f.a,nullptr);
  assert(f.hal.enabled==1&&f.hal.ic.ic_if.if_flags==IFF_UP&&
   f.pm.acknowledgements==2&&f.a.retained==2&&f.a.released==2);
  NativePowerTrace::Snapshot trace{};f.a.nativePowerTrace.snapshot(&trace);
  assert(trace.entries[0].auxiliary==offEpoch&&trace.entries[1].detail==uint32_t(
   NativePowerTrace::SystemPowerDetail::kSleepSupersededByNewerOn)&&
   trace.entries[1].result==kIOReturnAborted);++scenarios;}
 {Fixture f;f.a.pmPowerState=kPowerStateOff;
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==5000000&&f.a.onCall.pending&&
   f.a.retained==1&&f.a.released==0);
  // The stop latch and enqueue share nativePowerStateLock. Once latched, PM
  // requests return an implied ack and cannot repopulate a drained callout.
  f.a.setNativePowerStopping(true);
  assert(f.a.setPowerState(kPowerStateOff,&f.pm)==IOPMAckImplied&&
   !f.a.offCall.pending&&f.a.onCall.pending);
  f.a.unregistPM();
  assert(!f.a.offCall.pending&&!f.a.onCall.pending&&f.a.offCall.freed&&
   f.a.onCall.freed&&f.pm.acknowledgements==1);
  assert(f.a.setPowerState(kPowerStateOn,&f.pm)==IOPMAckImplied&&
   f.pm.acknowledgements==1);
  f.a.unregistPM();assert(f.pm.acknowledgements==1);++scenarios;}
 {parentInitResult=false;const int attempts=lockAllocationAttempts;AirportItlwm failed;
 assert(!failed.init(nullptr)&&!failed.nativePowerStateLock&&!failed.nativePowerTraceLock);
 assert(lockAllocationAttempts==attempts);parentInitResult=true;++scenarios;}
 {lockAllocationFailAt=lockAllocationAttempts;AirportItlwm failed;
 assert(!failed.init(nullptr)&&!failed.nativePowerStateLock&&!failed.nativePowerTraceLock);
 lockAllocationFailAt=-1;++scenarios;}
 {lockAllocationFailAt=lockAllocationAttempts+1;AirportItlwm failed;
 assert(!failed.init(nullptr)&&!failed.nativePowerStateLock&&!failed.nativePowerTraceLock);
 lockAllocationFailAt=-1;++scenarios;}
 {AirportItlwm failed;failed.nativePowerTraceLock=IOSimpleLockAlloc();
 lockAllocationFailAt=lockAllocationAttempts;
 assert(!failed.initializeNativePowerLocks()&&!failed.nativePowerStateLock&&
  !failed.nativePowerTraceLock);lockAllocationFailAt=-1;++scenarios;}
 {Fixture f;assert(f.state()==0&&f.a.nativePowerGetCount==1);++scenarios;}
 {Fixture f;f.a.updateNativePowerFlags(0,1U);
  assert(f.a.nativePowerFlags==1U&&f.state()==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;f.hal.faultSerial=11;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(2U,0);
  assert(f.a.nativePowerFlags==1U&&f.state()==1);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;f.hal.faultSerial=11;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(2U,0);++f.hal.faultSerial;
  assert(f.state()==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;f.hal.faultSerial=11;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(2U,0);
  g_uptimeNanoseconds=f.a.nativeAddressRestartNotification.deadlineNanoseconds();
  assert(f.state()==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;f.hal.faultSerial=11;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(2U,0);
  __atomic_store_n(&f.a.pmPowerState,kPowerStateOff,__ATOMIC_RELEASE);
  assert(f.state()==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.updateNativePowerFlags(1U,0);
  assert(f.a.nativePowerFlags==2U&&f.state()==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED);
  assert(f.a.nativePowerFlags==1U&&f.state()==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;f.hal.faultSerial=11;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(!f.a.commitNativeAddressRestartNotification(id,false,true));
  f.a.updateNativePowerFlags(2U,0);
  assert(f.state()==0);++scenarios;}
 {Fixture f;std::atomic<unsigned> destroyed{0},released{0};
  auto *heapHal=new HAL();heapHal->publicEpoch=&f.a.nativePowerEpoch;
  heapHal->destroyCount=&destroyed;heapHal->releaseCount=&released;
  heapHal->deleteOnRelease=true;f.a.fHalService=heapHal;
  f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;heapHal->faultSerial=11;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(2U,0);
  {std::lock_guard<std::mutex> guard(heapHal->faultReadMutex);
   heapHal->blockFaultRead=true;}
  std::atomic<unsigned> reported{99};
  std::thread reader([&]{reported.store(f.state(),std::memory_order_release);});
  {std::unique_lock<std::mutex> guard(heapHal->faultReadMutex);
   heapHal->faultReadCondition.wait(guard,[&]{return heapHal->faultReadEntered;});}
  std::thread teardown([&]{f.a.releaseNativePowerHAL();});
  while(f.a.nativePowerStateLock->waiters.load(std::memory_order_acquire)==0)
   std::this_thread::yield();
  assert(destroyed.load(std::memory_order_acquire)==0&&
   released.load(std::memory_order_acquire)==0);
  {std::lock_guard<std::mutex> guard(heapHal->faultReadMutex);
   heapHal->allowFaultRead=true;}
  heapHal->faultReadCondition.notify_all();
  reader.join();teardown.join();
  assert(reported.load(std::memory_order_acquire)==1);
  assert(destroyed.load(std::memory_order_acquire)==1&&
   released.load(std::memory_order_acquire)>=1&&
   released.load(std::memory_order_acquire)<=2&&f.a.fHalService==nullptr);
  assert(!(f.a.nativePowerFlags&1U)&&f.state()==0);++scenarios;}
 {Fixture f;const uint32_t onEpoch=f.a.advanceNativePowerEpoch(true);
 assert(onEpoch==1&&f.hal.requestUpdates==1&&f.hal.requestEpoch==onEpoch&&f.hal.requestOn);
 assert(f.hal.observedPublicEpoch==0);
 const uint32_t offEpoch=f.a.advanceNativePowerEpoch(false);
 assert(offEpoch==2&&f.hal.requestUpdates==2&&f.hal.requestEpoch==offEpoch&&!f.hal.requestOn);
 assert(f.hal.observedPublicEpoch==onEpoch&&f.a.nativePowerEpoch==offEpoch);
 assert(f.hal.requestHistory.size()==2&&f.hal.requestHistory[0]==std::make_pair(1U,true)&&
  f.hal.requestHistory[1]==std::make_pair(2U,false));++scenarios;}
 {Fixture f;auto p=f.request(1),copy=p;f.hal.result=kIOReturnError;
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnError&&!memcmp(&p,&copy,sizeof p));
 assert(!f.state()&&f.hal.enabled==1&&!f.gate.sleeps);
 assert(f.hal.requestUpdates==2&&f.hal.requestEpoch==f.a.nativePowerEpoch&&!f.hal.requestOn);
 assert(f.hal.requestHistory[0]==std::make_pair(1U,true)&&
  f.hal.requestHistory[1]==std::make_pair(1U,false));++scenarios;}
 {Fixture f;auto p=f.request(1);bool sawOff=false;
 f.gate.onSleep=[&]{assert(!f.q.gated);sawOff=f.state()==0;f.ready();};
 assert(f.a.setPOWER(nullptr,&p)==0&&sawOff&&f.state()==1&&f.gate.sleeps==1);
 assert(f.hal.requestOn&&f.hal.requestEpoch==f.a.nativePowerEpoch&&f.hal.requestUpdates==1);
 assert(f.hal.observedPublicEpoch+1==f.hal.requestEpoch);++scenarios;}
 {Fixture f;auto p=f.request(1);f.a.nativePowerFlags=1;f.hal.ic.ic_if.if_flags=IFF_UP;
 assert(f.a.setPOWER(nullptr,&p)==0&&f.hal.enabled==0&&f.gate.sleeps==1&&f.state()==1);++scenarios;}
 {Fixture f;auto p=f.request(1);assert(f.a.setPOWER(nullptr,&p)==0);
 assert(f.a.setPOWER(nullptr,&p)==0&&f.hal.enabled==1&&f.gate.sleeps==1);++scenarios;}
 {Fixture f;auto p=f.request(1);f.gate.onSleep=[&]{
 if(f.gate.sleeps==1){f.a.observeNativePowerEvent(7);assert(f.hal.ic.ic_if.if_flags==IFF_UP);}
 else f.ready();};
 assert(f.a.setPOWER(nullptr,&p)==0&&f.gate.sleeps==2&&f.hal.enabled==1);++scenarios;}
 {Fixture f;auto on=f.request(1);bool stopStarted=false;
 f.gate.onSleep=[&]{
  assert(!f.q.gated);
  if(stopStarted)return;
  stopStarted=true;
  // Model stop() publishing its admission latch while the original On is
  // asleep with the command gate yielded, then run its real terminal action.
  __atomic_store_n(&f.a.nativePowerStopping,true,__ATOMIC_RELEASE);
  assert(f.a.setPOWER(nullptr,&on)==kIOReturnNotReady);
  assert(f.gate.runAction(AirportItlwm::nativePowerStopAction,nullptr)==
   kIOReturnSuccess);
  assert(f.a.nativePowerEpoch==2&&f.a.nativePowerFlags==0&&
   !f.a.nativePowerOffPending&&f.gate.wakes==1);
 };
 assert(f.a.setPOWER(nullptr,&on)==kIOReturnAborted);
 assert(stopStarted&&f.a.nativePowerStopping&&f.a.nativePowerFlags==0&&
  f.a.nativePowerEpoch==2&&f.state()==0&&f.hal.enabled==1&&f.hal.disabled==0);
 // The gate action publishes policy only; the service stop owns one later
 // hardware disable after ingress has drained.
 assert(f.a.setPOWER(nullptr,&on)==kIOReturnNotReady&&f.hal.enabled==1);
 assert(f.a.disableAdapter(&f.bsd)==kIOReturnSuccess&&f.hal.disabled==1);
 ++scenarios;}
 {Fixture f;auto p=f.request(1);f.gate.onSleep=[&]{f.hal.ic.ic_if.if_flags=0;f.a.observeNativePowerEvent(7);};
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnError&&f.state()==0);++scenarios;}
 {Fixture f;auto p=f.request(1);f.gate.sleepResult=THREAD_TIMED_OUT;f.gate.onSleep=[]{};
 const uint64_t waitStart=g_uptimeNanoseconds;
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnTimeout&&f.state()==0&&f.hal.enabled==1);
 assert(f.hal.ic.ic_if.if_flags==IFF_UP&&f.gate.sleeps==240);
 assert(g_uptimeNanoseconds-waitStart==12000000000ULL);++scenarios;}
 {Fixture f;auto p=f.request(1);bool readyWithoutWake=false;
 f.gate.sleepResult=THREAD_TIMED_OUT;
 f.gate.onSleep=[&]{if(!readyWithoutWake){readyWithoutWake=true;f.ready();}};
 const uint64_t waitStart=g_uptimeNanoseconds;
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnSuccess&&readyWithoutWake);
 assert(f.gate.sleeps==1&&g_uptimeNanoseconds-waitStart==50000000ULL);
 assert(f.state()==1&&f.hal.ic.ic_if.if_flags==(IFF_UP|IFF_RUNNING));++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);f.gate.onSleep=[&]{
 assert(f.a.setPOWER(nullptr,&off)==0);f.a.observeNativePowerEvent(6);};
 assert(f.a.setPOWER(nullptr,&on)==kIOReturnAborted&&f.state()==0&&f.a.nativePowerFlags==0);++scenarios;}
 {Fixture f;auto p=f.request(1);f.gate.onSleep=[&]{++f.a.nativePowerEpoch;f.ready();};
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnAborted);++scenarios;}
 {Fixture f;auto p=f.request(1);f.gate.sleepResult=2;f.gate.onSleep=[]{};
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnAborted&&f.state()==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 assert(f.a.setPOWER(nullptr,&off)==0&&f.state()==0&&f.hal.disabled==1&&f.gate.wakes>=1);
 assert(!f.hal.requestOn&&f.hal.requestEpoch==f.a.nativePowerEpoch&&f.hal.requestUpdates==2);
 assert(f.hal.requestHistory[0].second&&!f.hal.requestHistory[1].second);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=3;f.gate.onSleep=[]{ };
 const uint64_t offStart=g_uptimeNanoseconds;
 assert(f.a.setPOWER(nullptr,&off)==0&&f.state()==0&&f.hal.disabled==4);
 assert(f.gate.sleeps==4&&f.timer.stopped==1);
 assert(g_uptimeNanoseconds-offStart==75000000ULL);
 assert(f.a.metadata["NativePowerOffAttempts"]==4&&f.a.metadata["NativePowerOffRetries"]==3);
 assert(f.a.metadata["NativePowerOffResult"]==0&&f.a.metadata["NativePowerOffPending"]==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=1;f.gate.earlyWakeCount=5;f.gate.onSleep=[]{ };
 const uint64_t offStart=g_uptimeNanoseconds;
 assert(f.a.setPOWER(nullptr,&off)==0&&f.hal.disabled==2&&f.state()==0);
 assert(f.a.metadata["NativePowerOffAttempts"]==2&&f.a.metadata["NativePowerOffRetries"]==1);
 assert(f.gate.retrySleeps==6&&g_uptimeNanoseconds-offStart==25000000ULL);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 // A state task drains after more than the former 40-attempt window.
 f.hal.disableBusyCount=40;f.gate.onSleep=[]{ };
 const uint64_t offStart=g_uptimeNanoseconds;
 assert(f.a.setPOWER(nullptr,&off)==0&&f.state()==0&&f.hal.disabled==41);
 assert(f.gate.sleeps==41&&f.timer.stopped==1);
 assert(g_uptimeNanoseconds-offStart==1000000000ULL);
 assert(f.a.metadata["NativePowerOffAttempts"]==41&&f.a.metadata["NativePowerOffRetries"]==40);
 assert(f.a.metadata["NativePowerOffResult"]==0&&f.a.metadata["NativePowerOffPending"]==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 // A state task that never drains hits the caller deadline and leaves radio on.
 f.hal.disableBusyCount=600;f.gate.onSleep=[]{ };
 const uint64_t offStart=g_uptimeNanoseconds;
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnBusy&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&f.hal.disabled==480&&f.gate.sleeps==481);
 assert(f.a.metadata["NativePowerOffAttempts"]==480&&f.a.metadata["NativePowerOffRetries"]==480);
 assert(f.gate.retrySleeps==480&&g_uptimeNanoseconds-offStart==12000000000ULL);
 assert(f.a.metadata["NativePowerOffResult"]==uint32_t(kIOReturnBusy));
 assert(f.a.metadata["NativePowerOffPending"]==0&&f.timer.stopped==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=1;f.gate.onSleep=[&]{assert(f.a.setPOWER(nullptr,&on)==0);};
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnAborted&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&f.hal.disabled==1&&f.gate.sleeps==2);
 assert(f.timer.stopped==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=1;bool insideOn=false;
 f.gate.onSleep=[&]{
  if(!insideOn){insideOn=true;f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN);
   assert(!(f.a.nativePowerFlags&2U)&&f.a.offPending());
   f.a.publishNativePowerState();assert(f.a.metadata["NativePowerOffPending"]==1);
   assert(f.a.setPOWER(nullptr,&on)==0);}
  else f.ready();
 };
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnAborted&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&!f.a.offPending()&&f.hal.disabled==1);
 assert(f.a.nativePowerOffAttempts==1&&f.a.nativePowerOffRetries==1);
 assert(f.a.metadata["NativePowerOffAttempts"]==1&&f.a.metadata["NativePowerOffRetries"]==1);
 assert(f.a.metadata["NativePowerOffResult"]==uint32_t(kIOReturnNotReady));
 assert(f.a.metadata["NativePowerOffPending"]==0&&f.timer.stopped==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=1;f.gate.sleepResult=2;f.gate.onSleep=[]{ };
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnAborted&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&!f.a.offPending()&&f.hal.disabled==1);
 assert(f.a.metadata["NativePowerOffResult"]==uint32_t(kIOReturnAborted));
 assert(f.timer.stopped==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableResult=kIOReturnError;
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnError&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&!f.a.offPending()&&f.hal.disabled==1);
 assert(f.hal.requestOn&&f.hal.requestEpoch==f.a.nativePowerEpoch);
 assert(f.a.metadata["NativePowerOffResult"]==uint32_t(kIOReturnError));
 assert(f.timer.stopped==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=1;bool entered=false;
 f.gate.onSleep=[&]{if(!entered){entered=true;assert(f.a.setPOWER(nullptr,&off)==0);}};
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnAborted&&f.state()==0);
 assert(f.a.nativePowerFlags==0&&!f.a.offPending()&&f.hal.disabled==2);
 assert(f.a.metadata["NativePowerOffAttempts"]==1&&f.a.metadata["NativePowerOffRetries"]==0);
 assert(f.a.metadata["NativePowerOffResult"]==0);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableBusyCount=1;bool entered=false;
 f.gate.onSleep=[&]{if(!entered){entered=true;assert(f.a.setPOWER(nullptr,&on)==0);}};
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnAborted&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&!f.a.offPending()&&f.hal.disabled==1);
 assert(f.a.metadata["NativePowerOffResult"]==uint32_t(kIOReturnNotReady));++scenarios;}
 {Fixture f;auto p=f.request(1);p.num_radios=0;assert(f.a.setPOWER(nullptr,&p)==kIOReturnBadArgument);
 p.num_radios=5;assert(f.a.setPOWER(nullptr,&p)==kIOReturnBadArgument);
 p=f.request(2);assert(f.a.setPOWER(nullptr,&p)==kIOReturnUnsupported);
 p=f.request(1);p.power_state[2]=0;assert(f.a.setPOWER(nullptr,&p)==kIOReturnUnsupported);
 assert(f.hal.enabled==0);++scenarios;}
 {Fixture f;auto p=f.request(1);f.q.worker=true;assert(f.a.setPOWER(nullptr,&p)==kIOReturnNotReady);
 f.q.worker=false;f.gate.loseGate=true;assert(f.a.setPOWER(nullptr,&p)==kIOReturnNotReady);
 f.gate.loseGate=false;Queue foreign;f.net.q=&foreign;
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnNotReady&&f.hal.enabled==0);++scenarios;}
 {Fixture f;auto p=f.request(1);irq=true;assert(f.a.setPOWER(nullptr,&p)==kIOReturnNotReady);
 assert(f.hal.enabled==0&&f.a.properties==0);irq=false;++scenarios;}
 {Fixture f;auto p=f.request(1);p.num_radios=1;p.power_state[1]=0xffffffff;
 assert(f.a.setPOWER(nullptr,&p)==0&&f.hal.enabled==1);++scenarios;}
 {Fixture f;auto on=f.request(1),off=f.request(0);assert(f.a.setPOWER(nullptr,&on)==0);
 f.hal.disableResult=kIOReturnBusy;auto timerStops=f.timer.stopped;
 assert(f.a.setPOWER(nullptr,&off)==kIOReturnBusy&&f.state()==1);
 assert(f.a.nativePowerFlags==3&&f.timer.stopped==timerStops);
 f.hal.disableResult=0;assert(f.a.setPOWER(nullptr,&off)==0&&f.state()==0);++scenarios;}
 {Fixture f;assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 f.a.updateNativePowerFlags(0,1U);f.ready();assert(f.a.nativePowerTransitionRevision==1);
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);++scenarios;}
 {Fixture f;f.a.updateNativePowerFlags(0,1U);f.ready();
 const uint64_t revision=f.a.nativePowerTransitionRevision;
 f.a.updateNativePowerFlags(1U,0); // Requested changes do not revise actual READY.
 assert(f.a.nativePowerTransitionRevision==revision);
 f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY); // Late READY cannot override Off.
 assert(f.a.nativePowerTransitionRevision==revision&&f.a.nativePowerFlags==2U);
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {Fixture f;f.a.updateNativePowerFlags(0,1U);f.ready();
 assert(f.a.nativePowerTransitionRevision==1);
 f.ready();assert(f.a.nativePowerTransitionRevision==1); // Duplicate READY is not a transition.
 f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED);
 assert(f.a.nativePowerTransitionRevision==2);
 f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED); // Repeated Off is not a transition.
 assert(f.a.nativePowerTransitionRevision==2);
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {Fixture f;f.a.updateNativePowerFlags(0,1U);f.ready();
 f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED);f.ready();
 assert(f.a.nativePowerTransitionRevision==3);
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {Fixture f;assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 f.a.updateNativePowerFlags(0,1U);f.ready();
 f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED);
 assert(f.a.nativePowerTransitionRevision==2&&!(f.a.nativePowerFlags&2U));
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);++scenarios;}
 {Fixture f;f.a.updateNativePowerFlags(0,1U);
 f.net.onPost=[&]{f.net.onPost=nullptr;f.ready();};
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
 assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);
 assert(!f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);++scenarios;}
 {for(unsigned i=0;i<128;++i){Fixture f;auto off=f.request(0);f.a.nativePowerFlags=1;
 f.hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;std::thread ready([&]{f.a.observeNativePowerEvent(6);});
 assert(f.a.setPOWER(nullptr,&off)==0);ready.join();assert(f.state()==0&&f.a.nativePowerFlags==0);}++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=7;f.hal.faultSerial=5;
  NativePowerTrace::PowerIngressContext oldReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&oldReady);
  assert(oldReady.addressRestartId==0&&oldReady.powerEpoch==7&&oldReady.powerFlags==3);
  assert(f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id!=0);
  NativePowerTrace::PowerIngressContext reset{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN,&reset);
  assert(reset.addressRestartId==id&&reset.addressRestartStartRevision==0&&
   reset.transitionRevision==1&&reset.powerEpoch==7&&reset.faultSerial==5);
  assert(f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kDriverReady,oldReady)==
   NativePowerTrace::AddressRestartDecision::kStale);
  assert(f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartPublishedId==id);
  assert(f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kResetBegin,reset)==
   NativePowerTrace::AddressRestartDecision::kSuppress);
  NativePowerTrace::PowerIngressContext stopped{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED,&stopped);
  assert(stopped.addressRestartId==id&&f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kDriverStopped,stopped)==
   NativePowerTrace::AddressRestartDecision::kSuppress);
  assert(f.net.messages==1&&f.state()==0);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  NativePowerTrace::PowerIngressContext ready{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&ready);
  assert(ready.addressRestartId==id&&f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kDriverReady,ready)==
   NativePowerTrace::AddressRestartDecision::kComplete);
  assert(!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartPublishedId==0);
  assert(f.state()==1&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);
  assert(f.a.nativePowerNotificationState.lastPostedReady());
  assert(f.a.nativeAddressRestartStartedCount==1&&f.a.nativeAddressRestartSuppressedCount==2&&
   f.a.nativeAddressRestartCompletedCount==1&&f.a.nativeAddressRestartCancelledCount==0);
  assert(f.a.nativeAddressRestartLastOutcome==uint32_t(
   NativePowerTrace::AddressRestartOutcome::kCompletedReady));++scenarios;}
 {g_uptimeNanoseconds=900000000ULL;Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=3;
  assert(f.a.postNativePowerChangedIfNeeded());uint64_t id=0;
  assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  NativePowerTrace::PowerIngressContext reset{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN,&reset);
  assert(f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kResetBegin,reset)==
   NativePowerTrace::AddressRestartDecision::kSuppress);
  // A one-second watchdog tick only advances wall time by 100 ms since begin.
  g_uptimeNanoseconds=1000000000ULL;
  assert(f.a.tickNativeAddressRestartNotification()&&f.a.nativeAddressRestartNotification.active());
  assert(f.net.messages==1);
  g_uptimeNanoseconds=1800000000ULL;
  assert(!f.a.tickNativeAddressRestartNotification()&&!f.a.nativeAddressRestartNotification.active());
  assert(f.a.nativeAddressRestartExpiredCount==1&&f.a.nativeAddressRestartCancelledCount==0);
  assert(!f.state()&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);
  assert(!f.a.nativePowerNotificationState.lastPostedReady());++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=2;f.hal.faultSerial=11;
  assert(f.a.postNativePowerChangedIfNeeded());uint64_t id=0;
  assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  NativePowerTrace::PowerIngressContext reset{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN,&reset);
  assert(f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kResetBegin,reset)==
   NativePowerTrace::AddressRestartDecision::kSuppress);
  f.hal.faultSerial=12;
  NativePowerTrace::PowerIngressContext faultStop{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED,&faultStop);
  assert(faultStop.addressRestartId==id&&faultStop.faultSerial==12);
  assert(f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kDriverStopped,faultStop)==
   NativePowerTrace::AddressRestartDecision::kPass);
  assert(!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartPublishedId==0);
  assert(f.a.nativeAddressRestartCancelledCount==1&&f.a.nativeAddressRestartLastOutcome==uint32_t(
   NativePowerTrace::AddressRestartOutcome::kCancelledFaultSerial));
  assert(!f.state()&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);
  NativePowerTrace::PowerIngressContext freshReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&freshReady);
  assert(freshReady.addressRestartId==0&&f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kDriverReady,freshReady)==
   NativePowerTrace::AddressRestartDecision::kPass);
  assert(f.state()&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==3);
  assert(f.a.nativeAddressRestartCompletedCount==0);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=4;
  assert(f.a.postNativePowerChangedIfNeeded());uint64_t id=0;
  assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  NativePowerTrace::PowerIngressContext reset{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN,&reset);
  assert(f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kResetBegin,reset)==
   NativePowerTrace::AddressRestartDecision::kSuppress);
  assert(!f.a.commitNativeAddressRestartNotification(id,true,false));
  assert(!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartPublishedId==0);
  assert(f.a.nativeAddressRestartCancelledCount==1&&f.a.nativeAddressRestartLastOutcome==uint32_t(
   NativePowerTrace::AddressRestartOutcome::kCancelledCommitOrEnable));
  assert(!f.state()&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==2);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=8;f.hal.faultSerialAvailable=false;
  uint64_t id=0;
  assert(f.a.beginNativeAddressRestartNotification(&id)==kIOReturnUnsupported&&id==0);
  NativePowerTrace::PowerIngressContext reset{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN,&reset);
  assert(reset.addressRestartId==0&&f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kResetBegin,reset)==
   NativePowerTrace::AddressRestartDecision::kPass);
  assert(f.a.nativeAddressRestartLastOutcome==uint32_t(
   NativePowerTrace::AddressRestartOutcome::kUnsupportedHal));++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=9;uint64_t id=0;
  assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  f.a.updateNativePowerFlags(1U,0);const uint32_t epoch=f.a.advanceNativePowerEpoch(false);
  assert(epoch==10&&!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartPublishedId==0);
  NativePowerTrace::PowerIngressContext stopped{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED,&stopped);
  assert(stopped.addressRestartId==0&&stopped.powerEpoch==10&&
   f.a.observeNativeAddressRestartEvent(
    NativePowerTrace::AddressRestartEvent::kDriverStopped,stopped)==
    NativePowerTrace::AddressRestartDecision::kPass);
  assert(f.a.nativeAddressRestartCancelledCount==1&&f.a.nativeAddressRestartLastOutcome==uint32_t(
   NativePowerTrace::AddressRestartOutcome::kCancelledEpochOrOff));++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1;f.a.nativePowerEpoch=5;
  NativePowerTrace::PowerIngressContext oldReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&oldReady);
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));++f.hal.faultSerial;
  assert(f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
   oldReady)==NativePowerTrace::AddressRestartDecision::kStale);
  assert(!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartCancelledCount==1&&
   f.a.nativeAddressRestartLastOutcome==uint32_t(
    NativePowerTrace::AddressRestartOutcome::kCancelledFaultSerial));
  assert(f.state()==1&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1;f.a.nativePowerEpoch=5;
  NativePowerTrace::PowerIngressContext oldReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&oldReady);
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(1U,0);
  assert(f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
   oldReady)==NativePowerTrace::AddressRestartDecision::kStale);
  assert(!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartCancelledCount==1&&
   f.a.nativeAddressRestartLastOutcome==uint32_t(
    NativePowerTrace::AddressRestartOutcome::kCancelledEpochOrOff));
  assert(f.state()==0&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {g_uptimeNanoseconds=1500000000ULL;Fixture f;f.a.nativePowerFlags=1;f.a.nativePowerEpoch=5;
  NativePowerTrace::PowerIngressContext oldReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&oldReady);
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  g_uptimeNanoseconds=f.a.nativeAddressRestartNotification.deadlineNanoseconds();
  assert(f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
   oldReady)==NativePowerTrace::AddressRestartDecision::kStale);
  assert(!f.a.nativeAddressRestartNotification.active()&&f.a.nativeAddressRestartExpiredCount==1&&
   f.a.nativeAddressRestartLastOutcome==uint32_t(
    NativePowerTrace::AddressRestartOutcome::kExpired));
  assert(f.state()==1&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1;f.a.nativePowerEpoch=5;
  NativePowerTrace::PowerIngressContext oldReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&oldReady);
  assert(oldReady.transitionRevision==1&&oldReady.addressRestartId==0&&oldReady.powerFlags==3);
  NativeWifi::Ingress ingress;ingress.lock_=IOSimpleLockAlloc();ingress.call_=reinterpret_cast<void*>(1);
  const unsigned beforeCalls=g_threadCallEnterCount;
  assert(ingress.signal(ITL_TAHOE_EVT_DRIVER_READY,0,nullptr,0,&oldReady));
  assert(g_threadCallEnterCount==beforeCalls+1&&ingress.count_==1);
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  const auto queuedOldReady=ingress.entries_[0].powerContext;
  assert(queuedOldReady.addressRestartId==0&&
   f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
    queuedOldReady)==NativePowerTrace::AddressRestartDecision::kStale);
  assert(f.a.nativeAddressRestartNotification.active());
  NativePowerTrace::PowerIngressContext reset{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_RESET_BEGIN,&reset);
  assert(ingress.signal(ITL_TAHOE_EVT_RESET_BEGIN,0,nullptr,0,&reset));
  assert(ingress.entries_[1].powerContext.addressRestartId==id&&
   f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kResetBegin,
    ingress.entries_[1].powerContext)==NativePowerTrace::AddressRestartDecision::kSuppress);
  NativePowerTrace::PowerIngressContext ready{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&ready);
  assert(ingress.signal(ITL_TAHOE_EVT_DRIVER_READY,0,nullptr,0,&ready));
  assert(ingress.entries_[2].powerContext.addressRestartId==id&&
   f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
    ingress.entries_[2].powerContext)==NativePowerTrace::AddressRestartDecision::kComplete);
  assert(!f.a.nativeAddressRestartNotification.active());
  assert(f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
   queuedOldReady)==NativePowerTrace::AddressRestartDecision::kStale);
  assert(f.state()==1&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);
  IOSimpleLockFree(ingress.lock_);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=1;f.a.nativePowerEpoch=3;
  NativePowerTrace::PowerIngressContext oldReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&oldReady);
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  f.a.updateNativePowerFlags(1U,0);assert(f.a.advanceNativePowerEpoch(false)==4);
  assert(!f.a.nativeAddressRestartNotification.active());
  assert(f.a.observeNativeAddressRestartEvent(NativePowerTrace::AddressRestartEvent::kDriverReady,
   oldReady)==NativePowerTrace::AddressRestartDecision::kStale);
  assert(f.state()==0&&f.a.postNativePowerChangedIfNeeded()&&f.net.messages==1);++scenarios;}
 {Fixture f;f.a.nativePowerFlags=3;f.a.nativePowerEpoch=5;f.hal.faultSerial=7;
  uint64_t id=0;assert(f.a.beginNativeAddressRestartNotification(&id)==0&&id);
  assert(f.a.commitNativeAddressRestartNotification(id,true,true));
  NativePowerTrace::PowerIngressContext sameIdReady{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_READY,&sameIdReady);
  assert(sameIdReady.addressRestartId==id&&sameIdReady.faultSerial==7);
  NativeWifi::Ingress ingress;ingress.lock_=IOSimpleLockAlloc();ingress.call_=reinterpret_cast<void*>(1);
  assert(ingress.signal(ITL_TAHOE_EVT_DRIVER_READY,0,nullptr,0,&sameIdReady));
  ++f.hal.faultSerial;NativePowerTrace::PowerIngressContext currentStop{};
  f.a.observeNativePowerEvent(ITL_TAHOE_EVT_DRIVER_STOPPED,&currentStop);
  assert(currentStop.addressRestartId==id&&currentStop.faultSerial==8&&
   !(currentStop.powerFlags&2U));
  assert(ingress.signal(ITL_TAHOE_EVT_DRIVER_STOPPED,0,nullptr,0,&currentStop));
  const auto queuedReady=ingress.entries_[0].powerContext;
  const auto decision=f.a.observeNativeAddressRestartEvent(
   NativePowerTrace::AddressRestartEvent::kDriverReady,queuedReady);
  assert(decision==NativePowerTrace::AddressRestartDecision::kStale&&
   !f.a.nativeAddressRestartNotification.active());
  TestNativeBackend backend;AirportItlwmSkywalkInterface consumer{&f.a,&backend};
  f.q.gated=true;consumePowerDecision(&consumer,true,decision);f.q.gated=false;
  assert(!backend.ready&&backend.driverStateCalls==0&&f.net.messages==1&&
   !f.a.nativePowerNotificationState.lastPostedReady());
  IOSimpleLockFree(ingress.lock_);++scenarios;}
 printf("{\"actual_body_scenarios\":%u,\"concurrent_off_ready_iterations\":128,\"address_restart_scenarios\":12,\"ingress_ring_scenarios\":2,\"io_requests\":0}\n",scenarios);
}
'''
with tempfile.TemporaryDirectory(prefix='native-power-control-') as d:
    cpp=Path(d)/'test.cpp';exe=Path(d)/'test';cpp.write_text(shim+'\n'+'\n'.join(methods)+consumer_shim+main)
    subprocess.run(['xcrun','clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(ROOT),str(cpp),'-o',str(exe)],check=True)
    result=subprocess.check_output([str(exe)],text=True);print(result,end='')
print('source_sha256='+hashlib.sha256(source.encode()).hexdigest())
