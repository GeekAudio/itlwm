#!/usr/bin/env python3
"""Compile actual Tahoe power methods with host KPI shims; no driver or radio IO."""
from pathlib import Path
import subprocess,tempfile,hashlib,json
ROOT=Path(__file__).resolve().parents[2]
source=(ROOT/'AirportItlwm/AirportItlwmV2.cpp').read_text()
def function(marker):
    start=source.index(marker); opening=source.index('{',start); depth=1; end=opening+1
    while depth:
        depth += (source[end]=='{')-(source[end]=='}'); end+=1
    return source[start:end]
methods=[function(s) for s in [
    'IOReturn AirportItlwm::\ngetPOWER(',
    'void AirportItlwm::observeNativePowerEvent(',
    'void AirportItlwm::publishNativePowerState(',
    'IOReturn AirportItlwm::nativePowerAction(',
    'IOReturn AirportItlwm::waitForNativePower(',
    'IOReturn AirportItlwm::disableAdapterWithRetry(',
    'void AirportItlwm::wakeNativePowerWaiters(',
    'IOReturn AirportItlwm::\nsetPOWER(',
    'IOReturn AirportItlwm::enable(IO80211SkywalkInterface *netif)',
    'IOReturn AirportItlwm::enableAdapter(',
    'IOReturn AirportItlwm::disableAdapter(']]
shim=r'''
#include <cstdint>
#include <cstring>
#include <cassert>
#include <map>
#include <string>
#include <thread>
#include <cstdio>
#include <functional>
#define AIRPORT_TAHOE 1
#define XYLog(...) do {} while (0)
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
constexpr unsigned ITL_TAHOE_EVT_DRIVER_READY=6,ITL_TAHOE_EVT_DRIVER_STOPPED=7,ITL_TAHOE_EVT_RESET_BEGIN=8;
constexpr unsigned IFF_UP=1,IFF_RUNNING=0x40,kWatchDogTimerPeriod=1000;
static bool irq=false;
static bool ml_at_interrupt_context(){return irq;}
struct OSObject {virtual ~OSObject()=default;};
#define OSDynamicCast(T,p) dynamic_cast<T*>(p)
struct apple80211_power_data {uint32_t version,num_radios,power_state[4];};
struct IONetworkInterface:OSObject {};
struct FakeIC {struct {uint32_t if_flags=0;} ic_if;uint32_t ic_tahoe_init_stage=0;int32_t ic_tahoe_init_error=0; uint32_t(*ic_tahoe_scan_state)(FakeIC*)=nullptr;};
struct HAL {FakeIC ic;IOReturn result=0,disableResult=0;unsigned enabled=0,disabled=0,disableBusyCount=0;bool stuck=false;
 FakeIC*get80211Controller(){return &ic;}
 IOReturn enable(IONetworkInterface*){++enabled;if(result)return result;ic.ic_if.if_flags|=IFF_UP;return 0;}
 IOReturn disable(IONetworkInterface*){++disabled;if(disableBusyCount){--disableBusyCount;return kIOReturnBusy;}
 if(disableResult)return disableResult;if(!stuck)ic.ic_if.if_flags=0;return 0;}};
struct Timer {unsigned started=0,stopped=0;void setTimeoutMS(unsigned){}void enable(){++started;}
 void cancelTimeout(){++stopped;}void disable(){}};
struct Queue {bool gated=false,worker=false;bool inGate(){return gated;}bool onThread(){return worker;}};
struct NativeIF {Queue*q;Queue*getControllerWorkQueue(){return q;}};
using IO80211SkywalkInterface=NativeIF;
static Queue*_fWorkloop=nullptr;
struct Gate {using Action=IOReturn(*)(OSObject*,void*,void*,void*,void*);
 OSObject*owner;Queue*q;bool loseGate=false;void enable(){}
 unsigned sleeps=0,wakes=0,retrySleeps=0,earlyWakeCount=0;
 IOReturn sleepResult=THREAD_AWAKENED;std::function<void()> onSleep;
 IOReturn commandSleep(void*,AbsoluteTime deadline,unsigned flags) {
  assert(q->gated&&deadline>g_uptimeNanoseconds&&flags==THREAD_INTERRUPTIBLE);
  const uint64_t delay=deadline-g_uptimeNanoseconds;
  const bool retry=delay<=25000000ULL;if(retry)++retrySleeps;
  ++sleeps;q->gated=false;assert(onSleep);onSleep();assert(!q->gated);q->gated=true;
  if(retry&&earlyWakeCount){--earlyWakeCount;g_uptimeNanoseconds+=1000000ULL;
   return THREAD_AWAKENED;}
  if(sleepResult==THREAD_TIMED_OUT)g_uptimeNanoseconds=deadline;
  else g_uptimeNanoseconds+=delay<25000000ULL?delay:25000000ULL;
  return sleepResult;
 }
 void commandWakeup(void*,bool one){assert(q->gated&&!one);++wakes;}
 IOReturn runAction(Action action,void*a){const bool old=q->gated;q->gated=!loseGate;
 IOReturn r=action(owner,a,nullptr,nullptr,nullptr);q->gated=old;return r;}};
static Gate*_fCommandGate=nullptr;
struct AirportItlwm:OSObject {
 HAL*fHalService=nullptr;IONetworkInterface*bsdInterface=nullptr;NativeIF*fNetIf=nullptr;Timer*watchdogTimer=nullptr;
 uint8_t power_state=0;bool nativeActivationAttempted=false;
 uint32_t nativePowerFlags=0,nativePowerGetCount=0,nativePowerSetCount=0,
 nativePowerLastResult=uint32_t(kIOReturnNotReady),nativePowerLastEvent=0,
 nativePowerReadyCount=0,nativePowerStoppedCount=0,nativePowerResetCount=0,nativePowerEpoch=0,
 nativePowerOffAttempts=0,nativePowerOffRetries=0,nativePowerOffResult=uint32_t(kIOReturnNotReady);
 bool nativePowerOffPending=false;
 unsigned properties=0;std::map<std::string,uint64_t> metadata;
 bool offPending()const{return __atomic_load_n(&nativePowerOffPending,__ATOMIC_ACQUIRE);}
 void setProperty(const char*k,uint64_t value,unsigned){assert(!irq);++properties;metadata[k]=value;}
 IOReturn getPOWER(OSObject*,apple80211_power_data*);
 IOReturn setPOWER(OSObject*,apple80211_power_data*);
 void observeNativePowerEvent(int);void publishNativePowerState();
 IOReturn waitForNativePower(uint32_t);void wakeNativePowerWaiters();
 IOReturn disableAdapterWithRetry(uint32_t);
 static IOReturn nativePowerAction(OSObject*,void*,void*,void*,void*);
 IOReturn enable(IO80211SkywalkInterface*);
 IOReturn enableAdapter(IONetworkInterface*);IOReturn disableAdapter(IONetworkInterface*);
};
struct Fixture {AirportItlwm a;HAL hal;Queue q;Gate gate;NativeIF net;IONetworkInterface bsd;Timer timer;
 Fixture():gate{&a,&q},net{&q}{_fWorkloop=&q;_fCommandGate=&gate;a.fHalService=&hal;
 a.fNetIf=&net;a.bsdInterface=&bsd;a.watchdogTimer=&timer;
 gate.onSleep=[this]{assert(!q.gated);ready();q.gated=true;a.wakeNativePowerWaiters();q.gated=false;};}
 apple80211_power_data request(unsigned value){return {1,4,{value,value,value,value}};}
 unsigned state(){apple80211_power_data p{};assert(a.getPOWER(nullptr,&p)==0);
 assert(p.version==1&&p.num_radios==4);for(auto r:p.power_state)assert(r==p.power_state[0]);return p.power_state[0];}
 void ready(){hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;irq=true;a.observeNativePowerEvent(6);irq=false;}
};
'''
main=r'''

int main(){unsigned scenarios=0;
 {Fixture f;assert(f.state()==0&&f.a.nativePowerGetCount==1);++scenarios;}
 {Fixture f;auto p=f.request(1),copy=p;f.hal.result=kIOReturnError;
 assert(f.a.setPOWER(nullptr,&p)==kIOReturnError&&!memcmp(&p,&copy,sizeof p));
 assert(!f.state()&&f.hal.enabled==1&&!f.gate.sleeps);++scenarios;}
 {Fixture f;auto p=f.request(1);bool sawOff=false;
 f.gate.onSleep=[&]{assert(!f.q.gated);sawOff=f.state()==0;f.ready();};
 assert(f.a.setPOWER(nullptr,&p)==0&&sawOff&&f.state()==1&&f.gate.sleeps==1);++scenarios;}
 {Fixture f;auto p=f.request(1);f.a.nativePowerFlags=1;f.hal.ic.ic_if.if_flags=IFF_UP;
 assert(f.a.setPOWER(nullptr,&p)==0&&f.hal.enabled==0&&f.gate.sleeps==1&&f.state()==1);++scenarios;}
 {Fixture f;auto p=f.request(1);assert(f.a.setPOWER(nullptr,&p)==0);
 assert(f.a.setPOWER(nullptr,&p)==0&&f.hal.enabled==1&&f.gate.sleeps==1);++scenarios;}
 {Fixture f;auto p=f.request(1);f.gate.onSleep=[&]{
 if(f.gate.sleeps==1){f.a.observeNativePowerEvent(7);assert(f.hal.ic.ic_if.if_flags==IFF_UP);}
 else f.ready();};
 assert(f.a.setPOWER(nullptr,&p)==0&&f.gate.sleeps==2&&f.hal.enabled==1);++scenarios;}
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
 assert(f.a.setPOWER(nullptr,&off)==0&&f.state()==0&&f.hal.disabled==1&&f.gate.wakes>=1);++scenarios;}
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
 {for(unsigned i=0;i<128;++i){Fixture f;auto off=f.request(0);f.a.nativePowerFlags=1;
 f.hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;std::thread ready([&]{f.a.observeNativePowerEvent(6);});
 assert(f.a.setPOWER(nullptr,&off)==0);ready.join();assert(f.state()==0&&f.a.nativePowerFlags==0);}++scenarios;}
 printf("{\"actual_body_scenarios\":%u,\"concurrent_off_ready_iterations\":128,\"io_requests\":0}\n",scenarios);
}
'''
with tempfile.TemporaryDirectory(prefix='native-power-control-') as d:
    cpp=Path(d)/'test.cpp';exe=Path(d)/'test';cpp.write_text(shim+'\n'+'\n'.join(methods)+main)
    subprocess.run(['xcrun','clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(cpp),'-o',str(exe)],check=True)
    result=subprocess.check_output([str(exe)],text=True);print(result,end='')
print('source_sha256='+hashlib.sha256(source.encode()).hexdigest())
