#!/usr/bin/env python3
"""Exercise the actual native private-address transaction with HAL/KPI failures."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
source=(root/'AirportItlwm/AirportItlwmSkywalkInterface.cpp').read_text()
start=source.index('IOReturn AirportItlwmSkywalkInterface::applyNativeAddressGated(')
opening=source.index('{',start);end=opening+1;depth=1
while depth:
    depth+=(source[end]=='{')-(source[end]=='}');end+=1
body=source[start:end]
shim=r'''
#include <cstdint>
#include <cstring>
#include <cassert>
#include <functional>
#include <map>
#include <string>
#include <vector>
using IOReturn=int32_t;using UInt32=uint32_t;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnNotReady=-1,kIOReturnNotPermitted=-2,
 kIOReturnBadArgument=-3,kIOReturnBusy=-4,kIOReturnUnsupported=-5,
 kIOReturnError=-6,kIOReturnNoMemory=-7;
constexpr unsigned IFF_UP=1,IFF_RUNNING=64,ITL_TAHOE_SCAN_STOPPED=4;
constexpr bool kOSBooleanTrue=true,kOSBooleanFalse=false;
static const char*kIOMACAddress="IOMACAddress";
struct Queue{bool inside=true;bool inGate(){return inside;}};
struct Gate{Queue*q;Queue*getWorkLoop(){return q;}};static Gate*_fCommandGate;
struct IC;
struct Ifnet{IC*owner;uint32_t if_flags=0;};
struct IC{Ifnet ic_if;uint8_t ic_myaddr[6]{};unsigned phase=0;
 static uint32_t phaseOf(IC*p){return p->phase;}
 uint32_t(*ic_tahoe_scan_state)(IC*)=phaseOf;IC():ic_if{this,0}{}};
struct Backend{bool joining_=false,changing_=false,scanning=true;unsigned begins=0,drains=0;
 bool joining(){return joining_;}bool changingAddress(){return changing_;}
 void cancelAddressChange(){changing_=false;}
 void beginAddressChange(){changing_=true;++begins;}
 void addressHardwareStopped(){assert(changing_);++drains;scanning=false;}};
struct BSD{IC*ic;uint8_t address[6]{},property[6]{};bool present=true,propertyFail=false;int lladdrFail=0;
 void*getIfnet(){return present?this:nullptr;}
 bool setProperty(const char*key,void*p,unsigned n){assert(key==kIOMACAddress&&n==6);
  if(propertyFail)return false;memcpy(property,p,6);return true;}};
static int ifnet_set_lladdr(void*ptr,const void*p,unsigned n){auto b=static_cast<BSD*>(ptr);assert(n==6);
 if(memcmp(p,b->ic->ic_myaddr,6))assert(!b->ic->ic_if.if_flags);
 if(b->lladdrFail)return b->lladdrFail;memcpy(b->address,p,6);return 0;}
static void if_setlladdr(Ifnet*ifp,const void*p){assert(!ifp->if_flags);memcpy(ifp->owner->ic_myaddr,p,6);}
struct Controller{BSD*bsdInterface;bool requested=true;bool nativePowerRequested()const{return requested;}};
struct HAL{IC ic;unsigned disables=0,enables=0;IOReturn disableResult=0,enableResult=0;
 bool stopIncomplete=false;std::function<void()> onEnable;
 IC*get80211Controller(){return &ic;}
 IOReturn disable(BSD*){++disables;if(disableResult)return disableResult;
  if(!stopIncomplete){ic.ic_if.if_flags=0;ic.phase=ITL_TAHOE_SCAN_STOPPED;}return 0;}
 IOReturn enable(BSD*){++enables;if(onEnable)onEnable();if(enableResult)return enableResult;
 ic.ic_if.if_flags=IFF_UP;return 0;}};
struct Registration{uint8_t address[6]{};bool fail=false;};
namespace NativeWifi{static bool updateRegistrationAddress(void*,Registration&r,const uint8_t*p){
 if(r.fail)return false;memcpy(r.address,p,6);return true;}}
struct AirportItlwmSkywalkInterface{
 Backend*nativeBackend;Controller*instance;HAL*fHalService;
 bool addressQuarantined=false,addressWasRequested=false;
 uint8_t requestedAddress[6]{},permanentAddress[6]{0,1,2,3,4,5};Registration registrationState;
 std::map<std::string,uint32_t>meta;
 void setProperty(const char*k,uint32_t v,unsigned){meta[k]=v;}
 void setProperty(const char*k,bool v){meta[k]=v;}
 IOReturn applyNativeAddressGated(const void*,UInt32);
};
struct Fixture{Queue q;Gate gate{&q};Backend backend;HAL hal;BSD bsd;Controller controller;AirportItlwmSkywalkInterface a;
 uint8_t privateMAC[6]{2,3,4,5,6,7};
 Fixture():bsd{&hal.ic},controller{&bsd},a{&backend,&controller,&hal}{_fCommandGate=&gate;
  uint8_t old[6]{2,1,1,1,1,1};memcpy(hal.ic.ic_myaddr,old,6);memcpy(bsd.address,old,6);
  memcpy(bsd.property,old,6);memcpy(a.registrationState.address,old,6);
  hal.ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;hal.ic.phase=1;
  hal.onEnable=[this]{assert(coherent(privateMAC)&&backend.changing_&&backend.drains==1);};}
 bool coherent(const uint8_t*p){return !memcmp(p,hal.ic.ic_myaddr,6)&&!memcmp(p,bsd.address,6)
  &&!memcmp(p,bsd.property,6)&&!memcmp(p,a.registrationState.address,6)&&!memcmp(p,a.requestedAddress,6);}
};
'''
main=r'''
int main(){unsigned cases=0;
 {Fixture f;assert(f.a.applyNativeAddressGated(f.privateMAC,6)==0);
  assert(f.hal.disables==1&&f.hal.enables==1&&f.coherent(f.privateMAC));
  assert(!f.a.addressQuarantined&&f.a.addressWasRequested&&!f.backend.scanning);++cases;}
 {Fixture f;auto before=f.hal.disables;uint8_t old[6];memcpy(old,f.hal.ic.ic_myaddr,6);
  assert(f.a.applyNativeAddressGated(old,6)==0&&f.hal.disables==before&&!f.hal.enables);
  assert(f.coherent(old));++cases;}
 {Fixture f;f.hal.ic.ic_if.if_flags=0;f.hal.ic.phase=4;
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==0&&!f.hal.disables&&!f.hal.enables);
  assert(f.coherent(f.privateMAC)&&f.backend.changing_);++cases;}
 {Fixture f;f.controller.requested=false;uint8_t old[6];memcpy(old,f.hal.ic.ic_myaddr,6);
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==kIOReturnBusy);
  assert(!f.hal.disables&&!f.hal.enables&&!f.a.addressQuarantined&&!f.backend.changing_);
  assert(!memcmp(old,f.hal.ic.ic_myaddr,6)&&!memcmp(old,f.bsd.address,6));
  assert(!memcmp(old,f.bsd.property,6)&&!memcmp(old,f.a.registrationState.address,6));++cases;}
 {Fixture f;f.controller.requested=false;f.hal.ic.ic_if.if_flags=0;f.hal.ic.phase=4;
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==0&&!f.hal.disables&&!f.hal.enables);
  assert(f.coherent(f.privateMAC));++cases;}
 for(auto state:{0,1,2}){Fixture f;
  if(state==0)f.hal.ic.ic_if.if_flags=IFF_UP;
  if(state==1)f.backend.joining_=true;
  if(state==2)f.backend.changing_=true;
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==kIOReturnBusy&&!f.hal.disables&&!f.a.addressQuarantined);++cases;}
 for(auto failure:{0,1,2,3,4,5}){Fixture f;
  if(failure==0)f.hal.disableResult=-20;
  if(failure==1)f.hal.stopIncomplete=true;
  if(failure==2)f.bsd.lladdrFail=1;
  if(failure==3)f.bsd.propertyFail=true;
  if(failure==4)f.a.registrationState.fail=true;
  if(failure==5)f.hal.enableResult=-21;
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)!=0&&f.a.addressQuarantined);
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==kIOReturnNotPermitted);
  if(failure<5)assert(!f.hal.enables);++cases;}
 {Fixture f;f.hal.disableResult=kIOReturnBusy;
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==kIOReturnBusy);
  assert(!f.a.addressQuarantined&&!f.backend.changing_&&!f.hal.enables);
  assert(!memcmp(f.bsd.address,f.hal.ic.ic_myaddr,6));
  f.hal.disableResult=0;assert(f.a.applyNativeAddressGated(f.privateMAC,6)==0);
  assert(f.coherent(f.privateMAC)&&f.hal.disables==2);++cases;}
 {Fixture f;f.q.inside=false;
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==kIOReturnNotReady&&!f.hal.disables);++cases;}
 {Fixture f;uint8_t bad[6]{3,1,2,3,4,5};
  assert(f.a.applyNativeAddressGated(bad,6)==kIOReturnBadArgument&&!f.hal.disables);
  assert(f.a.applyNativeAddressGated(f.privateMAC,5)==kIOReturnBadArgument&&!f.hal.disables);++cases;}
 {Fixture f;memcpy(f.privateMAC,f.a.permanentAddress,6);
  assert(f.a.applyNativeAddressGated(f.privateMAC,6)==0&&f.coherent(f.a.permanentAddress));++cases;}
 assert(cases==18);
}
'''
with tempfile.TemporaryDirectory(prefix='native-address-quiesce-') as directory:
    p=Path(directory);cpp=p/'case.cpp';cpp.write_text(shim+body+main);exe=p/'case'
    subprocess.run(['xcrun','clang++','-std=c++14','-O1','-fsanitize=address,undefined',
        '-fno-omit-frame-pointer',str(cpp),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
print('PASS: 18 actual address-quiesce scenarios; requested-power guard, powered-off commit, all address layers and failures')
