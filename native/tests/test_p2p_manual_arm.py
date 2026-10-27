#!/usr/bin/env python3
"""Exercise the production admin-only manual arm boundary without driver IO."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[2]
def function(path,marker):
 text=(ROOT/path).read_text(); start=text.index(marker); opening=text.index('{',start); depth=1;end=opening+1
 while depth:
  depth+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[start:end]
methods=[function('AirportItlwm/AirportItlwmV2.cpp','IOReturn AirportItlwm::setProperties('),
 function('itlwm/hal_iwx/ItlIwxP2PProbe.cpp','static bool psfObservationProfileEnabled('),
 function('itlwm/hal_iwx/ItlIwxP2PProbe.cpp','static bool mifFollowupProfileEnabled('),
 function('itlwm/hal_iwx/ItlIwxP2PProbe.cpp','IOReturn ItlIwx::nativeP2pArmProbe('),
 function('itlwm/hal_iwx/ItlIwxP2PProbe.cpp','static bool manualProbeGateOpen('),
 function('itlwm/hal_iwx/ItlIwxP2PProbe.cpp','static bool probeEnabled('),
 function('itlwm/hal_iwx/ItlIwxP2PProbe.cpp','static bool txProbeEnabled(')]
shim=r"""
#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <cstdio>
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnUnsupported=1,kIOReturnBadArgument=2,kIOReturnNotReady=3,kIOReturnBusy=4;
struct OSObject { virtual ~OSObject()=default; };
OSObject yes,no;
OSObject* kOSBooleanTrue=&yes; OSObject* kOSBooleanFalse=&no;
struct OSDictionary:OSObject { std::map<std::string,OSObject*> data; OSObject*getObject(const char*k){auto i=data.find(k);return i==data.end()?nullptr:i->second;} unsigned getCount(){return data.size();} };
#define OSDynamicCast(T,x) dynamic_cast<T*>(x)
static int privilegeResult=0;static int privilegeChecks=0;
static void*current_task(){return reinterpret_cast<void*>(7);}
constexpr const char*kIOClientPrivilegeAdministrator="root";
struct IOUserClient {static int clientHasPrivilege(void*p,const char*k){assert(p==current_task());assert(std::string(k)=="root");++privilegeChecks;return privilegeResult;}};
struct IOEthernetController {OSDictionary props; OSObject*getProperty(const char*k){return props.getObject(k);}};
struct ItlIwx {uint32_t nativeP2pManualArmRequested_=0;IOEthernetController controller;IOEthernetController*getController(){return &controller;} IOReturn nativeP2pArmProbe();};
struct Parent {static int calls;IOReturn setProperties(OSObject*){++calls;return 55;}};int Parent::calls=0;
#define super Parent
struct AirportItlwm:Parent {ItlIwx*fHalService=nullptr;IOReturn setProperties(OSObject*);};
static void profile(ItlIwx&h){for(const char*k:{"NativeP2PManualTrigger","NativeP2PProbe","NativeP2PRocProbe","NativeP2PTxProbe"})h.controller.props.data[k]=kOSBooleanTrue;}
"""
tests=r"""
int main(){
 AirportItlwm a;ItlIwx h;a.fHalService=&h;profile(h);
 assert(!probeEnabled(&h,&h.controller)&&!txProbeEnabled(&h,&h.controller));
 OSDictionary request;request.data["NativeP2PArmOnce"]=kOSBooleanTrue;
 privilegeResult=99;assert(a.setProperties(&request)==99);assert(h.nativeP2pManualArmRequested_==0);assert(Parent::calls==0);
 privilegeResult=0;request.data["NativeP2PArmOnce"]=kOSBooleanFalse;assert(a.setProperties(&request)==kIOReturnBadArgument);
 request.data["NativeP2PArmOnce"]=kOSBooleanTrue;request.data["extra"]=kOSBooleanTrue;assert(a.setProperties(&request)==kIOReturnBadArgument);request.data.erase("extra");
 for(const char*k:{"NativeP2PManualTrigger","NativeP2PManualArmed","NativeP2PProbe","NativeP2PRocProbe","NativeP2PTxProbe","NativeP2PAwdlPsfObservationOnly","NativeP2PAwdlMifFollowup","NativeP2PGp2Observation"}){OSDictionary bypass;bypass.data[k]=kOSBooleanFalse;assert(a.setProperties(&bypass)==kIOReturnUnsupported);assert(h.nativeP2pManualArmRequested_==0);}
 a.fHalService=nullptr;assert(a.setProperties(&request)==kIOReturnNotReady);a.fHalService=&h;
 for(const char*k:{"NativeP2PManualTrigger","NativeP2PProbe","NativeP2PRocProbe","NativeP2PTxProbe"}){h.controller.props.data[k]=kOSBooleanFalse;assert(a.setProperties(&request)==kIOReturnUnsupported);assert(h.nativeP2pManualArmRequested_==0);h.controller.props.data[k]=kOSBooleanTrue;}
 assert(a.setProperties(&request)==kIOReturnSuccess);assert(h.nativeP2pManualArmRequested_==1);assert(probeEnabled(&h,&h.controller)&&txProbeEnabled(&h,&h.controller));
 assert(a.setProperties(&request)==kIOReturnBusy);assert(h.nativeP2pManualArmRequested_==1);
 OSObject ordinary;assert(a.setProperties(&ordinary)==55);assert(Parent::calls==1);
 // Atomic one-shot across concurrent authorized HAL calls; no second arm.
 ItlIwx concurrent;profile(concurrent);std::atomic<unsigned>success{0};std::vector<std::thread>threads;
 for(int i=0;i<32;++i)threads.emplace_back([&]{int r=concurrent.nativeP2pArmProbe();if(r==0)++success;else assert(r==kIOReturnBusy);});
 for(auto&t:threads)t.join();assert(success==1);assert(concurrent.nativeP2pManualArmRequested_==1);
 // Historical nonmanual profiles retain their former enabled/disabled behavior.
 ItlIwx legacy;legacy.controller.props.data["NativeP2PProbe"]=kOSBooleanTrue;
 assert(probeEnabled(&legacy,&legacy.controller));assert(!txProbeEnabled(&legacy,&legacy.controller));assert(legacy.nativeP2pArmProbe()==kIOReturnUnsupported);
 // Observation-only mode requires the full immutable/manual profile. A bad
 // PSF profile must not fall through to the legacy vendor-action TX path.
 ItlIwx malformed;profile(malformed);
 malformed.controller.props.data["NativeP2PAwdlPsfObservationOnly"]=kOSBooleanTrue;
 malformed.controller.props.data["NativeP2PRocProbe"]=kOSBooleanFalse;
 assert(!probeEnabled(&malformed,&malformed.controller));
 assert(!txProbeEnabled(&malformed,&malformed.controller));
 assert(malformed.nativeP2pArmProbe()==kIOReturnUnsupported);
 assert(malformed.nativeP2pManualArmRequested_==0);
 ItlIwx noManual;profile(noManual);
 noManual.controller.props.data["NativeP2PManualTrigger"]=kOSBooleanFalse;
 noManual.controller.props.data["NativeP2PAwdlPsfObservationOnly"]=kOSBooleanTrue;
 assert(!probeEnabled(&noManual,&noManual.controller));
 assert(!txProbeEnabled(&noManual,&noManual.controller));
 assert(noManual.nativeP2pArmProbe()==kIOReturnUnsupported);
 assert(noManual.nativeP2pManualArmRequested_==0);
 ItlIwx experiment;profile(experiment);
 experiment.controller.props.data["NativeP2PAwdlPsfObservationOnly"]=kOSBooleanTrue;
 assert(experiment.nativeP2pManualArmRequested_==0);
 assert(!probeEnabled(&experiment,&experiment.controller));
 assert(!txProbeEnabled(&experiment,&experiment.controller));
 assert(experiment.nativeP2pArmProbe()==kIOReturnSuccess);
 assert(experiment.nativeP2pManualArmRequested_==1);
 assert(probeEnabled(&experiment,&experiment.controller));
 assert(txProbeEnabled(&experiment,&experiment.controller));
 ItlIwx mifMissingPsf;profile(mifMissingPsf);
 mifMissingPsf.controller.props.data["NativeP2PAwdlMifFollowup"]=kOSBooleanTrue;
 assert(!probeEnabled(&mifMissingPsf,&mifMissingPsf.controller));
 assert(!txProbeEnabled(&mifMissingPsf,&mifMissingPsf.controller));
 assert(mifMissingPsf.nativeP2pArmProbe()==kIOReturnUnsupported);
 assert(mifMissingPsf.nativeP2pManualArmRequested_==0);
 ItlIwx mifProfile;profile(mifProfile);
 mifProfile.controller.props.data["NativeP2PAwdlPsfObservationOnly"]=kOSBooleanTrue;
 mifProfile.controller.props.data["NativeP2PAwdlMifFollowup"]=kOSBooleanTrue;
 assert(mifFollowupProfileEnabled(&mifProfile.controller));
 assert(mifProfile.nativeP2pArmProbe()==kIOReturnSuccess);
 assert(probeEnabled(&mifProfile,&mifProfile.controller));
 assert(txProbeEnabled(&mifProfile,&mifProfile.controller));
 puts("PASS: production manual-arm privilege, profile, no-bypass, and one-shot concurrency boundaries");
}
"""
with tempfile.TemporaryDirectory(prefix='itl-manual-arm-') as d:
 p=Path(d);(p/'test.cpp').write_text(shim+'\n'+'\n'.join(methods)+'\n'+tests)
 subprocess.run(['xcrun','clang++','-std=c++17','-fsanitize=address,undefined','-pthread',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
