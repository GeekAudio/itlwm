#!/usr/bin/env python3
"""Run production native security-event handling with the real WCL backend."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test082_auth_retry_cleanup import production_function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'AirportItlwm/AirportItlwmSkywalkInterface.cpp'
PREFIX = r'''
#include "native/wcl_backend.hpp"
#include <assert.h>
#include <string.h>
#include <vector>
enum { IEEE80211_EVT_STA_ASSOC_DONE=3, IEEE80211_EVT_STA_DEAUTH=4,
 IEEE80211_S_AUTH=2, IEEE80211_S_RUN=4, IEEE80211_F_RSNON=1 };
namespace NativeWifi {
struct IngressEntry { unsigned kind; uint32_t value, detail; uint8_t bssid[6]; };
}
struct Node { uint8_t ni_bssid[6]={2,0,0,0,0,1};
 bool ni_port_valid=false, ni_pmf_link_pending=false; };
struct Controller { Node *ic_bss; int ic_state=IEEE80211_S_AUTH; unsigned ic_flags=IEEE80211_F_RSNON;
 uint16_t ic_assoc_status=0; bool ic_tahoe_join_requested=true; };
struct Hal { Controller ic; Controller *get80211Controller(){return &ic;} };
struct IngressSpy {
 unsigned kind=0; uint32_t value=0, detail=0; uint8_t bssid[6]{};
 bool signal(unsigned k,uint32_t v,const uint8_t *b,uint32_t d) {
  kind=k;value=v;detail=d;if(b)memcpy(bssid,b,6);return true;
 }
};
class AirportItlwmSkywalkInterface {
public:
 NativeWifi::Backend *nativeBackend; Hal *fHalService; IngressSpy *nativeIngress;
 uint32_t nativeJoinEpoch=1;
 static bool consumeNativeSecurityEvent(void*,const NativeWifi::IngressEntry&);
 void captureNativeAuthorization(bool);
};
static unsigned associations, connections, links;
static NativeWifi::Status join(void*,const NativeWifi::JoinPlan&) {
 return NativeWifi::Status::Ok;
}
static void emit(void*,uint32_t kind,const void*,size_t) {
 associations += kind==NativeWifi::Association;
 connections += kind==NativeWifi::Connection;
 links += kind==NativeWifi::Link;
}
'''
CASES = r'''
int main() {
 using namespace NativeWifi;
 Backend backend; Operations ops{};ops.join=join;ops.emit=emit;
 backend.initialize(ops);backend.driverState(true);
 std::vector<uint8_t> wire(JoinWireSize);
 write16(wire.data()+0xc,2);write32(wire.data()+0x10,1);
 write32(wire.data()+0x1c,1);wire[0x20]='x';
 write32(wire.data()+0x214,1);wire[0x21c]=2;wire[0x221]=1;
 assert(backend.joinRequest(wire.data(),wire.size())==Status::Ok);
 Node node; Hal hal; hal.ic.ic_bss=&node; IngressSpy ingress;
 AirportItlwmSkywalkInterface self{&backend,&hal,&ingress};
 IngressEntry event{};event.kind=IEEE80211_EVT_STA_ASSOC_DONE;
 memcpy(event.bssid,node.ni_bssid,6);
 auto consume=[&]{return self.consumeNativeSecurityEvent(&self,event);};
 assert(consume() && !associations && hal.ic.ic_tahoe_join_requested);
 event.detail=1; assert(consume() && !associations); // current epoch, not RUN
 hal.ic.ic_state=IEEE80211_S_RUN;event.bssid[5]=9;
 assert(consume() && !associations && hal.ic.ic_tahoe_join_requested);
 node.ni_bssid[5]=9; // Live BSS differs from this request's target.
 assert(consume() && !associations && hal.ic.ic_tahoe_join_requested);
 node.ni_bssid[5]=event.bssid[5]=1;
 assert(consume() && associations==1 && !hal.ic.ic_tahoe_join_requested);
 assert(consume() && associations==1); // duplicate does not replay association
 uint8_t ssid[1]={'x'}, ies[2]={0,0}, frame[38]={0x80};
 Beacon beacon{ssid,node.ni_bssid,ies,frame,1,2,sizeof(frame),0x1006,100,0,6,-45,-95,50};
 backend.observeBeacon(beacon);
 event.kind=10;event.value=1;
 assert(consume() && !connections); // no current port authorization
 node.ni_port_valid=true;node.ni_pmf_link_pending=true;
 assert(consume() && !connections);
 node.ni_pmf_link_pending=false;event.detail=0;
 assert(consume() && !connections); // old credentials, even same BSSID
 event.detail=1;assert(consume() && connections==1 && links==1);
 event.value=0;assert(consume() && links==1); // old down, currently authorized
 node.ni_port_valid=false;assert(consume() && links==2);
 assert(backend.joinRequest(wire.data(),wire.size())==Status::Ok);
 self.nativeJoinEpoch=2;hal.ic.ic_tahoe_join_requested=true;
 event.kind=IEEE80211_EVT_STA_ASSOC_DONE;event.value=0;
 assert(consume() && associations==1 && hal.ic.ic_tahoe_join_requested);
 self.captureNativeAuthorization(true);
 assert(ingress.kind==10 && ingress.value==1 && ingress.detail==2 &&
        !memcmp(ingress.bssid,node.ni_bssid,6));
 event.kind=IEEE80211_EVT_STA_DEAUTH;event.detail=1;
 assert(consume() && links==2 && backend.joining());
 // Open connections authorize at real RUN, without an RSN controlled port.
 event.kind=IEEE80211_EVT_STA_ASSOC_DONE;event.detail=2;event.value=0;
 assert(consume() && associations==2);
 backend.observeBeacon(beacon);hal.ic.ic_flags=0;
 event.kind=10;event.value=1;
 assert(consume() && connections==2 && links==3);
 event.kind=99;assert(!consume());
}
'''

source = SOURCE.read_text()
consume = production_function(source, 'bool AirportItlwmSkywalkInterface::consumeNativeSecurityEvent(')
capture = production_function(source, 'void AirportItlwmSkywalkInterface::captureNativeAuthorization(')
assert 'ic->ic_bss ? ic->ic_bss->ni_bssid : nullptr, nativeJoinEpoch' in source
with tempfile.TemporaryDirectory(prefix='native-security-events-') as tmp:
    path = Path(tmp)
    (path/'test.cpp').write_text(PREFIX+'\n'+consume+'\n'+capture+'\n'+CASES)
    subprocess.run(['clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(ROOT),
        str(path/'test.cpp'),str(ROOT/'native/wcl_backend.cpp'),
        str(ROOT/'native/wcl_wire.cpp'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)
print('PASS: production native security-event epochs, live port proof, stale/duplicate rejection (ASan/UBSan)')
