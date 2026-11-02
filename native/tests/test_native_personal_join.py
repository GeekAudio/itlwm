#!/usr/bin/env python3
"""Run the production native join/leave bodies at the net80211 boundary."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test082_auth_retry_cleanup import production_function

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'AirportItlwm/AirportItlwmSkywalkInterface.cpp').read_text()
join = production_function(source, 'NativeWifi::Status AirportItlwmSkywalkInterface::radioJoin(')
leave = production_function(source, 'void AirportItlwmSkywalkInterface::radioLeave(')
clear = production_function(source, 'void AirportItlwmSkywalkInterface::radioClearCredentials(')
preamble = r'''
#include "native/wcl_backend.hpp"
#include <assert.h>
#include <string.h>
#include <errno.h>
enum { IFF_RUNNING=1, IEEE80211_F_AUTO_JOIN=1, IEEE80211_F_PSK=2,
 IEEE80211_F_MFPR=4, IEEE80211_F_DESBSSID=8, IEEE80211_C_MFP=16,
 IEEE80211_S_SCAN=1, IEEE80211_S_RUN=4, IEEE80211_WPA_PROTO_WPA2=2,
 IEEE80211_WPA_AKM_PSK=1, IEEE80211_WPA_AKM_SHA256_PSK=4,
 IEEE80211_WPA_AKM_SAE=16, IEEE80211_WPA_CIPHER_CCMP=8 };
struct ieee80211com {
 struct { int if_flags=IFF_RUNNING; } ic_if;
 unsigned ic_caps=IEEE80211_C_MFP, ic_flags=0;
 unsigned char ic_psk[32]{}, ic_des_essid[32]{}, ic_des_bssid[6]{};
 unsigned ic_des_esslen=0; int ic_state=IEEE80211_S_SCAN;
 bool ic_tahoe_join_requested=false, ic_tahoe_scan_requested=false;
 int (*ic_tahoe_scan_state)(ieee80211com*)=nullptr;
 int (*ic_newstate)(ieee80211com*, int, int)=nullptr;
};
struct ieee80211_wpaparams {
 unsigned i_enabled=0, i_protos=0, i_akms=0, i_ciphers=0, i_groupcipher=0;
};
static ieee80211_wpaparams parameters;
static unsigned scanCalls, clearCalls, saeCalls, deriveCalls;
static int setterError, stateError, configError;
static bool deriveError;
static unsigned char saePassword[64]; static size_t saeLength;
static bool allZero(const void *p, size_t n) {
 const auto b=static_cast<const unsigned char *>(p);
 for(size_t i=0;i<n;++i) if(b[i]) return false;
 return true;
}
static void ieee80211_sae_clear(ieee80211com*) {
 ++clearCalls; memset(saePassword,0,sizeof(saePassword)); saeLength=0;
}
static int ieee80211_sae_set_password(ieee80211com*,const uint8_t *p,size_t n) {
 ++saeCalls; if(setterError) return setterError;
 assert(n && n<=64); memcpy(saePassword,p,n);saeLength=n;return 0;
}
static void ieee80211_disable_rsn(ieee80211com*) {}
static void ieee80211_disable_wep(ieee80211com*) {}
static int ieee80211_ioctl_setwpaparms(ieee80211com*,ieee80211_wpaparams *p) {
 parameters=*p;return configError;
}
static void ieee80211_begin_scan(void*) { ++scanCalls; }
static int ieee80211_new_state(ieee80211com *ic,int state,int) {
 ic->ic_state=state;return 0;
}
namespace NativeWifi {
bool deriveWPA2Pmk(const uint8_t*,size_t,const uint8_t*,size_t,uint8_t *out) {
 ++deriveCalls; memset(out,0x3c,32);return !deriveError;
}
}
struct Hal {
 ieee80211com ic; bool busy=false;
 bool nativeP2pBusy() const {return busy;}
 ieee80211com *get80211Controller(){return &ic;}
};
class AirportItlwmSkywalkInterface {
public:
 Hal *fHalService; bool addressWasRequested=false, addressReady=true;
 unsigned current_authtype_lower=0,current_authtype_upper=0;
 unsigned nativeJoinEpoch=0;
 bool nativeAddressReady(bool){return addressReady;}
 static NativeWifi::Status radioJoin(void*,const NativeWifi::JoinPlan&);
 static void radioLeave(void*);
 static void radioClearCredentials(void*);
};
static int idle(ieee80211com*){return 0;}
static AirportItlwmSkywalkInterface *replacementOwner;
static NativeWifi::JoinPlan replacementPlan;
static bool replaceOnState;
static int newstate(ieee80211com *ic,int,int){
 if(replaceOnState){
  replaceOnState=false;ic->ic_state=IEEE80211_S_SCAN;
  assert(replacementOwner->radioJoin(replacementOwner,replacementPlan)==NativeWifi::Status::Ok);
 }
 return stateError;
}
'''
tests = r'''
int main(){
 Hal hal;hal.ic.ic_tahoe_scan_state=idle;hal.ic.ic_newstate=newstate;
 AirportItlwmSkywalkInterface self;self.fHalService=&hal;
 NativeWifi::JoinPlan p{};p.secured=true;p.authentication=NativeWifi::Authentication::Sae;
 p.upperAuth=0x1000;p.lowerAuth=1;p.pmfCapable=p.pmfRequired=true;
 p.passwordLength=64;memset(p.password,'z',64);p.ssidLength=1;p.ssid[0]='x';p.bssid[0]=2;
 memset(hal.ic.ic_psk,0x55,32);hal.ic.ic_caps=0;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Unsupported);
 assert(!clearCalls&&!saeCalls&&!scanCalls&&hal.ic.ic_psk[0]==0x55);
 hal.ic.ic_caps=IEEE80211_C_MFP;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Ok);
 assert(clearCalls==1&&saeCalls==1&&deriveCalls==0&&saeLength==64);
 assert(allZero(hal.ic.ic_psk,32)&&!(hal.ic.ic_flags&IEEE80211_F_PSK));
 assert(hal.ic.ic_flags&IEEE80211_F_MFPR);
 assert(parameters.i_akms==IEEE80211_WPA_AKM_SAE&&parameters.i_ciphers==IEEE80211_WPA_CIPHER_CCMP);
 assert(self.current_authtype_upper==0x1000&&hal.ic.ic_tahoe_join_requested&&scanCalls==1);
 // A subsequent PSK request retires SAE credentials and mandatory-PMF policy.
 p.authentication=NativeWifi::Authentication::Psk;p.upperAuth=8;p.pmfRequired=false;
 p.derivePmk=true;p.passwordLength=8;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Ok);
 assert(clearCalls==2&&!saeLength&&allZero(saePassword,64)&&deriveCalls==1);
 assert(parameters.i_akms==IEEE80211_WPA_AKM_PSK);
 assert((hal.ic.ic_flags&IEEE80211_F_PSK)&&!(hal.ic.ic_flags&IEEE80211_F_MFPR));
 assert(hal.ic.ic_psk[0]==0x3c);
 p.authentication=NativeWifi::Authentication::PskSha256;p.upperAuth=0x400;
 p.derivePmk=false;memset(p.pmk,0x7a,32);p.pmfRequired=true;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Ok);
 assert(parameters.i_akms==IEEE80211_WPA_AKM_SHA256_PSK&&hal.ic.ic_psk[0]==0x7a&&deriveCalls==1);
 self.radioLeave(&self);
 assert(!saeLength&&allZero(hal.ic.ic_psk,32)&&!hal.ic.ic_des_esslen);
 assert(!(hal.ic.ic_flags&(IEEE80211_F_MFPR|IEEE80211_F_PSK|IEEE80211_F_DESBSSID)));
 // Rejected/failed SAE never imports producer PMK bytes or starts a scan.
 p.authentication=NativeWifi::Authentication::Sae;p.upperAuth=0x1000;
 p.passwordLength=1;p.password[0]='x';setterError=ENOMEM;
 unsigned scans=scanCalls;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Failed&&scanCalls==scans);
 assert(allZero(hal.ic.ic_psk,32)&&!(hal.ic.ic_flags&IEEE80211_F_PSK));
 setterError=0;hal.ic.ic_state=IEEE80211_S_RUN;stateError=EIO;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Failed);
 assert(!saeLength&&allZero(saePassword,64)&&!hal.ic.ic_tahoe_join_requested);
 assert(!hal.ic.ic_des_esslen&&allZero(hal.ic.ic_des_essid,32)&&allZero(hal.ic.ic_des_bssid,6));
 assert(!(hal.ic.ic_flags&(IEEE80211_F_DESBSSID|IEEE80211_F_MFPR|IEEE80211_F_PSK)));
 assert(!self.current_authtype_lower&&!self.current_authtype_upper);
 // An earlier setup failure also retires a prior desired target.
 stateError=0;hal.ic.ic_state=IEEE80211_S_SCAN;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Ok);
 configError=EIO;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Failed);
 assert(!hal.ic.ic_des_esslen&&allZero(hal.ic.ic_des_bssid,6));
 assert(!(hal.ic.ic_flags&IEEE80211_F_DESBSSID)&&!hal.ic.ic_tahoe_join_requested);
 configError=0;
 p.authentication=NativeWifi::Authentication::Psk;p.derivePmk=true;deriveError=true;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Failed);
 assert(!hal.ic.ic_des_esslen&&allZero(hal.ic.ic_des_bssid,6)&&allZero(hal.ic.ic_psk,32));
 deriveError=false;p.authentication=NativeWifi::Authentication::Sae;p.derivePmk=false;
 // Async reset/failure cleanup clears configuration without a radio transition.
 stateError=0;hal.ic.ic_state=IEEE80211_S_SCAN;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Ok);
 scans=scanCalls;hal.ic.ic_state=IEEE80211_S_RUN;
 self.radioClearCredentials(&self);
 assert(scanCalls==scans&&hal.ic.ic_state==IEEE80211_S_RUN);
 assert(!saeLength&&allZero(saePassword,64)&&allZero(hal.ic.ic_psk,32));
 assert(!hal.ic.ic_tahoe_join_requested&&!hal.ic.ic_des_esslen);
 assert(!(hal.ic.ic_flags&(IEEE80211_F_PSK|IEEE80211_F_MFPR|IEEE80211_F_DESBSSID)));
 // Failure cleanup is scoped to the exact radio request epoch. Model a
 // synchronous boundary replacement: A's failure must not erase B's selection.
 replacementOwner=&self;replacementPlan=p;replacementPlan.ssid[0]='b';
 replacementPlan.bssid[5]=2;replacementPlan.password[0]='b';
 hal.ic.ic_state=IEEE80211_S_RUN;stateError=EIO;replaceOnState=true;
 const unsigned oldEpoch=self.nativeJoinEpoch;
 assert(self.radioJoin(&self,p)==NativeWifi::Status::Failed);
 assert(self.nativeJoinEpoch==oldEpoch+2);
 assert(hal.ic.ic_tahoe_join_requested&&hal.ic.ic_des_esslen==1&&hal.ic.ic_des_essid[0]=='b');
 assert(!memcmp(hal.ic.ic_des_bssid,replacementPlan.bssid,6));
 assert((hal.ic.ic_flags&IEEE80211_F_DESBSSID)&&saeLength==1&&saePassword[0]=='b');
 assert(self.current_authtype_upper==replacementPlan.upperAuth);
}
'''
with tempfile.TemporaryDirectory(prefix='native-personal-join-') as d:
    path = Path(d)
    (path/'test.cpp').write_text(preamble+'\n'+join+'\n'+leave+'\n'+clear+'\n'+tests)
    subprocess.run(['clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                    '-I',str(ROOT),str(path/'test.cpp'),str(ROOT/'native/wcl_wire.cpp'),
                    '-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)
print('PASS: production join/leave selection, mandatory PMF, SAE password ownership, no PSK fallback, and cleanup (ASan/UBSan)')
