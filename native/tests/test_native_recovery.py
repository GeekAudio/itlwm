#!/usr/bin/env python3
"""Run actual native policy and Intel terminal-init paths with fault injection."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]


def extract(path, marker):
    source = (root / path).read_text()
    start = source.index(marker)
    opening = source.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def extract_block(source, marker):
    start = source.index(marker)
    opening = source.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


policy = r'''
#include <cstdint>
#include <cassert>
#include <map>
#include <string>
using IOReturn = int32_t;
constexpr IOReturn kIOReturnSuccess=0, kIOReturnBadArgument=-1,
    kIOReturnNotReady=-2, kIOReturnUnsupported=-3;
struct apple80211_fastlane { uint8_t bytes[2]; };
struct AirportItlwmSkywalkInterface {
    bool prepared=true, capable=true; unsigned updates=0;
    std::map<std::string,uint32_t> metadata;
    void *getBSDInterface() { return prepared ? this : nullptr; }
    void setFastlaneCapable(bool enabled) { capable=enabled; ++updates; }
    void setProperty(const char *key,uint32_t value,unsigned bits) {
        assert(bits==32); metadata[key]=value;
    }
    IOReturn setWCL_UPDATE_FAST_LANE(apple80211_fastlane *);
};
'''
policy_main = r'''
int main() {
    AirportItlwmSkywalkInterface f;
    auto p = new apple80211_fastlane {};
    assert(f.setWCL_UPDATE_FAST_LANE(p)==0 && !f.capable && f.updates==1);
    assert(p->bytes[0]==0 && p->bytes[1]==0);
    f.prepared=false;
    assert(f.setWCL_UPDATE_FAST_LANE(p)==kIOReturnNotReady && f.updates==1);
    for (auto flags : {uint16_t(1),uint16_t(256),uint16_t(257),uint16_t(65535)}) {
        p->bytes[0]=uint8_t(flags);p->bytes[1]=uint8_t(flags>>8);
        assert(f.setWCL_UPDATE_FAST_LANE(p)==kIOReturnUnsupported && f.updates==1);
        assert(f.metadata.at("NativeFastLaneRequestFlags")==flags);
    }
    assert(f.setWCL_UPDATE_FAST_LANE(nullptr)==kIOReturnBadArgument);
    delete p;
}
'''

radio = r'''
#include "native/iwx_reset_trace.hpp"
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#define AIRPORT_TAHOE 1
#define XYLog(...) do {} while(0)
#define IOLog(...) do {} while(0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define container_of(p,T,m) reinterpret_cast<T*>(reinterpret_cast<char*>(p)-offsetof(T,m))
#define SEC_TO_NSEC(n) (n)
enum { IFF_UP=1,IFF_RUNNING=64,IWX_INVALID_QUEUE=255,
 IEEE80211_M_MONITOR=1,IEEE80211_S_INIT=0,IEEE80211_S_SCAN=1,IEEE80211_S_RUN=2,
 ITL_TAHOE_EVT_DRIVER_READY=6,ITL_TAHOE_EVT_DRIVER_STOPPED=7,ITL_TAHOE_EVT_RESET_BEGIN=8,
 IWX_FLAG_HW_ERR=1,IWX_FLAG_RFKILL=2,PCATCH=0 };
struct IORecursiveLock { std::recursive_mutex mutex; };
static bool IORecursiveLockTryLock(IORecursiveLock *lock) {
 return lock && lock->mutex.try_lock();
}
static void IORecursiveLockUnlock(IORecursiveLock *lock) {
 assert(lock); lock->mutex.unlock();
}
struct task { unsigned adds=0; };
struct taskq {};
static taskq testTaskq;
static taskq *systq=&testTaskq;
static int task_add(taskq *,task *t) { ++t->adds; return 1; }
struct _ifnet {void *if_softc=nullptr; unsigned if_flags=0;int if_snd=0;};
struct Node {void *ni_chan=nullptr;};
struct ieee80211com {_ifnet ic_if;int ic_opmode=0,ic_state=0;Node *ic_bss=nullptr;void *ic_ibss_chan=nullptr;
 uint32_t ic_tahoe_init_stage=0;int32_t ic_tahoe_init_error=0;};
struct iwx_softc {ieee80211com sc_ic;struct {int qid=0;} sc_tid_data[4];int sc_generation=0,sc_flags=0;
 struct task init_task,ba_task,mac_ctxt_task,chan_ctxt_task;
 struct {bool sku_cap_11n_enable=false,sku_cap_11ac_enable=false,sku_cap_11ax_enable=false;} sc_nvm;};
static bool beginScanInstant=false,sleepSetsScan=false;static unsigned sleeps=0;
static int sleepResult=0;static bool cancelSleep=false;static iwx_softc *sleepOwner=nullptr;
static int splnet(){return 0;} static void splx(int){}
static void ifq_clr_oactive(int*){} static void ifq_flush(int*){}
static int tsleep_nsec(void *state,int,const char*,int) {
 ++sleeps;
 if(cancelSleep) {++sleepOwner->sc_generation;return ENXIO;}
 if(!sleepResult || sleepSetsScan)*static_cast<int*>(state)=IEEE80211_S_SCAN;
 return sleepResult;
}
static void ieee80211_new_state(ieee80211com *ic,int state,int){ic->ic_state=state;}
static int ieee80211_begin_scan_direct(_ifnet*){return 0;}
struct ItlIwx {
 iwx_softc com;int hwError=0;bool cancelHardware=false,p2pRetained=false;
 unsigned hwStarts=0,stops=0,stopCalls=0,ready=0,stopped=0;
 IORecursiveLock lifecycleLock;IORecursiveLock *nativeLifecycleLock_=&lifecycleLock;
 uint32_t nativeLifecycleDepth_=0,nativeLifecycleDeferredTasks_=0,nativeLifecycleTearingDown_=0;
 bool tahoeTryLifecycleFence();void tahoeReleaseLifecycleFence();
 void tahoeDeferLifecycleTasks(uint32_t);void tahoeFlushLifecycleTasks();
 struct task tahoe_scan_abort_task_;
 ItlIwx(){com.sc_ic.ic_if.if_softc=&com;}
 bool nativeP2pResourcesRetained(){return p2pRetained;}
 void tahoeRecordInitTaskTrigger(IwxResetTrace::InitTaskTrigger) {}
 void tahoeRecordReset(IwxResetTrace::ResetReason,iwx_softc*) {}
 int iwx_init_hw(iwx_softc *sc){++hwStarts;if(cancelHardware)++sc->sc_generation;return hwError;}
 void iwx_stop_device(iwx_softc*){++stops;}
 void iwx_setup_ht_rates(iwx_softc*){}void iwx_setup_vht_rates(iwx_softc*){}
 void iwx_setup_he_rates(iwx_softc*){}void tahoeScanOnline(bool){}
 void tahoeDriverEvent(int event){if(event==6)++ready;if(event==7)++stopped;}
 int iwx_stop(_ifnet *ifp,IwxResetTrace::ResetReason);
 int iwx_stop_body(_ifnet *ifp){++stopCalls;if(nativeP2pResourcesRetained())return EBUSY;
   ++stops;++com.sc_generation;ifp->if_flags&=~IFF_RUNNING;
   com.sc_flags&=~IWX_FLAG_HW_ERR;tahoeDriverEvent(7);return 0;}
 int iwx_scan(iwx_softc*sc){
  if(cancelSleep){++sc->sc_generation;return ENXIO;}
  if(sleepResult && !sleepSetsScan)return sleepResult;
  sc->sc_ic.ic_state=IEEE80211_S_SCAN;return 0;
 }
 static uint32_t tahoeScanState(ieee80211com*){return 0;}
 int iwx_init(_ifnet*);static void iwx_init_task(void*);
};
'''
radio_main = r'''
int main() {
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;f.p2pRetained=true;
  const int generation=f.com.sc_generation;const unsigned flags=ifp.if_flags;
  assert(f.iwx_init(&ifp)==EBUSY && f.hwStarts==0 && f.com.sc_generation==generation);
  assert(ifp.if_flags==flags && !f.ready && !f.stopped);}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP|IFF_RUNNING;
  f.p2pRetained=true;const int generation=f.com.sc_generation;const unsigned flags=ifp.if_flags;
  f.iwx_init_task(&f.com);
  assert(f.stopCalls==1 && f.stops==0 && f.hwStarts==0);
  assert(f.com.sc_generation==generation && ifp.if_flags==flags);
  assert(!f.ready && !f.stopped);}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;f.hwError=EIO;
  assert(f.iwx_init(&ifp)==EIO && ifp.if_flags==0 && f.stopped==1 && !f.ready);
  f.hwError=0;ifp.if_flags|=IFF_UP;sleepOwner=&f.com;
  assert(f.iwx_init(&ifp)==0 && ifp.if_flags==(IFF_UP|IFF_RUNNING) && f.ready==1);}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;f.hwError=EIO;f.cancelHardware=true;
  assert(f.iwx_init(&ifp)==EIO && ifp.if_flags==IFF_UP && !f.stopped && !f.stops);}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;sleepResult=ETIMEDOUT;sleepOwner=&f.com;
  assert(f.iwx_init(&ifp)==ETIMEDOUT && ifp.if_flags==0 && f.stopped==1 && !f.ready);
  sleepResult=0;}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;cancelSleep=true;sleepOwner=&f.com;
  assert(f.iwx_init(&ifp)==ENXIO && ifp.if_flags==(IFF_UP|IFF_RUNNING) && !f.stops && !f.stopped);
  cancelSleep=false;}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;beginScanInstant=true;
  auto before=sleeps;assert(f.iwx_init(&ifp)==0 && f.ready==1 && sleeps==before);
  beginScanInstant=false;}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;sleepResult=EWOULDBLOCK;
  sleepSetsScan=true;sleepOwner=&f.com;
  assert(f.iwx_init(&ifp)==0 && f.ready==1 && !f.stops);
  sleepResult=0;sleepSetsScan=false;}
 for (auto fatal:{IWX_FLAG_HW_ERR,IWX_FLAG_RFKILL}) {
  ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP|IFF_RUNNING;f.com.sc_flags=fatal;
  f.iwx_init_task(&f.com);assert(ifp.if_flags==0 && !f.hwStarts && !f.ready && f.stopped);
  if(fatal==IWX_FLAG_HW_ERR) {ifp.if_flags|=IFF_UP;sleepOwner=&f.com;f.iwx_init_task(&f.com);
   assert(f.hwStarts==1 && f.ready==1 && ifp.if_flags==(IFF_UP|IFF_RUNNING));}
 }
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;sleepOwner=&f.com;
  f.iwx_init_task(&f.com);assert(f.hwStarts==1 && f.ready==1 && ifp.if_flags==(IFF_UP|IFF_RUNNING));}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=0;
  assert(f.iwx_init(&ifp)==EBUSY && f.hwStarts==0 && f.com.sc_generation==0);}
 {ItlIwx f;auto &ifp=f.com.sc_ic.ic_if;ifp.if_flags=IFF_UP;
  std::atomic<bool> held{false},release{false};
  std::thread owner([&]{assert(f.tahoeTryLifecycleFence());held.store(true);
   while(!release.load())std::this_thread::yield();f.tahoeReleaseLifecycleFence();});
  while(!held.load())std::this_thread::yield();
  assert(f.iwx_init(&ifp)==EBUSY && f.hwStarts==0 && f.com.sc_generation==0);
  release.store(true);owner.join();}
}
'''

driver_source = (root / 'itlwm/hal_iwx/ItlIwx.cpp').read_text()
lifecycle_bits = extract_block(driver_source,
    'enum : uint32_t {\n    kTahoeLifecycleInitTask')
lifecycle_guard = extract_block(driver_source, 'class TahoeLifecycleGuard')
lifecycle_methods = '\n'.join(extract('itlwm/hal_iwx/ItlIwx.cpp', marker)
    for marker in (
        'bool ItlIwx::tahoeTryLifecycleFence()',
        'void ItlIwx::tahoeReleaseLifecycleFence()',
        'void ItlIwx::tahoeDeferLifecycleTasks(uint32_t taskBits)',
        'void ItlIwx::tahoeFlushLifecycleTasks()'))
radio_stop_guard = r'''
int ItlIwx::iwx_stop(_ifnet *ifp,IwxResetTrace::ResetReason) {
 TahoeLifecycleGuard lifecycle(this);
 if(!lifecycle)return EBUSY;
 return iwx_stop_body(ifp);
}
'''


beacons = r"""
#include <cassert>
#include <cstdint>
#include <cstring>
#define AIRPORT_TAHOE 1
#define XYLog(...) do {} while(0)
#define htole32(x) (x)
enum {IEEE80211_M_STA=0,IEEE80211_M_MONITOR=1,IWX_FLAG_MAC_ACTIVE=1,
 IWX_FW_CTXT_ACTION_ADD=1,IWX_FW_CTXT_ACTION_REMOVE=2,IWX_FW_CTXT_ACTION_MODIFY=3,
 IWX_MAC_FILTER_ACCEPT_GRP=1,IWX_MAC_FILTER_IN_BEACON=2,
 IWX_MAC_FILTER_IN_PROMISC=4,IWX_MAC_FILTER_IN_CONTROL_AND_MGMT=8,
 IWX_MAC_FILTER_IN_PROBE_REQUEST=16,IWX_MAC_FILTER_IN_CRC32=32,
 IWX_MAC_FILTER_IN_11AX=64,IEEE80211_NODE_HE=1,IWX_MAC_CONTEXT_CMD=40};
struct ieee80211_node {int ni_associd=0,ni_dtimperiod=0,ni_flags=0;};
struct ieee80211com {int ic_opmode=IEEE80211_M_STA;};
struct iwx_softc {ieee80211com sc_ic;int sc_flags=0;};
struct iwx_node {ieee80211_node in_ni;};
struct iwx_mac_data_sta {int associated=0;};
struct iwx_mac_ctx_cmd {uint32_t filter_flags=0;iwx_mac_data_sta sta;};
struct ItlIwx {
 unsigned sends=0,fills=0;int result=0;iwx_mac_ctx_cmd sent{};
 void iwx_mac_ctxt_cmd_common(iwx_softc*,iwx_node*,iwx_mac_ctx_cmd*c,uint32_t){c->filter_flags=IWX_MAC_FILTER_ACCEPT_GRP;}
 void iwx_mac_ctxt_cmd_fill_sta(iwx_softc*,iwx_node*,iwx_mac_data_sta*s,int assoc){++fills;s->associated=assoc;}
 int iwx_send_cmd_pdu(iwx_softc*,int cmd,int flags,unsigned size,const void*c){
  assert(cmd==IWX_MAC_CONTEXT_CMD&&!flags&&size==sizeof sent);sent=*static_cast<const iwx_mac_ctx_cmd*>(c);++sends;return result;}
 int iwx_mac_ctxt_cmd(iwx_softc*,iwx_node*,uint32_t,int);
};
"""
beacons_main = r"""
int main(){
 for(auto assoc:{0,1})for(auto aid:{0,1})for(auto dtim:{0,2})for(auto he:{0,1}){
  ItlIwx f;iwx_softc sc;iwx_node in;in.in_ni={aid,dtim,he};
  assert(f.iwx_mac_ctxt_cmd(&sc,&in,IWX_FW_CTXT_ACTION_MODIFY,assoc)==0);
  assert(f.sends==1&&(f.sent.filter_flags&IWX_MAC_FILTER_IN_BEACON));
  assert(!(f.sent.filter_flags&(IWX_MAC_FILTER_IN_PROMISC|IWX_MAC_FILTER_IN_CRC32)));
  assert(f.fills==unsigned(assoc&&aid&&dtim));
  assert(f.sent.sta.associated==int(assoc&&aid&&dtim));
  assert(bool(f.sent.filter_flags&IWX_MAC_FILTER_IN_11AX)==bool(he));
 }
 {ItlIwx f;iwx_softc sc;sc.sc_flags=IWX_FLAG_MAC_ACTIVE;iwx_node in;
  assert(f.iwx_mac_ctxt_cmd(&sc,&in,IWX_FW_CTXT_ACTION_REMOVE,0)==0);
  assert(f.sends==1&&!(f.sent.filter_flags&IWX_MAC_FILTER_IN_BEACON));}
 {ItlIwx f;iwx_softc sc;iwx_node in;f.result=5;
  assert(f.iwx_mac_ctxt_cmd(&sc,&in,IWX_FW_CTXT_ACTION_MODIFY,1)==5);}
}
"""

cases = [
    ('associated_beacon_filter', beacons + extract('itlwm/hal_iwx/ItlIwx.cpp',
        'int ItlIwx::\niwx_mac_ctxt_cmd(') + beacons_main),
    ('fastlane', policy + extract('AirportItlwm/AirportItlwmSkywalkInterface.cpp',
        'IOReturn AirportItlwmSkywalkInterface::setWCL_UPDATE_FAST_LANE(') + policy_main),
    ('radio', radio + lifecycle_bits + ';\n' + lifecycle_guard + ';\n' +
        lifecycle_methods + '\n' + radio_stop_guard +
        extract('itlwm/hal_iwx/ItlIwx.cpp', 'int ItlIwx::\niwx_init(') +
        extract('itlwm/hal_iwx/ItlIwx.cpp', 'void ItlIwx::\niwx_init_task(') +
        radio_main),
]
with tempfile.TemporaryDirectory(prefix='intel-native-recovery-') as directory:
    path = Path(directory)
    for name, source in cases:
        cpp, exe = path / (name + '.cpp'), path / name
        cpp.write_text(source)
        subprocess.run(['xcrun', 'clang++', '-std=c++14', '-O1',
            '-include', 'initializer_list', '-fsanitize=address,undefined',
            '-fno-omit-frame-pointer', '-I', str(root), str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        print('PASS:', name)
