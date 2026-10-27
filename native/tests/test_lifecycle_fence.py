#!/usr/bin/env python3
"""Exercise extracted Tahoe lifecycle guards and systq firmware callbacks."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
source = SOURCE.read_text()


def extract(marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def extract_block(marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


bits = extract_block("enum : uint32_t {\n    kTahoeLifecycleInitTask")
guard = extract_block("class TahoeLifecycleGuard")
fence_methods = "\n".join(extract(marker) for marker in (
    "bool ItlIwx::tahoeTryLifecycleFence()",
    "void ItlIwx::tahoeReleaseLifecycleFence()",
    "void ItlIwx::tahoeDeferLifecycleTasks(uint32_t taskBits)",
    "void ItlIwx::tahoeFlushLifecycleTasks()",
))
callbacks = "\n".join(extract(marker) for marker in (
    "void ItlIwx::\niwx_init_task(void *arg1)",
    "void ItlIwx::\niwx_ba_task(void *arg)",
    "void ItlIwx::\niwx_mac_ctxt_task(void *arg)",
    "void ItlIwx::\niwx_chan_ctxt_task(void *arg)",
    "void ItlIwx::tahoeScanAbortTask(void *arg)",
))
activation = extract("int ItlIwx::\niwx_activate(struct iwx_softc *sc, int act)")
stop_source = extract("int ItlIwx::\niwx_stop(struct _ifnet *ifp, IwxResetTrace::ResetReason reason)")
assert stop_source.index("TahoeLifecycleGuard lifecycle(this)") < \
       stop_source.index("tahoeP2pStopBeforeReset(sc)") < \
       stop_source.index("taskq_try_pause_with_diagnostics(")
assert "task_del(systq, &tahoe_scan_abort_task_)" in stop_source


HARNESS = r'''
#include "native/iwx_reset_trace.hpp"
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <memory>
#include <mutex>
#include <thread>

#define AIRPORT_TAHOE 1
#define XYLog(...) do {} while (0)
#define IOLog(...) do {} while (0)
#define container_of(p,T,m) reinterpret_cast<T*>(reinterpret_cast<char*>(p)-offsetof(T,m))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define IWX_AGG_SSN_TO_TXQ_IDX(cur,count) (cur)
#define isset(set,bit) (((set)&(bit)) != 0)
#define DEVNAME(sc) "test"

enum {
    IFF_UP=1, IFF_RUNNING=64, IWX_FLAG_SHUTDOWN=1,
    IEEE80211_S_RUN=2, IWX_MAX_TID_COUNT=4,
    IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD=1,
    IEEE80211_STATUS_UNSPECIFIED=1,
    ITL_TAHOE_SCAN_DRAINING=3,
    IWX_FW_CTXT_ACTION_MODIFY=3,
    DVACT_QUIESCE=1, DVACT_RESUME=2, DVACT_WAKEUP=3,
    IWX_FLAG_HW_ERR=2, IWX_FLAG_RFKILL=4,
    ITL_TAHOE_EVT_RESET_BEGIN=8, ITL_TAHOE_EVT_DRIVER_STOPPED=7
};

struct IORecursiveLock { std::recursive_mutex mutex; };
static std::mutex failedTryMutex;
static std::condition_variable failedTryCondition;
static bool pauseOneFailedTry=false, failedTryReached=false, allowFailedTry=false;
static void waitAtFailedTry() {
    std::unique_lock<std::mutex> lock(failedTryMutex);
    if (!pauseOneFailedTry)
        return;
    pauseOneFailedTry=false;
    failedTryReached=true;
    failedTryCondition.notify_all();
    failedTryCondition.wait(lock, [] { return allowFailedTry; });
}
static bool IORecursiveLockTryLock(IORecursiveLock *lock) {
    const bool acquired=lock && lock->mutex.try_lock();
    if (!acquired)
        waitAtFailedTry();
    return acquired;
}
static void IORecursiveLockUnlock(IORecursiveLock *lock) {
    assert(lock); lock->mutex.unlock();
}
static void armFailedTryPause() {
    std::lock_guard<std::mutex> lock(failedTryMutex);
    pauseOneFailedTry=true; failedTryReached=false; allowFailedTry=false;
}
static void waitForFailedTryPause() {
    std::unique_lock<std::mutex> lock(failedTryMutex);
    failedTryCondition.wait(lock, [] { return failedTryReached; });
}
static void releaseFailedTryPause() {
    std::lock_guard<std::mutex> lock(failedTryMutex);
    allowFailedTry=true; failedTryCondition.notify_all();
}

struct task { unsigned adds=0; bool queued=false; };
struct taskq {};
static taskq testTaskq;
static taskq *systq=&testTaskq;
static int task_add(taskq *, task *task) {
    if (task->queued) return 0;
    task->queued=true; ++task->adds; return 1;
}

struct _ifnet { void *if_softc=nullptr; uint32_t if_flags=0; };
struct ieee80211_rx_ba { int ba_winstart=0,ba_winsize=0,ba_timeout_val=0; };
struct ieee80211_tx_ba {
    int ba_winstart=0,ba_winend=0,ba_winsize=0,ba_timeout_val=0;
};
struct ieee80211_node {
    ieee80211_rx_ba ni_rx_ba[IWX_MAX_TID_COUNT];
    ieee80211_tx_ba ni_tx_ba[IWX_MAX_TID_COUNT];
};
struct iwx_phy_context { void *channel=nullptr; };
struct iwx_node { ieee80211_node in_ni; iwx_phy_context *in_phyctxt=nullptr; };
struct ieee80211com {
    _ifnet ic_if; int ic_state=0; ieee80211_node *ic_bss=nullptr;
};
struct iwx_tx_ring { unsigned cur=0,ring_count=16; };
struct iwx_softc {
    ieee80211com sc_ic; int sc_generation=0,sc_flags=0;
    uint32_t sc_enabled_capa=0;
    struct { uint32_t start_tidmask=0,stop_tidmask=0; } ba_rx,ba_tx;
    unsigned sc_rx_ba_sessions=0;
    iwx_tx_ring txq[4];
    task init_task,ba_task,mac_ctxt_task,chan_ctxt_task;
};
static int splnet() { return 0; }
static void splx(int) {}
static void ieee80211_addba_req_accept(ieee80211com *,ieee80211_node *,int) {}
static void ieee80211_addba_resp_accept(ieee80211com *,ieee80211_node *,int) {}
static void ieee80211_addba_resp_refuse(ieee80211com *,ieee80211_node *,int,int) {}

struct ItlIwx {
    iwx_softc com;
    IORecursiveLock lifecycleLock;
    IORecursiveLock *nativeLifecycleLock_=&lifecycleLock;
    uint32_t nativeLifecycleDepth_=0,nativeLifecycleDeferredTasks_=0;
    uint32_t nativeLifecycleTearingDown_=0;
    unsigned baCommands=0,macCommands=0,phyCommands=0,rateCommands=0;
    unsigned scanAbortCommands=0,initCalls=0,stopCalls=0,events=0;
    unsigned readyCalls=0;
    uint32_t scanState=0;
    struct task tahoe_scan_abort_task_;
    bool tahoeTryLifecycleFence();
    void tahoeReleaseLifecycleFence();
    void tahoeDeferLifecycleTasks(uint32_t);
    void tahoeFlushLifecycleTasks();
    void tahoeRecordInitTaskTrigger(IwxResetTrace::InitTaskTrigger) {}
    void tahoeRecordReset(IwxResetTrace::ResetReason,iwx_softc *) {}
    static uint32_t tahoeScanState(ieee80211com *) { return scanStateForTest; }
    static void iwx_init_task(void *);
    static void iwx_ba_task(void *);
    static void iwx_mac_ctxt_task(void *);
    static void iwx_chan_ctxt_task(void *);
    static void tahoeScanAbortTask(void *);
    int iwx_activate(iwx_softc *,int);
    static uint32_t scanStateForTest;
    int iwx_init(_ifnet *) { ++initCalls; return 0; }
    int iwx_stop(_ifnet *,IwxResetTrace::ResetReason) { ++stopCalls; return 0; }
    int iwx_resume(iwx_softc *) { return 0; }
    int iwx_set_hw_ready(iwx_softc *) { ++readyCalls; return 1; }
    void tahoeDriverEvent(int) { ++events; }
    void iwx_sta_rx_agg(iwx_softc *,ieee80211_node *,int,int,int,int,int) { ++baCommands; }
    bool iwx_nic_lock(iwx_softc *) { return true; }
    int iwx_tvqm_alloc_txq(iwx_softc *,int,int) { return 0; }
    void iwx_nic_unlock(iwx_softc *) {}
    int iwx_mac_ctxt_cmd(iwx_softc *,iwx_node *,int,int) { ++macCommands; return 0; }
    void iwx_unprotect_session(iwx_softc *,iwx_node *) {}
    bool iwx_mimo_enabled(iwx_softc *) { return false; }
    int iwx_phy_ctxt_update(iwx_softc *,iwx_phy_context *,void *,int,int,int) {
        ++phyCommands; return 0;
    }
    int iwx_rs_init(iwx_softc *,iwx_node *,bool) { ++rateCommands; return 0; }
    int iwx_scan_abort(iwx_softc *) { ++scanAbortCommands; return 0; }
};
uint32_t ItlIwx::scanStateForTest=0;
''' + bits + ";\n" + guard + ";\n" + fence_methods + "\n" + callbacks + "\n" + activation + r'''

static void set_running(ItlIwx &owner, iwx_node &node, iwx_phy_context &phy) {
    owner.com.sc_ic.ic_bss=&node.in_ni;
    owner.com.sc_ic.ic_if.if_softc=&owner.com;
    owner.com.sc_ic.ic_if.if_flags=IFF_UP|IFF_RUNNING;
    owner.com.sc_ic.ic_state=IEEE80211_S_RUN;
    node.in_phyctxt=&phy;
    ItlIwx::scanStateForTest=ITL_TAHOE_SCAN_DRAINING;
}

static void test_temporary_contention(
    void (*callback)(void *), task *work, ItlIwx &owner, iwx_node &node,
    const char *kind) {
    iwx_phy_context phy{};
    set_running(owner,node,phy);
    owner.com.ba_rx.start_tidmask=1;
    auto holder=std::make_unique<TahoeLifecycleGuard>(&owner);
    assert(bool(*holder));
    std::thread popped([&] { callback(&owner.com); });
    popped.join();
    assert(owner.baCommands==0 && owner.macCommands==0 && owner.phyCommands==0 &&
           owner.scanAbortCommands==0);
    holder.reset();
    assert(work->adds==1 && work->queued);
    work->queued=false; // The deferred task is now popped for its one retry.
    callback(&owner.com);
    if (kind[0]=='b') assert(owner.baCommands==1);
    if (kind[0]=='m') assert(owner.macCommands==1);
    if (kind[0]=='c') assert(owner.phyCommands==1 && owner.rateCommands==1);
    if (kind[0]=='s') assert(owner.scanAbortCommands==1);
}

int main() {
    unsigned scenarios=0;
    {
        ItlIwx owner;
        auto holder=std::make_unique<TahoeLifecycleGuard>(&owner);
        assert(bool(*holder));
        assert(owner.iwx_activate(&owner.com,DVACT_WAKEUP)==0);
        assert(owner.iwx_activate(&owner.com,DVACT_WAKEUP)==0);
        assert(owner.readyCalls==2 && owner.com.init_task.adds==0);
        assert(owner.nativeLifecycleDeferredTasks_==kTahoeLifecycleInitTask);
        holder.reset();
        assert(owner.com.init_task.adds==1 && owner.com.init_task.queued);
        ++scenarios;
    }
    {
        ItlIwx owner; iwx_node node; iwx_phy_context phy{};
        set_running(owner,node,phy); owner.com.ba_rx.start_tidmask=1;
        auto holder=std::make_unique<TahoeLifecycleGuard>(&owner);
        assert(bool(*holder)); armFailedTryPause();
        std::thread popped([&] { ItlIwx::iwx_ba_task(&owner.com); });
        waitForFailedTryPause();
        holder.reset(); // Unlock and exchange pending before callback publishes it.
        releaseFailedTryPause();
        popped.join();
        assert(owner.baCommands==0 && owner.com.ba_task.adds==1 &&
               owner.com.ba_task.queued);
        owner.com.ba_task.queued=false;
        ItlIwx::iwx_ba_task(&owner.com); // The post-publish retry performs the work once.
        assert(owner.baCommands==1 && owner.com.ba_task.adds==1);
        ++scenarios;
    }
    {
        ItlIwx owner; iwx_node node;
        test_temporary_contention(ItlIwx::iwx_ba_task,&owner.com.ba_task,owner,node,"ba");
        ++scenarios;
    }
    {
        ItlIwx owner; iwx_node node;
        test_temporary_contention(ItlIwx::iwx_mac_ctxt_task,&owner.com.mac_ctxt_task,
                                  owner,node,"mac");
        ++scenarios;
    }
    {
        ItlIwx owner; iwx_node node;
        test_temporary_contention(ItlIwx::iwx_chan_ctxt_task,&owner.com.chan_ctxt_task,
                                  owner,node,"chan");
        ++scenarios;
    }
    {
        ItlIwx owner; iwx_node node; iwx_phy_context phy{};
        set_running(owner,node,phy);
        test_temporary_contention(ItlIwx::tahoeScanAbortTask,
                                  &owner.tahoe_scan_abort_task_,owner,node,"scan");
        ++scenarios;
    }
    {
        /* Once Off clears UP/RUNNING, each deferred replay is a no-op. */
        using Callback=void (*)(void *);
        struct Case { Callback callback; task *work; uint32_t bit; };
        for (int i=0;i<5;i++) {
            ItlIwx owner; iwx_node node; iwx_phy_context phy{};
            set_running(owner,node,phy); owner.com.ba_rx.start_tidmask=1;
            task *work=nullptr; Callback callback=nullptr;
            switch(i) {
                case 0: callback=ItlIwx::iwx_init_task; work=&owner.com.init_task; break;
                case 1: callback=ItlIwx::iwx_ba_task; work=&owner.com.ba_task; break;
                case 2: callback=ItlIwx::iwx_mac_ctxt_task; work=&owner.com.mac_ctxt_task; break;
                case 3: callback=ItlIwx::iwx_chan_ctxt_task; work=&owner.com.chan_ctxt_task; break;
                default: callback=ItlIwx::tahoeScanAbortTask;
                         work=&owner.tahoe_scan_abort_task_; break;
            }
            auto holder=std::make_unique<TahoeLifecycleGuard>(&owner);
            assert(bool(*holder));
            std::thread popped([&] { callback(&owner.com); });
            popped.join();
            owner.com.sc_ic.ic_if.if_flags=0;
            holder.reset();
            assert(work->adds==1 && work->queued);
            work->queued=false;
            callback(&owner.com);
            assert(owner.baCommands==0 && owner.macCommands==0 &&
                   owner.phyCommands==0 && owner.rateCommands==0 &&
                   owner.scanAbortCommands==0 && owner.initCalls==0 &&
                   owner.stopCalls==0);
            ++scenarios;
        }
    }
    std::printf("{\"lifecycle_fence_scenarios\":%u}\n",scenarios);
}
'''

with tempfile.TemporaryDirectory(prefix="native-lifecycle-fence-") as directory:
    cpp = Path(directory) / "test.cpp"
    exe = Path(directory) / "test"
    cpp.write_text(HARNESS)
    subprocess.run([
        "xcrun", "clang++", "-std=c++17", "-O1", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT),
        str(cpp), "-o", str(exe),
    ], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: production lifecycle callbacks and lost-wakeup handoff")
