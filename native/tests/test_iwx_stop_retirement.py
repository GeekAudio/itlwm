#!/usr/bin/env python3
"""Fault-test the production bus-master poll and post-reset ring retirement."""

from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = r'''
#include "native/iwx_stop_retirement.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>

struct Dma { void *vaddr{}; uint64_t paddr{}; };
struct TxData { void *map{}; uint64_t cmd_paddr{}; };
struct Ring {
    Dma desc_dma{}, cmd_dma{}, bc_tbl{};
    void *desc{};
    void *cmd{};
    TxData data[8]{};
    unsigned ring_count{};
    int qid{-1};
    int queued{};
    bool static_placeholder{};
};

static Ring backedRing(int qid, uintptr_t base) {
    Ring r{};
    r.qid=qid; r.ring_count=8;
    r.desc=reinterpret_cast<void *>(base+1);
    r.cmd=reinterpret_cast<void *>(base+2);
    r.desc_dma={reinterpret_cast<void *>(base+3),base+4};
    r.cmd_dma={reinterpret_cast<void *>(base+5),base+6};
    r.bc_tbl={reinterpret_cast<void *>(base+7),base+8};
    for (unsigned i=0;i<r.ring_count;i++) {
        r.data[i].map=reinterpret_cast<void *>(base+16+i);
        r.data[i].cmd_paddr=base+128+i;
    }
    return r;
}

int main() {
    constexpr uint32_t kMasterDisabled=0x100;
    unsigned delays=0, reads=0;
    auto immediate=NativeIwxStop::waitForMasterDisabled(
        [&](){++reads;return kMasterDisabled;},
        [&](uint32_t us){assert(us==10);++delays;},kMasterDisabled,100);
    assert(immediate==NativeIwxStop::MasterDisabledPoll::kDisabled);
    assert(reads==1 && delays==0);

    uint32_t delayedValues[]={0,0,kMasterDisabled};
    reads=0; delays=0;
    auto delayed=NativeIwxStop::waitForMasterDisabled(
        [&](){return delayedValues[reads++];},
        [&](uint32_t us){assert(us==10);delays++;},kMasterDisabled,100);
    assert(delayed==NativeIwxStop::MasterDisabledPoll::kDisabled);
    assert(reads==3 && delays==2);

    reads=0; delays=0;
    auto timeout=NativeIwxStop::waitForMasterDisabled(
        [&](){++reads;return 0u;},
        [&](uint32_t us){assert(us==10);++delays;},kMasterDisabled,20);
    assert(timeout==NativeIwxStop::MasterDisabledPoll::kTimeout);
    assert(reads==3 && delays==2);

    reads=0; delays=0;
    auto badRead=NativeIwxStop::waitForMasterDisabled(
        [&](){++reads;return UINT32_MAX;},
        [&](uint32_t){++delays;},kMasterDisabled,100);
    assert(badRead==NativeIwxStop::MasterDisabledPoll::kInvalidRead);
    assert(reads==1 && delays==0); // all ones must not pass the mask test

    Ring queues[5]{};
    queues[0]=backedRing(0,0x1000); // firmware command queue
    queues[1]=backedRing(1,0x2000); // auxiliary queue
    queues[2]=backedRing(2,0x3000); // static P2P placeholder
    queues[2].static_placeholder=true;
    queues[3]=backedRing(3,0x4000); // stale dynamic STA queue
    queues[4]=backedRing(4,0x5000);
    Ring scratch=queues[3]; // exact non-owning alias after successful install
    Ring oversizedScratch=backedRing(3,0x8800);
    Ring oversizedInstalled=backedRing(3,0x8800);
    oversizedScratch.ring_count=9; // data[] has only eight slots
    assert(!NativeIwxStop::isInstalledRingAlias(
        oversizedScratch,oversizedInstalled));
    oversizedScratch.ring_count=8;
    oversizedInstalled.ring_count=9;
    assert(!NativeIwxStop::isInstalledRingAlias(
        oversizedScratch,oversizedInstalled));
    unsigned freed=0, cleared=0;
    auto freeRing=[&](Ring *r){++freed;*r=Ring{};r->qid=-1;};
    auto clearScratch=[&](Ring *r){++cleared;*r=Ring{};r->qid=-1;};

    size_t count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,true,true,true,false,freeRing,clearScratch);
    assert(count==2 && freed==2 && cleared==1);
    assert(queues[0].ring_count==8 && queues[1].ring_count==8);
    assert(queues[2].ring_count==8 && queues[2].static_placeholder);
    assert(queues[3].ring_count==0 && queues[4].ring_count==0);
    assert(scratch.ring_count==0 && scratch.desc==nullptr);

    // A positive bus-master read is insufficient unless SW_RESET was issued.
    queues[3]=backedRing(3,0x6000); scratch=queues[3]; freed=cleared=0;
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,true,true,false,false,freeRing,clearScratch);
    assert(count==0 && freed==0 && cleared==0 && queues[3].ring_count==8);

    // Failed master-disable proof keeps every dynamic ring.
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,true,false,true,false,freeRing,clearScratch);
    assert(count==0 && queues[3].ring_count==8 && scratch.ring_count==8);
    // Do not free if the interface has not committed its stopped state.
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,false,true,true,false,freeRing,clearScratch);
    assert(count==0 && queues[3].ring_count==8 && scratch.ring_count==8);
    // A contended main command gate passes callbacksSerialized=false. The
    // stop path must retain DMA even though master-disable and reset succeeded.
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,false,true,true,true,false,freeRing,clearScratch);
    assert(count==0 && queues[3].ring_count==8 && scratch.ring_count==8);
    // Any retained P2P lease keeps all queues, even after stop and reset.
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,true,true,true,true,freeRing,clearScratch);
    assert(count==0 && queues[3].ring_count==8 && scratch.ring_count==8);

    // An independent scratch ring from an uncertain command is not an alias;
    // retire the installed queue without losing that pending allocation.
    queues[3]=backedRing(3,0x7000);
    scratch=backedRing(9,0x8000); freed=cleared=0;
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,true,true,true,false,freeRing,clearScratch);
    assert(count==1 && freed==1 && cleared==0);
    assert(queues[3].ring_count==0 && scratch.ring_count==8);
    assert(scratch.desc==reinterpret_cast<void *>(0x8001));

    // A known completed stop leaves the dynamic slot reusable by a new ring.
    queues[3]=backedRing(3,0x9000);
    scratch=queues[3]; freed=cleared=0;
    count=NativeIwxStop::retireDynamicRingsAfterStop(
        queues,5,3,&scratch,true,true,true,true,false,freeRing,clearScratch);
    assert(count==1 && cleared==1 && queues[3].ring_count==0);
    queues[3]=backedRing(3,0xa000);
    assert(queues[3].ring_count==8 && queues[3].desc!=nullptr);
}
'''

with tempfile.TemporaryDirectory(prefix="iwx-stop-retirement-") as directory:
    binary = Path(directory) / "test"
    subprocess.run([
        "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(root), "-x", "c++", "-o", str(binary), "-"
    ], input=source, text=True, check=True)
    subprocess.run([str(binary)], check=True)

driver = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
stop_start = driver.index(
    "iwx_stop(struct _ifnet *ifp, IwxResetTrace::ResetReason reason)")
stop_end = driver.index("iwx_watchdog(struct _ifnet *ifp)", stop_start)
stop_body = driver[stop_start:stop_end]
ordered_markers = [
    "iwx_stop_device(sc)",
    "ifp->if_flags &= ~IFF_RUNNING;",
    "sc->sc_newstate(ic, IEEE80211_S_INIT, -1);",
    "tahoeRetireStoppedQueuesAfterSoftStop(sc, hardwareStopError);",
    "taskq_resume(sc->sc_nswq);",
]
positions = [stop_body.index(marker) for marker in ordered_markers]
assert positions == sorted(positions), "ring retirement must follow the soft stop and precede task resume"

print("PASS: master-stop fault handling and dynamic ring retirement")
print("PASS: stopped-state ordering before queue retirement")
