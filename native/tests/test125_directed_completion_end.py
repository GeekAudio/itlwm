#!/usr/bin/env python3
"""Execute the production END/completion wait block with a deterministic clock.

This checks ordering and lifetime only; it does not simulate firmware delivery.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'itlwm/hal_iwx/ItlIwxP2PProbe.cpp').read_text()
start = source.index('// A pre-submit failure still waits for canonical END')
start = source.index('if (!sessionEnded) {', start)
end = source.index('if (probe->directedDataSubmitCalled &&', start)
block = source[start:end]

fixture = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
enum class TahoeP2PDirectedDataState { kInFlight, kCompleted, kQuarantined };
struct TahoeP2PDirectedDataSnapshot {
    bool doorbellIssued = true, completionObserved = false;
    bool completionArmed = true, mbufHeldByRing = true;
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kInFlight;
};
struct Session { bool endSeen = false, outcomeUnknown = false; };
struct Event { Session snapshot; };
struct Probe { unsigned contextGeneration = 3; bool directedDataCompletionObserved = false; };
struct Owner { int nativeP2pDirectedDataTx_ = 0; };
constexpr int kDirectedDataQuarantined = 10;
constexpr uint64_t never = 1000000;
static uint64_t now, endAt, completeAt, quarantineAt, staleAt;
static bool validEnd, doorbell;
static bool quarantineAfterCompletion;
static unsigned completionReads;
static uint64_t completionReadCost;
static unsigned drainAfterEnd;
static uint64_t p2pProbeMonotonicNanoseconds() { return now * 1000; }
static void IOSleep(unsigned ms) { now += ms * 1000; }
static int readRocState(Probe *, Event *e) {
    e->snapshot.endSeen = now >= endAt;
    return now >= staleAt ? ESTALE : 0;
}
static void drainDirectedDataRxOutsideMainGate(Probe *, Event &e) {
    if (e.snapshot.endSeen) ++drainAfterEnd;
}
static bool iwx_tahoe_p2p_directed_data_snapshot(
    Owner *, int *, TahoeP2PDirectedDataSnapshot *d) {
    d->doorbellIssued = doorbell;
    d->completionObserved = now >= completeAt;
    d->completionArmed = doorbell && !d->completionObserved;
    d->mbufHeldByRing = d->completionArmed;
    d->state = now >= quarantineAt ? TahoeP2PDirectedDataState::kQuarantined :
        d->completionObserved ? TahoeP2PDirectedDataState::kCompleted :
                                TahoeP2PDirectedDataState::kInFlight;
    if (d->completionObserved) {
        if (quarantineAfterCompletion && completionReads++)
            d->state = TahoeP2PDirectedDataState::kQuarantined;
        now += completionReadCost;
    }
    return true;
}
static bool directedDataSessionEndConfirmed(const Session &s, unsigned) {
    return s.endSeen && validEnd;
}
static int run() {
    Owner o; Owner *owner = &o;
    Probe p; Probe *probe = &p;
    Event event;
    bool sessionEnded = false;
    auto recordFailure = [](int error, int stage) {
        assert(stage == kDirectedDataQuarantined); return error;
    };
''' + block + r'''
    return 0;
}
static void reset(uint64_t end, uint64_t completion) {
    now = 0; endAt = end; completeAt = completion;
    quarantineAt = staleAt = never;
    validEnd = doorbell = true; drainAfterEnd = 0;
    quarantineAfterCompletion = false;
    completionReads = 0; completionReadCost = 0;
}
int main() {
    // The real regression: END can precede the same slot's exact TX_RSP.
    reset(100000, 112000);
    assert(run() == 0 && now == 112000 && drainAfterEnd == 0);
    reset(100000, 80000);
    assert(run() == 0 && now == 100000 && drainAfterEnd == 0);
    // Missing completion still exhausts the original absolute 350 ms budget.
    reset(100000, never);
    assert(run() == ETIMEDOUT && now == 350000 && drainAfterEnd == 0);
    reset(never, 80000);
    assert(run() == ETIMEDOUT && now == 350000);
    // A foreign/malformed completion has already quarantined the live slot.
    reset(100000, never); quarantineAt = 106000;
    assert(run() == EIO && now == 106000);
    reset(100000, 112000); staleAt = 106000;
    assert(run() == ESTALE && now == 106000);
    reset(100000, 112000); validEnd = false;
    assert(run() == EPROTO && now == 100000);
    reset(100000, never); doorbell = false;
    assert(run() == 0 && now == 100000 && drainAfterEnd == 0);
    // Boundary and post-loop snapshots cannot admit a late completion.
    reset(100000, 350000);
    assert(run() == ETIMEDOUT && now == 350000);
    reset(100000, 348000);
    assert(run() == 0 && now == 348000);
    reset(100000, 348000); completionReadCost = 2000;
    assert(run() == ETIMEDOUT && now == 350000);
    // A matched response does not override concurrent slot quarantine.
    reset(100000, 100000); quarantineAt = 100000;
    assert(run() == EIO && now == 100000);
    reset(100000, 100000); quarantineAfterCompletion = true;
    assert(run() == EIO && now == 100000);
}
'''
with tempfile.TemporaryDirectory(prefix='test125-end-completion-') as tmp:
    cpp, exe = Path(tmp) / 'wait.cpp', Path(tmp) / 'wait'
    cpp.write_text(fixture)
    subprocess.run(['c++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                    str(cpp), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('Test125: 13 production-loop ordering/lifetime cases passed; no RF')
