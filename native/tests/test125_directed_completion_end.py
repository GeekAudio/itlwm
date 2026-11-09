#!/usr/bin/env python3
"""Execute the production END/completion wait with a deterministic clock.

The loop must keep validating owner/epoch state after END while never draining
RX after END. This only checks control-flow and lifetime; it does not simulate
firmware delivery.
"""
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
marker = source.index("// A pre-submit failure still waits for canonical END")


def extract_braced(source: str, opening: int) -> str:
    assert source[opening] == "{"
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[opening:end]


wait_open = source.index("{", marker)
wait_block = extract_braced(source, wait_open)
final_start = source.index("TahoeP2PDirectedDataSnapshot finalData{};", wait_open)
final_end = source.index(
    "NativeAwdlDirectedOriginTx::Snapshot finalOrigin{};", final_start)
final_check = source[final_start:final_end]

# Every iteration must sample live ROC/owner state, including after canonical
# END. The RX producer is already closed then, so no post-END drain is allowed.
assert not re.search(r"if\s*\(\s*!sessionEnded\s*\)\s*\{", wait_block)
assert "const int readError = readRocState(probe, &event);" in wait_block
assert re.search(
    r"if\s*\(\s*!readError\s*&&\s*!event.snapshot.endSeen\s*\)",
    wait_block)
assert wait_block.index("const int readError = readRocState") < \
       wait_block.index("if (readError)")

production = wait_block + "\n" + final_check

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
struct Probe {
    unsigned contextGeneration = 3;
    bool directedDataCompletionObserved = false;
    bool directedDataSubmitCalled = false;
    int directedDataSubmitResult = 0;
};
struct Owner { int nativeP2pDirectedDataTx_ = 0; };
struct DirectedDataOriginProofTracker {};
constexpr int kDirectedDataQuarantined = 10;
static uint64_t now, endAt, completeAt, quarantineAt, staleAt;
static bool validEnd, doorbell, quarantineAfterCompletion;
static bool submitCalled;
static int submitResult;
static unsigned completionReads, readAfterEnd, drainAfterEnd, drainCalls;
static uint64_t completionReadCost;
static uint64_t p2pProbeMonotonicNanoseconds() { return now * 1000; }
static void IOSleep(unsigned ms) { now += ms * 1000; }
static int readRocState(Probe *, Event *e) {
    e->snapshot.endSeen = now >= endAt;
    if (e->snapshot.endSeen)
        ++readAfterEnd;
    return now >= staleAt ? ESTALE : 0;
}
static void drainDirectedDataRxOutsideMainGate(Probe *, Event &e) {
    if (e.snapshot.endSeen)
        ++drainAfterEnd;
    else
        ++drainCalls;
}
static int syncDirectedDataOriginProofs(
    Probe *, DirectedDataOriginProofTracker *, Event *) {
    return 0;
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
constexpr uint64_t never = UINT64_MAX;
static int run() {
    Owner o; Owner *owner = &o;
    Probe p; Probe *probe = &p;
    p.directedDataSubmitCalled = submitCalled;
    p.directedDataSubmitResult = submitResult;
    Event event;
    bool sessionEnded = false;
    int originProofFailure = 0;
    DirectedDataOriginProofTracker originProofTracker{};
    uint64_t capturedFailureTime = never;
    auto rememberPreSubmitFailure = [&](int) {
        if (capturedFailureTime == never)
            capturedFailureTime = now;
    };
    auto recordFailure = [&](int error, int stage) {
        assert(stage == kDirectedDataQuarantined);
        return error;
    };
''' + production + r'''
    return 0;
}
static void reset(uint64_t end, uint64_t completion) {
    now = 0; endAt = end; completeAt = completion;
    quarantineAt = staleAt = never;
    validEnd = doorbell = true;
    submitCalled = false; submitResult = 0;
    quarantineAfterCompletion = false;
    completionReads = readAfterEnd = drainAfterEnd = drainCalls = 0;
    completionReadCost = 0;
}
int main() {
    // END does not retire an outstanding DMA; the exact TX_RSP may follow.
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
    // END must not suppress a later owner/epoch failure while TX_RSP is late.
    reset(100000, 112000); staleAt = 106000;
    assert(run() == ESTALE && now == 106000 && readAfterEnd != 0);
    assert(drainAfterEnd == 0);
    reset(100000, 112000); validEnd = false;
    assert(run() == EPROTO && now == 100000);
    reset(100000, never); doorbell = false;
    assert(run() == 0 && now == 100000 && drainAfterEnd == 0);
    // A completion at or after the wait budget cannot pass the final snapshot.
    reset(100000, 350000);
    assert(run() == ETIMEDOUT && now == 350000);
    reset(100000, 348000);
    assert(run() == 0 && now == 348000);
    reset(100000, 348000); completionReadCost = 2000;
    assert(run() == ETIMEDOUT && now == 350000);
    // Concurrent slot quarantine wins over a matched response.
    reset(100000, 100000); quarantineAt = 100000;
    assert(run() == EIO && now == 100000);
    reset(100000, 100000); quarantineAfterCompletion = true;
    assert(run() == EIO && now == 100000);
    // A successful submit without a recorded doorbell is inconsistent.
    reset(100000, never); submitCalled = true; submitResult = 0;
    doorbell = false;
    assert(run() == EPROTO && now == 100000);
}
'''

with tempfile.TemporaryDirectory(prefix="test125-end-completion-") as tmp:
    cpp, exe = Path(tmp) / "wait.cpp", Path(tmp) / "wait"
    cpp.write_text(fixture)
    subprocess.run(["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                    str(cpp), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("Test125: 14 production-loop ordering/lifetime cases passed; no RF")
