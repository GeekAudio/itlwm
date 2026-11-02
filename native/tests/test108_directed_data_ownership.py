#!/usr/bin/env python3
"""Exercise the production Data may-own atomic and safe-clear predicate."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ACTION = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
ITL = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


set_may_own = extract(ACTION, "static void directedDataSetMayOwnResource(")
can_clear = extract(ACTION,
    "static bool directedDataCanClearMayOwnResource(")

arm = extract(ACTION, "int iwx_tahoe_p2p_directed_data_arm(")
arm_flat = " ".join(arm.split())
assert arm_flat.index("directedDataSetMayOwnResource(context, true)") < \
       arm_flat.index("context->state = TahoeP2PDirectedDataState::kArmed")

quarantine = extract(ACTION,
    "void iwx_tahoe_p2p_directed_data_quarantine(")
assert quarantine.index("directedDataSetMayOwnResource(context, true)") < \
       quarantine.index("context->state = TahoeP2PDirectedDataState::kQuarantined")

close_commit = extract(ACTION,
    "static IOReturn directedDataCommitCloseAction(")
assert "directedDataCanClearMayOwnResource(context)" in close_commit
assert close_commit.index("context->originClosed = true") < \
       close_commit.index("directedDataCanClearMayOwnResource(context)")

hardstop = extract(ACTION,
    "static IOReturn directedDataHardStopFinalizeAction(")
assert "context->hardStopDrained = finalize->queueReleased" in hardstop
assert hardstop.index("context->hardStopDrained = finalize->queueReleased") < \
       hardstop.index("directedDataCanClearMayOwnResource(context)")

guard = extract(ITL, "bool ItlIwx::nativeP2pResourcesRetained()")
guard_flat = " ".join(guard.split())
assert "__atomic_load_n( &nativeP2pDirectedDataTx_.mayOwnResource, __ATOMIC_ACQUIRE)" in guard_flat
assert guard_flat.index("if (directedDataMayOwn != 0)") < \
       guard_flat.index("iwx_tahoe_p2p_directed_data_snapshot(this,")
assert "bool dataRetained = false;" in guard
assert "NativeP2PStopDataSnapshotAttempted" in guard
assert "NativeP2PStopDataSnapshotValid" in guard
assert "NativeP2PStopDataSnapshotGateResult" in guard

worker = extract(PROBE, "static int exerciseDirectedDataTx(P2PProbeRun *probe)")
failure = extract(worker,
    "auto recordFailure = [&](int error, uint32_t stage) {")
unbound_close = extract(failure, "} else if (dataTicketWasOpened) {")
exact_close = extract(unbound_close,
    "if (NativeAwdlBSD::closeDirectedOriginTx(")
assert "probe->directedDataOriginTicket" in exact_close
assert "dataTicketWasOpened = false;" in exact_close
assert "iwx_tahoe_p2p_directed_data_close(" in exact_close
assert exact_close.index("dataTicketWasOpened = false;") < \
       exact_close.index("iwx_tahoe_p2p_directed_data_close(")

snapshot = extract(ACTION,
    "bool iwx_tahoe_p2p_directed_data_snapshot(")
assert "gateResultOut" in snapshot
assert "*gateResultOut = static_cast<int>(gateResult)" in snapshot

fixture = r"""
#include <cassert>
#include <cstdint>

enum class TahoeP2PDirectedDataState : uint8_t {
    kIdle, kArmed, kTicketBound, kPermitIssued, kInFlight,
    kCompleted, kQuarantined, kClosed
};
struct CompletionSnapshot { bool armed; bool completed; };
struct Completion { CompletionSnapshot value{};
    CompletionSnapshot snapshot() const { return value; }
};
struct TahoeP2PDirectedDataContext {
    Completion completion;
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kIdle;
    bool originClosed = false;
    bool doorbellIssued = false;
    bool completionObserved = false;
    bool mbufHeldByRing = false;
    bool hardStopDrained = false;
    uint32_t mayOwnResource = 0;
};
""" + set_may_own + can_clear + r"""
int main() {
    TahoeP2PDirectedDataContext neverArmed;
    assert(__atomic_load_n(&neverArmed.mayOwnResource, __ATOMIC_ACQUIRE) == 0);
    directedDataSetMayOwnResource(&neverArmed, true);
    assert(__atomic_load_n(&neverArmed.mayOwnResource, __ATOMIC_ACQUIRE) == 1);
    directedDataSetMayOwnResource(&neverArmed, false);
    assert(__atomic_load_n(&neverArmed.mayOwnResource, __ATOMIC_ACQUIRE) == 0);

    TahoeP2PDirectedDataContext unsubmitted;
    unsubmitted.state = TahoeP2PDirectedDataState::kClosed;
    unsubmitted.originClosed = true;
    directedDataSetMayOwnResource(&unsubmitted, true);
    assert(directedDataCanClearMayOwnResource(&unsubmitted));

    TahoeP2PDirectedDataContext unsubmittedAfterPriorCompletion;
    unsubmittedAfterPriorCompletion.state = TahoeP2PDirectedDataState::kClosed;
    unsubmittedAfterPriorCompletion.originClosed = true;
    unsubmittedAfterPriorCompletion.completion.value = {true, true};
    assert(directedDataCanClearMayOwnResource(
        &unsubmittedAfterPriorCompletion));

    TahoeP2PDirectedDataContext pendingCompletion;
    pendingCompletion.state = TahoeP2PDirectedDataState::kClosed;
    pendingCompletion.originClosed = true;
    pendingCompletion.completion.value = {true, false};
    assert(!directedDataCanClearMayOwnResource(&pendingCompletion));

    TahoeP2PDirectedDataContext unknownDoorbell;
    unknownDoorbell.state = TahoeP2PDirectedDataState::kClosed;
    unknownDoorbell.originClosed = true;
    unknownDoorbell.doorbellIssued = true;
    unknownDoorbell.completion.value = {true, false};
    assert(!directedDataCanClearMayOwnResource(&unknownDoorbell));

    TahoeP2PDirectedDataContext heldMbuf;
    heldMbuf.state = TahoeP2PDirectedDataState::kClosed;
    heldMbuf.originClosed = true;
    heldMbuf.doorbellIssued = true;
    heldMbuf.completionObserved = true;
    heldMbuf.completion.value = {true, true};
    heldMbuf.mbufHeldByRing = true;
    assert(!directedDataCanClearMayOwnResource(&heldMbuf));

    TahoeP2PDirectedDataContext completed;
    completed.state = TahoeP2PDirectedDataState::kClosed;
    completed.originClosed = true;
    completed.doorbellIssued = true;
    completed.completionObserved = true;
    completed.completion.value = {true, true};
    assert(directedDataCanClearMayOwnResource(&completed));

    TahoeP2PDirectedDataContext quarantined;
    quarantined.state = TahoeP2PDirectedDataState::kQuarantined;
    quarantined.originClosed = true;
    quarantined.hardStopDrained = true;
    assert(!directedDataCanClearMayOwnResource(&quarantined));

    TahoeP2PDirectedDataContext hardStopped;
    hardStopped.state = TahoeP2PDirectedDataState::kClosed;
    hardStopped.originClosed = true;
    hardStopped.hardStopDrained = true;
    assert(directedDataCanClearMayOwnResource(&hardStopped));
}
"""

with tempfile.TemporaryDirectory(prefix="test108-data-may-own-") as tmp:
    source = Path(tmp) / "may_own.cpp"
    binary = Path(tmp) / "may_own"
    source.write_text(fixture)
    compiled = subprocess.run(
        ["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(source), "-o", str(binary)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    subprocess.run([str(binary)], check=True)

print("Test108 directed-data ownership transitions passed")
