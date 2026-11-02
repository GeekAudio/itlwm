#!/usr/bin/env python3
"""Fault-test the production completed-data logical retirement transition."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ACTION = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


transition = extract(ACTION, "static void directedDataMarkCompletedClosed(")
close = extract(ACTION, "int iwx_tahoe_p2p_directed_data_close(")
commit = extract(ACTION, "static IOReturn directedDataCommitCloseAction(")
snapshot = extract(ACTION,
    "bool iwx_tahoe_p2p_directed_data_snapshot(")
snapshot_action = extract(ACTION, "static IOReturn directedDataSnapshotAction(")
response = extract(ACTION,
    "bool iwx_tahoe_p2p_directed_data_tx_response(")
unknown_completion = commit.index(
    "if (context->doorbellIssued &&")
assert commit.index("directedDataMarkCompletedClosed(context)") > unknown_completion
assert "!context->completionObserved || context->mbufHeldByRing" in commit
assert "context->state != TahoeP2PDirectedDataState::kQuarantined" in commit
assert "context->originClosed = true;" in commit
assert "directedDataCaptureCloseIdentityAction" in close
assert "directedDataCommitCloseAction" in close
assert close.index("directedDataCaptureCloseIdentityAction") < \
       close.index("NativeAwdlBSD::closeDirectedOriginTx") < \
       close.index("directedDataCommitCloseAction")
assert "owner->tahoeP2pOnMainGate()" in snapshot_action
assert "directedDataSnapshotAction, &action, tryOnly)" in snapshot
assert "*gateResultOut = static_cast<int>(gateResult)" in snapshot
assert "return gateResult == kIOReturnSuccess && action.valid" in snapshot
assert "directedDataCaptureSnapshot" not in snapshot
assert "gate->runAction(action, owner, argument, nullptr, nullptr)" in ACTION
assert "gate->attemptAction(action, owner, argument, nullptr," in ACTION
assert response.index("!owner->tahoeP2pOnMainGate()") < \
       response.index("!context->binding.runSerial")

fixture = r"""
#include <cassert>
#include <cstdint>

enum class TahoeP2PDirectedDataState : uint8_t {
    kIdle, kArmed, kTicketBound, kPermitIssued, kInFlight,
    kCompleted, kQuarantined, kClosed
};
struct TahoeP2PDirectedDataContext {
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kIdle;
    bool completionObserved = false;
    bool mbufHeldByRing = false;
    bool frameAttemptSucceeded = false;
    uint16_t firmwareStatus = 0xffff;
    uint64_t runSerial = 0;
    uint16_t expectedNextSsn = 0xffff;
};
""" + transition + r"""
int main() {
    TahoeP2PDirectedDataContext completed;
    completed.state = TahoeP2PDirectedDataState::kCompleted;
    completed.completionObserved = true;
    completed.frameAttemptSucceeded = false;
    completed.firmwareStatus = 0x12;
    completed.runSerial = 71;
    completed.expectedNextSsn = 9;
    directedDataMarkCompletedClosed(&completed);
    assert(completed.state == TahoeP2PDirectedDataState::kClosed);
    // Logical resource retirement must not erase the exact TX_RSP evidence.
    assert(completed.completionObserved && !completed.frameAttemptSucceeded);
    assert(completed.firmwareStatus == 0x12);
    assert(completed.runSerial == 71 && completed.expectedNextSsn == 9);

    TahoeP2PDirectedDataContext noResponse;
    noResponse.state = TahoeP2PDirectedDataState::kCompleted;
    directedDataMarkCompletedClosed(&noResponse);
    assert(noResponse.state == TahoeP2PDirectedDataState::kCompleted);

    TahoeP2PDirectedDataContext mapped;
    mapped.state = TahoeP2PDirectedDataState::kCompleted;
    mapped.completionObserved = true;
    mapped.mbufHeldByRing = true;
    directedDataMarkCompletedClosed(&mapped);
    assert(mapped.state == TahoeP2PDirectedDataState::kCompleted);

    TahoeP2PDirectedDataContext unknown;
    unknown.state = TahoeP2PDirectedDataState::kQuarantined;
    unknown.completionObserved = true;
    directedDataMarkCompletedClosed(&unknown);
    assert(unknown.state == TahoeP2PDirectedDataState::kQuarantined);

    TahoeP2PDirectedDataContext empty;
    directedDataMarkCompletedClosed(&empty);
    assert(empty.state == TahoeP2PDirectedDataState::kIdle);
}
"""

with tempfile.TemporaryDirectory(prefix="test107-data-retirement-") as tmp:
    source = Path(tmp) / "retirement.cpp"
    binary = Path(tmp) / "retirement"
    source.write_text(fixture)
    compiled = subprocess.run(
        ["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(source), "-o", str(binary)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    subprocess.run([str(binary)], check=True)

print("Test107 completed data retirement ownership passed")
