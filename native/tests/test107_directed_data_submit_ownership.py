#!/usr/bin/env python3
"""Fault-test the production HAL submit wrapper's mbuf ownership boundary."""
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


submit_action = extract(ACTION, "struct DirectedDataSubmitAction {")
gate_action = extract(ACTION, "static IOReturn directedDataTxSubmitAction(")
submit = extract(ACTION, "int iwx_tahoe_p2p_directed_data_tx_submit(")

fixture = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>

using IOReturn = int;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnBusy = -1;
static constexpr IOReturn kIOReturnBadArgument = -2;
struct OSObject {};
struct iwx_softc {};
struct TahoeP2PStationLease {};
struct TahoeP2PTxQueueLease {};
struct TahoeP2PDirectedDataContext {};
struct TahoeP2PDirectedDataPermit {};
struct Mbuf { unsigned id; };
using mbuf_t = Mbuf *;
static unsigned gFreed = 0;
static void mbuf_freem(mbuf_t packet) {
    if (packet) { ++gFreed; delete packet; }
}
static mbuf_t packet(unsigned id) { return new Mbuf{id}; }

using GateAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);
struct IOCommandGate {
    OSObject *target = nullptr;
    bool invoke = false;
    IOReturn result = kIOReturnBusy;
    unsigned calls = 0;
    IOReturn attemptAction(GateAction action, void *arg0, void *arg1,
                           void *arg2, void *arg3) {
        ++calls;
        if (invoke)
            action(target, arg0, arg1, arg2, arg3);
        return result;
    }
};
struct ItlIwx : OSObject {
    iwx_softc com;
    bool inGate = false;
    IOCommandGate *gate = nullptr;
    bool tahoeP2pOnMainGate() const { return inGate; }
    IOCommandGate *tahoeP2pCommandGate() const { return gate; }
};
static unsigned gSubmitCalls = 0;
static int gSubmitResult = EIO;
static int directedDataTxSubmitOnMainGate(
    ItlIwx *, iwx_softc *, TahoeP2PStationLease *,
    TahoeP2PTxQueueLease *, TahoeP2PDirectedDataContext *,
    TahoeP2PDirectedDataPermit *, mbuf_t packet) {
    ++gSubmitCalls;
    mbuf_freem(packet); // The production inner submitter consumes this input.
    return gSubmitResult;
}
""" + submit_action + ";\n" + gate_action + "\n" + submit + r"""
int main() {
    ItlIwx owner;
    iwx_softc other;
    TahoeP2PStationLease station;
    TahoeP2PTxQueueLease queue;
    TahoeP2PDirectedDataContext context;
    TahoeP2PDirectedDataPermit permit;

    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &owner.com, &station, &queue, &context, &permit, nullptr) == EINVAL);
    assert(gFreed == 0);

    auto invalidOwnerPacket = packet(1);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        nullptr, &other, &station, &queue, &context, &permit,
        invalidOwnerPacket) == EINVAL);
    assert(gFreed == 1);

    auto mismatchedSoftcPacket = packet(2);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &other, &station, &queue, &context, &permit,
        mismatchedSoftcPacket) == EINVAL);
    assert(gFreed == 2);

    owner.inGate = true;
    gSubmitResult = EINVAL;
    auto directPacket = packet(3);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &owner.com, &station, &queue, &context, &permit,
        directPacket) == EINVAL);
    assert(gFreed == 3 && gSubmitCalls == 1);
    owner.inGate = false;

    auto noGatePacket = packet(4);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &owner.com, &station, &queue, &context, &permit,
        noGatePacket) == EBUSY);
    assert(gFreed == 4);

    IOCommandGate gate;
    gate.target = &owner;
    owner.gate = &gate;
    gate.invoke = false;
    gate.result = kIOReturnSuccess;
    auto gateRejectedPacket = packet(5);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &owner.com, &station, &queue, &context, &permit,
        gateRejectedPacket) == EBUSY);
    assert(gFreed == 5 && gate.calls == 1 && gSubmitCalls == 1);

    gate.invoke = true;
    gSubmitResult = 0;
    auto submittedPacket = packet(6);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &owner.com, &station, &queue, &context, &permit,
        submittedPacket) == 0);
    assert(gFreed == 6 && gate.calls == 2 && gSubmitCalls == 2);
    // Once called, the wrapper trusts the submitter's consume/quarantine
    // contract even if attemptAction reports a late gate-level error.
    gate.result = kIOReturnBusy;
    gSubmitResult = EIO;
    auto calledDespiteGateError = packet(7);
    assert(iwx_tahoe_p2p_directed_data_tx_submit(
        &owner, &owner.com, &station, &queue, &context, &permit,
        calledDespiteGateError) == EIO);
    assert(gFreed == 7 && gate.calls == 3 && gSubmitCalls == 3);
}
"""

with tempfile.TemporaryDirectory(prefix="test107-data-submit-owner-") as tmp:
    source = Path(tmp) / "submit_ownership.cpp"
    binary = Path(tmp) / "submit_ownership"
    source.write_text(fixture)
    compiled = subprocess.run(
        ["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(source), "-o", str(binary)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    subprocess.run([str(binary)], check=True)

print("Test107 submit mbuf ownership boundary passed")
