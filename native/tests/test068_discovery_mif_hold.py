#!/usr/bin/env python3
"""Test068 bounded MIF repeat reservation and production source contracts."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
BINDING = ROOT / "native/awdl_discovery_admitted_binding.hpp"
POLICY_TEST = ROOT / "native/tests/awdl_mif_discovery_hold_test068.cpp"


def function_body(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif ((state == "string" and char == '"') or
                  (state == "char" and char == "'")):
                state = "code"
        elif char == "/" and following == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and following == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
        index += 1
    raise AssertionError(f"Unclosed C++ body: {signature}")


source = PROBE.read_text(encoding="utf-8")
binding = BINDING.read_text(encoding="utf-8")

# The MIF repeat pause is tied to a pending one-shot reservation, its live
# same-entry binding, epoch match, and the candidate's bounded exclusive end.
hold_start = source.index("const NativeAwdlMifDiscoveryHoldTest068::Input discoveryHoldInput{")
hold_end = source.index("const bool holdMifForDiscovery", hold_start)
hold_call = source[hold_start:hold_end]
for required in (
        "probe->discoveryCandidateLocked",
        "probe->discoveryRequiresRuntimeMifBinding",
        "probe->discoveryRuntimeMifBound",
        "probe->discoveryBindingLocked",
        "probe->discoveryBinding.hasPendingReservation()",
        "Test066MifCurrentPhase::Status::kCandidate",
        "Test066MifCurrentPhase::sameEpochs(",
        "event.snapshot.endSeen",
        "event.snapshot.outcomeUnknown",
        "discoveryUsableLeaseEndUs"):
    assert required in hold_call, required
for forbidden in ("owner->", "self->", "com.sc_generation",
                  "sc_tx_rate_generation", "nativeP2pProbeGeneration_",
                  "isCurrentIeeeChannel6("):
    assert forbidden not in hold_call, forbidden
assert "hasPendingReservation()" in binding

repeat = source[source.index("if (probe->awdlMifFollowupEnabled && !holdMifForDiscovery"):]
repeat = repeat[:repeat.index("if (successfulStart &&")]
assert "mifBurstSubmittedFrames <" in repeat
assert "NativeAwdlProbe::kMifPacingMaximumFrames" in repeat
assert "tryPrepareMifAtPacingPoint(probe, event.snapshot" in repeat

# The hold policy is scheduling-only: data still requires the old same-entry,
# one-shot, strict QM, epochs, ROC, ring-idle and final submit gates.
mif = function_body(source, "static mbuf_t takeDiscoveryPacketMifCurrent(")
assert "run->nativeDataAttempts != 0" in mif
assert "sameDiscoveryHead(head, run->discoveryHead)" in mif
assert "run->discoveryBinding.authorizeTake(" in mif
assert "NativeAwdlBSD::nextDiscoveryTx(" in mif
assert "input.gates.ringIdle = ringIdle;" in mif
assert "input.gates.strictQmHeadStable = strictHeadStable;" in mif
assert "window.requireRuntimeMifBinding = true;" in mif
assert "window.phaseLatestUs = target.latestSubmitUs;" in mif
assert "finalRingIdle" in mif and "finalHeadStable" in mif

# Live power/station generations, ROC ownership, channel-6 identity and the
# data submission gate remain checked in their original serialized paths.
worker = function_body(source, "static int runTxProbeSession(")
data_gate = worker[worker.index("const NativeAwdlDataGate::State dataState{"):]
data_gate = data_gate[:data_gate.index("const uint32_t blockers=")]
for required in ("nativeP2pProbeGeneration_==run->contextGeneration",
                 "uint32_t(sc.sc_generation)==run->powerGeneration",
                 "sc_tx_rate_generation", "sc.sc_p2p.fw_generation==run->powerGeneration",
                 "session.generation==run->contextGeneration",
                 "!session.endSeen&&!session.outcomeUnknown",
                 "IWX_P2P_ROC_SESSION_ACKED"):
    assert required in data_gate, required
assert "isCurrentIeeeChannel6(&self->com.sc_ic" in worker

# The first successful local MIF timestamp stays write-once.
worker = function_body(source, "static int runTxProbeSession(")
first_guard = worker.index("probe->discoveryOwnFirstMifCompletionUs == 0")
first_mif = worker.index(
    "probe->discoveryOwnFirstMifCompletionUs =\n", first_guard)
assert first_guard < first_mif
assert "probe->mifBurstLastCompletionUs" in worker[first_mif:first_mif + 180]

with tempfile.TemporaryDirectory(prefix="awdl-test068-") as directory:
    binary = pathlib.Path(directory) / "awdl-mif-discovery-hold-test068"
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(POLICY_TEST), "-o", str(binary),
    ], cwd=ROOT, check=True)
    subprocess.run([str(binary)], cwd=ROOT, check=True)

print("PASS: Test068 pending same-entry MIF hold is bounded to its half-open target window under ASan/UBSan")
print("PASS: Test068 production source contracts preserve existing data, queue, MIF pacing, and write-once gates")
