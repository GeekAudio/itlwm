#!/usr/bin/env python3
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/awdl_mif_pacing_test.cpp"
PROBE_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


def function_body(source, signature):
    """Return one C++ function body while ignoring braces in comments/strings."""
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
            elif (state == "string" and char == '"') or (
                    state == "char" and char == "'"):
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
    raise AssertionError(f"Unclosed function body: {signature}")


def verify_production_source_contracts():
    source = PROBE_SOURCE.read_text(encoding="utf-8")
    read_gate = function_body(
        source, "static IOReturn readMifPacingPeerInGate(")
    # Deep pacing reads consume bounded records before sampling the clock;
    # the Test067 stack fix moved heavy publication to the shallow drain path.
    assert "owner->tahoeP2pRxDrain()" not in read_gate
    assert read_gate.index("owner->tahoeP2pRxConsume()") < read_gate.index(
        "p2pProbeMonotonicNanoseconds()")
    assert "getPsfSnapshot(" in read_gate
    assert "_peer_runtime_.snapshot(" not in read_gate
    assert "ieee80211_chan2ieee(&ic, &ic.ic_channels[newest.rxChannel]) == 6" in read_gate
    assert "tahoe_awdl_peer_observer_.observe(" not in read_gate
    assert "runAction(" not in read_gate

    worker = function_body(
        source, "static bool tryPrepareMifAtPacingPoint(")
    read_at = worker.index("if (!readMifPacingPeer(probe, &peer))")
    sample_at = worker.index("const uint64_t afterGateUs", read_at)
    plan_at = worker.index("planMifPacing(", sample_at)
    assert read_at < sample_at < plan_at
    assert "planNowUs" in worker[plan_at:]

    submit = function_body(
        source, "static IOReturn tahoeP2pSubmitActionInGate(")
    assert submit.count("refreshMifPacingAnchorInGate(") >= 2
    final_check_at = submit.rindex("finalCheckMifPacingAnchorInGate(")
    submit_at = submit.index("iwx_tahoe_p2p_action_tx_submit(")
    assert final_check_at < submit_at
    assert submit.rindex("makeActionFrameFromBytes(", 0, final_check_at) >= 0
    assert "finalPacingPlan.anchorRxUs !=" in submit[final_check_at:submit_at]
    assert "preparedFrameFresh" in submit[final_check_at:submit_at]

    consumed_at = submit.index("mifPacingLastConsumedAnchorRxUs =")
    accepted_at = submit.index("if (action->result == 0)", submit_at)
    assert submit_at < accepted_at < consumed_at
    assert "mifPacingAnchorCount" in submit[consumed_at:]
    assert "kMifPacingMaximumFrames" in submit[consumed_at:]

    final_check = function_body(
        source, "static NativeAwdlProbe::MifPacingPlan finalCheckMifPacingAnchorInGate(")
    assert "planMifPacing(" in final_check
    assert "nativeP2pRocEvents_.snapshot()" in final_check
    assert "sc.sc_generation" in final_check
    assert "sc.sc_tx_rate_generation" in final_check
    assert "runAction(" not in final_check

with tempfile.TemporaryDirectory(prefix="awdl-mif-pacing-058-") as directory:
    binary = pathlib.Path(directory) / "awdl-mif-pacing-test"
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(SOURCE), "-o", str(binary),
    ], cwd=ROOT, check=True)
    subprocess.run([str(binary)], cwd=ROOT, check=True)

print("PASS: Test058 MIF pacing bounds, fresh PSF anchor, channel mapping, epochs, and fail-closed deadline under ASan/UBSan")
verify_production_source_contracts()
print("PASS: Test058 production source contracts (static review; no live kernel callback executed)")
