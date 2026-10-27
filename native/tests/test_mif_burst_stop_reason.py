#!/usr/bin/env python3
"""Regression test for preserving the specific MIF burst stop cause."""
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


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


body = function_body(
    SOURCE.read_text(encoding="utf-8"),
    "static void recordMifPacingPlan(P2PProbeRun *probe,")

harness = r'''#include <assert.h>
#include <stdint.h>
#include "native/awdl_mif_pacing.hpp"
#include "native/awdl_mif_burst.hpp"
#include "native/awdl_mif_tx_gate.hpp"

struct ItlIwx {};
enum {
    kMifProbePreflightRejected = 3,
    kMifProbeWaitingForPeerPsf = 13
};
struct P2PProbeRun {
    ItlIwx *owner = nullptr;
    uint32_t mifPacingReason = 0;
    uint64_t mifPacingEarliestUs = 0;
    uint64_t mifPacingLatestUs = 0;
    uint64_t mifPacingCandidateAnchorRxUs = 0;
    bool mifBurstStopped = false;
    uint32_t mifStatus = 0;
    uint32_t mifBlockers = 0;
    uint32_t mifBurstStopReason = 0;
};
static void publishMifProbeDetails(ItlIwx *, const P2PProbeRun *) {}
'''

program = harness + r'''
static void recordMifPacingPlan(P2PProbeRun *probe,
                                const NativeAwdlProbe::MifPacingPlan &plan,
                                bool stop) {
''' + body + r'''
}
int main() {
    using namespace NativeAwdlProbe;
    const MifPacingPlan stopPlan{
        MifPacingDecision::Stop, MifPacingReason::ReadyAnchor,
        100, 200, 0, 0};

    // The caller has a more specific terminal cause from the repeat planner.
    P2PProbeRun dataStarted{};
    dataStarted.mifBurstStopReason = static_cast<uint32_t>(
        MifBurstStopReason::DataStarted);
    recordMifPacingPlan(&dataStarted, stopPlan, true);
    assert(dataStarted.mifBurstStopReason == static_cast<uint32_t>(
        MifBurstStopReason::DataStarted));

    // A stop without a specific cause still gets a useful generic label.
    P2PProbeRun unknownStop{};
    recordMifPacingPlan(&unknownStop, stopPlan, true);
    assert(unknownStop.mifBurstStopReason == static_cast<uint32_t>(
        MifBurstStopReason::CandidatePreparationFailed));
}
'''

with tempfile.TemporaryDirectory(prefix="awdl-mif-stop-reason-") as directory:
    source = pathlib.Path(directory) / "stop_reason_test.cpp"
    binary = pathlib.Path(directory) / "stop_reason_test"
    source.write_text(program, encoding="utf-8")
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT), str(source), "-o", str(binary),
    ], cwd=ROOT, check=True)
    subprocess.run([str(binary)], cwd=ROOT, check=True)

print("PASS: production MIF stop telemetry preserves specific causes")
