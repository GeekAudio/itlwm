#!/usr/bin/env python3
"""Fault-inject the actual TX_RSP handler's watchdog/reclaim boundary.

The host C++ shim is taken from Test076, but the function under test is always
extracted from current ItlIwx.cpp. Test082 additionally changes a response
status and arms a nonzero watchdog to prove invalid SSN/ring responses do not
clear it, while a valid descriptor clears and reclaims under both success and
failed TX status. The final note records the production owner/generation gap.
"""

from __future__ import annotations

import ast
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
BASE_TEST = ROOT / "native/tests/test076_tx_completion_observation.py"


STA_CORRELATION_TEST = r"""
static void testStaTxCorrelationIsNotFirmwareOwnership()
{
    iwx_sta_tx_observation_state state{};
    IwxStaTxObservation::initialize(&state);
    const uint32_t identity = IWX_STA_TX_OBS_HAS_DRIVER_GENERATION |
        IWX_STA_TX_OBS_HAS_OUTPUT_EPOCH | IWX_STA_TX_OBS_HAS_QID |
        IWX_STA_TX_OBS_HAS_FRAME_CONTROL |
        IWX_STA_TX_OBS_HAS_SEQUENCE_CONTROL;
    iwx_sta_tx_obs_event submit{};
    submit.kind = IWX_STA_TX_OBS_SUBMIT;
    submit.presence_flags = identity;
    submit.driver_generation = 5;
    submit.output_epoch = 5;
    submit.qid = 1;
    submit.frame_control = 0x00b0; // Authentication management frame.
    submit.sequence_control = 0x1230;
    uint64_t submitSerial = 0;
    assert(IwxStaTxObservation::record(&state, &submit, &submitSerial));
    assert(submitSerial != 0);

    iwx_sta_tx_obs_event response = submit;
    response.kind = IWX_STA_TX_OBS_RESPONSE;
    response.frame_count = 1;
    response.status = 5; // Failed TX status still only identifies a host tuple.
    response.presence_flags |= IWX_STA_TX_OBS_HAS_FRAME_COUNT |
        IWX_STA_TX_OBS_HAS_STATUS;
    assert(IwxStaTxObservation::record(&state, &response));
    iwx_sta_tx_observation_snapshot snapshot{};
    assert(IwxStaTxObservation::snapshot(&state, &snapshot));
    assert(snapshot.complete && snapshot.response_count == 1);
    assert(snapshot.last_response.match_class == IWX_STA_TX_OBS_MATCH_HOST_TUPLE);
    assert(snapshot.last_response.related_serial == submitSerial);
    assert(snapshot.firmware_queue_owner_proven == 0);
    assert(snapshot.firmware_dma_completion_proven == 0);
    assert(snapshot.peer_receipt_proven == 0);

    // The telemetry recognizes a stale host epoch as a different tuple. It
    // does not reject the actual firmware response or prove that firmware
    // honored either epoch.
    response.driver_generation = 6;
    response.output_epoch = 6;
    assert(IwxStaTxObservation::record(&state, &response));
    assert(IwxStaTxObservation::snapshot(&state, &snapshot));
    assert(snapshot.last_response.match_class ==
           IWX_STA_TX_OBS_MATCH_DIFFERENT_HOST_TUPLE);
    assert(snapshot.last_response.related_serial == 0);
    assert(snapshot.firmware_queue_owner_proven == 0);

    // A repeated same-tuple response can correlate to the same submit again;
    // duplicate/late response rejection is explicitly outside this observer.
    response.driver_generation = 5;
    response.output_epoch = 5;
    assert(IwxStaTxObservation::record(&state, &response));
    assert(IwxStaTxObservation::snapshot(&state, &snapshot));
    assert(snapshot.response_count == 3);
    assert(snapshot.last_response.related_serial == submitSerial);
    assert(snapshot.firmware_queue_owner_proven == 0);
}
"""


def braced_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"unterminated production block: {marker}")


def assignment_literal(tree: ast.Module, name: str) -> str:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, str):
                raise AssertionError(f"{name} is no longer a string fixture")
            return value
    raise AssertionError(f"could not reuse Test076 fixture {name}")


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    base_tree = ast.parse(BASE_TEST.read_text(encoding="utf-8"))
    prefix = assignment_literal(base_tree, "CPP_HANDLER_PREFIX")
    tests = assignment_literal(base_tree, "CPP_HANDLER_TESTS")

    tx_handler = braced_source(source, "void ItlIwx::\niwx_rx_tx_cmd(")
    helper_start = source.index(
        "#ifdef AIRPORT_TAHOE\nstatic iwx_tx_completion_event_input txCompletionRxInput("
    )
    helper_end = source.index(
        "\n#endif\n\nvoid ItlIwx::\niwx_rx_tx_ba_notif", helper_start
    ) + len("\n#endif")
    helpers = source[helper_start:helper_end]
    ring_guards = (
        braced_source(source, "static bool iwx_tx_response_ring(")
        + "\n"
        + braced_source(source, "static bool iwx_tx_response_index(")
    )
    sta_helpers = (
        braced_source(source, "static uint64_t recordStaTxResponse(")
        + "\n"
        + braced_source(source, "static void recordStaTxReclaim(")
    )

    # Reuse Test076's real-handler shim and replace only host-side observation
    # boundaries. The production handler's guard, timer clear, and reclaim are
    # left untouched.
    needle = '#include "native/iwx_tx_completion_observation.hpp"'
    if needle not in prefix:
        raise AssertionError("Test076 TX_RSP fixture include anchor changed")
    if '#include "native/iwx_sta_tx_observation.hpp"' not in prefix:
        prefix = prefix.replace(
            needle,
            needle + '\n#include "native/iwx_sta_tx_observation.hpp"',
            1,
        )
    prefix = prefix.replace(
        "#include <assert.h>", "#include <algorithm>\n#include <assert.h>", 1
    )
    softc_start = prefix.index("struct iwx_softc {")
    softc_end = prefix.index("\n};", softc_start)
    softc = prefix[softc_start:softc_end]
    if "sc_generation" not in softc or "sc_sta_tx_observation" not in softc:
        prefix = prefix[:softc_end] + \
            "\n    int sc_generation = 1;\n" \
            "    iwx_sta_tx_observation_state sc_sta_tx_observation{};" + \
            prefix[softc_end:]
    if "sc_sta_tx_observation" not in prefix:
        raise AssertionError("could not extend Test076 softc fixture")
    prefix = prefix.replace(
        "static void clear(int *) { gBusinessCalls.push_back(2); }",
        "static void clear(int *timer) { gBusinessCalls.push_back(2); *timer = 0; }",
        1,
    )
    prefix = prefix.replace(
        "static void iwx_rx_tx_cmd_single(iwx_softc *, iwx_rx_packet *, iwx_tx_data *) {\n    gBusinessCalls.push_back(4);\n}",
        "static uint16_t gObservedTxStatus = 0;\n"
        "static void iwx_rx_tx_cmd_single(iwx_softc *, iwx_rx_packet *pkt, iwx_tx_data *) {\n"
        "    gBusinessCalls.push_back(4);\n"
        "    gObservedTxStatus = reinterpret_cast<const iwx_tx_resp *>(pkt->data)->status.status;\n"
        "}",
        1,
    )

    # Put the watchdog timer into a visible armed state for every case and
    # carry it out of the production call for assertions.
    if tests.count("    int queued;\n    int tail;") != 1:
        raise AssertionError("Test076 outcome fixture changed")
    tests = tests.replace(
        "    int queued;\n    int tail;",
        "    int queued;\n    int tail;\n    int timer;\n    uint16_t responseStatus;\n    iwx_sta_tx_observation_snapshot staObservation{};",
        1,
    )
    tests = tests.replace(
        "    SingleReclaim\n};",
        "    SingleReclaim,\n    SingleReclaimFailedStatus\n};",
        1,
    )
    tests = tests.replace(
        "    sc.sc_tx_output_epoch = 17;",
        "    sc.sc_tx_output_epoch = 17;\n    sc.sc_tx_timer = 15;",
        1,
    )
    tests = tests.replace(
        "        response->status.status = 0;",
        "        response->status.status = scenario == SingleReclaimFailedStatus ? 5 : 0;",
        1,
    )
    tests = tests.replace(
        "    result.tail = sc.txq[1].tail;",
        "    result.tail = sc.txq[1].tail;\n    result.timer = sc.sc_tx_timer;\n    result.responseStatus = gObservedTxStatus;\n"
        "    assert(IwxStaTxObservation::snapshot(&sc.sc_sta_tx_observation, &result.staObservation));",
        1,
    )
    tests = tests.replace(
        "    assert(enabled.outputEpoch == 17);",
        "    assert(enabled.outputEpoch == 17);\n"
        "    const bool timerWasCleared = std::find(expectedCalls.begin(), expectedCalls.end(), 2) != expectedCalls.end();\n"
        "    assert(enabled.timer == (timerWasCleared ? 0 : 15));",
        1,
    )
    tests = tests.replace(
        "    compareScenario(RingEmpty,\n        IWX_TX_COMPLETION_TX_RSP_SINGLE_RING_EMPTY, {1, 2, 3});",
        "    compareScenario(RingEmpty,\n        IWX_TX_COMPLETION_TX_RSP_SINGLE_RING_EMPTY, {1});",
        1,
    )
    tests = tests.replace(
        "    compareScenario(ForcedSsnIndexReject,\n        IWX_TX_COMPLETION_TX_RSP_SSN_INDEX_REJECTED, {1, 2, 3});",
        "    compareScenario(ForcedSsnIndexReject,\n        IWX_TX_COMPLETION_TX_RSP_SSN_INDEX_REJECTED, {1});",
        1,
    )
    tests = tests.replace(
        "    testProductionRecordHelperKeepsPerKindEpochs();",
        "    compareScenario(SingleReclaimFailedStatus,\n"
        "        IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED,\n"
        "        {1, 2, 3, 4, 5, 6});\n"
        "    const Outcome failedStatus = runScenario(SingleReclaimFailedStatus, true);\n"
        "    assert(failedStatus.timer == 0 && failedStatus.queued == 2 && failedStatus.tail == 2);\n"
        "    assert(failedStatus.responseStatus == 5);\n"
        "    assert(failedStatus.staObservation.submit_count == 0);\n"
        "    assert(failedStatus.staObservation.response_count == 1);\n"
        "    assert(failedStatus.staObservation.reclaim_count == 1);\n"
        "    assert(failedStatus.staObservation.last_response.match_class == IWX_STA_TX_OBS_MATCH_NO_SUBMIT);\n"
        "    assert(failedStatus.staObservation.last_reclaim.related_serial == failedStatus.staObservation.last_response.serial);\n"
        "    assert(failedStatus.staObservation.firmware_queue_owner_proven == 0);\n"
        "    const Outcome emptyResponse = runScenario(RingEmpty, true);\n"
        "    assert(emptyResponse.timer == 15 && emptyResponse.staObservation.response_count == 1);\n"
        "    assert(emptyResponse.staObservation.reclaim_count == 0);\n"
        "    testProductionRecordHelperKeepsPerKindEpochs();",
        1,
    )
    if "SingleReclaimFailedStatus" not in tests:
        raise AssertionError("failed TX-status case was not added")
    tests = tests.replace(
        "int main() {", STA_CORRELATION_TEST + "\nint main() {", 1
    )
    tests = tests.replace(
        "    testProductionRecordHelperKeepsPerKindEpochs();",
        "    testProductionRecordHelperKeepsPerKindEpochs();\n"
        "    testStaTxCorrelationIsNotFirmwareOwnership();",
        1,
    )

    # The observation schema intentionally cannot claim firmware owner/DMA
    # ownership. Keep that boundary machine-checked and visible in test output.
    sta_header = (ROOT / "native/iwx_sta_tx_observation.hpp").read_text()
    assert "value.firmware_queue_owner_proven = 0;" in sta_header
    assert "value.firmware_dma_completion_proven = 0;" in sta_header
    assert "value.peer_receipt_proven = 0;" in sta_header
    owner_guard_before_reclaim = (
        "match_class" in tx_handler[: tx_handler.index("iwx_ampdu_txq_advance(")]
        or "related_response_serial" in tx_handler[: tx_handler.index("iwx_ampdu_txq_advance(")]
    )

    # Test076's helper range uses the same actual ring and TX_RSP functions.
    assert ring_guards.count("IwxTxRingCapacity::responseIndex(") == 1
    ring_guards = ring_guards.replace(
        "IwxTxRingCapacity::responseIndex(", "txResponseIndexForHarness(", 1
    )
    compiler = shutil.which("clang++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("No C++ compiler found")
    with tempfile.TemporaryDirectory(prefix="test082-tx-rsp-") as directory:
        harness = Path(directory) / "test082_tx_rsp_watchdog_clear.cpp"
        binary = Path(directory) / "test082_tx_rsp_watchdog_clear"
        harness.write_text(
            prefix + helpers + "\n" + ring_guards + "\n" + sta_helpers
            + "\n" + tx_handler + "\n" + tests,
            encoding="utf-8",
        )
        compiled = subprocess.run(
            [compiler, "-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-function", "-fsanitize=address,undefined",
             "-fno-omit-frame-pointer", "-pthread", "-I", str(ROOT),
             str(harness), "-o", str(binary)],
            capture_output=True,
            text=True,
        )
        if compiled.returncode:
            raise RuntimeError(compiled.stderr or compiled.stdout)
        run = subprocess.run([str(binary)], capture_output=True, text=True)
        if run.returncode:
            raise AssertionError(run.stdout + run.stderr)
        print("PASS: actual TX_RSP handler retains watchdog on empty/invalid single-frame response and clears/reclaims a valid descriptor even with failed status")
    print(
        "LIMIT: firmware TX_RSP carries no host generation/queue-incarnation owner; "
        + ("an owner guard is present before reclaim" if owner_guard_before_reclaim else
           "this test does not claim an owner/generation rejection gate; snapshot matching is correlation evidence only")
    )


if __name__ == "__main__":
    main()
