#!/usr/bin/env python3
"""Test080 RX149 profile contract and production wiring under ASan/UBSan."""

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).with_suffix(".cpp")
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
RX = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


def check_source_contract() -> None:
    probe = PROBE.read_text()
    rx = RX.read_text()
    exercise = function_body(probe, "static int exerciseRx149Observation(")
    assert "tahoeP2pRocPrepare" in exercise
    assert "kIeeeChannel" in exercise and "kSessionDurationMs" in exercise
    assert "mayReleaseAfterEnd" in exercise
    assert "tahoeP2pRocCleanup" in exercise
    for forbidden in (
        "makeActionFrameFromBytes",
        "preparePsfCandidateAfterStart",
        "prepareMifCandidateAfterPsfCompletion",
        "submitDiscoveryPacket",
        "submitNativeData",
        "iwx_tahoe_p2p_action_tx_submit",
        "iwx_tahoe_p2p_tvqm_allocate",
    ):
        assert forbidden not in exercise, forbidden

    tap = function_body(rx, "void ItlIwx::tahoeP2pTapAction(")
    assert "mayConsumeManagementAction" in tap
    assert "nativeDataPathAllowed" in tap
    assert tap.index("mayConsumeManagementAction") < tap.index("recordActionTap(")
    assert tap.index("recordActionTap(") < tap.index("tapActionFrame(")
    assert "receive_observation_only" in tap

    action_evidence = function_body(
        rx, "NativeP2PRx149Observation::RocEvidence currentRx149ActionEvidence(")
    assert "owner->tahoeP2pController()" in action_evidence
    assert "owner->getController()" not in action_evidence

    event_action = function_body(
        probe, "IOReturn ItlIwx::tahoeP2pRocEventAction(")
    close = function_body(probe, "static int exerciseRx149Observation(")
    post_cleanup_owner = function_body(
        probe, "static bool rx149PostCleanupOwnerEpochTokenMatches(")
    receipt_capture = function_body(
        probe, "captureRx149FailedEndCleanupReceipt(")
    receipt_seal = function_body(
        probe, "static bool sealRx149FailedEndCleanupReceipt(")
    assert "kRocCloseRx149" in event_action
    assert event_action.index("closeProducer(") < event_action.index(
        "tahoeP2pRxConsume();")
    assert "untrackedPendingIdentityOverflowCount == 0" in event_action
    assert "tahoeP2pPublishRxEventTimeline(controller)" in event_action
    assert close.index("rxDrainComplete") < close.index("tahoeP2pRocCleanup")
    assert "rx149StationAndPhyOwnerCurrent" not in post_cleanup_owner
    assert "roc.station_epoch != probe->stationGeneration" in post_cleanup_owner
    assert "roc.token != probe->contextGeneration" in post_cleanup_owner
    assert "rx149PostCleanupOwnerEpochTokenMatches" in receipt_capture
    assert "sc.sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT" in receipt_capture
    assert "sc.sc_phyctxt[sc.sc_p2p_roc.phy_id].channel" in receipt_capture
    assert receipt_seal.count("captureRx149FailedEndCleanupReceipt(probe)") == 2
    assert "publishCleanupReceipt" in receipt_seal
    assert "mayCleanupAfterFailedEnd" in event_action
    assert "mayReleaseAfterEnd" in event_action

    worker = function_body(probe, "void ItlIwx::tahoeP2pProbeTask(")
    selected = worker.index("run.rx149ObservationOnly")
    assert selected < worker.index("owner->nativeP2pProbe_.executeOnce(operations)")
    rx149_branch = worker.index("if (rx149Latched) {")
    rx149_end = worker.index("if (run.directedPrepareOnly)", rx149_branch)
    assert selected < rx149_branch < rx149_end
    assert "run.txProbeEnabled = false" in worker[rx149_branch:rx149_end]
    assert "run.awdlPsfProbeEnabled = false" in worker[rx149_branch:rx149_end]
    assert "run.awdlMifFollowupEnabled = false" in worker[rx149_branch:rx149_end]

    prearm = function_body(probe, "static IOReturn rx149PrearmCounterAction(")
    assert "probeSnapshot.attempted != 0" in prearm
    assert "rx149TxHistoryQuiescent(owner, &snapshot)" in prearm
    assert prearm.index("rx149TxHistoryQuiescent(owner, &snapshot)") < prearm.index(
        '"NativeP2PAwdlActionFramesSubmitted", uint32_t(0)')
    assert '"NativeP2PTxProbeEverDoorbelled"' in prearm


def main() -> None:
    check_source_contract()
    compiler = os.environ.get("CXX", "clang++")
    with tempfile.TemporaryDirectory(prefix="test080-rx149-") as tmp:
        executable = Path(tmp) / "rx149-observation-asan-ubsan"
        subprocess.run(
            [
                compiler,
                "-std=c++14",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                "-I",
                str(ROOT / "native"),
                str(HARNESS),
                str(ROOT / "native/p2p_hal_probe.cpp"),
                "-o",
                str(executable),
            ],
            check=True,
        )
        environment = dict(os.environ)
        environment.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
        environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
        subprocess.run([str(executable)], check=True, env=environment)
    print("Test080 RX149 observation contract and ASan/UBSan harness passed")


if __name__ == "__main__":
    main()
