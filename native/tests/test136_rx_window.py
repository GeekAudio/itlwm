#!/usr/bin/env python3
"""Host regressions for the Test136 discovery RX window."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
CPP_TEST = ROOT / "native/tests/awdl_discovery_rx_window_test.cpp"
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
HEADER = ROOT / "native/awdl_discovery_rx_window.hpp"
FW_REGS = ROOT / "itlwm/hal_iwx/if_iwxreg.h"


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"unterminated function body: {signature}")


def production_contract() -> None:
    probe = PROBE.read_text()
    header = HEADER.read_text()
    fw_regs = FW_REGS.read_text()

    publish = function_body(
        probe, "void ItlIwx::tahoeDiscoveryRxWindowPublish("
    )
    assert "!tahoeP2pOnMainGate()" in publish
    assert "nativeP2PPublicationBusy(this)" in publish
    assert "OSData::withBytes(nativeDiscoveryRxWindowWords_" in publish
    assert '"NativeAwdlDiscoveryRxWindowEvents"' in publish
    assert '"NativeAwdlDiscoveryRxWindowPublished",' in publish
    assert "uint32_t(1), 32" in publish
    for property_name in (
        "NativeAwdlDiscoveryRxWindowLeaseQualifiedCount",
        "NativeAwdlDiscoveryRxWindowLeaseUnqualifiedCount",
        "ManagementMpdu",
        "ControlMpdu",
        "DataMpdu",
        "ExtensionMpdu",
        "UnknownTypeMpdu",
        "DiscoveryInputSameWindowCommitted",
    ):
        assert property_name in publish, property_name
    assert '"NativeAwdlDiscoveryRxWindowBridge" suffix "Before"' in publish
    assert '"NativeAwdlDiscoveryRxWindowBridge" suffix "After"' in publish

    action = function_body(probe, "static IOReturn publishDiscoveryRxWindowAction(")
    assert "owner->tahoeP2pOnMainGate()" in action
    assert "nativeP2PPublicationBusy(owner)" in action
    request = function_body(
        probe, "static void requestNativeDiscoveryRxWindowPublish("
    )
    assert "gate->attemptAction(publishDiscoveryRxWindowAction" in request
    assert "owner->tahoeDiscoveryRxWindowPublish(controller)" in request

    # The regular publisher routes through the nonblocking main-gate wrapper;
    # it never calls the scratch-using publisher directly off-gate.
    publish_state = function_body(probe, "void ItlIwx::tahoeP2pPublishProbeState()")
    assert "requestNativeDiscoveryRxWindowPublish(this, controller)" in publish_state
    assert "tahoeDiscoveryRxWindowPublish(controller)" not in publish_state

    tap = function_body(probe, "void ItlIwx::tahoeP2pTapSessionEvent(")
    assert "canonicalStart" in tap and "nativeDiscoveryRxWindow_.begin" in tap
    assert "canonicalEnd" in tap and "nativeDiscoveryRxWindow_.close" in tap
    window_boundary_start = tap.index(
        "if (canonicalStart && reducerReturnedTrue && after.startStatus == 1"
    )
    window_boundary_end = tap.index("#endif", window_boundary_start)
    window_boundary = tap[window_boundary_start:window_boundary_end]
    assert "after.configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION" in window_boundary
    assert "nativeDiscoveryRxWindowConfiguration_ = after.configuration" in window_boundary
    assert "after.configuration == nativeDiscoveryRxWindowConfiguration_" in window_boundary
    assert "IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV" not in window_boundary

    # The production PSF/TX path chooses GO_NEGOTIATION before submit, and its
    # worker dispatches to the same exercise used by the ROC event reducer.
    tx_probe = function_body(probe, "static int exerciseTxProbe(P2PProbeRun *probe)")
    assert "const uint32_t configuration =" in tx_probe
    assert "configuration =\n        IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION" in tx_probe
    assert "IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV" not in tx_probe
    exercise = function_body(probe, "int ItlIwx::tahoeP2pExerciseRoc(void *opaque)")
    assert "if (probe && probe->txProbeEnabled)" in exercise
    assert "return exerciseTxProbe(probe);" in exercise
    probe_task = function_body(probe, "void ItlIwx::tahoeP2pProbeTask(void *opaque)")
    assert "operations.exercise = tahoeP2pExerciseRoc" in probe_task
    assert "run.txProbeEnabled" in probe_task

    window_epochs = function_body(
        probe, "bool ItlIwx::tahoeDiscoveryRxWindowEpochs("
    )
    assert "nativeDiscoveryRxWindowConfiguration_ !=\n            IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION" in window_epochs
    assert "session.configuration != nativeDiscoveryRxWindowConfiguration_" in window_epochs
    assert '"NativeAwdlDiscoveryRxWindowRocConfiguration"' in publish
    assert 'set32("NativeAwdlDiscoveryRxWindowRocConfiguration",\n          nativeDiscoveryRxWindowConfiguration_);' in publish
    assert "#define IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV  2" in fw_regs
    assert "#define IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION 3" in fw_regs

    # The legacy RX149 observer remains on its own DEVICE_DISCOV profile.
    rx149 = function_body(probe, "static int exerciseRx149Observation(P2PProbeRun *probe)")
    assert "IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV" in rx149
    finish = function_body(probe, "IOReturn ItlIwx::tahoeP2pFinishAction(")
    assert "tahoeDiscoveryRxWindowInvalidate" in finish
    cleared_cancel = finish.index(
        "__atomic_store_n(&owner->nativeP2pCancelRequested_, 0u"
    )
    terminal_publish = finish.index(
        "owner->tahoeDiscoveryRxWindowPublish(owner->tahoeP2pController())"
    )
    assert terminal_publish > cleared_cancel
    terminal_gate = finish[cleared_cancel:terminal_publish]
    assert "owner->tahoeP2pOnMainGate()" in terminal_gate
    assert "nativeLifecycleTearingDown_" in terminal_gate
    assert "discoveryRxTerminalMatchesRun(owner, run)" in terminal_gate
    assert "nativeDiscoveryRxWindowTerminalReceiptDirty_ = true" in terminal_gate
    assert "run->contextGeneration == 0" not in finish  # exact guard is helper
    terminal_helper = function_body(
        probe, "static bool discoveryRxTerminalMatchesRun("
    )
    assert "run->contextGeneration == 0" in terminal_helper
    assert "run->powerGeneration == 0" in terminal_helper
    assert "run->stationGeneration == 0" in terminal_helper
    assert "run->scGeneration == 0" in terminal_helper

    receipt = function_body(
        probe, "static void publishDiscoveryRxTerminalReceipt("
    )
    assert "nativeDiscoveryRxWindowTerminalReceiptDirty_" in receipt
    assert '"NativeAwdlDiscoveryRxWindowTerminalPublished", uint32_t(1), 32' in receipt
    for terminal_field in (
        "TerminalContextGeneration",
        "TerminalPowerGeneration",
        "TerminalStationGeneration",
        "TerminalRocGeneration",
        "TerminalDriverGeneration",
        "TerminalBeginResult",
        "TerminalCloseResult",
        "TerminalObserverState",
        "TerminalPublishFirstStatus",
        "TerminalPublishStatus",
    ):
        assert terminal_field in receipt

    begin_record = tap[tap.index("if (canonicalStart && reducerReturnedTrue"):]
    assert "nativeDiscoveryRxWindowTerminalBeginResult_ = began ? 1u : 2u" in begin_record
    assert "nativeDiscoveryRxWindow_.state() !=" not in begin_record
    assert "event.leaseState" in header
    assert "event.ownerReason" not in header
    assert "constexpr uint32_t kEventWordCount = 9;" in header


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test136-rx-window-") as temp:
        binary = pathlib.Path(temp) / "rx-window-test"
        subprocess.run(
            [
                "xcrun",
                "clang++",
                "-std=c++14",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(CPP_TEST),
                "-o",
                str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    production_contract()
    print(
        "PASS: discovery RX window generations, release state, bounded wire, "
        "bridge counters and main-gate publisher contract"
    )


if __name__ == "__main__":
    main()
