#!/usr/bin/env python3
"""Test121 thin receipt binding over the existing Test120 coordinator.

The shared Test120/Test119/Test104 runner retains its one-use claim, channel
lease, START/GO, bounded sender, and cleanup behavior. This entry point binds
the Test121 receipts, sender, parser, early-RX observer, and private runtime
paths without copying the older orchestration tree.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST120_PATH = REPO_ROOT / "developer-tools/test120/coordinate_test120_rx149.py"
TEST119_DIR = REPO_ROOT / "developer-tools/test119"
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test121.py"
EARLY_OBSERVER = TEST119_DIR / "early_rx_stage_test119.py"
SENDER_SOURCE = TOOL_DIR / "awdl_unicast_sender_test121.c"


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST121_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST121_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BINDING = _load("test121_rx149_binding", TOOL_DIR / "rx149_binding_test121.py")
T120 = _load("test121_reused_test120_coordinator", TEST120_PATH)
DUAL_PROTOCOL = _load("test121_dual_sender_protocol",
                      TOOL_DIR / "dual_sender_protocol_test121.py")
RUNNER = T120.RUNNER
REUSED_COORDINATOR = T120.REUSED_COORDINATOR

# Rebind the existing coordinator before any explicit prepare/capture/run mode.
T120.BINDING = BINDING
T120.NATIVE_WORKER = NATIVE_WORKER
REUSED_COORDINATOR.BINDING = BINDING
REUSED_COORDINATOR.NATIVE_WORKER = NATIVE_WORKER
REUSED_COORDINATOR.EARLY_OBSERVER = EARLY_OBSERVER
REUSED_COORDINATOR.DUAL_PROTOCOL = DUAL_PROTOCOL
RUNNER.CANDIDATE = BINDING.CANDIDATE
RUNNER.PROFILE = BINDING.PROFILE
RUNNER.NATIVE_WORKER = NATIVE_WORKER
RUNNER.RESULT_NAME = "test121-tools-private.json"
RUNNER.CAPTURE_NAME = "native-controlled-capture-private.json"
RUNNER.DEFAULT_AP = "wlan7"
RUNNER.IWN_ROOT = BINDING.IWN_ROOT
RUNNER.DEFAULT_METADATA = BINDING.METADATA
RUNNER.BUILD_RECEIPT = BINDING.BUILD_RECEIPT
RUNNER.DEPLOYMENT_RECEIPT = BINDING.DEPLOYMENT_RECEIPT
RUNNER.SENDER_BUILD_RECEIPT = BINDING.SENDER_RECEIPT
RUNNER.ROUTER_SOURCE_RECEIPT = BINDING.ROUTER_RECEIPT
RUNNER.TARGET_IDENTITY_RECEIPT = BINDING.TARGET_RECEIPT
RUNNER.SENDER_SOURCE = SENDER_SOURCE
RUNNER.SENDER_BINARY = None
RUNNER.SENDER_SHA256 = None
RUNNER.EXPECTED_SENDER_SOURCE_SHA256 = None
RUNNER.EXPECTED_SENDER_BINARY_SHA256 = None
RUNNER.RUNTIME_BINDING.CANDIDATE = BINDING.CANDIDATE
RUNNER.RUNTIME_BINDING.SENDER_CONTRACT = dict(BINDING.SENDER_CONTRACT)
RUNNER.RUNTIME_BINDING.METADATA_SCHEMA = (
    "test121-native-awdl-rx149-controlled-probe-private/v1")
RUNNER.PROTOCOL.candidate_binding.METADATA_SCHEMA = (
    "test121-native-awdl-rx149-controlled-probe-private/v1")
REUSED_COORDINATOR.RUNNER.CANDIDATE = BINDING.CANDIDATE
REUSED_COORDINATOR.RUNNER.SENDER_SOURCE = SENDER_SOURCE

_ORIGINAL_PROFILE_CONFIGURATOR = RUNNER.configure_test104_profile


def _configure_test121_profile():
    """Apply the Test121 wire adapter and consistently raise bounded line caps."""
    old_line_limits = (
        RUNNER.BASE.MAX_LINE_BYTES,
        RUNNER.ROUTER.MAX_LINE_BYTES,
        RUNNER.TEST088.MAX_LINE_BYTES,
    )
    RUNNER.BASE.MAX_LINE_BYTES = DUAL_PROTOCOL.MAX_LINE_BYTES
    RUNNER.ROUTER.MAX_LINE_BYTES = DUAL_PROTOCOL.MAX_LINE_BYTES
    RUNNER.TEST088.MAX_LINE_BYTES = DUAL_PROTOCOL.MAX_LINE_BYTES
    try:
        restore_profile = _ORIGINAL_PROFILE_CONFIGURATOR()
    except Exception:
        (RUNNER.BASE.MAX_LINE_BYTES, RUNNER.ROUTER.MAX_LINE_BYTES,
         RUNNER.TEST088.MAX_LINE_BYTES) = old_line_limits
        raise

    def restore_test121_profile():
        try:
            restore_profile()
        finally:
            (RUNNER.BASE.MAX_LINE_BYTES, RUNNER.ROUTER.MAX_LINE_BYTES,
             RUNNER.TEST088.MAX_LINE_BYTES) = old_line_limits

    return restore_test121_profile


RUNNER.configure_test104_profile = _configure_test121_profile


def plan() -> dict[str, Any]:
    return {
        "candidate": BINDING.CANDIDATE,
        "expected_uuid": None,
        "expected_uuid_source": "private Test121 build receipt",
        "profile": BINDING.PROFILE,
        "receiver_channel": 149,
        "channel_contrast": {
            "primary": {"station_channel": 36, "roc_channel": 149},
            "reference": {"station_channel": 149, "roc_channel": 149,
                          "source": "Test120 observation"},
            "first_run": "primary",
            "if_measured_conditions_do_not_match":
                "condition_mismatch_no_channel_attribution",
            "same_boot_second_window":
                "not_enabled_by_this_tool; preserve kernel claim behavior",
        },
        "driver_lease_ms": 100,
        "openwrt_frames": 4,
        "openwrt_interval_ms": 10,
        "openwrt_send_budget_ms": 40,
        "raw_monitor_sample_limit": 64,
        "raw_monitor_sample_bytes": 512,
        "raw_monitor_overflow": "fail_closed",
        "monitor_line_limit_bytes": DUAL_PROTOCOL.MAX_LINE_BYTES,
        "early_rx_counters_same_ioreg_read": True,
        "firmware_atomic_snapshot_proven": False,
        "outgoing_packet_tap_proves_rf": False,
        "raw_txs_and_mac_ack": "unknown_without_independent_per-frame_evidence",
        "default_action": "none",
        "router_contacted": False,
        "rf_triggered": False,
        "efi_modified": False,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def _configure_test121_run() -> None:
    """Install Test121 receipts and hash the exact shared and adapter inputs."""
    REUSED_COORDINATOR._configure()
    RUNNER.IWN_ROOT = BINDING.IWN_ROOT.resolve(strict=True)
    RUNNER.DEFAULT_METADATA = BINDING.METADATA
    RUNNER.BUILD_RECEIPT = BINDING.BUILD_RECEIPT
    RUNNER.DEPLOYMENT_RECEIPT = BINDING.DEPLOYMENT_RECEIPT
    RUNNER.ROUTER_SOURCE_RECEIPT = BINDING.ROUTER_RECEIPT
    RUNNER.TARGET_IDENTITY_RECEIPT = BINDING.TARGET_RECEIPT
    RUNNER.SENDER_BUILD_RECEIPT = BINDING.SENDER_RECEIPT
    RUNNER.CANDIDATE = BINDING.CANDIDATE
    RUNNER.NATIVE_WORKER = NATIVE_WORKER
    RUNNER.RESULT_NAME = "test121-tools-private.json"
    RUNNER.CAPTURE_NAME = "native-controlled-capture-private.json"
    RUNNER.PROFILE = BINDING.PROFILE
    RUNNER.test104_run_dir = lambda boot_epoch, _candidate: (
        BINDING.METADATA.parent / ("test121-tools-boot" + str(boot_epoch)))
    RUNNER.RUNTIME_BINDING.CANDIDATE = BINDING.CANDIDATE
    RUNNER.RUNTIME_BINDING.SENDER_CONTRACT = dict(BINDING.SENDER_CONTRACT)
    RUNNER.RUNTIME_BINDING.METADATA_SCHEMA = (
        "test121-native-awdl-rx149-controlled-probe-private/v1")
    RUNNER.PROTOCOL.candidate_binding.METADATA_SCHEMA = (
        "test121-native-awdl-rx149-controlled-probe-private/v1")

    old_hashes = RUNNER.runtime_tool_hashes

    def test121_runtime_tool_hashes() -> dict[str, str]:
        values = old_hashes()
        anchor = RUNNER.REPO.resolve(strict=True)
        paths = (
            TEST120_PATH,
            Path(__file__).resolve(),
            TOOL_DIR / "rx149_binding_test121.py",
            TOOL_DIR / "dual_sender_protocol_test121.py",
            TOOL_DIR / "test121_capture_contract.py",
            NATIVE_WORKER,
            SENDER_SOURCE,
            RUNNER.SENDER_BINARY,
        )
        for path in paths:
            if path.is_symlink() or not path.is_file():
                raise RUNNER.ControlledRunError(
                    "TEST121_RUNTIME_TOOL_UNAVAILABLE:" + path.name)
            resolved = path.resolve(strict=True)
            try:
                name = resolved.relative_to(anchor).as_posix()
            except ValueError:
                name = "external:" + str(resolved)
            values[name] = BINDING.sha256(resolved.read_bytes())
        return values

    RUNNER.runtime_tool_hashes = test121_runtime_tool_hashes


def main(argv: list[str] | None = None) -> int:
    """Use Test120's mature CLI after replacing its candidate-facing hooks."""
    T120.plan = plan
    T120._configure_test120_run = _configure_test121_run
    return T120.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
