#!/usr/bin/env python3
"""Test122 coordinator: T122 receipt binding over the bounded T120 RX path.

The default command is an inert plan. Explicit prepare/capture/run modes use
the existing one-use gate, 100 ms receive lease, bounded sender, and cleanup
path; no mode changes the station network or router configuration.
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
TEST121_DIR = REPO_ROOT / "developer-tools/test121"
T121_COORDINATOR_PATH = TEST121_DIR / "coordinate_test121_rx149.py"
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test122.py"
SENDER_SOURCE = TEST121_DIR / "awdl_unicast_sender_test121.c"


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST122_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST122_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BINDING = _load("test122_rx149_binding", TOOL_DIR / "rx149_binding_test122.py")
T121 = _load("test122_frozen_test121_coordinator", T121_COORDINATOR_PATH)
T120 = T121.T120
RUNNER = T121.RUNNER

# Rebind every candidate-facing component before any explicit runner mode.
BINDING.bind_template_paths()
T121.BINDING = BINDING
T120.BINDING = BINDING
T121.REUSED_COORDINATOR.BINDING = BINDING
T121.NATIVE_WORKER = NATIVE_WORKER
T121.REUSED_COORDINATOR.NATIVE_WORKER = NATIVE_WORKER
T121.REUSED_COORDINATOR.EARLY_OBSERVER = (
    REPO_ROOT / "developer-tools/test119/early_rx_stage_test119.py")
T121.REUSED_COORDINATOR.DUAL_PROTOCOL = T121.DUAL_PROTOCOL
T121.REUSED_COORDINATOR.RUNNER.CANDIDATE = BINDING.CANDIDATE


def plan() -> dict[str, Any]:
    return {
        "candidate": BINDING.CANDIDATE,
        "expected_uuid": None,
        "expected_uuid_source": "private Test122 build receipt",
        "profile": BINDING.PROFILE,
        "sender_reused_from": "25G332-Test121",
        "sender_rebuilt_for_test122": False,
        "sender_protocol": "test121-dual-socket-sender/v1",
        "receiver_channel": 149,
        "station_channel": "measure_actual_channel_at_run",
        "station_channel_changes_allowed": False,
        "channel_attribution": "only_if_actual_station_and_receiver_channels_are_recorded",
        "if_station_channel_unknown": "no_channel_attribution",
        "driver_lease_ms": 100,
        "openwrt_frames": 4,
        "openwrt_interval_ms": 10,
        "openwrt_send_budget_ms": 40,
        "raw_monitor_sample_limit": 64,
        "raw_monitor_sample_bytes": 512,
        "raw_monitor_overflow": "fail_closed",
        "monitor_line_limit_bytes": T121.DUAL_PROTOCOL.MAX_LINE_BYTES,
        "early_rx_counters_same_ioreg_read": True,
        "firmware_atomic_snapshot_proven": False,
        "outgoing_packet_tap_proves_rf": False,
        "raw_txs_and_mac_ack": "unknown_without_independent_per_frame_evidence",
        "rf_ack_peer_proven": False,
        "sleep_test_allowed": False,
        "default_action": "plan_only",
        "armed": False,
        "router_contacted": False,
        "scan_triggered": False,
        "rf_triggered": False,
        "efi_modified": False,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def _configure_test122_run() -> None:
    """Reuse the frozen T121 setup, then bind every result path to Test122."""
    T121._configure_test121_run()
    RUNNER.IWN_ROOT = BINDING.IWN_ROOT.resolve(strict=True)
    RUNNER.DEFAULT_METADATA = BINDING.METADATA
    RUNNER.BUILD_RECEIPT = BINDING.BUILD_RECEIPT
    RUNNER.DEPLOYMENT_RECEIPT = BINDING.DEPLOYMENT_RECEIPT
    RUNNER.ROUTER_SOURCE_RECEIPT = BINDING.ROUTER_RECEIPT
    RUNNER.TARGET_IDENTITY_RECEIPT = BINDING.TARGET_RECEIPT
    RUNNER.SENDER_BUILD_RECEIPT = BINDING.SENDER_RECEIPT
    RUNNER.CANDIDATE = BINDING.CANDIDATE
    RUNNER.NATIVE_WORKER = NATIVE_WORKER
    RUNNER.RESULT_NAME = "test122-tools-private.json"
    RUNNER.CAPTURE_NAME = "native-controlled-capture-private.json"
    RUNNER.DEFAULT_AP = "wlan7"
    RUNNER.PROFILE = BINDING.PROFILE
    RUNNER.test104_run_dir = lambda boot_epoch, _candidate: (
        BINDING.METADATA.parent / ("test122-tools-boot" + str(boot_epoch)))
    RUNNER.RUNTIME_BINDING.CANDIDATE = BINDING.CANDIDATE
    RUNNER.RUNTIME_BINDING.SENDER_CONTRACT = dict(BINDING.T121.SENDER_CONTRACT)
    RUNNER.RUNTIME_BINDING.METADATA_SCHEMA = BINDING.METADATA_SCHEMA
    RUNNER.PROTOCOL.candidate_binding.METADATA_SCHEMA = BINDING.METADATA_SCHEMA
    T121.REUSED_COORDINATOR.RUNNER.CANDIDATE = BINDING.CANDIDATE
    T121.REUSED_COORDINATOR.RUNNER.SENDER_SOURCE = SENDER_SOURCE

    previous_hashes = RUNNER.runtime_tool_hashes

    def test122_runtime_tool_hashes() -> dict[str, str]:
        values = previous_hashes()
        anchor = RUNNER.REPO.resolve(strict=True)
        for path in (Path(__file__).resolve(),
                     TOOL_DIR / "rx149_binding_test122.py",
                     NATIVE_WORKER):
            if path.is_symlink() or not path.is_file():
                raise RUNNER.ControlledRunError(
                    "TEST122_RUNTIME_TOOL_UNAVAILABLE:" + path.name)
            resolved = path.resolve(strict=True)
            try:
                name = resolved.relative_to(anchor).as_posix()
            except ValueError:
                name = "external:" + str(resolved)
            values[name] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        return values

    RUNNER.runtime_tool_hashes = test122_runtime_tool_hashes


def main(argv: list[str] | None = None) -> int:
    """Use T120's reviewed CLI; its default path remains side-effect free."""
    T120.plan = plan
    T120._configure_test120_run = _configure_test122_run
    return T120.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
