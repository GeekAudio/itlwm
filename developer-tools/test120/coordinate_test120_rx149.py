#!/usr/bin/env python3
"""Candidate-bound Test120 coordinator using the reviewed Test119/Test104 path.

Default invocation is an inert plan. The explicit ``--run`` path reuses the
bounded Test119 dual-socket sender and Test104 one-use RX149 coordinator, while
all build, source-freeze, deployment, runtime, and target checks bind to Test120.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST119_DIR = REPO_ROOT / "developer-tools/test119"
TEST119_COORDINATOR = TEST119_DIR / "coordinate_test119_rx149.py"


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST120_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST120_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BINDING = _load("test120_rx149_binding", TOOL_DIR / "rx149_binding_test120.py")
REUSED_COORDINATOR = _load(
    "test120_reused_test119_coordinator", TEST119_COORDINATOR)
RUNNER = REUSED_COORDINATOR.RUNNER
DUAL_PROTOCOL = REUSED_COORDINATOR.DUAL_PROTOCOL
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test120.py"

# Replace candidate-facing paths and properties before any explicit operation.
REUSED_COORDINATOR.BINDING = BINDING
REUSED_COORDINATOR.NATIVE_WORKER = NATIVE_WORKER
REUSED_COORDINATOR.TOOL_DIR = TEST119_DIR  # the sender/protocol artifacts are reused
REUSED_COORDINATOR.EARLY_OBSERVER = TEST119_DIR / "early_rx_stage_test119.py"
RUNNER.CANDIDATE = BINDING.CANDIDATE
RUNNER.PROFILE = BINDING.PROFILE
RUNNER.NATIVE_WORKER = NATIVE_WORKER
RUNNER.RESULT_NAME = "test120-tools-private.json"
RUNNER.CAPTURE_NAME = "native-controlled-capture-private.json"
RUNNER.DEFAULT_AP = "wlan7"
RUNNER.IWN_ROOT = BINDING.IWN_ROOT
RUNNER.DEFAULT_METADATA = BINDING.METADATA
RUNNER.BUILD_RECEIPT = BINDING.BUILD_RECEIPT
RUNNER.DEPLOYMENT_RECEIPT = BINDING.DEPLOYMENT_RECEIPT
RUNNER.SENDER_BUILD_RECEIPT = BINDING.SENDER_RECEIPT
RUNNER.ROUTER_SOURCE_RECEIPT = BINDING.ROUTER_RECEIPT
RUNNER.TARGET_IDENTITY_RECEIPT = BINDING.TARGET_RECEIPT
RUNNER.SENDER_SOURCE = REPO_ROOT / "developer-tools/test119/awdl_unicast_sender_test119.c"
RUNNER.RUNTIME_BINDING.CANDIDATE = BINDING.CANDIDATE
RUNNER.RUNTIME_BINDING.SENDER_CONTRACT = dict(BINDING.SENDER_CONTRACT)
RUNNER.RUNTIME_BINDING.METADATA_SCHEMA = (
    "test120-native-awdl-rx149-controlled-probe-private/v1")
RUNNER.PROTOCOL.candidate_binding.METADATA_SCHEMA = (
    "test120-native-awdl-rx149-controlled-probe-private/v1")


def _configure_test120_run() -> None:
    """Install Test120 receipt paths and extend the actual run hash manifest."""
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
    RUNNER.RESULT_NAME = "test120-tools-private.json"
    RUNNER.CAPTURE_NAME = "native-controlled-capture-private.json"
    RUNNER.PROFILE = BINDING.PROFILE
    RUNNER.test104_run_dir = lambda boot_epoch, _candidate: (
        BINDING.METADATA.parent / ("test120-tools-boot" + str(boot_epoch)))

    old_hashes = RUNNER.runtime_tool_hashes

    def test120_runtime_tool_hashes() -> dict[str, str]:
        values = old_hashes()
        anchor = RUNNER.REPO.resolve(strict=True)
        extra = (
            Path(__file__).resolve(),
            TOOL_DIR / "rx149_binding_test120.py",
            TOOL_DIR / "test120_capture_contract.py",
            TOOL_DIR / "native_controlled_capture_test120.py",
            TOOL_DIR / "sender-reuse-receipt-test120.json",
        )
        for path in extra:
            if path.is_symlink() or not path.is_file():
                raise RUNNER.ControlledRunError(
                    "TEST120_RUNTIME_TOOL_UNAVAILABLE:" + path.name)
            resolved = path.resolve(strict=True)
            try:
                name = resolved.relative_to(anchor).as_posix()
            except ValueError:
                name = "external:" + str(resolved)
            values[name] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        return values

    RUNNER.runtime_tool_hashes = test120_runtime_tool_hashes


def plan() -> dict[str, Any]:
    return {
        "candidate": BINDING.CANDIDATE,
        "profile": BINDING.PROFILE,
        "receiver_channel": 149,
        "driver_lease_ms": 100,
        "sender_reused_from": "25G332-Test119",
        "sender_rebuilt_for_test120": False,
        "sender_protocol": "test119-dual-socket-sender/v1",
        "sample_report_fields": list(
            __import__("test120_capture_contract").FINAL_SAMPLE_PROPERTIES),
        "allowed_runtime_terminal_mappings": [
            "probe_completed_and_released",
            "exercise_failed_but_safely_cleaned",
            "quarantined_resource_may_exist",
            "unknown_incomplete_sample",
        ],
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


def validate_metadata_path(path: Path) -> Path:
    """Reject non-Test120 metadata before configuring any live runner state."""
    normalized = Path(path).expanduser()
    if normalized != BINDING.METADATA:
        raise BINDING.BindingError("test120_metadata_path_mismatch")
    return normalized


def _load_current_identity() -> tuple[int, str]:
    boot_text = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "kern.boottime"], check=True,
        capture_output=True, text=True, timeout=5).stdout
    import re
    match = re.search(r"\bsec\s*=\s*(\d+)", boot_text)
    if not match:
        raise BINDING.BindingError("test120_boot_epoch_unavailable")
    boot_epoch = int(match.group(1))
    loaded = subprocess.run(
        ["/usr/bin/kmutil", "showloaded", "--list-only"], check=True,
        capture_output=True, text=True, timeout=10).stdout
    uuids = re.findall(
        r"org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})", loaded)
    if len(uuids) != 1:
        raise BINDING.BindingError("test120_loaded_uuid_ambiguous")
    return boot_epoch, uuids[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--prepare", action="store_true",
                      help="Write a new owner-only disarmed metadata bundle from Test120 receipts")
    mode.add_argument("--capture-target", action="store_true",
                      help="Read live awdl0 identity and bind it to Test120 receipts")
    mode.add_argument("--capture-router", action="store_true",
                      help="Read only the existing OpenWrt wlan7 identity")
    mode.add_argument("--run", action="store_true",
                      help="Run one Test120-bound, single-use RX149 observation")
    parser.add_argument("--minimum-boot-epoch-exclusive", type=int)
    parser.add_argument("--iwn-root", type=Path, default=BINDING.IWN_ROOT)
    parser.add_argument("--metadata", type=Path, default=BINDING.METADATA)
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--ap", default="wlan7")
    args = parser.parse_args(argv)
    try:
        selected = any((args.plan, args.prepare, args.capture_target,
                        args.capture_router, args.run))
        if not selected:
            print(json.dumps(plan(), sort_keys=True))
            return 0
        if args.plan:
            print(json.dumps(plan(), sort_keys=True))
            return 0
        if (args.iwn_root.expanduser().resolve(strict=True) !=
                BINDING.IWN_ROOT.resolve(strict=True)):
            raise BINDING.BindingError("test120_iwn_root_mismatch")
        validate_metadata_path(args.metadata)

        if args.prepare:
            if args.minimum_boot_epoch_exclusive is None:
                raise BINDING.BindingError("minimum_boot_epoch_required")
            path = BINDING.write_disarmed_metadata(
                minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive)
            print(json.dumps({
                "candidate": BINDING.CANDIDATE,
                "status": "prepared_disarmed",
                "metadata": str(path),
                "metadata_sha256": BINDING.sha256(path.read_bytes()),
                "armed": False,
                "retry_allowed": False,
                "rf_triggered": False,
                "efi_modified": False,
            }, sort_keys=True))
            return 0

        if args.capture_target:
            if args.minimum_boot_epoch_exclusive is None:
                raise BINDING.BindingError("minimum_boot_epoch_required")
            _configure_test120_run()
            path = REUSED_COORDINATOR.capture_target_identity(
                args.minimum_boot_epoch_exclusive)
            record, raw = BINDING.read_private(path)
            print(json.dumps({
                "status": "readback_verified", "candidate": BINDING.CANDIDATE,
                "boot_epoch": record["boot_epoch"], "interface": "awdl0",
                "ifindex_positive": record["ifindex"] > 0,
                "receipt_sha256": BINDING.sha256(raw),
                "router_modified": False, "rf_triggered": False,
            }, sort_keys=True))
            return 0

        if args.capture_router:
            if not args.host or not args.control_path:
                raise BINDING.BindingError("router_transport_required")
            _configure_test120_run()
            path = REUSED_COORDINATOR.capture_router_identity(
                args.host, args.control_path)
            record, raw = BINDING.read_private(path)
            parsed = RUNNER.PACKETSET.parse_router_identity_receipt(
                record, BINDING.sha256(raw))
            if parsed.get("interface") != "wlan7" or parsed.get("channel") != 149:
                raise BINDING.BindingError("router_identity_readback_rejected")
            print(json.dumps({
                "status": "readback_verified", "interface": "wlan7",
                "channel": 149, "receipt_sha256": BINDING.sha256(raw),
                "read_only": True, "router_modified": False,
                "wan_lan_modified": False, "rf_triggered": False,
            }, sort_keys=True))
            return 0

        if not args.host or not args.control_path:
            raise BINDING.BindingError("router_transport_required")
        _configure_test120_run()
        # The existing coordinator validates the exact Test120 receipts,
        # disarmed handoff, loaded UUID, new boot, target/router identities,
        # one-use claim, START/GO deadline, and single-use terminal before RF.
        boot_epoch, loaded_uuid = _load_current_identity()
        metadata, build, _raw, _path = BINDING.validate_bundle(args.metadata)
        if (loaded_uuid != build.get("mach_o_uuid") or
                boot_epoch <= metadata.get("minimum_boot_epoch_exclusive", boot_epoch)):
            raise BINDING.BindingError("test120_current_runtime_identity_mismatch")
        os.environ["INTEL_WIRELESS_NATIVE_ROOT"] = str(BINDING.IWN_ROOT)
        report, output_dir, _prearm = RUNNER.run_once(
            host=args.host, control_path=args.control_path,
            metadata_path=args.metadata, ap=args.ap)
        print(json.dumps({
            "candidate": BINDING.CANDIDATE,
            "status": report.get("status"),
            "complete": report.get("complete") is True,
            "output_directory": str(output_dir),
            "retry_allowed": False,
            "peer_receipt_proven": report.get("peer_receipt_proven") is True,
            "native_awdl_reply_proven": report.get("native_awdl_reply_proven") is True,
            "airdrop_proven": report.get("airdrop_proven") is True,
        }, sort_keys=True))
        return 0 if report.get("complete") is True else 2
    except Exception as error:
        code = getattr(error, "code", None) or str(error)[:120] or type(error).__name__
        print("ERROR: " + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
