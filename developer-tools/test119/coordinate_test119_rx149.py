#!/usr/bin/env python3
"""Candidate-bound Test119 channel-149 RX run using frozen Test104 transport.

The candidate receipt and deployment receipt remain in their real Test119
schema. The Test104 coordinator supplies only the one-use START/GO, 4-frame
40 ms sender, listener, and cleanup protocol; this adapter independently binds
the actual Test119 artifacts and adds same-cut early-RX stage counters.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import datetime as dt
import tempfile


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST104_DIR = REPO_ROOT / "developer-tools/test104"
TEST104_COORDINATOR = TEST104_DIR / "controlled_run_test104.py"
if str(TEST104_DIR) not in sys.path:
    sys.path.insert(0, str(TEST104_DIR))


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST119_TOOL_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST119_TOOL_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BINDING = _load("test119_rx149_binding", TOOL_DIR / "rx149_binding_test119.py")
RUNNER = _load("test119_test104_runner", TEST104_COORDINATOR)
DUAL_PROTOCOL = _load("test119_dual_sender_protocol",
                      TOOL_DIR / "dual_sender_protocol_test119.py")
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test119.py"
EARLY_OBSERVER = TOOL_DIR / "early_rx_stage_test119.py"
RUNNER.CANDIDATE = BINDING.CANDIDATE

_ORIGINAL_PROFILE_CONFIGURATOR = RUNNER.configure_test104_profile
_ORIGINAL_SENDER_PROTOCOL = RUNNER.SENDER_PROTOCOL
_ORIGINAL_PROVENANCE = RUNNER.PROVENANCE


def _configure_test119_profile():
    """Route frozen START/GO orchestration through Test119's raw parser."""
    RUNNER.SENDER_PROTOCOL = DUAL_PROTOCOL
    RUNNER.PROVENANCE = DUAL_PROTOCOL
    try:
        restore_frozen_profile = _ORIGINAL_PROFILE_CONFIGURATOR()
    except Exception:
        RUNNER.SENDER_PROTOCOL = _ORIGINAL_SENDER_PROTOCOL
        RUNNER.PROVENANCE = _ORIGINAL_PROVENANCE
        raise
    frozen_timing_parser = RUNNER.TEST088.TIMING.parse_sender_timing

    def parse_test119_timing(sender_result):
        if isinstance(sender_result, dict) and sender_result.get("schema") == DUAL_PROTOCOL.SCHEMA:
            reason = sender_result.get("stop_reason")
            if reason in {"go_to_start_budget_expired", "observer_drain_incomplete",
                          "send_spacing_violation"}:
                sender_result = dict(sender_result)
                sender_result["stop_reason"] = "send_errno"
        return frozen_timing_parser(sender_result)

    RUNNER.TEST088.TIMING.parse_sender_timing = parse_test119_timing
    frozen_legacy_result_parser = RUNNER.PROTOCOL.parse_sender_result

    def parse_test119_legacy_result(line):
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            return frozen_legacy_result_parser(line)
        if (isinstance(value, dict) and value.get("event") == "SENDER_RESULT" and
                value.get("schema") is None and value.get("stop_reason") in {
                    "go_to_start_budget_expired", "observer_drain_incomplete",
                    "send_spacing_violation"}):
            value = dict(value)
            value["stop_reason"] = "send_errno"
            line = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return frozen_legacy_result_parser(line)

    RUNNER.PROTOCOL.parse_sender_result = parse_test119_legacy_result

    def restore_test119_profile():
        try:
            restore_frozen_profile()
        finally:
            RUNNER.SENDER_PROTOCOL = _ORIGINAL_SENDER_PROTOCOL
            RUNNER.PROVENANCE = _ORIGINAL_PROVENANCE

    return restore_test119_profile


RUNNER.configure_test104_profile = _configure_test119_profile
RUNNER.PROFILE = BINDING.PROFILE
RUNNER.NATIVE_WORKER = NATIVE_WORKER
RUNNER.RESULT_NAME = "test119-tools-private.json"
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
RUNNER.SENDER_BINARY = None
RUNNER.SENDER_SHA256 = None
RUNNER.EXPECTED_SENDER_SOURCE_SHA256 = None
RUNNER.EXPECTED_SENDER_BINARY_SHA256 = None
RUNNER.RUNTIME_BINDING.CANDIDATE = BINDING.CANDIDATE
RUNNER.RUNTIME_BINDING.SENDER_CONTRACT = dict(BINDING.SENDER_CONTRACT)
RUNNER.RUNTIME_BINDING.METADATA_SCHEMA = (
    "test119-native-awdl-rx149-controlled-probe-private/v1")
RUNNER.PROTOCOL.candidate_binding.METADATA_SCHEMA = (
    "test119-native-awdl-rx149-controlled-probe-private/v1")

_PACKETSET = RUNNER.RUNTIME_BINDING.packetset
_ORIGINAL_TARGET_VALIDATOR = _PACKETSET.validate_target_identity


def _target_identity_for_test119(record, expected_boot_epoch=None,
                                 expected_uuid=None, *, expected_candidate=None,
                                 expected_binary_sha256=None,
                                 expected_build_receipt_sha256=None,
                                 expected_deployment_receipt_sha256=None):
    return _ORIGINAL_TARGET_VALIDATOR(
        record, expected_boot_epoch, expected_uuid,
        expected_candidate=BINDING.CANDIDATE,
        expected_binary_sha256=expected_binary_sha256,
        expected_build_receipt_sha256=expected_build_receipt_sha256,
        expected_deployment_receipt_sha256=expected_deployment_receipt_sha256)


_PACKETSET.validate_target_identity = _target_identity_for_test119


def _configure() -> None:
    sender, _raw, _binding = BINDING._sender_binding()
    RUNNER.SENDER_BINARY = Path(sender["binary_path"]).resolve(strict=True)
    RUNNER.SENDER_SHA256 = sender["binary_sha256"]
    RUNNER.EXPECTED_SENDER_SOURCE_SHA256 = sender["source_sha256"]
    RUNNER.EXPECTED_SENDER_BINARY_SHA256 = sender["binary_sha256"]

    # Test104 calls Path.relative_to(REPO) for the sender receipt/hash key.
    # Test119's sender is deliberately stored under the private RuntimeTest119
    # tree, outside the git checkout. Use their real common filesystem anchor;
    # do not copy, symlink, or claim the binary lives inside the repository.
    common_anchor = Path(os.path.commonpath((
        str(REPO_ROOT.resolve(strict=True)),
        str(BINDING.IWN_ROOT.resolve(strict=True)))))
    if (REPO_ROOT.resolve(strict=True).is_relative_to(common_anchor) is False or
            BINDING.IWN_ROOT.resolve(strict=True).is_relative_to(common_anchor) is False):
        raise RUNNER.ControlledRunError("TEST119_ARTIFACT_ANCHOR_INVALID")
    RUNNER.REPO = common_anchor

    def validate_deployment(owner_uid: int):
        build, build_raw = BINDING.read_private(BINDING.BUILD_RECEIPT)
        deployment, deployment_raw = BINDING._verify_deployment(build)
        if build.get("candidate") != BINDING.CANDIDATE:
            raise RUNNER.ControlledRunError("TEST119_BUILD_CANDIDATE_MISMATCH")
        BINDING._verify_archive(build)
        return build, deployment, build_raw, deployment_raw

    def sender_receipt(owner_uid: int) -> dict:
        sender, _raw, binding = BINDING._sender_binding()
        if (Path(sender["binary_path"]).resolve(strict=True) != RUNNER.SENDER_BINARY or
                binding.get("binary_sha256") != RUNNER.SENDER_SHA256):
            raise RUNNER.ControlledRunError("TEST119_SENDER_BINARY_BINDING_INVALID")
        return sender

    def validate_runtime_metadata(metadata_path: Path, build: dict,
                                  deployment: dict, boot_epoch: int,
                                  owner_uid: int):
        try:
            metadata, validated_build, build_raw, _path = BINDING.validate_bundle(metadata_path)
        except Exception as error:
            raise RUNNER.ControlledRunError(
                "TEST119_DISARMED_BUNDLE_REJECTED:" + str(error)[:80]) from error
        if (validated_build.get("mach_o_uuid") != build.get("mach_o_uuid") or
                boot_epoch <= metadata.get("minimum_boot_epoch_exclusive", boot_epoch)):
            raise RUNNER.ControlledRunError("TEST119_RUNTIME_BOOT_OR_BUILD_MISMATCH")
        loaded = RUNNER.RUNTIME_BINDING._run_text([
            "/usr/bin/kmutil", "showloaded", "--list-only",
            "--bundle-identifier", "org.geekaudio.AirportItlwm"])
        loaded_uuid = RUNNER.RUNTIME_BINDING._extract_loaded_uuid(loaded)
        if loaded_uuid != build.get("mach_o_uuid"):
            raise RUNNER.ControlledRunError("TEST119_LOADED_UUID_MISMATCH")
        try:
            handoff, _ = BINDING.read_private(BINDING.RUNTIME_HANDOFF)
        except Exception as error:
            raise RUNNER.ControlledRunError("TEST119_RF_HANDOFF_UNAVAILABLE") from error
        if (handoff.get("candidate") != BINDING.CANDIDATE or
                handoff.get("active_awdl_rf_allowed") is not True or
                handoff.get("sleep_test_allowed") is not False):
            raise RUNNER.ControlledRunError("TEST119_RF_SCOPE_NOT_AUTHORIZED")
        return metadata, {
            "candidate": BINDING.CANDIDATE,
            "expected_loaded_uuid": build["mach_o_uuid"],
            "actual_build_receipt_sha256": hashlib.sha256(build_raw).hexdigest(),
            "active_awdl_rf_allowed": True,
            "sleep_test_allowed": False,
        }, {"metadata_sha256": BINDING.sha256(metadata_path.read_bytes())}

    def validate_bundle_for_coordinator(metadata_path, owner_uid, protocol):
        try:
            metadata, build, build_raw, build_path = BINDING.validate_bundle(
                Path(metadata_path))
            return metadata, build, BINDING.sha256(build_raw), build_path
        except Exception as error:
            raise RUNNER.BASE.CoordinatorError(
                "TEST119_CANDIDATE_BINDING_REJECTED",
                {"reason": str(error)[:120]}) from error

    RUNNER.validate_deployment = validate_deployment
    RUNNER.sender_receipt = sender_receipt
    RUNNER.validate_runtime_metadata = validate_runtime_metadata
    RUNNER.BASE._validate_bundle = validate_bundle_for_coordinator
    RUNNER.test104_run_dir = lambda boot_epoch, candidate: (
        BINDING.METADATA.parent / ("test119-tools-boot" + str(boot_epoch)))
    def runtime_hashes():
        # Reproduce the frozen Test104 runtime dependency list, then append the
        # Test119 adapters. Hash every file at its real path. Test119 sender is
        # keyed relative to the common anchor so the unchanged pre-run gate can
        # compare its real SHA256 without relocating it into the checkout.
        paths = [
            Path(RUNNER.__file__).resolve(), RUNNER.NATIVE_WORKER,
            RUNNER.ARM_HELPER, RUNNER.START_READER_SOURCE,
            RUNNER.START_BARRIER_SOURCE, RUNNER.RUNTIME_BINDING_SOURCE,
            RUNNER.PROVENANCE_SOURCE,
            RUNNER.TOOL_DIR / "sender_protocol_test104.py",
            RUNNER.TOOL_DIR / "remote_sender_test104.py",
            RUNNER.TOOL_DIR / "packetset_test104.py", RUNNER.LISTENER_SOURCE,
            RUNNER.LISTENER_PROTOCOL_SOURCE,
            RUNNER.TOOL_DIR / "hcmd_rx_trace_test104.py",
            RUNNER.TOOL_DIR / "rx149_capture_attempts_test104.py",
            RUNNER.TOOL_DIR / "tx_rsp_retry_observation_test104.py",
            RUNNER.SENDER_SOURCE, RUNNER.SENDER_BINARY,
            REPO_ROOT / "developer-tools/test087/controlled_run_coordinator.py",
            REPO_ROOT / "developer-tools/test087/run_controlled_probe_once.py",
            REPO_ROOT / "developer-tools/test087/test087_controlled.py",
            REPO_ROOT / "developer-tools/test087/native_controlled_capture.py",
            REPO_ROOT / "developer-tools/test088/controlled_run_test088.py",
            RUNNER.TOOL_DIR / "frozen-template-test104.json",
            Path(__file__).resolve(), NATIVE_WORKER, EARLY_OBSERVER,
            TOOL_DIR / "rx149_binding_test119.py",
            TOOL_DIR / "dual_sender_protocol_test119.py",
        ]
        values = {}
        anchor = RUNNER.REPO.resolve(strict=True)
        for path in paths:
            if path.is_symlink() or not path.is_file():
                raise RUNNER.ControlledRunError("TEST119_RUNTIME_TOOL_UNAVAILABLE")
            resolved = path.resolve(strict=True)
            try:
                name = resolved.relative_to(anchor).as_posix()
            except ValueError:
                name = "external:" + str(resolved)
            values[name] = BINDING.sha256(resolved.read_bytes())
        return values

    RUNNER.runtime_tool_hashes = runtime_hashes


def capture_target_identity(minimum_boot_epoch_exclusive: int) -> Path:
    """Capture only local awdl0 identity, bound to the actual Test119 receipts."""
    metadata, build, build_raw, _path = BINDING.validate_bundle(BINDING.METADATA)
    deployment, deployment_raw = BINDING._verify_deployment(build)
    boot_text = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "kern.boottime"], check=True,
        capture_output=True, text=True, timeout=5).stdout
    match = __import__("re").search(r"\bsec\s*=\s*(\d+)", boot_text)
    if not match:
        raise BINDING.BindingError("target_boot_epoch_unavailable")
    boot_epoch = int(match.group(1))
    if (type(minimum_boot_epoch_exclusive) is not int or
            boot_epoch <= minimum_boot_epoch_exclusive or
            minimum_boot_epoch_exclusive != metadata.get("minimum_boot_epoch_exclusive")):
        raise BINDING.BindingError("target_boot_epoch_not_newer_than_deployment")
    loaded = subprocess.run(
        ["/usr/bin/kmutil", "showloaded", "--list-only"], check=True,
        capture_output=True, text=True, timeout=10).stdout
    loaded_uuids = __import__("re").findall(
        r"org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})", loaded)
    if loaded_uuids != [build.get("mach_o_uuid")]:
        raise BINDING.BindingError("target_loaded_uuid_mismatch")
    ifconfig = subprocess.run(
        ["/sbin/ifconfig", "awdl0"], check=True,
        capture_output=True, text=True, timeout=5).stdout
    mac, ipv6ll, is_up = RUNNER.RUNTIME_BINDING._parse_awdl0_ifconfig(ifconfig)
    ifindex = socket.if_nametoindex("awdl0")
    if ifindex <= 0:
        raise BINDING.BindingError("target_awdl0_ifindex_invalid")
    now = dt.datetime.now().astimezone().isoformat()
    evidence = {"ifconfig": ifconfig, "kmutil": loaded,
                "boot_epoch": boot_epoch, "ifindex": ifindex}
    record = {
        "schema": "test104-target-identity/v1",
        "status": "readback_verified", "captured_at": now,
        "boot_epoch": boot_epoch,
        "minimum_boot_epoch_exclusive": minimum_boot_epoch_exclusive,
        "interface": "awdl0", "ifindex": ifindex, "mac": mac,
        "ipv6_link_local": ipv6ll, "interface_up": is_up,
        "candidate": BINDING.CANDIDATE,
        "candidate_uuid": build["mach_o_uuid"],
        "candidate_binary_sha256": build["binary_sha256"],
        "build_receipt_sha256": BINDING.sha256(build_raw),
        "deployment_receipt_sha256": BINDING.sha256(deployment_raw),
        "source": "live_ifconfig_ifindex_kmutil",
        "evidence_sha256": BINDING.sha256(json.dumps(
            evidence, sort_keys=True, separators=(",", ":")).encode()),
    }
    canonical = json.dumps(record, sort_keys=True,
                           separators=(",", ":")).encode()
    record["identity_receipt_sha256"] = BINDING.sha256(canonical)
    _PACKETSET.validate_target_identity(
        record, boot_epoch, build["mach_o_uuid"],
        expected_candidate=BINDING.CANDIDATE,
        expected_binary_sha256=build["binary_sha256"],
        expected_build_receipt_sha256=BINDING.sha256(build_raw),
        expected_deployment_receipt_sha256=BINDING.sha256(deployment_raw))
    destination = BINDING.TARGET_RECEIPT
    if destination.exists() or destination.is_symlink():
        raise BINDING.BindingError("target_receipt_already_exists_no_overwrite")
    if destination.parent.is_symlink() or stat.S_IMODE(destination.parent.stat().st_mode) != 0o700:
        raise BINDING.BindingError("target_receipt_parent_unsafe")
    payload = json.dumps(record, ensure_ascii=False, indent=2,
                         sort_keys=True).encode() + b"\n"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return destination


def capture_router_identity(host: str, control_path: str) -> Path:
    """Read only the existing OpenWrt wlan7 identity; never changes UCI/radio."""
    if (not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}", host or "") or
            host.startswith("-") or "\n" in host):
        raise BINDING.BindingError("router_host_invalid")
    control = Path(control_path)
    if (not control.is_absolute() or "\n" in control_path or
            not control.exists() or not stat.S_ISSOCK(control.stat().st_mode)):
        raise BINDING.BindingError("router_control_socket_invalid")
    destination = BINDING.ROUTER_RECEIPT
    if destination.exists() or destination.is_symlink():
        raise BINDING.BindingError("router_receipt_already_exists_no_overwrite")
    remote_read_only = (
        "uname -r && iw dev && ip link show dev wlan7 && "
        "ip -6 addr show dev wlan7 && printf 'IFACE=wlan7\\n' && "
        "cat /sys/class/net/wlan7/address"
    )
    completed = subprocess.run(
        ["/usr/bin/ssh", "-S", str(control), "-o", "ControlMaster=no",
         "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host,
         remote_read_only],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, check=False, timeout=15)
    record = {
        "schema": "test119-router-identity-readonly/v1",
        "rc": completed.returncode,
        "scope": "read only uname -r, iw dev, ip link show dev wlan7, ip -6 addr show dev wlan7, sysfs wlan7 address",
        "at": dt.datetime.now().astimezone().isoformat(),
        "stdout": completed.stdout,
    }
    try:
        _PACKETSET.parse_router_identity_receipt(record)
    except Exception as error:
        raise BINDING.BindingError("router_identity_readback_rejected") from error
    if destination.parent.is_symlink() or stat.S_IMODE(destination.parent.stat().st_mode) != 0o700:
        raise BINDING.BindingError("router_receipt_parent_unsafe")
    payload = json.dumps(record, ensure_ascii=False, indent=2,
                         sort_keys=True).encode() + b"\n"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)
    raw = destination.read_bytes()
    receipt = json.loads(raw)
    parsed = _PACKETSET.parse_router_identity_receipt(
        receipt, BINDING.sha256(raw))
    if parsed.get("interface") != "wlan7" or parsed.get("channel") != 149:
        raise BINDING.BindingError("router_identity_readback_mismatch")
    return destination


def dry_prearm_check(*, metadata_path: Path, ap: str) -> dict:
    """Traverse run_once's real pre-ARM gates, then stop before Test088/network.

    The Test088 entry point is replaced only for this process with a sentinel
    that proves the coordinator reached the post-prearm boundary. It cannot
    consume a driver claim, contact OpenWrt, send frames, or arm RX.
    """
    _configure()
    reached_boundary = {"value": False}
    original_run = RUNNER.TEST088.run_test088_once
    original_run_dir = RUNNER.test104_run_dir

    def stop_before_test088(**_kwargs):
        reached_boundary["value"] = True
        raise RUNNER.TEST088.AdapterError("TEST119_DRY_PREARM_STOP")

    try:
        with tempfile.TemporaryDirectory(
                prefix="test119-dry-prearm-", dir=str(BINDING.ACTIVE_PRIVATE_ROOT)) as temp:
            RUNNER.TEST088.run_test088_once = stop_before_test088
            RUNNER.test104_run_dir = lambda boot_epoch, candidate: (
                Path(temp) / ("boot" + str(boot_epoch) + "-" + candidate))
            report, output_dir, _prearm = RUNNER.run_once(
                host="dry-prearm.invalid",
                control_path="/private/tmp/test119-dry-prearm-no-connection.sock",
                metadata_path=metadata_path, ap=ap)
            if not reached_boundary["value"]:
                raise BINDING.BindingError("dry_prearm_boundary_not_reached")
            if report.get("status") != "TEST119_DRY_PREARM_STOP":
                raise BINDING.BindingError("dry_prearm_did_not_stop_before_test088")
            return {
                "status": "dry_prearm_passed",
                "candidate": BINDING.CANDIDATE,
                "expected_uuid": report.get("expected_loaded_uuid"),
                "boot_epoch": report.get("boot_epoch"),
                "metadata_sha256": report.get("runtime_metadata_sha256"),
                "runtime_tool_hashes": report.get("runtime_tool_sha256"),
                "output_directory_created": bool(output_dir and output_dir.exists()),
                "post_prearm_boundary_reached": True,
                "test088_real_entrypoint_called": False,
                "test088_sentinel_boundary_triggered": True,
                "claim_consumed": False,
                "driver_arm_requested": False,
                "router_contacted": False,
                "sender_go_written": False,
                "rf_triggered": False,
                "efi_modified": False,
                "peer_receipt_proven": False,
                "native_awdl_reply_proven": False,
                "airdrop_proven": False,
            }
    finally:
        RUNNER.TEST088.run_test088_once = original_run
        RUNNER.test104_run_dir = original_run_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true",
                      help="Create a disarmed Test119 metadata file from real receipts")
    mode.add_argument("--capture-target", action="store_true",
                      help="Read current awdl0 identity and bind it to Test119 receipts")
    mode.add_argument("--capture-router", action="store_true",
                      help="Read only OpenWrt wlan7 identity; no router or RF settings change")
    mode.add_argument("--run", action="store_true",
                      help="Run one candidate-bound RX149 observation")
    mode.add_argument("--dry-prearm", action="store_true",
                      help="Traverse all pre-ARM gates, stopping before router/RF/claim")
    mode.add_argument("--plan", action="store_true",
                      help="Print the offline Test119 RX149 plan")
    parser.add_argument("--minimum-boot-epoch-exclusive", type=int)
    parser.add_argument("--iwn-root", type=Path, default=BINDING.IWN_ROOT)
    parser.add_argument("--metadata", type=Path, default=BINDING.METADATA)
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--ap", default="wlan7")
    args = parser.parse_args(argv)
    try:
        if args.iwn_root.resolve(strict=True) != BINDING.IWN_ROOT.resolve(strict=True):
            raise BINDING.BindingError("unexpected_iwn_root")
        if args.prepare:
            if args.minimum_boot_epoch_exclusive is None:
                raise BINDING.BindingError("minimum_boot_epoch_required")
            path = BINDING.write_disarmed_metadata(
                minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive)
            print(json.dumps({"status": "prepared_disarmed",
                              "candidate": BINDING.CANDIDATE,
                              "metadata": str(path),
                              "metadata_sha256": BINDING.sha256(path.read_bytes()),
                              "armed": False, "rf_triggered": False,
                              "efi_modified": False}, sort_keys=True))
            return 0
        if args.capture_target:
            if args.minimum_boot_epoch_exclusive is None:
                raise BINDING.BindingError("minimum_boot_epoch_required")
            path = capture_target_identity(args.minimum_boot_epoch_exclusive)
            record, raw = BINDING.read_private(path)
            print(json.dumps({"status": "readback_verified",
                              "candidate": record["candidate"],
                              "boot_epoch": record["boot_epoch"],
                              "interface": "awdl0",
                              "ifindex_positive": record["ifindex"] > 0,
                              "receipt": str(path),
                              "receipt_sha256": BINDING.sha256(raw)}, sort_keys=True))
            return 0
        if args.capture_router:
            if not args.host or not args.control_path:
                raise BINDING.BindingError("router_transport_required")
            path = capture_router_identity(args.host, args.control_path)
            record, raw = BINDING.read_private(path)
            parsed = _PACKETSET.parse_router_identity_receipt(
                record, BINDING.sha256(raw))
            print(json.dumps({"status": "readback_verified",
                              "interface": parsed["interface"],
                              "channel": parsed["channel"],
                              "ifindex_positive": parsed["ifindex"] > 0,
                              "kernel_release": record["stdout"].splitlines()[0],
                              "receipt": str(path),
                              "receipt_sha256": BINDING.sha256(raw),
                              "read_only": True, "router_modified": False,
                              "wan_lan_modified": False}, sort_keys=True))
            return 0
        if args.plan:
            print(json.dumps({"candidate": BINDING.CANDIDATE,
                              "expected_uuid": "A96FFB08-9AA7-3A5C-A20A-17E650A6D658",
                              "profile": BINDING.PROFILE,
                              "receiver_channel": 149,
                              "driver_lease_ms": 100,
                              "openwrt_frames": 4,
                              "openwrt_interval_ms": 10,
                              "openwrt_send_budget_ms": 40,
                              "early_rx_counters_same_ioreg_read": True,
                              "firmware_atomic_snapshot_proven": False,
                              "default_action": "none",
                              "efi_modified": False,
                              "rf_triggered": False,
                              "peer_receipt_proven": False,
                              "airdrop_proven": False}, sort_keys=True))
            return 0
        if args.dry_prearm:
            result = dry_prearm_check(metadata_path=args.metadata, ap=args.ap)
            print(json.dumps(result, sort_keys=True))
            return 0
        _configure()
        if not args.host or not args.control_path:
            raise BINDING.BindingError("router_transport_required")
        # Bind the frozen Test104 protocol modules to the Test119 private
        # receipts without running Test104's candidate/status receipt validator.
        RUNNER.IWN_ROOT = args.iwn_root.resolve(strict=True)
        RUNNER.TEST088.IWN_ROOT = RUNNER.IWN_ROOT
        RUNNER.BASE.IWN_ROOT = RUNNER.IWN_ROOT
        RUNNER.BASE.DEFAULT_METADATA = args.metadata
        RUNNER.TEST088.BASE.DEFAULT_METADATA = args.metadata
        os.environ["INTEL_WIRELESS_NATIVE_ROOT"] = str(RUNNER.IWN_ROOT)
        RUNNER.CANDIDATE = BINDING.CANDIDATE
        RUNNER.NATIVE_WORKER = NATIVE_WORKER
        RUNNER.DEFAULT_METADATA = args.metadata
        RUNNER.BUILD_RECEIPT = BINDING.BUILD_RECEIPT
        RUNNER.DEPLOYMENT_RECEIPT = BINDING.DEPLOYMENT_RECEIPT
        RUNNER.ROUTER_SOURCE_RECEIPT = BINDING.ROUTER_RECEIPT
        RUNNER.TARGET_IDENTITY_RECEIPT = BINDING.TARGET_RECEIPT
        RUNNER.SENDER_BUILD_RECEIPT = BINDING.SENDER_RECEIPT
        RUNNER.SENDER_BINARY = Path(BINDING._sender_binding()[0]["binary_path"]).resolve(strict=True)
        RUNNER.SENDER_SHA256 = BINDING._sender_binding()[0]["binary_sha256"]
        report, output_dir, _ = RUNNER.run_once(
            host=args.host, control_path=args.control_path,
            metadata_path=args.metadata, ap=args.ap)
        print(json.dumps({"candidate": BINDING.CANDIDATE,
                          "status": report.get("status"),
                          "complete": report.get("complete") is True,
                          "output_directory": str(output_dir),
                          "retry_allowed": False,
                          "peer_receipt_proven": report.get("peer_receipt_proven") is True,
                          "native_awdl_reply_proven": report.get("native_awdl_reply_proven") is True,
                          "airdrop_proven": report.get("airdrop_proven") is True}, sort_keys=True))
        return 0 if report.get("complete") is True else 2
    except Exception as error:
        code = getattr(error, "code", None) or str(error)[:120] or type(error).__name__
        print("ERROR: " + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
