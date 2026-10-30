#!/usr/bin/env python3
"""Test086 native one-shot actor for a controlled RX149 data-input run.

No-argument invocation is a plan and performs no local system reads. The
coordinator starts ``--native-worker`` only after the user-authorized run has
been prepared. This actor never starts the OpenWrt sender or UDP listener.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Optional, Tuple


ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = Path(__file__).resolve().parent
TEST086_DIR = ROOT / "developer-tools/test086"
TRACE_TOOL = TEST086_DIR / "tools/awdl_ioreg_u32.py"
IWN_ROOT = ROOT.parent / "IntelWirelessNative"
PRIVATE_ROOT = IWN_ROOT / "research/test086-controlled-preparation-private"
DEFAULT_METADATA = PRIVATE_ROOT / "native-controlled-probe-private.json"
BUILD = "25G332-Test086"
EXPECTED_UUID = "C28DBCB5-DB75-3C08-B09C-05354B5D2B57"
MINIMUM_BOOT_EPOCH_EXCLUSIVE = 1793340271
PROFILE = "native_awdl_rx149_data_input_only"
SOURCE_KIND = "controlled_probe"
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
ARM_RE = re.compile(rb"ARM ([0-9a-f]{32})\n\Z")
CONTROL_TIMEOUT_SECONDS = 15.0
POST_CAPTURE_TIMEOUT_SECONDS = 8.0
POST_STABILITY_DELAY_SECONDS = 0.03
NATIVE_OWNER_KEYS = (
    "NativeP2PRxTraceOwnerSerial",
    "NativeP2PProbeContextGeneration",
    "NativeP2PProbePowerGeneration",
    "NativeP2PProbeStationGeneration",
    "NativeP2PRocGeneration",
)
DATA_TX_COUNTER = "NativeAwdlDataTxSubmitted"
DATA_TX_PENDING = "NativeAwdlDataTxPending"


class NativeCaptureError(RuntimeError):
    """A sanitized fail-closed actor error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _json_line(event: str, fields: Dict[str, Any]) -> None:
    value = {"event": event, **fields}
    print(event + " " + json.dumps(value, sort_keys=True, separators=(",", ":")),
          flush=True)


def plan() -> Dict[str, Any]:
    """Pure plan; deliberately does not import the hardware collector."""
    return {
        "mode": "plan",
        "candidate": BUILD,
        "source_ready_kind": SOURCE_KIND,
        "requires_phone_ready": False,
        "profile": PROFILE,
        "diagnostic_duration_ms": 100,
        "native_worker_supported": True,
        "native_worker_armed": False,
        "claim_touched": False,
        "helper_invoked": False,
        "system_read": False,
        "note": "Native action requires a coordinator ARM token; no default action.",
    }


def parse_control_line(raw: bytes) -> Tuple[str, Optional[str]]:
    """Accept exactly one ABORT or one lower-case 128-bit ARM token line."""
    if raw == b"ABORT\n":
        return "abort", None
    match = ARM_RE.fullmatch(raw)
    if match is not None:
        token = match.group(1).decode("ascii")
        if TOKEN_RE.fullmatch(token):
            return "arm", token
    return "invalid", None


def wait_for_control(timeout: float = CONTROL_TIMEOUT_SECONDS) -> Tuple[str, Optional[str]]:
    readable, _, _ = select.select([sys.stdin], [], [], timeout)
    if not readable:
        return "timeout", None
    raw = os.read(sys.stdin.fileno(), 129)
    return parse_control_line(raw)


def validate_arm_token(token: str) -> bool:
    return type(token) is str and TOKEN_RE.fullmatch(token) is not None


def _load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise NativeCaptureError("NATIVE_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise NativeCaptureError("NATIVE_SOURCE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise NativeCaptureError("NATIVE_SOURCE_IMPORT_FAILED")
    return module


def _check_private_file(path: Path, account, *, required_parent: Optional[Path] = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise NativeCaptureError("PRIVATE_METADATA_UNAVAILABLE")
    info = path.lstat()
    if (info.st_uid != account.pw_uid or info.st_mode & 0o077 or
            (required_parent is not None and path.parent.resolve() != required_parent.resolve())):
        raise NativeCaptureError("PRIVATE_METADATA_UNSAFE")


def _metadata_path_allowed(metadata_path: Path) -> bool:
    """Pin all private inputs to the ignored sibling-worktree directory."""
    path = Path(metadata_path)
    return path.is_absolute() and path == DEFAULT_METADATA


def _check_private_directory_chain(account) -> None:
    for path in (IWN_ROOT, IWN_ROOT / "research", PRIVATE_ROOT):
        try:
            info = path.lstat()
        except OSError:
            raise NativeCaptureError("PRIVATE_METADATA_PARENT_UNAVAILABLE")
        if (path.is_symlink() or not path.is_dir() or
                info.st_uid != account.pw_uid or info.st_mode & 0o022):
            raise NativeCaptureError("PRIVATE_METADATA_PARENT_UNSAFE")
        if path == PRIVATE_ROOT and info.st_mode & 0o077:
            raise NativeCaptureError("PRIVATE_METADATA_PARENT_UNSAFE")


def _load_private_bundle(metadata_path: Path, account):
    metadata_path = Path(metadata_path)
    expected_parent = DEFAULT_METADATA.parent
    if (not _metadata_path_allowed(metadata_path) or
            metadata_path.name != DEFAULT_METADATA.name or
            metadata_path.parent.resolve() != expected_parent.resolve() or
            metadata_path.parent.is_symlink()):
        raise NativeCaptureError("PRIVATE_METADATA_PATH_INVALID")
    _check_private_directory_chain(account)
    parent_info = metadata_path.parent.lstat()
    if (not metadata_path.parent.is_dir() or parent_info.st_uid != account.pw_uid or
            parent_info.st_mode & 0o077):
        raise NativeCaptureError("PRIVATE_METADATA_PARENT_UNSAFE")
    _check_private_file(metadata_path, account, required_parent=metadata_path.parent)
    try:
        template = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        raise NativeCaptureError("PRIVATE_METADATA_INVALID")
    binding = template.get("source_binding") if isinstance(template, dict) else None
    if not isinstance(binding, dict):
        raise NativeCaptureError("SOURCE_BINDING_INVALID")
    build_report_path = Path(str(binding.get("build_report_path", "")))
    baseline_report_path = Path(str(binding.get("baseline_build_report_path", "")))
    for path in (build_report_path, baseline_report_path):
        _check_private_file(path, account, required_parent=metadata_path.parent)
    try:
        frozen_metadata = binding["frozen_test086_metadata"]
    except KeyError:
        raise NativeCaptureError("FROZEN_SOURCE_METADATA_MISSING")
    if not isinstance(frozen_metadata, dict):
        raise NativeCaptureError("FROZEN_SOURCE_METADATA_INVALID")
    try:
        build_receipt_raw = build_report_path.read_bytes()
        build_receipt = json.loads(build_receipt_raw)
        build_receipt_sha = hashlib.sha256(build_receipt_raw).hexdigest()
    except OSError:
        raise NativeCaptureError("BUILD_RECEIPT_UNAVAILABLE")
    except (ValueError, TypeError):
        raise NativeCaptureError("BUILD_RECEIPT_INVALID")
    if not isinstance(build_receipt, dict):
        raise NativeCaptureError("BUILD_RECEIPT_INVALID")
    expected_receipt_sha = binding.get("build_receipt_sha256")
    if expected_receipt_sha != build_receipt_sha:
        raise NativeCaptureError("BUILD_RECEIPT_HASH_MISMATCH")
    return (template, binding, frozen_metadata, build_report_path,
            baseline_report_path, build_receipt, build_receipt_raw,
            build_receipt_sha)


def _validate_source_binding(protocol, template: Dict[str, Any],
                             frozen_metadata: Dict[str, Any],
                             build_receipt: Dict[str, Any],
                             build_receipt_raw: bytes) -> None:
    if frozen_metadata.get("source_sha256") != template.get("source_sha256"):
        raise NativeCaptureError("FROZEN_SOURCE_MAP_MISMATCH")
    if protocol.validate_frozen_source_binding(
            template, build_receipt, build_receipt_raw):
        raise NativeCaptureError("FROZEN_SOURCE_BINDING_FAILED")


def _legacy_validation_copy(frozen_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Satisfy the legacy pure validator without changing the frozen manifest."""
    if frozen_metadata.get("armed") is not False:
        raise NativeCaptureError("SOURCE_MANIFEST_NOT_DISARMED")
    value = copy.deepcopy(frozen_metadata)
    value["armed"] = True
    return value


def _read_boot_epoch(capture) -> int:
    try:
        boot = capture._sysctl_boot_epoch()
    except Exception:
        raise NativeCaptureError("BOOT_EPOCH_UNAVAILABLE")
    if type(boot) is not int or boot <= MINIMUM_BOOT_EPOCH_EXCLUSIVE:
        raise NativeCaptureError("FRESH_BOOT_REQUIRED")
    return boot


def _account_for_private_files():
    try:
        return pwd.getpwuid(ROOT.stat().st_uid)
    except (OSError, KeyError):
        raise NativeCaptureError("PRIVATE_ACCOUNT_UNAVAILABLE")


def _claim_availability(capture, account, boot_epoch: int) -> Dict[str, Any]:
    home = Path(account.pw_dir)
    claim_dir = home / capture.CLAIM_RELATIVE
    current_path = home
    try:
        home_info = home.lstat()
    except OSError:
        raise NativeCaptureError("SHARED_CLAIM_PATH_UNSAFE")
    if (not home.is_dir() or home.is_symlink() or home_info.st_uid != account.pw_uid or
            home_info.st_mode & 0o022):
        raise NativeCaptureError("SHARED_CLAIM_PATH_UNSAFE")
    for component in capture.CLAIM_RELATIVE.parts:
        current_path = current_path / component
        try:
            info = current_path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise NativeCaptureError("SHARED_CLAIM_PATH_UNSAFE")
        is_final = component == capture.CLAIM_RELATIVE.parts[-1]
        if not _claim_directory_component_is_safe(
                info, workspace_uid=account.pw_uid, is_final=is_final):
            raise NativeCaptureError("SHARED_CLAIM_PATH_UNSAFE")
    current = claim_dir / ("boot-" + str(boot_epoch) + ".json")
    for candidate in capture._legacy_claims(claim_dir, boot_epoch):
        if candidate.exists() or candidate.is_symlink():
            raise NativeCaptureError("SHARED_BOOT_CLAIM_UNAVAILABLE")
    if current.exists() or current.is_symlink():
        raise NativeCaptureError("SHARED_BOOT_CLAIM_UNAVAILABLE")
    return {
        "available": True,
        "claim_scope": "shared Test065-Test086 BootGlobal one-claim-per-boot",
        "claim_filename": current.name,
        "path_logged": False,
    }


def _claim_directory_component_is_safe(info, *, workspace_uid: int,
                                        is_final: bool) -> bool:
    """Accept root/user-owned claim dirs, while keeping symlink/write gates."""
    mode = info.st_mode
    if (not stat.S_ISDIR(mode) or info.st_uid not in (0, workspace_uid) or
            mode & 0o022):
        return False
    if is_final and mode & 0o077:
        return False
    return True


def _custom_loaded_identity(capture, build_report_path: Path, expected: str) -> Dict[str, Any]:
    """Validate the frozen build archive from the new private metadata copy."""
    try:
        build = json.loads(build_report_path.read_text(encoding="utf-8"))
        if build.get("candidate") != expected:
            raise NativeCaptureError("BUILD_CANDIDATE_MISMATCH")
        archive = Path(build["archive"])
        archive_sha = build["archive_sha256"]
        binary_sha = build["binary_sha256"]
        if hashlib.sha256(archive.read_bytes()).hexdigest() != archive_sha:
            raise NativeCaptureError("BUILD_ARCHIVE_HASH_MISMATCH")
        import zipfile
        with zipfile.ZipFile(archive) as package:
            binary = package.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
        if hashlib.sha256(binary).hexdigest() != binary_sha:
            raise NativeCaptureError("BUILD_BINARY_HASH_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="iwn-t086-identity-", dir="/private/tmp") as temp:
            executable = Path(temp) / "AirportItlwm"
            executable.write_bytes(binary)
            dwarfdump = subprocess.check_output(
                ["xcrun", "dwarfdump", "--uuid", str(executable)],
                text=True, stderr=subprocess.DEVNULL)
        expected_uuids = re.findall(r"UUID: ([0-9A-F-]{36}) \(x86_64\)", dwarfdump)
        loaded = subprocess.check_output(
            ["/usr/bin/kmutil", "showloaded", "--list-only"],
            text=True, stderr=subprocess.DEVNULL)
        loaded_uuids = re.findall(
            r"org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})", loaded)
        matched = len(expected_uuids) == 1 and loaded_uuids == expected_uuids
        identity = {
            "archive_uuid": expected_uuids[0] if len(expected_uuids) == 1 else None,
            "loaded_uuid": loaded_uuids[0] if len(loaded_uuids) == 1 else None,
            "binary_identity_verified": matched,
        }
        return identity
    except NativeCaptureError:
        raise
    except Exception:
        raise NativeCaptureError("LOADED_IDENTITY_VALIDATION_FAILED")


def _validate_tx_zero(capture, initial: Dict[str, Any]) -> Dict[str, Any]:
    native = capture.tx_zero_evidence(initial, initial)
    extra = {DATA_TX_COUNTER: initial.get(DATA_TX_COUNTER),
             DATA_TX_PENDING: initial.get(DATA_TX_PENDING)}
    extra_ok = all(type(value) is int and value == 0 for value in extra.values())
    return {
        "valid": native.get("valid") is True and extra_ok,
        "native_control_counters": native,
        "data_tx_counters": extra,
        "host_management_or_data_tx_allowed": False,
    }


def _native_preflight(template: Dict[str, Any], binding: Dict[str, Any],
                      frozen_metadata: Dict[str, Any], build_report_path: Path,
                      baseline_report_path: Path, boot_epoch: int,
                      account, capture, protocol, build_receipt: Dict[str, Any],
                      build_receipt_raw: bytes) -> Dict[str, Any]:
    actual_receipt_sha = hashlib.sha256(build_report_path.read_bytes()).hexdigest()
    expected_receipt_sha = binding.get("build_receipt_sha256")
    errors = protocol.validate_private_metadata(
        template, boot_epoch=boot_epoch,
        expected_receipt_sha256=expected_receipt_sha,
        actual_receipt_sha256=actual_receipt_sha)
    if errors:
        raise NativeCaptureError("CONTROLLED_METADATA_GATE_FAILED")
    _validate_source_binding(protocol, template, frozen_metadata,
                             build_receipt, build_receipt_raw)

    if (template.get("candidate") != BUILD or
            template.get("source_ready_kind") != SOURCE_KIND or
            template.get("requires_phone_ready") is not False or
            template.get("expected_loaded_uuid") != EXPECTED_UUID):
        raise NativeCaptureError("CONTROLLED_SOURCE_IDENTITY_MISMATCH")
    if frozen_metadata.get("expected_loaded_uuid") != EXPECTED_UUID:
        raise NativeCaptureError("FROZEN_SOURCE_UUID_MISMATCH")
    if frozen_metadata.get("expected_binary_sha256") != binding.get("expected_binary_sha256") or \
            frozen_metadata.get("expected_info_plist_sha256") != binding.get("expected_info_plist_sha256"):
        raise NativeCaptureError("FROZEN_SOURCE_HASH_BINDING_MISMATCH")
    if frozen_metadata.get("build_report") != str(build_report_path):
        raise NativeCaptureError("NEW_BUILD_REPORT_PATH_MISMATCH")

    # Reuse Test086's pure frozen-artifact validator and native profile/counter
    # preflight with new private copies of the build receipts. Do not read or
    # write the old canonical metadata location. The closed source manifest
    # remains armed=false on disk. The legacy validator requires armed=true,
    # so the explicit --native-worker path gets a temporary in-memory copy;
    # this changes no private file and does not arm hardware or consume a claim.
    validation_metadata = _legacy_validation_copy(frozen_metadata)
    capture.BUILD_PATH = build_report_path
    capture.BASELINE_BUILD_PATH = baseline_report_path
    capture.loaded_identity = lambda expected: _custom_loaded_identity(
        capture, build_report_path, expected)
    try:
        identity, initial, p2p_tx_zero = capture._native_preflight(
            validation_metadata, boot_epoch)
    except NativeCaptureError:
        raise
    except Exception:
        raise NativeCaptureError("NATIVE_PREFLIGHT_FAILED")

    host_tx_zero = _validate_tx_zero(capture, initial)
    if not host_tx_zero["valid"]:
        raise NativeCaptureError("HOST_TX_NOT_ZERO")
    claim = _claim_availability(capture, account, boot_epoch)
    return {
        "identity": identity,
        "initial": initial,
        "p2p_tx_zero": p2p_tx_zero,
        "host_tx_zero": host_tx_zero,
        "claim": claim,
        "configured_armed": False,
        "legacy_validation_copy_armed": True,
    }


def _compile_helper(capture, temp_dir: Path) -> Path:
    try:
        helper = capture._compile_arm_helper(temp_dir)
    except Exception:
        raise NativeCaptureError("SWIFT_HELPER_COMPILE_FAILED")
    if helper.is_symlink() or not helper.is_file():
        raise NativeCaptureError("SWIFT_HELPER_COMPILE_FAILED")
    return helper


def _private_output(capture, path: Path, account) -> Path:
    try:
        return Path(capture._require_private_output(path, account))
    except NativeCaptureError:
        raise
    except Exception:
        raise NativeCaptureError("PRIVATE_OUTPUT_UNSAFE")


def capture_module():
    """Load the legacy Test086 module only for explicit worker execution."""
    path = TEST086_DIR / "capture_test086_receive149_once.py"
    if str(TEST086_DIR) not in sys.path:
        sys.path.insert(0, str(TEST086_DIR))
    return _load_module("test086_capture_native_controlled", path)


def _save_report(capture, path: Path, report: Dict[str, Any], account) -> None:
    try:
        capture._save_private_json(path, report, account)
    except Exception:
        raise NativeCaptureError("PRIVATE_REPORT_WRITE_FAILED")


def _read_current_owner(sample: Dict[str, Any]) -> Dict[str, Any]:
    return {key: sample.get(key) if type(sample.get(key)) is int else None
            for key in NATIVE_OWNER_KEYS}


def _session_terminal(sample: Dict[str, Any]) -> bool:
    return (sample.get("NativeP2PRx149Selected") == 1 and
            sample.get("NativeP2PProbeAttempted") == 1 and
            sample.get("NativeP2PProbeState") == 7 and
            sample.get("NativeP2PProbeResourceMayExist") == 0 and
            sample.get("NativeP2PRocEndSeen") == 1)


def _post_snapshots(capture, timeout: float = POST_CAPTURE_TIMEOUT_SECONDS):
    """Wait for RX-session terminal state, never gated by management trace."""
    latest = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        latest = capture.properties("AirportItlwm")
        if _session_terminal(latest):
            break
        time.sleep(0.05)
    if latest is None:
        latest = capture.properties("AirportItlwm")
    samples = [latest]
    time.sleep(POST_STABILITY_DELAY_SECONDS)
    samples.append(capture.properties("AirportItlwm"))
    time.sleep(POST_STABILITY_DELAY_SECONDS)
    samples.append(capture.properties("AirportItlwm"))
    return samples


def _load_trace_tool():
    return _load_module("test086_controlled_awdl_ioreg_u32", TRACE_TOOL)


def _derive_evidence(capture, trace_tool, post_samples):
    """Compute data and management-trace evidence independently."""
    data_rx = capture.awdl_data_rx_triplet_evidence(post_samples)
    receipt = capture.awdl_data_rx149_receipt_triplet_evidence(
        post_samples, post_samples[-1])
    management = None
    try:
        management = trace_tool.derive_rx_trace_guard_report(
            post_samples[0], post_samples[1], post_samples[2],
            capture.guarded_rx_trace_evidence)
    except Exception as error:
        management = {
            "combined_valid": False,
            "error_type": type(error).__name__,
            "raw_snapshots_saved": False,
            "peer_receipt_proven": False,
            "airdrop_proven": False,
        }
    # Deliberately return all three products without using management-trace
    # validity as a condition for retaining the data counters or receipt.
    return {"data_rx": data_rx, "data_receipt": receipt,
            "management_trace_u32": management}


def _guarded_ifnet_input_kpi(evidence: Dict[str, Any]) -> Optional[bool]:
    """Only surface the triplet's owner-bound aggregate result, never one read."""
    receipt = evidence.get("data_receipt")
    if not isinstance(receipt, dict) or receipt.get("valid") is not True:
        return None
    accepted = receipt.get("local_ifnet_input_kpi_accepted")
    return accepted if type(accepted) is bool else None


def _report_sample(sample, capture) -> Dict[str, Any]:
    return {
        "current_owner_and_epochs": _read_current_owner(sample),
        "rx149": capture.rx149_snapshot(sample),
        "native_awdl_data_rx": capture.awdl_data_rx_snapshot(sample),
        "native_awdl_data_rx149_receipt": capture.awdl_data_rx149_receipt_snapshot(sample),
        "host_tx_snapshot": {
            DATA_TX_COUNTER: sample.get(DATA_TX_COUNTER)
                if type(sample.get(DATA_TX_COUNTER)) is int else None,
            DATA_TX_PENDING: sample.get(DATA_TX_PENDING)
                if type(sample.get(DATA_TX_PENDING)) is int else None,
        },
    }


def _wait_for_helper_gate() -> Tuple[str, Optional[str]]:
    return wait_for_control(CONTROL_TIMEOUT_SECONDS)


def _emit_native_error(code: str, stage: str) -> None:
    _json_line("NATIVE_ERROR", {"code": code, "stage": stage,
                                "helper_invoked": False,
                                "claim_consumed": False,
                                "retry_allowed": False})


def _worker(args) -> int:
    if os.geteuid() != 0:
        _emit_native_error("ROOT_REQUIRED", "preflight")
        return 2
    try:
        account = _account_for_private_files()
        capture = capture_module()
        boot_epoch = _read_boot_epoch(capture)
        metadata_path = Path(args.metadata) if args.metadata else DEFAULT_METADATA
        (template, binding, frozen_metadata, build_path, baseline_path,
         build_receipt, build_receipt_raw, build_receipt_sha) = _load_private_bundle(
             metadata_path, account)
        protocol = _load_module("test086_controlled_protocol",
                                TOOL_DIR / "test086_controlled.py")
        preflight = _native_preflight(template, binding, frozen_metadata,
                                      build_path, baseline_path, boot_epoch,
                                      account, capture, protocol,
                                      build_receipt, build_receipt_raw)
        output = _private_output(capture, Path(args.output), account)
        report_path = output / "native-controlled-capture-private.json"
        if report_path.exists() or report_path.is_symlink():
            raise NativeCaptureError("OUTPUT_ALREADY_EXISTS")
    except NativeCaptureError as error:
        _emit_native_error(error.code, "preflight")
        return 2

    report: Dict[str, Any] = {
        "schema": "test086-controlled-native-runtime-private/v1",
        "source_ready_kind": SOURCE_KIND,
        "candidate": BUILD,
        "expected_loaded_uuid": EXPECTED_UUID,
        "boot_epoch": boot_epoch,
        "profile": PROFILE,
        "diagnostic_duration_ms": 100,
        "requires_phone_ready": False,
        "host_management_or_data_tx_allowed": False,
        "retry_allowed": False,
        "native_helper_invoked": False,
        "boot_attempt_claim_consumed": False,
        "arm_run_token": None,
        "build_receipt_sha256": build_receipt_sha,
        "identity": preflight["identity"],
        "configured_armed": preflight["configured_armed"],
        "legacy_validation_copy_armed": preflight["legacy_validation_copy_armed"],
        "claim_preflight": preflight["claim"],
        "host_tx_zero_preflight": preflight["host_tx_zero"],
        "p2p_tx_zero_preflight": preflight["p2p_tx_zero"],
        "native_awdl_data_rx_initial": capture.awdl_data_rx_snapshot(preflight["initial"]),
        "native_awdl_data_rx149_receipt_initial":
            capture.awdl_data_rx149_receipt_snapshot(preflight["initial"]),
        "rx149_initial": capture.rx149_snapshot(preflight["initial"]),
        "current_owner_and_epochs_initial": _read_current_owner(preflight["initial"]),
        "post_samples": [],
        "native_awdl_data_rx_evidence": None,
        "native_awdl_data_rx149_receipt_evidence": None,
        "management_trace_u32_evidence": None,
        "ifnet_input_kpi_accepted": None,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
        "status": "preflight_passed_waiting_for_coordinator",
        "scope": "One controlled, fixed 100 ms RX149 arm. Local ifnet_input result is KPI evidence only; the UDP listener is an independent application-layer observation.",
    }
    try:
        _save_report(capture, report_path, report, account)
    except NativeCaptureError as error:
        _emit_native_error(error.code, "preflight_report")
        return 2

    # The Swift helper is compiled before NATIVE_READY. It is not invoked here.
    with tempfile.TemporaryDirectory(prefix="intel-test086-controlled-",
                                     dir="/private/tmp") as temp_dir:
        try:
            helper = _compile_helper(capture, Path(temp_dir))
        except NativeCaptureError as error:
            report["status"] = "helper_compile_failed_no_claim"
            report["helper_compile_error"] = error.code
            _save_report(capture, report_path, report, account)
            _emit_native_error(error.code, "helper_compile")
            return 2

        _json_line("NATIVE_READY", {
            "candidate": BUILD,
            "source_ready_kind": SOURCE_KIND,
            "expected_loaded_uuid": EXPECTED_UUID,
            "boot_epoch": boot_epoch,
            "profile": PROFILE,
            "diagnostic_duration_ms": 100,
            "requires_phone_ready": False,
            "native_preflight_ready": True,
            "helper_compiled": True,
            "claim_available": True,
            "host_tx_zero": True,
            "host_management_or_data_tx_allowed": False,
            "run_token_required": True,
            "one_arm_maximum": True,
            "retry_allowed": False,
        })

        decision, run_token = _wait_for_helper_gate()
        if decision == "abort":
            report["status"] = "coordinator_aborted_before_claim"
            _save_report(capture, report_path, report, account)
            _json_line("NATIVE_ABORTED", {
                "helper_invoked": False, "claim_consumed": False,
                "retry_allowed": False,
            })
            return 0
        if decision != "arm" or not validate_arm_token(run_token or ""):
            report["status"] = "invalid_or_missing_arm_gate_no_claim"
            _save_report(capture, report_path, report, account)
            _json_line("NATIVE_REJECTED", {
                "code": "ARM_GATE_INVALID_OR_TIMEOUT",
                "helper_invoked": False, "claim_consumed": False,
                "retry_allowed": False,
            })
            return 2

        report["arm_run_token"] = run_token
        report["status"] = "claim_consumption_pending"
        try:
            claim_path = capture.consume_boot_claim(
                capture._claim_directory(account), boot_epoch, run_token)
        except Exception as error:
            report["status"] = "claim_outcome_unknown_no_retry"
            report["claim_error_type"] = type(error).__name__
            consumed = bool(
                (Path(account.pw_dir) / capture.CLAIM_RELATIVE /
                 ("boot-" + str(boot_epoch) + ".json")).exists())
            report["boot_attempt_claim_consumed"] = consumed
            try:
                _save_report(capture, report_path, report, account)
            except NativeCaptureError as save_error:
                report["claim_report_write_error"] = save_error.code
            _json_line("NATIVE_REJECTED", {
                "code": "SHARED_BOOT_CLAIM_FAILED",
                "run_token": run_token,
                "helper_invoked": False,
                "claim_consumed": consumed,
                "retry_allowed": False,
            })
            return 2
        report["boot_attempt_claim_consumed"] = True
        report["boot_attempt_claim_filename"] = claim_path.name
        report["status"] = "claim_consumed_helper_pending"
        report["native_helper_invocation_pending"] = True
        # This ACK is flushed after the one-boot claim exists and before the
        # Swift helper starts. Do not make the one-time ACK depend on a second
        # disk write: the atomic shared claim file is the durable claim record.
        # The coordinator should immediately send GO with this same token;
        # this message does not assert IORegistry arm success.
        _json_line("NATIVE_ARMED", {
            "run_token": run_token,
            "claim_consumed": True,
            "retry_allowed": False,
            "helper_invocation_pending": True,
            "arm_property_accepted": None,
            "roc_start_observed": False,
        })

        report["native_helper_invoked"] = True
        report["native_helper_invocation_pending"] = False
        report["status"] = "swift_helper_running_no_retry"
        helper_result: Dict[str, Any]
        try:
            result = subprocess.run(
                [str(helper), "--expect-build", BUILD,
                 "--expect-uuid", EXPECTED_UUID],
                capture_output=True, text=True, timeout=5)
            try:
                helper_summary = json.loads(result.stdout.strip())
            except (ValueError, TypeError):
                helper_summary = None
            helper_result = {
                "exit_code": result.returncode,
                "arm_property_accepted": (
                    helper_summary.get("arm_property_accepted")
                    if isinstance(helper_summary, dict) and
                    type(helper_summary.get("arm_property_accepted")) is bool
                    else None),
                "helper_summary": helper_summary,
                "stderr_present": bool(result.stderr),
                "helper_error_type": None,
            }
        except (OSError, subprocess.SubprocessError) as error:
            helper_result = {
                "exit_code": None,
                "arm_property_accepted": None,
                "helper_summary": None,
                "stderr_present": False,
                "helper_error_type": type(error).__name__,
            }
        report["swift_helper_result"] = helper_result
        report["status"] = "helper_returned_sampling_post_state_no_retry"
        try:
            _save_report(capture, report_path, report, account)
        except NativeCaptureError as error:
            report["helper_report_write_error"] = error.code
        _json_line("NATIVE_ARM_RESULT", {
            "run_token": run_token,
            **helper_result,
            "arm_property_acceptance_is_not_roc_start": True,
            "retry_allowed": False,
        })

        try:
            post_samples = _post_snapshots(capture)
            evidence = _derive_evidence(capture, _load_trace_tool(), post_samples)
            report["post_samples"] = [_report_sample(sample, capture)
                                      for sample in post_samples]
            report["native_awdl_data_rx_evidence"] = evidence["data_rx"]
            report["native_awdl_data_rx149_receipt_evidence"] = evidence["data_receipt"]
            report["management_trace_u32_evidence"] = evidence["management_trace_u32"]
            report["ifnet_input_kpi_accepted"] = _guarded_ifnet_input_kpi(evidence)
            report["current_owner_and_epochs_after"] = _read_current_owner(post_samples[-1])
            report["session_terminal_observed"] = _session_terminal(post_samples[-1])
            report["status"] = (
                "captured_no_retry" if report["session_terminal_observed"]
                else "session_terminal_unknown_no_retry")
        except Exception as error:
            report["post_capture_error_type"] = type(error).__name__
            report["status"] = "post_capture_unknown_no_retry"
        report["peer_receipt_proven"] = False
        report["native_awdl_reply_proven"] = False
        report["airdrop_proven"] = False
        try:
            _save_report(capture, report_path, report, account)
        except NativeCaptureError:
            # The claim is already spent. Do not invoke the helper or retry.
            _json_line("NATIVE_RESULT", {
                "run_token": run_token,
                "status": "native_report_write_failed_no_retry",
                "report_saved": False,
                "claim_consumed": True,
                "native_helper_invoked": True,
                "ifnet_input_kpi_accepted": report.get("ifnet_input_kpi_accepted"),
                "management_trace_valid": (
                    report.get("management_trace_u32_evidence", {}).get("combined_valid")
                    if isinstance(report.get("management_trace_u32_evidence"), dict) else None),
                "retry_allowed": False,
                "peer_receipt_proven": False,
                "native_awdl_reply_proven": False,
                "airdrop_proven": False,
            })
            return 2
        _json_line("NATIVE_RESULT", {
            "run_token": run_token,
            "status": report["status"],
            "report_saved": True,
            "claim_consumed": True,
            "native_helper_invoked": True,
            "ifnet_input_kpi_accepted": report["ifnet_input_kpi_accepted"],
            "management_trace_valid": (
                report.get("management_trace_u32_evidence", {}).get("combined_valid")
                if isinstance(report.get("management_trace_u32_evidence"), dict) else None),
            "peer_receipt_proven": False,
            "native_awdl_reply_proven": False,
            "airdrop_proven": False,
            "retry_allowed": False,
        })
        return 0 if report["status"] == "captured_no_retry" else 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true",
                        help="Print a non-invasive plan (the default).")
    parser.add_argument("--native-worker", action="store_true",
                        help="Join a controlled coordinator; never use standalone.")
    parser.add_argument("--metadata", type=Path,
                        help="Private Test086-derived bundle; defaults to the new private path.")
    parser.add_argument("--output", type=Path,
                        help="New private directory for this run's local report.")
    args = parser.parse_args(argv)
    if not args.native_worker:
        print(json.dumps(plan(), sort_keys=True))
        return 0
    if not args.output:
        _emit_native_error("PRIVATE_OUTPUT_REQUIRED", "arguments")
        return 2
    return _worker(args)


if __name__ == "__main__":
    raise SystemExit(main())
