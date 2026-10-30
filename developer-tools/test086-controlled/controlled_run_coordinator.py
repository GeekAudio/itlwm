#!/usr/bin/env python3
"""Single-use Test086 controlled coordinator for a future boot.

Default invocation is a static plan. ``--run`` is deliberately explicit and
requires the private Test086 bundle plus an existing authenticated OpenWrt
ControlMaster. The coordinator waits for native, router-sender, and awdl0
listener readiness before the one shared boot claim is consumed. After the
native actor confirms the claim, it sends the matching sender GO immediately.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


TOOL_DIR = Path(__file__).resolve().parent
ROOT = TOOL_DIR.parents[1]
PRIVATE_ROOT = ROOT.parent / "IntelWirelessNative/research/test086-controlled-preparation-private"
DEFAULT_METADATA = PRIVATE_ROOT / "native-controlled-probe-private.json"
DEFAULT_SENDER_BINARY = PRIVATE_ROOT / "afpacket-sender/build/awdl_probe_sender-aarch64-linux-musl"
DEFAULT_SENDER_SHA256 = "1864e8ada5857a86254d3bd2dfef1933568118828f91c950ded117e72b882aba"
DEFAULT_BUILD_RECEIPT = PRIVATE_ROOT / "native-build-report-private.json"
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture.py"
LISTENER_SOURCE = TOOL_DIR / "awdl0_udp_probe_listener.c"
BUILD = "25G332-Test086"
UUID = "C28DBCB5-DB75-3C08-B09C-05354B5D2B57"
PROFILE = "native_awdl_rx149_data_input_only"
SOURCE_KIND = "controlled_probe"
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_LINE_BYTES = 16384
NATIVE_READY_TIMEOUT = 75.0
NATIVE_ARM_TIMEOUT = 5.0
NATIVE_RESULT_TIMEOUT = 15.0
LISTENER_READY_TIMEOUT = 5.0
RUN_TOTAL_TIMEOUT = 50.0
LISTENER_RESULT_TIMEOUT = 15.5


class CoordinatorError(RuntimeError):
    def __init__(self, code: str, evidence: Optional[Dict[str, Any]] = None,
                 partial_report: Optional[Dict[str, Any]] = None):
        super().__init__(code)
        self.code = code
        self.evidence = evidence or {}
        self.partial_report = partial_report


def _load_module(module_name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise CoordinatorError("COORDINATOR_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise CoordinatorError("COORDINATOR_SOURCE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        raise CoordinatorError("COORDINATOR_SOURCE_IMPORT_FAILED")
    return module


def _modules():
    sys.path.insert(0, str(TOOL_DIR))
    import test086_controlled as protocol
    import run_controlled_probe_once as router
    return protocol, router


def _workspace_account():
    try:
        return pwd.getpwuid(ROOT.stat().st_uid)
    except (OSError, KeyError):
        raise CoordinatorError("PRIVATE_ACCOUNT_UNAVAILABLE")


def _read_private_json(path: Path, owner_uid: int, *, parent_must_be_private: bool) -> Tuple[Dict[str, Any], bytes]:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise CoordinatorError("PRIVATE_JSON_PATH_INVALID")
    try:
        info = path.lstat()
        parent = path.parent.lstat()
    except OSError:
        raise CoordinatorError("PRIVATE_JSON_UNAVAILABLE")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
            stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISDIR(parent.st_mode) or
            parent.st_uid != owner_uid or parent.st_mode & 0o022):
        raise CoordinatorError("PRIVATE_JSON_MODE_OR_OWNER_INVALID")
    if parent_must_be_private and stat.S_IMODE(parent.st_mode) != 0o700:
        raise CoordinatorError("PRIVATE_JSON_PARENT_NOT_PRIVATE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(raw) > 16 * 1024 * 1024:
        raise CoordinatorError("PRIVATE_JSON_OVERSIZE")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise CoordinatorError("PRIVATE_JSON_MALFORMED")
    if not isinstance(value, dict):
        raise CoordinatorError("PRIVATE_JSON_NOT_OBJECT")
    return value, raw


def _validate_bundle(metadata_path: Path, owner_uid: int,
                     protocol) -> Tuple[Dict[str, Any], Dict[str, Any], str, Path]:
    metadata, _ = _read_private_json(metadata_path, owner_uid, parent_must_be_private=True)
    if metadata_path.name != DEFAULT_METADATA.name or metadata_path.parent.resolve() != PRIVATE_ROOT.resolve():
        raise CoordinatorError("CONTROLLED_METADATA_PATH_INVALID")
    binding = metadata.get("source_binding")
    if not isinstance(binding, dict):
        raise CoordinatorError("SOURCE_BINDING_INVALID")
    build_path_value = binding.get("build_report_path")
    if not isinstance(build_path_value, str) or not Path(build_path_value).is_absolute():
        raise CoordinatorError("BUILD_RECEIPT_PATH_INVALID")
    build_path = Path(build_path_value)
    receipt, receipt_raw = _read_private_json(
        build_path, owner_uid, parent_must_be_private=False)
    baseline_path_value = binding.get("baseline_build_report_path")
    if not isinstance(baseline_path_value, str) or not Path(baseline_path_value).is_absolute():
        raise CoordinatorError("BASELINE_RECEIPT_PATH_INVALID")
    baseline_path = Path(baseline_path_value)
    _read_private_json(baseline_path, owner_uid, parent_must_be_private=False)
    static_expected = {
        "schema": "test086-controlled-probe-private/v1",
        "candidate": BUILD,
        "source_ready_kind": SOURCE_KIND,
        "requires_phone_ready": False,
        "armed": False,
        "status": "prepared_disarmed",
        "retry_allowed": False,
        "expected_loaded_uuid": UUID,
        "profile": PROFILE,
        "diagnostic_duration_ms": 100,
        "receiver_gated": True,
        "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
    }
    mismatches = [key for key, value in static_expected.items()
                  if metadata.get(key) != value]
    if mismatches:
        raise CoordinatorError("CONTROLLED_METADATA_GATE_FAILED", {"fields": mismatches})
    binding_errors = protocol.validate_frozen_source_binding(metadata, receipt, receipt_raw)
    if binding_errors:
        raise CoordinatorError("FROZEN_SOURCE_BINDING_FAILED", {"fields": binding_errors})
    if metadata.get("source_sha256") != receipt.get("source_sha256"):
        raise CoordinatorError("FROZEN_SOURCE_MAP_MISMATCH")
    frozen = binding.get("frozen_test086_metadata")
    if not isinstance(frozen, dict) or frozen.get("build_report") != str(build_path):
        raise CoordinatorError("FROZEN_MANIFEST_PATH_MISMATCH")
    if frozen.get("source_sha256") != receipt.get("source_sha256"):
        raise CoordinatorError("FROZEN_MANIFEST_SOURCE_MAP_MISMATCH")
    baseline_sha = binding.get("baseline_build_report_sha256")
    if baseline_sha != hashlib.sha256(baseline_path.read_bytes()).hexdigest():
        raise CoordinatorError("BASELINE_RECEIPT_HASH_MISMATCH")
    return metadata, receipt, hashlib.sha256(receipt_raw).hexdigest(), build_path


def _event_json(line: str, prefix: str, expected_keys: set[str]) -> Dict[str, Any]:
    if not line.startswith(prefix + " ") or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise CoordinatorError(prefix + "_PROTOCOL_INVALID")
    try:
        value = json.loads(line[len(prefix) + 1:])
    except (ValueError, TypeError):
        raise CoordinatorError(prefix + "_JSON_INVALID")
    if (not isinstance(value, dict) or value.get("event") != prefix or
            set(value) != expected_keys):
        raise CoordinatorError(prefix + "_FIELD_SET_MISMATCH")
    return value


NATIVE_READY_KEYS = {
    "event", "candidate", "source_ready_kind", "expected_loaded_uuid", "boot_epoch",
    "profile", "diagnostic_duration_ms", "requires_phone_ready", "native_preflight_ready",
    "helper_compiled", "claim_available", "host_tx_zero",
    "host_management_or_data_tx_allowed", "run_token_required", "one_arm_maximum",
    "retry_allowed",
}
NATIVE_ARMED_KEYS = {
    "event", "run_token", "claim_consumed", "retry_allowed",
    "helper_invocation_pending", "arm_property_accepted", "roc_start_observed",
}
NATIVE_ARM_RESULT_KEYS = {
    "event", "run_token", "exit_code", "arm_property_accepted", "helper_summary",
    "stderr_present", "helper_error_type",
    "arm_property_acceptance_is_not_roc_start", "retry_allowed",
}
NATIVE_RESULT_KEYS = {
    "event", "run_token", "status", "report_saved", "claim_consumed",
    "native_helper_invoked", "ifnet_input_kpi_accepted", "management_trace_valid",
    "peer_receipt_proven", "native_awdl_reply_proven", "airdrop_proven", "retry_allowed",
}


def _parse_native_ready(line: str) -> Dict[str, Any]:
    value = _event_json(line, "NATIVE_READY", NATIVE_READY_KEYS)
    if (value.get("candidate") != BUILD or value.get("source_ready_kind") != SOURCE_KIND or
            value.get("expected_loaded_uuid") != UUID or value.get("profile") != PROFILE or
            type(value.get("boot_epoch")) is not int or
            value["boot_epoch"] <= 1793340271 or
            value.get("diagnostic_duration_ms") != 100 or
            value.get("requires_phone_ready") is not False or
            value.get("native_preflight_ready") is not True or
            value.get("helper_compiled") is not True or
            value.get("claim_available") is not True or
            value.get("host_tx_zero") is not True or
            value.get("host_management_or_data_tx_allowed") is not False or
            value.get("run_token_required") is not True or
            value.get("one_arm_maximum") is not True or
            value.get("retry_allowed") is not False):
        raise CoordinatorError("NATIVE_READY_GATE_FAILED")
    return value


def _parse_native_armed(line: str, token: str) -> Dict[str, Any]:
    value = _event_json(line, "NATIVE_ARMED", NATIVE_ARMED_KEYS)
    if (value.get("run_token") != token or value.get("claim_consumed") is not True or
            value.get("retry_allowed") is not False or
            value.get("helper_invocation_pending") is not True or
            value.get("arm_property_accepted") is not None or
            value.get("roc_start_observed") is not False):
        raise CoordinatorError("NATIVE_ARMED_ACK_INVALID")
    return value


def _parse_native_arm_result(line: str, token: str) -> Dict[str, Any]:
    value = _event_json(line, "NATIVE_ARM_RESULT", NATIVE_ARM_RESULT_KEYS)
    if (value.get("run_token") != token or
            value.get("arm_property_acceptance_is_not_roc_start") is not True or
            value.get("retry_allowed") is not False or
            (value.get("exit_code") is not None and
             type(value.get("exit_code")) is not int) or
            (value.get("arm_property_accepted") is not None and
             type(value.get("arm_property_accepted")) is not bool) or
            (value.get("helper_summary") is not None and
             not isinstance(value.get("helper_summary"), dict)) or
            type(value.get("stderr_present")) is not bool or
            (value.get("helper_error_type") is not None and
             (not isinstance(value.get("helper_error_type"), str) or
              not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}",
                               value["helper_error_type"])))):
        raise CoordinatorError("NATIVE_ARM_RESULT_INVALID")
    # Retain only the whitelisted summary fields; do not propagate helper data.
    return {key: value.get(key) for key in (
        "event", "run_token", "exit_code", "arm_property_accepted",
        "stderr_present", "helper_error_type",
        "arm_property_acceptance_is_not_roc_start", "retry_allowed")}


def _parse_native_result(line: str, token: str) -> Dict[str, Any]:
    value = _event_json(line, "NATIVE_RESULT", NATIVE_RESULT_KEYS)
    if (value.get("run_token") != token or value.get("claim_consumed") is not True or
            value.get("native_helper_invoked") is not True or
            value.get("retry_allowed") is not False or
            value.get("peer_receipt_proven") is not False or
            value.get("native_awdl_reply_proven") is not False or
            value.get("airdrop_proven") is not False or
            type(value.get("report_saved")) is not bool or
            value.get("status") not in {
                "captured_no_retry", "session_terminal_unknown_no_retry",
                "post_capture_unknown_no_retry", "native_report_write_failed_no_retry"} or
            (value.get("ifnet_input_kpi_accepted") is not None and
             type(value.get("ifnet_input_kpi_accepted")) is not bool) or
            (value.get("management_trace_valid") is not None and
             type(value.get("management_trace_valid")) is not bool) or
            (value.get("report_saved") is False and
             value.get("status") != "native_report_write_failed_no_retry") or
            (value.get("report_saved") is True and
             value.get("status") == "native_report_write_failed_no_retry")):
        raise CoordinatorError("NATIVE_RESULT_INVALID")
    return value


def _parse_native_rejected(line: str, token: str) -> Optional[Dict[str, Any]]:
    if not line.startswith("NATIVE_REJECTED ") or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        return None
    try:
        value = json.loads(line[len("NATIVE_REJECTED "):])
    except (ValueError, TypeError):
        return None
    base = {"event", "code", "helper_invoked", "claim_consumed", "retry_allowed"}
    if (not isinstance(value, dict) or set(value) not in (base, base | {"run_token"}) or
            value.get("event") != "NATIVE_REJECTED" or
            not isinstance(value.get("code"), str) or
            type(value.get("helper_invoked")) is not bool or
            value.get("helper_invoked") is not False or
            type(value.get("claim_consumed")) is not bool or
            value.get("retry_allowed") is not False or
            ("run_token" in value and value.get("run_token") != token)):
        return None
    return {
        "event": "NATIVE_REJECTED", "code": value["code"],
        "claim_consumed": value["claim_consumed"],
        "run_token_matches": value.get("run_token", token) == token,
    }


class ManagedPipe:
    def __init__(self, argv: List[str]):
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0)
        self.selector = selectors.DefaultSelector()
        assert self.process.stdout is not None
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.state: Dict[str, Any] = {"buffer": b""}
        self.closed = False

    def read_line(self, timeout: float) -> Optional[str]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\n" in self.state["buffer"]:
                raw, self.state["buffer"] = self.state["buffer"].split(b"\n", 1)
                try:
                    return raw.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    raise CoordinatorError("CHILD_PROTOCOL_ENCODING_INVALID")
            # A child may have exited after writing one or more records that
            # remain queued in the OS pipe. Read until EOF so those terminal
            # records are not dropped just because poll() already has a code.
            events = self.selector.select(min(0.2, deadline - time.monotonic()))
            if not events:
                continue
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                if self.state["buffer"]:
                    raise CoordinatorError("CHILD_PROTOCOL_TRUNCATED")
                return None
            self.state["buffer"] += chunk
            if len(self.state["buffer"]) > MAX_LINE_BYTES and b"\n" not in self.state["buffer"]:
                raise CoordinatorError("CHILD_PROTOCOL_LINE_OVERSIZE")
        raise CoordinatorError("CHILD_PROTOCOL_TIMEOUT")

    def send_line(self, line: str) -> None:
        if self.closed or self.process.poll() is not None or self.process.stdin is None:
            raise CoordinatorError("CHILD_CONTROL_PIPE_CLOSED")
        if "\n" in line.rstrip("\n") or len(line) > 160:
            raise CoordinatorError("CHILD_CONTROL_INVALID")
        self.process.stdin.write((line.rstrip("\n") + "\n").encode("ascii"))
        self.process.stdin.flush()

    def terminate(self, timeout: float = 1.0) -> None:
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    self.process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
        self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _prepare_run_dir(path: Path, account) -> None:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or path.exists():
        raise CoordinatorError("RUN_OUTPUT_PATH_NOT_NEW")
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != account.pw_uid or
            stat.S_IMODE(parent.st_mode) != 0o700):
        raise CoordinatorError("RUN_OUTPUT_PARENT_UNSAFE")
    private_info = PRIVATE_ROOT.lstat()
    if (stat.S_ISLNK(private_info.st_mode) or not stat.S_ISDIR(private_info.st_mode) or
            private_info.st_uid != account.pw_uid or
            stat.S_IMODE(private_info.st_mode) != 0o700):
        raise CoordinatorError("PRIVATE_ROOT_MODE_OR_OWNER_INVALID")
    private_root = PRIVATE_ROOT.resolve(strict=True)
    resolved_parent = path.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(private_root)
    except ValueError:
        raise CoordinatorError("RUN_OUTPUT_OUTSIDE_PRIVATE_ROOT")
    path.mkdir(mode=0o700)
    if os.geteuid() == 0:
        os.chown(path, account.pw_uid, account.pw_gid)
    os.chmod(path, 0o700)


def _atomic_report(path: Path, value: Dict[str, Any], account) -> None:
    if path.exists() or path.is_symlink():
        raise CoordinatorError("RUN_REPORT_ALREADY_EXISTS")
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _compile_listener(output_dir: Path) -> Path:
    compiler = shutil.which("xcrun")
    if compiler is None:
        raise CoordinatorError("XCRUN_UNAVAILABLE")
    output = output_dir / "awdl0_udp_probe_listener"
    result = subprocess.run(
        [compiler, "clang", "-O2", "-Wall", "-Wextra", "-Werror",
         str(LISTENER_SOURCE), "-o", str(output)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0 or not output.is_file():
        raise CoordinatorError("LISTENER_COMPILE_FAILED")
    output.chmod(0o700)
    return output


def _native_argv(metadata_path: Path, output_dir: Path) -> List[str]:
    argv = [sys.executable, str(NATIVE_WORKER), "--native-worker",
            "--metadata", str(metadata_path), "--output", str(output_dir)]
    if os.geteuid() == 0:
        return argv
    return ["/usr/bin/sudo", "-n"] + argv


def _private_default_run_dir(account) -> Path:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return PRIVATE_ROOT / ("controlled-run-" + stamp)


def run_controlled_once(*, host: str, control_path: str, metadata_path: Path,
                        sender_binary: Path, sender_sha256: str,
                        output_dir: Path) -> Dict[str, Any]:
    protocol, router = _modules()
    account = _workspace_account()
    try:
        router.validate_transport(host, control_path)
    except Exception as error:
        raise CoordinatorError(getattr(error, "code", "ROUTER_TRANSPORT_PREFLIGHT_FAILED"))
    try:
        metadata, receipt, receipt_sha, build_path = _validate_bundle(
            metadata_path, account.pw_uid, protocol)
    except protocol.ControlledProbeError as error:
        raise CoordinatorError(error.code, error.evidence)
    sender_binary = Path(sender_binary)
    if (sender_binary.is_symlink() or not sender_binary.is_file() or
            hashlib.sha256(sender_binary.read_bytes()).hexdigest() != sender_sha256):
        raise CoordinatorError("SENDER_BINARY_HASH_MISMATCH")
    if sender_sha256 != DEFAULT_SENDER_SHA256:
        raise CoordinatorError("SENDER_BINARY_NOT_FROZEN")
    _prepare_run_dir(output_dir, account)
    listener_binary = _compile_listener(output_dir)
    run_token = __import__("secrets").token_hex(16)
    report: Dict[str, Any] = {
        "schema": "test086-controlled-run-private/v1",
        "candidate": BUILD,
        "source_ready_kind": SOURCE_KIND,
        "profile": PROFILE,
        "build_receipt_sha256": receipt_sha,
        "run_token": run_token,
        "boot_epoch": None,
        "events_parent_monotonic_ns": [],
        "native_ready": None,
        "monitor_ready": None,
        "sender_ready": None,
        "listener_ready": None,
        "native_armed_ack": None,
        "sender_result": None,
        "sender_cleanup": None,
        "native_arm_result": None,
        "native_result": None,
        "listener_result": None,
        "listener_result_error": None,
        "listener_worker_cleanup": None,
        "native_worker_cleanup": None,
        "local_sender_acceptance_is_rf_proof": False,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
        "efi_modified": False,
        "retry_allowed": False,
        "boot_claim_consumed": False,
        "claim_outcome": "not_requested",
        "complete": False,
        "partial": True,
        "status": "preparing",
    }
    native: Optional[ManagedPipe] = None
    listener: Optional[ManagedPipe] = None
    sender = None
    armed = False
    native_arm_control_sent = False
    try:
        native = ManagedPipe(_native_argv(metadata_path, output_dir))
        native_ready_line = native.read_line(NATIVE_READY_TIMEOUT)
        if native_ready_line is None:
            raise CoordinatorError("NATIVE_READY_MISSING")
        if native_ready_line.startswith("NATIVE_ERROR "):
            fields = {"event", "code", "stage", "helper_invoked",
                      "claim_consumed", "retry_allowed"}
            try:
                error_event = _event_json(native_ready_line, "NATIVE_ERROR", fields)
            except CoordinatorError:
                error_event = {"event": "NATIVE_ERROR", "protocol_valid": False}
            raise CoordinatorError("NATIVE_PREFLIGHT_FAILED", error_event)
        native_ready = _parse_native_ready(native_ready_line)
        if (native_ready.get("candidate") != receipt.get("candidate") or
                native_ready.get("expected_loaded_uuid") != receipt.get("mach_o_uuid")):
            raise CoordinatorError("NATIVE_READY_RECEIPT_MISMATCH")
        metadata_errors = protocol.validate_private_metadata(
            metadata, boot_epoch=native_ready["boot_epoch"],
            expected_receipt_sha256=receipt_sha, actual_receipt_sha256=receipt_sha)
        if metadata_errors:
            raise CoordinatorError("CONTROLLED_METADATA_GATE_FAILED",
                                   {"fields": metadata_errors})
        report["native_ready"] = {key: native_ready[key] for key in NATIVE_READY_KEYS
                                  if key != "event"}
        report["boot_epoch"] = native_ready["boot_epoch"]
        report["events_parent_monotonic_ns"].append({
            "event": "NATIVE_READY", "monotonic_ns": time.monotonic_ns()})

        try:
            sender, monitor_ready, sender_ready = router.RouterSenderSession.start(
                host=host, control_path=control_path, sender_binary=sender_binary,
                sender_sha256=sender_sha256, run_token=run_token)
        except protocol.ControlledProbeError as error:
            raise CoordinatorError(error.code, error.evidence)
        report["monitor_ready"] = monitor_ready
        report["sender_ready"] = sender_ready
        report["events_parent_monotonic_ns"].append({
            "event": "ROUTER_SENDER_READY", "monotonic_ns": time.monotonic_ns()})

        listener = ManagedPipe([str(listener_binary), "--listen", "T086RX01",
                                "--run-token", run_token, "--recv-anyif"])
        listener_ready_line = listener.read_line(LISTENER_READY_TIMEOUT)
        if listener_ready_line is None:
            raise CoordinatorError("AWDL_LISTENER_READY_MISSING")
        if listener_ready_line.startswith("{\"event\":\"LISTENER_RESULT\""):
            try:
                setup = json.loads(listener_ready_line)
                if (not isinstance(setup, dict) or setup.get("event") != "LISTENER_RESULT" or
                        setup.get("status") != "setup_error" or
                        setup.get("run_token") != run_token or
                        type(setup.get("errno")) is not int or
                        type(setup.get("recv_anyif_requested")) is not bool or
                        type(setup.get("recv_anyif_set")) is not bool):
                    setup = {"event": "LISTENER_RESULT", "protocol_valid": False}
                else:
                    setup = {key: setup.get(key) for key in (
                        "event", "status", "step", "errno", "recv_anyif_requested",
                        "recv_anyif_set", "recv_anyif_errno", "run_token")}
            except (ValueError, TypeError):
                setup = {"event": "LISTENER_RESULT", "protocol_valid": False}
            raise CoordinatorError("AWDL_LISTENER_PREFLIGHT_FAILED", setup)
        try:
            listener_ready = protocol.parse_listener_ready(
                listener_ready_line, run_token=run_token)
        except protocol.ControlledProbeError as error:
            raise CoordinatorError(error.code, error.evidence)
        report["listener_ready"] = {key: value for key, value in listener_ready.items()
                                    if not key.endswith("_parsed")}
        report["events_parent_monotonic_ns"].append({
            "event": "AWDL_LISTENER_READY", "monotonic_ns": time.monotonic_ns()})

        boot = native_ready["boot_epoch"]
        if (native_ready["claim_available"] is not True or
                native_ready["host_tx_zero"] is not True or
                native_ready["native_preflight_ready"] is not True or
                native_ready["helper_compiled"] is not True or
                sender_ready["send_started"] is not False or
                monitor_ready["ap_channel"] != 149 or
                listener_ready["recv_anyif_set"] is not True):
            raise CoordinatorError("PRE_ARM_GATE_FAILED")

        native_arm_control_sent = True
        report["boot_claim_consumed"] = None
        report["claim_outcome"] = "unknown_after_arm_request_no_retry"
        native.send_line("ARM " + run_token)
        armed_line = native.read_line(NATIVE_ARM_TIMEOUT)
        if armed_line is None or not armed_line.startswith("NATIVE_ARMED "):
            # The sender has not received GO. Do not consume another attempt.
            rejected = _parse_native_rejected(armed_line or "", run_token)
            if rejected is not None:
                report["native_arm_rejected"] = rejected
                report["boot_claim_consumed"] = rejected["claim_consumed"]
                report["claim_outcome"] = (
                    "consumed_no_retry" if rejected["claim_consumed"]
                    else "not_consumed_rejected_no_retry")
                armed = rejected["claim_consumed"]
            raise CoordinatorError("NATIVE_ARM_ACK_MISSING")
        try:
            armed_ack = _parse_native_armed(armed_line, run_token)
        except CoordinatorError:
            try:
                partial = json.loads(armed_line[len("NATIVE_ARMED "):])
                if (isinstance(partial, dict) and
                        type(partial.get("claim_consumed")) is bool):
                    armed = partial["claim_consumed"]
                    report["boot_claim_consumed"] = partial["claim_consumed"]
                    report["claim_outcome"] = (
                        "consumed_no_retry" if partial["claim_consumed"]
                        else "not_consumed_invalid_ack_no_retry")
                if partial.get("claim_consumed") is True:
                    report["native_armed_ack_invalid"] = {
                        "event": "NATIVE_ARMED",
                        "claim_consumed": True,
                        "retry_allowed": False,
                        "token_matches": partial.get("run_token") == run_token,
                    }
            except (ValueError, TypeError):
                pass
            raise
        armed = True
        report["native_armed_ack"] = armed_ack
        report["boot_claim_consumed"] = True
        report["claim_outcome"] = "consumed_no_retry"
        report["events_parent_monotonic_ns"].append({
            "event": "NATIVE_ARMED_CLAIMED", "monotonic_ns": time.monotonic_ns()})

        # The claim ACK is flushed before Swift helper invocation. Release
        # sender GO immediately to overlap the 750 ms burst with helper start.
        try:
            sender_completion = sender.go_once()
        except protocol.ControlledProbeError as error:
            raise CoordinatorError(error.code, error.evidence)
        report["sender_result"] = sender_completion["sender_result"]
        report["sender_cleanup"] = sender_completion["cleanup"]
        report["events_parent_monotonic_ns"].append({
            "event": "ROUTER_GO_RESULT", "monotonic_ns": time.monotonic_ns()})

        arm_result_line = native.read_line(NATIVE_RESULT_TIMEOUT)
        if arm_result_line is None:
            raise CoordinatorError("NATIVE_ARM_RESULT_MISSING")
        report["native_arm_result"] = _parse_native_arm_result(arm_result_line, run_token)
        native_result_line = native.read_line(NATIVE_RESULT_TIMEOUT)
        if native_result_line is None:
            raise CoordinatorError("NATIVE_FINAL_RESULT_MISSING")
        report["native_result"] = _parse_native_result(native_result_line, run_token)

        listener_result_line = listener.read_line(LISTENER_RESULT_TIMEOUT)
        if listener_result_line is None:
            raise CoordinatorError("AWDL_LISTENER_RESULT_MISSING")
        try:
            report["listener_result"] = protocol.parse_listener_result(
                listener_result_line, run_token=run_token)
        except protocol.ControlledProbeError as error:
            raise CoordinatorError(error.code, error.evidence)
        report["events_parent_monotonic_ns"].append({
            "event": "ALL_RESULTS_CAPTURED", "monotonic_ns": time.monotonic_ns()})
        report["ifnet_input_kpi_accepted"] = report["native_result"].get(
            "ifnet_input_kpi_accepted")
        report["udp_marker_received"] = report["listener_result"].get("marker_match") is True
        native_status = report["native_result"]["status"]
        if (native_status == "captured_no_retry" and
                report["native_result"]["report_saved"] is True):
            report["status"] = "captured_no_peer_or_airdrop_proof"
            report["complete"] = True
            report["partial"] = False
        else:
            report["status"] = (native_status if report["native_result"]["report_saved"]
                                else "native_report_write_failed_no_retry")
            report["complete"] = False
            report["partial"] = True
        return report
    except (CoordinatorError, protocol.ControlledProbeError, OSError,
            subprocess.SubprocessError) as caught:
        if isinstance(caught, CoordinatorError):
            error = caught
        elif isinstance(caught, protocol.ControlledProbeError):
            error = CoordinatorError(caught.code, caught.evidence)
        else:
            error = CoordinatorError(
                "LOCAL_OR_CONTROLLED_RUN_FAILED",
                {"error_type": type(caught).__name__})
        report["status"] = error.code
        report["error_evidence"] = error.evidence
        if sender is not None and not sender.control_consumed:
            try:
                cleanup = sender.abort()
                report["sender_result"] = cleanup["sender_result"]
                report["sender_cleanup"] = cleanup["cleanup"]
            except Exception:
                pass
        if native is not None and not native_arm_control_sent and native.process.poll() is None:
            try:
                report["boot_claim_consumed"] = False
                report["claim_outcome"] = "aborted_before_arm_no_claim"
                native.send_line("ABORT")
                abort_line = native.read_line(2.0)
                if abort_line and abort_line.startswith("NATIVE_ABORTED "):
                    report["native_aborted"] = _event_json(
                        abort_line, "NATIVE_ABORTED",
                        {"event", "helper_invoked", "claim_consumed", "retry_allowed"})
            except Exception:
                pass
        if armed or native_arm_control_sent:
            # ARM delivery and claim consumption are separate. A missing ACK
            # leaves claim state unknown, but never triggers GO or a second ARM.
            if report.get("boot_claim_consumed") is True:
                report["status"] += "_after_claim_no_retry"
            else:
                report["status"] += "_after_arm_request_no_retry"
        if sender is not None and sender.protocol_evidence:
            report["sender_protocol_evidence"] = dict(sender.protocol_evidence)
        error.partial_report = report
        if error is caught:
            raise
        raise error from caught
    finally:
        if native is not None:
            if native_arm_control_sent:
                deadline = time.monotonic() + NATIVE_RESULT_TIMEOUT
                while (time.monotonic() < deadline and
                       (report.get("native_arm_result") is None or
                        report.get("native_result") is None)):
                    try:
                        line = native.read_line(min(3.0, deadline - time.monotonic()))
                    except CoordinatorError:
                        break
                    if line is None:
                        break
                    try:
                        if line.startswith("NATIVE_ARM_RESULT ") and report.get("native_arm_result") is None:
                            report["native_arm_result"] = _parse_native_arm_result(line, run_token)
                        elif line.startswith("NATIVE_RESULT "):
                            report["native_result"] = _parse_native_result(line, run_token)
                    except CoordinatorError:
                        break
                try:
                    native.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    report["native_worker_cleanup"] = "terminated_after_result_deadline"
                    native.terminate(timeout=1.0)
                else:
                    report["native_worker_cleanup"] = "exited_within_result_deadline"
            elif native.process.poll() is None and not native_arm_control_sent:
                native.terminate()
            native.close()
        if listener is not None:
            if report.get("listener_ready") is not None:
                if report.get("listener_result") is None:
                    try:
                        listener_result_line = listener.read_line(
                            LISTENER_RESULT_TIMEOUT)
                    except CoordinatorError as listener_error:
                        report["listener_result_error"] = listener_error.code
                    else:
                        if listener_result_line is None:
                            report["listener_result_error"] = (
                                "AWDL_LISTENER_RESULT_MISSING")
                        else:
                            try:
                                report["listener_result"] = protocol.parse_listener_result(
                                    listener_result_line, run_token=run_token)
                            except protocol.ControlledProbeError as listener_error:
                                report["listener_result_error"] = listener_error.code
                try:
                    listener.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    report["listener_worker_cleanup"] = (
                        "terminated_after_result_deadline")
                    listener.terminate(timeout=1.0)
                else:
                    report["listener_worker_cleanup"] = (
                        "exited_after_result_window")
                    listener.close()
            else:
                listener.terminate()
        if sender is not None and not sender.closed:
            router._terminate_process(sender.process)


def plan() -> Dict[str, Any]:
    return {
        "mode": "plan",
        "candidate": BUILD,
        "source_ready_kind": SOURCE_KIND,
        "requires_phone_ready": False,
        "single_boot_claim": True,
        "sender_frames_max": 16,
        "sender_interval_ms": 50,
        "sender_host_transmit_allowed": False,
        "no_argument_action": "none",
        "native_worker_source_available": NATIVE_WORKER.is_file(),
        "listener_source_available": LISTENER_SOURCE.is_file(),
        "private_bundle_available": DEFAULT_METADATA.is_file(),
        "sender_binary_available": DEFAULT_SENDER_BINARY.is_file(),
        "build_receipt_available": DEFAULT_BUILD_RECEIPT.is_file(),
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


def _failure_report(error: CoordinatorError) -> Dict[str, Any]:
    failure = dict(error.partial_report or {})
    failure.update({
        "schema": "test086-controlled-run-private/v1",
        "candidate": BUILD, "source_ready_kind": SOURCE_KIND,
        "error_code": error.code, "error_evidence": error.evidence,
        "retry_allowed": False, "efi_modified": False,
        "peer_receipt_proven": False, "airdrop_proven": False,
        "complete": False, "partial": True,
    })
    failure.setdefault("status", error.code)
    return failure


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="Run the single-use controlled experiment; requires a future boot")
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--sender-binary", type=Path, default=DEFAULT_SENDER_BINARY)
    parser.add_argument("--sender-sha256", default=DEFAULT_SENDER_SHA256)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps(plan(), sort_keys=True))
        return 0
    if not args.host or not args.control_path:
        print("ERROR: ROUTER_TRANSPORT_REQUIRED", file=sys.stderr)
        return 2
    account = _workspace_account()
    output_dir = args.output_dir or _private_default_run_dir(account)
    if not output_dir.is_absolute():
        print("ERROR: RUN_OUTPUT_PATH_MUST_BE_ABSOLUTE", file=sys.stderr)
        return 2
    report_path = output_dir / "controlled-run-private.json"
    try:
        report = run_controlled_once(
            host=args.host, control_path=args.control_path,
            metadata_path=args.metadata, sender_binary=args.sender_binary,
            sender_sha256=args.sender_sha256, output_dir=output_dir)
        _atomic_report(report_path, report, account)
        if report.get("complete") is True and report.get("status") == "captured_no_peer_or_airdrop_proof":
            print("CONTROLLED_RUN_CAPTURED")
            return 0
        print("CONTROLLED_RUN_PARTIAL")
        return 2
    except CoordinatorError as error:
        failure = _failure_report(error)
        if output_dir.exists() and not report_path.exists() and stat.S_IMODE(output_dir.stat().st_mode) == 0o700:
            try:
                _atomic_report(report_path, failure, account)
            except Exception:
                pass
        print("ERROR: " + error.code, file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError):
        print("ERROR: LOCAL_OR_CONTROLLED_RUN_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
