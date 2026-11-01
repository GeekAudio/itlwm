#!/usr/bin/env python3
"""Run one candidate-bound Test104 RX149 capture behind a live START gate.

Default invocation is an offline plan. An active run requires --run, a fresh
disarmed Test104 bundle, an existing OpenWrt ControlMaster, and an explicit AP
interface. The shared Test087 coordinator provides the one-use claim and
cleanup protocol; Test088 provides bounded sender event collection. This
adapter changes the sender profile, native worker, run directory, and adds a
fail-closed live-START plus same-Mach-clock pre-GO deadline gate.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tempfile
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO = TOOL_DIR.parents[1]
IWN_ROOT = None
CANDIDATE = "25G332-Test104"
PROFILE = "native_awdl_rx149_preowner_observation"
DEFAULT_AP = "wlan7"
DEFAULT_METADATA = None
BUILD_RECEIPT = None
DEPLOYMENT_RECEIPT = None
SENDER_BUILD_RECEIPT = None
SENDER_SOURCE = TOOL_DIR / "awdl_unicast_sender_test104.c"
SENDER_BINARY = None
SENDER_TARGET = "aarch64-linux-musl"
SENDER_SHA256 = None
EXPECTED_SENDER_SOURCE_SHA256 = None
EXPECTED_SENDER_BINARY_SHA256 = None
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test104.py"
ARM_HELPER = TOOL_DIR / "arm_p2p_rx149_test104.swift"
START_READER_SOURCE = TOOL_DIR / "read_rx149_start_test104.swift"
START_BARRIER_SOURCE = TOOL_DIR / "rx149_start_barrier_test104.py"
RUNTIME_BINDING_SOURCE = TOOL_DIR / "runtime_binding_test104.py"
PROVENANCE_SOURCE = TOOL_DIR / "sender_schema_adapter_test104.py"
LISTENER_SOURCE = TOOL_DIR / "awdl0_unicast_listener_test104.c"
LISTENER_PROTOCOL_SOURCE = TOOL_DIR / "listener_protocol_test104.py"
MINIMUM_REMAINING_US = 60_000
PROFILE_FRAMES = 4
PROFILE_INTERVAL_MS = 10
PROFILE_BUDGET_MS = 40
PROFILE_BUDGET_NS = PROFILE_BUDGET_MS * 1_000_000
NATIVE_FINAL_RESULT_TIMEOUT_SECONDS = 45.0
RESULT_NAME = "test104-tools-private.json"
CAPTURE_NAME = "native-controlled-capture-private.json"
ROUTER_SOURCE_RECEIPT = None
TARGET_IDENTITY_RECEIPT = None
ACTIVE_PACKET_SET: bytes | None = None
ACTIVE_PACKET_MANIFEST: dict | None = None
ACTIVE_LISTENER_EXPECTATION: dict | None = None


class _NativeFinalResultWaitPipe:
    """Give only the post-arm native terminal read Test104's bounded budget."""

    def __init__(self, pipe):
        self._pipe = pipe
        self._awaiting_final_result = False

    def read_line(self, timeout: float):
        if self._awaiting_final_result:
            self._awaiting_final_result = False
            line = self._pipe.read_line(NATIVE_FINAL_RESULT_TIMEOUT_SECONDS)
        else:
            line = self._pipe.read_line(timeout)
        if isinstance(line, str) and line.startswith("NATIVE_ARM_RESULT "):
            self._awaiting_final_result = True
        return line

    def __getattr__(self, name: str):
        return getattr(self._pipe, name)


def _test104_managed_pipe(argv, pipe_factory):
    """Apply Test104's listener binding and native-only final wait wrapper."""
    adapted = list(argv)
    if (len(adapted) >= 5 and
            Path(str(adapted[0])).name == "awdl0_udp_probe_listener" and
            adapted[1:3] == ["--listen", LISTENER_PROTOCOL.MARKER]):
        expected = ACTIVE_LISTENER_EXPECTATION
        if expected is None:
            raise PROTOCOL.ControlledProbeError(
                "TEST104_LISTENER_EXPECTATION_NOT_BOUND")
        adapted.extend([
            "--expected-source-ipv6", expected["source_ipv6"],
            "--expected-destination-ipv6", expected["destination_ipv6"],
            "--expected-ifindex", str(expected["ifindex"]),
        ])
    pipe = pipe_factory(adapted)
    if any(str(argument) == str(NATIVE_WORKER) for argument in adapted):
        return _NativeFinalResultWaitPipe(pipe)
    return pipe


class ControlledRunError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise ControlledRunError("TOOL_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ControlledRunError("TOOL_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(name, None)
        raise ControlledRunError("TOOL_IMPORT_FAILED") from error
    return module


# Imports are source-only; neither adapter starts a process or reads hardware
# until its explicit --run path is called.
TEST088 = load_module("test104_test088_adapter", REPO / "developer-tools/test088/controlled_run_test088.py")
BASE = TEST088.BASE
PROTOCOL = TEST088.PROTOCOL
START_BARRIER = load_module("test104_rx149_start_barrier", START_BARRIER_SOURCE)
RUNTIME_BINDING = load_module("test104_runtime_binding", RUNTIME_BINDING_SOURCE)
PROVENANCE = load_module("test104_sender_schema_adapter", PROVENANCE_SOURCE)
SENDER_PROTOCOL = load_module("test104_sender_protocol", TOOL_DIR / "sender_protocol_test104.py")
REMOTE_SENDER = load_module("test104_remote_sender", TOOL_DIR / "remote_sender_test104.py")
PACKETSET = load_module("test104_packetset", TOOL_DIR / "packetset_test104.py")
LISTENER_PROTOCOL = load_module("test104_listener_protocol", LISTENER_PROTOCOL_SOURCE)


def configure_runtime(iwn_root: Path | str, *, metadata_path: Path | None = None,
                      sender_receipt_path: Path | None = None) -> None:
    """Bind all private inputs to an explicitly supplied local IWN root."""
    global IWN_ROOT, DEFAULT_METADATA, BUILD_RECEIPT, DEPLOYMENT_RECEIPT
    global SENDER_BUILD_RECEIPT, SENDER_BINARY, SENDER_SHA256
    global EXPECTED_SENDER_SOURCE_SHA256, EXPECTED_SENDER_BINARY_SHA256
    global ROUTER_SOURCE_RECEIPT, TARGET_IDENTITY_RECEIPT
    root = Path(iwn_root).expanduser()
    if not root.is_absolute() or root.is_symlink():
        raise ControlledRunError("IWN_ROOT_MUST_BE_ABSOLUTE_NON_SYMLINK")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise ControlledRunError("IWN_ROOT_UNAVAILABLE") from error
    IWN_ROOT = root
    DEFAULT_METADATA = metadata_path or root / (
        "research/test104-runtime-private/native-controlled-probe-private.json")
    BUILD_RECEIPT = root / "research/test104-build-private.json"
    DEPLOYMENT_RECEIPT = root / "research/test104-deployment-private.json"
    SENDER_BUILD_RECEIPT = sender_receipt_path or root / (
        "research/test104-preparation-private/sender-build-private.json")
    ROUTER_SOURCE_RECEIPT = root / "research/test104-preparation-private/router-identity-private.json"
    TARGET_IDENTITY_RECEIPT = root / "research/test104-preparation-private/target-awdl0-identity-private.json"
    try:
        sender_receipt_relative = SENDER_BUILD_RECEIPT.resolve(
            strict=False).relative_to(root)
    except ValueError as error:
        raise ControlledRunError("SENDER_RECEIPT_MUST_BE_UNDER_IWN_ROOT") from error
    RUNTIME_BINDING.SENDER_SOURCE = SENDER_SOURCE
    RUNTIME_BINDING.SENDER_RECEIPT_RELATIVE = Path(sender_receipt_relative.as_posix())
    BASE.IWN_ROOT = root
    BASE.DEFAULT_METADATA = DEFAULT_METADATA
    TEST088.IWN_ROOT = root
    TEST088.BASE.DEFAULT_METADATA = DEFAULT_METADATA
    PROTOCOL.HELPER_SOURCE = ARM_HELPER

    account = workspace_account()
    receipt, _ = read_private_json(SENDER_BUILD_RECEIPT, account.pw_uid)
    source_sha = sha256(SENDER_SOURCE)
    binary_rel = Path(str(receipt.get("binary_path", "")))
    if binary_rel.is_absolute() or ".." in binary_rel.parts:
        raise ControlledRunError("SENDER_BINARY_PATH_INVALID")
    binary = REPO / binary_rel
    binary_sha = receipt.get("binary_sha256")
    if (source_sha != receipt.get("source_sha256") or
            receipt.get("candidate") != CANDIDATE or
            receipt.get("status") != "built_offline" or
            receipt.get("target") != SENDER_TARGET or
            receipt.get("source_path") != str(SENDER_SOURCE.relative_to(REPO)) or
            receipt.get("source_sha256") != source_sha or
            receipt.get("provenance_schema") != "test104-unicast-sender/v1" or
            not isinstance(receipt.get("command"), list) or not receipt["command"] or
            not isinstance(binary_sha, str) or
            not re.fullmatch(r"[0-9a-f]{64}", binary_sha) or
            binary.is_symlink() or not binary.is_file() or sha256(binary) != binary_sha):
        raise ControlledRunError("TEST104_SENDER_RECEIPT_BINDING_INVALID")
    EXPECTED_SENDER_SOURCE_SHA256 = source_sha
    EXPECTED_SENDER_BINARY_SHA256 = binary_sha
    SENDER_BINARY = binary
    SENDER_SHA256 = binary_sha
    os.environ["INTEL_WIRELESS_NATIVE_ROOT"] = str(root)


def workspace_account():
    try:
        return pwd.getpwuid(REPO.stat().st_uid)
    except (OSError, KeyError) as error:
        raise ControlledRunError("PRIVATE_ACCOUNT_UNAVAILABLE") from error


def read_private_json(path: Path, owner_uid: int) -> tuple[dict, bytes]:
    path = Path(path)
    if path.is_symlink() or not path.is_absolute():
        raise ControlledRunError("PRIVATE_RECEIPT_PATH_INVALID")
    try:
        info = path.lstat()
    except OSError as error:
        raise ControlledRunError("PRIVATE_RECEIPT_UNAVAILABLE") from error
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise ControlledRunError("PRIVATE_RECEIPT_MODE_OR_OWNER_INVALID")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise ControlledRunError("PRIVATE_RECEIPT_MALFORMED") from error
    if not isinstance(value, dict):
        raise ControlledRunError("PRIVATE_RECEIPT_NOT_OBJECT")
    return value, raw


def sender_receipt(owner_uid: int) -> dict:
    """Bind the target binary to this build's source and private cross-build receipt."""
    if not re.fullmatch(r"[0-9a-f]{64}", SENDER_SHA256):
        raise ControlledRunError("SENDER_BINARY_HASH_NOT_FROZEN")
    receipt, _ = read_private_json(SENDER_BUILD_RECEIPT, owner_uid)
    expected_source_sha = sha256(SENDER_SOURCE)
    if (receipt.get("candidate") != CANDIDATE or
            receipt.get("status") != "built_offline" or
            receipt.get("target") != SENDER_TARGET or
            receipt.get("source_path") != str(SENDER_SOURCE.relative_to(REPO)) or
            receipt.get("source_sha256") != expected_source_sha or
            receipt.get("binary_path") != str(SENDER_BINARY.relative_to(REPO)) or
            receipt.get("binary_sha256") != SENDER_SHA256 or
            receipt.get("provenance_schema") != "test104-unicast-sender/v1" or
            receipt.get("command") is None or
            not isinstance(receipt.get("command"), list)):
        raise ControlledRunError("SENDER_BUILD_RECEIPT_BINDING_INVALID")
    if SENDER_BINARY.is_symlink() or not SENDER_BINARY.is_file():
        raise ControlledRunError("SENDER_BINARY_UNAVAILABLE")
    if sha256(SENDER_BINARY) != SENDER_SHA256:
        raise ControlledRunError("SENDER_BINARY_HASH_MISMATCH")
    return receipt


def validate_deployment(owner_uid: int) -> tuple[dict, dict, bytes, bytes]:
    build, build_raw = read_private_json(BUILD_RECEIPT, owner_uid)
    deployment, deployment_raw = read_private_json(DEPLOYMENT_RECEIPT, owner_uid)
    if (build.get("candidate") != CANDIDATE or
            build.get("status") != "built_offline" or
            build.get("installed") is not False or
            build.get("rf_tested") is not False or
            deployment.get("candidate") != CANDIDATE or
            deployment.get("status") != "deployed_waiting_reboot_disarmed" or
            deployment.get("automatic_reboot") is not False or
            deployment.get("mach_o_uuid") != build.get("mach_o_uuid") or
            deployment.get("binary_sha256") != build.get("binary_sha256") or
            deployment.get("build_report_sha256") != hashlib.sha256(build_raw).hexdigest()):
            raise ControlledRunError("TEST104_BUILD_DEPLOYMENT_BINDING_INVALID")
    return build, deployment, build_raw, deployment_raw


def validate_runtime_metadata(metadata_path: Path, build: dict,
                              deployment: dict, boot_epoch: int,
                              owner_uid: int) -> tuple[dict, dict, dict]:
    # This must remain the first run-gate. It does not create a run directory,
    # consume a claim, compile/arm the driver, contact the router, or transmit.
    try:
        prearm = RUNTIME_BINDING.validate_prearm_bundle(
            metadata_path, iwn_root=IWN_ROOT)
    except Exception as error:
        code = getattr(error, "code", None)
        message = str(error)
        raise ControlledRunError("PREARM_BINDING_REJECTED:" +
                                 (code or message[:96])) from error
    metadata, _ = read_private_json(metadata_path, owner_uid)
    if (prearm.get("candidate") != CANDIDATE or
            prearm.get("expected_loaded_uuid") != build.get("mach_o_uuid") or
            metadata.get("candidate") != CANDIDATE or
            metadata.get("expected_loaded_uuid") != build.get("mach_o_uuid") or
            metadata.get("source_binding", {}).get("build_receipt_sha256") !=
                hashlib.sha256(BUILD_RECEIPT.read_bytes()).hexdigest() or
            metadata.get("minimum_boot_epoch_exclusive", boot_epoch) >= boot_epoch or
            metadata.get("armed") is not False or
            metadata.get("retry_allowed") is not False or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("host_management_or_data_tx_allowed") is not False):
        raise ControlledRunError("TEST104_RUNTIME_METADATA_BINDING_INVALID")
    _sender_build, _sender_deployment, sender, _build_raw, _deployment_raw, sender_raw = \
        RUNTIME_BINDING._read_receipt_bundle(IWN_ROOT)
    expected_sender_binding = RUNTIME_BINDING._sender_observation_binding(sender, sender_raw)
    if metadata.get("sender_observation_binding") != expected_sender_binding:
        raise ControlledRunError("TEST104_SENDER_OBSERVATION_METADATA_MISMATCH")
    if (deployment.get("mach_o_uuid") != metadata.get("expected_loaded_uuid") or
            deployment.get("binary_sha256") != build.get("binary_sha256")):
        raise ControlledRunError("TEST104_RUNTIME_DEPLOYMENT_MISMATCH")
    return metadata, prearm, {"metadata_sha256": sha256(metadata_path)}


class MachTimebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def mach_uptime_us() -> int:
    """Return mach_absolute_time converted like the Swift/XNU START reader."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.mach_absolute_time.restype = ctypes.c_uint64
    lib.mach_timebase_info.argtypes = [ctypes.POINTER(MachTimebase)]
    lib.mach_timebase_info.restype = ctypes.c_int
    info = MachTimebase()
    if lib.mach_timebase_info(ctypes.byref(info)) != 0 or info.denom == 0:
        raise ControlledRunError("MACH_TIMEBASE_UNAVAILABLE")
    ticks = int(lib.mach_absolute_time())
    return (ticks * int(info.numer) // int(info.denom)) // 1000


def validate_pre_go_window(ready: Any, now_us: int,
                           minimum_remaining_us: int = MINIMUM_REMAINING_US) -> dict:
    if not isinstance(ready, dict):
        raise ControlledRunError("NATIVE_RX_READY_MISSING")
    deadline = ready.get("hard_deadline_us")
    observed = ready.get("observed_now_us")
    token = ready.get("run_token")
    if (type(deadline) is not int or type(observed) is not int or
            type(now_us) is not int or now_us < observed or
            not isinstance(token, str) or
            not re.fullmatch(r"[0-9a-f]{32}", token)):
        raise ControlledRunError("NATIVE_RX_READY_CLOCK_INVALID")
    remaining = deadline - now_us
    return {
        "status": "passed" if remaining >= minimum_remaining_us else "expired_before_go",
        "clock_domain": "mach_absolute_time_converted_to_microseconds_since_boot",
        "run_token": token,
        "start_observed_us": ready.get("start_observed_us"),
        "hard_deadline_us": deadline,
        "reader_observed_us": observed,
        "go_gate_observed_us": now_us,
        "reader_to_go_gate_delay_us": now_us - observed,
        "remaining_at_go_gate_us": remaining,
        "minimum_remaining_us": minimum_remaining_us,
        "same_mach_clock_domain": True,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
        "retry_allowed": False,
    }


def install_go_deadline_guard(*, clock=mach_uptime_us):
    """Guard GO at READY and again in BEGIN immediately before stdin.write."""
    original = TEST088.Test088SenderSession.go_once

    def guarded_go_once(session, *, on_control_write=None):
        capture = session.capture
        report = capture.report if isinstance(capture.report, dict) else {}
        ack = report.get("native_armed_ack")
        ready = ack.get("native_rx_ready") if isinstance(ack, dict) else None
        try:
            gate = validate_pre_go_window(ready, clock())
            if gate.get("status") != "passed":
                raise ControlledRunError("NATIVE_RX_WINDOW_TOO_SHORT_BEFORE_GO")
        except ControlledRunError as error:
            report["native_rx_go_gate"] = {
                "status": "failed_closed", "reason": error.code,
                "retry_allowed": False, "go_written": False,
                "no_go_written": True,
                "peer_receipt_proven": False,
                "native_awdl_reply_proven": False, "airdrop_proven": False,
            }
            raise PROTOCOL.ControlledProbeError(error.code)
        report["native_rx_go_gate"] = {**gate, "go_written": False}
        original_callback = on_control_write

        def timed_control_write(phase: str):
            record = report["native_rx_go_gate"]
            if phase == "BEGIN":
                # Test088 consumes the one-use sender control before invoking
                # this callback. Run the parent receipt callback first, then
                # sample Mach time as the final operation before stdin.write.
                # If the window expired in the gap after READY, fail closed;
                # the claim/control stays consumed and must not be retried.
                try:
                    if original_callback is not None:
                        original_callback(phase)
                    observed = clock()
                    gate_at_write = validate_pre_go_window(ready, observed)
                except Exception as error:
                    code = getattr(error, "code", "NATIVE_RX_GO_WRITE_CLOCK_INVALID")
                    record.update({
                        "status": "failed_closed",
                        "reason": code,
                        "go_write_begin_us": None,
                        "go_write_begin_remaining_us": None,
                        "no_go_written": True,
                        "go_written": False,
                        "sender_control_consumed": True,
                        "claim_consumed": bool(report.get("boot_claim_consumed", False)),
                        "retry_allowed": False,
                        "peer_receipt_proven": False,
                        "native_awdl_reply_proven": False,
                        "airdrop_proven": False,
                    })
                    raise PROTOCOL.ControlledProbeError(code)
                record["go_write_begin_us"] = observed
                record["go_write_begin_remaining_us"] = gate_at_write[
                    "remaining_at_go_gate_us"]
                record["minimum_remaining_at_go_write_us"] = MINIMUM_REMAINING_US
                record["go_write_begin_gate_status"] = gate_at_write["status"]
                if gate_at_write.get("status") != "passed":
                    code = "NATIVE_RX_WINDOW_TOO_SHORT_AT_GO_WRITE"
                    record.update({
                        "status": "failed_closed",
                        "reason": code,
                        "no_go_written": True,
                        "go_written": False,
                        "sender_control_consumed": True,
                        "claim_consumed": bool(report.get("boot_claim_consumed", False)),
                        "retry_allowed": False,
                        "peer_receipt_proven": False,
                        "native_awdl_reply_proven": False,
                        "airdrop_proven": False,
                    })
                    raise PROTOCOL.ControlledProbeError(code)
            elif phase == "END":
                observed = clock()
                record["go_write_end_us"] = observed
                record["go_written"] = True
                record["no_go_written"] = False
                record["sender_control_consumed"] = True
                record["claim_consumed"] = bool(report.get("boot_claim_consumed", False))
                record["remaining_after_go_flush_us"] = (
                    record["hard_deadline_us"] - observed)
                if original_callback is not None:
                    original_callback(phase)

        return original(session, on_control_write=timed_control_write)

    TEST088.Test088SenderSession.go_once = guarded_go_once
    return lambda: setattr(TEST088.Test088SenderSession, "go_once", original)


def configure_test104_profile():
    """Temporarily bind Test087/088 to the Test104 packet-set sender."""
    global ACTIVE_PACKET_SET
    token_state = {"run_token": None}
    router_session_cls = TEST088.ROUTER.RouterSenderSession
    old_start_descriptor = router_session_cls.__dict__["start"]
    old_start = router_session_cls.start
    old_timing_parse = TEST088.TIMING.parse_sender_timing
    old_timing_correlate = TEST088.TIMING.correlate_with_mac_events
    old_result_parser = PROTOCOL.parse_sender_result
    restore_values = {
        "protocol_frames": PROTOCOL.SENDER_FRAMES,
        "protocol_interval": PROTOCOL.SENDER_INTERVAL_MS,
        "protocol_frozen_interval": PROTOCOL.FROZEN_METADATA_SENDER_INTERVAL_MS,
        "protocol_deadline": PROTOCOL.SENDER_DEADLINE_SECONDS,
        "protocol_tx_flags": PROTOCOL.SENDER_TX_FLAGS,
        "protocol_helper_source": PROTOCOL.HELPER_SOURCE,
        "protocol_ready_parser": PROTOCOL.parse_sender_ready,
        "base_sender_profile": BASE.SENDER_PROFILE,
        "base_native_worker": BASE.NATIVE_WORKER,
        "base_native_argv": BASE._native_argv,
        "base_sender_binary": BASE.DEFAULT_SENDER_BINARY,
        "base_sender_sha256": BASE.DEFAULT_SENDER_SHA256,
        "base_listener_source": BASE.LISTENER_SOURCE,
        "base_managed_pipe": BASE.ManagedPipe,
        "test088_binary": TEST088.SENDER_BINARY,
        "test088_sha256": TEST088.SENDER_SHA256,
        "script_builder": PROTOCOL.build_remote_monitor_sender_script,
        "timing_parse": old_timing_parse,
        "timing_correlate": old_timing_correlate,
        "result_parser": old_result_parser,
        "listener_ready_parser": PROTOCOL.parse_listener_ready,
        "listener_result_parser": PROTOCOL.parse_listener_result,
    }
    PROTOCOL.SENDER_FRAMES = PROFILE_FRAMES
    PROTOCOL.SENDER_INTERVAL_MS = PROFILE_INTERVAL_MS
    PROTOCOL.FROZEN_METADATA_SENDER_INTERVAL_MS = PROFILE_INTERVAL_MS
    PROTOCOL.SENDER_DEADLINE_SECONDS = PROFILE_BUDGET_MS / 1000
    PROTOCOL.SENDER_TX_FLAGS = "NOSEQNO"
    PROTOCOL.HELPER_SOURCE = ARM_HELPER
    PROTOCOL.parse_sender_ready = SENDER_PROTOCOL.parse_ready
    BASE.SENDER_PROFILE = {
        "frames_max": PROFILE_FRAMES,
        "interval_ms": PROFILE_INTERVAL_MS,
        "hard_deadline_ms": PROFILE_BUDGET_MS,
    }
    BASE.NATIVE_WORKER = NATIVE_WORKER
    BASE.DEFAULT_SENDER_BINARY = SENDER_BINARY
    BASE.DEFAULT_SENDER_SHA256 = SENDER_SHA256
    BASE.LISTENER_SOURCE = LISTENER_SOURCE
    TEST088.SENDER_BINARY = SENDER_BINARY
    TEST088.SENDER_SHA256 = SENDER_SHA256

    original_native_argv = BASE._native_argv

    def test104_native_argv(metadata_path, output_dir):
        return [*original_native_argv(metadata_path, output_dir),
                "--iwn-root", str(IWN_ROOT)]

    BASE._native_argv = test104_native_argv

    original_managed_pipe = BASE.ManagedPipe

    def test104_managed_pipe(argv):
        return _test104_managed_pipe(argv, original_managed_pipe)

    BASE.ManagedPipe = test104_managed_pipe

    original_remote_builder = PROTOCOL.build_remote_monitor_sender_script

    def build_test104_remote_script(**kwargs):
        if ACTIVE_PACKET_SET is None:
            raise PROTOCOL.ControlledProbeError("TEST104_PACKET_SET_NOT_BOUND")
        script = REMOTE_SENDER.build_remote_script(
            sender_binary=kwargs.get("binary"), packet_set=ACTIVE_PACKET_SET,
            run_token=kwargs.get("run_token"), ap=kwargs.get("ap", DEFAULT_AP),
            monitor="iwn102mon")
        REMOTE_SENDER.validate_remote_script(script)
        return script

    PROTOCOL.build_remote_monitor_sender_script = build_test104_remote_script

    def parse_result(line):
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            return old_result_parser(line)
        if not isinstance(value, dict):
            return old_result_parser(line)
        if value.get("schema") != SENDER_PROTOCOL.SCHEMA:
            # Test088 creates a deliberately small legacy projection before it
            # calls the Test087 parser. Map only the Test104 C sender's
            # documented stop-reason spellings at that compatibility seam.
            # The original raw result is still retained and strictly checked
            # later by sender_protocol_test104.
            stop_map = {
                "schedule_wait_failed": "schedule_or_sleep_failed",
                "clock_before_failed": "monotonic_clock_unavailable",
                "clock_after_failed": "monotonic_clock_unavailable",
            }
            if (value.get("event") == "SENDER_RESULT" and
                    value.get("stop_reason") in stop_map):
                value = dict(value)
                value["stop_reason"] = stop_map[value["stop_reason"]]
                line = json.dumps(value, sort_keys=True, separators=(",", ":"))
            return old_result_parser(line)
        expected = token_state.get("run_token")
        if not isinstance(expected, str):
            raise PROTOCOL.ControlledProbeError("TEST104_RESULT_WITHOUT_ACTIVE_TOKEN")
        try:
            return SENDER_PROTOCOL.project_legacy_result(value, expected)
        except SENDER_PROTOCOL.SenderProtocolError as error:
            raise PROTOCOL.ControlledProbeError("TEST104_SENDER_RESULT_INVALID") from error

    PROTOCOL.parse_sender_result = parse_result

    def parse_test104_listener_ready(line, *, run_token):
        if ACTIVE_LISTENER_EXPECTATION is None:
            raise PROTOCOL.ControlledProbeError("TEST104_LISTENER_EXPECTATION_NOT_BOUND")
        try:
            return LISTENER_PROTOCOL.parse_ready(
                line, run_token=run_token, expected=ACTIVE_LISTENER_EXPECTATION)
        except LISTENER_PROTOCOL.ListenerProtocolError as error:
            raise PROTOCOL.ControlledProbeError(
                "TEST104_LISTENER_READY_INVALID:" + str(error)) from error

    def parse_test104_listener_result(line, *, run_token):
        if ACTIVE_LISTENER_EXPECTATION is None:
            raise PROTOCOL.ControlledProbeError("TEST104_LISTENER_EXPECTATION_NOT_BOUND")
        try:
            return LISTENER_PROTOCOL.parse_result(
                line, run_token=run_token, expected=ACTIVE_LISTENER_EXPECTATION)
        except LISTENER_PROTOCOL.ListenerProtocolError as error:
            raise PROTOCOL.ControlledProbeError(
                "TEST104_LISTENER_RESULT_INVALID:" + str(error)) from error

    PROTOCOL.parse_listener_ready = parse_test104_listener_ready
    PROTOCOL.parse_listener_result = parse_test104_listener_result

    def captured_start(cls, **kwargs):
        session, monitor_ready, sender_ready = old_start(**kwargs)
        token_state["run_token"] = session.run_token
        return session, monitor_ready, sender_ready

    router_session_cls.start = classmethod(captured_start)

    def normalize_timing_result(sender_result):
        if isinstance(sender_result, dict) and sender_result.get("schema") == SENDER_PROTOCOL.SCHEMA:
            sender_result = dict(sender_result)
            sender_result["stop_reason"] = {
                "schedule_wait_failed": "schedule_sleep_error",
                "clock_before_failed": "monotonic_clock_before_failed",
                "clock_after_failed": "monotonic_clock_after_failed",
            }.get(sender_result.get("stop_reason"), sender_result.get("stop_reason"))
        return old_timing_parse(sender_result)

    TEST088.TIMING.parse_sender_timing = normalize_timing_result

    def correlate_test104(sender_result, **kwargs):
        return old_timing_correlate(sender_result, **kwargs)

    TEST088.TIMING.correlate_with_mac_events = correlate_test104

    def restore():
        PROTOCOL.SENDER_FRAMES = restore_values["protocol_frames"]
        PROTOCOL.SENDER_INTERVAL_MS = restore_values["protocol_interval"]
        PROTOCOL.FROZEN_METADATA_SENDER_INTERVAL_MS = restore_values["protocol_frozen_interval"]
        PROTOCOL.SENDER_DEADLINE_SECONDS = restore_values["protocol_deadline"]
        PROTOCOL.SENDER_TX_FLAGS = restore_values["protocol_tx_flags"]
        PROTOCOL.HELPER_SOURCE = restore_values["protocol_helper_source"]
        PROTOCOL.parse_sender_ready = restore_values["protocol_ready_parser"]
        BASE.SENDER_PROFILE = restore_values["base_sender_profile"]
        BASE.NATIVE_WORKER = restore_values["base_native_worker"]
        BASE._native_argv = restore_values["base_native_argv"]
        BASE.DEFAULT_SENDER_BINARY = restore_values["base_sender_binary"]
        BASE.DEFAULT_SENDER_SHA256 = restore_values["base_sender_sha256"]
        BASE.LISTENER_SOURCE = restore_values["base_listener_source"]
        BASE.ManagedPipe = restore_values["base_managed_pipe"]
        TEST088.SENDER_BINARY = restore_values["test088_binary"]
        TEST088.SENDER_SHA256 = restore_values["test088_sha256"]
        PROTOCOL.build_remote_monitor_sender_script = restore_values["script_builder"]
        PROTOCOL.parse_sender_result = restore_values["result_parser"]
        PROTOCOL.parse_listener_ready = restore_values["listener_ready_parser"]
        PROTOCOL.parse_listener_result = restore_values["listener_result_parser"]
        TEST088.TIMING.parse_sender_timing = restore_values["timing_parse"]
        TEST088.TIMING.correlate_with_mac_events = restore_values["timing_correlate"]
        router_session_cls.start = old_start_descriptor
        token_state["run_token"] = None
    return restore


def test104_run_dir(boot_epoch: int, candidate: str) -> Path:
    identity = PROTOCOL.candidate_binding
    return identity.runtime_private_root(IWN_ROOT, candidate) / (
        "test104-tools-boot" + str(boot_epoch))


def atomic_private_write(path: Path, value: dict, account) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ControlledRunError("RUN_REPORT_ALREADY_EXISTS")
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise ControlledRunError("UNSAFE_PRIVATE_RUN_DIRECTORY")
    payload = json.dumps(value, ensure_ascii=False, indent=2,
                         sort_keys=True).encode("utf-8") + b"\n"
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


def runtime_tool_hashes() -> dict:
    paths = [Path(__file__).resolve(), NATIVE_WORKER, ARM_HELPER,
             START_READER_SOURCE, START_BARRIER_SOURCE, RUNTIME_BINDING_SOURCE,
             PROVENANCE_SOURCE, TOOL_DIR / "sender_protocol_test104.py",
             TOOL_DIR / "remote_sender_test104.py", TOOL_DIR / "packetset_test104.py",
             LISTENER_SOURCE, LISTENER_PROTOCOL_SOURCE,
             TOOL_DIR / "hcmd_rx_trace_test104.py",
             TOOL_DIR / "rx149_capture_attempts_test104.py",
             TOOL_DIR / "tx_rsp_retry_observation_test104.py",
             SENDER_SOURCE, SENDER_BINARY,
             REPO / "developer-tools/test087/controlled_run_coordinator.py",
             REPO / "developer-tools/test087/run_controlled_probe_once.py",
             REPO / "developer-tools/test087/test087_controlled.py",
             REPO / "developer-tools/test087/native_controlled_capture.py",
             REPO / "developer-tools/test088/controlled_run_test088.py",
             TOOL_DIR / "frozen-template-test104.json"]
    result = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ControlledRunError("RUNTIME_TOOL_SOURCE_UNAVAILABLE:" + path.name)
        result[str(path.relative_to(REPO))] = sha256(path)
    return result


def plan(metadata_path: Path | None = None,
         iwn_root: Path | str | None = None) -> dict:
    candidate = None
    expected_uuid = None
    minimum_boot = None
    try:
        metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8")) \
            if metadata_path is not None else {}
        if isinstance(metadata, dict):
            candidate = metadata.get("candidate")
            expected_uuid = metadata.get("expected_loaded_uuid")
            minimum_boot = metadata.get("minimum_boot_epoch_exclusive")
    except (OSError, ValueError, TypeError):
        pass
    identity = PROTOCOL.candidate_binding
    root = Path(iwn_root).expanduser() if iwn_root else None
    private_root = (identity.runtime_private_root(root, candidate)
                    if root is not None and root.is_absolute() and
                    identity.valid_candidate(candidate) else None)
    return {
        "mode": "plan", "tool_revision": "Test104",
        "driver_candidate": candidate, "expected_loaded_uuid": expected_uuid,
        "profile": PROFILE, "sender_contract": dict(RUNTIME_BINDING.SENDER_CONTRACT),
        "sender_binary": str(SENDER_BINARY or (REPO / (
            "developer-tools/test104/build/awdl_unicast_sender_test104-aarch64-linux-musl"))),
        "sender_sha256": SENDER_SHA256 or EXPECTED_SENDER_BINARY_SHA256,
        "sender_source_sha256": EXPECTED_SENDER_SOURCE_SHA256,
        "sender_build_receipt": str(SENDER_BUILD_RECEIPT or (
            (Path(iwn_root).expanduser() if iwn_root else Path("<IWN_ROOT>")) /
            "research/test104-preparation-private/sender-build-private.json")),
        "packet_set_template_sha256": PACKETSET.TEMPLATE_SHA256,
        "listener_contract": {
            "schema": LISTENER_PROTOCOL.SCHEMA,
            "source_destination_from_same_fresh_packet_manifest": True,
            "destination_is_unicast": True,
            "multicast_group": None,
            "interface": "awdl0",
            "interface_ifindex_bound": True,
            "source_port": LISTENER_PROTOCOL.SOURCE_PORT,
            "destination_port": LISTENER_PROTOCOL.PORT,
            "hop_limit": LISTENER_PROTOCOL.HOP_LIMIT,
            "truncated_datagrams_rejected": True,
            "raw_addresses_serialized": False,
        },
        "native_worker": str(NATIVE_WORKER), "arm_helper": str(ARM_HELPER),
        "start_reader": str(START_READER_SOURCE),
        "minimum_ready_remaining_us": MINIMUM_REMAINING_US,
        "run_directory_pattern": (str(private_root / "test104-tools-boot<epoch>")
                                   if private_root else None),
        "required_arguments_for_run": ["--run", "--host", "--control-path",
                                       "--iwn-root", "--metadata", "--ap"],
        "runtime_root_explicit": root is not None,
        "test104_sender_schema": SENDER_PROTOCOL.SCHEMA,
        "test104_receiver_profile": {
            "channel": 149, "duration_ms": 100,
            "native_data_input": True, "host_tx": False,
        },
        "hcmd_rx_trace_observation": "read_only_bounded_samples_during_worker_lifetime",
        "rx149_capture_attempts_observation": (
            "numeric_fixed_capacity_ledger; incomplete_or_overflow_is_not_delivery_proof"),
        "tx_rsp_retry_observation": (
            "same-cut TX_RSP counters; schema4 reports unavailable; not RF/ACK/peer proof"),
        "default_action": "none", "efi_modified": False,
        "rf_triggered": False, "retry_allowed": False,
        "peer_receipt_proven": False, "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def run_once(*, host: str, control_path: str, metadata_path: Path,
             ap: str) -> tuple[dict, Path, dict]:
    global ACTIVE_PACKET_SET, ACTIVE_PACKET_MANIFEST, ACTIVE_LISTENER_EXPECTATION
    account = workspace_account()
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}", host) or host.startswith("-"):
        raise ControlledRunError("INVALID_HOST")
    if not os.path.isabs(control_path) or "\n" in control_path:
        raise ControlledRunError("INVALID_CONTROL_PATH")
    try:
        PROTOCOL.validate_ap_interface(ap)
    except Exception as error:
        raise ControlledRunError("INVALID_AP_INTERFACE") from error

    # Configure protocol contracts before Test087's exact pre-arm validator.
    restore_profile = configure_test104_profile()
    try:
        build, deployment, build_raw, deployment_raw = validate_deployment(account.pw_uid)
        boot_epoch = RUNTIME_BINDING._read_boot_epoch()
        metadata, prearm, meta_digest = validate_runtime_metadata(
            metadata_path, build, deployment, boot_epoch, account.pw_uid)
        sender_build = sender_receipt(account.pw_uid)
        loaded_text = RUNTIME_BINDING._run_text([
            "/usr/bin/kmutil", "showloaded", "--list-only",
            "--bundle-identifier", "org.geekaudio.AirportItlwm"])
        loaded_uuid = RUNTIME_BINDING._extract_loaded_uuid(loaded_text)
        if loaded_uuid != build.get("mach_o_uuid"):
            raise ControlledRunError("LOADED_CANDIDATE_UUID_MISMATCH")
        router_receipt, router_raw = read_private_json(
            ROUTER_SOURCE_RECEIPT, account.pw_uid)
        target_receipt, target_raw = read_private_json(
            TARGET_IDENTITY_RECEIPT, account.pw_uid)
        try:
            packet_set, packet_manifest = RUNTIME_BINDING.bind_runtime_identities(
                metadata, router_receipt, target_receipt,
                expected_boot_epoch=boot_epoch, expected_uuid=loaded_uuid,
                router_receipt_sha256=hashlib.sha256(router_raw).hexdigest())
        except Exception as error:
            code = getattr(error, "code", None) or str(error)[:96] or type(error).__name__
            raise ControlledRunError("TEST104_IDENTITY_BINDING_REJECTED:" + code) from error
        ACTIVE_PACKET_SET = packet_set
        ACTIVE_PACKET_MANIFEST = packet_manifest
        try:
            ACTIVE_LISTENER_EXPECTATION = LISTENER_PROTOCOL.expected_binding(
                packet_manifest, target_receipt.get("ifindex"))
        except LISTENER_PROTOCOL.ListenerProtocolError as error:
            raise ControlledRunError("TEST104_LISTENER_BINDING_REJECTED:" + str(error)) from error

        # Compile the read-only IOKit START reader before the coordinator can
        # create its run directory, consume a claim, or issue ARM.
        with tempfile.TemporaryDirectory(prefix="test104-rx149-reader-",
                                         dir="/private/tmp") as temp_dir:
            reader_dir = Path(temp_dir)
            reader_dir.chmod(0o700)
            try:
                reader = START_BARRIER.compile_reader(reader_dir)
            except Exception as error:
                code = getattr(error, "code", None) or type(error).__name__
                raise ControlledRunError("TEST104_START_READER_PRECOMPILE_FAILED:" + code) from error
            reader_sha = sha256(reader)
            output_dir = test104_run_dir(boot_epoch, CANDIDATE)
            if output_dir.exists() or output_dir.is_symlink():
                raise ControlledRunError("CURRENT_BOOT_OUTPUT_EXISTS_NO_RETRY")

            identity = PROTOCOL.candidate_binding
            try:
                PROTOCOL.validate_ap_interface(ap)
                metadata_again, _, _, _ = BASE._validate_bundle(
                    metadata_path, account.pw_uid, PROTOCOL)
                if metadata_again.get("candidate") != CANDIDATE:
                    raise ControlledRunError("CANDIDATE_CHANGED_AFTER_PREARM")
                minimum_boot = metadata["minimum_boot_epoch_exclusive"]
                if boot_epoch <= minimum_boot:
                    raise ControlledRunError("BOOT_EPOCH_TOO_OLD")
                # Validate the sender binary against its private build receipt.
                sender_build = sender_receipt(account.pw_uid)
                hashes = runtime_tool_hashes()
                if hashes.get(str(SENDER_BINARY.relative_to(REPO))) != SENDER_SHA256:
                    raise ControlledRunError("SENDER_BINARY_RUNTIME_PIN_MISMATCH")
            except Exception as error:
                if isinstance(error, ControlledRunError):
                    raise
                raise ControlledRunError("TEST104_PRE_RUN_GATE_FAILED") from error

            restore_barrier = START_BARRIER.install_native_armed_go_barrier(
                BASE, reader=reader, build=CANDIDATE,
                minimum_remaining_us=MINIMUM_REMAINING_US)
            restore_go = install_go_deadline_guard()
            old_run_dir = TEST088._new_run_dir
            TEST088._new_run_dir = test104_run_dir
            try:
                report = TEST088.run_test088_once(
                    host=host, control_path=control_path,
                    metadata_path=metadata_path, ap=ap, boot_epoch=boot_epoch)
            except (BASE.CoordinatorError, PROTOCOL.ControlledProbeError,
                    TEST088.AdapterError) as error:
                report = getattr(error, "partial_report", None) or {
                    "complete": False, "partial": True,
                    "status": getattr(error, "code", type(error).__name__),
                    "error_code": getattr(error, "code", type(error).__name__),
                    "error_evidence": getattr(error, "evidence", {}),
                    "retry_allowed": False,
                    "peer_receipt_proven": False,
                    "native_awdl_reply_proven": False,
                    "airdrop_proven": False,
                }
            finally:
                restore_go()
                restore_barrier()
                TEST088._new_run_dir = old_run_dir

            # Decode only the recorded sender event. Missing or malformed
            # provenance never becomes a negative RF or native-input result.
            sender_event = report.get("test088_sender", {}).get("sender_result_event")
            try:
                provenance = PROVENANCE.classify_sender_result(sender_event)
            except (PROVENANCE.SenderAdapterError, TypeError, AttributeError) as error:
                provenance = {"status": "unknown", "reason": str(error),
                              "rf_transmission_proven": False,
                              "peer_receipt_proven": False,
                              "native_awdl0_ingress_proven": False,
                              "airdrop_proven": False}
            report["openwrt_tx_provenance"] = provenance
            report.update({
                "schema": "test104-tools-controlled-run-private/v1",
                "tool_revision": "Test104",
                "candidate": CANDIDATE,
                "driver_candidate": CANDIDATE,
                "expected_loaded_uuid": build["mach_o_uuid"],
                "boot_epoch": boot_epoch,
                "runtime_prearm": prearm,
                "runtime_metadata_sha256": meta_digest["metadata_sha256"],
                "build_receipt_sha256": hashlib.sha256(build_raw).hexdigest(),
                "deployment_receipt_sha256": hashlib.sha256(deployment_raw).hexdigest(),
                "sender_build_receipt_sha256": hashlib.sha256(
                    SENDER_BUILD_RECEIPT.read_bytes()).hexdigest(),
                "sender_binary_sha256": SENDER_SHA256,
                "sender_source_sha256": sender_build["source_sha256"],
                "sender_contract": dict(RUNTIME_BINDING.SENDER_CONTRACT),
                "router_source_receipt_sha256": hashlib.sha256(router_raw).hexdigest(),
                "target_identity_receipt_sha256": hashlib.sha256(target_raw).hexdigest(),
                "packet_set_binding": {
                    "schema": packet_manifest.get("schema"),
                    "packet_set_sha256": packet_manifest.get("packet_set_sha256"),
                    "frame_hashes": [row.get("packet_sha256") for row in
                                     packet_manifest.get("frames", [])],
                    "identity_freshness": packet_manifest.get("identity_freshness"),
                    "addresses_in_parent_report": False,
                },
                "listener_binding": {
                    "schema": LISTENER_PROTOCOL.SCHEMA,
                    "source_identity_tag_fnv1a64":
                        ACTIVE_LISTENER_EXPECTATION["source_identity_tag_fnv1a64"],
                    "destination_identity_tag_fnv1a64":
                        ACTIVE_LISTENER_EXPECTATION["destination_identity_tag_fnv1a64"],
                    "awdl0_ifindex": ACTIVE_LISTENER_EXPECTATION["ifindex"],
                    "source_port": ACTIVE_LISTENER_EXPECTATION["source_port"],
                    "destination_port": ACTIVE_LISTENER_EXPECTATION["destination_port"],
                    "hop_limit": ACTIVE_LISTENER_EXPECTATION["hop_limit"],
                    "raw_addresses_serialized": False,
                },
                "listener_source_sha256": sha256(LISTENER_SOURCE),
                "listener_protocol_source_sha256": sha256(LISTENER_PROTOCOL_SOURCE),
                "start_reader_source_sha256": sha256(START_READER_SOURCE),
                "start_reader_binary_sha256": reader_sha,
                "start_barrier_source_sha256": sha256(START_BARRIER_SOURCE),
                "arm_helper_source_sha256": sha256(ARM_HELPER),
                "native_worker_source_sha256": sha256(NATIVE_WORKER),
                "runtime_binding_source_sha256": sha256(RUNTIME_BINDING_SOURCE),
                "runtime_tool_sha256": hashes,
                "output_directory": str(output_dir),
                "sender_local_writes_prove_rf": False,
                "native_rx_ready_proves_peer_or_data_delivery": False,
                "peer_receipt_proven": False,
                "native_awdl_reply_proven": False,
                "airdrop_proven": False,
                "efi_modified": False,
                "retry_allowed": False,
                "sleep": "user_skipped",
            })
            report_path = output_dir / RESULT_NAME
            if output_dir.exists() and output_dir.is_dir():
                atomic_private_write(report_path, report, account)
            return report, output_dir, prearm
    finally:
        ACTIVE_PACKET_SET = None
        ACTIVE_PACKET_MANIFEST = None
        ACTIVE_LISTENER_EXPECTATION = None
        restore_profile()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="Run one Test104 candidate-bound RX149 capture")
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--iwn-root", type=Path,
                        help="IWN research root (or INTEL_WIRELESS_NATIVE_ROOT env var)")
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--sender-receipt", type=Path)
    parser.add_argument("--ap", help="explicit live AP interface, prepared profile wlan7")
    args = parser.parse_args(argv)
    root_arg = args.iwn_root or os.environ.get("INTEL_WIRELESS_NATIVE_ROOT")
    if not args.run:
        print(json.dumps(plan(args.metadata, root_arg), sort_keys=True))
        return 0
    if root_arg is None:
        print("ERROR: IWN_ROOT_REQUIRED", file=sys.stderr)
        return 2
    if not args.host or not args.control_path or not args.ap:
        print("ERROR: ROUTER_TRANSPORT_AND_AP_REQUIRED", file=sys.stderr)
        return 2
    try:
        configure_runtime(root_arg, metadata_path=args.metadata,
                          sender_receipt_path=args.sender_receipt)
        report, output_dir, _prearm = run_once(
            host=args.host, control_path=args.control_path,
            metadata_path=DEFAULT_METADATA, ap=args.ap)
    except ControlledRunError as error:
        print("ERROR: " + error.code, file=sys.stderr)
        return 2
    print(json.dumps({
        "candidate": CANDIDATE,
        "status": report.get("status"),
        "complete": report.get("complete") is True,
        "output_directory": str(output_dir),
        "retry_allowed": False,
    }, sort_keys=True))
    return 0 if report.get("complete") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
