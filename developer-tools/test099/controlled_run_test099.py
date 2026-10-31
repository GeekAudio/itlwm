#!/usr/bin/env python3
"""Run one candidate-bound Test099 RX149 capture behind a live START gate.

Default invocation is an offline plan. An active run requires --run, a fresh
disarmed Test099 bundle, an existing OpenWrt ControlMaster, and an explicit AP
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
IWN_ROOT = REPO.parent / "IntelWirelessNative"
CANDIDATE = "25G332-Test099"
PROFILE = "native_awdl_rx149_preowner_observation"
DEFAULT_AP = "wlan7"
DEFAULT_METADATA = IWN_ROOT / "research/test099-runtime-private/native-controlled-probe-private.json"
BUILD_RECEIPT = IWN_ROOT / "research/test099-build-private.json"
DEPLOYMENT_RECEIPT = IWN_ROOT / "research/test099-deployment-private.json"
SENDER_BUILD_RECEIPT = IWN_ROOT / "research/test099-preparation-private/sender-build-private.json"
SENDER_SOURCE = TOOL_DIR / "afpacket-sender/awdl_probe_sender.c"
SENDER_BINARY = TOOL_DIR / "afpacket-sender/build/awdl_probe_sender-aarch64-linux-musl"
SENDER_TARGET = "aarch64-linux-musl"
# Fixed from the private Zig 0.14.1 aarch64-linux-musl cross-build receipt.
SENDER_SHA256 = "1726f1e7b6f64b3e8d7482fb7d7d823aea31786fdff6c20900813f09d5b7e5e8"
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test099.py"
ARM_HELPER = TOOL_DIR / "arm_p2p_rx149_test099.swift"
START_READER_SOURCE = TOOL_DIR / "read_rx149_start_test099.swift"
START_BARRIER_SOURCE = TOOL_DIR / "rx149_start_barrier.py"
RUNTIME_BINDING_SOURCE = TOOL_DIR / "runtime_binding.py"
MINIMUM_REMAINING_US = 60_000
PROFILE_FRAMES = 4
PROFILE_INTERVAL_MS = 10
PROFILE_BUDGET_MS = 40
PROFILE_BUDGET_NS = PROFILE_BUDGET_MS * 1_000_000
RESULT_NAME = "test099-tools-private.json"
CAPTURE_NAME = "native-controlled-capture-private.json"


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
TEST088 = load_module("test099_test088_adapter", REPO / "developer-tools/test088/controlled_run_test088.py")
BASE = TEST088.BASE
PROTOCOL = TEST088.PROTOCOL
START_BARRIER = load_module("test099_rx149_start_barrier", START_BARRIER_SOURCE)
RUNTIME_BINDING = load_module("test099_runtime_binding", RUNTIME_BINDING_SOURCE)


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
            receipt.get("binary_path") != str(SENDER_BINARY) or
            receipt.get("binary_sha256") != SENDER_SHA256 or
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
        raise ControlledRunError("TEST099_BUILD_DEPLOYMENT_BINDING_INVALID")
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
                hashlib.sha256((IWN_ROOT / "research/test099-build-private.json").read_bytes()).hexdigest() or
            metadata.get("minimum_boot_epoch_exclusive", boot_epoch) >= boot_epoch or
            metadata.get("armed") is not False or
            metadata.get("retry_allowed") is not False or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("host_management_or_data_tx_allowed") is not False):
        raise ControlledRunError("TEST099_RUNTIME_METADATA_BINDING_INVALID")
    if (deployment.get("mach_o_uuid") != metadata.get("expected_loaded_uuid") or
            deployment.get("binary_sha256") != build.get("binary_sha256")):
        raise ControlledRunError("TEST099_RUNTIME_DEPLOYMENT_MISMATCH")
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


def configure_test099_profile():
    """Temporarily adapt the imported Test087/088 modules to Test099's exact profile."""
    restore_values = {
        "protocol_frames": PROTOCOL.SENDER_FRAMES,
        "protocol_interval": PROTOCOL.SENDER_INTERVAL_MS,
        "protocol_frozen_interval": PROTOCOL.FROZEN_METADATA_SENDER_INTERVAL_MS,
        "protocol_deadline": PROTOCOL.SENDER_DEADLINE_SECONDS,
        "base_sender_profile": BASE.SENDER_PROFILE,
        "base_native_worker": BASE.NATIVE_WORKER,
        "base_sender_binary": BASE.DEFAULT_SENDER_BINARY,
        "base_sender_sha256": BASE.DEFAULT_SENDER_SHA256,
        "test088_binary": TEST088.SENDER_BINARY,
        "test088_sha256": TEST088.SENDER_SHA256,
        "script_builder": PROTOCOL.build_remote_monitor_sender_script,
    }
    PROTOCOL.SENDER_FRAMES = PROFILE_FRAMES
    PROTOCOL.SENDER_INTERVAL_MS = PROFILE_INTERVAL_MS
    PROTOCOL.FROZEN_METADATA_SENDER_INTERVAL_MS = PROFILE_INTERVAL_MS
    PROTOCOL.SENDER_DEADLINE_SECONDS = PROFILE_BUDGET_MS / 1000
    BASE.SENDER_PROFILE = {
        "frames_max": PROFILE_FRAMES,
        "interval_ms": PROFILE_INTERVAL_MS,
        "hard_deadline_ms": PROFILE_BUDGET_MS,
    }
    BASE.NATIVE_WORKER = NATIVE_WORKER
    BASE.DEFAULT_SENDER_BINARY = SENDER_BINARY
    BASE.DEFAULT_SENDER_SHA256 = SENDER_SHA256
    TEST088.SENDER_BINARY = SENDER_BINARY
    TEST088.SENDER_SHA256 = SENDER_SHA256

    old_sender_command = (
        '"$BIN" --send --interface "$MON" --count 16 --interval-ms 80 '
        '--nonce "$RUN_TOKEN" --wait-go <&3 &')
    new_sender_command = (
        '"$BIN" --send --interface "$MON" --count 4 --interval-ms 10 '
        '--nonce "$RUN_TOKEN" --wait-go <&3 &')
    original_builder = PROTOCOL.build_remote_monitor_sender_script

    def build_test099_remote_script(**kwargs):
        script = original_builder(**kwargs)
        if script.count(old_sender_command) != 1:
            raise PROTOCOL.ControlledProbeError(
                "TEST099_REMOTE_SENDER_PROFILE_PATCH_FAILED")
        return script.replace(old_sender_command, new_sender_command, 1)

    PROTOCOL.build_remote_monitor_sender_script = build_test099_remote_script

    def restore():
        PROTOCOL.SENDER_FRAMES = restore_values["protocol_frames"]
        PROTOCOL.SENDER_INTERVAL_MS = restore_values["protocol_interval"]
        PROTOCOL.FROZEN_METADATA_SENDER_INTERVAL_MS = restore_values["protocol_frozen_interval"]
        PROTOCOL.SENDER_DEADLINE_SECONDS = restore_values["protocol_deadline"]
        BASE.SENDER_PROFILE = restore_values["base_sender_profile"]
        BASE.NATIVE_WORKER = restore_values["base_native_worker"]
        BASE.DEFAULT_SENDER_BINARY = restore_values["base_sender_binary"]
        BASE.DEFAULT_SENDER_SHA256 = restore_values["base_sender_sha256"]
        TEST088.SENDER_BINARY = restore_values["test088_binary"]
        TEST088.SENDER_SHA256 = restore_values["test088_sha256"]
        PROTOCOL.build_remote_monitor_sender_script = restore_values["script_builder"]
    return restore


def test099_run_dir(boot_epoch: int, candidate: str) -> Path:
    identity = PROTOCOL.candidate_binding
    return identity.runtime_private_root(IWN_ROOT, candidate) / (
        "test099-tools-boot" + str(boot_epoch))


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
             SENDER_SOURCE, SENDER_BINARY,
             REPO / "developer-tools/test087/controlled_run_coordinator.py",
             REPO / "developer-tools/test088/controlled_run_test088.py"]
    result = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ControlledRunError("RUNTIME_TOOL_SOURCE_UNAVAILABLE:" + path.name)
        result[str(path.relative_to(REPO))] = sha256(path)
    return result


def plan(metadata_path: Path = DEFAULT_METADATA) -> dict:
    candidate = None
    expected_uuid = None
    minimum_boot = None
    try:
        metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
        if isinstance(metadata, dict):
            candidate = metadata.get("candidate")
            expected_uuid = metadata.get("expected_loaded_uuid")
            minimum_boot = metadata.get("minimum_boot_epoch_exclusive")
    except (OSError, ValueError, TypeError):
        pass
    identity = PROTOCOL.candidate_binding
    private_root = (identity.runtime_private_root(IWN_ROOT, candidate)
                    if identity.valid_candidate(candidate) else None)
    return {
        "mode": "plan", "tool_revision": "Test099",
        "driver_candidate": candidate, "expected_loaded_uuid": expected_uuid,
        "profile": PROFILE, "sender_contract": dict(RUNTIME_BINDING.SENDER_CONTRACT),
        "sender_binary": str(SENDER_BINARY), "sender_sha256": SENDER_SHA256 or None,
        "sender_build_receipt": str(SENDER_BUILD_RECEIPT),
        "native_worker": str(NATIVE_WORKER), "arm_helper": str(ARM_HELPER),
        "start_reader": str(START_READER_SOURCE),
        "minimum_ready_remaining_us": MINIMUM_REMAINING_US,
        "run_directory_pattern": (str(private_root / "test099-tools-boot<epoch>")
                                   if private_root else None),
        "required_arguments_for_run": ["--run", "--host", "--control-path",
                                       "--metadata", "--ap"],
        "default_action": "none", "efi_modified": False,
        "rf_triggered": False, "retry_allowed": False,
        "peer_receipt_proven": False, "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def run_once(*, host: str, control_path: str, metadata_path: Path,
             ap: str) -> tuple[dict, Path, dict]:
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
    restore_profile = configure_test099_profile()
    try:
        build, deployment, build_raw, deployment_raw = validate_deployment(account.pw_uid)
        boot_epoch = TEST088._read_current_boot_epoch()
        metadata, prearm, meta_digest = validate_runtime_metadata(
            metadata_path, build, deployment, boot_epoch, account.pw_uid)
        sender_build = sender_receipt(account.pw_uid)

        # Compile the read-only IOKit START reader before the coordinator can
        # create its run directory, consume a claim, or issue ARM.
        with tempfile.TemporaryDirectory(prefix="test099-rx149-reader-",
                                         dir="/private/tmp") as temp_dir:
            reader_dir = Path(temp_dir)
            reader_dir.chmod(0o700)
            reader = START_BARRIER.compile_reader(reader_dir)
            reader_sha = sha256(reader)
            output_dir = test099_run_dir(boot_epoch, CANDIDATE)
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
                # Compile and verify the sender binary by fixed cross-build
                # receipt hash. This check precedes output/run-dir creation.
                sender_build = sender_receipt(account.pw_uid)
                hashes = runtime_tool_hashes()
                if hashes.get(str(SENDER_BINARY.relative_to(REPO))) != SENDER_SHA256:
                    raise ControlledRunError("SENDER_BINARY_RUNTIME_PIN_MISMATCH")
            except Exception as error:
                if isinstance(error, ControlledRunError):
                    raise
                raise ControlledRunError("TEST099_PRE_RUN_GATE_FAILED") from error

            restore_barrier = START_BARRIER.install_native_armed_go_barrier(
                BASE, reader=reader, build=CANDIDATE,
                minimum_remaining_us=MINIMUM_REMAINING_US)
            restore_go = install_go_deadline_guard()
            old_run_dir = TEST088._new_run_dir
            TEST088._new_run_dir = test099_run_dir
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

            report.update({
                "schema": "test099-tools-controlled-run-private/v1",
                "tool_revision": "Test099",
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
        restore_profile()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="Run one Test099 candidate-bound RX149 capture")
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--ap", help="explicit live AP interface, prepared profile wlan7")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps(plan(args.metadata), sort_keys=True))
        return 0
    if not args.host or not args.control_path or not args.ap:
        print("ERROR: ROUTER_TRANSPORT_AND_AP_REQUIRED", file=sys.stderr)
        return 2
    try:
        report, output_dir, _prearm = run_once(
            host=args.host, control_path=args.control_path,
            metadata_path=args.metadata, ap=args.ap)
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
