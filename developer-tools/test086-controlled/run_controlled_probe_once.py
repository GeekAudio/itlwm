#!/usr/bin/env python3
"""Fail-closed OpenWrt readiness probe for a future Test086 controlled run.

Default invocation is a local plan. ``--readiness-only`` opens a temporary
channel-149 monitor on the router, waits for the AF_PACKET sender's READY,
then sends ABORT and verifies zero sends plus cleanup. It never touches the
Intel kext, system metadata, boot claim, listener, or native RF controls.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

import test086_controlled as protocol


ROOT = Path(__file__).resolve().parents[2]
MAX_REMOTE_SCRIPT_BYTES = 3 * 1024 * 1024
MAX_LINE_BYTES = 16384
# Separate startup/readiness from the sender's own post-READY GO gate. The C
# sender starts its 30 s gate just before printing READY. After that gate, allow
# its existing 2 s TX budget plus a small bounded result/remote-cleanup grace.
READINESS_TIMEOUT_SECONDS = 24.0
SENDER_GO_TIMEOUT_SECONDS = 30.0
SENDER_TX_BUDGET_SECONDS = 2.0
SENDER_RESULT_CLEANUP_GRACE_SECONDS = 3.0
SENDER_POST_READY_TIMEOUT_SECONDS = (
    SENDER_GO_TIMEOUT_SECONDS + SENDER_TX_BUDGET_SECONDS +
    SENDER_RESULT_CLEANUP_GRACE_SECONDS)
HOST_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,255}$")


def load_openwrt_transport():
    path = ROOT / "developer-tools/test086/tools/openwrt_capture_once.py"
    module_name = "test086_openwrt_transport"
    current = sys.modules.get(module_name)
    if current is not None:
        return current
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise protocol.ControlledProbeError("SSH_TRANSPORT_HELPER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    # dataclasses (used by the helper) resolve annotations through
    # sys.modules[cls.__module__] while the module body is executing.
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        raise
    return module


def validate_transport(host: str, control_path: str) -> List[str]:
    if not HOST_RE.fullmatch(host) or host.startswith("-"):
        raise protocol.ControlledProbeError("INVALID_HOST")
    if not os.path.isabs(control_path) or "\n" in control_path:
        raise protocol.ControlledProbeError("INVALID_CONTROL_PATH")
    info = os.lstat(control_path)
    try:
        workspace_uid = ROOT.stat().st_uid
    except OSError:
        raise protocol.ControlledProbeError("WORKSPACE_OWNER_UNAVAILABLE")
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != workspace_uid or
            stat.S_ISLNK(info.st_mode)):
        raise protocol.ControlledProbeError("UNSAFE_CONTROL_SOCKET")
    transport = load_openwrt_transport()
    argv = transport.build_ssh_argv(host, control_path)
    if not argv or argv[0] != "ssh":
        raise protocol.ControlledProbeError("SSH_TRANSPORT_INVALID")
    return argv


def build_bootstrap_argv(host: str, control_path: str) -> List[str]:
    # openwrt_capture_once.py uses the same one-line base64 bootstrap.
    return validate_transport(host, control_path)


def remote_script_bytes(script: str) -> bytes:
    raw = script.encode("utf-8")
    if not raw or len(raw) > MAX_REMOTE_SCRIPT_BYTES:
        raise protocol.ControlledProbeError("REMOTE_SCRIPT_SIZE_INVALID")
    return base64.b64encode(raw) + b"\n"


def _terminate_process(process: subprocess.Popen, timeout: float = 1.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass


def _read_protocol_line(selector: selectors.BaseSelector, process: subprocess.Popen,
                        state: Dict[str, Any], deadline: float) -> Optional[str]:
    while time.monotonic() < deadline:
        # stdout can deliver several protocol records in one read. Drain the
        # buffered next line before checking EOF/selector readiness, otherwise
        # a child that exits after writing multiple lines can lose its tail.
        if b"\n" in state["buffer"]:
            raw, state["buffer"] = state["buffer"].split(b"\n", 1)
            if len(raw) > MAX_LINE_BYTES:
                raise protocol.ControlledProbeError("REMOTE_PROTOCOL_LINE_OVERSIZE")
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise protocol.ControlledProbeError("REMOTE_PROTOCOL_ENCODING_INVALID")
        # The SSH process may exit after writing protocol lines that remain
        # queued in its stdout pipe. Drain the descriptor through EOF instead
        # of treating poll() as proof that no terminal record is pending.
        events = selector.select(min(0.25, max(0.0, deadline - time.monotonic())))
        if not events:
            continue
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            return None
        state["buffer"] += chunk
        if len(state["buffer"]) > MAX_LINE_BYTES and b"\n" not in state["buffer"]:
            raise protocol.ControlledProbeError("REMOTE_PROTOCOL_LINE_OVERSIZE")
    raise protocol.ControlledProbeError("REMOTE_PROTOCOL_TIMEOUT")


class RouterSenderSession:
    """One-use router sender session; supports exactly one GO or ABORT."""

    def __init__(self, process: subprocess.Popen, selector: selectors.BaseSelector,
                 read_state: Dict[str, Any], deadline: float, run_token: str,
                 sender_sha256: str):
        self.process = process
        self.selector = selector
        self.read_state = read_state
        self.deadline = deadline
        self.run_token = run_token
        self.sender_sha256 = sender_sha256
        self.ready = True
        self.control_consumed = False
        self.closed = False
        self.protocol_evidence: Dict[str, Any] = {}

    @classmethod
    def start(cls, *, host: str, control_path: str, sender_binary: Path,
              sender_sha256: str, run_token: Optional[str] = None,
              ap: str = "wlan1"):
        protocol.validate_ap_interface(ap)
        if not protocol.SHA_RE.fullmatch(sender_sha256):
            raise protocol.ControlledProbeError("INVALID_SENDER_SHA256")
        sender_binary = Path(sender_binary)
        if sender_binary.is_symlink() or not sender_binary.is_file():
            raise protocol.ControlledProbeError("SENDER_BINARY_UNAVAILABLE")
        binary = sender_binary.read_bytes()
        actual_sha = hashlib.sha256(binary).hexdigest()
        if actual_sha != sender_sha256:
            raise protocol.ControlledProbeError("SENDER_BINARY_HASH_MISMATCH")
        token = run_token or __import__("secrets").token_hex(16)
        if not protocol.TOKEN_RE.fullmatch(token):
            raise protocol.ControlledProbeError("INVALID_RUN_TOKEN")
        script = protocol.build_remote_monitor_sender_script(
            binary=binary, binary_sha256=actual_sha, run_token=token, ap=ap)
        argv = build_bootstrap_argv(host, control_path)
        if len(script.encode("utf-8")) > MAX_REMOTE_SCRIPT_BYTES:
            raise protocol.ControlledProbeError("REMOTE_SCRIPT_SIZE_INVALID")
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        readiness_deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
        state: Dict[str, Any] = {"buffer": b""}
        try:
            assert process.stdin is not None
            process.stdin.write(remote_script_bytes(script))
            process.stdin.flush()
            monitor_line = _read_protocol_line(
                selector, process, state, readiness_deadline)
            if monitor_line is None:
                raise protocol.ControlledProbeError("ROUTER_READINESS_SETUP_FAILED")
            if monitor_line.startswith("REMOTE_ERROR "):
                match = re.fullmatch(r"REMOTE_ERROR code=([a-z0-9_]+)", monitor_line)
                remote_error = match.group(1) if match else "unknown"
                cleanup_line = _read_protocol_line(
                    selector, process, state, readiness_deadline)
                cleanup = None
                if cleanup_line and cleanup_line.startswith("CLEANUP "):
                    cleanup = protocol.parse_cleanup(cleanup_line, run_token=token)
                try:
                    exit_code = process.wait(timeout=max(
                        0.0, readiness_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    exit_code = None
                evidence = {"remote_error_code": remote_error,
                            "cleanup": cleanup, "ssh_exit_code": exit_code}
                raise protocol.ControlledProbeError(
                    "ROUTER_READINESS_SETUP_FAILED", evidence=evidence)
            monitor_ready = protocol.parse_monitor_ready(monitor_line)
            ready_line = _read_protocol_line(
                selector, process, state, readiness_deadline)
            if ready_line is None:
                raise protocol.ControlledProbeError("SENDER_READY_MISSING")
            if ready_line.startswith("REMOTE_ERROR "):
                match = re.fullmatch(r"REMOTE_ERROR code=([a-z0-9_]+)", ready_line)
                remote_error = match.group(1) if match else "unknown"
                cleanup_line = _read_protocol_line(
                    selector, process, state, readiness_deadline)
                cleanup = None
                if cleanup_line and cleanup_line.startswith("CLEANUP "):
                    cleanup = protocol.parse_cleanup(cleanup_line, run_token=token)
                try:
                    exit_code = process.wait(timeout=max(
                        0.0, readiness_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    exit_code = None
                raise protocol.ControlledProbeError(
                    "ROUTER_SENDER_SETUP_FAILED",
                    evidence={"monitor_ready": monitor_ready,
                              "remote_error_code": remote_error,
                              "cleanup": cleanup, "ssh_exit_code": exit_code})
            ready = protocol.parse_sender_ready(ready_line)
            # The 24 s readiness budget ends at sender READY. Give the sender
            # its declared 30 s GO gate, then its unchanged 2 s TX budget and
            # a bounded 3 s for result/monitor cleanup to reach this process.
            sender_deadline = time.monotonic() + SENDER_POST_READY_TIMEOUT_SECONDS
            session = cls(process, selector, state, sender_deadline, token, actual_sha)
            session.protocol_evidence["monitor_ready"] = monitor_ready
            session.protocol_evidence["sender_ready"] = ready
            return session, monitor_ready, ready
        except Exception:
            selector.close()
            _terminate_process(process)
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
            raise

    def finish(self, control: str, *, on_control_write=None) -> Dict[str, Any]:
        if self.closed or self.control_consumed:
            raise protocol.ControlledProbeError("SENDER_CONTROL_ALREADY_CONSUMED")
        if control not in {"ABORT", "GO"}:
            raise protocol.ControlledProbeError("SENDER_CONTROL_INVALID")
        self.control_consumed = True
        try:
            assert self.process.stdin is not None
            tokenized = "ABORT\n" if control == "ABORT" else "GO " + self.run_token + "\n"
            if on_control_write is not None:
                on_control_write("BEGIN")
            self.process.stdin.write(tokenized.encode("ascii"))
            self.process.stdin.flush()
            if on_control_write is not None:
                on_control_write("END")
            result_line = _read_protocol_line(
                self.selector, self.process, self.read_state, self.deadline)
            if result_line is None:
                raise protocol.ControlledProbeError("SENDER_RESULT_MISSING")
            result = protocol.parse_sender_result(result_line)
            self.protocol_evidence["sender_result"] = result
            if control == "ABORT" and (result.get("status") != "aborted" or
                                         not protocol.validate_readiness_abort(result)):
                raise protocol.ControlledProbeError("READINESS_ABORT_NOT_ZERO_SEND")
            cleanup_line = _read_protocol_line(
                self.selector, self.process, self.read_state, self.deadline)
            if cleanup_line is None:
                raise protocol.ControlledProbeError("REMOTE_CLEANUP_MISSING")
            cleanup = protocol.parse_cleanup(cleanup_line, run_token=self.run_token)
            self.protocol_evidence["cleanup"] = cleanup
            if not all(cleanup[key] for key in
                       ("monitor_removed", "ap_unchanged", "temporary_files_removed")):
                raise protocol.ControlledProbeError("REMOTE_CLEANUP_NOT_VERIFIED")
            remaining = max(0.0, self.deadline - time.monotonic())
            try:
                exit_code = self.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise protocol.ControlledProbeError("SSH_EXIT_TIMEOUT")
            self.closed = True
            self.protocol_evidence["ssh_exit_code"] = exit_code
            if control == "ABORT" and exit_code != 0:
                raise protocol.ControlledProbeError("SSH_REMOTE_EXIT_NONZERO")
            if control == "GO":
                if result["status"] == "complete" and exit_code != 0:
                    raise protocol.ControlledProbeError("SENDER_EXIT_STATUS_MISMATCH")
                if result["status"] == "failed" and exit_code == 0:
                    raise protocol.ControlledProbeError("SENDER_EXIT_STATUS_MISMATCH")
                if result["status"] != "complete" and result["status"] != "failed":
                    raise protocol.ControlledProbeError("SENDER_GO_RESULT_STATUS_INVALID")
            return {"sender_result": result, "cleanup": cleanup,
                    "remote_exit_code": exit_code,
                    "local_send_is_not_rf_proof": True}
        except Exception:
            _terminate_process(self.process)
            raise
        finally:
            self.selector.close()
            self.closed = True
            if self.process.stdin is not None:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
            if self.process.stdout is not None:
                try:
                    self.process.stdout.close()
                except OSError:
                    pass

    def abort(self) -> Dict[str, Any]:
        return self.finish("ABORT")

    def go_once(self, *, on_control_write=None) -> Dict[str, Any]:
        return self.finish("GO", on_control_write=on_control_write)


def run_readiness_only(*, host: str, control_path: str, sender_binary: Path,
                       sender_sha256: str, ap: str = "wlan1") -> Dict[str, Any]:
    session = None
    records: Dict[str, Any] = {
        "schema": "test086-controlled-readiness-private/v1",
        "source_ready_kind": "controlled_probe",
        "mode": "readiness_only",
        "run_token": None,
        "sender_binary_sha256": sender_sha256,
        "sender_ready": False,
        "abort_sent": False,
        "sender_result": None,
        "cleanup": None,
        "transmit_started": False,
        "local_send_calls": 0,
        "native_arm_started": False,
        "boot_claim_touched": False,
        "metadata_touched": False,
        "efi_touched": False,
        "success": False,
    }
    try:
        session, monitor_ready, ready = RouterSenderSession.start(
            host=host, control_path=control_path, sender_binary=sender_binary,
            sender_sha256=sender_sha256, ap=ap)
        records["run_token"] = session.run_token
        records["sender_ready"] = True
        records["monitor_ready"] = monitor_ready
        records["sender_contract"] = ready
        # This code path intentionally has no GO operation. The only command
        # sent to the remote sender is the pre-GO ABORT token.
        records["abort_sent"] = True
        records.update(session.abort())
        records["ssh_exit_code"] = records.pop("remote_exit_code")
        records["evidence_limit"] = (
            "READY confirms the AF_PACKET socket bound to the temporary monitor; "
            "ABORT and zero counters prove this tool made no sender send() call. "
            "This is not an RF-delivery test."
        )
        records["success"] = True
        return records
    except protocol.ControlledProbeError as exc:
        records["success"] = False
        records["error_code"] = exc.code
        records["protocol_evidence"] = dict(
            getattr(session, "protocol_evidence", {}) if session is not None else {})
        records["protocol_evidence"].update(exc.evidence)
        exc.evidence = records
        if session is not None and not session.control_consumed:
            try:
                session.abort()
            except Exception:
                _terminate_process(session.process)
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        records["success"] = False
        records["error_code"] = "LOCAL_OR_SSH_OPERATION_FAILED"
        records["error_type"] = type(exc).__name__
        records["protocol_evidence"] = dict(
            getattr(session, "protocol_evidence", {}) if session is not None else {})
        wrapped = protocol.ControlledProbeError(
            "LOCAL_OR_SSH_OPERATION_FAILED", evidence=records)
        if session is not None and not session.control_consumed:
            try:
                session.abort()
            except Exception:
                _terminate_process(session.process)
        raise wrapped from exc
    except Exception:
        if session is not None and not session.control_consumed:
            try:
                session.abort()
            except Exception:
                _terminate_process(session.process)
        raise


def _prepare_private_parent(path: Path) -> None:
    parent = path.parent
    if parent.is_symlink():
        raise protocol.ControlledProbeError("REFUSE_SYMLINK_REPORT_PARENT")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise protocol.ControlledProbeError("UNSAFE_PRIVATE_REPORT_PARENT")


def _save_failure_report(path: Path, code: str,
                         evidence: Optional[Dict[str, Any]] = None) -> None:
    if path.exists() or path.is_symlink():
        return
    protocol.private_atomic_write(path, {
        "schema": "test086-controlled-readiness-private/v1",
        "source_ready_kind": "controlled_probe",
        "mode": "readiness_only",
        "success": False,
        "error_code": code,
        "evidence": evidence or {},
        "transmit_started": False,
        "local_send_calls": 0,
    })


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness-only", action="store_true",
                        help="Open monitor and sender, then ABORT before GO; no native or RF action")
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--sender-binary", type=Path)
    parser.add_argument("--sender-sha256")
    parser.add_argument("--ap", default="wlan1",
                        help="live OpenWrt AP interface (default: wlan1)")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        protocol.validate_ap_interface(args.ap)
    except protocol.ControlledProbeError as exc:
        print("ERROR: " + exc.code, file=sys.stderr)
        return 2
    if not args.readiness_only:
        print(json.dumps({
            "mode": "plan",
            "candidate": protocol.BUILD,
            "source_ready_kind": protocol.SOURCE_KIND,
            "readiness_only_supported": True,
            "full_run_supported": False,
            "note": "No native arm, boot claim, listener, or RF operation is performed by default.",
        }, sort_keys=True))
        return 0
    if not all((args.host, args.control_path, args.sender_binary, args.sender_sha256, args.report)):
        print("ERROR: READINESS_ARGUMENTS_REQUIRED", file=sys.stderr)
        return 2
    report_prepared = False
    try:
        if not args.report.is_absolute():
            raise protocol.ControlledProbeError("REPORT_PATH_MUST_BE_ABSOLUTE")
        if args.report.exists() or args.report.is_symlink():
            raise protocol.ControlledProbeError("REFUSE_EXISTING_REPORT")
        _prepare_private_parent(args.report)
        report_prepared = True
        result = run_readiness_only(
            host=args.host, control_path=args.control_path,
            sender_binary=args.sender_binary, sender_sha256=args.sender_sha256,
            ap=args.ap)
        protocol.private_atomic_write(args.report, result)
        print("READINESS_ONLY_OK")
        return 0
    except protocol.ControlledProbeError as exc:
        code = exc.code
        if report_prepared:
            try:
                _save_failure_report(args.report, code, exc.evidence)
            except Exception:
                pass
    except (OSError, subprocess.SubprocessError):
        code = "LOCAL_OR_SSH_OPERATION_FAILED"
        if report_prepared:
            try:
                _save_failure_report(args.report, code)
            except Exception:
                pass
    print("ERROR: " + code, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
