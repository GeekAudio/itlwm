#!/usr/bin/env python3
"""Run a bounded sequence of independent passive OpenWrt capture windows.

The default is a plan-only dry run. Live capture requires --capture and an
already authenticated OpenSSH ControlMaster socket accepted by the existing
single-window helper. No shell is used to construct or launch commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import openwrt_capture_once as once


SCHEMA_VERSION = 1
MAX_WINDOWS = 8
MAX_INTERVAL_SECONDS = 30
DEFAULT_WINDOWS = 3
DEFAULT_INTERVAL_SECONDS = 2
DEFAULT_TOTAL_BUDGET_SECONDS = 240
MAX_TOTAL_BUDGET_SECONDS = 600
# The helper has its own duration + setup + cleanup deadline. Allow a small
# scheduling margin, then bounded SIGINT/SIGTERM/SIGKILL cleanup stages.
OUTER_TIMEOUT_MARGIN_SECONDS = 2
SIGINT_GRACE_SECONDS = 8
SIGTERM_GRACE_SECONDS = 2
SIGKILL_REAP_SECONDS = 2
SAFE_ID_RE = re.compile(r"^[0-9a-f]{8}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BatchError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class WindowOutcome:
    returncode: int
    stdout: bytes
    timed_out: bool = False


def window_deadline_seconds(duration: int) -> int:
    return (duration + once.LOCAL_SETUP_MARGIN_SECONDS
            + once.LOCAL_CLEANUP_MARGIN_SECONDS
            + OUTER_TIMEOUT_MARGIN_SECONDS + SIGINT_GRACE_SECONDS
            + SIGTERM_GRACE_SECONDS + SIGKILL_REAP_SECONDS)


def validate_batch_limits(windows: int, duration: int, interval: int,
                          total_budget: int, packets: int) -> int:
    if not 1 <= windows <= MAX_WINDOWS:
        raise BatchError("WINDOW_COUNT_OUT_OF_RANGE")
    try:
        once.validate_capture_limits(duration, packets)
    except once.CaptureError as exc:
        raise BatchError(exc.code) from exc
    if not 0 <= interval <= MAX_INTERVAL_SECONDS:
        raise BatchError("INTERVAL_OUT_OF_RANGE")
    if not 30 <= total_budget <= MAX_TOTAL_BUDGET_SECONDS:
        raise BatchError("TOTAL_BUDGET_OUT_OF_RANGE")
    required = windows * window_deadline_seconds(duration) + (windows - 1) * interval
    if required > total_budget:
        raise BatchError("TOTAL_BUDGET_TOO_SMALL")
    return required


def validate_capture_inputs(args: argparse.Namespace,
                            check_socket: bool = True) -> List[once.ExpectedAP]:
    once.validate_host(args.host)
    once.build_ssh_argv(args.host, args.control_path)
    ap_interfaces = [once.validate_interface(item) for item in args.ap]
    if (not ap_interfaces or len(ap_interfaces) > 4
            or len(set(ap_interfaces)) != len(ap_interfaces)):
        raise BatchError("INVALID_AP_SET")
    selected = once.validate_interface(args.interface or ap_interfaces[0])
    once.validate_interface(args.monitor)
    if selected not in ap_interfaces:
        raise BatchError("SELECTED_INTERFACE_NOT_IN_AP_SET")
    expected = [once.parse_expected_ap(item) for item in args.expect_ap]
    if {item.interface for item in expected} != set(ap_interfaces):
        raise BatchError("CAPTURE_REQUIRES_EXPECTATIONS_FOR_ALL_APS")
    if check_socket:
        once.validate_control_socket(args.control_path)
    return expected


def make_child_argv(args: argparse.Namespace, output_file: Path) -> List[str]:
    argv = [
        sys.executable,
        str(Path(once.__file__).resolve()),
        "--host", args.host,
        "--control-path", args.control_path,
    ]
    for item in args.ap:
        argv.extend(("--ap", item))
    for item in args.expect_ap:
        argv.extend(("--expect-ap", item))
    argv.extend((
        "--interface", args.interface or args.ap[0],
        "--monitor", args.monitor,
        "--capture",
        "--output", str(output_file),
        "--duration", str(args.duration),
        "--max-packets", str(args.max_packets),
    ))
    return argv


def _signal_process(proc: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (AttributeError, ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except OSError:
            pass


def _stop_and_reap(proc: subprocess.Popen[bytes],
                   initial_output: bytes = b"") -> bytes:
    """Boundedly signal the helper process group and drain/reap its child."""
    partial = initial_output
    if proc.poll() is not None:
        try:
            output, _ = proc.communicate(timeout=SIGKILL_REAP_SECONDS)
            return output or partial
        except (subprocess.TimeoutExpired, OSError):
            return partial

    for sig, grace in ((signal.SIGINT, SIGINT_GRACE_SECONDS),
                       (signal.SIGTERM, SIGTERM_GRACE_SECONDS),
                       (signal.SIGKILL, SIGKILL_REAP_SECONDS)):
        _signal_process(proc, sig)
        try:
            output, _ = proc.communicate(timeout=grace)
            return output or partial
        except subprocess.TimeoutExpired as exc:
            partial = exc.output or partial
        except OSError:
            # Continue to a stronger signal if draining a closed/broken pipe
            # fails; the next stage still targets the process group.
            continue
        except BaseException:
            # A second interruption must not strand the helper. Continue the
            # bounded escalation; the caller re-raises the original exception.
            continue
    return partial


def run_child(argv: Sequence[str], timeout_seconds: int) -> WindowOutcome:
    """Run one helper within a total budget that includes shutdown grace."""
    cleanup_budget = (SIGINT_GRACE_SECONDS + SIGTERM_GRACE_SECONDS
                      + SIGKILL_REAP_SECONDS)
    initial_wait = timeout_seconds - cleanup_budget
    if initial_wait < 1:
        raise BatchError("WINDOW_BUDGET_TOO_SMALL")
    try:
        proc = subprocess.Popen(
            list(argv), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise BatchError("HELPER_START_FAILED") from exc

    try:
        # Reserve cleanup_budget before waiting: communicate() may consume
        # only the non-cleanup portion of timeout_seconds.
        stdout, _ = proc.communicate(timeout=initial_wait)
        return WindowOutcome(proc.returncode or 0, stdout)
    except subprocess.TimeoutExpired as exc:
        stdout = _stop_and_reap(proc, exc.output or b"")
        return WindowOutcome(proc.returncode if proc.returncode is not None
                             else -signal.SIGKILL, stdout, timed_out=True)
    except BaseException:
        # Includes KeyboardInterrupt and unexpected communicate errors. The
        # helper owns remote monitor restoration; give it the chance to send
        # CANCEL and finish cleanup before escalating its local process group.
        _stop_and_reap(proc)
        raise


def parse_helper_json(stdout: bytes) -> Optional[Dict[str, object]]:
    for raw in reversed(stdout.splitlines()):
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def validate_helper_success(summary: Optional[Dict[str, object]],
                            expected: Sequence[once.ExpectedAP],
                            pcap_path: Path, packet_limit: int) -> Optional[str]:
    """Recheck the helper's success, cleanup, AP state, and local PCAP receipt."""
    if not summary or summary.get("schema_version") != 1 or summary.get("mode") != "capture":
        return "HELPER_SUMMARY_MISSING"
    if summary.get("state_unchanged") is not True:
        return "AP_OR_UCI_STATE_CHANGED"
    if type(summary.get("tcpdump_exit_code")) is not int or summary["tcpdump_exit_code"] != 0:
        return "TCPDUMP_FAILED"
    if summary.get("monitor_removed") is not True:
        return "MONITOR_CLEANUP_UNCONFIRMED"
    before, after = summary.get("ap_before"), summary.get("ap_after")
    if not isinstance(before, dict) or not isinstance(after, dict) or before != after:
        return "AP_SNAPSHOT_MISMATCH"
    if set(before) != {item.interface for item in expected}:
        return "AP_SNAPSHOT_INCOMPLETE"
    for item in expected:
        observed = before.get(item.interface)
        if not isinstance(observed, dict):
            return "AP_EXPECTATION_MISMATCH"
        if (observed.get("phy"), observed.get("channel"),
                observed.get("frequency_mhz"), observed.get("width_mhz")) != (
                item.phy, item.channel, item.frequency_mhz, item.width_mhz):
            return "AP_EXPECTATION_MISMATCH"
    before_hash, after_hash = (summary.get("uci_sha256_before"),
                               summary.get("uci_sha256_after"))
    if (not isinstance(before_hash, str) or not isinstance(after_hash, str)
            or not SHA256_RE.fullmatch(before_hash)
            or not SHA256_RE.fullmatch(after_hash) or before_hash != after_hash):
        return "UCI_STATE_MISMATCH"
    if summary.get("cancelled") is True:
        return "CAPTURE_CANCELLED"
    pcap_hash = summary.get("pcap_sha256")
    if not isinstance(pcap_hash, str) or not SHA256_RE.fullmatch(pcap_hash):
        return "PCAP_HASH_MISSING"
    if not pcap_path.is_file():
        return "PCAP_MISSING"
    try:
        size = pcap_path.stat().st_size
        with pcap_path.open("rb") as handle:
            magic = handle.read(4)
        actual_hash = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    except OSError:
        return "PCAP_READ_FAILED"
    max_bytes = 24 + packet_limit * (16 + once.SNAPLEN_BYTES)
    if size < 24 or size > max_bytes or size != summary.get("pcap_bytes"):
        return "PCAP_SIZE_INVALID"
    if magic not in once.PCAP_MAGICS or actual_hash != pcap_hash:
        return "PCAP_CONTENT_MISMATCH"
    return None


def _write_json_exclusive(path: Path, value: Dict[str, object]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def create_batch_directory(output_parent: Path) -> Tuple[Path, str]:
    try:
        parent = output_parent.expanduser().resolve(strict=True)
    except OSError as exc:
        raise BatchError("OUTPUT_PARENT_UNAVAILABLE") from exc
    if not parent.is_dir():
        raise BatchError("OUTPUT_PARENT_UNAVAILABLE")
    for _ in range(8):
        batch_id = uuid.uuid4().hex[:8]
        if not SAFE_ID_RE.fullmatch(batch_id):
            continue
        path = parent / ("openwrt-capture-batch-" + batch_id)
        try:
            path.mkdir(mode=0o700, exist_ok=False)
            return path, batch_id
        except FileExistsError:
            continue
        except OSError as exc:
            raise BatchError("OUTPUT_CREATE_FAILED") from exc
    raise BatchError("OUTPUT_CREATE_FAILED")


def validate_window_dir(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=False)


def run_batch(args: argparse.Namespace,
              executor: Callable[[Sequence[str], int], WindowOutcome] = run_child,
              clock: Callable[[], float] = time.monotonic,
              sleeper: Callable[[float], None] = time.sleep) -> Dict[str, object]:
    required_budget = validate_batch_limits(
        args.windows, args.duration, args.interval, args.total_budget,
        args.max_packets,
    )
    expected = validate_capture_inputs(args)
    output_parent = Path(args.output_dir)
    batch_dir, batch_id = create_batch_directory(output_parent)
    started = clock()
    deadline = started + args.total_budget
    windows: List[Dict[str, object]] = []
    overall_error: Optional[str] = None

    for index in range(1, args.windows + 1):
        full_window_budget = window_deadline_seconds(args.duration)
        if deadline - clock() < full_window_budget:
            overall_error = "TOTAL_BUDGET_INSUFFICIENT_FOR_WINDOW"
            break
        window_dir = batch_dir / ("window-%02d" % index)
        try:
            validate_window_dir(window_dir)
        except OSError:
            overall_error = "WINDOW_OUTPUT_CREATE_FAILED"
            break
        pcap_path = window_dir / "capture.pcap"
        child_argv = make_child_argv(args, pcap_path)
        remaining = deadline - clock()
        if remaining < full_window_budget:
            not_started: Dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "window": index,
                "status": "not_started",
                "duration_limit_seconds": args.duration,
                "packet_limit": args.max_packets,
                "elapsed_seconds": 0.0,
                "helper_exit_code": None,
                "error": "TOTAL_BUDGET_INSUFFICIENT_FOR_WINDOW",
                "pcap_file": None,
                "helper_result_file": None,
            }
            try:
                _write_json_exclusive(window_dir / "window.json", not_started)
            except OSError:
                pass
            windows.append(not_started)
            overall_error = "TOTAL_BUDGET_INSUFFICIENT_FOR_WINDOW"
            break
        timeout = full_window_budget
        window_started = clock()
        try:
            outcome = executor(child_argv, timeout)
        except BatchError as exc:
            outcome = WindowOutcome(127, b"")
            error = exc.code
        else:
            error = None
        helper_summary = parse_helper_json(outcome.stdout)
        if helper_summary is not None:
            try:
                _write_json_exclusive(window_dir / "helper-result.json", helper_summary)
            except OSError:
                error = error or "WINDOW_REPORT_WRITE_FAILED"
        if outcome.timed_out:
            error = error or "WINDOW_TIMEOUT"
        if outcome.returncode != 0:
            helper_error = helper_summary.get("error") if helper_summary else None
            error = error or (helper_error if isinstance(helper_error, str)
                              else "HELPER_EXIT_%d" % outcome.returncode)
        if error is None:
            error = validate_helper_success(helper_summary, expected, pcap_path,
                                            args.max_packets)
        elapsed = max(0.0, clock() - window_started)
        if elapsed > timeout:
            error = error or "WINDOW_TIMEOUT"
        window_receipt: Dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "window": index,
            "status": "passed" if error is None else "failed",
            "duration_limit_seconds": args.duration,
            "packet_limit": args.max_packets,
            "elapsed_seconds": round(elapsed, 3),
            "helper_exit_code": outcome.returncode,
            "error": error,
            "pcap_file": "capture.pcap" if pcap_path.exists() else None,
            "helper_result_file": "helper-result.json" if helper_summary else None,
        }
        try:
            _write_json_exclusive(window_dir / "window.json", window_receipt)
        except OSError:
            error = error or "WINDOW_REPORT_WRITE_FAILED"
            window_receipt["status"] = "failed"
            window_receipt["error"] = error
        windows.append(window_receipt)

        if error is not None:
            overall_error = error
            break
        if clock() > deadline:
            overall_error = "TOTAL_BUDGET_EXHAUSTED"
            break
        if index < args.windows:
            delay = args.interval
            if deadline - (clock() + delay) < full_window_budget:
                overall_error = "TOTAL_BUDGET_INSUFFICIENT_FOR_WINDOW"
                break
            if delay:
                sleeper(delay)

    success = len(windows) == args.windows and overall_error is None
    receipt: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "mode": "capture_batch",
        "batch_id": batch_id,
        "status": "passed" if success else "failed",
        "requested_windows": args.windows,
        "completed_windows": len(windows),
        "duration_limit_seconds": args.duration,
        "interval_seconds": args.interval,
        "max_packets_per_window": args.max_packets,
        "total_budget_seconds": args.total_budget,
        "planned_worst_case_seconds": required_budget,
        "elapsed_seconds": round(max(0.0, clock() - started), 3),
        "error": overall_error,
        "output_directory": str(batch_dir),
        "windows": windows,
    }
    try:
        _write_json_exclusive(batch_dir / "batch.json", receipt)
    except OSError:
        receipt["status"] = "failed"
        receipt["error"] = "BATCH_REPORT_WRITE_FAILED"
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bounded sequence of independent passive OpenWrt captures")
    parser.add_argument("--host", required=True,
                        help="SSH target already owned by the supplied ControlMaster")
    parser.add_argument("--control-path", required=True,
                        help="Existing authenticated OpenSSH ControlMaster socket")
    parser.add_argument("--ap", action="append", required=True,
                        help="AP interface to snapshot; repeat for each AP")
    parser.add_argument("--expect-ap", action="append", default=[],
                        metavar="IFACE:PHY:CHANNEL:FREQ:WIDTH")
    parser.add_argument("--interface", help="AP interface used for passive capture")
    parser.add_argument("--monitor", default="awdlmon0")
    parser.add_argument("--windows", type=int, default=DEFAULT_WINDOWS,
                        help="Independent windows (1 through 8; default 3)")
    parser.add_argument("--duration", type=int, default=once.DEFAULT_DURATION_SECONDS,
                        help="Seconds per window (12 through 20)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
                        help="Seconds between windows (0 through 30)")
    parser.add_argument("--total-budget", type=int,
                        default=DEFAULT_TOTAL_BUDGET_SECONDS,
                        help="Hard cumulative budget in seconds (30 through 600)")
    parser.add_argument("--max-packets", type=int, default=once.DEFAULT_PACKET_LIMIT,
                        help="Hard packet cap for each window (maximum 4096)")
    parser.add_argument("--output-dir", required=True,
                        help="Existing parent for a new private batch directory")
    parser.add_argument("--capture", action="store_true",
                        help="Explicitly run passive captures; default is plan-only")
    return parser


def _raise_interrupted_from_sigterm(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        required = validate_batch_limits(
            args.windows, args.duration, args.interval, args.total_budget,
            args.max_packets,
        )
        # Validate syntax on both paths, but inspect the socket and create files
        # only after the user explicitly requests live captures.
        once.validate_host(args.host)
        once.build_ssh_argv(args.host, args.control_path)
        if not args.capture:
            validate_capture_inputs(args, check_socket=False)
            plan_id = uuid.uuid4().hex[:8]
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "mode": "dry_run",
                "status": "planned",
                "windows": args.windows,
                "duration_limit_seconds": args.duration,
                "interval_seconds": args.interval,
                "total_budget_seconds": args.total_budget,
                "planned_worst_case_seconds": required,
                "would_create": str(Path(args.output_dir).expanduser()
                                     / ("openwrt-capture-batch-" + plan_id)),
                "will_start_subprocess": False,
            }, sort_keys=True, separators=(",", ":")))
            return 0
        previous_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _raise_interrupted_from_sigterm)
        try:
            receipt = run_batch(args)
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")))
        return 0 if receipt["status"] == "passed" else 2
    except (BatchError, once.CaptureError) as exc:
        code = exc.code if hasattr(exc, "code") else "INVALID_ARGUMENT"
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "failed",
                          "error": code}, sort_keys=True, separators=(",", ":")))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "interrupted",
                          "error": "INTERRUPTED"}, sort_keys=True, separators=(",", ":")))
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
