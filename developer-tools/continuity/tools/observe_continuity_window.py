#!/usr/bin/env python3
"""Bounded passive host capture for Instant Hotspot/AirDrop windows.

The default is disarmed; no system command runs without --capture. Raw unified
logs and Bluetooth profiler JSON stay in a new private directory under
research/. The tool records host state only and does not infer hotspot or
transfer success. actions.jsonl is a private manual record, one JSON object
per line, for example:
  {"utc":"...Z","action":"instant-hotspot","result":"failure"}
  {"utc":"...Z","action":"airdrop-mac-to-iphone","result":"success"}
  {"utc":"...Z","action":"airdrop-iphone-to-mac","result":"unknown"}
Use result success/failure/unknown; do not include names, addresses, SSIDs,
passwords, transfer contents, or free-form notes.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Optional, Sequence, Tuple


TOOL_ID = "org.geekaudio.observe-continuity-window"
SCHEMA = 1
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = PROJECT_ROOT / "research"
MIN_SECONDS = 15
MAX_SECONDS = 120
DEFAULT_SECONDS = 60
IFCONFIG_TIMEOUT = 2.0
BT_TIMEOUT = 5.0
END_RESERVE_NS = 7_000_000_000
TERMINATE_GRACE = 2.0
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
LOG_PROCESSES = ("sharingd", "rapportd", "bluetoothd", "wifip2pd", "airportd", "wifid")
LOG_PREDICATE = " OR ".join('process == "{}"'.format(item) for item in LOG_PROCESSES)


class InputError(Exception):
    pass


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def monotonic_ns() -> int:
    return time.monotonic_ns()


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def validate_interface(value: str) -> str:
    if not INTERFACE_RE.fullmatch(value):
        raise InputError("invalid interface name")
    return value


def prepare_output_dir(value: str, research: Optional[Path] = None) -> Path:
    root = research or RESEARCH_DIR
    if root.is_symlink() or not root.is_dir():
        raise InputError("project research directory is missing or unsafe")
    target = _lexical_absolute(Path(value))
    if target.parent != _lexical_absolute(root) or target.name in ("", ".", ".."):
        raise InputError("output must be a new direct child of this project's research directory")
    if target.exists() or target.is_symlink():
        raise InputError("output directory exists; refusing to overwrite")
    try:
        target.mkdir(mode=0o700, exist_ok=False)
        os.chmod(target, 0o700)
    except FileExistsError as exc:
        raise InputError("output directory exists; refusing to overwrite") from exc
    return target


def _new_private_file(path: Path, flags: int = os.O_WRONLY) -> int:
    flags |= os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    os.fchmod(fd, 0o600)
    return fd


def _write_manifest(path: Path, value: Dict[str, Any], create: bool = False) -> None:
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    if create:
        fd = _new_private_file(path)
    else:
        fd = os.open(str(path), flags | os.O_TRUNC)
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


class StopState:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.reason: Optional[str] = None

    def request(self, reason: str) -> None:
        if self.reason is None:
            self.reason = reason
        self.event.set()


def _install_signals(stop: StopState):
    previous = {}

    def handler(signum, _frame):
        stop.request(signal.Signals(signum).name.lower())

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.signal(signum, handler)
        except (ValueError, OSError):
            pass
    return previous


def _restore_signals(previous) -> None:
    for signum, handler in previous.items():
        try:
            signal.signal(signum, handler)
        except (ValueError, OSError):
            pass


def _stop_child(proc, grace: float = TERMINATE_GRACE) -> Optional[int]:
    if proc.poll() is not None:
        return proc.returncode
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        return proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            return proc.wait(timeout=grace)
        except (subprocess.TimeoutExpired, OSError):
            return proc.poll()


def _wait_child(proc, stop: StopState, deadline_ns: int, clock=monotonic_ns) -> Tuple[str, Optional[int]]:
    while True:
        code = proc.poll()
        if code is not None:
            return "exited", code
        if stop.event.is_set():
            return "interrupted", _stop_child(proc)
        remaining_ns = deadline_ns - clock()
        if remaining_ns <= 0:
            return "timed_out", _stop_child(proc)
        try:
            proc.wait(timeout=min(0.25, remaining_ns / 1_000_000_000))
        except subprocess.TimeoutExpired:
            continue
        except InterruptedError:
            continue
        except OSError:
            return "wait_error", _stop_child(proc)


def _exception_status(exc: OSError) -> str:
    if isinstance(exc, FileNotFoundError):
        return "command_missing"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    return "os_error_{}".format(exc.errno if exc.errno is not None else "unknown")


def _run_capture(command: Sequence[str], deadline_ns: int, stop: StopState, timeout: float) -> Dict[str, Any]:
    started = monotonic_ns()
    allowed = min(timeout, max(0.0, (deadline_ns - started) / 1_000_000_000))
    if stop.event.is_set():
        return {"status": "interrupted_before_start", "exit_code": None, "stdout": ""}
    if allowed <= 0:
        return {"status": "deadline_skipped", "exit_code": None, "stdout": ""}
    try:
        proc = subprocess.Popen(
            list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", start_new_session=True,
        )
    except OSError as exc:
        return {"status": _exception_status(exc), "exit_code": None, "stdout": ""}
    try:
        status, code = _wait_child(proc, stop, min(deadline_ns, started + int(allowed * 1_000_000_000)))
    except BaseException:
        _stop_child(proc)
        raise
    if proc.poll() is None:
        code = _stop_child(proc)
    try:
        stdout, _stderr = proc.communicate()
    except OSError:
        stdout = ""
    return {"status": status, "exit_code": code, "stdout": stdout or ""}


def _run_private(command: Sequence[str], path: Path, deadline_ns: int, stop: StopState, timeout: float) -> Dict[str, Any]:
    if stop.event.is_set():
        return {"status": "interrupted_before_start", "exit_code": None, "artifact": path.name}
    try:
        fd = _new_private_file(path)
    except OSError as exc:
        return {"status": _exception_status(exc), "exit_code": None, "artifact": path.name}
    started = monotonic_ns()
    allowed = min(timeout, max(0.0, (deadline_ns - started) / 1_000_000_000))
    if allowed <= 0:
        os.close(fd)
        return {"status": "deadline_skipped", "exit_code": None, "artifact": path.name}
    with os.fdopen(fd, "wb") as output:
        try:
            proc = subprocess.Popen(list(command), stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as exc:
            return {"status": _exception_status(exc), "exit_code": None, "artifact": path.name}
        try:
            status, code = _wait_child(proc, stop, min(deadline_ns, started + int(allowed * 1_000_000_000)))
        except BaseException:
            _stop_child(proc)
            raise
        if proc.poll() is None:
            code = _stop_child(proc)
        output.flush()
        os.fsync(output.fileno())
    if status == "exited" and code != 0:
        status = "command_exit_nonzero"
    return {"status": status, "exit_code": code, "artifact": path.name}


def _start_log_stream(directory: Path):
    path = directory / "continuity.log.jsonl"
    fd = _new_private_file(path)
    output = os.fdopen(fd, "wb")
    command = ["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate", LOG_PREDICATE]
    try:
        proc = subprocess.Popen(command, stdout=output, stderr=output, start_new_session=True)
    except OSError as exc:
        output.flush()
        os.fsync(output.fileno())
        output.close()
        return None, None, {"status": _exception_status(exc), "exit_code": None, "artifact": path.name}
    return proc, output, {
        "status": "running", "exit_code": None, "artifact": path.name,
        "process_filter": list(LOG_PROCESSES),
        "format": "ndjson with possible command diagnostics; validate each record",
    }


def _finish_log_stream(proc, output, info: Dict[str, Any]) -> None:
    if proc is not None:
        alive = proc.poll() is None
        info["alive_at_cleanup_boundary"] = alive
        if alive:
            _stop_child(proc)
        info["exit_code"] = proc.poll()
        if info.get("status") == "running":
            info["status"] = "stopped_at_boundary" if alive else "exited_before_cleanup"
        info["permissions_and_redactions_verified"] = False
    if output is not None:
        output.flush()
        os.fsync(output.fileno())
        output.close()


def _interface_snapshot(interface: str, deadline_ns: int, stop: StopState, phase: str) -> Dict[str, Any]:
    started_utc = utc_now()
    started_ns = monotonic_ns()
    result = _run_capture(["/sbin/ifconfig", interface], deadline_ns, stop, IFCONFIG_TIMEOUT)
    output = result.pop("stdout")
    code = result.get("exit_code")
    lines = output.splitlines()
    header = lines[0] if lines else ""
    flags_match = re.search(r"flags=[0-9]+<([^>]*)>", header)
    flags = set(flags_match.group(1).split(",")) if flags_match else set()
    link_status = None
    for line in lines:
        value = line.strip().lower()
        if value.startswith("status:"):
            value = value.split(":", 1)[1].strip()
            if value in ("active", "inactive"):
                link_status = value
            break
    valid = result["status"] == "exited" and code == 0 and bool(header)
    return {
        "kind": "interface_state", "phase": phase, "interface": interface,
        "utc_start": started_utc, "monotonic_start_ns": started_ns,
        "utc_end": utc_now(), "monotonic_end_ns": monotonic_ns(),
        "probe": result["status"] if result["status"] != "exited" else ("ok" if code == 0 else "command_exit_nonzero"),
        "exit_code": code,
        "interface_present": bool(header) if valid else None,
        "up": "UP" in flags if valid else None,
        "running": "RUNNING" in flags if valid else None,
        "link_status": link_status if valid else None,
        "ipv4_present": any(line.lstrip().startswith("inet ") for line in lines) if valid else None,
        "ipv6_present": any(line.lstrip().startswith("inet6 ") for line in lines) if valid else None,
    }


def _wait_until(deadline_ns: int, stop: StopState) -> str:
    while not stop.event.is_set():
        remaining = deadline_ns - monotonic_ns()
        if remaining <= 0:
            return "deadline"
        stop.event.wait(min(0.25, remaining / 1_000_000_000))
    return "signal"


def run_capture(directory: Path, interface: str, duration: int) -> Dict[str, Any]:
    stop = StopState()
    previous = _install_signals(stop)
    start_utc, start_ns = utc_now(), monotonic_ns()
    deadline_ns = start_ns + duration * 1_000_000_000
    manifest: Dict[str, Any] = {
        "tool": TOOL_ID, "schema": SCHEMA, "capture_status": "starting",
        "start_utc": start_utc, "start_monotonic_ns": start_ns,
        "deadline_monotonic_ns": deadline_ns, "end_utc": None, "end_monotonic_ns": None,
        "duration_seconds": duration, "interface": interface,
        "monotonic_clock_note": "Python 3.9 process-local time.monotonic_ns; do not subtract other process/kernel timestamps. UTC correlation only.",
        "log_stream": {}, "interface_observations": [], "bluetooth_snapshots": [],
        "action_markers_file": "actions.jsonl", "tool_state_changes": False,
        "instant_hotspot_result_inferred": False, "airdrop_transfer_result_inferred": False,
        "raw_outputs_private_only": True, "interface_summary_redacted": True,
        "raw_logs_and_bluetooth_snapshots_may_contain_identifiers": True,
    }
    _write_manifest(directory / "manifest.json", manifest, create=True)
    actions_fd = _new_private_file(directory / "actions.jsonl")
    os.close(actions_fd)
    log_proc = log_file = None
    log_info: Dict[str, Any] = {}
    end_boundary: Optional[Tuple[str, int]] = None
    try:
        log_proc, log_file, log_info = _start_log_stream(directory)
        manifest["log_stream"] = log_info
        if log_proc is not None and log_proc.poll() is not None:
            log_info.update({"status": "exited_early", "exit_code": log_proc.returncode})

        observations = manifest["interface_observations"]
        observations.append(_interface_snapshot(interface, deadline_ns - END_RESERVE_NS, stop, "start"))
        start_bt_deadline = max(start_ns, deadline_ns - END_RESERVE_NS)
        bt_start = _run_private(
            ["/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"],
            directory / "bluetooth-start.json", start_bt_deadline, stop, BT_TIMEOUT,
        )
        manifest["bluetooth_snapshots"].append({"phase": "start", **bt_start})

        final_phase_start = max(start_ns, deadline_ns - END_RESERVE_NS)
        _wait_until(final_phase_start, stop)
        if not stop.event.is_set():
            bt_end_deadline = max(monotonic_ns(), deadline_ns - IFCONFIG_TIMEOUT * 1_000_000_000)
            bt_end = _run_private(
                ["/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"],
                directory / "bluetooth-end.json", bt_end_deadline, stop, BT_TIMEOUT,
            )
            manifest["bluetooth_snapshots"].append({"phase": "end", **bt_end})
            if not stop.event.is_set():
                observations.append(_interface_snapshot(interface, deadline_ns, stop, "end"))

        result = _wait_until(deadline_ns, stop)
        end_boundary = (utc_now(), monotonic_ns())
        manifest["stop_reason"] = stop.reason or result
        manifest["capture_status"] = "window_elapsed" if result == "deadline" else "interrupted"
    except BaseException as exc:
        end_boundary = (utc_now(), monotonic_ns())
        manifest["capture_status"] = "capture_error"
        manifest["capture_error_type"] = type(exc).__name__
    finally:
        _finish_log_stream(log_proc, log_file, log_info)
        if end_boundary is None:
            end_boundary = (utc_now(), monotonic_ns())
        manifest["end_utc"], manifest["end_monotonic_ns"] = end_boundary
        manifest["cleanup_end_utc"] = utc_now()
        manifest["log_stream"] = log_info
        try:
            _write_manifest(directory / "manifest.json", manifest)
        finally:
            _restore_signals(previous)
    return manifest


def _duration(value: str) -> int:
    try:
        seconds = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("duration must be integer seconds") from exc
    if not MIN_SECONDS <= seconds <= MAX_SECONDS:
        raise argparse.ArgumentTypeError("duration must be between 15 and 120 seconds")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passive, private host observations; no result inference.")
    parser.add_argument("--capture", action="store_true", help="explicitly start a bounded capture")
    parser.add_argument("--interface", help="required with --capture, for example en0 or awdl0")
    parser.add_argument("--duration", type=_duration, default=DEFAULT_SECONDS, help="15..120 seconds (default 60)")
    parser.add_argument("--output-dir", help="new direct child of this project's research/ directory")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.capture:
        print("未启动采集：默认安全模式；只有显式传入 --capture 才会运行系统命令。")
        return 0
    if not args.interface:
        parser.error("--interface is required with --capture")
    if not args.output_dir:
        parser.error("--output-dir is required with --capture")
    try:
        interface = validate_interface(args.interface)
        directory = prepare_output_dir(args.output_dir)
    except InputError as exc:
        parser.error(str(exc))
    manifest = run_capture(directory, interface, args.duration)
    print("私有观测记录已保存；未自动判定即时热点或 AirDrop 结果。")
    print("capture_status={}; manifest={}".format(manifest["capture_status"], directory / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
