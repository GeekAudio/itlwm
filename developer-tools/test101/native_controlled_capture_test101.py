#!/usr/bin/env python3
"""Test101 native worker adapter with token-bound RX149 arm helper.

All capture, claim, counter, privacy, and report behavior is reused from the
unchanged Test087 worker. This wrapper changes only the compiled Swift helper
and passes the coordinator's one-use token before the existing arm property.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess as _subprocess
import stat
import sys
import threading
import time


from hcmd_rx_trace_test101 import sample_once, summarize_samples

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST087_WORKER = REPO_ROOT / "developer-tools/test087/native_controlled_capture.py"
TEST101_ARM_HELPER = TOOL_DIR / "arm_p2p_rx149_test101.swift"
TEST101_SENDER_PROFILE = {
    "frames": 4,
    "interval_ms": 10,
    "deadline_seconds": 0.04,
}


class _WorkerSubprocessAdapter:
    """Append the one-use token only to the compiled RX149 arm helper call."""

    def __init__(self, token_state: dict[str, str | None]):
        self._token_state = token_state

    def __getattr__(self, name: str):
        return getattr(_subprocess, name)

    def run(self, args, *positional, **kwargs):
        command = list(args) if isinstance(args, (list, tuple)) else args
        if (isinstance(command, list) and command and
                Path(str(command[0])).name == "arm-p2p-rx149"):
            token = self._token_state.get("run_token")
            if not isinstance(token, str) or not token:
                raise RuntimeError("Test101 helper token was not captured")
            if "--run-token" in command:
                raise RuntimeError("Test101 helper token argument was duplicated")
            command = [*command, "--run-token", token]
        return _subprocess.run(command, *positional, **kwargs)


def configure_worker(namespace: dict, *, iwn_root: Path) -> None:
    """Bind the worker to Test101 helper and the coordinator's ARM token."""
    namespace["IWN_ROOT"] = iwn_root
    namespace["PRIVATE_ROOT"] = iwn_root / "research/test101-runtime-private"
    namespace["DEFAULT_METADATA"] = (
        namespace["PRIVATE_ROOT"] / "native-controlled-probe-private.json")
    namespace["HELPER_SOURCE"] = TEST101_ARM_HELPER
    token_state: dict[str, str | None] = {"run_token": None}
    original_gate = namespace.get("_wait_for_helper_gate")
    original_load = namespace.get("_load_module")
    if not callable(original_gate):
        raise RuntimeError("NATIVE_ARM_GATE_UNAVAILABLE")
    if not callable(original_load):
        raise RuntimeError("NATIVE_MODULE_LOADER_UNAVAILABLE")

    def capture_token_from_gate():
        decision, token = original_gate()
        token_state["run_token"] = token
        return decision, token

    namespace["_wait_for_helper_gate"] = capture_token_from_gate
    def load_with_test101_helper(name, path):
        module = original_load(name, path)
        if Path(path).name == "test087_controlled.py":
            module.IWN_ROOT = iwn_root
            module.PRIVATE_ROOT = iwn_root / "research/test101-runtime-private"
            module.DEFAULT_METADATA = (
                module.PRIVATE_ROOT / "native-controlled-probe-private.json")
            module.HELPER_SOURCE = TEST101_ARM_HELPER
            # The child worker imports its own protocol module. The coordinator's
            # in-process Test101 profile changes do not cross this process boundary.
            # Keep the worker's metadata gate and READY/result decoders aligned with
            # the frozen 4-frame / 10 ms / 40 ms Test101 sender contract.
            module.SENDER_FRAMES = TEST101_SENDER_PROFILE["frames"]
            module.SENDER_INTERVAL_MS = TEST101_SENDER_PROFILE["interval_ms"]
            module.FROZEN_METADATA_SENDER_INTERVAL_MS = TEST101_SENDER_PROFILE["interval_ms"]
            module.SENDER_DEADLINE_SECONDS = TEST101_SENDER_PROFILE["deadline_seconds"]
        return module

    namespace["_load_module"] = load_with_test101_helper
    namespace["subprocess"] = _WorkerSubprocessAdapter(token_state)


def load_test087_worker():
    """Import Test087 as a real module so hooks change function globals."""
    if TEST087_WORKER.is_symlink() or not TEST087_WORKER.is_file():
        raise RuntimeError("NATIVE_WORKER_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(
        "test101_native_worker_adapter_runtime", TEST087_WORKER)
    if spec is None or spec.loader is None:
        raise RuntimeError("NATIVE_WORKER_SOURCE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise RuntimeError("NATIVE_WORKER_SOURCE_IMPORT_FAILED")
    return module


def _atomic_append_hcmd_report(output_dir: Path, evidence: dict) -> None:
    report_path = output_dir / "native-controlled-capture-private.json"
    if (report_path.is_symlink() or not report_path.is_file() or
            stat.S_IMODE(report_path.stat().st_mode) != 0o600):
        return
    try:
        original = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return
    if not isinstance(original, dict):
        return
    original["hcmd_rx_trace_observation"] = evidence
    payload = json.dumps(original, ensure_ascii=False, indent=2,
                         sort_keys=True).encode("utf-8") + b"\n"
    temporary = output_dir / ".native-controlled-capture-test101.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            if os.geteuid() == 0:
                os.fchown(fd, report_path.stat().st_uid, report_path.stat().st_gid)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        os.replace(temporary, report_path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _collect_hcmd_while_worker_runs(stop: threading.Event,
                                    samples: list[dict], *,
                                    interval_seconds: float = 1.0,
                                    maximum_samples: int = 12) -> None:
    next_deadline = time.monotonic()
    while not stop.is_set() and len(samples) < maximum_samples:
        samples.append(sample_once())
        next_deadline += interval_seconds
        stop.wait(max(0.0, next_deadline - time.monotonic()))


def main() -> int:
    args = list(sys.argv[1:])
    if "--iwn-root" not in args:
        print("IWN_ROOT_REQUIRED", file=sys.stderr)
        return 2
    root_index = args.index("--iwn-root")
    if root_index + 1 >= len(args):
        print("IWN_ROOT_REQUIRED", file=sys.stderr)
        return 2
    root_arg = Path(args[root_index + 1]).expanduser()
    del args[root_index:root_index + 2]
    if not root_arg.is_absolute() or root_arg.is_symlink():
        print("IWN_ROOT_INVALID", file=sys.stderr)
        return 2
    try:
        iwn_root = root_arg.resolve(strict=True)
    except OSError:
        print("IWN_ROOT_UNAVAILABLE", file=sys.stderr)
        return 2
    if TEST087_WORKER.is_symlink() or not TEST087_WORKER.is_file():
        print("NATIVE_WORKER_SOURCE_UNAVAILABLE", file=sys.stderr)
        return 2
    if TEST101_ARM_HELPER.is_symlink() or not TEST101_ARM_HELPER.is_file():
        print("TEST101_ARM_HELPER_UNAVAILABLE", file=sys.stderr)
        return 2
    try:
        worker = load_test087_worker()
        configure_worker(worker.__dict__, iwn_root=iwn_root)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 2
    worker_main = worker.main
    if not callable(worker_main):
        print("NATIVE_WORKER_ENTRY_UNAVAILABLE", file=sys.stderr)
        return 2
    # The coordinator passes its authorized private output directory to the
    # worker. Keep argv limited to Test087's unchanged worker protocol.
    sys.argv = [sys.argv[0], *args]
    output_dir = None
    for index, item in enumerate(args[:-1]):
        if item == "--output":
            output_dir = Path(args[index + 1])
            break
    stop = threading.Event()
    samples: list[dict] = []
    collector = threading.Thread(
        target=_collect_hcmd_while_worker_runs,
        args=(stop, samples), daemon=True)
    collector.start()
    try:
        result = int(worker_main())
    finally:
        stop.set()
        collector.join(timeout=1.5)
    summary = summarize_samples(samples)
    evidence = {
        **summary,
        "sampling_interval_seconds": 1.0,
        "sampling_scope": "read_only_worker_lifetime",
        "samples": samples,
        "sample_clock_domain": "host_monotonic_ns_bounded_around_ioreg_read",
        "driver_monotonic_values_are_unmapped": True,
    }
    if output_dir is not None and output_dir.is_absolute():
        _atomic_append_hcmd_report(output_dir, evidence)
    return result


if __name__ == "__main__":
    raise SystemExit(main())

