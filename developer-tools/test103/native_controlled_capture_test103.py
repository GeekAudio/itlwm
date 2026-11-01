#!/usr/bin/env python3
"""Test103 native worker adapter with token-bound RX149 arm helper.

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


from hcmd_rx_trace_test103 import (
    sample_once, summarize_samples, summarize_tx_rsp_retry_samples,
)
from rx149_capture_attempts_test103 import summarize_capture_samples

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST087_WORKER = REPO_ROOT / "developer-tools/test087/native_controlled_capture.py"
TEST103_ARM_HELPER = TOOL_DIR / "arm_p2p_rx149_test103.swift"
TEST103_SENDER_PROFILE = {
    "frames": 4,
    "interval_ms": 10,
    "deadline_seconds": 0.04,
}
MAX_WORKER_SAMPLE_SECONDS = 120.0
READ_Ioreg_TIMEOUT_SECONDS = 4.0


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
                raise RuntimeError("Test103 helper token was not captured")
            if "--run-token" in command:
                raise RuntimeError("Test103 helper token argument was duplicated")
            command = [*command, "--run-token", token]
        return _subprocess.run(command, *positional, **kwargs)


def configure_worker(namespace: dict, *, iwn_root: Path) -> None:
    """Bind the worker to Test103 helper and the coordinator's ARM token."""
    namespace["IWN_ROOT"] = iwn_root
    namespace["PRIVATE_ROOT"] = iwn_root / "research/test103-runtime-private"
    namespace["DEFAULT_METADATA"] = (
        namespace["PRIVATE_ROOT"] / "native-controlled-probe-private.json")
    namespace["HELPER_SOURCE"] = TEST103_ARM_HELPER
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
    def load_with_test103_helper(name, path):
        module = original_load(name, path)
        if Path(path).name == "test087_controlled.py":
            module.IWN_ROOT = iwn_root
            module.PRIVATE_ROOT = iwn_root / "research/test103-runtime-private"
            module.DEFAULT_METADATA = (
                module.PRIVATE_ROOT / "native-controlled-probe-private.json")
            module.HELPER_SOURCE = TEST103_ARM_HELPER
            # The child worker imports its own protocol module. The coordinator's
            # in-process Test103 profile changes do not cross this process boundary.
            # Keep the worker's metadata gate and READY/result decoders aligned with
            # the frozen 4-frame / 10 ms / 40 ms Test103 sender contract.
            module.SENDER_FRAMES = TEST103_SENDER_PROFILE["frames"]
            module.SENDER_INTERVAL_MS = TEST103_SENDER_PROFILE["interval_ms"]
            module.FROZEN_METADATA_SENDER_INTERVAL_MS = TEST103_SENDER_PROFILE["interval_ms"]
            module.SENDER_DEADLINE_SECONDS = TEST103_SENDER_PROFILE["deadline_seconds"]
        return module

    namespace["_load_module"] = load_with_test103_helper
    namespace["subprocess"] = _WorkerSubprocessAdapter(token_state)


def load_test087_worker():
    """Import Test087 as a real module so hooks change function globals."""
    if TEST087_WORKER.is_symlink() or not TEST087_WORKER.is_file():
        raise RuntimeError("NATIVE_WORKER_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(
        "test103_native_worker_adapter_runtime", TEST087_WORKER)
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
    temporary = output_dir / ".native-controlled-capture-test103.tmp"
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


def _collector_error_sample(error: Exception, *, phase: str) -> dict:
    message = str(error)[:120]
    return {
        "sample_status": "collector_error",
        "sampling_phase": phase,
        "error_code": message,
        "decoded": {"status": "collector_error", "error_code": message},
        "rx149_capture_attempts": {
            "schema": "test103-rx149-capture-attempts/v1",
            "status": "collector_error", "error_code": message,
            "records": [], "capture_delivery_proven": False,
            "ifnet_delivery_proven": False,
        },
        "tx_rsp_retry": {
            "status": "collector_error", "error_code": message,
            "rf_ack_peer_proven": False,
        },
    }


def _mark_sample_and_count(current: dict, *, phase: str, state: dict) -> dict:
    current = dict(current)
    current["sampling_phase"] = phase
    if current.get("sample_status") == "collector_error":
        state["sample_error_count"] = state.get("sample_error_count", 0) + 1
    if any(
        isinstance(current.get(key), dict) and
        current[key].get("status") in {
            "collector_error", "snapshot_unavailable_or_invalid"
        }
        for key in ("decoded", "rx149_capture_attempts", "tx_rsp_retry")
    ):
        state["component_decode_error_count"] = (
            state.get("component_decode_error_count", 0) + 1)
    return current


def _collect_hcmd_while_worker_runs(stop: threading.Event,
                                    samples: list[dict], *,
                                    samples_lock: threading.Lock,
                                    state: dict,
                                    interval_seconds: float = 1.0,
                                    maximum_seconds: float = MAX_WORKER_SAMPLE_SECONDS,
                                    sampler=sample_once,
                                    clock=time.monotonic,
                                    waiter=None) -> None:
    if waiter is None:
        waiter = stop.wait
    started = clock()
    deadline = started + maximum_seconds
    next_sample = started
    state.update({
        "maximum_seconds": maximum_seconds,
        "interval_seconds": interval_seconds,
        "sample_limit_reached": False,
        "sample_error_count": 0,
        "component_decode_error_count": 0,
        "missed_interval_count": 0,
        "collector_stop_reason": None,
    })
    while not stop.is_set():
        now = clock()
        if now >= deadline:
            state["sample_limit_reached"] = True
            state["collector_stop_reason"] = "maximum_duration_reached_before_worker_stop"
            break
        try:
            current = sampler()
        except Exception as error:
            current = _collector_error_sample(error, phase="worker_lifetime")
        if not isinstance(current, dict):
            current = _collector_error_sample(
                TypeError("sample_result_not_object"), phase="worker_lifetime")
        current = _mark_sample_and_count(
            current, phase="worker_lifetime", state=state)
        with samples_lock:
            samples.append(current)
        now = clock()
        if now >= deadline and not stop.is_set():
            state["sample_limit_reached"] = True
            state["collector_stop_reason"] = "maximum_duration_reached_before_worker_stop"
            break
        next_sample += interval_seconds
        if now >= next_sample:
            missed = int((now - next_sample) // interval_seconds) + 1
            state["missed_interval_count"] += missed
            next_sample += missed * interval_seconds
        waiter(max(0.0, next_sample - now))
    if state["collector_stop_reason"] is None:
        state["collector_stop_reason"] = (
            "worker_stop_requested" if stop.is_set() else "collector_stopped")
    state["collector_started_monotonic_seconds"] = started
    state["collector_finished_monotonic_seconds"] = clock()


def _run_worker_with_collector(worker_main, *, sampler=sample_once,
                               interval_seconds: float = 1.0,
                               maximum_seconds: float = MAX_WORKER_SAMPLE_SECONDS,
                               clock=time.monotonic, waiter=None):
    """Run the worker while a bounded read-only collector samples its lifetime.

    The only blocking read in the sampler is ioreg with a four-second timeout.
    We join without a timeout after setting stop, so the collector cannot outlive
    the frozen sample tuple or mutate the final report.
    """
    stop = threading.Event()
    samples: list[dict] = []
    samples_lock = threading.Lock()
    state: dict = {}
    def collect_safely():
        try:
            _collect_hcmd_while_worker_runs(
                stop, samples, samples_lock=samples_lock, state=state,
                interval_seconds=interval_seconds,
                maximum_seconds=maximum_seconds, sampler=sampler, clock=clock,
                waiter=waiter,
            )
        except Exception as error:
            state["collector_fatal_error"] = str(error)[:120]
            state["collector_stop_reason"] = "collector_internal_error"
            state["collector_finished_monotonic_seconds"] = clock()

    collector = threading.Thread(target=collect_safely, daemon=True)
    worker_started = clock()
    collector.start()
    worker_returned = False
    try:
        result = int(worker_main())
        worker_returned = True
    finally:
        worker_finished = clock()
        stop.set()
        collector.join()
        with samples_lock:
            worker_lifetime_samples = tuple(samples)
        joined = not collector.is_alive()
        state["worker_returned"] = worker_returned
        state["worker_started_monotonic_seconds"] = worker_started
        state["worker_finished_monotonic_seconds"] = worker_finished
        state["worker_duration_seconds"] = max(0.0, worker_finished - worker_started)
        state["collector_thread_joined"] = joined
        state["worker_lifetime_sample_count"] = len(worker_lifetime_samples)
        state["worker_lifetime_reached"] = (
            worker_returned and not state.get("sample_limit_reached", False))

        # Take one final read-only snapshot after the worker has exited. This
        # catches a ledger publication that lands after the last one-second
        # sample; read_ioreg_sample keeps its subprocess read bounded to 4s.
        state["post_worker_sample_attempted"] = True
        state["post_worker_sample_timeout_seconds"] = READ_Ioreg_TIMEOUT_SECONDS
        try:
            tail_sample = sampler()
            if not isinstance(tail_sample, dict):
                raise TypeError("sample_result_not_object")
        except Exception as error:
            tail_sample = _collector_error_sample(error, phase="post_worker")
            state["tail_sample_error"] = str(error)[:120]
        else:
            state["tail_sample_error"] = None
        tail_sample = _mark_sample_and_count(
            tail_sample, phase="post_worker", state=state)
        with samples_lock:
            samples.append(tail_sample)
            frozen_samples = tuple(samples)
        tail_component_error = any(
            isinstance(tail_sample.get(key), dict) and
            tail_sample[key].get("status") in {
                "collector_error", "snapshot_unavailable_or_invalid"
            }
            for key in ("decoded", "rx149_capture_attempts", "tx_rsp_retry")
        )
        state["post_worker_sample_status"] = tail_sample.get("sample_status")
        state["post_worker_sample_succeeded"] = bool(
            tail_sample.get("sample_status") != "collector_error" and
            not tail_component_error)
        state["sample_count"] = len(frozen_samples)
        state["coverage_complete"] = bool(
            state["worker_lifetime_reached"] and joined and
            state.get("worker_lifetime_sample_count", 0) > 0 and
            state["post_worker_sample_succeeded"] and
            not state.get("collector_fatal_error") and
            state.get("sample_error_count") == 0 and
            state.get("component_decode_error_count") == 0 and
            state.get("missed_interval_count") == 0)
        state["coverage_status"] = (
            "complete" if state["coverage_complete"] else "incomplete")
    return result, frozen_samples, state


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
    if TEST103_ARM_HELPER.is_symlink() or not TEST103_ARM_HELPER.is_file():
        print("TEST103_ARM_HELPER_UNAVAILABLE", file=sys.stderr)
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
    result, frozen_samples, collection_state = _run_worker_with_collector(worker_main)
    samples = list(frozen_samples)
    summary = summarize_samples(samples)
    capture_summary = summarize_capture_samples(samples)
    retry_summary = summarize_tx_rsp_retry_samples(samples)
    evidence = {
        **summary,
        "rx149_capture_attempts": capture_summary,
        "tx_rsp_retry_observation": retry_summary,
        "sampling_interval_seconds": 1.0,
        "sampling_scope": (
            "read_only_worker_lifetime" if collection_state["coverage_complete"]
            else "bounded_worker_observation_incomplete"),
        "sampling_coverage": collection_state,
        "samples": samples,
        "sample_clock_domain": "host_monotonic_ns_bounded_around_ioreg_read",
        "driver_monotonic_values_are_unmapped": True,
    }
    if output_dir is not None and output_dir.is_absolute():
        _atomic_append_hcmd_report(output_dir, evidence)
    return result


if __name__ == "__main__":
    raise SystemExit(main())

