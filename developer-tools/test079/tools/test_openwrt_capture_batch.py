#!/usr/bin/env python3
"""Offline tests for bounded multi-window OpenWrt capture orchestration."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional, Tuple
from unittest import mock

import run_openwrt_capture_batch as batch
import openwrt_capture_once as once


PCAP = (b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" +
        b"\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"\x00\x08\x00\x00\x7f\x00\x00\x00")
EXPECTED = once.parse_expected_ap("wlan0:0:6:2437:20")
AP_STATE = {
    "wlan0": {
        "ifindex": 101,
        "phy": 0,
        "type_code": 1,
        "channel": 6,
        "frequency_mhz": 2437,
        "width_mhz": 20,
    }
}


def args_for(root: Path, *, windows: int = 3, duration: int = 12,
             interval: int = 0, budget: int = 180) -> SimpleNamespace:
    return SimpleNamespace(
        host="root@router",
        control_path="/tmp/mock-control.sock",
        ap=["wlan0"],
        expect_ap=["wlan0:0:6:2437:20"],
        interface="wlan0",
        monitor="awdlmon0",
        windows=windows,
        duration=duration,
        interval=interval,
        total_budget=budget,
        max_packets=8,
        output_dir=str(root),
    )


def successful_summary() -> dict[str, object]:
    pcap_sha = hashlib.sha256(PCAP).hexdigest()
    return {
        "schema_version": 1,
        "mode": "capture",
        "state_unchanged": True,
        "tcpdump_exit_code": 0,
        "monitor_removed": True,
        "ap_before": AP_STATE,
        "ap_after": AP_STATE,
        "uci_sha256_before": "a" * 64,
        "uci_sha256_after": "a" * 64,
        "cancelled": False,
        "pcap_bytes": len(PCAP),
        "pcap_sha256": pcap_sha,
    }


def fake_success(argv: list[str], timeout: int) -> batch.WindowOutcome:
    output = Path(argv[argv.index("--output") + 1])
    output.write_bytes(PCAP)
    return batch.WindowOutcome(
        0,
        json.dumps(successful_summary(), separators=(",", ":")).encode("utf-8"),
    )


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class SequenceClock:
    def __init__(self, values: List[float]) -> None:
        self.values = list(values)
        self.last = values[-1]

    def __call__(self) -> float:
        if self.values:
            self.last = self.values.pop(0)
        return self.last


class FakeProcess:
    def __init__(self, events: List[object]) -> None:
        self.pid = 424242
        self.returncode: Optional[int] = None
        self.events = list(events)
        self.timeouts: list[float] = []

    def communicate(self, timeout: Optional[float] = None) -> Tuple[bytes, None]:
        self.timeouts.append(timeout or 0)
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        self.returncode = 0
        return event, None  # type: ignore[return-value]

    def poll(self) -> int | None:
        return self.returncode

    def send_signal(self, sig: int) -> None:
        raise AssertionError("mock killpg should handle process-group signals")


class OpenWrtCaptureBatchTests(unittest.TestCase):
    def test_three_windows_have_unique_outputs_and_independent_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = args_for(root)
            calls: list[tuple[list[str], int]] = []

            def executor(argv: list[str], timeout: int) -> batch.WindowOutcome:
                calls.append((list(argv), timeout))
                return fake_success(list(argv), timeout)

            with mock.patch.object(once, "validate_control_socket"):
                result = batch.run_batch(args, executor=executor)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed_windows"], 3)
            self.assertEqual(len(calls), 3)
            output_paths = [Path(argv[argv.index("--output") + 1])
                            for argv, _timeout in calls]
            self.assertEqual(len(set(output_paths)), 3)
            for index, path in enumerate(output_paths, start=1):
                self.assertTrue(path.is_file())
                window_json = path.parent / "window.json"
                self.assertTrue(window_json.is_file())
                self.assertEqual(json.loads(window_json.read_text())["window"], index)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertTrue((Path(result["output_directory"]) / "batch.json").is_file())
            self.assertTrue(all("--capture" in argv and "shell" not in argv
                                for argv, _timeout in calls))

    def test_first_failure_stops_batch_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls = 0

            def fail_first(_argv: list[str], _timeout: int) -> batch.WindowOutcome:
                nonlocal calls
                calls += 1
                return batch.WindowOutcome(
                    2, b'{"schema_version":1,"error":"STATE_MISMATCH"}')

            with mock.patch.object(once, "validate_control_socket"):
                result = batch.run_batch(args_for(Path(temporary)), executor=fail_first)
            self.assertEqual(calls, 1)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["completed_windows"], 1)
            self.assertEqual(result["error"], "STATE_MISMATCH")
            self.assertEqual(result["windows"][0]["status"], "failed")

    def test_global_deadline_stops_before_next_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_clock = SequenceClock([100.0, 100.0, 100.0, 100.0,
                                        101.0, 201.0])
            calls = 0

            def first_succeeds(argv: list[str], timeout: int) -> batch.WindowOutcome:
                nonlocal calls
                calls += 1
                return fake_success(list(argv), timeout)

            args = args_for(Path(temporary), windows=2, duration=12,
                            interval=0, budget=100)
            with mock.patch.object(once, "validate_control_socket"):
                result = batch.run_batch(args, executor=first_succeeds,
                                         clock=fake_clock, sleeper=lambda _s: None)
            self.assertEqual(calls, 1)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"], "TOTAL_BUDGET_EXHAUSTED")

    def test_executor_overrun_is_a_window_timeout_and_stops_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_clock = FakeClock()
            calls = 0

            def slow_window(argv: list[str], timeout: int) -> batch.WindowOutcome:
                nonlocal calls
                calls += 1
                outcome = fake_success(list(argv), timeout)
                fake_clock.advance(timeout + 1)
                return outcome

            args = args_for(Path(temporary), windows=2, duration=12,
                            interval=0, budget=100)
            with mock.patch.object(once, "validate_control_socket"):
                result = batch.run_batch(args, executor=slow_window,
                                         clock=fake_clock, sleeper=fake_clock.advance)
            self.assertEqual(calls, 1)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"], "WINDOW_TIMEOUT")

    def test_budget_validation_rejects_before_output_or_executor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_parent = Path(temporary)
            args = args_for(output_parent, windows=3, duration=20,
                            interval=30, budget=100)
            calls = 0

            def executor(_argv: list[str], _timeout: int) -> batch.WindowOutcome:
                nonlocal calls
                calls += 1
                raise AssertionError("executor must not run")

            with self.assertRaises(batch.BatchError) as raised:
                with mock.patch.object(once, "validate_control_socket"):
                    batch.run_batch(args, executor=executor)
            self.assertEqual(raised.exception.code, "TOTAL_BUDGET_TOO_SMALL")
            self.assertEqual(calls, 0)
            self.assertEqual(list(output_parent.iterdir()), [])

    def test_no_child_starts_without_a_full_remaining_window_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = args_for(Path(temporary), windows=2, duration=12,
                            interval=0, budget=100)
            calls = 0

            def executor(_argv: list[str], _timeout: int) -> batch.WindowOutcome:
                nonlocal calls
                calls += 1
                raise AssertionError("partial-budget window must not start")

            # The upfront worst-case budget passes (96 s), but setup delay
            # leaves only 47 s, less than the full 48 s window envelope.
            fake_clock = SequenceClock([100.0, 153.0, 153.0])
            with mock.patch.object(once, "validate_control_socket"):
                result = batch.run_batch(args, executor=executor,
                                         clock=fake_clock, sleeper=lambda _s: None)
            self.assertEqual(calls, 0)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"],
                             "TOTAL_BUDGET_INSUFFICIENT_FOR_WINDOW")
            self.assertEqual(result["completed_windows"], 0)

    def test_child_timeout_reserves_signal_cleanup_inside_total_budget(self) -> None:
        total_budget = batch.window_deadline_seconds(12)
        cleanup_budget = (batch.SIGINT_GRACE_SECONDS
                          + batch.SIGTERM_GRACE_SECONDS
                          + batch.SIGKILL_REAP_SECONDS)
        process = FakeProcess([
            subprocess.TimeoutExpired(["helper"],
                                      total_budget - cleanup_budget,
                                      output=b"READY"),
            b'{"schema_version":1,"error":"INTERRUPTED"}',
        ])
        with mock.patch.object(batch.subprocess, "Popen", return_value=process), \
                mock.patch.object(batch.os, "killpg") as killpg:
            outcome = batch.run_child(["helper"], total_budget)
        self.assertTrue(outcome.timed_out)
        self.assertEqual(process.timeouts[0], total_budget - cleanup_budget)
        self.assertLessEqual(sum(process.timeouts), total_budget)
        killpg.assert_called_once_with(process.pid, batch.signal.SIGINT)

    def test_interruption_escalates_group_signals_and_reaps_before_reraising(self) -> None:
        total_budget = batch.window_deadline_seconds(12)
        cleanup_budget = (batch.SIGINT_GRACE_SECONDS
                          + batch.SIGTERM_GRACE_SECONDS
                          + batch.SIGKILL_REAP_SECONDS)
        process = FakeProcess([
            KeyboardInterrupt(),
            subprocess.TimeoutExpired(["helper"],
                                      batch.SIGINT_GRACE_SECONDS,
                                      output=b"partial"),
            subprocess.TimeoutExpired(["helper"],
                                      batch.SIGTERM_GRACE_SECONDS,
                                      output=b"partial"),
            b"exited after kill",
        ])
        with mock.patch.object(batch.subprocess, "Popen", return_value=process), \
                mock.patch.object(batch.os, "killpg") as killpg:
            with self.assertRaises(KeyboardInterrupt):
                batch.run_child(["helper"], total_budget)
        self.assertEqual(
            [call.args[1] for call in killpg.call_args_list],
            [batch.signal.SIGINT, batch.signal.SIGTERM, batch.signal.SIGKILL],
        )
        self.assertEqual(sum(process.timeouts), total_budget)
        self.assertEqual(process.returncode, 0)

    def test_sigterm_during_live_batch_cleans_child_then_returns_interrupted(self) -> None:
        total_budget = batch.window_deadline_seconds(12)
        process = FakeProcess([b"cleaned up"])
        original_sigterm = batch.signal.getsignal(batch.signal.SIGTERM)
        first_call = True

        def send_sigterm_during_communicate(timeout: Optional[float] = None):
            nonlocal first_call
            process.timeouts.append(timeout or 0)
            if first_call:
                first_call = False
                batch.signal.raise_signal(batch.signal.SIGTERM)
            process.returncode = 0
            return b"cleaned up", None

        process.communicate = send_sigterm_during_communicate  # type: ignore[method-assign]
        with tempfile.TemporaryDirectory() as temporary:
            argv = [
                "--host", "root@router", "--control-path", "/tmp/mock-control.sock",
                "--ap", "wlan0", "--expect-ap", "wlan0:0:6:2437:20",
                "--interface", "wlan0", "--output-dir", temporary,
                "--capture",
            ]
            with mock.patch.object(batch.subprocess, "Popen", return_value=process), \
                    mock.patch.object(batch.os, "killpg") as killpg, \
                    mock.patch.object(batch, "run_batch",
                                      side_effect=lambda _args: batch.run_child(
                                          ["helper"], total_budget)):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = batch.main(argv)
            self.assertEqual(code, 130)
            self.assertEqual(json.loads(output.getvalue())["error"], "INTERRUPTED")
            killpg.assert_called_once_with(process.pid, batch.signal.SIGINT)
            self.assertEqual(batch.signal.getsignal(batch.signal.SIGTERM),
                             original_sigterm)

    def test_success_requires_monitor_cleanup_and_matching_ap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.pcap"
            path.write_bytes(PCAP)
            summary = successful_summary()
            summary["monitor_removed"] = False
            self.assertEqual(batch.validate_helper_success(summary, [EXPECTED], path, 8),
                             "MONITOR_CLEANUP_UNCONFIRMED")
            summary = successful_summary()
            changed = dict(AP_STATE["wlan0"])
            changed["channel"] = 11
            summary["ap_after"] = {"wlan0": changed}
            self.assertEqual(batch.validate_helper_success(summary, [EXPECTED], path, 8),
                             "AP_SNAPSHOT_MISMATCH")

    def test_dry_run_never_starts_child_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            argv = [
                "--host", "root@router", "--control-path", "/tmp/mock-control.sock",
                "--ap", "wlan0", "--expect-ap", "wlan0:0:6:2437:20",
                "--interface", "wlan0", "--output-dir", temporary,
            ]
            output = io.StringIO()
            with mock.patch.object(batch.subprocess, "Popen") as popen:
                with contextlib.redirect_stdout(output):
                    code = batch.main(argv)
            self.assertEqual(code, 0)
            popen.assert_not_called()
            result = json.loads(output.getvalue())
            self.assertEqual(result["mode"], "dry_run")
            self.assertFalse(result["will_start_subprocess"])
            self.assertEqual(result["windows"], batch.DEFAULT_WINDOWS)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_existing_generated_batch_directory_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            existing = parent / "openwrt-capture-batch-deadbeef"
            existing.mkdir()
            # UUID generation is patched to collide on every bounded attempt.
            fake_uuid = mock.Mock(hex="deadbeef" + "0" * 24)
            with mock.patch.object(batch.uuid, "uuid4", return_value=fake_uuid):
                with self.assertRaises(batch.BatchError) as raised:
                    batch.create_batch_directory(parent)
            self.assertEqual(raised.exception.code, "OUTPUT_CREATE_FAILED")
            self.assertEqual(list(parent.iterdir()), [existing])


if __name__ == "__main__":
    unittest.main()
