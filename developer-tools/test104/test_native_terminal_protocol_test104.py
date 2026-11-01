from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

import native_controlled_capture_test104 as adapter


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "developer-tools/test087"))
import controlled_run_coordinator as parent_coordinator


class NativeTerminalProtocolTests(unittest.TestCase):
    def test_parent_child_defers_terminal_past_slow_tail_and_report_publish(self):
        with tempfile.TemporaryDirectory(prefix="test104-terminal-") as tmp:
            sentinel = Path(tmp) / "report-published"
            child = r"""
import json, sys, threading, time
from pathlib import Path
sys.path.insert(0, sys.argv[2])
from native_controlled_capture_test104 import _run_worker_with_deferred_terminal

sentinel = Path(sys.argv[1])
sample_ready = threading.Event()
sample_count = 0
namespace = {}

def emit(event, fields):
    print(event + " " + json.dumps(fields, separators=(",", ":")), flush=True)

namespace["_json_line"] = emit

def sampler():
    global sample_count
    sample_count += 1
    if sample_count == 1:
        sample_ready.set()
    else:
        time.sleep(1.25)  # model the bounded slow post-worker ioreg read
    return {
        "sample_status": "trace_present",
        "decoded": {"status": "trace_not_published"},
        "rx149_capture_attempts": {"schema": "test104-rx149-capture-attempts/v1",
                                   "status": "property_not_published"},
        "tx_rsp_retry": {"status": "properties_not_published"},
    }

def worker_main():
    if not sample_ready.wait(1.0):
        raise RuntimeError("periodic_sample_not_started")
    namespace["_json_line"]("NATIVE_ARM_RESULT", {"event": "NATIVE_ARM_RESULT"})
    namespace["_json_line"]("NATIVE_RESULT", {
        "event": "NATIVE_RESULT", "run_token": "0123456789abcdef0123456789abcdef",
        "status": "captured_no_retry", "report_saved": True,
        "claim_consumed": True, "native_helper_invoked": True,
        "ifnet_input_kpi_accepted": None, "management_trace_valid": None,
        "preowner_snapshot_complete": False, "preowner_arm_accepted": True,
        "peer_receipt_proven": False, "native_awdl_reply_proven": False,
        "airdrop_proven": False, "retry_allowed": False,
    })
    return 0

def publish(result, samples, state):
    assert samples[-1]["sampling_phase"] == "post_worker"
    assert state["post_worker_sample_succeeded"] is True
    sentinel.write_text("complete", encoding="utf-8")
    return True, "published"

result, samples, state, published = _run_worker_with_deferred_terminal(
    namespace, worker_main, publish, sampler=sampler,
    interval_seconds=5.0, maximum_seconds=4.0)
if result != 0 or not published:
    raise SystemExit(3)
"""
            process = parent_coordinator.ManagedPipe([
                sys.executable, "-c", child, str(sentinel),
                str(REPO_ROOT / "developer-tools/test104"),
            ])
            self.addCleanup(process.close)

            started = time.monotonic()
            nonterminal = process.read_line(1.0)
            first_delay = time.monotonic() - started
            self.assertIsNotNone(nonterminal)
            self.assertTrue(nonterminal.startswith("NATIVE_ARM_RESULT "))
            self.assertLess(first_delay, 1.0)

            with self.assertRaises(parent_coordinator.CoordinatorError) as timeout:
                process.read_line(0.4)
            self.assertEqual(timeout.exception.code, "CHILD_PROTOCOL_TIMEOUT")
            self.assertIsNone(process.process.poll())
            self.assertFalse(sentinel.exists())

            terminal_started = time.monotonic()
            terminal = process.read_line(2.0)
            terminal_delay = time.monotonic() - terminal_started
            self.assertIsNotNone(terminal)
            self.assertTrue(terminal.startswith("NATIVE_RESULT "))
            self.assertGreaterEqual(terminal_delay, 0.7)
            self.assertTrue(sentinel.is_file())
            self.assertEqual(process.process.wait(timeout=1.0), 0)

    def test_report_temp_collision_is_preserved_and_does_not_publish(self):
        with tempfile.TemporaryDirectory(prefix="test104-report-") as tmp:
            output = Path(tmp)
            output.chmod(0o700)
            report = output / "native-controlled-capture-private.json"
            report.write_text('{"base":true}\n', encoding="utf-8")
            report.chmod(0o600)
            temporary = output / ".native-controlled-capture-test104.tmp"
            temporary.write_text("leave-existing-file", encoding="utf-8")
            temporary.chmod(0o600)

            published, status = adapter._atomic_append_hcmd_report(
                output, {"marker": "new"})

            self.assertFalse(published)
            self.assertTrue(status.startswith("atomic_publish_failed_"))
            self.assertEqual(temporary.read_text(encoding="utf-8"),
                             "leave-existing-file")
            self.assertEqual(json.loads(report.read_text(encoding="utf-8")),
                             {"base": True})

    def test_report_replace_and_fsync_failures_do_not_report_success(self):
        with tempfile.TemporaryDirectory(prefix="test104-report-fail-") as tmp:
            output = Path(tmp)
            output.chmod(0o700)
            report = output / "native-controlled-capture-private.json"
            report.write_text('{"base":true}\n', encoding="utf-8")
            report.chmod(0o600)

            with mock.patch.object(adapter.os, "replace", side_effect=OSError("replace")):
                published, status = adapter._atomic_append_hcmd_report(
                    output, {"marker": "replace-failure"})
            self.assertFalse(published)
            self.assertIn("OSError", status)
            self.assertEqual(json.loads(report.read_text(encoding="utf-8")),
                             {"base": True})
            self.assertFalse((output / ".native-controlled-capture-test104.tmp").exists())

            with mock.patch.object(adapter.os, "fsync",
                                   side_effect=[None, OSError("directory fsync")]):
                published, status = adapter._atomic_append_hcmd_report(
                    output, {"marker": "directory-fsync-failure"})
            self.assertFalse(published)
            self.assertIn("OSError", status)
            published_bytes = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(
                published_bytes["hcmd_rx_trace_observation"]["marker"],
                "directory-fsync-failure",
            )

            with mock.patch.object(adapter.os, "fsync", side_effect=OSError("fsync")):
                published, status = adapter._atomic_append_hcmd_report(
                    output, {"marker": "fsync-failure"})
            self.assertFalse(published)
            self.assertIn("OSError", status)
            self.assertEqual(
                json.loads(report.read_text(encoding="utf-8"))["hcmd_rx_trace_observation"]["marker"],
                "directory-fsync-failure",
            )
            self.assertFalse((output / ".native-controlled-capture-test104.tmp").exists())

    def test_terminal_gate_forwards_nonterminal_and_suppresses_unpublished_success(self):
        lines = []
        gate = adapter._DeferredNativeResult(lambda event, fields: lines.append((event, fields)))
        gate.emit("NATIVE_ARM_RESULT", {"event": "NATIVE_ARM_RESULT"})
        gate.emit("NATIVE_RESULT", {"event": "NATIVE_RESULT", "status": "captured_no_retry"})
        self.assertEqual([event for event, _ in lines], ["NATIVE_ARM_RESULT"])
        self.assertTrue(gate.release_report_publish_failure())
        self.assertEqual(lines[-1][1]["status"], "native_report_write_failed_no_retry")
        self.assertIs(lines[-1][1]["report_saved"], False)
        self.assertFalse(gate.release_after_report_publish())

    def test_failed_report_publish_emits_only_fail_closed_terminal(self):
        lines = []
        namespace = {
            "_json_line": lambda event, fields: lines.append((event, dict(fields)))
        }

        def worker():
            namespace["_json_line"]("NATIVE_ARM_RESULT", {"event": "NATIVE_ARM_RESULT"})
            namespace["_json_line"]("NATIVE_RESULT", {
                "event": "NATIVE_RESULT", "status": "captured_no_retry",
                "report_saved": True,
            })
            return 0

        _, _, state, published = adapter._run_worker_with_deferred_terminal(
            namespace, worker,
            lambda _result, _samples, _state: (False, "replace_failed"),
            sampler=lambda: {
                "sample_status": "trace_present",
                "decoded": {"status": "trace_not_published"},
                "rx149_capture_attempts": {"status": "property_not_published"},
                "tx_rsp_retry": {"status": "properties_not_published"},
            },
        )

        self.assertFalse(published)
        self.assertEqual(state["final_report_publish_status"], "replace_failed")
        self.assertEqual([event for event, _ in lines], [
            "NATIVE_ARM_RESULT", "NATIVE_RESULT",
        ])
        terminal = lines[-1][1]
        self.assertEqual(terminal["status"], "native_report_write_failed_no_retry")
        self.assertIs(terminal["report_saved"], False)


if __name__ == "__main__":
    unittest.main()
