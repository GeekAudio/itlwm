from __future__ import annotations

import json
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIR))
import controlled_run_test088 as adapter


RUN_TOKEN = "0123456789abcdef0123456789abcdef"
SENDER_GO_NS = 1_000_000_000


def _legacy_result(*, incomplete_timing=False):
    rows = []
    for i in range(16):
        before = None if incomplete_timing else SENDER_GO_NS + 10_000 + i * 80_000_000
        after = None if incomplete_timing else before + 1_000
        rows.append({
            "ordinal": i,
            "ieee80211_sequence": (291 + i) & 0xFFF,
            "awdl_sequence": (34305 + i) & 0xFFFF,
            "before_ns": before,
            "after_ns": after,
            "return_bytes": 106,
            "errno": 0,
        })
    return {
        "event": "SENDER_RESULT",
        "status": "complete",
        "frames_requested": 16,
        "frames_attempted": 16,
        "frames_completed": 16,
        "sent": 16,
        "payload_bytes": 96,
        "mpdu_bytes": 96,
        "radiotap_bytes": 10,
        "packet_bytes": 106,
        "udp_payload_bytes": 8,
        "elapsed_ms": 1200,
        "deadline_hit": False,
        "error_count": 0,
        "last_errno": 0,
        "stop_reason": "complete",
        "tx_flags_requested": "NOACK|NOSEQNO",
        "hardware_honoring": "unknown",
        "timing_schema": 1,
        "clock_domain": "CLOCK_MONOTONIC",
        "go_received_ns": SENDER_GO_NS,
        "started_ns": SENDER_GO_NS + 500,
        "finished_ns": SENDER_GO_NS + 1_202_000_000,
        "send_timing": rows,
    }


def _child_source(result, *, first_line=None, emit_started=True):
    started = {
        "event": "SENDER_STARTED", "timing_schema": 1,
        "clock_domain": "CLOCK_MONOTONIC",
        "go_received_ns": SENDER_GO_NS, "started_ns": SENDER_GO_NS + 500,
        "frames_requested": 16, "interval_ms": 80, "send_budget_ns": 2_000_000_000,
    }
    cleanup = {
        "event": "MONITOR_CLEANUP", "run_token": RUN_TOKEN,
        "monitor_removed": True, "ap_unchanged": True,
        "temporary_files_removed": True,
    }
    result_json = json.dumps(result, separators=(",", ":"))
    wire_line = result_json if first_line is None else first_line
    started_output = (
        f"print({json.dumps(json.dumps(started, separators=(',', ':')))}, flush=True)\n"
        if emit_started else "")
    return (
        "import json,sys\n"
        "line=sys.stdin.readline()\n"
        f"assert line == 'GO {RUN_TOKEN}\\n'\n"
        + started_output
        + f"print({json.dumps(wire_line)}, flush=True)\n"
        f"print('CLEANUP ' + {json.dumps(json.dumps(cleanup, separators=(',', ':')))}, flush=True)\n"
        + f"sys.exit({0 if result.get('status') in ('complete', 'aborted') else 1})\n"
    )


class _Clock:
    def __init__(self):
        self.value = 10_000_000

    def sample_pair(self):
        self.value += 100
        return {
            "status": "available",
            "clock_domain": "mach_absolute_time_ns_since_boot_excludes_sleep",
            "process_clock_domain": "python_time_monotonic_ns_epoch_not_shared",
            "process_epoch_shared": False,
            "process_monotonic_ns": self.value + 1_000_000,
            "boot_monotonic_ns": self.value,
            "boot_sample_lower_ns": self.value - 50,
            "boot_sample_upper_ns": self.value + 50,
        }


class ControlledRunTest088Tests(unittest.TestCase):
    def _session(self, result, *, first_line=None, emit_started=True):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", _child_source(
                result, first_line=first_line, emit_started=emit_started)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        underlying = SimpleNamespace(
            process=process,
            selector=selector,
            read_state={"buffer": b""},
            deadline=time.monotonic() + 5,
            run_token=RUN_TOKEN,
            sender_sha256="a" * 64,
            closed=False,
            control_consumed=False,
            protocol_evidence={},
        )
        return process, underlying

    def _run_fake_pipe(self, *, incomplete_timing=False, result=None,
                       first_line=None, emit_started=True, native_roc=None):
        capture = adapter._RunCapture("25G332-Test087")
        result = result or _legacy_result(incomplete_timing=incomplete_timing)
        process, underlying = self._session(
            result, first_line=first_line, emit_started=emit_started)
        wrapped = adapter.Test088SenderSession(underlying, capture)
        report = {"events_parent_monotonic_ns": [],
                  "events_parent_boot_monotonic_ns": []}
        clock = _Clock()

        def append_event(event):
            capture.report = report
            capture.parent_clock = clock
            adapter._sample_parent_clock(report, event, clock)
            if event in {"BEGIN", "ROUTER_GO_WRITE_BEGIN"}:
                capture.go_write["BEGIN"] = dict(report["events_parent_boot_monotonic_ns"][-1])
            elif event in {"END", "ROUTER_GO_WRITE_END"}:
                capture.go_write["END"] = dict(report["events_parent_boot_monotonic_ns"][-1])

        try:
            try:
                completion = wrapped.go_once(on_control_write=append_event)
                error = None
            except adapter.PROTOCOL.ControlledProbeError as caught:
                completion = None
                error = caught
        finally:
            if process.poll() is None:
                adapter.ROUTER._terminate_process(process)
        if error is not None and underlying.protocol_evidence:
            report["sender_protocol_evidence"] = dict(underlying.protocol_evidence)
        if native_roc is not None:
            capture.native_roc = native_roc
        attached = capture.attach({**report, "native_result": {
            "ifnet_input_kpi_accepted": True}})
        return attached, completion, error

    def test_default_plan_has_no_run_or_radio_side_effect(self):
        result = adapter.plan()
        self.assertEqual(result["tool_revision"], "Test088")
        self.assertEqual(result["driver_candidate"], "25G332-Test087")
        self.assertEqual(result["default_action"], "none")
        self.assertTrue(result["requires_explicit_run_flag"])

    def test_new_sender_protocol_uses_fake_pipe_and_keeps_raw_records(self):
        roc = {
            "status": "same_owner_boundary_valid",
            "roc_interval_ns": [10_010_500, 10_011_500],
            "cross_clock_mapping_proven": True,
        }
        report, completion, error = self._run_fake_pipe(native_roc=roc)
        self.assertIsNone(error)
        sender = report["test088_sender"]
        self.assertEqual(completion["sender_result"]["status"], "complete")
        self.assertTrue(sender["raw_records"]["sender_started_line"].startswith(
            '{"event":"SENDER_STARTED"'))
        self.assertTrue(sender["raw_records"]["sender_result_line"].startswith(
            '{"event":"SENDER_RESULT"'))
        self.assertEqual(sender["timing"]["status"], "complete")
        self.assertEqual(sender["timing"]["roc_overlap_status"],
                         "mapped_same_boot_clock_interval_bounded_by_usec_quantization")
        self.assertNotEqual(sender["timing"]["analysis"]["strict_causal_summary"],
                            "unknown_missing_mac_go_or_result_receipt")
        self.assertIn(sender["timing"]["analysis"]["nominal_summary"], {
            "one_or_more_nominal_intervals_overlap_unmeasured_rate_assumption",
            "nominal_intervals_disjoint_unmeasured_rate_assumption",
        })
        self.assertFalse(sender["timing"]["local_send_writes_prove_rf"])
        self.assertIn("ROUTER_SENDER_STARTED_RECEIVED",
                      [event["event"] for event in report["events_parent_boot_monotonic_ns"]])
        self.assertTrue(report["native_result"]["ifnet_input_kpi_accepted"])

    def test_incomplete_timing_is_unknown_and_does_not_override_native_input(self):
        report, completion, error = self._run_fake_pipe(incomplete_timing=True)
        self.assertIsNone(error)
        self.assertEqual(completion["sender_result"]["status"], "complete")
        self.assertEqual(report["test088_sender"]["timing"]["status"],
                         "unknown_incomplete")
        self.assertTrue(report["native_result"]["ifnet_input_kpi_accepted"])

    def test_old_boot_epoch_rejected_before_base_coordinator(self):
        minimum = adapter.plan()["minimum_boot_epoch_exclusive"]
        with mock.patch.object(adapter, "_read_current_boot_epoch",
                               return_value=minimum), \
                mock.patch.object(adapter.BASE, "run_controlled_once") as run:
            with self.assertRaises(adapter.AdapterError) as error:
                adapter.run_test088_once(host="router", control_path="/tmp/socket",
                                         ap="wlan7")
        self.assertEqual(error.exception.code, "BOOT_EPOCH_TOO_OLD")
        run.assert_not_called()

    def test_bad_or_unknown_first_line_is_retained_and_attach_is_non_gating(self):
        for wire, classification in (
                ('{"event":"SENDER_RESULT"', "malformed_known_event_json"),
                ('{"event":"OTHER"}', "malformed_or_unexpected_json_event")):
            with self.subTest(wire=wire):
                report, completion, error = self._run_fake_pipe(
                    first_line=wire, emit_started=False)
                self.assertIsNone(completion)
                self.assertIsNotNone(error)
                sender = report["test088_sender"]
                self.assertEqual(sender["raw_records"]["first_protocol_line"], wire)
                self.assertEqual(sender["raw_records"][
                    "first_protocol_line_classification"], classification)
                self.assertEqual(sender["timing"]["status"],
                                 "unknown_not_received")
                self.assertTrue(report["native_result"]["ifnet_input_kpi_accepted"])

    def test_legacy_validation_error_does_not_get_masked_by_timing_attach(self):
        bad = _legacy_result()
        bad["elapsed_ms"] = None
        wire = json.dumps(bad, separators=(",", ":"))
        report, completion, error = self._run_fake_pipe(
            result=bad, first_line=wire, emit_started=False)
        self.assertIsNone(completion)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "SENDER_RESULT_INVALID_COUNTER")
        self.assertIsNone(report["test088_sender"]["legacy_result_status"])
        self.assertEqual(report["test088_sender"]["raw_records"]["sender_result_line"], wire)
        self.assertEqual(report["test088_sender"]["timing"]["status"],
                         "unknown_legacy_result_not_validated")
        self.assertTrue(report["native_result"]["ifnet_input_kpi_accepted"])

    def test_go_rejects_aborted_status_after_cleanup_without_erasing_native(self):
        aborted = _legacy_result()
        aborted.update({
            "status": "aborted", "frames_attempted": 0, "frames_completed": 0,
            "sent": 0, "elapsed_ms": 0, "deadline_hit": False,
            "error_count": 0, "last_errno": 0, "stop_reason": "aborted_before_go",
            "send_timing": [],
        })
        wire = json.dumps(aborted, separators=(",", ":"))
        report, completion, error = self._run_fake_pipe(
            result=aborted, first_line=wire, emit_started=False)
        self.assertIsNone(completion)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "SENDER_GO_RESULT_STATUS_INVALID")
        self.assertTrue(report["test088_sender"]["raw_records"]["sender_result_line"])
        self.assertTrue(report["sender_protocol_evidence"]["cleanup"]["monitor_removed"])
        self.assertEqual(report["sender_protocol_evidence"]["ssh_exit_code"], 0)
        # The adapter rejects only the GO result classification; native evidence
        # remains independently available in the partial report.
        self.assertTrue(report["native_result"]["ifnet_input_kpi_accepted"])

    def test_known_sender_clock_failures_remain_failed_and_non_measurements(self):
        cases = []
        before = _legacy_result()
        before.update({
            "status": "failed", "frames_attempted": 0, "frames_completed": 0,
            "sent": 0, "elapsed_ms": 1, "deadline_hit": False,
            "error_count": 1, "last_errno": 5,
            "stop_reason": "monotonic_clock_before_failed", "send_timing": [],
        })
        cases.append(before)

        after = _legacy_result()
        after["status"] = "failed"
        after["frames_attempted"] = after["frames_completed"] = after["sent"] = 1
        after["elapsed_ms"] = 1
        after["error_count"] = 1
        after["last_errno"] = 5
        after["stop_reason"] = "monotonic_clock_after_failed"
        after["send_timing"] = [dict(after["send_timing"][0], after_ns=None)]
        cases.append(after)

        end = _legacy_result()
        end["elapsed_ms"] = None
        end["finished_ns"] = None
        end["status"] = "failed"
        end["error_count"] = 1
        end["last_errno"] = 5
        end["stop_reason"] = "monotonic_clock_end_failed"
        cases.append(end)

        schedule = _legacy_result()
        schedule["status"] = "failed"
        schedule["frames_attempted"] = schedule["frames_completed"] = schedule["sent"] = 1
        schedule["elapsed_ms"] = 1
        schedule["error_count"] = 1
        schedule["last_errno"] = 5
        schedule["stop_reason"] = "schedule_sleep_error"
        schedule["send_timing"] = schedule["send_timing"][:1]
        cases.append(schedule)

        for raw in cases:
            with self.subTest(stop_reason=raw["stop_reason"]):
                wire = json.dumps(raw, separators=(",", ":"))
                report, completion, error = self._run_fake_pipe(
                    result=raw, first_line=wire, emit_started=True)
                self.assertIsNone(error)
                self.assertEqual(completion["sender_result"]["status"], "failed")
                sender = report["test088_sender"]
                self.assertEqual(sender["legacy_result_status"], "failed")
                self.assertEqual(sender["timing"]["status"], "failed_clock_or_schedule")
                self.assertEqual(sender["sender_result_event"]["stop_reason"],
                                 raw["stop_reason"])
                if raw["stop_reason"] == "monotonic_clock_end_failed":
                    self.assertIsNone(sender["legacy_result_counters"]["elapsed_ms"])
                    self.assertIsNone(sender["timing"]["analysis"]["sender_finished_ns"])

    def test_before_clock_failure_keeps_previously_sent_prefix(self):
        prefix = _legacy_result()
        prefix.update({
            "status": "failed", "frames_attempted": 2,
            "frames_completed": 2, "sent": 2, "elapsed_ms": 161,
            "deadline_hit": False, "error_count": 1, "last_errno": 5,
            "stop_reason": "monotonic_clock_before_failed",
            "send_timing": prefix["send_timing"][:2],
        })
        wire = json.dumps(prefix, separators=(",", ":"))
        report, completion, error = self._run_fake_pipe(
            result=prefix, first_line=wire, emit_started=True)
        self.assertIsNone(error)
        self.assertEqual(completion["sender_result"]["status"], "failed")
        sender = report["test088_sender"]
        self.assertEqual(sender["sender_result_event"]["stop_reason"],
                         "monotonic_clock_before_failed")
        self.assertEqual(sender["sender_result_event"]["frames_attempted"], 2)
        self.assertEqual(sender["timing"]["entry_count"], 2)
        self.assertEqual(len(sender["timing"]["analysis"]["send_attempts"]), 2)
        self.assertEqual(sender["timing"]["status"], "failed_clock_or_schedule")

    def test_same_boot_roc_clock_maps_with_usec_quantization_bound(self):
        fields = {
            "OwnerSerial": 1, "OwnerSessionToken": 2,
            "ContextGeneration": 3, "PowerGeneration": 4,
            "StationGeneration": 5, "RocGeneration": 6,
        }
        values = {}
        for prefix, time_us, notification, raw_flag in (
                ("NativeP2PRxTraceRocStart", 1000, 10, 1),
                ("NativeP2PRxTraceRocEnd", 1200, 11, 0)):
            values[prefix + "Present"] = 1
            values[prefix + "HostMonotonicPresent"] = 1
            values[prefix + "HostMonotonicUs"] = time_us
            values[prefix + "NotificationSerial"] = notification
            values[prefix + "RawStartFlag"] = raw_flag
            values[prefix + "CanonicalTransitionPresent"] = 1
            values[prefix + "CanonicalTransition"] = 1
            for key, value in fields.items():
                values[prefix + key] = value
        result = adapter.extract_final_roc_boundary({
            "controlled_trace_review": {"guard": {"valid": True, "values": values}}})
        self.assertTrue(result["cross_clock_mapping_proven"])
        self.assertEqual(result["roc_interval_ns"], [1_000_000, 1_200_999])
        self.assertEqual(result["conversion_max_quantization_error_ns"], 999)


if __name__ == "__main__":
    unittest.main()
