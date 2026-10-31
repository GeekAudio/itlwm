from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import controlled_run_test099 as controlled


TOKEN = "0123456789abcdef0123456789abcdef"


def ready_event(*, remaining: int = controlled.MINIMUM_REMAINING_US) -> dict:
    now = 500_000
    return {
        "run_token": TOKEN,
        "start_observed_us": 450_000,
        "observed_now_us": now,
        "hard_deadline_us": now + remaining,
    }


class ControlledRun099Tests(unittest.TestCase):
    def test_plan_is_inert_and_advertises_test099_profile_and_gate(self):
        result = controlled.plan(Path("/missing/metadata.json"))
        self.assertEqual(result["mode"], "plan")
        self.assertEqual(result["tool_revision"], "Test099")
        self.assertEqual(result["sender_contract"]["frames_max"], 4)
        self.assertEqual(result["sender_contract"]["interval_ms"], 10)
        self.assertEqual(result["sender_contract"]["max_elapsed_seconds"], 0.04)
        self.assertEqual(result["minimum_ready_remaining_us"], 60_000)
        self.assertFalse(result["rf_triggered"])
        self.assertFalse(result["efi_modified"])
        self.assertFalse(result["retry_allowed"])

    def test_remote_sender_command_is_exactly_four_frames_ten_ms(self):
        restore = controlled.configure_test099_profile()
        try:
            binary = b"offline sender fixture"
            script = controlled.PROTOCOL.build_remote_monitor_sender_script(
                binary=binary,
                binary_sha256=hashlib.sha256(binary).hexdigest(),
                run_token=TOKEN,
                ap="wlan7",
            )
        finally:
            restore()
        self.assertIn("--count 4 --interval-ms 10", script)
        self.assertNotIn("--count 16 --interval-ms 80", script)

    def test_pre_go_gate_accepts_exact_sixty_ms_and_rejects_less(self):
        passed = controlled.validate_pre_go_window(
            ready_event(remaining=60_000), 500_000)
        failed = controlled.validate_pre_go_window(
            ready_event(remaining=60_000), 500_001)
        self.assertEqual(passed["status"], "passed")
        self.assertEqual(passed["remaining_at_go_gate_us"], 60_000)
        self.assertEqual(passed["reader_to_go_gate_delay_us"], 0)
        self.assertEqual(failed["status"], "expired_before_go")
        self.assertEqual(failed["remaining_at_go_gate_us"], 59_999)
        with self.assertRaises(controlled.ControlledRunError):
            controlled.validate_pre_go_window(ready_event(), 499_999)

    def test_go_guard_refuses_expired_ready_before_consuming_sender_control(self):
        original_calls = []
        original_method = controlled.TEST088.Test088SenderSession.go_once

        def fake_go_once(session, *, on_control_write=None):
            original_calls.append("GO")
            session.control_consumed = True
            if on_control_write:
                on_control_write("BEGIN")
                on_control_write("END")
            return {"go": True}

        report = {"native_armed_ack": {"native_rx_ready": ready_event()}}
        capture = types.SimpleNamespace(report=report)
        session = types.SimpleNamespace(capture=capture, control_consumed=False)
        with mock.patch.object(controlled.TEST088.Test088SenderSession,
                               "go_once", fake_go_once):
            restore = controlled.install_go_deadline_guard(clock=lambda: 500_001)
            try:
                with self.assertRaises(controlled.PROTOCOL.ControlledProbeError):
                    controlled.TEST088.Test088SenderSession.go_once(session)
            finally:
                restore()
        self.assertEqual(original_calls, [])
        self.assertFalse(session.control_consumed)
        self.assertFalse(report["native_rx_go_gate"]["go_written"])
        self.assertEqual(report["native_rx_go_gate"]["status"], "failed_closed")

    def test_actual_finish_rechecks_at_begin_and_never_writes_expired_go(self):
        class FakeStream:
            def __init__(self):
                self.write_calls = []
                self.flush_calls = 0
                self.closed = False

            def write(self, value):
                self.write_calls.append(value)

            def flush(self):
                self.flush_calls += 1

            def close(self):
                self.closed = True

        class FakeSelector:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        stdin = FakeStream()
        stdout = FakeStream()
        selector = FakeSelector()
        process = types.SimpleNamespace(stdin=stdin, stdout=stdout)
        transport = types.SimpleNamespace(
            closed=False, control_consumed=False, process=process,
            selector=selector, run_token=TOKEN, read_state={}, deadline=0,
            protocol_evidence={})
        report = {
            "boot_claim_consumed": True,
            "claim_outcome": "consumed_no_retry",
            "native_armed_ack": {"native_rx_ready": ready_event()},
        }
        wrapped = controlled.TEST088.Test088SenderSession(
            transport, types.SimpleNamespace(report=report))
        terminated = []
        observed_phases = []
        times = iter([500_000, 500_001])

        with mock.patch.object(controlled.TEST088.ROUTER, "_terminate_process",
                               lambda value: terminated.append(value)):
            restore = controlled.install_go_deadline_guard(clock=lambda: next(times))
            try:
                with self.assertRaises(controlled.PROTOCOL.ControlledProbeError) as error:
                    controlled.TEST088.Test088SenderSession.go_once(
                        wrapped, on_control_write=observed_phases.append)
            finally:
                restore()

        self.assertEqual(error.exception.code,
                         "NATIVE_RX_WINDOW_TOO_SHORT_AT_GO_WRITE")
        self.assertTrue(transport.control_consumed)
        self.assertTrue(transport.closed)
        self.assertTrue(selector.closed)
        self.assertTrue(stdin.closed)
        self.assertTrue(stdout.closed)
        self.assertEqual(stdin.write_calls, [])
        self.assertEqual(stdin.flush_calls, 0)
        self.assertEqual(observed_phases, ["BEGIN"])
        self.assertEqual(terminated, [process])
        gate = report["native_rx_go_gate"]
        self.assertEqual(gate["status"], "failed_closed")
        self.assertEqual(gate["reason"], "NATIVE_RX_WINDOW_TOO_SHORT_AT_GO_WRITE")
        self.assertEqual(gate["go_write_begin_remaining_us"], 59_999)
        self.assertTrue(gate["no_go_written"])
        self.assertFalse(gate["go_written"])
        self.assertTrue(gate["sender_control_consumed"])
        self.assertTrue(gate["claim_consumed"])
        self.assertEqual(report["claim_outcome"], "consumed_no_retry")
        self.assertFalse(gate["retry_allowed"])

    def test_go_guard_records_same_clock_delay_and_write_bracket(self):
        samples = iter([500_001, 500_002, 500_004])
        original_calls = []

        def fake_go_once(session, *, on_control_write=None):
            original_calls.append("GO")
            session.control_consumed = True
            on_control_write("BEGIN")
            on_control_write("END")
            return {"go": True}

        report = {"native_armed_ack": {"native_rx_ready": ready_event(remaining=70_000)}}
        session = types.SimpleNamespace(
            capture=types.SimpleNamespace(report=report), control_consumed=False)
        with mock.patch.object(controlled.TEST088.Test088SenderSession,
                               "go_once", fake_go_once):
            restore = controlled.install_go_deadline_guard(
                clock=lambda: next(samples))
            try:
                result = controlled.TEST088.Test088SenderSession.go_once(session)
            finally:
                restore()
        self.assertEqual(result, {"go": True})
        self.assertEqual(original_calls, ["GO"])
        self.assertEqual(report["native_rx_go_gate"]["go_gate_observed_us"], 500_001)
        self.assertEqual(report["native_rx_go_gate"]["go_write_begin_us"], 500_002)
        self.assertEqual(report["native_rx_go_gate"]["go_write_begin_remaining_us"], 69_998)
        self.assertEqual(report["native_rx_go_gate"]["go_write_begin_gate_status"], "passed")
        self.assertEqual(report["native_rx_go_gate"]["go_write_end_us"], 500_004)
        self.assertTrue(report["native_rx_go_gate"]["go_written"])

    def test_prearm_rejection_happens_before_reader_compile_or_run_dir(self):
        build = {"mach_o_uuid": "01234567-89AB-CDEF-0123-456789ABCDEF"}
        deployment = {"mach_o_uuid": build["mach_o_uuid"],
                      "binary_sha256": "a" * 64}
        with mock.patch.object(controlled, "validate_deployment",
                               return_value=(build, deployment, b"build", b"deploy")), \
                mock.patch.object(controlled.TEST088, "_read_current_boot_epoch",
                                  return_value=1_793_460_999), \
                mock.patch.object(controlled.RUNTIME_BINDING,
                                  "validate_prearm_bundle",
                                  side_effect=controlled.RUNTIME_BINDING.RuntimeBindingError(
                                      "preowner_observation_contract_mismatch")), \
                mock.patch.object(controlled.START_BARRIER, "compile_reader") as compile_reader, \
                mock.patch.object(controlled, "test099_run_dir") as run_dir:
            with self.assertRaises(controlled.ControlledRunError) as error:
                controlled.run_once(
                    host="root@192.0.2.1", control_path="/tmp/unused-control.sock",
                    metadata_path=Path("/tmp/unused-metadata.json"), ap="wlan7")
        self.assertIn("PREARM_BINDING_REJECTED", str(error.exception))
        compile_reader.assert_not_called()
        run_dir.assert_not_called()


if __name__ == "__main__":
    unittest.main()
