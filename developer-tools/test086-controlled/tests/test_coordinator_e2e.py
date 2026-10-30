#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import contextlib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
TOOL_DIR = ROOT / "developer-tools/test086-controlled"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = load_module("test086_controlled", TOOL_DIR / "test086_controlled.py")
coordinator = load_module(
    "test086_controlled_full_coordinator", TOOL_DIR / "controlled_run_coordinator.py")
router = load_module(
    "test086_controlled_runner", TOOL_DIR / "run_controlled_probe_once.py")


TOKEN = "0123456789abcdef0123456789abcdef"
READY_LINE = (
    "READY frames=16 interval_ms=80 mpdu_bytes=96 radiotap_bytes=10 "
    "packet_bytes=106 udp_payload_bytes=8 tx_flags=NOACK|NOSEQNO "
    "hardware_honoring=unknown")
MONITOR_LINE = (
    "MONITOR_READY mode=same_phy_active_ap_single_channel "
    "monitor_direct_channel_known=false monitor_wiphy=1 monitor_channel=0 "
    "monitor_frequency_mhz=0 ap_wiphy=1 ap_channel=149 ap_frequency_mhz=5745 "
    "ap_width_mhz=80 phy_single_channel_constraints_count=1 "
    "active_same_phy_channel_count=1 active_same_phy_channels=149 "
    "active_same_phy_frequencies_mhz=5745")


def native_ready_line():
    return "NATIVE_READY " + json.dumps({
        "event": "NATIVE_READY", "candidate": coordinator.BUILD,
        "source_ready_kind": coordinator.SOURCE_KIND,
        "expected_loaded_uuid": coordinator.UUID, "boot_epoch": 1793341000,
        "profile": coordinator.PROFILE, "diagnostic_duration_ms": 100,
        "requires_phone_ready": False, "native_preflight_ready": True,
        "helper_compiled": True, "claim_available": True, "host_tx_zero": True,
        "host_management_or_data_tx_allowed": False, "run_token_required": True,
        "one_arm_maximum": True, "retry_allowed": False,
    }, separators=(",", ":"))


def listener_ready_line(token):
    return json.dumps({
        "event": "LISTENER_READY", "interface": "awdl0", "ifindex": 8,
        "family": 6, "port": protocol.LISTENER_LOCAL_PORT,
        "group": protocol.LISTENER_GROUP, "timeout_ms": 15000,
        "bound_if": True, "pktinfo_enabled": True,
        "recv_anyif_requested": True, "recv_anyif_set": True,
        "recv_anyif_errno": 0, "run_token": token,
    }, separators=(",", ":"))


def listener_result_line(token):
    return json.dumps({
        "event": "LISTENER_RESULT", "status": "timeout_or_unmatched",
        "interface": "awdl0", "ifindex": 8, "datagrams": 0,
        "marker_match": False, "pktinfo_present": False,
        "pktinfo_ifindex_match": False, "destination_group_match": False,
        "source_link_local": False, "source_port_match": False,
        "payload_length": 0, "peer_address_serialized": False,
        "recv_anyif_requested": True, "recv_anyif_set": True,
        "recv_anyif_errno": 0, "run_token": token,
    }, separators=(",", ":"))


def native_result_line(token, *, saved=True, status=None):
    if status is None:
        status = "captured_no_retry" if saved else "native_report_write_failed_no_retry"
    return "NATIVE_RESULT " + json.dumps({
        "event": "NATIVE_RESULT", "run_token": token,
        "status": status,
        "report_saved": saved,
        "claim_consumed": True, "native_helper_invoked": True,
        "ifnet_input_kpi_accepted": False, "management_trace_valid": False,
        "peer_receipt_proven": False, "native_awdl_reply_proven": False,
        "airdrop_proven": False, "retry_allowed": False,
    }, separators=(",", ":"))


def native_arm_result_line(token):
    return "NATIVE_ARM_RESULT " + json.dumps({
        "event": "NATIVE_ARM_RESULT", "run_token": token,
        "exit_code": 0, "arm_property_accepted": True,
        "helper_summary": {"arm_property_accepted": True},
        "stderr_present": False, "helper_error_type": None,
        "arm_property_acceptance_is_not_roc_start": True,
        "retry_allowed": False,
    }, separators=(",", ":"))


def native_armed_line(token):
    return "NATIVE_ARMED " + json.dumps({
        "event": "NATIVE_ARMED", "run_token": token,
        "claim_consumed": True, "retry_allowed": False,
        "helper_invocation_pending": False, "arm_property_accepted": True,
        "roc_start_observed": False,
    }, separators=(",", ":"))


def native_arm_failed_line(token, *, code="ARM_PROPERTY_REJECTED"):
    return "NATIVE_ARM_FAILED " + json.dumps({
        "event": "NATIVE_ARM_FAILED", "run_token": token,
        "claim_consumed": True, "retry_allowed": False,
        "helper_invocation_pending": False, "arm_property_accepted": False,
        "failure_code": code, "helper_error_type": None,
    }, separators=(",", ":"))


def native_metadata():
    digest = "a" * 64
    return {
        "schema": "test086-controlled-probe-private/v1",
        "candidate": protocol.BUILD, "source_ready_kind": protocol.SOURCE_KIND,
        "requires_phone_ready": False, "armed": False,
        "status": "prepared_disarmed", "retry_allowed": False,
        "expected_loaded_uuid": protocol.EXPECTED_UUID,
        "profile": protocol.PROFILE, "diagnostic_duration_ms": 100,
        "receiver_gated": True, "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
        "owner_epoch_fields": list(protocol.OWNER_EPOCH_FIELDS),
        "required_zero_host_tx_counters": ["tx_a", "tx_b"],
        "source_sha256": {"source.c": digest},
        "source_binding": {
            "build_receipt_sha256": digest, "source_file_count": 396,
            "source_sha256_map_sha256": digest,
            "expected_binary_sha256": digest,
            "expected_info_plist_sha256": digest,
        },
        "sender": {"frames_max": 16, "interval_ms": 50,
                   "max_elapsed_seconds": 2},
    }


class FakeProcess:
    def __init__(self, pipe):
        self.pipe = pipe
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if (self.pipe.role == "native" and self.pipe.scenario == "native_hang" and
                self.returncode is None):
            raise subprocess.TimeoutExpired("fake-native", timeout)
        self.returncode = 0
        return self.returncode


class FakePipe:
    scenario = "success"
    event_trace = []

    def __init__(self, argv):
        self.argv = argv
        self.role = "native" if argv[0] == "fake-native" else "listener"
        self.process = FakeProcess(self)
        self.closed = False
        self.commands = []
        if self.role == "native":
            self.lines = [native_ready_line()]
        else:
            token = argv[argv.index("--run-token") + 1]
            if self.scenario == "listener_not_ready":
                self.lines = []
                self.process.returncode = 1
            else:
                self.lines = [listener_ready_line(token), listener_result_line(token)]

    def read_line(self, timeout):
        if not self.lines:
            return None
        line = self.lines.pop(0)
        if self.role == "native":
            event = line.split(" ", 1)[0]
        else:
            try:
                event = json.loads(line).get("event", "UNKNOWN")
            except (ValueError, TypeError):
                event = "UNKNOWN"
        self.event_trace.append(self.role + ":" + event)
        if line.startswith(("NATIVE_RESULT ", "NATIVE_ABORTED ", "NATIVE_REJECTED ")):
            self.process.returncode = 0
        return line

    def send_line(self, line):
        self.commands.append(line)
        self.event_trace.append("native:" + line.split(" ", 1)[0])
        if line.startswith("ARM "):
            token = line.split(" ", 1)[1]
            if self.scenario == "ack_missing":
                self.process.returncode = 2
            elif self.scenario == "native_arm_failed":
                self.lines.extend([native_arm_failed_line(token),
                                   native_arm_result_line(token),
                                   native_result_line(token)])
            elif self.scenario == "native_hang":
                self.lines.extend([native_armed_line(token),
                                   native_arm_result_line(token)])
            elif self.scenario == "sender_error_native_exited":
                self.lines.extend([native_armed_line(token),
                                   native_arm_result_line(token),
                                   native_result_line(token)])
                # Model a worker that wrote both terminal records and exited
                # before the sender path raised its transport error.
                self.process.returncode = 0
            else:
                native_status = {
                    "terminal_unknown": "session_terminal_unknown_no_retry",
                    "post_capture_unknown": "post_capture_unknown_no_retry",
                }.get(self.scenario)
                self.event_trace.append("native:HELPER_COMPLETE")
                self.lines.extend([native_armed_line(token),
                                   native_arm_result_line(token),
                                   native_result_line(token,
                                                      saved=self.scenario != "report_write_fail",
                                                      status=native_status)])
        elif line == "ABORT":
            self.lines.append("NATIVE_ABORTED " + json.dumps({
                "event": "NATIVE_ABORTED", "helper_invoked": False,
                "claim_consumed": False, "retry_allowed": False,
            }, separators=(",", ":")))

    def terminate(self, timeout=1.0):
        self.event_trace.append(self.role + ":TERMINATE")
        self.process.returncode = -15
        self.closed = True

    def close(self):
        self.closed = True


class FakeRouterSession:
    scenario = "success"
    event_trace = []
    last_ap = None

    def __init__(self, token):
        self.run_token = token
        self.control_consumed = False
        self.closed = False
        self.protocol_evidence = {}
        self.process = SimpleNamespace(poll=lambda: 0)

    @classmethod
    def start(cls, *, host, control_path, sender_binary, sender_sha256,
              run_token=None, ap="wlan1"):
        cls.last_ap = ap
        session = cls(run_token)
        monitor = protocol.parse_monitor_ready(MONITOR_LINE)
        sender = protocol.parse_sender_ready(READY_LINE)
        cls.event_trace.extend(["router:MONITOR_READY", "router:SENDER_READY"])
        session.protocol_evidence.update({
            "monitor_ready": monitor, "sender_ready": sender})
        return session, monitor, sender

    def _finish(self, control):
        self.control_consumed = True
        self.closed = True
        self.event_trace.append("router:" + control)
        sender_line = json.dumps({
            "event": "SENDER_RESULT", "status": "aborted" if control == "ABORT" else "complete",
            "frames_attempted": 0 if control == "ABORT" else 16,
            "frames_completed": 0 if control == "ABORT" else 16,
            "sent": 0 if control == "ABORT" else 16,
            "payload_bytes": 96, "mpdu_bytes": 96, "radiotap_bytes": 10,
            "packet_bytes": 106, "udp_payload_bytes": 8,
            "elapsed_ms": 0 if control == "ABORT" else 1200,
            "deadline_hit": False, "error_count": 0, "last_errno": 0,
            "stop_reason": "aborted_before_go" if control == "ABORT" else "complete",
            "tx_flags_requested": "NOACK|NOSEQNO", "hardware_honoring": "unknown",
        }, separators=(",", ":"))
        result = protocol.parse_sender_result(sender_line)
        cleanup = {"event": "MONITOR_CLEANUP", "run_token": self.run_token,
                   "monitor_removed": True, "ap_unchanged": True,
                   "temporary_files_removed": True}
        self.protocol_evidence["sender_result"] = result
        self.protocol_evidence["cleanup"] = cleanup
        return {"sender_result": result, "cleanup": cleanup,
                "remote_exit_code": 0, "local_send_is_not_rf_proof": True}

    def abort(self):
        return self._finish("ABORT")

    def go_once(self, *, on_control_write=None):
        if self.scenario == "sender_error_native_exited":
            self.control_consumed = True
            self.closed = True
            self.event_trace.append("router:GO_ERROR")
            raise protocol.ControlledProbeError("REMOTE_PROTOCOL_TIMEOUT")
        if on_control_write is not None:
            on_control_write("BEGIN")
        self.event_trace.append("router:GO_WRITE_BEGIN")
        result = self._finish("GO")
        self.event_trace.append("router:GO_WRITE_END")
        if on_control_write is not None:
            on_control_write("END")
        return result


class ControlledCoordinatorIntegrationTests(unittest.TestCase):
    def setUp(self):
        FakePipe.event_trace = []
        FakeRouterSession.event_trace = FakePipe.event_trace

    def run_fake(self, scenario):
        FakePipe.scenario = scenario
        FakeRouterSession.scenario = scenario
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sender_binary = root / "sender.bin"
            sender_binary.write_bytes(b"offline fake sender")
            sender_sha = hashlib.sha256(sender_binary.read_bytes()).hexdigest()
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(),
                                      pw_dir=str(root))
            receipt = {"candidate": coordinator.BUILD,
                       "mach_o_uuid": coordinator.UUID}
            metadata = native_metadata()
            build_path = root / "native-build-report-private.json"
            output_dir = root / "output"
            output_dir.mkdir(mode=0o700)
            output_dir.chmod(0o700)
            patches = [
                mock.patch.object(coordinator, "_modules", return_value=(protocol, router)),
                mock.patch.object(coordinator, "_workspace_account", return_value=account),
                mock.patch.object(coordinator, "_validate_bundle",
                                  return_value=(metadata, receipt, "a" * 64, build_path)),
                mock.patch.object(coordinator, "_prepare_run_dir"),
                mock.patch.object(coordinator, "_compile_listener",
                                  return_value=root / "fake-listener"),
                mock.patch.object(coordinator, "_native_argv", return_value=["fake-native"]),
                mock.patch.object(coordinator, "DEFAULT_SENDER_SHA256", sender_sha),
                mock.patch.object(coordinator, "ManagedPipe", FakePipe),
                mock.patch.object(router, "validate_transport", return_value=[]),
                mock.patch.object(router, "RouterSenderSession", FakeRouterSession),
            ]
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                    patches[5], patches[6], patches[7], patches[8], patches[9]:
                try:
                    result = coordinator.run_controlled_once(
                        host="root@router", control_path="/private/tmp/fake.sock",
                        metadata_path=root / "metadata.json", sender_binary=sender_binary,
                        sender_sha256=sender_sha, output_dir=output_dir / "run",
                        ap="wlan7")
                    return result, None, list(FakePipe.event_trace)
                except coordinator.CoordinatorError as error:
                    return None, error, list(FakePipe.event_trace)

    def test_full_success_orders_readiness_arm_ack_go_and_results(self):
        report, error, events = self.run_fake("success")
        self.assertIsNone(error)
        self.assertEqual(events, [
            "native:NATIVE_READY", "router:MONITOR_READY", "router:SENDER_READY",
            "listener:LISTENER_READY", "native:ARM", "native:HELPER_COMPLETE",
            "native:NATIVE_ARMED",
            "router:GO_WRITE_BEGIN", "router:GO", "router:GO_WRITE_END",
            "native:NATIVE_ARM_RESULT", "native:NATIVE_RESULT",
            "listener:LISTENER_RESULT",
        ])
        self.assertLess(events.index("native:HELPER_COMPLETE"),
                        events.index("native:NATIVE_ARMED"))
        boot_events = [item["event"] for item in
                       report["events_parent_boot_monotonic_ns"]]
        self.assertLess(boot_events.index("ROUTER_GO_WRITE_BEGIN"),
                        boot_events.index("ROUTER_GO_WRITE_END"))
        self.assertEqual(report["status"], "captured_no_peer_or_airdrop_proof")
        self.assertEqual(report["host_probe_protocol"],
                         "setter_success_before_go_v2")
        self.assertEqual(report["sender_profile"], {
            "frames_max": 16, "interval_ms": 80, "hard_deadline_ms": 2000,
        })
        self.assertEqual(FakeRouterSession.last_ap, "wlan7")
        self.assertTrue(report["complete"])
        self.assertFalse(report["partial"])
        self.assertTrue(report["boot_claim_consumed"])
        self.assertFalse(report["peer_receipt_proven"])
        self.assertFalse(report["native_awdl_reply_proven"])
        self.assertFalse(report["airdrop_proven"])
        self.assertFalse(report["udp_marker_received"])
        self.assertEqual(report["listener_result"]["status"], "timeout_or_unmatched")

    def test_listener_not_ready_aborts_both_gates_without_arm(self):
        report, error, events = self.run_fake("listener_not_ready")
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "AWDL_LISTENER_READY_MISSING")
        self.assertEqual(events, [
            "native:NATIVE_READY", "router:MONITOR_READY", "router:SENDER_READY",
            "router:ABORT", "native:ABORT", "native:NATIVE_ABORTED",
            "listener:TERMINATE",
        ])
        self.assertIsNone(error.partial_report["native_armed_ack"])
        self.assertFalse(error.partial_report["boot_claim_consumed"])

    def test_missing_arm_ack_never_sends_go_or_retries(self):
        report, error, events = self.run_fake("ack_missing")
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        self.assertIn("NATIVE_ARM_ACK_MISSING", error.code)
        self.assertEqual(events, [
            "native:NATIVE_READY", "router:MONITOR_READY", "router:SENDER_READY",
            "listener:LISTENER_READY", "native:ARM", "router:ABORT",
            "listener:LISTENER_RESULT",
        ])
        self.assertIsNone(error.partial_report["boot_claim_consumed"])
        self.assertEqual(error.partial_report["claim_outcome"],
                         "unknown_after_arm_request_no_retry")
        self.assertFalse(error.partial_report["retry_allowed"])
        self.assertEqual(error.partial_report["sender_result"]["sent"], 0)
        self.assertEqual(error.partial_report["listener_result"]["status"],
                         "timeout_or_unmatched")
        self.assertEqual(error.partial_report["status"],
                         "NATIVE_ARM_ACK_MISSING_after_arm_request_no_retry")

    def test_post_claim_worker_timeout_is_killed_without_second_go(self):
        report, error, events = self.run_fake("native_hang")
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        self.assertIn("NATIVE_FINAL_RESULT_MISSING", error.code)
        self.assertEqual(error.partial_report["boot_claim_consumed"], True)
        self.assertEqual(error.partial_report["claim_outcome"], "consumed_no_retry")
        self.assertEqual(error.partial_report["native_worker_cleanup"],
                         "terminated_after_result_deadline")
        self.assertEqual(events, [
            "native:NATIVE_READY", "router:MONITOR_READY", "router:SENDER_READY",
            "listener:LISTENER_READY", "native:ARM", "native:NATIVE_ARMED",
            "router:GO_WRITE_BEGIN", "router:GO", "router:GO_WRITE_END",
            "native:NATIVE_ARM_RESULT", "native:TERMINATE",
            "listener:LISTENER_RESULT",
        ])

    def test_arm_failure_consumes_claim_aborts_sender_and_never_goes(self):
        report, error, events = self.run_fake("native_arm_failed")
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        partial = error.partial_report
        self.assertIn("NATIVE_ARM_FAILED_NO_GO", error.code)
        self.assertTrue(partial["boot_claim_consumed"])
        self.assertEqual(partial["claim_outcome"], "consumed_no_retry")
        self.assertEqual(partial["native_arm_failed"]["failure_code"],
                         "ARM_PROPERTY_REJECTED")
        self.assertEqual(partial["sender_result"]["status"], "aborted")
        self.assertEqual(partial["sender_result"]["sent"], 0)
        self.assertNotIn("router:GO", events)
        self.assertNotIn("router:GO_WRITE_BEGIN", events)
        self.assertIn("router:ABORT", events)

    def test_sender_error_drains_exited_native_receipts_and_listener_result(self):
        report, error, events = self.run_fake("sender_error_native_exited")
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        partial = error.partial_report
        self.assertEqual(partial["boot_claim_consumed"], True)
        self.assertIsNotNone(partial["native_arm_result"])
        self.assertIsNotNone(partial["native_result"])
        self.assertEqual(partial["listener_result"]["status"],
                         "timeout_or_unmatched")
        self.assertEqual(partial["listener_worker_cleanup"],
                         "exited_after_result_window")
        self.assertLess(events.index("native:NATIVE_RESULT"),
                        events.index("listener:LISTENER_RESULT"))
        self.assertNotIn("listener:TERMINATE", events)

    def test_managed_pipe_drains_records_after_child_exit(self):
        pipe = coordinator.ManagedPipe([
            sys.executable, "-c", "print('first'); print('second')"])
        try:
            pipe.process.wait(timeout=5.0)
            self.assertIsNotNone(pipe.process.poll())
            self.assertEqual(pipe.read_line(1.0), "first")
            self.assertEqual(pipe.read_line(1.0), "second")
            self.assertIsNone(pipe.read_line(1.0))
        finally:
            pipe.close()

    def test_native_report_write_failure_keeps_streamed_and_listener_results(self):
        report, error, events = self.run_fake("report_write_fail")
        self.assertIsNone(error)
        self.assertEqual(report["status"],
                         "native_report_write_failed_no_retry")
        self.assertFalse(report["complete"])
        self.assertTrue(report["partial"])
        self.assertFalse(report["native_result"]["report_saved"])
        self.assertEqual(report["listener_result"]["status"], "timeout_or_unmatched")
        self.assertEqual(events[4:9], [
            "native:ARM", "native:HELPER_COMPLETE", "native:NATIVE_ARMED",
            "router:GO_WRITE_BEGIN", "router:GO"])

    def test_unknown_native_runtime_status_stays_partial(self):
        for scenario, expected in (
                ("terminal_unknown", "session_terminal_unknown_no_retry"),
                ("post_capture_unknown", "post_capture_unknown_no_retry")):
            with self.subTest(scenario=scenario):
                report, error, _ = self.run_fake(scenario)
                self.assertIsNone(error)
                self.assertEqual(report["status"], expected)
                self.assertFalse(report["complete"])
                self.assertTrue(report["partial"])
                self.assertFalse(report["airdrop_proven"])

    def test_cli_returns_nonzero_for_unknown_and_report_write_failure(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(),
                                  pw_dir=tempfile.gettempdir())
        for status in ("session_terminal_unknown_no_retry",
                       "post_capture_unknown_no_retry",
                       "native_report_write_failed_no_retry"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                output_dir = Path(temporary) / "run"
                output_dir.mkdir(mode=0o700)
                output_dir.chmod(0o700)
                result = {"schema": "test086-controlled-run-private/v1",
                          "candidate": coordinator.BUILD,
                          "source_ready_kind": coordinator.SOURCE_KIND,
                          "status": status, "complete": False, "partial": True,
                          "retry_allowed": False, "efi_modified": False,
                          "peer_receipt_proven": False, "airdrop_proven": False}
                stdout = io.StringIO()
                with mock.patch.object(coordinator, "_workspace_account",
                                       return_value=account), \
                        mock.patch.object(coordinator, "run_controlled_once",
                                          return_value=result) as run_mock, \
                        contextlib.redirect_stdout(stdout):
                    code = coordinator.main([
                        "--run", "--host", "root@router", "--control-path",
                        "/tmp/fake.sock", "--ap", "wlan7",
                        "--output-dir", str(output_dir)])
                self.assertEqual(code, 2)
                self.assertEqual(run_mock.call_args.kwargs["ap"], "wlan7")
                self.assertEqual(stdout.getvalue().strip(), "CONTROLLED_RUN_PARTIAL")
                saved = json.loads((output_dir / "controlled-run-private.json").read_text())
                self.assertEqual(saved["status"], status)
                self.assertTrue(saved["partial"])


if __name__ == "__main__":
    unittest.main()
