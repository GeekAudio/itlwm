#!/usr/bin/env python3
"""Offline terminal-flow regression for Test123 over the frozen T087/T088 path.

The test invokes the real T087 coordinator state machine and real T088 sender
reader. Only the native/listener pipes, OpenWrt transport constructor, bundle
preflight, and clock are fakes; no device, router, socket, or radio is used.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from contextlib import ExitStack
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "developer-tools/test087") not in sys.path:
    sys.path.insert(0, str(ROOT / "developer-tools/test087"))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"offline test component missing: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROTOCOL = load("test123_terminal_t087_protocol",
                ROOT / "developer-tools/test087/test087_controlled.py")
COORDINATOR = load("test123_terminal_t087_coordinator",
                   ROOT / "developer-tools/test087/controlled_run_coordinator.py")
T088 = load("test123_terminal_t088_adapter",
            ROOT / "developer-tools/test088/controlled_run_test088.py")
T088.BASE = COORDINATOR
T088.PROTOCOL = PROTOCOL
SENDER_PROTOCOL = load(
    "test123_terminal_sender_protocol",
    ROOT / "developer-tools/test123/router-status/dual_sender_protocol_test123.py")
SENDER_FIXTURES = load(
    "test123_terminal_sender_fixture_helpers",
    ROOT / "developer-tools/test123/router-status/test_dual_sender_protocol_test123.py")
IDENTITY_FIXTURES = load(
    "test123_terminal_identity_fixture_helpers",
    ROOT / "developer-tools/test123/test_binding_independent_test123.py")
TEST123_COORDINATOR = load(
    "test123_terminal_coordinator_under_test",
    ROOT / "developer-tools/test123/coordinate_test123_rx149.py")

TOKEN = SENDER_FIXTURES.TOKEN
NONCE = SENDER_FIXTURES.NONCE


class FakeClock:
    def __init__(self):
        self.value = 10_000_000

    def descriptor(self):
        return {"status": "available", "clock_domain": "fake-test-only"}

    def sample_pair(self):
        self.value += 100
        return {
            "status": "available",
            "clock_domain": "MachBootClock",
            "process_clock_domain": "python_time_monotonic_ns",
            "process_epoch_shared": False,
            "process_monotonic_ns": self.value + 1_000,
            "boot_monotonic_ns": self.value,
            "boot_sample_lower_ns": self.value - 50,
            "boot_sample_upper_ns": self.value + 50,
        }


class FakePipeProcess:
    def __init__(self):
        self.returncode = None
        self.stdin = None
        self.stdout = None
        self.wait_calls = 0
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        self.returncode = 0
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15


class FakeSenderStdin:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)
        return len(data)

    def flush(self):
        return None

    def close(self):
        self.closed = True


class FakeSenderStdout:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeSenderProcess:
    def __init__(self, exit_code):
        self.stdin = FakeSenderStdin()
        self.stdout = FakeSenderStdout()
        self.returncode = None
        self.exit_code = exit_code
        self.wait_calls = 0
        self.terminate_calls = 0
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        self.returncode = self.exit_code
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1
        self.terminated = True
        self.returncode = -15


class FakeSenderSelector:
    def __init__(self, lines):
        self.lines = list(lines)
        self.closed = False

    def register(self, *_args, **_kwargs):
        return None

    def close(self):
        self.closed = True


class FakeManagedPipe:
    instances = []

    def __init__(self, argv):
        self.argv = list(argv)
        self.process = FakePipeProcess()
        self.closed = False
        self.commands = []
        if "--native-worker" in self.argv:
            self.kind = "native"
            self.lines = [_event_line("NATIVE_READY", _native_ready())]
        else:
            self.kind = "listener"
            token = self.argv[self.argv.index("--run-token") + 1]
            self.lines = [
                json.dumps(_listener_ready(token), separators=(",", ":")),
                json.dumps(_listener_result(token), separators=(",", ":")),
            ]
        self.instances.append(self)

    def read_line(self, timeout):
        if self.lines:
            return self.lines.pop(0)
        return None

    def send_line(self, line):
        self.commands.append(line)
        if self.kind != "native" or not line.startswith("ARM "):
            return
        token = line.split(" ", 1)[1]
        self.lines.extend([
            _event_line("NATIVE_ARMED", {
                "event": "NATIVE_ARMED", "run_token": token,
                "claim_consumed": True, "retry_allowed": False,
                "helper_invocation_pending": False,
                "arm_property_accepted": True, "preowner_arm_accepted": True,
                "roc_start_observed": False,
            }),
            _event_line("NATIVE_ARM_RESULT", {
                "event": "NATIVE_ARM_RESULT", "run_token": token,
                "exit_code": 0, "arm_property_accepted": True,
                "preowner_arm_accepted": True, "helper_summary": {},
                "helper_candidate_binding_matches": True,
                "stderr_present": False, "helper_error_type": None,
                "arm_property_acceptance_is_not_roc_start": True,
                "retry_allowed": False,
            }),
            _event_line("NATIVE_RESULT", _native_result(token)),
        ])

    def terminate(self, timeout=1.0):
        self.process.terminate()
        self.close()

    def close(self):
        self.closed = True


def _event_line(prefix: str, value: dict) -> str:
    return prefix + " " + json.dumps(value, separators=(",", ":"))


def _native_ready():
    return {
        "event": "NATIVE_READY", "candidate": "25G332-Test122",
        "source_ready_kind": "controlled_probe",
        "expected_loaded_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "expected_archive_binary_sha256": "a" * 64,
        "boot_epoch": 1001,
        "profile": "native_awdl_rx149_preowner_observation",
        "diagnostic_duration_ms": 100,
        "preowner_observation_duration_ms": 4000,
        "requires_phone_ready": False, "native_preflight_ready": True,
        "helper_compiled": True, "claim_available": True, "host_tx_zero": True,
        "host_management_or_data_tx_allowed": False,
        "run_token_required": True, "one_arm_maximum": True,
        "retry_allowed": False,
    }


def _native_result(token: str):
    return {
        "event": "NATIVE_RESULT", "run_token": token,
        "status": "captured_no_retry", "report_saved": True,
        "claim_consumed": True, "native_helper_invoked": True,
        "ifnet_input_kpi_accepted": False, "management_trace_valid": True,
        "preowner_snapshot_complete": True, "preowner_arm_accepted": True,
        "peer_receipt_proven": False, "native_awdl_reply_proven": False,
        "airdrop_proven": False, "retry_allowed": False,
    }


def _listener_ready(token: str):
    return {
        "event": "LISTENER_READY", "interface": "awdl0", "ifindex": 31,
        "family": 6, "port": PROTOCOL.LISTENER_LOCAL_PORT,
        "group": PROTOCOL.LISTENER_GROUP, "timeout_ms": 15000,
        "bound_if": True, "pktinfo_enabled": True,
        "recv_anyif_requested": True, "recv_anyif_set": True,
        "recv_anyif_errno": 0, "run_token": token,
    }


def _listener_result(token: str):
    return {
        "event": "LISTENER_RESULT", "status": "timeout_or_unmatched",
        "interface": "awdl0", "ifindex": 31, "datagrams": 0,
        "marker_match": False, "pktinfo_present": False,
        "pktinfo_ifindex_match": False, "destination_group_match": False,
        "source_link_local": False, "source_port_match": False,
        "payload_length": 0, "peer_address_serialized": False,
        "recv_anyif_requested": True, "recv_anyif_set": True,
        "recv_anyif_errno": 0, "run_token": token,
    }


def _sender_started(token: str):
    return {
        "event": "SENDER_STARTED", "schema": SENDER_PROTOCOL.SCHEMA,
        "tool_test": "Test123", "running_kernel_test": "Test122",
        "packet_set_schema": SENDER_PROTOCOL.PACKETSET_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC",
        "observation_time_semantics": "userspace_recvmsg_return",
        "run_token": token, "wire_nonce_hex": NONCE,
        "driver_rx_lease_ms": 100, "go_received_ns": 1_000_000_000,
        "started_ns": 1_001_000_000,
        "send_deadline_ns": 1_041_000_000,
        "observer_deadline_ns": 3_041_000_000,
        "go_to_start_ns": 1_000_000, "go_to_start_max_ns": 5_000_000,
        "send_budget_ns": 40_000_000, "status_tail_ns": 2_000_000_000,
        "frames_requested": 4, "interval_ms": 10,
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "intel_arm_invoked": False, "boot_claim_used": False,
    }


class TerminalFlowTests(unittest.TestCase):
    def setUp(self):
        FakeManagedPipe.instances = []
        self.temp = tempfile.TemporaryDirectory(prefix="test123-terminal-flow-")
        self.root = Path(self.temp.name)
        self.binary = self.root / "sender-fixture"
        self.binary.write_bytes(b"offline sender fixture; not executed\n")
        self.binary_sha = __import__("hashlib").sha256(
            self.binary.read_bytes()).hexdigest()
        self.metadata_path = self.root / "metadata.json"
        self.listener_binary = self.root / "listener-fixture"
        self.listener_binary.write_bytes(b"offline listener fixture\n")
        self.listener_sha = __import__("hashlib").sha256(
            self.listener_binary.read_bytes()).hexdigest()
        self.uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        self.archive_sha = "a" * 64
        self.metadata = {
            "candidate": "25G332-Test122",
            "profile": "native_awdl_rx149_preowner_observation",
            "expected_loaded_uuid": self.uuid,
            "minimum_boot_epoch_exclusive": 1000,
            "source_binding": {"expected_binary_sha256": self.archive_sha},
        }
        self.receipt = {
            "candidate": self.metadata["candidate"],
            "mach_o_uuid": self.uuid,
            "binary_sha256": self.archive_sha,
        }
        binding = TEST123_COORDINATOR.BINDING
        binding.clear_active_run()
        router_receipt = IDENTITY_FIXTURES._router_receipt()
        target_receipt = IDENTITY_FIXTURES._target_receipt(uuid=self.uuid)
        self.packet_set_raw, self.test123_manifest = binding.bind_runtime_identities(
            IDENTITY_FIXTURES._metadata(self.uuid), router_receipt, target_receipt,
            expected_boot_epoch=target_receipt["boot_epoch"],
            expected_uuid=self.uuid,
            router_receipt_sha256=IDENTITY_FIXTURES._canonical_sha(router_receipt),
            now=IDENTITY_FIXTURES.NOW,
            wire_nonce_hex=NONCE,
            wifi_sequence_base=0x321, awdl_sequence_base=0x4567)
        self.packet_manifest = binding.PACKETSET.validate_packet_set(
            self.packet_set_raw)
        SENDER_PROTOCOL.bind_packet_set(self.packet_set_raw)
        self.sender_processes = []
        self.sender_selectors = []
        self.addCleanup(SENDER_PROTOCOL.clear_packet_set_binding)
        self.addCleanup(binding.clear_active_run)
        self.addCleanup(self.temp.cleanup)

    def _sender_start(self, *, scenario: str, run_token: str, **_kwargs):
        token = run_token
        send_complete = scenario != "sender_failed"
        monitor_complete = scenario != "monitor_incomplete"
        value = SENDER_FIXTURES.sender_result(
            self.packet_manifest, send_complete=send_complete,
            monitor_complete=monitor_complete)
        value["run_token"] = token
        if scenario == "monitor_malformed":
            value["monitor_observation"].pop("classification_complete")
        # Test088 is intentionally the production legacy seam. T123 validates
        # this same retained raw event after the coordinator returns.
        if scenario != "monitor_malformed":
            SENDER_PROTOCOL.validate_result(
                value, token, NONCE, self.packet_manifest)
        started = _sender_started(token)
        cleanup = {
            "event": "MONITOR_CLEANUP", "run_token": token,
            "monitor_removed": True, "ap_unchanged": True,
            "temporary_files_removed": True,
        }
        lines = [
            json.dumps(started, separators=(",", ":")),
            json.dumps(value, separators=(",", ":")),
            "CLEANUP " + json.dumps(cleanup, separators=(",", ":")),
        ]
        if scenario == "sender_result_truncated":
            lines[1] = '{"event":"SENDER_RESULT","status":'
        process = FakeSenderProcess(
            0 if value["status"] == "complete" else 1)
        self.sender_processes.append(process)
        selector = FakeSenderSelector(lines)
        self.sender_selectors.append(selector)
        session = SimpleNamespace(
            process=process, selector=selector, read_state={"buffer": b""},
            deadline=1.0e30, run_token=token,
            sender_sha256=self.binary_sha, closed=False,
            control_consumed=False, protocol_evidence={})
        return session, {"ap_channel": 149}, {"send_started": False}

    @staticmethod
    def _read_sender_line(selector, _process, _state, _deadline):
        return selector.lines.pop(0) if selector.lines else None

    def _run(self, scenario: str, *, with_t123_go_wrapper: bool = False):
        protocol = PROTOCOL
        owner = self

        class FakeRouterSenderSession:
            @classmethod
            def start(cls, **kwargs):
                return owner._sender_start(scenario=scenario, **kwargs)

        router = SimpleNamespace(
            validate_transport=lambda *_args: [],
            RouterSenderSession=FakeRouterSenderSession,
            _read_protocol_line=self._read_sender_line,
            _terminate_process=lambda process: process.terminate(),
        )
        fake_clock_module = SimpleNamespace(MachBootClock=FakeClock)
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with ExitStack() as stack:
            patches = [
                mock.patch.object(COORDINATOR, "_modules",
                                  return_value=(protocol, router)),
                mock.patch.object(T088, "ROUTER", router),
                mock.patch.object(COORDINATOR, "_workspace_account",
                                  return_value=account),
                mock.patch.object(COORDINATOR, "_validate_bundle",
                                  return_value=(self.metadata, self.receipt,
                                                "b" * 64, self.metadata_path)),
                mock.patch.object(COORDINATOR, "_prepare_run_dir"),
                mock.patch.object(COORDINATOR, "_compile_listener",
                                  return_value=self.listener_binary),
                mock.patch.object(COORDINATOR, "_load_module",
                                  return_value=fake_clock_module),
                mock.patch.object(COORDINATOR, "DEFAULT_SENDER_SHA256",
                                  self.binary_sha),
                mock.patch.object(protocol, "validate_private_metadata",
                                  return_value=[]),
                mock.patch.object(protocol, "SENDER_FRAMES", 4),
                mock.patch.object(protocol, "SENDER_TX_FLAGS", "NOSEQNO"),
                mock.patch("secrets.token_hex", return_value=TOKEN),
                mock.patch.object(COORDINATOR, "ManagedPipe", FakeManagedPipe),
            ]
            for patcher in patches:
                stack.enter_context(patcher)

            if with_t123_go_wrapper:
                runner = TEST123_COORDINATOR.RUNNER
                legacy_listener_ready_parser = protocol.parse_listener_ready
                legacy_listener_result_parser = protocol.parse_listener_result
                for target, name, value in (
                        (runner, "BASE", COORDINATOR),
                        (runner, "PROTOCOL", protocol),
                        (runner, "TEST088", T088),
                        (runner, "ROUTER", router),
                        (runner, "ACTIVE_PACKET_SET", self.packet_set_raw),
                        (runner, "ACTIVE_PACKET_MANIFEST", self.test123_manifest),
                        (runner, "ACTIVE_LISTENER_EXPECTATION",
                         TEST123_COORDINATOR.LISTENER_PROTOCOL.expected_binding(
                             self.test123_manifest, 31)),
                        (runner, "LISTENER_BINARY", self.listener_binary),
                        (runner, "LISTENER_SHA256", self.listener_sha),
                        (TEST123_COORDINATOR, "SENDER_PROTOCOL", SENDER_PROTOCOL),
                        (TEST123_COORDINATOR, "_ORIGINAL_TEST104_CONFIGURE",
                         lambda: (lambda: None)),
                ):
                    stack.enter_context(mock.patch.object(
                        target, name, value, create=True))
                restore_profile = TEST123_COORDINATOR._configure_test123_profile()
                stack.callback(restore_profile)
                # This regression targets the T123 GO exception wrapper. Keep
                # the frozen T087 listener grammar for the fake terminal pipe.
                stack.enter_context(mock.patch.object(
                    PROTOCOL, "parse_listener_ready",
                    legacy_listener_ready_parser))
                stack.enter_context(mock.patch.object(
                    PROTOCOL, "parse_listener_result",
                    legacy_listener_result_parser))

            capture = T088._RunCapture("25G332-Test122")
            originals = T088._decorate_run(
                capture, expected_epoch=1001, candidate="25G332-Test122",
                expected_uuid=self.uuid,
                expected_archive_binary_sha256=self.archive_sha,
                minimum_boot_epoch_exclusive=1000,
                profile="native_awdl_rx149_preowner_observation")
            stack.callback(T088._restore_run, originals)
            try:
                report = COORDINATOR.run_controlled_once(
                    host="router-fixture", control_path="/unused/test-control-socket",
                    metadata_path=self.metadata_path, sender_binary=self.binary,
                    sender_sha256=self.binary_sha, output_dir=self.root / "out",
                    ap="wlan7")
            except COORDINATOR.CoordinatorError as error:
                if error.partial_report is None:
                    raise
                report = error.partial_report
            report = capture.attach(report)
        sender_event = (report.get("test088_sender", {}).get(
            "sender_result_event"))
        try:
            report["openwrt_tx_provenance"] = SENDER_PROTOCOL.classify_sender_result(
                sender_event, NONCE, self.packet_manifest)
        except (SENDER_PROTOCOL.SenderAdapterError, TypeError, AttributeError):
            report["openwrt_tx_provenance"] = {
                "status": "unknown", "send_complete": False,
                "monitor_observation_state": "unknown",
                "monitor_capture_finished": False,
                "rf_transmission_proven": False,
                "peer_receipt_proven": False,
                "native_awdl0_ingress_proven": False,
                "airdrop_proven": False,
            }
        TEST123_COORDINATOR.finalize_capture_report(report)
        return report

    def test_sender_failure_still_collects_all_terminal_records_and_is_partial(self):
        report = self._run("sender_failed")
        self._assert_terminal_records_and_cleanup(report)
        self.assertEqual(report["test088_sender"]["sender_result_event"]["status"], "failed")
        self.assertFalse(report["test088_sender"]["sender_result_event"]["send_complete"])
        provenance = SENDER_PROTOCOL.classify_sender_result(
            report["test088_sender"]["sender_result_event"], NONCE,
            self.packet_manifest)
        self.assertFalse(provenance["send_complete"])
        self.assertTrue(provenance["sender_status_is_non_gating_for_rx"])
        self.assertFalse(report["complete"], "sender failure must keep the overall run partial")
        self.assertTrue(report["partial"])

    def test_complete_sender_and_monitor_keep_valid_native_capture_complete(self):
        report = self._run("complete")
        self._assert_terminal_records_and_cleanup(report)
        self.assertTrue(report["openwrt_tx_provenance"]["send_complete"])
        self.assertEqual(
            report["openwrt_tx_provenance"]["monitor_observation_state"],
            "complete")
        self.assertTrue(report["complete"])
        self.assertFalse(report["partial"])

    def test_incomplete_monitor_still_collects_native_and_listener_terminals(self):
        report = self._run("monitor_incomplete")
        self._assert_terminal_records_and_cleanup(report)
        provenance = SENDER_PROTOCOL.classify_sender_result(
            report["test088_sender"]["sender_result_event"], NONCE,
            self.packet_manifest)
        self.assertEqual(provenance["monitor_observation_state"], "incomplete")
        self.assertFalse(provenance["monitor_capture_finished"])
        self.assertFalse(report["complete"], "incomplete monitor capture must keep the run partial")
        self.assertTrue(report["partial"])

    def test_malformed_monitor_is_unknown_but_keeps_terminal_records_and_cleanup(self):
        report = self._run("monitor_malformed")
        self._assert_terminal_records_and_cleanup(report)
        with self.assertRaises(SENDER_PROTOCOL.SenderAdapterError):
            SENDER_PROTOCOL.classify_sender_result(
                report["test088_sender"]["sender_result_event"], NONCE,
                self.packet_manifest)
        self.assertFalse(report["complete"], "malformed monitor evidence must keep the run partial")
        self.assertTrue(report["partial"])

    def test_truncated_result_after_go_preserves_terminals_and_marks_cleanup_unknown(self):
        report = self._run("sender_result_truncated", with_t123_go_wrapper=True)
        self.assertIsInstance(report.get("native_armed_ack"), dict)
        self.assertIsInstance(report.get("native_arm_result"), dict)
        self.assertIsInstance(report.get("native_result"), dict)
        self.assertIsInstance(report.get("listener_result"), dict)
        sender = report.get("test088_sender")
        self.assertIsInstance(sender, dict)
        raw = sender.get("raw_records")
        self.assertEqual(
            raw["sender_result_line"], '{"event":"SENDER_RESULT","status":')
        self.assertIsNone(sender.get("sender_result_event"))
        terminal = report.get("sender_terminal_error")
        self.assertEqual(terminal["schema"], "test123-sender-terminal-error/v1")
        self.assertEqual(terminal["status"], "sender_go_terminal_incomplete")
        self.assertEqual(terminal["error_code"], "SENDER_RESULT_MALFORMED")
        self.assertEqual(terminal["go_phase"], "after_go_flush")
        self.assertTrue(terminal["go_write_started"])
        self.assertTrue(terminal["go_write_completed"])
        self.assertTrue(terminal["result_line_recorded"])
        self.assertFalse(terminal["first_line_truncated"])
        self.assertIsNone(terminal["result_line_truncated"])
        self.assertEqual(
            terminal["result_line_classification"],
            "result_line_recorded_but_unvalidated")
        self.assertFalse(terminal["sender_result_known"])
        self.assertFalse(terminal["cleanup_known"])
        self.assertFalse(terminal["remote_exit_code_known"])
        self.assertFalse(terminal["retry_allowed"])
        self.assertIsNone(report.get("sender_cleanup"))
        self.assertIn("sender_cleanup_unverified",
                      report["tool_workflow_incomplete_reasons"])
        self.assertFalse(report["complete"])
        self.assertTrue(report["partial"])
        self.assertFalse(report["retry_allowed"])
        native_pipe = next(pipe for pipe in FakeManagedPipe.instances
                           if pipe.kind == "native")
        self.assertEqual(native_pipe.commands, ["ARM " + TOKEN])
        self.assertNotIn("ABORT", native_pipe.commands)
        self.assertEqual(len(self.sender_processes), 1)
        process = self.sender_processes[0]
        self.assertEqual(bytes(process.stdin.data),
                         b"GO " + TOKEN.encode("ascii") + b"\n")
        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.wait_calls, 0)
        self.assertTrue(process.terminated)
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(self.sender_selectors[0].closed)

    def _assert_terminal_records_and_cleanup(self, report):
        self.assertIsInstance(report.get("native_armed_ack"), dict)
        self.assertIsInstance(report.get("native_arm_result"), dict)
        self.assertIsInstance(report.get("native_result"), dict)
        self.assertIsInstance(report.get("listener_result"), dict)
        cleanup = report.get("sender_cleanup")
        self.assertIsInstance(cleanup, dict)
        self.assertTrue(cleanup["monitor_removed"])
        self.assertTrue(cleanup["ap_unchanged"])
        self.assertTrue(cleanup["temporary_files_removed"])
        self.assertEqual(report.get("native_worker_cleanup"), "exited_within_result_deadline")
        self.assertEqual(report.get("listener_worker_cleanup"), "exited_after_result_window")
        self.assertTrue(all(pipe.closed and pipe.process.wait_calls == 1 and
                            not pipe.process.terminated
                            for pipe in FakeManagedPipe.instances))
        self.assertEqual(len(self.sender_processes), 1)
        self.assertEqual(self.sender_processes[0].wait_calls, 1)
        self.assertFalse(self.sender_processes[0].terminated)
        self.assertEqual(
            bytes(self.sender_processes[0].stdin.data),
            b"GO " + TOKEN.encode("ascii") + b"\n")
        self.assertTrue(self.sender_processes[0].stdin.closed)
        self.assertFalse(report["retry_allowed"])
        self.assertFalse(report["airdrop_proven"])


if __name__ == "__main__":
    unittest.main()
