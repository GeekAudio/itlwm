#!/usr/bin/env python3
"""Offline integration checks for Test123's frozen T087/T088 seams."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test_component_unavailable:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COORD = load("test123_coordinate_integration_under_test",
             HERE / "coordinate_test123_rx149.py")
SENDER_FIXTURES = load(
    "test123_sender_fixtures_for_coordinator",
    HERE / "router-status/test_dual_sender_protocol_test123.py")


class _Input:
    def __init__(self):
        self.writes = []

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        return None

    def close(self):
        return None


class _Output:
    def close(self):
        return None


class _Process:
    def __init__(self, exit_code=0):
        self.stdin = _Input()
        self.stdout = _Output()
        self.exit_code = exit_code
        self.terminated = False

    def wait(self, timeout=None):
        return self.exit_code


class _Selector:
    def close(self):
        return None


def _started_line(token: str, nonce: str) -> str:
    protocol = COORD.SENDER_PROTOCOL
    go = 1_000_000_000
    started = go + 1_000_000
    value = {
        "event": "SENDER_STARTED", "schema": protocol.SCHEMA,
        "tool_test": "Test123", "running_kernel_test": "Test122",
        "packet_set_schema": protocol.PACKETSET_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC",
        "observation_time_semantics": protocol.OBSERVATION_TIME_SEMANTICS,
        "run_token": token, "wire_nonce_hex": nonce,
        "driver_rx_lease_ms": protocol.DRIVER_RX_LEASE_MS,
        "go_received_ns": go, "started_ns": started,
        "send_deadline_ns": started + protocol.SEND_BUDGET_NS,
        "observer_deadline_ns": started + protocol.CAPTURE_WINDOW_NS,
        "go_to_start_ns": started - go,
        "go_to_start_max_ns": protocol.GO_TO_START_MAX_NS,
        "send_budget_ns": protocol.SEND_BUDGET_NS,
        "status_tail_ns": protocol.STATUS_TAIL_NS,
        "frames_requested": protocol.FRAME_COUNT,
        "interval_ms": protocol.INTERVAL_MS,
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "intel_arm_invoked": False, "boot_claim_used": False,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class Test123CoordinatorIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This validates local receipts and paths only. It does not read live
        # identity, contact OpenWrt, compile, arm, or open an interface.
        COORD._configure_test123_run()

    def setUp(self):
        COORD.SENDER_PROTOCOL.clear_packet_set_binding()
        COORD.BINDING.clear_active_run()

    def test_default_plan_is_inert_and_separates_tool_from_kernel(self):
        self.assertEqual(COORD.plan()["tool_test"], "Test123")
        self.assertEqual(COORD.plan()["running_kernel_test"], "Test122")
        self.assertFalse(COORD.plan()["rf_triggered"])
        self.assertFalse(COORD.plan()["armed"])
        self.assertEqual(COORD.main(["--plan"]), 0)

    def test_t088_go_once_uses_legacy_projection_but_preserves_raw_nonce_failure(self):
        restore = COORD._configure_test123_profile()
        packet_bytes, manifest = SENDER_FIXTURES.packet_set()
        token = SENDER_FIXTURES.TOKEN
        nonce = manifest["wire_nonce_hex"]
        raw_result = SENDER_FIXTURES.sender_result(manifest)
        raw_result["run_token"] = token
        raw_result["wire_nonce_hex"] = "ffffffffffffffff"  # legacy fields remain valid
        raw_lines = [
            _started_line(token, nonce),
            json.dumps(raw_result, sort_keys=True, separators=(",", ":")),
            "CLEANUP " + json.dumps({
                "event": "MONITOR_CLEANUP", "run_token": token,
                "monitor_removed": True, "ap_unchanged": True,
                "temporary_files_removed": True,
            }, sort_keys=True, separators=(",", ":")),
        ]
        COORD.SENDER_PROTOCOL.bind_packet_set(packet_bytes)

        process = _Process(exit_code=0)
        session = type("FakeSenderSession", (), {})()
        session.closed = False
        session.control_consumed = False
        session.process = process
        session.selector = _Selector()
        session.read_state = {"buffer": b""}
        session.deadline = 10_000_000_000
        session.run_token = token
        session.protocol_evidence = {}

        capture = COORD.RUNNER.TEST088._RunCapture(COORD.RUNNER.CANDIDATE)
        wrapped = COORD.RUNNER.TEST088.Test088SenderSession(session, capture)
        try:
            with mock.patch.object(
                    COORD.RUNNER.TEST088.ROUTER, "_read_protocol_line",
                    side_effect=raw_lines):
                completion = wrapped.go_once()

            self.assertEqual(completion["sender_result"]["status"], "complete")
            self.assertTrue(completion["cleanup"]["monitor_removed"])
            self.assertEqual(session.protocol_evidence["test088_raw_sender_result"], raw_result)
            self.assertEqual(capture.result_event, raw_result)
            self.assertEqual(process.stdin.writes, [f"GO {token}\n".encode("ascii")])

            # The frozen T088 legacy handoff cannot be mistaken for a validated
            # Test123 record; the separate raw validator rejects its wrong nonce.
            with self.assertRaises(COORD.SENDER_PROTOCOL.SenderProtocolError):
                COORD.SENDER_PROTOCOL.validate_result(
                    raw_result, token, expected_wire_nonce_hex=nonce,
                    packet_set_manifest=manifest)
        finally:
            restore()
            COORD.SENDER_PROTOCOL.clear_packet_set_binding()

    def test_listener_legacy_argv_is_intercepted_before_t104_marker_logic(self):
        token = "0123456789abcdef0123456789abcdef"
        expected = {
            "wire_nonce_hex": "1020304050607080",
            "source_ipv6": "fe80::1001",
            "destination_ipv6": "fe80::2002",
            "ifindex": 31,
        }
        old_expectation = COORD.RUNNER.ACTIVE_LISTENER_EXPECTATION
        old_binary = getattr(COORD.RUNNER, "LISTENER_BINARY", None)
        old_sha = getattr(COORD.RUNNER, "LISTENER_SHA256", None)
        old_pipe = COORD.RUNNER.BASE.ManagedPipe
        seen = []

        def fake_pipe(argv):
            seen.append(list(argv))
            return object()

        COORD.RUNNER.ACTIVE_LISTENER_EXPECTATION = expected
        COORD.RUNNER.BASE.ManagedPipe = fake_pipe
        try:
            restore = COORD._configure_test123_profile()
            try:
                legacy = [str(COORD.RUNNER.LISTENER_BINARY), "--listen",
                          COORD.RUNNER.PROTOCOL.LISTENER_MARKER,
                          "--run-token", token, "--recv-anyif"]
                COORD.RUNNER.BASE.ManagedPipe(legacy)
                self.assertEqual(len(seen), 1)
                self.assertEqual(seen[0][1:4], [
                    "--listen-nonce", expected["wire_nonce_hex"],
                    "--run-token"])
                self.assertIn("--expected-source-ipv6", seen[0])
                self.assertNotIn("--listen", seen[0])
            finally:
                restore()
        finally:
            COORD.RUNNER.ACTIVE_LISTENER_EXPECTATION = old_expectation
            COORD.RUNNER.BASE.ManagedPipe = old_pipe
            if old_binary is None:
                COORD.RUNNER.__dict__.pop("LISTENER_BINARY", None)
            else:
                COORD.RUNNER.LISTENER_BINARY = old_binary
            if old_sha is None:
                COORD.RUNNER.__dict__.pop("LISTENER_SHA256", None)
            else:
                COORD.RUNNER.LISTENER_SHA256 = old_sha

    def test_empty_listener_argv_is_inert(self):
        self.assertEqual(COORD.adapt_legacy_listener_argv([]), [])

    def test_workflow_completion_requires_all_terminal_observations(self):
        def report():
            return {
                "status": "captured_no_peer_or_airdrop_proof",
                "complete": True,
                "partial": False,
                "native_result": {
                    "status": "captured_no_retry", "report_saved": True,
                    "claim_consumed": True, "retry_allowed": False,
                },
                "test088_sender": {"sender_result_event": {
                    "status": "complete", "send_complete": True,
                }},
                "openwrt_tx_provenance": {
                    "status": "local_sender_record_validated",
                    "send_complete": True,
                    "monitor_observation_state": "complete",
                    "monitor_capture_finished": True,
                },
                "listener_result": {
                    "event": "LISTENER_RESULT",
                    "status": "timeout_or_unmatched",
                },
                "listener_result_error": None,
                "sender_cleanup": {
                    "monitor_removed": True, "ap_unchanged": True,
                    "temporary_files_removed": True,
                },
                "native_worker_cleanup": "exited_within_result_deadline",
                "listener_worker_cleanup": "exited_after_result_window",
            }

        complete = COORD.finalize_capture_report(report())
        self.assertTrue(complete["complete"])
        self.assertFalse(complete["partial"])
        self.assertEqual(complete["tool_workflow_incomplete_reasons"], [])

        cases = (
            ("sender failure", lambda value: value["test088_sender"][
                "sender_result_event"].update(status="failed", send_complete=False)),
            ("unknown sender", lambda value: value["openwrt_tx_provenance"].update(
                status="unknown")),
            ("incomplete monitor", lambda value: value["openwrt_tx_provenance"].update(
                monitor_observation_state="incomplete", monitor_capture_finished=False)),
            ("bad cleanup", lambda value: value["sender_cleanup"].update(
                monitor_removed=False)),
        )
        for name, change in cases:
            with self.subTest(name=name):
                value = report()
                change(value)
                finalized = COORD.finalize_capture_report(value)
                self.assertFalse(finalized["complete"])
                self.assertTrue(finalized["partial"])
                self.assertTrue(finalized["tool_workflow_incomplete_reasons"])


if __name__ == "__main__":
    unittest.main()
