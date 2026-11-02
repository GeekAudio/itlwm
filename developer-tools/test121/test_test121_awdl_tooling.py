#!/usr/bin/env python3
"""Offline contract tests for the Test121 raw-monitor bank and plan."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = ROOT / "developer-tools/test121"
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import dual_sender_protocol_test121 as dual

TOKEN = "0123456789abcdef0123456789abcdef"


def monitor(packet_count: int, *, sample_bytes: int = 106) -> dict:
    sample_count = min(packet_count, dual.RAW_CAPTURE_LIMIT)
    copied = min(sample_bytes, dual.RAW_CAPTURE_BYTES)
    samples = [{
        "packet_type_present": True,
        "packet_type": 4,
        "ifindex_present": True,
        "ifindex": 11,
        "msg_flags": 0,
        "received_len": sample_bytes,
        "copied_len": copied,
        "raw_packet_complete": copied == sample_bytes,
        "exact_ordinal": None,
        "raw_packet_hex": ("a5" * copied),
    } for _ in range(sample_count)]
    overflow = packet_count - sample_count
    return {
        "schema": dual.MONITOR_SCHEMA,
        "capture_window_ns": 40_000_000,
        "started_ns": 1_000_200_000,
        "ended_ns": 1_040_200_000,
        "capture_finished": packet_count < dual.RAW_CAPTURE_LIMIT,
        "capture_limit_reached": packet_count >= dual.RAW_CAPTURE_LIMIT,
        "read_attempts": packet_count,
        "packets_received": packet_count,
        "samples_recorded": sample_count,
        "samples_overflow": overflow,
        "receive_error": 0,
        "kernel_stats_available": True,
        "kernel_packets": packet_count,
        "kernel_dropped_packets": 0,
        "loss_free": (overflow == 0 and packet_count < dual.RAW_CAPTURE_LIMIT and
                      sample_bytes <= dual.RAW_CAPTURE_BYTES),
        "socket_topology": "distinct_tx_and_observer",
        "observer_bound_ifindex": 11,
        "outgoing_tap_is_rf_proof": False,
        "outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "non_outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "exact_identity_unavailable": 0,
        "samples": samples,
    }


def valid_result(packet_count: int = 37, *, sample_bytes: int = 106) -> dict:
    go = 1_000_000_000
    started = go + 200_000
    finished = started + 40_000_000
    rows = [{
        "ordinal": index,
        "ieee80211_sequence": 291 + index,
        "awdl_sequence": 34305 + index,
        "before_ns": started + 200_000 + index * 10_000_000,
        "after_ns": started + 300_000 + index * 10_000_000,
        "return_bytes": 106,
        "errno": 0,
    } for index in range(4)]
    drain = {
        "schema": dual.DRAIN_SCHEMA,
        "read_attempts": 1,
        "packets_drained": 0,
        "receive_error": 0,
        "drain_complete": True,
        "kernel_stats_available": True,
        "kernel_packets": 0,
        "kernel_dropped_packets": 0,
    }
    return {
        "event": "SENDER_RESULT", "schema": dual.SCHEMA,
        "timing_schema": 1, "clock_domain": "CLOCK_MONOTONIC",
        "status": "complete", "run_token": TOKEN, "go_received_ns": go,
        "frames_requested": 4, "frames_attempted": 4, "frames_completed": 4,
        "sent": 4, "payload_bytes": 96, "packet_bytes": 106,
        "radiotap_bytes": 10, "mpdu_bytes": 96, "udp_payload_bytes": 8,
        "elapsed_ms": 30, "deadline_hit": False, "error_count": 0,
        "last_errno": 0, "stop_reason": "complete",
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "ack_policy": "normal_unicast_requested", "hardware_honoring": "unknown",
        "raw_txs": "unknown", "mac_ack": "unknown", "interval_ms": 10,
        "send_budget_ns": 40_000_000, "started_ns": started,
        "finished_ns": finished, "go_to_start_ns": started - go,
        "go_to_start_max_ns": dual.GO_TO_START_MAX_NS,
        "first_send_ns": rows[0]["before_ns"], "local_send_calls": 4,
        "pre_capture_queue_drain": drain, "send_timing": rows,
        "actual_horizon_ns": 40_000_000,
        "monitor_observation": monitor(packet_count, sample_bytes=sample_bytes),
        "rf_transmission_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


class Test121AwldTooling(unittest.TestCase):
    def test_37_samples_fit_and_support_bounded_zero_exact_result(self):
        checked = dual.validate_result(valid_result(37), TOKEN)
        observed = checked["monitor_observation"]
        self.assertEqual(len(observed["samples"]), 37)
        self.assertEqual(observed["samples_overflow"], 0)
        self.assertTrue(observed["loss_free"])
        self.assertTrue(checked["zero_exact_interpretation_allowed"])
        self.assertFalse(checked["exact_current_run_attribution_allowed"])
        self.assertFalse(checked["rf_transmission_proven"])

    def test_64_sample_read_cap_is_incomplete_and_fails_closed(self):
        checked = dual.validate_result(valid_result(64), TOKEN)
        observed = checked["monitor_observation"]
        self.assertEqual(len(observed["samples"]), 64)
        self.assertEqual(observed["samples_overflow"], 0)
        self.assertTrue(observed["capture_limit_reached"])
        self.assertFalse(observed["capture_finished"])
        self.assertFalse(observed["loss_free"])
        self.assertFalse(checked["zero_exact_interpretation_allowed"])
        self.assertFalse(checked["exact_current_run_attribution_allowed"])

    def test_excess_packets_and_claimed_overflow_fail_closed(self):
        with self.assertRaises(dual.SenderProtocolError):
            dual.validate_result(valid_result(65), TOKEN)
        value = valid_result(64)
        value["monitor_observation"]["samples_overflow"] = 1
        with self.assertRaises(dual.SenderProtocolError):
            dual.validate_result(value, TOKEN)

    def test_64_full_512_byte_samples_fit_bounded_json_line(self):
        result = valid_result(64, sample_bytes=512)
        line = json.dumps(result, separators=(",", ":"))
        self.assertGreater(len(line.encode()), 16 * 1024)
        self.assertLessEqual(len(line.encode()), dual.MAX_LINE_BYTES)
        parsed, _legacy = dual.parse_result_line(line, TOKEN)
        self.assertEqual(len(parsed["monitor_observation"]["samples"]), 64)

    def test_truncated_raw_sample_cannot_support_zero_exact_interpretation(self):
        checked = dual.validate_result(valid_result(1, sample_bytes=513), TOKEN)
        sample = checked["monitor_observation"]["samples"][0]
        self.assertEqual(sample["received_len"], 513)
        self.assertEqual(sample["copied_len"], 512)
        self.assertFalse(sample["raw_packet_complete"])
        self.assertFalse(checked["monitor_observation"]["loss_free"])
        self.assertFalse(checked["zero_exact_interpretation_allowed"])

    def test_excess_read_attempts_and_old_schema_are_rejected(self):
        value = valid_result(37)
        value["monitor_observation"]["read_attempts"] = 65
        with self.assertRaises(dual.SenderProtocolError):
            dual.validate_result(value, TOKEN)
        value = valid_result(37)
        value["schema"] = "test119-dual-socket-sender/v1"
        with self.assertRaises(dual.SenderProtocolError):
            dual.validate_result(value, TOKEN)

    def test_candidate_plan_is_inert_and_marks_channel_mismatch(self):
        result = subprocess.run(
            [sys.executable, str(TOOL_DIR / "coordinate_test121_rx149.py"), "--plan"],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False, timeout=20,
            env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["candidate"], "25G332-Test121")
        self.assertIsNone(plan["expected_uuid"])
        self.assertEqual(plan["channel_contrast"]["first_run"], "primary")
        self.assertEqual(plan["channel_contrast"]["primary"],
                         {"station_channel": 36, "roc_channel": 149})
        self.assertEqual(plan["channel_contrast"]["if_measured_conditions_do_not_match"],
                         "condition_mismatch_no_channel_attribution")
        self.assertEqual(plan["raw_monitor_sample_limit"], 64)
        self.assertEqual(plan["raw_monitor_overflow"], "fail_closed")
        self.assertIs(plan["outgoing_packet_tap_proves_rf"], False)
        self.assertIs(plan["rf_triggered"], False)
        self.assertIs(plan["efi_modified"], False)

    def test_c_sender_keeps_transmit_window_and_capture_attempt_gate(self):
        source = (TOOL_DIR / "awdl_unicast_sender_test121.c").read_text()
        for exact in (
            "#define FRAME_COUNT 4U",
            "#define INTERVAL_MS 10U",
            "#define SEND_BUDGET_NS UINT64_C(40000000)",
            "#define RAW_CAPTURE_LIMIT 64U",
            "#define RAW_CAPTURE_BYTES 512U",
            "#define RAW_CAPTURE_READ_LIMIT 64U",
            "#define STALE_QUEUE_READ_LIMIT 256U",
            "#define GO_TO_START_MAX_NS UINT64_C(5000000)",
        ):
            self.assertIn(exact, source)
        self.assertIn(r'\"rf_transmission_proven\":false', source)
        self.assertIn(r'\"peer_receipt_proven\":false', source)
        self.assertIn(r'\"airdrop_proven\":false', source)


if __name__ == "__main__":
    unittest.main()
