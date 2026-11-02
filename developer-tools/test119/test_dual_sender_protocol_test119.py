#!/usr/bin/env python3
"""Focused offline contract tests for Test119's actual dual-socket seam."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import selectors
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
COORDINATOR = ROOT / "developer-tools/test119/coordinate_test119_rx149.py"
SPEC_NAME = "test119_dual_sender_contract_tests"
import importlib.util
SPEC = importlib.util.spec_from_file_location(SPEC_NAME, COORDINATOR)
COORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COORD
SPEC.loader.exec_module(COORD)
DUAL = COORD.DUAL_PROTOCOL

TOKEN = "0123456789abcdef0123456789abcdef"


def valid_result():
    go = 1_000_000_000
    started = go + 200_000
    first = started + 200_000
    rows = []
    for ordinal in range(4):
        before = first + ordinal * 10_000_000
        rows.append({
            "ordinal": ordinal,
            "ieee80211_sequence": 291 + ordinal,
            "awdl_sequence": 34305 + ordinal,
            "before_ns": before,
            "after_ns": before + 100_000,
            "return_bytes": 106,
            "errno": 0,
        })
    finished = started + 40_000_000
    return {
        "event": "SENDER_RESULT", "schema": DUAL.SCHEMA,
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
        "go_to_start_max_ns": DUAL.GO_TO_START_MAX_NS,
        "first_send_ns": first, "local_send_calls": 4,
        "pre_capture_queue_drain": {
            "schema": DUAL.DRAIN_SCHEMA, "read_attempts": 1, "packets_drained": 0,
            "receive_error": 0, "drain_complete": True,
            "kernel_stats_available": True, "kernel_packets": 0,
            "kernel_dropped_packets": 0,
        },
        "send_timing": rows, "actual_horizon_ns": 40_000_000,
        "monitor_observation": {
            "schema": DUAL.MONITOR_SCHEMA, "capture_window_ns": 40_000_000,
            "started_ns": started, "ended_ns": finished, "capture_finished": True,
            "capture_limit_reached": False, "read_attempts": 0,
            "packets_received": 0, "samples_recorded": 0, "samples_overflow": 0,
            "receive_error": 0, "kernel_stats_available": True,
            "kernel_packets": 0, "kernel_dropped_packets": 0, "loss_free": True,
            "socket_topology": "distinct_tx_and_observer", "observer_bound_ifindex": 32,
            "outgoing_tap_is_rf_proof": False,
            "outgoing_exact_by_ordinal": [0, 0, 0, 0],
            "non_outgoing_exact_by_ordinal": [0, 0, 0, 0],
            "exact_identity_unavailable": 0, "samples": [],
        },
        "rf_transmission_proven": False, "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


class Test119DualSenderProtocol(unittest.TestCase):
    def setUp(self):
        self.restore = COORD.RUNNER.configure_test104_profile()

    def tearDown(self):
        self.restore()

    def test_ready_and_full_result_use_test119_schema_through_runner(self):
        ready = "READY " + " ".join(f"{key}={value}" for key, value in DUAL.READY_VALUES.items())
        parsed = COORD.RUNNER.PROTOCOL.parse_sender_ready(ready)
        self.assertEqual(parsed["schema"], DUAL.SCHEMA)
        self.assertEqual(parsed["socket_topology"], "distinct_tx_and_observer")
        result = valid_result()
        validated = DUAL.validate_result(result, TOKEN)
        self.assertTrue(validated["zero_exact_interpretation_allowed"])
        self.assertFalse(validated["rf_transmission_proven"])
        provenance = COORD.RUNNER.PROVENANCE.classify_sender_result(result)
        self.assertEqual(provenance["status"], "local_sender_result_validated")
        self.assertFalse(provenance["raw_packet_hex_in_public_summary"])
        legacy = DUAL.project_legacy_result(result, TOKEN)
        self.assertEqual(legacy["status"], "complete")

    def test_stale_queue_and_kernel_drops_block_both_positive_and_zero_claims(self):
        result = valid_result()
        result["frames_attempted"] = 4
        result["frames_completed"] = 4
        result["send_timing"] = valid_result()["send_timing"]
        result["monitor_observation"]["packets_received"] = 1
        result["monitor_observation"]["read_attempts"] = 1
        result["monitor_observation"]["samples_recorded"] = 1
        result["monitor_observation"]["kernel_packets"] = 1
        result["monitor_observation"]["non_outgoing_exact_by_ordinal"] = [1, 0, 0, 0]
        result["monitor_observation"]["samples"] = [{
            "packet_type_present": True, "packet_type": 0, "ifindex_present": True,
            "ifindex": 32, "msg_flags": 0, "received_len": 106, "copied_len": 106,
            "raw_packet_complete": True, "exact_ordinal": 0, "raw_packet_hex": "00" * 106,
        }]
        drain = result["pre_capture_queue_drain"]
        drain.update({"read_attempts": 256, "packets_drained": 256,
                      "drain_complete": False, "kernel_packets": 256})
        checked = DUAL.validate_result(result, TOKEN)
        self.assertFalse(checked["capture_epoch_valid"])
        self.assertFalse(checked["exact_current_run_attribution_allowed"])
        self.assertFalse(checked["zero_exact_interpretation_allowed"])
        drain["drain_complete"] = True
        drain["kernel_dropped_packets"] = 1
        checked = DUAL.validate_result(result, TOKEN)
        self.assertFalse(checked["capture_epoch_valid"])
        self.assertFalse(checked["exact_current_run_attribution_allowed"])
        self.assertFalse(checked["zero_exact_interpretation_allowed"])

    def test_actual_test088_go_once_compatibility_path_maps_expired_sender(self):
        result = valid_result()
        result.update({
            "status": "failed", "frames_attempted": 0, "frames_completed": 0,
            "sent": 0, "error_count": 1, "last_errno": 110,
            "stop_reason": "go_to_start_budget_expired", "elapsed_ms": 0,
            "first_send_ns": None, "local_send_calls": 0,
            "send_timing": [],
        })
        result["monitor_observation"].update({"capture_finished": False,
            "loss_free": False, "ended_ns": result["started_ns"] + 1,
            "read_attempts": 1, "receive_error": 0, "kernel_packets": 0,
            "packets_received": 0})
        result["finished_ns"] = result["started_ns"] + 1
        result["actual_horizon_ns"] = 1
        result["monitor_observation"]["capture_window_ns"] = 40_000_000
        result["monitor_observation"]["started_ns"] = result["started_ns"]
        cleanup = {"event": "MONITOR_CLEANUP", "run_token": TOKEN,
                   "monitor_removed": True, "ap_unchanged": True,
                   "temporary_files_removed": True}
        started = {
            "event": "SENDER_STARTED", "schema": DUAL.SCHEMA,
            "timing_schema": 1, "clock_domain": "CLOCK_MONOTONIC",
            "run_token": TOKEN, "go_received_ns": result["go_received_ns"],
            "started_ns": result["started_ns"], "go_to_start_ns": result["go_to_start_ns"],
            "go_to_start_max_ns": DUAL.GO_TO_START_MAX_NS,
            "send_budget_ns": 40_000_000, "frames_requested": 4,
            "interval_ms": 10, "tx_flags_requested": "NOSEQNO",
            "noack_requested": False,
        }
        reader, writer = os.pipe()
        os.write(writer, (json.dumps(started, separators=(",", ":")) + "\n" +
                          json.dumps(result, separators=(",", ":")) + "\n" +
                          "CLEANUP " + json.dumps(cleanup, separators=(",", ":")) + "\n").encode())
        os.close(writer)

        class FakeStdin:
            def write(self, value):
                self.value = value
            def flush(self):
                return None
            def close(self):
                return None

        class FakeProcess:
            def __init__(self):
                self.stdin = FakeStdin()
                self.stdout = os.fdopen(reader, "rb", buffering=0)
            def wait(self, timeout=None):
                return 5

        process = FakeProcess()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        session = type("Session", (), {})()
        session.closed = False
        session.control_consumed = False
        session.process = process
        session.selector = selector
        session.read_state = {"buffer": b""}
        session.deadline = time.monotonic() + 5
        session.run_token = TOKEN
        session.protocol_evidence = {}
        capture = COORD.RUNNER.TEST088._RunCapture(COORD.BINDING.CANDIDATE)
        wrapped = COORD.RUNNER.TEST088.Test088SenderSession(session, capture)
        try:
            outcome = wrapped.go_once()
        finally:
            selector.close()
            process.stdout.close()
            process.stdin.close()
        self.assertEqual(outcome["sender_result"]["status"], "failed")
        self.assertEqual(outcome["sender_result"]["stop_reason"],
                         "go_to_start_budget_expired")
        self.assertFalse(session.protocol_evidence["test088_raw_sender_result"][
            "rf_transmission_proven"])

    def test_parser_rejects_sub_10ms_cadence_and_late_first_send(self):
        result = valid_result()
        result["send_timing"][1]["before_ns"] = result["send_timing"][0]["before_ns"] + 9_999_999
        with self.assertRaises(DUAL.SenderProtocolError):
            DUAL.validate_result(result, TOKEN)
        result = valid_result()
        result["first_send_ns"] = result["go_received_ns"] + DUAL.GO_TO_START_MAX_NS + 1
        result["send_timing"][0]["before_ns"] = result["first_send_ns"]
        result["go_to_start_ns"] = result["started_ns"] - result["go_received_ns"]
        with self.assertRaises(DUAL.SenderProtocolError):
            DUAL.validate_result(result, TOKEN)


if __name__ == "__main__":
    unittest.main()
