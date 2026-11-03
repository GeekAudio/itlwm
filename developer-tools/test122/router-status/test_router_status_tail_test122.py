#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


TOOL_PATH = Path(__file__).with_name("router_status_tail_test122.py")
SPEC = importlib.util.spec_from_file_location("router_status_tail_test122_under_test", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOL
SPEC.loader.exec_module(TOOL)

TOKEN = "0123456789abcdef0123456789abcdef"


def packet_set() -> bytes:
    value = bytearray(528)
    value[:8] = b"T104PKT1"
    value[8] = 1
    value[9] = 4
    struct.pack_into(">HHHHH", value, 10, 10, 40, 10, 96, 106)
    return bytes(value)


def monitor(*, kernel_stats: bool = True, truncated: int = 0,
            status_sample: dict | None = None) -> dict:
    samples = [status_sample] if status_sample else []
    packets = 1 if truncated or status_sample else 0
    return {
        "schema": TOOL.MONITOR_SCHEMA,
        "started_ns": 1_000_000_000,
        "ended_ns": 3_040_000_000,
        "actual_horizon_ns": TOOL.CAPTURE_WINDOW_NS,
        "capture_window_ns": TOOL.CAPTURE_WINDOW_NS,
        "status_tail_began_ns": 1_040_000_000,
        "capture_finished": True,
        "capture_limit_reached": False,
        "read_attempts": packets,
        "packets_received": packets,
        "exact_samples_recorded": 0,
        "exact_samples_overflow": 0,
        "receive_error": 0,
        "kernel_stats_available": kernel_stats,
        "kernel_packets": packets if kernel_stats else None,
        "kernel_dropped_packets": 0 if kernel_stats else None,
        "capture_loss_free": False if truncated else (True if kernel_stats else None),
        "classification_complete": True,
        "identity_complete": True,
        "radiotap_invalid": 0,
        "radiotap_unsupported": 0,
        "unmatched_valid_packets": 0,
        "truncated_packets": truncated,
        "exact_identity_unavailable": 0,
        "socket_topology": "distinct_tx_and_observer",
        "observer_bound_ifindex": 4,
        "outgoing_tap_is_rf_proof": False,
        "exact_match_by_ordinal": [0, 0, 0, 0],
        "outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "non_outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "tx_status_candidate_by_ordinal": [0, 0, 0, 0],
        "other_exact_by_ordinal": [0, 0, 0, 0],
        "samples": [],
        "status_candidate_matches_by_ordinal": [0, 0, 0, 0],
        "status_candidate_samples_recorded": len(samples),
        "status_candidate_samples_overflow": 0,
        "status_candidate_identity_unavailable": 0,
        "status_candidate_samples": samples,
    }


def result(*, capture: dict | None = None) -> dict:
    start = 1_000_000_000
    go = start - 1_000_000
    send_rows = []
    for index in range(4):
        before = start + index * 10_000_000
        send_rows.append({
            "ordinal": index, "ieee80211_sequence": 1 + index,
            "awdl_sequence": 10 + index, "before_ns": before,
            "after_ns": before + 100_000, "return_bytes": 106, "errno": 0,
        })
    ended = start + TOOL.CAPTURE_WINDOW_NS
    return {
        "event": "SENDER_RESULT", "schema": TOOL.SENDER_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC", "status": "send_complete",
        "run_token": TOKEN, "run_token_in_frame": False, "go_received_ns": go,
        "frames_requested": 4, "frames_attempted": 4, "frames_completed": 4,
        "send_complete": True, "packet_bytes": 106, "radiotap_bytes": 10,
        "mpdu_bytes": 96, "elapsed_ms": 30, "deadline_hit": False,
        "error_count": 0, "last_errno": 0, "stop_reason": "complete",
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "ack_policy": "normal_unicast_requested", "hardware_honoring": "unknown",
        "raw_txs": "unknown", "mac_ack": "unknown", "interval_ms": 10,
        "send_budget_ns": TOOL.SEND_BUDGET_NS, "status_tail_ns": TOOL.STATUS_TAIL_NS,
        "capture_window_ns": TOOL.CAPTURE_WINDOW_NS, "started_ns": start,
        "send_deadline_ns": start + TOOL.SEND_BUDGET_NS,
        "observer_deadline_ns": start + TOOL.CAPTURE_WINDOW_NS,
        "finished_ns": ended, "go_to_start_ns": start - go,
        "go_to_start_max_ns": TOOL.GO_TO_START_MAX_NS, "first_send_ns": start,
        "pre_capture_queue_drain": {
            "read_attempts": 1, "packets_drained": 0, "receive_error": 0,
            "drain_complete": True, "kernel_stats_available": True,
            "kernel_packets": 0, "kernel_dropped_packets": 0,
        },
        "send_timing": send_rows,
        "monitor_observation": capture if capture is not None else monitor(),
        "radio_transmission_proven": False, "rf_transmission_proven": False,
        "firmware_tx_status_proven": False, "peer_receipt_proven": False,
        "airdrop_proven": False, "intel_arm_invoked": False, "boot_claim_used": False,
    }


class RouterStatusTailTest122Tests(unittest.TestCase):
    def test_default_is_side_effect_free_plan_and_has_no_host_address(self):
        self.assertEqual(TOOL.main([]), 0)

    def test_ready_requires_exact_scope_and_explicit_noack_false(self):
        line = "READY " + " ".join(f"{key}={value}" for key, value in TOOL.READY_VALUES.items())
        parsed = TOOL.parse_ready(line)
        self.assertFalse(parsed["noack_requested"])
        self.assertFalse(parsed["intel_arm_invoked"])
        self.assertIn("send_budget_ms=40", line)
        with self.assertRaises(TOOL.RouterStatusTailError):
            TOOL.parse_ready(line.replace("noack_requested=false", "noack_requested=true"))

    def test_packetset_valid_is_only_a_nontransmitting_verification(self):
        line = ('PACKET_SET_VALID {"event":"PACKET_SET_VALID","schema":"test104-unicast-packet-set/v1",'
                '"frames":4,"interval_ms":10,"budget_ms":40,"noack_requested":false,'
                '"transmission_capability":false,"rf_transmission_proven":false}')
        self.assertFalse(TOOL.parse_packetset_valid(line)["transmission_capability"])
        self.assertFalse(TOOL.parse_packetset_valid(line)["rf_transmission_proven"])
        with self.assertRaises(TOOL.RouterStatusTailError):
            TOOL.parse_packetset_valid(line.replace('"rf_transmission_proven":false',
                                                    '"rf_transmission_proven":true'))

    def test_started_and_result_validate_40ms_send_and_full_tail(self):
        started_ns = 1_000_000_000
        started = {
            "event": "SENDER_STARTED", "schema": TOOL.SENDER_SCHEMA,
            "clock_domain": "CLOCK_MONOTONIC", "run_token": TOKEN,
            "go_received_ns": started_ns - 1_000_000, "started_ns": started_ns,
            "send_deadline_ns": started_ns + TOOL.SEND_BUDGET_NS,
            "observer_deadline_ns": started_ns + TOOL.CAPTURE_WINDOW_NS,
            "go_to_start_ns": 1_000_000, "go_to_start_max_ns": TOOL.GO_TO_START_MAX_NS,
            "send_budget_ns": TOOL.SEND_BUDGET_NS, "status_tail_ns": TOOL.STATUS_TAIL_NS,
            "frames_requested": 4, "interval_ms": 10, "tx_flags_requested": "NOSEQNO",
            "noack_requested": False, "intel_arm_invoked": False, "boot_claim_used": False,
        }
        self.assertEqual(TOOL.validate_started(started, TOKEN), started)
        good = TOOL.validate_result(result(), TOKEN)
        self.assertTrue(good["send_complete"])
        self.assertEqual(good["monitor_observation"]["actual_horizon_ns"],
                         TOOL.CAPTURE_WINDOW_NS)
        self.assertFalse(good["rf_transmission_proven"])
        self.assertEqual(good["mac_ack"], "unknown")

    def test_truncation_is_known_loss_even_when_kernel_statistics_are_unavailable(self):
        observation = monitor(kernel_stats=False, truncated=1)
        observation["capture_loss_free"] = False
        value = result(capture=observation)
        checked = TOOL.validate_result(value, TOKEN)
        self.assertFalse(checked["monitor_observation"]["capture_loss_free"])
        observation["capture_loss_free"] = None
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "monitor_loss_classification_invalid"):
            TOOL.validate_result(value, TOKEN)

    def test_candidate_with_unmapped_ordinal_is_retained_without_run_attribution(self):
        sample = {
            "ordinal": None, "packet_type": 3, "ifindex": 4, "msg_flags": 0,
            "received_len": 120, "bytes_retained": 120, "raw_prefix_truncated": False,
            "exact_match": False, "has_tx_flags": True, "tx_flags": 0,
            "has_data_retries": True, "data_retries": 1,
            "ieee80211_sequence": 900, "awdl_sequence": 901,
            "raw_prefix_hex": "aa" * 120,
        }
        observation = monitor(status_sample=sample)
        value = result(capture=observation)
        checked = TOOL.validate_result(value, TOKEN)
        self.assertIsNone(checked["monitor_observation"]["status_candidate_samples"][0]["ordinal"])

    def test_remote_script_stages_and_verifies_packetset_before_monitor_and_go(self):
        binary = b"fake-test122-sender"
        pset = packet_set()
        script = TOOL.build_remote_script(
            binary=binary, binary_sha256=hashlib.sha256(binary).hexdigest(),
            packet_set=pset, packet_set_sha256=hashlib.sha256(pset).hexdigest(),
            run_token=TOKEN)
        self.assertIn('"$BIN" --verify-only --packet-set "$PSET"', script)
        self.assertIn('"$BIN" --send --packet-set "$PSET" --interface "$MON"', script)
        self.assertLess(script.index("--verify-only"), script.index('interface add "$MON"'))
        self.assertIn("/tmp/iwn-test122-tail-$RUN_TOKEN", script)
        self.assertIn("MON=iwtail122", script)
        self.assertNotIn("uci commit", script)
        self.assertNotIn('iw dev "$AP" set', script)

    def test_exception_after_private_run_setup_still_writes_private_report(self):
        binary = b"fake-test122-sender"
        pset = packet_set()
        with unittest.TestCase().subTest():
            import tempfile
            with tempfile.TemporaryDirectory() as raw_dir:
                base = Path(raw_dir)
                private = base / "private"
                private.mkdir(mode=0o700)
                private.chmod(0o700)
                binary_path = private / "sender"
                binary_path.write_bytes(binary)
                binary_path.chmod(0o700)
                pset_path = private / "packet-set.bin"
                pset_path.write_bytes(pset)
                pset_path.chmod(0o600)
                output = private / "run-private.json"
                args = SimpleNamespace(
                    host="router-test", control_path=Path("/private/tmp/fake.sock"),
                    binary=binary_path, binary_sha256=hashlib.sha256(binary).hexdigest(),
                    packet_set=pset_path, packet_set_sha256=hashlib.sha256(pset).hexdigest(),
                    output=output)

                class FakeRunner:
                    @staticmethod
                    def build_bootstrap_argv(host, control_path):
                        return ["fake-ssh"]

                    @staticmethod
                    def remote_script_bytes(script):
                        return b"script\n"

                with mock.patch.object(TOOL, "_load_router_runner", return_value=FakeRunner), \
                     mock.patch.object(TOOL.subprocess, "Popen", side_effect=RuntimeError("start failed")):
                    report = TOOL.run(args)
                self.assertEqual(report["status"], "router_only_incomplete")
                self.assertEqual(report["error"], "RuntimeError")
                self.assertTrue(output.exists())
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                stored = json.loads(output.read_text())
                self.assertFalse(stored["rf_transmission_proven"])
                self.assertEqual(stored["error"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
