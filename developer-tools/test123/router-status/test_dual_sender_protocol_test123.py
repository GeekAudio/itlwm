#!/usr/bin/env python3
"""Offline Test123 sender/legacy-seam and non-gating capture regressions."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROTOCOL = load("test123_sender_protocol_under_test",
                HERE / "dual_sender_protocol_test123.py")
PACKETSET = PROTOCOL._PACKETSET
LEGACY087 = load("test123_frozen_test087_protocol",
                 REPO / "developer-tools/test087/test087_controlled.py")
SOURCE = {"mac": "02:00:00:00:10:01", "ipv6_link_local": "fe80::1001"}
TARGET = {"mac": "02:00:00:00:20:02", "ipv6_link_local": "fe80::2002"}
NONCE = "1020304050607080"
TOKEN = "0123456789abcdef0123456789abcdef"


def packet_set():
    raw, _ = PACKETSET.encode_packet_set(
        SOURCE, TARGET, "offline-test123", wire_nonce_hex=NONCE,
        wifi_sequence_base=4094, awdl_sequence_base=65534)
    return raw, PACKETSET.decode_packet_set(raw)


def monitor_record(started: int, *, complete: bool = True) -> dict:
    deadline = started + PROTOCOL.SEND_BUDGET_NS
    observer_deadline = deadline + PROTOCOL.STATUS_TAIL_NS
    ended = observer_deadline if complete else observer_deadline - 1_000_000
    return {
        "schema": PROTOCOL.MONITOR_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC",
        "observation_time_semantics": PROTOCOL.OBSERVATION_TIME_SEMANTICS,
        "started_ns": started,
        "ended_ns": ended,
        "actual_horizon_ns": ended - started,
        "capture_window_ns": PROTOCOL.CAPTURE_WINDOW_NS,
        "status_tail_began_ns": deadline,
        "capture_finished": complete,
        "capture_limit_reached": False,
        "read_attempts": 0,
        "packets_received": 0,
        "exact_samples_recorded": 0,
        "exact_samples_overflow": 0,
        "receive_error": 0,
        "kernel_stats_available": True,
        "kernel_packets": 0,
        "kernel_dropped_packets": 0,
        "capture_loss_free": complete,
        "classification_complete": True,
        "identity_complete": True,
        "radiotap_invalid": 0,
        "radiotap_unsupported": 0,
        "unmatched_valid_packets": 0,
        "truncated_packets": 0,
        "exact_identity_unavailable": 0,
        "socket_topology": "distinct_tx_and_observer",
        "observer_bound_ifindex": 7,
        "outgoing_tap_is_rf_proof": False,
        "exact_match_by_ordinal": [0, 0, 0, 0],
        "outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "non_outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "tx_status_candidate_by_ordinal": [0, 0, 0, 0],
        "other_exact_by_ordinal": [0, 0, 0, 0],
        "samples": [],
        "status_candidate_matches_by_ordinal": [0, 0, 0, 0],
        "status_candidate_samples_recorded": 0,
        "status_candidate_samples_overflow": 0,
        "status_candidate_identity_unavailable": 0,
        "status_candidate_samples": [],
        "nonmatch_samples_recorded": 0,
        "nonmatch_samples_overflow": 0,
        "nonmatch_samples": [],
    }


def sender_result(manifest: dict, *, send_complete: bool = True,
                  monitor_complete: bool = True, dirty_queue: bool = False,
                  late_start: bool = False) -> dict:
    go = 1_000_000_000
    started = go + (PROTOCOL.GO_TO_START_MAX_NS + 1 if late_start
                    else 1_000_000)
    deadline = started + PROTOCOL.SEND_BUDGET_NS
    observer_deadline = deadline + PROTOCOL.STATUS_TAIL_NS
    attempted = (PROTOCOL.FRAME_COUNT if send_complete else
                 0 if late_start else 1)
    completed = attempted if send_complete else 0
    send_reason = "complete" if send_complete else (
        "go_to_start_budget_expired" if late_start else "send_errno")
    legacy_reason = "complete" if send_complete else (
        "schedule_or_sleep_failed" if late_start else "send_errno")
    rows = []
    for ordinal in range(attempted):
        frame = manifest["frames"][ordinal]
        before = started + ordinal * PROTOCOL.INTERVAL_MS * 1_000_000
        success = send_complete
        after = before + 1_000
        rows.append({
            "ordinal": ordinal,
            "ieee80211_sequence": frame["wifi_sequence"],
            "ieee80211_sequence_control": frame["sequence_control"],
            "awdl_sequence": frame["awdl_sequence"],
            "before_ns": before,
            "after_ns": after,
            "return_bytes": 106 if success else -1,
            "errno": 0 if success else 5,
        })
    finished = observer_deadline if monitor_complete else observer_deadline - 1_000_000
    return {
        "event": "SENDER_RESULT",
        "schema": PROTOCOL.SCHEMA,
        "tool_test": PROTOCOL.TOOL_TEST,
        "running_kernel_test": PROTOCOL.RUNNING_KERNEL_TEST,
        "packet_set_schema": PROTOCOL.PACKETSET_SCHEMA,
        "observation_time_semantics": PROTOCOL.OBSERVATION_TIME_SEMANTICS,
        "clock_domain": "CLOCK_MONOTONIC",
        "status": "complete" if send_complete else "failed",
        "run_token": TOKEN,
        "wire_nonce_hex": NONCE,
        "run_token_in_frame": False,
        "driver_rx_lease_ms": PROTOCOL.DRIVER_RX_LEASE_MS,
        "go_received_ns": go,
        "frames_requested": PROTOCOL.FRAME_COUNT,
        "frames_attempted": attempted,
        "frames_completed": completed,
        "send_complete": send_complete,
        "packet_bytes": 106,
        "radiotap_bytes": 10,
        "mpdu_bytes": 96,
        "payload_bytes": 96,
        "udp_payload_bytes": 8,
        "sent": completed,
        "elapsed_ms": 30 if send_complete else 0,
        "deadline_hit": False,
        "error_count": 0 if send_complete else 1,
        "last_errno": 0 if send_complete else 5,
        "stop_reason": legacy_reason,
        "sender_stop_reason": send_reason,
        "tx_flags_requested": "NOSEQNO",
        "noack_requested": False,
        "ack_policy": "normal_unicast_requested",
        "hardware_honoring": "unknown",
        "raw_txs": "unknown",
        "mac_ack": "unknown",
        "interval_ms": PROTOCOL.INTERVAL_MS,
        "timing_schema": 1,
        "send_budget_ns": PROTOCOL.SEND_BUDGET_NS,
        "status_tail_ns": PROTOCOL.STATUS_TAIL_NS,
        "capture_window_ns": PROTOCOL.CAPTURE_WINDOW_NS,
        "started_ns": started,
        "send_deadline_ns": deadline,
        "observer_deadline_ns": observer_deadline,
        "finished_ns": finished,
        "go_to_start_ns": started - go,
        "go_to_start_max_ns": PROTOCOL.GO_TO_START_MAX_NS,
        "first_send_ns": None if late_start else started,
        "local_send_calls": attempted,
        "actual_horizon_ns": finished - started,
        "pre_capture_queue_drain": {
            "read_attempts": 1 if dirty_queue else 0,
            "packets_drained": 0,
            "receive_error": 0 if not dirty_queue else 5,
            "drain_complete": not dirty_queue,
            "kernel_stats_available": True,
            "kernel_packets": 0 if not dirty_queue else 1,
            "kernel_dropped_packets": 0,
        },
        "send_timing": rows,
        "monitor_observation": monitor_record(started, complete=monitor_complete),
        "radio_transmission_proven": False,
        "rf_transmission_proven": False,
        "firmware_tx_status_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
        "intel_arm_invoked": False,
        "boot_claim_used": False,
    }


class Test123SenderProtocol(unittest.TestCase):
    def setUp(self):
        PROTOCOL.clear_packet_set_binding()
        raw, self.manifest = packet_set()
        PROTOCOL.bind_packet_set(raw)

    def tearDown(self):
        PROTOCOL.clear_packet_set_binding()

    def test_complete_sender_uses_legacy_status_and_exact_projection(self):
        result = sender_result(self.manifest)
        checked = PROTOCOL.validate_result(result, TOKEN, NONCE, self.manifest)
        self.assertTrue(checked["sender_status_is_non_gating_for_rx"])
        self.assertEqual(checked["monitor_observation_state"], "complete")
        legacy = PROTOCOL.legacy_projection(checked)
        self.assertEqual(set(legacy), LEGACY087.SENDER_RESULT_ALLOWED_KEYS)
        old_frames = LEGACY087.SENDER_FRAMES
        old_flags = LEGACY087.SENDER_TX_FLAGS
        try:
            LEGACY087.SENDER_FRAMES = 4
            LEGACY087.SENDER_TX_FLAGS = "NOSEQNO"
            parsed = LEGACY087.parse_sender_result(
                json.dumps(legacy, separators=(",", ":")))
        finally:
            LEGACY087.SENDER_FRAMES = old_frames
            LEGACY087.SENDER_TX_FLAGS = old_flags
        self.assertEqual(parsed["status"], "complete")

    def test_sender_failure_keeps_completed_monitor_and_does_not_gate_rx(self):
        result = sender_result(self.manifest, send_complete=False)
        checked = PROTOCOL.validate_result(result, TOKEN, NONCE, self.manifest)
        self.assertFalse(checked["send_complete"])
        self.assertTrue(checked["sender_status_is_non_gating_for_rx"])
        self.assertTrue(checked["monitor_observation"]["capture_finished"])
        legacy = PROTOCOL.legacy_projection(checked)
        self.assertEqual(legacy["status"], "failed")
        old_frames = LEGACY087.SENDER_FRAMES
        old_flags = LEGACY087.SENDER_TX_FLAGS
        try:
            LEGACY087.SENDER_FRAMES = 4
            LEGACY087.SENDER_TX_FLAGS = "NOSEQNO"
            parsed = LEGACY087.parse_sender_result(
                json.dumps(legacy, separators=(",", ":")))
        finally:
            LEGACY087.SENDER_FRAMES = old_frames
            LEGACY087.SENDER_TX_FLAGS = old_flags
        self.assertEqual(parsed["status"], "failed")
        self.assertEqual(result["sender_stop_reason"], "send_errno")

    def test_missing_after_timestamp_is_unknown_not_zero_and_keeps_receive_result(self):
        result = sender_result(self.manifest, send_complete=False)
        result.update({
            "sender_stop_reason": "clock_after_failed",
            "stop_reason": "monotonic_clock_unavailable",
            "frames_completed": 1,
            "sent": 1,
        })
        result["send_timing"][0].update({"after_ns": None, "return_bytes": 106, "errno": 0})
        checked = PROTOCOL.validate_result(result, TOKEN, NONCE, self.manifest)
        self.assertIsNone(checked["send_timing"][0]["after_ns"])
        self.assertTrue(checked["sender_status_is_non_gating_for_rx"])

    def test_complete_send_preserves_incomplete_monitor_as_unknown_not_failure(self):
        result = sender_result(self.manifest, monitor_complete=False)
        checked = PROTOCOL.validate_result(result, TOKEN, NONCE, self.manifest)
        self.assertEqual(checked["status"], "complete")
        self.assertEqual(checked["monitor_observation_state"], "incomplete")
        self.assertFalse(checked["monitor_observation"]["capture_finished"])
        self.assertFalse(checked["monitor_observation"]["capture_loss_free"])

    def test_late_start_is_retained_as_failed_not_rejected_before_observation(self):
        value = sender_result(self.manifest, send_complete=False, late_start=True)
        checked = PROTOCOL.validate_result(value, TOKEN, NONCE, self.manifest)
        self.assertFalse(checked["send_complete"])
        self.assertGreater(checked["go_to_start_ns"], PROTOCOL.GO_TO_START_MAX_NS)
        self.assertIsNone(checked["first_send_ns"])

    def test_complete_sender_with_dirty_pre_capture_queue_is_rejected(self):
        value = sender_result(self.manifest, dirty_queue=True)
        with self.assertRaisesRegex(PROTOCOL.SenderProtocolError,
                                   "sender_clean_status_with_dirty_queue"):
            PROTOCOL.validate_result(value, TOKEN, NONCE, self.manifest)

    def test_ready_binds_current_packetset_nonce(self):
        self.assertEqual(PROTOCOL.parse_ready(
            "READY " + " ".join(f"{k}={v}" for k, v in PROTOCOL.READY_VALUES.items()) +
            f" wire_nonce_hex={NONCE}", NONCE)["wire_nonce_hex"], NONCE)
        with self.assertRaisesRegex(PROTOCOL.SenderProtocolError, "sender_ready_nonce_mismatch"):
            PROTOCOL.parse_ready(
                "READY " + " ".join(f"{k}={v}" for k, v in PROTOCOL.READY_VALUES.items()) +
                " wire_nonce_hex=ffffffffffffffff", NONCE)

    def test_started_event_records_late_window_without_rejecting_rx_attempt(self):
        go = 1_000_000_000
        started = go + PROTOCOL.GO_TO_START_MAX_NS + 1
        value = {
            "event": "SENDER_STARTED", "schema": PROTOCOL.SCHEMA,
            "tool_test": PROTOCOL.TOOL_TEST,
            "running_kernel_test": PROTOCOL.RUNNING_KERNEL_TEST,
            "packet_set_schema": PROTOCOL.PACKETSET_SCHEMA,
            "clock_domain": "CLOCK_MONOTONIC",
            "observation_time_semantics": PROTOCOL.OBSERVATION_TIME_SEMANTICS,
            "run_token": TOKEN, "wire_nonce_hex": NONCE,
            "driver_rx_lease_ms": PROTOCOL.DRIVER_RX_LEASE_MS,
            "go_received_ns": go, "started_ns": started,
            "send_deadline_ns": started + PROTOCOL.SEND_BUDGET_NS,
            "observer_deadline_ns": started + PROTOCOL.CAPTURE_WINDOW_NS,
            "go_to_start_ns": started - go,
            "go_to_start_max_ns": PROTOCOL.GO_TO_START_MAX_NS,
            "send_budget_ns": PROTOCOL.SEND_BUDGET_NS,
            "status_tail_ns": PROTOCOL.STATUS_TAIL_NS,
            "frames_requested": PROTOCOL.FRAME_COUNT,
            "interval_ms": PROTOCOL.INTERVAL_MS,
            "tx_flags_requested": "NOSEQNO", "noack_requested": False,
            "intel_arm_invoked": False, "boot_claim_used": False,
        }
        checked = PROTOCOL.parse_started(value, TOKEN, NONCE)
        self.assertFalse(checked["start_lease_valid"])

    def test_c_verify_only_interoperates_with_test122_packetset_without_sending(self):
        clang = shutil.which("clang")
        if clang is None:
            self.skipTest("clang unavailable for host-only sender contract build")
        source = HERE / "awdl_router_rx_lease_sender_test123.c"
        parser_dir = REPO / "developer-tools/test089/txstatus-observer"
        with tempfile.TemporaryDirectory(prefix="t123-host-") as tmp:
            binary = Path(tmp) / "sender-host"
            build = subprocess.run([
                clang, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-I", str(HERE), "-I", str(parser_dir), str(source),
                str(parser_dir / "radiotap_parser.c"), "-o", str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(build.returncode, 0, build.stderr)
            raw, _ = packet_set()
            packet_path = Path(tmp) / "packetset.bin"
            packet_path.write_bytes(raw)
            packet_path.chmod(0o600)
            verify = subprocess.run([str(binary), "--verify-only", "--packet-set",
                                     str(packet_path)], capture_output=True,
                                    text=True, check=False)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            parsed = PROTOCOL.parse_packetset_valid(
                "PACKET_SET_VALID " + verify.stdout.strip(),
                expected_wire_nonce_hex=NONCE)
            self.assertEqual(parsed["wire_nonce_hex"], NONCE)


if __name__ == "__main__":
    unittest.main()
