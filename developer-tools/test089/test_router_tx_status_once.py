#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import router_tx_status_once as tool


TOKEN = "0123456789abcdef0123456789abcdef"


def result(*, status: str, counts: dict, **overrides) -> dict:
    value = {
        "event": "TEST089_RESULT",
        "status": status,
        "run_token": TOKEN,
        "send_attempted": True,
        "send_completed": True,
        "setup_error": 0,
        "send_errno": 0,
        "send_bytes": 106,
        "observation_complete": True,
        "timeout": True,
        "recv_error": 0,
        "deadline_reached": True,
        "capture_limit_reached": False,
        "rx_window_ms": 2000,
        "elapsed_ms": 2000,
        "tx_flags_requested": "NOACK|NOSEQNO",
        "firmware_tx_status_proven": False,
        "airborne_proven": False,
        "rf_delivery_proven": False,
        "acked_proven": False,
        "counts": counts,
    }
    value.update(overrides)
    return value


def observation(*, kind: str, packet_type: int, has_tx_flags: bool,
                tx_flags: int, has_data_retries: bool,
                data_retries: int = 0) -> dict:
    return {
        "event": "TEST089_OBSERVATION",
        "run_token": TOKEN,
        "kind": kind,
        "packet_type": packet_type,
        "exact_mpdu_match": True,
        "wifi_sequence": 291,
        "awdl_sequence": 34305,
        "has_tx_flags": has_tx_flags,
        "tx_flags": tx_flags,
        "has_data_retries": has_data_retries,
        "data_retries": data_retries,
        "firmware_tx_status_proven": False,
        "airborne_proven": False,
        "rf_delivery_proven": False,
        "acked_proven": False,
    }


def send_event(**overrides) -> dict:
    value = {
        "event": "TEST089_SEND",
        "run_token": TOKEN,
        "send_attempted": True,
        "send_completed": True,
        "send_bytes": 106,
        "send_errno": 0,
        "send_started_ns": 1000,
        "send_finished_ns": 1001,
        "firmware_tx_status_proven": False,
        "airborne_proven": False,
        "rf_delivery_proven": False,
        "acked_proven": False,
    }
    value.update(overrides)
    return value


class RouterTxStatusOnceTests(unittest.TestCase):
    def test_json_event_order_is_send_observations_then_result(self):
        good = ["TEST089_SEND", "TEST089_OBSERVATION", "TEST089_RESULT"]
        self.assertEqual(tool.validate_event_order(good), [])
        self.assertIn("json_event_order", tool.validate_event_order(
            ["TEST089_OBSERVATION", "TEST089_SEND", "TEST089_RESULT"]))
        self.assertIn("json_event_order", tool.validate_event_order(
            ["TEST089_SEND", "TEST089_SEND", "TEST089_RESULT"]))
        self.assertIn("json_event_order", tool.validate_event_order(
            ["TEST089_SEND", "TEST089_RESULT", "TEST089_OBSERVATION"]))

    def test_matched_candidate_and_host_echo_are_only_router_completion_evidence(self):
        counts = {
            "rx_packets": 3,
            "probe_matches": 2,
            "outgoing_echo": 1,
            "host_driver_completion_candidate": 1,
            "other_match": 0,
        }
        observations = [
            observation(kind="packet_outgoing_echo", packet_type=4,
                        has_tx_flags=True, tx_flags=0x18,
                        has_data_retries=False),
            observation(kind="host_driver_completion_candidate", packet_type=3,
                        has_tx_flags=True, tx_flags=0,
                        has_data_retries=True),
        ]
        value = result(status="host_driver_completion_candidate_observed",
                       counts=counts)
        self.assertEqual(tool.validate_result(value, observations, TOKEN, [send_event()]), [])

    def test_complete_empty_window_is_unknown_not_failure(self):
        counts = {
            "rx_packets": 4,
            "probe_matches": 0,
            "outgoing_echo": 0,
            "host_driver_completion_candidate": 0,
            "other_match": 0,
        }
        value = result(status="no_matching_observation", counts=counts)
        self.assertEqual(tool.validate_result(value, [], TOKEN, [send_event()]), [])

    def test_outgoing_raw_echo_never_counts_as_status(self):
        counts = {
            "rx_packets": 1,
            "probe_matches": 1,
            "outgoing_echo": 1,
            "host_driver_completion_candidate": 0,
            "other_match": 0,
        }
        echo = observation(kind="packet_outgoing_echo", packet_type=4,
                           has_tx_flags=True, tx_flags=0x18,
                           has_data_retries=False)
        value = result(status="outgoing_echo_only", counts=counts)
        self.assertEqual(tool.validate_result(value, [echo], TOKEN, [send_event()]), [])

    def test_ten_byte_otherhost_copy_without_retries_is_not_status(self):
        counts = {
            "rx_packets": 1,
            "probe_matches": 1,
            "outgoing_echo": 0,
            "host_driver_completion_candidate": 0,
            "other_match": 1,
        }
        raw_echo = observation(kind="other_matching_packet", packet_type=3,
                               has_tx_flags=True, tx_flags=0x18,
                               has_data_retries=False)
        value = result(status="no_status_candidate_observed", counts=counts)
        self.assertEqual(tool.validate_result(value, [raw_echo], TOKEN, [send_event()]), [])

    def test_missing_result_field_fails_closed(self):
        counts = {
            "rx_packets": 0,
            "probe_matches": 0,
            "outgoing_echo": 0,
            "host_driver_completion_candidate": 0,
            "other_match": 0,
        }
        value = result(status="no_matching_observation", counts=counts)
        del value["rf_delivery_proven"]
        self.assertIn("result_field_set",
                      tool.validate_result(value, [], TOKEN, [send_event()]))

    def test_incomplete_or_capture_limited_window_is_rejected(self):
        counts = {
            "rx_packets": 1,
            "probe_matches": 0,
            "outgoing_echo": 0,
            "host_driver_completion_candidate": 0,
            "other_match": 0,
        }
        incomplete = result(status="no_matching_observation", counts=counts,
                            observation_complete=False, timeout=False,
                            deadline_reached=False, elapsed_ms=900)
        self.assertTrue(tool.validate_result(incomplete, [], TOKEN, [send_event()]))
        limited = result(status="no_matching_observation", counts=counts,
                         capture_limit_reached=True)
        self.assertIn("capture_limit_reached",
                      tool.validate_result(limited, [], TOKEN, [send_event()]))

    def test_count_mismatch_is_rejected(self):
        counts = {
            "rx_packets": 1,
            "probe_matches": 1,
            "outgoing_echo": 0,
            "host_driver_completion_candidate": 1,
            "other_match": 0,
        }
        value = result(status="host_driver_completion_candidate_observed",
                       counts=counts)
        errors = tool.validate_result(value, [], TOKEN, [send_event()])
        self.assertIn("observation_counts", errors)
        self.assertIn("probe_matches", errors)

    def test_observation_overclaim_and_malformed_types_are_rejected(self):
        counts = {
            "rx_packets": 1,
            "probe_matches": 1,
            "outgoing_echo": 0,
            "host_driver_completion_candidate": 1,
            "other_match": 0,
        }
        candidate = observation(kind="host_driver_completion_candidate", packet_type=3,
                                has_tx_flags=True, tx_flags=0,
                                has_data_retries=True)
        value = result(status="host_driver_completion_candidate_observed",
                       counts=counts)
        bad_claim = dict(candidate, airborne_proven=True)
        self.assertIn("observation_overclaim",
                      tool.validate_result(value, [bad_claim], TOKEN, [send_event()]))
        bad_rf_claim = dict(candidate, rf_delivery_proven=True)
        self.assertIn("observation_overclaim",
                      tool.validate_result(value, [bad_rf_claim], TOKEN, [send_event()]))
        missing = dict(candidate)
        del missing["acked_proven"]
        self.assertIn("observation_field_set",
                      tool.validate_result(value, [missing], TOKEN, [send_event()]))
        malformed = dict(candidate, tx_flags=True)
        self.assertIn("observation_types",
                      tool.validate_result(value, [malformed], TOKEN, [send_event()]))

    def test_missing_or_duplicate_send_event_is_rejected(self):
        counts = {"rx_packets": 0, "probe_matches": 0, "outgoing_echo": 0,
                  "host_driver_completion_candidate": 0, "other_match": 0}
        value = result(status="no_matching_observation", counts=counts)
        self.assertIn("send_event_count", tool.validate_result(value, [], TOKEN, []))
        self.assertIn("send_event_count",
                      tool.validate_result(value, [], TOKEN,
                                           [send_event(), send_event()]))

    def test_send_schema_flags_and_send_result_consistency_are_strict(self):
        counts = {"rx_packets": 0, "probe_matches": 0, "outgoing_echo": 0,
                  "host_driver_completion_candidate": 0, "other_match": 0}
        value = result(status="no_matching_observation", counts=counts)
        missing = send_event()
        del missing["rf_delivery_proven"]
        self.assertIn("send_field_set",
                      tool.validate_result(value, [], TOKEN, [missing]))
        overclaim = send_event(rf_delivery_proven=True)
        self.assertIn("send_overclaim",
                      tool.validate_result(value, [], TOKEN, [overclaim]))
        contradiction = send_event(send_bytes=105)
        errors = tool.validate_result(value, [], TOKEN, [contradiction])
        self.assertIn("send_send_bytes", errors)
        self.assertIn("send_result_mismatch", errors)

    def test_send_timestamps_must_be_nonzero_and_ordered(self):
        counts = {"rx_packets": 0, "probe_matches": 0, "outgoing_echo": 0,
                  "host_driver_completion_candidate": 0, "other_match": 0}
        value = result(status="no_matching_observation", counts=counts)
        bad_order = send_event(send_started_ns=1002, send_finished_ns=1001)
        self.assertIn("send_timestamp_order",
                      tool.validate_result(value, [], TOKEN, [bad_order]))
        zero = send_event(send_started_ns=0)
        self.assertIn("send_started_ns",
                      tool.validate_result(value, [], TOKEN, [zero]))

    def test_other_match_rejects_invalid_packet_type_and_absent_values(self):
        counts = {"rx_packets": 1, "probe_matches": 1, "outgoing_echo": 0,
                  "host_driver_completion_candidate": 0, "other_match": 1}
        value = result(status="no_status_candidate_observed", counts=counts)
        invalid_packet = observation(kind="other_matching_packet", packet_type=8,
                                     has_tx_flags=False, tx_flags=0,
                                     has_data_retries=False)
        self.assertIn("observation_types",
                      tool.validate_result(value, [invalid_packet], TOKEN,
                                           [send_event()]))
        inconsistent_absence = observation(kind="other_matching_packet", packet_type=3,
                                           has_tx_flags=False, tx_flags=1,
                                           has_data_retries=False, data_retries=0)
        self.assertIn("absent_radiotap_value",
                      tool.validate_result(value, [inconsistent_absence], TOKEN,
                                           [send_event()]))


if __name__ == "__main__":
    unittest.main()
