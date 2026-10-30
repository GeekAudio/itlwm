#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import send_timing


SENDER_GO_NS = 1_000_000_000


def sender_result(attempts=2):
    rows = []
    for i in range(attempts):
        before = SENDER_GO_NS + 10_000 + i * 80_000_000
        rows.append({
            "ordinal": i,
            "ieee80211_sequence": (291 + i) & 0xFFF,
            "awdl_sequence": (34305 + i) & 0xFFFF,
            "before_ns": before,
            "after_ns": before + 1_000,
            "return_bytes": 106,
            "errno": 0,
        })
    return {
        "event": "SENDER_RESULT",
        "timing_schema": 1,
        "clock_domain": "CLOCK_MONOTONIC",
        "go_received_ns": SENDER_GO_NS,
        "started_ns": SENDER_GO_NS + 500,
        "finished_ns": rows[-1]["after_ns"] + 1_000,
        "frames_attempted": attempts,
        "frames_completed": attempts,
        "send_timing": rows,
    }


def sender_started():
    return {
        "event": "SENDER_STARTED",
        "timing_schema": 1,
        "clock_domain": "CLOCK_MONOTONIC",
        "go_received_ns": SENDER_GO_NS,
        "started_ns": SENDER_GO_NS + 500,
    }


class SendTimingTests(unittest.TestCase):
    def test_ieee_and_awdl_sequences_are_distinct(self):
        parsed = send_timing.parse_sender_timing(sender_result())
        self.assertEqual(parsed["entries"][0]["ieee80211_sequence"], 291)
        self.assertEqual(parsed["entries"][0]["awdl_sequence"], 34305)
        self.assertNotEqual(parsed["entries"][0]["ieee80211_sequence"],
                            parsed["entries"][0]["awdl_sequence"])

    def test_nominal_interval_is_labeled_and_never_rf_proof(self):
        report = send_timing.correlate_with_mac_events(
            sender_result(),
            go_write_ns=(1_000_000, 1_010_000),
            sender_started_event=sender_started(),
            sender_started_receipt_ns=1_030_000,
            sender_result_receipt_ns=200_000_000,
            roc_ns=(1_031_000, 1_032_000),
        )
        row = report["send_attempts"][0]
        self.assertTrue(row["strict_interval_can_overlap_roc"])
        self.assertTrue(row["nominal_interval_overlaps_roc"])
        self.assertEqual(row["sender_clock_interval_ns"],
                         [SENDER_GO_NS + 10_000, SENDER_GO_NS + 11_000])
        self.assertFalse(report["nominal_assumption_is_measured"])
        self.assertFalse(report["local_send_writes_prove_rf"])
        self.assertFalse(report["cross_clock_epoch_subtraction_used"])
        self.assertTrue(report["timing_instrumentation_is_non_gating_for_native_input_evidence"])

    def test_missing_started_event_keeps_linux_and_mac_domains_unjoined(self):
        report = send_timing.correlate_with_mac_events(
            sender_result(),
            go_write_ns=(1_000_000, 1_010_000),
            sender_started_event=None,
            sender_started_receipt_ns=None,
            sender_result_receipt_ns=200_000_000,
            roc_ns=(1_031_000, 1_032_000),
        )
        row = report["send_attempts"][0]
        self.assertEqual(row["sender_clock_interval_ns"],
                         [SENDER_GO_NS + 10_000, SENDER_GO_NS + 11_000])
        self.assertEqual(row["strict_causal_host_interval_ns"],
                         [1_000_000, 200_000_000])
        self.assertIsNone(row["nominal_interval_overlaps_roc"])
        self.assertEqual(report["nominal_summary"],
                         "unknown_missing_sender_started_event_or_frames")

    def test_missing_packet_timestamp_is_unknown_not_a_global_failure(self):
        value = sender_result(attempts=1)
        value["send_timing"][0]["after_ns"] = None
        report = send_timing.correlate_with_mac_events(
            value,
            go_write_ns=(1_000_000, 1_010_000),
            sender_started_event=sender_started(),
            sender_started_receipt_ns=1_030_000,
            sender_result_receipt_ns=200_000_000,
            roc_ns=(1_031_000, 1_032_000),
        )
        row = report["send_attempts"][0]
        self.assertIsNone(row["nominal_interval_overlaps_roc"])
        self.assertEqual(row["strict_causal_host_interval_ns"],
                         [1_000_000, 200_000_000])
        self.assertFalse(report["send_timing_complete"])
        self.assertTrue(report["timing_instrumentation_is_non_gating_for_native_input_evidence"])

    def test_missing_mac_roc_keeps_clocks_separate_and_overlap_unknown(self):
        report = send_timing.correlate_with_mac_events(
            sender_result(),
            go_write_ns=(1_000_000, 1_010_000),
            sender_started_event=sender_started(),
            sender_started_receipt_ns=1_030_000,
            sender_result_receipt_ns=200_000_000,
            roc_ns=None,
        )
        row = report["send_attempts"][0]
        self.assertIsNotNone(row["strict_causal_host_interval_ns"])
        self.assertIsNotNone(row["nominal_host_interval_ns"])
        self.assertIsNone(row["nominal_interval_overlaps_roc"])
        self.assertEqual(report["strict_causal_summary"],
                         "unknown_missing_mac_roc_interval")

    def test_missing_mac_go_boundary_leaves_host_correlation_unknown(self):
        report = send_timing.correlate_with_mac_events(
            sender_result(),
            go_write_ns=None,
            sender_started_event=sender_started(),
            sender_started_receipt_ns=1_030_000,
            sender_result_receipt_ns=200_000_000,
            roc_ns=(1_031_000, 1_032_000),
        )
        row = report["send_attempts"][0]
        self.assertIsNone(row["strict_causal_host_interval_ns"])
        self.assertIsNone(row["nominal_host_interval_ns"])
        self.assertEqual(row["sender_clock_interval_ns"],
                         [SENDER_GO_NS + 10_000, SENDER_GO_NS + 11_000])

    def test_start_event_must_match_result_clock(self):
        started = sender_started()
        started["started_ns"] += 1
        with self.assertRaises(send_timing.TimingError):
            send_timing.correlate_with_mac_events(
                sender_result(),
                go_write_ns=(1_000_000, 1_010_000),
                sender_started_event=started,
                sender_started_receipt_ns=1_030_000,
                sender_result_receipt_ns=200_000_000,
                roc_ns=(1_031_000, 1_032_000),
            )

    def test_invalid_sender_go_order_rejected(self):
        value = sender_result()
        value["go_received_ns"] = value["started_ns"] + 1
        with self.assertRaises(send_timing.TimingError):
            send_timing.parse_sender_timing(value)

    def test_missing_per_frame_timing_rejected(self):
        value = sender_result()
        value["send_timing"].pop()
        with self.assertRaises(send_timing.TimingError):
            send_timing.parse_sender_timing(value)

    def test_missing_sender_finish_keeps_packet_rows_and_marks_unknown(self):
        value = sender_result()
        value["finished_ns"] = None
        parsed = send_timing.parse_sender_timing(value)
        self.assertIsNone(parsed["finished_ns"])
        self.assertFalse(parsed["finish_time_known"])
        self.assertFalse(parsed["timing_complete"])
        report = send_timing.correlate_with_mac_events(
            value,
            go_write_ns=(1_000_000, 1_010_000),
            sender_started_event=sender_started(),
            sender_started_receipt_ns=1_030_000,
            sender_result_receipt_ns=200_000_000,
            roc_ns=(1_031_000, 1_032_000),
        )
        self.assertIsNone(report["sender_finished_ns"])
        self.assertFalse(report["sender_finish_time_known"])
        self.assertEqual(report["send_entry_count"], 2)

    def test_sender_end_clock_failure_preserves_rows_without_deadline_claim(self):
        value = sender_result()
        value.update({
            "status": "failed",
            "stop_reason": "monotonic_clock_end_failed",
            "last_errno": 5,
            "error_count": 1,
            "deadline_hit": False,
            "elapsed_ms": None,
            "finished_ns": None,
        })
        parsed = send_timing.parse_sender_timing(value)
        self.assertEqual(parsed["sender_stop_reason"], "monotonic_clock_end_failed")
        self.assertTrue(parsed["clock_or_schedule_failure"])
        self.assertFalse(parsed["timing_complete"])
        self.assertEqual(len(parsed["entries"]), 2)

    def test_sender_after_clock_failure_keeps_send_record_unknown(self):
        value = sender_result(attempts=1)
        row = value["send_timing"][0]
        row["after_ns"] = None
        value.update({
            "status": "failed",
            "stop_reason": "monotonic_clock_after_failed",
            "last_errno": 5,
            "error_count": 1,
            "deadline_hit": False,
        })
        parsed = send_timing.parse_sender_timing(value)
        self.assertEqual(parsed["entries"][0]["return_bytes"], 106)
        self.assertIsNone(parsed["entries"][0]["after_ns"])
        self.assertFalse(parsed["timing_complete"])

    def test_wire_sequence_mismatch_rejected(self):
        value = sender_result()
        value["send_timing"][0]["awdl_sequence"] = 291
        with self.assertRaises(send_timing.TimingError):
            send_timing.parse_sender_timing(value)

    def test_short_write_has_zero_errno_and_is_not_completed(self):
        value = sender_result(attempts=1)
        value["send_timing"][0]["return_bytes"] = 50
        value["frames_completed"] = 0
        parsed = send_timing.parse_sender_timing(value)
        self.assertEqual(parsed["frames_completed"], 0)
        self.assertEqual(parsed["entries"][0]["errno"], 0)

    def test_failed_send_requires_errno(self):
        value = sender_result(attempts=1)
        value["send_timing"][0]["return_bytes"] = -1
        value["send_timing"][0]["errno"] = 5
        value["frames_completed"] = 0
        self.assertEqual(send_timing.parse_sender_timing(value)["frames_completed"], 0)
        value["send_timing"][0]["errno"] = 0
        with self.assertRaises(send_timing.TimingError):
            send_timing.parse_sender_timing(value)


if __name__ == "__main__":
    unittest.main()
