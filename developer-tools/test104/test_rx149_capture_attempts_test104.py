import struct
import unittest

from rx149_capture_attempts_test104 import (
    CAPACITY, CHECK_MASK, HEADER_FIELDS, LEGACY_CHECK_MASK, MAGIC,
    RECORD_FIELDS, WIRE_BYTES, WIRE_SCHEMA, WORD_COUNT, SCHEMA,
    CaptureLedgerError, decode_capture_attempts,
    summarize_capture_samples,
)


def make_wire(*, complete=True, overflow=0, commit_mask=None, reserved_begin=1,
              reserved_end=None, record_overrides=None):
    if reserved_end is None:
        reserved_end = reserved_begin
    if commit_mask is None:
        commit_mask = (1 << reserved_begin) - 1 if complete else 0
    header = [
        MAGIC, 1, WORD_COUNT, CAPACITY, reserved_begin, reserved_end,
        commit_mask, overflow, int(complete),
    ]
    rows = []
    for slot in range(CAPACITY):
        record = [0] * len(RECORD_FIELDS)
        record[RECORD_FIELDS.index("Outcome")] = 2
        record[RECORD_FIELDS.index("EvaluatedMask")] = 0b111
        record[RECORD_FIELDS.index("PassedMask")] = 0b011
        record[RECORD_FIELDS.index("FailureCheck")] = 3
        if slot == 0:
            for key, value in (record_overrides or {}).items():
                record[RECORD_FIELDS.index(key)] = value
        rows.extend(record)
    words = header + rows
    return struct.pack("<" + "Q" * len(words), *words)


class Rx149CaptureAttemptTests(unittest.TestCase):
    def test_schema1_wire_layout_remains_unchanged(self):
        self.assertEqual(WIRE_SCHEMA, 1)
        self.assertEqual(len(HEADER_FIELDS), 9)
        self.assertEqual(len(RECORD_FIELDS), 52)
        self.assertEqual(WORD_COUNT, 425)
        self.assertEqual(WIRE_BYTES, 3400)

    def test_decodes_numeric_attempt_without_promoting_it_to_delivery(self):
        decoded = decode_capture_attempts(make_wire())
        self.assertEqual(decoded["status"], "stable_complete_cut")
        self.assertEqual(decoded["record_count"], 1)
        self.assertEqual(decoded["records"][0]["outcome_name"], "rejected")
        self.assertEqual(decoded["records"][0]["fields"]["FailureCheck"], 3)
        self.assertFalse(decoded["capture_delivery_proven"])
        self.assertFalse(decoded["ifnet_delivery_proven"])
        self.assertFalse(decoded["roc_end_or_close_proven"])

    def test_missing_property_is_unknown_not_success(self):
        decoded = decode_capture_attempts(None)
        self.assertEqual(decoded["status"], "property_not_published")
        self.assertFalse(decoded["capture_delivery_proven"])

    def test_rejects_wrong_size_magic_schema_or_capacity(self):
        with self.assertRaisesRegex(CaptureLedgerError, "wire_size"):
            decode_capture_attempts(bytes(WIRE_BYTES - 8))
        for position, value in ((0, 0), (1, 2), (3, CAPACITY + 1)):
            words = list(struct.unpack("<" + "Q" * WORD_COUNT, make_wire()))
            words[position] = value
            with self.assertRaises(CaptureLedgerError):
                decode_capture_attempts(struct.pack("<" + "Q" * WORD_COUNT, *words))

    def test_partial_publication_and_sticky_overflow_are_preserved(self):
        partial = decode_capture_attempts(make_wire(
            complete=False, overflow=0, commit_mask=1,
            reserved_begin=1, reserved_end=2))
        self.assertEqual(partial["status"], "partial_cut")
        # The first ledger snapshot can reserve seven slots, then an append
        # commits the eighth and a following append sets sticky overflow
        # before the second reservation load.
        partial_overflow = decode_capture_attempts(make_wire(
            complete=False, overflow=1, commit_mask=0x7f,
            reserved_begin=7, reserved_end=8))
        self.assertEqual(partial_overflow["status"], "partial_cut")
        self.assertEqual(partial_overflow["record_count"], 7)
        self.assertTrue(partial_overflow["overflow_observed"])
        self.assertFalse(partial_overflow["complete_cut"])
        overflow = decode_capture_attempts(make_wire(
            complete=True, overflow=1, commit_mask=(1 << CAPACITY) - 1,
            reserved_begin=CAPACITY, reserved_end=CAPACITY))
        self.assertEqual(overflow["status"], "stable_complete_cut_with_overflow")
        self.assertTrue(overflow["overflow_observed"])
        self.assertFalse(partial["overflow_observed"])
        self.assertEqual(partial["record_count"], 1)
        self.assertFalse(partial["complete_cut_is_freshness_proof"])

    def test_captured_requires_every_production_check_to_pass(self):
        captured = decode_capture_attempts(make_wire(record_overrides={
            "Outcome": 1,
            "FailureCheck": 0,
            "EvaluatedMask": LEGACY_CHECK_MASK,
            "PassedMask": LEGACY_CHECK_MASK,
        }))
        self.assertEqual(captured["records"][0]["outcome_name"],
                         "captured_to_bounded_queue")
        current_captured = decode_capture_attempts(make_wire(record_overrides={
            "Outcome": 1,
            "FailureCheck": 0,
            "EvaluatedMask": CHECK_MASK,
            "PassedMask": CHECK_MASK,
        }))
        self.assertEqual(current_captured["records"][0]["outcome_name"],
                         "captured_to_bounded_queue")
        with self.assertRaisesRegex(CaptureLedgerError, "captured_failure"):
            decode_capture_attempts(make_wire(record_overrides={
                "Outcome": 1,
                "FailureCheck": 3,
                "EvaluatedMask": 0b111,
                "PassedMask": 0b011,
            }))
        with self.assertRaisesRegex(CaptureLedgerError, "captured_failure"):
            decode_capture_attempts(make_wire(record_overrides={
                "Outcome": 1,
                "FailureCheck": 0,
                "EvaluatedMask": 0b111,
                "PassedMask": 0b111,
            }))

    def test_queue_full_and_rejected_outcomes_match_first_failed_check(self):
        full_mask = LEGACY_CHECK_MASK
        queue_full = decode_capture_attempts(make_wire(record_overrides={
            "Outcome": 3,
            "FailureCheck": 25,
            "EvaluatedMask": full_mask,
            "PassedMask": full_mask & ~(1 << 24),
        }))
        self.assertEqual(queue_full["records"][0]["failure_check_name"],
                         "QueueSpaceAvailable")
        with self.assertRaisesRegex(CaptureLedgerError, "queue_full_failure"):
            decode_capture_attempts(make_wire(record_overrides={
                "Outcome": 3,
                "FailureCheck": 24,
                "EvaluatedMask": full_mask,
                "PassedMask": full_mask & ~(1 << 23),
            }))
        with self.assertRaisesRegex(CaptureLedgerError, "rejected_failure"):
            decode_capture_attempts(make_wire(record_overrides={
                "Outcome": 2,
                "FailureCheck": 3,
                "EvaluatedMask": 0b111,
                "PassedMask": 0b001,
            }))
        with self.assertRaisesRegex(CaptureLedgerError, "unknown"):
            decode_capture_attempts(make_wire(record_overrides={
                "Outcome": 5,
                "FailureCheck": 3,
                "EvaluatedMask": 0b111,
                "PassedMask": 0b011,
            }))

    def test_retry_window_rejection_and_duplicate_are_distinct_from_capture(self):
        rejected = decode_capture_attempts(make_wire(record_overrides={
            "Outcome": 2,
            "FailureCheck": 26,
            "EvaluatedMask": CHECK_MASK,
            "PassedMask": CHECK_MASK & ~(1 << 25),
        }))
        self.assertEqual(rejected["records"][0]["failure_check_name"],
                         "RetryWindowSlotAvailable")

        duplicate = decode_capture_attempts(make_wire(record_overrides={
            "Outcome": 4,
            "FailureCheck": 0,
            "EvaluatedMask": CHECK_MASK,
            "PassedMask": CHECK_MASK,
        }))
        self.assertEqual(duplicate["record_count"], 1)
        self.assertEqual(duplicate["records"][0]["outcome_name"],
                         "duplicate_retry_not_queued")
        self.assertNotEqual(duplicate["records"][0]["outcome_name"],
                            "captured_to_bounded_queue")
        self.assertFalse(duplicate["capture_delivery_proven"])
        self.assertFalse(duplicate["ifnet_delivery_proven"])

    def test_duplicate_requires_all_26_checks_and_no_failure(self):
        malformed = (
            {"FailureCheck": 26, "EvaluatedMask": CHECK_MASK,
             "PassedMask": CHECK_MASK & ~(1 << 25)},
            {"FailureCheck": 0, "EvaluatedMask": LEGACY_CHECK_MASK,
             "PassedMask": LEGACY_CHECK_MASK},
        )
        for overrides in malformed:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(CaptureLedgerError, "duplicate_failure"):
                    decode_capture_attempts(make_wire(record_overrides={
                        "Outcome": 4, **overrides,
                    }))

    def test_uncommitted_slot_is_not_read_and_complete_cut_is_strict(self):
        partial = decode_capture_attempts(make_wire(
            complete=False, commit_mask=0, reserved_begin=1, reserved_end=1))
        self.assertEqual(partial["record_count"], 0)
        words = list(struct.unpack("<" + "Q" * WORD_COUNT, make_wire()))
        words[4] = 2  # reserved begin, but only slot 0 is committed
        words[5] = 2  # keep the reservation interval monotonic
        with self.assertRaisesRegex(CaptureLedgerError, "complete_cut"):
            decode_capture_attempts(struct.pack("<" + "Q" * WORD_COUNT, *words))

    def test_rejects_inconsistent_check_masks(self):
        with self.assertRaisesRegex(CaptureLedgerError, "check_masks"):
            decode_capture_attempts(make_wire(record_overrides={
                "PassedMask": 0b100,
            }))

    def test_rejects_reservation_bounds_that_move_backwards(self):
        with self.assertRaisesRegex(CaptureLedgerError, "header_value"):
            decode_capture_attempts(make_wire(
                complete=False, commit_mask=0b11,
                reserved_begin=2, reserved_end=1))
        with self.assertRaisesRegex(CaptureLedgerError, "header_value"):
            decode_capture_attempts(make_wire(
                complete=False, overflow=1, commit_mask=0x7f,
                reserved_begin=7, reserved_end=7))

    def test_collector_errors_do_not_count_as_property_present(self):
        summary = summarize_capture_samples([{
            "sample_status": "collector_error",
            "rx149_capture_attempts": {
                "schema": SCHEMA,
                "status": "collector_error",
                "records": [],
            },
        }])
        self.assertEqual(summary["property_present_sample_count"], 0)
        self.assertEqual(summary["sample_errors"], {"collector_error": 1})

    def test_collector_error_keeps_prior_cut_historical_not_current(self):
        valid = decode_capture_attempts(make_wire())
        error = {
            "schema": SCHEMA,
            "status": "collector_error",
            "records": [],
        }
        summary = summarize_capture_samples([
            {"rx149_capture_attempts": valid},
            {"rx149_capture_attempts": error},
        ])
        self.assertEqual(summary["status"], "collector_error")
        self.assertFalse(summary["current_cut_available"])
        self.assertIsNone(summary["latest_wire_sha256"])
        self.assertIsNone(summary["latest_record_count"])
        self.assertIsNone(summary["latest_overflow_observed"])
        self.assertIsNone(summary["latest_complete_cut"])
        self.assertFalse(summary["latest_cut_is_last_sample"])
        self.assertFalse(summary["latest_cut_freshness_proven"])
        self.assertEqual(summary["last_valid_sample"]["sample_index"], 0)
        self.assertFalse(summary["last_valid_sample"]["is_current_sample"])
        self.assertEqual(summary["last_decodable_cut"]["sample_index"], 0)
        self.assertEqual(summary["last_decodable_cut"]["record_count"], 1)
        self.assertFalse(summary["last_decodable_cut"]["is_current_sample"])
        self.assertFalse(summary["last_decodable_cut"]["freshness_proven"])

    def test_worker_sampler_reads_capture_ledger_from_same_ioreg_sample(self):
        from hcmd_rx_trace_test104 import sample_once
        raw = {
            "read_status": "trace_not_published", "blob": None,
            "markers": {}, "key_response": {},
            "publish_revision_begin": 0, "publish_revision_end": 0,
            "rx149_capture_attempts_raw": make_wire(),
        }
        sample = sample_once(reader=lambda: raw)
        self.assertEqual(sample["sample_status"], "trace_not_published")
        self.assertEqual(sample["rx149_capture_attempts"]["record_count"], 1)
        self.assertNotIn("rx149_capture_attempts_raw", sample)

    def test_worker_sampler_keeps_schema4_retry_fields_unavailable(self):
        from hcmd_rx_trace_test104 import sample_once, summarize_tx_rsp_retry_samples
        values = {
            "Schema": 4, "SnapshotVersionBegin": 8, "SnapshotVersionEnd": 8,
            "SnapshotAvailable": 1, "SnapshotComplete": 1, "DroppedCount": 0,
            "Event0Present": 1, "Event0Kind": 0,
            "Event0PresenceFlags": 1 << 31, "Event0Serial": 44,
        }
        raw = {
            "read_status": "trace_not_published", "blob": None,
            "markers": {}, "key_response": {},
            "publish_revision_begin": 0, "publish_revision_end": 0,
            "rx149_capture_attempts_raw": None,
            "tx_rsp_retry_scalars": values,
        }
        sample = sample_once(reader=lambda: raw)
        self.assertEqual(sample["tx_rsp_retry"]["status"], "decoded")
        stats = sample["tx_rsp_retry"]["decoded"]["tx_rsp_retry_stats"]
        self.assertEqual(stats["status"], "unavailable_in_schema_4")
        self.assertIsNone(stats["bt_kill_count"])
        summary = summarize_tx_rsp_retry_samples([sample])
        self.assertEqual(summary["unique_retained_event_serial_count"], 1)
        self.assertFalse(summary["mac_ack_proven"])


if __name__ == "__main__":
    unittest.main()
