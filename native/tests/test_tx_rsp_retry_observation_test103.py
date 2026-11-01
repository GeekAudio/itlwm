#!/usr/bin/env python3
"""Offline contract tests for Test103's versioned TX_RSP counters."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "developer-tools/test103/tx_rsp_retry_observation_test103.py"
spec = importlib.util.spec_from_file_location("tx_rsp_retry_observation_test103", MODULE_PATH)
decoder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(decoder)


def fixture(schema: int = 5) -> dict:
    values = {
        "Schema": schema,
        "SnapshotVersionBegin": 4,
        "SnapshotVersionEnd": 4,
        "SnapshotAvailable": 1,
        "SnapshotComplete": 1,
        "DroppedCount": 0,
        "NextSerial": 3,
        "RelevantSerial": 2,
        "PublicationSequence": 4,
        "PublicationSource": 1,
        "PublicationGeneration": 12,
        "OwnerGeneration": 12,
        "Event0Present": 1,
        "Event0Kind": 0,
        "Event0PresenceFlags": (
            decoder.HAS_OBSERVER_SERIAL | decoder.HAS_FRAME_COUNT |
            decoder.HAS_PAYLOAD_LENGTH),
        "Event0FrameCount": 1,
        "Event0PayloadLength": 48,
        "Event0TxRspRetryStatsVersion": 1,
        "Event0TxRspBtKillCount": 0,
        "Event0TxRspFailureRts": 2,
        "Event0TxRspFailureFrame": 3,
    }
    if schema == 4:
        for key in decoder.RETRY_FIELD_NAMES:
            values.pop("Event0" + key)
    return values


class TxRspRetryDecodeTests(unittest.TestCase):
    def test_schema_four_is_readable_but_has_no_retry_claim(self):
        values = fixture(schema=4)
        # Even if similarly named values appear, the old schema has no contract.
        values["Event0TxRspRetryStatsVersion"] = 1
        values["Event0TxRspFailureFrame"] = 99
        decoded = decoder.decode_scalars(values)
        stats = decoded["tx_rsp_retry_stats"]
        self.assertEqual(decoded["schema"], 4)
        self.assertEqual(stats["status"], "unavailable_in_schema_4")
        self.assertIsNone(stats["failure_frame"])

    def test_schema_five_decodes_same_cut_present_counters(self):
        stats = decoder.decode_scalars(fixture())["tx_rsp_retry_stats"]
        self.assertEqual(stats["status"], "host_layout_v1_present")
        self.assertEqual(stats["layout_version"], 1)
        self.assertEqual(stats["frame_count"], 1)
        self.assertEqual(stats["bt_kill_count"], 0)
        self.assertEqual(stats["failure_rts"], 2)
        self.assertEqual(stats["failure_frame"], 3)
        self.assertIn("not proof", stats["evidence_scope"])
        self.assertIn("not establish", stats["note"])

    def test_zero_is_valid_but_unavailable_is_not_zero_evidence(self):
        values = fixture()
        values.update({
            "Event0TxRspRetryStatsVersion": 1,
            "Event0TxRspBtKillCount": 0,
            "Event0TxRspFailureRts": 0,
            "Event0TxRspFailureFrame": 0,
        })
        decoded = decoder.decode_scalars(values)
        self.assertEqual(decoded["tx_rsp_retry_stats"]["status"],
                         "host_layout_v1_present")
        values["Event0TxRspRetryStatsVersion"] = 0
        unavailable = decoder.decode_scalars(values)["tx_rsp_retry_stats"]
        self.assertEqual(unavailable["status"], "unavailable_in_schema_5")
        self.assertIsNone(unavailable["failure_frame"])

    def test_schema_five_version_zero_is_explicitly_unavailable(self):
        values = fixture()
        values.update({
            "Event0TxRspRetryStatsVersion": 0,
            "Event0TxRspBtKillCount": 0,
            "Event0TxRspFailureRts": 0,
            "Event0TxRspFailureFrame": 0,
        })
        self.assertEqual(decoder.decode_scalars(values)["tx_rsp_retry_stats"]["status"],
                         "unavailable_in_schema_5")

    def test_no_event_does_not_create_zero_counter_evidence(self):
        values = fixture()
        values.update({
            "Event0Present": 0,
            "PublicationSource": 2,
            "Event0TxRspRetryStatsVersion": 0,
            "Event0TxRspBtKillCount": 0,
            "Event0TxRspFailureRts": 0,
            "Event0TxRspFailureFrame": 0,
        })
        self.assertEqual(decoder.decode_scalars(values)["tx_rsp_retry_stats"]["status"],
                         "unavailable_no_retained_txrsp_row")
        values["PublicationSource"] = 1
        with self.assertRaises(decoder.CompletionDecodeError):
            decoder.decode_scalars(values)

    def test_present_row_must_be_a_tx_rsp_with_observer_serial(self):
        values = fixture(schema=4)
        values["Event0Kind"] = 1
        with self.assertRaises(decoder.CompletionDecodeError):
            decoder.decode_scalars(values)
        values = fixture(schema=4)
        values["Event0PresenceFlags"] &= ~decoder.HAS_OBSERVER_SERIAL
        with self.assertRaises(decoder.CompletionDecodeError):
            decoder.decode_scalars(values)

    def test_schema_five_requires_complete_stable_snapshot(self):
        values = fixture()
        values.pop("Event0TxRspFailureFrame")
        with self.assertRaises(decoder.CompletionDecodeError):
            decoder.decode_scalars(values)
        values = fixture()
        values["SnapshotVersionEnd"] = 6
        with self.assertRaises(decoder.CompletionDecodeError):
            decoder.decode_scalars(values)
        values = fixture()
        values["DroppedCount"] = 1
        with self.assertRaises(decoder.CompletionDecodeError):
            decoder.decode_scalars(values)

    def test_bad_variant_kind_presence_or_width_fails_closed(self):
        variants = []
        values = fixture()
        values["Event0TxRspRetryStatsVersion"] = 2
        variants.append(values)
        values = fixture()
        values["Event0Kind"] = 1  # BA cannot be attributed these TX_RSP fields.
        variants.append(values)
        values = fixture()
        values["Event0FrameCount"] = 2
        variants.append(values)
        values = fixture()
        values["Event0PayloadLength"] = 47
        variants.append(values)
        values = fixture()
        values["Event0PresenceFlags"] &= ~decoder.HAS_PAYLOAD_LENGTH
        variants.append(values)
        values = fixture()
        values["Event0TxRspFailureFrame"] = 256
        variants.append(values)
        for values in variants:
            with self.subTest(values=values):
                with self.assertRaises(decoder.CompletionDecodeError):
                    decoder.decode_scalars(values)

    def test_property_extraction_omits_strings_and_booleans(self):
        values = decoder.completion_scalars({
            "NativeStaCompletionSchema": 5,
            "NativeStaCompletionEvent0TxRspFailureFrame": 3,
            "NativeStaCompletionDebug": "private",
            "NativeStaCompletionFlag": True,
            "OtherProperty": 99,
        })
        self.assertEqual(values, {
            "Schema": 5,
            "Event0TxRspFailureFrame": 3,
        })


if __name__ == "__main__":
    unittest.main()
