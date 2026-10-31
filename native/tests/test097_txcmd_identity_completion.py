#!/usr/bin/env python3
"""Schema 1 compatibility and Test097 schema 2 completion decoding tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "developer-tools/test097/txcmd_identity_completion.py"
spec = importlib.util.spec_from_file_location("txcmd_identity_completion", MODULE_PATH)
decoder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(decoder)
sys.modules["txcmd_identity_completion"] = decoder
capture_spec = importlib.util.spec_from_file_location(
    "capture_native_sta_completion",
    ROOT / "developer-tools/test097/capture_native_sta_completion.py")
capture_module = importlib.util.module_from_spec(capture_spec)
assert capture_spec.loader is not None
capture_spec.loader.exec_module(capture_module)


def fixture(schema: int = 2) -> dict:
    values = {
        "Schema": schema,
        "SnapshotVersionBegin": 4,
        "SnapshotVersionEnd": 4,
        "SnapshotAvailable": 1,
        "SnapshotComplete": 1,
        "DroppedCount": 0,
        "NextSerial": 9,
        "FirmwareResponseIdentityProven": 0,
        "PeerReceiptProven": 0,
        "Event0Present": 1,
        "Event0Kind": 0,
        "Event0Stage": 1,
        "Event0TerminalReason": 8,
        "Event0PresenceFlags": decoder.HAS_OBSERVER_SERIAL,
        "Event0OutputEpoch": 2,
        "Event0ResponseFrameControl": 0x4108,
        "Event0ResponseSequenceControl": 0x0580,
        "Event0FirmwareQid": 1,
        "Event0QueueIndex": 89,
        "Event0RingCount": 1024,
        "Event0Queued": 8,
        "Event0Tail": 81,
        "Event0Ssn": 89,
        "Event0RaTid": 0,
        "Event0Status": 1,
    }
    if schema in (2, 3):
        values["Event0PresenceFlags"] |= (
            decoder.HAS_RESPONSE_FC | decoder.HAS_RESPONSE_SEQ |
            decoder.HAS_TXCMD_SCAN | decoder.HAS_TXCMD_UNIQUE)
        values.update({
            "Event0TxCommandScanStatus": 1,
            "Event0TxCommandExpectedCount": 8,
            "Event0TxCommandScannedCount": 8,
            "Event0TxCommandCandidateCount": 1,
            "Event0TxCommandCandidateIndex": 88,
            "Event0TxCommandApiGeneration": 2,
            "Event0TxCommandVersion": 7,
            "Event0TxCommandFlags": 5,
            "Event0TxCommandOffloadAssist": 0x0c00,
        })
    return values


class CompletionDecodeTest(unittest.TestCase):
    def test_legacy_schema_one_remains_readable_without_identity_claim(self):
        decoded = decoder.decode_scalars(fixture(schema=1))
        self.assertEqual(decoded["schema"], 1)
        self.assertEqual(decoded["txcmd_identity"]["status"],
                         "unavailable_in_schema_1")

    def test_schema_two_unique_candidate_is_host_only(self):
        decoded = decoder.decode_scalars(fixture())
        identity = decoded["txcmd_identity"]
        self.assertEqual(identity["status"], "unique_host_command_candidate")
        self.assertEqual(identity["descriptor_index"], 88)
        self.assertEqual(identity["command_flags"], 5)
        self.assertFalse(decoded["firmware_response_identity_proven"])
        self.assertFalse(decoded["peer_receipt_proven"])

    def test_schema_two_incomplete_and_ambiguous_stay_unattributed(self):
        incomplete = fixture()
        incomplete["Event0PresenceFlags"] &= ~decoder.HAS_TXCMD_UNIQUE
        incomplete["Event0TxCommandScanStatus"] = 2
        incomplete["Event0TxCommandScannedCount"] = 7
        incomplete["Event0TxCommandCandidateCount"] = 1
        for key in ("Event0TxCommandCandidateIndex",
                    "Event0TxCommandApiGeneration", "Event0TxCommandVersion",
                    "Event0TxCommandFlags", "Event0TxCommandOffloadAssist"):
            incomplete.pop(key)
        self.assertEqual(decoder.decode_scalars(incomplete)["txcmd_identity"]["status"],
                         "incomplete_scan")

        ambiguous = fixture()
        ambiguous["Event0PresenceFlags"] &= ~decoder.HAS_TXCMD_UNIQUE
        ambiguous["Event0TxCommandCandidateCount"] = 2
        for key in ("Event0TxCommandCandidateIndex",
                    "Event0TxCommandApiGeneration", "Event0TxCommandVersion",
                    "Event0TxCommandFlags", "Event0TxCommandOffloadAssist"):
            ambiguous.pop(key)
        self.assertEqual(decoder.decode_scalars(ambiguous)["txcmd_identity"]["status"],
                         "complete_ambiguous")

    def test_schema_three_single_raw_header_is_not_exact_response_identity(self):
        values = fixture(schema=3)
        values["Event0PresenceFlags"] &= ~decoder.HAS_TXCMD_UNIQUE
        values["Event0TxCommandCandidateCount"] = 0
        values["Event0TxCommandExpectedCount"] = 1
        values["Event0TxCommandScannedCount"] = 1
        values["Event0QueueIndex"] = 89
        values.update({
            "Event0TxCommandCandidateIndex": 88,
            "Event0TxCommandApiGeneration": 2,
            "Event0TxCommandVersion": 7,
            "Event0TxCommandFlags": 5,
            "Event0TxCommandOffloadAssist": 0x0c00,
            "Event0SingleSlotTxCommandHeader": (0x4908 << 16) | 0x08A0,
        })
        values["Event0PresenceFlags"] |= decoder.HAS_SINGLE_SLOT_TXCMD_HEADER
        decoded = decoder.decode_scalars(values)
        identity = decoded["txcmd_identity"]
        self.assertEqual(identity["status"],
                         "single_slot_raw_header_no_exact_response_match")
        self.assertEqual(identity["single_slot_host_command"]["frame_control"],
                         0x4908)
        self.assertEqual(identity["single_slot_host_command"]["sequence_control"],
                         0x08A0)
        self.assertFalse(decoded["firmware_response_identity_proven"])
        self.assertFalse(decoded["peer_receipt_proven"])

    def test_schema_three_rejects_raw_header_without_single_complete_scan(self):
        values = fixture(schema=3)
        values["Event0PresenceFlags"] |= decoder.HAS_SINGLE_SLOT_TXCMD_HEADER
        values["Event0TxCommandExpectedCount"] = 2
        values["Event0TxCommandScannedCount"] = 2
        values["Event0TxCommandCandidateIndex"] = 88
        values["Event0TxCommandApiGeneration"] = 2
        values["Event0TxCommandVersion"] = 7
        values["Event0TxCommandFlags"] = 5
        values["Event0TxCommandOffloadAssist"] = 0x0c00
        values["Event0SingleSlotTxCommandHeader"] = (0x4108 << 16) | 0x0580
        with self.assertRaises(ValueError):
            decoder.decode_scalars(values)

        old_schema = fixture(schema=2)
        old_schema["Event0PresenceFlags"] |= decoder.HAS_SINGLE_SLOT_TXCMD_HEADER
        with self.assertRaises(ValueError):
            decoder.decode_scalars(old_schema)

    def test_schema_three_rejects_in_ring_but_wrong_single_slot_index(self):
        values = fixture(schema=3)
        values["Event0PresenceFlags"] &= ~decoder.HAS_TXCMD_UNIQUE
        values["Event0TxCommandCandidateCount"] = 0
        values["Event0TxCommandExpectedCount"] = 1
        values["Event0TxCommandScannedCount"] = 1
        values["Event0QueueIndex"] = 89
        values["Event0TxCommandCandidateIndex"] = 87  # In range, wrong slot.
        values["Event0TxCommandApiGeneration"] = 2
        values["Event0TxCommandVersion"] = 7
        values["Event0TxCommandFlags"] = 5
        values["Event0TxCommandOffloadAssist"] = 0x0c00
        values["Event0SingleSlotTxCommandHeader"] = (0x4908 << 16) | 0x08A0
        values["Event0PresenceFlags"] |= decoder.HAS_SINGLE_SLOT_TXCMD_HEADER
        with self.assertRaises(ValueError):
            decoder.decode_scalars(values)

    def test_torn_or_inconsistent_snapshots_are_rejected(self):
        values = fixture()
        values["SnapshotVersionEnd"] = 6
        with self.assertRaises(ValueError):
            decoder.decode_scalars(values)
        values = fixture()
        values["Event0TxCommandScanStatus"] = 2
        with self.assertRaises(ValueError):
            decoder.decode_scalars(values)  # unique bit cannot survive an incomplete scan

    def test_collection_keeps_only_numeric_completion_properties(self):
        source = {"NativeStaCompletionSchema": 2,
                  "NativeStaCompletionPeerReceiptProven": 0,
                  "NativeStaCompletionPrivateName": "should not copy",
                  "DeviceAddress": "not included"}
        self.assertEqual(decoder.completion_scalars(source), {
            "Schema": 2, "PeerReceiptProven": 0,
        })

    def test_live_collector_verifies_build_and_saves_numeric_schema_fields(self):
        service = {"NativeTestBuild": "25G332-Test097",
                   **{f"NativeStaCompletion{key}": value
                      for key, value in fixture().items()},
                   "DeviceAddress": "never copied",
                   "NativeStaCompletionPrivateName": "never copied"}
        with mock.patch.object(capture_module.subprocess, "check_output",
                               return_value=plistlib.dumps([service])):
            row = capture_module.sample_ioreg("25G332-Test097")
        self.assertEqual(row["build"], "25G332-Test097")
        self.assertEqual(row["properties"], fixture())
        self.assertEqual(row["decode_status"], "snapshot_valid")
        self.assertEqual(row["decoded"]["txcmd_identity"]["status"],
                         "unique_host_command_candidate")
        self.assertEqual(row["decoded"]["txcmd_identity"]["descriptor_index"],
                         88)
        self.assertNotIn("DeviceAddress", str(row))
        self.assertNotIn("PrivateName", str(row))


if __name__ == "__main__":
    unittest.main()
