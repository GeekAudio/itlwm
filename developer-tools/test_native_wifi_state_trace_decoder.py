#!/usr/bin/env python3
"""Contract tests for the fixed-size NativeWifiStateTrace decoder."""

import importlib.util
import plistlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECODER_PATH = ROOT / "developer-tools/decode_native_wifi_state_trace.py"
SPEC = importlib.util.spec_from_file_location("native_wifi_state_trace_decoder", DECODER_PATH)
DECODER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DECODER)

HEADER = struct.Struct("<10I")
ENTRY = struct.Struct("<QQQQIIIIIiIIII")


def entry(sequence=1, kind=0, result=0, flags=1 << 11, value=1, auxiliary=4,
          restart_id=0, fault_serial=0, reserved=0):
    return ENTRY.pack(
        100, 20, restart_id, 0, sequence, kind, 7, 3, fault_serial,
        result, flags, value, auxiliary, reserved,
    )


def snapshot(rows=(), *, newest=None, overwritten=0, reserved=0, capacity=DECODER.CAPACITY,
             schema=DECODER.SCHEMA_VERSION, call_counts=(0, 0, 0, 0)):
    rows = list(rows)
    newest = newest if newest is not None else (rows[-1][0] if rows else 0)
    blob = HEADER.pack(schema, capacity, len(rows), newest, overwritten, reserved, *call_counts)
    encoded = b"".join(row[1] for row in rows)
    encoded += bytes(max(0, capacity - len(rows)) * ENTRY.size)
    return blob + encoded


class NativeWifiStateTraceDecoderTests(unittest.TestCase):
    def test_decodes_power_and_plist(self):
        raw = snapshot([(1, entry(sequence=1, kind=0, value=1))], call_counts=(1, 0, 0, 0))
        for payload in (raw, plistlib.dumps({"NativeWifiStateTrace": raw})):
            decoded = DECODER.decode(payload)
            self.assertEqual(decoded["status"], "decoded")
            self.assertFalse(decoded["historyTruncated"])
            self.assertEqual(decoded["observations"]["get_power"]["state"], "observed")
            self.assertEqual(decoded["entries"][0]["returnedPowerState"], 1)

    def test_empty_ledger_means_unknown_not_success(self):
        decoded = DECODER.decode(snapshot())
        self.assertEqual(decoded["count"], 0)
        for kind in DECODER.KINDS.values():
            self.assertEqual(decoded["observations"][kind]["state"], "unknown_not_observed")

    def test_marks_ring_truncation_and_estimate(self):
        rows = [(seq, entry(sequence=seq, kind=3,
                            flags=(1 << 11) | (1 << 20), value=seq & 1,
                            auxiliary=216)) for seq in (5, 6, 7)]
        decoded = DECODER.decode(snapshot(rows, newest=7, overwritten=4,
                                          call_counts=(0, 0, 0, 9)))
        self.assertTrue(decoded["historyTruncated"])
        self.assertEqual(decoded["overwrittenEntries"], 4)
        self.assertEqual(decoded["entries"][-1]["eventCode"], 216)
        self.assertIsNone(decoded["entries"][-1]["acknowledged"])

    def test_decodes_redacted_ssid_source_and_bssid_compare(self):
        rows = [
            (1, entry(sequence=1, kind=1, value=6, flags=(1 << 11) | (1 << 13), auxiliary=2)),
            (2, entry(sequence=2, kind=2, value=6,
                      flags=(1 << 11) | (1 << 16) | (1 << 17), auxiliary=0)),
        ]
        decoded = DECODER.decode(snapshot(rows, newest=2, call_counts=(0, 1, 1, 0)))
        self.assertEqual(decoded["entries"][0]["ssidLength"], 6)
        self.assertEqual(decoded["entries"][0]["ssidSource"], "desired_ssid")
        self.assertTrue(decoded["entries"][1]["desiredBssidComparisonValid"])
        self.assertTrue(decoded["entries"][1]["bssidMatchesDesired"])
        self.assertNotIn("ssid", decoded["entries"][0])
        self.assertNotIn("bssid", decoded["entries"][1])

    def test_rejects_bad_schema_capacity_length_kind_flags_and_reserved(self):
        valid = snapshot([(1, entry())])
        bad_schema = snapshot(schema=2)
        bad_capacity = snapshot(capacity=8)
        bad_length = valid[:-1]
        bad_kind = snapshot([(1, entry(kind=99))])
        bad_flags = snapshot([(1, entry(flags=1 << 30))])
        bad_reserved = snapshot([(1, entry(reserved=1))])
        bad_header_reserved = snapshot(reserved=1)
        inconsistent_newest = snapshot([(1, entry(sequence=1))], newest=2)
        for raw in (b"short", bad_schema, bad_capacity, bad_length, bad_kind,
                    bad_flags, bad_reserved, bad_header_reserved, inconsistent_newest):
            with self.subTest(length=len(raw)):
                with self.assertRaises(DECODER.DecodeError):
                    DECODER.decode(raw)


if __name__ == "__main__":
    unittest.main()
