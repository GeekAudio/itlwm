#!/usr/bin/env python3
"""Compatibility checks for NativePowerTrace's JSON decoder."""

import importlib.util
import plistlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECODER_PATH = ROOT / "developer-tools/decode_native_power_trace.py"
SPEC = importlib.util.spec_from_file_location("native_power_trace_decoder", DECODER_PATH)
DECODER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DECODER)


HEADER = struct.Struct("<IIII")
ENTRY = struct.Struct("<QQIIIIIIIIiI")


def entry(sequence, operation, phase, detail=0, result=0, auxiliary=0):
    return ENTRY.pack(
        sequence * 1000, 7, sequence, sequence, operation, phase,
        12, 3, 0x41, detail, result, auxiliary,
    )


def snapshot(rows):
    capacity = 32
    return HEADER.pack(1, capacity, len(rows), len(rows)) + b"".join(rows) + bytes(
        (capacity - len(rows)) * ENTRY.size
    )


class NativePowerTraceDecoderTests(unittest.TestCase):
    def test_decodes_legacy_and_system_power_entries_from_raw_and_plist(self):
        raw = snapshot([
            entry(1, 1, 19),  # Existing pre-PM operation/phase.
            entry(2, 7, 22, detail=9, result=-5, auxiliary=8),
        ])
        for payload in (raw, plistlib.dumps({"NativePowerTrace": raw})):
            with self.subTest(input_type=type(payload).__name__):
                decoded = DECODER.decode(payload)
                self.assertEqual(decoded["status"], "decoded")
                self.assertEqual(decoded["count"], 2)
                self.assertEqual(decoded["entries"][0]["operation"]["name"], "power_set")
                wake = decoded["entries"][1]
                self.assertEqual(wake["operation"]["name"], "system_power")
                self.assertEqual(wake["phase"]["name"], "wake_restore_end")
                self.assertEqual(wake["detail"]["name"], "wake_restore_attempt")
                self.assertEqual(wake["result"]["iorReturn"], -5)
                self.assertEqual(wake["auxiliary"], 8)

    def test_unknown_future_enums_are_preserved_without_failure_classification(self):
        raw = snapshot([entry(1, 99, 98, detail=97, result=-5, auxiliary=44)])
        decoded = DECODER.decode(raw)
        item = decoded["entries"][0]
        self.assertEqual(decoded["status"], "decoded")
        self.assertEqual(item["operation"], {"value": 99, "name": "unknown"})
        self.assertEqual(item["phase"], {"value": 98, "name": "unknown"})
        self.assertEqual(item["detail"], {"value": 97, "name": "unknown"})
        self.assertEqual(item["result"]["iorReturn"], -5)

    def test_rejects_truncated_or_wrong_schema_snapshot(self):
        with self.assertRaises(DECODER.DecodeError):
            DECODER.decode(b"short")
        bad_schema = HEADER.pack(2, 32, 0, 0) + bytes(32 * ENTRY.size)
        with self.assertRaisesRegex(DECODER.DecodeError, "unsupported schema"):
            DECODER.decode(bad_schema)


if __name__ == "__main__":
    unittest.main()
