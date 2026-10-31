#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("rx_completion_decode.py")
SPEC = importlib.util.spec_from_file_location("rx_completion_decode", MODULE_PATH)
decoder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(decoder)


def fixture(sample_count=1, schema=1):
    blob = bytearray(decoder.WIRE_BYTES)
    decoder.HEADER.pack_into(
        blob, 0, schema, 1, 22, 20, 2, 4, 2, 9, 3, 31, 17,
        sample_count, 123456789,
    )
    for index in range(min(sample_count, decoder.SAMPLE_CAPACITY)):
        decoder.SAMPLE.pack_into(
            blob, decoder.HEADER_BYTES + index * decoder.SAMPLE_BYTES,
            index + 1, 9, 3, 31, 17, 0x9090, 0xA5,
            123456789 + index, 44 + index,
        )
    return bytes(blob)


class CompletionDecodeTests(unittest.TestCase):
    def test_decodes_one_sample_and_marks_limits(self):
        result = decoder.decode(fixture())
        self.assertEqual(result["sampleCount"], 1)
        self.assertEqual(result["lastAttemptUptimeUs"], 123456789)
        self.assertEqual(result["samples"][0], {
            "sequence": 1,
            "driverGeneration": 9,
            "observationSerial": 3,
            "head": 31,
            "slot": 17,
            "rawRbid": 0x9090,
            "rawFlags": 0xA5,
            "hostUptimeUs": 123456789,
            "allocationIncarnation": 44,
        })
        self.assertFalse(result["interpretationLimits"]["dmaOwnershipProven"])
        self.assertTrue(
            result["interpretationLimits"]["laterTrafficCanOverwriteEarlierTargetSamples"]
        )
        self.assertTrue(
            result["interpretationLimits"]["overwrittenCountDoesNotIdentifyDroppedFrameTypes"]
        )

    def test_zero_and_full_sample_capacity_boundaries(self):
        self.assertEqual(decoder.decode(fixture(0))["samples"], [])
        full = decoder.decode(fixture(decoder.SAMPLE_CAPACITY))
        self.assertEqual(full["sampleCount"], decoder.SAMPLE_CAPACITY)
        self.assertEqual(full["samples"][-1]["sequence"], 16)

    def test_rejects_truncated_and_wrong_sized_payloads(self):
        for blob in (b"", fixture()[:-1], fixture() + b"\0"):
            with self.subTest(length=len(blob)):
                with self.assertRaises(decoder.DecodeError):
                    decoder.decode(blob)

    def test_rejects_unknown_schema_and_over_capacity_count(self):
        with self.assertRaisesRegex(decoder.DecodeError, "schema"):
            decoder.decode(fixture(schema=2))
        with self.assertRaisesRegex(decoder.DecodeError, "exceeds capacity"):
            decoder.decode(fixture(sample_count=17))


if __name__ == "__main__":
    unittest.main()
