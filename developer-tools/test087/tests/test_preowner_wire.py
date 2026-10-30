#!/usr/bin/env python3
"""Cross-language fixture and strict malformed-input tests for Test087 wire v1."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_SOURCE = ROOT / "native/tests/test087_preowner_wire.cpp"
DECODER_PATH = Path(__file__).resolve().parents[1] / "preowner_decode.py"
SPEC = importlib.util.spec_from_file_location("preowner_decode", DECODER_PATH)
assert SPEC and SPEC.loader
preowner_decode = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preowner_decode)


def replace_word(blob: bytes, index: int, value: int) -> bytes:
    mutable = bytearray(blob)
    struct.pack_into("<Q", mutable, index * 8, value)
    return bytes(mutable)


def event_word_index(bank: int, slot: int, field: str) -> int:
    return (
        preowner_decode.HEADER_WORDS + preowner_decode.SNAPSHOT_WORDS +
        bank * preowner_decode.WITNESS_BANK_CAPACITY * preowner_decode.WITNESS_WORDS +
        slot * preowner_decode.WITNESS_WORDS + 1 +
        preowner_decode.EVENT_FIELD_INDEX[field]
    )


def read_fixture_archive(data: bytes) -> list[bytes]:
    if len(data) < 8:
        raise AssertionError("short fixture archive")
    record_count = struct.unpack_from("<Q", data, 0)[0]
    offset = 8
    records = []
    for _ in range(record_count):
        if offset + 8 > len(data):
            raise AssertionError("truncated fixture record length")
        word_count = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
        end = offset + word_count * 8
        if end > len(data):
            raise AssertionError("truncated fixture record")
        records.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise AssertionError("unexpected fixture archive trailing bytes")
    return records


class TestPreownerWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            raise RuntimeError("clang++ or g++ is required for Test087 wire fixture")
        cls.temp = tempfile.TemporaryDirectory(prefix="test087-preowner-wire-")
        cls.binary = Path(cls.temp.name) / "test087-preowner-wire"
        command = [
            compiler,
            "-std=c++17",
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-I",
            str(ROOT),
            str(FIXTURE_SOURCE),
            "-o",
            str(cls.binary),
        ]
        subprocess.run(command, check=True, cwd=ROOT)
        completed = subprocess.run(
            [str(cls.binary)], check=True, stdout=subprocess.PIPE, cwd=ROOT
        )
        cls.records = read_fixture_archive(completed.stdout)
        if len(cls.records) != 5:
            raise AssertionError("fixture should provide five snapshots")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_cpp_encoder_python_decoder_round_trip(self) -> None:
        mixed, closed_empty, active_empty, witness_overflow, counter_overflow = self.records
        decoded = preowner_decode.decode_blob(mixed)
        self.assertEqual(decoded["wire"], {
            "magic": "NRXOWN01",
            "version": 1,
            "wordCount": 711,
        })
        snap = decoded["snapshot"]
        self.assertEqual(snap["totalEvents"], 4)
        self.assertEqual(snap["kindCounts"]["MpduEntry"], 2)
        self.assertEqual(snap["rxClassCounts"]["Channel149"], 1)
        self.assertEqual(snap["awdlCandidateCount"], 1)
        self.assertEqual(snap["ownerQualifiedCount"], 1)
        self.assertEqual(snap["ownerFailedCount"], 1)
        self.assertEqual(snap["ownerReasonCounts"]["LeaseInactive"], 1)
        self.assertEqual(snap["witness149Count"], 1)
        self.assertEqual(snap["witnessNon149Count"], 1)

        witness = snap["channel149Witnesses"][0]["event"]
        self.assertEqual(witness["mpduLengthPresent"], True)
        self.assertEqual(witness["mpduLength"], 0)
        self.assertEqual(witness["rawMacPhyIndexPresent"], True)
        self.assertEqual(witness["rawMacPhyIndex"], 0)
        self.assertEqual(witness["gp2OnAirRisePresent"], True)
        self.assertEqual(witness["gp2OnAirRiseRaw"], 0)
        self.assertEqual(witness["tsfOnAirRisePresent"], True)
        self.assertEqual(witness["tsfOnAirRiseRaw"], 0)
        self.assertEqual(witness["frameControl"], 8)
        self.assertFalse(witness["notificationQidPresent"])
        self.assertIsNone(witness["notificationQid"])
        non149 = snap["non149Witnesses"][0]["event"]
        self.assertFalse(non149["mpduLengthPresent"])
        self.assertIsNone(non149["mpduLength"])

        summary = decoded["summary"]
        self.assertEqual(summary["all_transport"]["totalEvents"], 4)
        self.assertEqual(summary["channel149"]["witnessCount"], 1)
        self.assertEqual(summary["awdlCandidate"]["mpduEntryCount"], 1)
        self.assertEqual(summary["owner"]["qualified"], 1)
        self.assertFalse(decoded["evidenceScope"]["endToEndAirDropProven"])
        self.assertFalse(decoded["evidenceScope"]["provesSamePacketOnAir"])

        closed = preowner_decode.decode_blob(closed_empty)["snapshot"]
        self.assertEqual(closed["totalEvents"], 0)
        self.assertTrue(closed["closed"])
        active = preowner_decode.decode_blob(active_empty)["snapshot"]
        self.assertEqual(active["totalEvents"], 0)
        self.assertTrue(active["active"])

        witness_ov = preowner_decode.decode_blob(witness_overflow)["snapshot"]
        self.assertEqual(witness_ov["witness149Count"], 8)
        self.assertEqual(witness_ov["witness149Overflow"], 2)
        self.assertTrue(witness_ov["overflow"])
        counter_ov = preowner_decode.decode_blob(counter_overflow)["snapshot"]
        self.assertTrue(counter_ov["counterOverflow"])
        self.assertEqual(counter_ov["totalEvents"], 0xFFFFFFFF)

    def test_three_saved_reads_report_stable_complete_without_filling_missing(self) -> None:
        mixed, closed_empty, active_empty, _, _ = self.records
        complete = preowner_decode.compare_three_reads(
            [closed_empty, closed_empty, closed_empty]
        )
        self.assertEqual(complete["status"], "complete")
        self.assertTrue(complete["stable"])
        self.assertTrue(complete["complete"])

        active = preowner_decode.compare_three_reads(
            [active_empty, active_empty, active_empty]
        )
        self.assertEqual(active["status"], "active_incomplete")
        self.assertTrue(active["stable"])
        self.assertFalse(active["complete"])

        missing = preowner_decode.compare_three_reads([closed_empty, None, closed_empty])
        self.assertEqual(missing["status"], "missing")
        self.assertFalse(missing["stable"])
        self.assertFalse(missing["complete"])
        self.assertEqual(missing["missingReadIndexes"], [1])

        unstable = preowner_decode.compare_three_reads(
            [mixed, replace_word(mixed, 6, 2_000_040), mixed]
        )
        self.assertEqual(unstable["status"], "unstable")
        self.assertFalse(unstable["stable"])
        self.assertFalse(unstable["complete"])

        with self.assertRaises(preowner_decode.DecodeError):
            preowner_decode.compare_three_reads([b"", b"", b""])
        with self.assertRaises(ValueError):
            preowner_decode.compare_three_reads([closed_empty, closed_empty])

    def test_rejects_short_long_and_unaligned_records(self) -> None:
        mixed = self.records[0]
        for malformed in (b"", mixed[:7], mixed[:-1], mixed + b"\x00", mixed + b"\x00" * 8):
            with self.subTest(length=len(malformed)):
                with self.assertRaises(preowner_decode.DecodeError):
                    preowner_decode.decode_blob(malformed)

    def test_rejects_bad_magic_version_and_declared_size(self) -> None:
        mixed = self.records[0]
        for index, value in ((0, 0), (1, 2), (2, 1025), (2, 710)):
            with self.subTest(index=index, value=value):
                with self.assertRaises(preowner_decode.DecodeError):
                    preowner_decode.decode_blob(replace_word(mixed, index, value))

    def test_rejects_enum_boolean_absence_counter_and_time_corruption(self) -> None:
        mixed = self.records[0]
        snapshot_start = preowner_decode.HEADER_WORDS
        bad_kind = replace_word(
            mixed,
            event_word_index(0, 0, "kind"),
            len(preowner_decode.KIND_NAMES),
        )
        bad_boolean = replace_word(
            mixed,
            event_word_index(0, 0, "awdlCandidate"),
            2,
        )
        absent_value = replace_word(
            mixed,
            event_word_index(0, 1, "payloadLen"),
            1,
        )
        bad_total = replace_word(
            mixed,
            snapshot_start + preowner_decode.SNAPSHOT_FIELD_INDEX["totalEvents"],
            5,
        )
        bad_end = replace_word(
            mixed,
            snapshot_start + preowner_decode.SNAPSHOT_FIELD_INDEX["endUs"],
            6_000_001,
        )
        bad_u32 = replace_word(
            mixed,
            snapshot_start + preowner_decode.SNAPSHOT_FIELD_INDEX["totalEvents"],
            0x1_0000_0000,
        )
        closed_empty = self.records[1]
        early_deadline = replace_word(
            closed_empty,
            snapshot_start + preowner_decode.SNAPSHOT_FIELD_INDEX["closeReason"],
            1,
        )
        malformed_cases = (
            ("enum", bad_kind),
            ("boolean", bad_boolean),
            ("absent-value", absent_value),
            ("counter-relation", bad_total),
            ("time-bound", bad_end),
            ("u32-overflow", bad_u32),
            ("early-deadline-close", early_deadline),
        )
        for name, malformed in malformed_cases:
            with self.subTest(name=name):
                with self.assertRaises(preowner_decode.DecodeError):
                    preowner_decode.decode_blob(malformed)


if __name__ == "__main__":
    unittest.main()
