#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "roc_rx_correlation_decode", HERE / "roc_rx_correlation_decode.py")
decoder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(decoder)


IDENTITY = {
    "captureSerial": 1,
    "driverGeneration": 11,
    "contextGeneration": 6,
    "powerGeneration": 11,
    "stationGeneration": 23,
    "rocGeneration": 6,
    "sessionToken": 99,
    "armUs": 1000,
    "startUs": 2000,
    "deadlineUs": 97000,
}


def fixture(*, state=decoder.STATE_CLOSED, reason=2, retained=1,
            full_slots=1, overflow=0, skips=0, invalid=0, unfinished=0,
            coverage=None, copy_status=1, identity=None, slots=None,
            notification_overflow=False, mpdu=True):
    identity = dict(IDENTITY if identity is None else identity)
    if coverage is None:
        coverage = int(state == decoder.STATE_CLOSED and reason == 2 and
                       not overflow and not skips and not invalid and
                       not unfinished and retained == full_slots)
    start = identity["startUs"] if reason != 1 else 0
    deadline = identity["deadlineUs"] if reason != 1 else 0
    closed = 4000 if state == decoder.STATE_CLOSED else 0
    blob = bytearray(decoder.WIRE_BYTES)
    decoder.HEADER.pack_into(
        blob, 0, decoder.MAGIC, decoder.SCHEMA_VERSION,
        decoder.HEADER_BYTES, decoder.RECORD_BYTES, decoder.CAPACITY,
        state, reason, identity["captureSerial"], identity["driverGeneration"],
        identity["contextGeneration"], identity["powerGeneration"],
        identity["stationGeneration"], identity["rocGeneration"],
        identity["sessionToken"], identity["armUs"], start, deadline, closed,
        full_slots, retained, overflow, skips, invalid, unfinished, coverage,
        retained,
    )
    for index in range(retained):
        offset = decoder.HEADER_BYTES + index * decoder.RECORD_BYTES
        slot = slots[index] if slots is not None else index
        completion_ok = copy_status == 1
        record_flags = decoder.RECORD_FINALIZED
        if completion_ok:
            record_flags |= decoder.RECORD_COMPLETION_VALID
        if notification_overflow:
            record_flags |= decoder.RECORD_NOTIFICATION_OVERFLOW
        if mpdu:
            record_flags |= decoder.RECORD_MPDU_PRESENT
        status_bytes = bytes(range(8)) if completion_ok else bytes(8)
        decoder.RECORD_HEADER.pack_into(
            blob, offset, index + 1, 2500 + index, 44,
            identity["captureSerial"], identity["driverGeneration"],
            0, slot, slot, record_flags, copy_status, status_bytes,
            1, int(notification_overflow), 0x04, 0,
        )
        decoder.NOTIFICATION.pack_into(
            blob, offset + 56, 137, 234, 5, 0, 0x1001, 0, 96, 106, 0)
        mpdu_flags = decoder.MPDU_CHANNEL_PRESENT | decoder.MPDU_RAW_MAC_PHY_PRESENT
        decoder.MPDU.pack_into(
            blob, offset + 120,
            mpdu_flags if mpdu else 0, 149 if mpdu else 0,
            0x11 if mpdu else 0, 2 if mpdu else 0, 0x80 if mpdu else 0,
            0x1234 if mpdu else 0, 287 if mpdu else 0,
            64 if mpdu else 0, 0 if mpdu else 0,
            137 if mpdu else 0, 234 if mpdu else 0,
            0x101B if mpdu else 0, 3000 + index if mpdu else 0,
        )
        struct.pack_into("<I", blob, offset + 152, 1000 + index)
    return bytes(blob)


class RocCorrelationDecodeTests(unittest.TestCase):
    def test_decodes_same_copy_to_notification_and_mpdu(self):
        result = decoder.decode(fixture(), expected_identity=IDENTITY,
                                 require_closed=True)
        self.assertTrue(result["closed"])
        self.assertTrue(result["coverageComplete"])
        self.assertEqual(result["identityMatch"], {"matched": True,
                                                     "differences": {}})
        record = result["records"][0]
        self.assertEqual(record["completionBytes"], "0001020304050607")
        self.assertEqual(record["slot"], 0)
        self.assertEqual(record["notifications"][0]["index"], 234)
        self.assertEqual(record["completionSequence"], 1000)
        self.assertEqual(record["mpdu"]["channel"], 149)
        self.assertEqual(record["mpdu"]["rawMacPhy"], 0x11)
        self.assertFalse(result["evidenceLimits"]["dmaOwnershipProven"])

    def test_slot_188_survives_late_station_slots(self):
        slots = [188] + [((188 + i) % 512) for i in range(1, 64)]
        result = decoder.decode(fixture(retained=64, full_slots=70,
                                        overflow=6, coverage=0, slots=slots))
        self.assertEqual(result["records"][0]["slot"], 188)
        self.assertEqual(result["records"][0]["mpdu"]["channel"], 149)
        self.assertEqual(result["records"][-1]["slot"], (188 + 63) % 512)
        self.assertEqual(result["overflow"], 6)
        self.assertFalse(result["coverageComplete"])

    def test_closed_zero_slot_end_is_complete_but_no_start_is_unknown(self):
        ended = decoder.decode(fixture(retained=0, full_slots=0, coverage=1))
        self.assertTrue(ended["coverageComplete"])
        self.assertEqual(ended["records"], [])
        limits = ended["evidenceLimits"]
        self.assertTrue(limits["coverageCompleteEligibleSlotInternalOnly"])
        self.assertFalse(limits["fullRocMpduCompletenessProven"])
        self.assertFalse(limits["zeroEligibleSlotsProvesNoRocReceive"])
        self.assertFalse(limits["zeroMpduRecordsProvesNoReceive"])
        self.assertTrue(limits["noMpduDoesNotProvePhyOrFilterFailure"])
        self.assertTrue(limits["rocStartAndFollowingMpduMayShareOneCopy"])
        self.assertTrue(limits["armedCopyMayHaveNoSlotToken"])
        self.assertEqual(limits["maximumMpduRecordsPerSlot"], 1)
        self.assertFalse(limits["secondMpduInOneSlotFullyRepresented"])
        self.assertEqual(limits["maximumNotificationsPerSlot"], 4)
        self.assertFalse(limits["notificationEventsPastCapacityFullyRepresented"])

        no_mpdu = decoder.decode(fixture(mpdu=False))
        self.assertTrue(no_mpdu["coverageComplete"])
        self.assertNotIn("mpdu", no_mpdu["records"][0])
        self.assertFalse(no_mpdu["evidenceLimits"]["fullRocMpduCompletenessProven"])
        self.assertTrue(no_mpdu["evidenceLimits"]["noMpduDoesNotProvePhyOrFilterFailure"])

        no_start = decoder.decode(fixture(reason=1, retained=0, full_slots=0,
                                          coverage=0))
        self.assertTrue(no_start["closed"])
        self.assertFalse(no_start["coverageComplete"])

    def test_overflow_copy_skip_invalid_and_unfinished_fail_closed(self):
        for kwargs in (
            {"overflow": 1, "full_slots": 2, "retained": 1, "coverage": 1},
            {"skips": 1, "full_slots": 1, "retained": 1, "coverage": 1,
             "copy_status": 8},
            {"invalid": 1, "full_slots": 1, "retained": 1, "coverage": 1},
            {"unfinished": 1, "full_slots": 1, "retained": 1, "coverage": 1},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(decoder.DecodeError):
                    decoder.decode(fixture(**kwargs))
        skipped = decoder.decode(fixture(skips=1, copy_status=8,
                                         coverage=0))
        self.assertFalse(skipped["records"][0]["completionBytesValid"])
        self.assertEqual(skipped["records"][0]["completionBytes"], "00" * 8)

    def test_rejects_wrong_size_schema_magic_and_identity(self):
        with self.assertRaisesRegex(decoder.DecodeError, "exactly"):
            decoder.decode(fixture()[:-1])
        unknown_schema = bytearray(fixture())
        struct.pack_into("<I", unknown_schema, 8, 99)
        with self.assertRaisesRegex(decoder.DecodeError, "schema"):
            decoder.decode(bytes(unknown_schema))
        bad_magic = bytearray(fixture())
        bad_magic[0] ^= 0xff
        with self.assertRaisesRegex(decoder.DecodeError, "magic"):
            decoder.decode(bytes(bad_magic))
        changed = dict(IDENTITY, rocGeneration=7)
        decoded = decoder.decode(fixture(), expected_identity=changed)
        self.assertFalse(decoded["identityMatch"]["matched"])

    def test_arm_us_is_required_and_participates_in_identity_match(self):
        expected_without_arm = {
            key: value for key, value in IDENTITY.items() if key != "armUs"
        }
        missing = decoder.decode(fixture(),
                                 expected_identity=expected_without_arm)
        self.assertEqual(missing["identityMatch"], {
            "matched": False,
            "missing": ["armUs"],
        })

        expected_wrong_arm = dict(IDENTITY, armUs=IDENTITY["armUs"] + 1)
        changed = decoder.decode(fixture(), expected_identity=expected_wrong_arm)
        self.assertFalse(changed["identityMatch"]["matched"])
        self.assertEqual(changed["identityMatch"]["differences"], {
            "armUs": {
                "expected": IDENTITY["armUs"] + 1,
                "observed": IDENTITY["armUs"],
            }
        })

    def test_rejects_open_snapshot_when_closed_is_required(self):
        open_blob = fixture(state=decoder.STATE_ACTIVE, reason=0, coverage=0)
        self.assertFalse(decoder.decode(open_blob)["closed"])
        with self.assertRaisesRegex(decoder.DecodeError, "still active"):
            decoder.decode(open_blob, require_closed=True)


if __name__ == "__main__":
    unittest.main()
