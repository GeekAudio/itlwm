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
            notification_overflow=False, mpdu=True, schema=decoder.SCHEMA_VERSION,
            rx_counts=None):
    identity = dict(IDENTITY if identity is None else identity)
    if coverage is None:
        coverage = int(state == decoder.STATE_CLOSED and reason == 2 and
                       not overflow and not skips and not invalid and
                       not unfinished and retained == full_slots)
    start = identity["startUs"] if reason != 1 else 0
    deadline = identity["deadlineUs"] if reason != 1 else 0
    closed = 4000 if state == decoder.STATE_CLOSED else 0
    header_bytes = (decoder.LEGACY_HEADER_BYTES if
                    schema == decoder.LEGACY_SCHEMA_VERSION else
                    decoder.HEADER_BYTES)
    wire_bytes = header_bytes + decoder.RECORD_BYTES * decoder.CAPACITY
    blob = bytearray(wire_bytes)
    base_header = (
        decoder.MAGIC, schema, header_bytes, decoder.RECORD_BYTES, decoder.CAPACITY,
        state, reason, identity["captureSerial"], identity["driverGeneration"],
        identity["contextGeneration"], identity["powerGeneration"],
        identity["stationGeneration"], identity["rocGeneration"],
        identity["sessionToken"], identity["armUs"], start, deadline, closed,
        full_slots, retained, overflow, skips, invalid, unfinished, coverage,
    )
    if schema == decoder.LEGACY_SCHEMA_VERSION:
        decoder.HEADER_V1.pack_into(blob, 0, *base_header, retained)
    else:
        counts = dict(rx_counts or {})
        flags = counts.get("flags", 3 if state == decoder.STATE_CLOSED and reason == 2
                           else 1 if state == decoder.STATE_ACTIVE else 0)
        stage = counts.get(
            "stage", 1 if flags == 3 else 0)
        summary = (
            flags, stage,
            counts.get("irq", 0), counts.get("legacy", 0),
            counts.get("msix", 0), counts.get("drain", 0),
            counts.get("ring", 0), counts.get("seen", 0),
            counts.get("validated", 0), counts.get("rejected", 0),
            counts.get("non_mpdu", 0), counts.get("mpdu_dispatch", 0),
            counts.get("first_slot", 0), counts.get("last_slot", 0),
            counts.get("first_head", 0), counts.get("last_head", 0),
        )
        decoder.HEADER_V2.pack_into(blob, 0, *base_header, retained, *summary)
    for index in range(retained):
        offset = header_bytes + index * decoder.RECORD_BYTES
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

    def test_v1_snapshot_remains_readable_without_inventing_rx_summary(self):
        result = decoder.decode(fixture(schema=decoder.LEGACY_SCHEMA_VERSION))
        self.assertEqual(result["schemaVersion"], 1)
        self.assertFalse(result["rxWindowSummaryAvailable"])
        self.assertEqual(result["rxWindowStageName"], "not_recorded_in_schema_v1")

    def test_v2_control_only_summary_does_not_claim_airdrop(self):
        result = decoder.decode(fixture(rx_counts={
            "flags": 3, "stage": 6, "irq": 1, "legacy": 1,
            "drain": 1, "ring": 1, "seen": 1, "validated": 1,
            "non_mpdu": 1, "first_slot": 312, "last_slot": 312,
            "first_head": 313, "last_head": 313,
        }))
        self.assertTrue(result["rxWindowSummaryAvailable"])
        self.assertEqual(
            result["rxWindowStageName"],
            "validated_non_mpdu_notifications_only",
        )
        self.assertFalse(result["evidenceLimits"]["hostRxStageIsRfReceipt"])
        self.assertTrue(
            result["evidenceLimits"][
                "endControlNotificationDoesNotProveFullWindowActivity"])

    def test_v2_rejects_summary_stage_inconsistent_with_counts(self):
        blob = fixture(rx_counts={
            "flags": 3, "stage": 2, "irq": 1, "legacy": 1,
            "drain": 1,
        })
        with self.assertRaisesRegex(decoder.DecodeError, "interrupt-without-drain"):
            decoder.decode(blob)

    def test_v2_unknown_means_no_successful_start_end_pair(self):
        no_start = decoder.decode(fixture(
            reason=1, rx_counts={"flags": 0, "stage": 0},
        ))
        self.assertEqual(no_start["rxWindowStageName"], "unknown")
        self.assertEqual(no_start["rxWindowFlags"], 0)

        incomplete = decoder.decode(fixture(
            reason=3, rx_counts={"flags": 1, "stage": 0},
        ))
        self.assertEqual(incomplete["rxWindowStageName"], "unknown")
        self.assertTrue(incomplete["rxWindowFlags"] & 1)
        self.assertFalse(incomplete["rxWindowFlags"] & 2)

    def test_v2_notification_seen_without_classification_is_separate(self):
        result = decoder.decode(fixture(rx_counts={
            "flags": 3, "stage": 9, "irq": 1, "legacy": 1,
            "drain": 1, "ring": 1, "seen": 1,
            "first_slot": 312, "last_slot": 312,
            "first_head": 313, "last_head": 313,
        }))
        self.assertEqual(
            result["rxWindowStageName"],
            "notification_seen_without_validation",
        )

    def test_v2_rxmpdu_notification_is_not_peer_receipt(self):
        result = decoder.decode(fixture(rx_counts={
            "flags": 3, "stage": 7, "irq": 1, "legacy": 1,
            "drain": 1, "ring": 1, "seen": 1, "validated": 1,
            "mpdu_dispatch": 1, "first_slot": 312, "last_slot": 312,
            "first_head": 313, "last_head": 313,
        }))
        self.assertEqual(result["rxWindowStageName"],
                         "rx_mpdu_notification_validated_seen")
        self.assertFalse(result["evidenceLimits"]
                         ["rxMpduNotificationValidatedIsAwdlOrDataProof"])
        self.assertFalse(result["evidenceLimits"]["peerOrSocketReceiptProven"])

    def test_v2_invalid_counter_stage_is_explicit_and_bounded(self):
        result = decoder.decode(fixture(rx_counts={
            "flags": 15, "stage": 8,
        }))
        self.assertEqual(result["rxWindowStageName"],
                         "invalid_counters_or_timeline")
        bad = fixture(rx_counts={"flags": 3, "stage": 8})
        with self.assertRaisesRegex(decoder.DecodeError,
                                    "lacks overflow/timeline flag"):
            decoder.decode(bad)

    def test_v2_boundary_partial_service_keeps_notification_facts(self):
        result = decoder.decode(fixture(rx_counts={
            "flags": 3 | 16,
            "stage": 7,
            "seen": 2,
            "validated": 1,
            "mpdu_dispatch": 1,
        }))
        self.assertEqual(result["rxWindowStageName"],
                         "rx_mpdu_notification_validated_seen")
        self.assertTrue(result["rxWindowFlags"] & 16)
        self.assertEqual(result["rxInterruptHandlerCalls"], 0)
        self.assertEqual(result["rxDrainCalls"], 0)
        self.assertEqual(result["rxRingSlots"], 0)
        self.assertEqual(result["rxNotificationSeen"], 2)
        self.assertEqual(result["rxMpduNotificationValidated"], 1)
        self.assertTrue(result["evidenceLimits"]
                        ["boundaryPartialMayOmitOuterRxServiceStages"])
        self.assertTrue(result["evidenceLimits"]
                        ["boundaryPartialPreservesObservedNotificationCounts"])

    def test_v2_boundary_partial_stage_requires_positive_boundary_flag(self):
        no_boundary = fixture(rx_counts={"flags": 3, "stage": 11})
        with self.assertRaisesRegex(decoder.DecodeError,
                                    "partial RX service stage contradicts evidence"):
            decoder.decode(no_boundary)

        contradictory = fixture(rx_counts={
            "flags": 3 | 16, "stage": 1, "ring": 1,
            "first_slot": 312, "last_slot": 312,
            "first_head": 313, "last_head": 313,
        })
        with self.assertRaisesRegex(decoder.DecodeError,
                                    "unclassified boundary service gap lacks partial stage"):
            decoder.decode(contradictory)

        partial = decoder.decode(fixture(rx_counts={
            "flags": 3 | 16, "stage": 11, "ring": 1,
            "first_slot": 312, "last_slot": 312,
            "first_head": 313, "last_head": 313,
        }))
        self.assertEqual(partial["rxWindowStageName"],
                         "boundary_spanning_partial_rx_service")


if __name__ == "__main__":
    unittest.main()
