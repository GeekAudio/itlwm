import unittest
from live_key105 import FIELDS, FIELDS_V1, PREFIX, parse_live_key


def fixture():
    d = {PREFIX + key: 0 for key in FIELDS}
    d.update({PREFIX + key: value for key, value in {
        "Schema": 2, "RevisionBegin": 2, "RevisionEnd": 2,
        "SampleMonotonicNs": 1000, "OwnerGeneration": 3,
        "OwnerOutputEpoch": 7, "OwnerContextStable": 1,
        "SubmitPresent": 1, "SubmitStable": 1, "SubmitSerial": 20,
        "SubmitMonotonicNs": 900, "SubmitDriverGeneration": 3,
        "SubmitFirmwareGeneration": 3, "SubmitPhase": 1, "SubmitSource": 1,
        "SubmitCommandId": 0x17, "SubmitIndex": 4, "SubmitHeaderSequence": 4,
        "SubmitFlags": 1 << 4,
        "ResponsePresent": 1, "ResponseStable": 1, "ResponseSerial": 10,
        "ResponseMonotonicNs": 800, "ResponseDriverGeneration": 3,
        "ResponseFirmwareGeneration": 3, "ResponsePhase": 7, "ResponseSource": 2,
        "ResponseCommandId": 0x17, "ResponseIndex": 4, "ResponseHeaderSequence": 4,
        "ResponseFlags": 1 << 10, "ResponseResult": 1,
    }.items()})
    return d


class LiveKeyTests(unittest.TestCase):
    def test_same_slot_and_generation_do_not_join_old_reply(self):
        r = parse_live_key(fixture())
        self.assertEqual(r["status"], "stable_publication")
        self.assertEqual(r["command_response_match"], "unknown")
        self.assertEqual(r["key_install_result"], "unknown")
        self.assertEqual(r["observations"]["response"]["entry"]["Serial"], 10)

    def test_later_reply_does_not_imply_no_slot_reuse(self):
        d = fixture(); d[PREFIX + "ResponseSerial"] = 21
        d[PREFIX + "ResponseMonotonicNs"] = 950
        self.assertEqual(parse_live_key(d)["command_response_match"], "unknown")

    def test_missing_odd_revision_and_bad_width(self):
        for key, value, status in [
            ("RevisionBegin", 3, "unstable_publication"),
            ("RevisionEnd", 4, "unstable_publication"),
            ("SubmitFlags", True, "missing_or_invalid_fields"),
            ("ResponseResult", 1 << 32, "missing_or_invalid_fields"),
            ("Schema", 3, "unsupported_schema"),
        ]:
            with self.subTest(key=key):
                d = fixture(); d[PREFIX + key] = value
                self.assertEqual(parse_live_key(d)["status"], status)
        d = fixture(); del d[PREFIX + "ResponseSource"]
        self.assertEqual(parse_live_key(d)["status"], "missing_or_invalid_fields")

    def test_lost_event_and_old_generation_are_explicit(self):
        d = fixture(); d[PREFIX + "ResponseDriverGeneration"] = 2
        self.assertEqual(parse_live_key(d)["observations"]["response"]["status"],
                         "retained_older_generation")
        d = fixture(); d[PREFIX + "ResponseDroppedSerial"] = 11
        d[PREFIX + "ResponseDroppedCount"] = 1
        self.assertEqual(parse_live_key(d)["observations"]["response"]["status"],
                         "retained_with_newer_event_lost")

    def test_payload_secret_or_future_time_never_becomes_proof(self):
        d = fixture(); d[PREFIX + "SubmitMonotonicNs"] = 1001
        self.assertEqual(parse_live_key(d)["status"], "invalid_observation_identity")
        d = fixture(); d[PREFIX + "KeyBytes"] = "do-not-export"
        d[PREFIX + "SubmitFlags"] = "do-not-export"
        self.assertNotIn("do-not-export", repr(parse_live_key(d)))
        d = fixture(); d[PREFIX + "ResponsePresent"] = 0
        self.assertEqual(parse_live_key(d)["status"], "absent_observation_has_payload")

    def test_v1_capture_remains_readable(self):
        d = {PREFIX + key: 0 for key in FIELDS_V1}
        d.update({PREFIX + key: value for key, value in {
            "Schema": 1, "RevisionBegin": 2, "RevisionEnd": 2,
            "SampleMonotonicNs": 1000, "OwnerGeneration": 3,
            "OwnerOutputEpoch": 7, "OwnerContextStable": 1,
            "SubmitPresent": 1, "SubmitStable": 1, "SubmitSerial": 20,
            "SubmitMonotonicNs": 900, "SubmitDriverGeneration": 3,
            "SubmitFirmwareGeneration": 3, "SubmitPhase": 1,
            "SubmitSource": 1, "SubmitCommandId": 0x17,
            "SubmitIndex": 4, "SubmitHeaderSequence": 4,
            "SubmitFlags": 1 << 4,
        }.items()})
        self.assertEqual(parse_live_key(d)["status"], "stable_publication")
        self.assertNotIn("rxsequence", parse_live_key(d)["observations"])

    def test_sequence_slots_keep_independent_origin_submit_serials(self):
        d = fixture()
        d.update({PREFIX + key: value for key, value in {
            "SubmitSerial": 21, "SubmitGroupId": 1, "SubmitVersion": 3,
            "SubmitIndex": 5, "SubmitHeaderSequence": 5,
        }.items()})
        rx_prefix = PREFIX + "RxSequence"
        tx_prefix = PREFIX + "TxSequence"
        common = {
            "Present": 1, "Stable": 1, "DroppedCount": 0,
            "DroppedSerial": 0, "MonotonicNs": 950,
            "DriverGeneration": 3, "FirmwareGeneration": 3,
            "Source": 1, "CommandId": 0x17, "GroupId": 1,
            "Version": 3, "Qid": 0, "Index": 5,
            "HeaderSequence": 5, "Result": 7, "ResultDetail": 0,
            "PacketLength": 0, "PayloadLength": 21,
            "OriginSubmitSerial": 21,
        }
        rx = {**common, "Serial": 30, "Phase": 14,
              "Flags": (1 << 4) | (1 << 13) | (1 << 14) | (1 << 15) |
                       (15 << 20) | (1 << 17) | (1 << 19)}
        tx = {**common, "Serial": 31, "Phase": 15,
              "Flags": (1 << 4) | (1 << 13) | (1 << 14) |
                       (1 << 17) | (1 << 19)}
        d.update({rx_prefix + key: value for key, value in rx.items()})
        d.update({tx_prefix + key: value for key, value in tx.items()})
        parsed = parse_live_key(d)
        self.assertEqual(parsed["status"], "stable_publication")
        self.assertEqual(parsed["key_sequence_bundle"]["status"],
                         "same_submit_serial")
        self.assertTrue(parsed["key_sequence_bundle"][
            "origin_submit_serial_matches_current_submit"])
        self.assertEqual(parsed["observations"]["rxsequence"]["entry"][
            "MaximumTid"], 15)
        self.assertTrue(parsed["key_sequence_bundle"]["same_origin_submit_serial"])
        self.assertFalse(parsed["key_install_success_proven"])
        self.assertFalse(parsed["peer_ack_proven"])

        # Same qid/index is not enough: distinct command-event serials never
        # get joined into one key update.
        tx["Serial"] = 32
        tx["PayloadLength"] = 22
        tx["OriginSubmitSerial"] = 22
        d.update({tx_prefix + key: value for key, value in tx.items()})
        parsed = parse_live_key(d)
        self.assertEqual(parsed["key_sequence_bundle"]["status"],
                         "different_submit_serials_not_joined")

        # A matching origin ID is necessary but all exact command metadata
        # must also agree before describing the pair as one submission.
        tx["PayloadLength"] = 21
        tx["OriginSubmitSerial"] = 21
        tx["Version"] = 2
        d.update({tx_prefix + key: value for key, value in tx.items()})
        parsed = parse_live_key(d)
        self.assertEqual(parsed["key_sequence_bundle"]["status"],
                         "same_submit_serial_identity_conflict")

    def test_current_unavailable_slot_supersedes_older_sequence_pair(self):
        d = fixture()
        d.update({PREFIX + key: value for key, value in {
            "SubmitSerial": 33, "SubmitGroupId": 1, "SubmitVersion": 99,
            "SubmitIndex": 5, "SubmitHeaderSequence": 5,
        }.items()})
        common = {
            "Present": 1, "Stable": 1, "DroppedCount": 0,
            "DroppedSerial": 0, "MonotonicNs": 950,
            "DriverGeneration": 3, "FirmwareGeneration": 3,
            "Source": 1, "CommandId": 0x17, "GroupId": 1,
            "Version": 99, "Qid": 0, "Index": 5,
            "HeaderSequence": 5, "Result": 2, "ResultDetail": 0,
            "PacketLength": 0, "PayloadLength": 33,
            "OriginSubmitSerial": 33,
            "Flags": (1 << 4) | (1 << 14) | (1 << 17) | (1 << 19),
        }
        d.update({PREFIX + "SequenceUnavailable" + key: value
                  for key, value in {**common, "Serial": 40,
                                     "Phase": 16}.items()})
        parsed = parse_live_key(d)
        self.assertEqual(parsed["key_sequence_bundle"]["status"],
                         "current_submit_sequence_unavailable")
        self.assertTrue(parsed["key_sequence_bundle"]["current_sequence_unavailable"])
        self.assertFalse(parsed["key_sequence_bundle"]["key_install_success_proven"])

    def test_old_exact_pair_is_not_reported_as_current_submit(self):
        d = fixture()
        rx_prefix = PREFIX + "RxSequence"
        tx_prefix = PREFIX + "TxSequence"
        common = {
            "Present": 1, "Stable": 1, "DroppedCount": 0,
            "DroppedSerial": 0, "MonotonicNs": 950,
            "DriverGeneration": 3, "FirmwareGeneration": 3,
            "Source": 1, "CommandId": 0x17, "GroupId": 1,
            "Version": 3, "Qid": 0, "Index": 5,
            "HeaderSequence": 5, "Result": 7, "ResultDetail": 0,
            "PacketLength": 0, "PayloadLength": 21,
            "OriginSubmitSerial": 21,
        }
        rx = {**common, "Serial": 30, "Phase": 14,
              "Flags": (1 << 4) | (1 << 13) | (1 << 14) | (1 << 15) |
                       (15 << 20) | (1 << 17) | (1 << 19)}
        tx = {**common, "Serial": 31, "Phase": 15,
              "Flags": (1 << 4) | (1 << 13) | (1 << 14) |
                       (1 << 17) | (1 << 19)}
        d.update({rx_prefix + key: value for key, value in rx.items()})
        d.update({tx_prefix + key: value for key, value in tx.items()})
        parsed = parse_live_key(d)
        bundle = parsed["key_sequence_bundle"]
        self.assertTrue(bundle["same_origin_submit_serial"])
        self.assertFalse(bundle["origin_submit_serial_matches_current_submit"])
        self.assertEqual(bundle["status"], "stale_sequence_pair_not_current")

    def test_unknown_or_changed_generation_is_not_key_install_evidence(self):
        d = fixture()
        d.update({PREFIX + key: value for key, value in {
            "SubmitSerial": 21, "SubmitDriverGeneration": 2,
            "SubmitFirmwareGeneration": 0, "SubmitGroupId": 1,
            "SubmitVersion": 3, "SubmitIndex": 5,
            "SubmitHeaderSequence": 5,
        }.items()})
        prefix = PREFIX + "RxSequence"
        row = {
            "Present": 1, "Stable": 1, "Serial": 30,
            "MonotonicNs": 950, "DriverGeneration": 2,
            "FirmwareGeneration": 0, "Phase": 14, "Source": 1,
            "CommandId": 0x17, "GroupId": 1, "Version": 3,
            "Qid": 0, "Index": 5, "HeaderSequence": 5,
            "Flags": (1 << 4) | (1 << 13) | (1 << 14) | (1 << 15) |
                     (1 << 17) | (1 << 18) | (1 << 19),
            "Result": 7, "ResultDetail": 0, "PacketLength": 0,
            "PayloadLength": 21, "OriginSubmitSerial": 21,
            "DroppedCount": 0, "DroppedSerial": 0,
        }
        d.update({prefix + key: value for key, value in row.items()})
        parsed = parse_live_key(d)
        self.assertEqual(parsed["observations"]["rxsequence"]["status"],
                         "retained_origin_generation_changed")
        self.assertEqual(parsed["key_sequence_bundle"]["status"],
                         "partial_sequence_generation_unverified")
        self.assertFalse(parsed["key_install_success_proven"])

        row["Flags"] &= ~(1 << 17)
        row["Flags"] &= ~(1 << 18)
        d.update({prefix + key: value for key, value in row.items()})
        parsed = parse_live_key(d)
        self.assertEqual(parsed["observations"]["rxsequence"]["status"],
                         "retained_origin_generation_unknown")


if __name__ == "__main__":
    unittest.main()
