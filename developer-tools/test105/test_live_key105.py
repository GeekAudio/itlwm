import unittest
from live_key105 import FIELDS, PREFIX, parse_live_key


def fixture():
    d = {PREFIX + key: 0 for key in FIELDS}
    d.update({PREFIX + key: value for key, value in {
        "Schema": 1, "RevisionBegin": 2, "RevisionEnd": 2,
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
            ("Schema", 2, "unsupported_schema"),
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


if __name__ == "__main__":
    unittest.main()
