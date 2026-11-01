import copy
import unittest

from firmware_single_queue_completion105 import evaluate, REQUIRED_PRESENCE


def fixture():
    top = dict(Schema=5, SnapshotVersionBegin=12, SnapshotVersionEnd=12,
               SnapshotAvailable=1, SnapshotComplete=1, DroppedCount=0,
               RelatedRecordDroppedCount=0, RelatedCutLostCount=0,
               OwnerGeneration=9, PublicationGeneration=9, PublicationSource=1,
               PublicationSequence=12, NextSerial=27, TxRspPrefixExtensionSchema=1,
               TxRspVersionLookupGroup=1, TxRspVersionLookupCommand=28)
    e = dict(Present=1, Kind=0, Stage=1, TerminalReason=8, Serial=27, Count=11,
             MonotonicNs=123456789, DriverGeneration=9, OutputEpoch=8,
             PresenceFlags=REQUIRED_PRESENCE, RxGroup=0, RxCommand=28,
             RxHeaderQid=1, RxHeaderIndex=20, RxPacketLength=52, PayloadLength=48,
             FirmwareQid=1, QueueIndex=21, RingCount=1024, Queued=1, Cur=21,
             Tail=20, FrameCount=1, Ssn=21, RaTid=15, Status=1,
             ResponseFrameControl=0x4108, ResponseSequenceControl=0x160,
             TxCommandScanStatus=1, TxCommandExpectedCount=1,
             TxCommandScannedCount=1, TxCommandCandidateCount=0,
             TxCommandCandidateIndex=20, TxCommandApiGeneration=3, TxCommandVersion=10,
             TxCommandFlags=4, TxCommandOffloadAssist=0,
             SingleSlotTxCommandHeader=(0x4108 << 16) | 0x140,
             HostOriginState=2, HostOriginCookie=501, HostOriginSlotGeneration=7,
             HostOriginContextGeneration=9, HostOriginOutputEpoch=8,
             HostOriginIdentityEpoch=3, HostOriginAttemptId=2, HostOriginSource=1,
             HostOriginIndex=20, HostOriginFrameControl=0x4108,
             HostOriginSequenceControl=0x140, HostOriginTid=15,
             TxRspPrefixObservationVersion=1, TxRspNotificationVersion=7)
    return {"NativeStaCompletion" + k: v for k, v in top.items()} | {
        "NativeStaCompletionEvent0" + k: v for k, v in e.items()}


def run(values):
    return evaluate(values, expected_generation=9, expected_output_epoch=8)


class QueueCompletionTests(unittest.TestCase):
    def test_independent_of_sc_but_never_upgrades_peer(self):
        values = fixture(); saved = copy.deepcopy(values)
        result = run(values)
        self.assertIs(result["firmware_single_queue_completion_success"], True)
        self.assertIs(result["exact_response_tuple_match_observed"], False)
        self.assertIs(result["exact_sequence_control_equal_observed"], False)
        self.assertEqual(result["host_slot"], 20)
        self.assertEqual(result["exclusive_boundary"], 21)
        self.assertEqual(values, saved)
        for name in ("peer_receipt_proven", "peer_key_validation_proven",
                     "airdrop_proven", "on_air_sequence_proven",
                     "radio_ack_proven", "firmware_incarnation_echo_proven",
                     "original_exact_sc_match_modified"):
            self.assertIs(result[name], False)

    def test_same_sc_keeps_original_candidate_bit_consistent(self):
        values = fixture()
        values["NativeStaCompletionEvent0ResponseSequenceControl"] = 0x140
        self.assertIsNone(run(values)["firmware_single_queue_completion_success"])
        values["NativeStaCompletionEvent0TxCommandCandidateCount"] = 1
        values["NativeStaCompletionEvent0PresenceFlags"] |= 1 << 29
        result = run(values)
        self.assertTrue(result["firmware_single_queue_completion_success"])
        self.assertTrue(result["exact_response_tuple_match_observed"])

    def test_every_required_field_missing_and_bad_type_is_unknown(self):
        for key in fixture():
            for bad in (None, True, "1", -1, 1 << 65):
                with self.subTest(key=key, bad=bad):
                    values = fixture(); values[key] = bad
                    self.assertIsNone(run(values)["firmware_single_queue_completion_success"])

    def test_every_required_presence_bit_missing_is_unknown(self):
        for bit in range(32):
            if REQUIRED_PRESENCE & (1 << bit):
                values = fixture()
                values["NativeStaCompletionEvent0PresenceFlags"] &= ~(1 << bit)
                self.assertIsNone(run(values)["firmware_single_queue_completion_success"])

    def test_negative_identity_version_status_and_reclaim_cases(self):
        cases = {
            "Schema": [4, 6], "SnapshotVersionBegin": [0, 11, 14],
            "SnapshotVersionEnd": [10, 11], "SnapshotComplete": [0],
            "SnapshotAvailable": [0], "DroppedCount": [1],
            "RelatedRecordDroppedCount": [1], "RelatedCutLostCount": [1],
            "OwnerGeneration": [8], "PublicationGeneration": [8],
            "PublicationSource": [2], "PublicationSequence": [14],
            "TxRspPrefixExtensionSchema": [0, 2], "TxRspVersionLookupGroup": [0],
            "TxRspVersionLookupCommand": [23], "NextSerial": [0, 26],
            "Event0DriverGeneration": [8], "Event0HostOriginContextGeneration": [8],
            "Event0OutputEpoch": [7], "Event0HostOriginOutputEpoch": [7],
            "Event0HostOriginIdentityEpoch": [0xffffffff],
            "Event0Present": [0], "Event0Kind": [1], "Event0Stage": [2],
            "Event0TerminalReason": [5, 9], "Event0Serial": [0, 28],
            "Event0MonotonicNs": [0], "Event0FrameCount": [0, 2],
            "Event0Status": [0, 2, 0x101], "Event0RxGroup": [1, 64],
            "Event0RxCommand": [23], "Event0RxHeaderQid": [2, 129],
            "Event0RxHeaderIndex": [21, 276], "Event0PayloadLength": [47],
            "Event0RxPacketLength": [48, 53], "Event0RingCount": [0, 3, 2048],
            "Event0Queued": [0, 2], "Event0Tail": [19, 1024],
            "Event0Cur": [20], "Event0QueueIndex": [20, 22, 1024],
            "Event0Ssn": [20, 22, 4096], "Event0FirmwareQid": [2, 256],
            "Event0HostOriginState": [1, 3, 4, 5], "Event0HostOriginIndex": [21],
            "Event0HostOriginCookie": [0], "Event0HostOriginAttemptId": [0],
            "Event0HostOriginSlotGeneration": [0], "Event0HostOriginSource": [0, 3],
            "Event0TxCommandCandidateIndex": [21], "Event0TxCommandCandidateCount": [1, 2],
            "Event0TxCommandExpectedCount": [2], "Event0TxCommandScannedCount": [0],
            "Event0TxCommandScanStatus": [2], "Event0TxCommandApiGeneration": [2],
            "Event0TxCommandVersion": [1, 8, 9, 255], "Event0TxCommandFlags": [65536],
            "Event0SingleSlotTxCommandHeader": [0], "Event0HostOriginFrameControl": [65536],
            "Event0HostOriginSequenceControl": [65536], "Event0HostOriginTid": [16],
            "Event0RaTid": [14, 256], "Event0ResponseSequenceControl": [65536],
            "Event0TxRspPrefixObservationVersion": [0, 2],
            "Event0TxRspNotificationVersion": [0, 6, 255],
        }
        for suffix, bads in cases.items():
            for bad in bads:
                with self.subTest(field=suffix, value=bad):
                    values = fixture(); values["NativeStaCompletion" + suffix] = bad
                    self.assertIsNone(run(values)["firmware_single_queue_completion_success"])

    def test_modular_wrap_and_full_ring_slot_with_u8_header(self):
        for tail, boundary in [(1023, 0), (276, 277)]:
            values = fixture()
            for name in ("Tail", "HostOriginIndex", "TxCommandCandidateIndex"):
                values["NativeStaCompletionEvent0" + name] = tail
            for name in ("Cur", "QueueIndex", "Ssn"):
                values["NativeStaCompletionEvent0" + name] = boundary
            values["NativeStaCompletionEvent0RxHeaderIndex"] = tail & 255
            self.assertTrue(run(values)["firmware_single_queue_completion_success"])

    def test_no_context_or_no_scalar_cut_unknown(self):
        for g, e in [(0, 8), (9, 0), (True, 8), (9, 0xffffffff), (9, None)]:
            self.assertIsNone(evaluate(fixture(), expected_generation=g,
                                      expected_output_epoch=e)["firmware_single_queue_completion_success"])
        self.assertIsNone(run(None)["firmware_single_queue_completion_success"])


if __name__ == "__main__":
    unittest.main()
