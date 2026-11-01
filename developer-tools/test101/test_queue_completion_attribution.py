import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "queue_completion_attribution",
    Path(__file__).with_name("queue_completion_attribution.py"))
tool = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(tool)


def fixture(source=1):
    flags = sum(1 << bit for bit in (7, 8, 9, 10, 11, 12, 13, 14, 16,
                                     25, 26, 27, 28, 30))
    scalars = {
        "NativeStaCompletionSchema": 4,
        "NativeStaCompletionSnapshotAvailable": 1,
        "NativeStaCompletionSnapshotComplete": 1,
        "NativeStaCompletionSnapshotVersionBegin": 2,
        "NativeStaCompletionSnapshotVersionEnd": 2,
        "NativeStaCompletionPublicationSource": source,
        "NativeStaCompletionPublicationGeneration": 5,
        "NativeStaCompletionRelatedCutLostCount": 0,
        "NativeStaCompletionRelatedRecordDroppedCount": 0,
        "NativeStaCompletionEvent0Present": 1,
        "NativeStaCompletionEvent0Kind": 0,
        "NativeStaCompletionEvent0Serial": 1961,
        "NativeStaCompletionEvent0FirmwareQid": 1,
        "NativeStaCompletionEvent0QueueIndex": 26,
        "NativeStaCompletionEvent0RingCount": 1024,
        "NativeStaCompletionEvent0Queued": 1,
        "NativeStaCompletionEvent0Cur": 26,
        "NativeStaCompletionEvent0Tail": 25,
        "NativeStaCompletionEvent0FrameCount": 1,
        "NativeStaCompletionEvent0Ssn": 26,
        "NativeStaCompletionEvent0Status": 1,
        "NativeStaCompletionEvent0HostOriginState": 2,
        "NativeStaCompletionEvent0HostOriginCookie": 1,
        "NativeStaCompletionEvent0HostOriginSlotGeneration": 1,
        "NativeStaCompletionEvent0HostOriginContextGeneration": 5,
        "NativeStaCompletionEvent0HostOriginOutputEpoch": 5,
        "NativeStaCompletionEvent0HostOriginIdentityEpoch": 0,
        "NativeStaCompletionEvent0HostOriginAttemptId": 1,
        "NativeStaCompletionEvent0HostOriginSource": source,
        "NativeStaCompletionEvent0HostOriginIndex": 25,
        "NativeStaCompletionEvent0HostOriginFrameControl": 0x4108,
        "NativeStaCompletionEvent0HostOriginSequenceControl": 0x0190,
        "NativeStaCompletionEvent0HostOriginTid": 15,
        "NativeStaCompletionEvent0DriverGeneration": 5,
        "NativeStaCompletionEvent0OutputEpoch": 5,
        "NativeStaCompletionEvent0TerminalReason": 8,
        "NativeStaCompletionEvent0PresenceFlags": flags,
        "NativeStaCompletionEvent0ResponseFrameControl": 0x4108,
        "NativeStaCompletionEvent0ResponseSequenceControl": 0x01A0,
        "NativeStaCompletionEvent0TxCommandScanStatus": 1,
        "NativeStaCompletionEvent0TxCommandExpectedCount": 1,
        "NativeStaCompletionEvent0TxCommandScannedCount": 1,
        "NativeStaCompletionEvent0TxCommandCandidateCount": 0,
        "NativeStaCompletionEvent0TxCommandCandidateIndex": 25,
    }
    origin = {
        "status": "unique_host_slot",
        "schema": 4,
        "snapshot_version": 2,
        "event_serial": 1961,
        "same_slot_descriptor": True,
        "exact_response_tuple_match": False,
        "host_origin_queue_id": 1,
        "command_header_index": 25,
        "host_origin": {
            "cookie": 1,
            "slot_generation": 1,
            "context_generation": 5,
            "output_epoch": 5,
            "identity_epoch": 0,
            "attempt_id": 1,
            "source": source,
            "index": 25,
            "frame_control": 0x4108,
            "sequence_control": 0x0190,
            "tid": 15,
        },
    }
    return scalars, origin


class QueueCompletionAttributionTests(unittest.TestCase):
    def test_anchor_attributes_single_slot_without_ack_or_strict_tuple(self):
        scalars, origin = fixture()
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertIs(result["queue_processed"], True)
        self.assertEqual(result["queue_processed_basis"],
                         "single_slot_tx_rsp_scd_contract")
        self.assertEqual(result["device_status"], {
            "raw": 1, "meaning": "firmware_reported_success",
            "source": "Event0.Status"})
        self.assertIs(result["strict_header_match"], False)
        self.assertEqual(result["peer_receipt"], "unknown")
        self.assertEqual(result["reference"], {
            "event_serial": 1961, "completion_cut": 2,
            "publication_source": 1})

    def test_zero_identity_epoch_and_source_two_are_valid(self):
        scalars, origin = fixture(source=2)
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertIs(result["queue_processed"], True)
        self.assertEqual(result["evidence"]["publication_source"], 2)
        self.assertTrue(result["evidence"]["identity_epoch_zero_is_valid"])
        self.assertEqual(result["peer_receipt"], "unknown")

    def test_wrap_and_queued_more_than_interval_allow_cur_not_boundary(self):
        scalars, origin = fixture()
        scalars.update({
            "NativeStaCompletionEvent0Tail": 1023,
            "NativeStaCompletionEvent0QueueIndex": 0,
            "NativeStaCompletionEvent0Ssn": 1024,
            "NativeStaCompletionEvent0Queued": 4,
            "NativeStaCompletionEvent0Cur": 1027,
            "NativeStaCompletionEvent0HostOriginIndex": 1023,
            "NativeStaCompletionEvent0TxCommandCandidateIndex": 1023,
        })
        origin["command_header_index"] = 1023
        origin["host_origin"]["index"] = 1023
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertIs(result["queue_processed"], True)
        self.assertEqual(result["evidence"]["exclusive_distance"], 1)
        self.assertEqual(result["evidence"]["queued"], 4)

    def test_device_status_failure_does_not_erase_queue_processing(self):
        scalars, origin = fixture()
        scalars["NativeStaCompletionEvent0Status"] = 7
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertIs(result["queue_processed"], True)
        self.assertEqual(result["device_status"]["raw"], 7)
        self.assertEqual(result["device_status"]["meaning"],
                         "firmware_reported_status")

    def test_strict_match_layer_is_independent(self):
        scalars, origin = fixture()
        scalars["NativeStaCompletionEvent0TxCommandCandidateCount"] = 1
        scalars["NativeStaCompletionEvent0PresenceFlags"] |= 1 << 29
        origin["exact_response_tuple_match"] = True
        self.assertIs(tool.classify_schema4_cut(scalars, origin)[
            "strict_header_match"], True)

        scalars.pop("NativeStaCompletionEvent0TxCommandCandidateCount")
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertIs(result["queue_processed"], True)
        self.assertEqual(result["strict_header_match"], "unknown")

    def test_identity_epoch_mismatch_is_not_hidden(self):
        scalars, origin = fixture()
        self.assertEqual(origin["host_origin"]["identity_epoch"], 0)
        self.assertEqual(tool.classify_schema4_cut(scalars, origin)[
            "queue_processed"], True)
        wrong_identity = tool.classify_schema4_cut(
            scalars, origin, identity_matches_header=False)
        self.assertEqual(wrong_identity["queue_processed_reason"],
                         "capture_identity_mismatch")
        self.assertIsNone(wrong_identity["device_status"]["raw"])
        self.assertEqual(wrong_identity["strict_header_match"], "unknown")

    def test_unstable_cut_does_not_publish_other_layers(self):
        scalars, origin = fixture()
        scalars["NativeStaCompletionSnapshotVersionEnd"] = 4
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertEqual(result["queue_processed"], "unknown")
        self.assertEqual(result["device_status"]["raw"], None)
        self.assertEqual(result["strict_header_match"], "unknown")
        self.assertEqual(result["peer_receipt"], "unknown")

    def test_unique_status_is_revalidated_against_same_scalar_cut(self):
        scalars, origin = fixture()
        scalars["NativeStaCompletionEvent0HostOriginState"] = 3
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertEqual(result["queue_processed"], "unknown")
        self.assertEqual(result["queue_processed_reason"],
                         "host_origin_scalar_not_unique")

        scalars, origin = fixture()
        scalars["NativeStaCompletionEvent0HostOriginSequenceControl"] = 0x01A0
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertEqual(result["queue_processed"], "unknown")
        self.assertEqual(result["queue_processed_reason"],
                         "host_origin_not_interval_slot")

    def test_fail_closed_conditions(self):
        mutations = [
            ("NativeStaCompletionEvent0FrameCount", 2,
             "frame_count_not_one"),
            ("NativeStaCompletionEvent0QueueIndex", 27,
             "queue_geometry_invalid"),
            ("NativeStaCompletionEvent0Ssn", 27,
             "queue_geometry_invalid"),
            ("NativeStaCompletionEvent0RingCount", 1000,
             "queue_geometry_invalid"),
            ("NativeStaCompletionEvent0FirmwareQid", 65536,
             "queue_geometry_invalid"),
            ("NativeStaCompletionEvent0TerminalReason", 7,
             "single_reclaim_terminal_not_established"),
        ]
        for field, value, reason in mutations:
            with self.subTest(field=field):
                scalars, origin = fixture()
                scalars[field] = value
                result = tool.classify_schema4_cut(scalars, origin)
                self.assertEqual(result["queue_processed"], "unknown")
                self.assertEqual(result["queue_processed_reason"], reason)

    def test_prior_retention_loss_does_not_erase_complete_event(self):
        for source in (1, 2):
            scalars, origin = fixture()
            scalars["NativeStaCompletionPublicationSource"] = source
            scalars["NativeStaCompletionRelatedCutLostCount"] = 2
            scalars["NativeStaCompletionRelatedRecordDroppedCount"] = 8
            result = tool.classify_schema4_cut(scalars, origin)
            self.assertIs(result["queue_processed"], True)
            self.assertEqual(result["evidence"]["related_cut_lost_count"], 2)
            scalars["NativeStaCompletionSnapshotComplete"] = 0
            self.assertEqual(tool.classify_schema4_cut(scalars, origin)[
                "queue_processed"], "unknown")

    def test_missing_stale_or_ambiguous_origin_is_unknown(self):
        for status in ("none", "multiple", "stale_or_reset_ambiguous",
                       "interval_sidecar_unbound_from_command_header"):
            with self.subTest(status=status):
                scalars, origin = fixture()
                origin["status"] = status
                result = tool.classify_schema4_cut(scalars, origin)
                self.assertEqual(result["queue_processed"], "unknown")
                self.assertEqual(result["queue_processed_reason"],
                                 "host_origin_not_unique_current")

        scalars, origin = fixture()
        origin["host_origin"]["context_generation"] += 1
        scalars["NativeStaCompletionEvent0HostOriginContextGeneration"] += 1
        self.assertEqual(tool.classify_schema4_cut(scalars, origin)[
            "queue_processed_reason"], "host_origin_epoch_mismatch")

    def test_queue_origin_requires_scan_presence_but_not_candidate_count(self):
        scalars, origin = fixture()
        scalars["NativeStaCompletionEvent0PresenceFlags"] &= ~(1 << 28)
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertEqual(result["queue_processed"], "unknown")
        self.assertEqual(result["queue_processed_reason"],
                         "host_origin_header_scan_incomplete")

        scalars, origin = fixture()
        scalars.pop("NativeStaCompletionEvent0TxCommandCandidateCount")
        result = tool.classify_schema4_cut(scalars, origin)
        self.assertIs(result["queue_processed"], True)
        self.assertEqual(result["strict_header_match"], "unknown")

    def test_jsonl_report_keeps_four_layers_on_same_cut(self):
        scalars, origin = fixture()
        sample = {
            "record_type": "sample", "sample_index": 1,
            "captured_at": "2026-11-01T12:04:09+08:00",
            "boot_epoch": 99, "candidate_build": "test-build",
            "os_build": "25G332", "loaded_kext_uuid": "uuid",
            "completion_scalars": scalars,
            "completion_host_origin": origin,
        }
        header = {
            "record_type": "header", "expected_boot_epoch": 99,
            "expected_candidate_build": "test-build",
            "expected_os_build": "25G332", "expected_loaded_kext_uuid": "uuid",
            "identity_error": None,
            "identity": {"boot_epoch": 99, "candidate_build_expected": "test-build",
                         "os_build": "25G332", "loaded_kext_uuid": "uuid"},
        }
        report = tool.analyze_capture(
            [header, sample, copy.deepcopy(sample), {"record_type": "footer"}],
            "a" * 64)
        self.assertEqual(report["unique_tx_rsp_cut_count"], 1)
        cut = report["cuts"][0]
        self.assertIs(cut["queue_processed"], True)
        self.assertIs(cut["strict_header_match"], False)
        self.assertEqual(cut["peer_receipt"], "unknown")
        self.assertEqual(cut["reference"]["event_serial"], 1961)
        self.assertEqual(cut["reference"]["completion_cut"], 2)

        bad_identity_header = copy.deepcopy(header)
        bad_identity_sample = copy.deepcopy(sample)
        bad_identity_sample["completion_scalars"][
            "NativeStaCompletionSnapshotVersionEnd"] = 4
        bad_identity_sample["loaded_kext_uuid"] = "different"
        bad_identity = tool.analyze_capture(
            [bad_identity_header, bad_identity_sample,
             {"record_type": "footer"}], "b" * 64)
        self.assertFalse(bad_identity["capture_identity"][
            "matches_header_for_classified_samples"])
        self.assertEqual(bad_identity["cuts"][0]["queue_processed_reason"],
                         "incomplete_or_unstable_cut")
        self.assertIsNone(bad_identity["cuts"][0]["device_status"]["raw"])

    def test_empty_identity_cannot_match_missing_fields(self):
        scalars, origin = fixture()
        header = {
            "expected_boot_epoch": None,
            "expected_candidate_build": None,
            "expected_os_build": None,
            "expected_loaded_kext_uuid": None,
            "identity": {}, "identity_error": None,
        }
        sample = {"boot_epoch": None, "candidate_build": None,
                  "os_build": None, "loaded_kext_uuid": None}
        self.assertFalse(tool._identity_matches(header, sample))


if __name__ == "__main__":
    unittest.main()
