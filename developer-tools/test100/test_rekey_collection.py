"""Verify schema-4 host-origin evidence is retained as a separate live cut."""
import importlib.util
from pathlib import Path
import plistlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('rekey100', Path(__file__).with_name('collect_rekey100.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class SavedSampleTests(unittest.TestCase):
    def test_new_header_and_live_counters_survive_sample_serialization(self):
        service = {
            'NativeTestBuild': '25G332-Test100',
            'NativeStaCompletionSchema': 4,
            'NativeStaCompletionSnapshotComplete': 1,
            'NativeStaCompletionSnapshotVersionBegin': 2,
            'NativeStaCompletionSnapshotVersionEnd': 2,
            'NativeStaCompletionEvent0Present': 1,
            'NativeStaCompletionEvent0Kind': 0,
            'NativeStaCompletionEvent0Serial': 5,
            'NativeStaCompletionEvent0FirmwareQid': 1,
            'NativeStaCompletionEvent0QueueIndex': 139,
            'NativeStaCompletionEvent0RingCount': 1024,
            'NativeStaCompletionEvent0Queued': 1,
            'NativeStaCompletionEvent0Tail': 138,
            'NativeStaCompletionEvent0PresenceFlags': 1 << 30,
            'NativeStaCompletionEvent0TxCommandScanStatus': 1,
            'NativeStaCompletionEvent0TxCommandExpectedCount': 1,
            'NativeStaCompletionEvent0TxCommandScannedCount': 1,
            'NativeStaCompletionEvent0TxCommandCandidateIndex': 138,
            'NativeStaCompletionEvent0SingleSlotTxCommandHeader': 0x410808A0,
            'NativeStaCompletionEvent0HostOriginState': 2,
            'NativeStaCompletionEvent0HostOriginCookie': 11,
            'NativeStaCompletionEvent0HostOriginSlotGeneration': 19,
            'NativeStaCompletionEvent0HostOriginContextGeneration': 5,
            'NativeStaCompletionEvent0HostOriginOutputEpoch': 12,
            'NativeStaCompletionEvent0HostOriginIdentityEpoch': 3,
            'NativeStaCompletionEvent0HostOriginAttemptId': 77,
            'NativeStaCompletionEvent0HostOriginSource': 1,
            'NativeStaCompletionEvent0HostOriginIndex': 138,
            'NativeStaCompletionEvent0HostOriginFrameControl': 0x4108,
            'NativeStaCompletionEvent0HostOriginSequenceControl': 0x04B0,
            'NativeStaCompletionEvent0HostOriginTid': 6,
            'NativeStaCompletionRelatedCutLostCount': 0,
            'NativeStaCompletionLiveRelatedCutLostCount': 7,
            'PrivateKeyNotAllowed': b'fixture-not-a-real-key',
        }
        responses = [plistlib.dumps([service]), b'en1: flags=3<UP,RUNNING>\n\tinet 192.0.2.1\n\tinet6 fe80::1\n\tstatus: active\n']
        with patch.object(collector, '_run_bytes', side_effect=responses):
            sample = collector.sample_once('25G332-Test100', {'boot_epoch': 1})
        row, _ = collector.materialize_sample(sample, {}, 1)
        stable = row['completion_scalars']
        live = row['completion_live_counters']
        host_origin = row['completion_host_origin']
        self.assertEqual(stable['NativeStaCompletionEvent0SingleSlotTxCommandHeader'], 0x410808A0)
        self.assertEqual(stable['NativeStaCompletionRelatedCutLostCount'], 0)
        self.assertEqual(host_origin['status'], 'unique_host_slot')
        self.assertTrue(host_origin['same_slot_descriptor'])
        self.assertFalse(host_origin['exact_response_tuple_match'])
        self.assertEqual(host_origin['host_origin']['sequence_control'], 0x04B0)
        self.assertNotIn('NativeStaCompletionLiveRelatedCutLostCount', stable)
        self.assertEqual(live, {'NativeStaCompletionLiveRelatedCutLostCount': 7})
        self.assertNotIn('PrivateKeyNotAllowed', repr(row))

    @staticmethod
    def schema5_unique_scalars():
        prefix = 'NativeStaCompletion'
        fields = {
            'Schema': 5,
            'SnapshotComplete': 1,
            'SnapshotVersionBegin': 20,
            'SnapshotVersionEnd': 20,
            'Event0Present': 1,
            'Event0Kind': 0,
            'Event0Serial': 453,
            'Event0PresenceFlags': ((1 << 7) | (1 << 8) | (1 << 9) |
                                    (1 << 10) | (1 << 12) | (1 << 25) |
                                    (1 << 26) | (1 << 27) | (1 << 28) |
                                    (1 << 30) | (1 << 31)),
            'Event0OutputEpoch': 5,
            'Event0HostOriginState': 2,
            'Event0HostOriginCookie': 10,
            'Event0HostOriginSlotGeneration': 10,
            'Event0HostOriginContextGeneration': 5,
            'Event0HostOriginOutputEpoch': 5,
            'Event0HostOriginIdentityEpoch': 0,
            'Event0HostOriginAttemptId': 10,
            'Event0HostOriginSource': 1,
            'Event0HostOriginIndex': 20,
            'Event0HostOriginFrameControl': 0x4108,
            'Event0HostOriginSequenceControl': 0x0140,
            'Event0HostOriginTid': 15,
            'Event0FirmwareQid': 1,
            'Event0QueueIndex': 21,
            'Event0RingCount': 1024,
            'Event0Queued': 1,
            'Event0Tail': 20,
            'Event0TxCommandScanStatus': 1,
            'Event0TxCommandExpectedCount': 1,
            'Event0TxCommandScannedCount': 1,
            'Event0TxCommandCandidateCount': 0,
            'Event0TxCommandCandidateIndex': 20,
            'Event0TxCommandApiGeneration': 3,
            'Event0TxCommandVersion': 1,
            'Event0SingleSlotTxCommandHeader': 0x41080140,
            'Event0ResponseFrameControl': 0x4108,
            'Event0ResponseSequenceControl': 0x0160,
        }
        return {prefix + suffix: value for suffix, value in fields.items()}

    def test_schema5_preserves_host_and_response_tuple_without_claiming_exact_match(self):
        scalars = self.schema5_unique_scalars()
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['schema'], 5)
        self.assertEqual(parsed['status'], 'unique_host_slot')
        self.assertTrue(parsed['same_slot_descriptor'])
        self.assertFalse(parsed['exact_response_tuple_match'])
        self.assertEqual(parsed['response_tuple_status'], 'raw_tuple_unmarked')
        self.assertFalse(parsed['response_tuple_matches_single_slot_header'])
        self.assertEqual(parsed['host_origin']['sequence_control'], 0x0140)
        self.assertEqual(
            parsed['raw_witness']['single_slot_tx_command_header'], 0x41080140)
        self.assertEqual(parsed['raw_witness']['response_sequence_control'], 0x0160)
        self.assertNotIn('peer_ack', parsed)
        self.assertNotIn('airdrop_received', parsed)

    def test_schema5_witness_survives_collector_sample_serialization(self):
        service = {
            'NativeTestBuild': '25G332-Test100',
            **self.schema5_unique_scalars(),
        }
        responses = [
            plistlib.dumps([service]),
            b'en1: flags=3<UP,RUNNING>\n\tinet 192.0.2.1\n\tstatus: active\n',
        ]
        with patch.object(collector, '_run_bytes', side_effect=responses):
            sample = collector.sample_once('25G332-Test100', {'boot_epoch': 1})
        row, _ = collector.materialize_sample(sample, {}, 1)
        self.assertEqual(row['completion_scalars'][
            'NativeStaCompletionEvent0SingleSlotTxCommandHeader'], 0x41080140)
        self.assertEqual(row['completion_host_origin']['raw_witness'][
            'host_origin_sequence_control'], 0x0140)
        self.assertEqual(row['completion_host_origin']['raw_witness'][
            'response_sequence_control'], 0x0160)

    def test_schema5_presence_type_must_be_numeric_and_raw_witness_remains_visible(self):
        scalars = self.schema5_unique_scalars()
        scalars['NativeStaCompletionEvent0PresenceFlags'] = 'not-a-number'
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_presence')
        self.assertEqual(parsed['raw_witness']['presence_flags'], 'not-a-number')

    def test_schema5_epoch_mismatch_is_not_accepted_as_same_host_origin(self):
        scalars = self.schema5_unique_scalars()
        scalars['NativeStaCompletionEvent0HostOriginOutputEpoch'] = 6
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_epoch')
        self.assertFalse(parsed['same_slot_descriptor'])
        self.assertEqual(parsed['raw_witness']['host_origin_output_epoch'], 6)

    def test_schema5_requires_presence_markers_and_does_not_fill_missing_fields(self):
        scalars = self.schema5_unique_scalars()
        key = 'NativeStaCompletionEvent0PresenceFlags'
        scalars[key] &= ~(1 << 30)
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_presence')
        self.assertEqual(
            parsed['raw_witness']['single_slot_tx_command_header'], 0x41080140)

        scalars = self.schema5_unique_scalars()
        del scalars['NativeStaCompletionEvent0HostOriginSequenceControl']
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_payload')
        self.assertIsNone(parsed['raw_witness']['host_origin_sequence_control'])

    def test_schema5_rejects_conflicting_origin_header_but_keeps_both_raw_values(self):
        scalars = self.schema5_unique_scalars()
        scalars['NativeStaCompletionEvent0SingleSlotTxCommandHeader'] = 0x41080160
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_header_conflict')
        self.assertFalse(parsed['same_slot_descriptor'])
        self.assertEqual(parsed['raw_witness']['host_origin_sequence_control'], 0x0140)
        self.assertEqual(
            parsed['raw_witness']['single_slot_tx_command_header'], 0x41080160)

    def test_schema5_exact_response_match_requires_flag_and_full_raw_tuple(self):
        scalars = self.schema5_unique_scalars()
        scalars['NativeStaCompletionEvent0ResponseSequenceControl'] = 0x0140
        unmarked = collector.parse_completion_host_origin(scalars)
        self.assertFalse(unmarked['exact_response_tuple_match'])
        self.assertEqual(unmarked['response_tuple_status'], 'raw_tuple_unmarked')

        scalars['NativeStaCompletionEvent0PresenceFlags'] |= 1 << 29
        scalars['NativeStaCompletionEvent0TxCommandCandidateCount'] = 1
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'unique_host_slot')
        self.assertTrue(parsed['exact_response_tuple_match'])
        self.assertEqual(parsed['response_tuple_status'],
                         'exact_candidate_header_match')

        scalars['NativeStaCompletionEvent0ResponseSequenceControl'] = 0x0160
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_response_tuple_binding')
        self.assertFalse(parsed['exact_response_tuple_match'])
        self.assertEqual(parsed['raw_witness']['response_sequence_control'], 0x0160)

    def test_unbound_sidecar_is_never_labeled_same_slot(self):
        scalars = {
            'NativeStaCompletionSchema': 4,
            'NativeStaCompletionSnapshotComplete': 1,
            'NativeStaCompletionSnapshotVersionBegin': 2,
            'NativeStaCompletionSnapshotVersionEnd': 2,
            'NativeStaCompletionEvent0Present': 1,
            'NativeStaCompletionEvent0Kind': 0,
            'NativeStaCompletionEvent0Serial': 6,
            'NativeStaCompletionEvent0PresenceFlags': 0,
            'NativeStaCompletionEvent0FirmwareQid': 1,
            'NativeStaCompletionEvent0QueueIndex': 139,
            'NativeStaCompletionEvent0RingCount': 1024,
            'NativeStaCompletionEvent0Queued': 1,
            'NativeStaCompletionEvent0Tail': 138,
            'NativeStaCompletionEvent0TxCommandCandidateIndex': 138,
            'NativeStaCompletionEvent0HostOriginState': 5,
            'NativeStaCompletionEvent0HostOriginCookie': 1,
            'NativeStaCompletionEvent0HostOriginSlotGeneration': 2,
            'NativeStaCompletionEvent0HostOriginContextGeneration': 3,
            'NativeStaCompletionEvent0HostOriginOutputEpoch': 4,
            'NativeStaCompletionEvent0HostOriginIdentityEpoch': 0,
            'NativeStaCompletionEvent0HostOriginAttemptId': 5,
            'NativeStaCompletionEvent0HostOriginSource': 2,
            'NativeStaCompletionEvent0HostOriginIndex': 138,
            'NativeStaCompletionEvent0HostOriginFrameControl': 0x4108,
            'NativeStaCompletionEvent0HostOriginSequenceControl': 0x04B0,
            'NativeStaCompletionEvent0HostOriginTid': 6,
        }
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'],
                         'interval_sidecar_unbound_from_command_header')
        self.assertFalse(parsed['same_slot_descriptor'])

    def test_unique_sidecar_requires_single_reclaim_slot_and_boundary_predecessor(self):
        scalars = {
            'NativeStaCompletionSchema': 4,
            'NativeStaCompletionSnapshotComplete': 1,
            'NativeStaCompletionSnapshotVersionBegin': 2,
            'NativeStaCompletionSnapshotVersionEnd': 2,
            'NativeStaCompletionEvent0Present': 1,
            'NativeStaCompletionEvent0Kind': 0,
            'NativeStaCompletionEvent0Serial': 7,
            'NativeStaCompletionEvent0PresenceFlags': 1 << 30,
            'NativeStaCompletionEvent0FirmwareQid': 1,
            'NativeStaCompletionEvent0QueueIndex': 77,
            'NativeStaCompletionEvent0RingCount': 1024,
            'NativeStaCompletionEvent0Queued': 2,
            'NativeStaCompletionEvent0Tail': 75,
            'NativeStaCompletionEvent0TxCommandScanStatus': 1,
            'NativeStaCompletionEvent0TxCommandExpectedCount': 1,
            'NativeStaCompletionEvent0TxCommandScannedCount': 1,
            'NativeStaCompletionEvent0TxCommandCandidateIndex': 76,
            'NativeStaCompletionEvent0HostOriginState': 2,
            'NativeStaCompletionEvent0HostOriginCookie': 11,
            'NativeStaCompletionEvent0HostOriginSlotGeneration': 19,
            'NativeStaCompletionEvent0HostOriginContextGeneration': 5,
            'NativeStaCompletionEvent0HostOriginOutputEpoch': 12,
            'NativeStaCompletionEvent0HostOriginIdentityEpoch': 3,
            'NativeStaCompletionEvent0HostOriginAttemptId': 77,
            'NativeStaCompletionEvent0HostOriginSource': 1,
            'NativeStaCompletionEvent0HostOriginIndex': 76,
            'NativeStaCompletionEvent0HostOriginFrameControl': 0x4108,
            'NativeStaCompletionEvent0HostOriginSequenceControl': 0x04B0,
            'NativeStaCompletionEvent0HostOriginTid': 6,
        }
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_binding')
        self.assertIsNot(parsed.get('same_slot_descriptor'), True)

        # The interval must also reject a candidate that happens to agree
        # with the sidecar but is not the boundary's modular predecessor.
        scalars['NativeStaCompletionEvent0TxCommandCandidateIndex'] = 75
        scalars['NativeStaCompletionEvent0HostOriginIndex'] = 75
        parsed = collector.parse_completion_host_origin(scalars)
        self.assertEqual(parsed['status'], 'invalid_host_origin_binding')
        self.assertIsNot(parsed.get('same_slot_descriptor'), True)

    def test_different_candidate_is_rejected_before_serialization(self):
        with self.assertRaises(collector.IdentityMismatch):
            collector.select_allowlisted({'NativeTestBuild': '25G332-Test098'}, '25G332-Test100')


if __name__ == '__main__':
    unittest.main()
