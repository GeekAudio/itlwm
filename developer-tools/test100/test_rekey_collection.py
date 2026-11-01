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

    def test_different_candidate_is_rejected_before_serialization(self):
        with self.assertRaises(collector.IdentityMismatch):
            collector.select_allowlisted({'NativeTestBuild': '25G332-Test098'}, '25G332-Test100')


if __name__ == '__main__':
    unittest.main()
