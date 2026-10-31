"""Verify the saved sample retains separate schema-3 and live observations."""
import importlib.util
from pathlib import Path
import plistlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('rekey099', Path(__file__).with_name('collect_rekey099.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class SavedSampleTests(unittest.TestCase):
    def test_new_header_and_live_counters_survive_sample_serialization(self):
        service = {
            'NativeTestBuild': '25G332-Test099',
            'NativeStaCompletionSchema': 3,
            'NativeStaCompletionSnapshotVersionBegin': 2,
            'NativeStaCompletionSnapshotVersionEnd': 2,
            'NativeStaCompletionEvent0PresenceFlags': 1 << 30,
            'NativeStaCompletionEvent0SingleSlotTxCommandHeader': 0x410808A0,
            'NativeStaCompletionRelatedCutLostCount': 0,
            'NativeStaCompletionLiveRelatedCutLostCount': 7,
            'PrivateKeyNotAllowed': b'fixture-not-a-real-key',
        }
        responses = [plistlib.dumps([service]), b'en1: flags=3<UP,RUNNING>\n\tinet 192.0.2.1\n\tinet6 fe80::1\n\tstatus: active\n']
        with patch.object(collector, '_run_bytes', side_effect=responses):
            sample = collector.sample_once('25G332-Test099', {'boot_epoch': 1})
        row, _ = collector.materialize_sample(sample, {}, 1)
        stable = row['completion_scalars']
        live = row['completion_live_counters']
        self.assertEqual(stable['NativeStaCompletionEvent0SingleSlotTxCommandHeader'], 0x410808A0)
        self.assertEqual(stable['NativeStaCompletionRelatedCutLostCount'], 0)
        self.assertNotIn('NativeStaCompletionLiveRelatedCutLostCount', stable)
        self.assertEqual(live, {'NativeStaCompletionLiveRelatedCutLostCount': 7})
        self.assertNotIn('PrivateKeyNotAllowed', repr(row))

    def test_different_candidate_is_rejected_before_serialization(self):
        with self.assertRaises(collector.IdentityMismatch):
            collector.select_allowlisted({'NativeTestBuild': '25G332-Test098'}, '25G332-Test099')


if __name__ == '__main__':
    unittest.main()
