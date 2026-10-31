#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('integration', HERE/'collect_after_capture.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class CaptureIntegrationTests(unittest.TestCase):
    def fixture(self):
        fixture = json.loads((HERE.parent/'test096/fixtures/test095_runtime_close_marker.json').read_text())
        binding = fixture['binding']
        build = {'candidate': module.CANDIDATE, 'mach_o_uuid': binding['loadedUUID'], 'binary_sha256': 'synthetic-binary-sha'}
        p = fixture['preownerCapture']
        report = {'candidate': module.CANDIDATE, 'boot_epoch': binding['bootEpoch'],
            'arm_run_token': binding['armRunToken'], 'boot_attempt_claim_consumed': True,
            'native_helper_invoked': True, 'expected_archive_binary_sha256': build['binary_sha256'],
            'identity': {'loaded_uuid': binding['loadedUUID'], 'loaded_uuid_matches_receipt': True,
                         'archive_binary_sha256_verified': True, 'archive_info_plist_sha256_verified': True},
            'preowner_observation': {'comparison': {'stable': p['stable'], 'decoded': p['decoded']},
                 'raw_reads': [{}, {}, {}], 'commit_markers_valid_for_all_reads': p['commitMarkersValidForAllReads']},
            'management_trace_u32_evidence': {'raw_snapshots': {'post': fixture['traceSnapshot']['rawSnapshot']}}}
        return report, build, binding

    def test_binding_and_separate_read_only_collection(self):
        report, build, binding = self.fixture()
        actual = module.bind_capture(report, build, binding['bootEpoch'], binding['loadedUUID'])
        self.assertEqual(actual, binding)
        result = module.collect(report, actual, lambda: None, publication_timeout=0)
        self.assertEqual(result['independent_marker']['status'], 'verified_end_marker')
        self.assertFalse(result['complete'])
        self.assertIsNone(result['copies'])

    def test_wrong_candidate_boot_uuid_and_claim_are_rejected(self):
        report, build, binding = self.fixture()
        for key, value in [('candidate','old'),('boot_epoch',0),('boot_attempt_claim_consumed',False),
                           ('native_helper_invoked',False),('arm_run_token',''),
                           ('expected_archive_binary_sha256','wrong')]:
            row = copy.deepcopy(report); row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.bind_capture(row, build, binding['bootEpoch'], binding['loadedUUID'])
        with self.assertRaises(ValueError):
            module.bind_capture(report, build, binding['bootEpoch'], 'wrong-loaded-uuid')

    def test_missing_terminal_evidence_never_reads_property(self):
        report, build, binding = self.fixture()
        report['management_trace_u32_evidence'] = {}
        def forbidden():
            raise AssertionError('must not read a property before the independent terminal marker')
        result = module.collect(report, binding, forbidden, publication_timeout=0)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['copies'])

if __name__ == '__main__':
    unittest.main()
