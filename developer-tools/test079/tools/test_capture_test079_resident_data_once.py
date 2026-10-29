#!/usr/bin/env python3
"""Offline safety checks for Test079's disarmed one-shot host collector."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    'capture_test079', ROOT / 'capture_test079_resident_data_once.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Test079CollectorSafetyTests(unittest.TestCase):
    def test_template_is_disarmed_and_build_manifest_matches(self):
        if not (ROOT / "research/test079-next-boot-private.json").is_file():
            self.skipTest("Private hardware metadata is intentionally excluded")
        metadata = json.loads(
            (ROOT / 'research/test079-next-boot-private.json').read_text())
        self.assertFalse(metadata['installed'])
        self.assertFalse(metadata['reboot_ready'])
        self.assertFalse(metadata['armed'])
        self.assertFalse(metadata['hardware_tested'])
        self.assertEqual(metadata['maximum_rf_sessions_per_boot'], 1)
        self.assertEqual(metadata['maximum_qm_submissions'], 1)
        self.assertEqual(metadata['diagnostic_duration_ms'], 900)
        frozen = json.loads(
            (ROOT / 'research/test079-prebuild-source-private.json').read_text())
        self.assertEqual(metadata['source_sha256'], frozen['source_sha256'])
        self.assertGreater(len(metadata['source_sha256']), 0)
        problems = MODULE.test079_metadata_problems(
            metadata, '25G332-Test079', root=ROOT)
        self.assertIn('installed', problems)
        self.assertIn('reboot_ready', problems)
        self.assertIn('armed', problems)
        self.assertIn('previous_boot_epoch', problems)
        self.assertIn('runtime_boot_epoch', problems)
        self.assertNotIn('build_identity_or_frozen_manifest', problems)
        self.assertNotIn('source_manifest_mismatch', problems)

    def test_default_invocation_stops_before_live_reads_or_filesystem(self):
        argv = [
            'capture_test079_resident_data_once.py',
            '--expect-build', '25G332-Test079',
            '--phone-ready',
            '--native-browser-active',
            '--router-observation-id', 'offline-gate-check',
            '--receiver-gated',
        ]
        with patch.object(sys, 'argv', argv), \
             patch.object(MODULE.signal, 'signal'), \
             patch.object(MODULE.subprocess, 'check_output') as live_read, \
             patch.object(Path, 'read_text') as filesystem_read, \
             patch.object(MODULE, 'properties') as properties, \
             patch.object(MODULE, 'loaded_identity') as identity:
            with self.assertRaisesRegex(SystemExit, 'disarmed by default'):
                MODULE.main()
        live_read.assert_not_called()
        filesystem_read.assert_not_called()
        properties.assert_not_called()
        identity.assert_not_called()

    def test_claim_is_consumed_once_and_never_allows_same_boot_retry(self):
        with tempfile.TemporaryDirectory(prefix='test079-claim-') as temp:
            claim_dir = Path(temp) / 'ObservationClaims/BootGlobal'
            claim = MODULE.claim_boot_attempt(
                claim_dir, 1234567890, 'offline-gate-check')
            content = json.loads(claim.read_text())
            self.assertEqual(content['test_scope'], 'Test079')
            self.assertEqual(content['build'], '25G332-Test079')
            self.assertTrue(content['attempt_consumed'])
            self.assertFalse(content['retry_allowed'])
            with self.assertRaises(FileExistsError):
                MODULE.claim_boot_attempt(
                    claim_dir, 1234567890, 'different-output-label')

    def test_prior_test077_claim_is_a_read_only_blocker(self):
        with tempfile.TemporaryDirectory(prefix='test079-legacy-claim-') as temp:
            claim_dir = Path(temp) / 'ObservationClaims/BootGlobal'
            legacy = claim_dir.parent / 'Test077' / 'boot-1234567891.json'
            legacy.parent.mkdir(parents=True)
            legacy.write_text('{}')
            with self.assertRaises(FileExistsError):
                MODULE.claim_boot_attempt(
                    claim_dir, 1234567891, 'offline-gate-check')
            self.assertTrue(legacy.exists())
            self.assertFalse(claim_dir.exists())


if __name__ == '__main__':
    unittest.main()
