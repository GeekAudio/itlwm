#!/usr/bin/env python3
"""Offline default-disarmed and explicit-arm checks for the Test079 coordinator."""

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    'run_test079_router_observation_once',
    ROOT / 'tools/run_test079_router_observation_once.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Test079CoordinatorSafetyTests(unittest.TestCase):
    def test_default_is_offline_description_without_children_or_rf(self):
        with patch.object(sys, 'argv', ['run_test079_router_observation_once.py']), \
             patch.object(MODULE.subprocess, 'Popen') as popen, \
             patch.object(MODULE.subprocess, 'run') as run, \
             patch.object(MODULE.subprocess, 'check_output') as check_output:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = MODULE.main()
        self.assertEqual(result, 0)
        self.assertFalse(popen.called)
        self.assertFalse(run.called)
        self.assertFalse(check_output.called)
        self.assertFalse(__import__('json').loads(output.getvalue())['capture_started'])
        self.assertEqual(MODULE.BUILD, '25G332-Test079')
        self.assertEqual(
            MODULE.RECEIVER_OUTPUT_PARENT.name,
            'test079-router-runtime-private')

    def test_explicit_run_path_passes_arm_only_to_test079_collector(self):
        source = (ROOT / 'tools/run_test079_router_observation_once.py').read_text()
        self.assertIn("parser.add_argument('--run',action='store_true')", source)
        self.assertIn("'--expect-build',BUILD,'--arm','--phone-ready'", source)
        self.assertIn("capture_test079_resident_data_once.py", source)
        self.assertNotIn('capture_test077_resident_data_once.py', source)


if __name__ == '__main__':
    unittest.main()
