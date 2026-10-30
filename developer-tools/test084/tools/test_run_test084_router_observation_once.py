#!/usr/bin/env python3
"""Offline protocol and topology tests for Test084's OpenWrt coordinator."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    'run_test084_router_observation_once',
    ROOT / 'tools/run_test084_router_observation_once.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Test084CoordinatorTests(unittest.TestCase):
    def test_default_only_describes_plan_without_launching_or_reading_system(self):
        with patch.object(sys, 'argv', ['run_test084_router_observation_once.py']), \
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
        summary = json.loads(output.getvalue())
        self.assertFalse(summary['capture_started'])
        self.assertFalse(summary['native_rx149_arm_started'])
        self.assertEqual(summary['receiver_channel'], 149)
        self.assertEqual(summary['native_trigger_ms'], 100)

    def test_receiver_is_wlan1_ch149_and_never_requests_retune(self):
        args = MODULE.receiver_capture_args(
            '/usr/bin/python3', 'root@router.invalid',
            '/tmp/openwrt-control.sock', ROOT / 'receiver-private')
        ap_values = [args[i + 1] for i, value in enumerate(args) if value == '--ap']
        expected = [args[i + 1] for i, value in enumerate(args) if value == '--expect-ap']
        self.assertEqual(ap_values, ['wlan0', 'wlan1'])
        self.assertEqual(expected, [
            'wlan0:0:6:2437:20', 'wlan1:1:149:5745:80'])
        self.assertEqual(args[args.index('--interface') + 1], 'wlan1')
        self.assertEqual(args[args.index('--monitor') + 1], 'iwawdl0')
        self.assertEqual(args[args.index('--duration') + 1], '20')
        self.assertEqual(args[args.index('--max-packets') + 1], '4096')
        self.assertNotIn('--channel', args)
        self.assertNotIn('--frequency', args)
        self.assertNotIn('--retune', args)

    def test_fence_consumes_one_ready_token_only(self):
        token = '0123456789abcdef0123456789abcdef'
        ready = 'READY ' + token + ' window_seconds=20 link_type=127'
        fence = MODULE.StartFence()
        called = []
        self.assertEqual(fence.release(ready, lambda: called.append(True)),
                         (token, None))
        with self.assertRaises(ValueError):
            fence.release(ready, lambda: called.append(True))
        self.assertEqual(called, [True])

    def test_receiver_result_requires_unchanged_ap_state_and_removed_monitor(self):
        token = '0123456789abcdef0123456789abcdef'
        result = {'schema_version': 1, 'cancelled': False,
                  'monitor_removed': True, 'state_unchanged': True,
                  'ready_token': token, 'tcpdump_exit_code': 0}
        self.assertTrue(MODULE.receiver_result_healthy(result, token))
        self.assertFalse(MODULE.receiver_result_healthy(
            dict(result, state_unchanged=False), token))
        self.assertFalse(MODULE.receiver_result_healthy(
            dict(result, monitor_removed=False), token))
        self.assertFalse(MODULE.receiver_result_healthy(
            dict(result, tcpdump_exit_code=True), token))

    def test_no_old_test079_collector_or_tx_profile_invocation(self):
        source = (ROOT / 'tools/run_test084_router_observation_once.py').read_text()
        self.assertIn('capture_test084_receive149_once.py', source)
        self.assertNotIn('capture_test079_resident_data_once.py', source)
        self.assertIn("'--receiver-gated'", source)
        self.assertIn("'--phone-ready'", source)

    def test_disarmed_metadata_stops_before_boot_query_or_openwrt(self):
        argv = ['run_test084_router_observation_once.py', '--run', '--phone-ready',
                '--host', 'router.invalid', '--control-path', '/tmp/control.sock',
                '--observation-id', 't084-test']
        with patch.object(sys, 'argv', argv), \
             patch.object(MODULE.os, 'geteuid', return_value=0), \
             patch.object(MODULE.subprocess, 'Popen') as popen, \
             patch.object(MODULE, 'load_capture') as load_capture:
            capture = type('Capture', (), {
                'fresh_observation_id': staticmethod(lambda value: True),
                '_load_metadata': staticmethod(lambda: {'armed': False}),
                '_sysctl_boot_epoch': staticmethod(lambda: self.fail('boot read after disarm')),
            })()
            load_capture.return_value = capture
            with self.assertRaisesRegex(SystemExit, 'metadata is disarmed'):
                MODULE.main()
        popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
