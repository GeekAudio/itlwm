#!/usr/bin/env python3
"""Deterministic simulated-send tests; this binary has no packet socket."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

NONCE = '0123456789abcdef0123456789abcdef'
TEST_BINARY: Path | None = None


class SenderTimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if TEST_BINARY is None or not TEST_BINARY.is_file():
            raise RuntimeError('timing-test binary path required')
        cls.binary = TEST_BINARY

    def run_sender(self, fail_at=None, clock_fail_stage=None, sleep_error=None):
        env = os.environ.copy()
        env.pop('SENDER_TIMING_TEST_FAIL_AT', None)
        env.pop('SENDER_TIMING_TEST_CLOCK_FAIL_STAGE', None)
        env.pop('SENDER_TIMING_TEST_SLEEP_ERROR', None)
        if fail_at is not None:
            env['SENDER_TIMING_TEST_FAIL_AT'] = str(fail_at)
        if clock_fail_stage is not None:
            env['SENDER_TIMING_TEST_CLOCK_FAIL_STAGE'] = clock_fail_stage
        if sleep_error is not None:
            env['SENDER_TIMING_TEST_SLEEP_ERROR'] = str(sleep_error)
        process = subprocess.Popen(
            [str(self.binary), '--send', '--interface', 'mon0', '--nonce',
             NONCE, '--wait-go'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, env=env)
        self.assertTrue(process.stdout.readline().startswith('READY '))
        process.stdin.write(f'GO {NONCE}\n')
        process.stdin.flush()
        started_line = process.stdout.readline()
        started = json.loads(started_line)
        self.assertEqual(started['event'], 'SENDER_STARTED')
        self.assertEqual(started['timing_schema'], 1)
        self.assertEqual(started['clock_domain'], 'CLOCK_MONOTONIC')
        result_line = process.stdout.readline()
        process.wait(timeout=3)
        stderr = process.stderr.read()
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        self.assertFalse(stderr, stderr)
        return process.returncode, json.loads(result_line), started

    def test_sixteen_synthetic_writes_have_ordered_per_call_samples(self):
        code, result, started = self.run_sender()
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['frames_requested'], 16)
        self.assertEqual(result['frames_attempted'], 16)
        self.assertEqual(result['frames_completed'], 16)
        self.assertEqual(result['timing_schema'], 1)
        self.assertEqual(result['clock_domain'], 'CLOCK_MONOTONIC')
        self.assertEqual(result['go_received_ns'], started['go_received_ns'])
        self.assertEqual(result['started_ns'], started['started_ns'])
        self.assertLessEqual(result['go_received_ns'], result['started_ns'])
        self.assertLessEqual(result['started_ns'], result['finished_ns'])
        self.assertEqual(len(result['send_timing']), 16)
        for index, row in enumerate(result['send_timing']):
            self.assertEqual(row['ordinal'], index)
            self.assertEqual(row['ieee80211_sequence'], (291 + index) & 0x0fff)
            self.assertEqual(row['awdl_sequence'], (34305 + index) & 0xffff)
            self.assertIsInstance(row['before_ns'], int)
            self.assertIsInstance(row['after_ns'], int)
            self.assertLessEqual(result['started_ns'], row['before_ns'])
            self.assertLessEqual(row['before_ns'], row['after_ns'])
            self.assertLessEqual(row['after_ns'], result['finished_ns'])
            self.assertEqual(row['return_bytes'], 106)
            self.assertEqual(row['errno'], 0)
            if index:
                self.assertLess(result['send_timing'][index - 1]['before_ns'],
                                row['before_ns'])
        self.assertGreaterEqual(result['send_timing'][1]['before_ns'] -
                                result['started_ns'], 80000000)
        for secret in ('T086RX01', '33:33', '00:25', 'fe80::', 'ff02::1'):
            self.assertNotIn(secret, json.dumps(result))

    def test_failed_write_records_only_actual_attempts(self):
        code, result, _started = self.run_sender(fail_at=4)
        self.assertEqual(code, 5)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['frames_requested'], 16)
        self.assertEqual(result['frames_attempted'], 4)
        self.assertEqual(result['frames_completed'], 3)
        self.assertEqual(result['stop_reason'], 'send_errno')
        rows = result['send_timing']
        self.assertEqual(len(rows), result['frames_attempted'])
        self.assertEqual([row['ordinal'] for row in rows], [0, 1, 2, 3])
        self.assertEqual(rows[3]['return_bytes'], -1)
        self.assertEqual(rows[3]['errno'], 5)
        self.assertEqual(rows[3]['ieee80211_sequence'], (291 + 3) & 0x0fff)

    def test_before_clock_failure_is_not_misreported_as_budget_expiry(self):
        code, result, _started = self.run_sender(clock_fail_stage='before')
        self.assertEqual(code, 5)
        self.assertEqual(result['frames_attempted'], 0)
        self.assertEqual(result['send_timing'], [])
        self.assertFalse(result['deadline_hit'])
        self.assertEqual(result['stop_reason'], 'monotonic_clock_before_failed')
        self.assertEqual(result['last_errno'], 5)

    def test_after_clock_failure_preserves_send_without_claiming_budget_expiry(self):
        code, result, _started = self.run_sender(clock_fail_stage='after')
        self.assertEqual(code, 5)
        self.assertEqual(result['frames_attempted'], 1)
        self.assertEqual(result['frames_completed'], 1)
        self.assertFalse(result['deadline_hit'])
        self.assertEqual(result['stop_reason'], 'monotonic_clock_after_failed')
        self.assertIsNone(result['send_timing'][0]['after_ns'])
        self.assertEqual(result['send_timing'][0]['return_bytes'], 106)
        self.assertEqual(result['send_timing'][0]['errno'], 0)

    def test_finish_clock_failure_is_null_and_keeps_sent_rows(self):
        code, result, _started = self.run_sender(clock_fail_stage='finish')
        self.assertEqual(code, 5)
        self.assertEqual(result['frames_attempted'], 16)
        self.assertEqual(len(result['send_timing']), 16)
        self.assertFalse(result['deadline_hit'])
        self.assertEqual(result['stop_reason'], 'monotonic_clock_end_failed')
        self.assertIsNone(result['finished_ns'])
        self.assertIsNone(result['elapsed_ms'])

    def test_sleep_error_code_is_preserved_without_deadline_claim(self):
        code, result, _started = self.run_sender(sleep_error=22)
        self.assertEqual(code, 5)
        self.assertEqual(result['frames_attempted'], 1)
        self.assertEqual(result['frames_completed'], 1)
        self.assertFalse(result['deadline_hit'])
        self.assertEqual(result['stop_reason'], 'schedule_sleep_error')
        self.assertEqual(result['last_errno'], 22)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: test_sender_timing.py BINARY')
    TEST_BINARY = Path(sys.argv[1]).resolve()
    unittest.main(argv=[sys.argv[0]])
