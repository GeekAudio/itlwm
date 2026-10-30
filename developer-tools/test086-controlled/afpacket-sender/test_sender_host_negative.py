#!/usr/bin/env python3
"""Negative and dry-run tests for the host-only sender build; never opens a socket."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / 'fixtures' / 'probe-spec.json'
NONCE = '0123456789abcdef0123456789abcdef'
TEST_BINARY: Path | None = None


class SenderHostNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if TEST_BINARY is None:
            raise RuntimeError('host-test binary path required')
        cls.binary = TEST_BINARY
        if not cls.binary.is_file():
            raise RuntimeError('host-test binary missing')

    def run_sender(self, args=(), stdin=''):
        return subprocess.run(
            [str(self.binary), *args], input=stdin, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
            check=False)

    def run_live_gate(self, args, gate_lines, close_after=False):
        process = subprocess.Popen(
            [str(self.binary), *args], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1)
        ready = process.stdout.readline()
        if close_after:
            process.stdin.write(gate_lines)
            process.stdin.flush()
            process.stdin.close()
        else:
            process.stdin.write(gate_lines)
            process.stdin.flush()
        result_line = process.stdout.readline()
        process.wait(timeout=3)
        stderr = process.stderr.read()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        return process.returncode, ready, result_line, stderr

    def send_args(self, *extra):
        return [
            '--send', '--interface', 'mon0', '--nonce', NONCE, '--wait-go',
            *extra,
        ]

    def test_embedded_frame_matches_approved_spec_without_addresses_in_output(self):
        source = (HERE / 'awdl_probe_sender.c').read_text()
        spec = json.loads(SPEC_PATH.read_text())
        def array(name):
            match = re.search(
                r'static const uint8_t ' + re.escape(name) +
                r'\[[^]]+\] = \{(.*?)\};', source, re.S)
            self.assertIsNotNone(match, name)
            return bytes(int(value, 16) for value in
                         re.findall(r'0x([0-9a-fA-F]{2})', match.group(1)))
        self.assertEqual(array('mpdu_base'), bytes.fromhex(spec['mpdu_hex']))
        self.assertEqual(array('radiotap_base'), bytes.fromhex(spec['radiotap_hex']))
        self.assertEqual(len(array('mpdu_base')), 96)
        self.assertEqual(len(array('radiotap_base')), 10)
        run = self.run_sender(['--count', '3', '--interval-ms', '80'])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('mode=dry-run frames=3 interval_ms=80', run.stdout)
        self.assertIn('frame=1 wifi_seq=291 awdl_seq=34305 bytes=106', run.stdout)
        self.assertIn('frame=2 wifi_seq=292 awdl_seq=34306 bytes=106', run.stdout)
        self.assertIn('frame=3 wifi_seq=293 awdl_seq=34307 bytes=106', run.stdout)
        for token in ('33:33', '02:86', '00:25', 'T086RX01', 'ff02::1', 'fe80::'):
            self.assertNotIn(token, run.stdout + run.stderr)

    def test_default_invocation_is_dry_run_and_never_sends(self):
        run = self.run_sender()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('mode=dry-run frames=16 interval_ms=80', run.stdout)
        self.assertIn('frames=16 interval_ms=80', run.stdout)
        self.assertEqual(run.stdout.count('frame='), 16)
        self.assertNotIn('READY', run.stdout)
        self.assertNotIn('SENDER_RESULT', run.stdout)

    def test_send_requires_explicit_interface_nonce_and_gate(self):
        for args in (
            ['--send'],
            ['--send', '--interface', 'mon0'],
            ['--send', '--nonce', NONCE, '--wait-go'],
            ['--send', '--interface', 'mon0', '--nonce', NONCE],
            self.send_args('--nonce', NONCE),
            ['--nonce', NONCE],
            ['--wait-go'],
        ):
            with self.subTest(args=args):
                run = self.run_sender(args)
                self.assertEqual(run.returncode, 2)
                self.assertIn('invalid_arguments', run.stderr)
                self.assertNotIn('READY', run.stdout)

    def test_frame_count_interval_interface_and_nonce_bounds_are_strict(self):
        invalid = (
            ['--count', '0'], ['--count', '17'], ['--count', '-1'],
            ['--count', '1x'], ['--count', '1', '--count', '2'],
            ['--interval-ms', '-1'], ['--interval-ms', '81'],
            ['--interval-ms', '5x'], ['--interval-ms', '1', '--interval-ms', '2'],
            ['--interface', 'name-too-long-123'], ['--interface', 'mon/0'],
            ['--interface', 'mon0', '--interface', 'mon1'],
        )
        for extra in invalid:
            with self.subTest(extra=extra):
                run = self.run_sender(extra)
                self.assertEqual(run.returncode, 2)
                self.assertIn('invalid_arguments', run.stderr)
        for nonce in ('A' * 32, 'g' * 32, 'a' * 31, 'a' * 33):
            with self.subTest(nonce=nonce):
                run = self.run_sender(['--send', '--interface', 'mon0',
                                       '--nonce', nonce, '--wait-go'])
                self.assertEqual(run.returncode, 2)
                self.assertNotIn('READY', run.stdout)

    def test_abort_before_go_reports_zero_frames_and_no_send(self):
        run = self.run_sender(self.send_args(), stdin='ABORT\n')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('READY frames=16 interval_ms=80 mpdu_bytes=96', run.stdout)
        lines = [line for line in run.stdout.splitlines()
                 if line.startswith('{"event":"SENDER_RESULT"')]
        self.assertEqual(len(lines), 1)
        result = json.loads(lines[0])
        self.assertEqual(result['status'], 'aborted')
        self.assertEqual(result['frames_attempted'], 0)
        self.assertEqual(result['frames_completed'], 0)
        self.assertEqual(result['sent'], 0)
        self.assertEqual(result['error_count'], 0)
        self.assertEqual(result['stop_reason'], 'aborted_before_go')
        self.assertNotIn('T086RX01', run.stdout + run.stderr)

    def test_eof_or_invalid_nonce_before_go_fails_closed_with_zero_frames(self):
        for input_text in ('', 'GO ffffffffffffffffffffffffffffffff\n',
                           'GO 0123456789abcdef0123456789abcdef EXTRA\n'):
            with self.subTest(input_text=input_text):
                run = self.run_sender(self.send_args(), stdin=input_text)
                self.assertEqual(run.returncode, 3)
                lines = [line for line in run.stdout.splitlines()
                         if line.startswith('{"event":"SENDER_RESULT"')]
                self.assertEqual(len(lines), 1)
                result = json.loads(lines[0])
                self.assertEqual(result['frames_attempted'], 0)
                self.assertEqual(result['sent'], 0)
                self.assertGreaterEqual(result['error_count'], 1)

    def test_host_build_hard_disables_send_even_after_valid_go(self):
        code, ready, result_line, stderr = self.run_live_gate(
            self.send_args('--count', '1', '--interval-ms', '0'),
            gate_lines=f'GO {NONCE}\n')
        self.assertEqual(code, 6, stderr)
        self.assertTrue(ready.startswith('READY '))
        result = json.loads(result_line)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['stop_reason'], 'host_test_send_disabled')
        self.assertEqual(result['frames_attempted'], 0)
        self.assertEqual(result['sent'], 0)

    def test_duplicate_go_aborts_before_any_packet_and_reports_zero(self):
        code, ready, result_line, stderr = self.run_live_gate(
            self.send_args(), gate_lines=f'GO {NONCE}\nGO {NONCE}\n')
        self.assertEqual(code, 5, stderr)
        self.assertTrue(ready.startswith('READY '))
        result = json.loads(result_line)
        self.assertEqual(result['frames_attempted'], 0)
        self.assertEqual(result['frames_completed'], 0)
        self.assertEqual(result['sent'], 0)
        self.assertEqual(result['stop_reason'], 'post_go_control_or_stdin_closed')

    def test_eof_or_abort_after_go_stops_before_any_host_packet(self):
        for control, close_after in (('', True), ('ABORT\n', False)):
            with self.subTest(control=control, close_after=close_after):
                code, ready, result_line, stderr = self.run_live_gate(
                    self.send_args(), gate_lines=f'GO {NONCE}\n' + control,
                    close_after=close_after)
                self.assertEqual(code, 5, stderr)
                self.assertTrue(ready.startswith('READY '))
                result = json.loads(result_line)
                self.assertEqual(result['frames_attempted'], 0)
                self.assertEqual(result['sent'], 0)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: test_sender_host_negative.py HOST_TEST_BINARY')
    TEST_BINARY = Path(sys.argv[1]).resolve()
    unittest.main(argv=[sys.argv[0]])
