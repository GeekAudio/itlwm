#!/usr/bin/env python3
"""CLI and fail-closed checks for the host-only AF_PACKET sender build."""
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

    def run_sender(self, args=(), stdin=''):
        return subprocess.run([str(self.binary), *args], input=stdin, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=3, check=False)

    def send_args(self, *extra):
        return ['--send', '--interface', 'mon0', '--nonce', NONCE, '--wait-go', *extra]

    def test_packet_stays_byte_identical_and_dry_run_hides_addresses(self):
        source = (HERE / 'awdl_probe_sender.c').read_text()
        spec = json.loads(SPEC_PATH.read_text())
        def array(name):
            match = re.search(r'static const uint8_t ' + re.escape(name) +
                              r'\[[^]]+\] = \{(.*?)\};', source, re.S)
            self.assertIsNotNone(match, name)
            return bytes(int(value, 16) for value in re.findall(
                r'0x([0-9a-fA-F]{2})', match.group(1)))
        self.assertEqual(array('mpdu_base'), bytes.fromhex(spec['mpdu_hex']))
        self.assertEqual(array('radiotap_base'), bytes.fromhex(spec['radiotap_hex']))
        result = self.run_sender(['--count', '2'])
        self.assertEqual(result.returncode, 0, result.stderr)
        for token in ('33:33', '02:86', '00:25', 'T086RX01', 'ff02::1', 'fe80::'):
            self.assertNotIn(token, result.stdout + result.stderr)

    def test_invalid_send_controls_fail_before_ready(self):
        for args in (['--send'], ['--send', '--interface', 'mon0'],
                     ['--send', '--nonce', NONCE, '--wait-go'],
                     ['--send', '--interface', 'mon0', '--nonce', NONCE],
                     ['--wait-go'], ['--nonce', NONCE]):
            with self.subTest(args=args):
                result = self.run_sender(args)
                self.assertEqual(result.returncode, 2)
                self.assertIn('invalid_arguments', result.stderr)
                self.assertNotIn('READY', result.stdout)

    def test_abort_and_host_send_disabled_leave_slots_unattempted(self):
        aborted = self.run_sender(self.send_args(), stdin='ABORT\n')
        self.assertEqual(aborted.returncode, 0, aborted.stderr)
        self.assertFalse(any(line.startswith('{"event":"SENDER_STARTED"')
                             for line in aborted.stdout.splitlines()))
        result = json.loads(next(line for line in aborted.stdout.splitlines()
                                 if line.startswith('{"event":"SENDER_RESULT"')))
        self.assertEqual(result['frames_requested'], 16)
        self.assertEqual(result['frames_attempted'], 0)
        self.assertNotIn('timing_schema', result)
        self.assertNotIn('send_timing', result)

        process = subprocess.Popen([str(self.binary), *self.send_args()],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, bufsize=1)
        self.assertTrue(process.stdout.readline().startswith('READY '))
        process.stdin.write(f'GO {NONCE}\n')
        process.stdin.flush()
        line = process.stdout.readline()
        process.wait(timeout=3)
        self.assertEqual(process.returncode, 6)
        result = json.loads(line)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(result['frames_attempted'], 0)
        self.assertNotIn('timing_schema', result)
        self.assertNotIn('send_timing', result)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: test_sender_host_negative.py BINARY')
    TEST_BINARY = Path(sys.argv[1]).resolve()
    unittest.main(argv=[sys.argv[0]])
