from __future__ import annotations

import sys
import time
import unittest
from unittest import mock

import controlled_run_test104 as run


class _FakePipe:
    def __init__(self, lines=()):
        self.lines = list(lines)
        self.timeouts = []

    def read_line(self, timeout):
        self.timeouts.append(timeout)
        return self.lines.pop(0) if self.lines else None


class NativeTerminalWaitTests(unittest.TestCase):
    def _real_native_pipe(self, child_source):
        argv = [sys.executable, "-c", child_source, str(run.NATIVE_WORKER)]
        return run._test104_managed_pipe(argv, run.BASE.ManagedPipe)

    def test_real_managed_pipe_allows_terminal_past_original_timeout(self):
        child = r"""
import json, sys, time
print('NATIVE_READY ' + json.dumps({'event':'NATIVE_READY'}), flush=True)
print('NATIVE_ARM_RESULT ' + json.dumps({'event':'NATIVE_ARM_RESULT'}), flush=True)
time.sleep(0.35)
print('NATIVE_RESULT ' + json.dumps({'event':'NATIVE_RESULT'}), flush=True)
"""
        with mock.patch.object(run, "NATIVE_FINAL_RESULT_TIMEOUT_SECONDS", 0.8):
            pipe = self._real_native_pipe(child)
            self.addCleanup(pipe.terminate)

            start = time.monotonic()
            ready = pipe.read_line(0.4)
            self.assertTrue(ready.startswith("NATIVE_READY "))
            self.assertLess(time.monotonic() - start, 0.4)

            start = time.monotonic()
            armed = pipe.read_line(0.4)
            self.assertTrue(armed.startswith("NATIVE_ARM_RESULT "))
            self.assertLess(time.monotonic() - start, 0.4)

            start = time.monotonic()
            terminal = pipe.read_line(0.1)  # the historical caller budget
            terminal_delay = time.monotonic() - start
            self.assertTrue(terminal.startswith("NATIVE_RESULT "))
            self.assertGreater(terminal_delay, 0.1)
            self.assertLess(terminal_delay, 0.8)
            self.assertEqual(pipe.process.wait(timeout=1.0), 0)

    def test_terminal_timeout_remains_bounded_and_fail_closed(self):
        child = r"""
import json, time
print('NATIVE_READY ' + json.dumps({'event':'NATIVE_READY'}), flush=True)
print('NATIVE_ARM_RESULT ' + json.dumps({'event':'NATIVE_ARM_RESULT'}), flush=True)
time.sleep(0.6)
print('NATIVE_RESULT ' + json.dumps({'event':'NATIVE_RESULT'}), flush=True)
"""
        with mock.patch.object(run, "NATIVE_FINAL_RESULT_TIMEOUT_SECONDS", 0.15):
            pipe = self._real_native_pipe(child)
            self.addCleanup(pipe.terminate)
            self.assertTrue(pipe.read_line(0.4).startswith("NATIVE_READY "))
            self.assertTrue(pipe.read_line(0.4).startswith("NATIVE_ARM_RESULT "))
            started = time.monotonic()
            with self.assertRaises(run.BASE.CoordinatorError) as error:
                pipe.read_line(0.05)
            elapsed = time.monotonic() - started
            self.assertEqual(error.exception.code, "CHILD_PROTOCOL_TIMEOUT")
            self.assertGreaterEqual(elapsed, 0.12)
            self.assertLess(elapsed, 0.4)

    def test_only_next_native_read_after_arm_result_is_extended(self):
        fake = _FakePipe([
            "NATIVE_READY {}", "NATIVE_ARM_RESULT {}", "NATIVE_RESULT {}",
        ])
        with mock.patch.object(run, "NATIVE_FINAL_RESULT_TIMEOUT_SECONDS", 0.75):
            wrapped = run._test104_managed_pipe(
                ["/usr/bin/python3", str(run.NATIVE_WORKER)], lambda _argv: fake)
            self.assertIsNot(wrapped, fake)
            self.assertEqual(wrapped.read_line(0.1), "NATIVE_READY {}")
            self.assertEqual(wrapped.read_line(0.2), "NATIVE_ARM_RESULT {}")
            self.assertEqual(wrapped.read_line(0.3), "NATIVE_RESULT {}")
        self.assertEqual(fake.timeouts, [0.1, 0.2, 0.75])

    def test_listener_pipe_and_timeout_are_unchanged(self):
        fake = _FakePipe(["LISTENER_READY"])
        previous = run.ACTIVE_LISTENER_EXPECTATION
        run.ACTIVE_LISTENER_EXPECTATION = {
            "source_ipv6": "fe80::1", "destination_ipv6": "fe80::2",
            "ifindex": 7,
        }
        try:
            argv = ["/tmp/awdl0_udp_probe_listener", "--listen",
                    run.LISTENER_PROTOCOL.MARKER, "--run-token", "token"]
            received_argv = []

            def factory(adapted):
                received_argv.extend(adapted)
                return fake

            pipe = run._test104_managed_pipe(argv, factory)
            self.assertIs(pipe, fake)
            self.assertEqual(pipe.read_line(0.125), "LISTENER_READY")
            self.assertEqual(fake.timeouts, [0.125])
            self.assertEqual(received_argv[-6:], [
                "--expected-source-ipv6", "fe80::1",
                "--expected-destination-ipv6", "fe80::2",
                "--expected-ifindex", "7",
            ])
        finally:
            run.ACTIVE_LISTENER_EXPECTATION = previous


if __name__ == "__main__":
    unittest.main()
