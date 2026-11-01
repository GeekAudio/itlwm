#!/usr/bin/env python3
"""Targeted host fixture for the result/provenance struct alias."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


NONCE = "0123456789abcdef0123456789abcdef"
BINARY: Path | None = None


class ProvenanceCaptureAliasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if BINARY is None or not BINARY.is_file():
            raise RuntimeError("alias-test binary path required")
        cls.binary = BINARY

    def test_capture_state_survives_send_result_zeroing(self):
        process = subprocess.Popen(
            [str(self.binary), "--send", "--interface", "mon0", "--nonce",
             NONCE, "--wait-go"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self.assertTrue(process.stdout.readline().startswith("READY "))
        process.stdin.write(f"GO {NONCE}\n")
        process.stdin.flush()
        started = json.loads(process.stdout.readline())
        result = json.loads(process.stdout.readline())
        process.wait(timeout=3)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr.read(), "")
        self.assertEqual(result["status"], "complete")
        capture = result["tx_provenance"]["capture"]
        self.assertEqual(capture["status"], "bounded_during_send_sequence")
        self.assertTrue(capture["complete"])
        self.assertTrue(capture["pre_send_queue_empty"])
        self.assertIsInstance(capture["started_ns"], int)
        self.assertIsInstance(capture["ended_ns"], int)
        self.assertGreaterEqual(capture["started_ns"], started["started_ns"])
        self.assertGreaterEqual(capture["ended_ns"], capture["started_ns"])
        self.assertLessEqual(capture["ended_ns"] - capture["started_ns"],
                             capture["budget_ns"])
        self.assertEqual(result["tx_provenance"]["pid_cookie_bound_tx_status"],
                         "unknown")
        self.assertFalse(result["tx_provenance"]["rf_transmission_proven"])
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_provenance_capture_alias_test100.py BINARY")
    BINARY = Path(sys.argv.pop()).resolve()
    unittest.main(argv=[sys.argv[0]])
