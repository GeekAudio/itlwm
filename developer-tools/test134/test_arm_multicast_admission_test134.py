#!/usr/bin/env python3
"""Offline compile and argument-rejection checks; never reads IOKit or arms."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import json


SOURCE = Path(__file__).with_name("arm_multicast_admission.swift")
VALID_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"


class ArmMulticastAdmissionCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="test134-arm-cli-",
                                               dir="/private/tmp")
        cls.binary = Path(cls.temp.name) / "arm_multicast_admission"
        subprocess.run([
            "/usr/bin/swiftc", "-warnings-as-errors", "-O", str(SOURCE),
            "-framework", "IOKit", "-o", str(cls.binary),
        ], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_rejected(self, *arguments):
        return subprocess.run([str(self.binary), *arguments],
                              capture_output=True, text=True, timeout=5)

    def test_wrong_candidate_rejected_before_iokit(self):
        result = self.run_rejected("--expect-build", "25G416-Test133",
                                   "--expect-uuid", VALID_UUID, "--arm")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Expected build must be 25G416-Test134", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_malformed_uuid_rejected_before_iokit(self):
        result = self.run_rejected("--expect-build", "25G416-Test134",
                                   "--expect-uuid", "not-a-uuid", "--arm")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Expected UUID must be uppercase Mach-O UUID", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_unknown_arm_switch_rejected_before_iokit(self):
        result = self.run_rejected("--expect-build", "25G416-Test134",
                                   "--expect-uuid", VALID_UUID, "--force")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Only --arm is accepted", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_missing_identity_arguments_rejected_before_iokit(self):
        result = self.run_rejected("--arm")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_pure_success_prepare_abort_failure_and_unknown_cases(self):
        result = self.run_rejected("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "self_test_passed")
        self.assertIn("prepare_abort_changes_allowed", report["cases"])
        self.assertIn("missing_legacy_counters_use_explicit_gate", report["cases"])
        self.assertIn("present_invalid_legacy_counter_rejected", report["cases"])
        self.assertIn("missing_serial_is_not_terminal", report["cases"])
        self.assertIn("nonzero_legacy_counter_blocks_success", report["cases"])
        self.assertIn("failed_operation_cleanup", report["cases"])
        self.assertIn("missing_is_unknown", report["cases"])
        self.assertIn("ack_identity_mismatch", report["cases"])
        self.assertEqual(report["queue_serial_round_trip"], (1 << 63) | 9)
        self.assertFalse(report["hardware_actions"])


if __name__ == "__main__":
    unittest.main()
