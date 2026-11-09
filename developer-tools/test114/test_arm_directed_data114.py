#!/usr/bin/env python3
"""No-run contract checks for the compiled Test114 helper."""
import json
import os
import subprocess
import unittest


HELPER = os.environ.get("ARM_DIRECTED_DATA_HELPER")
UUID = "00000000-0000-4000-8000-000000000001"
TOKEN = "0102030405060708090a0b0c0d0e0f10"


class ArmDirectedData114PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HELPER:
            raise RuntimeError("Set ARM_DIRECTED_DATA_HELPER to the compiled helper")

    def invoke(self, *, build="25G332-Test114", peer_ipv6=True, ready_file=True):
        args = [
            HELPER,
            "--expect-build", build,
            "--expect-uuid", UUID,
            "--peer-mac", "02:00:00:00:00:02",
            "--local-ipv6", "fe80::1",
            "--nonce", "0102030405060708",
            "--run-token", TOKEN,
        ]
        if peer_ipv6:
            args += ["--peer-ipv6", "fe80::2"]
        if ready_file:
            args += ["--peer-ready-file", "/must-not-be-read.json"]
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def test_test114_plan_is_matched_return_and_one_shot(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["build"], "25G332-Test114")
        self.assertTrue(payload["peer_ready_required"])
        self.assertFalse(payload["peer_ready_file_read"])
        self.assertEqual(payload["native_udp_count"], 1)
        self.assertEqual(payload["matched_return_capture_max_ms"], 100)
        self.assertTrue(payload["rx_lease_poll_within_original_window"])
        self.assertEqual(payload["rx_lease_max_checks"], 128)
        self.assertFalse(payload["hardware_action"])
        self.assertFalse(payload["airdrop_proven"])

    def test_test114_requires_both_fresh_peer_inputs(self):
        for kwargs in ({"peer_ipv6": False}, {"ready_file": False}):
            with self.subTest(kwargs=kwargs):
                result = self.invoke(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["phase"], "arguments")
                self.assertFalse(payload["arm_may_have_changed"])
                self.assertFalse(payload["native_udp_attempted"])

    def test_test126_plan_uses_the_matched_return_rx_lease_path(self):
        result = self.invoke(build="25G416-Test126")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["build"], "25G416-Test126")
        self.assertTrue(payload["peer_ready_required"])
        self.assertEqual(payload["native_udp_count"], 1)
        self.assertEqual(payload["matched_return_capture_max_ms"], 100)
        self.assertTrue(payload["rx_lease_poll_within_original_window"])
        self.assertEqual(payload["rx_lease_max_checks"], 128)
        self.assertFalse(payload["hardware_action"])
        self.assertFalse(payload["airdrop_proven"])

    def test_test126_requires_both_fresh_peer_inputs(self):
        for kwargs in ({"peer_ipv6": False}, {"ready_file": False}):
            with self.subTest(kwargs=kwargs):
                result = self.invoke(build="25G416-Test126", **kwargs)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["phase"], "arguments")
                self.assertFalse(payload["arm_may_have_changed"])
                self.assertFalse(payload["native_udp_attempted"])

    def test_test113_compatibility_remains_matched_return(self):
        result = self.invoke(build="25G332-Test113")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["build"], "25G332-Test113")
        self.assertTrue(payload["peer_ready_required"])
        self.assertEqual(payload["native_udp_count"], 1)
        self.assertFalse(payload["rx_lease_poll_within_original_window"])
        self.assertEqual(payload["rx_lease_max_checks"], 1)

    def test_test109_legacy_plan_still_needs_no_peer_ready(self):
        result = self.invoke(build="25G332-Test109", peer_ipv6=False, ready_file=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["peer_ready_required"])
        self.assertFalse(payload["peer_ready_file_read"])
        self.assertEqual(payload["matched_return_capture_max_ms"], 0)


if __name__ == "__main__":
    unittest.main()
