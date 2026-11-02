#!/usr/bin/env python3
"""No-run argument/profile compatibility tests for the Test107 helper."""

import json
import os
import subprocess
import unittest


HELPER = os.environ.get("ARM_DIRECTED_DATA_HELPER")


class TestArmDirectedData111Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HELPER:
            raise RuntimeError("Set ARM_DIRECTED_DATA_HELPER to the compiled helper")

    def invoke(self, build, peer=True, peer_ipv6=True, ready_file=True):
        args = [
            HELPER,
            "--expect-build", build,
            "--expect-uuid", "00000000-0000-4000-8000-000000000001",
            "--peer-mac", "02:00:00:00:00:02",
            "--local-ipv6", "fe80::1",
            "--nonce", "0102030405060708",
            "--run-token", "0102030405060708090a0b0c0d0e0f10",
        ]
        if peer:
            if peer_ipv6:
                args += ["--peer-ipv6", "fe80::2"]
            if ready_file:
                args += ["--peer-ready-file", "/this-file-must-not-be-read.json"]
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def test_test111_uses_strict_matched_return_plan(self):
        result = self.invoke("25G332-Test111")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["peer_ready_required"])
        self.assertFalse(payload["peer_ready_file_read"])
        self.assertEqual(payload["matched_return_capture_max_ms"], 100)
        self.assertFalse(payload["hardware_action"])
        self.assertFalse(payload["airdrop_proven"])

    def test_test111_requires_both_peer_inputs(self):
        for options in ({"peer": False}, {"peer_ipv6": False}, {"ready_file": False}):
            with self.subTest(options=options):
                result = self.invoke("25G332-Test111", **options)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["phase"], "arguments")
                self.assertFalse(payload["arm_may_have_changed"])
                self.assertFalse(payload["native_udp_attempted"])

    def test_test110_keeps_matched_return_contract(self):
        result = self.invoke("25G332-Test110")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["peer_ready_required"])
        self.assertEqual(payload["matched_return_capture_max_ms"], 100)

    def test_test107_through_test109_keep_legacy_arguments(self):
        for build in ("25G332-Test107", "25G332-Test108", "25G332-Test109"):
            with self.subTest(build=build):
                result = self.invoke(build, peer=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertFalse(payload["peer_ready_required"])
                self.assertEqual(payload["matched_return_capture_max_ms"], 0)
                self.assertFalse(payload["hardware_action"])

    def test_legacy_identity_rejects_new_peer_arguments(self):
        result = self.invoke("25G332-Test109", peer=True)
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["phase"], "arguments")
        self.assertFalse(payload["arm_may_have_changed"])


if __name__ == "__main__":
    unittest.main()
