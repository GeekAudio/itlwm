#!/usr/bin/env python3
"""Plan-mode checks for the compiled Test112 helper; never pass --run."""
import json
import os
import subprocess
import unittest


HELPER = os.environ.get("ARM_DIRECTED_DATA_HELPER")
UUID = "00000000-0000-4000-8000-000000000001"
TOKEN = "0102030405060708090a0b0c0d0e0f10"


class ArmDirectedData112PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HELPER:
            raise RuntimeError("Set ARM_DIRECTED_DATA_HELPER to the compiled helper")

    def invoke(self, build="25G332-Test112", *, peer_ipv6=True,
               ready_file=True, uuid=UUID):
        args = [
            HELPER,
            "--expect-build", build,
            "--expect-uuid", uuid,
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

    def test_test112_uses_matched_return_plan_without_reading_ready_file(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["build"], "25G332-Test112")
        self.assertTrue(payload["peer_ready_required"])
        self.assertFalse(payload["peer_ready_file_read"])
        self.assertEqual(payload["matched_return_capture_max_ms"], 100)
        self.assertFalse(payload["hardware_action"])
        self.assertFalse(payload["airdrop_proven"])

    def test_test112_requires_both_fresh_peer_inputs(self):
        for kwargs in ({"peer_ipv6": False}, {"ready_file": False}):
            with self.subTest(kwargs=kwargs):
                result = self.invoke(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["phase"], "arguments")
                self.assertFalse(payload["arm_may_have_changed"])
                self.assertFalse(payload["native_udp_attempted"])

    def test_test112_rejects_noncanonical_loaded_uuid_argument(self):
        result = self.invoke(uuid="not-a-uuid")
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["phase"], "arguments")
        self.assertFalse(payload["arm_may_have_changed"])


if __name__ == "__main__":
    unittest.main()
