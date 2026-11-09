#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise Test131 against the production shared runner without hardware."""
from pathlib import Path
import sys
import unittest
import contextlib
import io
import json
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "developer-tools/test131"), str(ROOT / "developer-tools/test130")]
import coordinate_directed_test131 as profile
import coordinate_directed_test130 as tool
import test_coordinate_directed_test130 as previous

class Test131Profile(unittest.TestCase):
    def test_main_reports_test131_on_preflight_failure(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["test131", "--config", "/dev/null"]), \
             patch.object(tool, "_validate_build", side_effect=ValueError("offline fixture")), \
             contextlib.redirect_stdout(output):
            self.assertEqual(profile.main(), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["schema"], "test131-local-coordinator/v1")
        self.assertEqual(result["build"], "25G416-Test131")
        self.assertFalse(result["hardware_action"])

    def test_runtime_argv_keeps_both_nonces(self):
        with patch.object(tool, "BUILD", "25G416-Test131"):
            case = previous.Test130CoordinatorContracts()
            case.test_shared_runner_uses_test130_nonce_and_remote_contract()

    def test_exact_profile_reuses_frozen_peer_and_restores_globals(self):
        peer = tool.PEER_RECEIPT
        def run():
            self.assertEqual(tool.BUILD, "25G416-Test131")
            self.assertEqual(tool.PEER_BUILD, "25G416-Test130")
            self.assertEqual(tool.MONITOR_BUILD, "25G416-Test130")
            self.assertEqual(tool.PEER_RECEIPT, peer)
            self.assertEqual(tool.ARCHIVE_NAME, "AirportItlwm-Test131.zip")
            self.assertIn("RuntimeTest131", str(tool.HELPER_RECEIPT))
            self.assertEqual(tool.shared._coordinator_schema(tool.BUILD), "test131-local-coordinator/v1")
            raise RuntimeError("simulated preflight failure")
        with patch.object(tool, "main", run):
            with self.assertRaisesRegex(RuntimeError, "simulated"):
                profile.main()
        self.assertEqual(tool.BUILD, "25G416-Test130")
        self.assertEqual(tool.ARCHIVE_NAME, "AirportItlwm-Test130.zip")

if __name__ == "__main__":
    unittest.main()
