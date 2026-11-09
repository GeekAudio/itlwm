"""Offline preparation identity checks; no SSH or RF."""
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "test111"))
from test_coordinate_test111 import OfflineDeps, make_config
import coordinate_test111 as coordinator


class PrepareIdentityTests(unittest.TestCase):
    def test_bound_peer_mac_is_opt_in_and_failure_still_restores(self):
        for enabled in (None, False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temp:
                config = make_config(temp)
                if enabled is not None:
                    config["prepare_peer_mac_required"] = enabled
                deps = OfflineDeps(temp, config)
                result = coordinator.execute_run(config, deps)
                self.assertEqual(result["automatic_ack_possible_during_prepare"], enabled is True)
                prepare = next(shlex.split(cmd[-1]) for cmd in deps.commands
                               if "/usr/bin/ssh" in cmd and "--prepare" in cmd[-1])
                if enabled is True:
                    self.assertEqual(prepare[-2:], ["--peer-mac", "02:00:00:00:00:02"])
                else:
                    self.assertNotIn("--peer-mac", prepare)
                self.assertEqual(deps.remote_restores, 1)
                self.assertFalse(result["orchestration_completed"])
                self.assertFalse(result["airdrop_proven"])

    def test_non_boolean_option_is_rejected_before_execution(self):
        for value in (1, 0, "true", [], None):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                config = make_config(temp)
                config["prepare_peer_mac_required"] = value
                deps = OfflineDeps(temp, config)
                with self.assertRaisesRegex(coordinator.CoordinatorError, "must be a boolean"):
                    coordinator.execute_run(config, deps)
                self.assertEqual(deps.commands, [])


if __name__ == "__main__":
    unittest.main()
