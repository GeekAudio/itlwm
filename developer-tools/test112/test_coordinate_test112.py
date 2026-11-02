#!/usr/bin/env python3
"""Offline-only Test112 coordinator adapter checks."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import coordinate_test112 as coordinator

TEST111_TESTS = Path(__file__).resolve().parents[1] / "test111"
if str(TEST111_TESTS) not in sys.path:
    sys.path.insert(0, str(TEST111_TESTS))
from test_coordinate_test111 import make_config, make_snapshot, UUID  # noqa: E402


BUILD = "25G332-Test112"


def write_config(path: Path, config: dict) -> None:
    value = {key: item for key, item in config.items()
             if not key.startswith("_")}
    path.write_text(json.dumps(value))
    os.chmod(path, 0o600)


class CoordinateTest112Tests(unittest.TestCase):
    def test_plan_is_test112_bound_and_has_no_hardware_side_effects(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            config["expected_build"] = BUILD
            config_path = Path(temp) / "config112.json"
            write_config(config_path, config)
            output = io.StringIO()
            with mock.patch("subprocess.run",
                            side_effect=AssertionError("plan launched a command")), \
                    contextlib.redirect_stdout(output):
                status = coordinator.main(["--config", str(config_path)])
            self.assertEqual(status, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["schema"], "test112-local-coordinator/v1")
            self.assertEqual(result["build"], BUILD)
            self.assertEqual(result["mode"], "plan")
            self.assertFalse(result["hardware_action"])
            self.assertFalse(result["ssh_attempted"])
            self.assertFalse(Path(config["output_dir"]).exists())

    def test_test112_entry_rejects_test111_config(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            config_path = Path(temp) / "wrong-build.json"
            write_config(config_path, config)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = coordinator.main(["--config", str(config_path)])
            self.assertEqual(status, 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result["schema"], "test112-local-coordinator/v1")
            self.assertFalse(result["hardware_action"])
            self.assertIn("expected_build must be 25G332-Test112", result["error"])

    def test_shared_preflight_still_binds_test112_build_boot_and_loaded_uuid(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            config["expected_build"] = BUILD
            config["identity"] = coordinator.shared.normalize_identity(
                config["identity"])
            raw = make_snapshot()
            props = plistlib.loads(raw["ioreg"])[0]
            props["NativeTestBuild"] = BUILD
            raw["ioreg"] = plistlib.dumps([props])
            summary = coordinator.shared.inspect_snapshot(raw, config)
            coordinator.shared.validate_preflight(summary, config)

            wrong_boot = dict(config, expected_boot=config["expected_boot"] + 1)
            with self.assertRaisesRegex(coordinator.shared.CoordinatorError,
                                        "preflight gate failed: boot"):
                coordinator.shared.validate_preflight(summary, wrong_boot)

            wrong_uuid = dict(summary, loaded_uuid_matches=False)
            with self.assertRaisesRegex(coordinator.shared.CoordinatorError,
                                        "preflight gate failed: loaded_uuid_matches"):
                coordinator.shared.validate_preflight(wrong_uuid, config)

            wrong_build = dict(summary, build="25G332-Test111")
            with self.assertRaisesRegex(coordinator.shared.CoordinatorError,
                                        "preflight gate failed: build"):
                coordinator.shared.validate_preflight(wrong_build, config)


if __name__ == "__main__":
    unittest.main()
