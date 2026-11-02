#!/usr/bin/env python3
"""Offline checks for the Test118-to-Test104 runtime adapter."""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
from pathlib import Path
import pwd
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
COORDINATOR = ROOT / "developer-tools/test118/coordinate_test118_rx149.py"
SPEC = importlib.util.spec_from_file_location("coordinate_test118_test", COORDINATOR)
COORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COORD
SPEC.loader.exec_module(COORD)
RUNTIME = COORD.RUNNER.RUNTIME_BINDING
PACKETSET = RUNTIME.packetset


class Test118BindingAdapterTests(unittest.TestCase):
    def setUp(self):
        COORD._configure()

    def test_accepts_real_test118_schema_without_normalizing_receipts(self):
        now = dt.datetime.now(dt.timezone.utc)
        sha = "a" * 64
        uuid = "F3CCC4F2-B476-31EC-92A9-C51D708D2B9D"
        metadata = {
            "schema": "test118-native-awdl-rx149-controlled-probe-private/v1",
            "candidate": COORD.BINDING.CANDIDATE,
            "status": "prepared_disarmed", "armed": False,
            "retry_allowed": False, "minimum_boot_epoch_exclusive": 100,
            "expected_loaded_uuid": uuid,
            "source_binding": {"expected_binary_sha256": sha,
                               "build_receipt_sha256": sha},
            "runtime_binding_test104": {
                "candidate": COORD.BINDING.CANDIDATE,
                "build_receipt_sha256": sha,
                "deployment_receipt_sha256": sha,
            },
        }
        router = {"rc": 0, "stdout": "unused", "scope": "read only"}
        target = {"minimum_boot_epoch_exclusive": 100,
                  "build_receipt_sha256": sha,
                  "deployment_receipt_sha256": sha}
        with (patch.object(PACKETSET, "validate_target_identity",
                           return_value={"captured_at": now.isoformat(), "ifindex": 7,
                                         "boot_epoch": 101}),
              patch.object(PACKETSET, "parse_router_identity_receipt",
                           return_value={"captured_at": now.isoformat()}),
              patch.object(PACKETSET, "encode_packet_set", return_value=(b"set", {}))):
            packet_set, manifest = RUNTIME.bind_runtime_identities(
                metadata, router, target, expected_boot_epoch=101,
                expected_uuid=uuid, router_receipt_sha256=sha)
        self.assertEqual(packet_set, b"set")
        self.assertTrue(manifest["identity_freshness"]["current_boot_match"])
        self.assertEqual(metadata["schema"],
                         "test118-native-awdl-rx149-controlled-probe-private/v1")

    def test_rejects_test104_or_unknown_metadata_schema(self):
        metadata = {
            "schema": "native-awdl-rx149-controlled-probe-private/v2",
            "status": "prepared_disarmed", "armed": False,
            "runtime_binding_test104": {"candidate": COORD.BINDING.CANDIDATE},
            "source_binding": {},
        }
        with self.assertRaises(Exception):
            RUNTIME.bind_runtime_identities(
                metadata, {}, {}, expected_boot_epoch=101,
                expected_uuid="F3CCC4F2-B476-31EC-92A9-C51D708D2B9D")

    def test_iwn_root_uses_repository_owner_home_even_if_process_home_differs(self):
        expected = (Path(pwd.getpwuid(COORD.REPO_ROOT.stat().st_uid).pw_dir) /
                    "Library/Application Support/IntelWirelessNative")
        self.assertEqual(COORD.BINDING.IWN_ROOT, expected)
        script = (
            "import importlib.util,sys; from pathlib import Path; "
            f"p=Path({str(COORD.TOOL_DIR / 'rx149_binding_test118.py')!r}); "
            "s=importlib.util.spec_from_file_location('binding_home_probe',p); "
            "m=importlib.util.module_from_spec(s); sys.modules[s.name]=m; "
            "s.loader.exec_module(m); print(m.IWN_ROOT)"
        )
        env = dict(os.environ)
        env["HOME"] = "/var/root"
        result = subprocess.run([sys.executable, "-c", script],
                                env=env, text=True, capture_output=True,
                                check=True, timeout=10)
        self.assertEqual(Path(result.stdout.strip()), expected)


if __name__ == "__main__":
    unittest.main()
