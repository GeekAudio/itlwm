#!/usr/bin/env python3
"""Integration fixture for the Test119 pre-ARM run_once gate boundary."""
from __future__ import annotations

import importlib.util
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
COORDINATOR = ROOT / "developer-tools/test119/coordinate_test119_rx149.py"
SPEC = importlib.util.spec_from_file_location("coordinate_test119_dry_gate", COORDINATOR)
COORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COORD
SPEC.loader.exec_module(COORD)
RUNNER = COORD.RUNNER
BINDING = COORD.BINDING


class Test119DryPrearmTests(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "requires a non-root parent process")
    def test_native_worker_subprocess_stdin_eof_reports_root_gate_without_arm(self):
        worker = ROOT / "developer-tools/test119/native_controlled_capture_test119.py"
        with tempfile.TemporaryDirectory(prefix="test119-worker-eof-") as temporary:
            output = Path(temporary) / "worker-output"
            completed = subprocess.run(
                [
                    sys.executable, str(worker), "--native-worker",
                    "--metadata", str(BINDING.METADATA),
                    "--output", str(output),
                    "--iwn-root", str(BINDING.IWN_ROOT),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                check=False,
            )

        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertNotIn("ModuleNotFoundError", completed.stderr)
        self.assertEqual(completed.stderr, "")
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, completed.stdout)
        prefix, separator, payload = lines[0].partition(" ")
        self.assertEqual(prefix, "NATIVE_ERROR")
        self.assertTrue(separator)
        event = json.loads(payload)
        self.assertEqual(event.get("code"), "ROOT_REQUIRED")
        self.assertEqual(event.get("stage"), "preflight")
        self.assertIs(event.get("helper_invoked"), False)
        self.assertIs(event.get("claim_consumed"), False)
        self.assertIs(event.get("retry_allowed"), False)
        self.assertFalse(output.exists())
        self.assertNotIn("NATIVE_READY", completed.stdout)
        self.assertNotIn("NATIVE_ARMED", completed.stdout)
        self.assertNotIn("NATIVE_ARM_RESULT", completed.stdout)

    def test_real_run_once_prearm_reaches_boundary_without_test088(self):
        metadata, build, build_raw, _ = BINDING.validate_bundle(BINDING.METADATA)
        uuid = build["mach_o_uuid"]
        boot_epoch = metadata["minimum_boot_epoch_exclusive"] + 1
        captured_at = dt.datetime.now(dt.timezone.utc).isoformat()
        router_mac = "02:11:22:33:44:55"
        target_mac = "02:AA:BB:CC:DD:EE"
        router_ip = "fe80::11:22ff:fe33:4455"
        target_ip = "fe80::2aa:bbff:fecc:ddee%awdl0"
        router_stdout = "\n".join((
            "phy#7", "    Interface wlan7", "        ifindex 7",
            f"        addr {router_mac}", "        type AP",
            "        channel 149 (5745 MHz), width: 80 MHz, center1: 5775 MHz",
            "7: wlan7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default",
            f"    link/ether {router_mac} brd ff:ff:ff:ff:ff:ff",
            f"    inet6 {router_ip}/64 scope link", "IFACE=wlan7", router_mac,
        ))
        router = {"rc": 0, "scope": "read only iw dev and ip -6 addr show",
                  "at": captured_at, "stdout": router_stdout}
        target = {
            "schema": "test104-target-identity/v1",
            "status": "readback_verified", "captured_at": captured_at,
            "boot_epoch": boot_epoch,
            "minimum_boot_epoch_exclusive": metadata["minimum_boot_epoch_exclusive"],
            "interface": "awdl0", "ifindex": 7, "mac": target_mac,
            "ipv6_link_local": target_ip, "interface_up": True,
            "candidate": BINDING.CANDIDATE, "candidate_uuid": uuid,
            "candidate_binary_sha256": build["binary_sha256"],
            "build_receipt_sha256": metadata["source_binding"]["build_receipt_sha256"],
            "deployment_receipt_sha256": metadata["runtime_binding_test104"]["deployment_receipt_sha256"],
            "source": "live_ifconfig_ifindex_kmutil",
            "evidence_sha256": BINDING.sha256(b"dry-prearm fixture evidence"),
        }
        target["identity_receipt_sha256"] = BINDING.sha256(json.dumps(
            target, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
        original_router_read = RUNNER.read_private_json
        try:
            with (
                patch.object(RUNNER.RUNTIME_BINDING, "_read_boot_epoch",
                             return_value=boot_epoch),
                patch.object(RUNNER.RUNTIME_BINDING, "_run_text",
                             return_value="loaded fixture"),
                patch.object(RUNNER.RUNTIME_BINDING, "_extract_loaded_uuid",
                             return_value=uuid),
            ):
                RUNNER.read_private_json = lambda path, _uid: (
                    (router, b"router fixture") if path == BINDING.ROUTER_RECEIPT
                    else (target, b"target fixture"))
                result = COORD.dry_prearm_check(
                    metadata_path=BINDING.METADATA, ap="wlan7")
        finally:
            RUNNER.read_private_json = original_router_read

        self.assertEqual(result["status"], "dry_prearm_passed")
        self.assertTrue(result["post_prearm_boundary_reached"])
        self.assertFalse(result["test088_real_entrypoint_called"])
        self.assertTrue(result["test088_sentinel_boundary_triggered"])
        self.assertFalse(result["claim_consumed"])
        self.assertFalse(result["driver_arm_requested"])
        self.assertFalse(result["router_contacted"])
        self.assertFalse(result["sender_go_written"])
        self.assertFalse(result["rf_triggered"])
        self.assertFalse(result["efi_modified"])
        sender_key = str(RUNNER.SENDER_BINARY.relative_to(RUNNER.REPO))
        self.assertEqual(result["runtime_tool_hashes"][sender_key],
                         RUNNER.SENDER_SHA256)


if __name__ == "__main__":
    unittest.main()
