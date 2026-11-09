#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline receipt and dispatch tests. No device, socket or router access."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import uuid
from zipfile import ZipFile

import coordinate_directed_test124 as tool

UUID = "00000000-0000-4000-8000-000000000001"
TOKEN = "0102030405060708090a0b0c0d0e0f10"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


class DirectedTest124Contracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "Development" / "itlwm-active"
        self.repo.mkdir(parents=True)
        self.prep = self.root / "RuntimeTest124" / "research" / "preparation-private"
        self.tools = self.prep / "tools"
        self.tools.mkdir(parents=True)
        for path in (self.prep.parent, self.prep, self.tools):
            path.chmod(0o700)
        for name in (*tool.HELPER_SOURCES, *tool.PEER_SOURCES):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        self.patches = [mock.patch.object(tool, "REPO_ROOT", self.repo),
                        mock.patch.object(tool, "PRIVATE_DIR", self.prep)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.binary = self.tools / "helper"
        self.binary.write_bytes(b"fixture helper, never execute")
        self.binary.chmod(0o700)
        self.helper_receipt = self.tools / "test124-helper-build-private.json"
        source_hashes = {name: digest((self.repo / name).read_bytes()) for name in tool.HELPER_SOURCES}
        self.helper = {
            "schema": "test124-mode4-helper-build/v1", "candidate": tool.BUILD_ID,
            "status": "built_offline", "installed": False, "rf_tested": False,
            "binary_path": str(self.binary), "binary_sha256": digest(self.binary.read_bytes()),
            "source_path": tool.HELPER_SOURCES[0], "source_sha256": source_hashes[tool.HELPER_SOURCES[0]],
            "source_hashes": source_hashes,
        }
        private_json(self.helper_receipt, self.helper)
        self.manifest = self.prep / "build-input-before-private.json"
        private_json(self.manifest, {"native/example.cpp": "a" * 64})
        macho = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x1000007, 3, 11, 1, 24, 0, 0)
        macho += struct.pack("<II", 0x1B, 24) + uuid.UUID(UUID).bytes
        plist = plistlib.dumps({"AirportTahoeBuild": tool.BUILD_ID,
                               "CFBundleIdentifier": "org.geekaudio.AirportItlwm",
                               "CFBundleExecutable": "AirportItlwm"})
        archive = self.prep / "AirportItlwm-Test124.zip"
        with ZipFile(archive, "w") as output:
            output.writestr("AirportItlwm.kext/Contents/Info.plist", plist)
            output.writestr("AirportItlwm.kext/Contents/MacOS/AirportItlwm", macho)
            output.writestr("AirportItlwm.kext/Contents/_CodeSignature/CodeResources", b"fixture")
        self.receipt = self.prep / "test124-build-private.json"
        self.build = {
            "candidate": tool.BUILD_ID, "test_build": tool.BUILD_ID,
            "full_build_passed": True, "strict_signature_passed": True,
            "build_inputs_unchanged": True, "installed": False, "rf_tested": False,
            "compile_profile_count": 72, "target_os_build": "25G416",
            "target_os_abi_review_passed": False,
            "mach_o_uuid": UUID, "source_commit": "1" * 40,
            "binary_sha256": digest(macho), "info_plist_sha256": digest(plist),
            "archive_sha256": digest(archive.read_bytes()), "sha256": digest(archive.read_bytes()),
            "build_input_manifest_sha256": digest(self.manifest.read_bytes()),
            "output": str(archive), "native_awdl_tx_evidence": False, "p2p_tx_probe": False,
        }
        for name in ("native_awdl_directed_data_compiled", "native_awdl_directed_data_enabled",
                     "native_awdl_directed_prepare_compiled", "native_awdl_directed_prepare_enabled",
                     "native_awdl_resident_data", "native_awdl_rx149_data_input",
                     "native_awdl_rx149_observation_only", "p2p_manual_trigger", "p2p_probe"):
            self.build[name] = True
        private_json(self.receipt, self.build)
        peer = self.tools / "peer"
        peer.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + b"\xb7\0" + b"fixture peer, never execute")
        self.peer_receipt = self.tools / "test124-peer-build-private.json"
        self.peer = {
            "schema": "test124-mode4-peer-build/v1", "candidate": tool.BUILD_ID,
            "status": "built_offline", "target": "aarch64-linux-musl",
            "wire_contract": "mode4-peer-unicast-ff02-allnodes/v1",
            "binary_path": str(peer), "binary_sha256": digest(peer.read_bytes()),
            "source_hashes": {name: digest((self.repo / name).read_bytes()) for name in tool.PEER_SOURCES},
        }
        private_json(self.peer_receipt, self.peer)
        script = self.tools / "script"
        script.write_bytes(b"fixture script, never execute")
        self.config = {
            "ssh_target": "root@192.168.5.1", "ssh_socket": "/tmp/never-connect-test124.sock",
            "remote_dir": f"/tmp/iw111echo-{TOKEN}",
            "output_dir": str(self.tools / f"run-{TOKEN}"),
            "expected_boot": 1793697291, "expected_uuid": UUID,
            "expected_build": tool.BUILD_ID, "expected_reset_count": 0,
            "helper_path": str(self.binary), "helper_sha256": self.helper["binary_sha256"],
            "helper_source_path": str(self.repo / tool.HELPER_SOURCES[0]),
            "helper_source_sha256": self.helper["source_sha256"],
            "remote_script_path": str(script), "remote_script_sha256": digest(script.read_bytes()),
            "peer_binary_path": str(peer), "peer_sha256": digest(peer.read_bytes()),
            "identity": {"run_token": TOKEN, "nonce": "0102030405060708",
                         "local_mac": "02:00:00:00:00:01", "peer_mac": "02:00:00:00:00:02",
                         "local_ipv6": "fe80::1", "peer_ipv6": "fe80::2"},
        }
        self.config_path = private_json(self.prep / "runtime.json", self.config)
        self.deployment_path = self.prep.parent / "test124-deployment-private.json"

    def validate(self, deployment=False):
        return tool.validate_local_inputs(
            config_path=self.config_path, build_receipt_path=self.receipt,
            source_manifest_path=self.manifest, helper_receipt_path=self.helper_receipt,
            peer_receipt_path=self.peer_receipt,
            deployment_receipt_path=self.deployment_path if deployment else None,
            require_deployment=deployment)

    def deploy(self):
        private_json(self.deployment_path, {
            "candidate": tool.BUILD_ID, "status": "deployed_waiting_reboot_disarmed",
            "automatic_reboot": False, "mach_o_uuid": UUID,
            "binary_sha256": self.build["binary_sha256"],
            "build_report_sha256": digest(self.receipt.read_bytes()),
        })

    def cli(self, run=False):
        args = ["--config", str(self.config_path), "--build-receipt", str(self.receipt),
                "--source-input-manifest", str(self.manifest),
                "--helper-build-receipt", str(self.helper_receipt),
                "--peer-build-receipt", str(self.peer_receipt),
                "--deployment-receipt", str(self.deployment_path)]
        if run:
            args.append("--run")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = tool.main(args)
        return code, json.loads(output.getvalue())

    def test_default_plan_uses_separate_contracts_without_device_access(self):
        with mock.patch.object(tool.subprocess, "run", side_effect=AssertionError("no OS/device access")):
            code, result = self.cli()
        self.assertEqual(code, 0)
        self.assertTrue(result["candidate_build_receipt_validated"])
        self.assertTrue(result["source_input_manifest_validated_separately"])
        self.assertTrue(result["deployment_required_before_run"])
        self.assertFalse(result["hardware_action"])
        self.assertFalse(result["runtime_os_build_checked"])
        self.assertFalse(result["target_os_abi_review_passed"])

    def test_run_missing_deployment_never_checks_os_or_dispatches(self):
        with mock.patch.object(tool, "verify_target_os") as os_check, \
                mock.patch.object(tool.shared, "execute_run") as execute:
            code, result = self.cli(run=True)
        self.assertEqual(code, 1)
        os_check.assert_not_called()
        execute.assert_not_called()
        self.assertIn("fresh_disarmed_deployment_receipt_required", result["error"])

    def test_real_deployment_location_binds_current_candidate_receipt(self):
        self.deploy()
        _, result = self.validate(deployment=True)
        self.assertTrue(result["deployment_verified"])
        value = json.loads(self.deployment_path.read_text())
        value["build_report_sha256"] = "a" * 64
        private_json(self.deployment_path, value)
        with self.assertRaisesRegex(tool.Test124Error, "deployment_receipt_build_binding_invalid"):
            self.validate(deployment=True)

    def test_build_manifest_cannot_be_substituted_for_receipt(self):
        private_json(self.receipt, {"native/example.cpp": "a" * 64})
        with self.assertRaisesRegex(tool.Test124Error, "candidate_build_receipt_contract_invalid"):
            self.validate()

    def test_source_manifest_mutation_and_binary_identity_are_rejected(self):
        private_json(self.manifest, {"native/example.cpp": "b" * 64})
        with self.assertRaisesRegex(tool.Test124Error, "source_manifest_binding"):
            self.validate()
        self.build["build_input_manifest_sha256"] = digest(self.manifest.read_bytes())
        self.build["mach_o_uuid"] = "00000000-0000-4000-8000-000000000002"
        private_json(self.receipt, self.build)
        with self.assertRaisesRegex(tool.Test124Error, "binary_uuid_mismatch"):
            self.validate()

    def test_helper_dependency_changes_are_not_hidden_by_main_source_hash(self):
        (self.repo / tool.HELPER_SOURCES[2]).write_bytes(b"modified lease dependency")
        with self.assertRaisesRegex(tool.Test124Error, "helper_dependency_hash_mismatch"):
            self.validate()

    def test_helper_receipt_requires_all_five_sources(self):
        del self.helper["source_hashes"][tool.HELPER_SOURCES[4]]
        private_json(self.helper_receipt, self.helper)
        with self.assertRaisesRegex(tool.Test124Error, "helper_all_source_hashes_required"):
            self.validate()

    def test_peer_receipt_rejects_old_wire_contract(self):
        self.peer["wire_contract"] = "old-multicast-da"
        private_json(self.peer_receipt, self.peer)
        with self.assertRaisesRegex(tool.Test124Error, "peer_build_receipt_binding_invalid"):
            self.validate()

    def test_changed_peer_parser_cannot_reuse_old_binary_receipt(self):
        (self.repo / "developer-tools/test110/openwrt_echo_core.hpp").write_bytes(b"changed peer parser")
        with self.assertRaisesRegex(tool.Test124Error, "peer_dependency_hash_mismatch"):
            self.validate()

    def test_os_unreviewed_and_os_mismatch_stop_before_dispatch(self):
        self.deploy()
        with mock.patch.object(tool.shared, "execute_run") as execute:
            code, result = self.cli(run=True)
        self.assertEqual(code, 1)
        execute.assert_not_called()
        self.assertIn("target_os_abi_review_required", result["error"])
        self.build["target_os_abi_review_passed"] = True
        private_json(self.receipt, self.build)
        self.deploy()
        with mock.patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "25G332\n", "")), \
                mock.patch.object(tool.shared, "execute_run") as execute:
            code, result = self.cli(run=True)
        self.assertEqual(code, 1)
        execute.assert_not_called()
        self.assertIn("runtime_os_build_mismatch", result["error"])

    def test_run_dispatches_exact_validated_config_once_after_os_match(self):
        self.build["target_os_abi_review_passed"] = True
        private_json(self.receipt, self.build)
        self.deploy()
        with mock.patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "25G416\n", "")), \
                mock.patch.object(tool.shared, "execute_run", return_value={"orchestration_completed": True, "hardware_action": False}) as execute:
            code, result = self.cli(run=True)
        self.assertEqual(code, 0)
        execute.assert_called_once()
        self.assertEqual(execute.call_args.kwargs, {"build_id": tool.BUILD_ID})
        self.assertEqual(execute.call_args.args[0]["identity"]["run_token"], TOKEN)
        self.assertTrue(result["runtime_os_build_checked"])

    def test_unhandled_shared_error_does_not_report_no_hardware_action(self):
        self.build["target_os_abi_review_passed"] = True
        private_json(self.receipt, self.build)
        self.deploy()
        with mock.patch.object(tool.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "25G416\n", "")), \
                mock.patch.object(tool.shared, "execute_run", side_effect=RuntimeError("test failure after dispatch")):
            code, result = self.cli(run=True)
        self.assertEqual(code, 1)
        self.assertIsNone(result["hardware_action"])
        self.assertEqual(result["execution_outcome"], "unknown_after_dispatch")


if __name__ == "__main__":
    unittest.main()
