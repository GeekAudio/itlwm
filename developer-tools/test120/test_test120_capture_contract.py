#!/usr/bin/env python3
"""Offline mock tests for Test120 receipt and HAL-probe sample classification."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "developer-tools/test120/test120_capture_contract.py"
SPEC = importlib.util.spec_from_file_location("test120_capture_contract", MODULE_PATH)
CONTRACT = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(CONTRACT)


def sample(**overrides):
    props = {
        "NativeP2PRx149Selected": 1,
        "NativeP2PProbeAttempted": 1,
        "NativeP2PProbeState": 7,
        "NativeP2PProbeResourceMayExist": 0,
        "NativeP2PRocEndSeen": 1,
        "NativeP2PProbeExerciseRecoveryAttempted": 0,
        "NativeP2PProbeExerciseRecoveryProofAccepted": 0,
        "NativeP2PProbeExerciseResult": 0,
        "NativeP2PProbeRemoveResult": 0,
    }
    props.update(overrides)
    return props


class Test120CaptureContractTests(unittest.TestCase):
    def test_default_plan_is_disarmed_and_has_no_rf_or_router_action(self):
        value = CONTRACT.plan()
        self.assertEqual(value["default_action"], "plan_only")
        self.assertIs(value["armed"], False)
        self.assertIs(value["router_contacted"], False)
        self.assertIs(value["scan_triggered"], False)
        self.assertIs(value["rf_triggered"], False)
        self.assertIs(value["efi_modified"], False)

    def test_test119_sender_reuse_receipt_disclaims_new_build(self):
        receipt = json.loads(
            (ROOT / "developer-tools/test120/sender-reuse-receipt-test120.json")
            .read_text(encoding="utf-8"))
        self.assertEqual(receipt["reused_from"], "25G332-Test119")
        self.assertIs(receipt["validated_offline"], True)
        self.assertIs(receipt["newly_compiled_for_test120"], False)
        self.assertIs(receipt["rf_tested"], False)
        self.assertEqual(receipt["protocol"]["schema"],
                         "test119-dual-socket-sender/v1")

    def test_candidate_coordinator_subprocess_import_is_plan_only(self):
        result = subprocess.run(
            [sys.executable,
             str(ROOT / "developer-tools/test120/coordinate_test120_rx149.py"),
             "--plan"],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=15, check=False,
            env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["candidate"], CONTRACT.CANDIDATE)
        self.assertEqual(plan["profile"], "native_awdl_rx149_preowner_observation")
        self.assertIs(plan["armed"], False)
        self.assertIs(plan["router_contacted"], False)
        self.assertIs(plan["rf_triggered"], False)
        self.assertIs(plan["efi_modified"], False)
        self.assertEqual(plan["sender_reused_from"], "25G332-Test119")

    def test_wrong_metadata_path_is_rejected_before_runner_configuration(self):
        path = ROOT / "developer-tools/test120/coordinate_test120_rx149.py"
        spec = importlib.util.spec_from_file_location("test120_coordinate_for_test", path)
        module = importlib.util.module_from_spec(spec)
        self.assertIsNotNone(spec)
        spec.loader.exec_module(module)
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_runtime_metadata(
                {"candidate": "25G332-Test120", "armed": True},
                {"candidate": "25G332-Test120"})
        with self.assertRaises(module.BINDING.BindingError):
            module.validate_metadata_path(ROOT / "wrong-metadata.json")

    def test_test120_worker_report_hook_attaches_same_cut_terminal_fields(self):
        path = ROOT / "developer-tools/test120/native_controlled_capture_test120.py"
        spec = importlib.util.spec_from_file_location("test120_worker_for_test", path)
        wrapper = importlib.util.module_from_spec(spec)
        self.assertIsNotNone(spec)
        spec.loader.exec_module(wrapper)
        underlying = SimpleNamespace(
            _report_sample=lambda _sample, _capture: {"existing_capture_fields": True})
        adapter = SimpleNamespace(
            _run_worker_with_deferred_terminal=lambda *a, **k: None,
            _atomic_append_hcmd_report=lambda *a, **k: (True, "ok"),
            configure_worker=lambda _namespace, *, iwn_root: None,
            load_test087_worker=lambda: underlying,
        )
        wrapper._instrument_worker(adapter, ROOT)
        loaded = adapter.load_test087_worker()
        first = loaded._report_sample(
            sample(), object())
        failed_cleaned = sample(
            NativeP2PProbeState=10,
            NativeP2PProbeExerciseResult=0xFFFFFFF2,
            NativeP2PProbeExerciseRecoveryAttempted=1,
            NativeP2PProbeExerciseRecoveryProofAccepted=1,
            NativeP2PProbeRemoveResult=0,
        )
        failed_cleaned["SSID"] = "must-not-be-copied"
        failed_cleaned["MACAddress"] = "must-not-be-copied"
        second = loaded._report_sample(failed_cleaned, object())
        third = loaded._report_sample(
            sample(NativeP2PProbeState=8,
                   NativeP2PProbeResourceMayExist=1), object())
        self.assertEqual(first["native_p2p_probe_lifecycle"]["sample_index"], 0)
        self.assertEqual(first["native_p2p_probe_lifecycle"]["interpretation"],
                         "probe_completed_and_released")
        self.assertEqual(second["native_p2p_probe_lifecycle"]["sample_index"], 1)
        self.assertEqual(second["native_p2p_probe_lifecycle"]["interpretation"],
                         "exercise_failed_but_safely_cleaned")
        self.assertEqual(third["native_p2p_probe_lifecycle"]["sample_index"], 2)
        self.assertEqual(third["native_p2p_probe_lifecycle"]["interpretation"],
                         "quarantined_resource_may_exist")
        self.assertNotIn("SSID", second["native_p2p_probe_lifecycle"])
        self.assertNotIn("MACAddress", second["native_p2p_probe_lifecycle"])
        self.assertIs(second["native_p2p_probe_lifecycle"]["airdrop_proven"], False)

    def test_completed_state_means_probe_lifecycle_only(self):
        result = CONTRACT.normalize_final_sample(sample())
        self.assertEqual(result["interpretation"], "probe_completed_and_released")
        self.assertEqual(result["StateName"], "complete_released")
        self.assertFalse(result["missing_fields"])
        self.assertFalse(result["invalid_fields"])

    def test_state_ten_is_failed_exercise_even_when_safely_cleaned(self):
        result = CONTRACT.normalize_final_sample(sample(
            NativeP2PProbeState=10,
            NativeP2PProbeExerciseResult=0xFFFFFFF2,
            NativeP2PProbeExerciseRecoveryAttempted=1,
            NativeP2PProbeExerciseRecoveryProofAccepted=1,
            NativeP2PProbeResourceMayExist=0,
            NativeP2PProbeRemoveResult=0,
        ))
        self.assertEqual(result["interpretation"], "exercise_failed_but_safely_cleaned")
        self.assertNotEqual(result["interpretation"], "probe_completed_and_released")

    def test_state_eight_is_quarantined_not_success(self):
        result = CONTRACT.normalize_final_sample(sample(
            NativeP2PProbeState=8,
            NativeP2PProbeResourceMayExist=1,
            NativeP2PProbeRemoveResult=0xFFFFFFFF,
        ))
        self.assertEqual(result["interpretation"], "quarantined_resource_may_exist")

    def test_missing_and_boolean_numeric_values_remain_unknown(self):
        missing = sample()
        del missing["NativeP2PProbeExerciseRecoveryProofAccepted"]
        missing_result = CONTRACT.normalize_final_sample(missing)
        self.assertEqual(missing_result["ProofAccepted"], None)
        self.assertIn("ProofAccepted", missing_result["missing_fields"])
        self.assertEqual(missing_result["interpretation"], "unknown_incomplete_sample")

        bool_value = CONTRACT.normalize_final_sample(sample(
            NativeP2PProbeAttempted=False))
        self.assertIsNone(bool_value["Attempted"])
        self.assertIn("Attempted", bool_value["invalid_fields"])
        self.assertEqual(bool_value["interpretation"], "unknown_incomplete_sample")

    def test_state_seven_without_end_or_remove_proof_is_not_success(self):
        result = CONTRACT.normalize_final_sample(sample(
            NativeP2PRocEndSeen=0,
            NativeP2PProbeRemoveResult=1,
        ))
        self.assertEqual(result["interpretation"],
                         "terminal_complete_but_evidence_incomplete")

    def test_source_commit_is_dynamic_but_must_match_both_receipts(self):
        commit = "a" * 40
        blob = b"frozen source"
        digest = CONTRACT.sha256(blob)
        build = {
            "source_commit": commit,
            "build_inputs_unchanged": True,
            "build_input_manifest_sha256": CONTRACT.sha256(b"unused in dict helper"),
        }
        source_receipt = {"commit": commit, "pushed": True}
        freeze = {"native/example.hpp": digest}
        inputs = {"native/example.hpp": digest}
        verified = CONTRACT.verify_source_freeze(
            build, source_receipt, freeze, inputs, inputs,
            git_show=lambda seen_commit, path: blob
            if (seen_commit, path) == (commit, "native/example.hpp") else b"",
        )
        self.assertEqual(verified["source_commit"], commit)
        self.assertTrue(verified["source_commit_pushed"])
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.verify_source_freeze(
                build, {"commit": "b" * 40, "pushed": True},
                freeze, inputs, inputs,
                git_show=lambda _commit, _path: blob)

    def test_raw_build_input_receipts_must_match_exact_manifest_bytes(self):
        commit = "c" * 40
        blob = b"frozen source"
        freeze = {"native/example.hpp": CONTRACT.sha256(blob)}
        source_raw = json.dumps(
            {"commit": commit, "pushed": True}, sort_keys=True).encode()
        freeze_raw = json.dumps(freeze, sort_keys=True).encode()
        inputs = {"native/example.hpp": CONTRACT.sha256(blob)}
        before_raw = json.dumps(inputs, sort_keys=True).encode()
        after_raw = before_raw
        build = {
            "source_commit": commit,
            "build_inputs_unchanged": True,
            "build_input_manifest_sha256": CONTRACT.sha256(after_raw),
        }
        result = CONTRACT.verify_source_freeze_raw(
            build, source_raw, freeze_raw, before_raw, after_raw,
            git_show=lambda seen_commit, path: blob
            if (seen_commit, path) == (commit, "native/example.hpp") else b"",
        )
        self.assertEqual(result["source_commit"], commit)
        self.assertEqual(result["build_input_manifest_sha256"],
                         CONTRACT.sha256(after_raw))
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.verify_source_freeze_raw(
                build, source_raw, freeze_raw, before_raw,
                after_raw + b" ",
                git_show=lambda _commit, _path: blob)

    def test_archive_hash_payload_and_uuid_are_all_bound(self):
        uuid = "12345678-90AB-CDEF-1234-567890ABCDEF"
        binary, info = b"mock executable", b"mock plist"
        with tempfile.TemporaryDirectory(prefix="test120-archive-") as temp:
            root = Path(temp)
            archive = root / "candidate.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr("AirportItlwm.kext/Contents/MacOS/AirportItlwm", binary)
                package.writestr("AirportItlwm.kext/Contents/Info.plist", info)
            build = {
                "candidate": CONTRACT.CANDIDATE,
                "full_build_passed": True,
                "strict_signature_passed": True,
                "build_inputs_unchanged": True,
                "rf_tested": False,
                "mach_o_uuid": uuid,
                "archive_sha256": CONTRACT.sha256(archive.read_bytes()),
                "binary_sha256": CONTRACT.sha256(binary),
                "info_plist_sha256": CONTRACT.sha256(info),
                "output": str(archive),
            }
            result = CONTRACT.verify_archive(
                build, run_root=root, uuid_reader=lambda _path: uuid)
            self.assertTrue(result["archive_identity_verified"])
            with self.assertRaises(CONTRACT.ContractError):
                CONTRACT.verify_archive(
                    build, run_root=root, uuid_reader=lambda _path: "0" * 36)

    def test_deployment_gate_requires_matching_artifact_and_backup_evidence(self):
        build = {
            "candidate": CONTRACT.CANDIDATE,
            "mach_o_uuid": "12345678-90AB-CDEF-1234-567890ABCDEF",
            "binary_sha256": "1" * 64,
            "info_plist_sha256": "2" * 64,
        }
        deployment = {
            **build,
            "config_unchanged": True,
            "unrelated_paths_written": False,
            "remount_readback_verified": True,
            "minimal_backup_verified": True,
            "older_driver_activated": False,
        }
        CONTRACT.verify_deployment(build, deployment)
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.verify_deployment(
                build, dict(deployment, minimal_backup_verified=False))

    def test_runtime_requires_new_boot_and_all_artifact_bindings(self):
        binding = {
            "mach_o_uuid": "12345678-90AB-CDEF-1234-567890ABCDEF",
            "minimum_boot_epoch_exclusive": 100,
            "build_receipt_sha256": "1" * 64,
            "deployment_receipt_sha256": "2" * 64,
            "archive_sha256": "3" * 64,
            "source_commit": "a" * 40,
            "production_freeze_manifest_sha256": "4" * 64,
        }
        snapshot = {
            "candidate": CONTRACT.CANDIDATE,
            "boot_epoch": 101,
            "loaded_bundle_id": "org.geekaudio.AirportItlwm",
            "loaded_uuid": binding["mach_o_uuid"],
            "build_receipt_sha256": binding["build_receipt_sha256"],
            "deployment_receipt_sha256": binding["deployment_receipt_sha256"],
            "archive_sha256": binding["archive_sha256"],
            "source_commit": binding["source_commit"],
            "production_freeze_manifest_sha256":
                binding["production_freeze_manifest_sha256"],
        }
        CONTRACT.validate_runtime_snapshot(snapshot, binding)
        stale = dict(snapshot, boot_epoch=100)
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_runtime_snapshot(stale, binding)

    def test_runtime_metadata_unknown_or_armed_state_is_rejected(self):
        binding = {
            "candidate": CONTRACT.CANDIDATE,
            "profile": CONTRACT.DEFAULT_PROFILE,
            "mach_o_uuid": "12345678-90AB-CDEF-1234-567890ABCDEF",
            "build_receipt_sha256": "1" * 64,
            "deployment_receipt_sha256": "2" * 64,
            "archive_sha256": "3" * 64,
            "source_commit": "a" * 40,
            "production_freeze_manifest_sha256": "4" * 64,
        }
        metadata = {
            "candidate": CONTRACT.CANDIDATE,
            "profile": CONTRACT.DEFAULT_PROFILE,
            "status": "prepared_disarmed",
            "armed": False,
            "retry_allowed": False,
            "host_management_or_data_tx_allowed": False,
            "expected_loaded_uuid": binding["mach_o_uuid"],
            "minimum_boot_epoch_exclusive": 100,
            "source_binding": {
                key: value for key, value in binding.items()
                if key not in {"candidate", "profile", "mach_o_uuid"}
            },
        }
        checked = CONTRACT.validate_runtime_metadata(metadata, binding)
        self.assertEqual(checked["minimum_boot_epoch_exclusive"], 100)
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_runtime_metadata(
                dict(metadata, armed=True), binding)

    def test_current_runtime_requires_authorized_matching_handoff(self):
        binding = {
            "candidate": CONTRACT.CANDIDATE,
            "profile": CONTRACT.DEFAULT_PROFILE,
            "mach_o_uuid": "12345678-90AB-CDEF-1234-567890ABCDEF",
            "build_receipt_sha256": "1" * 64,
            "deployment_receipt_sha256": "2" * 64,
            "archive_sha256": "3" * 64,
            "source_commit": "a" * 40,
            "production_freeze_manifest_sha256": "4" * 64,
        }
        binding["minimum_boot_epoch_exclusive"] = 100
        handoff = {
            "candidate": CONTRACT.CANDIDATE,
            "active_awdl_rf_allowed": True,
            "sleep_test_allowed": False,
            "expected_loaded_uuid": binding["mach_o_uuid"],
            "expected_binary_sha256": "5" * 64,
            "minimum_boot_epoch_exclusive": 100,
        }
        build = {"binary_sha256": "5" * 64}
        runtime = {
            "boot_epoch": 101,
            "loaded_uuid": binding["mach_o_uuid"],
        }
        with (
            patch.object(CONTRACT, "validate_preparation_bundle",
                         return_value=dict(binding)),
            patch.object(CONTRACT, "read_private_json",
                         side_effect=[{"metadata": True}, handoff, build]),
            patch.object(CONTRACT, "validate_runtime_metadata",
                         return_value=binding),
            patch.object(CONTRACT, "read_actual_runtime_snapshot",
                         return_value=runtime),
        ):
            result = CONTRACT.validate_current_runtime()
        self.assertTrue(result["runtime_identity_verified"])
        self.assertTrue(result["rf_authorized"])

        with (
            patch.object(CONTRACT, "validate_preparation_bundle",
                         return_value=dict(binding)),
            patch.object(CONTRACT, "read_private_json",
                         side_effect=[{"metadata": True}, dict(
                             handoff, active_awdl_rf_allowed=False), build]),
            patch.object(CONTRACT, "validate_runtime_metadata",
                         return_value=binding),
        ):
            with self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_current_runtime()


if __name__ == "__main__":
    unittest.main()
