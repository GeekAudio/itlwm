#!/usr/bin/env python3
"""Offline Test119 checks for the unchanged Test087 metadata and pre-GO gates."""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
COORDINATOR = ROOT / "developer-tools/test119/coordinate_test119_rx149.py"
SPEC = importlib.util.spec_from_file_location("test119_protocol_gates", COORDINATOR)
COORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COORD
SPEC.loader.exec_module(COORD)


def _literal_assignment(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a literal assignment in {path}")


class Test119ProtocolGateTests(unittest.TestCase):
    def setUp(self):
        COORD._configure()
        self.restore_profile = COORD.RUNNER.configure_test104_profile()
        self.binding = COORD.BINDING
        self.protocol = COORD.RUNNER.PROTOCOL
        (self.metadata, self.build, self.build_raw,
         self.build_path) = self.binding.validate_bundle(self.binding.METADATA)
        self.receipt_sha = self.binding.sha256(self.build_raw)
        self.boot_epoch = self.metadata["minimum_boot_epoch_exclusive"] + 1

    def tearDown(self):
        self.restore_profile()

    def _private_errors(self, metadata=None, *, boot_epoch=None,
                        expected_receipt_sha=None, actual_receipt_sha=None):
        return self.protocol.validate_private_metadata(
            copy.deepcopy(self.metadata if metadata is None else metadata),
            boot_epoch=self.boot_epoch if boot_epoch is None else boot_epoch,
            expected_receipt_sha256=(self.receipt_sha if expected_receipt_sha is None
                                     else expected_receipt_sha),
            actual_receipt_sha256=(self.receipt_sha if actual_receipt_sha is None
                                   else actual_receipt_sha),
        )

    def _full_gate_errors(self, *, metadata=None, boot_epoch=None,
                          expected_receipt_sha=None, actual_receipt_sha=None,
                          claim=True, router=True, native=True, listener=True,
                          counters=None):
        template = copy.deepcopy(self.metadata if metadata is None else metadata)
        if counters is None:
            counters = {key: 0 for key in template["required_zero_host_tx_counters"]}
        return self.protocol.validate_full_run_gates(
            template,
            boot_epoch=self.boot_epoch if boot_epoch is None else boot_epoch,
            expected_receipt_sha256=(self.receipt_sha if expected_receipt_sha is None
                                     else expected_receipt_sha),
            actual_receipt_sha256=(self.receipt_sha if actual_receipt_sha is None
                                   else actual_receipt_sha),
            shared_boot_claim_available=claim,
            host_tx_counters=counters,
            router_sender_ready=router,
            native_preflight_ready=native,
            listener_ready=listener,
        )

    def test_real_test119_bundle_passes_unchanged_test087_private_gate(self):
        self.assertEqual(
            self.metadata["schema"],
            "test119-native-awdl-rx149-controlled-probe-private/v1")
        self.assertEqual(self.metadata["source_sha256"],
                         self.metadata["source_binding"][
                             "production_freeze_source_sha256"])
        self.assertEqual(
            self.metadata["source_binding"]["source_sha256_map_sha256"],
            self.protocol.candidate_binding.canonical_json_sha256(
                self.metadata["source_sha256"]))
        self.assertEqual(self._private_errors(), [])

    def test_private_gate_rejects_missing_or_changed_required_fields(self):
        invalid_cases = (
            ("schema", "wrong-schema"),
            ("candidate", "invalid candidate"),
            ("source_ready_kind", "wrong-kind"),
            ("requires_phone_ready", True),
            ("armed", True),
            ("status", "armed"),
            ("retry_allowed", True),
            ("expected_loaded_uuid", "invalid-uuid"),
            ("profile", "wrong-profile"),
            ("diagnostic_duration_ms", 101),
            ("preowner_observation_duration_ms", 4001),
            ("receiver_gated", False),
            ("atomic_boot_claim_required", False),
            ("host_management_or_data_tx_allowed", True),
            ("owner_epoch_fields", []),
            ("expected_arm_helper_source_sha256", "0" * 64),
            ("source_sha256", {}),
            ("preowner_observation_contract", {}),
            ("sender", {}),
        )
        for key, value in invalid_cases:
            with self.subTest(field=key):
                mutated = copy.deepcopy(self.metadata)
                mutated[key] = value
                self.assertTrue(self._private_errors(mutated), key)

        binding_cases = (
            ("build_receipt_sha256", "0" * 64),
            ("source_file_count", -1),
            ("source_sha256_map_sha256", "0" * 64),
            ("expected_binary_sha256", "invalid-sha"),
            ("expected_info_plist_sha256", "invalid-sha"),
            ("candidate", "wrong candidate"),
            ("profile", "wrong profile"),
        )
        for key, value in binding_cases:
            with self.subTest(source_binding=key):
                mutated = copy.deepcopy(self.metadata)
                mutated["source_binding"][key] = value
                self.assertTrue(self._private_errors(mutated), key)

        preowner_cases = (
            ("schema", 2),
            ("duration_ms", 3000),
            ("property", "wrong-property"),
            ("published_property", "wrong-property"),
            ("revision_property", "wrong-property"),
            ("schema_property", "wrong-property"),
            ("arm_accepted_property", "wrong-property"),
        )
        for key, value in preowner_cases:
            with self.subTest(preowner_contract=key):
                mutated = copy.deepcopy(self.metadata)
                mutated["preowner_observation_contract"][key] = value
                self.assertTrue(self._private_errors(mutated), key)

    def test_private_gate_rejects_stale_boot_and_changed_receipt(self):
        errors = self._private_errors(
            boot_epoch=self.metadata["minimum_boot_epoch_exclusive"])
        self.assertIn("fresh_boot_required", errors)
        errors = self._private_errors(actual_receipt_sha="0" * 64)
        self.assertIn("frozen_build_receipt_changed", errors)

    def test_bundle_binding_rejects_well_formed_but_wrong_artifact_hashes(self):
        original_read = self.binding.read_private
        for key in ("expected_binary_sha256", "expected_info_plist_sha256"):
            with self.subTest(source_binding=key):
                mutated = copy.deepcopy(self.metadata)
                current = mutated["source_binding"][key]
                mutated["source_binding"][key] = (
                    "0" * 64 if current != "0" * 64 else "1" * 64)
                mutated_raw = json.dumps(
                    mutated, sort_keys=True, separators=(",", ":")).encode()

                def read_with_mutated_metadata(path):
                    if Path(path) == self.binding.METADATA:
                        return mutated, mutated_raw
                    return original_read(path)

                with patch.object(self.binding, "read_private",
                                  side_effect=read_with_mutated_metadata):
                    with self.assertRaises(self.binding.BindingError):
                        self.binding.validate_bundle(self.binding.METADATA)

    def test_real_worker_contract_is_the_seven_zero_tx_counters(self):
        native_capture = ROOT / "developer-tools/test086/capture_test086_receive149_once.py"
        native_worker = ROOT / "developer-tools/test087/native_controlled_capture.py"
        tx_zero = _literal_assignment(native_capture, "TX_ZERO_COUNTERS")
        data_tx_counter = _literal_assignment(native_worker, "DATA_TX_COUNTER")
        data_tx_pending = _literal_assignment(native_worker, "DATA_TX_PENDING")
        expected = [*tx_zero, data_tx_counter, data_tx_pending]
        self.assertEqual(len(expected), 7)
        self.assertEqual(self.metadata["required_zero_host_tx_counters"], expected)

    def test_full_gate_passes_only_with_all_seven_numeric_zero_counters(self):
        counters = {key: 0 for key in self.metadata["required_zero_host_tx_counters"]}
        self.assertEqual(self._full_gate_errors(counters=counters), [])

    def test_full_gate_rejects_each_nonzero_or_missing_counter(self):
        required = self.metadata["required_zero_host_tx_counters"]
        for key in required:
            with self.subTest(counter=key, value=1):
                counters = {item: 0 for item in required}
                counters[key] = 1
                self.assertIn("host_tx_nonzero_or_missing:" + key,
                              self._full_gate_errors(counters=counters))
            with self.subTest(counter=key, value="missing"):
                counters = {item: 0 for item in required if item != key}
                self.assertIn("host_tx_nonzero_or_missing:" + key,
                              self._full_gate_errors(counters=counters))
        counters = {key: 0 for key in required}
        counters[required[0]] = True
        self.assertIn("host_tx_nonzero_or_missing:" + required[0],
                      self._full_gate_errors(counters=counters))

    def test_full_gate_rejects_missing_claim_and_each_readiness_gate(self):
        required = self.metadata["required_zero_host_tx_counters"]
        counters = {key: 0 for key in required}
        cases = (
            ("shared_boot_claim_unavailable", {"claim": False}),
            ("router_sender_ready", {"router": False}),
            ("native_preflight_ready", {"native": False}),
            ("listener_ready", {"listener": False}),
        )
        for expected_error, kwargs in cases:
            with self.subTest(gate=expected_error):
                self.assertIn(expected_error,
                              self._full_gate_errors(counters=counters, **kwargs))


if __name__ == "__main__":
    unittest.main()
