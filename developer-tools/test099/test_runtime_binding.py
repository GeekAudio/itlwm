from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parent
MODULE_PATH = TOOL_DIR / "runtime_binding.py"
SPEC = importlib.util.spec_from_file_location(
    "test099_runtime_binding_under_test", MODULE_PATH)
assert SPEC and SPEC.loader
runtime_binding = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime_binding
SPEC.loader.exec_module(runtime_binding)


BASE_CONTRACT = {
    "window_us": 4_000_000,
    "numeric_only": True,
    "rx_policy_changed": False,
    "tx_policy_changed": False,
    "schema_version": 1,
    "snapshot_property": "NativeRxPreOwnerSnapshot",
}


def expected_contract() -> dict:
    return {**BASE_CONTRACT, **runtime_binding.PUBLICATION_FIELDS}


def metadata_for(contract: dict | None = None, helper: Path | None = None) -> dict:
    helper = helper or Path("/unused/test099-helper.swift")
    return {
        "candidate": "25G332-Test099",
        "expected_loaded_uuid": "01234567-89AB-CDEF-0123-456789ABCDEF",
        "status": "prepared_disarmed",
        "armed": False,
        "preowner_observation_contract": dict(
            contract if contract is not None else expected_contract()),
        "expected_arm_helper_source_sha256": hashlib.sha256(
            helper.read_bytes()).hexdigest() if helper.is_file() else "a" * 64,
        "sender": dict(runtime_binding.SENDER_CONTRACT),
    }


class RuntimeBindingContractTests(unittest.TestCase):
    def test_metadata_generation_adds_all_seven_publication_fields(self):
        with tempfile.TemporaryDirectory(prefix="test099-binding-generation-") as temp:
            root = Path(temp)
            build_path = root / "build.json"
            baseline_path = root / "baseline.json"
            build_path.write_text("{}\n")
            baseline_path.write_text("{}\n")
            helper = root / "arm-helper.swift"
            helper.write_text("// offline fixture\n")

            build = {
                "candidate": "25G332-Test099",
                "rx_preowner_observation_contract": dict(BASE_CONTRACT),
            }
            baseline = {"candidate": "25G332-Test098"}

            class FakeBinding:
                @staticmethod
                def validate_metadata_binding(*args, **kwargs):
                    return []

            class FakeFinalizer:
                candidate_binding = FakeBinding()

                @staticmethod
                def build_metadata(**kwargs):
                    return {
                        "candidate": "25G332-Test099",
                        "expected_loaded_uuid": "01234567-89AB-CDEF-0123-456789ABCDEF",
                        "status": "prepared_disarmed",
                        "armed": False,
                        "preowner_observation_contract": dict(BASE_CONTRACT),
                    }

                @staticmethod
                def validate_receipts(**kwargs):
                    return build, b"build", baseline, b"baseline"

                @staticmethod
                def _paths(*args, **kwargs):
                    return root, build_path, baseline_path, root / "runtime"

            with mock.patch.object(runtime_binding, "_finalizer",
                                   return_value=FakeFinalizer()), \
                    mock.patch.object(runtime_binding, "TEST099_HELPER", helper):
                result = runtime_binding.build_disarmed_metadata(
                    minimum_boot_epoch_exclusive=1_793_460_000,
                    iwn_root=root,
                    candidate="25G332-Test099",
                    build_receipt=build_path,
                    baseline_receipt=baseline_path,
                )

            self.assertEqual(result["preowner_observation_contract"],
                             expected_contract())
            self.assertEqual(len(runtime_binding.PUBLICATION_FIELDS), 7)
            self.assertFalse(result["armed"])
            self.assertEqual(result["status"], "prepared_disarmed")
            self.assertEqual(result["sender"], runtime_binding.SENDER_CONTRACT)

    def test_prearm_rejects_each_publication_mismatch_before_claim_or_run_dir(self):
        for field, bad_value in runtime_binding.PUBLICATION_FIELDS.items():
            with self.subTest(field=field), \
                    tempfile.TemporaryDirectory(
                        prefix="test099-binding-prearm-") as temp:
                root = Path(temp)
                metadata_path = root / "metadata.json"
                helper = root / "arm-helper.swift"
                helper.write_text("// offline fixture\n")
                claim_root = root / "ObservationClaims" / "BootGlobal"
                run_root = root / "test099-runtime-private" / "run-dir"

                contract = expected_contract()
                contract[field] = not bad_value if isinstance(bad_value, bool) else (
                    bad_value + 1 if isinstance(bad_value, int) else "mismatch")
                metadata = metadata_for(contract, helper)
                metadata_path.write_text(json.dumps(metadata) + "\n")

                build = {"rx_preowner_observation_contract": dict(BASE_CONTRACT)}
                calls = []
                protocol = types.SimpleNamespace(
                    HELPER_SOURCE=Path("/previous/test087-helper.swift"),
                    SENDER_FRAMES=16, SENDER_INTERVAL_MS=80,
                    FROZEN_METADATA_SENDER_INTERVAL_MS=80,
                    SENDER_DEADLINE_SECONDS=2.0)

                class FakeCoordinator:
                    IWN_ROOT = root

                    @staticmethod
                    def _modules():
                        return protocol, object()

                    @staticmethod
                    def _validate_bundle(path, owner_uid, protocol):
                        calls.append("validate_bundle")
                        self.assertEqual(protocol.SENDER_FRAMES, 4)
                        self.assertEqual(protocol.SENDER_INTERVAL_MS, 10)
                        self.assertEqual(protocol.FROZEN_METADATA_SENDER_INTERVAL_MS, 10)
                        self.assertEqual(protocol.SENDER_DEADLINE_SECONDS, 0.04)
                        self.assertEqual(protocol.HELPER_SOURCE, helper)
                        self.assertFalse(claim_root.exists())
                        self.assertFalse(run_root.exists())
                        return metadata, build, "receipt-sha", root / "build.json"

                with mock.patch.object(runtime_binding, "_load_module",
                                       return_value=FakeCoordinator), \
                        mock.patch.object(runtime_binding, "TEST099_HELPER", helper):
                    with self.assertRaises(runtime_binding.RuntimeBindingError) as error:
                        runtime_binding.validate_prearm_bundle(
                            metadata_path, iwn_root=root)

                self.assertIn("preowner_observation_contract_mismatch",
                              str(error.exception))
                self.assertEqual(calls, ["validate_bundle"])
                self.assertEqual(protocol.SENDER_FRAMES, 16)
                self.assertEqual(protocol.SENDER_INTERVAL_MS, 80)
                self.assertEqual(protocol.FROZEN_METADATA_SENDER_INTERVAL_MS, 80)
                self.assertEqual(protocol.SENDER_DEADLINE_SECONDS, 2.0)
                self.assertEqual(protocol.HELPER_SOURCE,
                                 Path("/previous/test087-helper.swift"))
                self.assertFalse(claim_root.exists())
                self.assertFalse(run_root.exists())

    def test_valid_prearm_is_read_only_and_reports_no_claim_or_run_directory(self):
        with tempfile.TemporaryDirectory(prefix="test099-binding-prearm-valid-") as temp:
            root = Path(temp)
            metadata_path = root / "metadata.json"
            helper = root / "arm-helper.swift"
            helper.write_text("// offline fixture\n")
            metadata = metadata_for(helper=helper)
            metadata_path.write_text(json.dumps(metadata) + "\n")
            build = {"rx_preowner_observation_contract": dict(BASE_CONTRACT)}
            claim_root = root / "ObservationClaims" / "BootGlobal"
            run_root = root / "test099-runtime-private" / "run-dir"
            protocol = types.SimpleNamespace(
                HELPER_SOURCE=Path("/previous/test087-helper.swift"),
                SENDER_FRAMES=16, SENDER_INTERVAL_MS=80,
                FROZEN_METADATA_SENDER_INTERVAL_MS=80,
                SENDER_DEADLINE_SECONDS=2.0)

            class FakeCoordinator:
                IWN_ROOT = root

                @staticmethod
                def _modules():
                    return protocol, object()

                @staticmethod
                def _validate_bundle(path, owner_uid, protocol):
                    self.assertEqual(protocol.SENDER_FRAMES, 4)
                    self.assertEqual(protocol.SENDER_INTERVAL_MS, 10)
                    self.assertEqual(protocol.FROZEN_METADATA_SENDER_INTERVAL_MS, 10)
                    self.assertEqual(protocol.SENDER_DEADLINE_SECONDS, 0.04)
                    self.assertEqual(protocol.HELPER_SOURCE, helper)
                    self.assertFalse(claim_root.exists())
                    self.assertFalse(run_root.exists())
                    return metadata, build, "receipt-sha", root / "build.json"

            with mock.patch.object(runtime_binding, "_load_module",
                                   return_value=FakeCoordinator), \
                    mock.patch.object(runtime_binding, "TEST099_HELPER", helper):
                result = runtime_binding.validate_prearm_bundle(
                    metadata_path, iwn_root=root)

            self.assertEqual(result["status"], "prearm_binding_validated")
            self.assertFalse(result["claim_consumed"])
            self.assertFalse(result["run_directory_created"])
            self.assertEqual(protocol.SENDER_FRAMES, 16)
            self.assertEqual(protocol.SENDER_INTERVAL_MS, 80)
            self.assertEqual(protocol.FROZEN_METADATA_SENDER_INTERVAL_MS, 80)
            self.assertEqual(protocol.SENDER_DEADLINE_SECONDS, 2.0)
            self.assertEqual(protocol.HELPER_SOURCE,
                             Path("/previous/test087-helper.swift"))
            self.assertFalse(claim_root.exists())
            self.assertFalse(run_root.exists())


if __name__ == "__main__":
    unittest.main()
