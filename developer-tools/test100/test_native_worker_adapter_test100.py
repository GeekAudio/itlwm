from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parent
ADAPTER_PATH = TOOL_DIR / "native_controlled_capture_test100.py"
SPEC = importlib.util.spec_from_file_location(
    "test100_native_worker_adapter_under_test", ADAPTER_PATH)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def metadata_fixture(protocol):
    source_map = {"native/test100-fixture.cpp": "a" * 64}
    receipt_sha = "b" * 64
    profile = "native_awdl_rx149_preowner_observation"
    candidate = "25G332-Test100"
    metadata = {
        "schema": protocol.candidate_binding.METADATA_SCHEMA,
        "candidate": candidate,
        "source_ready_kind": protocol.SOURCE_KIND,
        "requires_phone_ready": False,
        "armed": False,
        "status": "prepared_disarmed",
        "retry_allowed": False,
        "expected_loaded_uuid": "09726FCA-F27F-349B-A5AD-F1B58B11DF3E",
        "profile": profile,
        "diagnostic_duration_ms": 100,
        "preowner_observation_duration_ms": 4000,
        "receiver_gated": True,
        "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
        "minimum_boot_epoch_exclusive": 10,
        "owner_epoch_fields": list(protocol.OWNER_EPOCH_FIELDS),
        "expected_arm_helper_source_sha256": hashlib.sha256(
            adapter.TEST100_ARM_HELPER.read_bytes()).hexdigest(),
        "source_sha256": source_map,
        "source_binding": {
            "build_receipt_sha256": receipt_sha,
            "source_file_count": len(source_map),
            "source_sha256_map_sha256": protocol.candidate_binding.canonical_json_sha256(source_map),
            "expected_binary_sha256": "c" * 64,
            "expected_info_plist_sha256": "d" * 64,
            "candidate": candidate,
            "profile": profile,
        },
        "preowner_observation_contract": {
            "schema": 1,
            "duration_ms": 4000,
            "property": "NativeRxPreOwnerSnapshot",
            "published_property": "NativeRxPreOwnerPublished",
            "revision_property": "NativeRxPreOwnerRevision",
            "schema_property": "NativeRxPreOwnerSchema",
            "arm_accepted_property": "NativeRxPreOwnerArmAccepted",
        },
        "sender": {
            "frames_max": 4,
            "interval_ms": 10,
            "max_elapsed_seconds": 0.04,
        },
    }

    return metadata, receipt_sha


class NativeWorkerAdapterTests(unittest.TestCase):
    def test_hooks_are_installed_in_actual_worker_function_globals(self):
        worker = adapter.load_test087_worker()
        captured_commands = []
        run_token = "0123456789abcdef0123456789abcdef"
        worker._wait_for_helper_gate = lambda: ("ARM", run_token)

        adapter.configure_worker(worker.__dict__)

        self.assertIs(worker.main.__globals__, worker.__dict__)
        self.assertIs(worker._native_preflight.__globals__, worker.__dict__)
        self.assertEqual(worker.HELPER_SOURCE, adapter.TEST100_ARM_HELPER)
        self.assertEqual(worker._wait_for_helper_gate(), ("ARM", run_token))

        with mock.patch.object(adapter._subprocess, "run",
                               side_effect=lambda command, *args, **kwargs:
                               captured_commands.append(command) or object()):
            worker.subprocess.run([
                "/tmp/arm-p2p-rx149", "--expect-build", "Test100"])
        self.assertEqual(captured_commands, [[
            "/tmp/arm-p2p-rx149", "--expect-build", "Test100",
            "--run-token", run_token]])

    def test_nested_test087_helper_loader_uses_test100_source(self):
        worker = adapter.load_test087_worker()
        adapter.configure_worker(worker.__dict__)

        nested = worker._load_module(
            "test087_controlled_protocol",
            worker.TOOL_DIR / "test087_controlled.py")

        self.assertEqual(nested.HELPER_SOURCE, adapter.TEST100_ARM_HELPER)
        self.assertEqual(nested.SENDER_FRAMES, 4)
        self.assertEqual(nested.SENDER_INTERVAL_MS, 10)
        self.assertEqual(nested.FROZEN_METADATA_SENDER_INTERVAL_MS, 10)
        self.assertEqual(nested.SENDER_DEADLINE_SECONDS, 0.04)

    def test_real_worker_protocol_accepts_test100_metadata_and_rejects_legacy(self):
        worker = adapter.load_test087_worker()
        adapter.configure_worker(worker.__dict__)
        protocol = worker._load_module(
            "test087_controlled_protocol",
            worker.TOOL_DIR / "test087_controlled.py")

        metadata, receipt_sha = metadata_fixture(protocol)

        kwargs = {
            "boot_epoch": 11,
            "expected_receipt_sha256": receipt_sha,
            "actual_receipt_sha256": receipt_sha,
        }
        self.assertEqual(protocol.validate_private_metadata(metadata, **kwargs), [])

        legacy = json.loads(json.dumps(metadata))
        legacy["sender"] = {"frames_max": 16, "interval_ms": 80, "max_elapsed_seconds": 2.0}
        self.assertEqual(set(protocol.validate_private_metadata(legacy, **kwargs)), {
            "sender_deadline", "sender_frame_limit", "sender_interval",
        })

        missing_hash = json.loads(json.dumps(metadata))
        missing_hash.pop("expected_arm_helper_source_sha256")
        self.assertIn("arm_helper_source_hash",
                      protocol.validate_private_metadata(missing_hash, **kwargs))


if __name__ == "__main__":
    unittest.main()
