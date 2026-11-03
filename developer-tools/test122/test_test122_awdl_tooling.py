#!/usr/bin/env python3
"""Offline negative and identity tests for the Test122 RX149 adapters.

These tests never start a router session, send frames, arm the driver, change
EFI, or write a disarmed metadata bundle. The preflight test calls the actual
Test121 worker after the Test122 instrumentation has been applied, while
mocking only external identity commands and the final claim-availability read.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = Path(__file__).resolve().parent
BINDING_PATH = TOOL_DIR / "rx149_binding_test122.py"
COORDINATOR_PATH = TOOL_DIR / "coordinate_test122_rx149.py"
WORKER_ADAPTER_PATH = TOOL_DIR / "native_controlled_capture_test122.py"
TEST121_CANDIDATE = "25G332-Test121"
TEST121_METADATA_SCHEMA = (
    "test121-native-awdl-rx149-controlled-probe-private/v1")
TEST121_SOURCE_SCHEMA = "test121-actual-build-binding/v1"


def load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("test122_fixture_missing:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test122_fixture_unloadable:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COORDINATOR = load_module("test122_offline_test_coordinator", COORDINATOR_PATH)
BINDING = COORDINATOR.BINDING


def mock_dwarfdump(expected_uuid: str):
    def run(args, **kwargs):
        if args and Path(str(args[0])).name == "xcrun":
            return subprocess.CompletedProcess(
                args, 0, stdout=f"UUID: {expected_uuid} (x86_64)\n", stderr="")
        return _REAL_SUBPROCESS_RUN(args, **kwargs)
    return run


_REAL_SUBPROCESS_RUN = subprocess.run


class Test122OfflineBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata_path = BINDING.METADATA
        cls.metadata_existed = cls.metadata_path.exists()
        cls.metadata_stat = (cls.metadata_path.stat() if cls.metadata_existed
                             else None)
        required_receipts = (
            BINDING.BUILD_RECEIPT, BINDING.DEPLOYMENT_RECEIPT,
            BINDING.SOURCE_COMMIT_RECEIPT, BINDING.PRODUCTION_FREEZE,
            BINDING.BUILD_INPUT_BEFORE, BINDING.BUILD_INPUT_AFTER,
            BINDING.SENDER_RECEIPT, BINDING.ORIGINAL_SENDER_RECEIPT,
        )
        cls.private_receipts_available = all(
            not p.is_symlink() and p.is_file() for p in required_receipts)
        cls.synthetic_metadata = {
            "schema": "test122-native-awdl-rx149-controlled-probe-private/v1",
            "candidate": BINDING.CANDIDATE,
            "profile": BINDING.PROFILE,
            "status": "prepared_disarmed",
            "armed": False,
            "retry_allowed": False,
            "host_management_or_data_tx_allowed": False,
            "source_binding": {
                "schema": "test122-actual-build-binding/v1",
                "build_receipt_sha256": "a" * 64,
                "production_freeze_source_sha256": {},
            },
        }
        cls.metadata = copy.deepcopy(cls.synthetic_metadata)
        cls.metadata_raw = json.dumps(
            cls.metadata, sort_keys=True, ensure_ascii=False).encode("utf-8")
        cls.build = None
        cls.build_raw = b"synthetic-build-receipt"
        cls.expected_uuid = "17DB1FD2-214C-30A1-825C-C841B5F9E80B"
        if cls.private_receipts_available:
            cls.build, cls.build_raw = BINDING.read_private(BINDING.BUILD_RECEIPT)
            cls.expected_uuid = cls.build["mach_o_uuid"]
            with mock.patch.object(
                    BINDING.T121.subprocess, "run",
                    side_effect=mock_dwarfdump(cls.expected_uuid)):
                cls.metadata = BINDING.build_disarmed_metadata(
                    minimum_boot_epoch_exclusive=1)
            cls.metadata_raw = json.dumps(
                cls.metadata, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def require_private_receipts(self):
        if not self.private_receipts_available:
            self.skipTest("requires owner-only RuntimeTest122/RuntimeTest121 receipts")

    def test_build_is_candidate_bound_disarmed_and_100ms(self):
        self.require_private_receipts()
        metadata = self.metadata
        self.assertEqual(metadata["candidate"], "25G332-Test122")
        self.assertEqual(metadata["schema"],
                         "test122-native-awdl-rx149-controlled-probe-private/v1")
        self.assertEqual(metadata["source_binding"]["schema"],
                         "test122-actual-build-binding/v1")
        self.assertEqual(metadata["expected_loaded_uuid"], self.expected_uuid)
        self.assertIs(metadata["armed"], False)
        self.assertIs(metadata["retry_allowed"], False)
        self.assertIs(metadata["host_management_or_data_tx_allowed"], False)
        self.assertIs(metadata["atomic_boot_claim_required"], True)
        self.assertEqual(metadata["diagnostic_duration_ms"], 100)
        self.assertEqual(metadata["preowner_observation_duration_ms"], 4000)
        self.assertEqual(metadata["rx149_data_input_contract"]["session_duration_ms"], 100)
        self.assertEqual(metadata["rx149_data_input_contract"]["sender_frames_max"], 4)
        self.assertIs(metadata["peer_receipt_proven"], False)
        self.assertIs(metadata["native_awdl_reply_proven"], False)
        self.assertIs(metadata["airdrop_proven"], False)
        self.assertEqual(BINDING.METADATA.exists(), self.metadata_existed)
        if self.metadata_existed:
            self.assertEqual(BINDING.METADATA.stat().st_mtime_ns,
                             self.metadata_stat.st_mtime_ns)

    def test_plan_and_default_invocation_are_inert(self):
        sentinels = (BINDING.METADATA, BINDING.RUNTIME_HANDOFF)
        before = {p: (p.exists(), p.stat().st_mtime_ns if p.exists() else None)
                  for p in sentinels}
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for args in ([], ["--plan"]):
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-B", str(COORDINATOR_PATH), *args],
                    cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, check=False, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                plan = json.loads(result.stdout)
                self.assertEqual(plan["candidate"], "25G332-Test122")
                self.assertEqual(plan["default_action"], "plan_only")
                self.assertIs(plan["armed"], False)
                self.assertIs(plan["router_contacted"], False)
                self.assertIs(plan["rf_triggered"], False)
                self.assertIs(plan["efi_modified"], False)
                self.assertIs(plan["peer_receipt_proven"], False)
                self.assertIs(plan["native_awdl_reply_proven"], False)
                self.assertIs(plan["airdrop_proven"], False)
                self.assertEqual(plan["driver_lease_ms"], 100)
        after = {p: (p.exists(), p.stat().st_mtime_ns if p.exists() else None)
                 for p in sentinels}
        self.assertEqual(after, before)

    def test_coordinator_rebinds_all_runtime_paths_and_reused_sender(self):
        self.require_private_receipts()
        script = r'''import importlib.util, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("test122_config_probe", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module._configure_test122_run()
b = module.BINDING
r = module.RUNNER
sender, _raw, binding = b._sender_binding()
hashes = r.runtime_tool_hashes()
result = {
  "candidate": r.CANDIDATE,
  "profile": r.PROFILE,
  "iwn_root_is_t122": r.IWN_ROOT == b.IWN_ROOT.resolve(strict=True),
  "metadata_is_t122": r.DEFAULT_METADATA == b.METADATA,
  "build_is_t122": r.BUILD_RECEIPT == b.BUILD_RECEIPT,
  "deployment_is_t122": r.DEPLOYMENT_RECEIPT == b.DEPLOYMENT_RECEIPT,
  "sender_receipt_is_t122_reuse": r.SENDER_BUILD_RECEIPT == b.SENDER_RECEIPT,
  "sender_binary_is_t121": r.SENDER_BINARY == pathlib.Path(sender["binary_path"]).resolve(strict=True),
  "sender_hash_matches_reuse": r.SENDER_SHA256 == binding["binary_sha256"],
  "sender_marked_reused": binding["reused_from"] == "25G332-Test121" and binding["newly_compiled_for_test122"] is False,
  "result_name": r.RESULT_NAME,
  "capture_name": r.CAPTURE_NAME,
  "worker_is_t122": r.NATIVE_WORKER == module.NATIVE_WORKER,
  "runtime_binding_candidate": r.RUNTIME_BINDING.CANDIDATE,
  "runtime_schema": r.RUNTIME_BINDING.METADATA_SCHEMA,
  "protocol_schema": r.PROTOCOL.candidate_binding.METADATA_SCHEMA,
  "sender_contract_matches": r.RUNTIME_BINDING.SENDER_CONTRACT == b.SENDER_CONTRACT,
  "run_dir_is_t122": r.test104_run_dir(2, "ignored") == b.METADATA.parent / "test122-tools-boot2",
  "t122_coordinator_hashed": any(k.endswith("developer-tools/test122/coordinate_test122_rx149.py") for k in hashes),
  "t122_binding_hashed": any(k.endswith("developer-tools/test122/rx149_binding_test122.py") for k in hashes),
  "t122_worker_hashed": any(k.endswith("developer-tools/test122/native_controlled_capture_test122.py") for k in hashes),
  "t121_sender_source_hashed": any(k.endswith("developer-tools/test121/awdl_unicast_sender_test121.c") for k in hashes),
}
print(json.dumps(result, sort_keys=True))
'''
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(COORDINATOR_PATH)],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False, timeout=40,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout)
        self.assertEqual(values["candidate"], "25G332-Test122")
        self.assertEqual(values["profile"], BINDING.PROFILE)
        for key in (
                "iwn_root_is_t122", "metadata_is_t122", "build_is_t122",
                "deployment_is_t122", "sender_receipt_is_t122_reuse",
                "sender_binary_is_t121", "sender_hash_matches_reuse",
                "sender_marked_reused", "worker_is_t122",
                "sender_contract_matches", "t122_coordinator_hashed",
                "t122_binding_hashed", "t122_worker_hashed",
                "t121_sender_source_hashed"):
            self.assertIs(values[key], True, key)
        self.assertEqual(values["result_name"], "test122-tools-private.json")
        self.assertEqual(values["capture_name"],
                         "native-controlled-capture-private.json")
        self.assertEqual(values["runtime_binding_candidate"],
                         "25G332-Test122")
        self.assertEqual(values["runtime_schema"], BINDING.METADATA_SCHEMA)
        self.assertEqual(values["protocol_schema"], BINDING.METADATA_SCHEMA)
        self.assertIs(values["run_dir_is_t122"], True)

    def test_profile_configurator_uses_actual_router_and_restores_three_caps(self):
        self.require_private_receipts()
        COORDINATOR._configure_test122_run()
        runner = COORDINATOR.RUNNER
        self.assertIs(runner.ROUTER, runner.TEST088.ROUTER)
        readers = (runner.BASE, runner.TEST088.ROUTER, runner.TEST088)
        original_limits = tuple(reader.MAX_LINE_BYTES for reader in readers)
        self.assertEqual(len(original_limits), 3)

        restore = runner.configure_test104_profile()
        try:
            expected = COORDINATOR.T121.DUAL_PROTOCOL.MAX_LINE_BYTES
            self.assertEqual(tuple(reader.MAX_LINE_BYTES for reader in readers),
                             (expected, expected, expected))
            self.assertEqual(expected, 128 * 1024)
        finally:
            restore()
        self.assertEqual(tuple(reader.MAX_LINE_BYTES for reader in readers),
                         original_limits)

    def test_sender_reuse_is_bound_to_t121_sources_and_binary(self):
        self.require_private_receipts()
        receipt, raw, sender = BINDING._sender_binding()
        self.assertEqual(receipt["candidate"], "25G332-Test122")
        self.assertEqual(sender["reused_from"], TEST121_CANDIDATE)
        self.assertIs(sender["newly_compiled_for_test122"], False)
        self.assertEqual(sender["binary_sha256"], receipt["binary_sha256"])
        self.assertEqual(sender["sender_receipt_sha256"],
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual(sender["source_path"],
                         "developer-tools/test121/awdl_unicast_sender_test121.c")
        self.assertEqual(sender["protocol_schema"],
                         "test121-dual-socket-sender/v1")
        self.assertIs(sender["rf_ack_peer_proven"], False)

    def test_sender_reuse_rejects_changed_original_receipt_hash(self):
        self.require_private_receipts()
        original_read = BINDING.read_private

        def altered_original(path: Path):
            value, raw = original_read(Path(path))
            if Path(path) == BINDING.ORIGINAL_SENDER_RECEIPT:
                return value, raw + b"tampered"
            return value, raw

        with mock.patch.object(BINDING, "read_private", side_effect=altered_original):
            with self.assertRaisesRegex(BINDING.BindingError,
                                        "test122_sender_reuse_receipt_invalid"):
                BINDING._sender_binding()

    def test_test121_metadata_path_is_rejected(self):
        old_path = (BINDING.IWN_ROOT / "RuntimeTest121/research/"
                    "runtime-current-private/awdl-preparation/"
                    "native-controlled-probe-private.json")
        with self.assertRaisesRegex(BINDING.BindingError,
                                    "test122_metadata_path_mismatch"):
            BINDING.validate_bundle(old_path)

    def test_old_candidate_or_schema_is_rejected_before_frozen_validator(self):
        old = copy.deepcopy(self.synthetic_metadata)
        old["candidate"] = TEST121_CANDIDATE
        old["schema"] = TEST121_METADATA_SCHEMA
        old["source_binding"]["schema"] = TEST121_SOURCE_SCHEMA
        with mock.patch.object(BINDING, "read_private",
                               return_value=(old, b"old-test121-document")), \
             mock.patch.object(BINDING, "_ORIGINAL_VALIDATE_BUNDLE") as frozen:
            with self.assertRaisesRegex(BINDING.BindingError,
                                        "test122_disarmed_bundle_invalid"):
                BINDING.validate_bundle(BINDING.METADATA)
            frozen.assert_not_called()

    def test_schema_bridge_is_in_memory_and_restores_read_hook_on_success(self):
        original_read = BINDING.T121.read_private
        raw = self.metadata_raw

        def fake_read(path: Path):
            return copy.deepcopy(self.metadata), raw

        def fake_frozen_validator(path: Path):
            translated, translated_raw = BINDING.T121.read_private(path)
            self.assertEqual(translated["schema"], TEST121_METADATA_SCHEMA)
            self.assertEqual(translated["source_binding"]["schema"],
                             TEST121_SOURCE_SCHEMA)
            self.assertEqual(translated_raw, raw)
            return translated, self.build, self.build_raw, BINDING.BUILD_RECEIPT

        try:
            BINDING.T121.read_private = fake_read
            with mock.patch.object(BINDING, "read_private", side_effect=fake_read), \
                 mock.patch.object(BINDING, "_ORIGINAL_VALIDATE_BUNDLE",
                                   side_effect=fake_frozen_validator):
                validated, _build, _build_raw, _build_path = BINDING.validate_bundle(
                    BINDING.METADATA)
            self.assertIs(BINDING.T121.read_private, fake_read)
            self.assertEqual(validated["schema"],
                             "test122-native-awdl-rx149-controlled-probe-private/v1")
            self.assertEqual(validated["source_binding"]["schema"],
                             "test122-actual-build-binding/v1")
        finally:
            BINDING.T121.read_private = original_read

    def test_schema_bridge_restores_read_hook_when_frozen_validator_fails(self):
        original_read = BINDING.T121.read_private
        raw = self.metadata_raw

        def fake_read(path: Path):
            return copy.deepcopy(self.metadata), raw

        def failing_frozen_validator(path: Path):
            translated, translated_raw = BINDING.T121.read_private(path)
            self.assertEqual(translated["schema"], TEST121_METADATA_SCHEMA)
            self.assertEqual(translated_raw, raw)
            raise RuntimeError("frozen-validator-sentinel")

        try:
            BINDING.T121.read_private = fake_read
            with mock.patch.object(BINDING, "read_private", side_effect=fake_read), \
                 mock.patch.object(BINDING, "_ORIGINAL_VALIDATE_BUNDLE",
                                   side_effect=failing_frozen_validator):
                with self.assertRaisesRegex(RuntimeError,
                                            "frozen-validator-sentinel"):
                    BINDING.validate_bundle(BINDING.METADATA)
            self.assertIs(BINDING.T121.read_private, fake_read)
        finally:
            BINDING.T121.read_private = original_read

    def test_instrumented_preflight_reaches_test122_archive_uuid_check(self):
        self.require_private_receipts()
        adapter = load_module("test122_offline_test_worker_adapter",
                              WORKER_ADAPTER_PATH)
        worker_loader = adapter._WORKER
        test104 = worker_loader._load(
            "test122_offline_preflight_test104",
            worker_loader.TEST104_WORKER_PATH)
        worker_loader._instrument_worker(test104, adapter.BINDING.IWN_ROOT)
        worker = test104.load_test087_worker()
        test104.configure_worker(worker.__dict__,
                                 iwn_root=adapter.BINDING.IWN_ROOT)

        build, build_raw = adapter.BINDING.read_private(
            adapter.BINDING.BUILD_RECEIPT)
        uuid = build["mach_o_uuid"]
        metadata = adapter.BINDING.build_disarmed_metadata(
            minimum_boot_epoch_exclusive=1)
        source_binding = metadata["source_binding"]
        self.assertEqual(source_binding["build_receipt_sha256"],
                         hashlib.sha256(build_raw).hexdigest())

        class Capture:
            def __init__(self):
                self.initial = {
                    "NativeTestBuild": adapter.BINDING.CANDIDATE,
                    "NativePowerReady": 1,
                    "NativeRxPreOwnerObservation": True,
                    "NativeP2PManualArmed": 0,
                    "NativeP2PProbeAttempted": 0,
                    "NativeP2PProbeResourceMayExist": 0,
                    worker.PREOWNER_ARM_ACCEPTED_KEY: 0,
                    worker.PREOWNER_PUBLISHED_KEY: 0,
                    worker.DATA_TX_PENDING: 0,
                    "NativeAwdlDataTxSubmitted": 0,
                }

            def properties(self, service):
                if service == "IOPCIEDeviceWrapper":
                    return {"NativeTestBuild": adapter.BINDING.CANDIDATE}
                if service == "AirportItlwm":
                    return dict(self.initial)
                raise AssertionError("unexpected IOKit service read")

            @staticmethod
            def profile_problems(_properties, *, selected):
                return []

            @staticmethod
            def awdl_data_rx_snapshot(_properties):
                return {"complete": True}

            @staticmethod
            def awdl_data_rx149_receipt_snapshot(_properties):
                return {"complete": True}

            @staticmethod
            def receipt_preflight_problem(_receipt):
                return None

            @staticmethod
            def tx_zero_evidence(_before, _after):
                return {"valid": True}

        capture = Capture()
        template = {
            "candidate": adapter.BINDING.CANDIDATE,
            "profile": adapter.BINDING.PROFILE,
            "status": "prepared_disarmed",
            "armed": False,
            "retry_allowed": False,
            "minimum_boot_epoch_exclusive": 1,
            "expected_loaded_uuid": uuid,
        }
        archive_verifier = adapter.BINDING._verify_archive
        with mock.patch.object(
                adapter.BINDING.T121.subprocess, "run",
                side_effect=mock_dwarfdump(uuid)), \
             mock.patch.object(adapter.BINDING, "_verify_archive",
                               wraps=archive_verifier) as archive_spy, \
             mock.patch.object(
                 worker.subprocess, "check_output",
                 return_value=("org.geekaudio.AirportItlwm (Test122) " +
                               uuid + "\n")), \
             mock.patch.object(worker, "_validate_tx_zero",
                               return_value={"valid": True}), \
             mock.patch.object(worker, "_claim_availability",
                               return_value={"available": True}) as claim:
            result = worker._native_preflight(
                template, source_binding, {}, Path("/offline/build"),
                adapter.BINDING.DEPLOYMENT_RECEIPT, 2, object(), capture,
                object(), build, build_raw)
        archive_spy.assert_called_once_with(build)
        claim.assert_called_once()
        self.assertEqual(result["identity"]["archive_uuid"], uuid)
        self.assertEqual(result["identity"]["loaded_uuid"], uuid)
        self.assertIs(result["configured_armed"], False)
        self.assertIs(result["legacy_validation_copy_armed"], False)

    def test_instrumented_preflight_rejects_old_identity_and_used_one_shot(self):
        self.require_private_receipts()
        adapter = load_module("test122_offline_test_worker_negative_adapter",
                              WORKER_ADAPTER_PATH)
        worker_loader = adapter._WORKER
        test104 = worker_loader._load(
            "test122_offline_preflight_negative_test104",
            worker_loader.TEST104_WORKER_PATH)
        worker_loader._instrument_worker(test104, adapter.BINDING.IWN_ROOT)
        worker = test104.load_test087_worker()
        test104.configure_worker(worker.__dict__,
                                 iwn_root=adapter.BINDING.IWN_ROOT)
        build, build_raw = adapter.BINDING.read_private(
            adapter.BINDING.BUILD_RECEIPT)
        uuid = build["mach_o_uuid"]
        metadata = adapter.BINDING.build_disarmed_metadata(
            minimum_boot_epoch_exclusive=1)
        source_binding = metadata["source_binding"]

        class Capture:
            def __init__(self):
                self.initial = {
                    "NativeTestBuild": adapter.BINDING.CANDIDATE,
                    "NativePowerReady": 1,
                    "NativeRxPreOwnerObservation": True,
                    "NativeP2PManualArmed": 0,
                    "NativeP2PProbeAttempted": 0,
                    "NativeP2PProbeResourceMayExist": 0,
                    worker.PREOWNER_ARM_ACCEPTED_KEY: 0,
                    worker.PREOWNER_PUBLISHED_KEY: 0,
                    worker.DATA_TX_PENDING: 0,
                    "NativeAwdlDataTxSubmitted": 0,
                }

            def properties(self, service):
                if service == "IOPCIEDeviceWrapper":
                    return {"NativeTestBuild": adapter.BINDING.CANDIDATE}
                return dict(self.initial)

            @staticmethod
            def profile_problems(_properties, *, selected):
                return []

            @staticmethod
            def awdl_data_rx_snapshot(_properties):
                return {"complete": True}

            @staticmethod
            def awdl_data_rx149_receipt_snapshot(_properties):
                return {"complete": True}

            @staticmethod
            def receipt_preflight_problem(_receipt):
                return None

            @staticmethod
            def tx_zero_evidence(_before, _after):
                return {"valid": True}

        capture = Capture()
        template = {
            "candidate": adapter.BINDING.CANDIDATE,
            "profile": adapter.BINDING.PROFILE,
            "status": "prepared_disarmed",
            "armed": False,
            "retry_allowed": False,
            "minimum_boot_epoch_exclusive": 1,
            "expected_loaded_uuid": uuid,
        }
        with mock.patch.object(adapter.BINDING, "_verify_archive") as archive, \
             mock.patch.object(worker, "_claim_availability") as claim:
            old_identity = dict(template, candidate=TEST121_CANDIDATE)
            with self.assertRaises(worker.NativeCaptureError):
                worker._native_preflight(
                    old_identity, source_binding, {}, Path("/offline/build"),
                    adapter.BINDING.DEPLOYMENT_RECEIPT, 2, object(), capture,
                    object(), build, build_raw)
            archive.assert_not_called()
            claim.assert_not_called()

            capture.initial["NativeP2PProbeAttempted"] = 1
            with mock.patch.object(
                    adapter.BINDING.T121.subprocess, "run",
                    side_effect=mock_dwarfdump(uuid)), \
                 mock.patch.object(
                     worker.subprocess, "check_output",
                     return_value=("org.geekaudio.AirportItlwm (Test122) " +
                                   uuid + "\n")), \
                 mock.patch.object(adapter.BINDING, "_verify_archive",
                                   wraps=adapter.BINDING._verify_archive) as verify:
                with self.assertRaises(worker.NativeCaptureError):
                    worker._native_preflight(
                        template, source_binding, {}, Path("/offline/build"),
                        adapter.BINDING.DEPLOYMENT_RECEIPT, 2, object(), capture,
                        object(), build, build_raw)
                verify.assert_called_once_with(build)
            claim.assert_not_called()


if __name__ == "__main__":
    unittest.main()
