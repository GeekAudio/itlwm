from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
IWN_ROOT = REPO_ROOT.parent / "IntelWirelessNative"
TOOL_DIR = REPO_ROOT / "developer-tools/test087"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = load_module("test087_protocol_under_test", TOOL_DIR / "test087_controlled.py")
worker = load_module("test087_worker_under_test", TOOL_DIR / "native_controlled_capture.py")
coordinator = load_module(
    "test087_coordinator_under_test", TOOL_DIR / "controlled_run_coordinator.py")
decoder = load_module("test087_decoder_under_test", TOOL_DIR / "preowner_decode.py")
binding_builder = load_module(
    "test087_binding_builder_under_test",
    TOOL_DIR / "finalize_test087_runtime_binding.py")


def read_wire_records(data: bytes) -> list[bytes]:
    count = struct.unpack_from("<Q", data, 0)[0]
    offset = 8
    records = []
    for _ in range(count):
        words = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
        end = offset + words * 8
        records.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise AssertionError("wire fixture contains trailing bytes")
    return records


class Test087RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            raise RuntimeError("clang++ or g++ required for offline wire fixture")
        cls.temp = tempfile.TemporaryDirectory(prefix="test087-runtime-offline-")
        binary = Path(cls.temp.name) / "preowner-wire-fixture"
        subprocess.run([
            compiler, "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-I", str(REPO_ROOT),
            str(REPO_ROOT / "native/tests/test087_preowner_wire.cpp"),
            "-o", str(binary),
        ], check=True, cwd=REPO_ROOT)
        output = subprocess.run([str(binary)], check=True, stdout=subprocess.PIPE).stdout
        cls.closed_blob = read_wire_records(output)[1]
        decoded = decoder.decode_blob(cls.closed_blob)
        if decoded["snapshot"]["active"] or not decoded["snapshot"]["closed"]:
            raise AssertionError("fixture record 2 must be a closed snapshot")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_raw_osdata_triplet_is_preserved_and_strictly_decoded(self):
        markers = {
            worker.PREOWNER_PUBLISHED_KEY: 1,
            worker.PREOWNER_REVISION_KEY: 2,
            worker.PREOWNER_SCHEMA_KEY: 1,
            worker.PREOWNER_ARM_ACCEPTED_KEY: 1,
            worker.PREOWNER_SNAPSHOT_KEY: self.closed_blob,
        }
        with mock.patch.object(worker, "_read_preowner_registry",
                               side_effect=[dict(markers) for _ in range(4)]), \
                mock.patch.object(worker.time, "sleep", return_value=None):
            result = worker._preowner_observation(decoder)

        self.assertTrue(result["complete"])
        self.assertTrue(result["zero_values_are_observed_counts"])
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["commit_markers_valid_for_all_reads"])
        self.assertEqual(result["evidence_limits"]["window_us"], 4_000_000)
        self.assertEqual(result["evidence_limits"]["maximum_mpdu_witnesses"], 16)
        self.assertTrue(result["evidence_limits"]["missing_publication_or_blob_is_unknown_not_zero"])
        self.assertEqual(len(result["raw_reads"]), 3)
        for item in result["raw_reads"]:
            self.assertEqual(item["raw_blob_length"], len(self.closed_blob))
            self.assertEqual(item["raw_blob_sha256"], hashlib.sha256(self.closed_blob).hexdigest())
            self.assertEqual(base64.b64decode(item["raw_blob_base64"]), self.closed_blob)
        self.assertEqual(result["comparison"]["decoded"]["wire"]["wordCount"], 711)

    def test_snapshot_is_not_complete_without_published_commit_markers(self):
        reads = [{
            worker.PREOWNER_PUBLISHED_KEY: 1,
            worker.PREOWNER_REVISION_KEY: 1,
            worker.PREOWNER_SCHEMA_KEY: 1,
            worker.PREOWNER_ARM_ACCEPTED_KEY: 1,
            worker.PREOWNER_SNAPSHOT_KEY: self.closed_blob,
        } for _ in range(4)]
        with mock.patch.object(worker, "_read_preowner_registry", side_effect=reads), \
                mock.patch.object(worker.time, "sleep", return_value=None):
            result = worker._preowner_observation(decoder)
        self.assertFalse(result["complete"])
        self.assertFalse(result["zero_values_are_observed_counts"])
        self.assertFalse(result["commit_markers_valid_for_all_reads"])
        self.assertEqual(result["comparison"]["status"], "complete")

    def test_missing_publication_is_unknown_not_a_zero_snapshot(self):
        with mock.patch.object(worker, "_read_preowner_registry", return_value={
                worker.PREOWNER_PUBLISHED_KEY: 0,
                worker.PREOWNER_REVISION_KEY: 0,
                worker.PREOWNER_SCHEMA_KEY: 0,
                worker.PREOWNER_ARM_ACCEPTED_KEY: 1,
                worker.PREOWNER_SNAPSHOT_KEY: None,
        }), mock.patch.object(worker.time, "monotonic", side_effect=[0.0, 6.1]), \
                mock.patch.object(worker.time, "sleep", return_value=None):
            result = worker._preowner_observation(decoder)
        self.assertEqual(result["status"], "not_published_yet")
        self.assertFalse(result["complete"])
        self.assertFalse(result["zero_values_are_observed_counts"])
        self.assertEqual(result["raw_reads"], [])
        self.assertEqual(result["comparison"]["status"], "not_read")

    def test_arm_ack_requires_both_rx149_and_preowner_acceptance(self):
        token = "0123456789abcdef0123456789abcdef"
        event, fields = worker._arm_gate_event(token, {
            "exit_code": 0, "arm_property_accepted": True,
            "preowner_arm_accepted": True, "helper_error_type": None,
        })
        self.assertEqual(event, "NATIVE_ARMED")
        self.assertTrue(fields["preowner_arm_accepted"])
        event, fields = worker._arm_gate_event(token, {
            "exit_code": 0, "arm_property_accepted": True,
            "preowner_arm_accepted": False, "helper_error_type": None,
        })
        self.assertEqual(event, "NATIVE_ARM_FAILED")
        self.assertEqual(fields["failure_code"], "PREOWNER_ARM_NOT_ACKNOWLEDGED")

    def test_receipt_uuid_and_source_count_are_dynamic(self):
        uuid = "2E1F109C-8DF2-359F-8D7E-EDE692B454E9"
        sha = "a" * 64
        source_map = {
            "native/rx_preowner_observation.hpp": "b" * 64,
            "native/p2p_rx149_data_input.hpp": "c" * 64,
        }
        rx_contract = {
            "artifact_enabled": True,
            "host_management_or_data_tx_allowed": False,
            "session_duration_ms": 100, "channel": 149,
            "source_header": "native/p2p_rx149_data_input.hpp",
            "source_header_sha256": source_map["native/p2p_rx149_data_input.hpp"],
        }
        preowner_receipt = {
            "window_us": 4_000_000, "numeric_only": True,
            "rx_policy_changed": False, "tx_policy_changed": False,
            "schema_version": 1,
            "snapshot_property": "NativeRxPreOwnerSnapshot",
            "source_header_sha256": source_map["native/rx_preowner_observation.hpp"],
        }
        frozen = {
            "source_sha256": source_map, "expected_loaded_uuid": uuid,
            "expected_binary_sha256": sha, "expected_info_plist_sha256": sha,
        }
        template = {
            "source_sha256": source_map, "expected_loaded_uuid": uuid,
            "rx149_data_input_contract": rx_contract,
            "preowner_observation_contract": {
                **preowner_receipt, "schema": 1, "duration_ms": 4000,
            },
            "source_binding": {
                "build_receipt_sha256": sha, "source_file_count": len(source_map),
                "source_sha256_map_sha256": hashlib.sha256(json.dumps(
                    source_map, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "expected_binary_sha256": sha, "expected_info_plist_sha256": sha,
                "expected_loaded_uuid": uuid, "frozen_test087_metadata": frozen,
            },
        }
        receipt = {
            "candidate": protocol.BUILD, "status": "built_offline",
            "mach_o_uuid": uuid, "source_sha256": source_map,
            "source_file_count": len(source_map),
            "binary_sha256": sha, "info_plist_sha256": sha,
            "rx149_data_input_contract": rx_contract,
            "rx_preowner_observation_contract": preowner_receipt,
        }
        raw = json.dumps(receipt, sort_keys=True).encode()
        template["source_binding"]["build_receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertEqual(protocol.validate_frozen_source_binding(template, receipt, raw), [])
        receipt["source_file_count"] = 396
        self.assertIn("receipt_source_file_count",
                      protocol.validate_frozen_source_binding(template, receipt, raw))

    def test_binding_finalizer_copies_dynamic_build_identity_and_map(self):
        uuid = "2E1F109C-8DF2-359F-8D7E-EDE692B454E9"
        source_map = {
            "native/rx_preowner_observation.hpp": "b" * 64,
            "native/p2p_rx149_data_input.hpp": "c" * 64,
        }
        build = {
            "candidate": "25G332-Test087", "baseline": "25G332-Test086",
            "status": "built_offline", "installed": False, "rf_tested": False,
            "mach_o_uuid": uuid, "source_sha256": source_map,
            "source_file_count": len(source_map),
            "binary_sha256": "a" * 64, "info_plist_sha256": "d" * 64,
            "profile": protocol.PROFILE,
            "rx149_data_input_contract": {
                "artifact_enabled": True,
                "host_management_or_data_tx_allowed": False,
                "session_duration_ms": 100, "channel": 149,
                "source_header": "native/p2p_rx149_data_input.hpp",
                "source_header_sha256": source_map["native/p2p_rx149_data_input.hpp"],
            },
            "rx_preowner_observation_contract": {
                "window_us": 4_000_000, "numeric_only": True,
                "rx_policy_changed": False, "tx_policy_changed": False,
                "schema_version": 1,
                "snapshot_property": "NativeRxPreOwnerSnapshot",
                "source_header_sha256": source_map["native/rx_preowner_observation.hpp"],
            },
        }
        baseline = {"candidate": "25G332-Test086"}
        with mock.patch.object(binding_builder, "validate_receipts",
                               return_value=(build, b"build", baseline, b"baseline")):
            metadata = binding_builder.build_metadata(
                minimum_boot_epoch_exclusive=1234)
        self.assertEqual(metadata["expected_loaded_uuid"], uuid)
        self.assertEqual(metadata["source_binding"]["source_file_count"], 2)
        self.assertEqual(metadata["source_sha256"], source_map)
        self.assertEqual(metadata["minimum_boot_epoch_exclusive"], 1234)
        self.assertEqual(metadata["sender"]["interval_ms"], 80)
        self.assertEqual(metadata["sender"]["interval_ms"],
                         coordinator.SENDER_PROFILE["interval_ms"])
        self.assertEqual(protocol.FROZEN_METADATA_SENDER_INTERVAL_MS,
                         coordinator.SENDER_PROFILE["interval_ms"])
        self.assertFalse(metadata["armed"])

    def test_real_worker_event_lines_pass_real_coordinator_parsers(self):
        token = "0123456789abcdef0123456789abcdef"
        uuid = "2E1F109C-8DF2-359F-8D7E-EDE692B454E9"
        template = {"expected_loaded_uuid": uuid}
        frozen = {}
        binding = {}
        receipt = {"candidate": protocol.BUILD, "mach_o_uuid": uuid}
        temp_root = Path(self.temp.name)
        output = temp_root / "run"
        output.mkdir(mode=0o700)
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(),
                                  pw_dir=self.temp.name)

        class FakeCapture:
            CLAIM_RELATIVE = Path("claims")

            @staticmethod
            def awdl_data_rx_snapshot(_sample):
                return {"complete": True}

            @staticmethod
            def awdl_data_rx149_receipt_snapshot(_sample):
                return {"complete": True}

            @staticmethod
            def rx149_snapshot(_sample):
                return {"selected": True}

            @staticmethod
            def _claim_directory(_account):
                return temp_root / "claims"

            @staticmethod
            def consume_boot_claim(_claim_dir, _boot, _token):
                return Path("boot-123.json")

        initial = {"NativeP2PProbeState": 7}
        preflight = {
            "identity": {"binary_identity_verified": True},
            "initial": initial,
            "p2p_tx_zero": {"valid": True},
            "host_tx_zero": {"valid": True},
            "claim": {"available": True},
            "configured_armed": False,
        }
        terminal = {
            "NativeP2PRx149Selected": 1, "NativeP2PProbeAttempted": 1,
            "NativeP2PProbeState": 7, "NativeP2PProbeResourceMayExist": 0,
            "NativeP2PRocEndSeen": 1,
        }
        evidence = {
            "data_rx": {"valid": True}, "data_receipt": {"valid": True},
            "management_trace_u32": {"combined_valid": False},
            "controlled_trace_review": {"status": "invalid_or_not_applicable"},
        }
        helper = Path(self.temp.name) / "fake-helper"
        helper.write_text("offline fixture")
        helper.chmod(0o700)
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"arm_property_accepted": True,
                               "preowner_arm_accepted": True}),
            stderr="",
        )
        marker = {
            worker.PREOWNER_PUBLISHED_KEY: 1,
            worker.PREOWNER_REVISION_KEY: 2,
            worker.PREOWNER_SCHEMA_KEY: 1,
            worker.PREOWNER_ARM_ACCEPTED_KEY: 1,
            worker.PREOWNER_SNAPSHOT_KEY: self.closed_blob,
        }
        with mock.patch.object(worker.os, "geteuid", return_value=0), \
                mock.patch.object(worker, "_account_for_private_files", return_value=account), \
                mock.patch.object(worker, "capture_module", return_value=FakeCapture()), \
                mock.patch.object(worker, "_read_boot_epoch", return_value=1234), \
                mock.patch.object(worker, "_load_private_bundle", return_value=(
                    template, binding, frozen, temp_root / "build.json",
                    temp_root / "base.json", receipt, b"{}", "a" * 64)), \
                mock.patch.object(worker, "_native_preflight", return_value=preflight), \
                mock.patch.object(worker, "_private_output", return_value=output), \
                mock.patch.object(worker, "_save_report", return_value=None), \
                mock.patch.object(worker, "_compile_helper", return_value=helper), \
                mock.patch.object(worker, "_wait_for_helper_gate", return_value=("arm", token)), \
                mock.patch.object(worker.subprocess, "run", return_value=fake_result), \
                mock.patch.object(worker, "_post_snapshots", return_value=[terminal] * 3), \
                mock.patch.object(worker, "_derive_evidence", return_value=evidence), \
                mock.patch.object(worker, "_load_trace_tool", return_value=object()), \
                mock.patch.object(worker, "_read_preowner_registry",
                                  side_effect=[dict(marker) for _ in range(4)]), \
                mock.patch.object(worker.time, "sleep", return_value=None):
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                status = worker._worker(SimpleNamespace(
                    metadata=Path("/unused"), output=output))

        self.assertEqual(status, 0)
        lines = captured.getvalue().splitlines()
        ready = next(line for line in lines if line.startswith("NATIVE_READY "))
        armed = next(line for line in lines if line.startswith("NATIVE_ARMED "))
        arm_result = next(line for line in lines if line.startswith("NATIVE_ARM_RESULT "))
        final_result = next(line for line in lines if line.startswith("NATIVE_RESULT "))
        coordinator.EXPECTED_UUID = uuid
        coordinator.MINIMUM_BOOT_EPOCH_EXCLUSIVE = 1000
        self.assertEqual(coordinator._parse_native_ready(ready)["expected_loaded_uuid"], uuid)
        self.assertTrue(coordinator._parse_native_armed(armed, token)["preowner_arm_accepted"])
        self.assertTrue(coordinator._parse_native_arm_result(arm_result, token)[
            "preowner_arm_accepted"])
        parsed = coordinator._parse_native_result(final_result, token)
        self.assertTrue(parsed["preowner_arm_accepted"])
        self.assertTrue(parsed["preowner_snapshot_complete"])


if __name__ == "__main__":
    unittest.main()
