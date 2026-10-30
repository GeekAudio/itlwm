from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "developer-tools/test086-controlled/native_controlled_capture.py"
SPEC = importlib.util.spec_from_file_location("native_controlled_capture_test", SCRIPT)
native = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(native)


class NativeControlledCaptureTests(unittest.TestCase):
    def test_default_plan_does_not_start_native_worker(self):
        original = native._worker
        native._worker = lambda _args: self.fail("plan called worker")
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                self.assertEqual(native.main([]), 0)
        finally:
            native._worker = original
        self.assertIn('"mode": "plan"', output.getvalue())
        self.assertIn('"system_read": false', output.getvalue())
        self.assertIn('"claim_touched": false', output.getvalue())
        self.assertIn('"requires_phone_ready": false', output.getvalue())

    def test_exact_abort_and_single_arm_protocol(self):
        self.assertEqual(native.parse_control_line(b"ABORT\n"), ("abort", None))
        token = "0123456789abcdef0123456789abcdef"
        self.assertEqual(native.parse_control_line(("ARM " + token + "\n").encode()),
                         ("arm", token))
        for invalid in (
                b"ARM 0123456789ABCDEF0123456789abcdef\n",
                b"ARM 0123456789abcdef0123456789abcdef extra\n",
                b"ARM 0123456789abcdef0123456789abcde\n",
                b"ARM 0123456789abcdef0123456789abcdef\nABORT\n",
                b"GO 0123456789abcdef0123456789abcdef\n",
                b"ABORT\r\n"):
            with self.subTest(invalid=invalid):
                self.assertEqual(native.parse_control_line(invalid), ("invalid", None))

    def test_ready_metadata_does_not_claim_phone_readiness(self):
        value = native.plan()
        self.assertEqual(value["source_ready_kind"], "controlled_probe")
        self.assertFalse(value["requires_phone_ready"])
        self.assertFalse(value["native_worker_armed"])
        self.assertFalse(value["helper_invoked"])

    def test_session_terminal_does_not_require_management_trace(self):
        state = {
            "NativeP2PRx149Selected": 1,
            "NativeP2PProbeAttempted": 1,
            "NativeP2PProbeState": 7,
            "NativeP2PProbeResourceMayExist": 0,
            "NativeP2PRocEndSeen": 1,
            # Intentionally no RX management trace producer properties.
        }
        self.assertTrue(native._session_terminal(state))

    def test_missing_trace_does_not_hide_data_receipt(self):
        class FakeCapture:
            @staticmethod
            def awdl_data_rx_triplet_evidence(_samples):
                return {"valid": True, "delivered_delta": 1}

            @staticmethod
            def awdl_data_rx149_receipt_triplet_evidence(_samples, _roc):
                return {"valid": True, "final": {
                    "local_ifnet_input_kpi_accepted": True}}

            @staticmethod
            def guarded_rx_trace_evidence(*_args):
                return {"valid": False, "problems": ["trace_missing"]}

        class FakeTraceTool:
            @staticmethod
            def derive_rx_trace_guard_report(*_args):
                return {"combined_valid": False, "guard": {"valid": False}}

        samples = [{"sample": index} for index in range(3)]
        result = native._derive_evidence(FakeCapture, FakeTraceTool, samples)
        self.assertTrue(result["data_rx"]["valid"])
        self.assertTrue(result["data_receipt"]["final"]["local_ifnet_input_kpi_accepted"])
        self.assertIsNone(native._guarded_ifnet_input_kpi(result))
        self.assertFalse(result["management_trace_u32"]["combined_valid"])

    def test_ifnet_kpi_requires_valid_triplet_aggregate(self):
        evidence = {"data_receipt": {
            "valid": False,
            "final": {"local_ifnet_input_kpi_accepted": True},
            "local_ifnet_input_kpi_accepted": None,
        }}
        self.assertIsNone(native._guarded_ifnet_input_kpi(evidence))
        evidence["data_receipt"] = {
            "valid": True,
            "final": {"local_ifnet_input_kpi_accepted": False},
            "local_ifnet_input_kpi_accepted": True,
        }
        self.assertIs(native._guarded_ifnet_input_kpi(evidence), True)

    def test_current_owner_snapshot_is_whitelisted_and_numeric_only(self):
        sample = {
            "NativeP2PRxTraceOwnerSerial": 9,
            "NativeP2PProbeContextGeneration": 10,
            "NativeP2PProbePowerGeneration": 11,
            "NativeP2PProbeStationGeneration": 12,
            "NativeP2PRocGeneration": 13,
            "NativeP2PPeerAddress": "must-not-copy",
        }
        self.assertEqual(native._read_current_owner(sample), {
            "NativeP2PRxTraceOwnerSerial": 9,
            "NativeP2PProbeContextGeneration": 10,
            "NativeP2PProbePowerGeneration": 11,
            "NativeP2PProbeStationGeneration": 12,
            "NativeP2PRocGeneration": 13,
        })

    def test_private_source_map_is_bound_to_receipt_and_frozen_manifest(self):
        digest = "a" * 64
        source_map = {f"file-{index}": digest for index in range(396)}
        binding = {
            "build_receipt_sha256": "placeholder",
            "source_file_count": 396,
            "source_sha256_map_sha256": hashlib.sha256(json.dumps(
                source_map, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "expected_binary_sha256": digest,
            "expected_info_plist_sha256": digest,
        }
        template = {"source_sha256": source_map, "source_binding": binding}
        receipt = {
            "candidate": native.BUILD,
            "status": "built_offline",
            "mach_o_uuid": native.EXPECTED_UUID,
            "source_file_count": 396,
            "source_sha256": source_map,
            "binary_sha256": digest,
            "info_plist_sha256": digest,
        }
        raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        binding["build_receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        frozen = {"source_sha256": dict(source_map)}
        protocol = native._load_module(
            "test086_controlled_protocol_test",
            ROOT / "developer-tools/test086-controlled/test086_controlled.py")

        native._validate_source_binding(protocol, template, frozen, receipt, raw)

        mismatched_receipt = copy.deepcopy(receipt)
        mismatched_receipt["source_sha256"]["file-0"] = "b" * 64
        mismatched_raw = json.dumps(
            mismatched_receipt, sort_keys=True, separators=(",", ":")).encode()
        binding["build_receipt_sha256"] = hashlib.sha256(mismatched_raw).hexdigest()
        with self.assertRaises(native.NativeCaptureError) as receipt_caught:
            native._validate_source_binding(
                protocol, template, frozen, mismatched_receipt, mismatched_raw)
        self.assertEqual(receipt_caught.exception.code,
                         "FROZEN_SOURCE_BINDING_FAILED")

        binding["build_receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        frozen["source_sha256"]["file-0"] = "b" * 64
        with self.assertRaises(native.NativeCaptureError) as caught:
            native._validate_source_binding(protocol, template, frozen, receipt, raw)
        self.assertEqual(caught.exception.code, "FROZEN_SOURCE_MAP_MISMATCH")

    def test_private_metadata_is_pinned_to_sibling_private_root(self):
        expected = (ROOT.parent / "IntelWirelessNative/research/"
                    "test086-controlled-preparation-private/"
                    "native-controlled-probe-private.json")
        self.assertEqual(native.DEFAULT_METADATA, expected)
        self.assertTrue(native._metadata_path_allowed(expected))
        self.assertFalse(native._metadata_path_allowed(
            ROOT / "research/test086-controlled-preparation-private/"
            "native-controlled-probe-private.json"))
        self.assertFalse(native._metadata_path_allowed(
            expected.parent / ".." / "test086-next-boot-private.json"))
        self.assertFalse(native._metadata_path_allowed(
            expected.parent / "other-controlled-metadata.json"))

    def test_legacy_armed_validation_copy_does_not_modify_source_file(self):
        configured = {"armed": False, "status": "prepared_disarmed",
                      "expected_loaded_uuid": native.EXPECTED_UUID}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frozen.json"
            original = json.dumps(configured, sort_keys=True).encode()
            path.write_bytes(original)
            os.chmod(path, 0o600)
            before = path.stat()
            loaded = json.loads(path.read_bytes())
            validation_copy = native._legacy_validation_copy(loaded)
            after = path.stat()

            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
            self.assertEqual(before.st_size, after.st_size)
            self.assertFalse(loaded["armed"])
            self.assertFalse(configured["armed"])
            self.assertTrue(validation_copy["armed"])
            self.assertEqual(validation_copy["status"], "prepared_disarmed")


if __name__ == "__main__":
    unittest.main()
