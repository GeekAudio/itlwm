#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
TOOL_DIR = ROOT / "developer-tools/test086-controlled"
spec = importlib.util.spec_from_file_location(
    "test086_controlled_full_coordinator", TOOL_DIR / "controlled_run_coordinator.py")
coordinator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = coordinator
spec.loader.exec_module(coordinator)


def native_ready(**changes):
    value = {
        "event": "NATIVE_READY", "candidate": coordinator.BUILD,
        "source_ready_kind": coordinator.SOURCE_KIND,
        "expected_loaded_uuid": coordinator.UUID, "boot_epoch": 1793341000,
        "profile": coordinator.PROFILE, "diagnostic_duration_ms": 100,
        "requires_phone_ready": False, "native_preflight_ready": True,
        "helper_compiled": True, "claim_available": True, "host_tx_zero": True,
        "host_management_or_data_tx_allowed": False, "run_token_required": True,
        "one_arm_maximum": True, "retry_allowed": False,
    }
    value.update(changes)
    return "NATIVE_READY " + json.dumps(value, separators=(",", ":"))


class FullCoordinatorTests(unittest.TestCase):
    def test_native_ready_requires_all_identity_and_safety_gates(self):
        ready = coordinator._parse_native_ready(native_ready())
        self.assertEqual(ready["boot_epoch"], 1793341000)
        for changed in (
            {"boot_epoch": 1793340271},
            {"requires_phone_ready": True},
            {"claim_available": False},
            {"host_tx_zero": False},
            {"retry_allowed": True},
            {"expected_loaded_uuid": "0" * 36},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(coordinator.CoordinatorError):
                    coordinator._parse_native_ready(native_ready(**changed))

    def test_claim_ack_binds_single_run_token(self):
        token = "0123456789abcdef0123456789abcdef"
        value = {
            "event": "NATIVE_ARMED", "run_token": token,
            "claim_consumed": True, "retry_allowed": False,
            "helper_invocation_pending": True, "arm_property_accepted": None,
            "roc_start_observed": False,
        }
        line = "NATIVE_ARMED " + json.dumps(value, separators=(",", ":"))
        self.assertTrue(coordinator._parse_native_armed(line, token)["claim_consumed"])
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator._parse_native_armed(line, "f" * 32)
        value["retry_allowed"] = True
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator._parse_native_armed(
                "NATIVE_ARMED " + json.dumps(value, separators=(",", ":")), token)

    def test_native_result_never_promotes_peer_or_airdrop(self):
        token = "0123456789abcdef0123456789abcdef"
        value = {
            "event": "NATIVE_RESULT", "run_token": token,
            "status": "captured_no_retry", "report_saved": True,
            "claim_consumed": True, "native_helper_invoked": True,
            "ifnet_input_kpi_accepted": True, "management_trace_valid": False,
            "peer_receipt_proven": False, "native_awdl_reply_proven": False,
            "airdrop_proven": False, "retry_allowed": False,
        }
        line = "NATIVE_RESULT " + json.dumps(value, separators=(",", ":"))
        parsed = coordinator._parse_native_result(line, token)
        self.assertTrue(parsed["ifnet_input_kpi_accepted"])
        self.assertFalse(parsed["peer_receipt_proven"])
        self.assertFalse(parsed["airdrop_proven"])
        value["airdrop_proven"] = True
        with self.assertRaises(coordinator.CoordinatorError):
            coordinator._parse_native_result(
                "NATIVE_RESULT " + json.dumps(value, separators=(",", ":")), token)

    def test_helper_error_and_native_report_write_failure_keep_fixed_protocol(self):
        token = "0123456789abcdef0123456789abcdef"
        arm_result = {
            "event": "NATIVE_ARM_RESULT", "run_token": token,
            "exit_code": None, "arm_property_accepted": None,
            "helper_summary": None, "stderr_present": False,
            "helper_error_type": "FileNotFoundError",
            "arm_property_acceptance_is_not_roc_start": True,
            "retry_allowed": False,
        }
        parsed_arm = coordinator._parse_native_arm_result(
            "NATIVE_ARM_RESULT " + json.dumps(arm_result, separators=(",", ":")), token)
        self.assertEqual(parsed_arm["helper_error_type"], "FileNotFoundError")

        native_result = {
            "event": "NATIVE_RESULT", "run_token": token,
            "status": "native_report_write_failed_no_retry", "report_saved": False,
            "claim_consumed": True, "native_helper_invoked": True,
            "ifnet_input_kpi_accepted": None, "management_trace_valid": None,
            "peer_receipt_proven": False, "native_awdl_reply_proven": False,
            "airdrop_proven": False, "retry_allowed": False,
        }
        parsed_result = coordinator._parse_native_result(
            "NATIVE_RESULT " + json.dumps(native_result, separators=(",", ":")), token)
        self.assertFalse(parsed_result["report_saved"])

    def test_full_entrypoint_default_is_plan_only(self):
        result = subprocess.run(
            [sys.executable, str(TOOL_DIR / "controlled_run_coordinator.py")],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["mode"], "plan")
        self.assertEqual(plan["no_argument_action"], "none")
        self.assertFalse(plan["peer_receipt_proven"])
        self.assertFalse(plan["airdrop_proven"])

    def test_failure_report_preserves_partial_evidence_without_promotion(self):
        error = coordinator.CoordinatorError(
            "NATIVE_ARM_RESULT_MISSING", {"stage": "post_arm"},
            partial_report={
                "boot_epoch": 1793341000,
                "native_armed_ack": {"claim_consumed": True},
                "sender_result": {"sent": 16},
                "peer_receipt_proven": False,
                "airdrop_proven": False,
            })
        report = coordinator._failure_report(error)
        self.assertEqual(report["boot_epoch"], 1793341000)
        self.assertEqual(report["sender_result"]["sent"], 16)
        self.assertEqual(report["error_code"], "NATIVE_ARM_RESULT_MISSING")
        self.assertFalse(report["retry_allowed"])
        self.assertFalse(report["peer_receipt_proven"])
        self.assertFalse(report["airdrop_proven"])

    def test_run_directory_must_be_inside_owner_private_root(self):
        account = coordinator._workspace_account()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            private = base / "private"
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            outside = base / "outside"
            outside.mkdir(mode=0o700)
            outside.chmod(0o700)
            original = coordinator.PRIVATE_ROOT
            coordinator.PRIVATE_ROOT = private
            try:
                allowed = private / "controlled-run"
                coordinator._prepare_run_dir(allowed, account)
                self.assertEqual(os.stat(allowed).st_uid, account.pw_uid)
                self.assertEqual(os.stat(allowed).st_mode & 0o777, 0o700)
                with self.assertRaises(coordinator.CoordinatorError) as raised:
                    coordinator._prepare_run_dir(outside / "controlled-run", account)
                self.assertEqual(raised.exception.code, "RUN_OUTPUT_OUTSIDE_PRIVATE_ROOT")
            finally:
                coordinator.PRIVATE_ROOT = original


if __name__ == "__main__":
    unittest.main()
