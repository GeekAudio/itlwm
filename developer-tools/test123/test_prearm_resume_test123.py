#!/usr/bin/env python3
"""Offline safety tests for Test123's one-use pre-ARM continuation gate."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("prearm_resume_test123.py")
SPEC = importlib.util.spec_from_file_location("test123_prearm_resume_under_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot_load_prearm_resume_test123")
resume = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resume)


BOOT_EPOCH = 1793697291
UUID = "17DB1FD2-214C-30A1-825C-C841B5F9E80B"
ARCHIVE_SHA = "a" * 64
TOKEN = "e55ee9aaeec5f80be68bf699062a36ff"


def _write_private_json(path: Path, value: dict) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    return raw


class PrearmResumeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test123-prearm-resume-")
        self.root = Path(self.temp.name).resolve()
        os.chmod(self.root, 0o700)
        self.kernel_meta = self.root / "kernel" / "native-controlled-probe-private.json"
        self.kernel_meta.parent.mkdir(mode=0o700)
        os.chmod(self.kernel_meta.parent, 0o700)
        self.kernel_meta.write_text("{}\n")
        self.tool_root = self.root / "RuntimeTest123"
        research = self.tool_root / "research"
        research.mkdir(parents=True, mode=0o700)
        os.chmod(self.tool_root, 0o700)
        os.chmod(research, 0o700)

        self._patches = [
            mock.patch.object(resume, "KERNEL_METADATA", self.kernel_meta),
            mock.patch.object(resume, "TOOL_ROOT", self.tool_root),
            mock.patch.object(resume, "KERNEL_CANDIDATE", "25G332-Test122"),
        ]
        for patcher in self._patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        self.paths = resume._expected_paths(BOOT_EPOCH)
        self.paths["report_dir"].mkdir(mode=0o700)
        os.chmod(self.paths["report_dir"], 0o700)
        self.paths["cleanup_dir"].mkdir(parents=True, mode=0o700)
        os.chmod(self.paths["cleanup_dir"], 0o700)
        self.now_epoch = time.time()
        self.write_records()

    def tearDown(self):
        self.temp.cleanup()

    def write_records(self, *, report_mutator=None, capture_mutator=None,
                      cleanup_mutator=None, host_mutator=None,
                      observation_epoch=None):
        observed = (self.now_epoch - 1 if observation_epoch is None
                    else observation_epoch)
        observed_at = dt.datetime.fromtimestamp(
            observed, tz=dt.timezone.utc).isoformat()
        report = {
            "schema": resume.REPORT_SCHEMA,
            "tool_id": "Tool123",
            "tool_test": "Test123",
            "running_kernel_test": "Test122",
            "candidate": "25G332-Test122",
            "driver_candidate": "25G332-Test122",
            "output_directory": str(self.paths["report_dir"]),
            "status": "MONITOR_READY_MALFORMED",
            "complete": False,
            "partial": True,
            "boot_epoch": BOOT_EPOCH,
            "expected_loaded_uuid": UUID,
            "boot_claim_consumed": False,
            "claim_outcome": "aborted_before_arm_no_claim",
            "retry_allowed": False,
            "rf_transmission_proven": False,
            "run_token": TOKEN,
            "expected_archive_binary_sha256": ARCHIVE_SHA,
            "native_ready": {
                "boot_epoch": BOOT_EPOCH,
                "candidate": "25G332-Test122",
                "expected_loaded_uuid": UUID,
                "claim_available": True,
                "one_arm_maximum": True,
            },
            "native_aborted": {
                "event": "NATIVE_ABORTED",
                "claim_consumed": False,
                "helper_invoked": False,
                "retry_allowed": False,
            },
            "events_parent_boot_monotonic_ns": [{"event": "NATIVE_READY"}],
            "events_parent_monotonic_ns": [{"event": "NATIVE_READY"}],
            "test088_sender": {
                "raw_records": {
                    "first_protocol_line": None,
                    "sender_started_line": None,
                    "sender_result_line": None,
                },
                "sender_started_event": None,
                "sender_result_event": None,
            },
        }
        for field in (
            "native_arm_failed", "native_armed_ack", "native_arm_result",
            "native_result", "sender_result", "sender_cleanup", "monitor_ready",
            "sender_ready", "listener_ready", "listener_result",
        ):
            report[field] = None
        if report_mutator:
            report_mutator(report)

        capture = {
            "schema": resume.CAPTURE_SCHEMA,
            "candidate": "25G332-Test122",
            "status": "coordinator_aborted_before_claim",
            "boot_epoch": BOOT_EPOCH,
            "boot_attempt_claim_consumed": False,
            "native_helper_invoked": False,
            "configured_armed": False,
            "legacy_validation_copy_armed": False,
            "preowner_arm_accepted": False,
            "arm_run_token": None,
            "retry_allowed": False,
            "identity": {
                "loaded_uuid": UUID,
                "archive_uuid": UUID,
                "loaded_uuid_matches_receipt": True,
                "archive_binary_sha256_verified": True,
                "expected_archive_binary_sha256": ARCHIVE_SHA,
            },
            "claim_preflight": {
                "available": True,
                "claim_filename": f"boot-{BOOT_EPOCH}.json",
                "claim_scope": "shared IntelWirelessNative BootGlobal one-claim-per-boot",
            },
        }
        if capture_mutator:
            capture_mutator(capture)

        report_raw = _write_private_json(self.paths["report"], report)
        _write_private_json(self.paths["capture"], capture)
        cleanup = {
            "at": observed_at,
            "boot_epoch": BOOT_EPOCH,
            "source_report_sha256": hashlib.sha256(report_raw).hexdigest(),
            "monitor_absent": True,
            "exact_temporary_directory_absent": True,
            "ap_identity_and_channel_unchanged": True,
            "diagnostic_process_absent": True,
            "kernel_arm_not_invoked": True,
            "observations": {
                "interfaces": {"exit_code": 0, "stdout": "wlan7\n"},
                "ap": {"exit_code": 0, "stdout": "same-ap"},
                "processes": {"exit_code": 0, "stdout": ""},
                "temporary_absent": {"exit_code": 0, "stdout": ""},
            },
        }
        if cleanup_mutator:
            cleanup_mutator(cleanup)
        _write_private_json(self.paths["cleanup"], cleanup)
        host_processes = {
            "at": observed_at,
            "boot_epoch": BOOT_EPOCH,
            "source_report_sha256": hashlib.sha256(report_raw).hexdigest(),
            "matching_processes": [],
        }
        if host_mutator:
            host_mutator(host_processes)
        _write_private_json(self.paths["host_processes"], host_processes)

    def assert_rejected(self, *, expected_boot_epoch=BOOT_EPOCH,
                        expected_uuid=UUID):
        with self.assertRaises(resume.PrearmResumeError):
            resume.verify_prearm_resume(
                expected_boot_epoch=expected_boot_epoch,
                expected_uuid=expected_uuid, now_epoch=self.now_epoch)

    def test_valid_prearm_abort_returns_bound_fresh_paths(self):
        verified = resume.verify_prearm_resume(
            expected_boot_epoch=BOOT_EPOCH, expected_uuid=UUID,
            now_epoch=self.now_epoch)
        self.assertTrue(verified["eligible"])
        self.assertTrue(verified["same_boot"])
        self.assertFalse(verified["prior_native_claim_consumed"])
        self.assertFalse(verified["prior_go_attempted"])
        self.assertTrue(verified["kernel_claim_recheck_required_by_normal_preflight"])
        self.assertNotIn("actual_kernel_claim_rechecked_by_normal_preflight", verified)
        self.assertEqual(verified["prior_status"], "MONITOR_READY_MALFORMED")
        self.assertEqual(verified["report_sha256"], hashlib.sha256(
            self.paths["report"].read_bytes()).hexdigest())
        self.assertEqual(verified["capture_sha256"], hashlib.sha256(
            self.paths["capture"].read_bytes()).hexdigest())
        self.assertEqual(verified["fresh_output_directory"],
                         str(self.paths["resume_output"]))
        self.assertFalse(Path(verified["fresh_output_directory"]).exists())

    def test_rejects_arm_or_go_event(self):
        self.write_records(report_mutator=lambda d: d["events_parent_monotonic_ns"].append(
            {"event": "NATIVE_ARMED_ACK"}))
        self.assert_rejected()

    def test_rejects_claim_or_helper_invocation(self):
        self.write_records(capture_mutator=lambda d: d.update({
            "boot_attempt_claim_consumed": True,
            "native_helper_invoked": True,
        }))
        self.assert_rejected()

    def test_rejects_missing_cleanup_or_visible_monitor(self):
        self.paths["cleanup"].unlink()
        self.assert_rejected()
        self.write_records(cleanup_mutator=lambda d: d.update({"monitor_absent": False}))
        self.assert_rejected()

    def test_rejects_different_boot_or_uuid(self):
        self.assert_rejected(expected_boot_epoch=BOOT_EPOCH + 1)
        self.assert_rejected(expected_uuid="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")

    def test_rejects_report_changed_after_cleanup_hash(self):
        report = json.loads(self.paths["report"].read_text())
        report["status"] = "different"
        raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.paths["report"].write_bytes(raw)
        os.chmod(self.paths["report"], 0o600)
        self.assert_rejected()

    def test_claim_is_persistent_and_one_use(self):
        verification = resume.verify_prearm_resume(
            expected_boot_epoch=BOOT_EPOCH, expected_uuid=UUID,
            now_epoch=self.now_epoch)
        claimed = resume.claim_prearm_resume(verification)
        self.assertTrue(claimed["resume_marker_created"])
        marker = Path(claimed["resume_marker_path"])
        self.assertTrue(marker.is_file())
        marker_record = json.loads(marker.read_text())
        self.assertFalse(marker_record["kernel_claim_reset"])
        self.assertEqual(marker_record["source_report_sha256"], verification["report_sha256"])
        with self.assertRaises(resume.PrearmResumeError):
            resume.claim_prearm_resume(verification)
        self.assertTrue(marker.exists())

    def test_rejects_output_path_collision(self):
        self.paths["resume_output"].mkdir(mode=0o700)
        self.assert_rejected()

    def test_rejects_unbound_or_nonempty_host_process_snapshot(self):
        self.paths["host_processes"].unlink()
        self.assert_rejected()
        self.write_records()
        self.write_records(host_mutator=lambda d: d.update({
            "matching_processes": ["native_controlled_capture_test123.py"],
        }))
        self.assert_rejected()
        self.write_records(host_mutator=lambda d: d.update({
            "source_report_sha256": "0" * 64,
        }))
        self.assert_rejected()

    def test_rejects_stale_or_future_observations(self):
        self.write_records(observation_epoch=self.now_epoch - 181)
        self.assert_rejected()
        self.write_records(observation_epoch=self.now_epoch + 1)
        self.assert_rejected()

    def test_rejects_stale_or_future_host_process_snapshot(self):
        old_at = dt.datetime.fromtimestamp(
            self.now_epoch - 181, tz=dt.timezone.utc).isoformat()
        self.write_records(host_mutator=lambda d: d.update({"at": old_at}))
        self.assert_rejected()
        future_at = dt.datetime.fromtimestamp(
            self.now_epoch + 1, tz=dt.timezone.utc).isoformat()
        self.write_records(host_mutator=lambda d: d.update({"at": future_at}))
        self.assert_rejected()

    def test_rejects_old_run_token_or_status_reader_in_remote_process_snapshot(self):
        self.write_records(cleanup_mutator=lambda d: d["observations"]["processes"].update({
            "stdout": f"router_status_tail_test122 --run {TOKEN}",
        }))
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
