#!/usr/bin/env python3
"""Offline contract tests for Test101 runtime-only adapters."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load " + str(path))
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hcmd = load("test101_hcmd_trace_under_test", TOOL_DIR / "hcmd_rx_trace_test101.py")
adapter = load("test101_sender_adapter_under_test",
               TOOL_DIR / "sender_schema_adapter_test101.py")
binding = load("test101_runtime_binding_under_test",
               TOOL_DIR / "runtime_binding_test101.py")
runner = load("test101_controlled_runner_under_test",
              TOOL_DIR / "controlled_run_test101.py")


def hcmd_sample(*, flags: int = 1 << 10, result: int = 0,
                payload_length: int = 4, revision: int = 2,
                overwritten: int = 0,
                phase: int = hcmd.PHASE_RX_RESPONSE_NO_BUFFER) -> dict:
    entry = bytearray(hcmd.WIRE_ENTRY_BYTES)
    values = {
        0: (1, "Q"), 8: (987654321, "Q"), 16: (5, "I"),
        20: (8, "I"), 24: (phase, "I"),
        28: (hcmd.SOURCE_COMMAND_RESPONSE_QUEUE, "I"),
        32: (hcmd.IWX_ADD_STA_KEY, "I"), 36: (0, "I"),
        40: (1, "I"), 44: (hcmd.IWX_DQA_CMD_QUEUE, "I"),
        48: (2, "I"), 52: (0x4108, "I"), 56: (flags, "I"),
        60: (result, "I"), 64: (0, "I"), 68: (8, "I"),
        72: (payload_length, "I"), 76: (0, "I"),
    }
    for offset, (value, fmt) in values.items():
        struct.pack_into("<" + fmt, entry, offset, value)
    blob = bytearray(hcmd.WIRE_HEADER_BYTES)
    header_values = {
        0: (hcmd.WIRE_MAGIC, "I"), 4: (hcmd.WIRE_SCHEMA, "I"),
        8: (hcmd.WIRE_HEADER_BYTES, "I"), 12: (hcmd.WIRE_ENTRY_BYTES, "I"),
        16: (revision, "Q"), 24: (revision, "Q"),
        32: (5, "I"), 36: (9, "I"), 40: (1, "I"),
        44: (1, "I"), 48: (0, "I"), 52: (overwritten, "I"),
        56: (0, "I"), 60: (1, "Q"), 68: (1, "Q"),
        76: (1, "I"), 80: (1, "I"),
    }
    for offset, (value, fmt) in header_values.items():
        struct.pack_into("<" + fmt, blob, offset, value)
    blob.extend(entry)
    header = {
        "schema": hcmd.WIRE_SCHEMA,
        "blob_length": len(blob),
        "version_begin": revision,
        "version_end": revision,
        "owner_generation": 5,
        "owner_watchdog_sequence": 9,
        "owner_watchdog_sequence_present": 1,
        "row_count": 1,
        "dropped_count": 0,
        "overwritten_count": overwritten,
        "gap_count": 0,
        "window_start_serial": 1,
        "window_end_serial": 1,
        "stable": 1,
        "complete": 1,
    }
    markers = {
        key: header[name]
        for key, (name, _bits) in hcmd.COMPANION_FIELDS.items()
    }
    response = {
        "NativeKeyResponsePresent": 1,
        "NativeKeyResponseStable": 1,
        "NativeKeyResponseDroppedCount": 0,
        "NativeKeyResponseDroppedSerial": 0,
        "NativeKeyResponseSerial": 1,
        "NativeKeyResponseMonotonicNs": 987654321,
        "NativeKeyResponseDriverGeneration": 5,
        "NativeKeyResponseFirmwareGeneration": 8,
        "NativeKeyResponsePhase": phase,
        "NativeKeyResponseSource": hcmd.SOURCE_COMMAND_RESPONSE_QUEUE,
        "NativeKeyResponseCommandId": hcmd.IWX_ADD_STA_KEY,
        "NativeKeyResponseGroupId": 0,
        "NativeKeyResponseQid": hcmd.IWX_DQA_CMD_QUEUE,
        "NativeKeyResponseIndex": 2,
        "NativeKeyResponseHeaderSequence": 0x4108,
        "NativeKeyResponseFlags": flags,
        "NativeKeyResponseResult": result,
        "NativeKeyResponsePayloadLength": payload_length,
        "NativeKeyResponseTraceVersionBegin": revision,
        "NativeKeyResponseTraceVersionEnd": revision,
    }
    return {
        "read_status": "trace_present", "blob": bytes(blob),
        "markers": markers,
        "key_response": response,
        "publish_revision_begin": revision,
        "publish_revision_end": revision,
        "host_monotonic_lower_ns": 1234,
        "host_monotonic_upper_ns": 5678,
    }


def sender_result_fixture() -> dict:
    send_rows = []
    for ordinal in range(4):
        send_rows.append({
            "ordinal": ordinal,
            "ieee80211_sequence": (291 + ordinal) & 0x0FFF,
            "awdl_sequence": (34305 + ordinal) & 0xFFFF,
            "mpdu_sha256": hashlib.sha256(bytes([ordinal]) * 96).hexdigest(),
            "before_ns": 1000 + ordinal * 10_000_000,
            "after_ns": 1001 + ordinal * 10_000_000,
            "return_bytes": 106, "errno": 0,
        })
    capture = {
        "status": "not_started", "window": "send_sequence_span",
        "budget_ns": 40_000_000, "started_ns": None, "ended_ns": None,
        "window_cutoff_semantics": "min(actual_finished_ns,started_ns+budget_ns)",
        "actual_finished_ns": None,
        "schema_contract": "capture_finished_is_execution_completion_not_full_budget_coverage",
        "capture_finished": False, "loss_free": None,
        "decoder_coverage": None, "actual_horizon_ns": None,
        "decode_coverage": {
            "packet_received": 0, "packet_decoded": 0,
            "invalid_radiotap": 0, "unsupported_radiotap": 0,
            "truncated_packets": 0, "fcs_bytes_missing": 0,
            "rejected_radiotap_samples_recorded": 0,
            "rejected_radiotap_sample_overflow": 0,
            "kernel_stats_available": False, "kernel_dropped_packets": None,
            "kernel_packets": None, "kernel_stats_error": None,
            "receive_error": None, "capture_limit_reached": False,
        },
        "pre_send_drained_packets": 0, "pre_send_queue_empty": True,
        "rejected_radiotap_samples": [],
    }
    return {
        "event": "SENDER_RESULT", "status": "complete",
        "frames_requested": 4, "frames_attempted": 4,
        "frames_completed": 4, "sent": 4,
        "payload_bytes": 32, "mpdu_bytes": 96, "radiotap_bytes": 10,
        "packet_bytes": 106, "udp_payload_bytes": 8, "elapsed_ms": 31,
        "deadline_hit": False, "error_count": 0, "last_errno": 0,
        "stop_reason": "complete", "tx_flags_requested": "NOACK|NOSEQNO",
        "hardware_honoring": "unknown", "timing_schema": 1,
        "clock_domain": "CLOCK_MONOTONIC", "go_received_ns": 100,
        "started_ns": 200, "finished_ns": 31_000_200,
        "send_timing": send_rows,
        "tx_provenance": {
            "schema": "openwrt-tx-observation/v1", "capture": capture,
            "observations": [], "fixture_mode": "synthetic_host_fixture",
            "run_nonce_is_local_only": True, "nonce_in_mpdu": False,
            "tx_status_path": "not_observed", "tx_status_pid": None,
            "tx_status_cookie": None, "pid_txs_expectation": "unknown",
            "pid_cookie_bound_tx_status": "unknown",
            "pid_cookie_status_source_available": False,
            "tx_status_unknown_reason": "no pid-cookie status source",
            "rf_transmission_proven": False, "peer_receipt_proven": False,
            "ack_proven": False,
        },
    }


class HcmdTraceTests(unittest.TestCase):
    def test_decodes_raw_add_sta_key_status_without_semantic_upgrade(self):
        decoded = hcmd.decode_snapshot(hcmd_sample(result=0))
        row = decoded["add_sta_key_status_events"][0]
        self.assertEqual(decoded["status"], "stable_complete_cut")
        self.assertEqual(row["firmware_status_state"], "raw_status_present")
        self.assertEqual(row["firmware_status_raw_le32"], 0)
        self.assertFalse(row["status_interpreted_as_key_install_success"])
        self.assertFalse(row["peer_ack_proven"])
        slot = decoded["key_response_slot"]
        self.assertEqual(slot["status"], "latest_target_event")
        self.assertEqual(slot["ring_crosscheck"], "same_serial_fields_match")
        self.assertEqual(slot["event"]["firmware_status_raw_le32"], 0)

    def test_short_payload_is_unavailable_not_zero_status(self):
        decoded = hcmd.decode_snapshot(
            hcmd_sample(flags=1 << 11, result=0, payload_length=0))
        row = decoded["add_sta_key_status_events"][0]
        self.assertEqual(row["firmware_status_state"], "status_unavailable")
        self.assertIsNone(row["firmware_status_raw_le32"])
        self.assertEqual(decoded["key_response_slot"]["event"][
            "firmware_status_state"], "status_unavailable")

    def test_phase_and_command_failed_flag_are_independent(self):
        # The producer records no-buffer responses before parsing the failed
        # bit, so phase 7 may legitimately carry the failure flag.
        failed_no_buffer = hcmd.decode_snapshot(hcmd_sample(
            flags=(1 << 10) | hcmd.FLAG_COMMAND_RESPONSE_FAILED,
            phase=hcmd.PHASE_RX_RESPONSE_NO_BUFFER))
        event = failed_no_buffer["key_response_slot"]["event"]
        self.assertEqual(event["phase"], hcmd.PHASE_RX_RESPONSE_NO_BUFFER)
        self.assertTrue(event["command_response_failed_flag"])

        # Phase 8 also covers malformed-length rejection without a failed
        # command bit; keep the two observations independent.
        length_reject = hcmd.decode_snapshot(hcmd_sample(
            flags=1 << 11, payload_length=2,
            phase=hcmd.PHASE_RX_RESPONSE_LENGTH_REJECT))
        event = length_reject["key_response_slot"]["event"]
        self.assertEqual(event["phase"], hcmd.PHASE_RX_RESPONSE_LENGTH_REJECT)
        self.assertFalse(event["command_response_failed_flag"])

    def test_slot_dropped_serial_after_saved_serial_is_unknown(self):
        sample = hcmd_sample()
        sample["key_response"]["NativeKeyResponseDroppedSerial"] = 2
        decoded = hcmd.decode_snapshot(sample)
        self.assertEqual(decoded["key_response_slot"]["status"],
                         "latest_slot_superseded_by_dropped_event")
        self.assertIsNone(decoded["key_response_slot"]["event"])

    def test_slot_ring_mismatch_is_rejected(self):
        sample = hcmd_sample()
        sample["key_response"]["NativeKeyResponseIndex"] = 7
        with self.assertRaisesRegex(hcmd.HcmdTraceError,
                                     "key_response_ring_slot_field_mismatch"):
            hcmd.decode_snapshot(sample)

    def test_rejects_publish_revision_mismatch_and_companion_mismatch(self):
        sample = hcmd_sample()
        sample["publish_revision_end"] = 4
        with self.assertRaisesRegex(hcmd.HcmdTraceError, "publish_revision_unstable"):
            hcmd.decode_snapshot(sample)
        sample = hcmd_sample()
        sample["markers"]["NativeHcmdRxTraceOwnerGeneration"] = 99
        with self.assertRaisesRegex(hcmd.HcmdTraceError, "companion_mismatch"):
            hcmd.decode_snapshot(sample)

    def test_summary_marks_history_loss_and_deduplicates_serial(self):
        decoded = hcmd.decode_snapshot(hcmd_sample(overwritten=1))
        summary = hcmd.summarize_samples([
            {"decoded": decoded, "host_monotonic_lower_ns": 100,
             "host_monotonic_upper_ns": 200},
            {"decoded": decoded, "host_monotonic_lower_ns": 300,
             "host_monotonic_upper_ns": 400},
        ])
        self.assertTrue(decoded["window_history_truncated"])
        self.assertEqual(summary["unique_add_sta_key_response_count"], 1)


class SenderAdapterTests(unittest.TestCase):
    def test_full_new_schema_is_classified_then_projected_for_test088(self):
        event = sender_result_fixture()
        result = adapter.classify_sender_result(event)
        self.assertEqual(result["evidence_scope"], "synthetic")
        self.assertEqual(result["send"]["local_send_accepted"], 4)
        self.assertFalse(result["rf_transmission_proven"])
        self.assertFalse(result["ack_proven"])
        self.assertEqual(result["test088_legacy_projection"]["frames_completed"], 4)
        self.assertNotIn("tx_provenance", result["test088_legacy_projection"])

    def test_adapter_rejects_missing_new_provenance(self):
        event = sender_result_fixture()
        del event["tx_provenance"]
        with self.assertRaises(adapter.SenderAdapterError):
            adapter.project_legacy_result(event)


class RuntimeBindingTests(unittest.TestCase):
    def test_receipt_must_pin_candidate_source_binary_and_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            receipt_dir = root / binding.SENDER_RECEIPT_RELATIVE.parent
            receipt_dir.mkdir(mode=0o700, parents=True)
            binary_rel = binding.SENDER_BINARY_RELATIVE
            binary = ROOT / binary_rel
            source_sha = hashlib.sha256(binding.SENDER_SOURCE.read_bytes()).hexdigest()
            binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            receipt = {
                "candidate": "25G332-Test101", "status": "built_offline",
                "target": "aarch64-linux-musl",
                "source_path": "developer-tools/openwrt-tx-observation/afpacket-sender/awdl_probe_sender.c",
                "source_sha256": source_sha, "binary_path": binary_rel.as_posix(),
                "binary_sha256": binary_sha,
                "provenance_schema": "openwrt-tx-observation/v1",
                "command": ["zig", "cc", "-target", "aarch64-linux-musl"],
            }
            receipt_path = root / binding.SENDER_RECEIPT_RELATIVE
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)
            loaded = binding._load_sender_binding(root)
            self.assertEqual(loaded["source_sha256"], binding.SENDER_SOURCE_SHA256)
            self.assertEqual(loaded["binary_sha256"], binding.SENDER_BINARY_SHA256)
            receipt["binary_sha256"] = "0" * 64
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)
            with self.assertRaisesRegex(binding.RuntimeBindingError,
                                         "test101_sender_receipt_binding_invalid"):
                binding._load_sender_binding(root)

    def test_missing_explicit_root_is_rejected(self):
        with self.assertRaisesRegex(binding.RuntimeBindingError,
                                     "explicit_iwn_root_required"):
            binding._require_root(None)

    def test_plan_is_disarmed_and_has_exact_sender_pin(self):
        output = runner.plan()
        self.assertEqual(output["sender_sha256"], runner.EXPECTED_SENDER_BINARY_SHA256)
        self.assertEqual(output["sender_source_sha256"],
                         runner.EXPECTED_SENDER_SOURCE_SHA256)
        self.assertEqual(output["default_action"], "none")
        self.assertFalse(output["rf_triggered"])
        self.assertFalse(output["efi_modified"])

    def test_go_guard_refuses_stale_window_before_writing(self):
        token = "a" * 32
        ready = {"hard_deadline_us": 100_000, "observed_now_us": 10_000,
                 "run_token": token, "start_observed_us": 0}
        report = {"native_armed_ack": {"native_rx_ready": ready},
                  "boot_claim_consumed": True}
        stream = _FakeStream()
        session = types.SimpleNamespace(
            closed=False, control_consumed=False, capture=types.SimpleNamespace(report=report),
            process=types.SimpleNamespace(stdin=stream, stdout=None),
            selector=_FakeSelector(), run_token=token, protocol_evidence={},
            deadline=1.0, read_state={},
        )
        values = iter((20_000, 50_000))  # READY passes; BEGIN has <60ms remaining.
        restore = runner.install_go_deadline_guard(clock=lambda: next(values))
        with mock.patch.object(runner.TEST088.ROUTER, "_terminate_process", lambda _p: None):
            try:
                with self.assertRaises(runner.PROTOCOL.ControlledProbeError):
                    runner.TEST088.Test088SenderSession(session, types.SimpleNamespace(
                        report=report)).go_once()
            finally:
                restore()
        self.assertEqual(stream.writes, [])
        self.assertEqual(stream.flush_count, 0)
        self.assertTrue(session.control_consumed)
        self.assertFalse(report["native_rx_go_gate"]["go_written"])
        self.assertTrue(report["native_rx_go_gate"]["no_go_written"])
        self.assertFalse(report["native_rx_go_gate"]["retry_allowed"])


class _FakeStream:
    def __init__(self):
        self.writes = []
        self.flush_count = 0
        self.closed = False

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        self.flush_count += 1

    def close(self):
        self.closed = True


class _FakeSelector:
    def close(self):
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
