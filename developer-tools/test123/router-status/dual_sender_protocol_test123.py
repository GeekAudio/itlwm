#!/usr/bin/env python3
"""Strict Test123 router-sender protocol for a live Test122 kernel.

The packet-set codec and monitor validator are reused as pure validators.
This module does not open sockets, contact a router, or arm a device.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[2]
PACKETSET_PATH = REPO_ROOT / "developer-tools/test122/router-status/packetset_correlated_test122.py"
MONITOR_VALIDATOR_PATH = REPO_ROOT / "developer-tools/test122/router-status/router_status_tail_test122.py"
LEGACY_PROTOCOL_PATH = REPO_ROOT / "developer-tools/test119/dual_sender_protocol_test119.py"

SCHEMA = SENDER_SCHEMA = "test123-router-status-sender/v1"
MONITOR_SCHEMA = "test123-router-status-monitor/v1"
PACKETSET_SCHEMA = "test122-correlated-packet-set/v2"
TOOL_TEST = "Test123"
RUNNING_KERNEL_TEST = "Test122"
OBSERVATION_TIME_SEMANTICS = "userspace_recvmsg_return"
FRAME_COUNT = 4
INTERVAL_MS = 10
SEND_BUDGET_NS = 40_000_000
STATUS_TAIL_NS = 2_000_000_000
CAPTURE_WINDOW_NS = SEND_BUDGET_NS + STATUS_TAIL_NS
DRIVER_RX_LEASE_MS = 100
GO_TO_START_MAX_NS = 5_000_000
MAX_LINE_BYTES = 128 * 1024
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
WIRE_RE = re.compile(r"^(?!0{16}$)[0-9a-f]{16}$")


class SenderProtocolError(ValueError):
    """Raised when a sender record violates the frozen Test123 contract."""


class SenderAdapterError(ValueError):
    """Raised when a sender result cannot be summarized safely."""


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST123_PROTOCOL_DEPENDENCY_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST123_PROTOCOL_DEPENDENCY_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


_PACKETSET = _load("test123_frozen_test122_packetset", PACKETSET_PATH)
_MONITOR = _load("test123_frozen_test122_monitor_validator", MONITOR_VALIDATOR_PATH)
_LEGACY = _load("test123_frozen_test119_legacy_projection", LEGACY_PROTOCOL_PATH)
_MONITOR.MONITOR_SCHEMA = MONITOR_SCHEMA

_ACTIVE_PACKETSET_MANIFEST: dict | None = None
_ACTIVE_WIRE_NONCE_HEX: str | None = None

READY_VALUES = {
    "schema": SCHEMA,
    "tool_test": TOOL_TEST,
    "running_kernel_test": RUNNING_KERNEL_TEST,
    "packet_set_schema": PACKETSET_SCHEMA,
    "frames": "4",
    "interval_ms": "10",
    "mpdu_bytes": "96",
    "radiotap_bytes": "10",
    "packet_bytes": "106",
    "send_budget_ms": "40",
    "status_tail_ms": "2000",
    "driver_rx_lease_ms": "100",
    "tx_flags": "NOSEQNO",
    "hardware_honoring": "unknown",
    "noack_requested": "false",
    "intel_arm_invoked": "false",
    "boot_claim_used": "false",
    "observation_time_semantics": OBSERVATION_TIME_SEMANTICS,
}

STARTED_FIELDS = {
    "event", "schema", "tool_test", "running_kernel_test", "packet_set_schema",
    "clock_domain", "observation_time_semantics", "run_token", "wire_nonce_hex",
    "driver_rx_lease_ms", "go_received_ns", "started_ns", "send_deadline_ns",
    "observer_deadline_ns", "go_to_start_ns", "go_to_start_max_ns",
    "send_budget_ns", "status_tail_ns", "frames_requested", "interval_ms",
    "tx_flags_requested", "noack_requested", "intel_arm_invoked", "boot_claim_used",
}

RESULT_FIELDS = {
    "event", "schema", "tool_test", "running_kernel_test", "packet_set_schema",
    "observation_time_semantics", "clock_domain", "status", "run_token",
    "wire_nonce_hex", "run_token_in_frame", "driver_rx_lease_ms", "go_received_ns",
    "frames_requested", "frames_attempted", "frames_completed", "send_complete",
    "packet_bytes", "radiotap_bytes", "mpdu_bytes", "payload_bytes",
    "udp_payload_bytes", "sent", "elapsed_ms", "deadline_hit", "error_count",
    "last_errno", "stop_reason", "sender_stop_reason", "tx_flags_requested", "noack_requested", "ack_policy",
    "hardware_honoring", "raw_txs", "mac_ack", "interval_ms", "timing_schema",
    "send_budget_ns", "status_tail_ns", "capture_window_ns", "started_ns",
    "send_deadline_ns", "observer_deadline_ns", "finished_ns", "go_to_start_ns",
    "go_to_start_max_ns", "first_send_ns", "local_send_calls", "actual_horizon_ns",
    "pre_capture_queue_drain", "send_timing", "monitor_observation",
    "radio_transmission_proven", "rf_transmission_proven", "firmware_tx_status_proven",
    "peer_receipt_proven", "airdrop_proven", "intel_arm_invoked", "boot_claim_used",
}

ABORTED_FIELDS = {
    "event", "schema", "tool_test", "running_kernel_test", "packet_set_schema",
    "status", "run_token", "wire_nonce_hex", "run_token_in_frame", "frames_requested",
    "frames_attempted", "frames_completed", "send_complete", "send_budget_ms",
    "status_tail_ms", "driver_rx_lease_ms", "tx_flags_requested", "noack_requested",
    "radio_transmission_proven", "rf_transmission_proven", "firmware_tx_status_proven",
    "mac_ack", "peer_receipt_proven", "airdrop_proven", "intel_arm_invoked",
    "boot_claim_used",
}

QUEUE_FIELDS = {
    "read_attempts", "packets_drained", "receive_error", "drain_complete",
    "kernel_stats_available", "kernel_packets", "kernel_dropped_packets",
}


def _wire_nonce(value: Any) -> str:
    if not isinstance(value, str) or not WIRE_RE.fullmatch(value):
        raise SenderProtocolError("wire_nonce_invalid")
    return value


def _token(value: Any) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise SenderProtocolError("run_token_invalid")
    return value


def _expected_nonce(explicit: str | None) -> str:
    expected = explicit if explicit is not None else _ACTIVE_WIRE_NONCE_HEX
    return _wire_nonce(expected)


def bind_packet_set(packet_set: bytes | bytearray | Path,
                    *, expected_sha256: str | None = None) -> dict:
    """Bind protocol validation to the exact same Test122 v2 packet set."""
    global _ACTIVE_PACKETSET_MANIFEST, _ACTIVE_WIRE_NONCE_HEX
    if isinstance(packet_set, Path):
        if packet_set.is_symlink() or not packet_set.is_file():
            raise SenderProtocolError("packet_set_path_invalid")
        raw = packet_set.read_bytes()
    elif isinstance(packet_set, (bytes, bytearray)):
        raw = bytes(packet_set)
    else:
        raise SenderProtocolError("packet_set_input_invalid")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise SenderProtocolError("packet_set_sha256_mismatch")
    try:
        manifest = _PACKETSET.decode_packet_set(raw)
    except Exception as error:
        raise SenderProtocolError("packet_set_v2_invalid") from error
    if (manifest.get("schema") != PACKETSET_SCHEMA or manifest.get("valid") is not True or
            manifest.get("frame_count") != FRAME_COUNT or
            manifest.get("packet_set_sha256") != digest or
            len(manifest.get("frames", [])) != FRAME_COUNT):
        raise SenderProtocolError("packet_set_v2_contract_mismatch")
    _ACTIVE_PACKETSET_MANIFEST = dict(manifest)
    _ACTIVE_WIRE_NONCE_HEX = _wire_nonce(manifest.get("wire_nonce_hex"))
    return dict(manifest)


def clear_packet_set_binding() -> None:
    global _ACTIVE_PACKETSET_MANIFEST, _ACTIVE_WIRE_NONCE_HEX
    _ACTIVE_PACKETSET_MANIFEST = None
    _ACTIVE_WIRE_NONCE_HEX = None


def parse_packetset_valid(line: str, *, expected_wire_nonce_hex: str | None = None) -> dict:
    prefix = "PACKET_SET_VALID "
    if not isinstance(line, str) or not line.startswith(prefix):
        raise SenderProtocolError("packetset_verification_malformed")
    value = _json(line[len(prefix):], "packetset_verification")
    fields = {"event", "schema", "frames", "interval_ms", "budget_ms",
              "noack_requested", "transmission_capability", "rf_transmission_proven",
              "wire_nonce_hex"}
    if (set(value) != fields or value.get("event") != "PACKET_SET_VALID" or
            value.get("schema") != PACKETSET_SCHEMA or value.get("frames") != 4 or
            value.get("interval_ms") != 10 or value.get("budget_ms") != 40 or
            value.get("noack_requested") is not False or
            value.get("transmission_capability") is not False or
            value.get("rf_transmission_proven") is not False):
        raise SenderProtocolError("packetset_verification_contract_mismatch")
    nonce = _wire_nonce(value["wire_nonce_hex"])
    expected = expected_wire_nonce_hex if expected_wire_nonce_hex is not None else _ACTIVE_WIRE_NONCE_HEX
    if expected is not None and nonce != _wire_nonce(expected):
        raise SenderProtocolError("packetset_verification_nonce_mismatch")
    return dict(value)


def _json(value: Any, label: str) -> dict:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_LINE_BYTES:
        raise SenderProtocolError(label + "_line_invalid")
    try:
        def unique_fields(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise SenderProtocolError(label + "_duplicate_json_field")
                result[key] = item
            return result
        parsed = json.loads(value, object_pairs_hook=unique_fields)
    except (ValueError, TypeError) as error:
        raise SenderProtocolError(label + "_json_invalid") from error
    if not isinstance(parsed, dict):
        raise SenderProtocolError(label + "_not_object")
    return parsed


def parse_ready(line: str, expected_wire_nonce_hex: str | None = None) -> dict:
    if not isinstance(line, str) or not line.startswith("READY "):
        raise SenderProtocolError("sender_ready_malformed")
    values: dict[str, str] = {}
    for item in line[6:].split():
        if item.count("=") != 1:
            raise SenderProtocolError("sender_ready_malformed")
        key, value = item.split("=", 1)
        if not key or not value or key in values:
            raise SenderProtocolError("sender_ready_malformed")
        values[key] = value
    nonce = _wire_nonce(values.pop("wire_nonce_hex", None))
    if values != READY_VALUES:
        raise SenderProtocolError("sender_ready_contract_mismatch")
    expected = _expected_nonce(expected_wire_nonce_hex)
    if nonce != expected:
        raise SenderProtocolError("sender_ready_nonce_mismatch")
    if _ACTIVE_PACKETSET_MANIFEST is None:
        raise SenderProtocolError("packet_set_manifest_not_bound")
    return {
        "schema": SCHEMA, "tool_test": TOOL_TEST,
        "running_kernel_test": RUNNING_KERNEL_TEST,
        "packet_set_schema": PACKETSET_SCHEMA,
        "wire_nonce_hex": nonce, "frames": FRAME_COUNT, "interval_ms": INTERVAL_MS,
        "mpdu_bytes": 96, "radiotap_bytes": 10, "packet_bytes": 106,
        "send_budget_ms": 40, "status_tail_ms": 2000,
        "driver_rx_lease_ms": DRIVER_RX_LEASE_MS,
        "observation_time_semantics": OBSERVATION_TIME_SEMANTICS,
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "hardware_honoring": "unknown", "intel_arm_invoked": False,
        "boot_claim_used": False, "send_started": False,
    }


def _integer_fields(value: dict, keys: tuple[str, ...], label: str,
                    *, allow_negative: bool = False) -> None:
    for key in keys:
        item = value.get(key)
        if type(item) is not int or (item < 0 and not allow_negative):
            raise SenderProtocolError(label + "_integer_invalid:" + key)


def parse_started(value: Any, run_token: str,
                  expected_wire_nonce_hex: str | None = None) -> dict:
    token = _token(run_token)
    if not isinstance(value, dict) or set(value) != STARTED_FIELDS:
        raise SenderProtocolError("sender_started_field_set_invalid")
    _integer_fields(value, (
        "driver_rx_lease_ms", "go_received_ns", "started_ns", "send_deadline_ns",
        "observer_deadline_ns", "go_to_start_ns", "go_to_start_max_ns", "send_budget_ns",
        "status_tail_ns", "frames_requested", "interval_ms"), "sender_started")
    nonce = _wire_nonce(value.get("wire_nonce_hex"))
    if (value.get("event") != "SENDER_STARTED" or value.get("schema") != SCHEMA or
            value.get("tool_test") != TOOL_TEST or
            value.get("running_kernel_test") != RUNNING_KERNEL_TEST or
            value.get("packet_set_schema") != PACKETSET_SCHEMA or
            value.get("clock_domain") != "CLOCK_MONOTONIC" or
            value.get("observation_time_semantics") != OBSERVATION_TIME_SEMANTICS or
            value.get("run_token") != token or nonce != _expected_nonce(expected_wire_nonce_hex) or
            value.get("driver_rx_lease_ms") != DRIVER_RX_LEASE_MS or
            value.get("started_ns") < value.get("go_received_ns") or
            value.get("send_deadline_ns") != value["started_ns"] + SEND_BUDGET_NS or
            value.get("observer_deadline_ns") != value["send_deadline_ns"] + STATUS_TAIL_NS or
            value.get("go_to_start_ns") != value["started_ns"] - value["go_received_ns"] or
            value.get("go_to_start_max_ns") != GO_TO_START_MAX_NS or
            value.get("send_budget_ns") != SEND_BUDGET_NS or
            value.get("status_tail_ns") != STATUS_TAIL_NS or
            value.get("frames_requested") != FRAME_COUNT or
            value.get("interval_ms") != INTERVAL_MS or
            value.get("tx_flags_requested") != "NOSEQNO" or
            value.get("noack_requested") is not False or
            value.get("intel_arm_invoked") is not False or
            value.get("boot_claim_used") is not False):
        raise SenderProtocolError("sender_started_contract_mismatch")
    return {**value, "start_lease_valid": value["go_to_start_ns"] <= GO_TO_START_MAX_NS}


def validate_send_timing(sender_result: dict, packet_set_manifest: dict) -> list[dict]:
    """Validate send rows against this run's exact Test122 v2 wire sequences."""
    if not isinstance(sender_result, dict) or not isinstance(packet_set_manifest, dict):
        raise SenderProtocolError("send_timing_binding_invalid")
    if (packet_set_manifest.get("schema") != PACKETSET_SCHEMA or
            packet_set_manifest.get("valid") is not True or
            packet_set_manifest.get("wire_nonce_hex") != sender_result.get("wire_nonce_hex")):
        raise SenderProtocolError("send_timing_packetset_binding_mismatch")
    frames = packet_set_manifest.get("frames")
    rows = sender_result.get("send_timing")
    if not isinstance(frames, list) or len(frames) != FRAME_COUNT or not isinstance(rows, list):
        raise SenderProtocolError("send_timing_rows_invalid")
    if (type(sender_result.get("frames_attempted")) is not int or
            len(rows) != sender_result["frames_attempted"] or len(rows) > FRAME_COUNT):
        raise SenderProtocolError("send_timing_count_invalid")
    started = sender_result.get("started_ns")
    deadline = sender_result.get("send_deadline_ns")
    go = sender_result.get("go_received_ns")
    if any(type(item) is not int for item in (started, deadline, go)):
        raise SenderProtocolError("send_timing_clock_invalid")
    completed = 0
    previous_before: int | None = None
    for ordinal, row in enumerate(rows):
        fields = {"ordinal", "ieee80211_sequence", "ieee80211_sequence_control",
                  "awdl_sequence", "before_ns", "after_ns", "return_bytes", "errno"}
        if not isinstance(row, dict) or set(row) != fields:
            raise SenderProtocolError("send_timing_field_set_invalid")
        _integer_fields(row, ("ordinal", "ieee80211_sequence", "ieee80211_sequence_control",
                              "awdl_sequence", "before_ns", "errno"),
                        "send_timing")
        after = row.get("after_ns")
        after_missing = after is None
        if not after_missing and (type(after) is not int or after < 0):
            raise SenderProtocolError("send_timing_after_clock_invalid")
        is_last = ordinal == len(rows) - 1
        returned = row.get("return_bytes")
        expected = frames[ordinal]
        expected_sc = expected.get("sequence_control")
        expected_wifi = expected.get("wifi_sequence")
        expected_awdl = expected.get("awdl_sequence")
        if (row["ordinal"] != ordinal or row["ieee80211_sequence"] != expected_wifi or
                row["ieee80211_sequence_control"] != expected_sc or
                row["awdl_sequence"] != expected_awdl or
                row["ieee80211_sequence_control"] != row["ieee80211_sequence"] << 4 or
                not 0 <= row["ieee80211_sequence"] <= 0x0FFF or
                not 0 <= row["awdl_sequence"] <= 0xFFFF or
                type(returned) is not int or not -1 <= returned <= 106 or
                (returned == -1 and row["errno"] == 0) or
                (returned >= 0 and row["errno"] != 0) or
                row["before_ns"] < go or row["before_ns"] < started or
                row["before_ns"] >= deadline or
                (after_missing and (not is_last or sender_result.get("send_complete") is True)) or
                (not after_missing and after < row["before_ns"]) or
                (not after_missing and after > deadline and not (
                    is_last and sender_result.get("sender_stop_reason") ==
                    "send_completed_after_budget"))):
            raise SenderProtocolError("send_timing_row_invalid")
        if previous_before is not None and row["before_ns"] - previous_before < INTERVAL_MS * 1_000_000:
            raise SenderProtocolError("send_timing_spacing_invalid")
        previous_before = row["before_ns"]
        completed += returned == 106
    if completed != sender_result.get("frames_completed"):
        raise SenderProtocolError("send_timing_completion_count_mismatch")
    if rows and rows[0]["before_ns"] - go > GO_TO_START_MAX_NS:
        raise SenderProtocolError("send_timing_first_send_lease_exceeded")
    return [dict(row) for row in rows]


def _validate_queue(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != QUEUE_FIELDS:
        raise SenderProtocolError("pre_capture_queue_field_set_invalid")
    _integer_fields(value, ("read_attempts", "packets_drained"), "pre_capture_queue")
    if type(value.get("receive_error")) is not int:
        raise SenderProtocolError("pre_capture_queue_errno_invalid")
    for key in ("drain_complete", "kernel_stats_available"):
        if type(value.get(key)) is not bool:
            raise SenderProtocolError("pre_capture_queue_boolean_invalid:" + key)
    if value["packets_drained"] > value["read_attempts"]:
        raise SenderProtocolError("pre_capture_queue_count_invalid")
    if value["kernel_stats_available"]:
        _integer_fields(value, ("kernel_packets", "kernel_dropped_packets"), "pre_capture_queue")
    elif value.get("kernel_packets") is not None or value.get("kernel_dropped_packets") is not None:
        raise SenderProtocolError("pre_capture_queue_unknown_stats_invalid")
    return dict(value)


def _validate_monitor_non_gating(value: Any, *, started: int, deadline: int,
                                 observer_deadline: int) -> tuple[dict, str]:
    """Validate monitor structure while retaining a valid-but-incomplete run.

    The frozen Test122 validator intentionally accepts only a completed window.
    Test123 must still preserve a bounded incomplete observation so an observer
    failure cannot discard the independent native listener result.
    """
    if not isinstance(value, dict) or set(value) != _MONITOR.MONITOR_FIELDS:
        raise SenderProtocolError("monitor_observation_field_set_invalid")
    end = value.get("ended_ns")
    if (type(end) is not int or end < started or
            type(value.get("actual_horizon_ns")) is not int or
            value.get("actual_horizon_ns") != end - started or
            end > observer_deadline + 100_000_000):
        raise SenderProtocolError("monitor_observation_time_invalid")
    for rows_key in ("samples", "status_candidate_samples", "nonmatch_samples"):
        rows = value.get(rows_key)
        if not isinstance(rows, list):
            raise SenderProtocolError("monitor_observation_samples_invalid")
        try:
            _MONITOR._validate_sample_times(rows, started=started, ended=end)
        except Exception as error:
            raise SenderProtocolError("monitor_observation_sample_time_invalid") from error

    complete = (value.get("capture_finished") is True and
                value.get("capture_limit_reached") is False and
                value.get("receive_error") == 0 and end >= observer_deadline)
    if complete:
        try:
            return (_MONITOR._validate_monitor(
                value, started=started, deadline=deadline,
                observer_deadline=observer_deadline), "complete")
        except Exception as error:
            raise SenderProtocolError("monitor_observation_invalid") from error

    # An incomplete capture must never be presented as loss-free. Validate the
    # unchanged arrays/counters with the frozen validator using a private copy
    # normalized only for that validator's completion gate, then retain and
    # return the original, truthful incomplete record.
    if value.get("capture_loss_free") is not False:
        raise SenderProtocolError("monitor_incomplete_loss_claim_invalid")
    candidate = dict(value)
    candidate["capture_finished"] = True
    candidate["capture_limit_reached"] = False
    candidate["receive_error"] = 0
    candidate["ended_ns"] = max(end, observer_deadline)
    candidate["actual_horizon_ns"] = candidate["ended_ns"] - started
    if candidate.get("truncated_packets", 0) > 0:
        candidate["capture_loss_free"] = False
    elif candidate.get("kernel_stats_available") is True:
        candidate["capture_loss_free"] = (
            candidate.get("kernel_packets") == candidate.get("packets_received") and
            candidate.get("kernel_dropped_packets") == 0)
    else:
        candidate["capture_loss_free"] = None
    try:
        _MONITOR._validate_monitor(
            candidate, started=started, deadline=deadline,
            observer_deadline=observer_deadline)
    except Exception as error:
        raise SenderProtocolError("monitor_incomplete_structure_invalid") from error
    return dict(value), "incomplete"


def validate_result(value: Any, run_token: str,
                    expected_wire_nonce_hex: str | None = None,
                    packet_set_manifest: dict | None = None) -> dict:
    token = _token(run_token)
    if not isinstance(value, dict):
        raise SenderProtocolError("sender_result_not_object")
    if value.get("status") == "aborted":
        if set(value) != ABORTED_FIELDS:
            raise SenderProtocolError("sender_abort_field_set_invalid")
        nonce = _wire_nonce(value.get("wire_nonce_hex"))
        if (value.get("event") != "SENDER_RESULT" or value.get("schema") != SCHEMA or
                value.get("tool_test") != TOOL_TEST or
                value.get("running_kernel_test") != RUNNING_KERNEL_TEST or
                value.get("packet_set_schema") != PACKETSET_SCHEMA or
                value.get("run_token") != token or nonce != _expected_nonce(expected_wire_nonce_hex) or
                value.get("run_token_in_frame") is not False or
                value.get("frames_requested") != FRAME_COUNT or
                value.get("frames_attempted") != 0 or value.get("frames_completed") != 0 or
                value.get("send_complete") is not False or value.get("send_budget_ms") != 40 or
                value.get("status_tail_ms") != 2000 or
                value.get("driver_rx_lease_ms") != DRIVER_RX_LEASE_MS or
                value.get("tx_flags_requested") != "NOSEQNO" or
                value.get("noack_requested") is not False or
                any(value.get(k) is not False for k in (
                    "radio_transmission_proven", "rf_transmission_proven",
                    "firmware_tx_status_proven", "peer_receipt_proven", "airdrop_proven",
                    "intel_arm_invoked", "boot_claim_used")) or value.get("mac_ack") != "unknown"):
            raise SenderProtocolError("sender_abort_contract_mismatch")
        return dict(value)

    if set(value) != RESULT_FIELDS:
        raise SenderProtocolError("sender_result_field_set_invalid")
    _integer_fields(value, (
        "driver_rx_lease_ms", "go_received_ns", "frames_requested", "frames_attempted",
        "frames_completed", "packet_bytes", "radiotap_bytes", "mpdu_bytes",
        "payload_bytes", "udp_payload_bytes", "sent", "elapsed_ms", "error_count",
        "send_budget_ns", "status_tail_ns", "capture_window_ns", "timing_schema",
        "started_ns", "send_deadline_ns", "observer_deadline_ns", "finished_ns",
        "go_to_start_ns", "go_to_start_max_ns", "local_send_calls", "actual_horizon_ns"),
        "sender_result")
    if type(value.get("last_errno")) is not int:
        raise SenderProtocolError("sender_result_errno_invalid")
    bools = ("run_token_in_frame", "send_complete", "deadline_hit", "noack_requested",
             "radio_transmission_proven", "rf_transmission_proven", "firmware_tx_status_proven",
             "peer_receipt_proven", "airdrop_proven", "intel_arm_invoked", "boot_claim_used")
    if any(type(value.get(key)) is not bool for key in bools):
        raise SenderProtocolError("sender_result_boolean_invalid")
    nonce = _wire_nonce(value.get("wire_nonce_hex"))
    if value.get("wire_nonce_hex") != _expected_nonce(expected_wire_nonce_hex):
        raise SenderProtocolError("sender_result_nonce_mismatch")
    if _ACTIVE_PACKETSET_MANIFEST is None and packet_set_manifest is None:
        raise SenderProtocolError("packet_set_manifest_not_bound")
    manifest = packet_set_manifest or _ACTIVE_PACKETSET_MANIFEST
    if (value.get("event") != "SENDER_RESULT" or value.get("schema") != SCHEMA or
            value.get("tool_test") != TOOL_TEST or
            value.get("running_kernel_test") != RUNNING_KERNEL_TEST or
            value.get("packet_set_schema") != PACKETSET_SCHEMA or
            value.get("observation_time_semantics") != OBSERVATION_TIME_SEMANTICS or
            value.get("clock_domain") != "CLOCK_MONOTONIC" or value.get("run_token") != token or
            value.get("run_token_in_frame") is not False or
            value.get("driver_rx_lease_ms") != DRIVER_RX_LEASE_MS or
            value.get("frames_requested") != FRAME_COUNT or
            value.get("packet_bytes") != 106 or value.get("radiotap_bytes") != 10 or
            value.get("mpdu_bytes") != 96 or value.get("payload_bytes") != 96 or
            value.get("udp_payload_bytes") != 8 or value.get("interval_ms") != INTERVAL_MS or
            value.get("timing_schema") != 1 or value.get("send_budget_ns") != SEND_BUDGET_NS or
            value.get("status_tail_ns") != STATUS_TAIL_NS or
            value.get("capture_window_ns") != CAPTURE_WINDOW_NS or
            value.get("started_ns") < value.get("go_received_ns") or
            value.get("send_deadline_ns") != value["started_ns"] + SEND_BUDGET_NS or
            value.get("observer_deadline_ns") != value["send_deadline_ns"] + STATUS_TAIL_NS or
            value.get("finished_ns") < value.get("started_ns") or
            value.get("actual_horizon_ns") != value["finished_ns"] - value["started_ns"] or
            value.get("go_to_start_ns") != value["started_ns"] - value["go_received_ns"] or
            value.get("go_to_start_max_ns") != GO_TO_START_MAX_NS or
            value.get("tx_flags_requested") != "NOSEQNO" or
            value.get("noack_requested") is not False or
            value.get("ack_policy") != "normal_unicast_requested" or
            value.get("hardware_honoring") != "unknown" or value.get("raw_txs") != "unknown" or
            value.get("mac_ack") != "unknown" or value.get("radio_transmission_proven") is not False or
            value.get("rf_transmission_proven") is not False or
            value.get("firmware_tx_status_proven") is not False or
            value.get("peer_receipt_proven") is not False or value.get("airdrop_proven") is not False or
            value.get("intel_arm_invoked") is not False or value.get("boot_claim_used") is not False or
            value.get("local_send_calls") != value.get("frames_attempted") or
            value.get("frames_attempted") > FRAME_COUNT or
            value.get("frames_completed") > value.get("frames_attempted") or
            value.get("sent") != value.get("frames_completed")):
        raise SenderProtocolError("sender_result_contract_mismatch")
    if value.get("status") not in ("complete", "failed"):
        raise SenderProtocolError("sender_result_status_invalid")
    if value.get("send_complete") is not (value.get("status") == "complete"):
        raise SenderProtocolError("sender_result_send_status_mismatch")
    legacy_stop_reasons = {
        "complete", "gate_eof_timeout_or_invalid_token", "post_go_control_or_stdin_closed",
        "send_errno", "short_write", "host_test_send_disabled",
        "monotonic_clock_unavailable", "monotonic_clock_end_failed", "partial_sequence",
        "schedule_or_sleep_failed", "send_budget_expired", "send_completed_after_budget",
        "socket_close_error",
    }
    sender_stop_reasons = {
        "complete", "observer_drain_incomplete", "go_to_start_budget_expired",
        "send_budget_expired", "sender_started_output_failed", "clock_before_failed",
        "schedule_wait_failed", "send_spacing_violation", "send_errno", "short_write",
        "clock_after_failed", "send_completed_after_budget", "partial_sequence",
    }
    if value.get("stop_reason") not in legacy_stop_reasons:
        raise SenderProtocolError("sender_result_legacy_stop_reason_invalid")
    if value.get("sender_stop_reason") not in sender_stop_reasons:
        raise SenderProtocolError("sender_result_stop_reason_invalid")
    if value["send_complete"]:
        if (value["frames_attempted"] != FRAME_COUNT or
                value["frames_completed"] != FRAME_COUNT or value["error_count"] != 0 or
                value["last_errno"] != 0 or value.get("stop_reason") != "complete" or
                value.get("sender_stop_reason") != "complete" or
                value.get("deadline_hit") is not False or
                value.get("go_to_start_ns") > GO_TO_START_MAX_NS):
            raise SenderProtocolError("sender_result_completion_claim_invalid")
    elif (value["stop_reason"] == "complete" or
          value.get("sender_stop_reason") == "complete"):
        raise SenderProtocolError("sender_result_incomplete_reason_invalid")
    if (value.get("go_to_start_ns") > GO_TO_START_MAX_NS and
            value.get("sender_stop_reason") != "go_to_start_budget_expired"):
        raise SenderProtocolError("sender_go_to_start_failure_reason_mismatch")
    if value["deadline_hit"] != (value["sender_stop_reason"] in {
            "send_budget_expired", "send_completed_after_budget"}):
        raise SenderProtocolError("sender_result_deadline_contradiction")
    rows = validate_send_timing(value, manifest)
    if value["frames_attempted"] == 0 and value["first_send_ns"] is not None:
        raise SenderProtocolError("sender_first_send_presence_mismatch")
    if value["frames_attempted"] > 0 and value["first_send_ns"] != rows[0]["before_ns"]:
        raise SenderProtocolError("sender_first_send_timestamp_mismatch")
    first = value.get("first_send_ns")
    if first is not None and (type(first) is not int or first - value["go_received_ns"] > GO_TO_START_MAX_NS):
        raise SenderProtocolError("sender_first_send_lease_exceeded")
    if value.get("error_count") != (1 if value.get("last_errno") else 0):
        raise SenderProtocolError("sender_error_count_mismatch")
    queue = _validate_queue(value.get("pre_capture_queue_drain"))
    monitor, monitor_state = _validate_monitor_non_gating(
        value.get("monitor_observation"), started=value["started_ns"],
        deadline=value["send_deadline_ns"],
        observer_deadline=value["observer_deadline_ns"])
    if value["finished_ns"] != monitor["ended_ns"]:
        raise SenderProtocolError("sender_monitor_horizon_mismatch")
    if value["status"] == "complete" and not queue["drain_complete"]:
        raise SenderProtocolError("sender_clean_status_with_dirty_queue")
    return {**value, "pre_capture_queue_drain": queue,
            "monitor_observation": monitor,
            "monitor_observation_state": monitor_state,
            "sender_status_is_non_gating_for_rx": True,
            "send_sequence_checked_against_packetset": True}


def legacy_projection(value: dict) -> dict:
    """Minimal legacy shape for the frozen Test104/Test087 parser seam only."""
    raw = _LEGACY.legacy_projection(value)
    return raw


def project_legacy_result(value: dict, run_token: str,
                          expected_wire_nonce_hex: str | None = None,
                          packet_set_manifest: dict | None = None) -> dict:
    raw = validate_result(value, run_token, expected_wire_nonce_hex,
                          packet_set_manifest)
    return legacy_projection(raw)


def parse_result_line(line: str, run_token: str,
                      expected_wire_nonce_hex: str | None = None,
                      packet_set_manifest: dict | None = None) -> tuple[dict, dict]:
    raw = validate_result(_json(line, "sender_result"), run_token,
                          expected_wire_nonce_hex, packet_set_manifest)
    return raw, legacy_projection(raw)


def parse_result(line: str, run_token: str,
                 expected_wire_nonce_hex: str | None = None,
                 packet_set_manifest: dict | None = None) -> tuple[dict, dict]:
    return parse_result_line(line, run_token, expected_wire_nonce_hex,
                             packet_set_manifest)


def classify_sender_result(sender_result: Any,
                           expected_wire_nonce_hex: str | None = None,
                           packet_set_manifest: dict | None = None) -> dict:
    if not isinstance(sender_result, dict):
        raise SenderAdapterError("sender_result_not_object")
    token = sender_result.get("run_token")
    try:
        checked = validate_result(sender_result, token, expected_wire_nonce_hex,
                                  packet_set_manifest)
        canonical = json.dumps(sender_result, ensure_ascii=True, sort_keys=True,
                               separators=(",", ":"))
    except (SenderProtocolError, TypeError, ValueError) as error:
        raise SenderAdapterError("sender_result_validation_failed") from error
    monitor = checked["monitor_observation"]
    return {
        "schema": "test123-sender-adapter/v1",
        "status": "local_sender_record_validated",
        "tool_test": TOOL_TEST,
        "running_kernel_test": RUNNING_KERNEL_TEST,
        "raw_sender_result_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "frames_requested": FRAME_COUNT,
        "frames_attempted": checked["frames_attempted"],
        "frames_completed": checked["frames_completed"],
        "send_complete": checked["send_complete"],
        "monitor_observation_state": checked["monitor_observation_state"],
        "monitor_capture_finished": monitor["capture_finished"],
        "monitor_capture_loss_free": monitor["capture_loss_free"],
        "sender_status_is_non_gating_for_rx": True,
        "wire_nonce_in_public_summary": False,
        "raw_packet_bytes_in_public_summary": False,
        "raw_txs": "unknown", "mac_ack": "unknown",
        "rf_transmission_proven": False, "peer_receipt_proven": False,
        "native_awdl0_ingress_proven": False, "airdrop_proven": False,
    }
