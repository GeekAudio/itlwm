#!/usr/bin/env python3
"""Run a router-only, bounded Test122 transmit-status tail observation.

The default invocation is a side-effect-free plan.  An explicit --run stages a
hash-bound sender and packet set over the already-authenticated SSH
ControlMaster, verifies the packet set with the sender before creating a
temporary channel-149 monitor, then requires one GO before the 4-frame/40 ms
send and independent 2 s monitor tail.  This never arms Intel or changes AP,
channel, WAN, or LAN configuration.  Local send completion and monitor samples
are not proof of RF transmission, ACK, peer receipt, or AirDrop.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
TOOL_DIR = Path(__file__).resolve().parent
SCHEMA = "test122-router-status-tail/v2"
SENDER_SCHEMA = "test122-router-status-sender/v2"
MONITOR_SCHEMA = "test122-router-status-monitor/v2"
PACKETSET_SCHEMA = "test122-correlated-packet-set/v2"
AP_INTERFACE = "wlan7"
MONITOR_INTERFACE = "iwtail122"
GO_TO_START_MAX_NS = 5_000_000
SEND_BUDGET_NS = 40_000_000
STATUS_TAIL_NS = 2_000_000_000
CAPTURE_WINDOW_NS = SEND_BUDGET_NS + STATUS_TAIL_NS
MAX_BINARY_BYTES = 2 * 1024 * 1024
MAX_REMOTE_SCRIPT_BYTES = 3 * 1024 * 1024
MAX_REMOTE_LINE_BYTES = 64 * 1024
MAX_REMOTE_OUTPUT_BYTES = 2 * 1024 * 1024
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
WIRE_RE = re.compile(r"^(?!0{16}$)[0-9a-f]{16}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

READY_VALUES = {
    "schema": SENDER_SCHEMA,
    "frames": "4",
    "interval_ms": "10",
    "mpdu_bytes": "96",
    "radiotap_bytes": "10",
    "packet_bytes": "106",
    "send_budget_ms": "40",
    "status_tail_ms": "2000",
    "tx_flags": "NOSEQNO",
    "hardware_honoring": "unknown",
    "noack_requested": "false",
    "intel_arm_invoked": "false",
    "boot_claim_used": "false",
}


class RouterStatusTailError(ValueError):
    """Sanitized local protocol/preflight error."""


def _load_module(name: str, path: Path):
    current = sys.modules.get(name)
    if current is not None:
        return current
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RouterStatusTailError("dependency_unavailable:" + name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def _load_packetset():
    return _load_module("test122_correlated_packetset", TOOL_DIR / "packetset_correlated_test122.py")


def _wire_nonce(value: Any) -> str:
    if not isinstance(value, str) or not WIRE_RE.fullmatch(value):
        raise RouterStatusTailError("wire_nonce_invalid")
    return value


def _load_router_runner():
    path = ROOT / "developer-tools/test087/run_controlled_probe_once.py"
    return _load_module("test122_router_status_tail_transport", path)


def _load_router_protocol():
    path = ROOT / "developer-tools/test087/test087_controlled.py"
    return _load_module("test087_controlled", path)


def _json_record(value: str, label: str) -> dict:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_REMOTE_LINE_BYTES:
        raise RouterStatusTailError(label + "_line_invalid")
    try:
        def unique_fields(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise RouterStatusTailError(label + "_duplicate_json_field")
                result[key] = item
            return result
        parsed = json.loads(value, object_pairs_hook=unique_fields)
    except (TypeError, ValueError) as exc:
        raise RouterStatusTailError(label + "_json_invalid") from exc
    if not isinstance(parsed, dict):
        raise RouterStatusTailError(label + "_not_object")
    return parsed


def parse_ready(line: str) -> dict:
    if not isinstance(line, str) or not line.startswith("READY "):
        raise RouterStatusTailError("sender_ready_malformed")
    values: dict[str, str] = {}
    for item in line[6:].split():
        if item.count("=") != 1:
            raise RouterStatusTailError("sender_ready_malformed")
        key, value = item.split("=", 1)
        if not key or not value or key in values:
            raise RouterStatusTailError("sender_ready_malformed")
        values[key] = value
    wire_nonce = _wire_nonce(values.pop("wire_nonce_hex", None))
    if values != READY_VALUES:
        raise RouterStatusTailError("sender_ready_contract_mismatch")
    return {
        "schema": SENDER_SCHEMA, "wire_nonce_hex": wire_nonce, "frames": 4, "interval_ms": 10,
        "mpdu_bytes": 96, "radiotap_bytes": 10, "packet_bytes": 106,
        "send_budget_ms": 40, "status_tail_ms": 2000,
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "hardware_honoring": "unknown", "intel_arm_invoked": False,
        "boot_claim_used": False,
    }


def parse_packetset_valid(line: str) -> dict:
    prefix = "PACKET_SET_VALID "
    if not isinstance(line, str) or not line.startswith(prefix):
        raise RouterStatusTailError("packetset_verification_malformed")
    value = _json_record(line[len(prefix):], "packetset_verification")
    required = {"event", "schema", "wire_nonce_hex", "frames", "interval_ms", "budget_ms",
                "noack_requested", "transmission_capability",
                "rf_transmission_proven"}
    if (set(value) != required or value.get("event") != "PACKET_SET_VALID" or
            value.get("schema") != PACKETSET_SCHEMA or value.get("frames") != 4 or
            value.get("interval_ms") != 10 or value.get("budget_ms") != 40 or
            value.get("noack_requested") is not False or
            value.get("transmission_capability") is not False or
            value.get("rf_transmission_proven") is not False):
        raise RouterStatusTailError("packetset_verification_contract_mismatch")
    _wire_nonce(value["wire_nonce_hex"])
    return value


STARTED_FIELDS = {
    "event", "schema", "clock_domain", "run_token", "wire_nonce_hex", "go_received_ns",
    "started_ns", "send_deadline_ns", "observer_deadline_ns", "go_to_start_ns",
    "go_to_start_max_ns", "send_budget_ns", "status_tail_ns", "frames_requested",
    "interval_ms", "tx_flags_requested", "noack_requested", "intel_arm_invoked",
    "boot_claim_used",
}


def validate_started(value: Any, token: str) -> dict:
    if not isinstance(value, dict) or set(value) != STARTED_FIELDS:
        raise RouterStatusTailError("sender_started_field_set_invalid")
    int_keys = ("go_received_ns", "started_ns", "send_deadline_ns",
                "observer_deadline_ns", "go_to_start_ns", "go_to_start_max_ns",
                "send_budget_ns", "status_tail_ns", "frames_requested", "interval_ms")
    if any(type(value.get(k)) is not int or value[k] < 0 for k in int_keys):
        raise RouterStatusTailError("sender_started_integer_invalid")
    if (value["event"] != "SENDER_STARTED" or value["schema"] != SENDER_SCHEMA or
            value["clock_domain"] != "CLOCK_MONOTONIC" or value["run_token"] != token or
            value["started_ns"] < value["go_received_ns"] or
            value["go_to_start_ns"] != value["started_ns"] - value["go_received_ns"] or
            value["go_to_start_max_ns"] != GO_TO_START_MAX_NS or
            value["go_to_start_ns"] > GO_TO_START_MAX_NS or
            value["send_deadline_ns"] != value["started_ns"] + SEND_BUDGET_NS or
            value["observer_deadline_ns"] != value["send_deadline_ns"] + STATUS_TAIL_NS or
            value["send_budget_ns"] != SEND_BUDGET_NS or
            value["status_tail_ns"] != STATUS_TAIL_NS or
            value["frames_requested"] != 4 or value["interval_ms"] != 10 or
            value["tx_flags_requested"] != "NOSEQNO" or
            value["noack_requested"] is not False or
            value["intel_arm_invoked"] is not False or
            value["boot_claim_used"] is not False):
        raise RouterStatusTailError("sender_started_contract_mismatch")
    _wire_nonce(value["wire_nonce_hex"])
    return dict(value)


RESULT_FIELDS = {
    "event", "schema", "clock_domain", "status", "run_token", "wire_nonce_hex", "run_token_in_frame",
    "go_received_ns", "frames_requested", "frames_attempted", "frames_completed",
    "send_complete", "packet_bytes", "radiotap_bytes", "mpdu_bytes", "elapsed_ms",
    "deadline_hit", "error_count", "last_errno", "stop_reason", "tx_flags_requested",
    "noack_requested", "ack_policy", "hardware_honoring", "raw_txs", "mac_ack",
    "interval_ms", "send_budget_ns", "status_tail_ns", "capture_window_ns", "started_ns",
    "send_deadline_ns", "observer_deadline_ns", "finished_ns", "go_to_start_ns",
    "go_to_start_max_ns", "first_send_ns", "pre_capture_queue_drain", "send_timing",
    "monitor_observation", "radio_transmission_proven", "rf_transmission_proven",
    "firmware_tx_status_proven", "peer_receipt_proven", "airdrop_proven",
    "intel_arm_invoked", "boot_claim_used",
}
ABORTED_FIELDS = {
    "event", "schema", "status", "run_token", "wire_nonce_hex", "run_token_in_frame", "frames_requested",
    "frames_attempted", "frames_completed", "send_complete", "send_budget_ms",
    "status_tail_ms", "tx_flags_requested", "noack_requested", "radio_transmission_proven",
    "rf_transmission_proven", "firmware_tx_status_proven", "mac_ack", "peer_receipt_proven",
    "airdrop_proven", "intel_arm_invoked", "boot_claim_used",
}
SEND_ROW_FIELDS = {"ordinal", "ieee80211_sequence", "ieee80211_sequence_control", "awdl_sequence", "before_ns", "after_ns",
                   "return_bytes", "errno"}
QUEUE_FIELDS = {"read_attempts", "packets_drained", "receive_error", "drain_complete",
                "kernel_stats_available", "kernel_packets", "kernel_dropped_packets"}
MONITOR_FIELDS = {
    "schema", "clock_domain", "observation_time_semantics", "started_ns", "ended_ns", "actual_horizon_ns", "capture_window_ns",
    "status_tail_began_ns", "capture_finished", "capture_limit_reached", "read_attempts",
    "packets_received", "exact_samples_recorded", "exact_samples_overflow", "receive_error",
    "kernel_stats_available", "kernel_packets", "kernel_dropped_packets", "capture_loss_free",
    "classification_complete", "identity_complete", "radiotap_invalid", "radiotap_unsupported",
    "unmatched_valid_packets", "truncated_packets", "exact_identity_unavailable",
    "socket_topology", "observer_bound_ifindex", "outgoing_tap_is_rf_proof",
    "exact_match_by_ordinal", "outgoing_exact_by_ordinal", "non_outgoing_exact_by_ordinal",
    "tx_status_candidate_by_ordinal", "other_exact_by_ordinal", "samples",
    "status_candidate_matches_by_ordinal", "status_candidate_samples_recorded",
    "status_candidate_samples_overflow", "status_candidate_identity_unavailable",
    "status_candidate_samples", "nonmatch_samples_recorded", "nonmatch_samples_overflow", "nonmatch_samples",
}
STATUS_SAMPLE_FIELDS = {
    "ordinal", "packet_type", "ifindex", "msg_flags", "received_len", "bytes_retained",
    "raw_prefix_truncated", "exact_match", "has_tx_flags", "tx_flags", "has_data_retries",
    "data_retries", "ieee80211_sequence", "ieee80211_sequence_control", "awdl_sequence", "observed_ns", "raw_prefix_hex",
}


def _ints(value: dict, keys: tuple[str, ...], label: str) -> None:
    for key in keys:
        if type(value.get(key)) is not int or value[key] < 0:
            raise RouterStatusTailError(label + "_integer_invalid:" + key)


def _validate_sample_times(samples: list, *, started: int, ended: int) -> None:
    previous = started
    for sample in samples:
        observed = sample.get("observed_ns")
        if type(observed) is not int or not previous <= observed <= ended:
            raise RouterStatusTailError("sample_observation_time_invalid")
        previous = observed
        if "ieee80211_sequence_control" in sample:
            sc, seq = sample["ieee80211_sequence_control"], sample["ieee80211_sequence"]
            if (type(sc) is not int or type(seq) is not int or not 0 <= seq <= 4095 or
                    sc != seq << 4 or type(sample["awdl_sequence"]) is not int or
                    not 0 <= sample["awdl_sequence"] <= 65535):
                raise RouterStatusTailError("sample_full_sequence_invalid")


def _validate_monitor(value: Any, *, started: int, deadline: int,
                      observer_deadline: int) -> dict:
    if not isinstance(value, dict) or set(value) != MONITOR_FIELDS:
        raise RouterStatusTailError("monitor_field_set_invalid")
    ints = ("started_ns", "ended_ns", "actual_horizon_ns", "capture_window_ns",
            "status_tail_began_ns", "read_attempts", "packets_received",
            "exact_samples_recorded", "exact_samples_overflow", "receive_error",
            "radiotap_invalid", "radiotap_unsupported", "unmatched_valid_packets",
            "truncated_packets", "exact_identity_unavailable", "observer_bound_ifindex",
            "status_candidate_samples_recorded", "status_candidate_samples_overflow",
            "status_candidate_identity_unavailable", "nonmatch_samples_recorded", "nonmatch_samples_overflow")
    _ints(value, ints, "monitor")
    bools = ("capture_finished", "capture_limit_reached", "kernel_stats_available",
             "classification_complete", "identity_complete", "outgoing_tap_is_rf_proof")
    if any(type(value.get(k)) is not bool for k in bools):
        raise RouterStatusTailError("monitor_boolean_invalid")
    if (value.get("schema") != MONITOR_SCHEMA or value.get("clock_domain") != "CLOCK_MONOTONIC" or
            value.get("observation_time_semantics") != "userspace_recvmsg_return" or value["started_ns"] != started or
            value["status_tail_began_ns"] != deadline or
            value["capture_window_ns"] != CAPTURE_WINDOW_NS or
            value["ended_ns"] < value["started_ns"] or
            value["actual_horizon_ns"] != value["ended_ns"] - value["started_ns"] or
            value["ended_ns"] > observer_deadline + 100_000_000 or
            value["read_attempts"] > 4096 or value["packets_received"] > value["read_attempts"] or
            value["observer_bound_ifindex"] <= 0 or
            value["socket_topology"] != "distinct_tx_and_observer" or
            value["outgoing_tap_is_rf_proof"] is not False):
        raise RouterStatusTailError("monitor_contract_mismatch")
    if (value["capture_limit_reached"] or value["receive_error"] != 0 or
            not value["capture_finished"] or value["ended_ns"] < observer_deadline):
        raise RouterStatusTailError("monitor_window_incomplete")
    if value["capture_limit_reached"] or value["receive_error"] != 0 or not value["capture_finished"] or value["truncated_packets"] > 0:
        expected_loss_free = False
    elif value["kernel_stats_available"]:
        _ints(value, ("kernel_packets", "kernel_dropped_packets"), "monitor_kernel")
        expected_loss_free = (value["kernel_packets"] == value["packets_received"] and
                              value["kernel_dropped_packets"] == 0)
    elif value["kernel_packets"] is not None or value["kernel_dropped_packets"] is not None:
        raise RouterStatusTailError("monitor_missing_kernel_stats_invalid")
    else:
        expected_loss_free = None
    if value["capture_loss_free"] is not expected_loss_free:
        raise RouterStatusTailError("monitor_loss_classification_invalid")
    if value["capture_loss_free"] is True and (
            value["capture_limit_reached"] or value["receive_error"] or
            not value["capture_finished"]):
        raise RouterStatusTailError("monitor_loss_free_overclaim")
    for key in ("exact_match_by_ordinal", "outgoing_exact_by_ordinal",
                "non_outgoing_exact_by_ordinal", "tx_status_candidate_by_ordinal",
                "other_exact_by_ordinal", "status_candidate_matches_by_ordinal"):
        row = value.get(key)
        if (not isinstance(row, list) or len(row) != 4 or
                any(type(item) is not int or item < 0 for item in row)):
            raise RouterStatusTailError("monitor_ordinal_counts_invalid:" + key)
    samples = value.get("samples")
    if not isinstance(samples, list) or len(samples) != value["exact_samples_recorded"] or len(samples) > 16:
        raise RouterStatusTailError("monitor_samples_count_invalid")
    for sample in samples:
        required = {"exact_ordinal", "packet_type_present", "packet_type", "ifindex_present",
                    "ifindex", "msg_flags", "received_len", "copied_len", "parse_supported",
                    "exact_match", "outgoing_echo", "host_driver_completion_candidate",
                    "has_tx_flags", "tx_flags", "has_data_retries", "data_retries",
                    "ieee80211_sequence", "ieee80211_sequence_control", "awdl_sequence", "observed_ns"}
        if not isinstance(sample, dict) or set(sample) != required:
            raise RouterStatusTailError("monitor_sample_field_set_invalid")
    status_samples = value.get("status_candidate_samples")
    if (not isinstance(status_samples, list) or
            len(status_samples) != value["status_candidate_samples_recorded"] or
            len(status_samples) > 8 or
            value["status_candidate_samples_recorded"] + value["status_candidate_samples_overflow"] > 4096):
        raise RouterStatusTailError("status_candidate_sample_count_invalid")
    for sample in status_samples:
        if not isinstance(sample, dict) or set(sample) != STATUS_SAMPLE_FIELDS:
            raise RouterStatusTailError("status_candidate_sample_fields_invalid")
        _ints(sample, ("packet_type", "ifindex", "msg_flags", "received_len", "bytes_retained",
                       "tx_flags", "data_retries", "ieee80211_sequence", "ieee80211_sequence_control", "awdl_sequence", "observed_ns"),
              "status_candidate_sample")
        ordinal = sample["ordinal"]
        ordinal_valid = type(ordinal) is int and 0 <= ordinal < 4
        if (sample["packet_type"] != 3 or sample["ifindex"] != value["observer_bound_ifindex"] or
                sample["bytes_retained"] > 256 or sample["bytes_retained"] > sample["received_len"] or
                not ordinal_valid or
                type(sample["raw_prefix_truncated"]) is not bool or
                type(sample["exact_match"]) is not bool or
                sample["has_tx_flags"] is not True or type(sample["has_tx_flags"]) is not bool or
                sample["has_data_retries"] is not True or type(sample["has_data_retries"]) is not bool or
                len(sample["raw_prefix_hex"]) != sample["bytes_retained"] * 2 or
                not re.fullmatch(r"(?:[0-9a-f]{2})*", sample["raw_prefix_hex"])):
            raise RouterStatusTailError("status_candidate_sample_invalid")
        if sample["raw_prefix_truncated"] != (sample["received_len"] > 256):
            raise RouterStatusTailError("status_candidate_prefix_truncation_invalid")
    nonmatches = value["nonmatch_samples"]
    if (not isinstance(nonmatches, list) or len(nonmatches) > 8 or
            len(nonmatches) != value["nonmatch_samples_recorded"] or
            len(nonmatches) + value["nonmatch_samples_overflow"] > value["packets_received"]):
        raise RouterStatusTailError("nonmatch_samples_count_invalid")
    for sample in nonmatches:
        fields = {"observed_ns", "parse_status", "packet_type_present", "packet_type",
                  "ifindex_present", "ifindex", "msg_flags", "received_len", "copied_len",
                  "raw_prefix_truncated", "raw_prefix_hex"}
        if not isinstance(sample, dict) or set(sample) != fields:
            raise RouterStatusTailError("nonmatch_sample_fields_invalid")
        _ints(sample, ("msg_flags", "received_len", "copied_len",
                       "observed_ns"), "nonmatch_sample")
        for field in ("packet_type", "ifindex"):
            present = sample[field + "_present"]
            if (type(present) is not bool or
                    (present and (type(sample[field]) is not int or sample[field] < 0)) or
                    (not present and sample[field] is not None)):
                raise RouterStatusTailError("nonmatch_sample_identity_invalid")
        if (sample["parse_status"] not in {"invalid", "unsupported", "valid_unmatched"} or
                any(type(sample[k]) is not bool for k in (
                    "packet_type_present", "ifindex_present", "raw_prefix_truncated")) or
                sample["copied_len"] > min(256, sample["received_len"]) or
                not isinstance(sample["raw_prefix_hex"], str) or
                len(sample["raw_prefix_hex"]) != sample["copied_len"] * 2 or
                not re.fullmatch(r"(?:[0-9a-f]{2})*", sample["raw_prefix_hex"]) or
                sample["raw_prefix_truncated"] != (sample["received_len"] > sample["copied_len"])):
            raise RouterStatusTailError("nonmatch_sample_invalid")
    for rows in (samples, status_samples, nonmatches):
        _validate_sample_times(rows, started=started, ended=value["ended_ns"])
    return dict(value)


def validate_result(value: Any, token: str) -> dict:
    if not isinstance(value, dict):
        raise RouterStatusTailError("sender_result_not_object")
    _wire_nonce(value.get("wire_nonce_hex"))
    if value.get("status") == "aborted":
        if set(value) != ABORTED_FIELDS:
            raise RouterStatusTailError("sender_abort_field_set_invalid")
        if (value.get("event") != "SENDER_RESULT" or value.get("schema") != SENDER_SCHEMA or
                value.get("run_token") != token or value.get("run_token_in_frame") is not False or
                value.get("frames_requested") != 4 or value.get("frames_attempted") != 0 or
                value.get("frames_completed") != 0 or value.get("send_complete") is not False or
                value.get("send_budget_ms") != 40 or value.get("status_tail_ms") != 2000 or
                value.get("tx_flags_requested") != "NOSEQNO" or
                value.get("noack_requested") is not False or
                any(value.get(k) is not False for k in (
                    "radio_transmission_proven", "rf_transmission_proven",
                    "firmware_tx_status_proven", "peer_receipt_proven", "airdrop_proven",
                    "intel_arm_invoked", "boot_claim_used")) or value.get("mac_ack") != "unknown"):
            raise RouterStatusTailError("sender_abort_contract_mismatch")
        return dict(value)
    if set(value) != RESULT_FIELDS:
        raise RouterStatusTailError("sender_result_field_set_invalid")
    ints = ("go_received_ns", "frames_requested", "frames_attempted", "frames_completed",
            "packet_bytes", "radiotap_bytes", "mpdu_bytes", "elapsed_ms", "error_count",
            "send_budget_ns", "status_tail_ns", "capture_window_ns", "started_ns",
            "send_deadline_ns", "observer_deadline_ns", "finished_ns", "go_to_start_ns",
            "go_to_start_max_ns")
    if any(type(value.get(k)) is not int or value[k] < 0 for k in ints):
        raise RouterStatusTailError("sender_result_integer_invalid")
    if type(value.get("last_errno")) is not int:
        raise RouterStatusTailError("sender_result_errno_invalid")
    bools = ("run_token_in_frame", "send_complete", "deadline_hit", "noack_requested",
             "radio_transmission_proven", "rf_transmission_proven",
             "firmware_tx_status_proven", "peer_receipt_proven", "airdrop_proven",
             "intel_arm_invoked", "boot_claim_used")
    if any(type(value.get(k)) is not bool for k in bools):
        raise RouterStatusTailError("sender_result_boolean_invalid")
    if (value.get("event") != "SENDER_RESULT" or value.get("schema") != SENDER_SCHEMA or
            value.get("clock_domain") != "CLOCK_MONOTONIC" or value.get("run_token") != token or
            value["run_token_in_frame"] is not False or value["frames_requested"] != 4 or
            value["packet_bytes"] != 106 or value["radiotap_bytes"] != 10 or
            value["mpdu_bytes"] != 96 or value["interval_ms"] != 10 or
            value["send_budget_ns"] != SEND_BUDGET_NS or value["status_tail_ns"] != STATUS_TAIL_NS or
            value["capture_window_ns"] != CAPTURE_WINDOW_NS or
            value["started_ns"] < value["go_received_ns"] or
            value["send_deadline_ns"] != value["started_ns"] + SEND_BUDGET_NS or
            value["observer_deadline_ns"] != value["send_deadline_ns"] + STATUS_TAIL_NS or
            value["finished_ns"] < value["started_ns"] or
            value["go_to_start_ns"] != value["started_ns"] - value["go_received_ns"] or
            value["go_to_start_max_ns"] != GO_TO_START_MAX_NS or
            value["go_to_start_ns"] > GO_TO_START_MAX_NS or
            value["tx_flags_requested"] != "NOSEQNO" or value["noack_requested"] is not False or
            value["ack_policy"] != "normal_unicast_requested" or
            value["hardware_honoring"] != "unknown" or value["raw_txs"] != "unknown" or
            value["mac_ack"] != "unknown" or value["radio_transmission_proven"] is not False or
            value["rf_transmission_proven"] is not False or
            value["firmware_tx_status_proven"] is not False or
            value["peer_receipt_proven"] is not False or value["airdrop_proven"] is not False or
            value["intel_arm_invoked"] is not False or value["boot_claim_used"] is not False):
        raise RouterStatusTailError("sender_result_contract_mismatch")
    if type(value.get("deadline_hit")) is not bool or value.get("stop_reason") not in {
            "complete", "observer_drain_incomplete", "go_to_start_budget_expired",
            "send_budget_expired", "schedule_wait_failed", "clock_before_failed",
            "send_errno", "short_write", "clock_after_failed", "send_completed_after_budget"}:
        raise RouterStatusTailError("sender_result_status_invalid")
    if type(value.get("error_count")) is not int or value["error_count"] < 0:
        raise RouterStatusTailError("sender_error_count_invalid")
    queue = value.get("pre_capture_queue_drain")
    if not isinstance(queue, dict) or set(queue) != QUEUE_FIELDS:
        raise RouterStatusTailError("stale_queue_field_set_invalid")
    _ints(queue, ("read_attempts", "packets_drained"), "stale_queue")
    if type(queue.get("receive_error")) is not int or type(queue.get("drain_complete")) is not bool or type(queue.get("kernel_stats_available")) is not bool:
        raise RouterStatusTailError("stale_queue_types_invalid")
    if queue["kernel_stats_available"]:
        _ints(queue, ("kernel_packets", "kernel_dropped_packets"), "stale_queue_kernel")
    elif queue["kernel_packets"] is not None or queue["kernel_dropped_packets"] is not None:
        raise RouterStatusTailError("stale_queue_unknown_stats_invalid")
    rows = value.get("send_timing")
    if not isinstance(rows, list) or len(rows) != value["frames_attempted"]:
        raise RouterStatusTailError("send_timing_count_invalid")
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != SEND_ROW_FIELDS:
            raise RouterStatusTailError("send_timing_field_set_invalid")
        _ints(row, ("ordinal", "ieee80211_sequence", "ieee80211_sequence_control", "awdl_sequence", "before_ns", "after_ns",
                    "errno"), "send_timing")
        if (row["ordinal"] != index or row["ieee80211_sequence"] > 4095 or
                row["ieee80211_sequence_control"] != row["ieee80211_sequence"] << 4 or
                row["awdl_sequence"] > 65535 or row["after_ns"] < row["before_ns"] or
                row["return_bytes"] != 106 or row["errno"] != 0 or
                row["before_ns"] < value["started_ns"] or
                row["after_ns"] > value["send_deadline_ns"]):
            raise RouterStatusTailError("send_timing_contract_invalid")
        if index and row["before_ns"] - rows[index - 1]["before_ns"] < 10_000_000:
            raise RouterStatusTailError("send_spacing_invalid")
    if (value["status"] != "send_complete" or value["send_complete"] is not True or
            value["frames_attempted"] != 4 or value["frames_completed"] != 4 or
            value["error_count"] != 0 or value["last_errno"] != 0 or
            value["stop_reason"] != "complete" or value["deadline_hit"] is not False or
            len(rows) != 4 or not queue["drain_complete"] or queue["receive_error"] != 0 or
            not queue["kernel_stats_available"] or queue["kernel_dropped_packets"] != 0 or
            queue["kernel_packets"] != queue["packets_drained"]):
        raise RouterStatusTailError("send_completion_contract_invalid")
    if any(row["after_ns"] - value["started_ns"] > SEND_BUDGET_NS for row in rows):
        raise RouterStatusTailError("send_timing_exceeds_40ms_budget")
    monitor = _validate_monitor(value.get("monitor_observation"),
                                started=value["started_ns"],
                                deadline=value["send_deadline_ns"],
                                observer_deadline=value["observer_deadline_ns"])
    if (value["finished_ns"] != monitor["ended_ns"] or
            monitor["actual_horizon_ns"] < CAPTURE_WINDOW_NS):
        raise RouterStatusTailError("sender_monitor_horizon_mismatch")
    return {**value, "monitor_observation": monitor}


def _validate_input_file(path: Path, expected_sha: str, *, private: bool) -> bytes:
    if not SHA_RE.fullmatch(expected_sha or ""):
        raise RouterStatusTailError("sha256_invalid")
    try:
        info = path.lstat()
    except OSError as exc:
        raise RouterStatusTailError("input_file_unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
        raise RouterStatusTailError("input_file_not_owned_regular")
    if private and stat.S_IMODE(info.st_mode) != 0o600:
        raise RouterStatusTailError("packet_set_must_be_mode_0600")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RouterStatusTailError("input_file_read_failed") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise RouterStatusTailError("input_file_sha_mismatch")
    return raw


def validate_packetset_shape(raw: bytes) -> dict:
    try:
        return _load_packetset().decode_packet_set(raw)
    except (ValueError, KeyError, TypeError) as exc:
        raise RouterStatusTailError("packet_set_invalid") from exc


def claim_wire_nonce(directory: Path, nonce: str, packet_set_sha256: str, token: str) -> Path:
    """Reserve a frame identity before device I/O; never reuse it after an abort."""
    _wire_nonce(nonce)
    if not SHA_RE.fullmatch(packet_set_sha256) or not TOKEN_RE.fullmatch(token):
        raise RouterStatusTailError("nonce_claim_binding_invalid")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise RouterStatusTailError("nonce_ledger_must_be_private_0700")
    path = directory / (nonce + ".json")
    try:
        _write_private_new(path, {"schema": "test122-wire-nonce-claim/v1",
                                 "wire_nonce_hex": nonce, "run_token": token,
                                 "packet_set_sha256": packet_set_sha256,
                                 "state": "reserved_before_device_io"})
    except FileExistsError as exc:
        raise RouterStatusTailError("wire_nonce_already_claimed") from exc
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                           getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return path


def correlate_status_samples(report: dict, packet_set: bytes) -> dict:
    """Bind raw host status copies to this packet set, without claiming RF RX."""
    decoded = validate_packetset_shape(packet_set)
    result = report["sender_result"]
    if result["wire_nonce_hex"] != decoded["wire_nonce_hex"]:
        raise RouterStatusTailError("result_wire_nonce_mismatch")
    _validate_sample_times(result["monitor_observation"]["status_candidate_samples"],
                           started=result["started_ns"],
                           ended=result["monitor_observation"]["ended_ns"])
    for row, expected in zip(result["send_timing"], decoded["frames"]):
        if (row["ordinal"] != expected["ordinal"] or
                row["ieee80211_sequence_control"] != expected["sequence_control"] or
                row["awdl_sequence"] != expected["awdl_sequence"]):
            raise RouterStatusTailError("send_packetset_sequence_mismatch")
    correlated = []
    for sample in result["monitor_observation"]["status_candidate_samples"]:
        raw = bytes.fromhex(sample["raw_prefix_hex"])
        if len(raw) < 8 or raw[0] != 0:
            raise RouterStatusTailError("status_raw_radiotap_invalid")
        offset = int.from_bytes(raw[2:4], "little")
        if offset < 8 or offset + 96 > len(raw):
            raise RouterStatusTailError("status_raw_mpdu_incomplete")
        match = _load_packetset().match_frame(raw[offset:offset + 96], packet_set)
        if (match is None or match["ordinal"] != sample["ordinal"] or
                match["sequence_control"] != sample["ieee80211_sequence_control"] or
                match["awdl_sequence"] != sample["awdl_sequence"]):
            raise RouterStatusTailError("status_raw_packetset_identity_mismatch")
        row = result["send_timing"][match["ordinal"]]
        if sample["observed_ns"] < row["before_ns"]:
            raise RouterStatusTailError("status_observed_before_bound_send")
        correlated.append({
            "ordinal": match["ordinal"], "observed_ns": sample["observed_ns"],
            "send_before_ns": row["before_ns"], "send_after_ns": row["after_ns"],
            "observed_after_send_return_ns": sample["observed_ns"] - row["after_ns"],
            "observed_after_send_budget": sample["observed_ns"] > result["send_deadline_ns"],
            "tx_flags_raw": sample["tx_flags"], "data_retries_raw": sample["data_retries"],
            "host_tx_fail_bit": bool(sample["tx_flags"] & 1),
            "frame_identity_matched": True, "exact_mpdu_match": match["exact_mpdu_match"],
        })
    return {"schema": "test122-frame-correlation/v2", "wire_nonce_hex": decoded["wire_nonce_hex"],
            "clock_domain": "CLOCK_MONOTONIC", "time_semantics": "userspace_recvmsg_return",
            "samples": correlated, "matched_status_samples": len(correlated),
            "missing_ordinals": [i for i in range(4) if i not in {s["ordinal"] for s in correlated}],
            "kernel_receive_timestamp_present": False, "rf_transmission_proven": False,
            "hardware_ack_proven": False, "intel_rx_correlated": False}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def build_remote_script(*, binary: bytes, binary_sha256: str, packet_set: bytes,
                        packet_set_sha256: str, run_token: str) -> str:
    if not TOKEN_RE.fullmatch(run_token or ""):
        raise RouterStatusTailError("run_token_invalid")
    if hashlib.sha256(binary).hexdigest() != binary_sha256 or not SHA_RE.fullmatch(binary_sha256):
        raise RouterStatusTailError("sender_binary_sha_mismatch")
    if hashlib.sha256(packet_set).hexdigest() != packet_set_sha256:
        raise RouterStatusTailError("packet_set_sha_mismatch")
    packetset_info = validate_packetset_shape(packet_set)
    wire_nonce = packetset_info["wire_nonce_hex"]
    if not binary or len(binary) > MAX_BINARY_BYTES:
        raise RouterStatusTailError("sender_binary_size_invalid")
    router = _load_router_protocol()
    script = router.build_remote_monitor_sender_script(
        binary=binary, binary_sha256=binary_sha256,
        run_token=run_token, ap=AP_INTERFACE, monitor=MONITOR_INTERFACE)
    replacements = (
        ('TMP="/tmp/iwn-t087-controlled-$RUN_TOKEN"', 'TMP="/tmp/iwn-test122-tail-$RUN_TOKEN"'),
        ('BIN="$TMP/awdl_probe_sender"', 'BIN="$TMP/router_status_tail_test122"\nPSET="$TMP/packetset.bin"'),
        ('EXPECTED_BIN_SHA=' + binary_sha256, 'EXPECTED_BIN_SHA=' + binary_sha256 +
         '\nEXPECTED_PSET_SHA=' + packet_set_sha256),
    )
    for old, new in replacements:
        if script.count(old) != 1:
            raise RouterStatusTailError("remote_script_anchor_mismatch")
        script = script.replace(old, new, 1)
    stage_anchor = (
        'if [ "$BIN_SHA" != "$EXPECTED_BIN_SHA" ]; then\n'
        '  printf \'REMOTE_ERROR code=sender_sha_mismatch\\n\'\n'
        '  exit 2\n'
        'fi\n'
    )
    verify_json = json.dumps({"event": "PACKET_SET_VALID", "schema": PACKETSET_SCHEMA,
                              "frames": 4, "interval_ms": 10, "budget_ms": 40,
                              "noack_requested": False, "transmission_capability": False,
                              "rf_transmission_proven": False, "wire_nonce_hex": wire_nonce},
                             separators=(",", ":"))
    pset_block = (
        stage_anchor +
        f"printf '%s' '{_b64(packet_set)}' | base64 -d > \"$PSET\" || "
        "{ printf 'REMOTE_ERROR code=packet_set_stage_failed\\n'; exit 2; }\n"
        'chmod 600 "$PSET" || { printf \'REMOTE_ERROR code=packet_set_mode_failed\\n\'; exit 2; }\n'
        'PSET_SHA="$(sha256sum "$PSET" 2>/dev/null | awk \'{print $1}\')"\n'
        'if [ "$PSET_SHA" != "$EXPECTED_PSET_SHA" ]; then\n'
        '  printf \'REMOTE_ERROR code=packet_set_sha_mismatch\\n\'\n'
        '  exit 2\n'
        'fi\n'
        'VERIFY_OUT="$("$BIN" --verify-only --packet-set "$PSET" 2>&1)" || { printf \'REMOTE_ERROR code=packet_set_verify_failed\\n\'; exit 2; }\n'
        f'case "$VERIFY_OUT" in \'{verify_json}\') ;; *) printf \'REMOTE_ERROR code=packet_set_verify_contract_mismatch\\n\'; exit 2 ;; esac\n'
        'printf \'PACKET_SET_VALID %s\\n\' "$VERIFY_OUT"\n'
    )
    if script.count(stage_anchor) != 1:
        raise RouterStatusTailError("packetset_stage_anchor_mismatch")
    script = script.replace(stage_anchor, pset_block, 1)
    old_command = '"$BIN" --send --interface "$MON" --count 16 --interval-ms 80 --nonce "$RUN_TOKEN" --wait-go <&3 &'
    new_command = '"$BIN" --send --packet-set "$PSET" --interface "$MON" --source-interface "$AP" --nonce "$RUN_TOKEN" --wait-go <&3 &'
    if script.count(old_command) != 1:
        raise RouterStatusTailError("sender_command_anchor_mismatch")
    script = script.replace(old_command, new_command, 1)
    if len(script.encode("utf-8")) > MAX_REMOTE_SCRIPT_BYTES:
        raise RouterStatusTailError("remote_script_size_invalid")
    if "iw dev \"$AP\" set" in script or "uci set" in script or "uci commit" in script:
        raise RouterStatusTailError("remote_script_contains_forbidden_ap_change")
    return script


def _write_private_new(path: Path, report: dict) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode) or
            parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise RouterStatusTailError("output_parent_must_be_private_0700")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _write_abort(process: subprocess.Popen, report: dict) -> None:
    if report.get("go_write_attempted") or report.get("abort_write_attempted"):
        return
    report["abort_write_attempted"] = True
    if process.stdin is None or process.poll() is not None:
        return
    try:
        process.stdin.write(b"ABORT\n")
        process.stdin.flush()
        report["abort_sent"] = True
    except (BrokenPipeError, OSError):
        report["abort_sent"] = False


def _read_remote_line(selector, process, state: dict, deadline: float) -> str | None:
    while time.monotonic() < deadline:
        if b"\n" in state["buffer"]:
            raw, _, state["buffer"] = state["buffer"].partition(b"\n")
            if len(raw) > MAX_REMOTE_LINE_BYTES:
                raise RouterStatusTailError("remote_line_oversize")
            return raw.decode("utf-8", errors="strict").rstrip("\r")
        events = selector.select(min(0.2, max(0.0, deadline - time.monotonic())))
        if not events:
            if process.poll() is not None:
                try:
                    chunk = os.read(process.stdout.fileno(), 4096)
                except OSError:
                    return None
                if not chunk:
                    return None
                state["buffer"].extend(chunk)
                continue
            continue
        chunk = os.read(process.stdout.fileno(), 8192)
        if not chunk:
            return None
        state["total"] += len(chunk)
        if state["total"] > MAX_REMOTE_OUTPUT_BYTES:
            raise RouterStatusTailError("remote_output_oversize")
        state["buffer"].extend(chunk)
        if b"\n" not in state["buffer"] and len(state["buffer"]) > MAX_REMOTE_LINE_BYTES:
            raise RouterStatusTailError("remote_line_oversize")
    raise RouterStatusTailError("remote_protocol_timeout")


def _record_line(report: dict, line: str, token: str) -> None:
    report["transcript"].append(line)
    if line.startswith("PACKET_SET_VALID "):
        if report.get("packetset_verified") is not None or report.get("monitor_ready") is not None:
            raise RouterStatusTailError("packetset_verification_order_invalid")
        report["packetset_verified"] = parse_packetset_valid(line)
        if report["packetset_verified"]["wire_nonce_hex"] != report["wire_nonce_hex"]:
            raise RouterStatusTailError("packetset_verification_wire_nonce_mismatch")
        report["event_order"].append("PACKET_SET_VALID")
        return
    if line.startswith("MONITOR_READY "):
        if report.get("packetset_verified") is None or report.get("monitor_ready") is not None:
            raise RouterStatusTailError("monitor_ready_order_invalid")
        report["monitor_ready"] = _load_router_protocol().parse_monitor_ready(line)
        report["event_order"].append("MONITOR_READY")
        return
    if line.startswith("READY "):
        if (report.get("packetset_verified") is None or report.get("monitor_ready") is None or
                report.get("ready") is not None):
            raise RouterStatusTailError("sender_ready_order_invalid")
        report["ready"] = parse_ready(line)
        if report["ready"]["wire_nonce_hex"] != report["wire_nonce_hex"]:
            raise RouterStatusTailError("ready_wire_nonce_mismatch")
        report["event_order"].append("READY")
        return
    if line.startswith("CLEANUP "):
        if report.get("cleanup") is not None:
            raise RouterStatusTailError("duplicate_cleanup")
        cleanup = _json_record(line[len("CLEANUP "):], "cleanup")
        fields = {"event", "run_token", "monitor_removed", "ap_unchanged", "temporary_files_removed"}
        if (set(cleanup) != fields or cleanup.get("event") != "MONITOR_CLEANUP" or
                cleanup.get("run_token") != token or any(type(cleanup.get(k)) is not bool for k in (
                    "monitor_removed", "ap_unchanged", "temporary_files_removed"))):
            raise RouterStatusTailError("cleanup_contract_invalid")
        report["cleanup"] = cleanup
        report["event_order"].append("CLEANUP")
        return
    if line.startswith("REMOTE_ERROR "):
        report.setdefault("remote_errors", []).append(line[:512])
        return
    if line.startswith("{"):
        value = _json_record(line, "sender_event")
        event = value.get("event")
        if event == "SENDER_STARTED":
            if not report.get("go_sent") or report.get("sender_started") is not None or report.get("sender_result") is not None:
                raise RouterStatusTailError("sender_started_order_invalid")
            report["sender_started"] = validate_started(value, token)
        elif event == "SENDER_RESULT":
            if report.get("sender_result") is not None:
                raise RouterStatusTailError("duplicate_sender_result")
            try:
                report["sender_result"] = validate_result(value, token)
            except (ValueError, KeyError, TypeError):
                report["sender_result_unvalidated"] = value
                raise
            if (value.get("status") != "aborted" and report.get("sender_started") is None):
                raise RouterStatusTailError("sender_result_before_started")
        else:
            raise RouterStatusTailError("sender_event_unknown")
        if value["wire_nonce_hex"] != report["wire_nonce_hex"]:
            raise RouterStatusTailError("sender_wire_nonce_mismatch")
        report["event_order"].append(event)
        return
    raise RouterStatusTailError("remote_protocol_line_unknown")


def run(args) -> dict:
    if args.output.exists() or args.output.is_symlink():
        raise RouterStatusTailError("output_already_exists")
    binary = _validate_input_file(args.binary, args.binary_sha256, private=False)
    if len(binary) > MAX_BINARY_BYTES:
        raise RouterStatusTailError("sender_binary_size_invalid")
    packet_set = _validate_input_file(args.packet_set, args.packet_set_sha256, private=True)
    packetset_info = validate_packetset_shape(packet_set)
    wire_nonce = packetset_info["wire_nonce_hex"]
    if args.output.parent.is_symlink():
        raise RouterStatusTailError("output_parent_symlink")
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = args.output.parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() or
            stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise RouterStatusTailError("output_parent_must_be_private_0700")
    token = secrets.token_hex(16)
    script = build_remote_script(binary=binary, binary_sha256=args.binary_sha256,
                                 packet_set=packet_set,
                                 packet_set_sha256=args.packet_set_sha256,
                                 run_token=token)
    runner = _load_router_runner()
    if not args.host or not args.control_path:
        raise RouterStatusTailError("host_and_control_path_required")
    argv = runner.build_bootstrap_argv(args.host, str(args.control_path))
    claim_path = claim_wire_nonce(args.nonce_ledger_dir, wire_nonce, args.packet_set_sha256, token)
    report = {
        "schema": SCHEMA, "status": "starting", "complete": False,
        "run_token": token, "wire_nonce_hex": wire_nonce, "wire_nonce_claim": str(claim_path),
        "frame_nonce_in_payload": True, "sender_sha256": args.binary_sha256,
        "packet_set_sha256": args.packet_set_sha256,
        "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
        "execution_host": args.host, "control_path": str(args.control_path),
        "ap_interface": AP_INTERFACE,
        "monitor_interface": MONITOR_INTERFACE, "packetset_verified": None,
        "monitor_ready": None, "ready": None, "sender_started": None,
        "sender_result": None, "cleanup": None, "go_write_attempted": False,
        "go_sent": False, "intel_arm_invoked": False, "boot_claim_used": False,
        "efi_written": False, "ap_channel_changed": False,
        "wan_lan_changed": False, "rf_transmission_proven": False,
        "firmware_tx_status_proven": False, "mac_ack": "unknown",
        "peer_receipt_proven": False, "native_awdl0_ingress_proven": False,
        "airdrop_proven": False, "event_order": [], "transcript": [],
    }
    process = None
    selector = selectors.DefaultSelector()
    state = {"buffer": bytearray(), "total": 0}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
        process.stdin.write(runner.remote_script_bytes(script))
        process.stdin.flush()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            line = _read_remote_line(selector, process, state, deadline)
            if line is None:
                break
            _record_line(report, line, token)
            if report.get("ready") is not None and not report["go_write_attempted"]:
                report["go_write_attempted"] = True
                process.stdin.write(("GO " + token + "\n").encode("ascii"))
                process.stdin.flush()
                report["go_sent"] = True
                deadline = time.monotonic() + 12.0
            if report.get("sender_result") is not None and report.get("cleanup") is not None:
                break
        if process.poll() is None and report.get("sender_result") is None:
            if not report["go_write_attempted"]:
                _write_abort(process, report)
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and report.get("cleanup") is None:
                    line = _read_remote_line(selector, process, state, deadline)
                    if line is None:
                        break
                    _record_line(report, line, token)
            if process.poll() is None and report.get("sender_result") is None:
                raise RouterStatusTailError("remote_session_deadline")
        try:
            report["exit_code"] = process.wait(timeout=3.0)
        except subprocess.TimeoutExpired as exc:
            raise RouterStatusTailError("remote_cleanup_deadline") from exc
        cleanup = report.get("cleanup") or {}
        result = report.get("sender_result") or {}
        report["cleanup_verified"] = all(cleanup.get(k) is True for k in (
            "monitor_removed", "ap_unchanged", "temporary_files_removed"))
        report["complete"] = (
            report["exit_code"] == 0 and report.get("go_sent") is True and
            result.get("status") == "send_complete" and result.get("send_complete") is True and
            report["cleanup_verified"] is True and not report.get("remote_errors")
        )
        report["status"] = "router_only_tail_complete" if report["complete"] else "router_only_incomplete"
        monitor = result.get("monitor_observation", {})
        report["status_candidate_samples_count"] = len(monitor.get("status_candidate_samples", []))
        report["outgoing_exact_total"] = sum(monitor.get("outgoing_exact_by_ordinal", []))
        report["non_outgoing_exact_total"] = sum(monitor.get("non_outgoing_exact_by_ordinal", []))
        report["capture_loss_free"] = monitor.get("capture_loss_free")
        if report["complete"]:
            report["frame_correlation"] = correlate_status_samples(report, packet_set)
    except Exception as exc:
        report["status"] = "router_only_incomplete"
        report["complete"] = False
        report["error"] = (str(exc)[:240] if isinstance(exc, RouterStatusTailError)
                            else type(exc).__name__)
        if process is not None and process.poll() is None and not report.get("go_write_attempted"):
            _write_abort(process, report)
    finally:
        selector.close()
        if process is not None:
            if process.stdin:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except OSError:
                    pass
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        pass
    _write_private_new(args.output, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly execute one router-only run")
    parser.add_argument("--host", help="SSH host using the already-authenticated ControlMaster")
    parser.add_argument("--control-path", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--packet-set", type=Path)
    parser.add_argument("--packet-set-sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--nonce-ledger-dir", type=Path, help="persistent private ledger; a frame nonce is never reused")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({
            "mode": "plan", "schema": SCHEMA,
            "ap_interface": AP_INTERFACE, "channel": 149,
            "frames": 4, "send_budget_ms": 40, "independent_status_tail_ms": 2000,
            "intel_arm_invoked": False, "boot_claim_used": False,
            "efi_written": False, "ap_channel_changed": False, "wan_lan_changed": False,
            "rf_transmission_proven": False, "peer_receipt_proven": False,
            "airdrop_proven": False,
        }, ensure_ascii=False))
        return 0
    missing = [name for name in ("host", "control_path", "binary", "binary_sha256", "packet_set",
                                  "packet_set_sha256", "output", "nonce_ledger_dir")
               if getattr(args, name) is None]
    if missing:
        parser.error("--run requires --host, --control-path, --binary, --binary-sha256, --packet-set, "
                     "--packet-set-sha256, --output and --nonce-ledger-dir")
    try:
        report = run(args)
    except Exception as exc:
        print(json.dumps({"status": "preflight_failed", "error": str(exc)[:240],
                          "output_written": False}, ensure_ascii=False))
        return 2
    print(json.dumps({
        "status": report.get("status"), "complete": report.get("complete", False),
        "go_sent": report.get("go_sent", False), "exit_code": report.get("exit_code"),
        "status_candidate_samples_count": report.get("status_candidate_samples_count", 0),
        "outgoing_exact_total": report.get("outgoing_exact_total", 0),
        "non_outgoing_exact_total": report.get("non_outgoing_exact_total", 0),
        "rf_transmission_proven": False, "mac_ack": "unknown",
        "peer_receipt_proven": False, "airdrop_proven": False,
        "report": str(args.output),
    }, ensure_ascii=False))
    return 0 if report.get("complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
