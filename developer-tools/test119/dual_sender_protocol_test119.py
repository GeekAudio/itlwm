#!/usr/bin/env python3
"""Strict parser for the Test119 dual-socket OpenWrt sender protocol.

Local AF_PACKET writes, PACKET_OUTGOING, and native listener silence are not RF,
ACK, peer receipt, native input, or AirDrop proof.
"""
from __future__ import annotations

import json
import hashlib
import re
from typing import Any


SENDER_SCHEMA = "test119-dual-socket-sender/v1"
SCHEMA = SENDER_SCHEMA
MONITOR_SCHEMA = "test119-dual-socket-monitor/v1"
DRAIN_SCHEMA = "test119-pre-capture-drain/v1"
GO_TO_START_MAX_NS = 5_000_000
READY_VALUES = {
    "schema": SENDER_SCHEMA,
    "frames": "4",
    "interval_ms": "10",
    "mpdu_bytes": "96",
    "radiotap_bytes": "10",
    "packet_bytes": "106",
    "udp_payload_bytes": "8",
    "tx_flags": "NOSEQNO",
    "hardware_honoring": "unknown",
    "noack_requested": "false",
    "raw_txs": "unknown",
}
STARTED_FIELDS = {
    "event", "schema", "timing_schema", "clock_domain", "run_token",
    "go_received_ns", "started_ns", "go_to_start_ns", "go_to_start_max_ns",
    "send_budget_ns", "frames_requested", "interval_ms", "tx_flags_requested",
    "noack_requested",
}
RESULT_FIELDS = {
    "event", "schema", "timing_schema", "clock_domain", "status", "run_token",
    "go_received_ns", "frames_requested", "frames_attempted", "frames_completed",
    "sent", "payload_bytes", "packet_bytes", "radiotap_bytes", "mpdu_bytes",
    "udp_payload_bytes", "elapsed_ms", "deadline_hit", "error_count", "last_errno",
    "stop_reason", "tx_flags_requested", "noack_requested", "ack_policy",
    "hardware_honoring", "raw_txs", "mac_ack", "interval_ms", "send_budget_ns",
    "started_ns", "finished_ns", "go_to_start_ns", "go_to_start_max_ns",
    "first_send_ns", "local_send_calls", "pre_capture_queue_drain",
    "send_timing", "actual_horizon_ns", "monitor_observation",
    "rf_transmission_proven", "peer_receipt_proven", "airdrop_proven",
}
ABORT_FIELDS = {
    "event", "schema", "status", "run_token", "frames_requested",
    "frames_attempted", "frames_completed", "sent", "payload_bytes", "packet_bytes",
    "radiotap_bytes", "mpdu_bytes", "udp_payload_bytes", "elapsed_ms",
    "deadline_hit", "error_count", "last_errno", "stop_reason",
    "tx_flags_requested", "hardware_honoring",
}
LEGACY_FIELDS = {
    "event", "status", "frames_attempted", "frames_completed", "sent",
    "payload_bytes", "mpdu_bytes", "radiotap_bytes", "packet_bytes",
    "udp_payload_bytes", "elapsed_ms", "deadline_hit", "error_count",
    "last_errno", "stop_reason", "tx_flags_requested", "hardware_honoring",
}
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})*$")
STOP_REASONS = {
    "complete", "aborted_before_go", "send_budget_expired", "schedule_wait_failed",
    "clock_before_failed", "send_errno", "short_write", "clock_after_failed",
    "send_completed_after_budget", "go_to_start_budget_expired",
    "observer_drain_incomplete", "send_spacing_violation",
}


class SenderProtocolError(ValueError):
    pass


def _json(line: Any) -> dict:
    if not isinstance(line, str) or len(line.encode("utf-8")) > 16 * 1024:
        raise SenderProtocolError("sender_line_oversize_or_invalid")
    try:
        value = json.loads(line)
    except (ValueError, TypeError) as error:
        raise SenderProtocolError("sender_json_invalid") from error
    if not isinstance(value, dict):
        raise SenderProtocolError("sender_record_not_object")
    return value


def _integer_map(value: Any, keys: tuple[str, ...], *, maximum: int | None = None) -> None:
    if not isinstance(value, dict):
        raise SenderProtocolError("record_not_object")
    for key in keys:
        item = value.get(key)
        if type(item) is not int or item < 0 or (maximum is not None and item > maximum):
            raise SenderProtocolError("integer_invalid:" + key)


def parse_ready(line: str) -> dict:
    if not isinstance(line, str) or not line.startswith("READY "):
        raise SenderProtocolError("sender_ready_malformed")
    values = {}
    for item in line[6:].split():
        if item.count("=") != 1:
            raise SenderProtocolError("sender_ready_malformed")
        key, value = item.split("=", 1)
        if key in values or not key or not value:
            raise SenderProtocolError("sender_ready_malformed")
        values[key] = value
    if values != READY_VALUES:
        raise SenderProtocolError("sender_ready_contract_mismatch")
    return {
        "schema": SENDER_SCHEMA, "frames": 4, "interval_ms": 10,
        "mpdu_bytes": 96, "radiotap_bytes": 10, "packet_bytes": 106,
        "udp_payload_bytes": 8, "tx_flags_requested": "NOSEQNO",
        "noack_requested": False, "hardware_honoring": "unknown",
        "raw_txs": "unknown", "send_started": False,
        "socket_topology": "distinct_tx_and_observer",
    }


def parse_started(value: Any, run_token: str) -> dict:
    if not TOKEN_RE.fullmatch(run_token or "") or not isinstance(value, dict):
        raise SenderProtocolError("sender_started_invalid")
    if set(value) != STARTED_FIELDS or value.get("event") != "SENDER_STARTED":
        raise SenderProtocolError("sender_started_field_set_invalid")
    if value.get("schema") != SENDER_SCHEMA:
        raise SenderProtocolError("sender_started_schema_invalid")
    _integer_map(value, ("timing_schema", "go_received_ns", "started_ns",
                         "go_to_start_ns", "go_to_start_max_ns", "send_budget_ns",
                         "frames_requested", "interval_ms"))
    if (value["timing_schema"] != 1 or value["clock_domain"] != "CLOCK_MONOTONIC" or
            value["run_token"] != run_token or value["started_ns"] < value["go_received_ns"] or
            value["go_to_start_ns"] != value["started_ns"] - value["go_received_ns"] or
            value["go_to_start_max_ns"] != GO_TO_START_MAX_NS or
            value["go_to_start_ns"] > GO_TO_START_MAX_NS or
            value["send_budget_ns"] != 40_000_000 or value["frames_requested"] != 4 or
            value["interval_ms"] != 10 or value["tx_flags_requested"] != "NOSEQNO" or
            value["noack_requested"] is not False):
        raise SenderProtocolError("sender_started_contract_mismatch")
    return {**value, "go_to_start_within_bound":
            value["go_to_start_ns"] <= GO_TO_START_MAX_NS}


def _validate_drain(value: Any) -> dict:
    fields = {"schema", "read_attempts", "packets_drained", "receive_error",
              "drain_complete", "kernel_stats_available", "kernel_packets",
              "kernel_dropped_packets"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != DRAIN_SCHEMA:
        raise SenderProtocolError("stale_queue_drain_fields_invalid")
    _integer_map(value, ("read_attempts", "packets_drained", "receive_error"),
                 maximum=256)
    if value["packets_drained"] > value["read_attempts"]:
        raise SenderProtocolError("stale_queue_drain_count_invalid")
    if type(value["drain_complete"]) is not bool or type(value["kernel_stats_available"]) is not bool:
        raise SenderProtocolError("stale_queue_drain_boolean_invalid")
    if value["kernel_stats_available"]:
        _integer_map(value, ("kernel_packets", "kernel_dropped_packets"))
    elif value["kernel_packets"] is not None or value["kernel_dropped_packets"] is not None:
        raise SenderProtocolError("stale_queue_missing_stats_must_be_unknown")
    clean = (value["drain_complete"] and value["receive_error"] == 0 and
             value["kernel_stats_available"] and value["kernel_dropped_packets"] == 0 and
             value["kernel_packets"] == value["packets_drained"])
    return {**value, "capture_epoch_clean": clean}


def _validate_monitor(value: Any, *, started: int, finished: int) -> dict:
    fields = {
        "schema", "capture_window_ns", "started_ns", "ended_ns", "capture_finished",
        "capture_limit_reached", "read_attempts", "packets_received", "samples_recorded",
        "samples_overflow", "receive_error", "kernel_stats_available", "kernel_packets",
        "kernel_dropped_packets", "loss_free", "socket_topology", "observer_bound_ifindex",
        "outgoing_tap_is_rf_proof", "outgoing_exact_by_ordinal",
        "non_outgoing_exact_by_ordinal", "exact_identity_unavailable", "samples",
    }
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != MONITOR_SCHEMA:
        raise SenderProtocolError("monitor_observation_field_set_invalid")
    _integer_map(value, ("capture_window_ns", "started_ns", "ended_ns", "read_attempts",
                         "packets_received", "samples_recorded", "samples_overflow",
                         "receive_error", "observer_bound_ifindex",
                         "exact_identity_unavailable"))
    if (value["capture_window_ns"] != 40_000_000 or value["started_ns"] != started or
            value["ended_ns"] != finished or value["read_attempts"] > 64 or
            value["packets_received"] > value["read_attempts"] or
            value["socket_topology"] != "distinct_tx_and_observer" or
            value["observer_bound_ifindex"] <= 0 or
            value["outgoing_tap_is_rf_proof"] is not False):
        raise SenderProtocolError("monitor_observation_contract_invalid")
    for key in ("capture_finished", "capture_limit_reached", "kernel_stats_available"):
        if type(value[key]) is not bool:
            raise SenderProtocolError("monitor_boolean_invalid:" + key)
    for key in ("outgoing_exact_by_ordinal", "non_outgoing_exact_by_ordinal"):
        rows = value[key]
        if (not isinstance(rows, list) or len(rows) != 4 or
                any(type(item) is not int or item < 0 for item in rows)):
            raise SenderProtocolError("monitor_ordinal_counts_invalid:" + key)
    if sum(value["outgoing_exact_by_ordinal"]) + sum(value["non_outgoing_exact_by_ordinal"]) + value["exact_identity_unavailable"] > value["packets_received"]:
        raise SenderProtocolError("monitor_exact_counts_exceed_packet_count")
    samples = value["samples"]
    expected = min(value["packets_received"], 8)
    if (not isinstance(samples, list) or len(samples) != expected or
            value["samples_recorded"] != expected or
            value["samples_overflow"] != value["packets_received"] - expected):
        raise SenderProtocolError("monitor_sample_count_invalid")
    for sample in samples:
        sample_fields = {"packet_type_present", "packet_type", "ifindex_present", "ifindex",
                         "msg_flags", "received_len", "copied_len", "raw_packet_complete",
                         "exact_ordinal", "raw_packet_hex"}
        if not isinstance(sample, dict) or set(sample) != sample_fields:
            raise SenderProtocolError("monitor_sample_field_set_invalid")
        for key in ("packet_type_present", "ifindex_present", "raw_packet_complete"):
            if type(sample.get(key)) is not bool:
                raise SenderProtocolError("monitor_sample_boolean_invalid")
        _integer_map(sample, ("msg_flags",), maximum=512)
        _integer_map(sample, ("received_len",), maximum=65535)
        _integer_map(sample, ("copied_len",), maximum=512)
        if (sample["copied_len"] > sample["received_len"] or
                sample["raw_packet_complete"] != (sample["copied_len"] == sample["received_len"]) or
                not isinstance(sample["raw_packet_hex"], str) or
                len(sample["raw_packet_hex"]) != sample["copied_len"] * 2 or
                not HEX_RE.fullmatch(sample["raw_packet_hex"])):
            raise SenderProtocolError("monitor_sample_bytes_invalid")
        if sample["packet_type_present"] != (type(sample.get("packet_type")) is int):
            raise SenderProtocolError("monitor_sample_packet_type_mismatch")
        if sample["ifindex_present"] != (type(sample.get("ifindex")) is int):
            raise SenderProtocolError("monitor_sample_ifindex_mismatch")
        if sample["exact_ordinal"] is not None and (
                type(sample["exact_ordinal"]) is not int or not 0 <= sample["exact_ordinal"] < 4):
            raise SenderProtocolError("monitor_sample_ordinal_invalid")
    if value["kernel_stats_available"]:
        _integer_map(value, ("kernel_packets", "kernel_dropped_packets"))
        expected_loss_free = (value["kernel_dropped_packets"] == 0 and
                              value["kernel_packets"] == value["packets_received"] and
                              value["samples_overflow"] == 0 and value["capture_finished"] and
                              not value["capture_limit_reached"] and value["receive_error"] == 0)
    else:
        if value["kernel_packets"] is not None or value["kernel_dropped_packets"] is not None:
            raise SenderProtocolError("monitor_missing_stats_must_be_unknown")
        expected_loss_free = False if (
            value["samples_overflow"] or value["capture_limit_reached"] or
            value["receive_error"] or not value["capture_finished"]) else None
    if value["loss_free"] is not expected_loss_free:
        raise SenderProtocolError("monitor_loss_free_classification_invalid")
    return dict(value)


def validate_result(value: Any, run_token: str) -> dict:
    if not TOKEN_RE.fullmatch(run_token or "") or not isinstance(value, dict):
        raise SenderProtocolError("sender_result_invalid")
    if value.get("schema") != SENDER_SCHEMA or value.get("event") != "SENDER_RESULT":
        raise SenderProtocolError("sender_result_schema_invalid")
    if value.get("run_token") != run_token:
        raise SenderProtocolError("sender_result_token_mismatch")
    if set(value) == ABORT_FIELDS:
        if (value.get("status") != "aborted" or value.get("stop_reason") != "aborted_before_go" or
                any(type(value.get(key)) is not int for key in (
                    "frames_requested", "frames_attempted", "frames_completed", "sent",
                    "payload_bytes", "packet_bytes", "radiotap_bytes", "mpdu_bytes",
                    "udp_payload_bytes", "elapsed_ms", "error_count", "last_errno")) or
                any(value[key] != 0 for key in ("frames_attempted", "frames_completed", "sent",
                                                "elapsed_ms", "error_count", "last_errno")) or
                value["frames_requested"] != 4 or value["deadline_hit"] is not False or
                value["tx_flags_requested"] != "NOSEQNO" or
                value["hardware_honoring"] != "unknown"):
            raise SenderProtocolError("sender_abort_contract_mismatch")
        return {**value, "raw_txs": "unknown", "mac_ack": "unknown",
                "rf_transmission_proven": False, "peer_receipt_proven": False,
                "airdrop_proven": False, "send_timing": []}
    if set(value) != RESULT_FIELDS:
        raise SenderProtocolError("sender_result_field_set_invalid")
    int_fields = ("timing_schema", "go_received_ns", "frames_requested", "frames_attempted",
                  "frames_completed", "sent", "payload_bytes", "packet_bytes", "radiotap_bytes",
                  "mpdu_bytes", "udp_payload_bytes", "elapsed_ms", "error_count", "last_errno",
                  "interval_ms", "send_budget_ns", "started_ns", "finished_ns",
                  "local_send_calls", "actual_horizon_ns", "go_to_start_ns",
                  "go_to_start_max_ns")
    _integer_map(value, int_fields)
    if (value["timing_schema"] != 1 or value["clock_domain"] != "CLOCK_MONOTONIC" or
            value["frames_requested"] != 4 or value["interval_ms"] != 10 or
            value["send_budget_ns"] != 40_000_000 or value["started_ns"] < value["go_received_ns"] or
            value["finished_ns"] < value["started_ns"] or
            value["actual_horizon_ns"] != value["finished_ns"] - value["started_ns"] or
            value["go_to_start_ns"] != value["started_ns"] - value["go_received_ns"] or
            value["go_to_start_max_ns"] != GO_TO_START_MAX_NS or
            value["tx_flags_requested"] != "NOSEQNO" or value["noack_requested"] is not False or
            value["ack_policy"] != "normal_unicast_requested" or
            value["hardware_honoring"] != "unknown" or value["raw_txs"] != "unknown" or
            value["mac_ack"] != "unknown" or value["rf_transmission_proven"] is not False or
            value["peer_receipt_proven"] is not False or value["airdrop_proven"] is not False or
            value["payload_bytes"] != 96 or value["mpdu_bytes"] != 96 or
            value["radiotap_bytes"] != 10 or value["packet_bytes"] != 106 or
            value["udp_payload_bytes"] != 8 or value["local_send_calls"] != value["frames_attempted"] or
            value["frames_attempted"] > 4 or value["frames_completed"] > value["frames_attempted"] or
            value["sent"] != value["frames_completed"] or value["stop_reason"] not in STOP_REASONS):
        raise SenderProtocolError("sender_result_contract_mismatch")
    if type(value["deadline_hit"]) is not bool:
        raise SenderProtocolError("sender_deadline_invalid")
    rows = value["send_timing"]
    if not isinstance(rows, list) or len(rows) != value["frames_attempted"]:
        raise SenderProtocolError("sender_timing_rows_invalid")
    completed = 0
    previous = value["started_ns"]
    for ordinal, row in enumerate(rows):
        fields = {"ordinal", "ieee80211_sequence", "awdl_sequence", "before_ns",
                  "after_ns", "return_bytes", "errno"}
        if not isinstance(row, dict) or set(row) != fields:
            raise SenderProtocolError("sender_timing_row_fields_invalid")
        _integer_map(row, ("ordinal", "ieee80211_sequence", "awdl_sequence",
                           "before_ns", "after_ns", "errno"))
        if (row["ordinal"] != ordinal or row["ieee80211_sequence"] != 291 + ordinal or
                row["awdl_sequence"] != 34305 + ordinal or
                row["before_ns"] < value["go_received_ns"] or row["before_ns"] < previous or
                row["after_ns"] < row["before_ns"] or row["after_ns"] > value["finished_ns"] or
                row["return_bytes"] not in (-1, 0, 106) or
                (row["return_bytes"] == -1 and row["errno"] == 0) or
                (row["return_bytes"] >= 0 and row["errno"] != 0)):
            raise SenderProtocolError("sender_timing_row_invalid")
        if ordinal and row["before_ns"] - previous < 10_000_000:
            raise SenderProtocolError("sender_frame_spacing_below_10ms")
        completed += row["return_bytes"] == 106
        previous = row["before_ns"]
    if completed != value["frames_completed"]:
        raise SenderProtocolError("sender_completion_count_invalid")
    first_send_ns = value["first_send_ns"]
    if first_send_ns is not None and (
            type(first_send_ns) is not int or first_send_ns < value["started_ns"] or
            first_send_ns < value["go_received_ns"]):
        raise SenderProtocolError("sender_first_send_timestamp_invalid")
    if (value["frames_attempted"] == 0) != (first_send_ns is None):
        raise SenderProtocolError("sender_first_send_presence_mismatch")
    if first_send_ns is not None and (
            not rows or first_send_ns != rows[0]["before_ns"] or
            first_send_ns - value["go_received_ns"] > GO_TO_START_MAX_NS):
        raise SenderProtocolError("sender_first_send_lease_bound_violated")
    if (value["status"] == "complete" and
            (value["stop_reason"] != "complete" or value["frames_attempted"] != 4 or
             value["frames_completed"] != 4 or value["error_count"] != 0 or
             value["last_errno"] != 0 or value["deadline_hit"])):
        raise SenderProtocolError("sender_completion_claim_invalid")
    if value["status"] not in ("complete", "failed"):
        raise SenderProtocolError("sender_status_invalid")
    if (value["go_to_start_ns"] > GO_TO_START_MAX_NS and
            value["frames_attempted"] != 0):
        raise SenderProtocolError("go_to_start_lease_bound_violated")
    if (value["stop_reason"] == "go_to_start_budget_expired" and
            (value["frames_attempted"] != 0 or first_send_ns is not None)):
        raise SenderProtocolError("go_to_start_expiry_reason_contradiction")
    if value["deadline_hit"] != (value["stop_reason"] in {
            "send_budget_expired", "send_completed_after_budget"}):
        raise SenderProtocolError("sender_deadline_contradiction")
    drain = _validate_drain(value["pre_capture_queue_drain"])
    monitor = _validate_monitor(value["monitor_observation"], started=value["started_ns"],
                                finished=value["finished_ns"])
    go_to_first_send_ns = (None if first_send_ns is None else
                           first_send_ns - value["go_received_ns"])
    go_to_first_send_valid = (go_to_first_send_ns is not None and
                              0 <= go_to_first_send_ns <= GO_TO_START_MAX_NS)
    epoch_valid = drain["capture_epoch_clean"] and go_to_first_send_valid
    attempted_ordinals = {
        row["ordinal"] for row in rows if row["return_bytes"] == 106
    }
    observed_ordinals = {
        ordinal for ordinal, count in enumerate(monitor["outgoing_exact_by_ordinal"])
        if count
    } | {
        ordinal for ordinal, count in enumerate(monitor["non_outgoing_exact_by_ordinal"])
        if count
    }
    exact_attribution_valid = (
        bool(observed_ordinals) and epoch_valid and monitor["capture_finished"] and
        monitor["loss_free"] is True and
        observed_ordinals.issubset(attempted_ordinals))
    return {**value, "pre_capture_queue_drain": drain, "monitor_observation": monitor,
            "capture_epoch_valid": epoch_valid,
            "go_to_first_send_ns": go_to_first_send_ns,
            "zero_exact_interpretation_allowed": epoch_valid and monitor["capture_finished"] and
                monitor["loss_free"] is True and value["frames_attempted"] == 4 and
                value["frames_completed"] == 4,
            "exact_current_run_attribution_allowed": exact_attribution_valid,
            "observed_exact_ordinals": sorted(observed_ordinals),
            "locally_completed_ordinals": sorted(attempted_ordinals)}


def legacy_projection(value: dict) -> dict:
    stop_map = {
        "schedule_wait_failed": "schedule_or_sleep_failed",
        "clock_before_failed": "monotonic_clock_unavailable",
        "clock_after_failed": "monotonic_clock_unavailable",
        "go_to_start_budget_expired": "send_errno",
        "observer_drain_incomplete": "send_errno",
        "send_spacing_violation": "send_errno",
    }
    return {
        "event": "SENDER_RESULT", "status": value.get("status"),
        "frames_attempted": value.get("frames_attempted"),
        "frames_completed": value.get("frames_completed"), "sent": value.get("sent"),
        "payload_bytes": value.get("payload_bytes"), "mpdu_bytes": value.get("mpdu_bytes"),
        "radiotap_bytes": value.get("radiotap_bytes"), "packet_bytes": value.get("packet_bytes"),
        "udp_payload_bytes": value.get("udp_payload_bytes"), "elapsed_ms": value.get("elapsed_ms"),
        "deadline_hit": value.get("deadline_hit"), "error_count": value.get("error_count"),
        "last_errno": value.get("last_errno"),
        "stop_reason": stop_map.get(value.get("stop_reason"), value.get("stop_reason")),
        "tx_flags_requested": value.get("tx_flags_requested"),
        "hardware_honoring": value.get("hardware_honoring"),
    }


def project_legacy_result(value: dict, run_token: str) -> dict:
    raw = validate_result(value, run_token)
    legacy = legacy_projection(raw)
    if set(legacy) != LEGACY_FIELDS:
        raise SenderProtocolError("legacy_projection_field_set_invalid")
    return legacy


def parse_result_line(line: str, run_token: str) -> tuple[dict, dict]:
    raw = validate_result(_json(line), run_token)
    return raw, legacy_projection(raw)


class SenderAdapterError(ValueError):
    pass


def classify_sender_result(sender_result: Any) -> dict:
    """Validate raw sender data and return a private-safe evidence summary."""
    if not isinstance(sender_result, dict):
        raise SenderAdapterError("sender_result_not_object")
    token = sender_result.get("run_token")
    try:
        validated = validate_result(sender_result, token)
        canonical = json.dumps(sender_result, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"))
    except (SenderProtocolError, TypeError, ValueError) as error:
        raise SenderAdapterError("sender_result_validation_failed") from error
    monitor = validated.get("monitor_observation") or {}
    return {
        "schema": "test119-sender-adapter/v1",
        "status": "local_sender_result_validated",
        "raw_sender_result_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "frames_requested": validated.get("frames_requested"),
        "frames_attempted": validated.get("frames_attempted"),
        "frames_completed": validated.get("frames_completed"),
        "send_timing": validated.get("send_timing", []),
        "pre_capture_queue_drain": validated.get("pre_capture_queue_drain"),
        "monitor_capture_finished": monitor.get("capture_finished"),
        "monitor_loss_free": monitor.get("loss_free"),
        "capture_epoch_valid": validated.get("capture_epoch_valid"),
        "zero_exact_interpretation_allowed": validated.get(
            "zero_exact_interpretation_allowed"),
        "exact_current_run_attribution_allowed": validated.get(
            "exact_current_run_attribution_allowed"),
        "observed_exact_ordinals": validated.get("observed_exact_ordinals", []),
        "locally_completed_ordinals": validated.get("locally_completed_ordinals", []),
        "raw_packet_hex_in_public_summary": False,
        "raw_txs": "unknown", "mac_ack": "unknown",
        "rf_transmission_proven": False, "peer_receipt_proven": False,
        "native_awdl0_ingress_proven": False, "airdrop_proven": False,
        "test088_legacy_projection_is_non_authoritative": True,
    }
