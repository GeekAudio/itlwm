#!/usr/bin/env python3
"""Strict offline parser for the Test104 unicast sender protocol."""
from __future__ import annotations

import json
import re
from typing import Any


SCHEMA = "test104-unicast-sender/v1"
READY_SCHEMA = "test104-unicast-sender/v1"
MAX_LINE_BYTES = 16 * 1024
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
READY_FIELDS = {
    "schema": READY_SCHEMA,
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
    "go_received_ns", "started_ns", "send_budget_ns", "frames_requested",
    "interval_ms", "tx_flags_requested", "noack_requested",
}
RESULT_FIELDS = {
    "event", "schema", "timing_schema", "clock_domain", "status", "run_token",
    "go_received_ns", "frames_requested", "frames_attempted", "frames_completed",
    "sent", "payload_bytes", "packet_bytes", "radiotap_bytes", "mpdu_bytes",
    "udp_payload_bytes", "elapsed_ms", "deadline_hit", "error_count", "last_errno",
    "stop_reason", "tx_flags_requested", "noack_requested", "ack_policy",
    "hardware_honoring", "raw_txs", "mac_ack", "interval_ms", "send_budget_ns",
    "started_ns", "finished_ns", "local_send_calls", "send_timing",
    "actual_horizon_ns", "monitor_observation",
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
STOP_REASONS = {
    "complete", "aborted_before_go", "send_budget_expired", "schedule_wait_failed",
    "clock_before_failed", "send_errno", "short_write", "clock_after_failed",
    "send_completed_after_budget",
}


class SenderProtocolError(ValueError):
    pass


def _bounded_json(line: Any) -> dict:
    if not isinstance(line, str) or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise SenderProtocolError("sender_line_oversize_or_invalid")
    try:
        value = json.loads(line)
    except (ValueError, TypeError) as error:
        raise SenderProtocolError("sender_json_invalid") from error
    if not isinstance(value, dict):
        raise SenderProtocolError("sender_record_not_object")
    return value


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
    if values != READY_FIELDS:
        raise SenderProtocolError("sender_ready_contract_mismatch")
    return {
        "frames": 4,
        "interval_ms": 10,
        "mpdu_bytes": 96,
        "radiotap_bytes": 10,
        "packet_bytes": 106,
        "udp_payload_bytes": 8,
        "tx_flags_requested": "NOSEQNO",
        "noack_requested": False,
        "hardware_honoring": "unknown",
        "raw_txs": "unknown",
        "send_started": False,
    }


def parse_started(value: Any, run_token: str) -> dict:
    if not TOKEN_RE.fullmatch(run_token or "") or not isinstance(value, dict):
        raise SenderProtocolError("sender_started_invalid")
    if set(value) != STARTED_FIELDS or value.get("event") != "SENDER_STARTED" or value.get("schema") != SCHEMA:
        raise SenderProtocolError("sender_started_field_set_or_schema_invalid")
    integers = ("timing_schema", "go_received_ns", "started_ns", "send_budget_ns",
                "frames_requested", "interval_ms")
    if any(type(value.get(field)) is not int or value[field] < 0 for field in integers):
        raise SenderProtocolError("sender_started_integer_invalid")
    if (value["timing_schema"] != 1 or value["clock_domain"] != "CLOCK_MONOTONIC" or
            value["run_token"] != run_token or value["started_ns"] < value["go_received_ns"] or
            value["send_budget_ns"] != 40_000_000 or value["frames_requested"] != 4 or
            value["interval_ms"] != 10 or value["tx_flags_requested"] != "NOSEQNO" or
            value["noack_requested"] is not False):
        raise SenderProtocolError("sender_started_contract_mismatch")
    return dict(value)


def _legacy_projection(value: dict) -> dict:
    stop_reason = value.get("stop_reason")
    stop_map = {
        "schedule_wait_failed": "schedule_or_sleep_failed",
        "clock_before_failed": "monotonic_clock_before_failed",
        "clock_after_failed": "monotonic_clock_after_failed",
    }
    return {
        "event": "SENDER_RESULT",
        "status": value.get("status"),
        "frames_attempted": value.get("frames_attempted"),
        "frames_completed": value.get("frames_completed"),
        "sent": value.get("sent"),
        "payload_bytes": value.get("payload_bytes"),
        "mpdu_bytes": value.get("mpdu_bytes"),
        "radiotap_bytes": value.get("radiotap_bytes"),
        "packet_bytes": value.get("packet_bytes"),
        "udp_payload_bytes": value.get("udp_payload_bytes"),
        "elapsed_ms": value.get("elapsed_ms"),
        "deadline_hit": value.get("deadline_hit"),
        "error_count": value.get("error_count"),
        "last_errno": value.get("last_errno"),
        "stop_reason": stop_map.get(stop_reason, stop_reason),
        "tx_flags_requested": value.get("tx_flags_requested"),
        "hardware_honoring": value.get("hardware_honoring"),
    }


def validate_result(value: Any, run_token: str) -> dict:
    if not TOKEN_RE.fullmatch(run_token or "") or not isinstance(value, dict):
        raise SenderProtocolError("sender_result_invalid")
    if value.get("schema") != SCHEMA or value.get("event") != "SENDER_RESULT":
        raise SenderProtocolError("sender_result_schema_invalid")
    if value.get("run_token") != run_token:
        raise SenderProtocolError("sender_result_token_mismatch")
    if set(value) == ABORT_FIELDS:
        if (value.get("status") != "aborted" or
                value.get("stop_reason") != "aborted_before_go" or
                value.get("frames_requested") != 4 or
                any(type(value.get(key)) is not int for key in (
                    "frames_attempted", "frames_completed", "sent", "payload_bytes",
                    "packet_bytes", "radiotap_bytes", "mpdu_bytes", "udp_payload_bytes",
                    "elapsed_ms", "error_count", "last_errno")) or
                any(value.get(key) != 0 for key in (
                    "frames_attempted", "frames_completed", "sent", "elapsed_ms",
                    "error_count", "last_errno")) or
                value.get("deadline_hit") is not False or
                value.get("tx_flags_requested") != "NOSEQNO" or
                value.get("hardware_honoring") != "unknown"):
            raise SenderProtocolError("sender_abort_contract_mismatch")
        return {**value, "raw_txs": "unknown", "mac_ack": "unknown",
                "rf_transmission_proven": False, "peer_receipt_proven": False,
                "airdrop_proven": False, "send_timing": []}
    if set(value) != RESULT_FIELDS:
        raise SenderProtocolError("sender_result_field_set_invalid")
    int_fields = ("timing_schema", "go_received_ns", "frames_requested", "frames_attempted",
                  "frames_completed", "sent", "payload_bytes", "packet_bytes",
                  "radiotap_bytes", "mpdu_bytes", "udp_payload_bytes", "elapsed_ms",
                  "error_count", "last_errno", "interval_ms", "send_budget_ns",
                  "started_ns", "finished_ns", "local_send_calls")
    if any(type(value.get(key)) is not int or value[key] < 0 for key in int_fields):
        raise SenderProtocolError("sender_result_integer_invalid")
    if (value["timing_schema"] != 1 or value["clock_domain"] != "CLOCK_MONOTONIC" or
            value["frames_requested"] != 4 or value["interval_ms"] != 10 or
            value["send_budget_ns"] != 40_000_000 or value["tx_flags_requested"] != "NOSEQNO" or
            value["noack_requested"] is not False or
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
    if type(value.get("deadline_hit")) is not bool:
        raise SenderProtocolError("sender_result_deadline_invalid")
    rows = value.get("send_timing")
    if not isinstance(rows, list) or len(rows) != value["frames_attempted"]:
        raise SenderProtocolError("sender_result_timing_rows_invalid")
    previous_before = value["started_ns"]
    completed = 0
    for ordinal, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
                "ordinal", "ieee80211_sequence", "awdl_sequence", "before_ns",
                "after_ns", "return_bytes", "errno"}:
            raise SenderProtocolError("sender_result_timing_row_fields_invalid")
        if any(type(row.get(key)) is not int for key in row):
            raise SenderProtocolError("sender_result_timing_row_type_invalid")
        if (row["ordinal"] != ordinal or row["ieee80211_sequence"] != 291 + ordinal or
                row["awdl_sequence"] != 34305 + ordinal or
                row["before_ns"] < value["go_received_ns"] or
                row["before_ns"] < previous_before or row["after_ns"] < row["before_ns"] or
                row["before_ns"] > value["finished_ns"] or row["after_ns"] > value["finished_ns"] or
                row["return_bytes"] not in (-1, 0, 106) or row["errno"] < 0 or
                (row["return_bytes"] == -1 and row["errno"] == 0) or
                (row["return_bytes"] >= 0 and row["errno"] != 0)):
            raise SenderProtocolError("sender_result_timing_row_invalid")
        if row["return_bytes"] == 106:
            completed += 1
        previous_before = row["before_ns"]
    if completed != value["frames_completed"]:
        raise SenderProtocolError("sender_result_completion_count_mismatch")
    if value["status"] == "complete":
        if (value["stop_reason"] != "complete" or value["frames_attempted"] != 4 or
                value["frames_completed"] != 4 or value["sent"] != 4 or
                value["error_count"] != 0 or value["last_errno"] != 0 or
                value["deadline_hit"]):
            raise SenderProtocolError("sender_result_completion_claim_invalid")
    elif value["status"] != "failed" or value["stop_reason"] == "complete":
        raise SenderProtocolError("sender_result_status_invalid")
    if value["deadline_hit"] != (value["stop_reason"] in {
            "send_budget_expired", "send_completed_after_budget"}):
        raise SenderProtocolError("sender_result_deadline_contradiction")
    if value["actual_horizon_ns"] != value["finished_ns"] - value["started_ns"]:
        raise SenderProtocolError("sender_result_actual_horizon_mismatch")
    monitor = value["monitor_observation"]
    monitor_fields = {
        "schema", "capture_window_ns", "started_ns", "ended_ns", "capture_finished",
        "capture_limit_reached", "read_attempts", "packets_received", "samples_recorded",
        "samples_overflow", "receive_error", "kernel_stats_available", "kernel_packets",
        "kernel_dropped_packets", "loss_free", "samples",
    }
    if not isinstance(monitor, dict) or set(monitor) != monitor_fields:
        raise SenderProtocolError("monitor_observation_field_set_invalid")
    integer_fields = ("capture_window_ns", "started_ns", "ended_ns", "read_attempts",
                      "packets_received", "samples_recorded", "samples_overflow", "receive_error")
    if any(type(monitor.get(key)) is not int or monitor[key] < 0 for key in integer_fields):
        raise SenderProtocolError("monitor_observation_integer_invalid")
    if (monitor["schema"] != "test104-monitor-observation/v1" or
            monitor["capture_window_ns"] != 40_000_000 or
            monitor["started_ns"] != value["started_ns"] or
            monitor["ended_ns"] != value["finished_ns"] or
            monitor["read_attempts"] > 64 or monitor["packets_received"] > monitor["read_attempts"] or
            type(monitor.get("capture_finished")) is not bool or
            type(monitor.get("capture_limit_reached")) is not bool or
            type(monitor.get("kernel_stats_available")) is not bool):
        raise SenderProtocolError("monitor_observation_contract_invalid")
    samples = monitor.get("samples")
    expected_recorded = min(monitor["packets_received"], 8)
    if (not isinstance(samples, list) or len(samples) != expected_recorded or
            monitor["samples_recorded"] != expected_recorded or
            monitor["samples_overflow"] != monitor["packets_received"] - expected_recorded):
        raise SenderProtocolError("monitor_observation_sample_count_invalid")
    for sample in samples:
        sample_fields = {"packet_type_present", "packet_type", "ifindex_present", "ifindex",
                         "msg_flags", "received_len", "copied_len", "raw_packet_complete",
                         "exact_ordinal", "raw_packet_hex"}
        if not isinstance(sample, dict) or set(sample) != sample_fields:
            raise SenderProtocolError("monitor_sample_field_set_invalid")
        for key in ("packet_type_present", "ifindex_present", "raw_packet_complete"):
            if type(sample.get(key)) is not bool:
                raise SenderProtocolError("monitor_sample_boolean_invalid")
        for key in ("msg_flags", "received_len", "copied_len"):
            if type(sample.get(key)) is not int or sample[key] < 0:
                raise SenderProtocolError("monitor_sample_length_or_flags_invalid")
        if (sample["copied_len"] > 512 or sample["copied_len"] > sample["received_len"] or
                sample["raw_packet_complete"] != (sample["copied_len"] == sample["received_len"]) or
                not isinstance(sample.get("raw_packet_hex"), str) or
                len(sample["raw_packet_hex"]) != sample["copied_len"] * 2 or
                not re.fullmatch(r"(?:[0-9a-f]{2})*", sample["raw_packet_hex"])):
            raise SenderProtocolError("monitor_sample_raw_bytes_invalid")
        if sample["packet_type_present"] != (type(sample.get("packet_type")) is int):
            raise SenderProtocolError("monitor_sample_packet_type_presence_mismatch")
        if sample["ifindex_present"] != (type(sample.get("ifindex")) is int):
            raise SenderProtocolError("monitor_sample_ifindex_presence_mismatch")
        if sample.get("exact_ordinal") is not None and (
                type(sample["exact_ordinal"]) is not int or
                not 0 <= sample["exact_ordinal"] < 4):
            raise SenderProtocolError("monitor_sample_exact_ordinal_invalid")
    if monitor["kernel_stats_available"]:
        for key in ("kernel_packets", "kernel_dropped_packets"):
            if type(monitor.get(key)) is not int or monitor[key] < 0:
                raise SenderProtocolError("monitor_kernel_stats_invalid")
        expected_loss_free = (
            monitor["kernel_dropped_packets"] == 0 and
            monitor["kernel_packets"] == monitor["packets_received"] and
            monitor["samples_overflow"] == 0 and
            monitor["capture_finished"] and not monitor["capture_limit_reached"] and
            monitor["receive_error"] == 0)
    else:
        if monitor["kernel_packets"] is not None or monitor["kernel_dropped_packets"] is not None:
            raise SenderProtocolError("monitor_missing_stats_must_be_unknown")
        expected_loss_free = False if (
            monitor["samples_overflow"] or monitor["capture_limit_reached"] or
            monitor["receive_error"] or not monitor["capture_finished"]) else None
    if monitor.get("loss_free") is not expected_loss_free:
        raise SenderProtocolError("monitor_loss_free_classification_invalid")
    return dict(value)


def project_legacy_result(value: dict, run_token: str) -> dict:
    raw = validate_result(value, run_token)
    legacy = _legacy_projection(raw)
    if set(legacy) != LEGACY_FIELDS:
        raise SenderProtocolError("sender_result_legacy_projection_invalid")
    return legacy


def parse_result_line(line: str, run_token: str) -> tuple[dict, dict]:
    raw = validate_result(_bounded_json(line), run_token)
    return raw, _legacy_projection(raw)

