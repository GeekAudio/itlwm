#!/usr/bin/env python3
"""Test121 wire adapter with a 64-sample raw monitor bank.

The stable Test119 validator remains the implementation base for the bounded
sender fields. Test121 binds a new wire schema and replaces only the monitor
sample-cap validator. All 40 ms, four-frame, 10 ms spacing, queue-drain,
ordinal, and fail-closed checks remain intact.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
BASE_PROTOCOL_PATH = REPO_ROOT / "developer-tools/test119/dual_sender_protocol_test119.py"
SENDER_SCHEMA = "test121-dual-socket-sender/v1"
MONITOR_SCHEMA = "test121-dual-socket-monitor/v1"
DRAIN_SCHEMA = "test121-pre-capture-drain/v1"
RAW_CAPTURE_LIMIT = 64
RAW_CAPTURE_BYTES = 512
MAX_LINE_BYTES = 128 * 1024


def _load_base():
    if BASE_PROTOCOL_PATH.is_symlink() or not BASE_PROTOCOL_PATH.is_file():
        raise RuntimeError("TEST121_BASE_PROTOCOL_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(
        "test121_frozen_test119_dual_sender_protocol", BASE_PROTOCOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST121_BASE_PROTOCOL_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_BASE = _load_base()
_BASE.SENDER_SCHEMA = SENDER_SCHEMA
_BASE.SCHEMA = SENDER_SCHEMA
_BASE.MONITOR_SCHEMA = MONITOR_SCHEMA
_BASE.DRAIN_SCHEMA = DRAIN_SCHEMA
_BASE.READY_VALUES = {**_BASE.READY_VALUES, "schema": SENDER_SCHEMA}


def _json(line: Any) -> dict:
    if not isinstance(line, str) or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise _BASE.SenderProtocolError("sender_line_oversize_or_invalid")
    try:
        import json
        value = json.loads(line)
    except (ValueError, TypeError) as error:
        raise _BASE.SenderProtocolError("sender_json_invalid") from error
    if not isinstance(value, dict):
        raise _BASE.SenderProtocolError("sender_record_not_object")
    return value


_BASE._json = _json


def _validate_monitor(value: Any, *, started: int, finished: int) -> dict:
    fields = {
        "schema", "capture_window_ns", "started_ns", "ended_ns", "capture_finished",
        "capture_limit_reached", "read_attempts", "packets_received", "samples_recorded",
        "samples_overflow", "receive_error", "kernel_stats_available", "kernel_packets",
        "kernel_dropped_packets", "loss_free", "socket_topology", "observer_bound_ifindex",
        "outgoing_tap_is_rf_proof", "outgoing_exact_by_ordinal",
        "non_outgoing_exact_by_ordinal", "exact_identity_unavailable", "samples",
    }
    error = _BASE.SenderProtocolError
    integer_map = _BASE._integer_map
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != MONITOR_SCHEMA:
        raise error("monitor_observation_field_set_invalid")
    integer_map(value, ("capture_window_ns", "started_ns", "ended_ns", "read_attempts",
                        "packets_received", "samples_recorded", "samples_overflow",
                        "receive_error", "observer_bound_ifindex",
                        "exact_identity_unavailable"))
    if (value["capture_window_ns"] != 40_000_000 or value["started_ns"] != started or
            value["ended_ns"] != finished or value["read_attempts"] > 64 or
            value["packets_received"] > value["read_attempts"] or
            (value["read_attempts"] == 64 and
             (value["capture_limit_reached"] is not True or
              value["capture_finished"] is not False)) or
            (value["read_attempts"] < 64 and value["capture_limit_reached"] is True) or
            value["socket_topology"] != "distinct_tx_and_observer" or
            value["observer_bound_ifindex"] <= 0 or
            value["outgoing_tap_is_rf_proof"] is not False):
        raise error("monitor_observation_contract_invalid")
    for key in ("capture_finished", "capture_limit_reached", "kernel_stats_available"):
        if type(value[key]) is not bool:
            raise error("monitor_boolean_invalid:" + key)
    for key in ("outgoing_exact_by_ordinal", "non_outgoing_exact_by_ordinal"):
        rows = value[key]
        if (not isinstance(rows, list) or len(rows) != 4 or
                any(type(item) is not int or item < 0 for item in rows)):
            raise error("monitor_ordinal_counts_invalid:" + key)
    if (sum(value["outgoing_exact_by_ordinal"]) +
            sum(value["non_outgoing_exact_by_ordinal"]) +
            value["exact_identity_unavailable"] > value["packets_received"]):
        raise error("monitor_exact_counts_exceed_packet_count")
    samples = value["samples"]
    expected = min(value["packets_received"], RAW_CAPTURE_LIMIT)
    if (not isinstance(samples, list) or len(samples) != expected or
            value["samples_recorded"] != expected or
            value["samples_overflow"] != value["packets_received"] - expected):
        raise error("monitor_sample_count_invalid")
    for sample in samples:
        sample_fields = {"packet_type_present", "packet_type", "ifindex_present", "ifindex",
                         "msg_flags", "received_len", "copied_len", "raw_packet_complete",
                         "exact_ordinal", "raw_packet_hex"}
        if not isinstance(sample, dict) or set(sample) != sample_fields:
            raise error("monitor_sample_field_set_invalid")
        for key in ("packet_type_present", "ifindex_present", "raw_packet_complete"):
            if type(sample.get(key)) is not bool:
                raise error("monitor_sample_boolean_invalid")
        integer_map(sample, ("msg_flags",), maximum=512)
        integer_map(sample, ("received_len",), maximum=65535)
        integer_map(sample, ("copied_len",), maximum=RAW_CAPTURE_BYTES)
        if (sample["copied_len"] > sample["received_len"] or
                sample["raw_packet_complete"] !=
                (sample["copied_len"] == sample["received_len"]) or
                not isinstance(sample["raw_packet_hex"], str) or
                len(sample["raw_packet_hex"]) != sample["copied_len"] * 2 or
                not _BASE.HEX_RE.fullmatch(sample["raw_packet_hex"])):
            raise error("monitor_sample_bytes_invalid")
        if sample["packet_type_present"] != (type(sample.get("packet_type")) is int):
            raise error("monitor_sample_packet_type_mismatch")
        if sample["ifindex_present"] != (type(sample.get("ifindex")) is int):
            raise error("monitor_sample_ifindex_mismatch")
        ordinal = sample["exact_ordinal"]
        if ordinal is not None and (type(ordinal) is not int or not 0 <= ordinal < 4):
            raise error("monitor_sample_ordinal_invalid")
    all_samples_complete = all(sample["raw_packet_complete"] for sample in samples)
    if value["kernel_stats_available"]:
        integer_map(value, ("kernel_packets", "kernel_dropped_packets"))
        expected_loss_free = (
            value["kernel_dropped_packets"] == 0 and
            value["kernel_packets"] == value["packets_received"] and
            value["samples_overflow"] == 0 and value["capture_finished"] and
            not value["capture_limit_reached"] and value["receive_error"] == 0 and
            all_samples_complete)
    else:
        if value["kernel_packets"] is not None or value["kernel_dropped_packets"] is not None:
            raise error("monitor_missing_stats_must_be_unknown")
        expected_loss_free = False if (
            value["samples_overflow"] or value["capture_limit_reached"] or
            value["receive_error"] or not value["capture_finished"] or
            not all_samples_complete) else None
    if value["loss_free"] is not expected_loss_free:
        raise error("monitor_loss_free_classification_invalid")
    return dict(value)


_BASE._validate_monitor = _validate_monitor


def classify_sender_result(sender_result: Any) -> dict:
    result = _BASE.classify_sender_result(sender_result)
    return {**result, "schema": "test121-sender-adapter/v1",
            "raw_capture_limit": RAW_CAPTURE_LIMIT,
            "raw_capture_bytes_per_sample": RAW_CAPTURE_BYTES}


def __getattr__(name: str):
    return getattr(_BASE, name)
