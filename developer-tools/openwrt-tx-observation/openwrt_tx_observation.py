#!/usr/bin/env python3
"""Offline, conservative classifier for bounded OpenWrt AF_PACKET captures.

This module reads JSON only. It does not open a socket, contact a router, or
perform a wireless operation. Local send acceptance, monitor observations,
capture completeness, decoder coverage, and device/peer evidence are separate
facts by design.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "openwrt-tx-observation/v1"
LEGACY_SCHEMA = "test100-openwrt-tx-provenance/v1"
MAX_FRAMES = 4
MAX_OBSERVATIONS = 16
MAX_CAPTURE_PACKETS = 128
MAX_CAPTURE_NS = 40_000_000
MAX_REJECT_SAMPLES = 8
MAX_PREFIX_BYTES = 96
MAX_PACKET_BYTES = 4096
MAX_U64 = (1 << 64) - 1
WINDOW_CUTOFF_SEMANTICS = "min(actual_finished_ns,started_ns+budget_ns)"
PACKET_OTHERHOST = 3
PACKET_OUTGOING = 4
TX_FLAGS_REQUESTED = "NOACK|NOSEQNO"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})*$")
REJECT_REASONS = {
    "packet_truncated", "short_header", "invalid_version", "invalid_pad",
    "invalid_declared_length", "present_bitmap_truncated",
    "present_bitmap_capacity_exceeded", "vendor_namespace",
    "unsupported_namespace", "unsupported_field", "field_bounds",
    "fcs_bytes_missing",
}
PARSE_REASONS = REJECT_REASONS | {"none"}


class ObservationError(ValueError):
    """Malformed, contradictory, or overclaiming sender evidence."""


def _int(value: Any, field: str, *, minimum: int = 0,
         maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum:
        raise ObservationError("invalid_" + field)
    if maximum is not None and value > maximum:
        raise ObservationError("invalid_" + field)
    return value


def _bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ObservationError("invalid_" + field)
    return value


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise ObservationError("invalid_" + field)
    return value


def _expected_sequences(ordinal: int) -> tuple[int, int]:
    return (291 + ordinal) & 0x0FFF, (34305 + ordinal) & 0xFFFF


def _claim_false(container: dict[str, Any], key: str, scope: str) -> None:
    if key in container and _bool(container[key], key) is not False:
        raise ObservationError(scope + "_overclaim_" + key)


def _classify_full_observation(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ObservationError("observation_not_object")
    ordinal = _int(row.get("ordinal"), "ordinal", maximum=MAX_FRAMES - 1)
    packet_type = _int(row.get("packet_type"), "packet_type", maximum=7)
    if _bool(row.get("exact_mpdu_match"), "exact_mpdu_match") is not True:
        raise ObservationError("observation_not_exact_full_mpdu_match")
    digest = _hash(row.get("mpdu_sha256"), "observation_mpdu_sha256")
    wifi_sequence = _int(row.get("wifi_sequence"), "wifi_sequence", maximum=0x0FFF)
    awdl_sequence = _int(row.get("awdl_sequence"), "awdl_sequence", maximum=0xFFFF)
    if (wifi_sequence, awdl_sequence) != _expected_sequences(ordinal):
        raise ObservationError("observation_frame_identity_mismatch")
    observed_ns = _int(row.get("observed_ns"), "observed_ns")
    has_tx_flags = _bool(row.get("has_tx_flags"), "has_tx_flags")
    tx_flags = _int(row.get("tx_flags"), "tx_flags", maximum=0xFFFF)
    has_retries = _bool(row.get("has_data_retries"), "has_data_retries")
    retries = _int(row.get("data_retries"), "data_retries", maximum=0xFF)
    if not has_tx_flags and tx_flags != 0:
        raise ObservationError("tx_flags_value_without_presence")
    if not has_retries and retries != 0:
        raise ObservationError("data_retries_value_without_presence")

    if packet_type == PACKET_OUTGOING:
        classification = "packet_outgoing_echo"
    elif packet_type == PACKET_OTHERHOST and has_tx_flags and has_retries:
        classification = "generated_tx_completion_copy_candidate"
    else:
        classification = "exact_frame_match_unclassified"
    if row.get("classification", classification) != classification:
        raise ObservationError("observation_classification_mismatch")
    if "invocation_bound" in row and _bool(row["invocation_bound"],
                                           "invocation_bound") is not False:
        raise ObservationError("observation_invocation_binding_overclaim")
    for claim in ("pid_cookie_tx_status_proven", "rf_transmission_proven",
                  "ack_proven", "peer_receipt_proven"):
        _claim_false(row, claim, "observation")
    return {
        "ordinal": ordinal,
        "packet_type": packet_type,
        "classification": classification,
        "mpdu_sha256": digest,
        "wifi_sequence": wifi_sequence,
        "awdl_sequence": awdl_sequence,
        "observed_ns": observed_ns,
        "has_tx_flags": has_tx_flags,
        "tx_flags": tx_flags,
        "has_data_retries": has_retries,
        "data_retries": retries,
        "pid_cookie_tx_status_proven": False,
        "rf_transmission_proven": False,
        "ack_proven": False,
        "peer_receipt_proven": False,
    }


def _validate_rejected_sample(sample: Any) -> dict[str, Any]:
    if not isinstance(sample, dict):
        raise ObservationError("rejected_sample_not_object")
    packet_type_present = _bool(sample.get("packet_type_present"),
                                "sample_packet_type_present")
    packet_type = sample.get("packet_type")
    if packet_type_present:
        packet_type = _int(packet_type, "sample_packet_type", maximum=7)
    elif packet_type is not None:
        raise ObservationError("packet_type_value_without_presence")
    msg_flags = _int(sample.get("msg_flags"), "sample_msg_flags", maximum=0xFFFFFFFF)
    received_len = _int(sample.get("received_len"), "sample_received_len",
                        maximum=MAX_U64)
    copied_len = _int(sample.get("copied_len"), "sample_copied_len",
                      maximum=MAX_PACKET_BYTES)
    if copied_len > received_len:
        raise ObservationError("sample_copied_length_exceeds_received")
    if copied_len != min(received_len, MAX_PACKET_BYTES):
        raise ObservationError("sample_copied_length_not_recvmsg_bound")

    prefix_hex = sample.get("raw_prefix_hex")
    if not isinstance(prefix_hex, str) or HEX_RE.fullmatch(prefix_hex) is None:
        raise ObservationError("invalid_raw_prefix_hex")
    prefix = bytes.fromhex(prefix_hex)
    prefix_len = _int(sample.get("raw_prefix_len"), "sample_raw_prefix_len",
                      maximum=MAX_PREFIX_BYTES)
    if prefix_len != len(prefix) or prefix_len > min(copied_len, MAX_PREFIX_BYTES):
        raise ObservationError("raw_prefix_length_mismatch")
    if prefix_len != min(copied_len, MAX_PREFIX_BYTES):
        raise ObservationError("raw_prefix_not_maximal_available_prefix")

    version_present = _bool(sample.get("version_present"),
                            "sample_version_present")
    version = sample.get("version")
    raw_version_present = len(prefix) >= 1
    raw_version = prefix[0] if raw_version_present else None
    if version_present is not raw_version_present:
        raise ObservationError("version_presence_disagrees_with_raw_prefix")
    if version_present:
        version = _int(version, "sample_version", maximum=0xFF)
        if version != raw_version:
            raise ObservationError("version_disagrees_with_raw_prefix")
    elif version is not None:
        raise ObservationError("version_value_without_presence")

    pad_present = _bool(sample.get("pad_present"), "sample_pad_present")
    pad = sample.get("pad")
    raw_pad_present = len(prefix) >= 2
    raw_pad = prefix[1] if raw_pad_present else None
    if pad_present is not raw_pad_present:
        raise ObservationError("pad_presence_disagrees_with_raw_prefix")
    if pad_present:
        pad = _int(pad, "sample_pad", maximum=0xFF)
        if pad != raw_pad:
            raise ObservationError("pad_disagrees_with_raw_prefix")
    elif pad is not None:
        raise ObservationError("pad_value_without_presence")

    declared_present = _bool(sample.get("rtap_declared_len_present"),
                             "sample_declared_length_present")
    declared_len = sample.get("rtap_declared_len")
    raw_declared_present = len(prefix) >= 4
    raw_declared_len = (prefix[2] | (prefix[3] << 8)) if raw_declared_present else None
    if declared_present is not raw_declared_present:
        raise ObservationError("declared_length_presence_disagrees_with_raw_prefix")
    if declared_present:
        declared_len = _int(declared_len, "sample_declared_length", maximum=0xFFFF)
        if declared_len != raw_declared_len:
            raise ObservationError("declared_length_disagrees_with_raw_prefix")
    elif declared_len is not None:
        raise ObservationError("declared_length_value_without_presence")

    ifindex_present = _bool(sample.get("ifindex_present"), "sample_ifindex_present")
    ifindex = sample.get("ifindex")
    if ifindex_present:
        ifindex = _int(ifindex, "sample_ifindex", minimum=1, maximum=(1 << 31) - 1)
    elif ifindex is not None:
        raise ObservationError("ifindex_value_without_presence")

    bitmap_present = _bool(sample.get("present_bitmap_present"),
                           "sample_present_bitmap_present")
    bitmap_complete = _bool(sample.get("present_bitmap_complete"),
                            "sample_present_bitmap_complete")
    bitmap_overflow = _bool(sample.get("present_bitmap_capacity_exceeded"),
                             "sample_present_bitmap_capacity_exceeded")
    word_count = _int(sample.get("present_word_count"), "sample_present_word_count",
                      maximum=8)
    words = sample.get("present_words")
    if not isinstance(words, list) or len(words) != word_count:
        raise ObservationError("present_bitmap_word_count_mismatch")
    words = [_int(word, "sample_present_word", maximum=0xFFFFFFFF)
             for word in words]
    raw_bitmap_present = len(prefix) >= 8
    if bitmap_present is not raw_bitmap_present:
        raise ObservationError("present_bitmap_presence_disagrees_with_raw_prefix")
    raw_words: list[int] = []
    raw_bitmap_complete = False
    raw_bitmap_overflow = False
    if raw_bitmap_present:
        offset = 4
        while offset + 4 <= len(prefix) and len(raw_words) < 8:
            word = int.from_bytes(prefix[offset:offset + 4], "little")
            raw_words.append(word)
            offset += 4
            if (word & 0x80000000) == 0:
                raw_bitmap_complete = True
                break
        if len(raw_words) == 8 and raw_words[-1] & 0x80000000:
            raw_bitmap_overflow = True
    if words != raw_words:
        raise ObservationError("present_words_disagree_with_raw_prefix")
    if bitmap_complete is not raw_bitmap_complete:
        raise ObservationError("present_bitmap_complete_disagrees_with_raw_prefix")
    if bitmap_overflow is not raw_bitmap_overflow:
        raise ObservationError("present_bitmap_capacity_disagrees_with_raw_prefix")
    if not bitmap_present and (word_count != 0 or bitmap_complete):
        raise ObservationError("present_bitmap_metadata_without_presence")
    if bitmap_complete and (not bitmap_present or bitmap_overflow):
        raise ObservationError("present_bitmap_complete_contradiction")
    if bitmap_overflow and bitmap_complete:
        raise ObservationError("present_bitmap_overflow_contradiction")

    reason = sample.get("reject_reason")
    if reason not in REJECT_REASONS:
        raise ObservationError("invalid_reject_reason")
    parse_reason = sample.get("radiotap_parse_reason")
    if parse_reason not in PARSE_REASONS:
        raise ObservationError("invalid_radiotap_parse_reason")
    packet_truncated = _bool(sample.get("packet_truncated"),
                             "sample_packet_truncated")
    if (reason == "packet_truncated") is not packet_truncated:
        raise ObservationError("packet_truncated_reason_mismatch")
    # Linux MSG_TRUNC is 0x20. A reported length beyond the supplied iovec or
    # MSG_TRUNC must never be represented as a complete copied packet.
    if received_len > copied_len or (msg_flags & 0x20):
        if not packet_truncated:
            raise ObservationError("truncation_metadata_missing")

    prefix_truncated = _bool(sample.get("raw_prefix_truncated"),
                             "sample_raw_prefix_truncated")
    if prefix_truncated is not (copied_len > prefix_len):
        raise ObservationError("raw_prefix_truncation_flag_mismatch")
    prefix_hash = _hash(sample.get("raw_prefix_sha256"), "raw_prefix_sha256")
    if hashlib.sha256(prefix).hexdigest() != prefix_hash:
        raise ObservationError("raw_prefix_sha256_mismatch")
    if ("classification" in sample and
            sample["classification"] != "rejected_prefix_unmatched"):
        raise ObservationError("rejected_prefix_classification_overclaim")

    # Prefix bytes are diagnostic only. They cannot support a full-MPDU hash,
    # a frame/target match, or a completion claim.
    for forbidden in ("exact_mpdu_match", "mpdu_sha256", "target_match",
                      "pid_cookie_tx_status_proven", "rf_transmission_proven",
                      "ack_proven", "peer_receipt_proven"):
        if forbidden in sample and sample[forbidden] not in (False, None):
            raise ObservationError("rejected_prefix_overclaim_" + forbidden)
    return {
        "packet_type_present": packet_type_present,
        "packet_type": packet_type,
        "ifindex_present": ifindex_present,
        "ifindex": ifindex,
        "msg_flags": msg_flags,
        "received_len": received_len,
        "copied_len": copied_len,
        "rtap_declared_len_present": declared_present,
        "rtap_declared_len": declared_len,
        "present_bitmap_present": bitmap_present,
        "present_bitmap_complete": bitmap_complete,
        "present_bitmap_capacity_exceeded": bitmap_overflow,
        "present_word_count": word_count,
        "present_words": words,
        "reject_reason": reason,
        "radiotap_parse_reason": parse_reason,
        "packet_truncated": packet_truncated,
        "raw_prefix_len": prefix_len,
        "raw_prefix_truncated": prefix_truncated,
        "raw_prefix_sha256": prefix_hash,
        "raw_header_fields": {
            "version_present": version_present,
            "version": version,
            "pad_present": pad_present,
            "pad": pad,
            "rtap_declared_len_present": declared_present,
            "rtap_declared_len": declared_len,
            "present_bitmap_present": bitmap_present,
            "present_bitmap_complete": bitmap_complete,
            "present_bitmap_capacity_exceeded": bitmap_overflow,
            "present_word_count": word_count,
            "present_words": words,
        },
        "classification": "rejected_prefix_unmatched",
        "full_packet_identity": "unknown",
        "rf_transmission_proven": False,
        "ack_proven": False,
        "peer_receipt_proven": False,
    }


def _classify_capture(capture: Any) -> dict[str, Any]:
    if not isinstance(capture, dict):
        raise ObservationError("capture_not_object")
    if capture.get("window") != "send_sequence_span":
        raise ObservationError("capture_window_invalid")
    if ("schema_contract" in capture and
            capture["schema_contract"] !=
            "capture_finished_is_execution_completion_not_full_budget_coverage"):
        raise ObservationError("capture_schema_contract_invalid")
    capture_status = capture.get("status")
    allowed_status = {
        "not_run_host_test", "not_started", "receive_error",
        "bounded_limit_reached", "bounded_during_send_sequence",
    }
    if capture_status not in allowed_status:
        raise ObservationError("capture_status_invalid")
    budget = _int(capture.get("budget_ns"), "capture_budget_ns",
                  minimum=1, maximum=MAX_CAPTURE_NS)
    start_raw, end_raw = capture.get("started_ns"), capture.get("ended_ns")
    finish_raw = capture.get("actual_finished_ns")
    if capture.get("window_cutoff_semantics") != WINDOW_CUTOFF_SEMANTICS:
        raise ObservationError("window_cutoff_semantics_invalid")
    if start_raw is None:
        if end_raw is not None or finish_raw is not None:
            raise ObservationError("capture_timestamp_without_start")
        start = end = actual_finished = None
    else:
        start = _int(start_raw, "capture_started_ns", maximum=MAX_U64)
        if start > MAX_U64 - budget:
            raise ObservationError("capture_deadline_overflow")
        if finish_raw is None:
            actual_finished = end = None
            if end_raw is not None:
                raise ObservationError("capture_cutoff_without_actual_finish")
        else:
            actual_finished = _int(finish_raw, "actual_finished_ns", maximum=MAX_U64)
            if actual_finished < start:
                raise ObservationError("capture_actual_finish_before_start")
            expected_cutoff = min(actual_finished, start + budget)
            end = _int(end_raw, "capture_cutoff_ns", maximum=MAX_U64)
            if end != expected_cutoff:
                raise ObservationError("capture_cutoff_mismatch")

    finished = _bool(capture.get("capture_finished"), "capture_finished")
    loss_free_input = capture.get("loss_free")
    if loss_free_input is not None and type(loss_free_input) is not bool:
        raise ObservationError("invalid_loss_free")
    coverage_input = capture.get("decoder_coverage")
    if coverage_input is not None and type(coverage_input) is not bool:
        raise ObservationError("invalid_decoder_coverage")

    counts = capture.get("decode_coverage")
    if not isinstance(counts, dict):
        raise ObservationError("decode_coverage_not_object")
    pre_send_drained = _int(capture.get("pre_send_drained_packets"),
                            "pre_send_drained_packets", maximum=MAX_CAPTURE_PACKETS * 2)
    pre_send_queue_empty = _bool(capture.get("pre_send_queue_empty"),
                                 "pre_send_queue_empty")
    if pre_send_queue_empty and pre_send_drained >= MAX_CAPTURE_PACKETS * 2:
        raise ObservationError("pre_send_empty_after_drain_cap_contradiction")
    count_fields = (
        "packet_received", "packet_decoded", "invalid_radiotap",
        "unsupported_radiotap", "truncated_packets", "fcs_bytes_missing",
        "rejected_radiotap_samples_recorded",
        "rejected_radiotap_sample_overflow",
    )
    values = {key: _int(counts.get(key), key, maximum=MAX_CAPTURE_PACKETS)
              for key in count_fields}
    kernel_stats = _bool(counts.get("kernel_stats_available"),
                         "kernel_stats_available")
    dropped_raw = counts.get("kernel_dropped_packets")
    if kernel_stats:
        dropped = _int(dropped_raw, "kernel_dropped_packets")
        kernel_packets = _int(counts.get("kernel_packets"), "kernel_packets")
        if counts.get("kernel_stats_error") is not None:
            raise ObservationError("kernel_stats_error_with_valid_stats")
    else:
        if dropped_raw is not None:
            raise ObservationError("kernel_drop_count_without_stats")
        dropped = None
        kernel_packets_raw = counts.get("kernel_packets")
        if kernel_packets_raw is not None:
            raise ObservationError("kernel_packet_count_without_stats")
        kernel_packets = None
        stats_error_raw = counts.get("kernel_stats_error")
        stats_error = (None if stats_error_raw is None else
                       _int(stats_error_raw, "kernel_stats_error",
                            minimum=1, maximum=(1 << 31) - 1))
    if kernel_stats:
        stats_error = None
    receive_error_raw = counts.get("receive_error")
    if receive_error_raw is None:
        receive_error = None
    else:
        receive_error = _int(receive_error_raw, "receive_error",
                             maximum=(1 << 31) - 1)
    limit_reached = _bool(counts.get("capture_limit_reached"),
                          "capture_limit_reached")

    category_sum = (values["packet_decoded"] + values["invalid_radiotap"] +
                    values["unsupported_radiotap"] + values["truncated_packets"])
    if category_sum != values["packet_received"]:
        raise ObservationError("packet_decode_categories_do_not_partition_received")
    if values["fcs_bytes_missing"] > values["invalid_radiotap"]:
        raise ObservationError("fcs_missing_count_exceeds_invalid_packets")

    if finished:
        if start is None or actual_finished is None or end is None:
            raise ObservationError("capture_finished_contradiction")
    elif actual_finished is not None:
        raise ObservationError("capture_finished_missing_actual_finish")
    if start is None and capture_status not in {"not_run_host_test", "not_started"}:
        raise ObservationError("capture_status_without_start")
    if start is not None and capture_status in {"not_run_host_test", "not_started"}:
        raise ObservationError("capture_started_status_mismatch")
    if capture_status == "receive_error" and receive_error in (None, 0):
        raise ObservationError("capture_error_status_mismatch")
    if capture_status == "bounded_limit_reached" and not limit_reached:
        raise ObservationError("capture_limit_status_mismatch")
    if capture_status == "bounded_during_send_sequence" and (
            receive_error not in (None, 0) or limit_reached):
        raise ObservationError("capture_bounded_status_mismatch")

    sample_list = capture.get("rejected_radiotap_samples")
    if not isinstance(sample_list, list):
        raise ObservationError("rejected_samples_not_list")
    recorded = values["rejected_radiotap_samples_recorded"]
    overflow = values["rejected_radiotap_sample_overflow"]
    if len(sample_list) != recorded or len(sample_list) > MAX_REJECT_SAMPLES:
        raise ObservationError("rejected_sample_record_count_mismatch")
    if overflow and len(sample_list) != MAX_REJECT_SAMPLES:
        raise ObservationError("rejected_sample_overflow_without_full_sample_buffer")
    rejected_packet_count = (values["invalid_radiotap"] +
                             values["unsupported_radiotap"] +
                             values["truncated_packets"])
    if recorded + overflow != rejected_packet_count:
        raise ObservationError("rejected_sample_count_does_not_match_rejected_packets")
    checked_samples = [_validate_rejected_sample(sample) for sample in sample_list]

    decoder_coverage = None if values["packet_received"] == 0 else (
        values["packet_decoded"] == values["packet_received"] and
        values["invalid_radiotap"] == 0 and
        values["unsupported_radiotap"] == 0 and
        values["truncated_packets"] == 0 and overflow == 0
    )
    if coverage_input is not decoder_coverage:
        raise ObservationError("decoder_coverage_does_not_match_counts")

    loss_event = ((dropped is not None and dropped > 0) or
                  values["truncated_packets"] > 0 or overflow > 0 or
                  receive_error not in (None, 0) or limit_reached)
    if loss_event or (start is not None and not finished):
        expected_loss_free = False
    elif not kernel_stats:
        expected_loss_free = None
    elif start is None:
        expected_loss_free = None
    else:
        expected_loss_free = True
    if loss_free_input is not expected_loss_free:
        raise ObservationError("loss_free_does_not_match_capture_evidence")
    raw_horizon = capture.get("actual_horizon_ns")
    expected_horizon = (None if start is None or actual_finished is None else
                        actual_finished - start)
    if raw_horizon is not None:
        raw_horizon = _int(raw_horizon, "actual_horizon_ns", maximum=MAX_U64)
    if raw_horizon != expected_horizon:
        raise ObservationError("actual_horizon_mismatch")

    return {
        "window": "send_sequence_span",
        "budget_ns": budget,
        "started_ns": start,
        "ended_ns": end,
        "window_cutoff_semantics": WINDOW_CUTOFF_SEMANTICS,
        "actual_finished_ns": actual_finished,
        "actual_horizon_ns": expected_horizon,
        "capture_finished": finished,
        "status": capture_status,
        "loss_free": expected_loss_free,
        "decoder_coverage": decoder_coverage,
        "pre_send_drained_packets": pre_send_drained,
        "pre_send_queue_empty": pre_send_queue_empty,
        "invocation_correlation": (
            "bounded_clean_queue_candidate" if pre_send_queue_empty else
            "ambiguous_pre_send_queue"),
        "decode_coverage": {**values,
                             "kernel_dropped_packets": dropped,
                             "kernel_stats_available": kernel_stats,
                             "kernel_packets": kernel_packets,
                             "kernel_stats_error": stats_error,
                             "receive_error": receive_error,
                             "capture_limit_reached": limit_reached},
        "rejected_samples": checked_samples,
    }


def classify_sender_result(sender_result: dict[str, Any]) -> dict[str, Any]:
    """Classify one new-schema SENDER_RESULT without upgrading it to RF proof."""
    if not isinstance(sender_result, dict) or sender_result.get("event") != "SENDER_RESULT":
        raise ObservationError("sender_result_invalid")
    if sender_result.get("tx_flags_requested") != TX_FLAGS_REQUESTED:
        raise ObservationError("sender_tx_flags_contract_invalid")
    if sender_result.get("hardware_honoring") != "unknown":
        raise ObservationError("hardware_honoring_must_remain_unknown")

    provenance = sender_result.get("tx_provenance")
    if not isinstance(provenance, dict):
        raise ObservationError("tx_provenance_missing")
    schema = provenance.get("schema")
    if schema == LEGACY_SCHEMA:
        raise ObservationError("legacy_schema_requires_new_capture")
    if schema != SCHEMA:
        raise ObservationError("tx_provenance_schema_invalid")

    send_rows = sender_result.get("send_timing")
    if not isinstance(send_rows, list) or len(send_rows) > MAX_FRAMES:
        raise ObservationError("send_timing_invalid")
    expected_hashes: dict[int, str] = {}
    accepted: dict[int, bool] = {}
    for expected_ordinal, row in enumerate(send_rows):
        if not isinstance(row, dict):
            raise ObservationError("send_timing_row_invalid")
        ordinal = _int(row.get("ordinal"), "send_ordinal", maximum=MAX_FRAMES - 1)
        if ordinal != expected_ordinal:
            raise ObservationError("send_timing_order_invalid")
        digest = _hash(row.get("mpdu_sha256"), "send_mpdu_sha256")
        wifi = _int(row.get("ieee80211_sequence"), "send_wifi_sequence", maximum=0x0FFF)
        awdl = _int(row.get("awdl_sequence"), "send_awdl_sequence", maximum=0xFFFF)
        if (wifi, awdl) != _expected_sequences(ordinal):
            raise ObservationError("send_frame_identity_mismatch")
        returned = row.get("return_bytes")
        if type(returned) is not int or returned < -1 or returned > 106:
            raise ObservationError("send_return_bytes_invalid")
        err = _int(row.get("errno"), "send_errno")
        if returned >= 0 and err != 0:
            raise ObservationError("send_errno_contradiction")
        if returned == -1 and err == 0:
            raise ObservationError("send_errno_missing")
        expected_hashes[ordinal] = digest
        accepted[ordinal] = returned == 106 and err == 0
    attempted = _int(sender_result.get("frames_attempted"), "frames_attempted",
                     maximum=MAX_FRAMES)
    completed = _int(sender_result.get("frames_completed"), "frames_completed",
                     maximum=MAX_FRAMES)
    if attempted != len(send_rows) or completed != sum(accepted.values()):
        raise ObservationError("send_count_mismatch")

    for claim in ("rf_transmission_proven", "ack_proven", "peer_receipt_proven"):
        if _bool(provenance.get(claim), claim) is not False:
            raise ObservationError("sender_overclaim_" + claim)
    if provenance.get("pid_cookie_bound_tx_status") != "unknown":
        raise ObservationError("sender_cannot_claim_pid_cookie_tx_status")
    if _bool(provenance.get("pid_cookie_status_source_available"),
             "pid_cookie_status_source_available") is not False:
        raise ObservationError("sender_has_no_pid_cookie_status_source")
    if provenance.get("tx_status_path") != "not_observed":
        raise ObservationError("tx_status_path_must_remain_unobserved")
    if provenance.get("tx_status_pid") is not None:
        raise ObservationError("runtime_tx_status_pid_must_remain_unknown")
    if provenance.get("tx_status_cookie") is not None:
        raise ObservationError("runtime_tx_status_cookie_must_remain_unknown")
    if provenance.get("pid_txs_expectation") != "unknown":
        raise ObservationError("runtime_pid_txs_expectation_must_remain_unknown")
    if "tx_status_events" in provenance and provenance["tx_status_events"]:
        raise ObservationError("tx_status_event_source_not_integrated")
    if _bool(provenance.get("run_nonce_is_local_only"),
             "run_nonce_is_local_only") is not True:
        raise ObservationError("run_nonce_scope_invalid")
    if _bool(provenance.get("nonce_in_mpdu"), "nonce_in_mpdu") is not False:
        raise ObservationError("nonce_must_not_be_claimed_in_mpdu")
    fixture_mode = provenance.get("fixture_mode")
    if fixture_mode not in (None, "synthetic_host_fixture"):
        raise ObservationError("unknown_fixture_mode")
    capture = _classify_capture(provenance.get("capture"))
    evidence_scope = ("synthetic" if fixture_mode == "synthetic_host_fixture" else
                      ("runtime_capture_record" if capture["started_ns"] is not None
                       else "local_sender_record_no_capture"))
    rows = provenance.get("observations")
    if not isinstance(rows, list) or len(rows) > MAX_OBSERVATIONS:
        raise ObservationError("observations_invalid")
    if len(rows) > capture["decode_coverage"]["packet_received"]:
        raise ObservationError("observation_count_exceeds_received_packets")
    if len(rows) > capture["decode_coverage"]["packet_decoded"]:
        raise ObservationError("observation_count_exceeds_decoded_packets")
    observations = [_classify_full_observation(row) for row in rows]
    for row in observations:
        if capture["started_ns"] is None or capture["ended_ns"] is None:
            raise ObservationError("observation_without_capture_window")
        if not capture["started_ns"] <= row["observed_ns"] <= capture["ended_ns"]:
            raise ObservationError("observation_outside_capture_window")
        ordinal = row["ordinal"]
        if ordinal not in expected_hashes:
            raise ObservationError("observation_without_send_row")
        if row["mpdu_sha256"] != expected_hashes[ordinal]:
            raise ObservationError("observation_full_mpdu_hash_mismatch")
        row["invocation_bound"] = False
        row["invocation_correlation"] = capture["invocation_correlation"]

    per_frame = []
    for ordinal, digest in sorted(expected_hashes.items()):
        frame_rows = [row for row in observations if row["ordinal"] == ordinal]
        per_frame.append({
            "ordinal": ordinal,
            "mpdu_sha256": digest,
            "local_send_accepted": accepted[ordinal],
            "packet_outgoing_echo_count": sum(
                row["classification"] == "packet_outgoing_echo" for row in frame_rows),
            "completion_copy_candidate_count": sum(
                row["classification"] == "generated_tx_completion_copy_candidate"
                for row in frame_rows),
            "other_exact_frame_count": sum(
                row["classification"] == "exact_frame_match_unclassified"
                for row in frame_rows),
            "pid_cookie_tx_status": "unknown",
            "invocation_bound": False,
            "invocation_correlation": capture["invocation_correlation"],
            "rf_transmission_proven": False,
            "ack_proven": False,
            "peer_receipt_proven": False,
        })

    return {
        "schema": "openwrt-tx-observation-summary/v1",
        "fixture_mode": fixture_mode,
        "evidence_scope": evidence_scope,
        "send": {
            "frames_attempted": attempted,
            "frames_completed": completed,
            "local_send_accepted": sum(accepted.values()),
            "hardware_honoring": "unknown",
        },
        "capture": capture,
        "observations": observations,
        "frames": per_frame,
        "pid_cookie_bound_tx_status": "unknown",
        "pid_cookie_status_source_available": False,
        "tx_status_path": "not_observed",
        "tx_status_pid": None,
        "tx_status_cookie": None,
        "runtime_pid_txs_expectation": "unknown",
        "conditional_pid_txs_expectation": "not_requested_by_reviewed_noack_path",
        "conditional_pid_txs_expectation_basis": "offline_reviewed_noack_path_contract_not_runtime_observation",
        "conditional_pid_txs_expectation_review": {
            "report_sha256": "2365707a9cd91031e20902b13784bd0ad6e07b2a7c90b0a7e468cdabd123c0da",
            "reviewed_module_sha256_prefix": "8f301a5c",
            "runtime_path_observed": False,
        },
        "status_sources": {
            "software_txfree": "not_collected",
            "timeout_generated_ack": "not_collected",
            "raw_hardware_txs": "not_collected",
        },
        "rf_transmission_proven": False,
        "ack_proven": False,
        "peer_receipt_proven": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="saved sender JSON; read only")
    parser.add_argument("--output", type=Path, help="write summary JSON")
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        summary = classify_sender_result(data)
    except (OSError, json.JSONDecodeError, ObservationError) as exc:
        print(f"ERROR:{exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
