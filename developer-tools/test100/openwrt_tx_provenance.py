#!/usr/bin/env python3
"""Conservatively classify Test100 OpenWrt TX provenance records.

This module performs no network or hardware access. It only classifies a
bounded sender result that was already collected by the Test100 AF_PACKET
sender. Packet-socket echoes and mac80211 completion-shaped copies are kept
separate from a per-frame PID/cookie-bound TX status record.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "test100-openwrt-tx-provenance/v1"
SUMMARY_SCHEMA = "test100-openwrt-tx-provenance-summary/v1"
MAX_FRAMES = 4
MAX_OBSERVATIONS = 16
MPDU_BYTES = 96
PACKET_BYTES = 106
PACKET_OTHERHOST = 3
PACKET_OUTGOING = 4
TX_FLAGS_REQUESTED = "NOACK|NOSEQNO"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class ProvenanceError(ValueError):
    """Malformed or contradictory provenance evidence."""


def _int(value: Any, field: str, *, minimum: int = 0,
         maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum:
        raise ProvenanceError("invalid_" + field)
    if maximum is not None and value > maximum:
        raise ProvenanceError("invalid_" + field)
    return value


def _bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ProvenanceError("invalid_" + field)
    return value


def _expected_frame_identity(ordinal: int) -> tuple[int, int]:
    return (291 + ordinal) & 0x0FFF, (34305 + ordinal) & 0xFFFF


def classify_observation(row: dict[str, Any]) -> dict[str, Any]:
    """Classify one exact monitor observation without upgrading it to RF proof."""
    if not isinstance(row, dict):
        raise ProvenanceError("observation_not_object")
    ordinal = _int(row.get("ordinal"), "ordinal", maximum=MAX_FRAMES - 1)
    packet_type = _int(row.get("packet_type"), "packet_type", maximum=7)
    if _bool(row.get("exact_mpdu_match"), "exact_mpdu_match") is not True:
        raise ProvenanceError("observation_not_exact_match")
    digest = row.get("mpdu_sha256")
    if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
        raise ProvenanceError("invalid_mpdu_sha256")
    wifi_sequence = _int(row.get("wifi_sequence"), "wifi_sequence", maximum=0x0FFF)
    awdl_sequence = _int(row.get("awdl_sequence"), "awdl_sequence", maximum=0xFFFF)
    if (wifi_sequence, awdl_sequence) != _expected_frame_identity(ordinal):
        raise ProvenanceError("frame_identity_mismatch")
    observed_ns = _int(row.get("observed_ns"), "observed_ns")
    has_tx_flags = _bool(row.get("has_tx_flags"), "has_tx_flags")
    tx_flags = _int(row.get("tx_flags"), "tx_flags", maximum=0xFFFF)
    has_data_retries = _bool(row.get("has_data_retries"), "has_data_retries")
    data_retries = _int(row.get("data_retries"), "data_retries", maximum=0xFF)
    if not has_tx_flags and tx_flags != 0:
        raise ProvenanceError("tx_flags_present_without_field")
    if not has_data_retries and data_retries != 0:
        raise ProvenanceError("data_retries_present_without_field")

    if packet_type == PACKET_OUTGOING:
        classification = "packet_outgoing_echo"
    elif (packet_type == PACKET_OTHERHOST and has_tx_flags and
          has_data_retries):
        classification = "generated_tx_completion_copy_candidate"
    else:
        classification = "exact_frame_match_unclassified"
    if row.get("classification", classification) != classification:
        raise ProvenanceError("sender_observation_classification_mismatch")
    for claim in ("pid_cookie_tx_status_proven", "rf_transmission_proven",
                  "peer_receipt_proven", "ack_proven"):
        if claim in row and row[claim] is not False:
            raise ProvenanceError("observation_overclaim_" + claim)

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
        "has_data_retries": has_data_retries,
        "data_retries": data_retries,
        "tx_status_proven": False,
        "rf_transmission_proven": False,
        "peer_receipt_proven": False,
        "ack_proven": False,
    }


def classify_sender_result(sender_result: dict[str, Any]) -> dict[str, Any]:
    """Return bounded provenance levels from a Test100 SENDER_RESULT object."""
    if not isinstance(sender_result, dict) or sender_result.get("event") != "SENDER_RESULT":
        raise ProvenanceError("sender_result_invalid")
    if sender_result.get("tx_flags_requested") != TX_FLAGS_REQUESTED:
        raise ProvenanceError("sender_tx_flags_contract_invalid")
    if sender_result.get("hardware_honoring") != "unknown":
        raise ProvenanceError("sender_hardware_honoring_must_remain_unknown")

    timing = sender_result.get("send_timing")
    if not isinstance(timing, list) or len(timing) > MAX_FRAMES:
        raise ProvenanceError("send_timing_invalid")
    local_send: dict[int, bool] = {}
    expected_hashes: dict[int, str] = {}
    for expected_ordinal, item in enumerate(timing):
        if not isinstance(item, dict):
            raise ProvenanceError("send_timing_row_invalid")
        ordinal = _int(item.get("ordinal"), "send_ordinal", maximum=MAX_FRAMES - 1)
        if ordinal != expected_ordinal:
            raise ProvenanceError("send_timing_order_invalid")
        digest = item.get("mpdu_sha256")
        if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
            raise ProvenanceError("send_timing_hash_invalid")
        wifi_sequence = _int(item.get("ieee80211_sequence"),
                             "send_wifi_sequence", maximum=0x0FFF)
        awdl_sequence = _int(item.get("awdl_sequence"),
                             "send_awdl_sequence", maximum=0xFFFF)
        if (wifi_sequence, awdl_sequence) != _expected_frame_identity(ordinal):
            raise ProvenanceError("send_frame_identity_mismatch")
        returned = item.get("return_bytes")
        if type(returned) is not int or returned < -1 or returned > PACKET_BYTES:
            raise ProvenanceError("send_return_invalid")
        err = _int(item.get("errno"), "send_errno")
        if returned >= 0 and err != 0:
            raise ProvenanceError("send_errno_contradiction")
        if returned == -1 and err == 0:
            raise ProvenanceError("send_errno_missing")
        local_send[ordinal] = returned == PACKET_BYTES and err == 0
        expected_hashes[ordinal] = digest
    if _int(sender_result.get("frames_attempted"),
            "frames_attempted", maximum=MAX_FRAMES) != len(timing):
        raise ProvenanceError("send_attempt_count_mismatch")
    if _int(sender_result.get("frames_completed"),
            "frames_completed", maximum=MAX_FRAMES) != sum(local_send.values()):
        raise ProvenanceError("send_completed_count_mismatch")

    provenance = sender_result.get("tx_provenance")
    if not isinstance(provenance, dict):
        raise ProvenanceError("tx_provenance_missing")
    if provenance.get("schema") != SCHEMA:
        raise ProvenanceError("tx_provenance_schema_invalid")
    capture = provenance.get("capture")
    if not isinstance(capture, dict):
        raise ProvenanceError("capture_invalid")
    if capture.get("window") != "send_sequence_span":
        raise ProvenanceError("capture_window_invalid")
    budget_ns = _int(capture.get("budget_ns"), "capture_budget_ns", maximum=40_000_000)
    capture_status = capture.get("status")
    not_captured = capture_status in {"not_run_host_test", "not_started"}
    if not_captured:
        if capture.get("started_ns") is not None or capture.get("ended_ns") is not None:
            raise ProvenanceError("not_captured_timestamp_present")
        start_ns = end_ns = None
    else:
        start_ns = _int(capture.get("started_ns"), "capture_started_ns")
        end_ns = _int(capture.get("ended_ns"), "capture_ended_ns")
        if end_ns < start_ns:
            raise ProvenanceError("capture_time_order_invalid")
        if end_ns - start_ns > budget_ns:
            raise ProvenanceError("capture_window_exceeded_budget")
    rx_packets = _int(capture.get("rx_packets"), "rx_packets",
                      maximum=128)
    dropped_packets = _int(capture.get("dropped_packets"), "dropped_packets")
    _int(capture.get("kernel_packets"), "kernel_packets")
    receive_error = _int(capture.get("receive_error"), "receive_error")
    if dropped_packets > capture["kernel_packets"]:
        raise ProvenanceError("drop_count_exceeds_kernel_packet_count")
    _int(capture.get("pre_send_drained_packets"), "pre_send_drained_packets")
    pre_send_drained = _bool(capture.get("pre_send_queue_empty"),
                              "pre_send_queue_empty")
    capture_complete = _bool(capture.get("complete"), "capture_complete")
    capture_limited = _bool(capture.get("limit_reached"), "capture_limit_reached")
    if capture_complete and capture_limited:
        raise ProvenanceError("complete_capture_cannot_be_limited")
    if capture_status not in {
            "bounded_during_send_sequence", "bounded_limit_reached",
            "receive_error", "not_started", "not_run_host_test"}:
        raise ProvenanceError("capture_status_invalid")
    if capture_status == "bounded_limit_reached" and not capture_limited:
        raise ProvenanceError("capture_limit_status_mismatch")
    if capture_status == "receive_error" and receive_error == 0:
        raise ProvenanceError("capture_error_status_mismatch")
    if _bool(provenance.get("run_nonce_is_local_only"),
             "run_nonce_is_local_only") is not True:
        raise ProvenanceError("run_nonce_scope_invalid")
    if _bool(provenance.get("nonce_in_mpdu"), "nonce_in_mpdu") is not False:
        raise ProvenanceError("nonce_must_not_be_claimed_in_mpdu")
    if provenance.get("pid_cookie_bound_tx_status") != "unknown":
        raise ProvenanceError("raw_afpacket_capture_cannot_claim_pid_cookie_txs")
    if _bool(provenance.get("pid_cookie_status_source_available"),
             "pid_cookie_status_source_available") is not False:
        raise ProvenanceError("afpacket_capture_has_no_pid_cookie_txs_source")
    _bool(provenance.get("rf_transmission_proven"),
          "rf_transmission_proven")
    if provenance["rf_transmission_proven"] is not False:
        raise ProvenanceError("sender_cannot_prove_rf_transmission")
    _bool(provenance.get("peer_receipt_proven"), "peer_receipt_proven")
    if provenance["peer_receipt_proven"] is not False:
        raise ProvenanceError("sender_cannot_prove_peer_receipt")
    _bool(provenance.get("ack_proven"), "ack_proven")
    if provenance["ack_proven"] is not False:
        raise ProvenanceError("noack_probe_cannot_claim_ack")
    if not isinstance(provenance.get("observations"), list):
        raise ProvenanceError("observations_invalid")
    raw_observations = provenance["observations"]
    if len(raw_observations) > MAX_OBSERVATIONS:
        raise ProvenanceError("observation_count_exceeds_limit")
    if len(raw_observations) > rx_packets:
        raise ProvenanceError("observation_count_exceeds_rx_packets")
    observations = [classify_observation(row) for row in raw_observations]
    for row in observations:
        if (start_ns is None or end_ns is None or
                row["observed_ns"] < start_ns or row["observed_ns"] > end_ns):
            raise ProvenanceError("observation_outside_capture_window")
        if row["ordinal"] not in expected_hashes:
            raise ProvenanceError("observation_without_send_row")
        if row["mpdu_sha256"] != expected_hashes[row["ordinal"]]:
            raise ProvenanceError("observation_hash_mismatch")

    frames = []
    for ordinal in sorted(local_send):
        rows = [row for row in observations if row["ordinal"] == ordinal]
        outgoing = sum(row["classification"] == "packet_outgoing_echo" for row in rows)
        completion = sum(
            row["classification"] == "generated_tx_completion_copy_candidate"
            for row in rows)
        exact_other = sum(
            row["classification"] == "exact_frame_match_unclassified"
            for row in rows)
        frames.append({
            "ordinal": ordinal,
            "mpdu_sha256": expected_hashes[ordinal],
            "local_send_accepted": local_send[ordinal],
            "packet_outgoing_echo_count": outgoing,
            "generated_tx_completion_copy_candidate_count": completion,
            "other_exact_frame_match_count": exact_other,
            "pid_cookie_bound_tx_status": "unknown",
            "pid_cookie_tx_status_proven": False,
            "tx_status_unknown_reason": "no_pid_cookie_bound_txs_source_collected",
            "invocation_binding": (
                "not_captured" if not_captured else
                "ambiguous_pre_send_queue_not_empty" if not pre_send_drained else
                "exact_frame_and_time_only_nonce_not_in_mpdu"),
            "rf_transmission_proven": False,
            "peer_receipt_proven": False,
            "ack_proven": False,
        })

    return {
        "schema": SUMMARY_SCHEMA,
        "capture_complete": capture_complete,
        "capture_limit_reached": capture_limited,
        "frames": frames,
        "counts": {
            "local_send_accepted": sum(1 for row in frames if row["local_send_accepted"]),
            "packet_outgoing_echoes": sum(row["packet_outgoing_echo_count"] for row in frames),
            "generated_tx_completion_copy_candidates": sum(
                row["generated_tx_completion_copy_candidate_count"] for row in frames),
            "pid_cookie_bound_tx_statuses": 0,
            "unbound_or_ambiguous_status_records": 0,
        },
        "pid_cookie_bound_tx_status": "unknown",
        "tx_flags_zero_is_success": False,
        "data_retries_zero_is_success": False,
        "requested_noack_is_ack_evidence": False,
        "rf_transmission_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path,
                        help="local JSON file containing a saved SENDER_RESULT")
    args = parser.parse_args()
    if args.input is None:
        print(json.dumps({"mode": "plan", "schema": SUMMARY_SCHEMA,
                          "network_access": False, "rf_triggered": False,
                          "default_action": "none"}, indent=2))
        return 0
    try:
        sender_result = json.loads(args.input.read_text(encoding="utf-8"))
        summary = classify_sender_result(sender_result)
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"status": "invalid", "error": str(error)},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
