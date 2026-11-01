#!/usr/bin/env python3
"""Fail-closed, address-free correlation for GTK key-command evidence.

The input is a stable Test103-format HCTX snapshot plus the same IOKit read's
STA-auth trace. This module only associates host command metadata and local
driver events. It never infers firmware key installation, radio transmission,
peer acceptance, or a causal reason for disconnection.
"""
from __future__ import annotations

from typing import Any

COMMAND_ID_ADD_STA_KEY = 0x17
COMMAND_GROUP_LONG = 1
COMMAND_QUEUE_ID = 0

SOURCE_HOST_COMMAND = 1
SOURCE_COMMAND_RESPONSE_QUEUE = 2

PHASE_COMMAND_SUBMITTED = 1
PHASE_COMMAND_SUBMIT_FAILED = 2
PHASE_RX_VALIDATED = 5
PHASE_RX_RESPONSE_COPIED = 6
PHASE_RX_RESPONSE_NO_BUFFER = 7
PHASE_RX_RESPONSE_REJECTED = 8
PHASE_RX_DISPATCH_COMPLETED = 9
PHASE_COMMAND_RETIRED = 11

FLAG_HEADER_FIELDS_PRESENT = 1 << 4
FLAG_FIRMWARE_STATUS_PRESENT = 1 << 10
FLAG_FIRMWARE_STATUS_UNAVAILABLE = 1 << 11
FLAG_COMMAND_RESPONSE_FAILED = 1 << 12

AUTH_KIND_GROUP1_BEGIN = 1
AUTH_KIND_KEY_SUBMIT = 4
AUTH_KIND_GROUP2_RESULT = 5
AUTH_KIND_RX_DEAUTH = 6
AUTH_STAGE_KEY_CALLBACK = 13
AUTH_STAGE_GROUP2_OUTPUT = 14
AUTH_COMPONENT_GTK = 1
AUTH_SOURCE_HAL_COMMAND = 4
AUTH_SUBMIT_LOCAL_ENQUEUE = 2
AUTH_FLAG_DOORBELL_ISSUED = 1 << 6
AUTH_FLAG_REPLAY_CHECKED = 1 << 12
AUTH_FLAG_REPLAY_EQUAL = 1 << 13
AUTH_FLAG_REPLAY_MISMATCH = 1 << 14

RX_RESPONSE_PHASES = frozenset({
    PHASE_RX_VALIDATED,
    PHASE_RX_RESPONSE_COPIED,
    PHASE_RX_RESPONSE_NO_BUFFER,
    PHASE_RX_RESPONSE_REJECTED,
    PHASE_RX_DISPATCH_COMPLETED,
    PHASE_COMMAND_RETIRED,
})


def _is_uint(value: Any, bits: int) -> bool:
    return type(value) is int and 0 <= value < (1 << bits)


def _valid_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    widths = {
        "serial": 64,
        "driver_monotonic_ns": 64,
        "driver_generation": 32,
        "firmware_generation": 32,
        "phase": 32,
        "source": 32,
        "command_id": 32,
        "group_id": 32,
        "version": 32,
        "qid": 32,
        "index": 32,
        "header_sequence": 32,
        "flags": 32,
        "result": 32,
        "result_detail": 32,
        "packet_length": 32,
        "payload_length": 32,
        "reserved": 32,
    }
    return (all(_is_uint(row.get(name), bits) for name, bits in widths.items()) and
            row["serial"] != 0 and row["reserved"] == 0)


def _row_identity(row: dict) -> tuple[int, int, int, int]:
    return (row["driver_generation"], row["qid"], row["index"],
            row["command_id"])


def _is_key_command(row: dict) -> bool:
    return (row["command_id"] == COMMAND_ID_ADD_STA_KEY and
            row["qid"] == COMMAND_QUEUE_ID and
            row["driver_generation"] != 0 and
            row["index"] <= 0xFF and
            row["group_id"] == COMMAND_GROUP_LONG and
            bool(row["flags"] & FLAG_HEADER_FIELDS_PRESENT))


def _is_key_response(row: dict) -> bool:
    # Raw RX phases preserve pkt.hdr.group_id (group 1 or failed 0x41).
    # CommandRetired is synthesized from the already-normalized wide code and
    # therefore publishes group 0. Keep that phase-specific distinction.
    group_valid = (
        row["group_id"] == 0 if row["phase"] == PHASE_COMMAND_RETIRED else
        row["group_id"] in (COMMAND_GROUP_LONG, COMMAND_GROUP_LONG | 0x40)
    )
    return (row["command_id"] == COMMAND_ID_ADD_STA_KEY and
            row["qid"] == COMMAND_QUEUE_ID and
            row["driver_generation"] != 0 and row["index"] <= 0xFF and
            group_valid and
            bool(row["flags"] & FLAG_HEADER_FIELDS_PRESENT))


def _valid_auth_event(event: Any) -> bool:
    if not isinstance(event, dict):
        return False
    unsigned = {
        "sequence": 32,
        "monotonic_us": 64,
        "diagnostic_instance": 32,
        "driver_generation": 32,
        "association_id": 32,
        "attempt_id": 32,
        "kind": 16,
        "stage": 16,
        "component": 16,
        "source": 16,
        "flags": 32,
        "detail": 32,
    }
    if not all(_is_uint(event.get(name), bits)
               for name, bits in unsigned.items()):
        return False
    result = event.get("result")
    return type(result) is int and -(1 << 31) <= result < (1 << 31)


def _replay_relation(flags: int) -> str:
    checked = bool(flags & AUTH_FLAG_REPLAY_CHECKED)
    equal = bool(flags & AUTH_FLAG_REPLAY_EQUAL)
    mismatch = bool(flags & AUTH_FLAG_REPLAY_MISMATCH)
    if equal and mismatch:
        return "contradictory_flags"
    if not checked and (equal or mismatch):
        return "contradictory_flags"
    if not checked:
        return "not_recorded"
    return "equal" if equal else "mismatch" if mismatch else "checked_relation_unknown"


def _decode_key_submit_detail(detail: int) -> tuple[int, int, int]:
    state = (detail >> 24) & 0xFF
    qid = (detail >> 16) & 0xFF
    index = detail & 0xFFFF
    return state, qid, index


def correlate_key_lifecycle(hcmd_decoded: Any, auth_snapshot: Any) -> dict:
    """Correlate GTK callback -> host command -> RX response -> same-assoc RX deauth.

    A response is only attached when command ID, qid, index, driver generation,
    serial ordering, and a stable complete HCTX cut agree. The 8-bit ring slot
    tuple is not a firmware transaction ID; missing, truncated, reused, or
    conflicting evidence stays unknown.
    """
    if not isinstance(hcmd_decoded, dict):
        return {"status": "hcmd_sample_unavailable", "lifecycles": []}
    header = hcmd_decoded.get("header")
    rows = hcmd_decoded.get("rows")
    if (hcmd_decoded.get("snapshot_stable") is not True or
            hcmd_decoded.get("snapshot_complete") is not True or
            not isinstance(header, dict) or not isinstance(rows, list)):
        return {"status": "hcmd_cut_unstable_or_incomplete", "lifecycles": []}
    if not isinstance(auth_snapshot, dict) or auth_snapshot.get("snapshot_status") != "stable":
        return {"status": "auth_snapshot_unavailable", "lifecycles": []}

    checked_rows: list[dict] = []
    previous_serial = 0
    for row in rows:
        if not _valid_row(row) or row["serial"] <= previous_serial:
            return {"status": "hcmd_rows_invalid_or_unordered", "lifecycles": []}
        previous_serial = row["serial"]
        checked_rows.append(row)

    events = auth_snapshot.get("events")
    if not isinstance(events, list):
        return {"status": "auth_events_unavailable", "lifecycles": []}
    previous_auth_sequence = 0
    for event in events:
        if (not _valid_auth_event(event) or
                event["sequence"] <= previous_auth_sequence):
            return {"status": "auth_event_invalid", "lifecycles": []}
        previous_auth_sequence = event["sequence"]

    key_submits = []
    for event in events:
        if (event.get("kind") != AUTH_KIND_KEY_SUBMIT or
                event.get("stage") != AUTH_STAGE_KEY_CALLBACK or
                event.get("component") != AUTH_COMPONENT_GTK or
                event.get("source") != AUTH_SOURCE_HAL_COMMAND):
            continue
        detail = event.get("detail")
        if not _is_uint(detail, 32):
            continue
        state, qid, index = _decode_key_submit_detail(detail)
        if (state != AUTH_SUBMIT_LOCAL_ENQUEUE or qid != COMMAND_QUEUE_ID or
                index > 0xFF or not (event.get("flags", 0) & AUTH_FLAG_DOORBELL_ISSUED)):
            continue
        generation = event.get("driver_generation")
        association = event.get("association_id")
        attempt = event.get("attempt_id")
        monotonic_us = event.get("monotonic_us")
        sequence = event.get("sequence")
        if (not _is_uint(generation, 32) or generation == 0 or
                not _is_uint(association, 32) or association == 0 or
                not _is_uint(attempt, 32) or attempt == 0 or
                not _is_uint(monotonic_us, 64) or not _is_uint(sequence, 32)):
            continue
        key_submits.append({
            "attempt_id": attempt,
            "association_id": association,
            "driver_generation": generation,
            "auth_sequence": sequence,
            "auth_monotonic_us": monotonic_us,
            "qid": qid,
            "index": index,
            "callback_result": event.get("result"),
            "local_enqueue_observed": True,
        })

    if not key_submits:
        return {
            "status": "no_eligible_group_key_local_enqueue_in_auth_cut",
            "lifecycles": [],
            "key_install_success_proven": False,
            "peer_ack_proven": False,
        }

    all_host_submits = [row for row in checked_rows
        if row["source"] == SOURCE_HOST_COMMAND and
        row["phase"] in (PHASE_COMMAND_SUBMITTED, PHASE_COMMAND_SUBMIT_FAILED)]
    candidate_host_submits = [row for row in all_host_submits
        if _is_key_command(row) and row["phase"] == PHASE_COMMAND_SUBMITTED]
    response_rows = [row for row in checked_rows
        if _is_key_response(row) and row["source"] == SOURCE_COMMAND_RESPONSE_QUEUE and
        row["phase"] in RX_RESPONSE_PHASES]

    lifecycles: list[dict] = []
    for key_event in key_submits:
        matches = [row for row in candidate_host_submits
            if _row_identity(row) == (
                key_event["driver_generation"], key_event["qid"],
                key_event["index"], COMMAND_ID_ADD_STA_KEY)]
        # Align the callback and Hcmd timestamps in the kernel uptime domain;
        # do not convert either value to wall time. A loose bound avoids tying
        # an old reused slot to a current auth attempt.
        key_us = key_event["auth_monotonic_us"]
        # PAE stores whole microseconds while HCTX stores nanoseconds. Compare
        # at the coarser shared precision so valid ordering inside the same
        # microsecond is not rejected; sub-microsecond order remains unknown.
        matches = [row for row in matches if row["driver_monotonic_ns"] > 0 and
                   0 <= key_us - row["driver_monotonic_ns"] // 1000 <= 5_000_000]
        if len(matches) != 1:
            lifecycles.append({
                **key_event,
                "hcmd_submit_status": "missing_or_ambiguous_same_tuple_submit",
                "hcmd_submit_serial": None,
                "response_status": "unknown",
                "response_rows": [],
                "rx_deauth_after_same_association": None,
                "association_relation": "not_joined",
            })
            continue

        submit = matches[0]
        # Any host command reusing this generation/qid/index ends the old
        # slot's attribution window, even if the new command has another ID.
        next_same_slot = min((row["serial"] for row in all_host_submits
            if (row["driver_generation"], row["qid"], row["index"]) ==
                (submit["driver_generation"], submit["qid"], submit["index"]) and
            row["serial"] > submit["serial"]), default=None)
        same_slot_responses = [row for row in response_rows
            if _row_identity(row) == _row_identity(submit) and
            row["serial"] > submit["serial"] and
            (next_same_slot is None or row["serial"] < next_same_slot)]

        firmware_generation_unavailable = submit["firmware_generation"] == 0
        firmware_generation_mismatch = any(
            row["firmware_generation"] != submit["firmware_generation"]
            for row in same_slot_responses)
        matched_responses = ([] if (firmware_generation_unavailable or
                                    firmware_generation_mismatch) else
                             same_slot_responses)

        # Refuse to join if observed response timestamps move backwards or are
        # separated by implausible elapsed time. This is only a metadata-order
        # check, not a firmware transaction-ID proof.
        time_order_ok = all(
            row["driver_monotonic_ns"] >= submit["driver_monotonic_ns"] and
            row["driver_monotonic_ns"] - submit["driver_monotonic_ns"] <= 30_000_000_000
            for row in matched_responses)
        if not time_order_ok:
            matched_responses = []

        response_summary = []
        response_failed_flag = False
        local_response_rejected = False
        contradictory_response_metadata = False
        for row in matched_responses:
            failed_flag = (bool(row["group_id"] & 0x40) or
                           bool(row["flags"] & FLAG_COMMAND_RESPONSE_FAILED))
            rejected_locally = row["phase"] == PHASE_RX_RESPONSE_REJECTED
            response_failed_flag = response_failed_flag or failed_flag
            local_response_rejected = local_response_rejected or rejected_locally
            status_present = bool(row["flags"] & FLAG_FIRMWARE_STATUS_PRESENT)
            status_unavailable = bool(row["flags"] & FLAG_FIRMWARE_STATUS_UNAVAILABLE)
            if status_present and status_unavailable:
                contradictory_response_metadata = True
                break
            if status_present and row["payload_length"] != 4:
                contradictory_response_metadata = True
                break
            response_summary.append({
                "serial": row["serial"],
                "phase": row["phase"],
                "driver_monotonic_ns": row["driver_monotonic_ns"],
                "firmware_generation": row["firmware_generation"],
                "group_id": row["group_id"],
                "response_failed_flag": failed_flag,
                "local_response_rejected": rejected_locally,
                "firmware_status_state": (
                    "raw_status_present" if status_present else
                    "status_unavailable" if status_unavailable else
                    "not_recorded_in_this_phase"),
                "firmware_status_raw_le32": row["result"] if status_present else None,
                "dispatch_handled": (row["result"] == 1
                    if row["phase"] == PHASE_RX_DISPATCH_COMPLETED else None),
            })
        if firmware_generation_unavailable:
            response_summary = []
            response_status = "response_firmware_generation_unavailable_unknown"
        elif firmware_generation_mismatch:
            response_summary = []
            response_status = "response_generation_mismatch_unknown"
        elif contradictory_response_metadata:
            response_summary = []
            response_status = "contradictory_response_metadata_unknown"
        elif not matched_responses:
            response_status = "no_matching_response_row_in_visible_cut"
        elif response_failed_flag or local_response_rejected:
            response_status = "failed_response_flag_or_reject_observed"
        elif any(row["phase"] == PHASE_COMMAND_RETIRED for row in matched_responses):
            response_status = "response_seen_and_host_command_retired"
        elif any(row["phase"] == PHASE_RX_DISPATCH_COMPLETED and row["result"] == 1
                 for row in matched_responses):
            response_status = "response_dispatched_handled"
        else:
            response_status = "response_observed_completion_unknown"

        if (firmware_generation_unavailable or firmware_generation_mismatch or
                contradictory_response_metadata):
            lifecycles.append({
                **key_event,
                "hcmd_submit_status": "same_tuple_submit_observed",
                "hcmd_submit_serial": submit["serial"],
                "hcmd_submit_monotonic_ns": submit["driver_monotonic_ns"],
                "hcmd_submit_phase": submit["phase"],
                "response_status": response_status,
                "response_rows": [],
                "response_failed_flag_observed": False,
                "local_response_rejected_observed": False,
                "response_firmware_generation_unavailable": firmware_generation_unavailable,
                "mismatched_response_generation_observed": firmware_generation_mismatch,
                "rx_deauth_after_same_association": None,
                "association_relation": "not_joined",
                "key_install_success_proven": False,
                "peer_ack_proven": False,
            })
            continue

        later_deauths = [event for event in events
            if event.get("kind") == AUTH_KIND_RX_DEAUTH and
            event.get("driver_generation") == key_event["driver_generation"] and
            event.get("association_id") == key_event["association_id"] and
            event.get("sequence", 0) > key_event["auth_sequence"] and
            event.get("monotonic_us", 0) > key_event["auth_monotonic_us"]]
        later_deauth = min(later_deauths, key=lambda event: event["sequence"]) if later_deauths else None

        group2 = [event for event in events
            if event.get("kind") == AUTH_KIND_GROUP2_RESULT and
            event.get("driver_generation") == key_event["driver_generation"] and
            event.get("association_id") == key_event["association_id"] and
            event.get("attempt_id") == key_event["attempt_id"] and
            event.get("sequence", 0) > key_event["auth_sequence"]]
        replay_relations = [_replay_relation(event.get("flags", 0)) for event in group2]
        lifecycles.append({
            **key_event,
            "hcmd_submit_status": "same_tuple_submit_observed",
            "hcmd_submit_serial": submit["serial"],
            "hcmd_submit_monotonic_ns": submit["driver_monotonic_ns"],
            "hcmd_submit_phase": submit["phase"],
            "response_status": response_status,
            "response_rows": response_summary,
            "response_failed_flag_observed": response_failed_flag,
            "local_response_rejected_observed": local_response_rejected,
            "response_firmware_generation_unavailable": False,
            "mismatched_response_generation_observed": False,
            "same_attempt_group2_events": len(group2),
            "same_attempt_group2_replay_relations": replay_relations,
            "rx_deauth_after_same_association": later_deauth is not None,
            "rx_deauth_auth_sequence": (
                later_deauth["sequence"] if later_deauth else None),
            "rx_deauth_reason_code": (
                later_deauth["result"] if later_deauth else None),
            "association_relation": (
                "later_rx_deauth_same_generation_association; causality_unproven"
                if later_deauth else "no_later_rx_deauth_in_auth_cut"),
            "key_install_success_proven": False,
            "peer_ack_proven": False,
        })

    return {
        "status": "classified_from_stable_complete_cuts",
        "hcmd_cut": {
            "version_begin": header.get("version_begin"),
            "version_end": header.get("version_end"),
            "window_start_serial": header.get("window_start_serial"),
            "window_end_serial": header.get("window_end_serial"),
            "row_count": header.get("row_count"),
            "dropped_count": header.get("dropped_count"),
            "overwritten_count": header.get("overwritten_count"),
            "gap_count": header.get("gap_count"),
            "history_may_be_truncated": bool(
                header.get("dropped_count") or header.get("overwritten_count") or
                header.get("gap_count")),
        },
        "lifecycles": lifecycles,
        "timestamp_contract": (
            "Hcmd monotonic_ns and auth monotonic_us are retained in their driver "
            "uptime domain; no wall-clock conversion is performed. Their join "
            "uses microsecond precision because the auth trace is quantized; "
            "sub-microsecond order is unknown. The 5-second submit join and "
            "30-second response cut are tool bounds, not firmware protocol "
            "timeouts. Qid/index is a queue-slot tuple, not a firmware transaction ID."),
        "key_install_success_proven": False,
        "peer_ack_proven": False,
        "airdrop_proven": False,
    }


def trigger_reasons(decoded_hcmd: dict, auth_snapshot: dict,
                    link_snapshot: dict, previous_en1: dict | None,
                    current_en1: dict | None, seen_hcmd_serials: set,
                    seen_auth_sequences: set) -> list[str]:
    """Return newly observed bounded event anchors; first sample is baseline."""
    reasons: list[str] = []
    rows = decoded_hcmd.get("rows", []) if isinstance(decoded_hcmd, dict) else []
    new_rows = []
    for row in rows:
        key = (row.get("driver_generation"), row.get("serial"))
        if key not in seen_hcmd_serials:
            seen_hcmd_serials.add(key)
            new_rows.append(row)
    if any(_is_key_command(row) and row["source"] == SOURCE_HOST_COMMAND and
           row["phase"] in (PHASE_COMMAND_SUBMITTED, PHASE_COMMAND_SUBMIT_FAILED)
           for row in new_rows):
        reasons.append("new_add_sta_key_host_command")
    if any(_is_key_response(row) and row["source"] == SOURCE_COMMAND_RESPONSE_QUEUE and
           row["phase"] in RX_RESPONSE_PHASES for row in new_rows):
        reasons.append("new_add_sta_key_rx_response_event")

    auth_events = auth_snapshot.get("events", []) if isinstance(auth_snapshot, dict) else []
    new_auth = []
    for event in auth_events:
        key = (event.get("diagnostic_instance"), event.get("sequence"))
        if key not in seen_auth_sequences:
            seen_auth_sequences.add(key)
            new_auth.append(event)
    if any(event.get("kind") == AUTH_KIND_GROUP1_BEGIN for event in new_auth):
        reasons.append("new_group1_rekey_anchor")
    if any(event.get("kind") == AUTH_KIND_RX_DEAUTH for event in new_auth):
        reasons.append("new_rx_deauth_event")

    if isinstance(link_snapshot, dict) and link_snapshot.get("snapshot_status") == "stable":
        # Link sequence changes alone can be noisy; actual readiness loss below
        # is the stop/tail signal. The complete link trace remains in the file.
        pass
    required = ("present", "up", "running", "link_active", "ipv4_present")
    if (isinstance(previous_en1, dict) and isinstance(current_en1, dict) and
            all(previous_en1.get(key) is True for key in required) and
            any(current_en1.get(key) is not True for key in required)):
        reasons.append("en1_readiness_lost")
    return reasons
