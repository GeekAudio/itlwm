#!/usr/bin/env python3
"""Fail-closed, address-free correlation for GTK key-command evidence.

The input is a stable Test103-format HCTX snapshot plus the same IOKit read's
STA-auth trace. This module only associates host command metadata and local
driver events. Missing tuples in an old HCTX cut are reported as freshness
unproven, never as a firmware non-response. It never infers firmware key
installation, radio transmission, peer acceptance, or a causal reason for
disconnection.
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
AUTH_KIND_KEY_COMMAND_ORIGIN = 15
AUTH_STAGE_KEY_CALLBACK = 13
AUTH_STAGE_GROUP2_OUTPUT = 14
AUTH_STAGE_KEY_COMMAND_ORIGIN = 22
AUTH_COMPONENT_GTK = 1
AUTH_SOURCE_HAL_COMMAND = 4
AUTH_SOURCE_SOFTWARE_CRYPTO = 5
AUTH_SUBMIT_LOCAL_ENQUEUE = 2
AUTH_FLAG_DOORBELL_ISSUED = 1 << 6
AUTH_FLAG_REPLAY_CHECKED = 1 << 12
AUTH_FLAG_REPLAY_EQUAL = 1 << 13
AUTH_FLAG_REPLAY_MISMATCH = 1 << 14
AUTH_FLAG_COMMAND_SUBMIT_SERIAL_PRESENT = 1 << 15
HCTX_FLAG_ORIGIN_SUBMIT_SERIAL_PRESENT = 1 << 19

HCTX_PHASE_KEY_SEQUENCE_RX = 14
HCTX_PHASE_KEY_SEQUENCE_TX = 15
HCTX_PHASE_KEY_SEQUENCE_UNAVAILABLE = 16

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


def decode_command_submit_origin(event: Any) -> dict:
    """Decode the optional 64-bit HCTX submit serial from auth kind 15.

    The signed auth `result` field stores the high 32-bit bit pattern; `detail`
    stores the low word. This value is a host command serial, not key material.
    """
    if (not isinstance(event, dict) or
            event.get("kind") != AUTH_KIND_KEY_COMMAND_ORIGIN or
            event.get("stage") != AUTH_STAGE_KEY_COMMAND_ORIGIN):
        return {"status": "not_origin_witness", "serial": None}
    flags = event.get("flags")
    result = event.get("result")
    detail = event.get("detail")
    source = event.get("source")
    if (not _is_uint(flags, 32) or
            type(result) is not int or not -(1 << 31) <= result < (1 << 31) or
            not _is_uint(detail, 32)):
        return {"status": "invalid_origin_witness_fields", "serial": None}
    present = bool(flags & AUTH_FLAG_COMMAND_SUBMIT_SERIAL_PRESENT)
    if source == AUTH_SOURCE_SOFTWARE_CRYPTO:
        if flags != 0 or result != 0 or detail != 0:
            return {"status": "invalid_software_crypto_origin_payload",
                    "serial": None}
        return {"status": "software_crypto_no_firmware_command",
                "serial": None, "serial_present": False}
    if source != AUTH_SOURCE_HAL_COMMAND:
        return {"status": "unsupported_origin_source", "serial": None}
    if not present:
        if flags != 0 or result != 0 or detail != 0:
            return {"status": "invalid_unflagged_origin_payload",
                    "serial": None}
        return {"status": "origin_serial_not_present", "serial": None,
                "serial_present": False}
    if flags != AUTH_FLAG_COMMAND_SUBMIT_SERIAL_PRESENT:
        return {"status": "invalid_origin_witness_flags", "serial": None}
    serial = ((result & 0xFFFFFFFF) << 32) | detail
    if serial == 0:
        return {"status": "invalid_zero_origin_serial", "serial": None}
    return {"status": "origin_serial_present", "serial": serial,
            "serial_present": True}


def _hctx_history_may_be_truncated(header: dict) -> bool:
    return bool(header.get("dropped_count") or header.get("overwritten_count") or
                header.get("gap_count"))


def _auth_history_may_be_truncated(auth_snapshot: dict) -> bool:
    return bool(auth_snapshot.get("dropped_count"))


def _association_lifecycle_join(key_event: dict, witness: dict,
                                events: list[dict],
                                auth_snapshot: dict) -> dict:
    anchors = [event for event in events
        if event.get("kind") == AUTH_KIND_GROUP1_BEGIN and
        event.get("driver_generation") == key_event["driver_generation"] and
        event.get("attempt_id") == key_event["attempt_id"]]
    if not anchors:
        status = ("group1_anchor_not_observed_may_be_truncated"
                  if _auth_history_may_be_truncated(auth_snapshot) else
                  "group1_anchor_not_observed")
        return {"association_lifecycle_status": status,
                "same_association_lifecycle_observed": False,
                "group1_anchor_sequence": None}
    if len(anchors) != 1:
        return {"association_lifecycle_status": "group1_anchor_ambiguous",
                "same_association_lifecycle_observed": False,
                "group1_anchor_sequence": None,
                "group1_anchor_count": len(anchors)}

    anchor = anchors[0]
    association_ids = (anchor.get("association_id"),
                       key_event.get("association_id"),
                       witness.get("association_id"))
    if any(not _is_uint(value, 32) or value == 0 for value in association_ids):
        status = "association_id_zero_or_unavailable"
    elif len(set(association_ids)) != 1:
        status = "association_mismatch_across_group1_key_submit_origin"
    else:
        sequence_ordered = (
            anchor.get("sequence", 0) < key_event.get("auth_sequence", 0) <
            witness.get("sequence", 0))
        time_ordered = (
            anchor.get("monotonic_us", 0) <= key_event.get("auth_monotonic_us", 0) <=
            witness.get("monotonic_us", 0))
        status = ("same_association_group1_key_submit_origin_ordered"
                  if sequence_ordered and time_ordered else
                  "group1_key_origin_record_order_unverified")

    return {
        "association_lifecycle_status": status,
        "same_association_lifecycle_observed":
            status == "same_association_group1_key_submit_origin_ordered",
        "group1_anchor_sequence": anchor.get("sequence"),
        "group1_anchor_monotonic_us": anchor.get("monotonic_us"),
    }


def _hctx_row_identity_mismatches(row: dict, key_event: dict) -> list[str]:
    expected_header_sequence = (key_event["qid"] << 8) | key_event["index"]
    expected = {
        "source": SOURCE_HOST_COMMAND,
        "phase": PHASE_COMMAND_SUBMITTED,
        "driver_generation": key_event["driver_generation"],
        "command_id": COMMAND_ID_ADD_STA_KEY,
        "group_id": COMMAND_GROUP_LONG,
        "qid": key_event["qid"],
        "index": key_event["index"],
        "header_sequence": expected_header_sequence,
    }
    return [name for name, value in expected.items() if row.get(name) != value]


def _hctx_origin_submit_serial(row: dict) -> int | None:
    flags = row.get("flags")
    if not _is_uint(flags, 32) or not (flags & HCTX_FLAG_ORIGIN_SUBMIT_SERIAL_PRESENT):
        return None
    high, low = row.get("packet_length"), row.get("payload_length")
    if not (_is_uint(high, 32) and _is_uint(low, 32)):
        return None
    value = (high << 32) | low
    return value or None


def _origin_sequence_row_summary(row: dict, origin_serial: int) -> dict:
    return {
        "phase": row["phase"],
        "serial": row["serial"],
        "driver_monotonic_ns": row["driver_monotonic_ns"],
        "driver_generation": row["driver_generation"],
        "firmware_generation": row["firmware_generation"],
        "command_id": row["command_id"],
        "group_id": row["group_id"],
        "qid": row["qid"],
        "index": row["index"],
        "header_sequence": row["header_sequence"],
        "origin_submit_serial": origin_serial,
    }


def _exact_origin_join(key_event: dict, events: list[dict], rows: list[dict],
                       hcmd_header: dict, auth_snapshot: dict) -> dict:
    """Join a same-attempt kind-15 serial to one exact HCTX submit row.

    Tuple/time matching remains available in the legacy response summary, but
    it is never promoted to this exact-origin result.
    """
    schema = auth_snapshot.get("schema")
    history_truncated = _hctx_history_may_be_truncated(hcmd_header)
    base_witnesses = [event for event in events
        if event.get("kind") == AUTH_KIND_KEY_COMMAND_ORIGIN and
        event.get("stage") == AUTH_STAGE_KEY_COMMAND_ORIGIN and
        event.get("attempt_id") == key_event["attempt_id"] and
        event.get("driver_generation") == key_event["driver_generation"] and
        event.get("component") == key_event["component"]]
    common = {
        "auth_schema": schema,
        "same_ioreg_sample": True,
        "hctx_history_may_be_truncated": history_truncated,
        "auth_ring_dropped_count": auth_snapshot.get("dropped_count"),
        "auth_ring_may_have_truncated": _auth_history_may_be_truncated(auth_snapshot),
        "exact_match": False,
        "peer_ack_proven": False,
    }
    if not base_witnesses:
        return {**common,
                "status": ("origin_witness_not_observed_auth_schema1"
                           if schema == 1 else "origin_witness_not_observed"),
                "origin_submit_serial": None,
                "association_lifecycle_status": "origin_witness_unavailable",
                "same_association_lifecycle_observed": False}
    if len(base_witnesses) != 1:
        return {**common, "status": "origin_witness_ambiguous_same_attempt",
                "origin_submit_serial": None,
                "association_lifecycle_status": "origin_witness_ambiguous",
                "same_association_lifecycle_observed": False,
                "matching_origin_witness_count": len(base_witnesses)}
    witness = base_witnesses[0]
    association_join = _association_lifecycle_join(
        key_event, witness, events, auth_snapshot)
    if witness.get("source") != key_event["source"]:
        return {**common, "status": "origin_witness_source_mismatch",
                "origin_submit_serial": None, **association_join}
    decoded = decode_command_submit_origin(witness)
    witness_meta = {
        "origin_witness_sequence": witness.get("sequence"),
        "origin_witness_monotonic_us": witness.get("monotonic_us"),
        "origin_witness_status": decoded.get("status"),
    }
    if decoded.get("status") != "origin_serial_present":
        return {**common, **witness_meta,
                "status": "origin_witness_serial_unavailable",
                "origin_submit_serial": None, **association_join}

    origin_serial = decoded["serial"]
    serial_rows = [row for row in rows if row.get("serial") == origin_serial]
    if not serial_rows:
        status = ("origin_submit_serial_not_in_hctx_cut_may_be_truncated"
                  if history_truncated else "origin_submit_serial_not_in_hctx_cut")
        return {**common, **witness_meta, "status": status,
                "origin_submit_serial": origin_serial, **association_join}
    if len(serial_rows) != 1:
        return {**common, **witness_meta,
                "status": "origin_submit_hctx_serial_ambiguous",
                "origin_submit_serial": origin_serial,
                **association_join,
                "hctx_rows_with_origin_serial": len(serial_rows)}

    submit = serial_rows[0]
    mismatches = _hctx_row_identity_mismatches(submit, key_event)
    if mismatches:
        return {**common, **witness_meta,
                "status": "origin_submit_hctx_identity_mismatch",
                "origin_submit_serial": origin_serial,
                **association_join,
                "hcmd_submit_identity_mismatch_fields": mismatches,
                "hcmd_submit_row_phase": submit.get("phase"),
                "hcmd_submit_row_source": submit.get("source")}

    sequence_rows = [row for row in rows
        if row.get("phase") in (HCTX_PHASE_KEY_SEQUENCE_RX,
                                 HCTX_PHASE_KEY_SEQUENCE_TX,
                                 HCTX_PHASE_KEY_SEQUENCE_UNAVAILABLE) and
        _hctx_origin_submit_serial(row) == origin_serial]
    by_phase = {phase: [row for row in sequence_rows if row["phase"] == phase]
                for phase in (HCTX_PHASE_KEY_SEQUENCE_RX,
                              HCTX_PHASE_KEY_SEQUENCE_TX,
                              HCTX_PHASE_KEY_SEQUENCE_UNAVAILABLE)}
    sequence_summaries: list[dict] = []
    sequence_identity_mismatches: list[dict] = []
    for phase_rows in by_phase.values():
        for row in phase_rows:
            mismatched = _hctx_row_identity_mismatches(
                {**row, "phase": PHASE_COMMAND_SUBMITTED}, key_event)
            if mismatched:
                sequence_identity_mismatches.append({
                    "phase": row["phase"],
                    "row_serial": row["serial"],
                    "mismatch_fields": mismatched,
                })
            sequence_summaries.append(
                _origin_sequence_row_summary(row, origin_serial))
    duplicated_phases = [phase for phase, values in by_phase.items()
                         if len(values) > 1]
    if duplicated_phases:
        sequence_status = "sequence_phase_ambiguous"
    elif sequence_identity_mismatches:
        sequence_status = "sequence_row_identity_mismatch"
    elif by_phase[HCTX_PHASE_KEY_SEQUENCE_UNAVAILABLE]:
        sequence_status = "sequence_api_layout_unavailable"
    elif by_phase[HCTX_PHASE_KEY_SEQUENCE_RX] and by_phase[HCTX_PHASE_KEY_SEQUENCE_TX]:
        sequence_status = "rx_tx_origin_rows_match"
    elif sequence_rows:
        sequence_status = "sequence_origin_rows_partial"
    else:
        sequence_status = "sequence_origin_rows_not_observed"
    return {
        **common,
        **witness_meta,
        **association_join,
        "status": "exact_command_submit_origin_match",
        "exact_match": True,
        "origin_submit_serial": origin_serial,
        "hcmd_submit_row_serial": submit["serial"],
        "hcmd_submit_monotonic_ns": submit["driver_monotonic_ns"],
        "hcmd_submit_identity": {
            name: submit[name] for name in (
                "driver_generation", "command_id", "group_id", "qid",
                "index", "header_sequence")},
        "sequence_rows_status": sequence_status,
        "sequence_bundle_complete": sequence_status == "rx_tx_origin_rows_match",
        "sequence_rows_by_phase": {
            str(phase): len(values) for phase, values in by_phase.items()},
        "missing_sequence_phases": [phase for phase in (
            HCTX_PHASE_KEY_SEQUENCE_RX, HCTX_PHASE_KEY_SEQUENCE_TX)
            if not by_phase[phase]],
        "duplicated_sequence_phases": duplicated_phases,
        "sequence_identity_mismatches": sequence_identity_mismatches,
        "sequence_rows": sequence_summaries,
    }


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


def _hcmd_cut_freshness(rows: list[dict], anchor_monotonic_us: int,
                       driver_generation: int) -> dict:
    """Classify whether the retained HCTX rows reach a local auth anchor.

    HCTX monotonic_ns and STA-auth monotonic_us are produced from the same
    kernel monotonic clock. A cut whose newest row is more than the existing
    five-second submit-join bound older than the auth anchor cannot adjudicate
    that attempt. This is a freshness warning only; it is never evidence that
    firmware did or did not return a response.
    """
    generation_rows = [row for row in rows
                       if row["driver_generation"] == driver_generation]
    if not generation_rows:
        return {"status": "freshness_unknown_no_hcmd_rows_for_generation",
                "freshness_unproven": True}
    if any(row["driver_monotonic_ns"] == 0 for row in generation_rows):
        return {"status": "freshness_unknown_missing_row_timestamps",
                "freshness_unproven": True}
    newest_ns = max(row["driver_monotonic_ns"] for row in generation_rows)
    anchor_ns = anchor_monotonic_us * 1000
    gap_ns = anchor_ns - newest_ns
    if gap_ns > 5_000_000_000:
        return {
            "status": "cut_predates_submit_join_window",
            "freshness_unproven": True,
            "newest_hcmd_monotonic_ns": newest_ns,
            "auth_anchor_monotonic_us": anchor_monotonic_us,
            "older_than_anchor_us": gap_ns // 1000,
            "join_bound_us": 5_000_000,
        }
    return {
        "status": "cut_reaches_submit_join_window",
        "freshness_unproven": True,
        "interpretation": (
            "A retained row reaches the time-join interval; this alone does "
            "not prove snapshot publication freshness or a matching tuple."),
        "newest_hcmd_monotonic_ns": newest_ns,
        "auth_anchor_monotonic_us": anchor_monotonic_us,
        "older_than_anchor_us": max(0, gap_ns // 1000),
        "join_bound_us": 5_000_000,
    }


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
                not _is_uint(association, 32) or
                not _is_uint(attempt, 32) or attempt == 0 or
                not _is_uint(monotonic_us, 64) or not _is_uint(sequence, 32)):
            continue
        key_event = {
            "attempt_id": attempt,
            "association_id": association,
            "driver_generation": generation,
            "auth_sequence": sequence,
            "auth_monotonic_us": monotonic_us,
            "component": event["component"],
            "source": event["source"],
            "qid": qid,
            "index": index,
            "callback_result": event.get("result"),
            "local_enqueue_observed": True,
        }
        key_event["origin_submit_join"] = _exact_origin_join(
            key_event, events, checked_rows, header, auth_snapshot)
        key_submits.append(key_event)

    if not key_submits:
        group1_anchors = [event for event in events
            if event.get("kind") == AUTH_KIND_GROUP1_BEGIN and
            _is_uint(event.get("monotonic_us"), 64)]
        result = {
            "status": "no_eligible_group_key_local_enqueue_in_auth_cut",
            "lifecycles": [],
            "key_install_success_proven": False,
            "peer_ack_proven": False,
            "auth_cut_scope": "this_bounded_snapshot_only",
            "interpretation": (
                "No eligible enqueue is present in this auth snapshot; this "
                "does not exclude an enqueue that aged out of the bounded cut."),
        }
        if group1_anchors:
            latest_anchor = max(group1_anchors, key=lambda event: event["sequence"])
            result["hcmd_cut_freshness"] = _hcmd_cut_freshness(
                checked_rows, latest_anchor["monotonic_us"],
                latest_anchor["driver_generation"])
            result["auth_anchor_sequence"] = latest_anchor["sequence"]
        else:
            result["hcmd_cut_freshness"] = {
                "status": "freshness_unknown_no_auth_anchor",
                "freshness_unproven": True,
            }
        return result

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
        cut_freshness = _hcmd_cut_freshness(
            checked_rows, key_event["auth_monotonic_us"],
            key_event["driver_generation"])
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
            submit_status = (
                "cut_predates_submit_freshness_unproven"
                if cut_freshness["status"] == "cut_predates_submit_join_window"
                else "missing_or_ambiguous_same_tuple_submit")
            lifecycles.append({
                **key_event,
                "hcmd_submit_status": submit_status,
                "hcmd_submit_serial": None,
                "hcmd_cut_freshness": cut_freshness,
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
                "hcmd_cut_freshness": cut_freshness,
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
            if key_event["association_id"] != 0 and
            event.get("kind") == AUTH_KIND_RX_DEAUTH and
            event.get("driver_generation") == key_event["driver_generation"] and
            event.get("association_id") == key_event["association_id"] and
            event.get("sequence", 0) > key_event["auth_sequence"] and
            event.get("monotonic_us", 0) > key_event["auth_monotonic_us"]]
        later_deauth = min(later_deauths, key=lambda event: event["sequence"]) if later_deauths else None

        group2 = [event for event in events
            if key_event["association_id"] != 0 and
            event.get("kind") == AUTH_KIND_GROUP2_RESULT and
            event.get("driver_generation") == key_event["driver_generation"] and
            event.get("association_id") == key_event["association_id"] and
            event.get("attempt_id") == key_event["attempt_id"] and
            event.get("sequence", 0) > key_event["auth_sequence"]]
        replay_relations = [_replay_relation(event.get("flags", 0)) for event in group2]
        lifecycles.append({
            **key_event,
            "hcmd_submit_status": "same_tuple_submit_observed",
            "hcmd_cut_freshness": cut_freshness,
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
                if later_deauth else
                "association_id_unavailable_no_join"
                if key_event["association_id"] == 0 else
                "no_later_rx_deauth_in_auth_cut"),
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
