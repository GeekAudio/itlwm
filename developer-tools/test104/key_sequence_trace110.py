"""Decode private Test110 ADD_STA_KEY sequence metadata from Test104 HCTX rows.

The decoder reports values staged by the host in the exact key-command path.
It never infers firmware key installation, AP acceptance, or over-air PN.
"""
from __future__ import annotations

from typing import Any

PHASE_RX = 14
PHASE_TX = 15
PHASE_UNAVAILABLE = 16
SOURCE_HOST_COMMAND = 1
COMMAND_ADD_STA_KEY = 0x17
GROUP_LONG = 1
FLAG_HEADER_FIELDS_PRESENT = 1 << 4
FLAG_FIRMWARE_STATE_KNOWN = 1 << 6
FLAG_SEQUENCE_VALUE_PRESENT = 1 << 13
FLAG_API_VERSION_PRESENT = 1 << 14
FLAG_MAX_TID_PRESENT = 1 << 15
FLAG_ORIGIN_GENERATION_PRESENT = 1 << 17
FLAG_ORIGIN_GENERATION_CHANGED = 1 << 18
FLAG_ORIGIN_SUBMIT_SERIAL_PRESENT = 1 << 19
MAX_TID_SHIFT = 20
MAX_TID_MASK = 0x0F << MAX_TID_SHIFT
PN_MASK_48 = (1 << 48) - 1


def _uint(value: Any, bits: int) -> bool:
    return type(value) is int and 0 <= value < (1 << bits)


def _decode_row(row: Any, owner_generation: int) -> dict:
    if not isinstance(row, dict):
        return {"status": "invalid_row"}
    fields = {
        "serial": 64, "driver_monotonic_ns": 64,
        "driver_generation": 32, "firmware_generation": 32,
        "phase": 32, "source": 32, "command_id": 32,
        "group_id": 32, "version": 32, "qid": 32, "index": 32,
        "header_sequence": 32, "flags": 32, "result": 32,
        "result_detail": 32, "packet_length": 32, "payload_length": 32,
    }
    if not all(_uint(row.get(name), bits) for name, bits in fields.items()):
        return {"status": "invalid_numeric_fields"}

    phase = row["phase"]
    flags = row["flags"]
    generation_present = bool(flags & FLAG_ORIGIN_GENERATION_PRESENT)
    generation_changed = bool(flags & FLAG_ORIGIN_GENERATION_CHANGED)
    serial_present = bool(flags & FLAG_ORIGIN_SUBMIT_SERIAL_PRESENT)
    encoded_submit_serial = (row["packet_length"] << 32) | row["payload_length"]
    identity_valid = (
        phase in (PHASE_RX, PHASE_TX, PHASE_UNAVAILABLE) and
        row["serial"] > 0 and row["driver_monotonic_ns"] > 0 and
        row["source"] == SOURCE_HOST_COMMAND and
        row["command_id"] == COMMAND_ADD_STA_KEY and
        row["group_id"] == GROUP_LONG and row["qid"] == 0 and
        row["index"] <= 0xFF and
        row["header_sequence"] == ((row["qid"] << 8) | row["index"]) and
        bool(flags & FLAG_HEADER_FIELDS_PRESENT) and
        bool(flags & FLAG_API_VERSION_PRESENT) and
        not (generation_changed and not generation_present) and
        (row["driver_generation"] > 0 if generation_present else
         row["driver_generation"] == 0) and
        (encoded_submit_serial > 0 if serial_present else
         encoded_submit_serial == 0)
    )
    if not identity_valid:
        return {"status": "invalid_key_command_identity"}

    result = {
        "serial": row["serial"],
        "monotonic_ns": row["driver_monotonic_ns"],
        "driver_generation": row["driver_generation"],
        "firmware_generation": row["firmware_generation"],
        "queue_id": row["qid"],
        "queue_index": row["index"],
        "command_id": row["command_id"],
        "group_id": row["group_id"],
        "header_sequence": row["header_sequence"],
        "api_version": row["version"],
        "origin_generation_present": generation_present,
        "origin_generation_changed_before_record": generation_changed,
        "origin_generation_current": (
            generation_present and not generation_changed and
            row["driver_generation"] == owner_generation),
        "firmware_alive_generation_match_observed": (
            bool(flags & FLAG_FIRMWARE_STATE_KNOWN) and
            row["firmware_generation"] != 0 and
            row["firmware_generation"] == row["driver_generation"] and
            not generation_changed),
        "origin_submit_serial": encoded_submit_serial if serial_present else None,
        "firmware_status_proven": False,
        "firmware_key_install_proven": False,
        "peer_acceptance_proven": False,
    }
    has_value = bool(flags & FLAG_SEQUENCE_VALUE_PRESENT)
    has_tid = bool(flags & FLAG_MAX_TID_PRESENT)
    max_tid_bits = flags & MAX_TID_MASK
    if phase == PHASE_UNAVAILABLE:
        if (has_value or has_tid or max_tid_bits != 0 or
                row["result_detail"] != 0):
            return {"status": "invalid_unavailable_row"}
        result.update(status="api_layout_unavailable",
                      reason_code=row["result"])
        return result

    if (not has_value or row["version"] not in (2, 3) or
            (phase == PHASE_RX) != has_tid):
        return {"status": "invalid_sequence_row"}
    if phase == PHASE_TX and max_tid_bits != 0:
        return {"status": "invalid_sequence_row"}

    value = row["result"] | (row["result_detail"] << 32)
    result["counter_value"] = value
    if phase == PHASE_RX:
        if value > PN_MASK_48:
            return {"status": "rx_pn_out_of_range"}
        result.update(kind="rx_replay_floor",
                      max_tid=max_tid_bits >> MAX_TID_SHIFT,
                      status="host_counter_retained")
    else:
        result.update(kind="tx_sequence_counter", status="host_counter_retained",
                      within_ccmp_48_bit_range=value <= PN_MASK_48)

    if generation_changed:
        result["status"] = "origin_generation_changed_before_record"
    elif not generation_present:
        result["status"] = "origin_generation_unknown"
    elif row["driver_generation"] != owner_generation:
        result["status"] = "origin_generation_not_current"
    return result


def _bundles(events: list[dict]) -> list[dict]:
    grouped: dict[int, dict[str, list[dict]]] = {}
    for event in events:
        origin = event.get("origin_submit_serial")
        if not origin:
            continue
        roles = grouped.setdefault(origin, {"rx": [], "tx": [], "unavailable": []})
        if event.get("kind") == "rx_replay_floor":
            roles["rx"].append(event)
        elif event.get("kind") == "tx_sequence_counter":
            roles["tx"].append(event)
        elif event.get("status") == "api_layout_unavailable":
            roles["unavailable"].append(event)

    output = []
    for origin, roles in sorted(grouped.items()):
        rx = roles["rx"]
        tx = roles["tx"]
        unavailable = roles["unavailable"]
        bundle = {
            "origin_submit_serial": origin,
            "rx_event_serials": [event["serial"] for event in rx],
            "tx_event_serials": [event["serial"] for event in tx],
            "same_origin_submit_serial": bool(rx and tx),
            "firmware_key_install_proven": False,
            "peer_acceptance_proven": False,
        }
        if rx and tx:
            consistent = all(
                row["driver_generation"] == rx[0]["driver_generation"] and
                row["queue_id"] == rx[0]["queue_id"] and
                row["queue_index"] == rx[0]["queue_index"] and
                row["command_id"] == rx[0]["command_id"] and
                row["group_id"] == rx[0]["group_id"] and
                row["api_version"] == rx[0]["api_version"] and
                row["header_sequence"] == rx[0]["header_sequence"]
                for row in rx + tx)
            current = all(row.get("origin_generation_current") for row in rx + tx)
            bundle["status"] = (
                "same_origin_submit_serial" if consistent and current else
                "same_submit_serial_generation_unverified" if consistent else
                "same_submit_serial_identity_conflict")
        elif unavailable:
            bundle["status"] = "sequence_unavailable"
        elif rx or tx:
            bundle["status"] = "partial_sequence_observation"
        else:
            bundle["status"] = "not_assessed"
        output.append(bundle)
    return output


def decode_key_sequences(hcmd_snapshot: Any) -> dict:
    """Decode Test110 numeric rows from a Test104 `hcmd` snapshot object."""
    if not isinstance(hcmd_snapshot, dict):
        return {"schema": "test110-key-sequence/v1", "status": "snapshot_missing",
                "events": [], "bundles": []}
    rows = hcmd_snapshot.get("rows")
    if not isinstance(rows, list):
        return {"schema": "test110-key-sequence/v1", "status": "rows_missing",
                "events": [], "bundles": []}
    header = hcmd_snapshot.get("header")
    if not isinstance(header, dict):
        return {"schema": "test110-key-sequence/v1", "status": "header_missing",
                "events": [], "bundles": []}
    owner_generation = header.get("owner_generation")
    if not _uint(owner_generation, 32) or owner_generation == 0:
        return {"schema": "test110-key-sequence/v1", "status": "owner_invalid",
                "events": [], "bundles": []}

    stable = hcmd_snapshot.get("snapshot_stable") is True
    complete = hcmd_snapshot.get("snapshot_complete") is True
    events = []
    for row in rows:
        if isinstance(row, dict) and row.get("phase") in (
                PHASE_RX, PHASE_TX, PHASE_UNAVAILABLE):
            events.append(_decode_row(row, owner_generation))
    return {
        "schema": "test110-key-sequence/v1",
        "status": "stable_complete_cut" if stable and complete else
                  "partial_or_unstable_cut",
        "snapshot_stable": stable,
        "snapshot_complete": complete,
        "events": events,
        "bundles": _bundles(events),
        "interpretation": (
            "Host-side CCMP sequence values staged in the keyed command path; "
            "not firmware install, AP acceptance, or over-air PN evidence."),
    }
