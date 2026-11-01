#!/usr/bin/env python3
"""Decode Test103's bounded, same-cut TX_RSP retry counters.

The layout version is a host decoder version, not a claimed firmware API
version. These fields do not establish RF transmission, TX success, ACK, or
peer receipt.
"""
from __future__ import annotations

PREFIX = "NativeStaCompletion"
SCHEMA_4 = 4
SCHEMA_5 = 5
HAS_PAYLOAD_LENGTH = 1 << 6
HAS_FRAME_COUNT = 1 << 13
HAS_OBSERVER_SERIAL = 1 << 31
RETRY_FIELD_NAMES = (
    "TxRspRetryStatsVersion",
    "TxRspBtKillCount",
    "TxRspFailureRts",
    "TxRspFailureFrame",
)


class CompletionDecodeError(ValueError):
    pass


def completion_scalars(properties: dict) -> dict[str, int]:
    """Keep only numeric NativeStaCompletion properties from one IORegistry row."""
    if not isinstance(properties, dict):
        raise CompletionDecodeError("completion properties must be a dictionary")
    result: dict[str, int] = {}
    for key, value in properties.items():
        if (isinstance(key, str) and key.startswith(PREFIX) and
                type(value) is int):
            result[key[len(PREFIX):]] = value
    return result


def _require_int(values: dict[str, int], name: str) -> int:
    value = values.get(name)
    if type(value) is not int:
        raise CompletionDecodeError(f"{name} is missing or not an integer")
    return value


def _validate_snapshot(values: dict[str, int]) -> int:
    if not isinstance(values, dict):
        raise CompletionDecodeError("completion scalar map must be a dictionary")
    schema = _require_int(values, "Schema")
    if schema not in (SCHEMA_4, SCHEMA_5):
        raise CompletionDecodeError("unsupported NativeStaCompletion schema")
    begin = _require_int(values, "SnapshotVersionBegin")
    end = _require_int(values, "SnapshotVersionEnd")
    if begin != end or begin & 1:
        raise CompletionDecodeError("completion snapshot is missing, torn, or odd")
    if (_require_int(values, "SnapshotAvailable") != 1 or
            _require_int(values, "SnapshotComplete") != 1):
        raise CompletionDecodeError("completion snapshot is unavailable or incomplete")
    if _require_int(values, "DroppedCount") != 0:
        raise CompletionDecodeError("completion observer reports dropped records")

    if "PublicationSequence" in values:
        sequence = _require_int(values, "PublicationSequence")
        source = _require_int(values, "PublicationSource")
        generation = _require_int(values, "PublicationGeneration")
        owner_generation = _require_int(values, "OwnerGeneration")
        relevant = _require_int(values, "RelevantSerial")
        next_serial = _require_int(values, "NextSerial")
        if (sequence != begin or source not in (1, 2) or
                generation != owner_generation or relevant < 0 or
                next_serial < 0 or relevant > next_serial):
            raise CompletionDecodeError("completion publication metadata is inconsistent")
        if source == 1 and relevant == 0:
            raise CompletionDecodeError("ordinary publication lacks a related completion")
    return schema


def decode_scalars(values: dict[str, int]) -> dict:
    """Validate a stable schema 4/5 cut and decode only the new TX_RSP fields."""
    schema = _validate_snapshot(values)
    present = _require_int(values, "Event0Present")
    if present not in (0, 1):
        raise CompletionDecodeError("Event0Present is not boolean")
    if present == 0 and values.get("PublicationSource") == 1:
        raise CompletionDecodeError("ordinary completion publication has no retained TX_RSP row")

    result = {
        "schema": schema,
        "event_present": bool(present),
        "tx_rsp_retry_stats": {
            "status": (
                "unavailable_no_retained_txrsp_row" if present == 0 else
                "unavailable_in_schema_4" if schema == SCHEMA_4 else
                "unavailable_no_retained_txrsp_row"
            ),
            "layout_version": None,
            "frame_count": None,
            "bt_kill_count": None,
            "failure_rts": None,
            "failure_frame": None,
            "evidence_scope": (
                "host-decoded TX_RSP fields only; not proof of RF transmission, "
                "TX success, ACK, or peer receipt"
            ),
        },
    }

    if present == 1:
        kind = _require_int(values, "Event0Kind")
        flags = _require_int(values, "Event0PresenceFlags")
        if kind != 0 or not (flags & HAS_OBSERVER_SERIAL):
            raise CompletionDecodeError("Event0 is not a retained TX_RSP record")

    if schema == SCHEMA_4:
        # Schema 4 had no retry-stat contract. Never reinterpret any similarly
        # named stray fields as evidence when reading that historical schema.
        return result

    names = ("Event0TxRspRetryStatsVersion", "Event0TxRspBtKillCount",
             "Event0TxRspFailureRts", "Event0TxRspFailureFrame")
    if any(name not in values for name in names):
        raise CompletionDecodeError("schema 5 is missing retry-stat scalars")
    version, bt_kill, failure_rts, failure_frame = (
        _require_int(values, name) for name in names)
    if version not in (0, 1):
        raise CompletionDecodeError("unknown host TX_RSP layout version")
    counters = (bt_kill, failure_rts, failure_frame)
    if any(value < 0 or value > 255 for value in counters):
        raise CompletionDecodeError("TX_RSP retry counter is outside uint8 width")

    stats = result["tx_rsp_retry_stats"]
    if present == 0:
        if version != 0 or any(counters):
            raise CompletionDecodeError("retry stats exist without a retained TX_RSP row")
        return result

    if version == 0:
        if any(counters):
            raise CompletionDecodeError("unavailable retry stats must be zero-filled")
        stats["status"] = "unavailable_in_schema_5"
        return result

    frame_count = _require_int(values, "Event0FrameCount")
    payload_length = _require_int(values, "Event0PayloadLength")
    required_presence = HAS_FRAME_COUNT | HAS_PAYLOAD_LENGTH
    if ((flags & required_presence) != required_presence or
            frame_count != 1 or payload_length < 48):
        raise CompletionDecodeError("single-frame retry-stat contract is incomplete")
    stats.update({
        "status": "host_layout_v1_present",
        "layout_version": version,
        "frame_count": frame_count,
        "bt_kill_count": bt_kill,
        "failure_rts": failure_rts,
        "failure_frame": failure_frame,
        "note": (
            "zero counters do not establish that no RF retry occurred; "
            "firmware API compatibility is not independently verified"
        ),
    })
    return result
