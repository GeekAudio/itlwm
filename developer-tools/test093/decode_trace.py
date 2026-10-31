#!/usr/bin/env python3
"""Decode payload-free Test093 raw snapshots using explicit x86_64 offsets."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


SCAN_SCHEMA = 1
SCAN_RECORD_BYTES = 136
SCAN_HEADER_BYTES = 40
SCAN_CAPACITY = 16
SCAN_SNAPSHOT_BYTES = SCAN_HEADER_BYTES + SCAN_RECORD_BYTES * SCAN_CAPACITY
POWER_SCHEMA = 1
POWER_ENTRY_BYTES = 56
POWER_HEADER_BYTES = 16
POWER_CAPACITY = 32
POWER_SNAPSHOT_BYTES = POWER_HEADER_BYTES + POWER_ENTRY_BYTES * POWER_CAPACITY

STATUS = {0: "ok", 1: "bad_request", 2: "unsupported", 3: "busy", 4: "not_ready", 5: "failed"}
BUSY_CLASS = {
    0: "none", 1: "backend_address_change", 2: "backend_scan_drain",
    3: "backend_join_pending", 4: "backend_active_scan",
    5: "radio_unclassified", 6: "radio_reported",
}
TERMINAL_SOURCE = {
    0: "none", 1: "firmware_complete", 2: "firmware_aborted",
    3: "request_replacement", 4: "request_abort", 5: "request_timeout",
    6: "driver_offline", 7: "reset_drained", 8: "admission_failure",
}
CLOCK_SOURCE = {0: "tick_fallback", 1: "monotonic_callback"}
POWER_OPERATION = {
    0: "none", 1: "power_set", 2: "address", 3: "apple_disassociate",
    4: "wcl_leave", 5: "wcl_abort_join", 6: "hal_event",
}
POWER_PHASE = {
    0: "unknown", 1: "call_begin", 2: "native_action_begin", 3: "native_action_end",
    4: "wait_begin", 5: "wait_end", 6: "disable_begin", 7: "disable_end",
    8: "enable_begin", 9: "enable_end", 10: "disassociate_begin",
    11: "disassociate_mgmt_end", 12: "disassociate_state_end",
    13: "address_quiesce_begin", 14: "address_quiesce_end", 15: "address_commit",
    16: "driver_event", 17: "notification_call", 18: "timeout", 19: "call_end",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _bool(value: int, field: str) -> bool:
    _require(value in (0, 1), f"{field} is not a wire boolean")
    return bool(value)


def decode_scan(data: bytes, *, schema: int, record_bytes: int) -> dict[str, Any]:
    _require(schema == SCAN_SCHEMA, "unsupported scan schema")
    _require(record_bytes == SCAN_RECORD_BYTES, "scan RecordBytes mismatch")
    _require(len(data) == SCAN_SNAPSHOT_BYTES, "scan snapshot size mismatch")

    version, count, requests, replacements, overwrites, stale_total = struct.unpack_from(
        "<IIQQQQ", data, 0
    )
    _require(version == SCAN_SCHEMA, "scan wire version mismatch")
    _require(count <= SCAN_CAPACITY, "scan record count exceeds capacity")
    records: list[dict[str, Any]] = []

    for index in range(SCAN_CAPACITY):
        start = SCAN_HEADER_BYTES + index * SCAN_RECORD_BYTES
        raw = data[start : start + SCAN_RECORD_BYTES]
        if index >= count:
            _require(not any(raw), "unused scan record is not zero-filled")
            continue
        fields = struct.unpack("<12I8QII10B6x", raw)
        (
            request_serial, generation, replaces_serial, replaced_by_serial,
            admission_attempts, radio_attempts, busy_attempts, event201_count,
            stale_terminals, firmware_status, native237_status, native237_emit_count,
            request_ns, first_radio_ns, last_radio_ns, accepted_ns,
            first201_ns, last201_ns, firmware_consumed_ns, native237_emit_ns,
            busy_reason_code, admission_status, busy_class, terminal_source,
            clock_source, valid, has_first201, has_firmware_terminal,
            has_native237, native237_emit_called, has_first_radio, has_accepted,
        ) = fields

        _require(not any(raw[130:136]), "scan record padding is not zero-filled")
        _require(_bool(valid, "valid"), "retained scan record is not valid")
        _require(request_serial != 0, "scan request serial is zero")
        _require(admission_status in STATUS, "unknown scan admission status")
        _require(busy_class in BUSY_CLASS, "unknown scan Busy class")
        _require(terminal_source in TERMINAL_SOURCE, "unknown scan terminal source")
        _require(clock_source in CLOCK_SOURCE, "unknown scan clock source")
        _require(admission_attempts >= radio_attempts, "radio attempts exceed admission attempts")
        _require(busy_attempts <= admission_attempts, "Busy attempts exceed admission attempts")

        has_first201_b = _bool(has_first201, "hasFirst201")
        has_fw_b = _bool(has_firmware_terminal, "hasFirmwareTerminal")
        has_native_b = _bool(has_native237, "hasNative237")
        emit_called_b = _bool(native237_emit_called, "native237EmitCalled")
        has_first_radio_b = _bool(has_first_radio, "hasFirstRadioAttempt")
        has_accepted_b = _bool(has_accepted, "hasAccepted")
        _require(has_first_radio_b == (radio_attempts != 0), "first radio time flag disagrees with attempts")
        _require(has_accepted_b == (admission_status == 0), "accepted flag disagrees with last admission")
        _require(native237_emit_count <= 1, "one scan generation emitted duplicate native 237 calls")
        _require(emit_called_b == (native237_emit_count != 0), "native 237 emit flag/count mismatch")

        if has_first201_b:
            _require(event201_count > 0 and first201_ns <= last201_ns, "invalid 201 interval")
        else:
            _require(event201_count == 0 and first201_ns == 0 and last201_ns == 0,
                     "201 fields set without an emitted 201")
        if has_fw_b:
            _require(firmware_status in (1, 2), "invalid consumed firmware terminal status")
        else:
            _require(firmware_status == 0xFFFFFFFF and firmware_consumed_ns == 0,
                     "firmware terminal fields set without a consumed terminal")
        if has_native_b:
            _require(terminal_source != 0, "native 237 has no terminal source")
        else:
            _require(native237_status == 0xFFFFFFFF and terminal_source == 0,
                     "native 237 fields set without a terminal")
        if native237_emit_count == 0:
            _require(native237_emit_ns == 0, "native emit timestamp set without an emit callback")
        if busy_attempts == 0:
            _require(busy_class == 0 and busy_reason_code == 0, "Busy reason set without Busy attempt")
        if busy_class == 6:
            _require(busy_reason_code != 0, "radio-reported Busy class has no reason code")

        records.append({
            "request_serial": request_serial,
            "hal_generation": generation,
            "replaces_serial": replaces_serial,
            "replaced_by_serial": replaced_by_serial,
            "admission_attempts": admission_attempts,
            "radio_attempts": radio_attempts,
            "busy_attempts": busy_attempts,
            "busy_class": BUSY_CLASS[busy_class],
            "busy_reason_code": busy_reason_code,
            "last_admission": STATUS[admission_status],
            "event201_count": event201_count,
            "first201_ns": first201_ns,
            "last201_ns": last201_ns,
            "firmware_status": firmware_status if has_fw_b else None,
            "firmware_terminal_consumed_ns": firmware_consumed_ns if has_fw_b else None,
            "native237_status": native237_status if has_native_b else None,
            "native237_source": TERMINAL_SOURCE[terminal_source],
            "native237_emit_call_count": native237_emit_count,
            "native237_emit_call_ns": native237_emit_ns if emit_called_b else None,
            "clock_source": CLOCK_SOURCE[clock_source],
            "request_ns": request_ns,
            "first_radio_attempt_ns": first_radio_ns if has_first_radio_b else None,
            "last_radio_attempt_ns": last_radio_ns if has_first_radio_b else None,
            "accepted_ns": accepted_ns if has_accepted_b else None,
            "stale_terminals": stale_terminals,
        })

    return {
        "schema": version,
        "record_bytes": record_bytes,
        "retained_count": count,
        "request_count": requests,
        "replacement_count": replacements,
        "overwrite_count": overwrites,
        "stale_terminal_count": stale_total,
        "records": records,
    }


def decode_power(data: bytes, *, schema: int, record_bytes: int) -> dict[str, Any]:
    _require(schema == POWER_SCHEMA, "unsupported power schema")
    _require(record_bytes == POWER_ENTRY_BYTES, "power RecordBytes mismatch")
    _require(len(data) == POWER_SNAPSHOT_BYTES, "power snapshot size mismatch")
    version, capacity, count, newest = struct.unpack_from("<IIII", data, 0)
    _require(version == POWER_SCHEMA, "power wire version mismatch")
    _require(capacity == POWER_CAPACITY, "power capacity mismatch")
    _require(count <= POWER_CAPACITY, "power entry count exceeds capacity")
    entries: list[dict[str, Any]] = []
    for index in range(POWER_CAPACITY):
        start = POWER_HEADER_BYTES + index * POWER_ENTRY_BYTES
        raw = data[start : start + POWER_ENTRY_BYTES]
        if index >= count:
            _require(not any(raw), "unused power entry is not zero-filled")
            continue
        values = struct.unpack("<QQ8IiI", raw)
        (time_ns, revision, sequence, call_id, operation, phase, epoch, power_flags,
         interface_flags, detail, result, reserved) = values
        _require(sequence != 0 and call_id != 0, "power entry sequence/call id is zero")
        _require(operation in POWER_OPERATION, "unknown power operation")
        _require(phase in POWER_PHASE, "unknown power phase")
        _require(reserved == 0, "power entry reserved field is nonzero")
        entries.append({
            "monotonic_ns": time_ns,
            "transition_revision": revision,
            "sequence": sequence,
            "call_id": call_id,
            "operation": POWER_OPERATION[operation],
            "phase": POWER_PHASE[phase],
            "power_epoch": epoch,
            "power_flags": power_flags,
            "interface_flags": interface_flags,
            "detail": detail,
            "result": result,
        })
    if entries:
        _require(entries[-1]["sequence"] == newest, "power newest sequence mismatch")
    else:
        _require(newest == 0, "empty power snapshot has a newest sequence")
    return {"schema": version, "record_bytes": record_bytes, "capacity": capacity,
            "count": count, "newest_sequence": newest, "entries": entries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("scan", "power"))
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--schema", type=int, required=True)
    parser.add_argument("--record-bytes", type=int, required=True)
    args = parser.parse_args()
    data = args.snapshot.read_bytes()
    if args.kind == "scan":
        decoded = decode_scan(data, schema=args.schema, record_bytes=args.record_bytes)
    else:
        decoded = decode_power(data, schema=args.schema, record_bytes=args.record_bytes)
    print(json.dumps(decoded, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
