#!/usr/bin/env python3
"""Decode the fixed-size NativePowerTrace IORegistry property.

Unknown operation, phase, and detail values are preserved as numeric unknowns;
they are not treated as capture failures. Input may be a raw 1808-byte snapshot
or a plist containing an IORegistry entry with a NativePowerTrace data value.
"""

from __future__ import annotations

import argparse
import json
import plistlib
import struct
from pathlib import Path
from typing import Any


HEADER = struct.Struct("<IIII")
ENTRY = struct.Struct("<QQIIIIIIIIiI")
SCHEMA_VERSION = 1

OPERATIONS = {
    0: "none",
    1: "power_set",
    2: "address",
    3: "apple_disassociate",
    4: "wcl_leave",
    5: "wcl_abort_join",
    6: "hal_event",
    7: "system_power",
}
PHASES = {
    0: "unknown",
    1: "call_begin",
    2: "native_action_begin",
    3: "native_action_end",
    4: "wait_begin",
    5: "wait_end",
    6: "disable_begin",
    7: "disable_end",
    8: "enable_begin",
    9: "enable_end",
    10: "disassociate_begin",
    11: "disassociate_mgmt_end",
    12: "disassociate_state_end",
    13: "address_quiesce_begin",
    14: "address_quiesce_end",
    15: "address_commit",
    16: "driver_event",
    17: "notification_call",
    18: "timeout",
    19: "call_end",
    20: "system_power_begin",
    21: "wake_restore_decision",
    22: "wake_restore_end",
    23: "system_power_ack",
    24: "system_power_adapter_end",
}
SYSTEM_POWER_DETAILS = {
    1: "sleep",
    2: "wake",
    3: "wake_requested_off",
    4: "wake_stopping",
    5: "wake_hal_unavailable",
    6: "wake_interface_unavailable",
    7: "wake_already_active",
    8: "wake_partial_interface",
    9: "wake_restore_attempt",
    10: "sleep_stopping",
    11: "wake_superseded_by_newer_off",
    12: "sleep_superseded_by_newer_on",
}


class DecodeError(ValueError):
    pass


def _find_trace(value: Any) -> bytes | None:
    if isinstance(value, dict):
        trace = value.get("NativePowerTrace")
        if isinstance(trace, bytes):
            return trace
        for child in value.values():
            found = _find_trace(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_trace(child)
            if found is not None:
                return found
    return None


def extract_snapshot(data: bytes) -> bytes:
    try:
        value = plistlib.loads(data)
    except Exception:
        return data
    snapshot = _find_trace(value)
    if snapshot is None:
        raise DecodeError("plist does not contain NativePowerTrace data")
    return snapshot


def _label(mapping: dict[int, str], value: int) -> dict[str, Any]:
    return {"value": value, "name": mapping.get(value, "unknown")}


def decode(data: bytes) -> dict[str, Any]:
    snapshot = extract_snapshot(data)
    if len(snapshot) < HEADER.size:
        raise DecodeError("snapshot header is truncated")
    schema, capacity, count, newest_sequence = HEADER.unpack_from(snapshot)
    if schema != SCHEMA_VERSION:
        raise DecodeError(f"unsupported schema version {schema}")
    if capacity == 0 or count > capacity:
        raise DecodeError("invalid capacity or entry count")
    expected_size = HEADER.size + capacity * ENTRY.size
    if len(snapshot) != expected_size:
        raise DecodeError(
            f"snapshot size {len(snapshot)} does not match header size {expected_size}"
        )

    entries = []
    for index in range(count):
        fields = ENTRY.unpack_from(snapshot, HEADER.size + index * ENTRY.size)
        (monotonic_ns, transition_revision, sequence, call_id, operation,
         phase, power_epoch, power_flags, interface_flags, detail, result,
         auxiliary) = fields
        operation_label = _label(OPERATIONS, operation)
        phase_label = _label(PHASES, phase)
        detail_map = SYSTEM_POWER_DETAILS if operation == 7 else {}
        entries.append({
            "monotonicNs": monotonic_ns,
            "transitionRevision": transition_revision,
            "sequence": sequence,
            "callId": call_id,
            "operation": operation_label,
            "phase": phase_label,
            "powerEpoch": power_epoch,
            "powerFlags": {
                "value": power_flags,
                "requested": bool(power_flags & 1),
                "ready": bool(power_flags & 2),
            },
            "interfaceFlags": {
                "value": interface_flags,
                "up": bool(interface_flags & 1),
                "running": bool(interface_flags & 0x40),
            },
            "detail": _label(detail_map, detail),
            "result": {"iorReturn": result, "hex": f"0x{result & 0xffffffff:08x}"},
            "auxiliary": auxiliary,
        })
    return {
        "status": "decoded",
        "schemaVersion": schema,
        "capacity": capacity,
        "count": count,
        "newestSequence": newest_sequence,
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    try:
        decoded = decode(args.snapshot.read_bytes())
    except (OSError, DecodeError) as error:
        parser.error(str(error))
    print(json.dumps(decoded, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
