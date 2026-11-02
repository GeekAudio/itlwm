#!/usr/bin/env python3
"""Decode AirportItlwm's private, numeric-only Wi-Fi state trace.

Input is the raw fixed-size OSData payload or an ``ioreg -a`` plist containing
the ``NativeWifiStateTrace`` property. The decoder never handles SSID/BSSID or
key bytes. A missing query kind is reported as unknown/not observed, not pass.
"""

from __future__ import annotations

import argparse
import json
import plistlib
import struct
from pathlib import Path
from typing import Any


HEADER = struct.Struct("<10I")
ENTRY = struct.Struct("<QQQQIIIIIiIIII")
SCHEMA_VERSION = 1
CAPACITY = 16
KIND_COUNT = 4

KINDS = {
    0: "get_power",
    1: "get_ssid",
    2: "get_bssid",
    3: "wcl_link_event_216",
}
FLAGS = {
    0: "pm_requested_on",
    1: "hal_ready",
    2: "system_pm_on",
    3: "state_lock_missing",
    4: "restart_active",
    5: "restart_committed",
    6: "fault_serial_valid",
    7: "fault_serial_matches",
    8: "restart_identity_matches",
    9: "restart_epoch_matches",
    10: "restart_revision_matches",
    11: "value_valid",
    12: "current_bss_ssid_source",
    13: "desired_ssid_source",
    14: "controller_run",
    15: "bss_present",
    16: "desired_bssid_comparison_valid",
    17: "bssid_matches_desired",
    18: "link_up",
    19: "linkdown_debounce_active",
    20: "emit_call_only_no_ack",
    21: "restart_validation_evaluated",
}
KNOWN_FLAGS = (1 << len(FLAGS)) - 1
VALUE_VALID = 1 << 11
CURRENT_BSS_SOURCE = 1 << 12
DESIRED_SSID_SOURCE = 1 << 13
ADDRESS_COMPARISON_VALID = 1 << 16
ADDRESS_MATCHES_DESIRED = 1 << 17
LINK_UP = 1 << 18
EMIT_CALL_ONLY = 1 << 20
RESTART_VALIDATION_EVALUATED = 1 << 21


class DecodeError(ValueError):
    pass


def _find_trace(value: Any) -> bytes | None:
    if isinstance(value, dict):
        payload = value.get("NativeWifiStateTrace")
        if isinstance(payload, bytes):
            return payload
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
        plist = plistlib.loads(data)
    except Exception:
        return data
    snapshot = _find_trace(plist)
    if snapshot is None:
        raise DecodeError("plist does not contain NativeWifiStateTrace data")
    return snapshot


def _decode_entry(blob: bytes, index: int) -> dict[str, Any]:
    fields = ENTRY.unpack_from(blob, index * ENTRY.size)
    (monotonic_ns, transition_revision, restart_id, restart_remaining_ns,
     sequence, kind, power_epoch, power_flags, fault_serial, result,
     flags, value, auxiliary, reserved) = fields
    if kind not in KINDS:
        raise DecodeError(f"entry {index} has unknown kind {kind}")
    if flags & ~KNOWN_FLAGS:
        raise DecodeError(f"entry {index} has unknown flag bits 0x{flags & ~KNOWN_FLAGS:x}")
    if reserved != 0:
        raise DecodeError(f"entry {index} has nonzero reserved field")
    if sequence == 0:
        raise DecodeError(f"entry {index} has invalid zero sequence")
    if flags & ADDRESS_MATCHES_DESIRED and not flags & ADDRESS_COMPARISON_VALID:
        raise DecodeError(f"entry {index} reports BSSID match without a valid comparison")
    if flags & CURRENT_BSS_SOURCE and flags & DESIRED_SSID_SOURCE:
        raise DecodeError(f"entry {index} has conflicting SSID sources")

    item: dict[str, Any] = {
        "sequence": sequence,
        "kind": KINDS[kind],
        "monotonicNs": monotonic_ns,
        "transitionRevision": transition_revision,
        "powerEpoch": power_epoch,
        "powerFlagsRaw": power_flags,
        "result": {"iorReturn": result, "hex": f"0x{result & 0xffffffff:08x}"},
        "flags": [name for bit, name in FLAGS.items() if flags & (1 << bit)],
        "valueValid": bool(flags & VALUE_VALID),
        "auxiliary": auxiliary,
    }
    if kind == 0:
        item.update({
            "requestedOn": bool(flags & 1),
            "halReady": bool(flags & 2),
            "systemPMOn": bool(flags & (1 << 2)),
            "powerLockMissing": bool(flags & (1 << 3)),
            "returnedPowerState": value if flags & VALUE_VALID else None,
            "radioCount": auxiliary,
            "restartId": restart_id or None,
            "restartRemainingNs": restart_remaining_ns,
            "faultSerial": fault_serial if flags & (1 << 6) else None,
            "restartValidationEvaluated": bool(flags & RESTART_VALIDATION_EVALUATED),
            "faultSerialMatches": (bool(flags & (1 << 7))
                                   if flags & RESTART_VALIDATION_EVALUATED else None),
            "restartIdentityMatches": (bool(flags & (1 << 8))
                                       if flags & RESTART_VALIDATION_EVALUATED else None),
            "restartEpochMatches": (bool(flags & (1 << 9))
                                    if flags & RESTART_VALIDATION_EVALUATED else None),
            "restartRevisionMatches": (bool(flags & (1 << 10))
                                       if flags & RESTART_VALIDATION_EVALUATED else None),
        })
    elif kind == 1:
        source = ("current_bss" if flags & CURRENT_BSS_SOURCE else
                  "desired_ssid" if flags & DESIRED_SSID_SOURCE else "none")
        item.update({"ssidLength": value if flags & VALUE_VALID else None,
                     "ssidSource": source})
    elif kind == 2:
        item.update({
            "bssidLength": value if flags & VALUE_VALID else None,
            "desiredBssidComparisonValid": bool(flags & ADDRESS_COMPARISON_VALID),
            "bssidMatchesDesired": (bool(flags & ADDRESS_MATCHES_DESIRED)
                                    if flags & ADDRESS_COMPARISON_VALID else None),
        })
    else:
        item.update({
            "linkUp": bool(flags & LINK_UP),
            "debounceActive": bool(flags & (1 << 19)),
            "eventCode": auxiliary,
            "acknowledged": None,
        })
    return item


def decode(data: bytes) -> dict[str, Any]:
    snapshot = extract_snapshot(data)
    if len(snapshot) < HEADER.size:
        raise DecodeError("snapshot header is truncated")
    (schema, capacity, count, newest_sequence, overwritten_count, reserved,
     power_get_calls, ssid_calls, bssid_calls, link_calls) = HEADER.unpack_from(snapshot)
    if schema != SCHEMA_VERSION:
        raise DecodeError(f"unsupported schema version {schema}")
    if capacity != CAPACITY:
        raise DecodeError(f"unexpected capacity {capacity}; expected {CAPACITY}")
    if reserved != 0:
        raise DecodeError("snapshot header has nonzero reserved field")
    if count > capacity:
        raise DecodeError("entry count exceeds capacity")
    expected_size = HEADER.size + capacity * ENTRY.size
    if len(snapshot) != expected_size:
        raise DecodeError(
            f"snapshot size {len(snapshot)} does not match fixed wire size {expected_size}"
        )
    if (count == 0) != (newest_sequence == 0):
        raise DecodeError("empty/count and newestSequence disagree")

    entries = []
    for index in range(count):
        offset = HEADER.size + index * ENTRY.size
        entries.append(_decode_entry(snapshot[offset:offset + ENTRY.size], 0))
    if entries and entries[-1]["sequence"] != newest_sequence:
        raise DecodeError("newestSequence does not match the newest entry")

    calls = [power_get_calls, ssid_calls, bssid_calls, link_calls]
    observed = {}
    for kind, name in KINDS.items():
        count_for_kind = calls[kind]
        observed[name] = {
            "state": "observed" if count_for_kind else "unknown_not_observed",
            "observedCallsAtSnapshot": count_for_kind,
        }

    # The overwrite counter saturates instead of wrapping, so this remains
    # reliable even if the entry sequence eventually wraps. Call counters are
    # only the value at this snapshot; duplicate polls are refreshed on the
    # next ingress publication even when the event sequence does not change.
    truncated = overwritten_count != 0
    return {
        "status": "decoded",
        "schemaVersion": schema,
        "capacity": capacity,
        "count": count,
        "newestSequence": newest_sequence,
        "historyTruncated": truncated,
        "overwrittenEntries": overwritten_count,
        "callCountsSemantics": "saturating observed-call counters captured in this snapshot; publication may lag one ingress tick",
        "observations": observed,
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path,
                        help="raw OSData bytes or an ioreg -a plist containing the property")
    args = parser.parse_args()
    try:
        decoded = decode(args.snapshot.read_bytes())
    except (OSError, DecodeError) as error:
        parser.error(str(error))
    print(json.dumps(decoded, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
