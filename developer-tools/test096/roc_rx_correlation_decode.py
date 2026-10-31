#!/usr/bin/env python3
"""Decode the fixed-width ROC scoped RX copy-correlation snapshot."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


MAGIC = b"IRXROC01"
SCHEMA_VERSION = 1
HEADER_BYTES = 128
RECORD_BYTES = 192
CAPACITY = 64
WIRE_BYTES = HEADER_BYTES + RECORD_BYTES * CAPACITY

HEADER = struct.Struct("<8s12I 5Q 8I")
RECORD_HEADER = struct.Struct("<3Q 2I 4H I 8s 4B")
NOTIFICATION = struct.Struct("<4B I 4H")
MPDU = struct.Struct("<I 3B x 5H 2B I Q")

STATE_DISABLED = 0
STATE_ARMED = 1
STATE_ACTIVE = 2
STATE_CLOSED = 3
KNOWN_STATES = {STATE_DISABLED, STATE_ARMED, STATE_ACTIVE, STATE_CLOSED}
KNOWN_CLOSE_REASONS = set(range(7))

RECORD_FINALIZED = 1 << 0
RECORD_COMPLETION_VALID = 1 << 1
RECORD_NOTIFICATION_OVERFLOW = 1 << 2
RECORD_MPDU_PRESENT = 1 << 3

MPDU_CHANNEL_PRESENT = 1 << 0
MPDU_RAW_MAC_PHY_PRESENT = 1 << 1
MPDU_DECODE_MODE_PRESENT = 1 << 2
MPDU_FRAME_CONTROL_PRESENT = 1 << 3
MPDU_SEQUENCE_CONTROL_PRESENT = 1 << 4
MPDU_RAW_STATUS_PRESENT = 1 << 5
MPDU_LENGTH_PRESENT = 1 << 6
MPDU_DESCRIPTOR_LENGTH_PRESENT = 1 << 7
MPDU_PACKET_OFFSET_PRESENT = 1 << 8
MPDU_TIME_PRESENT = 1 << 9
KNOWN_MPDU_FLAGS = (1 << 10) - 1
NOTIFICATION_OUTCOMES = {
    1: "seen", 2: "header_rejected", 3: "length_rejected",
    4: "validated", 5: "mpdu_dispatch", 6: "non_mpdu",
    7: "addbuf_failed", 8: "copy_failed", 9: "no_packet",
}


class DecodeError(ValueError):
    """Raised for malformed or unsupported snapshots."""


def _read_u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def _read_u64(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", blob, offset)[0]


def _decode_header(blob: bytes) -> dict[str, Any]:
    magic = blob[:8]
    if magic != MAGIC:
        raise DecodeError("wrong ROC correlation magic")
    schema = _read_u32(blob, 8)
    header_bytes = _read_u32(blob, 12)
    record_bytes = _read_u32(blob, 16)
    capacity = _read_u32(blob, 20)
    if schema != SCHEMA_VERSION:
        raise DecodeError(f"unsupported schema version {schema}")
    if (header_bytes, record_bytes, capacity) != (
            HEADER_BYTES, RECORD_BYTES, CAPACITY):
        raise DecodeError("wire dimensions do not match schema version")

    # Header fields from offset 8 through 127 are twelve DWORDs, five QWORDs,
    # and eight trailing DWORDs, all little-endian without native padding.
    state = _read_u32(blob, 24)
    values = {
        "schemaVersion": schema,
        "headerBytes": header_bytes,
        "recordBytes": record_bytes,
        "capacity": capacity,
        "state": state,
        "closeReason": _read_u32(blob, 28),
        "captureSerial": _read_u32(blob, 32),
        "driverGeneration": _read_u32(blob, 36),
        "contextGeneration": _read_u32(blob, 40),
        "powerGeneration": _read_u32(blob, 44),
        "stationGeneration": _read_u32(blob, 48),
        "rocGeneration": _read_u32(blob, 52),
        "sessionToken": _read_u64(blob, 56),
        "armUs": _read_u64(blob, 64),
        "startUs": _read_u64(blob, 72),
        "deadlineUs": _read_u64(blob, 80),
        "closedUs": _read_u64(blob, 88),
        "fullSlots": _read_u32(blob, 96),
        "retained": _read_u32(blob, 100),
        "overflow": _read_u32(blob, 104),
        "copySkips": _read_u32(blob, 108),
        "invalid": _read_u32(blob, 112),
        "unfinished": _read_u32(blob, 116),
        "coverageComplete": _read_u32(blob, 120),
        "recordCount": _read_u32(blob, 124),
    }
    if state not in KNOWN_STATES:
        raise DecodeError(f"unknown capture state {state}")
    if values["closeReason"] not in KNOWN_CLOSE_REASONS:
        raise DecodeError("unknown close reason")
    if state != STATE_CLOSED and values["closeReason"] != 0:
        raise DecodeError("open or disabled snapshot has a close reason")
    if state == STATE_CLOSED and values["closeReason"] == 0:
        raise DecodeError("closed snapshot has no close reason")
    if values["coverageComplete"] not in (0, 1):
        raise DecodeError("coverageComplete must be 0 or 1")
    if values["retained"] > CAPACITY or values["recordCount"] != values["retained"]:
        raise DecodeError("retained count is outside the fixed record capacity")
    if values["recordCount"] > values["fullSlots"]:
        raise DecodeError("record count exceeds visited slot count")
    if state == STATE_CLOSED and values["closedUs"] == 0:
        raise DecodeError("closed snapshot has no close timestamp")
    if state != STATE_CLOSED and values["closedUs"] != 0:
        raise DecodeError("open snapshot exposes a close timestamp")
    if state == STATE_ACTIVE and (
            values["startUs"] == 0 or values["deadlineUs"] < values["startUs"]):
        raise DecodeError("active snapshot has invalid ROC boundaries")
    if state == STATE_CLOSED and values["closeReason"] == 2 and (
            values["startUs"] == 0 or values["deadlineUs"] < values["startUs"]):
        raise DecodeError("END-closed snapshot has invalid ROC boundaries")
    if values["coverageComplete"] and (
            state != STATE_CLOSED or values["overflow"] or values["copySkips"] or
            values["invalid"] or values["unfinished"]):
        raise DecodeError("coverage is marked complete despite missing observations")
    return values


def _decode_record(blob: bytes, index: int) -> dict[str, Any]:
    base = HEADER_BYTES + index * RECORD_BYTES
    (sequence, copy_us, mapping_incarnation, capture_serial, driver_generation,
     ring, slot, head, flags, copy_status, completion, notification_count,
     notification_overflow, slot_parse_flags, reserved) = \
        RECORD_HEADER.unpack_from(blob, base)
    if flags & ~(RECORD_FINALIZED | RECORD_COMPLETION_VALID |
                 RECORD_NOTIFICATION_OVERFLOW | RECORD_MPDU_PRESENT):
        raise DecodeError(f"record {index} has unknown record flags")
    if reserved != 0:
        raise DecodeError(f"record {index} reserved byte is nonzero")
    if notification_count > 4 or notification_overflow not in (0, 1):
        raise DecodeError(f"record {index} has invalid notification counts")
    if bool(flags & RECORD_COMPLETION_VALID) != (copy_status == 1):
        raise DecodeError(f"record {index} completion-valid flag contradicts copy status")
    if not flags & RECORD_COMPLETION_VALID and any(completion):
        raise DecodeError(f"record {index} has bytes without a successful copy")
    if bool(flags & RECORD_NOTIFICATION_OVERFLOW) != bool(notification_overflow):
        raise DecodeError(f"record {index} notification overflow flags disagree")

    notifications = []
    for item in range(notification_count):
        offset = base + 56 + item * 16
        qid, packet_index, outcome, item_flags, code, packet_offset, payload_len, \
            packet_len, item_reserved = NOTIFICATION.unpack_from(blob, offset)
        if outcome not in NOTIFICATION_OUTCOMES:
            raise DecodeError(f"record {index} notification {item} has unknown outcome")
        if item_reserved != 0:
            raise DecodeError(f"record {index} notification {item} reserved bits are nonzero")
        notifications.append({
            "qid": qid, "index": packet_index, "outcome": outcome,
            "outcomeName": NOTIFICATION_OUTCOMES[outcome],
            "flags": item_flags, "code": code, "packetOffset": packet_offset,
            "payloadLength": payload_len, "packetLength": packet_len,
        })

    (mpdu_flags, channel, raw_mac_phy, decode_mode, frame_control,
     sequence_control, mpdu_length, descriptor_length, packet_offset,
     qid, packet_index, raw_status, mpdu_host_us) = \
        MPDU.unpack_from(blob, base + 120)
    if mpdu_flags & ~KNOWN_MPDU_FLAGS:
        raise DecodeError(f"record {index} has unknown MPDU field flags")
    copy_sequence = _read_u32(blob, base + 152)
    mpdu_present = bool(flags & RECORD_MPDU_PRESENT)
    if mpdu_present != bool(mpdu_flags):
        raise DecodeError(f"record {index} MPDU presence flags disagree")
    if mpdu_present and not flags & RECORD_FINALIZED:
        raise DecodeError(f"record {index} MPDU metadata was not finalized")
    if any(blob[base + 156:base + RECORD_BYTES]):
        raise DecodeError(f"record {index} extension bytes are nonzero")

    result: dict[str, Any] = {
        "sequence": sequence,
        "copyUs": copy_us,
        "mappingIncarnation": mapping_incarnation,
        "captureSerial": capture_serial,
        "driverGeneration": driver_generation,
        "ring": ring,
        "slot": slot,
        "head": head,
        "recordFlags": flags,
        "copyStatus": copy_status,
        "completionBytesValid": bool(flags & RECORD_COMPLETION_VALID),
        "completionBytes": completion.hex(),
        "notifications": notifications,
        "notificationOverflow": bool(notification_overflow),
        "slotParseFlags": slot_parse_flags,
        "mpduPresent": mpdu_present,
        "completionSequence": copy_sequence,
    }
    if mpdu_present:
        result["mpdu"] = {
            "fieldFlags": mpdu_flags,
            "channel": channel,
            "rawMacPhy": raw_mac_phy,
            "decodeMode": decode_mode,
            "frameControl": frame_control,
            "sequenceControl": sequence_control,
            "length": mpdu_length,
            "descriptorLength": descriptor_length,
            "packetOffset": packet_offset,
            "qid": qid,
            "index": packet_index,
            "rawStatus": raw_status,
            "hostRxUs": mpdu_host_us,
        }
    return result


def decode(blob: bytes, *, expected_identity: dict[str, int] | None = None,
           require_closed: bool = False) -> dict[str, Any]:
    """Decode one snapshot. Missing expected identity fields remain unknown."""
    if len(blob) != WIRE_BYTES:
        raise DecodeError(f"expected exactly {WIRE_BYTES} bytes, got {len(blob)}")
    header = _decode_header(blob)
    records = [_decode_record(blob, i) for i in range(header["recordCount"])]
    if header["state"] == STATE_CLOSED:
        if any(not record["recordFlags"] & RECORD_FINALIZED for record in records):
            raise DecodeError("closed snapshot contains an unfinished record")
        if header["unfinished"]:
            raise DecodeError("closed snapshot reports unfinished records")
    elif header["state"] == STATE_ACTIVE and require_closed:
        raise DecodeError("snapshot is still active")
    if header["coverageComplete"] and any(
            record["notificationOverflow"] for record in records):
        raise DecodeError("coverage is complete despite notification overflow")

    identity_match = None
    if expected_identity is not None:
        identity_fields = (
            "captureSerial", "driverGeneration", "contextGeneration",
            "powerGeneration", "stationGeneration", "rocGeneration",
            "sessionToken", "armUs", "startUs", "deadlineUs",
        )
        missing = [key for key in identity_fields if key not in expected_identity]
        if missing:
            identity_match = {"matched": False, "missing": missing}
        else:
            differences = {
                key: {"expected": expected_identity[key], "observed": header[key]}
                for key in identity_fields if expected_identity[key] != header[key]
            }
            identity_match = {"matched": not differences,
                              "differences": differences}

    closed = header["state"] == STATE_CLOSED
    return {
        **header,
        "closed": closed,
        "coverageComplete": bool(header["coverageComplete"]),
        "records": records,
        "identityMatch": identity_match,
        "evidenceLimits": {
            "sameDispatchNumericCorrelationOnly": True,
            "dmaOwnershipProven": False,
            "rawFreshnessProven": False,
            "completionCoherenceProven": False,
            "phyOwnershipProven": False,
            "peerOrSocketReceiptProven": False,
            "coverageCompleteEligibleSlotInternalOnly": True,
            "fullRocMpduCompletenessProven": False,
            "zeroEligibleSlotsProvesNoRocReceive": False,
            "zeroMpduRecordsProvesNoReceive": False,
            "noMpduDoesNotProvePhyOrFilterFailure": True,
            "rocStartAndFollowingMpduMayShareOneCopy": True,
            "armedCopyMayHaveNoSlotToken": True,
            "maximumMpduRecordsPerSlot": 1,
            "secondMpduInOneSlotFullyRepresented": False,
            "maximumNotificationsPerSlot": 4,
            "notificationEventsPastCapacityFullyRepresented": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("blob", type=Path, help="raw ROC correlation OSData")
    parser.add_argument("--require-closed", action="store_true")
    args = parser.parse_args()
    try:
        result = decode(args.blob.read_bytes(), require_closed=args.require_closed)
    except (OSError, DecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
