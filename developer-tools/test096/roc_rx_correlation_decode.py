#!/usr/bin/env python3
"""Decode the fixed-width ROC scoped RX copy-correlation snapshot."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


MAGIC = b"IRXROC01"
SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
LEGACY_HEADER_BYTES = 128
HEADER_BYTES = 192
RECORD_BYTES = 192
CAPACITY = 64
WIRE_BYTES = HEADER_BYTES + RECORD_BYTES * CAPACITY

HEADER_V1 = struct.Struct("<8s12I 5Q 8I")
HEADER_V2 = struct.Struct("<8s12I 5Q 24I")
HEADER = HEADER_V1  # Kept for callers constructing legacy v1 fixtures.
RECORD_HEADER = struct.Struct("<3Q 2I 4H I 8s 4B")
NOTIFICATION = struct.Struct("<4B I 4H")
MPDU = struct.Struct("<I 3B x 5H 2B I Q")

STATE_DISABLED = 0
STATE_ARMED = 1
STATE_ACTIVE = 2
STATE_CLOSED = 3
KNOWN_STATES = {STATE_DISABLED, STATE_ARMED, STATE_ACTIVE, STATE_CLOSED}
KNOWN_CLOSE_REASONS = set(range(7))
RX_WINDOW_STAGES = {
    0: "unknown",
    1: "no_host_rx_interrupt_handler_observed",
    2: "rx_interrupt_without_drain",
    3: "drain_without_ring_slot",
    4: "ring_slots_without_notification",
    5: "rejected_notifications_only",
    6: "validated_non_mpdu_notifications_only",
    7: "rx_mpdu_notification_validated_seen",
    8: "invalid_counters_or_timeline",
    9: "notification_seen_without_validation",
    10: "mixed_notification_results",
    11: "boundary_spanning_partial_rx_service",
}

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
    if schema not in (LEGACY_SCHEMA_VERSION, SCHEMA_VERSION):
        raise DecodeError(f"unsupported schema version {schema}")
    expected_header = LEGACY_HEADER_BYTES if schema == LEGACY_SCHEMA_VERSION else HEADER_BYTES
    if len(blob) < expected_header:
        raise DecodeError("snapshot is shorter than its declared header")
    if (header_bytes, record_bytes, capacity) != (
            expected_header, RECORD_BYTES, CAPACITY):
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
    if schema == SCHEMA_VERSION:
        values.update({
            "rxWindowFlags": _read_u32(blob, 128),
            "rxWindowStage": _read_u32(blob, 132),
            "rxWindowStageName": RX_WINDOW_STAGES.get(_read_u32(blob, 132), "invalid"),
            "rxInterruptHandlerCalls": _read_u32(blob, 136),
            "rxLegacyCauseCalls": _read_u32(blob, 140),
            "rxMsixQueueCauseCalls": _read_u32(blob, 144),
            "rxDrainCalls": _read_u32(blob, 148),
            "rxRingSlots": _read_u32(blob, 152),
            "rxNotificationSeen": _read_u32(blob, 156),
            "rxNotificationValidated": _read_u32(blob, 160),
            "rxNotificationRejected": _read_u32(blob, 164),
            "rxValidatedNonMpdu": _read_u32(blob, 168),
            "rxMpduNotificationValidated": _read_u32(blob, 172),
            "rxFirstSlot": _read_u32(blob, 176),
            "rxLastSlot": _read_u32(blob, 180),
            "rxFirstHead": _read_u32(blob, 184),
            "rxLastHead": _read_u32(blob, 188),
            "rxWindowSummaryAvailable": True,
        })
    else:
        values.update({
            "rxWindowFlags": None,
            "rxWindowStage": None,
            "rxWindowStageName": "not_recorded_in_schema_v1",
            "rxWindowSummaryAvailable": False,
        })
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
    if schema == SCHEMA_VERSION:
        flags = values["rxWindowFlags"]
        stage = values["rxWindowStage"]
        if flags & ~0x1f or stage not in RX_WINDOW_STAGES:
            raise DecodeError("RX window summary has unknown flags or stage")
        started = bool(flags & 1)
        ended = bool(flags & 2)
        counter_overflow = bool(flags & 4)
        timeline_invalid = bool(flags & 8)
        boundary_partial = bool(flags & 16)
        if (counter_overflow or timeline_invalid) and started and ended:
            if stage != 8:
                raise DecodeError("invalid RX timeline/counter lacks invalid stage")
        elif (values["rxLegacyCauseCalls"] + values["rxMsixQueueCauseCalls"] !=
                values["rxInterruptHandlerCalls"]):
            raise DecodeError("RX interrupt source counts do not sum to total")
        if not counter_overflow:
            if values["rxNotificationValidated"] != (
                    values["rxValidatedNonMpdu"] +
                    values["rxMpduNotificationValidated"]):
                raise DecodeError("RX notification validation counts disagree")
            if values["rxNotificationSeen"] < (
                    values["rxNotificationValidated"] +
                    values["rxNotificationRejected"]):
                raise DecodeError("RX notification stages exceed seen count")
        has_slot = values["rxRingSlots"] != 0
        slot_values = (
            values["rxFirstSlot"], values["rxLastSlot"],
            values["rxFirstHead"], values["rxLastHead"])
        if has_slot and any(value >= 512 for value in slot_values):
            raise DecodeError("RX ring slot/head is outside its ring")
        if not has_slot and any(slot_values):
            raise DecodeError("RX slot/head values exist without slot visits")
        service_coverage_gap = (
            (values["rxInterruptHandlerCalls"] == 0 and
             (values["rxDrainCalls"] or values["rxRingSlots"] or
              values["rxNotificationSeen"])) or
            (values["rxDrainCalls"] == 0 and
             (values["rxRingSlots"] or values["rxNotificationSeen"])) or
            (values["rxRingSlots"] == 0 and values["rxNotificationSeen"] != 0))
        if service_coverage_gap and not boundary_partial:
            # Keep v2 fail-closed for timelines that cannot be explained by a
            # START/END notification sharing a host RX service batch.
            raise DecodeError("RX service-stage counters contradict without boundary evidence")
        if (service_coverage_gap and boundary_partial and started and ended and
                not (counter_overflow or timeline_invalid) and
                values["rxNotificationSeen"] == 0 and
                values["rxNotificationValidated"] == 0 and
                values["rxNotificationRejected"] == 0 and stage != 11):
            raise DecodeError("unclassified boundary service gap lacks partial stage")
        if stage != 0 and not (started and ended):
            raise DecodeError("classified RX summary lacks successful START/END")
        if started and ended and stage == 0:
            raise DecodeError("successful RX START/END lacks a classified stage")
        if ended and state != STATE_CLOSED:
            raise DecodeError("RX summary says END while ROC is open")
        if stage == 1 and not (
                values["rxInterruptHandlerCalls"] == 0 and
                values["rxDrainCalls"] == 0 and
                values["rxRingSlots"] == 0 and
                values["rxNotificationSeen"] == 0):
            raise DecodeError("no-interrupt stage contradicts RX path counts")
        if stage == 2 and not (
                values["rxInterruptHandlerCalls"] and
                not values["rxDrainCalls"] and
                not values["rxRingSlots"] and
                not values["rxNotificationSeen"]):
            raise DecodeError("interrupt-without-drain stage contradicts counts")
        if stage == 3 and not (
                values["rxDrainCalls"] and not values["rxRingSlots"] and
                not values["rxNotificationSeen"]):
            raise DecodeError("drain-without-slot stage contradicts counts")
        if stage == 4 and not (
                values["rxRingSlots"] and not values["rxNotificationSeen"]):
            raise DecodeError("slot-without-notification stage contradicts counts")
        if stage == 5 and not (
                values["rxNotificationSeen"] and
                values["rxNotificationRejected"] and
                not values["rxNotificationValidated"] and
                values["rxNotificationSeen"] ==
                    values["rxNotificationRejected"]):
            raise DecodeError("rejected-only stage contradicts counts")
        if stage == 6 and not (
                values["rxNotificationValidated"] and
                values["rxValidatedNonMpdu"] ==
                    values["rxNotificationValidated"] and
                not values["rxNotificationRejected"] and
                values["rxNotificationSeen"] ==
                    values["rxNotificationValidated"]):
            raise DecodeError("validated-control-only stage contradicts counts")
        if stage == 7 and not values["rxMpduNotificationValidated"]:
            raise DecodeError("RX_MPDU notification stage contradicts counts")
        if stage == 8 and not (counter_overflow or timeline_invalid):
            raise DecodeError("invalid RX stage lacks overflow/timeline flag")
        if stage == 9 and not (
                values["rxNotificationSeen"] >
                values["rxNotificationValidated"] +
                values["rxNotificationRejected"]):
            raise DecodeError("unclassified-notification stage contradicts counts")
        if stage == 10 and not (
                values["rxNotificationRejected"] and
                values["rxNotificationValidated"] and
                values["rxNotificationSeen"] ==
                    values["rxNotificationValidated"] +
                    values["rxNotificationRejected"]):
            raise DecodeError("mixed-notification stage contradicts counts")
        if stage == 11 and not (
                started and ended and boundary_partial and service_coverage_gap and
                values["rxNotificationSeen"] == 0 and
                values["rxNotificationValidated"] == 0 and
                values["rxNotificationRejected"] == 0):
            raise DecodeError("partial RX service stage contradicts evidence")
    return values


def _decode_record(blob: bytes, index: int, header_bytes: int) -> dict[str, Any]:
    base = header_bytes + index * RECORD_BYTES
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
    if len(blob) < LEGACY_HEADER_BYTES:
        raise DecodeError(f"expected at least {LEGACY_HEADER_BYTES} bytes, got {len(blob)}")
    header = _decode_header(blob)
    expected_bytes = header["headerBytes"] + RECORD_BYTES * CAPACITY
    if len(blob) != expected_bytes:
        raise DecodeError(f"expected exactly {expected_bytes} bytes, got {len(blob)}")
    records = [_decode_record(blob, i, header["headerBytes"])
               for i in range(header["recordCount"])]
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
            "hostRxStageIsRfReceipt": False,
            "rxMpduNotificationValidatedIsAwdlOrDataProof": False,
            "endControlNotificationDoesNotProveFullWindowActivity": True,
            "boundaryPartialMayOmitOuterRxServiceStages": True,
            "boundaryPartialPreservesObservedNotificationCounts": True,
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
