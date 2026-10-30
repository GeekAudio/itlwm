#!/usr/bin/env python3
"""Strict decoder for the Test087 NativeRxPreOwnerSnapshot wire record."""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence


WIRE_MAGIC = int.from_bytes(b"NRXOWN01", "little")
WIRE_VERSION = 1
WINDOW_US = 4_000_000
HEADER_WORDS = 3
KIND_NAMES = (
    "Irq",
    "Drain",
    "Slot",
    "NotificationSeen",
    "HeaderRejected",
    "LengthRejected",
    "NotificationValidated",
    "MpduDispatch",
    "AddbufFailed",
    "CopyFailed",
    "MpduEntry",
    "OwnerRecorderAccepted",
    "OwnerRecorderRejected",
)
RX_CLASS_NAMES = ("Unknown", "Sta", "Channel149", "Other")
OWNER_REASON_NAMES = (
    "Qualified",
    "InvalidInput",
    "MainGate",
    "LeaseInactive",
    "LeaseContextZero",
    "LeasePowerZero",
    "LeaseStationZero",
    "LeaseContextMismatchCurrent",
    "LeaseContextMismatchProbe",
    "LeasePowerMismatchLeaseCurrent",
    "LeaseStationMismatchLeaseCurrent",
    "PowerMismatchScGeneration",
    "PowerMismatchFwGeneration",
    "StationMismatchScGeneration",
    "RocMissing",
    "RocGenerationMismatchLease",
    "RocGenerationMismatchCurrent",
    "RocCommandPending",
    "RocCommandFailed",
    "RocWindowNotQualified",
    "RocTokenMismatch",
    "RocPhaseNotAcked",
    "Unknown",
)
IRQ_SOURCE_NAMES = ("None", "Legacy", "Msix")
CLOSE_REASON_NAMES = ("None", "Deadline", "Explicit", "Stop", "GenerationChanged")

EVENT_FIELDS = (
    ("nowUs", "u64"),
    ("generation", "u32"),
    ("kind", "kind"),
    ("rxClass", "rxClass"),
    ("ownerReason", "ownerReason"),
    ("irqSource", "irqSource"),
    ("irqCause", "u32"),
    ("notificationCode", "u32"),
    ("physicalRingPresent", "bool"),
    ("physicalRing", "u32"),
    ("physicalSlotPresent", "bool"),
    ("physicalSlot", "u32"),
    ("notificationQidPresent", "bool"),
    ("notificationQid", "u32"),
    ("notificationIndexPresent", "bool"),
    ("notificationIndex", "u32"),
    ("payloadLen", "u32"),
    ("descSize", "u32"),
    ("mpduLengthPresent", "bool"),
    ("mpduLength", "u32"),
    ("rawStatusPresent", "bool"),
    ("rawStatus", "u32"),
    ("rawMacPhyIndexPresent", "bool"),
    ("rawMacPhyIndex", "u32"),
    ("macPhyDecodeModePresent", "bool"),
    ("macPhyDecodeMode", "u32"),
    ("channelPresent", "bool"),
    ("channel", "u32"),
    ("macIndexPresent", "bool"),
    ("macIndex", "u32"),
    ("frameControlPresent", "bool"),
    ("frameControl", "u32"),
    ("sequenceControlPresent", "bool"),
    ("sequenceControl", "u32"),
    ("gp2OnAirRisePresent", "bool"),
    ("gp2OnAirRiseRaw", "u32"),
    ("tsfOnAirRisePresent", "bool"),
    ("tsfOnAirRiseRaw", "u64"),
    ("awdlCandidate", "bool"),
)
EVENT_WORDS = len(EVENT_FIELDS)
SNAPSHOT_WORDS = (
    1 + 1 + 1 + 4 + 3 + 1 + len(KIND_NAMES) + len(RX_CLASS_NAMES) +
    5 + len(OWNER_REASON_NAMES) + 12
)
WITNESS_BANK_CAPACITY = 8
WITNESS_WORDS = 1 + EVENT_WORDS
WIRE_WORDS = HEADER_WORDS + SNAPSHOT_WORDS + 2 * WITNESS_BANK_CAPACITY * WITNESS_WORDS
MAX_WIRE_WORDS = 1024
SNAPSHOT_OFFSET = HEADER_WORDS
SNAPSHOT_FIELD_INDEX = {
    "schemaVersion": 0,
    "captureSerial": 1,
    "driverGeneration": 2,
    "beginUs": 3,
    "endUs": 4,
    "deadlineUs": 5,
    "snapshotUs": 6,
    "active": 7,
    "closed": 8,
    "closeReason": 9,
    "totalEvents": 10,
    "lockContentionLoss": 56,
    "invalidSampleLoss": 57,
    "generationMismatchLoss": 58,
    "deadlineRejectCount": 59,
    "clockReversalLoss": 60,
    "witness149Overflow": 61,
    "witnessNon149Overflow": 62,
    "lossCount": 63,
    "overflow": 64,
    "counterOverflow": 65,
    "witness149Count": 66,
    "witnessNon149Count": 67,
}
EVENT_FIELD_INDEX = {name: index for index, (name, _) in enumerate(EVENT_FIELDS)}
assert EVENT_WORDS == 39
assert SNAPSHOT_WORDS == 68
assert WIRE_WORDS == 711


class DecodeError(ValueError):
    """The byte stream is missing fields or violates the published schema."""


def _enum_name(code: int, names: Sequence[str], field: str) -> str:
    if code >= len(names):
        raise DecodeError("invalid " + field + " enum value")
    return names[code]


def _saturating_add(left: int, right: int) -> int:
    return min(0xFFFFFFFF, left + right)


def _read_event(words: Sequence[int], index: int) -> tuple[Dict[str, Any], int]:
    event: Dict[str, Any] = {}
    for field, field_type in EVENT_FIELDS:
        if index >= len(words):
            raise DecodeError("truncated event")
        value = words[index]
        index += 1
        if field_type != "u64" and value > 0xFFFFFFFF:
            raise DecodeError("32-bit event field overflow: " + field)
        if field_type == "bool":
            if value not in (0, 1):
                raise DecodeError("invalid boolean event field: " + field)
            event[field] = bool(value)
        elif field_type == "kind":
            event[field + "Code"] = value
            event[field] = _enum_name(value, KIND_NAMES, field)
        elif field_type == "rxClass":
            event[field + "Code"] = value
            event[field] = _enum_name(value, RX_CLASS_NAMES, field)
        elif field_type == "ownerReason":
            event[field + "Code"] = value
            event[field] = _enum_name(value, OWNER_REASON_NAMES, field)
        elif field_type == "irqSource":
            event[field + "Code"] = value
            event[field] = _enum_name(value, IRQ_SOURCE_NAMES, field)
        else:
            event[field] = value

    optional_pairs = (
        ("physicalRingPresent", "physicalRing"),
        ("physicalSlotPresent", "physicalSlot"),
        ("notificationQidPresent", "notificationQid"),
        ("notificationIndexPresent", "notificationIndex"),
        ("mpduLengthPresent", "mpduLength"),
        ("rawStatusPresent", "rawStatus"),
        ("rawMacPhyIndexPresent", "rawMacPhyIndex"),
        ("macPhyDecodeModePresent", "macPhyDecodeMode"),
        ("channelPresent", "channel"),
        ("macIndexPresent", "macIndex"),
        ("frameControlPresent", "frameControl"),
        ("sequenceControlPresent", "sequenceControl"),
        ("gp2OnAirRisePresent", "gp2OnAirRiseRaw"),
        ("tsfOnAirRisePresent", "tsfOnAirRiseRaw"),
    )
    for present_field, value_field in optional_pairs:
        if not event[present_field]:
            if event[value_field] != 0:
                raise DecodeError("absent event field carries a value: " + value_field)
            event[value_field] = None

    notification_kinds = {
        "NotificationSeen",
        "HeaderRejected",
        "LengthRejected",
        "NotificationValidated",
    }
    if event["kind"] not in notification_kinds and event["notificationCode"] != 0:
        raise DecodeError("notification code on non-notification event")
    if event["irqSource"] == "None" and event["irqCause"] != 0:
        raise DecodeError("IRQ cause present without IRQ source")
    if event["frameControl"] is not None and event["frameControl"] > 0xFFFF:
        raise DecodeError("frame control exceeds 16 bits")
    if event["sequenceControl"] is not None and event["sequenceControl"] > 0xFFFF:
        raise DecodeError("sequence control exceeds 16 bits")
    if event["rawMacPhyIndex"] is not None and event["rawMacPhyIndex"] > 0xFF:
        raise DecodeError("raw PHY index exceeds 8 bits")
    if event["macPhyDecodeMode"] is not None and event["macPhyDecodeMode"] > 2:
        raise DecodeError("unsupported MAC/PHY decode mode")
    if event["rxClass"] == "Channel149" and (
        event["channel"] is None or event["channel"] != 149
    ):
        raise DecodeError("channel-149 class lacks channel 149")
    return event, index


def _event_is_zero(event: Dict[str, Any]) -> bool:
    for field, _ in EVENT_FIELDS:
        value = event.get(field + "Code", event.get(field))
        if value is not None and value != 0:
            return False
    return True


def _read_u32(words: Sequence[int], index: int, field: str) -> tuple[int, int]:
    if index >= len(words):
        raise DecodeError("truncated snapshot at " + field)
    value = words[index]
    if value > 0xFFFFFFFF:
        raise DecodeError("32-bit snapshot field overflow: " + field)
    return value, index + 1


def _read_u64(words: Sequence[int], index: int, field: str) -> tuple[int, int]:
    if index >= len(words):
        raise DecodeError("truncated snapshot at " + field)
    return words[index], index + 1


def _parse_snapshot(words: Sequence[int]) -> Dict[str, Any]:
    index = HEADER_WORDS
    snapshot: Dict[str, Any] = {}

    snapshot["schemaVersion"], index = _read_u32(words, index, "schemaVersion")
    snapshot["captureSerial"], index = _read_u64(words, index, "captureSerial")
    snapshot["driverGeneration"], index = _read_u32(words, index, "driverGeneration")
    for field in ("beginUs", "endUs", "deadlineUs", "snapshotUs"):
        snapshot[field], index = _read_u64(words, index, field)
    for field in ("active", "closed"):
        value, index = _read_u32(words, index, field)
        if value not in (0, 1):
            raise DecodeError("invalid snapshot boolean: " + field)
        snapshot[field] = bool(value)
    close_code, index = _read_u32(words, index, "closeReason")
    snapshot["closeReasonCode"] = close_code
    snapshot["closeReason"] = _enum_name(close_code, CLOSE_REASON_NAMES, "closeReason")
    scalar_names_before_arrays = ("totalEvents",)
    for field in scalar_names_before_arrays:
        snapshot[field], index = _read_u32(words, index, field)

    snapshot["kindCounts"] = {}
    for name in KIND_NAMES:
        snapshot["kindCounts"][name], index = _read_u32(words, index, "kindCounts." + name)
    snapshot["rxClassCounts"] = {}
    for name in RX_CLASS_NAMES:
        snapshot["rxClassCounts"][name], index = _read_u32(words, index, "rxClassCounts." + name)

    counter_fields = (
        "dispatchCount",
        "mpduEntryCount",
        "awdlCandidateCount",
        "ownerQualifiedCount",
        "ownerFailedCount",
    )
    for field in counter_fields:
        snapshot[field], index = _read_u32(words, index, field)
    snapshot["ownerReasonCounts"] = {}
    for name in OWNER_REASON_NAMES:
        snapshot["ownerReasonCounts"][name], index = _read_u32(
            words, index, "ownerReasonCounts." + name
        )
    for field in (
        "lockContentionLoss",
        "invalidSampleLoss",
        "generationMismatchLoss",
        "deadlineRejectCount",
        "clockReversalLoss",
        "witness149Overflow",
        "witnessNon149Overflow",
        "lossCount",
        "overflow",
        "counterOverflow",
        "witness149Count",
        "witnessNon149Count",
    ):
        snapshot[field], index = _read_u32(words, index, field)
    for field in ("overflow", "counterOverflow"):
        if snapshot[field] not in (0, 1):
            raise DecodeError("invalid snapshot boolean: " + field)
        snapshot[field] = bool(snapshot[field])

    witnesses: Dict[str, List[Dict[str, Any]]] = {
        "channel149Witnesses": [],
        "non149Witnesses": [],
    }
    for bank in witnesses:
        for _ in range(WITNESS_BANK_CAPACITY):
            present, index = _read_u32(words, index, bank + ".present")
            if present not in (0, 1):
                raise DecodeError("invalid witness presence flag")
            event, index = _read_event(words, index)
            if not present and not _event_is_zero(event):
                raise DecodeError("absent witness contains nonzero event fields")
            witnesses[bank].append(
                {"present": bool(present), "event": event if present else None}
            )
    if index != len(words):
        raise DecodeError("internal wire parser did not consume fixed record")
    snapshot.update(witnesses)
    _validate_snapshot(snapshot)
    return snapshot


def _validate_snapshot(snapshot: Dict[str, Any]) -> None:
    if snapshot["schemaVersion"] != 1 or snapshot["captureSerial"] != 1:
        raise DecodeError("unsupported snapshot schema or capture serial")
    if snapshot["active"] == snapshot["closed"]:
        raise DecodeError("capture must be exactly active or closed")
    begin = snapshot["beginUs"]
    deadline = snapshot["deadlineUs"]
    snapshot_us = snapshot["snapshotUs"]
    end = snapshot["endUs"]
    if deadline < begin or deadline - begin != WINDOW_US:
        raise DecodeError("invalid capture time bounds")
    if snapshot_us < begin:
        raise DecodeError("snapshot precedes capture start")
    if snapshot["active"]:
        if end != 0 or snapshot["closeReason"] != "None":
            raise DecodeError("active capture carries closed-only fields")
    elif (
        end < begin or end > deadline or snapshot["closeReason"] == "None" or
        (snapshot["closeReason"] == "Deadline" and end != deadline)
    ):
        raise DecodeError("closed capture has invalid end time or close reason")

    kind_counts = snapshot["kindCounts"]
    class_counts = snapshot["rxClassCounts"]
    reason_counts = snapshot["ownerReasonCounts"]
    kind_total = 0
    for value in kind_counts.values():
        kind_total = _saturating_add(kind_total, value)
    class_total = 0
    for value in class_counts.values():
        class_total = _saturating_add(class_total, value)
    if not snapshot["counterOverflow"]:
        if kind_total != snapshot["totalEvents"] or class_total != snapshot["totalEvents"]:
            raise DecodeError("event/class counters do not match totalEvents")
        if snapshot["dispatchCount"] != kind_counts["MpduDispatch"]:
            raise DecodeError("dispatch counter mismatch")
        if snapshot["mpduEntryCount"] != kind_counts["MpduEntry"]:
            raise DecodeError("MPDU entry counter mismatch")

    entry_count = snapshot["mpduEntryCount"]
    qualified = snapshot["ownerQualifiedCount"]
    failed = snapshot["ownerFailedCount"]
    candidates = snapshot["awdlCandidateCount"]
    if max(qualified, failed, candidates) > entry_count:
        raise DecodeError("owner or AWDL candidate count exceeds MPDU entries")
    reasons_total = 0
    for value in reason_counts.values():
        reasons_total = _saturating_add(reasons_total, value)
    if not snapshot["counterOverflow"] and reasons_total != entry_count:
        raise DecodeError("owner reason counters do not match MPDU entries")
    if reason_counts["Qualified"] != qualified or _saturating_add(qualified, failed) != entry_count:
        raise DecodeError("owner qualified/failed counters disagree")

    loss_fields = (
        "lockContentionLoss",
        "invalidSampleLoss",
        "generationMismatchLoss",
        "deadlineRejectCount",
        "clockReversalLoss",
        "witness149Overflow",
        "witnessNon149Overflow",
    )
    loss_sum = 0
    for field in loss_fields:
        loss_sum += snapshot[field]
    expected_loss = min(0xFFFFFFFF, loss_sum)
    if snapshot["lossCount"] != expected_loss:
        raise DecodeError("loss counters do not match lossCount")

    overflow_by_witness = (
        snapshot["witness149Overflow"] > 0 or
        snapshot["witnessNon149Overflow"] > 0
    )
    expected_overflow = (
        snapshot["counterOverflow"] or overflow_by_witness or
        loss_sum > 0xFFFFFFFF
    )
    if snapshot["overflow"] != expected_overflow:
        raise DecodeError("overflow flag disagrees with loss counters")
    if snapshot["counterOverflow"]:
        counters = list(kind_counts.values()) + list(class_counts.values())
        counters.extend([
            snapshot["totalEvents"], snapshot["dispatchCount"],
            snapshot["mpduEntryCount"], snapshot["awdlCandidateCount"],
            qualified, failed,
        ])
        counters.extend(reason_counts.values())
        counters.extend(snapshot[field] for field in loss_fields)
        if 0xFFFFFFFF not in counters:
            raise DecodeError("counterOverflow set without a saturated counter")

    for bank_name, channel149 in (("channel149Witnesses", True), ("non149Witnesses", False)):
        bank = snapshot[bank_name]
        count_field = "witness149Count" if channel149 else "witnessNon149Count"
        count = snapshot[count_field]
        if count > WITNESS_BANK_CAPACITY:
            raise DecodeError("witness count exceeds bank capacity")
        for position, witness in enumerate(bank):
            if witness["present"] != (position < count):
                raise DecodeError("witness presence does not match count")
            if not witness["present"]:
                continue
            event = witness["event"]
            if event["kind"] != "MpduEntry":
                raise DecodeError("witness is not an MPDU entry")
            if event["generation"] != snapshot["driverGeneration"]:
                raise DecodeError("witness generation mismatch")
            if event["nowUs"] < begin or event["nowUs"] >= deadline:
                raise DecodeError("witness timestamp outside capture interval")
            is_channel149 = event["channel"] is not None and event["channel"] == 149
            if is_channel149 != channel149:
                raise DecodeError("witness stored in wrong channel bank")


def decode_blob(blob: bytes) -> Dict[str, Any]:
    """Decode and strictly validate one complete wire record."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise DecodeError("blob must be bytes-like")
    raw = bytes(blob)
    if len(raw) < HEADER_WORDS * 8:
        raise DecodeError("short wire header")
    if len(raw) % 8:
        raise DecodeError("wire size is not u64 aligned")
    magic, version, declared_words = struct.unpack_from("<QQQ", raw, 0)
    if magic != WIRE_MAGIC:
        raise DecodeError("wire magic mismatch")
    if version != WIRE_VERSION:
        raise DecodeError("unsupported wire version")
    if declared_words > MAX_WIRE_WORDS:
        raise DecodeError("declared wire size exceeds fixed 1024-word limit")
    if declared_words != WIRE_WORDS:
        raise DecodeError("wire word count does not match schema v1")
    if len(raw) != declared_words * 8:
        raise DecodeError("wire length differs from declared word count")
    words = struct.unpack("<" + "Q" * declared_words, raw)
    snapshot = _parse_snapshot(words)
    return {
        "wire": {"magic": "NRXOWN01", "version": version, "wordCount": declared_words},
        "snapshot": snapshot,
        "summary": _summary(snapshot),
        "evidenceScope": {
            "all_transport": "Host-side RX pipeline counters and bounded witnesses.",
            "channel149": "Channel metadata in accepted MPDU-entry witnesses; not RF proof.",
            "awdlCandidate": "Driver classifier count only; not peer receipt or AWDL proof.",
            "owner": "The production owner predicate result; not AirDrop success.",
            "endToEndAirDropProven": False,
            "provesSamePacketOnAir": False,
        },
    }


def _summary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "all_transport": {
            "totalEvents": snapshot["totalEvents"],
            "kindCounts": dict(snapshot["kindCounts"]),
            "rxClassCounts": dict(snapshot["rxClassCounts"]),
            "dispatchCount": snapshot["dispatchCount"],
            "mpduEntryCount": snapshot["mpduEntryCount"],
            "lossCount": snapshot["lossCount"],
            "overflow": snapshot["overflow"],
            "counterOverflow": snapshot["counterOverflow"],
        },
        "channel149": {
            "rxClassEventCount": snapshot["rxClassCounts"]["Channel149"],
            "witnessCount": snapshot["witness149Count"],
            "witnessOverflow": snapshot["witness149Overflow"],
        },
        "awdlCandidate": {
            "mpduEntryCount": snapshot["awdlCandidateCount"],
        },
        "owner": {
            "qualified": snapshot["ownerQualifiedCount"],
            "failed": snapshot["ownerFailedCount"],
            "reasonCounts": dict(snapshot["ownerReasonCounts"]),
        },
    }


def compare_three_reads(reads: Sequence[Optional[bytes]]) -> Dict[str, Any]:
    """Compare three saved property reads without inventing zero-filled data."""
    if len(reads) != 3:
        raise ValueError("exactly three saved reads are required")
    missing = [index for index, item in enumerate(reads) if item is None]
    if missing:
        return {
            "status": "missing",
            "stable": False,
            "complete": False,
            "missingReadIndexes": missing,
        }
    for index, item in enumerate(reads):
        if item is not None and not isinstance(item, (bytes, bytearray, memoryview)):
            raise DecodeError("saved read is not bytes-like at index " + str(index))
    blobs = [bytes(item) for item in reads if item is not None]
    lengths = [len(item) for item in blobs]
    if blobs[0] != blobs[1] or blobs[1] != blobs[2]:
        return {
            "status": "unstable",
            "stable": False,
            "complete": False,
            "readByteLengths": lengths,
        }
    decoded = decode_blob(blobs[0])
    closed = decoded["snapshot"]["closed"]
    return {
        "status": "complete" if closed else "active_incomplete",
        "stable": True,
        "complete": bool(closed),
        "readByteLengths": lengths,
        "decoded": decoded,
    }
