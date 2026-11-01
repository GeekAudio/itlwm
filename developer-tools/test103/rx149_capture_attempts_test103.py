#!/usr/bin/env python3
"""Strict decoder for Test103's bounded RX149 capture-attempt ledger.

The property is an LE64 numeric snapshot.  It records admission checks; it
does not carry packet bytes and cannot prove queue delivery, ifnet input, ROC
closure, or AirDrop.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any


PROPERTY = "NativeAwdlDataRx149CaptureAttempts"
SCHEMA = "test103-rx149-capture-attempts/v1"
MAGIC = 0x3130445041435852
WIRE_SCHEMA = 1
CAPACITY = 8
WORD_BYTES = 8
HEADER_FIELDS = (
    "Magic", "Schema", "WordCount", "Capacity", "ReservedBegin",
    "ReservedEnd", "CommittedMask", "OverflowObserved", "CompleteCut",
)
RECORD_FIELDS = (
    "Outcome", "FailureCheck", "EvaluatedMask", "PassedMask", "FrameLength",
    "FrameControl", "SequenceControl", "HeaderPresentMask", "PowerGeneration",
    "PermitOwner", "PermitContext", "PermitPower", "PermitStation", "PermitRoc",
    "PermitStartUs", "PermitCapturedUs", "PermitDeadlineUs", "PermitChannel",
    "PermitMacIndex", "PermitDecodeMode", "PermitRxStatus", "LeaseOwner",
    "LeaseContext", "LeasePower", "LeaseStation", "LeaseRoc", "LeaseStartUs",
    "LeaseNowUs", "LeaseFlags", "DecisionNowUs", "StatePresent", "FirstGateWord",
    "AuthorityGateWord", "ActiveOwner", "ActiveContext", "ActivePower",
    "ActiveStation", "ActiveRoc", "ActiveStartUs", "ActiveNowUs", "ActiveFlags",
    "ActiveVersion", "OwnerHighWater", "InterfaceIncarnation", "RadioGeneration",
    "BridgeFlags", "AttachedCount", "ClosingRequested", "ReceiptSequenceBefore",
    "ReceiptRevisionBefore", "QueueCountAtDecision", "AssignedReceiptSequence",
)
WORD_COUNT = len(HEADER_FIELDS) + CAPACITY * len(RECORD_FIELDS)
WIRE_BYTES = WORD_COUNT * WORD_BYTES
CHECK_MASK = (1 << 25) - 1
CHECK_NAMES = (
    "BridgeLock", "Unprotected", "LengthWithinLimit", "PermitValid",
    "PowerGenerationMatches", "FirstGateClear", "PermitCurrent",
    "AuthorityGateClear", "ActiveLeaseValid", "ActiveVersionNonzero",
    "LeaseIdentityMatches", "PermitIdentityMatches", "ActiveLeaseCurrent",
    "ActivePermitCurrent", "InterfaceIncarnationNonzero", "InterfacePresent",
    "NotClosing", "NotDetached", "RadioReady", "ClosingNotRequested",
    "RadioGenerationMatches", "Attached", "SequenceAvailable",
    "RevisionAvailable", "QueueSpaceAvailable",
)
OUTCOME_NAMES = {
    0: "not_awdl_data_candidate",
    1: "captured_to_bounded_queue",
    2: "rejected",
    3: "queue_full",
}


class CaptureLedgerError(ValueError):
    pass


def decode_capture_attempts(value: Any) -> dict:
    """Decode a property value while preserving incomplete/overflow states."""
    if value is None:
        return {
            "schema": SCHEMA, "status": "property_not_published", "records": [],
            "capture_delivery_proven": False, "ifnet_delivery_proven": False,
        }
    if not isinstance(value, bytes):
        raise CaptureLedgerError("capture_property_not_osdata")
    if len(value) != WIRE_BYTES:
        raise CaptureLedgerError("capture_wire_size_mismatch")
    words = struct.unpack("<" + "Q" * WORD_COUNT, value)
    header = dict(zip(HEADER_FIELDS, words[:len(HEADER_FIELDS)]))
    if (header["Magic"] != MAGIC or header["Schema"] != WIRE_SCHEMA or
            header["WordCount"] != WORD_COUNT or header["Capacity"] != CAPACITY):
        raise CaptureLedgerError("capture_wire_header_mismatch")
    begin, end = header["ReservedBegin"], header["ReservedEnd"]
    committed, overflow, complete = (
        header["CommittedMask"], header["OverflowObserved"], header["CompleteCut"])
    if (begin > CAPACITY or end > CAPACITY or end < begin or
            overflow not in (0, 1) or
            complete not in (0, 1) or committed >> CAPACITY or
            committed >> begin or (overflow and begin != CAPACITY)):
        raise CaptureLedgerError("capture_wire_header_value_invalid")
    expected_mask = (1 << begin) - 1 if begin else 0
    if complete and (begin != end or committed != expected_mask):
        raise CaptureLedgerError("capture_complete_cut_inconsistent")

    records = []
    offset = len(HEADER_FIELDS)
    for slot in range(CAPACITY):
        bit = 1 << slot
        if slot >= begin or not (committed & bit):
            continue
        start = offset + slot * len(RECORD_FIELDS)
        row = dict(zip(RECORD_FIELDS, words[start:start + len(RECORD_FIELDS)]))
        evaluated, passed = row["EvaluatedMask"], row["PassedMask"]
        failure = row["FailureCheck"]
        if (evaluated & ~CHECK_MASK or passed & ~CHECK_MASK or
                passed & ~evaluated or failure > 25 or
                (failure and (not (evaluated & (1 << (failure - 1))) or
                              (passed & (1 << (failure - 1)))))):
            raise CaptureLedgerError("capture_record_check_masks_invalid")
        records.append({
            "slot": slot,
            "outcome_name": OUTCOME_NAMES.get(row["Outcome"], "unknown_numeric_outcome"),
            "failure_check_name": (
                CHECK_NAMES[failure - 1] if failure else "none_recorded"),
            "fields": row,
        })

    status = ("stable_complete_cut_with_overflow" if complete and overflow else
              "stable_complete_cut" if complete else
              "partial_cut" if begin != end or committed != expected_mask else
              "complete_flag_not_set")
    return {
        "schema": SCHEMA,
        "status": status,
        "property": PROPERTY,
        "wire_sha256": hashlib.sha256(value).hexdigest(),
        "wire_bytes": len(value),
        "word_count": WORD_COUNT,
        "header": header,
        "records": records,
        "record_count": len(records),
        "overflow_observed": bool(overflow),
        "complete_cut": bool(complete),
        "complete_cut_is_freshness_proof": False,
        "capture_delivery_proven": False,
        "ifnet_delivery_proven": False,
        "roc_end_or_close_proven": False,
        "airdrop_proven": False,
    }


def summarize_capture_samples(samples: list[dict]) -> dict:
    """Keep the last valid fixed-capacity cut and describe sampling coverage."""
    decoded = []
    errors: dict[str, int] = {}
    for sample in samples:
        item = sample.get("rx149_capture_attempts") if isinstance(sample, dict) else None
        if not isinstance(item, dict):
            errors["missing_decoded_sample"] = errors.get("missing_decoded_sample", 0) + 1
            continue
        status = item.get("status", "unknown")
        if status == "collector_error":
            errors["collector_error"] = errors.get("collector_error", 0) + 1
        decoded.append(item)
    valid = [item for item in decoded if item.get("schema") == SCHEMA]
    latest = valid[-1] if valid else None
    return {
        "schema": SCHEMA,
        "status": latest.get("status") if latest else "no_valid_capture_sample",
        "sample_count": len(samples),
        "property_present_sample_count": sum(
            1 for item in valid if item.get("status") not in {
                "property_not_published", "collector_error",
            }),
        "latest_wire_sha256": latest.get("wire_sha256") if latest else None,
        "latest_record_count": latest.get("record_count", 0) if latest else 0,
        "latest_overflow_observed": latest.get("overflow_observed") if latest else None,
        "latest_complete_cut": latest.get("complete_cut") if latest else None,
        "sample_errors": errors,
        "complete_cut_is_freshness_proof": False,
        "capture_delivery_proven": False,
        "ifnet_delivery_proven": False,
        "airdrop_proven": False,
    }
