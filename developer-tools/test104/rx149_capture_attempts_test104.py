#!/usr/bin/env python3
"""Strict decoder for Test104's bounded RX149 capture-attempt ledger.

The property is an LE64 numeric snapshot.  It records admission checks; it
does not carry packet bytes and cannot prove queue delivery, ifnet input, ROC
closure, or AirDrop.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any


PROPERTY = "NativeAwdlDataRx149CaptureAttempts"
SCHEMA = "test104-rx149-capture-attempts/v1"
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
LEGACY_CHECK_MASK = (1 << 25) - 1
CHECK_MASK = (1 << 26) - 1
CHECK_NAMES = (
    "BridgeLock", "Unprotected", "LengthWithinLimit", "PermitValid",
    "PowerGenerationMatches", "FirstGateClear", "PermitCurrent",
    "AuthorityGateClear", "ActiveLeaseValid", "ActiveVersionNonzero",
    "LeaseIdentityMatches", "PermitIdentityMatches", "ActiveLeaseCurrent",
    "ActivePermitCurrent", "InterfaceIncarnationNonzero", "InterfacePresent",
    "NotClosing", "NotDetached", "RadioReady", "ClosingNotRequested",
    "RadioGenerationMatches", "Attached", "SequenceAvailable",
    "RevisionAvailable", "QueueSpaceAvailable", "RetryWindowSlotAvailable",
)
OUTCOME_NAMES = {
    0: "not_awdl_data_candidate",
    1: "captured_to_bounded_queue",
    2: "rejected",
    3: "queue_full",
    4: "duplicate_retry_not_queued",
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
            committed >> begin or (overflow and end != CAPACITY)):
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
        outcome = row["Outcome"]
        if (evaluated & ~CHECK_MASK or passed & ~CHECK_MASK or
                passed & ~evaluated or failure > len(CHECK_NAMES) or
                (failure and (not (evaluated & (1 << (failure - 1))) or
                              (passed & (1 << (failure - 1)))))):
            raise CaptureLedgerError("capture_record_check_masks_invalid")
        failed_mask = evaluated & ~passed
        if outcome == 0:
            # Non-candidates return before the production ledger append.
            raise CaptureLedgerError("capture_record_non_candidate_impossible")
        if outcome == 1:
            # Schema 1 was first deployed with 25 checks. Keep accepting those
            # immutable snapshots alongside the 26-check form.
            if (failure != 0 or evaluated not in (LEGACY_CHECK_MASK, CHECK_MASK) or
                    passed != evaluated or failed_mask != 0):
                raise CaptureLedgerError("capture_outcome_captured_failure_contradiction")
        elif outcome == 2:
            expected_evaluated = (1 << failure) - 1 if failure else 0
            expected_passed = expected_evaluated & ~(1 << (failure - 1)) if failure else 0
            if (failure == 0 or evaluated != expected_evaluated or
                    passed != expected_passed or
                    failed_mask != (1 << (failure - 1))):
                raise CaptureLedgerError("capture_outcome_rejected_failure_contradiction")
        elif outcome == 3:
            queue_space_bit = 1 << 24
            # QueueSpaceAvailable precedes RetryWindowSlotAvailable, so a full
            # queue terminates with the legacy 25-check prefix.
            if (failure != 25 or evaluated != LEGACY_CHECK_MASK or
                    passed != (LEGACY_CHECK_MASK & ~queue_space_bit) or
                    failed_mask != queue_space_bit):
                raise CaptureLedgerError("capture_outcome_queue_full_failure_contradiction")
        elif outcome == 4:
            # A retry duplicate has passed the retry-window check but is not
            # admitted to the bounded capture queue.
            if (failure != 0 or evaluated != CHECK_MASK or
                    passed != CHECK_MASK or failed_mask != 0):
                raise CaptureLedgerError("capture_outcome_duplicate_failure_contradiction")
        else:
            raise CaptureLedgerError("capture_record_outcome_unknown")
        records.append({
            "slot": slot,
            "outcome_name": OUTCOME_NAMES[outcome],
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
    """Separate the current sample from the last decodable historical cut."""
    decoded = []
    errors: dict[str, int] = {}
    last_sample_index = len(samples) - 1
    latest_item = None
    latest_status = None
    for index, sample in enumerate(samples):
        item = sample.get("rx149_capture_attempts") if isinstance(sample, dict) else None
        if not isinstance(item, dict):
            errors["missing_decoded_sample"] = errors.get("missing_decoded_sample", 0) + 1
            if index == last_sample_index:
                latest_status = "missing_decoded_sample"
            continue
        if index == last_sample_index:
            latest_item = item
            latest_status = item.get("status", "unknown")
        status = item.get("status", "unknown")
        if status == "collector_error":
            errors["collector_error"] = errors.get("collector_error", 0) + 1
        decoded.append((index, item))
    valid = [(index, item) for index, item in decoded
             if item.get("schema") == SCHEMA]
    successful_property_reads = [
        (index, item) for index, item in valid
        if item.get("status") not in {"property_not_published", "collector_error"}
    ]
    last_valid_sample = successful_property_reads[-1] if successful_property_reads else None
    decodable_cuts = [
        (index, item) for index, item in successful_property_reads
        if isinstance(item.get("wire_sha256"), str) and
        type(item.get("record_count")) is int
    ]
    last_decodable = decodable_cuts[-1] if decodable_cuts else None
    decodable_index, cut = last_decodable if last_decodable else (None, None)
    last_valid_index, last_valid = (
        last_valid_sample if last_valid_sample else (None, None))
    current_cut = None
    if (isinstance(latest_item, dict) and latest_item.get("schema") == SCHEMA and
            latest_item.get("status") not in {
                "property_not_published", "collector_error"} and
            isinstance(latest_item.get("wire_sha256"), str) and
            type(latest_item.get("record_count")) is int):
        current_cut = latest_item
    return {
        "schema": SCHEMA,
        "status": latest_status or "no_valid_capture_sample",
        "sample_count": len(samples),
        "property_present_sample_count": sum(
            1 for _, item in successful_property_reads),
        "latest_sample_status": latest_status,
        "current_cut_available": current_cut is not None,
        "last_valid_sample": ({
            "sample_index": last_valid_index,
            "status": last_valid.get("status"),
            "is_last_sample": last_valid_index == last_sample_index,
            "is_current_sample": last_valid_index == last_sample_index,
            "freshness_proven": False,
        } if last_valid else None),
        "last_decodable_cut": ({
            "sample_index": decodable_index,
            "status": cut.get("status"),
            "wire_sha256": cut.get("wire_sha256"),
            "record_count": cut.get("record_count"),
            "overflow_observed": cut.get("overflow_observed"),
            "complete_cut": cut.get("complete_cut"),
            "is_last_sample": decodable_index == last_sample_index,
            "is_current_sample": decodable_index == last_sample_index,
            "freshness_proven": False,
        } if cut else None),
        # These legacy/latest fields now describe only the latest usable sample;
        # a previous cut remains under last_decodable_cut and is never promoted.
        "latest_wire_sha256": (
            current_cut.get("wire_sha256") if current_cut else None),
        "latest_record_count": (
            current_cut.get("record_count") if current_cut else None),
        "latest_overflow_observed": (
            current_cut.get("overflow_observed") if current_cut else None),
        "latest_complete_cut": (
            current_cut.get("complete_cut") if current_cut else None),
        "latest_cut_is_last_sample": current_cut is not None,
        "latest_cut_freshness_proven": False,
        "sample_errors": errors,
        "complete_cut_is_freshness_proof": False,
        "capture_delivery_proven": False,
        "ifnet_delivery_proven": False,
        "airdrop_proven": False,
    }
