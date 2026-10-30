"""Strict, offline normalization for Test075 AWDL RX trace uint32 scalars.

This module never reads IORegistry or mutates collector snapshots. Callers must
pass the three raw reads together so mixed signed/unsigned representations are
reported instead of being silently treated as a stable snapshot.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

U32_MAX = (1 << 32) - 1
I32_MIN = -(1 << 31)
U32_MODULUS = 1 << 32
EVENT_CAPACITY = 32
PROPERTY_PREFIX = "NativeP2PRxTraceEvent"
SCHEMA_VERSION = 1
SCHEMA_NAME = "Test075 RX trace event U32 whitelist"

# Frozen copy of capture_test075_resident_data_once.py's
# RX_TRACE_EVENT_U32_FIELDS. The Test076 offline test checks exact parity so a
# future collector schema change cannot silently widen this converter.
FORMAL_RX_TRACE_EVENT_U32_FIELDS = frozenset((
    "ContextGeneration", "PowerGeneration", "StationGeneration", "RocGeneration",
    "Kind", "HostMonotonicPresent", "RawLength", "SourceOrdinal", "SourceKnown",
    "FrameControlPresent", "FrameControl", "FrameType", "FrameSubtype",
    "SequenceControlPresent", "SequenceControl", "AwdlSubtypePresent", "AwdlSubtype",
    "WirePhyPresent", "WirePhyTxUs", "WireTargetPresent", "WireTargetTxUs",
    "ChannelIndex", "RxGp2Present", "RxGp2Us", "RxMacPhyIndexPresent", "RxMacPhyIndex",
    "ParseAttempted", "ParseResultPresent", "ParseStatus", "ParseRejectReason",
    "ParseRejectSubtype", "ParseTlvType", "ParseExpectedTlvType", "ParseTlvOffset",
    "ParseDeclaredLength", "ParseAvailableLength", "DecodeAttempted", "DecodeResultPresent",
    "DecodeStatus", "DecodeRejectStage", "DecodeOffendingTlvType", "DecodeRelatedTlvType",
    "RouteAttempted", "RouteResultPresent", "RouteStatus", "QueueAccepted",
    "TableObserveAttempted", "TableResultPresent", "TableStatus", "PeerObserverAttempted",
    "PeerObserverResultPresent", "PeerObserverStatus", "CompletionUpdated", "PendingDrain",
    "NotificationApi", "NotificationMatchStatusPresent", "NotificationMatchStatus",
    "TimeEventTimestamp", "TimeEventSessionId", "TimeEventUniqueId",
    "TimeEventMacIdAndColor", "TimeEventRawAction", "TimeEventRawStatus",
    "TimeEventExpectedUidKnown", "TimeEventExpectedUid", "TxSequenceControl",
    "TxWireInfoPresent", "TxWirePhyTxUs", "TxWireTargetTxUs", "TxQueueId",
    "TxDescriptorIndex",
))

_PROPERTY_RE = re.compile(
    r"^NativeP2PRxTraceEvent(?P<index>0|[1-9][0-9]*)(?P<field>[A-Za-z][A-Za-z0-9]*)$"
)
_READ_LABELS = ("pre", "middle", "post")


class U32NormalizationError(ValueError):
    """A property or scalar is outside the frozen RX event U32 schema."""


def _parse_whitelisted_property(property_name: str) -> tuple[int, str]:
    if type(property_name) is not str:
        raise U32NormalizationError("property_name_must_be_str")
    match = _PROPERTY_RE.fullmatch(property_name)
    if match is None:
        raise U32NormalizationError("unknown_property_name")
    event_index = int(match.group("index"))
    if event_index >= EVENT_CAPACITY:
        raise U32NormalizationError("event_index_out_of_range")
    field = match.group("field")
    if field not in FORMAL_RX_TRACE_EVENT_U32_FIELDS:
        raise U32NormalizationError("field_not_in_formal_u32_whitelist")
    return event_index, field


def normalize_ioreg_u32_property(property_name: str, raw_value: object) -> dict:
    """Normalize one formally whitelisted Test075 RX event uint32 property.

    IORegistry readers can surface a uint32 whose high bit is set as an int32
    negative value. Only signed-int32 range values are reinterpreted by adding
    2^32. Booleans, U64 properties, unknown keys, and out-of-range values fail.
    The returned record preserves both raw and canonical values for audit.
    """
    event_index, field = _parse_whitelisted_property(property_name)
    if type(raw_value) is not int:
        raise U32NormalizationError("value_must_be_exact_int")
    if 0 <= raw_value <= U32_MAX:
        normalized = raw_value
        encoding = "unsigned_u32"
    elif I32_MIN <= raw_value <= -1:
        normalized = raw_value + U32_MODULUS
        encoding = "signed_i32_as_u32"
    else:
        raise U32NormalizationError("value_outside_u32_or_signed_i32_range")
    return {
        "property": property_name,
        "event_index": event_index,
        "field": field,
        "raw": raw_value,
        "normalized": normalized,
        "bit_width": 32,
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "encoding": encoding,
        "converted": raw_value < 0,
    }


def _is_whitelisted_event_property(property_name: object) -> bool:
    if type(property_name) is not str:
        return False
    match = _PROPERTY_RE.fullmatch(property_name)
    if match is None or int(match.group("index")) >= EVENT_CAPACITY:
        return False
    return match.group("field") in FORMAL_RX_TRACE_EVENT_U32_FIELDS


def normalize_rx_trace_u32_reads(pre: Mapping, middle: Mapping, post: Mapping) -> dict:
    """Normalize only formal event-U32 fields across stable pre/middle/post reads.

    Non-event properties (including U64 fields) are copied unchanged. Every
    selected field must exist in all three reads, pass the strict scalar
    validator, and have exactly the same raw integer representation in all
    reads. Thus -1 versus 0xffffffff is marked raw_changed even though the
    canonical bits are equal.
    """
    snapshots = {"pre": pre, "middle": middle, "post": post}
    for label, sample in snapshots.items():
        if not isinstance(sample, Mapping):
            raise U32NormalizationError(f"{label}_snapshot_must_be_mapping")

    normalized = {label: dict(sample) for label, sample in snapshots.items()}
    keys = set()
    for sample in snapshots.values():
        keys.update(key for key in sample if _is_whitelisted_event_property(key))

    missing = []
    invalid = []
    raw_changed = []
    audit = []
    converted_scalar_count = 0
    for key in sorted(keys):
        raw_by_read = {}
        normalized_by_read = {}
        encodings = {}
        errors = {}
        for label, sample in snapshots.items():
            if key not in sample:
                missing.append(f"{label}.{key}")
                continue
            raw = sample[key]
            raw_by_read[label] = raw
            try:
                entry = normalize_ioreg_u32_property(key, raw)
            except U32NormalizationError as error:
                errors[label] = str(error)
                continue
            normalized_by_read[label] = entry["normalized"]
            encodings[label] = entry["encoding"]
            normalized[label][key] = entry["normalized"]
            converted_scalar_count += int(entry["converted"])
        if errors:
            invalid.append({"property": key, "errors": errors})
        if len(raw_by_read) == 3 and any(type(v) is not int for v in raw_by_read.values()):
            # Invalid types are already recorded above; never compare bools as
            # ints even if their Python equality happens to match 0 or 1.
            pass
        elif len(raw_by_read) == 3 and len(set(raw_by_read.values())) != 1:
            raw_changed.append(key)
        audit.append({
            "property": key,
            "field": _parse_whitelisted_property(key)[1],
            "bit_width": 32,
            "schema": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "raw_by_read": raw_by_read,
            "normalized_by_read": normalized_by_read,
            "encoding_by_read": encodings,
            "raw_equal_across_reads": (
                len(raw_by_read) == 3 and
                all(type(value) is int for value in raw_by_read.values()) and
                len(set(raw_by_read.values())) == 1
            ),
            "errors": errors,
        })

    reasons = []
    if not keys:
        reasons.append("no_whitelisted_u32_fields")
    if missing:
        reasons.append("missing_across_three_reads")
    if invalid:
        reasons.append("invalid_whitelisted_u32_value")
    if raw_changed:
        reasons.append("raw_changed_across_three_reads")
    valid = bool(keys) and not missing and not invalid and not raw_changed
    return {
        "valid": valid,
        "checked_property_count": len(keys),
        "converted_scalar_count": converted_scalar_count,
        "missing_fields": missing,
        "invalid_fields": invalid,
        "raw_changed": raw_changed,
        "reasons": reasons,
        "normalized_snapshots": normalized,
        "audit": audit,
        "raw_snapshots_mutated": False,
        "scope": "Offline normalization of formally whitelisted Test075 RX trace event U32 fields only.",
    }


def derive_rx_trace_guard_report(pre: Mapping, middle: Mapping, post: Mapping,
                                production_guard) -> dict:
    """Create an in-memory derived report without changing any source report.

    `production_guard` must be the real collector guard supplied by the caller.
    Raw snapshots are copied unchanged; the guard receives only the normalized
    copies. The combined result is fail-closed on either normalization or guard
    failure and never claims peer receipt or AirDrop.
    """
    if not callable(production_guard):
        raise U32NormalizationError("production_guard_must_be_callable")
    raw = {"pre": dict(pre), "middle": dict(middle), "post": dict(post)}
    normalization = normalize_rx_trace_u32_reads(
        raw["pre"], raw["middle"], raw["post"]
    )
    normalized = normalization["normalized_snapshots"]
    guard_result = production_guard(
        normalized["pre"], normalized["middle"], normalized["post"]
    )
    if not isinstance(guard_result, Mapping):
        raise U32NormalizationError("production_guard_result_must_be_mapping")
    guard_result = dict(guard_result)
    combined_valid = normalization["valid"] and guard_result.get("valid") is True
    return {
        "schema": "Test076 derived RX trace validation",
        "schema_version": 1,
        "raw_snapshots": raw,
        "normalization": normalization,
        "guard": guard_result,
        "combined_valid": combined_valid,
        "raw_snapshots_preserved": True,
        "source_test075_report_updated": False,
        "source_test075_overall_result_promoted": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
        "scope": "Offline derived telemetry validation only; not a runtime, peer-receipt, or AirDrop result.",
    }
