"""Derive a safe summary for the owner-scoped Test086 management trace.

The legacy U32 normalizer correctly rejects a snapshot that has no event-entry
fields.  For a stable, explicitly empty event timeline this module records that
case as not applicable, without claiming that a control or data frame arrived.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, Mapping, Tuple


EVENT_COUNT_KEY = "NativeP2PRxTraceEventCount"
EVENT_ENTRY_RE = re.compile(r"^NativeP2PRxTraceEvent\d+(?:\D|$)")
REQUIRED_GUARD_TRUE = (
    "valid", "stable_complete_snapshot", "trace_coverage_complete",
    "schema_supported", "stage_results_valid", "source_attribution_complete",
    "epoch_match", "owner_present", "owner_inactive_post_roc",
    "producer_closed", "producer_time_valid",
)
REQUIRED_GUARD_ZERO = (
    "dropped_event_count", "pending_drain_count", "session_anomaly_count",
    "session_boundary_order_invalid", "source_table_full_count",
    "stale_completion_count", "time_event_notification_dropped_count",
    "untracked_pending_drain_count", "untracked_pending_identity_overflow_count",
)


def _event_count_triplet(raw_snapshots: Any) -> Tuple[bool, str, Any, Dict[str, bool]]:
    if not isinstance(raw_snapshots, Mapping):
        return False, "raw_snapshots_missing", None, {}
    if set(raw_snapshots) != {"pre", "middle", "post"}:
        return False, "raw_snapshot_labels_not_exact_three", None, {}
    values = []
    entries: Dict[str, bool] = {}
    for label in ("pre", "middle", "post"):
        snapshot = raw_snapshots.get(label)
        if not isinstance(snapshot, Mapping):
            return False, "raw_snapshot_missing_" + label, None, entries
        value = snapshot.get(EVENT_COUNT_KEY)
        if type(value) is not int:
            return False, "event_count_not_exact_int_" + label, None, entries
        values.append(value)
        entries[label] = any(EVENT_ENTRY_RE.match(str(key)) for key in snapshot)
    if values[0] != values[1] or values[1] != values[2]:
        return False, "event_count_changed", None, entries
    return True, "", values[0], entries


def _normalized_snapshots_have_entries(normalized: Any) -> bool:
    if (not isinstance(normalized, Mapping) or
            set(normalized) != {"pre", "middle", "post"}):
        return True
    for label in ("pre", "middle", "post"):
        sample = normalized.get(label)
        if not isinstance(sample, Mapping):
            return True
        if any(EVENT_ENTRY_RE.match(str(key)) for key in sample):
            return True
    return False


def _has_event_entries(sample: Any) -> bool:
    return (isinstance(sample, Mapping) and
            any(EVENT_ENTRY_RE.match(str(key)) for key in sample))


def _has_entries_in_all_snapshots(snapshots: Any) -> bool:
    return (isinstance(snapshots, Mapping) and
            set(snapshots) == {"pre", "middle", "post"} and
            all(_has_event_entries(snapshots.get(label))
                for label in ("pre", "middle", "post")))


def _guard_complete(guard: Any, expected_event_count: int) -> Tuple[bool, str]:
    if not isinstance(guard, Mapping):
        return False, "production_guard_missing"
    for key in REQUIRED_GUARD_TRUE:
        if guard.get(key) is not True:
            return False, "production_guard_not_true_" + key
    for key in REQUIRED_GUARD_ZERO:
        if type(guard.get(key)) is not int or guard[key] != 0:
            return False, "production_guard_not_zero_" + key
    if (type(guard.get("event_count")) is not int or
            guard["event_count"] != expected_event_count):
        return False, "production_guard_event_count_invalid"
    if not isinstance(guard.get("missing_fields"), list) or guard["missing_fields"]:
        return False, "production_guard_missing_fields"
    if not isinstance(guard.get("invalid_fields"), list) or guard["invalid_fields"]:
        return False, "production_guard_invalid_fields"
    if not isinstance(guard.get("reasons"), list) or guard["reasons"]:
        return False, "production_guard_has_reasons"
    values = guard.get("values")
    if (not isinstance(values, Mapping) or
            type(values.get(EVENT_COUNT_KEY)) is not int or
            values[EVENT_COUNT_KEY] != expected_event_count):
        return False, "production_guard_event_count_value_invalid"
    return True, ""


def _empty_normalization_only_reason(normalization: Any) -> Tuple[bool, str]:
    if not isinstance(normalization, Mapping):
        return False, "normalization_missing"
    if normalization.get("valid") is not False:
        return False, "normalization_not_the_expected_failure"
    if type(normalization.get("checked_property_count")) is not int or normalization["checked_property_count"] != 0:
        return False, "normalization_checked_properties_nonzero"
    if normalization.get("reasons") != ["no_whitelisted_u32_fields"]:
        return False, "normalization_has_other_reasons"
    for key in ("missing_fields", "invalid_fields", "raw_changed", "audit"):
        if normalization.get(key) != []:
            return False, "normalization_not_empty_" + key
    if _normalized_snapshots_have_entries(
            normalization.get("normalized_snapshots")):
        return False, "normalized_event_entry_present_or_incomplete"
    return True, ""


def derive_controlled_trace_report(legacy_derivation: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy a legacy derived report and classify only the stable empty case.

    This does not re-run or replace the original production guard. All source
    snapshots remain byte-for-byte equivalent JSON values in the copy.
    """
    if not isinstance(legacy_derivation, Mapping):
        raise TypeError("legacy derivation must be a mapping")
    result = deepcopy(dict(legacy_derivation))
    legacy_schema_ok = (
        result.get("schema") == "Test076 derived RX trace validation" and
        type(result.get("schema_version")) is int and
        result.get("schema_version") == 1)
    raw = result.get("raw_snapshots")
    normalization = result.get("normalization")
    guard = result.get("guard")

    event_ok, event_reason, event_count, raw_entries = _event_count_triplet(raw)
    if event_ok and event_count != 0:
        event_reason = "event_count_nonzero"
    elif event_ok and any(raw_entries.values()):
        event_reason = "event_entry_present"
    guard_ok, guard_reason = (
        _guard_complete(guard, event_count) if event_ok else
        (False, "production_guard_not_checked_after_event_count_failure"))
    norm_ok, norm_reason = _empty_normalization_only_reason(normalization)
    no_raw_entries = not any(raw_entries.values())
    no_normalized_entries = not _normalized_snapshots_have_entries(
        normalization.get("normalized_snapshots")
        if isinstance(normalization, Mapping) else None)
    guard_values = guard.get("values") if isinstance(guard, Mapping) else None
    no_guard_entries = not _has_event_entries(guard_values)
    if guard_ok and not no_guard_entries:
        guard_reason = "production_guard_event_entry_present"
    eligible = (legacy_schema_ok and event_ok and event_count == 0 and no_raw_entries and
                guard_ok and norm_ok and no_normalized_entries and no_guard_entries)
    if eligible:
        normalized = result["normalization"]
        normalized["reason_history"] = list(normalized["reasons"])
        normalized["reasons"] = []
        normalized["valid"] = True
        normalized["status"] = "not_applicable_empty_timeline"
        normalized["event_timeline_status"] = "empty_stable"
        result["combined_valid"] = True
        result["status"] = "not_applicable_empty_timeline"
        result["event_timeline_status"] = "empty_stable"
        result["event_count"] = 0
        result["control_frames_observed"] = False
        result["data_frames_observed"] = False
        result["peer_receipt_proven"] = False
        result["airdrop_proven"] = False
        result["empty_timeline_is_frame_evidence"] = False
        result["source_legacy_derivation_modified"] = False
        result["scope"] = (
            "Derived validation only: the stable complete trace has no event "
            "entries. This is not AWDL control/data frame or peer-receipt evidence."
        )
        return result

    # Preserve the established valid path for a real nonempty event timeline.
    # An empty or changing count without its matching entries never qualifies.
    nonempty_legacy_valid = (
        event_ok and event_count > 0 and all(raw_entries.values()) and
        guard_ok and isinstance(normalization, Mapping) and
        normalization.get("valid") is True and
        type(normalization.get("checked_property_count")) is int and
        normalization["checked_property_count"] > 0 and
        normalization.get("missing_fields") == [] and
        normalization.get("invalid_fields") == [] and
        normalization.get("raw_changed") == [] and
        isinstance(normalization.get("normalized_snapshots"), Mapping) and
        _has_entries_in_all_snapshots(normalization["normalized_snapshots"]) and
        result.get("combined_valid") is True)
    if nonempty_legacy_valid:
        if not legacy_schema_ok:
            result["combined_valid"] = False
            result["status"] = "invalid_or_not_applicable"
            result["not_applicable_rejection_reasons"] = ["legacy_schema_invalid"]
            return result
        result["status"] = "legacy_validated_nonempty_timeline"
        return result

    # A malformed/incomplete empty case can only lower a reported result.
    result["combined_valid"] = False
    result["status"] = "invalid_or_not_applicable"
    result["not_applicable_rejection_reasons"] = [
        reason for reason in (
            "legacy_schema_invalid" if not legacy_schema_ok else "",
            event_reason, guard_reason, norm_reason) if reason]
    result["control_frames_observed"] = False
    result["data_frames_observed"] = False
    result["peer_receipt_proven"] = False
    result["airdrop_proven"] = False
    result["empty_timeline_is_frame_evidence"] = False
    result["source_legacy_derivation_modified"] = False
    return result
