#!/usr/bin/env python3
"""Interpret bounded sender timing without treating local writes as RF proof."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple


MAX_FRAMES = 16
SCHEMA_VERSION = 1
PACKET_BYTES = 106
IEEE80211_SEQUENCE_BASE = 291
AWDL_SEQUENCE_BASE = 34305
CLOCK_FAILURE_REASONS = {
    "monotonic_clock_before_failed",
    "monotonic_clock_after_failed",
    "monotonic_clock_end_failed",
    "schedule_sleep_error",
}


class TimingError(ValueError):
    pass


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise TimingError("invalid " + field)
    return value


def parse_sender_timing(sender_result: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the sender's per-attempt timestamps and bounded sequence.

    The sender clock remains its own domain. This function never compares its
    absolute ticks with host/driver timestamps.
    """
    if not isinstance(sender_result, dict):
        raise TimingError("sender result is not an object")
    if sender_result.get("event") not in (None, "SENDER_RESULT"):
        raise TimingError("sender result event is invalid")
    if sender_result.get("timing_schema") != SCHEMA_VERSION:
        raise TimingError("sender timing schema is absent or unsupported")
    if sender_result.get("clock_domain") != "CLOCK_MONOTONIC":
        raise TimingError("sender clock domain is absent or unsupported")
    go = _integer(sender_result.get("go_received_ns"), "go_received_ns")
    start = _integer(sender_result.get("started_ns"), "started_ns")
    finish_raw = sender_result.get("finished_ns")
    finish = None if finish_raw is None else _integer(finish_raw, "finished_ns")
    if start < go or (finish is not None and finish < start):
        raise TimingError("sender GO/start/finish order is invalid")
    attempts = _integer(sender_result.get("frames_attempted"), "frames_attempted")
    completed = _integer(sender_result.get("frames_completed"), "frames_completed")
    if attempts > MAX_FRAMES or completed > attempts:
        raise TimingError("sender frame totals exceed the bounded profile")
    raw = sender_result.get("send_timing")
    if not isinstance(raw, list) or len(raw) != attempts or len(raw) > MAX_FRAMES:
        raise TimingError("send timing entries do not match attempted sends")

    entries: List[Dict[str, Any]] = []
    previous_before = -1
    seen_sequences = set()
    seen_awdl_sequences = set()
    completed_from_entries = 0
    for expected_ordinal, item in enumerate(raw):
        if not isinstance(item, dict):
            raise TimingError("send timing entry is not an object")
        ordinal = _integer(item.get("ordinal"), "ordinal")
        sequence = _integer(item.get("ieee80211_sequence"), "ieee80211_sequence")
        awdl_sequence = _integer(item.get("awdl_sequence"), "awdl_sequence")
        before_raw = item.get("before_ns")
        after_raw = item.get("after_ns")
        before = None if before_raw is None else _integer(before_raw, "before_ns")
        after = None if after_raw is None else _integer(after_raw, "after_ns")
        returned = item.get("return_bytes")
        if type(returned) is not int or returned < -1 or returned > PACKET_BYTES:
            raise TimingError("invalid return_bytes")
        error_number = _integer(item.get("errno"), "errno")
        if ordinal != expected_ordinal or (
                before is not None and after is not None and before > after):
            raise TimingError("send entry order or timing is invalid")
        if ((before is not None and (before < go or before < start or
                                     (finish is not None and before > finish))) or
                (after is not None and (after < start or
                                        (finish is not None and after > finish)))):
            raise TimingError("send timing falls outside sender GO/start/finish")
        if before is not None and before < previous_before:
            raise TimingError("send attempt timestamps are not ordered")
        if sequence > 0xFFF or sequence in seen_sequences:
            raise TimingError("IEEE 802.11 sequence is invalid or repeated")
        if awdl_sequence > 0xFFFF or awdl_sequence in seen_awdl_sequences:
            raise TimingError("AWDL sequence is invalid or repeated")
        expected_ieee = (IEEE80211_SEQUENCE_BASE + ordinal) & 0xFFF
        expected_awdl = (AWDL_SEQUENCE_BASE + ordinal) & 0xFFFF
        if sequence != expected_ieee or awdl_sequence != expected_awdl:
            raise TimingError("wire sequences do not match the frozen probe frame builder")
        if returned == PACKET_BYTES:
            completed_from_entries += 1
        if returned >= 0 and error_number != 0:
            raise TimingError("successful or short send must report errno zero")
        if returned == -1 and error_number == 0:
            raise TimingError("failed send is missing errno")
        if before is not None:
            previous_before = before
        seen_sequences.add(sequence)
        seen_awdl_sequences.add(awdl_sequence)
        entries.append({
            "ordinal": ordinal,
            "ieee80211_sequence": sequence,
            "awdl_sequence": awdl_sequence,
            "before_ns": before,
            "after_ns": after,
            "return_bytes": returned,
            "errno": error_number,
        })

    if completed_from_entries != completed:
        raise TimingError("frame completion total does not match send return values")
    stop_reason = sender_result.get("stop_reason")
    status = sender_result.get("status")
    last_errno = sender_result.get("last_errno")
    deadline_hit = sender_result.get("deadline_hit")
    if stop_reason in CLOCK_FAILURE_REASONS:
        if status != "failed" or deadline_hit is not False or type(last_errno) is not int or last_errno <= 0:
            raise TimingError("clock failure result is inconsistent")
        if stop_reason == "monotonic_clock_before_failed":
            requested = sender_result.get("frames_requested", MAX_FRAMES)
            if (type(requested) is not int or not 1 <= requested <= MAX_FRAMES or
                    attempts >= requested):
                raise TimingError("before-clock failure must precede an unsent attempt")
        if stop_reason == "monotonic_clock_after_failed" and (
                not entries or entries[-1]["after_ns"] is not None):
            raise TimingError("after-clock failure must retain its unsampled send row")
        if stop_reason == "monotonic_clock_end_failed" and (
                finish is not None or sender_result.get("elapsed_ms") is not None):
            raise TimingError("end-clock failure must leave finish duration unknown")
    timing_complete = (finish is not None and all(
        item["before_ns"] is not None and item["after_ns"] is not None
        for item in entries))
    return {
        "clock_domain": "CLOCK_MONOTONIC",
        "go_received_ns": go,
        "started_ns": start,
        "finished_ns": finish,
        "finish_time_known": finish is not None,
        "frames_attempted": attempts,
        "frames_completed": completed,
        "entries": entries,
        "coverage_complete": len(entries) == attempts,
        "timing_complete": timing_complete,
        "sender_stop_reason": stop_reason,
        "clock_or_schedule_failure": stop_reason in CLOCK_FAILURE_REASONS,
        "local_send_writes_prove_rf": False,
    }


def parse_sender_started(sender_started: Dict[str, Any]) -> Dict[str, int]:
    """Validate the one pre-loop event used only as a host-clock anchor."""
    if not isinstance(sender_started, dict):
        raise TimingError("sender started event is not an object")
    if sender_started.get("event") != "SENDER_STARTED":
        raise TimingError("sender started event name is invalid")
    if sender_started.get("timing_schema") != SCHEMA_VERSION:
        raise TimingError("sender started timing schema is absent or unsupported")
    if sender_started.get("clock_domain") != "CLOCK_MONOTONIC":
        raise TimingError("sender started clock domain is absent or unsupported")
    go = _integer(sender_started.get("go_received_ns"), "started.go_received_ns")
    start = _integer(sender_started.get("started_ns"), "started.started_ns")
    if start < go:
        raise TimingError("sender started event precedes GO receipt")
    return {"go_received_ns": go, "started_ns": start}


def _range_intersects(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def correlate_with_mac_events(
    sender_result: Dict[str, Any],
    *,
    go_write_ns: Optional[Tuple[int, int]],
    sender_started_event: Optional[Dict[str, Any]] = None,
    sender_started_receipt_ns: Optional[Any],
    sender_result_receipt_ns: Optional[Any],
    roc_ns: Optional[Tuple[int, int]],
) -> Dict[str, Any]:
    """Return strict causal and explicitly nominal same-scale intervals.

    ``go_write_ns`` is the host's Mach-time bracket around its GO write.
    ``sender_started_receipt_ns`` and ``sender_result_receipt_ns`` are host
    Mach times taken when those protocol lines reach the parent. The strict
    per-send bracket is GO-write begin through sender-result receipt: all
    events are causally contained there, though the interval may be too wide
    to determine ROC overlap.

    A second interval uses the sender's elapsed nanoseconds on the host ns
    scale. That scale conversion is an explicit assumption, not measured clock
    synchronization. Its answer is always labeled estimate/unknown and never
    upgraded into RF, target reception, or successful packet delivery.
    """
    parsed = parse_sender_timing(sender_result)
    go_interval = (None if go_write_ns is None else
                    (_integer(go_write_ns[0], "go_write_begin_ns"),
                     _integer(go_write_ns[1], "go_write_end_ns")))
    roc_interval = (None if roc_ns is None else
                    (_integer(roc_ns[0], "roc_start_ns"),
                     _integer(roc_ns[1], "roc_end_ns")))
    if ((go_interval is not None and go_interval[0] > go_interval[1]) or
            (roc_interval is not None and roc_interval[0] > roc_interval[1])):
        raise TimingError("host event interval is inverted")
    go_lo = None if go_interval is None else go_interval[0]
    go_hi = None if go_interval is None else go_interval[1]
    started_event = (None if sender_started_event is None else
                     parse_sender_started(sender_started_event))
    if started_event is not None and (
            started_event["go_received_ns"] != parsed["go_received_ns"] or
            started_event["started_ns"] != parsed["started_ns"]):
        raise TimingError("SENDER_STARTED and SENDER_RESULT clocks disagree")
    def _host_bounds(value: Optional[Any], field: str) -> Optional[Tuple[int, int]]:
        if value is None:
            return None
        if type(value) is int:
            point = _integer(value, field)
            return point, point
        if (isinstance(value, (tuple, list)) and len(value) == 2):
            lower = _integer(value[0], field + "_lower")
            upper = _integer(value[1], field + "_upper")
            if lower > upper:
                raise TimingError(field + " bounds are inverted")
            return lower, upper
        raise TimingError(field + " must be an integer or a two-value bracket")

    result_host_bounds = _host_bounds(sender_result_receipt_ns,
                                      "sender_result_receipt_ns")
    started_host_bounds = _host_bounds(sender_started_receipt_ns,
                                       "sender_started_receipt_ns")
    result_host = None if result_host_bounds is None else result_host_bounds[1]
    started_host = None if started_host_bounds is None else started_host_bounds[1]
    has_started_anchor = started_event is not None and started_host_bounds is not None
    strict_upper = result_host
    # The protocol reader and GO callback establish event order. Mach sample
    # brackets can overlap even when the events are sequential, so do not
    # reject a valid order by comparing bracket midpoints or upper bounds.
    # Reject only intervals that prove an impossible ordering even at their
    # most permissive endpoints.
    if (go_lo is not None and started_host_bounds is not None and
            started_host_bounds[1] < go_lo):
        raise TimingError("sender started receipt definitely predates GO write")
    if (go_lo is not None and result_host_bounds is not None and
            result_host_bounds[1] < go_lo):
        raise TimingError("sender result receipt definitely predates GO write")
    if (started_host_bounds is not None and result_host_bounds is not None and
            result_host_bounds[1] < started_host_bounds[0]):
        raise TimingError("sender result receipt definitely predates started receipt")

    entries = []
    for item in parsed["entries"]:
        strict = (None if strict_upper is None or go_lo is None else
                  [go_lo, strict_upper])
        strict_overlaps = (None if strict is None or roc_interval is None else
                           _range_intersects((strict[0], strict[1]), roc_interval))

        estimated = None
        estimate_intersects = None
        rate_assumption = "unknown"
        if (has_started_anchor and go_lo is not None and item["before_ns"] is not None and
                item["after_ns"] is not None and
                item["before_ns"] >= parsed["go_received_ns"]):
            # The lower endpoint uses only the causal fact that sender GO
            # cannot be received before the Mac begins writing it. The upper
            # endpoint is anchored to receipt of SENDER_STARTED, which follows
            # the sender's start event. Mapping elapsed ns onto Mach ns is an
            # explicit equal-rate assumption; this is not clock calibration.
            elapsed_from_go = item["before_ns"] - parsed["go_received_ns"]
            elapsed_from_start = item["after_ns"] - parsed["started_ns"]
            estimated = [go_lo + elapsed_from_go,
                         started_host + elapsed_from_start]
            if estimated[0] <= estimated[1]:
                if roc_interval is not None:
                    estimate_intersects = _range_intersects(
                        (estimated[0], estimated[1]), roc_interval)
                rate_assumption = "nominal_equal_nanosecond_scale_unmeasured"
            else:
                estimated = None

        entries.append({
            "ordinal": item["ordinal"],
            "ieee80211_sequence": item["ieee80211_sequence"],
            "awdl_sequence": item["awdl_sequence"],
            "send_return_bytes": item["return_bytes"],
            "send_errno": item["errno"],
            "sender_clock_interval_ns": [item["before_ns"], item["after_ns"]],
            "strict_causal_host_interval_ns": strict,
            "strict_interval_can_overlap_roc": strict_overlaps,
            "nominal_host_interval_ns": estimated,
            "nominal_interval_overlaps_roc": estimate_intersects,
            "nominal_clock_rate_assumption": rate_assumption,
            "radio_transmission_proven": False,
        })

    if result_host is None or go_lo is None:
        strict_summary = "unknown_missing_mac_go_or_result_receipt"
    elif roc_interval is None:
        strict_summary = "unknown_missing_mac_roc_interval"
    elif not _range_intersects((go_lo, result_host), roc_interval):
        strict_summary = "definitely_disjoint_by_causal_host_bounds"
    else:
        strict_summary = "causal_envelope_can_overlap_but_does_not_prove_a_send_in_window"

    any_estimate = any(item["nominal_interval_overlaps_roc"] is True for item in entries)
    all_estimate_disjoint = bool(entries) and all(
        item["nominal_interval_overlaps_roc"] is False for item in entries)
    if not entries or not has_started_anchor or go_lo is None:
        estimate_summary = "unknown_missing_sender_started_event_or_frames"
    elif roc_interval is None:
        estimate_summary = "unknown_missing_mac_roc_interval"
    elif any_estimate:
        estimate_summary = "one_or_more_nominal_intervals_overlap_unmeasured_rate_assumption"
    elif all_estimate_disjoint and parsed["timing_complete"]:
        estimate_summary = "nominal_intervals_disjoint_unmeasured_rate_assumption"
    else:
        estimate_summary = "unknown_incomplete_clock_or_timing_data"

    return {
        "schema": "test088-send-timing-interpretation/v1",
        "sender_clock_domain": parsed["clock_domain"],
        "mac_clock_domain": "MachBootClock",
        "mac_go_write_interval_ns": (None if go_interval is None else
                                      [go_interval[0], go_interval[1]]),
        "mac_sender_started_receipt_ns": started_host,
        "mac_sender_result_receipt_ns": result_host,
        "mac_sender_started_receipt_bounds_ns": (
            None if started_host_bounds is None else list(started_host_bounds)),
        "mac_sender_result_receipt_bounds_ns": (
            None if result_host_bounds is None else list(result_host_bounds)),
        "mac_roc_interval_ns": (None if roc_interval is None else
                                 [roc_interval[0], roc_interval[1]]),
        "sender_finished_ns": parsed["finished_ns"],
        "sender_finish_time_known": parsed["finish_time_known"],
        "cross_clock_epoch_subtraction_used": False,
        "send_entry_count": len(entries),
        "send_timing_records_complete": parsed["coverage_complete"],
        "send_timing_complete": parsed["timing_complete"],
        "strict_causal_summary": strict_summary,
        "nominal_summary": estimate_summary,
        "nominal_assumption_is_measured": False,
        "send_attempts": entries,
        "local_send_writes_prove_rf": False,
        "timing_instrumentation_is_non_gating_for_native_input_evidence": True,
    }
