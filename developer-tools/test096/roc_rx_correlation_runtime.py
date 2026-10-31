#!/usr/bin/env python3
"""Pure adapter from verified PreOwner and ROC trace snapshots to a close marker.

The caller performs all I/O and verifies the loaded UUID, boot epoch, and run
token before calling this module. This adapter checks that both supplied
snapshots carry that same verified binding, validates their terminal/version
and ROC-boundary fields, then derives the ROC correlation identity. It never
reads IORegistry or hardware, and it never reads the ROC property to make its
own close marker.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_EPOCH_FIELDS = (
    ("contextGeneration", "ContextGeneration"),
    ("powerGeneration", "PowerGeneration"),
    ("stationGeneration", "StationGeneration"),
    ("rocGeneration", "RocGeneration"),
)
_EVENT_REQUIRED = (
    "Api",
    "RawLength",
    "Configuration",
    "MacIdAndColor",
    "CanonicalTransitionPresent",
    "CanonicalTransition",
    "ReducerResultPresent",
    "ReducerReturnedTrue",
    "RawStatus",
    "HostMonotonicPresent",
)
_IDENTITY_FIELDS = (
    "captureSerial",
    "driverGeneration",
    "contextGeneration",
    "powerGeneration",
    "stationGeneration",
    "rocGeneration",
    "sessionToken",
    "armUs",
    "startUs",
    "deadlineUs",
)
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1


def _unknown(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "marker": None,
        "expected_identity": None,
    }


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _in_unsigned_range(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


def _equals_int(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _binding_key(value: Any) -> tuple[str, int, str] | None:
    if not isinstance(value, Mapping) or value.get("verified") is not True:
        return None
    uuid = value.get("loadedUUID")
    boot = value.get("bootEpoch")
    token = value.get("armRunToken")
    if (not isinstance(uuid, str) or not uuid.strip() or
            not _positive_int(boot) or not isinstance(token, str) or
            not token.strip()):
        return None
    return uuid, boot, token


def _trace_value(raw: Mapping[str, Any], role: str, field: str) -> Any:
    return raw.get("NativeP2PRxTraceRoc" + role + field)


def derive_closed_identity(
    verified_binding: Mapping[str, Any],
    preowner_capture: Mapping[str, Any],
    trace_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Return an externally witnessed close marker and property identity.

    Inputs are caller-read values. The verified binding must already have
    been checked against the loaded kext UUID, boot epoch, and manual-run
    token. Both evidence objects must repeat that binding so data from a
    different load or run cannot be joined accidentally.

    The PreOwner side must be one stable three-read terminal snapshot. The
    trace side must be one unchanged, nonzero even-version raw registry
    snapshot with an accepted ROC START/END pair. Missing or failed evidence returns
    status unknown with no marker or identity; it is never converted into a
    zero-copy result.
    """
    binding_key = _binding_key(verified_binding)
    if binding_key is None:
        return _unknown("loaded_uuid_boot_epoch_run_token_unverified")
    if not isinstance(preowner_capture, Mapping):
        return _unknown("preowner_snapshot_missing")
    if not isinstance(trace_snapshot, Mapping):
        return _unknown("roc_trace_snapshot_missing")
    if (_binding_key(preowner_capture.get("binding")) != binding_key or
            _binding_key(trace_snapshot.get("binding")) != binding_key):
        return _unknown("capture_binding_mismatch_or_stale")

    if preowner_capture.get("stable") is not True:
        return _unknown("preowner_snapshot_unstable")
    if preowner_capture.get("commitMarkersValidForAllReads") is not True:
        return _unknown("preowner_commit_markers_unverified")
    if preowner_capture.get("stableReadCount") != 3:
        return _unknown("preowner_not_three_stable_reads")
    decoded = preowner_capture.get("decoded")
    preowner = decoded.get("snapshot") if isinstance(decoded, Mapping) else None
    if not isinstance(preowner, Mapping):
        return _unknown("preowner_decoded_snapshot_missing")
    if preowner.get("closed") is not True or preowner.get("active") is not False:
        return _unknown("preowner_not_terminal")
    for field in ("captureSerial", "driverGeneration"):
        if not _in_unsigned_range(preowner.get(field), _UINT32_MAX):
            return _unknown("preowner_" + field + "_missing_or_invalid")
    for field in ("beginUs", "endUs"):
        if not _in_unsigned_range(preowner.get(field), _UINT64_MAX):
            return _unknown("preowner_" + field + "_missing_or_invalid")
    if preowner["endUs"] < preowner["beginUs"]:
        return _unknown("preowner_terminal_time_invalid")

    raw = trace_snapshot.get("rawSnapshot")
    if not isinstance(raw, Mapping):
        return _unknown("roc_trace_raw_snapshot_missing")
    version_begin = raw.get("NativeP2PRxTraceSnapshotVersionBegin")
    version_end = raw.get("NativeP2PRxTraceSnapshotVersionEnd")
    if (not _in_unsigned_range(version_begin, _UINT32_MAX) or
            not _in_unsigned_range(version_end, _UINT32_MAX)):
        return _unknown("roc_trace_version_missing_zero_or_out_of_range")
    if version_begin != version_end:
        return _unknown("roc_trace_snapshot_unstable")
    if version_begin & 1:
        return _unknown("roc_trace_version_odd")

    start_present = raw.get("NativeP2PRxTraceRocStartPresent")
    if _equals_int(start_present, 0):
        return _unknown("roc_start_not_observed_no_zero_identity")
    if not _equals_int(start_present, 1):
        return _unknown("roc_start_presence_missing_or_invalid")
    end_present = raw.get("NativeP2PRxTraceRocEndPresent")
    if _equals_int(end_present, 0):
        return _unknown("roc_end_not_observed")
    if not _equals_int(end_present, 1):
        return _unknown("roc_end_presence_missing_or_invalid")

    for role in ("Start", "End"):
        expected_start_flag = 1 if role == "Start" else 0
        if not _equals_int(_trace_value(raw, role, "RawStartFlag"),
                           expected_start_flag):
            return _unknown("roc_" + role.lower() + "_flag_invalid")
        if not _equals_int(_trace_value(raw, role, "Present"), 1):
            return _unknown("roc_" + role.lower() + "_presence_invalid")
        for field in _EVENT_REQUIRED:
            expected = 1
            if field == "RawLength":
                expected = 16
            elif field == "Configuration":
                expected = 2
            if not _equals_int(_trace_value(raw, role, field), expected):
                return _unknown("roc_" + role.lower() + "_" + field + "_failed")

    owner_present = raw.get("NativeP2PRxTraceOwnerPresent")
    owner_serial = raw.get("NativeP2PRxTraceOwnerSerial")
    if (not _equals_int(owner_present, 1) or
            not _in_unsigned_range(owner_serial, _UINT64_MAX)):
        return _unknown("roc_trace_owner_missing")

    epoch: dict[str, int] = {}
    for identity_field, trace_field in _EPOCH_FIELDS:
        start_value = _trace_value(raw, "Start", trace_field)
        end_value = _trace_value(raw, "End", trace_field)
        top_value = raw.get("NativeP2PRxTrace" + trace_field)
        if (not _in_unsigned_range(start_value, _UINT32_MAX) or
                not _equals_int(end_value, start_value) or
                not _equals_int(top_value, start_value)):
            return _unknown("roc_" + identity_field + "_invalid_or_mismatch")
        epoch[identity_field] = start_value

    start_token = _trace_value(raw, "Start", "OwnerSessionToken")
    end_token = _trace_value(raw, "End", "OwnerSessionToken")
    start_owner = _trace_value(raw, "Start", "OwnerSerial")
    end_owner = _trace_value(raw, "End", "OwnerSerial")
    if (not _in_unsigned_range(start_token, _UINT64_MAX) or
            not _equals_int(end_token, start_token) or
            not _in_unsigned_range(start_owner, _UINT64_MAX) or
            not _equals_int(end_owner, start_owner) or
            not _equals_int(start_owner, owner_serial)):
        return _unknown("roc_owner_token_or_serial_mismatch")
    if epoch["powerGeneration"] != preowner["driverGeneration"]:
        return _unknown("preowner_driver_generation_mismatch")

    duration_ms = raw.get("NativeP2PRocRequestedDurationMs")
    start_us = _trace_value(raw, "Start", "HostMonotonicUs")
    end_us = _trace_value(raw, "End", "HostMonotonicUs")
    if not _positive_int(duration_ms):
        return _unknown("roc_requested_duration_missing_or_invalid")
    if duration_ms > _UINT64_MAX // 1000:
        return _unknown("roc_deadline_overflow")
    if duration_ms > _UINT32_MAX:
        return _unknown("roc_requested_duration_missing_or_invalid")
    if (not _in_unsigned_range(start_us, _UINT64_MAX) or
            not _in_unsigned_range(end_us, _UINT64_MAX)):
        return _unknown("roc_boundary_time_missing_or_invalid")
    duration_us = duration_ms * 1000
    if start_us > _UINT64_MAX - duration_us:
        return _unknown("roc_deadline_overflow")
    deadline_us = start_us + duration_us
    if not (preowner["beginUs"] < start_us < end_us <= deadline_us and
            end_us <= preowner["endUs"]):
        return _unknown("roc_boundary_time_mismatch")

    expected_identity = {
        "captureSerial": preowner["captureSerial"],
        "driverGeneration": preowner["driverGeneration"],
        **epoch,
        "sessionToken": start_token,
        "armUs": preowner["beginUs"],
        "startUs": start_us,
        "deadlineUs": deadline_us,
    }
    # Keep the projection fixed so downstream collectors cannot accidentally
    # rely on a private or future property field.
    expected_identity = {
        field: expected_identity[field] for field in _IDENTITY_FIELDS
    }
    marker = {
        "closed": True,
        "sameCaptureEpochVerified": True,
        "evidenceSource": "verified-preowner-stable3read+roc-trace-end",
        "identity": dict(expected_identity),
        "binding": {
            "loadedUUID": binding_key[0],
            "bootEpoch": binding_key[1],
            "armRunToken": binding_key[2],
        },
        "traceSnapshotVersion": version_begin,
        "preownerCloseReason": preowner.get("closeReason"),
    }
    return {
        "status": "verified_end_marker",
        "reason": None,
        "marker": marker,
        "expected_identity": expected_identity,
    }
