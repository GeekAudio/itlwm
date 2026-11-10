#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Decode Test137 local receipts with the unchanged Test136 wire decoder."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Mapping


BUILD_ID = "25G416-Test137"
TERMINAL_PREFIX = "NativeAwdlDiscoveryRxWindowTerminal"
TERMINAL_FIELDS = (
    "ContextGeneration", "PowerGeneration", "StationGeneration",
    "RocGeneration", "DriverGeneration", "BeginResult", "CloseResult",
    "ObserverState", "PublishFirstStatus", "PublishStatus", "Published",
)
_BASE_PATH = (Path(__file__).resolve().parents[1] / "test136" /
              "test136_diagnostics.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "test136_diagnostics_for_test137", _BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("Test136 legacy receipt decoder unavailable")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)

_BEGIN_NAMES = {0: "not_observed", 1: "accepted", 2: "rejected"}
_CLOSE_NAMES = {0: "no_canonical_end", 1: "accepted", 2: "rejected"}
_OBSERVER_NAMES = {0: "idle", 1: "active", 2: "closed", 3: "invalid"}
_PUBLISH_NAMES = {
    0: "not_attempted", 1: "published", 2: "teardown", 3: "busy",
    4: "context_mismatch", 5: "snapshot_unavailable", 6: "encode_failed",
    7: "first_property_failed", 8: "body_property_failed",
    9: "events_allocation_failed", 10: "events_property_failed",
    11: "commit_property_failed", 12: "not_main_gate",
}


def _numeric(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _field(value: Any, names: Mapping[int, str] | None = None) -> dict[str, Any]:
    code = _numeric(value)
    if code is None:
        return {"value": None, "meaning": "unknown_missing_or_non_numeric"}
    if names is None:
        return {"value": code, "meaning": "numeric_observation"}
    return {"value": code, "meaning": names.get(code, "unknown_code")}


def terminal_snapshot(snapshot: Any) -> dict[str, dict[str, Any]]:
    values = snapshot if isinstance(snapshot, Mapping) else {}
    result: dict[str, dict[str, Any]] = {}
    for suffix in TERMINAL_FIELDS:
        names = None
        if suffix == "BeginResult":
            names = _BEGIN_NAMES
        elif suffix == "CloseResult":
            names = _CLOSE_NAMES
        elif suffix == "ObserverState":
            names = _OBSERVER_NAMES
        elif suffix in ("PublishFirstStatus", "PublishStatus"):
            names = _PUBLISH_NAMES
        elif suffix == "Published":
            names = {0: "terminal_receipt_uncommitted",
                     1: "terminal_receipt_committed"}
        result[suffix] = _field(values.get(TERMINAL_PREFIX + suffix), names)
    return result


def _profile_boolean(snapshot: Any) -> bool | None:
    if not isinstance(snapshot, Mapping):
        return None
    value = snapshot.get("NativeAwdlDiscoveryCurrentAwFallbackEnabled")
    return value if isinstance(value, bool) else None


def terminal_generation_match(snapshot: Any) -> dict[str, Any]:
    """Compare the observer receipt to the current run's public generations."""
    if not isinstance(snapshot, Mapping):
        return {"status": "unknown_snapshot_missing", "matches": {}}
    if _numeric(snapshot.get(TERMINAL_PREFIX + "Published")) != 1:
        return {"status": "unknown_uncommitted", "matches": {}}
    comparisons = {
        "ContextGeneration": "NativeP2PProbeContextGeneration",
        "PowerGeneration": "NativeP2PProbePowerGeneration",
        "StationGeneration": "NativeP2PProbeStationGeneration",
        "RocGeneration": "NativeP2PRocGeneration",
    }
    matches: dict[str, Any] = {}
    unknown = False
    mismatch = False
    for terminal_suffix, peer_key in comparisons.items():
        terminal_value = _numeric(snapshot.get(TERMINAL_PREFIX + terminal_suffix))
        peer_value = _numeric(snapshot.get(peer_key))
        if terminal_value is None or peer_value is None:
            matches[terminal_suffix] = {
                "terminal_value": terminal_value,
                "probe_value": peer_value,
                "match": None,
            }
            unknown = True
        else:
            same = terminal_value != 0 and terminal_value == peer_value
            matches[terminal_suffix] = {
                "terminal_value": terminal_value,
                "probe_value": peer_value,
                "match": same,
            }
            if not same:
                mismatch = True
    if mismatch:
        status = "generation_mismatch"
    elif unknown:
        status = "unknown_generation_missing_or_invalid"
    else:
        status = "exact_generation_match"
    return {"status": status, "matches": matches}


def terminal_current_run_match(receipt: Any, snapshots: Mapping[str, Any],
                               snapshot_matches: Mapping[str, Any]) -> dict[str, Any]:
    """Keep an exact snapshot tuple separate from proof it belongs to this run."""
    if not isinstance(receipt, Mapping):
        return {"status": "unknown_run_identity"}
    if receipt.get("context_changed_for_run") is False:
        return {"status": "stale_baseline"}
    if receipt.get("terminal_identity_valid") is not True or \
            receipt.get("context_changed_for_run") is not True:
        return {"status": "unknown_run_identity"}
    before_context = _numeric(receipt.get("context_generation_before_arm"))
    frozen_context = _numeric(receipt.get("terminal_context_generation"))
    cleanup = snapshots.get("terminal_cleanup_snapshot")
    final = snapshots.get("final")
    cleanup_context = _numeric(
        cleanup.get("NativeP2PProbeContextGeneration")
        if isinstance(cleanup, Mapping) else None)
    final_context = _numeric(
        final.get("NativeP2PProbeContextGeneration")
        if isinstance(final, Mapping) else None)
    if (before_context is None or before_context == 0 or frozen_context is None or
            frozen_context == 0 or cleanup_context is None or final_context is None):
        return {"status": "unknown_run_identity"}
    if (before_context == frozen_context or cleanup_context != frozen_context or
            final_context != frozen_context):
        return {"status": "stale_baseline"}
    cleanup_status = snapshot_matches.get(
        "terminal_cleanup_snapshot", {}).get("status", "unknown_snapshot_missing")
    final_status = snapshot_matches.get(
        "final", {}).get("status", "unknown_snapshot_missing")
    # The cleanup probe tuple is frozen independently of the RX receipt.
    # A later watchdog publication can join it even if cleanup had no receipt.
    for key in ("NativeP2PProbePowerGeneration",
                "NativeP2PProbeStationGeneration", "NativeP2PRocGeneration"):
        frozen = _numeric(cleanup.get(key))
        later = _numeric(final.get(key))
        if frozen is None or frozen == 0 or later is None or later == 0:
            return {"status": "unknown_run_identity", "cleanup_status": cleanup_status}
        if later != frozen:
            return {"status": "stale_baseline", "cleanup_status": cleanup_status}
    return {
        "status": "exact_current_run_match"
        if final_status == "exact_generation_match" else final_status,
        "cleanup_status": cleanup_status,
    }


def decode_test137_receipt(receipt: Any) -> dict[str, Any]:
    summary = _BASE.decode_test136_receipt(receipt)
    if not isinstance(receipt, Mapping):
        return summary
    snapshots = {
        name: receipt.get(name)
        for name in ("preflight", "before_arm", "terminal_cleanup_snapshot", "final")
    }
    booleans = {name: _profile_boolean(values) for name, values in snapshots.items()}
    profile_problems = []
    if receipt.get("expected_build") != BUILD_ID:
        profile_problems.append("expected_build_mismatch")
    expected_uuid = receipt.get("expected_uuid")
    if (not isinstance(expected_uuid, str) or
            receipt.get("loaded_uuid_matches_after") is not True):
        profile_problems.append("loaded_uuid_identity_unconfirmed")
    for name in ("preflight", "before_arm"):
        if booleans[name] is not True:
            profile_problems.append(name + "_fallback_flag_missing_or_disabled")
    summary["status"] = (
        "decoded_private_test137_receipt"
        if summary.get("valid") is True else summary.get("status")
    )
    summary["test137_profile"] = {
        "expected_build": BUILD_ID,
        "receipt_build": receipt.get("expected_build"),
        "current_aw_fallback_enabled_by_snapshot": booleans,
        "profile_match": not profile_problems,
        "profile_problems": profile_problems,
        "attempt_record": summary.get("current_aw_attempt_only"),
        "fallback_used_is_attempt_evidence_only": True,
    }
    summary["rx_window_terminal_publisher"] = {
        name: terminal_snapshot(values) for name, values in snapshots.items()
    }
    same_snapshot_matches = {
        name: terminal_generation_match(snapshots[name])
        for name in ("terminal_cleanup_snapshot", "final")
    }
    summary["rx_window_terminal_generation_match"] = {
        "same_snapshot": same_snapshot_matches,
        "current_run": terminal_current_run_match(
            receipt, snapshots, same_snapshot_matches),
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: test137_diagnostics.py PRIVATE_RECEIPT.json", file=sys.stderr)
        return 2
    try:
        receipt = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "receipt_unreadable", "detail": str(error)}))
        return 1
    summary = decode_test137_receipt(receipt)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0 if (
        summary.get("valid") and
        summary.get("test137_profile", {}).get("profile_match")
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
