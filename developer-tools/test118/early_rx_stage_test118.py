#!/usr/bin/env python3
"""Numeric early-RX stage counters for the Test118 RX149 cut.

This adapter reads AirportItlwm once per sample and decodes both the existing
Test104 RX149 ledger and Test118's pre-owner/early-AWDL counters from that one
IORegistry plist. This means one host-side IORegistry read, not an atomic
firmware snapshot. It is read-only and does not arm the driver or start RF.
"""
from __future__ import annotations

import hashlib
import importlib.util
import plistlib
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST104_DIR = REPO_ROOT / "developer-tools/test104"
TEST104_HCMD = TEST104_DIR / "hcmd_rx_trace_test104.py"
SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
if str(TEST104_DIR) not in sys.path:
    sys.path.insert(0, str(TEST104_DIR))

STAGE_COUNTERS = (
    "NativeP2PRxDataStageEarlyAwdlBssidCandidate",
    "NativeP2PRxDataStageAfterDecryptAwdlBssidCandidate",
    "NativeP2PRxDataStageDecryptRejectedAwdlBssidCandidate",
    "NativeP2PRxDataStageAfterDuplicateAwdlBssidCandidate",
    "NativeP2PRxDataStageDuplicateRejectedAwdlBssidCandidate",
    "NativeP2PRxDataStageAtTapAwdlBssidCandidate",
    "NativeP2PRxDataStageTapRejectedAwdlBssidCandidate",
    "NativeP2PRxDataStageTapContextUnavailableAwdlBssidCandidate",
    "NativeP2PRxDataStageTapLeaseInactiveAwdlBssidCandidate",
    "NativeP2PRxDataStageTapRX149PathNotSelectedAwdlBssidCandidate",
    "NativeP2PRxDataStageTapRX149OwnerRejectedAwdlBssidCandidate",
    "NativeP2PRxDataStageTapLeaseSnapshotUnavailableAwdlBssidCandidate",
    "NativeP2PRxDataStageTapOriginalDescriptorMissingAwdlBssidCandidate",
    "NativeP2PRxDataStageTapInputInvalidAwdlBssidCandidate",
    "NativeP2PRxDataStageTapPermitRejectedAwdlBssidCandidate",
    "NativeP2PRxDataStageTapCaptureRejectedAwdlBssidCandidate",
    "NativeP2PRxDataStageTapQueueFullAwdlBssidCandidate",
    "NativeP2PRxDataStagePreDuplicateBridgeQueueAcceptedAwdlBssidCandidate",
    "NativeP2PRxDataStagePreDuplicateRetrySuppressedAfterBridgeAcceptance",
)
STAGE_SCHEMA_PROPERTY = "NativeP2PRxStageSchema"
STAGE_OWNER_GENERATION_PROPERTY = "NativeP2PRxStageOwnerGeneration"
STAGE_OWNER_ACTIVE_PROPERTY = "NativeP2PRxStageOwnerActive"
STAGE_SCHEMA = 2


class EarlyRxSampleError(ValueError):
    pass


def _load_test104_hcmd():
    if TEST104_HCMD.is_symlink() or not TEST104_HCMD.is_file():
        raise EarlyRxSampleError("test104_hcmd_source_unavailable")
    spec = importlib.util.spec_from_file_location(
        "test118_test104_hcmd_decoder", TEST104_HCMD)
    if spec is None or spec.loader is None:
        raise EarlyRxSampleError("test104_hcmd_import_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(spec.name, None)
        raise EarlyRxSampleError("test104_hcmd_import_failed") from error
    return module


HCMD = _load_test104_hcmd()


def _counter_values(service: dict) -> dict:
    values = {}
    for key in STAGE_COUNTERS:
        value = service.get(key)
        # plistlib may materialize an OSNumber as int, but bool is deliberately
        # excluded because it is a Python int subclass and is not a counter.
        values[key] = value if type(value) is int and value >= 0 else None
    return values


def _owner_context(service: dict) -> dict:
    schema = service.get(STAGE_SCHEMA_PROPERTY)
    generation = service.get(STAGE_OWNER_GENERATION_PROPERTY)
    active = service.get(STAGE_OWNER_ACTIVE_PROPERTY)
    schema_ok = type(schema) is int and schema == STAGE_SCHEMA
    generation_ok = type(generation) is int and generation > 0
    active_ok = type(active) is int and active in (0, 1)
    return {
        "schema": schema if type(schema) is int else None,
        "owner_generation": generation if generation_ok else None,
        "owner_active": active if active_ok else None,
        "valid": schema_ok and generation_ok and active_ok,
        "valid_for_delta": schema_ok and generation_ok and active == 1,
        "reason": (
            None if schema_ok and generation_ok and active_ok else
            "stage_schema_unavailable_or_mismatch" if not schema_ok else
            "owner_generation_unavailable" if not generation_ok else
            "owner_active_unavailable_or_invalid"),
    }


def sample_once(*, check_output: Callable[..., bytes] = subprocess.check_output,
                clock_ns: Callable[[], int] = time.monotonic_ns) -> dict:
    """Capture ledger and stage counters from one host-side ioreg read."""
    before = clock_ns()
    raw = check_output(
        ["/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"],
        stderr=subprocess.DEVNULL, timeout=4)
    tree = plistlib.loads(raw)
    service = HCMD._locate_service(tree)
    after = clock_ns()
    sample_input = {
        "read_status": "trace_present" if isinstance(
            service.get(HCMD.TRACE_PROPERTY), bytes) else "trace_not_published",
        "blob": service.get(HCMD.TRACE_PROPERTY),
        "rx149_capture_attempts_raw": service.get(HCMD.CAPTURE_ATTEMPTS_PROPERTY),
        "tx_rsp_retry_scalars": HCMD.completion_scalars(service),
        "markers": {key: service.get(key) for key in HCMD.COMPANION_FIELDS},
        "key_response": {key: service.get(key) for key in HCMD.KEY_RESPONSE_FIELDS},
        "publish_revision_begin": service.get(
            "NativeHcmdRxTracePublishRevisionBegin"),
        "publish_revision_end": service.get(
            "NativeHcmdRxTracePublishRevisionEnd"),
        "host_monotonic_lower_ns": before,
        "host_monotonic_upper_ns": after,
    }
    # The frozen Test104 decoder keeps ownership of the OSData ledger. Stage
    # counters are OSNumber scalars and are never used to decode that ledger.
    core = HCMD.sample_once(reader=lambda: sample_input)
    counters = _counter_values(service)
    context = _owner_context(service)
    counters_complete = all(value is not None for value in counters.values())
    core["early_rx_counter_snapshot"] = {
        "schema": "test118-early-rx-stage-sample/v2",
        "status": "complete" if counters_complete and context["valid"] else
                  "incomplete_counter_scalars" if not counters_complete else
                  "incomplete_owner_context",
        "properties": list(STAGE_COUNTERS),
        "source_sha256": SOURCE_SHA256,
        "same_ioreg_read_as_rx149_ledger": True,
        "firmware_atomic_snapshot_proven": False,
        "read_window_host_monotonic_ns": [before, after],
        "owner_context": context,
        "frame_or_payload_delivery_proven": False,
    }
    core["same_read_early_rx_stage_counters"] = counters
    return core


def summarize(samples: list[dict]) -> dict:
    """Compute deltas only inside one active, same-schema owner generation."""
    grouped: dict[tuple[int, int, int], list[dict]] = {}
    context_status_counts: dict[str, int] = {}
    observed_early_sample_count = 0
    complete_counter_sample_count = 0
    for sample in samples:
        row = sample.get("same_read_early_rx_stage_counters") \
            if isinstance(sample, dict) else None
        observation = sample.get("early_rx_counter_snapshot") \
            if isinstance(sample, dict) else None
        context = observation.get("owner_context") \
            if isinstance(observation, dict) else None
        if not isinstance(row, dict) or not isinstance(context, dict):
            context_status_counts["missing_early_observation"] = (
                context_status_counts.get("missing_early_observation", 0) + 1)
            continue
        if observation.get("schema") != "test118-early-rx-stage-sample/v2":
            context_status_counts["collector_schema_mismatch"] = (
                context_status_counts.get("collector_schema_mismatch", 0) + 1)
            continue
        if observation.get("same_ioreg_read_as_rx149_ledger") is not True:
            context_status_counts["not_same_ioreg_read_as_rx149_ledger"] = (
                context_status_counts.get("not_same_ioreg_read_as_rx149_ledger", 0) + 1)
            continue
        observed_early_sample_count += 1
        if not context.get("valid"):
            reason = str(context.get("reason") or "owner_context_invalid")
            context_status_counts[reason] = context_status_counts.get(reason, 0) + 1
            continue
        if (observation.get("status") == "complete" and
                all(type(row.get(key)) is int and row[key] >= 0
                    for key in STAGE_COUNTERS)):
            complete_counter_sample_count += 1
        if not context.get("valid_for_delta"):
            context_status_counts["owner_inactive"] = (
                context_status_counts.get("owner_inactive", 0) + 1)
            continue
        if not all(type(row.get(key)) is int and row[key] >= 0
                   for key in STAGE_COUNTERS):
            context_status_counts["counter_scalars_missing"] = (
                context_status_counts.get("counter_scalars_missing", 0) + 1)
            continue
        key = (context["schema"], context["owner_generation"],
               context["owner_active"])
        grouped.setdefault(key, []).append(row)

    owner_contexts = []
    for (schema, generation, active), rows in sorted(grouped.items()):
        per_context = {}
        for key in STAGE_COUNTERS:
            values = [row[key] for row in rows]
            monotonic = all(left <= right for left, right in zip(values, values[1:]))
            enough = len(values) >= 2
            per_context[key] = {
                "sample_count": len(values),
                "first": values[0] if values else None,
                "last": values[-1] if values else None,
                "observed_delta": (values[-1] - values[0]
                                   if enough and monotonic else None),
                "delta_status": ("same_active_owner_delta"
                                 if enough and monotonic else
                                 "counter_decreased" if enough else
                                 "insufficient_same_owner_samples"),
                "monotonic_non_decreasing": monotonic if enough else None,
            }
        owner_contexts.append({
            "schema": schema, "owner_generation": generation,
            "owner_active": active, "sample_count": len(rows),
            "counters": per_context,
        })

    if not grouped:
        coverage_status = ("unknown_no_early_samples"
                           if observed_early_sample_count == 0 else
                           "incomplete_no_valid_active_owner_samples")
    elif len(grouped) > 1:
        coverage_status = "incomplete_multiple_owner_contexts"
    elif len(next(iter(grouped.values()))) < 2:
        coverage_status = "incomplete_fewer_than_two_same_owner_samples"
    elif any(value["delta_status"] != "same_active_owner_delta"
             for value in owner_contexts[0]["counters"].values()):
        coverage_status = "incomplete_counter_reset_or_missing"
    else:
        coverage_status = "complete_same_active_owner_window"

    single_owner = len(owner_contexts) == 1
    counters = {}
    for key in STAGE_COUNTERS:
        selected = owner_contexts[0]["counters"][key] if single_owner else None
        counters[key] = {
            "sample_count": selected["sample_count"] if selected else
                            sum(owner["counters"][key]["sample_count"]
                                for owner in owner_contexts),
            "first": selected["first"] if selected else None,
            "last": selected["last"] if selected else None,
            "observed_delta": selected["observed_delta"] if selected else None,
            "delta_status": selected["delta_status"] if selected else
                            "multiple_owner_contexts_no_cross_owner_delta",
            "monotonic_non_decreasing": selected["monotonic_non_decreasing"]
                                         if selected else None,
        }
    return {
        "schema": "test118-early-rx-stage-counters/v2",
        "same_ioreg_read_as_rx149_capture_ledger": True,
        "firmware_atomic_snapshot_proven": False,
        "sample_count": len(samples),
        "complete_counter_sample_count": complete_counter_sample_count,
        "early_counter_coverage_status": coverage_status,
        "early_counter_coverage_complete": (
            coverage_status == "complete_same_active_owner_window"),
        "valid_owner_context_sample_count": sum(len(rows) for rows in grouped.values()),
        "context_status_counts": context_status_counts,
        "owner_contexts": owner_contexts,
        "counters": counters,
        "interpretation": (
            "numeric OSNumber stage counters; deltas require at least two complete "
            "samples with the same schema and active owner generation; the same "
            "ioreg read is not an atomic firmware snapshot; no descriptor, MPDU, "
            "peer, or AirDrop claim"),
        "frame_or_payload_delivery_proven": False,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }
