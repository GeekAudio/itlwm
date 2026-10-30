#!/usr/bin/env python3
"""Read saved Test088/Test087 evidence without contacting the machine or router."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from typing import Any


def read_private(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("expected a regular evidence file: " + path.name)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("evidence file owner or permissions are invalid: " + path.name)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evidence root must be an object: " + path.name)
    return value


def observed(value: Any, complete: bool) -> Any:
    """Do not turn absent/incomplete evidence into a measured zero."""
    return value if complete else None


def compact_witness(witness: Any) -> dict[str, Any] | None:
    if not isinstance(witness, dict):
        return None
    event = witness.get("event")
    if not isinstance(event, dict):
        return None
    keys = ("kind", "rxClass", "channel", "channelPresent", "frameControl",
            "mpduLength", "awdlCandidate", "ownerReason", "macIndex",
            "physicalRing", "physicalSlot", "notificationQid", "notificationIndex")
    return {key: event[key] for key in keys if key in event}


def preowner_readout(native: dict[str, Any]) -> dict[str, Any]:
    observation = native.get("preowner_observation")
    if not isinstance(observation, dict):
        return {"status": "unknown_missing_observation", "complete": False,
                "counts": None, "channel149_witnesses": None}
    comparison = observation.get("comparison")
    decoded = comparison.get("decoded") if isinstance(comparison, dict) else None
    snapshot = decoded.get("snapshot") if isinstance(decoded, dict) else None
    complete = (observation.get("complete") is True and
                observation.get("commit_markers_valid_for_all_reads") is True and
                isinstance(comparison, dict) and comparison.get("complete") is True and
                comparison.get("stable") is True and
                isinstance(snapshot, dict))
    count_keys = ("closeReason", "totalEvents", "kindCounts", "rxClassCounts",
                  "dispatchCount", "mpduEntryCount", "awdlCandidateCount",
                  "ownerQualifiedCount", "ownerFailedCount", "ownerReasonCounts",
                  "witness149Count", "witness149Overflow", "witnessNon149Count",
                  "witnessNon149Overflow", "lossCount", "deadlineRejectCount",
                  "lockContentionLoss", "generationMismatchLoss", "invalidSampleLoss",
                  "clockReversalLoss", "overflow", "counterOverflow")
    witnesses = snapshot.get("channel149Witnesses") if complete else None
    counts = ({key: snapshot[key] for key in count_keys if key in snapshot}
              if complete else None)
    if complete and isinstance(counts, dict):
        non149_truncated = counts.get("witnessNon149Overflow")
        deadline_rejected = counts.get("deadlineRejectCount")
        reported_loss = counts.get("lossCount")
        mpdu_entries = counts.get("mpduEntryCount")
        event_total = counts.get("totalEvents")
        classes = counts.get("rxClassCounts")
        unknown_rx_class = classes.get("Unknown") if isinstance(classes, dict) else None
        class_names = ("Channel149", "Other", "Sta")
        known_mpdu_classes = (sum(classes[name] for name in class_names)
                              if isinstance(classes, dict) and
                              all(name in classes for name in class_names) else None)
        counts["loss_interpretation"] = {
            "reported_loss_count": reported_loss,
            "non149_witness_samples_truncated": non149_truncated,
            "deadline_rejected_samples": deadline_rejected,
            "components_reconcile": (
                isinstance(reported_loss, int) and isinstance(non149_truncated, int) and
                isinstance(deadline_rejected, int) and
                reported_loss == non149_truncated + deadline_rejected),
            "channel149_witness_overflow": counts.get("witness149Overflow"),
            "counter_overflow": counts.get("counterOverflow"),
            "lock_contention_loss": counts.get("lockContentionLoss"),
            "generation_mismatch_loss": counts.get("generationMismatchLoss"),
            "invalid_sample_loss": counts.get("invalidSampleLoss"),
            "clock_reversal_loss": counts.get("clockReversalLoss"),
            "packet_loss_proven": False,
        }
        counts["rx_class_interpretation"] = {
            "unknown_count": unknown_rx_class,
            "mpdu_entry_count": mpdu_entries,
            "total_event_count": event_total,
            "known_mpdu_class_count": known_mpdu_classes,
            "known_classes_reconcile_to_mpdu_count": (
                isinstance(known_mpdu_classes, int) and isinstance(mpdu_entries, int) and
                known_mpdu_classes == mpdu_entries),
            "unknown_equals_non_mpdu_stage_event_count": (
                isinstance(unknown_rx_class, int) and isinstance(mpdu_entries, int) and
                isinstance(event_total, int) and unknown_rx_class == event_total - mpdu_entries and
                isinstance(known_mpdu_classes, int) and known_mpdu_classes == mpdu_entries),
        }
    return {
        "status": observation.get("status", "unknown"),
        "complete": complete,
        "zero_values_are_observed_counts": (
            observation.get("zero_values_are_observed_counts") is True),
        "counts": counts,
        "channel149_witnesses": ([compact_witness(row) for row in witnesses
                                   if isinstance(row, dict) and row.get("present") is True]
                                  if isinstance(witnesses, list) else None),
        "evidence_limits": observation.get("evidence_limits"),
    }


def data_rx_readout(native: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for source_key in ("native_awdl_data_rx_initial", "native_awdl_data_rx_evidence",
                       "native_awdl_data_rx149_receipt_evidence"):
        value = native.get(source_key)
        if not isinstance(value, dict):
            output[source_key] = {"status": "unknown_missing", "complete": False}
            continue
        if source_key == "native_awdl_data_rx149_receipt_evidence":
            samples = value.get("samples")
            result = {
                "status": value.get("status", "unknown"),
                "valid": value.get("valid"),
                "complete": (value.get("valid") is True and isinstance(samples, list)
                             and bool(samples)
                             and all(isinstance(row, dict) and row.get("complete") is True
                                     for row in samples)),
                "local_ifnet_input_kpi_accepted": value.get(
                    "local_ifnet_input_kpi_accepted"),
                "peer_or_socket_receipt_proven": value.get(
                    "peer_or_socket_receipt_proven"),
                "publication_seqlock_valid": value.get("publication_seqlock_valid"),
                "candidate_to_receipt_per_frame_join_proven": value.get(
                    "candidate_to_receipt_per_frame_join_proven"),
                "problems": value.get("problems"),
                "samples": [compact_receipt_sample(row) for row in samples]
                if isinstance(samples, list) else None,
            }
            output[source_key] = result
            continue

        if source_key.endswith("_evidence") and "samples" in value:
            samples = value.get("samples")
            complete = (value.get("valid") is True and isinstance(samples, list)
                        and bool(samples)
                        and all(isinstance(row, dict) and row.get("complete") is True
                                for row in samples))
            output[source_key] = {
                "status": value.get("status", "unknown"),
                "valid": value.get("valid"),
                "complete": complete,
                "samples": [compact_data_sample(row) for row in samples]
                if isinstance(samples, list) else None,
                "problems": value.get("problems"),
            }
            continue

        complete = value.get("complete") is True
        output[source_key] = {
            "status": value.get("status", "unknown"),
            "complete": complete,
            "counters": observed(value.get("counters"), complete)
            if isinstance(value.get("counters"), dict) else None,
            "counter_presence": value.get("counter_presence"),
            "counter_missing": value.get("counter_missing"),
            "counter_invalid": value.get("counter_invalid"),
            "descriptor_candidate_count": observed(
                value.get("descriptor_candidate_count"), complete)
            if "descriptor_candidate_count" in value else None,
            "descriptor_candidate_count_present": value.get(
                "descriptor_candidate_count_present"),
            "descriptor_candidate_snapshot_stable": value.get(
                "descriptor_candidate_snapshot_stable"),
            "data_counter_owner_epoch_status": value.get(
                "data_counter_owner_epoch_status"),
            "rx_entry_epochs": value.get("rx_entry_epochs"),
            "rx_entry_snapshot_version": value.get("rx_entry_snapshot_version"),
            "rx_entry_epoch_missing": value.get("rx_entry_epoch_missing"),
            "rx_entry_epoch_invalid": value.get("rx_entry_epoch_invalid"),
            "snapshot_version_status": value.get("snapshot_version_status"),
            "ifnet_delivery_semantics": value.get("ifnet_delivery_semantics"),
        }
    return output


def compact_data_sample(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    complete = row.get("complete") is True
    return {
        "complete": complete,
        "counters": observed(row.get("counters"), complete)
        if isinstance(row.get("counters"), dict) else None,
        "counter_presence": row.get("counter_presence"),
        "counter_missing": row.get("counter_missing"),
        "counter_invalid": row.get("counter_invalid"),
        "descriptor_candidate_count": observed(
            row.get("descriptor_candidate_count"), complete),
        "descriptor_candidate_count_present": row.get(
            "descriptor_candidate_count_present"),
        "descriptor_candidate_count_valid": row.get(
            "descriptor_candidate_count_valid"),
        "descriptor_candidate_snapshot_stable": row.get(
            "descriptor_candidate_snapshot_stable"),
        "data_counter_owner_epoch_status": row.get(
            "data_counter_owner_epoch_status"),
        "rx_entry_epochs": row.get("rx_entry_epochs"),
        "rx_entry_snapshot_version": row.get("rx_entry_snapshot_version"),
        "rx_entry_epoch_missing": row.get("rx_entry_epoch_missing"),
        "rx_entry_epoch_invalid": row.get("rx_entry_epoch_invalid"),
        "snapshot_version_status": row.get("snapshot_version_status"),
    }


def compact_receipt_sample(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    missing = row.get("missing")
    prefix = "NativeAwdlDataRx149Receipt"
    complete = row.get("complete") is True
    return {
        "status": row.get("status", "unknown"),
        "complete": complete,
        "valid": row.get("valid"),
        "receipt_observed": observed(row.get("receipt_observed"), complete),
        "local_ifnet_input_kpi_accepted": observed(
            row.get("local_ifnet_input_kpi_accepted"), complete),
        "peer_or_socket_receipt_proven": observed(
            row.get("peer_or_socket_receipt_proven"), complete),
        "publication_seqlock_valid": observed(
            row.get("publication_seqlock_valid"), complete),
        "raw_payload_or_addresses_saved": observed(
            row.get("raw_payload_or_addresses_saved"), complete),
        "missing_fields": [field.removeprefix(prefix) for field in missing]
        if isinstance(missing, list) else None,
        "errors": row.get("errors"),
        "invalid": row.get("invalid"),
    }


def compact_listener(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = ("status", "datagrams", "interface", "ifindex", "pktinfo_present",
            "pktinfo_ifindex_match", "destination_group_match", "source_link_local",
            "source_port_match", "marker_match", "payload_length", "recv_anyif_set")
    return {key: value[key] for key in keys if key in value}


def compact_cleanup(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = ("ap_unchanged", "monitor_removed", "temporary_files_removed")
    return {key: value[key] for key in keys if key in value}


def compact_sender_result(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = ("status", "frames_attempted", "frames_completed", "sent", "error_count",
            "last_errno", "elapsed_ms", "deadline_hit", "stop_reason",
            "hardware_honoring", "tx_flags_requested", "mpdu_bytes", "packet_bytes",
            "udp_payload_bytes")
    return {key: value[key] for key in keys if key in value}


def compact_native_result(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = ("status", "claim_consumed", "retry_allowed", "native_helper_invoked",
            "preowner_arm_accepted", "preowner_snapshot_complete", "management_trace_valid",
            "ifnet_input_kpi_accepted", "peer_receipt_proven", "native_awdl_reply_proven",
            "airdrop_proven")
    return {key: value[key] for key in keys if key in value}


def compact_roc_clock(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = ("clock_domain", "conversion_max_quantization_error_ns", "duration_us",
            "end_notification_serial", "end_us", "roc_interval_ns", "start_notification_serial",
            "start_us", "status")
    result = {key: value[key] for key in keys if key in value}
    owner = value.get("owner")
    if isinstance(owner, dict):
        owner_keys = ("ContextGeneration", "OwnerSerial", "PowerGeneration",
                      "RocGeneration", "StationGeneration")
        result["owner"] = {key: owner[key] for key in owner_keys if key in owner}
    return result


def sender_readout(adapter: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(adapter, dict):
        return {"status": "unknown_missing_adapter_report", "attempts": None,
                "local_send_proves_rf": False}
    block = adapter.get("test088_sender")
    if not isinstance(block, dict):
        return {"status": "unknown_missing_sender_block", "attempts": None,
                "local_send_proves_rf": False}
    timing = block.get("timing")
    if not isinstance(timing, dict):
        return {"status": "unknown_missing_timing", "attempts": None,
                "local_send_proves_rf": False}
    analysis = timing.get("analysis")
    attempts = analysis.get("send_attempts") if isinstance(analysis, dict) else None
    compact = []
    if isinstance(attempts, list):
        for row in attempts:
            if not isinstance(row, dict):
                continue
            compact.append({key: row[key] for key in (
                "ordinal", "ieee80211_sequence", "awdl_sequence", "send_return_bytes",
                "send_errno", "sender_clock_interval_ns", "strict_causal_host_interval_ns",
                "strict_interval_can_overlap_roc", "nominal_host_interval_ns",
                "nominal_interval_overlaps_roc", "nominal_clock_rate_assumption",
                "radio_transmission_proven") if key in row})
    return {
        "status": timing.get("status", "unknown"),
        "coverage_complete": timing.get("coverage_complete"),
        "send_timing_complete": timing.get("send_timing_complete"),
        "strict_causal_summary": (analysis.get("strict_causal_summary")
                                   if isinstance(analysis, dict) else None),
        "nominal_summary": (analysis.get("nominal_summary")
                            if isinstance(analysis, dict) else None),
        "native_roc_driver_clock": compact_roc_clock(
            timing.get("native_roc_driver_clock")),
        "roc_overlap_status": timing.get("roc_overlap_status"),
        "attempts": compact if isinstance(attempts, list) else None,
        "local_send_proves_rf": False,
    }


def make_readout(run_dir: Path) -> dict[str, Any]:
    adapter_path = run_dir / "test088-tools-private.json"
    native_path = run_dir / "native-controlled-capture-private.json"
    if adapter_path.is_file():
        # Test088 invokes the frozen coordinator as a library and saves its
        # returned report under the adapter filename.
        base = read_private(adapter_path)
        adapter = base
    else:
        # Test087 wrote the same coordinator payload under this older name.
        base = read_private(run_dir / "controlled-run-private.json")
        adapter = None
    native = read_private(native_path)
    result = base.get("native_result")
    listener = base.get("listener_result")
    receipt = native.get("native_awdl_data_rx149_receipt_evidence")
    receipt_final = receipt.get("final") if isinstance(receipt, dict) else None
    roc_review = native.get("controlled_trace_review")
    roc_guard = roc_review.get("guard") if isinstance(roc_review, dict) else None
    roc_values = roc_guard.get("values") if isinstance(roc_guard, dict) else None
    ifnet = None
    if isinstance(result, dict) and "ifnet_input_kpi_accepted" in result:
        ifnet = result["ifnet_input_kpi_accepted"]
    elif isinstance(receipt_final, dict) and "local_ifnet_input_kpi_accepted" in receipt_final:
        ifnet = receipt_final["local_ifnet_input_kpi_accepted"]
    coordinator = {key: base.get(key) for key in (
        "status", "complete", "partial", "boot_claim_consumed", "claim_outcome",
        "udp_marker_received")}
    coordinator["sender_result"] = compact_sender_result(base.get("sender_result"))
    coordinator["sender_cleanup"] = compact_cleanup(base.get("sender_cleanup"))
    coordinator["listener_result"] = compact_listener(listener)
    coordinator["native_result"] = compact_native_result(result)
    return {
        "schema": "test088-readout-private/v1",
        "tool_revision": "Test088",
        "driver_candidate": base.get("candidate", native.get("candidate", "unknown")),
        "boot_epoch": base.get("boot_epoch", native.get("boot_epoch")),
        "coordinator": coordinator,
        "sender_timing": sender_readout(adapter),
        "rx_before_owner": preowner_readout(native),
        "native_data_rx": data_rx_readout(native),
        "ifnet_input_kpi_accepted": ifnet,
        "awdl0_listener": compact_listener(listener),
        "awdl0_listener_datagrams": listener.get("datagrams") if isinstance(listener, dict) else None,
        "roc_trace_guard_valid": roc_guard.get("valid") if isinstance(roc_guard, dict) else None,
        "roc_start_us": roc_values.get("NativeP2PRxTraceRocStartHostMonotonicUs")
        if isinstance(roc_values, dict) else None,
        "roc_end_us": roc_values.get("NativeP2PRxTraceRocEndHostMonotonicUs")
        if isinstance(roc_values, dict) else None,
        "rf_transmission_proven": False,
        "peer_receipt_proven": base.get("peer_receipt_proven", False),
        "airdrop_proven": base.get("airdrop_proven", False),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path,
                        help="directory containing the saved coordinator and native reports")
    parser.add_argument("--output", type=Path, required=True,
                        help="new path for the private summary JSON")
    args = parser.parse_args()
    value = make_readout(args.run_dir)
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(args.output),
                      "airdrop_proven": value["airdrop_proven"],
                      "preowner_complete": value["rx_before_owner"]["complete"],
                      "sender_attempts": (len(value["sender_timing"]["attempts"])
                                          if isinstance(value["sender_timing"]["attempts"], list)
                                          else None)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
