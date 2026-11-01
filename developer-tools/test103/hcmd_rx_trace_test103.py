#!/usr/bin/env python3
"""Read and decode the published Hcmd RX trace for Test103.

This is read-only. It samples one stable I/O Registry service at a time,
validates the seqlock revision, OSData wire header, and mirrored scalar
properties, then reports raw ADD_STA_KEY response status without interpreting
the status value as successful key installation or peer acknowledgement.
"""
from __future__ import annotations

import hashlib
import plistlib
import struct
import subprocess
import time
from typing import Any, Callable

from rx149_capture_attempts_test103 import (
    CaptureLedgerError, decode_capture_attempts,
)
from tx_rsp_retry_observation_test103 import (
    CompletionDecodeError, completion_scalars, decode_scalars,
)


TRACE_SCHEMA = "test103-hcmd-rx-observation/v1"
WIRE_MAGIC = 0x54584348
WIRE_SCHEMA = 1
WIRE_HEADER_BYTES = 84
WIRE_ENTRY_BYTES = 80
TRACE_CAPACITY = 64
TRACE_PROPERTY = "NativeHcmdRxTrace"
CAPTURE_ATTEMPTS_PROPERTY = "NativeAwdlDataRx149CaptureAttempts"

PHASE_RX_RESPONSE_NO_BUFFER = 7
PHASE_RX_RESPONSE_LENGTH_REJECT = 8
SOURCE_COMMAND_RESPONSE_QUEUE = 2
IWX_ADD_STA_KEY = 0x17
IWX_DQA_CMD_QUEUE = 0

FLAG_FIRMWARE_STATUS_PRESENT = 1 << 10
FLAG_FIRMWARE_STATUS_UNAVAILABLE = 1 << 11
FLAG_COMMAND_RESPONSE_FAILED = 1 << 12

COMPANION_FIELDS = {
    "NativeHcmdRxTraceSchema": ("schema", 32),
    "NativeHcmdRxTraceBlobLength": ("blob_length", 32),
    "NativeHcmdRxTraceVersionBegin": ("version_begin", 64),
    "NativeHcmdRxTraceVersionEnd": ("version_end", 64),
    "NativeHcmdRxTraceWindowStartSerial": ("window_start_serial", 64),
    "NativeHcmdRxTraceWindowEndSerial": ("window_end_serial", 64),
    "NativeHcmdRxTraceOwnerGeneration": ("owner_generation", 32),
    "NativeHcmdRxTraceOwnerWatchdogSequence": ("owner_watchdog_sequence", 32),
    "NativeHcmdRxTraceOwnerWatchdogSequencePresent": ("owner_watchdog_sequence_present", 32),
    "NativeHcmdRxTraceRowCount": ("row_count", 32),
    "NativeHcmdRxTraceDroppedCount": ("dropped_count", 32),
    "NativeHcmdRxTraceOverwrittenCount": ("overwritten_count", 32),
    "NativeHcmdRxTraceGapCount": ("gap_count", 32),
    "NativeHcmdRxTraceSnapshotStable": ("stable", 32),
    "NativeHcmdRxTraceSnapshotComplete": ("complete", 32),
}
KEY_RESPONSE_FIELDS = {
    "NativeKeyResponsePresent": ("present", 32),
    "NativeKeyResponseStable": ("stable", 32),
    "NativeKeyResponseDroppedCount": ("dropped_count", 32),
    "NativeKeyResponseDroppedSerial": ("dropped_serial", 64),
    "NativeKeyResponseSerial": ("serial", 64),
    "NativeKeyResponseMonotonicNs": ("monotonic_ns", 64),
    "NativeKeyResponseDriverGeneration": ("driver_generation", 32),
    "NativeKeyResponseFirmwareGeneration": ("firmware_generation", 32),
    "NativeKeyResponsePhase": ("phase", 32),
    "NativeKeyResponseSource": ("source", 32),
    "NativeKeyResponseCommandId": ("command_id", 32),
    "NativeKeyResponseGroupId": ("group_id", 32),
    "NativeKeyResponseQid": ("qid", 32),
    "NativeKeyResponseIndex": ("index", 32),
    "NativeKeyResponseHeaderSequence": ("header_sequence", 32),
    "NativeKeyResponseFlags": ("flags", 32),
    "NativeKeyResponseResult": ("result", 32),
    "NativeKeyResponsePayloadLength": ("payload_length", 32),
    "NativeKeyResponseTraceVersionBegin": ("trace_version_begin", 64),
    "NativeKeyResponseTraceVersionEnd": ("trace_version_end", 64),
}
KEY_RESPONSE_STATUS_SCHEMA = "test103-key-response-slot/v1"


class HcmdTraceError(ValueError):
    pass


def _uint(value: Any, bits: int) -> bool:
    return type(value) is int and 0 <= value < (1 << bits)


def _u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def _u64(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", blob, offset)[0]


def _decode_key_response_slot(sample: dict, *, trace_header: dict | None) -> dict:
    """Decode same-revision latest ADD_STA_KEY status scalars without inference."""
    raw = sample.get("key_response")
    if not isinstance(raw, dict):
        return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
                "status": "slot_not_published", "event": None,
                "key_install_success_proven": False, "peer_ack_proven": False}
    values: dict[str, int | None] = {}
    any_present = False
    for property_key, (field, bits) in KEY_RESPONSE_FIELDS.items():
        value = raw.get(property_key)
        if value is not None:
            any_present = True
            if not _uint(value, bits):
                raise HcmdTraceError("key_response_invalid_" + field)
        values[field] = value
    if not any_present:
        return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
                "status": "slot_not_published", "event": None,
                "key_install_success_proven": False, "peer_ack_proven": False}

    revision_begin = sample.get("publish_revision_begin")
    revision_end = sample.get("publish_revision_end")
    if (not _uint(revision_begin, 32) or not _uint(revision_end, 32) or
            revision_begin == 0 or revision_begin != revision_end or
            revision_begin & 1):
        raise HcmdTraceError("key_response_publish_revision_unstable")
    if any(value is None for value in values.values()):
        raise HcmdTraceError("key_response_scalar_group_incomplete")
    if values["present"] not in (0, 1) or values["stable"] not in (0, 1):
        raise HcmdTraceError("key_response_presence_or_stability_invalid")
    if (values["trace_version_begin"] != values["trace_version_end"] or
            (trace_header is not None and
             (values["trace_version_begin"] != trace_header["version_begin"] or
              values["trace_version_end"] != trace_header["version_end"]))):
        raise HcmdTraceError("key_response_trace_version_mismatch")
    if values["stable"] != 1:
        return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
                "status": "slot_unstable", "event": None,
                "revision": revision_end,
                "trace_version": values["trace_version_end"],
                "key_install_success_proven": False, "peer_ack_proven": False}
    # The producer defines slot stability only for a stable trace cut in the
    # same publication transaction. A missing or incomplete ring cannot prove it.
    if (trace_header is None or trace_header.get("stable") != 1 or
            trace_header.get("version_begin") != trace_header.get("version_end")):
        return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
                "status": "trace_cut_not_stable", "event": None,
                "revision": revision_end,
                "key_install_success_proven": False, "peer_ack_proven": False}
    if values["dropped_serial"] > values["serial"]:
        return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
                "status": "latest_slot_superseded_by_dropped_event", "event": None,
                "revision": revision_end,
                "dropped_count": values["dropped_count"],
                "dropped_serial": values["dropped_serial"],
                "serial": values["serial"],
                "key_install_success_proven": False, "peer_ack_proven": False}
    if values["present"] == 0:
        if values["serial"] != 0:
            raise HcmdTraceError("key_response_absent_with_nonzero_serial")
        return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
                "status": "no_target_event_observed", "event": None,
                "revision": revision_end,
                "dropped_count": values["dropped_count"],
                "dropped_serial": values["dropped_serial"],
                "key_install_success_proven": False, "peer_ack_proven": False}

    if (values["serial"] == 0 or values["monotonic_ns"] == 0 or
            values["source"] != SOURCE_COMMAND_RESPONSE_QUEUE or
            values["command_id"] != IWX_ADD_STA_KEY or
            values["qid"] != IWX_DQA_CMD_QUEUE or
            values["phase"] not in (PHASE_RX_RESPONSE_NO_BUFFER,
                                      PHASE_RX_RESPONSE_LENGTH_REJECT)):
        raise HcmdTraceError("key_response_target_identity_invalid")
    flags = values["flags"]
    status_present = bool(flags & FLAG_FIRMWARE_STATUS_PRESENT)
    status_unavailable = bool(flags & FLAG_FIRMWARE_STATUS_UNAVAILABLE)
    command_failed = bool(flags & FLAG_COMMAND_RESPONSE_FAILED)
    if status_present and status_unavailable:
        raise HcmdTraceError("key_response_status_presence_flags_contradict")
    if status_present and values["payload_length"] != 4:
        raise HcmdTraceError("key_response_status_payload_length_invalid")
    if status_unavailable and values["payload_length"] == 4:
        raise HcmdTraceError("key_response_unavailable_payload_length_contradiction")
    event = {
        **values,
        "firmware_status_state": (
            "raw_status_present" if status_present else
            "status_unavailable" if status_unavailable else
            "status_not_recorded"),
        "firmware_status_raw_le32": values["result"] if status_present else None,
        "command_response_failed_flag": command_failed,
        "status_interpreted_as_key_install_success": False,
        "peer_ack_proven": False,
    }
    return {"schema": KEY_RESPONSE_STATUS_SCHEMA,
            "status": "latest_target_event", "event": event,
            "revision": revision_end,
            "dropped_count": values["dropped_count"],
            "dropped_serial": values["dropped_serial"],
            "key_install_success_proven": False,
            "peer_ack_proven": False}


def _locate_service(tree: Any) -> dict:
    matches: list[dict] = []

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if (TRACE_PROPERTY in node or "NativeHcmdRxTraceSchema" in node or
                "NativeKeyResponsePresent" in node or
                "NativeHcmdRxTracePublishRevisionBegin" in node):
            matches.append(node)
        children = node.get("IORegistryEntryChildren", [])
        if isinstance(children, list):
            for child in children:
                visit(child)

    if isinstance(tree, list):
        for item in tree:
            visit(item)
    if len(matches) != 1:
        raise HcmdTraceError("hcmd_trace_service_missing_or_ambiguous")
    return matches[0]


def read_ioreg_sample(*, check_output: Callable[..., bytes] = subprocess.check_output,
                      clock_ns: Callable[[], int] = time.monotonic_ns) -> dict:
    """Read one immutable plist snapshot; no I/O Registry write is issued."""
    before = clock_ns()
    raw = check_output(["/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"],
                       stderr=subprocess.DEVNULL, timeout=4)
    after = clock_ns()
    tree = plistlib.loads(raw)
    service = _locate_service(tree)
    blob = service.get(TRACE_PROPERTY)
    if not isinstance(blob, bytes):
        return {
            "read_status": "trace_not_published",
            "blob": None,
            "rx149_capture_attempts_raw": service.get(CAPTURE_ATTEMPTS_PROPERTY),
            "tx_rsp_retry_scalars": completion_scalars(service),
            "markers": {key: service.get(key) for key in COMPANION_FIELDS},
            "key_response": {key: service.get(key) for key in KEY_RESPONSE_FIELDS},
            "publish_revision_begin": service.get(
                "NativeHcmdRxTracePublishRevisionBegin"),
            "publish_revision_end": service.get(
                "NativeHcmdRxTracePublishRevisionEnd"),
            "host_monotonic_lower_ns": before,
            "host_monotonic_upper_ns": after,
        }
    return {
        "read_status": "trace_present",
        "blob": blob,
        "rx149_capture_attempts_raw": service.get(CAPTURE_ATTEMPTS_PROPERTY),
        "tx_rsp_retry_scalars": completion_scalars(service),
        "markers": {key: service.get(key) for key in COMPANION_FIELDS},
        "key_response": {key: service.get(key) for key in KEY_RESPONSE_FIELDS},
        "publish_revision_begin": service.get(
            "NativeHcmdRxTracePublishRevisionBegin"),
        "publish_revision_end": service.get(
            "NativeHcmdRxTracePublishRevisionEnd"),
        "host_monotonic_lower_ns": before,
        "host_monotonic_upper_ns": after,
    }


def decode_snapshot(sample: Any) -> dict:
    if not isinstance(sample, dict):
        raise HcmdTraceError("hcmd_trace_sample_invalid")
    if sample.get("read_status") != "trace_present":
        return {
            "schema": TRACE_SCHEMA,
            "status": "trace_not_published",
            "snapshot_stable": False,
            "snapshot_complete": False,
            "add_sta_key_status_events": [],
            "key_response_slot": _decode_key_response_slot(
                sample, trace_header=None),
        }
    blob = sample.get("blob")
    markers = sample.get("markers")
    if not isinstance(blob, bytes) or not isinstance(markers, dict):
        raise HcmdTraceError("hcmd_trace_blob_or_markers_invalid")
    revision_begin = sample.get("publish_revision_begin")
    revision_end = sample.get("publish_revision_end")
    if (not _uint(revision_begin, 32) or not _uint(revision_end, 32) or
            revision_begin == 0 or revision_begin != revision_end or
            revision_begin & 1):
        raise HcmdTraceError("hcmd_publish_revision_unstable")
    if len(blob) < WIRE_HEADER_BYTES:
        raise HcmdTraceError("hcmd_wire_header_truncated")
    if (_u32(blob, 0) != WIRE_MAGIC or _u32(blob, 4) != WIRE_SCHEMA or
            _u32(blob, 8) != WIRE_HEADER_BYTES or
            _u32(blob, 12) != WIRE_ENTRY_BYTES):
        raise HcmdTraceError("hcmd_wire_header_invalid")

    header = {
        "schema": _u32(blob, 4),
        "blob_length": len(blob),
        "header_bytes": _u32(blob, 8),
        "entry_bytes": _u32(blob, 12),
        "version_begin": _u64(blob, 16),
        "version_end": _u64(blob, 24),
        "owner_generation": _u32(blob, 32),
        "owner_watchdog_sequence": _u32(blob, 36),
        "owner_watchdog_sequence_present": _u32(blob, 40),
        "row_count": _u32(blob, 44),
        "dropped_count": _u32(blob, 48),
        "overwritten_count": _u32(blob, 52),
        "gap_count": _u32(blob, 56),
        "window_start_serial": _u64(blob, 60),
        "window_end_serial": _u64(blob, 68),
        "stable": _u32(blob, 76),
        "complete": _u32(blob, 80),
    }
    if (header["row_count"] > TRACE_CAPACITY or
            len(blob) != WIRE_HEADER_BYTES + header["row_count"] * WIRE_ENTRY_BYTES):
        raise HcmdTraceError("hcmd_wire_length_or_row_count_invalid")
    for property_key, (header_key, bits) in COMPANION_FIELDS.items():
        value = markers.get(property_key)
        if not _uint(value, bits) or value != header[header_key]:
            raise HcmdTraceError("hcmd_companion_mismatch_" + header_key)
    if (header["version_begin"] != header["version_end"] or
            header["stable"] not in (0, 1) or header["complete"] not in (0, 1) or
            header["owner_watchdog_sequence_present"] not in (0, 1)):
        raise HcmdTraceError("hcmd_snapshot_header_inconsistent")

    rows = []
    previous_serial = 0
    offset = WIRE_HEADER_BYTES
    for index in range(header["row_count"]):
        row = {
            "serial": _u64(blob, offset + 0),
            "driver_monotonic_ns": _u64(blob, offset + 8),
            "driver_generation": _u32(blob, offset + 16),
            "firmware_generation": _u32(blob, offset + 20),
            "phase": _u32(blob, offset + 24),
            "source": _u32(blob, offset + 28),
            "command_id": _u32(blob, offset + 32),
            "group_id": _u32(blob, offset + 36),
            "version": _u32(blob, offset + 40),
            "qid": _u32(blob, offset + 44),
            "index": _u32(blob, offset + 48),
            "header_sequence": _u32(blob, offset + 52),
            "flags": _u32(blob, offset + 56),
            "result": _u32(blob, offset + 60),
            "result_detail": _u32(blob, offset + 64),
            "packet_length": _u32(blob, offset + 68),
            "payload_length": _u32(blob, offset + 72),
            "reserved": _u32(blob, offset + 76),
        }
        if (row["serial"] <= previous_serial or row["serial"] == 0 or
                not header["window_start_serial"] <= row["serial"] <=
                header["window_end_serial"] or row["reserved"] != 0):
            raise HcmdTraceError("hcmd_row_order_or_window_invalid")
        previous_serial = row["serial"]
        rows.append(row)
        offset += WIRE_ENTRY_BYTES

    targeted = []
    for row in rows:
        if (row["phase"] != PHASE_RX_RESPONSE_NO_BUFFER or
                row["source"] != SOURCE_COMMAND_RESPONSE_QUEUE or
                row["command_id"] != IWX_ADD_STA_KEY or
                row["qid"] != IWX_DQA_CMD_QUEUE):
            continue
        flags = row["flags"]
        status_present = bool(flags & FLAG_FIRMWARE_STATUS_PRESENT)
        status_unavailable = bool(flags & FLAG_FIRMWARE_STATUS_UNAVAILABLE)
        if status_present and status_unavailable:
            raise HcmdTraceError("hcmd_status_presence_flags_contradict")
        targeted.append({
            **row,
            "firmware_status_state": (
                "raw_status_present" if status_present else
                "status_unavailable" if status_unavailable else
                "status_not_recorded"),
            "firmware_status_raw_le32": row["result"] if status_present else None,
            "command_response_failed_flag": bool(flags & FLAG_COMMAND_RESPONSE_FAILED),
            "status_interpreted_as_key_install_success": False,
            "peer_ack_proven": False,
        })

    stable = header["stable"] == 1
    complete = header["complete"] == 1
    key_response_slot = _decode_key_response_slot(sample, trace_header=header)
    slot_event = key_response_slot.get("event")
    if isinstance(slot_event, dict):
        same_serial = [row for row in rows if row["serial"] == slot_event["serial"]]
        if same_serial:
            if len(same_serial) != 1:
                raise HcmdTraceError("key_response_ring_serial_ambiguous")
            row = same_serial[0]
            comparable_fields = (
                "driver_generation", "firmware_generation", "phase", "source",
                "command_id", "group_id", "qid", "index", "header_sequence",
                "flags", "result", "payload_length", "driver_monotonic_ns",
            )
            slot_fields = {
                "driver_generation": "driver_generation",
                "firmware_generation": "firmware_generation",
                "phase": "phase", "source": "source", "command_id": "command_id",
                "group_id": "group_id", "qid": "qid", "index": "index",
                "header_sequence": "header_sequence", "flags": "flags",
                "result": "result", "payload_length": "payload_length",
                "driver_monotonic_ns": "monotonic_ns",
            }
            if any(row[field] != slot_event[slot_fields[field]]
                   for field in comparable_fields):
                raise HcmdTraceError("key_response_ring_slot_field_mismatch")
            key_response_slot["ring_crosscheck"] = "same_serial_fields_match"
        elif header["window_start_serial"] <= slot_event["serial"] <= header["window_end_serial"]:
            if complete:
                raise HcmdTraceError("key_response_missing_from_complete_ring_window")
            key_response_slot["ring_crosscheck"] = "ring_incomplete_no_same_serial_row"
        elif slot_event["serial"] < header["window_start_serial"]:
            key_response_slot["ring_crosscheck"] = "event_older_than_ring_retention_window"
        elif slot_event["serial"] > header["window_end_serial"]:
            raise HcmdTraceError("key_response_newer_than_same_cut_ring")
        else:
            key_response_slot["ring_crosscheck"] = "not_in_ring_serial_window"
    return {
        "schema": TRACE_SCHEMA,
        "status": ("stable_complete_cut" if stable and complete else
                   "stable_incomplete_cut" if stable else "unstable_cut"),
        "publish_revision": revision_end,
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "blob_length": len(blob),
        "header": header,
        "snapshot_stable": stable,
        "snapshot_complete": complete,
        "rows": rows,
        "add_sta_key_status_events": targeted,
        "key_response_slot": key_response_slot,
        "window_history_truncated": bool(
            header["dropped_count"] or header["overwritten_count"] or header["gap_count"]),
        "row_timestamp_clock_mapped_to_host": False,
        "key_install_success_proven": False,
        "peer_ack_proven": False,
        "wifi_stability_proven": False,
    }


def summarize_samples(samples: list[dict]) -> dict:
    """Deduplicate repeated snapshots by serial without merging unstable cuts."""
    events: dict[int, dict] = {}
    latest_slots: dict[int, dict] = {}
    statuses: dict[str, int] = {}
    for index, item in enumerate(samples):
        decoded = item.get("decoded") if isinstance(item, dict) else None
        if not isinstance(decoded, dict):
            statuses["invalid_sample"] = statuses.get("invalid_sample", 0) + 1
            continue
        status = decoded.get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1
        if decoded.get("snapshot_stable") is not True:
            continue
        for event in decoded.get("add_sta_key_status_events", []):
            serial = event.get("serial")
            if type(serial) is int:
                events.setdefault(serial, {
                    **event,
                    "first_sample_index": index,
                    "first_sample_host_monotonic_lower_ns": item.get(
                        "host_monotonic_lower_ns"),
                    "first_sample_host_monotonic_upper_ns": item.get(
                        "host_monotonic_upper_ns"),
                })
        slot = decoded.get("key_response_slot")
        slot_status = slot.get("status", "unknown") if isinstance(slot, dict) else "unknown"
        statuses["key_response_slot:" + str(slot_status)] = (
            statuses.get("key_response_slot:" + str(slot_status), 0) + 1)
        slot_event = slot.get("event") if isinstance(slot, dict) else None
        if isinstance(slot_event, dict) and type(slot_event.get("serial")) is int:
            serial = slot_event["serial"]
            latest_slots.setdefault(serial, {
                **slot_event,
                "first_sample_index": index,
                "first_sample_host_monotonic_lower_ns": item.get(
                    "host_monotonic_lower_ns"),
                "first_sample_host_monotonic_upper_ns": item.get(
                    "host_monotonic_upper_ns"),
            })
    return {
        "schema": TRACE_SCHEMA,
        "sample_count": len(samples),
        "snapshot_status_counts": statuses,
        "unique_add_sta_key_response_rows": [events[key] for key in sorted(events)],
        "unique_add_sta_key_response_count": len(events),
        "unique_key_response_latest_slots": [latest_slots[key]
                                             for key in sorted(latest_slots)],
        "unique_key_response_latest_slot_count": len(latest_slots),
        "missing_event_means_not_observed_not_failed": True,
        "key_install_success_proven": False,
        "peer_ack_proven": False,
        "wifi_stability_proven": False,
    }


def sample_once(reader: Callable[[], dict] = read_ioreg_sample) -> dict:
    before = time.monotonic_ns()
    raw = None
    try:
        raw = reader()
    except Exception as error:
        decoded = {
            "schema": TRACE_SCHEMA,
            "status": "collector_error",
            "snapshot_stable": False,
            "snapshot_complete": False,
            "error_code": str(error)[:120],
            "add_sta_key_status_events": [],
        }
        capture_attempts = {
            "schema": "test103-rx149-capture-attempts/v1",
            "status": "collector_error",
            "error_code": str(error)[:120],
            "records": [],
            "capture_delivery_proven": False,
            "ifnet_delivery_proven": False,
        }
        tx_rsp_retry = {
            "status": "collector_error", "error_code": str(error)[:120],
            "tx_rsp_retry_stats": {"status": "unknown", "bt_kill_count": None,
                                    "failure_rts": None, "failure_frame": None},
            "rf_ack_peer_proven": False,
        }
    else:
        try:
            decoded = decode_snapshot(raw)
        except Exception as error:
            decoded = {
                "schema": TRACE_SCHEMA,
                "status": "collector_error",
                "snapshot_stable": False,
                "snapshot_complete": False,
                "error_code": str(error)[:120],
                "add_sta_key_status_events": [],
            }
        try:
            if not isinstance(raw, dict):
                raise CaptureLedgerError("ioreg_sample_not_object")
            capture_attempts = decode_capture_attempts(
                raw.get("rx149_capture_attempts_raw"))
        except Exception as error:
            capture_attempts = {
                "schema": "test103-rx149-capture-attempts/v1",
                "status": "collector_error",
                "error_code": str(error)[:120],
                "records": [],
                "capture_delivery_proven": False,
                "ifnet_delivery_proven": False,
            }
        values = raw.get("tx_rsp_retry_scalars") if isinstance(raw, dict) else None
        if not isinstance(values, dict) or "Schema" not in values:
            tx_rsp_retry = {
                "status": "properties_not_published",
                "source_scalars": values if isinstance(values, dict) else {},
                "tx_rsp_retry_stats": {
                    "status": "unavailable_properties_not_published",
                    "layout_version": None, "frame_count": None,
                    "bt_kill_count": None, "failure_rts": None,
                    "failure_frame": None,
                },
                "rf_ack_peer_proven": False,
            }
        else:
            try:
                tx_rsp_retry = {
                    "status": "decoded", "source_scalars": values,
                    "decoded": decode_scalars(values),
                    "rf_ack_peer_proven": False,
                }
            except CompletionDecodeError as error:
                tx_rsp_retry = {
                    "status": "snapshot_unavailable_or_invalid",
                    "source_scalars": values,
                    "error_code": str(error)[:120],
                    "tx_rsp_retry_stats": {
                        "status": "unknown", "layout_version": None,
                        "frame_count": None, "bt_kill_count": None,
                        "failure_rts": None, "failure_frame": None,
                    },
                    "rf_ack_peer_proven": False,
                }
    status = decoded.get("status")
    after = time.monotonic_ns()
    return {
        "sample_status": status,
        "host_monotonic_lower_ns": before,
        "host_monotonic_upper_ns": after,
        "decoded": decoded,
        "rx149_capture_attempts": capture_attempts,
        "tx_rsp_retry": tx_rsp_retry,
    }


def summarize_tx_rsp_retry_samples(samples: list[dict]) -> dict:
    """Count same-cut parser states without inferring RF or peer outcomes."""
    status_counts: dict[str, int] = {}
    event_serials: set[int] = set()
    last_stats = None
    for sample in samples:
        observation = sample.get("tx_rsp_retry") if isinstance(sample, dict) else None
        if not isinstance(observation, dict):
            status = "sample_missing"
        else:
            status = observation.get("status", "unknown")
            source = observation.get("source_scalars")
            if isinstance(source, dict) and source.get("Event0Present") == 1:
                serial = source.get("Event0Serial")
                if type(serial) is int and serial > 0:
                    event_serials.add(serial)
            if isinstance(observation.get("decoded"), dict):
                last_stats = observation["decoded"].get("tx_rsp_retry_stats")
            elif isinstance(observation.get("tx_rsp_retry_stats"), dict):
                last_stats = observation["tx_rsp_retry_stats"]
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "schema": "test103-tx-rsp-retry-observation-summary/v1",
        "sample_count": len(samples),
        "status_counts": status_counts,
        "unique_retained_event_serial_count": len(event_serials),
        "latest_retry_stats": last_stats,
        "rf_transmission_proven": False,
        "mac_ack_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }
