#!/usr/bin/env python3
"""Decode private Test136 receipts without upgrading local evidence to RF proof.

The fixed QWR1/QWS1 and scalar RX window formats are decoded fail-closed.
Raw command/MPDU bytes and OSData base64 are never returned in the summary.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Any, Mapping


_LEGACY_PATH = (Path(__file__).resolve().parents[1] / "test079" / "tools" /
                "awdl_osdata_diagnostics.py")
_LEGACY_SPEC = importlib.util.spec_from_file_location(
    "test079_awdl_osdata_diagnostics", _LEGACY_PATH)
if _LEGACY_SPEC is None or _LEGACY_SPEC.loader is None:
    raise RuntimeError("Test079 address-free OSData decoder unavailable")
_LEGACY = importlib.util.module_from_spec(_LEGACY_SPEC)
_LEGACY_SPEC.loader.exec_module(_LEGACY)


QWR1_MAGIC = 0x31525751
QWR1_SCHEMA = 1
QWR1_HEADER_BYTES = 112
QWR1_TOTAL_BYTES = 2224
QWR1_COMMAND_CAPACITY = 64
QWR1_MPDU_CAPACITY = 2048
QWR1_FLAGS_MASK = 0x7F
QWR1_CANDIDATE = 1 << 0
QWR1_COMMAND_COPIED = 1 << 1
QWR1_MPDU_DONE = 1 << 2
QWR1_COMMAND_TRUNCATED = 1 << 3
QWR1_MPDU_TRUNCATED = 1 << 4
QWR1_STAGE_ACCEPTED = 1 << 5
QWR1_RAW_RESPONSE_CAPTURED = 1 << 6
QWR1_STAGED_AWAITING_PUBLISH = 6
QWR1_HEADER = struct.Struct("<IHHIIQQQQQHHHHHHIIIIiiIQQ")

QWS1_MAGIC = 0x31535751
QWS1_SCHEMA = 1
QWS1_BYTES = 56
QWS1_STATUS_NAMES = {
    0: "none",
    1: "candidate",
    2: "copy_or_header_rejected",
    3: "captured_awaiting_finish",
    4: "finish_failed",
    5: "stage_cas_failed",
    6: "staged_awaiting_publish",
    7: "allocation_failed",
    8: "raw_property_write_failed",
    9: "legacy_facts_write_failed",
    10: "published",
}
QWS1_STATUS = struct.Struct("<IHHIIQQQQQ")

DATA_TX_TRACE_HEADER_SUFFIXES = (
    "SnapshotVersionBegin", "SnapshotComplete", "SchemaVersion", "Revision",
    "OwnerPresent", "OwnerSerial", "OwnerDiagnosticGeneration",
    "OwnerContextGeneration", "OwnerPowerGeneration", "OwnerStationGeneration",
    "OwnerRocGeneration", "Count", "DroppedCount", "CoverageUnknown",
    "ResponseTapMergeStatus", "StopTapMergeStatus", "TxRspTapState",
    "TxRspTapSequence", "TxRspTapConsumedSequence", "TxRspTapDroppedCount",
    "TxRspTapActivePublicationSequence", "TxRspTapActiveToken", "StopTapState",
    "StopTapSequence", "StopTapConsumedSequence", "StopTapDroppedCount",
    "StopTapActivePublicationSequence", "StopTapActiveToken",
    "FirmwareEchoesFullIdentity", "AssociationStrengthCandidateOnly",
    "AssociationStrengthLocalScalarMatch", "AssociationStrengthExistingHandlerAccepted",
    "SnapshotVersionEnd",
)
DATA_TX_TRACE_RECORD_SUFFIXES = (
    "RecordPresent", "Used", "RecordSerial", "Token", "DiagnosticGeneration",
    "ContextGeneration", "PowerGeneration", "StationGeneration", "RocGeneration",
    "StagePresenceFlags", "QueueMetadataPresent", "QueryClass", "Eligible",
    "QueueBornUs", "DequeuedUs", "SubmitCallStartUs", "FinalWireUs",
    "RingReservedUs", "DescriptorReadyUs", "DoorbellMarkedUs", "DoorbellIssuedUs",
    "TxRspTapUs", "CompletionUs", "CancelUs", "UnknownUs", "EncodeFailureUs",
    "StopUs", "SubmitCallEndUs", "FrameControl", "SequenceControl", "MpduLength",
    "PacketCount", "IPv6Length", "QueueId", "RingSize", "DescriptorIndex",
    "TxRspQueueId", "TxRspRxHeaderIndex", "TxRspSequenceControl", "TxRspByteCount",
    "TxRspFrameControl", "TxRspStatus", "TxRspRaTid", "TxRspScdSsn",
    "TxRspValidFields", "SubmitCallResult", "CompletionResult", "CancellationReason",
    "UnknownReason", "EncodeFailureResult", "StopNewGeneration", "StopReason",
    "StopProvenDrain", "ResponseMismatchMask", "ResponseScalarMatchMask",
    "AssociationStrength", "TxRspHandlerDisposition", "FirmwareEchoesFullIdentity",
    "AmbiguousLateQueueUnknown", "ResponseCandidateSeen",
)
DATA_TX_TRACE_SLOTS = 8
DATA_TX_TRACE_STAGE_BITS = {
    "queue_born": 1 << 0,
    "dequeued": 1 << 1,
    "submit_call_start": 1 << 2,
    "final_wire": 1 << 3,
    "ring_reserved": 1 << 4,
    "descriptor_ready": 1 << 5,
    "doorbell_marked": 1 << 6,
    "doorbell_issued": 1 << 7,
    "tx_response_tap": 1 << 8,
    "completion": 1 << 9,
    "cancel": 1 << 10,
    "submit_call_end": 1 << 11,
    "unknown": 1 << 12,
    "encode_failure": 1 << 13,
    "stop_observed": 1 << 14,
}
DATA_TX_TRACE_KNOWN_STAGE_MASK = (1 << 15) - 1

RX_WINDOW_PREFIX = "NativeAwdlDiscoveryRxWindow"
RX_WINDOW_SUFFIXES = (
    "SchemaVersion", "Published", "SnapshotBegin", "SnapshotEnd", "Valid",
    "Complete", "Overflow", "CloseReason", "DriverGeneration",
    "RocConfiguration",
    "ContextGeneration", "PowerGeneration", "StationGeneration",
    "RocGeneration", "StartMonotonicUs", "EndMonotonicUs",
    "FirstMpduEntryMonotonicUs", "LastMpduEntryMonotonicUs", "MpduEntryCount",
    "ManagementMpduCount", "ControlMpduCount", "DataMpduCount",
    "ExtensionMpduCount", "UnknownTypeMpduCount", "AwdlDataCandidateCount",
    "LeaseQualifiedCount", "LeaseUnqualifiedCount", "DescriptorUnavailableCount",
    "CrcRejectedCount", "OverrunRejectedCount", "Channel149Count",
    "RoutePassToStaCount", "RouteQueuedForNativeCount",
    "RouteDuplicateRetryCount",
    "ServiceRxDrainCount", "ServiceRxDrainFirstMonotonicUs",
    "ServiceRxDrainLastMonotonicUs", "ServiceRxRingSlotCount",
    "ServiceRxRingSlotFirstMonotonicUs", "ServiceRxRingSlotLastMonotonicUs",
    "ServiceNotificationSeenCount", "ServiceNotificationSeenFirstMonotonicUs",
    "ServiceNotificationSeenLastMonotonicUs", "ServiceHeaderRejectedCount",
    "ServiceHeaderRejectedFirstMonotonicUs", "ServiceHeaderRejectedLastMonotonicUs",
    "ServiceLengthRejectedCount", "ServiceLengthRejectedFirstMonotonicUs",
    "ServiceLengthRejectedLastMonotonicUs", "ServiceNotificationValidatedCount",
    "ServiceNotificationValidatedFirstMonotonicUs",
    "ServiceNotificationValidatedLastMonotonicUs", "ServiceMpduDispatchCount",
    "ServiceMpduDispatchFirstMonotonicUs", "ServiceMpduDispatchLastMonotonicUs",
    "ServiceAddbufFailedCount", "ServiceAddbufFailedFirstMonotonicUs",
    "ServiceAddbufFailedLastMonotonicUs", "ServiceCopyFailedCount",
    "ServiceCopyFailedFirstMonotonicUs", "ServiceCopyFailedLastMonotonicUs",
    "BridgeRxCapturedBefore", "BridgeRxCapturedAfter", "BridgeRxRejectedBefore",
    "BridgeRxRejectedAfter", "BridgeRxDecodedBefore", "BridgeRxDecodedAfter",
    "BridgeRxDeliveredBefore", "BridgeRxDeliveredAfter", "BridgeRxInputFailedBefore",
    "BridgeRxInputFailedAfter", "BridgeRxPendingBefore", "BridgeRxPendingAfter",
    "BridgeDiscoveryInputCallsBefore", "BridgeDiscoveryInputCallsAfter",
    "BridgeDiscoveryInputSuccessBefore", "BridgeDiscoveryInputSuccessAfter",
    "BridgeDiscoveryInputSameWindowCommittedBefore",
    "BridgeDiscoveryInputSameWindowCommittedAfter",
)
RX_WINDOW_INTEGER_KEYS = tuple(RX_WINDOW_PREFIX + suffix
                               for suffix in RX_WINDOW_SUFFIXES)
RX_WINDOW_EPOCH_KEYS = (
    "ContextGeneration", "PowerGeneration", "StationGeneration", "RocGeneration")
RX_WINDOW_MPDU_COUNT_KEYS = (
    "MpduEntryCount", "ManagementMpduCount", "ControlMpduCount", "DataMpduCount",
    "ExtensionMpduCount", "UnknownTypeMpduCount", "AwdlDataCandidateCount",
    "LeaseQualifiedCount", "LeaseUnqualifiedCount", "DescriptorUnavailableCount")
RX_WINDOW_BRIDGE_PAIRS = (
    ("RxCaptured", "BridgeRxCapturedBefore", "BridgeRxCapturedAfter"),
    ("RxRejected", "BridgeRxRejectedBefore", "BridgeRxRejectedAfter"),
    ("RxDecoded", "BridgeRxDecodedBefore", "BridgeRxDecodedAfter"),
    ("RxDelivered", "BridgeRxDeliveredBefore", "BridgeRxDeliveredAfter"),
    ("RxInputFailed", "BridgeRxInputFailedBefore", "BridgeRxInputFailedAfter"),
    ("RxPending", "BridgeRxPendingBefore", "BridgeRxPendingAfter"),
    ("DiscoveryInputCalls", "BridgeDiscoveryInputCallsBefore",
     "BridgeDiscoveryInputCallsAfter"),
    ("DiscoveryInputSuccess", "BridgeDiscoveryInputSuccessBefore",
     "BridgeDiscoveryInputSuccessAfter"),
    ("DiscoverySameWindowCommitted", "BridgeDiscoveryInputSameWindowCommittedBefore",
     "BridgeDiscoveryInputSameWindowCommittedAfter"),
)
RX_EVENTS_PROPERTY = "NativeAwdlDiscoveryRxWindowEventsBase64"
RX_EVENTS_MAGIC = 0x314E495758524441
RX_EVENTS_SCHEMA = 1
RX_EVENTS_HEADER = struct.Struct("<4Q")
RX_EVENTS_ROW = struct.Struct("<9Q")
RX_EVENTS_CAPACITY = 64
RX_EVENT_FLAGS_MASK = (1 << 10) - 1
RX_EVENT_ROUTE_RECORDED = 1 << 9
RX_EVENT_CLASS_NAMES = {
    0: "unknown", 1: "management", 2: "control", 3: "data", 4: "extension",
}
RX_EVENT_ROUTE_NAMES = {
    0: "not_recorded", 1: "pass_to_sta", 2: "queued_for_native",
    3: "duplicate_retry",
}
RX_LEASE_STATE_NAMES = {0: "unknown", 1: "command_roc_qualified", 2: "command_pending"}


def _unknown(status: str, reasons: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "status": status,
        "valid": False,
        "reasons": reasons,
        "radio_transmit_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
        **extra,
    }


def _bytes_payload(payload: Any) -> bytes | None:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return None
    return bytes(payload)


def decode_base64_property(value: Any) -> tuple[bytes | None, str | None]:
    if not isinstance(value, str):
        return None, "missing_or_wrong_type"
    try:
        return base64.b64decode(value, validate=True), None
    except (ValueError, base64.binascii.Error):
        return None, "invalid_base64"


def decode_legacy_qm_wire_snapshot(payload: Any) -> dict[str, Any]:
    """Decode the existing address-free QM facts using its actual field count."""
    raw = _bytes_payload(payload)
    if raw is None:
        return _unknown("unknown_missing_or_wrong_type", ["payload_not_bytes"])
    expected_size = len(_LEGACY.QM_WIRE_FIELD_NAMES) * 8
    if _LEGACY.QM_WIRE_SIZE != expected_size:
        return _unknown("unknown_decoder_field_count_mismatch",
                        ["legacy_decoder_size_disagrees_with_field_count"],
                        expected_bytes=expected_size,
                        decoder_bytes=_LEGACY.QM_WIRE_SIZE)
    if len(raw) != expected_size:
        return _unknown("unknown_invalid_length", ["payload_length_mismatch"],
                        payload_length=len(raw), expected_length=expected_size)
    return _LEGACY.decode_qm_wire_osdata(raw)


def _legacy_identity(report: Mapping[str, Any] | None) -> dict[str, int] | None:
    if not isinstance(report, Mapping) or report.get("valid") is not True:
        return None
    values = report.get("values")
    if not isinstance(values, Mapping):
        return None
    names = {
        "token": "token",
        "context_generation": "context_generation",
        "power_generation": "power_generation",
        "station_generation": "station_generation",
        "roc_token": "roc_token",
    }
    result: dict[str, int] = {}
    for out_name, in_name in names.items():
        value = values.get(in_name)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return None
        result[out_name] = value
    return result


def _identity_matches(left: Mapping[str, int], right: Mapping[str, int]) -> bool:
    return all(left.get(key) == right.get(key) for key in (
        "token", "context_generation", "power_generation",
        "station_generation", "roc_token"))


def _decode_qws1(payload: Any) -> dict[str, Any]:
    raw = _bytes_payload(payload)
    if raw is None:
        return _unknown("unknown_missing_or_wrong_type", ["status_not_bytes"])
    if len(raw) != QWS1_BYTES:
        return _unknown("unknown_invalid_length", ["status_length_mismatch"],
                        payload_length=len(raw), expected_length=QWS1_BYTES)
    values = QWS1_STATUS.unpack(raw)
    magic, schema, byte_count, status, reserved, token, context, power, station, roc = values
    reasons = []
    if magic != QWS1_MAGIC:
        reasons.append("status_magic_mismatch")
    if schema != QWS1_SCHEMA:
        reasons.append("status_schema_unsupported")
    if byte_count != QWS1_BYTES:
        reasons.append("status_byte_count_mismatch")
    if reserved != 0:
        reasons.append("status_reserved_nonzero")
    if status not in QWS1_STATUS_NAMES:
        reasons.append("status_code_unsupported")
    if reasons:
        return _unknown("unknown_invalid_status", reasons)
    identity = {
        "token": token,
        "context_generation": context,
        "power_generation": power,
        "station_generation": station,
        "roc_token": roc,
    }
    if not all(identity.values()):
        return _unknown("unknown_status_identity_missing",
                        ["status_identity_missing"], status_code=status,
                        status_name=QWS1_STATUS_NAMES[status])
    return {
        "status": "valid_status_record",
        "valid": True,
        "status_code": status,
        "status_name": QWS1_STATUS_NAMES[status],
        "identity": identity,
        "published": status == 10,
        "explicit_failure": status in {2, 4, 5, 7, 8, 9},
        "radio_transmit_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


def _decode_qwr1(payload: Any) -> dict[str, Any]:
    raw = _bytes_payload(payload)
    if raw is None:
        return _unknown("unknown_missing_or_wrong_type", ["raw_snapshot_not_bytes"])
    if len(raw) != QWR1_TOTAL_BYTES:
        return _unknown("unknown_invalid_length", ["raw_snapshot_length_mismatch"],
                        payload_length=len(raw), expected_length=QWR1_TOTAL_BYTES)
    unpacked = QWR1_HEADER.unpack_from(raw)
    names = (
        "magic", "schema", "header_bytes", "total_bytes", "flags", "token",
        "context_generation", "power_generation", "station_generation", "roc_token",
        "station_id", "queue_id", "ring_size", "descriptor_index",
        "sequence_control", "frame_control", "command_actual_length",
        "command_copied_length", "mpdu_actual_length", "mpdu_copied_length",
        "command_copy_result", "mpdu_copy_result", "stage", "doorbell_us",
        "finish_us")
    values = dict(zip(names, unpacked))
    reasons = []
    if values["magic"] != QWR1_MAGIC:
        reasons.append("raw_magic_mismatch")
    if values["schema"] != QWR1_SCHEMA:
        reasons.append("raw_schema_unsupported")
    if values["header_bytes"] != QWR1_HEADER_BYTES:
        reasons.append("raw_header_size_mismatch")
    if values["total_bytes"] != QWR1_TOTAL_BYTES:
        reasons.append("raw_total_size_mismatch")
    if values["flags"] & ~QWR1_FLAGS_MASK:
        reasons.append("raw_unknown_flags")
    required_flags = QWR1_CANDIDATE | QWR1_COMMAND_COPIED | QWR1_MPDU_DONE | QWR1_STAGE_ACCEPTED
    if (values["flags"] & required_flags) != required_flags:
        reasons.append("raw_capture_flags_incomplete")
    if values["flags"] & (QWR1_COMMAND_TRUNCATED | QWR1_MPDU_TRUNCATED):
        reasons.append("raw_payload_truncated")
    if values["flags"] & QWR1_RAW_RESPONSE_CAPTURED:
        reasons.append("unexpected_raw_response_capture")
    if values["stage"] != QWR1_STAGED_AWAITING_PUBLISH:
        reasons.append("raw_stage_not_staged_for_publish")
    identity = {key: values[key] for key in (
        "token", "context_generation", "power_generation",
        "station_generation", "roc_token")}
    if not all(identity.values()):
        reasons.append("raw_identity_missing")
    if values["command_actual_length"] <= 0 or \
            values["command_actual_length"] > QWR1_COMMAND_CAPACITY or \
            values["command_copied_length"] != values["command_actual_length"]:
        reasons.append("command_payload_length_invalid")
    if values["mpdu_actual_length"] <= 0 or \
            values["mpdu_actual_length"] > QWR1_MPDU_CAPACITY or \
            values["mpdu_copied_length"] != values["mpdu_actual_length"]:
        reasons.append("mpdu_payload_length_invalid")
    if values["command_copy_result"] != 0 or values["mpdu_copy_result"] != 0:
        reasons.append("raw_copy_failed")
    if values["doorbell_us"] == 0 or values["finish_us"] == 0 or \
            values["finish_us"] < values["doorbell_us"]:
        reasons.append("raw_submit_timestamps_invalid")
    values["identity"] = identity
    values["command_bytes_captured"] = values["command_copied_length"]
    values["mpdu_bytes_captured"] = values["mpdu_copied_length"]
    values["valid"] = not reasons
    values["reasons"] = reasons
    values["status"] = ("valid_private_qm_raw_candidate" if not reasons else
                        "unknown_invalid_private_qm_raw_candidate")
    values["radio_transmit_proven"] = False
    values["peer_receipt_proven"] = False
    values["airdrop_proven"] = False
    return values


def decode_qm_raw_publication(raw_payload: Any, status_payload: Any,
                              legacy_qm_report: Mapping[str, Any] | None) -> dict[str, Any]:
    """Require published QWS1 status and exact identity across both snapshots."""
    status = _decode_qws1(status_payload)
    if not status.get("valid"):
        return _unknown("unknown_status_unavailable_or_invalid",
                        status.get("reasons", [status.get("status", "unknown")]),
                        status_record=status)
    if status["explicit_failure"]:
        return {
            "status": "explicit_raw_capture_failure",
            "valid": False,
            "failure_status": status["status_name"],
            "failure_status_code": status["status_code"],
            "raw_capture_valid": False,
            "radio_transmit_proven": False,
            "peer_receipt_proven": False,
            "airdrop_proven": False,
        }
    if not status["published"]:
        return _unknown("unknown_raw_capture_not_published",
                        ["qws1_status_not_published"], status_record=status)

    raw = _decode_qwr1(raw_payload)
    if not raw.get("valid"):
        return _unknown("unknown_raw_snapshot_unavailable_or_invalid",
                        raw.get("reasons", [raw.get("status", "unknown")]),
                        status_record=status, raw_snapshot=raw)
    legacy_identity = _legacy_identity(legacy_qm_report)
    if legacy_identity is None:
        return _unknown("unknown_legacy_facts_unavailable_or_invalid",
                        ["legacy_qm_identity_unavailable"],
                        status_record=status, raw_snapshot=raw)
    if not _identity_matches(status["identity"], raw["identity"]):
        return _unknown("unknown_raw_status_identity_mismatch",
                        ["qws1_qwr1_identity_mismatch"],
                        status_record=status, raw_snapshot=raw)
    if not _identity_matches(legacy_identity, raw["identity"]):
        return _unknown("unknown_legacy_facts_identity_mismatch",
                        ["qwr1_legacy_facts_identity_mismatch"],
                        status_record=status, raw_snapshot=raw,
                        legacy_facts_identity=legacy_identity)
    legacy_values = legacy_qm_report.get("values")
    if not isinstance(legacy_values, Mapping):
        return _unknown("unknown_legacy_facts_unavailable_or_invalid",
                        ["legacy_qm_values_unavailable"],
                        status_record=status, raw_snapshot=raw)
    raw_legacy_fields = {
        "station_id": "station_id",
        "queue_id": "queue_id",
        "ring_size": "ring_size",
        "descriptor_index": "descriptor_index",
        "sequence_control": "sequence_control",
        "frame_control": "frame_control",
        "mpdu_actual_length": "mpdu_length",
    }
    mismatched_wire_fields = [
        raw_name for raw_name, legacy_name in raw_legacy_fields.items()
        if raw[raw_name] != legacy_values.get(legacy_name)
    ]
    if mismatched_wire_fields:
        return _unknown("unknown_raw_legacy_descriptor_mismatch",
                        ["qwr1_legacy_descriptor_fields_mismatch"],
                        mismatched_fields=mismatched_wire_fields,
                        status_record=status, raw_snapshot=raw)
    return {
        "status": "private_command_mpdu_capture_published",
        "valid": True,
        "capture_identity_matches_status_and_legacy_facts": True,
        "status_code": status["status_code"],
        "status_name": status["status_name"],
        "identity": raw["identity"],
        "wire_fields": {
            "station_id": raw["station_id"],
            "queue_id": raw["queue_id"],
            "ring_size": raw["ring_size"],
            "descriptor_index": raw["descriptor_index"],
            "sequence_control": raw["sequence_control"],
            "frame_control": raw["frame_control"],
            "mpdu_length": raw["mpdu_actual_length"],
            "legacy_host_pre_doorbell_us": legacy_values.get("host_pre_doorbell_us"),
        },
        "command_bytes_captured": raw["command_bytes_captured"],
        "mpdu_bytes_captured": raw["mpdu_bytes_captured"],
        "doorbell_us": raw["doorbell_us"],
        "finish_us": raw["finish_us"],
        "raw_response_captured": False,
        "radio_transmit_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


def _int_value(values: Mapping[str, Any], key: str) -> int | None:
    value = values.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        return None
    return value


def _data_tx_trace_key(suffix: str) -> str:
    return "NativeP2PDataTxTrace" + suffix


def _data_tx_record_key(slot: int, suffix: str) -> str:
    return f"NativeP2PDataTxTraceRecord{slot}{suffix}"


def decode_data_tx_trace(values: Mapping[str, Any],
                         expected_identity: Mapping[str, int] | None = None,
                         expected_wire_fields: Mapping[str, int] | None = None
                         ) -> dict[str, Any]:
    """Validate the complete TX ledger and match one immutable row exactly."""
    required = [_data_tx_trace_key(field) for field in DATA_TX_TRACE_HEADER_SUFFIXES]
    required.extend(_data_tx_record_key(slot, field)
                    for slot in range(DATA_TX_TRACE_SLOTS)
                    for field in DATA_TX_TRACE_RECORD_SUFFIXES)
    missing = [key for key in required if _int_value(values, key) is None]
    if missing:
        return _unknown("unknown_missing_or_invalid_data_tx_trace_fields",
                        ["required_numeric_trace_fields_missing_or_invalid"],
                        missing_fields=missing,
                        identity_match_status="unknown_trace_fields_missing",
                        matched_record=None, matched_record_events=None)

    header = {_data_tx_trace_key(field): _int_value(values, _data_tx_trace_key(field))
              for field in DATA_TX_TRACE_HEADER_SUFFIXES}
    begin = header[_data_tx_trace_key("SnapshotVersionBegin")]
    end = header[_data_tx_trace_key("SnapshotVersionEnd")]
    reasons = []
    if header[_data_tx_trace_key("SchemaVersion")] != 1:
        reasons.append("unsupported_data_tx_trace_schema")
    if begin == 0 or begin != end or begin & 1:
        reasons.append("data_tx_trace_snapshot_revision_unstable")
    if header[_data_tx_trace_key("SnapshotComplete")] != 1:
        reasons.append("data_tx_trace_snapshot_incomplete")
    if header[_data_tx_trace_key("CoverageUnknown")] != 0:
        reasons.append("data_tx_trace_coverage_unknown")
    if header[_data_tx_trace_key("DroppedCount")] != 0:
        reasons.append("data_tx_trace_dropped_records")
    if header[_data_tx_trace_key("Count")] > DATA_TX_TRACE_SLOTS:
        reasons.append("data_tx_trace_count_exceeds_capacity")
    owner_present = header[_data_tx_trace_key("OwnerPresent")]
    owner_serial = header[_data_tx_trace_key("OwnerSerial")]
    owner_diag = header[_data_tx_trace_key("OwnerDiagnosticGeneration")]
    if owner_present != 1:
        reasons.append("data_tx_trace_owner_missing")
    if not owner_serial or owner_serial != owner_diag:
        reasons.append("data_tx_trace_owner_serial_diagnostic_mismatch")
    owner_epochs = {
        "ContextGeneration": header[_data_tx_trace_key("OwnerContextGeneration")],
        "PowerGeneration": header[_data_tx_trace_key("OwnerPowerGeneration")],
        "StationGeneration": header[_data_tx_trace_key("OwnerStationGeneration")],
        "RocGeneration": header[_data_tx_trace_key("OwnerRocGeneration")],
    }
    if not all(owner_epochs.values()):
        reasons.append("data_tx_trace_owner_generation_missing")

    rows = []
    for slot in range(DATA_TX_TRACE_SLOTS):
        row = {suffix: _int_value(values, _data_tx_record_key(slot, suffix))
               for suffix in DATA_TX_TRACE_RECORD_SUFFIXES}
        present = row["RecordPresent"]
        if present not in (0, 1):
            reasons.append(f"record_{slot}_present_not_boolean")
        if present:
            if row["Used"] != 1:
                reasons.append(f"record_{slot}_used_flag_invalid")
            if row["StagePresenceFlags"] & ~DATA_TX_TRACE_KNOWN_STAGE_MASK:
                reasons.append(f"record_{slot}_unknown_stage_bits")
            if row["RecordSerial"] == 0 or row["DiagnosticGeneration"] == 0:
                reasons.append(f"record_{slot}_owner_identity_missing")
            if not all(row[field] for field in (
                    "Token", "ContextGeneration", "PowerGeneration",
                    "StationGeneration", "RocGeneration")):
                reasons.append(f"record_{slot}_generation_missing")
            if row["QueueBornUs"] == 0 or not (
                    row["StagePresenceFlags"] & DATA_TX_TRACE_STAGE_BITS["queue_born"]):
                reasons.append(f"record_{slot}_queue_birth_missing")
            rows.append({"slot": slot, **row})
    if len(rows) != header[_data_tx_trace_key("Count")]:
        reasons.append("data_tx_trace_count_mismatch")

    exact_rows = []
    if expected_identity is not None:
        identity_fields = (
            ("Token", "token"),
            ("ContextGeneration", "context_generation"),
            ("PowerGeneration", "power_generation"),
            ("StationGeneration", "station_generation"),
            ("RocGeneration", "roc_generation"),
        )
        for row in rows:
            if all(row[record_key] == expected_identity.get(identity_key)
                   for record_key, identity_key in identity_fields):
                exact_rows.append(row)

    owner_matched_rows = []
    for row in exact_rows:
        if row["DiagnosticGeneration"] == owner_diag and all(
                owner_epochs[field] == row[field] for field in owner_epochs):
            owner_matched_rows.append(row)
    descriptor_matches = None
    timing_matches = None
    if expected_wire_fields is not None and len(owner_matched_rows) == 1:
        matched_for_wire = owner_matched_rows[0]
        expected_to_trace = {
            "queue_id": "QueueId",
            "ring_size": "RingSize",
            "descriptor_index": "DescriptorIndex",
            "sequence_control": "SequenceControl",
            "frame_control": "FrameControl",
            "mpdu_length": "MpduLength",
        }
        wire_mismatches = [
            wire_name for wire_name, trace_name in expected_to_trace.items()
            if matched_for_wire[trace_name] != expected_wire_fields.get(wire_name)
        ]
        descriptor_matches = not wire_mismatches
        timing_keys = ("legacy_host_pre_doorbell_us", "raw_doorbell_us", "raw_finish_us")
        has_timing = any(key in expected_wire_fields for key in timing_keys)
        if has_timing:
            host_pre = expected_wire_fields.get("legacy_host_pre_doorbell_us")
            raw_doorbell = expected_wire_fields.get("raw_doorbell_us")
            raw_finish = expected_wire_fields.get("raw_finish_us")
            trace_doorbell = matched_for_wire["DoorbellIssuedUs"]
            timing_fields_valid = all(isinstance(value, int) and not isinstance(value, bool)
                                      and value > 0 for value in
                                      (host_pre, raw_doorbell, raw_finish, trace_doorbell))
            if timing_fields_valid:
                timing_matches = (
                    matched_for_wire["QueueBornUs"] <= host_pre <= raw_doorbell <=
                    trace_doorbell <= raw_finish)
            else:
                timing_matches = False
            if not (matched_for_wire["StagePresenceFlags"] &
                    DATA_TX_TRACE_STAGE_BITS["doorbell_issued"]):
                timing_matches = False
        if matched_for_wire["QueueMetadataPresent"] != 1 or matched_for_wire["Eligible"] != 1:
            reasons.append("trace_row_queue_not_eligible_or_metadata_missing")
    else:
        wire_mismatches = []
    if timing_matches is False:
        reasons.append("trace_raw_doorbell_timing_mismatch")

    if len(exact_rows) == 1 and len(owner_matched_rows) == 0:
        reasons.append("trace_owner_epoch_row_mismatch")
    if descriptor_matches is False:
        reasons.append("trace_descriptor_fields_mismatch")
        reasons.extend("trace_wire_" + field + "_mismatch" for field in wire_mismatches)
    if len(exact_rows) > 1:
        reasons.append("ambiguous_duplicate_trace_identity")
    valid = not reasons
    matched = (owner_matched_rows[0] if valid and len(owner_matched_rows) == 1 and
               descriptor_matches is not False else None)
    if expected_identity is None:
        identity_status = "unknown_expected_identity_missing"
    elif not valid:
        identity_status = "unknown_trace_invalid"
    elif len(exact_rows) == 0:
        identity_status = "identity_mismatch"
    elif len(exact_rows) > 1:
        identity_status = "ambiguous_multiple_identity_matches"
    elif len(owner_matched_rows) == 0:
        identity_status = "trace_row_owner_epoch_mismatch"
    elif descriptor_matches is False:
        identity_status = "trace_descriptor_mismatch"
    elif timing_matches is False:
        identity_status = "trace_raw_doorbell_timing_mismatch"
    else:
        identity_status = "exact_local_identity_match"

    events = None
    if matched is not None:
        stage_mask = matched["StagePresenceFlags"]
        def observed(name: str, time_field: str) -> bool:
            return bool(stage_mask & DATA_TX_TRACE_STAGE_BITS[name]) and matched[time_field] > 0
        completion_seen = observed("completion", "CompletionUs")
        events = {
            "queue_born": observed("queue_born", "QueueBornUs"),
            "dequeued": observed("dequeued", "DequeuedUs"),
            "submit_call_start": observed("submit_call_start", "SubmitCallStartUs"),
            "final_wire": observed("final_wire", "FinalWireUs"),
            "ring_reserved": observed("ring_reserved", "RingReservedUs"),
            "descriptor_ready": observed("descriptor_ready", "DescriptorReadyUs"),
            "doorbell_marked": observed("doorbell_marked", "DoorbellMarkedUs"),
            "doorbell_issued": observed("doorbell_issued", "DoorbellIssuedUs"),
            "tx_response_tap": observed("tx_response_tap", "TxRspTapUs"),
            "completion": completion_seen,
            "submit_call_end": observed("submit_call_end", "SubmitCallEndUs"),
            # IntelP2PActionTx::Result::kCompletion is 10. kReady (0) is a
            # pre-submit state and kFrameFailed (9) is an unsuccessful MPDU.
            "local_completion_succeeded": completion_seen and matched["CompletionResult"] == 10,
            "doorbell_issued_us": matched["DoorbellIssuedUs"] or None,
            "tx_response_tap_us": matched["TxRspTapUs"] or None,
            "completion_us": matched["CompletionUs"] or None,
            "submit_call_result": matched["SubmitCallResult"],
            "completion_result": matched["CompletionResult"],
            "tx_rsp_handler_disposition": matched["TxRspHandlerDisposition"],
            "association_strength": matched["AssociationStrength"],
            "record_serial": matched["RecordSerial"],
            "diagnostic_generation": matched["DiagnosticGeneration"],
            "queue_born_us": matched["QueueBornUs"],
        }
    return {
        "status": "valid_complete_data_tx_trace" if valid else
                  "unknown_invalid_data_tx_trace",
        "valid": valid,
        "reasons": reasons,
        "schema_version": header[_data_tx_trace_key("SchemaVersion")],
        "snapshot_version": begin if valid else None,
        "revision": header[_data_tx_trace_key("Revision")],
        "owner_present": header[_data_tx_trace_key("OwnerPresent")] == 1,
        "record_count": len(rows),
        "records": rows,
        "owner_serial": owner_serial,
        "owner_diagnostic_generation": owner_diag,
        "owner_epochs": owner_epochs,
        "identity_match_status": identity_status,
        "descriptor_fields_match": descriptor_matches,
        "descriptor_mismatches": wire_mismatches,
        "doorbell_timing_match": timing_matches,
        "matched_record": matched,
        "matched_record_events": events,
        "radio_transmit_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


def decode_discovery_rx_window(values: Mapping[str, Any],
                               expected_identity: Mapping[str, int] | None = None
                               ) -> dict[str, Any]:
    """Decode RX-window aggregates without upgrading lease data to owner proof."""
    missing = [key for key in RX_WINDOW_INTEGER_KEYS if _int_value(values, key) is None]
    if missing:
        return _unknown("unknown_missing_or_invalid_rx_window_fields",
                        ["required_rx_window_fields_missing_or_invalid"],
                        missing_fields=missing)
    field = lambda suffix: _int_value(values, RX_WINDOW_PREFIX + suffix)
    begin, end = field("SnapshotBegin"), field("SnapshotEnd")
    start_us, end_us = field("StartMonotonicUs"), field("EndMonotonicUs")
    first_us, last_us = field("FirstMpduEntryMonotonicUs"), field("LastMpduEntryMonotonicUs")
    mpdu_count = field("MpduEntryCount")
    identity = {
        "context_generation": field("ContextGeneration"),
        "power_generation": field("PowerGeneration"),
        "station_generation": field("StationGeneration"),
        "roc_generation": field("RocGeneration"),
    }
    reasons = []
    if field("Published") != 1:
        reasons.append("rx_window_not_published")
    if begin == 0 or begin != end or begin & 1:
        reasons.append("rx_window_snapshot_revision_unstable")
    if field("SchemaVersion") != 1:
        reasons.append("rx_window_schema_unsupported")
    if field("Valid") != 1:
        reasons.append("rx_window_marked_invalid")
    overflow = field("Overflow")
    if overflow not in (0, 1):
        reasons.append("rx_window_overflow_flag_invalid")
    if field("Complete") != (1 if overflow == 0 else 0):
        reasons.append("rx_window_complete_overflow_mismatch")
    if field("CloseReason") != 1:
        reasons.append("rx_window_not_closed_by_canonical_roc_end")
    if field("DriverGeneration") == 0:
        reasons.append("rx_window_driver_generation_missing")
    if field("RocConfiguration") != 3:
        reasons.append("rx_window_roc_configuration_mismatch")
    if start_us == 0 or end_us == 0:
        reasons.append("rx_window_time_missing")
    if not all(identity.values()):
        reasons.append("rx_window_generation_missing")
    if end_us < start_us:
        reasons.append("rx_window_bounds_reversed")
    if mpdu_count:
        if not (start_us <= first_us <= last_us <= end_us):
            reasons.append("rx_entry_times_outside_window")
    elif first_us or last_us:
        reasons.append("rx_entry_time_without_mpdu")
    class_counts = {
        "management": field("ManagementMpduCount"),
        "control": field("ControlMpduCount"),
        "data": field("DataMpduCount"),
        "extension": field("ExtensionMpduCount"),
        "unknown": field("UnknownTypeMpduCount"),
    }
    if sum(class_counts.values()) != mpdu_count:
        reasons.append("rx_frame_class_count_mismatch")
    lease_qualified = field("LeaseQualifiedCount")
    lease_unqualified = field("LeaseUnqualifiedCount")
    if lease_qualified + lease_unqualified != mpdu_count:
        reasons.append("rx_lease_classification_count_mismatch")
    if field("DescriptorUnavailableCount") > mpdu_count:
        reasons.append("rx_descriptor_unavailable_count_exceeds_entries")

    same_generation: bool | None = None
    generation_reasons = []
    if expected_identity is None:
        generation_status = "unknown_tx_identity_missing"
    else:
        expected_keys = (
            "context_generation", "power_generation", "station_generation", "roc_generation")
        same_generation = all(identity[key] == expected_identity.get(key)
                              for key in expected_keys)
        generation_status = ("same_generation" if same_generation else
                             "generation_mismatch")
        if not same_generation:
            generation_reasons.append("rx_window_tx_generation_mismatch")

    bridge = {}
    for label, before_suffix, after_suffix in RX_WINDOW_BRIDGE_PAIRS:
        before, after = field(before_suffix), field(after_suffix)
        is_pending_depth = label == "RxPending"
        bridge[label] = {
            "before": before,
            "after": after,
            "delta": after - before,
            "counter_order_valid": is_pending_depth or after >= before,
            "is_live_queue_depth": is_pending_depth,
        }
        if after < before and not is_pending_depth:
            reasons.append("bridge_counter_reversed_" + label)

    service_events = {}
    service_kinds = (
        "RxDrain", "RxRingSlot", "NotificationSeen", "HeaderRejected",
        "LengthRejected", "NotificationValidated", "MpduDispatch",
        "AddbufFailed", "CopyFailed",
    )
    for kind in service_kinds:
        count = field("Service" + kind + "Count")
        first = field("Service" + kind + "FirstMonotonicUs")
        last = field("Service" + kind + "LastMonotonicUs")
        service_events[kind] = {"count": count, "first_us": first or None,
                                "last_us": last or None}
        if count == 0 and (first or last):
            reasons.append("rx_service_time_without_count_" + kind)
        if count > 0 and not (start_us <= first <= last <= end_us):
            reasons.append("rx_service_times_outside_window_" + kind)

    scalar_aggregates_valid = not reasons
    if overflow:
        reasons.append("rx_window_overflow_event_sequence_incomplete")
    valid = not reasons
    result = {
        "status": "valid_discovery_rx_window" if valid else
                  "unknown_invalid_discovery_rx_window",
        "valid": valid,
        "scalar_aggregates_valid": scalar_aggregates_valid,
        "event_sequence_complete": overflow == 0,
        "reasons": reasons,
        "generation_status": generation_status,
        "same_generation_as_tx": same_generation,
        "correlated_to_tx_generation": valid and same_generation is True,
        "generation_reasons": generation_reasons,
        "identity": identity,
        "start_monotonic_us": start_us,
        "end_monotonic_us": end_us,
        "first_mpdu_entry_monotonic_us": first_us,
        "last_mpdu_entry_monotonic_us": last_us,
        "mpdu_entry_count": mpdu_count,
        "overflow": overflow,
        "frame_class_counts": class_counts,
        "lease_qualified_count": lease_qualified,
        "lease_unqualified_count": lease_unqualified,
        "awdl_data_candidate_count": field("AwdlDataCandidateCount"),
        "descriptor_unavailable_count": field("DescriptorUnavailableCount"),
        "crc_rejected_count": field("CrcRejectedCount"),
        "overrun_rejected_count": field("OverrunRejectedCount"),
        "channel_149_count": field("Channel149Count"),
        "data_route_counts": {
            "pass_to_sta": field("RoutePassToStaCount"),
            "queued_for_native": field("RouteQueuedForNativeCount"),
            "duplicate_retry": field("RouteDuplicateRetryCount"),
        },
        "service_events": service_events,
        "rx_entry_counts": {
            suffix: field(suffix) for suffix in RX_WINDOW_MPDU_COUNT_KEYS
        },
        "bridge_boundary_counters": bridge,
        "bridge_boundary_semantics": (
            "START-to-END snapshots; not split at the QM doorbell"),
        "radio_transmit_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }
    return result


def decode_discovery_rx_events(payload: Any,
                               rx_window: Mapping[str, Any] | None = None,
                               raw_doorbell_us: int | None = None,
                               tx_generation_matches: bool | None = None
                               ) -> dict[str, Any]:
    """Decode ADRXWIN1 MPDU entries; overflow never proves event absence."""
    raw = _bytes_payload(payload)
    if raw is None:
        return _unknown("unknown_rx_events_missing_or_wrong_type",
                        ["rx_events_not_bytes"])
    if len(raw) < RX_EVENTS_HEADER.size or len(raw) % 8:
        return _unknown("unknown_rx_events_invalid_length",
                        ["rx_events_length_invalid"], payload_length=len(raw))
    magic, schema, total_words, event_count = RX_EVENTS_HEADER.unpack_from(raw)
    reasons = []
    if magic != RX_EVENTS_MAGIC:
        reasons.append("rx_events_magic_mismatch")
    if schema != RX_EVENTS_SCHEMA:
        reasons.append("rx_events_schema_unsupported")
    if event_count > RX_EVENTS_CAPACITY:
        reasons.append("rx_events_count_exceeds_capacity")
    if total_words != len(raw) // 8:
        reasons.append("rx_events_total_word_count_mismatch")
    expected_words = 4 + event_count * 9
    if total_words != expected_words or len(raw) != expected_words * 8:
        reasons.append("rx_events_payload_size_mismatch")
    if reasons:
        return _unknown("unknown_invalid_rx_events", reasons,
                        event_count=event_count, total_word_count=total_words)

    window = rx_window if isinstance(rx_window, Mapping) else {}
    start_us, end_us = window.get("start_monotonic_us"), window.get("end_monotonic_us")
    mpdu_count, overflow = window.get("mpdu_entry_count"), window.get("overflow")
    decoded_events = []
    class_counts = {name: 0 for name in RX_EVENT_CLASS_NAMES.values()}
    route_counts = {name: 0 for name in RX_EVENT_ROUTE_NAMES.values()}
    lease_qualified = lease_unqualified = awdl_candidate_count = descriptor_missing = 0
    crc_rejected = overrun_rejected = 0
    channel_149 = 0
    previous_time = 0
    for index in range(event_count):
        offset = RX_EVENTS_HEADER.size + index * RX_EVENTS_ROW.size
        (timestamp, ordinal, frame_class, flags, channel, mpdu_length,
         frame_control, lease_reason, route_result) = RX_EVENTS_ROW.unpack_from(raw, offset)
        if any(value > 0xFFFFFFFF for value in (
                ordinal, frame_class, flags, channel, mpdu_length,
                frame_control, lease_reason, route_result)):
            reasons.append(f"event_{index}_field_out_of_u32_range")
        if timestamp == 0 or timestamp < previous_time:
            reasons.append(f"event_{index}_timestamp_order_invalid")
        previous_time = timestamp
        if ordinal != index + 1:
            reasons.append(f"event_{index}_ordinal_not_sequential")
        class_name = RX_EVENT_CLASS_NAMES.get(frame_class)
        if class_name is None:
            reasons.append(f"event_{index}_frame_class_invalid")
        else:
            class_counts[class_name] += 1
        if flags & ~RX_EVENT_FLAGS_MASK:
            reasons.append(f"event_{index}_unknown_flags")
        descriptor_present = bool(flags & (1 << 0))
        fc_present = bool(flags & (1 << 1))
        raw_status_present = bool(flags & (1 << 2))
        crc_ok = bool(flags & (1 << 3))
        overrun_ok = bool(flags & (1 << 4))
        channel_present = bool(flags & (1 << 5))
        length_present = bool(flags & (1 << 6))
        lease_ok = bool(flags & (1 << 7))
        awdl_is_candidate = bool(flags & (1 << 8))
        route_recorded = bool(flags & RX_EVENT_ROUTE_RECORDED)
        descriptor_missing += 0 if descriptor_present else 1
        lease_qualified += 1 if lease_ok else 0
        lease_unqualified += 0 if lease_ok else 1
        awdl_candidate_count += 1 if awdl_is_candidate else 0
        channel_149 += 1 if channel_present and channel == 149 else 0
        if raw_status_present and not crc_ok:
            crc_rejected += 1
        if raw_status_present and not overrun_ok:
            overrun_rejected += 1
        if not channel_present and channel != 0:
            reasons.append(f"event_{index}_channel_without_presence")
        if not length_present and mpdu_length != 0:
            reasons.append(f"event_{index}_length_without_presence")
        if not fc_present and frame_control != 0:
            reasons.append(f"event_{index}_frame_control_without_presence")
        if fc_present and frame_control > 0xFFFF:
            reasons.append(f"event_{index}_frame_control_out_of_range")
        route_name = RX_EVENT_ROUTE_NAMES.get(route_result)
        lease_state_name = RX_LEASE_STATE_NAMES.get(lease_reason)
        if lease_state_name is None:
            reasons.append(f"event_{index}_lease_state_invalid")
        elif lease_ok != (lease_reason == 1):
            reasons.append(f"event_{index}_lease_flag_state_mismatch")
        if route_name is None:
            reasons.append(f"event_{index}_route_result_invalid")
        elif route_recorded:
            if route_result == 0:
                reasons.append(f"event_{index}_recorded_route_is_not_recorded")
            else:
                route_counts[route_name] += 1
        elif route_result != 0:
            reasons.append(f"event_{index}_route_without_recorded_flag")
        if (isinstance(start_us, int) and isinstance(end_us, int) and
                not start_us <= timestamp <= end_us):
            reasons.append(f"event_{index}_outside_rx_window")

        if tx_generation_matches is True and isinstance(raw_doorbell_us, int) and raw_doorbell_us > 0:
            relative = ("before_raw_doorbell" if timestamp < raw_doorbell_us else
                        "after_raw_doorbell" if timestamp > raw_doorbell_us else
                        "same_monotonic_microsecond")
        else:
            relative = "unknown_tx_generation_or_doorbell"
        decoded_events.append({
            "timestamp_us": timestamp,
            "ordinal": ordinal,
            "frame_class": class_name or "unknown_invalid",
            "flags": flags,
            "descriptor_present": descriptor_present,
            "frame_control_present": fc_present,
            "raw_status_present": raw_status_present,
            "crc_ok": crc_ok if raw_status_present else None,
            "overrun_ok": overrun_ok if raw_status_present else None,
            "channel": channel if channel_present else None,
            "mpdu_length": mpdu_length if length_present else None,
            "frame_control": frame_control if fc_present else None,
            "lease_qualified": lease_ok,
            "lease_state": lease_state_name or "unknown_invalid",
            "awdl_data_candidate": awdl_is_candidate,
            "data_route_recorded": route_recorded,
            "data_route": route_name if route_recorded else None,
            "relative_to_raw_doorbell": relative,
        })

    sequence_complete = overflow == 0
    if overflow not in (0, 1):
        reasons.append("rx_window_overflow_unknown")
    if isinstance(mpdu_count, int):
        expected_event_count = min(mpdu_count, RX_EVENTS_CAPACITY) if overflow == 1 else mpdu_count
        if event_count != expected_event_count:
            reasons.append("rx_events_scalar_count_mismatch")
    if sequence_complete and isinstance(rx_window, Mapping):
        expected_classes = rx_window.get("frame_class_counts", {})
        if any(class_counts[name] != expected_classes.get(name)
               for name in class_counts):
            reasons.append("rx_events_frame_class_aggregate_mismatch")
        if lease_qualified != rx_window.get("lease_qualified_count"):
            reasons.append("rx_events_lease_qualified_aggregate_mismatch")
        if lease_unqualified != rx_window.get("lease_unqualified_count"):
            reasons.append("rx_events_lease_unqualified_aggregate_mismatch")
        if awdl_candidate_count != rx_window.get("awdl_data_candidate_count"):
            reasons.append("rx_events_awdl_candidate_aggregate_mismatch")
        if descriptor_missing != rx_window.get("descriptor_unavailable_count"):
            reasons.append("rx_events_descriptor_aggregate_mismatch")
        if crc_rejected != rx_window.get("crc_rejected_count"):
            reasons.append("rx_events_crc_aggregate_mismatch")
        if overrun_rejected != rx_window.get("overrun_rejected_count"):
            reasons.append("rx_events_overrun_aggregate_mismatch")
        if channel_149 != rx_window.get("channel_149_count"):
            reasons.append("rx_events_channel_149_aggregate_mismatch")
        for route in ("pass_to_sta", "queued_for_native", "duplicate_retry"):
            if route_counts[route] != rx_window.get("data_route_counts", {}).get(route):
                reasons.append("rx_events_route_aggregate_mismatch_" + route)

    valid = not reasons
    return {
        "status": "valid_rx_entry_events" if valid else "unknown_invalid_rx_entry_events",
        "valid": valid,
        "reasons": reasons,
        "schema": schema,
        "event_count": event_count,
        "mpdu_entry_count": mpdu_count,
        "overflow": overflow,
        "sequence_complete": sequence_complete,
        "frame_class_counts_from_events": class_counts,
        "route_counts_from_events": route_counts,
        "lease_qualified_count_from_events": lease_qualified,
        "lease_unqualified_count_from_events": lease_unqualified,
        "awdl_data_candidate_count_from_events": awdl_candidate_count,
        "descriptor_unavailable_count_from_events": descriptor_missing,
        "crc_rejected_count_from_events": crc_rejected,
        "overrun_rejected_count_from_events": overrun_rejected,
        "channel_149_count_from_events": channel_149,
        "events": decoded_events,
        "scope": ("MPDUs that reached iwx_rx_mpdu_mq. This does not count every "
                  "RF frame or prove native protocol dispatch or peer receipt."),
        "radio_transmit_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


def _identity_for_trace(qm: Mapping[str, Any] | None) -> dict[str, int] | None:
    if not isinstance(qm, Mapping) or qm.get("valid") is not True:
        return None
    values = qm.get("values")
    if not isinstance(values, Mapping):
        return None
    identity = {
        "token": values.get("token"),
        "context_generation": values.get("context_generation"),
        "power_generation": values.get("power_generation"),
        "station_generation": values.get("station_generation"),
        # ItlIwxP2PAction.cpp supplies its canonical rocToken as both the QM
        # context and the DataTxTrace RocGeneration. This is a producer-side
        # join for this path, not a general claim that token and generation
        # fields share semantics.
        "roc_generation": values.get("roc_token"),
    }
    for key in ("token", "context_generation", "power_generation",
                "station_generation", "roc_generation"):
        if not isinstance(identity[key], int) or isinstance(identity[key], bool) or identity[key] <= 0:
            return None
    if identity["context_generation"] != identity["roc_generation"]:
        return None
    return identity


def decode_test136_receipt(receipt: Any) -> dict[str, Any]:
    """Decode a private helper JSON receipt into a base64-free public summary."""
    if not isinstance(receipt, Mapping):
        return _unknown("unknown_receipt_wrong_type", ["receipt_not_object"])
    final = receipt.get("final")
    if not isinstance(final, Mapping):
        return _unknown("unknown_final_snapshot_missing", ["final_not_object"])

    legacy_bytes, legacy_error = decode_base64_property(
        final.get("NativeP2PQmWireSnapshotBase64"))
    legacy_qm = decode_legacy_qm_wire_snapshot(legacy_bytes) if legacy_error is None else \
        _unknown("unknown_legacy_qm_missing", [legacy_error or "legacy_qm_missing"])
    raw_bytes, raw_error = decode_base64_property(
        final.get("NativeP2PQmWireRawSnapshotPrivateBase64"))
    status_bytes, status_error = decode_base64_property(
        final.get("NativeP2PQmWireRawSnapshotPrivateStatusBase64"))
    if raw_error is not None or status_error is not None:
        raw_publication = _unknown("unknown_private_raw_osdata_missing",
                                   [reason for reason in (raw_error, status_error) if reason])
    else:
        raw_publication = decode_qm_raw_publication(
            raw_bytes, status_bytes, legacy_qm)

    expected_identity = _identity_for_trace(legacy_qm)
    legacy_values = legacy_qm.get("values") if isinstance(legacy_qm, Mapping) else None
    expected_wire_fields = None
    if isinstance(legacy_values, Mapping):
        expected_wire_fields = {
            "station_id": legacy_values.get("station_id"),
            "queue_id": legacy_values.get("queue_id"),
            "ring_size": legacy_values.get("ring_size"),
            "descriptor_index": legacy_values.get("descriptor_index"),
            "sequence_control": legacy_values.get("sequence_control"),
            "frame_control": legacy_values.get("frame_control"),
            "mpdu_length": legacy_values.get("mpdu_length"),
        }
    raw_wire_fields = raw_publication.get("wire_fields") \
        if raw_publication.get("valid") is True else None
    if isinstance(raw_wire_fields, Mapping):
        expected_wire_fields = dict(raw_wire_fields)
        expected_wire_fields["raw_doorbell_us"] = raw_publication.get("doorbell_us")
        expected_wire_fields["raw_finish_us"] = raw_publication.get("finish_us")
    trace = decode_data_tx_trace(final, expected_identity, expected_wire_fields)
    matched_record = trace.get("matched_record") if trace.get("valid") else None
    rx_expected = None
    if isinstance(matched_record, Mapping):
        rx_expected = {
            "context_generation": matched_record.get("ContextGeneration"),
            "power_generation": matched_record.get("PowerGeneration"),
            "station_generation": matched_record.get("StationGeneration"),
            "roc_generation": matched_record.get("RocGeneration"),
        }
    rx_window = decode_discovery_rx_window(final, rx_expected)
    rx_events_bytes, rx_events_error = decode_base64_property(
        final.get(RX_EVENTS_PROPERTY))
    raw_doorbell_us = raw_publication.get("doorbell_us") \
        if raw_publication.get("valid") is True else None
    rx_events = decode_discovery_rx_events(
        rx_events_bytes if rx_events_error is None else None,
        rx_window=rx_window,
        raw_doorbell_us=raw_doorbell_us,
        tx_generation_matches=rx_window.get("same_generation_as_tx"))
    current_aw_bytes, current_aw_error = decode_base64_property(
        final.get("NativeP2PCurrentAwAttemptOnlyBase64"))
    if current_aw_error is None:
        current_aw = _LEGACY.decode_current_aw_attempt_osdata(current_aw_bytes)
    else:
        current_aw = _unknown("unknown_current_aw_osdata_missing", [current_aw_error])
    current_aw_qm_crosscheck = _LEGACY.cross_check_attempt_qm_identity(
        current_aw, legacy_qm)

    trace_events = trace.get("matched_record_events")
    local_tx_path = {
        "exact_data_tx_trace_row_matched": isinstance(matched_record, Mapping),
        "driver_doorbell_issued_observed": bool(
            isinstance(trace_events, Mapping) and trace_events.get("doorbell_issued")),
        "local_tx_response_tap_observed": bool(
            isinstance(trace_events, Mapping) and trace_events.get("tx_response_tap")),
        "local_completion_observed": bool(
            isinstance(trace_events, Mapping) and trace_events.get("completion")),
        "local_completion_succeeded": bool(
            isinstance(trace_events, Mapping) and trace_events.get("local_completion_succeeded")),
        "firmware_echoes_full_identity": False,
        "radio_transmit_proven": False,
        "peer_ack_proven": False,
        "peer_receipt_proven": False,
    }
    raw_trace_join_valid = (
        raw_publication.get("valid") is True and
        trace.get("valid") is True and
        isinstance(matched_record, Mapping) and
        trace.get("identity_match_status") == "exact_local_identity_match" and
        trace.get("descriptor_fields_match") is True and
        trace.get("doorbell_timing_match") is True
    )

    return {
        "status": "decoded_private_test136_receipt",
        "valid": True,
        "run_id": receipt.get("run_id"),
        "expected_build": receipt.get("expected_build"),
        "expected_uuid": receipt.get("expected_uuid"),
        "browse": receipt.get("browse"),
        "cleanup": receipt.get("cleanup"),
        "publication": receipt.get("publication"),
        "address_free_qm_facts": legacy_qm,
        "current_aw_attempt_only": current_aw,
        "private_command_mpdu_capture": raw_publication,
        "raw_legacy_trace_join": {
            "status": "exact_single_record_match" if raw_trace_join_valid else
                      "unknown_or_mismatch",
            "raw_facts_status_identity_joined_to_one_trace_row": raw_trace_join_valid,
            "trace_identity_match_status": trace.get("identity_match_status"),
            "descriptor_fields_match": trace.get("descriptor_fields_match"),
            "doorbell_timing_match": trace.get("doorbell_timing_match"),
            "same_window_monotonic_join_is_local_only": True,
            "radio_transmit_proven": False,
            "peer_receipt_proven": False,
        },
        "data_tx_trace": trace,
        "local_tx_path": local_tx_path,
        "discovery_rx_window": rx_window,
        "discovery_rx_events": rx_events,
        "current_aw_qm_identity_crosscheck": current_aw_qm_crosscheck,
        "proof_limits": {
            "local_submission_is_driver_path_evidence_only": True,
            "firmware_completion_is_not_peer_ack": True,
            "firmware_echoes_full_identity": False,
            "peer_receipt_proven": False,
            "airdrop_proven": False,
            "note": ("Raw command/MPDU, DataTxTrace and RX-window events are local "
                     "driver observations; they do not establish RF airtime or peer receipt."),
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: decode_test136_receipt.py PRIVATE_RECEIPT.json", file=sys.stderr)
        return 2
    try:
        receipt = json.loads(Path(args[0]).read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "receipt_unreadable", "detail": str(error)}))
        return 1
    summary = decode_test136_receipt(receipt)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0 if summary.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
