#!/usr/bin/env python3
"""Bounded, passive Test100 rekey / link-loss evidence collector.

This private preparation tool retains only a fixed IORegistry allowlist,
numeric completion fields, and boolean en1 readiness. Binary diagnostic
snapshots are copied only when their digest changes. It never stores the full
IORegistry tree, interface addresses, SSID/BSSID, key bytes, or packet data.

The collector is event anchored: a new Group1/key event or a link/reset/error
transition starts a 30-second tail and extends that tail if further relevant
events arrive. If no event is observed, it exits at --duration with
duration_elapsed_no_anchor; that is not a stability pass.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import sys
import time
from typing import Callable, Dict, Optional, Tuple


CANDIDATE_BUILD = "25G332-Test100"
EXPECTED_OS_BUILD = "25G332"
BUNDLE_ID = "org.geekaudio.AirportItlwm"
EXPECTED_KEXT_UUID = None  # Required CLI value from the reviewed build receipt.
INTERFACE = "en1"
TAIL_SECONDS = 30.0
MAX_CONSECUTIVE_READ_ERRORS = 3
MAX_DURATION_SECONDS = 6 * 60 * 60

AUTH_PROPERTY = "NativeGroupKeyForensicSnapshot"
GROUP2_PROPERTY = "NativeGroup2TxTrace"
LINK_PROPERTY = "NativeWifiLinkTransitionTrace"
BINARY_PROPERTIES = (AUTH_PROPERTY, GROUP2_PROPERTY, LINK_PROPERTY)

# Fixed, reviewed numeric allowlist. Deliberately omit all firmware register
# dumps and every nonnumeric/identity-bearing property.
POWER_COUNTERS = frozenset({
    "NativePowerGetCount", "NativePowerHALFlags", "NativePowerReady",
    "NativePowerReadyCount", "NativePowerResetCount", "NativePowerSetCount",
    "NativePowerStoppedCount", "NativePowerTraceSequence",
})
RESET_COUNTERS = frozenset({
    "NativeResetTraceSequence", "NativeResetTraceLastInitTaskTriggerSequence",
    "NativeResetTraceTxWatchdogSequence", "NativeResetTraceTxWatchdogArmSequence",
    "NativeResetTraceTxWatchdogClearSequence",
    "NativeResetTraceReasonCountAdapterDisableQuiesce",
    "NativeResetTraceReasonCountIfFlagsDown",
    "NativeResetTraceReasonCountInitHardwareFailureCleanup",
    "NativeResetTraceReasonCountInitTaskNotRunningRecovery",
    "NativeResetTraceReasonCountInitTaskRunningRecovery",
    "NativeResetTraceReasonCountInitialScanFailureCleanup",
    "NativeResetTraceReasonCountInitialScanWaitInterrupted",
    "NativeResetTraceReasonCountIoctlEnetReset",
    "NativeResetTraceReasonCountMediaChange",
    "NativeResetTraceReasonCountUnknown",
    "NativeResetTraceTriggerCountCriticalTemperature",
    "NativeResetTraceTriggerCountLegacyFirmwareSwError",
    "NativeResetTraceTriggerCountLegacyHardwareError",
    "NativeResetTraceTriggerCountLegacyRfKill",
    "NativeResetTraceTriggerCountLifecycleFenceRetry",
    "NativeResetTraceTriggerCountMsixFirmwareSwError",
    "NativeResetTraceTriggerCountMsixHardwareError",
    "NativeResetTraceTriggerCountMsixRfKill",
    "NativeResetTraceTriggerCountNewStateError",
    "NativeResetTraceTriggerCountTxWatchdogTimeout",
    "NativeResetTraceTriggerCountUnknown",
    "NativeResetTraceTriggerCountWakeupDeferred",
})
FW_ERROR_SUMMARY = frozenset({
    "NativeFwErrorSnapshotSchema", "NativeFwErrorSnapshotSnapshotComplete",
    "NativeFwErrorSnapshotCaptureSerial", "NativeFwErrorSnapshotCaptureStatus",
    "NativeFwErrorSnapshotDriverGeneration",
    "NativeFwErrorSnapshotFirmwareGeneration",
    "NativeFwErrorSnapshotResetReason", "NativeFwErrorSnapshotResetSequence",
    "NativeFwErrorSnapshotWatchdogSequence",
    "NativeFwErrorSnapshotWatchdogSequencePresent",
    "NativeFwErrorSnapshotPublishRevisionBegin",
    "NativeFwErrorSnapshotPublishRevisionEnd",
    "NativeFwErrorSnapshotReadBudgetNs", "NativeFwErrorSnapshotReadElapsedNs",
    "NativeFwErrorSnapshotReadWordCount",
})
NUMERIC_ALLOWLIST = POWER_COUNTERS | RESET_COUNTERS | FW_ERROR_SUMMARY

AUTH_HEADER = struct.Struct("<I4H11I")
AUTH_EVENT = struct.Struct("<7I4Hi2I")
AUTH_MAGIC = 0x41535449
AUTH_SIZE = AUTH_HEADER.size + (16 + 8) * AUTH_EVENT.size
GROUP2_HEADER = struct.Struct("<I4H4xQQIIQQQI4x")
GROUP2_EVENT = struct.Struct("<QQQQ12IiIHH4x")
GROUP2_MAGIC = 0x47545849
GROUP2_CAPACITY = 32
GROUP2_SIZE = GROUP2_HEADER.size + GROUP2_CAPACITY * GROUP2_EVENT.size
LINK_HEADER = struct.Struct("<6IQ")
LINK_EVENT = struct.Struct("<QQ11I4x")
LINK_SIZE = LINK_HEADER.size + 8 * LINK_EVENT.size
EXPECTED_BINARY_LENGTHS = {
    AUTH_PROPERTY: AUTH_SIZE,
    GROUP2_PROPERTY: GROUP2_SIZE,
    LINK_PROPERTY: LINK_SIZE,
}
UUID_PATTERN = re.compile(
    r"\b([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})\b")


class CollectorError(Exception):
    """A bounded, sanitized collection failure."""


class IdentityMismatch(CollectorError):
    def __init__(self, field: str, expected: object, observed: object):
        super().__init__(field)
        self.field = field
        self.expected = expected
        self.observed = observed


def _run_bytes(argv, timeout: float = 8.0) -> bytes:
    return subprocess.check_output(argv, timeout=timeout, stderr=subprocess.DEVNULL)


def extract_bundle_uuid(loaded_output: str, bundle_id: str = BUNDLE_ID) -> str:
    """Require exactly one UUID on the exact target-bundle output line."""
    bundle_token = re.compile(
        r"(?<![A-Za-z0-9_.-])" + re.escape(bundle_id) +
        r"(?![A-Za-z0-9_.-])")
    rows = [line for line in loaded_output.splitlines()
            if bundle_token.search(line)]
    if len(rows) != 1:
        raise CollectorError("target_bundle_line_not_unique")
    uuids = UUID_PATTERN.findall(rows[0])
    if len(uuids) != 1:
        raise CollectorError("target_bundle_uuid_not_unique")
    return uuids[0].upper()


def read_boot_epoch() -> int:
    raw = _run_bytes(["/usr/sbin/sysctl", "-n", "kern.boottime"]).decode(
        "ascii", "replace")
    match = re.search(r"\bsec\s*=\s*(\d+)", raw)
    if not match:
        raise CollectorError("boot_epoch_unavailable")
    return int(match.group(1))


def read_host_identity(expected_boot: int, expected_build: str) -> dict:
    observed_boot = read_boot_epoch()
    if observed_boot != expected_boot:
        raise IdentityMismatch("boot_epoch", expected_boot, observed_boot)
    os_build = _run_bytes(["/usr/bin/sw_vers", "-buildVersion"]).decode(
        "ascii", "replace").strip()
    if os_build != EXPECTED_OS_BUILD:
        raise IdentityMismatch("os_build", EXPECTED_OS_BUILD, os_build)
    loaded = _run_bytes([
        "/usr/bin/kmutil", "showloaded", "--list-only",
        "--bundle-identifier", BUNDLE_ID,
    ], timeout=30.0).decode("ascii", "replace")
    uuid = extract_bundle_uuid(loaded)
    if uuid != EXPECTED_KEXT_UUID:
        raise IdentityMismatch("loaded_kext_uuid", EXPECTED_KEXT_UUID, uuid)
    return {
        "boot_epoch": observed_boot,
        "os_build": os_build,
        "candidate_build_expected": expected_build,
        "loaded_kext_uuid": uuid,
    }


def one_driver_service(raw_plist: bytes) -> dict:
    tree = plistlib.loads(raw_plist)
    if (not isinstance(tree, list) or len(tree) != 1 or
            not isinstance(tree[0], dict)):
        raise CollectorError("unexpected_ioreg_service_shape")
    return tree[0]


def parse_auth_snapshot(raw: bytes) -> dict:
    if len(raw) != AUTH_SIZE:
        raise ValueError("unexpected_auth_snapshot_length")
    values = AUTH_HEADER.unpack_from(raw)
    (magic, schema, header_bytes, event_bytes, capacity, revision_begin,
     revision_end, flags, live_count, dropped_count, diagnostic_instance,
     driver_generation, association_id, next_attempt_id, first_state,
     first_count) = values
    if (magic != AUTH_MAGIC or schema != 1 or header_bytes != AUTH_HEADER.size or
            event_bytes != AUTH_EVENT.size or capacity != 16 or
            live_count > 16 or first_count > 8 or first_state > 3):
        raise ValueError("unsupported_auth_snapshot_layout")
    if revision_begin != revision_end or revision_begin & 1:
        raise ValueError("unstable_auth_snapshot_revision")
    if (flags & ~1 or (first_state == 2 and first_count == 0) or
            (first_state != 2 and first_count != 0) or
            bool(flags & 1) != (first_state == 3)):
        raise ValueError("inconsistent_auth_snapshot_state")
    events = []
    for i in range(live_count):
        event = AUTH_EVENT.unpack_from(raw, AUTH_HEADER.size + i * AUTH_EVENT.size)
        if event[0] != 0:
            if event[7] not in range(1, 16):
                raise ValueError("unknown_auth_event_kind")
            events.append({"sequence": event[0], "kind": event[7],
                           "stage": event[8], "component": event[9],
                           "source": event[10]})
    if any(raw[AUTH_HEADER.size + live_count * AUTH_EVENT.size:
              AUTH_HEADER.size + 16 * AUTH_EVENT.size]):
        raise ValueError("nonzero_unused_live_records")
    first_offset = AUTH_HEADER.size + 16 * AUTH_EVENT.size
    for i in range(first_count):
        event = AUTH_EVENT.unpack_from(raw, first_offset + i * AUTH_EVENT.size)
        if event[0] != 0:
            if event[7] not in range(1, 16):
                raise ValueError("unknown_auth_event_kind")
            events.append({"sequence": event[0], "kind": event[7],
                           "stage": event[8], "component": event[9],
                           "source": event[10]})
    if any(raw[first_offset + first_count * AUTH_EVENT.size:]):
        raise ValueError("nonzero_unused_first_records")
    events.sort(key=lambda item: item["sequence"])
    return {
        "snapshot_status": "stable",
        "schema": schema,
        "sequence": max((item["sequence"] for item in events), default=None),
        "revision_begin": revision_begin,
        "revision_end": revision_end,
        "dropped_count": dropped_count,
        "live_count": live_count,
        "diagnostic_instance": diagnostic_instance,
        "driver_generation": driver_generation,
        "association_id": association_id,
        "first_state": first_state,
        "first_count": first_count,
        "events": events,
    }


def parse_group2_snapshot(raw: bytes) -> dict:
    if len(raw) != GROUP2_SIZE:
        raise ValueError("unexpected_group2_snapshot_length")
    values = GROUP2_HEADER.unpack_from(raw)
    (magic, schema, header_bytes, event_bytes, capacity, revision_begin,
     revision_end, dropped_count, event_count, next_cookie,
     next_event_sequence, next_slot_generation, flags) = values
    if (magic != GROUP2_MAGIC or schema != 1 or
            header_bytes != GROUP2_HEADER.size or event_bytes != GROUP2_EVENT.size or
            capacity != GROUP2_CAPACITY or event_count > GROUP2_CAPACITY):
        raise ValueError("unsupported_group2_snapshot_layout")
    if revision_begin != revision_end or revision_begin & 1:
        raise ValueError("unstable_group2_snapshot_revision")
    if flags & ~3:
        raise ValueError("unknown_group2_snapshot_flags")
    events = []
    for index in range(event_count):
        event = GROUP2_EVENT.unpack_from(
            raw, GROUP2_HEADER.size + index * GROUP2_EVENT.size)
        if event[0] == 0 or event[18] not in range(1, 20):
            raise ValueError("invalid_group2_event")
        events.append(event[0])
    if any(a >= b for a, b in zip(events, events[1:])):
        raise ValueError("unordered_group2_events")
    if any(raw[GROUP2_HEADER.size + event_count * GROUP2_EVENT.size:]):
        raise ValueError("nonzero_unused_group2_events")
    return {
        "snapshot_status": "stable",
        "sequence": next_event_sequence,
        "revision_begin": revision_begin,
        "revision_end": revision_end,
        "dropped_count": dropped_count,
        "event_count": event_count,
        "next_cookie": next_cookie,
        "next_slot_generation": next_slot_generation,
        "flags": flags,
    }


def parse_link_snapshot(raw: bytes) -> dict:
    if len(raw) != LINK_SIZE:
        raise ValueError("unexpected_link_snapshot_length")
    values = LINK_HEADER.unpack_from(raw)
    schema, capacity, version_begin, version_end, dropped_count, count, next_sequence = values
    if schema != 2 or capacity != 8 or count > 8:
        raise ValueError("unsupported_link_snapshot_layout")
    if version_begin != version_end or version_begin & 1:
        raise ValueError("unstable_link_snapshot_revision")
    events = []
    for i in range(count):
        record = LINK_EVENT.unpack_from(raw, LINK_HEADER.size + i * LINK_EVENT.size)
        if record[0] != 0:
            if record[2] not in range(1, 8) or record[12] & ~0x7F:
                raise ValueError("invalid_link_event")
            events.append({"sequence": record[0], "event_code": record[2]})
    if any(a["sequence"] >= b["sequence"] for a, b in zip(events, events[1:])):
        raise ValueError("unordered_link_events")
    if any(raw[LINK_HEADER.size + count * LINK_EVENT.size:]):
        raise ValueError("nonzero_unused_link_events")
    return {
        "snapshot_status": "stable",
        "sequence": next_sequence,
        "revision_begin": version_begin,
        "revision_end": version_end,
        "dropped_count": dropped_count,
        "count": count,
        "events": events,
    }


SNAPSHOT_PARSERS = {
    AUTH_PROPERTY: parse_auth_snapshot,
    GROUP2_PROPERTY: parse_group2_snapshot,
    LINK_PROPERTY: parse_link_snapshot,
}


def sanitized_link_state(raw: bytes) -> dict:
    text = raw.decode("ascii", "replace")
    lines = text.splitlines()
    first = lines[0] if lines else ""
    match = re.search(r"flags=\d+<([^>]*)>", first)
    flags = set(match.group(1).split(",")) if match else set()
    status_match = re.search(r"^\s*status:\s*(\w+)\s*$", text, re.M)
    return {
        "present": bool(first),
        "up": "UP" in flags,
        "running": "RUNNING" in flags,
        "link_active": bool(status_match and status_match.group(1).lower() == "active"),
        "ipv4_present": bool(re.search(r"^\s*inet\s+[0-9]", text, re.M)),
        "ipv6_present": bool(re.search(r"^\s*inet6\s+[0-9a-fA-F:]", text, re.M)),
    }


def select_allowlisted(service: dict, expected_build: str) -> dict:
    observed_build = service.get("NativeTestBuild")
    if observed_build != expected_build:
        raise IdentityMismatch("candidate_build", expected_build, observed_build)

    counters = {}
    for key in NUMERIC_ALLOWLIST:
        value = service.get(key)
        if type(value) is int:
            counters[key] = value

    completion = {}
    live_counters = {}
    for key, value in service.items():
        if (isinstance(key, str) and key.startswith("NativeStaCompletion") and
                type(value) is int):
            if key.startswith("NativeStaCompletionLive"):
                live_counters[key] = value
            else:
                completion[key] = value

    host_origin = parse_completion_host_origin(completion)

    binaries = {}
    for name in BINARY_PROPERTIES:
        value = service.get(name)
        if isinstance(value, bytes):
            digest = hashlib.sha256(value).hexdigest()
            parser = SNAPSHOT_PARSERS[name]
            try:
                parsed = parser(value)
            except (ValueError, struct.error) as error:
                parsed = {"snapshot_status": "unparsed",
                          "parse_error": str(error)}
            binaries[name] = {
                "present": True,
                "length": len(value),
                "sha256": digest,
                "sequence": parsed.get("sequence"),
                "parsed": parsed,
                "raw_bytes": value,
                "retain_bytes_allowed": len(value) == EXPECTED_BINARY_LENGTHS[name],
            }
        else:
            binaries[name] = {"present": False}

    return {
        "candidate_build": observed_build,
        "numeric_counters": counters,
        "completion_scalars": completion,
        "completion_live_counters": live_counters,
        "completion_host_origin": host_origin,
        "binary_snapshots": binaries,
    }


def parse_completion_host_origin(scalars: dict) -> dict:
    """Decode stable schema-4/schema-5 TX_RSP host-origin witnesses.

    The structured result is deliberately distinct from firmware response
    identity, peer acknowledgement, and AirDrop receipt. An UNBOUND sidecar
    carries host metadata from the interval but has no matching raw command
    header and must never be treated as a same-attempt join. Schema 4 keeps
    its historical interpretation. Schema 5 additionally validates the
    published presence mask and the raw host-origin/command-header tuple.
    """
    def get(suffix: str):
        return scalars.get("NativeStaCompletion" + suffix)

    presence_bits = {
        "firmware_qid": 1 << 7,
        "queue_index": 1 << 8,
        "ring_count": 1 << 9,
        "queued": 1 << 10,
        "tail": 1 << 12,
        "output_epoch": 1 << 25,
        "response_frame_control": 1 << 26,
        "response_sequence_control": 1 << 27,
        "tx_command_scan": 1 << 28,
        "tx_command_unique_candidate": 1 << 29,
        "single_slot_tx_command_header": 1 << 30,
    }

    schema = get("Schema")
    if type(schema) is not int or schema not in (4, 5):
        return {"status": "schema_unavailable", "schema": schema}
    begin = get("SnapshotVersionBegin")
    end = get("SnapshotVersionEnd")
    if (type(begin) is not int or type(end) is not int or begin != end or
            begin & 1):
        return {"status": "snapshot_unstable", "schema": schema}
    if get("SnapshotComplete") != 1:
        return {"status": "snapshot_incomplete", "schema": schema,
                "snapshot_version": begin}
    if get("Event0Present") != 1 or get("Event0Kind") != 0:
        return {"status": "tx_response_not_present", "schema": schema,
                "snapshot_version": begin}

    raw_witness = None
    if schema == 5:
        raw_witness = {
            "host_origin_state": get("Event0HostOriginState"),
            "host_origin_cookie": get("Event0HostOriginCookie"),
            "host_origin_slot_generation": get("Event0HostOriginSlotGeneration"),
            "host_origin_context_generation": get("Event0HostOriginContextGeneration"),
            "host_origin_output_epoch": get("Event0HostOriginOutputEpoch"),
            "host_origin_identity_epoch": get("Event0HostOriginIdentityEpoch"),
            "host_origin_attempt_id": get("Event0HostOriginAttemptId"),
            "host_origin_source": get("Event0HostOriginSource"),
            "host_origin_index": get("Event0HostOriginIndex"),
            "presence_flags": get("Event0PresenceFlags"),
            "host_origin_frame_control": get("Event0HostOriginFrameControl"),
            "host_origin_sequence_control": get("Event0HostOriginSequenceControl"),
            "host_origin_tid": get("Event0HostOriginTid"),
            "event_output_epoch": get("Event0OutputEpoch"),
            "firmware_qid": get("Event0FirmwareQid"),
            "queue_index": get("Event0QueueIndex"),
            "ring_count": get("Event0RingCount"),
            "queued": get("Event0Queued"),
            "tail": get("Event0Tail"),
            "single_slot_tx_command_header": get("Event0SingleSlotTxCommandHeader"),
            "tx_command_candidate_index": get("Event0TxCommandCandidateIndex"),
            "tx_command_candidate_count": get("Event0TxCommandCandidateCount"),
            "tx_command_api_generation": get("Event0TxCommandApiGeneration"),
            "tx_command_version": get("Event0TxCommandVersion"),
            "tx_command_scan_status": get("Event0TxCommandScanStatus"),
            "tx_command_expected_count": get("Event0TxCommandExpectedCount"),
            "tx_command_scanned_count": get("Event0TxCommandScannedCount"),
            "response_frame_control": get("Event0ResponseFrameControl"),
            "response_sequence_control": get("Event0ResponseSequenceControl"),
        }

    state = get("Event0HostOriginState")
    state_names = {
        0: "unavailable",
        1: "none",
        2: "unique_host_slot",
        3: "multiple",
        4: "stale_or_reset_ambiguous",
        5: "interval_sidecar_unbound_from_command_header",
    }
    if type(state) is not int or state not in state_names:
        result = {"status": "invalid_host_origin_state", "schema": schema,
                  "snapshot_version": begin}
        if raw_witness is not None:
            result["raw_witness"] = raw_witness
        return result

    def invalid_schema5(status: str, parsed_result=None) -> dict:
        result = dict(parsed_result or {})
        result.update({"status": status, "schema": schema,
                       "snapshot_version": begin})
        if parsed_result is None:
            result["same_slot_descriptor"] = False
        if raw_witness is not None:
            result.setdefault("raw_witness", raw_witness)
        return result

    presence_value = get("Event0PresenceFlags")
    if schema == 5:
        response_candidate_flag = (type(presence_value) is int and
                                   bool(presence_value & (1 << 29)))
    else:
        response_candidate_flag = bool((presence_value or 0) & (1 << 29))
    result = {"status": state_names[state], "schema": schema,
              "snapshot_version": begin,
              "event_serial": get("Event0Serial"),
              "same_slot_descriptor": state == 2,
              "exact_response_tuple_match": response_candidate_flag}
    if raw_witness is not None:
        result["raw_witness"] = raw_witness
    payload_fields = {
        "cookie": "Event0HostOriginCookie",
        "slot_generation": "Event0HostOriginSlotGeneration",
        "context_generation": "Event0HostOriginContextGeneration",
        "output_epoch": "Event0HostOriginOutputEpoch",
        "identity_epoch": "Event0HostOriginIdentityEpoch",
        "attempt_id": "Event0HostOriginAttemptId",
        "source": "Event0HostOriginSource",
        "index": "Event0HostOriginIndex",
        "frame_control": "Event0HostOriginFrameControl",
        "sequence_control": "Event0HostOriginSequenceControl",
        "tid": "Event0HostOriginTid",
    }
    values = {name: get(suffix) for name, suffix in payload_fields.items()}
    if state in (2, 5):
        if any(type(value) is not int for value in values.values()):
            if schema == 5:
                return invalid_schema5("invalid_host_origin_payload")
            return {"status": "invalid_host_origin_payload", "schema": schema,
                    "snapshot_version": begin}
        qid = get("Event0FirmwareQid")
        boundary = get("Event0QueueIndex")
        ring_count = get("Event0RingCount")
        tail = get("Event0Tail")
        queued = get("Event0Queued")
        required_range = (qid, boundary, ring_count, tail, queued)
        if any(type(value) is not int for value in required_range):
            if schema == 5:
                return invalid_schema5("invalid_host_origin_range")
            return {"status": "invalid_host_origin_range", "schema": schema,
                    "snapshot_version": begin}
        if (values["cookie"] == 0 or values["slot_generation"] == 0 or
                values["attempt_id"] == 0 or values["source"] not in (1, 2) or
                ring_count <= 0 or boundary < 0 or boundary >= ring_count or
                tail < 0 or tail >= ring_count or queued < 0 or
                queued > ring_count or values["index"] < 0 or
                values["index"] >= ring_count or
                values["frame_control"] < 0 or
                values["frame_control"] > 0xffff or
                values["sequence_control"] < 0 or
                values["sequence_control"] > 0xffff or
                values["tid"] < 0 or values["tid"] > 15):
            if schema == 5:
                return invalid_schema5("invalid_host_origin_payload")
            return {"status": "invalid_host_origin_payload", "schema": schema,
                    "snapshot_version": begin}
        distance = (boundary + ring_count - tail) % ring_count
        origin_offset = (values["index"] + ring_count - tail) % ring_count
        if distance == 0 or distance > queued or origin_offset >= distance:
            if schema == 5:
                return invalid_schema5("invalid_host_origin_range")
            return {"status": "invalid_host_origin_range", "schema": schema,
                    "snapshot_version": begin}
        if state == 2:
            presence = get("Event0PresenceFlags")
            raw_candidate = get("Event0TxCommandCandidateIndex")
            preceding_index = boundary - 1 if boundary else ring_count - 1
            if schema == 5:
                # Schema 5's publisher derives this packed header from the
                # same unique scanner candidate used to identify the host
                # origin. Require every producer presence bit; scalar zeros
                # alone are not evidence that a field was captured.
                required_presence = (
                    presence_bits["firmware_qid"] |
                    presence_bits["queue_index"] |
                    presence_bits["ring_count"] |
                    presence_bits["queued"] |
                    presence_bits["tail"] |
                    presence_bits["output_epoch"] |
                    presence_bits["tx_command_scan"] |
                    presence_bits["single_slot_tx_command_header"])
                scan_values = (
                    get("Event0TxCommandScanStatus"),
                    get("Event0TxCommandExpectedCount"),
                    get("Event0TxCommandScannedCount"),
                    get("Event0TxCommandCandidateCount"),
                    get("Event0TxCommandApiGeneration"),
                    get("Event0TxCommandVersion"),
                    raw_candidate,
                    get("Event0SingleSlotTxCommandHeader"),
                )
                if (type(presence) is not int or presence < 0 or
                        presence > 0xffffffff or
                        (presence & required_presence) != required_presence or
                        any(type(value) is not int for value in scan_values) or
                        qid < 0 or qid > 0xffff):
                    return invalid_schema5("invalid_host_origin_presence")
                if (get("Event0TxCommandApiGeneration") not in (2, 3) or
                        get("Event0TxCommandVersion") < 0 or
                        get("Event0TxCommandVersion") > 0xff or
                        get("Event0TxCommandCandidateCount") < 0 or
                        get("Event0TxCommandCandidateCount") > 1 or
                        ((get("Event0TxCommandCandidateCount") == 1) !=
                         bool(presence & presence_bits[
                             "tx_command_unique_candidate"]))):
                    return invalid_schema5("invalid_host_origin_scan")
            if (type(presence) is not int or not (presence & (1 << 30)) or
                    get("Event0TxCommandScanStatus") != 1 or
                    get("Event0TxCommandExpectedCount") != 1 or
                    get("Event0TxCommandScannedCount") != 1 or
                    distance != 1 or origin_offset != 0 or
                    raw_candidate != preceding_index or
                    raw_candidate != values["index"]):
                if schema == 5:
                    return invalid_schema5("invalid_host_origin_binding")
                return {"status": "invalid_host_origin_binding", "schema": schema,
                        "snapshot_version": begin}
            if schema == 5:
                packed_origin = ((values["frame_control"] << 16) |
                                 values["sequence_control"])
                raw_header = get("Event0SingleSlotTxCommandHeader")
                if raw_header != packed_origin:
                    return invalid_schema5(
                        "invalid_host_origin_header_conflict")
        result["host_origin"] = values
        result["host_origin_queue_id"] = qid
        result["command_header_index"] = get("Event0TxCommandCandidateIndex")
    else:
        if any(get(suffix) != 0 for suffix in payload_fields.values()):
            if schema == 5:
                return invalid_schema5("invalid_nonunique_payload")
            return {"status": "invalid_nonunique_payload", "schema": schema,
                    "snapshot_version": begin}
    if schema == 5:
        presence = get("Event0PresenceFlags")
        if state in (2, 5):
            required_origin_presence = (
                presence_bits["firmware_qid"] |
                presence_bits["queue_index"] |
                presence_bits["ring_count"] |
                presence_bits["queued"] |
                presence_bits["tail"] |
                presence_bits["output_epoch"])
            if (type(presence) is not int or presence < 0 or
                    presence > 0xffffffff or
                    (presence & required_origin_presence) !=
                    required_origin_presence):
                return invalid_schema5("invalid_host_origin_presence")
            event_output_epoch = get("Event0OutputEpoch")
            u32_origin_fields = (
                values["context_generation"], values["output_epoch"],
                values["identity_epoch"], values["attempt_id"], qid,
                boundary, ring_count, tail, queued)
            if (type(event_output_epoch) is not int or
                    not 0 <= event_output_epoch <= 0xffffffff or
                    any(not 0 <= value <= 0xffffffff
                        for value in u32_origin_fields) or
                    not 0 < values["cookie"] <= 0xffffffffffffffff or
                    not 0 < values["slot_generation"] <= 0xffffffffffffffff or
                    values["index"] > 0xffff or
                    values["output_epoch"] != event_output_epoch):
                return invalid_schema5("invalid_host_origin_epoch")
        exact_candidate = (type(presence) is int and
                           bool(presence & presence_bits[
                               "tx_command_unique_candidate"]))
        result["response_tuple_status"] = "not_marked_unique_candidate"
        result["response_tuple_matches_single_slot_header"] = None
        if (type(presence) is int and
                presence & (presence_bits["response_frame_control"] |
                            presence_bits["response_sequence_control"]) ==
                (presence_bits["response_frame_control"] |
                 presence_bits["response_sequence_control"])):
            response_fc = get("Event0ResponseFrameControl")
            response_sc = get("Event0ResponseSequenceControl")
            if (type(response_fc) is int and type(response_sc) is int and
                    0 <= response_fc <= 0xffff and
                    0 <= response_sc <= 0xffff):
                response_packed = (response_fc << 16) | response_sc
                raw_header = get("Event0SingleSlotTxCommandHeader")
                result["response_tuple_matches_single_slot_header"] = (
                    type(raw_header) is int and response_packed == raw_header)
                if exact_candidate:
                    if not (presence & presence_bits[
                            "single_slot_tx_command_header"]):
                        result["exact_response_tuple_match"] = False
                        return invalid_schema5(
                            "invalid_response_tuple_presence", result)
                    if not result["response_tuple_matches_single_slot_header"]:
                        result["exact_response_tuple_match"] = False
                        return invalid_schema5(
                            "invalid_response_tuple_binding", result)
                    result["response_tuple_status"] = "exact_candidate_header_match"
                else:
                    result["response_tuple_status"] = "raw_tuple_unmarked"
            elif exact_candidate:
                result["exact_response_tuple_match"] = False
                return invalid_schema5("invalid_response_tuple_presence", result)
        elif exact_candidate:
            result["exact_response_tuple_match"] = False
            return invalid_schema5("invalid_response_tuple_presence", result)
        result["exact_response_tuple_match"] = (
            exact_candidate and
            result["response_tuple_status"] == "exact_candidate_header_match")
    return result


def sample_once(expected_build: str, identity: dict) -> dict:
    raw = _run_bytes(["/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"])
    service = one_driver_service(raw)
    filtered = select_allowlisted(service, expected_build)
    link = None
    link_error = None
    try:
        link = sanitized_link_state(_run_bytes(["/sbin/ifconfig", INTERFACE], timeout=5.0))
    except Exception as error:
        link_error = type(error).__name__

    return {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "epoch_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        **identity,
        "candidate_build": filtered["candidate_build"],
        "numeric_counters": filtered["numeric_counters"],
        "completion_scalars": filtered["completion_scalars"],
        "completion_live_counters": filtered["completion_live_counters"],
        "completion_host_origin": filtered["completion_host_origin"],
        "binary_snapshots": filtered["binary_snapshots"],
        "en1": link,
        "en1_read_error": link_error,
    }


def _append_jsonl(stream, row: dict) -> None:
    stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":")) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def materialize_sample(point: dict, previous_digests: dict,
                       sample_index: int) -> Tuple[dict, dict]:
    next_digests = dict(previous_digests)
    snapshot_state = {}
    changed = {}
    current = point.get("binary_snapshots", {})
    for name in BINARY_PROPERTIES:
        value = current.get(name, {"present": False})
        if not value.get("present"):
            snapshot_state[name] = {"present": False}
            if name in next_digests:
                next_digests.pop(name, None)
            continue

        raw = value["raw_bytes"]
        item = {key: value[key] for key in ("present", "length", "sha256", "sequence", "parsed")}
        snapshot_state[name] = item
        digest = value["sha256"]
        if previous_digests.get(name) != digest:
            change = {
                "length": len(raw),
                "sha256": digest,
                "sequence": value.get("sequence"),
                "snapshot_status": value.get("parsed", {}).get("snapshot_status"),
                "sample_index": sample_index,
            }
            if value.get("retain_bytes_allowed"):
                change["base64"] = base64.b64encode(raw).decode("ascii")
                change["bytes_retained"] = True
            else:
                change["bytes_retained"] = False
                change["retention_reason"] = "unexpected_length_fail_closed"
            changed[name] = change
            next_digests[name] = digest

    row = {
        key: value for key, value in point.items()
        if key not in ("binary_snapshots",)
    }
    row["snapshot_state"] = snapshot_state
    row["changed_snapshots"] = changed
    return row, next_digests


def _new_sequences(parsed: dict, seen: set, identity_key: str) -> list:
    found = []
    if not isinstance(parsed, dict):
        return found
    for event in parsed.get("events", []):
        sequence = event.get("sequence")
        if sequence is None:
            continue
        key = (identity_key, sequence)
        if key not in seen:
            seen.add(key)
            found.append(event)
    return found


def trigger_reasons(point: dict, previous: Optional[dict], state: dict) -> list:
    """Return newly observed key/link/reset events using only numeric metadata."""
    reasons = []
    snapshots = point.get("binary_snapshots", {})

    auth_value = snapshots.get(AUTH_PROPERTY, {})
    auth = auth_value.get("parsed", {})
    auth_id = str(auth.get("diagnostic_instance", "unknown"))
    if previous is None:
        # The first sample is the baseline. Existing retained records in it
        # belong to pre-capture history and must not be mislabeled as new.
        _new_sequences(auth, state["seen_auth"], auth_id)
        link_value = snapshots.get(LINK_PROPERTY, {})
        _new_sequences(link_value.get("parsed", {}), state["seen_link"], "link")
    else:
        new_auth = _new_sequences(auth, state["seen_auth"], auth_id)
        if any(event.get("kind") == 1 for event in new_auth):
            reasons.append("new_group1_key_update_anchor")
        if any(event.get("kind") in (2, 3, 4, 5) for event in new_auth):
            reasons.append("new_key_handshake_progress")
        if any(event.get("kind") in (6, 7, 8, 9, 11, 12, 13) for event in new_auth):
            reasons.append("new_auth_or_association_failure_event")

        link_value = snapshots.get(LINK_PROPERTY, {})
        link = link_value.get("parsed", {})
        link_events = _new_sequences(link, state["seen_link"], "link")
        if any(event.get("event_code") in (3, 5, 6, 7) for event in link_events):
            reasons.append("new_link_deauth_or_reset_event")

        old_snapshots = previous.get("binary_snapshots", {})
        for name in BINARY_PROPERTIES:
            old_parsed = old_snapshots.get(name, {}).get("parsed", {})
            new_parsed = snapshots.get(name, {}).get("parsed", {})
            old_dropped = old_parsed.get("dropped_count")
            new_dropped = new_parsed.get("dropped_count")
            if (type(old_dropped) is int and type(new_dropped) is int and
                    new_dropped > old_dropped):
                reasons.append("trace_drop_count_increased:" + name)

        before = previous.get("numeric_counters", {})
        after = point.get("numeric_counters", {})
        for key in sorted(RESET_COUNTERS):
            old, new = before.get(key), after.get(key)
            if type(old) is int and type(new) is int and new > old:
                reasons.append("counter_increased:" + key)
        old_fw, new_fw = before.get("NativeFwErrorSnapshotCaptureSerial"), after.get("NativeFwErrorSnapshotCaptureSerial")
        if type(old_fw) is int and type(new_fw) is int and new_fw > old_fw:
            reasons.append("firmware_error_snapshot_serial_increased")

        old_link = previous.get("en1") or {}
        new_link = point.get("en1") or {}
        required = ("present", "up", "running", "link_active", "ipv4_present")
        if all(old_link.get(key) is True for key in required) and any(
                new_link.get(key) is not True for key in required):
            reasons.append("en1_readiness_lost")

        live_before = previous.get("completion_live_counters", {})
        live_after = point.get("completion_live_counters", {})
        if any(type(live_before.get(key)) is int and type(value) is int and
               value > live_before[key] for key, value in live_after.items()):
            reasons.append("live_completion_counter_increased")

        group2_now = snapshots.get(GROUP2_PROPERTY, {}).get("parsed", {}).get("sequence")
        group2_before = previous.get("binary_snapshots", {}).get(GROUP2_PROPERTY, {}).get("parsed", {}).get("sequence")
        if state["gtk_anchor_seen"] and type(group2_now) is int and type(group2_before) is int and group2_now > group2_before:
            reasons.append("group2_tx_trace_advanced_after_group1")

    if "new_group1_key_update_anchor" in reasons:
        state["gtk_anchor_seen"] = True
    return reasons


def _sanitized_error(error: BaseException) -> dict:
    if isinstance(error, IdentityMismatch):
        return {"class": "IdentityMismatch", "field": error.field,
                "expected": error.expected, "observed": error.observed}
    # Do not serialize arbitrary command output or exception text.
    return {"class": type(error).__name__}


def capture(output: Path, expected_boot: int, expected_build: str,
            duration: float, interval: float = 1.0,
            sample_fn: Callable[[str, dict], dict] = sample_once,
            identity_fn: Callable[[int, str], dict] = read_host_identity,
            monotonic_fn: Callable[[], float] = time.monotonic,
            sleep_fn: Callable[[float], None] = time.sleep) -> dict:
    if duration <= 0 or duration > MAX_DURATION_SECONDS or interval <= 0 or interval > 10:
        raise ValueError("duration must be (0, 21600] and interval (0, 10]")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
        os.close(fd)
        raise CollectorError("output_permissions_not_private")

    start = monotonic_fn()
    sample_count = 0
    error_count = 0
    consecutive_errors = 0
    last_point = None
    previous_digests = {}
    event_state = {"seen_auth": set(), "seen_link": set(), "gtk_anchor_seen": False}
    tail_until = None
    trigger_log = []
    sample_attempt_count = 0
    next_sample_due = start
    terminal_status = "duration_elapsed_no_anchor"

    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        try:
            try:
                identity = identity_fn(expected_boot, expected_build)
                identity_error = None
            except Exception as error:
                identity = {"boot_epoch": expected_boot,
                            "candidate_build_expected": expected_build}
                identity_error = _sanitized_error(error)
            header = {
                "record_type": "header",
                "schema": "test100-rekey-passive-capture/v1",
                "created_at": datetime.datetime.now().astimezone().isoformat(),
                "expected_boot_epoch": expected_boot,
                "expected_candidate_build": expected_build,
                "expected_os_build": EXPECTED_OS_BUILD,
                "expected_loaded_kext_uuid": EXPECTED_KEXT_UUID,
                "identity": identity,
                "identity_error": identity_error,
                "duration_seconds": duration,
                "sample_interval_seconds": interval,
                "event_tail_seconds": TAIL_SECONDS,
                "event_mode": "GTK/link failure anchored; no-anchor timeout is not a stability pass",
                "scope": "Read-only allowlisted ioreg counters/traces and boolean en1 readiness; no RF, traffic, scans, Wi-Fi changes, sleep, router, EFI, packet capture, SSID/BSSID, IP addresses, key bytes, or packet bodies.",
            }
            _append_jsonl(stream, header)
            if identity_error:
                _append_jsonl(stream, {"record_type": "terminal_error",
                                       "elapsed_seconds": 0.0,
                                       "error": identity_error,
                                       "status": "identity_preflight_failed"})
                terminal_status = "identity_preflight_failed"
            else:
                while True:
                    sample_started = monotonic_fn()
                    elapsed = sample_started - start
                    if elapsed >= duration:
                        terminal_status = ("event_window_complete" if tail_until is not None and elapsed >= tail_until
                                           else "duration_elapsed_during_event_tail" if tail_until is not None
                                           else "duration_elapsed_no_anchor")
                        break
                    sample_attempt_count += 1
                    try:
                        point = sample_fn(expected_build, identity)
                        point["elapsed_seconds"] = round(monotonic_fn() - start, 3)
                        sample_count += 1
                        consecutive_errors = 0
                        row, previous_digests = materialize_sample(
                            point, previous_digests, sample_attempt_count)
                        row["record_type"] = "sample"
                        row["sample_index"] = sample_attempt_count
                        row["expected_boot_epoch"] = expected_boot
                        reasons = trigger_reasons(point, last_point, event_state)
                        row["new_event_reasons"] = reasons
                        if reasons:
                            when = point["elapsed_seconds"]
                            trigger_log.append({"elapsed_seconds": when,
                                                "reasons": reasons})
                            tail_until = when + TAIL_SECONDS
                        last_point = point
                    except Exception as error:
                        error_count += 1
                        consecutive_errors += 1
                        row = {
                            "record_type": "sample_error",
                            "sample_index": sample_attempt_count,
                            "captured_at": datetime.datetime.now().astimezone().isoformat(),
                            "epoch_ns": time.time_ns(),
                            "monotonic_ns": time.monotonic_ns(),
                            "elapsed_seconds": round(monotonic_fn() - start, 3),
                            "expected_boot_epoch": expected_boot,
                            "expected_candidate_build": expected_build,
                            "error": _sanitized_error(error),
                        }
                        if isinstance(error, IdentityMismatch):
                            _append_jsonl(stream, row)
                            terminal_status = "identity_mismatch"
                            break
                        if (consecutive_errors >= MAX_CONSECUTIVE_READ_ERRORS and
                                tail_until is None):
                            row["consecutive_error_limit_reached"] = True
                            _append_jsonl(stream, row)
                            terminal_status = "collection_stopped_after_consecutive_errors"
                            break
                    _append_jsonl(stream, row)

                    elapsed = monotonic_fn() - start
                    if tail_until is not None and elapsed >= tail_until:
                        terminal_status = "event_window_complete"
                        break
                    if elapsed >= duration:
                        terminal_status = ("duration_elapsed_during_event_tail" if tail_until is not None
                                           else "duration_elapsed_no_anchor")
                        break
                    delay = min(interval, max(0.0, duration - elapsed))
                    if tail_until is not None:
                        delay = min(delay, max(0.0, tail_until - elapsed))
                    if delay > 0:
                        next_sample_due += interval
                        now = monotonic_fn()
                        if next_sample_due <= now:
                            missed = int((now - next_sample_due) // interval) + 1
                            next_sample_due += missed * interval
                        sleep_fn(max(0.0, next_sample_due - now))
        except KeyboardInterrupt:
            terminal_status = "interrupted_output_preserved"
            _append_jsonl(stream, {
                "record_type": "terminal_error",
                "elapsed_seconds": round(monotonic_fn() - start, 3),
                "error": {"class": "KeyboardInterrupt"},
                "status": terminal_status,
            })
        finally:
            footer = {
                "record_type": "footer",
                "ended_at": datetime.datetime.now().astimezone().isoformat(),
                "elapsed_seconds": round(monotonic_fn() - start, 3),
                "sample_count": sample_count,
                "collection_error_count": error_count,
                "terminal_status": terminal_status,
                "trigger_log": trigger_log,
                "anchor_observed": bool(trigger_log),
                "stability_pass": False,
                "note": "A no-anchor bounded capture is not a 65-minute stability pass; use a separate long-stability result.",
            }
            _append_jsonl(stream, footer)

    return {
        "terminal_status": terminal_status,
        "sample_count": sample_count,
        "collection_error_count": error_count,
        "trigger_count": len(trigger_log),
        "output": str(output),
        "mode": "synthetic test" if sample_fn is not sample_once else "passive runtime collector",
    }


def main() -> None:
    global EXPECTED_KEXT_UUID
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, required=True,
                        help="hard maximum seconds; no event by deadline is not a pass")
    parser.add_argument("--out", type=Path, required=True,
                        help="new private JSONL path; existing path is never overwritten")
    parser.add_argument("--boot", type=int, required=True,
                        help="expected kern.boottime epoch from this boot")
    parser.add_argument("--build", default=CANDIDATE_BUILD,
                        help="expected NativeTestBuild; defaults to Test100")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="read-only sample interval seconds (default 1)")
    parser.add_argument("--expected-uuid", required=True,
                        help="UUID from the reviewed Test100 build receipt")
    args = parser.parse_args()
    if not UUID_PATTERN.fullmatch(args.expected_uuid):
        parser.error("--expected-uuid must be a Mach-O UUID")
    EXPECTED_KEXT_UUID = args.expected_uuid.upper()
    try:
        result = capture(args.out, args.boot, args.build,
                         args.duration, args.interval)
    except FileExistsError:
        print("output exists; choose a new private path", file=sys.stderr)
        raise SystemExit(2)
    except Exception as error:
        print("capture setup failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
