#!/usr/bin/env python3
"""Shared, fail-closed protocol helpers for the isolated Test086 controlled probe."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


BUILD = "25G332-Test086"
EXPECTED_UUID = "C28DBCB5-DB75-3C08-B09C-05354B5D2B57"
MINIMUM_BOOT_EPOCH_EXCLUSIVE = 1793340271
PROFILE = "native_awdl_rx149_data_input_only"
SOURCE_KIND = "controlled_probe"
SENDER_FRAMES = 16
SENDER_INTERVAL_MS = 80
# The metadata is part of the frozen native-kext build record. Its 50 ms
# sender field remains historical; the separate private host sender binary
# is pinned by its own SHA-256 and reports the 80 ms runtime contract.
FROZEN_METADATA_SENDER_INTERVAL_MS = 50
SENDER_DEADLINE_SECONDS = 2.0
MPDU_BYTES = 96
RADIOTAP_BYTES = 10
PACKET_BYTES = 106
UDP_PAYLOAD_BYTES = 8
SENDER_TX_FLAGS = "NOACK|NOSEQNO"
LISTENER_MARKER = "T086RX01"
LISTENER_LOCAL_PORT = 49153
LISTENER_SOURCE_PORT = 49152
LISTENER_GROUP = "ff02::1"
OWNER_EPOCH_FIELDS = ("ContextGeneration", "PowerGeneration",
                      "StationGeneration", "RocGeneration")
MAX_PROTOCOL_LINE_BYTES = 8192

READY_RE = re.compile(r"READY(?:\t| )(?P<tail>.+)\Z")
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class ControlledProbeError(RuntimeError):
    """A sanitized local error code, never an address or packet payload."""

    def __init__(self, code: str, evidence: Optional[Dict[str, Any]] = None):
        super().__init__(code)
        self.code = code
        self.evidence = evidence or {}


def read_private_json(path: Path) -> Tuple[Dict[str, Any], bytes]:
    """Read an owner-only JSON file without following symlinks."""
    path = Path(path)
    if path.is_symlink():
        raise ControlledProbeError("REFUSE_SYMLINK_PRIVATE_JSON")
    try:
        info = path.lstat()
    except OSError:
        raise ControlledProbeError("PRIVATE_JSON_UNAVAILABLE")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise ControlledProbeError("UNSAFE_PRIVATE_JSON_MODE_OR_OWNER")
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or
            stat.S_IMODE(parent.st_mode) != 0o700):
        raise ControlledProbeError("UNSAFE_PRIVATE_JSON_PARENT")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise ControlledProbeError("PRIVATE_JSON_OPEN_FAILED")
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(raw) > 16 * 1024 * 1024:
        raise ControlledProbeError("PRIVATE_JSON_OVERSIZE")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise ControlledProbeError("PRIVATE_JSON_MALFORMED")
    if not isinstance(value, dict):
        raise ControlledProbeError("PRIVATE_JSON_NOT_OBJECT")
    return value, raw


def validate_frozen_source_binding(template: Dict[str, Any], receipt: Dict[str, Any],
                                   receipt_raw: bytes) -> List[str]:
    errors: List[str] = []
    binding = template.get("source_binding")
    if not isinstance(binding, dict):
        return ["source_binding"]
    receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
    source_map = receipt.get("source_sha256")
    if not isinstance(source_map, dict):
        errors.append("receipt_source_map")
        source_map = {}
    source_map_sha = hashlib.sha256(json.dumps(
        source_map, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if receipt.get("candidate") != BUILD or receipt.get("status") != "built_offline":
        errors.append("receipt_identity")
    if receipt.get("mach_o_uuid") != EXPECTED_UUID:
        errors.append("receipt_uuid")
    if receipt.get("source_file_count") != len(source_map) or len(source_map) != 396:
        errors.append("receipt_source_file_count")
    if receipt.get("binary_sha256") != binding.get("expected_binary_sha256"):
        errors.append("receipt_binary_sha256")
    if receipt.get("info_plist_sha256") != binding.get("expected_info_plist_sha256"):
        errors.append("receipt_info_plist_sha256")
    if (binding.get("build_receipt_sha256") != receipt_sha or
            binding.get("source_file_count") != len(source_map) or
            binding.get("source_sha256_map_sha256") != source_map_sha):
        errors.append("frozen_receipt_binding")
    if template.get("source_sha256") != source_map:
        errors.append("template_source_map_mismatch")
    return sorted(set(errors))


def parse_key_values(line: str, prefix: str) -> Dict[str, str]:
    match = READY_RE.fullmatch(line) if prefix == "READY" else None
    if prefix == "READY":
        if not match:
            raise ControlledProbeError("SENDER_READY_MALFORMED")
        tail = match.group("tail")
    else:
        if not line.startswith(prefix + " "):
            raise ControlledProbeError(prefix + "_MALFORMED")
        tail = line[len(prefix) + 1:]
    result: Dict[str, str] = {}
    for token in tail.split():
        if token.count("=") != 1:
            raise ControlledProbeError(prefix + "_MALFORMED")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in result or not value:
            raise ControlledProbeError(prefix + "_MALFORMED")
        result[key] = value
    return result


def parse_sender_ready(line: str) -> Dict[str, Any]:
    """Validate the exact OpenWrt sender READY contract without sending."""
    values = parse_key_values(line, "READY")
    expected = {
        "frames": str(SENDER_FRAMES),
        "interval_ms": str(SENDER_INTERVAL_MS),
        "mpdu_bytes": str(MPDU_BYTES),
        "radiotap_bytes": str(RADIOTAP_BYTES),
        "packet_bytes": str(PACKET_BYTES),
        "udp_payload_bytes": str(UDP_PAYLOAD_BYTES),
        "tx_flags": SENDER_TX_FLAGS,
        "hardware_honoring": "unknown",
    }
    if values != expected:
        raise ControlledProbeError("SENDER_READY_CONTRACT_MISMATCH")
    return {
        "frames": SENDER_FRAMES,
        "interval_ms": SENDER_INTERVAL_MS,
        "mpdu_bytes": MPDU_BYTES,
        "radiotap_bytes": RADIOTAP_BYTES,
        "packet_bytes": PACKET_BYTES,
        "udp_payload_bytes": UDP_PAYLOAD_BYTES,
        "tx_flags_requested": SENDER_TX_FLAGS,
        "hardware_honoring": "unknown",
        "send_started": False,
    }


MONITOR_READY_KEYS = {
    "mode", "monitor_direct_channel_known", "monitor_wiphy", "monitor_channel",
    "monitor_frequency_mhz", "ap_wiphy", "ap_channel", "ap_frequency_mhz",
    "ap_width_mhz", "phy_single_channel_constraints_count",
    "active_same_phy_channel_count", "active_same_phy_channels",
    "active_same_phy_frequencies_mhz",
}


def parse_monitor_ready(line: str) -> Dict[str, Any]:
    values = parse_key_values(line, "MONITOR_READY")
    if set(values) != MONITOR_READY_KEYS:
        raise ControlledProbeError("MONITOR_READY_FIELD_SET_MISMATCH")
    if values.get("mode") not in {
            "monitor_direct_channel", "same_phy_active_ap_single_channel"}:
        raise ControlledProbeError("MONITOR_READY_MODE_INVALID")
    if values.get("monitor_direct_channel_known") not in {"true", "false"}:
        raise ControlledProbeError("MONITOR_READY_BOOLEAN_INVALID")
    int_keys = ("monitor_wiphy", "monitor_channel", "monitor_frequency_mhz",
                "ap_wiphy", "ap_channel", "ap_frequency_mhz", "ap_width_mhz",
                "phy_single_channel_constraints_count",
                "active_same_phy_channel_count")
    parsed: Dict[str, int] = {}
    for key in int_keys:
        if not re.fullmatch(r"[0-9]{1,6}", values[key]):
            raise ControlledProbeError("MONITOR_READY_NUMBER_INVALID")
        parsed[key] = int(values[key])
    if (parsed["ap_channel"] != 149 or parsed["ap_frequency_mhz"] != 5745 or
            parsed["ap_width_mhz"] != 80):
        raise ControlledProbeError("MONITOR_READY_AP_CHANNEL_INVALID")
    if values["active_same_phy_channels"] == "none":
        channels: List[int] = []
    else:
        tokens = values["active_same_phy_channels"].split(",")
        if any(not re.fullmatch(r"[0-9]{1,3}", item) for item in tokens):
            raise ControlledProbeError("MONITOR_READY_CHANNEL_LIST_INVALID")
        channels = [int(item) for item in tokens]
    if values["active_same_phy_frequencies_mhz"] == "none":
        frequencies: List[int] = []
    else:
        tokens = values["active_same_phy_frequencies_mhz"].split(",")
        if any(not re.fullmatch(r"[0-9]{4,5}", item) for item in tokens):
            raise ControlledProbeError("MONITOR_READY_FREQUENCY_LIST_INVALID")
        frequencies = [int(item) for item in tokens]
    if (len(channels) != parsed["active_same_phy_channel_count"] or
            len(frequencies) != parsed["active_same_phy_channel_count"]):
        raise ControlledProbeError("MONITOR_READY_CHANNEL_COUNT_MISMATCH")
    if any(channel != 149 for channel in channels) or any(freq != 5745 for freq in frequencies):
        raise ControlledProbeError("MONITOR_READY_ACTIVE_PHY_CHANNEL_MISMATCH")
    direct_known = values["monitor_direct_channel_known"] == "true"
    if direct_known:
        if values["mode"] != "monitor_direct_channel" or (
                parsed["monitor_channel"] != 149 or
                parsed["monitor_frequency_mhz"] != 5745):
            raise ControlledProbeError("MONITOR_READY_DIRECT_CHANNEL_MISMATCH")
    else:
        if (values["mode"] != "same_phy_active_ap_single_channel" or
                parsed["monitor_channel"] != 0 or
                parsed["monitor_frequency_mhz"] != 0 or
                parsed["monitor_wiphy"] != parsed["ap_wiphy"] or
                parsed["phy_single_channel_constraints_count"] < 1 or
                parsed["active_same_phy_channel_count"] < 1):
            raise ControlledProbeError("MONITOR_READY_FALLBACK_BINDING_INVALID")
    return {**values, **parsed, "active_same_phy_channels_parsed": channels,
            "active_same_phy_frequencies_mhz_parsed": frequencies,
            "monitor_direct_channel_known": direct_known}
SENDER_RESULT_ALLOWED_KEYS = {
    "event", "status", "frames_attempted", "frames_completed", "sent", "payload_bytes",
    "mpdu_bytes", "radiotap_bytes", "packet_bytes", "udp_payload_bytes",
    "elapsed_ms", "deadline_hit", "error_count", "last_errno", "stop_reason",
    "tx_flags_requested", "hardware_honoring",
}


def parse_sender_result(line: str) -> Dict[str, Any]:
    """Validate sender counters while rejecting raw peer/payload fields."""
    if len(line.encode("utf-8")) > MAX_PROTOCOL_LINE_BYTES:
        raise ControlledProbeError("SENDER_RESULT_OVERSIZE")
    try:
        value = json.loads(line)
    except (ValueError, TypeError):
        raise ControlledProbeError("SENDER_RESULT_MALFORMED")
    if not isinstance(value, dict) or value.get("event") != "SENDER_RESULT":
        raise ControlledProbeError("SENDER_RESULT_MALFORMED")
    if set(value) != SENDER_RESULT_ALLOWED_KEYS:
        raise ControlledProbeError("SENDER_RESULT_FIELD_SET_MISMATCH")
    integer_fields = ("frames_attempted", "frames_completed", "sent", "payload_bytes",
                      "mpdu_bytes", "radiotap_bytes", "packet_bytes", "udp_payload_bytes",
                      "elapsed_ms", "error_count", "last_errno")
    if any(type(value.get(key)) is not int or value[key] < 0 for key in integer_fields):
        raise ControlledProbeError("SENDER_RESULT_INVALID_COUNTER")
    if type(value.get("deadline_hit")) is not bool:
        raise ControlledProbeError("SENDER_RESULT_INVALID_DEADLINE")
    if (value["elapsed_ms"] > int(SENDER_DEADLINE_SECONDS * 1000) and
            value["deadline_hit"] is False):
        raise ControlledProbeError("SENDER_RESULT_DEADLINE_CONTRADICTION")
    if value.get("stop_reason") not in {
            "aborted_before_go", "complete", "gate_eof_timeout_or_invalid_token",
            "post_go_control_or_stdin_closed", "send_errno", "short_write",
            "host_test_send_disabled", "monotonic_clock_unavailable",
            "monotonic_clock_end_failed", "partial_sequence",
            "schedule_or_sleep_failed", "send_budget_expired",
            "send_completed_after_budget", "socket_close_error"}:
        raise ControlledProbeError("SENDER_RESULT_INVALID_STOP_REASON")
    expected_status = {
        "aborted_before_go": "aborted",
        "complete": "complete",
        "gate_eof_timeout_or_invalid_token": "failed",
        "post_go_control_or_stdin_closed": "failed",
        "send_errno": "failed",
        "short_write": "failed",
        "host_test_send_disabled": "failed",
        "monotonic_clock_unavailable": "failed",
        "monotonic_clock_end_failed": "failed",
        "partial_sequence": "failed",
        "schedule_or_sleep_failed": "failed",
        "send_budget_expired": "failed",
        "send_completed_after_budget": "failed",
        "socket_close_error": "failed",
    }[value["stop_reason"]]
    if value.get("status") != expected_status:
        raise ControlledProbeError("SENDER_RESULT_STATUS_MISMATCH")
    if (value["payload_bytes"] != MPDU_BYTES or value["mpdu_bytes"] != MPDU_BYTES or
            value["radiotap_bytes"] != RADIOTAP_BYTES or
            value["packet_bytes"] != PACKET_BYTES or
            value["udp_payload_bytes"] != UDP_PAYLOAD_BYTES or
            value.get("tx_flags_requested") != SENDER_TX_FLAGS or
            value.get("hardware_honoring") != "unknown"):
        raise ControlledProbeError("SENDER_RESULT_CONTRACT_MISMATCH")
    if value["frames_attempted"] > SENDER_FRAMES or value["frames_completed"] > SENDER_FRAMES or value["sent"] > SENDER_FRAMES:
        raise ControlledProbeError("SENDER_RESULT_FRAME_LIMIT_EXCEEDED")
    if value["frames_completed"] > value["frames_attempted"] or value["sent"] > value["frames_attempted"]:
        raise ControlledProbeError("SENDER_RESULT_COUNTER_ORDER_INVALID")
    if value["stop_reason"] == "aborted_before_go" and not validate_readiness_abort(value):
        raise ControlledProbeError("SENDER_RESULT_ABORT_NOT_ZERO_SEND")
    if value["stop_reason"] == "complete" and (
            value["frames_attempted"] != SENDER_FRAMES or
            value["frames_completed"] != SENDER_FRAMES or
            value["sent"] != SENDER_FRAMES or value["deadline_hit"]):
        raise ControlledProbeError("SENDER_RESULT_COMPLETION_INCOMPLETE")
    if value["status"] == "failed" and value["stop_reason"] == "complete":
        raise ControlledProbeError("SENDER_RESULT_STATUS_MISMATCH")
    return value


def validate_readiness_abort(result: Dict[str, Any]) -> bool:
    return (result.get("stop_reason") == "aborted_before_go" and
            result.get("frames_attempted") == 0 and
            result.get("frames_completed") == 0 and
            result.get("sent") == 0 and result.get("elapsed_ms") == 0 and
            result.get("deadline_hit") is False and
            result.get("error_count") == 0 and result.get("last_errno") == 0)


def parse_cleanup(line: str, *, run_token: str) -> Dict[str, Any]:
    if not TOKEN_RE.fullmatch(run_token):
        raise ControlledProbeError("INVALID_RUN_TOKEN")
    prefix = "CLEANUP "
    if not line.startswith(prefix) or len(line.encode("utf-8")) > MAX_PROTOCOL_LINE_BYTES:
        raise ControlledProbeError("CLEANUP_MALFORMED")
    try:
        value = json.loads(line[len(prefix):])
    except (ValueError, TypeError):
        raise ControlledProbeError("CLEANUP_MALFORMED")
    if (not isinstance(value, dict) or value.get("run_token") != run_token or
            value.get("event") != "MONITOR_CLEANUP" or
            type(value.get("monitor_removed")) is not bool or
            type(value.get("ap_unchanged")) is not bool or
            type(value.get("temporary_files_removed")) is not bool):
        raise ControlledProbeError("CLEANUP_CONTRACT_MISMATCH")
    return value


LISTENER_READY_KEYS = {
    "event", "interface", "ifindex", "family", "port", "group", "timeout_ms",
    "bound_if", "pktinfo_enabled", "recv_anyif_requested", "recv_anyif_set",
    "recv_anyif_errno", "run_token",
}
LISTENER_RESULT_KEYS = {
    "event", "status", "interface", "ifindex", "datagrams", "marker_match",
    "pktinfo_present", "pktinfo_ifindex_match", "destination_group_match",
    "source_link_local", "source_port_match", "payload_length",
    "peer_address_serialized", "recv_anyif_requested", "recv_anyif_set",
    "recv_anyif_errno", "run_token",
}


def _parse_json_event(line: str, event: str, keys: set[str]) -> Dict[str, Any]:
    if len(line.encode("utf-8")) > MAX_PROTOCOL_LINE_BYTES:
        raise ControlledProbeError(event + "_OVERSIZE")
    try:
        value = json.loads(line)
    except (ValueError, TypeError):
        raise ControlledProbeError(event + "_MALFORMED")
    if not isinstance(value, dict) or set(value) != keys or value.get("event") != event:
        raise ControlledProbeError(event + "_FIELD_SET_MISMATCH")
    return value


def parse_listener_ready(line: str, *, run_token: str) -> Dict[str, Any]:
    if not TOKEN_RE.fullmatch(run_token):
        raise ControlledProbeError("INVALID_RUN_TOKEN")
    value = _parse_json_event(line, "LISTENER_READY", LISTENER_READY_KEYS)
    if (value.get("interface") != "awdl0" or type(value.get("ifindex")) is not int or
            value["ifindex"] <= 0 or value.get("family") != 6 or
            value.get("port") != LISTENER_LOCAL_PORT or
            value.get("group") != LISTENER_GROUP or value.get("timeout_ms") != 15000 or
            value.get("bound_if") is not True or value.get("pktinfo_enabled") is not True or
            value.get("recv_anyif_requested") is not True or
            value.get("recv_anyif_set") is not True or value.get("recv_anyif_errno") != 0 or
            value.get("run_token") != run_token):
        raise ControlledProbeError("LISTENER_READY_CONTRACT_MISMATCH")
    return value


def parse_listener_result(line: str, *, run_token: str) -> Dict[str, Any]:
    if not TOKEN_RE.fullmatch(run_token):
        raise ControlledProbeError("INVALID_RUN_TOKEN")
    value = _parse_json_event(line, "LISTENER_RESULT", LISTENER_RESULT_KEYS)
    if (value.get("interface") != "awdl0" or type(value.get("ifindex")) is not int or
            value["ifindex"] <= 0 or value.get("run_token") != run_token or
            value.get("peer_address_serialized") is not False or
            value.get("recv_anyif_requested") is not True or
            value.get("recv_anyif_set") is not True or value.get("recv_anyif_errno") != 0 or
            value.get("status") not in {"marker_received", "timeout_or_unmatched"}):
        raise ControlledProbeError("LISTENER_RESULT_CONTRACT_MISMATCH")
    bool_keys = ("marker_match", "pktinfo_present", "pktinfo_ifindex_match",
                 "destination_group_match", "source_link_local", "source_port_match")
    if any(type(value.get(key)) is not bool for key in bool_keys):
        raise ControlledProbeError("LISTENER_RESULT_INVALID_BOOLEAN")
    if (type(value.get("datagrams")) is not int or value["datagrams"] < 0 or
            type(value.get("payload_length")) is not int or value["payload_length"] < 0):
        raise ControlledProbeError("LISTENER_RESULT_INVALID_COUNTER")
    marker_ok = (value["status"] == "marker_received" and value["marker_match"] is True and
                 value["pktinfo_present"] and value["pktinfo_ifindex_match"] and
                 value["destination_group_match"] and value["source_link_local"] and
                 value["source_port_match"] and value["datagrams"] >= 1 and
                 value["payload_length"] == UDP_PAYLOAD_BYTES)
    if value["status"] == "marker_received" and not marker_ok:
        raise ControlledProbeError("LISTENER_RESULT_MARKER_CONTRACT_MISMATCH")
    return value


def validate_private_metadata(template: Dict[str, Any], *, boot_epoch: int,
                              expected_receipt_sha256: str,
                              actual_receipt_sha256: str) -> List[str]:
    """Validate the isolated, disarmed source binding before any runtime action."""
    errors: List[str] = []
    expected = {
        "schema": "test086-controlled-probe-private/v1",
        "candidate": BUILD,
        "source_ready_kind": SOURCE_KIND,
        "requires_phone_ready": False,
        "armed": False,
        "status": "prepared_disarmed",
        "retry_allowed": False,
        "expected_loaded_uuid": EXPECTED_UUID,
        "profile": PROFILE,
        "diagnostic_duration_ms": 100,
        "receiver_gated": True,
        "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
    }
    for key, value in expected.items():
        if template.get(key) != value:
            errors.append(key)
    if type(boot_epoch) is not int or boot_epoch <= MINIMUM_BOOT_EPOCH_EXCLUSIVE:
        errors.append("fresh_boot_required")
    if actual_receipt_sha256 != expected_receipt_sha256:
        errors.append("frozen_build_receipt_changed")
    binding = template.get("source_binding")
    if (not isinstance(binding, dict) or
            binding.get("build_receipt_sha256") != expected_receipt_sha256 or
            binding.get("source_file_count") != 396 or
            not SHA_RE.fullmatch(str(binding.get("source_sha256_map_sha256", ""))) or
            binding.get("expected_binary_sha256") is None or
            binding.get("expected_info_plist_sha256") is None):
        errors.append("source_binding")
    if template.get("owner_epoch_fields") != list(OWNER_EPOCH_FIELDS):
        errors.append("owner_epoch_fields")
    sender = template.get("sender")
    if not isinstance(sender, dict):
        sender = {}
    if sender.get("frames_max") != SENDER_FRAMES:
        errors.append("sender_frame_limit")
    if sender.get("interval_ms") != FROZEN_METADATA_SENDER_INTERVAL_MS:
        errors.append("sender_interval")
    if sender.get("max_elapsed_seconds") != SENDER_DEADLINE_SECONDS:
        errors.append("sender_deadline")
    return sorted(set(errors))


def validate_full_run_gates(template: Dict[str, Any], *, boot_epoch: int,
                            expected_receipt_sha256: str,
                            actual_receipt_sha256: str,
                            shared_boot_claim_available: bool,
                            host_tx_counters: Dict[str, Any],
                            router_sender_ready: bool,
                            native_preflight_ready: bool,
                            listener_ready: bool) -> List[str]:
    """Evaluate all pre-GO gates without consuming a claim or mutating state."""
    errors = validate_private_metadata(
        template, boot_epoch=boot_epoch,
        expected_receipt_sha256=expected_receipt_sha256,
        actual_receipt_sha256=actual_receipt_sha256)
    if shared_boot_claim_available is not True:
        errors.append("shared_boot_claim_unavailable")
    required_counters = template.get("required_zero_host_tx_counters")
    if not isinstance(required_counters, list) or not required_counters:
        errors.append("host_tx_counter_contract")
    else:
        for key in required_counters:
            value = host_tx_counters.get(key)
            if type(value) is not int or value != 0:
                errors.append("host_tx_nonzero_or_missing:" + str(key))
    for key, value in (("router_sender_ready", router_sender_ready),
                       ("native_preflight_ready", native_preflight_ready),
                       ("listener_ready", listener_ready)):
        if value is not True:
            errors.append(key)
    return sorted(set(errors))


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _b64_no_wrap(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def validate_ap_interface(ap: str) -> str:
    """Preserve the existing shell-safe Linux interface-name contract."""
    if not isinstance(ap, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", ap):
        raise ControlledProbeError("INVALID_INTERFACE_NAME")
    return ap


def build_remote_monitor_sender_script(*, binary: bytes, binary_sha256: str,
                                       run_token: str, ap: str = "wlan1",
                                       monitor: str = "iwawdl0") -> str:
    """Create a short-lived, cleanup-guarded OpenWrt monitor+sender transaction."""
    if not TOKEN_RE.fullmatch(run_token):
        raise ControlledProbeError("INVALID_RUN_TOKEN")
    if hashlib.sha256(binary).hexdigest() != binary_sha256 or not SHA_RE.fullmatch(binary_sha256):
        raise ControlledProbeError("SENDER_BINARY_HASH_MISMATCH")
    if not binary or len(binary) > 2 * 1024 * 1024:
        raise ControlledProbeError("SENDER_BINARY_SIZE_INVALID")
    validate_ap_interface(ap)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", monitor):
        raise ControlledProbeError("INVALID_INTERFACE_NAME")
    binary_data = _b64_no_wrap(binary)
    # AP, monitor, run token and binary digest are strictly validated above.
    return f'''#!/bin/sh
LC_ALL=C
export LC_ALL
umask 077
AP={ap}
MON={monitor}
RUN_TOKEN={run_token}
EXPECTED_BIN_SHA={binary_sha256}
TMP="/tmp/iwn-t086-controlled-$RUN_TOKEN"
BIN="$TMP/awdl_probe_sender"
MON_CREATED=0
MON_IFINDEX=""
SENDER_PID=""
AP_BEFORE=""
AP_AFTER=""
MON_REMOVED=false
AP_UNCHANGED=false
TMP_REMOVED=false
cleanup() {{
  rc=$?
  trap - EXIT INT TERM HUP
  set +e
  if [ -n "$SENDER_PID" ]; then
    kill -TERM "$SENDER_PID" 2>/dev/null
    wait "$SENDER_PID" 2>/dev/null
    SENDER_PID=""
  fi
  if [ "$MON_CREATED" -eq 1 ]; then
    current="$(cat "/sys/class/net/$MON/ifindex" 2>/dev/null || true)"
    if [ -n "$MON_IFINDEX" ] && [ "$current" = "$MON_IFINDEX" ]; then
      ip link set dev "$MON" down >/dev/null 2>&1
      current="$(cat "/sys/class/net/$MON/ifindex" 2>/dev/null || true)"
      if [ "$current" = "$MON_IFINDEX" ]; then
        iw dev "$MON" del >/dev/null 2>&1
      fi
    fi
  fi
  if [ ! -e "/sys/class/net/$MON" ]; then MON_REMOVED=true; fi
  AP_AFTER="$(ap_config_digest 2>/dev/null || true)"
  if [ -n "$AP_BEFORE" ] && [ "$AP_AFTER" = "$AP_BEFORE" ]; then AP_UNCHANGED=true; fi
  rm -rf "$TMP" 2>/dev/null
  if [ ! -e "$TMP" ]; then TMP_REMOVED=true; fi
  exec 3<&- 2>/dev/null
  printf 'CLEANUP {{"event":"MONITOR_CLEANUP","run_token":"%s","monitor_removed":%s,"ap_unchanged":%s,"temporary_files_removed":%s}}\\n' \\
    "$RUN_TOKEN" "$MON_REMOVED" "$AP_UNCHANGED" "$TMP_REMOVED"
  exit "$rc"
}}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

ap_config_digest() {{
  iw dev "$AP" info 2>/dev/null | awk '
    $1 == "type" {{ type = $2 }}
    $1 == "channel" {{
      channel = $2; gsub(/[()]/, "", $3); frequency = $3
      for (i = 1; i < NF; i++) if ($i == "width:") width = $(i + 1)
      gsub(/[^0-9]/, "", width)
    }}
    $1 == "txpower" {{ power = $2 }}
    END {{
      if (type == "" || channel == "" || frequency == "" || width == "") exit 1
      printf "%s|%s|%s|%s|%s\\n", type, channel, frequency, width, power
    }}
  ' | sha256sum | awk '{{print $1}}'
}}

if [ -e "$TMP" ] || [ -e "/sys/class/net/$MON" ]; then
  printf 'REMOTE_ERROR code=monitor_or_temp_path_already_exists\\n'
  exit 2
fi
mkdir -m 700 "$TMP" || {{ printf 'REMOTE_ERROR code=temp_create_failed\\n'; exit 2; }}
AP_INFO="$(iw dev "$AP" info 2>/dev/null)" || {{ printf 'REMOTE_ERROR code=ap_state_unavailable\\n'; exit 2; }}
AP_PHY="$(printf '%s\\n' "$AP_INFO" | awk '$1=="wiphy"{{print $2;exit}}')"
AP_CHANNEL="$(printf '%s\\n' "$AP_INFO" | awk '$1=="channel"{{print $2;exit}}')"
AP_FREQUENCY="$(printf '%s\\n' "$AP_INFO" | awk '$1=="channel"{{gsub(/[()]/,"",$3);print $3;exit}}')"
AP_WIDTH="$(printf '%s\\n' "$AP_INFO" | awk '$1=="channel"{{for(i=1;i<NF;i++)if($i=="width:"){{gsub(/[^0-9]/,"",$(i+1));print $(i+1);exit}}}}')"
case "$AP_PHY:$AP_CHANNEL:$AP_FREQUENCY:$AP_WIDTH" in *[!0-9:]*) printf 'REMOTE_ERROR code=ap_channel_parse_failed\\n'; exit 2 ;; esac
if [ "$AP_CHANNEL" != 149 ] || [ "$AP_FREQUENCY" != 5745 ] || [ "$AP_WIDTH" != 80 ]; then
  printf 'REMOTE_ERROR code=expected_channel_149_unavailable\\n'
  exit 2
fi
AP_BEFORE="$(ap_config_digest 2>/dev/null || true)"
case "$AP_BEFORE" in ''|*[!0-9a-f]*) printf 'REMOTE_ERROR code=ap_snapshot_failed\\n'; exit 2 ;; esac
[ "${{#AP_BEFORE}}" -eq 64 ] || {{ printf 'REMOTE_ERROR code=ap_snapshot_failed\\n'; exit 2; }}
if ! iw phy "phy$AP_PHY" info 2>/dev/null | awk '/Supported interface modes:/{{m=1;next}} m&&$1=="*"&&$2=="monitor"{{ok=1}} END{{exit !ok}}'; then
  printf 'REMOTE_ERROR code=monitor_unsupported\\n'
  exit 2
fi
printf '%s' '{binary_data}' | base64 -d > "$BIN" || {{ printf 'REMOTE_ERROR code=sender_stage_failed\\n'; exit 2; }}
chmod 700 "$BIN" || {{ printf 'REMOTE_ERROR code=sender_mode_failed\\n'; exit 2; }}
BIN_SHA="$(sha256sum "$BIN" 2>/dev/null | awk '{{print $1}}')"
if [ "$BIN_SHA" != "$EXPECTED_BIN_SHA" ]; then
  printf 'REMOTE_ERROR code=sender_sha_mismatch\\n'
  exit 2
fi
if ! iw phy "phy$AP_PHY" interface add "$MON" type monitor flags otherbss >/dev/null 2>&1; then
  printf 'REMOTE_ERROR code=monitor_create_failed\\n'
  exit 2
fi
MON_CREATED=1
MON_IFINDEX="$(cat "/sys/class/net/$MON/ifindex" 2>/dev/null || true)"
case "$MON_IFINDEX" in ''|*[!0-9]*) printf 'REMOTE_ERROR code=monitor_ifindex_unavailable\\n'; exit 2 ;; esac
ip link set dev "$MON" up >/dev/null 2>&1 || {{ printf 'REMOTE_ERROR code=monitor_up_failed\\n'; exit 2; }}
MON_INFO="$(iw dev "$MON" info 2>/dev/null)" || {{ printf 'REMOTE_ERROR code=monitor_info_unavailable\\n'; exit 2; }}
printf '%s\\n' "$MON_INFO" | awk '$1=="type"&&$2=="monitor"{{ok=1}} END{{exit !ok}}' || {{ printf 'REMOTE_ERROR code=monitor_type_mismatch\\n'; exit 2; }}
MON_PHY="$(printf '%s\\n' "$MON_INFO" | awk '$1=="wiphy"{{print $2;exit}}')"
MON_CHANNEL="$(printf '%s\\n' "$MON_INFO" | awk '$1=="channel"{{print $2;exit}}')"
MON_FREQUENCY="$(printf '%s\\n' "$MON_INFO" | awk '$1=="channel"{{gsub(/[()]/,"",$3);print $3;exit}}')"
if [ -z "$MON_CHANNEL" ] && [ -z "$MON_FREQUENCY" ]; then
  MON_CHANNEL=0
  MON_FREQUENCY=0
  MON_DIRECT=false
elif [ -n "$MON_CHANNEL" ] && [ -n "$MON_FREQUENCY" ]; then
  MON_DIRECT=true
  if [ "$MON_CHANNEL" != 149 ] || [ "$MON_FREQUENCY" != 5745 ]; then
    printf 'REMOTE_ERROR code=monitor_channel_mismatch\\n'
    exit 2
  fi
else
  printf 'REMOTE_ERROR code=monitor_channel_parse_incomplete\\n'
  exit 2
fi
case "$MON_PHY:$AP_PHY" in *[!0-9:]*) printf 'REMOTE_ERROR code=monitor_wiphy_unavailable\\n'; exit 2 ;; esac
PHY_INFO="$(iw phy "phy$AP_PHY" info 2>/dev/null)" || PHY_INFO=""
PHY_CHANNEL_LIMIT_COUNT="$(printf '%s\\n' "$PHY_INFO" | awk '
  /valid interface combinations:/ {{ in_combos = 1; next }}
  in_combos && /^[^[:space:]]/ {{ in_combos = 0 }}
  in_combos {{
    for (i = 1; i < NF; i++) if ($i == "#channels") {{
      value = $(i + 2); gsub(/[^0-9]/, "", value); count++
      if (value != "1") bad = 1
    }}
  }}
  END {{ if (bad) print 0; else print count + 0 }}
')"
case "$PHY_CHANNEL_LIMIT_COUNT" in ''|*[!0-9]*) printf 'REMOTE_ERROR code=phy_combo_parse_failed\\n'; exit 2 ;; esac
ACTIVE_CHANNELS=""
ACTIVE_FREQUENCIES=""
ACTIVE_SAME_PHY_COUNT=0
for IFACE in $(iw dev 2>/dev/null | awk '$1=="Interface"{{print $2}}'); do
  case "$IFACE" in *[!A-Za-z0-9_.-]*) printf 'REMOTE_ERROR code=active_interface_name_invalid\\n'; exit 2 ;; esac
  [ "$IFACE" = "$MON" ] && continue
  IFACE_INFO="$(iw dev "$IFACE" info 2>/dev/null)" || {{ printf 'REMOTE_ERROR code=active_interface_info_unavailable\\n'; exit 2; }}
  IFACE_PHY="$(printf '%s\\n' "$IFACE_INFO" | awk '$1=="wiphy"{{print $2;exit}}')"
  [ "$IFACE_PHY" = "$AP_PHY" ] || continue
  LINK_FLAGS="$(ip -o link show dev "$IFACE" 2>/dev/null | awk '{{print $3}}')"
  [ -n "$LINK_FLAGS" ] || {{ printf 'REMOTE_ERROR code=active_interface_state_unavailable\\n'; exit 2; }}
  case ",$LINK_FLAGS," in *,UP,*) ;; *) continue ;; esac
  IFACE_CHANNEL="$(printf '%s\\n' "$IFACE_INFO" | awk '$1=="channel"{{print $2;exit}}')"
  IFACE_FREQUENCY="$(printf '%s\\n' "$IFACE_INFO" | awk '$1=="channel"{{gsub(/[()]/,"",$3);print $3;exit}}')"
  case "$IFACE_CHANNEL:$IFACE_FREQUENCY" in *[!0-9:]*) printf 'REMOTE_ERROR code=active_phy_channel_unavailable\\n'; exit 2 ;; esac
  if [ "$IFACE_CHANNEL" != 149 ] || [ "$IFACE_FREQUENCY" != 5745 ]; then
    printf 'REMOTE_ERROR code=active_phy_channel_mismatch\\n'
    exit 2
  fi
  ACTIVE_SAME_PHY_COUNT=$((ACTIVE_SAME_PHY_COUNT + 1))
  if [ -n "$ACTIVE_CHANNELS" ]; then
    ACTIVE_CHANNELS="$ACTIVE_CHANNELS,$IFACE_CHANNEL"
    ACTIVE_FREQUENCIES="$ACTIVE_FREQUENCIES,$IFACE_FREQUENCY"
  else
    ACTIVE_CHANNELS="$IFACE_CHANNEL"
    ACTIVE_FREQUENCIES="$IFACE_FREQUENCY"
  fi
done
if [ "$MON_DIRECT" = false ]; then
  if [ "$MON_PHY" != "$AP_PHY" ] || [ "$PHY_CHANNEL_LIMIT_COUNT" -lt 1 ] || [ "$ACTIVE_SAME_PHY_COUNT" -lt 1 ]; then
    printf 'REMOTE_ERROR code=monitor_same_phy_single_channel_unproven\\n'
    exit 2
  fi
  MONITOR_MODE=same_phy_active_ap_single_channel
else
  MONITOR_MODE=monitor_direct_channel
fi
if [ -z "$ACTIVE_CHANNELS" ]; then ACTIVE_CHANNELS=none; ACTIVE_FREQUENCIES=none; fi
printf 'MONITOR_READY mode=%s monitor_direct_channel_known=%s monitor_wiphy=%s monitor_channel=%s monitor_frequency_mhz=%s ap_wiphy=%s ap_channel=%s ap_frequency_mhz=%s ap_width_mhz=%s phy_single_channel_constraints_count=%s active_same_phy_channel_count=%s active_same_phy_channels=%s active_same_phy_frequencies_mhz=%s\\n' \\
  "$MONITOR_MODE" "$MON_DIRECT" "$MON_PHY" "$MON_CHANNEL" "$MON_FREQUENCY" \\
  "$AP_PHY" "$AP_CHANNEL" "$AP_FREQUENCY" "$AP_WIDTH" "$PHY_CHANNEL_LIMIT_COUNT" \\
  "$ACTIVE_SAME_PHY_COUNT" "$ACTIVE_CHANNELS" "$ACTIVE_FREQUENCIES"
if ! exec 3<&0; then
  printf 'REMOTE_ERROR code=sender_control_pipe_dup_failed\\n'
  exit 2
fi
"$BIN" --send --interface "$MON" --count 16 --interval-ms 80 --nonce "$RUN_TOKEN" --wait-go <&3 &
SENDER_PID=$!
wait "$SENDER_PID"
SENDER_STATUS=$?
SENDER_PID=""
exec 3<&-
exit "$SENDER_STATUS"
'''


def private_atomic_write(path: Path, data: Dict[str, Any]) -> None:
    path = Path(path)
    if path.is_symlink():
        raise ControlledProbeError("REFUSE_SYMLINK_REPORT")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise ControlledProbeError("UNSAFE_PRIVATE_DIRECTORY_MODE")
    temp = path.with_name("." + path.name + "." + secrets.token_hex(8))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    os.replace(temp, path)
    os.chmod(path, 0o600)
