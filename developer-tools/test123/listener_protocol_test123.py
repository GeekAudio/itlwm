#!/usr/bin/env python3
"""Strict parser for the Test123 awdl0 IPv6-unicast listener."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any


SCHEMA = "test123-awdl-unicast-listener/v1"
PAYLOAD_LENGTH = 8
NONCE_RE = re.compile(r"^[0-9a-f]{16}$")
PORT = 49153
SOURCE_PORT = 49152
HOP_LIMIT = 1
TIMEOUT_MS = 15000
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
TAG_RE = re.compile(r"^[0-9a-f]{16}$")
MAX_LINE_BYTES = 8192


class ListenerProtocolError(ValueError):
    pass


def identity_tag(address: str) -> str:
    """Return a non-cryptographic config-comparison tag."""
    try:
        parsed = ipaddress.IPv6Address(address.split("%", 1)[0])
    except (ipaddress.AddressValueError, AttributeError) as error:
        raise ListenerProtocolError("listener_expected_ipv6_invalid") from error
    if not parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
        raise ListenerProtocolError("listener_expected_ipv6_not_unicast_link_local")
    value = 0xCBF29CE484222325
    for byte in parsed.packed:
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def expected_binding(manifest: Any, ifindex: Any) -> dict:
    if type(ifindex) is not int or ifindex <= 0:
        raise ListenerProtocolError("listener_expected_ifindex_invalid")
    if not isinstance(manifest, dict):
        raise ListenerProtocolError("listener_packet_manifest_invalid")
    if (manifest.get("schema") != "test122-correlated-packet-set/v2" or
            manifest.get("packet_set_length") != 536 or
            manifest.get("frame_count") != 4):
        raise ListenerProtocolError("listener_packet_manifest_version_invalid")
    nonce = manifest.get("wire_nonce_hex")
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce) or nonce == "0" * 16:
        raise ListenerProtocolError("listener_wire_nonce_invalid")
    frames = manifest.get("frames")
    if (not isinstance(frames, list) or len(frames) != 4 or
            any(not isinstance(row, dict) or row.get("ordinal") != i or
                row.get("payload_hex") != nonce for i, row in enumerate(frames))):
        raise ListenerProtocolError("listener_frame_payload_binding_mismatch")
    identities = manifest.get("identities")
    if not isinstance(identities, dict):
        raise ListenerProtocolError("listener_packet_manifest_identities_missing")
    source = identities.get("source")
    destination = identities.get("destination_awdl0")
    if not isinstance(source, dict) or not isinstance(destination, dict):
        raise ListenerProtocolError("listener_packet_manifest_addresses_missing")
    source_ip = source.get("ipv6_link_local")
    destination_ip = destination.get("ipv6_link_local")
    if any(not isinstance(ip, str) or "%" in ip for ip in (source_ip, destination_ip)):
        raise ListenerProtocolError("listener_expected_ipv6_zone_not_allowed")
    source_tag = identity_tag(source_ip)
    destination_tag = identity_tag(destination_ip)
    if source_tag == destination_tag:
        raise ListenerProtocolError("listener_expected_identity_collision")
    return {
        "interface": "awdl0",
        "ifindex": ifindex,
        "source_ipv6": source_ip,
        "destination_ipv6": destination_ip,
        "source_identity_tag_fnv1a64": source_tag,
        "destination_identity_tag_fnv1a64": destination_tag,
        "source_port": SOURCE_PORT,
        "destination_port": PORT,
        "hop_limit": HOP_LIMIT,
        "payload": nonce,
        "payload_encoding": "hex",
        "wire_nonce_hex": nonce,
    }


READY_KEYS = {
    "event", "schema", "interface", "ifindex", "family", "port",
    "source_port", "hop_limit", "payload", "timeout_ms", "bound_if",
    "destination_assigned", "pktinfo_enabled", "hoplimit_enabled",
    "recv_anyif_requested", "recv_anyif_set", "recv_anyif_errno",
    "source_identity_tag_fnv1a64", "destination_identity_tag_fnv1a64",
    "peer_address_serialized", "run_token", "wire_nonce_hex", "payload_encoding",
    "tool_test", "running_kernel_test", "clock_domain", "clock_host", "ready_ns",
}

RESULT_KEYS = {
    "event", "schema", "status", "interface", "ifindex", "datagrams",
    "marker_match", "source_address_match", "destination_address_match",
    "source_port_match", "destination_port_match", "hop_limit_present",
    "hop_limit_match", "pktinfo_present", "pktinfo_ifindex_match",
    "payload_length", "payload_match", "payload_truncated",
    "control_truncated", "wrong_source_datagrams",
    "wrong_destination_datagrams", "other_unmatched_datagrams",
    "source_identity_tag_fnv1a64", "destination_identity_tag_fnv1a64",
    "receive_error", "peer_address_serialized", "recv_anyif_requested", "recv_anyif_set",
    "recv_anyif_errno", "run_token", "wire_nonce_hex", "payload_encoding",
    "tool_test", "running_kernel_test", "clock_domain", "clock_host", "ready_ns",
    "observed_ns", "finished_ns", "time_semantics", "received_payload_hex",
    "distinct_ordinals_proven",
}


def _object(line: str, event: str, keys: set[str]) -> dict:
    if not isinstance(line, str) or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise ListenerProtocolError(event + "_oversize")
    try:
        def unique_fields(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON field")
                result[key] = item
            return result
        value = json.loads(line, object_pairs_hook=unique_fields)
    except (ValueError, TypeError) as error:
        raise ListenerProtocolError(event + "_malformed") from error
    if not isinstance(value, dict) or set(value) != keys or value.get("event") != event:
        raise ListenerProtocolError(event + "_field_set_mismatch")
    if value.get("schema") != SCHEMA:
        raise ListenerProtocolError(event + "_schema_mismatch")
    if (value.get("tool_test") != "Test123" or
            value.get("running_kernel_test") != "Test122" or
            value.get("clock_domain") != "CLOCK_MONOTONIC" or
            value.get("clock_host") != "mac" or
            value.get("payload_encoding") != "hex"):
        raise ListenerProtocolError(event + "_tool_or_clock_mismatch")
    return value


def parse_ready(line: str, *, run_token: str, expected: dict) -> dict:
    if not isinstance(run_token, str) or not TOKEN_RE.fullmatch(run_token):
        raise ListenerProtocolError("invalid_run_token")
    value = _object(line, "LISTENER_READY", READY_KEYS)
    if (type(value.get("ready_ns")) is not int or value["ready_ns"] <= 0 or
            value.get("wire_nonce_hex") != expected["wire_nonce_hex"]):
        raise ListenerProtocolError("listener_ready_nonce_or_time_mismatch")
    numeric_fields = ("ifindex", "family", "port", "source_port", "hop_limit",
                      "timeout_ms", "recv_anyif_errno")
    if any(type(value.get(key)) is not int for key in numeric_fields):
        raise ListenerProtocolError("listener_ready_numeric_type_invalid")
    if (value.get("interface") != "awdl0" or
            type(value.get("ifindex")) is not int or
            value.get("ifindex") != expected["ifindex"] or
            value.get("family") != 6 or value.get("port") != PORT or
            value.get("source_port") != SOURCE_PORT or
            value.get("hop_limit") != HOP_LIMIT or
            value.get("payload") != expected["wire_nonce_hex"] or
            value.get("timeout_ms") != TIMEOUT_MS or
            value.get("bound_if") is not True or
            value.get("destination_assigned") is not True or
            value.get("pktinfo_enabled") is not True or
            value.get("hoplimit_enabled") is not True or
            value.get("recv_anyif_requested") is not True or
            value.get("recv_anyif_set") is not True or
            value.get("recv_anyif_errno") != 0 or
            value.get("source_identity_tag_fnv1a64") !=
                expected["source_identity_tag_fnv1a64"] or
            value.get("destination_identity_tag_fnv1a64") !=
                expected["destination_identity_tag_fnv1a64"] or
            value.get("peer_address_serialized") is not False or
            value.get("run_token") != run_token):
        raise ListenerProtocolError("listener_ready_contract_mismatch")
    return value


def parse_result(line: str, *, run_token: str, expected: dict) -> dict:
    if not isinstance(run_token, str) or not TOKEN_RE.fullmatch(run_token):
        raise ListenerProtocolError("invalid_run_token")
    value = _object(line, "LISTENER_RESULT", RESULT_KEYS)
    if (value.get("wire_nonce_hex") != expected["wire_nonce_hex"] or
            value.get("distinct_ordinals_proven") is not False or
            value.get("time_semantics") != "userspace_recvmsg_return"):
        raise ListenerProtocolError("listener_result_nonce_or_proof_mismatch")
    if (type(expected.get("ready_ns")) is not int or expected["ready_ns"] <= 0 or
            any(type(value.get(k)) is not int for k in ("ready_ns", "observed_ns", "finished_ns")) or
            value["ready_ns"] != expected["ready_ns"] or
            value["finished_ns"] < value["ready_ns"] or
            value["finished_ns"] - value["ready_ns"] > (TIMEOUT_MS + 2000) * 1_000_000 or
            not (value["observed_ns"] == 0 or
                 value["ready_ns"] <= value["observed_ns"] <= value["finished_ns"])):
        raise ListenerProtocolError("listener_result_time_binding_invalid")
    if type(value.get("recv_anyif_errno")) is not int:
        raise ListenerProtocolError("listener_result_recv_anyif_errno_invalid")
    if (value.get("interface") != "awdl0" or
            type(value.get("ifindex")) is not int or
            value.get("ifindex") != expected["ifindex"] or
            value.get("run_token") != run_token or
            value.get("peer_address_serialized") is not False or
            value.get("recv_anyif_requested") is not True or
            value.get("recv_anyif_set") is not True or
            value.get("recv_anyif_errno") != 0 or
            value.get("status") not in {"marker_received", "timeout_or_unmatched"}):
        raise ListenerProtocolError("listener_result_contract_mismatch")
    bool_fields = (
        "marker_match", "source_address_match", "destination_address_match",
        "source_port_match", "destination_port_match", "hop_limit_present",
        "hop_limit_match", "pktinfo_present", "pktinfo_ifindex_match",
        "payload_match", "payload_truncated", "control_truncated")
    if any(type(value.get(key)) is not bool for key in bool_fields):
        raise ListenerProtocolError("listener_result_invalid_boolean")
    int_fields = ("datagrams", "payload_length", "wrong_source_datagrams",
                  "wrong_destination_datagrams", "other_unmatched_datagrams")
    if any(type(value.get(key)) is not int or value[key] < 0 for key in int_fields):
        raise ListenerProtocolError("listener_result_invalid_counter")
    if type(value.get("receive_error")) is not int or value["receive_error"] < 0:
        raise ListenerProtocolError("listener_result_receive_error_invalid")
    source_tag = value.get("source_identity_tag_fnv1a64")
    destination_tag = value.get("destination_identity_tag_fnv1a64")
    if source_tag is not None and (not isinstance(source_tag, str) or not TAG_RE.fullmatch(source_tag)):
        raise ListenerProtocolError("listener_result_source_tag_invalid")
    if (destination_tag is not None and
            (not isinstance(destination_tag, str) or not TAG_RE.fullmatch(destination_tag))):
        raise ListenerProtocolError("listener_result_destination_tag_invalid")
    # Never accept a source/destination match flag which contradicts the
    # identity tags computed from the very packet manifest used by the sender.
    if value["source_address_match"] != (
            source_tag == expected["source_identity_tag_fnv1a64"]):
        raise ListenerProtocolError("listener_result_source_identity_conflict")
    if value["destination_address_match"] != (
            destination_tag == expected["destination_identity_tag_fnv1a64"]):
        raise ListenerProtocolError("listener_result_destination_identity_conflict")
    received_hex = value.get("received_payload_hex")
    if received_hex is not None and (not isinstance(received_hex, str) or
                                      not NONCE_RE.fullmatch(received_hex)):
        raise ListenerProtocolError("listener_result_payload_hex_invalid")
    payload_positive = (received_hex == expected["wire_nonce_hex"] and
                        value["payload_length"] == PAYLOAD_LENGTH and
                        value["payload_truncated"] is False)
    if value["payload_match"] != payload_positive:
        raise ListenerProtocolError("listener_result_payload_identity_conflict")
    if (value["datagrams"] == 0) != (value["observed_ns"] == 0):
        raise ListenerProtocolError("listener_result_observed_time_missing")
    positive = (
        value["receive_error"] == 0 and
        value["status"] == "marker_received" and value["marker_match"] is True and
        value["source_address_match"] is True and
        value["destination_address_match"] is True and
        value["source_port_match"] is True and
        value["destination_port_match"] is True and
        value["hop_limit_present"] is True and value["hop_limit_match"] is True and
        value["pktinfo_present"] is True and
        value["pktinfo_ifindex_match"] is True and
        value["payload_match"] is True and value["payload_length"] == PAYLOAD_LENGTH and
        value["payload_truncated"] is False and value["control_truncated"] is False and
        value["datagrams"] >= 1)
    if value["status"] == "marker_received" and not positive:
        raise ListenerProtocolError("listener_result_positive_contract_mismatch")
    if value["status"] == "timeout_or_unmatched" and value["marker_match"] is True:
        raise ListenerProtocolError("listener_result_false_positive_status")
    return value



def listener_argv(binary, *, run_token: str, expected: dict) -> list[str]:
    """Build argv without a shell. No socket, identity read, or device action."""
    if not isinstance(run_token, str) or not TOKEN_RE.fullmatch(run_token):
        raise ListenerProtocolError("invalid_run_token")
    nonce = expected.get("wire_nonce_hex")
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce) or nonce == "0" * 16:
        raise ListenerProtocolError("listener_wire_nonce_invalid")
    return [str(binary), "--listen-nonce", nonce, "--run-token", run_token,
            "--expected-source-ipv6", expected["source_ipv6"],
            "--expected-destination-ipv6", expected["destination_ipv6"],
            "--expected-ifindex", str(expected["ifindex"]), "--recv-anyif"]
