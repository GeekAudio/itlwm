#!/usr/bin/env python3
"""Strict parser for the Test102 awdl0 IPv6-unicast listener."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any


SCHEMA = "test102-awdl-unicast-listener/v1"
MARKER = "T086RX01"
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
    """Return a non-cryptographic, non-reversible config-comparison tag."""
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
    identities = manifest.get("identities")
    if not isinstance(identities, dict):
        raise ListenerProtocolError("listener_packet_manifest_identities_missing")
    source = identities.get("source")
    destination = identities.get("destination_awdl0")
    if not isinstance(source, dict) or not isinstance(destination, dict):
        raise ListenerProtocolError("listener_packet_manifest_addresses_missing")
    source_ip = source.get("ipv6_link_local")
    destination_ip = destination.get("ipv6_link_local")
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
        "payload": MARKER,
    }


READY_KEYS = {
    "event", "schema", "interface", "ifindex", "family", "port",
    "source_port", "hop_limit", "payload", "timeout_ms", "bound_if",
    "destination_assigned", "pktinfo_enabled", "hoplimit_enabled",
    "recv_anyif_requested", "recv_anyif_set", "recv_anyif_errno",
    "source_identity_tag_fnv1a64", "destination_identity_tag_fnv1a64",
    "peer_address_serialized", "run_token",
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
    "recv_anyif_errno", "run_token",
}


def _object(line: str, event: str, keys: set[str]) -> dict:
    if not isinstance(line, str) or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise ListenerProtocolError(event + "_oversize")
    try:
        value = json.loads(line)
    except (ValueError, TypeError) as error:
        raise ListenerProtocolError(event + "_malformed") from error
    if not isinstance(value, dict) or set(value) != keys or value.get("event") != event:
        raise ListenerProtocolError(event + "_field_set_mismatch")
    if value.get("schema") != SCHEMA:
        raise ListenerProtocolError(event + "_schema_mismatch")
    return value


def parse_ready(line: str, *, run_token: str, expected: dict) -> dict:
    if not isinstance(run_token, str) or not TOKEN_RE.fullmatch(run_token):
        raise ListenerProtocolError("invalid_run_token")
    value = _object(line, "LISTENER_READY", READY_KEYS)
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
            value.get("payload") != MARKER or
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
    positive = (
        value["status"] == "marker_received" and value["marker_match"] is True and
        value["source_address_match"] is True and
        value["destination_address_match"] is True and
        value["source_port_match"] is True and
        value["destination_port_match"] is True and
        value["hop_limit_present"] is True and value["hop_limit_match"] is True and
        value["pktinfo_present"] is True and
        value["pktinfo_ifindex_match"] is True and
        value["payload_match"] is True and value["payload_length"] == len(MARKER) and
        value["payload_truncated"] is False and value["control_truncated"] is False and
        value["datagrams"] >= 1)
    if value["status"] == "marker_received" and not positive:
        raise ListenerProtocolError("listener_result_positive_contract_mismatch")
    if value["status"] == "timeout_or_unmatched" and value["marker_match"] is True:
        raise ListenerProtocolError("listener_result_false_positive_status")
    return value

