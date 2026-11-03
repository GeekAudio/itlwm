#!/usr/bin/env python3
"""Offline builder/validator for per-run correlated Test122 packet sets.

This module only transforms packet bytes and validates identities. It does not
open sockets, contact a router, claim a runtime window, or transmit packets.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
import sys
from pathlib import Path
from typing import Any

TOOL_DIR = Path(__file__).resolve().parent
TEST104_DIR = TOOL_DIR.parents[1] / "test104"
if str(TEST104_DIR) not in sys.path:
    sys.path.insert(0, str(TEST104_DIR))
import packetset_test104 as _test104  # noqa: E402

PACKET_SET_MAGIC = b"T122PKT2"
PACKET_SET_SCHEMA = "test122-correlated-packet-set/v2"
PACKET_COUNT = _test104.PACKET_COUNT
INTERVAL_MS = _test104.INTERVAL_MS
BUDGET_MS = _test104.BUDGET_MS
RADIOTAP_LEN = _test104.RADIOTAP_LEN
MPDU_LEN = _test104.MPDU_LEN
PACKET_LEN = _test104.PACKET_LEN
HEADER_LEN = 112
PACKET_SET_LEN = HEADER_LEN + PACKET_COUNT * PACKET_LEN
TEMPLATE_SHA256 = _test104.TEMPLATE_SHA256
RADIOTAP_NOSEQNO_ONLY = _test104.RADIOTAP_NOSEQNO_ONLY


class PacketSetError(ValueError):
    """Raised when a packet set violates the pinned Test122 contract."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wire_nonce(value: Any) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{16}", value) is None:
        raise PacketSetError("wire_nonce_hex_invalid")
    nonce = bytes.fromhex(value)
    if nonce == bytes(8):
        raise PacketSetError("wire_nonce_must_be_nonzero")
    return nonce


def _sequence_base(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise PacketSetError(label + "_out_of_range")
    return value


def _normalize_identity(source: dict, target: dict) -> tuple[bytes, bytes, bytes, bytes]:
    if not isinstance(source, dict) or not isinstance(target, dict):
        raise PacketSetError("identities_must_be_objects")
    source_mac = _test104._mac(source.get("mac"), "router_source")
    source_ip, _ = _test104._ipv6ll(source.get("ipv6_link_local"), "router_source")
    target_mac = _test104._mac(target.get("mac"), "target_awdl0")
    target_ip, _ = _test104._ipv6ll(target.get("ipv6_link_local"), "target_awdl0")
    if source_mac == target_mac or source_ip == target_ip:
        raise PacketSetError("source_destination_identity_collision")
    return source_mac, target_mac, source_ip, target_ip


def _build_mpdu(template: bytes, source_mac: bytes, target_mac: bytes,
                source_ip: bytes, target_ip: bytes, nonce: bytes,
                wifi_sequence: int, awdl_sequence: int) -> bytes:
    frame = bytearray(_test104._build_mpdu(
        template, source_mac, target_mac, source_ip, target_ip))
    sequence_control = (wifi_sequence & 0x0FFF) << 4
    # IEEE 802.11 Sequence Control and AWDL sequence are little-endian on wire.
    struct.pack_into("<H", frame, 22, sequence_control)
    struct.pack_into("<H", frame, 34, awdl_sequence & 0xFFFF)
    frame[88:96] = nonce
    frame[86:88] = b"\x00\x00"
    struct.pack_into("!H", frame, 86,
                     _test104._udp_checksum(source_ip, target_ip, bytes(frame[80:96])))
    return bytes(frame)


def _checksum_valid(mpdu: bytes, source_ip: bytes, target_ip: bytes) -> bool:
    udp = mpdu[80:96]
    pseudo = source_ip + target_ip + struct.pack("!I3xB", len(udp), 17)
    return _test104._checksum(pseudo + udp) == 0


def _header_values(raw: bytes, source: dict | None = None,
                   target: dict | None = None,
                   expected_wire_nonce_hex: str | None = None) -> dict:
    if not isinstance(raw, bytes) or len(raw) != PACKET_SET_LEN:
        raise PacketSetError("packet_set_length_invalid")
    header = raw[:HEADER_LEN]
    if header[:8] != PACKET_SET_MAGIC or header[8] != 2:
        raise PacketSetError("packet_set_schema_invalid")
    if (header[9] != PACKET_COUNT or
            struct.unpack_from(">HHHHH", header, 10) !=
            (INTERVAL_MS, BUDGET_MS, RADIOTAP_LEN, MPDU_LEN, PACKET_LEN) or
            header[68:100] != bytes.fromhex(TEMPLATE_SHA256) or
            header[100:104] != bytes(4)):
        raise PacketSetError("packet_set_header_invalid")

    wifi_sequence_base, awdl_sequence_base = struct.unpack_from(">HH", header, 20)
    if wifi_sequence_base > 0x0FFF:
        raise PacketSetError("wifi_sequence_base_out_of_range")
    nonce = header[104:112]
    if nonce == bytes(8):
        raise PacketSetError("wire_nonce_must_be_nonzero")
    nonce_hex = nonce.hex()
    if expected_wire_nonce_hex is not None:
        expected_nonce = _wire_nonce(expected_wire_nonce_hex)
        if nonce != expected_nonce:
            raise PacketSetError("wire_nonce_expectation_mismatch")

    source_mac = header[24:30]
    target_mac = header[30:36]
    source_ip = header[36:52]
    target_ip = header[52:68]
    source_norm = {
        "mac": _test104._format_mac(source_mac),
        "ipv6_link_local": str(ipaddress.IPv6Address(source_ip)),
    }
    target_norm = {
        "mac": _test104._format_mac(target_mac),
        "ipv6_link_local": str(ipaddress.IPv6Address(target_ip)),
    }
    _normalize_identity(source_norm, target_norm)
    if source is not None and _normalize_identity(source, target_norm)[::2] != (source_mac, source_ip):
        raise PacketSetError("packet_set_source_binding_mismatch")
    if target is not None and _normalize_identity(source_norm, target)[1::2] != (target_mac, target_ip):
        raise PacketSetError("packet_set_destination_binding_mismatch")

    return {
        "wire_nonce": nonce,
        "wire_nonce_hex": nonce_hex,
        "wifi_sequence_base": wifi_sequence_base,
        "awdl_sequence_base": awdl_sequence_base,
        "source_mac": source_mac,
        "target_mac": target_mac,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "source": source_norm,
        "destination_awdl0": target_norm,
    }


def _validate_mpdu(mpdu: bytes, values: dict, templates: list[bytes], ordinal: int) -> dict:
    if not isinstance(mpdu, bytes) or len(mpdu) != MPDU_LEN:
        raise PacketSetError("mpdu_length_invalid")
    wifi_sequence = (values["wifi_sequence_base"] + ordinal) & 0x0FFF
    awdl_sequence = (values["awdl_sequence_base"] + ordinal) & 0xFFFF
    expected_sc = wifi_sequence << 4
    sequence_control = struct.unpack_from("<H", mpdu, 22)[0]
    if sequence_control & 0x000F:
        raise PacketSetError("fragment_number_must_be_zero")
    if sequence_control != expected_sc:
        raise PacketSetError("wifi_sequence_control_mismatch")
    if struct.unpack_from("<H", mpdu, 34)[0] != awdl_sequence:
        raise PacketSetError("awdl_sequence_mismatch")
    if mpdu[88:96] != values["wire_nonce"]:
        raise PacketSetError("wire_nonce_payload_mismatch")
    if mpdu[48:64] != values["source_ip"] or mpdu[64:80] != values["target_ip"]:
        raise PacketSetError("ipv6_address_binding_mismatch")
    if not _checksum_valid(mpdu, values["source_ip"], values["target_ip"]):
        raise PacketSetError("udp_checksum_invalid")

    expected = _build_mpdu(
        templates[ordinal], values["source_mac"], values["target_mac"],
        values["source_ip"], values["target_ip"], values["wire_nonce"],
        wifi_sequence, awdl_sequence)
    if mpdu != expected:
        raise PacketSetError("frame_not_exact_bound_template")
    return {
        "ordinal": ordinal,
        "payload_hex": mpdu[88:96].hex(),
        "sequence_control": sequence_control,
        "wifi_sequence": wifi_sequence,
        "awdl_sequence": awdl_sequence,
        "mpdu_sha256": _sha(mpdu),
        "packet_sha256": _sha(RADIOTAP_NOSEQNO_ONLY + mpdu),
        "udp_checksum_valid": True,
    }


def encode_packet_set(source: dict, target: dict, experiment_id: str,
                      *, wire_nonce_hex: str, wifi_sequence_base: int,
                      awdl_sequence_base: int) -> tuple[bytes, dict]:
    """Create a 536-byte v2 packet set. It never sends or arms anything."""
    if not isinstance(experiment_id, str) or re.fullmatch(
            r"[A-Za-z0-9_.-]{1,96}", experiment_id) is None:
        raise PacketSetError("experiment_id_invalid")
    nonce = _wire_nonce(wire_nonce_hex)
    wifi_base = _sequence_base(wifi_sequence_base, 0x0FFF, "wifi_sequence_base")
    awdl_base = _sequence_base(awdl_sequence_base, 0xFFFF, "awdl_sequence_base")
    source_mac, target_mac, source_ip, target_ip = _normalize_identity(source, target)
    template_meta, templates = _test104._load_templates()

    header = bytearray(HEADER_LEN)
    header[0:8] = PACKET_SET_MAGIC
    header[8] = 2
    header[9] = PACKET_COUNT
    struct.pack_into(">HHHHH", header, 10,
                     INTERVAL_MS, BUDGET_MS, RADIOTAP_LEN, MPDU_LEN, PACKET_LEN)
    struct.pack_into(">HH", header, 20, wifi_base, awdl_base)
    header[24:30] = source_mac
    header[30:36] = target_mac
    header[36:52] = source_ip
    header[52:68] = target_ip
    header[68:100] = bytes.fromhex(TEMPLATE_SHA256)
    # bytes 100..103 remain reserved; bytes 104..111 identify this wire run.
    header[104:112] = nonce

    packets: list[bytes] = []
    rows: list[dict] = []
    for ordinal, template in enumerate(templates):
        wifi_sequence = (wifi_base + ordinal) & 0x0FFF
        awdl_sequence = (awdl_base + ordinal) & 0xFFFF
        mpdu = _build_mpdu(template, source_mac, target_mac, source_ip, target_ip,
                           nonce, wifi_sequence, awdl_sequence)
        packet = RADIOTAP_NOSEQNO_ONLY + mpdu
        row = _validate_mpdu(mpdu, {
            "wire_nonce": nonce,
            "wifi_sequence_base": wifi_base,
            "awdl_sequence_base": awdl_base,
            "source_mac": source_mac,
            "target_mac": target_mac,
            "source_ip": source_ip,
            "target_ip": target_ip,
        }, templates, ordinal)
        row.update({"radiotap_length": RADIOTAP_LEN,
                    "mpdu_length": MPDU_LEN,
                    "packet_length": PACKET_LEN})
        packets.append(packet)
        rows.append(row)

    packet_set = bytes(header) + b"".join(packets)
    if len(packet_set) != PACKET_SET_LEN:
        raise PacketSetError("packet_set_internal_length_error")
    decoded = validate_packet_set(packet_set, source, target,
                                  expected_wire_nonce_hex=wire_nonce_hex)
    manifest = {
        "schema": PACKET_SET_SCHEMA,
        "experiment_id": experiment_id,
        "dry_run": True,
        "transmission_capability": False,
        "frame_count": PACKET_COUNT,
        "interval_ms": INTERVAL_MS,
        "send_budget_ms": BUDGET_MS,
        "wire_nonce_hex": wire_nonce_hex,
        "wifi_sequence_base": wifi_base,
        "awdl_sequence_base": awdl_base,
        "radiotap_flags": "NOSEQNO only; NOACK bit clear",
        "ack_policy_request": "normal_unicast_ack_requested_by_radiotap_absence_of_NOACK",
        "hardware_ack_or_raw_txs": "unknown",
        "identities": {
            "source": source,
            "destination_awdl0": target,
            "router_source_is_test_injector": True,
            "destination_identity_verified_at_capture": True,
            "destination_current_at_run_revalidated": False,
        },
        "template": {
            "source_commit": template_meta["source"].get("commit"),
            "source_file_sha256": TEMPLATE_SHA256,
            "fcs_included": False,
        },
        "packet_set_length": len(packet_set),
        "packet_set_sha256": _sha(packet_set),
        "frames": rows,
        "evidence": {
            "local_send_calls": 0,
            "rf_transmission_proven": False,
            "raw_txs": "unknown",
            "mac_ack": "unknown",
            "peer_receipt": "unknown",
            "native_awdl0_ingress": "unknown",
            "airdrop": "unknown",
        },
        "validation": {
            "schema": decoded["schema"],
            "wire_identity_unique_per_packet_set": True,
            "frame_count": len(decoded["frames"]),
        },
    }
    return packet_set, manifest


def decode_packet_set(raw: bytes, source: dict | None = None,
                      target: dict | None = None, *,
                      expected_wire_nonce_hex: str | None = None) -> dict:
    """Validate and decode a v2 packet set without causing side effects."""
    values = _header_values(raw, source, target, expected_wire_nonce_hex)
    template_meta, templates = _test104._load_templates()
    frames = []
    for ordinal in range(PACKET_COUNT):
        offset = HEADER_LEN + ordinal * PACKET_LEN
        packet = raw[offset:offset + PACKET_LEN]
        if packet[:RADIOTAP_LEN] != RADIOTAP_NOSEQNO_ONLY:
            raise PacketSetError("radiotap_must_request_noseqno_without_noack")
        row = _validate_mpdu(packet[RADIOTAP_LEN:], values, templates, ordinal)
        row.update({"radiotap_length": RADIOTAP_LEN,
                    "mpdu_length": MPDU_LEN,
                    "packet_length": PACKET_LEN})
        frames.append(row)
    return {
        "schema": PACKET_SET_SCHEMA,
        "valid": True,
        "frame_count": PACKET_COUNT,
        "interval_ms": INTERVAL_MS,
        "send_budget_ms": BUDGET_MS,
        "source": values["source"],
        "destination_awdl0": values["destination_awdl0"],
        "wire_nonce_hex": values["wire_nonce_hex"],
        "wifi_sequence_base": values["wifi_sequence_base"],
        "awdl_sequence_base": values["awdl_sequence_base"],
        "template_source_commit": template_meta["source"].get("commit"),
        "template_sha256": TEMPLATE_SHA256,
        "packet_set_sha256": _sha(raw),
        "frames": frames,
        "rf_proven": False,
        "raw_txs": "unknown",
        "mac_ack": "unknown",
    }


def validate_packet_set(raw: bytes, source: dict | None = None,
                        target: dict | None = None, *,
                        expected_wire_nonce_hex: str | None = None) -> dict:
    return decode_packet_set(raw, source, target,
                             expected_wire_nonce_hex=expected_wire_nonce_hex)


def match_frame(mpdu: bytes, packet_set: bytes) -> dict | None:
    """Map a captured MPDU to one frame by nonce + both sequence spaces.

    Header fields such as duration may legitimately be rewritten downstream,
    so a non-exact match is returned as identity-only and never represented as
    an exact template match. Radiotap must be removed by the caller.
    """
    if not isinstance(mpdu, bytes) or len(mpdu) != MPDU_LEN:
        return None
    decoded = decode_packet_set(packet_set)
    if mpdu[88:96].hex() != decoded["wire_nonce_hex"]:
        return None
    sequence_control = struct.unpack_from("<H", mpdu, 22)[0]
    if sequence_control & 0x000F:
        return None
    wifi_sequence = sequence_control >> 4
    awdl_sequence = struct.unpack_from("<H", mpdu, 34)[0]
    if (mpdu[4:10] != bytes.fromhex(decoded["destination_awdl0"]["mac"].replace(":", "")) or
            mpdu[10:16] != bytes.fromhex(decoded["source"]["mac"].replace(":", "")) or
            mpdu[48:64] != ipaddress.IPv6Address(decoded["source"]["ipv6_link_local"]).packed or
            mpdu[64:80] != ipaddress.IPv6Address(decoded["destination_awdl0"]["ipv6_link_local"]).packed):
        return None
    matches = [row for row in decoded["frames"]
               if row["wifi_sequence"] == wifi_sequence and
               row["awdl_sequence"] == awdl_sequence]
    if not matches:
        return None
    if len(matches) != 1:
        raise PacketSetError("captured_frame_identity_ambiguous")
    row = matches[0]
    offset = HEADER_LEN + row["ordinal"] * PACKET_LEN + RADIOTAP_LEN
    expected_mpdu = packet_set[offset:offset + MPDU_LEN]
    return {
        "ordinal": row["ordinal"],
        "wire_nonce_hex": decoded["wire_nonce_hex"],
        "sequence_control": sequence_control,
        "wifi_sequence": wifi_sequence,
        "awdl_sequence": awdl_sequence,
        "identity_match": True,
        "exact_mpdu_match": mpdu == expected_mpdu,
    }


__all__ = [
    "PACKET_SET_MAGIC", "PACKET_SET_SCHEMA", "PACKET_COUNT", "INTERVAL_MS",
    "BUDGET_MS", "RADIOTAP_LEN", "MPDU_LEN", "PACKET_LEN", "HEADER_LEN",
    "PACKET_SET_LEN", "TEMPLATE_SHA256", "PacketSetError", "encode_packet_set",
    "decode_packet_set", "validate_packet_set", "match_frame",
]
