#!/usr/bin/env python3
"""Build and validate an offline Test104 unicast packet set.

This module only handles bytes and read-only identity receipts. It has no
network, router, socket, sleep, or transmit code.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import sys
from typing import Any

TOOL_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = TOOL_DIR / "frozen-template-test104.json"
TEMPLATE_SHA256 = "b7c234200d117ca17d5eea349bb322d30f0ffdb1f0f323e36d08e2428cd5ee61"
PACKET_SET_MAGIC = b"T104PKT1"
PACKET_SET_SCHEMA = "test104-unicast-packet-set/v1"
PACKET_COUNT = 4
INTERVAL_MS = 10
BUDGET_MS = 40
RADIOTAP_LEN = 10
MPDU_LEN = 96
PACKET_LEN = RADIOTAP_LEN + MPDU_LEN
HEADER_LEN = 104
PACKET_SET_LEN = HEADER_LEN + PACKET_COUNT * PACKET_LEN
RADIOTAP_NOSEQNO_ONLY = bytes.fromhex("00000a00008000001000")
PAYLOAD = b"T086RX01"


class PacketSetError(ValueError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mac(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
        raise PacketSetError(label + "_mac_invalid")
    raw = bytes.fromhex(value.replace(":", ""))
    if raw == bytes(6) or raw[0] & 1:
        raise PacketSetError(label + "_mac_not_unicast")
    return raw


def _ipv6ll(value: Any, label: str) -> tuple[bytes, str]:
    if not isinstance(value, str) or not value or value.count("%") > 1:
        raise PacketSetError(label + "_ipv6_invalid")
    address, _, zone = value.partition("%")
    try:
        parsed = ipaddress.IPv6Address(address)
    except ipaddress.AddressValueError as error:
        raise PacketSetError(label + "_ipv6_invalid") from error
    if not parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
        raise PacketSetError(label + "_ipv6_not_link_local")
    if zone and zone not in ("awdl0", "wlan7") and not re.fullmatch(r"[0-9]{1,10}", zone):
        raise PacketSetError(label + "_ipv6_zone_invalid")
    return parsed.packed, zone


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{part:02x}" for part in raw)


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _udp_checksum(source_ip: bytes, destination_ip: bytes, udp: bytes) -> int:
    pseudo = source_ip + destination_ip + struct.pack("!I3xB", len(udp), 17)
    return _checksum(pseudo + udp) or 0xFFFF


def _load_templates() -> tuple[dict, list[bytes]]:
    if TEMPLATE_PATH.is_symlink() or not TEMPLATE_PATH.is_file():
        raise PacketSetError("frozen_template_unavailable")
    raw = TEMPLATE_PATH.read_bytes()
    if _sha(raw) != TEMPLATE_SHA256:
        raise PacketSetError("frozen_template_hash_mismatch")
    try:
        record = json.loads(raw)
        templates = [bytes.fromhex(item) for item in record["baseline_mpdu_hex"]]
    except (ValueError, KeyError, TypeError) as error:
        raise PacketSetError("frozen_template_malformed") from error
    if (record.get("schema") != "awdl-unicast-offline-frozen-template/v1" or
            len(templates) != PACKET_COUNT or
            any(len(frame) != MPDU_LEN for frame in templates) or
            record.get("offsets") != {"ipv6": 40, "udp": 80, "udp_payload": 88}):
        raise PacketSetError("frozen_template_contract_mismatch")
    if [_sha(frame) for frame in templates] != record.get("baseline_mpdu_sha256"):
        raise PacketSetError("frozen_template_frame_hash_mismatch")
    return record, templates


def parse_router_identity_receipt(record: Any, receipt_sha256: str | None = None) -> dict:
    """Parse the existing read-only `iw dev` + `ip -6 addr` router receipt."""
    if not isinstance(record, dict) or type(record.get("rc")) is not int or record["rc"] != 0:
        raise PacketSetError("router_identity_receipt_failed")
    stdout = record.get("stdout")
    scope = record.get("scope")
    if not isinstance(stdout, str) or not isinstance(scope, str) or "read only" not in scope.lower():
        raise PacketSetError("router_identity_receipt_scope_invalid")
    lines = stdout.splitlines()
    blocks = []
    current = None
    for line in lines:
        match = re.match(r"^\s*Interface\s+([A-Za-z0-9_.-]+)\s*$", line)
        if match:
            if current:
                blocks.append(current)
            current = {"name": match.group(1), "lines": [line]}
        elif current is not None:
            if re.match(r"^phy#\d+\s*$", line):
                blocks.append(current)
                current = None
            else:
                current["lines"].append(line)
    if current:
        blocks.append(current)
    matches = [item for item in blocks if item["name"] == "wlan7"]
    if len(matches) != 1:
        raise PacketSetError("router_source_interface_not_unique")
    block = "\n".join(matches[0]["lines"])
    ifindex_match = re.search(r"(?m)^\s*ifindex\s+(\d+)\s*$", block)
    mac_match = re.search(r"(?m)^\s*addr\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*$", block)
    channel_match = re.search(r"(?m)^\s*channel\s+149\s+\(5745 MHz\),\s+width:\s*80 MHz", block)
    type_match = re.search(r"(?m)^\s*type\s+AP\s*$", block)
    if not all((ifindex_match, mac_match, channel_match, type_match)):
        raise PacketSetError("router_source_interface_contract_mismatch")
    iplink_match = re.search(r"(?m)^\s*(\d+):\s+wlan7:\s+<([^>]*)>", stdout)
    if not iplink_match or int(iplink_match.group(1)) != int(ifindex_match.group(1)):
        raise PacketSetError("router_source_ifindex_mismatch")
    flags = set(iplink_match.group(2).split(","))
    if "UP" not in flags or "LOWER_UP" not in flags:
        raise PacketSetError("router_source_interface_not_up")
    # Parse the link-local address only from the wlan7 `ip addr` section.
    interface_sections = re.split(r"(?m)^\s*\d+:\s+[^:]+:", stdout)
    interface_headers = re.findall(r"(?m)^\s*(\d+):\s+([^:]+):", stdout)
    wlan7_ll = []
    for index, header in enumerate(interface_headers):
        if header[1] != "wlan7":
            continue
        section = interface_sections[index + 1] if index + 1 < len(interface_sections) else ""
        for address in re.findall(r"(?m)^\s*inet6\s+([^\s/]+)/\d+\s+scope\s+link\b", section):
            wlan7_ll.append(address.split("%", 1)[0])
    if len(wlan7_ll) != 1:
        raise PacketSetError("router_source_link_local_not_unique")
    source_mac = _mac(mac_match.group(1), "router_source")
    marker = re.search(
        r"(?m)^IFACE=wlan7\s*\n((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*$",
        stdout)
    if marker is None or _mac(marker.group(1), "router_source_readback") != source_mac:
        raise PacketSetError("router_source_mac_readback_mismatch")
    source_ip, _ = _ipv6ll(wlan7_ll[0], "router_source")
    captured_at = record.get("at")
    if not isinstance(captured_at, str):
        raise PacketSetError("router_identity_timestamp_missing")
    try:
        parsed_at = dt.datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise PacketSetError("router_identity_timestamp_invalid") from error
    if parsed_at.tzinfo is None:
        raise PacketSetError("router_identity_timestamp_timezone_missing")
    if receipt_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", receipt_sha256):
        raise PacketSetError("router_receipt_sha_invalid")
    canonical_sha = _sha(json.dumps(
        record, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8"))
    return {
        "interface": "wlan7",
        "ifindex": int(ifindex_match.group(1)),
        "mac": _format_mac(source_mac),
        "ipv6_link_local": str(ipaddress.IPv6Address(source_ip)),
        "captured_at": captured_at,
        "source_receipt_sha256": receipt_sha256 or canonical_sha,
        "channel": 149,
        "width_mhz": 80,
    }


def validate_target_identity(record: Any, expected_boot_epoch: int | None = None,
                             expected_uuid: str | None = None,
                             *, expected_candidate: str = "25G332-Test104",
                             expected_binary_sha256: str | None = None,
                             expected_build_receipt_sha256: str | None = None,
                             expected_deployment_receipt_sha256: str | None = None) -> dict:
    if not isinstance(record, dict):
        raise PacketSetError("target_identity_not_object")
    if (record.get("schema") != "test104-target-identity/v1" or
            record.get("status") != "readback_verified" or
            record.get("interface") != "awdl0" or
            record.get("source") != "live_ifconfig_ifindex_kmutil"):
        raise PacketSetError("target_identity_not_live_verified")
    boot = record.get("boot_epoch")
    if type(boot) is not int or boot <= 0 or (
            expected_boot_epoch is not None and boot != expected_boot_epoch):
        raise PacketSetError("target_identity_boot_mismatch")
    minimum_boot = record.get("minimum_boot_epoch_exclusive")
    if (type(minimum_boot) is not int or minimum_boot <= 0 or boot <= minimum_boot):
        raise PacketSetError("target_identity_not_from_postdeployment_boot")
    candidate_uuid = record.get("candidate_uuid")
    if (not isinstance(candidate_uuid, str) or
            not re.fullmatch(r"[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}", candidate_uuid) or
            (expected_uuid is not None and candidate_uuid != expected_uuid)):
        raise PacketSetError("target_identity_uuid_mismatch")
    if record.get("candidate") != expected_candidate:
        raise PacketSetError("target_identity_candidate_mismatch")
    sha_fields = ("candidate_binary_sha256", "build_receipt_sha256",
                  "deployment_receipt_sha256", "evidence_sha256")
    for field in sha_fields:
        if not isinstance(record.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", record[field]):
            raise PacketSetError("target_identity_hash_invalid_" + field)
    if ((expected_binary_sha256 is not None and
         record["candidate_binary_sha256"] != expected_binary_sha256) or
            (expected_build_receipt_sha256 is not None and
             record["build_receipt_sha256"] != expected_build_receipt_sha256) or
            (expected_deployment_receipt_sha256 is not None and
             record["deployment_receipt_sha256"] != expected_deployment_receipt_sha256)):
        raise PacketSetError("target_identity_receipt_binding_mismatch")
    if type(record.get("ifindex")) is not int or record["ifindex"] <= 0:
        raise PacketSetError("target_identity_ifindex_invalid")
    mac = _mac(record.get("mac"), "target_awdl0")
    ip, zone = _ipv6ll(record.get("ipv6_link_local"), "target_awdl0")
    if zone not in ("", "awdl0", str(record["ifindex"])):
        raise PacketSetError("target_identity_zone_mismatch")
    if record.get("interface_up") is not True:
        raise PacketSetError("target_awdl0_not_up")
    captured_at = record.get("captured_at")
    if not isinstance(captured_at, str):
        raise PacketSetError("target_identity_timestamp_missing")
    try:
        parsed_at = dt.datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise PacketSetError("target_identity_timestamp_invalid") from error
    if parsed_at.tzinfo is None:
        raise PacketSetError("target_identity_timestamp_timezone_missing")
    receipt_sha = record.get("identity_receipt_sha256")
    if not isinstance(receipt_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_sha):
        raise PacketSetError("target_identity_receipt_hash_invalid")
    canonical = dict(record)
    canonical.pop("identity_receipt_sha256", None)
    expected_receipt_sha = _sha(json.dumps(
        canonical, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8"))
    if receipt_sha != expected_receipt_sha:
        raise PacketSetError("target_identity_receipt_hash_mismatch")
    return {
        "interface": "awdl0",
        "ifindex": record["ifindex"],
        "mac": _format_mac(mac),
        "ipv6_link_local": str(ipaddress.IPv6Address(ip)),
        "captured_at": captured_at,
        "boot_epoch": boot,
        "candidate_uuid": candidate_uuid,
        "identity_receipt_sha256": record.get("identity_receipt_sha256"),
    }


def _build_mpdu(template: bytes, source_mac: bytes, target_mac: bytes,
                source_ip: bytes, target_ip: bytes) -> bytes:
    frame = bytearray(template)
    frame[4:10] = target_mac
    frame[10:16] = source_mac
    frame[48:64] = source_ip
    frame[64:80] = target_ip
    frame[86:88] = b"\x00\x00"
    frame[86:88] = struct.pack("!H", _udp_checksum(
        source_ip, target_ip, bytes(frame[80:96])))
    return bytes(frame)


def encode_packet_set(source: dict, target: dict,
                      experiment_id: str = "test104-unicast-offline") -> tuple[bytes, dict]:
    """Generate a fixed 528-byte packet set; no send capability is provided."""
    if not isinstance(experiment_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,96}", experiment_id):
        raise PacketSetError("experiment_id_invalid")
    smac = _mac(source.get("mac"), "router_source")
    sip, _ = _ipv6ll(source.get("ipv6_link_local"), "router_source")
    dmac = _mac(target.get("mac"), "target_awdl0")
    dip, _ = _ipv6ll(target.get("ipv6_link_local"), "target_awdl0")
    if smac == dmac or sip == dip:
        raise PacketSetError("source_destination_identity_collision")
    template_meta, templates = _load_templates()
    packet_rows = []
    packet_bytes = []
    for ordinal, template in enumerate(templates):
        mpdu = _build_mpdu(template, smac, dmac, sip, dip)
        packet = RADIOTAP_NOSEQNO_ONLY + mpdu
        validate_packet(packet, source, target, ordinal)
        packet_bytes.append(packet)
        packet_rows.append({
            "ordinal": ordinal,
            "radiotap_length": RADIOTAP_LEN,
            "mpdu_length": MPDU_LEN,
            "packet_length": PACKET_LEN,
            "mpdu_sha256": _sha(mpdu),
            "packet_sha256": _sha(packet),
            "udp_checksum_valid": True,
        })
    header = bytearray(HEADER_LEN)
    header[0:8] = PACKET_SET_MAGIC
    header[8] = 1
    header[9] = PACKET_COUNT
    struct.pack_into(">HHHHH", header, 10,
                     INTERVAL_MS, BUDGET_MS, RADIOTAP_LEN, MPDU_LEN, PACKET_LEN)
    # bytes 20..21 are reserved and must remain zero.
    header[24:30] = smac
    header[30:36] = dmac
    header[36:52] = sip
    header[52:68] = dip
    header[68:100] = bytes.fromhex(TEMPLATE_SHA256)
    # bytes 100..103 are reserved and must remain zero.
    packet_set = bytes(header) + b"".join(packet_bytes)
    if len(packet_set) != PACKET_SET_LEN:
        raise PacketSetError("packet_set_internal_length_error")
    # Validate the exact serialized form before returning it.
    validate_packet_set(packet_set, source, target)
    manifest = {
        "schema": PACKET_SET_SCHEMA,
        "experiment_id": experiment_id,
        "dry_run": True,
        "transmission_capability": False,
        "frame_count": PACKET_COUNT,
        "interval_ms": INTERVAL_MS,
        "send_budget_ms": BUDGET_MS,
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
        "frames": packet_rows,
        "evidence": {
            "local_send_calls": 0,
            "rf_transmission_proven": False,
            "raw_txs": "unknown",
            "mac_ack": "unknown",
            "peer_receipt": "unknown",
            "native_awdl0_ingress": "unknown",
            "airdrop": "unknown",
        },
        "notes": [
            "The source is the observed OpenWrt wlan7 test injector, not the Intel receiver.",
            "The destination identity was verified at capture time; runtime must recheck boot, UUID and freshness.",
            "NOACK is not requested; an ACK policy request does not prove firmware TXS or a received ACK.",
            "A future native data/peer receipt can be positive independently of raw TXS availability.",
            "This packet set is generated offline; packet hashes and planned timing do not prove RF.",
        ],
    }
    return packet_set, manifest


def validate_packet(packet: bytes, source: dict, target: dict,
                    ordinal: int | None = None) -> dict:
    if not isinstance(packet, bytes) or len(packet) != PACKET_LEN:
        raise PacketSetError("packet_length_invalid")
    if packet[:RADIOTAP_LEN] != RADIOTAP_NOSEQNO_ONLY:
        raise PacketSetError("radiotap_must_request_noseqno_without_noack")
    mpdu = packet[RADIOTAP_LEN:]
    src_mac = _mac(source.get("mac"), "router_source")
    dst_mac = _mac(target.get("mac"), "target_awdl0")
    src_ip, _ = _ipv6ll(source.get("ipv6_link_local"), "router_source")
    dst_ip, _ = _ipv6ll(target.get("ipv6_link_local"), "target_awdl0")
    if mpdu[0:4] != bytes.fromhex("08000000"):
        raise PacketSetError("ieee80211_data_header_mismatch")
    if mpdu[4:10] != dst_mac or mpdu[10:16] != src_mac:
        raise PacketSetError("ieee80211_address_binding_mismatch")
    _, templates = _load_templates()
    matches = []
    for index, template in enumerate(templates):
        if _build_mpdu(template, src_mac, dst_mac, src_ip, dst_ip) == mpdu:
            matches.append(index)
    if len(matches) != 1 or (ordinal is not None and matches[0] != ordinal):
        raise PacketSetError("frame_not_exact_bound_template")
    if mpdu[48:64] != src_ip or mpdu[64:80] != dst_ip:
        raise PacketSetError("ipv6_address_binding_mismatch")
    if mpdu[88:96] != PAYLOAD:
        raise PacketSetError("payload_marker_mismatch")
    udp = mpdu[80:96]
    if struct.unpack_from("!H", udp, 6)[0] != _udp_checksum(src_ip, dst_ip, udp[:6] + b"\x00\x00" + udp[8:]):
        raise PacketSetError("udp_checksum_mismatch")
    if _checksum(src_ip + dst_ip + struct.pack("!I3xB", len(udp), 17) + udp) != 0:
        raise PacketSetError("udp_checksum_invalid")
    return {"valid": True, "ordinal": matches[0], "packet_sha256": _sha(packet)}


def validate_packet_set(raw: bytes, source: dict | None = None,
                        target: dict | None = None) -> dict:
    if not isinstance(raw, bytes) or len(raw) != PACKET_SET_LEN:
        raise PacketSetError("packet_set_length_invalid")
    header = raw[:HEADER_LEN]
    if (header[:8] != PACKET_SET_MAGIC or header[8] != 1 or
            header[9] != PACKET_COUNT or
            struct.unpack_from(">HHHHH", header, 10) !=
                (INTERVAL_MS, BUDGET_MS, RADIOTAP_LEN, MPDU_LEN, PACKET_LEN) or
            header[20:24] != b"\x00" * 4 or
            header[68:100] != bytes.fromhex(TEMPLATE_SHA256) or
            header[100:104] != b"\x00" * 4):
        raise PacketSetError("packet_set_header_invalid")
    src = {"mac": _format_mac(header[24:30]),
           "ipv6_link_local": str(ipaddress.IPv6Address(header[36:52]))}
    dst = {"mac": _format_mac(header[30:36]),
           "ipv6_link_local": str(ipaddress.IPv6Address(header[52:68]))}
    if source is not None and (_mac(source.get("mac"), "router_source") != header[24:30] or
                               _ipv6ll(source.get("ipv6_link_local"), "router_source")[0] != header[36:52]):
        raise PacketSetError("packet_set_source_binding_mismatch")
    if target is not None and (_mac(target.get("mac"), "target_awdl0") != header[30:36] or
                               _ipv6ll(target.get("ipv6_link_local"), "target_awdl0")[0] != header[52:68]):
        raise PacketSetError("packet_set_destination_binding_mismatch")
    rows = []
    for ordinal in range(PACKET_COUNT):
        start = HEADER_LEN + ordinal * PACKET_LEN
        rows.append(validate_packet(raw[start:start + PACKET_LEN], src, dst, ordinal))
    return {
        "schema": PACKET_SET_SCHEMA,
        "valid": True,
        "frame_count": PACKET_COUNT,
        "interval_ms": INTERVAL_MS,
        "budget_ms": BUDGET_MS,
        "source": src,
        "destination_awdl0": dst,
        "packet_set_sha256": _sha(raw),
        "frames": rows,
        "rf_proven": False,
        "raw_txs": "unknown",
    }


def _atomic_private_write(path: Path, raw: bytes) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise PacketSetError("refuse_overwrite_output")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
        raise PacketSetError("unsafe_output_directory_mode")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build offline packet set from verified receipts")
    build.add_argument("--router-receipt", type=Path, required=True)
    build.add_argument("--target-identity", type=Path, required=True)
    build.add_argument("--expected-boot", type=int, required=True)
    build.add_argument("--expected-uuid", required=True)
    build.add_argument("--experiment-id", required=True)
    build.add_argument("--packet-set-out", type=Path, required=True)
    build.add_argument("--manifest-out", type=Path, required=True)
    validate = sub.add_parser("validate", help="offline validate an existing packet set")
    validate.add_argument("--packet-set", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            result = validate_packet_set(args.packet_set.read_bytes())
        else:
            router_raw = args.router_receipt.read_bytes()
            router_record = json.loads(router_raw)
            target_record = json.loads(args.target_identity.read_text(encoding="utf-8"))
            source = parse_router_identity_receipt(router_record, _sha(router_raw))
            target = validate_target_identity(target_record,
                                              expected_boot_epoch=args.expected_boot,
                                              expected_uuid=args.expected_uuid)
            raw, manifest = encode_packet_set(source, target, args.experiment_id)
            _atomic_private_write(args.packet_set_out, raw)
            manifest_bytes = json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                                        indent=2).encode("utf-8") + b"\n"
            _atomic_private_write(args.manifest_out, manifest_bytes)
            result = {"packet_set_path": str(args.packet_set_out),
                      "packet_set_sha256": _sha(raw),
                      "manifest_path": str(args.manifest_out),
                      "manifest_sha256": _sha(manifest_bytes),
                      "transmission_capability": False,
                      "rf_transmission_proven": False}
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
