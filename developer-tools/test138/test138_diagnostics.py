#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Decode Test138 local TX receipts and the final captured AirDrop QM MPDU."""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Any, Mapping


BUILD_ID = "25G416-Test138"
MPDU_OFFSET = 112 + 64
EXPECTED_MPDU_LENGTH = 125
EXPECTED_IPV6_LENGTH = 85
EXPECTED_UDP_LENGTH = 45
EXPECTED_DNS_LENGTH = 37
EXPECTED_QUESTION = (
    b"\x08_airdrop\x04_tcp\x05local\x00" +
    struct.pack("!HH", 12, 1)
)

_BASE_PATH = Path(__file__).resolve().parents[1] / "test137" / "test137_diagnostics.py"
_BASE_SPEC = importlib.util.spec_from_file_location(
    "test137_diagnostics_for_test138", _BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("Test137 receipt decoder unavailable")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)
_D136 = _BASE._BASE


def _number(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _profile(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        return {"valid": False, "problems": ["receipt_not_object"]}
    problems: list[str] = []
    if receipt.get("expected_build") != BUILD_ID:
        problems.append("expected_build_mismatch")
    uuid = receipt.get("expected_uuid")
    if not isinstance(uuid, str) or receipt.get("loaded_uuid_matches_after") is not True:
        problems.append("loaded_uuid_identity_unconfirmed")
    loaded = receipt.get("loaded_uuids_after")
    if (not isinstance(uuid, str) or not isinstance(loaded, list) or
            loaded != [uuid]):
        problems.append("loaded_uuid_list_mismatch")
    snapshots = {name: receipt.get(name) for name in ("preflight", "before_arm", "final")}
    required = {
        "NativeTestBuild": BUILD_ID,
        "NativeAwdlDiscoveryExperimentEnabled": True,
        "NativeAwdlDiscoveryMifCurrentSlotEnabled": True,
        "NativeAwdlDiscoveryRxInputEnabled": True,
        "NativeAwdlDiscoveryCurrentAwFallbackEnabled": True,
        "NativeAwdlQmNoKnownAnswerCompiled": True,
        "NativeAwdlQmNormalPriorityCompiled": False,
    }
    for snapshot_name in ("preflight", "before_arm", "final"):
        values = snapshots[snapshot_name]
        if not isinstance(values, Mapping):
            problems.append(snapshot_name + "_snapshot_missing")
            continue
        for key, expected in required.items():
            actual = values.get(key)
            matched = actual is expected if isinstance(expected, bool) else actual == expected
            if not matched:
                problems.append(snapshot_name + "_" + key + "_mismatch")
    return {
        "valid": not problems,
        "expected_build": BUILD_ID,
        "receipt_build": receipt.get("expected_build"),
        "expected_uuid_present": isinstance(uuid, str),
        "current_aw_fallback_flag": True,
        "no_known_answer_compiled": True,
        "normal_priority_compiled": False,
        "problems": problems,
    }


def _checksum_valid(ipv6: bytes, udp: bytes) -> bool:
    if len(ipv6) < 40 or len(udp) < 8 or len(udp) > 0xFFFFFFFF:
        return False
    if struct.unpack_from("!H", udp, 6)[0] == 0:
        return False
    pseudo = ipv6[8:40] + struct.pack("!I3xB", len(udp), 17) + udp
    if len(pseudo) & 1:
        pseudo += b"\0"
    total = sum(struct.unpack(f"!{len(pseudo) // 2}H", pseudo))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def _ipv6_multicast_mac(address: bytes) -> bytes:
    return b"\x33\x33" + address[-4:]


def _source_eui64_matches(ipv6_source: bytes, mac: bytes) -> bool:
    if len(ipv6_source) != 16 or len(mac) != 6:
        return False
    expected = bytes((mac[0] ^ 0x02,)) + mac[1:3] + b"\xff\xfe" + mac[3:]
    return ipv6_source[8:] == expected


def decode_final_qm_mpdu(mpdu: bytes) -> dict[str, Any]:
    """Validate the exact final MPDU wire shape without returning addresses."""
    checks: dict[str, bool] = {}
    errors: list[str] = []

    checks["exact_mpdu_length"] = len(mpdu) == EXPECTED_MPDU_LENGTH
    if not checks["exact_mpdu_length"]:
        errors.append("mpdu_length_mismatch")
    if len(mpdu) < 40:
        return {"valid": False, "status": "unknown_mpdu_truncated",
                "checks": checks, "errors": errors + ["mpdu_header_truncated"]}

    frame_control = struct.unpack_from("<H", mpdu, 0)[0]
    sequence_control = struct.unpack_from("<H", mpdu, 22)[0]
    checks["data_frame_control"] = frame_control == 0x0008
    checks["no_ds_protected_or_fragment_bits"] = not (frame_control & 0x4700)
    checks["awdl_bssid"] = mpdu[16:22] == bytes.fromhex("002500ff9473")
    checks["snap_awdl_ipv6_encapsulation"] = (
        mpdu[24:34] == bytes.fromhex("aaaa030017f208000304") and
        mpdu[36:40] == bytes.fromhex("000086dd"))
    if not checks["data_frame_control"]:
        errors.append("frame_control_not_plain_data")
    if not checks["no_ds_protected_or_fragment_bits"]:
        errors.append("unsupported_frame_control_bits")
    if not checks["awdl_bssid"]:
        errors.append("awdl_bssid_mismatch")
    if not checks["snap_awdl_ipv6_encapsulation"]:
        errors.append("snap_awdl_or_ethertype_mismatch")

    ipv6 = mpdu[40:]
    checks["ipv6_exact_length"] = len(ipv6) == EXPECTED_IPV6_LENGTH
    checks["ipv6_version"] = bool(ipv6) and ipv6[0] >> 4 == 6
    if len(ipv6) < 40:
        errors.append("ipv6_header_truncated")
        return {"valid": False, "status": "unknown_mpdu_invalid",
                "checks": checks, "errors": errors}
    payload_length = struct.unpack_from("!H", ipv6, 4)[0]
    checks["ipv6_payload_length"] = len(ipv6) == 40 + payload_length
    checks["ipv6_direct_udp"] = ipv6[6] == 17
    checks["ipv6_hop_limit_255"] = ipv6[7] == 255
    source = ipv6[8:24]
    destination = ipv6[24:40]
    checks["ipv6_link_local_source"] = source[0] == 0xFE and source[1] & 0xC0 == 0x80
    checks["ipv6_ff02_mdns_destination"] = destination == bytes.fromhex(
        "ff0200000000000000000000000000fb")
    checks["multicast_mac_mapping"] = mpdu[4:10] == _ipv6_multicast_mac(destination)
    checks["source_mac_eui64_matches_ipv6"] = _source_eui64_matches(source, mpdu[10:16])
    if not checks["ipv6_exact_length"]:
        errors.append("ipv6_length_not_expected_85")
    if not checks["ipv6_version"]:
        errors.append("ipv6_version_invalid")
    if not checks["ipv6_payload_length"]:
        errors.append("ipv6_payload_length_mismatch")
    if not checks["ipv6_direct_udp"]:
        errors.append("ipv6_extension_or_non_udp")
    if not checks["ipv6_hop_limit_255"]:
        errors.append("ipv6_hop_limit_mismatch")
    if not checks["ipv6_link_local_source"]:
        errors.append("ipv6_source_not_link_local")
    if not checks["ipv6_ff02_mdns_destination"]:
        errors.append("ipv6_destination_not_ff02_fb")
    if not checks["multicast_mac_mapping"]:
        errors.append("ipv6_multicast_mac_mismatch")
    if not checks["source_mac_eui64_matches_ipv6"]:
        errors.append("source_eui64_mismatch")

    udp = ipv6[40:]
    checks["udp_exact_length"] = len(udp) == EXPECTED_UDP_LENGTH
    if len(udp) < 8:
        errors.append("udp_header_truncated")
        return {"valid": False, "status": "unknown_mpdu_invalid",
                "checks": checks, "errors": errors}
    udp_length = struct.unpack_from("!H", udp, 4)[0]
    checks["udp_length_field"] = udp_length == len(udp) == payload_length
    checks["udp_ports_mdns"] = struct.unpack_from("!HH", udp, 0) == (5353, 5353)
    checks["udp_checksum_valid"] = _checksum_valid(ipv6, udp)
    if not checks["udp_exact_length"]:
        errors.append("udp_length_not_expected_45")
    if not checks["udp_length_field"]:
        errors.append("udp_length_field_mismatch")
    if not checks["udp_ports_mdns"]:
        errors.append("udp_ports_not_5353")
    if not checks["udp_checksum_valid"]:
        errors.append("udp_checksum_invalid")

    dns = udp[8:]
    checks["dns_exact_length"] = len(dns) == EXPECTED_DNS_LENGTH
    if len(dns) < 12:
        errors.append("dns_header_truncated")
        return {"valid": False, "status": "unknown_mpdu_invalid",
                "checks": checks, "errors": errors}
    identifier, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", dns, 0)
    checks["dns_id_zero"] = identifier == 0
    checks["dns_flags_zero"] = flags == 0
    checks["dns_qdcount_one"] = qd == 1
    checks["dns_ancount_zero"] = an == 0
    checks["dns_nscount_zero"] = ns == 0
    checks["dns_arcount_zero"] = ar == 0
    checks["exact_airdrop_ptr_in_qm_question"] = dns[12:].lower() == EXPECTED_QUESTION
    if not checks["dns_exact_length"]:
        errors.append("dns_length_not_expected_37")
    if not checks["dns_id_zero"]:
        errors.append("dns_id_nonzero")
    if not checks["dns_flags_zero"]:
        errors.append("dns_flags_nonzero")
    for name in ("qdcount_one", "ancount_zero", "nscount_zero", "arcount_zero"):
        if not checks["dns_" + name]:
            errors.append("dns_" + name + "_mismatch")
    if not checks["exact_airdrop_ptr_in_qm_question"]:
        errors.append("dns_question_or_trailing_data_mismatch")

    valid = not errors
    return {
        "valid": valid,
        "status": "valid_final_airdrop_qm_mpdu" if valid else "unknown_mpdu_invalid",
        "checks": checks,
        "errors": errors,
        "frame_control": frame_control,
        "sequence_control": sequence_control,
        "mpdu_length": len(mpdu),
        "ipv6_length": len(ipv6),
        "ipv6_payload_length": payload_length,
        "udp_length": len(udp),
        "dns_length": len(dns),
        "dns_counts": {"qd": qd, "an": an, "ns": ns, "ar": ar},
        "udp_checksum_valid": checks["udp_checksum_valid"],
        "raw_addresses_emitted": False,
    }


def decode_test138_receipt(receipt: Any) -> dict[str, Any]:
    base = _D136.decode_test136_receipt(receipt)
    if not isinstance(receipt, Mapping):
        return {**base, "test138_profile": _profile(receipt)}
    profile = _profile(receipt)
    final = receipt.get("final")
    joined = base.get("raw_legacy_trace_join", {}).get(
        "raw_facts_status_identity_joined_to_one_trace_row") is True
    tx_complete = base.get("local_tx_path", {}).get("local_completion_succeeded") is True
    raw_capture = base.get("private_command_mpdu_capture", {})
    raw_bytes, raw_error = _D136.decode_base64_property(
        final.get("NativeP2PQmWireRawSnapshotPrivateBase64")
        if isinstance(final, Mapping) else None)
    mpdu_report: dict[str, Any]
    if raw_error is not None or raw_bytes is None:
        mpdu_report = {"valid": False, "status": "unknown_raw_mpdu_missing",
                       "errors": [raw_error or "raw_mpdu_missing"]}
    else:
        raw_header = _D136._decode_qwr1(raw_bytes)
        if raw_header.get("valid") is not True:
            mpdu_report = {"valid": False, "status": "unknown_raw_mpdu_invalid",
                           "errors": raw_header.get("reasons", [])}
        else:
            length = raw_header["mpdu_copied_length"]
            mpdu = raw_bytes[MPDU_OFFSET:MPDU_OFFSET + length]
            mpdu_report = decode_final_qm_mpdu(mpdu)
            mpdu_report["raw_qm_capture_valid"] = raw_capture.get("valid") is True
            mpdu_report["raw_qm_trace_join_exact"] = joined
            mpdu_report["local_completion_succeeded"] = tx_complete
            mpdu_report["same_packet_submission_gate"] = (
                raw_capture.get("valid") is True and joined and tx_complete)

    direct_final_an0 = (
        profile.get("valid") is True and
        raw_capture.get("valid") is True and joined and tx_complete and
        mpdu_report.get("valid") is True and
        mpdu_report.get("dns_counts", {}).get("an") == 0)
    known_answer = {
        "final_an_count": mpdu_report.get("dns_counts", {}).get("an"),
        "final_an_count_directly_observed": (
            isinstance(mpdu_report.get("dns_counts"), Mapping) and
            _number(mpdu_report.get("dns_counts", {}).get("an")) is not None),
        "original_an_count": None,
        "original_an_count_directly_observed": False,
        "original_an_count_status": (
            "inferred_original_an1_from_test138_guarded_success_path"
            if direct_final_an0 else "unknown_no_direct_pre_strip_witness"),
        "inference_is_not_packet_level_observation": True,
        "peer_response_or_airdrop_completion_proven": False,
    }
    return {
        "status": "decoded_private_test138_receipt",
        "valid": base.get("valid") is True,
        "expected_build": receipt.get("expected_build"),
        "expected_uuid": receipt.get("expected_uuid"),
        "test138_profile": profile,
        "final_qm_mpdu": mpdu_report,
        "known_answer_removal": known_answer,
        "raw_legacy_trace_join": base.get("raw_legacy_trace_join"),
        "local_tx_path": base.get("local_tx_path"),
        "current_aw_attempt_only": base.get("current_aw_attempt_only"),
        "discovery_rx_window": base.get("discovery_rx_window"),
        "discovery_rx_events": base.get("discovery_rx_events"),
        "cleanup": receipt.get("cleanup"),
        "proof_limits": {
            "final_packet_is_same_packet_local_submission_evidence": direct_final_an0,
            "original_known_answer_count_is_inferred_only": True,
            "radio_transmit_proven": False,
            "peer_ack_proven": False,
            "peer_receipt_proven": False,
            "airdrop_proven": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: test138_diagnostics.py PRIVATE_RECEIPT.json", file=sys.stderr)
        return 2
    try:
        receipt = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "receipt_unreadable", "detail": str(error)}))
        return 1
    summary = decode_test138_receipt(receipt)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0 if summary.get("proof_limits", {}).get(
        "final_packet_is_same_packet_local_submission_evidence") else 1


if __name__ == "__main__":
    raise SystemExit(main())
