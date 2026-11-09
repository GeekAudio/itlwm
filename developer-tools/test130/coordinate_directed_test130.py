#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate Test130 artifacts and prepare one bounded two-packet exchange.

Default mode is offline: it verifies frozen build/deployment/tool receipts and
prints a no-action plan. Only --run dispatches the shared guarded runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import zipfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools/test111"))
sys.path.insert(0, str(ROOT / "developer-tools/test130"))
sys.path.insert(0, str(ROOT / "developer-tools/test127"))
import coordinate_test111 as shared
import coordinate_directed_test127 as base_runner
import build_helper_test130
import build_peer_test130
import build_monitor_test130

BASE = ROOT.parent.parent
BUILD = "25G416-Test130"
PRIVATE = BASE / "RuntimeTest130/research/preparation-private"
MONITOR_PRIVATE = BASE / "RuntimeTest128/research/preparation-private"
BUILD_RECEIPT = PRIVATE / "test130-build-private.json"
SOURCE_MANIFEST = PRIVATE / "build-input-before-private.json"
DEPLOYMENT_RECEIPT = PRIVATE.parent / "test130-deployment-private.json"
TARGET_REVIEW_RECEIPT = PRIVATE / "test130-target-os-review-private.json"
TOOLS = PRIVATE / "tools"
HELPER_RECEIPT = TOOLS / "test130-helper-build-private.json"
PEER_RECEIPT = TOOLS / "test130-peer-build-private.json"
MONITOR_RECEIPT = TOOLS / "test130-monitor-build-private.json"
MONITOR_SCRIPT = TOOLS / "openwrt_monitor_window130.sh"
MONITOR_CAPABILITY_RECEIPT = MONITOR_PRIVATE / "test128-tools-private.json"
MONITOR_CAPABILITY_BINARY = MONITOR_PRIVATE / "openwrt_active_monitor_capability128"

UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class Test130Error(ValueError):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _uint(value: Any, *, positive: bool = False) -> bool:
    return (type(value) is int and value >= (1 if positive else 0) and
            value <= 0xFFFFFFFFFFFFFFFF)


def _sha_map_valid(value: Any) -> bool:
    return (isinstance(value, dict) and bool(value) and all(
        isinstance(name, str) and name and not name.startswith("/") and
        ".." not in Path(name).parts and isinstance(sha, str) and
        SHA_RE.fullmatch(sha) is not None for name, sha in value.items()))


def _read(path: Path, maximum: int = 2 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    return base_runner.previous._private_json(path, private_dir=path.parent,
                                              max_bytes=maximum)


def _validate_build(config_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    build, build_raw = _read(BUILD_RECEIPT, 256 * 1024)
    manifest, manifest_raw = _read(SOURCE_MANIFEST)
    deployment, deployment_raw = _read(DEPLOYMENT_RECEIPT, 256 * 1024)
    expected_true = ("full_enabled_profile_build_passed", "strict_signature_passed",
                     "independent_firmware_review_passed",
                     "independent_lifecycle_review_passed",
                     "target_os_abi_review_passed", "source_inputs_unchanged")
    if (build.get("candidate") != BUILD or
            any(build.get(key) is not True for key in expected_true) or
            build.get("installed") is not False or build.get("rf_tested") is not False or
            build.get("target_os_build") != "25G416"):
        raise Test130Error("Test130 build receipt is incomplete or mismatched")
    uuid = build.get("mach_o_uuid")
    if not isinstance(uuid, str) or UUID_RE.fullmatch(uuid) is None:
        raise Test130Error("Test130 candidate UUID invalid")
    for key in ("binary_sha256", "info_plist_sha256", "archive_sha256",
                "build_input_manifest_sha256"):
        if not isinstance(build.get(key), str) or SHA_RE.fullmatch(build[key]) is None:
            raise Test130Error("Test130 build hash invalid: " + key)
    if (not _sha_map_valid(build.get("source_files_sha256")) or
            digest(manifest_raw) != build.get("build_input_manifest_sha256") or
            digest(manifest_raw) != build.get("source_input_manifest_sha256",
                                               build.get("build_input_manifest_sha256"))):
        raise Test130Error("Test130 production source manifest binding mismatch")
    for name, expected_hash in build["source_files_sha256"].items():
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected_hash:
            raise Test130Error("Test130 frozen production source changed: " + name)

    archive = PRIVATE / "AirportItlwm-Test130.zip"
    if archive.is_symlink() or digest(archive.read_bytes()) != build["archive_sha256"]:
        raise Test130Error("Test130 archive hash mismatch")
    with zipfile.ZipFile(archive) as zf:
        binary = zf.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
        info_raw = zf.read("AirportItlwm.kext/Contents/Info.plist")
    info = plistlib.loads(info_raw)
    if (digest(binary) != build["binary_sha256"] or
            digest(info_raw) != build["info_plist_sha256"] or
            base_runner.previous._macho_uuids(binary) != {uuid} or
            info.get("AirportTahoeBuild") != BUILD or
            info.get("CFBundleIdentifier") != "org.geekaudio.AirportItlwm"):
        raise Test130Error("Test130 archive identity mismatch")
    profile = info.get("IOKitPersonalities", {}).get("NetworkController", {})
    for key in ("NativeP2PProbe", "NativeP2PManualTrigger", "NativeAwdlResidentEnabled",
                "NativeP2PDirectedPrepareCompiled", "NativeP2PDirectedPrepareEnabled",
                "NativeP2PDirectedDataCompiled", "NativeP2PDirectedDataEnabled"):
        if profile.get(key) is not True:
            raise Test130Error("Test130 enabled feature missing: " + key)
    for key in ("NativeP2PTxProbe", "NativeAwdlReplyShadowEnabled",
                "NativeAwdlDiscoveryExperimentEnabled", "NativeAwdlTxEvidenceEnabled"):
        if profile.get(key) is not False:
            raise Test130Error("Test130 competing experiment enabled: " + key)

    if (deployment.get("candidate") != BUILD or
            deployment.get("status") != "deployed_waiting_reboot_disarmed" or
            deployment.get("mach_o_uuid") != uuid or
            deployment.get("binary_sha256") != build["binary_sha256"] or
            deployment.get("archive_sha256") != build["archive_sha256"] or
            deployment.get("build_report_sha256") != digest(build_raw) or
            deployment.get("remount_readback_verified") is not True or
            deployment.get("config_unchanged") is not True or
            deployment.get("automatic_reboot") is not False or
            deployment.get("rf_triggered") is not False):
        raise Test130Error("Test130 deployment receipt binding mismatch")

    review, review_raw = _read(TARGET_REVIEW_RECEIPT, 128 * 1024)
    if (review.get("schema") != "test130-target-os-review/v1" or
            review.get("candidate") != BUILD or review.get("mach_o_uuid") != uuid or
            review.get("target_os_build") != "25G416" or
            review.get("review_passed") is not True or
            review.get("build_receipt_sha256") != digest(build_raw) or
            review.get("deployment_receipt_sha256") != digest(deployment_raw) or
            review.get("source_commit") != build.get("source_commit") or
            review.get("binary_sha256") != build.get("binary_sha256")):
        raise Test130Error("Test130 target OS review binding mismatch")

    config = shared.read_private_config(config_path)
    normalized, _config_hashes = shared.validate_config(config, build_id=BUILD)
    if (normalized.get("expected_uuid") != uuid or
            normalized.get("expected_build") != BUILD or
            normalized.get("prepare_peer_mac_required") is not True or
            Path(normalized["remote_script_path_resolved"]) != MONITOR_SCRIPT.resolve()):
        raise Test130Error("Test130 runtime config candidate/adapter mismatch")
    identity = normalized["identity"]
    if (len(identity.get("nonces", [])) != 2 or
            identity.get("nonce") != identity["nonces"][0] or
            identity.get("nonce2") != identity["nonces"][1]):
        raise Test130Error("Test130 runtime identity is not an ordered nonce pair")

    helper, helper_raw = _read(HELPER_RECEIPT, 128 * 1024)
    if (helper.get("schema") != "test130-two-packet-helper-build/v1" or
            helper.get("candidate") != BUILD or helper.get("status") != "built_offline" or
            helper.get("installed") is not False or helper.get("rf_tested") is not False or
            helper.get("binary_path") != normalized["helper_path_resolved"] or
            helper.get("binary_sha256") != normalized.get("helper_sha256") or
            helper.get("source_path") != "developer-tools/test130/arm_directed_data130.swift"):
        raise Test130Error("Test130 helper build receipt mismatch")
    helper_sources = helper.get("source_hashes")
    if not isinstance(helper_sources, dict) or set(helper_sources) != set(build_helper_test130.HELPER_SOURCES):
        raise Test130Error("Test130 helper source manifest mismatch")
    for name, expected_hash in helper_sources.items():
        source = ROOT / name
        if source.is_symlink() or not source.is_file() or digest(source.read_bytes()) != expected_hash:
            raise Test130Error("Test130 helper dependency changed: " + name)
    helper_binary = Path(normalized["helper_path_resolved"])
    if helper_binary.is_symlink() or digest(helper_binary.read_bytes()) != helper["binary_sha256"]:
        raise Test130Error("Test130 helper binary changed")

    peer, peer_raw = _read(PEER_RECEIPT, 128 * 1024)
    if (peer.get("schema") != "test130-two-packet-peer-build/v1" or
            peer.get("candidate") != BUILD or peer.get("status") != "built_offline" or
            peer.get("uploaded") is not False or peer.get("rf_tested") is not False or
            peer.get("target") != "aarch64-linux-musl" or
            peer.get("wire_contract") != "test130-ordered-two-nonce-echo/v1" or
            peer.get("binary_path") != normalized["peer_binary_path_resolved"] or
            peer.get("binary_sha256") != normalized.get("peer_sha256")):
        raise Test130Error("Test130 peer build receipt mismatch")
    peer_sources = peer.get("source_hashes")
    if not isinstance(peer_sources, dict) or set(peer_sources) != set(build_peer_test130.SOURCES):
        raise Test130Error("Test130 peer source manifest mismatch")
    for name, expected_hash in peer_sources.items():
        source = ROOT / name
        if source.is_symlink() or not source.is_file() or digest(source.read_bytes()) != expected_hash:
            raise Test130Error("Test130 peer dependency changed: " + name)
    peer_binary = Path(normalized["peer_binary_path_resolved"])
    peer_raw_binary = peer_binary.read_bytes()
    if (peer_binary.is_symlink() or digest(peer_raw_binary) != peer["binary_sha256"] or
            peer_raw_binary[:6] != b"\x7fELF\x02\x01" or
            int.from_bytes(peer_raw_binary[18:20], "little") != 183):
        raise Test130Error("Test130 peer ELF/hash mismatch")

    monitor, monitor_raw = _read(MONITOR_RECEIPT, 128 * 1024)
    base_script = ROOT / "developer-tools/test128/openwrt_monitor_window128.sh"
    adapter_raw = MONITOR_SCRIPT.read_bytes()
    expected_adapter = build_monitor_test130.render(
        base_script.read_text(encoding="utf-8"), peer["binary_sha256"]).encode("utf-8")
    if (monitor.get("schema") != "test130-openwrt-monitor-adapter-build/v1" or
            monitor.get("candidate") != BUILD or monitor.get("status") != "built_offline" or
            monitor.get("router_mutated") is not False or monitor.get("rf_tested") is not False or
            monitor.get("binary_path") != str(MONITOR_SCRIPT) or
            monitor.get("binary_sha256") != digest(adapter_raw) or
            adapter_raw != expected_adapter or
            monitor.get("peer_binary_sha256") != peer["binary_sha256"] or
            normalized["remote_script_sha256"] != monitor["binary_sha256"]):
        raise Test130Error("Test130 monitor adapter binding mismatch")
    monitor_sources = monitor.get("source_hashes")
    expected_monitor_sources = {
        "developer-tools/test128/openwrt_monitor_window128.sh": digest(base_script.read_bytes()),
        "developer-tools/test110/openwrt_echo_channel.hpp": digest(
            (ROOT / "developer-tools/test110/openwrt_echo_channel.hpp").read_bytes()),
        "developer-tools/test130/build_monitor_test130.py": digest(
            (ROOT / "developer-tools/test130/build_monitor_test130.py").read_bytes()),
    }
    if monitor_sources != expected_monitor_sources:
        raise Test130Error("Test130 monitor source dependency changed")

    capability, capability_raw = _read(MONITOR_CAPABILITY_RECEIPT, 128 * 1024)
    capability_sha = digest(MONITOR_CAPABILITY_BINARY.read_bytes())
    if (Path(normalized.get("capability_helper_path", "")).resolve() != MONITOR_CAPABILITY_BINARY.resolve() or
            normalized.get("capability_helper_sha256") != capability_sha or
            capability.get("schema") != "test128-peer-tools/v1" or
            capability.get("monitor_script_sha256") != digest(base_script.read_bytes()) or
            capability.get("capability_binary_sha256") != capability_sha or
            capability.get("offline_tests_passed") is not True or
            capability.get("independent_review_passed") is not True):
        raise Test130Error("Test128 monitor capability reuse mismatch")
    capability_script = base_script.read_text(encoding="utf-8")
    match = re.search(r"^CAPABILITY_SHA256='([0-9a-f]{64})'$", capability_script, re.M)
    if not match or match.group(1) != capability_sha:
        raise Test130Error("Test128 capability pin mismatch")
    script = MONITOR_SCRIPT.read_text(encoding="utf-8")
    if not re.search(r"^CAPABILITY_SHA256='" + re.escape(capability_sha) + r"'$", script, re.M):
        raise Test130Error("Test130 adapter lost the pinned capability")

    return normalized, {
        "candidate": BUILD,
        "mach_o_uuid": uuid,
        "binary_sha256": build["binary_sha256"],
        "build_receipt_sha256": digest(build_raw),
        "deployment_receipt_sha256": digest(deployment_raw),
        "target_review_receipt_sha256": digest(review_raw),
        "helper_binary_sha256": helper["binary_sha256"],
        "helper_receipt_sha256": digest(helper_raw),
        "peer_binary_sha256": peer["binary_sha256"],
        "peer_receipt_sha256": digest(peer_raw),
        "monitor_adapter_sha256": monitor["binary_sha256"],
        "monitor_receipt_sha256": digest(monitor_raw),
        "monitor_capability_receipt_sha256": digest(capability_raw),
    }


def _packet_gate(helper: dict[str, Any], peer: dict[str, Any], identity: dict[str, Any],
                 deadline_us: int) -> dict[str, Any]:
    failures: list[str] = []
    def require(ok: bool, name: str) -> None:
        if not ok:
            failures.append(name)
    expected_nonces = identity["nonces"]
    helper_packets = helper.get("packet_receipts")
    peer_packets = peer.get("packets")
    require(helper.get("packet_count") == 2, "helper_two_packet_count")
    require(helper.get("native_udp_attempted") is True and
            helper.get("native_udp_bytes") == [8, 8], "two_native_udp_sends")
    require(helper.get("peer_socket_matched") == [True, True], "two_matched_peer_returns")
    require(helper.get("tx_completion_observed") == [True, True], "two_tx_completions")
    require(helper.get("firmware_attempt_succeeded") == [True, True], "two_tx_rsp_successes")
    require(helper.get("ifnet_delivery_proven") == [True, True], "two_ifnet_deliveries")
    require(isinstance(helper_packets, list) and len(helper_packets) == 2,
            "two_independent_helper_packet_receipts")
    require(isinstance(peer_packets, list) and len(peer_packets) == 2,
            "two_independent_peer_packet_receipts")
    if isinstance(helper_packets, list) and len(helper_packets) == 2:
        identities: list[tuple[Any, ...]] = []
        for slot, packet in enumerate(helper_packets):
            require(isinstance(packet, dict) and packet.get("present") is True,
                    f"packet{slot}_receipt_present")
            if not isinstance(packet, dict):
                continue
            exact = packet.get("exact_reply")
            require(packet.get("slot") == slot and packet.get("nonce") == expected_nonces[slot],
                    f"packet{slot}_ordered_nonce")
            require(all(_uint(packet.get(key), positive=True) for key in (
                "packet_serial", "owner_serial", "run_serial", "ifindex",
                "interface_incarnation", "context_generation", "station_generation",
                "roc_generation")) and
                _uint(packet.get("descriptor_index")) and
                all(_uint(packet.get(key), positive=True) for key in
                    ("wifi_sequence", "awdl_sequence", "ssn")),
                f"packet{slot}_identity_fields")
            require(packet.get("tx_rsp_seen") is True and packet.get("tx_rsp_success") is True and
                    packet.get("origin_doorbell_recorded") is True and
                    packet.get("origin_completion_recorded") is True and
                    packet.get("resources_absent") is True, f"packet{slot}_tx_and_release")
            require(packet.get("doorbell_us", 0) > 0 and
                    packet.get("doorbell_us", 0) <= packet.get("tx_rsp_us", 0) < deadline_us,
                    f"packet{slot}_tx_before_roc_end")
            require(isinstance(exact, dict) and exact.get("captured") is True and
                    exact.get("delivered") is True and exact.get("valid") is True and
                    exact.get("slot") == slot and exact.get("nonce") is None,
                    f"packet{slot}_exact_rx_receipt")
            if isinstance(exact, dict):
                require(_uint(exact.get("snapshot_sequence"), positive=True) and
                        exact.get("snapshot_sequence", 1) % 2 == 0 and
                        exact.get("packet_serial") == packet.get("packet_serial") and
                        exact.get("owner_serial") == packet.get("owner_serial") and
                        exact.get("run_serial") == packet.get("run_serial") and
                        exact.get("ifindex") == packet.get("ifindex") and
                        exact.get("interface_incarnation") == packet.get("interface_incarnation") and
                        exact.get("context_generation") == packet.get("context_generation") and
                        exact.get("power_generation") == packet.get("power_generation") and
                        exact.get("station_generation") == packet.get("station_generation") and
                        exact.get("roc_generation") == packet.get("roc_generation"),
                        f"packet{slot}_exact_same_session")
                require(packet.get("doorbell_us", 0) <= exact.get("capture_us", 0) <=
                        exact.get("input_us", 0) < deadline_us,
                        f"packet{slot}_exact_in_window")
            identities.append((packet.get("packet_serial"), packet.get("descriptor_index"),
                               packet.get("wifi_sequence"), packet.get("awdl_sequence"),
                               packet.get("ssn")))
        if len(identities) == 2:
            require(_uint(identities[0][0], positive=True) and
                    _uint(identities[1][0], positive=True) and
                    identities[0][0] != identities[1][0] and
                    _uint(identities[0][1]) and _uint(identities[1][1]) and
                    identities[0][1] != identities[1][1] and
                    all(_uint(a, positive=True) and _uint(b, positive=True) and a != b
                        for a, b in zip(identities[0][2:], identities[1][2:])),
                    "unique_serial_descriptor_sequences_and_ssn")
            first = helper_packets[0]
            second = helper_packets[1]
            require(second.get("doorbell_us", 0) >
                    first.get("exact_reply", {}).get("input_us", 0),
                    "packet2_after_exact_packet1_rx")
            first_ticket = first.get("exact_reply", {}).get("ticket_serial")
            second_ticket = second.get("exact_reply", {}).get("ticket_serial")
            require(_uint(first_ticket, positive=True) and first_ticket == second_ticket,
                    "same_nonzero_ticket_serial")
            require(first.get("tx_rsp_us", 0) < second.get("doorbell_us", 0),
                    "packet2_after_first_tx_completion")
            require(first.get("owner_serial") == second.get("owner_serial") and
                    first.get("run_serial") == second.get("run_serial") and
                    first.get("ifindex") == second.get("ifindex") and
                    first.get("interface_incarnation") == second.get("interface_incarnation") and
                    first.get("context_generation") == second.get("context_generation") and
                    first.get("power_generation") == second.get("power_generation") and
                    first.get("station_generation") == second.get("station_generation") and
                    first.get("roc_generation") == second.get("roc_generation") and
                    first.get("deadline_us") == second.get("deadline_us"),
                    "same_session_and_roc")
    if isinstance(peer_packets, list) and len(peer_packets) == 2:
        for slot, packet in enumerate(peer_packets):
            require(isinstance(packet, dict) and packet.get("slot") == slot and
                    packet.get("nonce") == expected_nonces[slot] and
                    packet.get("matched_requests") == 1 and
                    packet.get("duplicate_requests") == 0 and
                    packet.get("out_of_order_matches") == 0 and
                    packet.get("reply_attempted") is True and
                    packet.get("reply_result") == "local_send_succeeded" and
                    packet.get("reply_wifi_sequence") == 0x110 + slot and
                    packet.get("reply_awdl_sequence") == 0x110 + slot,
                    f"peer_packet{slot}_single_ordered_reply")
    require(helper.get("automatic_retry_allowed") is False and
            peer.get("automatic_retry") is False, "no_automatic_retry")
    require(helper.get("cleanup_ack") is True and
            helper.get("run_resources_absent") is True and
            helper.get("outer_release_accepted") is True and
            helper.get("terminal_gate_accepted") is True,
            "run_cleanup_and_outer_release")
    require(helper.get("peer_receipt_proven") is False and
            helper.get("radio_ack_proven") is False and
            helper.get("airdrop_proven") is False and
            peer.get("over_air_delivery_proven") is False and
            peer.get("airdrop_proven") is False,
            "unproven_air_over_air_and_airdrop_remain_false")
    return {"accepted": not failures, "failures": failures,
            "packet_count": 2, "radio_ack_proven": False,
            "peer_receipt_proven": False, "airdrop_proven": False}


def _finalize(result: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    helper = result.get("helper_summary")
    peer = result.get("peer_result")
    if not isinstance(helper, dict) or not isinstance(peer, dict):
        result["test130_terminal_acceptance"] = {
            "accepted": False, "failures": ["helper_or_peer_result_missing"],
            "radio_ack_proven": False, "peer_receipt_proven": False, "airdrop_proven": False}
        result["orchestration_completed"] = False
        return result
    try:
        deadline = max((packet.get("deadline_us", 0) for packet in helper.get("packet_receipts", [])
                        if isinstance(packet, dict)), default=0)
        acceptance = _packet_gate(helper, peer, config["identity"], deadline)
    except Exception as error:
        acceptance = {"accepted": False,
                      "failures": [error.__class__.__name__ + ": " + str(error)],
                      "radio_ack_proven": False, "peer_receipt_proven": False,
                      "airdrop_proven": False}
    result["test130_terminal_acceptance"] = acceptance
    result["orchestration_completed"] = bool(
        result.get("orchestration_completed") is True and
        result.get("helper_exit_code") == 0 and acceptance.get("accepted") is True)
    result["radio_ack_proven"] = False
    result["peer_receipt_proven"] = False
    result["airdrop_proven"] = False
    return result


def _verify_target_os() -> None:
    review, _ = _read(TARGET_REVIEW_RECEIPT, 128 * 1024)
    actual = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.osversion"],
                            capture_output=True, text=True, timeout=5, check=False)
    if actual.returncode != 0 or actual.stdout.strip() != review.get("target_os_build"):
        raise Test130Error("runtime macOS build differs from reviewed target")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    delegated = False
    try:
        config, hashes = _validate_build(args.config)
        if args.run:
            _verify_target_os()
            delegated = True
            result = shared.execute_run(config, build_id=BUILD)
            result = _finalize(result, config)
        else:
            result = shared.make_plan(config, build_id=BUILD)
            result.update({"deployment_required_before_run": False,
                           "hardware_action": False,
                           "runtime_os_build_checked": False,
                           "ordered_packet_count": 2,
                           "same_100ms_roc": True,
                           "automatic_retry": False})
        result.update(hashes)
        result["test130_artifacts_validated"] = True
        result["tool_campaign"] = "Test130"
        result["radio_ack_proven"] = False
        result["peer_receipt_proven"] = False
        result["airdrop_proven"] = False
        result["hardware_action"] = bool(args.run and result.get("hardware_action"))
        result["runtime_os_build_checked"] = bool(args.run)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if not args.run or result.get("orchestration_completed") is True else 1
    except Exception as error:
        result = {"schema": "test130-local-coordinator/v1", "mode": "error",
                  "build": BUILD, "hardware_action": None if delegated else False,
                  "ssh_attempted": None if delegated else False,
                  "arm_attempted": None if delegated else False,
                  "execution_outcome": "unknown_after_dispatch" if delegated else "not_started",
                  "radio_ack_proven": False, "peer_receipt_proven": False,
                  "airdrop_proven": False,
                  "error": error.__class__.__name__ + ": " + str(error)}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
