#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate Test129 artifacts and run one bounded, fully witnessed diagnostic.

The runtime path is derived from Test127/Test124 and uses the Test128 active
monitor peer script. This adapter binds those tools to the separate Test129
kext build and requires the helper's TX/return evidence plus the final outer
P2P cleanup publication before reporting a completed run.
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
sys.path.insert(0, str(ROOT / "developer-tools/test127"))
sys.path.insert(0, str(ROOT / "developer-tools/test129"))
import coordinate_directed_test127 as base_runner
import build_helper_test129

shared = base_runner.shared
BASE = ROOT.parent.parent
BUILD = "25G416-Test129"
PRIVATE = BASE / "RuntimeTest129/research/preparation-private"
PEER_DIR = BASE / "RuntimeTest124/research/preparation-private/tools"
MONITOR_PRIVATE = BASE / "RuntimeTest128/research/preparation-private"
MONITOR_SCRIPT = ROOT / "developer-tools/test128/openwrt_monitor_window128.sh"
MONITOR_CAPABILITY_SOURCE = ROOT / "developer-tools/test128/openwrt_active_monitor_capability128.cpp"
MONITOR_CHANNEL_SOURCE = ROOT / "developer-tools/test110/openwrt_echo_channel.hpp"
BUILD_RECEIPT = PRIVATE / "test129-build-private.json"
SOURCE_MANIFEST = PRIVATE / "build-input-before-private.json"
DEPLOYMENT_RECEIPT = PRIVATE.parent / "test129-deployment-private.json"
HELPER_RECEIPT = PRIVATE / "tools/test129-helper-build-private.json"
MONITOR_RECEIPT = MONITOR_PRIVATE / "test128-tools-private.json"
MONITOR_CAPABILITY_BINARY = MONITOR_PRIVATE / "openwrt_active_monitor_capability128"

UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class Test129Error(ValueError):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _uint32(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def _terminal_gates(helper: dict[str, Any], before: dict[str, Any],
                    after: dict[str, Any], outer_after: dict[str, Any],
                    config: dict[str, Any]) -> dict[str, Any]:
    """Pure acceptance predicate shared by orchestration and offline tests."""
    diagnostic = helper.get("diagnostics")
    diagnostic = diagnostic if isinstance(diagnostic, dict) else {}
    outer = helper.get("outer_probe")
    outer = outer if isinstance(outer, dict) else {}
    expected = {
        "build": BUILD,
        "expected_uuid": config.get("expected_uuid"),
        "run_token": config.get("identity", {}).get("run_token"),
        "outer_state": 7,
        "outer_remove_result": 0,
        "outer_resource_may_exist": 0,
        "outer_attempted": 1,
    }
    for generation in ("context_generation", "power_generation", "station_generation"):
        expected["outer_" + generation] = outer.get("frozen_" + generation)
    same_outer_keys = {
        "attempted": "outer_attempted",
        "state": "outer_state",
        "remove_result": "outer_remove_result",
        "resource_may_exist": "outer_resource_may_exist",
        "context_generation": "outer_context_generation",
        "power_generation": "outer_power_generation",
        "station_generation": "outer_station_generation",
    }
    failures: list[str] = []

    def require(condition: bool, name: str) -> None:
        if not condition:
            failures.append(name)

    require(helper.get("build") == expected["build"], "helper_build_matches")
    require(helper.get("expected_uuid") == expected["expected_uuid"], "helper_uuid_matches")
    require(helper.get("run_token") == expected["run_token"], "helper_run_token_matches")
    require(helper.get("run_identity_matches") is True, "helper_run_identity_matches")
    require(helper.get("arm_accepted") is True, "same_run_arm_accepted")
    require(helper.get("native_udp_attempted") is True and
            type(helper.get("native_udp_bytes")) is int and helper.get("native_udp_bytes") == 8 and
            helper.get("matched_peer_return_proven") is True and
            helper.get("ifnet_delivery_proven") is True,
            "matched_return_delivered_to_awdl0")
    require(helper.get("tx_completion_observed") is True and
            _uint32(diagnostic.get("CompletionObserved")) and diagnostic.get("CompletionObserved") == 1 and
            _uint32(diagnostic.get("RawTxStatus")) and diagnostic.get("RawTxStatus") == 1,
            "tx_completion_observed")
    require(helper.get("firmware_attempt_succeeded") is True and
            _uint32(diagnostic.get("FirmwareAttemptSucceeded")) and
            diagnostic.get("FirmwareAttemptSucceeded") == 1,
            "firmware_attempt_succeeded")
    require(_uint32(diagnostic.get("Stage")) and diagnostic.get("Stage") == 8 and
            _uint32(diagnostic.get("Result")) and diagnostic.get("Result") == 0,
            "directed_exercise_completed")
    require(_uint32(diagnostic.get("CleanupAck")) and diagnostic.get("CleanupAck") == 1 and
            _uint32(diagnostic.get("ResourcesAbsent")) and diagnostic.get("ResourcesAbsent") == 1,
            "inner_cleanup_ack_and_resources_absent")
    require(helper.get("outer_probe_release_accepted") is True,
            "helper_outer_probe_release_accepted")
    require(helper.get("terminal_release_accepted") is True,
            "helper_terminal_release_accepted")
    require(type(before.get("boot")) is int and type(after.get("boot")) is int and
            before.get("boot") == config.get("expected_boot") and
            after.get("boot") == config.get("expected_boot") == before.get("boot"),
            "same_expected_boot")
    require(before.get("loaded_uuid_matches") is True and
            after.get("loaded_uuid_matches") is True,
            "loaded_kernel_uuid_matches")
    require(before.get("build") == BUILD and after.get("build") == BUILD,
            "same_test129_build")

    for helper_key, expected_key in same_outer_keys.items():
        value = outer.get(helper_key)
        require(_uint32(value) and value == expected[expected_key],
                "helper_outer_" + helper_key + "_matches")
        property_key = {
            "attempted": "NativeP2PProbeAttempted",
            "state": "NativeP2PProbeState",
            "remove_result": "NativeP2PProbeRemoveResult",
            "resource_may_exist": "NativeP2PProbeResourceMayExist",
            "context_generation": "NativeP2PProbeContextGeneration",
            "power_generation": "NativeP2PProbePowerGeneration",
            "station_generation": "NativeP2PProbeStationGeneration",
        }[helper_key]
        raw_after_value = outer_after.get(property_key)
        require(_uint32(raw_after_value) and raw_after_value == value,
                "after_ioreg_" + helper_key + "_matches_helper")

    for generation in ("context_generation", "power_generation", "station_generation"):
        frozen_key = "frozen_" + generation
        frozen = outer.get(frozen_key)
        live = outer.get(generation)
        require(_uint32(frozen) and frozen > 0 and frozen == live,
                "outer_" + generation + "_matches_frozen_rx_lease")

    require(helper.get("peer_receipt_proven") is False and
            helper.get("radio_ack_proven") is False and
            helper.get("airdrop_proven") is False,
            "unproven_ack_peer_receipt_airdrop_remain_false")
    return {"accepted": not failures, "failures": failures,
            "tx_completion_observed": helper.get("tx_completion_observed") is True,
            "firmware_attempt_succeeded": helper.get("firmware_attempt_succeeded") is True,
            "matched_peer_return_proven": helper.get("matched_peer_return_proven") is True,
            "outer_probe_release_accepted": helper.get("outer_probe_release_accepted") is True}


def _read_json(path: Path, maximum: int = 2 * 1024 * 1024) -> dict[str, Any]:
    value, _raw = base_runner.read_receipt(path)
    return value


def _source_map_valid(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    for name, sha in value.items():
        if (not isinstance(name, str) or not name or name.startswith("/") or
                ".." in Path(name).parts or not isinstance(sha, str) or
                SHA_RE.fullmatch(sha) is None):
            return False
    return True


def _validate_build(config_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    build, build_raw = base_runner.read_receipt(BUILD_RECEIPT)
    manifest, manifest_raw = base_runner.read_receipt(SOURCE_MANIFEST)
    deployment, deployment_raw = base_runner.read_receipt(DEPLOYMENT_RECEIPT)
    if (build.get("candidate") != BUILD or build.get("full_enabled_profile_build_passed") is not True or
            build.get("strict_signature_passed") is not True or
            build.get("independent_firmware_review_passed") is not True or
            build.get("installed") is not False or build.get("rf_tested") is not False):
        raise Test129Error("Test129 build receipt mismatch")
    uuid = build.get("mach_o_uuid")
    if not isinstance(uuid, str) or UUID_RE.fullmatch(uuid) is None:
        raise Test129Error("Test129 candidate UUID invalid")
    for key in ("binary_sha256", "info_plist_sha256", "archive_sha256"):
        if not isinstance(build.get(key), str) or SHA_RE.fullmatch(build[key]) is None:
            raise Test129Error("Test129 build hash invalid: " + key)
    if not _source_map_valid(build.get("source_files_sha256")):
        raise Test129Error("Test129 committed-source hash map missing")
    source_hashes = build["source_files_sha256"]
    for name, expected_hash in source_hashes.items():
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected_hash:
            raise Test129Error("Test129 source input changed: " + name)
    if (not isinstance(manifest, dict) or not manifest or
            digest(manifest_raw) != build.get("build_input_manifest_sha256")):
        raise Test129Error("Test129 source input manifest binding mismatch")

    archive = PRIVATE / "AirportItlwm-Test129.zip"
    if archive.is_symlink() or digest(archive.read_bytes()) != build.get("archive_sha256"):
        raise Test129Error("Test129 archive changed")
    with zipfile.ZipFile(archive) as z:
        binary = z.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
        info_raw = z.read("AirportItlwm.kext/Contents/Info.plist")
    info = plistlib.loads(info_raw)
    if (digest(binary) != build.get("binary_sha256") or
            digest(info_raw) != build.get("info_plist_sha256") or
            base_runner.previous._macho_uuids(binary) != {uuid} or
            info.get("AirportTahoeBuild") != BUILD or
            info.get("CFBundleIdentifier") != "org.geekaudio.AirportItlwm"):
        raise Test129Error("Test129 archive identity mismatch")
    profile = info["IOKitPersonalities"]["NetworkController"]
    for key in ("NativeP2PProbe", "NativeP2PManualTrigger", "NativeAwdlResidentEnabled",
                "NativeP2PRx149ObservationOnly", "NativeP2PRx149DataInputExperiment",
                "NativeP2PDirectedPrepareCompiled", "NativeP2PDirectedPrepareEnabled",
                "NativeP2PDirectedDataCompiled", "NativeP2PDirectedDataEnabled"):
        if profile.get(key) is not True:
            raise Test129Error("Test129 enabled profile mismatch: " + key)
    for key in ("NativeP2PTxProbe", "NativeAwdlReplyShadowEnabled",
                "NativeAwdlDiscoveryExperimentEnabled", "NativeAwdlTxEvidenceEnabled"):
        if profile.get(key) is not False:
            raise Test129Error("Test129 competing profile enabled: " + key)

    if (deployment.get("candidate") != BUILD or deployment.get("mach_o_uuid") != uuid or
            deployment.get("status") != "deployed_waiting_reboot_disarmed" or
            deployment.get("build_report_sha256") != digest(build_raw) or
            deployment.get("binary_sha256") != build.get("binary_sha256") or
            deployment.get("remount_readback_verified") is not True or
            deployment.get("config_unchanged") is not True or
            deployment.get("automatic_reboot") is not False or
            deployment.get("rf_triggered") is not False):
        raise Test129Error("Test129 deployment binding mismatch")

    config = shared.read_private_config(config_path)
    normalized, _ = shared.validate_config(config, build_id=BUILD)
    if normalized.get("expected_uuid") != uuid:
        raise Test129Error("runtime UUID differs from Test129 candidate")

    helper, helper_raw = base_runner.read_receipt(HELPER_RECEIPT)
    if (helper.get("schema") != "test129-mode4-helper-build/v1" or
            helper.get("candidate") != BUILD or helper.get("status") != "built_offline" or
            helper.get("installed") is not False or helper.get("rf_tested") is not False or
            helper.get("binary_path") != normalized["helper_path_resolved"] or
            helper.get("binary_sha256") != normalized.get("helper_sha256") or
            helper.get("source_path") != "developer-tools/test129/arm_directed_data129.swift"):
        raise Test129Error("Test129 helper receipt mismatch")
    helper_sources = helper.get("source_hashes")
    expected_helper_sources = set(build_helper_test129.HELPER_SOURCES)
    if not isinstance(helper_sources, dict) or set(helper_sources) != expected_helper_sources:
        raise Test129Error("Test129 helper dependency hash set mismatch")
    if helper.get("source_sha256") != helper_sources.get(helper.get("source_path")):
        raise Test129Error("Test129 helper entry source hash mismatch")
    for name, expected_hash in helper_sources.items():
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected_hash:
            raise Test129Error("Test129 helper dependency changed: " + name)
    helper_binary = Path(normalized["helper_path_resolved"])
    if digest(helper_binary.read_bytes()) != helper.get("binary_sha256"):
        raise Test129Error("Test129 helper binary changed")

    # Reuse the frozen Test128 active monitor script/capability pair and the
    # unchanged Test124 echo protocol, while binding both to the Test129 run.
    monitor, _monitor_raw = base_runner.read_receipt(MONITOR_RECEIPT)
    capability_sha = digest(MONITOR_CAPABILITY_BINARY.read_bytes())
    if (normalized.get("prepare_peer_mac_required") is not True or
            Path(normalized["remote_script_path_resolved"]) != MONITOR_SCRIPT.resolve() or
            Path(config.get("capability_helper_path", "")).resolve() != MONITOR_CAPABILITY_BINARY.resolve() or
            config.get("capability_helper_sha256") != capability_sha or
            monitor.get("schema") != "test128-peer-tools/v1" or
            monitor.get("monitor_script_sha256") != digest(MONITOR_SCRIPT.read_bytes()) or
            monitor.get("capability_source_sha256") != digest(MONITOR_CAPABILITY_SOURCE.read_bytes()) or
            monitor.get("channel_header_sha256") != digest(MONITOR_CHANNEL_SOURCE.read_bytes()) or
            monitor.get("capability_binary_sha256") != capability_sha or
            monitor.get("offline_tests_passed") is not True or
            monitor.get("independent_review_passed") is not True):
        raise Test129Error("Test128 active-monitor reuse contract mismatch")
    script_text = MONITOR_SCRIPT.read_text()
    match = re.search(r"^CAPABILITY_SHA256='([0-9a-f]{64})'$", script_text, re.M)
    if not match or match.group(1) != capability_sha:
        raise Test129Error("Test128 active-monitor capability pin mismatch")
    peer_config = dict(normalized)
    peer_config["peer_binary_path_resolved"] = str(Path(normalized["peer_binary_path"]).resolve(strict=True))
    base_runner.previous._validate_peer_receipt(
        PEER_DIR / "test124-peer-build-private.json", peer_config,
        private_dir=PEER_DIR.parent)

    return normalized, {
        "candidate": BUILD,
        "mach_o_uuid": uuid,
        "binary_sha256": build["binary_sha256"],
        "build_receipt_sha256": digest(build_raw),
        "source_manifest_sha256": digest(manifest_raw),
        "deployment_receipt_sha256": digest(deployment_raw),
        "helper_binary_sha256": helper["binary_sha256"],
        "helper_build_receipt_sha256": digest(helper_raw),
        "test128_monitor_script_sha256": digest(MONITOR_SCRIPT.read_bytes()),
        "test128_capability_binary_sha256": capability_sha,
    }


def _load_run_snapshots(result: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = Path(result["run_directory"])
    if directory.is_symlink() or not directory.is_dir():
        raise Test129Error("run evidence directory unavailable")
    before_path = directory / "before-summary.json"
    after_path = directory / "after-summary.json"
    after_ioreg_path = directory / "after-ioreg.plist"
    before = json.loads(before_path.read_text())
    after = json.loads(after_path.read_text())
    records = shared._find_ioreg_records(plistlib.loads(after_ioreg_path.read_bytes()))
    if len(records) != 1:
        raise Test129Error("terminal after-ioreg record missing or ambiguous")
    return before, after, records[0]


def _verify_target_os() -> None:
    review, review_raw = base_runner.read_receipt(
        PRIVATE / "test129-target-os-review-private.json")
    build_raw = BUILD_RECEIPT.read_bytes()
    deployment_raw = DEPLOYMENT_RECEIPT.read_bytes()
    build = json.loads(build_raw)
    if (review.get("schema") != "test129-target-os-review/v1" or
            review.get("candidate") != BUILD or
            review.get("mach_o_uuid") != build.get("mach_o_uuid") or
            review.get("target_os_build") != "25G416" or
            review.get("review_passed") is not True or
            review.get("build_receipt_sha256") != digest(build_raw) or
            review.get("deployment_receipt_sha256") != digest(deployment_raw) or
            review.get("source_commit") != build.get("source_commit") or
            review.get("binary_sha256") != build.get("binary_sha256")):
        raise Test129Error("Test129 target OS review binding mismatch")
    result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.osversion"],
                            capture_output=True, text=True, timeout=5, check=False)
    if result.returncode != 0 or result.stdout.strip() != review["target_os_build"]:
        raise Test129Error("Test129 target OS build mismatch")


def _finalize_run(result: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    helper = result.get("helper_summary")
    if not isinstance(helper, dict):
        result["test129_terminal_acceptance"] = {
            "accepted": False, "failures": ["helper_summary_missing"]}
        result["orchestration_completed"] = False
        return result
    try:
        before, after, outer_after = _load_run_snapshots(result)
        acceptance = _terminal_gates(helper, before, after, outer_after, config)
    except Exception as error:
        acceptance = {"accepted": False,
                      "failures": [error.__class__.__name__ + ": " + str(error)]}
    result["test129_terminal_acceptance"] = acceptance
    result["orchestration_completed"] = bool(
        result.get("orchestration_completed") is True and
        result.get("helper_exit_code") == 0 and acceptance.get("accepted") is True)
    result["peer_receipt_proven"] = False
    result["radio_ack_proven"] = False
    result["airdrop_proven"] = False
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    delegated_run = False
    try:
        config, hashes = _validate_build(args.config)
        if args.run:
            _verify_target_os()
            delegated_run = True
            result = shared.execute_run(config, build_id=BUILD)
            result = _finalize_run(result, config)
        else:
            result = shared.make_plan(config, build_id=BUILD)
            result["deployment_required_before_run"] = False
            result["hardware_action"] = False
            result["runtime_os_build_checked"] = False
        result.update(hashes)
        result["test129_artifacts_validated"] = True
        result["tool_campaign"] = "Test129"
        result["matched_peer_return_proven"] = bool(
            isinstance(result.get("helper_summary"), dict) and
            result["helper_summary"].get("matched_peer_return_proven") is True)
        result["tx_completion_observed"] = bool(
            isinstance(result.get("helper_summary"), dict) and
            result["helper_summary"].get("tx_completion_observed") is True)
        result["firmware_attempt_succeeded"] = bool(
            isinstance(result.get("helper_summary"), dict) and
            result["helper_summary"].get("firmware_attempt_succeeded") is True)
        result["peer_receipt_proven"] = False
        result["radio_ack_proven"] = False
        result["airdrop_proven"] = False
        result["hardware_action"] = bool(args.run and result.get("hardware_action"))
        result["runtime_os_build_checked"] = bool(args.run)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if not args.run or result.get("orchestration_completed") is True else 1
    except Exception as error:
        result = {
            "schema": "test129-local-coordinator/v1",
            "mode": "error",
            "build": BUILD,
            "hardware_action": None if delegated_run else False,
            "ssh_attempted": None if delegated_run else False,
            "arm_attempted": None if delegated_run else False,
            "execution_outcome": "unknown_after_dispatch" if delegated_run else "not_started",
            "peer_receipt_proven": False,
            "radio_ack_proven": False,
            "airdrop_proven": False,
            "error": error.__class__.__name__ + ": " + str(error),
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
