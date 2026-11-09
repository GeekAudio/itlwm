#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline plan and guarded runtime entry point for Test124 mode-4 echo.

This is a thin Test111 coordinator adapter. It keeps the kext build receipt,
its source-input manifest, the separately compiled helper receipt, and the
deployment receipt as distinct inputs before delegating to the existing
READY, boot/UUID, one-shot, lease, and same-socket receive gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import pwd
import re
import stat
import struct
import subprocess
import sys
from typing import Any
from zipfile import BadZipFile, ZipFile


REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DIR = REPO_ROOT.parent.parent / "RuntimeTest124" / "research" / "preparation-private"
BUILD_ID = "25G416-Test124"
BUILD_RECEIPT = PRIVATE_DIR / "test124-build-private.json"
SOURCE_INPUT_MANIFEST = PRIVATE_DIR / "build-input-before-private.json"
DEPLOYMENT_RECEIPT = PRIVATE_DIR.parent / "test124-deployment-private.json"
HELPER_BUILD_RECEIPT = PRIVATE_DIR / "tools" / "test124-helper-build-private.json"
PEER_BUILD_RECEIPT = PRIVATE_DIR / "tools" / "test124-peer-build-private.json"
PEER_SOURCES = (
    "developer-tools/test110/openwrt_echo_peer.cpp",
    "developer-tools/test110/openwrt_echo_core.hpp",
    "developer-tools/test110/openwrt_echo_channel.hpp",
    "native/awdl_data_frame.cpp",
    "native/awdl_data_frame.hpp",
)
HELPER_SOURCES = (
    "developer-tools/test107/arm_directed_data107.swift",
    "developer-tools/test107/IORegistryBooleanFlag107.swift",
    "developer-tools/test114/Test114RxLease.swift",
    "developer-tools/test110/matched_return_test110.c",
    "developer-tools/test110/matched_return_test110.h",
)
UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class Test124Error(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise Test124Error("duplicate_json_key")
        value[key] = item
    return value


def _private_json(path: Path, *, private_dir: Path, max_bytes: int) -> tuple[dict, bytes]:
    if not path.is_absolute() or path.is_symlink():
        raise Test124Error("private_receipt_path_invalid")
    try:
        resolved_dir = private_dir.resolve(strict=True)
        if path.parent.resolve(strict=True) != resolved_dir:
            raise Test124Error("private_receipt_outside_candidate_directory")
        directory_info = resolved_dir.stat()
        info = path.lstat()
        raw = path.read_bytes()
        owner = pwd.getpwnam("geek").pw_uid
    except (OSError, KeyError) as error:
        raise Test124Error("private_receipt_unavailable") from error
    if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_mode & 0o077 or
            not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, owner} or
            stat.S_IMODE(info.st_mode) != 0o600 or len(raw) == 0 or len(raw) > max_bytes):
        raise Test124Error("private_receipt_mode_owner_or_size_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, Test124Error) as error:
        raise Test124Error("private_receipt_malformed") from error
    if not isinstance(value, dict):
        raise Test124Error("private_receipt_not_object")
    return value, raw


def _valid_source_manifest(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    for name, digest in value.items():
        if (not isinstance(name, str) or not name or "\\" in name or
                PurePosixPath(name).is_absolute() or
                any(part in {"", ".", ".."} for part in name.split("/")) or
                not isinstance(digest, str) or SHA_RE.fullmatch(digest) is None):
            return False
    return True


def _macho_uuids(raw: bytes) -> set[str]:
    """Read LC_UUID values directly, without extracting or executing the kext."""
    def thin(data: bytes) -> set[str]:
        if len(data) < 28:
            raise Test124Error("candidate_binary_macho_header_invalid")
        little_magic = struct.unpack_from("<I", data, 0)[0]
        big_magic = struct.unpack_from(">I", data, 0)[0]
        if little_magic == 0xFEEDFACF:
            endian = "<"
        elif big_magic == 0xFEEDFACF:
            endian = ">"
        elif little_magic == 0xFEEDFACE:
            endian = "<"
        elif big_magic == 0xFEEDFACE:
            endian = ">"
        else:
            raise Test124Error("candidate_binary_macho_magic_invalid")
        ncmds = struct.unpack_from(endian + "I", data, 16)[0]
        command_offset = 32 if little_magic == 0xFEEDFACF or big_magic == 0xFEEDFACF else 28
        if command_offset > len(data) or ncmds > 100_000:
            raise Test124Error("candidate_binary_macho_commands_invalid")
        found: set[str] = set()
        for _ in range(ncmds):
            if command_offset + 8 > len(data):
                raise Test124Error("candidate_binary_macho_commands_truncated")
            command, command_size = struct.unpack_from(endian + "II", data, command_offset)
            if command_size < 8 or command_offset + command_size > len(data):
                raise Test124Error("candidate_binary_macho_command_size_invalid")
            if command == 0x1B:
                if command_size < 24:
                    raise Test124Error("candidate_binary_lc_uuid_truncated")
                import uuid
                found.add(str(uuid.UUID(bytes=data[command_offset + 8:command_offset + 24])).upper())
            command_offset += command_size
        return found

    if len(raw) < 4:
        raise Test124Error("candidate_binary_too_small")
    magic = raw[:4]
    fat_order = {b"\xca\xfe\xba\xbe": ">", b"\xbe\xba\xfe\xca": "<"}
    fat64_order = {b"\xca\xfe\xba\xbf": ">", b"\xbf\xba\xfe\xca": "<"}
    if magic not in fat_order and magic not in fat64_order:
        values = thin(raw)
    else:
        endian = fat_order.get(magic, fat64_order.get(magic))
        is64 = magic in fat64_order
        if len(raw) < 8:
            raise Test124Error("candidate_binary_fat_header_invalid")
        count = struct.unpack_from(endian + "I", raw, 4)[0]
        entry_size = 32 if is64 else 20
        if count == 0 or count > 64 or 8 + count * entry_size > len(raw):
            raise Test124Error("candidate_binary_fat_arches_invalid")
        values = set()
        for index in range(count):
            offset = 8 + index * entry_size
            if is64:
                slice_offset, slice_size = struct.unpack_from(endian + "QQ", raw, offset + 8)
            else:
                slice_offset, slice_size = struct.unpack_from(endian + "II", raw, offset + 8)
            if slice_size == 0 or slice_offset + slice_size > len(raw):
                raise Test124Error("candidate_binary_fat_slice_invalid")
            values.update(thin(raw[slice_offset:slice_offset + slice_size]))
    if not values:
        raise Test124Error("candidate_binary_uuid_missing")
    return values


def _candidate_receipt_contract(receipt: dict, receipt_raw: bytes,
                                manifest: dict, manifest_raw: bytes,
                                *, private_dir: Path) -> dict[str, Any]:
    if (receipt.get("candidate") != BUILD_ID or receipt.get("test_build") != BUILD_ID or
            receipt.get("full_build_passed") is not True or
            receipt.get("strict_signature_passed") is not True or
            receipt.get("build_inputs_unchanged") is not True or
            receipt.get("installed") is not False or receipt.get("rf_tested") is not False or
            receipt.get("compile_profile_count") != 72):
        raise Test124Error("candidate_build_receipt_contract_invalid")
    enabled = (
        "native_awdl_directed_data_compiled", "native_awdl_directed_data_enabled",
        "native_awdl_directed_prepare_compiled", "native_awdl_directed_prepare_enabled",
        "native_awdl_resident_data", "native_awdl_rx149_data_input",
        "native_awdl_rx149_observation_only", "p2p_manual_trigger", "p2p_probe",
    )
    if any(receipt.get(field) is not True for field in enabled):
        raise Test124Error("candidate_build_profile_incomplete")
    if (receipt.get("native_awdl_tx_evidence") is not False or
            receipt.get("p2p_tx_probe") is not False):
        raise Test124Error("candidate_build_tx_evidence_must_remain_disabled")
    target_os = receipt.get("target_os_build")
    if (not isinstance(target_os, str) or re.fullmatch(r"[0-9]{2}[A-Z][0-9]+[a-z]?", target_os) is None or
            type(receipt.get("target_os_abi_review_passed")) is not bool):
        raise Test124Error("candidate_target_os_review_missing")
    uuid = receipt.get("mach_o_uuid")
    if not isinstance(uuid, str) or UUID_RE.fullmatch(uuid) is None:
        raise Test124Error("candidate_build_uuid_invalid")
    for field in ("binary_sha256", "archive_sha256", "sha256", "info_plist_sha256",
                  "build_input_manifest_sha256"):
        if not isinstance(receipt.get(field), str) or SHA_RE.fullmatch(receipt[field]) is None:
            raise Test124Error("candidate_build_hash_invalid")
    if (not isinstance(receipt.get("source_commit"), str) or
            COMMIT_RE.fullmatch(receipt["source_commit"]) is None):
        raise Test124Error("candidate_source_commit_invalid")
    if (not _valid_source_manifest(manifest) or
            _sha(manifest_raw) != receipt.get("build_input_manifest_sha256")):
        raise Test124Error("candidate_source_manifest_binding_invalid")
    archive_path = private_dir / "AirportItlwm-Test124.zip"
    output = receipt.get("output")
    if not isinstance(output, str) or Path(output) != archive_path:
        raise Test124Error("candidate_archive_path_invalid")
    try:
        archive_info = archive_path.lstat()
        if not stat.S_ISREG(archive_info.st_mode) or archive_info.st_size > 128 * 1024 * 1024:
            raise Test124Error("candidate_archive_file_invalid")
        archive_sha = _sha(archive_path.read_bytes())
    except OSError as error:
        raise Test124Error("candidate_archive_unavailable") from error
    if (archive_sha != receipt["archive_sha256"] or archive_sha != receipt["sha256"]):
        raise Test124Error("candidate_archive_hash_mismatch")
    expected_members = {
        "AirportItlwm.kext/Contents/Info.plist",
        "AirportItlwm.kext/Contents/MacOS/AirportItlwm",
        "AirportItlwm.kext/Contents/_CodeSignature/CodeResources",
    }
    try:
        with ZipFile(archive_path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)) or set(names) != expected_members:
                raise Test124Error("candidate_archive_members_invalid")
            if any(stat.S_ISLNK(item.external_attr >> 16) for item in infos):
                raise Test124Error("candidate_archive_symlink_rejected")
            plist_raw = archive.read("AirportItlwm.kext/Contents/Info.plist")
            binary = archive.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
    except (OSError, BadZipFile, KeyError) as error:
        raise Test124Error("candidate_archive_unreadable") from error
    if _sha(plist_raw) != receipt["info_plist_sha256"]:
        raise Test124Error("candidate_info_plist_hash_mismatch")
    try:
        info_plist = plistlib.loads(plist_raw)
    except (ValueError, plistlib.InvalidFileException) as error:
        raise Test124Error("candidate_info_plist_invalid") from error
    if (info_plist.get("AirportTahoeBuild") != BUILD_ID or
            info_plist.get("CFBundleIdentifier") != "org.geekaudio.AirportItlwm" or
            info_plist.get("CFBundleExecutable") != "AirportItlwm"):
        raise Test124Error("candidate_info_plist_identity_mismatch")
    if _sha(binary) != receipt["binary_sha256"]:
        raise Test124Error("candidate_binary_hash_mismatch")
    if _macho_uuids(binary) != {uuid}:
        raise Test124Error("candidate_binary_uuid_mismatch")
    return {
        "candidate": BUILD_ID,
        "target_os_build": target_os,
        "target_os_abi_review_passed": receipt["target_os_abi_review_passed"],
        "mach_o_uuid": uuid,
        "binary_sha256": receipt["binary_sha256"],
        "archive_sha256": archive_sha,
        "build_receipt_sha256": _sha(receipt_raw),
        "source_input_manifest_sha256": _sha(manifest_raw),
    }


def _deployment_contract(deployment: dict, deployment_raw: bytes,
                         build: dict[str, Any], *, build_receipt_raw: bytes) -> dict[str, Any]:
    if (deployment.get("candidate") != BUILD_ID or
            deployment.get("status") != "deployed_waiting_reboot_disarmed" or
            deployment.get("automatic_reboot") is not False or
            deployment.get("mach_o_uuid") != build["mach_o_uuid"] or
            deployment.get("binary_sha256") != build["binary_sha256"] or
            deployment.get("build_report_sha256") != _sha(build_receipt_raw)):
        raise Test124Error("deployment_receipt_build_binding_invalid")
    return {"deployment_receipt_sha256": _sha(deployment_raw),
            "deployment_verified": True}


def _validate_helper_receipt(path: Path, config: dict[str, Any], build: dict[str, Any],
                             *, private_dir: Path) -> dict[str, Any]:
    helper_dir = private_dir / "tools"
    receipt, raw = _private_json(path, private_dir=helper_dir, max_bytes=65536)
    expected_path = Path(config["helper_path"])
    if not expected_path.is_absolute():
        expected_path = REPO_ROOT / expected_path
    expected_path = expected_path.resolve(strict=True)
    if (receipt.get("schema") != "test124-mode4-helper-build/v1" or
            receipt.get("candidate") != BUILD_ID or
            receipt.get("status") != "built_offline" or
            receipt.get("installed") is not False or receipt.get("rf_tested") is not False or
            receipt.get("binary_path") != str(expected_path) or
            receipt.get("binary_sha256") != config.get("helper_sha256") or
            receipt.get("source_path") != "developer-tools/test107/arm_directed_data107.swift" or
            receipt.get("source_sha256") != config.get("helper_source_sha256")):
        raise Test124Error("helper_build_receipt_binding_invalid")
    source_hashes = receipt.get("source_hashes")
    if (not isinstance(source_hashes, dict) or set(source_hashes) != set(HELPER_SOURCES) or
            any(not isinstance(digest, str) or SHA_RE.fullmatch(digest) is None
                for digest in source_hashes.values())):
        raise Test124Error("helper_all_source_hashes_required")
    try:
        if any(_sha((REPO_ROOT / name).read_bytes()) != digest
               for name, digest in source_hashes.items()):
            raise Test124Error("helper_dependency_hash_mismatch")
        actual_binary_sha = _sha(expected_path.read_bytes())
        source_path = REPO_ROOT / "developer-tools/test107/arm_directed_data107.swift"
        actual_source_sha = _sha(source_path.read_bytes())
    except OSError as error:
        raise Test124Error("helper_build_artifact_unavailable") from error
    if actual_binary_sha != receipt.get("binary_sha256") or actual_source_sha != receipt.get("source_sha256"):
        raise Test124Error("helper_build_artifact_hash_mismatch")
    return {"helper_build_receipt_sha256": _sha(raw),
            "helper_binary_sha256": actual_binary_sha,
            "helper_source_sha256": actual_source_sha}


def _validate_peer_receipt(path: Path, config: dict[str, Any], *, private_dir: Path) -> dict[str, Any]:
    receipt, raw = _private_json(path, private_dir=private_dir / "tools", max_bytes=65536)
    source_hashes = receipt.get("source_hashes")
    if (receipt.get("schema") != "test124-mode4-peer-build/v1" or
            receipt.get("candidate") != BUILD_ID or receipt.get("status") != "built_offline" or
            receipt.get("target") != "aarch64-linux-musl" or
            receipt.get("wire_contract") != "mode4-peer-unicast-ff02-allnodes/v1" or
            receipt.get("binary_path") != config["peer_binary_path_resolved"] or
            receipt.get("binary_sha256") != config["peer_sha256"] or
            not isinstance(source_hashes, dict) or set(source_hashes) != set(PEER_SOURCES)):
        raise Test124Error("peer_build_receipt_binding_invalid")
    if any(_sha((REPO_ROOT / name).read_bytes()) != digest
           for name, digest in source_hashes.items()):
        raise Test124Error("peer_dependency_hash_mismatch")
    binary = Path(config["peer_binary_path_resolved"]).read_bytes()
    if (binary[:6] != b"\x7fELF\x02\x01" or len(binary) < 20 or
            int.from_bytes(binary[18:20], "little") != 183 or
            _sha(binary) != receipt["binary_sha256"]):
        raise Test124Error("peer_binary_hash_or_architecture_mismatch")
    return {"peer_build_receipt_sha256": _sha(raw),
            "peer_binary_sha256": receipt["binary_sha256"]}


def validate_local_inputs(*, config_path: Path, build_receipt_path: Path = BUILD_RECEIPT,
                          source_manifest_path: Path = SOURCE_INPUT_MANIFEST,
                          deployment_receipt_path: Path | None = None,
                          helper_receipt_path: Path = HELPER_BUILD_RECEIPT,
                          peer_receipt_path: Path = PEER_BUILD_RECEIPT,
                          require_deployment: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt_path = Path(build_receipt_path)
    manifest_path = Path(source_manifest_path)
    if receipt_path != PRIVATE_DIR / "test124-build-private.json" or \
            manifest_path != PRIVATE_DIR / "build-input-before-private.json":
        raise Test124Error("candidate_input_paths_not_canonical")
    receipt, receipt_raw = _private_json(receipt_path, private_dir=PRIVATE_DIR, max_bytes=65536)
    manifest, manifest_raw = _private_json(manifest_path, private_dir=PRIVATE_DIR, max_bytes=2 * 1024 * 1024)
    if (receipt_path.resolve() == manifest_path.resolve() or
            os.stat(receipt_path).st_ino == os.stat(manifest_path).st_ino):
        raise Test124Error("candidate_receipt_and_source_manifest_must_be_distinct")
    candidate = _candidate_receipt_contract(receipt, receipt_raw, manifest, manifest_raw,
                                             private_dir=PRIVATE_DIR)
    config = shared.read_private_config(config_path)
    normalized, _ = shared.validate_config(config, build_id=BUILD_ID)
    if (normalized["expected_build"] != BUILD_ID or
            normalized["expected_uuid"] != candidate["mach_o_uuid"]):
        raise Test124Error("runtime_config_candidate_identity_mismatch")
    helper = _validate_helper_receipt(Path(helper_receipt_path), normalized, candidate,
                                      private_dir=PRIVATE_DIR)
    peer = _validate_peer_receipt(Path(peer_receipt_path), normalized, private_dir=PRIVATE_DIR)
    deployment: dict[str, Any] = {"deployment_verified": False}
    if deployment_receipt_path is not None:
        deployment_path = Path(deployment_receipt_path)
        if deployment_path != PRIVATE_DIR.parent / "test124-deployment-private.json":
            raise Test124Error("deployment_receipt_path_not_canonical")
        raw_deployment, deployment_raw = _private_json(
            deployment_path, private_dir=PRIVATE_DIR.parent, max_bytes=65536)
        deployment = _deployment_contract(raw_deployment, deployment_raw, candidate,
                                          build_receipt_raw=receipt_raw)
    if require_deployment and not deployment.get("deployment_verified"):
        raise Test124Error("fresh_disarmed_deployment_receipt_required")
    hashes = {**candidate, **helper, **peer, **deployment}
    return normalized, hashes


def verify_target_os(candidate: dict[str, Any]) -> None:
    """The source ABI label is not proof that a newer installed OS was reviewed."""
    if candidate.get("target_os_abi_review_passed") is not True:
        raise Test124Error("target_os_abi_review_required_before_run")
    result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.osversion"],
                            capture_output=True, text=True, timeout=5, check=False)
    if result.returncode != 0 or result.stdout.strip() != candidate["target_os_build"]:
        raise Test124Error("runtime_os_build_mismatch")


def _load_shared():
    shared_dir = REPO_ROOT / "developer-tools" / "test111"
    sys.path.insert(0, str(shared_dir))
    import coordinate_test111 as coordinator
    return coordinator


shared = _load_shared()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="absolute private T124 runtime config")
    parser.add_argument("--build-receipt", default=str(BUILD_RECEIPT))
    parser.add_argument("--source-input-manifest", default=str(SOURCE_INPUT_MANIFEST))
    parser.add_argument("--helper-build-receipt", default=str(HELPER_BUILD_RECEIPT))
    parser.add_argument("--peer-build-receipt", default=str(PEER_BUILD_RECEIPT))
    parser.add_argument("--deployment-receipt", default=str(DEPLOYMENT_RECEIPT))
    parser.add_argument("--run", action="store_true", help="run one bounded diagnostic after fresh deployment/boot")
    args = parser.parse_args(argv)
    delegated_run = False
    try:
        deployment_path = Path(args.deployment_receipt)
        if not deployment_path.exists():
            deployment_path = None
        normalized, hashes = validate_local_inputs(
            config_path=Path(args.config),
            build_receipt_path=Path(args.build_receipt),
            source_manifest_path=Path(args.source_input_manifest),
            deployment_receipt_path=deployment_path,
            helper_receipt_path=Path(args.helper_build_receipt),
            peer_receipt_path=Path(args.peer_build_receipt),
            require_deployment=args.run)
        if args.run:
            verify_target_os(hashes)
            delegated_run = True
            result = shared.execute_run(normalized, build_id=BUILD_ID)
        else:
            result = shared.make_plan(normalized, build_id=BUILD_ID)
            result["deployment_required_before_run"] = not hashes.get("deployment_verified", False)
        result.update({key: value for key, value in hashes.items() if key.endswith("sha256")})
        result["target_os_build"] = hashes["target_os_build"]
        result["target_os_abi_review_passed"] = hashes["target_os_abi_review_passed"]
        result["runtime_os_build_checked"] = bool(args.run)
        result["candidate_build_receipt_validated"] = True
        result["source_input_manifest_validated_separately"] = True
        result["hardware_action"] = bool(args.run and result.get("hardware_action"))
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 0 if not args.run or result.get("orchestration_completed") is True else 1
    except Exception as error:
        result = {
            "schema": "test124-local-coordinator/v1",
            "mode": "error",
            "build": BUILD_ID,
            "hardware_action": None if delegated_run else False,
            "ssh_attempted": None if delegated_run else False,
            "arm_attempted": None if delegated_run else False,
            "execution_outcome": "unknown_after_dispatch" if delegated_run else "not_started",
            "airdrop_proven": False,
            "error": error.__class__.__name__ + ": " + str(error),
        }
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
