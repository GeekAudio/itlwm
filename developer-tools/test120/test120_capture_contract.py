#!/usr/bin/env python3
"""Test120 receipt and terminal-sample contract.

Importing this module is inert. Its CLI is plan/read-only validation only;
the separate candidate-bound coordinator owns the gated runtime path. Runtime
callers validate current Test120 receipts and boot identity before collection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import zipfile
from typing import Callable, Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
IWN_ROOT = Path(pwd.getpwuid(REPO_ROOT.stat().st_uid).pw_dir) / (
    "Library/Application Support/IntelWirelessNative")
RUN_ROOT = IWN_ROOT / "RuntimeTest120"
PREP_ROOT = RUN_ROOT / "research/preparation-private"
ACTIVE_PRIVATE_ROOT = RUN_ROOT / "research/runtime-current-private/awdl-preparation"

CANDIDATE = "25G332-Test120"
DEFAULT_PROFILE = "native_awdl_rx149_preowner_observation"
BUILD_RECEIPT = PREP_ROOT / "test120-build-private.json"
SOURCE_COMMIT_RECEIPT = PREP_ROOT / "source-commit-private.json"
PRODUCTION_FREEZE = PREP_ROOT / "production-freeze-private.json"
BUILD_INPUT_BEFORE = PREP_ROOT / "build-input-before-private.json"
BUILD_INPUT_AFTER = PREP_ROOT / "build-input-after-private.json"
DEPLOYMENT_RECEIPT = RUN_ROOT / "research/test120-deployment-private.json"
METADATA = ACTIVE_PRIVATE_ROOT / "native-controlled-probe-private.json"
RUNTIME_HANDOFF = RUN_ROOT / "research/runtime-handoff-private.json"
SENDER_REUSE_RECEIPT = TOOL_DIR / "sender-reuse-receipt-test120.json"
TEST119_SENDER_RECEIPT = (
    IWN_ROOT / "RuntimeTest119/research/runtime-1793637912-private/"
    "awdl-preparation/sender-build-private.json")
TEST119_SENDER_RECEIPT_RELATIVE = (
    "RuntimeTest119/research/runtime-1793637912-private/"
    "awdl-preparation/sender-build-private.json")

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UUID_RE = re.compile(r"^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$")

STATE_NAMES = {
    0: "idle",
    1: "disabled",
    2: "deferred",
    3: "queued",
    4: "adding",
    5: "added",
    6: "removing",
    7: "complete_released",
    8: "quarantined",
    9: "reset_drained",
    10: "exercise_failed_cleaned",
}

# These are numeric IORegistry properties. Missing values and Python bools
# remain unknown; neither is coerced to zero or success.
FINAL_SAMPLE_PROPERTIES = {
    "Selected": "NativeP2PRx149Selected",
    "Attempted": "NativeP2PProbeAttempted",
    "State": "NativeP2PProbeState",
    "ResourceMayExist": "NativeP2PProbeResourceMayExist",
    "EndSeen": "NativeP2PRocEndSeen",
    "RecoveryAttempted": "NativeP2PProbeExerciseRecoveryAttempted",
    "ProofAccepted": "NativeP2PProbeExerciseRecoveryProofAccepted",
    "ExerciseResult": "NativeP2PProbeExerciseResult",
    "RemoveResult": "NativeP2PProbeRemoveResult",
}
_BOOLEAN_NUMBERS = {
    "Selected", "Attempted", "ResourceMayExist", "EndSeen",
    "RecoveryAttempted", "ProofAccepted",
}


class ContractError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8"))


def _safe_relative(name: Any) -> bool:
    if not isinstance(name, str) or not name or "\x00" in name:
        return False
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts


def validate_sender_reuse_fields(receipt: dict, *, source: bytes,
                                 protocol: bytes, binary: bytes) -> dict:
    """Verify the explicit Test119 reuse receipt without claiming a Test120 build."""
    if not isinstance(receipt, dict):
        raise ContractError("sender_reuse_receipt_not_object")
    checks = (
        receipt.get("schema") == "test120-reused-sender-offline-validation/v1",
        receipt.get("candidate") == CANDIDATE,
        receipt.get("reused_from") == "25G332-Test119",
        receipt.get("validated_offline") is True,
        receipt.get("newly_compiled_for_test120") is False,
        receipt.get("rf_tested") is False,
    )
    source_meta = receipt.get("source")
    protocol_meta = receipt.get("protocol")
    binary_meta = receipt.get("binary")
    if not all(checks):
        raise ContractError("sender_reuse_receipt_contract_invalid")
    if (not isinstance(source_meta, dict) or
            source_meta.get("repo_path") !=
            "developer-tools/test119/awdl_unicast_sender_test119.c" or
            source_meta.get("sha256") != sha256(source)):
        raise ContractError("sender_reuse_source_mismatch")
    if (not isinstance(protocol_meta, dict) or
            protocol_meta.get("repo_path") !=
            "developer-tools/test119/dual_sender_protocol_test119.py" or
            protocol_meta.get("schema") != "test119-dual-socket-sender/v1" or
            protocol_meta.get("sha256") != sha256(protocol)):
        raise ContractError("sender_reuse_protocol_mismatch")
    if (not isinstance(binary_meta, dict) or
            binary_meta.get("target") != "aarch64-linux-musl" or
            binary_meta.get("sha256") != sha256(binary) or
            binary_meta.get("exit_code") != 0 or
            binary_meta.get("private_receipt") != TEST119_SENDER_RECEIPT_RELATIVE):
        raise ContractError("sender_reuse_binary_mismatch")
    return {
        "reused_from": receipt["reused_from"],
        "validated_offline": True,
        "newly_compiled_for_test120": False,
        "rf_tested": False,
        "source_sha256": source_meta["sha256"],
        "protocol_schema": protocol_meta["schema"],
        "protocol_sha256": protocol_meta["sha256"],
        "binary_sha256": binary_meta["sha256"],
    }


def verify_local_sender_reuse() -> dict:
    """Verify the versioned receipt against real Test119 files and private receipt."""
    try:
        receipt = json.loads(SENDER_REUSE_RECEIPT.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ContractError("sender_reuse_receipt_unavailable") from error
    source = REPO_ROOT / "developer-tools/test119/awdl_unicast_sender_test119.c"
    protocol = REPO_ROOT / "developer-tools/test119/dual_sender_protocol_test119.py"
    for path in (source, protocol, TEST119_SENDER_RECEIPT):
        if path.is_symlink() or not path.is_file():
            raise ContractError("sender_reuse_input_unavailable:" + path.name)
    private = read_private_json(TEST119_SENDER_RECEIPT)
    if (private.get("schema") != "test119-sender-build-private/v1" or
            private.get("candidate") != "25G332-Test119" or
            private.get("exit_code") != 0 or private.get("rf_tested") is not False):
        raise ContractError("test119_sender_receipt_invalid")
    source_path = Path(str(private.get("source_path", "")))
    if not source_path.is_absolute():
        source_path = REPO_ROOT / source_path
    protocol_path = Path(str(private.get("protocol_source_path", "")))
    if (not protocol_path.is_absolute() or
            protocol_path.resolve(strict=False) != protocol.resolve(strict=True) or
            source_path.resolve(strict=False) != source.resolve(strict=True) or
            private.get("target") != "aarch64-linux-musl"):
        raise ContractError("test119_sender_source_or_target_mismatch")
    binary_path = Path(str(private.get("binary_path", "")))
    if binary_path.is_symlink() or not binary_path.is_file():
        raise ContractError("test119_sender_binary_unavailable")
    try:
        binary_path.resolve(strict=True).relative_to(
            (IWN_ROOT / "RuntimeTest119").resolve(strict=True))
    except (ValueError, OSError) as error:
        raise ContractError("test119_sender_binary_outside_private_runtime") from error
    if (private.get("source_sha256") != sha256(source.read_bytes()) or
            private.get("protocol_source_sha256") != sha256(protocol.read_bytes()) or
            private.get("binary_sha256") != sha256(binary_path.read_bytes()) or
            private.get("protocol_schema") != "test119-dual-socket-sender/v1"):
        raise ContractError("test119_sender_private_binding_mismatch")
    return validate_sender_reuse_fields(
        receipt, source=source.read_bytes(), protocol=protocol.read_bytes(),
        binary=binary_path.read_bytes())


def read_private_json(path: Path) -> dict:
    value, _raw = read_private_document(path)
    return value


def read_private_document(path: Path) -> tuple[dict, bytes]:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ContractError("private_path_invalid:" + path.name)
    try:
        info = path.lstat()
        raw = path.read_bytes()
        parent_info = path.parent.lstat()
    except OSError as error:
        raise ContractError("private_receipt_unavailable:" + path.name) from error
    owner_uid = REPO_ROOT.stat().st_uid
    private_parent = (stat.S_ISDIR(parent_info.st_mode) and
                      parent_info.st_uid == owner_uid and
                      stat.S_IMODE(parent_info.st_mode) == 0o700)
    private_file = stat.S_IMODE(info.st_mode) == 0o600
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
            info.st_mode & 0o022 or not (private_file or private_parent)):
        raise ContractError("private_receipt_owner_or_mode_invalid:" + path.name)
    try:
        value = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise ContractError("private_receipt_malformed:" + path.name) from error
    if not isinstance(value, dict):
        raise ContractError("private_receipt_not_object:" + path.name)
    return value, raw


def verify_source_freeze(build: dict, source_commit: dict, freeze: dict,
                         build_inputs_before: dict, build_inputs_after: dict,
                         *, repo_root: Path = REPO_ROOT,
                         git_show: Callable[[str, str], bytes] | None = None) -> dict:
    """Bind freeze, pre/post build inputs, and source commit without a pinned SHA."""
    if not all(isinstance(item, dict) for item in
               (build, source_commit, freeze, build_inputs_before, build_inputs_after)):
        raise ContractError("source_binding_receipts_not_objects")
    commit = build.get("source_commit")
    if (not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit) or
            source_commit.get("commit") != commit or
            source_commit.get("pushed") is not True):
        raise ContractError("build_source_commit_receipt_mismatch")
    if (not freeze or build_inputs_before != build_inputs_after or
            build.get("build_inputs_unchanged") is not True):
        raise ContractError("build_input_or_freeze_mismatch")
    if not callable(git_show):
        def git_show(commit_id: str, relative: str) -> bytes:
            result = subprocess.run(
                ["git", "show", f"{commit_id}:{relative}"], cwd=repo_root,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False, timeout=10)
            if result.returncode:
                raise ContractError("frozen_source_missing_from_commit:" + Path(relative).name)
            return result.stdout
    for relative, expected in freeze.items():
        if (not _safe_relative(relative) or not isinstance(expected, str) or
                not SHA256_RE.fullmatch(expected)):
            raise ContractError("production_freeze_manifest_invalid")
        if sha256(git_show(commit, relative)) != expected:
            raise ContractError("production_freeze_commit_mismatch:" + Path(relative).name)
        if build_inputs_after.get(relative) != expected:
            raise ContractError("production_freeze_build_input_mismatch:" + Path(relative).name)
    return {
        "source_commit": commit,
        "source_commit_pushed": True,
        "production_freeze_manifest_sha256": canonical_json_sha256(freeze),
        "build_input_manifest_sha256": canonical_json_sha256(build_inputs_after),
        "build_inputs_unchanged": True,
    }


def verify_source_freeze_raw(build: dict, source_commit_raw: bytes,
                             freeze_raw: bytes, before_raw: bytes,
                             after_raw: bytes, *, repo_root: Path = REPO_ROOT,
                             git_show: Callable[[str, str], bytes] | None = None) -> dict:
    """Strict private-file variant that also binds exact receipt bytes."""
    try:
        source_commit = json.loads(source_commit_raw)
        freeze = json.loads(freeze_raw)
        before = json.loads(before_raw)
        after = json.loads(after_raw)
    except (ValueError, TypeError) as error:
        raise ContractError("source_binding_receipt_json_invalid") from error
    if (not isinstance(source_commit, dict) or not isinstance(freeze, dict) or
            not isinstance(before, dict) or not isinstance(after, dict) or
            before != after or sha256(before_raw) != sha256(after_raw) or
            build.get("build_input_manifest_sha256") != sha256(after_raw)):
        raise ContractError("build_input_receipt_hash_mismatch")
    result = verify_source_freeze(
        build, source_commit, freeze, before, after,
        repo_root=repo_root, git_show=git_show)
    result["production_freeze_manifest_sha256"] = sha256(freeze_raw)
    result["build_input_manifest_sha256"] = sha256(after_raw)
    result["source_commit_receipt_sha256"] = sha256(source_commit_raw)
    return result


def verify_build_receipt(build: dict) -> None:
    if (not isinstance(build, dict) or build.get("candidate") != CANDIDATE or
            build.get("full_build_passed") is not True or
            build.get("strict_signature_passed") is not True or
            build.get("build_inputs_unchanged") is not True or
            build.get("rf_tested") is not False or
            not UUID_RE.fullmatch(str(build.get("mach_o_uuid", ""))) or
            not SHA256_RE.fullmatch(str(build.get("archive_sha256", ""))) or
            not SHA256_RE.fullmatch(str(build.get("binary_sha256", ""))) or
            not SHA256_RE.fullmatch(str(build.get("info_plist_sha256", "")))):
        raise ContractError("test120_build_receipt_invalid")


def validate_preparation_bundle(*, repo_root: Path = REPO_ROOT,
                                git_show: Callable[[str, str], bytes] | None = None) -> dict:
    """Read and bind the actual Test120 source/build/archive/deployment receipts."""
    build, build_raw = read_private_document(BUILD_RECEIPT)
    commit, commit_raw = read_private_document(SOURCE_COMMIT_RECEIPT)
    freeze, freeze_raw = read_private_document(PRODUCTION_FREEZE)
    before, before_raw = read_private_document(BUILD_INPUT_BEFORE)
    after, after_raw = read_private_document(BUILD_INPUT_AFTER)
    deployment, deployment_raw = read_private_document(DEPLOYMENT_RECEIPT)
    verify_build_receipt(build)
    source = verify_source_freeze_raw(
        build, commit_raw, freeze_raw, before_raw, after_raw,
        repo_root=repo_root, git_show=git_show)
    archive = verify_archive(build)
    verify_deployment(build, deployment)
    return {
        "candidate": CANDIDATE,
        "profile": (build.get("profile") if isinstance(build.get("profile"), str)
                    and build["profile"] else DEFAULT_PROFILE),
        "mach_o_uuid": build["mach_o_uuid"],
        "build_receipt_sha256": sha256(build_raw),
        "deployment_receipt_sha256": sha256(deployment_raw),
        "archive_sha256": archive["archive_sha256"],
        "source_commit": source["source_commit"],
        "production_freeze_manifest_sha256":
            source["production_freeze_manifest_sha256"],
        "source_commit_receipt_sha256": source["source_commit_receipt_sha256"],
        "minimum_boot_epoch_exclusive":
            deployment.get("minimum_boot_epoch_exclusive"),
        "build_verified": True,
        "archive_verified": True,
        "deployment_verified": True,
        "freeze_verified": True,
    }


def validate_runtime_metadata(metadata: dict, binding: dict) -> dict:
    """Bind a disarmed runtime metadata file to the verified Test120 receipts."""
    source = metadata.get("source_binding") if isinstance(metadata, dict) else None
    if (not isinstance(metadata, dict) or not isinstance(source, dict) or
            metadata.get("candidate") != CANDIDATE or
            metadata.get("profile") != binding.get("profile") or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("armed") is not False or
            metadata.get("retry_allowed") is not False or
            metadata.get("host_management_or_data_tx_allowed") is not False or
            metadata.get("expected_loaded_uuid") != binding.get("mach_o_uuid") or
            type(metadata.get("minimum_boot_epoch_exclusive")) is not int or
            metadata.get("minimum_boot_epoch_exclusive", 0) <= 0 or
            source.get("build_receipt_sha256") != binding.get("build_receipt_sha256") or
            source.get("deployment_receipt_sha256") !=
            binding.get("deployment_receipt_sha256") or
            source.get("archive_sha256") != binding.get("archive_sha256") or
            source.get("source_commit") != binding.get("source_commit") or
            source.get("production_freeze_manifest_sha256") !=
            binding.get("production_freeze_manifest_sha256")):
        raise ContractError("test120_disarmed_runtime_metadata_binding_invalid")
    return {
        **binding,
        "minimum_boot_epoch_exclusive": metadata["minimum_boot_epoch_exclusive"],
    }


def read_actual_runtime_snapshot(binding: dict) -> dict:
    """Read only boot epoch and loaded kext UUID; never changes radio or EFI."""
    boot_result = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "kern.boottime"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        check=False, timeout=5)
    if boot_result.returncode:
        raise ContractError("actual_boot_epoch_unavailable")
    match = re.search(r"\bsec\s*=\s*(\d+)", boot_result.stdout)
    if not match:
        raise ContractError("actual_boot_epoch_unavailable")
    loaded_result = subprocess.run(
        ["/usr/bin/kmutil", "showloaded", "--list-only"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, check=False, timeout=10)
    if loaded_result.returncode:
        raise ContractError("actual_loaded_kext_list_unavailable")
    loaded_uuids = re.findall(
        r"org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})",
        loaded_result.stdout)
    if len(loaded_uuids) != 1:
        raise ContractError("actual_loaded_kext_uuid_ambiguous")
    snapshot = {
        "candidate": CANDIDATE,
        "boot_epoch": int(match.group(1)),
        "loaded_bundle_id": "org.geekaudio.AirportItlwm",
        "loaded_uuid": loaded_uuids[0],
        "build_receipt_sha256": binding.get("build_receipt_sha256"),
        "deployment_receipt_sha256": binding.get("deployment_receipt_sha256"),
        "archive_sha256": binding.get("archive_sha256"),
        "source_commit": binding.get("source_commit"),
        "production_freeze_manifest_sha256":
            binding.get("production_freeze_manifest_sha256"),
    }
    validate_runtime_snapshot(snapshot, binding)
    return snapshot


def validate_current_runtime() -> dict:
    """Join private Test120 receipts, disarmed metadata, handoff, and live boot UUID."""
    binding = validate_preparation_bundle()
    metadata = read_private_json(METADATA)
    binding = validate_runtime_metadata(metadata, binding)
    handoff = read_private_json(RUNTIME_HANDOFF)
    if (handoff.get("candidate") != CANDIDATE or
            handoff.get("active_awdl_rf_allowed") is not True or
            handoff.get("sleep_test_allowed") is not False or
            handoff.get("expected_loaded_uuid") != binding.get("mach_o_uuid") or
            handoff.get("expected_binary_sha256") !=
            read_private_json(BUILD_RECEIPT).get("binary_sha256") or
            handoff.get("minimum_boot_epoch_exclusive") !=
            binding.get("minimum_boot_epoch_exclusive")):
        raise ContractError("test120_runtime_handoff_binding_invalid")
    runtime = read_actual_runtime_snapshot(binding)
    return {
        "candidate": CANDIDATE,
        "profile": binding["profile"],
        "boot_epoch": runtime["boot_epoch"],
        "loaded_uuid": runtime["loaded_uuid"],
        "build_receipt_sha256": binding["build_receipt_sha256"],
        "deployment_receipt_sha256": binding["deployment_receipt_sha256"],
        "archive_sha256": binding["archive_sha256"],
        "source_commit": binding["source_commit"],
        "production_freeze_manifest_sha256":
            binding["production_freeze_manifest_sha256"],
        "runtime_identity_verified": True,
        "rf_authorized": True,
        "sleep_test_allowed": False,
    }


def verify_archive(build: dict, *, run_root: Path = RUN_ROOT,
                   uuid_reader: Callable[[Path], str] | None = None) -> dict:
    verify_build_receipt(build)
    archive = Path(str(build.get("output", "")))
    if archive.is_symlink() or not archive.is_absolute() or not archive.is_file():
        raise ContractError("test120_archive_unavailable")
    try:
        archive.resolve(strict=True).relative_to(run_root.resolve(strict=True))
    except (ValueError, OSError) as error:
        raise ContractError("test120_archive_outside_private_runtime") from error
    raw = archive.read_bytes()
    if sha256(raw) != build.get("archive_sha256"):
        raise ContractError("test120_archive_hash_mismatch")
    try:
        with zipfile.ZipFile(archive) as package:
            binary = package.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
            info = package.read("AirportItlwm.kext/Contents/Info.plist")
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        raise ContractError("test120_archive_payload_invalid") from error
    if (sha256(binary) != build.get("binary_sha256") or
            sha256(info) != build.get("info_plist_sha256")):
        raise ContractError("test120_archive_payload_hash_mismatch")
    if uuid_reader is None:
        def uuid_reader(binary_path: Path) -> str:
            result = subprocess.run(
                ["xcrun", "dwarfdump", "--uuid", str(binary_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, check=False, timeout=20)
            found = re.findall(r"UUID: ([0-9A-F-]{36}) \(x86_64\)", result.stdout)
            if result.returncode or len(found) != 1:
                raise ContractError("test120_archive_uuid_unavailable")
            return found[0]
    import tempfile
    with tempfile.TemporaryDirectory(prefix="iwn-test120-uuid-") as directory:
        executable = Path(directory) / "AirportItlwm"
        executable.write_bytes(binary)
        uuid = uuid_reader(executable)
    if uuid != build.get("mach_o_uuid"):
        raise ContractError("test120_archive_uuid_mismatch")
    return {
        "archive_sha256": sha256(raw),
        "binary_sha256": sha256(binary),
        "info_plist_sha256": sha256(info),
        "mach_o_uuid": uuid,
        "archive_identity_verified": True,
    }


def verify_deployment(build: dict, deployment: dict) -> None:
    if (deployment.get("candidate") != CANDIDATE or
            deployment.get("mach_o_uuid") != build.get("mach_o_uuid") or
            deployment.get("binary_sha256") != build.get("binary_sha256") or
            deployment.get("info_plist_sha256") != build.get("info_plist_sha256") or
            deployment.get("config_unchanged") is not True or
            deployment.get("unrelated_paths_written") is not False or
            deployment.get("remount_readback_verified") is not True or
            deployment.get("minimal_backup_verified") is not True or
            deployment.get("older_driver_activated") is not False):
        raise ContractError("test120_deployment_receipt_binding_invalid")


def validate_runtime_snapshot(snapshot: dict, binding: dict) -> None:
    """Fail-closed check for actual post-deploy boot and artifact identities."""
    if not isinstance(snapshot, dict) or not isinstance(binding, dict):
        raise ContractError("runtime_snapshot_or_binding_invalid")
    required = (
        "candidate", "boot_epoch", "loaded_bundle_id", "loaded_uuid",
        "build_receipt_sha256", "deployment_receipt_sha256",
        "archive_sha256", "source_commit", "production_freeze_manifest_sha256",
    )
    if any(key not in snapshot for key in required):
        raise ContractError("runtime_snapshot_incomplete")
    if (not UUID_RE.fullmatch(str(binding.get("mach_o_uuid", ""))) or
            any(not SHA256_RE.fullmatch(str(binding.get(key, ""))) for key in (
                "build_receipt_sha256", "deployment_receipt_sha256",
                "archive_sha256", "production_freeze_manifest_sha256")) or
            not COMMIT_RE.fullmatch(str(binding.get("source_commit", ""))) or
            type(binding.get("minimum_boot_epoch_exclusive")) is not int or
            binding["minimum_boot_epoch_exclusive"] <= 0):
        raise ContractError("runtime_binding_incomplete")
    if (snapshot.get("candidate") != CANDIDATE or
            snapshot.get("loaded_bundle_id") != "org.geekaudio.AirportItlwm" or
            snapshot.get("loaded_uuid") != binding.get("mach_o_uuid") or
            type(snapshot.get("boot_epoch")) is not int or
            type(binding.get("minimum_boot_epoch_exclusive")) is not int or
            snapshot["boot_epoch"] <= binding["minimum_boot_epoch_exclusive"] or
            snapshot.get("build_receipt_sha256") != binding.get("build_receipt_sha256") or
            snapshot.get("deployment_receipt_sha256") != binding.get("deployment_receipt_sha256") or
            snapshot.get("archive_sha256") != binding.get("archive_sha256") or
            snapshot.get("source_commit") != binding.get("source_commit") or
            snapshot.get("production_freeze_manifest_sha256") !=
            binding.get("production_freeze_manifest_sha256")):
        raise ContractError("test120_actual_runtime_identity_mismatch")


def normalize_final_sample(properties: dict) -> dict:
    """Return only the nine bounded numeric fields requested for a final sample."""
    if not isinstance(properties, dict):
        raise ContractError("probe_sample_not_object")
    values: dict[str, int | None] = {}
    invalid: list[str] = []
    missing: list[str] = []
    for alias, property_name in FINAL_SAMPLE_PROPERTIES.items():
        if property_name not in properties:
            values[alias] = None
            missing.append(alias)
            continue
        value = properties[property_name]
        if type(value) is not int or value < 0:
            values[alias] = None
            invalid.append(alias)
            continue
        if alias in _BOOLEAN_NUMBERS and value not in (0, 1):
            values[alias] = None
            invalid.append(alias)
            continue
        if alias == "State" and value not in STATE_NAMES:
            values[alias] = None
            invalid.append(alias)
            continue
        values[alias] = value
    values["StateName"] = STATE_NAMES.get(values["State"]) if values["State"] is not None else None
    values["missing_fields"] = missing
    values["invalid_fields"] = invalid
    values["interpretation"] = classify_final_sample(values)
    return values


def report_final_probe_sample(properties: dict, *, sample_index: int) -> dict:
    """Create the report fragment attached to each final Test087 HAL sample.

    The caller supplies a single same-snapshot IORegistry property mapping.
    Only the nine whitelisted numeric fields leave this helper; unrelated
    properties such as interface addresses and known-network data are omitted.
    """
    if type(sample_index) is not int or sample_index < 0:
        raise ContractError("probe_sample_index_invalid")
    return {
        "schema": "test120-native-p2p-probe-lifecycle/v1",
        "sample_index": sample_index,
        **normalize_final_sample(properties),
        "rx_or_peer_delivery_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def attach_final_probe_samples(report: dict, raw_samples: list[dict]) -> dict:
    """Attach sanitized lifecycle fields for every final same-boot sample."""
    if not isinstance(report, dict) or not isinstance(raw_samples, list):
        raise ContractError("probe_report_or_samples_invalid")
    report["native_p2p_probe_lifecycle_samples"] = [
        report_final_probe_sample(sample, sample_index=index)
        for index, sample in enumerate(raw_samples)
    ]
    report["native_p2p_probe_lifecycle_claim_limit"] = (
        "HAL lifecycle only; no RX, peer, native awdl0, or AirDrop proof")
    return report


def classify_final_sample(sample: dict) -> str:
    """Classify lifecycle only; this never claims RX, peer, or AirDrop success."""
    required = tuple(FINAL_SAMPLE_PROPERTIES)
    if not isinstance(sample, dict) or any(sample.get(key) is None for key in required):
        return "unknown_incomplete_sample"
    if sample["Selected"] == 0 and sample["Attempted"] == 0:
        return "not_selected"
    if sample["Selected"] != 1 or sample["Attempted"] != 1:
        return "inconsistent_selection_or_attempt"
    state = sample["State"]
    if state == 8:
        return "quarantined_resource_may_exist" if sample["ResourceMayExist"] == 1 else "quarantined"
    if state == 9:
        return "reset_drained_not_a_successful_experiment"
    if state == 10:
        if (sample["RecoveryAttempted"] == 1 and sample["ProofAccepted"] == 1 and
                sample["ExerciseResult"] != 0 and sample["ResourceMayExist"] == 0 and
                sample["RemoveResult"] == 0):
            return "exercise_failed_but_safely_cleaned"
        return "exercise_failed_cleanup_unproven"
    if state == 7:
        if (sample["EndSeen"] == 1 and sample["RecoveryAttempted"] == 0 and
                sample["ProofAccepted"] == 0 and
                sample["ExerciseResult"] == 0 and sample["ResourceMayExist"] == 0 and
                sample["RemoveResult"] == 0):
            return "probe_completed_and_released"
        return "terminal_complete_but_evidence_incomplete"
    return "not_terminal"


def plan() -> dict:
    return {
        "candidate": CANDIDATE,
        "profile": DEFAULT_PROFILE,
        "channel": 149,
        "sender_reuse": "Test119 source/protocol/binary; receipt declares no Test120 rebuild",
        "runtime_root": "RuntimeTest120/research/runtime-current-private/awdl-preparation",
        "default_action": "plan_only",
        "armed": False,
        "router_contacted": False,
        "scan_triggered": False,
        "rf_triggered": False,
        "efi_modified": False,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-reuse-receipt", action="store_true")
    parser.add_argument("--verify-preparation-receipts", action="store_true")
    parser.add_argument("--verify-current-runtime", action="store_true")
    args = parser.parse_args(argv)
    try:
        selected = sum((args.verify_reuse_receipt, args.verify_preparation_receipts,
                        args.verify_current_runtime))
        if selected > 1:
            raise ContractError("choose_one_read_only_verification")
        if args.verify_reuse_receipt:
            result = verify_local_sender_reuse()
        elif args.verify_preparation_receipts:
            result = validate_preparation_bundle()
        elif args.verify_current_runtime:
            result = validate_current_runtime()
        else:
            result = plan()
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        code = getattr(error, "code", None) or str(error)[:120] or type(error).__name__
        print("ERROR: " + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
