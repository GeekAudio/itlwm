#!/usr/bin/env python3
"""Private Test118 receipt binding for one bounded channel-149 run.

The Test118 build/deployment receipts keep their real schema and status. This
module verifies those receipts and creates a separate disarmed run bundle; it
does not rewrite or normalize either receipt into a Test104 build claim.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import tempfile
import zipfile


CANDIDATE = "25G332-Test118"
PROFILE = "native_awdl_rx149_preowner_observation"
REPO_ROOT = Path(__file__).resolve().parents[2]
_OWNER = pwd.getpwuid(REPO_ROOT.stat().st_uid)
IWN_ROOT = Path(_OWNER.pw_dir) / "Library/Application Support/IntelWirelessNative"
RUN_ROOT = IWN_ROOT / "RuntimeTest118"
PREP_ROOT = RUN_ROOT / "research/preparation-private"
ACTIVE_PRIVATE_ROOT = RUN_ROOT / "research/runtime-1793631755-private/awdl-preparation"
BUILD_RECEIPT = PREP_ROOT / "test118-build-private.json"
DEPLOYMENT_RECEIPT = RUN_ROOT / "research/test118-deployment-private.json"
SOURCE_COMMIT_RECEIPT = PREP_ROOT / "source-commit-private.json"
PRODUCTION_FREEZE = PREP_ROOT / "production-freeze-private.json"
BUILD_INPUT_AFTER = PREP_ROOT / "build-input-after-private.json"
BUILD_INPUT_BEFORE = PREP_ROOT / "build-input-before-private.json"
SENDER_RECEIPT = ACTIVE_PRIVATE_ROOT / "sender-build-private.json"
ROUTER_RECEIPT = ACTIVE_PRIVATE_ROOT / "router-identity-private.json"
TARGET_RECEIPT = ACTIVE_PRIVATE_ROOT / "target-awdl0-identity-private.json"
METADATA = ACTIVE_PRIVATE_ROOT / "native-controlled-probe-private.json"
RUNTIME_HANDOFF = RUN_ROOT / "research/runtime-1793631755-private/runtime-handoff-private.json"
ARM_HELPER = REPO_ROOT / "developer-tools/test104/arm_p2p_rx149_test104.swift"
SENDER_CONTRACT = {
    "execution_host": "OpenWrt aarch64 router",
    "transport": "AF_PACKET SOCK_RAW on temporary 149-channel radiotap monitor",
    "frames_max": 4,
    "interval_ms": 10,
    "send_budget_ms": 40,
    "radiotap_bytes": 10,
    "mpdu_bytes": 96,
    "packet_bytes": 106,
    "radiotap_tx_flags": "NOSEQNO",
    "max_elapsed_seconds": 0.04,
    "noack_requested": False,
    "ack_policy": "normal unicast ACK requested; hardware handling unknown",
    "single_nonce_go": True,
    "retry_after_go": False,
    "raw_txs_source_available": False,
    "native_positive_independent_of_raw_txs": True,
}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$")


class BindingError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _account():
    return pwd.getpwuid(REPO_ROOT.stat().st_uid)


def read_private(path: Path) -> tuple[dict, bytes]:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise BindingError("private_path_invalid")
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise BindingError("private_receipt_unavailable:" + path.name) from error
    try:
        parent_info = path.parent.lstat()
    except OSError as error:
        raise BindingError("private_receipt_parent_unavailable:" + path.name) from error
    parent_private = (stat.S_ISDIR(parent_info.st_mode) and
                      parent_info.st_uid == _account().pw_uid and
                      stat.S_IMODE(parent_info.st_mode) == 0o700)
    file_private = stat.S_IMODE(info.st_mode) == 0o600
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != _account().pw_uid or
            info.st_mode & 0o022 or not (file_private or parent_private)):
        raise BindingError("private_receipt_owner_or_mode_invalid:" + path.name)
    try:
        value = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise BindingError("private_receipt_malformed:" + path.name) from error
    if not isinstance(value, dict):
        raise BindingError("private_receipt_not_object:" + path.name)
    return value, raw


def _verify_source_commit() -> tuple[str, dict, str, dict]:
    source_receipt, _ = read_private(SOURCE_COMMIT_RECEIPT)
    manifest, manifest_raw = read_private(PRODUCTION_FREEZE)
    inputs, inputs_raw = read_private(BUILD_INPUT_AFTER)
    inputs_before, inputs_before_raw = read_private(BUILD_INPUT_BEFORE)
    commit = source_receipt.get("commit")
    if (commit != "a86fa65c53b58afbdeb1f4c73452b900890c2c21" or
            source_receipt.get("pushed") is not True or
            not isinstance(manifest, dict) or not manifest or
            not isinstance(inputs, dict) or inputs != inputs_before or
            sha256(inputs_before_raw) != sha256(inputs_raw) or
            sha256(inputs_raw) != _build_receipt().get("build_input_manifest_sha256")):
        raise BindingError("test118_source_receipt_binding_invalid")
    for relative, expected in manifest.items():
        if (not isinstance(relative, str) or not isinstance(expected, str) or
                not SHA_RE.fullmatch(expected) or Path(relative).is_absolute() or
                ".." in Path(relative).parts):
            raise BindingError("production_freeze_manifest_invalid")
        result = subprocess.run(
            ["git", "show", f"{commit}:{relative}"], cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=10)
        if result.returncode != 0 or sha256(result.stdout) != expected:
            raise BindingError("production_freeze_commit_mismatch:" + Path(relative).name)
    return commit, manifest, sha256(manifest_raw), inputs


def _build_receipt() -> dict:
    receipt, _ = read_private(BUILD_RECEIPT)
    return receipt


def _verify_archive(build: dict) -> dict:
    archive = Path(str(build.get("output", "")))
    if (not archive.is_absolute() or archive.is_symlink() or not archive.is_file()):
        raise BindingError("test118_archive_unavailable")
    try:
        archive.resolve(strict=True).relative_to(RUN_ROOT.resolve(strict=True))
    except (ValueError, OSError) as error:
        raise BindingError("test118_archive_outside_private_runtime") from error
    archive_raw = archive.read_bytes()
    archive_sha = build.get("archive_sha256")
    if not isinstance(archive_sha, str) or sha256(archive_raw) != archive_sha:
        raise BindingError("test118_archive_hash_mismatch")
    try:
        with zipfile.ZipFile(archive) as package:
            binary = package.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
            info = package.read("AirportItlwm.kext/Contents/Info.plist")
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        raise BindingError("test118_archive_payload_invalid") from error
    if sha256(binary) != build.get("binary_sha256"):
        raise BindingError("test118_archive_binary_hash_mismatch")
    if sha256(info) != build.get("info_plist_sha256"):
        raise BindingError("test118_archive_info_hash_mismatch")
    with tempfile.TemporaryDirectory(prefix="iwn-test118-uuid-") as directory:
        executable = Path(directory) / "AirportItlwm"
        executable.write_bytes(binary)
        result = subprocess.run(
            ["xcrun", "dwarfdump", "--uuid", str(executable)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, check=False, timeout=20)
    uuids = re.findall(r"UUID: ([0-9A-F-]{36}) \(x86_64\)", result.stdout)
    if result.returncode != 0 or uuids != [build.get("mach_o_uuid")]:
        raise BindingError("test118_archive_uuid_mismatch")
    return {"archive_path": str(archive), "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary), "info_plist_sha256": sha256(info),
            "mach_o_uuid": uuids[0], "archive_identity_verified": True}


def _verify_deployment(build: dict) -> tuple[dict, bytes]:
    deployment, raw = read_private(DEPLOYMENT_RECEIPT)
    if (deployment.get("candidate") != CANDIDATE or
            deployment.get("mach_o_uuid") != build.get("mach_o_uuid") or
            deployment.get("binary_sha256") != build.get("binary_sha256") or
            deployment.get("info_plist_sha256") != build.get("info_plist_sha256") or
            deployment.get("config_unchanged") is not True or
            deployment.get("unrelated_paths_written") is not False or
            deployment.get("remount_readback_verified") is not True or
            deployment.get("minimal_backup_verified") is not True or
            deployment.get("older_driver_activated") is not False):
        raise BindingError("test118_deployment_receipt_binding_invalid")
    return deployment, raw


def _sender_binding() -> tuple[dict, bytes, dict]:
    sender, raw = read_private(SENDER_RECEIPT)
    source_path = Path(str(sender.get("source_path", "")))
    binary_path = Path(str(sender.get("binary_path", "")))
    if not source_path.is_absolute():
        source_path = REPO_ROOT / source_path
    for path in (source_path, binary_path):
        if path.is_symlink() or not path.is_file():
            raise BindingError("test118_sender_artifact_unavailable")
    source_relative = source_path.resolve(strict=True).relative_to(REPO_ROOT.resolve(strict=True))
    if (source_relative.as_posix() != "developer-tools/test104/awdl_unicast_sender_test104.c" or
            sha256(source_path.read_bytes()) != sender.get("source_sha256") or
            sha256(binary_path.read_bytes()) != sender.get("binary_sha256") or
            sender.get("candidate") != CANDIDATE or sender.get("exit_code") != 0 or
            sender.get("rf_tested") is not False):
        raise BindingError("test118_sender_receipt_binding_invalid")
    binding = {
        "schema": "test104-unicast-sender/v1",
        "source_path": source_relative.as_posix(),
        "source_sha256": sender["source_sha256"],
        "binary_path": str(binary_path.resolve(strict=True)),
        "binary_sha256": sender["binary_sha256"],
        "sender_receipt_path": str(SENDER_RECEIPT),
        "sender_receipt_sha256": sha256(raw),
        "target": "aarch64-linux-musl",
        "tx_flags_requested": "NOSEQNO",
        "noack_requested": False,
        "rf_ack_peer_proven": False,
    }
    return sender, raw, binding


def _ensure_private_output(path: Path) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise BindingError("test118_private_output_directory_unsafe")
    if path.exists() or path.is_symlink():
        raise BindingError("test118_metadata_already_exists_no_overwrite")


def build_disarmed_metadata(*, minimum_boot_epoch_exclusive: int) -> dict:
    if type(minimum_boot_epoch_exclusive) is not int or minimum_boot_epoch_exclusive <= 0:
        raise BindingError("minimum_boot_epoch_invalid")
    build, build_raw = read_private(BUILD_RECEIPT)
    deployment, deployment_raw = _verify_deployment(build)
    archive = _verify_archive(build)
    commit, freeze, freeze_sha, full_source_map = _verify_source_commit()
    sender, sender_raw, sender_binding = _sender_binding()
    if (build.get("candidate") != CANDIDATE or
            build.get("full_build_passed") is not True or
            build.get("strict_signature_passed") is not True or
            build.get("build_inputs_unchanged") is not True or
            build.get("installed") is not False or build.get("rf_tested") is not False or
            build.get("native_awdl_rx149_data_input") is not True or
            build.get("native_rx_preowner_observation") is not True or
            build.get("native_awdl_tx_evidence") is not False or
            not UUID_RE.fullmatch(str(build.get("mach_o_uuid", "")))):
        raise BindingError("test118_build_receipt_binding_invalid")
    helper_hash = sha256(ARM_HELPER.read_bytes())
    build_sha = sha256(build_raw)
    deployment_sha = sha256(deployment_raw)
    source_header_sha = full_source_map.get("native/p2p_rx149_data_input.hpp")
    preowner_header_sha = full_source_map.get("native/rx_preowner_observation.hpp")
    if not (SHA_RE.fullmatch(str(source_header_sha)) and
            SHA_RE.fullmatch(str(preowner_header_sha))):
        raise BindingError("test118_frozen_contract_headers_missing")
    runtime_binding = {
        "schema": "test104-runtime-binding/v1",
        "candidate": CANDIDATE,
        "build_receipt_sha256": build_sha,
        "deployment_receipt_sha256": deployment_sha,
        "sender_observation_binding": sender_binding,
        "packet_template_sha256": "",  # filled by the frozen Test104 packet-set module below
        "packet_set_length_bytes": 0,
        "listener_binding": {
            "schema": "test104-awdl-unicast-listener-binding/v1",
            "listener_source_sha256": "",
            "listener_protocol_source_sha256": "",
            "destination_contract": "exact_fresh_manifest_ipv6_unicast",
            "interface": "awdl0", "interface_ifindex_bound": True,
            "source_port": 49152, "destination_port": 49153,
            "hop_limit": 1, "payload": "T086RX01",
            "truncation_rejected": True, "raw_addresses_serialized": False,
        },
        "receiver_identity": {"interface": "awdl0",
                              "status": "capture_after_deployment_reboot",
                              "contains_address": False},
        "router_source_identity": {"interface": "wlan7",
                                   "status": "refresh_read_only_before_run",
                                   "contains_address": False},
        "host_management_or_data_tx_allowed": False,
        "mac_host_tx_blocked": True,
    }
    # Bind the existing, frozen Test104 packet/listener formats without using
    # its candidate-specific receipt validators.
    import importlib.util
    packet_path = REPO_ROOT / "developer-tools/test104/packetset_test104.py"
    listener_path = REPO_ROOT / "developer-tools/test104/listener_protocol_test104.py"
    for path in (packet_path, listener_path):
        if path.is_symlink() or not path.is_file():
            raise BindingError("test104_identity_tool_unavailable")
    spec = importlib.util.spec_from_file_location("test118_packetset", packet_path)
    packetset = importlib.util.module_from_spec(spec); spec.loader.exec_module(packetset)
    spec = importlib.util.spec_from_file_location("test118_listener_protocol", listener_path)
    listener = importlib.util.module_from_spec(spec); spec.loader.exec_module(listener)
    runtime_binding["packet_template_sha256"] = packetset.TEMPLATE_SHA256
    runtime_binding["packet_set_length_bytes"] = packetset.PACKET_SET_LEN
    runtime_binding["listener_binding"].update({
        "listener_source_sha256": sha256((REPO_ROOT / "developer-tools/test104/awdl0_unicast_listener_test104.c").read_bytes()),
        "listener_protocol_source_sha256": sha256(listener_path.read_bytes()),
    })
    return {
        "schema": "test118-native-awdl-rx149-controlled-probe-private/v1",
        "candidate": CANDIDATE,
        "profile": PROFILE,
        "source_ready_kind": "controlled_probe",
        "status": "prepared_disarmed",
        "armed": False,
        "retry_allowed": False,
        "minimum_boot_epoch_exclusive": minimum_boot_epoch_exclusive,
        "expected_loaded_uuid": build["mach_o_uuid"],
        "expected_arm_helper_source_sha256": helper_hash,
        "requires_phone_ready": False,
        "diagnostic_duration_ms": 100,
        "preowner_observation_duration_ms": 4000,
        "receiver_gated": True,
        "atomic_boot_claim_required": True,
        "owner_epoch_fields": [
            "ContextGeneration", "PowerGeneration", "StationGeneration", "RocGeneration"],
        "required_zero_host_tx_counters": [
            "NativeP2PTxProbeEverDoorbelled", "NativeP2PAwdlActionFramesSubmitted",
            "NativeP2PAwdlPsfFrameSubmitted", "NativeP2PAwdlMifFrameSubmitted",
            "NativeP2PAwdlMifBootstrapSubmitted", "NativeAwdlDataTxSubmitted",
            "NativeAwdlDataTxPending"],
        "source_sha256": freeze,
        "host_management_or_data_tx_allowed": False,
        "preowner_observation_contract": {
            "schema": 1, "duration_ms": 4000,
            "property": "NativeRxPreOwnerSnapshot",
            "published_property": "NativeRxPreOwnerPublished",
            "revision_property": "NativeRxPreOwnerRevision",
            "schema_property": "NativeRxPreOwnerSchema",
            "arm_accepted_property": "NativeRxPreOwnerArmAccepted",
            "schema_version": 1, "window_us": 4_000_000,
            "numeric_only": True, "rx_policy_changed": False,
            "tx_policy_changed": False,
            "snapshot_property": "NativeRxPreOwnerSnapshot",
            "source_header_sha256": preowner_header_sha,
        },
        "rx149_data_input_contract": {
            "channel": 149, "session_duration_ms": 100,
            "artifact_enabled": True,
            "host_management_or_data_tx_allowed": False,
            "source_header": "native/p2p_rx149_data_input.hpp",
            "source_header_sha256": source_header_sha,
            "sender_frames_max": 4, "sender_interval_ms": 10,
            "sender_budget_ms": 40,
        },
        "sender": dict(SENDER_CONTRACT),
        "sender_observation_binding": sender_binding,
        "source_binding": {
            "schema": "test118-actual-build-binding/v1",
            "candidate": CANDIDATE,
            "profile": PROFILE,
            "source_file_count": len(freeze),
            "source_sha256_map_sha256": sha256(json.dumps(
                freeze, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8")),
            "build_receipt_path": str(BUILD_RECEIPT),
            "build_receipt_sha256": build_sha,
            "deployment_receipt_path": str(DEPLOYMENT_RECEIPT),
            "deployment_receipt_sha256": deployment_sha,
            "archive_path": archive["archive_path"],
            "archive_sha256": archive["archive_sha256"],
            "expected_binary_sha256": archive["binary_sha256"],
            "expected_info_plist_sha256": archive["info_plist_sha256"],
            "expected_loaded_uuid": archive["mach_o_uuid"],
            "source_commit": commit,
            "production_freeze_manifest_sha256": freeze_sha,
            "production_freeze_source_sha256": freeze,
            "build_input_source_sha256": full_source_map,
            "build_input_manifest_sha256": build["build_input_manifest_sha256"],
            "sender_receipt_sha256": sha256(sender_raw),
        },
        "runtime_binding_test104": runtime_binding,
        "runtime_scope": "bounded one-use channel-149 receive observation; 100 ms driver lease; four OpenWrt frames over 40 ms; separate 4 s pre-owner observation",
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def write_disarmed_metadata(*, minimum_boot_epoch_exclusive: int) -> Path:
    metadata = build_disarmed_metadata(
        minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive)
    _ensure_private_output(METADATA)
    payload = json.dumps(metadata, ensure_ascii=False, indent=2,
                         sort_keys=True).encode("utf-8") + b"\n"
    fd = os.open(METADATA, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, _account().pw_uid, _account().pw_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return METADATA


def validate_bundle(metadata_path: Path) -> tuple[dict, dict, bytes, Path]:
    metadata, metadata_raw = read_private(metadata_path)
    build, build_raw = read_private(BUILD_RECEIPT)
    deployment, deployment_raw = _verify_deployment(build)
    archive = _verify_archive(build)
    commit, freeze, freeze_sha, full_source_map = _verify_source_commit()
    sender, sender_raw, sender_binding = _sender_binding()
    binding = metadata.get("source_binding")
    extension = metadata.get("runtime_binding_test104")
    checks = (
        metadata_path == METADATA,
        metadata.get("schema") == "test118-native-awdl-rx149-controlled-probe-private/v1",
        metadata.get("candidate") == CANDIDATE,
        metadata.get("profile") == PROFILE,
        metadata.get("status") == "prepared_disarmed",
        metadata.get("armed") is False,
        metadata.get("retry_allowed") is False,
        metadata.get("host_management_or_data_tx_allowed") is False,
        metadata.get("minimum_boot_epoch_exclusive", 0) > 0,
        metadata.get("expected_loaded_uuid") == build.get("mach_o_uuid"),
        isinstance(binding, dict) and binding.get("build_receipt_sha256") == sha256(build_raw),
        isinstance(binding, dict) and binding.get("deployment_receipt_sha256") == sha256(deployment_raw),
        isinstance(binding, dict) and binding.get("archive_sha256") == archive["archive_sha256"],
        isinstance(binding, dict) and binding.get("source_commit") == commit,
        isinstance(binding, dict) and binding.get("production_freeze_manifest_sha256") == freeze_sha,
        isinstance(binding, dict) and binding.get("production_freeze_source_sha256") == freeze,
        metadata.get("source_sha256") == freeze,
        isinstance(binding, dict) and binding.get("build_input_source_sha256") == full_source_map,
        isinstance(binding, dict) and binding.get("expected_binary_sha256") == archive["binary_sha256"],
        isinstance(binding, dict) and binding.get("expected_info_plist_sha256") == archive["info_plist_sha256"],
        isinstance(binding, dict) and binding.get("expected_loaded_uuid") == archive["mach_o_uuid"],
        metadata.get("sender_observation_binding") == sender_binding,
        isinstance(extension, dict) and extension.get("candidate") == CANDIDATE,
        isinstance(extension, dict) and extension.get("build_receipt_sha256") == sha256(build_raw),
        isinstance(extension, dict) and extension.get("deployment_receipt_sha256") == sha256(deployment_raw),
        isinstance(extension, dict) and extension.get("sender_observation_binding") == sender_binding,
        extension.get("packet_template_sha256") if isinstance(extension, dict) else None,
        extension.get("packet_set_length_bytes") if isinstance(extension, dict) else None,
        isinstance(sender, dict),
        len(metadata_raw) > 0,
    )
    if not all(checks):
        raise BindingError("test118_disarmed_bundle_binding_invalid")
    return metadata, build, build_raw, BUILD_RECEIPT
