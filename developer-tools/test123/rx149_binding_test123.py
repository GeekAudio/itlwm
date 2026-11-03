#!/usr/bin/env python3
"""Tool123 runtime binding for the unchanged Test122 kernel candidate.

This adapter validates the real Test122 kernel receipts, then creates a
per-run Test122-correlated v2 packet set for the existing 100 ms RX149
coordinator.  It does not build or relabel a kernel candidate.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST122_DIR = REPO_ROOT / "developer-tools/test122"
TEST104_DIR = REPO_ROOT / "developer-tools/test104"
TOOL_ID = "Tool123"
RUNNING_KERNEL_TEST = "Test122"
TOOL_TEST = "Test123"


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TOOL123_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TOOL123_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(spec.name) is module:
            del sys.modules[spec.name]
        raise
    return module


KERNEL = _load("tool123_test122_kernel_binding",
               TEST122_DIR / "rx149_binding_test122.py")
PACKETSET = _load("tool123_correlated_packetset_v2",
                  TEST122_DIR / "router-status/packetset_correlated_test122.py")
# The freshness limits are part of the original Test104 identity contract.
# Load that module explicitly instead of reaching through the Test122 binding
# to a coordinator namespace which it does not own.
if str(TEST104_DIR) not in sys.path:
    sys.path.insert(0, str(TEST104_DIR))
_TEST104_RUNTIME = _load(
    "tool123_test104_runtime_binding",
    TEST104_DIR / "runtime_binding_test104.py")
_STATUS_TOOL = None

KERNEL_CANDIDATE = KERNEL.CANDIDATE
KERNEL_METADATA = KERNEL.METADATA
KERNEL_BUILD_RECEIPT = KERNEL.BUILD_RECEIPT
KERNEL_DEPLOYMENT_RECEIPT = KERNEL.DEPLOYMENT_RECEIPT
KERNEL_HANDOFF = KERNEL.RUNTIME_HANDOFF
IWN_ROOT = KERNEL.IWN_ROOT
TOOL_ROOT = IWN_ROOT / "RuntimeTest123"
TOOL_RESEARCH_ROOT = TOOL_ROOT / "research"
PACKET_SET_ROOT = TOOL_RESEARCH_ROOT / "packetsets-private"
NONCE_LEDGER_ROOT = IWN_ROOT / "RuntimeHandoffs/router-wire-nonce-ledger-private"

ACTIVE_PACKET_SET: bytes | None = None
ACTIVE_PACKET_MANIFEST: dict[str, Any] | None = None
ACTIVE_PACKET_SET_PATH: Path | None = None
ACTIVE_NONCE_CLAIM_PATH: Path | None = None


class Tool123BindingError(ValueError):
    """A fail-closed Tool123 identity or wire-packet binding error."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_disarmed_kernel(metadata: Any, *, expected_uuid: str) -> tuple[dict, dict]:
    if not isinstance(metadata, dict):
        raise Tool123BindingError("test122_metadata_not_object")
    if (metadata.get("candidate") != KERNEL_CANDIDATE or
            metadata.get("expected_loaded_uuid") != expected_uuid or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("armed") is not False or
            metadata.get("retry_allowed") is not False or
            metadata.get("host_management_or_data_tx_allowed") is not False):
        raise Tool123BindingError("test122_kernel_bundle_not_disarmed_or_bound")
    source_binding = metadata.get("source_binding")
    extension = metadata.get("runtime_binding_test104")
    if not isinstance(source_binding, dict) or not isinstance(extension, dict):
        raise Tool123BindingError("test122_kernel_runtime_binding_missing")
    return source_binding, extension


def validate_kernel_bundle(metadata_path: Path | None = None) -> tuple[dict, dict, bytes, Path]:
    """Validate the existing Test122 driver bundle without rewriting it."""
    path = Path(metadata_path or KERNEL_METADATA)
    if path != KERNEL_METADATA:
        raise Tool123BindingError("test122_kernel_metadata_path_mismatch")
    try:
        metadata, build, raw, build_path = KERNEL.validate_bundle(path)
    except Exception as error:
        raise Tool123BindingError("test122_kernel_bundle_rejected") from error
    _validate_disarmed_kernel(metadata, expected_uuid=str(build.get("mach_o_uuid", "")))
    return metadata, build, raw, build_path


def _validate_identity_freshness(source: dict, target: dict, *,
                                 now: dt.datetime) -> tuple[int, int]:
    try:
        router_time = dt.datetime.fromisoformat(
            source["captured_at"].replace("Z", "+00:00"))
        target_time = dt.datetime.fromisoformat(
            target["captured_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise Tool123BindingError("identity_receipt_timestamp_invalid") from error
    if now.tzinfo is None:
        raise Tool123BindingError("identity_validation_clock_timezone_missing")
    router_age = (now - router_time.astimezone(dt.timezone.utc)).total_seconds()
    target_age = (now - target_time.astimezone(dt.timezone.utc)).total_seconds()
    # Keep the original Test104 freshness windows; packet-format upgrades do
    # not create a reason to loosen runtime identity freshness.
    max_router_age = _TEST104_RUNTIME.ROUTER_RECEIPT_MAX_AGE_SECONDS
    max_target_age = _TEST104_RUNTIME.TARGET_RECEIPT_MAX_AGE_SECONDS
    if router_age < -10 or router_age > max_router_age:
        raise Tool123BindingError("router_source_identity_stale")
    if target_age < -10 or target_age > max_target_age:
        raise Tool123BindingError("target_awdl0_identity_stale")
    return int(router_age), int(target_age)


def bind_runtime_identities(metadata: dict, router_receipt: dict,
                            target_receipt: dict, *, expected_boot_epoch: int,
                            expected_uuid: str,
                            router_receipt_sha256: str | None = None,
                            now: dt.datetime | None = None,
                            wire_nonce_hex: str | None = None,
                            wifi_sequence_base: int | None = None,
                            awdl_sequence_base: int | None = None) -> tuple[bytes, dict]:
    """Create one identity-bound v2 packet set, preserving Test122 checks.

    Optional nonce/sequence values exist only for deterministic offline tests.
    Production callers omit them and receive fresh random wire identity.
    """
    global ACTIVE_PACKET_SET, ACTIVE_PACKET_MANIFEST
    source_binding, extension = _validate_disarmed_kernel(
        metadata, expected_uuid=expected_uuid)
    if (type(expected_boot_epoch) is not int or expected_boot_epoch <= 0 or
            metadata.get("expected_loaded_uuid") != expected_uuid):
        raise Tool123BindingError("test122_kernel_boot_or_uuid_mismatch")
    try:
        packet_source = PACKETSET._test104.parse_router_identity_receipt(
            router_receipt, receipt_sha256=router_receipt_sha256)
        packet_target = PACKETSET._test104.validate_target_identity(
            target_receipt, expected_boot_epoch, expected_uuid,
            expected_candidate=KERNEL_CANDIDATE,
            expected_binary_sha256=source_binding.get("expected_binary_sha256"),
            expected_build_receipt_sha256=source_binding.get("build_receipt_sha256"),
            expected_deployment_receipt_sha256=extension.get("deployment_receipt_sha256"))
    except Exception as error:
        raise Tool123BindingError("test122_runtime_identity_rejected") from error
    now = now or dt.datetime.now(dt.timezone.utc)
    router_age, target_age = _validate_identity_freshness(
        packet_source, packet_target, now=now)

    nonce = wire_nonce_hex if wire_nonce_hex is not None else secrets.token_hex(8)
    wifi_base = (wifi_sequence_base if wifi_sequence_base is not None
                 else secrets.randbelow(0x1000))
    awdl_base = (awdl_sequence_base if awdl_sequence_base is not None
                 else secrets.randbelow(0x10000))
    try:
        raw, manifest = PACKETSET.encode_packet_set(
            packet_source, packet_target, "tool123-native-rx149",
            wire_nonce_hex=nonce,
            wifi_sequence_base=wifi_base,
            awdl_sequence_base=awdl_base)
    except Exception as error:
        raise Tool123BindingError("test122_v2_packetset_construction_failed") from error

    manifest.update({
        "tool_id": TOOL_ID,
        "tool_test": TOOL_TEST,
        "running_kernel_test": RUNNING_KERNEL_TEST,
        "kernel_candidate": KERNEL_CANDIDATE,
        "kernel_uuid": expected_uuid,
        "identity_freshness": {
            "router_receipt_age_seconds": router_age,
            "target_receipt_age_seconds": target_age,
            "target_boot_epoch": packet_target["boot_epoch"],
            "current_boot_match": True,
            "candidate_uuid_match": True,
            "router_receipt_sha256": router_receipt_sha256,
            "target_receipt_sha256": target_receipt.get("identity_receipt_sha256"),
        },
        "frame_claim_scope": "same-window payload nonce proves at least one datagram only",
        "distinct_received_ordinals_proven": False,
    })
    manifest["packet_set_sha256"] = sha256(raw)
    ACTIVE_PACKET_SET = raw
    ACTIVE_PACKET_MANIFEST = manifest
    return raw, manifest


def _status_tool():
    global _STATUS_TOOL
    if _STATUS_TOOL is None:
        _STATUS_TOOL = _load(
            "tool123_frozen_test122_status_nonce_claim",
            TEST122_DIR / "router-status/router_status_tail_test122.py")
    return _STATUS_TOOL


def validate_active_packetset() -> tuple[bytes, dict]:
    if ACTIVE_PACKET_SET is None or ACTIVE_PACKET_MANIFEST is None:
        raise Tool123BindingError("tool123_packetset_not_bound")
    decoded = PACKETSET.validate_packet_set(ACTIVE_PACKET_SET)
    manifest = ACTIVE_PACKET_MANIFEST
    identities = manifest.get("identities")
    if not isinstance(identities, dict):
        raise Tool123BindingError("tool123_manifest_identities_invalid")
    source_identity = identities.get("source")
    destination_identity = identities.get("destination_awdl0")
    decoded_source = decoded.get("source")
    decoded_destination = decoded.get("destination_awdl0")
    identity_keys = ("mac", "ipv6_link_local")
    if (not isinstance(source_identity, dict) or
            not isinstance(destination_identity, dict) or
            not isinstance(decoded_source, dict) or
            not isinstance(decoded_destination, dict) or
            any(source_identity.get(key) != decoded_source.get(key)
                for key in identity_keys) or
            any(destination_identity.get(key) != decoded_destination.get(key)
                for key in identity_keys) or
            identities.get("router_source_is_test_injector") is not True or
            identities.get("destination_identity_verified_at_capture") is not True or
            identities.get("destination_current_at_run_revalidated") is not False):
        raise Tool123BindingError("tool123_manifest_identity_binding_mismatch")

    manifest_frames = manifest.get("frames")
    decoded_frames = decoded.get("frames")
    frame_keys = (
        "ordinal", "payload_hex", "sequence_control", "wifi_sequence",
        "awdl_sequence", "mpdu_sha256", "packet_sha256", "udp_checksum_valid",
        "radiotap_length", "mpdu_length", "packet_length",
    )
    if (not isinstance(manifest_frames, list) or
            not isinstance(decoded_frames, list) or
            len(manifest_frames) != PACKETSET.PACKET_COUNT or
            len(decoded_frames) != PACKETSET.PACKET_COUNT or
            any(not isinstance(expected, dict) or not isinstance(actual, dict) or
                any(type(expected.get(key)) is not type(actual.get(key)) or
                    expected.get(key) != actual.get(key)
                    for key in frame_keys)
                for expected, actual in zip(manifest_frames, decoded_frames))):
        raise Tool123BindingError("tool123_manifest_frame_binding_mismatch")

    if (decoded.get("schema") != PACKETSET.PACKET_SET_SCHEMA or
            decoded.get("packet_set_sha256") != manifest.get("packet_set_sha256") or
            manifest.get("packet_set_length") != len(ACTIVE_PACKET_SET) or
            decoded.get("packet_set_length", len(ACTIVE_PACKET_SET)) != len(ACTIVE_PACKET_SET) or
            decoded.get("frame_count") != PACKETSET.PACKET_COUNT or
            manifest.get("frame_count") != PACKETSET.PACKET_COUNT or
            decoded.get("wire_nonce_hex") != manifest.get("wire_nonce_hex") or
            decoded.get("wifi_sequence_base") != manifest.get("wifi_sequence_base") or
            decoded.get("awdl_sequence_base") != manifest.get("awdl_sequence_base") or
            manifest.get("template", {}).get("source_file_sha256") != PACKETSET.TEMPLATE_SHA256 or
            manifest.get("tool_id") != TOOL_ID or
            manifest.get("tool_test") != TOOL_TEST or
            manifest.get("running_kernel_test") != RUNNING_KERNEL_TEST or
            manifest.get("kernel_candidate") != KERNEL_CANDIDATE):
        raise Tool123BindingError("tool123_active_packetset_binding_mismatch")
    return ACTIVE_PACKET_SET, ACTIVE_PACKET_MANIFEST


def write_packetset_for_run(run_token: str) -> tuple[Path, Path]:
    """Persist the exact bound bytes and claim its nonce before router I/O."""
    global ACTIVE_PACKET_SET_PATH, ACTIVE_NONCE_CLAIM_PATH
    raw, manifest = validate_active_packetset()
    if not isinstance(run_token, str) or len(run_token) != 32 or any(
            char not in "0123456789abcdef" for char in run_token):
        raise Tool123BindingError("test123_run_token_invalid")
    _ensure_private_directory(PACKET_SET_ROOT)
    _ensure_private_directory(NONCE_LEDGER_ROOT)
    path = PACKET_SET_ROOT / (manifest["wire_nonce_hex"] + ".packetset")
    try:
        _write_workspace_private_new(path, raw)
    except FileExistsError as error:
        raise Tool123BindingError("test123_packetset_already_exists_no_retry") from error
    try:
        claim = _claim_wire_nonce(
            NONCE_LEDGER_ROOT, manifest["wire_nonce_hex"],
            manifest["packet_set_sha256"], run_token)
    except Exception as error:
        # The packet set is retained as an unclaimed private artifact, but the
        # caller must fail before starting the router or issuing GO.
        raise Tool123BindingError("test123_wire_nonce_claim_failed") from error
    ACTIVE_PACKET_SET_PATH = path
    ACTIVE_NONCE_CLAIM_PATH = claim
    return path, claim


def _workspace_ids() -> tuple[int, int]:
    """Use the checked-out repository owner, never sudo's HOME or UID."""
    info = REPO_ROOT.stat()
    if os.geteuid() not in (0, info.st_uid):
        raise Tool123BindingError("tool123_executor_not_workspace_owner_or_root")
    return info.st_uid, info.st_gid


def _ensure_private_directory(path: Path) -> None:
    path = Path(path)
    owner_uid, owner_gid = _workspace_ids()
    if not path.is_absolute() or path.is_symlink():
        raise Tool123BindingError("tool123_private_directory_is_symlink")
    try:
        if not path.parent.exists():
            _ensure_private_directory(path.parent)
        if path.parent.resolve(strict=True) != path.parent:
            raise Tool123BindingError("tool123_private_directory_parent_is_symlink")
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            # Do not chmod/chown an existing ledger to make a check pass.
            pass
        else:
            if os.geteuid() == 0:
                os.chown(path, owner_uid, owner_gid, follow_symlinks=False)
        info = path.lstat()
    except OSError as error:
        raise Tool123BindingError("tool123_private_directory_unavailable") from error
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise Tool123BindingError("tool123_private_directory_mode_or_owner_invalid")


def _write_workspace_private_new(path: Path, raw: bytes) -> None:
    owner_uid, owner_gid = _workspace_ids()
    _ensure_private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, owner_uid, owner_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY |
                           getattr(os, "O_DIRECTORY", 0) |
                           getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _claim_wire_nonce(directory: Path, nonce: str, digest: str, token: str) -> Path:
    """Keep the Test122 ledger filename/schema; support privileged coordinator.

    A new tool number or executor cannot reuse an existing reservation. Only
    new files are assigned to the workspace owner; existing claims stay intact.
    """
    if (not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{16}", nonce)
            or nonce == "0" * 16 or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token)):
        raise Tool123BindingError("tool123_nonce_claim_binding_invalid")
    path = Path(directory) / (nonce + ".json")
    value = {"schema": "test122-wire-nonce-claim/v1", "wire_nonce_hex": nonce,
             "run_token": token, "packet_set_sha256": digest,
             "state": "reserved_before_device_io"}
    try:
        _write_workspace_private_new(
            path, (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"))
    except FileExistsError as error:
        raise Tool123BindingError("wire_nonce_already_claimed") from error
    return path


def clear_active_run() -> None:
    global ACTIVE_PACKET_SET, ACTIVE_PACKET_MANIFEST
    global ACTIVE_PACKET_SET_PATH, ACTIVE_NONCE_CLAIM_PATH
    ACTIVE_PACKET_SET = None
    ACTIVE_PACKET_MANIFEST = None
    ACTIVE_PACKET_SET_PATH = None
    ACTIVE_NONCE_CLAIM_PATH = None


__all__ = [
    "TOOL_ID", "TOOL_TEST", "RUNNING_KERNEL_TEST", "KERNEL_CANDIDATE", "KERNEL_METADATA",
    "KERNEL_BUILD_RECEIPT", "KERNEL_DEPLOYMENT_RECEIPT", "KERNEL_HANDOFF",
    "IWN_ROOT", "TOOL_ROOT", "TOOL_RESEARCH_ROOT", "PACKET_SET_ROOT",
    "NONCE_LEDGER_ROOT", "Tool123BindingError", "validate_kernel_bundle",
    "bind_runtime_identities", "validate_active_packetset",
    "write_packetset_for_run", "clear_active_run", "sha256",
]
