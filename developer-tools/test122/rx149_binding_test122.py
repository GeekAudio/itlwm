#!/usr/bin/env python3
"""Test122-specific private receipt binding over the frozen Test121 validator.

This module keeps the underlying build, source-freeze, deployment, archive,
UUID, one-use, and sender-contract checks. It changes only candidate paths and
the two Test121 bundle schema labels. The sender is explicitly reused from
Test121 and is not represented as newly built for Test122.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST122_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST122_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


T121 = _load("test122_frozen_test121_binding",
             REPO_ROOT / "developer-tools/test121/rx149_binding_test121.py")

CANDIDATE = "25G332-Test122"
PROFILE = T121.PROFILE
SENDER_CONTRACT = T121.SENDER_CONTRACT
IWN_ROOT = T121.IWN_ROOT
RUN_ROOT = IWN_ROOT / "RuntimeTest122"
PREP_ROOT = RUN_ROOT / "research/preparation-private"
ACTIVE_PRIVATE_ROOT = RUN_ROOT / "research/runtime-current-private/awdl-preparation"
BUILD_RECEIPT = PREP_ROOT / "test122-build-private.json"
DEPLOYMENT_RECEIPT = RUN_ROOT / "research/test122-deployment-private.json"
SOURCE_COMMIT_RECEIPT = PREP_ROOT / "source-commit-private.json"
PRODUCTION_FREEZE = PREP_ROOT / "production-freeze-private.json"
BUILD_INPUT_AFTER = PREP_ROOT / "build-input-after-private.json"
BUILD_INPUT_BEFORE = PREP_ROOT / "build-input-before-private.json"
SENDER_RECEIPT = PREP_ROOT / "awdl-preparation/sender-reuse-receipt-private.json"
ORIGINAL_SENDER_RECEIPT = (
    IWN_ROOT / "RuntimeTest121/research/preparation-private/"
    "awdl-preparation/sender-build-private.json")
ROUTER_RECEIPT = ACTIVE_PRIVATE_ROOT / "router-identity-private.json"
TARGET_RECEIPT = ACTIVE_PRIVATE_ROOT / "target-awdl0-identity-private.json"
METADATA = ACTIVE_PRIVATE_ROOT / "native-controlled-probe-private.json"
RUNTIME_HANDOFF = RUN_ROOT / "research/runtime-handoff-private.json"

_T121_CANDIDATE = T121.CANDIDATE
_T121_METADATA_SCHEMA = "test121-native-awdl-rx149-controlled-probe-private/v1"
_T121_SOURCE_SCHEMA = "test121-actual-build-binding/v1"
_T122_METADATA_SCHEMA = "test122-native-awdl-rx149-controlled-probe-private/v1"
_T122_SOURCE_SCHEMA = "test122-actual-build-binding/v1"
METADATA_SCHEMA = _T122_METADATA_SCHEMA
_ORIGINAL_WRITE_METADATA = T121.write_disarmed_metadata
_ORIGINAL_BUILD_METADATA = T121.build_disarmed_metadata
_ORIGINAL_VALIDATE_BUNDLE = T121.validate_bundle
_ORIGINAL_READ_PRIVATE = T121.read_private


class BindingError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_private(path: Path) -> tuple[dict, bytes]:
    try:
        return T121.read_private(Path(path))
    except Exception as error:
        raise BindingError(str(error)) from error


def _under(path: Path, root: Path, code: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise BindingError(code)
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (ValueError, OSError) as error:
        raise BindingError(code) from error
    return path.resolve(strict=True)


def _sender_binding() -> tuple[dict, bytes, dict]:
    """Verify the Test122 reuse receipt and emit the frozen runner binding."""
    reuse, reuse_raw = read_private(SENDER_RECEIPT)
    original, original_raw = read_private(ORIGINAL_SENDER_RECEIPT)
    source_path = REPO_ROOT / "developer-tools/test121/awdl_unicast_sender_test121.c"
    protocol_path = REPO_ROOT / "developer-tools/test121/dual_sender_protocol_test121.py"
    source = _under(source_path, REPO_ROOT, "test122_sender_source_unavailable")
    protocol = _under(protocol_path, REPO_ROOT, "test122_sender_protocol_unavailable")
    binary = Path(str(reuse.get("binary_path", "")))
    binary = _under(binary, IWN_ROOT / "RuntimeTest121",
                    "test122_reused_sender_binary_unavailable")

    original_receipt_path = Path(str(reuse.get("original_sender_build_receipt_path", "")))
    if original_receipt_path != ORIGINAL_SENDER_RECEIPT:
        raise BindingError("test122_original_sender_receipt_path_mismatch")
    if (reuse.get("schema") != "test122-reused-sender-offline-validation/v1" or
            reuse.get("candidate") != CANDIDATE or
            reuse.get("reused_from") != _T121_CANDIDATE or
            reuse.get("validated_offline") is not True or
            reuse.get("newly_compiled_for_test122") is not False or
            reuse.get("rf_tested") is not False or
            reuse.get("original_sender_build_receipt_sha256") != sha256(original_raw)):
        raise BindingError("test122_sender_reuse_receipt_invalid")
    source_sha = sha256(source.read_bytes())
    protocol_sha = sha256(protocol.read_bytes())
    binary_sha = sha256(binary.read_bytes())
    if (reuse.get("source_path") != str(source) or
            reuse.get("source_sha256") != source_sha or
            reuse.get("protocol_source_path") != str(protocol) or
            reuse.get("protocol_source_sha256") != protocol_sha or
            reuse.get("protocol_schema") != "test121-dual-socket-sender/v1" or
            reuse.get("binary_sha256") != binary_sha or
            reuse.get("target") != "aarch64-linux-musl" or
            reuse.get("sender_contract") != T121.SENDER_CONTRACT):
        raise BindingError("test122_sender_reuse_artifact_mismatch")
    if (original.get("schema") != "test121-sender-build-private/v1" or
            original.get("candidate") != _T121_CANDIDATE or
            original.get("status") != "built_offline" or
            original.get("source_path") != str(source) or
            original.get("protocol_source_path") != str(protocol) or
            original.get("binary_path") != str(binary) or
            original.get("rf_tested") is not False or
            original.get("exit_code") != 0 or
            not isinstance(original.get("command"), list) or
            not original["command"] or
            original.get("source_sha256") != source_sha or
            original.get("binary_sha256") != binary_sha or
            original.get("protocol_source_sha256") != protocol_sha or
            original.get("protocol_schema") != reuse.get("protocol_schema") or
            original.get("target") != reuse.get("target") or
            original.get("sender_contract") != T121.SENDER_CONTRACT):
        raise BindingError("test122_original_sender_receipt_mismatch")

    source_relative = source.relative_to(REPO_ROOT).as_posix()
    binding = {
        "schema": "test121-dual-socket-sender-build/v1",
        "newly_compiled_for_test121": False,
        "validated_offline": True,
        "source_path": source_relative,
        "source_sha256": source_sha,
        "protocol_source_path": str(protocol),
        "protocol_source_sha256": protocol_sha,
        "protocol_schema": reuse["protocol_schema"],
        "binary_path": str(binary),
        "binary_sha256": binary_sha,
        "sender_receipt_path": str(SENDER_RECEIPT),
        "sender_receipt_sha256": sha256(reuse_raw),
        "original_sender_receipt_path": str(ORIGINAL_SENDER_RECEIPT),
        "original_sender_receipt_sha256": sha256(original_raw),
        "reused_from": _T121_CANDIDATE,
        "newly_compiled_for_test122": False,
        "target": "aarch64-linux-musl",
        "tx_flags_requested": "NOSEQNO",
        "socket_topology": "distinct_tx_and_observer",
        "observer_ignore_outgoing": False,
        "pre_capture_drain_after_go": True,
        "stale_queue_read_limit": 256,
        "packet_statistics_required_for_clean_epoch": True,
        "go_to_first_send_max_ms": 5,
        "noack_requested": False,
        "rf_ack_peer_proven": False,
        "raw_monitor_sample_limit": 64,
        "raw_monitor_sample_bytes": 512,
        "overflow_fails_closed": True,
    }
    return reuse, reuse_raw, binding


def build_disarmed_metadata(*, minimum_boot_epoch_exclusive: int) -> dict:
    T121.CANDIDATE = CANDIDATE
    T121.PROFILE = PROFILE
    T121.IWN_ROOT = IWN_ROOT
    T121.RUN_ROOT = RUN_ROOT
    T121.PREP_ROOT = PREP_ROOT
    T121.ACTIVE_PRIVATE_ROOT = ACTIVE_PRIVATE_ROOT
    T121.BUILD_RECEIPT = BUILD_RECEIPT
    T121.DEPLOYMENT_RECEIPT = DEPLOYMENT_RECEIPT
    T121.SOURCE_COMMIT_RECEIPT = SOURCE_COMMIT_RECEIPT
    T121.PRODUCTION_FREEZE = PRODUCTION_FREEZE
    T121.BUILD_INPUT_AFTER = BUILD_INPUT_AFTER
    T121.BUILD_INPUT_BEFORE = BUILD_INPUT_BEFORE
    T121.SENDER_RECEIPT = SENDER_RECEIPT
    T121.ROUTER_RECEIPT = ROUTER_RECEIPT
    T121.TARGET_RECEIPT = TARGET_RECEIPT
    T121.METADATA = METADATA
    T121.RUNTIME_HANDOFF = RUNTIME_HANDOFF
    T121._sender_binding = _sender_binding
    metadata = _ORIGINAL_BUILD_METADATA(
        minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive)
    metadata["schema"] = _T122_METADATA_SCHEMA
    metadata["source_binding"]["schema"] = _T122_SOURCE_SCHEMA
    metadata["station_channel_policy"] = "measure_actual_channel_no_network_switch"
    metadata["channel_attribution"] = "unknown_unless_measured_conditions_match"
    return metadata


def write_disarmed_metadata(*, minimum_boot_epoch_exclusive: int) -> Path:
    metadata = build_disarmed_metadata(
        minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive)
    T121._ensure_private_output(METADATA)
    payload = json.dumps(metadata, ensure_ascii=False, indent=2,
                         sort_keys=True).encode("utf-8") + b"\n"
    account = pwd.getpwuid(REPO_ROOT.stat().st_uid)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(METADATA, flags, 0o600)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return METADATA


def validate_bundle(metadata_path: Path) -> tuple[dict, dict, bytes, Path]:
    if Path(metadata_path) != METADATA:
        raise BindingError("test122_metadata_path_mismatch")
    metadata, raw = read_private(METADATA)
    if (metadata.get("schema") != _T122_METADATA_SCHEMA or
            metadata.get("candidate") != CANDIDATE or
            metadata.get("profile") != PROFILE or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("armed") is not False or
            metadata.get("retry_allowed") is not False or
            metadata.get("host_management_or_data_tx_allowed") is not False or
            metadata.get("source_binding", {}).get("schema") != _T122_SOURCE_SCHEMA):
        raise BindingError("test122_disarmed_bundle_invalid")

    # The frozen validator still performs every receipt/archive/source check.
    # Translate only the two version labels in an in-memory copy, then restore
    # the Test122 labels on the returned object. The private file stays intact.
    original_read = T121.read_private

    def translated_read(path: Path) -> tuple[dict, bytes]:
        value, data = original_read(Path(path))
        if Path(path) == METADATA:
            value = dict(value)
            value["source_binding"] = dict(value["source_binding"])
            if (value.get("schema") != _T122_METADATA_SCHEMA or
                    value["source_binding"].get("schema") != _T122_SOURCE_SCHEMA):
                raise BindingError("test122_schema_translation_rejected")
            value["schema"] = _T121_METADATA_SCHEMA
            value["source_binding"]["schema"] = _T121_SOURCE_SCHEMA
        return value, data

    try:
        T121.read_private = translated_read
        result = _ORIGINAL_VALIDATE_BUNDLE(METADATA)
    finally:
        T121.read_private = original_read
    validated = result[0]
    validated["schema"] = _T122_METADATA_SCHEMA
    validated["source_binding"]["schema"] = _T122_SOURCE_SCHEMA
    validated["station_channel_policy"] = "measure_actual_channel_no_network_switch"
    validated["channel_attribution"] = "unknown_unless_measured_conditions_match"
    return validated, result[1], result[2], result[3]


def bind_template_paths() -> None:
    """Apply Test122 receipt locations to the frozen Test121 validator."""
    for name, value in {
        "CANDIDATE": CANDIDATE,
        "PROFILE": PROFILE,
        "IWN_ROOT": IWN_ROOT,
        "RUN_ROOT": RUN_ROOT,
        "PREP_ROOT": PREP_ROOT,
        "ACTIVE_PRIVATE_ROOT": ACTIVE_PRIVATE_ROOT,
        "BUILD_RECEIPT": BUILD_RECEIPT,
        "DEPLOYMENT_RECEIPT": DEPLOYMENT_RECEIPT,
        "SOURCE_COMMIT_RECEIPT": SOURCE_COMMIT_RECEIPT,
        "PRODUCTION_FREEZE": PRODUCTION_FREEZE,
        "BUILD_INPUT_AFTER": BUILD_INPUT_AFTER,
        "BUILD_INPUT_BEFORE": BUILD_INPUT_BEFORE,
        "SENDER_RECEIPT": SENDER_RECEIPT,
        "ROUTER_RECEIPT": ROUTER_RECEIPT,
        "TARGET_RECEIPT": TARGET_RECEIPT,
        "METADATA": METADATA,
        "RUNTIME_HANDOFF": RUNTIME_HANDOFF,
    }.items():
        setattr(T121, name, value)
    T121._sender_binding = _sender_binding
    T121.build_disarmed_metadata = build_disarmed_metadata
    T121.write_disarmed_metadata = write_disarmed_metadata
    T121.validate_bundle = validate_bundle


# The frozen T121 worker directly uses this helper during native preflight.
# Its globals above are rebound to the T122 archive/runtime roots.
_verify_archive = T121._verify_archive
_verify_deployment = T121._verify_deployment


bind_template_paths()
