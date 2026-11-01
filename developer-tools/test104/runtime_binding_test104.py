#!/usr/bin/env python3
"""Test104 disarmed metadata and post-boot awdl0 identity reader.

The default commands are offline/read-only. This module never arms the driver,
creates a one-use claim, contacts OpenWrt, or opens an AF_PACKET socket.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
from typing import Any

import packetset_test104 as packetset

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
CANDIDATE = "25G332-Test104"
PROFILE = "native_awdl_rx149_preowner_observation"
SENDER_SOURCE = TOOL_DIR / "awdl_unicast_sender_test104.c"
ARM_HELPER = TOOL_DIR / "arm_p2p_rx149_test104.swift"
FINALIZER_PATH = REPO_ROOT / "developer-tools/test087/finalize_test087_runtime_binding.py"
COORDINATOR_PATH = REPO_ROOT / "developer-tools/test087/controlled_run_coordinator.py"
SENDER_BINARY_RELATIVE = Path(
    "developer-tools/test104/build/awdl_unicast_sender_test104-aarch64-linux-musl")
SENDER_RECEIPT_RELATIVE = Path(
    "research/test104-preparation-private/sender-build-private.json")
BUILD_RECEIPT_RELATIVE = Path("research/test104-build-private.json")
DEPLOYMENT_RECEIPT_RELATIVE = Path("research/test104-deployment-private.json")
ROUTER_SOURCE_RECEIPT_RELATIVE = Path(
    "research/test104-preparation-private/router-identity-private.json")
TARGET_RECEIPT_RELATIVE = Path(
    "research/test104-preparation-private/target-awdl0-identity-private.json")
METADATA_RELATIVE = Path(
    "research/test104-runtime-private/native-controlled-probe-private.json")
EXPECTED_SENDER_SCHEMA = "test104-unicast-sender/v1"
METADATA_SCHEMA = "native-awdl-rx149-controlled-probe-private/v2"
RUNTIME_BINDING_SCHEMA = "test104-runtime-binding/v1"
LISTENER_BINDING_SCHEMA = "test104-awdl-unicast-listener-binding/v1"
LISTENER_SOURCE = TOOL_DIR / "awdl0_unicast_listener_test104.c"
LISTENER_PROTOCOL_SOURCE = TOOL_DIR / "listener_protocol_test104.py"
ROUTER_RECEIPT_MAX_AGE_SECONDS = 180
TARGET_RECEIPT_MAX_AGE_SECONDS = 180

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


class RuntimeBindingError(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeBindingError("test087_component_unavailable")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeBindingError("test087_component_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(name, None)
        raise RuntimeBindingError("test087_component_import_failed") from error
    return module


def _private_account():
    try:
        return pwd.getpwuid(REPO_ROOT.stat().st_uid)
    except (OSError, KeyError) as error:
        raise RuntimeBindingError("private_account_unavailable") from error


def _read_private_json(path: Path, owner_uid: int) -> tuple[dict, bytes]:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeBindingError("private_receipt_path_invalid")
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise RuntimeBindingError("private_receipt_unavailable") from error
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise RuntimeBindingError("private_receipt_mode_or_owner_invalid")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise RuntimeBindingError("private_receipt_malformed") from error
    if not isinstance(value, dict):
        raise RuntimeBindingError("private_receipt_not_object")
    return value, raw


def _read_receipt_bundle(iwn_root: Path, build_path: Path | None = None,
                         deployment_path: Path | None = None,
                         sender_path: Path | None = None) -> tuple[dict, dict, dict, bytes, bytes, bytes]:
    root = Path(iwn_root)
    if not root.is_absolute() or root.is_symlink():
        raise RuntimeBindingError("explicit_absolute_iwn_root_required")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise RuntimeBindingError("iwn_root_unavailable") from error
    owner_uid = _private_account().pw_uid
    build_path = build_path or root / BUILD_RECEIPT_RELATIVE
    deployment_path = deployment_path or root / DEPLOYMENT_RECEIPT_RELATIVE
    sender_path = sender_path or root / SENDER_RECEIPT_RELATIVE
    build, build_raw = _read_private_json(build_path, owner_uid)
    deployment, deployment_raw = _read_private_json(deployment_path, owner_uid)
    sender, sender_raw = _read_private_json(sender_path, owner_uid)
    if (build.get("candidate") != CANDIDATE or
            build.get("status") != "built_offline" or
            build.get("installed") is not False or
            build.get("rf_tested") is not False or
            deployment.get("candidate") != CANDIDATE or
            deployment.get("status") != "deployed_waiting_reboot_disarmed" or
            deployment.get("automatic_reboot") is not False or
            deployment.get("mach_o_uuid") != build.get("mach_o_uuid") or
            deployment.get("binary_sha256") != build.get("binary_sha256") or
            deployment.get("build_report_sha256") != _sha(build_raw)):
        raise RuntimeBindingError("test104_build_deployment_binding_invalid")
    if (sender.get("candidate") != CANDIDATE or
            sender.get("status") != "built_offline" or
            sender.get("target") != "aarch64-linux-musl" or
            sender.get("provenance_schema") != EXPECTED_SENDER_SCHEMA or
            sender.get("source_path") != SENDER_SOURCE.relative_to(REPO_ROOT).as_posix() or
            sender.get("source_sha256") != _sha(SENDER_SOURCE.read_bytes()) or
            sender.get("binary_path") != SENDER_BINARY_RELATIVE.as_posix() or
            not isinstance(sender.get("binary_sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", sender["binary_sha256"]) or
            not isinstance(sender.get("command"), list) or not sender["command"]):
        raise RuntimeBindingError("test104_sender_build_binding_invalid")
    binary = REPO_ROOT / SENDER_BINARY_RELATIVE
    if binary.is_symlink() or not binary.is_file() or _sha(binary.read_bytes()) != sender["binary_sha256"]:
        raise RuntimeBindingError("test104_sender_binary_hash_mismatch")
    return build, deployment, sender, build_raw, deployment_raw, sender_raw


def _sender_observation_binding(sender: dict, sender_raw: bytes) -> dict:
    return {
        "schema": EXPECTED_SENDER_SCHEMA,
        "source_path": SENDER_SOURCE.relative_to(REPO_ROOT).as_posix(),
        "source_sha256": _sha(SENDER_SOURCE.read_bytes()),
        "binary_path": SENDER_BINARY_RELATIVE.as_posix(),
        "binary_sha256": sender.get("binary_sha256"),
        "sender_receipt_path": SENDER_RECEIPT_RELATIVE.as_posix(),
        "sender_receipt_sha256": _sha(sender_raw),
        "target": sender.get("target"),
        "tx_flags_requested": "NOSEQNO",
        "noack_requested": False,
        "raw_txs_source_available": False,
        "rf_ack_peer_proven": False,
    }


def build_disarmed_metadata(*, iwn_root: Path,
                            minimum_boot_epoch_exclusive: int,
                            build_path: Path | None = None,
                            deployment_path: Path | None = None,
                            sender_path: Path | None = None) -> dict:
    """Build a Test087-compatible, Test104-bound disarmed metadata bundle."""
    if type(minimum_boot_epoch_exclusive) is not int or minimum_boot_epoch_exclusive <= 0:
        raise RuntimeBindingError("minimum_boot_epoch_invalid")
    root = Path(iwn_root).expanduser()
    if not root.is_absolute() or root.is_symlink():
        raise RuntimeBindingError("explicit_absolute_iwn_root_required")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise RuntimeBindingError("iwn_root_unavailable") from error
    build, deployment, sender, build_raw, deployment_raw, sender_raw = _read_receipt_bundle(
        root, build_path, deployment_path, sender_path)
    finalizer = _load_module("test104_tracked_test087_finalizer", FINALIZER_PATH)
    initial_build, _, _, _ = finalizer.validate_receipts(
        iwn_root=root, candidate=CANDIDATE,
        build_receipt=build_path or root / BUILD_RECEIPT_RELATIVE,
        baseline_receipt=None)
    _, resolved_build, resolved_baseline, _ = finalizer._paths(
        root, candidate=CANDIDATE,
        build_receipt=build_path or root / BUILD_RECEIPT_RELATIVE,
        baseline_receipt=None)
    if resolved_baseline is None:
        resolved_baseline = finalizer.candidate_binding.default_build_receipt_path(
            root, str(initial_build.get("baseline", "")))
    resolved_build = resolved_build.resolve(strict=True)
    resolved_baseline = resolved_baseline.resolve(strict=True)
    metadata = finalizer.build_metadata(
        minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive,
        iwn_root=root, candidate=CANDIDATE,
        build_receipt=resolved_build, baseline_receipt=resolved_baseline)
    metadata["expected_arm_helper_source_sha256"] = _sha(ARM_HELPER.read_bytes())
    metadata["sender"] = dict(SENDER_CONTRACT)
    binding = _sender_observation_binding(sender, sender_raw)
    metadata["sender_observation_binding"] = binding
    metadata["runtime_binding_test104"] = {
        "schema": RUNTIME_BINDING_SCHEMA,
        "candidate": CANDIDATE,
        "build_receipt_sha256": _sha(build_raw),
        "deployment_receipt_sha256": _sha(deployment_raw),
        "sender_observation_binding": binding,
        "packet_template_sha256": packetset.TEMPLATE_SHA256,
        "packet_set_length_bytes": packetset.PACKET_SET_LEN,
        "listener_binding": {
            "schema": LISTENER_BINDING_SCHEMA,
            "listener_source_sha256": _sha(LISTENER_SOURCE.read_bytes()),
            "listener_protocol_source_sha256": _sha(LISTENER_PROTOCOL_SOURCE.read_bytes()),
            "destination_contract": "exact_fresh_manifest_ipv6_unicast",
            "interface": "awdl0",
            "interface_ifindex_bound": True,
            "source_port": 49152,
            "destination_port": 49153,
            "hop_limit": 1,
            "payload": "T086RX01",
            "truncation_rejected": True,
            "raw_addresses_serialized": False,
        },
        "receiver_identity": {
            "interface": "awdl0",
            "status": "capture_after_deployment_reboot",
            "contains_address": False,
        },
        "router_source_identity": {
            "interface": "wlan7",
            "status": "refresh_read_only_before_run",
            "contains_address": False,
        },
        "next_boot_steps": [
            "capture-target --minimum-boot-epoch-exclusive <predeployment-boot>",
            "refresh the read-only wlan7 identity receipt",
            "run once with the current boot identities and existing control socket",
        ],
        "evidence_boundary": {
            "local_send_return_is_rf_proof": False,
            "raw_txs": "unknown_unavailable_in_sender",
            "mac_ack": "unknown",
            "peer_receipt": "unknown",
            "native_awdl0_positive_independent_of_raw_txs": True,
        },
        "host_management_or_data_tx_allowed": False,
        "mac_host_tx_blocked": True,
        "sleep_test": "skipped_by_user",
    }
    if metadata.get("armed") is not False or metadata.get("status") != "prepared_disarmed":
        raise RuntimeBindingError("runtime_bundle_not_disarmed")
    validated_build, validated_build_raw, baseline, baseline_raw = finalizer.validate_receipts(
        iwn_root=root, candidate=CANDIDATE,
        build_receipt=resolved_build, baseline_receipt=resolved_baseline)
    errors = finalizer.candidate_binding.validate_metadata_binding(
        metadata, validated_build, validated_build_raw, baseline, baseline_raw,
        resolved_build, resolved_baseline, expected_candidate=CANDIDATE)
    if errors:
        raise RuntimeBindingError("candidate_binding_failed:" + ",".join(errors))
    validate_disarmed_metadata(metadata, build, deployment, sender,
                               build_raw, deployment_raw, sender_raw)
    validate_test104_tool_contract(metadata, root)
    return metadata


def _read_boot_epoch() -> int:
    try:
        result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"],
                                check=True, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeBindingError("boot_epoch_unavailable") from error
    match = re.search(r"\bsec\s*=\s*(\d+)", result.stdout)
    if not match or int(match.group(1)) <= 0:
        raise RuntimeBindingError("boot_epoch_invalid")
    return int(match.group(1))


def _run_text(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, check=True, capture_output=True,
                                text=True, timeout=8)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeBindingError("read_only_identity_command_failed") from error
    return result.stdout


def _extract_loaded_uuid(text: str) -> str:
    matches = re.findall(r"org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})", text)
    if len(matches) != 1 or not re.fullmatch(
            r"[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}", matches[0]):
        raise RuntimeBindingError("loaded_candidate_uuid_not_unique")
    return matches[0]


def _parse_awdl0_ifconfig(text: str) -> tuple[str, str, bool]:
    first = text.splitlines()[0] if text.splitlines() else ""
    if not re.search(r"^awdl0:\s+flags=\d+<[^>]*\bUP\b", first):
        raise RuntimeBindingError("awdl0_not_up")
    macs = re.findall(r"(?m)^\s*ether\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*$", text)
    if len(macs) != 1:
        raise RuntimeBindingError("awdl0_mac_not_unique")
    try:
        mac = bytes.fromhex(macs[0].replace(":", ""))
    except ValueError as error:
        raise RuntimeBindingError("awdl0_mac_invalid") from error
    if mac == bytes(6) or mac[0] & 1:
        raise RuntimeBindingError("awdl0_mac_not_unicast")
    addresses = []
    for token in re.findall(r"(?m)^\s*inet6\s+(\S+)\s+prefixlen\s+\d+", text):
        address = token.split("%", 1)[0]
        try:
            parsed = ipaddress.IPv6Address(address)
        except ipaddress.AddressValueError:
            continue
        if parsed.is_link_local and not parsed.is_multicast and not parsed.is_unspecified:
            addresses.append(str(parsed))
    if len(addresses) != 1:
        raise RuntimeBindingError("awdl0_link_local_not_unique")
    return ":".join(f"{byte:02x}" for byte in mac), addresses[0], True


def capture_target_identity(*, iwn_root: Path, output: Path | None = None,
                            minimum_boot_epoch_exclusive: int,
                            build_path: Path | None = None,
                            deployment_path: Path | None = None,
                            sender_path: Path | None = None) -> dict:
    """Read live awdl0 and loaded UUID after boot; never changes system state."""
    root = Path(iwn_root).expanduser()
    build, deployment, sender, build_raw, deployment_raw, _ = _read_receipt_bundle(
        root, build_path, deployment_path, sender_path)
    boot_epoch = _read_boot_epoch()
    if (type(minimum_boot_epoch_exclusive) is not int or
            boot_epoch <= minimum_boot_epoch_exclusive):
        raise RuntimeBindingError("target_capture_requires_newer_boot")
    loaded_text = _run_text([
        "/usr/bin/kmutil", "showloaded", "--list-only",
        "--bundle-identifier", "org.geekaudio.AirportItlwm"])
    loaded_uuid = _extract_loaded_uuid(loaded_text)
    expected_uuid = build.get("mach_o_uuid")
    if loaded_uuid != expected_uuid or deployment.get("mach_o_uuid") != expected_uuid:
        raise RuntimeBindingError("loaded_candidate_uuid_mismatch")
    ifconfig = _run_text(["/sbin/ifconfig", "awdl0"])
    mac, ipv6ll, interface_up = _parse_awdl0_ifconfig(ifconfig)
    try:
        ifindex = socket.if_nametoindex("awdl0")
    except OSError as error:
        raise RuntimeBindingError("awdl0_ifindex_unavailable") from error
    if ifindex <= 0:
        raise RuntimeBindingError("awdl0_ifindex_invalid")
    now = dt.datetime.now().astimezone().isoformat()
    raw_evidence = json.dumps({
        "ifconfig": ifconfig,
        "kmutil": loaded_text,
        "boot_epoch": boot_epoch,
        "ifindex": ifindex,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record = {
        "schema": "test104-target-identity/v1",
        "status": "readback_verified",
        "captured_at": now,
        "boot_epoch": boot_epoch,
        "minimum_boot_epoch_exclusive": minimum_boot_epoch_exclusive,
        "interface": "awdl0",
        "ifindex": ifindex,
        "mac": mac,
        "ipv6_link_local": ipv6ll,
        "interface_up": interface_up,
        "candidate": CANDIDATE,
        "candidate_uuid": expected_uuid,
        "candidate_binary_sha256": build.get("binary_sha256"),
        "build_receipt_sha256": _sha(build_raw),
        "deployment_receipt_sha256": _sha(deployment_raw),
        "source": "live_ifconfig_ifindex_kmutil",
        "evidence_sha256": _sha(raw_evidence),
    }
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    record["identity_receipt_sha256"] = _sha(canonical)
    packetset.validate_target_identity(
        record, boot_epoch, expected_uuid,
        expected_binary_sha256=build.get("binary_sha256"),
        expected_build_receipt_sha256=_sha(build_raw),
        expected_deployment_receipt_sha256=_sha(deployment_raw))
    if output is not None:
        _write_private_json(Path(output), record)
    return record


def _write_private_json(path: Path, value: dict) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise RuntimeBindingError("refuse_overwrite_existing_output")
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise RuntimeBindingError("unsafe_private_output_directory")
    data = json.dumps(value, ensure_ascii=False, indent=2,
                      sort_keys=True).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if os.geteuid() == 0:
            account = _private_account()
            os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def validate_disarmed_metadata(metadata: Any, build: dict,
                               deployment: dict, sender: dict,
                               build_raw: bytes, deployment_raw: bytes,
                               sender_raw: bytes) -> None:
    expected_binding = _sender_observation_binding(sender, sender_raw)
    extension = metadata.get("runtime_binding_test104") if isinstance(metadata, dict) else None
    source_binding = metadata.get("source_binding") if isinstance(metadata, dict) else None
    expected_listener_binding = {
        "schema": LISTENER_BINDING_SCHEMA,
        "listener_source_sha256": _sha(LISTENER_SOURCE.read_bytes()),
        "listener_protocol_source_sha256": _sha(LISTENER_PROTOCOL_SOURCE.read_bytes()),
        "destination_contract": "exact_fresh_manifest_ipv6_unicast",
        "interface": "awdl0",
        "interface_ifindex_bound": True,
        "source_port": 49152,
        "destination_port": 49153,
        "hop_limit": 1,
        "payload": "T086RX01",
        "truncation_rejected": True,
        "raw_addresses_serialized": False,
    }
    if (not isinstance(metadata, dict) or
            metadata.get("schema") != METADATA_SCHEMA or
            metadata.get("candidate") != CANDIDATE or
            metadata.get("profile") != PROFILE or
            metadata.get("source_ready_kind") != "controlled_probe" or
            metadata.get("armed") is not False or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("armed") is not False or
            metadata.get("retry_allowed") is not False or
            metadata.get("expected_loaded_uuid") != build.get("mach_o_uuid") or
            not isinstance(source_binding, dict) or
            source_binding.get("expected_binary_sha256") != build.get("binary_sha256") or
            source_binding.get("build_receipt_sha256") != _sha(build_raw) or
            metadata.get("sender") != SENDER_CONTRACT or
            metadata.get("host_management_or_data_tx_allowed") is not False or
            metadata.get("expected_arm_helper_source_sha256") != _sha(ARM_HELPER.read_bytes()) or
            metadata.get("sender_observation_binding") != expected_binding or
            not isinstance(extension, dict) or
            extension.get("schema") != RUNTIME_BINDING_SCHEMA or
            extension.get("candidate") != CANDIDATE or
            extension.get("build_receipt_sha256") != _sha(build_raw) or
            extension.get("deployment_receipt_sha256") != _sha(deployment_raw) or
            extension.get("sender_observation_binding") != expected_binding or
            extension.get("packet_template_sha256") != packetset.TEMPLATE_SHA256 or
            extension.get("packet_set_length_bytes") != packetset.PACKET_SET_LEN or
            extension.get("listener_binding") != expected_listener_binding or
            extension.get("receiver_identity", {}).get("contains_address") is not False or
            extension.get("receiver_identity", {}).get("status") != "capture_after_deployment_reboot" or
            extension.get("router_source_identity", {}).get("contains_address") is not False or
            extension.get("router_source_identity", {}).get("status") != "refresh_read_only_before_run" or
            extension.get("host_management_or_data_tx_allowed") is not False or
            extension.get("mac_host_tx_blocked") is not True or
            metadata.get("minimum_boot_epoch_exclusive") is None or
            type(metadata.get("minimum_boot_epoch_exclusive")) is not int):
        raise RuntimeBindingError("test104_disarmed_metadata_binding_invalid")


def validate_test104_tool_contract(metadata: dict, iwn_root: Path) -> None:
    if ARM_HELPER.is_symlink() or not ARM_HELPER.is_file():
        raise RuntimeBindingError("test104_arm_helper_unavailable")
    if metadata.get("expected_arm_helper_source_sha256") != _sha(ARM_HELPER.read_bytes()):
        raise RuntimeBindingError("test104_arm_helper_hash_mismatch")
    for path in (LISTENER_SOURCE, LISTENER_PROTOCOL_SOURCE):
        if path.is_symlink() or not path.is_file():
            raise RuntimeBindingError("test104_unicast_listener_source_unavailable")
    build, deployment, sender, build_raw, deployment_raw, sender_raw = _read_receipt_bundle(iwn_root)
    validate_disarmed_metadata(metadata, build, deployment, sender,
                               build_raw, deployment_raw, sender_raw)


def validate_prearm_bundle(metadata_path: Path | str, *, iwn_root: Path) -> dict:
    """Run the tracked Test087 bundle gate, then enforce Test104 pins."""
    root = Path(iwn_root).expanduser()
    if not root.is_absolute() or root.is_symlink():
        raise RuntimeBindingError("explicit_absolute_iwn_root_required")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise RuntimeBindingError("iwn_root_unavailable") from error
    path = Path(metadata_path).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeBindingError("runtime_metadata_unavailable")
    coordinator = _load_module("test104_tracked_test087_prearm_coordinator", COORDINATOR_PATH)
    original_root = coordinator.IWN_ROOT
    protocol = None
    old_helper = None
    old_values = None
    try:
        coordinator.IWN_ROOT = root
        protocol, _router = coordinator._modules()
        old_helper = protocol.HELPER_SOURCE
        old_values = (protocol.SENDER_FRAMES, protocol.SENDER_INTERVAL_MS,
                      protocol.FROZEN_METADATA_SENDER_INTERVAL_MS,
                      protocol.SENDER_DEADLINE_SECONDS, protocol.SENDER_TX_FLAGS)
        protocol.HELPER_SOURCE = ARM_HELPER
        protocol.SENDER_FRAMES = SENDER_CONTRACT["frames_max"]
        protocol.SENDER_INTERVAL_MS = SENDER_CONTRACT["interval_ms"]
        protocol.FROZEN_METADATA_SENDER_INTERVAL_MS = SENDER_CONTRACT["interval_ms"]
        protocol.SENDER_DEADLINE_SECONDS = SENDER_CONTRACT["max_elapsed_seconds"]
        protocol.SENDER_TX_FLAGS = SENDER_CONTRACT["radiotap_tx_flags"]
        metadata, _build, receipt_sha, _build_path = coordinator._validate_bundle(
            path, root.stat().st_uid, protocol)
    except Exception as error:
        code = getattr(error, "code", type(error).__name__)
        raise RuntimeBindingError("prearm_bundle_rejected:" + str(code)) from error
    finally:
        coordinator.IWN_ROOT = original_root
        if protocol is not None and old_helper is not None and old_values is not None:
            protocol.HELPER_SOURCE = old_helper
            (protocol.SENDER_FRAMES, protocol.SENDER_INTERVAL_MS,
             protocol.FROZEN_METADATA_SENDER_INTERVAL_MS,
             protocol.SENDER_DEADLINE_SECONDS, protocol.SENDER_TX_FLAGS) = old_values
    build, deployment, sender, build_raw, deployment_raw, sender_raw = _read_receipt_bundle(root)
    validate_disarmed_metadata(metadata, build, deployment, sender,
                               build_raw, deployment_raw, sender_raw)
    validate_test104_tool_contract(metadata, root)
    return {
        "status": "prearm_binding_validated",
        "candidate": metadata["candidate"],
        "expected_loaded_uuid": metadata["expected_loaded_uuid"],
        "build_receipt_sha256": receipt_sha,
        "armed": False,
        "claim_consumed": False,
        "run_directory_created": False,
    }


def write_disarmed_metadata(metadata: dict, *, iwn_root: Path) -> Path:
    root = Path(iwn_root).expanduser()
    if not root.is_absolute() or root.is_symlink():
        raise RuntimeBindingError("explicit_absolute_iwn_root_required")
    root = root.resolve(strict=True)
    build, deployment, sender, build_raw, deployment_raw, sender_raw = _read_receipt_bundle(root)
    validate_disarmed_metadata(metadata, build, deployment, sender,
                               build_raw, deployment_raw, sender_raw)
    validate_test104_tool_contract(metadata, root)
    finalizer = _load_module("test104_tracked_test087_finalizer_write", FINALIZER_PATH)
    if metadata.get("armed") is not False or metadata.get("status") != "prepared_disarmed":
        raise RuntimeBindingError("refusing_armed_runtime_metadata")
    finalizer.write_metadata(metadata, iwn_root=root)
    path = Path(finalizer.candidate_binding.metadata_path(root, CANDIDATE))
    validate_prearm_bundle(path, iwn_root=root)
    return path


def bind_runtime_identities(metadata: dict, router_receipt: dict,
                            target_receipt: dict, *, expected_boot_epoch: int,
                            expected_uuid: str, router_receipt_sha256: str | None = None,
                            now: dt.datetime | None = None) -> tuple[bytes, dict]:
    """Bind fresh post-boot identities and return a packet set, still offline."""
    extension = metadata.get("runtime_binding_test104")
    source_binding = metadata.get("source_binding")
    if (metadata.get("schema") != METADATA_SCHEMA or
            metadata.get("status") != "prepared_disarmed" or
            metadata.get("armed") is not False or
            not isinstance(extension, dict) or
            not isinstance(source_binding, dict) or
            extension.get("candidate") != CANDIDATE):
        raise RuntimeBindingError("runtime_metadata_not_disarmed_or_uuid_mismatch")
    target = packetset.validate_target_identity(
        target_receipt, expected_boot_epoch, expected_uuid,
        expected_binary_sha256=source_binding.get("expected_binary_sha256"),
        expected_build_receipt_sha256=source_binding.get("build_receipt_sha256"),
        expected_deployment_receipt_sha256=extension.get("deployment_receipt_sha256"))
    target_time = dt.datetime.fromisoformat(target["captured_at"].replace("Z", "+00:00"))
    source = packetset.parse_router_identity_receipt(
        router_receipt, receipt_sha256=router_receipt_sha256)
    now = now or dt.datetime.now(dt.timezone.utc)
    captured = dt.datetime.fromisoformat(source["captured_at"].replace("Z", "+00:00"))
    age = (now - captured.astimezone(dt.timezone.utc)).total_seconds()
    target_age = (now - target_time.astimezone(dt.timezone.utc)).total_seconds()
    if age < -10 or age > ROUTER_RECEIPT_MAX_AGE_SECONDS:
        raise RuntimeBindingError("router_source_identity_stale")
    if target_age < -10 or target_age > TARGET_RECEIPT_MAX_AGE_SECONDS:
        raise RuntimeBindingError("target_awdl0_identity_stale")
    if (metadata.get("expected_loaded_uuid") != expected_uuid or
            target_receipt.get("minimum_boot_epoch_exclusive") !=
                metadata.get("minimum_boot_epoch_exclusive") or
            target_receipt.get("build_receipt_sha256") != extension.get("build_receipt_sha256") or
            target_receipt.get("deployment_receipt_sha256") != extension.get("deployment_receipt_sha256")):
        raise RuntimeBindingError("target_awdl0_receipt_binding_mismatch")
    raw, manifest = packetset.encode_packet_set(source, target)
    manifest["identity_freshness"] = {
        "router_receipt_age_seconds": int(age),
        "target_receipt_age_seconds": int(target_age),
        "target_boot_epoch": target["boot_epoch"],
        "current_boot_match": True,
        "candidate_uuid_match": True,
    }
    manifest["packet_set_sha256"] = _sha(raw)
    return raw, manifest


def _atomic_write(path: Path, value: dict) -> None:
    _write_private_json(path, value)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="show disarmed preparation plan")
    plan.add_argument("--iwn-root", type=Path, required=True)
    plan.add_argument("--minimum-boot-epoch-exclusive", type=int, required=True)
    capture = sub.add_parser("capture-target", help="read current post-boot awdl0 identity")
    capture.add_argument("--iwn-root", type=Path, required=True)
    capture.add_argument("--minimum-boot-epoch-exclusive", type=int, required=True)
    capture.add_argument("--out", type=Path)
    write = sub.add_parser("write", help="write a validated disarmed runtime bundle")
    write.add_argument("--iwn-root", type=Path, required=True)
    write.add_argument("--minimum-boot-epoch-exclusive", type=int, required=True)
    prearm = sub.add_parser("prearm", help="validate a bundle without arming")
    prearm.add_argument("--iwn-root", type=Path, required=True)
    prearm.add_argument("--metadata", type=Path, required=True)
    bind = sub.add_parser("bind-identities", help="offline bind fresh private identities")
    bind.add_argument("--metadata", type=Path, required=True)
    bind.add_argument("--router-receipt", type=Path, required=True)
    bind.add_argument("--target-identity", type=Path, required=True)
    bind.add_argument("--expected-boot", type=int, required=True)
    bind.add_argument("--expected-uuid", required=True)
    bind.add_argument("--packet-set-out", type=Path, required=True)
    bind.add_argument("--manifest-out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture-target":
            output = args.out or (args.iwn_root / TARGET_RECEIPT_RELATIVE)
            result = capture_target_identity(
                iwn_root=args.iwn_root, output=output,
                minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive)
            print(json.dumps({"status": result["status"],
                              "boot_epoch": result["boot_epoch"],
                              "interface": result["interface"],
                              "ifindex_positive": result["ifindex"] > 0,
                              "candidate_uuid": result["candidate_uuid"],
                              "identity_receipt_sha256": result["identity_receipt_sha256"],
                              "output": str(output)}, sort_keys=True))
        elif args.command in {"plan", "write"}:
            metadata = build_disarmed_metadata(
                iwn_root=args.iwn_root,
                minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive)
            result = {"status": metadata["status"],
                      "candidate": metadata["candidate"],
                      "armed": metadata["armed"],
                      "target_address_deferred": True,
                      "router_address_deferred": True,
                      "metadata_schema": metadata["schema"]}
            if args.command == "write":
                output = write_disarmed_metadata(metadata, iwn_root=args.iwn_root)
                result.update({"status": "written_disarmed",
                               "output": str(output),
                               "metadata_sha256": _sha(output.read_bytes())})
            print(json.dumps(result, sort_keys=True))
        elif args.command == "prearm":
            print(json.dumps(validate_prearm_bundle(args.metadata,
                                                    iwn_root=args.iwn_root), sort_keys=True))
        else:
            owner_uid = _private_account().pw_uid
            metadata, _ = _read_private_json(args.metadata, owner_uid)
            router, router_raw = _read_private_json(args.router_receipt, owner_uid)
            target, _ = _read_private_json(args.target_identity, owner_uid)
            actual_boot = _read_boot_epoch()
            if args.expected_boot != actual_boot:
                raise RuntimeBindingError("expected_boot_not_current")
            loaded_uuid = _extract_loaded_uuid(_run_text([
                "/usr/bin/kmutil", "showloaded", "--list-only",
                "--bundle-identifier", "org.geekaudio.AirportItlwm"]))
            if args.expected_uuid != loaded_uuid:
                raise RuntimeBindingError("expected_uuid_not_current")
            packet_bytes, manifest = bind_runtime_identities(
                metadata, router, target, expected_boot_epoch=actual_boot,
                expected_uuid=loaded_uuid, router_receipt_sha256=_sha(router_raw))
            packetset._atomic_private_write(args.packet_set_out, packet_bytes)
            manifest_bytes = json.dumps(manifest, ensure_ascii=False,
                                        sort_keys=True, indent=2).encode("utf-8") + b"\n"
            packetset._atomic_private_write(args.manifest_out, manifest_bytes)
            print(json.dumps({"status": "identity_binding_validated",
                              "packet_set_sha256": _sha(packet_bytes),
                              "packet_count": packetset.PACKET_COUNT,
                              "transmission_capability": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeBindingError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
