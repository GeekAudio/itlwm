#!/usr/bin/env python3
"""Create the disarmed Test087 runtime bundle from the final build receipt.

This is an offline binding step. It does not read IORegistry, consume a boot
claim, load a kext, contact OpenWrt, or perform RF activity. Private receipts
and generated metadata stay outside the public repository. The default private
workspace is a sibling ``IntelWirelessNative`` checkout; use ``--iwn-root``
when it lives elsewhere.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IWN_ROOT = REPO_ROOT.parent / "IntelWirelessNative"
HELPER_SOURCE = REPO_ROOT / "developer-tools/test087/arm_p2p_rx149_test087.swift"
UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def _paths(iwn_root: Path | str | None = None) -> tuple[Path, Path, Path, Path]:
    root = Path(iwn_root or DEFAULT_IWN_ROOT).expanduser()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("private workspace root must be an existing absolute directory")
    root = root.resolve()
    return (
        root,
        root / "research/test087-build-private.json",
        root / "research/test086-build-private.json",
        root / "research/test087-runtime-private",
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded)


def _read_private_json(path: Path) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("receipt unavailable or symlinked")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("receipt must be a private regular file")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("receipt must contain a JSON object")
    return value, raw


def validate_receipts(*, iwn_root: Path | str | None = None) -> tuple[dict, bytes, dict, bytes]:
    private_root, build_report, baseline_report, _ = _paths(iwn_root)
    build, build_raw = _read_private_json(build_report)
    baseline, baseline_raw = _read_private_json(baseline_report)
    if build.get("candidate") != "25G332-Test087" or build.get("status") != "built_offline":
        raise ValueError("final Test087 build receipt is not ready")
    if build.get("installed") is not False or build.get("rf_tested") is not False:
        raise ValueError("build receipt must remain offline and uninstalled")
    if build.get("baseline") != "25G332-Test086" or \
            baseline.get("candidate") != "25G332-Test086" or \
            baseline.get("status") != "built_offline":
        raise ValueError("Test086 baseline receipt mismatch")
    source_map = build.get("source_sha256")
    if (not isinstance(source_map, dict) or not source_map or
            build.get("source_file_count") != len(source_map)):
        raise ValueError("dynamic source map/count mismatch")
    for name, digest in source_map.items():
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or
                not relative.parts or not isinstance(digest, str) or
                not SHA_RE.fullmatch(digest)):
            raise ValueError("invalid source map entry")
        source = REPO_ROOT / relative
        if source.is_symlink() or not source.is_file() or sha256(source.read_bytes()) != digest:
            raise ValueError("current source differs from final build receipt")
    uuid = build.get("mach_o_uuid")
    if not isinstance(uuid, str) or not UUID_RE.fullmatch(uuid):
        raise ValueError("invalid build UUID")
    for field in ("binary_sha256", "info_plist_sha256"):
        value = build.get(field)
        if not isinstance(value, str) or not SHA_RE.fullmatch(value):
            raise ValueError("invalid build hash: " + field)
    if build.get("full_build_passed") is not True or build.get("strict_signature_passed") is not True:
        raise ValueError("build validation gates are incomplete")
    archive = Path(str(build.get("archive", "")))
    if (not archive.is_absolute() or archive.is_symlink() or not archive.is_file() or
            sha256(archive.read_bytes()) != build.get("archive_sha256")):
        raise ValueError("final archive hash mismatch")
    try:
        archive.resolve(strict=True).relative_to(private_root)
    except (OSError, ValueError):
        raise ValueError("final archive must be inside the private workspace")
    with zipfile.ZipFile(archive) as package:
        binary = package.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
        info = package.read("AirportItlwm.kext/Contents/Info.plist")
    if sha256(binary) != build.get("binary_sha256") or \
            sha256(info) != build.get("info_plist_sha256"):
        raise ValueError("archive contents differ from build receipt")
    profile = build.get("profile")
    if profile != "native_awdl_rx149_preowner_observation":
        raise ValueError("Test087 profile mismatch")
    rx = build.get("rx149_data_input_contract")
    if (not isinstance(rx, dict) or rx.get("channel") != 149 or
            rx.get("session_duration_ms") != 100 or
            rx.get("host_management_or_data_tx_allowed") is not False or
            rx.get("artifact_enabled") is not True):
        raise ValueError("Test087 RX149 contract mismatch")
    preowner = build.get("rx_preowner_observation_contract")
    if (not isinstance(preowner, dict) or preowner.get("window_us") != 4_000_000 or
            preowner.get("numeric_only") is not True or
            preowner.get("rx_policy_changed") is not False or
            preowner.get("tx_policy_changed") is not False or
            preowner.get("schema_version") != 1 or
            preowner.get("snapshot_property") != "NativeRxPreOwnerSnapshot" or
            preowner.get("source_header_sha256") !=
                source_map.get("native/rx_preowner_observation.hpp")):
        raise ValueError("Test087 pre-owner contract mismatch")
    helper_hash = sha256(HELPER_SOURCE.read_bytes()) if HELPER_SOURCE.is_file() else None
    if not helper_hash:
        raise ValueError("Test087 arm helper unavailable")
    return build, build_raw, baseline, baseline_raw


def build_metadata(*, minimum_boot_epoch_exclusive: int,
                   iwn_root: Path | str | None = None) -> dict:
    if type(minimum_boot_epoch_exclusive) is not int or minimum_boot_epoch_exclusive < 1:
        raise ValueError("minimum boot epoch must be a positive integer")
    _, build_report, baseline_report, _ = _paths(iwn_root)
    build, build_raw, baseline, baseline_raw = validate_receipts(iwn_root=iwn_root)
    source_map = build["source_sha256"]
    uuid = build["mach_o_uuid"]
    helper_hash = sha256(HELPER_SOURCE.read_bytes())
    receipt_path = str(build_report)
    baseline_path = str(baseline_report)
    preowner_receipt = build["rx_preowner_observation_contract"]
    contract = {
        **preowner_receipt,
        "schema": 1,
        "duration_ms": 4000,
        "property": "NativeRxPreOwnerSnapshot",
        "published_property": "NativeRxPreOwnerPublished",
        "revision_property": "NativeRxPreOwnerRevision",
        "schema_property": "NativeRxPreOwnerSchema",
        "arm_accepted_property": "NativeRxPreOwnerArmAccepted",
    }
    frozen = {
        "build_report": receipt_path,
        "expected_loaded_uuid": uuid,
        "expected_binary_sha256": build["binary_sha256"],
        "expected_info_plist_sha256": build["info_plist_sha256"],
        "source_sha256": source_map,
        "armed": False,
        "status": "frozen_disarmed",
    }
    binding = {
        "build_report_path": receipt_path,
        "build_receipt_sha256": sha256(build_raw),
        "baseline_build_report_path": baseline_path,
        "baseline_build_report_sha256": sha256(baseline_raw),
        "expected_loaded_uuid": uuid,
        "expected_binary_sha256": build["binary_sha256"],
        "expected_info_plist_sha256": build["info_plist_sha256"],
        "source_file_count": len(source_map),
        "source_sha256_map_sha256": canonical_json_sha256(source_map),
        "frozen_test087_metadata": frozen,
    }
    return {
        "schema": "test087-controlled-probe-private/v1",
        "candidate": build["candidate"],
        "baseline": build["baseline"],
        "source_ready_kind": "controlled_probe",
        "requires_phone_ready": False,
        "armed": False,
        "status": "prepared_disarmed",
        "retry_allowed": False,
        "expected_loaded_uuid": uuid,
        "profile": build["profile"],
        "minimum_boot_epoch_exclusive": minimum_boot_epoch_exclusive,
        "diagnostic_duration_ms": 100,
        "preowner_observation_duration_ms": 4000,
        "receiver_gated": True,
        "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
        "required_zero_host_tx_counters": [
            "NativeP2PTxProbeEverDoorbelled",
            "NativeP2PAwdlActionFramesSubmitted",
            "NativeP2PAwdlPsfFrameSubmitted",
            "NativeP2PAwdlMifFrameSubmitted",
            "NativeP2PAwdlMifBootstrapSubmitted",
            "NativeAwdlDataTxSubmitted",
            "NativeAwdlDataTxPending",
        ],
        "owner_epoch_fields": [
            "ContextGeneration", "PowerGeneration", "StationGeneration", "RocGeneration"],
        "source_sha256": source_map,
        "expected_arm_helper_source_sha256": helper_hash,
        "rx149_data_input_contract": build["rx149_data_input_contract"],
        "preowner_observation_contract": contract,
        "sender": {
            "execution_host": "OpenWrt aarch64 router",
            "frames_max": 16,
            "interval_ms": 80,
            "max_elapsed_seconds": 2,
            "mpdu_bytes": 96,
            "radiotap_bytes": 10,
            "packet_bytes": 106,
            "udp_payload_bytes": 8,
            "tx_flags": "NOACK|NOSEQNO",
            "hardware_honoring": "unknown",
            "single_nonce_go": True,
        },
        "source_binding": binding,
    }


def write_metadata(metadata: dict, *, iwn_root: Path | str | None = None) -> None:
    _, _, _, output_root = _paths(iwn_root)
    output_metadata = output_root / "native-controlled-probe-private.json"
    if output_root.exists():
        if output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("runtime output path is unsafe")
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("runtime output directory must have mode 0700")
    else:
        output_root.mkdir(mode=0o700)
    if output_metadata.exists() or output_metadata.is_symlink():
        raise ValueError("refusing to overwrite existing runtime metadata")
    encoded = (json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".native-controlled-", dir=output_root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output_metadata)
        os.chmod(output_metadata, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minimum-boot-epoch-exclusive", type=int, required=True,
                        help="Current boot epoch; this run requires a later boot.")
    parser.add_argument("--iwn-root", type=Path, default=DEFAULT_IWN_ROOT,
                        help="Private IntelWirelessNative workspace (defaults to sibling checkout).")
    parser.add_argument("--plan", action="store_true",
                        help="Validate final receipts and print the disarmed binding without writing it.")
    args = parser.parse_args(argv)
    try:
        metadata = build_metadata(
            minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive,
            iwn_root=args.iwn_root)
        if args.plan:
            print(json.dumps({
                "mode": "plan", "candidate": metadata["candidate"],
                "expected_loaded_uuid": metadata["expected_loaded_uuid"],
                "source_file_count": metadata["source_binding"]["source_file_count"],
                "build_receipt_sha256": metadata["source_binding"]["build_receipt_sha256"],
                "output": str(args.iwn_root / "research/test087-runtime-private/"
                               "native-controlled-probe-private.json"), "armed": False,
            }, sort_keys=True))
            return 0
        write_metadata(metadata, iwn_root=args.iwn_root)
        print("TEST087_RUNTIME_BINDING_WRITTEN")
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, TypeError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
