#!/usr/bin/env python3
"""Create a disarmed native AWDL RX149 runtime bundle from build receipts.

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
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IWN_ROOT = REPO_ROOT.parent / "IntelWirelessNative"
HELPER_SOURCE = REPO_ROOT / "developer-tools/test087/arm_p2p_rx149_test087.swift"
UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
import candidate_binding as candidate_binding


def _paths(iwn_root: Path | str | None = None, *, candidate: str = "25G332-Test087",
           build_receipt: Path | str | None = None,
           baseline_receipt: Path | str | None = None,
           output_root: Path | str | None = None) -> tuple[Path, Path, Path, Path]:
    root = Path(iwn_root or DEFAULT_IWN_ROOT).expanduser()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("private workspace root must be an existing absolute directory")
    root = root.resolve()
    research = root / "research"
    if (research.is_symlink() or not research.is_dir() or
            research.stat().st_uid != root.stat().st_uid or
            research.stat().st_mode & 0o022):
        raise ValueError("private research directory is unsafe")
    if not candidate_binding.valid_candidate(candidate):
        raise ValueError("candidate tag is invalid")
    build_path = Path(build_receipt) if build_receipt else \
        candidate_binding.default_build_receipt_path(root, candidate)
    baseline_path = Path(baseline_receipt) if baseline_receipt else None
    expected_runtime_root = candidate_binding.runtime_private_root(root, candidate)
    runtime_root = Path(output_root) if output_root else expected_runtime_root
    if runtime_root != expected_runtime_root:
        raise ValueError("output root does not match candidate")
    return root, build_path.expanduser(), baseline_path, runtime_root.expanduser()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded)


def _read_private_json(path: Path, *, owner_uid: int) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("receipt unavailable or symlinked")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
            info.st_mode & 0o077):
        raise ValueError("receipt must be a private regular file")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("receipt must contain a JSON object")
    return value, raw


def _validate_receipt_path(path: Path, research_root: Path) -> None:
    if path.is_symlink() or not path.is_absolute() or not path.is_file():
        raise ValueError("receipt path must be an absolute regular file")
    try:
        if path.parent.resolve(strict=True) != research_root.resolve(strict=True):
            raise ValueError("receipt must be directly under private research")
    except (OSError, ValueError):
        raise ValueError("receipt must live under the private research directory")


def validate_receipts(*, iwn_root: Path | str | None = None,
                      candidate: str | None = None,
                      build_receipt: Path | str | None = None,
                      baseline_receipt: Path | str | None = None,
                      output_root: Path | str | None = None
                      ) -> tuple[dict, bytes, dict, bytes]:
    selected_candidate = candidate or "25G332-Test087"
    private_root, build_report, baseline_report, _ = _paths(
        iwn_root, candidate=selected_candidate, build_receipt=build_receipt,
        baseline_receipt=baseline_receipt)
    research_root = private_root / "research"
    _validate_receipt_path(build_report, research_root)
    # Resolve harmless workspace aliases (for example /var -> /private/var)
    # before comparing candidate-derived receipt paths. The receipt itself and
    # its direct parent are still checked above for symlinks and containment.
    build_report = build_report.resolve(strict=True)
    owner_uid = private_root.stat().st_uid
    build, build_raw = _read_private_json(build_report, owner_uid=owner_uid)
    if candidate is None:
        selected_candidate = build.get("candidate")
    if not candidate_binding.valid_candidate(selected_candidate):
        raise ValueError("candidate tag is invalid")
    expected_output_root = candidate_binding.runtime_private_root(
        private_root, selected_candidate)
    if output_root is not None and Path(output_root) != expected_output_root:
        raise ValueError("output root does not match candidate")
    if build_report != candidate_binding.default_build_receipt_path(
            research_root.parent, selected_candidate):
        raise ValueError("build receipt path does not match its candidate")
    if baseline_report is None:
        baseline_report = candidate_binding.default_build_receipt_path(
            research_root.parent, str(build.get("baseline", "")))
    _validate_receipt_path(baseline_report, research_root)
    baseline_report = baseline_report.resolve(strict=True)
    expected_baseline = candidate_binding.default_build_receipt_path(
        research_root.parent, str(build.get("baseline", "")))
    if baseline_report != expected_baseline:
        raise ValueError("baseline receipt path does not match its candidate")
    baseline, baseline_raw = _read_private_json(baseline_report, owner_uid=owner_uid)
    receipt_errors = candidate_binding.validate_receipt_pair(
        build, build_raw, baseline, baseline_raw,
        expected_candidate=selected_candidate)
    if receipt_errors:
        raise ValueError("candidate receipt binding failed: " + ",".join(receipt_errors))
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
    if profile != candidate_binding.SUPPORTED_PROFILE:
        raise ValueError("unsupported candidate profile")
    rx = build.get("rx149_data_input_contract")
    if (not isinstance(rx, dict) or rx.get("channel") != 149 or
            rx.get("session_duration_ms") != 100 or
            rx.get("host_management_or_data_tx_allowed") is not False or
            rx.get("artifact_enabled") is not True):
        raise ValueError("candidate RX149 contract mismatch")
    preowner = build.get("rx_preowner_observation_contract")
    if (not isinstance(preowner, dict) or preowner.get("window_us") != 4_000_000 or
            preowner.get("numeric_only") is not True or
            preowner.get("rx_policy_changed") is not False or
            preowner.get("tx_policy_changed") is not False or
            preowner.get("schema_version") != 1 or
            preowner.get("snapshot_property") != "NativeRxPreOwnerSnapshot" or
            preowner.get("source_header_sha256") !=
                source_map.get("native/rx_preowner_observation.hpp")):
        raise ValueError("candidate pre-owner contract mismatch")
    helper_hash = sha256(HELPER_SOURCE.read_bytes()) if HELPER_SOURCE.is_file() else None
    if not helper_hash:
        raise ValueError("RX149 arm helper unavailable")
    return build, build_raw, baseline, baseline_raw


def build_metadata(*, minimum_boot_epoch_exclusive: int,
                   iwn_root: Path | str | None = None,
                   candidate: str | None = None,
                   build_receipt: Path | str | None = None,
                   baseline_receipt: Path | str | None = None,
                   output_root: Path | str | None = None) -> dict:
    if type(minimum_boot_epoch_exclusive) is not int or minimum_boot_epoch_exclusive < 1:
        raise ValueError("minimum boot epoch must be a positive integer")
    build, build_raw, baseline, baseline_raw = validate_receipts(
        iwn_root=iwn_root, candidate=candidate, build_receipt=build_receipt,
        baseline_receipt=baseline_receipt)
    _, build_report, baseline_report, _ = _paths(
        iwn_root, candidate=build["candidate"], build_receipt=build_receipt,
        baseline_receipt=baseline_receipt, output_root=output_root)
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
    identity = candidate_binding.make_binding(
        build, build_raw, baseline, baseline_raw, build_report, baseline_report)
    binding = candidate_binding.source_binding_dict(identity)
    return {
        "schema": candidate_binding.METADATA_SCHEMA,
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


def write_metadata(metadata: dict, *, iwn_root: Path | str | None = None,
                   output_root: Path | str | None = None) -> None:
    candidate = metadata.get("candidate")
    _, _, _, default_output_root = _paths(
        iwn_root, candidate=candidate or "25G332-Test087", output_root=output_root)
    output_root = default_output_root
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
    parser.add_argument("--candidate", help="Expected candidate tag; must equal the build receipt.")
    parser.add_argument("--build-receipt", type=Path,
                        help="Candidate build receipt under research/; defaults from --candidate.")
    parser.add_argument("--baseline-receipt", type=Path,
                        help="Baseline build receipt; defaults from the candidate receipt.")
    parser.add_argument("--output-root", type=Path,
                        help="Candidate-private runtime directory; defaults from the candidate tag.")
    parser.add_argument("--plan", action="store_true",
                        help="Validate final receipts and print the disarmed binding without writing it.")
    args = parser.parse_args(argv)
    try:
        metadata = build_metadata(
            minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive,
            iwn_root=args.iwn_root, candidate=args.candidate,
            build_receipt=args.build_receipt,
            baseline_receipt=args.baseline_receipt, output_root=args.output_root)
        if args.plan:
            output_path = (args.output_root or candidate_binding.runtime_private_root(
                args.iwn_root, metadata["candidate"])) / "native-controlled-probe-private.json"
            print(json.dumps({
                "mode": "plan", "candidate": metadata["candidate"],
                "expected_loaded_uuid": metadata["expected_loaded_uuid"],
                "source_file_count": metadata["source_binding"]["source_file_count"],
                "build_receipt_sha256": metadata["source_binding"]["build_receipt_sha256"],
                "output": str(output_path), "armed": False,
            }, sort_keys=True))
            return 0
        write_metadata(metadata, iwn_root=args.iwn_root, output_root=args.output_root)
        print("CANDIDATE_RUNTIME_BINDING_WRITTEN")
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, TypeError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
