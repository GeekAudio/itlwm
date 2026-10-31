#!/usr/bin/env python3
"""Test099 offline runtime binding and exact pre-arm validation.

This tool delegates bundle generation to the tracked Test087 finalizer and
pre-arm validation to the tracked Test087 coordinator. It never arms a driver,
consumes a boot claim, creates a run directory, loads a kext, or contacts a
router. The seven publication-contract fields are validated before a bundle
can be written or handed to a runtime coordinator.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
DEFAULT_IWN_ROOT = REPO_ROOT.parent / "IntelWirelessNative"
TEST087_DIR = REPO_ROOT / "developer-tools/test087"
TEST099_HELPER = TOOL_DIR / "arm_p2p_rx149_test099.swift"
FINALIZER_PATH = TEST087_DIR / "finalize_test087_runtime_binding.py"
COORDINATOR_PATH = TEST087_DIR / "controlled_run_coordinator.py"

PUBLICATION_FIELDS = {
    "schema": 1,
    "duration_ms": 4000,
    "property": "NativeRxPreOwnerSnapshot",
    "published_property": "NativeRxPreOwnerPublished",
    "revision_property": "NativeRxPreOwnerRevision",
    "schema_property": "NativeRxPreOwnerSchema",
    "arm_accepted_property": "NativeRxPreOwnerArmAccepted",
}

SENDER_CONTRACT = {
    "execution_host": "OpenWrt aarch64 router",
    "frames_max": 4,
    "interval_ms": 10,
    "max_elapsed_seconds": 0.04,
    "mpdu_bytes": 96,
    "radiotap_bytes": 10,
    "packet_bytes": 106,
    "udp_payload_bytes": 8,
    "tx_flags": "NOACK|NOSEQNO",
    "hardware_honoring": "unknown",
    "single_nonce_go": True,
}


class RuntimeBindingError(ValueError):
    """Fail-closed metadata or pre-arm binding error."""


def _load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeBindingError("tracked_test087_tool_unavailable")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeBindingError("tracked_test087_tool_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(name, None)
        raise RuntimeBindingError("tracked_test087_tool_import_failed") from error
    return module


def _finalizer():
    return _load_module("test099_tracked_test087_finalizer", FINALIZER_PATH)


def expected_publication_contract(build_contract: Any) -> dict:
    if not isinstance(build_contract, dict):
        raise RuntimeBindingError("build_preowner_contract_missing")
    return {**build_contract, **PUBLICATION_FIELDS}


def validate_publication_contract(metadata: dict, build: dict) -> None:
    expected = expected_publication_contract(
        build.get("rx_preowner_observation_contract"))
    if metadata.get("preowner_observation_contract") != expected:
        raise RuntimeBindingError("preowner_observation_contract_mismatch")


def validate_test099_tool_contract(metadata: dict) -> None:
    if TEST099_HELPER.is_symlink() or not TEST099_HELPER.is_file():
        raise RuntimeBindingError("test099_arm_helper_unavailable")
    expected_helper_hash = hashlib.sha256(TEST099_HELPER.read_bytes()).hexdigest()
    if metadata.get("expected_arm_helper_source_sha256") != expected_helper_hash:
        raise RuntimeBindingError("test099_arm_helper_hash_mismatch")
    if metadata.get("sender") != SENDER_CONTRACT:
        raise RuntimeBindingError("test099_sender_contract_mismatch")


def build_disarmed_metadata(*, minimum_boot_epoch_exclusive: int,
                            iwn_root: Path | str = DEFAULT_IWN_ROOT,
                            candidate: str,
                            build_receipt: Path | str | None = None,
                            baseline_receipt: Path | str | None = None) -> dict:
    """Build and validate a disarmed bundle through the tracked finalizer."""
    root = Path(iwn_root).expanduser().resolve(strict=True)
    finalizer = _finalizer()
    # The tracked Test087 finalizer can infer the baseline receipt when
    # validating, but its metadata builder later passes the unresolved None
    # path into candidate_binding.make_binding. Resolve both receipt paths
    # here so the exact same validated paths are used for generation.
    initial_build, _, _, _ = finalizer.validate_receipts(
        iwn_root=root, candidate=candidate,
        build_receipt=build_receipt, baseline_receipt=baseline_receipt)
    _, resolved_build, resolved_baseline, _ = finalizer._paths(
        root, candidate=candidate, build_receipt=build_receipt,
        baseline_receipt=baseline_receipt)
    if resolved_baseline is None:
        resolved_baseline = finalizer.candidate_binding.default_build_receipt_path(
            root, str(initial_build.get("baseline", "")))
    resolved_build = resolved_build.resolve(strict=True)
    resolved_baseline = resolved_baseline.resolve(strict=True)
    metadata = finalizer.build_metadata(
        minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive,
        iwn_root=root,
        candidate=candidate,
        build_receipt=resolved_build,
        baseline_receipt=resolved_baseline,
    )
    if TEST099_HELPER.is_symlink() or not TEST099_HELPER.is_file():
        raise RuntimeBindingError("test099_arm_helper_unavailable")
    metadata["expected_arm_helper_source_sha256"] = hashlib.sha256(
        TEST099_HELPER.read_bytes()).hexdigest()
    metadata["sender"] = dict(SENDER_CONTRACT)

    build, build_raw, baseline, baseline_raw = finalizer.validate_receipts(
        iwn_root=root,
        candidate=candidate,
        build_receipt=resolved_build,
        baseline_receipt=resolved_baseline,
    )
    metadata["preowner_observation_contract"] = expected_publication_contract(
        build.get("rx_preowner_observation_contract"))
    _, build_path, baseline_path, _ = finalizer._paths(
        root,
        candidate=candidate,
        build_receipt=resolved_build,
        baseline_receipt=resolved_baseline,
    )
    if baseline_path is None:
        baseline_path = finalizer.candidate_binding.default_build_receipt_path(
            root, str(build.get("baseline", "")))
    binding = finalizer.candidate_binding
    errors = binding.validate_metadata_binding(
        metadata,
        build,
        build_raw,
        baseline,
        baseline_raw,
        build_path.resolve(strict=True),
        baseline_path.resolve(strict=True),
        expected_candidate=candidate,
    )
    if errors:
        raise RuntimeBindingError("candidate_binding_failed:" + ",".join(errors))
    validate_publication_contract(metadata, build)
    if metadata.get("armed") is not False or metadata.get("status") != "prepared_disarmed":
        raise RuntimeBindingError("runtime_bundle_not_disarmed")
    validate_test099_tool_contract(metadata)
    return metadata


def validate_prearm_bundle(metadata_path: Path | str, *,
                           iwn_root: Path | str = DEFAULT_IWN_ROOT) -> dict:
    """Run Test087's exact bundle validator before any run-dir/claim/arm step."""
    root = Path(iwn_root).expanduser().resolve(strict=True)
    path = Path(metadata_path).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeBindingError("runtime_metadata_unavailable")

    coordinator = _load_module(
        "test099_tracked_test087_coordinator", COORDINATOR_PATH)
    original_root = coordinator.IWN_ROOT
    original_helper = None
    original_sender = None
    try:
        coordinator.IWN_ROOT = root
        protocol, _router = coordinator._modules()
        original_helper = protocol.HELPER_SOURCE
        protocol.HELPER_SOURCE = TEST099_HELPER
        original_sender = (
            protocol.SENDER_FRAMES,
            protocol.SENDER_INTERVAL_MS,
            protocol.FROZEN_METADATA_SENDER_INTERVAL_MS,
            protocol.SENDER_DEADLINE_SECONDS,
        )
        protocol.SENDER_FRAMES = SENDER_CONTRACT["frames_max"]
        protocol.SENDER_INTERVAL_MS = SENDER_CONTRACT["interval_ms"]
        protocol.FROZEN_METADATA_SENDER_INTERVAL_MS = SENDER_CONTRACT["interval_ms"]
        protocol.SENDER_DEADLINE_SECONDS = SENDER_CONTRACT["max_elapsed_seconds"]
        metadata, build, receipt_sha, _build_path = coordinator._validate_bundle(
            path, root.stat().st_uid, protocol)
    except Exception as error:
        code = getattr(error, "code", type(error).__name__)
        raise RuntimeBindingError("prearm_bundle_rejected:" + str(code)) from error
    finally:
        coordinator.IWN_ROOT = original_root
        if original_helper is not None:
            try:
                protocol.HELPER_SOURCE = original_helper
            except UnboundLocalError:
                pass
        if original_sender is not None:
            try:
                (protocol.SENDER_FRAMES,
                 protocol.SENDER_INTERVAL_MS,
                 protocol.FROZEN_METADATA_SENDER_INTERVAL_MS,
                 protocol.SENDER_DEADLINE_SECONDS) = original_sender
            except UnboundLocalError:
                pass

    validate_publication_contract(metadata, build)
    validate_test099_tool_contract(metadata)
    return {
        "status": "prearm_binding_validated",
        "candidate": metadata["candidate"],
        "expected_loaded_uuid": metadata["expected_loaded_uuid"],
        "build_receipt_sha256": receipt_sha,
        "preowner_publication_contract_valid": True,
        "armed": False,
        "claim_consumed": False,
        "run_directory_created": False,
    }


def write_disarmed_metadata(metadata: dict, *,
                            iwn_root: Path | str = DEFAULT_IWN_ROOT) -> Path:
    """Write a generated bundle after all receipt and contract checks pass."""
    root = Path(iwn_root).expanduser().resolve(strict=True)
    finalizer = _finalizer()
    validate_publication_contract(
        metadata,
        json.loads(Path(finalizer.candidate_binding.default_build_receipt_path(
            root, metadata["candidate"])).read_text(encoding="utf-8")),
    )
    validate_test099_tool_contract(metadata)
    if metadata.get("armed") is not False:
        raise RuntimeBindingError("refusing_armed_runtime_metadata")
    finalizer.write_metadata(metadata, iwn_root=root)
    path = finalizer.candidate_binding.metadata_path(root, metadata["candidate"])
    validate_prearm_bundle(path, iwn_root=root)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="build and validate disarmed metadata in memory")
    plan.add_argument("--minimum-boot-epoch-exclusive", type=int, required=True)
    plan.add_argument("--iwn-root", type=Path, default=DEFAULT_IWN_ROOT)
    plan.add_argument("--candidate", required=True)
    plan.add_argument("--build-receipt", type=Path)
    plan.add_argument("--baseline-receipt", type=Path)
    prearm = subparsers.add_parser("prearm", help="validate an existing bundle without arming")
    prearm.add_argument("--iwn-root", type=Path, default=DEFAULT_IWN_ROOT)
    prearm.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            metadata = build_disarmed_metadata(
                minimum_boot_epoch_exclusive=args.minimum_boot_epoch_exclusive,
                iwn_root=args.iwn_root,
                candidate=args.candidate,
                build_receipt=args.build_receipt,
                baseline_receipt=args.baseline_receipt,
            )
            result = {
                "status": "disarmed_runtime_binding_validated",
                "candidate": metadata["candidate"],
                "expected_loaded_uuid": metadata["expected_loaded_uuid"],
                "preowner_publication_contract_valid": True,
                "armed": False,
            }
        else:
            result = validate_prearm_bundle(args.metadata, iwn_root=args.iwn_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, RuntimeBindingError, ValueError, TypeError, KeyError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
