#!/usr/bin/env python3
"""Shared fail-closed candidate/build-receipt binding for native AWDL tools.

This module is deliberately offline and side-effect free.  It validates the
identity and measurement contract carried by a successful build receipt; it
does not arm a driver, consume a claim, load a kext, or contact a router.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional


SUPPORTED_PROFILE = "native_awdl_rx149_preowner_observation"
METADATA_SCHEMA = "native-awdl-rx149-controlled-probe-private/v2"
LEGACY_METADATA_SCHEMA = "test087-controlled-probe-private/v1"
LEGACY_CANDIDATE = "25G332-Test087"
SOURCE_KIND = "controlled_probe"
UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
CANDIDATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CandidateBindingError(ValueError):
    """A fail-closed candidate receipt or metadata binding error."""


@dataclass(frozen=True)
class CandidateBinding:
    candidate: str
    profile: str
    mach_o_uuid: str
    binary_sha256: str
    info_plist_sha256: str
    build_receipt_sha256: str
    baseline_candidate: str
    baseline_receipt_sha256: str
    source_sha256: Dict[str, str]
    source_sha256_map_sha256: str
    source_file_count: int
    build_receipt_path: Path
    baseline_receipt_path: Path


def valid_candidate(candidate: Any) -> bool:
    return isinstance(candidate, str) and CANDIDATE_RE.fullmatch(candidate) is not None


def candidate_key(candidate: str) -> str:
    """Return the conventional private research key without losing full tag identity."""
    if not valid_candidate(candidate):
        raise CandidateBindingError("candidate tag invalid")
    match = re.search(r"(?:^|[-_])(test[0-9]{3,})$", candidate, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return re.sub(r"[^a-z0-9]+", "-", candidate.lower()).strip("-")


def runtime_private_root(iwn_root: Path | str, candidate: str) -> Path:
    return Path(iwn_root) / "research" / (candidate_key(candidate) + "-runtime-private")


def default_build_receipt_path(iwn_root: Path | str, candidate: str) -> Path:
    return Path(iwn_root) / "research" / (candidate_key(candidate) + "-build-private.json")


def metadata_path(iwn_root: Path | str, candidate: str) -> Path:
    return runtime_private_root(iwn_root, candidate) / "native-controlled-probe-private.json"


def normalize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the shipped Test087 v1 bundle for backward-compatible reads.

    This narrow adapter is only for the existing Test087 private metadata. New
    candidates must use the candidate-bound v2 schema emitted by the finalizer.
    """
    if metadata.get("schema") == METADATA_SCHEMA:
        return metadata
    if (metadata.get("schema") != LEGACY_METADATA_SCHEMA or
            metadata.get("candidate") != LEGACY_CANDIDATE):
        raise CandidateBindingError("metadata schema unsupported")
    normalized = dict(metadata)
    normalized["schema"] = METADATA_SCHEMA
    old = normalized.get("source_binding")
    if not isinstance(old, dict):
        raise CandidateBindingError("legacy source binding missing")
    old = dict(old)
    frozen = old.pop("frozen_test087_metadata", None)
    if not isinstance(frozen, dict):
        raise CandidateBindingError("legacy frozen metadata missing")
    frozen_candidate = dict(frozen)
    frozen_candidate.update({
        "candidate": LEGACY_CANDIDATE,
        "profile": normalized.get("profile"),
    })
    old.update({
        "schema": "candidate-build-binding/v1",
        "candidate": LEGACY_CANDIDATE,
        "profile": normalized.get("profile"),
        "frozen_candidate_metadata": frozen_candidate,
    })
    normalized["source_binding"] = old
    return normalized


def canonical_json_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _valid_source_map(value: Any) -> bool:
    return (isinstance(value, dict) and bool(value) and
            all(isinstance(name, str) and name and "\\" not in name and
                not Path(name).is_absolute() and ".." not in Path(name).parts and
                "." not in Path(name).parts and isinstance(digest, str) and
                SHA_RE.fullmatch(digest) is not None
                for name, digest in value.items()))


def validate_build_receipt(receipt: Dict[str, Any], receipt_raw: bytes, *,
                           expected_candidate: Optional[str] = None) -> List[str]:
    """Validate the candidate identity and fixed RX149/pre-owner safety contract."""
    errors: List[str] = []
    candidate = receipt.get("candidate")
    if (not valid_candidate(candidate) or
            (expected_candidate is not None and candidate != expected_candidate)):
        errors.append("candidate")
    if receipt.get("status") != "built_offline":
        errors.append("build_status")
    if receipt.get("installed") is not False or receipt.get("rf_tested") is not False:
        errors.append("build_not_offline")
    if receipt.get("full_build_passed") is not True or \
            receipt.get("strict_signature_passed") is not True:
        errors.append("build_gates")
    if receipt.get("source_freeze_matches") is not True:
        errors.append("source_freeze_matches")
    if receipt.get("profile") != SUPPORTED_PROFILE:
        errors.append("profile")
    uuid = receipt.get("mach_o_uuid")
    if not isinstance(uuid, str) or UUID_RE.fullmatch(uuid) is None:
        errors.append("mach_o_uuid")
    for field in ("binary_sha256", "info_plist_sha256", "archive_sha256"):
        digest = receipt.get(field)
        if not isinstance(digest, str) or SHA_RE.fullmatch(digest) is None:
            errors.append(field)
    source_map = receipt.get("source_sha256")
    if (not _valid_source_map(source_map) or
            receipt.get("source_file_count") != len(source_map or {})):
        errors.append("source_sha256")
        source_map = source_map if isinstance(source_map, dict) else {}
    baseline = receipt.get("baseline")
    if not valid_candidate(baseline):
        errors.append("baseline")
    rx = receipt.get("rx149_data_input_contract")
    if (not isinstance(rx, dict) or rx.get("artifact_enabled") is not True or
            rx.get("host_management_or_data_tx_allowed") is not False or
            rx.get("session_duration_ms") != 100 or rx.get("channel") != 149 or
            rx.get("source_header") != "native/p2p_rx149_data_input.hpp" or
            rx.get("source_header_sha256") !=
                source_map.get("native/p2p_rx149_data_input.hpp")):
        errors.append("rx149_contract")
    preowner = receipt.get("rx_preowner_observation_contract")
    if (not isinstance(preowner, dict) or preowner.get("window_us") != 4_000_000 or
            preowner.get("numeric_only") is not True or
            preowner.get("rx_policy_changed") is not False or
            preowner.get("tx_policy_changed") is not False or
            preowner.get("schema_version") != 1 or
            preowner.get("snapshot_property") != "NativeRxPreOwnerSnapshot" or
            preowner.get("source_header_sha256") !=
                source_map.get("native/rx_preowner_observation.hpp")):
        errors.append("preowner_contract")
    if not isinstance(receipt_raw, bytes) or not receipt_raw:
        errors.append("receipt_bytes")
    return sorted(set(errors))


def validate_receipt_pair(build: Dict[str, Any], build_raw: bytes,
                          baseline: Dict[str, Any], baseline_raw: bytes, *,
                          expected_candidate: Optional[str] = None) -> List[str]:
    errors = validate_build_receipt(
        build, build_raw, expected_candidate=expected_candidate)
    baseline_candidate = build.get("baseline")
    if (not isinstance(baseline, dict) or
            not valid_candidate(baseline_candidate) or
            baseline.get("candidate") != baseline_candidate or
            baseline.get("status") != "built_offline" or
            baseline.get("installed") is not False):
        errors.append("baseline_receipt_identity")
    # Test087 and later receipts use baseline_build_report_sha256. Accept the
    # older explicit baseline_receipt_sha256 spelling, but never omit the hash.
    recorded_baseline_sha = build.get("baseline_build_report_sha256")
    if recorded_baseline_sha is None:
        recorded_baseline_sha = build.get("baseline_receipt_sha256")
    actual_baseline_sha = (hashlib.sha256(baseline_raw).hexdigest()
                           if isinstance(baseline_raw, bytes) else None)
    if (not isinstance(recorded_baseline_sha, str) or
            SHA_RE.fullmatch(recorded_baseline_sha) is None or
            recorded_baseline_sha != actual_baseline_sha):
        errors.append("baseline_receipt_hash")
    if not isinstance(baseline_raw, bytes) or not baseline_raw:
        errors.append("baseline_receipt_bytes")
    return sorted(set(errors))


def make_binding(build: Dict[str, Any], build_raw: bytes,
                 baseline: Dict[str, Any], baseline_raw: bytes,
                 build_path: Path, baseline_path: Path) -> CandidateBinding:
    errors = validate_receipt_pair(build, build_raw, baseline, baseline_raw)
    if errors:
        raise CandidateBindingError("receipt binding invalid: " + ",".join(errors))
    source_map = dict(build["source_sha256"])
    return CandidateBinding(
        candidate=build["candidate"], profile=build["profile"],
        mach_o_uuid=build["mach_o_uuid"],
        binary_sha256=build["binary_sha256"],
        info_plist_sha256=build["info_plist_sha256"],
        build_receipt_sha256=hashlib.sha256(build_raw).hexdigest(),
        baseline_candidate=build["baseline"],
        baseline_receipt_sha256=hashlib.sha256(baseline_raw).hexdigest(),
        source_sha256=source_map,
        source_sha256_map_sha256=canonical_json_sha256(source_map),
        source_file_count=len(source_map),
        build_receipt_path=Path(build_path),
        baseline_receipt_path=Path(baseline_path),
    )


def source_binding_dict(binding: CandidateBinding) -> Dict[str, Any]:
    frozen = {
        "candidate": binding.candidate,
        "profile": binding.profile,
        "build_report": str(binding.build_receipt_path),
        "expected_loaded_uuid": binding.mach_o_uuid,
        "expected_binary_sha256": binding.binary_sha256,
        "expected_info_plist_sha256": binding.info_plist_sha256,
        "source_sha256": binding.source_sha256,
        "status": "frozen_disarmed",
        "armed": False,
    }
    return {
        "schema": "candidate-build-binding/v1",
        "candidate": binding.candidate,
        "profile": binding.profile,
        "build_report_path": str(binding.build_receipt_path),
        "build_receipt_sha256": binding.build_receipt_sha256,
        "baseline_build_report_path": str(binding.baseline_receipt_path),
        "baseline_build_report_sha256": binding.baseline_receipt_sha256,
        "expected_loaded_uuid": binding.mach_o_uuid,
        "expected_binary_sha256": binding.binary_sha256,
        "expected_info_plist_sha256": binding.info_plist_sha256,
        "source_file_count": binding.source_file_count,
        "source_sha256_map_sha256": binding.source_sha256_map_sha256,
        "frozen_candidate_metadata": frozen,
    }


def validate_metadata_binding(metadata: Dict[str, Any], build: Dict[str, Any],
                              build_raw: bytes, baseline: Dict[str, Any],
                              baseline_raw: bytes, build_path: Path,
                              baseline_path: Path, *,
                              expected_candidate: Optional[str] = None) -> List[str]:
    """Validate candidate, UUID, hashes, receipt paths, and unchanged measurement gates."""
    errors = validate_receipt_pair(
        build, build_raw, baseline, baseline_raw,
        expected_candidate=expected_candidate)
    candidate = build.get("candidate")
    profile = build.get("profile")
    binding = metadata.get("source_binding")
    if not isinstance(binding, dict):
        return sorted(set(errors + ["source_binding"]))
    source_map = build.get("source_sha256")
    if not isinstance(source_map, dict):
        source_map = {}
    build_sha = hashlib.sha256(build_raw).hexdigest()
    baseline_sha = hashlib.sha256(baseline_raw).hexdigest()
    identity_expected = {
        "schema": METADATA_SCHEMA,
        "candidate": candidate,
        "baseline": build.get("baseline"),
        "source_ready_kind": SOURCE_KIND,
        "requires_phone_ready": False,
        "armed": False,
        "status": "prepared_disarmed",
        "retry_allowed": False,
        "expected_loaded_uuid": build.get("mach_o_uuid"),
        "profile": profile,
        "diagnostic_duration_ms": 100,
        "preowner_observation_duration_ms": 4000,
        "receiver_gated": True,
        "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
        "source_sha256": source_map,
        "rx149_data_input_contract": build.get("rx149_data_input_contract"),
    }
    for key, value in identity_expected.items():
        if metadata.get(key) != value:
            errors.append("metadata_" + key)
    try:
        minimum_epoch = metadata.get("minimum_boot_epoch_exclusive")
        if type(minimum_epoch) is not int or minimum_epoch < 1:
            errors.append("minimum_boot_epoch")
    except TypeError:
        errors.append("minimum_boot_epoch")
    if str(build_path) != binding.get("build_report_path"):
        errors.append("build_receipt_path")
    if str(baseline_path) != binding.get("baseline_build_report_path"):
        errors.append("baseline_receipt_path")
    nested_expected = {
        "schema": "candidate-build-binding/v1",
        "candidate": candidate,
        "profile": profile,
        "build_report_path": str(build_path),
        "build_receipt_sha256": build_sha,
        "baseline_build_report_path": str(baseline_path),
        "baseline_build_report_sha256": baseline_sha,
        "expected_loaded_uuid": build.get("mach_o_uuid"),
        "expected_binary_sha256": build.get("binary_sha256"),
        "expected_info_plist_sha256": build.get("info_plist_sha256"),
        "source_file_count": len(source_map),
        "source_sha256_map_sha256": canonical_json_sha256(source_map),
    }
    for key, value in nested_expected.items():
        if binding.get(key) != value:
            errors.append("binding_" + key)
    frozen = binding.get("frozen_candidate_metadata")
    frozen_expected = {
        "candidate": candidate,
        "profile": profile,
        "build_report": str(build_path),
        "expected_loaded_uuid": build.get("mach_o_uuid"),
        "expected_binary_sha256": build.get("binary_sha256"),
        "expected_info_plist_sha256": build.get("info_plist_sha256"),
        "source_sha256": source_map,
        "status": "frozen_disarmed",
        "armed": False,
    }
    if not isinstance(frozen, dict):
        errors.append("frozen_candidate_metadata")
    else:
        for key, value in frozen_expected.items():
            if frozen.get(key) != value:
                errors.append("frozen_" + key)
    preowner_receipt = build.get("rx_preowner_observation_contract")
    expected_preowner = {
        **(preowner_receipt if isinstance(preowner_receipt, dict) else {}),
        "schema": 1,
        "duration_ms": 4000,
        "property": "NativeRxPreOwnerSnapshot",
        "published_property": "NativeRxPreOwnerPublished",
        "revision_property": "NativeRxPreOwnerRevision",
        "schema_property": "NativeRxPreOwnerSchema",
        "arm_accepted_property": "NativeRxPreOwnerArmAccepted",
    }
    if metadata.get("preowner_observation_contract") != expected_preowner:
        errors.append("preowner_observation_contract")
    if metadata.get("owner_epoch_fields") != [
            "ContextGeneration", "PowerGeneration", "StationGeneration", "RocGeneration"]:
        errors.append("owner_epoch_fields")
    return sorted(set(errors))

