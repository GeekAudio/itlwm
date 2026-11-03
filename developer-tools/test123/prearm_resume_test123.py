#!/usr/bin/env python3
"""One-use continuation gate for a verified Test123 pre-ARM abort.

This module never reads live device state, starts a capture, contacts OpenWrt,
or changes the kernel claim. The caller must obtain the current boot epoch and
loaded UUID independently, then pass them here. The normal Test104/Test087
preflight still runs on the continuation and remains authoritative for whether
the kernel claim is currently available.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]


def _load_binding():
    path = TOOL_DIR / "rx149_binding_test123.py"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("test123_prearm_binding_unavailable")
    name = "tool123_prearm_resume_binding"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test123_prearm_binding_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise RuntimeError("test123_prearm_binding_import_failed") from error
    return module


BINDING = _load_binding()
KERNEL_METADATA = BINDING.KERNEL_METADATA
TOOL_ROOT = BINDING.TOOL_ROOT
KERNEL_CANDIDATE = BINDING.KERNEL_CANDIDATE

REPORT_NAME = "test123-tools-private.json"
CAPTURE_NAME = "native-controlled-capture-private.json"
CLEANUP_NAME = "prearm-abort-cleanup-observation-private.json"
HOST_PROCESSES_NAME = "host-post-abort-processes-private.json"
MARKER_NAME = "prearm-resume-claim-private.json"
RESUME_DIRECTORY_SUFFIX = "-prearm-resume"
REPORT_SCHEMA = "test104-tools-controlled-run-private/v1"
CAPTURE_SCHEMA = "native-awdl-rx149-controlled-native-runtime-private/v3"
CLEANUP_SCHEMA = "test123-prearm-abort-cleanup-observation-private/v1"
RESUME_SCHEMA = "test123-prearm-resume-claim-private/v1"
MAX_PRIVATE_JSON_BYTES = 16 * 1024 * 1024
UUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PrearmResumeError(ValueError):
    """A fail-closed rejection of a proposed pre-ARM continuation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PrearmResumeError("private_json_duplicate_key")
        result[key] = value
    return result


def _workspace_owner() -> tuple[int, int]:
    try:
        info = REPO_ROOT.stat()
    except OSError as error:
        raise PrearmResumeError("workspace_owner_unavailable") from error
    if os.geteuid() not in (0, info.st_uid):
        raise PrearmResumeError("executor_not_workspace_owner_or_root")
    return info.st_uid, info.st_gid


def _check_private_directory(path: Path, owner_uid: int) -> None:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise PrearmResumeError("private_directory_path_invalid")
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as error:
        raise PrearmResumeError("private_directory_unavailable") from error
    if (resolved != path or not stat.S_ISDIR(info.st_mode) or
            stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != owner_uid):
        raise PrearmResumeError("private_directory_mode_owner_or_path_invalid")


def _read_private_json(path: Path, *, owner_uid: int) -> tuple[dict[str, Any], bytes]:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise PrearmResumeError("private_record_path_invalid")
    try:
        if path.resolve(strict=True) != path:
            raise PrearmResumeError("private_record_path_not_canonical")
        parent_info = path.parent.lstat()
        info = path.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or
                stat.S_IMODE(parent_info.st_mode) != 0o700 or
                parent_info.st_uid != owner_uid or
                not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
                stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_size > MAX_PRIVATE_JSON_BYTES):
            raise PrearmResumeError("private_record_mode_owner_or_size_invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != info.st_dev or
                    opened.st_ino != info.st_ino or opened.st_uid != owner_uid or
                    stat.S_IMODE(opened.st_mode) != 0o600):
                raise PrearmResumeError("private_record_changed_during_read")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_PRIVATE_JSON_BYTES + 1)
        finally:
            os.close(fd)
    except PrearmResumeError:
        raise
    except OSError as error:
        raise PrearmResumeError("private_record_unavailable") from error
    if len(raw) > MAX_PRIVATE_JSON_BYTES:
        raise PrearmResumeError("private_record_too_large")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except PrearmResumeError:
        raise
    except (ValueError, TypeError) as error:
        raise PrearmResumeError("private_record_malformed") from error
    if not isinstance(value, dict):
        raise PrearmResumeError("private_record_not_object")
    return value, raw


def _expected_paths(boot_epoch: int) -> dict[str, Path]:
    if type(boot_epoch) is not int or boot_epoch <= 0:
        raise PrearmResumeError("current_boot_epoch_invalid")
    metadata = Path(KERNEL_METADATA)
    if not metadata.is_absolute() or metadata.is_symlink():
        raise PrearmResumeError("kernel_metadata_anchor_invalid")
    try:
        metadata = metadata.resolve(strict=True)
    except OSError as error:
        raise PrearmResumeError("kernel_metadata_anchor_unavailable") from error
    output_parent = metadata.parent
    cleanup_dir = Path(TOOL_ROOT) / "research" / f"boot{boot_epoch}-private"
    resume_output = output_parent / (
        f"test123-tools-boot{boot_epoch}{RESUME_DIRECTORY_SUFFIX}")
    return {
        "output_parent": output_parent,
        "report_dir": output_parent / f"test123-tools-boot{boot_epoch}",
        "report": output_parent / f"test123-tools-boot{boot_epoch}" / REPORT_NAME,
        "capture": output_parent / f"test123-tools-boot{boot_epoch}" / CAPTURE_NAME,
        "cleanup_dir": cleanup_dir,
        "cleanup": cleanup_dir / CLEANUP_NAME,
        "host_processes": cleanup_dir / HOST_PROCESSES_NAME,
        "marker": cleanup_dir / MARKER_NAME,
        "resume_output": resume_output,
    }


def _assert_identical_absent(path: Path, *, code: str) -> None:
    if path.exists() or path.is_symlink():
        raise PrearmResumeError(code)


def _validate_no_arm_or_go(report: dict[str, Any], capture: dict[str, Any],
                           *, expected_boot_epoch: int,
                           expected_uuid: str) -> str:
    expected_report_dir = (Path(KERNEL_METADATA).parent /
                           f"test123-tools-boot{expected_boot_epoch}")
    if (report.get("schema") != REPORT_SCHEMA or
            report.get("tool_id") != "Tool123" or
            report.get("tool_test") != "Test123" or
            report.get("running_kernel_test") != "Test122" or
            report.get("candidate") != KERNEL_CANDIDATE or
            report.get("driver_candidate") != KERNEL_CANDIDATE or
            report.get("output_directory") != str(expected_report_dir) or
            report.get("status") != "MONITOR_READY_MALFORMED" or
            report.get("complete") is not False or
            report.get("partial") is not True or
            report.get("boot_epoch") != expected_boot_epoch or
            report.get("expected_loaded_uuid") != expected_uuid or
            report.get("boot_claim_consumed") is not False or
            report.get("claim_outcome") != "aborted_before_arm_no_claim" or
            report.get("retry_allowed") is not False or
            report.get("rf_transmission_proven") is not False):
        raise PrearmResumeError("prior_report_not_exact_prearm_abort")

    token = report.get("run_token")
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise PrearmResumeError("prior_run_token_invalid")
    native_ready = report.get("native_ready")
    aborted = report.get("native_aborted")
    if (not isinstance(native_ready, dict) or
            native_ready.get("boot_epoch") != expected_boot_epoch or
            native_ready.get("candidate") != KERNEL_CANDIDATE or
            native_ready.get("expected_loaded_uuid") != expected_uuid or
            native_ready.get("claim_available") is not True or
            native_ready.get("one_arm_maximum") is not True or
            not isinstance(aborted, dict) or
            aborted.get("event") != "NATIVE_ABORTED" or
            aborted.get("claim_consumed") is not False or
            aborted.get("helper_invoked") is not False or
            aborted.get("retry_allowed") is not False):
        raise PrearmResumeError("prior_native_abort_not_verified")

    prohibited_result_fields = (
        "native_arm_failed", "native_armed_ack", "native_arm_result",
        "native_result", "sender_result", "sender_cleanup", "monitor_ready",
        "sender_ready", "listener_ready", "listener_result",
    )
    if any(report.get(key) is not None for key in prohibited_result_fields):
        raise PrearmResumeError("prior_run_has_arm_or_sender_terminal")
    sender = report.get("test088_sender")
    if not isinstance(sender, dict):
        raise PrearmResumeError("prior_sender_capture_missing")
    raw_records = sender.get("raw_records")
    if (not isinstance(raw_records, dict) or
            raw_records.get("first_protocol_line") is not None or
            raw_records.get("sender_started_line") is not None or
            raw_records.get("sender_result_line") is not None or
            sender.get("sender_started_event") is not None or
            sender.get("sender_result_event") is not None):
        raise PrearmResumeError("prior_sender_events_present")
    for name in ("events_parent_boot_monotonic_ns", "events_parent_monotonic_ns"):
        events = report.get(name)
        if (not isinstance(events, list) or not events or
                any(not isinstance(event, dict) or event.get("event") != "NATIVE_READY"
                    for event in events)):
            raise PrearmResumeError("prior_run_has_arm_or_go_event")

    if (capture.get("schema") != CAPTURE_SCHEMA or
            capture.get("candidate") != KERNEL_CANDIDATE or
            capture.get("status") != "coordinator_aborted_before_claim" or
            capture.get("boot_epoch") != expected_boot_epoch or
            capture.get("boot_attempt_claim_consumed") is not False or
            capture.get("native_helper_invoked") is not False or
            capture.get("configured_armed") is not False or
            capture.get("legacy_validation_copy_armed") is not False or
            capture.get("preowner_arm_accepted") is not False or
            capture.get("arm_run_token") is not None or
            capture.get("retry_allowed") is not False):
        raise PrearmResumeError("prior_native_capture_not_prearm_abort")
    identity = capture.get("identity")
    claim = capture.get("claim_preflight")
    if (not isinstance(identity, dict) or
            identity.get("loaded_uuid") != expected_uuid or
            identity.get("archive_uuid") != expected_uuid or
            identity.get("loaded_uuid_matches_receipt") is not True or
            identity.get("archive_binary_sha256_verified") is not True or
            identity.get("expected_archive_binary_sha256") !=
                report.get("expected_archive_binary_sha256") or
            not isinstance(claim, dict) or claim.get("available") is not True or
            claim.get("claim_filename") != f"boot-{expected_boot_epoch}.json" or
            claim.get("claim_scope") !=
                "shared IntelWirelessNative BootGlobal one-claim-per-boot"):
        raise PrearmResumeError("prior_native_capture_identity_mismatch")
    return token


def verify_prearm_resume(*, expected_boot_epoch: int,
                         expected_uuid: str,
                         now_epoch: float | None = None) -> dict[str, Any]:
    """Verify the saved pre-ARM failure and cleanup; do not create or mutate.

    Paths are derived only from the pinned Test122 metadata and Test123 private
    root. The caller supplies only fresh current-boot and loaded-kext identity
    values; arbitrary evidence paths are not accepted.
    """
    if not isinstance(expected_uuid, str) or not UUID_RE.fullmatch(expected_uuid):
        raise PrearmResumeError("current_loaded_uuid_invalid")
    paths = _expected_paths(expected_boot_epoch)
    owner_uid, _ = _workspace_owner()
    _check_private_directory(paths["output_parent"], owner_uid)
    _check_private_directory(paths["report_dir"], owner_uid)
    _check_private_directory(paths["cleanup_dir"], owner_uid)
    _assert_identical_absent(paths["marker"], code="prearm_resume_already_claimed")
    _assert_identical_absent(paths["resume_output"], code="prearm_resume_output_exists")

    report, report_raw = _read_private_json(paths["report"], owner_uid=owner_uid)
    capture, capture_raw = _read_private_json(paths["capture"], owner_uid=owner_uid)
    cleanup, cleanup_raw = _read_private_json(paths["cleanup"], owner_uid=owner_uid)
    host_processes, host_processes_raw = _read_private_json(
        paths["host_processes"], owner_uid=owner_uid)
    token = _validate_no_arm_or_go(
        report, capture, expected_boot_epoch=expected_boot_epoch,
        expected_uuid=expected_uuid)
    report_sha = _sha256(report_raw)
    cleanup_observations = cleanup.get("observations")
    if now_epoch is None:
        now_epoch = time.time()
    if (isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)) or
            not math.isfinite(now_epoch)):
        raise PrearmResumeError("prearm_resume_clock_invalid")

    def _fresh_observation_epoch(document: dict[str, Any], *, label: str) -> float:
        raw_at = document.get("at")
        if not isinstance(raw_at, str):
            raise PrearmResumeError(label + "_timestamp_missing")
        try:
            parsed = dt.datetime.fromisoformat(raw_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone_missing")
            observed_epoch = parsed.timestamp()
        except (OverflowError, OSError, TypeError, ValueError) as error:
            raise PrearmResumeError(label + "_timestamp_invalid") from error
        age = now_epoch - observed_epoch
        if not math.isfinite(age) or age < 0 or age > 180:
            raise PrearmResumeError(label + "_observation_stale_or_future")
        return observed_epoch

    cleanup_epoch = _fresh_observation_epoch(cleanup, label="cleanup")
    if (cleanup.get("schema", CLEANUP_SCHEMA) != CLEANUP_SCHEMA or
            cleanup.get("boot_epoch") != expected_boot_epoch or
            cleanup.get("source_report_sha256") != report_sha or
            cleanup.get("monitor_absent") is not True or
            cleanup.get("exact_temporary_directory_absent") is not True or
            cleanup.get("ap_identity_and_channel_unchanged") is not True or
            cleanup.get("diagnostic_process_absent") is not True or
            cleanup.get("kernel_arm_not_invoked") is not True or
            not isinstance(cleanup_observations, dict)):
        raise PrearmResumeError("post_abort_cleanup_not_bound_or_incomplete")
    for key in ("interfaces", "ap", "processes", "temporary_absent"):
        item = cleanup_observations.get(key)
        if not isinstance(item, dict) or item.get("exit_code") != 0:
            raise PrearmResumeError("post_abort_cleanup_observation_incomplete")
    interfaces_text = cleanup_observations["interfaces"].get("stdout")
    process_text = cleanup_observations["processes"].get("stdout")
    if (not isinstance(interfaces_text, str) or "iwn102mon" in interfaces_text or
            not isinstance(process_text, str) or
            any(name in process_text for name in (
                "coordinate_test123_rx149.py", "native_controlled_capture_test123.py",
                "awdl_router_rx_lease_sender_test123", "awdl0_unicast_listener_test123"))):
        raise PrearmResumeError("post_abort_resources_still_visible")
    running_token = report.get("run_token")
    process_artifact_names = (
        "coordinate_test123_rx149.py", "native_controlled_capture_test123.py",
        "awdl_router_rx_lease_sender_test123", "awdl0_unicast_listener_test123",
        "remote_sender_test123.py", "router_status_tail_test122",
        "router_status_tail_test123", "awdl_router_status_tail_test122",
        "awdl_router_status_tail_test123",
    )
    if running_token in process_text or any(
            name in process_text for name in process_artifact_names):
        raise PrearmResumeError("post_abort_diagnostic_process_still_visible")
    if cleanup_observations["temporary_absent"].get("stdout") != "":
        raise PrearmResumeError("post_abort_temporary_directory_not_absent")

    host_processes_epoch = _fresh_observation_epoch(
        host_processes, label="host_processes")
    if (host_processes.get("boot_epoch") != expected_boot_epoch or
            host_processes.get("source_report_sha256") != report_sha or
            host_processes.get("matching_processes") != []):
        raise PrearmResumeError("post_abort_host_processes_not_bound_or_empty")

    return {
        "schema": "test123-prearm-resume-verification/v1",
        "eligible": True,
        "same_boot": True,
        "expected_boot_epoch": expected_boot_epoch,
        "expected_uuid": expected_uuid,
        "kernel_candidate": KERNEL_CANDIDATE,
        "prior_status": report["status"],
        "prior_native_claim_consumed": False,
        "prior_go_attempted": False,
        "prior_run_token_sha256": _sha256(token.encode("ascii")),
        "report_path": str(paths["report"]),
        "report_sha256": report_sha,
        "capture_path": str(paths["capture"]),
        "capture_sha256": _sha256(capture_raw),
        "cleanup_observation_path": str(paths["cleanup"]),
        "cleanup_observation_sha256": _sha256(cleanup_raw),
        "cleanup_observation_epoch": cleanup_epoch,
        "host_processes_path": str(paths["host_processes"]),
        "host_processes_sha256": _sha256(host_processes_raw),
        "host_processes_observation_epoch": host_processes_epoch,
        "resume_marker_path": str(paths["marker"]),
        "fresh_output_directory": str(paths["resume_output"]),
        "prior_nonce_reused": False,
        "kernel_claim_recheck_required_by_normal_preflight": True,
    }


def claim_prearm_resume(verification: dict[str, Any]) -> dict[str, Any]:
    """Atomically consume the sole same-boot resume opportunity.

    Re-reads and revalidates the canonical artifacts immediately before an
    O_EXCL marker write. The marker is intentionally persistent and never
    deleted; it does not change, reset, or pre-consume the kernel claim.
    """
    if not isinstance(verification, dict):
        raise PrearmResumeError("prearm_resume_verification_invalid")
    expected_boot_epoch = verification.get("expected_boot_epoch")
    expected_uuid = verification.get("expected_uuid")
    current = verify_prearm_resume(
        expected_boot_epoch=expected_boot_epoch, expected_uuid=expected_uuid)
    if (verification.get("schema") != current["schema"] or
            verification.get("eligible") is not True or
            verification.get("same_boot") is not True or
            verification.get("prior_native_claim_consumed") is not False or
            verification.get("prior_go_attempted") is not False or
            set(verification) != set(current) or
            any(verification.get(key) != value for key, value in current.items())):
        raise PrearmResumeError("prearm_resume_evidence_changed")

    marker = Path(current["resume_marker_path"])
    owner_uid, owner_gid = _workspace_owner()
    _check_private_directory(marker.parent, owner_uid)
    value = {
        "schema": RESUME_SCHEMA,
        "boot_epoch": current["expected_boot_epoch"],
        "expected_uuid": current["expected_uuid"],
        "kernel_candidate": current["kernel_candidate"],
        "source_report_sha256": current["report_sha256"],
        "source_capture_sha256": current["capture_sha256"],
        "cleanup_observation_sha256": current["cleanup_observation_sha256"],
        "host_processes_sha256": current["host_processes_sha256"],
        "fresh_output_directory": current["fresh_output_directory"],
        "kernel_claim_reset": False,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(marker, flags, 0o600)
    except FileExistsError as error:
        raise PrearmResumeError("prearm_resume_already_claimed") from error
    except OSError as error:
        raise PrearmResumeError("prearm_resume_marker_create_failed") from error
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
    directory_fd = os.open(marker.parent, os.O_RDONLY |
                           getattr(os, "O_DIRECTORY", 0) |
                           getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {**current, "resume_marker_created": True,
            "resume_marker_sha256": _sha256(raw)}


__all__ = ["PrearmResumeError", "verify_prearm_resume", "claim_prearm_resume"]
