#!/usr/bin/env python3
"""Test088 tools-only adapter for the shared candidate-bound native capture.

No-argument invocation prints a plan. A run requires explicit ``--run`` and
reuses the Test087-compatible native worker, metadata, helper, one-boot claim, counters,
listener, and router transport. Only the router sender protocol adapter is
revised here to preserve the new sender timing events.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import selectors
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple


TOOL_DIR = Path(__file__).resolve().parent
ROOT = TOOL_DIR.parents[1]
IWN_ROOT = ROOT.parent / "IntelWirelessNative"
NATIVE_WORKER = ROOT / "developer-tools/test087/native_controlled_capture.py"
COORDINATOR_SOURCE = ROOT / "developer-tools/test087/controlled_run_coordinator.py"
SENDER_BINARY = TOOL_DIR / "afpacket-sender/build/awdl_probe_sender-aarch64-linux-musl"
SENDER_SHA256 = "f134be242075e19f38b61ca105d89dfa148133fd3dafdf37480fcd3d7c0fd222"
MAX_LINE_BYTES = 16384
RESULT_EVENT = "SENDER_RESULT"
STARTED_EVENT = "SENDER_STARTED"
DEFAULT_AP_INTERFACE = "wlan7"
_PATCH_LOCK = threading.RLock()


def _load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST087_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST087_SOURCE_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def _load_frozen_components():
    if str(ROOT / "developer-tools/test087") not in sys.path:
        sys.path.insert(0, str(ROOT / "developer-tools/test087"))
    coordinator = _load_module(
        "test088_frozen_test087_coordinator", COORDINATOR_SOURCE)
    router = _load_module(
        "test088_frozen_test087_router",
        ROOT / "developer-tools/test087/run_controlled_probe_once.py")
    protocol = router.protocol
    timing = _load_module("test088_send_timing", TOOL_DIR / "send_timing.py")
    return coordinator, router, protocol, timing


BASE, ROUTER, PROTOCOL, TIMING = _load_frozen_components()
BASE.DEFAULT_SENDER_BINARY = SENDER_BINARY
BASE.DEFAULT_SENDER_SHA256 = SENDER_SHA256


class AdapterError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _workspace_account():
    try:
        return pwd.getpwuid(ROOT.stat().st_uid)
    except (OSError, KeyError):
        raise AdapterError("PRIVATE_ACCOUNT_UNAVAILABLE")


def _private_atomic_write(path: Path, value: Dict[str, Any], account) -> None:
    if path.exists() or path.is_symlink():
        raise AdapterError("RUN_REPORT_ALREADY_EXISTS")
    payload = json.dumps(value, ensure_ascii=False, indent=2,
                         sort_keys=True).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
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


def _read_current_boot_epoch() -> int:
    """Use the exact frozen Test087 helper for the kernel boot epoch."""
    native = _load_module("test088_frozen_test087_native_worker", NATIVE_WORKER)
    capture = native.capture_module()
    try:
        value = native._read_boot_epoch(capture)
    except Exception:
        raise AdapterError("BOOT_EPOCH_UNAVAILABLE")
    if type(value) is not int or value <= 0:
        raise AdapterError("BOOT_EPOCH_INVALID")
    return value


def _new_run_dir(boot_epoch: int, candidate: str) -> Path:
    identity = PROTOCOL.candidate_binding
    return identity.runtime_private_root(IWN_ROOT, candidate) / (
        "test088-tools-boot" + str(boot_epoch))


def _event_hint(line: str) -> Optional[str]:
    """Cheaply label the sender's canonical prefix before JSON parsing."""
    if line.startswith('{"event":"SENDER_STARTED"'):
        return STARTED_EVENT
    if line.startswith('{"event":"SENDER_RESULT"'):
        return RESULT_EVENT
    return None


def _sample_parent_clock(report: Dict[str, Any], event: str, clock: Any) -> Dict[str, Any]:
    sample = clock.sample_pair()
    process_ns = sample.get("process_monotonic_ns")
    if type(process_ns) is not int or process_ns < 0:
        process_ns = time.monotonic_ns()
    report.setdefault("events_parent_monotonic_ns", []).append({
        "event": event, "monotonic_ns": process_ns})
    report.setdefault("events_parent_boot_monotonic_ns", []).append({
        **sample, "event": event})
    return sample


def _json_record(line: str, event: str) -> Dict[str, Any]:
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise PROTOCOL.ControlledProbeError(event + "_OVERSIZE")
    try:
        value = json.loads(line)
    except (ValueError, TypeError):
        raise PROTOCOL.ControlledProbeError(event + "_MALFORMED")
    if not isinstance(value, dict) or value.get("event") != event:
        raise PROTOCOL.ControlledProbeError(event + "_MALFORMED")
    return value


class _RunCapture:
    def __init__(self, candidate: str):
        self.candidate = candidate
        self.report: Optional[Dict[str, Any]] = None
        self.parent_clock: Any = None
        self.started_raw: Optional[str] = None
        self.started_event: Optional[Dict[str, Any]] = None
        self.started_receipt: Optional[Dict[str, Any]] = None
        self.first_line_raw: Optional[str] = None
        self.first_line_truncated = False
        self.first_line_classification = "not_received"
        self.result_raw: Optional[str] = None
        self.result_event: Optional[Dict[str, Any]] = None
        self.result_receipt: Optional[Dict[str, Any]] = None
        self.native_report_path: Optional[Path] = None
        self.native_report_owner_uid: Optional[int] = None
        self.native_roc: Dict[str, Any] = {
            "status": "unknown_native_report_not_loaded",
            "clock_domain": "MachBootClock_nanoseconds_since_boot_excluding_sleep",
            "cross_clock_mapping_proven": False,
        }
        self.go_write: Dict[str, Optional[Dict[str, Any]]] = {"BEGIN": None, "END": None}
        self.legacy_result: Optional[Dict[str, Any]] = None
        self.timing: Dict[str, Any] = {
            "status": "unknown_not_received",
            "timing_instrumentation_is_non_gating_for_native_input_evidence": True,
        }

    def record_receipt(self, event: str) -> Optional[Dict[str, Any]]:
        if self.report is None or self.parent_clock is None:
            return None
        try:
            sample = _sample_parent_clock(self.report, event, self.parent_clock)
        except Exception:
            return {"status": "unknown_sample_failed",
                    "clock_domain": "MachBootClock"}
        if sample.get("status") != "available" or type(sample.get("boot_monotonic_ns")) is not int:
            return {"status": sample.get("status", "unknown"),
                    "clock_domain": sample.get("clock_domain", "MachBootClock")}
        return sample

    def timing_report(self) -> Dict[str, Any]:
        if self.result_event is None:
            return dict(self.timing)
        if not isinstance(self.legacy_result, dict):
            return {
                "status": "unknown_legacy_result_not_validated",
                "native_roc_driver_clock": dict(self.native_roc),
                "local_send_writes_prove_rf": False,
                "timing_instrumentation_is_non_gating_for_native_input_evidence": True,
            }
        try:
            parsed = TIMING.parse_sender_timing(self.result_event)
            if (self.result_event.get("frames_requested") !=
                    BASE.SENDER_PROFILE["frames_max"] or
                    parsed.get("frames_attempted") !=
                    self.legacy_result.get("frames_attempted") or
                    parsed.get("frames_completed") !=
                    self.legacy_result.get("frames_completed")):
                raise TIMING.TimingError("timing totals disagree with legacy result")
            started_valid = False
            if self.started_event is not None:
                try:
                    TIMING.parse_sender_started(self.started_event)
                    if (self.started_event.get("frames_requested") !=
                            BASE.SENDER_PROFILE["frames_max"] or
                            self.started_event.get("interval_ms") !=
                            BASE.SENDER_PROFILE["interval_ms"] or
                            self.started_event.get("send_budget_ns") !=
                            BASE.SENDER_PROFILE["hard_deadline_ms"] * 1_000_000):
                        raise TIMING.TimingError(
                            "SENDER_STARTED disagrees with frozen sender profile")
                    started_valid = True
                except TIMING.TimingError:
                    pass
            complete = parsed.get("coverage_complete") is True and parsed.get("timing_complete") is True
            status = ("failed_clock_or_schedule" if
                      parsed.get("clock_or_schedule_failure") is True else
                      "complete" if complete else "unknown_incomplete")
            result_receipt_ns = (
                [self.result_receipt.get("boot_sample_lower_ns"),
                 self.result_receipt.get("boot_sample_upper_ns")]
                if isinstance(self.result_receipt, dict) and
                type(self.result_receipt.get("boot_sample_lower_ns")) is int and
                type(self.result_receipt.get("boot_sample_upper_ns")) is int else None)
            started_receipt_ns = (
                [self.started_receipt.get("boot_sample_lower_ns"),
                 self.started_receipt.get("boot_sample_upper_ns")]
                if isinstance(self.started_receipt, dict) and
                type(self.started_receipt.get("boot_sample_lower_ns")) is int and
                type(self.started_receipt.get("boot_sample_upper_ns")) is int else None)
            go_begin, go_end = self.go_write["BEGIN"], self.go_write["END"]
            go_interval = None
            if isinstance(go_begin, dict) and isinstance(go_end, dict):
                begin_lower = go_begin.get("boot_sample_lower_ns")
                end_upper = go_end.get("boot_sample_upper_ns")
                if type(begin_lower) is int and type(end_upper) is int:
                    go_interval = (begin_lower, end_upper)
            roc_interval = None
            if self.native_roc.get("status") == "same_owner_boundary_valid":
                candidate = self.native_roc.get("roc_interval_ns")
                if (isinstance(candidate, list) and len(candidate) == 2 and
                        all(type(item) is int for item in candidate)):
                    roc_interval = (candidate[0], candidate[1])
            analysis = TIMING.correlate_with_mac_events(
                self.result_event,
                go_write_ns=go_interval,
                sender_started_event=(self.started_event if started_valid else None),
                sender_started_receipt_ns=started_receipt_ns,
                sender_result_receipt_ns=result_receipt_ns,
                roc_ns=roc_interval,
            )
            return {
                "status": status,
                "coverage_complete": parsed.get("coverage_complete") is True,
                "send_timing_complete": parsed.get("timing_complete") is True,
                "entry_count": len(parsed.get("entries", [])),
                "analysis": analysis,
                "native_roc_driver_clock": dict(self.native_roc),
                "roc_overlap_status": (
                    "mapped_same_boot_clock_interval_bounded_by_usec_quantization"
                    if roc_interval is not None else
                    "unknown_native_roc_missing_or_owner_invalid"),
                "local_send_writes_prove_rf": False,
                "timing_instrumentation_is_non_gating_for_native_input_evidence": True,
            }
        except Exception as error:
            return {
                "status": "unknown_invalid_or_missing_timing",
                "reason": type(error).__name__,
                "native_roc_driver_clock": dict(self.native_roc),
                "roc_overlap_status": (
                    "unknown_driver_clock_has_no_mapping_to_mach_or_sender_clock"
                    if self.native_roc.get("status") == "same_owner_boundary_valid" else
                    "unknown_native_roc_missing_or_owner_invalid"),
                "local_send_writes_prove_rf": False,
                "timing_instrumentation_is_non_gating_for_native_input_evidence": True,
            }

    def load_final_native_roc(self) -> Dict[str, Any]:
        if self.native_report_path is None or self.native_report_owner_uid is None:
            return dict(self.native_roc)
        try:
            value, _ = BASE._read_private_json(
                self.native_report_path, self.native_report_owner_uid,
                parent_must_be_private=True)
        except BASE.CoordinatorError as error:
            return {**self.native_roc, "status": "unknown_native_report_unavailable",
                    "reason_code": error.code}
        except Exception:
            return {**self.native_roc, "status": "unknown_native_report_unavailable",
                    "reason_code": "NATIVE_REPORT_READ_FAILED"}
        return extract_final_roc_boundary(value)

    def attach(self, report: Dict[str, Any]) -> Dict[str, Any]:
        try:
            self.native_roc = self.load_final_native_roc()
        except Exception as error:
            self.native_roc = {
                "status": "unknown_native_roc_load_failed",
                "reason": type(error).__name__,
                "cross_clock_mapping_proven": False,
            }
        report["tool_revision"] = "Test088"
        report["driver_candidate"] = self.candidate
        report["test088_sender"] = {
            "binary_sha256": SENDER_SHA256,
            "raw_records": {
                "first_protocol_line": self.first_line_raw,
                "first_protocol_line_truncated": self.first_line_truncated,
                "first_protocol_line_classification": self.first_line_classification,
                "sender_started_line": self.started_raw,
                "sender_result_line": self.result_raw,
            },
            "sender_started_event": self.started_event,
            "sender_started_parent_receipt": self.started_receipt,
            "sender_result_event": self.result_event,
            "sender_result_parent_receipt": self.result_receipt,
            "legacy_result_status": (
                self.legacy_result.get("status")
                if isinstance(self.legacy_result, dict) else None),
            "legacy_result_counters": (
                {key: self.legacy_result.get(key) for key in (
                    "frames_attempted", "frames_completed", "sent", "elapsed_ms",
                    "deadline_hit", "error_count", "last_errno", "stop_reason")}
                if isinstance(self.legacy_result, dict) else None),
            "timing": self.timing_report(),
            "timing_instrumentation_is_non_gating_for_native_input_evidence": True,
        }
        report["efi_modified"] = False
        report["retry_allowed"] = False
        return report


def extract_final_roc_boundary(native_report: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a same-owner ROC pair and conservatively map it to Mach ns.

    The driver derives its monotonic nanoseconds from XNU clock_get_uptime,
    which returns the mach_absolute_time boot clock. HostMonotonicUs floors
    that value to microseconds, so expand the nanosecond interval by at most
    999 ns at its upper boundary.
    """
    unknown = {
        "status": "unknown_native_roc_owner_pair_invalid_or_missing",
        "clock_domain": "MachBootClock_nanoseconds_since_boot_excluding_sleep",
        "cross_clock_mapping_proven": False,
    }
    if not isinstance(native_report, dict):
        return unknown
    review = native_report.get("controlled_trace_review")
    guard = review.get("guard") if isinstance(review, dict) else None
    values = guard.get("values") if isinstance(guard, dict) else None
    if not isinstance(guard, dict) or guard.get("valid") is not True or not isinstance(values, dict):
        return unknown
    fields = (
        "OwnerSerial", "OwnerSessionToken", "ContextGeneration",
        "PowerGeneration", "StationGeneration", "RocGeneration",
    )
    start_prefix = "NativeP2PRxTraceRocStart"
    end_prefix = "NativeP2PRxTraceRocEnd"
    start_owner = {field: values.get(start_prefix + field) for field in fields}
    end_owner = {field: values.get(end_prefix + field) for field in fields}
    start_us = values.get(start_prefix + "HostMonotonicUs")
    end_us = values.get(end_prefix + "HostMonotonicUs")
    start_notification = values.get(start_prefix + "NotificationSerial")
    end_notification = values.get(end_prefix + "NotificationSerial")
    identity_valid = (
        start_owner == end_owner and
        all(type(value) is int and value > 0 for value in start_owner.values()))
    boundary_valid = all((
        values.get(start_prefix + "Present") == 1,
        values.get(end_prefix + "Present") == 1,
        values.get(start_prefix + "HostMonotonicPresent") == 1,
        values.get(end_prefix + "HostMonotonicPresent") == 1,
        values.get(start_prefix + "RawStartFlag") == 1,
        values.get(end_prefix + "RawStartFlag") == 0,
        values.get(start_prefix + "CanonicalTransitionPresent") == 1,
        values.get(end_prefix + "CanonicalTransitionPresent") == 1,
        values.get(start_prefix + "CanonicalTransition") == 1,
        values.get(end_prefix + "CanonicalTransition") == 1,
        type(start_us) is int and start_us > 0,
        type(end_us) is int and end_us > start_us,
        type(start_notification) is int and start_notification > 0,
        type(end_notification) is int and end_notification > start_notification,
    ))
    if not identity_valid or not boundary_valid:
        return unknown
    start_ns_lower = start_us * 1000
    end_ns_upper = end_us * 1000 + 999
    return {
        "status": "same_owner_boundary_valid",
        "clock_domain": "MachBootClock_nanoseconds_since_boot_excluding_sleep",
        "start_us": start_us,
        "end_us": end_us,
        "duration_us": end_us - start_us,
        "roc_interval_ns": [start_ns_lower, end_ns_upper],
        "conversion_max_quantization_error_ns": 999,
        "owner": start_owner,
        "start_notification_serial": start_notification,
        "end_notification_serial": end_notification,
        "cross_clock_mapping_proven": True,
        "mapping_note": (
            "clock_get_uptime returns mach_absolute_time; XNU converts that "
            "boot-clock value to nanoseconds. HostMonotonicUs floors the "
            "driver value to microseconds, so the mapped ROC upper bound is "
            "expanded by 999 ns. This is same-clock mapping, not RF proof."),
    }


class Test088SenderSession:
    """Read Test088 events, then hand only the legacy result to Test087 logic."""

    def __init__(self, session: Any, capture: _RunCapture):
        self.session = session
        self.capture = capture

    def __getattr__(self, name: str):
        return getattr(self.session, name)

    def abort(self):
        # Before GO the sender still speaks the exact Test087 ABORT contract.
        return self.session.abort()

    def go_once(self, *, on_control_write=None):
        session = self.session
        if session.closed or session.control_consumed:
            raise PROTOCOL.ControlledProbeError("SENDER_CONTROL_ALREADY_CONSUMED")
        session.control_consumed = True
        try:
            assert session.process.stdin is not None
            if on_control_write is not None:
                on_control_write("BEGIN")
            session.process.stdin.write(("GO " + session.run_token + "\n").encode("ascii"))
            session.process.stdin.flush()
            if on_control_write is not None:
                on_control_write("END")

            first_line = ROUTER._read_protocol_line(
                session.selector, session.process, session.read_state, session.deadline)
            if first_line is None:
                raise PROTOCOL.ControlledProbeError("SENDER_RESULT_MISSING")
            (self.capture.first_line_raw,
             self.capture.first_line_truncated) = _bounded_raw_line(first_line)
            self.capture.first_line_classification = "unclassified"
            # Take the Mach receipt sample before decoding the sender event.
            # The current sender emits canonical compact JSON, so a bounded
            # prefix gives the event label without parsing or waiting again.
            first_hint = _event_hint(first_line)
            if first_hint is not None:
                self.capture.first_line_classification = first_hint.lower()
            first_receipt = self.capture.record_receipt(
                "ROUTER_SENDER_STARTED_RECEIVED" if first_hint == STARTED_EVENT else
                "ROUTER_SENDER_RESULT_RECEIVED" if first_hint == RESULT_EVENT else
                "ROUTER_SENDER_EVENT_RECEIVED")
            if first_line.startswith("{"):
                try:
                    first_event = _json_record(first_line, _event_name(first_line))
                except PROTOCOL.ControlledProbeError:
                    if first_hint is None:
                        self.capture.first_line_classification = "malformed_or_unexpected_json_event"
                        raise
                    self.capture.first_line_classification = "malformed_known_event_json"
                    first_event = None
            else:
                self.capture.first_line_classification = "non_json_or_unknown_line"
                first_event = None

            if ((isinstance(first_event, dict) and first_event.get("event") == STARTED_EVENT) or
                    first_hint == STARTED_EVENT):
                self.capture.started_raw = first_line
                self.capture.started_event = first_event
                self.capture.started_receipt = first_receipt
                if isinstance(first_event, dict):
                    self.capture.first_line_classification = STARTED_EVENT.lower()
                result_line = ROUTER._read_protocol_line(
                    session.selector, session.process, session.read_state, session.deadline)
                if result_line is not None:
                    self.capture.result_receipt = self.capture.record_receipt(
                        "ROUTER_SENDER_RESULT_RECEIVED")
            else:
                result_line = first_line
                self.capture.result_receipt = first_receipt
                if first_hint == RESULT_EVENT and isinstance(first_event, dict):
                    self.capture.first_line_classification = RESULT_EVENT.lower()

            if result_line is None:
                raise PROTOCOL.ControlledProbeError("SENDER_RESULT_MISSING")
            self.capture.result_raw = result_line
            raw_result = _json_record(result_line, RESULT_EVENT)
            self.capture.result_event = raw_result

            allowed = PROTOCOL.SENDER_RESULT_ALLOWED_KEYS
            if not allowed.issubset(raw_result):
                raise PROTOCOL.ControlledProbeError("SENDER_RESULT_LEGACY_FIELDS_MISSING")
            clock_reason_map = {
                "monotonic_clock_before_failed": "monotonic_clock_unavailable",
                "monotonic_clock_after_failed": "monotonic_clock_unavailable",
                "monotonic_clock_end_failed": "monotonic_clock_end_failed",
                "schedule_sleep_error": "schedule_or_sleep_failed",
            }
            stop_reason = raw_result.get("stop_reason")
            if stop_reason in clock_reason_map:
                if (raw_result.get("status") != "failed" or
                        raw_result.get("deadline_hit") is not False or
                        type(raw_result.get("last_errno")) is not int or
                        raw_result.get("last_errno", 0) <= 0):
                    raise PROTOCOL.ControlledProbeError(
                        "SENDER_CLOCK_FAILURE_RESULT_INVALID")
                if stop_reason == "monotonic_clock_before_failed":
                    requested = raw_result.get("frames_requested")
                    attempted = raw_result.get("frames_attempted")
                    rows = raw_result.get("send_timing")
                    if (type(requested) is not int or
                            requested != BASE.SENDER_PROFILE["frames_max"] or
                            type(attempted) is not int or
                            not 0 <= attempted < requested or
                            not isinstance(rows, list) or len(rows) != attempted):
                        raise PROTOCOL.ControlledProbeError(
                            "SENDER_CLOCK_BEFORE_FAILURE_PREFIX_INVALID")
                if stop_reason == "monotonic_clock_after_failed" and (
                        not isinstance(raw_result.get("send_timing"), list) or
                        not raw_result["send_timing"] or
                        raw_result["send_timing"][-1].get("after_ns") is not None):
                    raise PROTOCOL.ControlledProbeError(
                        "SENDER_CLOCK_AFTER_FAILURE_ROW_INVALID")
                if stop_reason == "monotonic_clock_end_failed" and (
                        raw_result.get("finished_ns") is not None or
                        raw_result.get("elapsed_ms") is not None):
                    raise PROTOCOL.ControlledProbeError(
                        "SENDER_CLOCK_END_FAILURE_DURATION_MUST_BE_UNKNOWN")
            legacy_line = json.dumps(
                {key: (clock_reason_map.get(raw_result.get("stop_reason"),
                                            raw_result.get("stop_reason"))
                       if key == "stop_reason" else
                       0 if (key == "elapsed_ms" and
                             stop_reason == "monotonic_clock_end_failed") else
                       raw_result[key]) for key in allowed},
                sort_keys=True, separators=(",", ":"))
            legacy_result = PROTOCOL.parse_sender_result(legacy_line)
            # The temporary 0 above exists only to satisfy Test087's strict
            # legacy integer parser. It is never retained as a measurement.
            if stop_reason == "monotonic_clock_end_failed":
                legacy_result["elapsed_ms"] = None
            legacy_result["stop_reason"] = stop_reason
            self.capture.legacy_result = legacy_result
            session.protocol_evidence["sender_result"] = legacy_result
            session.protocol_evidence["test088_raw_sender_result"] = raw_result

            cleanup_line = ROUTER._read_protocol_line(
                session.selector, session.process, session.read_state, session.deadline)
            if cleanup_line is None:
                raise PROTOCOL.ControlledProbeError("REMOTE_CLEANUP_MISSING")
            cleanup = PROTOCOL.parse_cleanup(cleanup_line, run_token=session.run_token)
            session.protocol_evidence["cleanup"] = cleanup
            if not all(cleanup[key] for key in (
                    "monitor_removed", "ap_unchanged", "temporary_files_removed")):
                raise PROTOCOL.ControlledProbeError("REMOTE_CLEANUP_NOT_VERIFIED")

            remaining = max(0.0, session.deadline - time.monotonic())
            try:
                exit_code = session.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise PROTOCOL.ControlledProbeError("SSH_EXIT_TIMEOUT")
            session.closed = True
            session.protocol_evidence["ssh_exit_code"] = exit_code
            if legacy_result["status"] not in {"complete", "failed"}:
                raise PROTOCOL.ControlledProbeError(
                    "SENDER_GO_RESULT_STATUS_INVALID")
            if legacy_result["status"] == "complete" and exit_code != 0:
                raise PROTOCOL.ControlledProbeError("SENDER_EXIT_STATUS_MISMATCH")
            if legacy_result["status"] == "failed" and exit_code == 0:
                raise PROTOCOL.ControlledProbeError("SENDER_EXIT_STATUS_MISMATCH")
            return {
                "sender_result": legacy_result,
                "cleanup": cleanup,
                "remote_exit_code": exit_code,
                "local_send_is_not_rf_proof": True,
            }
        except Exception:
            ROUTER._terminate_process(session.process)
            raise
        finally:
            session.selector.close()
            session.closed = True
            for stream in (session.process.stdin, session.process.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


def _event_name(line: str) -> str:
    """Extract only a bounded event name so malformed timing remains non-gating."""
    try:
        value = json.loads(line)
    except (ValueError, TypeError):
        raise PROTOCOL.ControlledProbeError("SENDER_EVENT_MALFORMED")
    event = value.get("event") if isinstance(value, dict) else None
    if event not in {STARTED_EVENT, RESULT_EVENT}:
        raise PROTOCOL.ControlledProbeError("SENDER_EVENT_UNEXPECTED")
    return event


def _bounded_raw_line(line: str) -> Tuple[str, bool]:
    raw = line.encode("utf-8", errors="replace")
    if len(raw) <= MAX_LINE_BYTES:
        return line, False
    return raw[:MAX_LINE_BYTES].decode("utf-8", errors="replace"), True


def _router_facade(capture: _RunCapture):
    class SenderFactory:
        @staticmethod
        def start(**kwargs):
            session, monitor_ready, sender_ready = ROUTER.RouterSenderSession.start(**kwargs)
            return Test088SenderSession(session, capture), monitor_ready, sender_ready

    values = {name: value for name, value in vars(ROUTER).items()
              if not name.startswith("__")}
    values["RouterSenderSession"] = SenderFactory
    return SimpleNamespace(**values)


def _decorate_run(capture: _RunCapture, *, expected_epoch: int,
                  candidate: str, expected_uuid: str,
                  expected_archive_binary_sha256: str,
                  minimum_boot_epoch_exclusive: int, profile: str):
    original_modules = BASE._modules
    original_append = BASE._append_parent_clock_event
    original_parse_ready = BASE._parse_native_ready

    def injected_modules():
        return PROTOCOL, _router_facade(capture)

    def append_parent_clock_event(report, event, clock):
        capture.report = report
        capture.parent_clock = clock
        original_append(report, event, clock)
        if event in {"ROUTER_GO_WRITE_BEGIN", "ROUTER_GO_WRITE_END"}:
            sample = dict(report["events_parent_boot_monotonic_ns"][-1])
            phase = "BEGIN" if event.endswith("BEGIN") else "END"
            capture.go_write[phase] = sample

    def parse_native_ready(line, *, candidate: str, expected_uuid: str,
                           expected_archive_binary_sha256: str,
                           minimum_boot_epoch_exclusive: int, profile: str):
        if (candidate != bound_candidate or expected_uuid != bound_uuid or
                expected_archive_binary_sha256 != bound_archive_binary_sha256 or
                minimum_boot_epoch_exclusive != bound_minimum_boot_epoch_exclusive or
                profile != bound_profile):
            raise BASE.CoordinatorError("NATIVE_READY_EXPECTATION_CHANGED")
        value = original_parse_ready(
            line, candidate=candidate, expected_uuid=expected_uuid,
            expected_archive_binary_sha256=expected_archive_binary_sha256,
            minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive,
            profile=profile)
        if value.get("boot_epoch") != expected_epoch:
            raise BASE.CoordinatorError("BOOT_EPOCH_CHANGED_OR_MISMATCH")
        if value.get("boot_epoch", 0) <= minimum_boot_epoch_exclusive:
            raise BASE.CoordinatorError("BOOT_EPOCH_TOO_OLD")
        return value

    bound_candidate = candidate
    bound_uuid = expected_uuid
    bound_archive_binary_sha256 = expected_archive_binary_sha256
    bound_minimum_boot_epoch_exclusive = minimum_boot_epoch_exclusive
    bound_profile = profile

    BASE._modules = injected_modules
    BASE._append_parent_clock_event = append_parent_clock_event
    BASE._parse_native_ready = parse_native_ready
    return original_modules, original_append, original_parse_ready


def _restore_run(originals) -> None:
    BASE._modules, BASE._append_parent_clock_event, BASE._parse_native_ready = originals


def run_test088_once(*, host: str, control_path: str,
                     metadata_path: Path = BASE.DEFAULT_METADATA,
                     ap: Optional[str] = None,
                     boot_epoch: Optional[int] = None) -> Dict[str, Any]:
    """Run one Test087 driver capture with the Test088 sender adapter."""
    if not isinstance(ap, str) or not ap:
        raise AdapterError("AP_INTERFACE_REQUIRED")
    try:
        PROTOCOL.validate_ap_interface(ap)
    except PROTOCOL.ControlledProbeError as error:
        raise AdapterError(error.code)
    if boot_epoch is None:
        boot_epoch = _read_current_boot_epoch()
    if type(boot_epoch) is not int or boot_epoch <= 0:
        raise AdapterError("BOOT_EPOCH_INVALID")
    account = _workspace_account()
    try:
        metadata, _, _, _ = BASE._validate_bundle(
            Path(metadata_path), account.pw_uid, PROTOCOL)
    except BASE.CoordinatorError as error:
        raise AdapterError(error.code)
    candidate = metadata["candidate"]
    minimum_boot_epoch_exclusive = metadata["minimum_boot_epoch_exclusive"]
    if boot_epoch <= minimum_boot_epoch_exclusive:
        raise AdapterError("BOOT_EPOCH_TOO_OLD")
    output_dir = _new_run_dir(boot_epoch, candidate)
    capture = _RunCapture(candidate)
    capture.native_report_path = output_dir / "native-controlled-capture-private.json"
    capture.native_report_owner_uid = _workspace_account().pw_uid
    with _PATCH_LOCK:
        originals = _decorate_run(
            capture, expected_epoch=boot_epoch, candidate=candidate,
            expected_uuid=metadata["expected_loaded_uuid"],
            expected_archive_binary_sha256=metadata["source_binding"][
                "expected_binary_sha256"],
            minimum_boot_epoch_exclusive=minimum_boot_epoch_exclusive,
            profile=metadata["profile"])
        try:
            report = BASE.run_controlled_once(
                host=host,
                control_path=control_path,
                metadata_path=Path(metadata_path),
                sender_binary=SENDER_BINARY,
                sender_sha256=SENDER_SHA256,
                output_dir=output_dir,
                ap=ap,
            )
        except BASE.CoordinatorError as error:
            if error.partial_report is not None:
                capture.attach(error.partial_report)
                error.partial_report["output_directory"] = str(output_dir)
            raise
        finally:
            _restore_run(originals)
    report["boot_epoch"] = report.get("boot_epoch") or boot_epoch
    report["output_directory"] = str(output_dir)
    return capture.attach(report)


def plan(metadata_path: Path = BASE.DEFAULT_METADATA) -> Dict[str, Any]:
    candidate = None
    expected_uuid = None
    profile = None
    minimum_boot_epoch = None
    try:
        metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
        if isinstance(metadata, dict):
            candidate = metadata.get("candidate")
            expected_uuid = metadata.get("expected_loaded_uuid")
            profile = metadata.get("profile")
            minimum_boot_epoch = metadata.get("minimum_boot_epoch_exclusive")
    except (OSError, ValueError, TypeError):
        pass
    identity = PROTOCOL.candidate_binding
    private_root = (identity.runtime_private_root(IWN_ROOT, candidate)
                    if identity.valid_candidate(candidate) else None)
    return {
        "mode": "plan",
        "tool_revision": "Test088",
        "driver_candidate": candidate,
        "expected_loaded_uuid": expected_uuid,
        "expected_profile": profile,
        "native_worker_source": str(NATIVE_WORKER),
        "metadata_source": str(metadata_path),
        "sender_binary": str(SENDER_BINARY),
        "sender_sha256": SENDER_SHA256,
        "run_directory_pattern": (str(private_root / "test088-tools-boot<epoch>")
                                   if private_root else None),
        "minimum_boot_epoch_exclusive": minimum_boot_epoch,
        "ap_interface_must_be_explicit_for_run": True,
        "ap_interface_profile": DEFAULT_AP_INTERFACE,
        "requires_explicit_run_flag": True,
        "default_action": "none",
        "efi_modified": False,
        "retry_allowed": False,
        "sender_timing_is_non_gating_for_native_input_evidence": True,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="Run one candidate-bound native capture using Test088 tools")
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--metadata", type=Path, default=BASE.DEFAULT_METADATA)
    parser.add_argument("--ap", help="explicit live AP interface (next-run profile: wlan7)")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps(plan(args.metadata), sort_keys=True))
        return 0
    if not args.host or not args.control_path:
        print("ERROR: ROUTER_TRANSPORT_REQUIRED", file=sys.stderr)
        return 2
    if not args.ap:
        print("ERROR: AP_INTERFACE_REQUIRED (use --ap wlan7 for the prepared profile)",
              file=sys.stderr)
        return 2
    account = _workspace_account()
    output_dir: Optional[Path] = None
    candidate: Optional[str] = None
    try:
        PROTOCOL.validate_ap_interface(args.ap)
        boot_epoch = _read_current_boot_epoch()
        metadata, _, _, _ = BASE._validate_bundle(
            args.metadata, account.pw_uid, PROTOCOL)
        candidate = metadata["candidate"]
        minimum_boot_epoch = metadata["minimum_boot_epoch_exclusive"]
        if boot_epoch <= minimum_boot_epoch:
            raise AdapterError("BOOT_EPOCH_TOO_OLD")
        output_dir = _new_run_dir(boot_epoch, candidate)
        report = run_test088_once(
            host=args.host, control_path=args.control_path,
            metadata_path=args.metadata, ap=args.ap, boot_epoch=boot_epoch)
        report["schema"] = "test088-tools-controlled-run-private/v1"
        report["output_directory"] = str(output_dir)
        _private_atomic_write(output_dir / "test088-tools-private.json", report, account)
        print("TEST088_TOOLS_RUN_COMPLETE")
        return 0 if report.get("complete") is True else 2
    except AdapterError as error:
        failure = {
            "schema": "test088-tools-controlled-run-private/v1",
            "tool_revision": "Test088",
            "driver_candidate": candidate,
            "error_code": error.code,
            "efi_modified": False,
            "retry_allowed": False,
            "complete": False,
            "partial": True,
        }
        if output_dir is not None and output_dir.is_dir():
            try:
                _private_atomic_write(output_dir / "test088-tools-private.json", failure, account)
            except Exception:
                pass
        print("ERROR: " + error.code, file=sys.stderr)
        return 2
    except BASE.CoordinatorError as error:
        failure = error.partial_report or {}
        failure.update({
            "schema": "test088-tools-controlled-run-private/v1",
            "tool_revision": "Test088",
            "driver_candidate": candidate,
            "error_code": error.code,
            "error_evidence": error.evidence,
            "efi_modified": False,
            "retry_allowed": False,
            "complete": False,
            "partial": True,
        })
        if output_dir is not None and output_dir.is_dir():
            try:
                _private_atomic_write(output_dir / "test088-tools-private.json", failure, account)
            except Exception:
                pass
        print("ERROR: " + error.code, file=sys.stderr)
        return 2
    except PROTOCOL.ControlledProbeError as error:
        failure = {
            "schema": "test088-tools-controlled-run-private/v1",
            "tool_revision": "Test088",
            "driver_candidate": candidate,
            "error_code": error.code,
            "error_evidence": error.evidence,
            "efi_modified": False,
            "retry_allowed": False,
            "complete": False,
            "partial": True,
        }
        if output_dir is not None and output_dir.is_dir():
            try:
                _private_atomic_write(output_dir / "test088-tools-private.json", failure, account)
            except Exception:
                pass
        print("ERROR: " + error.code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
