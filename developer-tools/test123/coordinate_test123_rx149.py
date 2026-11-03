#!/usr/bin/env python3
"""Run Test123 tools against the unchanged Test122 RX149 kernel candidate.

The default command is an inert plan. An explicit ``--run`` reuses the
Test122 one-use START/GO path while binding a fresh v2 packet set and the
Test123 router sender and awdl0 listener. This module never modifies EFI or
router configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST122_DIR = REPO_ROOT / "developer-tools/test122"
TEST122_COORDINATOR_PATH = TEST122_DIR / "coordinate_test122_rx149.py"
NATIVE_WORKER = TOOL_DIR / "native_controlled_capture_test123.py"
SENDER_SOURCE = TOOL_DIR / "router-status/awdl_router_rx_lease_sender_test123.c"
SENDER_PROTOCOL_SOURCE = TOOL_DIR / "router-status/dual_sender_protocol_test123.py"
LISTENER_SOURCE = TOOL_DIR / "awdl0_unicast_listener_test123.c"
LISTENER_PROTOCOL_SOURCE = TOOL_DIR / "listener_protocol_test123.py"
SENDER_RECEIPT = (Path.home() / "Library/Application Support/IntelWirelessNative/"
                  "RuntimeTest123/research/preparation-private/sender-build-private.json")
LISTENER_RECEIPT = (Path.home() / "Library/Application Support/IntelWirelessNative/"
                    "RuntimeTest123/research/preparation-private/listener-build-private.json")


def _load(name: str, path: Path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST123_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST123_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(spec.name) is module:
            del sys.modules[spec.name]
        raise
    return module


KERNEL_COORDINATOR = _load(
    "test123_frozen_test122_coordinator", TEST122_COORDINATOR_PATH)
T120 = KERNEL_COORDINATOR.T120
T121 = KERNEL_COORDINATOR.T121
RUNNER = KERNEL_COORDINATOR.RUNNER
BINDING = _load("tool123_runtime_binding", TOOL_DIR / "rx149_binding_test123.py")
# The repo/runtime root is pinned by Test122, not by the effective user's HOME.
# This keeps root-launched runs bound to the same geek-owned receipt files.
SENDER_RECEIPT = (BINDING.TOOL_ROOT / "research/preparation-private/"
                  "sender-build-private.json")
LISTENER_RECEIPT = (BINDING.TOOL_ROOT / "research/preparation-private/"
                    "listener-build-private.json")
SENDER_PROTOCOL = _load(
    "tool123_sender_protocol", TOOL_DIR / "router-status/dual_sender_protocol_test123.py")
LISTENER_PROTOCOL = _load(
    "tool123_listener_protocol", TOOL_DIR / "listener_protocol_test123.py")
REMOTE_SENDER = _load(
    "tool123_remote_sender", TOOL_DIR / "remote_sender_test123.py")
ARTIFACTS_PATH = TOOL_DIR / "tool_artifacts_test123.py"
_ARTIFACTS = None

_ORIGINAL_TEST104_CONFIGURE = RUNNER.configure_test104_profile


def plan() -> dict[str, Any]:
    return {
        "tool_id": "Tool123",
        "tool_test": "Test123",
        "running_kernel_test": "Test122",
        "candidate": BINDING.KERNEL_CANDIDATE,
        "kernel_metadata": str(BINDING.KERNEL_METADATA),
        "profile": BINDING.KERNEL.PROFILE,
        "receiver_channel": 149,
        "driver_lease_ms": 100,
        "router_sender": {
            "schema": SENDER_PROTOCOL.SCHEMA,
            "frames": 4,
            "interval_ms": 10,
            "send_budget_ms": 40,
            "passive_status_tail_ms": 2000,
            "does_not_extend_driver_lease": True,
        },
        "listener": {
            "schema": LISTENER_PROTOCOL.SCHEMA,
            "interface": "awdl0",
            "wire_nonce_bytes": LISTENER_PROTOCOL.PAYLOAD_LENGTH,
            "distinct_frame_ordinals_proven": False,
        },
        "start_snapshot": {
            "same_run_token_checked": True,
            "same_owner_current_lease_atomicity_proven": False,
            "unavailable_live_owner_or_ifnet_state": "unknown",
        },
        "default_action": "plan_only",
        "armed": False,
        "boot_claim_consumed": False,
        "router_contacted": False,
        "rf_triggered": False,
        "wifi_smoke_test": "user_skipped",
        "sleep_test": "user_skipped",
        "efi_modified": False,
        "wan_lan_modified": False,
        "peer_receipt_proven": False,
        "native_awdl_reply_proven": False,
        "airdrop_proven": False,
    }


def _artifact_validator():
    global _ARTIFACTS
    if _ARTIFACTS is None:
        _ARTIFACTS = _load("tool123_artifact_validator", ARTIFACTS_PATH)
    return _ARTIFACTS


def _validated_tool_artifacts() -> tuple[dict, dict]:
    validator = _artifact_validator()
    sender = validator.validate_build_receipt(
        SENDER_RECEIPT, kind="sender", repo_root=REPO_ROOT,
        private_root=BINDING.TOOL_ROOT)
    listener = validator.validate_build_receipt(
        LISTENER_RECEIPT, kind="listener", repo_root=REPO_ROOT,
        private_root=BINDING.TOOL_ROOT)
    return sender, listener


def _artifact_binary(receipt: dict, *, label: str) -> Path:
    value = receipt.get("binary_path")
    if not isinstance(value, str) or not value:
        raise RUNNER.ControlledRunError("TEST123_" + label + "_BINARY_PATH_MISSING")
    path = Path(value)
    if not path.is_absolute():
        path = BINDING.IWN_ROOT / path
    if path.is_symlink() or not path.is_file():
        raise RUNNER.ControlledRunError("TEST123_" + label + "_BINARY_UNAVAILABLE")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != receipt.get("binary_sha256"):
        raise RUNNER.ControlledRunError("TEST123_" + label + "_BINARY_HASH_MISMATCH")
    return path.resolve(strict=True)


def _private_hash_key(path: Path) -> str:
    resolved = Path(path).resolve(strict=True)
    try:
        return resolved.relative_to(REPO_ROOT.resolve(strict=True)).as_posix()
    except ValueError:
        try:
            return "private:" + resolved.relative_to(BINDING.IWN_ROOT.resolve(strict=True)).as_posix()
        except ValueError as error:
            raise RUNNER.ControlledRunError("TEST123_RUNTIME_TOOL_OUTSIDE_BOUND_ROOT") from error


def _configure_test123_profile():
    """Install the T123 protocols after T104 installs its reviewed START gate."""
    restore_test104 = _ORIGINAL_TEST104_CONFIGURE()
    base = RUNNER.BASE
    protocol = RUNNER.PROTOCOL
    timing = RUNNER.TEST088.TIMING
    saved = {
        "listener_protocol": RUNNER.LISTENER_PROTOCOL,
        "listener_source": RUNNER.LISTENER_SOURCE,
        "listener_protocol_source": RUNNER.LISTENER_PROTOCOL_SOURCE,
        "sender_protocol": RUNNER.SENDER_PROTOCOL,
        "provenance": RUNNER.PROVENANCE,
        "remote_sender": RUNNER.REMOTE_SENDER,
        "protocol_ready": protocol.parse_sender_ready,
        "protocol_result": protocol.parse_sender_result,
        "protocol_listener_ready": protocol.parse_listener_ready,
        "protocol_listener_result": protocol.parse_listener_result,
        "remote_builder": protocol.build_remote_monitor_sender_script,
        "timing_parse": timing.parse_sender_timing,
        "timing_started": timing.parse_sender_started,
        "managed_pipe": base.ManagedPipe,
        "compile_listener": base._compile_listener,
        "sender_start_descriptor": RUNNER.ROUTER.RouterSenderSession.__dict__["start"],
        "sender_start": RUNNER.ROUTER.RouterSenderSession.start,
        "sender_go_once": RUNNER.TEST088.Test088SenderSession.go_once,
        "capture_attach": RUNNER.TEST088._RunCapture.attach,
        "provenance_classifier": SENDER_PROTOCOL.classify_sender_result,
        "atomic_private_write": RUNNER.atomic_private_write,
    }

    token_state = {"run_token": None}

    RUNNER.LISTENER_PROTOCOL = LISTENER_PROTOCOL
    RUNNER.LISTENER_SOURCE = LISTENER_SOURCE
    RUNNER.LISTENER_PROTOCOL_SOURCE = LISTENER_PROTOCOL_SOURCE
    RUNNER.SENDER_PROTOCOL = SENDER_PROTOCOL
    RUNNER.PROVENANCE = SENDER_PROTOCOL
    RUNNER.REMOTE_SENDER = REMOTE_SENDER

    # T088SenderSession first validates the full event's legacy counters and
    # then deliberately calls parse_sender_result() with a reduced legacy
    # projection. Keep that frozen seam; T104's later provenance step validates
    # the original raw event against this run's nonce, token and packet set.
    protocol.parse_sender_result = saved["protocol_result"]

    def parse_sender_ready(line: str):
        try:
            return SENDER_PROTOCOL.parse_ready(
                line, expected_wire_nonce_hex=_active_nonce())
        except SENDER_PROTOCOL.SenderProtocolError as error:
            raise protocol.ControlledProbeError(
                "TEST123_SENDER_READY_INVALID") from error

    protocol.parse_sender_ready = parse_sender_ready

    # Capture the actual random run token before the sender session parses
    # READY. Supplying it explicitly uses the existing Test087 API and avoids
    # treating a token copied from STARTED/RESULT as its own expectation.
    sender_session_class = RUNNER.ROUTER.RouterSenderSession
    original_sender_start = sender_session_class.start
    def capture_sender_start(cls, **kwargs):
        token = kwargs.get("run_token")
        if token is None:
            token = secrets.token_hex(16)
            kwargs["run_token"] = token
        if (not isinstance(token, str) or len(token) != 32 or
                any(char not in "0123456789abcdef" for char in token)):
            raise protocol.ControlledProbeError("TEST123_RUN_TOKEN_INVALID")
        if token_state["run_token"] is not None:
            raise protocol.ControlledProbeError("TEST123_DUPLICATE_SENDER_START")
        token_state["run_token"] = token
        return original_sender_start(**kwargs)
    sender_session_class.start = classmethod(capture_sender_start)

    def go_once_preserving_after_go(self, *, on_control_write=None):
        state = {"go_write_started": False, "go_write_completed": False}

        def record_control_write(phase):
            if phase == "END":
                # T088 calls END only after write+flush have returned.
                state["go_write_completed"] = True
            if on_control_write is not None:
                on_control_write(phase)
            if phase == "BEGIN":
                # BEGIN follows the pre-write callback. If that callback fails,
                # GO was not attempted and the original error must propagate.
                state["go_write_started"] = True

        try:
            return saved["sender_go_once"](
                self, on_control_write=record_control_write)
        except Exception as error:
            # Once BEGIN has completed, a partial GO write cannot safely be
            # retried. Return only already-known sender/cleanup facts so the
            # frozen T087 state machine continues its bounded native and
            # listener reads instead of skipping those terminal records.
            if not state["go_write_started"]:
                raise
            native_gate = getattr(self.capture, "report", None)
            native_gate = (native_gate.get("native_rx_go_gate")
                           if isinstance(native_gate, dict) else None)
            if (isinstance(native_gate, dict) and
                    native_gate.get("no_go_written") is True and
                    native_gate.get("go_written") is False):
                # The Test104 guard explicitly refused GO before stdin.write.
                # Let frozen T087 handle this known no-GO failure path.
                raise
            raw_code = getattr(error, "code", None)
            error_code = (raw_code if isinstance(raw_code, str) and
                          raw_code.isascii() and raw_code.replace("_", "").isalnum() and
                          1 <= len(raw_code) <= 96 else
                          "SENDER_GO_RESULT_UNAVAILABLE")
            session = self.session
            protocol_evidence = getattr(session, "protocol_evidence", {})
            if not isinstance(protocol_evidence, dict):
                protocol_evidence = {}
            sender_result = getattr(self.capture, "legacy_result", None)
            if not isinstance(sender_result, dict):
                sender_result = None
            cleanup = protocol_evidence.get("cleanup")
            if not isinstance(cleanup, dict):
                cleanup = None
            remote_exit_code = protocol_evidence.get("ssh_exit_code")
            if type(remote_exit_code) is not int:
                remote_exit_code = None
            result_raw = getattr(self.capture, "result_raw", None)
            first_raw = getattr(self.capture, "first_line_raw", None)
            if result_raw is None:
                result_line_truncated = None
                result_classification = "result_line_missing"
            elif result_raw == first_raw:
                result_line_truncated = getattr(
                    self.capture, "first_line_truncated", None)
                result_classification = getattr(
                    self.capture, "first_line_classification", "unknown")
            else:
                result_line_truncated = None
                result_classification = "result_line_recorded_but_unvalidated"
            terminal = {
                "schema": "test123-sender-terminal-error/v1",
                "status": "sender_go_terminal_incomplete",
                "error_code": error_code,
                "go_phase": ("after_go_flush" if state["go_write_completed"] else
                             "after_go_write_attempt"),
                "go_write_started": (True if state["go_write_completed"] else None),
                "go_write_may_have_been_attempted": True,
                "go_write_completed": state["go_write_completed"],
                "sender_result_known": isinstance(sender_result, dict),
                "cleanup_known": isinstance(cleanup, dict),
                "remote_exit_code_known": remote_exit_code is not None,
                "result_line_recorded": result_raw is not None,
                "first_line_truncated": getattr(
                    self.capture, "first_line_truncated", None),
                "result_line_truncated": result_line_truncated,
                "result_line_classification": result_classification,
                "retry_allowed": False,
            }
            self.capture.test123_sender_terminal_error = terminal
            protocol_evidence["test123_sender_terminal_error"] = terminal
            return {
                "sender_result": sender_result,
                "cleanup": cleanup,
                "remote_exit_code": remote_exit_code,
                "local_send_is_not_rf_proof": True,
                "test123_sender_terminal_error": terminal,
            }

    RUNNER.TEST088.Test088SenderSession.go_once = go_once_preserving_after_go

    def attach_sender_terminal_error(self, report):
        result = saved["capture_attach"](self, report)
        terminal = getattr(self, "test123_sender_terminal_error", None)
        if isinstance(terminal, dict):
            result["sender_terminal_error"] = dict(terminal)
        return result

    RUNNER.TEST088._RunCapture.attach = attach_sender_terminal_error

    def classify_sender_result(sender_result):
        expected_token = token_state.get("run_token")
        if (not isinstance(expected_token, str) or
                not isinstance(sender_result, dict) or
                sender_result.get("run_token") != expected_token):
            raise SENDER_PROTOCOL.SenderAdapterError(
                "sender_result_run_token_not_bound_to_session")
        return saved["provenance_classifier"](
            sender_result, expected_wire_nonce_hex=_active_nonce(),
            packet_set_manifest=_active_manifest())
    SENDER_PROTOCOL.classify_sender_result = classify_sender_result

    def parse_listener_ready(line: str, *, run_token: str):
        expected = RUNNER.ACTIVE_LISTENER_EXPECTATION
        if not isinstance(expected, dict):
            raise protocol.ControlledProbeError("TEST123_LISTENER_EXPECTATION_MISSING")
        try:
            ready = LISTENER_PROTOCOL.parse_ready(
                line, run_token=run_token, expected=expected)
        except LISTENER_PROTOCOL.ListenerProtocolError as error:
            raise protocol.ControlledProbeError("TEST123_LISTENER_READY_INVALID") from error
        if expected.get("ready_ns") is not None:
            raise protocol.ControlledProbeError("TEST123_LISTENER_READY_DUPLICATE")
        expected["ready_ns"] = ready["ready_ns"]
        return ready

    def parse_listener_result(line: str, *, run_token: str):
        expected = RUNNER.ACTIVE_LISTENER_EXPECTATION
        if not isinstance(expected, dict):
            raise protocol.ControlledProbeError("TEST123_LISTENER_EXPECTATION_MISSING")
        try:
            return LISTENER_PROTOCOL.parse_result(
                line, run_token=run_token, expected=expected)
        except LISTENER_PROTOCOL.ListenerProtocolError as error:
            raise protocol.ControlledProbeError("TEST123_LISTENER_RESULT_INVALID") from error

    protocol.parse_listener_ready = parse_listener_ready
    protocol.parse_listener_result = parse_listener_result

    # The old Test087 coordinator constructs the legacy argv. Intercept it
    # before Test104's MARKER-specific wrapper, then feed the strict T123 argv
    # to that wrapper (which now sees a different executable/argument shape).
    previous_managed_pipe = base.ManagedPipe
    def managed_pipe(argv):
        adapted = adapt_legacy_listener_argv(argv)
        return previous_managed_pipe(adapted)
    base.ManagedPipe = managed_pipe

    # Use the exact receipt-pinned Mach-O built for Test123. Do not compile a
    # second unreceipted listener in the controlled run directory.
    listener_binary = RUNNER.LISTENER_BINARY
    listener_sha = RUNNER.LISTENER_SHA256
    def compile_receipted_listener(_output_dir):
        if (listener_binary.is_symlink() or not listener_binary.is_file() or
                hashlib.sha256(listener_binary.read_bytes()).hexdigest() != listener_sha):
            raise RUNNER.ControlledRunError("TEST123_LISTENER_RUNTIME_HASH_MISMATCH")
        return listener_binary
    base._compile_listener = compile_receipted_listener

    def parse_sender_timing(sender_result: dict) -> dict:
        expected_token = token_state.get("run_token")
        if (not isinstance(expected_token, str) or
                sender_result.get("run_token") != expected_token):
            raise timing.TimingError("Test123 SENDER_RESULT token mismatch")
        checked = SENDER_PROTOCOL.validate_result(
            sender_result, expected_token,
            expected_wire_nonce_hex=_active_nonce(),
            packet_set_manifest=_active_manifest())
        rows = checked["send_timing"]
        return {
            "clock_domain": "CLOCK_MONOTONIC",
            "go_received_ns": checked["go_received_ns"],
            "started_ns": checked["started_ns"],
            "finished_ns": checked["finished_ns"],
            "finish_time_known": True,
            "frames_attempted": checked["frames_attempted"],
            "frames_completed": checked["frames_completed"],
            "entries": [dict(row) for row in rows],
            "coverage_complete": len(rows) == checked["frames_attempted"],
            "timing_complete": all(row["after_ns"] is not None for row in rows),
            "sender_stop_reason": checked["sender_stop_reason"],
            "clock_or_schedule_failure": checked["sender_stop_reason"] in {
                "clock_before_failed", "clock_after_failed", "schedule_wait_failed"},
            "local_send_writes_prove_rf": False,
            "sequence_validation": "test123_exact_packetset_manifest",
        }

    def parse_sender_started(sender_started: dict) -> dict:
        expected_token = token_state.get("run_token")
        if (not isinstance(sender_started, dict) or
                not isinstance(expected_token, str) or
                sender_started.get("schema") != SENDER_PROTOCOL.SCHEMA or
                sender_started.get("tool_test") != "Test123" or
                sender_started.get("running_kernel_test") != "Test122" or
                sender_started.get("wire_nonce_hex") != _active_nonce() or
                sender_started.get("run_token") != expected_token):
            raise timing.TimingError("Test123 SENDER_STARTED identity mismatch")
        checked = SENDER_PROTOCOL.parse_started(
            sender_started, expected_token,
            expected_wire_nonce_hex=_active_nonce())
        return {"go_received_ns": checked["go_received_ns"],
                "started_ns": checked["started_ns"]}

    timing.parse_sender_timing = parse_sender_timing
    timing.parse_sender_started = parse_sender_started

    def build_test123_remote_script(**kwargs):
        packet_set, manifest = BINDING.validate_active_packetset()
        token = kwargs.get("run_token")
        if not isinstance(token, str) or token != token_state.get("run_token"):
            raise protocol.ControlledProbeError("TEST123_REMOTE_TOKEN_MISMATCH")
        try:
            if BINDING.ACTIVE_PACKET_SET_PATH is not None:
                raise BINDING.Tool123BindingError("test123_packetset_claim_already_consumed")
            SENDER_PROTOCOL.bind_packet_set(
                packet_set, expected_sha256=manifest["packet_set_sha256"])
            BINDING.write_packetset_for_run(token)
            script = REMOTE_SENDER.build_remote_script(
                sender_binary=kwargs.get("binary"), packet_set=packet_set,
                run_token=token, ap=kwargs.get("ap", "wlan7"),
                monitor="iwn102mon")
            REMOTE_SENDER.validate_remote_script(
                script, run_token=token,
                packet_set_sha256=manifest["packet_set_sha256"])
            return script
        except (BINDING.Tool123BindingError, REMOTE_SENDER.RemoteScriptError,
                SENDER_PROTOCOL.SenderProtocolError) as error:
            raise protocol.ControlledProbeError(
                "TEST123_REMOTE_PACKETSET_SETUP_FAILED") from error

    protocol.build_remote_monitor_sender_script = build_test123_remote_script

    def save_test123_report(path, value, account):
        if not isinstance(value, dict):
            raise RUNNER.ControlledRunError("TEST123_REPORT_NOT_OBJECT")
        finalize_capture_report(value)
        sender = value.get("test088_sender")
        sender = sender if isinstance(sender, dict) else {}
        sender_event = sender.get("sender_result_event")
        sender_event = sender_event if isinstance(sender_event, dict) else {}
        listener = value.get("listener_result")
        listener = listener if isinstance(listener, dict) else {}
        provenance = value.get("openwrt_tx_provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        native = value.get("native_result")
        native = native if isinstance(native, dict) else {}
        manifest = BINDING.ACTIVE_PACKET_MANIFEST
        wire_nonce = (manifest.get("wire_nonce_hex")
                      if isinstance(manifest, dict) else None)
        value.update({
            "tool_id": "Tool123",
            "tool_test": "Test123",
            "running_kernel_test": "Test122",
            "workflow_complete": value.get("complete") is True,
            "workflow_complete_semantics": (
                "native_sender_monitor_listener_terminals_and_cleanup"),
            "sender_record_status": sender_event.get("status", "unknown"),
            "sender_record_validated": (
                provenance.get("status") == "local_sender_record_validated"),
            "monitor_observation_state": provenance.get(
                "monitor_observation_state", "unknown"),
            "listener_status": listener.get("status", "unknown"),
            "listener_nonce_payload_received": (
                listener.get("status") == "marker_received" and
                listener.get("marker_match") is True and
                listener.get("payload_match") is True),
            "listener_input_nonce_sha256": (
                hashlib.sha256(wire_nonce.encode("ascii")).hexdigest()
                if isinstance(wire_nonce, str) else None),
            "native_result_status": native.get("status", "unknown"),
            "native_input_is_nonce_correlated": False,
            "same_owner_current_lease_atomicity_proven": False,
            "live_current_lease_owner_or_ifnet_state": "unknown",
            "distinct_received_frame_ordinals_proven": False,
            "rf_transmission_proven": False,
            "peer_receipt_proven": False,
            "native_awdl_reply_proven": False,
            "airdrop_proven": False,
        })
        return saved["atomic_private_write"](path, value, account)

    RUNNER.atomic_private_write = save_test123_report

    def restore():
        protocol.parse_sender_ready = saved["protocol_ready"]
        protocol.parse_sender_result = saved["protocol_result"]
        protocol.parse_listener_ready = saved["protocol_listener_ready"]
        protocol.parse_listener_result = saved["protocol_listener_result"]
        protocol.build_remote_monitor_sender_script = saved["remote_builder"]
        timing.parse_sender_timing = saved["timing_parse"]
        timing.parse_sender_started = saved["timing_started"]
        RUNNER.TEST088.Test088SenderSession.go_once = saved["sender_go_once"]
        RUNNER.TEST088._RunCapture.attach = saved["capture_attach"]
        sender_session_class.start = saved["sender_start_descriptor"]
        SENDER_PROTOCOL.classify_sender_result = saved["provenance_classifier"]
        RUNNER.atomic_private_write = saved["atomic_private_write"]
        base.ManagedPipe = saved["managed_pipe"]
        base._compile_listener = saved["compile_listener"]
        SENDER_PROTOCOL.clear_packet_set_binding()
        for name, attribute in (
                ("listener_protocol", "LISTENER_PROTOCOL"),
                ("listener_source", "LISTENER_SOURCE"),
                ("listener_protocol_source", "LISTENER_PROTOCOL_SOURCE"),
                ("sender_protocol", "SENDER_PROTOCOL"),
                ("provenance", "PROVENANCE"),
                ("remote_sender", "REMOTE_SENDER")):
            setattr(RUNNER, attribute, saved[name])
        restore_test104()
    return restore


def _active_manifest() -> dict:
    value = RUNNER.ACTIVE_PACKET_MANIFEST
    if not isinstance(value, dict):
        raise RUNNER.ControlledRunError("TEST123_PACKETSET_NOT_BOUND")
    return value


def _active_nonce() -> str:
    value = _active_manifest().get("wire_nonce_hex")
    if not isinstance(value, str):
        raise RUNNER.ControlledRunError("TEST123_WIRE_NONCE_NOT_BOUND")
    return value


def _active_run_token_from_line(line: str) -> str:
    try:
        value = json.loads(line)
    except (ValueError, TypeError) as error:
        raise RUNNER.ControlledRunError("TEST123_SENDER_RESULT_MALFORMED") from error
    token = value.get("run_token") if isinstance(value, dict) else None
    if not isinstance(token, str):
        raise RUNNER.ControlledRunError("TEST123_SENDER_RUN_TOKEN_MISSING")
    return token


def finalize_capture_report(report: dict[str, Any]) -> dict[str, Any]:
    """Aggregate Test123 terminal evidence without changing frozen T087/T088.

    T087's ``complete`` flag describes only its native capture terminal.  The
    Test123 workflow also requires a validated sender record, a complete
    passive monitor observation, a valid listener terminal, and verified
    cleanup.  Keep every captured terminal in the report, but downgrade the
    workflow to partial if any required observation is absent or incomplete.
    """
    if not isinstance(report, dict):
        raise RUNNER.ControlledRunError("TEST123_REPORT_NOT_OBJECT")

    sender_container = report.get("test088_sender")
    sender_container = sender_container if isinstance(sender_container, dict) else {}
    sender_event = sender_container.get("sender_result_event")
    sender_event = sender_event if isinstance(sender_event, dict) else {}
    provenance = report.get("openwrt_tx_provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    native = report.get("native_result")
    native = native if isinstance(native, dict) else {}
    listener = report.get("listener_result")
    listener = listener if isinstance(listener, dict) else {}
    cleanup = report.get("sender_cleanup")
    cleanup = cleanup if isinstance(cleanup, dict) else {}

    reasons: list[str] = []
    if report.get("complete") is not True:
        reasons.append("coordinator_flow_incomplete")
    if (native.get("status") != "captured_no_retry" or
            native.get("report_saved") is not True or
            native.get("claim_consumed") is not True or
            native.get("retry_allowed") is not False):
        reasons.append("native_terminal_incomplete")
    if provenance.get("status") != "local_sender_record_validated":
        reasons.append("sender_record_unvalidated")
    elif (sender_event.get("status") != "complete" or
          sender_event.get("send_complete") is not True or
          provenance.get("send_complete") is not True):
        reasons.append("sender_send_incomplete")
    if isinstance(report.get("sender_terminal_error"), dict):
        reasons.append("sender_go_terminal_incomplete")
    if (provenance.get("monitor_observation_state") != "complete" or
            provenance.get("monitor_capture_finished") is not True):
        reasons.append("monitor_observation_incomplete")
    if (not listener or listener.get("event") != "LISTENER_RESULT" or
            listener.get("status") not in {"marker_received", "timeout_or_unmatched"} or
            report.get("listener_result_error") is not None):
        reasons.append("listener_terminal_unvalidated")
    if (not cleanup or any(cleanup.get(key) is not True for key in (
            "monitor_removed", "ap_unchanged", "temporary_files_removed"))):
        reasons.append("sender_cleanup_unverified")
    if report.get("native_worker_cleanup") != "exited_within_result_deadline":
        reasons.append("native_worker_cleanup_unverified")
    if report.get("listener_worker_cleanup") != "exited_after_result_window":
        reasons.append("listener_worker_cleanup_unverified")

    complete = not reasons
    original_status = report.get("status")
    report["complete"] = complete
    report["partial"] = not complete
    report["tool_workflow_status"] = "complete" if complete else "partial"
    report["tool_workflow_incomplete_reasons"] = reasons
    report["workflow_complete"] = complete
    report["workflow_complete_semantics"] = (
        "native_sender_monitor_listener_terminals_and_cleanup"
    )
    if not complete and original_status == "captured_no_peer_or_airdrop_proof":
        report["native_capture_status"] = original_status
        report["status"] = "captured_native_partial_tool_observation"
    return report


def adapt_legacy_listener_argv(argv: list[str]) -> list[str]:
    """Translate exactly the frozen T087 listener invocation to T123 argv."""
    values = list(argv)
    if len(values) < 5:
        return values
    legacy_executable = Path(str(values[0]))
    if ((legacy_executable.name not in {"awdl0_udp_probe_listener",
                                             "awdl0_unicast_listener_test123"} and
             legacy_executable != Path(getattr(RUNNER, "LISTENER_BINARY", ""))) or
            values[1:3] != ["--listen", RUNNER.PROTOCOL.LISTENER_MARKER]):
        return values
    try:
        token_index = values.index("--run-token")
        token = values[token_index + 1]
    except (ValueError, IndexError) as error:
        raise RUNNER.ControlledRunError("TEST123_LEGACY_LISTENER_TOKEN_MISSING") from error
    expected = RUNNER.ACTIVE_LISTENER_EXPECTATION
    if not isinstance(expected, dict):
        raise RUNNER.ControlledRunError("TEST123_LISTENER_EXPECTATION_MISSING")
    try:
        return LISTENER_PROTOCOL.listener_argv(
            RUNNER.LISTENER_BINARY, run_token=token, expected=expected)
    except LISTENER_PROTOCOL.ListenerProtocolError as error:
        raise RUNNER.ControlledRunError("TEST123_LISTENER_ARGV_BINDING_INVALID") from error


def _configure_test123_run() -> None:
    """Reuse Test122 run gates, then bind the independently built T123 tools."""
    KERNEL_COORDINATOR._configure_test122_run()
    sender, listener = _validated_tool_artifacts()
    sender_binary = _artifact_binary(sender, label="SENDER")
    listener_binary = _artifact_binary(listener, label="LISTENER")

    # Capture the validated Test122 tool graph before replacing its old
    # Test121 sender path with the receipt-pinned Tool123 ELF.
    base_hashes = RUNNER.runtime_tool_hashes()
    old_sender_source = Path(RUNNER.SENDER_SOURCE)
    old_sender_binary = Path(RUNNER.SENDER_BINARY)

    RUNNER.IWN_ROOT = BINDING.IWN_ROOT.resolve(strict=True)
    RUNNER.DEFAULT_METADATA = BINDING.KERNEL_METADATA
    RUNNER.BUILD_RECEIPT = BINDING.KERNEL_BUILD_RECEIPT
    RUNNER.DEPLOYMENT_RECEIPT = BINDING.KERNEL_DEPLOYMENT_RECEIPT
    RUNNER.ROUTER_SOURCE_RECEIPT = BINDING.KERNEL.ROUTER_RECEIPT
    RUNNER.TARGET_IDENTITY_RECEIPT = BINDING.KERNEL.TARGET_RECEIPT
    RUNNER.CANDIDATE = BINDING.KERNEL_CANDIDATE
    RUNNER.PROFILE = BINDING.KERNEL.PROFILE
    RUNNER.NATIVE_WORKER = NATIVE_WORKER
    RUNNER.RESULT_NAME = "test123-tools-private.json"
    RUNNER.CAPTURE_NAME = "native-controlled-capture-private.json"
    RUNNER.DEFAULT_AP = "wlan7"
    RUNNER.test104_run_dir = lambda boot_epoch, _candidate: (
        BINDING.KERNEL_METADATA.parent / ("test123-tools-boot" + str(boot_epoch)))

    runtime_binding = RUNNER.RUNTIME_BINDING
    runtime_binding.CANDIDATE = BINDING.KERNEL_CANDIDATE
    runtime_binding.bind_runtime_identities = BINDING.bind_runtime_identities
    RUNNER.SENDER_BUILD_RECEIPT = SENDER_RECEIPT
    RUNNER.SENDER_SOURCE = SENDER_SOURCE
    RUNNER.SENDER_BINARY = sender_binary
    RUNNER.SENDER_SHA256 = sender["binary_sha256"]
    RUNNER.EXPECTED_SENDER_SOURCE_SHA256 = sender["source_sha256"]
    RUNNER.EXPECTED_SENDER_BINARY_SHA256 = sender["binary_sha256"]
    RUNNER.SENDER_TARGET = "aarch64-linux-musl"
    RUNNER.LISTENER_BINARY = listener_binary
    RUNNER.LISTENER_SHA256 = listener["binary_sha256"]
    RUNNER.LISTENER_BUILD_RECEIPT = LISTENER_RECEIPT

    def sender_receipt(owner_uid: int) -> dict:
        receipt, raw = RUNNER.read_private_json(SENDER_RECEIPT, owner_uid)
        # The independent artifact validator checks source/protocol/dependency
        # and binary identity; this second read binds the exact private file
        # used by the run to the same validated build record.
        checked = _artifact_validator().validate_build_receipt(
            SENDER_RECEIPT, kind="sender", repo_root=REPO_ROOT,
            private_root=BINDING.TOOL_ROOT)
        validated_digest = checked.pop("validated_build_receipt_sha256", None)
        if (receipt != checked or
                hashlib.sha256(raw).hexdigest() != validated_digest):
            raise RUNNER.ControlledRunError("TEST123_SENDER_RECEIPT_CHANGED")
        return receipt
    RUNNER.sender_receipt = sender_receipt

    # Snapshot the fully validated Test122 dependencies before replacing its
    # reused Test121 sender path. The T123 result records the current tool,
    # while the Test122 kernel and START/GO implementation remain included.
    for path in (old_sender_source, old_sender_binary):
        try:
            base_hashes.pop(Path(path).resolve(strict=True).relative_to(
                REPO_ROOT.resolve(strict=True)).as_posix(), None)
        except (ValueError, OSError):
            pass
    runtime_paths = (
        Path(__file__).resolve(), TOOL_DIR / "rx149_binding_test123.py",
        TOOL_DIR / "tool_artifacts_test123.py", NATIVE_WORKER,
        SENDER_SOURCE, SENDER_PROTOCOL_SOURCE,
        TOOL_DIR / "remote_sender_test123.py", LISTENER_SOURCE,
        LISTENER_PROTOCOL_SOURCE, KERNEL_COORDINATOR.NATIVE_WORKER,
        sender_binary, listener_binary,
    )
    def runtime_tool_hashes() -> dict[str, str]:
        values = dict(base_hashes)
        for path in runtime_paths:
            path = Path(path)
            if path.is_symlink() or not path.is_file():
                raise RUNNER.ControlledRunError(
                    "TEST123_RUNTIME_TOOL_UNAVAILABLE:" + path.name)
            values[_private_hash_key(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        return values
    RUNNER.runtime_tool_hashes = runtime_tool_hashes

    # Attach Test123 adapters only around the actual run's existing Test104
    # profile setup. START reader, one-use claim, 100 ms lease, pre-GO deadline,
    # and native END/cleanup remain owned by the frozen T104/T087 code.
    RUNNER.configure_test104_profile = _configure_test123_profile


def _run_once(*, host: str, control_path: str, metadata: Path, ap: str) -> tuple[dict, Path]:
    import re
    if (not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}", host)
            or host.startswith("-") or not Path(control_path).is_absolute()):
        raise BINDING.Tool123BindingError("router_transport_arguments_invalid")
    if metadata != BINDING.KERNEL_METADATA:
        raise BINDING.Tool123BindingError("test122_metadata_path_mismatch")
    if ap != "wlan7":
        raise BINDING.Tool123BindingError("router_interface_must_be_prepared_wlan7")
    _configure_test123_run()
    boot_epoch, loaded_uuid = T120._load_current_identity()
    kernel_metadata, build, _raw, _path = BINDING.validate_kernel_bundle(metadata)
    if (loaded_uuid != build.get("mach_o_uuid") or
            boot_epoch <= kernel_metadata.get("minimum_boot_epoch_exclusive", boot_epoch)):
        raise BINDING.Tool123BindingError("test122_current_runtime_identity_mismatch")
    os.environ["INTEL_WIRELESS_NATIVE_ROOT"] = str(BINDING.IWN_ROOT)
    try:
        report, output_dir, _prearm = RUNNER.run_once(
            host=host, control_path=control_path, metadata_path=metadata, ap=ap)
    finally:
        BINDING.clear_active_run()
        SENDER_PROTOCOL.clear_packet_set_binding()
    return report, output_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--run", action="store_true",
                      help="Perform one explicitly authorized Test123 capture on Test122")
    parser.add_argument("--host")
    parser.add_argument("--control-path")
    parser.add_argument("--iwn-root", type=Path, default=BINDING.IWN_ROOT)
    parser.add_argument("--metadata", type=Path, default=BINDING.KERNEL_METADATA)
    parser.add_argument("--ap", default="wlan7")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps(plan(), sort_keys=True))
        return 0
    try:
        if args.iwn_root.expanduser().resolve(strict=True) != BINDING.IWN_ROOT.resolve(strict=True):
            raise BINDING.Tool123BindingError("iwn_root_mismatch")
        if not args.host or not args.control_path:
            raise BINDING.Tool123BindingError("router_transport_required")
        report, output_dir = _run_once(
            host=args.host, control_path=args.control_path,
            metadata=args.metadata, ap=args.ap)
        sender_event = (report.get("test088_sender", {})
                        .get("sender_result_event"))
        sender_status = sender_event.get("status") if isinstance(sender_event, dict) else "unknown"
        listener_result = report.get("listener_result")
        rx_status = ("payload_received" if isinstance(listener_result, dict) and
                     listener_result.get("status") == "marker_received" else
                     "unknown_or_not_received")
        print(json.dumps({
            "tool_test": "Test123", "running_kernel_test": "Test122",
            "sender_status": sender_status,
            "listener_status": rx_status,
            "complete": report.get("complete") is True,
            "output_directory": str(output_dir),
            "retry_allowed": False,
            "rf_transmission_proven": False,
            "peer_receipt_proven": False,
            "native_awdl_reply_proven": False,
            "airdrop_proven": False,
        }, sort_keys=True))
        return 0 if report.get("complete") is True else 2
    except Exception as error:
        code = getattr(error, "code", None) or str(error)[:120] or type(error).__name__
        print("ERROR: " + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
