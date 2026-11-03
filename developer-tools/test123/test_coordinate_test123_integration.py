#!/usr/bin/env python3
"""Offline integration checks for Test123's frozen T087/T088 seams."""
from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test_component_unavailable:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COORD = load("test123_coordinate_integration_under_test",
             HERE / "coordinate_test123_rx149.py")
SENDER_FIXTURES = load(
    "test123_sender_fixtures_for_coordinator",
    HERE / "router-status/test_dual_sender_protocol_test123.py")
IDENTITY_FIXTURES = load(
    "test123_identity_fixtures_for_coordinator",
    HERE / "test_binding_independent_test123.py")


class _Input:
    def __init__(self):
        self.writes = []

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        return None

    def close(self):
        return None


class _Output:
    def close(self):
        return None


class _Process:
    def __init__(self, exit_code=0):
        self.pid = 12345
        self.stdin = _Input()
        self.stdout = _Output()
        self.exit_code = exit_code
        self.terminated = False

    def wait(self, timeout=None):
        return self.exit_code


class _Selector:
    def register(self, *_args, **_kwargs):
        return None

    def close(self):
        return None


def _started_line(token: str, nonce: str) -> str:
    protocol = COORD.SENDER_PROTOCOL
    go = 1_000_000_000
    started = go + 1_000_000
    value = {
        "event": "SENDER_STARTED", "schema": protocol.SCHEMA,
        "tool_test": "Test123", "running_kernel_test": "Test122",
        "packet_set_schema": protocol.PACKETSET_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC",
        "observation_time_semantics": protocol.OBSERVATION_TIME_SEMANTICS,
        "run_token": token, "wire_nonce_hex": nonce,
        "driver_rx_lease_ms": protocol.DRIVER_RX_LEASE_MS,
        "go_received_ns": go, "started_ns": started,
        "send_deadline_ns": started + protocol.SEND_BUDGET_NS,
        "observer_deadline_ns": started + protocol.CAPTURE_WINDOW_NS,
        "go_to_start_ns": started - go,
        "go_to_start_max_ns": protocol.GO_TO_START_MAX_NS,
        "send_budget_ns": protocol.SEND_BUDGET_NS,
        "status_tail_ns": protocol.STATUS_TAIL_NS,
        "frames_requested": protocol.FRAME_COUNT,
        "interval_ms": protocol.INTERVAL_MS,
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "intel_arm_invoked": False, "boot_claim_used": False,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _packetset_valid_line(nonce: str, **overrides) -> str:
    value = {
        "event": "PACKET_SET_VALID",
        "schema": COORD.SENDER_PROTOCOL.PACKETSET_SCHEMA,
        "frames": 4,
        "interval_ms": 10,
        "budget_ms": 40,
        "noack_requested": False,
        "transmission_capability": False,
        "rf_transmission_proven": False,
        "wire_nonce_hex": nonce,
    }
    value.update(overrides)
    return "PACKET_SET_VALID " + json.dumps(
        value, sort_keys=True, separators=(",", ":"))


def _monitor_ready_line() -> str:
    values = {
        "mode": "monitor_direct_channel",
        "monitor_direct_channel_known": "true",
        "monitor_wiphy": "0", "monitor_channel": "149",
        "monitor_frequency_mhz": "5745", "ap_wiphy": "0",
        "ap_channel": "149", "ap_frequency_mhz": "5745",
        "ap_width_mhz": "80", "phy_single_channel_constraints_count": "1",
        "active_same_phy_channel_count": "1",
        "active_same_phy_channels": "149",
        "active_same_phy_frequencies_mhz": "5745",
    }
    return "MONITOR_READY " + " ".join(f"{key}={value}" for key, value in values.items())


def _sender_ready_line(nonce: str) -> str:
    values = dict(COORD.SENDER_PROTOCOL.READY_VALUES)
    values["wire_nonce_hex"] = nonce
    return "READY " + " ".join(f"{key}={value}" for key, value in values.items())


class Test123CoordinatorIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This validates local receipts and paths only. It does not read live
        # identity, contact OpenWrt, compile, arm, or open an interface.
        COORD._configure_test123_run()

    def setUp(self):
        COORD.SENDER_PROTOCOL.clear_packet_set_binding()
        COORD.BINDING.clear_active_run()

    def _invoke_real_t087_start(self, lines):
        """Run the installed T123 wrapper around the real T087 start method."""
        restore = COORD._configure_test123_profile()
        router_receipt = IDENTITY_FIXTURES._router_receipt()
        target_receipt = IDENTITY_FIXTURES._target_receipt()
        raw, manifest = COORD.BINDING.bind_runtime_identities(
            IDENTITY_FIXTURES._metadata(), router_receipt, target_receipt,
            expected_boot_epoch=target_receipt["boot_epoch"],
            expected_uuid=IDENTITY_FIXTURES.UUID,
            router_receipt_sha256=IDENTITY_FIXTURES._canonical_sha(router_receipt),
            now=IDENTITY_FIXTURES.NOW,
            wire_nonce_hex=SENDER_FIXTURES.NONCE,
            wifi_sequence_base=0x321, awdl_sequence_base=0x4567)
        nonce = manifest["wire_nonce_hex"]
        COORD.SENDER_PROTOCOL.bind_packet_set(raw)
        old_manifest = getattr(COORD.RUNNER, "ACTIVE_PACKET_MANIFEST", None)
        COORD.RUNNER.ACTIVE_PACKET_MANIFEST = manifest
        process = _Process(exit_code=0)
        selector = _Selector()
        reader = mock.Mock(side_effect=list(lines))
        router = COORD.RUNNER.ROUTER
        # T087 only needs a real file and a matching digest before it opens the
        # mocked subprocess; the file is never executed by this test.
        with tempfile.TemporaryDirectory(prefix="test123-ready-") as tmp:
            binary = Path(tmp) / "sender"
            binary.write_bytes(b"offline fake sender binary")
            binary.chmod(0o600)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            try:
                with (
                    mock.patch.object(router, "_read_protocol_line", reader),
                    mock.patch.object(router, "build_bootstrap_argv",
                                      return_value=["ssh", "mock"]),
                    mock.patch.object(router.subprocess, "Popen", return_value=process),
                    mock.patch.object(router.selectors, "DefaultSelector",
                                      return_value=selector),
                    mock.patch.object(router.protocol,
                                      "build_remote_monitor_sender_script",
                                      return_value="#!/bin/sh\n"),
                    mock.patch.object(router, "_terminate_process") as terminate,
                ):
                    result = COORD.RUNNER.ROUTER.RouterSenderSession.start(
                        host="root@192.0.2.1", control_path="/private/tmp/mock.sock",
                        sender_binary=binary, sender_sha256=digest,
                        run_token=SENDER_FIXTURES.TOKEN, ap="wlan7")
                    capture = COORD.RUNNER.TEST088._RunCapture(
                        COORD.RUNNER.CANDIDATE)
                    attached_report = COORD.RUNNER.TEST088._RunCapture.attach(
                        capture, {})
                return (result, reader, process, terminate, nonce,
                        hashlib.sha256(raw).hexdigest(), attached_report)
            finally:
                restore()
                COORD.RUNNER.ACTIVE_PACKET_MANIFEST = old_manifest
                COORD.SENDER_PROTOCOL.clear_packet_set_binding()
                COORD.BINDING.clear_active_run()

    def test_default_plan_is_inert_and_separates_tool_from_kernel(self):
        self.assertEqual(COORD.plan()["tool_test"], "Test123")
        self.assertEqual(COORD.plan()["running_kernel_test"], "Test122")
        self.assertFalse(COORD.plan()["rf_triggered"])
        self.assertFalse(COORD.plan()["armed"])
        self.assertEqual(COORD.main(["--plan"]), 0)

    def test_t087_start_validates_packetset_preface_then_parses_real_readiness(self):
        nonce = SENDER_FIXTURES.NONCE
        (result, reader, process, terminate, _, actual_packet_sha,
         attached_report) = self._invoke_real_t087_start([
            _packetset_valid_line(nonce), _monitor_ready_line(),
            _sender_ready_line(nonce),
        ])
        session, monitor_ready, sender_ready = result
        self.assertEqual(monitor_ready["ap_channel"], 149)
        self.assertEqual(sender_ready["wire_nonce_hex"], nonce)
        evidence = session.protocol_evidence["test123_packetset_verification"]
        self.assertEqual(evidence["status"], "validated")
        self.assertEqual(evidence["frames"], 4)
        self.assertEqual(evidence["interval_ms"], 10)
        self.assertEqual(evidence["budget_ms"], 40)
        self.assertFalse(evidence["rf_transmission_proven"])
        self.assertEqual(evidence["packet_set_sha256"], actual_packet_sha)
        self.assertNotIn("wire_nonce_hex", evidence)
        self.assertEqual(
            attached_report["test123_packetset_verification"]["status"],
            "validated")
        self.assertEqual(reader.call_count, 3)
        self.assertFalse(process.terminated)
        terminate.assert_not_called()

    def test_t087_start_rejects_missing_wrong_nonce_and_duplicate_preface(self):
        raw, manifest = SENDER_FIXTURES.packet_set()
        nonce = manifest["wire_nonce_hex"]
        cases = (
            ("missing", [_monitor_ready_line(), _sender_ready_line(nonce)],
             "packetset_verification_missing", None),
            ("wrong nonce", [_packetset_valid_line("ffffffffffffffff"),
                              _monitor_ready_line(), _sender_ready_line(nonce)],
             "packetset_verification_contract_invalid",
             "packetset_verification_nonce_mismatch"),
            ("float frames", [_packetset_valid_line(nonce, frames=4.0),
                               _monitor_ready_line(), _sender_ready_line(nonce)],
             "packetset_verification_numeric_type_invalid", "frames"),
            ("boolean frames", [_packetset_valid_line(nonce, frames=True),
                                 _monitor_ready_line(), _sender_ready_line(nonce)],
             "packetset_verification_contract_invalid",
             "packetset_verification_contract_mismatch"),
            ("duplicate", [_packetset_valid_line(nonce),
                            _packetset_valid_line(nonce), _monitor_ready_line(),
                            _sender_ready_line(nonce)],
             "packetset_verification_duplicate", None),
        )
        for name, lines, error_code, reason in cases:
            with self.subTest(name=name):
                with self.assertRaises(COORD.RUNNER.PROTOCOL.ControlledProbeError) as caught:
                    self._invoke_real_t087_start(lines)
                self.assertEqual(
                    caught.exception.code,
                    "TEST123_PACKETSET_VERIFICATION_INVALID")
                self.assertEqual(
                    caught.exception.evidence["test123_packetset_verification"]["error_code"],
                    error_code)
                if reason is not None:
                    self.assertEqual(
                        caught.exception.evidence["test123_packetset_verification"]["reason"],
                        reason)

    def test_t087_remote_error_still_reads_cleanup_without_packetset_preface(self):
        cleanup = "CLEANUP " + json.dumps({
            "event": "MONITOR_CLEANUP",
            "run_token": SENDER_FIXTURES.TOKEN,
            "monitor_removed": True,
            "ap_unchanged": True,
            "temporary_files_removed": True,
        }, sort_keys=True, separators=(",", ":"))
        with self.assertRaises(COORD.RUNNER.PROTOCOL.ControlledProbeError) as caught:
            self._invoke_real_t087_start([
                "REMOTE_ERROR code=monitor_create_failed", cleanup,
            ])
        self.assertEqual(caught.exception.code, "ROUTER_READINESS_SETUP_FAILED")
        self.assertTrue(caught.exception.evidence["cleanup"]["monitor_removed"])
        self.assertTrue(caught.exception.evidence["cleanup"]["temporary_files_removed"])

    def test_t088_go_once_uses_legacy_projection_but_preserves_raw_nonce_failure(self):
        restore = COORD._configure_test123_profile()
        packet_bytes, manifest = SENDER_FIXTURES.packet_set()
        token = SENDER_FIXTURES.TOKEN
        nonce = manifest["wire_nonce_hex"]
        raw_result = SENDER_FIXTURES.sender_result(manifest)
        raw_result["run_token"] = token
        raw_result["wire_nonce_hex"] = "ffffffffffffffff"  # legacy fields remain valid
        raw_lines = [
            _started_line(token, nonce),
            json.dumps(raw_result, sort_keys=True, separators=(",", ":")),
            "CLEANUP " + json.dumps({
                "event": "MONITOR_CLEANUP", "run_token": token,
                "monitor_removed": True, "ap_unchanged": True,
                "temporary_files_removed": True,
            }, sort_keys=True, separators=(",", ":")),
        ]
        COORD.SENDER_PROTOCOL.bind_packet_set(packet_bytes)

        process = _Process(exit_code=0)
        session = type("FakeSenderSession", (), {})()
        session.closed = False
        session.control_consumed = False
        session.process = process
        session.selector = _Selector()
        session.read_state = {"buffer": b""}
        session.deadline = 10_000_000_000
        session.run_token = token
        session.protocol_evidence = {}

        capture = COORD.RUNNER.TEST088._RunCapture(COORD.RUNNER.CANDIDATE)
        wrapped = COORD.RUNNER.TEST088.Test088SenderSession(session, capture)
        try:
            with mock.patch.object(
                    COORD.RUNNER.TEST088.ROUTER, "_read_protocol_line",
                    side_effect=raw_lines):
                completion = wrapped.go_once()

            self.assertEqual(completion["sender_result"]["status"], "complete")
            self.assertTrue(completion["cleanup"]["monitor_removed"])
            self.assertEqual(session.protocol_evidence["test088_raw_sender_result"], raw_result)
            self.assertEqual(capture.result_event, raw_result)
            self.assertEqual(process.stdin.writes, [f"GO {token}\n".encode("ascii")])

            # The frozen T088 legacy handoff cannot be mistaken for a validated
            # Test123 record; the separate raw validator rejects its wrong nonce.
            with self.assertRaises(COORD.SENDER_PROTOCOL.SenderProtocolError):
                COORD.SENDER_PROTOCOL.validate_result(
                    raw_result, token, expected_wire_nonce_hex=nonce,
                    packet_set_manifest=manifest)
        finally:
            restore()
            COORD.SENDER_PROTOCOL.clear_packet_set_binding()

    def test_listener_legacy_argv_is_intercepted_before_t104_marker_logic(self):
        token = "0123456789abcdef0123456789abcdef"
        expected = {
            "wire_nonce_hex": "1020304050607080",
            "source_ipv6": "fe80::1001",
            "destination_ipv6": "fe80::2002",
            "ifindex": 31,
        }
        old_expectation = COORD.RUNNER.ACTIVE_LISTENER_EXPECTATION
        old_binary = getattr(COORD.RUNNER, "LISTENER_BINARY", None)
        old_sha = getattr(COORD.RUNNER, "LISTENER_SHA256", None)
        old_pipe = COORD.RUNNER.BASE.ManagedPipe
        seen = []

        def fake_pipe(argv):
            seen.append(list(argv))
            return object()

        COORD.RUNNER.ACTIVE_LISTENER_EXPECTATION = expected
        COORD.RUNNER.BASE.ManagedPipe = fake_pipe
        try:
            restore = COORD._configure_test123_profile()
            try:
                legacy = [str(COORD.RUNNER.LISTENER_BINARY), "--listen",
                          COORD.RUNNER.PROTOCOL.LISTENER_MARKER,
                          "--run-token", token, "--recv-anyif"]
                COORD.RUNNER.BASE.ManagedPipe(legacy)
                self.assertEqual(len(seen), 1)
                self.assertEqual(seen[0][1:4], [
                    "--listen-nonce", expected["wire_nonce_hex"],
                    "--run-token"])
                self.assertIn("--expected-source-ipv6", seen[0])
                self.assertNotIn("--listen", seen[0])
            finally:
                restore()
        finally:
            COORD.RUNNER.ACTIVE_LISTENER_EXPECTATION = old_expectation
            COORD.RUNNER.BASE.ManagedPipe = old_pipe
            if old_binary is None:
                COORD.RUNNER.__dict__.pop("LISTENER_BINARY", None)
            else:
                COORD.RUNNER.LISTENER_BINARY = old_binary
            if old_sha is None:
                COORD.RUNNER.__dict__.pop("LISTENER_SHA256", None)
            else:
                COORD.RUNNER.LISTENER_SHA256 = old_sha

    def test_empty_listener_argv_is_inert(self):
        self.assertEqual(COORD.adapt_legacy_listener_argv([]), [])

    def test_t104_exact_sender_pin_passes_and_rejects_before_io(self):
        """Exercise the frozen T104 preflight expression through run_once."""
        from types import SimpleNamespace

        # Rebind the actual Test123 paths/receipts, then make only the inputs
        # preceding T104's runtime hash gate deterministic. The T088 sentinel
        # is the first point after that gate; no barrier, claim, or device I/O
        # is allowed in this offline test.
        COORD._configure_test123_run()
        runner = COORD.RUNNER
        packet_bytes, manifest = COORD.SENDER_PROTOCOL._PACKETSET.encode_packet_set(
            SENDER_FIXTURES.SOURCE, SENDER_FIXTURES.TARGET,
            "preflight-runtime-pin", wire_nonce_hex="a1b2c3d4e5f67890",
            wifi_sequence_base=19, awdl_sequence_base=411)
        uuid = "17DB1FD2-214C-30A1-825C-C841B5F9E80B"
        build = {
            "candidate": runner.CANDIDATE,
            "mach_o_uuid": uuid,
            "binary_sha256": "a" * 64,
        }
        deployment = {
            "candidate": runner.CANDIDATE,
            "mach_o_uuid": uuid,
            "binary_sha256": "a" * 64,
        }
        metadata = {
            "candidate": runner.CANDIDATE,
            "expected_loaded_uuid": uuid,
            "minimum_boot_epoch_exclusive": 100,
        }
        original_read_private = runner.read_private_json
        def read_private(path, owner_uid):
            if Path(path) == Path(runner.ROUTER_SOURCE_RECEIPT):
                return {"identity_receipt_sha256": "b" * 64}, b"router"
            if Path(path) == Path(runner.TARGET_IDENTITY_RECEIPT):
                return {"ifindex": 31}, b"target"
            return original_read_private(path, owner_uid)

        class ReachedT088(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="test123-preflight-") as temp:
            temp_root = Path(temp)
            output_dir = temp_root / "run-output"
            def fake_reader(directory):
                path = Path(directory) / "mock-reader"
                path.write_bytes(b"offline test reader")
                return path

            original_hashes = runner.runtime_tool_hashes
            expected_key = str(runner.SENDER_BINARY.relative_to(runner.REPO))
            def hashes(*, corrupt=False):
                value = original_hashes()
                private_keys = [key for key in value
                                if key.startswith("private:") and
                                key.endswith("/" + runner.SENDER_BINARY.name)]
                self.assertEqual(len(private_keys), 1)
                self.assertEqual(value.get(expected_key), value[private_keys[0]])
                if corrupt:
                    value[expected_key] = "0" * 64
                return value

            def run_preflight(*, corrupt):
                reached = []
                def stop_before_device_io(**_kwargs):
                    reached.append(True)
                    raise ReachedT088()

                with mock.patch.object(runner, "workspace_account",
                                       return_value=SimpleNamespace(pw_uid=runner.REPO.stat().st_uid,
                                                                    pw_gid=runner.REPO.stat().st_gid)), \
                     mock.patch.object(runner, "validate_deployment",
                                       return_value=(build, deployment, b"build", b"deployment")), \
                     mock.patch.object(runner, "validate_runtime_metadata",
                                       return_value=(metadata, {"status": "passed"},
                                                     {"metadata_sha256": "c" * 64})), \
                     mock.patch.object(runner.RUNTIME_BINDING, "_read_boot_epoch",
                                       return_value=200), \
                     mock.patch.object(runner.RUNTIME_BINDING, "_run_text",
                                       return_value="loaded " + uuid), \
                     mock.patch.object(runner.RUNTIME_BINDING, "_extract_loaded_uuid",
                                       return_value=uuid), \
                     mock.patch.object(runner, "read_private_json",
                                       side_effect=read_private), \
                     mock.patch.object(runner.RUNTIME_BINDING, "bind_runtime_identities",
                                       return_value=(packet_bytes, manifest)), \
                     mock.patch.object(runner.START_BARRIER, "compile_reader",
                                       side_effect=fake_reader), \
                     mock.patch.object(runner, "test104_run_dir",
                                       return_value=output_dir), \
                     mock.patch.object(runner.BASE, "_validate_bundle",
                                       return_value=(metadata, build, "d" * 64,
                                                     Path("build.json"))), \
                     mock.patch.object(runner, "runtime_tool_hashes",
                                       side_effect=lambda: hashes(corrupt=corrupt)), \
                     mock.patch.object(runner.START_BARRIER,
                                       "install_native_armed_go_barrier",
                                       return_value=lambda: None) as barrier, \
                     mock.patch.object(runner, "install_go_deadline_guard",
                                       return_value=lambda: None), \
                     mock.patch.object(runner.TEST088, "run_test088_once",
                                       side_effect=stop_before_device_io) as t088:
                    if corrupt:
                        with self.assertRaises(runner.ControlledRunError) as caught:
                            runner.run_once(
                                host="root@192.0.2.1", control_path="/private/tmp/mock.sock",
                                metadata_path=COORD.BINDING.KERNEL_METADATA, ap="wlan7")
                        self.assertEqual(caught.exception.code,
                                         "SENDER_BINARY_RUNTIME_PIN_MISMATCH")
                        self.assertEqual(reached, [])
                        barrier.assert_not_called()
                        t088.assert_not_called()
                    else:
                        with self.assertRaises(ReachedT088):
                            runner.run_once(
                                host="root@192.0.2.1", control_path="/private/tmp/mock.sock",
                                metadata_path=COORD.BINDING.KERNEL_METADATA, ap="wlan7")
                        self.assertEqual(reached, [True])
                        barrier.assert_called_once()
                        t088.assert_called_once()

            run_preflight(corrupt=False)
            run_preflight(corrupt=True)

    def test_workflow_completion_requires_all_terminal_observations(self):
        def report():
            return {
                "status": "captured_no_peer_or_airdrop_proof",
                "complete": True,
                "partial": False,
                "native_result": {
                    "status": "captured_no_retry", "report_saved": True,
                    "claim_consumed": True, "retry_allowed": False,
                },
                "test088_sender": {"sender_result_event": {
                    "status": "complete", "send_complete": True,
                }},
                "openwrt_tx_provenance": {
                    "status": "local_sender_record_validated",
                    "send_complete": True,
                    "monitor_observation_state": "complete",
                    "monitor_capture_finished": True,
                },
                "listener_result": {
                    "event": "LISTENER_RESULT",
                    "status": "timeout_or_unmatched",
                },
                "listener_result_error": None,
                "sender_cleanup": {
                    "monitor_removed": True, "ap_unchanged": True,
                    "temporary_files_removed": True,
                },
                "native_worker_cleanup": "exited_within_result_deadline",
                "listener_worker_cleanup": "exited_after_result_window",
            }

        complete = COORD.finalize_capture_report(report())
        self.assertTrue(complete["complete"])
        self.assertFalse(complete["partial"])
        self.assertEqual(complete["tool_workflow_incomplete_reasons"], [])

        cases = (
            ("sender failure", lambda value: value["test088_sender"][
                "sender_result_event"].update(status="failed", send_complete=False)),
            ("unknown sender", lambda value: value["openwrt_tx_provenance"].update(
                status="unknown")),
            ("incomplete monitor", lambda value: value["openwrt_tx_provenance"].update(
                monitor_observation_state="incomplete", monitor_capture_finished=False)),
            ("bad cleanup", lambda value: value["sender_cleanup"].update(
                monitor_removed=False)),
        )
        for name, change in cases:
            with self.subTest(name=name):
                value = report()
                change(value)
                finalized = COORD.finalize_capture_report(value)
                self.assertFalse(finalized["complete"])
                self.assertTrue(finalized["partial"])
                self.assertTrue(finalized["tool_workflow_incomplete_reasons"])

    def test_resume_prearm_requires_explicit_run(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(COORD.main(["--resume-prearm"]), 2)
        self.assertIn("resume_prearm_requires_explicit_run", stderr.getvalue())

    def test_resume_prearm_claims_once_after_barrier_install_and_restores_paths(self):
        from types import SimpleNamespace

        runner = COORD.RUNNER
        boot_epoch = 1793697291
        uuid = "17DB1FD2-214C-30A1-825C-C841B5F9E80B"
        temp_root = Path(tempfile.mkdtemp(prefix="test123-prearm-output-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(temp_root, ignore_errors=True))
        kernel_metadata = temp_root / "native-controlled-probe-private.json"
        fresh_output = (kernel_metadata.parent /
                        f"test123-tools-boot{boot_epoch}-prearm-resume")
        verification = {
            "eligible": True, "same_boot": True,
            "expected_boot_epoch": boot_epoch, "expected_uuid": uuid,
            "kernel_claim_recheck_required_by_normal_preflight": True,
            "fresh_output_directory": str(fresh_output),
            "prior_status": "MONITOR_READY_MALFORMED",
            "prior_native_claim_consumed": False, "prior_go_attempted": False,
            "report_sha256": "a" * 64, "capture_sha256": "b" * 64,
            "cleanup_observation_sha256": "c" * 64,
            "host_processes_sha256": "d" * 64,
        }
        claim = {
            "resume_marker_created": True,
            "fresh_output_directory": str(fresh_output),
            "resume_marker_sha256": "e" * 64,
        }
        events = []
        helper = SimpleNamespace(
            PrearmResumeError=type("PrearmResumeError", (ValueError,), {}),
            verify_prearm_resume=mock.Mock(return_value=verification),
            claim_prearm_resume=mock.Mock(
                side_effect=lambda value: (events.append("claim") or claim)),
        )
        old_run_directory = runner.test104_run_dir
        old_test104_configure = COORD._ORIGINAL_TEST104_CONFIGURE
        old_context = COORD._ACTIVE_PREARM_RESUME_CONTEXT
        old_installer = runner.START_BARRIER.install_native_armed_go_barrier
        old_run_once = runner.run_once

        def original_test104_configure():
            return lambda: None

        def original_installer(*_args, **_kwargs):
            events.append("barrier_installed")
            return lambda: events.append("barrier_restored")

        def fake_run_once(**kwargs):
            self.assertEqual(kwargs["metadata_path"], COORD.BINDING.KERNEL_METADATA)
            self.assertEqual(runner.test104_run_dir(boot_epoch, runner.CANDIDATE),
                             fresh_output)
            restore_profile = runner.configure_test104_profile()
            try:
                restore_barrier = runner.START_BARRIER.install_native_armed_go_barrier()
                try:
                    self.assertEqual(events[:2], ["barrier_installed", "claim"])
                    self.assertEqual(helper.claim_prearm_resume.call_count, 1)
                    self.assertTrue(COORD._ACTIVE_PREARM_RESUME_CONTEXT[
                        "resume_marker_created"])
                finally:
                    restore_barrier()
            finally:
                restore_profile()
            return {"status": "offline_mock"}, fresh_output, None

        try:
            COORD._ORIGINAL_TEST104_CONFIGURE = original_test104_configure
            runner.START_BARRIER.install_native_armed_go_barrier = original_installer
            runner.run_once = fake_run_once
            with (
                mock.patch.object(COORD, "_configure_test123_run"),
                mock.patch.object(COORD.BINDING, "KERNEL_METADATA", kernel_metadata),
                mock.patch.object(COORD.T120, "_load_current_identity",
                                  return_value=(boot_epoch, uuid)),
                mock.patch.object(COORD.BINDING, "validate_kernel_bundle",
                                  return_value=({"minimum_boot_epoch_exclusive":
                                                 boot_epoch - 1},
                                                {"mach_o_uuid": uuid}, b"", Path("meta"))),
                mock.patch.object(COORD, "_load", return_value=helper),
                mock.patch.dict(os.environ, {}, clear=False),
            ):
                report, output_dir = COORD._run_once(
                    host="root@192.0.2.1", control_path="/private/tmp/mock.sock",
                    metadata=COORD.BINDING.KERNEL_METADATA, ap="wlan7",
                    resume_prearm=True)
            self.assertEqual(report["status"], "offline_mock")
            self.assertEqual(output_dir, fresh_output)
            self.assertEqual(runner.test104_run_dir, old_run_directory)
            self.assertIsNone(COORD._ACTIVE_PREARM_RESUME_CONTEXT)
            helper.verify_prearm_resume.assert_called_once_with(
                expected_boot_epoch=boot_epoch, expected_uuid=uuid)
            helper.claim_prearm_resume.assert_called_once_with(verification)
            self.assertEqual(events, ["barrier_installed", "claim", "barrier_restored"])
        finally:
            runner.test104_run_dir = old_run_directory
            COORD._ORIGINAL_TEST104_CONFIGURE = old_test104_configure
            runner.START_BARRIER.install_native_armed_go_barrier = old_installer
            runner.run_once = old_run_once
            COORD._ACTIVE_PREARM_RESUME_CONTEXT = old_context

    def test_resume_prearm_rejects_bad_recheck_semantics_before_run(self):
        from types import SimpleNamespace

        boot_epoch = 1793697291
        uuid = "17DB1FD2-214C-30A1-825C-C841B5F9E80B"
        bad_verification = {
            "eligible": True, "same_boot": True,
            "expected_boot_epoch": boot_epoch, "expected_uuid": uuid,
            "kernel_claim_recheck_required_by_normal_preflight": False,
            "fresh_output_directory": str(COORD.BINDING.KERNEL_METADATA.parent /
                                           f"test123-tools-boot{boot_epoch}-prearm-resume"),
        }
        helper = SimpleNamespace(
            PrearmResumeError=type("PrearmResumeError", (ValueError,), {}),
            verify_prearm_resume=mock.Mock(return_value=bad_verification),
            claim_prearm_resume=mock.Mock(),
        )
        with (
            mock.patch.object(COORD, "_configure_test123_run"),
            mock.patch.object(COORD.T120, "_load_current_identity",
                              return_value=(boot_epoch, uuid)),
            mock.patch.object(COORD.BINDING, "validate_kernel_bundle",
                              return_value=({"minimum_boot_epoch_exclusive": boot_epoch - 1},
                                            {"mach_o_uuid": uuid}, b"", Path("meta"))),
            mock.patch.object(COORD, "_load", return_value=helper),
            mock.patch.object(COORD.RUNNER, "run_once") as run_once,
        ):
            with self.assertRaises(COORD.BINDING.Tool123BindingError) as caught:
                COORD._run_once(
                    host="root@192.0.2.1", control_path="/private/tmp/mock.sock",
                    metadata=COORD.BINDING.KERNEL_METADATA, ap="wlan7",
                    resume_prearm=True)
        self.assertEqual(caught.exception.args[0],
                         "test123_prearm_resume_binding_mismatch")
        run_once.assert_not_called()
        helper.claim_prearm_resume.assert_not_called()


if __name__ == "__main__":
    unittest.main()
