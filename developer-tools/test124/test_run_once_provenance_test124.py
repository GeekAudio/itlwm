#!/usr/bin/env python3
"""Test124 regression for the real Test104-to-Test123 sender provenance path.

The test keeps the real Test123 packet encoder, Test104 ``run_once`` binding,
Test123 profile, T087 sender-session start, T088 result parser/timing report,
and Test104 post-run provenance classifier.  Only boot/receipt reads, the
native START barrier, router subprocess/pipe, and private output location are
replaced with deterministic offline fixtures.  No router, RF, EFI, or driver
operation is performed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
TEST123 = REPO / "developer-tools/test123"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test124_component_unavailable:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COORD = load("test124_coordinate_under_test",
             TEST123 / "coordinate_test123_rx149.py")
FIXTURES = load("test124_binding_identity_fixtures",
                TEST123 / "test_binding_independent_test123.py")
SENDER_FIXTURES = load("test124_sender_record_fixtures",
                       TEST123 / "router-status/test_dual_sender_protocol_test123.py")


class _Input:
    def __init__(self):
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, value):
        self.writes.append(value)
        return len(value)

    def flush(self):
        return None

    def close(self):
        self.closed = True


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


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _packetset_valid_line(nonce: str) -> str:
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
    return "MONITOR_READY " + " ".join(
        f"{key}={value}" for key, value in values.items())


def _ready_line(nonce: str) -> str:
    values = dict(COORD.SENDER_PROTOCOL.READY_VALUES)
    values["wire_nonce_hex"] = nonce
    return "READY " + " ".join(f"{key}={value}" for key, value in values.items())


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


def _cleanup_line(token: str) -> str:
    value = {
        "event": "MONITOR_CLEANUP", "run_token": token,
        "monitor_removed": True, "ap_unchanged": True,
        "temporary_files_removed": True,
    }
    return "CLEANUP " + json.dumps(value, sort_keys=True, separators=(",", ":"))


class Test124RunOnceProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Validate only the already-built private tool receipts.  No runtime
        # identity, network, kernel, or router operation is performed here.
        COORD._configure_test123_run()

    def setUp(self):
        COORD.BINDING.clear_active_run()
        COORD.SENDER_PROTOCOL.clear_packet_set_binding()

    def tearDown(self):
        COORD.BINDING.clear_active_run()
        COORD.SENDER_PROTOCOL.clear_packet_set_binding()

    def _run_real_t104_once(self, *, corrupt_sequence=False):
        runner = COORD.RUNNER
        uuid = FIXTURES.UUID
        boot_epoch = FIXTURES._target_receipt()["boot_epoch"]
        router_receipt = FIXTURES._router_receipt()
        target_receipt = FIXTURES._target_receipt()
        target_raw = _canonical(target_receipt)
        # read_private_json returns the bytes whose digest is bound by the
        # production Tool123 packet encoder.  For the source receipt, match
        # Test104's receipt digest contract exactly.
        router_raw = _canonical(router_receipt)
        router_receipt_sha = hashlib.sha256(router_raw).hexdigest()

        metadata = FIXTURES._metadata(uuid)
        metadata["minimum_boot_epoch_exclusive"] = boot_epoch - 100
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

        with tempfile.TemporaryDirectory(prefix="test124-t104-run-") as temp:
            temp_root = Path(temp)
            output_dir = temp_root / "output"
            run_lines: list[str] = []
            token = SENDER_FIXTURES.TOKEN
            original_read_private = runner.read_private_json

            def read_private(path, _owner_uid):
                if Path(path) == Path(runner.ROUTER_SOURCE_RECEIPT):
                    return router_receipt, router_raw
                if Path(path) == Path(runner.TARGET_IDENTITY_RECEIPT):
                    return target_receipt, target_raw
                return original_read_private(path, _owner_uid)

            def compile_reader(directory):
                path = Path(directory) / "test124-offline-start-reader"
                path.write_bytes(b"offline-reader-placeholder")
                return path

            def run_t088_boundary(**_kwargs):
                # T104 has just called the real Tool123 bind_runtime_identities
                # and assigned its exact return values to ACTIVE_PACKET_SET /
                # ACTIVE_PACKET_MANIFEST.  Do not substitute a decoder result
                # here: the regression is precisely about that handoff.
                raw_packetset = runner.ACTIVE_PACKET_SET
                construction_manifest = runner.ACTIVE_PACKET_MANIFEST
                self.assertIsInstance(raw_packetset, bytes)
                self.assertIsInstance(construction_manifest, dict)
                self.assertEqual(
                    construction_manifest["packet_set_sha256"],
                    hashlib.sha256(raw_packetset).hexdigest())
                self.assertNotIn("valid", construction_manifest)
                nonce = construction_manifest["wire_nonce_hex"]

                # Enter the real T123-wrapped T087 readiness path.  All
                # subprocess and pipe operations are in-memory fakes; the
                # sender binary itself is never executed.
                process = _Process(exit_code=0)
                selector = _Selector()
                lines = [
                    _packetset_valid_line(nonce), _monitor_ready_line(),
                    _ready_line(nonce), _started_line(token, nonce),
                ]
                result = SENDER_FIXTURES.sender_result(construction_manifest)
                result["run_token"] = token
                result["wire_nonce_hex"] = nonce
                if corrupt_sequence:
                    result["send_timing"][0]["ieee80211_sequence_control"] = (
                        result["send_timing"][0]["ieee80211_sequence_control"] ^ 0x10)
                lines.extend((json.dumps(result, sort_keys=True,
                                         separators=(",", ":")),
                              _cleanup_line(token)))
                run_lines.extend(lines)
                router = runner.ROUTER
                old_receipt = runner.TEST088._RunCapture.record_receipt
                try:
                    # Claiming a nonce and staging files are outside this
                    # offline regression; the protocol still binds the real
                    # in-memory bytes and digest before the fake READY event.
                    with (
                        mock.patch.object(COORD.BINDING, "write_packetset_for_run",
                                          return_value=(None, None)),
                        mock.patch.object(router, "_read_protocol_line",
                                          side_effect=lines),
                        mock.patch.object(router, "build_bootstrap_argv",
                                          return_value=["ssh", "offline-fake"]),
                        mock.patch.object(router.subprocess, "Popen",
                                          return_value=process),
                        mock.patch.object(router.selectors, "DefaultSelector",
                                          return_value=selector),
                        mock.patch.object(router, "_terminate_process") as terminate,
                        mock.patch.object(runner.TEST088._RunCapture,
                                          "record_receipt", return_value={}),
                    ):
                        session, _monitor, _ready = router.RouterSenderSession.start(
                            host="root@192.0.2.1",
                            control_path="/private/tmp/test124-offline.sock",
                            sender_binary=runner.SENDER_BINARY,
                            sender_sha256=runner.SENDER_SHA256,
                            run_token=token, ap="wlan7")
                        capture = runner.TEST088._RunCapture(runner.CANDIDATE)
                        completion = runner.TEST088.Test088SenderSession(
                            session, capture).go_once()
                        self.assertEqual(completion["sender_result"]["status"],
                                         "complete")
                        self.assertTrue(completion["cleanup"]["monitor_removed"])
                        self.assertEqual(process.stdin.writes[-1],
                                         f"GO {token}\n".encode("ascii"))
                        self.assertFalse(process.terminated)
                        terminate.assert_not_called()
                    report = capture.attach({})
                    # Force the exact same non-gating timing parser used by
                    # the production Test088 capture attachment and retain its
                    # summary for the test assertion.
                    run_lines.append(json.dumps(
                        report["test088_sender"]["timing"], sort_keys=True))
                    output_dir.mkdir(mode=0o700)
                    return report
                finally:
                    runner.TEST088._RunCapture.record_receipt = old_receipt

            def read_json(path):
                return json.loads(Path(path).read_text(encoding="utf-8"))

            old_test104_configure = COORD._ORIGINAL_TEST104_CONFIGURE
            try:
                with (
                    mock.patch.object(runner, "workspace_account",
                                      return_value=SimpleNamespace(
                                          pw_uid=runner.REPO.stat().st_uid,
                                          pw_gid=runner.REPO.stat().st_gid)),
                    mock.patch.object(runner, "validate_deployment",
                                      return_value=(build, deployment,
                                                    b"build-receipt", b"deploy-receipt")),
                    mock.patch.object(runner, "validate_runtime_metadata",
                                      return_value=(metadata,
                                                    {"status": "passed"},
                                                    {"metadata_sha256": "c" * 64})),
                    mock.patch.object(runner.RUNTIME_BINDING, "_read_boot_epoch",
                                      return_value=boot_epoch),
                    mock.patch.object(runner.RUNTIME_BINDING, "_run_text",
                                      return_value="loaded " + uuid),
                    mock.patch.object(runner.RUNTIME_BINDING, "_extract_loaded_uuid",
                                      return_value=uuid),
                    mock.patch.object(runner, "read_private_json", side_effect=read_private),
                    mock.patch.object(COORD.BINDING, "_validate_identity_freshness",
                                      return_value=(0, 0)),
                    mock.patch.object(COORD.BINDING.secrets, "token_hex",
                                      return_value=FIXTURES.WIRE_NONCE),
                    mock.patch.object(COORD.BINDING.secrets, "randbelow",
                                      side_effect=lambda _limit: 23),
                    mock.patch.object(runner.START_BARRIER, "compile_reader",
                                      side_effect=compile_reader),
                    mock.patch.object(runner, "test104_run_dir",
                                      return_value=output_dir),
                    mock.patch.object(runner.BASE, "_validate_bundle",
                                      return_value=(metadata, build, "d" * 64,
                                                    Path("build.json"))),
                    mock.patch.object(runner.START_BARRIER,
                                      "install_native_armed_go_barrier",
                                      return_value=lambda: None),
                    mock.patch.object(runner, "install_go_deadline_guard",
                                      return_value=lambda: None),
                    mock.patch.object(runner.TEST088, "run_test088_once",
                                      side_effect=run_t088_boundary),
                    mock.patch.object(COORD.BINDING.PACKETSET._test104,
                                      "parse_router_identity_receipt",
                                      wraps=COORD.BINDING.PACKETSET._test104.parse_router_identity_receipt),
                ):
                    # The real run_once calls the real T123 binder and then
                    # performs the T104 post-run provenance classification.
                    report, run_directory, _prearm = runner.run_once(
                        host="root@192.0.2.1",
                        control_path="/private/tmp/test124-offline.sock",
                        metadata_path=COORD.BINDING.KERNEL_METADATA,
                        ap="wlan7")
            finally:
                COORD._ORIGINAL_TEST104_CONFIGURE = old_test104_configure

            self.assertEqual(run_directory, output_dir)
            persisted = read_json(output_dir / runner.RESULT_NAME)
            return report, persisted, run_lines

    def test_actual_t104_run_once_uses_validated_wire_contract_for_timing_and_provenance(self):
        report, persisted, lines = self._run_real_t104_once()
        timing = report["test088_sender"]["timing"]
        self.assertEqual(timing.get("status"), "complete")
        self.assertEqual(timing.get("entry_count"), 4)
        self.assertEqual(report["openwrt_tx_provenance"].get("status"),
                         "local_sender_record_validated")
        self.assertTrue(persisted["sender_record_validated"])
        self.assertEqual(persisted["sender_record_status"], "complete")
        self.assertEqual(
            persisted["packet_set_binding"]["packet_set_sha256"],
            persisted["test123_packetset_verification"]["packet_set_sha256"])
        self.assertTrue(any('"status": "complete"' in line for line in lines))

    def test_actual_t104_run_once_rejects_sender_sequence_mismatch_without_claiming_proof(self):
        report, persisted, _lines = self._run_real_t104_once(corrupt_sequence=True)
        self.assertEqual(report["test088_sender"]["timing"]["status"],
                         "unknown_invalid_or_missing_timing")
        self.assertEqual(report["openwrt_tx_provenance"].get("status"), "unknown")
        self.assertFalse(persisted["sender_record_validated"])
        self.assertFalse(persisted["rf_transmission_proven"])
        self.assertFalse(persisted["peer_receipt_proven"])


if __name__ == "__main__":
    unittest.main()
