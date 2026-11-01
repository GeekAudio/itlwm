#!/usr/bin/env python3
"""Focused offline tests for the Test102 coordinator integration."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest import mock

import controlled_run_test102 as run
import packetset_test102 as packetset
import sender_protocol_test102 as sender_protocol


class Test102ControlledRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test102-offline-")
        self.addCleanup(self.tmp.cleanup)
        self.temp_root = Path(self.tmp.name)
        self.iwn_root = self.temp_root / "IWN"
        self.iwn_root.mkdir(mode=0o700)
        prep = self.iwn_root / "research/test102-preparation-private"
        prep.mkdir(mode=0o700, parents=True)
        self.saved = {
            name: getattr(run, name) for name in (
                "IWN_ROOT", "DEFAULT_METADATA", "BUILD_RECEIPT",
                "DEPLOYMENT_RECEIPT", "SENDER_BUILD_RECEIPT", "SENDER_BINARY",
                "SENDER_SHA256", "EXPECTED_SENDER_SOURCE_SHA256",
                "EXPECTED_SENDER_BINARY_SHA256", "ROUTER_SOURCE_RECEIPT",
                "TARGET_IDENTITY_RECEIPT", "ACTIVE_PACKET_SET",
                "ACTIVE_PACKET_MANIFEST", "ACTIVE_LISTENER_EXPECTATION")}
        self.addCleanup(self._restore_globals)
        self.account = pwd.getpwuid(run.REPO.stat().st_uid)
        self.binary = run.REPO / "developer-tools/test102/build/awdl_unicast_sender_test102-aarch64-linux-musl"
        self.source_sha = run.sha256(run.SENDER_SOURCE)
        self.binary_sha = run.sha256(self.binary)
        self.sender_receipt = prep / "sender-build-private.json"
        self._write_private(self.sender_receipt, {
            "candidate": run.CANDIDATE,
            "status": "built_offline",
            "target": run.SENDER_TARGET,
            "source_path": str(run.SENDER_SOURCE.relative_to(run.REPO)),
            "source_sha256": self.source_sha,
            "binary_path": str(self.binary.relative_to(run.REPO)),
            "binary_sha256": self.binary_sha,
            "provenance_schema": "test102-unicast-sender/v1",
            "command": ["zig", "cc", "-target", "aarch64-linux-musl"],
        })
        run.configure_runtime(self.iwn_root)

    def _restore_globals(self):
        for name, value in self.saved.items():
            setattr(run, name, value)
        run.ACTIVE_PACKET_SET = None

    def _write_private(self, path: Path, value: dict):
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(path, self.account.pw_uid, self.account.pw_gid)

    @staticmethod
    def _packet_fixture():
        source = {
            "mac": "02:11:22:33:44:55",
            "ipv6_link_local": "fe80::1122",
        }
        target = {
            "mac": "02:aa:bb:cc:dd:ee",
            "ipv6_link_local": "fe80::aabb",
        }
        raw, manifest = packetset.encode_packet_set(source, target, "offline-mock")
        return raw, manifest

    def test_sender_stop_reason_compatibility_maps_test102_names(self):
        restore = run.configure_test102_profile()
        try:
            base = {
                "event": "SENDER_RESULT", "status": "failed",
                "frames_attempted": 0, "frames_completed": 0, "sent": 0,
                "payload_bytes": 96, "mpdu_bytes": 96, "radiotap_bytes": 10,
                "packet_bytes": 106, "udp_payload_bytes": 8, "elapsed_ms": 0,
                "deadline_hit": False, "error_count": 1, "last_errno": 5,
                "tx_flags_requested": "NOSEQNO", "hardware_honoring": "unknown",
            }
            cases = {
                "schedule_wait_failed": "schedule_or_sleep_failed",
                "clock_before_failed": "monotonic_clock_unavailable",
                "clock_after_failed": "monotonic_clock_unavailable",
            }
            for raw_reason, expected in cases.items():
                value = {**base, "stop_reason": raw_reason}
                parsed = run.PROTOCOL.parse_sender_result(json.dumps(value))
                self.assertEqual(parsed["stop_reason"], expected)
        finally:
            restore()

    def test_run_binds_packet_set_before_coordinator_and_keeps_it_dynamic(self):
        packet_bytes, manifest = self._packet_fixture()
        build = {
            "candidate": run.CANDIDATE,
            "mach_o_uuid": "8907BD50-B8B3-32DD-BCC3-82C66CAD7BE1",
            "binary_sha256": "a" * 64,
        }
        deployment = {
            "candidate": run.CANDIDATE,
            "mach_o_uuid": build["mach_o_uuid"],
            "binary_sha256": build["binary_sha256"],
        }
        metadata = {
            "candidate": run.CANDIDATE,
            "expected_loaded_uuid": build["mach_o_uuid"],
            "minimum_boot_epoch_exclusive": 100,
            "profile": run.PROFILE,
            "armed": False,
            "status": "prepared_disarmed",
            "retry_allowed": False,
        }
        output_dir = self.temp_root / "run-output"
        metadata_path = self.temp_root / "runtime-private.json"
        metadata_path.write_text("{}", encoding="utf-8")

        router = {"fixture": "router-receipt"}
        target = {"fixture": "target-receipt", "ifindex": 31}
        receipt_bytes = json.dumps(router).encode("utf-8")
        observed = []
        listener_argv_seen = []
        real_read_private_json = run.read_private_json

        def fake_pipe(argv):
            listener_argv_seen.append(list(argv))
            return object()

        def private_receipt_for_run(path, owner_uid):
            if Path(path) == run.SENDER_BUILD_RECEIPT:
                return real_read_private_json(path, owner_uid)
            if Path(path) == run.ROUTER_SOURCE_RECEIPT:
                return router, receipt_bytes
            if Path(path) == run.TARGET_IDENTITY_RECEIPT:
                return target, b"target"
            raise AssertionError("unexpected private receipt path")

        def fake_coordinator(**kwargs):
            self.assertEqual(run.ACTIVE_PACKET_SET, packet_bytes)
            self.assertEqual(run.ACTIVE_PACKET_MANIFEST, manifest)
            self.assertEqual(run.BASE.LISTENER_SOURCE, run.LISTENER_SOURCE)
            run.BASE.ManagedPipe([
                "/private/tmp/awdl0_udp_probe_listener", "--listen", "T086RX01",
                "--run-token", "0123456789abcdef0123456789abcdef", "--recv-anyif"])
            self.assertEqual(listener_argv_seen[-1][-6:], [
                "--expected-source-ipv6", manifest["identities"]["source"]["ipv6_link_local"],
                "--expected-destination-ipv6",
                manifest["identities"]["destination_awdl0"]["ipv6_link_local"],
                "--expected-ifindex", "31"])
            observed.append("coordinator")
            # Exercise the actual packet-set remote-script adapter without SSH.
            script = run.PROTOCOL.build_remote_monitor_sender_script(
                binary=run.SENDER_BINARY.read_bytes(),
                binary_sha256=run.SENDER_SHA256,
                run_token="0123456789abcdef0123456789abcdef",
                ap="wlan7")
            result = run.REMOTE_SENDER.validate_remote_script(script)
            self.assertEqual(result["frames_max"], 4)
            self.assertIn(hashlib.sha256(packet_bytes).hexdigest(), script)
            output_dir.mkdir(mode=0o700)
            return {
                "complete": False,
                "status": "offline_mock_no_capture",
                "test088_sender": {"sender_result_event": None},
            }

        with mock.patch.object(run, "validate_deployment",
                               return_value=(build, deployment, b"build", b"deployment")), \
             mock.patch.object(run, "validate_runtime_metadata",
                               return_value=(metadata, {"status": "passed"},
                                             {"metadata_sha256": "b" * 64})), \
             mock.patch.object(run.RUNTIME_BINDING, "_read_boot_epoch", return_value=200), \
             mock.patch.object(run.RUNTIME_BINDING, "_run_text",
                               return_value="org.geekaudio.AirportItlwm (test) " + build["mach_o_uuid"]), \
             mock.patch.object(run.RUNTIME_BINDING, "_extract_loaded_uuid",
                               return_value=build["mach_o_uuid"]), \
             mock.patch.object(run, "read_private_json",
                               side_effect=private_receipt_for_run), \
             mock.patch.object(run.RUNTIME_BINDING, "bind_runtime_identities",
                               side_effect=lambda *a, **k: (packet_bytes, manifest)) as bind_mock, \
             mock.patch.object(run.START_BARRIER, "compile_reader",
                               side_effect=lambda d: self._fake_reader(d)), \
             mock.patch.object(run, "test102_run_dir", return_value=output_dir), \
             mock.patch.object(run.BASE, "ManagedPipe", side_effect=fake_pipe), \
             mock.patch.object(run.BASE, "_validate_bundle",
                               return_value=(metadata, build, "c" * 64, Path("build.json"))), \
             mock.patch.object(run.TEST088, "run_test088_once", side_effect=fake_coordinator):
            report, actual_output, _ = run.run_once(
                host="root@192.0.2.1", control_path="/private/tmp/mock.sock",
                metadata_path=metadata_path, ap="wlan7")

        self.assertEqual(observed, ["coordinator"])
        self.assertEqual(len(listener_argv_seen), 1)
        self.assertEqual(actual_output, output_dir)
        self.assertEqual(bind_mock.call_args.kwargs["expected_boot_epoch"], 200)
        self.assertEqual(bind_mock.call_args.kwargs["expected_uuid"], build["mach_o_uuid"])
        self.assertEqual(report["packet_set_binding"]["packet_set_sha256"],
                         hashlib.sha256(packet_bytes).hexdigest())
        self.assertEqual(report["listener_binding"]["awdl0_ifindex"], 31)
        self.assertEqual(report["listener_binding"]["schema"],
                         "test102-awdl-unicast-listener/v1")
        self.assertFalse(report["listener_binding"]["raw_addresses_serialized"])
        self.assertFalse(report["peer_receipt_proven"])
        self.assertFalse(report["native_awdl_reply_proven"])
        self.assertFalse(report["airdrop_proven"])
        self.assertEqual(run.ACTIVE_PACKET_SET, None)

    def _fake_reader(self, directory: Path) -> Path:
        path = Path(directory) / "mock-reader"
        path.write_bytes(b"offline reader fixture")
        path.chmod(0o700)
        return path


if __name__ == "__main__":
    unittest.main()
