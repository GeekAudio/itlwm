#!/usr/bin/env python3
"""Offline integration regressions for the Test123 profile adapter.

No router process, socket, RF operation, driver arm, EFI mutation, or network
configuration is involved. The fake sender start exercises the exact keyword
shape used by the frozen Test087 RouterSenderSession.start call.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
COORDINATOR_PATH = ROOT / "developer-tools/test123/coordinate_test123_rx149.py"
SPEC = importlib.util.spec_from_file_location(
    "test123_profile_independent_coordinator", COORDINATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("test123_coordinator_unavailable")
COORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COORD
SPEC.loader.exec_module(COORD)

BINDING = COORD.BINDING
RUNNER = COORD.RUNNER
NOW = dt.datetime(2026, 11, 3, 12, 0, 0, tzinfo=dt.timezone.utc)
UUID = "7B8174FD-0BFF-3A04-BC2F-B012FEB545C0"
NONCE = "1234567890abcdef"
RUN_TOKEN = "a" * 32
SOURCE_MAC = "02:11:22:33:44:55"
TARGET_MAC = "02:aa:bb:cc:dd:ee"
SOURCE_IP = "fe80::1122:3344:5566:7788"
TARGET_IP = "fe80::aabb:ccdd:eeff:1020"


def _canonical_sha(value: dict) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _metadata() -> dict:
    return {
        "candidate": BINDING.KERNEL_CANDIDATE,
        "expected_loaded_uuid": UUID,
        "status": "prepared_disarmed",
        "armed": False,
        "retry_allowed": False,
        "host_management_or_data_tx_allowed": False,
        "source_binding": {
            "expected_binary_sha256": "a" * 64,
            "build_receipt_sha256": "b" * 64,
        },
        "runtime_binding_test104": {"deployment_receipt_sha256": "c" * 64},
    }


def _router_receipt() -> dict:
    output = "\n".join((
        "Interface wlan7", "\tifindex 7", f"\taddr {SOURCE_MAC}",
        "\ttype AP", "\tchannel 149 (5745 MHz), width: 80 MHz",
        "phy#7", "7: wlan7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP",
        f"    inet6 {SOURCE_IP}/64 scope link", "IFACE=wlan7", SOURCE_MAC,
    ))
    return {"rc": 0, "scope": "read only iw dev and ip -6 addr",
            "stdout": output, "at": NOW.isoformat().replace("+00:00", "Z")}


def _target_receipt() -> dict:
    receipt = {
        "schema": "test104-target-identity/v1", "status": "readback_verified",
        "interface": "awdl0", "source": "live_ifconfig_ifindex_kmutil",
        "boot_epoch": 1_800_000_000,
        "minimum_boot_epoch_exclusive": 1_799_999_900,
        "candidate_uuid": UUID, "candidate": BINDING.KERNEL_CANDIDATE,
        "candidate_binary_sha256": "a" * 64,
        "build_receipt_sha256": "b" * 64,
        "deployment_receipt_sha256": "c" * 64,
        "evidence_sha256": "d" * 64,
        "ifindex": 31, "mac": TARGET_MAC, "ipv6_link_local": TARGET_IP,
        "interface_up": True,
        "captured_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    receipt["identity_receipt_sha256"] = _canonical_sha(receipt)
    return receipt


class Test123ProfileAdapterTests(unittest.TestCase):
    def setUp(self):
        BINDING.clear_active_run()
        COORD.SENDER_PROTOCOL.clear_packet_set_binding()
        self.restore_profile = lambda: None
        self.had_router_alias = hasattr(RUNNER, "ROUTER")
        self.old_router_alias = getattr(RUNNER, "ROUTER", None)
        RUNNER.ROUTER = RUNNER.TEST088.ROUTER
        runner_names = ("ACTIVE_PACKET_SET", "ACTIVE_PACKET_MANIFEST",
                        "ACTIVE_LISTENER_EXPECTATION", "LISTENER_BINARY",
                        "LISTENER_SHA256")
        self.runner_presence = {name: hasattr(RUNNER, name) for name in runner_names}
        self.old_runner_values = {name: getattr(RUNNER, name, None)
                                  for name in runner_names}
        self.sender_class = RUNNER.ROUTER.RouterSenderSession
        self.old_sender_start = self.sender_class.__dict__["start"]
        metadata = _metadata()
        router = _router_receipt()
        target = _target_receipt()
        _raw, manifest = BINDING.bind_runtime_identities(
            metadata, router, target,
            expected_boot_epoch=target["boot_epoch"], expected_uuid=UUID,
            router_receipt_sha256=_canonical_sha(router), now=NOW,
            wire_nonce_hex=NONCE, wifi_sequence_base=0x321,
            awdl_sequence_base=0x4567)
        raw, manifest = BINDING.validate_active_packetset()
        RUNNER.ACTIVE_PACKET_SET = raw
        RUNNER.ACTIVE_PACKET_MANIFEST = manifest
        RUNNER.ACTIVE_LISTENER_EXPECTATION = \
            COORD.LISTENER_PROTOCOL.expected_binding(manifest, 31)
        self.temp = tempfile.TemporaryDirectory(prefix="test123-profile-")
        self.private_root = Path(self.temp.name).resolve(strict=True)
        listener_binary = self.private_root / "listener-test-fixture"
        listener_binary.write_bytes(b"offline listener fixture")
        RUNNER.LISTENER_BINARY = listener_binary
        RUNNER.LISTENER_SHA256 = hashlib.sha256(listener_binary.read_bytes()).hexdigest()
        self.packet_root = self.private_root / "packetsets-private"
        self.ledger_root = self.private_root / "nonce-ledger-private"
        self.packet_root.mkdir(mode=0o700)
        self.ledger_root.mkdir(mode=0o700)

    def tearDown(self):
        self.restore_profile()
        self.sender_class.start = self.old_sender_start
        for name, value in self.old_runner_values.items():
            if self.runner_presence[name]:
                setattr(RUNNER, name, value)
            elif hasattr(RUNNER, name):
                delattr(RUNNER, name)
        if self.had_router_alias:
            RUNNER.ROUTER = self.old_router_alias
        else:
            delattr(RUNNER, "ROUTER")
        BINDING.clear_active_run()
        COORD.SENDER_PROTOCOL.clear_packet_set_binding()
        self.temp.cleanup()

    def test_frozen_start_keyword_shape_binds_packetset_and_parses_ready(self):
        """T087 passes binary/hash/token/AP, not a packet_set keyword."""
        self.result = None
        fake_binary = b"offline test sender bytes"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()
        protocol = RUNNER.PROTOCOL

        def fake_start(_cls, *, host, control_path, sender_binary,
                       sender_sha256, run_token, ap):
            # This is the frozen T087 builder call shape. No extra packet_set
            # parameter is supplied; the Test123 adapter must bind its active
            # validated packetset from the already-created run manifest.
            active_builder = protocol.build_remote_monitor_sender_script
            script = protocol.build_remote_monitor_sender_script(
                binary=fake_binary, binary_sha256=fake_sha,
                run_token=run_token, ap=ap)
            self.assertIs(protocol.build_remote_monitor_sender_script, active_builder)
            status_builder = sys.modules[
                "test123_frozen_test122_remote_builder_unpatched"]
            frozen_protocol = sys.modules[
                "test123_frozen_test087_base_remote_protocol"]
            self.assertIs(status_builder._load_router_protocol(), frozen_protocol)
            self.assertIsNot(frozen_protocol, protocol)
            ready_line = "READY " + " ".join(
                f"{key}={value}" for key, value in
                COORD.SENDER_PROTOCOL.READY_VALUES.items()) + (
                    " wire_nonce_hex=" + NONCE)
            ready = protocol.parse_sender_ready(ready_line)
            self.result = {"script": script, "ready": ready,
                           "host": host, "control_path": control_path,
                           "sender_binary": sender_binary,
                           "sender_sha256": sender_sha256}
            return SimpleNamespace(run_token=run_token), {}, ready

        self.sender_class.start = classmethod(fake_start)
        with mock.patch.object(BINDING, "PACKET_SET_ROOT", self.packet_root), \
             mock.patch.object(BINDING, "NONCE_LEDGER_ROOT", self.ledger_root):
            self.restore_profile = COORD._configure_test123_profile()
            session, _monitor_ready, sender_ready = self.sender_class.start(
                host="router.example", control_path="/private/tmp/control.sock",
                sender_binary=Path("/unused/offline-sender"),
                sender_sha256="e" * 64, run_token=RUN_TOKEN, ap="wlan7")

            self.assertEqual(session.run_token, RUN_TOKEN)
            self.assertEqual(sender_ready["wire_nonce_hex"], NONCE)
            self.assertTrue(sender_ready["send_started"] is False)
            packet_files = list(self.packet_root.glob("*.packetset"))
            claims = list(self.ledger_root.glob("*.json"))
            self.assertEqual(len(packet_files), 1)
            self.assertEqual(len(claims), 1)
            self.assertIn("packetset.bin", self.result["script"])
            self.assertEqual(BINDING.ACTIVE_PACKET_SET_PATH, packet_files[0])
            syntax = subprocess.run(
                ["/bin/sh", "-n"], input=self.result["script"], text=True,
                capture_output=True, check=False)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_raw_sender_provenance_is_bound_to_captured_session_token(self):
        fake_binary = b"offline test sender bytes"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()

        def fake_start(_cls, *, host, control_path, sender_binary,
                       sender_sha256, run_token, ap):
            session = type("OfflineSession", (), {"run_token": run_token})()
            return session, {}, {}

        self.sender_class.start = classmethod(fake_start)
        self.restore_profile = COORD._configure_test123_profile()
        self.sender_class.start(
            host="router.example", control_path="/private/tmp/control.sock",
            sender_binary=Path("/unused/offline-sender"),
            sender_sha256=fake_sha, run_token=RUN_TOKEN, ap="wlan7")
        with self.assertRaises(COORD.SENDER_PROTOCOL.SenderAdapterError):
            COORD.SENDER_PROTOCOL.classify_sender_result({"run_token": "b" * 32})

    def test_profile_restore_reinstates_original_callbacks(self):
        old = {
            "parse_sender_ready": RUNNER.PROTOCOL.parse_sender_ready,
            "parse_sender_result": RUNNER.PROTOCOL.parse_sender_result,
            "listener_ready": RUNNER.PROTOCOL.parse_listener_ready,
            "listener_result": RUNNER.PROTOCOL.parse_listener_result,
            "remote_builder": RUNNER.PROTOCOL.build_remote_monitor_sender_script,
            "sender_start": self.sender_class.__dict__["start"],
        }
        self.sender_class.start = classmethod(
            lambda _cls, **kwargs: (None, {}, {}))
        patched_sender_start = self.sender_class.__dict__["start"]
        self.restore_profile = COORD._configure_test123_profile()
        self.restore_profile()
        self.restore_profile = lambda: None
        self.assertIs(RUNNER.PROTOCOL.parse_sender_ready, old["parse_sender_ready"])
        self.assertIs(RUNNER.PROTOCOL.parse_sender_result, old["parse_sender_result"])
        self.assertIs(RUNNER.PROTOCOL.parse_listener_ready, old["listener_ready"])
        self.assertIs(RUNNER.PROTOCOL.parse_listener_result, old["listener_result"])
        self.assertIs(RUNNER.PROTOCOL.build_remote_monitor_sender_script,
                      old["remote_builder"])
        self.assertIs(self.sender_class.__dict__["start"], patched_sender_start)


if __name__ == "__main__":
    unittest.main()
