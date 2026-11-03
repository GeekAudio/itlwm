#!/usr/bin/env python3
"""Independent offline adversarial tests for the Tool123 wire binder.

These tests exercise the real Test123 binder and Test122 packet codec with
synthetic identity receipts. They never contact a router, open a socket, arm
the driver, or touch EFI.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BINDING_PATH = Path(__file__).resolve().parent / "rx149_binding_test123.py"
SPEC = importlib.util.spec_from_file_location(
    "test123_independent_binding_under_test", BINDING_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("test123_binding_unavailable")
BINDING = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BINDING
SPEC.loader.exec_module(BINDING)
PACKETSET = BINDING.PACKETSET

UUID = "7B8174FD-0BFF-3A04-BC2F-B012FEB545C0"
NOW = dt.datetime(2026, 11, 3, 12, 0, 0, tzinfo=dt.timezone.utc)
WIRE_NONCE = "1234567890abcdef"
SOURCE_MAC = "02:11:22:33:44:55"
TARGET_MAC = "02:aa:bb:cc:dd:ee"
SOURCE_IP = "fe80::1122:3344:5566:7788"
TARGET_IP = "fe80::aabb:ccdd:eeff:1020"


def _canonical_sha(value: dict) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _metadata(uuid: str = UUID) -> dict:
    return {
        "candidate": BINDING.KERNEL_CANDIDATE,
        "expected_loaded_uuid": uuid,
        "status": "prepared_disarmed",
        "armed": False,
        "retry_allowed": False,
        "host_management_or_data_tx_allowed": False,
        "source_binding": {
            "expected_binary_sha256": "a" * 64,
            "build_receipt_sha256": "b" * 64,
        },
        "runtime_binding_test104": {
            "deployment_receipt_sha256": "c" * 64,
        },
    }


def _router_receipt() -> dict:
    output = "\n".join((
        "Interface wlan7",
        "\tifindex 7",
        f"\taddr {SOURCE_MAC}",
        "\ttype AP",
        "\tchannel 149 (5745 MHz), width: 80 MHz",
        "phy#7",
        "7: wlan7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP",
        f"    inet6 {SOURCE_IP}/64 scope link",
        "IFACE=wlan7",
        SOURCE_MAC,
    ))
    return {
        "rc": 0,
        "scope": "read only iw dev and ip -6 addr",
        "stdout": output,
        "at": NOW.isoformat().replace("+00:00", "Z"),
    }


def _target_receipt(*, boot: int = 1_800_000_000,
                    uuid: str = UUID) -> dict:
    receipt = {
        "schema": "test104-target-identity/v1",
        "status": "readback_verified",
        "interface": "awdl0",
        "source": "live_ifconfig_ifindex_kmutil",
        "boot_epoch": boot,
        "minimum_boot_epoch_exclusive": boot - 100,
        "candidate_uuid": uuid,
        "candidate": BINDING.KERNEL_CANDIDATE,
        "candidate_binary_sha256": "a" * 64,
        "build_receipt_sha256": "b" * 64,
        "deployment_receipt_sha256": "c" * 64,
        "evidence_sha256": "d" * 64,
        "ifindex": 31,
        "mac": TARGET_MAC,
        "ipv6_link_local": TARGET_IP,
        "interface_up": True,
        "captured_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    receipt["identity_receipt_sha256"] = _canonical_sha(receipt)
    return receipt


class Tool123IndependentBindingTests(unittest.TestCase):
    def setUp(self):
        BINDING.clear_active_run()
        self.metadata = _metadata()
        self.router = _router_receipt()
        self.target = _target_receipt()
        self.router_sha = _canonical_sha(self.router)
        self.packet_bytes, self.manifest = BINDING.bind_runtime_identities(
            self.metadata, self.router, self.target,
            expected_boot_epoch=self.target["boot_epoch"],
            expected_uuid=UUID, router_receipt_sha256=self.router_sha,
            now=NOW, wire_nonce_hex=WIRE_NONCE,
            wifi_sequence_base=0x321, awdl_sequence_base=0x4567)

    def tearDown(self):
        BINDING.clear_active_run()

    def test_mutated_manifest_identity_cannot_override_packet_bytes(self):
        BINDING.ACTIVE_PACKET_MANIFEST["identities"]["destination_awdl0"]["mac"] = (
            "02:aa:bb:cc:dd:ef")
        with self.assertRaises(BINDING.Tool123BindingError):
            BINDING.validate_active_packetset()

    def test_mutated_manifest_sequence_cannot_override_packet_bytes(self):
        row = BINDING.ACTIVE_PACKET_MANIFEST["frames"][0]
        row["sequence_control"] ^= 0x10
        with self.assertRaises(BINDING.Tool123BindingError):
            BINDING.validate_active_packetset()

    def test_target_receipt_from_another_boot_is_rejected(self):
        stale = _target_receipt(boot=self.target["boot_epoch"] - 1)
        with self.assertRaisesRegex(
                BINDING.Tool123BindingError,
                "test122_runtime_identity_rejected"):
            BINDING.bind_runtime_identities(
                self.metadata, self.router, stale,
                expected_boot_epoch=self.target["boot_epoch"],
                expected_uuid=UUID, router_receipt_sha256=self.router_sha,
                now=NOW, wire_nonce_hex="2234567890abcdef",
                wifi_sequence_base=0x321, awdl_sequence_base=0x4567)

    def test_target_receipt_for_another_uuid_is_rejected(self):
        wrong_uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        mismatched = _target_receipt(uuid=wrong_uuid)
        with self.assertRaisesRegex(
                BINDING.Tool123BindingError,
                "test122_runtime_identity_rejected"):
            BINDING.bind_runtime_identities(
                self.metadata, self.router, mismatched,
                expected_boot_epoch=self.target["boot_epoch"],
                expected_uuid=UUID, router_receipt_sha256=self.router_sha,
                now=NOW, wire_nonce_hex="3234567890abcdef",
                wifi_sequence_base=0x321, awdl_sequence_base=0x4567)

    def test_packet_file_and_nonce_claim_are_private_and_nonreusable(self):
        with tempfile.TemporaryDirectory(prefix="test123-binding-") as temp:
            # Resolve macOS /var/folders aliases so private-path checks see
            # the canonical filesystem path rather than its symlinked alias.
            root = Path(temp).resolve(strict=True)
            packet_root = root / "packetsets-private"
            ledger_root = root / "wire-nonce-claims-private"
            with mock.patch.object(BINDING, "PACKET_SET_ROOT", packet_root), \
                 mock.patch.object(BINDING, "NONCE_LEDGER_ROOT", ledger_root):
                packet_path, claim_path = BINDING.write_packetset_for_run(
                    "1" * 32)
                persisted = packet_path.read_bytes()
                self.assertEqual(persisted, self.packet_bytes)
                self.assertEqual(hashlib.sha256(persisted).hexdigest(),
                                 self.manifest["packet_set_sha256"])
                self.assertEqual(packet_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(claim_path.stat().st_mode & 0o777, 0o600)
                claim = json.loads(claim_path.read_text())
                self.assertEqual(claim["wire_nonce_hex"], WIRE_NONCE)
                self.assertEqual(claim["packet_set_sha256"],
                                 self.manifest["packet_set_sha256"])
                with self.assertRaises(BINDING.Tool123BindingError):
                    BINDING.write_packetset_for_run("2" * 32)
                with self.assertRaises(Exception):
                    BINDING._status_tool().claim_wire_nonce(
                        ledger_root, WIRE_NONCE,
                        self.manifest["packet_set_sha256"], "3" * 32)

    def test_packetset_claim_keeps_tool_and_kernel_versions_distinct(self):
        raw, manifest = BINDING.validate_active_packetset()
        decoded = PACKETSET.decode_packet_set(raw)
        self.assertEqual(manifest["tool_id"], "Tool123")
        self.assertEqual(manifest["tool_test"], "Test123")
        self.assertEqual(manifest["running_kernel_test"], "Test122")
        self.assertEqual(decoded["schema"], "test122-correlated-packet-set/v2")
        self.assertFalse(manifest["distinct_received_ordinals_proven"])
        self.assertEqual(decoded["frames"][0]["sequence_control"],
                         manifest["frames"][0]["sequence_control"])
        self.assertEqual(decoded["frames"][0]["awdl_sequence"],
                         manifest["frames"][0]["awdl_sequence"])

    def test_failed_component_import_does_not_leave_partial_module(self):
        module_name = "test123_expected_import_failure_probe"
        with tempfile.TemporaryDirectory(prefix="test123-import-") as temp:
            source = Path(temp) / "broken_component.py"
            source.write_text("raise RuntimeError('intentional offline probe')\n")
            sys.modules.pop(module_name, None)
            with self.assertRaisesRegex(RuntimeError, "intentional offline probe"):
                BINDING._load(module_name, source)
            self.assertNotIn(module_name, sys.modules)


if __name__ == "__main__":
    unittest.main()
