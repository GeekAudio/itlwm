#!/usr/bin/env python3
"""Offline identity-binding tests for Test102."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import unittest

import runtime_binding_test102 as runtime


class RuntimeBindingTests(unittest.TestCase):
    now = dt.datetime(2026, 11, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    boot = 200
    uuid = "8907BD50-B8B3-32DD-BCC3-82C66CAD7BE1"
    binary_sha = "a" * 64
    build_sha = "b" * 64
    deployment_sha = "c" * 64

    def _router_receipt(self, captured_at=None):
        stdout = """phy#0
\tInterface wlan7
\t\tifindex 17
\t\twdev 0x1
\t\taddr 02:11:22:33:44:55
\t\ttype AP
\t\tchannel 149 (5745 MHz), width: 80 MHz, center1: 5775 MHz
17: wlan7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::1122/64 scope link
IFACE=wlan7
02:11:22:33:44:55
"""
        return {
            "rc": 0,
            "scope": "read only iw dev and ip -6 addr",
            "at": captured_at or self.now.isoformat(),
            "stdout": stdout,
        }

    def _target_receipt(self, *, captured_at=None, minimum_boot=100):
        record = {
            "schema": "test102-target-identity/v1",
            "status": "readback_verified",
            "captured_at": captured_at or self.now.isoformat(),
            "boot_epoch": self.boot,
            "minimum_boot_epoch_exclusive": minimum_boot,
            "interface": "awdl0",
            "ifindex": 31,
            "mac": "02:aa:bb:cc:dd:ee",
            "ipv6_link_local": "fe80::aabb",
            "interface_up": True,
            "candidate": runtime.CANDIDATE,
            "candidate_uuid": self.uuid,
            "candidate_binary_sha256": self.binary_sha,
            "build_receipt_sha256": self.build_sha,
            "deployment_receipt_sha256": self.deployment_sha,
            "source": "live_ifconfig_ifindex_kmutil",
            "evidence_sha256": "d" * 64,
        }
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        record["identity_receipt_sha256"] = hashlib.sha256(canonical).hexdigest()
        return record

    def _metadata(self, minimum_boot=100):
        return {
            "schema": runtime.METADATA_SCHEMA,
            "status": "prepared_disarmed",
            "armed": False,
            "candidate": runtime.CANDIDATE,
            "expected_loaded_uuid": self.uuid,
            "minimum_boot_epoch_exclusive": minimum_boot,
            "source_binding": {
                "expected_binary_sha256": self.binary_sha,
                "build_receipt_sha256": self.build_sha,
            },
            "runtime_binding_test102": {
                "schema": runtime.RUNTIME_BINDING_SCHEMA,
                "candidate": runtime.CANDIDATE,
                "build_receipt_sha256": self.build_sha,
                "deployment_receipt_sha256": self.deployment_sha,
            },
        }

    def test_fresh_receipts_bind_dynamic_awdl_destination(self):
        raw, manifest = runtime.bind_runtime_identities(
            self._metadata(), self._router_receipt(), self._target_receipt(),
            expected_boot_epoch=self.boot, expected_uuid=self.uuid,
            router_receipt_sha256="e" * 64, now=self.now)
        checked = runtime.packetset.validate_packet_set(raw)
        self.assertEqual(len(raw), runtime.packetset.PACKET_SET_LEN)
        self.assertEqual(checked["frame_count"], 4)
        self.assertEqual(checked["source"]["mac"], "02:11:22:33:44:55")
        self.assertEqual(checked["destination_awdl0"]["mac"], "02:aa:bb:cc:dd:ee")
        self.assertEqual(manifest["identity_freshness"]["current_boot_match"], True)
        self.assertEqual(manifest["identity_freshness"]["candidate_uuid_match"], True)
        self.assertFalse(manifest["evidence"]["rf_transmission_proven"])

    def test_stale_or_wrong_boot_receipts_fail_closed(self):
        with self.assertRaisesRegex(runtime.RuntimeBindingError,
                                    "router_source_identity_stale"):
            runtime.bind_runtime_identities(
                self._metadata(), self._router_receipt(
                    (self.now - dt.timedelta(seconds=181)).isoformat()),
                self._target_receipt(), expected_boot_epoch=self.boot,
                expected_uuid=self.uuid, router_receipt_sha256="e" * 64,
                now=self.now)
        with self.assertRaisesRegex(runtime.RuntimeBindingError,
                                    "target_awdl0_receipt_binding_mismatch"):
            runtime.bind_runtime_identities(
                self._metadata(), self._router_receipt(),
                self._target_receipt(minimum_boot=99),
                expected_boot_epoch=self.boot, expected_uuid=self.uuid,
                router_receipt_sha256="e" * 64, now=self.now)


if __name__ == "__main__":
    unittest.main()
