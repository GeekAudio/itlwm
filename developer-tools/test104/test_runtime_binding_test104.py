#!/usr/bin/env python3
"""Offline identity-binding tests for Test104."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import runtime_binding_test104 as runtime


class RuntimeBindingTests(unittest.TestCase):
    now = dt.datetime(2026, 11, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    boot = 200
    uuid = "F3B0C8AA-3377-49E0-8A8A-024E7A8E1033"
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
            "schema": "test104-target-identity/v1",
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
            "runtime_binding_test104": {
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

    def test_disarmed_metadata_builder_and_prearm_pin_unicast_listener(self):
        with tempfile.TemporaryDirectory(prefix="test104-metadata-prearm-") as temp:
            root = Path(temp)
            build_path = root / "build.json"
            baseline_path = root / "baseline.json"
            build_path.write_text("{}", encoding="utf-8")
            baseline_path.write_text("{}", encoding="utf-8")
            uuid = "F3B0C8AA-3377-49E0-8A8A-024E7A8E1033"
            build = {
                "candidate": runtime.CANDIDATE, "status": "built_offline",
                "installed": False, "rf_tested": False,
                "mach_o_uuid": uuid, "binary_sha256": "a" * 64,
                "baseline": "Test103", "rx149_data_input_contract": {},
            }
            build_raw = json.dumps(build, sort_keys=True).encode()
            baseline = {"candidate": "Test103"}
            baseline_raw = json.dumps(baseline, sort_keys=True).encode()
            deployment = {
                "candidate": runtime.CANDIDATE,
                "status": "deployed_waiting_reboot_disarmed",
                "automatic_reboot": False, "mach_o_uuid": uuid,
                "binary_sha256": build["binary_sha256"],
                "build_report_sha256": hashlib.sha256(build_raw).hexdigest(),
            }
            deployment_raw = json.dumps(deployment, sort_keys=True).encode()
            sender = {
                "candidate": runtime.CANDIDATE, "status": "built_offline",
                "target": "aarch64-linux-musl",
                "source_sha256": hashlib.sha256(runtime.SENDER_SOURCE.read_bytes()).hexdigest(),
                "binary_sha256": "b" * 64,
            }
            sender_raw = json.dumps(sender, sort_keys=True).encode()
            receipts = (build, deployment, sender, build_raw, deployment_raw, sender_raw)

            class CandidateBinding:
                @staticmethod
                def default_build_receipt_path(_root, _candidate):
                    return baseline_path

                @staticmethod
                def validate_metadata_binding(*_args, **_kwargs):
                    return []

                @staticmethod
                def runtime_private_root(iwn_root, _candidate):
                    return Path(iwn_root) / "runtime-private"

            metadata_seed = {
                "schema": runtime.METADATA_SCHEMA,
                "candidate": runtime.CANDIDATE, "baseline": "Test103",
                "source_ready_kind": "controlled_probe",
                "requires_phone_ready": False, "armed": False,
                "status": "prepared_disarmed", "retry_allowed": False,
                "expected_loaded_uuid": uuid, "profile": runtime.PROFILE,
                "minimum_boot_epoch_exclusive": 100,
                "host_management_or_data_tx_allowed": False,
                "source_binding": {
                    "expected_binary_sha256": build["binary_sha256"],
                    "build_receipt_sha256": hashlib.sha256(build_raw).hexdigest(),
                },
            }

            finalizer = SimpleNamespace(
                candidate_binding=CandidateBinding,
                validate_receipts=lambda **_kwargs: (
                    build, build_raw, baseline, baseline_raw),
                _paths=lambda _root, **_kwargs: (
                    root, build_path, baseline_path, root / "runtime-private"),
                build_metadata=lambda **_kwargs: dict(metadata_seed),
            )

            protocol = SimpleNamespace(
                HELPER_SOURCE=runtime.ARM_HELPER, SENDER_FRAMES=16,
                SENDER_INTERVAL_MS=80, FROZEN_METADATA_SENDER_INTERVAL_MS=80,
                SENDER_DEADLINE_SECONDS=2, SENDER_TX_FLAGS="NOACK|NOSEQNO",
            )
            metadata_path = root / "runtime-private" / "native-controlled-probe-private.json"
            metadata_path.parent.mkdir(mode=0o700, parents=True)

            def fake_coordinator(name, _path):
                if "finalizer" in name:
                    return finalizer
                return SimpleNamespace(
                    IWN_ROOT=None,
                    _modules=lambda: (protocol, None),
                    _validate_bundle=lambda path, _uid, _protocol: (
                        json.loads(Path(path).read_text(encoding="utf-8")),
                        build, hashlib.sha256(build_raw).hexdigest(), build_path),
                )

            with mock.patch.object(runtime, "_read_receipt_bundle", return_value=receipts), \
                 mock.patch.object(runtime, "_load_module", side_effect=fake_coordinator):
                metadata = runtime.build_disarmed_metadata(
                    iwn_root=root, minimum_boot_epoch_exclusive=100,
                    build_path=build_path)
                self.assertEqual(
                    metadata["runtime_binding_test104"]["listener_binding"]["schema"],
                    runtime.LISTENER_BINDING_SCHEMA)
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
                prearm = runtime.validate_prearm_bundle(metadata_path, iwn_root=root)
                self.assertFalse(prearm["armed"])
                self.assertFalse(prearm["claim_consumed"])
                metadata["runtime_binding_test104"]["listener_binding"][
                    "listener_source_sha256"] = "0" * 64
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
                with self.assertRaisesRegex(runtime.RuntimeBindingError,
                                            "test104_disarmed_metadata_binding_invalid"):
                    runtime.validate_prearm_bundle(metadata_path, iwn_root=root)
        with self.assertRaisesRegex(runtime.RuntimeBindingError,
                                    "target_awdl0_receipt_binding_mismatch"):
            runtime.bind_runtime_identities(
                self._metadata(), self._router_receipt(),
                self._target_receipt(minimum_boot=99),
                expected_boot_epoch=self.boot, expected_uuid=self.uuid,
                router_receipt_sha256="e" * 64, now=self.now)


if __name__ == "__main__":
    unittest.main()
