#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline exact-contract tests for the ordered Test130 OpenWrt receipt."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "test130_openwrt_echo_ready", ROOT / "test110/openwrt_echo_ready.py")
R = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = R
spec.loader.exec_module(R)


class ReadyContractTests(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "run_token": "12" * 16,
            "nonces": ["34" * 8, "56" * 8],
            "local_mac": "02:00:00:00:00:01",
            "peer_mac": "02:00:00:00:00:02",
            "local_ipv6": "fe80::1", "peer_ipv6": "fe80::2",
        }
        self.event = {
            "schema": R.TWO_PACKET_SCHEMA, "event": "READY",
            "run_token": self.identity["run_token"], "packet_count": 2,
            "local_mac": self.identity["local_mac"],
            "peer_mac": self.identity["peer_mac"],
            "local_ipv6": self.identity["local_ipv6"],
            "peer_ipv6": self.identity["peer_ipv6"],
            **R.TWO_PACKET_FIXED,
            "window_ms": 16000, "ifindex": 8,
            "monotonic_start_ns": 100,
            "monotonic_deadline_ns": 16000000100,
            "token_bytes_hex": self.identity["run_token"],
            "packets": [
                {"slot": slot, "nonce": nonce,
                 "run_token": self.identity["run_token"],
                 "local_mac": self.identity["local_mac"],
                 "peer_mac": self.identity["peer_mac"],
                 "local_ipv6": self.identity["local_ipv6"],
                 "peer_ipv6": self.identity["peer_ipv6"],
                 "reply_wifi_sequence": 0x110 + slot,
                 "reply_awdl_sequence": 0x110 + slot}
                for slot, nonce in enumerate(self.identity["nonces"])
            ],
        }

    def line(self):
        import json
        return (json.dumps(self.event, separators=(",", ":")) + "\n").encode()

    def test_two_exact_identities_and_private_ready_digest(self):
        value = R.validate_live_line_two_packet(self.line(), self.identity, 300)
        self.assertEqual(value["window_ms"], 15700)
        self.assertEqual([packet["nonce"] for packet in value["packets"]],
                         self.identity["nonces"])
        self.assertEqual(value["contract_identity_digest"],
                         R.two_packet_contract_digest(self.identity))
        self.assertEqual(len(value["router_ready_sha256"]), 64)

    def test_packet_order_nonce_and_identity_mismatches_rejected(self):
        cases = (
            lambda: self.event["packets"].reverse(),
            lambda: self.event["packets"][1].update(nonce=self.identity["nonces"][0]),
            lambda: self.event["packets"][1].update(slot=0),
            lambda: self.event["packets"][1].update(run_token="78" * 16),
            lambda: self.event["packets"][1].update(local_ipv6="fe80::3"),
            lambda: self.event["packets"][1].update(reply_wifi_sequence=0x110),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                event = copy.deepcopy(self.event)
                self.event = event
                mutate()
                with self.assertRaises(ValueError):
                    R.validate_live_line_two_packet(self.line(), self.identity, 1)
                self.setUp()

    def test_window_shape_and_expired_ready_rejected(self):
        for elapsed in (-1, 10000, 16000, True):
            with self.subTest(elapsed=elapsed), self.assertRaises(ValueError):
                R.validate_live_line_two_packet(self.line(), self.identity, elapsed)
        for key, value in (("channel", 149), ("packet_count", True),
                           ("window_ms", 16001),
                           ("monotonic_deadline_ns", 17000000100)):
            original = self.event[key]
            self.event[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                R.validate_live_line_two_packet(self.line(), self.identity, 1)
            self.event[key] = original

    def test_duplicate_json_keys_and_invalid_expected_contract_rejected(self):
        with self.assertRaises(ValueError):
            R.validate_live_line_two_packet(
                self.line().replace(b'{', b'{"event":"READY",', 1),
                self.identity, 1)
        invalid = copy.deepcopy(self.identity)
        invalid["nonces"][1] = invalid["nonces"][0]
        with self.assertRaises(ValueError):
            R.validate_live_line_two_packet(self.line(), invalid, 1)
        invalid = copy.deepcopy(self.identity)
        invalid["nonces"] = ["00" * 8, invalid["nonces"][1]]
        with self.assertRaises(ValueError):
            R.normalize_two_packet(invalid)


if __name__ == "__main__":
    unittest.main()
