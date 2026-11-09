#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline two-packet terminal contract and shared-runner adapter tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest

import coordinate_directed_test130 as tool
import coordinate_test111 as shared

TOKEN = "12" * 16
IDENTITY = {
    "run_token": TOKEN,
    "nonces": ["34" * 8, "56" * 8],
    "local_mac": "02:00:00:00:00:01",
    "peer_mac": "02:00:00:00:00:02",
    "local_ipv6": "fe80::1",
    "peer_ipv6": "fe80::2",
}


def exact(slot: int, *, ticket: int = 900, snapshot: int = 2,
          packet_serial: int | None = None, doorbell: int | None = None,
          capture: int | None = None, input_us: int | None = None,
          owner: int = 11, run: int = 13, ifindex: int = 4,
          incarnation: int = 17, context: int = 3, power: int = 5,
          station: int = 7, roc: int = 9) -> dict:
    bell = doorbell if doorbell is not None else (100 if slot == 0 else 140)
    return {
        "ticket_serial": ticket,
        "snapshot_sequence": snapshot,
        "packet_serial": packet_serial if packet_serial is not None else 100 + slot,
        "slot": slot,
        "owner_serial": owner,
        "run_serial": run,
        "ifindex": ifindex,
        "interface_incarnation": incarnation,
        "context_generation": context,
        "power_generation": power,
        "station_generation": station,
        "roc_generation": roc,
        "doorbell_us": bell,
        "capture_us": capture if capture is not None else bell + 1,
        "input_us": input_us if input_us is not None else bell + 3,
        "captured": True,
        "delivered": True,
        "valid": True,
    }


def packet(slot: int, *, nonce: str | None = None, packet_serial: int | None = None,
           descriptor: int | None = None, wifi: int | None = None,
           awdl: int | None = None, ssn: int | None = None,
           doorbell: int | None = None, tx_rsp: int | None = None,
           exact_receipt: dict | None = None, owner: int = 11, run: int = 13,
           ifindex: int = 4, incarnation: int = 17, context: int = 3,
           power: int = 5, station: int = 7, roc: int = 9,
           deadline: int = 200) -> dict:
    bell = doorbell if doorbell is not None else (100 if slot == 0 else 140)
    serial = packet_serial if packet_serial is not None else 100 + slot
    return {
        "present": True,
        "slot": slot,
        "packet_serial": serial,
        "nonce": nonce or IDENTITY["nonces"][slot],
        "wifi_sequence": wifi if wifi is not None else 0x210 + slot,
        "awdl_sequence": awdl if awdl is not None else 0x310 + slot,
        "descriptor_index": descriptor if descriptor is not None else slot,
        "ssn": ssn if ssn is not None else 20 + slot,
        "owner_serial": owner,
        "run_serial": run,
        "ifindex": ifindex,
        "interface_incarnation": incarnation,
        "context_generation": context,
        "power_generation": power,
        "station_generation": station,
        "roc_generation": roc,
        "deadline_us": deadline,
        "doorbell_us": bell,
        "tx_rsp_seen": True,
        "tx_rsp_success": True,
        "tx_rsp_us": tx_rsp if tx_rsp is not None else bell + 10,
        "origin_doorbell_recorded": True,
        "origin_completion_recorded": True,
        "resources_absent": True,
        "exact_reply": exact_receipt or exact(slot, packet_serial=serial,
            doorbell=bell, owner=owner, run=run, ifindex=ifindex,
            incarnation=incarnation, context=context, power=power,
            station=station, roc=roc),
    }


def peer_packet(slot: int, *, nonce: str | None = None, result: str = "local_send_succeeded",
                matches: int = 1, duplicates: int = 0, out_of_order: int = 0) -> dict:
    return {
        "slot": slot,
        "nonce": nonce or IDENTITY["nonces"][slot],
        "matched_requests": matches,
        "duplicate_requests": duplicates,
        "out_of_order_matches": out_of_order,
        "reply_attempted": True,
        "reply_result": result,
        "reply_wifi_sequence": 0x110 + slot,
        "reply_awdl_sequence": 0x110 + slot,
    }


def evidence() -> tuple[dict, dict]:
    helper = {
        "packet_count": 2,
        "native_udp_attempted": True,
        "native_udp_bytes": [8, 8],
        "peer_socket_matched": [True, True],
        "tx_completion_observed": [True, True],
        "firmware_attempt_succeeded": [True, True],
        "ifnet_delivery_proven": [True, True],
        "packet_receipts": [packet(0), packet(1)],
        "automatic_retry_allowed": False,
        "cleanup_ack": True,
        "run_resources_absent": True,
        "outer_release_accepted": True,
        "terminal_gate_accepted": True,
        "peer_receipt_proven": False,
        "radio_ack_proven": False,
        "airdrop_proven": False,
    }
    peer = {
        "schema": "test130-openwrt-echo-peer/v1",
        "event": "RESULT",
        "run_token": TOKEN,
        "packet_count": 2,
        "packets": [peer_packet(0), peer_packet(1)],
        "automatic_retry": False,
        "over_air_delivery_proven": False,
        "airdrop_proven": False,
    }
    return helper, peer


class Test130CoordinatorContracts(unittest.TestCase):
    def gate(self, mutate_helper=None, mutate_peer=None, identity=None):
        helper, peer = evidence()
        if mutate_helper:
            mutate_helper(helper)
        if mutate_peer:
            mutate_peer(peer)
        return tool._packet_gate(helper, peer, identity or IDENTITY, 200)

    def test_complete_two_packet_exchange_passes(self):
        outcome = self.gate()
        self.assertTrue(outcome["accepted"], outcome["failures"])
        self.assertEqual(outcome["packet_count"], 2)
        self.assertFalse(outcome["airdrop_proven"])

    def test_no_scalar_latest_receipt_can_replace_both_slots(self):
        outcome = self.gate(lambda h: h.update(packet_receipts=[packet(1)]))
        self.assertFalse(outcome["accepted"])
        self.assertIn("two_independent_helper_packet_receipts", outcome["failures"])

    def test_packet_two_requires_both_first_tx_completion_and_exact_return(self):
        outcome = self.gate(lambda h: h["packet_receipts"][0].update(tx_rsp_us=145))
        self.assertFalse(outcome["accepted"])
        self.assertIn("packet2_after_first_tx_completion", outcome["failures"])

    def test_both_packets_share_one_nonzero_ticket(self):
        outcome = self.gate(lambda h: h["packet_receipts"][1]["exact_reply"].update(ticket_serial=901))
        self.assertFalse(outcome["accepted"])
        self.assertIn("same_nonzero_ticket_serial", outcome["failures"])

    def test_even_exact_receipt_snapshot_and_unique_descriptor(self):
        cases = (
            (lambda h: h["packet_receipts"][1]["exact_reply"].update(snapshot_sequence=3),
             "packet1_exact_same_session"),
            (lambda h: h["packet_receipts"][1].update(descriptor_index=0),
             "unique_serial_descriptor_sequences_and_ssn"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                outcome = self.gate(mutate)
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_peer_must_report_two_distinct_single_local_sends(self):
        cases = (
            (lambda p: p.update(packets=[peer_packet(0), peer_packet(1, result="local_send_failed")]),
             "peer_packet1_single_ordered_reply"),
            (lambda p: p.update(automatic_retry=True), "no_automatic_retry"),
            (lambda p: p.update(packets=[peer_packet(0), peer_packet(1, matches=2)]),
             "peer_packet1_single_ordered_reply"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                outcome = self.gate(mutate_peer=mutate)
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_unproven_airdrop_and_radio_ack_cannot_be_promoted(self):
        outcome = self.gate(lambda h: h.update(airdrop_proven=True))
        self.assertFalse(outcome["accepted"])
        self.assertIn("unproven_air_over_air_and_airdrop_remain_false", outcome["failures"])

    def test_shared_runner_uses_test130_nonce_and_remote_contract(self):
        with tempfile.TemporaryDirectory(prefix="test130-runner-contract-") as temp:
            root = Path(temp)
            helper = root / "arm_directed_data130"
            script = root / "openwrt_monitor_window130.sh"
            peer = root / "openwrt_echo130"
            for path in (helper, script, peer):
                path.write_bytes(path.name.encode())
            sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            run_dir = root / ("run-" + TOKEN)
            config = {
                "ssh_target": "root@192.168.5.1",
                "ssh_socket": str(root / "test.sock"),
                "remote_dir": "/tmp/iw111echo-" + TOKEN,
                "output_dir": str(run_dir),
                "expected_boot": 1794202067,
                "expected_uuid": "00000000-0000-4000-8000-000000000130",
                "expected_build": tool.BUILD,
                "expected_reset_count": 0,
                "helper_path": str(helper), "helper_sha256": sha(helper),
                "helper_source_path": str(helper), "helper_source_sha256": sha(helper),
                "remote_script_path": str(script), "remote_script_sha256": sha(script),
                "peer_binary_path": str(peer), "peer_sha256": sha(peer),
                "prepare_peer_mac_required": True,
                "identity": IDENTITY,
            }
            normalized, _ = shared.validate_config(config, build_id=tool.BUILD)
            self.assertEqual(normalized["identity"]["nonce"], IDENTITY["nonces"][0])
            self.assertEqual(normalized["identity"]["nonce2"], IDENTITY["nonces"][1])
            self.assertEqual(normalized["remote_script_remote_path"],
                             config["remote_dir"] + "/monitor_window130.sh")
            self.assertEqual(normalized["peer_binary_remote_path"],
                             config["remote_dir"] + "/openwrt_echo130")
            remote = shared._peer_remote_args(normalized)
            self.assertIn("--packet-count", remote)
            self.assertIn("--nonce-2", remote)
            self.assertEqual(remote[remote.index("--nonce-2") + 1], IDENTITY["nonces"][1])
            helper_args = shared._helper_argv(normalized, root / "ready.json")
            self.assertIn("--nonce-2", helper_args)
            self.assertEqual(helper_args[helper_args.index("--nonce-2") + 1],
                             IDENTITY["nonces"][1])


if __name__ == "__main__":
    unittest.main()
