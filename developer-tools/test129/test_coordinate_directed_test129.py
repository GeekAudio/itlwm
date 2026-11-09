#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline Test129 acceptance predicates; no device, SSH, peer or RF access."""
from __future__ import annotations

from copy import deepcopy
import unittest

import coordinate_directed_test129 as tool

UUID = "00000000-0000-4000-8000-000000000129"
TOKEN = "0123456789abcdef0123456789abcdef"
CONFIG = {"expected_boot": 1794202067, "expected_uuid": UUID,
          "identity": {"run_token": TOKEN}}


def evidence():
    helper = {
        "build": tool.BUILD,
        "expected_uuid": UUID,
        "run_token": TOKEN,
        "run_identity_matches": True,
        "arm_accepted": True,
        "native_udp_attempted": True,
        "native_udp_bytes": 8,
        "matched_peer_return_proven": True,
        "ifnet_delivery_proven": True,
        "tx_completion_observed": True,
        "firmware_attempt_succeeded": True,
        "outer_probe_release_accepted": True,
        "terminal_release_accepted": True,
        "peer_receipt_proven": False,
        "radio_ack_proven": False,
        "airdrop_proven": False,
        "diagnostics": {
            "Stage": 8, "Result": 0, "CompletionObserved": 1,
            "RawTxStatus": 1, "FirmwareAttemptSucceeded": 1,
            "CleanupAck": 1, "ResourcesAbsent": 1,
        },
        "outer_probe": {
            "attempted": 1, "state": 7, "remove_result": 0,
            "resource_may_exist": 0,
            "context_generation": 3, "power_generation": 5,
            "station_generation": 7,
            "frozen_context_generation": 3, "frozen_power_generation": 5,
            "frozen_station_generation": 7,
        },
    }
    before = {"boot": CONFIG["expected_boot"], "loaded_uuid_matches": True,
              "build": tool.BUILD}
    after = deepcopy(before)
    outer_after = {
        "NativeP2PProbeAttempted": 1,
        "NativeP2PProbeState": 7,
        "NativeP2PProbeRemoveResult": 0,
        "NativeP2PProbeResourceMayExist": 0,
        "NativeP2PProbeContextGeneration": 3,
        "NativeP2PProbePowerGeneration": 5,
        "NativeP2PProbeStationGeneration": 7,
    }
    return helper, before, after, outer_after


class Test129TerminalContract(unittest.TestCase):
    def check(self, mutate):
        helper, before, after, outer = evidence()
        mutate(helper, before, after, outer)
        return tool._terminal_gates(helper, before, after, outer, CONFIG)

    def test_complete_tx_return_and_outer_cleanup_pass_independently(self):
        helper, before, after, outer = evidence()
        outcome = tool._terminal_gates(helper, before, after, outer, CONFIG)
        self.assertTrue(outcome["accepted"], outcome["failures"])
        self.assertTrue(outcome["tx_completion_observed"])
        self.assertTrue(outcome["firmware_attempt_succeeded"])
        self.assertTrue(outcome["matched_peer_return_proven"])
        self.assertTrue(outcome["outer_probe_release_accepted"])

    def test_inner_stage8_cannot_substitute_for_outer_release(self):
        def quarantine_inner_and_outer(helper, before, after, outer):
            helper["outer_probe"].update(state=8, resource_may_exist=1)
            outer.update(NativeP2PProbeState=8, NativeP2PProbeRemoveResult=0,
                         NativeP2PProbeResourceMayExist=1)
        outcome = self.check(quarantine_inner_and_outer)
        self.assertFalse(outcome["accepted"])
        self.assertIn("helper_outer_state_matches", outcome["failures"])

    def test_outer_release_claim_must_be_bound_to_cleanup_and_generations(self):
        outcome = self.check(lambda h, b, a, o: h.update(
            outer_probe_release_accepted=False))
        self.assertFalse(outcome["accepted"])
        self.assertIn("helper_outer_probe_release_accepted", outcome["failures"])

    def test_tx_completion_firmware_success_and_return_are_separate_gates(self):
        cases = (
            (lambda h, b, a, o: h.update(tx_completion_observed=False),
             "tx_completion_observed"),
            (lambda h, b, a, o: h.update(firmware_attempt_succeeded=False),
             "firmware_attempt_succeeded"),
            (lambda h, b, a, o: h.update(matched_peer_return_proven=False),
             "matched_return_delivered_to_awdl0"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                outcome = self.check(mutate)
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_hostile_run_build_uuid_and_boot_changes_fail(self):
        cases = (
            (lambda h, b, a, o: h.update(run_token="f" * 32), "helper_run_token_matches"),
            (lambda h, b, a, o: h.update(build="25G416-Test128"), "helper_build_matches"),
            (lambda h, b, a, o: h.update(expected_uuid="f" * 36), "helper_uuid_matches"),
            (lambda h, b, a, o: a.update(boot=CONFIG["expected_boot"] + 1), "same_expected_boot"),
            (lambda h, b, a, o: a.update(loaded_uuid_matches=False), "loaded_kernel_uuid_matches"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                outcome = self.check(mutate)
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_every_outer_generation_is_bound_to_frozen_valid_lease(self):
        for key, expected in (
            ("NativeP2PProbeContextGeneration", "after_ioreg_context_generation_matches_helper"),
            ("NativeP2PProbePowerGeneration", "after_ioreg_power_generation_matches_helper"),
            ("NativeP2PProbeStationGeneration", "after_ioreg_station_generation_matches_helper"),
        ):
            with self.subTest(key=key):
                outcome = self.check(lambda h, b, a, o, field=key: o.update({field: 99}))
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_cleared_lease_or_outer_snapshot_cannot_be_mistaken_for_identity(self):
        cases = (
            (lambda h, b, a, o: h["outer_probe"].update(frozen_context_generation=0),
             "outer_context_generation_matches_frozen_rx_lease"),
            (lambda h, b, a, o: h["outer_probe"].update(frozen_power_generation=None),
             "outer_power_generation_matches_frozen_rx_lease"),
            (lambda h, b, a, o: o.update(NativeP2PProbeStationGeneration=0),
             "after_ioreg_station_generation_matches_helper"),
            (lambda h, b, a, o: o.pop("NativeP2PProbeContextGeneration"),
             "after_ioreg_context_generation_matches_helper"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                outcome = self.check(mutate)
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_outer_terminal_state_and_cleanup_ack_are_exact(self):
        cases = (
            (lambda h, b, a, o: h["outer_probe"].update(remove_result=1) or
                o.update(NativeP2PProbeRemoveResult=1), "helper_outer_remove_result_matches"),
            (lambda h, b, a, o: h["diagnostics"].update(CleanupAck=0),
             "inner_cleanup_ack_and_resources_absent"),
            (lambda h, b, a, o: h["diagnostics"].update(ResourcesAbsent=0),
             "inner_cleanup_ack_and_resources_absent"),
            (lambda h, b, a, o: h["outer_probe"].update(attempted=0) or
                o.update(NativeP2PProbeAttempted=0), "helper_outer_attempted_matches"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                outcome = self.check(mutate)
                self.assertFalse(outcome["accepted"])
                self.assertIn(expected, outcome["failures"])

    def test_ack_peer_receipt_and_airdrop_claims_must_remain_false(self):
        for key in ("radio_ack_proven", "peer_receipt_proven", "airdrop_proven"):
            with self.subTest(key=key):
                outcome = self.check(lambda h, b, a, o, field=key: h.update({field: True}))
                self.assertFalse(outcome["accepted"])
                self.assertIn("unproven_ack_peer_receipt_airdrop_remain_false",
                              outcome["failures"])


if __name__ == "__main__":
    unittest.main()
