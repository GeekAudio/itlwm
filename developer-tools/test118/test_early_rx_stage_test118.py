#!/usr/bin/env python3
from __future__ import annotations

import plistlib
import struct
import unittest

import early_rx_stage_test118 as observer


def valid_capture_ledger() -> bytes:
    ledger = observer.HCMD
    from rx149_capture_attempts_test104 import (
        CAPACITY, HEADER_FIELDS, MAGIC, RECORD_FIELDS, WIRE_BYTES,
        WIRE_SCHEMA, WORD_COUNT,
    )
    header = [MAGIC, WIRE_SCHEMA, WORD_COUNT, CAPACITY, 0, 0, 0, 0, 1]
    words = header + [0] * (CAPACITY * len(RECORD_FIELDS))
    assert len(header) == len(HEADER_FIELDS)
    raw = struct.pack("<" + "Q" * WORD_COUNT, *words)
    assert len(raw) == WIRE_BYTES
    return raw


def counter_row(value: int) -> dict:
    return {key: value for key in observer.STAGE_COUNTERS}


def sample(value: int, *, generation: int = 7, schema: int = 2,
           active: int = 1) -> dict:
    return {
        "same_read_early_rx_stage_counters": counter_row(value),
        "early_rx_counter_snapshot": {
            "schema": "test118-early-rx-stage-sample/v2",
            "status": "complete",
            "same_ioreg_read_as_rx149_ledger": True,
            "owner_context": {
                "schema": schema, "owner_generation": generation,
                "owner_active": active, "valid": True,
                "valid_for_delta": schema == 2 and active == 1,
                "reason": None,
            },
        },
    }


class Test118EarlyRxStageTests(unittest.TestCase):
    def test_osdata_ledger_stays_with_test104_decoder_and_outside_stage_counters(self):
        capture_ledger = valid_capture_ledger()
        service = {
            "NativeHcmdRxTraceSchema": 1,
            observer.HCMD.CAPTURE_ATTEMPTS_PROPERTY: capture_ledger,
            "NativeP2PRxStageSchema": 2,
            "NativeP2PRxStageOwnerGeneration": 7,
            "NativeP2PRxStageOwnerActive": 1,
        }
        for index, key in enumerate(observer.STAGE_COUNTERS):
            service[key] = index
        calls = []

        def check_output(command, **_kwargs):
            calls.append(command)
            return plistlib.dumps([service])

        result = observer.sample_once(
            check_output=check_output, clock_ns=iter((10, 20)).__next__)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], [
            "/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"])
        self.assertNotIn(observer.HCMD.CAPTURE_ATTEMPTS_PROPERTY,
                         observer.STAGE_COUNTERS)
        self.assertEqual(result["rx149_capture_attempts"]["status"],
                         "stable_complete_cut")
        self.assertEqual(result["same_read_early_rx_stage_counters"], {
            key: index for index, key in enumerate(observer.STAGE_COUNTERS)
        })
        observation = result["early_rx_counter_snapshot"]
        self.assertTrue(observation["same_ioreg_read_as_rx149_ledger"])
        self.assertFalse(observation["firmware_atomic_snapshot_proven"])
        self.assertFalse(observation["frame_or_payload_delivery_proven"])

    def test_missing_or_boolean_scalar_is_unknown_not_zero(self):
        service = {key: 3 for key in observer.STAGE_COUNTERS}
        service[observer.STAGE_COUNTERS[0]] = True
        service[observer.STAGE_COUNTERS[1]] = None
        parsed = observer._counter_values(service)
        self.assertIsNone(parsed[observer.STAGE_COUNTERS[0]])
        self.assertIsNone(parsed[observer.STAGE_COUNTERS[1]])
        self.assertEqual(parsed[observer.STAGE_COUNTERS[2]], 3)

    def test_one_sample_is_incomplete_and_delta_is_none(self):
        result = observer.summarize([sample(4)])
        self.assertFalse(result["early_counter_coverage_complete"])
        self.assertEqual(result["early_counter_coverage_status"],
                         "incomplete_fewer_than_two_same_owner_samples")
        self.assertIsNone(result["counters"][observer.STAGE_COUNTERS[0]]
                          ["observed_delta"])
        self.assertEqual(result["counters"][observer.STAGE_COUNTERS[0]]
                         ["delta_status"],
                         "insufficient_same_owner_samples")

    def test_two_complete_same_active_owner_samples_have_delta(self):
        result = observer.summarize([sample(4), sample(9)])
        key = observer.STAGE_COUNTERS[0]
        self.assertTrue(result["early_counter_coverage_complete"])
        self.assertEqual(result["early_counter_coverage_status"],
                         "complete_same_active_owner_window")
        self.assertEqual(result["counters"][key]["observed_delta"], 5)
        self.assertFalse(result["firmware_atomic_snapshot_proven"])

    def test_owner_generation_change_never_produces_cross_owner_delta(self):
        result = observer.summarize([
            sample(2, generation=2), sample(9, generation=9)])
        key = observer.STAGE_COUNTERS[0]
        self.assertEqual(result["early_counter_coverage_status"],
                         "incomplete_multiple_owner_contexts")
        self.assertFalse(result["early_counter_coverage_complete"])
        self.assertIsNone(result["counters"][key]["observed_delta"])
        self.assertEqual(result["counters"][key]["delta_status"],
                         "multiple_owner_contexts_no_cross_owner_delta")
        self.assertEqual(len(result["owner_contexts"]), 2)
        self.assertTrue(all(
            context["counters"][key]["observed_delta"] is None
            for context in result["owner_contexts"]))

    def test_legacy_coverage_complete_does_not_imply_early_coverage(self):
        result = observer.summarize([{"coverage_complete": True}])
        self.assertEqual(result["early_counter_coverage_status"],
                         "unknown_no_early_samples")
        self.assertFalse(result["early_counter_coverage_complete"])
        self.assertIsNone(result["counters"][observer.STAGE_COUNTERS[0]]
                          ["observed_delta"])

    def test_inactive_owner_samples_do_not_produce_delta(self):
        result = observer.summarize([
            sample(4, active=0), sample(9, active=0)])
        self.assertFalse(result["early_counter_coverage_complete"])
        self.assertEqual(result["early_counter_coverage_status"],
                         "incomplete_no_valid_active_owner_samples")
        self.assertEqual(result["context_status_counts"]["owner_inactive"], 2)


if __name__ == "__main__":
    unittest.main()
