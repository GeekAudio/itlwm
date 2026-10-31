#!/usr/bin/env python3
"""Validate the pure runtime-evidence adapter with a synthetic timing fixture."""

import copy
import json
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import roc_rx_correlation_collect as collector
import roc_rx_correlation_runtime as runtime
from test_roc_rx_correlation_decode import fixture as property_fixture


FIXTURE_PATH = HERE / "fixtures/test095_runtime_close_marker.json"


def load_fixture():
    return json.loads(FIXTURE_PATH.read_text())


def adapt(fixture=None, *, binding=None, preowner=None, trace=None):
    fixture = fixture or load_fixture()
    return runtime.derive_closed_identity(
        fixture["binding"] if binding is None else binding,
        fixture["preownerCapture"] if preowner is None else preowner,
        fixture["traceSnapshot"] if trace is None else trace,
    )


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class RocCorrelationRuntimeTests(unittest.TestCase):
    def assert_unknown(self, result, reason):
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], reason)
        self.assertIsNone(result["marker"])
        self.assertIsNone(result["expected_identity"])

    def test_synthetic_timing_fixture_derives_expected_identity(self):
        result = adapt()
        self.assertEqual(result["status"], "verified_end_marker")
        self.assertIsNone(result["reason"])
        self.assertTrue(result["marker"]["closed"])
        self.assertTrue(result["marker"]["sameCaptureEpochVerified"])
        self.assertEqual(
            result["marker"]["evidenceSource"],
            "verified-preowner-stable3read+roc-trace-end")
        self.assertEqual(result["marker"]["traceSnapshotVersion"], 2)
        self.assertEqual(result["marker"]["preownerCloseReason"], "Explicit")
        self.assertEqual(result["expected_identity"], {
            "captureSerial": 101,
            "driverGeneration": 202,
            "contextGeneration": 303,
            "powerGeneration": 202,
            "stationGeneration": 404,
            "rocGeneration": 505,
            "sessionToken": 707,
            "armUs": 1479306056,
            "startUs": 1480037387,
            "deadlineUs": 1480137387,
        })
        self.assertEqual(result["marker"]["identity"],
                         result["expected_identity"])

    def test_public_fixture_uses_synthetic_identity_and_numeric_timing(self):
        fixture = load_fixture()
        self.assertEqual(fixture["provenance"]["kind"],
                         "synthetic_projection")
        self.assertEqual(fixture["provenance"]["timingSource"],
                         "Test095 monotonic timing values only")
        self.assertEqual(fixture["provenance"]["identityValues"], "synthetic")
        self.assertNotIn("sourceSha256", fixture["provenance"])
        self.assertEqual(fixture["binding"], {
            "verified": True,
            "loadedUUID": "00000000-0000-4000-8000-000000000096",
            "bootEpoch": 96,
            "armRunToken": "synthetic-test096-run-token",
        })
        result = adapt(fixture)
        self.assertEqual(result["status"], "verified_end_marker")
        self.assertEqual(result["expected_identity"]["captureSerial"], 101)
        self.assertEqual(result["expected_identity"]["driverGeneration"], 202)
        self.assertEqual(result["expected_identity"]["armUs"], 1479306056)
        self.assertEqual(result["expected_identity"]["startUs"], 1480037387)
        self.assertEqual(result["expected_identity"]["deadlineUs"], 1480137387)

    def test_preowner_binding_must_be_verified_and_same_run(self):
        fixture = load_fixture()
        binding = dict(fixture["binding"], verified=False)
        self.assert_unknown(
            adapt(fixture, binding=binding),
            "loaded_uuid_boot_epoch_run_token_unverified")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["binding"]["armRunToken"] = "another-run"
        self.assert_unknown(
            adapt(fixture, preowner=preowner),
            "capture_binding_mismatch_or_stale")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["binding"]["bootEpoch"] += 1
        self.assert_unknown(
            adapt(fixture, trace=trace),
            "capture_binding_mismatch_or_stale")

    def test_missing_snapshots_return_unknown_without_zero_identity(self):
        fixture = load_fixture()
        self.assert_unknown(runtime.derive_closed_identity(
            fixture["binding"], None, fixture["traceSnapshot"]),
            "preowner_snapshot_missing")
        self.assert_unknown(runtime.derive_closed_identity(
            fixture["binding"], fixture["preownerCapture"], None),
            "roc_trace_snapshot_missing")

    def test_preowner_requires_one_stable_closed_three_read_snapshot(self):
        fixture = load_fixture()
        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["stable"] = False
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_snapshot_unstable")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["stableReadCount"] = 2
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_not_three_stable_reads")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["commitMarkersValidForAllReads"] = False
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_commit_markers_unverified")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["decoded"]["snapshot"]["active"] = True
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_not_terminal")

    def test_trace_version_must_be_stable_nonzero_and_start_end_present(self):
        fixture = load_fixture()
        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceSnapshotVersionEnd"] = 5
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_trace_snapshot_unstable")

        for begin, end in ((3, 3), (-1, -1), (0, 0), (None, None)):
            trace = copy.deepcopy(fixture["traceSnapshot"])
            raw = trace["rawSnapshot"]
            if begin is None:
                raw.pop("NativeP2PRxTraceSnapshotVersionBegin")
                raw.pop("NativeP2PRxTraceSnapshotVersionEnd")
            else:
                raw["NativeP2PRxTraceSnapshotVersionBegin"] = begin
                raw["NativeP2PRxTraceSnapshotVersionEnd"] = end
            expected_reason = (
                "roc_trace_version_odd" if begin == 3 else
                "roc_trace_version_missing_zero_or_out_of_range")
            result = adapt(fixture, trace=trace)
            self.assert_unknown(result, expected_reason)
            self.assertIsNone(result["marker"])
            self.assertIsNone(result["expected_identity"])

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocStartPresent"] = 0
        result = adapt(fixture, trace=trace)
        self.assert_unknown(
            result, "roc_start_not_observed_no_zero_identity")
        self.assertNotIn("identity", result)

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocEndPresent"] = 0
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_end_not_observed")

    def test_failed_boundaries_and_epoch_owner_or_generation_mismatch_are_unknown(self):
        fixture = load_fixture()
        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocStartRawStatus"] = 0
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_start_RawStatus_failed")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocEndApi"] = 0
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_end_Api_failed")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocEndContextGeneration"] = 7
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_contextGeneration_invalid_or_mismatch")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocEndOwnerSessionToken"] = 9
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_owner_token_or_serial_mismatch")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTracePowerGeneration"] = 12
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_powerGeneration_invalid_or_mismatch")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["decoded"]["snapshot"]["driverGeneration"] = 12
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_driver_generation_mismatch")

    def test_boundary_times_must_fit_arm_requested_duration_and_preowner_end(self):
        fixture = load_fixture()
        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocEndHostMonotonicUs"] = (
            1480137388)
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_boundary_time_mismatch")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocEndHostMonotonicUs"] = (
            1479306056)
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_boundary_time_mismatch")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["decoded"]["snapshot"]["endUs"] = 1480100000
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "roc_boundary_time_mismatch")

    def test_deadline_overflow_and_wire_identity_ranges_are_rejected(self):
        fixture = load_fixture()
        trace = copy.deepcopy(fixture["traceSnapshot"])
        raw = trace["rawSnapshot"]
        uint64_max = (1 << 64) - 1
        raw["NativeP2PRxTraceRocStartHostMonotonicUs"] = uint64_max - 50
        raw["NativeP2PRxTraceRocEndHostMonotonicUs"] = uint64_max - 25
        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["decoded"]["snapshot"]["endUs"] = uint64_max
        self.assert_unknown(adapt(fixture, preowner=preowner, trace=trace),
                            "roc_deadline_overflow")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRocRequestedDurationMs"] = (
            (1 << 32))
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_requested_duration_missing_or_invalid")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRocRequestedDurationMs"] = uint64_max
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_deadline_overflow")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["decoded"]["snapshot"]["captureSerial"] = (1 << 32)
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_captureSerial_missing_or_invalid")

        preowner = copy.deepcopy(fixture["preownerCapture"])
        preowner["decoded"]["snapshot"]["driverGeneration"] = (1 << 32)
        self.assert_unknown(adapt(fixture, preowner=preowner),
                            "preowner_driverGeneration_missing_or_invalid")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        raw = trace["rawSnapshot"]
        for key in (
            "NativeP2PRxTraceContextGeneration",
            "NativeP2PRxTraceRocStartContextGeneration",
            "NativeP2PRxTraceRocEndContextGeneration",
        ):
            raw[key] = 1 << 32
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_contextGeneration_invalid_or_mismatch")

        trace = copy.deepcopy(fixture["traceSnapshot"])
        trace["rawSnapshot"]["NativeP2PRxTraceRocStartOwnerSessionToken"] = (
            1 << 64)
        self.assert_unknown(adapt(fixture, trace=trace),
                            "roc_owner_token_or_serial_mismatch")

    def test_external_marker_starts_property_collection_budget(self):
        result = adapt()
        clock = FakeClock()
        calls = []

        def close_reader():
            calls.append(("close", clock.now))
            return result["marker"]

        property_bytes = property_fixture(
            identity=result["expected_identity"])

        def property_reader():
            calls.append(("property", clock.now))
            return property_bytes

        collected = collector.collect_after_closed_marker(
            close_reader,
            property_reader,
            expected_identity=result["expected_identity"],
            close_marker_timeout=2.0,
            publication_timeout=1.0,
            poll_interval=0.1,
            stable_reads=3,
            clock=clock.clock,
            sleep=clock.sleep,
        )
        self.assertEqual(collected["status"], "decoded_stable_closed")
        self.assertTrue(collected["propertyTimeoutStartedAfterCloseMarker"])
        self.assertEqual(calls[0][0], "close")
        self.assertEqual([item[0] for item in calls[1:]],
                         ["property", "property", "property"])
        self.assertEqual(collected["decoded"]["fullSlots"], 1)


if __name__ == "__main__":
    unittest.main()
