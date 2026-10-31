#!/usr/bin/env python3
"""Decode publisher-stage scalars and preserve the original ROC timeout."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools/test096"))

import roc_rx_correlation_collect as collector
from test_roc_rx_correlation_decode import IDENTITY, fixture


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def close_marker():
    return {
        "closed": True,
        "sameCaptureEpochVerified": True,
        "evidenceSource": "offline-Test098-fixture",
        "identity": dict(IDENTITY),
    }


def trace_properties(*, stage=4, revision=2, identity=None, arm_us=None,
                     gate_result=0xe00002cc):
    # schema=1, stage, Closed(3), END(2), unfinished=0, ready=1,
    # encode=1, allocation=0, property=0, published=0, one payload try,
    # two gate attempts, one action entry, gate result valid.
    word = (
        1 | (stage << 8) | (3 << 16) | (2 << 18) |
        (1 << 30) | (1 << 31) | (1 << 35) |
        (2 << 37) | (1 << 45) | (1 << 53)
    )
    current = IDENTITY if identity is None else identity
    packed_identity = (
        (current["driverGeneration"] << 32) | current["captureSerial"]
    )
    return {
        collector.PUBLICATION_TRACE_PROPERTIES["versionBegin"]: revision,
        collector.PUBLICATION_TRACE_PROPERTIES["versionEnd"]: revision,
        collector.PUBLICATION_TRACE_PROPERTIES["traceV1"]: word,
        collector.PUBLICATION_TRACE_PROPERTIES["gateResult"]: gate_result,
        collector.PUBLICATION_TRACE_PROPERTIES["identity"]: packed_identity,
        collector.PUBLICATION_TRACE_PROPERTIES["armUs"]:
            current["armUs"] if arm_us is None else arm_us,
    }


class RocPublicationTraceTests(unittest.TestCase):
    def test_stable_trace_decodes_stage_and_capture_identity(self):
        result = collector.decode_publication_trace(
            trace_properties(), expected_identity=IDENTITY)
        self.assertEqual(result["status"], "decoded_stable_trace")
        self.assertEqual(result["stage"], "allocation_failed")
        self.assertEqual(result["recorderState"], 3)
        self.assertEqual(result["closeReason"], 2)
        self.assertTrue(result["readyToEncode"])
        self.assertTrue(result["encodeSucceeded"])
        self.assertFalse(result["allocationSucceeded"])
        self.assertFalse(result["published"])
        self.assertEqual(result["gateAttempts"], 2)
        self.assertEqual(result["gateEntries"], 1)
        self.assertEqual(result["gateResultUnsigned"], 0xe00002cc)
        self.assertEqual(result["gateResultScope"],
                         "last_completed_attempt_before_snapshot")
        self.assertFalse(result["limits"]["peerReceiptProven"])

    def test_torn_or_stale_trace_is_rejected(self):
        properties = trace_properties(revision=3)
        self.assertEqual(collector.decode_publication_trace(
            properties, expected_identity=IDENTITY)["status"],
            "trace_version_odd")
        properties = trace_properties()
        properties[collector.PUBLICATION_TRACE_PROPERTIES["versionEnd"]] = 4
        self.assertEqual(collector.decode_publication_trace(
            properties, expected_identity=IDENTITY)["status"],
            "trace_version_unstable")
        stale = dict(IDENTITY, driverGeneration=IDENTITY["driverGeneration"] + 1)
        self.assertEqual(collector.decode_publication_trace(
            trace_properties(identity=stale), expected_identity=IDENTITY)["status"],
            "trace_identity_mismatch")

    def test_trace_supplements_timeout_without_reclassifying_it(self):
        clock = FakeClock()
        samples = []

        def read_trace():
            value = trace_properties()
            samples.append(value)
            return value

        result = collector.collect_after_closed_marker(
            close_marker,
            lambda: None,
            expected_identity=IDENTITY,
            close_marker_timeout=0.1,
            publication_timeout=0.2,
            publication_trace_reader=read_trace,
            poll_interval=0.1,
            stable_reads=3,
            clock=clock.clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result["status"], "publication_timeout")
        self.assertEqual(result["propertyReadCount"], 3)
        self.assertTrue(result["closedMarkerObserved"])
        self.assertIsNone(result["copies"])
        self.assertEqual(result["publicationTrace"]["readCount"], 3)
        self.assertEqual(result["publicationTrace"]["lastStable"]["stage"],
                         "allocation_failed")
        self.assertEqual(len(samples), 3)

    def test_trace_reader_errors_do_not_change_primary_timeout(self):
        clock = FakeClock()

        def broken_trace_reader():
            raise OSError("private reader detail")

        result = collector.collect_after_closed_marker(
            close_marker,
            lambda: None,
            expected_identity=IDENTITY,
            close_marker_timeout=0.1,
            publication_timeout=0.1,
            publication_trace_reader=broken_trace_reader,
            poll_interval=0.1,
            clock=clock.clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result["status"], "publication_timeout")
        self.assertEqual(result["publicationTrace"]["lastRead"], {
            "status": "trace_read_error",
            "errorType": "OSError",
        })
        self.assertNotIn("private reader detail", str(result))


if __name__ == "__main__":
    unittest.main()
