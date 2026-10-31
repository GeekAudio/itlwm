#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import roc_rx_correlation_decode as decoder
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
    return {"closed": True, "sameCaptureEpochVerified": True,
            "evidenceSource": "offline-test-fixture",
            "identity": dict(IDENTITY)}


class RocCorrelationCollectTests(unittest.TestCase):
    def call(self, close_reader, property_reader, clock, **kwargs):
        return collector.collect_after_closed_marker(
            close_reader, property_reader,
            expected_identity=IDENTITY,
            close_marker_timeout=kwargs.get("close_timeout", 2.0),
            publication_timeout=kwargs.get("publication_timeout", 1.0),
            poll_interval=kwargs.get("poll_interval", 0.1),
            stable_reads=kwargs.get("stable_reads", 3),
            clock=clock.clock, sleep=clock.sleep,
        )

    def test_close_marker_is_observed_before_property_timeout_starts(self):
        clock = FakeClock()
        calls = []

        def close_reader():
            calls.append("close")
            return close_marker()

        def property_reader():
            calls.append("property")
            return fixture()

        result = self.call(close_reader, property_reader, clock)
        self.assertEqual(result["status"], "decoded_stable_closed")
        self.assertEqual(calls[0], "close")
        self.assertEqual(calls[1:], ["property", "property", "property"])
        self.assertTrue(result["propertyTimeoutStartedAfterCloseMarker"])
        self.assertEqual(result["closeEvidenceSource"], "offline-test-fixture")
        self.assertEqual(result["rawReads"], 3)

    def test_wait_for_close_does_not_consume_publication_budget(self):
        clock = FakeClock()
        close_results = [None] * 10 + [close_marker()]
        property_calls = []

        def close_reader():
            return close_results.pop(0)

        def property_reader():
            property_calls.append(clock.now)
            return fixture()

        result = self.call(close_reader, property_reader, clock,
                           close_timeout=2.0, publication_timeout=0.25,
                           poll_interval=0.1)
        self.assertEqual(result["status"], "decoded_stable_closed")
        self.assertGreaterEqual(property_calls[0], 0.99)
        self.assertLessEqual(property_calls[-1] - property_calls[0], 0.25)
        self.assertTrue(result["propertyTimeoutStartedAfterCloseMarker"])

    def test_property_absence_is_unknown_not_zero_or_failure(self):
        clock = FakeClock()
        result = self.call(close_marker, lambda: None, clock,
                           publication_timeout=0.2, poll_interval=0.1)
        self.assertEqual(result["status"], "publication_timeout")
        self.assertTrue(result["closedMarkerObserved"])
        self.assertTrue(result["propertyTimeoutStartedAfterCloseMarker"])
        self.assertEqual(result["propertyReadCount"], 3)
        self.assertIsNone(result["attempts"])
        self.assertIsNone(result["copies"])
        self.assertTrue(result["evidenceLimits"]["missingPropertyMeansUnknown"])
        self.assertFalse(result["evidenceLimits"]["missingPropertyMeansZeroCopies"])
        self.assertFalse(result["evidenceLimits"]["missingPropertyMeansReceiveFailure"])

    def test_close_marker_timeout_never_reads_property(self):
        clock = FakeClock()
        property_calls = []
        result = self.call(lambda: None,
                           lambda: property_calls.append(1), clock,
                           close_timeout=0.2, poll_interval=0.1)
        self.assertEqual(result["status"], "close_marker_timeout")
        self.assertFalse(result["propertyTimeoutStartedAfterCloseMarker"])
        self.assertEqual(result["propertyReadCount"], 0)
        self.assertEqual(property_calls, [])

    def test_stable_reads_reject_mutation_and_read_errors(self):
        clock = FakeClock()
        values = [fixture(), fixture(slots=[4]), fixture(slots=[5])]
        result = self.call(close_marker, lambda: values.pop(0), clock)
        self.assertEqual(result["status"], "unstable_property")
        clock = FakeClock()

        def raises():
            raise OSError("offline reader failure")

        result = self.call(close_marker, raises, clock)
        self.assertEqual(result["status"], "publication_timeout")
        self.assertEqual(result["errorType"], "OSError")
        self.assertIsNone(result["copies"])

    def test_identity_mismatch_and_open_property_keep_waiting(self):
        clock = FakeClock()
        wrong_marker = {"closed": True, "sameCaptureEpochVerified": True,
                        "evidenceSource": "offline-test-fixture",
                        "identity": dict(IDENTITY, rocGeneration=99)}
        markers = [wrong_marker, close_marker()]
        props = [fixture(state=decoder.STATE_ACTIVE, reason=0, coverage=0),
                 fixture(), fixture(), fixture()]
        result = self.call(lambda: markers.pop(0), lambda: props.pop(0), clock)
        self.assertEqual(result["status"], "decoded_stable_closed")
        self.assertEqual(result["closeMarkerReadCount"], 2)
        self.assertEqual(result["propertyReadCount"], 4)

    def test_property_identity_change_or_decode_error_remains_unknown(self):
        clock = FakeClock()
        wrong = dict(IDENTITY, rocGeneration=8)
        result = self.call(close_marker,
                           lambda: fixture(identity=wrong), clock,
                           publication_timeout=0.1, poll_interval=0.1)
        self.assertEqual(result["status"], "identity_mismatch")
        self.assertIsNone(result["copies"])
        clock = FakeClock()
        result = self.call(close_marker, lambda: b"bad", clock,
                           publication_timeout=0.1, poll_interval=0.1)
        self.assertEqual(result["status"], "malformed_property")
        self.assertIsNone(result["attempts"])

    def test_arm_us_only_property_mismatch_remains_unknown(self):
        clock = FakeClock()
        property_identity = dict(IDENTITY, armUs=IDENTITY["armUs"] + 1)
        result = self.call(
            close_marker,
            lambda: fixture(identity=property_identity),
            clock,
            publication_timeout=0.1,
            poll_interval=0.1,
        )
        self.assertEqual(result["status"], "identity_mismatch")
        self.assertTrue(result["closedMarkerObserved"])
        self.assertIsNone(result["attempts"])
        self.assertIsNone(result["copies"])
        self.assertIsNone(result["records"])


if __name__ == "__main__":
    unittest.main()
