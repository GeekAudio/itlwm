#!/usr/bin/env python3
"""Pure, injected-reader collector for a closed ROC correlation property.

This module does not access IORegistry or hardware. Callers provide externally
verified, same-capture close evidence and a property reader. It is not wired
to a current driver terminal marker; publication timing is tested offline.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping

try:
    from . import roc_rx_correlation_decode as decoder
except ImportError:  # direct loading by the adjacent command-line tests
    import roc_rx_correlation_decode as decoder


IDENTITY_FIELDS = (
    "captureSerial", "driverGeneration", "contextGeneration",
    "powerGeneration", "stationGeneration", "rocGeneration",
    "sessionToken", "armUs", "startUs", "deadlineUs",
)


def _marker_matches(marker: Any, expected: Mapping[str, int]) -> bool:
    if not isinstance(marker, Mapping) or marker.get("closed") is not True:
        return False
    if marker.get("sameCaptureEpochVerified") is not True:
        return False
    if not isinstance(marker.get("evidenceSource"), str) or not marker["evidenceSource"]:
        return False
    identity = marker.get("identity")
    return isinstance(identity, Mapping) and all(
        identity.get(key) == expected[key] for key in IDENTITY_FIELDS
    )


def _unknown(status: str, *, close_marker_observed: bool,
             property_timeout_started: bool, close_marker_reads: int,
             property_reads: int, elapsed: float,
             error_type: str | None = None,
             close_evidence_source: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "complete": False,
        "closedMarkerObserved": close_marker_observed,
        "closeEvidenceSource": close_evidence_source,
        "propertyTimeoutStartedAfterCloseMarker": property_timeout_started,
        "closeMarkerReadCount": close_marker_reads,
        "propertyReadCount": property_reads,
        "elapsedSeconds": max(0.0, elapsed),
        "errorType": error_type,
        "attempts": None,
        "copies": None,
        "records": None,
        "evidenceLimits": {
            "missingPropertyMeansUnknown": True,
            "missingPropertyMeansZeroCopies": False,
            "missingPropertyMeansReceiveFailure": False,
            "dmaOwnershipProven": False,
            "rawFreshnessProven": False,
            "peerOrSocketReceiptProven": False,
        },
    }


def collect_after_closed_marker(
    close_marker_reader: Callable[[], Any],
    property_reader: Callable[[], bytes | None],
    *,
    expected_identity: Mapping[str, int],
    close_marker_timeout: float,
    publication_timeout: float,
    poll_interval: float = 0.03,
    stable_reads: int = 3,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Wait for a matching close marker, then start the property timeout.

    The close marker must already be externally verified for this capture and
    epoch; this helper does not authenticate a hardware or driver marker. A
    stable closed property is accepted only after ``stable_reads`` identical
    reads whose decoded identity matches this arm. The first property read is
    made after the marker, so time spent waiting for close does not consume
    the publication budget. Reader exceptions and absence remain unknown.
    """
    missing = [key for key in IDENTITY_FIELDS if key not in expected_identity]
    if missing:
        raise ValueError("expected_identity is missing: " + ", ".join(missing))
    if close_marker_timeout < 0 or publication_timeout < 0 or poll_interval <= 0:
        raise ValueError("timeouts must be nonnegative and poll_interval positive")
    if stable_reads < 2:
        raise ValueError("at least two reads are required for stable publication")

    started = clock()
    close_deadline = started + close_marker_timeout
    close_reads = 0
    close_observed = False
    close_evidence_source: str | None = None
    close_error: str | None = None
    while True:
        close_reads += 1
        try:
            marker = close_marker_reader()
            if _marker_matches(marker, expected_identity):
                close_observed = True
                close_evidence_source = marker["evidenceSource"]
                break
        except Exception as error:  # test seam keeps collection best-effort
            close_error = type(error).__name__
        now = clock()
        if now >= close_deadline:
            return _unknown(
                "close_marker_timeout", close_marker_observed=False,
                property_timeout_started=False, close_marker_reads=close_reads,
                property_reads=0, elapsed=now - started,
                error_type=close_error,
            )
        sleep(min(poll_interval, close_deadline - now))

    publication_started = clock()
    publication_deadline = publication_started + publication_timeout
    property_reads = 0
    first_blob: bytes | None = None
    last_error: str | None = None
    last_status = "publication_timeout"
    while True:
        property_reads += 1
        try:
            sample = property_reader()
        except Exception as error:
            last_error = type(error).__name__
            sample = None
        if isinstance(sample, bytes):
            try:
                snapshot = decoder.decode(
                    sample, expected_identity=dict(expected_identity))
            except decoder.DecodeError:
                last_status = "malformed_property"
            else:
                identity = snapshot["identityMatch"]
                if identity is None or identity.get("matched") is not True:
                    last_status = "identity_mismatch"
                elif snapshot["state"] == decoder.STATE_CLOSED:
                    first_blob = sample
                    break
                else:
                    last_status = "property_still_open"
        now = clock()
        if now >= publication_deadline:
            return _unknown(
                last_status, close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=now - started,
                error_type=last_error,
                close_evidence_source=close_evidence_source,
            )
        sleep(min(poll_interval, publication_deadline - now))

    blobs = [first_blob]
    for _ in range(1, stable_reads):
        now = clock()
        if now >= publication_deadline:
            return _unknown(
                "stability_timeout", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=now - started,
                close_evidence_source=close_evidence_source,
            )
        sleep(min(poll_interval, publication_deadline - now))
        property_reads += 1
        try:
            blob = property_reader()
        except Exception as error:
            return _unknown(
                "property_read_error", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                error_type=type(error).__name__,
                close_evidence_source=close_evidence_source,
            )
        if not isinstance(blob, bytes):
            return _unknown(
                "property_disappeared", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            )
        try:
            stable_snapshot = decoder.decode(
                blob, expected_identity=dict(expected_identity),
                require_closed=True)
        except decoder.DecodeError:
            return _unknown(
                "unstable_or_malformed_property",
                close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            )
        if stable_snapshot["identityMatch"].get("matched") is not True:
            return _unknown(
                "identity_changed_during_stability_reads",
                close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            )
        blobs.append(blob)
        if blob != first_blob:
            return _unknown(
                "unstable_property", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            )

    return {
        "status": "decoded_stable_closed",
        "complete": True,
        "closedMarkerObserved": True,
        "closeEvidenceSource": close_evidence_source,
        "propertyTimeoutStartedAfterCloseMarker": True,
        "closeMarkerReadCount": close_reads,
        "propertyReadCount": property_reads,
        "elapsedSeconds": max(0.0, clock() - started),
        "decoded": decoder.decode(first_blob, expected_identity=dict(expected_identity),
                                   require_closed=True),
        "rawReads": len(blobs),
        "allRawReadsEqual": True,
        "evidenceLimits": {
            "sameDispatchNumericCorrelationOnly": True,
            "dmaOwnershipProven": False,
            "rawFreshnessProven": False,
            "completionCoherenceProven": False,
            "phyOwnershipProven": False,
            "peerOrSocketReceiptProven": False,
        },
    }
