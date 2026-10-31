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

PUBLICATION_TRACE_PROPERTIES = {
    "versionBegin": "NativeRXRocCopyCorrelationPublishVersionBegin",
    "versionEnd": "NativeRXRocCopyCorrelationPublishVersionEnd",
    "traceV1": "NativeRXRocCopyCorrelationPublishTraceV1",
    "gateResult": "NativeRXRocCopyCorrelationPublishGateResult",
    "identity": "NativeRXRocCopyCorrelationPublishIdentity",
    "armUs": "NativeRXRocCopyCorrelationPublishArmUs",
}
_PUBLICATION_STAGES = {
    0: "unobserved",
    1: "gate_unavailable",
    2: "recorder_not_ready",
    3: "encode_failed",
    4: "allocation_failed",
    5: "property_write_failed",
    6: "published",
    7: "retry_exhausted",
}


def decode_publication_trace(
    properties: Any,
    *,
    expected_identity: Mapping[str, int],
) -> dict[str, Any]:
    """Decode the scalar Test098 publisher trace without promoting its proof.

    ``properties`` is one caller-read IOKit snapshot. The begin/end markers
    must be the same nonzero even revision; capture serial, driver generation,
    and arm time must also match the independently derived ROC marker.
    """
    if not isinstance(properties, Mapping):
        return {"status": "trace_missing"}

    values: dict[str, int] = {}
    for field, key in PUBLICATION_TRACE_PROPERTIES.items():
        value = properties.get(key)
        if type(value) is not int or value < 0:
            return {"status": "trace_field_missing_or_invalid", "field": field}
        values[field] = value

    begin = values["versionBegin"]
    end = values["versionEnd"]
    if begin == 0 or end == 0:
        return {"status": "trace_version_missing"}
    if begin != end:
        return {"status": "trace_version_unstable"}
    if begin & 1:
        return {"status": "trace_version_odd"}

    word = values["traceV1"]
    if word > 0xffffffffffffffff:
        return {"status": "trace_word_out_of_range"}
    schema = word & 0xff
    if schema != 1:
        return {"status": "trace_schema_unsupported", "schema": schema}
    stage = (word >> 8) & 0xff
    state = (word >> 16) & 0x3
    reason = (word >> 18) & 0xf
    identity = values["identity"]
    capture_serial = identity & 0xffffffff
    driver_generation = (identity >> 32) & 0xffffffff
    arm_us = values["armUs"]
    expected = expected_identity
    if (capture_serial != expected.get("captureSerial") or
            driver_generation != expected.get("driverGeneration") or
            arm_us != expected.get("armUs")):
        return {
            "status": "trace_identity_mismatch",
            "captureSerial": capture_serial,
            "driverGeneration": driver_generation,
            "armUs": arm_us,
        }

    return {
        "status": "decoded_stable_trace",
        "revision": begin,
        "schema": schema,
        "stage": _PUBLICATION_STAGES.get(stage, "unknown_stage"),
        "stageCode": stage,
        "recorderState": state,
        "closeReason": reason,
        "unfinished": (word >> 22) & 0xff,
        "readyToEncode": bool((word >> 30) & 1),
        "encodeSucceeded": bool((word >> 31) & 1),
        "allocationSucceeded": bool((word >> 32) & 1),
        "propertyWriteSucceeded": bool((word >> 33) & 1),
        "published": bool((word >> 34) & 1),
        "payloadAttempts": (word >> 35) & 0x3,
        "gateAttempts": (word >> 37) & 0xff,
        "gateEntries": (word >> 45) & 0xff,
        "gateResultValid": bool((word >> 53) & 1),
        "gateResultUnsigned": values["gateResult"] & 0xffffffff,
        "gateResultScope": "last_completed_attempt_before_snapshot",
        "captureSerial": capture_serial,
        "driverGeneration": driver_generation,
        "armUs": arm_us,
        "limits": {
            "publicationStageOnly": True,
            "peerReceiptProven": False,
            "airdropProven": False,
        },
    }


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
    publication_trace_reader: Callable[[], Mapping[str, Any] | None] | None = None,
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

    trace_state: dict[str, Any] = {
        "reads": 0,
        "last": None,
        "lastStable": None,
    }

    def read_publication_trace() -> None:
        if publication_trace_reader is None:
            return
        trace_state["reads"] += 1
        try:
            properties = publication_trace_reader()
        except Exception as error:  # preserve the property result as primary
            decoded_trace = {
                "status": "trace_read_error",
                "errorType": type(error).__name__,
            }
        else:
            decoded_trace = decode_publication_trace(
                properties, expected_identity=expected_identity)
        trace_state["last"] = decoded_trace
        if decoded_trace.get("status") == "decoded_stable_trace":
            trace_state["lastStable"] = decoded_trace

    def finish(result: dict[str, Any]) -> dict[str, Any]:
        if publication_trace_reader is not None:
            result["publicationTrace"] = {
                "readCount": trace_state["reads"],
                "lastRead": trace_state["last"],
                "lastStable": trace_state["lastStable"],
            }
        return result

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
            return finish(_unknown(
                "close_marker_timeout", close_marker_observed=False,
                property_timeout_started=False, close_marker_reads=close_reads,
                property_reads=0, elapsed=now - started,
                error_type=close_error,
            ))
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
        read_publication_trace()
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
            return finish(_unknown(
                last_status, close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=now - started,
                error_type=last_error,
                close_evidence_source=close_evidence_source,
            ))
        sleep(min(poll_interval, publication_deadline - now))

    blobs = [first_blob]
    for _ in range(1, stable_reads):
        now = clock()
        if now >= publication_deadline:
            return finish(_unknown(
                "stability_timeout", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=now - started,
                close_evidence_source=close_evidence_source,
            ))
        sleep(min(poll_interval, publication_deadline - now))
        property_reads += 1
        try:
            blob = property_reader()
        except Exception as error:
            read_publication_trace()
            return finish(_unknown(
                "property_read_error", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                error_type=type(error).__name__,
                close_evidence_source=close_evidence_source,
            ))
        read_publication_trace()
        if not isinstance(blob, bytes):
            return finish(_unknown(
                "property_disappeared", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            ))
        try:
            stable_snapshot = decoder.decode(
                blob, expected_identity=dict(expected_identity),
                require_closed=True)
        except decoder.DecodeError:
            return finish(_unknown(
                "unstable_or_malformed_property",
                close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            ))
        if stable_snapshot["identityMatch"].get("matched") is not True:
            return finish(_unknown(
                "identity_changed_during_stability_reads",
                close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            ))
        blobs.append(blob)
        if blob != first_blob:
            return finish(_unknown(
                "unstable_property", close_marker_observed=close_observed,
                property_timeout_started=True, close_marker_reads=close_reads,
                property_reads=property_reads, elapsed=clock() - started,
                close_evidence_source=close_evidence_source,
            ))

    return finish({
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
    })
