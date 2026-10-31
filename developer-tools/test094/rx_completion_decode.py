#!/usr/bin/env python3
"""Decode the fixed-width NativeRXCompletionObservation OSData payload."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SAMPLE_CAPACITY = 16
HEADER_BYTES = 56
SAMPLE_BYTES = 44
WIRE_BYTES = HEADER_BYTES + SAMPLE_CAPACITY * SAMPLE_BYTES

HEADER = struct.Struct("<12IQ")
SAMPLE = struct.Struct("<7I2Q")


class DecodeError(ValueError):
    """Raised for truncated, malformed, or unsupported payloads."""


def decode(blob: bytes) -> dict[str, Any]:
    if len(blob) != WIRE_BYTES:
        raise DecodeError(
            f"expected exactly {WIRE_BYTES} bytes, got {len(blob)}"
        )

    header = HEADER.unpack_from(blob)
    (schema, last_status, attempts, copies, skips, overwritten, family,
     last_generation, last_serial, last_head, last_slot, sample_count,
     last_uptime_us) = header

    if schema != SCHEMA_VERSION:
        raise DecodeError(f"unsupported schema version {schema}")
    if sample_count > SAMPLE_CAPACITY:
        raise DecodeError(
            f"sample count {sample_count} exceeds capacity {SAMPLE_CAPACITY}"
        )

    samples = []
    for index in range(sample_count):
        offset = HEADER_BYTES + index * SAMPLE_BYTES
        (sequence, generation, observation_serial, head, slot, raw_rbid,
         raw_flags, host_uptime_us, allocation_incarnation) = \
            SAMPLE.unpack_from(blob, offset)
        samples.append({
            "sequence": sequence,
            "driverGeneration": generation,
            "observationSerial": observation_serial,
            "head": head,
            "slot": slot,
            "rawRbid": raw_rbid,
            "rawFlags": raw_flags,
            "hostUptimeUs": host_uptime_us,
            "allocationIncarnation": allocation_incarnation,
        })

    return {
        "schemaVersion": schema,
        "lastStatus": last_status,
        "attempts": attempts,
        "copies": copies,
        "skips": skips,
        "overwrittenSamples": overwritten,
        "family": family,
        "lastAttemptGeneration": last_generation,
        "lastAttemptSerial": last_serial,
        "lastAttemptHead": last_head,
        "lastAttemptSlot": last_slot,
        "sampleCount": sample_count,
        "lastAttemptUptimeUs": last_uptime_us,
        "samples": samples,
        "interpretationLimits": {
            "sampleRingKeepsLatest16CopiesOnly": True,
            "laterTrafficCanOverwriteEarlierTargetSamples": True,
            "overwrittenCountDoesNotIdentifyDroppedFrameTypes": True,
            "rawRbidAndFlagsAreUninterpreted": True,
            "dmaOwnershipProven": False,
            "rawFreshnessProven": False,
            "eightByteCoherenceProven": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("blob", type=Path,
                        help="raw 760-byte OSData payload saved to a file")
    args = parser.parse_args()
    try:
        result = decode(args.blob.read_bytes())
    except (OSError, DecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
