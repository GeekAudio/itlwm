#!/usr/bin/env python3
"""Collect only numeric NativeStaCompletion fields from AirportItlwm ioreg."""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time

from txcmd_identity_completion import completion_scalars, decode_scalars


def sample_ioreg(expected_build: str) -> dict:
    raw = subprocess.check_output(
        ["/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"], timeout=8)
    tree = plistlib.loads(raw)
    if not isinstance(tree, list) or len(tree) != 1 or not isinstance(tree[0], dict):
        raise ValueError("expected one AirportItlwm service in ioreg output")
    service = tree[0]
    if service.get("NativeTestBuild") != expected_build:
        raise ValueError("loaded kext build does not match the requested candidate")
    scalars = completion_scalars(service)
    row = {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "epoch_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "build": expected_build,
        "properties": scalars,
    }
    if not scalars:
        row["decode_status"] = "completion_properties_absent"
        return row
    try:
        row["decoded"] = decode_scalars(scalars)
        row["decode_status"] = "snapshot_valid"
    except ValueError as error:
        # Keep the scalar cut for diagnosis while refusing to interpret a
        # missing, torn, or incomplete publication as a valid observation.
        row["decode_status"] = "snapshot_not_decodable"
        row["decode_error"] = str(error)
    return row


def capture(output: Path, expected_build: str, duration: float,
            interval: float) -> dict:
    if duration <= 0 or interval <= 0:
        raise ValueError("duration and interval must be positive")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    count = 0
    errors = 0
    start = time.monotonic()
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        while time.monotonic() - start < duration:
            sample_start = time.monotonic()
            try:
                row = sample_ioreg(expected_build)
            except Exception as error:  # retain only the error class/message
                errors += 1
                row = {
                    "captured_at": datetime.datetime.now().astimezone().isoformat(),
                    "epoch_ns": time.time_ns(),
                    "monotonic_ns": time.monotonic_ns(),
                    "build": expected_build,
                    "decode_status": "collection_error",
                    "decode_error": str(error),
                }
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            count += 1
            remaining = interval - (time.monotonic() - sample_start)
            if remaining > 0:
                time.sleep(min(remaining, max(0.0, duration - (time.monotonic() - start))))
    output.chmod(0o600)
    return {"samples": count, "collection_errors": errors,
            "duration_seconds": time.monotonic() - start,
            "output": str(output)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True,
                        help="expected NativeTestBuild value")
    parser.add_argument("--duration", type=float, required=True,
                        help="bounded collection duration in seconds")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="sampling interval in seconds")
    parser.add_argument("--output", type=Path, required=True,
                        help="new private JSONL output path")
    args = parser.parse_args()
    try:
        result = capture(args.output, args.build, args.duration, args.interval)
    except Exception as error:
        print(f"capture failed: {error}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
