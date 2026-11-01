#!/usr/bin/env python3
"""Candidate-bound passive sampler for Test101 Hcmd/key-response telemetry.

This sidecar intentionally keeps its own I/O Registry read bracket and host
monotonic timestamps. It is not merged with another collector's snapshot and
does not trigger radio, key, network, sleep, EFI, or firmware actions.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

HERE = Path(__file__).resolve().parent
DEVTOOLS = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(DEVTOOLS / "test100"))

import collect_rekey100 as base  # noqa: E402
import hcmd_rx_trace_test101 as hcmd  # noqa: E402

MAX_DURATION_SECONDS = 6 * 60 * 60
BASELINE_SECONDS = 300.0
TAIL_SECONDS = 30.0

HEADER_FIELDS = (
    "schema", "blob_length", "version_begin", "version_end",
    "owner_generation", "owner_watchdog_sequence",
    "owner_watchdog_sequence_present", "row_count", "dropped_count",
    "overwritten_count", "gap_count", "window_start_serial",
    "window_end_serial", "stable", "complete",
)


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError("output_directory_permissions_not_private")


def _selected_decode(sample: dict) -> dict:
    decoded = sample.get("decoded")
    if not isinstance(decoded, dict):
        return {"status": "decoded_sample_missing", "snapshot_stable": False,
                "snapshot_complete": False, "add_sta_key_status_events": [],
                "key_response_slot": None}
    header = decoded.get("header")
    selected_header = None
    if isinstance(header, dict):
        selected_header = {key: header.get(key) for key in HEADER_FIELDS}
    events = []
    for event in decoded.get("add_sta_key_status_events", []):
        if not isinstance(event, dict):
            continue
        events.append({key: event.get(key) for key in (
            "serial", "driver_monotonic_ns", "driver_generation",
            "firmware_generation", "phase", "source", "command_id",
            "group_id", "qid", "index", "header_sequence", "flags",
            "result", "payload_length", "firmware_status_state",
            "firmware_status_raw_le32", "command_response_failed_flag",
            "status_interpreted_as_key_install_success", "peer_ack_proven",
        )})
    return {
        "schema": decoded.get("schema"),
        "status": decoded.get("status"),
        "snapshot_stable": decoded.get("snapshot_stable") is True,
        "snapshot_complete": decoded.get("snapshot_complete") is True,
        "publish_revision": decoded.get("publish_revision"),
        "blob_sha256": decoded.get("blob_sha256"),
        "header": selected_header,
        "window_history_truncated": decoded.get("window_history_truncated"),
        "add_sta_key_status_events": events,
        "key_response_slot": decoded.get("key_response_slot"),
        "key_install_success_proven": False,
        "peer_ack_proven": False,
        "wifi_stability_proven": False,
    }


def _event_serials(decoded: dict) -> set[int]:
    serials: set[int] = set()
    for event in decoded.get("add_sta_key_status_events", []):
        serial = event.get("serial") if isinstance(event, dict) else None
        if type(serial) is int and serial > 0:
            serials.add(serial)
    slot = decoded.get("key_response_slot")
    event = slot.get("event") if isinstance(slot, dict) else None
    serial = event.get("serial") if isinstance(event, dict) else None
    if type(serial) is int and serial > 0:
        serials.add(serial)
    return serials


def capture(output: Path, *, boot_epoch: int, expected_uuid: str,
            expected_build: str, duration: float = 3600.0,
            interval: float = 1.0) -> dict:
    if not (0 < duration <= MAX_DURATION_SECONDS and 0 < interval <= 10):
        raise ValueError("invalid_bounded_capture_duration")
    if not output.parent.is_dir():
        _private_directory(output.parent)
    elif stat.S_IMODE(output.parent.stat().st_mode) & 0o077:
        raise PermissionError("output_directory_permissions_not_private")

    base.EXPECTED_KEXT_UUID = expected_uuid.upper()
    identity = base.read_host_identity(boot_epoch, expected_build)
    if identity.get("boot_epoch") != boot_epoch or identity.get("loaded_kext_uuid") != expected_uuid.upper():
        raise ValueError("candidate_identity_mismatch")

    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
        os.close(fd)
        raise PermissionError("output_file_permissions_not_private")
    start = time.monotonic()
    sample_count = 0
    error_count = 0
    seen_serials: set[int] = set()
    first_sample = True
    trigger_log = []
    tail_until: float | None = None
    terminal_status = "duration_elapsed_no_anchor"
    next_due = start

    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        header = {
            "record_type": "header",
            "schema": "test101-hcmd-rekey-passive/v1",
            "created_at": datetime.datetime.now().astimezone().isoformat(),
            "boot_epoch": boot_epoch,
            "candidate_build": expected_build,
            "os_build": identity.get("os_build"),
            "loaded_kext_uuid": identity.get("loaded_kext_uuid"),
            "duration_seconds": duration,
            "interval_seconds": interval,
            "baseline_seconds": BASELINE_SECONDS,
            "event_tail_seconds": TAIL_SECONDS,
            "scope": "Read-only allowlisted Hcmd trace and NativeKeyResponse scalars; no RF, network changes, sleep, EFI, raw packet data, or key material.",
            "timestamp_contract": "Each Hcmd snapshot keeps its own host monotonic read bracket; it is not the same cut as the parallel Wi-Fi collector.",
        }
        stream.write(json.dumps(header, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        try:
            while True:
                before = time.monotonic()
                elapsed = before - start
                if elapsed >= duration:
                    terminal_status = "event_window_complete" if tail_until is not None and elapsed >= tail_until else (
                        "duration_elapsed_during_event_tail" if tail_until is not None else "duration_elapsed_no_anchor")
                    break
                point = hcmd.sample_once()
                decoded = point.get("decoded") if isinstance(point, dict) else None
                decoded = decoded if isinstance(decoded, dict) else {}
                serials = _event_serials(decoded)
                if first_sample:
                    seen_serials.update(serials)
                    first_sample = False
                    new_serials = set()
                else:
                    new_serials = serials - seen_serials
                    seen_serials.update(serials)
                reasons = ["new_add_sta_key_response_status_observed"] if new_serials else []
                sample_mono = time.monotonic_ns()
                try:
                    wall = datetime.datetime.now().astimezone().isoformat()
                    item = {
                        "record_type": "sample",
                        "sample_index": sample_count + 1,
                        "captured_at": wall,
                        "elapsed_seconds": round(time.monotonic() - start, 3),
                        "host_monotonic_ns": sample_mono,
                        "host_monotonic_lower_ns": point.get("host_monotonic_lower_ns"),
                        "host_monotonic_upper_ns": point.get("host_monotonic_upper_ns"),
                        "sample_status": point.get("sample_status"),
                        "decoded": _selected_decode(point),
                        "new_event_reasons": reasons,
                    }
                except Exception:
                    error_count += 1
                    item = {"record_type": "sample_error", "sample_index": sample_count + 1,
                            "captured_at": datetime.datetime.now().astimezone().isoformat(),
                            "elapsed_seconds": round(time.monotonic() - start, 3),
                            "error": "sample_sanitization_failed"}
                    reasons = []
                stream.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
                sample_count += 1
                if reasons:
                    tail_until = time.monotonic() - start + TAIL_SECONDS
                    trigger_log.append({"elapsed_seconds": round(time.monotonic() - start, 3),
                                        "reason": reasons[0]})
                elapsed = time.monotonic() - start
                if tail_until is not None and elapsed >= tail_until:
                    terminal_status = "event_window_complete"
                    break
                if elapsed >= duration:
                    terminal_status = "duration_elapsed_during_event_tail" if tail_until is not None else "duration_elapsed_no_anchor"
                    break
                next_due += interval
                now = time.monotonic()
                if next_due <= now:
                    next_due = now + interval
                delay = min(max(0.0, next_due - now), max(0.0, duration - elapsed))
                if tail_until is not None:
                    delay = min(delay, max(0.0, tail_until - elapsed))
                if delay:
                    time.sleep(delay)
                if sample_count % 60 == 0:
                    baseline_state = "complete" if elapsed >= BASELINE_SECONDS else "collecting"
                    print(f"PROGRESS elapsed={int(elapsed)} samples={sample_count} baseline={baseline_state} anchor={bool(trigger_log)}", flush=True)
        except KeyboardInterrupt:
            terminal_status = "interrupted_output_preserved"
        finally:
            elapsed = time.monotonic() - start
            footer = {
                "record_type": "footer",
                "ended_at": datetime.datetime.now().astimezone().isoformat(),
                "elapsed_seconds": round(elapsed, 3),
                "sample_count": sample_count,
                "collection_error_count": error_count,
                "baseline_seconds": BASELINE_SECONDS,
                "baseline_observed": elapsed >= BASELINE_SECONDS,
                "terminal_status": terminal_status,
                "trigger_log": trigger_log,
                "anchor_observed": bool(trigger_log),
                "stability_pass": False,
                "note": "Passive Hcmd observation only; no key response is not a failure, and this capture does not prove Wi-Fi stability, key-install success, peer ACK, or AirDrop.",
            }
            stream.write(json.dumps(footer, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    os.chmod(output, 0o600)
    return {"output": str(output), "terminal_status": terminal_status,
            "sample_count": sample_count, "collection_error_count": error_count,
            "anchor_observed": bool(trigger_log)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--boot", type=int, required=True)
    parser.add_argument("--expected-uuid", required=True)
    parser.add_argument("--build", default="25G332-Test101")
    parser.add_argument("--duration", type=float, default=3600.0)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    try:
        result = capture(args.out, boot_epoch=args.boot,
                         expected_uuid=args.expected_uuid,
                         expected_build=args.build,
                         duration=args.duration, interval=args.interval)
    except FileExistsError:
        print("output_exists_choose_new_private_path", file=sys.stderr)
        return 2
    except Exception as error:
        print("collector_preflight_or_runtime_error=" + type(error).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
