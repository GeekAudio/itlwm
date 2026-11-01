#!/usr/bin/env python3
"""Bounded, passive Test104 GTK / HCMD response correlation collector.

Reads one AirportItlwm I/O Registry snapshot per sample and keeps only fixed,
address-free command/auth/link metadata and boolean en1 readiness. Every stable
HCTX cut retains its complete available event ring. Sticky latest-key scalars
remain separate from ring rows and are never used to fill a missing response.
This program performs no Wi-Fi, RF, network, sleep, EFI, or key action.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import sys
import time
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
DEVTOOLS = HERE.parent
sys.path.insert(0, str(DEVTOOLS / "test100"))
sys.path.insert(0, str(DEVTOOLS / "test103"))
sys.path.insert(0, str(DEVTOOLS / "test105"))

from live_key105 import parse_live_key, completion_with_live_authority  # noqa: E402

import collect_rekey100 as base  # noqa: E402
import hcmd_rx_trace_test103 as hcmd  # noqa: E402
from hcmd_rekey_correlation104 import (  # noqa: E402
    correlate_key_lifecycle, trigger_reasons,
)

MAX_DURATION_SECONDS = 6 * 60 * 60
MIN_INTERVAL_SECONDS = 0.25
MAX_INTERVAL_SECONDS = 10.0
BASELINE_SECONDS = 300.0
TAIL_SECONDS = 30.0
IDENTITY_RECHECK_SECONDS = 60.0
AUTH_PROPERTY = "NativeGroupKeyForensicSnapshot"
LINK_PROPERTY = "NativeWifiLinkTransitionTrace"
AUTH_EVENT = struct.Struct("<7I4Hi2I")
HCMD_MAX_LENGTH = (hcmd.WIRE_HEADER_BYTES +
                    hcmd.TRACE_CAPACITY * hcmd.WIRE_ENTRY_BYTES)


class CollectorError(RuntimeError):
    pass


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise PermissionError("output_directory_permissions_not_private")


def _decode_auth_trace(raw: Any) -> dict:
    if not isinstance(raw, bytes):
        return {"snapshot_status": "not_published", "events": [],
                "dropped_count": None}
    # Reuse the frozen Test100 parser for size, schema, revision, and unused
    # record validation, then expose the complete non-sensitive event fields.
    try:
        header = base.parse_auth_snapshot(raw)
    except (ValueError, struct.error) as error:
        return {"snapshot_status": "invalid",
                "parse_error_class": type(error).__name__, "events": [],
                "dropped_count": None}
    vals = base.AUTH_HEADER.unpack_from(raw)
    live_count = vals[8]
    first_count = vals[15]
    events_by_sequence: dict[int, dict] = {}
    offsets = [(base.AUTH_HEADER.size, live_count),
               (base.AUTH_HEADER.size + 16 * AUTH_EVENT.size, first_count)]
    for start, count in offsets:
        for index in range(count):
            item = AUTH_EVENT.unpack_from(raw, start + index * AUTH_EVENT.size)
            sequence = item[0]
            if sequence == 0:
                continue
            event = {
                "sequence": sequence,
                "monotonic_us": item[1] | (item[2] << 32),
                "diagnostic_instance": item[3],
                "driver_generation": item[4],
                "association_id": item[5],
                "attempt_id": item[6],
                "kind": item[7],
                "stage": item[8],
                "component": item[9],
                "source": item[10],
                "result": item[11],
                "flags": item[12],
                "detail": item[13],
            }
            old = events_by_sequence.get(sequence)
            if old is not None and old != event:
                raise CollectorError("auth_duplicate_sequence_conflict")
            events_by_sequence[sequence] = event
    return {
        "snapshot_status": "stable",
        "revision_begin": header["revision_begin"],
        "revision_end": header["revision_end"],
        "diagnostic_instance": header["diagnostic_instance"],
        "driver_generation": header["driver_generation"],
        "association_id": header["association_id"],
        "dropped_count": header["dropped_count"],
        "live_count": header["live_count"],
        "first_state": header["first_state"],
        "first_count": header["first_count"],
        "history_may_be_truncated": bool(header["dropped_count"]),
        "events": [events_by_sequence[key] for key in sorted(events_by_sequence)],
    }


def _decode_group2_trace(raw: Any) -> dict:
    if not isinstance(raw, bytes):
        return {"snapshot_status": "not_published", "events": [],
                "peer_ack_proven": False}
    try:
        parsed = base.parse_group2_snapshot(raw)
    except (ValueError, struct.error) as error:
        return {"snapshot_status": "invalid", "parse_error_class": type(error).__name__,
                "events": [], "peer_ack_proven": False}
    fields = ("sequence", "monotonic_us", "cookie", "slot_generation",
              "attempt_id", "source", "origin_generation", "origin_association",
              "context_generation", "output_epoch", "queue_id", "index",
              "ring_count", "frame_control", "sequence_control", "tid",
              "result", "flags", "stage", "status")
    events = []
    for index in range(parsed["event_count"]):
        values = base.GROUP2_EVENT.unpack_from(
            raw, base.GROUP2_HEADER.size + index * base.GROUP2_EVENT.size)
        events.append(dict(zip(fields, values)))
    return {**parsed, "events": events,
            "history_may_be_truncated": bool(parsed["dropped_count"] or
                (events and events[-1]["sequence"] > len(events))),
            "peer_ack_proven": False}


def _decode_link_trace(raw: Any) -> dict:
    if not isinstance(raw, bytes):
        return {"snapshot_status": "not_published", "events": [],
                "dropped_count": None}
    try:
        parsed = base.parse_link_snapshot(raw)
    except (ValueError, struct.error) as error:
        return {"snapshot_status": "invalid",
                "parse_error_class": type(error).__name__, "events": [],
                "dropped_count": None}
    return {
        "snapshot_status": parsed["snapshot_status"],
        "revision_begin": parsed["revision_begin"],
        "revision_end": parsed["revision_end"],
        "sequence": parsed["sequence"],
        "dropped_count": parsed["dropped_count"],
        "count": parsed["count"],
        "history_may_be_truncated": bool(parsed["dropped_count"]),
        "events": parsed["events"],
    }


def _hcmd_sample_from_service(service: dict, before_ns: int,
                             after_ns: int) -> dict:
    blob = service.get(hcmd.TRACE_PROPERTY)
    if isinstance(blob, bytes) and len(blob) > HCMD_MAX_LENGTH:
        return {
            "schema": hcmd.TRACE_SCHEMA,
            "status": "decode_error",
            "decode_error_class": "OversizeOSData",
            "snapshot_stable": False,
            "snapshot_complete": False,
            "blob_length": len(blob),
            "blob_sha256": None,
            "header": None,
            "rows": [],
            "add_sta_key_status_events": [],
            "key_response_slot": {"status": "unavailable_after_decode_error"},
            "key_install_success_proven": False,
            "peer_ack_proven": False,
        }
    raw_sample = {
        "read_status": "trace_present" if isinstance(blob, bytes)
                       else "trace_not_published",
        "blob": blob if isinstance(blob, bytes) else None,
        "markers": {key: service.get(key) for key in hcmd.COMPANION_FIELDS},
        "key_response": {key: service.get(key) for key in hcmd.KEY_RESPONSE_FIELDS},
        "publish_revision_begin": service.get(
            "NativeHcmdRxTracePublishRevisionBegin"),
        "publish_revision_end": service.get(
            "NativeHcmdRxTracePublishRevisionEnd"),
        "host_monotonic_lower_ns": before_ns,
        "host_monotonic_upper_ns": after_ns,
    }
    try:
        return hcmd.decode_snapshot(raw_sample)
    except (ValueError, struct.error) as error:
        return {
            "schema": hcmd.TRACE_SCHEMA,
            "status": "decode_error",
            "decode_error_class": type(error).__name__,
            "snapshot_stable": False,
            "snapshot_complete": False,
            "blob_length": len(blob) if isinstance(blob, bytes) else None,
            "blob_sha256": (hashlib.sha256(blob).hexdigest()
                            if isinstance(blob, bytes) else None),
            "header": None,
            "rows": [],
            "add_sta_key_status_events": [],
            "key_response_slot": {"status": "unavailable_after_decode_error"},
            "key_install_success_proven": False,
            "peer_ack_proven": False,
        }


def _locate_candidate_service(tree: Any, expected_build: str) -> dict:
    matches: list[dict] = []

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("NativeTestBuild") == expected_build:
            matches.append(node)
        children = node.get("IORegistryEntryChildren", [])
        if isinstance(children, list):
            for child in children:
                visit(child)

    if isinstance(tree, list):
        for item in tree:
            visit(item)
    if len(matches) != 1:
        raise CollectorError("candidate_ioreg_service_missing_or_ambiguous")
    return matches[0]


def _retain_raw_osdata(raw: Any, *, maximum_length: int,
                       required_length: int | None = None) -> dict:
    if not isinstance(raw, bytes):
        return {"present": False, "length": None, "sha256": None,
                "base64": None, "retained": False,
                "status": "not_published"}
    length = len(raw)
    if length > maximum_length:
        return {"present": True, "length": length, "sha256": None,
                "base64": None, "retained": False,
                "status": "over_size_limit"}
    if required_length is not None and length != required_length:
        return {"present": True, "length": length,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "base64": None, "retained": False,
                "status": "unexpected_fixed_length"}
    return {"present": True, "length": length,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "base64": base64.b64encode(raw).decode("ascii"),
            "retained": True, "status": "retained_bounded_osdata"}


def sample_once(expected_build: str, identity: dict,
                *, ioreg_fn: Callable[..., bytes] = subprocess.check_output,
                ifconfig_fn: Callable[..., bytes] = subprocess.check_output,
                monotonic_ns: Callable[[], int] = time.monotonic_ns,
                wall_now: Callable[[], datetime.datetime] =
                    lambda: datetime.datetime.now().astimezone()) -> dict:
    before = monotonic_ns()
    raw = ioreg_fn(["/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"],
                   stderr=subprocess.DEVNULL, timeout=5)
    after = monotonic_ns()
    tree = plistlib.loads(raw)
    service = _locate_candidate_service(tree, expected_build)
    selected = base.select_allowlisted(service, expected_build)
    hcmd_decoded = _hcmd_sample_from_service(service, before, after)
    live_key = parse_live_key(service)
    auth_raw = service.get(AUTH_PROPERTY)
    auth = _decode_auth_trace(auth_raw)
    link_trace = _decode_link_trace(service.get(LINK_PROPERTY))
    interface_before = monotonic_ns()
    interface_raw = ifconfig_fn(["/sbin/ifconfig", base.INTERFACE],
                                 stderr=subprocess.DEVNULL, timeout=5)
    interface_after = monotonic_ns()
    en1 = base.sanitized_link_state(interface_raw)
    wall = wall_now().isoformat()
    return {
        "captured_at": wall,
        "host_monotonic_lower_ns": before,
        "host_monotonic_upper_ns": after,
        "identity": {
            "boot_epoch": identity.get("boot_epoch"),
            "os_build": identity.get("os_build"),
            "candidate_build": selected.get("candidate_build"),
            "loaded_kext_uuid": identity.get("loaded_kext_uuid"),
        },
        "numeric_counters": selected.get("numeric_counters", {}),
        "hcmd": hcmd_decoded,
        "auth_trace": auth,
        "live_key": live_key,
        "firmware_queue_completion": completion_with_live_authority(
            selected.get("completion_scalars", {}), live_key),
        "group2_tx_trace": _decode_group2_trace(service.get(base.GROUP2_PROPERTY)),
        "completion_scalars": selected.get("completion_scalars", {}),
        "completion_live_counters": selected.get("completion_live_counters", {}),
        "completion_host_origin": selected.get("completion_host_origin", {}),
        # Fixed diagnostic OSData values contain metadata only. Keep
        # their bytes in the same sample cut so an offline reviewer can replay
        # the exact decode without saving the full I/O Registry property list.
        "raw_osdata": {
            "NativeHcmdRxTrace": _retain_raw_osdata(
                service.get(hcmd.TRACE_PROPERTY),
                maximum_length=HCMD_MAX_LENGTH),
            AUTH_PROPERTY: _retain_raw_osdata(
                auth_raw, maximum_length=base.AUTH_SIZE,
                required_length=base.AUTH_SIZE),
            base.GROUP2_PROPERTY: _retain_raw_osdata(
                service.get(base.GROUP2_PROPERTY), maximum_length=base.GROUP2_SIZE,
                required_length=base.GROUP2_SIZE),
        },
        "link_trace": link_trace,
        "en1": en1,
        "en1_sample_wall_time": wall_now().isoformat(),
        "en1_host_monotonic_lower_ns": interface_before,
        "en1_host_monotonic_upper_ns": interface_after,
    }


def _selected_hcmd(decoded: dict) -> dict:
    header = decoded.get("header") if isinstance(decoded, dict) else None
    selected_header = None
    if isinstance(header, dict):
        selected_header = {key: header.get(key) for key in (
            "schema", "blob_length", "version_begin", "version_end",
            "owner_generation", "owner_watchdog_sequence",
            "owner_watchdog_sequence_present", "row_count", "dropped_count",
            "overwritten_count", "gap_count", "window_start_serial",
            "window_end_serial", "stable", "complete")}
    slot = decoded.get("key_response_slot") if isinstance(decoded, dict) else None
    if isinstance(slot, dict):
        slot = {key: slot.get(key) for key in (
            "schema", "status", "revision", "trace_version", "dropped_count",
            "dropped_serial", "ring_crosscheck", "event")}
    return {
        "schema": decoded.get("schema") if isinstance(decoded, dict) else None,
        "status": decoded.get("status") if isinstance(decoded, dict) else "invalid",
        "snapshot_stable": decoded.get("snapshot_stable") is True
            if isinstance(decoded, dict) else False,
        "snapshot_complete": decoded.get("snapshot_complete") is True
            if isinstance(decoded, dict) else False,
        "blob_sha256": decoded.get("blob_sha256") if isinstance(decoded, dict) else None,
        "blob_length": decoded.get("blob_length") if isinstance(decoded, dict) else None,
        "header": selected_header,
        # Full fixed-width HCTX rows: no payload data, keys, addresses, or raw
        # I/O Registry tree. Repeated snapshots are intentionally retained.
        "rows": decoded.get("rows", []) if isinstance(decoded, dict) else [],
        "key_response_slot_is_separate_sticky_evidence": True,
        "key_response_slot": slot,
        "key_install_success_proven": False,
        "peer_ack_proven": False,
    }


def _selected_auth(auth: dict) -> dict:
    if not isinstance(auth, dict):
        return {"snapshot_status": "invalid", "events": []}
    return {key: auth.get(key) for key in (
        "snapshot_status", "revision_begin", "revision_end",
        "diagnostic_instance", "driver_generation", "association_id",
        "dropped_count", "live_count", "first_state", "first_count",
        "history_may_be_truncated", "events")}


def _prime_seen(point: dict, seen_hcmd: set, seen_auth: set) -> None:
    decoded = point.get("hcmd", {})
    auth = point.get("auth_trace", {})
    # Establish the initial baseline only when both sides of this combined
    # IOKit sample are trustworthy. Otherwise leave all rows unseen so the
    # first usable sample can start a bounded tail instead of consuming a
    # possibly relevant event from a partial cut.
    if not (isinstance(decoded, dict) and decoded.get("snapshot_stable") is True and
            decoded.get("snapshot_complete") is True and
            isinstance(auth, dict) and auth.get("snapshot_status") == "stable"):
        return
    for row in decoded.get("rows", []):
        key = (row.get("driver_generation"), row.get("serial"))
        if all(type(value) is int for value in key):
            seen_hcmd.add(key)
    for event in auth.get("events", []):
        key = (event.get("diagnostic_instance"), event.get("sequence"))
        if all(type(value) is int for value in key):
            seen_auth.add(key)


def _sanitized_error(error: BaseException) -> dict:
    return {"class": type(error).__name__}


def capture(output: Path, *, boot_epoch: int, expected_uuid: str,
            expected_build: str = "25G332-Test104", duration: float = 3600.0,
            interval: float = 1.0,
            identity_reader: Callable[[int, str], dict] = base.read_host_identity,
            sample_reader: Callable[[str, dict], dict] = sample_once,
            monotonic: Callable[[], float] = time.monotonic,
            sleep: Callable[[float], None] = time.sleep,
            wall_now: Callable[[], datetime.datetime] =
                lambda: datetime.datetime.now().astimezone()) -> dict:
    if (duration <= 0 or duration > MAX_DURATION_SECONDS or
            interval < MIN_INTERVAL_SECONDS or interval > MAX_INTERVAL_SECONDS):
        raise ValueError("capture_duration_or_interval_out_of_bounds")
    if (not isinstance(expected_uuid, str) or
            not re.fullmatch(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
                             expected_uuid)):
        raise ValueError("expected_uuid_invalid")
    if not output.parent.exists():
        _private_directory(output.parent)
    elif stat.S_IMODE(output.parent.stat().st_mode) & 0o077:
        raise PermissionError("output_directory_permissions_not_private")

    base.EXPECTED_KEXT_UUID = expected_uuid.upper()
    identity = identity_reader(boot_epoch, expected_build)
    if (identity.get("boot_epoch") != boot_epoch or
            identity.get("loaded_kext_uuid") != expected_uuid.upper() or
            identity.get("os_build") != base.EXPECTED_OS_BUILD):
        raise CollectorError("candidate_identity_preflight_mismatch")

    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
        os.close(fd)
        raise PermissionError("output_file_permissions_not_private")

    start = monotonic()
    next_due = start
    sample_count = 0
    attempt_count = 0
    error_count = 0
    consecutive_errors = 0
    trigger_log: list[dict] = []
    tail_until: float | None = None
    terminal_status = "duration_elapsed_no_anchor"
    previous_en1: dict | None = None
    seen_hcmd: set[tuple[int, int]] = set()
    seen_auth: set[tuple[int, int]] = set()
    primed = False
    last_identity_check = start

    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        def append(row: dict) -> None:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        append({
            "record_type": "header",
            "schema": "test104-gtk-hcmd-passive/v1",
            "created_at": wall_now().isoformat(),
            "boot_epoch": boot_epoch,
            "candidate_build": expected_build,
            "os_build": identity.get("os_build"),
            "loaded_kext_uuid": identity.get("loaded_kext_uuid"),
            "duration_seconds": duration,
            "sample_interval_seconds": interval,
            "baseline_target_seconds": BASELINE_SECONDS,
            "event_tail_seconds": TAIL_SECONDS,
            "scope": "Read-only HCTX command/RX ring, STA auth/link traces and en1 boolean readiness; no RF, network, Wi-Fi change, sleep, EFI, payload, key material, SSID/BSSID, or addresses.",
            "timestamp_contract": "HCTX driver monotonic_ns and auth driver monotonic_us are retained; wall timestamps are collector capture times and no absolute event-to-wall mapping is claimed.",
            "correlation_contract": "Only a stable complete HCTX cut with exact command/qid/index/driver-generation and ordered serials may attach a response. The latest-key scalar is sticky and never substitutes for a missing row.",
        })
        try:
            while True:
                now = monotonic()
                elapsed = now - start
                if elapsed >= duration:
                    terminal_status = ("event_window_complete" if
                        tail_until is not None and elapsed >= tail_until else
                        "duration_elapsed_during_event_tail" if tail_until is not None else
                        "duration_elapsed_no_anchor")
                    break
                if now - last_identity_check >= IDENTITY_RECHECK_SECONDS:
                    try:
                        observed = identity_reader(boot_epoch, expected_build)
                    except Exception as error:
                        terminal_status = "candidate_identity_recheck_failed"
                        append({"record_type": "terminal_error",
                                "elapsed_seconds": round(elapsed, 3),
                                "error": _sanitized_error(error)})
                        break
                    if (observed.get("boot_epoch") != boot_epoch or
                            observed.get("loaded_kext_uuid") != expected_uuid.upper() or
                            observed.get("os_build") != identity.get("os_build")):
                        terminal_status = "candidate_identity_changed"
                        append({"record_type": "terminal_error",
                                "elapsed_seconds": round(elapsed, 3),
                                "error": "candidate_identity_changed"})
                        break
                    last_identity_check = now

                attempt_count += 1
                try:
                    point = sample_reader(expected_build, identity)
                    if point.get("identity", {}).get("candidate_build") != expected_build:
                        raise CollectorError("candidate_build_changed")
                    decoded_hcmd = point.get("hcmd", {})
                    auth = point.get("auth_trace", {})
                    link = point.get("link_trace", {})
                    if not primed:
                        _prime_seen(point, seen_hcmd, seen_auth)
                        reasons = []
                        primed = True
                    else:
                        reasons = trigger_reasons(decoded_hcmd, auth, link,
                            previous_en1, point.get("en1"), seen_hcmd, seen_auth)
                    correlation = correlate_key_lifecycle(decoded_hcmd, auth)
                    sample_count += 1
                    consecutive_errors = 0
                    captured = {
                        "record_type": "sample",
                        "sample_index": attempt_count,
                        "captured_at": point.get("captured_at"),
                        "elapsed_seconds": round(monotonic() - start, 3),
                        "host_monotonic_lower_ns": point.get("host_monotonic_lower_ns"),
                        "host_monotonic_upper_ns": point.get("host_monotonic_upper_ns"),
                        "en1_sample_wall_time": point.get("en1_sample_wall_time"),
                        "en1_host_monotonic_lower_ns": point.get("en1_host_monotonic_lower_ns"),
                        "en1_host_monotonic_upper_ns": point.get("en1_host_monotonic_upper_ns"),
                        "identity": point.get("identity"),
                        "en1": point.get("en1"),
                        "numeric_counters": point.get("numeric_counters", {}),
                        "hcmd": _selected_hcmd(decoded_hcmd),
                        "auth_trace": _selected_auth(auth),
                        "live_key": point.get("live_key", {"status": "not_published"}),
                        "firmware_queue_completion": point.get("firmware_queue_completion"),
                        "group2_tx_trace": point.get("group2_tx_trace"),
                        "completion_scalars": point.get("completion_scalars", {}),
                        "completion_live_counters": point.get("completion_live_counters", {}),
                        "completion_host_origin": point.get("completion_host_origin", {}),
                        "raw_osdata": point.get("raw_osdata", {}),
                        "link_trace": point.get("link_trace"),
                        "key_lifecycle_correlation": correlation,
                        "new_event_reasons": reasons,
                    }
                    append(captured)
                    if reasons:
                        tail_until = monotonic() - start + TAIL_SECONDS
                        trigger_log.append({"elapsed_seconds": captured["elapsed_seconds"],
                                            "reasons": reasons})
                    previous_en1 = point.get("en1")
                except Exception as error:
                    error_count += 1
                    consecutive_errors += 1
                    append({
                        "record_type": "sample_error",
                        "sample_index": attempt_count,
                        "captured_at": wall_now().isoformat(),
                        "elapsed_seconds": round(monotonic() - start, 3),
                        "error": _sanitized_error(error),
                    })
                    if consecutive_errors >= 3 and tail_until is None:
                        terminal_status = "collection_stopped_after_read_errors"
                        break

                elapsed = monotonic() - start
                if tail_until is not None and elapsed >= tail_until:
                    terminal_status = "event_window_complete"
                    break
                if elapsed >= duration:
                    terminal_status = ("duration_elapsed_during_event_tail"
                                       if tail_until is not None else
                                       "duration_elapsed_no_anchor")
                    break
                next_due += interval
                now = monotonic()
                if next_due <= now:
                    next_due = now + interval
                delay = min(max(0.0, next_due - now), max(0.0, duration - elapsed))
                if tail_until is not None:
                    delay = min(delay, max(0.0, tail_until - elapsed))
                if delay > 0:
                    sleep(delay)
        except KeyboardInterrupt:
            terminal_status = "interrupted_output_preserved"
        finally:
            append({
                "record_type": "footer",
                "ended_at": wall_now().isoformat(),
                "elapsed_seconds": round(monotonic() - start, 3),
                "sample_count": sample_count,
                "sample_attempt_count": attempt_count,
                "collection_error_count": error_count,
                "baseline_target_seconds": BASELINE_SECONDS,
                "baseline_completed": monotonic() - start >= BASELINE_SECONDS,
                "terminal_status": terminal_status,
                "trigger_log": trigger_log,
                "anchor_observed": bool(trigger_log),
                "sleep_tested": False,
                "wifi_stability_pass": False,
                "key_install_success_proven": False,
                "peer_ack_proven": False,
                "airdrop_proven": False,
                "note": "No anchor by the hard deadline is not a key-update pass or a long-term Wi-Fi stability pass. A same-slot response row is local driver evidence only.",
            })
    os.chmod(output, 0o600)
    return {"output": str(output), "terminal_status": terminal_status,
            "sample_count": sample_count, "collection_error_count": error_count,
            "anchor_observed": bool(trigger_log)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True,
                        help="new private JSONL path; existing files are never overwritten")
    parser.add_argument("--boot", type=int, required=True,
                        help="expected kern.boottime epoch")
    parser.add_argument("--expected-uuid", required=True,
                        help="reviewed loaded kext UUID for this candidate")
    parser.add_argument("--build", default="25G332-Test104",
                        help="expected NativeTestBuild (default: Test104)")
    parser.add_argument("--duration", type=float, default=3600.0,
                        help="hard maximum seconds; no event is not a pass")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="read-only sample interval, 0.25..10 seconds")
    args = parser.parse_args(argv)
    try:
        result = capture(args.out, boot_epoch=args.boot,
                         expected_uuid=args.expected_uuid,
                         expected_build=args.build,
                         duration=args.duration, interval=args.interval)
    except FileExistsError:
        print("output_exists_choose_new_private_path", file=sys.stderr)
        return 2
    except Exception as error:
        print("collector_error=" + type(error).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
