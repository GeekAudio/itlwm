#!/usr/bin/env python3
"""Offline queue-completion classifier for existing Test100 schema-4 captures.

This reports host queue processing/reclaim under the ordinary TX_RSP contract.
It does not change the strict matcher, TX reclaim, or imply an over-air ACK.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


REPORT_SCHEMA = "queue-contract-report/v1"
TX_RSP_KIND = 0
TX_RSP_SINGLE_RECLAIM_COMPLETED = 8
MAX_RING_COUNT = 1024

# iwx_tx_completion_observation.hpp presence bits used for ordinary TX_RSP.
HAS_FIRMWARE_QID = 1 << 7
HAS_QUEUE_INDEX = 1 << 8
HAS_RING_COUNT = 1 << 9
HAS_QUEUED = 1 << 10
HAS_CUR = 1 << 11
HAS_TAIL = 1 << 12
HAS_FRAME_COUNT = 1 << 13
HAS_SSN = 1 << 14
HAS_STATUS = 1 << 16
HAS_OUTPUT_EPOCH = 1 << 25
HAS_RESPONSE_FRAME_CONTROL = 1 << 26
HAS_RESPONSE_SEQUENCE_CONTROL = 1 << 27
HAS_TXCMD_SCAN = 1 << 28
HAS_TXCMD_UNIQUE_CANDIDATE = 1 << 29
HAS_SINGLE_SLOT_TXCMD_HEADER = 1 << 30

QUEUE_REQUIRED_FLAGS = (
    HAS_FIRMWARE_QID | HAS_QUEUE_INDEX | HAS_RING_COUNT | HAS_QUEUED |
    HAS_CUR | HAS_TAIL | HAS_FRAME_COUNT | HAS_SSN | HAS_STATUS |
    HAS_OUTPUT_EPOCH | HAS_RESPONSE_FRAME_CONTROL |
    HAS_RESPONSE_SEQUENCE_CONTROL
)


def _uint(value: Any, bits: int) -> bool:
    return type(value) is int and 0 <= value < (1 << bits)


def _unknown(reason: str, reference: Optional[dict] = None,
             device_status: Optional[dict] = None,
             strict_match: Any = "unknown") -> dict:
    return {
        "report_schema": REPORT_SCHEMA,
        "derived_from_schema4": True,
        "reference": reference or {},
        "queue_processed": "unknown",
        "queue_processed_basis": None,
        "queue_processed_reason": reason,
        "device_status": device_status or {
            "raw": None, "meaning": "unknown", "source": "Event0.Status"},
        "strict_header_match": strict_match,
        "peer_receipt": "unknown",
    }


def _strict_match(s: dict) -> Any:
    flags = s.get("NativeStaCompletionEvent0PresenceFlags")
    count = s.get("NativeStaCompletionEvent0TxCommandCandidateCount")
    scan = s.get("NativeStaCompletionEvent0TxCommandScanStatus")
    expected = s.get("NativeStaCompletionEvent0TxCommandExpectedCount")
    scanned = s.get("NativeStaCompletionEvent0TxCommandScannedCount")
    raw_index = s.get("NativeStaCompletionEvent0TxCommandCandidateIndex")
    if (not _uint(flags, 32) or not (flags & HAS_TXCMD_SCAN) or
            not (flags & HAS_SINGLE_SLOT_TXCMD_HEADER) or
            not _uint(scan, 32) or scan != 1 or
            not _uint(expected, 32) or expected != 1 or
            not _uint(scanned, 32) or scanned != 1 or
            not _uint(count, 32)):
        return "unknown"
    exact = bool(flags & HAS_TXCMD_UNIQUE_CANDIDATE)
    raw_index = s.get("NativeStaCompletionEvent0TxCommandCandidateIndex")
    ring = s.get("NativeStaCompletionEvent0RingCount")
    origin_state = s.get("NativeStaCompletionEvent0HostOriginState")
    origin_index = s.get("NativeStaCompletionEvent0HostOriginIndex")
    if (not _uint(raw_index, 32) or not _uint(ring, 32) or
            ring == 0 or raw_index >= ring or
            not _uint(origin_state, 32) or origin_state != 2 or
            not _uint(origin_index, 32) or origin_index != raw_index or
            not (flags & HAS_SINGLE_SLOT_TXCMD_HEADER)):
        return "unknown"
    if count == 0 and not exact:
        return False
    if count == 1 and exact:
        return True
    return "unknown"


def classify_schema4_cut(scalars: dict, host_origin: dict,
                         identity_matches_header: bool = True) -> dict:
    """Classify one already-decoded schema-4 sample without joining other rows."""
    if not isinstance(scalars, dict) or not isinstance(host_origin, dict):
        return _unknown("missing_schema4_sample")
    schema = scalars.get("NativeStaCompletionSchema")
    begin = scalars.get("NativeStaCompletionSnapshotVersionBegin")
    end = scalars.get("NativeStaCompletionSnapshotVersionEnd")
    serial = scalars.get("NativeStaCompletionEvent0Serial")
    publication_source = scalars.get("NativeStaCompletionPublicationSource")
    reference = {"event_serial": serial, "completion_cut": begin,
                 "publication_source": publication_source}
    if schema != 4:
        result = _unknown("schema_not_4", reference)
        result["derived_from_schema4"] = False
        return result
    if (not _uint(scalars.get("NativeStaCompletionSnapshotAvailable"), 32) or
            scalars.get("NativeStaCompletionSnapshotAvailable") != 1 or
            not _uint(scalars.get("NativeStaCompletionSnapshotComplete"), 32) or
            scalars.get("NativeStaCompletionSnapshotComplete") != 1 or
            not _uint(begin, 32) or not _uint(end, 32) or
            begin != end or (begin & 1)):
        return _unknown("incomplete_or_unstable_cut", reference)
    reference["completion_cut"] = end
    if not identity_matches_header:
        return _unknown("capture_identity_mismatch", reference)
    if (not _uint(scalars.get("NativeStaCompletionEvent0Present"), 32) or
            scalars.get("NativeStaCompletionEvent0Present") != 1 or
            not _uint(scalars.get("NativeStaCompletionEvent0Kind"), 32) or
            scalars.get("NativeStaCompletionEvent0Kind") != TX_RSP_KIND):
        return _unknown("ordinary_tx_rsp_not_established", reference)
    if (not _uint(serial, 64) or serial == 0 or
            not _uint(publication_source, 32) or publication_source not in (1, 2)):
        return _unknown("event_reference_missing", reference)

    status_raw = scalars.get("NativeStaCompletionEvent0Status")
    presence = scalars.get("NativeStaCompletionEvent0PresenceFlags")
    status = ({"raw": status_raw,
               "meaning": "firmware_reported_success" if status_raw == 1
               else "firmware_reported_status",
               "source": "Event0.Status"}
              if _uint(status_raw, 16) and _uint(presence, 32) and
              (presence & HAS_STATUS) else
              {"raw": None, "meaning": "unknown", "source": "Event0.Status"})
    origin = host_origin.get("host_origin") if isinstance(host_origin, dict) else None
    strict_match = _strict_match(scalars)

    def fail(reason: str) -> dict:
        return _unknown(reason, reference, status, strict_match)

    # These are cumulative retention counters. A previously lost cut does not
    # invalidate this complete, independently bound Event0 publication.
    if (not _uint(presence, 32) or
            (presence & QUEUE_REQUIRED_FLAGS) != QUEUE_REQUIRED_FLAGS):
        return fail("required_tx_rsp_fields_missing")
    terminal = scalars.get("NativeStaCompletionEvent0TerminalReason")
    if not _uint(terminal, 32) or terminal != TX_RSP_SINGLE_RECLAIM_COMPLETED:
        return fail("single_reclaim_terminal_not_established")
    frame_count = scalars.get("NativeStaCompletionEvent0FrameCount")
    if not _uint(frame_count, 32) or frame_count != 1:
        return fail("frame_count_not_one")
    if not isinstance(host_origin, dict) or host_origin.get("status") != "unique_host_slot" or host_origin.get("same_slot_descriptor") is not True:
        return fail("host_origin_not_unique_current")
    if (host_origin.get("event_serial") != serial or
            host_origin.get("snapshot_version") != end):
        return fail("host_origin_cut_or_event_mismatch")
    host_state = scalars.get("NativeStaCompletionEvent0HostOriginState")
    if not _uint(host_state, 32) or host_state != 2:
        return fail("host_origin_scalar_not_unique")
    if (not (presence & HAS_TXCMD_SCAN) or
            not (presence & HAS_SINGLE_SLOT_TXCMD_HEADER) or
            not _uint(scalars.get("NativeStaCompletionEvent0TxCommandScanStatus"), 32) or
            scalars.get("NativeStaCompletionEvent0TxCommandScanStatus") != 1 or
            not _uint(scalars.get("NativeStaCompletionEvent0TxCommandExpectedCount"), 32) or
            scalars.get("NativeStaCompletionEvent0TxCommandExpectedCount") != 1 or
            not _uint(scalars.get("NativeStaCompletionEvent0TxCommandScannedCount"), 32) or
            scalars.get("NativeStaCompletionEvent0TxCommandScannedCount") != 1):
        return fail("host_origin_header_scan_incomplete")
    if (not isinstance(origin, dict) or
            not all(_uint(origin.get(k), 64 if k in ("cookie", "slot_generation") else 32)
                       for k in ("cookie", "slot_generation", "context_generation",
                                 "output_epoch", "identity_epoch", "attempt_id",
                                 "source", "index", "frame_control",
                                 "sequence_control", "tid"))):
        return fail("host_origin_payload_missing")
    if (origin["cookie"] == 0 or origin["slot_generation"] == 0 or
            origin["attempt_id"] == 0 or origin["source"] not in (1, 2) or
            origin["tid"] > 15 or origin["frame_control"] > 0xffff or
            origin["sequence_control"] > 0xffff):
        return fail("host_origin_payload_invalid")

    qid = scalars.get("NativeStaCompletionEvent0FirmwareQid")
    boundary = scalars.get("NativeStaCompletionEvent0QueueIndex")
    ring = scalars.get("NativeStaCompletionEvent0RingCount")
    queued = scalars.get("NativeStaCompletionEvent0Queued")
    cur = scalars.get("NativeStaCompletionEvent0Cur")
    tail = scalars.get("NativeStaCompletionEvent0Tail")
    ssn = scalars.get("NativeStaCompletionEvent0Ssn")
    if (not _uint(qid, 16) or not _uint(ring, 32) or ring == 0 or
            ring > MAX_RING_COUNT or ring & (ring - 1) or
            not all(_uint(v, 32) for v in (boundary, queued, tail)) or
            not _uint(cur, 16) or not _uint(ssn, 16) or
            boundary >= ring or tail >= ring or
            queued == 0 or queued >= ring or
            boundary != (ssn & (ring - 1))):
        return fail("queue_geometry_invalid")
    distance = (boundary - tail) & (ring - 1)
    if distance != 1 or distance > queued:
        return fail("exclusive_interval_not_single_slot")
    if ((cur & (ring - 1)) != ((tail + queued) & (ring - 1))):
        return fail("queue_cursor_mismatch")
    candidate_index = scalars.get("NativeStaCompletionEvent0TxCommandCandidateIndex")
    raw_origin_fields = {
        "cookie": "Cookie", "slot_generation": "SlotGeneration",
        "context_generation": "ContextGeneration", "output_epoch": "OutputEpoch",
        "identity_epoch": "IdentityEpoch", "attempt_id": "AttemptId",
        "source": "Source", "index": "Index", "frame_control": "FrameControl",
        "sequence_control": "SequenceControl", "tid": "Tid",
    }
    scalar_origin_matches = all(
        scalars.get("NativeStaCompletionEvent0HostOrigin" + suffix) == value
        for field, suffix in raw_origin_fields.items()
        for value in (origin[field],))
    if (not _uint(candidate_index, 32) or candidate_index != origin["index"] or
            host_origin.get("command_header_index") != candidate_index or
            host_origin.get("host_origin_queue_id") != qid or
            host_origin.get("exact_response_tuple_match") is not
                bool(presence & HAS_TXCMD_UNIQUE_CANDIDATE) or
            not scalar_origin_matches or origin["index"] != tail or
            host_origin.get("command_header_index") != origin["index"]):
        return fail("host_origin_not_interval_slot")
    driver_generation = scalars.get("NativeStaCompletionEvent0DriverGeneration")
    output_epoch = scalars.get("NativeStaCompletionEvent0OutputEpoch")
    if (not _uint(driver_generation, 32) or
            origin["context_generation"] != driver_generation or
            not _uint(output_epoch, 32) or
            origin["output_epoch"] != output_epoch):
        return fail("host_origin_epoch_mismatch")

    return {
        "report_schema": REPORT_SCHEMA,
        "derived_from_schema4": True,
        "reference": reference,
        "queue_processed": True,
        "queue_processed_basis": "single_slot_tx_rsp_scd_contract",
        "queue_processed_reason": None,
        "device_status": status,
        "strict_header_match": strict_match,
        "peer_receipt": "unknown",
        "evidence": {
            "qid": qid, "slot": origin["index"],
            "exclusive_boundary": boundary, "ring_count": ring,
            "exclusive_distance": distance, "queued": queued,
            "frame_count": 1, "driver_context_generation": driver_generation,
            "output_epoch": output_epoch,
            "identity_epoch_present": True,
            "identity_epoch_zero_is_valid": origin["identity_epoch"] == 0,
            "publication_source": publication_source,
            "terminal_reason_raw": TX_RSP_SINGLE_RECLAIM_COMPLETED,
            "related_cut_lost_count": scalars.get(
                "NativeStaCompletionRelatedCutLostCount"),
            "related_record_dropped_count": scalars.get(
                "NativeStaCompletionRelatedRecordDroppedCount"),
            "strict_candidate_count": scalars.get(
                "NativeStaCompletionEvent0TxCommandCandidateCount"),
            "strict_bit29": bool(presence & HAS_TXCMD_UNIQUE_CANDIDATE),
        },
        "limits": [
            "Queue processed/reclaimed under the ordinary TX_RSP contract; not over-air delivery.",
            "Firmware status, exact header match, and peer receipt are separate claims.",
            "No live queue read, new cookie, RF action, or kernel behavior was used.",
        ],
    }


def _identity_matches(header: dict, sample: dict) -> bool:
    identity = header.get("identity")
    if not isinstance(identity, dict) or header.get("identity_error") is not None:
        return False
    boot = identity.get("boot_epoch")
    os_build = identity.get("os_build")
    candidate = identity.get("candidate_build_expected")
    uuid = identity.get("loaded_kext_uuid")
    expected_uuid = header.get("expected_loaded_kext_uuid")
    return (type(boot) is int and boot > 0 and
            boot == header.get("expected_boot_epoch") == sample.get("boot_epoch") and
            isinstance(os_build, str) and bool(os_build) and
            os_build == header.get("expected_os_build") == sample.get("os_build") and
            isinstance(candidate, str) and bool(candidate) and
            candidate == header.get("expected_candidate_build") == sample.get("candidate_build") and
            isinstance(uuid, str) and bool(uuid) and
            isinstance(expected_uuid, str) and bool(expected_uuid) and
            uuid == expected_uuid == sample.get("loaded_kext_uuid"))


def analyze_capture(rows: Iterable[dict], input_sha256: str) -> dict:
    records = list(rows)
    headers = [row for row in records if row.get("record_type") == "header"]
    footers = [row for row in records if row.get("record_type") == "footer"]
    if len(headers) != 1 or len(footers) != 1:
        raise ValueError("capture_requires_one_header_and_footer")
    header = headers[0]
    reports: List[dict] = []
    seen = set()
    sample_count = 0
    identity_checks = []
    for row in records:
        if row.get("record_type") != "sample":
            continue
        sample_count += 1
        scalars = row.get("completion_scalars")
        if not isinstance(scalars, dict) or scalars.get("NativeStaCompletionEvent0Present") != 1:
            continue
        identity_ok = _identity_matches(header, row)
        identity_checks.append(identity_ok)
        derived = classify_schema4_cut(
            scalars, row.get("completion_host_origin"),
            identity_ok)
        signature = json.dumps(derived, sort_keys=True, separators=(",", ":"))
        if signature not in seen:
            seen.add(signature)
            derived["sample_reference"] = {
                "sample_index": row.get("sample_index"),
                "captured_at": row.get("captured_at"),
            }
            reports.append(derived)
    return {
        "report_schema": REPORT_SCHEMA,
        "input_sha256": input_sha256,
        "capture_identity": {
            "matches_header_for_classified_samples": bool(identity_checks) and
                all(identity_checks),
            "candidate_build": header.get("expected_candidate_build"),
            "os_build": header.get("expected_os_build"),
        },
        "sample_count": sample_count,
        "unique_tx_rsp_cut_count": len(reports),
        "cuts": reports,
        "limits": [
            "A true queue_processed value means host queue processing/reclaim only.",
            "device_status, strict_header_match, and peer_receipt are independent layers.",
            "peer_receipt remains unknown without independent peer evidence.",
        ],
    }


def read_jsonl(path: Path) -> tuple[list, str]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return rows, hashlib.sha256(raw).hexdigest()


def write_private_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="existing private Test100 collector JSONL")
    parser.add_argument("--output", required=True, type=Path,
                        help="new private report path; existing files are not overwritten")
    args = parser.parse_args(argv)
    rows, digest = read_jsonl(args.input)
    report = analyze_capture(rows, digest)
    write_private_report(args.output, report)
    print(json.dumps({"report": str(args.output),
                      "unique_tx_rsp_cut_count": report["unique_tx_rsp_cut_count"],
                      "queue_processed_count": sum(
                          cut.get("queue_processed") is True for cut in report["cuts"]),
                      "report_schema": report["report_schema"]},
                     separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
