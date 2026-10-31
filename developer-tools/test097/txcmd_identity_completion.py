#!/usr/bin/env python3
"""Decode bounded numeric NativeStaCompletion snapshots, schemas 1 and 2."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib

PREFIX = "NativeStaCompletion"
HAS_RESPONSE_FC = 1 << 26
HAS_RESPONSE_SEQ = 1 << 27
HAS_TXCMD_SCAN = 1 << 28
HAS_TXCMD_UNIQUE = 1 << 29
HAS_OBSERVER_SERIAL = 1 << 31


def completion_scalars(properties: dict) -> dict[str, int]:
    """Keep only numeric completion properties; omit the rest of ioreg."""
    result: dict[str, int] = {}
    for key, value in properties.items():
        if not isinstance(key, str) or not key.startswith(PREFIX):
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        result[key[len(PREFIX):]] = value
    return result


def decode_scalars(values: dict[str, int]) -> dict:
    if not isinstance(values, dict):
        raise ValueError("completion scalar map must be a dictionary")
    schema = values.get("Schema")
    if schema not in (1, 2):
        raise ValueError("unsupported NativeStaCompletion schema")
    begin = values.get("SnapshotVersionBegin")
    end = values.get("SnapshotVersionEnd")
    if (not isinstance(begin, int) or not isinstance(end, int) or
            begin != end or begin & 1):
        raise ValueError("completion snapshot version is missing, torn, or odd")
    if values.get("SnapshotAvailable") != 1 or values.get("SnapshotComplete") != 1:
        raise ValueError("completion snapshot is unavailable or incomplete")
    if values.get("DroppedCount") != 0:
        raise ValueError("completion observer reports dropped records")

    result = {
        "schema": schema,
        "snapshot_version": begin,
        "next_serial": values.get("NextSerial"),
        "firmware_response_identity_proven": values.get(
            "FirmwareResponseIdentityProven", 0) == 1,
        "peer_receipt_proven": values.get("PeerReceiptProven", 0) == 1,
        "txcmd_identity": {
            "status": "unavailable_in_schema_1" if schema == 1 else "not_observed",
            "observation_scope": (
                "schema 1 has no live TX_CMD identity scan; no inference is made"
                if schema == 1 else
                "host command bytes and local TX_RSP correlation only; not firmware acceptance or peer receipt"
            ),
        },
    }

    event_prefix = "Event0"
    present = values.get(event_prefix + "Present") == 1
    if not present:
        result["txrsp_event"] = None
        return result

    required = ("Kind", "Stage", "TerminalReason", "PresenceFlags",
                "OutputEpoch")
    if any(event_prefix + name not in values for name in required):
        raise ValueError("present TX_RSP event lacks required scalar fields")
    flags = values[event_prefix + "PresenceFlags"]
    if (flags & HAS_OBSERVER_SERIAL) == 0 or values[event_prefix + "Kind"] != 0:
        raise ValueError("Event0 is not a valid retained TX_RSP row")
    result["txrsp_event"] = {
        "kind": values[event_prefix + "Kind"],
        "stage": values[event_prefix + "Stage"],
        "terminal_reason": values[event_prefix + "TerminalReason"],
        "presence_flags": flags,
        "output_epoch": values[event_prefix + "OutputEpoch"],
        "response_frame_control": values.get(event_prefix + "ResponseFrameControl"),
        "response_sequence_control": values.get(event_prefix + "ResponseSequenceControl"),
        "firmware_qid": values.get(event_prefix + "FirmwareQid"),
        "queue_index": values.get(event_prefix + "QueueIndex"),
        "ring_count": values.get(event_prefix + "RingCount"),
        "queued": values.get(event_prefix + "Queued"),
        "tail": values.get(event_prefix + "Tail"),
        "ssn": values.get(event_prefix + "Ssn"),
        "ra_tid": values.get(event_prefix + "RaTid"),
        "status": values.get(event_prefix + "Status"),
    }

    if schema == 1:
        return result

    if (flags & (HAS_RESPONSE_FC | HAS_RESPONSE_SEQ)) != (
            HAS_RESPONSE_FC | HAS_RESPONSE_SEQ):
        raise ValueError("schema 2 TX_RSP row lacks response FC/SC presence")
    scan_present = (flags & HAS_TXCMD_SCAN) != 0
    unique_present = (flags & HAS_TXCMD_UNIQUE) != 0
    if not scan_present:
        if unique_present:
            raise ValueError("unique TX_CMD row is marked without a scan")
        return result

    names = ("TxCommandScanStatus", "TxCommandExpectedCount",
             "TxCommandScannedCount", "TxCommandCandidateCount")
    if any(event_prefix + name not in values for name in names):
        raise ValueError("schema 2 scan is missing bounded interval fields")
    status = values[event_prefix + "TxCommandScanStatus"]
    expected = values[event_prefix + "TxCommandExpectedCount"]
    scanned = values[event_prefix + "TxCommandScannedCount"]
    count = values[event_prefix + "TxCommandCandidateCount"]
    ring_count = values.get(event_prefix + "RingCount", 0)
    queued = values.get(event_prefix + "Queued", 0)
    if (status not in (1, 2) or expected <= 0 or expected > ring_count or
            expected > queued or scanned < 0 or scanned > expected or count < 0 or
            count > scanned):
        raise ValueError("schema 2 scan interval fields are inconsistent")
    if status == 1 and scanned != expected:
        raise ValueError("complete scan did not visit its whole interval")
    if status == 1 and count == 1 and not unique_present:
        raise ValueError("complete single candidate lacks unique-candidate flag")
    if unique_present and (status != 1 or scanned != expected or count != 1):
        raise ValueError("unique candidate is inconsistent with the scan")

    summary = {
        "status": "complete_no_match" if status == 1 and count == 0 else
                  "complete_ambiguous" if status == 1 and count > 1 else
                  "incomplete_scan" if status == 2 else
                  "unique_host_command_candidate",
        "scan_status": status,
        "expected_count": expected,
        "scanned_count": scanned,
        "candidate_count": count,
        "observation_scope": result["txcmd_identity"]["observation_scope"],
    }
    if unique_present:
        field_names = ("TxCommandCandidateIndex", "TxCommandApiGeneration",
                       "TxCommandVersion", "TxCommandFlags",
                       "TxCommandOffloadAssist")
        if any(event_prefix + name not in values for name in field_names):
            raise ValueError("unique candidate lacks command identity fields")
        index = values[event_prefix + "TxCommandCandidateIndex"]
        api = values[event_prefix + "TxCommandApiGeneration"]
        version = values[event_prefix + "TxCommandVersion"]
        if index < 0 or index >= ring_count or api not in (2, 3) or not 0 <= version <= 255:
            raise ValueError("unique candidate has invalid descriptor/API values")
        summary.update(
            descriptor_index=index,
            api_generation=api,
            command_version=version,
            command_flags=values[event_prefix + "TxCommandFlags"],
            offload_assist=values[event_prefix + "TxCommandOffloadAssist"],
        )
    result["txcmd_identity"] = summary
    return result


def decode_ioreg(raw: bytes) -> dict:
    tree = plistlib.loads(raw)
    if not isinstance(tree, list) or len(tree) != 1 or not isinstance(tree[0], dict):
        raise ValueError("expected one AirportItlwm ioreg service dictionary")
    values = completion_scalars(tree[0])
    return decode_scalars(values)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ioreg_plist", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    decoded = decode_ioreg(args.ioreg_plist.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(decoded, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
