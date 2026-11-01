from __future__ import annotations

import datetime
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest

import collect_rekey104 as collector
import collect_rekey100 as base
import hcmd_rx_trace_test103 as hcmd


UUID = "17D05CC1-2351-3A74-BAAD-77F67E362577"
BUILD = "25G332-Test104"


def auth_blob(*, event=None, duplicate_in_first=False):
    header = base.AUTH_HEADER.pack(
        base.AUTH_MAGIC, 1, base.AUTH_HEADER.size, base.AUTH_EVENT.size,
        16, 2, 2, 0, 1 if event else 0, 0, 1, 5, 2, 8,
        2 if duplicate_in_first else 0, 1 if duplicate_in_first else 0)
    raw = bytearray(base.AUTH_SIZE)
    raw[:len(header)] = header
    if event is not None:
        encoded = base.AUTH_EVENT.pack(*event)
        offset = base.AUTH_HEADER.size
        raw[offset:offset + len(encoded)] = encoded
        if duplicate_in_first:
            offset = base.AUTH_HEADER.size + 16 * base.AUTH_EVENT.size
            raw[offset:offset + len(encoded)] = encoded
    return bytes(raw)


def make_hcmd_service(*, include_row=True):
    rows = []
    if include_row:
        rows.append(struct.pack("<QQ16I", 1, 123456789, 5, 5, 1, 1,
            0x17, 1, 0, 0, 64, 64, 1 << 4, 0, 0, 48, 4, 0))
    row_count = len(rows)
    start = 1 if row_count else 0
    end = start
    header = struct.pack("<4I2Q7I2Q2I", hcmd.WIRE_MAGIC,
        hcmd.WIRE_SCHEMA, hcmd.WIRE_HEADER_BYTES, hcmd.WIRE_ENTRY_BYTES,
        2, 2, 5, 0, 0, row_count, 0, 0, 0, start, end, 1, 1)
    markers = {
        "NativeHcmdRxTraceSchema": hcmd.WIRE_SCHEMA,
        "NativeHcmdRxTraceBlobLength": len(header) + sum(map(len, rows)),
        "NativeHcmdRxTraceVersionBegin": 2,
        "NativeHcmdRxTraceVersionEnd": 2,
        "NativeHcmdRxTraceWindowStartSerial": start,
        "NativeHcmdRxTraceWindowEndSerial": end,
        "NativeHcmdRxTraceOwnerGeneration": 5,
        "NativeHcmdRxTraceOwnerWatchdogSequence": 0,
        "NativeHcmdRxTraceOwnerWatchdogSequencePresent": 0,
        "NativeHcmdRxTraceRowCount": row_count,
        "NativeHcmdRxTraceDroppedCount": 0,
        "NativeHcmdRxTraceOverwrittenCount": 0,
        "NativeHcmdRxTraceGapCount": 0,
        "NativeHcmdRxTraceSnapshotStable": 1,
        "NativeHcmdRxTraceSnapshotComplete": 1,
    }
    service = {
        "NativeTestBuild": BUILD,
        "NativeHcmdRxTrace": header + b"".join(rows),
        "NativeHcmdRxTracePublishRevisionBegin": 2,
        "NativeHcmdRxTracePublishRevisionEnd": 2,
    }
    service.update(markers)
    return service


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, value):
        self.value += value


def fake_point(*, rows=None, events=None):
    return {
        "captured_at": "2026-11-01T10:00:00+08:00",
        "host_monotonic_lower_ns": 100,
        "host_monotonic_upper_ns": 200,
        "identity": {"candidate_build": BUILD},
        "numeric_counters": {},
        "hcmd": {
            "snapshot_stable": True,
            "snapshot_complete": True,
            "header": {"version_begin": 2, "version_end": 2},
            "rows": rows or [],
            "key_response_slot": {"status": "slot_not_published"},
        },
        "auth_trace": {"snapshot_status": "stable", "events": events or []},
        "link_trace": {"snapshot_status": "stable", "events": []},
        "en1": {"present": True, "up": True, "running": True,
                "link_active": True, "ipv4_present": True,
                "ipv6_present": True},
    }


class CollectRekey104Tests(unittest.TestCase):
    def test_auth_parser_keeps_numeric_event_and_deduplicates_same_cut_copy(self):
        event = (4, 100, 0, 1, 5, 2, 7, 4, 13, 1, 4, -16, 64, 0x02000040)
        parsed = collector._decode_auth_trace(
            auth_blob(event=event, duplicate_in_first=True))
        self.assertEqual(parsed["snapshot_status"], "stable")
        self.assertEqual(len(parsed["events"]), 1)
        self.assertEqual(parsed["events"][0]["result"], -16)
        self.assertEqual(parsed["events"][0]["detail"], 0x02000040)

    def test_sample_reads_whole_hcmd_ring_and_emits_only_boolean_link_state(self):
        service = make_hcmd_service()
        service[collector.AUTH_PROPERTY] = auth_blob()
        raw_ioreg = plistlib.dumps([service], fmt=plistlib.FMT_BINARY)

        class Ticks:
            value = 1000
            def __call__(self):
                self.value += 100
                return self.value

        def ioreg(argv, **_kwargs):
            self.assertIn("AirportItlwm", argv)
            return raw_ioreg

        def ifconfig(argv, **_kwargs):
            self.assertEqual(argv[-1], "en1")
            return (b"en1: flags=8863<UP,RUNNING> mtu 1500\n"
                    b" status: active\n inet 192.0.2.3\n")

        point = collector.sample_once(BUILD,
            {"boot_epoch": 1793525969, "os_build": "25G332",
             "loaded_kext_uuid": UUID},
            ioreg_fn=ioreg, ifconfig_fn=ifconfig, monotonic_ns=Ticks(),
            wall_now=lambda: datetime.datetime.fromisoformat(
                "2026-11-01T10:00:00+08:00"))
        self.assertEqual(len(point["hcmd"]["rows"]), 1)
        self.assertEqual(point["hcmd"]["rows"][0]["index"], 64)
        self.assertTrue(point["hcmd"]["snapshot_complete"])
        self.assertEqual(point["identity"]["loaded_kext_uuid"], UUID)
        self.assertTrue(point["en1"]["ipv4_present"])
        raw_hcmd = point["raw_osdata"]["NativeHcmdRxTrace"]
        self.assertTrue(raw_hcmd["retained"])
        self.assertEqual(raw_hcmd["length"], len(service[hcmd.TRACE_PROPERTY]))
        self.assertEqual(raw_hcmd["sha256"],
                         hashlib.sha256(service[hcmd.TRACE_PROPERTY]).hexdigest())
        self.assertEqual(base64.b64decode(raw_hcmd["base64"]),
                         service[hcmd.TRACE_PROPERTY])
        raw_auth = point["raw_osdata"][collector.AUTH_PROPERTY]
        self.assertTrue(raw_auth["retained"])
        self.assertEqual(raw_auth["length"], base.AUTH_SIZE)
        self.assertEqual(base64.b64decode(raw_auth["base64"]),
                         service[collector.AUTH_PROPERTY])
        encoded = json.dumps(point, sort_keys=True)
        self.assertNotIn("192.0.2.3", encoded)
        self.assertNotIn("SSID", encoded)

    def test_capture_records_unique_attempt_indexes_and_no_anchor_is_not_pass(self):
        clock = FakeClock()
        calls = 0

        def sample_reader(_build, _identity):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("fixture read failure")
            return fake_point()

        with tempfile.TemporaryDirectory() as temp:
            os.chmod(temp, 0o700)
            path = Path(temp) / "run.jsonl"
            result = collector.capture(path, boot_epoch=1793525969,
                expected_uuid=UUID, expected_build=BUILD, duration=1.0,
                interval=0.25,
                identity_reader=lambda boot, _build: {
                    "boot_epoch": boot, "os_build": base.EXPECTED_OS_BUILD,
                    "loaded_kext_uuid": UUID},
                sample_reader=sample_reader, monotonic=clock.monotonic,
                sleep=clock.sleep,
                wall_now=lambda: datetime.datetime.fromisoformat(
                    "2026-11-01T10:00:00+08:00"))
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            records = [row for row in rows if row["record_type"] in
                       ("sample", "sample_error")]
            self.assertEqual([row["sample_index"] for row in records],
                             list(range(1, len(records) + 1)))
            footer = rows[-1]
            self.assertEqual(footer["record_type"], "footer")
            self.assertEqual(result["terminal_status"], "duration_elapsed_no_anchor")
            self.assertFalse(footer["wifi_stability_pass"])
            self.assertFalse(footer["key_install_success_proven"])
            self.assertFalse(footer["peer_ack_proven"])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_priming_does_not_consume_rows_from_unstable_cut(self):
        row = {"driver_generation": 5, "serial": 10}
        event = {"diagnostic_instance": 1, "sequence": 3}
        point = fake_point(rows=[row])
        point["auth_trace"]["events"] = [event]
        point["hcmd"]["snapshot_stable"] = False
        seen_hcmd, seen_auth = set(), set()
        collector._prime_seen(point, seen_hcmd, seen_auth)
        self.assertEqual(seen_hcmd, set())
        self.assertEqual(seen_auth, set())


if __name__ == "__main__":
    unittest.main()
