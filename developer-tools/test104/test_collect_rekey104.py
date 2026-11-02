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
from live_key105 import FIELDS as LIVE_KEY_FIELDS, PREFIX as LIVE_KEY_PREFIX


UUID = "17D05CC1-2351-3A74-BAAD-77F67E362577"
BUILD = "25G332-Test104"


def auth_blob(*, event=None, events=None, duplicate_in_first=False):
    if events is None:
        events = [event] if event is not None else []
    live_events = list(events[:16])
    header = base.AUTH_HEADER.pack(
        base.AUTH_MAGIC, 1, base.AUTH_HEADER.size, base.AUTH_EVENT.size,
        16, 2, 2, 0, len(live_events), 0, 1, 5, 2, 8,
        2 if duplicate_in_first else 0, 1 if duplicate_in_first else 0)
    raw = bytearray(base.AUTH_SIZE)
    raw[:len(header)] = header
    for index, current in enumerate(live_events):
        encoded = base.AUTH_EVENT.pack(*current)
        offset = base.AUTH_HEADER.size + index * base.AUTH_EVENT.size
        raw[offset:offset + len(encoded)] = encoded
    if duplicate_in_first and live_events:
        encoded = base.AUTH_EVENT.pack(*live_events[0])
        offset = base.AUTH_HEADER.size + 16 * base.AUTH_EVENT.size
        raw[offset:offset + len(encoded)] = encoded
    return bytes(raw)


def make_hcmd_service(*, include_row=True, sequence_bundle=False):
    rows = []
    if sequence_bundle:
        def encode(serial, phase, *, flags, result=0, result_detail=0,
                   packet_length=0, payload_length=0):
            return struct.pack("<QQ16I", serial, serial * 1000000, 5, 5,
                phase, 1, 0x17, 1, 3, 0, 5, 5, flags, result,
                result_detail, packet_length, payload_length, 0)

        rows.extend([
            encode(1, 1, flags=(1 << 2) | (1 << 4), result=0),
            encode(2, 14, flags=(1 << 4) | (1 << 13) | (1 << 14) |
                   (1 << 15) | (13 << 20) | (1 << 17) | (1 << 19),
                   result=7, payload_length=1),
            encode(3, 15, flags=(1 << 4) | (1 << 13) | (1 << 14) |
                   (1 << 17) | (1 << 19), result=8, payload_length=1),
        ])
    elif include_row:
        rows.append(struct.pack("<QQ16I", 1, 123456789, 5, 5, 1, 1,
            0x17, 1, 0, 0, 64, 64, 1 << 4, 0, 0, 48, 4, 0))
    row_count = len(rows)
    start = 1 if row_count else 0
    end = start + row_count - 1 if row_count else 0
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


def live_key_sequence_properties():
    props = {LIVE_KEY_PREFIX + key: 0 for key in LIVE_KEY_FIELDS}
    values = {
        "Schema": 2, "RevisionBegin": 2, "RevisionEnd": 2,
        "SampleMonotonicNs": 200000000, "OwnerGeneration": 5,
        "OwnerOutputEpoch": 7, "OwnerContextStable": 1,
        "RxSequencePresent": 1, "RxSequenceStable": 1,
        "RxSequenceSerial": 3, "RxSequenceMonotonicNs": 123456789,
        "RxSequenceDriverGeneration": 5,
        "RxSequenceFirmwareGeneration": 5,
        "RxSequencePhase": 14, "RxSequenceSource": 1,
        "RxSequenceCommandId": 0x17, "RxSequenceGroupId": 1,
        "RxSequenceVersion": 3, "RxSequenceQid": 0,
        "RxSequenceIndex": 4, "RxSequenceHeaderSequence": 4,
        "RxSequenceFlags": (1 << 4) | (1 << 13) | (1 << 14) |
                            (1 << 15) | (15 << 20) |
                            (1 << 17) | (1 << 19),
        "RxSequenceResult": 9, "RxSequencePacketLength": 0,
        "RxSequencePayloadLength": 1,
        "RxSequenceOriginSubmitSerial": 1,
    }
    props.update({LIVE_KEY_PREFIX + key: value for key, value in values.items()})
    return props


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

    def test_auth_parser_decodes_unsigned_command_submit_serial(self):
        event = (8, 200, 0, 1, 5, 2, 7, 15, 22, 1, 4, -1,
                 1 << 15, 0x89ABCDEF)
        parsed = collector._decode_auth_trace(auth_blob(event=event))
        self.assertEqual(parsed["schema"], 1)
        origin = parsed["events"][0]["command_submit_origin"]
        self.assertEqual(origin["status"], "origin_serial_present")
        self.assertEqual(origin["serial"], 0xFFFFFFFF89ABCDEF)

    def test_auth_parser_labels_software_crypto_without_firmware_serial(self):
        event = (8, 200, 0, 1, 5, 2, 7, 15, 22, 1, 5, 0, 0, 0)
        parsed = collector._decode_auth_trace(auth_blob(event=event))
        self.assertEqual(
            parsed["events"][0]["command_submit_origin"]["status"],
            "software_crypto_no_firmware_command")

    def test_auth_parser_rejects_unexpected_origin_flags(self):
        event = (8, 200, 0, 1, 5, 2, 7, 15, 22, 1, 4, 2,
                 (1 << 15) | (1 << 6), 0x89ABCDEF)
        parsed = collector._decode_auth_trace(auth_blob(event=event))
        self.assertEqual(
            parsed["events"][0]["command_submit_origin"]["status"],
            "invalid_origin_witness_flags")

    def test_sample_auth_and_hcmd_cuts_join_exact_origin_together(self):
        service = make_hcmd_service(sequence_bundle=True)
        service[collector.AUTH_PROPERTY] = auth_blob(events=[
            (1, 1_000_900, 0, 1, 5, 2, 7, 1, 0, 1, 1, 0, 0, 0),
            (2, 1_001_000, 0, 1, 5, 2, 7, 4, 13, 1, 4, 0,
             1 << 6, (2 << 24) | 5),
            (3, 1_001_100, 0, 1, 5, 2, 7, 15, 22, 1, 4, 0,
             1 << 15, 1),
        ])
        raw_ioreg = plistlib.dumps([service], fmt=plistlib.FMT_BINARY)

        def ioreg(_argv, **_kwargs):
            return raw_ioreg

        def ifconfig(_argv, **_kwargs):
            return (b"en1: flags=8863<UP,RUNNING> mtu 1500\n"
                    b" status: active\n")

        ticks = FakeClock()
        point = collector.sample_once(BUILD,
            {"boot_epoch": 1793525969, "os_build": "25G332",
             "loaded_kext_uuid": UUID},
            ioreg_fn=ioreg, ifconfig_fn=ifconfig,
            monotonic_ns=lambda: int(ticks.monotonic() * 1_000_000_000) + 100,
            wall_now=lambda: datetime.datetime.fromisoformat(
                "2026-11-01T10:00:00+08:00"))
        correlation = collector.correlate_key_lifecycle(
            point["hcmd"], point["auth_trace"])
        join = correlation["lifecycles"][0]["origin_submit_join"]
        self.assertEqual(join["status"], "exact_command_submit_origin_match")
        self.assertEqual(join["origin_submit_serial"], 1)
        self.assertEqual(join["sequence_rows_status"], "rx_tx_origin_rows_match")
        self.assertTrue(join["same_association_lifecycle_observed"])

    def test_sample_reads_whole_hcmd_ring_and_emits_only_boolean_link_state(self):
        service = make_hcmd_service()
        service[collector.AUTH_PROPERTY] = auth_blob()
        service.update(live_key_sequence_properties())
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
        self.assertEqual(
            point["live_key"]["observations"]["rxsequence"]["origin_submit_serial"],
            1)
        self.assertEqual(point["live_key"]["key_sequence_bundle"]["status"],
                         "partial_sequence_current_submit_unknown")
        self.assertEqual(point["key_sequence_trace"]["status"],
                         "stable_complete_cut")
        self.assertEqual(point["key_sequence_trace"]["events"], [])
        raw_hcmd = point["raw_osdata"]["NativeHcmdRxTrace"]
        self.assertFalse(raw_hcmd["retained"])
        self.assertEqual(raw_hcmd["length"], len(service[hcmd.TRACE_PROPERTY]))
        self.assertEqual(raw_hcmd["sha256"],
                         hashlib.sha256(service[hcmd.TRACE_PROPERTY]).hexdigest())
        self.assertIsNone(raw_hcmd["base64"])
        self.assertEqual(raw_hcmd["status"],
                         "hash_and_length_only_sensitive_sequence_fields")
        raw_auth = point["raw_osdata"][collector.AUTH_PROPERTY]
        self.assertTrue(raw_auth["retained"])
        self.assertEqual(raw_auth["length"], base.AUTH_SIZE)
        self.assertEqual(base64.b64decode(raw_auth["base64"]),
                         service[collector.AUTH_PROPERTY])
        encoded = json.dumps(point, sort_keys=True)
        self.assertNotIn("192.0.2.3", encoded)
        self.assertNotIn("SSID", encoded)

    def test_sample_exposes_exact_origin_submit_bundle(self):
        service = make_hcmd_service(sequence_bundle=True)
        raw_ioreg = plistlib.dumps([service], fmt=plistlib.FMT_BINARY)

        def ioreg(_argv, **_kwargs):
            return raw_ioreg

        def ifconfig(_argv, **_kwargs):
            return (b"en1: flags=8863<UP,RUNNING> mtu 1500\n"
                    b" status: active\n")

        ticks = FakeClock()
        point = collector.sample_once(BUILD,
            {"boot_epoch": 1793525969, "os_build": "25G332",
             "loaded_kext_uuid": UUID},
            ioreg_fn=ioreg, ifconfig_fn=ifconfig,
            monotonic_ns=lambda: int(ticks.monotonic() * 1_000_000_000) + 100,
            wall_now=lambda: datetime.datetime.fromisoformat(
                "2026-11-01T10:00:00+08:00"))
        trace = point["key_sequence_trace"]
        self.assertEqual(trace["status"], "stable_complete_cut")
        self.assertEqual([event["kind"] for event in trace["events"]],
                         ["rx_replay_floor", "tx_sequence_counter"])
        self.assertEqual(trace["events"][0]["max_tid"], 13)
        self.assertEqual(trace["events"][0]["origin_submit_serial"], 1)
        self.assertEqual(trace["bundles"][0]["status"],
                         "same_origin_submit_serial")
        self.assertFalse(trace["bundles"][0]["firmware_key_install_proven"])

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
