from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools" / "test104"))

import collect_rekey104 as collector
import collect_rekey100 as base
import hcmd_rx_trace_test103 as hcmd
from test_collect_rekey104 import (
    FakeClock,
    live_key_sequence_properties,
    make_hcmd_service,
)


FIXTURE = Path(__file__).parent / "fixtures" / "test111-real-group2-sample.json"
BUILD = "25G332-Test111"
HCTX_ENTRY = struct.Struct("<QQ16I")


def _service_with_real_group2_fixture() -> tuple[dict, dict]:
    fixture = json.loads(FIXTURE.read_text())
    raw_group2 = base64.b64decode(fixture["group2_osdata"]["base64"], validate=True)
    if (len(raw_group2) != fixture["group2_osdata"]["length"] or
            hashlib.sha256(raw_group2).hexdigest() !=
            fixture["group2_osdata"]["sha256"]):
        raise AssertionError("real_group2_fixture_integrity_mismatch")

    service = make_hcmd_service(sequence_bundle=True)
    service["NativeTestBuild"] = BUILD
    service[base.GROUP2_PROPERTY] = raw_group2
    service.update(live_key_sequence_properties())
    # These values are test sentinels standing in for host-side sequence
    # counters. The output serializer must never persist them.
    props = {
        "RxSequenceResult": 0x03040506,
        "RxSequenceResultDetail": 0x00000102,
    }
    service.update({"NativeKeyLive" + key: value for key, value in props.items()})

    # Put two recognizable 48-bit sequence values into real HCTX wire rows.
    blob = bytearray(service[hcmd.TRACE_PROPERTY])
    for index in range(3):
        offset = hcmd.WIRE_HEADER_BYTES + index * hcmd.WIRE_ENTRY_BYTES
        values = list(HCTX_ENTRY.unpack_from(blob, offset))
        phase = values[4]
        if phase == 14:
            values[13], values[14] = 0x03040506, 0x00000102
        elif phase == 15:
            values[13], values[14] = 0x000D0E0F, 0x000A0B0C
        blob[offset:offset + hcmd.WIRE_ENTRY_BYTES] = HCTX_ENTRY.pack(*values)
    service[hcmd.TRACE_PROPERTY] = bytes(blob)
    service["NativeHcmdRxTraceBlobLength"] = len(blob)
    return fixture, service


class Test112CollectorPrivacyTests(unittest.TestCase):
    def test_redaction_preserves_ring_overwrite_and_origin_metadata(self):
        decoded = {
            "schema": "test103-hcmd-rx-observation/v1",
            "status": "partial_cut",
            "snapshot_stable": True,
            "snapshot_complete": False,
            "blob_sha256": "fixture-digest",
            "blob_length": 164,
            "header": {
                "schema": 1, "blob_length": 164,
                "version_begin": 6, "version_end": 6,
                "owner_generation": 5, "owner_watchdog_sequence": 0,
                "owner_watchdog_sequence_present": 0, "row_count": 1,
                "dropped_count": 7, "overwritten_count": 4,
                "gap_count": 3, "window_start_serial": 14,
                "window_end_serial": 14, "stable": 1, "complete": 0,
            },
            "rows": [{
                "serial": 14, "driver_monotonic_ns": 1234,
                "driver_generation": 5, "firmware_generation": 5,
                "phase": 14, "source": 1, "command_id": 0x17,
                "group_id": 1, "version": 3, "qid": 0,
                "index": 4, "header_sequence": 4,
                "flags": 1 << 13, "result": 0x03040506,
                "result_detail": 0x00000102,
                "packet_length": 0, "payload_length": 0xABCDEF01,
                "reserved0": 0,
            }],
            "key_response_slot": {
                "schema": "test103-key-response-slot/v1",
                "status": "latest_target_event", "event": None,
            },
        }
        selected = collector._selected_hcmd(decoded)
        self.assertEqual(selected["header"]["dropped_count"], 7)
        self.assertEqual(selected["header"]["overwritten_count"], 4)
        self.assertEqual(selected["header"]["gap_count"], 3)
        self.assertFalse(selected["snapshot_complete"])
        row = selected["rows"][0]
        self.assertEqual(row["serial"], 14)
        self.assertEqual(row["driver_monotonic_ns"], 1234)
        self.assertEqual(row["payload_length"], 0xABCDEF01)
        self.assertTrue(row["sequence_value_present"])
        self.assertTrue(row["sequence_value_redacted"])
        self.assertNotIn("result", row)
        self.assertNotIn("result_detail", row)
        self.assertEqual(decoded["rows"][0]["result"], 0x03040506)
        self.assertTrue(selected["key_response_slot_is_separate_sticky_evidence"])

        unsafe_source = {
            "NativeHcmdRxTrace": {
                "present": True,
                "length": 3,
                "sha256": None,
                "base64": base64.b64encode(b"PN!").decode("ascii"),
                "retained": True,
            }
        }
        writer_edge = collector._selected_raw_osdata(unsafe_source)
        self.assertIsNone(writer_edge["NativeHcmdRxTrace"]["base64"])
        self.assertFalse(writer_edge["NativeHcmdRxTrace"]["retained"])
        self.assertEqual(writer_edge["NativeHcmdRxTrace"]["length"], 3)
        self.assertEqual(writer_edge["NativeHcmdRxTrace"]["sha256"],
                         hashlib.sha256(b"PN!").hexdigest())

    def test_real_group2_sample_is_kept_with_same_boot_identity_and_time(self):
        fixture, service = _service_with_real_group2_fixture()
        raw_plist = plistlib.dumps([service], fmt=plistlib.FMT_BINARY)
        ticks = iter((100_000_000, 110_000_000, 120_000_000, 130_000_000))

        point = collector.sample_once(
            BUILD,
            fixture["identity"],
            ioreg_fn=lambda *_args, **_kwargs: raw_plist,
            ifconfig_fn=lambda *_args, **_kwargs:
                b"en1: flags=8863<UP,RUNNING> mtu 1500\n status: active\n",
            monotonic_ns=lambda: next(ticks),
            wall_now=lambda: datetime.datetime.fromisoformat(
                "2026-11-02T15:04:15+08:00"),
        )

        self.assertEqual(point["identity"], fixture["identity"])
        self.assertEqual(point["captured_at"], "2026-11-02T15:04:15+08:00")
        self.assertLessEqual(point["host_monotonic_lower_ns"],
                             point["host_monotonic_upper_ns"])
        self.assertEqual(point["group2_tx_trace"]["snapshot_status"], "stable")
        self.assertEqual(point["group2_tx_trace"]["event_count"], 7)
        self.assertEqual(len(point["group2_tx_trace"]["events"]), 7)
        self.assertFalse(point["group2_tx_trace"]["peer_ack_proven"])

        # Re-emit this point through the real JSONL capture path. This checks
        # that HCTX, NativeKeyLive, Group2, identity, and timestamps stay in
        # one sample envelope rather than being joined across samples.
        clock = FakeClock()
        with tempfile.TemporaryDirectory() as temp:
            os.chmod(temp, 0o700)
            output = Path(temp) / "test112.jsonl"
            result = collector.capture(
                output,
                boot_epoch=fixture["identity"]["boot_epoch"],
                expected_uuid=fixture["identity"]["loaded_kext_uuid"],
                expected_build=BUILD,
                duration=0.25,
                interval=0.25,
                identity_reader=lambda boot, _build: {
                    "boot_epoch": boot,
                    "os_build": fixture["identity"]["os_build"],
                    "loaded_kext_uuid": fixture["identity"]["loaded_kext_uuid"],
                },
                sample_reader=lambda _build, _identity: point,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
                wall_now=lambda: datetime.datetime.fromisoformat(
                    "2026-11-02T15:04:15+08:00"),
            )
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            sample = next(row for row in rows if row["record_type"] == "sample")
            self.assertEqual(result["sample_count"], 1)
            self.assertEqual(sample["identity"], fixture["identity"])
            self.assertEqual(sample["captured_at"], point["captured_at"])
            self.assertEqual(sample["host_monotonic_lower_ns"],
                             point["host_monotonic_lower_ns"])
            self.assertEqual(sample["host_monotonic_upper_ns"],
                             point["host_monotonic_upper_ns"])
            self.assertEqual(sample["group2_tx_trace"]["event_count"], 7)
            self.assertEqual(sample["raw_osdata"][base.GROUP2_PROPERTY]["sha256"],
                             fixture["group2_osdata"]["sha256"])

            hctx = sample["raw_osdata"]["NativeHcmdRxTrace"]
            self.assertFalse(hctx["retained"])
            self.assertIsNone(hctx["base64"])
            self.assertEqual(hctx["length"], len(service[hcmd.TRACE_PROPERTY]))
            self.assertEqual(hctx["sha256"],
                             hashlib.sha256(service[hcmd.TRACE_PROPERTY]).hexdigest())
            self.assertGreaterEqual(
                sample["hcmd"]["sequence_value_rows_redacted_count"], 2)
            for entry in sample["hcmd"]["rows"]:
                if entry.get("phase") in (14, 15):
                    self.assertNotIn("result", entry)
                    self.assertNotIn("result_detail", entry)
                    self.assertTrue(entry["sequence_value_redacted"])

            key_events = sample["key_sequence_trace"]["events"]
            self.assertEqual(len(key_events), 2)
            for event in key_events:
                self.assertNotIn("counter_value", event)
                self.assertTrue(event["sequence_value_redacted"])
                self.assertEqual(event["origin_submit_serial"], 1)
                self.assertIn("serial", event)
                self.assertIn("monotonic_ns", event)

            live = sample["live_key"]
            self.assertNotIn("RxSequenceResult", live["scalars"])
            self.assertNotIn("RxSequenceResultDetail", live["scalars"])
            self.assertNotIn("Result", live["observations"]["rxsequence"]["entry"])
            self.assertNotIn("ResultDetail",
                             live["observations"]["rxsequence"]["entry"])
            self.assertEqual(
                live["observations"]["rxsequence"]["origin_submit_serial"], 1)

            serialized = output.read_text()
            for secret_counter in (0x010203040506, 0x0A0B0C0D0E0F):
                self.assertNotIn(str(secret_counter), serialized)
                self.assertNotIn(f"{secret_counter:012x}", serialized.lower())


if __name__ == "__main__":
    unittest.main()
