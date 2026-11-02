import unittest
import struct

from key_sequence_trace110 import decode_key_sequences
from hcmd_rx_trace_test104 import decode_snapshot


def row(phase, *, serial=2, value=0x010203040506, api=3, tid=0,
        flags=None, generation=7, origin_serial=1):
    if flags is None:
        flags = (1 << 4) | (1 << 14) | (1 << 17) | (1 << 19)
        if phase in (14, 15):
            flags |= 1 << 13
        if phase == 14:
            flags |= (1 << 15) | (tid << 20)
    return {
        "serial": serial, "driver_monotonic_ns": serial * 1000,
        "driver_generation": generation, "firmware_generation": generation,
        "phase": phase, "source": 1,
        "command_id": 0x17, "group_id": 1, "version": api,
        "qid": 0, "index": 41, "header_sequence": 41,
        "flags": flags, "result": value & 0xffffffff,
        "result_detail": value >> 32,
        "packet_length": (origin_serial >> 32) & 0xffffffff,
        "payload_length": origin_serial & 0xffffffff,
    }


def snapshot(rows, *, stable=True, complete=True):
    return {
        "header": {"owner_generation": 7},
        "snapshot_stable": stable, "snapshot_complete": complete,
        "rows": rows,
    }


class KeySequenceDecoderTests(unittest.TestCase):
    def test_existing_hcmd_decoder_accepts_new_phases(self):
        rows = []
        for serial, phase in enumerate((14, 15, 16), start=1):
            rows.append(struct.pack(
                "<QQIIIIIIIIIIIIIIII",
                serial, serial * 1000, 7, 7, phase, 1, 0x17, 1, 3, 0, 41,
                41, (1 << 4) | (1 << 14) | (1 << 13),
                0xABCDEF, 0, 156, 76, 0))
        header = struct.pack(
            "<IIIIQQIIIIIIIQQII", 0x54584348, 1, 84, 80, 4, 4,
            7, 0, 0, 3, 0, 0, 0, 1, 3, 1, 1)
        sample = {
            "read_status": "trace_present",
            "blob": header + b"".join(rows),
            "markers": {
                "NativeHcmdRxTraceSchema": 1,
                "NativeHcmdRxTraceBlobLength": 84 + 3 * 80,
                "NativeHcmdRxTraceVersionBegin": 4,
                "NativeHcmdRxTraceVersionEnd": 4,
                "NativeHcmdRxTraceWindowStartSerial": 1,
                "NativeHcmdRxTraceWindowEndSerial": 3,
                "NativeHcmdRxTraceOwnerGeneration": 7,
                "NativeHcmdRxTraceOwnerWatchdogSequence": 0,
                "NativeHcmdRxTraceOwnerWatchdogSequencePresent": 0,
                "NativeHcmdRxTraceRowCount": 3,
                "NativeHcmdRxTraceDroppedCount": 0,
                "NativeHcmdRxTraceOverwrittenCount": 0,
                "NativeHcmdRxTraceGapCount": 0,
                "NativeHcmdRxTraceSnapshotStable": 1,
                "NativeHcmdRxTraceSnapshotComplete": 1,
            },
            "publish_revision_begin": 2,
            "publish_revision_end": 2,
        }
        decoded = decode_snapshot(sample)
        self.assertEqual(decoded["status"], "stable_complete_cut")
        self.assertEqual([row["phase"] for row in decoded["rows"]],
                         [14, 15, 16])
        self.assertEqual(decoded["add_sta_key_status_events"], [])

    def test_decodes_rx_tx_counters_as_host_evidence_only(self):
        rx = row(14, value=0x010203040506, tid=9)
        tx = row(15, serial=3, value=0x00000000abcdef)
        result = decode_key_sequences(snapshot([rx, tx]))
        self.assertEqual(result["status"], "stable_complete_cut")
        self.assertEqual(result["events"][0]["kind"], "rx_replay_floor")
        self.assertEqual(result["events"][0]["counter_value"], 0x010203040506)
        self.assertEqual(result["events"][0]["max_tid"], 9)
        self.assertEqual(result["events"][0]["origin_submit_serial"], 1)
        self.assertFalse(result["events"][0]["firmware_status_proven"])
        self.assertEqual(result["events"][1]["kind"], "tx_sequence_counter")
        self.assertEqual(result["bundles"][0]["status"],
                         "same_origin_submit_serial")
        self.assertFalse(result["events"][1]["peer_acceptance_proven"])

    def test_origin_serial_blocks_qid_index_reuse_join(self):
        rx = row(14, serial=3, origin_serial=0x100000001, tid=13)
        tx = row(15, serial=4, origin_serial=0x100000002)
        decoded = decode_key_sequences(snapshot([rx, tx]))
        self.assertEqual(decoded["events"][0]["max_tid"], 13)
        self.assertEqual(decoded["events"][0]["origin_submit_serial"],
                         0x100000001)
        self.assertFalse(decoded["bundles"][0]["same_origin_submit_serial"])
        self.assertEqual(decoded["bundles"][0]["status"],
                         "partial_sequence_observation")

    def test_generation_mismatch_is_retained_but_not_current(self):
        stale = row(14, generation=6, tid=4)
        changed = row(15, generation=6, flags=(1 << 4) | (1 << 13) |
                      (1 << 14) | (1 << 17) | (1 << 18) | (1 << 19),
                      origin_serial=1)
        changed["firmware_generation"] = 0
        decoded = decode_key_sequences(snapshot([stale, changed]))
        self.assertEqual(decoded["events"][0]["status"],
                         "origin_generation_not_current")
        self.assertEqual(decoded["events"][1]["status"],
                         "origin_generation_changed_before_record")
        self.assertEqual(decoded["events"][0]["counter_value"],
                         0x010203040506)

    def test_reports_unknown_api_without_counter(self):
        result = row(16, value=2, api=99,
                     flags=(1 << 4) | (1 << 14) | (1 << 17) | (1 << 19))
        decoded = decode_key_sequences(snapshot([result]))["events"][0]
        self.assertEqual(decoded["status"], "api_layout_unavailable")
        self.assertEqual(decoded["api_version"], 99)
        self.assertNotIn("counter_value", decoded)

    def test_rejects_wrong_identity_and_overwide_rx(self):
        bad_identity = row(14)
        bad_identity["group_id"] = 5
        overwide = row(14, value=1 << 48)
        events = decode_key_sequences(snapshot([bad_identity, overwide]))["events"]
        self.assertEqual(events[0]["status"], "invalid_key_command_identity")
        self.assertEqual(events[1]["status"], "rx_pn_out_of_range")

    def test_unstable_cut_cannot_be_reported_complete(self):
        decoded = decode_key_sequences(snapshot([row(14)], stable=False))
        self.assertEqual(decoded["status"], "partial_or_unstable_cut")
        self.assertFalse(decoded["snapshot_stable"])


if __name__ == "__main__":
    unittest.main()
