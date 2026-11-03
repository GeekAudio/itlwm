#!/usr/bin/env python3
"""Offline regression tests for the Test122 correlated packet-set encoder."""
from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path

TOOL_PATH = Path(__file__).with_name("packetset_correlated_test122.py")
SPEC = importlib.util.spec_from_file_location("packetset_correlated_test122", TOOL_PATH)
packetset = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(packetset)

SOURCE = {"mac": "02:00:00:00:10:01", "ipv6_link_local": "fe80::1001"}
TARGET = {"mac": "02:00:00:00:20:02", "ipv6_link_local": "fe80::2002"}
NONCE_A = "1020304050607080"
NONCE_B = "1020304050607081"


def build(*, nonce=NONCE_A, wifi_base=291, awdl_base=34305):
    return packetset.encode_packet_set(
        SOURCE, TARGET, "offline-test122", wire_nonce_hex=nonce,
        wifi_sequence_base=wifi_base, awdl_sequence_base=awdl_base)


def packet_offset(ordinal=0):
    return packetset.HEADER_LEN + ordinal * packetset.PACKET_LEN


def mpdu_offset(ordinal=0):
    return packet_offset(ordinal) + packetset.RADIOTAP_LEN


class CorrelatedPacketSetTests(unittest.TestCase):
    def test_v2_layout_manifest_and_checksum(self):
        raw, manifest = build()
        decoded = packetset.decode_packet_set(
            raw, SOURCE, TARGET, expected_wire_nonce_hex=NONCE_A)
        self.assertEqual(len(raw), 536)
        self.assertEqual(raw[:8], b"T122PKT2")
        self.assertEqual(raw[8], 2)
        self.assertEqual(struct.unpack_from(">HH", raw, 20), (291, 34305))
        self.assertEqual(raw[68:100], bytes.fromhex(packetset.TEMPLATE_SHA256))
        self.assertEqual(raw[104:112].hex(), NONCE_A)
        self.assertEqual(decoded["schema"], "test122-correlated-packet-set/v2")
        self.assertEqual(decoded["packet_set_sha256"], manifest["packet_set_sha256"])
        self.assertEqual(manifest["wire_nonce_hex"], NONCE_A)
        self.assertEqual(len(manifest["frames"]), 4)
        for ordinal, row in enumerate(manifest["frames"]):
            self.assertEqual(row["ordinal"], ordinal)
            self.assertEqual(row["payload_hex"], NONCE_A)
            self.assertEqual(row["sequence_control"], (291 + ordinal) << 4)
            self.assertEqual(row["wifi_sequence"], 291 + ordinal)
            self.assertEqual(row["awdl_sequence"], 34305 + ordinal)
            self.assertTrue(row["udp_checksum_valid"])
            self.assertEqual(decoded["frames"][ordinal]["mpdu_sha256"], row["mpdu_sha256"])

    def test_both_sequence_spaces_wrap_without_duplicates(self):
        raw, manifest = build(wifi_base=4094, awdl_base=65534)
        decoded = packetset.decode_packet_set(raw)
        rows = decoded["frames"]
        self.assertEqual([row["wifi_sequence"] for row in rows], [4094, 4095, 0, 1])
        self.assertEqual([row["sequence_control"] for row in rows], [0xFFE0, 0xFFF0, 0, 0x10])
        self.assertEqual([row["awdl_sequence"] for row in rows], [65534, 65535, 0, 1])
        self.assertEqual(len({row["wifi_sequence"] for row in rows}), 4)
        self.assertEqual(len({row["awdl_sequence"] for row in rows}), 4)
        self.assertEqual(manifest["wifi_sequence_base"], 4094)
        self.assertEqual(manifest["awdl_sequence_base"], 65534)

    def test_wrong_wire_nonce_in_frame_is_rejected_even_with_recomputed_checksum(self):
        raw, _ = build()
        changed = bytearray(raw)
        start = mpdu_offset()
        changed[start + 88:start + 96] = bytes.fromhex(NONCE_B)
        changed[start + 86:start + 88] = b"\x00\x00"
        source_ip = bytes.fromhex("fe800000000000000000000000001001")
        target_ip = bytes.fromhex("fe800000000000000000000000002002")
        struct.pack_into("!H", changed, start + 86, packetset._test104._udp_checksum(
            source_ip, target_ip, bytes(changed[start + 80:start + 96])))
        with self.assertRaisesRegex(packetset.PacketSetError, "wire_nonce_payload_mismatch"):
            packetset.validate_packet_set(bytes(changed))

    def test_wrong_udp_checksum_is_rejected(self):
        raw, _ = build()
        changed = bytearray(raw)
        changed[mpdu_offset() + 87] ^= 0x01
        with self.assertRaisesRegex(packetset.PacketSetError, "udp_checksum_invalid"):
            packetset.validate_packet_set(bytes(changed))

    def test_nonzero_fragment_is_rejected(self):
        raw, _ = build()
        changed = bytearray(raw)
        offset = mpdu_offset() + 22
        sequence_control = struct.unpack_from("<H", changed, offset)[0]
        struct.pack_into("<H", changed, offset, sequence_control | 1)
        with self.assertRaisesRegex(packetset.PacketSetError, "fragment_number_must_be_zero"):
            packetset.validate_packet_set(bytes(changed))

    def test_wrong_wifi_and_awdl_sequences_are_rejected(self):
        raw, _ = build()
        changed_wifi = bytearray(raw)
        offset = mpdu_offset(1) + 22
        struct.pack_into("<H", changed_wifi, offset, (999 << 4))
        with self.assertRaisesRegex(packetset.PacketSetError, "wifi_sequence_control_mismatch"):
            packetset.validate_packet_set(bytes(changed_wifi))

        changed_awdl = bytearray(raw)
        offset = mpdu_offset(1) + 34
        struct.pack_into("<H", changed_awdl, offset, 999)
        with self.assertRaisesRegex(packetset.PacketSetError, "awdl_sequence_mismatch"):
            packetset.validate_packet_set(bytes(changed_awdl))

    def test_wrong_schema_and_truncated_packet_set_are_rejected(self):
        raw, _ = build()
        bad_magic = bytearray(raw)
        bad_magic[0] ^= 1
        with self.assertRaisesRegex(packetset.PacketSetError, "packet_set_schema_invalid"):
            packetset.validate_packet_set(bytes(bad_magic))
        bad_version = bytearray(raw)
        bad_version[8] = 1
        with self.assertRaisesRegex(packetset.PacketSetError, "packet_set_schema_invalid"):
            packetset.validate_packet_set(bytes(bad_version))
        with self.assertRaisesRegex(packetset.PacketSetError, "packet_set_length_invalid"):
            packetset.validate_packet_set(raw[:-1])
        with self.assertRaisesRegex(packetset.PacketSetError, "packet_set_length_invalid"):
            packetset.validate_packet_set(raw + b"\x00")

    def test_wrong_expected_nonce_is_rejected(self):
        raw, _ = build()
        with self.assertRaisesRegex(packetset.PacketSetError, "wire_nonce_expectation_mismatch"):
            packetset.decode_packet_set(raw, expected_wire_nonce_hex=NONCE_B)

    def test_capture_match_requires_current_run_nonce_and_both_sequences(self):
        raw_a, _ = build(nonce=NONCE_A, wifi_base=291, awdl_base=34305)
        raw_b, _ = build(nonce=NONCE_B, wifi_base=700, awdl_base=42000)
        frame_a = raw_a[mpdu_offset():mpdu_offset() + packetset.MPDU_LEN]
        match = packetset.match_frame(frame_a, raw_a)
        self.assertIsNotNone(match)
        self.assertEqual(match["ordinal"], 0)
        self.assertEqual(match["wire_nonce_hex"], NONCE_A)
        self.assertTrue(match["exact_mpdu_match"])
        self.assertIsNone(packetset.match_frame(frame_a, raw_b))

        wrong_sequence = bytearray(frame_a)
        struct.pack_into("<H", wrong_sequence, 22, 701 << 4)
        self.assertIsNone(packetset.match_frame(bytes(wrong_sequence), raw_b))

    def test_identity_survives_duration_rewrite_but_is_not_exact_match(self):
        raw, _ = build()
        frame = bytearray(raw[mpdu_offset():mpdu_offset() + packetset.MPDU_LEN])
        frame[2:4] = b"\x34\x12"
        match = packetset.match_frame(bytes(frame), raw)
        self.assertIsNotNone(match)
        self.assertTrue(match["identity_match"])
        self.assertFalse(match["exact_mpdu_match"])

    def test_invalid_nonce_and_sequence_inputs_are_rejected(self):
        with self.assertRaisesRegex(packetset.PacketSetError, "wire_nonce_hex_invalid"):
            build(nonce="xyz")
        with self.assertRaisesRegex(packetset.PacketSetError, "wire_nonce_must_be_nonzero"):
            build(nonce="0000000000000000")
        with self.assertRaisesRegex(packetset.PacketSetError, "wifi_sequence_base_out_of_range"):
            build(wifi_base=4096)
        with self.assertRaisesRegex(packetset.PacketSetError, "awdl_sequence_base_out_of_range"):
            build(awdl_base=65536)
        with self.assertRaisesRegex(packetset.PacketSetError, "wifi_sequence_base_out_of_range"):
            build(wifi_base=True)


if __name__ == "__main__":
    unittest.main()
