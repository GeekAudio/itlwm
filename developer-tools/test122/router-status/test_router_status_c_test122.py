#!/usr/bin/env python3
"""Host-only checks for the Test122 sender and run-correlated packet set."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[2]
PARSER_DIR = REPO_ROOT / "developer-tools/test089/txstatus-observer"
SENDER_SOURCE = TOOL_DIR / "awdl_router_status_sender_test122.c"
PARSER_TEST_SOURCE = TOOL_DIR / "radiotap_status_parser_test122.c"
sys.path.insert(0, str(TOOL_DIR))
import packetset_correlated_test122 as packetset  # noqa: E402
import router_status_tail_test122 as router_wrapper  # noqa: E402


WIRE_NONCE = "0123456789abcdef"


class Test122SenderHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="test122-router-status-host-")
        cls.root = Path(cls.tmp.name)
        cls.sender = cls.root / "sender-verify"
        cls.parser_test = cls.root / "radiotap-status-test"
        common = ["/usr/bin/clang", "-std=c11", "-O2", "-Wall", "-Wextra",
                  "-Werror", "-I", str(TOOL_DIR), "-I", str(PARSER_DIR)]
        compile_sender = subprocess.run(
            common + [str(SENDER_SOURCE), str(PARSER_DIR / "radiotap_parser.c"),
                      "-o", str(cls.sender)],
            check=False, capture_output=True, text=True, timeout=60)
        if compile_sender.returncode:
            raise AssertionError(compile_sender.stderr)
        compile_parser = subprocess.run(
            common + [str(PARSER_TEST_SOURCE), str(PARSER_DIR / "radiotap_parser.c"),
                      "-o", str(cls.parser_test)],
            check=False, capture_output=True, text=True, timeout=60)
        if compile_parser.returncode:
            raise AssertionError(compile_parser.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def make_packet_set(self) -> bytes:
        source = {"mac": "02:11:22:33:44:55", "ipv6_link_local": "fe80::1122"}
        target = {"mac": "02:aa:bb:cc:dd:ee", "ipv6_link_local": "fe80::aabb"}
        data, manifest = packetset.encode_packet_set(
            source, target, "test122-host-only", wire_nonce_hex=WIRE_NONCE,
            wifi_sequence_base=0x0FFE, awdl_sequence_base=0xFFFE)
        self.assertEqual(len(data), 536)
        self.assertEqual(manifest["schema"], "test122-correlated-packet-set/v2")
        self.assertEqual(manifest["wire_nonce_hex"], WIRE_NONCE)
        self.assertFalse(manifest["transmission_capability"])
        return data

    def write_private(self, data: bytes, name: str = "packet-set.bin") -> Path:
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def verify(self, data: bytes, name: str = "packet-set.bin"):
        packet_path = self.write_private(data, name)
        return subprocess.run(
            [str(self.sender), "--verify-only", "--packet-set", str(packet_path)],
            check=False, capture_output=True, text=True, timeout=10)

    def test_c_verifier_accepts_v2_and_preserves_json_wire_order(self):
        result = self.verify(self.make_packet_set())
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (
            '{"event":"PACKET_SET_VALID",'
            '"schema":"test122-correlated-packet-set/v2",'
            '"frames":4,"interval_ms":10,"budget_ms":40,'
            '"noack_requested":false,"transmission_capability":false,'
            '"rf_transmission_proven":false,'
            f'"wire_nonce_hex":"{WIRE_NONCE}"' + '}\n'
        )
        self.assertEqual(result.stdout, expected)
        decoded = json.loads(result.stdout)
        self.assertEqual(decoded["wire_nonce_hex"], WIRE_NONCE)
        parsed = router_wrapper.parse_packetset_valid(
            "PACKET_SET_VALID " + result.stdout.rstrip("\n"))
        self.assertEqual(parsed["schema"], "test122-correlated-packet-set/v2")
        self.assertEqual(parsed["wire_nonce_hex"], WIRE_NONCE)
        self.assertFalse(parsed["transmission_capability"])

    def test_c_packetset_verifier_rejects_sequence_mutation(self):
        data = bytearray(self.make_packet_set())
        data[112 + 10 + 22] ^= 0x10
        result = self.verify(bytes(data), "bad-sequence.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_c_packetset_verifier_rejects_wire_nonce_mutation(self):
        data = bytearray(self.make_packet_set())
        data[112 + 10 + 88] ^= 0x01
        result = self.verify(bytes(data), "bad-frame-nonce.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_c_packetset_verifier_rejects_zero_header_nonce(self):
        data = bytearray(self.make_packet_set())
        data[104:112] = bytes(8)
        result = self.verify(bytes(data), "zero-header-nonce.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_c_packetset_verifier_rejects_checksum_mutation(self):
        data = bytearray(self.make_packet_set())
        data[112 + 10 + 86] ^= 0x01
        result = self.verify(bytes(data), "bad-checksum.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_c_packetset_verifier_rejects_sequence_base_mismatch(self):
        data = bytearray(self.make_packet_set())
        data[20:22] = b"\x00\x10"  # exceeds the 12-bit Wi-Fi sequence range
        result = self.verify(bytes(data), "bad-base.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_host_default_does_not_enter_send_path(self):
        result = subprocess.run([str(self.sender)], check=False,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--verify-only", result.stderr)

    def test_parser_handles_dynamic_nonce_and_full_sequences(self):
        result = subprocess.run([str(self.parser_test)], check=False,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS Test122", result.stdout)


if __name__ == "__main__":
    unittest.main()
