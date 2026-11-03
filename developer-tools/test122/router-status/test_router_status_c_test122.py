#!/usr/bin/env python3
"""Host-only checks for the Test122 sender and radiotap/TX-status parser."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[2]
PARSER_DIR = REPO_ROOT / "developer-tools/test089/txstatus-observer"
PACKETSET_DIR = REPO_ROOT / "developer-tools/test104"
SENDER_SOURCE = TOOL_DIR / "awdl_router_status_sender_test122.c"
PARSER_TEST_SOURCE = TOOL_DIR / "radiotap_status_parser_test122.c"
sys.path.insert(0, str(PACKETSET_DIR))
import packetset_test104 as packetset  # noqa: E402


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
        data, manifest = packetset.encode_packet_set(source, target, "test122-host-only")
        self.assertFalse(manifest["transmission_capability"])
        return data

    def write_private(self, data: bytes, name: str = "packet-set.bin") -> Path:
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_c_packetset_verifier_accepts_existing_test104_contract(self):
        packet_path = self.write_private(self.make_packet_set())
        result = subprocess.run(
            [str(self.sender), "--verify-only", "--packet-set", str(packet_path)],
            check=False, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "event": "PACKET_SET_VALID",
            "schema": "test104-unicast-packet-set/v1",
            "frames": 4,
            "interval_ms": 10,
            "budget_ms": 40,
            "noack_requested": False,
            "transmission_capability": False,
            "rf_transmission_proven": False,
        })

    def test_c_packetset_verifier_rejects_frame_mutation(self):
        data = bytearray(self.make_packet_set())
        data[104 + 10 + 22] ^= 1
        packet_path = self.write_private(bytes(data), "mutated.bin")
        result = subprocess.run(
            [str(self.sender), "--verify-only", "--packet-set", str(packet_path)],
            check=False, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_host_default_does_not_enter_send_path(self):
        result = subprocess.run([str(self.sender)], check=False,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--verify-only", result.stderr)

    def test_parser_handles_exact_echo_header_change_and_fcs(self):
        result = subprocess.run([str(self.parser_test)], check=False,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS Test122", result.stdout)


if __name__ == "__main__":
    unittest.main()
