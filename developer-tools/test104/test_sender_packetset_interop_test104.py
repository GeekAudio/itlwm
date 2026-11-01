#!/usr/bin/env python3
"""Exercise the real packet-set producer against the compiled C verifier."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import packetset_test104 as packetset

TOOL_DIR = Path(__file__).resolve().parent
SENDER_SOURCE = TOOL_DIR / "awdl_unicast_sender_test104.c"


class SenderPacketSetInteropTests(unittest.TestCase):
    def test_python_packetset_is_accepted_by_compiled_c_verifier(self):
        source = {"mac": "02:11:22:33:44:55", "ipv6_link_local": "fe80::1122"}
        target = {"mac": "02:aa:bb:cc:dd:ee", "ipv6_link_local": "fe80::aabb"}
        packet_bytes, manifest = packetset.encode_packet_set(
            source, target, "sender-c-interop")
        self.assertEqual(packet_bytes[:8], b"T104PKT1")
        self.assertFalse(manifest["transmission_capability"])

        with tempfile.TemporaryDirectory(prefix="test104-c-sender-interop-") as tmp:
            root = Path(tmp)
            packet_path = root / "packet-set.bin"
            binary_path = root / "sender-verify"
            packet_path.write_bytes(packet_bytes)
            packet_path.chmod(0o600)
            compile_result = subprocess.run(
                ["/usr/bin/clang", "-std=c11", "-O2", "-Wall", "-Wextra",
                 "-Werror", str(SENDER_SOURCE), "-o", str(binary_path)],
                check=False, capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            verify = subprocess.run(
                [str(binary_path), "--verify-only", "--packet-set", str(packet_path)],
                check=False, capture_output=True, text=True, timeout=10)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(json.loads(verify.stdout), {
                "event": "PACKET_SET_VALID",
                "schema": "test104-unicast-packet-set/v1",
                "frames": 4,
                "interval_ms": 10,
                "budget_ms": 40,
                "noack_requested": False,
                "transmission_capability": False,
                "rf_transmission_proven": False,
            })

            stale = bytearray(packet_bytes)
            stale[:8] = b"T103PKT1"
            packet_path.write_bytes(stale)
            packet_path.chmod(0o600)
            rejected = subprocess.run(
                [str(binary_path), "--verify-only", "--packet-set", str(packet_path)],
                check=False, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, "")


if __name__ == "__main__":
    unittest.main()
