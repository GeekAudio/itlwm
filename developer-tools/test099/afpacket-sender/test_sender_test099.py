from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


SOURCE = Path(__file__).with_name("awdl_probe_sender.c")
NONCE = "0123456789abcdef0123456789abcdef"
TEST_BINARY: Path | None = None


def expected_mpdu_hashes() -> list[str]:
    text = SOURCE.read_text(encoding="utf-8")
    match = re.search(r"static const uint8_t mpdu_base\[MPDU_LENGTH\] = \{(.*?)\};",
                      text, re.DOTALL)
    if not match:
        raise AssertionError("MPDU base fixture missing")
    base = bytes(int(value, 16) for value in
                 re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))
    if len(base) != 96:
        raise AssertionError("MPDU base size changed")
    output = []
    for ordinal in range(4):
        packet = bytearray(base)
        wifi = (291 + ordinal) & 0x0FFF
        awdl = (34305 + ordinal) & 0xFFFF
        packet[22] = (wifi << 4) & 0xFF
        packet[23] = wifi >> 4
        packet[34] = awdl & 0xFF
        packet[35] = awdl >> 8
        output.append(hashlib.sha256(packet).hexdigest())
    return output


class Test099SenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if TEST_BINARY is None or not TEST_BINARY.is_file():
            raise RuntimeError("timing-test binary path required")
        cls.binary = TEST_BINARY

    def test_four_frames_at_ten_ms_with_exact_mpdu_sha256(self):
        env = os.environ.copy()
        process = subprocess.Popen(
            [str(self.binary), "--send", "--interface", "mon0", "--nonce",
             NONCE, "--wait-go"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, env=env)
        self.assertTrue(process.stdout.readline().startswith("READY "))
        process.stdin.write(f"GO {NONCE}\n")
        process.stdin.flush()
        started = json.loads(process.stdout.readline())
        result = json.loads(process.stdout.readline())
        process.wait(timeout=3)
        self.assertEqual(process.stderr.read(), "")
        self.assertEqual(process.returncode, 0)
        self.assertEqual(started["frames_requested"], 4)
        self.assertEqual(started["interval_ms"], 10)
        self.assertEqual(started["send_budget_ns"], 40_000_000)
        self.assertEqual(result["frames_attempted"], 4)
        self.assertEqual(result["frames_completed"], 4)
        rows = result["send_timing"]
        self.assertEqual(len(rows), 4)
        self.assertEqual([row["ieee80211_sequence"] for row in rows], [291, 292, 293, 294])
        self.assertEqual([row["awdl_sequence"] for row in rows], [34305, 34306, 34307, 34308])
        self.assertEqual([row["mpdu_sha256"] for row in rows], expected_mpdu_hashes())
        self.assertGreaterEqual(rows[1]["before_ns"] - started["started_ns"], 10_000_000)
        self.assertFalse(result["hardware_honoring"] != "unknown")
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()

    def test_count_above_four_is_rejected(self):
        result = subprocess.run([str(self.binary), "--count", "5"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_sender_test099.py BINARY")
    TEST_BINARY = Path(sys.argv.pop()).resolve()
    unittest.main(argv=[sys.argv[0]])

