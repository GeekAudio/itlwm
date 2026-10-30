#!/usr/bin/env python3
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netstat_counters import make_counter_reader, parse_netstat_output, NetstatReadError


VALID_OUTPUT = """netstat banner line
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0        1500  <Link#4>    02:00:00:00:00:01     100     0      10000       90     0       9000     0
en1        1500  198.51.100     198.51.100.27        200     -      20000      180     -      18000     -
en1        1500  <Link#5>    02:00:00:00:00:02     210     0      21000      190     1      19000     0
"""
FAILED_OUTPUT = b"Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n"


class NetstatCounterTests(unittest.TestCase):
    def test_header_matching_skips_banner_and_ipv4_rows(self):
        self.assertEqual(parse_netstat_output(VALID_OUTPUT), {
            "input_packets": 210,
            "input_errors": 0,
            "input_bytes": 21000,
            "output_packets": 190,
            "output_errors": 1,
            "output_bytes": 19000,
            "collisions": 0,
        })

    def test_duplicate_link_rows_are_ambiguous(self):
        with self.assertRaisesRegex(ValueError, "link row count=2"):
            parse_netstat_output(VALID_OUTPUT +
                                 "en1 1500 <Link#5> 02:00:00:00:00:02 211 0 21100 191 1 19100 0\n")

    def test_bounded_retry_records_raw_failure_and_uses_retry_sample(self):
        outputs = [
            FAILED_OUTPUT,
            VALID_OUTPUT.encode(),
        ]
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            body = outputs.pop(0)
            stderr = b"transient netstat formatting failure\n" if len(calls) == 1 else b""
            return subprocess.CompletedProcess(command, 0, body, stderr)

        with tempfile.TemporaryDirectory() as directory:
            reader = make_counter_reader(Path(directory), command_runner=fake_run,
                                         sleep=lambda _seconds: None)
            value = reader()
            self.assertEqual(len(calls), 2)
            self.assertEqual(value["input_packets"], 210)
            self.assertEqual(value["output_errors"], 1)
            self.assertEqual(value["counter_read_attempts"], 2)
            self.assertEqual(value["counter_read_retry_count"], 1)
            self.assertEqual(len(value["counter_read_failures"]), 1)
            failure = value["counter_read_failures"][0]
            self.assertEqual(failure["return_code"], 0)
            self.assertIn("netstat_output_unparsed", failure["reason"])
            self.assertEqual(Path(failure["stdout_file"]).read_bytes(), FAILED_OUTPUT)
            self.assertEqual(Path(failure["stderr_file"]).read_bytes(),
                             b"transient netstat formatting failure\n")
            self.assertEqual(stat.S_IMODE(os.stat(failure["stdout_file"]).st_mode), 0o600)
            self.assertIn("counter_read_completed_at", value)

    def test_two_failed_reads_preserve_diagnostics_and_raise_unknown(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command, 0, b"header changed\n", b"missing link row\n")

        with tempfile.TemporaryDirectory() as directory:
            reader = make_counter_reader(Path(directory), command_runner=fake_run,
                                         sleep=lambda _seconds: None)
            with self.assertRaises(NetstatReadError) as caught:
                reader()
            self.assertEqual(len(calls), 2)
            diagnostic = json.loads(str(caught.exception))
            self.assertEqual(diagnostic["status"],
                             "unknown_counter_read_failed_after_bounded_retry")
            self.assertEqual(len(diagnostic["attempts"]), 2)
            for attempt in diagnostic["attempts"]:
                self.assertEqual(attempt["return_code"], 0)
                self.assertEqual(Path(attempt["stdout_file"]).read_bytes(),
                                 b"header changed\n")
                self.assertEqual(Path(attempt["stderr_file"]).read_bytes(),
                                 b"missing link row\n")


if __name__ == "__main__":
    unittest.main()
