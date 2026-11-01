from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
FIXTURE_SOURCE = ROOT / "test_radiotap_observation.c"


class SenderObservationTests(unittest.TestCase):
    def test_bounded_radiotap_fixtures_and_c_serializer_contract(self):
        with tempfile.TemporaryDirectory(prefix="openwrt-tx-observation-") as temp:
            binary = Path(temp) / "test_radiotap_observation"
            compile_result = subprocess.run(
                [
                    "cc", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", str(FIXTURE_SOURCE), "-o", str(binary),
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stderr)

            fixtures = subprocess.run([str(binary)], capture_output=True,
                                      text=True, check=False)
            self.assertEqual(fixtures.returncode, 0, fixtures.stderr)
            self.assertIn("radiotap_observation_fixtures=passed", fixtures.stdout)

            emitted = subprocess.run([str(binary), "--emit-synthetic"],
                                     capture_output=True, text=True,
                                     check=False)
            self.assertEqual(emitted.returncode, 0, emitted.stderr)
            rows = [line for line in emitted.stdout.splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            result = json.loads(rows[0])
            self.assertEqual(result["event"], "SENDER_RESULT")
            self.assertEqual(result["tx_provenance"]["schema"],
                             "openwrt-tx-observation/v1")
            provenance = result["tx_provenance"]
            self.assertEqual(provenance["fixture_mode"],
                             "synthetic_host_fixture")
            self.assertFalse(provenance["rf_transmission_proven"])
            self.assertFalse(provenance["ack_proven"])
            self.assertFalse(provenance["peer_receipt_proven"])
            capture = provenance["capture"]
            self.assertTrue(capture["capture_finished"])
            self.assertTrue(capture["loss_free"])
            self.assertFalse(capture["decoder_coverage"])
            self.assertEqual(capture["window_cutoff_semantics"],
                             "min(actual_finished_ns,started_ns+budget_ns)")
            self.assertEqual(capture["ended_ns"], 131_000)
            self.assertEqual(capture["actual_finished_ns"], 131_000)
            self.assertEqual(capture["actual_horizon_ns"], 31_000)
            coverage = capture["decode_coverage"]
            self.assertEqual(coverage["packet_received"], 2)
            self.assertEqual(coverage["packet_decoded"], 1)
            self.assertEqual(coverage["unsupported_radiotap"], 1)
            self.assertEqual(coverage["rejected_radiotap_samples_recorded"], 1)
            self.assertEqual(coverage["rejected_radiotap_sample_overflow"], 0)
            self.assertEqual(
                coverage["rejected_radiotap_samples_recorded"] +
                coverage["rejected_radiotap_sample_overflow"],
                coverage["invalid_radiotap"] +
                coverage["unsupported_radiotap"] +
                coverage["truncated_packets"],
            )
            sample = capture["rejected_radiotap_samples"][0]
            self.assertEqual(sample["reject_reason"], "vendor_namespace")
            self.assertEqual(sample["radiotap_parse_reason"], "vendor_namespace")
            self.assertEqual(sample["raw_prefix_hex"], "0000080000000040")
            self.assertEqual(sample["raw_prefix_len"], 8)
            self.assertFalse(sample["raw_prefix_truncated"])
            self.assertEqual(sample["raw_prefix_sha256"],
                             "75bc82ce6ca470413685b223080fb158211e920737acb5116bae63fd780de561")
            echo = provenance["observations"][0]
            self.assertEqual(echo["classification"], "packet_outgoing_echo")
            self.assertTrue(echo["exact_mpdu_match"])
            self.assertFalse(echo["invocation_bound"])
            self.assertFalse(echo["rf_transmission_proven"])
            self.assertEqual(provenance["pid_cookie_bound_tx_status"], "unknown")
            self.assertEqual(provenance["pid_txs_expectation"], "unknown")

            failed = subprocess.run(
                [str(binary), "--emit-synthetic-failure"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(failed.returncode, 0, failed.stderr)
            failed_result = json.loads(failed.stdout)
            failed_capture = failed_result["tx_provenance"]["capture"]
            self.assertFalse(failed_capture["capture_finished"])
            self.assertFalse(failed_capture["loss_free"])
            self.assertIsNone(failed_capture["actual_finished_ns"])
            self.assertFalse(failed_capture["decode_coverage"]["kernel_stats_available"])
            self.assertEqual(failed_capture["decode_coverage"]["receive_error"], 5)


if __name__ == "__main__":
    unittest.main()
