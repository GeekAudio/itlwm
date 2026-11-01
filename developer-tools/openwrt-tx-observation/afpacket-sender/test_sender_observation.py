from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
FIXTURE_SOURCE = ROOT / "test_radiotap_observation.c"
CLASSIFIER = ROOT.parent / "openwrt_tx_observation.py"
TEST087_DIR = ROOT.parents[1] / "test087"
sys.path.insert(0, str(TEST087_DIR))
import test087_controlled


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

            short_headers = subprocess.run(
                [str(binary), "--emit-short-header-fixtures"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(short_headers.returncode, 0, short_headers.stderr)
            short_rows = [line for line in short_headers.stdout.splitlines()
                          if line.strip()]
            self.assertEqual(len(short_rows), 1)
            short_result = json.loads(short_rows[0])
            short_capture = short_result["tx_provenance"]["capture"]
            self.assertEqual(short_result["tx_provenance"]["fixture_mode"],
                             "synthetic_host_fixture")
            self.assertEqual(short_capture["decode_coverage"]["packet_received"], 3)
            self.assertEqual(short_capture["decode_coverage"]["invalid_radiotap"], 3)
            self.assertEqual(short_capture["decode_coverage"]["packet_decoded"], 0)
            self.assertEqual(short_capture["decode_coverage"][
                "rejected_radiotap_samples_recorded"], 3)
            self.assertEqual([sample["raw_prefix_len"] for sample in
                              short_capture["rejected_radiotap_samples"]],
                             [1, 3, 7])

            saved_input = Path(temp) / "short-header-sender-result.json"
            saved_input.write_text(json.dumps(short_result), encoding="utf-8")
            classified = subprocess.run(
                [sys.executable, str(CLASSIFIER), str(saved_input)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(classified.returncode, 0, classified.stderr)
            summary = json.loads(classified.stdout)
            self.assertEqual(summary["evidence_scope"], "synthetic")
            self.assertEqual(summary["capture"]["decode_coverage"][
                "invalid_radiotap"], 3)
            decoded_samples = summary["capture"]["rejected_samples"]
            self.assertEqual(len(decoded_samples), 3)
            expected_fields = [
                {"version_present": True, "version": 0,
                 "pad_present": False, "pad": None,
                 "rtap_declared_len_present": False,
                 "rtap_declared_len": None,
                 "present_bitmap_present": False,
                 "present_bitmap_complete": False,
                 "present_bitmap_capacity_exceeded": False,
                 "present_word_count": 0, "present_words": []},
                {"version_present": True, "version": 0,
                 "pad_present": True, "pad": 0,
                 "rtap_declared_len_present": False,
                 "rtap_declared_len": None,
                 "present_bitmap_present": False,
                 "present_bitmap_complete": False,
                 "present_bitmap_capacity_exceeded": False,
                 "present_word_count": 0, "present_words": []},
                {"version_present": True, "version": 0,
                 "pad_present": True, "pad": 0,
                 "rtap_declared_len_present": True,
                 "rtap_declared_len": 8,
                 "present_bitmap_present": False,
                 "present_bitmap_complete": False,
                 "present_bitmap_capacity_exceeded": False,
                 "present_word_count": 0, "present_words": []},
            ]
            for sample, expected in zip(decoded_samples, expected_fields):
                self.assertEqual(sample["reject_reason"], "short_header")
                self.assertEqual(sample["classification"],
                                 "rejected_prefix_unmatched")
                self.assertEqual(sample["raw_header_fields"], expected)
                self.assertEqual(sample["full_packet_identity"], "unknown")
            self.assertFalse(summary["rf_transmission_proven"])
            self.assertFalse(summary["ack_proven"])
            self.assertFalse(summary["peer_receipt_proven"])

            # The receive tail may finish slightly after its fixed cutoff due
            # to scheduling. That actual horizon remains visible, while the
            # strict Test087 compatibility validator judges only send time.
            tail = subprocess.run(
                [str(binary), "--emit-tail-deadline-regression"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(tail.returncode, 0, tail.stderr)
            tail_lines = [line for line in tail.stdout.splitlines() if line.strip()]
            self.assertEqual(len(tail_lines), 2)
            started_event = json.loads(tail_lines[0])
            self.assertEqual(started_event["event"], "SENDER_STARTED")
            tail_result = json.loads(tail_lines[1])
            self.assertEqual(tail_result["status"], "complete")
            self.assertEqual(tail_result["frames_attempted"], 4)
            self.assertEqual(tail_result["frames_completed"], 4)
            self.assertEqual(tail_result["sent"], 4)
            self.assertFalse(tail_result["deadline_hit"])
            self.assertEqual(tail_result["elapsed_ms"], 30)
            tail_capture = tail_result["tx_provenance"]["capture"]
            self.assertEqual(tail_capture["budget_ns"], 40_000_000)
            self.assertEqual(tail_capture["ended_ns"],
                             tail_capture["started_ns"] + 40_000_000)
            self.assertEqual(tail_capture["actual_finished_ns"],
                             tail_result["finished_ns"])
            self.assertEqual(tail_capture["actual_horizon_ns"], 40_498_450)
            self.assertGreater(tail_capture["actual_finished_ns"],
                               tail_capture["ended_ns"])

            legacy = {key: tail_result[key]
                      for key in test087_controlled.SENDER_RESULT_ALLOWED_KEYS}
            old_frames = test087_controlled.SENDER_FRAMES
            old_deadline = test087_controlled.SENDER_DEADLINE_SECONDS
            old_interval = test087_controlled.SENDER_INTERVAL_MS
            try:
                test087_controlled.SENDER_FRAMES = 4
                test087_controlled.SENDER_DEADLINE_SECONDS = 0.04
                test087_controlled.SENDER_INTERVAL_MS = 10
                accepted = test087_controlled.parse_sender_result(
                    json.dumps(legacy, sort_keys=True, separators=(",", ":")))
            finally:
                test087_controlled.SENDER_FRAMES = old_frames
                test087_controlled.SENDER_DEADLINE_SECONDS = old_deadline
                test087_controlled.SENDER_INTERVAL_MS = old_interval
            self.assertEqual(accepted["status"], "complete")
            self.assertFalse(accepted["deadline_hit"])

            tail_input = Path(temp) / "tail-deadline-sender-result.json"
            tail_input.write_text(json.dumps(tail_result), encoding="utf-8")
            tail_classified = subprocess.run(
                [sys.executable, str(CLASSIFIER), str(tail_input)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(tail_classified.returncode, 0,
                             tail_classified.stderr)
            tail_summary = json.loads(tail_classified.stdout)
            self.assertEqual(tail_summary["evidence_scope"], "synthetic")
            self.assertEqual(tail_summary["capture"]["actual_horizon_ns"],
                             40_498_450)
            self.assertEqual(tail_summary["capture"]["ended_ns"],
                             tail_summary["capture"]["started_ns"] +
                             40_000_000)
            self.assertFalse(tail_summary["rf_transmission_proven"])


if __name__ == "__main__":
    unittest.main()
