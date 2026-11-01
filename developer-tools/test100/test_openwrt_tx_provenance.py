#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import openwrt_tx_provenance as provenance


HASHES = [f"{value:064x}" for value in (1, 2, 3, 4)]


def observation(*, packet_type: int, ordinal: int = 0,
                has_tx_flags: bool = False, tx_flags: int = 0,
                has_data_retries: bool = False, data_retries: int = 0,
                observed_ns: int = 1100, digest: str | None = None) -> dict:
    return {
        "ordinal": ordinal,
        "packet_type": packet_type,
        "exact_mpdu_match": True,
        "mpdu_sha256": digest or HASHES[ordinal],
        "wifi_sequence": 291 + ordinal,
        "awdl_sequence": 34305 + ordinal,
        "observed_ns": observed_ns,
        "has_tx_flags": has_tx_flags,
        "tx_flags": tx_flags,
        "has_data_retries": has_data_retries,
        "data_retries": data_retries,
    }


def sender_result(observations: list[dict] | None = None, *,
                  pre_send_queue_empty: bool = True,
                  dropped_packets: int = 0, complete: bool = True) -> dict:
    rows = [{
        "ordinal": ordinal,
        "ieee80211_sequence": 291 + ordinal,
        "awdl_sequence": 34305 + ordinal,
        "mpdu_sha256": HASHES[ordinal],
        "before_ns": 1010 + ordinal * 10,
        "after_ns": 1011 + ordinal * 10,
        "return_bytes": 106,
        "errno": 0,
    } for ordinal in range(4)]
    return {
        "event": "SENDER_RESULT",
        "status": "complete",
        "tx_flags_requested": "NOACK|NOSEQNO",
        "hardware_honoring": "unknown",
        "frames_attempted": 4,
        "frames_completed": 4,
        "send_timing": rows,
        "tx_provenance": {
            "schema": provenance.SCHEMA,
            "capture": {
                "started_ns": 1000,
                "ended_ns": 1200,
                "window": "send_sequence_span",
                "budget_ns": 40_000_000,
                "status": "bounded_during_send_sequence",
                "rx_packets": len(observations or []),
                "dropped_packets": dropped_packets,
                "kernel_packets": dropped_packets + len(observations or []),
                "pre_send_drained_packets": 0,
                "pre_send_queue_empty": pre_send_queue_empty,
                "complete": complete,
                "limit_reached": False,
                "receive_error": 0,
            },
            "observations": list(observations or []),
            "run_nonce_is_local_only": True,
            "nonce_in_mpdu": False,
            "pid_cookie_bound_tx_status": "unknown",
            "pid_cookie_status_source_available": False,
            "tx_status_unknown_reason": "AF_PACKET has no PID-cookie TXS source",
            "rf_transmission_proven": False,
            "peer_receipt_proven": False,
            "ack_proven": False,
        },
    }


class OpenWrtTxProvenanceTests(unittest.TestCase):
    def test_send_syscall_acceptance_is_separate_from_rf(self):
        result = provenance.classify_sender_result(sender_result())
        self.assertEqual(result["counts"]["local_send_accepted"], 4)
        self.assertEqual(result["pid_cookie_bound_tx_status"], "unknown")
        self.assertFalse(result["rf_transmission_proven"])
        self.assertFalse(result["peer_receipt_proven"])

    def test_packet_outgoing_is_only_local_echo_even_with_zero_status_fields(self):
        row = observation(packet_type=provenance.PACKET_OUTGOING,
                          has_tx_flags=True, tx_flags=0,
                          has_data_retries=True, data_retries=0)
        classified = provenance.classify_observation(row)
        self.assertEqual(classified["classification"], "packet_outgoing_echo")
        self.assertFalse(classified["tx_status_proven"])
        result = provenance.classify_sender_result(sender_result([row]))
        self.assertEqual(result["counts"]["packet_outgoing_echoes"], 1)
        self.assertFalse(result["tx_flags_zero_is_success"])
        self.assertFalse(result["data_retries_zero_is_success"])
        self.assertFalse(result["requested_noack_is_ack_evidence"])

    def test_otherhost_with_status_fields_is_completion_copy_candidate_only(self):
        row = observation(packet_type=provenance.PACKET_OTHERHOST,
                          has_tx_flags=True, tx_flags=0,
                          has_data_retries=True, data_retries=0)
        classified = provenance.classify_observation(row)
        self.assertEqual(
            classified["classification"],
            "generated_tx_completion_copy_candidate")
        result = provenance.classify_sender_result(sender_result([row]))
        frame = result["frames"][0]
        self.assertEqual(frame["generated_tx_completion_copy_candidate_count"], 1)
        self.assertFalse(frame["pid_cookie_tx_status_proven"])
        self.assertEqual(frame["pid_cookie_bound_tx_status"], "unknown")
        self.assertFalse(result["rf_transmission_proven"])

    def test_otherhost_without_both_radiotap_fields_remains_unclassified(self):
        row = observation(packet_type=provenance.PACKET_OTHERHOST,
                          has_tx_flags=True, tx_flags=0,
                          has_data_retries=False, data_retries=0)
        self.assertEqual(
            provenance.classify_observation(row)["classification"],
            "exact_frame_match_unclassified")

    def test_wrong_hash_or_sequence_cannot_join_to_send(self):
        wrong_hash = observation(packet_type=provenance.PACKET_OUTGOING,
                                 digest="f" * 64)
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "observation_hash_mismatch"):
            provenance.classify_sender_result(sender_result([wrong_hash]))
        wrong_sequence = observation(packet_type=provenance.PACKET_OUTGOING)
        wrong_sequence["wifi_sequence"] = 292
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "frame_identity_mismatch"):
            provenance.classify_observation(wrong_sequence)

    def test_sender_cannot_promote_observation_to_rf_or_txs(self):
        row = observation(packet_type=provenance.PACKET_OTHERHOST,
                          has_tx_flags=True, has_data_retries=True)
        row["rf_transmission_proven"] = True
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "observation_overclaim_rf_transmission_proven"):
            provenance.classify_observation(row)

    def test_preexisting_queue_ambiguity_is_kept(self):
        row = observation(packet_type=provenance.PACKET_OUTGOING)
        result = provenance.classify_sender_result(
            sender_result([row], pre_send_queue_empty=False))
        self.assertEqual(result["frames"][0]["invocation_binding"],
                         "ambiguous_pre_send_queue_not_empty")

    def test_unavailable_pid_cookie_source_stays_unknown(self):
        value = sender_result()
        result = provenance.classify_sender_result(value)
        self.assertEqual(result["pid_cookie_bound_tx_status"], "unknown")
        self.assertEqual(result["counts"]["pid_cookie_bound_tx_statuses"], 0)
        self.assertTrue(all(
            not frame["pid_cookie_tx_status_proven"] for frame in result["frames"]))
        overclaim = copy.deepcopy(value)
        overclaim["tx_provenance"]["pid_cookie_bound_tx_status"] = "observed"
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "raw_afpacket_capture_cannot_claim_pid_cookie_txs"):
            provenance.classify_sender_result(overclaim)

    def test_host_offline_sender_is_explicitly_not_captured(self):
        value = sender_result()
        capture = value["tx_provenance"]["capture"]
        capture.update({"status": "not_run_host_test", "started_ns": None,
                        "ended_ns": None, "complete": False})
        result = provenance.classify_sender_result(value)
        self.assertFalse(result["capture_complete"])
        self.assertEqual(result["pid_cookie_bound_tx_status"], "unknown")

    def test_malformed_provenance_fails_closed(self):
        value = sender_result()
        value["tx_flags_requested"] = ""
        with self.assertRaises(provenance.ProvenanceError):
            provenance.classify_sender_result(value)
        value = sender_result()
        value["tx_provenance"]["observations"] = [
            observation(packet_type=provenance.PACKET_OUTGOING)] * 17
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "observation_count_exceeds_limit"):
            provenance.classify_sender_result(value)


if __name__ == "__main__":
    unittest.main()
