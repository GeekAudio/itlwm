from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import openwrt_tx_observation as classifier


HASHES = [f"{i:064x}" for i in (1, 2, 3, 4)]


def rejected_sample(*, raw: bytes = b"\x00\x00\x0a\x00\x00\x00\x00\x20ab",
                    **changes) -> dict:
    prefix = raw[:96]
    version_present = len(prefix) >= 1
    pad_present = len(prefix) >= 2
    declared_present = len(prefix) >= 4
    bitmap_present = len(prefix) >= 8
    words: list[int] = []
    bitmap_complete = False
    bitmap_overflow = False
    if bitmap_present:
        offset = 4
        while offset + 4 <= len(prefix) and len(words) < 8:
            word = int.from_bytes(prefix[offset:offset + 4], "little")
            words.append(word)
            offset += 4
            if (word & 0x80000000) == 0:
                bitmap_complete = True
                break
        if len(words) == 8 and words[-1] & 0x80000000:
            bitmap_overflow = True
    sample = {
        "packet_type_present": True,
        "packet_type": 3,
        "ifindex_present": True,
        "ifindex": 7,
        "msg_flags": 0,
        "received_len": len(raw),
        "copied_len": len(raw),
        "version_present": version_present,
        "version": prefix[0] if version_present else None,
        "pad_present": pad_present,
        "pad": prefix[1] if pad_present else None,
        "rtap_declared_len_present": declared_present,
        "rtap_declared_len": int.from_bytes(prefix[2:4], "little") if declared_present else None,
        "present_bitmap_present": bitmap_present,
        "present_bitmap_complete": bitmap_complete,
        "present_bitmap_capacity_exceeded": bitmap_overflow,
        "present_word_count": len(words),
        "present_words": words,
        "reject_reason": "unsupported_field",
        "radiotap_parse_reason": "unsupported_field",
        "packet_truncated": False,
        "raw_prefix_hex": prefix.hex(),
        "raw_prefix_len": len(prefix),
        "raw_prefix_truncated": False,
        "raw_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
    }
    sample.update(changes)
    return sample


def capture(*, received: int = 1, decoded: int = 1, invalid: int = 0,
            unsupported: int = 0, truncated: int = 0, dropped: int | None = 0,
            fcs: int = 0, stats: bool = True, error: int | None = None, limit: bool = False,
            finished: bool = True, loss_free: bool | None = True,
            decoder_coverage: bool | None = True,
            sample_count: int = 0, sample_overflow: int = 0) -> dict:
    has_capture = finished or received > 0
    status = ("receive_error" if error not in (None, 0) else
              ("bounded_limit_reached" if limit else
               ("bounded_during_send_sequence" if has_capture else
                "not_run_host_test")))
    return {
        "window_cutoff_semantics": classifier.WINDOW_CUTOFF_SEMANTICS,
        "status": status,
        "schema_contract": "capture_finished_is_execution_completion_not_full_budget_coverage",
        "window": "send_sequence_span",
        "budget_ns": 40_000_000,
        "started_ns": 1_000_000 if has_capture else None,
        "ended_ns": 1_001_000 if has_capture and finished else None,
        "actual_finished_ns": 1_001_000 if has_capture and finished else None,
        "actual_horizon_ns": 1_000 if has_capture and finished else None,
        "capture_finished": finished,
        "pre_send_drained_packets": 0,
        "pre_send_queue_empty": True,
        "loss_free": loss_free,
        "decoder_coverage": decoder_coverage,
        "decode_coverage": {
            "packet_received": received,
            "packet_decoded": decoded,
            "invalid_radiotap": invalid,
            "unsupported_radiotap": unsupported,
            "truncated_packets": truncated,
            "fcs_bytes_missing": fcs,
            "rejected_radiotap_samples_recorded": sample_count,
            "rejected_radiotap_sample_overflow": sample_overflow,
            "kernel_dropped_packets": dropped,
            "kernel_stats_available": stats,
            "kernel_packets": received + (dropped or 0) if stats else None,
            "kernel_stats_error": None if stats else 5,
            "receive_error": error,
            "capture_limit_reached": limit,
        },
    }


def sender_result(*, cap: dict | None = None,
                  samples: list[dict] | None = None,
                  observations: list[dict] | None = None,
                  fixture_mode: str | None = None) -> dict:
    timing = [{
        "ordinal": ordinal,
        "ieee80211_sequence": 291 + ordinal,
        "awdl_sequence": 34305 + ordinal,
        "mpdu_sha256": HASHES[ordinal],
        "return_bytes": 106,
        "errno": 0,
    } for ordinal in range(4)]
    cap = copy.deepcopy(cap or capture())
    samples = copy.deepcopy(samples or [])
    cap["rejected_radiotap_samples"] = samples
    result = {
        "event": "SENDER_RESULT",
        "status": "complete",
        "tx_flags_requested": "NOACK|NOSEQNO",
        "hardware_honoring": "unknown",
        "frames_attempted": 4,
        "frames_completed": 4,
        "send_timing": timing,
        "tx_provenance": {
            "schema": classifier.SCHEMA,
            "capture": cap,
            "observations": copy.deepcopy(observations or []),
            "run_nonce_is_local_only": True,
            "nonce_in_mpdu": False,
            "tx_status_path": "not_observed",
            "tx_status_pid": None,
            "tx_status_cookie": None,
            "pid_txs_expectation": "unknown",
            "pid_cookie_bound_tx_status": "unknown",
            "pid_cookie_status_source_available": False,
            "rf_transmission_proven": False,
            "ack_proven": False,
            "peer_receipt_proven": False,
        },
    }
    if fixture_mode is not None:
        result["tx_provenance"]["fixture_mode"] = fixture_mode
    return result


def observation(packet_type: int = classifier.PACKET_OUTGOING) -> dict:
    return {
        "ordinal": 0,
        "packet_type": packet_type,
        "exact_mpdu_match": True,
        "mpdu_sha256": HASHES[0],
        "wifi_sequence": 291,
        "awdl_sequence": 34305,
        "observed_ns": 1_000_500,
        "has_tx_flags": False,
        "tx_flags": 0,
        "has_data_retries": False,
        "data_retries": 0,
    }


class OpenWrtTxObservationTests(unittest.TestCase):
    def test_local_send_is_not_rf_ack_or_peer_proof(self):
        result = classifier.classify_sender_result(sender_result())
        self.assertEqual(result["send"]["local_send_accepted"], 4)
        self.assertEqual(result["pid_cookie_bound_tx_status"], "unknown")
        self.assertEqual(result["conditional_pid_txs_expectation"],
                         "not_requested_by_reviewed_noack_path")
        self.assertEqual(result["conditional_pid_txs_expectation_basis"],
                         "offline_reviewed_noack_path_contract_not_runtime_observation")
        self.assertEqual(result["status_sources"], {
            "software_txfree": "not_collected",
            "timeout_generated_ack": "not_collected",
            "raw_hardware_txs": "not_collected",
        })
        self.assertFalse(result["rf_transmission_proven"])
        self.assertFalse(result["ack_proven"])
        self.assertFalse(result["peer_receipt_proven"])

    def test_synthetic_sender_fixture_is_marked_and_never_runtime_evidence(self):
        result = classifier.classify_sender_result(
            sender_result(fixture_mode="synthetic_host_fixture"))
        self.assertEqual(result["fixture_mode"], "synthetic_host_fixture")
        self.assertEqual(result["evidence_scope"], "synthetic")
        self.assertFalse(result["rf_transmission_proven"])
        self.assertFalse(result["ack_proven"])
        self.assertFalse(result["peer_receipt_proven"])

    def test_capture_finished_loss_and_decode_coverage_are_independent(self):
        one_reject = rejected_sample()
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=1,
                        decoder_coverage=False, sample_count=1),
            samples=[one_reject])
        result = classifier.classify_sender_result(value)
        self.assertTrue(result["capture"]["capture_finished"])
        self.assertEqual(result["capture"]["actual_horizon_ns"], 1_000)
        self.assertTrue(result["capture"]["loss_free"])
        self.assertFalse(result["capture"]["decoder_coverage"])
        self.assertEqual(result["capture"]["rejected_samples"][0]["classification"],
                         "rejected_prefix_unmatched")
        self.assertFalse(result["frames"][0]["invocation_bound"])

    def test_no_kernel_stats_means_loss_free_unknown(self):
        value = sender_result(cap=capture(stats=False, dropped=None,
                                          loss_free=None))
        result = classifier.classify_sender_result(value)
        self.assertTrue(result["capture"]["capture_finished"])
        self.assertIsNone(result["capture"]["loss_free"])
        self.assertTrue(result["capture"]["decoder_coverage"])

    def test_actual_finish_horizon_is_not_clamped_to_cutoff_budget(self):
        cap = capture(limit=True, loss_free=False)
        cap.update({"budget_ns": 30_000, "started_ns": 100_000,
                    "ended_ns": 130_000, "actual_finished_ns": 131_000,
                    "actual_horizon_ns": 31_000})
        result = classifier.classify_sender_result(sender_result(cap=cap))
        self.assertEqual(result["capture"]["ended_ns"], 130_000)
        self.assertEqual(result["capture"]["actual_finished_ns"], 131_000)
        self.assertEqual(result["capture"]["actual_horizon_ns"], 31_000)

    def test_actual_horizon_and_cutoff_must_match_timestamps(self):
        cap = capture()
        cap["ended_ns"] += 1
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "capture_cutoff_mismatch"):
            classifier.classify_sender_result(sender_result(cap=cap))

        cap = capture()
        cap["actual_horizon_ns"] += 1
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "actual_horizon_mismatch"):
            classifier.classify_sender_result(sender_result(cap=cap))

    def test_known_receive_error_means_loss_free_false_even_without_stats(self):
        value = sender_result(cap=capture(stats=False, dropped=None,
                                          error=5, loss_free=False))
        result = classifier.classify_sender_result(value)
        self.assertTrue(result["capture"]["capture_finished"])
        self.assertFalse(result["capture"]["loss_free"])

    def test_drops_do_not_claim_missing_tx_completion(self):
        value = sender_result(cap=capture(dropped=1, loss_free=False))
        result = classifier.classify_sender_result(value)
        self.assertFalse(result["capture"]["loss_free"])
        self.assertEqual(result["pid_cookie_bound_tx_status"], "unknown")
        self.assertEqual(result["status_sources"]["raw_hardware_txs"], "not_collected")

    def test_dirty_pre_send_queue_never_binds_exact_hash_to_this_invocation(self):
        cap = capture()
        cap["pre_send_drained_packets"] = 2
        cap["pre_send_queue_empty"] = False
        result = classifier.classify_sender_result(
            sender_result(cap=cap, observations=[observation()]))
        self.assertEqual(result["capture"]["invocation_correlation"],
                         "ambiguous_pre_send_queue")
        self.assertFalse(result["observations"][0]["invocation_bound"])
        self.assertEqual(result["observations"][0]["invocation_correlation"],
                         "ambiguous_pre_send_queue")
        self.assertTrue(all(not frame["invocation_bound"]
                            for frame in result["frames"]))

    def test_pre_send_drain_cap_cannot_be_reported_as_empty(self):
        cap = capture()
        cap["pre_send_drained_packets"] = 256
        cap["pre_send_queue_empty"] = True
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "pre_send_empty_after_drain_cap_contradiction"):
            classifier.classify_sender_result(sender_result(cap=cap))

    def test_clean_queue_exact_hash_is_still_only_a_correlation_candidate(self):
        result = classifier.classify_sender_result(
            sender_result(observations=[observation()]))
        self.assertEqual(result["capture"]["invocation_correlation"],
                         "bounded_clean_queue_candidate")
        self.assertFalse(result["observations"][0]["invocation_bound"])

    def test_empty_capture_keeps_decoder_coverage_unknown(self):
        value = sender_result(cap=capture(received=0, decoded=0,
                                          decoder_coverage=None))
        result = classifier.classify_sender_result(value)
        self.assertIsNone(result["capture"]["decoder_coverage"])

    def test_prefix_is_hashed_only_as_a_prefix_and_never_matches_a_frame(self):
        raw = b"\x00\x00\x78\x00\x00\x00\x00\x20" + bytes(112)
        prefix = raw[:96]
        sample = rejected_sample(raw=raw,
                                 received_len=len(raw), copied_len=len(raw),
                                 raw_prefix_hex=prefix.hex(), raw_prefix_len=len(prefix),
                                 raw_prefix_truncated=True,
                                 raw_prefix_sha256=hashlib.sha256(prefix).hexdigest())
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=1,
                        decoder_coverage=False, sample_count=1),
            samples=[sample])
        result = classifier.classify_sender_result(value)
        checked = result["capture"]["rejected_samples"][0]
        self.assertEqual(checked["raw_prefix_sha256"], hashlib.sha256(prefix).hexdigest())
        self.assertEqual(checked["full_packet_identity"], "unknown")
        self.assertEqual(checked["classification"], "rejected_prefix_unmatched")
        self.assertFalse(checked["rf_transmission_proven"])

    def test_prefix_hash_mismatch_is_rejected(self):
        sample = rejected_sample(raw=b"abcdefgh", raw_prefix_sha256="f" * 64)
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=1,
                        decoder_coverage=False, sample_count=1),
            samples=[sample])
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "raw_prefix_sha256_mismatch"):
            classifier.classify_sender_result(value)

    def test_prefix_cannot_claim_exact_target_or_full_frame_hash(self):
        sample = rejected_sample(target_match=True)
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=1,
                        decoder_coverage=False, sample_count=1),
            samples=[sample])
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "rejected_prefix_overclaim_target_match"):
            classifier.classify_sender_result(value)

    def test_unbound_status_event_input_is_rejected(self):
        value = sender_result()
        value["tx_provenance"]["tx_status_events"] = [{"kind": "raw_hardware_txs"}]
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "tx_status_event_source_not_integrated"):
            classifier.classify_sender_result(value)

    def test_sender_overclaim_is_rejected(self):
        value = sender_result()
        value["tx_provenance"]["ack_proven"] = True
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "sender_overclaim_ack_proven"):
            classifier.classify_sender_result(value)

    def test_runtime_pid_or_expectation_cannot_be_fabricated(self):
        value = sender_result()
        value["tx_provenance"]["tx_status_pid"] = 0
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "runtime_tx_status_pid_must_remain_unknown"):
            classifier.classify_sender_result(value)

        value = sender_result()
        value["tx_provenance"]["pid_txs_expectation"] = "not_requested_by_path"
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "runtime_pid_txs_expectation_must_remain_unknown"):
            classifier.classify_sender_result(value)

    def test_frozen_test100_schema_is_explicitly_rejected(self):
        value = sender_result()
        value["tx_provenance"]["schema"] = classifier.LEGACY_SCHEMA
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "legacy_schema_requires_new_capture"):
            classifier.classify_sender_result(value)

    def test_raw_sample_header_presence_and_truncation_are_strict(self):
        sample = rejected_sample(rtap_declared_len_present=False,
                                 rtap_declared_len=10)
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=1,
                        decoder_coverage=False, sample_count=1),
            samples=[sample])
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "declared_length_presence_disagrees_with_raw_prefix"):
            classifier.classify_sender_result(value)

        raw = b"1234"
        sample = rejected_sample(raw=raw, received_len=4, copied_len=4,
                                 msg_flags=0x20,
                                 packet_truncated=False,
                                 raw_prefix_hex=b"1234".hex(), raw_prefix_len=4,
                                 raw_prefix_sha256=hashlib.sha256(b"1234").hexdigest())
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=0, truncated=1,
                        decoder_coverage=False, loss_free=False,
                        sample_count=1), samples=[sample])
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "truncation_metadata_missing"):
            classifier.classify_sender_result(value)

    def test_raw_header_values_must_match_prefix_bytes(self):
        mutations = [
            ({"version": 1}, "version_disagrees_with_raw_prefix"),
            ({"rtap_declared_len": 11}, "declared_length_disagrees_with_raw_prefix"),
            ({"present_words": [0]}, "present_words_disagree_with_raw_prefix"),
        ]
        for changes, error in mutations:
            with self.subTest(error=error):
                sample = rejected_sample(**changes)
                value = sender_result(
                    cap=capture(received=1, decoded=0, unsupported=1,
                                decoder_coverage=False, sample_count=1),
                    samples=[sample])
                with self.assertRaisesRegex(classifier.ObservationError, error):
                    classifier.classify_sender_result(value)

    def test_present_extension_chain_must_match_prefix(self):
        # The first bitmap word's extension bit is set, but the retained prefix
        # ends before the required second word.
        sample = rejected_sample(raw=b"\x00\x00\x0a\x00\x00\x00\x00\x80",
                                 present_bitmap_complete=True,
                                 present_words=[0x80000000])
        value = sender_result(
            cap=capture(received=1, decoded=0, unsupported=1,
                        decoder_coverage=False, sample_count=1), samples=[sample])
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "present_bitmap_complete_disagrees_with_raw_prefix"):
            classifier.classify_sender_result(value)

    def test_short_prefix_keeps_unavailable_header_fields_unknown(self):
        sample = rejected_sample(raw=b"\x00", reject_reason="short_header",
                                 radiotap_parse_reason="short_header")
        value = sender_result(
            cap=capture(received=1, decoded=0, invalid=1,
                        decoder_coverage=False, sample_count=1), samples=[sample])
        result = classifier.classify_sender_result(value)
        header = result["capture"]["rejected_samples"][0]["raw_header_fields"]
        self.assertEqual(header["version"], 0)
        self.assertFalse(header["pad_present"])
        self.assertIsNone(header["pad"])
        self.assertFalse(header["rtap_declared_len_present"])
        self.assertIsNone(header["rtap_declared_len"])
        self.assertFalse(header["present_bitmap_present"])
        self.assertEqual(header["present_words"], [])

    def test_rejected_sample_count_and_overflow_match_rejection_counters(self):
        value = sender_result(cap=capture(received=2, decoded=0,
                                           unsupported=2,
                                           decoder_coverage=False,
                                           sample_count=1),
                              samples=[rejected_sample()])
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "rejected_sample_count_does_not_match_rejected_packets"):
            classifier.classify_sender_result(value)

    def test_capture_categories_must_account_for_every_received_packet(self):
        value = sender_result(cap=capture(received=2, decoded=1))
        with self.assertRaisesRegex(classifier.ObservationError,
                                    "packet_decode_categories_do_not_partition_received"):
            classifier.classify_sender_result(value)


if __name__ == "__main__":
    unittest.main()
