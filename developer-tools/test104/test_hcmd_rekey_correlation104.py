#!/usr/bin/env python3
from __future__ import annotations

import unittest

from hcmd_rekey_correlation104 import (
    AUTH_COMPONENT_GTK,
    AUTH_FLAG_DOORBELL_ISSUED,
    AUTH_FLAG_REPLAY_CHECKED,
    AUTH_FLAG_REPLAY_EQUAL,
    AUTH_KIND_GROUP2_RESULT,
    AUTH_KIND_KEY_SUBMIT,
    AUTH_KIND_RX_DEAUTH,
    AUTH_SOURCE_HAL_COMMAND,
    AUTH_STAGE_GROUP2_OUTPUT,
    AUTH_STAGE_KEY_CALLBACK,
    COMMAND_GROUP_LONG,
    COMMAND_ID_ADD_STA_KEY,
    COMMAND_QUEUE_ID,
    FLAG_COMMAND_RESPONSE_FAILED,
    FLAG_FIRMWARE_STATUS_PRESENT,
    FLAG_HEADER_FIELDS_PRESENT,
    PHASE_COMMAND_RETIRED,
    PHASE_COMMAND_SUBMITTED,
    PHASE_RX_DISPATCH_COMPLETED,
    PHASE_RX_RESPONSE_REJECTED,
    SOURCE_COMMAND_RESPONSE_QUEUE,
    SOURCE_HOST_COMMAND,
    correlate_key_lifecycle,
    trigger_reasons,
)


def hcmd_row(serial, phase, source, *, index=64, generation=5, fw_generation=5,
             group=COMMAND_GROUP_LONG, mono=1_000_000_000, flags=None,
             result=0, payload_length=4, command_id=COMMAND_ID_ADD_STA_KEY):
    if flags is None:
        flags = FLAG_HEADER_FIELDS_PRESENT
    return {
        "serial": serial,
        "driver_monotonic_ns": mono,
        "driver_generation": generation,
        "firmware_generation": fw_generation,
        "phase": phase,
        "source": source,
        "command_id": command_id,
        "group_id": group,
        "version": 0,
        "qid": COMMAND_QUEUE_ID,
        "index": index,
        "header_sequence": index,
        "flags": flags,
        "result": result,
        "result_detail": 0,
        "packet_length": 48,
        "payload_length": payload_length,
        "reserved": 0,
    }


def auth_event(sequence, kind, *, mono_us, generation=5, association=2,
               attempt=7, stage=0, component=0, source=0, result=0,
               flags=0, detail=0):
    return {
        "sequence": sequence,
        "monotonic_us": mono_us,
        "diagnostic_instance": 1,
        "driver_generation": generation,
        "association_id": association,
        "attempt_id": attempt,
        "kind": kind,
        "stage": stage,
        "component": component,
        "source": source,
        "result": result,
        "flags": flags,
        "detail": detail,
    }


def stable_decoded(rows):
    return {
        "status": "stable_complete_cut",
        "snapshot_stable": True,
        "snapshot_complete": True,
        "header": {
            "version_begin": 10,
            "version_end": 10,
            "window_start_serial": rows[0]["serial"] if rows else 0,
            "window_end_serial": rows[-1]["serial"] if rows else 0,
            "row_count": len(rows),
            "dropped_count": 0,
            "overwritten_count": 0,
            "gap_count": 0,
        },
        "rows": rows,
    }


def stable_auth(events):
    return {"snapshot_status": "stable", "events": events,
            "dropped_count": 0, "driver_generation": 5}


def gtk_submit(*, index=64, mono_us=1_001_000, generation=5,
               association=2, attempt=7, sequence=2):
    detail = (2 << 24) | (0 << 16) | index
    return auth_event(sequence, AUTH_KIND_KEY_SUBMIT, mono_us=mono_us,
        generation=generation, association=association, attempt=attempt,
        stage=AUTH_STAGE_KEY_CALLBACK, component=AUTH_COMPONENT_GTK,
        source=AUTH_SOURCE_HAL_COMMAND, flags=AUTH_FLAG_DOORBELL_ISSUED,
        detail=detail)


class HcmdRekeyCorrelationTests(unittest.TestCase):
    def test_test110_key_sequence_phases_do_not_break_existing_correlation(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(101, 14, SOURCE_HOST_COMMAND, mono=1_000_000_001),
            hcmd_row(102, 15, SOURCE_HOST_COMMAND, mono=1_000_000_002),
            hcmd_row(103, 16, SOURCE_HOST_COMMAND, mono=1_000_000_003),
        ]
        result = correlate_key_lifecycle(
            stable_decoded(rows), stable_auth([gtk_submit()]))
        self.assertNotEqual(result["status"], "hcmd_rows_invalid_or_unordered")
        self.assertEqual(result["lifecycles"][0]["hcmd_submit_serial"], 100)
        self.assertEqual(result["lifecycles"][0]["response_status"],
                         "no_matching_response_row_in_visible_cut")

    def test_same_tuple_command_response_retire_and_later_deauth(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(101, 5, SOURCE_COMMAND_RESPONSE_QUEUE, mono=1_001_100_000),
            hcmd_row(102, PHASE_RX_DISPATCH_COMPLETED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, mono=1_001_200_000,
                     result=1),
            hcmd_row(103, PHASE_COMMAND_RETIRED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, group=0,
                     mono=1_001_300_000),
        ]
        events = [
            gtk_submit(),
            auth_event(3, AUTH_KIND_GROUP2_RESULT, mono_us=1_002_000,
                stage=AUTH_STAGE_GROUP2_OUTPUT,
                flags=AUTH_FLAG_REPLAY_CHECKED | AUTH_FLAG_REPLAY_EQUAL),
            auth_event(4, AUTH_KIND_RX_DEAUTH, mono_us=1_008_000,
                attempt=0, result=16),
        ]
        result = correlate_key_lifecycle(stable_decoded(rows), stable_auth(events))
        life = result["lifecycles"][0]
        self.assertEqual(life["response_status"], "response_seen_and_host_command_retired")
        self.assertEqual(life["hcmd_submit_serial"], 100)
        self.assertTrue(life["rx_deauth_after_same_association"])
        self.assertEqual(life["rx_deauth_reason_code"], 16)
        self.assertEqual(life["same_attempt_group2_replay_relations"], ["equal"])
        self.assertFalse(result["key_install_success_proven"])
        self.assertFalse(result["peer_ack_proven"])

    def test_old_sticky_slot_index_does_not_match_current_group_key(self):
        rows = [
            hcmd_row(99, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     index=37, mono=900_000_000),
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     index=64, mono=1_000_000_000),
        ]
        result = correlate_key_lifecycle(stable_decoded(rows),
                                         stable_auth([gtk_submit()]))
        life = result["lifecycles"][0]
        self.assertEqual(life["hcmd_submit_serial"], 100)
        self.assertEqual(life["response_status"], "no_matching_response_row_in_visible_cut")
        self.assertEqual(life["response_rows"], [])

    def test_failed_add_sta_key_response_is_distinct_from_success(self):
        rows = [
            hcmd_row(200, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=2_000_000_000),
            hcmd_row(201, PHASE_RX_RESPONSE_REJECTED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, mono=2_001_000_000,
                     group=0x41,
                     flags=(FLAG_HEADER_FIELDS_PRESENT |
                            FLAG_COMMAND_RESPONSE_FAILED |
                            FLAG_FIRMWARE_STATUS_PRESENT),
                     result=9),
        ]
        result = correlate_key_lifecycle(
            stable_decoded(rows), stable_auth([gtk_submit(mono_us=2_001_500,
                sequence=2)]))
        life = result["lifecycles"][0]
        self.assertEqual(life["response_status"], "failed_response_flag_or_reject_observed")
        self.assertTrue(life["response_failed_flag_observed"])
        self.assertEqual(life["response_rows"][0]["firmware_status_raw_le32"], 9)
        self.assertFalse(life["key_install_success_proven"])

    def test_local_reject_without_failed_flag_is_not_reported_as_firmware_failure(self):
        rows = [
            hcmd_row(200, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=2_000_000_000),
            hcmd_row(201, PHASE_RX_RESPONSE_REJECTED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, mono=2_001_000_000,
                     group=COMMAND_GROUP_LONG,
                     flags=FLAG_HEADER_FIELDS_PRESENT, result=0),
        ]
        life = correlate_key_lifecycle(
            stable_decoded(rows), stable_auth([gtk_submit(mono_us=2_001_500,
                sequence=2)]))["lifecycles"][0]
        self.assertEqual(life["response_status"],
                         "failed_response_flag_or_reject_observed")
        self.assertFalse(life["response_failed_flag_observed"])
        self.assertTrue(life["local_response_rejected_observed"])
        self.assertFalse(life["response_rows"][0]["response_failed_flag"])
        self.assertTrue(life["response_rows"][0]["local_response_rejected"])

    def test_mismatched_generation_or_tuple_stays_unknown(self):
        rows = [
            hcmd_row(10, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     generation=4, mono=1_000_000_000),
            hcmd_row(11, PHASE_RX_DISPATCH_COMPLETED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, generation=5,
                     mono=1_001_000_000, result=1),
        ]
        result = correlate_key_lifecycle(stable_decoded(rows),
                                         stable_auth([gtk_submit()]))
        self.assertEqual(result["lifecycles"][0]["hcmd_submit_status"],
                         "missing_or_ambiguous_same_tuple_submit")
        self.assertEqual(result["lifecycles"][0]["response_status"], "unknown")

    def test_ambiguous_reused_tuple_does_not_choose_one_submit(self):
        rows = [
            hcmd_row(10, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(11, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_500_000),
        ]
        result = correlate_key_lifecycle(stable_decoded(rows),
                                         stable_auth([gtk_submit()]))
        self.assertEqual(result["lifecycles"][0]["hcmd_submit_status"],
                         "missing_or_ambiguous_same_tuple_submit")

    def test_retained_numeric_cut_predates_gtk_anchor_freshness_unproven(self):
        # Sanitized numeric fixture from Test104's retained HCTX cut: same
        # 64-row serial window, no key-command tuple, and a newest row almost
        # 38 minutes older than the auth callback. No payload/address data.
        rows = []
        first_ns = 1_084_943_836_439
        last_ns = 1_085_221_126_472
        for offset in range(64):
            row = hcmd_row(
                128_755 + offset,
                5 if offset % 2 == 0 else 9,
                3,
                index=219,
                generation=5,
                fw_generation=5,
                group=0,
                mono=first_ns + (last_ns - first_ns) * offset // 63,
                flags=216,
                result=0 if offset % 2 == 0 else 1,
                payload_length=452,
                command_id=193,
            )
            row["qid"] = 160
            row["header_sequence"] = 41_179
            row["packet_length"] = 456
            rows.append(row)
        decoded = stable_decoded(rows)
        decoded["header"].update({
            "version_begin": 128_818,
            "version_end": 128_818,
            "window_start_serial": 128_755,
            "window_end_serial": 128_818,
            "row_count": 64,
            "dropped_count": 0,
            "overwritten_count": 128_754,
            "gap_count": 0,
        })
        result = correlate_key_lifecycle(decoded, stable_auth([
            gtk_submit(index=75, mono_us=3_372_706_060, association=1,
                       attempt=1, sequence=6),
        ]))
        life = result["lifecycles"][0]
        self.assertEqual(life["hcmd_submit_status"],
                         "cut_predates_submit_freshness_unproven")
        self.assertEqual(life["hcmd_cut_freshness"]["status"],
                         "cut_predates_submit_join_window")
        self.assertGreater(life["hcmd_cut_freshness"]["older_than_anchor_us"],
                           5_000_000)
        self.assertEqual(life["response_status"], "unknown")
        self.assertTrue(life["hcmd_cut_freshness"]["freshness_unproven"])

    def test_fresh_nonmatching_cut_does_not_get_stale_label(self):
        rows = [hcmd_row(
            200, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
            index=90, command_id=0x20, mono=3_372_706_100_000,
        )]
        result = correlate_key_lifecycle(stable_decoded(rows), stable_auth([
            gtk_submit(index=75, mono_us=3_372_706_060, association=1,
                       attempt=1, sequence=6),
        ]))
        life = result["lifecycles"][0]
        self.assertEqual(life["hcmd_submit_status"],
                         "missing_or_ambiguous_same_tuple_submit")
        self.assertEqual(life["hcmd_cut_freshness"]["status"],
                         "cut_reaches_submit_join_window")
        self.assertTrue(life["hcmd_cut_freshness"]["freshness_unproven"])
        self.assertIn("does not prove snapshot publication freshness",
                      life["hcmd_cut_freshness"]["interpretation"])
        self.assertEqual(life["response_status"], "unknown")

    def test_deauth_cut_without_enqueue_does_not_erase_older_anchor(self):
        rows = [hcmd_row(
            128_818, PHASE_RX_DISPATCH_COMPLETED,
            SOURCE_COMMAND_RESPONSE_QUEUE, index=219, command_id=193,
            mono=1_085_221_126_472, result=1,
        )]
        result = correlate_key_lifecycle(stable_decoded(rows), stable_auth([
            auth_event(49, 1, mono_us=3_381_798_510, association=1,
                       attempt=10, source=1),
            auth_event(54, AUTH_KIND_RX_DEAUTH, mono_us=3_382_814_203,
                       association=1, attempt=0, stage=15, source=1,
                       result=16, detail=192),
        ]))
        self.assertEqual(result["status"],
                         "no_eligible_group_key_local_enqueue_in_auth_cut")
        self.assertEqual(result["auth_cut_scope"],
                         "this_bounded_snapshot_only")
        self.assertEqual(result["hcmd_cut_freshness"]["status"],
                         "cut_predates_submit_join_window")
        self.assertIn("does not exclude an enqueue", result["interpretation"])

    def test_non_key_command_reusing_slot_ends_old_attribution_window(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(101, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     command_id=0x20, mono=1_001_000_000),
            hcmd_row(102, PHASE_RX_DISPATCH_COMPLETED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, mono=1_002_000_000,
                     result=1),
        ]
        result = correlate_key_lifecycle(stable_decoded(rows),
                                         stable_auth([gtk_submit()]))
        self.assertEqual(result["lifecycles"][0]["response_status"],
                         "no_matching_response_row_in_visible_cut")
        self.assertEqual(result["lifecycles"][0]["response_rows"], [])

    def test_firmware_generation_mismatch_is_unknown(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(101, PHASE_RX_DISPATCH_COMPLETED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, fw_generation=6,
                     mono=1_001_000_000, result=1),
        ]
        life = correlate_key_lifecycle(stable_decoded(rows),
            stable_auth([gtk_submit()]))["lifecycles"][0]
        self.assertEqual(life["response_status"],
                         "response_generation_mismatch_unknown")
        self.assertTrue(life["mismatched_response_generation_observed"])
        self.assertEqual(life["response_rows"], [])

    def test_same_microsecond_quantization_does_not_reject_host_submit(self):
        rows = [hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                         mono=1_000_000_100)]
        event = gtk_submit(mono_us=1_000_000)
        life = correlate_key_lifecycle(stable_decoded(rows),
            stable_auth([event]))["lifecycles"][0]
        self.assertEqual(life["hcmd_submit_status"],
                         "same_tuple_submit_observed")
        self.assertEqual(life["hcmd_submit_serial"], 100)
        self.assertEqual(life["response_status"],
                         "no_matching_response_row_in_visible_cut")

    def test_prior_contradictory_response_does_not_poison_next_lifecycle(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     index=64, mono=1_000_000_000),
            hcmd_row(101, PHASE_RX_RESPONSE_REJECTED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, index=64, mono=1_001_000_000,
                     flags=(FLAG_HEADER_FIELDS_PRESENT |
                            FLAG_FIRMWARE_STATUS_PRESENT |
                            (1 << 11)), result=9),
            hcmd_row(102, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     index=65, mono=1_002_000_000),
            hcmd_row(103, PHASE_RX_DISPATCH_COMPLETED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, index=65, mono=1_003_000_000,
                     result=1),
            hcmd_row(104, PHASE_COMMAND_RETIRED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, index=65, group=0,
                     mono=1_003_100_000),
        ]
        events = [gtk_submit(index=64, mono_us=1_001_500, sequence=2),
                  gtk_submit(index=65, mono_us=1_003_000, sequence=3)]
        result = correlate_key_lifecycle(stable_decoded(rows),
                                         stable_auth(events))
        self.assertEqual(len(result["lifecycles"]), 2)
        self.assertEqual(result["lifecycles"][0]["response_status"],
                         "contradictory_response_metadata_unknown")
        self.assertEqual(result["lifecycles"][1]["response_status"],
                         "response_seen_and_host_command_retired")

    def test_status_length_mismatch_does_not_publish_raw_status(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(101, PHASE_RX_RESPONSE_REJECTED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, mono=1_001_000_000,
                     flags=(FLAG_HEADER_FIELDS_PRESENT |
                            FLAG_FIRMWARE_STATUS_PRESENT), result=9,
                     payload_length=8),
        ]
        life = correlate_key_lifecycle(stable_decoded(rows),
            stable_auth([gtk_submit()]))["lifecycles"][0]
        self.assertEqual(life["response_status"],
                         "contradictory_response_metadata_unknown")
        self.assertEqual(life["response_rows"], [])

    def test_wrong_command_group_does_not_correlate(self):
        rows = [hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                         group=2, mono=1_000_000_000)]
        life = correlate_key_lifecycle(stable_decoded(rows),
            stable_auth([gtk_submit()]))["lifecycles"][0]
        self.assertEqual(life["hcmd_submit_status"],
                         "missing_or_ambiguous_same_tuple_submit")

    def test_retired_phase_uses_normalized_group_zero_but_raw_rx_does_not(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     mono=1_000_000_000),
            hcmd_row(101, PHASE_RX_RESPONSE_REJECTED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, group=0,
                     mono=1_001_000_000),
            hcmd_row(102, PHASE_COMMAND_RETIRED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, group=0,
                     mono=1_001_100_000),
        ]
        life = correlate_key_lifecycle(stable_decoded(rows),
            stable_auth([gtk_submit()]))["lifecycles"][0]
        self.assertEqual(life["response_status"],
                         "response_seen_and_host_command_retired")
        self.assertEqual([row["phase"] for row in life["response_rows"]],
                         [PHASE_COMMAND_RETIRED])

    def test_missing_firmware_generation_is_unknown(self):
        rows = [
            hcmd_row(100, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND,
                     fw_generation=0, mono=1_000_000_000),
            hcmd_row(101, PHASE_RX_DISPATCH_COMPLETED,
                     SOURCE_COMMAND_RESPONSE_QUEUE, fw_generation=0,
                     mono=1_001_000_000, result=1),
        ]
        life = correlate_key_lifecycle(stable_decoded(rows),
            stable_auth([gtk_submit()]))["lifecycles"][0]
        self.assertEqual(life["response_status"],
                         "response_firmware_generation_unavailable_unknown")
        self.assertTrue(life["response_firmware_generation_unavailable"])
        self.assertEqual(life["response_rows"], [])

    def test_malformed_auth_event_is_rejected(self):
        event = gtk_submit()
        event["sequence"] = True
        result = correlate_key_lifecycle(
            stable_decoded([hcmd_row(100, PHASE_COMMAND_SUBMITTED,
                                     SOURCE_HOST_COMMAND)]),
            stable_auth([event]))
        self.assertEqual(result["status"], "auth_event_invalid")

    def test_incomplete_cut_is_not_negative_response_evidence(self):
        decoded = stable_decoded([hcmd_row(100, PHASE_COMMAND_SUBMITTED,
                                            SOURCE_HOST_COMMAND)])
        decoded["snapshot_complete"] = False
        result = correlate_key_lifecycle(decoded, stable_auth([gtk_submit()]))
        self.assertEqual(result["status"], "hcmd_cut_unstable_or_incomplete")
        self.assertEqual(result["lifecycles"], [])

    def test_initial_snapshot_rows_are_baseline_not_new_triggers(self):
        rows = [hcmd_row(1, PHASE_COMMAND_SUBMITTED, SOURCE_HOST_COMMAND)]
        decoded = stable_decoded(rows)
        auth = stable_auth([gtk_submit()])
        seen_rows = {(5, 1)}
        seen_auth = {(1, 2)}
        reasons = trigger_reasons(decoded, auth, {"snapshot_status": "stable"},
                                  None, {"present": True}, seen_rows, seen_auth)
        self.assertEqual(reasons, [])


if __name__ == "__main__":
    unittest.main()
