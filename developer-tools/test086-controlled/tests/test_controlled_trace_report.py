from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest


TOOL_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "test086_controlled_trace_report", TOOL_DIR / "controlled_trace_report.py")
trace_report = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = trace_report
SPEC.loader.exec_module(trace_report)


def empty_legacy_derivation():
    raw = {label: {"NativeP2PRxTraceEventCount": 0,
                   "NativeP2PRxTraceSchemaVersion": 1}
           for label in ("pre", "middle", "post")}
    guard = {
        "valid": True,
        "stable_complete_snapshot": True,
        "trace_coverage_complete": True,
        "schema_supported": True,
        "stage_results_valid": True,
        "source_attribution_complete": True,
        "epoch_match": True,
        "owner_present": True,
        "owner_inactive_post_roc": True,
        "producer_closed": True,
        "producer_time_valid": True,
        "dropped_event_count": 0,
        "pending_drain_count": 0,
        "session_anomaly_count": 0,
        "session_boundary_order_invalid": 0,
        "source_table_full_count": 0,
        "stale_completion_count": 0,
        "time_event_notification_dropped_count": 0,
        "untracked_pending_drain_count": 0,
        "untracked_pending_identity_overflow_count": 0,
        "event_count": 0,
        "missing_fields": [],
        "invalid_fields": [],
        "reasons": [],
        "values": {"NativeP2PRxTraceEventCount": 0},
    }
    normalized = deepcopy(raw)
    return {
        "schema": "Test076 derived RX trace validation",
        "schema_version": 1,
        "raw_snapshots": raw,
        "normalization": {
            "valid": False,
            "checked_property_count": 0,
            "missing_fields": [],
            "invalid_fields": [],
            "raw_changed": [],
            "reasons": ["no_whitelisted_u32_fields"],
            "normalized_snapshots": normalized,
            "audit": [],
            "raw_snapshots_mutated": False,
        },
        "guard": guard,
        "combined_valid": False,
        "raw_snapshots_preserved": True,
        "source_test075_report_updated": False,
        "source_test075_overall_result_promoted": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }


class ControlledTraceReportTests(unittest.TestCase):
    def test_stable_empty_event_timeline_is_not_applicable_not_frame_evidence(self):
        source = empty_legacy_derivation()
        original = deepcopy(source)
        result = trace_report.derive_controlled_trace_report(source)

        self.assertEqual(result["status"], "not_applicable_empty_timeline")
        self.assertTrue(result["combined_valid"])
        self.assertEqual(result["normalization"]["status"],
                         "not_applicable_empty_timeline")
        self.assertEqual(result["normalization"]["reason_history"],
                         ["no_whitelisted_u32_fields"])
        self.assertEqual(result["event_count"], 0)
        self.assertFalse(result["control_frames_observed"])
        self.assertFalse(result["data_frames_observed"])
        self.assertFalse(result["empty_timeline_is_frame_evidence"])
        self.assertFalse(result["peer_receipt_proven"])
        self.assertFalse(result["airdrop_proven"])
        self.assertEqual(source, original)
        self.assertEqual(result["raw_snapshots"], original["raw_snapshots"])

    def test_positive_count_without_whitelisted_fields_stays_invalid(self):
        source = empty_legacy_derivation()
        for snapshot in source["raw_snapshots"].values():
            snapshot["NativeP2PRxTraceEventCount"] = 1
        source["guard"]["event_count"] = 1
        source["guard"]["values"]["NativeP2PRxTraceEventCount"] = 1
        result = trace_report.derive_controlled_trace_report(source)
        self.assertFalse(result["combined_valid"])
        self.assertEqual(result["status"], "invalid_or_not_applicable")
        self.assertIn("event_count_nonzero",
                      result["not_applicable_rejection_reasons"])

    def test_changed_bool_or_inconsistent_count_stays_invalid(self):
        cases = []
        changed = empty_legacy_derivation()
        changed["raw_snapshots"]["post"]["NativeP2PRxTraceEventCount"] = 1
        cases.append(("changed", changed, "event_count_changed"))
        boolean = empty_legacy_derivation()
        boolean["raw_snapshots"]["middle"]["NativeP2PRxTraceEventCount"] = False
        cases.append(("bool", boolean, "event_count_not_exact_int_middle"))
        inconsistent_guard = empty_legacy_derivation()
        inconsistent_guard["guard"]["event_count"] = 1
        cases.append(("guard count", inconsistent_guard,
                      "production_guard_event_count_invalid"))
        for label, source, reason in cases:
            with self.subTest(label=label):
                result = trace_report.derive_controlled_trace_report(source)
                self.assertFalse(result["combined_valid"])
                self.assertIn(reason, result["not_applicable_rejection_reasons"])

    def test_any_event_entry_including_out_of_range_residue_blocks_empty_case(self):
        for location in ("raw", "normalized", "guard"):
            source = empty_legacy_derivation()
            if location == "raw":
                source["raw_snapshots"]["middle"]["NativeP2PRxTraceEvent32OwnerSerial"] = 0
            elif location == "normalized":
                source["normalization"]["normalized_snapshots"]["post"][
                    "NativeP2PRxTraceEvent0Status"] = 0
            else:
                source["guard"]["values"]["NativeP2PRxTraceEvent1Status"] = 0
            with self.subTest(location=location):
                result = trace_report.derive_controlled_trace_report(source)
                self.assertFalse(result["combined_valid"])
                self.assertTrue(result["not_applicable_rejection_reasons"])

    def test_guard_and_normalization_failure_boundaries_stay_invalid(self):
        for key, value, reason in (
                ("valid", False, "production_guard_not_true_valid"),
                ("stable_complete_snapshot", False,
                 "production_guard_not_true_stable_complete_snapshot"),
                ("trace_coverage_complete", False,
                 "production_guard_not_true_trace_coverage_complete")):
            source = empty_legacy_derivation()
            source["guard"][key] = value
            result = trace_report.derive_controlled_trace_report(source)
            self.assertFalse(result["combined_valid"])
            self.assertIn(reason, result["not_applicable_rejection_reasons"])

        extra_reason = empty_legacy_derivation()
        extra_reason["normalization"]["reasons"].append("other_failure")
        result = trace_report.derive_controlled_trace_report(extra_reason)
        self.assertFalse(result["combined_valid"])
        self.assertIn("normalization_has_other_reasons",
                      result["not_applicable_rejection_reasons"])

    def test_extra_snapshot_or_unknown_legacy_schema_fails_closed(self):
        extra = empty_legacy_derivation()
        extra["raw_snapshots"]["fourth"] = {
            "NativeP2PRxTraceEventCount": 0}
        result = trace_report.derive_controlled_trace_report(extra)
        self.assertFalse(result["combined_valid"])
        self.assertIn("raw_snapshot_labels_not_exact_three",
                      result["not_applicable_rejection_reasons"])

        wrong_schema = empty_legacy_derivation()
        wrong_schema["schema_version"] = True
        result = trace_report.derive_controlled_trace_report(wrong_schema)
        self.assertFalse(result["combined_valid"])
        self.assertIn("legacy_schema_invalid",
                      result["not_applicable_rejection_reasons"])

    def test_existing_valid_nonempty_derivation_is_preserved(self):
        source = empty_legacy_derivation()
        for label, snapshot in source["raw_snapshots"].items():
            snapshot["NativeP2PRxTraceEventCount"] = 1
            snapshot["NativeP2PRxTraceEvent0Status"] = 1
        for snapshot in source["normalization"]["normalized_snapshots"].values():
            snapshot["NativeP2PRxTraceEventCount"] = 1
            snapshot["NativeP2PRxTraceEvent0Status"] = 1
        source["normalization"].update({
            "valid": True, "checked_property_count": 1,
            "reasons": [], "audit": [{"property": "NativeP2PRxTraceEvent0Status"}],
        })
        source["guard"]["event_count"] = 1
        source["guard"]["values"]["NativeP2PRxTraceEventCount"] = 1
        source["combined_valid"] = True
        result = trace_report.derive_controlled_trace_report(source)
        self.assertTrue(result["combined_valid"])
        self.assertEqual(result["status"], "legacy_validated_nonempty_timeline")
        self.assertEqual(result["normalization"], source["normalization"])
        self.assertFalse(result["peer_receipt_proven"])


if __name__ == "__main__":
    unittest.main()
