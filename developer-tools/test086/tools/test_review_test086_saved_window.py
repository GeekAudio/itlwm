"""Offline tests for the Test086 saved-window correction review."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import review_test086_saved_window as REVIEW


def _load_fixture_module():
    path = ROOT / 'tests' / 'test086_rx_entry_guard.py'
    spec = importlib.util.spec_from_file_location('test086_public_rx_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE = _load_fixture_module()


def signed_u32_trace_reads():
    """Build a small synthetic closed trace with two stable signed U32 values."""
    reads = FIXTURE.closed_zero_event_reads()
    event = 'NativeP2PRxTraceEvent0'
    for sample in reads:
        sample['NativeP2PRxTraceEventCount'] = 1
        values = {
            'Serial': 1,
            'OwnerSerial': 1,
            'HostMonotonicUs': 150,
            'Kind': 3,
            'HostMonotonicPresent': 1,
            'SourceKnown': 0,
            'SourceOrdinal': 0,
            'PendingDrain': 0,
            'WirePhyPresent': 1,
            'WirePhyTxUs': -1488060950,
            'WireTargetPresent': 1,
            'WireTargetTxUs': -1488061059,
        }
        for suffix, value in values.items():
            sample[event + suffix] = value
        for suffix in FIXTURE.EVIDENCE.RX_TRACE_OWNER_EPOCH_FIELDS:
            sample[event + suffix] = 1
    return reads


def empty_receipt(status='not_published_yet'):
    return {
        'receipt_observed': False,
        'status': status,
        'missing': [f'receipt-field-{index}' for index in range(24)],
        'invalid': [],
        'local_ifnet_input_kpi_accepted': False,
        'peer_or_socket_receipt_proven': False,
        'airdrop_proven': False,
    }


def no_data_native_report(reads=None):
    reads = reads or signed_u32_trace_reads()
    names = REVIEW.COUNTER_NAMES
    snapshot = {
        'counter_presence': {name: True for name in names},
        'counters': {name: 0 for name in names},
        'descriptor_candidate_count': 0,
    }
    return {
        'session_complete': False,
        'roc_session_complete': True,
        'roc_session_problems': [],
        'post_profile_problems': [
            REVIEW.RECEIPT_BLOCKER,
            REVIEW.TRACE_BLOCKER,
        ],
        'rx_trace_properties': reads,
        'rx_trace_evidence': {
            'valid': False,
            'stable_complete_snapshot': False,
            'trace_coverage_complete': False,
            'reasons': ['unstable_or_incomplete_snapshot_version',
                        'trace_fields_changed_across_reads'],
            'invalid_fields': [
                'pre.NativeP2PRxTraceEvent0WirePhyTxUs',
                'pre.NativeP2PRxTraceEvent0WireTargetTxUs',
            ],
        },
        'native_awdl_data_rx_initial': snapshot,
        'native_awdl_data_rx_after': snapshot,
        'native_awdl_data_rx_delta': {
            'observed_counter_delta': {name: 0 for name in names},
        },
        'native_awdl_data_rx149_receipt_initial': empty_receipt(),
        'native_awdl_data_rx149_receipt_after': empty_receipt(),
        'native_awdl_data_rx149_receipt_delta': {
            'receipt_session_complete': False,
            'new_sequence_since_prearm': None,
            'local_ifnet_input_kpi_accepted': False,
            'peer_or_socket_receipt_proven': False,
            'airdrop_proven': False,
        },
    }


class TestReviewTest086SavedWindow(unittest.TestCase):
    def test_stable_signed_u32_is_recovered_without_promoting_missing_data(self):
        report = REVIEW.review_saved_window(
            no_data_native_report(), {'complete': False})
        trace = report['trace_review']
        self.assertTrue(trace['signed_u32_normalization']['valid'])
        self.assertEqual(trace['signed_u32_normalization']['converted_scalar_count'], 6)
        self.assertTrue(trace['corrected_production_trace_guard']['valid'])
        self.assertTrue(trace['corrected_production_trace_guard']['snapshot_complete_gate'])
        self.assertTrue(trace['trace_guard_changed_from_fail_to_pass'])
        self.assertEqual(report['roc']['roc_session_complete'], True)
        self.assertEqual(report['acceptance']['overall_measurement_complete'], False)
        self.assertFalse(report['acceptance']['overall_data_acceptance_promoted'])
        self.assertEqual(report['acceptance']['derived_remaining_problems_after_trace_recheck'],
                         [REVIEW.RECEIPT_BLOCKER])
        receipt = report['native_data_rx']['receipt_after']
        self.assertFalse(receipt['observed'])
        self.assertEqual(receipt['status'], 'not_published_yet')
        self.assertEqual(receipt['missing_field_count'], 24)
        self.assertFalse(report['native_data_rx']['data_input_acceptance_claimed'])
        for counter in REVIEW.COUNTER_NAMES:
            self.assertEqual(report['native_data_rx']['counts'][counter]['after']['value'], 0)
            self.assertEqual(report['native_data_rx']['counts'][counter]['after']['status'],
                             'observed_numeric_counter')

    def test_negative_value_outside_signed_i32_range_is_rejected(self):
        reads = signed_u32_trace_reads()
        for sample in reads:
            sample['NativeP2PRxTraceEvent0WirePhyTxUs'] = -(1 << 31) - 1
        report = REVIEW.review_saved_window(no_data_native_report(reads))
        self.assertFalse(report['trace_review']['signed_u32_normalization']['valid'])
        self.assertFalse(report['trace_review']['corrected_production_trace_guard']['valid'])
        self.assertFalse(report['trace_review']['trace_guard_changed_from_fail_to_pass'])
        self.assertFalse(report['acceptance']['overall_data_acceptance_promoted'])

    def test_u64_event_serial_is_never_reinterpreted_as_u32(self):
        reads = signed_u32_trace_reads()
        for sample in reads:
            sample['NativeP2PRxTraceEvent0Serial'] = -1
        report = REVIEW.review_saved_window(no_data_native_report(reads))
        self.assertTrue(report['trace_review']['signed_u32_normalization']['valid'])
        self.assertFalse(report['trace_review']['corrected_production_trace_guard']['valid'])
        invalid = report['trace_review']['corrected_production_trace_guard']['invalid_fields']
        self.assertTrue(any('Event0Serial' in field for field in invalid))

    def test_mixed_signed_unsigned_encoding_across_reads_is_rejected(self):
        reads = signed_u32_trace_reads()
        reads[1]['NativeP2PRxTraceEvent0WirePhyTxUs'] = 2806906346
        report = REVIEW.review_saved_window(no_data_native_report(reads))
        normalization = report['trace_review']['signed_u32_normalization']
        self.assertFalse(normalization['valid'])
        self.assertIn('NativeP2PRxTraceEvent0WirePhyTxUs', normalization['raw_changed'])
        self.assertFalse(report['trace_review']['corrected_production_trace_guard']['valid'])

    def test_mixed_snapshot_versions_are_still_rejected(self):
        reads = signed_u32_trace_reads()
        reads[2]['NativeP2PRxTraceSnapshotVersionEnd'] = 6
        report = REVIEW.review_saved_window(no_data_native_report(reads))
        self.assertTrue(report['trace_review']['signed_u32_normalization']['valid'])
        corrected = report['trace_review']['corrected_production_trace_guard']
        self.assertFalse(corrected['valid'])
        self.assertFalse(corrected['snapshot_complete_gate'])


if __name__ == '__main__':
    unittest.main()
