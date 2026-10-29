#!/usr/bin/env python3
"""Offline fail-closed tests for the 544-byte Wi-Fi link-state OSData trace."""

import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import iwx_link_state_trace_diagnostics as diagnostics


def record(sequence, *, event=1, valid_mask=0x7F, if_up_running=3):
    has = lambda bit: bool(valid_mask & (1 << bit))
    return diagnostics.WIFI_LINK_TRACE_RECORD.pack(
        sequence, 100000 + sequence, event,
        4 if has(0) else 0, 5 if has(0) else 0,
        6 if has(1) else 0, 7 if has(2) else 0,
        -8 if has(3) else 0,
        if_up_running if has(4) else 0,
        9 if has(5) else 0, 10 if has(5) else 0,
        11 if has(6) else 0, valid_mask)


def payload(*, schema=2, capacity=8, begin=2, end=2, dropped=0,
            count=2, next_sequence=2, records=None):
    if records is None:
        records = [record(1), record(2, event=6)]
    records = list(records) + [bytes(diagnostics.WIFI_LINK_TRACE_RECORD.size)] * (
        diagnostics.WIFI_LINK_TRACE_CAPACITY - len(records))
    return diagnostics.WIFI_LINK_TRACE_HEADER.pack(
        schema, capacity, begin, end, dropped, count, next_sequence) + b''.join(records)


class WifiLinkTraceTests(unittest.TestCase):
    def test_valid_snapshot_is_decoded_through_numeric_whitelist(self):
        raw = payload()
        self.assertEqual(len(raw), diagnostics.WIFI_LINK_TRACE_SIZE)
        self.assertEqual(diagnostics.WIFI_LINK_TRACE_RECORD.size, 64)
        report = diagnostics.decode_wifi_link_trace_osdata(raw)
        self.assertTrue(report['valid'], report['reasons'])
        self.assertEqual(report['status'], 'valid_wifi_link_transition_trace')
        self.assertEqual([row['sequence'] for row in report['records']], [1, 2])
        self.assertEqual(report['records'][0]['event'], 'new_state_requested')
        self.assertEqual(report['records'][0]['result_code'], -8)
        self.assertEqual(report['records'][0]['if_up_running'], 3)
        self.assertFalse(report['wifi_link_stability_proven'])
        self.assertFalse(report['radio_transmit_proven'])
        self.assertFalse(report['peer_receipt_proven'])
        self.assertFalse(report['airdrop_proven'])
        forbidden = ('address', 'mac', 'ssid', 'packet', 'frame', 'peer')
        self.assertFalse(any(any(term in key.lower() for term in forbidden)
                             for row in report['records'] for key in row))

    def test_invalid_fields_are_not_exported_as_values(self):
        raw = payload(records=[record(1, valid_mask=0), record(2, valid_mask=0)])
        report = diagnostics.decode_wifi_link_trace_osdata(raw)
        self.assertTrue(report['valid'], report['reasons'])
        row = report['records'][0]
        self.assertIsNone(row['old_state'])
        self.assertIsNone(row['deauth_reason'])
        self.assertIsNone(row['result_code'])
        self.assertIsNone(row['if_up_running'])

    def test_nonzero_value_without_its_validity_bit_fails_closed(self):
        bad = diagnostics.WIFI_LINK_TRACE_RECORD.pack(
            1, 100001, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        report = diagnostics.decode_wifi_link_trace_osdata(
            payload(records=[bad, record(2, valid_mask=0)]))
        self.assertFalse(report['valid'])
        self.assertIn('record_0_invalid_field_nonzero_old_state',
                      report['reasons'])

    def test_schema_seqlock_count_event_and_mask_errors_fail_closed(self):
        cases = (
            (payload(schema=3), 'unsupported_schema'),
            (payload(begin=3, end=3), 'snapshot_seqlock_unstable'),
            (payload(begin=2, end=4), 'snapshot_seqlock_unstable'),
            (payload(count=9, next_sequence=9), 'count_out_of_range'),
            (payload(count=1, next_sequence=2), 'sequence_count_mismatch'),
            (payload(records=[record(1), record(2, event=8)]), 'record_1_unknown_event_code'),
            (payload(records=[record(1), record(2, valid_mask=0x80)]), 'record_1_unknown_validity_bits'),
            (payload(records=[record(1), record(2, if_up_running=4)]), 'record_1_interface_flags_out_of_range'),
        )
        for raw, reason in cases:
            with self.subTest(reason=reason):
                report = diagnostics.decode_wifi_link_trace_osdata(raw)
                self.assertFalse(report['valid'])
                self.assertIn(reason, report['reasons'])
                self.assertFalse(report['wifi_link_stability_proven'])

    def test_sequence_gaps_are_rejected(self):
        report = diagnostics.decode_wifi_link_trace_osdata(
            payload(records=[record(1), record(4)], next_sequence=4))
        self.assertFalse(report['valid'])
        self.assertIn('record_0_record_sequence_not_contiguous', report['reasons'])

    def test_wrong_length_or_type_is_unknown(self):
        for value in (None, 'raw-data', b'x' * 543, b'x' * 545):
            with self.subTest(value=type(value).__name__):
                report = diagnostics.decode_wifi_link_trace_osdata(value)
                self.assertFalse(report['valid'])
                self.assertFalse(report['wifi_link_stability_proven'])
        self.assertEqual(
            diagnostics.decode_wifi_link_trace_osdata(b'x' * 543)['status'],
            'unknown_invalid_length')


if __name__ == '__main__':
    unittest.main()
