#!/usr/bin/env python3
"""Offline schema and fail-closed checks for AWDL OSData diagnostics."""

import struct
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import awdl_osdata_diagnostics as diagnostics


def attempt_payload(*, final_token=42, final_generation=12,
                    final_roc_generation=14, consistency_flags=3):
    # Exact packed ABI: 110 bytes, little endian, no address or frame fields.
    return struct.pack(
        '<IH12B4I2Q2Q3I4Q',
        diagnostics.CURRENT_AW_ATTEMPT_MAGIC, 1,
        1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1,
        consistency_flags,
        11, 12, 13, final_roc_generation,
        42, 12,
        1000, 1100,
        2, 0, 0,
        1200, 1500, 1200, 1500,
    )


def qm_payload(*, token=42, context=11, power=12, station=13,
               roc_token=77, schema=1, gp2_valid=0):
    values = [0] * 36
    fields = diagnostics.QM_WIRE_FIELD_NAMES
    for name, value in {
            'schema': schema, 'token': token, 'context_generation': context,
            'power_generation': power, 'station_generation': station,
            'roc_token': roc_token, 'queue_id': 7, 'ring_size': 256,
            'descriptor_index': 3, 'frame_control': 0x80,
            'sequence_control': 0x1230, 'mpdu_length': 128,
            'header_length': 24, 'ds_bits': 0, 'address_role_flags': 0x83,
            'header_is_valid': 1, 'tx_command_api': 2,
            'payload_segment_count': 1, 'payload_bytes': 104,
            'channel': 6, 'frequency_mhz': 2437,
            'host_pre_doorbell_us': 1000, 'window_not_before_us': 1200,
            'window_deadline_us': 1500, 'current_gp2_valid': gp2_valid,
    }.items():
        values[fields.index(name)] = value
    return struct.pack('<36Q', *values)


class CurrentAwAttemptOnlyTests(unittest.TestCase):
    def test_candidate_is_local_attempt_only_and_fixed_size(self):
        payload = attempt_payload()
        self.assertEqual(len(payload), diagnostics.CURRENT_AW_ATTEMPT_SIZE)
        report = diagnostics.decode_current_aw_attempt_osdata(payload)
        self.assertTrue(report['valid'], report['reasons'])
        self.assertEqual(report['status'], 'valid_attempt_only')
        self.assertEqual(report['qm_token'], 42)
        self.assertEqual(report['qm_generation'], 12)
        self.assertTrue(report['qm_identity_consistent'])
        self.assertTrue(report['planner_epochs_stable'])
        self.assertEqual(report['plans']['initial']['planner_now_us'], 1000)
        self.assertEqual(report['plans']['final']['planner_now_us'], 1100)
        self.assertTrue(report['plans']['initial']['fallback_used'])
        self.assertTrue(report['plans']['final']['candidate_valid'])
        self.assertFalse(report['radio_transmit_proven'])
        self.assertFalse(report['peer_receipt_proven'])
        self.assertFalse(report['airdrop_proven'])

    def test_rejected_plan_has_status_without_window(self):
        payload = struct.pack(
            '<IH12B4I2Q2Q3I4Q',
            diagnostics.CURRENT_AW_ATTEMPT_MAGIC, 1,
            1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0,
            3,
            11, 12, 13, 14,
            42, 12,
            1000, 1100,
            2, 26, 27,
            0, 0, 0, 0,
        )
        report = diagnostics.decode_current_aw_attempt_osdata(payload)
        self.assertTrue(report['valid'], report['reasons'])
        self.assertFalse(report['plans']['initial']['candidate_valid'])
        self.assertEqual(report['plans']['initial']['status'], 26)
        self.assertEqual(report['plans']['final']['status'], 27)
        self.assertEqual(report['plans']['final']['earliest_submit_us'], 0)

    def test_qm_generation_mismatch_is_visible_but_never_proof(self):
        payload = bytearray(attempt_payload())
        # qmGeneration offset is 42; set it to 99 without touching other fields.
        struct.pack_into('<Q', payload, 42, 99)
        report = diagnostics.decode_current_aw_attempt_osdata(payload)
        self.assertFalse(report['valid'])
        self.assertIn('qm_power_generation_mismatch', report['reasons'])
        self.assertFalse(report['radio_transmit_proven'])

    def test_changed_epochs_clear_stability_flag(self):
        report = diagnostics.decode_current_aw_attempt_osdata(
            attempt_payload(consistency_flags=1))
        self.assertTrue(report['valid'], report['reasons'])
        self.assertTrue(report['qm_identity_consistent'])
        self.assertFalse(report['planner_epochs_stable'])

    def test_invalid_length_schema_proof_bits_and_unknown_flags_fail_closed(self):
        payload = attempt_payload()
        self.assertFalse(diagnostics.decode_current_aw_attempt_osdata(
            payload[:-1])['valid'])
        self.assertFalse(diagnostics.decode_current_aw_attempt_osdata(
            payload + b'\0')['valid'])

        for offset, value, expected in (
                (4, 2, 'unsupported_schema'),
                (8, 1, 'attempt_record_claims_forbidden_proof'),
                (17, 0x80, 'unknown_consistency_flags')):
            corrupted = bytearray(payload)
            corrupted[offset] = value
            report = diagnostics.decode_current_aw_attempt_osdata(corrupted)
            self.assertFalse(report['valid'])
            self.assertIn(expected, report['reasons'])

    def test_missing_and_wrong_payload_types_are_unknown(self):
        for payload in (None, 'not data', 110):
            report = diagnostics.decode_current_aw_attempt_osdata(payload)
            self.assertFalse(report['valid'])
            self.assertEqual(report['status'], 'unknown_missing_or_wrong_type')


class QmWireSnapshotTests(unittest.TestCase):
    def test_fixed_size_local_qm_snapshot_is_address_free_and_nonproof(self):
        payload = qm_payload()
        self.assertEqual(len(payload), diagnostics.QM_WIRE_SIZE)
        report = diagnostics.decode_qm_wire_osdata(payload)
        self.assertTrue(report['valid'], report['reasons'])
        self.assertEqual(report['values']['token'], 42)
        self.assertEqual(report['values']['channel'], 6)
        self.assertEqual(report['values']['frequency_mhz'], 2437)
        self.assertFalse(report['radio_transmit_proven'])
        self.assertFalse(report['peer_receipt_proven'])
        self.assertFalse(report['airdrop_proven'])
        self.assertFalse(any('address' in key.lower() and
                             key not in ('address_role_flags',)
                             for key in report['values']))

    def test_qm_schema_length_generation_and_gp2_claim_fail_closed(self):
        self.assertFalse(diagnostics.decode_qm_wire_osdata(
            qm_payload()[:-1])['valid'])
        for payload, expected in (
                (qm_payload(schema=2), 'unsupported_schema'),
                (qm_payload(gp2_valid=1), 'unexpected_current_gp2_claim')):
            report = diagnostics.decode_qm_wire_osdata(payload)
            self.assertFalse(report['valid'])
            self.assertIn(expected, report['reasons'])

    def test_qm_missing_wrong_type_truncated_and_oversized_data_are_unknown(self):
        for payload in (None, 'not data', qm_payload()[:-1],
                        qm_payload() + b'\\0'):
            with self.subTest(payload=type(payload).__name__,
                              length=len(payload) if isinstance(payload, bytes) else None):
                report = diagnostics.decode_qm_wire_osdata(payload)
                self.assertFalse(report['valid'])
                self.assertFalse(report['radio_transmit_proven'])
                self.assertFalse(report['peer_receipt_proven'])
        self.assertEqual(
            diagnostics.decode_qm_wire_osdata(None)['status'],
            'unknown_missing_or_wrong_type')
        self.assertEqual(
            diagnostics.decode_qm_wire_osdata(qm_payload()[:-1])['status'],
            'unknown_invalid_length')

    def test_attempt_to_qm_identity_cross_check_does_not_compare_roc_token_to_epoch(self):
        attempt = diagnostics.decode_current_aw_attempt_osdata(attempt_payload())
        qm = diagnostics.decode_qm_wire_osdata(qm_payload(roc_token=999))
        report = diagnostics.cross_check_attempt_qm_identity(attempt, qm)
        self.assertTrue(report['valid'], report)
        self.assertTrue(report['token_matches'])
        self.assertTrue(report['generation_matches'])
        self.assertEqual(report['attempt_roc_generation'], 14)
        self.assertEqual(report['qm_roc_token'], 999)
        self.assertFalse(report['radio_transmit_proven'])

    def test_qm_token_or_generation_mismatch_is_visible(self):
        attempt = diagnostics.decode_current_aw_attempt_osdata(attempt_payload())
        qm = diagnostics.decode_qm_wire_osdata(qm_payload(token=99))
        report = diagnostics.cross_check_attempt_qm_identity(attempt, qm)
        self.assertFalse(report['valid'])
        self.assertFalse(report['token_matches'])
        self.assertTrue(report['generation_matches'])


if __name__ == '__main__':
    unittest.main()
