#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location(
    'decode_group2_tx', HERE / 'decode_group2_tx.py')
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


class Group2TxWireTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='test094-group2-wire-')
        root = Path(cls.temp.name)
        binary = root / 'group2_tx_fixture'
        output = root / 'snapshot.bin'
        subprocess.run([
            'xcrun', 'clang++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
            '-I', str(ROOT), str(HERE / 'group2_tx_wire_fixture.cpp'),
            '-o', str(binary),
        ], check=True, capture_output=True)
        subprocess.run([str(binary), str(output)], check=True)
        cls.raw = output.read_bytes()
        cls.decoded = decoder.decode(cls.raw)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_fixed_little_endian_snapshot_and_numeric_linkage(self):
        result = self.decoded
        self.assertEqual(len(self.raw), decoder.SIZE)
        self.assertEqual(result['schema'], 1)
        self.assertEqual(result['event_bytes'], 96)
        self.assertEqual(result['header_bytes'], 72)
        self.assertGreaterEqual(result['event_count'], 11)
        self.assertEqual(result['revision_begin'], result['revision_end'])

        by_stage = {}
        for event in result['events']:
            by_stage.setdefault(event['stage_label'], []).append(event)
        enqueue = by_stage['ifq_enqueue_operation'][0]
        self.assertEqual(enqueue['enqueue_drop_count'], 2)
        self.assertEqual(enqueue['target_disposition'], 'unknown')
        self.assertEqual(enqueue['queue_kind'], 'software_if_snd')
        self.assertEqual(enqueue['queue_id_status'], 'unknown')
        self.assertIsNone(enqueue['hardware_qid'])

        dequeued = by_stage['dequeued'][0]
        submitted = by_stage['local_doorbell'][0]
        self.assertEqual(dequeued['cookie'], 1)
        self.assertEqual(submitted['cookie'], dequeued['cookie'])
        self.assertEqual(submitted['index'], 7)
        self.assertIn('not firmware completion', submitted['observation_scope'])

        completion = by_stage['exclusive_tx_rsp_match'][0]
        self.assertEqual(completion['cookie'], dequeued['cookie'])
        self.assertEqual(completion['index'], 0)
        self.assertEqual(completion['exclusive_reclaim_boundary'], 0)
        self.assertEqual(completion['matched_slot_index'], 7)
        self.assertEqual(completion['completion_match'], 'unique')
        self.assertEqual(completion['firmware_tx_status_raw'], 0x2345)
        self.assertIn('exclusive reclaim interval', completion['observation_scope'])

        retired = by_stage['slot_retired'][0]
        self.assertEqual(retired['completion_match'], 'unique')
        self.assertIsNone(retired['firmware_tx_status_raw'])
        flushed = by_stage['flush_reclaim_unknown'][0]
        self.assertEqual(flushed['completion_match'], 'unknown')
        self.assertEqual(flushed['retirement_reason'], 'firmware_flush_reclaim')
        self.assertIsNone(flushed['firmware_tx_status_raw'])
        self.assertIn('not a TX_RSP, ACK', flushed['observation_scope'])

        reset = next(event for event in by_stage['reset_invalidated_unknown']
                     if event['cookie'] == 3)
        self.assertEqual(reset['cookie'], 3)
        self.assertEqual(reset['completion_match'], 'reset_ambiguous')
        self.assertIsNone(reset['firmware_tx_status_raw'])
        unknown = by_stage['tx_rsp_unknown'][0]
        self.assertEqual(unknown['completion_match'], 'reset_ambiguous')
        self.assertEqual(unknown['cookie'], 0)
        self.assertIsNone(unknown['firmware_tx_status_raw'])

    def test_rejects_unknown_schema_truncation_and_nonzero_unused_events(self):
        raw = bytearray(self.raw)
        raw[4:6] = b'\x02\x00'
        with self.assertRaises(ValueError):
            decoder.decode(raw)
        with self.assertRaises(ValueError):
            decoder.decode(self.raw[:-1])
        raw = bytearray(self.raw)
        raw[-1] = 1
        with self.assertRaises(ValueError):
            decoder.decode(raw)

    def test_scope_limits_are_explicit(self):
        limits = ' '.join(self.decoded['evidence_limits'])
        self.assertIn('not a specific packet', limits)
        self.assertIn('not firmware acceptance', limits)
        self.assertIn('stay unknown', limits)


if __name__ == '__main__':
    unittest.main()
