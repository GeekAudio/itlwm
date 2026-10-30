"""Offline Test083 closed-RX-timeline guard mocks; no RF or helper invocation."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COLLECTOR = load('capture_test083_rx_trace',
                 ROOT / 'capture_test083_receive149_once.py')
EVIDENCE = load('capture_test076_rx_trace',
                ROOT / 'capture_test076_resident_data_once.py')


def closed_zero_event_reads():
    """Mock the production schema: seqlock/version, closed owner, no events."""
    values = {key: 0 for key in EVIDENCE.RX_TRACE_SNAPSHOT_KEYS}
    prefix = EVIDENCE.RX_TRACE_PREFIX
    for suffix, value in (
            ('SnapshotVersionBegin', 4), ('SnapshotVersionEnd', 4),
            ('Revision', 4), ('SchemaVersion', 1), ('OwnerPresent', 1),
            ('OwnerSerial', 1), ('Active', 0), ('ProducerClosed', 1),
            ('EventCount', 0)):
        values[prefix + suffix] = value
    for key in EVIDENCE.RX_TRACE_PROBE_EPOCHS:
        values[key] = 1
    for field in EVIDENCE.RX_TRACE_OWNER_EPOCH_FIELDS:
        values[prefix + field] = 1

    for boundary, start_flag, timestamp, notification in (
            ('RocStart', 1, 100, 1), ('RocEnd', 0, 200, 2)):
        pfx = prefix + boundary
        for field, value in (
                ('Present', 1), ('Api', 1), ('HostMonotonicPresent', 1),
                ('RawLength', 16), ('RawStartFlag', start_flag),
                ('ReducerResultPresent', 1), ('ReducerReturnedTrue', 1),
                ('CanonicalTransitionPresent', 1), ('CanonicalTransition', 1),
                ('OwnerSerial', 1), ('NotificationSerial', notification),
                ('HostMonotonicUs', timestamp)):
            values[pfx + field] = value
        for field in EVIDENCE.RX_TRACE_OWNER_EPOCH_FIELDS:
            values[pfx + field] = 1
    return [dict(values), dict(values), dict(values)]


class Test083RxTraceSnapshotGuard(unittest.TestCase):
    def test_accepts_stable_closed_empty_timeline_without_unpublished_flag(self):
        reads = closed_zero_event_reads()
        evidence = EVIDENCE.guarded_rx_trace_evidence(*reads)
        self.assertTrue(evidence['valid'], evidence['reasons'])
        self.assertTrue(evidence['stable_complete_snapshot'])
        self.assertTrue(evidence['trace_coverage_complete'])
        self.assertNotIn('NativeP2PRxTraceSnapshotComplete', reads[-1])
        self.assertTrue(COLLECTOR.rx_trace_snapshot_complete(evidence, reads[-1]))

    def test_rejects_unstable_publication_version(self):
        reads = closed_zero_event_reads()
        evidence = EVIDENCE.guarded_rx_trace_evidence(*reads)
        post = dict(reads[-1])
        post['NativeP2PRxTraceSnapshotVersionEnd'] = 5
        self.assertFalse(COLLECTOR.rx_trace_snapshot_complete(evidence, post))

    def test_rejects_unclosed_or_dropped_timeline(self):
        reads = closed_zero_event_reads()
        evidence = EVIDENCE.guarded_rx_trace_evidence(*reads)
        for key, value in (
                ('NativeP2PRxTraceProducerClosed', 0),
                ('NativeP2PRxTraceDroppedEventCount', 1)):
            post = dict(reads[-1])
            post[key] = value
            self.assertFalse(COLLECTOR.rx_trace_snapshot_complete(evidence, post))


if __name__ == '__main__':
    unittest.main()
