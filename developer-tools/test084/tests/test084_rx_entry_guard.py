"""Offline Test084 RX trace and configuration-2 entry-telemetry mocks; no private metadata tests."""
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


COLLECTOR = load('capture_test084_rx_entry',
                 ROOT / 'capture_test084_receive149_once.py')
EVIDENCE = load('capture_test076_rx_entry_schema',
                ROOT / 'capture_test076_resident_data_once.py')


def closed_zero_event_reads():
    """Build a complete synthetic producer schema with an empty closed ring."""
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


def closed_zero_entry_reads():
    values = {key: 0 for key in EVIDENCE.RX_ENTRY_SNAPSHOT_KEYS}
    fields = {
        'NativeP2PRxEntrySnapshotBegin': 2,
        'NativeP2PRxEntrySnapshotEnd': 2,
        'NativeP2PRxEntrySchema': 1,
        'NativeP2PRxEntryActive': 0,
        'NativeP2PRxEntryContextGeneration': 3,
        'NativeP2PRxEntryPowerGeneration': 5,
        'NativeP2PRxEntryStationGeneration': 7,
        'NativeP2PRxEntryRocGeneration': 3,
        'NativeP2PProbeContextGeneration': 3,
        'NativeP2PProbePowerGeneration': 5,
        'NativeP2PProbeStationGeneration': 7,
        'NativeP2PRocGeneration': 3,
    }
    values.update(fields)
    return [dict(values), dict(values), dict(values)]


def closed_discovery_roc():
    values = dict(COLLECTOR.ROC_REQUIRED_VALUES)
    values.update({'NativeP2PRocGeneration': 3,
                   'NativeP2PProbeContextGeneration': 3})
    return values


class Test084RxEntryGuard(unittest.TestCase):
    def test_closed_empty_event_timeline_uses_published_stable_schema(self):
        reads = closed_zero_event_reads()
        evidence = EVIDENCE.guarded_rx_trace_evidence(*reads)
        self.assertTrue(evidence['valid'], evidence['reasons'])
        self.assertTrue(evidence['stable_complete_snapshot'])
        self.assertTrue(evidence['trace_coverage_complete'])
        self.assertNotIn('NativeP2PRxTraceSnapshotComplete', reads[-1])
        self.assertTrue(COLLECTOR.rx_trace_snapshot_complete(evidence, reads[-1]))

    def test_event_timeline_still_rejects_odd_open_or_lossy_snapshots(self):
        reads = closed_zero_event_reads()
        evidence = EVIDENCE.guarded_rx_trace_evidence(*reads)
        for key, value in (
                ('NativeP2PRxTraceSnapshotVersionEnd', 5),
                ('NativeP2PRxTraceProducerClosed', 0),
                ('NativeP2PRxTraceDroppedEventCount', 1)):
            with self.subTest(key=key):
                self.assertFalse(COLLECTOR.rx_trace_snapshot_complete(
                    evidence, dict(reads[-1], **{key: value})))

    def test_cfg2_owner_rxentry_is_collected_without_pii_or_rf_claim(self):
        reads = closed_zero_entry_reads()
        for sample in reads:
            sample['NativeP2PRocConfiguration'] = 2
            sample['NativeP2PRxEntryPeerAddress'] = 'synthetic-private-address'
            sample['NativeP2PRxEntryLastDescriptorPayload'] = b'synthetic-payload'
        safe = [COLLECTOR.safe_runtime_snapshot(sample) for sample in reads]
        self.assertIn('NativeP2PRxEntryCountDataFrame', safe[0])
        self.assertNotIn('NativeP2PRxEntryPeerAddress', safe[0])
        self.assertNotIn('NativeP2PRxEntryLastDescriptorPayload', safe[0])

        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertTrue(result['valid'], result)
        self.assertTrue(result['entry_snapshot_valid'])
        self.assertTrue(result['discovery_configuration_2'])
        self.assertEqual(result['entry_evidence']['values'][
            'NativeP2PRxEntryCountDataFrame'], 0)
        self.assertFalse(result['zero_counters_interpreted_as_rf_silence'])
        self.assertIsNone(result['channel149_rx_observed'])
        self.assertFalse(result['peer_receipt_proven'])
        self.assertFalse(result['airdrop_proven'])

        wrong_cfg = closed_discovery_roc()
        wrong_cfg['NativeP2PRocConfiguration'] = 3
        self.assertFalse(COLLECTOR.rx_entry_observation_evidence(
            reads, wrong_cfg)['valid'])
        missing = [dict(sample) for sample in reads]
        del missing[1]['NativeP2PRxEntryCountCrcRejected']
        self.assertFalse(COLLECTOR.rx_entry_observation_evidence(
            missing, closed_discovery_roc())['valid'])



if __name__ == '__main__':
    unittest.main()
