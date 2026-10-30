"""Offline Test086 RX trace and configuration-2 entry-telemetry mocks."""
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


COLLECTOR = load('capture_test086_rx_entry',
                 ROOT / 'capture_test086_receive149_once.py')
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
        'NativeP2PRxEntrySchema': 2,
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
    for key in COLLECTOR.RX_ENTRY_EXTENSION_KEYS:
        values[key] = 0
    return [dict(values), dict(values), dict(values)]


def expected_mac_phy_149_reads():
    reads = closed_zero_entry_reads()
    pfx = COLLECTOR.RX_ENTRY_PREFIX + 'LastTarget'
    mac_pfx = COLLECTOR.RX_ENTRY_PREFIX + 'LastMacIndexTarget'
    updates = {
        COLLECTOR.RX_ENTRY_PREFIX + 'CountChannel149': 1,
        COLLECTOR.RX_ENTRY_PREFIX + 'CountMacIndex1Channel149': 1,
        COLLECTOR.RX_ENTRY_PREFIX + 'CountExpectedMacPhy149': 1,
        pfx + 'Present': 1,
        pfx + 'ContextGeneration': 3,
        pfx + 'PowerGeneration': 5,
        pfx + 'StationGeneration': 7,
        pfx + 'RocGeneration': 3,
        pfx + 'ChannelPresent': 1,
        pfx + 'Channel': 149,
        pfx + 'MacContextPresent': 1,
        pfx + 'MacContextRaw': 0xA2,
        pfx + 'MacIndexPresent': 1,
        pfx + 'MacIndex': 1,
        pfx + 'PhyIndexPresent': 1,
        pfx + 'PhyIndex': 1,
        pfx + 'MacPhyIndexDecodeModePresent': 1,
        pfx + 'MacPhyIndexDecodeMode': 1,
        pfx + 'HostRxMonotonicUsPresent': 1,
        pfx + 'HostRxMonotonicUs': 9876543210,
        pfx + 'Gp2OnAirRisePresent': 1,
        pfx + 'Gp2OnAirRiseRaw': 12345,
        pfx + 'TsfOnAirRisePresent': 1,
        pfx + 'TsfOnAirRiseRaw': 67890123456789,
        pfx + 'TsfValidPresent': 1,
        pfx + 'TsfValid': 0,
        pfx + 'RxRingPresent': 1,
        pfx + 'RxRing': 0,
        pfx + 'RxRingSlotPresent': 1,
        pfx + 'RxRingSlot': 17,
        pfx + 'TransportNotificationQidPresent': 1,
        pfx + 'TransportNotificationQid': 9,
        pfx + 'TransportNotificationIndexPresent': 1,
        pfx + 'TransportNotificationIndex': 4,
    }
    for sample in reads:
        sample.update(updates)
        sample.update({mac_pfx + key[len(pfx):]: value
                       for key, value in updates.items() if key.startswith(pfx)})
    return reads


def mac_only_target_149_reads():
    reads = closed_zero_entry_reads()
    prefix = COLLECTOR.RX_ENTRY_PREFIX
    pfx = prefix + 'LastMacIndexTarget'
    updates = {
        prefix + 'CountChannel149': 2,
        prefix + 'CountMacIndex1Channel149': 1,
        prefix + 'CountExpectedMacPhy149': 0,
        pfx + 'Present': 1,
        pfx + 'ContextGeneration': 3,
        pfx + 'PowerGeneration': 5,
        pfx + 'StationGeneration': 7,
        pfx + 'RocGeneration': 3,
        pfx + 'ChannelPresent': 1,
        pfx + 'Channel': 149,
        pfx + 'MacContextPresent': 0,
        pfx + 'MacContextRaw': 0xA2,
        pfx + 'MacIndexPresent': 1,
        pfx + 'MacIndex': 1,
        pfx + 'PhyIndexPresent': 0,
        pfx + 'PhyIndex': 0,
        pfx + 'MacPhyIndexDecodeModePresent': 1,
        pfx + 'MacPhyIndexDecodeMode': 2,
        pfx + 'RxRingPresent': 1,
        pfx + 'RxRing': 0,
        pfx + 'RxRingSlotPresent': 1,
        pfx + 'RxRingSlot': 11,
        pfx + 'HostRxMonotonicUsPresent': 1,
        pfx + 'HostRxMonotonicUs': 9876543210,
    }
    for sample in reads:
        sample.update(updates)
    return reads


def closed_discovery_roc():
    values = dict(COLLECTOR.ROC_REQUIRED_VALUES)
    values.update({'NativeP2PRocGeneration': 3,
                   'NativeP2PProbeContextGeneration': 3,
                   'NativeP2PProbePowerGeneration': 5,
                   'NativeP2PProbeStationGeneration': 7})
    return values


def awdl_data_candidate_149_reads():
    reads = closed_zero_entry_reads()
    prefix = COLLECTOR.RX_ENTRY_PREFIX
    candidate = prefix + 'LastAwdlDataCandidate'
    values = {
        prefix + 'CountAwdlBssidCandidate': 1,
        candidate + 'Present': 1,
        candidate + 'ContextGeneration': 3,
        candidate + 'PowerGeneration': 5,
        candidate + 'StationGeneration': 7,
        candidate + 'RocGeneration': 3,
        candidate + 'HostRxMonotonicUsPresent': 1,
        candidate + 'HostRxMonotonicUs': 9876543210,
        candidate + 'ChannelPresent': 1,
        candidate + 'Channel': 149,
        candidate + 'FrameControlPresent': 1,
        candidate + 'FrameType': 2,
        candidate + 'FrameSubtype': 8,
        candidate + 'ToDs': 0,
        candidate + 'FromDs': 0,
        candidate + 'AwdlBssidCandidate': 1,
    }
    for sample in reads:
        sample.update(values)
    return reads


class Test086RxEntryGuard(unittest.TestCase):
    def test_data_candidate_witness_binds_channel149_owner_without_phy_inference(self):
        reads = awdl_data_candidate_149_reads()
        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertTrue(result['valid'], result)
        candidate = result['data_candidate_evidence']
        self.assertEqual(candidate['status'], 'owner_bound_data_descriptor_candidate')
        self.assertEqual(candidate['descriptor_candidate_count'], 1)
        self.assertTrue(candidate['matched_roc_owner'])
        self.assertFalse(candidate['phy_index_inferred'])
        self.assertFalse(candidate['count_zero_proves_rf_absence'])

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
        self.assertTrue(result['schema_v2'])
        self.assertEqual(result['strict_channel149_count'], 0)
        self.assertEqual(result['strict_mac_index1_channel149_count'], 0)
        self.assertEqual(result['strict_expected_mac_phy149_count'], 0)
        self.assertFalse(result['strict_count_zero_is_rf_absence'])

        wrong_cfg = closed_discovery_roc()
        wrong_cfg['NativeP2PRocConfiguration'] = 3
        self.assertFalse(COLLECTOR.rx_entry_observation_evidence(
            reads, wrong_cfg)['valid'])
        missing = [dict(sample) for sample in reads]
        del missing[1]['NativeP2PRxEntryCountCrcRejected']
        self.assertFalse(COLLECTOR.rx_entry_observation_evidence(
            missing, closed_discovery_roc())['valid'])

    def test_schema_two_target_uses_decoded_mac_phy_not_raw_context_and_preserves_clocks(self):
        reads = expected_mac_phy_149_reads()
        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertTrue(result['valid'], result)
        self.assertEqual(result['strict_channel149_count'], 1)
        self.assertEqual(result['strict_expected_mac_phy149_count'], 1)
        extension = result['extension_evidence']
        self.assertEqual(extension['last_target_status'],
                         'verified_expected_mac_phy_149_witness')
        values = extension['values']
        prefix = COLLECTOR.RX_ENTRY_PREFIX + 'LastTarget'
        self.assertEqual(values[prefix + 'MacContextRaw'], 0xA2)
        self.assertEqual(values[prefix + 'MacIndex'], 1)
        self.assertEqual(values[prefix + 'PhyIndex'], 1)
        self.assertNotEqual(values[prefix + 'MacContextRaw'], values[prefix + 'MacIndex'])
        self.assertEqual(values[prefix + 'RxRing'], 0)
        self.assertEqual(values[prefix + 'RxRingSlot'], 17)
        self.assertEqual(values[prefix + 'HostRxMonotonicUs'], 9876543210)
        self.assertGreater(values[prefix + 'HostRxMonotonicUs'], 0xffffffff)
        self.assertEqual(values[prefix + 'TransportNotificationQid'], 9)
        self.assertEqual(values[prefix + 'TransportNotificationIndex'], 4)
        self.assertNotEqual(values[prefix + 'RxRingSlot'],
                            values[prefix + 'TransportNotificationQid'])
        self.assertEqual(values[prefix + 'Gp2OnAirRiseRaw'], 12345)
        self.assertEqual(values[prefix + 'TsfOnAirRiseRaw'], 67890123456789)
        self.assertGreater(values[prefix + 'TsfOnAirRiseRaw'], 0xffffffff)
        self.assertEqual(values[prefix + 'TsfValid'], 0)
        self.assertFalse(extension['raw_mac_context_interpreted_as_index'])
        self.assertFalse(extension['transport_notification_qid_used_as_rx_ring'])
        self.assertFalse(result['gp2_and_tsf_combined_or_converted'])
        self.assertIsNone(result['channel149_rx_observed'])

    def test_zero_expected_target_count_is_valid_and_missing_v2_aliases_stay_unknown(self):
        reads = closed_zero_entry_reads()
        for sample in reads:
            for key in COLLECTOR.RX_ENTRY_SCHEMA2_ONLY_KEYS:
                sample.pop(key, None)
        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertFalse(result['valid'], result)
        self.assertEqual(result['extension_evidence']['status'],
                         'partially_published_unknowns_retained')
        self.assertEqual(result['data_candidate_evidence']['status'],
                         'unknown_candidate_witness')
        self.assertIsNone(result['strict_channel149_count'])
        self.assertIsNone(result['strict_expected_mac_phy149_count'])
        self.assertIsNone(result['channel149_rx_observed'])

    def test_test086_requires_schema_two_even_if_legacy_snapshot_is_stable(self):
        reads = closed_zero_entry_reads()
        for sample in reads:
            sample['NativeP2PRxEntrySchema'] = 1
        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertFalse(result['valid'])
        self.assertFalse(result['schema_v2'])

    def test_target_count_and_last_target_must_agree_when_both_are_published(self):
        reads = expected_mac_phy_149_reads()
        for sample in reads:
            sample['NativeP2PRxEntryCountExpectedMacPhy149'] = 0
        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertFalse(result['valid'])
        self.assertEqual(result['extension_evidence']['last_target_status'],
                         'invalid_expected_mac_phy_149_witness')

    def test_band_in_rx_mac_only_target_does_not_invent_phy_or_context_identity(self):
        reads = mac_only_target_149_reads()
        result = COLLECTOR.rx_entry_observation_evidence(reads, closed_discovery_roc())
        self.assertTrue(result['valid'], result)
        self.assertEqual(result['strict_channel149_count'], 2)
        self.assertEqual(result['strict_mac_index1_channel149_count'], 1)
        self.assertEqual(result['strict_expected_mac_phy149_count'], 0)
        extension = result['extension_evidence']
        self.assertEqual(extension['last_mac_index_target_status'],
                         'verified_mac_index_1_channel_149_witness')
        self.assertEqual(extension['last_target_status'],
                         'no_expected_mac_phy_149_descriptor')
        values = extension['values']
        prefix = COLLECTOR.RX_ENTRY_PREFIX + 'LastMacIndexTarget'
        self.assertEqual(values[prefix + 'MacIndex'], 1)
        self.assertEqual(values[prefix + 'MacContextPresent'], 0)
        self.assertEqual(values[prefix + 'PhyIndexPresent'], 0)
        self.assertEqual(values[prefix + 'MacPhyIndexDecodeMode'], 2)
        self.assertFalse(result['raw_mac_context_interpreted_as_index'])


if __name__ == '__main__':
    unittest.main()
