#!/usr/bin/env python3
"""Offline behavioral tests for Test081's receive-only gates."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    'capture_test081_receive149_once', ROOT / 'capture_test081_receive149_once.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Test081ReceiveOnlyGateTests(unittest.TestCase):
    def test_prepare_failure_survives_without_roc_owner_and_does_not_imply_cleanup(self):
        p = MODULE.PREPARE_PROPERTY_PREFIX
        values = {p + 'SchemaVersion': 1, p + 'SnapshotValid': 1,
                  p + 'SnapshotVersionBegin': 6, p + 'SnapshotVersionEnd': 6,
                  p + 'Revision': 6, p + 'AttemptSerial': 1,
                  p + 'PrepareErrno': 102, p + 'CleanupErrno': 0,
                  p + 'Step': 4, p + 'Reason': 7,
                  p + 'Field.valid': 1, p + 'Field.serial': 1,
                  p + 'Field.prepareErrno': 102, p + 'Field.cleanupErrno': 0,
                  p + 'Field.step': 4, p + 'Field.reason': 7,
                  p + 'DebugAddress': 'private-address'}
        evidence = MODULE.prepare_trace_evidence([values, values, values])
        self.assertTrue(evidence['snapshot_valid'])
        self.assertEqual(evidence['prepare_errno'], 102)
        self.assertFalse(evidence['cleanup_safety_inferred_by_collector'])
        self.assertFalse(evidence['current_attempt_matches'])
        self.assertFalse(evidence['roc_success_inferred'])
        self.assertNotIn(p + 'DebugAddress', evidence['samples'][0])
        stale = dict(values, **{p + 'Field.reason': 8})
        self.assertFalse(MODULE.prepare_trace_evidence([values, stale, values])['snapshot_valid'])
        odd = dict(values, **{p + 'Revision': 7})
        self.assertFalse(MODULE.prepare_trace_evidence([odd] * 3)['snapshot_valid'])
        missing = dict(values)
        del missing[p + 'Field.prepareErrno']
        self.assertFalse(MODULE.prepare_trace_evidence([missing] * 3)['snapshot_valid'])
        complete = MODULE.prepare_trace_evidence([values] * 3, {'fields': ['valid', 'serial']})
        self.assertTrue(complete['snapshot_valid'])
        omitted = MODULE.prepare_trace_evidence([values] * 3, {'fields': ['firmwareCapabilitiesCaptured']})
        self.assertFalse(omitted['snapshot_valid'])
        current = dict(values)
        for name, value in {
            'NativeP2PManualArmed': 2, 'NativeP2PProbeAttempted': 1,
            'NativeP2PProbeContextGeneration': 3, 'NativeP2PProbePowerGeneration': 5,
            'NativeP2PProbeStationGeneration': 7}.items():
            current[name] = value
        for name, value in {'token': 3, 'scGenerationEntry': 5, 'scGenerationExit': 5,
            'p2pFirmwareGenerationEntry': 5, 'p2pFirmwareGenerationExit': 5,
            'stationEpochEntry': 7, 'stationEpochExit': 7, 'configuration': 2,
            'receiveObservation149': 1, 'featureCompiled': 1}.items():
            current[p + 'Field.' + name] = value
        self.assertTrue(MODULE.prepare_trace_evidence([current] * 3)['current_attempt_matches'])
        stale = dict(current, NativeP2PProbeContextGeneration=4)
        stale_evidence = MODULE.prepare_trace_evidence([stale] * 3)
        self.assertTrue(stale_evidence['snapshot_valid'])
        self.assertFalse(stale_evidence['current_attempt_matches'])

    def test_disarmed_worker_stops_before_any_system_or_rf_access(self):
        args = type('Args', (), {
            'arm': True, 'receiver_gated': True,
            'router_observation_id': 't081-test', 'expect_build': MODULE.BUILD,
            'phone_ready': True, 'output': '/tmp/unused-test081-output'})()
        with patch.object(MODULE.os, 'geteuid', return_value=0), \
             patch.object(MODULE, '_load_metadata', return_value={'armed': False}), \
             patch.object(MODULE, '_sysctl_boot_epoch') as boot, \
             patch.object(MODULE, 'properties') as properties, \
             patch.object(MODULE.subprocess, 'run') as run:
            with self.assertRaisesRegex(SystemExit, 'metadata is disarmed'):
                MODULE._native_worker(args)
        boot.assert_not_called()
        properties.assert_not_called()
        run.assert_not_called()

    def test_profile_requires_rx149_and_every_legacy_path_disabled(self):
        values = dict(MODULE.REQUIRED_ENABLED_FLAGS)
        values.update({key: False for key in MODULE.REQUIRED_DISABLED_FLAGS})
        values.update({
            'NativeP2PRx149ProfileEnabled': 1,
            'NativeP2PRx149HostTxBlocked': 1,
            'NativeP2PRx149Selected': 0,
        })
        self.assertEqual(MODULE.profile_problems(values, selected=False), [])

        values['NativeP2PRocProbe'] = True
        self.assertIn('NativeP2PRocProbe', MODULE.profile_problems(values, selected=False))
        values['NativeP2PRocProbe'] = False
        del values['NativeP2PRx149HostTxBlocked']
        self.assertIn('NativeP2PRx149HostTxBlocked',
                      MODULE.profile_problems(values, selected=False))

    def test_zero_tx_proof_requires_real_zero_counters_before_and_after(self):
        zeros = {key: 0 for key in MODULE.TX_ZERO_COUNTERS}
        evidence = MODULE.tx_zero_evidence(zeros, zeros, samples=[zeros, zeros])
        self.assertTrue(evidence['valid'])
        self.assertFalse(evidence['counters_cleared_by_collector'])
        self.assertEqual(evidence['sample_count'], 2)

        nonzero = dict(zeros, NativeP2PAwdlActionFramesSubmitted=1)
        self.assertFalse(MODULE.tx_zero_evidence(zeros, nonzero)['valid'])
        self.assertFalse(MODULE.tx_zero_evidence(zeros, zeros,
                         samples=[nonzero])['valid'])
        missing = dict(zeros)
        del missing['NativeP2PTxProbeEverDoorbelled']
        result = MODULE.tx_zero_evidence(missing, zeros)
        self.assertFalse(result['valid'])
        self.assertIn('NativeP2PTxProbeEverDoorbelled', result['missing'])
        boolean_value = dict(zeros, NativeP2PTxProbeEverDoorbelled=False)
        self.assertFalse(MODULE.tx_zero_evidence(boolean_value, zeros)['valid'])
        self.assertEqual(evidence['counter_provenance'][
            'NativeP2PTxProbeEverDoorbelled'],
            'actual_sticky_controller_queue_doorbell_snapshot')

    def test_roc_success_requires_exact_149_discov_start_end_and_owner(self):
        values = dict(MODULE.ROC_REQUIRED_VALUES)
        values.update({'NativeP2PRocGeneration': 9,
                       'NativeP2PProbeContextGeneration': 9})
        self.assertEqual(MODULE.roc_session_problems(values), [])
        values['NativeP2PRocConfiguration'] = 1
        self.assertIn('NativeP2PRocConfiguration',
                      MODULE.roc_session_problems(values))
        values['NativeP2PRocConfiguration'] = 2
        values['NativeP2PRocGeneration'] = 10
        self.assertIn('NativeP2PRocGeneration_owner_mismatch',
                      MODULE.roc_session_problems(values))

    def test_session_completion_requires_closed_stable_rx_trace(self):
        trace_values = {'NativeP2PRxTraceEventCount': 0}
        evidence = {'valid': True, 'values': trace_values}
        post = {
            'NativeP2PRxTraceSnapshotComplete': 1,
            'NativeP2PRxTraceProducerClosed': 1,
            'NativeP2PRxTraceActive': 0,
            'NativeP2PRxTracePendingDrainCount': 0,
            'NativeP2PRxTraceUntrackedPendingDrainCount': 0,
            'NativeP2PRxTraceUntrackedPendingIdentityOverflowCount': 0,
            'NativeP2PRxTraceDroppedEventCount': 0,
            'NativeP2PRxTraceStaleCompletionCount': 0,
            'NativeP2PRxTraceSourceTableFullCount': 0,
            'NativeP2PRxTraceTimeEventNotificationDroppedCount': 0,
        }
        self.assertTrue(MODULE.rx_trace_snapshot_complete(evidence, post))
        self.assertFalse(MODULE.rx_trace_snapshot_complete(
            evidence, dict(post, NativeP2PRxTracePendingDrainCount=None)))
        self.assertFalse(MODULE.rx_trace_snapshot_complete(
            dict(evidence, valid=False), post))

    def test_immutable_mode_latch_distinguishes_rx149_from_legacy(self):
        samples = [
            {'NativeP2PManualArmed': 0},
            {'NativeP2PManualArmed': 2},
            {'NativeP2PManualArmed': 2},
        ]
        self.assertEqual(MODULE.rx149_mode_lock_problems(samples, samples[-1]), [])
        self.assertIn('legacy_manual_mode_observed', MODULE.rx149_mode_lock_problems(
            [{'NativeP2PManualArmed': 1}, {'NativeP2PManualArmed': 2}],
            {'NativeP2PManualArmed': 2}))
        self.assertIn('rx149_mode_lock_not_published', MODULE.rx149_mode_lock_problems(
            [{'NativeP2PManualArmed': 0}], {'NativeP2PManualArmed': 0}))
        self.assertIn('NativeP2PManualArmed_missing_or_invalid',
                      MODULE.rx149_mode_lock_problems(
                          [{'NativeP2PManualArmed': None}],
                          {'NativeP2PManualArmed': 2}))

    def test_post_arm_attempt_state_is_explicit_and_missing_stays_unknown(self):
        values = {
            'NativeP2PProbeAttempted': 1,
            'NativeP2PProbeState': 7,
            'NativeP2PProbeResourceMayExist': 0,
            'NativeP2PProbePeerAddress': 'private-address',
        }
        self.assertEqual(MODULE.attempt_state_snapshot(values), {
            'NativeP2PProbeAttempted': 1,
            'NativeP2PProbeState': 7,
            'NativeP2PProbeResourceMayExist': 0,
        })
        self.assertEqual(MODULE.attempt_state_problems(values), [])
        missing = MODULE.attempt_state_snapshot({'NativeP2PProbeState': 'unknown'})
        self.assertEqual(missing['NativeP2PProbeAttempted'], None)
        self.assertEqual(missing['NativeP2PProbeResourceMayExist'], None)
        self.assertIn('NativeP2PProbeAttempted_missing_or_invalid',
                      MODULE.attempt_state_problems(missing))
        not_attempted = {'NativeP2PProbeAttempted': 0}
        self.assertIn('NativeP2PProbeAttempted_not_1',
                      MODULE.attempt_state_problems(not_attempted))

    def test_rx_snapshot_excludes_addresses_and_non_numeric_values(self):
        values = {
            'NativeP2PRx149Selected': 1,
            'NativeP2PRx149LastPeerAddress': 'aa:bb:cc:dd:ee:ff',
            'NativeP2PRx149Debug': 'private',
            'NativeP2PRxFrameCount': 2,
            'NativeP2PTxProbeEverDoorbelled': 0,
        }
        self.assertEqual(MODULE.rx149_snapshot(values), {
            'NativeP2PRx149Selected': 1,
            'NativeP2PRxFrameCount': 2,
        })

    def test_peer_table_numeric_evidence_is_preserved_without_identity_or_proof(self):
        before = {
            'NativeP2PPeerMIFFramesTotal': 3,
            'NativeP2PPeerPSFFramesTotal': 5,
            'NativeP2PPeerAcceptedFrames': 2,
            'NativeP2PPeerRejectedRecords': 1,
            'NativeP2PPeerLastResult': 7,
            'NativeP2PPeerCandidateFramesTotal': 9,
            'NativeP2PPeerAdmissionCountTotal': 2,
            'NativeP2PPeerUpdateCountTotal': 4,
            'NativeP2PPeerRxChannelIndex': 36,
            'NativeP2PPeerAddress': 0x001122334455,
            'NativeP2PPeerMAC': '00:11:22:33:44:55',
        }
        after = dict(before,
            NativeP2PPeerMIFFramesTotal=4,
            NativeP2PPeerAcceptedFrames=3,
            NativeP2PPeerLastResult=8,
            NativeP2PPeerRxChannelIndex=149)
        del after['NativeP2PPeerPSFFramesTotal']
        summary = MODULE.peer_evidence_delta(before, after)
        self.assertEqual(summary['pre']['NativeP2PPeerMIFFramesTotal'], 3)
        self.assertEqual(summary['post']['NativeP2PPeerMIFFramesTotal'], 4)
        runtime_sample = MODULE.rx149_observation_snapshot(after)
        self.assertEqual(runtime_sample['NativeP2PPeerMIFFramesTotal'], 4)
        self.assertIsNone(runtime_sample['NativeP2PPeerPSFFramesTotal'])
        self.assertNotIn('NativeP2PPeerAddress', runtime_sample)
        self.assertNotIn('NativeP2PPeerMAC', runtime_sample)
        self.assertEqual(summary['observed_counter_delta'][
            'NativeP2PPeerMIFFramesTotal'], 1)
        self.assertIsNone(summary['post']['NativeP2PPeerPSFFramesTotal'])
        self.assertIn('NativeP2PPeerPSFFramesTotal', summary['post']['missing'])
        self.assertIsNone(summary['observed_counter_delta'][
            'NativeP2PPeerPSFFramesTotal'])
        self.assertIsNone(summary['observed_counter_delta'][
            'NativeP2PPeerLastResult'])
        self.assertIsNone(summary['observed_counter_delta'][
            'NativeP2PPeerRxChannelIndex'])
        self.assertEqual(summary['mif_decode_status'],
                         'unknown_not_inferred_from_session_completion')
        self.assertIsNone(summary['peer_table_acceptance_proven'])
        self.assertIn('not inferred', summary['counter_delta_interpretation'])
        safe = MODULE.safe_runtime_snapshot(before)
        self.assertEqual(safe['NativeP2PPeerMIFFramesTotal'], 3)
        self.assertNotIn('NativeP2PPeerAddress', safe)
        self.assertNotIn('NativeP2PPeerMAC', safe)
        self.assertNotIn('NativeP2PPeerAcceptedFrames',
                         MODULE.safe_runtime_snapshot({
                             'NativeP2PPeerAcceptedFrames': True}))
        self.assertNotIn('NativeP2PPeerAddress', json.dumps(summary))
        self.assertNotIn('00:11:22:33:44:55', json.dumps(summary))

    def test_peer_missing_pre_or_post_stays_unknown_not_zero(self):
        summary = MODULE.peer_evidence_delta({}, {
            'NativeP2PPeerMIFFramesTotal': 1,
        })
        self.assertIsNone(summary['pre']['NativeP2PPeerMIFFramesTotal'])
        self.assertIsNone(summary['observed_counter_delta'][
            'NativeP2PPeerMIFFramesTotal'])
        self.assertIn('NativeP2PPeerMIFFramesTotal', summary['pre']['missing'])
        pending = MODULE.peer_evidence_delta({'NativeP2PPeerMIFFramesTotal': 1})
        self.assertIsNone(pending['post'])
        self.assertIsNone(pending['observed_counter_delta'][
            'NativeP2PPeerMIFFramesTotal'])

    def test_ready_requires_twenty_second_radiotap_capture(self):
        token = '0123456789abcdef0123456789abcdef'
        self.assertEqual(MODULE.ready_event('READY ' + token +
            ' window_seconds=20 link_type=127'), token)
        for line in (
            'READY ' + token + ' window_seconds=20 link_type=1',
            'READY ' + token + ' window_seconds=900 link_type=127',
            'READY bad-token window_seconds=20 link_type=127',
        ):
            with self.assertRaises(ValueError):
                MODULE.ready_event(line)

    def test_receiver_budget_requires_matching_live_token_and_expires(self):
        token = '0123456789abcdef0123456789abcdef'
        budget = MODULE.ReceiverBudget()
        budget.ready('READY ' + token + ' window_seconds=20 link_type=127', 10.0)
        with self.assertRaises(ValueError):
            budget.window('WINDOW ffffffffffffffffffffffffffffffff remaining_seconds=18', 10.2)
        budget.window('WINDOW ' + token + ' remaining_seconds=18', 10.2)
        self.assertGreater(budget.available(10.3), 0)
        self.assertEqual(budget.available(12.0), 0)

    def test_arm_helper_uses_one_rx149_gate_and_does_not_clear_tx_counters(self):
        source = (ROOT / 'arm_p2p_rx149_test081.swift').read_text()
        self.assertEqual(source.count('IORegistryEntrySetCFProperty('), 1)
        self.assertIn('NativeP2PRx149ObservationOnly', source)
        self.assertIn('NativeP2PRx149HostTxBlocked', source)
        self.assertIn('NativeP2PRx149ArmOnce', source)
        self.assertNotIn('NativeP2PArmOnce', source)
        self.assertIn('kmutil', source)
        self.assertIn('--expect-uuid', source)
        self.assertNotIn('NativeP2PRx149HostTxBlocked", kCFBooleanFalse', source)
        self.assertEqual(source.count('IORegistryEntrySetCFProperty('), 1)
        collector = (ROOT / 'capture_test081_receive149_once.py').read_text()
        self.assertEqual(collector.count('subprocess.run([str(helper)'), 1)


if __name__ == '__main__':
    unittest.main()
