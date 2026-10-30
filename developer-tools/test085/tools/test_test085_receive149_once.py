#!/usr/bin/env python3
"""Offline behavioral tests for Test085's receive-only gates."""
import contextlib
import importlib.util
import io
import json
import plistlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    'capture_test085_receive149_once', ROOT / 'capture_test085_receive149_once.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TRACE_GUARD_SPEC = importlib.util.spec_from_file_location(
    'test085_rx_entry_guard_fixture', ROOT / 'tests' / 'test085_rx_entry_guard.py')
TRACE_GUARD_FIXTURE = importlib.util.module_from_spec(TRACE_GUARD_SPEC)
TRACE_GUARD_SPEC.loader.exec_module(TRACE_GUARD_FIXTURE)


class Test085ReceiveOnlyGateTests(unittest.TestCase):
    @staticmethod
    def trace_row(serial=1, *, monotonic_ns=1000, command_id=0x123, result=0):
        return struct.pack('<QQIIIIIIIIIIIIIIII',
            serial, monotonic_ns, 5, 4, 6, 2, command_id, 1, 1,
            3, 0, 0x300, 3, result, 0, 20, 0, 0)

    @classmethod
    def trace_sample(cls, *, schema=1, serial_begin=1, serial_end=1,
                     window_start=1, window_end=1, rows=None, dropped=0,
                     overwritten=0, gap=0, stable=1, complete=1,
                     publish_revision_begin=2, publish_revision_end=2):
        rows = [cls.trace_row()] if rows is None and window_end else (rows or [])
        blob = struct.pack('<IIIIQQIIIIIIIQQII',
            MODULE.HCMD_TRACE_MAGIC, schema, MODULE.HCMD_TRACE_HEADER_BYTES,
            MODULE.HCMD_TRACE_ENTRY_BYTES, serial_begin, serial_end,
            5, 7, 1, len(rows), dropped, overwritten, gap,
            window_start, window_end, stable, complete) + b''.join(rows)
        sample = {MODULE.HCMD_TRACE_KEY: blob,
                  MODULE.HCMD_TRACE_KEY + 'PublishRevisionBegin': publish_revision_begin,
                  MODULE.HCMD_TRACE_KEY + 'PublishRevisionEnd': publish_revision_end,
                  MODULE.HCMD_TRACE_KEY + 'BlobLength': len(blob)}
        header = {
            'schema': schema, 'snapshot_serial_begin': serial_begin,
            'snapshot_serial_end': serial_end, 'owner_generation': 5,
            'owner_watchdog_sequence': 7,
            'owner_watchdog_sequence_present': 1, 'row_count': len(rows),
            'dropped_count': dropped, 'overwritten_count': overwritten,
            'gap_count': gap, 'window_start_serial': window_start,
            'window_end_serial': window_end, 'stable': stable, 'complete': complete,
        }
        for suffix, field in MODULE.HCMD_TRACE_ALIAS_TO_HEADER.items():
            sample[MODULE.HCMD_TRACE_KEY + suffix] = header[field]
        return sample

    def test_hcmd_rx_trace_decodes_bounded_le_rows_and_requires_three_identical_reads(self):
        sample = self.trace_sample()
        evidence = MODULE.hcmd_rx_trace_evidence([sample, sample, sample])
        self.assertTrue(evidence['valid'])
        self.assertTrue(evidence['complete'])
        self.assertTrue(evidence['three_snapshot_consistency_proven'])
        self.assertEqual(evidence['sample_count'], 3)
        self.assertEqual(evidence['decoded_rows'][0]['serial'], 1)
        self.assertEqual(evidence['decoded_rows'][0]['command_id'], 0x123)
        self.assertEqual(evidence['decoded_rows'][0]['result'], 0)
        self.assertFalse(evidence['raw_blob_saved'])
        self.assertNotIn(MODULE.HCMD_TRACE_KEY, evidence)
        changed = self.trace_sample(rows=[self.trace_row(serial=1),
                                          self.trace_row(serial=2)],
                                    serial_begin=2, serial_end=2,
                                    window_start=1, window_end=2,
                                    gap=0, complete=1)
        unstable = MODULE.hcmd_rx_trace_evidence([sample, sample, changed])
        self.assertFalse(unstable['valid'])
        self.assertIn('header_blob_or_revision_changed_between_reads', unstable['errors'])
        self.assertEqual(len(unstable['decoded_rows_by_sample']), 3)
        empty = self.trace_sample(serial_begin=0, serial_end=0,
                                  window_start=0, window_end=0,
                                  rows=[], complete=1)
        before = MODULE.hcmd_rx_trace_evidence([empty, empty, empty])
        delta = MODULE.firmware_trace_row_delta(before, evidence)
        self.assertTrue(delta['comparable'])
        self.assertEqual(delta['new_row_count'], 1)
        self.assertIn('no ownership or completion proof', delta['interpretation'])
        lossy = self.trace_sample(dropped=1, complete=1)
        lossy_evidence = MODULE.hcmd_rx_trace_evidence([lossy, lossy, lossy])
        self.assertTrue(lossy_evidence['complete'])
        self.assertTrue(lossy_evidence['history_truncated'])
        self.assertTrue(MODULE.firmware_trace_row_delta(before, lossy_evidence)['comparable'])

    def test_hcmd_rx_trace_overwritten_history_keeps_complete_window_and_rows(self):
        rows = [self.trace_row(serial=serial) for serial in range(2, 66)]
        overwritten = self.trace_sample(
            serial_begin=65, serial_end=65, window_start=2, window_end=65,
            rows=rows, overwritten=1, gap=0, complete=1)
        result = MODULE.hcmd_rx_trace_snapshot(overwritten)
        self.assertTrue(result['valid'])
        self.assertTrue(result['complete'])
        self.assertTrue(result['history_truncated'])
        self.assertEqual(result['header']['overwritten_count'], 1)
        self.assertEqual(len(result['rows']), 64)
        evidence = MODULE.hcmd_rx_trace_evidence([overwritten] * 3)
        self.assertTrue(evidence['valid'])
        self.assertTrue(evidence['complete'])
        self.assertTrue(evidence['history_truncated'])
        self.assertEqual([row['serial'] for row in evidence['decoded_rows']],
                         list(range(2, 66)))

        before = self.trace_sample(
            serial_begin=1, serial_end=1, window_start=1, window_end=1,
            rows=[self.trace_row(serial=1)], complete=1)
        before_evidence = MODULE.hcmd_rx_trace_evidence([before] * 3)
        delta = MODULE.firmware_trace_row_delta(before_evidence, evidence)
        self.assertTrue(delta['comparable'])
        self.assertTrue(delta['delta_window_complete'])
        self.assertTrue(delta['post_history_truncated'])
        self.assertEqual(delta['new_row_count'], 64)
        self.assertEqual([row['serial'] for row in delta['new_rows']],
                         list(range(2, 66)))

        max_serial = (1 << 64) - 1
        huge_window_start = max_serial - MODULE.HCMD_TRACE_CAPACITY + 1
        huge_rows = [self.trace_row(serial=serial) for serial in
                     range(huge_window_start, max_serial + 1)]
        terminal = self.trace_sample(
            serial_begin=max_serial, serial_end=max_serial,
            window_start=huge_window_start, window_end=max_serial,
            rows=huge_rows, overwritten=1, gap=0, complete=1)
        terminal_result = MODULE.hcmd_rx_trace_snapshot(terminal)
        self.assertTrue(terminal_result['valid'])
        self.assertTrue(terminal_result['complete'])
        self.assertEqual(len(terminal_result['rows']), MODULE.HCMD_TRACE_CAPACITY)

        beyond = self.trace_sample(
            serial_begin=66, serial_end=66, window_start=3, window_end=66,
            rows=[self.trace_row(serial=serial) for serial in range(3, 67)],
            overwritten=2, complete=1)
        beyond_evidence = MODULE.hcmd_rx_trace_evidence([beyond] * 3)
        too_wide = MODULE.firmware_trace_row_delta(before_evidence, beyond_evidence)
        self.assertFalse(too_wide['comparable'])
        self.assertEqual(too_wide['reason'],
                         'serial_delta_exceeds_bounded_post_window')

    def test_hcmd_rx_trace_accepts_stable_empty_ring_and_distinguishes_missing_osdata(self):
        empty = self.trace_sample(serial_begin=0, serial_end=0,
                                  window_start=0, window_end=0,
                                  rows=[], complete=1)
        evidence = MODULE.hcmd_rx_trace_evidence([empty, empty, empty])
        self.assertTrue(evidence['valid'])
        self.assertTrue(evidence['complete'])
        self.assertEqual(evidence['decoded_rows'], [])
        missing = MODULE.hcmd_rx_trace_evidence([{}, {}, {}])
        self.assertFalse(missing['valid'])
        self.assertIn('blob_missing', missing['sample_headers'][0]['errors'])
        self.assertNotEqual(missing['sample_headers'][0]['blob_length'], 0)

    def test_hcmd_rx_trace_rejects_bad_size_odd_tail_unknown_schema_and_capacity(self):
        sample = self.trace_sample()
        cases = []
        short = dict(sample, **{MODULE.HCMD_TRACE_KEY: sample[MODULE.HCMD_TRACE_KEY][:-1]})
        cases.append((short, 'blob_length_mismatch'))
        odd = dict(sample, **{MODULE.HCMD_TRACE_KEY: sample[MODULE.HCMD_TRACE_KEY] + b'X'})
        cases.append((odd, 'blob_length_mismatch'))
        unknown = self.trace_sample(schema=2)
        cases.append((unknown, 'unknown_schema'))
        too_many_blob = struct.pack('<IIIIQQIIIIIIIQQII',
            MODULE.HCMD_TRACE_MAGIC, 1, 84, 80, 65, 65, 5, 7, 1,
            65, 0, 0, 0, 2, 65, 1, 0) + b'\0' * (65 * 80)
        too_many = dict(sample, **{MODULE.HCMD_TRACE_KEY: too_many_blob,
                                  MODULE.HCMD_TRACE_KEY + 'BlobLength': len(too_many_blob)})
        cases.append((too_many, 'row_count_exceeds_capacity'))
        for bad, expected in cases:
            with self.subTest(expected=expected):
                result = MODULE.hcmd_rx_trace_snapshot(bad)
                self.assertFalse(result['valid'])
                self.assertIn(expected, result['errors'])

    def test_hcmd_rx_trace_checks_serial_window_gap_drop_and_complete_consistency(self):
        dropped = self.trace_sample(dropped=1, complete=1)
        result = MODULE.hcmd_rx_trace_snapshot(dropped)
        self.assertTrue(result['valid'])
        self.assertTrue(result['complete'])
        self.assertTrue(result['history_truncated'])
        self.assertEqual(result['header']['dropped_count'], 1)
        gap = self.trace_sample(serial_begin=2, serial_end=2,
            window_start=1, window_end=2, rows=[self.trace_row(serial=1)],
            gap=1, complete=0)
        result = MODULE.hcmd_rx_trace_snapshot(gap)
        self.assertTrue(result['valid'])
        self.assertFalse(result['complete'])
        mismatch = self.trace_sample(complete=0)
        self.assertIn('complete_flag_mismatch',
                      MODULE.hcmd_rx_trace_snapshot(mismatch)['errors'])
        bad_window = self.trace_sample(serial_begin=1, serial_end=1,
            window_start=1, window_end=1, rows=[self.trace_row(serial=2)],
            gap=0, complete=0)
        self.assertIn('row_serial_outside_window',
                      MODULE.hcmd_rx_trace_snapshot(bad_window)['errors'])
        serial_mismatch = self.trace_sample(serial_begin=1, serial_end=2,
            window_start=1, window_end=2, rows=[self.trace_row(serial=1),
                                                self.trace_row(serial=2)],
            stable=1, complete=0)
        self.assertIn('stable_serial_mismatch',
                      MODULE.hcmd_rx_trace_snapshot(serial_mismatch)['errors'])

    def test_hcmd_rx_trace_outer_aliases_and_publish_revision_are_strict(self):
        base = self.trace_sample()
        no_alias = dict(base)
        del no_alias[MODULE.HCMD_TRACE_KEY + 'RowCount']
        self.assertIn('numeric_alias_missing_or_invalid:RowCount',
                      MODULE.hcmd_rx_trace_snapshot(no_alias)['errors'])
        alias_mismatch = dict(base,
            **{MODULE.HCMD_TRACE_KEY + 'VersionEnd': 2})
        self.assertIn('numeric_alias_mismatch:VersionEnd',
                      MODULE.hcmd_rx_trace_snapshot(alias_mismatch)['errors'])
        odd_revision = self.trace_sample(publish_revision_begin=3,
                                         publish_revision_end=3)
        self.assertIn('publish_revision_odd',
                      MODULE.hcmd_rx_trace_snapshot(odd_revision)['errors'])
        revision_mismatch = self.trace_sample(publish_revision_begin=2,
                                              publish_revision_end=4)
        self.assertIn('publish_revision_mismatch',
                      MODULE.hcmd_rx_trace_snapshot(revision_mismatch)['errors'])

    def test_ioreg_hcmd_trace_reader_keeps_only_the_documented_osdata_and_numbers(self):
        sample = self.trace_sample()
        tree = [{**sample, 'NativeOtherPrivateData': b'private',
                 'NativeFirmwareIdentityFirmwareName': 'private-name'}]
        encoded = plistlib.dumps(tree)
        with patch.object(MODULE.subprocess, 'check_output', return_value=encoded):
            received = MODULE.ioreg_hcmd_trace_properties()
        self.assertEqual(received[MODULE.HCMD_TRACE_KEY], sample[MODULE.HCMD_TRACE_KEY])
        self.assertEqual(received[MODULE.HCMD_TRACE_KEY + 'RowCount'], 1)
        self.assertNotIn('NativeOtherPrivateData', received)
        self.assertNotIn('NativeFirmwareIdentityFirmwareName', received)

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

    def test_supporting_trace_keeps_numeric_fields_without_inventing_radio_proof(self):
        raw = {'NativeMCCSnapshotValid': 1, 'NativeMCCAppliedChannel149Flags': 0,
               'NativeMCCDebugCountry': 'private', 'NativeStaTxSnapshotValid': 0,
               'NativeStaTxDebugAddress': 'private',
               'NativeFwErrorSnapshotLmacErrorId': 3,
               'NativeHcmdRxTraceRow0Serial': 22,
               'NativeFirmwareIdentityDriverGeneration': 9,
               'NativeFirmwareIdentityFirmwareName': 'private-firmware-name',
               'NativeFirmwareIdentitySerialNumber': 'private-serial',
               'Unrelated': 8}
        values = MODULE.safe_runtime_snapshot(raw)
        self.assertEqual(values['NativeMCCAppliedChannel149Flags'], 0)
        self.assertEqual(values['NativeStaTxSnapshotValid'], 0)
        self.assertEqual(values['NativeFwErrorSnapshotLmacErrorId'], 3)
        self.assertEqual(values['NativeHcmdRxTraceRow0Serial'], 22)
        self.assertEqual(values['NativeFirmwareIdentityDriverGeneration'], 9)
        self.assertNotIn('NativeMCCDebugCountry', values)
        self.assertNotIn('NativeStaTxDebugAddress', values)
        self.assertNotIn('NativeFirmwareIdentityFirmwareName', values)
        self.assertNotIn('NativeFirmwareIdentitySerialNumber', values)
        self.assertNotIn('Unrelated', values)
        self.assertNotIn('NativeMCCResponseProfile149Present', values)
        for key in values:
            self.assertNotIn(key, MODULE.REQUIRED_ENABLED_FLAGS)
            self.assertNotIn(key, MODULE.REQUIRED_DISABLED_FLAGS)
            self.assertNotIn(key, MODULE.TX_ZERO_COUNTERS)
            self.assertNotIn(key, MODULE.ROC_REQUIRED_VALUES)
        profile = dict(MODULE.REQUIRED_ENABLED_FLAGS)
        profile.update({key: False for key in MODULE.REQUIRED_DISABLED_FLAGS})
        profile.update({'NativeP2PRx149ProfileEnabled': 1,
                        'NativeP2PRx149HostTxBlocked': 1,
                        'NativeP2PRx149Selected': 0,
                        'NativeP2PTxProbe': True,
                        'NativeFwErrorSnapshotTransmitAllowed': 1,
                        'NativeHcmdRxTracePeerAccepted': 1})
        problems = MODULE.profile_problems(profile, selected=False)
        self.assertIn('NativeP2PTxProbe', problems)
        self.assertNotIn('NativeFwErrorSnapshotTransmitAllowed', problems)
        self.assertNotIn('NativeHcmdRxTracePeerAccepted', problems)
        self.assertIn('NativeP2PRocStartSeen', MODULE.roc_session_problems({
            'NativeFwErrorSnapshotRocStartSeen': 1,
            'NativeHcmdRxTraceSessionStarted': 1,
        }))

    def test_disarmed_worker_stops_before_any_system_or_rf_access(self):
        args = type('Args', (), {
            'arm': True, 'receiver_gated': True,
            'router_observation_id': 't084-test', 'expect_build': MODULE.BUILD,
            'phone_ready': True, 'output': '/tmp/unused-test085-output'})()
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
        reads = TRACE_GUARD_FIXTURE.closed_zero_event_reads()
        evidence = TRACE_GUARD_FIXTURE.EVIDENCE.guarded_rx_trace_evidence(*reads)
        post = dict(reads[-1])
        self.assertNotIn('NativeP2PRxTraceSnapshotComplete', post)
        self.assertTrue(MODULE.rx_trace_snapshot_complete(evidence, post))
        self.assertFalse(MODULE.rx_trace_snapshot_complete(
            evidence, dict(post, NativeP2PRxTracePendingDrainCount=None)))
        self.assertFalse(MODULE.rx_trace_snapshot_complete(
            dict(evidence, valid=False), post))
        self.assertFalse(MODULE.rx_trace_snapshot_complete(
            evidence, dict(post, NativeP2PRxTraceSnapshotVersionEnd=5)))

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
            'NativeP2PRx149LastPeerAddress': 'TEST_PEER_1',
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
            'NativeP2PPeerMAC': 'TEST_PEER_2',
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
        self.assertNotIn('TEST_PEER_2', json.dumps(summary))

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

    def test_clock_sample_is_bracketed_and_does_not_claim_cross_domain_mapping(self):
        with patch.object(MODULE.time, 'CLOCK_UPTIME_RAW', 91, create=True), \
             patch.object(MODULE.time, 'time_ns', side_effect=[1000, 1180]), \
             patch.object(MODULE.time, 'clock_gettime_ns', return_value=1090) as get_clock:
            sample = MODULE.clock_domain_snapshot()
        get_clock.assert_called_once_with(91)
        self.assertTrue(sample['uptime_clock_present'])
        self.assertEqual(sample['uptime_ns'], 1090)
        self.assertEqual(sample['realtime_before_ns'], 1000)
        self.assertEqual(sample['realtime_after_ns'], 1180)
        self.assertEqual(sample['realtime_bracket_width_ns'], 180)
        self.assertEqual(sample['realtime_sample_error_bound_ns'], 180)
        self.assertFalse(sample['directly_comparable_to_driver_rx_host_us'])
        self.assertFalse(sample['clock_mapping_to_router_pcap_proven'])

    def test_clock_sample_reports_unavailable_instead_of_fabricating_uptime(self):
        with patch.object(MODULE.time, 'CLOCK_UPTIME_RAW', 92, create=True), \
             patch.object(MODULE.time, 'time_ns', side_effect=[1000]), \
             patch.object(MODULE.time, 'clock_gettime_ns', side_effect=OSError):
            sample = MODULE.clock_domain_snapshot()
        self.assertFalse(sample['uptime_clock_present'])
        self.assertEqual(sample['realtime_before_ns'], 1000)
        self.assertIsNone(sample['realtime_after_ns'])
        self.assertIsNone(sample['uptime_ns'])
        self.assertEqual(sample['uptime_clock_error_type'], 'OSError')
        self.assertFalse(sample['clock_mapping_to_router_pcap_proven'])

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
        source = (ROOT / 'arm_p2p_rx149_test085.swift').read_text()
        self.assertEqual(source.count('IORegistryEntrySetCFProperty('), 1)
        self.assertIn('NativeP2PRx149ObservationOnly', source)
        self.assertIn('NativeP2PRx149HostTxBlocked', source)
        self.assertIn('NativeP2PRx149ArmOnce', source)
        self.assertNotIn('NativeP2PArmOnce', source)
        self.assertIn('kmutil', source)
        self.assertIn('--expect-uuid', source)
        self.assertNotIn('NativeP2PRx149HostTxBlocked", kCFBooleanFalse', source)
        self.assertEqual(source.count('IORegistryEntrySetCFProperty('), 1)
        collector = (ROOT / 'capture_test085_receive149_once.py').read_text()
        self.assertEqual(collector.count('subprocess.run([str(helper)'), 1)


if __name__ == '__main__':
    unittest.main()
