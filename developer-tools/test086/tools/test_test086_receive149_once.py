#!/usr/bin/env python3
"""Offline behavioral tests for Test086's receive-only gates."""
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
    'capture_test086_receive149_once', ROOT / 'capture_test086_receive149_once.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TRACE_GUARD_SPEC = importlib.util.spec_from_file_location(
    'test086_rx_entry_guard_fixture', ROOT / 'tests' / 'test086_rx_entry_guard.py')
TRACE_GUARD_FIXTURE = importlib.util.module_from_spec(TRACE_GUARD_SPEC)
TRACE_GUARD_SPEC.loader.exec_module(TRACE_GUARD_FIXTURE)


class Test086ReceiveOnlyGateTests(unittest.TestCase):
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
                        'NativeP2PRx149DataInputProfileEnabled': 1,
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
            'phone_ready': True, 'output': '/tmp/unused-test086-output'})()
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
            'NativeP2PRx149DataInputProfileEnabled': 1,
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

    def test_data_input_flag_and_prearm_profile_are_independent_required_gates(self):
        values = dict(MODULE.REQUIRED_ENABLED_FLAGS)
        values.update({key: False for key in MODULE.REQUIRED_DISABLED_FLAGS})
        values.update({'NativeP2PRx149ProfileEnabled': 1,
                       'NativeP2PRx149DataInputProfileEnabled': 1,
                       'NativeP2PRx149HostTxBlocked': 1,
                       'NativeP2PRx149Selected': 0})
        self.assertEqual(MODULE.profile_problems(values, selected=False), [])
        values['NativeP2PRx149DataInputExperiment'] = False
        self.assertIn('NativeP2PRx149DataInputExperiment',
                      MODULE.profile_problems(values, selected=False))
        values['NativeP2PRx149DataInputExperiment'] = True
        values['NativeP2PRx149DataInputProfileEnabled'] = 0
        self.assertIn('NativeP2PRx149DataInputProfileEnabled',
                      MODULE.profile_problems(values, selected=False))
        values['NativeP2PRx149DataInputProfileEnabled'] = 1
        values['NativeP2PRx149HostTxBlocked'] = 0
        self.assertIn('NativeP2PRx149HostTxBlocked',
                      MODULE.profile_problems(values, selected=False))

    @staticmethod
    def data_rx_sample(**changes):
        sample = {key: 0 for key in (
            MODULE.AWDL_DATA_RX_COUNTERS + MODULE.AWDL_DATA_RX_GAUGES +
            MODULE.AWDL_HOST_TX_COUNTERS + MODULE.AWDL_HOST_TX_GAUGES +
            MODULE.AWDL_DATA_RX_EPOCH_KEYS)}
        sample.update({
            'NativeP2PRx149HostTxBlocked': 1,
            'NativeP2PRxEntrySnapshotBegin': 2,
            'NativeP2PRxEntrySnapshotEnd': 2,
            'NativeP2PRxEntrySchema': 2,
            'NativeP2PRxEntryLastAwdlDataCandidatePresent': 0,
            'NativeP2PRxEntryLastAwdlDataCandidateContextGeneration': 0,
            'NativeP2PRxEntryLastAwdlDataCandidatePowerGeneration': 0,
            'NativeP2PRxEntryLastAwdlDataCandidateStationGeneration': 0,
            'NativeP2PRxEntryLastAwdlDataCandidateRocGeneration': 0,
            'NativeP2PRxEntryLastAwdlDataCandidateHostRxMonotonicUs': 0,
            'NativeP2PRxEntryCountAwdlBssidCandidate': 0,
        })
        sample.update(changes)
        return sample

    def test_data_rx_missing_counters_stay_unknown_and_never_become_zero(self):
        empty = MODULE.awdl_data_rx_snapshot({})
        self.assertFalse(empty['complete'])
        self.assertIsNone(empty['counters']['NativeAwdlDataRxCaptured'])
        self.assertIn('NativeAwdlDataRxCaptured', empty['counter_missing'])
        delta = MODULE.awdl_data_rx_delta({}, self.data_rx_sample())
        self.assertIsNone(delta['observed_counter_delta']['NativeAwdlDataRxCaptured'])
        self.assertIsNone(delta['awdl_data_tx_submitted_delta'])

    def test_data_rx_pipeline_deltas_and_ifnet_semantics_are_narrow(self):
        epoch = dict(zip(MODULE.AWDL_DATA_RX_EPOCH_KEYS, (11, 13, 17, 19)))
        before = self.data_rx_sample(**epoch)
        after = self.data_rx_sample(
            NativeAwdlDataRxCaptured=2, NativeAwdlDataRxDecoded=2,
            NativeAwdlDataRxDelivered=1, NativeAwdlDataRxInputFailed=1, **epoch,
            NativeP2PRxEntryCountAwdlBssidCandidate=2)
        result = MODULE.awdl_data_rx_delta(before, after)
        self.assertEqual(result['observed_counter_delta']['NativeAwdlDataRxCaptured'], 2)
        self.assertEqual(result['observed_counter_delta']['NativeAwdlDataRxDecoded'], 2)
        self.assertEqual(result['observed_counter_delta']['NativeAwdlDataRxDelivered'], 1)
        self.assertEqual(result['candidate_descriptor_count_delta'], 2)
        self.assertFalse(result['counter_delta_is_per_frame_correlation'])
        self.assertFalse(result['native_awdl_reply_proven'])
        self.assertFalse(result['airdrop_proven'])
        self.assertIn('KPI acceptance', result['post']['ifnet_delivery_semantics'])

    def test_candidate_delta_is_unknown_across_owner_epoch_change(self):
        before = self.data_rx_sample(
            **dict(zip(MODULE.AWDL_DATA_RX_EPOCH_KEYS, (11, 13, 17, 19))))
        after = self.data_rx_sample(
            **dict(zip(MODULE.AWDL_DATA_RX_EPOCH_KEYS, (11, 13, 17, 20))),
            NativeP2PRxEntryCountAwdlBssidCandidate=3)
        result = MODULE.awdl_data_rx_delta(before, after)
        self.assertIsNone(result['candidate_descriptor_count_delta'])
        self.assertFalse(result['candidate_epoch_match'])
        self.assertEqual(result['candidate_descriptor_count_post'], 3)

    def test_candidate_delta_is_unknown_without_nonzero_owner_epochs(self):
        before = self.data_rx_sample()
        after = self.data_rx_sample(NativeP2PRxEntryCountAwdlBssidCandidate=3)
        result = MODULE.awdl_data_rx_delta(before, after)
        self.assertIsNone(result['candidate_descriptor_count_delta'])
        self.assertFalse(result['candidate_epoch_match'])

    def test_candidate_delta_is_unknown_when_entry_snapshot_is_unstable(self):
        epoch = dict(zip(MODULE.AWDL_DATA_RX_EPOCH_KEYS, (11, 13, 17, 19)))
        before = self.data_rx_sample(**epoch)
        after = self.data_rx_sample(
            **epoch, NativeP2PRxEntrySnapshotEnd=3,
            NativeP2PRxEntryCountAwdlBssidCandidate=3)
        result = MODULE.awdl_data_rx_delta(before, after)
        self.assertIsNone(result['candidate_descriptor_count_delta'])
        self.assertTrue(result['candidate_epoch_match'])
        self.assertFalse(result['candidate_snapshots_stable'])

    def test_data_rx_requires_stable_drained_window_and_zero_data_tx(self):
        sample = self.data_rx_sample()
        evidence = MODULE.awdl_data_rx_triplet_evidence([sample, sample, sample])
        self.assertTrue(evidence['valid'], evidence)
        submitted = self.data_rx_sample(NativeAwdlDataTxSubmitted=1)
        delta = MODULE.awdl_data_rx_delta(sample, submitted)
        self.assertEqual(delta['awdl_data_tx_submitted_delta'], 1)
        self.assertFalse(delta['awdl_data_tx_submission_unchanged'])
        missing = dict(sample)
        del missing['NativeAwdlDataRxDecoded']
        self.assertFalse(MODULE.awdl_data_rx_triplet_evidence([missing] * 3)['valid'])

    @staticmethod
    def data_receipt_sample(**changes):
        prefix = MODULE.AWDL_RX149_RECEIPT_PREFIX
        sample = {prefix + key: 0 for key in MODULE.AWDL_RX149_RECEIPT_FIELDS}
        sample.update({
            prefix + 'SchemaVersion': 2,
            prefix + 'SnapshotBegin': 2,
            prefix + 'SnapshotEnd': 2,
            'NativeP2PProbeContextGeneration': 3,
            'NativeP2PProbePowerGeneration': 5,
            'NativeP2PProbeStationGeneration': 7,
            'NativeP2PRocGeneration': 9,
            'NativeP2PRxTraceOwnerSerial': 11,
        })
        sample.update({prefix + key: value for key, value in changes.items()})
        return sample

    def test_numeric_rx_receipt_binds_one_149_ifnet_kpi_without_peer_claim(self):
        sample = self.data_receipt_sample(
            ContentRevision=1, Disposition=6, Sequence=12, OwnerSerial=11, InterfaceIncarnation=4,
            ContextGeneration=3, PowerGeneration=5, StationGeneration=7,
            RocGeneration=9, CaptureMonotonicUs=100, InputMonotonicUs=120,
            DeadlineMonotonicUs=200, IeeeChannel=149, MacIndexPresent=1,
            MacIndex=1, MacPhyDecodeMode=2, MpduLength=512,
            DecodedIpv6Count=1, IfnetInputResultPresent=1, IfnetInputResult=0)
        snapshot = MODULE.awdl_data_rx149_receipt_snapshot(sample)
        self.assertTrue(snapshot['valid'], snapshot)
        self.assertTrue(snapshot['local_ifnet_input_kpi_accepted'])
        self.assertFalse(snapshot['input_time_proves_completion_before_deadline'])
        self.assertIn('admission/ticket time', snapshot['input_time_semantics'])
        evidence = MODULE.awdl_data_rx149_receipt_triplet_evidence(
            [sample, sample, sample], sample)
        self.assertTrue(evidence['valid'], evidence)
        self.assertTrue(evidence['local_ifnet_input_kpi_accepted'])
        self.assertTrue(evidence['publication_seqlock_valid'])
        self.assertTrue(evidence['content_revision_stable'])
        self.assertTrue(evidence['mpdu_sequence_stable'])
        self.assertFalse(evidence['peer_or_socket_receipt_proven'])
        self.assertFalse(evidence['airdrop_proven'])
        delta = MODULE.awdl_data_rx149_receipt_delta(
            self.data_receipt_sample(), sample, evidence)
        self.assertEqual(delta['sequence_delta'], 12)
        self.assertTrue(delta['new_receipt_bound_to_current_owner'])
        self.assertTrue(delta['local_ifnet_input_kpi_accepted'])

    def test_numeric_rx_receipt_keeps_missing_and_bad_time_order_unknown(self):
        sample = self.data_receipt_sample()
        missing = dict(sample)
        del missing[MODULE.AWDL_RX149_RECEIPT_PREFIX + 'Disposition']
        self.assertFalse(MODULE.awdl_data_rx149_receipt_snapshot(missing)['valid'])
        invalid = self.data_receipt_sample(
            ContentRevision=1, Disposition=6, Sequence=1, OwnerSerial=11, InterfaceIncarnation=4,
            ContextGeneration=3, PowerGeneration=5, StationGeneration=7,
            RocGeneration=9, CaptureMonotonicUs=150, InputMonotonicUs=120,
            DeadlineMonotonicUs=200, IeeeChannel=149,
            IfnetInputResultPresent=1, IfnetInputResult=0)
        result = MODULE.awdl_data_rx149_receipt_snapshot(invalid)
        self.assertFalse(result['valid'])
        self.assertIn('input_time_precedes_capture', result['errors'])

        at_deadline = self.data_receipt_sample(
            ContentRevision=1, Disposition=6, Sequence=1, OwnerSerial=11, InterfaceIncarnation=4,
            ContextGeneration=3, PowerGeneration=5, StationGeneration=7,
            RocGeneration=9, CaptureMonotonicUs=100, InputMonotonicUs=200,
            DeadlineMonotonicUs=200, IeeeChannel=149,
            IfnetInputResultPresent=1, IfnetInputResult=0)
        result = MODULE.awdl_data_rx149_receipt_snapshot(at_deadline)
        self.assertFalse(result['valid'])
        self.assertIn('ifnet_input_admission_not_before_lease_deadline', result['errors'])

    def test_receipt_sequence_reset_invalidates_window_completion(self):
        post = self.data_receipt_sample(
            ContentRevision=1, Disposition=6, Sequence=1, OwnerSerial=11, InterfaceIncarnation=4,
            ContextGeneration=3, PowerGeneration=5, StationGeneration=7,
            RocGeneration=9, CaptureMonotonicUs=100, InputMonotonicUs=120,
            DeadlineMonotonicUs=200, IeeeChannel=149, MacIndexPresent=1,
            MacIndex=1, IfnetInputResultPresent=1, IfnetInputResult=0)
        evidence = MODULE.awdl_data_rx149_receipt_triplet_evidence(
            [post, post, post], post)
        result = MODULE.awdl_data_rx149_receipt_delta(
            self.data_receipt_sample(ContentRevision=20, Disposition=1,
                                     Sequence=12, OwnerSerial=11,
                                     InterfaceIncarnation=4, ContextGeneration=3,
                                     PowerGeneration=5, StationGeneration=7,
                                     RocGeneration=9, CaptureMonotonicUs=80,
                                     DeadlineMonotonicUs=190, IeeeChannel=149),
            post, evidence)
        self.assertTrue(result['sequence_reset_or_wrap'])
        self.assertFalse(result['receipt_session_complete'])
        self.assertFalse(result['local_ifnet_input_kpi_accepted'])

    def test_receipt_publication_seqlock_requires_explicit_even_stable_markers(self):
        no_prior_receipt = MODULE.awdl_data_rx149_receipt_snapshot({})
        self.assertEqual(no_prior_receipt['status'], 'not_published_yet')
        self.assertIsNone(MODULE.receipt_preflight_problem(no_prior_receipt))
        self.assertFalse(no_prior_receipt['receipt_observed'])
        self.assertFalse(no_prior_receipt['local_ifnet_input_kpi_accepted'])

        good = self.data_receipt_sample(
            ContentRevision=1, Disposition=6, Sequence=4, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            InputMonotonicUs=120, DeadlineMonotonicUs=200, IeeeChannel=149,
            IfnetInputResultPresent=1, IfnetInputResult=0)
        self.assertTrue(MODULE.awdl_data_rx149_receipt_snapshot(good)['valid'])

        for changes, expected_error in (
                ({'SnapshotBegin': 3, 'SnapshotEnd': 3}, 'publication_snapshot_version_odd'),
                ({'SnapshotBegin': 4, 'SnapshotEnd': 6}, 'publication_snapshot_version_mismatch'),
                ({'SchemaVersion': 1}, 'unknown_schema_version')):
            with self.subTest(changes=changes):
                result = MODULE.awdl_data_rx149_receipt_snapshot(dict(good, **{
                    MODULE.AWDL_RX149_RECEIPT_PREFIX + key: value
                    for key, value in changes.items()}))
                self.assertFalse(result['valid'])
                self.assertIn(expected_error, result['errors'])
                self.assertFalse(result['receipt_observed'])
                self.assertFalse(result['local_ifnet_input_kpi_accepted'])
                self.assertIsNotNone(MODULE.receipt_preflight_problem(result))

        missing = dict(good)
        del missing[MODULE.AWDL_RX149_RECEIPT_PREFIX + 'SnapshotEnd']
        result = MODULE.awdl_data_rx149_receipt_snapshot(missing)
        self.assertFalse(result['valid'])
        self.assertIn(MODULE.AWDL_RX149_RECEIPT_PREFIX + 'SnapshotEnd', result['missing'])
        self.assertFalse(result['receipt_observed'])
        self.assertFalse(result['local_ifnet_input_kpi_accepted'])
        self.assertIsNotNone(MODULE.receipt_preflight_problem(result))

    def test_same_mpdu_can_advance_from_captured_to_ifnet_kpi_acceptance(self):
        before = self.data_receipt_sample(
            ContentRevision=8, Disposition=1, Sequence=12, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            DeadlineMonotonicUs=200, IeeeChannel=149)
        after = self.data_receipt_sample(
            SnapshotBegin=4, SnapshotEnd=4, ContentRevision=9,
            Disposition=6, Sequence=12, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            InputMonotonicUs=150, DeadlineMonotonicUs=200, IeeeChannel=149,
            IfnetInputResultPresent=1, IfnetInputResult=0)
        evidence = MODULE.awdl_data_rx149_receipt_triplet_evidence(
            [after, after, after], after)
        self.assertTrue(evidence['valid'], evidence)
        delta = MODULE.awdl_data_rx149_receipt_delta(before, after, evidence)
        self.assertEqual(delta['sequence_delta'], 0)
        self.assertEqual(delta['content_revision_delta'], 1)
        self.assertTrue(delta['same_mpdu_content_updated_since_prearm'])
        self.assertFalse(delta['new_sequence_since_prearm'])
        self.assertTrue(delta['new_receipt_bound_to_current_owner'])
        self.assertTrue(delta['local_ifnet_input_kpi_accepted'])
        self.assertFalse(delta['peer_or_socket_receipt_proven'])
        self.assertFalse(delta['airdrop_proven'])

    def test_ifnet_failure_errno_decodes_unsigned_registry_u32(self):
        failed = self.data_receipt_sample(
            ContentRevision=3, Disposition=7, Sequence=12, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            InputMonotonicUs=150, DeadlineMonotonicUs=200, IeeeChannel=149,
            IfnetInputResultPresent=1, IfnetInputResult=0xfffffffB)
        result = MODULE.awdl_data_rx149_receipt_snapshot(failed)
        self.assertTrue(result['valid'], result)
        self.assertEqual(result['values']['IfnetInputResult'], -5)
        self.assertFalse(result['local_ifnet_input_kpi_accepted'])

    def test_queue_full_disposition_is_valid_without_ifnet_acceptance_claim(self):
        queue_full = self.data_receipt_sample(
            ContentRevision=2, Disposition=8, Sequence=12, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            DeadlineMonotonicUs=200, IeeeChannel=149)
        result = MODULE.awdl_data_rx149_receipt_snapshot(queue_full)
        self.assertTrue(result['valid'], result)
        self.assertFalse(result['local_ifnet_input_kpi_accepted'])

    def test_mixed_receipt_publications_in_triplet_are_unknown_not_ifnet_success(self):
        captured = self.data_receipt_sample(
            ContentRevision=8, Disposition=1, Sequence=12, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            DeadlineMonotonicUs=200, IeeeChannel=149)
        delivered = self.data_receipt_sample(
            SnapshotBegin=4, SnapshotEnd=4, ContentRevision=9,
            Disposition=6, Sequence=12, OwnerSerial=11,
            InterfaceIncarnation=4, ContextGeneration=3, PowerGeneration=5,
            StationGeneration=7, RocGeneration=9, CaptureMonotonicUs=100,
            InputMonotonicUs=150, DeadlineMonotonicUs=200, IeeeChannel=149,
            IfnetInputResultPresent=1, IfnetInputResult=0)
        evidence = MODULE.awdl_data_rx149_receipt_triplet_evidence(
            [captured, delivered, delivered], delivered)
        self.assertFalse(evidence['valid'])
        self.assertIsNone(evidence['local_ifnet_input_kpi_accepted'])
        self.assertIn('ContentRevision:changed_between_reads', evidence['problems'])
        delta = MODULE.awdl_data_rx149_receipt_delta(captured, delivered, evidence)
        self.assertFalse(delta['receipt_session_complete'])
        self.assertFalse(delta['local_ifnet_input_kpi_accepted'])

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
        source = (ROOT / 'arm_p2p_rx149_test086.swift').read_text()
        self.assertEqual(source.count('IORegistryEntrySetCFProperty('), 1)
        self.assertIn('NativeP2PRx149ObservationOnly', source)
        self.assertIn('NativeP2PRx149DataInputExperiment', source)
        self.assertIn('NativeP2PRx149DataInputProfileEnabled', source)
        self.assertIn('NativeP2PRx149HostTxBlocked', source)
        self.assertIn('NativeP2PRx149ArmOnce', source)
        self.assertNotIn('NativeP2PArmOnce', source)
        self.assertIn('kmutil', source)
        self.assertIn('--expect-uuid', source)
        self.assertNotIn('NativeP2PRx149HostTxBlocked", kCFBooleanFalse', source)
        self.assertEqual(source.count('IORegistryEntrySetCFProperty('), 1)
        collector = (ROOT / 'capture_test086_receive149_once.py').read_text()
        self.assertEqual(collector.count('subprocess.run([str(helper)'), 1)


if __name__ == '__main__':
    unittest.main()
