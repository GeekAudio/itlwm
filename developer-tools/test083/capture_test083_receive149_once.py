#!/usr/bin/env python3
"""One fresh-boot, receiver-gated Test083 RX149-only observation.

No native discovery query or host management/data TX is submitted. The one
manual arm can issue low-level MAC/PHY/session-protection control commands,
which are distinct from host frame transmission. Default invocation is
disarmed; this tool never edits EFI, changes the AP, retries, or downgrades.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import plistlib
from pathlib import Path
import pwd
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time

from capture_test076_resident_data_once import guarded_rx_trace_evidence
from probe_p2p_result import loaded_identity
from probe_wifi_rate import properties

ROOT = Path(__file__).resolve().parent
BUILD = '25G332-Test083'
BASELINE = '25G332-Test082'
PROFILE = 'native_awdl_rx149_observation_only'
METADATA_PATH = ROOT / 'research/test083-next-boot-private.json'
BUILD_PATH = ROOT / 'research/test083-build-private.json'
HELPER_SOURCE = ROOT / 'arm_p2p_rx149_test083.swift'
CLAIM_RELATIVE = Path('Library/Application Support/IntelWirelessNative/ObservationClaims/BootGlobal')
REQUIRED_ENABLED_FLAGS = {
    'NativeP2PProbe': True,
    'NativeP2PManualTrigger': True,
    'NativeP2PRx149ObservationOnly': True,
}
REQUIRED_DISABLED_FLAGS = (
    'NativeP2PRocProbe',
    'NativeP2PTxProbe',
    'NativeP2PAwdlPsfObservationOnly',
    'NativeP2PAwdlMifFollowup',
    'NativeP2PGp2Observation',
    'NativeAwdlDiscoveryExperimentEnabled',
    'NativeAwdlDiscoveryMifCurrentSlotEnabled',
    'NativeAwdlDiscoveryCurrentAwFallbackEnabled',
)
TX_ZERO_COUNTERS = (
    'NativeP2PTxProbeEverDoorbelled',
    'NativeP2PAwdlActionFramesSubmitted',
    'NativeP2PAwdlPsfFrameSubmitted',
    'NativeP2PAwdlMifFrameSubmitted',
    'NativeP2PAwdlMifBootstrapSubmitted',
)
RX_PROPERTY_PREFIXES = ('NativeP2PRx149', 'NativeP2PRx')
PREPARE_PROPERTY_PREFIX = 'NativeP2PPrepareTrace'
ATTEMPT_STATE_PROPERTIES = (
    'NativeP2PProbeAttempted',
    'NativeP2PProbeState',
    'NativeP2PProbeResourceMayExist',
)
PEER_ANONYMOUS_PROPERTIES = (
    'NativeP2PPeerMIFFramesTotal',
    'NativeP2PPeerPSFFramesTotal',
    'NativeP2PPeerAcceptedFrames',
    'NativeP2PPeerRejectedRecords',
    'NativeP2PPeerLastResult',
    'NativeP2PPeerCandidateFramesTotal',
    'NativeP2PPeerAdmissionCountTotal',
    'NativeP2PPeerUpdateCountTotal',
    'NativeP2PPeerRxChannelIndex',
)
PEER_COUNTER_PROPERTIES = tuple(
    key for key in PEER_ANONYMOUS_PROPERTIES
    if key not in ('NativeP2PPeerLastResult', 'NativeP2PPeerRxChannelIndex'))
ROC_REQUIRED_VALUES = {
    'NativeP2PRocRequestedChannel': 149,
    'NativeP2PRocActualChannel': 149,
    'NativeP2PRocRequestedDurationMs': 100,
    'NativeP2PRocConfiguration': 2,  # IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV
    'NativeP2PRocReceiveObservationOnly': 1,
    'NativeP2PRocStartSeen': 1,
    'NativeP2PRocStartStatus': 1,
    'NativeP2PRocEndSeen': 1,
    'NativeP2PRocEndStatus': 1,
    'NativeP2PRocCommandResult': 0,
    'NativeP2PRocCleanupAllowed': 1,
    'NativeP2PRocUnknown': 0,
    'NativeP2PProbeState': 7,
    'NativeP2PProbeResourceMayExist': 0,
}
OBSERVATION_SECONDS = 20
MAX_CAPTURE_PACKETS = 4096
CAPTURE_DEADLINE_SECONDS = OBSERVATION_SECONDS + 5.0
MAX_PROTOCOL_BYTES = 65536
HCMD_TRACE_KEY = 'NativeHcmdRxTrace'
HCMD_TRACE_MAGIC = 0x54584348
HCMD_TRACE_SCHEMA = 1
HCMD_TRACE_HEADER_BYTES = 84
HCMD_TRACE_ENTRY_BYTES = 80
HCMD_TRACE_CAPACITY = 64
HCMD_TRACE_ALIAS_TO_HEADER = {
    'Schema': 'schema',
    'VersionBegin': 'snapshot_serial_begin',
    'VersionEnd': 'snapshot_serial_end',
    'OwnerGeneration': 'owner_generation',
    'OwnerWatchdogSequence': 'owner_watchdog_sequence',
    'OwnerWatchdogSequencePresent': 'owner_watchdog_sequence_present',
    'RowCount': 'row_count',
    'DroppedCount': 'dropped_count',
    'OverwrittenCount': 'overwritten_count',
    'GapCount': 'gap_count',
    'WindowStartSerial': 'window_start_serial',
    'WindowEndSerial': 'window_end_serial',
    'SnapshotStable': 'stable',
    'SnapshotComplete': 'complete',
}


def _is_sha256(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def test083_metadata_problems(metadata, boot_epoch=None, identity=None, root=ROOT):
    """Validate the frozen Test083 identity/profile contract without side effects."""
    if not isinstance(metadata, dict) or metadata.get('schema') != 1:
        return ['metadata_schema']
    problems = []
    for key, expected in (
        ('candidate', BUILD), ('baseline', BASELINE), ('profile', PROFILE),
        ('installed', True), ('reboot_ready', True), ('armed', True),
        ('rf_manual_only', True), ('maximum_rf_sessions_per_boot', 1),
        ('diagnostic_duration_ms', 100), ('receiver_gated', True),
        ('atomic_boot_claim_required', True), ('formal_peer_policy_changed', False),
        ('no_automatic_reboot', True), ('source_frozen', True),
    ):
        if metadata.get(key) != expected:
            problems.append(key)
    for key in ('expected_binary_sha256', 'expected_info_plist_sha256'):
        if not _is_sha256(metadata.get(key)):
            problems.append(key)
    if not _is_sha256(metadata.get('expected_arm_helper_source_sha256')):
        problems.append('expected_arm_helper_source_sha256')
    elif (not HELPER_SOURCE.is_file() or metadata.get('expected_arm_helper_source_sha256') !=
          hashlib.sha256(HELPER_SOURCE.read_bytes()).hexdigest()):
        problems.append('arm_helper_source_hash')
    expected_uuid = metadata.get('expected_loaded_uuid')
    if (not isinstance(expected_uuid, str) or
            re.fullmatch(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',
                         expected_uuid) is None):
        problems.append('expected_loaded_uuid')
    source_hashes = metadata.get('source_sha256')
    if not isinstance(source_hashes, dict) or not source_hashes:
        problems.append('source_sha256')
    else:
        for name, digest in source_hashes.items():
            if not isinstance(name, str):
                problems.append('source_sha256_entry')
                break
            path = Path(name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or
                    not _is_sha256(digest)):
                problems.append('source_sha256_entry')
                break
    trace_schema = metadata.get('prepare_trace_schema')
    if (not isinstance(trace_schema, dict) or trace_schema.get('version') != 1 or
            trace_schema.get('source_header') != 'native/iwx_p2p_roc_prepare_trace.h' or
            not isinstance(trace_schema.get('fields'), list) or
            len(trace_schema['fields']) < 80 or
            any(not isinstance(v, str) or re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', v) is None
                for v in trace_schema['fields']) or
            len(set(trace_schema['fields'])) != len(trace_schema['fields']) or
            not isinstance(source_hashes, dict) or
            source_hashes.get(trace_schema['source_header']) != trace_schema.get('source_header_sha256')):
        problems.append('prepare_trace_schema')
    for key in ('previous_boot_epoch', 'runtime_boot_epoch'):
        if type(metadata.get(key)) is not int or metadata[key] <= 0:
            problems.append(key)
    previous = metadata.get('previous_boot_epoch')
    observed = metadata.get('runtime_boot_epoch')
    if type(boot_epoch) is int:
        if boot_epoch == previous:
            problems.append('not_a_new_boot')
        if type(observed) is int and boot_epoch <= observed:
            problems.append('boot_not_newer_than_last_observation')
    reported_build = metadata.get('build_report')
    if isinstance(reported_build, str):
        reported_path = Path(reported_build)
        if not reported_path.is_absolute():
            reported_path = Path(root) / reported_path
        try:
            if reported_path.resolve() != BUILD_PATH.resolve():
                problems.append('build_report')
        except OSError:
            problems.append('build_report')
    else:
        problems.append('build_report')

    if identity is not None:
        if identity.get('binary_identity_verified') is not True:
            problems.append('binary_identity')
        if identity.get('loaded_uuid') != expected_uuid:
            problems.append('loaded_uuid')

    if root is not None:
        root = Path(root)
        try:
            if BUILD_PATH.is_symlink():
                raise ValueError('symlinked Test083 build report')
            build = json.loads(BUILD_PATH.read_text())
            if (build.get('candidate') != BUILD or
                    build.get('baseline') != BASELINE or
                    build.get('status') != 'built_offline' or
                    build.get('source_freeze_matches') is not True or
                    build.get('binary_sha256') != metadata.get('expected_binary_sha256') or
                    build.get('info_plist_sha256') != metadata.get('expected_info_plist_sha256') or
                    build.get('arm_helper_source_sha256') != metadata.get('expected_arm_helper_source_sha256') or
                    build.get('prepare_trace_schema') != trace_schema or
                    build.get('mach_o_uuid') != expected_uuid or
                    build.get('source_file_count') != len(source_hashes or {}) or
                    build.get('source_sha256') != source_hashes or
                    build.get('full_build_passed') is not True or
                    build.get('strict_signature_passed') is not True or
                    build.get('installed') is not False or
                    build.get('rf_tested') is not False):
                problems.append('build_identity_or_frozen_manifest')
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            problems.append('build_report_unavailable')
    return sorted(set(problems))


def profile_problems(values, *, selected):
    """Fail closed on wrong/missing profile flags and RX149 selection state."""
    problems = []
    for key, expected in REQUIRED_ENABLED_FLAGS.items():
        if values.get(key) is not expected:
            problems.append(key)
    for key in REQUIRED_DISABLED_FLAGS:
        if values.get(key) is not False:
            problems.append(key)
    expected_numeric = {
        'NativeP2PRx149ProfileEnabled': 1,
        'NativeP2PRx149HostTxBlocked': 1,
        'NativeP2PRx149Selected': 1 if selected else 0,
    }
    for key, expected in expected_numeric.items():
        value = values.get(key)
        if type(value) is not int or value != expected:
            problems.append(key)
    return sorted(set(problems))


def rx149_mode_lock_problems(samples, final):
    """Require the immutable shared once-per-boot latch to remain RX149 mode."""
    values = [sample.get('NativeP2PManualArmed') for sample in samples]
    problems = []
    if any(type(value) is not int for value in values):
        problems.append('NativeP2PManualArmed_missing_or_invalid')
    if any(value == 1 for value in values):
        problems.append('legacy_manual_mode_observed')
    if type(final.get('NativeP2PManualArmed')) is not int or \
            final.get('NativeP2PManualArmed') != 2:
        problems.append('rx149_mode_lock_not_published')
    return sorted(set(problems))


def tx_zero_evidence(before, after, samples=()):
    """Require actual, unmodified zero counters through the arm window."""
    observations = [before, *samples, after]
    missing = [key for key in TX_ZERO_COUNTERS
               if any(key not in sample for sample in observations)]
    invalid = [key for key in TX_ZERO_COUNTERS
               if any(key in sample and type(sample[key]) is not int
                      for sample in observations)]
    nonzero = [key for key in TX_ZERO_COUNTERS
               if any(key in sample and type(sample[key]) is int and sample[key] != 0
                      for sample in observations)]
    changed = [key for key in TX_ZERO_COUNTERS
               if any(key in sample and key in before and sample[key] != before[key]
                      for sample in observations[1:])]
    valid = not (missing or invalid or nonzero or changed)
    return {
        'status': 'complete_zero_window' if valid else 'unknown_or_nonzero',
        'valid': valid,
        'counters_cleared_by_collector': False,
        'missing': missing,
        'invalid': invalid,
        'nonzero': nonzero,
        'changed': changed,
        'before': {key: before.get(key) for key in TX_ZERO_COUNTERS},
        'after': {key: after.get(key) for key in TX_ZERO_COUNTERS},
        'sample_count': len(samples),
        'host_management_or_data_tx_observed': bool(nonzero or changed),
        'counter_provenance': {
            'NativeP2PTxProbeEverDoorbelled':
                'actual_sticky_controller_queue_doorbell_snapshot',
            'NativeP2PAwdlActionFramesSubmitted':
                'driver_per_run_frame_submission_count',
            'NativeP2PAwdlPsfFrameSubmitted':
                'driver_per_run_frame_submission_count',
            'NativeP2PAwdlMifFrameSubmitted':
                'driver_per_run_frame_submission_count',
            'NativeP2PAwdlMifBootstrapSubmitted':
                'driver_per_run_frame_submission_count',
        },
        'per_run_zero_initialization_guard':
            'source may initialize only after valid RX149 profile, no arm/attempt, and an actual empty/idle TX snapshot; it must never overwrite nonzero history',
        'mac_phy_session_protection_control_commands_may_occur': True,
        'scope': 'Four driver per-run Submitted counters plus one actual sticky queue-doorbell history value; missing is unknown. ' \
                 'MAC/PHY/session-protection control commands are not host frame TX.',
    }


def rx149_snapshot(values):
    """Keep only address-free integer/boolean RX149/RX numeric properties."""
    return {key: value for key, value in values.items()
            if key.startswith(RX_PROPERTY_PREFIXES) and type(value) in (int, bool)}


def attempt_state_snapshot(values):
    """Preserve explicit attempt/state/resource fields; missing stays unknown."""
    return {key: values.get(key) if type(values.get(key)) is int else None
            for key in ATTEMPT_STATE_PROPERTIES}


def peer_evidence_snapshot(values):
    """Keep only named numeric peer-table counters/status, never MAC/address fields."""
    snapshot = {}
    missing = []
    invalid = []
    for key in PEER_ANONYMOUS_PROPERTIES:
        value = values.get(key)
        if key not in values:
            snapshot[key] = None
            missing.append(key)
        elif type(value) is not int or not -(1 << 31) <= value <= 0xffffffff:
            snapshot[key] = None
            invalid.append(key)
        else:
            snapshot[key] = value
    snapshot['missing'] = missing
    snapshot['invalid'] = invalid
    return snapshot


def peer_evidence_delta(before, after=None):
    """Calculate only observed counter differences; status/channel are not deltas."""
    left = peer_evidence_snapshot(before)
    right = peer_evidence_snapshot(after) if isinstance(after, dict) else None
    delta = {}
    for key in PEER_COUNTER_PROPERTIES:
        if right is not None and type(left[key]) is int and type(right[key]) is int:
            delta[key] = right[key] - left[key]
        else:
            delta[key] = None
    delta['NativeP2PPeerLastResult'] = None
    delta['NativeP2PPeerRxChannelIndex'] = None
    return {
        'pre': left,
        'post': right,
        'observed_counter_delta': delta,
        'post_status': 'observed' if right is not None else 'unknown_not_sampled',
        'delta_basis': 'arithmetic difference of captured numeric pre/post counters only; missing/invalid is unknown',
        'counter_delta_interpretation': 'arithmetic only; counter reset, wrap, MIF decode, and peer receipt are not inferred',
        'state_and_channel_delta': 'not_applicable',
        'peer_table_acceptance_proven': None,
        'mif_decode_status': 'unknown_not_inferred_from_session_completion',
    }


def rx149_observation_snapshot(values):
    """Combine the RX149 sample with a strict anonymized peer-table whitelist."""
    peer = peer_evidence_snapshot(values)
    return {**rx149_snapshot(values), **{
        key: peer[key] for key in PEER_ANONYMOUS_PROPERTIES}}


def attempt_state_problems(final):
    """An arm outcome is incomplete unless the driver reports an attempt."""
    value = final.get('NativeP2PProbeAttempted')
    if type(value) is not int:
        return ['NativeP2PProbeAttempted_missing_or_invalid']
    if value != 1:
        return ['NativeP2PProbeAttempted_not_1']
    return []


def roc_session_problems(values):
    """Require an ended, successful DISCOV owner session on requested channel 149."""
    problems = []
    for key, expected in ROC_REQUIRED_VALUES.items():
        value = values.get(key)
        if type(value) is not int or value != expected:
            problems.append(key)
    generation = values.get('NativeP2PRocGeneration')
    context_generation = values.get('NativeP2PProbeContextGeneration')
    if (type(generation) is not int or generation <= 0 or
            type(context_generation) is not int or context_generation <= 0 or
            generation != context_generation):
        problems.append('NativeP2PRocGeneration_owner_mismatch')
    return sorted(set(problems))


def safe_runtime_snapshot(values):
    """Preserve numeric/bool driver evidence without private address fields."""
    prefixes = ('NativeP2PRx149', 'NativeP2PRxTrace', 'NativeP2PRoc',
                PREPARE_PROPERTY_PREFIX, 'NativeP2PProbeExercise',
                'NativeMCC', 'NativeStaTx', 'NativeFwErrorSnapshot',
                'NativeHcmdRxTrace', 'NativeFirmwareIdentity')
    exact = set(ATTEMPT_STATE_PROPERTIES) | {
        'NativeP2PManualArmed', 'NativeP2PProbeContextGeneration',
        'NativeP2PProbePowerGeneration', 'NativeP2PProbeStationGeneration',
        'NativeP2PProbeAddResult', 'NativeP2PProbeRemoveResult',
        'NativeP2PProbeBlocked',
    } | set(PEER_ANONYMOUS_PROPERTIES)
    return {key: value for key, value in values.items()
            if (key.startswith(prefixes) or key in exact) and
            (type(value) is int if key in PEER_ANONYMOUS_PROPERTIES else
             type(value) in (int, bool))}


def ioreg_hcmd_trace_properties(class_name='AirportItlwm'):
    """Read only the fixed NativeHcmdRxTrace OSData and its numeric aliases."""
    tree = plistlib.loads(subprocess.check_output(
        ['/usr/sbin/ioreg', '-a', '-r', '-c', class_name]))
    found = {}

    def visit(node):
        for key, value in node.items():
            if key == HCMD_TRACE_KEY and isinstance(value, bytes):
                found[key] = value
            elif (key.startswith(HCMD_TRACE_KEY) and key != HCMD_TRACE_KEY and
                  type(value) in (int, bool)):
                found[key] = value
        for child in node.get('IORegistryEntryChildren', []):
            visit(child)

    for node in tree:
        visit(node)
    return found


def hcmd_rx_trace_snapshot(sample):
    """Decode one fixed little-endian HCTX blob; preserve invalid rows for review."""
    errors = []
    blob = sample.get(HCMD_TRACE_KEY) if isinstance(sample, dict) else None
    if not isinstance(blob, bytes):
        missing_error = 'blob_missing' if blob is None else 'blob_not_osdata'
        revision = _hcmd_trace_publish_revision(sample, errors)
        return {
            'valid': False, 'complete': False,
            'errors': sorted(set([missing_error, *errors])),
            'blob_present': blob is not None, 'blob_length': None,
            'blob_sha256': None, 'publish_revision': revision,
            'header': None, 'rows': [],
            'numeric_summary': _hcmd_trace_numeric_summary(sample),
        'history_truncated': None,
            'wire_complete': False, 'raw_blob_saved': False,
            'interpretation': 'Trace OSData is missing or has the wrong type; no fields were inferred.',
        }

    blob_sha = hashlib.sha256(blob).hexdigest()
    raw_header = {
        'blob_length': len(blob),
        'blob_sha256': blob_sha,
        'magic': None, 'schema': None, 'header_bytes': None,
        'entry_bytes': None, 'snapshot_serial_begin': None,
        'snapshot_serial_end': None, 'owner_generation': None,
        'owner_watchdog_sequence': None,
        'owner_watchdog_sequence_present': None, 'row_count': None,
        'dropped_count': None, 'overwritten_count': None,
        'gap_count': None, 'window_start_serial': None,
        'window_end_serial': None, 'stable': None, 'complete': None,
        'history_truncated': None,
    }
    rows = []
    if len(blob) < HCMD_TRACE_HEADER_BYTES:
        errors.append('blob_shorter_than_header')
        revision = _hcmd_trace_publish_revision(sample, errors)
        return _finish_hcmd_snapshot(
            sample, raw_header, rows, errors, publish_revision=revision)

    values = struct.unpack_from('<IIIIQQIIIIIIIQQII', blob, 0)
    header = dict(zip((
        'magic', 'schema', 'header_bytes', 'entry_bytes',
        'snapshot_serial_begin', 'snapshot_serial_end',
        'owner_generation', 'owner_watchdog_sequence',
        'owner_watchdog_sequence_present', 'row_count',
        'dropped_count', 'overwritten_count', 'gap_count',
        'window_start_serial', 'window_end_serial', 'stable', 'complete'), values))
    raw_header.update(header)
    raw_header['history_truncated'] = (
        header['dropped_count'] > 0 or header['overwritten_count'] > 0 or
        header['window_start_serial'] > 1)

    if header['magic'] != HCMD_TRACE_MAGIC:
        errors.append('bad_magic')
    if header['schema'] != HCMD_TRACE_SCHEMA:
        errors.append('unknown_schema')
    if header['header_bytes'] != HCMD_TRACE_HEADER_BYTES:
        errors.append('header_size_mismatch')
    if header['entry_bytes'] != HCMD_TRACE_ENTRY_BYTES:
        errors.append('entry_size_mismatch')
    if header['row_count'] > HCMD_TRACE_CAPACITY:
        errors.append('row_count_exceeds_capacity')
    if type(header['stable']) is not int or header['stable'] not in (0, 1):
        errors.append('stable_flag_invalid')
    if type(header['complete']) is not int or header['complete'] not in (0, 1):
        errors.append('complete_flag_invalid')
    if type(header['owner_watchdog_sequence_present']) is not int or \
            header['owner_watchdog_sequence_present'] not in (0, 1):
        errors.append('owner_watchdog_presence_invalid')

    publish_revision = _hcmd_trace_publish_revision(sample, errors)
    expected_length = (HCMD_TRACE_HEADER_BYTES +
                       header['row_count'] * HCMD_TRACE_ENTRY_BYTES)
    if len(blob) != expected_length:
        errors.append('blob_length_mismatch')
    if (header['magic'] != HCMD_TRACE_MAGIC or
            header['schema'] != HCMD_TRACE_SCHEMA or
            header['header_bytes'] != HCMD_TRACE_HEADER_BYTES or
            header['entry_bytes'] != HCMD_TRACE_ENTRY_BYTES or
            header['row_count'] > HCMD_TRACE_CAPACITY or
            len(blob) != expected_length):
        return _finish_hcmd_snapshot(
            sample, raw_header, rows, errors, publish_revision)

    for index in range(header['row_count']):
        offset = HCMD_TRACE_HEADER_BYTES + index * HCMD_TRACE_ENTRY_BYTES
        row_values = struct.unpack_from('<QQIIIIIIIIIIIIIIII', blob, offset)
        row = dict(zip((
            'serial', 'monotonic_ns', 'driver_generation',
            'firmware_generation', 'phase', 'source', 'command_id',
            'group_id', 'version', 'qid', 'index', 'header_sequence',
            'flags', 'result', 'result_detail', 'packet_length',
            'payload_length', 'reserved0'), row_values))
        rows.append(row)

    row_errors = _hcmd_trace_row_errors(header, rows)
    errors.extend(row_errors)
    summary = _hcmd_trace_numeric_summary(sample)
    errors.extend(_hcmd_trace_alias_errors(raw_header, summary, len(blob)))
    complete_expected = _hcmd_trace_complete_expected(header, rows, row_errors)
    if header['complete'] != int(complete_expected):
        errors.append('complete_flag_mismatch')
    if header['stable'] == 1 and \
            header['snapshot_serial_begin'] != header['snapshot_serial_end']:
        errors.append('stable_serial_mismatch')
    if header['stable'] == 0:
        errors.append('snapshot_unstable')

    valid = not errors
    wire_complete = header['complete'] == 1 and complete_expected
    return {
        'valid': valid,
        'complete': valid and wire_complete,
        'wire_complete': wire_complete,
        'errors': sorted(set(errors)),
        'blob_present': True,
        'blob_length': len(blob),
        'blob_sha256': blob_sha,
        'publish_revision': publish_revision,
        'header': raw_header,
        'rows': rows,
        'numeric_summary': summary,
        'history_truncated': raw_header['history_truncated'],
        'raw_blob_saved': False,
        'interpretation': (
            'Decoded supporting command/RX chronology only; qid/index and phase/source hints '
            'do not prove firmware ownership, RF transmission, peer receipt, or AirDrop.'),
    }


def _hcmd_trace_numeric_summary(sample):
    if not isinstance(sample, dict):
        return {}
    return {key: value for key, value in sample.items()
            if key.startswith(HCMD_TRACE_KEY) and key != HCMD_TRACE_KEY and
            type(value) in (int, bool)}


def _finish_hcmd_snapshot(sample, header, rows, errors, publish_revision):
    return {
        'valid': False, 'complete': False,
        'errors': sorted(set(errors)),
        'blob_present': isinstance(sample, dict) and HCMD_TRACE_KEY in sample,
        'blob_length': header.get('blob_length'),
        'blob_sha256': header.get('blob_sha256'),
        'publish_revision': publish_revision,
        'header': header,
        'rows': rows,
        'numeric_summary': _hcmd_trace_numeric_summary(sample),
        'history_truncated': header.get('history_truncated'),
        'raw_blob_saved': False,
        'interpretation': (
            'Decoded supporting command/RX chronology only; qid/index and phase/source hints '
            'do not prove firmware ownership, RF transmission, peer receipt, or AirDrop.'),
    }


def _hcmd_trace_publish_revision(sample, errors):
    prefix = HCMD_TRACE_KEY
    begin = sample.get(prefix + 'PublishRevisionBegin') if isinstance(sample, dict) else None
    end = sample.get(prefix + 'PublishRevisionEnd') if isinstance(sample, dict) else None
    if type(begin) is not int or type(end) is not int:
        errors.append('publish_revision_missing_or_invalid')
        return None
    if begin != end:
        errors.append('publish_revision_mismatch')
    if begin % 2 != 0:
        errors.append('publish_revision_odd')
    return begin


def _hcmd_trace_alias_errors(header, summary, blob_length):
    errors = []
    for suffix, field in HCMD_TRACE_ALIAS_TO_HEADER.items():
        key = HCMD_TRACE_KEY + suffix
        value = summary.get(key)
        if type(value) is not int:
            errors.append('numeric_alias_missing_or_invalid:' + suffix)
        elif value != header[field]:
            errors.append('numeric_alias_mismatch:' + suffix)
    length = summary.get(HCMD_TRACE_KEY + 'BlobLength')
    if type(length) is not int:
        errors.append('numeric_alias_missing_or_invalid:BlobLength')
    elif length != blob_length:
        errors.append('numeric_alias_mismatch:BlobLength')
    return errors


def _hcmd_trace_row_errors(header, rows):
    errors = []
    begin = header['window_start_serial']
    end = header['window_end_serial']
    expected_begin = 0 if end == 0 else max(1, end - HCMD_TRACE_CAPACITY + 1)
    if begin != expected_begin:
        errors.append('serial_window_start_mismatch')
    if end != header['snapshot_serial_end']:
        errors.append('serial_window_end_mismatch')
    if end == 0 and (begin != 0 or rows):
        errors.append('empty_serial_window_mismatch')
    if end > 0 and (begin <= 0 or begin > end):
        errors.append('serial_window_invalid')
    previous = None
    for row in rows:
        serial = row['serial']
        if serial <= 0 or (previous is not None and serial <= previous):
            errors.append('row_serial_not_strictly_increasing')
        if serial < begin or serial > end:
            errors.append('row_serial_outside_window')
        if row['reserved0'] != 0:
            errors.append('row_reserved_nonzero')
        previous = serial
    width = 0 if end == 0 else max(0, end - begin + 1)
    expected_gap = max(0, width - len(rows))
    if header['gap_count'] != expected_gap:
        errors.append('gap_count_mismatch')
    return errors


def _hcmd_trace_complete_expected(header, rows, row_errors):
    begin, end = header['window_start_serial'], header['window_end_serial']
    if end == 0:
        serial_window_complete = begin == 0 and not rows
    elif begin > 0 and begin <= end:
        width = end - begin + 1
        serial_window_complete = (len(rows) == width and all(
            row['serial'] == begin + index for index, row in enumerate(rows)))
    else:
        serial_window_complete = False
    return (header['stable'] == 1 and
            header['snapshot_serial_begin'] == header['snapshot_serial_end'] and
            header['gap_count'] == 0 and not row_errors and
            serial_window_complete)


def hcmd_rx_trace_evidence(samples):
    """Require three identical, alias-consistent snapshots; never infer permission."""
    parsed = [hcmd_rx_trace_snapshot(sample) for sample in samples]
    errors = []
    if len(samples) != 3:
        errors.append('three_snapshots_required')
    if any(not item['valid'] for item in parsed):
        errors.append('one_or_more_snapshots_invalid')
    signatures = [(
        item['blob_sha256'], item['publish_revision'], item['header'])
        for item in parsed]
    stable_across_reads = bool(
        len(signatures) == 3 and all(item == signatures[0] for item in signatures[1:]))
    if len(signatures) == 3 and not stable_across_reads:
        errors.append('header_blob_or_revision_changed_between_reads')
    if not stable_across_reads:
        errors.append('three_snapshot_consistency_not_proven')
    latest = parsed[-1] if parsed else None
    return {
        'valid': not errors,
        'complete': bool(not errors and latest and stable_across_reads and latest['complete']),
        'history_truncated': latest.get('history_truncated') if latest else None,
        'wire_complete': bool(latest and latest.get('wire_complete')),
        'three_snapshot_consistency_proven': stable_across_reads,
        'errors': sorted(set(errors)),
        'sample_count': len(parsed),
        'sample_headers': [{
            'valid': item['valid'], 'errors': item['errors'],
            'blob_length': item['blob_length'],
            'blob_sha256': item['blob_sha256'],
            'publish_revision': item['publish_revision'],
            'header': item['header'],
            'history_truncated': item.get('history_truncated'),
            'numeric_summary': item['numeric_summary'],
        } for item in parsed],
        'decoded_rows': latest['rows'] if latest and stable_across_reads else [],
        'decoded_rows_by_sample': (
            [] if stable_across_reads else [item['rows'] for item in parsed]),
        'raw_blob_saved': False,
        'interpretation': (
            'Supporting chronology only; no RF, command ownership, completion, peer receipt, '
            'or AirDrop permission is derived from these rows.'),
    }


def _read_hcmd_rx_trace_triplet():
    samples = []
    for index in range(3):
        if index:
            time.sleep(0.03)
        samples.append(ioreg_hcmd_trace_properties())
    return hcmd_rx_trace_evidence(samples)


def _safe_hcmd_rx_trace_triplet():
    try:
        return _read_hcmd_rx_trace_triplet()
    except Exception as error:
        return {
            'valid': False, 'complete': False,
            'three_snapshot_consistency_proven': False,
            'sample_count': 0, 'errors': ['ioreg_read_failed'],
            'error_type': type(error).__name__,
            'decoded_rows': [], 'raw_blob_saved': False,
            'interpretation': 'Supporting log unavailable; RF permissions unchanged.',
        }


def firmware_trace_row_delta(before, after):
    """Show newly visible serials only when both bounded snapshots are comparable."""
    if not (isinstance(before, dict) and before.get('valid') is True and
            isinstance(after, dict) and after.get('valid') is True):
        return {'comparable': False, 'reason': 'snapshot_not_valid'}
    if before.get('complete') is not True or after.get('complete') is not True:
        return {'comparable': False, 'reason': 'snapshot_not_complete'}
    pre_header = before['sample_headers'][-1]['header']
    post_header = after['sample_headers'][-1]['header']
    if pre_header['owner_generation'] != post_header['owner_generation']:
        return {'comparable': False, 'reason': 'owner_generation_changed'}
    pre_end = pre_header['snapshot_serial_end']
    post_end = post_header['snapshot_serial_end']
    if post_end < pre_end:
        return {'comparable': False, 'reason': 'serial_counter_reset'}
    expected_new_count = post_end - pre_end
    if expected_new_count > HCMD_TRACE_CAPACITY:
        return {
            'comparable': False,
            'reason': 'serial_delta_exceeds_bounded_post_window',
            'expected_new_row_count': expected_new_count,
            'post_window_start_serial': post_header['window_start_serial'],
        }
    if (expected_new_count > 0 and
            post_header['window_start_serial'] > pre_end + 1):
        return {
            'comparable': False,
            'reason': 'post_window_does_not_cover_new_serial_range',
            'expected_new_row_count': expected_new_count,
            'post_window_start_serial': post_header['window_start_serial'],
        }
    added = [row for row in after['decoded_rows'] if row['serial'] > pre_end]
    expected_serials = list(range(pre_end + 1, post_end + 1))
    if [row['serial'] for row in added] != expected_serials:
        return {
            'comparable': False,
            'reason': 'post_window_new_serial_range_incomplete',
            'expected_new_row_count': expected_new_count,
            'observed_new_serials': [row['serial'] for row in added],
        }
    return {
        'comparable': True,
        'pre_owner_generation': pre_header['owner_generation'],
        'post_owner_generation': post_header['owner_generation'],
        'pre_snapshot_serial_end': pre_end,
        'post_snapshot_serial_end': post_end,
        'new_row_count': len(added),
        'new_rows': added,
        'pre_history_truncated': before.get('history_truncated'),
        'post_history_truncated': after.get('history_truncated'),
        'delta_window_complete': True,
        'interpretation': (
            'Host-observed rows from a complete bounded delta window only; lifetime history '
            'may be truncated, and no ownership or completion proof is inferred.'),
    }


def prepare_trace_snapshot(values):
    """Keep the independent numeric preparation record, even without an ROC owner."""
    return {key: value for key, value in values.items()
            if key.startswith(PREPARE_PROPERTY_PREFIX) and type(value) is int}


def _read_prepare_trace_triplet():
    """Read three independent snapshots; interpretation requires stable owner evidence."""
    samples = []
    for index in range(3):
        if index:
            time.sleep(0.03)
        samples.append(safe_runtime_snapshot(properties('AirportItlwm')))
    return samples


def prepare_trace_evidence(samples, schema=None):
    """Validate publication integrity separately from safe cleanup or RX success."""
    raw = [prepare_trace_snapshot(item) for item in samples]
    problems = []
    if len(raw) != 3:
        problems.append('three_snapshots_required')
    prefix = PREPARE_PROPERTY_PREFIX
    revisions, attempts = [], []
    for sample in raw:
        if isinstance(schema, dict):
            for field in schema.get('fields', []):
                if type(sample.get(prefix + 'Field.' + field)) is not int:
                    problems.append('raw_field_missing_or_invalid:' + field)
        if sample.get(prefix + 'SchemaVersion') != 1:
            problems.append('schema_missing_or_invalid')
        if sample.get(prefix + 'SnapshotValid') != 1:
            problems.append('snapshot_not_valid')
        versions = [sample.get(prefix + suffix) for suffix in (
            'SnapshotVersionBegin', 'SnapshotVersionEnd', 'Revision')]
        if not (all(type(v) is int and v > 0 and v % 2 == 0 for v in versions)
                and len(set(versions)) == 1):
            problems.append('snapshot_version_not_stable_even')
        revisions.append(sample.get(prefix + 'Revision'))
        attempt = sample.get(prefix + 'AttemptSerial')
        if type(attempt) is not int or attempt <= 0:
            problems.append('attempt_missing_or_invalid')
        attempts.append(attempt)
        if (sample.get(prefix + 'Field.valid') != 1 or
                sample.get(prefix + 'Field.serial') != attempt):
            problems.append('raw_attempt_alias_mismatch')
        for name, field in (('PrepareErrno', 'prepareErrno'),
                            ('CleanupErrno', 'cleanupErrno'),
                            ('Step', 'step'), ('Reason', 'reason')):
            alias = sample.get(prefix + name)
            if type(alias) is not int or sample.get(prefix + 'Field.' + field) != alias:
                problems.append('raw_' + field + '_alias_mismatch')
    if len(set(revisions)) != 1 or len(set(attempts)) != 1:
        problems.append('revision_or_attempt_changed_between_reads')
    if raw and any(sample != raw[0] for sample in raw[1:]):
        problems.append('trace_fields_changed_between_reads')
    latest = raw[-1] if raw else {}
    owner_bindings = []
    for full, trace in zip(samples, raw):
        context = full.get('NativeP2PProbeContextGeneration')
        power = full.get('NativeP2PProbePowerGeneration')
        station = full.get('NativeP2PProbeStationGeneration')
        field = lambda name: trace.get(prefix + 'Field.' + name)
        bound = (all(type(v) is int and v > 0 for v in (context, power, station))
            and full.get('NativeP2PManualArmed') == 2
            and full.get('NativeP2PProbeAttempted') == 1
            and field('token') == context
            and field('scGenerationEntry') == field('scGenerationExit') == power
            and field('p2pFirmwareGenerationEntry') == field('p2pFirmwareGenerationExit') == power
            and field('stationEpochEntry') == field('stationEpochExit') == station
            and field('configuration') == 2 and field('receiveObservation149') == 1
            and field('featureCompiled') == 1)
        owner_bindings.append(bool(bound))
    owner_tuples = [tuple(item.get('NativeP2PProbe' + suffix)
                          for suffix in ('ContextGeneration', 'PowerGeneration', 'StationGeneration'))
                    for item in samples]
    current_attempt_matches = bool(len(owner_bindings) == 3 and all(owner_bindings)
                                   and len(set(owner_tuples)) == 1)
    return {
        'snapshot_valid': not problems,
        'current_attempt_matches': current_attempt_matches,
        'problems': sorted(set(problems)), 'samples': raw,
        'attempt_serial': latest.get(prefix + 'AttemptSerial'),
        'prepare_step': latest.get(prefix + 'Step'),
        'prepare_reason': latest.get(prefix + 'Reason'),
        'prepare_errno': latest.get(prefix + 'PrepareErrno'),
        'cleanup_errno': latest.get(prefix + 'CleanupErrno'),
        'cleanup_safety_inferred_by_collector': False,
        'roc_success_inferred': False,
        'peer_receipt_or_airdrop_inferred': False,
        'scope': 'Three identical valid preparation publications; owner validity, original diagnostic failure, cleanup outcome and ROC/RX success remain separate evidence.',
    }


def rx_trace_snapshot_complete(trace_evidence, post):
    """Require producer closure, the published seqlock, drain, and no loss.

    The production publisher exposes SchemaVersion and an even, matching
    SnapshotVersionBegin/End pair. There is no separate SnapshotComplete
    property; stable completeness is derived by guarded_rx_trace_evidence.
    """
    trace_values = trace_evidence.get('values', {}) if isinstance(trace_evidence, dict) else {}
    required = {
        'NativeP2PRxTraceSchemaVersion': 1,
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
    values_valid = all(type(post.get(key)) is int and post.get(key) == expected
                       for key, expected in required.items())
    begin = post.get('NativeP2PRxTraceSnapshotVersionBegin')
    end = post.get('NativeP2PRxTraceSnapshotVersionEnd')
    revision = post.get('NativeP2PRxTraceRevision')
    event_count = post.get('NativeP2PRxTraceEventCount')
    evidence_revision = trace_values.get('NativeP2PRxTraceRevision')
    evidence_event_count = trace_values.get('NativeP2PRxTraceEventCount')
    event_capacity = trace_evidence.get('event_capacity')
    version_valid = (type(begin) is int and type(end) is int and
                     begin > 0 and begin == end and begin % 2 == 0)
    evidence_matches = (
        type(revision) is int and revision >= 0 and revision == evidence_revision and
        type(event_capacity) is int and event_capacity >= 0 and
        type(event_count) is int and 0 <= event_count <= event_capacity and
        event_count == evidence_event_count and
        type(trace_evidence.get('event_count')) is int and
        event_count == trace_evidence.get('event_count'))
    return (trace_evidence.get('valid') is True and
            trace_evidence.get('stable_complete_snapshot') is True and
            trace_evidence.get('trace_coverage_complete') is True and
            values_valid and version_valid and evidence_matches)


def fresh_observation_id(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', value) is not None


def ready_event(line):
    match = re.fullmatch(r'READY ([a-f0-9]{32}) window_seconds=(\d+) link_type=(\d+)', line)
    if not match:
        raise ValueError('Invalid capture readiness event')
    token, seconds, link_type = match.groups()
    if int(seconds) != OBSERVATION_SECONDS or int(link_type) != 127:
        raise ValueError('Expected the prepared 20-second Radiotap capture')
    return token


class StartFence:
    def __init__(self):
        self.consumed = False

    def start(self, line, callback):
        token = ready_event(line)
        if self.consumed:
            raise ValueError('Duplicate readiness event; never retry')
        self.consumed = True
        return token, callback()


class ReceiverBudget:
    """Use only coordinator receipt times; never map host/router clocks."""
    def __init__(self):
        self.token = None
        self.ready_at = None
        self.window_at = None
        self.remaining = None
        self.closed = False

    def ready(self, line, now):
        if self.token is not None:
            raise ValueError('Duplicate capture readiness')
        self.token = ready_event(line)
        self.ready_at = now

    def window(self, line, now):
        match = re.fullmatch(r'WINDOW ([a-f0-9]{32}) remaining_seconds=(\d+)', line)
        if not match or match.group(1) != self.token:
            raise ValueError('Wrong capture window token')
        remaining = int(match.group(2))
        if remaining > OBSERVATION_SECONDS or (self.remaining is not None and remaining > self.remaining):
            raise ValueError('Regressing capture countdown')
        self.remaining = remaining
        self.window_at = now

    def available(self, now):
        if (self.closed or self.window_at is None or self.ready_at is None or
                now - self.window_at > 1.6):
            return 0.0
        return max(0.0, min(OBSERVATION_SECONDS - (now - self.ready_at),
                            self.remaining - (now - self.window_at)) - 2.0)


def receiver_capture_args(python_executable, host, control_path, folder):
    """Pin the existing 6/149 AP topology and listen only on wlan1/ch149."""
    folder = Path(folder)
    return [python_executable, str(ROOT / 'tools/openwrt_capture_once.py'),
        '--host', host, '--control-path', control_path,
        '--ap', 'wlan0', '--ap', 'wlan1', '--interface', 'wlan1',
        '--monitor', 'iwawdl0',
        '--expect-ap', 'wlan0:0:6:2437:20',
        '--expect-ap', 'wlan1:1:149:5745:80',
        '--capture', '--duration', str(OBSERVATION_SECONDS),
        '--max-packets', str(MAX_CAPTURE_PACKETS),
        '--output', str(folder / 'receiver149-private.pcap')]


def _sysctl_boot_epoch():
    output = subprocess.check_output(['/usr/sbin/sysctl', '-n', 'kern.boottime'], text=True)
    match = re.search(r'sec = (\d+)', output)
    if not match:
        raise ValueError('Could not identify current boot epoch')
    return int(match.group(1))


def _claim_directory(account):
    return Path(account.pw_dir) / CLAIM_RELATIVE


def _legacy_claims(claim_dir, boot_epoch):
    parent = claim_dir.parent
    return [parent / ('Test0' + str(number)) / ('boot-' + str(boot_epoch) + '.json')
            for number in range(65, 83)]


def consume_boot_claim(claim_dir, boot_epoch, observation_id):
    """Atomically spend the shared boot claim; failed arm attempts never retry."""
    claim_dir = Path(claim_dir)
    if any(path.exists() or path.is_symlink() for path in _legacy_claims(claim_dir, boot_epoch)):
        raise FileExistsError('Same-boot legacy claim exists; no Test083 arm permitted')
    claim_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = claim_dir / ('boot-' + str(boot_epoch) + '.json')
    payload = {
        'schema': 1, 'test_scope': 'Test083', 'build': BUILD,
        'mode': PROFILE, 'boot_epoch': boot_epoch,
        'observation_id': observation_id, 'attempt_consumed': True,
        'helper_outcome': 'unknown', 'retry_allowed': False,
        'claimed_at': datetime.datetime.now().astimezone().isoformat(),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', closefd=False) as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return target


def _require_private_output(path, account):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refuse symlinked output directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not path.is_dir() or info.st_uid not in (0, account.pw_uid) or info.st_mode & 0o077:
        raise PermissionError('Output directory is not private')
    if info.st_uid == 0 and os.geteuid() == 0:
        os.chown(path, account.pw_uid, account.pw_gid)
    info = path.stat()
    if info.st_uid != account.pw_uid or info.st_mode & 0o077:
        raise PermissionError('Output directory owner/mode is unsafe')
    return path


def _save_private_json(path, value, account):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refuse symlinked report')
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    flags |= os.O_TRUNC if path.exists() else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', closefd=False) as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _load_metadata():
    if METADATA_PATH.is_symlink():
        raise ValueError('Test083 metadata is a symlink')
    return json.loads(METADATA_PATH.read_text())


def _native_preflight(metadata, boot_epoch):
    identity = loaded_identity(BUILD)
    identity_problems = test083_metadata_problems(
        metadata, boot_epoch=boot_epoch, identity=identity, root=ROOT)
    if identity_problems:
        raise ValueError('Test083 identity/source gate failed: ' + ','.join(identity_problems))
    wrapper = properties('IOPCIEDeviceWrapper')
    if wrapper.get('NativeTestBuild') != BUILD:
        raise ValueError('Loaded wrapper build does not match Test083')
    state = properties('AirportItlwm')
    profile_errors = profile_problems(state, selected=False)
    if profile_errors:
        raise ValueError('Test083 RX149 profile gate failed: ' + ','.join(profile_errors))
    if state.get('NativePowerReady') != 1:
        raise ValueError('Intel Wi-Fi power is not ready')
    for key in ('NativeP2PManualArmed', 'NativeP2PProbeAttempted',
                'NativeP2PProbeResourceMayExist'):
        if type(state.get(key)) is not int or state[key] != 0:
            raise ValueError('Test083 one-shot state is nonzero or unknown: ' + key)
    counters = {key: state.get(key) for key in TX_ZERO_COUNTERS}
    evidence = tx_zero_evidence(counters, counters)
    if not evidence['valid']:
        raise ValueError('Test083 pre-arm TX counters are nonzero or unknown')
    return identity, state, evidence


def _compile_arm_helper(temp_dir):
    output = Path(temp_dir) / 'arm-p2p-rx149'
    result = subprocess.run(['/usr/bin/swiftc', '-O', '-o', str(output),
                             str(HELPER_SOURCE)], capture_output=True, text=True,
                            timeout=20)
    if result.returncode != 0 or not output.is_file() or output.is_symlink():
        raise RuntimeError('Test083 helper compilation failed')
    os.chmod(output, 0o700)
    return output


def _wait_for_arm_gate(timeout=20):
    readable, _, _ = select.select([sys.stdin], [], [], timeout)
    if not readable:
        raise TimeoutError('Receiver gate timed out; do not retry this boot')
    command = os.read(sys.stdin.fileno(), 32)
    if command == b'ABORT\n':
        raise ValueError('Receiver gate aborted before arm')
    if command != b'ARM\n':
        raise ValueError('Unexpected receiver gate; do not retry this boot')


def _sample_after_arm(timeout=8.0):
    deadline = time.monotonic() + timeout
    samples = []
    trace_evidence = None
    trace_snapshots = None
    while time.monotonic() < deadline:
        sample = properties('AirportItlwm')
        samples.append(sample)
        terminal = (
            sample.get('NativeP2PRx149Selected') == 1 and
            sample.get('NativeP2PProbeAttempted') == 1 and
            sample.get('NativeP2PProbeState') == 7 and
            sample.get('NativeP2PProbeResourceMayExist') == 0 and
            sample.get('NativeP2PRocEndSeen') == 1 and
            sample.get('NativeP2PRxTraceProducerClosed') == 1)
        if terminal:
            pre = properties('AirportItlwm')
            time.sleep(0.03)
            middle = properties('AirportItlwm')
            time.sleep(0.03)
            post = properties('AirportItlwm')
            trace_snapshots = (pre, middle, post)
            trace_evidence = guarded_rx_trace_evidence(pre, middle, post)
            trace_coverage = rx_trace_snapshot_complete(trace_evidence, post)
            if trace_coverage and not roc_session_problems(post):
                samples.extend((pre, middle, post))
                break
        time.sleep(0.05)
    return samples, trace_evidence, trace_snapshots


def _native_worker(args):
    if not args.arm:
        raise SystemExit('Test083 is disarmed by default; no system state read or claim')
    if not args.receiver_gated or not args.router_observation_id:
        raise SystemExit('Test083 requires the receiver-gated coordinator; unchanged')
    if os.geteuid() != 0 or args.expect_build != BUILD or not args.phone_ready:
        raise SystemExit('Require root, Test083 and freshly confirmed phone; unchanged')
    if not fresh_observation_id(args.router_observation_id):
        raise SystemExit('Invalid Test083 observation id; unchanged')
    metadata = _load_metadata()
    if metadata.get('armed') is not True:
        raise SystemExit('Test083 metadata is disarmed; no boot claim or RF action')
    boot = _sysctl_boot_epoch()
    metadata_problems = test083_metadata_problems(metadata, boot_epoch=boot, root=ROOT)
    if metadata_problems:
        raise SystemExit('Test083 metadata gate failed; no boot claim; fields=' + ','.join(metadata_problems))
    identity, initial, initial_zero = _native_preflight(metadata, boot)
    account = pwd.getpwuid(ROOT.stat().st_uid)
    if not args.output:
        raise SystemExit('Missing private Test083 output directory; unchanged')
    folder = _require_private_output(args.output, account)
    report_path = folder / 'native-rx149-observation-private.json'
    if report_path.exists() or report_path.is_symlink():
        raise SystemExit('Test083 output already exists; no capture or retry')
    report = {
        'schema': 1, 'build': BUILD, 'boot_epoch': boot,
        'observation_id': args.router_observation_id,
        'profile': PROFILE, 'identity': identity,
        'collector_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'arm_attempted': False, 'retry_allowed': False,
        'rf_manual_only': True, 'diagnostic_duration_ms': 100,
        'receiver_gated': True, 'receiver_ready_before_arm': False,
        'efi_modified': False, 'ap_modified': False,
        'tx_zero_window': initial_zero,
        'rx149_initial': rx149_snapshot(initial),
        'peer_table_evidence': peer_evidence_delta(initial, initial),
        'attempt_state_initial': attempt_state_snapshot(initial),
        'prepare_trace_initial': prepare_trace_snapshot(initial),
        'prepare_trace_properties': None,
        'prepare_trace_interpretation': 'unknown_until_stable_revision_attempt_and_owner_are_verified',
        'rx149_after': None,
        'attempt_state_samples': [],
        'attempt_state_after': None,
        'roc_session_complete': False,
        'roc_session_problems': None,
        'session_complete': False,
        'rx_trace_evidence': None,
        'rx_trace_properties': None,
        'firmware_hcmd_rx_trace_pre_arm': None,
        'firmware_hcmd_rx_trace_post_arm': None,
        'firmware_hcmd_rx_trace_serial_delta': None,
        'channel149_rx_observed': None,
        'channel149_rx_observation_source': 'analyze closed driver RX trace/descriptor evidence and independent OpenWrt PCAP separately; PCAP alone does not prove driver receipt',
        'mif_decode_status': 'unknown_not_inferred_from_session_completion',
        'peer_table_acceptance': None,
        'host_management_or_data_tx_blocked': True,
        'host_management_or_data_tx_queue_created': None,
        'host_tx_queue_creation_independently_exposed': False,
        'mac_phy_session_protection_control_commands_may_occur': True,
        'radio_transmit_proven': False, 'peer_receipt_proven': False,
        'native_awdl_reply_proven': False, 'airdrop_proven': False,
        'scope': 'One receiver-gated 100 ms Test083 RX149 session. Closed driver RX trace/descriptor evidence and independent OpenWrt PCAP are separate evidence sources; neither alone proves peer identity, native awdl0 reply, or AirDrop.',
        'status': 'preflight_passed_waiting_for_receiver',
    }
    report['firmware_hcmd_rx_trace_pre_arm'] = _safe_hcmd_rx_trace_triplet()
    _save_private_json(report_path, report, account)
    with tempfile.TemporaryDirectory(prefix='intel-test083-', dir='/private/tmp') as temp_dir:
        helper = _compile_arm_helper(temp_dir)
        print('NATIVE-PREFLIGHT-READY', flush=True)
        _wait_for_arm_gate()
        # From this point every outcome consumes the shared boot claim and forbids
        # a second trigger. No fallback path exists.
        claim_dir = _claim_directory(account)
        claim_path = consume_boot_claim(claim_dir, boot, args.router_observation_id)
        report['boot_attempt_claim'] = str(claim_path)
        report['boot_attempt_consumed_before_arm'] = True
        report['receiver_ready_before_arm'] = True
        report['arm_attempted'] = True
        report['status'] = 'arm_outcome_pending'
        _save_private_json(report_path, report, account)
        try:
            result = subprocess.run([str(helper), '--expect-build', BUILD,
                '--expect-uuid', metadata['expected_loaded_uuid']],
                capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as error:
            report['status'] = 'arm_outcome_unknown_no_retry'
            report['outcome'] = 'incomplete_no_retry'
            report['helper_error_type'] = type(error).__name__
            report['firmware_hcmd_rx_trace_post_arm'] = _safe_hcmd_rx_trace_triplet()
            report['firmware_hcmd_rx_trace_serial_delta'] = firmware_trace_row_delta(
                report['firmware_hcmd_rx_trace_pre_arm'],
                report['firmware_hcmd_rx_trace_post_arm'])
            _save_private_json(report_path, report, account)
            print('NATIVE-ARM-RETURNED', flush=True)
            print(json.dumps({'complete': False, 'retry_allowed': False,
                              'host_management_or_data_tx_queue_created': None,
                              'host_tx_queue_creation_independently_exposed': False,
                              'mac_phy_session_protection_control_commands_may_occur': True,
                              'peer_receipt_proven': False, 'airdrop_proven': False}), flush=True)
            return 2
    report['arm_helper_exit'] = result.returncode
    try:
        helper_summary = json.loads(result.stdout.strip())
    except (ValueError, TypeError):
        helper_summary = None
    report['arm_helper_summary'] = helper_summary
    if result.returncode != 0 or not isinstance(helper_summary, dict) or \
            helper_summary.get('arm_property_accepted') is not True:
        report['status'] = 'arm_rejected_or_unknown_no_retry'
        report['outcome'] = 'incomplete_no_retry'
        report['firmware_hcmd_rx_trace_post_arm'] = _safe_hcmd_rx_trace_triplet()
        report['firmware_hcmd_rx_trace_serial_delta'] = firmware_trace_row_delta(
            report['firmware_hcmd_rx_trace_pre_arm'],
            report['firmware_hcmd_rx_trace_post_arm'])
        _save_private_json(report_path, report, account)
        print('NATIVE-ARM-RETURNED', flush=True)
        print(json.dumps({'complete': False, 'retry_allowed': False,
                          'host_management_or_data_tx_queue_created': None,
                          'host_tx_queue_creation_independently_exposed': False,
                          'mac_phy_session_protection_control_commands_may_occur': True,
                          'peer_receipt_proven': False, 'airdrop_proven': False}), flush=True)
        return 2
    report['helper_returned_monotonic_ns'] = time.monotonic_ns()
    print('NATIVE-ARM-RETURNED', flush=True)
    samples, rx_trace_evidence, rx_trace_snapshots = _sample_after_arm()
    report['firmware_hcmd_rx_trace_post_arm'] = _safe_hcmd_rx_trace_triplet()
    report['firmware_hcmd_rx_trace_serial_delta'] = firmware_trace_row_delta(
        report['firmware_hcmd_rx_trace_pre_arm'],
        report['firmware_hcmd_rx_trace_post_arm'])
    report['prepare_trace_properties'] = _read_prepare_trace_triplet()
    report['prepare_trace_evidence'] = prepare_trace_evidence(
        report['prepare_trace_properties'], metadata.get('prepare_trace_schema'))
    after = samples[-1] if samples else {}
    report['post_runtime_numeric'] = safe_runtime_snapshot(after)
    prepare = report['prepare_trace_evidence']
    report['prepare_diagnostic_summary'] = {
        key: prepare.get(key) for key in (
            'snapshot_valid', 'current_attempt_matches', 'attempt_serial', 'prepare_step',
            'prepare_reason', 'prepare_errno', 'cleanup_errno')}
    report['prepare_diagnostic_summary'].update(
        driver_recovery_attempted=after.get('NativeP2PProbeExerciseRecoveryAttempted'),
        driver_recovery_proof_accepted=after.get('NativeP2PProbeExerciseRecoveryProofAccepted'),
        exercise_result=after.get('NativeP2PProbeExerciseResult'),
        outer_mac_remove_result=after.get('NativeP2PProbeRemoveResult'),
        resource_may_exist=after.get('NativeP2PProbeResourceMayExist'),
        diagnostic_failure_is_not_rx_success=True)
    roc_problems = roc_session_problems(after)
    report['roc_session_complete'] = not roc_problems
    report['roc_session_problems'] = roc_problems
    report['rx_trace_evidence'] = rx_trace_evidence
    report['rx_trace_properties'] = ([safe_runtime_snapshot(item)
        for item in rx_trace_snapshots] if rx_trace_snapshots else None)
    trace_complete = bool(rx_trace_evidence and rx_trace_snapshots and
        rx_trace_snapshot_complete(rx_trace_evidence, rx_trace_snapshots[-1]))
    after_counters = {key: after.get(key) for key in TX_ZERO_COUNTERS}
    tx_samples = [{key: sample.get(key) for key in TX_ZERO_COUNTERS}
                  for sample in samples]
    report['rx149_samples'] = [rx149_observation_snapshot(sample)
                               for sample in samples]
    report['rx149_after'] = rx149_snapshot(after)
    report['peer_table_evidence'] = peer_evidence_delta(initial, after)
    report['attempt_state_samples'] = [attempt_state_snapshot(sample) for sample in samples]
    report['attempt_state_after'] = attempt_state_snapshot(after)
    selected_values = [sample.get('NativeP2PRx149Selected') for sample in samples]
    report['selected_after_arm'] = bool(selected_values and selected_values[-1] == 1)
    first_selected = next((index for index, value in enumerate(selected_values)
                           if value == 1), None)
    report['host_tx_blocked_after_arm'] = all(
        sample.get('NativeP2PRx149HostTxBlocked') == 1 for sample in samples)
    report['rx149_mode_lock_samples'] = [sample.get('NativeP2PManualArmed')
                                         for sample in samples]
    report['tx_zero_window'] = tx_zero_evidence(
        {key: initial.get(key) for key in TX_ZERO_COUNTERS}, after_counters,
        samples=tx_samples)
    profile_errors = []
    for sample in samples:
        profile_errors.extend(profile_problems(
            sample, selected=(sample.get('NativeP2PRx149Selected') == 1)))
    if not report['selected_after_arm']:
        profile_errors.append('NativeP2PRx149Selected_never_became_1')
    if first_selected is not None and any(value != 1 for value in selected_values[first_selected:]):
        profile_errors.append('NativeP2PRx149Selected_did_not_remain_selected')
    profile_errors.extend(rx149_mode_lock_problems(samples, after))
    profile_errors.extend(attempt_state_problems(after))
    profile_errors.extend(roc_problems)
    if not rx_trace_evidence or rx_trace_evidence.get('valid') is not True:
        profile_errors.append('rx_trace_snapshot_not_complete_or_owner_guard_failed')
    report['post_profile_problems'] = sorted(set(profile_errors))
    report['session_complete'] = bool(
        report['selected_after_arm'] and report['roc_session_complete'] and
        trace_complete and report['tx_zero_window']['valid'] and
        report['host_tx_blocked_after_arm'] and not report['post_profile_problems'])
    prepare_error = report['prepare_diagnostic_summary'].get('prepare_errno')
    report['prepare_rejection_captured'] = bool(
        prepare.get('snapshot_valid') is True and
        prepare.get('current_attempt_matches') is True and
        type(prepare_error) is int and prepare_error > 0 and
        after.get('NativeP2PRocStage') == 6 and
        after.get('NativeP2PRocResult') == prepare_error and
        after.get('NativeP2PProbeExerciseResult') == prepare_error and
        report['selected_after_arm'] and report['tx_zero_window']['valid'] and
        report['host_tx_blocked_after_arm'])
    report['status'] = ('rx149_session_complete_no_peer_claim' if
        report['session_complete'] else
        'prepare_rejected_diagnostic_captured_no_rx_claim' if report['prepare_rejection_captured']
        else 'measurement_incomplete_no_retry')
    report['outcome'] = 'single_arm_no_retry'
    report['radio_transmit_proven'] = False
    report['peer_receipt_proven'] = False
    report['native_awdl_reply_proven'] = False
    report['airdrop_proven'] = False
    _save_private_json(report_path, report, account)
    complete = report['session_complete']
    print(json.dumps({'complete': complete, 'session_complete': complete,
                      'status': report['status'],
                      'prepare_diagnostic': report['prepare_diagnostic_summary'],
                      'prepare_rejection_captured': report['prepare_rejection_captured'],
                      'retry_allowed': False,
                      'channel149_rx_observed': None,
                      'mif_decode_status': 'unknown_not_inferred_from_session_completion',
                      'peer_table_acceptance': None,
                      'host_management_or_data_tx_blocked': True,
                      'host_management_or_data_tx_queue_created': None,
                      'host_tx_queue_creation_independently_exposed': False,
                      'mac_phy_session_protection_control_commands_may_occur': True,
                      'radio_transmit_proven': False,
                      'peer_receipt_proven': False,
                      'native_awdl_reply_proven': False,
                      'airdrop_proven': False}), flush=True)
    return 0 if complete else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-build', default=BUILD)
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('--phone-ready', action='store_true')
    parser.add_argument('--receiver-gated', action='store_true')
    parser.add_argument('--router-observation-id')
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    if not args.arm:
        raise SystemExit('Test083 is disarmed by default; no system state read or claim')
    return _native_worker(args)


if __name__ == '__main__':
    raise SystemExit(main())
