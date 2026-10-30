#!/usr/bin/env python3
"""One fresh-boot, receiver-gated Test086 RX149-only observation.

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

from capture_test076_resident_data_once import (
    guarded_rx_entry_evidence, guarded_rx_trace_evidence,
    rx_entry_scalar_snapshot,
)
from probe_p2p_result import loaded_identity
from probe_wifi_rate import properties

ROOT = Path(__file__).resolve().parent
BUILD = '25G332-Test086'
BASELINE = '25G332-Test085'
PROFILE = 'native_awdl_rx149_data_input_only'
METADATA_PATH = ROOT / 'research/test086-next-boot-private.json'
BUILD_PATH = ROOT / 'research/test086-build-private.json'
BASELINE_BUILD_PATH = ROOT / 'research/test085-build-private.json'
HELPER_SOURCE = ROOT / 'arm_p2p_rx149_test086.swift'
CLAIM_RELATIVE = Path('Library/Application Support/IntelWirelessNative/ObservationClaims/BootGlobal')
REQUIRED_ENABLED_FLAGS = {
    'NativeP2PProbe': True,
    'NativeP2PManualTrigger': True,
    'NativeP2PRx149ObservationOnly': True,
    'NativeP2PRx149DataInputExperiment': True,
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
RX_ENTRY_PREFIX = 'NativeP2PRxEntry'
RX_ENTRY_EXTENSION_COUNTERS = (
    RX_ENTRY_PREFIX + 'CountChannel149',
    RX_ENTRY_PREFIX + 'CountChannel36',
    RX_ENTRY_PREFIX + 'CountMacIndex1Channel149',
    RX_ENTRY_PREFIX + 'CountExpectedMacPhy149',
)
AWDL_DATA_RX_COUNTERS = (
    'NativeAwdlDataRxCaptured',
    'NativeAwdlDataRxRejected',
    'NativeAwdlDataRxQueueFull',
    'NativeAwdlDataRxDecoded',
    'NativeAwdlDataRxDelivered',
    'NativeAwdlDataRxInputFailed',
)
AWDL_DATA_RX_GAUGES = ('NativeAwdlDataRxPending',)
AWDL_HOST_TX_COUNTERS = ('NativeAwdlDataTxSubmitted',)
AWDL_HOST_TX_GAUGES = ('NativeAwdlDataTxPending',)
AWDL_RX149_RECEIPT_PREFIX = 'NativeAwdlDataRx149Receipt'
AWDL_RX149_RECEIPT_FIELDS = (
    'SchemaVersion', 'SnapshotBegin', 'SnapshotEnd', 'ContentRevision',
    'Disposition', 'Sequence', 'OwnerSerial',
    'InterfaceIncarnation', 'ContextGeneration', 'PowerGeneration',
    'StationGeneration', 'RocGeneration', 'CaptureMonotonicUs',
    'InputMonotonicUs', 'DeadlineMonotonicUs', 'IeeeChannel',
    'MacIndexPresent', 'MacIndex', 'MacPhyDecodeMode', 'MpduLength',
    'OriginalRxStatus', 'DecodedIpv6Count', 'IfnetInputResultPresent',
    'IfnetInputResult',
)
AWDL_RX149_RECEIPT_U64_FIELDS = {
    'SnapshotBegin', 'SnapshotEnd', 'ContentRevision', 'Sequence',
    'OwnerSerial', 'InterfaceIncarnation', 'ContextGeneration',
    'PowerGeneration', 'StationGeneration', 'RocGeneration',
    'CaptureMonotonicUs', 'InputMonotonicUs', 'DeadlineMonotonicUs',
}
AWDL_DATA_RX_EPOCH_KEYS = (
    RX_ENTRY_PREFIX + 'ContextGeneration',
    RX_ENTRY_PREFIX + 'PowerGeneration',
    RX_ENTRY_PREFIX + 'StationGeneration',
    RX_ENTRY_PREFIX + 'RocGeneration',
)
RX_ENTRY_EXTENSION_WITNESS_PREFIXES = (
    RX_ENTRY_PREFIX + 'LastDescriptor',
    RX_ENTRY_PREFIX + 'LastTarget',
    RX_ENTRY_PREFIX + 'LastMacIndexTarget',
    RX_ENTRY_PREFIX + 'LastAwdlDataCandidate',
)
RX_ENTRY_EXTENSION_WITNESS_FIELDS = (
    'Present', 'ContextGeneration', 'PowerGeneration', 'StationGeneration',
    'RocGeneration', 'PayloadLength', 'DmaCapacity', 'DescriptorSize',
    'Version', 'MpduLength', 'StatusPresent', 'Status',
    'MacPhyIndexPresent', 'MacPhyIndex', 'FilterMatchPresent', 'FilterMatch',
    'RpaEnabled', 'ChannelPresent', 'Channel', 'FrameControlPresent',
    'FrameControl', 'FrameType', 'FrameSubtype', 'ToDs', 'FromDs',
    'AwdlBssidCandidate',
    'MacContextPresent', 'MacContextRaw', 'MacIndexPresent', 'MacIndex',
    'PhyIndexPresent', 'PhyIndex', 'MacPhyIndexDecodeModePresent',
    'MacPhyIndexDecodeMode',
    'HostRxMonotonicUsPresent', 'HostRxMonotonicUs',
    'Gp2OnAirRisePresent', 'Gp2OnAirRiseRaw',
    'TsfOnAirRisePresent', 'TsfOnAirRiseRaw', 'TsfValidPresent', 'TsfValid',
    'RxRingPresent', 'RxRing', 'RxRingSlotPresent', 'RxRingSlot',
    'TransportNotificationQidPresent', 'TransportNotificationQid',
    'TransportNotificationIndexPresent', 'TransportNotificationIndex',
)
RX_ENTRY_EXTENSION_WITNESS_KEYS = tuple(
    prefix + field for prefix in RX_ENTRY_EXTENSION_WITNESS_PREFIXES
    for field in RX_ENTRY_EXTENSION_WITNESS_FIELDS)
RX_ENTRY_EXTENSION_KEYS = RX_ENTRY_EXTENSION_COUNTERS + RX_ENTRY_EXTENSION_WITNESS_KEYS
RX_ENTRY_V2_DESCRIPTOR_ONLY_FIELDS = (
    'MacContextPresent', 'MacContextRaw', 'MacIndexPresent', 'MacIndex',
    'PhyIndexPresent', 'PhyIndex', 'MacPhyIndexDecodeModePresent',
    'MacPhyIndexDecodeMode',
    'HostRxMonotonicUsPresent', 'HostRxMonotonicUs',
    'Gp2OnAirRisePresent', 'Gp2OnAirRiseRaw',
    'TsfOnAirRisePresent', 'TsfOnAirRiseRaw', 'TsfValidPresent', 'TsfValid',
    'RxRingPresent', 'RxRing', 'RxRingSlotPresent', 'RxRingSlot',
    'TransportNotificationQidPresent', 'TransportNotificationQid',
    'TransportNotificationIndexPresent', 'TransportNotificationIndex',
)
RX_ENTRY_SCHEMA2_ONLY_KEYS = (
    RX_ENTRY_EXTENSION_COUNTERS +
    tuple(RX_ENTRY_EXTENSION_WITNESS_PREFIXES[0] + field
          for field in RX_ENTRY_V2_DESCRIPTOR_ONLY_FIELDS) +
    tuple(RX_ENTRY_EXTENSION_WITNESS_PREFIXES[1] + field
          for field in RX_ENTRY_EXTENSION_WITNESS_FIELDS) +
    tuple(RX_ENTRY_EXTENSION_WITNESS_PREFIXES[2] + field
          for field in RX_ENTRY_EXTENSION_WITNESS_FIELDS) +
    tuple(RX_ENTRY_EXTENSION_WITNESS_PREFIXES[3] + field
          for field in RX_ENTRY_V2_DESCRIPTOR_ONLY_FIELDS)
)
RX_ENTRY_U64_KEYS = {
    prefix + suffix
    for prefix in RX_ENTRY_EXTENSION_WITNESS_PREFIXES
    for suffix in ('HostRxMonotonicUs', 'TsfOnAirRiseRaw')
}
RX_ENTRY_PRESENCE_VALUE_PAIRS = (
    ('MacContextPresent', 'MacContextRaw'),
    ('MacIndexPresent', 'MacIndex'),
    ('PhyIndexPresent', 'PhyIndex'),
    ('MacPhyIndexDecodeModePresent', 'MacPhyIndexDecodeMode'),
    ('HostRxMonotonicUsPresent', 'HostRxMonotonicUs'),
    ('Gp2OnAirRisePresent', 'Gp2OnAirRiseRaw'),
    ('TsfOnAirRisePresent', 'TsfOnAirRiseRaw'),
    ('TsfValidPresent', 'TsfValid'),
    ('RxRingPresent', 'RxRing'),
    ('RxRingSlotPresent', 'RxRingSlot'),
    ('TransportNotificationQidPresent', 'TransportNotificationQid'),
    ('TransportNotificationIndexPresent', 'TransportNotificationIndex'),
)
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


def test086_metadata_problems(metadata, boot_epoch=None, identity=None, root=ROOT):
    """Validate the frozen Test086 identity/profile contract without side effects."""
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
    contract = metadata.get('rx149_data_input_contract')
    if (not isinstance(contract, dict) or contract.get('version') != 1 or
            contract.get('source_header') != 'native/p2p_rx149_data_input.hpp' or
            not _is_sha256(contract.get('source_header_sha256')) or
            contract.get('compile_macro') != 'ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332' or
            contract.get('artifact_enabled') is not True or
            contract.get('host_management_or_data_tx_allowed') is not False or
            contract.get('session_duration_ms') != 100 or
            contract.get('channel') != 149):
        problems.append('rx149_data_input_contract')
    if (isinstance(contract, dict) and isinstance(metadata.get('source_sha256'), dict) and
            metadata['source_sha256'].get(contract.get('source_header')) !=
            contract.get('source_header_sha256')):
        problems.append('rx149_data_input_source_hash')
    expected_uuid = metadata.get('expected_loaded_uuid')
    if (not isinstance(expected_uuid, str) or
            re.fullmatch(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',
                         expected_uuid) is None):
        problems.append('expected_loaded_uuid')
    baseline_uuid = metadata.get('baseline_mach_o_uuid')
    if (not isinstance(baseline_uuid, str) or
            re.fullmatch(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',
                         baseline_uuid) is None):
        problems.append('baseline_mach_o_uuid')
    elif baseline_uuid == expected_uuid:
        problems.append('candidate_uuid_reused_baseline')
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
    rx_schema = metadata.get('rx_entry_schema')
    required_rx_counters = {
        'AwdlBssidCandidate', 'Channel149', 'Channel36',
        'MacIndex1Channel149', 'ExpectedMacPhy149'}
    required_rx_witness_fields = {
        'macContextPresent', 'macContext', 'macIndexPresent', 'macIndex',
        'phyIndexPresent', 'phyIndex', 'macPhyIndexDecodeModePresent',
        'macPhyIndexDecodeMode', 'hostRxMonotonicUsPresent', 'hostRxMonotonicUs',
        'gp2OnAirRisePresent', 'gp2OnAirRiseRaw', 'tsfOnAirRisePresent',
        'tsfOnAirRiseRaw', 'tsfValidPresent', 'tsfValid', 'rxRingPresent',
        'rxRing', 'rxRingSlotPresent', 'rxRingSlot',
        'transportNotificationQidPresent', 'transportNotificationQid',
        'transportNotificationIndexPresent', 'transportNotificationIndex',
        'channelPresent', 'channel', 'frameControlPresent', 'frameControl',
        'frameType', 'frameSubtype', 'toDs', 'fromDs', 'awdlBssidCandidate',
    }
    if (not isinstance(rx_schema, dict) or rx_schema.get('version') != 2 or
            rx_schema.get('source_header') != 'native/awdl_rx_entry_telemetry.hpp' or
            not _is_sha256(rx_schema.get('source_header_sha256')) or
            source_hashes.get(rx_schema.get('source_header')) !=
            rx_schema.get('source_header_sha256') or
            not isinstance(rx_schema.get('counters'), list) or
            not required_rx_counters.issubset(rx_schema['counters']) or
            len(rx_schema['counters']) != len(set(rx_schema['counters'])) or
            not isinstance(rx_schema.get('witness_fields'), list) or
            not required_rx_witness_fields.issubset(rx_schema['witness_fields']) or
            len(rx_schema['witness_fields']) != len(set(rx_schema['witness_fields'])) or
            not isinstance(rx_schema.get('dispatch_fields'), list) or
            not isinstance(rx_schema.get('snapshot_witnesses'), list) or
            not {'lastDescriptor', 'lastTarget', 'lastMacIndexTarget',
                 'lastAwdlDataCandidate'}.issubset(
                rx_schema['snapshot_witnesses'])):
        problems.append('rx_entry_schema')
    validation_hashes = metadata.get('validation_source_sha256')
    if (not isinstance(validation_hashes, dict) or not validation_hashes or
            any(not isinstance(name, str) or not isinstance(digest, str) or
                not _is_sha256(digest) or Path(name).is_absolute() or
                '..' in Path(name).parts for name, digest in validation_hashes.items())):
        problems.append('validation_source_sha256')
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
                raise ValueError('symlinked Test086 build report')
            build = json.loads(BUILD_PATH.read_text())
            if BASELINE_BUILD_PATH.is_symlink():
                raise ValueError('symlinked Test085 build report')
            baseline = json.loads(BASELINE_BUILD_PATH.read_text())
            if (build.get('candidate') != BUILD or
                    build.get('baseline') != BASELINE or
                    build.get('status') != 'built_offline' or
                    build.get('source_freeze_matches') is not True or
                    build.get('binary_sha256') != metadata.get('expected_binary_sha256') or
                    build.get('info_plist_sha256') != metadata.get('expected_info_plist_sha256') or
                    build.get('arm_helper_source_sha256') != metadata.get('expected_arm_helper_source_sha256') or
                    build.get('prepare_trace_schema') != trace_schema or
                    build.get('rx_entry_schema') != rx_schema or
                    build.get('rx149_data_input_contract') != contract or
                    build.get('mach_o_uuid') != expected_uuid or
                    build.get('source_file_count') != len(source_hashes or {}) or
                    build.get('source_sha256') != source_hashes or
                    build.get('validation_source_sha256') != validation_hashes or
                    build.get('full_build_passed') is not True or
                    build.get('strict_signature_passed') is not True or
                    build.get('baseline_build_report') != str(BASELINE_BUILD_PATH) or
                    build.get('baseline_build_report_sha256') != hashlib.sha256(
                        BASELINE_BUILD_PATH.read_bytes()).hexdigest() or
                    build.get('baseline_mach_o_uuid') != baseline_uuid or
                    build.get('baseline_test085_source_sha256') != baseline.get('source_sha256') or
                    baseline.get('candidate') != BASELINE or
                    baseline.get('status') != 'built_offline' or
                    baseline.get('source_sha256') != metadata.get('baseline_source_sha256') or
                    baseline.get('mach_o_uuid') != baseline_uuid or
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
        'NativeP2PRx149DataInputProfileEnabled': 1,
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


def awdl_data_candidate_descriptor_evidence(extension, entry, roc_values):
    """Check the owner-guarded schema-2 data-candidate count and witness."""
    prefix = RX_ENTRY_PREFIX + 'LastAwdlDataCandidate'
    count_key = RX_ENTRY_PREFIX + 'CountAwdlBssidCandidate'
    values = extension.get('values', {})
    base_values = entry.get('values', {}) if isinstance(entry, dict) else {}
    required = tuple(prefix + suffix for suffix in (
        'Present', 'ContextGeneration', 'PowerGeneration', 'StationGeneration',
        'RocGeneration', 'HostRxMonotonicUsPresent', 'HostRxMonotonicUs',
        'ChannelPresent', 'Channel', 'FrameControlPresent', 'FrameType',
        'FrameSubtype', 'ToDs', 'FromDs', 'AwdlBssidCandidate'))
    missing = [key for key in required if key not in values]
    if count_key not in base_values:
        missing.append(count_key)
    errors = []
    count = base_values.get(count_key)
    present = values.get(prefix + 'Present')
    status = 'unknown_candidate_witness'
    if missing:
        errors.append('candidate_alias_missing')
    elif present == 0:
        if count != 0:
            errors.append('candidate_count_without_candidate_witness')
            status = 'invalid_candidate_witness'
        else:
            status = 'complete_no_descriptor_candidate'
    elif present == 1:
        expected_epochs = {
            'ContextGeneration': roc_values.get('NativeP2PProbeContextGeneration'),
            'PowerGeneration': roc_values.get('NativeP2PProbePowerGeneration'),
            'StationGeneration': roc_values.get('NativeP2PProbeStationGeneration'),
            'RocGeneration': roc_values.get('NativeP2PRocGeneration'),
        }
        for suffix, expected in expected_epochs.items():
            actual = values.get(prefix + suffix)
            if type(expected) is not int or actual != expected:
                errors.append('candidate_' + suffix + '_owner_mismatch')
        if count < 1:
            errors.append('candidate_witness_without_candidate_count')
        if (values.get(prefix + 'HostRxMonotonicUsPresent') != 1 or
                values.get(prefix + 'HostRxMonotonicUs', 0) <= 0):
            errors.append('candidate_host_rx_time_missing')
        if (values.get(prefix + 'ChannelPresent') != 1 or
                values.get(prefix + 'Channel') != 149):
            errors.append('candidate_channel_not_149')
        if (values.get(prefix + 'FrameControlPresent') != 1 or
                values.get(prefix + 'FrameType') != 2 or
                values.get(prefix + 'FrameSubtype') not in (0, 8) or
                values.get(prefix + 'ToDs') != 0 or
                values.get(prefix + 'FromDs') != 0 or
                values.get(prefix + 'AwdlBssidCandidate') != 1):
            errors.append('candidate_not_unicast_eligible_data_frame_shape')
        status = ('owner_bound_data_descriptor_candidate' if not errors
                  else 'invalid_candidate_witness')
    else:
        errors.append('candidate_present_flag_invalid')
        status = 'invalid_candidate_witness'
    return {
        'valid': not errors,
        'status': status,
        'descriptor_candidate_count': count,
        'matched_roc_owner': present == 1 and not errors,
        'candidate_snapshot': {
            'schema_present': RX_ENTRY_PREFIX + 'Schema' in base_values,
            'schema': base_values.get(RX_ENTRY_PREFIX + 'Schema'),
            'version_begin_present': RX_ENTRY_PREFIX + 'SnapshotBegin' in base_values,
            'version_begin': base_values.get(RX_ENTRY_PREFIX + 'SnapshotBegin'),
            'version_end_present': RX_ENTRY_PREFIX + 'SnapshotEnd' in base_values,
            'version_end': base_values.get(RX_ENTRY_PREFIX + 'SnapshotEnd'),
            'stable_complete_snapshot': (
                entry.get('stable_complete_snapshot') is True
                if isinstance(entry, dict) else False),
            'epochs': {RX_ENTRY_PREFIX + key: base_values.get(
                RX_ENTRY_PREFIX + key) for key in (
                    'ContextGeneration', 'PowerGeneration',
                    'StationGeneration', 'RocGeneration')},
        },
        'candidate_witness_epochs': {
            suffix: values.get(prefix + suffix) for suffix in (
                'ContextGeneration', 'PowerGeneration', 'StationGeneration',
                'RocGeneration')},
        'witness': {key: values.get(key) for key in required if key in values},
        'errors': sorted(set(errors)),
        'count_zero_proves_rf_absence': False,
        'phy_index_inferred': False,
    }


def rx_entry_observation_evidence(samples, roc_values):
    """Validate stable Test086 v2 RX telemetry without turning counts into RF claims.

    The frozen v1 counters/witnesses retain their original three-read guard.
    Schema 2 is mandatory for Test086. New per-alias extension fields are
    checked when published; an alias missing from every read remains unknown,
    while a changing or malformed published alias invalidates the extension.
    """
    scalar_samples = [rx086_entry_scalar_snapshot(sample) for sample in samples]
    schema_values = [sample.get(RX_ENTRY_PREFIX + 'Schema') for sample in samples]
    schema2 = (len(schema_values) == 3 and
               all(type(value) is int and value == 2 for value in schema_values))
    # Reuse the established v1 guard for every retained v1 field. Its only
    # version-specific rule is v1 itself; check the actual v2 schema above.
    base_samples = []
    for sample in scalar_samples:
        base = {key: value for key, value in sample.items()
                if key not in RX_ENTRY_SCHEMA2_ONLY_KEYS}
        if RX_ENTRY_PREFIX + 'Schema' in base:
            base[RX_ENTRY_PREFIX + 'Schema'] = 1
        base_samples.append(base)
    entry = (guarded_rx_entry_evidence(*base_samples)
             if len(base_samples) == 3 else None)
    extension = rx_entry_extension_evidence(scalar_samples)
    roc_problems = roc_session_problems(roc_values)
    candidate_evidence = awdl_data_candidate_descriptor_evidence(
        extension, entry, roc_values)
    discov_configuration = roc_values.get('NativeP2PRocConfiguration') == 2
    schema_problems = [] if schema2 else ['schema_v2_missing_or_unstable']
    extension_problems = extension['problems']
    return {
        'valid': bool(entry and entry.get('valid') is True and schema2 and
                      discov_configuration and not roc_problems and
                      extension['valid'] is not False and candidate_evidence['valid']),
        'entry_snapshot_valid': bool(entry and entry.get('valid') is True),
        'schema_v2': schema2,
        'schema_problems': schema_problems,
        'extension_evidence': extension,
        'data_candidate_evidence': candidate_evidence,
        'strict_channel149_count': extension['values'].get(
            RX_ENTRY_PREFIX + 'CountChannel149'),
        'strict_mac_index1_channel149_count': extension['values'].get(
            RX_ENTRY_PREFIX + 'CountMacIndex1Channel149'),
        'strict_expected_mac_phy149_count': extension['values'].get(
            RX_ENTRY_PREFIX + 'CountExpectedMacPhy149'),
        'last_target_status': extension.get('last_target_status'),
        'last_mac_index_target_status': extension.get(
            'last_mac_index_target_status'),
        'strict_channel36_count': extension['values'].get(
            RX_ENTRY_PREFIX + 'CountChannel36'),
        'strict_awdl_bssid_candidate_count': extension['values'].get(
            RX_ENTRY_PREFIX + 'CountAwdlBssidCandidate') if RX_ENTRY_PREFIX +
            'CountAwdlBssidCandidate' in extension['values'] else
            (entry.get('values', {}).get(RX_ENTRY_PREFIX +
                'CountAwdlBssidCandidate') if isinstance(entry, dict) else None),
        'strict_count_zero_is_rf_absence': False,
        'roc_session_complete': not roc_problems,
        'discovery_configuration_2': discov_configuration,
        'roc_session_problems': roc_problems,
        'extension_problems': extension_problems,
        'entry_evidence': entry,
        'channel149_rx_observed': None,
        'peer_receipt_proven': False,
        'airdrop_proven': False,
        'zero_counters_interpreted_as_rf_silence': False,
        'raw_mac_context_interpreted_as_index': False,
        'transport_notification_qid_used_as_rx_ring': False,
        'gp2_and_tsf_combined_or_converted': False,
        'scope': 'Stable closed schema-2 RX-entry telemetry bound to successful channel-149 DISCOV ROC. The address-free data-candidate witness is checked against ROC owner epochs, but is not paired with a later AWDL queue receipt. Descriptor-reported channel counts and target-index witness remain instrumentation only; raw MAC context is uninterpreted, RX ring slot is distinct from transport notification QID/index, GP2 and TSF remain separate clocks, and zero counters prove neither RF silence nor peer absence.',
    }


def rx086_entry_scalar_snapshot(sample):
    """Whitelist v1 plus Test086 v2 RX entry numeric properties only."""
    snapshot = rx_entry_scalar_snapshot(sample)
    for key in RX_ENTRY_EXTENSION_KEYS:
        if key in sample:
            value = sample[key]
            snapshot[key] = value if type(value) is int else {
                'invalid_type': type(value).__name__}
    schema_key = RX_ENTRY_PREFIX + 'Schema'
    if schema_key in sample:
        value = sample[schema_key]
        snapshot[schema_key] = value if type(value) is int else {
            'invalid_type': type(value).__name__}
    return snapshot


def awdl_data_rx_snapshot(sample):
    """Keep numeric receive-path counters and their presence/epoch context.

    Data counters are cumulative driver values without a published snapshot
    version or owner epoch. The current RX-entry epoch is recorded separately;
    it is not retroactively assigned to those lifetime counters.
    """
    counters = {}
    missing = []
    invalid = []
    for key in AWDL_DATA_RX_COUNTERS + AWDL_DATA_RX_GAUGES:
        if key not in sample:
            counters[key] = None
            missing.append(key)
            continue
        value = sample[key]
        if type(value) is not int or not 0 <= value <= 0xffffffffffffffff:
            counters[key] = None
            invalid.append(key)
            continue
        counters[key] = value

    host_tx = {}
    host_tx_presence = {}
    host_tx_missing = []
    host_tx_invalid = []
    for key in AWDL_HOST_TX_COUNTERS + AWDL_HOST_TX_GAUGES:
        host_tx_presence[key] = key in sample
        if key not in sample:
            host_tx[key] = None
            host_tx_missing.append(key)
        elif type(sample[key]) is not int or not 0 <= sample[key] <= 0xffffffffffffffff:
            host_tx[key] = None
            host_tx_invalid.append(key)
        else:
            host_tx[key] = sample[key]

    epochs = {}
    epoch_missing = []
    epoch_invalid = []
    for key in AWDL_DATA_RX_EPOCH_KEYS:
        if key not in sample:
            epochs[key] = None
            epoch_missing.append(key)
        elif type(sample[key]) is not int or not 0 <= sample[key] <= 0xffffffff:
            epochs[key] = None
            epoch_invalid.append(key)
        else:
            epochs[key] = sample[key]

    candidate_prefix = RX_ENTRY_PREFIX + 'LastAwdlDataCandidate'
    candidate = {}
    candidate_fields = ('Present', 'ContextGeneration', 'PowerGeneration',
                        'StationGeneration', 'RocGeneration', 'HostRxMonotonicUs',
                        'ChannelPresent', 'Channel', 'FrameType', 'FrameSubtype',
                        'AwdlBssidCandidate')
    for suffix in candidate_fields:
        key = candidate_prefix + suffix
        value = sample.get(key)
        candidate[key] = (value if type(value) is int and
                          0 <= value <= 0xffffffffffffffff else None)
    candidate['snapshot_stable_guard'] = (
        candidate[candidate_prefix + 'Present'] is not None and
        candidate[candidate_prefix + 'ContextGeneration'] is not None and
        candidate[candidate_prefix + 'PowerGeneration'] is not None and
        candidate[candidate_prefix + 'StationGeneration'] is not None and
        candidate[candidate_prefix + 'RocGeneration'] is not None and
        candidate[candidate_prefix + 'HostRxMonotonicUs'] is not None and
        type(sample.get('NativeP2PRxEntrySnapshotBegin')) is int and
        sample.get('NativeP2PRxEntrySnapshotBegin') ==
        sample.get('NativeP2PRxEntrySnapshotEnd') and
        sample.get('NativeP2PRxEntrySchema') == 2)
    candidate_count_key = RX_ENTRY_PREFIX + 'CountAwdlBssidCandidate'
    candidate_count = sample.get(candidate_count_key)
    candidate_count_valid = (type(candidate_count) is int and
                             0 <= candidate_count <= 0xffffffffffffffff)

    entry_version_begin = sample.get('NativeP2PRxEntrySnapshotBegin')
    entry_version_end = sample.get('NativeP2PRxEntrySnapshotEnd')
    entry_schema = sample.get('NativeP2PRxEntrySchema')

    return {
        'counters': counters,
        'counter_presence': {key: key in sample for key in counters},
        'counter_missing': missing,
        'counter_invalid': invalid,
        'host_tx': host_tx,
        'host_tx_presence': host_tx_presence,
        'host_tx_missing': host_tx_missing,
        'host_tx_invalid': host_tx_invalid,
        'snapshot_version': None,
        'snapshot_version_status': 'not_published_for_native_awdl_data_rx_counters',
        'rx_entry_snapshot_version': {
            'begin_present': 'NativeP2PRxEntrySnapshotBegin' in sample,
            'begin': entry_version_begin if type(entry_version_begin) is int else None,
            'end_present': 'NativeP2PRxEntrySnapshotEnd' in sample,
            'end': entry_version_end if type(entry_version_end) is int else None,
            'schema_present': 'NativeP2PRxEntrySchema' in sample,
            'schema': entry_schema if type(entry_schema) is int else None,
        },
        'data_counter_owner_epoch': None,
        'data_counter_owner_epoch_status': 'not_published; current RX-entry epochs are separate',
        'rx_entry_epochs': epochs,
        'rx_entry_epoch_missing': epoch_missing,
        'rx_entry_epoch_invalid': epoch_invalid,
        'last_awdl_data_candidate_witness': candidate,
        'descriptor_candidate_count_present': candidate_count_key in sample,
        'descriptor_candidate_count': candidate_count if candidate_count_valid else None,
        'descriptor_candidate_count_valid': candidate_count_valid,
        'descriptor_candidate_snapshot_stable': candidate['snapshot_stable_guard'],
        'host_tx_blocked_flag': sample.get('NativeP2PRx149HostTxBlocked')
            if type(sample.get('NativeP2PRx149HostTxBlocked')) is int else None,
        'lifetime_counter_values_are_not_frame_timestamps': True,
        'ifnet_delivery_semantics': (
            'NativeAwdlDataRxDelivered increments only when ifnet_input returns 0; '
            'this is KPI acceptance, not peer/socket/application/AirDrop receipt.'),
        'complete': (not missing and not invalid and not host_tx_missing and
                     not host_tx_invalid and not epoch_missing and not epoch_invalid),
    }


def awdl_data_rx149_receipt_snapshot(sample):
    """Parse only the address-free numeric latest-MPDU receive receipt."""
    values = {}
    presence = {}
    missing = []
    invalid = []
    errors = []
    for suffix in AWDL_RX149_RECEIPT_FIELDS:
        key = AWDL_RX149_RECEIPT_PREFIX + suffix
        presence[key] = key in sample
        if key not in sample:
            values[suffix] = None
            missing.append(key)
            continue
        value = sample[key]
        if suffix == 'IfnetInputResult':
            good = type(value) is int and -(1 << 31) <= value <= 0xffffffff
            if good and value >= (1 << 31):
                value -= 1 << 32
        else:
            width = 64 if suffix in AWDL_RX149_RECEIPT_U64_FIELDS else 32
            good = type(value) is int and 0 <= value < (1 << width)
        if not good:
            values[suffix] = None
            invalid.append(key)
        else:
            values[suffix] = value

    complete = not missing and not invalid
    publication_seqlock_valid = bool(
        complete and values['SchemaVersion'] == 2 and
        values['SnapshotBegin'] > 0 and values['SnapshotBegin'] == values['SnapshotEnd'] and
        values['SnapshotBegin'] % 2 == 0)
    input_time_semantics = (
        'InputMonotonicUs is the lock-linearized input admission/ticket time '
        'immediately before the KPI call; it is not KPI completion or return time.')
    if complete:
        if values['SchemaVersion'] != 2:
            errors.append('unknown_schema_version')
        if values['SnapshotBegin'] == 0 or values['SnapshotEnd'] == 0:
            errors.append('publication_snapshot_version_zero')
        if values['SnapshotBegin'] & 1 or values['SnapshotEnd'] & 1:
            errors.append('publication_snapshot_version_odd')
        if values['SnapshotBegin'] != values['SnapshotEnd']:
            errors.append('publication_snapshot_version_mismatch')
        if values['Disposition'] not in range(9):
            errors.append('unknown_disposition')
        if values['Sequence'] == 0:
            if values['Disposition'] != 0:
                errors.append('zero_sequence_with_nonempty_disposition')
            if values['ContentRevision'] != 0:
                errors.append('zero_sequence_with_nonzero_content_revision')
        else:
            if values['ContentRevision'] == 0:
                errors.append('content_revision_zero_for_receipt')
            for name in ('OwnerSerial', 'InterfaceIncarnation', 'ContextGeneration',
                         'PowerGeneration', 'StationGeneration', 'RocGeneration',
                         'CaptureMonotonicUs', 'DeadlineMonotonicUs'):
                if values[name] == 0:
                    errors.append(name + '_zero_for_receipt')
            if values['DeadlineMonotonicUs'] <= values['CaptureMonotonicUs']:
                errors.append('deadline_not_after_capture')
            if values['InputMonotonicUs'] and values['InputMonotonicUs'] < values['CaptureMonotonicUs']:
                errors.append('input_time_precedes_capture')
            if values['Disposition'] in (6, 7):
                if values['IfnetInputResultPresent'] != 1 or values['InputMonotonicUs'] == 0:
                    errors.append('ifnet_result_or_admission_time_missing_for_input_disposition')
                elif values['InputMonotonicUs'] >= values['DeadlineMonotonicUs']:
                    errors.append('ifnet_input_admission_not_before_lease_deadline')
                if values['Disposition'] == 6 and values['IfnetInputResult'] != 0:
                    errors.append('success_disposition_without_zero_ifnet_result')
                if values['Disposition'] == 7 and values['IfnetInputResult'] == 0:
                    errors.append('failure_disposition_with_zero_ifnet_result')
            elif values['IfnetInputResultPresent'] not in (0, 1):
                errors.append('ifnet_result_presence_invalid')

    sequence = values.get('Sequence')
    disposition = values.get('Disposition')
    unpublished = bool(not complete and
                       len(missing) == len(AWDL_RX149_RECEIPT_FIELDS) and
                       not invalid)
    return {
        'values': values,
        'presence': presence,
        'missing': missing,
        'invalid': invalid,
        'errors': sorted(set(errors)),
        'complete': complete,
        'valid': complete and not errors,
        'publication_seqlock_valid': publication_seqlock_valid,
        'status': ('not_published_yet' if unpublished else
                   'no_receipt' if complete and sequence == 0 and not errors else
                   'receipt_observed' if complete and sequence and not errors else
                   'unknown_or_invalid'),
        'receipt_observed': bool(
            complete and not errors and type(sequence) is int and sequence > 0),
        'local_ifnet_input_kpi_accepted': bool(
            complete and not errors and disposition == 6 and
            values.get('IfnetInputResultPresent') == 1 and
            values.get('IfnetInputResult') == 0),
        'input_time_semantics': input_time_semantics,
        'input_time_proves_completion_before_deadline': False,
        'sequence_is_mpdu_identity_not_publication_version': True,
        'content_revision_is_publication_content_version': True,
        'snapshot_begin_end_are_publication_seqlock_markers': True,
        'raw_payload_or_addresses_saved': False,
        'peer_or_socket_receipt_proven': False,
        'airdrop_proven': False,
    }


def receipt_preflight_problem(snapshot):
    """Allow only a wholly unpublished first receipt; malformed publication blocks arm."""
    if snapshot.get('valid') is True:
        return None
    if (snapshot.get('status') == 'not_published_yet' and
            len(snapshot.get('missing', [])) == len(AWDL_RX149_RECEIPT_FIELDS) and
            not snapshot.get('invalid')):
        return None
    return 'Test086 numeric RX receipt is partially published or invalid before claim'


def awdl_data_rx149_receipt_triplet_evidence(samples, roc_values):
    """Require three identical stable v2 publications and bind owner epochs."""
    if len(samples) != 3:
        return {'valid': False, 'status': 'three_snapshots_required',
                'samples': [], 'problems': ['three_snapshots_required'],
                'peer_or_socket_receipt_proven': False, 'airdrop_proven': False}
    snapshots = [awdl_data_rx149_receipt_snapshot(sample) for sample in samples]
    problems = []
    if any(not item['valid'] for item in snapshots):
        problems.append('receipt_missing_invalid_or_unknown_schema')
    for suffix in AWDL_RX149_RECEIPT_FIELDS:
        values = [item['values'].get(suffix) for item in snapshots]
        if any(value is None for value in values):
            continue
        if len(set(values)) != 1:
            problems.append(suffix + ':changed_between_reads')
    final = snapshots[-1]
    fields = final['values']
    if final['receipt_observed']:
        owner_pairs = (
            ('ContextGeneration', 'NativeP2PProbeContextGeneration'),
            ('PowerGeneration', 'NativeP2PProbePowerGeneration'),
            ('StationGeneration', 'NativeP2PProbeStationGeneration'),
            ('RocGeneration', 'NativeP2PRocGeneration'),
            ('OwnerSerial', 'NativeP2PRxTraceOwnerSerial'),
        )
        final_sample = samples[-1]
        for receipt_key, runtime_key in owner_pairs:
            if type(final_sample.get(runtime_key)) is not int:
                problems.append(runtime_key + '_missing_for_receipt_binding')
            elif fields[receipt_key] != final_sample[runtime_key]:
                problems.append(receipt_key + '_does_not_match_runtime_owner')
        if fields['IeeeChannel'] != 149:
            problems.append('receipt_channel_not_149')
        if fields['MacIndexPresent'] == 1 and fields['MacIndex'] != 1:
            problems.append('receipt_mac_index_not_1')
        if (fields['MacIndexPresent'] not in (0, 1) or
                fields['IfnetInputResultPresent'] not in (0, 1)):
            problems.append('receipt_presence_flag_invalid')
    return {
        'valid': not problems,
        'status': 'stable_numeric_receipt' if not problems else 'incomplete_or_unstable',
        'publication_seqlock_valid': all(
            item['publication_seqlock_valid'] for item in snapshots),
        'content_revision_stable': all(
            type(item['values'].get('ContentRevision')) is int
            for item in snapshots) and
            len({item['values'].get('ContentRevision') for item in snapshots}) == 1,
        'mpdu_sequence_stable': all(
            type(item['values'].get('Sequence')) is int for item in snapshots) and
            len({item['values'].get('Sequence') for item in snapshots}) == 1,
        'samples': snapshots,
        'final': final,
        'problems': sorted(set(problems)),
        'local_ifnet_input_kpi_accepted': (
            final['local_ifnet_input_kpi_accepted'] if not problems else None),
        'sequence_is_mpdu_identity_not_publication_version': True,
        'peer_or_socket_receipt_proven': False,
        'airdrop_proven': False,
        'owner_serial_and_epoch_match_proves_frame_content': False,
        'candidate_to_receipt_per_frame_join_proven': False,
    }


def awdl_data_rx149_receipt_delta(before, after, triplet_evidence=None):
    """Compare MPDU identity and publication revision across separate reads."""
    left = awdl_data_rx149_receipt_snapshot(before)
    right = awdl_data_rx149_receipt_snapshot(after)
    a = left['values'].get('Sequence')
    b = right['values'].get('Sequence')
    sequence_delta = b - a if (type(a) is int and type(b) is int and b >= a) else None
    reset_or_wrap = type(a) is int and type(b) is int and b < a
    before_revision = left['values'].get('ContentRevision')
    after_revision = right['values'].get('ContentRevision')
    revision_delta = (after_revision - before_revision
                      if type(before_revision) is int and
                      type(after_revision) is int and
                      after_revision >= before_revision else None)
    revision_reset_or_wrap = (type(before_revision) is int and
                              type(after_revision) is int and
                              after_revision < before_revision)
    stable_receipt = bool(triplet_evidence and triplet_evidence.get('valid') is True)
    baseline_and_post_valid = left['valid'] and right['valid']
    sequence_advanced = bool(sequence_delta is not None and sequence_delta > 0)
    revision_advanced = bool(revision_delta is not None and revision_delta > 0)
    same_mpdu_updated = bool(sequence_delta == 0 and revision_advanced)
    inconsistent = []
    if sequence_advanced and not revision_advanced:
        inconsistent.append('sequence_advanced_without_content_revision')
    if (sequence_delta == 0 and revision_delta == 0 and left['valid'] and right['valid']):
        mutable_fields = ('Disposition', 'InputMonotonicUs', 'DecodedIpv6Count',
                          'IfnetInputResultPresent', 'IfnetInputResult')
        if any(left['values'].get(key) != right['values'].get(key)
               for key in mutable_fields):
            inconsistent.append('receipt_content_changed_without_content_revision')
    if sequence_delta == 0 and left['valid'] and right['valid']:
        mutable_fields = {'SnapshotBegin', 'SnapshotEnd', 'ContentRevision',
                          'Disposition', 'InputMonotonicUs', 'DecodedIpv6Count',
                          'IfnetInputResultPresent', 'IfnetInputResult'}
        immutable_fields_changed = [key for key in AWDL_RX149_RECEIPT_FIELDS
                                    if key not in mutable_fields and
                                    left['values'].get(key) != right['values'].get(key)]
        if immutable_fields_changed:
            inconsistent.append('same_mpdu_immutable_fields_changed')
    new_in_window = bool(
        stable_receipt and baseline_and_post_valid and not reset_or_wrap and
        not revision_reset_or_wrap and not inconsistent and
        ((sequence_advanced and revision_advanced) or same_mpdu_updated))
    owner_match = bool(stable_receipt and not triplet_evidence.get('problems') and
                       triplet_evidence.get('final', {}).get('receipt_observed'))
    return {
        'pre': left,
        'post': right,
        'sequence_delta': sequence_delta,
        'sequence_reset_or_wrap': reset_or_wrap,
        'content_revision_pre': before_revision,
        'content_revision_post': after_revision,
        'content_revision_delta': revision_delta,
        'content_revision_reset_or_wrap': revision_reset_or_wrap,
        'new_sequence_since_prearm': (
            bool(new_in_window and sequence_advanced)
            if baseline_and_post_valid and stable_receipt else None),
        'same_mpdu_content_updated_since_prearm': (
            bool(new_in_window and same_mpdu_updated)
            if baseline_and_post_valid and stable_receipt else None),
        'new_receipt_bound_to_current_owner': bool(new_in_window and owner_match),
        'receipt_session_complete': bool(
            stable_receipt and not reset_or_wrap and not revision_reset_or_wrap and
            not inconsistent),
        'pre_post_problems': sorted(set(inconsistent)),
        'input_time_proves_kpi_completion_before_roc_end': False,
        'local_ifnet_input_kpi_accepted': bool(
            new_in_window and owner_match and
            triplet_evidence.get('local_ifnet_input_kpi_accepted') is True),
        'per_frame_candidate_join_proven': False,
        'peer_or_socket_receipt_proven': False,
        'airdrop_proven': False,
    }


def awdl_data_rx_delta(before, after):
    """Return arithmetic-only counter deltas; absent/reset values stay unknown."""
    left = awdl_data_rx_snapshot(before)
    right = awdl_data_rx_snapshot(after)
    delta = {}
    reset = []
    for key in AWDL_DATA_RX_COUNTERS:
        a = left['counters'][key]
        b = right['counters'][key]
        if type(a) is int and type(b) is int and b >= a:
            delta[key] = b - a
        else:
            delta[key] = None
            if type(a) is int and type(b) is int and b < a:
                reset.append(key)
    before_epochs = left['rx_entry_epochs']
    after_epochs = right['rx_entry_epochs']
    epochs_match = (all(type(before_epochs[key]) is int and
                        type(after_epochs[key]) is int and
                        before_epochs[key] == after_epochs[key]
                        for key in AWDL_DATA_RX_EPOCH_KEYS))
    epochs_owned = (epochs_match and all(
        before_epochs[key] > 0 for key in AWDL_DATA_RX_EPOCH_KEYS))
    candidate_key = RX_ENTRY_PREFIX + 'CountAwdlBssidCandidate'
    candidate_pre = (before[candidate_key] if candidate_key in before and
                     type(before[candidate_key]) is int and
                     before[candidate_key] >= 0 else None)
    candidate_post = (after[candidate_key] if candidate_key in after and
                      type(after[candidate_key]) is int and
                      after[candidate_key] >= 0 else None)
    candidate_delta = None
    candidate_snapshots_stable = bool(
        left['descriptor_candidate_snapshot_stable'] and
        right['descriptor_candidate_snapshot_stable'])
    if (epochs_owned and candidate_snapshots_stable and
            candidate_pre is not None and candidate_post is not None and
            candidate_post >= candidate_pre):
        candidate_delta = candidate_post - candidate_pre
    tx_key = AWDL_HOST_TX_COUNTERS[0]
    tx_before = left['host_tx'].get(tx_key)
    tx_after = right['host_tx'].get(tx_key)
    tx_delta = (tx_after - tx_before if type(tx_before) is int and
                type(tx_after) is int and tx_after >= tx_before else None)
    return {
        'pre': left,
        'post': right,
        'observed_counter_delta': delta,
        'counter_reset_or_wrap': reset,
        'candidate_descriptor_count_pre': candidate_pre,
        'candidate_descriptor_count_post': candidate_post,
        'candidate_descriptor_count_delta': candidate_delta,
        'candidate_epoch_match': epochs_owned,
        'candidate_snapshots_stable': candidate_snapshots_stable,
        'candidate_epoch_match_status': (
            'same_nonzero_owner_epochs_and_stable_snapshots'
            if epochs_owned and candidate_snapshots_stable else
            'unknown_or_not_same_nonzero_owner_epochs_or_snapshot'),
        'awdl_data_tx_submitted_delta': tx_delta,
        'awdl_data_tx_submission_unchanged': tx_delta == 0 if tx_delta is not None else None,
        'data_tx_pending_pre': left['host_tx'].get('NativeAwdlDataTxPending'),
        'data_tx_pending_post': right['host_tx'].get('NativeAwdlDataTxPending'),
        'delta_basis': 'arithmetic difference of observed numeric properties only; missing/reset is unknown',
        'counter_delta_is_per_frame_correlation': False,
        'native_awdl_reply_proven': False,
        'airdrop_proven': False,
    }


def awdl_data_rx_triplet_evidence(samples):
    """Require a stable, drained post-session read without inferring delivery."""
    if len(samples) != 3:
        return {'valid': False, 'status': 'three_snapshots_required',
                'samples': [], 'problems': ['three_snapshots_required']}
    snapshots = [awdl_data_rx_snapshot(sample) for sample in samples]
    problems = []
    if any(not item['complete'] for item in snapshots):
        problems.append('missing_or_invalid_numeric_counter_or_epoch')
    for key in AWDL_DATA_RX_COUNTERS + AWDL_DATA_RX_GAUGES:
        values = [item['counters'].get(key) for item in snapshots]
        if values[0] is None or values[1] is None or values[2] is None:
            continue
        if len(set(values)) != 1:
            problems.append(key + ':changed_between_reads')
    for key in AWDL_HOST_TX_COUNTERS + AWDL_HOST_TX_GAUGES:
        values = [item['host_tx'].get(key) for item in snapshots]
        if values[0] is None or values[1] is None or values[2] is None:
            continue
        if len(set(values)) != 1:
            problems.append(key + ':changed_between_reads')
    if any(item['counters'].get('NativeAwdlDataRxPending') != 0
           for item in snapshots):
        problems.append('NativeAwdlDataRxPending_not_zero')
    if any(item['host_tx'].get('NativeAwdlDataTxPending') != 0
           for item in snapshots):
        problems.append('NativeAwdlDataTxPending_not_zero')
    epoch_tuples = [tuple(item['rx_entry_epochs'].get(key)
                           for key in AWDL_DATA_RX_EPOCH_KEYS)
                    for item in snapshots]
    if any(any(value is None for value in epoch) for epoch in epoch_tuples):
        problems.append('rx_entry_epoch_unknown')
    elif len(set(epoch_tuples)) != 1:
        problems.append('rx_entry_epoch_changed_between_reads')
    return {
        'valid': not problems,
        'status': 'stable_drained_numeric_snapshot' if not problems else 'incomplete_or_unstable',
        'samples': snapshots,
        'problems': sorted(set(problems)),
        'snapshot_version': None,
        'per_frame_counter_epoch_attribution': False,
        'ifnet_delivery_semantics': (
            'Delivered is ifnet_input return-zero KPI acceptance only; '
            'no peer/socket/application/AirDrop receipt is inferred.'),
    }


def rx_entry_extension_evidence(samples):
    """Check stable published Test086 aliases while keeping absent values unknown."""
    if len(samples) != 3:
        return {'valid': False, 'status': 'three_snapshots_required',
                'values': {}, 'missing_aliases': list(RX_ENTRY_EXTENSION_KEYS),
                'problems': ['three_snapshots_required']}
    values = {}
    missing = []
    invalid = []
    problems = []
    any_published = False
    for key in RX_ENTRY_EXTENSION_KEYS:
        seen = [key in sample for sample in samples]
        if not any(seen):
            missing.append(key)
            continue
        any_published = True
        if not all(seen):
            problems.append(key + ':presence_changed_between_reads')
            continue
        scalars = [sample[key] for sample in samples]
        width = 64 if key in RX_ENTRY_U64_KEYS else 32
        maximum = (1 << width) - 1
        if any(type(value) is not int or not 0 <= value <= maximum
               for value in scalars):
            invalid.append(key)
            continue
        if len(set(scalars)) != 1:
            problems.append(key + ':changed_between_reads')
            continue
        values[key] = scalars[1]

    for key in RX_ENTRY_EXTENSION_COUNTERS:
        if key in values and not 0 <= values[key] <= 0xffffffff:
            invalid.append(key)
    channel149 = values.get(RX_ENTRY_PREFIX + 'CountChannel149')
    expected149 = values.get(RX_ENTRY_PREFIX + 'CountExpectedMacPhy149')
    mac1_149 = values.get(RX_ENTRY_PREFIX + 'CountMacIndex1Channel149')
    if (type(channel149) is int and type(expected149) is int and
            expected149 > channel149):
        problems.append('expected_mac_phy_149_count_exceeds_reported_channel_149')
    if (type(mac1_149) is int and type(expected149) is int and
            expected149 > mac1_149):
        problems.append('expected_mac_phy_149_count_exceeds_mac_index_1_channel_149')
    if (type(mac1_149) is int and type(channel149) is int and
            mac1_149 > channel149):
        problems.append('mac_index_1_channel_149_count_exceeds_reported_channel_149')

    witness_status = 'unknown_missing_alias'
    target_prefix = RX_ENTRY_PREFIX + 'LastTarget'
    target_present_key = target_prefix + 'Present'
    target_required = tuple(target_prefix + suffix for suffix in (
        'Present', 'ChannelPresent', 'Channel', 'MacIndexPresent', 'MacIndex',
        'PhyIndexPresent', 'PhyIndex', 'MacPhyIndexDecodeModePresent',
        'MacPhyIndexDecodeMode',
        'RxRingPresent', 'RxRing', 'RxRingSlotPresent', 'RxRingSlot'))
    if all(key in values for key in target_required):
        target_present = values[target_present_key]
        if target_present == 0:
            if expected149 == 0:
                witness_status = 'no_expected_mac_phy_149_descriptor'
            elif type(expected149) is int and expected149 > 0:
                witness_status = 'invalid_expected_count_without_last_target'
                problems.append('expected_mac_phy_149_count_without_last_target')
            else:
                witness_status = 'no_last_target_witness'
        elif target_present == 1:
            witness_status = 'verified_expected_mac_phy_149_witness'
            expected_fields = (
                ('ChannelPresent', 1), ('Channel', 149),
                ('MacIndexPresent', 1), ('MacIndex', 1),
                ('PhyIndexPresent', 1), ('PhyIndex', 1),
                ('MacPhyIndexDecodeModePresent', 1),
                ('RxRingPresent', 1), ('RxRing', 0),
                ('RxRingSlotPresent', 1),
            )
            bad = [name for name, expected in expected_fields
                   if values.get(target_prefix + name) != expected]
            if (values.get(target_prefix + 'MacPhyIndexDecodeModePresent') != 1 or
                    values.get(target_prefix + 'MacPhyIndexDecodeMode') not in (1, 2)):
                bad.append('MacPhyIndexDecodeMode')
            if expected149 == 0:
                bad.append('CountExpectedMacPhy149')
            for witness_suffix, snapshot_suffix in (
                    ('ContextGeneration', 'ContextGeneration'),
                    ('PowerGeneration', 'PowerGeneration'),
                    ('StationGeneration', 'StationGeneration'),
                    ('RocGeneration', 'RocGeneration')):
                witness_key = target_prefix + witness_suffix
                snapshot_key = RX_ENTRY_PREFIX + snapshot_suffix
                owner_values = [sample.get(snapshot_key) for sample in samples]
                if (type(values.get(witness_key)) is not int or
                        any(type(value) is not int for value in owner_values) or
                        len(set(owner_values)) != 1 or
                        values[witness_key] != owner_values[0]):
                    bad.append(witness_suffix + '_owner_mismatch')
            if bad:
                witness_status = 'invalid_expected_mac_phy_149_witness'
                problems.extend('last_target:' + name for name in bad)
        else:
            witness_status = 'invalid_last_target_present_flag'
            invalid.append(target_present_key)

    mac_target_status = 'unknown_missing_alias'
    mac_target_prefix = RX_ENTRY_PREFIX + 'LastMacIndexTarget'
    mac_target_required = tuple(mac_target_prefix + suffix for suffix in (
        'Present', 'ChannelPresent', 'Channel', 'MacIndexPresent', 'MacIndex',
        'MacPhyIndexDecodeModePresent', 'MacPhyIndexDecodeMode',
        'RxRingPresent', 'RxRing', 'RxRingSlotPresent', 'RxRingSlot'))
    if all(key in values for key in mac_target_required):
        mac_target_present = values[mac_target_prefix + 'Present']
        if mac_target_present == 0:
            if mac1_149 == 0:
                mac_target_status = 'no_mac_index_1_channel_149_descriptor'
            elif type(mac1_149) is int and mac1_149 > 0:
                mac_target_status = 'invalid_mac_index_1_count_without_last_target'
                problems.append('mac_index_1_channel_149_count_without_last_target')
            else:
                mac_target_status = 'no_last_mac_index_target_witness'
        elif mac_target_present == 1:
            mac_target_status = 'verified_mac_index_1_channel_149_witness'
            expected_fields = (
                ('ChannelPresent', 1), ('Channel', 149),
                ('MacIndexPresent', 1), ('MacIndex', 1),
                ('MacPhyIndexDecodeModePresent', 1),
                ('RxRingPresent', 1), ('RxRing', 0),
                ('RxRingSlotPresent', 1),
            )
            bad = [name for name, expected in expected_fields
                   if values.get(mac_target_prefix + name) != expected]
            if values.get(mac_target_prefix + 'MacPhyIndexDecodeMode') not in (1, 2):
                bad.append('MacPhyIndexDecodeMode')
            if mac1_149 == 0:
                bad.append('CountMacIndex1Channel149')
            for witness_suffix, snapshot_suffix in (
                    ('ContextGeneration', 'ContextGeneration'),
                    ('PowerGeneration', 'PowerGeneration'),
                    ('StationGeneration', 'StationGeneration'),
                    ('RocGeneration', 'RocGeneration')):
                witness_key = mac_target_prefix + witness_suffix
                snapshot_key = RX_ENTRY_PREFIX + snapshot_suffix
                owner_values = [sample.get(snapshot_key) for sample in samples]
                if (type(values.get(witness_key)) is not int or
                        any(type(value) is not int for value in owner_values) or
                        len(set(owner_values)) != 1 or
                        values[witness_key] != owner_values[0]):
                    bad.append(witness_suffix + '_owner_mismatch')
            if bad:
                mac_target_status = 'invalid_mac_index_1_channel_149_witness'
                problems.extend('last_mac_index_target:' + name for name in bad)
        else:
            mac_target_status = 'invalid_last_mac_index_target_present_flag'
            invalid.append(mac_target_prefix + 'Present')

    # Explicit presence bits govern whether their paired numeric value has
    # meaning. In particular a raw mac_context value is never compared with
    # the decoded P2P MAC index.
    for prefix in RX_ENTRY_EXTENSION_WITNESS_PREFIXES:
        for flag_suffix, value_suffix in RX_ENTRY_PRESENCE_VALUE_PAIRS:
            flag_key = prefix + flag_suffix
            value_key = prefix + value_suffix
            flag = values.get(flag_key)
            value = values.get(value_key)
            if flag is None:
                continue
            if flag not in (0, 1):
                invalid.append(flag_key)
            elif flag == 1 and value is None:
                problems.append(value_key + ':presence_flag_without_value')
    for suffix in ('Present', 'StatusPresent', 'MacPhyIndexPresent',
                   'FilterMatchPresent', 'ChannelPresent',
                   'FrameControlPresent', 'AwdlBssidCandidate', 'ToDs', 'FromDs',
                   'MacContextPresent', 'MacIndexPresent', 'PhyIndexPresent',
                   'MacPhyIndexDecodeModePresent',
                   'HostRxMonotonicUsPresent', 'Gp2OnAirRisePresent',
                   'TsfOnAirRisePresent', 'TsfValidPresent', 'RxRingPresent',
                   'RxRingSlotPresent', 'TransportNotificationQidPresent',
                   'TransportNotificationIndexPresent', 'TsfValid'):
        for prefix in RX_ENTRY_EXTENSION_WITNESS_PREFIXES:
            key = prefix + suffix
            if key in values and values[key] not in (0, 1):
                invalid.append(key)
    for prefix in RX_ENTRY_EXTENSION_WITNESS_PREFIXES:
        mode_key = prefix + 'MacPhyIndexDecodeMode'
        if mode_key in values and values[mode_key] not in (0, 1, 2):
            invalid.append(mode_key)

    problems.extend('invalid_scalar:' + key for key in invalid)
    valid = not problems and not invalid
    status = ('not_published_unknown' if not any_published else
              'invalid_or_unstable' if not valid else
              'verified' if not missing else 'partially_published_unknowns_retained')
    return {
        'valid': None if not any_published else valid,
        'status': status,
        'values': values,
        'missing_aliases': missing,
        'invalid_aliases': sorted(set(invalid)),
        'problems': sorted(set(problems)),
        'last_target_status': witness_status,
        'last_mac_index_target_status': mac_target_status,
        'last_target_is_peer_identity': False,
        'raw_mac_context_interpreted_as_index': False,
        'transport_notification_qid_used_as_rx_ring': False,
        'gp2_and_tsf_combined_or_converted': False,
        'zero_counts_prove_rf_absence': False,
    }


def safe_runtime_snapshot(values):
    """Preserve numeric/bool driver evidence without private address fields."""
    prefixes = ('NativeP2PRx149', 'NativeP2PRxEntry', 'NativeP2PRxTrace', 'NativeP2PRoc',
                'NativeAwdlDataRx',
                PREPARE_PROPERTY_PREFIX, 'NativeP2PProbeExercise',
                'NativeMCC', 'NativeStaTx', 'NativeFwErrorSnapshot',
                'NativeHcmdRxTrace', 'NativeFirmwareIdentity')
    exact = set(ATTEMPT_STATE_PROPERTIES) | set(AWDL_HOST_TX_COUNTERS) | \
        set(AWDL_HOST_TX_GAUGES) | {
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


def clock_domain_snapshot():
    """Record CLOCK_UPTIME_RAW between realtime reads without sleeping.

    This only describes the local sample and its realtime bracket. It does not
    align the kernel RX host-microsecond value or the router PCAP clock.
    """
    result = {
        'schema': 1,
        'uptime_clock_name': 'CLOCK_UPTIME_RAW',
        'uptime_clock_present': False,
        'uptime_ns': None,
        'realtime_before_ns': None,
        'realtime_after_ns': None,
        'realtime_bracket_width_ns': None,
        'realtime_sample_error_bound_ns': None,
        'uptime_sample_bracketed_by_realtime': False,
        'directly_comparable_to_driver_rx_host_us': False,
        'clock_mapping_to_router_pcap_proven': False,
    }
    try:
        clock_id = getattr(time, 'CLOCK_UPTIME_RAW')
        before = time.time_ns()
        result['realtime_before_ns'] = before
        uptime = time.clock_gettime_ns(clock_id)
        result['uptime_ns'] = uptime
        after = time.time_ns()
        result['realtime_after_ns'] = after
    except (AttributeError, OSError, OverflowError, ValueError) as error:
        result['uptime_clock_error_type'] = type(error).__name__
        return result
    width = max(0, after - before)
    result.update({
        'uptime_clock_present': True,
        'realtime_bracket_width_ns': width,
        'realtime_sample_error_bound_ns': width,
        'uptime_sample_bracketed_by_realtime': before <= after,
    })
    return result


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
            for number in range(65, 86)]


def consume_boot_claim(claim_dir, boot_epoch, observation_id):
    """Atomically spend the shared boot claim; failed arm attempts never retry."""
    claim_dir = Path(claim_dir)
    if any(path.exists() or path.is_symlink() for path in _legacy_claims(claim_dir, boot_epoch)):
        raise FileExistsError('Same-boot legacy claim exists; no Test086 arm permitted')
    claim_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = claim_dir / ('boot-' + str(boot_epoch) + '.json')
    payload = {
        'schema': 1, 'test_scope': 'Test086', 'build': BUILD,
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
        raise ValueError('Test086 metadata is a symlink')
    return json.loads(METADATA_PATH.read_text())


def _native_preflight(metadata, boot_epoch):
    identity = loaded_identity(BUILD)
    identity_problems = test086_metadata_problems(
        metadata, boot_epoch=boot_epoch, identity=identity, root=ROOT)
    if identity_problems:
        raise ValueError('Test086 identity/source gate failed: ' + ','.join(identity_problems))
    wrapper = properties('IOPCIEDeviceWrapper')
    if wrapper.get('NativeTestBuild') != BUILD:
        raise ValueError('Loaded wrapper build does not match Test086')
    state = properties('AirportItlwm')
    profile_errors = profile_problems(state, selected=False)
    if profile_errors:
        raise ValueError('Test086 RX149 profile gate failed: ' + ','.join(profile_errors))
    if state.get('NativePowerReady') != 1:
        raise ValueError('Intel Wi-Fi power is not ready')
    data_rx = awdl_data_rx_snapshot(state)
    if not data_rx['complete']:
        raise ValueError('Test086 native data RX telemetry is missing/invalid before claim')
    data_receipt = awdl_data_rx149_receipt_snapshot(state)
    receipt_problem = receipt_preflight_problem(data_receipt)
    if receipt_problem:
        raise ValueError(receipt_problem)
    for key in ('NativeP2PManualArmed', 'NativeP2PProbeAttempted',
                'NativeP2PProbeResourceMayExist'):
        if type(state.get(key)) is not int or state[key] != 0:
            raise ValueError('Test086 one-shot state is nonzero or unknown: ' + key)
    counters = {key: state.get(key) for key in TX_ZERO_COUNTERS}
    evidence = tx_zero_evidence(counters, counters)
    if not evidence['valid']:
        raise ValueError('Test086 pre-arm TX counters are nonzero or unknown')
    if data_rx['host_tx'].get('NativeAwdlDataTxPending') != 0:
        raise ValueError('Test086 AWDL data TX queue is nonempty before claim')
    return identity, state, evidence


def _compile_arm_helper(temp_dir):
    output = Path(temp_dir) / 'arm-p2p-rx149'
    result = subprocess.run(['/usr/bin/swiftc', '-O', '-o', str(output),
                             str(HELPER_SOURCE)], capture_output=True, text=True,
                            timeout=20)
    if result.returncode != 0 or not output.is_file() or output.is_symlink():
        raise RuntimeError('Test086 helper compilation failed')
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
    rx_entry_evidence = None
    data_rx_evidence = None
    data_receipt_evidence = None
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
            rx_entry_evidence = rx_entry_observation_evidence(
                trace_snapshots, post)
            data_rx_evidence = awdl_data_rx_triplet_evidence(trace_snapshots)
            data_receipt_evidence = awdl_data_rx149_receipt_triplet_evidence(
                trace_snapshots, post)
            if (trace_coverage and not roc_session_problems(post) and
                    data_rx_evidence.get('valid') is True and
                    data_receipt_evidence.get('valid') is True):
                samples.extend((pre, middle, post))
                break
        time.sleep(0.05)
    return (samples, trace_evidence, trace_snapshots, rx_entry_evidence,
            data_rx_evidence, data_receipt_evidence)


def _native_worker(args):
    if not args.arm:
        raise SystemExit('Test086 is disarmed by default; no system state read or claim')
    if not args.receiver_gated or not args.router_observation_id:
        raise SystemExit('Test086 requires the receiver-gated coordinator; unchanged')
    if os.geteuid() != 0 or args.expect_build != BUILD or not args.phone_ready:
        raise SystemExit('Require root, Test086 and freshly confirmed phone; unchanged')
    if not fresh_observation_id(args.router_observation_id):
        raise SystemExit('Invalid Test086 observation id; unchanged')
    metadata = _load_metadata()
    if metadata.get('armed') is not True:
        raise SystemExit('Test086 metadata is disarmed; no boot claim or RF action')
    boot = _sysctl_boot_epoch()
    metadata_problems = test086_metadata_problems(metadata, boot_epoch=boot, root=ROOT)
    if metadata_problems:
        raise SystemExit('Test086 metadata gate failed; no boot claim; fields=' + ','.join(metadata_problems))
    identity, initial, initial_zero = _native_preflight(metadata, boot)
    account = pwd.getpwuid(ROOT.stat().st_uid)
    if not args.output:
        raise SystemExit('Missing private Test086 output directory; unchanged')
    folder = _require_private_output(args.output, account)
    report_path = folder / 'native-rx149-data-input-private.json'
    if report_path.exists() or report_path.is_symlink():
        raise SystemExit('Test086 output already exists; no capture or retry')
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
        'native_awdl_data_rx_initial': awdl_data_rx_snapshot(initial),
        'native_awdl_data_rx_after': None,
        'native_awdl_data_rx_delta': None,
        'native_awdl_data_rx149_receipt_initial': awdl_data_rx149_receipt_snapshot(initial),
        'native_awdl_data_rx149_receipt_after': None,
        'native_awdl_data_rx149_receipt_delta': None,
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
        'rx_entry_evidence': None,
        'rx_entry_properties': None,
        'rx_entry_v2_extension_evidence': None,
        'strict_channel149_count': None,
        'strict_mac_index1_channel149_count': None,
        'strict_expected_mac_phy149_count': None,
        'last_mac_index_target_status': None,
        'strict_channel36_count': None,
        'strict_awdl_bssid_candidate_count': None,
        'rx_entry_observation_complete': False,
        'native_awdl_data_rx_observation_complete': False,
        'native_awdl_data_rx_stability_evidence': None,
        'native_awdl_data_rx149_receipt_stability_evidence': None,
        'native_awdl_host_tx_zero_window': False,
        'firmware_hcmd_rx_trace_pre_arm': None,
        'firmware_hcmd_rx_trace_post_arm': None,
        'firmware_hcmd_rx_trace_serial_delta': None,
        'channel149_rx_observed': None,
        'channel149_rx_observation_source': 'retain descriptor-reported channel149 counters and same-target witness as numeric driver instrumentation; analyze independent OpenWrt PCAP separately; neither source alone proves peer receipt',
        'mif_decode_status': 'unknown_not_inferred_from_session_completion',
        'peer_table_acceptance': None,
        'host_management_or_data_tx_blocked': True,
        'host_management_or_data_tx_queue_created': None,
        'host_tx_queue_creation_independently_exposed': False,
        'mac_phy_session_protection_control_commands_may_occur': True,
        'clock_domain_context': {
            'python_monotonic_ns': 'collector-process-local-ordering-only',
            'driver_rx_host_monotonic_us': 'independent-kernel-clock-domain; no direct alignment',
            'router_pcap_clock': 'independent-capture-clock-domain; no mapping proven',
            'clock_mapping_to_router_pcap_proven': False,
        },
        'arm_helper_return_clock_domain': None,
        'radio_transmit_proven': False, 'peer_receipt_proven': False,
        'native_awdl_reply_proven': False, 'airdrop_proven': False,
        'scope': 'One receiver-gated 100 ms Test086 cfg2 RX149 session with the separate native AWDL data-input experiment explicitly enabled. Host management/data TX remains blocked. The owner-guarded schema-2 descriptor candidate count and existing NativeAwdlDataRx counter deltas are separate instrumentation; the data counters have no owner-version or per-frame epoch and cannot be aligned to a specific descriptor. NativeAwdlDataRxDelivered means only ifnet_input returned 0. No PHY identity, peer/socket receipt, native awdl0 reply, or AirDrop is inferred.',
        'status': 'preflight_passed_waiting_for_receiver',
    }
    report['firmware_hcmd_rx_trace_pre_arm'] = _safe_hcmd_rx_trace_triplet()
    _save_private_json(report_path, report, account)
    with tempfile.TemporaryDirectory(prefix='intel-test086-', dir='/private/tmp') as temp_dir:
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
            report['arm_helper_return_clock_domain'] = clock_domain_snapshot()
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
    report['arm_helper_return_clock_domain'] = clock_domain_snapshot()
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
    (samples, rx_trace_evidence, rx_trace_snapshots,
     rx_entry_evidence, data_rx_evidence,
     data_receipt_evidence) = _sample_after_arm()
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
    report['rx_entry_evidence'] = rx_entry_evidence
    report['rx_entry_v2_extension_evidence'] = (
        rx_entry_evidence.get('extension_evidence') if rx_entry_evidence else None)
    report['strict_channel149_count'] = (
        rx_entry_evidence.get('strict_channel149_count') if rx_entry_evidence else None)
    report['strict_mac_index1_channel149_count'] = (
        rx_entry_evidence.get('strict_mac_index1_channel149_count') if rx_entry_evidence else None)
    report['strict_expected_mac_phy149_count'] = (
        rx_entry_evidence.get('strict_expected_mac_phy149_count') if rx_entry_evidence else None)
    report['last_mac_index_target_status'] = (
        rx_entry_evidence.get('last_mac_index_target_status') if rx_entry_evidence else None)
    report['strict_channel36_count'] = (
        rx_entry_evidence.get('strict_channel36_count') if rx_entry_evidence else None)
    report['strict_awdl_bssid_candidate_count'] = (
        rx_entry_evidence.get('strict_awdl_bssid_candidate_count') if rx_entry_evidence else None)
    report['rx_entry_properties'] = ([rx086_entry_scalar_snapshot(item)
        for item in rx_trace_snapshots] if rx_trace_snapshots else None)
    report['rx_entry_observation_complete'] = bool(
        rx_entry_evidence and rx_entry_evidence.get('valid') is True)
    report['native_awdl_data_rx_after'] = awdl_data_rx_snapshot(after)
    report['native_awdl_data_rx_delta'] = awdl_data_rx_delta(initial, after)
    report['native_awdl_data_rx_observation_complete'] = bool(
        report['native_awdl_data_rx_after']['complete'] and
        report['native_awdl_data_rx_delta']['pre']['complete'] and
        not report['native_awdl_data_rx_delta']['counter_reset_or_wrap'] and
        data_rx_evidence and data_rx_evidence.get('valid') is True)
    report['native_awdl_data_rx_stability_evidence'] = data_rx_evidence
    report['native_awdl_data_rx149_receipt_after'] = awdl_data_rx149_receipt_snapshot(after)
    report['native_awdl_data_rx149_receipt_stability_evidence'] = data_receipt_evidence
    report['native_awdl_data_rx149_receipt_delta'] = awdl_data_rx149_receipt_delta(
        initial, after, data_receipt_evidence)
    data_rx_deltas = report['native_awdl_data_rx_delta']['observed_counter_delta']
    report['native_awdl_data_rx_pipeline_stages'] = {
        'descriptor_candidate_count_delta': report['native_awdl_data_rx_delta'].get(
            'candidate_descriptor_count_delta'),
        'descriptor_candidate_delta_owner_status': report[
            'native_awdl_data_rx_delta'].get('candidate_epoch_match_status'),
        'descriptor_candidate_current_owner_evidence': (
            rx_entry_evidence.get('data_candidate_evidence')
            if rx_entry_evidence else None),
        'queue_capture_accepted_delta': data_rx_deltas.get('NativeAwdlDataRxCaptured'),
        'queue_rejected_delta': data_rx_deltas.get('NativeAwdlDataRxRejected'),
        'queue_full_delta': data_rx_deltas.get('NativeAwdlDataRxQueueFull'),
        'frame_decode_success_delta': data_rx_deltas.get('NativeAwdlDataRxDecoded'),
        'ifnet_input_return_zero_delta': data_rx_deltas.get('NativeAwdlDataRxDelivered'),
        'ifnet_input_failed_delta': data_rx_deltas.get('NativeAwdlDataRxInputFailed'),
        'latest_receipt': report['native_awdl_data_rx149_receipt_delta']['post'],
        'aggregate_counter_to_per_frame_mapping_proven': False,
        'peer_socket_or_airdrop_receipt_proven': False,
    }
    report['native_awdl_data_rx_interpretation'] = {
        'candidate_source': 'owner-guarded schema-2 NativeP2PRxEntryCountAwdlBssidCandidate and LastAwdlDataCandidate witness',
        'capture_source': 'NativeAwdlDataRxCaptured means bounded native queue acceptance',
        'decode_source': 'NativeAwdlDataRxDecoded means frame parse success',
        'ifnet_input_source': 'NativeAwdlDataRxDelivered means ifnet_input returned 0 (KPI acceptance only)',
        'receipt_input_monotonic_time': (
            'lock-linearized input admission/ticket time immediately before KPI; '
            'not KPI completion or return time'),
        'receipt_time_proves_completion_before_roc_end': False,
        'per_mpdu_receipt': report['native_awdl_data_rx149_receipt_delta'],
        'host_awdl_data_tx_submission_delta': report['native_awdl_data_rx_delta'].get(
            'awdl_data_tx_submitted_delta'),
        'host_awdl_data_tx_submission_unchanged': report['native_awdl_data_rx_delta'].get(
            'awdl_data_tx_submission_unchanged'),
        'host_awdl_data_tx_pending_pre': report['native_awdl_data_rx_delta'].get(
            'data_tx_pending_pre'),
        'host_awdl_data_tx_pending_post': report['native_awdl_data_rx_delta'].get(
            'data_tx_pending_post'),
        'host_awdl_data_tx_submission_during_window_proven_absent': (
            report['native_awdl_data_rx_delta'].get('awdl_data_tx_submission_unchanged') is True and
            report['native_awdl_data_rx_delta'].get('data_tx_pending_pre') == 0 and
            report['native_awdl_data_rx_delta'].get('data_tx_pending_post') == 0),
        'peer_or_socket_receipt_proven': False,
        'airdrop_proven': False,
    }
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
    report['native_awdl_host_tx_zero_window'] = bool(
        report['tx_zero_window']['valid'] and
        report['native_awdl_data_rx_delta'].get('awdl_data_tx_submission_unchanged') is True and
        report['native_awdl_data_rx_delta'].get('data_tx_pending_pre') == 0 and
        report['native_awdl_data_rx_delta'].get('data_tx_pending_post') == 0 and
        report['host_tx_blocked_after_arm'])
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
    if not report['rx_entry_observation_complete']:
        profile_errors.append('rx_entry_snapshot_not_complete_or_discovery_owner_guard_failed')
    if not report['native_awdl_data_rx_observation_complete']:
        profile_errors.append('native_awdl_data_rx_snapshot_missing_unstable_or_undrained')
    if not report['native_awdl_data_rx149_receipt_delta']['receipt_session_complete']:
        profile_errors.append('native_awdl_data_rx149_receipt_missing_unstable_or_invalid')
    if not report['native_awdl_host_tx_zero_window']:
        profile_errors.append('host_management_or_data_tx_not_proven_zero')
    report['post_profile_problems'] = sorted(set(profile_errors))
    report['session_complete'] = bool(
        report['selected_after_arm'] and report['roc_session_complete'] and
        trace_complete and report['tx_zero_window']['valid'] and
        report['host_tx_blocked_after_arm'] and
        report['rx_entry_observation_complete'] and
        report['native_awdl_data_rx_observation_complete'] and
        report['native_awdl_host_tx_zero_window'] and
        not report['post_profile_problems'])
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
                      'rx_entry_observation_complete': report['rx_entry_observation_complete'],
                      'native_data_rx_pipeline_stages': report.get(
                          'native_awdl_data_rx_pipeline_stages'),
                      'native_data_rx_receipt_status': data_receipt_evidence.get('status')
                          if data_receipt_evidence else None,
                      'native_ifnet_input_kpi_accepted': report[
                          'native_awdl_data_rx149_receipt_delta'].get(
                              'local_ifnet_input_kpi_accepted'),
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
        raise SystemExit('Test086 is disarmed by default; no system state read or claim')
    return _native_worker(args)


if __name__ == '__main__':
    raise SystemExit(main())
