#!/usr/bin/env python3
"""One fresh-boot, receiver-gated Test080 RX149-only observation.

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
from pathlib import Path
import pwd
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

from capture_test076_resident_data_once import guarded_rx_trace_evidence
from probe_p2p_result import loaded_identity
from probe_wifi_rate import properties

ROOT = Path(__file__).resolve().parent
BUILD = '25G332-Test080'
BASELINE = '25G332-Test079'
PROFILE = 'native_awdl_rx149_observation_only'
METADATA_PATH = ROOT / 'research/test080-next-boot-private.json'
BUILD_PATH = ROOT / 'research/test080-build-private.json'
SOURCE_FREEZE_PATH = ROOT / 'research/test080-prebuild-source-private.json'
HELPER_SOURCE = ROOT / 'arm_p2p_rx149_probe.swift'
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


def _is_sha256(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def test080_metadata_problems(metadata, boot_epoch=None, identity=None, root=ROOT):
    """Validate the frozen Test080 identity/profile contract without side effects."""
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
            if (not isinstance(name, str) or path.is_absolute() or
                    '..' in path.parts or not path.parts or not _is_sha256(digest)):
                problems.append('source_sha256_entry')
                break
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
    reported_freeze = metadata.get('source_freeze_report')
    if isinstance(reported_freeze, str):
        reported_path = Path(reported_freeze)
        if not reported_path.is_absolute():
            reported_path = Path(root) / reported_path
        try:
            if reported_path.resolve() != SOURCE_FREEZE_PATH.resolve():
                problems.append('source_freeze_report')
        except OSError:
            problems.append('source_freeze_report')
    else:
        problems.append('source_freeze_report')

    if identity is not None:
        if identity.get('binary_identity_verified') is not True:
            problems.append('binary_identity')
        if identity.get('loaded_uuid') != expected_uuid:
            problems.append('loaded_uuid')

    if root is not None:
        root = Path(root)
        try:
            if BUILD_PATH.is_symlink() or SOURCE_FREEZE_PATH.is_symlink():
                raise ValueError('symlinked build/source report')
            build = json.loads(BUILD_PATH.read_text())
            frozen = json.loads(SOURCE_FREEZE_PATH.read_text())
            if (build.get('candidate') != BUILD or
                    build.get('source_freeze_matches') is not True or
                    build.get('binary_sha256') != metadata.get('expected_binary_sha256') or
                    build.get('info_plist_sha256') != metadata.get('expected_info_plist_sha256') or
                    build.get('arm_helper_source_sha256') != metadata.get('expected_arm_helper_source_sha256') or
                    build.get('mach_o_uuid') != expected_uuid or
                    build.get('source_file_count') != len(source_hashes or {}) or
                    build.get('full_build_passed') is not True or
                    build.get('strict_signature_passed') is not True or
                    build.get('installed') is not False or
                    build.get('rf_tested') is not False):
                problems.append('build_identity_or_frozen_manifest')
            if (Path(build.get('source_freeze_report', '')).resolve() !=
                    SOURCE_FREEZE_PATH.resolve()):
                problems.append('build_source_freeze_report')
            if (frozen.get('candidate') != BUILD or
                    frozen.get('source_sha256') != source_hashes):
                problems.append('source_manifest_mismatch')
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            problems.append('build_or_source_report_unavailable')
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
    prefixes = ('NativeP2PRx149', 'NativeP2PRxTrace', 'NativeP2PRoc')
    exact = set(ATTEMPT_STATE_PROPERTIES) | {
        'NativeP2PManualArmed', 'NativeP2PProbeContextGeneration',
        'NativeP2PProbePowerGeneration', 'NativeP2PProbeStationGeneration',
    } | set(PEER_ANONYMOUS_PROPERTIES)
    return {key: value for key, value in values.items()
            if (key.startswith(prefixes) or key in exact) and
            (type(value) is int if key in PEER_ANONYMOUS_PROPERTIES else
             type(value) in (int, bool))}


def rx_trace_snapshot_complete(trace_evidence, post):
    """Require producer closure, stable snapshot, drain, and no trace loss."""
    trace_values = trace_evidence.get('values', {}) if isinstance(trace_evidence, dict) else {}
    required = {
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
    values_valid = all(type(post.get(key)) is int and post.get(key) == expected
                       for key, expected in required.items())
    event_count = trace_values.get('NativeP2PRxTraceEventCount')
    return (trace_evidence.get('valid') is True and values_valid and
            type(event_count) is int and event_count >= 0)


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
            for number in range(65, 80)]


def consume_boot_claim(claim_dir, boot_epoch, observation_id):
    """Atomically spend the shared boot claim; failed arm attempts never retry."""
    claim_dir = Path(claim_dir)
    if any(path.exists() or path.is_symlink() for path in _legacy_claims(claim_dir, boot_epoch)):
        raise FileExistsError('Same-boot legacy claim exists; no Test080 arm permitted')
    claim_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = claim_dir / ('boot-' + str(boot_epoch) + '.json')
    payload = {
        'schema': 1, 'test_scope': 'Test080', 'build': BUILD,
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
        raise ValueError('Test080 metadata is a symlink')
    return json.loads(METADATA_PATH.read_text())


def _native_preflight(metadata, boot_epoch):
    identity = loaded_identity(BUILD)
    identity_problems = test080_metadata_problems(
        metadata, boot_epoch=boot_epoch, identity=identity, root=ROOT)
    if identity_problems:
        raise ValueError('Test080 identity/source gate failed: ' + ','.join(identity_problems))
    wrapper = properties('IOPCIEDeviceWrapper')
    if wrapper.get('NativeTestBuild') != BUILD:
        raise ValueError('Loaded wrapper build does not match Test080')
    state = properties('AirportItlwm')
    profile_errors = profile_problems(state, selected=False)
    if profile_errors:
        raise ValueError('Test080 RX149 profile gate failed: ' + ','.join(profile_errors))
    if state.get('NativePowerReady') != 1:
        raise ValueError('Intel Wi-Fi power is not ready')
    for key in ('NativeP2PManualArmed', 'NativeP2PProbeAttempted',
                'NativeP2PProbeResourceMayExist'):
        if type(state.get(key)) is not int or state[key] != 0:
            raise ValueError('Test080 one-shot state is nonzero or unknown: ' + key)
    counters = {key: state.get(key) for key in TX_ZERO_COUNTERS}
    evidence = tx_zero_evidence(counters, counters)
    if not evidence['valid']:
        raise ValueError('Test080 pre-arm TX counters are nonzero or unknown')
    return identity, state, evidence


def _compile_arm_helper(temp_dir):
    output = Path(temp_dir) / 'arm-p2p-rx149'
    result = subprocess.run(['/usr/bin/swiftc', '-O', '-o', str(output),
                             str(HELPER_SOURCE)], capture_output=True, text=True,
                            timeout=20)
    if result.returncode != 0 or not output.is_file() or output.is_symlink():
        raise RuntimeError('Test080 helper compilation failed')
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
        raise SystemExit('Test080 is disarmed by default; no system state read or claim')
    if not args.receiver_gated or not args.router_observation_id:
        raise SystemExit('Test080 requires the receiver-gated coordinator; unchanged')
    if os.geteuid() != 0 or args.expect_build != BUILD or not args.phone_ready:
        raise SystemExit('Require root, Test080 and freshly confirmed phone; unchanged')
    if not fresh_observation_id(args.router_observation_id):
        raise SystemExit('Invalid Test080 observation id; unchanged')
    metadata = _load_metadata()
    if metadata.get('armed') is not True:
        raise SystemExit('Test080 metadata is disarmed; no boot claim or RF action')
    boot = _sysctl_boot_epoch()
    metadata_problems = test080_metadata_problems(metadata, boot_epoch=boot, root=ROOT)
    if metadata_problems:
        raise SystemExit('Test080 metadata gate failed; no boot claim; fields=' + ','.join(metadata_problems))
    identity, initial, initial_zero = _native_preflight(metadata, boot)
    account = pwd.getpwuid(ROOT.stat().st_uid)
    if not args.output:
        raise SystemExit('Missing private Test080 output directory; unchanged')
    folder = _require_private_output(args.output, account)
    report_path = folder / 'native-rx149-observation-private.json'
    if report_path.exists() or report_path.is_symlink():
        raise SystemExit('Test080 output already exists; no capture or retry')
    report = {
        'schema': 1, 'build': BUILD, 'boot_epoch': boot,
        'observation_id': args.router_observation_id,
        'profile': PROFILE, 'identity': identity,
        'arm_attempted': False, 'retry_allowed': False,
        'rf_manual_only': True, 'diagnostic_duration_ms': 100,
        'receiver_gated': True, 'receiver_ready_before_arm': False,
        'efi_modified': False, 'ap_modified': False,
        'tx_zero_window': initial_zero,
        'rx149_initial': rx149_snapshot(initial),
        'peer_table_evidence': peer_evidence_delta(initial, initial),
        'attempt_state_initial': attempt_state_snapshot(initial),
        'rx149_after': None,
        'attempt_state_samples': [],
        'attempt_state_after': None,
        'roc_session_complete': False,
        'roc_session_problems': None,
        'session_complete': False,
        'rx_trace_evidence': None,
        'rx_trace_properties': None,
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
        'scope': 'One receiver-gated 100 ms Test080 RX149 session. Closed driver RX trace/descriptor evidence and independent OpenWrt PCAP are separate evidence sources; neither alone proves peer identity, native awdl0 reply, or AirDrop.',
        'status': 'preflight_passed_waiting_for_receiver',
    }
    _save_private_json(report_path, report, account)
    with tempfile.TemporaryDirectory(prefix='intel-test080-', dir='/private/tmp') as temp_dir:
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
    after = samples[-1] if samples else {}
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
    report['status'] = ('rx149_session_complete_no_peer_claim' if
        report['session_complete']
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
        raise SystemExit('Test080 is disarmed by default; no system state read or claim')
    return _native_worker(args)


if __name__ == '__main__':
    raise SystemExit(main())
