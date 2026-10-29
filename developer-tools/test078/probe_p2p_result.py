#!/usr/bin/env python3
"""Read one-shot P2P command-probe results; never submit commands or change power."""
import datetime
import argparse
import json
import hashlib
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

from probe_wifi_rate import properties, ready


def loaded_identity(expected):
    """Correlate the loaded Mach-O UUID with the archived, hashed artifact."""
    suffix = expected.split('-')[-1].lower()
    if not suffix.startswith('test') or not suffix[4:].isdigit():
        raise ValueError('Expected build must end with TestNNN')
    root = Path(__file__).resolve().parent
    metadata = json.loads((root / ('research/' + suffix + '-build-private.json')).read_text())
    if metadata.get('candidate') != expected:
        raise ValueError('Build record candidate mismatch')
    archive = Path(metadata['archive'])
    if hashlib.sha256(archive.read_bytes()).hexdigest() != metadata['archive_sha256']:
        raise ValueError('Archived artifact hash mismatch')
    with zipfile.ZipFile(archive) as z:
        binary = z.read('AirportItlwm.kext/Contents/MacOS/AirportItlwm')
    if hashlib.sha256(binary).hexdigest() != metadata['binary_sha256']:
        raise ValueError('Archived binary hash mismatch')
    with tempfile.TemporaryDirectory(prefix='intel-identity-', dir='/private/tmp') as temp:
        executable = Path(temp) / 'AirportItlwm'
        executable.write_bytes(binary)
        output = subprocess.check_output(['xcrun', 'dwarfdump', '--uuid', str(executable)], text=True)
    expected_uuids = re.findall(r'UUID: ([0-9A-F-]{36}) \(x86_64\)', output)
    loaded = subprocess.check_output(['/usr/bin/kmutil', 'showloaded', '--list-only'],
                                     text=True, stderr=subprocess.DEVNULL)
    loaded_uuids = re.findall(r'org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})', loaded)
    matched = len(expected_uuids) == 1 and loaded_uuids == expected_uuids
    return {'archive_uuid': expected_uuids[0] if len(expected_uuids) == 1 else None,
            'loaded_uuid': loaded_uuids[0] if len(loaded_uuids) == 1 else None,
            'binary_identity_verified': matched}




def peer_runtime_diagnostics(p2p):
    """Keep paired raw peer timing distinct from clock/schedule proof."""
    prefix = 'NativeP2PPeerState'
    raw = {k[len(prefix):]: v for k, v in p2p.items() if k.startswith(prefix)}
    samples = []
    count = raw.get('TimingCount', 0)
    if type(count) is int and 0 <= count <= 3:
        for i in range(count):
            sample = {key: raw.get('Sample' + str(i) + key)
                      for key in ('RxHostUs', 'RxGp2Us', 'PhyTxUs', 'Present', 'Subtype')}
            samples.append(sample)
    channels = []
    lo, hi = raw.get('ChannelsLo'), raw.get('ChannelsHi')
    if all(type(x) is int and -(1 << 63) <= x <= 0xffffffffffffffff for x in (lo, hi)):
        lo &= 0xffffffffffffffff
        hi &= 0xffffffffffffffff
        channels = [((lo if i < 8 else hi) >> (8 * (i % 8))) & 255
                    for i in range(16)]
    current = (raw.get('MifFresh') == 1 and raw.get('HasMif') == 1 and
               raw.get('SyncConsistent') == 1 and raw.get('Context', 0) > 0 and
               raw.get('Context') == p2p.get('NativeP2PProbeContextGeneration') and
               raw.get('PowerGeneration') == p2p.get('NativeP2PProbePowerGeneration') and
               raw.get('StationGeneration') == p2p.get('NativeP2PProbeStationGeneration'))
    paired = (bool(samples) and len(samples) == count and
              all(x['Present'] == 1 and type(x['RxHostUs']) is int and
                  x['RxHostUs'] > 0 and all(type(x[k]) is int and
                  0 <= x[k] <= 0xffffffff for k in ('RxGp2Us', 'PhyTxUs'))
                  for x in samples) and
              all(a['RxHostUs'] < b['RxHostUs'] for a, b in zip(samples, samples[1:])))
    deltas = []
    if paired:
        for a, b in zip(samples, samples[1:]):
            local = (b['RxGp2Us'] - a['RxGp2Us']) & 0xffffffff
            peer = (b['PhyTxUs'] - a['PhyTxUs']) & 0xffffffff
            deltas.append({'rx_gp2_elapsed_us': local, 'peer_phy_elapsed_us': peer,
                           'from_subtype': a.get('Subtype'),
                           'to_subtype': b.get('Subtype'),
                           'same_source_type': (a.get('Subtype') in (0, 3) and
                                                a.get('Subtype') == b.get('Subtype')),
                           'both_forward_under_half_range':
                               0 < local < 0x80000000 and 0 < peer < 0x80000000})
    psf_current = (raw.get('PsfFresh') == 1 and raw.get('PsfHas') == 1 and
                   raw.get('PsfSyncConsistent') == 1 and
                   raw.get('PsfContext', 0) > 0 and
                   raw.get('PsfContext') == p2p.get('NativeP2PProbeContextGeneration') and
                   raw.get('PsfPowerGeneration') == p2p.get('NativeP2PProbePowerGeneration') and
                   raw.get('PsfStationGeneration') == p2p.get('NativeP2PProbeStationGeneration'))
    psf_slots = []
    psf_lo, psf_hi = raw.get('PsfChannelsLo'), raw.get('PsfChannelsHi')
    if all(type(x) is int and -(1 << 63) <= x <= 0xffffffffffffffff for x in (psf_lo, psf_hi)):
        psf_lo &= 0xffffffffffffffff
        psf_hi &= 0xffffffffffffffff
        psf_slots = [((psf_lo if i < 8 else psf_hi) >> (8 * (i % 8))) & 255
                     for i in range(16)]
    return {'supported': bool(raw), 'raw': raw, 'representative_mif_current': current,
            'last_mif_decode_is_lifetime_history': True,
            'last_psf_decode_is_lifetime_history': True,
            'representative_psf_current': psf_current,
            'psf_channel_slots': psf_slots,
            'raw_pairs_present_ordered': paired, 'timing_samples': samples,
            'channel_slots': channels, 'raw_delta_observations': deltas,
            'mapping_proven': False, 'schedule_permission': False,
            'scope': 'Per-peer same-frame scalar observations only; stale MIF history is not current election, synchronization or TX permission'}


def gp2_observation_diagnostics(p2p):
    """Summarize raw brackets without manufacturing a verified clock map."""
    keys = ('Observation', 'PreStatus', 'PostStatus', 'PreValue', 'PostValue',
            'PreHostBeforeUs', 'PreHostAfterUs', 'PostHostBeforeUs',
            'PostHostAfterUs', 'PreGeneration', 'PostGeneration',
            'PrphAddress', 'DeviceFamily', 'PowerGeneration',
            'StationGeneration', 'MappingProven', 'DriftBoundProven')
    raw = {key: p2p.get('NativeP2PGp2' + key) for key in keys}
    result = {'raw': raw, 'raw_pair_valid': False, 'mapping_proven': False,
              'scope': 'Two raw device/host observations only; no verified drift, peer time, TX timing or scheduler permission'}
    generation = p2p.get('NativeP2PProbeContextGeneration')
    if (raw['Observation'] is not True or raw['PreStatus'] != 1 or
            raw['PostStatus'] != 1 or not isinstance(generation, int) or
            generation <= 0 or raw['PreGeneration'] != generation or
            raw['PostGeneration'] != generation):
        return result
    scalar = [raw[key] for key in ('PreValue', 'PostValue',
        'PreHostBeforeUs', 'PreHostAfterUs', 'PostHostBeforeUs', 'PostHostAfterUs')]
    if not all(type(value) is int and value >= 0 for value in scalar):
        return result
    pre, post, before, after, later_before, later_after = scalar
    if not (pre <= 0xffffffff and post <= 0xffffffff and
            before <= after < later_before <= later_after):
        return result
    delta = (post - pre) & 0xffffffff
    if not 0 < delta < 0x80000000:
        return result
    result.update(raw_pair_valid=True, device_elapsed_us=delta,
                  host_elapsed_min_us=later_before - after,
                  host_elapsed_max_us=later_after - before,
                  pre_bracket_us=after - before,
                  post_bracket_us=later_after - later_before)
    return result


def awdl_receive_diagnostics(p2p):
    """Decode numeric-only TLV metadata; never expose peer addresses/payloads."""
    prefix = 'NativeP2PRxLastReject'
    reason = p2p.get(prefix + 'Reason')
    names = {0: 'None', 1: 'LengthOverrun', 2: 'InvalidValue', 3: 'ArpaInPsf',
             4: 'DuplicateRequired', 5: 'RequiredOrder', 6: 'MissingRequired',
             7: 'EmptyList'}
    data_path_prefix = prefix + 'DataPath'
    data_path_stages = {0: 'None', 1: 'Flags', 2: 'CountryCode',
                        3: 'SocialChannels', 4: 'InfrastructureInfo',
                        5: 'InfrastructureAddress', 6: 'AwdlAddress',
                        7: 'Umi', 8: 'OptionsLength', 9: 'OptionsData',
                        10: 'UnsupportedExtFlags', 11: 'LogTrigger',
                        12: 'Rlfc', 13: 'ActiveTimeCounters',
                        14: 'TrailingBytes', 15: 'ExtendedFlags'}
    data_path_stage = p2p.get(data_path_prefix + 'RejectStage')
    data_path = {
        'supported': data_path_stage is not None,
        'reject_stage': data_path_stage,
        'reject_stage_name': data_path_stages.get(data_path_stage, 'Unknown'),
        'offset_in_value': p2p.get(data_path_prefix + 'Offset'),
    }
    for field in ('Flags', 'ExtFlags', 'OptionsLength'):
        present = p2p.get(data_path_prefix + field + 'Present')
        data_path[field + '_present'] = present
        data_path[field] = p2p.get(data_path_prefix + field) if present == 1 else None
    history_keys = {
        'candidate_frames_total': 'NativeP2PPeerCandidateFramesTotal',
        'psf_frames_total': 'NativeP2PPeerPSFFramesTotal',
        'mif_frames_total': 'NativeP2PPeerMIFFramesTotal',
        'admission_count_total': 'NativeP2PPeerAdmissionCountTotal',
        'update_count_total': 'NativeP2PPeerUpdateCountTotal',
        'last_admission_context_generation': 'NativeP2PPeerHistoryLastAdmissionContextGeneration',
        'active_window_peak_valid_count': 'NativeP2PPeerHistoryActiveWindowPeakValidCount',
        'active_window_peak_context_generation': 'NativeP2PPeerHistoryActiveWindowPeakContextGeneration',
    }
    peer_history = {'supported': history_keys['candidate_frames_total'] in p2p}
    peer_history.update({key: p2p.get(value) for key, value in history_keys.items()})
    count = p2p.get(prefix + 'TraceCount', 0)
    lo = p2p.get(prefix + 'TypeTraceLo', 0) & ((1 << 64) - 1)
    hi = p2p.get(prefix + 'TypeTraceHi', 0) & ((1 << 64) - 1)
    types = [((lo if i < 8 else hi) >> (8 * (i % 8))) & 0xff
             for i in range(min(max(count, 0), 16))]
    return {'envelopes': p2p.get('NativeP2PRxEnvelopeSeen'),
            'parsed_frames': p2p.get('NativeP2PRxActionFrames'),
            'parse_rejected': p2p.get('NativeP2PRxParseRejected'),
            'valid_peer_count': p2p.get('NativeP2PPeerCount'),
            'peer_history': peer_history,
            'queue_full': p2p.get('NativeP2PRxQueueFull'),
            'last_parse_status': p2p.get('NativeP2PRxLastParseStatus'),
            'data_path_diagnostics': data_path,
            'tlv_diagnostics_supported': reason is not None,
            'last_reject_reason': names.get(reason, 'Unknown') if reason is not None else None,
            'last_reject_fields': {key[len(prefix):]: value for key, value in p2p.items()
                                   if key.startswith(prefix)},
            'tlv_type_trace': types, 'trace_truncated': count > 16}


def awdl_transmit_diagnostics(p2p):
    prefix = 'NativeP2PAwdlPsf'
    statuses = {0: 'NotRequested', 1: 'WaitingForStart', 2: 'EncodedBlocked',
                3: 'CandidateRejected', 4: 'SubmissionAttempted',
                5: 'CandidateStale', 6: 'EndedBeforeSubmit',
                7: 'EncodedEligible', 8: 'StartWithoutCandidate',
                9: 'FirmwareTxCompleted', 10: 'FirmwareFrameFailed'}
    status = p2p.get(prefix + 'ObservationOnlyStatus')
    fields = ('TxBlockers', 'ProductionBlockers', 'FrameLength',
              'ClockMappingProven', 'ScheduleExpiryProven',
              'AdvertisedCoverageProven', 'DataPathAdvertised',
              'TxComplete', 'TxSucceeded', 'TxStatus', 'FrameSubmitted',
              'PeerAcknowledged', 'StartObservedMonotonicUs',
              'CandidateBuiltMonotonicUs', 'HardDeadlineMonotonicUs',
              'HostTxGateMonotonicUs', 'HostLeaseRemainingAtGateUs')
    mif_status = p2p.get('NativeP2PAwdlMifFollowupStatus')
    mif_names = {0: 'NotRequested', 1: 'WaitingForPsfCompletion',
                 2: 'CandidateEncodedReady', 3: 'PreflightRejected',
                 4: 'FirstPsfFailed', 5: 'EndedBeforeSubmit',
                 6: 'SubmissionAttempted', 7: 'CandidateStale',
                 8: 'FirmwareTxCompleted', 9: 'FirmwareFrameFailed',
                 10: 'Quarantined', 11: 'PsfNotSubmitted',
                 12: 'SubmissionFailed'}
    mif_fields = ('TxBlockers', 'FrameLength', 'FrameSubmitted', 'TxAttempted',
                  'TxComplete', 'TxSucceeded', 'TxStatus',
                  'PeerAcknowledged', 'DataPathAdvertised')
    return {'supported': 'NativeP2PAwdlPsfObservationOnly' in p2p,
            'observation_only_enabled': p2p.get('NativeP2PAwdlPsfObservationOnly'),
            'frame_kind': p2p.get('NativeP2PTxFrameKind'),
            'status': status, 'status_name': statuses.get(status, 'Unavailable'),
            'diagnostics': {key: p2p.get(prefix + key) for key in fields},
            'mif_followup': {
                'enabled': p2p.get('NativeP2PAwdlMifFollowup'),
                'status': mif_status, 'status_name': mif_names.get(mif_status, 'Unavailable'),
                'diagnostics': {key: p2p.get('NativeP2PAwdlMif' + key)
                                for key in mif_fields},
                'frames_submitted': p2p.get('NativeP2PAwdlActionFramesSubmitted'),
                'frames_completed': p2p.get('NativeP2PAwdlActionFramesCompleted'),
                'frames_succeeded': p2p.get('NativeP2PAwdlActionFramesSucceeded'),
                'two_frame_complete': p2p.get('NativeP2PAwdlPsfMifTwoFrameComplete'),
                'two_frame_succeeded': p2p.get('NativeP2PAwdlPsfMifTwoFrameSucceeded')},
            'scope': 'Experimental control-only PSF; firmware completion is not on-air timing, peer delivery, native awdl0 or AirDrop proof'}


def classify_mif_followup(p2p, base_verdict, linked, mac_passed,
                          roc_passed, roc_ended_known, tx_passed):
    """Keep first-frame completion, partial burst and last-ticket ownership separate."""
    if (p2p.get('NativeP2PAwdlMifFollowup') is not True or
            p2p.get('NativeP2PProbeAttempted') != 1):
        return base_verdict
    retired = mac_passed and roc_ended_known and all(p2p.get(key) == 0 for key in (
        'NativeP2PTxProbeRingMayExist', 'NativeP2PTxProbeOutstandingTx',
        'NativeP2PTxProbeQueueState', 'NativeP2PTxProbeStationState'))
    first_passed = all(p2p.get('NativeP2PAwdlPsf' + key) == value for key, value in (
        ('FrameSubmitted', 1), ('TxComplete', 1), ('TxSucceeded', 1),
        ('ObservationOnlyStatus', 9))) and p2p.get('NativeP2PAwdlPsfTxStatus', 0) & 0xff == 1
    second_passed = all(p2p.get('NativeP2PAwdlMif' + key) == value for key, value in (
        ('FrameSubmitted', 1), ('TxComplete', 1), ('TxSucceeded', 1),
        ('FollowupStatus', 8))) and p2p.get('NativeP2PAwdlMifTxStatus', 0) & 0xff == 1
    counts_passed = all(p2p.get('NativeP2PAwdlActionFrames' + key) == 2
                        for key in ('Submitted', 'Completed', 'Succeeded'))
    if (retired and roc_passed and tx_passed and first_passed and second_passed
            and counts_passed and p2p.get('NativeP2PAwdlPsfMifTwoFrameComplete') == 1
            and p2p.get('NativeP2PAwdlPsfMifTwoFrameSucceeded') == 1):
        return ('observation_PSF_MIF_firmware_TX_and_cleanup_passed' if linked
                else 'observation_PSF_MIF_TX_passed_wifi_not_ready')
    if (retired and first_passed
            and p2p.get('NativeP2PAwdlMifFrameSubmitted') == 0
            and p2p.get('NativeP2PAwdlMifFollowupStatus') in (3, 5, 7, 11, 12)
            and p2p.get('NativeP2PAwdlActionFramesSubmitted') == 1
            and p2p.get('NativeP2PAwdlActionFramesCompleted') == 1):
        return 'PSF_completed_MIF_not_sent_resources_retired'
    if (retired and first_passed
            and p2p.get('NativeP2PAwdlMifFrameSubmitted') == 1
            and p2p.get('NativeP2PAwdlMifTxComplete') == 1
            and p2p.get('NativeP2PAwdlMifTxSucceeded') == 0):
        return 'PSF_completed_MIF_firmware_failed_resources_retired'
    return base_verdict


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-build', default='25G241-Test025')
    args = parser.parse_args()
    build = properties('IOPCIEDeviceWrapper').get('NativeTestBuild')
    reported_build = build
    identity = loaded_identity(args.expect_build)
    if identity['binary_identity_verified']:
        build = args.expect_build
    power = properties('AirportItlwm')
    linked = ready('en1')
    p2p = {k: v for k, v in power.items() if k.startswith('NativeP2P')}
    mac_passed = (p2p.get('NativeP2PProbeState') == 7
          and p2p.get('NativeP2PProbeAttempted') == 1
          and p2p.get('NativeP2PProbeAddResult') == 0
          and p2p.get('NativeP2PProbeRemoveResult') == 0
          and p2p.get('NativeP2PProbeResourceMayExist') == 0)
    roc_ended_known = (p2p.get('NativeP2PRocStage') in (5, 27)
          and p2p.get('NativeP2PRocGeneration') == p2p.get('NativeP2PProbeContextGeneration')
          and p2p.get('NativeP2PRocStartSeen') == 1
          and p2p.get('NativeP2PRocEndSeen') == 1
          and p2p.get('NativeP2PRocStartStatus') == 1
          and p2p.get('NativeP2PRocEndStatus') in (0, 1)
          and p2p.get('NativeP2PRocCleanupAllowed') == 1
          and p2p.get('NativeP2PRocUnknown') == 0)
    roc_finished = (roc_ended_known
          and p2p.get('NativeP2PRocObserved') == 1
          and p2p.get('NativeP2PRocEndStatus') == 1)
    # The shared ROC result also carries a completed frame's TX error.
    roc_passed = roc_finished and p2p.get('NativeP2PRocResult') == 0
    tx_passed = (p2p.get('NativeP2PTxProbeStage') == 27
          and p2p.get('NativeP2PTxProbeResult') == 0
          and p2p.get('NativeP2PTxProbeTicketCompleted') == 1
          and p2p.get('NativeP2PTxProbeAttemptSucceeded') == 1
          and p2p.get('NativeP2PTxProbeStatus', 0) & 0xff == 1
          and p2p.get('NativeP2PTxProbeRingMayExist') == 0
          and p2p.get('NativeP2PTxProbeOutstandingTx') == 0
          and p2p.get('NativeP2PTxProbeQueueState') == 0
          and p2p.get('NativeP2PTxProbeStationState') == 0)
    tx_failed_and_retired = (p2p.get('NativeP2PTxProbeStage') == 27
          and p2p.get('NativeP2PTxProbeTicketCompleted') == 1
          and p2p.get('NativeP2PTxProbeAttemptSucceeded') == 0
          and p2p.get('NativeP2PTxProbeStatus', 0) & 0xff != 1
          and p2p.get('NativeP2PTxProbeRingMayExist') == 0
          and p2p.get('NativeP2PTxProbeOutstandingTx') == 0
          and p2p.get('NativeP2PTxProbeQueueState') == 0
          and p2p.get('NativeP2PTxProbeStationState') == 0)
    probes_disabled = all(p2p.get(key) is False for key in (
        'NativeP2PProbe', 'NativeP2PRocProbe', 'NativeP2PTxProbe'))
    if (not identity['binary_identity_verified'] or
            reported_build != args.expect_build):
        verdict = 'expected_build_not_loaded'
    elif probes_disabled:
        verdict = ('automatic_P2P_probes_disabled_no_attempt'
                   if p2p.get('NativeP2PProbeAttempted', 0) == 0
                   and p2p.get('NativeP2PProbeResourceMayExist', 0) == 0
                   else 'probes_disabled_but_prior_resource_state_present')
    elif (p2p.get('NativeP2PManualTrigger') is True
          and p2p.get('NativeP2PManualArmed') == 0):
        verdict = ('manual_probe_waiting_for_admin_arm_no_attempt'
                   if p2p.get('NativeP2PProbeAttempted') == 0
                   and p2p.get('NativeP2PProbeResourceMayExist') == 0
                   else 'manual_probe_unarmed_but_resource_state_present')
    elif p2p.get('NativeP2PTxProbe') is True:
        if mac_passed and roc_passed and tx_passed:
            verdict = ('diagnostic_TX_completion_and_cleanup_passed' if linked
                       else 'diagnostic_TX_passed_wifi_not_ready')
        elif mac_passed and roc_ended_known and tx_passed:
            # A matching END with status 0 permits cleanup, but does not
            # establish a successful full scheduled dwell. Keep that boundary
            # visible instead of classifying a retired TX ticket as waiting.
            verdict = 'TX_succeeded_resources_retired_ROC_schedule_not_passed'
        elif mac_passed and roc_ended_known and tx_failed_and_retired:
            verdict = 'TX_completed_firmware_reported_failure_resources_retired'
        elif p2p.get('NativeP2PTxProbeStage') == 29:
            verdict = 'TX_probe_quarantined_do_not_toggle_or_retry_this_boot'
        elif (args.expect_build == '25G241-Test023'
              and p2p.get('NativeP2PTxProbeStage') == 28
              and p2p.get('NativeP2PTxQueueResponseValid') == 1
              and p2p.get('NativeP2PTxQueueResponseFlags', 0) != 0):
            verdict = 'TX_queue_flags_rejected_firmware_absence_not_proven_do_not_toggle'
        elif (mac_passed and p2p.get('NativeP2PTxProbeStage') == 28
              and p2p.get('NativeP2PTxProbeResult') == 102
              and p2p.get('NativeP2PTxProbeRingMayExist') == 0
              and p2p.get('NativeP2PTxProbeStationState') == 0
              and p2p.get('NativeP2PRocCleanupAllowed') == 1):
            verdict = 'TX_preflight_unsupported_no_frame_sent_safe_cleanup'
        elif (mac_passed and p2p.get('NativeP2PTxProbeStage') == 28
              and p2p.get('NativeP2PTxProbeRingMayExist') == 0
              and p2p.get('NativeP2PTxProbeStationState') == 0
              and p2p.get('NativeP2PTxProbeQueueState') == 0
              and p2p.get('NativeP2PTxProbeTicketArmed') == 0
              and p2p.get('NativeP2PRocCleanupAllowed') == 1
              and p2p.get('NativeP2PRocUnknown') == 0):
            verdict = 'TX_setup_failed_no_frame_sent_safe_cleanup'
        else:
            verdict = 'TX_probe_not_passed_or_waiting'
    elif args.expect_build == '25G241-Test019' and mac_passed and roc_passed:
        verdict = 'session_dwell_and_cleanup_passed' if linked else 'session_passed_wifi_not_ready'
    elif p2p.get('NativeP2PRocStage') == 6:
        verdict = 'ROC_quarantined_do_not_retry_in_this_boot'
    elif (args.expect_build == '25G241-Test019'
          and p2p.get('NativeP2PRocObserved') == 1
          and p2p.get('NativeP2PRocGeneration') != p2p.get('NativeP2PProbeContextGeneration')):
        verdict = 'historical_ROC_pass_current_epoch_changed'
    elif args.expect_build == '25G241-Test019' and mac_passed:
        verdict = 'MAC_passed_ROC_not_passed'
    elif mac_passed:
        verdict = 'MAC_command_ACK_pair_passed' if linked else 'MAC_ACK_passed_wifi_not_ready'
    elif p2p.get('NativeP2PProbeState') in (8, 9):
        verdict = 'probe_quarantined_do_not_retry_in_this_boot'
    else:
        verdict = 'waiting_for_admission_or_completion'
    observation_psf = p2p.get('NativeP2PAwdlPsfObservationOnly') is True
    if observation_psf and p2p.get('NativeP2PProbeAttempted') == 1:
        if mac_passed and roc_passed and tx_passed:
            if (p2p.get('NativeP2PTxFrameKind') == 2 and
                    p2p.get('NativeP2PAwdlPsfObservationOnlyStatus') == 9):
                verdict = ('observation_PSF_firmware_TX_and_cleanup_passed' if linked
                           else 'observation_PSF_TX_passed_wifi_not_ready')
            else:
                verdict = 'observation_profile_frame_kind_or_status_mismatch'
        elif (mac_passed and roc_ended_known and
              p2p.get('NativeP2PAwdlPsfObservationOnlyStatus') in (2, 3, 5, 6, 8) and
              p2p.get('NativeP2PTxProbeTicketArmed') == 0 and
              p2p.get('NativeP2PTxProbeTicketCompleted') == 0 and
              all(p2p.get(key) == 0 for key in (
                  'NativeP2PTxProbeRingMayExist', 'NativeP2PTxProbeOutstandingTx',
                  'NativeP2PTxProbeQueueState', 'NativeP2PTxProbeStationState'))):
            verdict = 'observation_PSF_not_sent_resources_retired'
    verdict = classify_mif_followup(p2p, verdict, linked, mac_passed,
                                    roc_passed, roc_ended_known, tx_passed)
    result = {
        'captured_at': datetime.datetime.now().isoformat(),
        'loaded_build': build,
        'reported_build_label': reported_build,
        'build_label_matches_binary': reported_build == build,
        'binary_identity': identity,
        'expected_build': args.expect_build,
        'wifi_ready': linked,
        'p2p_result_current_generation': (
            p2p.get('NativeP2PRocGeneration') ==
            p2p.get('NativeP2PProbeContextGeneration')),
        'verdict': verdict,
        'p2p': p2p,
        'awdl_receive': awdl_receive_diagnostics(p2p),
        'awdl_transmit': awdl_transmit_diagnostics(p2p),
        'gp2_observation': gp2_observation_diagnostics(p2p),
        'peer_runtime': peer_runtime_diagnostics(p2p),
        'scope': ('One manually armed PSF/MIF experiment; per-frame firmware TX completion is not peer delivery, aligned AWDL schedule, awdl0 or AirDrop proof'
                  if p2p.get('NativeP2PAwdlMifFollowup') is True else
                  'One experimental control-only PSF; firmware TX completion only, no peer delivery, aligned AWDL schedule, awdl0 or AirDrop proof'
                  if observation_psf else
                  'Automatic firmware probes disabled; ordinary Wi-Fi isolation only, not an AWDL/AirDrop transfer test'
                  if probes_disabled else
                  'One diagnostic broadcast Action TX and firmware completion only; no peer reception, awdl0, or AirDrop transfer proof'
                  if p2p.get('NativeP2PTxProbe') is True else
                  'Session dwell START/END and cleanup only; no RF TX, awdl0, or AirDrop transfer proof'
                  if args.expect_build == '25G241-Test019' else
                  'MAC firmware command ACKs only; no RF TX, ROC, awdl0, or AirDrop transfer proof'),
    }
    suffix = args.expect_build.split('-')[-1].lower()
    if not suffix.startswith('test') or not suffix[4:].isdigit():
        raise ValueError('Expected build must end with TestNNN')
    folder = Path(__file__).resolve().parent / ('research/' + suffix + '-runtime-private')
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = folder / 'p2p-result-numeric.json'
    target.write_text(json.dumps(result, indent=2) + '\n')
    target.chmod(0o600)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
