#!/usr/bin/env python3
"""One Test076 native discovery diagnostic; never run before fresh-boot/phone checks.

Request real native DNS-SD queries scoped to awdl0. Never inject synthetic
RX, claim peer receipt from local completion, retry an arm, or write EFI.
"""
import argparse,datetime,json,os,pathlib,pwd,re,select,socket,subprocess,sys,time,signal
from probe_wifi_rate import properties,ready
from probe_p2p_result import loaded_identity
from tools.awdl_ioreg_u32 import derive_rx_trace_guard_report

DATA_COUNTERS = (
    'NativeAwdlDataTxAccepted', 'NativeAwdlDataTxRejected',
    'NativeAwdlDataTxExpired', 'NativeAwdlDataTxEncoded',
    'NativeAwdlDataTxSubmitted', 'NativeAwdlDataTxCompleted',
    'NativeAwdlDataTxSucceeded', 'NativeAwdlDataTxFailed',
    'NativeAwdlDataTxStaleCompletion', 'NativeAwdlDataRxCaptured',
    'NativeAwdlDataRxRejected', 'NativeAwdlDataRxQueueFull',
    'NativeAwdlDataRxDecoded', 'NativeAwdlDataRxDelivered',
    'NativeAwdlDataRxInputFailed', 'NativeAwdlDataTxPending',
    'NativeAwdlDataRxPending', 'NativeAwdlDataGateChecks',
    'NativeAwdlDataGateAllowed', 'NativeAwdlDataGateReasonsSeen',
    'NativeAwdlDataIpv6ConfigResult', 'NativeAwdlDataIpv6Configured',
    'NativeAwdlDataOffloadCapabilities', 'NativeAwdlDataTxObservationCount',
    'NativeAwdlDataTxChecksumStatusSeenMask',
    'NativeAwdlDataTxSourceEui64MismatchCount',
    'NativeAwdlDataTxMulticastMappingMismatchCount',
    'NativeAwdlDataTxMalformedCount',
)
MDNS_CLASSES = ('Legacy', 'Qu', 'Qm', 'Other', 'Unknown')
MDNS_STAGES = ('Attempts', 'Submitted', 'Completed', 'Succeeded')
MDNS_COUNTERS = tuple(
    'NativeAwdlDataTxMdns' + name + stage
    for stage in MDNS_STAGES for name in MDNS_CLASSES
)
REQUIRED_COUNTERS = DATA_COUNTERS + MDNS_COUNTERS

# Test076's new fixed-capacity per-data-packet trace. The independent Revision
# detects ledger ABA/update races; SnapshotVersionBegin/End is the publication
# seqlock. A scalar's absence is always unknown, never defaulted to zero.
DATA_TX_TRACE_PREFIX = 'NativeP2PDataTxTrace'
DATA_TX_TRACE_CAPACITY = 8
DATA_TX_TRACE_HEADER_FIELDS = (
    'Revision', 'SnapshotVersionBegin', 'SnapshotVersionEnd',
    'SnapshotComplete', 'CoverageUnknown', 'ResponseTapMergeStatus',
    'StopTapMergeStatus', 'TxRspTapState', 'TxRspTapSequence',
    'TxRspTapConsumedSequence', 'TxRspTapDroppedCount',
    'TxRspTapActivePublicationSequence', 'TxRspTapActiveToken',
    'StopTapState', 'StopTapSequence', 'StopTapConsumedSequence',
    'StopTapDroppedCount', 'StopTapActivePublicationSequence',
    'StopTapActiveToken', 'SchemaVersion',
    'OwnerPresent', 'OwnerSerial', 'OwnerDiagnosticGeneration',
    'OwnerContextGeneration', 'OwnerPowerGeneration',
    'OwnerStationGeneration', 'OwnerRocGeneration', 'Count', 'DroppedCount',
    'FirmwareEchoesFullIdentity', 'AssociationStrengthCandidateOnly',
    'AssociationStrengthLocalScalarMatch',
    'AssociationStrengthExistingHandlerAccepted',
)
DATA_TX_TRACE_RECORD_FIELDS = (
    'RecordPresent', 'Used', 'RecordSerial', 'Token', 'DiagnosticGeneration',
    'ContextGeneration', 'PowerGeneration', 'StationGeneration',
    'RocGeneration', 'QueueMetadataPresent', 'QueryClass', 'Eligible', 'StagePresenceFlags',
    'QueueBornUs', 'DequeuedUs',
    'SubmitCallStartUs', 'FinalWireUs', 'RingReservedUs',
    'DescriptorReadyUs', 'DoorbellMarkedUs', 'DoorbellIssuedUs',
    'TxRspTapUs', 'CompletionUs', 'CancelUs', 'SubmitCallEndUs',
    'UnknownUs', 'EncodeFailureUs', 'StopUs',
    'FrameControl', 'SequenceControl', 'MpduLength',
    'PacketCount', 'IPv6Length', 'QueueId', 'RingSize',
    'DescriptorIndex', 'TxRspQueueId', 'TxRspRxHeaderIndex',
    'TxRspSequenceControl', 'TxRspByteCount', 'TxRspFrameControl',
    'TxRspStatus', 'TxRspRaTid', 'TxRspScdSsn', 'TxRspValidFields',
    'SubmitCallResult', 'CompletionResult', 'CancellationReason', 'AssociationStrength',
    'ResponseScalarMatchMask', 'ResponseMismatchMask', 'ResponseCandidateSeen',
    'TxRspHandlerDisposition', 'AmbiguousLateQueueUnknown', 'UnknownReason',
    'EncodeFailureResult', 'FirmwareEchoesFullIdentity',
    'StopNewGeneration', 'StopReason', 'StopProvenDrain',
)
DATA_TX_TRACE_TIMESTAMP_BITS = {
    0: 'QueueBornUs', 1: 'DequeuedUs', 2: 'SubmitCallStartUs',
    3: 'FinalWireUs', 4: 'RingReservedUs', 5: 'DescriptorReadyUs',
    6: 'DoorbellMarkedUs', 7: 'DoorbellIssuedUs', 8: 'TxRspTapUs',
    9: 'CompletionUs', 10: 'CancelUs', 11: 'SubmitCallEndUs',
    12: 'UnknownUs', 13: 'EncodeFailureUs', 14: 'StopUs',
}
DATA_TX_TRACE_U64_FIELDS = {
    'Revision', 'SnapshotVersionBegin', 'SnapshotVersionEnd',
    'TxRspTapSequence', 'TxRspTapConsumedSequence',
    'TxRspTapDroppedCount', 'TxRspTapActivePublicationSequence',
    'TxRspTapActiveToken', 'StopTapSequence', 'StopTapConsumedSequence',
    'StopTapDroppedCount', 'StopTapActivePublicationSequence',
    'StopTapActiveToken', 'OwnerSerial',
    'OwnerDiagnosticGeneration', 'OwnerContextGeneration',
    'OwnerPowerGeneration', 'OwnerStationGeneration', 'OwnerRocGeneration',
    'DroppedCount', 'RecordSerial', 'DiagnosticGeneration',
    'ContextGeneration', 'PowerGeneration', 'StationGeneration',
    'RocGeneration', 'Token',
    'QueueBornUs', 'DequeuedUs', 'SubmitCallStartUs', 'FinalWireUs',
    'RingReservedUs', 'DescriptorReadyUs', 'DoorbellMarkedUs',
    'DoorbellIssuedUs', 'TxRspTapUs', 'CompletionUs', 'CancelUs',
    'SubmitCallEndUs', 'UnknownUs', 'EncodeFailureUs', 'StopUs',
}
DATA_TX_TRACE_RECORD_U32_FIELDS = set(DATA_TX_TRACE_RECORD_FIELDS) - {
    'Token', 'DiagnosticGeneration', 'ContextGeneration', 'PowerGeneration',
    'StationGeneration', 'RocGeneration', *DATA_TX_TRACE_TIMESTAMP_BITS.values(),
}
DATA_TX_TRACE_IDENTITY_FIELDS = (
    'DiagnosticGeneration', 'ContextGeneration', 'PowerGeneration',
    'StationGeneration', 'RocGeneration',
)
DATA_TX_TRACE_OWNER_IDENTITY_FIELDS = (
    'OwnerDiagnosticGeneration', 'OwnerContextGeneration',
    'OwnerPowerGeneration', 'OwnerStationGeneration', 'OwnerRocGeneration',
)
DATA_TX_TRACE_RESPONSE_VALID_BITS = {
    'TxRspQueueId': 0,
    'TxRspRxHeaderIndex': 1,
    'TxRspSequenceControl': 2,
    'TxRspByteCount': 3,
    'TxRspFrameControl': 4,
    'TxRspStatus': 5,
    'TxRspRaTid': 6,
    'TxRspScdSsn': 7,
}
DATA_TX_TRACE_QUERY_CLASS_NAMES = {
    0: 'Unknown',
    1: 'LegacyUnicastReply',
    2: 'QuUnicastPreferred',
    3: 'QmMulticast',
    4: 'Other',
}
LEGACY_BOOT_CLAIM_SCOPES = tuple('Test0' + str(number) for number in range(65, 76))
NATIVE_BROWSE_COMPLETION_GRACE_SECONDS = 1.5
NATIVE_BROWSE_TERMINATE_GRACE_SECONDS = 0.5
NATIVE_BROWSE_KILL_REAP_GRACE_SECONDS = 0.5
NON_MONOTONIC_COUNTERS = {
    'NativeAwdlDataTxPending', 'NativeAwdlDataRxPending',
    'NativeAwdlDataGateReasonsSeen', 'NativeAwdlDataIpv6ConfigResult',
    'NativeAwdlDataIpv6Configured', 'NativeAwdlDataOffloadCapabilities',
    'NativeAwdlDataTxChecksumStatusSeenMask',
}
MONOTONIC_COUNTERS = tuple(key for key in REQUIRED_COUNTERS
                           if key not in NON_MONOTONIC_COUNTERS)


def counter_problems(values):
    """Return absent and malformed counter names without inventing zeroes."""
    missing = [key for key in REQUIRED_COUNTERS if key not in values]
    invalid = [key for key in REQUIRED_COUNTERS
               if key in values and (type(values[key]) is not int or values[key] < 0)]
    return missing, invalid


def counter_regressions(values, baseline):
    """Return required counters that went backwards from a complete baseline."""
    return [key for key in MONOTONIC_COUNTERS
            if key in values and type(values[key]) is int and values[key] >= 0
            and values[key] < baseline[key]]


def data_tx_trace_scalar_snapshot(sample):
    """Return only the exact numeric Test076 trace whitelist."""
    keys = [DATA_TX_TRACE_PREFIX + field
            for field in DATA_TX_TRACE_HEADER_FIELDS]
    for slot in range(DATA_TX_TRACE_CAPACITY):
        keys.extend(DATA_TX_TRACE_PREFIX + 'Record' + str(slot) + field
                    for field in DATA_TX_TRACE_RECORD_FIELDS)
    result = {}
    for key in keys:
        if key not in sample:
            continue
        value = sample[key]
        result[key] = value if type(value) is int else {
            'invalid_type': type(value).__name__}
    return result


def guarded_data_tx_trace_evidence(pre, middle, post, current_attempt=None):
    """Validate three identical, stable snapshots of the owner-scoped TX ledger.

    The helper Revision may be odd: it is an independent mutation counter,
    not a seqlock. Published SnapshotVersionBegin/End must match and be even.
    Timestamps are emitted only when their StagePresenceFlags bit is present.
    """
    samples = (('pre', pre), ('middle', middle), ('post', post))
    missing, invalid, reasons = [], [], []
    typed = {}
    publication_stable = {}

    def exact_int(label, sample, key, width):
        if key not in sample:
            missing.append(label + '.' + key)
            return None
        value = sample[key]
        maximum = (1 << width) - 1
        if type(value) is not int or not 0 <= value <= maximum:
            invalid.append(label + '.' + key)
            return None
        return value

    for label, sample in samples:
        typed[label] = {}
        for field in DATA_TX_TRACE_HEADER_FIELDS:
            key = DATA_TX_TRACE_PREFIX + field
            width = 64 if field in DATA_TX_TRACE_U64_FIELDS else 32
            value = exact_int(label, sample, key, width)
            if value is not None:
                typed[label][field] = value
        for flag in ('OwnerPresent','FirmwareEchoesFullIdentity',
                     'SnapshotComplete','CoverageUnknown'):
            value = typed[label].get(flag)
            if value is not None and value not in (0, 1):
                invalid.append(label + '.' + DATA_TX_TRACE_PREFIX + flag)
        begin = typed[label].get('SnapshotVersionBegin')
        end = typed[label].get('SnapshotVersionEnd')
        publication_stable[label] = (begin is not None and end == begin and
                                     not (begin & 1))
        if begin is not None and end is not None and not publication_stable[label]:
            reasons.append(label + ':publication_seqlock_unstable')
        if typed[label].get('SchemaVersion') != 1:
            reasons.append(label + ':schema_not_v1')
        for slot in range(DATA_TX_TRACE_CAPACITY):
            record = {}
            for field in DATA_TX_TRACE_RECORD_FIELDS:
                key = DATA_TX_TRACE_PREFIX + 'Record' + str(slot) + field
                width = 64 if field in DATA_TX_TRACE_U64_FIELDS else 32
                value = exact_int(label, sample, key, width)
                if value is not None:
                    record[field] = value
            typed[label]['Record' + str(slot)] = record
            for flag in ('RecordPresent', 'Used', 'QueueMetadataPresent',
                         'Eligible', 'ResponseCandidateSeen',
                         'AmbiguousLateQueueUnknown','FirmwareEchoesFullIdentity',
                         'StopProvenDrain'):
                value = record.get(flag)
                if value is not None and value not in (0, 1):
                    invalid.append(label + '.' + DATA_TX_TRACE_PREFIX +
                                   'Record' + str(slot) + flag)
            stage_mask = record.get('StagePresenceFlags')
            if stage_mask is not None and stage_mask & ~0x7FFF:
                invalid.append(label + '.' + DATA_TX_TRACE_PREFIX +
                               'Record' + str(slot) + 'StagePresenceFlags')
            query_class = record.get('QueryClass')
            if (record.get('QueueMetadataPresent') == 1 and query_class is not None
                    and query_class not in DATA_TX_TRACE_QUERY_CLASS_NAMES):
                invalid.append(label + '.' + DATA_TX_TRACE_PREFIX +
                               'Record' + str(slot) + 'QueryClass')
            valid_fields = record.get('TxRspValidFields')
            if valid_fields is not None and valid_fields & ~0xFF:
                invalid.append(label + '.' + DATA_TX_TRACE_PREFIX +
                               'Record' + str(slot) + 'TxRspValidFields')

    prefix = DATA_TX_TRACE_PREFIX
    # Require all three complete scalar sets to be exactly the same. This
    # intentionally waits for a quiescent snapshot instead of joining races.
    three_reads_identical = False
    if not missing and not invalid:
        three_reads_identical = typed['pre'] == typed['middle'] == typed['post']
        if not three_reads_identical:
            reasons.append('three_reads_not_identical')
    # An odd or changing publication invalidates the old tap properties too.
    # Keep those scalars only as explicitly stale raw diagnostics; never infer
    # Pending/Unstable from fields left behind by the previous even snapshot.
    tap_publication_current = (
        not missing and not invalid and three_reads_identical and
        all(publication_stable.get(label, False) for label, _ in samples) and
        all(typed[label].get('SchemaVersion') == 1 for label, _ in samples)
    )
    if tap_publication_current:
        label = 'post'
        for tap in ('TxRspTap', 'StopTap'):
            state = typed[label].get(tap + 'State')
            sequence = typed[label].get(tap + 'Sequence')
            consumed = typed[label].get(tap + 'ConsumedSequence')
            status_field = ('ResponseTapMergeStatus' if tap == 'TxRspTap'
                            else 'StopTapMergeStatus')
            status = typed[label].get(status_field)
            if state is not None and state not in (0, 1, 2):
                invalid.append(label + '.' + DATA_TX_TRACE_PREFIX + tap + 'State')
            if status is not None and status > 14:
                invalid.append(label + '.' + DATA_TX_TRACE_PREFIX + status_field)
            if state in (1, 2):
                reasons.append(label + ':' + tap.lower() + '_unresolved')
            if (sequence is not None and consumed is not None and
                    sequence != consumed):
                reasons.append(label + ':' + tap.lower() + '_sequence_unconsumed')
            if sequence is not None and sequence & 1:
                reasons.append(label + ':' + tap.lower() + '_odd_sequence')
            active_publication = typed[label].get(
                tap + 'ActivePublicationSequence')
            if active_publication is not None and active_publication & 1:
                reasons.append(label + ':' + tap.lower() + '_active_tuple_unstable')
            if status in (13, 14):
                reasons.append(label + ':' + tap.lower() + '_merge_unresolved')
            if state == 0 and sequence is not None and consumed is not None and sequence != consumed:
                reasons.append(label + ':' + tap.lower() + '_empty_state_mismatch')
    stable = not missing and not invalid and not reasons
    records = []
    if stable:
        header = typed['post']
        if header['Revision'] != typed['pre']['Revision']:
            reasons.append('independent_revision_changed')
            stable = False
        if header['Count'] > DATA_TX_TRACE_CAPACITY:
            reasons.append('count_exceeds_capacity')
            stable = False
        if header['FirmwareEchoesFullIdentity'] != 0:
            reasons.append('firmware_full_identity_echo_contract_unexpected')
        coverage_unknown = header['CoverageUnknown']
        snapshot_complete = header['SnapshotComplete']
        tap_drops = (header['TxRspTapDroppedCount'] +
                     header['StopTapDroppedCount'])
        if snapshot_complete == coverage_unknown:
            reasons.append('snapshot_coverage_contract_invalid')
        if not coverage_unknown and (header['DroppedCount'] != 0 or tap_drops != 0):
            reasons.append('unreported_publisher_drop')
        merge_clean = all(header[field] in (0, 6) for field in (
            'ResponseTapMergeStatus', 'StopTapMergeStatus'))
        if snapshot_complete and (coverage_unknown or not merge_clean):
            reasons.append('snapshot_complete_with_incomplete_taps')
        if not snapshot_complete and not coverage_unknown:
            reasons.append('incomplete_snapshot_without_unknown_coverage')
        if ((header['AssociationStrengthCandidateOnly'],
             header['AssociationStrengthLocalScalarMatch'],
             header['AssociationStrengthExistingHandlerAccepted']) != (1, 2, 3)):
            reasons.append('association_strength_enum_contract_unexpected')
        if header['OwnerPresent']:
            if any(header.get(field, 0) == 0 for field in
                   ('OwnerSerial',) + DATA_TX_TRACE_OWNER_IDENTITY_FIELDS):
                reasons.append('owner_identity_incomplete')
                stable = False
        present_count = 0
        for slot in range(DATA_TX_TRACE_CAPACITY):
            record = header['Record' + str(slot)]
            if record['Used'] and not record['RecordPresent']:
                reasons.append('used_record_not_published:' + str(slot))
                continue
            if not record['RecordPresent'] or not record['Used']:
                continue
            present_count += 1
            if not header['OwnerPresent']:
                reasons.append('record_without_owner:' + str(slot))
            if record['Token'] == 0 or any(record.get(field, 0) == 0 for field in
                                           DATA_TX_TRACE_IDENTITY_FIELDS):
                reasons.append('record_identity_incomplete:' + str(slot))
            if record['RecordSerial'] == 0:
                reasons.append('record_serial_missing:' + str(slot))
            if record['AmbiguousLateQueueUnknown'] != 1:
                reasons.append('late_queue_ambiguity_not_explicit:' + str(slot))
            if record['FirmwareEchoesFullIdentity'] != 0:
                reasons.append('record_firmware_full_identity_echo_unexpected:' + str(slot))
            if record['AssociationStrength'] not in (1, 2, 3):
                reasons.append('association_strength_unknown:' + str(slot))
            if any(record[field] != header['Owner' + field]
                   for field in DATA_TX_TRACE_IDENTITY_FIELDS):
                reasons.append('record_owner_generation_mismatch:' + str(slot))
            if record['DiagnosticGeneration'] != header['OwnerSerial']:
                reasons.append('record_owner_serial_mismatch:' + str(slot))
            stage_mask = record['StagePresenceFlags']
            timestamps = []
            materialized = dict(record)
            for bit, field in DATA_TX_TRACE_TIMESTAMP_BITS.items():
                materialized[field] = record[field] if stage_mask & (1 << bit) else None
                if stage_mask & (1 << bit):
                    timestamps.append((bit, record[field]))
            for fields, bit in (
                (('FrameControl','SequenceControl','MpduLength',
                  'PacketCount','IPv6Length'),3),
                (('QueueId','RingSize'),4),
                (('DescriptorIndex',),5),
                (('TxRspHandlerDisposition',),8),
                (('SubmitCallResult',),11),
                (('CompletionResult',),9),
                (('CancellationReason',),10),
                (('UnknownReason',),12),
                (('EncodeFailureResult',),13),
                (('StopNewGeneration','StopReason','StopProvenDrain'),14),
            ):
                for field in fields:
                    materialized[field] = record[field] if stage_mask & (1 << bit) else None
            for field, bit in DATA_TX_TRACE_RESPONSE_VALID_BITS.items():
                materialized[field] = record[field] if record['TxRspValidFields'] & (1 << bit) else None
            metadata_present = record['QueueMetadataPresent'] == 1
            materialized['QueryClass'] = record['QueryClass'] if metadata_present else None
            materialized['Eligible'] = record['Eligible'] if metadata_present else None
            materialized['QueryClassName'] = (
                DATA_TX_TRACE_QUERY_CLASS_NAMES.get(record['QueryClass'])
                if metadata_present else None)
            for field in ('ResponseScalarMatchMask','ResponseMismatchMask'):
                materialized[field] = record[field] if record['ResponseCandidateSeen'] else None
            # The local submit chain is ordered, but the firmware TX_RSP tap,
            # completion, cancellation, stop tap and wrapper return are
            # asynchronous relative to one another. Check only edges the
            # producer API guarantees; never sort stage bits into one timeline.
            stage_times = {bit: value for bit, value in timestamps}
            causal_edges = (
                (0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6),
                (6, 7), (7, 11), (2, 11),
            )
            if any(left in stage_times and right in stage_times and
                   stage_times[left] > stage_times[right]
                   for left, right in causal_edges):
                reasons.append('causal_stage_timestamp_order_invalid:' + str(slot))
            if stage_mask & (1 << 14):
                stop_us = record['StopUs']
                stop_reason = record['StopReason']
                proven_drain = record['StopProvenDrain']
                doorbell_issued = bool(stage_mask & (1 << 7))
                if not stop_us or not record['StopNewGeneration']:
                    reasons.append('stop_identity_or_time_missing:' + str(slot))
                if doorbell_issued or not proven_drain:
                    if (not stage_mask & (1 << 12) or
                            record['UnknownUs'] != stop_us or
                            record['UnknownReason'] != stop_reason):
                        reasons.append('stop_unknown_association_incomplete:' + str(slot))
                elif (not stage_mask & (1 << 10) or
                      record['CancelUs'] != stop_us or
                      record['CancellationReason'] != stop_reason):
                    reasons.append('proven_stop_cancel_association_incomplete:' + str(slot))
            if stage_mask & (1 << 8):
                if not record['ResponseCandidateSeen']:
                    reasons.append('tx_response_stage_without_candidate:' + str(slot))
            records.append(materialized)
        if present_count != header['Count']:
            reasons.append('count_presence_mismatch')
    valid = stable and not reasons and not invalid and not missing
    dropped = typed.get('post', {}).get('DroppedCount')
    post_header = typed.get('post', {})
    raw_tap_publication = {
        'tx_response': {field: post_header.get('TxRspTap' + field)
                        for field in ('State','Sequence','ConsumedSequence',
                                      'DroppedCount','ActivePublicationSequence',
                                      'ActiveToken')},
        'stop': {field: post_header.get('StopTap' + field)
                 for field in ('State','Sequence','ConsumedSequence',
                               'DroppedCount','ActivePublicationSequence',
                               'ActiveToken')},
        'merge_status': {
            'tx_response': post_header.get('ResponseTapMergeStatus'),
            'stop': post_header.get('StopTapMergeStatus'),
        },
    }
    current_tap_publication = raw_tap_publication if tap_publication_current else None
    stale_tap_publication = (
        {'status': 'stale_unknown', 'raw_post': raw_tap_publication}
        if not tap_publication_current else None)
    publication_complete = (valid and post_header.get('SnapshotComplete') == 1 and
                            post_header.get('CoverageUnknown') == 0)
    current_attempt_expected = None
    current_attempt_bound = None
    freshness_status = 'not_assessed'
    freshness_reasons = []
    current_record_serial = None
    if current_attempt is not None:
        current_attempt_expected = current_attempt.get('attempt_expected')
        if current_attempt_expected is not True:
            freshness_status = ('clean_preflight' if current_attempt_expected is False
                                else 'unknown_attempt_state')
            if current_attempt_expected is None:
                freshness_reasons.append('current_attempt_state_missing')
        elif not valid or current_attempt.get('identity_ready') is not True:
            current_attempt_bound = False
            freshness_status = 'stale_unknown'
            freshness_reasons.append('current_attempt_identity_unavailable')
        else:
            expected_token = current_attempt.get('discovery_token')
            expected_generations = current_attempt.get('discovery_generations', {})
            matches = []
            for record in records:
                if record.get('Token') != expected_token:
                    continue
                if all(record.get(field) == expected_generations.get(field)
                       for field in DATA_TX_TRACE_IDENTITY_FIELDS):
                    matches.append(record)
            if len(matches) == 1:
                current_attempt_bound = True
                freshness_status = 'current_token_record_bound'
                current_record_serial = matches[0].get('RecordSerial')
            else:
                current_attempt_bound = False
                freshness_status = 'stale_unknown'
                freshness_reasons.append(
                    'current_token_record_missing_or_ambiguous')
    return {
        'status': ('stable_complete' if publication_complete else
                   'stable_incomplete_coverage' if valid else
                   'incomplete_or_unstable'),
        'valid': valid,
        'structurally_valid': valid,
        'publication_complete': publication_complete,
        'coverage_unknown': post_header.get('CoverageUnknown'),
        'current_attempt_expected': current_attempt_expected,
        'current_attempt_bound': current_attempt_bound,
        'freshness_status': freshness_status,
        'freshness_reasons': freshness_reasons,
        'current_record_serial': current_record_serial,
        'current_attempt_stage_coverage_complete': (
            bool(publication_complete and current_attempt_bound)
            if current_attempt_expected is True else None),
        'current_attempt_witness': current_attempt,
        'stage_coverage_complete': bool(publication_complete and dropped == 0),
        'missing_fields': sorted(set(missing)),
        'invalid_fields': sorted(set(invalid)),
        'reasons': sorted(set(reasons)),
        'revision': typed.get('post', {}).get('Revision'),
        'record_count': typed.get('post', {}).get('Count'),
        'dropped_count': dropped,
        'tap_publication_status': ('stable_current' if tap_publication_current
                                   else 'stale_unknown'),
        'tap_merge_status': (current_tap_publication['merge_status']
                             if current_tap_publication is not None else None),
        'tap_publication': current_tap_publication,
        'tap_publication_stale_raw': stale_tap_publication,
        'owner_present': typed.get('post', {}).get('OwnerPresent'),
        'owner_serial': typed.get('post', {}).get('OwnerSerial'),
        'owner_generations': {field:typed.get('post',{}).get('Owner'+field)
                              for field in DATA_TX_TRACE_IDENTITY_FIELDS},
        'firmware_echoes_full_identity':typed.get('post',{}).get('FirmwareEchoesFullIdentity'),
        'query_class_enum':dict(DATA_TX_TRACE_QUERY_CLASS_NAMES),
        'stop_observation_scope': 'StopObserved is per-record evidence. A stop after DoorbellIssued or without a proven drain is retained as unknown; only a proven-drained pre-doorbell stop is represented as cancellation.',
        'tx_rsp_rx_header_index_scope': 'TxRspRxHeaderIndex is the raw RX notification header index; it is not the TX descriptor index or ownership evidence.',
        'records': records if valid else [],
        'raw_zero_defaults_exported_as_values':False,
        'response_owner_proven': False,
        'association_scope': 'AssociationStrength and scalar match/mismatch masks describe local candidate/scalar/handler correlation only; firmware does not echo the host token or full generations.',
        'query_class_scope': 'QueryClass and Eligible are immutable native BSD queue-classifier metadata copied from DiscoveryTxSnapshot; they do not prove MPDU bytes, firmware ownership, or over-air query class.',
        'peer_receipt_proven': False,
        'airdrop_proven': False,
        'scope': 'Owner-scoped local TX identity/timing only; no RF airtime, peer receipt, RX delivery, or AirDrop proof.',
    }


# Optional ordinary-STA watchdog progress snapshot. This side channel is
# separate from AWDL DATA identity and is never a preflight gate. Its retained
# rows are the latest event per kind, not a packet queue or a full ring image.
TX_PROGRESS_PREFIX = 'NativeResetTraceTxProgress'
TX_PROGRESS_EVENT_COUNT = 6
TX_PROGRESS_ANCHOR_FIELDS = (
    'NativeResetTracePublishVersion', 'NativeResetTraceSchema',
    'NativeResetTraceTxWatchdogSequence',
    'NativeResetTraceTxWatchdogGeneration',
)
TX_PROGRESS_HEADER_U32_FIELDS = (
    'Schema', 'SnapshotVersionBegin', 'SnapshotVersionEnd',
    'SnapshotAvailable', 'SnapshotComplete', 'DroppedCountPresent',
    'NextSerialPresent', 'RingSnapshotComplete',
    'FirmwareResponseIdentityProven', 'SequenceIdentityProven',
    'OwnerWatchdogSequence', 'OwnerGeneration',
)
TX_PROGRESS_HEADER_U64_FIELDS = (
    'DroppedCount', 'NextSerial',
    *(f'ResponseReason{index}Count' for index in range(3)),
    *(f'GuardReason{index}Count' for index in range(2)),
    *(f'RunStopReason{index}Count' for index in range(2)),
)
TX_PROGRESS_EVENT_U32_FIELDS = (
    'Present', 'Generation', 'OutputEpoch', 'PresenceFlags', 'Reason',
    'Qid', 'Index', 'RingCount', 'Queued', 'Cur', 'Tail',
)
TX_PROGRESS_EVENT_U64_FIELDS = ('Count', 'Serial', 'MonotonicNs')
TX_PROGRESS_PRESENCE_BITS = {
    'Generation': 1 << 0,
    'OutputEpoch': 1 << 1,
    'MonotonicNs': 1 << 2,
    'Serial': 1 << 3,
    'Qid': 1 << 4,
    'Index': 1 << 5,
    'RingCount': 1 << 6,
    'Queued': 1 << 7,
    'Cur': 1 << 8,
    'Tail': 1 << 9,
}
TX_PROGRESS_EVENT_NAMES = (
    'Doorbell', 'ResponseDispatch', 'GuardDecision',
    'OrdinaryReclaim', 'FlushReclaim', 'RunStop',
)


def tx_progress_property_keys():
    keys = [TX_PROGRESS_PREFIX + field for field in
            TX_PROGRESS_HEADER_U32_FIELDS + TX_PROGRESS_HEADER_U64_FIELDS]
    keys.extend(TX_PROGRESS_ANCHOR_FIELDS)
    for slot in range(TX_PROGRESS_EVENT_COUNT):
        keys.extend(TX_PROGRESS_PREFIX + 'Event' + str(slot) + field
                    for field in TX_PROGRESS_EVENT_U32_FIELDS +
                    TX_PROGRESS_EVENT_U64_FIELDS)
    return tuple(keys)


def guarded_sta_tx_progress_evidence(pre, middle, post):
    """Associate optional last-event snapshots with the current TX watchdog.

    This guard has no effect on Wi-Fi admission or Test076. It preserves raw
    numbers when the owner is stale or incomplete and never calls the six
    event rows a queue, ring snapshot, descriptor owner, or AirDrop evidence.
    """
    samples = (pre, middle, post)
    missing, invalid, reasons = [], [], []
    typed = []
    u32max = (1 << 32) - 1
    u64max = (1 << 64) - 1

    def read_int(sample, key, width):
        if not isinstance(sample, dict) or key not in sample:
            missing.append(key)
            return None
        value = sample[key]
        maximum = u64max if width == 64 else u32max
        if type(value) is not int or not 0 <= value <= maximum:
            invalid.append(key)
            return None
        return value

    for sample in samples:
        values = {}
        for key in TX_PROGRESS_ANCHOR_FIELDS:
            values[key] = read_int(sample, key, 32)
        for field in TX_PROGRESS_HEADER_U32_FIELDS:
            key = TX_PROGRESS_PREFIX + field
            values[key] = read_int(sample, key, 32)
        for field in TX_PROGRESS_HEADER_U64_FIELDS:
            key = TX_PROGRESS_PREFIX + field
            values[key] = read_int(sample, key, 64)
        for slot in range(TX_PROGRESS_EVENT_COUNT):
            prefix = TX_PROGRESS_PREFIX + 'Event' + str(slot)
            for field in TX_PROGRESS_EVENT_U32_FIELDS:
                values[prefix + field] = read_int(sample, prefix + field, 32)
            for field in TX_PROGRESS_EVENT_U64_FIELDS:
                values[prefix + field] = read_int(sample, prefix + field, 64)
        typed.append(values)

    raw = [{key: sample[key] for key in tx_progress_property_keys()
            if isinstance(sample, dict) and key in sample}
           for sample in samples]
    anchors = [[value.get(key) for key in TX_PROGRESS_ANCHOR_FIELDS]
               for value in typed]
    anchors_stable = all(value == anchors[0] for value in anchors[1:])
    anchor_values = dict(zip(TX_PROGRESS_ANCHOR_FIELDS, anchors[-1]))
    watchdog_sequence = anchor_values.get('NativeResetTraceTxWatchdogSequence')
    anchor_complete = (not any(key in TX_PROGRESS_ANCHOR_FIELDS for key in missing) and
                       not any(key in TX_PROGRESS_ANCHOR_FIELDS for key in invalid))
    reset_version = anchor_values.get('NativeResetTracePublishVersion')
    reset_schema = anchor_values.get('NativeResetTraceSchema')
    anchor_valid = (anchor_complete and anchors_stable and
        reset_schema == 3 and reset_version is not None and
        reset_version % 2 == 0)
    if not anchor_valid:
        return {
            'status': 'unknown_anchor', 'applicable': None, 'valid': False,
            'current': False, 'complete': False,
            'watchdog_sequence': watchdog_sequence,
            'watchdog_generation': anchor_values.get(
                'NativeResetTraceTxWatchdogGeneration'),
            'owner_watchdog_sequence': None, 'owner_generation': None,
            'snapshot_available': None, 'snapshot_dropped_count': None,
            'missing_fields': sorted(set(missing)),
            'invalid_fields': sorted(set(invalid)),
            'reasons': ['reset_trace_anchor_missing_unstable_or_invalid'],
            'raw_samples': raw,
            'scope': 'Optional ordinary STA TX progress only; unknown anchors are not interpreted as a watchdog snapshot.',
        }

    watchdog_generation = anchor_values['NativeResetTraceTxWatchdogGeneration']
    if watchdog_sequence == 0:
        return {
            'status': 'not_applicable', 'applicable': False, 'valid': True,
            'current': False, 'complete': False,
            'watchdog_sequence': 0,
            'watchdog_generation': watchdog_generation,
            'owner_watchdog_sequence': None, 'owner_generation': None,
            'snapshot_available': None, 'snapshot_dropped_count': None,
            'missing_fields': [], 'invalid_fields': [], 'reasons': [],
            'raw_samples': raw,
            'scope': 'No TX watchdog has been recorded in the stable reset-trace batch.',
        }

    if missing or invalid:
        return {
            'status': 'incomplete_unknown', 'applicable': True, 'valid': False,
            'current': False, 'complete': False,
            'watchdog_sequence': watchdog_sequence,
            'watchdog_generation': watchdog_generation,
            'owner_watchdog_sequence': None, 'owner_generation': None,
            'snapshot_available': None, 'snapshot_dropped_count': None,
            'missing_fields': sorted(set(missing)),
            'invalid_fields': sorted(set(invalid)),
            'reasons': ['progress_snapshot_required_scalar_missing_or_invalid'],
            'raw_samples': raw,
            'scope': 'Optional ordinary STA TX progress only; missing values remain unknown.',
        }

    if not (typed[0] == typed[1] == typed[2]):
        return {
            'status': 'stale_unknown', 'applicable': True, 'valid': False,
            'current': False, 'complete': False,
            'watchdog_sequence': watchdog_sequence,
            'watchdog_generation': watchdog_generation,
            'owner_watchdog_sequence': None, 'owner_generation': None,
            'snapshot_available': None, 'snapshot_dropped_count': None,
            'missing_fields': [], 'invalid_fields': [],
            'reasons': ['three_progress_reads_not_identical'],
            'raw_samples': raw,
            'scope': 'Optional ordinary STA TX progress only; changed reads are stale/unknown.',
        }

    snapshot = typed[-1]
    begin = snapshot[TX_PROGRESS_PREFIX + 'SnapshotVersionBegin']
    end = snapshot[TX_PROGRESS_PREFIX + 'SnapshotVersionEnd']
    schema = snapshot[TX_PROGRESS_PREFIX + 'Schema']
    owner_sequence = snapshot[TX_PROGRESS_PREFIX + 'OwnerWatchdogSequence']
    owner_generation = snapshot[TX_PROGRESS_PREFIX + 'OwnerGeneration']
    available = snapshot[TX_PROGRESS_PREFIX + 'SnapshotAvailable']
    complete = snapshot[TX_PROGRESS_PREFIX + 'SnapshotComplete']
    dropped_present = snapshot[TX_PROGRESS_PREFIX + 'DroppedCountPresent']
    dropped_count = snapshot[TX_PROGRESS_PREFIX + 'DroppedCount']
    next_serial_present = snapshot[TX_PROGRESS_PREFIX + 'NextSerialPresent']
    next_serial = snapshot[TX_PROGRESS_PREFIX + 'NextSerial']

    boolean_fields = (
        'SnapshotAvailable', 'SnapshotComplete', 'DroppedCountPresent',
        'NextSerialPresent', 'RingSnapshotComplete',
        'FirmwareResponseIdentityProven', 'SequenceIdentityProven',
    )
    for field in boolean_fields:
        value = snapshot[TX_PROGRESS_PREFIX + field]
        if value not in (0, 1):
            invalid.append(TX_PROGRESS_PREFIX + field)
    for slot in range(TX_PROGRESS_EVENT_COUNT):
        event_prefix = TX_PROGRESS_PREFIX + 'Event' + str(slot)
        if snapshot[event_prefix + 'Present'] not in (0, 1):
            invalid.append(event_prefix + 'Present')
        flags = snapshot[event_prefix + 'PresenceFlags']
        if flags & ~0x3ff:
            invalid.append(event_prefix + 'PresenceFlags')

    reasons = []
    if begin != end or begin & 1:
        reasons.append('progress_publication_seqlock_unstable')
    if schema != 1:
        reasons.append('progress_schema_not_v1')
    if not anchors_stable:
        reasons.append('reset_trace_anchor_changed')
    if invalid:
        reasons.append('progress_scalar_out_of_range')

    owner_matches = (owner_sequence == watchdog_sequence and
                     owner_generation == watchdog_generation)
    if not owner_matches:
        reasons.append('progress_owner_does_not_match_watchdog_anchor')
    if snapshot[TX_PROGRESS_PREFIX + 'RingSnapshotComplete'] != 0:
        reasons.append('ring_snapshot_contract_unexpected')
    if snapshot[TX_PROGRESS_PREFIX + 'FirmwareResponseIdentityProven'] != 0:
        reasons.append('firmware_response_identity_contract_unexpected')
    if snapshot[TX_PROGRESS_PREFIX + 'SequenceIdentityProven'] != 0:
        reasons.append('sequence_identity_contract_unexpected')
    if dropped_present != available or next_serial_present != available:
        reasons.append('progress_optional_scalar_presence_contract_invalid')
    if available == 0 and complete != 0:
        reasons.append('unavailable_progress_marked_complete')
    if dropped_present == 0:
        materialized_dropped = None
    else:
        materialized_dropped = dropped_count
    if next_serial_present == 0:
        materialized_next_serial = None
    else:
        materialized_next_serial = next_serial
    if (available == 1 and dropped_present == 1 and
            ((dropped_count == 0) != (complete == 1))):
        reasons.append('progress_complete_drop_count_contract_invalid')

    events = []
    for slot, name in enumerate(TX_PROGRESS_EVENT_NAMES):
        event_prefix = TX_PROGRESS_PREFIX + 'Event' + str(slot)
        event = {field: snapshot[event_prefix + field]
                 for field in TX_PROGRESS_EVENT_U32_FIELDS +
                 TX_PROGRESS_EVENT_U64_FIELDS}
        flags = event['PresenceFlags']
        if (available == 1 and
                event['Present'] != int(event['Count'] > 0)):
            invalid.append(event_prefix + 'PresentCountMismatch')
        if event['Present']:
            max_reason = (2 if slot == 1 else 1 if slot in (2, 5) else 0)
            if event['Reason'] > max_reason:
                invalid.append(event_prefix + 'Reason')
        for field, bit in TX_PROGRESS_PRESENCE_BITS.items():
            event[field] = event[field] if flags & bit else None
        events.append({'slot': slot, 'kind': name, **event})

    valid = not reasons and not invalid and owner_matches
    current = bool(valid and owner_matches)
    complete = bool(current and available == 1 and complete == 1 and dropped_present == 1 and
                     materialized_dropped == 0)
    status = ('current_complete' if complete else
              'current_incomplete' if current else
              'stale_unknown')
    return {
        'status': status, 'applicable': True, 'valid': valid,
        'current': current, 'complete': complete,
        'watchdog_sequence': watchdog_sequence,
        'watchdog_generation': watchdog_generation,
        'owner_watchdog_sequence': owner_sequence,
        'owner_generation': owner_generation,
        'snapshot_available': available,
        'snapshot_complete': snapshot[TX_PROGRESS_PREFIX + 'SnapshotComplete'],
        'snapshot_dropped_count_present': dropped_present,
        'snapshot_dropped_count': materialized_dropped,
        'next_serial_present': next_serial_present,
        'next_serial': materialized_next_serial,
        'ring_snapshot_complete': snapshot[TX_PROGRESS_PREFIX + 'RingSnapshotComplete'],
        'firmware_response_identity_proven': snapshot[
            TX_PROGRESS_PREFIX + 'FirmwareResponseIdentityProven'],
        'sequence_identity_proven': snapshot[
            TX_PROGRESS_PREFIX + 'SequenceIdentityProven'],
        'missing_fields': sorted(set(missing)),
        'invalid_fields': sorted(set(invalid)),
        'reasons': sorted(set(reasons)),
        'events': events,
        'raw_samples': raw,
        'scope': 'Six latest event rows are not the full STA queue/ring, not same-packet ownership, not firmware identity, and not AWDL/AirDrop evidence. Event slots are not a chronological ordering.',
    }


TIME_EVIDENCE_PREFIX = 'NativeP2PTxTimeEvidence'
TIME_EVIDENCE_RECORD_FIELDS = ('Used', 'DiagnosticGeneration', 'TicketSerial', 'FrameKind', 'FrameOrdinal', 'SequenceControl', 'ContextGeneration', 'PowerGeneration', 'StationGeneration', 'RocGeneration', 'QueueId', 'RingSize', 'DescriptorIndex', 'CreatedAtUs', 'ScheduleObservedAtUs', 'ScheduleValidUntilUs', 'PreDoorbellLowerUs', 'NotificationTapUpperUs', 'PeerBindingVerified', 'Submitted', 'Completed', 'ScheduleStale', 'Invalidated', 'DeviceFamily', 'TxCommandApi', 'TxLayout', 'StatusFlags')
TIME_EVIDENCE_RECORD_CAPACITY = 4
# Optional Test076 wire metadata is published on the same ticket record. These
# keys never participate in the legacy time-evidence validity gate; they are
# required only after a TxPrepared event has been joined to one exact ticket.
TIME_EVIDENCE_WIRE_FIELDS = (
    'WireInfoPresent', 'WireSubtype', 'WireMpduLength', 'WirePhyTxPresent',
    'WirePhyTxUs', 'WireTargetTxPresent', 'WireTargetTxUs',
)
TIME_EVIDENCE_WIRE_PRESENCE_FIELDS = (
    'WireInfoPresent', 'WirePhyTxPresent', 'WireTargetTxPresent',
)
TIME_EVIDENCE_IDENTITY_U64_FIELDS = (
    'DiagnosticGeneration', 'TicketSerial', 'ContextGeneration',
    'PowerGeneration', 'StationGeneration', 'RocGeneration',
)
TIME_EVIDENCE_IDENTITY_U32_FIELDS = (
    'SequenceControl', 'QueueId', 'DescriptorIndex',
)
TIME_EVIDENCE_TICKET_IDENTITY_FIELDS = (
    'DiagnosticGeneration', 'TicketSerial', 'FrameKind', 'FrameOrdinal',
    'SequenceControl', 'ContextGeneration', 'PowerGeneration',
    'StationGeneration', 'RocGeneration', 'QueueId', 'RingSize',
    'DescriptorIndex',
)


DISCOVERY_PREFIX = 'NativeP2PDiscovery'
# Test076 is deliberately schema-2-only. Test065/schema-1 keeps its old copy.
DISCOVERY_FIELDS = (
    'SnapshotVersionBegin', 'Schema', 'ContextGeneration', 'PowerGeneration',
    'StationGeneration', 'Status', 'FormalObserverPeerCount',
    'RuntimeMifBindingRequired', 'RuntimeMifBindingValid',
    'RuntimePeerIncarnation', 'RuntimePsfRevision', 'RuntimeMifRevision',
    'HistoryCompatible', 'ModeSelected', 'Mode', 'RuntimeMifRequirementSelected',
    'MifTimingStatus', 'MifFirstCompletionUs', 'MifCurrentSlot',
    'MifEarliestSubmitUs', 'MifLatestSubmitUs', 'MifTargetAwStartGp2',
    'MifTargetAwCounter', 'BindingFailureReason', 'PhaseStatus', 'Checks',
    'Consumed', 'CandidateLocked', 'WindowClosed', 'PacketToken',
    'PsfObservedUs', 'EstimatedEarliestSubmitUs', 'EstimatedLatestSubmitUs',
    'EstimatedTargetGp2', 'ScheduleRevision', 'SubmitCallStartUs',
    'SubmitCallEndUs', 'Doorbelled', 'SubmitResult', 'PacketLimit',
    'ExperimentalOnly', 'ClockMappingVerified', 'AirtimeVerified',
    'FormalPeerPolicyChanged', 'LocalCompletionCount', 'LocalSuccessCount',
    'LocalOutcomeKnown', 'SnapshotVersionEnd',
)
DISCOVERY_PROBE_GENERATIONS = (
    'NativeP2PProbeContextGeneration',
    'NativeP2PProbePowerGeneration',
    'NativeP2PProbeStationGeneration',
)
DISCOVERY_SNAPSHOT_KEYS = tuple(DISCOVERY_PREFIX + field
                                for field in DISCOVERY_FIELDS) + DISCOVERY_PROBE_GENERATIONS
# Test076's per-call blocker mask is optional diagnostic telemetry. It is
# deliberately excluded from the schema-2 required snapshot and startup gates.
OPTIONAL_DISCOVERY_DIAGNOSTIC_KEYS = (
    'NativeP2PDiscoveryPrerequisiteBlockers',
)
MIF_BOOTSTRAP_DIAGNOSTIC_KEYS = (
    'NativeP2PAwdlMifBootstrapStatus',
    'NativeP2PAwdlMifBootstrapBlockers',
    'NativeP2PAwdlMifBootstrapChecks',
    'NativeP2PAwdlMifBootstrapReady',
    'NativeP2PAwdlMifBootstrapPrepared',
    'NativeP2PAwdlMifBootstrapSubmitted',
    'NativeP2PAwdlMifBootstrapSucceeded',
)
DISCOVERY_EPOCH_PAIRS = (
    ('ContextGeneration', 'NativeP2PProbeContextGeneration'),
    ('PowerGeneration', 'NativeP2PProbePowerGeneration'),
    ('StationGeneration', 'NativeP2PProbeStationGeneration'),
)
DISCOVERY_BOOLEAN_FIELDS = (
    'ModeSelected', 'RuntimeMifBindingRequired', 'RuntimeMifBindingValid',
    'RuntimeMifRequirementSelected', 'HistoryCompatible', 'Consumed', 'CandidateLocked',
    'WindowClosed', 'Doorbelled', 'ExperimentalOnly',
    'ClockMappingVerified', 'AirtimeVerified', 'FormalPeerPolicyChanged',
    'LocalOutcomeKnown',
)
DISCOVERY_MODE_NAMES = {0: 'psf_next_slot', 1: 'mif_current_slot'}
DISCOVERY_BINDING_FAILURE_NAMES = (
    'ready', 'invalid_snapshot', 'mode_mismatch', 'missing_mif_binding',
    'incomplete_mif_witness', 'mif_witness_mismatch', 'window_changed',
    'stale_psf', 'stale_mif', 'epoch_mismatch', 'channel_mismatch',
    'no_channel6_next_slot', 'queue_head_invalid', 'window_closed',
    'roc_inactive', 'lease_outside', 'phase_not_yet_open', 'phase_expired',
    'invalid_phase_candidate', 'not_locked', 'peer_incarnation_changed',
    'psf_revision_changed', 'mif_revision_changed', 'psf_witness_changed',
    'queue_head_changed', 'already_attempted', 'history_incompatible',
)
DISCOVERY_U64_MAX = (1 << 64) - 1
DISCOVERY_STATUS_MAX = 21
DISCOVERY_PHASE_STATUS_MAX = 23
DISCOVERY_MIF_TIMING_STATUS_MAX = 32
DISCOVERY_EXPECTED_MODE = 1
DISCOVERY_DATA_DELTA_COUNTERS = (
    'NativeAwdlDataTxAccepted', 'NativeAwdlDataTxEncoded',
    'NativeAwdlDataTxSubmitted', 'NativeAwdlDataTxCompleted',
    'NativeAwdlDataTxSucceeded', 'NativeAwdlDataTxFailed',
    'NativeAwdlDataTxMdnsQmAttempts', 'NativeAwdlDataTxMdnsQmSubmitted',
    'NativeAwdlDataTxMdnsQmCompleted', 'NativeAwdlDataTxMdnsQmSucceeded',
)
# TxAccepted increments when the BSD filter admits an mbuf to its software
# ring. It can include other native traffic and does not mean an MPDU was
# encoded, submitted to firmware, or transmitted over the air.
DISCOVERY_RF_PROGRESS_DELTA_COUNTERS = tuple(
    key for key in DISCOVERY_DATA_DELTA_COUNTERS
    if key != 'NativeAwdlDataTxAccepted'
)


def discovery_scalar_snapshot(sample):
    """Keep only root-published discovery scalars and actual probe epochs."""
    result = {}
    for key in DISCOVERY_SNAPSHOT_KEYS + OPTIONAL_DISCOVERY_DIAGNOSTIC_KEYS:
        if key not in sample:
            continue
        value = sample[key]
        if type(value) is int and 0 <= value <= DISCOVERY_U64_MAX:
            result[key] = value
        else:
            # Preserve malformed type evidence without copying arbitrary data.
            result[key] = {'invalid_type': type(value).__name__}
    return result


def mif_bootstrap_diagnostic_snapshot(sample):
    """Capture only optional, address-free Test076 bootstrap scalars.

    Missing values remain unknown rather than being filled with zero. These
    observations do not participate in the Test076 startup/RF authorization
    gates and do not by themselves prove a firmware transmission or peer RX.
    """
    values = {}
    missing = []
    invalid = []
    for key in MIF_BOOTSTRAP_DIAGNOSTIC_KEYS:
        if key not in sample:
            missing.append(key)
            continue
        value = sample[key]
        if type(value) in (int, bool):
            values[key] = value
        else:
            invalid.append({'key': key, 'type': type(value).__name__})
    return {'values': values, 'missing_fields': missing,
            'invalid_fields': invalid}


def guarded_discovery_evidence(pre, middle, post):
    """Validate one stable Test076 schema-2 MIF-mode publication snapshot.

    This is a numeric publication/binding-status guard. It does not prove
    queue transmission, host/GP2 clock mapping, RF airtime, peer receipt, or
    AirDrop. Unknown schema, mode, status, or binding failure code is rejected.
    """
    snapshots = (('pre', pre), ('middle', middle), ('post', post))
    required_fields = tuple(DISCOVERY_PREFIX + field for field in DISCOVERY_FIELDS)
    required = required_fields + DISCOVERY_PROBE_GENERATIONS
    missing = []
    invalid = []
    reasons = []
    typed = {}
    for label, sample in snapshots:
        typed[label] = {}
        for key in required:
            if key not in sample:
                missing.append(label + '.' + key)
                continue
            value = sample[key]
            if type(value) is not int or not 0 <= value <= DISCOVERY_U64_MAX:
                invalid.append(label + '.' + key)
                continue
            typed[label][key] = value

    version_keys = (
        DISCOVERY_PREFIX + 'SnapshotVersionBegin',
        DISCOVERY_PREFIX + 'SnapshotVersionEnd',
    )
    versions = [typed[label].get(key) for label, _ in snapshots
                for key in version_keys]
    version_stable = (not missing and not invalid and
        all(type(value) is int and value > 0 and value % 2 == 0
            for value in versions) and len(set(versions)) == 1)
    if not version_stable:
        reasons.append('unstable_or_invalid_snapshot_version')

    fields_stable = (not missing and not invalid and all(
        len({typed[label].get(key) for label, _ in snapshots}) == 1
        for key in required_fields))
    if not fields_stable:
        reasons.append('discovery_fields_changed_across_reads')

    epochs_valid = True
    for discovery_field, probe_key in DISCOVERY_EPOCH_PAIRS:
        discovery_key = DISCOVERY_PREFIX + discovery_field
        values = [typed[label].get(discovery_key) for label, _ in snapshots]
        actual = [typed[label].get(probe_key) for label, _ in snapshots]
        if (any(type(value) is not int or value <= 0 for value in values + actual)
                or len(set(values)) != 1 or len(set(actual)) != 1
                or values[0] != actual[0]):
            epochs_valid = False
    if not epochs_valid:
        reasons.append('discovery_probe_epoch_mismatch')

    middle_values = typed['middle']
    schema = middle_values.get(DISCOVERY_PREFIX + 'Schema')
    schema_supported = schema == 2
    if not schema_supported:
        reasons.append('unsupported_or_missing_schema')

    boolean_fields_valid = all(
        type(typed[label].get(DISCOVERY_PREFIX + field)) is int and
        typed[label][DISCOVERY_PREFIX + field] in (0, 1)
        for label, _ in snapshots for field in DISCOVERY_BOOLEAN_FIELDS)
    if not boolean_fields_valid:
        reasons.append('invalid_boolean_scalar')

    bounded_counts_valid = all(
        type(typed[label].get(DISCOVERY_PREFIX + field)) is int and
        0 <= typed[label][DISCOVERY_PREFIX + field] <= maximum
        for label, _ in snapshots for field, maximum in (
            ('FormalObserverPeerCount', 16), ('MifCurrentSlot', 15),
            ('MifTargetAwCounter', 0xffff), ('Consumed', 1),
            ('Doorbelled', 1), ('LocalCompletionCount', 1),
            ('LocalSuccessCount', 1), ('LocalOutcomeKnown', 1),
        ))
    if not bounded_counts_valid:
        reasons.append('out_of_range_schema2_count_or_index')

    code_values_valid = all(
        type(typed[label].get(DISCOVERY_PREFIX + field)) is int and
        typed[label][DISCOVERY_PREFIX + field] <= maximum
        for label, _ in snapshots for field, maximum in (
            ('Status', DISCOVERY_STATUS_MAX),
            ('Mode', max(DISCOVERY_MODE_NAMES)),
            ('MifTimingStatus', DISCOVERY_MIF_TIMING_STATUS_MAX),
            ('PhaseStatus', DISCOVERY_PHASE_STATUS_MAX),
            ('BindingFailureReason', len(DISCOVERY_BINDING_FAILURE_NAMES) - 1),
        ))
    if not code_values_valid:
        reasons.append('unknown_schema2_mode_or_status')

    mode_values = [typed[label].get(DISCOVERY_PREFIX + 'Mode')
                   for label, _ in snapshots]
    selected_values = [typed[label].get(DISCOVERY_PREFIX + 'ModeSelected')
                       for label, _ in snapshots]
    selected_mode_valid = all(
        mode == DISCOVERY_EXPECTED_MODE and selected == 1
        for mode, selected in zip(mode_values, selected_values))
    if not selected_mode_valid:
        reasons.append('expected_mif_current_slot_mode_not_selected')

    fixed_flags_valid = all(
        all(typed[label].get(DISCOVERY_PREFIX + field) == expected
            for label, _ in snapshots)
        for field, expected in (
            ('PacketLimit', 1), ('ExperimentalOnly', 1),
            ('ClockMappingVerified', 0), ('AirtimeVerified', 0),
            ('FormalPeerPolicyChanged', 0)))
    if not fixed_flags_valid:
        reasons.append('unsafe_or_unexpected_experiment_flags')

    middle_failure = middle_values.get(
        DISCOVERY_PREFIX + 'BindingFailureReason')
    failure_name = (DISCOVERY_BINDING_FAILURE_NAMES[middle_failure]
                    if type(middle_failure) is int and
                    0 <= middle_failure < len(DISCOVERY_BINDING_FAILURE_NAMES)
                    else None)
    middle_mode = middle_values.get(DISCOVERY_PREFIX + 'Mode')
    valid = (version_stable and fields_stable and epochs_valid and
             schema_supported and boolean_fields_valid and
             bounded_counts_valid and code_values_valid and
             selected_mode_valid and fixed_flags_valid and
             not missing and not invalid)
    return {
        'valid': valid,
        'stable_scalar_snapshot': version_stable and fields_stable,
        'epoch_match': epochs_valid,
        'schema_supported': schema_supported,
        'mode_supported': middle_mode in DISCOVERY_MODE_NAMES,
        'mode_selected': selected_mode_valid,
        'mode_name': DISCOVERY_MODE_NAMES.get(middle_mode),
        'binding_failure_reason': middle_failure,
        'binding_failure_name': failure_name,
        'experimental_flags_valid': fixed_flags_valid,
        'bounded_counts_valid': bounded_counts_valid,
        'known_status_codes': code_values_valid,
        'values': {key: value for key, value in middle_values.items()
                   if key.startswith(DISCOVERY_PREFIX)},
        'missing_fields': missing,
        'invalid_fields': invalid,
        'reasons': reasons,
        'formal_peer_or_window_coverage_interpreted': False,
        'scope': 'Stable schema-2 numeric publication, selected mode and known status guard only; not transaction, PHY timing, RF airtime, peer receipt, or AirDrop proof.',
    }


def discovery_coverage(evidence, data_deltas):
    """Label a bounded local QM firmware submission, not BSD queue admission.

    TxAccepted counts BSD software-ring enqueues; it is required and reported,
    but excluded from the one-radio-packet bound because ambient native output
    may be queued without being submitted to firmware in this experiment.
    """
    missing = [key for key in DISCOVERY_DATA_DELTA_COUNTERS
               if key not in data_deltas]
    invalid = [key for key in DISCOVERY_DATA_DELTA_COUNTERS
               if key in data_deltas and
               (type(data_deltas[key]) is not int or data_deltas[key] < 0)]
    deltas = {key: data_deltas[key] for key in DISCOVERY_DATA_DELTA_COUNTERS
              if key in data_deltas and type(data_deltas[key]) is int and
              data_deltas[key] >= 0}
    maximum = (max(deltas[key] for key in DISCOVERY_RF_PROGRESS_DELTA_COUNTERS)
               if len(deltas) == len(DISCOVERY_DATA_DELTA_COUNTERS) else None)
    values = evidence.get('values', {})
    consumed = values.get(DISCOVERY_PREFIX + 'Consumed')
    doorbelled = values.get(DISCOVERY_PREFIX + 'Doorbelled')
    qm_submitted = deltas.get('NativeAwdlDataTxMdnsQmSubmitted')
    runtime_binding_required = values.get(
        DISCOVERY_PREFIX + 'RuntimeMifBindingRequired')
    runtime_binding_valid = values.get(
        DISCOVERY_PREFIX + 'RuntimeMifBindingValid')
    covered = (evidence.get('valid') is True and not missing and not invalid and
               evidence.get('mode_name') == 'mif_current_slot' and
               runtime_binding_required == 1 and runtime_binding_valid == 1 and
               consumed == 1 and doorbelled == 1 and qm_submitted == 1 and
               maximum is not None and maximum <= 1)
    return {
        'discovery_covered': covered,
        'qm_submitted_delta': qm_submitted,
        'bsd_queue_enqueue_delta': deltas.get('NativeAwdlDataTxAccepted'),
        'max_data_delta': maximum,
        'max_radio_progress_delta': maximum,
        'single_radio_limit_counters': list(DISCOVERY_RF_PROGRESS_DELTA_COUNTERS),
        'data_deltas': deltas,
        'missing_delta_counters': missing,
        'invalid_delta_counters': invalid,
        'runtime_mif_binding_required': runtime_binding_required,
        'runtime_mif_binding_valid': runtime_binding_valid,
        'formal_peer_or_window_coverage_claimed': False,
        'scope': 'One local QM firmware submission candidate only. BSD TxAccepted is software-ring admission, not radio transmission; no peer receipt, advertised-window coverage, or AirDrop proof.',
    }


def current_data_tx_attempt_witness(pre, middle, post, baseline_counters):
    """Bind the trace to this one-shot Discovery token when a packet was consumed.

    A current encoded/submitted delta without a stable consumed token is unknown;
    a previously published empty trace must never stand in for this attempt.
    """
    discovery = guarded_discovery_evidence(pre, middle, post)
    samples = (pre, middle, post)
    relevant = ('NativeAwdlDataTxEncoded', 'NativeAwdlDataTxSubmitted')
    counter_deltas = {}
    counter_problems_seen = []
    any_positive_delta = False
    for key in relevant:
        baseline = baseline_counters.get(key)
        values = [sample.get(key) for sample in samples]
        if (type(baseline) is not int or baseline < 0 or
                any(type(value) is not int or value < 0 for value in values)):
            counter_problems_seen.append(key + ':missing_or_invalid')
            counter_deltas[key] = None
            continue
        maximum_delta = max(value - baseline for value in values)
        if maximum_delta < 0:
            counter_problems_seen.append(key + ':regressed')
            counter_deltas[key] = None
            continue
        if len(set(values)) != 1:
            counter_problems_seen.append(key + ':changed_during_three_reads')
        counter_deltas[key] = maximum_delta
        any_positive_delta = any_positive_delta or maximum_delta > 0

    consumed_seen = any(
        type(sample.get(DISCOVERY_PREFIX + 'Consumed')) is int and
        sample.get(DISCOVERY_PREFIX + 'Consumed') == 1
        for sample in samples)
    attempt_expected = (consumed_seen or any_positive_delta or
                        bool(counter_problems_seen))
    values = discovery.get('values', {})
    consumed = values.get(DISCOVERY_PREFIX + 'Consumed')
    token = values.get(DISCOVERY_PREFIX + 'PacketToken')
    generations = {
        'DiagnosticGeneration': values.get(DISCOVERY_PREFIX + 'ContextGeneration'),
        'ContextGeneration': values.get(DISCOVERY_PREFIX + 'ContextGeneration'),
        'PowerGeneration': values.get(DISCOVERY_PREFIX + 'PowerGeneration'),
        'StationGeneration': values.get(DISCOVERY_PREFIX + 'StationGeneration'),
        'RocGeneration': values.get(DISCOVERY_PREFIX + 'ContextGeneration'),
    }
    identity_ready = (discovery.get('valid') is True and consumed == 1 and
                      type(token) is int and token > 0 and
                      all(type(value) is int and value > 0
                          for value in generations.values()))
    return {
        'attempt_expected': attempt_expected,
        'discovery_consumed_seen': consumed_seen,
        'counter_deltas': counter_deltas,
        'counter_problems': counter_problems_seen,
        'stable_discovery_valid': discovery.get('valid') is True,
        'discovery_token': token if type(token) is int and token > 0 else None,
        'discovery_generations': generations,
        'identity_ready': identity_ready,
        'discovery_reasons': discovery.get('reasons', []),
        'scope': 'Current-run packet witness from the stable Discovery snapshot and encoded/submitted counter deltas. It does not prove RF airtime or peer receipt.',
    }


def guarded_time_evidence(pre, middle, post):
    """Bracket a complete scalar read; do not rely on dictionary key order.

    This validates a publication snapshot, not ticket causality or RF coverage.
    Fresh independent reads must complete in pre -> middle -> post order.
    """
    prefix = TIME_EVIDENCE_PREFIX
    values = {key: value for key, value in middle.items()
              if key.startswith(prefix) and type(value) in (int, bool)}
    version_keys = [(pre, 'SnapshotVersionEnd'),
                    (middle, 'SnapshotVersionBegin'),
                    (middle, 'SnapshotVersionEnd'),
                    (post, 'SnapshotVersionBegin'),
                    (post, 'SnapshotVersionEnd')]
    versions = [obj.get(prefix + key) for obj, key in version_keys]
    generations = [obj.get(prefix + 'DiagnosticGeneration')
                   for obj in (pre, middle, post)]
    count = middle.get(prefix + 'Count')
    required = [prefix + 'Record' + str(index) + field
                for index in range(TIME_EVIDENCE_RECORD_CAPACITY)
                for field in TIME_EVIDENCE_RECORD_FIELDS]
    missing = [key for key in required if key not in middle]
    invalid = [key for key in required
               if key in middle and type(middle[key]) not in (int, bool)]
    valid = (all(type(value) is int and value > 0 and value % 2 == 0
                 for value in versions) and len(set(versions)) == 1 and
             all(type(value) is int and value > 0 for value in generations) and
             len(set(generations)) == 1 and
             generations[1] == middle.get('NativeP2PProbeContextGeneration') and
             type(middle.get(prefix + 'SchemaVersion')) is int and
             middle.get(prefix + 'SchemaVersion') == 1 and
             type(count) is int and 0 <= count <= TIME_EVIDENCE_RECORD_CAPACITY and
             type(middle.get(prefix + 'DroppedCount')) is int and
             middle[prefix + 'DroppedCount'] >= 0 and not missing and not invalid)
    optional_wire_records = []
    for index in range(TIME_EVIDENCE_RECORD_CAPACITY):
        samples = {}
        for label, source in (('pre', pre), ('middle', middle), ('post', post)):
            fields, missing_wire, invalid_wire = {}, [], []
            for field in TIME_EVIDENCE_WIRE_FIELDS:
                key = prefix + 'Record' + str(index) + field
                if key not in source:
                    missing_wire.append(field)
                    continue
                value = source[key]
                if type(value) is not int or not 0 <= value <= _U32_MAX:
                    invalid_wire.append({
                        'field': field,
                        'type': type(value).__name__,
                        'out_of_u32_range': type(value) is int,
                    })
                    continue
                fields[field] = value
            samples[label] = {
                'values': fields,
                'missing_fields': missing_wire,
                'invalid_fields': invalid_wire,
            }
        all_wire_present = all(
            not samples[label]['missing_fields'] and
            not samples[label]['invalid_fields'] and
            all(field in samples[label]['values'] for field in TIME_EVIDENCE_WIRE_FIELDS)
            for label in ('pre', 'middle', 'post'))
        wire_stable = (all_wire_present and all(
            samples['pre']['values'][field] ==
            samples['middle']['values'][field] ==
            samples['post']['values'][field]
            for field in TIME_EVIDENCE_WIRE_FIELDS))
        missing_wire_fields = sorted({
            field for label in ('pre', 'middle', 'post')
            for field in samples[label]['missing_fields']
        })
        invalid_wire_fields = [
            {'sample': label, **item}
            for label in ('pre', 'middle', 'post')
            for item in samples[label]['invalid_fields']
        ]
        optional_wire_records.append({
            'slot': index,
            'snapshot_stable': wire_stable,
            'missing_fields': missing_wire_fields,
            'invalid_fields': invalid_wire_fields,
        })
    return {'stable_scalar_snapshot': valid, 'values': values,
            'missing_record_fields': missing, 'invalid_record_fields': invalid,
            'optional_wire_records': optional_wire_records,
            'retrospective_coverage_interpreted': False,
            'scope': 'Publication version/epoch guard only; missing, odd, changed or unsupported metadata is not a zero-filled trace. Local transaction or radio coverage requires separate ticket validation.'}


def local_time_evidence_ticket_ledger(time_evidence):
    """Preserve each published ticket and its seven wire fields without RXTrace."""
    if not isinstance(time_evidence, dict):
        return {
            'status': 'time_snapshot_unavailable', 'applicable': None,
            'valid': False, 'records': [], 'indeterminate_slots': [],
        }

    values = time_evidence.get('values', {})
    snapshot_stable = time_evidence.get('stable_scalar_snapshot') is True
    missing_base = set(time_evidence.get('missing_record_fields', []))
    invalid_base = set(time_evidence.get('invalid_record_fields', []))
    wire_slots = {item.get('slot'): item for item in
                  time_evidence.get('optional_wire_records', [])
                  if isinstance(item, dict)}
    identity_u64 = set(TIME_EVIDENCE_IDENTITY_U64_FIELDS)
    identity_u32 = set(TIME_EVIDENCE_IDENTITY_U32_FIELDS) | {
        'FrameKind', 'FrameOrdinal', 'RingSize',
    }
    records, indeterminate = [], []
    for slot in range(TIME_EVIDENCE_RECORD_CAPACITY):
        prefix = TIME_EVIDENCE_PREFIX + 'Record' + str(slot)
        used = values.get(prefix + 'Used')
        if type(used) is not int or used not in (0, 1):
            indeterminate.append({
                'slot': slot,
                'reason': 'used_flag_missing_or_invalid',
            })
            continue
        if used == 0:
            continue

        identity, identity_missing, identity_invalid = {}, [], []
        for field in TIME_EVIDENCE_TICKET_IDENTITY_FIELDS:
            key = prefix + field
            value = values.get(key)
            if key in missing_base or key not in values:
                identity_missing.append(field)
                continue
            if key in invalid_base:
                identity_invalid.append({
                    'field': field, 'reason': 'invalid_base_record_field',
                })
                continue
            width = 64 if field in identity_u64 else 32
            maximum = (1 << width) - 1
            if type(value) is not int or not 0 <= value <= maximum:
                identity_invalid.append({
                    'field': field,
                    'type': type(value).__name__,
                    'out_of_range': type(value) is int,
                })
                continue
            if field in ('DiagnosticGeneration', 'TicketSerial',
                         'ContextGeneration', 'PowerGeneration',
                         'StationGeneration', 'RocGeneration') and value == 0:
                identity_invalid.append({
                    'field': field, 'reason': 'required_identity_is_zero',
                })
                continue
            identity[field] = value

        optional = wire_slots.get(slot, {})
        wire_values = {
            field: values[prefix + field]
            for field in TIME_EVIDENCE_WIRE_FIELDS
            if type(values.get(prefix + field)) is int and
            0 <= values[prefix + field] <= _U32_MAX
        }
        wire_missing = list(optional.get('missing_fields', []))
        wire_invalid = list(optional.get('invalid_fields', []))
        wire_stable = optional.get('snapshot_stable') is True
        wire_complete = (
            wire_stable and not wire_missing and not wire_invalid and
            all(field in wire_values for field in TIME_EVIDENCE_WIRE_FIELDS))
        presence_valid = (wire_complete and all(
            type(wire_values.get(field)) is int and wire_values[field] in (0, 1)
            for field in TIME_EVIDENCE_WIRE_PRESENCE_FIELDS))
        semantics_valid = (
            presence_valid and
            (wire_values['WireInfoPresent'] == 1 or all(
                wire_values[field] == 0
                for field in TIME_EVIDENCE_WIRE_FIELDS[1:])) and
            (wire_values['WirePhyTxPresent'] == 1 or
             wire_values['WirePhyTxUs'] == 0) and
            (wire_values['WireTargetTxPresent'] == 1 or
             wire_values['WireTargetTxUs'] == 0))
        identity_complete = (
            not identity_missing and not identity_invalid and
            all(field in identity for field in TIME_EVIDENCE_TICKET_IDENTITY_FIELDS))
        complete = (snapshot_stable and identity_complete and
                    wire_complete and semantics_valid)
        status = ('local_ticket_record_complete' if complete else
                  'local_ticket_record_incomplete')
        records.append({
            'slot': slot,
            'status': status,
            'snapshot_stable': snapshot_stable,
            'ticket_identity': identity,
            'identity_missing_fields': identity_missing,
            'identity_invalid_fields': identity_invalid,
            'wire_fields': wire_values,
            'wire_missing_fields': wire_missing,
            'wire_invalid_fields': wire_invalid,
            'wire_snapshot_stable': wire_stable,
            'wire_semantics_valid': bool(semantics_valid),
            'wire_info_present': (
                wire_values.get('WireInfoPresent') == 1
                if presence_valid else None),
        })

    complete = (snapshot_stable and not indeterminate and
                all(item['status'] == 'local_ticket_record_complete'
                    for item in records))
    if not records and not indeterminate and snapshot_stable:
        return {
            'status': 'no_ticket_records', 'applicable': False,
            'valid': None, 'records': [], 'indeterminate_slots': [],
            'snapshot_stable': True,
            'scope': 'No used TimeEvidence ticket is published in this stable snapshot; no wire fields are required.',
        }
    return {
        'status': 'ticket_records_complete' if complete else
                  'ticket_records_incomplete',
        'applicable': bool(records) or bool(indeterminate),
        'valid': complete, 'snapshot_stable': snapshot_stable,
        'records': records, 'indeterminate_slots': indeterminate,
        'scope': 'Local per-ticket TimeEvidence publication only. Each used record preserves its ticket identity and the seven same-record wire fields; this does not by itself prove a matching RX event, RF transmission, or peer receipt.',
    }


def correlate_prepared_wire_evidence(time_evidence, rx_trace):
    """Join optional wire metadata to a TxPrepared event by full ticket identity.

    No global/last-value fields are used as fallback. Missing wire properties
    leave this optional result unknown without changing the legacy time guard.
    """
    local_ledger = local_time_evidence_ticket_ledger(time_evidence)

    def unknown(status, reason, applicable=None):
        correlation = {
            'status': status, 'valid': False, 'reason': reason,
        }
        return {
            'status': status, 'applicable': applicable, 'valid': False,
            'reason': reason, 'records': [], 'local_ticket_ledger': local_ledger,
            'rx_trace_correlation': correlation,
            'global_fallback_used': False,
            'scope': 'Optional per-ticket prepared-wire metadata. It is joined only by ticket, diagnostic generation, sequence, epochs, queue and descriptor identity; no global values or AirDrop/RF claim.',
        }

    if not isinstance(rx_trace, dict) or rx_trace.get('valid') is not True:
        return unknown('rx_trace_incomplete', 'complete_stable_rx_trace_unavailable')

    rx_values = rx_trace.get('values', {})
    event_count = rx_trace.get('event_count')
    if (type(event_count) is not int or
            not 0 <= event_count <= RX_TRACE_EVENT_CAPACITY):
        return unknown('rx_trace_incomplete', 'invalid_event_count')

    prepared = []
    for index in range(event_count):
        pfx = RX_TRACE_PREFIX + 'Event' + str(index)
        if rx_values.get(pfx + 'Kind') == 3:
            prepared.append((index, pfx))
    if not prepared:
        return {
            'status': 'unknown_no_tx_prepared_event',
            'applicable': bool(local_ledger.get('records')), 'valid': None,
            'reason': 'no_tx_prepared_event_for_local_ticket_cross_check',
            'records': [], 'local_ticket_ledger': local_ledger,
            'rx_trace_correlation': {
                'status': 'unknown_no_tx_prepared_event',
                'valid': None,
                'reason': 'rx_trace_contains_no_kind3_tx_prepared_row',
            },
            'global_fallback_used': False,
            'scope': 'The local TimeEvidence ledger is retained independently. RXTrace has no TxPrepared row, so cross-publication identity correlation remains unknown; absence of that row does not discard or invalidate the local ticket record.',
        }
    if not isinstance(time_evidence, dict) or time_evidence.get(
            'stable_scalar_snapshot') is not True:
        return unknown('time_evidence_incomplete',
                       'stable_ticket_snapshot_unavailable', applicable=True)

    time_values = time_evidence.get('values', {})
    wire_slots = {item.get('slot'): item for item in
                  time_evidence.get('optional_wire_records', [])
                  if isinstance(item, dict)}
    identity_pairs = (
        ('TxTicketSerial', 'TicketSerial', 64, True),
        ('TxDiagnosticGeneration', 'DiagnosticGeneration', 64, True),
        ('TxSequenceControl', 'SequenceControl', 32, False),
        ('ContextGeneration', 'ContextGeneration', 32, True),
        ('PowerGeneration', 'PowerGeneration', 32, True),
        ('StationGeneration', 'StationGeneration', 32, True),
        ('RocGeneration', 'RocGeneration', 32, True),
        ('TxQueueId', 'QueueId', 32, False),
        ('TxDescriptorIndex', 'DescriptorIndex', 32, False),
    )
    matched, invalid_reasons = [], []
    for event_index, event_prefix in prepared:
        event_identity = {}
        identity_valid = True
        for event_field, record_field, width, must_be_positive in identity_pairs:
            value = rx_values.get(event_prefix + event_field)
            maximum = (1 << width) - 1
            if (type(value) is not int or value < 0 or value > maximum or
                    (must_be_positive and value == 0)):
                invalid_reasons.append(
                    'event' + str(event_index) + '_invalid_' + event_field)
                identity_valid = False
            else:
                event_identity[record_field] = value
        if not identity_valid:
            matched.append({
                'event_index': event_index,
                'event_serial': rx_values.get(event_prefix + 'Serial'),
                'status': 'identity_unknown', 'valid': False,
                'reason': 'prepared_event_identity_invalid',
                'identity': event_identity,
            })
            continue

        candidates, malformed_slots = [], []
        for slot in range(TIME_EVIDENCE_RECORD_CAPACITY):
            record_prefix = TIME_EVIDENCE_PREFIX + 'Record' + str(slot)
            used = time_values.get(record_prefix + 'Used')
            if type(used) is not int or used not in (0, 1):
                malformed_slots.append(slot)
                continue
            if used != 1:
                continue
            candidate_identity, candidate_valid = {}, True
            for _, record_field, width, must_be_positive in identity_pairs:
                value = time_values.get(record_prefix + record_field)
                maximum = (1 << width) - 1
                if (type(value) is not int or value < 0 or value > maximum or
                        (must_be_positive and value == 0)):
                    candidate_valid = False
                    break
                candidate_identity[record_field] = value
            if not candidate_valid:
                malformed_slots.append(slot)
            elif candidate_identity == event_identity:
                candidates.append(slot)

        if len(candidates) != 1:
            reason = ('ambiguous_exact_ticket_identity' if len(candidates) > 1
                      else 'no_exact_ticket_identity_match')
            if malformed_slots:
                reason += '_with_malformed_used_record'
            invalid_reasons.append('event' + str(event_index) + '_' + reason)
            matched.append({
                'event_index': event_index,
                'event_serial': rx_values.get(event_prefix + 'Serial'),
                'status': 'identity_unknown', 'valid': False,
                'reason': reason, 'candidate_slots': candidates,
                'malformed_slots': malformed_slots,
                'identity': event_identity,
            })
            continue

        slot = candidates[0]
        optional = wire_slots.get(slot)
        if not isinstance(optional, dict):
            matched.append({
                'event_index': event_index,
                'event_serial': rx_values.get(event_prefix + 'Serial'),
                'slot': slot, 'status': 'wire_fields_unknown', 'valid': False,
                'reason': 'optional_wire_record_snapshot_missing',
                'identity': event_identity,
            })
            invalid_reasons.append('event' + str(event_index) + '_wire_record_missing')
            continue

        missing_fields = list(optional.get('missing_fields', []))
        invalid_fields = list(optional.get('invalid_fields', []))
        record_prefix = TIME_EVIDENCE_PREFIX + 'Record' + str(slot)
        values = {
            field: time_values[record_prefix + field]
            for field in TIME_EVIDENCE_WIRE_FIELDS
            if type(time_values.get(record_prefix + field)) is int and
            0 <= time_values[record_prefix + field] <= _U32_MAX
        }
        if (missing_fields or invalid_fields or
                optional.get('snapshot_stable') is not True):
            matched.append({
                'event_index': event_index,
                'event_serial': rx_values.get(event_prefix + 'Serial'),
                'slot': slot, 'status': 'wire_fields_unknown', 'valid': False,
                'reason': 'wire_fields_missing_invalid_or_unstable',
                'missing_fields': missing_fields,
                'invalid_fields': invalid_fields,
                'identity': event_identity,
            })
            invalid_reasons.append('event' + str(event_index) + '_wire_fields_incomplete')
            continue

        presence_valid = all(
            type(values.get(field)) is int and values[field] in (0, 1)
            for field in TIME_EVIDENCE_WIRE_PRESENCE_FIELDS)
        consistency_valid = (
            presence_valid and
            (values['WireInfoPresent'] == 1 or all(
                values[field] == 0 for field in TIME_EVIDENCE_WIRE_FIELDS[1:])) and
            (values['WirePhyTxPresent'] == 1 or values['WirePhyTxUs'] == 0) and
            (values['WireTargetTxPresent'] == 1 or
             values['WireTargetTxUs'] == 0))
        if not consistency_valid:
            matched.append({
                'event_index': event_index,
                'event_serial': rx_values.get(event_prefix + 'Serial'),
                'slot': slot, 'status': 'wire_fields_invalid', 'valid': False,
                'reason': 'invalid_presence_or_absent_value_semantics',
                'values': values, 'identity': event_identity,
            })
            invalid_reasons.append('event' + str(event_index) + '_wire_semantics_invalid')
            continue

        matched.append({
            'event_index': event_index,
            'event_serial': rx_values.get(event_prefix + 'Serial'),
            'slot': slot, 'status': 'matched_wire_record_complete',
            'valid': True, 'identity': event_identity,
            'wire_info_present': values['WireInfoPresent'] == 1,
            'wire_subtype': values['WireSubtype'] if values['WireInfoPresent'] else None,
            'wire_mpdu_length': values['WireMpduLength'] if values['WireInfoPresent'] else None,
            'wire_phy_tx_present': values['WirePhyTxPresent'] == 1,
            'wire_phy_tx_us': values['WirePhyTxUs'] if values['WirePhyTxPresent'] else None,
            'wire_target_tx_present': values['WireTargetTxPresent'] == 1,
            'wire_target_tx_us': values['WireTargetTxUs'] if values['WireTargetTxPresent'] else None,
        })

    matched_slots = [item['slot'] for item in matched
                     if type(item.get('slot')) is int]
    if len(matched_slots) != len(set(matched_slots)):
        invalid_reasons.append('multiple_tx_prepared_events_map_to_same_record')
        for item in matched:
            if matched_slots.count(item.get('slot')) > 1:
                item.update(status='ambiguous_duplicate_event_to_ticket_join',
                            valid=False)

    complete = (not invalid_reasons and len(matched) == len(prepared) and
                all(item.get('valid') is True for item in matched))
    return {
        'status': 'matched_wire_records_complete' if complete else
                  'wire_record_join_incomplete',
        'applicable': True, 'valid': complete,
        'reason': None if complete else 'one_or_more_prepared_ticket_joins_unproven',
        'details': invalid_reasons, 'records': matched,
        'local_ticket_ledger': local_ledger,
        'rx_trace_correlation': {
            'status': 'matched_wire_records_complete' if complete else
                      'wire_record_join_incomplete',
            'valid': complete, 'details': invalid_reasons, 'records': matched,
        },
        'global_fallback_used': False,
        'scope': 'Per-ticket prepared-wire metadata joined to the same stable time-evidence record by ticket serial, diagnostic generation, sequence control, all four epochs, queue ID and descriptor index. Missing/invalid fields remain unknown; values are never borrowed from global/last-ticket properties. This is local driver metadata, not RF transmission or peer receipt.',
    }


def firmware_resources_absent(sample):
    return sample.get('NativeP2PProbeResourceMayExist') == 0


_U32_MAX = (1 << 32) - 1

RX_ENTRY_PREFIX = 'NativeP2PRxEntry'
RX_ENTRY_HEADER_FIELDS = (
    'SnapshotBegin', 'Schema', 'Active', 'ContextGeneration',
    'PowerGeneration', 'StationGeneration', 'RocGeneration', 'SnapshotEnd',
)
RX_ENTRY_COUNTER_FIELDS = (
    'CountOwnerGateEntries', 'CountStatusTruncated', 'CountCrcRejected',
    'CountOverrunRejected', 'CountMpduLengthShort',
    'CountDescriptorTruncated', 'CountPayloadTruncated',
    'CountCapacityOverflow', 'CountFullDescriptor',
    'CountFrameControlValid', 'CountManagementFrame', 'CountControlFrame',
    'CountDataFrame', 'CountReservedFrame', 'CountQosDataFrame',
    'CountAwdlBssidCandidate', 'CountFilterMatchAvailable',
    'CountFilterMatchUnavailable',
)
RX_ENTRY_WITNESS_PREFIXES = (
    RX_ENTRY_PREFIX + 'LastDescriptor',
    RX_ENTRY_PREFIX + 'LastAwdlDataCandidate',
)
RX_ENTRY_WITNESS_FIELDS = (
    'Present', 'ContextGeneration', 'PowerGeneration', 'StationGeneration',
    'RocGeneration', 'PayloadLength', 'DmaCapacity', 'DescriptorSize',
    'Version', 'MpduLength', 'StatusPresent', 'Status',
    'MacPhyIndexPresent', 'MacPhyIndex', 'FilterMatchPresent', 'FilterMatch',
    'RpaEnabled', 'ChannelPresent', 'Channel', 'FrameControlPresent',
    'FrameControl', 'FrameType', 'FrameSubtype', 'ToDs', 'FromDs',
    'AwdlBssidCandidate',
)
RX_ENTRY_WITNESS_SUFFIX_FIELDS = tuple(
    prefix[len(RX_ENTRY_PREFIX):] + field
    for prefix in RX_ENTRY_WITNESS_PREFIXES
    for field in RX_ENTRY_WITNESS_FIELDS
)
RX_ENTRY_WITNESS_KEYS = tuple(
    prefix + field for prefix in RX_ENTRY_WITNESS_PREFIXES
    for field in RX_ENTRY_WITNESS_FIELDS
)
RX_ENTRY_FIELDS = (RX_ENTRY_HEADER_FIELDS + RX_ENTRY_COUNTER_FIELDS +
                   RX_ENTRY_WITNESS_SUFFIX_FIELDS)
RX_ENTRY_PROBE_GENERATIONS = (
    'NativeP2PProbeContextGeneration',
    'NativeP2PProbePowerGeneration',
    'NativeP2PProbeStationGeneration',
    'NativeP2PRocGeneration',
)
RX_ENTRY_EPOCH_PAIRS = (
    ('ContextGeneration', 'NativeP2PProbeContextGeneration'),
    ('PowerGeneration', 'NativeP2PProbePowerGeneration'),
    ('StationGeneration', 'NativeP2PProbeStationGeneration'),
    ('RocGeneration', 'NativeP2PRocGeneration'),
)
RX_ENTRY_BOOLEAN_FIELDS = tuple(
    RX_ENTRY_PREFIX + field for field in ('Active',)
) + tuple(key for key in RX_ENTRY_WITNESS_KEYS
          if key.endswith('Present')) + tuple(
    prefix + field for prefix in RX_ENTRY_WITNESS_PREFIXES
    for field in ('RpaEnabled', 'ToDs', 'FromDs', 'AwdlBssidCandidate')
)
RX_ENTRY_SNAPSHOT_KEYS = tuple(RX_ENTRY_PREFIX + field
                               for field in RX_ENTRY_FIELDS) + RX_ENTRY_PROBE_GENERATIONS

# Test076's event trace is separate from the older last-descriptor snapshot.
# Frozen Test076 export names follow native/awdl_rx_event_timeline.hpp.
RX_TRACE_PREFIX = 'NativeP2PRxTrace'
RX_TRACE_EVENT_CAPACITY = 32
RX_TRACE_HEADER_U64_FIELDS = (
    'SnapshotVersionBegin', 'SnapshotVersionEnd', 'OwnerSerial', 'Revision',
)
RX_TRACE_OWNER_EPOCH_FIELDS = (
    'ContextGeneration', 'PowerGeneration', 'StationGeneration', 'RocGeneration',
)
RX_TRACE_HEADER_U32_FIELDS = (
    'SchemaVersion', 'OwnerPresent', *RX_TRACE_OWNER_EPOCH_FIELDS, 'Active',
    'ProducerClosed', 'PendingDrainCount', 'UntrackedPendingDrainCount',
    'UntrackedPendingIdentityOverflowCount',
    'EventCount', 'DroppedEventCount', 'StaleCompletionCount',
    'SourceTableFullCount', 'FilteredActionCount', 'RejectedOwnerCount',
    'StaleNotificationCount', 'SessionAnomalyCount',
    'SessionReducerReturnedTrueCount', 'SessionCanonicalTransitionCount',
    'SessionNotificationAcceptedCount', 'SessionNotificationIgnoredCount',
    'SessionNotificationDuplicateCount', 'SessionNotificationConflictingCount',
    'SessionNotificationLateCount', 'SessionNotificationMalformedCount',
    'SessionNotificationForeignCount', 'SessionBoundaryOrderInvalid',
    'TimeEventNotificationCount', 'TimeEventNotificationDroppedCount',
    'ProducerCloseReason',
)
RX_TRACE_BOUNDARY_NAMES = ('RocStart', 'RocEnd')
RX_TRACE_BOUNDARY_U64_FIELDS = (
    'NotificationSerial', 'OwnerSerial', 'HostMonotonicUs',
)
RX_TRACE_BOUNDARY_U32_FIELDS = (
    'Present', 'Api', *RX_TRACE_OWNER_EPOCH_FIELDS, 'HostMonotonicPresent',
    'RawLength', 'OwnerSessionToken', 'ExpectedUidKnown', 'ExpectedUid',
    'MacIdAndColor', 'RawStatus', 'RawStartFlag', 'Configuration',
    'ReducerResultPresent', 'ReducerReturnedTrue', 'ReducerResult',
    'CanonicalTransitionPresent', 'CanonicalTransition',
)
RX_TRACE_EVENT_U64_FIELDS = (
    'Serial', 'OwnerSerial', 'HostMonotonicUs', 'QueueSerial', 'TxTicketSerial',
    'TxDiagnosticGeneration',
)
RX_TRACE_EVENT_U32_FIELDS = (
    *RX_TRACE_OWNER_EPOCH_FIELDS, 'Kind', 'HostMonotonicPresent', 'RawLength',
    'SourceOrdinal', 'SourceKnown', 'FrameControlPresent', 'FrameControl',
    'FrameType', 'FrameSubtype', 'SequenceControlPresent', 'SequenceControl',
    'AwdlSubtypePresent', 'AwdlSubtype', 'WirePhyPresent', 'WirePhyTxUs',
    'WireTargetPresent', 'WireTargetTxUs', 'ChannelIndex', 'RxGp2Present',
    'RxGp2Us', 'RxMacPhyIndexPresent', 'RxMacPhyIndex',
    'ParseAttempted', 'ParseResultPresent', 'ParseStatus', 'ParseRejectReason',
    'ParseRejectSubtype', 'ParseTlvType', 'ParseExpectedTlvType',
    'ParseTlvOffset', 'ParseDeclaredLength', 'ParseAvailableLength',
    'DecodeAttempted', 'DecodeResultPresent', 'DecodeStatus',
    'DecodeRejectStage', 'DecodeOffendingTlvType', 'DecodeRelatedTlvType',
    'RouteAttempted', 'RouteResultPresent', 'RouteStatus', 'QueueAccepted',
    'TableObserveAttempted', 'TableResultPresent', 'TableStatus',
    'PeerObserverAttempted', 'PeerObserverResultPresent', 'PeerObserverStatus',
    'CompletionUpdated', 'PendingDrain', 'NotificationApi',
    'NotificationMatchStatusPresent', 'NotificationMatchStatus',
    'TimeEventTimestamp', 'TimeEventSessionId', 'TimeEventUniqueId',
    'TimeEventMacIdAndColor', 'TimeEventRawAction', 'TimeEventRawStatus',
    'TimeEventExpectedUidKnown', 'TimeEventExpectedUid',
    'TxSequenceControl', 'TxWireInfoPresent', 'TxWirePhyTxUs',
    'TxWireTargetTxUs', 'TxQueueId', 'TxDescriptorIndex',
)
RX_TRACE_ANOMALY_NAMES = ('FirstSessionAnomaly', 'LastSessionAnomaly')
RX_TRACE_ANOMALY_U64_FIELDS = (
    'NotificationSerial', 'OwnerSerial', 'HostMonotonicUs',
)
RX_TRACE_ANOMALY_U32_FIELDS = (
    'Present', 'Api', 'Reason', *RX_TRACE_OWNER_EPOCH_FIELDS,
    'HostMonotonicPresent', 'RawLength', 'OwnerSessionToken',
    'ExpectedUidKnown', 'ExpectedUid', 'MacIdAndColor', 'RawStatus',
    'RawStartFlag', 'Configuration', 'ReducerResultPresent',
    'ReducerReturnedTrue', 'ReducerResult',
)
RX_TRACE_PROBE_EPOCHS = (
    'NativeP2PProbeContextGeneration',
    'NativeP2PProbePowerGeneration',
    'NativeP2PProbeStationGeneration',
    'NativeP2PRocGeneration',
)
RX_TRACE_BOUNDARY_BOOL_FIELDS = (
    'Present', 'HostMonotonicPresent', 'ExpectedUidKnown',
    'ReducerResultPresent', 'ReducerReturnedTrue',
    'CanonicalTransitionPresent',
)
RX_TRACE_EVENT_BOOL_FIELDS = (
    'HostMonotonicPresent', 'SourceKnown', 'FrameControlPresent',
    'SequenceControlPresent', 'AwdlSubtypePresent', 'WirePhyPresent',
    'WireTargetPresent', 'RxGp2Present', 'RxMacPhyIndexPresent',
    'ParseAttempted', 'ParseResultPresent', 'DecodeAttempted',
    'DecodeResultPresent', 'RouteAttempted', 'RouteResultPresent',
    'QueueAccepted', 'TableObserveAttempted', 'TableResultPresent',
    'PeerObserverAttempted', 'PeerObserverResultPresent',
    'CompletionUpdated', 'PendingDrain', 'NotificationMatchStatusPresent',
    'TimeEventExpectedUidKnown', 'TxWireInfoPresent',
)
RX_TRACE_ANOMALY_BOOL_FIELDS = (
    'Present', 'HostMonotonicPresent', 'ExpectedUidKnown',
    'ReducerResultPresent', 'ReducerReturnedTrue',
)
RX_TRACE_SNAPSHOT_KEYS = tuple(
    RX_TRACE_PREFIX + field for field in
    RX_TRACE_HEADER_U64_FIELDS + RX_TRACE_HEADER_U32_FIELDS
) + tuple(
    RX_TRACE_PREFIX + boundary + field
    for boundary in RX_TRACE_BOUNDARY_NAMES
    for field in RX_TRACE_BOUNDARY_U64_FIELDS + RX_TRACE_BOUNDARY_U32_FIELDS
) + tuple(
    RX_TRACE_PREFIX + f'Event{index}' + field
    for index in range(RX_TRACE_EVENT_CAPACITY)
    for field in RX_TRACE_EVENT_U64_FIELDS + RX_TRACE_EVENT_U32_FIELDS
) + tuple(
    RX_TRACE_PREFIX + anomaly + field
    for anomaly in RX_TRACE_ANOMALY_NAMES
    for field in RX_TRACE_ANOMALY_U64_FIELDS + RX_TRACE_ANOMALY_U32_FIELDS
) + RX_TRACE_PROBE_EPOCHS
RX_TRACE_U64_KEYS = set(
    RX_TRACE_PREFIX + field for field in RX_TRACE_HEADER_U64_FIELDS
) | set(
    RX_TRACE_PREFIX + boundary + field
    for boundary in RX_TRACE_BOUNDARY_NAMES
    for field in RX_TRACE_BOUNDARY_U64_FIELDS
) | set(
    RX_TRACE_PREFIX + f'Event{index}' + field
    for index in range(RX_TRACE_EVENT_CAPACITY)
    for field in RX_TRACE_EVENT_U64_FIELDS
) | set(
    RX_TRACE_PREFIX + anomaly + field
    for anomaly in RX_TRACE_ANOMALY_NAMES
    for field in RX_TRACE_ANOMALY_U64_FIELDS
)
RX_TRACE_U32_KEYS = set(RX_TRACE_SNAPSHOT_KEYS) - RX_TRACE_U64_KEYS
RX_TRACE_EPOCH_BINDINGS = tuple(zip(
    RX_TRACE_OWNER_EPOCH_FIELDS,
    ('NativeP2PProbeContextGeneration', 'NativeP2PProbePowerGeneration',
     'NativeP2PProbeStationGeneration', 'NativeP2PRocGeneration'),
))

def rx_entry_scalar_snapshot(sample):
    """Keep only the frozen Test076 RX entry uint32 whitelist."""
    result = {}
    for key in RX_ENTRY_SNAPSHOT_KEYS:
        if key not in sample:
            continue
        value = sample[key]
        if type(value) is int:
            result[key] = value
        else:
            # Keep the type failure without copying arbitrary property content.
            result[key] = {'invalid_type': type(value).__name__}
    return result


def guarded_rx_entry_evidence(pre, middle, post):
    """Validate three complete, stable numeric reads of the ended ROC snapshot.

    This is a driver-entry telemetry snapshot only. It does not decode raw
    status/mac_phy/filter-match values, infer peer receipt, or treat zero
    counters as evidence of RF silence.
    """
    snapshots = (('pre', pre), ('middle', middle), ('post', post))
    missing = []
    invalid = []
    reasons = []
    typed = {}
    required = tuple(RX_ENTRY_PREFIX + field for field in RX_ENTRY_FIELDS) + RX_ENTRY_PROBE_GENERATIONS
    for label, sample in snapshots:
        typed[label] = {}
        for key in required:
            if key not in sample:
                missing.append(label + '.' + key)
                continue
            value = sample[key]
            if type(value) is not int or not 0 <= value <= _U32_MAX:
                invalid.append(label + '.' + key)
                continue
            typed[label][key] = value

    begin_key = RX_ENTRY_PREFIX + 'SnapshotBegin'
    end_key = RX_ENTRY_PREFIX + 'SnapshotEnd'
    versions = [typed[label].get(key) for label, _ in snapshots
                for key in (begin_key, end_key)]
    version_stable = (not missing and not invalid and
        all(type(value) is int and value > 0 and value % 2 == 0
            for value in versions) and len(set(versions)) == 1)
    if not version_stable:
        reasons.append('unstable_or_invalid_snapshot_version')

    fields_stable = (not missing and not invalid and all(
        len({typed[label].get(RX_ENTRY_PREFIX + field)
             for label, _ in snapshots}) == 1
        for field in RX_ENTRY_FIELDS))
    if not fields_stable:
        reasons.append('rx_entry_fields_changed_across_reads')

    schema_values = [typed[label].get(RX_ENTRY_PREFIX + 'Schema')
                     for label, _ in snapshots]
    schema_supported = all(value == 1 for value in schema_values)
    if not schema_supported:
        reasons.append('unsupported_or_missing_schema')

    epochs_valid = True
    for entry_field, actual_key in RX_ENTRY_EPOCH_PAIRS:
        entry_key = RX_ENTRY_PREFIX + entry_field
        entry_values = [typed[label].get(entry_key) for label, _ in snapshots]
        actual_values = [typed[label].get(actual_key) for label, _ in snapshots]
        if (any(type(value) is not int or value <= 0
                for value in entry_values + actual_values) or
                len(set(entry_values)) != 1 or len(set(actual_values)) != 1 or
                entry_values[0] != actual_values[0]):
            epochs_valid = False
    context_values = [typed[label].get(RX_ENTRY_PREFIX + 'ContextGeneration')
                      for label, _ in snapshots]
    roc_values = [typed[label].get(RX_ENTRY_PREFIX + 'RocGeneration')
                  for label, _ in snapshots]
    if (any(type(value) is not int or value <= 0
            for value in context_values + roc_values) or
            any(context != roc for context, roc in zip(context_values, roc_values))):
        epochs_valid = False
    if not epochs_valid:
        reasons.append('rx_entry_epoch_mismatch')

    boolean_fields_valid = all(
        type(typed[label].get(key)) is int and
        typed[label][key] in (0, 1)
        for label, _ in snapshots for key in RX_ENTRY_BOOLEAN_FIELDS)
    if not boolean_fields_valid:
        reasons.append('invalid_boolean_scalar')

    active_closed = all(
        type(typed[label].get(RX_ENTRY_PREFIX + 'Active')) is int and
        typed[label][RX_ENTRY_PREFIX + 'Active'] == 0
        for label, _ in snapshots)
    if not active_closed:
        reasons.append('rx_entry_snapshot_not_inactive_after_roc')

    valid = (version_stable and fields_stable and schema_supported and
             epochs_valid and boolean_fields_valid and active_closed and
             not missing and not invalid)
    middle_values = typed['middle']
    witness_presence = {
        prefix: middle_values.get(prefix + 'Present') == 1
        for prefix in RX_ENTRY_WITNESS_PREFIXES
        if type(middle_values.get(prefix + 'Present')) is int
    }
    return {
        'valid': valid,
        'stable_complete_snapshot': version_stable and fields_stable,
        'schema_supported': schema_supported,
        'epoch_match': epochs_valid,
        'boolean_fields_valid': boolean_fields_valid,
        'inactive_post_roc': active_closed,
        'values': {key: value for key, value in middle_values.items()
                   if key.startswith(RX_ENTRY_PREFIX)},
        'witness_present': witness_presence,
        'missing_fields': missing,
        'invalid_fields': invalid,
        'reasons': reasons,
        'raw_status_mac_phy_and_filter_match_interpreted': False,
        'zero_counters_interpreted_as_rf_silence': False,
        'scope': 'Stable post-ROC driver-entry numeric telemetry only; not peer receipt, packet decode/delivery, or AirDrop proof.',
    }


def rx_trace_scalar_snapshot(sample):
    """Keep only the frozen Test076 RX trace numeric whitelist."""
    result = {}
    for key in RX_TRACE_SNAPSHOT_KEYS:
        if key not in sample:
            continue
        value = sample[key]
        if type(value) is int:
            result[key] = value
        else:
            result[key] = {'invalid_type': type(value).__name__}
    return result


def guarded_rx_trace_evidence(pre, middle, post):
    """Validate the frozen owner-scoped Test076 RX/event publication.

    This accepts only local producer-side evidence. It keeps host callback time
    separate from GP2, raw 24-byte TimeEvent timestamps, and peer-declared wire
    PHY values. A zero result status is retained as a result when its presence
    bit is set; status codes are not interpreted here.
    """
    snapshots = (('pre', pre), ('middle', middle), ('post', post))
    missing, invalid, reasons = [], [], []
    typed = {}
    header_u64 = tuple(RX_TRACE_PREFIX + field
                       for field in RX_TRACE_HEADER_U64_FIELDS)
    header_u32 = tuple(RX_TRACE_PREFIX + field
                       for field in RX_TRACE_HEADER_U32_FIELDS) + RX_TRACE_PROBE_EPOCHS
    boundary_u64 = tuple(RX_TRACE_PREFIX + boundary + field
                         for boundary in RX_TRACE_BOUNDARY_NAMES
                         for field in RX_TRACE_BOUNDARY_U64_FIELDS)
    boundary_u32 = tuple(RX_TRACE_PREFIX + boundary + field
                         for boundary in RX_TRACE_BOUNDARY_NAMES
                         for field in RX_TRACE_BOUNDARY_U32_FIELDS)
    anomaly_u64 = tuple(RX_TRACE_PREFIX + anomaly + field
                        for anomaly in RX_TRACE_ANOMALY_NAMES
                        for field in RX_TRACE_ANOMALY_U64_FIELDS)
    anomaly_u32 = tuple(RX_TRACE_PREFIX + anomaly + field
                        for anomaly in RX_TRACE_ANOMALY_NAMES
                        for field in RX_TRACE_ANOMALY_U32_FIELDS)
    base_u64 = header_u64 + boundary_u64 + anomaly_u64
    base_u32 = header_u32 + boundary_u32 + anomaly_u32

    def read_keys(label, sample, keys, width):
        maximum = (1 << width) - 1
        for key in keys:
            if key not in sample:
                missing.append(label + '.' + key)
                continue
            value = sample[key]
            if type(value) is not int or not 0 <= value <= maximum:
                invalid.append(label + '.' + key)
                continue
            typed[label][key] = value

    for label, sample in snapshots:
        typed[label] = {}
        read_keys(label, sample, base_u64, 64)
        read_keys(label, sample, base_u32, 32)

    count_key = RX_TRACE_PREFIX + 'EventCount'
    event_counts = [typed[label].get(count_key) for label, _ in snapshots]
    count_stable = (
        all(type(value) is int and 0 <= value <= RX_TRACE_EVENT_CAPACITY
            for value in event_counts) and len(set(event_counts)) == 1)
    if not count_stable:
        reasons.append('event_count_missing_invalid_or_changed')
    event_count = event_counts[1] if count_stable else 0
    event_u64 = tuple(RX_TRACE_PREFIX + f'Event{index}' + field
                      for index in range(event_count)
                      for field in RX_TRACE_EVENT_U64_FIELDS)
    event_u32 = tuple(RX_TRACE_PREFIX + f'Event{index}' + field
                      for index in range(event_count)
                      for field in RX_TRACE_EVENT_U32_FIELDS)
    for label, sample in snapshots:
        read_keys(label, sample, event_u64, 64)
        read_keys(label, sample, event_u32, 32)

    all_keys = base_u64 + base_u32 + event_u64 + event_u32
    begin = RX_TRACE_PREFIX + 'SnapshotVersionBegin'
    end = RX_TRACE_PREFIX + 'SnapshotVersionEnd'
    versions = [typed[label].get(key) for label, _ in snapshots
                for key in (begin, end)]
    version_stable = (
        not missing and not invalid and
        all(type(value) is int and value > 0 and value % 2 == 0
            for value in versions) and len(set(versions)) == 1)
    if not version_stable:
        reasons.append('unstable_or_incomplete_snapshot_version')

    revision_key = RX_TRACE_PREFIX + 'Revision'
    revisions = [typed[label].get(revision_key) for label, _ in snapshots]
    revision_stable = (
        all(type(value) is int and value >= 0 for value in revisions) and
        len(set(revisions)) == 1)
    if not revision_stable:
        reasons.append('trace_revision_changed_or_missing')

    fields_stable = (not missing and not invalid and all(
        len({typed[label].get(key) for label, _ in snapshots}) == 1
        for key in all_keys))
    if not fields_stable:
        reasons.append('trace_fields_changed_across_reads')

    schema_key = RX_TRACE_PREFIX + 'SchemaVersion'
    schema_supported = all(typed[label].get(schema_key) == 1
                           for label, _ in snapshots)
    if not schema_supported:
        reasons.append('unsupported_or_missing_trace_schema')

    bool_keys = {RX_TRACE_PREFIX + field for field in (
        'OwnerPresent', 'Active', 'ProducerClosed', 'SessionBoundaryOrderInvalid')}
    bool_keys.update(RX_TRACE_PREFIX + boundary + field
                     for boundary in RX_TRACE_BOUNDARY_NAMES
                     for field in RX_TRACE_BOUNDARY_BOOL_FIELDS)
    bool_keys.update(RX_TRACE_PREFIX + index + field
                     for index in RX_TRACE_ANOMALY_NAMES
                     for field in RX_TRACE_ANOMALY_BOOL_FIELDS)
    bool_keys.update(RX_TRACE_PREFIX + f'Event{index}' + field
                     for index in range(event_count)
                     for field in RX_TRACE_EVENT_BOOL_FIELDS)
    boolean_fields_valid = all(
        type(typed[label].get(key)) is int and typed[label][key] in (0, 1)
        for label, _ in snapshots for key in bool_keys)
    if not boolean_fields_valid:
        reasons.append('invalid_trace_boolean')

    middle_values = typed['middle']

    def value(suffix):
        return middle_values.get(RX_TRACE_PREFIX + suffix)

    owner_present = value('OwnerPresent')
    owner_serial = value('OwnerSerial')
    active = value('Active')
    producer_closed = value('ProducerClosed')
    if owner_present != 1 or type(owner_serial) is not int or owner_serial <= 0:
        reasons.append('trace_owner_missing')
    if active != 0:
        reasons.append('trace_owner_still_active')
    if producer_closed != 1:
        reasons.append('trace_producer_not_closed')

    epochs_valid = True
    for field, probe_key in RX_TRACE_EPOCH_BINDINGS:
        owner_key = RX_TRACE_PREFIX + field
        owner_values = [typed[label].get(owner_key) for label, _ in snapshots]
        probe_values = [typed[label].get(probe_key) for label, _ in snapshots]
        if (any(type(item) is not int or item <= 0
                for item in owner_values + probe_values) or
                len(set(owner_values)) != 1 or len(set(probe_values)) != 1 or
                owner_values[0] != probe_values[0]):
            epochs_valid = False
    if not epochs_valid:
        reasons.append('trace_owner_epoch_mismatch')

    boundary_times = {}
    boundary_valid = True
    for boundary, expected_start_flag in (('RocStart', 1), ('RocEnd', 0)):
        pfx = RX_TRACE_PREFIX + boundary
        expected = {
            'Present': 1,
            'Api': 1,                 # SessionProtection16
            'HostMonotonicPresent': 1,
            'RawLength': 16,
            'ReducerResultPresent': 1,
            'ReducerReturnedTrue': 1,
            'CanonicalTransitionPresent': 1,
            'CanonicalTransition': 1,
        }
        if any(middle_values.get(pfx + suffix) != expected_value
               for suffix, expected_value in expected.items()):
            boundary_valid = False
        if middle_values.get(pfx + 'RawStartFlag') != expected_start_flag:
            boundary_valid = False
        if middle_values.get(pfx + 'OwnerSerial') != owner_serial:
            boundary_valid = False
        notification_serial = middle_values.get(pfx + 'NotificationSerial')
        if type(notification_serial) is not int or notification_serial <= 0:
            boundary_valid = False
        timestamp = middle_values.get(pfx + 'HostMonotonicUs')
        if type(timestamp) is not int or timestamp <= 0:
            boundary_valid = False
        else:
            boundary_times[boundary] = timestamp
        for field in RX_TRACE_OWNER_EPOCH_FIELDS:
            if middle_values.get(pfx + field) != value(field):
                boundary_valid = False
    start_time = boundary_times.get('RocStart')
    end_time = boundary_times.get('RocEnd')
    if (type(start_time) is not int or type(end_time) is not int or
            not 0 < start_time < end_time or
            value('SessionBoundaryOrderInvalid') != 0):
        boundary_valid = False
    if not boundary_valid:
        reasons.append('roc_boundary_not_canonical_or_ordered')

    event_serials, action_queue_serials, event_times = [], [], []
    event_epochs_valid = True
    producer_times_valid = boundary_valid
    stage_results_valid = True
    source_attribution_complete = True
    for index in range(event_count):
        pfx = RX_TRACE_PREFIX + f'Event{index}'
        kind = middle_values.get(pfx + 'Kind')
        if kind not in (1, 2, 3):
            reasons.append(f'event{index}_unsupported_kind')
            stage_results_valid = False
        serial = middle_values.get(pfx + 'Serial')
        if type(serial) is not int or serial <= 0:
            reasons.append(f'event{index}_invalid_serial')
        else:
            event_serials.append(serial)
        queue_serial = middle_values.get(pfx + 'QueueSerial')
        if kind == 1:
            if type(queue_serial) is not int or queue_serial <= 0:
                reasons.append(f'event{index}_invalid_action_queue_serial')
            else:
                action_queue_serials.append(queue_serial)
        if middle_values.get(pfx + 'OwnerSerial') != owner_serial:
            event_epochs_valid = False
        for field in RX_TRACE_OWNER_EPOCH_FIELDS:
            if middle_values.get(pfx + field) != value(field):
                event_epochs_valid = False

        known = middle_values.get(pfx + 'SourceKnown')
        ordinal = middle_values.get(pfx + 'SourceOrdinal')
        if ((known == 1 and (type(ordinal) is not int or ordinal <= 0)) or
                (known == 0 and ordinal != 0)):
            source_attribution_complete = False

        time_present = middle_values.get(pfx + 'HostMonotonicPresent')
        host_time = middle_values.get(pfx + 'HostMonotonicUs')
        if time_present == 1 and type(host_time) is int and host_time > 0:
            event_times.append(host_time)
        else:
            producer_times_valid = False
            reasons.append(f'event{index}_producer_time_unavailable')

        for stage in ('Parse', 'Decode', 'Route', 'TableObserve', 'PeerObserver'):
            attempted = middle_values.get(pfx + stage + 'Attempted')
            result_present_suffix = {
                'Parse': 'ParseResultPresent',
                'Decode': 'DecodeResultPresent',
                'Route': 'RouteResultPresent',
                'TableObserve': 'TableResultPresent',
                'PeerObserver': 'PeerObserverResultPresent',
            }[stage]
            result_present = middle_values.get(pfx + result_present_suffix)
            if result_present == 1 and attempted != 1:
                stage_results_valid = False
                reasons.append(f'event{index}_{stage.lower()}_result_without_attempt')

        if kind == 2:
            if (middle_values.get(pfx + 'NotificationApi') != 2 or
                    middle_values.get(pfx + 'RawLength') != 24):
                reasons.append(f'event{index}_time_event_abi_mismatch')
                stage_results_valid = False

        if middle_values.get(pfx + 'PendingDrain') != 0:
            stage_results_valid = False
            reasons.append(f'event{index}_pending_drain_not_closed')

    if event_serials and (len(set(event_serials)) != len(event_serials) or
                          event_serials != sorted(event_serials)):
        event_epochs_valid = False
        reasons.append('event_serial_order_invalid')
    if len(set(action_queue_serials)) != len(action_queue_serials):
        event_epochs_valid = False
        reasons.append('action_queue_serial_reused')
    if not event_epochs_valid:
        reasons.append('event_owner_epoch_mismatch')
    if (boundary_valid and event_times and
            (min(event_times) < start_time or max(event_times) > end_time)):
        producer_times_valid = False
        reasons.append('event_producer_time_outside_roc')

    pending = value('PendingDrainCount')
    untracked_pending = value('UntrackedPendingDrainCount')
    untracked_identity_overflow = value('UntrackedPendingIdentityOverflowCount')
    dropped = value('DroppedEventCount')
    stale_completion = value('StaleCompletionCount')
    source_full = value('SourceTableFullCount')
    time_dropped = value('TimeEventNotificationDroppedCount')
    trace_coverage_complete = (
        version_stable and revision_stable and fields_stable and schema_supported and
        boolean_fields_valid and epochs_valid and event_epochs_valid and
        owner_present == 1 and owner_serial > 0 and active == 0 and
        producer_closed == 1 and pending == 0 and untracked_pending == 0 and
        untracked_identity_overflow == 0 and
        dropped == 0 and stale_completion == 0 and source_full == 0 and
        time_dropped == 0 and boundary_valid and producer_times_valid and
        stage_results_valid and not missing and not invalid)
    valid = trace_coverage_complete and not reasons

    return {
        'valid': valid,
        'stable_complete_snapshot': version_stable and revision_stable and
                                    fields_stable and not missing and not invalid,
        'schema_supported': schema_supported,
        'epoch_match': epochs_valid and event_epochs_valid,
        'owner_present': owner_present == 1,
        'owner_inactive_post_roc': active == 0,
        'producer_closed': producer_closed == 1,
        'pending_drain_count': pending,
        'untracked_pending_drain_count': untracked_pending,
        'untracked_pending_identity_overflow_count': untracked_identity_overflow,
        'producer_time_valid': producer_times_valid,
        'event_count': event_count,
        'event_capacity': RX_TRACE_EVENT_CAPACITY,
        'dropped_event_count': dropped,
        'stale_completion_count': stale_completion,
        'source_table_full_count': source_full,
        'time_event_notification_dropped_count': time_dropped,
        'session_anomaly_count': value('SessionAnomalyCount'),
        'session_boundary_order_invalid': value('SessionBoundaryOrderInvalid'),
        'source_attribution_complete': source_attribution_complete,
        'stage_results_valid': stage_results_valid,
        'trace_coverage_complete': trace_coverage_complete,
        'values': {key: item for key, item in middle_values.items()
                   if key.startswith(RX_TRACE_PREFIX)},
        'missing_fields': missing,
        'invalid_fields': invalid,
        'reasons': reasons,
        'raw_addresses_exported': False,
        'time_event_timestamp_interpreted_as_gp2': False,
        'wire_phy_interpreted_as_local_rx_time': False,
        'stage_status_zero_interpreted_as_missing': False,
        'unobserved_early_reject_paths': 'unknown',
        'scope': 'Owner-scoped bounded producer RX timeline. This does not prove peer receipt, delivered payload, or AirDrop.',
    }


def test076_rx_trace_transport_evidence(pre, middle, post):
    """Combine raw U32 stability with the actual owner-scoped trace guard.

    Normalization is an input adapter only. A complete result still requires
    the production version, owner, schema, time and coverage checks. Raw reads
    and the conversion audit stay beside the derived decision.
    """
    report = derive_rx_trace_guard_report(
        pre, middle, post, guarded_rx_trace_evidence)
    guard = dict(report['guard'])
    combined = report['combined_valid'] is True
    guard['transport_normalization_valid'] = (
        report['normalization'].get('valid') is True)
    guard['combined_valid'] = combined
    guard['valid'] = combined
    guard['trace_coverage_complete'] = (
        combined and guard.get('trace_coverage_complete') is True)
    if not guard['transport_normalization_valid']:
        guard['reasons'] = list(guard.get('reasons', [])) + [
            'transport_u32_normalization_failed']
    report['guard'] = guard
    report['valid'] = combined
    report['overall_status_promoted_by_transport_normalizer'] = False
    report['scope'] = (
        'Test076 derived host validation requires identical raw event-U32 '
        'representations across the three reads and a passing production '
        'owner-scoped RX guard. It is not runtime, peer receipt, payload '
        'delivery, or AirDrop proof.')
    return report


def successful_roc_ended(sample):
    """Whether this diagnostic's ROC start succeeded and its owner ended."""
    expected = {
        'NativeP2PRocStartSeen': 1,
        'NativeP2PRocStartStatus': 1,
        'NativeP2PRocCommandResult': 0,
        'NativeP2PRocEndSeen': 1,
        'NativeP2PRocUnknown': 0,
    }
    return all(type(sample.get(key)) is int and sample[key] == value
               for key, value in expected.items())


def successful_roc_start(sample):
    expected = {
        'NativeP2PRocStartSeen': 1,
        'NativeP2PRocStartStatus': 1,
        'NativeP2PRocCommandResult': 0,
    }
    return all(type(sample.get(key)) is int and sample[key] == value
               for key, value in expected.items())


_ROC_UNUSED_FIELDS = (
    'NativeP2PRocCleanupAllowed', 'NativeP2PRocCommandResult',
    'NativeP2PRocConfiguration', 'NativeP2PRocEndSeen',
    'NativeP2PRocEndStatus', 'NativeP2PRocGeneration',
    'NativeP2PRocObserved', 'NativeP2PRocRequestedChannel',
    'NativeP2PRocRequestedDurationMs', 'NativeP2PRocResult',
    'NativeP2PRocStage', 'NativeP2PRocStartSeen',
    'NativeP2PRocStartStatus', 'NativeP2PRocUnknown',
)
_MAC_UNUSED_COUNTERS = (
    'NativeP2PTxPreArmEventCount', 'NativeP2PTxSubmitAttemptCount',
)
_OPTIONAL_ZERO_RF_COUNTERS = (
    'NativeP2PTxProbeStage', 'NativeP2PTxProbeSetupStep',
    'NativeP2PTxProbeTicketArmed', 'NativeP2PTxProbeTicketCompleted',
    'NativeP2PTxProbeAttemptSucceeded', 'NativeP2PTxProbePeerAcknowledged',
    'NativeP2PTxProbeEverDoorbelled', 'NativeP2PTxProbeOutstandingTx',
    'NativeP2PTxProbeRingMayExist', 'NativeP2PTxProbeQueueState',
    'NativeP2PTxProbeStationState', 'NativeP2PTxProbeActionState',
    'NativeP2PAwdlActionFramesSubmitted',
    'NativeP2PAwdlActionFramesCompleted',
    'NativeP2PAwdlActionFramesSucceeded',
    'NativeP2PAwdlPsfFrameSubmitted', 'NativeP2PAwdlPsfTxComplete',
    'NativeP2PAwdlPsfTxSucceeded', 'NativeP2PAwdlMifFrameSubmitted',
    'NativeP2PAwdlMifTxAttempted', 'NativeP2PAwdlMifTxComplete',
    'NativeP2PAwdlMifTxSucceeded', 'NativeP2PAwdlMifBurstAttempted',
    'NativeP2PAwdlMifBurstSubmitted', 'NativeP2PAwdlMifBurstCompleted',
    'NativeP2PAwdlMifBurstSucceeded',
)
_DEFERRED_UNARMED_REASONS = {2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 19, 20, 22}


def unarmed_probe_preflight(values):
    """Validate that this boot has no prior MAC/ROC control attempt.

    Context generation is a reset/drain epoch and may advance without arming.
    The controller's attempted bit is the sticky per-boot fence: resetDrained
    deliberately preserves it. This permits a recovered, still-unarmed boot
    while rejecting an earlier attempted or quarantined diagnostic.
    """
    problems = []

    def exact_int(key, minimum=0, maximum=_U32_MAX):
        value = values.get(key)
        if type(value) is not int or not minimum <= value <= maximum:
            problems.append(key)
            return None
        return value

    # A nonzero context epoch is expected after successful firmware reset
    # drains. Keep it typed and bounded; never treat a missing value as zero.
    context = exact_int('NativeP2PProbeContextGeneration')
    exact_int('NativeP2PProbePowerGeneration')
    if context is not None and context > 0:
        power = values.get('NativeP2PProbePowerGeneration')
        if type(power) is not int or power == 0:
            problems.append('NativeP2PProbePowerGeneration')
    if exact_int('NativeP2PProbeStationGeneration') != 0:
        problems.append('NativeP2PProbeStationGeneration')

    state = exact_int('NativeP2PProbeState')
    blocked = exact_int('NativeP2PProbeBlocked')
    allowed_blocked = {
        0: {0},                 # Idle
        1: {1},                 # Disabled / ProbeDisabled
        2: _DEFERRED_UNARMED_REASONS,
    }
    if state not in allowed_blocked or blocked not in allowed_blocked.get(state, set()):
        problems.extend(('NativeP2PProbeState', 'NativeP2PProbeBlocked'))

    for key, expected in (
        ('NativeP2PManualArmed', 0),
        ('NativeP2PProbeAttempted', 0),
        ('NativeP2PProbeResourceMayExist', 0),
        ('NativeP2PProbeAddResult', -1),
        ('NativeP2PProbeRemoveResult', -1),
    ):
        value = values.get(key)
        if type(value) is not int or value != expected:
            problems.append(key)

    # Require the full published ROC snapshot to remain untouched. These
    # fields are emitted at driver startup and are not inferred from absence.
    for key in _ROC_UNUSED_FIELDS:
        if exact_int(key) != 0:
            problems.append(key)

    # These two counters are always published by the driver. Other TX fields
    # are only published once the diagnostic enters those stages, so if one
    # exists it must still carry its unused zero value. Missing optional fields
    # are safe only with the sticky attempted/arm sentinels above still clear.
    for key in _MAC_UNUSED_COUNTERS:
        if exact_int(key) != 0:
            problems.append(key)
    for key in _OPTIONAL_ZERO_RF_COUNTERS:
        if key in values and exact_int(key) != 0:
            problems.append(key)
    problems.extend(unarmed_rx_trace_preflight(values))
    return sorted(set(problems))


def unarmed_rx_trace_preflight(values):
    """Require the native trace to be present but still at its clean boot state."""
    problems = []
    prefix = RX_TRACE_PREFIX
    for suffix in RX_TRACE_HEADER_U64_FIELDS + RX_TRACE_HEADER_U32_FIELDS:
        key = prefix + suffix
        value = values.get(key)
        maximum = (1 << 64) - 1 if key in RX_TRACE_U64_KEYS else _U32_MAX
        if type(value) is not int or not 0 <= value <= maximum:
            problems.append(key)
            continue
        expected = 1 if suffix == 'SchemaVersion' else 0
        if suffix not in ('SnapshotVersionBegin', 'SnapshotVersionEnd', 'Revision') and value != expected:
            problems.append(key)

    begin = values.get(prefix + 'SnapshotVersionBegin')
    end = values.get(prefix + 'SnapshotVersionEnd')
    revision = values.get(prefix + 'Revision')
    if (type(begin) is not int or type(end) is not int or
            begin != end or begin % 2 != 0):
        problems.append('snapshot_version')
    if type(revision) is not int or revision < 0:
        problems.append(prefix + 'Revision')

    for boundary in RX_TRACE_BOUNDARY_NAMES:
        key = prefix + boundary + 'Present'
        if type(values.get(key)) is not int or values[key] != 0:
            problems.append(key)
    for anomaly in RX_TRACE_ANOMALY_NAMES:
        key = prefix + anomaly + 'Present'
        if type(values.get(key)) is not int or values[key] != 0:
            problems.append(key)
    return sorted(set(problems))

def test076_metadata_problems(metadata, expected_build, boot_epoch=None,
                              identity=None, root=None):
    """Require an explicitly prepared Test076 MIF-mode next-boot record."""
    problems = []
    if not isinstance(metadata, dict) or metadata.get('schema') != 1:
        return ['metadata_schema']
    if metadata.get('candidate') != expected_build:
        problems.append('candidate')
    if metadata.get('baseline') != '25G332-Test075':
        problems.append('baseline')
    if metadata.get('installed') is not True:
        problems.append('installed')
    if metadata.get('reboot_ready') is not True:
        problems.append('reboot_ready')
    if metadata.get('armed') is not True:
        problems.append('armed')
    if metadata.get('rf_manual_only') is not True:
        problems.append('rf_manual_only')
    if metadata.get('maximum_rf_sessions_per_boot') != 1:
        problems.append('maximum_rf_sessions_per_boot')
    for key, expected in (
        ('maximum_mif_frames', 3),
        ('maximum_mif_only_bootstrap_frames', 1),
        ('maximum_qm_submissions', 1),
        ('diagnostic_duration_ms', 900),
    ):
        if metadata.get(key) != expected:
            problems.append(key)
    if metadata.get('receiver_gated') is not True:
        problems.append('receiver_gated')
    if metadata.get('atomic_boot_claim_required') is not True:
        problems.append('atomic_boot_claim_required')
    if metadata.get('formal_peer_policy_changed') is not False:
        problems.append('formal_peer_policy_changed')
    if metadata.get('no_automatic_reboot') is not True:
        problems.append('no_automatic_reboot')
    if metadata.get('expected_discovery_mode') != 'mif_current_slot':
        problems.append('expected_discovery_mode')
    if metadata.get('native_awdl_discovery_mif_current_slot') is not True:
        problems.append('native_awdl_discovery_mif_current_slot')
    if metadata.get('source_frozen') is not True:
        problems.append('source_frozen')
    if metadata.get('hardware_tested') is not False:
        problems.append('hardware_tested')
    for key in ('expected_binary_sha256', 'expected_info_plist_sha256'):
        value = metadata.get(key)
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
            problems.append(key)
    source_hashes = metadata.get('source_sha256')
    if not isinstance(source_hashes, dict) or not source_hashes:
        problems.append('source_sha256')
    else:
        for path, digest in source_hashes.items():
            parts = pathlib.PurePosixPath(path)
            if (not isinstance(path, str) or parts.is_absolute() or
                    '..' in parts.parts or not parts.parts or
                    not isinstance(digest, str) or
                    not re.fullmatch(r'[0-9a-f]{64}', digest)):
                problems.append('source_sha256_entry')
                break
    for key in ('previous_boot_epoch', 'runtime_boot_epoch'):
        value = metadata.get(key)
        if type(value) is not int or value <= 0:
            problems.append(key)
    previous = metadata.get('previous_boot_epoch')
    last_observed = metadata.get('runtime_boot_epoch')
    if type(boot_epoch) is int:
        if type(previous) is int and boot_epoch == previous:
            problems.append('not_a_new_boot')
        if type(last_observed) is int and boot_epoch <= last_observed:
            problems.append('boot_not_newer_than_last_observation')
    expected_uuid = metadata.get('expected_loaded_uuid')
    if (not isinstance(expected_uuid, str) or
            not re.fullmatch(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}', expected_uuid)):
        problems.append('expected_loaded_uuid')
    if identity is not None:
        if identity.get('binary_identity_verified') is not True:
            problems.append('binary_identity')
        if identity.get('loaded_uuid') != expected_uuid:
            problems.append('loaded_uuid')
    if root is not None:
        root = pathlib.Path(root)
        build_path = root / 'research/test076-build-private.json'
        frozen_path = root / 'research/test076-frozen-source-private.json'
        try:
            if build_path.is_symlink() or frozen_path.is_symlink():
                raise ValueError('symlinked build/source report')
            build = json.loads(build_path.read_text())
            frozen = json.loads(frozen_path.read_text())
            metadata_report = pathlib.Path(
                metadata.get('source_freeze_report', '')).resolve()
            if metadata_report != frozen_path.resolve():
                problems.append('metadata_source_freeze_report_path')
            if (build.get('candidate') != expected_build or
                    build.get('source_freeze_matches') is not True or
                    build.get('binary_sha256') != metadata.get('expected_binary_sha256') or
                    build.get('info_plist_sha256') != metadata.get('expected_info_plist_sha256') or
                    build.get('mach_o_uuid') != expected_uuid or
                    build.get('source_files') != len(source_hashes)):
                problems.append('build_identity_or_frozen_manifest')
            report_path = pathlib.Path(build.get('source_freeze_report', ''))
            if report_path.resolve() != frozen_path.resolve():
                problems.append('source_freeze_report_path')
            if (frozen.get('candidate') != expected_build or
                    frozen.get('source_sha256') != source_hashes):
                problems.append('source_manifest_mismatch')
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            problems.append('build_or_source_report_unavailable')
    return sorted(set(problems))


def mif_current_slot_controller_enabled(controller_properties):
    return controller_properties.get(
        'NativeAwdlDiscoveryMifCurrentSlotEnabled') is True


def wrapper_build_tag_matches(wrapper_properties, expected_build):
    return wrapper_properties.get('NativeTestBuild') == expected_build


def claim_directory_for(account):
    """Return the fixed cross-version, one-claim-per-boot directory."""
    return (pathlib.Path(account.pw_dir) /
            'Library/Application Support/IntelWirelessNative/ObservationClaims/BootGlobal')


def legacy_boot_claim_paths_for(claim_directory, boot_epoch):
    """Enumerate old per-test claims without creating, moving, or removing them."""
    observation_claims = pathlib.Path(claim_directory).parent
    claim_name = 'boot-' + str(boot_epoch) + '.json'
    return tuple(observation_claims / scope / claim_name
                 for scope in LEGACY_BOOT_CLAIM_SCOPES)


def existing_legacy_boot_claims(claim_directory, boot_epoch):
    """Return same-boot legacy claim paths, including dangling symlinks."""
    return tuple(path for path in legacy_boot_claim_paths_for(
        claim_directory, boot_epoch) if path.exists() or path.is_symlink())


def observation_folder(root, observation_id, boot_epoch, last_observed_boot):
    """Keep a fresh-boot router observation separate from the frozen first run.

    This selects an output path only. It cannot relax the driver's sticky
    once-per-boot preflight and does not start the external receiver.
    """
    if observation_id is None:
        return root/'research/test076-runtime-private'
    if not isinstance(observation_id,str) or not re.fullmatch(
            r'[a-z0-9][a-z0-9-]{0,47}',observation_id):
        raise ValueError('Invalid router observation identifier')
    if (type(boot_epoch) is not int or type(last_observed_boot) is not int or
            last_observed_boot<=0 or boot_epoch<=last_observed_boot):
        raise ValueError('Router observation requires a fresh boot after the recorded run')
    return root/'research/test076-router-runtime-private'/(
        observation_id+'-boot'+str(boot_epoch))


def claim_boot_attempt(claim_directory, boot_epoch, observation_id):
    """Atomically consume this boot before entering the privileged helper.

    The claim is independent of output labels. A helper failure, ambiguous
    timeout, or even a local save failure after this point must not permit
    another helper invocation in the same boot. Never remove a failed claim.
    """
    if type(boot_epoch) is not int or boot_epoch<=0:
        raise ValueError('Invalid attempt boot epoch')
    legacy_claims = existing_legacy_boot_claims(claim_directory, boot_epoch)
    if legacy_claims:
        raise FileExistsError('Same-boot legacy observation claim exists; read-only refusal')
    claim_directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    claim=claim_directory/('boot-'+str(boot_epoch)+'.json')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(claim,flags,0o600)
    try:
        payload=(json.dumps({'schema':1,'test_scope':'Test076',
            'build':'25G332-Test076','mode':'mif_current_slot',
            'boot_epoch':boot_epoch,'observation_id':observation_id,
            'attempt_consumed':True,'helper_outcome':'unknown',
            'retry_allowed':False,
            'claimed_at':datetime.datetime.now().astimezone().isoformat()})+'\n').encode()
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return claim


def start_claimed_native_browser(claim_directory, boot_epoch, observation_id,
                                 browser_path, on_claim):
    """Exclude parallel/repeated native browse requests as well as helper arms.

    A failure to start or make the browser ready still consumes this boot.
    The observer must use a fresh boot instead of retrying a different label.
    """
    claim=claim_boot_attempt(claim_directory,boot_epoch,observation_id)
    on_claim(claim)
    process=subprocess.Popen([str(browser_path),'20'],stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,text=True)
    process.test076_window_started_monotonic=time.monotonic()
    process.test076_window_started_monotonic_ns=time.monotonic_ns()
    return process


def parse_native_browse_completion(output, timeout_seconds):
    """Accept only one well-formed final phase-2 record proving full completion."""
    numeric = []
    malformed_lines = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            malformed_lines += 1
            continue
        if not isinstance(value, dict):
            malformed_lines += 1
            continue
        numeric.append({key: value_ for key, value_ in value.items()
                        if type(value_) in (int, bool)})
    phase2 = [value for value in numeric
              if type(value.get('phase')) is int and value['phase'] == 2]
    phase2_record = (phase2[0] if len(phase2) == 1 and numeric and
                     numeric[-1] is phase2[0] else None)
    required = ('window_complete', 'process_complete',
                'deallocation_returned', 'elapsed_ms')
    valid = bool(malformed_lines == 0 and phase2_record is not None and
        all(type(phase2_record.get(field)) is int for field in required) and
        phase2_record.get('window_complete') == 1 and
        phase2_record.get('process_complete') == 1 and
        phase2_record.get('deallocation_returned') == 1 and
        phase2_record.get('elapsed_ms') >= int(timeout_seconds * 1000))
    return {
        'numeric': numeric,
        'phase2_record_count': len(phase2),
        'phase2_final_record_valid': valid,
        'malformed_line_count': malformed_lines,
    }


def finish_native_browse_window(browser, record, timeout=20.0,
                                power_ready_check=None, cancel_check=None,
                                completion_grace=NATIVE_BROWSE_COMPLETION_GRACE_SECONDS):
    """Wait in bounded polls and censor power/cancel loss.

    The one-second subprocess wait is only a polling slice. The power property
    read has no timeout; the parent coordinator's 35-second total deadline and
    process cleanup provide the outer bound.
    """
    if browser is None:
        record['native_browse'].update(
            window_status='not_started',window_complete=False,censored=True)
        return False
    started=getattr(browser,'test076_window_started_monotonic',None)
    if type(started) not in (int,float):
        record['native_browse'].update(
            window_status='start_time_unknown',window_complete=False,censored=True)
        return False
    elapsed=max(0.0,time.monotonic()-started)
    remaining=max(0.0,timeout-elapsed)
    record['native_browse'].update(
        declared_window_seconds=timeout,
        elapsed_before_wait_seconds=round(elapsed,3),
        remaining_window_seconds=round(remaining,3))
    record['native_browse']['started_monotonic_ns']=getattr(
        browser,'test076_window_started_monotonic_ns',None)
    record['native_browse']['power_poll_wait_slice_seconds']=1.0
    record['native_browse']['power_poll_slice_is_detection_deadline']=False
    record['native_browse']['power_property_read_has_timeout']=False
    record['native_browse']['parent_total_deadline_seconds']=35.0
    if not callable(power_ready_check):
        def power_ready_check():
            try:
                return properties('AirportItlwm').get('NativePowerReady') == 1
            except (OSError, ValueError, subprocess.SubprocessError):
                return False

    output=''
    censor_reason=None
    completion_deadline=started+timeout+max(0.0,completion_grace)
    while True:
        if callable(cancel_check):
            try:
                if cancel_check() is True:
                    censor_reason='coordinator_cancelled_during_browse_wait'
                    break
            except Exception:
                censor_reason='coordinator_cancel_state_unknown_during_browse_wait'
                break
        try:
            power_ready=power_ready_check()
        except Exception:
            power_ready=False
        if power_ready is not True:
            censor_reason='native_power_not_ready_or_unknown_during_browse_wait'
            break
        now=time.monotonic()
        remaining=max(0.0,timeout-(now-started))
        if browser.poll() is not None:
            try:
                output,_=browser.communicate(timeout=0.25)
            except subprocess.TimeoutExpired:
                censor_reason='process_exit_output_drain_timeout'
            break
        completion_remaining=completion_deadline-now
        if completion_remaining <= 0:
            censor_reason='declared_window_completion_grace_timeout'
            break
        try:
            output,_=browser.communicate(timeout=min(1.0,completion_remaining))
            break
        except subprocess.TimeoutExpired:
            continue

    if censor_reason is not None and browser.poll() is None:
        record['native_browse']['forced_termination_reason']=censor_reason
        try:
            browser.terminate()
            record['native_browse']['forced_terminate_sent']=True
        except OSError as error:
            record['native_browse']['forced_terminate_error']=type(error).__name__
        try:
            output,_=browser.communicate(timeout=NATIVE_BROWSE_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                browser.kill()
                record['native_browse']['forced_kill_sent']=True
            except OSError as error:
                record['native_browse']['forced_kill_error']=type(error).__name__
            record['native_browse']['forced_termination_reason']=censor_reason+'_and_terminate_timeout'
            try:
                output,_=browser.communicate(timeout=NATIVE_BROWSE_KILL_REAP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                output=''

    actual=max(0.0,time.monotonic()-started)
    parsed=parse_native_browse_completion(output,timeout)
    numeric=parsed['numeric']
    phase2_valid=parsed['phase2_final_record_valid']
    complete=(censor_reason is None and actual>=timeout and
              browser.returncode==0 and phase2_valid)
    if censor_reason is None and not complete:
        censor_reason=('phase2_missing_duplicate_or_malformed' if not phase2_valid else
                       'process_exited_before_declared_duration_or_nonzero')
    record['native_browse'].update(
        window_status='natural_window_complete' if complete else
            'censored_power_loss' if 'power' in (censor_reason or '') else
            'censored_timeout' if 'timeout' in (censor_reason or '') else
            'censored_early_exit',
        window_complete=complete,censored=not complete,
        normal_exit=browser.returncode is not None and browser.returncode >= 0,
        exit_kind=('normal_zero' if browser.returncode==0 else
                   'normal_nonzero' if browser.returncode is not None and browser.returncode > 0 else
                   'signal_' + str(-browser.returncode) if browser.returncode is not None else 'unknown'),
        elapsed_seconds=round(actual,3),
        phase2_record_count=parsed['phase2_record_count'],
        phase2_final_record_valid=phase2_valid,
        malformed_output_line_count=parsed['malformed_line_count'])
    if not complete:
        record['native_browse']['censor_reason']=censor_reason
    record['native_browse']['exit']=browser.returncode
    record['native_browse']['final_numeric']=numeric
    return record['native_browse'].get('window_complete') is True


def receiver_gate(expected, event, timeout=25):
    """Wait for one parent-owned phase release; no cross-process clock math."""
    if expected not in ('BROWSE','ARM'):
        raise ValueError('Unsupported receiver gate')
    print(event,flush=True)
    readable,_,_=select.select([sys.stdin],[],[],timeout)
    if not readable:
        raise SystemExit('External receiver gate timed out; boot consumed, do not retry')
    command=os.read(sys.stdin.fileno(),32)
    if command!=(expected+'\n').encode('ascii'):
        raise SystemExit('External receiver did not release this phase; boot consumed, do not retry')


def bounded_browser_ready_line(stream, timeout=3, maximum_bytes=2048):
    """Read one complete line under an absolute deadline, without read-ahead."""
    deadline=time.monotonic()+timeout
    data=bytearray()
    while len(data)<maximum_bytes:
        remaining=deadline-time.monotonic()
        if remaining<=0:
            raise SystemExit('Native browser ready line timed out; no arm, do not retry')
        readable,_,_=select.select([stream],[],[],remaining)
        if not readable:
            raise SystemExit('Native browser ready line timed out; no arm, do not retry')
        byte=os.read(stream.fileno(),1)
        if not byte:
            raise SystemExit('Native browser closed before ready; no arm, do not retry')
        data.extend(byte)
        if byte==b'\n':
            return bytes(data)
    raise SystemExit('Native browser ready line exceeded bound; no arm, do not retry')


def require_native_browser_alive(browser):
    if browser.poll() is not None:
        raise SystemExit('Native browser exited before arm release; no arm, do not retry')


def main():
    cancellation={'requested':False,'during_cleanup':False,'signal':None}
    def coordinator_stop(signum, _frame):
        cancellation['requested']=True
        cancellation['signal']=signal.Signals(signum).name
        if not cancellation['during_cleanup']:
            raise SystemExit('coordinator cancelled the single observation')
    signal.signal(signal.SIGTERM,coordinator_stop)
    signal.signal(signal.SIGINT,coordinator_stop)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-build',required=True)
    parser.add_argument('--phone-ready',action='store_true',help='Only after the user confirms nearby/unlocked/Everyone visibility')
    parser.add_argument('--native-browser-active',action='store_true',help='Only after native Finder AirDrop browsing is active')
    parser.add_argument('--router-observation-id',help='Fresh-boot run identifier; external receiver must already be ready. Never overwrites the frozen first observation.')
    parser.add_argument('--receiver-gated',action='store_true',help='Parent must separately release browse and arm after receiver readiness; no standalone stdin release.')
    args=parser.parse_args()
    # The coordinator is the only supported runtime entry point. Reject a
    # standalone collector before checking root, reading live state/metadata,
    # creating an observation directory, or consuming this boot's claim.
    if not args.receiver_gated:
        raise SystemExit('Test076 collector requires the receiver-gated coordinator entry; unchanged')
    if not args.router_observation_id:
        raise SystemExit('Test076 receiver-gated collector requires a router observation identifier; unchanged')
    if os.geteuid()!=0 or args.expect_build!='25G332-Test076' or not args.phone_ready or not args.native_browser_active:
        raise SystemExit('Require root, Test076, confirmed phone and native browser preparation; unchanged')
    root=pathlib.Path(__file__).resolve().parent
    metadata=json.loads((root/'research/test076-next-boot-private.json').read_text())
    boot=int(re.search(r'sec = (\d+)',subprocess.check_output(['/usr/sbin/sysctl','-n','kern.boottime'],text=True)).group(1))
    metadata_problems=test076_metadata_problems(
        metadata,args.expect_build,boot_epoch=boot,root=root)
    if metadata_problems:
        raise SystemExit('Test076 metadata is not explicitly armed for this boot; unchanged; fields='+
                         ','.join(metadata_problems))
    try:
        folder=observation_folder(root,args.router_observation_id,boot,
                                  metadata.get('runtime_boot_epoch'))
    except ValueError as error:
        raise SystemExit(str(error)+'; unchanged')
    out=folder/'native-data-observation-private.json'
    helper=pathlib.Path('/private/tmp/intel-test076-arm-p2p')
    browser=pathlib.Path('/private/tmp/intel-test076-native-browse')
    if out.exists() or out.is_symlink() or not helper.is_file() or not browser.is_file():raise SystemExit('Existing observation or missing helper; unchanged')
    state=properties('AirportItlwm');address=properties('AirportItlwmSkywalkInterface')
    wrapper=properties('IOPCIEDeviceWrapper')
    if not wrapper_build_tag_matches(wrapper,args.expect_build):
        raise SystemExit('IOPCIEDeviceWrapper build tag does not match Test076; unchanged')
    if not mif_current_slot_controller_enabled(state):
        raise SystemExit('AirportItlwm MIF-current-slot controller property is not enabled; unchanged')
    identity=loaded_identity(args.expect_build)
    identity_problems=test076_metadata_problems(
        metadata,args.expect_build,boot_epoch=boot,identity=identity,root=root)
    if identity_problems:
        raise SystemExit('Test076 loaded identity does not match the armed private metadata; unchanged; fields='+
                         ','.join(identity_problems))
    flags=state.get('NativeAwdlLifecycleFlags',0)
    counter_missing,counter_invalid=counter_problems(state)
    unarmed_problems=unarmed_probe_preflight(state)
    if counter_missing or counter_invalid:
        raise SystemExit('Required Test076 counters unavailable or invalid before RF; missing='+
                         ','.join(counter_missing)+' invalid='+','.join(counter_invalid))
    if (boot==metadata['previous_boot_epoch'] or not identity['binary_identity_verified'] or not ready('en1') or
        state.get('NativeP2PTxDrainEventCount',0)<1 or state.get('NativeP2PTxDrainLastResult')!=0 or
        state.get('NativeP2PTxDrainLastHardStop')!=1 or state.get('NativeP2PTxDrainLastNewGeneration',0)<=0 or
        state.get('NativeAwdlTxEvidenceEnabled') is not True or
        state.get('NativeP2PGp2Observation') is not True or
        state.get('NativeAwdlResidentEnabled') is not True or state.get('NativeAwdlResidentCompiled') is not True or
        state.get('NativeAwdlDiscoveryExperimentEnabled') is not True or
        state.get('NativeAwdlLifecyclePhase')!=13 or flags&0x4003ff!=0x4003ff or flags&0x300000 or
        state.get('NativeAwdlLifecycleStartWitness')!=0x3ff or state.get('NativeAwdlDataAttached')!=1 or
        state.get('NativeAwdlDataIpv6Configured')!=1 or state.get('NativeAwdlDataIpv6ConfigResult')!=0 or
        state.get('NativeAwdlDataClosing')!=0 or state.get('NativeAwdlDataLinkReady')!=1 or
        unarmed_problems or
        address.get('NativeAddressStage')!=5 or address.get('NativeAddressResult')!=0 or address.get('NativeAddressQuarantined') is not False):
        raise SystemExit('Unexpected boot/identity/resident/discovery/private-address or prior-control state; unchanged; control='+','.join(unarmed_problems))
    try:index=socket.if_nametoindex('awdl0')
    except OSError:raise SystemExit('Missing resident native awdl0; unchanged')
    config=subprocess.check_output(['/sbin/ifconfig','awdl0'],text=True)
    if 'RUNNING' not in config or 'inet6 fe80:' not in config or 'tentative' in config or 'duplicated' in config:
        raise SystemExit('Native IPv6 not automatically usable; unchanged')
    data_tx_initial=guarded_data_tx_trace_evidence(
        data_tx_trace_scalar_snapshot(properties('AirportItlwm')),
        data_tx_trace_scalar_snapshot(properties('AirportItlwm')),
        data_tx_trace_scalar_snapshot(properties('AirportItlwm')))
    if not data_tx_initial.get('valid'):
        raise SystemExit('Test076 data-TX trace is not a stable complete schema-v1 publication; unchanged; reasons='+
                         ','.join(data_tx_initial.get('reasons',[])))
    if (data_tx_initial.get('record_count') != 0 or
            data_tx_initial.get('dropped_count') != 0 or
            data_tx_initial.get('owner_present') != 0):
        raise SystemExit('Test076 data-TX trace is not empty/unowned before the one-shot diagnostic; unchanged')
    # Native mDNSResponder owns UDP 5353; a scoped browse request is not proof
    # that a particular QU/QM packet was emitted. Actual driver counters decide.
    browse=None
    browse_finish_allowed=False
    browse_cancel_reason='rf_sampling_not_complete'
    initial={k:v for k,v in state.items() if
        (k.startswith('NativeAwdlData') or k in DISCOVERY_SNAPSHOT_KEYS or
         k.startswith(RX_TRACE_PREFIX) or
         k.startswith(TX_PROGRESS_PREFIX) or k in TX_PROGRESS_ANCHOR_FIELDS or
         k in ('NativeAwdlDiscoveryExperimentEnabled',
               'NativeP2PProbeContextGeneration',
               'NativeP2PProbePowerGeneration',
               'NativeP2PProbeStationGeneration') or
         k in OPTIONAL_DISCOVERY_DIAGNOSTIC_KEYS +
              MIF_BOOTSTRAP_DIAGNOSTIC_KEYS) and type(v) in (int,bool)}
    initial_counters={key:state[key] for key in REQUIRED_COUNTERS}
    record={'build':args.expect_build,'boot_epoch':boot,'started_at':datetime.datetime.now().astimezone().isoformat(),
        'router_observation_id':args.router_observation_id,
        'external_receiver_started_by_collector':False,
        'receiver_gated':args.receiver_gated,
        'identity':identity,'bsd_index':index,'retry_permitted':False,'status':'preflight_passed_not_armed',
        'initial':initial,'initial_counters':initial_counters,'samples':[],
        'native_browser_active_before_arm':True,'maximum_mif_frames':3,
        'wire_query_class_determined_by_driver':True,'native_browse':{},
        'mif_bootstrap_diagnostic_scope':'Optional address-free current-state scalars only; missing values are unknown. Ready/Prepared/Submitted/Succeeded are local driver witnesses and do not prove peer receipt, AirDrop, or RF airtime.',
        'mif_bootstrap_diagnostic_samples':[],
        'counter_anomalies':[],'raw_counter_missing_keys':[],'raw_counter_invalid_keys':[],
        'raw_counter_regressed_keys':[],'arm_attempted':False,
        'discovery_evidence_samples':[],'discovery_covered':False,
        'discovery_coverage':{'discovery_covered':False,
            'scope':'No stable discovery snapshot or local QM submission has been proven.'},
        'rx_entry_evidence':{
            'status':'not_published_before_post_ROC', 'valid':False,
            'scope':'RX entry telemetry is published after the ROC owner ends; absence before then is expected and is not zero-filled.'},
        'rx_trace_evidence':{
            'status':'not_published_before_post_ROC', 'valid':False,
            'scope':'The Test076 bounded RX event trace is published after the ROC owner ends; absence before then is unknown and is not zero-filled.'},
        'data_tx_trace_evidence':data_tx_initial,
        'data_tx_trace_evidence_samples':[
            {'phase':'pre_arm_stable_baseline',**data_tx_initial}],
        'ordinary_sta_tx_progress_evidence':{
            'status':'awaiting_three_reads','applicable':None,'valid':False,
            'current':False,'complete':False,
            'scope':'Optional watchdog-correlated STA TX progress; no queue/ring ownership or AWDL claim.'},
        'ordinary_sta_tx_progress_evidence_samples':[],
        'prepared_wire_evidence':{
            'status':'awaiting_post_ROC_trace', 'applicable':None, 'valid':False,
            'global_fallback_used':False,
            'scope':'Optional same-ticket wire metadata; no ticket result is inferred before a complete post-ROC trace.'},
        'prepared_wire_evidence_samples':[],
        'query_response_scope':'Native scoped DNS-SD may emit QU, QM, other traffic or no new query due to caching. Actual class-specific firmware successes establish coverage. Missing QM is not a receive failure.',
        'scope':'One bounded real kernel/firmware/RX data observation; not sustained throughput or AirDrop proof.'}
    def save():
        out.write_text(json.dumps(record,indent=2)+'\n');out.chmod(0o600)
        account=pwd.getpwnam(os.environ['SUDO_USER']) if os.environ.get('SUDO_USER') else pwd.getpwuid(root.stat().st_uid)
        os.chown(out,account.pw_uid,account.pw_gid)
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    with out.open('x'):pass
    save()
    try:
        account=pwd.getpwuid(root.stat().st_uid)
        claim_directory=claim_directory_for(account)
        def record_claim(claim):
            record['boot_attempt_claim']=str(claim)
            record['boot_attempt_consumed_before_native_browser']=True
            record['status']='boot_attempt_consumed_before_native_browser'
            save()
            if args.receiver_gated:
                receiver_gate('BROWSE','NATIVE-PREFLIGHT-READY')
        try:
            browse=start_claimed_native_browser(
                claim_directory,boot,args.router_observation_id,browser,record_claim)
        except FileExistsError:
            raise SystemExit('This boot already has a consumed observation attempt; do not retry with another output label')
        browser_ready=json.loads(bounded_browser_ready_line(browse.stdout))
        if browser_ready.get('ready') is not True or browser_ready.get('interface_index')!=index:
            raise SystemExit('Native DNS-SD interface/request rejected; no arm')
        record['native_browse'].update(
            started_monotonic_ns=getattr(browse,'test076_window_started_monotonic_ns',None),
            ready_monotonic_ns=time.monotonic_ns(),ready=True)
        record['native_browse']['request']=browser_ready;save()
        if args.receiver_gated:
            receiver_gate('ARM','NATIVE-BROWSER-READY',timeout=10)
        require_native_browser_alive(browse)
        record['arm_attempted']=True
        record['status']='arm_attempt_outcome_pending'
        save()
        try:
            arm=subprocess.run([str(helper),'--expect-build',args.expect_build,'--expect-resident-data'],capture_output=True,text=True,timeout=10)
        except subprocess.TimeoutExpired:
            record.update(status='measurement_incomplete',arm_outcome='timeout_ambiguous')
            save()
            raise SystemExit('Arm result timed out; this boot is consumed and must not be retried')
        if args.receiver_gated:
            print('NATIVE-ARM-RETURNED',flush=True)
        record.update(arm_exit=arm.returncode,arm_output=arm.stdout.strip(),error=arm.stderr.strip(),status='armed' if not arm.returncode else 'arm_rejected');save()
        if arm.returncode:raise SystemExit('Arm rejected; inspect without retry')
        started=time.monotonic();prior=None;prior_discovery=None;prior_rx=None;prior_rx_trace=None;prior_bootstrap=None;prior_prepared_wire=None;prior_data_tx_trace=data_tx_initial;final=None
        prior_sta_tx_progress=None
        while time.monotonic()-started<20:
            elapsed=time.monotonic()-started
            trace_pre=properties('AirportItlwm')
            values=properties('AirportItlwm')
            trace_post=properties('AirportItlwm')
            trace=guarded_time_evidence(trace_pre,values,trace_post)
            discovery_guard=guarded_discovery_evidence(
                trace_pre,values,trace_post)
            trace['elapsed_seconds']=round(elapsed,3)
            record.setdefault('time_evidence_snapshots',[]).append(trace)
            missing,invalid=counter_problems(values)
            current={key:values[key] for key in REQUIRED_COUNTERS
                     if key in values and type(values[key]) is int and values[key]>=0}
            regressed=counter_regressions(values,initial_counters)
            if missing or invalid or regressed:
                anomaly={'elapsed_seconds':round(elapsed,3),'missing_keys':missing,
                         'invalid_keys':invalid,'regressed_keys':regressed}
                if anomaly not in record['counter_anomalies']:
                    record['counter_anomalies'].append(anomaly)
                record['raw_counter_missing_keys']=sorted(set(record['raw_counter_missing_keys'])|set(missing))
                record['raw_counter_invalid_keys']=sorted(set(record['raw_counter_invalid_keys'])|set(invalid))
                record['raw_counter_regressed_keys']=sorted(set(record['raw_counter_regressed_keys'])|set(regressed))
                record['status']='measurement_incomplete'
            else:
                final=current
            row={k:v for k,v in values.items() if type(v) in (int,bool) and
                (k.startswith(('NativeAwdlData','NativeAwdlLifecycle','NativeP2PProbe','NativeP2PTxPreArm','NativeP2PTxSubmit','NativeP2PTxDrain','NativeP2PTxHost','NativeP2PTxTimeEvidence','NativeP2PGp2','NativeP2PTxQueue','NativeP2PTxFirmware','NativeP2PTxPlaceholder','NativeP2PTxSetup','NativeP2PPeer','NativeP2PRx','NativeP2PAwdl','NativeP2PTxRebind','NativeP2PTxRetained','NativeP2PRoc','NativeResetTrace')) or
                 k in DISCOVERY_SNAPSHOT_KEYS + OPTIONAL_DISCOVERY_DIAGNOSTIC_KEYS + ('NativePowerReady','NativePowerResetCount','NativeAwdlDiscoveryExperimentEnabled'))}
            data_tx_attempt = current_data_tx_attempt_witness(
                trace_pre, values, trace_post, initial_counters)
            data_tx_sample=guarded_data_tx_trace_evidence(
                data_tx_trace_scalar_snapshot(trace_pre),
                data_tx_trace_scalar_snapshot(values),
                data_tx_trace_scalar_snapshot(trace_post),
                current_attempt=data_tx_attempt)
            data_tx_changed=data_tx_sample!=prior_data_tx_trace
            if data_tx_changed:
                record['data_tx_trace_evidence']=data_tx_sample
                record['data_tx_trace_evidence_samples'].append({
                    'elapsed_seconds':round(elapsed,3),**data_tx_sample})
                prior_data_tx_trace=data_tx_sample
            sta_tx_progress=guarded_sta_tx_progress_evidence(
                trace_pre,values,trace_post)
            if sta_tx_progress!=prior_sta_tx_progress:
                record['ordinary_sta_tx_progress_evidence']=sta_tx_progress
                record['ordinary_sta_tx_progress_evidence_samples'].append({
                    'elapsed_seconds':round(elapsed,3),**sta_tx_progress})
                prior_sta_tx_progress=sta_tx_progress
            discovery_sample={
                'pre':discovery_scalar_snapshot(trace_pre),
                'middle':discovery_scalar_snapshot(values),
                'post':discovery_scalar_snapshot(trace_post),
                'guard':discovery_guard,
            }
            bootstrap_sample={
                'pre':mif_bootstrap_diagnostic_snapshot(trace_pre),
                'middle':mif_bootstrap_diagnostic_snapshot(values),
                'post':mif_bootstrap_diagnostic_snapshot(trace_post),
            }
            bootstrap_changed=bootstrap_sample!=prior_bootstrap
            if bootstrap_changed:
                record['mif_bootstrap_diagnostic_samples'].append({
                    'elapsed_seconds':round(elapsed,3),**bootstrap_sample})
                prior_bootstrap=bootstrap_sample
            rx_guard=guarded_rx_entry_evidence(
                rx_entry_scalar_snapshot(trace_pre),
                rx_entry_scalar_snapshot(values),
                rx_entry_scalar_snapshot(trace_post))
            rx_trace_transport=test076_rx_trace_transport_evidence(
                rx_trace_scalar_snapshot(trace_pre),
                rx_trace_scalar_snapshot(values),
                rx_trace_scalar_snapshot(trace_post))
            rx_trace_pre=rx_trace_transport['raw_snapshots']['pre']
            rx_trace_middle=rx_trace_transport['raw_snapshots']['middle']
            rx_trace_post=rx_trace_transport['raw_snapshots']['post']
            rx_trace_guard=rx_trace_transport['guard']
            roc_started=successful_roc_start(values)
            roc_ended=successful_roc_ended(values)
            prepared_wire_sample=correlate_prepared_wire_evidence(
                trace, rx_trace_guard)
            prepared_wire_changed=prepared_wire_sample!=prior_prepared_wire
            if prepared_wire_changed:
                record['prepared_wire_evidence']=prepared_wire_sample
                record['prepared_wire_evidence_samples'].append({
                    'elapsed_seconds':round(elapsed,3),
                    **prepared_wire_sample})
                prior_prepared_wire=prepared_wire_sample
            if roc_ended and rx_guard['valid']:
                rx_sample={
                    'status':'stable_complete_post_ROC_snapshot',
                    'valid':True,
                    'roc_start_succeeded':True,
                    'roc_owner_ended':True,
                    'pre':rx_entry_scalar_snapshot(trace_pre),
                    'middle':rx_entry_scalar_snapshot(values),
                    'post':rx_entry_scalar_snapshot(trace_post),
                    'guard':rx_guard,
                    'interpretation':'Numeric owner-window entry counts and bounded witnesses only. Raw status/mac_phy/filter_match are not decoded; zero counts are not treated as RF silence.',
                }
            elif roc_ended:
                rx_sample={
                    'status':'post_ROC_snapshot_incomplete',
                    'valid':False,
                    'roc_start_succeeded':True,
                    'roc_owner_ended':True,
                    'pre':rx_entry_scalar_snapshot(trace_pre),
                    'middle':rx_entry_scalar_snapshot(values),
                    'post':rx_entry_scalar_snapshot(trace_post),
                    'guard':rx_guard,
                    'interpretation':'Post-window snapshot is incomplete or unstable; missing fields are unknown, not zero.',
                }
            elif roc_started:
                rx_sample={
                    'status':'awaiting_ROC_owner_end_publication',
                    'valid':False,
                    'roc_start_succeeded':True,
                    'roc_owner_ended':False,
                    'scope':'No complete entry snapshot is expected while the ROC owner is active.',
                }
            else:
                rx_sample={
                    'status':'awaiting_successful_ROC_start',
                    'valid':False,
                    'roc_start_succeeded':False,
                    'roc_owner_ended':False,
                    'scope':'No RX entry interpretation is available before a successful current ROC.',
                }
            if roc_ended:
                rx_trace_sample={
                    'status':'stable_complete_post_ROC_trace' if rx_trace_guard['valid'] else 'post_ROC_trace_incomplete_or_invalid',
                    'valid':rx_trace_guard['valid'],
                    'roc_start_succeeded':True,
                    'roc_owner_ended':True,
                    'pre':rx_trace_pre,
                    'middle':rx_trace_middle,
                    'post':rx_trace_post,
                    'guard':rx_trace_guard,
                    'transport_validation':rx_trace_transport,
                    'prepared_wire_evidence':prepared_wire_sample,
                    'interpretation':'Producer-side bounded event trace only. Dropped events, stale completions, and source-table exhaustion are explicit coverage limits; no peer receipt is inferred.',
                }
            elif roc_started:
                rx_trace_sample={
                    'status':'awaiting_ROC_owner_end_publication',
                    'valid':False,
                    'roc_start_succeeded':True,
                    'roc_owner_ended':False,
                    'scope':'No complete trace snapshot is expected while the ROC owner is active.',
                }
            else:
                rx_trace_sample={
                    'status':'awaiting_successful_ROC_start',
                    'valid':False,
                    'roc_start_succeeded':False,
                    'roc_owner_ended':False,
                    'scope':'No RX trace is interpreted before a successful current ROC.',
                }
            rx_changed=rx_sample!=prior_rx
            if rx_changed:
                record['rx_entry_evidence']=rx_sample
                prior_rx=rx_sample
            rx_trace_changed=rx_trace_sample!=prior_rx_trace
            if rx_trace_changed:
                record['rx_trace_evidence']=rx_trace_sample
                prior_rx_trace=rx_trace_sample
            discovery_changed=discovery_sample!=prior_discovery
            if discovery_changed:
                record['discovery_evidence_samples'].append({
                    'elapsed_seconds':round(elapsed,3),**discovery_sample})
                prior_discovery=discovery_sample
            row_changed=row!=prior
            if row_changed:
                record['samples'].append({'elapsed_seconds':round(elapsed,3),'values':row})
                prior=row
            if (row_changed or discovery_changed or rx_changed or rx_trace_changed or
                    bootstrap_changed or prepared_wire_changed or data_tx_changed):
                save()
            if values.get('NativePowerReady')!=1:
                browse_cancel_reason='native_power_not_ready'
                record['native_browse']['sampling_stop_reason']=browse_cancel_reason
                break
            if (elapsed>3 and values.get('NativeP2PProbeAttempted')==1 and
                    values.get('NativeP2PProbeResourceMayExist')==0 and
                    (not roc_started or (rx_sample.get('valid') is True and
                                         rx_trace_sample.get('valid') is True))):
                browse_finish_allowed=True
                break
            time.sleep(.05)
        else:
            browse_finish_allowed=True
        if record['counter_anomalies'] or final is None:
            last_guard=(record['discovery_evidence_samples'][-1]['guard']
                        if record['discovery_evidence_samples'] else {'valid':False,'values':{}})
            record['discovery_coverage']=discovery_coverage(last_guard,{})
            record['discovery_covered']=False
            record.update(status='measurement_incomplete',
                counter_delta_interpretation='suppressed_due_to_missing_invalid_or_regressed_counter',
                wifi_ready=ready('en1'),resident_survives='awdl0' in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split(),
                firmware_resources_absent=firmware_resources_absent(prior or {}),
                finished_at=datetime.datetime.now().astimezone().isoformat())
            save()
            print(json.dumps({k:record[k] for k in ['status','raw_counter_missing_keys','raw_counter_invalid_keys','raw_counter_regressed_keys','wifi_ready','resident_survives','firmware_resources_absent','discovery_covered']}))
            return
        delta=lambda key:final[key]-initial_counters[key]
        discovery_delta={key:delta(key) for key in DISCOVERY_DATA_DELTA_COUNTERS}
        last_guard=(record['discovery_evidence_samples'][-1]['guard']
                    if record['discovery_evidence_samples'] else {'valid':False,'values':{}})
        record['discovery_coverage']=discovery_coverage(last_guard,discovery_delta)
        record['discovery_covered']=record['discovery_coverage']['discovery_covered']
        stages={'kernel_tx_accepted':delta('NativeAwdlDataTxAccepted')>0,
            'firmware_data_tx_completed':delta('NativeAwdlDataTxCompleted')>0,
            'firmware_data_tx_success':delta('NativeAwdlDataTxSucceeded')>0,
            'real_radio_data_captured':delta('NativeAwdlDataRxCaptured')>0,
            'native_input_accepted':delta('NativeAwdlDataRxDelivered')>0,
            'remote_receipt_proven':False,'airdrop_proven':False}
        passed=all(stages[k] for k in ['kernel_tx_accepted','firmware_data_tx_success','real_radio_data_captured','native_input_accepted'])
        record['actual_query_class_deltas']={name:{stage:delta('NativeAwdlDataTxMdns'+name+stage) for stage in MDNS_STAGES} for name in MDNS_CLASSES}
        record['qm_firmware_success_covered']=record['actual_query_class_deltas']['Qm']['Succeeded']>0
        record['address_advertisement']={k:(prior or {}).get(k) for k in [
            'NativeP2PAwdlNativeAddressCandidateVerified','NativeP2PAwdlNativeAddressVerified','NativeP2PAwdlNativeAddressFailure',
            'NativeP2PAwdlPsfDataPathAddressCandidate','NativeP2PAwdlPsfDataPathAdvertised',
            'NativeP2PAwdlPsfFrameSubmitted','NativeP2PAwdlPsfTxComplete','NativeP2PAwdlPsfTxSucceeded',
            'NativeP2PAwdlMifDataPathAddressCandidate','NativeP2PAwdlMifDataPathAdvertised',
            'NativeP2PAwdlMifFrameSubmitted','NativeP2PAwdlMifTxComplete','NativeP2PAwdlMifTxSucceeded']}
        record['address_advertisement_scope']='Candidate, submit and firmware-completion scalars are distinct local witnesses. No addresses are saved. Fields are last published observations, not remote receipt, external-ioctl exclusion, or AirDrop proof.'
        record.update(status='limited_native_data_pipeline_observed' if passed else 'partial_native_data_pipeline_observation',
            stages=stages,wifi_ready=ready('en1'),resident_survives='awdl0' in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split(),
            firmware_resources_absent=firmware_resources_absent(prior or {}),
            rx_entry_snapshot_valid=record['rx_entry_evidence'].get('valid') is True,
            rx_entry_snapshot_status=record['rx_entry_evidence'].get('status'),
            discovery_coverage_scope='Local single-QM submission only; not remote receipt, formal window coverage, or AirDrop proof.',
            finished_at=datetime.datetime.now().astimezone().isoformat())
        save();print(json.dumps({k:record[k] for k in ['status','stages','wifi_ready','resident_survives','firmware_resources_absent','discovery_covered','prepared_wire_evidence']}))
    finally:
        cancellation['during_cleanup']=True
        if browse:
            if (record['arm_attempted'] and browse_finish_allowed and
                    not cancellation['requested']):
                finish_native_browse_window(
                    browse,record,cancel_check=lambda: cancellation['requested'])
            else:
                reason=('coordinator_cancelled_' + str(cancellation['signal'])
                        if cancellation['requested'] else
                        browse_cancel_reason if record['arm_attempted'] else
                        'cancelled_before_arm')
                record['native_browse'].update(
                    window_status='censored_interrupted',window_complete=False,censored=True,
                    normal_exit=False,exit_kind='forced_termination',
                    forced_termination_reason=reason)
                if browse.poll() is None:
                    browse.terminate()
                    record['native_browse']['forced_terminate_sent']=True
                try:output,_=browse.communicate(
                    timeout=NATIVE_BROWSE_TERMINATE_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    browse.kill()
                    record['native_browse']['forced_kill_sent']=True
                    try:
                        output,_=browse.communicate(
                            timeout=NATIVE_BROWSE_KILL_REAP_GRACE_SECONDS)
                    except subprocess.TimeoutExpired:
                        output=''
                record['native_browse']['exit']=browse.returncode
                record['native_browse']['final_numeric']=[]
        if record['arm_attempted'] and record['status'] in ('arm_attempt_outcome_pending','armed'):
            record['status']='measurement_incomplete'
            record['counter_delta_interpretation']='capture_interrupted_before_complete_counter_validation'
        record['native_browse_window_complete']=(
            record.get('native_browse',{}).get('window_complete') is True)
        progress=record.get('ordinary_sta_tx_progress_evidence',{})
        record['ordinary_sta_tx_progress_status']=progress.get('status')
        record['ordinary_sta_tx_watchdog_current']=progress.get('current') is True
        record['receiver_browse_overlap_seconds']=None
        record['receiver_browse_overlap_proven']=False
        record['receiver_browse_overlap_scope']='Unknown: independent receiver/browse clocks and capture scheduling do not prove full over-air window overlap.'
        save()
        print(json.dumps({
            'status':record.get('status'),
            'native_browse_window_complete':record['native_browse_window_complete'],
            'native_browse_window_status':record.get('native_browse',{}).get('window_status'),
            'data_tx_trace_status':record.get('data_tx_trace_evidence',{}).get('status'),
            'data_tx_trace_valid':record.get('data_tx_trace_evidence',{}).get('valid'),
            'data_tx_trace_stage_coverage_complete':record.get('data_tx_trace_evidence',{}).get('stage_coverage_complete'),
            'data_tx_trace_current_attempt_bound':record.get('data_tx_trace_evidence',{}).get('current_attempt_bound'),
            'data_tx_trace_freshness_status':record.get('data_tx_trace_evidence',{}).get('freshness_status'),
            'peer_receipt_proven':False,'airdrop_proven':False},separators=(',',':'),flush=True))

if __name__=='__main__':main()
