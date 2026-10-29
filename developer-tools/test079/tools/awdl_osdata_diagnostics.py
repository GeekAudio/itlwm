#!/usr/bin/env python3
"""Decode bounded, address-free native AWDL diagnostic OSData records.

These records are local driver observations. They do not establish over-air
transmission, peer receipt, or AirDrop completion.
"""

from __future__ import annotations

import plistlib
import struct
import subprocess


CURRENT_AW_ATTEMPT_KEY = 'NativeP2PCurrentAwAttemptOnly'
CURRENT_AW_ATTEMPT_SIZE = 110
CURRENT_AW_ATTEMPT_STRUCT = struct.Struct('<IH12B4I2Q2Q3I4Q')
CURRENT_AW_ATTEMPT_MAGIC = 0x41574143  # little-endian bytes "CAWA"
CURRENT_AW_ATTEMPT_SCHEMA = 1
CURRENT_AW_ATTEMPT_STATUS_MAX = 31
CURRENT_AW_ATTEMPT_CONSISTENCY_QM_IDENTITY = 1 << 0
CURRENT_AW_ATTEMPT_CONSISTENCY_EPOCHS = 1 << 1
CURRENT_AW_ATTEMPT_KNOWN_CONSISTENCY_FLAGS = (
    CURRENT_AW_ATTEMPT_CONSISTENCY_QM_IDENTITY |
    CURRENT_AW_ATTEMPT_CONSISTENCY_EPOCHS
)
QM_WIRE_KEY = 'NativeP2PQmWireSnapshot'
QM_WIRE_SIZE = 288
QM_WIRE_FIELD_NAMES = (
    'schema', 'token', 'context_generation', 'power_generation',
    'station_generation', 'roc_token', 'station_id', 'queue_id', 'ring_size',
    'descriptor_index', 'frame_control', 'sequence_control', 'mpdu_length',
    'header_length', 'ds_bits', 'address_role_flags', 'header_is_valid',
    'driver_frame_type', 'tx_layout', 'tx_command_api', 'tx_notification_api',
    'tx_flags', 'rate_n_flags', 'offload_assist', 'mh_size_words', 'tfd_count',
    'first_tb_bytes', 'command_tail_bytes', 'payload_segment_count',
    'payload_bytes', 'channel', 'frequency_mhz', 'host_pre_doorbell_us',
    'window_not_before_us', 'window_deadline_us', 'current_gp2_valid',
)
QM_WIRE_HEADER_ROLE_FLAGS = 0xff


def decode_current_aw_attempt_osdata(payload: bytes | bytearray | memoryview | None):
    """Validate/decode one fixed-size current-AW attempt-only payload."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return {
            'status': 'unknown_missing_or_wrong_type', 'valid': False,
            'reasons': ['payload_not_bytes'],
            'radio_transmit_proven': False, 'peer_receipt_proven': False,
        }
    raw = bytes(payload)
    if len(raw) != CURRENT_AW_ATTEMPT_SIZE:
        return {
            'status': 'unknown_invalid_length', 'valid': False,
            'payload_length': len(raw), 'expected_length': CURRENT_AW_ATTEMPT_SIZE,
            'reasons': ['payload_length_mismatch'],
            'radio_transmit_proven': False, 'peer_receipt_proven': False,
        }

    values = CURRENT_AW_ATTEMPT_STRUCT.unpack(raw)
    (magic, schema, evidence_class, complete, peer_receipt_proven,
     radio_transmit_proven, fallback_enabled, initial_present, final_present,
     initial_candidate_valid, final_candidate_valid, initial_fallback_used,
     final_fallback_used, consistency_flags, context_generation,
     power_generation, station_generation, roc_generation, qm_token,
     qm_generation, initial_planner_now_us, final_planner_now_us,
     planner_calls, initial_status, final_status, initial_earliest_submit_us,
     initial_latest_submit_us, final_earliest_submit_us,
     final_latest_submit_us) = values

    reasons = []
    if magic != CURRENT_AW_ATTEMPT_MAGIC:
        reasons.append('magic_mismatch')
    if schema != CURRENT_AW_ATTEMPT_SCHEMA:
        reasons.append('unsupported_schema')
    if evidence_class != 1 or complete != 1:
        reasons.append('not_complete_attempt_only_record')
    if peer_receipt_proven != 0 or radio_transmit_proven != 0:
        reasons.append('attempt_record_claims_forbidden_proof')
    booleans = (
        peer_receipt_proven, radio_transmit_proven, fallback_enabled,
        initial_present, final_present, initial_candidate_valid,
        final_candidate_valid, initial_fallback_used, final_fallback_used,
    )
    if any(value not in (0, 1) for value in booleans):
        reasons.append('invalid_boolean_field')
    if consistency_flags & ~CURRENT_AW_ATTEMPT_KNOWN_CONSISTENCY_FLAGS:
        reasons.append('unknown_consistency_flags')
    if not all((context_generation, power_generation, station_generation,
                roc_generation, qm_token, qm_generation)):
        reasons.append('generation_or_qm_identity_missing')
    if qm_generation != power_generation:
        reasons.append('qm_power_generation_mismatch')
    if planner_calls == 0 or planner_calls > 255:
        reasons.append('planner_call_count_invalid')

    plans = {
        'initial': {
            'present': bool(initial_present),
            'planner_now_us': initial_planner_now_us,
            'status': initial_status,
            'candidate_valid': bool(initial_candidate_valid),
            'fallback_used': bool(initial_fallback_used),
            'earliest_submit_us': initial_earliest_submit_us,
            'latest_submit_us': initial_latest_submit_us,
        },
        'final': {
            'present': bool(final_present),
            'planner_now_us': final_planner_now_us,
            'status': final_status,
            'candidate_valid': bool(final_candidate_valid),
            'fallback_used': bool(final_fallback_used),
            'earliest_submit_us': final_earliest_submit_us,
            'latest_submit_us': final_latest_submit_us,
        },
    }
    if not any(plan['present'] for plan in plans.values()):
        reasons.append('no_planner_observation')
    for label, plan in plans.items():
        if not plan['present']:
            if any((plan['planner_now_us'], plan['status'],
                    plan['candidate_valid'], plan['fallback_used'],
                    plan['earliest_submit_us'], plan['latest_submit_us'])):
                reasons.append(label + '_absent_plan_has_values')
            continue
        if plan['status'] > CURRENT_AW_ATTEMPT_STATUS_MAX:
            reasons.append(label + '_unsupported_planner_status')
        if plan['candidate_valid'] != (plan['status'] == 0):
            reasons.append(label + '_candidate_status_mismatch')
        if plan['fallback_used'] and (
                not plan['candidate_valid'] or not fallback_enabled):
            reasons.append(label + '_fallback_flag_mismatch')
        if plan['candidate_valid']:
            if (plan['earliest_submit_us'] == 0 or
                    plan['latest_submit_us'] <= plan['earliest_submit_us']):
                reasons.append(label + '_candidate_window_invalid')
        elif plan['earliest_submit_us'] or plan['latest_submit_us']:
            reasons.append(label + '_rejected_plan_has_window')

    qm_identity_consistent = bool(
        consistency_flags & CURRENT_AW_ATTEMPT_CONSISTENCY_QM_IDENTITY)
    planner_epochs_stable = bool(
        consistency_flags & CURRENT_AW_ATTEMPT_CONSISTENCY_EPOCHS)
    if qm_identity_consistent and not (initial_present and final_present):
        reasons.append('qm_identity_consistency_without_both_plans')

    valid = not reasons
    return {
        'status': 'valid_attempt_only' if valid else
                  'unknown_invalid_attempt_only_record',
        'valid': valid,
        'schema': schema,
        'evidence_class': evidence_class,
        'complete': bool(complete),
        'fallback_enabled': bool(fallback_enabled),
        'consistency_flags': consistency_flags,
        'qm_identity_consistent': qm_identity_consistent,
        'planner_epochs_stable': planner_epochs_stable,
        'context_generation': context_generation,
        'power_generation': power_generation,
        'station_generation': station_generation,
        'roc_generation': roc_generation,
        'qm_token': qm_token,
        'qm_generation': qm_generation,
        'planner_calls': planner_calls,
        'plans': plans,
        'radio_transmit_proven': False,
        'peer_receipt_proven': False,
        'airdrop_proven': False,
        'reasons': reasons,
        'scope': ('Planner attempt only. Local timing/queue identity does not '
                  'prove firmware transmission, RF airtime, peer receipt, or AirDrop.'),
    }


def read_ioreg_data_property(class_name: str, key: str):
    """Return one NSData property from an ioreg plist, or None if absent."""
    tree = plistlib.loads(subprocess.check_output(
        ['/usr/sbin/ioreg', '-a', '-r', '-c', class_name]))
    found = []

    def visit(node):
        if not isinstance(node, dict):
            return
        if key in node:
            found.append(node[key])
        for child in node.get('IORegistryEntryChildren', []):
            visit(child)

    for node in tree:
        visit(node)
    if not found:
        return None
    if len(found) != 1 or not isinstance(found[0], bytes):
        raise ValueError('ioreg data property missing, duplicated, or not NSData')
    return found[0]


def decode_qm_wire_osdata(payload: bytes | bytearray | memoryview | None):
    """Validate/decode the 36-field, 288-byte address-free local QM snapshot."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return {
            'status': 'unknown_missing_or_wrong_type', 'valid': False,
            'reasons': ['payload_not_bytes'],
            'radio_transmit_proven': False, 'peer_receipt_proven': False,
        }
    raw = bytes(payload)
    if len(raw) != QM_WIRE_SIZE:
        return {
            'status': 'unknown_invalid_length', 'valid': False,
            'payload_length': len(raw), 'expected_length': QM_WIRE_SIZE,
            'reasons': ['payload_length_mismatch'],
            'radio_transmit_proven': False, 'peer_receipt_proven': False,
        }
    values = struct.unpack('<36Q', raw)
    record = dict(zip(QM_WIRE_FIELD_NAMES, values))
    reasons = []
    if record['schema'] != 1:
        reasons.append('unsupported_schema')
    if not all(record[name] for name in (
            'token', 'context_generation', 'power_generation',
            'station_generation', 'roc_token')):
        reasons.append('token_or_generation_missing')
    if record['header_is_valid'] not in (0, 1):
        reasons.append('invalid_header_valid_flag')
    if record['address_role_flags'] & ~QM_WIRE_HEADER_ROLE_FLAGS:
        reasons.append('unknown_address_role_flags')
    if bool(record['header_is_valid']) != bool(record['address_role_flags'] & 1):
        reasons.append('header_validity_role_flag_mismatch')
    if record['ds_bits'] > 3:
        reasons.append('invalid_ds_bits')
    if record['header_length'] > 255 or record['frame_control'] > 0xffff or \
            record['sequence_control'] > 0xffff or record['mpdu_length'] > 0xffff:
        reasons.append('header_scalar_out_of_range')
    if record['current_gp2_valid'] != 0:
        reasons.append('unexpected_current_gp2_claim')
    if (record['window_not_before_us'] and record['window_deadline_us'] and
            record['window_deadline_us'] <= record['window_not_before_us']):
        reasons.append('submit_window_invalid')
    valid = not reasons
    return {
        'status': 'valid_local_qm_wire_snapshot' if valid else
                  'unknown_invalid_qm_wire_snapshot',
        'valid': valid,
        'schema': record['schema'],
        'values': record,
        'radio_transmit_proven': False,
        'peer_receipt_proven': False,
        'airdrop_proven': False,
        'reasons': reasons,
        'scope': ('Local driver TX-path snapshot. It contains no raw address or '
                  'frame bytes and does not prove over-air transmission or peer receipt.'),
    }


def cross_check_attempt_qm_identity(attempt, qm):
    """Compare local planner and local QM records without upgrading proof."""
    if not (isinstance(attempt, dict) and attempt.get('valid') and
            isinstance(qm, dict) and qm.get('valid')):
        return {
            'status': 'unknown_missing_or_invalid_record', 'valid': False,
            'token_matches': None, 'generation_matches': None,
            'radio_transmit_proven': False, 'peer_receipt_proven': False,
        }
    qm_values = qm['values']
    token_matches = attempt['qm_token'] == qm_values['token']
    generation_matches = (
        attempt['qm_generation'] == qm_values['power_generation'] and
        attempt['context_generation'] == qm_values['context_generation'] and
        attempt['station_generation'] == qm_values['station_generation'])
    valid = token_matches and generation_matches
    return {
        'status': 'local_identity_match' if valid else 'local_identity_mismatch',
        'valid': valid,
        'token_matches': token_matches,
        'generation_matches': generation_matches,
        'attempt_roc_generation': attempt['roc_generation'],
        'qm_roc_token': qm_values['roc_token'],
        'radio_transmit_proven': False,
        'peer_receipt_proven': False,
        'airdrop_proven': False,
    }
