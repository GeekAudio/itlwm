#!/usr/bin/env python3
"""Read-only, whitelist decoder for the 544-byte Iwx link-state OSData trace.

The decoded record contains bounded numeric state-transition telemetry only.
It never includes addresses, identifiers, packet contents, or RF/peer claims.
"""

from __future__ import annotations

import struct


WIFI_LINK_TRACE_KEY = 'NativeWifiLinkTransitionTrace'
WIFI_LINK_TRACE_SIZE = 544
WIFI_LINK_TRACE_SCHEMA = 2
WIFI_LINK_TRACE_CAPACITY = 8
WIFI_LINK_TRACE_KNOWN_VALIDITY_MASK = 0x7F
WIFI_LINK_TRACE_HEADER = struct.Struct('<6IQ')
WIFI_LINK_TRACE_RECORD = struct.Struct('<QQ5Ii5I4x')

EVENT_NAMES = {
    1: 'new_state_requested',
    2: 'new_state_task_completed',
    3: 'deauth_entered',
    4: 'deauth_returned',
    5: 'reset_begin',
    6: 'reset_complete',
    7: 'reset_skipped',
}

VALIDITY_FIELDS = (
    (1 << 0, 'old_state'),
    (1 << 0, 'new_state'),
    (1 << 1, 'deauth_reason'),
    (1 << 2, 'state_argument'),
    (1 << 3, 'result_code'),
    (1 << 4, 'if_up_running'),
    (1 << 5, 'driver_generation'),
    (1 << 5, 'reset_generation'),
    (1 << 6, 'watchdog_sequence'),
)


def decode_wifi_link_trace_osdata(payload: bytes | bytearray | memoryview | None):
    """Validate and whitelist-decode one immutable 544-byte OSData snapshot."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return {
            'status': 'unknown_missing_or_wrong_type', 'valid': False,
            'reasons': ['payload_not_bytes'], 'records': [],
            'wifi_link_stability_proven': False,
        }

    raw = bytes(payload)
    if len(raw) != WIFI_LINK_TRACE_SIZE:
        return {
            'status': 'unknown_invalid_length', 'valid': False,
            'payload_length': len(raw), 'expected_length': WIFI_LINK_TRACE_SIZE,
            'reasons': ['payload_length_mismatch'], 'records': [],
            'wifi_link_stability_proven': False,
        }

    schema, capacity, version_begin, version_end, dropped, count, next_sequence = \
        WIFI_LINK_TRACE_HEADER.unpack_from(raw)
    reasons = []
    if schema != WIFI_LINK_TRACE_SCHEMA:
        reasons.append('unsupported_schema')
    if capacity != WIFI_LINK_TRACE_CAPACITY:
        reasons.append('capacity_mismatch')
    if version_begin != version_end or (version_begin & 1):
        reasons.append('snapshot_seqlock_unstable')
    if count > capacity:
        reasons.append('count_out_of_range')
    if next_sequence < count or count != min(next_sequence, capacity):
        reasons.append('sequence_count_mismatch')

    records = []
    if count <= capacity and next_sequence >= count:
        expected_sequence = next_sequence - count + 1
        for index in range(count):
            offset = WIFI_LINK_TRACE_HEADER.size + index * WIFI_LINK_TRACE_RECORD.size
            (sequence, monotonic_ns, event_code, old_state, new_state,
             deauth_reason, state_argument, result_code, if_up_running,
             driver_generation, reset_generation, watchdog_sequence,
             valid_mask) = WIFI_LINK_TRACE_RECORD.unpack_from(raw, offset)
            row_reasons = []
            if sequence != expected_sequence + index:
                row_reasons.append('record_sequence_not_contiguous')
            if sequence == 0 or monotonic_ns == 0:
                row_reasons.append('record_identity_or_clock_missing')
            if event_code not in EVENT_NAMES:
                row_reasons.append('unknown_event_code')
            if valid_mask & ~WIFI_LINK_TRACE_KNOWN_VALIDITY_MASK:
                row_reasons.append('unknown_validity_bits')
            if valid_mask & (1 << 4) and if_up_running & ~0x3:
                row_reasons.append('interface_flags_out_of_range')

            source_values = (
                old_state, new_state, deauth_reason, state_argument,
                result_code, if_up_running, driver_generation,
                reset_generation, watchdog_sequence,
            )
            field_values = dict(zip(
                (name for _, name in VALIDITY_FIELDS), source_values))
            for bit, name in VALIDITY_FIELDS:
                if not valid_mask & bit and field_values[name] != 0:
                    row_reasons.append('invalid_field_nonzero_' + name)
            whitelisted = {
                name: value if valid_mask & bit else None
                for (bit, name), value in zip(VALIDITY_FIELDS, source_values)
            }

            row = {
                'sequence': sequence,
                'monotonic_ns': monotonic_ns,
                'event_code': event_code,
                'event': EVENT_NAMES.get(event_code),
                'valid_mask': valid_mask,
                **whitelisted,
            }
            if row_reasons:
                reasons.extend('record_' + str(index) + '_' + item
                               for item in row_reasons)
            records.append(row)

    valid = not reasons
    return {
        'status': 'valid_wifi_link_transition_trace' if valid else
                  'unknown_invalid_wifi_link_transition_trace',
        'valid': valid,
        'schema': schema,
        'capacity': capacity,
        'snapshot_version_begin': version_begin,
        'snapshot_version_end': version_end,
        'dropped_count': dropped,
        'count': count,
        'next_sequence': next_sequence,
        'records': records,
        'wifi_link_stability_proven': False,
        'radio_transmit_proven': False,
        'peer_receipt_proven': False,
        'airdrop_proven': False,
        'reasons': reasons,
        'scope': ('Read-only driver state-transition telemetry. A bounded trace with no '
                  'observed transitions is not proof of Wi-Fi stability; it does not '
                  'prove RF transmission, peer receipt, or AirDrop.'),
    }
