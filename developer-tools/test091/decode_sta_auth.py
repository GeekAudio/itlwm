#!/usr/bin/env python3
"""Decode a saved numeric STA-auth snapshot. No live I/O or device operations."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct

HEADER = struct.Struct('<I4H11I')
RECORD = struct.Struct('<7I4Hi2I')
MAGIC = 0x41535449
LIVE_CAPACITY, FIRST_CAPACITY = 16, 8
SIZE = HEADER.size + (LIVE_CAPACITY + FIRST_CAPACITY) * RECORD.size
KINDS = {
    1: 'group1_begin', 2: 'group1_validation', 3: 'key_component',
    4: 'key_submit', 5: 'group2_local_output_result',
    6: 'received_deauth_handler', 7: 'received_disassoc_handler',
    8: 'local_deauth_output_result', 9: 'group1_local_failure',
    10: 'run_established', 11: 'association_loss_requested',
    12: 'driver_deauth_cleanup', 13: 'association_loss_completed',
}
SOURCES = {
    0: 'unknown', 1: 'receive_handler_not_authenticated_peer_proof',
    2: 'local_group1', 3: 'driver_cleanup', 4: 'hal_command',
    5: 'software_crypto',
}


def decode_record(raw: bytes) -> dict:
    fields = RECORD.unpack(raw)
    keys = ('sequence', 'monotonic_us_low', 'monotonic_us_high',
            'diagnostic_instance', 'driver_generation', 'association_id',
            'attempt_id', 'kind', 'stage', 'component', 'source',
            'result', 'flags', 'detail')
    row = dict(zip(keys, fields))
    if (row['sequence'] == 0 or row['kind'] not in KINDS or
            row['stage'] > 20 or row['component'] > 2 or
            row['source'] not in SOURCES or row['flags'] & ~0x1ff):
        raise ValueError('unknown or invalid numeric record')
    row['monotonic_us'] = row.pop('monotonic_us_low') | (row.pop('monotonic_us_high') << 32)
    row['event'] = KINDS[row['kind']]
    row['source_label'] = SOURCES[row['source']]
    return row


def decode(raw: bytes) -> dict:
    if len(raw) != SIZE:
        raise ValueError(f'snapshot length must be {SIZE}, got {len(raw)}')
    values = HEADER.unpack_from(raw)
    keys = ('magic', 'schema', 'header_bytes', 'record_bytes', 'capacity',
            'revision_begin', 'revision_end', 'flags', 'live_count',
            'dropped_count', 'diagnostic_instance', 'driver_generation',
            'association_id', 'next_attempt_id', 'first_state', 'first_count')
    result = dict(zip(keys, values))
    if (result['magic'] != MAGIC or result['schema'] != 1 or
            result['header_bytes'] != HEADER.size or
            result['record_bytes'] != RECORD.size or
            result['capacity'] != LIVE_CAPACITY):
        raise ValueError('unsupported snapshot layout')
    if (result['revision_begin'] != result['revision_end'] or
            result['revision_begin'] & 1 or result['flags'] & ~1 or
            result['live_count'] > LIVE_CAPACITY or
            result['first_count'] > FIRST_CAPACITY or result['first_state'] > 3):
        raise ValueError('inconsistent snapshot header')
    if (result['first_state'] == 2 and result['first_count'] == 0 or
            result['first_state'] != 2 and result['first_count'] != 0 or
            bool(result['flags'] & 1) != (result['first_state'] == 3)):
        raise ValueError('inconsistent first-trigger status')
    for name, capacity, count, offset in (
        ('live', LIVE_CAPACITY, result['live_count'], HEADER.size),
        ('first', FIRST_CAPACITY, result['first_count'], HEADER.size + LIVE_CAPACITY * RECORD.size),
    ):
        rows = [decode_record(raw[offset + i * RECORD.size:offset + (i + 1) * RECORD.size])
                for i in range(count)]
        if any(a['sequence'] >= b['sequence'] for a, b in zip(rows, rows[1:])):
            raise ValueError('unordered event sequence')
        if any(raw[offset + count * RECORD.size:offset + capacity * RECORD.size]):
            raise ValueError('nonzero unused record bytes')
        result[name] = rows
    result['first_capture_status'] = ('unclaimed', 'pending_unknown', 'captured', 'lost_unknown')[result['first_state']]
    result['records_dropped'] = result['dropped_count'] != 0
    result['snapshot_sha256'] = hashlib.sha256(raw).hexdigest()
    result['evidence_limits'] = [
        'Numeric local observations only; no keys, frame bodies, or addresses.',
        'Local enqueue and output success are not firmware ACK or peer receipt.',
        'Receive-handler entry is not sender authenticity or PMF validation.',
        'Only matching explicit attempt identifiers support attempt attribution.',
        'Lost records or a lost first trigger leave missing causes unknown.',
        'Captured means a bounded record copy, not complete causal history; ordering is append order.',
        'Receive-handler association identity is sampled at append, not at handler entry.',
        'Local deauth coverage here is Group1 and driver cleanup, not every system disconnect source.',
    ]
    return result


def extract_saved_blob(raw: bytes, property_name: str) -> bytes:
    if raw[:4] == struct.pack('<I', MAGIC):
        return raw
    tree = plistlib.loads(raw)
    matches = []
    def walk(value):
        if isinstance(value, dict):
            if property_name in value:
                matches.append(value[property_name])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(tree)
    if len(matches) != 1 or not isinstance(matches[0], bytes):
        raise ValueError('saved plist must contain exactly one binary snapshot property')
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--property', default='NativeGroupKeyForensicSnapshot')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = decode(extract_saved_blob(args.input.read_bytes(), args.property))
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'decoded': True, 'live_count': result['live_count'],
                      'first_capture_status': result['first_capture_status'],
                      'dropped_count': result['dropped_count']}))


if __name__ == '__main__':
    main()
