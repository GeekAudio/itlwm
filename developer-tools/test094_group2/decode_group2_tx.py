#!/usr/bin/env python3
"""Decode the bounded numeric Group2 TX trace property offline."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct

MAGIC = 0x47545849
SCHEMA = 1
CAPACITY = 32
HEADER = struct.Struct('<I4H4xQQIIQQQI4x')
EVENT = struct.Struct('<QQQQ12IiIHH4x')
SIZE = HEADER.size + CAPACITY * EVENT.size

STAGES = {
    1: 'origin', 2: 'mbuf_alloc_failed', 3: 'tag_unavailable',
    4: 'tag_attach_failed', 5: 'ifq_enqueue_operation',
    6: 'dequeue_without_tag', 7: 'dequeued', 8: 'pullup_failed',
    9: 'encap_failed', 10: 'iwx_tx_rejected', 11: 'slot_committed',
    12: 'local_doorbell', 13: 'exclusive_tx_rsp_match',
    14: 'tx_rsp_unknown', 15: 'slot_retired',
    16: 'reset_invalidated_unknown', 17: 'trace_lost',
    18: 'prepend_failed', 19: 'flush_reclaim_unknown',
}
SOURCES = {0: 'unknown', 1: 'rsn', 2: 'wpa'}
KNOWN_FLAGS = 0x3FFFF
HAS_COOKIE = 1 << 0
HAS_ATTEMPT = 1 << 1
HAS_SOURCE = 1 << 2
HAS_MATCH_RESULT = 1 << 12
HAS_SLOT = 1 << 8
QUEUE_DROP_COUNT_PRESENT = 1 << 14
RESET_AMBIGUOUS = 1 << 13
HAS_COMPLETION_BOUNDARY = 1 << 16
HAS_FIRMWARE_STATUS = 1 << 17
TX_MATCHES = {
    0: 'unknown', 1: 'unique', 2: 'none', 3: 'multiple',
    4: 'bad_range', 5: 'reset_ambiguous', 6: 'generation_mismatch',
}


def decode_event(raw: bytes) -> dict:
    fields = EVENT.unpack(raw)
    names = (
        'sequence', 'monotonic_us', 'cookie', 'slot_generation',
        'attempt_id', 'source', 'origin_generation', 'origin_association',
        'context_generation', 'output_epoch', 'queue_id', 'index',
        'ring_count', 'frame_control', 'sequence_control', 'tid',
        'result', 'flags', 'stage', 'status',
    )
    row = dict(zip(names, fields))
    if row['sequence'] == 0:
        raise ValueError('zero event sequence')
    if row['stage'] not in STAGES or row['source'] not in SOURCES:
        raise ValueError('unknown numeric stage or source')
    if row['flags'] & ~KNOWN_FLAGS:
        raise ValueError('unknown event flags')
    if row['flags'] & HAS_COOKIE:
        if row['cookie'] == 0 or row['attempt_id'] == 0:
            raise ValueError('identified event lacks cookie or attempt')
        if not row['flags'] & HAS_ATTEMPT or not row['flags'] & HAS_SOURCE:
            raise ValueError('identity flags are incomplete')
    elif row['cookie'] != 0:
        raise ValueError('cookie present without identity flag')
    row['stage_label'] = STAGES[row['stage']]
    row['source_label'] = SOURCES[row['source']]
    if row['flags'] & HAS_COMPLETION_BOUNDARY:
        row['exclusive_reclaim_boundary'] = row['index']
    row['firmware_tx_status_raw'] = (
        row['result'] if row['flags'] & HAS_FIRMWARE_STATUS else None
    )
    if row['stage'] in (13, 14) and not row['flags'] & HAS_COMPLETION_BOUNDARY:
        raise ValueError('TX_RSP event lacks an exclusive reclaim boundary')
    if row['stage'] == 5:
        row['queue_kind'] = (
            'software_if_snd' if row['queue_id'] == 0xFFFFFFFF else 'unknown'
        )
        row['queue_id_status'] = 'unknown'
        row['hardware_qid'] = None
        row['enqueue_drop_count'] = (
            row['result'] if row['flags'] & QUEUE_DROP_COUNT_PRESENT else None
        )
        row['target_disposition'] = 'unknown'
        row['observation_scope'] = (
            'queue-call drop count; it does not identify which packet was freed '
            'or prove this Group2 packet remained queued'
        )
    elif row['stage'] == 12:
        row['observation_scope'] = (
            'local TX ring doorbell write; not firmware completion or peer receipt'
        )
    elif row['stage'] == 13:
        row['completion_match'] = (
            TX_MATCHES.get(row['status'], 'unknown')
            if row['flags'] & HAS_MATCH_RESULT else 'unknown'
        )
        row['observation_scope'] = (
            'unique local candidate inside the exclusive reclaim interval; '
            'not peer receipt'
        )
    elif row['stage'] in (14, 16):
        row['completion_match'] = (
            TX_MATCHES.get(row['status'], 'unknown')
            if row['flags'] & HAS_MATCH_RESULT else 'unknown'
        )
        row['observation_scope'] = 'reset or completion ambiguity remains unknown'
    elif row['stage'] == 15:
        row['completion_match'] = (
            TX_MATCHES.get(row['status'], 'unknown')
            if row['flags'] & HAS_MATCH_RESULT else 'unknown'
        )
        row['observation_scope'] = (
            'local sidecar retired within a verified reclaim interval; '
            'this does not imply peer receipt'
        )
    elif row['stage'] == 19:
        row['completion_match'] = 'unknown'
        row['retirement_reason'] = 'firmware_flush_reclaim'
        row['observation_scope'] = (
            'sidecar cleared by a verified exclusive flush reclaim interval; '
            'flush is not a TX_RSP, ACK, or peer receipt'
        )
    return row


def decode(raw: bytes) -> dict:
    if len(raw) != SIZE:
        raise ValueError(f'snapshot length must be {SIZE}, got {len(raw)}')
    values = HEADER.unpack_from(raw)
    names = (
        'magic', 'schema', 'header_bytes', 'event_bytes', 'capacity',
        'revision_begin', 'revision_end', 'dropped_count', 'event_count',
        'next_cookie', 'next_event_sequence', 'next_slot_generation', 'flags',
    )
    result = dict(zip(names, values))
    if (result['magic'] != MAGIC or result['schema'] != SCHEMA or
            result['header_bytes'] != HEADER.size or
            result['event_bytes'] != EVENT.size or
            result['capacity'] != CAPACITY):
        raise ValueError('unsupported Group2 TX snapshot schema')
    if (result['revision_begin'] != result['revision_end'] or
            result['revision_begin'] & 1 or result['event_count'] > CAPACITY or
            result['flags'] & ~3):
        raise ValueError('inconsistent Group2 TX snapshot header')
    events = []
    for i in range(result['event_count']):
        offset = HEADER.size + i * EVENT.size
        events.append(decode_event(raw[offset:offset + EVENT.size]))
    if any(a['sequence'] >= b['sequence'] for a, b in zip(events, events[1:])):
        raise ValueError('event sequence is not strictly increasing')
    unused = raw[HEADER.size + result['event_count'] * EVENT.size:]
    if any(unused):
        raise ValueError('unused event slots are nonzero')
    committed = {}
    for event in events:
        if event['stage'] not in (11, 12) or not event['flags'] & HAS_SLOT:
            continue
        identity = (event['cookie'], event['slot_generation'], event['queue_id'])
        committed.setdefault(identity, set()).add(event['index'])
    for event in events:
        if event['stage'] != 13 or not event['flags'] & HAS_COOKIE:
            continue
        identity = (event['cookie'], event['slot_generation'], event['queue_id'])
        indices = committed.get(identity, set())
        if len(indices) == 1:
            event['matched_slot_index'] = next(iter(indices))
        elif len(indices) > 1:
            event['matched_slot_index'] = None
            event['slot_index_ambiguous'] = True
    result['events'] = events
    result['records_dropped'] = result['dropped_count'] != 0
    result['snapshot_sha256'] = hashlib.sha256(raw).hexdigest()
    result['evidence_limits'] = [
        'Numeric identifiers and metadata only; no keys, packet bodies, addresses, or payloads.',
        'An enqueue drop count belongs to the queue operation, not a specific packet.',
        'A local doorbell is not firmware acceptance, RF transmission, or peer receipt.',
        'A unique TX_RSP candidate is host-side reclaim correlation only.',
        'Reset, missing tags, trace loss, or ambiguous matches stay unknown.',
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
        raise ValueError('plist must contain exactly one binary Group2 TX property')
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--property', default='NativeGroup2TxTrace')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = decode(extract_saved_blob(args.input.read_bytes(), args.property))
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'decoded': True, 'event_count': result['event_count'],
                      'dropped_count': result['dropped_count']}))


if __name__ == '__main__':
    main()
