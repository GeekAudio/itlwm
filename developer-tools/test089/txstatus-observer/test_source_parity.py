#!/usr/bin/env python3
"""Verify Test089's probe stays byte-identical to the frozen Test088 source."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TEST088 = ROOT / 'developer-tools' / 'test088' / 'afpacket-sender'
SENDER = TEST088 / 'awdl_probe_sender.c'
PROBE = HERE / 'probe_frame.c'
SPEC = TEST088 / 'fixtures' / 'probe-spec.json'
MANIFEST = ROOT / 'developer-tools' / 'test088' / 'SOURCE-MANIFEST.json'


def array_bytes(source: str, name: str) -> bytes:
    match = re.search(
        r'static const uint8_t\s+' + re.escape(name) +
        r'\s*\[[^]]+\]\s*=\s*\{(.*?)\};', source, re.S)
    if match is None:
        raise AssertionError(f'missing byte array: {name}')
    values = re.findall(r'0x([0-9a-fA-F]{2})', match.group(1))
    return bytes(int(value, 16) for value in values)


class SourceParityTests(unittest.TestCase):
    def test_probe_bytes_match_test088_source_and_manifest(self):
        sender_source = SENDER.read_text()
        probe_source = PROBE.read_text()
        sender_manifest = json.loads(MANIFEST.read_text())
        spec = json.loads(SPEC.read_text())
        sender_hash = hashlib.sha256(SENDER.read_bytes()).hexdigest()
        self.assertEqual(sender_hash,
                         sender_manifest['source_files'][
                             'developer-tools/test088/afpacket-sender/awdl_probe_sender.c'])

        for name, key in (('radiotap_base', 'radiotap_hex'),
                          ('mpdu_base', 'mpdu_hex')):
            source_bytes = array_bytes(sender_source, name)
            copied_bytes = array_bytes(probe_source, name)
            self.assertEqual(copied_bytes, source_bytes)
            self.assertEqual(copied_bytes, bytes.fromhex(spec[key]))

        packet = bytes.fromhex(spec['radiotap_hex'] + spec['mpdu_hex'])
        self.assertEqual(len(packet), spec['packet_socket_payload_length'])
        self.assertEqual(hashlib.sha256(packet).hexdigest(),
                         spec['packet_socket_payload_sha256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
