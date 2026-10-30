#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location('decode_sta_auth', HERE / 'decode_sta_auth.py')
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


class SavedSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='test091-decode-')
        root = Path(cls.tmp.name)
        source = root / 'fixture.cpp'
        source.write_text(r'''
#include <cstdio>
#include "native/iwx_sta_auth_trace.h"
int main(int argc, char **argv) {
    IwxStaAuthTrace trace{};
    iwx_sta_auth_trace_init(&trace, 7);
    iwx_sta_auth_trace_begin_run(&trace);
    const auto attempt = iwx_sta_auth_trace_begin_attempt(&trace, 100, 5);
    IwxStaAuthTraceInput input{};
    input.monotonic_us = 101;
    input.driver_generation = 5;
    input.attempt_id = attempt;
    input.kind = IWX_STA_TRACE_GROUP1_LOCAL_FAILURE;
    input.source = IWX_STA_SOURCE_LOCAL_GROUP1;
    input.result = 35;
    input.freeze_first_failure = 1;
    iwx_sta_auth_trace_record(&trace, &input);
    input.freeze_first_failure = 0;
    input.kind = IWX_STA_TRACE_DRIVER_DEAUTH_CLEANUP;
    input.source = IWX_STA_SOURCE_DRIVER_CLEANUP;
    input.attempt_id = 0;
    for (unsigned i = 0; i < 40; ++i) {
        input.monotonic_us = 102 + i;
        iwx_sta_auth_trace_record(&trace, &input);
    }
    IwxStaAuthTraceSnapshot snapshot{};
    if (!iwx_sta_auth_trace_snapshot(&trace, &snapshot)) return 2;
    FILE *out = std::fopen(argv[1], "wb");
    if (!out) return 3;
    const auto written = std::fwrite(&snapshot, 1, sizeof(snapshot), out);
    std::fclose(out);
    return written == sizeof(snapshot) ? 0 : 4;
}
''')
        binary = root / 'fixture'
        subprocess.run(['xcrun', 'clang++', '-std=c++17', '-I', str(REPO),
                        str(source), '-o', str(binary)], check=True, capture_output=True)
        raw = root / 'snapshot.bin'
        subprocess.run([str(binary), str(raw)], check=True)
        cls.raw = raw.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_real_header_snapshot_retains_first_fault_after_wrap(self):
        result = decoder.decode(self.raw)
        self.assertEqual(result['live_count'], 16)
        self.assertEqual(result['first_capture_status'], 'captured')
        self.assertEqual(result['first'][-1]['event'], 'group1_local_failure')
        self.assertEqual(result['first'][-1]['attempt_id'], 1)
        self.assertEqual(result['first'][-1]['result'], 35)
        self.assertGreater(result['live'][0]['sequence'], result['first'][-1]['sequence'])

    def test_saved_plist_round_trip_and_ambiguous_owner_rejected(self):
        prop = 'NativeGroupKeyForensicSnapshot'
        raw = plistlib.dumps([{prop: self.raw}])
        self.assertEqual(decoder.extract_saved_blob(raw, prop), self.raw)
        with self.assertRaises(ValueError):
            decoder.extract_saved_blob(plistlib.dumps([{prop: self.raw}, {prop: self.raw}]), prop)

    def test_torn_revision_rejected(self):
        raw = bytearray(self.raw)
        struct.pack_into('<I', raw, 16, 1)
        with self.assertRaises(ValueError):
            decoder.decode(raw)

    def test_truncated_or_unknown_layout_rejected(self):
        with self.assertRaises(ValueError):
            decoder.decode(self.raw[:-1])
        raw = bytearray(self.raw)
        struct.pack_into('<H', raw, 4, 2)
        with self.assertRaises(ValueError):
            decoder.decode(raw)

    def test_first_loss_cannot_masquerade_as_complete(self):
        raw = bytearray(self.raw)
        struct.pack_into('<I', raw, 48, 3)
        with self.assertRaises(ValueError):
            decoder.decode(raw)

    def test_consistent_pending_and_lost_states_remain_unknown(self):
        for state, flags, label in ((1, 0, 'pending_unknown'), (3, 1, 'lost_unknown')):
            raw = bytearray(self.raw)
            struct.pack_into('<I', raw, 20, flags)
            struct.pack_into('<I', raw, 48, state)
            struct.pack_into('<I', raw, 52, 0)
            raw[decoder.HEADER.size + decoder.LIVE_CAPACITY * decoder.RECORD.size:] = bytes(decoder.FIRST_CAPACITY * decoder.RECORD.size)
            result = decoder.decode(raw)
            self.assertEqual(result['first_capture_status'], label)
            self.assertEqual(result['first'], [])


if __name__ == '__main__':
    unittest.main()
