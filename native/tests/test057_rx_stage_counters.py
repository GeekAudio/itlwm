#!/usr/bin/env python3
"""Host-only ASan/UBSan coverage for Test057's bounded RX stage counters."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
header = (ROOT / 'itlwm/hal_iwx/ItlIwx.hpp').read_text()
cpp = (ROOT / 'itlwm/hal_iwx/ItlIwx.cpp').read_text()
rx = (ROOT / 'itlwm/hal_iwx/ItlIwxP2PRx.cpp').read_text()

start = header.index('struct TahoeAwdlRxStageCounters {')
end = header.index('\n};\n#endif', start) + len('\n};')
counter_struct = header[start:end]

# Keep the host test coupled to the production placement and numeric-only API.
assert cpp.index('mbuf_adj(m, 2);', cpp.index('iwx_rx_mpdu_mq')) < cpp.index(
    'TahoeAwdlRxStageCounters::classify(', cpp.index('iwx_rx_mpdu_mq'))
assert cpp.index('TahoeAwdlRxStageCounters::kEarly', cpp.index('iwx_rx_mpdu_mq')) < cpp.index(
    'iwx_rx_hwdecrypt(sc, m', cpp.index('iwx_rx_mpdu_mq'))
assert 'TahoeAwdlRxStageCounters::kDecryptRejected' in cpp
assert 'TahoeAwdlRxStageCounters::kAfterDecrypt' in cpp
assert 'TahoeAwdlRxStageCounters::kDuplicateRejected' in cpp
assert 'TahoeAwdlRxStageCounters::kAfterDuplicate' in cpp
assert cpp.index('TahoeAwdlRxStageCounters::kTap', cpp.index('iwx_rx_frame')) < cpp.index(
    'tahoeP2pTapAction(sc', cpp.index('iwx_rx_frame'))
for name in ('NativeP2PRxStageEarlyPsf', 'NativeP2PRxStageEarlyMif',
             'NativeP2PRxStageAfterDecryptMif', 'NativeP2PRxStageAtTapMif'):
    assert name in rx
assert 'tahoeP2pOnMainGate()' in cpp[cpp.index('iwx_rx_mpdu_mq'):]
assert 'lease.contextGeneration == lease.currentContextGeneration' in cpp[
    cpp.index('iwx_rx_mpdu_mq'):]

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
''' + counter_struct + r'''

static void makeFrame(uint8_t *frame, uint8_t awdlSubtype, bool ordered = false)
{
    memset(frame, 0, 64);
    frame[0] = 0xd0; // 802.11 management action
    const size_t body = ordered ? 28u : 24u;
    if (ordered)
        frame[1] = 0x80; // Order/HT-Control adds four bytes before action body.
    frame[body + 0] = 127;
    frame[body + 1] = 0x00;
    frame[body + 2] = 0x17;
    frame[body + 3] = 0xf2;
    frame[body + 4] = 8;
    frame[body + 5] = 0x10;
    frame[body + 6] = awdlSubtype;
    frame[body + 7] = 0;
}

int main()
{
    uint8_t frame[64]{};
    makeFrame(frame, 0);
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kPsf);
    makeFrame(frame, 3);
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kMif);

    // Bounds and classification rejects must never read beyond supplied data.
    for (size_t length = 0; length < 32; ++length)
        assert(TahoeAwdlRxStageCounters::classify(frame, length) ==
               TahoeAwdlRxStageCounters::kNotAwdl);
    makeFrame(frame, 3);
    frame[1] |= 0x40; // Protected bit: never inspect encrypted AWDL payload.
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kNotAwdl);
    makeFrame(frame, 1); // Unknown AWDL subtype.
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kNotAwdl);
    makeFrame(frame, 3);
    frame[24 + 7] = 1; // Unknown AWDL action flags.
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kNotAwdl);
    makeFrame(frame, 0);
    frame[24 + 3] ^= 1; // Wrong vendor OUI.
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kNotAwdl);
    makeFrame(frame, 0, true);
    assert(TahoeAwdlRxStageCounters::classify(frame, 36) ==
           TahoeAwdlRxStageCounters::kPsf);
    assert(TahoeAwdlRxStageCounters::classify(frame, 35) ==
           TahoeAwdlRxStageCounters::kNotAwdl);
    makeFrame(frame, 0);
    frame[1] |= 0x01; // To-DS/From-DS shape is rejected, not misparsed.
    assert(TahoeAwdlRxStageCounters::classify(frame, 32) ==
           TahoeAwdlRxStageCounters::kNotAwdl);

    TahoeAwdlRxStageCounters counters;
    counters.beginOwner(41);
    assert(!counters.record(0, TahoeAwdlRxStageCounters::kPsf,
                            TahoeAwdlRxStageCounters::kEarly));
    assert(!counters.record(40, TahoeAwdlRxStageCounters::kMif,
                            TahoeAwdlRxStageCounters::kEarly));
    assert(!counters.record(41, TahoeAwdlRxStageCounters::kNotAwdl,
                            TahoeAwdlRxStageCounters::kEarly));
    assert(!counters.record(41, TahoeAwdlRxStageCounters::kMif,
                            static_cast<TahoeAwdlRxStageCounters::Stage>(99)));
    assert(counters.record(41, TahoeAwdlRxStageCounters::kPsf,
                           TahoeAwdlRxStageCounters::kEarly));
    assert(counters.record(41, TahoeAwdlRxStageCounters::kMif,
                           TahoeAwdlRxStageCounters::kAfterDecrypt));
    assert(counters.record(41, TahoeAwdlRxStageCounters::kMif,
                           TahoeAwdlRxStageCounters::kTap));
    auto snapshot = counters.snapshot();
    assert(snapshot.ownerGeneration == 41 && snapshot.active == 1);
    assert(snapshot.counts[TahoeAwdlRxStageCounters::kEarly][0] == 1);
    assert(snapshot.counts[TahoeAwdlRxStageCounters::kAfterDecrypt][1] == 1);
    assert(snapshot.counts[TahoeAwdlRxStageCounters::kTap][1] == 1);
    counters.endOwner(40); // Wrong owner cannot end the active generation.
    assert(counters.snapshot().active == 1);
    counters.endOwner(41);
    assert(!counters.record(41, TahoeAwdlRxStageCounters::kMif,
                            TahoeAwdlRxStageCounters::kTap));
    counters.beginOwner(42); // A new owner clears the previous test window.
    snapshot = counters.snapshot();
    assert(snapshot.ownerGeneration == 42 && snapshot.active == 1);
    for (unsigned stage = 0; stage < TahoeAwdlRxStageCounters::kStageCount; ++stage)
        for (unsigned kind = 0; kind < TahoeAwdlRxStageCounters::kKindCount; ++kind)
            assert(snapshot.counts[stage][kind] == 0);
    assert(!counters.record(41, TahoeAwdlRxStageCounters::kPsf,
                            TahoeAwdlRxStageCounters::kEarly));
    counters.endOwner(42);
    assert(counters.snapshot().active == 0);
}
'''

with tempfile.TemporaryDirectory(prefix='test057-rx-stage-') as tmp:
    source = Path(tmp) / 'test.cpp'
    binary = Path(tmp) / 'test'
    source.write_text(fixture)
    subprocess.run([
        'xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
        str(source), '-o', str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True)

report = {
    'schema': 'test057-rx-stage-host-v1',
    'production_code_extracted': 'TahoeAwdlRxStageCounters from ItlIwx.hpp',
    'production_integration_source_checks_passed': True,
    'asan_ubsan_host_run_passed': True,
    'commands': [
        'python3 native/tests/test057_rx_stage_counters.py',
        'python3 native/tests/test_iwx_p2p_rx_tap.py'
    ],
    'integration_boundaries': {
        'early': 'after CRC/overrun, descriptor length, mbuf length, and padding checks',
        'decrypt': 'separate rejected count or after successful iwx_rx_hwdecrypt',
        'duplicate': 'separate rejected count or after successful iwx_detect_duplicate',
        'tap': 'after CCMP decapsulation and immediately before the existing P2P side tap'
    },
    'published_data': 'numeric counters, owner generation, and active bit only',
    'no_radio_or_kernel_object_constructed': True,
    'no_rf_or_wifi_toggle': True,
    'behavior_changed': False,
    'kernel_build_performed': False,
    'runtime_validation_performed': False,
    'negative_cases': [
        'null/short frame lengths 0..31', 'Protected action', 'unknown AWDL subtype',
        'nonzero reserved action byte', 'wrong vendor OUI', 'short HT-Control header',
        'To-DS frame-control bits', 'zero owner generation', 'stale owner generation',
        'non-AWDL kind', 'invalid stage enum', 'wrong-generation end',
        'record after owner end', 'new generation resets prior window'
    ],
    'positive_cases': [
        'PSF subtype 0', 'MIF subtype 3', 'HT-Control header offset',
        'early/decrypt/tap stage counters'
    ],
    'source_tree_mutations_by_test': [],
    'report_output': 'research/test057-rx-stage-host-private.json'
}
art = ROOT.parent / 'IntelWirelessNative/research/test057-rx-stage-host-private.json'
art.parent.mkdir(parents=True, exist_ok=True)
art.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print('PASS: bounded AWDL PSF/MIF classification and owner-scoped stage counters under ASan/UBSan')
print(art)
