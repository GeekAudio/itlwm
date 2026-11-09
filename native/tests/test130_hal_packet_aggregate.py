#!/usr/bin/env python3
"""Exercise Test130 HAL run-level doorbell/completion aggregation offline."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'itlwm/hal_iwx/ItlIwxP2PAction.cpp').read_text()


def cut(first, last):
    start = source.index(first)
    return source[start:source.index(last, start + len(first))]


aggregate = cut('static bool directedDataAllDoorbellsCompleted(',
                'static bool directedDataHasDoorbellHistory(')
history = cut('static bool directedDataHasDoorbellHistory(',
              'static void directedDataRecordUnsubmittedSlot(')
assert 'return anyDoorbell;' in aggregate
assert 'if (!packet.completionObserved || !packet.resourcesAbsent)' in aggregate
assert 'value.doorbellIssued = directedDataHasDoorbellHistory(context);' in source
assert ('value.completionObserved = value.doorbellIssued &&\n'
        '        directedDataAllDoorbellsCompleted(context);') in source
record_cancel = cut('static void directedDataRecordUnsubmittedSlot(',
                    'struct DirectedDataUnsubmittedNextSlotEvidence')
assert ('context->completionObserved = directedDataHasDoorbellHistory(context) &&\n'
        '        directedDataAllDoorbellsCompleted(context);') in record_cancel

reserve = cut('static IOReturn directedDataReserveSequencesAction(',
              'bool iwx_tahoe_p2p_directed_data_reserve_sequences(')
assert 'context->completionObserved = false;' not in reserve
submit = cut('static int directedDataTxSubmitOnMainGate(',
             'int iwx_tahoe_p2p_directed_data_tx_submit(')
assert 'context->completionObserved = false;' in submit

fixture = r'''
#include <cassert>
#include <cstdint>
struct PacketRecord {
    bool doorbellIssued;
    bool completionObserved;
    bool resourcesAbsent;
};
struct TahoeP2PDirectedDataContext {
    uint8_t packetCount;
    PacketRecord packets[2];
};
''' + aggregate + history + r'''
int main() {
    TahoeP2PDirectedDataContext c{};
    c.packetCount = 2;
    // Empty set is never mistaken for a completed DMA run.
    assert(!directedDataHasDoorbellHistory(&c));
    assert(!directedDataAllDoorbellsCompleted(&c));
    // Slot zero completed; slot one has not reached its doorbell. The actual
    // submitted packet set is complete, including during slot-one prep/cancel.
    c.packets[0] = {true, true, true};
    assert(directedDataHasDoorbellHistory(&c));
    assert(directedDataAllDoorbellsCompleted(&c));
    // A second actual doorbell remains outstanding regardless of slot-zero's
    // historical completion.
    c.packets[1] = {true, false, false};
    assert(!directedDataAllDoorbellsCompleted(&c));
    // Once the second packet's own TX response and resource release arrive,
    // the run-level aggregate becomes complete again.
    c.packets[1] = {true, true, true};
    assert(directedDataAllDoorbellsCompleted(&c));
}
'''

with tempfile.TemporaryDirectory(prefix='test130-hal-packet-aggregate-') as tmp:
    cpp = Path(tmp) / 'aggregate.cpp'
    exe = Path(tmp) / 'aggregate'
    cpp.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', str(cpp), '-o', str(exe)],
                   check=True)
    subprocess.run([str(exe)], check=True)
print('Test130: run-level any-doorbell and all-actual-completion proof passed')
