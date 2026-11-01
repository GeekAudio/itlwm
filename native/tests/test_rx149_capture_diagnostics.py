#!/usr/bin/env python3
"""Offline production capture differential, publication, and concurrency checks."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def run(argv, log):
    result = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    log.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} exited {result.returncode}; {log}\n{result.stdout[-3000:]}')
    return result.stdout

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--baseline-source', type=Path)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shims = out / 'shims'
    for name in ('IOKit/IOLib.h', 'IOKit/IOLocks.h', 'kern/clock.h',
                 'net/kpi_interfacefilter.h', 'net/if.h', 'sys/socket.h',
                 'sys/mbuf.h', 'net/kpi_interface.h', 'sys/kpi_socket.h',
                 'netinet/in.h', 'netinet6/in6_var.h'):
        path = shims / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
    common = ['xcrun', 'clang++', '-std=c++14', '-O1', '-g', '-Wall',
              '-Wextra', '-Werror', '-Wno-unused-function', '-fno-omit-frame-pointer',
              '-DITL_NATIVE_AWDL_RESIDENT_25G332=1',
              '-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1',
              '-DITL_NATIVE_AWDL_RX149_TEST_HOOKS=1',
              '-I' + str(shims), '-Inative/tests', '-Inative']
    sources = ['native/awdl_data_frame.cpp', 'native/tests/rx149_capture_diagnostics_test.cpp']
    candidate = out / 'capture-asan'
    run(common + ['-fsanitize=address,undefined'] + sources + ['-o', str(candidate)], out / 'compile-asan.log')
    baseline = None
    if args.baseline_source:
        baseline = out / 'baseline-asan'
        text = args.baseline_source.read_text()
        # Only adapt header resolution to avoid two physical pragma-once
        # copies; the frozen original function/body is unchanged.
        replacement = '#include "' + str(ROOT / 'native/awdl_native_bsd_data_25G332.hpp') + '"'
        text = text.replace('#include "awdl_native_bsd_data_25G332.hpp"', replacement, 1)
        source = out / 'baseline-bridge.inc'
        source.write_text(text)
        define = '-DRX149_CAPTURE_BASELINE_SOURCE="' + str(source) + '"'
        run(common + [define, '-fsanitize=address,undefined'] + sources + ['-o', str(baseline)], out / 'compile-baseline.log')
    results = []
    for case in range(29):
        actual = run([str(candidate), str(case), str(out / f'wire-{case}.bin')], out / f'case-{case}.log')
        if baseline:
            before = run([str(baseline), str(case)], out / f'baseline-{case}.log')
            assert before == actual, ('baseline mismatch', case)
        results.append({'case': case, 'passed': True, 'baseline_equal': bool(baseline)})
    run([str(candidate), 'ledger'], out / 'ledger-asan.log')
    tsan = out / 'capture-tsan'
    run(common + ['-fsanitize=thread'] + sources + ['-o', str(tsan)], out / 'compile-tsan.log')
    run([str(tsan), 'ledger'], out / 'ledger-tsan.log')

    production = (ROOT / 'itlwm/hal_iwx/ItlIwxP2PRx.cpp').read_text()
    begin = production.index('    NativeAwdlBSD::Rx149CaptureDiagnostics::Wire captureAttempts{};')
    end = production.index('\n#endif', begin)
    block = production[begin:end]
    assert 'copyProperty(' in block and 'getProperty(' not in block
    assert block.index('retainedCaptureAttempts->release()') < block.index('controller->setProperty(')
    probe = r'''
#include "rx149_capture_diagnostics.hpp"
#include <assert.h>
#include <string.h>
#include <vector>
using Wire=NativeAwdlBSD::Rx149CaptureDiagnostics::Wire;
Wire nextWire;
namespace NativeAwdlBSD { void captureRx149Diagnostics(Wire *out){*out=nextWire;} }
unsigned destroyed=0;
struct OSObject { unsigned refs=1; virtual ~OSObject(){++destroyed;}
 void retain(){++refs;} void release(){assert(refs);if(!--refs)delete this;} };
struct OSData:OSObject { std::vector<unsigned char> bytes;
 explicit OSData(const Wire &wire):bytes(sizeof(Wire)){memcpy(bytes.data(),&wire,sizeof(wire));}
 size_t getLength()const{return bytes.size();}
 const void *getBytesNoCopy()const{assert(refs);return bytes.data();} };
#define OSDynamicCast(type,value) dynamic_cast<type *>(value)
struct Controller { OSData *property=nullptr; bool race=false,fail=false; unsigned writes=0;
 ~Controller(){if(property)property->release();}
 OSObject *copyProperty(const char *){auto old=property;if(old)old->retain();
   if(race){race=false;property=new OSData(nextWire);if(old)old->release();}return old;}
 bool setProperty(const char *,const void *bytes,size_t length){++writes;assert(length==sizeof(Wire));
   if(fail)return false;auto replacement=new OSData(*static_cast<const Wire *>(bytes));
   if(property)property->release();property=replacement;return true;} };
void publish(Controller *controller){
BLOCK
}
int main(){
 Controller controller; nextWire.header[0]=42;
 publish(&controller);assert(controller.writes==1&&controller.property->refs==1);
 publish(&controller);assert(controller.writes==1&&controller.property->refs==1);
 nextWire.header[0]=43;controller.race=true;publish(&controller);
 assert(controller.writes==2&&controller.property->refs==1&&destroyed==2);
 nextWire.header[0]=44;controller.fail=true;publish(&controller);
 assert(controller.property->refs==1&&controller.writes==3);
 assert(static_cast<const uint64_t *>(controller.property->getBytesNoCopy())[0]==43);
 controller.fail=false;publish(&controller);assert(controller.writes==4&&controller.property->refs==1);
 assert(static_cast<const uint64_t *>(controller.property->getBytesNoCopy())[0]==44);
}
'''.replace('BLOCK', block)
    cpp = out / 'publisher-fixture.cpp'
    cpp.write_text(probe)
    binary = out / 'publisher-fixture'
    run(common + ['-fsanitize=address,undefined', str(cpp), '-o', str(binary)], out / 'publisher-compile.log')
    run([str(binary)], out / 'publisher-result.log')
    pinned = ['native/rx149_capture_diagnostics.hpp', 'native/awdl_native_bsd_data_25G332.cpp',
              'native/awdl_native_bsd_data_25G332.hpp', 'itlwm/hal_iwx/ItlIwxP2PRx.cpp',
              'native/tests/rx149_capture_diagnostics_test.cpp', 'native/tests/test_rx149_capture_diagnostics.py']
    receipt = {'passed': True, 'cases': results, 'ledger_ASan_UBSan': True,
               'ledger_TSan': True, 'publisher_retained_lifetime_replacement_failure_retry': True,
               'source_sha256': {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in pinned},
               'device_IO': False, 'network_IO': False, 'kernel_execution': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('29 production scenarios passed' + (' with frozen baseline parity' if baseline else '') +
          '; ASan/UBSan + TSan immutable ledger; retained OSData publisher passed.')

if __name__ == '__main__':
    main()
