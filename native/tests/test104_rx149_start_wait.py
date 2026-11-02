#!/usr/bin/env python3
"""Compile actual RX149 getter/bridge under host shims; no kernel/RF actions.

Portable in repo/native/tests. Outputs go only to the explicitly supplied new
directory. An optional baseline tree reproduces the old pending/false-ready bug.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
GETTER='itlwm/hal_iwx/ItlIwxP2PRx.cpp'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_function(source,signature):
    start=source.index(signature)
    brace=source.index('{',start)
    depth=1
    end=brace+1
    while depth:
        if source[end]=='{':depth+=1
        elif source[end]=='}':depth-=1
        end+=1
    return source[start:end].strip()+'\n'


def extract_getter(tree):
    source=(tree/GETTER).read_text()
    return extract_function(source,'bool ItlIwx::tahoeP2pRx149DataLease(')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--baseline',type=Path)
    args=ap.parse_args()
    out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    commands=[]

    def run(argv,log,timeout=60):
        result=subprocess.run(argv,cwd=ROOT,text=True,stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,timeout=timeout)
        target=out/log;target.write_text(result.stdout);target.chmod(0o600)
        commands.append({'argv':argv,'returncode':result.returncode,'log':log})
        if result.returncode:
            raise RuntimeError(str(result.returncode)+' '+log+'\n'+result.stdout[-3000:])
        return result.stdout

    shims=out/'shims';shims.mkdir(mode=0o700)
    for name in ('IOKit/IOLib.h','IOKit/IOLocks.h','kern/clock.h',
                 'net/kpi_interfacefilter.h','net/if.h','sys/socket.h','sys/mbuf.h',
                 'net/kpi_interface.h','sys/kpi_socket.h','netinet/in.h','netinet6/in6_var.h'):
        path=shims/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n');path.chmod(0o600)
    getter=out/'test104_rx149_hal_getter.inc';getter.write_text(extract_getter(ROOT));getter.chmod(0o600)
    common=['xcrun','clang++','-std=c++14','-O1','-g','-Wall','-Wextra','-Werror',
            '-Wno-unused-function','-fno-omit-frame-pointer',
            '-DITL_NATIVE_AWDL_RESIDENT_25G332=1',
            '-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1',
            '-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1',
            '-DITL_NATIVE_AWDL_RX149_TEST_HOOKS=1',
            '-I'+str(shims),'-I'+str(out),'-Inative/tests','-Inative']
    frame='native/awdl_data_frame.cpp'
    fixture='native/tests/test104_rx149_start_wait_test.cpp'
    binary=out/'test104-asan'
    run(common+['-fsanitize=address,undefined',frame,fixture,'-o',str(binary)],'compile-candidate-asan.log',300)
    binary.chmod(0o700)
    cases=['flag_matrix','pending_then_start']+['flag_'+str(i) for i in range(1,16)]+[
        'terminal_before_start','active_same_pending','active_old_pending_new',
        'stale_pending_newer_active','publish_expires_under_lock','publish_fault_under_lock']+[
        'bridge_'+name for name in ('interface','incarnation','closing','detached','radio',
                                   'generation','close_latch','attached','fault','exhausted')]+[
        'ticket_interface','ticket_incarnation','ticket_close_latch','close_after_ticket',
        'address_binding','no_bridge','off_main_gate','publish_version_exhausted','pending_vs_revoke']
    results=[]
    for case in cases:
        value=json.loads(run([str(binary),case],'case-'+case+'.log'))
        assert value['passed'];results.append(value)

    # Existing 21 production RX/ifnet/ticket/recovery regressions are recompiled
    # against the candidate, including stricter receive-interface instrumentation.
    legacy=out/'existing-rx149-asan'
    run(common+['-fsanitize=address,undefined','native/awdl_native_bsd_data_25G332.cpp',
                frame,'native/tests/awdl_native_rx149_data_input_test.cpp','-o',str(legacy)],
        'compile-existing-rx149-asan.log',300)
    legacy.chmod(0o700)
    for case in range(1,24):
        run([str(legacy),str(case)],'existing-rx149-'+str(case)+'.log')

    tsan=out/'test104-tsan'
    run(common+['-fsanitize=thread',frame,fixture,'-o',str(tsan)],'compile-candidate-tsan.log',300)
    tsan.chmod(0o700)
    for case in ('pending_vs_revoke','close_after_ticket'):
        run([str(tsan),case],'tsan-'+case+'.log')
    stress=out/'existing-rx149-tsan'
    run(common+['-fsanitize=thread','native/awdl_native_bsd_data_25G332.cpp',frame,
                'native/tests/awdl_native_rx149_data_input_tsan_test.cpp','-o',str(stress)],
        'compile-existing-rx149-tsan.log',300)
    stress.chmod(0o700);run([str(stress)],'existing-rx149-tsan.log')

    baseline_results=[]
    if args.baseline:
        base=args.baseline.resolve();work=out/'baseline';work.mkdir(mode=0o700)
        inc=work/'test104_rx149_hal_getter.inc';inc.write_text(extract_getter(base));inc.chmod(0o600)
        original=work/'baseline-driver.cpp'
        original.write_text(r'''#include "test104_rx149_hal_fixture.hpp"
int main(int argc,char **argv) {
    assert(argc==2);FakeIf dev;prepare(dev);ItlIwx hal;P_PLACEHOLDER::Lease lease{};
    if(!strcmp(argv[1],"pending")) {
        hal.pending();assert(!hal.tahoeP2pRx149DataLease(&lease));
        assert(NativeAwdlBSD::rx149OwnerSerialHighWater==901);
        hal.started();
    } else {
        const auto old=validLease();NativeAwdlBSD::revokeRx149DataInput(old.ownerSerial,old.epochs);
    }
    assert(hal.tahoeP2pRx149DataLease(&lease)); // old getter says ready incorrectly.
    assert(!NativeAwdlBSD::activeRx149LeaseValid);
    assert(captureFrameResult(lease,nullptr)==NativeAwdlBSD::CaptureResult::Rejected);
    assert(delivered==0);assert(NativeAwdlBSD::close());
    puts("old bug reproduced with original getter and bridge");
}
'''.replace('P_PLACEHOLDER','NativeP2PRx149DataInput'))
        original.chmod(0o600)
        baseflags=common[:common.index('-I'+str(shims))]+[
            '-I'+str(shims),'-I'+str(work),'-I'+str(base/'native/tests'),
            '-I'+str(ROOT/'native/tests'),'-I'+str(base/'native'),
            '-DTEST104_EXISTING_TEST_SOURCE="'+str(base/'native/tests/awdl_native_rx149_data_input_test.cpp')+'"',
            '-DTEST104_BRIDGE_SOURCE="'+str(base/'native/awdl_native_bsd_data_25G332.cpp')+'"']
        reference=work/'original-asan'
        run(baseflags+['-fsanitize=address,undefined',str(base/frame),str(original),'-o',str(reference)],
            'compile-baseline-asan.log',300)
        reference.chmod(0o700)
        for case in ('pending','false_ready'):
            run([str(reference),case],'baseline-'+case+'.log')
            baseline_results.append(case)

    report={'schema':'test104-start-wait-host-validation/v1','new_cases_passed':len(results),
            'new_cases':results,'existing_asan_cases_passed':23,
            'tsan_new_races_passed':2,'existing_tsan_stress_passed':True,
            'baseline_original_bugs_reproduced':baseline_results,
            'actual_hal_getter_body_extracted':True,'getter_body_sha256':sha(getter),
            'getter_context_and_kpi_are_fakes':True,'full_hal_or_kext_built':False,
            'source_root':str(ROOT),'device_or_rf_actions':False,'commands':commands}
    path=out/'validation.json';path.write_text(json.dumps(report,indent=2)+'\n');path.chmod(0o600)
    print(json.dumps({k:v for k,v in report.items() if k not in ('commands','new_cases')},indent=2))


if __name__=='__main__':main()
