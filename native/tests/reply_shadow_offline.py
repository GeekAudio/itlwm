#!/usr/bin/env python3
"""Compile actual Shadow bridge with fake clock/KPI; no real sockets/devices."""
import argparse,json,subprocess,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--with-regressions',action='store_true');args=ap.parse_args()
    out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    commands=[]
    def run(argv,log,timeout=60):
        p=subprocess.run(argv,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
        (out/log).write_text(p.stdout);commands.append({'argv':argv,'exit':p.returncode,'log':log})
        if p.returncode:raise RuntimeError(log+'\n'+p.stdout[-4000:])
        return p.stdout
    shims=out/'shims'
    for f in ('IOKit/IOLib.h','IOKit/IOLocks.h','kern/clock.h','net/kpi_interfacefilter.h','net/if.h','sys/socket.h','sys/mbuf.h','net/kpi_interface.h','sys/kpi_socket.h','netinet/in.h','netinet6/in6_var.h'):
        p=shims/f;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
    source=(ROOT/'itlwm/hal_iwx/ItlIwxP2PRx.cpp').read_text();start=source.index('bool ItlIwx::tahoeP2pRx149DataLease(');end=source.index('\nvoid ItlIwx::tahoeP2pTapAction(',start)
    getter=out/'test104_rx149_hal_getter.inc';getter.write_text(source[start:end])
    common=['xcrun','clang++','-std=c++14','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-fno-omit-frame-pointer',
      '-DITL_NATIVE_AWDL_RESIDENT_25G332=1','-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1','-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1','-DITL_NATIVE_AWDL_RX149_TEST_HOOKS=1',
      '-I'+str(shims),'-I'+str(out),'-Inative/tests','-Inative']
    src=['native/awdl_data_frame.cpp','native/tests/reply_shadow_test.cpp']
    flag='-DITL_NATIVE_AWDL_REPLY_SHADOW_25G332=1'
    binary=out/'shadow-asan';run(common+[flag,'-fsanitize=address,undefined']+src+['-o',str(binary)],'compile-asan.log',300)
    cases=['default','runtime_off','start','sync','async','copy','duplicate','concurrent','input_fail','input_end','input_fault','no_request','close_pin','finalize_end','finalize_rewrite','deferred_checksum']
    cases+=['config_'+s for s in ('owner','epoch','incarnation','mac','ip','nonce','deadline','expired')]
    cases+=['request_'+s for s in ('payload','ports','address','hop','checksum')]
    cases+=['reply_'+s for s in ('payload','ports','address','mac','hop','checksum','short','long','header','ifnet','family')]
    cases+=['end','old_owner','fault','disable','expiry','incarnation','radio','epoch','new_owner','clock_rollback']
    results=[json.loads(run([str(binary),c],'case-'+c+'.log')) for c in cases]
    disabled=out/'disabled-asan';run(common+['-fsanitize=address,undefined']+src+['-o',str(disabled)],'compile-disabled.log',300)
    run([str(disabled),'compiled_off'],'compiled-off.log')
    tsan=out/'shadow-tsan';run(common+[flag,'-fsanitize=thread']+src+['-o',str(tsan)],'compile-tsan.log',300)
    for c in ('concurrent','close_pin'):run([str(tsan),c],'tsan-'+c+'.log')
    legacy_count=0
    if args.with_regressions:
        legacy_cases=['flag_matrix','pending_then_start']+['flag_'+str(i) for i in range(1,16)]+[
            'terminal_before_start','active_same_pending','active_old_pending_new',
            'stale_pending_newer_active','publish_expires_under_lock','publish_fault_under_lock']+[
            'bridge_'+n for n in ('interface','incarnation','closing','detached','radio','generation','close_latch','attached','fault','exhausted')]+[
            'ticket_interface','ticket_incarnation','ticket_close_latch','close_after_ticket','address_binding','no_bridge','off_main_gate','publish_version_exhausted','pending_vs_revoke']
        old=out/'test104-feature-on-asan'
        old_src=['native/awdl_data_frame.cpp','native/tests/test104_rx149_start_wait_test.cpp']
        run(common+[flag,'-fsanitize=address,undefined']+old_src+['-o',str(old)],'compile-test104-feature-on.log',300)
        for c in legacy_cases:run([str(old),c],'test104-feature-on-'+c+'.log')
        direct=out/'rx149-feature-on-asan'
        direct_src=['native/awdl_native_bsd_data_25G332.cpp','native/awdl_data_frame.cpp','native/tests/awdl_native_rx149_data_input_test.cpp']
        run(common+[flag,'-fsanitize=address,undefined']+direct_src+['-o',str(direct)],'compile-rx149-feature-on.log',300)
        for c in range(1,22):run([str(direct),str(c)],'rx149-feature-on-'+str(c)+'.log')
        old_tsan=out/'test104-feature-on-tsan'
        run(common+[flag,'-fsanitize=thread']+old_src+['-o',str(old_tsan)],'compile-test104-feature-on-tsan.log',300)
        for c in ('pending_vs_revoke','close_after_ticket'):run([str(old_tsan),c],'test104-feature-on-tsan-'+c+'.log')
        stress=out/'rx149-feature-on-tsan'
        run(common+[flag,'-fsanitize=thread']+direct_src[:-1]+['native/tests/awdl_native_rx149_data_input_tsan_test.cpp','-o',str(stress)],'compile-rx149-feature-on-tsan.log',300)
        run([str(stress)],'rx149-feature-on-tsan.log')
        legacy_count=len(legacy_cases)+21
    report={'schema':'directed-reply-shadow-host-validation/v1','feature_on_legacy_asan_cases_passed':legacy_count,'feature_on_legacy_tsan_races_passed':2 if args.with_regressions else 0,'feature_on_legacy_tsan_stress_passed':args.with_regressions,'cases_passed':len(results),'cases':results,'compiled_off_passed':True,'tsan_cases_passed':2,'actual_bridge_compiled':True,'actual_getter_sha256':hashlib.sha256(getter.read_bytes()).hexdigest(),'clock_kpi_and_native_stack_are_fakes':True,'real_socket_or_rf_actions':False,'full_kext_built':False,'commands':commands}
    (out/'validation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('cases','commands')},indent=2))
if __name__=='__main__':main()
