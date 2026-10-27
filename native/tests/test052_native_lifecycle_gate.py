#!/usr/bin/env python3
"""Failure injection, exact SDK ABI/link checks; never instantiate a kernel object."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
ART=ROOT.parent/'IntelWirelessNative/research'
def run(args):
    p=subprocess.run(args,cwd=ROOT,text=True,capture_output=True)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return p.stdout

def main():
    with tempfile.TemporaryDirectory(prefix='native-lifecycle050-') as t:
        d=Path(t)
        host=['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
              '-fsanitize=address,undefined','-fno-omit-frame-pointer']
        run(host+['native/tests/awdl_lifecycle_transaction_test.cpp','-o',str(d/'host')])
        run([str(d/'host')])
        worker=(ROOT/'itlwm/hal_iwx/ItlIwxP2PProbe.cpp').read_text()
        start=worker.index('    const bool nativeLifecycleOnly = run.admitted &&')
        end=worker.index('    const bool nativeInitOnly = run.admitted &&',start)
        branch=worker[start:end]
        fixture='''
#include <assert.h>
#include "awdl_native_lifecycle_25G332.hpp"
class IOService {};
static int token;static void *kOSBooleanTrue=&token;
static unsigned calls,firmware;
namespace NativeAwdlLifecycle {void observeOnce(IOService *,const uint8_t[6]){++calls;}}
struct Controller:IOService {bool profile;void *getProperty(const char *){return profile?kOSBooleanTrue:nullptr;}};
struct Owner{Controller controller;Controller *getController(){return &controller;}};
struct Run{bool admitted,callerOutsideMainWorkLoop;uint8_t address[6]{};};
void execute(Owner *owner,Run &run){
'''+branch+'''
if(run.admitted)++firmware;
}
int main(){Owner owner;owner.controller.profile=true;Run native{true,true};execute(&owner,native);
assert(!native.admitted&&firmware==0);
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
assert(calls==1);
#else
assert(calls==0);
#endif
Run gated{true,false};execute(&owner,gated);assert(!gated.admitted&&firmware==0);
owner.controller.profile=false;Run ordinary{true,true};execute(&owner,ordinary);assert(ordinary.admitted&&firmware==1);
}
'''
        (d/'dispatch.cpp').write_text(fixture)
        for macro in ([],['-DITL_NATIVE_AWDL_LIFECYCLE_25G332=1']):
            run(host+macro+['-Inative',str(d/'dispatch.cpp'),'-o',str(d/'dispatch')]);run([str(d/'dispatch')])
        sdk=Path(run(['xcrun','--sdk','macosx','--show-sdk-path']).strip())
        cmd=['xcrun','clang++','-target','x86_64-apple-macosx26.0','-std=gnu++14',
             '-fapple-kext','-fno-rtti','-fno-exceptions','-nostdinc++','-DKERNEL=1',
             '-D__IO80211_TARGET=260000','-DAIRPORT_TAHOE=1','-Wno-deprecated-declarations',
             '-Wframe-larger-than=4096','-Werror=frame-larger-than','-Iinclude','-I'+str(sdk/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
        macro=['-DITL_NATIVE_AWDL_LIFECYCLE_25G332=1','-DITL_NATIVE_AWDL_RESIDENT_25G332=1']
        objects=[]
        for name in ('awdl_native_concrete_25G332','awdl_native_lifecycle_25G332','awdl_native_bsd_data_25G332','awdl_data_frame','runtime_guard'):
            p=d/(name+'.o');run(cmd+macro+['-c','native/'+name+'.cpp','-o',str(p)]);objects.append(str(p))
        linked=d/'native.o';run(['xcrun','ld','-r','-arch','x86_64','-o',str(linked),*objects])
        undefined=run(['xcrun','nm','-u',str(linked)])
        assert not any(x in undefined for x in ('ItlAwdl','NativeAwdl','NativeWifi'))
        available=set()
        for p in [ART/'test037-upgrade-private/IO80211Family-25G332.linked-analysis.macho',
                  ART/'test037-upgrade-private/IOSkywalkFamily-25G332.linked-analysis.macho',
                  Path('/System/Library/Kernels/kernel')]:
            available.update(x.split()[-1] for x in run(['xcrun','nm','-gU',str(p)]).splitlines() if len(x.split())>=3)
        assert all(x in available for x in undefined.splitlines()),[x for x in undefined.splitlines() if x not in available]
        normal=d/'normal.o';run(cmd+['-c','native/awdl_native_lifecycle_25G332.cpp','-o',str(normal)])
        assert 'ItlAwdl' not in run(['xcrun','nm',str(normal)])
        dump=run(cmd+macro+['-S','-o','/dev/null','-Xclang','-fdump-vtable-layouts','native/awdl_native_lifecycle_25G332.cpp'])
        table=dump[dump.index("VTable indices for 'ItlAwdlLifecycle25G332'"):]
        for name in ('::stop(','::prepareBSDInterface(','::setPowerState(','::setInterfaceEnable(','::free()'):
            assert name in table
        report={'transaction_cases_including_held_resident':10,'asan_ubsan_passed':True,'kernel_sdk_compile_passed':True,
                'relocatable_link_passed':True,'normal_build_excludes_lifecycle':True,
                'compiled_in_out_native_dispatch_skips_rf':True,'native_undefined_symbols_available':True,
                'runtime_tested':False,'scope':'Native attach/start/register/terminate transaction binding; resident/data candidate binding; no kernel/RF or AirDrop proof.'}
        (ART/'test052-native-lifecycle-offline-private.json').write_text(json.dumps(report,indent=2)+'\n')
        (ART/'test052-native-lifecycle-undefined-private.txt').write_text(undefined)
        (ART/'test052-native-lifecycle-vtable-private.txt').write_text(table)
        print(json.dumps(report))
if __name__=='__main__':main()
