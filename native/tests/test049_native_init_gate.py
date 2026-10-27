#!/usr/bin/env python3
"""Compile/link and sanitizer checks. Never construct an IOKit object."""
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT.parent / 'IntelWirelessNative/research'
CPP = ROOT / 'native/awdl_native_init_probe_25G332.cpp'

def run(*args):
    result=subprocess.run(args,cwd=ROOT,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stdout+result.stderr)
    return result.stdout

def body(source, signature):
    start=source.index(signature)
    opening=source.index('{',start)
    level=0
    for i in range(opening,len(source)):
        if source[i]=='{': level+=1
        elif source[i]=='}':
            level-=1
            if level==0: return source[opening+1:i]
    raise ValueError('unclosed function')

def main():
    source=CPP.read_text()
    with tempfile.TemporaryDirectory(prefix='test049-native-init-') as temp:
        d=Path(temp)
        host=['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
              '-fsanitize=address,undefined','-fno-omit-frame-pointer']
        run(*host,'native/tests/awdl_unpublished_cleanup_test.cpp','-o',str(d/'cleanup'))
        run(str(d/'cleanup'))
        free_body=body(source,'void ItlAwdlNativeInitGate25G332::free()')
        fixture=r'''
#include <assert.h>
#include <stdint.h>
#include "awdl_unpublished_cleanup.hpp"
#include "awdl_native_init_probe_25G332.hpp"
static unsigned flags, deletedObjects, controllerReleases, serviceFrees, nativeFrees;
void note(uint32_t value) { flags |= value; }
class IOService {
public:
    virtual ~IOService() = default;
    virtual void free() { ++serviceFrees; delete this; }
    void release() { ++controllerReleases; }
};
class IO80211VirtualInterface : public IOService {
public:
    void free() override { ++nativeFrees; delete this; }
};
class ItlAwdlNativeInitGate25G332 : public IO80211VirtualInterface {
public:
    IOService *originalController_;
    NativeAwdlInit::Disposal disposal_;
    ItlAwdlNativeInitGate25G332(IOService *c, NativeAwdlInit::Disposal d)
        : originalController_(c), disposal_(d) {}
    ~ItlAwdlNativeInitGate25G332() override { ++deletedObjects; }
    void free() override;
};
void ItlAwdlNativeInitGate25G332::free() {
''' + free_body + r'''
}
void deferredWorker(IOService *controller, ItlAwdlNativeInitGate25G332 **held) {
    // The worker ends before framework retention releases its final reference.
    *held = new ItlAwdlNativeInitGate25G332(controller,
        NativeAwdlInit::Disposal::VirtualInterfaceBase);
}
int main() {
    IOService controller;
    auto a = new ItlAwdlNativeInitGate25G332(&controller, NativeAwdlInit::Disposal::ServiceBase);
    a->free();
    assert(serviceFrees==1 && nativeFrees==0 && deletedObjects==1 && controllerReleases==1);
    assert((flags & NativeAwdlInit::FreeReturned)!=0);
    flags=0;
    ItlAwdlNativeInitGate25G332 *later=nullptr;
    deferredWorker(&controller,&later);
    later->free();
    assert(nativeFrees==1 && deletedObjects==2 && controllerReleases==2);
    assert((flags & NativeAwdlInit::VirtualBaseFreed)!=0);
    auto raw = new ItlAwdlNativeInitGate25G332(nullptr, NativeAwdlInit::Disposal::ServiceBase);
    raw->free();
    assert(deletedObjects==3 && controllerReleases==2);
}
'''
        (d/'free.cpp').write_text(fixture)
        run(*host,'-Inative',str(d/'free.cpp'),'-o',str(d/'free'))
        run(str(d/'free'))
        worker=(ROOT/'itlwm/hal_iwx/ItlIwxP2PProbe.cpp').read_text()
        start=worker.index('    const bool nativeInitOnly = run.admitted &&')
        end=worker.index('    if (run.admitted) {',start)
        branch=worker[start:end]
        handled=body(worker,'static bool nativeInitObservationHandled(')
        assert '    run.canceled = nativeInitOnly || nativeLifecycleOnly;' in worker[end:]
        # Compile the real dispatch fragment in both configurations: a signed
        # init-only profile must never fall through to RF when code is absent.
        dispatch=r'''
#include <assert.h>
#include "awdl_native_init_probe_25G332.hpp"
class IOService {};
static int trueToken;
static void *kOSBooleanTrue=&trueToken;
static unsigned calls, sleeps, firmwareCalls;
static uint32_t flags;
static void IOSleep(unsigned) { ++sleeps; }
namespace NativeAwdlInit {
void observeOnce(IOService *, const uint8_t[6]) { ++calls; }
Snapshot snapshot() { return {flags,0,0,0}; }
}
struct Controller : IOService {
    bool profile;
    void *getProperty(const char *) { return profile ? kOSBooleanTrue : nullptr; }
};
using IOEthernetController=Controller;
bool nativeInitObservationHandled(IOEthernetController *controller) {
''' + handled + r'''
}
struct Owner { Controller c; Controller *getController() { return &c; } };
struct Run { bool admitted,callerOutsideMainWorkLoop; uint8_t address[6]{}; bool canceled=false; };
void execute(Owner *owner,Run &run) {
''' + branch + r'''
    if(run.admitted) ++firmwareCalls;
    run.canceled=nativeInitOnly;
}
int main() {
    Owner owner; owner.c.profile=true;
    Run native{true,true}; flags=NativeAwdlInit::Attempted|NativeAwdlInit::FreeReturned;execute(&owner,native);
    assert(!native.admitted && native.canceled && firmwareCalls==0);
    assert(nativeInitObservationHandled(&owner.c));
    assert(!nativeInitObservationHandled(nullptr));
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
    assert(calls==1);
    flags=0;assert(!nativeInitObservationHandled(&owner.c));
    Run delayed{true,true};flags=0;execute(&owner,delayed);
    assert(!delayed.admitted && delayed.canceled && sleeps==250 && firmwareCalls==0);
    Run wrongThread{true,false};execute(&owner,wrongThread);
    assert(!wrongThread.admitted && wrongThread.canceled && calls==2 && firmwareCalls==0);
#else
    assert(calls==0 && sleeps==0);
#endif
    owner.c.profile=false;Run ordinary{true,true};execute(&owner,ordinary);
    assert(!nativeInitObservationHandled(&owner.c));
    assert(ordinary.admitted && !ordinary.canceled && firmwareCalls==1);
    owner.c.profile=true;Run denied{false,true};execute(&owner,denied);
    assert(!denied.admitted && !denied.canceled && firmwareCalls==1);
}
'''
        (d/'dispatch.cpp').write_text(dispatch)
        for macro in ([],['-DITL_NATIVE_AWDL_INIT_OBSERVATION_25G332=1']):
            # IOSleep is intentionally unused in the compiled-out variant.
            run(*host,'-Wno-unused-function',*macro,'-Inative',str(d/'dispatch.cpp'),'-o',str(d/'dispatch'))
            run(str(d/'dispatch'))
        sdk=Path(run('xcrun','--sdk','macosx','--show-sdk-path').strip())
        common=['xcrun','clang++','-target','x86_64-apple-macosx26.0','-std=gnu++14',
                '-fapple-kext','-fno-rtti','-fno-exceptions','-nostdinc++','-DKERNEL=1',
                '-D__IO80211_TARGET=260000','-DAIRPORT_TAHOE=1',
                '-DITL_NATIVE_AWDL_INIT_OBSERVATION_25G332=1','-Iinclude',
                '-I'+str(sdk/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers')]
        objects=[]
        for name in ('awdl_native_concrete_25G332','awdl_native_init_probe_25G332','runtime_guard'):
            obj=d/(name+'.o');run(*common,'-c','native/'+name+'.cpp','-o',str(obj));objects.append(str(obj))
        linked=d/'linked.o';run('xcrun','ld','-r','-arch','x86_64','-o',str(linked),*objects)
        unresolved=run('xcrun','nm','-u',str(linked))
        assert not any(x in unresolved for x in ('ItlAwdl','NativeAwdlInit','NativeWifi'))
        assert '__ZN23IO80211VirtualInterface16freeBpfResourcesEv' in unresolved
        dump=run(*common,'-S','-o','/dev/null','-Xclang','-fdump-vtable-layouts',str(CPP))
        start=dump.index("VTable indices for 'ItlAwdlNativeInitGate25G332'")
        rows=dump[start:]
        assert 'powerStateWillChangeTo' in rows and 'powerStateDidChangeTo' in rows
        assert '::free()' in rows and '::attach(' in rows and '::start(' in rows
        report={'schema':1,'host_cleanup_cases':7,'source_extracted_free_cases':3,
                'native_only_dispatch_compiled_in_and_out':True,
                'asan_ubsan_passed':True,'target_compile':'gnu++14, x86_64, Kernel SDK',
                'relocatable_link_passed':True,'own_unresolved_symbols':0,
                'instance_bytes':0x140,'hardware_tested':False,
                'scope':'Unpublished init/cleanup observation only. No attach/start or RF execution.'}
        (ART/'test049-native-init-offline-gate-private.json').write_text(json.dumps(report,indent=2)+'\n')
        (ART/'test049-native-init-vtable-private.txt').write_text(rows)
        print(json.dumps(report))

if __name__=='__main__': main()
