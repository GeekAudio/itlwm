#!/usr/bin/env python3
"""Run the actual HAL arm function against bounded host shims; no hardware."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'itlwm/hal_iwx/ItlIwxP2PProbe.cpp').read_text()

def function(marker):
    start = SOURCE.index(marker)
    opening = SOURCE.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
        end += 1
    return SOURCE[start:end]

PRODUCTION = '\n'.join(function(marker) for marker in (
    'static uint32_t manualProbeArmMode(',
    'static bool directedPrepareProfileEnabled(',
    'static bool validDirectedPeerMac(',
    'static bool validDirectedPrepareRunToken(',
    'static void retireDirectedPrepareInput(',
    'static bool rx149ArmModeSelected(',
    'static bool rx149ObservationOnlyRequested(',
    'IOReturn ItlIwx::nativeP2pArmDirectedPrepare(',
))
SHIM = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <cstdio>
using IOReturn = int;
enum { kIOReturnSuccess=0, kIOReturnUnsupported=1, kIOReturnBadArgument=2,
       kIOReturnBusy=3, IWX_P2P_RESOURCE_ABSENT=0 };
static int trueObject;
static void * const kOSBooleanTrue=&trueObject;
static constexpr uint32_t kDirectedPrepareArmMode=3u;
struct IOEthernetController {
    std::map<std::string, bool> properties;
    void *getProperty(const char *name) {
        return properties[name] ? kOSBooleanTrue : nullptr;
    }
};
namespace NativeP2PRx149Observation {
inline bool isRx149ArmMode(uint32_t mode) { return mode==2; }
}
namespace NativeP2PProbe {
struct Snapshot { uint32_t attempted=0, resourceMayExist=0; };
}
struct Probe {
    NativeP2PProbe::Snapshot state;
    NativeP2PProbe::Snapshot snapshot() const { return state; }
};
struct Node { uint8_t ni_macaddr[6]={2,0,0,0,0,2}; };
struct IC { uint8_t ic_myaddr[6]={2,0,0,0,0,1}; Node *ic_bss=nullptr; };
struct P2P {
    unsigned mac_state=0, binding_state=0, phy_leased=0;
    bool initialized=true;
    uint8_t mac_address[6]={2,0,0,0,0,3};
};
struct Softc { IC sc_ic; P2P sc_p2p; };
struct ItlIwx {
    IOEthernetController controller;
    Node bss;
    Softc com;
    Probe nativeP2pProbe_;
    uint32_t nativeP2pManualArmRequested_=0, nativeP2pProbeQueued_=0,
        nativeP2pNswqPaused_=0, nativeP2pDirectedPrepareArmed_=0;
    void *nativeP2pProbeOwner_=nullptr;
    uint8_t nativeP2pDirectedPreparePeer_[6]{};
    char nativeP2pDirectedPrepareRunToken_[33]{};
    bool mainGate=true, busy=false, retained=false;
    ItlIwx() {
        com.sc_ic.ic_bss=&bss;
        controller.properties["NativeP2PDirectedPrepareEnabled"]=true;
        controller.properties["NativeP2PManualTrigger"]=true;
        controller.properties["NativeP2PRx149ObservationOnly"]=true;
    }
    IOEthernetController *getController() { return &controller; }
    bool tahoeP2pOnMainGate() const { return mainGate; }
    bool nativeP2pBusy() const { return busy; }
    bool nativeP2pResourcesRetained() const { return retained; }
    IOReturn nativeP2pArmDirectedPrepare(const uint8_t[6], const char[33]);
};
'''
BODY = r'''
int main() {
    const uint8_t peer[6]={2,0,0,0,0,4};
    const char token[33]="0123456789abcdef0123456789abcdef";
#ifndef ITL_NATIVE_AWDL_DIRECTED_PREPARE_25G332
    ItlIwx off;
    assert(off.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnUnsupported);
    assert(off.nativeP2pManualArmRequested_==0 && off.nativeP2pDirectedPrepareArmed_==0);
#else
    // RX149 availability is not an active RX149 request. The combined
    // artifact must be able to admit mode3 while its RX profile stays true.
    {
        ItlIwx a;
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnSuccess);
        assert(a.nativeP2pManualArmRequested_==3 && a.nativeP2pDirectedPrepareArmed_==1);
        assert(!memcmp(a.nativeP2pDirectedPreparePeer_,peer,6));
        assert(!memcmp(a.nativeP2pDirectedPrepareRunToken_,token,33));
        assert(a.controller.getProperty("NativeP2PRx149ObservationOnly")==kOSBooleanTrue);
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnBusy);
        a.nativeP2pProbeQueued_=1;
        a.nativeP2pProbe_.state.attempted=1;
        retireDirectedPrepareInput(&a);
        assert(a.nativeP2pManualArmRequested_==0 && a.nativeP2pDirectedPrepareArmed_==0);
        assert(a.nativeP2pProbeQueued_==1 && a.nativeP2pProbe_.state.attempted==1);
        for(auto value:a.nativeP2pDirectedPreparePeer_)assert(value==0);
        for(auto value:a.nativeP2pDirectedPrepareRunToken_)assert(value==0);
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnBusy);
    }
    for (unsigned gate=0; gate<11; ++gate) {
        ItlIwx a;
        switch(gate) {
            case 0:a.nativeP2pManualArmRequested_=2;break;
            case 1:a.nativeP2pProbeQueued_=1;break;
            case 2:a.nativeP2pNswqPaused_=1;break;
            case 3:a.nativeP2pProbeOwner_=&a;break;
            case 4:a.retained=true;break;
            case 5:a.busy=true;break;
            case 6:a.com.sc_p2p.mac_state=1;break;
            case 7:a.com.sc_p2p.binding_state=1;break;
            case 8:a.com.sc_p2p.phy_leased=1;break;
            case 9:a.nativeP2pProbe_.state.attempted=1;break;
            case 10:a.nativeP2pProbe_.state.resourceMayExist=1;break;
        }
        const auto oldMode=a.nativeP2pManualArmRequested_;
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnBusy);
        assert(a.nativeP2pManualArmRequested_==oldMode && a.nativeP2pDirectedPrepareArmed_==0);
    }
    {
        ItlIwx a;a.mainGate=false;
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnUnsupported);
        assert(a.nativeP2pManualArmRequested_==0);
    }
    {
        ItlIwx a;a.controller.properties["NativeP2PDirectedPrepareEnabled"]=false;
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnUnsupported);
        assert(a.nativeP2pManualArmRequested_==0);
    }
    {
        ItlIwx a;a.controller.properties["NativeP2PManualTrigger"]=false;
        assert(a.nativeP2pArmDirectedPrepare(peer,token)==kIOReturnUnsupported);
        assert(a.nativeP2pManualArmRequested_==0 && a.nativeP2pDirectedPrepareArmed_==0);
    }
    const uint8_t bad[5][6]={{0,0,0,0,0,0},{1,0,0,0,0,4},
        {2,0,0,0,0,1},{2,0,0,0,0,2},{2,0,0,0,0,3}};
    for (const auto &address:bad) {
        ItlIwx a;
        assert(a.nativeP2pArmDirectedPrepare(address,token)==kIOReturnBadArgument);
        assert(a.nativeP2pManualArmRequested_==0 && a.nativeP2pDirectedPrepareArmed_==0);
    }
    for (unsigned invalid=0; invalid<3; ++invalid) {
        ItlIwx a;char badToken[33];memcpy(badToken,token,33);
        if(invalid==0)memset(badToken,'0',32);
        if(invalid==1)badToken[3]='G';
        if(invalid==2)badToken[32]='1';
        assert(a.nativeP2pArmDirectedPrepare(peer,badToken)==kIOReturnBadArgument);
        assert(a.nativeP2pManualArmRequested_==0 && a.nativeP2pDirectedPrepareArmed_==0);
    }
#endif
    puts("Test105 production directed arm guards passed");
}
'''
with tempfile.TemporaryDirectory(prefix='test105-directed-arm-') as temporary:
    cpp=Path(temporary)/'arm.cpp';cpp.write_text(SHIM+'\n'+PRODUCTION+'\n'+BODY)
    for enabled in (False,True):
        output=Path(temporary)/('enabled' if enabled else 'disabled')
        args=['clang++','-std=c++14','-Wall','-Wextra','-Werror','-Wno-unused-function',
              '-Wno-unused-const-variable','-fsanitize=address,undefined',
              '-fno-omit-frame-pointer',str(cpp),'-o',str(output)]
        if enabled:args.append('-DITL_NATIVE_AWDL_DIRECTED_PREPARE_25G332=1')
        subprocess.run(args,check=True);subprocess.run([str(output)],check=True)
