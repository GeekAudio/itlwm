#!/usr/bin/env python3
"""Compile actual adapter branches/methods with production Backend and trace.

The gate/controller are host fixtures. No native user client, radio, or device
is exercised. The old adapter branch is an explicit negative control.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "AirportItlwm/AirportItlwmSkywalkInterface.cpp"
BASELINE = "f37154abbd629099b15646c22b085f4b88a09240"


def braced(source, marker, include_declaration=True):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return source[start:end + 1] if include_declaration else source[opening + 1:end]
    raise AssertionError(marker)


def assoc_branch(source):
    start = source.index("case IEEE80211_EVT_STA_ASSOC_DONE:",
                         source.index("AirportItlwmSkywalkInterface::consumeNative("))
    return source[start:source.index("break;", start) + len("break;")]


PREAMBLE = r"""
#include "native/scan_dispatch_trace.hpp"
#include "native/native_power_trace.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
using IOReturn = int32_t;
constexpr IOReturn kIOReturnUnsupported = int32_t(0xe00002c7U);
struct apple80211ScanRequest {};
struct apple80211_bgscan_cached_network_data_list {};
struct apple80211_bg_scan {};
struct scanHomeAndAwayTime {};
struct apple80211AssocCandidates {};
struct ControllerState { bool ic_tahoe_join_requested {true}; };
struct Hal { ControllerState ic; ControllerState *get80211Controller() { return &ic; } };
class AirportItlwm {
public:
    NativePowerTrace::Ledger ledger;
    uint64_t clock {};
    uint32_t beginNativeControlTrace(NativePowerTrace::Operation op,
        NativePowerTrace::Phase phase, uint32_t detail, int32_t result) {
        return ledger.begin(op, phase, ++clock, 1, 3, 0x41, 1, detail, result);
    }
    void recordNativeControlTrace(uint32_t id, NativePowerTrace::Operation op,
        NativePowerTrace::Phase phase, uint32_t detail, int32_t result) {
        ledger.record(id, op, phase, ++clock, 1, 3, 0x41, 1, detail, result);
    }
};
struct Gate {
    IOReturn result {};
    void *object {}, *operation {}, *data {}, *length {};
    template<class Fn>
    IOReturn runAction(Fn, void *o, void *op, void *d, void *n = nullptr) {
        object=o;operation=op;data=d;length=n;return result;
    }
};
Gate *_fCommandGate;
class AirportItlwmSkywalkInterface {
public:
    AirportItlwm *instance {};
    Hal *fHalService {};
    NativeWifi::ScanDispatchTrace::Trace nativeScanDispatchTrace;
    static uint64_t scanMonotonicNanoseconds(void *) { static uint64_t n=100; return ++n; }
    static IOReturn nativeRequest(void *, void *, void *, void *, void *) { return 0; }
    uint64_t recordNativeScanDispatch(NativeWifi::ScanDispatchTrace::Selector,
        NativeWifi::ScanDispatchTrace::Phase, IOReturn, const void *, uint64_t=0);
    IOReturn getWCL_BGSCAN_CACHE_RESULT(apple80211_bgscan_cached_network_data_list *);
    IOReturn setWCL_SCAN_REQ(apple80211ScanRequest *);
    IOReturn setWCL_CONFIG_BGSCAN(apple80211_bg_scan *);
    IOReturn setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *);
    IOReturn setWCL_ASSOCIATE(apple80211AssocCandidates *);
};
"""

MAIN = r"""
enum { IEEE80211_EVT_STA_ASSOC_DONE = 1 };
struct Entry { int kind; uint32_t value; const uint8_t *bssid; };
void consume(Radio &radio, AirportItlwmSkywalkInterface &adapter, const Entry &entry) {
    auto backend = &radio.backend;
    auto self = &adapter;
    switch (entry.kind) {
    __ASSOC_BRANCH__
    }
}
const uint8_t a[6]={2,0,0,0,1,1}, b[6]={2,0,0,0,1,2};
void replaceDuringAssociation(Radio *radio) {
    assert(radio->backend.leave(true)==Status::Ok);
    requestJoin(*radio,b);
}
int main() {
    Hal radioControl;
    AirportItlwmSkywalkInterface adapter;
    adapter.fHalService=&radioControl;
    {
        Radio radio;
        consume(radio,adapter,{1,0,a}); // No pending join.
        if (!radioControl.ic.ic_tahoe_join_requested) {
            std::cout<<"REJECTED_ASSOC_CLEARED_FLAG\n"; return 42;
        }
        requestJoin(radio,a);
        consume(radio,adapter,{1,0,b}); // A foreign target must not cancel A.
        assert(radioControl.ic.ic_tahoe_join_requested && radio.backend.joining());
        consume(radio,adapter,{1,0,a});
        assert(!radioControl.ic.ic_tahoe_join_requested);
    }
    {
        Radio radio; requestJoin(radio,a);
        radioControl.ic.ic_tahoe_join_requested=true;
        consume(radio,adapter,{1,1,a}); // Accepted association failure.
        assert(!radioControl.ic.ic_tahoe_join_requested && !radio.backend.joining());
    }
    {
        Radio radio;
        radio.backend.beginAddressChange(); requestJoin(radio,a);
        radioControl.ic.ic_tahoe_join_requested=true;
        consume(radio,adapter,{1,0,a}); // Deferred; not submitted to radio.
        assert(radioControl.ic.ic_tahoe_join_requested);
        radio.backend.stop();
        consume(radio,adapter,{1,0,a});
        assert(radioControl.ic.ic_tahoe_join_requested);
    }
    {
        Radio radio; requestJoin(radio,a);
        radio.associationHook=replaceDuringAssociation;
        radioControl.ic.ic_tahoe_join_requested=true;
        consume(radio,adapter,{1,0,a});
        assert(radioControl.ic.ic_tahoe_join_requested && radio.backend.joining());
        consume(radio,adapter,{1,0,b});
        assert(!radioControl.ic.ic_tahoe_join_requested);
    }
    Gate gate; _fCommandGate=&gate;
    const IOReturn returns[]={0,int32_t(0xe00002d5U),int32_t(0xe00002d8U),-77};
    for (const auto result:returns) {
        AirportItlwm controller;
        AirportItlwmSkywalkInterface iface; iface.instance=&controller;
        gate.result=result;
        auto request=reinterpret_cast<apple80211ScanRequest *>(uintptr_t(1));
        assert(iface.setWCL_SCAN_REQ(request)==result);
        assert(gate.data==request && gate.operation==reinterpret_cast<void *>(Scan));
        assert(iface.getWCL_BGSCAN_CACHE_RESULT(
            reinterpret_cast<apple80211_bgscan_cached_network_data_list *>(uintptr_t(1)))
            ==kIOReturnUnsupported);
        assert(iface.setWCL_CONFIG_BGSCAN(
            reinterpret_cast<apple80211_bg_scan *>(uintptr_t(1)))==kIOReturnUnsupported);
        assert(iface.setWCL_SET_SCAN_HOME_AWAY_TIME(
            reinterpret_cast<scanHomeAndAwayTime *>(uintptr_t(1)))==kIOReturnUnsupported);
        NativeWifi::ScanDispatchTrace::Snapshot snapshot {};
        assert(iface.nativeScanDispatchTrace.snapshot(&snapshot) && snapshot.count==8);
        for (unsigned i=0;i<8;i+=2) {
            assert(snapshot.records[i].callSerial==snapshot.records[i+1].callSerial);
            assert(snapshot.records[i].context & NativeWifi::ScanDispatchTrace::GateContextUnknown);
        }
        auto join=reinterpret_cast<apple80211AssocCandidates *>(uintptr_t(1));
        assert(iface.setWCL_ASSOCIATE(join)==result);
        assert(gate.data==join && gate.object==&iface &&
               gate.operation==reinterpret_cast<void *>(Join));
        NativePowerTrace::Snapshot calls {};
        controller.ledger.snapshot(&calls);
        assert(calls.count==2 && calls.entries[0].callId==calls.entries[1].callId);
        assert(calls.entries[0].operation==uint32_t(NativePowerTrace::Operation::kWclJoin));
        assert(calls.entries[0].phase==uint32_t(NativePowerTrace::Phase::kCallBegin));
        assert(calls.entries[1].phase==uint32_t(NativePowerTrace::Phase::kCallEnd));
        assert(calls.entries[1].result==result &&
               uintptr_t(gate.length)==calls.entries[0].callId);
    }
    std::cout<<"actual adapter/dispatch methods: PASS\n";
}
"""


def main():
    source = SOURCE.read_text()
    fixture = (ROOT / "native/tests/wifi_switch_state_machine_test.cpp").read_text()
    fixture = fixture[:fixture.index("\nvoid testConnectedTargetChangeWithoutIntermediateDown")]
    fixture += "\n}\n"  # Close the reused fixture's anonymous namespace.
    scope = braced(source, "class NativeControlTraceScope") + ";"
    enum_start = source.index("enum NativeRequest {")
    dispatch_enum = source[enum_start:source.index(";", enum_start) + 1]
    methods = "\n".join(braced(source, marker) for marker in (
        "uint64_t AirportItlwmSkywalkInterface::recordNativeScanDispatch(",
        "IOReturn AirportItlwmSkywalkInterface::getWCL_BGSCAN_CACHE_RESULT(",
        "IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_REQ(",
        "IOReturn AirportItlwmSkywalkInterface::setWCL_CONFIG_BGSCAN(",
        "IOReturn AirportItlwmSkywalkInterface::setWCL_SET_SCAN_HOME_AWAY_TIME(",
        "IOReturn AirportItlwmSkywalkInterface::setWCL_ASSOCIATE(",
    ))
    baseline = subprocess.check_output(
        ["git", "show", BASELINE + ":AirportItlwm/AirportItlwmSkywalkInterface.cpp"],
        cwd=ROOT, text=True)
    with tempfile.TemporaryDirectory(prefix="test117-actual-adapter-") as tmp:
        for label, branch in (("candidate", assoc_branch(source)),
                              ("baseline-adapter", assoc_branch(baseline))):
            cpp = Path(tmp) / (label + ".cpp")
            binary = Path(tmp) / label
            cpp.write_text(PREAMBLE + fixture + dispatch_enum + scope + methods +
                           MAIN.replace("__ASSOC_BRANCH__", branch))
            subprocess.run([
                "xcrun", "clang++", "-std=gnu++14", "-O1", "-g",
                "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT), "-I", str(ROOT / "native/tests"),
                "native/wcl_wire.cpp", "native/wcl_backend.cpp",
                str(cpp), "-o", str(binary),
            ], cwd=ROOT, check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            if label == "candidate":
                assert result.returncode == 0, result.stderr
            else:
                assert result.returncode == 42 and "REJECTED_ASSOC_CLEARED_FLAG" in result.stdout
            print(label + ": " + result.stdout.strip())


if __name__ == "__main__":
    main()
