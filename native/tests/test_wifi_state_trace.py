#!/usr/bin/env python3
"""Host-test the actual Wi-Fi getter bodies and the bounded trace ledger."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
V2 = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
SKYWALK = (ROOT / "AirportItlwm/AirportItlwmSkywalkInterface.cpp").read_text()


def function_from(text: str, marker: str) -> str:
    start = text.index(marker)
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


POWER_GET = function_from(V2, "IOReturn AirportItlwm::\ngetPOWER(")
SSID_GET = function_from(SKYWALK, "IOReturn AirportItlwmSkywalkInterface::\ngetSSID(")
BSSID_GET = function_from(SKYWALK, "IOReturn AirportItlwmSkywalkInterface::\ngetBSSID(")
EMIT_NATIVE = function_from(SKYWALK, "void AirportItlwmSkywalkInterface::emitNative(")


HARNESS = r'''#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <map>
#include <string>
#include <vector>
#include "native/native_power_trace.hpp"
#include "native/native_wifi_state_trace.hpp"

#define AIRPORT_TAHOE 1
using IOReturn = int32_t;
using OSObject = void;
constexpr IOReturn kIOReturnSuccess=0, kIOReturnError=int32_t(0xe00002bc),
    kIOReturnBadArgument=int32_t(0xe00002c2), kIOReturnNotReady=int32_t(0xe00002d8);
constexpr uint32_t APPLE80211_VERSION=1, APPLE80211_MAX_RADIO=4,
    APPLE80211_ADDR_LEN=6, kPowerStateOff=0, kPowerStateOn=1,
    IEEE80211_S_RUN=4, IEEE80211_F_DESBSSID=0x100;
struct IOSimpleLock {};
using IOInterruptState=uint32_t;
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *) { return 0; }
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *, IOInterruptState) {}
static uint64_t g_now_ns=1000000;
static uint64_t nativePowerUptimeNanoseconds() { return g_now_ns; }

struct apple80211_power_data { uint32_t version, num_radios, power_state[4]; };
struct apple80211_ssid_data { uint32_t version, ssid_len; uint8_t ssid_bytes[32]; };
struct apple80211_bssid_data { uint32_t version; struct { uint8_t octet[6]; } bssid; };
struct ieee80211_node {
    int ni_esslen;
    uint8_t ni_essid[32];
    uint8_t ni_bssid[6];
};
struct ieee80211com {
    uint32_t ic_state;
    uint32_t ic_flags;
    ieee80211_node *ic_bss;
    int ic_des_esslen;
    uint8_t ic_des_essid[32];
    uint8_t ic_des_bssid[6];
};
class ItlHalService {
public:
    ieee80211com *controller {};
    uint32_t faultSerial {0};
    bool faultSerialValid {false};
    ieee80211com *get80211Controller() { return controller; }
    bool readNativePowerFaultSerial(uint32_t *out) {
        if (faultSerialValid && out) *out=faultSerial;
        return faultSerialValid;
    }
};
class OSData {
public:
    static OSData *withBytes(const void *data, size_t size) {
        OSData *result=new OSData;
        result->bytes.assign(static_cast<const uint8_t *>(data),
                             static_cast<const uint8_t *>(data)+size);
        return result;
    }
    void release() { delete this; }
    std::vector<uint8_t> bytes;
};
static bool ml_at_interrupt_context() { return false; }
class AirportItlwm {
public:
    IOSimpleLock *nativePowerStateLock {};
    IOSimpleLock *nativePowerTraceLock {};
    uint32_t nativePowerFlags {}, nativePowerEpoch {}, pmPowerState {kPowerStateOn};
    uint64_t nativePowerTransitionRevision {};
    uint64_t nativeAddressRestartPublishedId {}, nativeAddressRestartStartRevision {};
    uint32_t nativeAddressRestartPublishedEpoch {};
    uint32_t nativePowerGetCount {};
    uint32_t nativeWifiStateTracePublishedSequence {};
    bool nativeWifiStateTracePublished {false};
    uint32_t nativeWifiStateTracePublishedCallCounts[NativeWifiStateTrace::kKindCount] {};
    ItlHalService *fHalService {};
    NativePowerTrace::AddressRestartNotification nativeAddressRestartNotification {};
    NativeWifiStateTrace::Ledger nativeWifiStateTrace {};
    NativeWifiStateTrace::Ledger ledger {};
    std::vector<uint8_t> publishedStateTrace;
    std::map<std::string,uint32_t> numericProperties;
    uint32_t dataPropertyWrites {};
    IOReturn getPOWER(OSObject *, apple80211_power_data *);
    bool recordNativeWifiStateObservation(
        const NativeWifiStateTrace::Observation &, bool forceAppend=false);
    bool setProperty(const char *name, OSData *data) {
        if (std::string(name)=="NativeWifiStateTrace") {
            publishedStateTrace=data->bytes;
            ++dataPropertyWrites;
        }
        return true;
    }
    bool setProperty(const char *name, uint32_t value, unsigned) {
        numericProperties[name]=value;
        return true;
    }
    void publishNativeWifiStateTrace();
    void publishNativePowerState() {}
};
class AirportItlwmSkywalkInterface {
public:
    AirportItlwm *instance {};
    ItlHalService *fHalService {};
    IOReturn getSSID(apple80211_ssid_data *);
    IOReturn getBSSID(apple80211_bssid_data *);
};

''' + POWER_GET + '\n' + SSID_GET + '\n' + BSSID_GET + r'''

''' + function_from(V2, "bool AirportItlwm::recordNativeWifiStateObservation(") + '\n' + function_from(V2, "void AirportItlwm::publishNativeWifiStateTrace(") + r'''

static const NativeWifiStateTrace::Observation *lastKind(
    const NativeWifiStateTrace::Snapshot &snapshot,
    NativeWifiStateTrace::Kind kind) {
    for (uint32_t i=snapshot.count; i>0; --i)
        if (snapshot.entries[i-1].kind == uint32_t(kind))
            return &snapshot.entries[i-1];
    return nullptr;
}

static void testPowerGetBody() {
    IOSimpleLock lock;
    ItlHalService hal;
    AirportItlwm driver;
    apple80211_power_data out{};
    driver.nativePowerTraceLock=&lock;
    driver.nativePowerStateLock=&lock;
    driver.fHalService=&hal;
    driver.nativePowerFlags=3;
    driver.nativePowerEpoch=9;
    driver.nativePowerTransitionRevision=41;
    driver.pmPowerState=kPowerStateOn;
    assert(driver.getPOWER(nullptr,&out)==kIOReturnSuccess);
    assert(out.num_radios==APPLE80211_MAX_RADIO && out.power_state[0]==1);
    NativeWifiStateTrace::Snapshot snapshot{};
    driver.nativeWifiStateTrace.snapshot(&snapshot);
    assert(snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kPowerGet)]==1);
    auto record=lastKind(snapshot,NativeWifiStateTrace::Kind::kPowerGet);
    assert(record && record->result==kIOReturnSuccess && record->value==out.power_state[0]);
    assert(record->powerEpoch==9 && record->transitionRevision==41);
    assert((record->flags & NativeWifiStateTrace::kPMRequestedOn) &&
           (record->flags & NativeWifiStateTrace::kHALReady) &&
           (record->flags & NativeWifiStateTrace::kSystemPMOn));

    // One committed private-address restart may hold GET_POWER on only until
    // its existing 900 ms deadline; the observation must share that exact
    // decision and report the remaining window without a second snapshot.
    driver.nativeAddressRestartNotification = NativePowerTrace::AddressRestartNotification{};
    const uint64_t restartId=driver.nativeAddressRestartNotification.begin(
        9,41,17,true,3,g_now_ns);
    assert(restartId!=0);
    assert(driver.nativeAddressRestartNotification.commit(restartId,9,17,true,true,true));
    driver.nativeAddressRestartPublishedId=restartId;
    driver.nativeAddressRestartStartRevision=41;
    driver.nativeAddressRestartPublishedEpoch=9;
    hal.faultSerial=17;
    hal.faultSerialValid=true;
    driver.nativePowerFlags=1; // READY dipped while requested power remains On
    g_now_ns += 899000000ULL;
    assert(driver.getPOWER(nullptr,&out)==kIOReturnSuccess && out.power_state[0]==1);
    driver.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kPowerGet);
    assert(record && record->value==1 && record->restartId==restartId);
    assert(record->restartRemainingNs==1000000ULL);
    assert((record->flags & NativeWifiStateTrace::kRestartActive) &&
           (record->flags & NativeWifiStateTrace::kRestartCommitted) &&
           (record->flags & NativeWifiStateTrace::kFaultSerialValid) &&
           (record->flags & NativeWifiStateTrace::kFaultSerialMatches) &&
           (record->flags & NativeWifiStateTrace::kRestartIdentityMatch) &&
           (record->flags & NativeWifiStateTrace::kRestartEpochMatch) &&
           (record->flags & NativeWifiStateTrace::kRestartRevisionMatch) &&
           (record->flags & NativeWifiStateTrace::kRestartValidationEvaluated));

    g_now_ns += 1000000ULL;
    assert(driver.getPOWER(nullptr,&out)==kIOReturnSuccess && out.power_state[0]==0);
    driver.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kPowerGet);
    assert(record && record->value==0 && record->restartRemainingNs==0);

    // Missing getter data is not inferred as success; a null output is an
    // observed error, and a missing lifecycle lock is explicitly flagged.
    const uint32_t before=snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kPowerGet)];
    assert(driver.getPOWER(nullptr,nullptr)==kIOReturnError);
    driver.nativeWifiStateTrace.snapshot(&snapshot);
    assert(snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kPowerGet)]==before+1);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kPowerGet);
    assert(record && record->result==kIOReturnError && !(record->flags & NativeWifiStateTrace::kValueValid));

    AirportItlwm lockless;
    lockless.nativePowerTraceLock=&lock;
    lockless.nativePowerFlags=3;
    lockless.pmPowerState=kPowerStateOn;
    assert(lockless.getPOWER(nullptr,&out)==kIOReturnSuccess && out.power_state[0]==1);
    lockless.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kPowerGet);
    assert(record && (record->flags & NativeWifiStateTrace::kStateLockMissing));
}

static void testActualPublishBodyAndInitialEmptySnapshot() {
    IOSimpleLock traceLock;
    AirportItlwm driver;
    driver.nativePowerTraceLock=&traceLock;
    driver.publishNativeWifiStateTrace();
    assert(driver.nativeWifiStateTracePublishedSequence==0);
    assert(driver.nativeWifiStateTracePublished);
    assert(driver.publishedStateTrace.size()==sizeof(NativeWifiStateTrace::Snapshot));
    NativeWifiStateTrace::Snapshot snapshot{};
    std::memcpy(&snapshot,driver.publishedStateTrace.data(),sizeof(snapshot));
    assert(snapshot.schemaVersion==NativeWifiStateTrace::kSchemaVersion && snapshot.count==0);
    for (uint32_t calls : snapshot.callCounts) assert(calls==0);
    driver.publishNativeWifiStateTrace(); // same sequence/counts is not republished
    assert(driver.dataPropertyWrites==1);

    NativeWifiStateTrace::Observation observation{};
    observation.kind=uint32_t(NativeWifiStateTrace::Kind::kSSIDQuery);
    observation.result=kIOReturnNotReady;
    assert(driver.recordNativeWifiStateObservation(observation));
    // The getter only updates the numeric ledger. IOKit publication is queued
    // to the existing native-ingress command-gate consumer, not done here.
    assert(driver.publishedStateTrace.size()==sizeof(snapshot));
    driver.publishNativeWifiStateTrace();
    assert(driver.nativeWifiStateTracePublishedSequence==1);
    std::memcpy(&snapshot,driver.publishedStateTrace.data(),sizeof(snapshot));
    assert(snapshot.count==1 && snapshot.newestSequence==1);
    assert(snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kSSIDQuery)]==1);

    // A deduplicated poll increments the observation count without changing
    // ring sequence. The next gate publication must still refresh the OSData.
    assert(!driver.recordNativeWifiStateObservation(observation));
    driver.nativeWifiStateTrace.snapshot(&snapshot);
    assert(snapshot.newestSequence==1 &&
           snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kSSIDQuery)]==2);
    driver.publishNativeWifiStateTrace();
    assert(driver.nativeWifiStateTracePublishedSequence==1 && driver.dataPropertyWrites==3);
    std::memcpy(&snapshot,driver.publishedStateTrace.data(),sizeof(snapshot));
    assert(snapshot.newestSequence==1 &&
           snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kSSIDQuery)]==2);
}

static void testSSIDAndBSSIDBodies() {
    AirportItlwm controller;
    ItlHalService hal;
    ieee80211com ic{};
    ieee80211_node bss{};
    IOSimpleLock traceLock;
    AirportItlwmSkywalkInterface iface;
    iface.instance=&controller;
    iface.fHalService=&hal;
    controller.nativePowerTraceLock=&traceLock;
    hal.controller=&ic;
    ic.ic_state=IEEE80211_S_RUN;
    ic.ic_bss=&bss;
    bss.ni_esslen=7;
    std::memcpy(bss.ni_essid,"visible",7);
    apple80211_ssid_data ssid{};
    assert(iface.getSSID(&ssid)==kIOReturnSuccess && ssid.ssid_len==7);
    NativeWifiStateTrace::Snapshot snapshot{};
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    auto record=lastKind(snapshot,NativeWifiStateTrace::Kind::kSSIDQuery);
    assert(record && record->result==kIOReturnSuccess && record->value==7 &&
           (record->flags & NativeWifiStateTrace::kCurrentBSSSource) &&
           (record->flags & NativeWifiStateTrace::kValueValid));

    // During join, the same getter exposes desired SSID length/source only.
    ic.ic_state=0;
    ic.ic_des_esslen=6;
    std::memcpy(ic.ic_des_essid,"target",6);
    assert(iface.getSSID(&ssid)==kIOReturnSuccess && ssid.ssid_len==6);
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kSSIDQuery);
    assert(record && record->value==6 && (record->flags & NativeWifiStateTrace::kDesiredSSIDSource));
    ic.ic_des_esslen=0;
    assert(iface.getSSID(&ssid)==kIOReturnNotReady);
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kSSIDQuery);
    assert(record && record->result==kIOReturnNotReady &&
           !(record->flags & NativeWifiStateTrace::kValueValid));
    ic.ic_des_esslen=-1;
    assert(iface.getSSID(&ssid)==kIOReturnBadArgument);

    // Compare current BSSID with an explicit desired BSSID only when the
    // DESBSSID flag makes that comparison meaningful.
    ic.ic_state=IEEE80211_S_RUN;
    const uint8_t address[6]={0x00,0x11,0x22,0x33,0x44,0x55};
    std::memcpy(bss.ni_bssid,address,sizeof(address));
    apple80211_bssid_data bssid{};
    assert(iface.getBSSID(&bssid)==kIOReturnSuccess);
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kBSSIDQuery);
    ic.ic_flags=IEEE80211_F_DESBSSID;
    std::memcpy(ic.ic_des_bssid,address,sizeof(address));
    assert(iface.getBSSID(&bssid)==kIOReturnSuccess);
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kBSSIDQuery);
    assert(record && record->result==kIOReturnSuccess && record->value==6 &&
           (record->flags & NativeWifiStateTrace::kAddressComparisonValid) &&
           (record->flags & NativeWifiStateTrace::kAddressMatchesDesired));
    ic.ic_des_bssid[5]^=1;
    assert(iface.getBSSID(&bssid)==kIOReturnSuccess);
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kBSSIDQuery);
    assert(record && (record->flags & NativeWifiStateTrace::kAddressComparisonValid) &&
           !(record->flags & NativeWifiStateTrace::kAddressMatchesDesired));
    ic.ic_state=0;
    assert(iface.getBSSID(&bssid)==6);
    controller.nativeWifiStateTrace.snapshot(&snapshot);
    record=lastKind(snapshot,NativeWifiStateTrace::Kind::kBSSIDQuery);
    assert(record && record->result==6 && !(record->flags & NativeWifiStateTrace::kValueValid));
}

static void testLedgerDedupAndBound() {
    NativeWifiStateTrace::Ledger ledger;
    NativeWifiStateTrace::Snapshot snapshot{};
    ledger.snapshot(&snapshot);
    assert(snapshot.count==0 && snapshot.callCounts[0]==0); // not observed, unknown
    NativeWifiStateTrace::Observation item{};
    item.kind=uint32_t(NativeWifiStateTrace::Kind::kPowerGet);
    item.result=kIOReturnSuccess; item.value=1; item.flags=NativeWifiStateTrace::kValueValid;
    item.monotonicNs=1; item.restartRemainingNs=10;
    assert(ledger.observe(item));
    item.monotonicNs=2; item.restartRemainingNs=9;
    assert(!ledger.observe(item)); // polling without a state change is collapsed
    assert(ledger.sequence()==1);
    for (uint32_t i=0;i<NativeWifiStateTrace::kCapacity+3;i++) {
        item.kind=uint32_t(NativeWifiStateTrace::Kind::kWclLinkEvent);
        item.value=i & 1U; item.auxiliary=216;
        assert(ledger.observe(item,true)); // preserve repeated event calls
    }
    ledger.snapshot(&snapshot);
    assert(snapshot.count==5); // power keeps its own slot set; link retains its last four
    assert(snapshot.overwrittenCount==NativeWifiStateTrace::kCapacity-1);
    assert(snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kPowerGet)]==2);
    assert(snapshot.callCounts[uint32_t(NativeWifiStateTrace::Kind::kWclLinkEvent)]==NativeWifiStateTrace::kCapacity+3);
    for (uint32_t i=1;i<snapshot.count;i++)
        assert(snapshot.entries[i-1].sequence < snapshot.entries[i].sequence);
    assert(snapshot.entries[0].sequence==1); // link flood cannot evict GET_POWER state
    assert(snapshot.entries[snapshot.count-1].sequence==NativeWifiStateTrace::kCapacity+4);
}

int main() {
    testPowerGetBody();
    testActualPublishBodyAndInitialEmptySnapshot();
    testSSIDAndBSSIDBodies();
    testLedgerDedupAndBound();
    return 0;
}
'''


class WifiStateTraceTests(unittest.TestCase):
    def test_actual_getter_bodies_and_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace_test.cpp"
            exe = Path(tmp) / "trace_test"
            src.write_text(HARNESS)
            subprocess.run([
                "c++", "-std=c++17", "-Wall", "-Wextra", "-I", str(ROOT),
                str(src), "-o", str(exe),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(exe)], check=True, capture_output=True, text=True)

    def test_snapshot_and_callsite_redaction_contract(self):
        # Public wire structs are numeric only; network bytes never enter the
        # observation object or its fixed-ring serialization.
        trace_header = (ROOT / "native/native_wifi_state_trace.hpp").read_text()
        observation_decl = trace_header.split("struct Observation {", 1)[1].split("};", 1)[0]
        for forbidden in ("ssid_bytes", "ni_essid", "bssid.octet", "key_material", "uint8_t "):
            self.assertNotIn(forbidden, observation_decl)

        self.assertIn("observation.value = returnedLength", SSID_GET)
        self.assertIn("observation.result = result", SSID_GET)
        self.assertIn("observation.value = result == kIOReturnSuccess ? APPLE80211_ADDR_LEN : 0", BSSID_GET)
        self.assertIn("ic->ic_flags & IEEE80211_F_DESBSSID", BSSID_GET)
        self.assertIn("NativeWifiStateTrace::kAddressComparisonValid", BSSID_GET)
        self.assertIn("NativeWifiStateTrace::kAddressMatchesDesired", BSSID_GET)
        self.assertIn("observation.auxiliary = event; // NativeWifi::Link == WCL event 216", EMIT_NATIVE)
        self.assertIn("NativeWifiStateTrace::kEmitCallOnly", EMIT_NATIVE)
        self.assertIn("recordNativeWifiStateObservation(observation, true)", EMIT_NATIVE)
        self.assertLess(EMIT_NATIVE.index("postMessage(event"),
                        EMIT_NATIVE.index("recordNativeWifiStateObservation(observation, true)"))
        self.assertNotIn("nativePowerStateSnapshot", POWER_GET)
        self.assertLess(POWER_GET.index("for (unsigned i"), POWER_GET.rindex("recordNativeWifiStateObservation(observation)"))
        watchdog = function_from(V2, "void AirportItlwm::watchdogAction(")
        consume = function_from(SKYWALK, "void AirportItlwmSkywalkInterface::consumeNative(")
        self.assertIn("captureNativeTick", watchdog)
        self.assertNotIn("runAction", watchdog)
        self.assertIn("nativeIngress->initialize(_fCommandGate, consumeNative, this)", SKYWALK)
        self.assertIn("publishNativeWifiStateTrace()", consume)
        self.assertEqual(V2.count("publishNativeWifiStateTrace();"), 0)
        publisher = function_from(V2, "void AirportItlwm::publishNativeWifiStateTrace(")
        unlock = publisher.index("IOSimpleLockUnlockEnableInterrupt(traceLock, irq)")
        self.assertLess(unlock, publisher.index("OSData::withBytes"))
        self.assertLess(unlock, publisher.index("setProperty(\"NativeWifiStateTrace\""))


if __name__ == "__main__":
    unittest.main()
