// SPDX-License-Identifier: GPL-2.0-only
// Host-only fixture: compile the unchanged getter body extracted by the runner
// against the actual production bridge, with fake HAL evidence and KPI types.
#pragma once
#ifndef TEST104_EXISTING_TEST_SOURCE
#define TEST104_EXISTING_TEST_SOURCE "awdl_native_rx149_data_input_test.cpp"
#endif
#ifndef TEST104_BRIDGE_SOURCE
#define TEST104_BRIDGE_SOURCE "../awdl_native_bsd_data_25G332.cpp"
#endif
#define main test104ExistingRegressionMainNotInvoked
#include TEST104_EXISTING_TEST_SOURCE
#undef main
#include TEST104_BRIDGE_SOURCE
#include <stdio.h>
#include <thread>

namespace NativeP2PRx149Observation { constexpr uint16_t kIeeeChannel=149; }
constexpr uint32_t IWX_FLAG_HW_ERR=1u, IWX_FLAG_SHUTDOWN=2u, IWX_FLAG_RFKILL=4u;
struct FakeBoolean {};
static FakeBoolean fakeTrue;
static FakeBoolean *const kOSBooleanTrue=&fakeTrue;
struct IOEthernetController {
    bool experiment=true,profile=true;
    const FakeBoolean *getProperty(const char *key) const {
        return !strcmp(key,"NativeP2PRx149DataInputExperiment")&&experiment
            ?kOSBooleanTrue:nullptr;
    }
};
inline bool rx149PropertyIsOne(IOEthernetController *p,const char *) {
    return p&&p->profile;
}
struct iwx_softc {
    uint32_t sc_generation=72,sc_tx_rate_generation=73,sc_flags=0;
};
struct Test104RawLease {uint64_t contextGeneration=71,powerGeneration=72,stationGeneration=73;};
struct Test104Session {uint32_t generation=71;uint64_t startObservedMonotonicUs=1000;};
struct Test104TraceOwner {uint64_t ownerSerial=901;};
template<typename T> struct Test104Snapshot {
    T value{};
    T snapshot() const {return value;}
};
struct ItlIwx {
    iwx_softc com;
    IOEthernetController controller;
    bool inMainGate=true,controllerPresent=true;
    uint32_t nativeP2pCancelRequested_=0;
    Test104RawLease tahoe_p2p_rx_lease_;
    Test104Snapshot<Test104Session> nativeP2pRocEvents_;
    Test104Snapshot<Test104TraceOwner> nativeAwdlRxEventTimeline_;
    NativeP2PRx149DataInput::Lease evidence=validLease();
    bool tahoeP2pOnMainGate() const {return inMainGate;}
    IOEthernetController *tahoeP2pController(){return controllerPresent?&controller:nullptr;}
    bool tahoeP2pRx149DataLease(NativeP2PRx149DataInput::Lease *);
    void pending() {
        evidence.startSeen=evidence.startSucceeded=false;
        nativeP2pRocEvents_.value.startObservedMonotonicUs=0;
    }
    void started() {
        evidence.startSeen=evidence.startSucceeded=true;
        nativeP2pRocEvents_.value.startObservedMonotonicUs=1000;
    }
    void nextOwner() {
        nativeAwdlRxEventTimeline_.value.ownerSerial=902;
        tahoe_p2p_rx_lease_.contextGeneration=72;
        tahoe_p2p_rx_lease_.stationGeneration=74;
        nativeP2pRocEvents_.value.generation=72;
        com.sc_tx_rate_generation=74;
    }
};
inline NativeP2PRx149DataInput::Lease currentRx149ActionEvidence(
    ItlIwx *p,iwx_softc *,const Test104RawLease &,uint16_t,
    const Test104Session &,const Test104TraceOwner &) {return p->evidence;}
inline uint64_t tahoeP2pRxMonotonicUs(){return fakeTime;}

// Exact text of candidate (or baseline) method; no hand-written branch model.
#include "test104_rx149_hal_getter.inc"
