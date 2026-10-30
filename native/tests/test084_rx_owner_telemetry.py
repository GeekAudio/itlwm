#!/usr/bin/env python3
"""Test084 RX-owner telemetry against the current production source.

The first two ASan/UBSan builds extract the production window predicates and
retain the 38 cfg2/cfg3 contract checks. A third build extracts the production
RX149 owner evidence and tahoeP2pCurrentRxDiagnosticEpochs method into a small
fake-driver fixture. It exercises the real lease, generation, firmware,
session, owner, channel/color/binding, trace, token, phase, and timing gates.
No kext, RF, interface, EFI, or firmware is touched.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
RX = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"
IWN = ROOT.parent / "IntelWirelessNative"
PREP = IWN / "research/test084-preparation-private"
FEATURE = "ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing production function: {signature}")
    opening = source.find("{", start)
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")

    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start:index + 1]
        index += 1
    raise AssertionError(f"unterminated production function: {signature}")


def source_contracts(source: str) -> None:
    body = extract_function(
        source, "bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs("
    )
    evidence = extract_function(
        source,
        "NativeP2PRx149Observation::RocEvidence currentRx149ActionEvidence(",
    )
    window = extract_function(source, "static bool rxDiagnosticSessionWindowQualified(")

    for required in (
        "!lease.active",
        "lease.contextGeneration != lease.currentContextGeneration",
        "lease.powerGeneration != uint32_t(sc->sc_p2p.fw_generation)",
        "lease.stationGeneration != currentStation",
        "session.generation != lease.contextGeneration",
        "session.generation != currentRoc",
        "!session.commandReturned",
        "session.commandResult != 0",
        "sc->sc_p2p_roc.token != session.generation",
        "sc->sc_p2p_roc.phase != IWX_P2P_ROC_SESSION_ACKED",
        "currentRx149ActionEvidence(",
        "static_cast<uint16_t>(0xffffu)",
    ):
        assert required in body, f"production glue lost required gate: {required}"

    for required in (
        '"NativeP2PRx149Selected"',
        '"NativeP2PRx149HostTxBlocked"',
        "sc->sc_p2p_roc.receive_observation_only",
        "nativeP2pRocChannel_",
        "nativeP2pRocDurationMs_",
        "rocChannel149",
        "rx149StationAndPhyOwnerCurrent(sc)",
        "traceMatches",
        "ownerCurrent",
        "epochsMatch",
        "tokenMatches",
    ):
        assert required in evidence, f"current owner evidence missing: {required}"
    assert "validStartedOwner(*rx149Owner)" in window
    assert "rxChannel149" not in window

    # Keep this an observation-scope gate only; do not quietly widen permissions.
    assert "mayConsumeManagementAction" not in body
    assert "nativeDataPathAllowed" not in body
    assert "submit" not in body.lower()


WINDOW_HARNESS = r'''#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "native/p2p_rx149_observation.hpp"
#include "native/awdl_rx_entry_telemetry.hpp"

#define IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV 2
#define IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION 3

namespace IntelROCEvent {
struct SessionSnapshot {
    uint32_t generation;
    bool commandReturned;
    int commandResult;
    uint32_t configuration;
    bool startSeen;
    int startStatus;
    bool endSeen;
    bool outcomeUnknown;
    uint64_t startObservedMonotonicUs;
};
}

@@EXTRACTED_HELPERS@@

static unsigned checks = 0;

static void expect(const char *name, bool actual, bool expected = true)
{
    ++checks;
    if (actual != expected) {
        std::fprintf(stderr, "FAIL: %s expected=%d actual=%d\n",
                     name, expected ? 1 : 0, actual ? 1 : 0);
        std::abort();
    }
}

static NativeP2PRx149Observation::RocEvidence validOwner()
{
    NativeP2PRx149Observation::RocEvidence evidence{};
    evidence.profileSelected = true;
    evidence.receiveObservationOnly = true;
    evidence.requestedChannel149 = true;
    evidence.actualRocChannel149 = true;
    // Deliberately false: owner telemetry must not assert a packet channel.
    evidence.rxChannel149 = false;
    evidence.leaseActive = true;
    evidence.ownerCurrent = true;
    evidence.epochsMatch = true;
    evidence.tokenMatches = true;
    evidence.commandReturned = true;
    evidence.commandSucceeded = true;
    evidence.deviceDiscoveryConfiguration = true;
    evidence.startSeen = true;
    evidence.startSucceeded = true;
    evidence.endSeen = false;
    evidence.endConfirmed = false;
    evidence.outcomeUnknown = false;
    return evidence;
}

static IntelROCEvent::SessionSnapshot session(uint32_t configuration,
                                              uint64_t startUs = 1000000)
{
    IntelROCEvent::SessionSnapshot value{};
    value.generation = 7;
    value.commandReturned = true;
    value.commandResult = 0;
    value.configuration = configuration;
    value.startSeen = true;
    value.startStatus = 1;
    value.endSeen = false;
    value.outcomeUnknown = false;
    value.startObservedMonotonicUs = startUs;
    return value;
}

int main()
{
    using NativeP2PRx149Observation::RocEvidence;
    auto cfg2 = session(IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV);
    auto owner = validOwner();

    expect("generic cfg2 rejected", !rxDiagnosticSessionWindowQualified(
        cfg2, cfg2.startObservedMonotonicUs + 1, nullptr));
    expect("RX149 without descriptor channel assertion accepted at 99,999us",
        rxDiagnosticSessionWindowQualified(cfg2,
            cfg2.startObservedMonotonicUs + 99999, &owner),
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
        true
#else
        false
#endif
    );

#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    expect("cfg2 accepted at START", rxDiagnosticSessionWindowQualified(
        cfg2, cfg2.startObservedMonotonicUs, &owner), true);
    expect("cfg2 rejected at 100ms", !rxDiagnosticSessionWindowQualified(
        cfg2, cfg2.startObservedMonotonicUs + 100000, &owner));
    expect("cfg2 rejects before START", !rxDiagnosticSessionWindowQualified(
        cfg2, cfg2.startObservedMonotonicUs - 1, &owner));
    expect("cfg2 rejects zero START timestamp",
        !rxDiagnosticSessionWindowQualified(cfg2, 100, &owner));

    auto preStart = cfg2;
    preStart.startSeen = false;
    expect("cfg2 rejects pre-START", !rxDiagnosticSessionWindowQualified(
        preStart, preStart.startObservedMonotonicUs + 1, &owner));
    auto failedStart = cfg2;
    failedStart.startStatus = 0;
    expect("cfg2 rejects failed START", !rxDiagnosticSessionWindowQualified(
        failedStart, failedStart.startObservedMonotonicUs + 1, &owner));
    auto postEnd = cfg2;
    postEnd.endSeen = true;
    expect("cfg2 rejects post-END", !rxDiagnosticSessionWindowQualified(
        postEnd, postEnd.startObservedMonotonicUs + 1, &owner));
    auto unknown = cfg2;
    unknown.outcomeUnknown = true;
    expect("cfg2 rejects unknown outcome",
        !rxDiagnosticSessionWindowQualified(unknown,
            unknown.startObservedMonotonicUs + 1, &owner));

#define REJECT_OWNER_FIELD(field) do { \
    RocEvidence bad = owner; bad.field = false; \
    expect("cfg2 owner field " #field " required", \
        !rxDiagnosticSessionWindowQualified(cfg2, \
            cfg2.startObservedMonotonicUs + 1, &bad)); \
} while (0)
    REJECT_OWNER_FIELD(profileSelected);
    REJECT_OWNER_FIELD(receiveObservationOnly);
    REJECT_OWNER_FIELD(requestedChannel149);
    REJECT_OWNER_FIELD(actualRocChannel149);
    REJECT_OWNER_FIELD(leaseActive);
    REJECT_OWNER_FIELD(ownerCurrent);
    REJECT_OWNER_FIELD(epochsMatch);
    REJECT_OWNER_FIELD(tokenMatches);
    REJECT_OWNER_FIELD(commandReturned);
    REJECT_OWNER_FIELD(commandSucceeded);
    REJECT_OWNER_FIELD(deviceDiscoveryConfiguration);
    REJECT_OWNER_FIELD(startSeen);
    REJECT_OWNER_FIELD(startSucceeded);
#undef REJECT_OWNER_FIELD
#else
    expect("feature-off rejects cfg2 despite otherwise valid owner",
        !rxDiagnosticSessionWindowQualified(cfg2,
            cfg2.startObservedMonotonicUs + 1, &owner));
#endif

    auto wrongConfigEvidence = validOwner();
    wrongConfigEvidence.deviceDiscoveryConfiguration = false;
    expect("wrong ROC configuration rejected",
        !rxDiagnosticSessionWindowQualified(cfg2,
            cfg2.startObservedMonotonicUs + 1, &wrongConfigEvidence));

    auto cfg3 = session(IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
    expect("cfg3 900ms behavior retained without RX149 owner",
        rxDiagnosticSessionWindowQualified(cfg3,
            cfg3.startObservedMonotonicUs + 899999, nullptr), true);
    expect("cfg3 half-open 900ms boundary retained",
        !rxDiagnosticSessionWindowQualified(cfg3,
            cfg3.startObservedMonotonicUs + 900000, nullptr));
    auto cfg3PreStart = cfg3;
    cfg3PreStart.startSeen = false;
    expect("cfg3 rejects pre-START", !rxDiagnosticSessionWindowQualified(
        cfg3PreStart, cfg3PreStart.startObservedMonotonicUs + 1, nullptr));
    auto cfg3PostEnd = cfg3;
    cfg3PostEnd.endSeen = true;
    expect("cfg3 rejects post-END", !rxDiagnosticSessionWindowQualified(
        cfg3PostEnd, cfg3PostEnd.startObservedMonotonicUs + 1, nullptr));
    auto cfg3Unknown = cfg3;
    cfg3Unknown.outcomeUnknown = true;
    expect("cfg3 rejects unknown outcome",
        !rxDiagnosticSessionWindowQualified(cfg3Unknown,
            cfg3Unknown.startObservedMonotonicUs + 1, nullptr));

    std::printf("PASS: %u checks (%s build)\n", checks,
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
        "RX149 feature-on"
#else
        "RX149 feature-off"
#endif
    );
    return 0;
}
'''


GLUE_HARNESS = r'''#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "native/p2p_rx149_observation.hpp"
#include "native/awdl_rx_entry_telemetry.hpp"
#include "native/awdl_rx_event_timeline.hpp"
#include "native/intel_roc_event_state.hpp"
#include "native/intel_p2p_rx_router.hpp"

#define IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV 2
#define IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION 3
#define IWX_P2P_RESOURCE_ACTIVE 1
#define IWX_P2P_ROC_SESSION_ACKED 8
#define IWX_NUM_PHY_CTX 2
#define IWX_FLAG_SHUTDOWN (1U << 0)
#define IWX_FLAG_HW_ERR (1U << 1)
#define IWX_FLAG_RFKILL (1U << 2)
#define IEEE80211_S_RUN 5
#define nitems(value) (sizeof(value) / sizeof((value)[0]))

struct OSObject { virtual ~OSObject() = default; };
struct OSBoolean : OSObject {};
struct OSNumber : OSObject {
    explicit OSNumber(uint32_t value = 0) : value(value) {}
    uint32_t unsigned32BitValue() const { return value; }
    uint32_t value;
};
static OSBoolean gTrueBoolean;
#define kOSBooleanTrue (&gTrueBoolean)
#define OSDynamicCast(type, value) dynamic_cast<type *>(value)

class IOEthernetController {
public:
    OSNumber profileEnabled{1};
    OSNumber selected{1};
    OSNumber hostTxBlocked{1};
    bool observationOnly = true;

    OSObject *getProperty(const char *name)
    {
        if (std::strcmp(name, "NativeP2PRx149ObservationOnly") == 0)
            return observationOnly ? kOSBooleanTrue : nullptr;
        if (std::strcmp(name, "NativeP2PRx149ProfileEnabled") == 0)
            return &profileEnabled;
        if (std::strcmp(name, "NativeP2PRx149Selected") == 0)
            return &selected;
        if (std::strcmp(name, "NativeP2PRx149HostTxBlocked") == 0)
            return &hostTxBlocked;
        return nullptr;
    }
};

struct ieee80211_channel { uint16_t ieee = 0; };
struct iwx_phy_ctxt {
    uint16_t id = 0;
    uint16_t color = 0;
    ieee80211_channel *channel = nullptr;
};
struct iwx_node {
    iwx_phy_ctxt *in_phyctxt = nullptr;
    struct { ieee80211_channel *ni_chan = nullptr; } in_ni;
};
struct ieee80211com {
    int ic_state = IEEE80211_S_RUN;
    void *ic_bss = nullptr;
    ieee80211_channel ic_channels[197]{};
};
struct iwx_p2p_context {
    bool initialized = true;
    uint8_t mac_state = IWX_P2P_RESOURCE_ACTIVE;
    uint8_t binding_state = IWX_P2P_RESOURCE_ACTIVE;
    bool phy_leased = true;
    uint8_t mac_id = 1;
    uint8_t phy_id = 1;
    uint8_t binding_id = 1;
    uint8_t phy_color = 22;
    uint8_t binding_color = 22;
    uint32_t fw_generation = 40;
};
struct iwx_p2p_roc_state {
    uint32_t token = 70;
    uint32_t fw_generation = 40;
    uint8_t phase = IWX_P2P_ROC_SESSION_ACKED;
    uint8_t phy_id = 1;
    uint16_t phy_color = 22;
    uint8_t station_phy_id = 0;
    uint16_t station_phy_color = 11;
    uint32_t station_epoch = 50;
    void *station_bss = nullptr;
    ieee80211_channel *station_phy_channel = nullptr;
    ieee80211_channel *roc_channel = nullptr;
    bool receive_observation_only = true;
};
struct iwx_softc {
    uint32_t sc_generation = 40;
    uint32_t sc_tx_rate_generation = 50;
    uint32_t sc_flags = 0;
    ieee80211com sc_ic{};
    iwx_p2p_context sc_p2p{};
    iwx_p2p_roc_state sc_p2p_roc{};
    iwx_phy_ctxt sc_phyctxt[IWX_NUM_PHY_CTX]{};
};

static uint32_t gChannelLookups = 0;
static unsigned ieee80211_chan2ieee(ieee80211com *, ieee80211_channel *channel)
{
    ++gChannelLookups;
    return channel ? channel->ieee : 0;
}

struct SessionReducerStub {
    IntelROCEvent::SessionSnapshot value{};
    IntelROCEvent::SessionSnapshot snapshot() const { return value; }
};
struct RxTimelineStub {
    NativeAwdlRxTrace::Snapshot value{};
    NativeAwdlRxTrace::Snapshot snapshot() const { return value; }
};

class ItlIwx {
public:
    IntelP2PRx::LeaseSnapshot tahoe_p2p_rx_lease_{};
    uint32_t nativeP2pProbeGeneration_ = 70;
    uint32_t nativeP2pRocGeneration_ = 70;
    uint32_t nativeP2pManualArmRequested_ =
        NativeP2PRx149Observation::kRx149ArmMode;
    void *nativeP2pProbeOwner_ = nullptr;
    uint32_t nativeP2pRocChannel_ = 149;
    uint32_t nativeP2pRocDurationMs_ = 100;
    uint64_t nativeAwdlRxEventOwnerSerial_ = 81;
    bool busy_ = true;
    bool mainGate_ = true;
    IOEthernetController *controller_ = nullptr;
    SessionReducerStub nativeP2pRocEvents_{};
    RxTimelineStub nativeAwdlRxEventTimeline_{};

    IOEthernetController *tahoeP2pController() { return controller_; }
    bool nativeP2pBusy() const { return busy_; }
    bool tahoeP2pOnMainGate() const { return mainGate_; }
    bool tahoeP2pCurrentRxDiagnosticEpochs(
        iwx_softc *, NativeAwdlRxEntry::Epochs *);
};

static uint64_t gNowUs = 1000050;
static uint64_t tahoeP2pRxMonotonicUs() { return gNowUs; }

@@ACTUAL_FUNCTIONS@@

static unsigned glueChecks = 0;
static void check(bool condition, const char *name)
{
    ++glueChecks;
    if (!condition) {
        std::fprintf(stderr, "FAIL glue: %s\n", name);
        std::abort();
    }
}

struct Fixture {
    ItlIwx owner{};
    IOEthernetController controller{};
    iwx_softc sc{};
    iwx_node station{};
    NativeAwdlRxEntry::Epochs output{};

    void setup(uint32_t configuration =
                   IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV)
    {
        owner.controller_ = &controller;
        for (unsigned i = 0; i < nitems(sc.sc_ic.ic_channels); ++i)
            sc.sc_ic.ic_channels[i].ieee = static_cast<uint16_t>(i);
        sc.sc_ic.ic_bss = &station;
        station.in_phyctxt = &sc.sc_phyctxt[0];
        station.in_ni.ni_chan = &sc.sc_ic.ic_channels[36];
        sc.sc_phyctxt[0].id = 0;
        sc.sc_phyctxt[0].color = 11;
        sc.sc_phyctxt[0].channel = &sc.sc_ic.ic_channels[36];
        sc.sc_phyctxt[1].id = 1;
        sc.sc_phyctxt[1].color = 22;
        sc.sc_phyctxt[1].channel = &sc.sc_ic.ic_channels[149];

        sc.sc_p2p_roc.station_bss = &station;
        sc.sc_p2p_roc.station_phy_channel = &sc.sc_ic.ic_channels[36];
        sc.sc_p2p_roc.roc_channel = &sc.sc_ic.ic_channels[149];
        sc.sc_p2p_roc.token = 70;
        sc.sc_p2p_roc.phase = IWX_P2P_ROC_SESSION_ACKED;

        auto &lease = owner.tahoe_p2p_rx_lease_;
        lease = {};
        lease.contextGeneration = 70;
        lease.powerGeneration = 40;
        lease.stationGeneration = 50;
        lease.currentContextGeneration = 70;
        lease.currentPowerGeneration = 40;
        lease.currentStationGeneration = 50;
        lease.active = true;

        auto &session = owner.nativeP2pRocEvents_.value;
        session = {};
        session.generation = 70;
        session.configuration = configuration;
        session.commandResult = 0;
        session.startStatus = 1;
        session.startObservedMonotonicUs = 1000000;
        session.commandReturned = true;
        session.startSeen = true;

        auto &trace = owner.nativeAwdlRxEventTimeline_.value;
        trace = {};
        trace.ownerPresent = 1;
        trace.ownerSerial = 81;
        trace.active = 1;
        trace.epochs = {70, 40, 50, 70};

        owner.nativeP2pProbeGeneration_ = 70;
        owner.nativeP2pRocGeneration_ = 70;
        owner.nativeP2pManualArmRequested_ =
            NativeP2PRx149Observation::kRx149ArmMode;
        owner.nativeP2pProbeOwner_ = &owner;
        owner.nativeP2pRocChannel_ = 149;
        owner.nativeP2pRocDurationMs_ = 100;
        owner.nativeAwdlRxEventOwnerSerial_ = 81;
        owner.busy_ = true;
        owner.mainGate_ = true;
        controller.observationOnly = true;
        controller.profileEnabled.value = 1;
        controller.selected.value = 1;
        controller.hostTxBlocked.value = 1;
        sc.sc_generation = 40;
        sc.sc_tx_rate_generation = 50;
        sc.sc_flags = 0;
        sc.sc_p2p.fw_generation = 40;
        sc.sc_p2p_roc.fw_generation = 40;
        sc.sc_p2p_roc.station_epoch = 50;
        output = {901, 902, 903, 904};
        gNowUs = 1000050;
        gChannelLookups = 0;
    }

    bool run()
    {
        return owner.tahoeP2pCurrentRxDiagnosticEpochs(&sc, &output);
    }
};

static void expectResult(const char *name, Fixture &fixture, bool expected)
{
    const auto before = fixture.output;
    const bool actual = fixture.run();
    check(actual == expected, name);
    if (expected) {
        const auto &session = fixture.owner.nativeP2pRocEvents_.value;
        const auto &lease = fixture.owner.tahoe_p2p_rx_lease_;
        check(fixture.output.contextGeneration == lease.contextGeneration,
              "accepted context epoch published");
        check(fixture.output.powerGeneration == lease.powerGeneration,
              "accepted power epoch published");
        check(fixture.output.stationGeneration == lease.stationGeneration,
              "accepted station epoch published");
        check(fixture.output.rocGeneration == session.generation,
              "accepted ROC epoch published");
    } else {
        check(std::memcmp(&fixture.output, &before, sizeof(before)) == 0,
              "rejected call leaves epochs untouched");
    }
}

static void expectCfg3Reject(const char *name, void (*mutate)(Fixture &))
{
    Fixture fixture;
    fixture.setup(IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
    mutate(fixture);
    expectResult(name, fixture, false);
}

int main()
{
    Fixture valid;
    valid.setup();
    const auto session = valid.owner.nativeP2pRocEvents_.snapshot();
    const auto trace = valid.owner.nativeAwdlRxEventTimeline_.snapshot();
    const auto evidence = currentRx149ActionEvidence(
        &valid.owner, &valid.sc, valid.owner.tahoe_p2p_rx_lease_,
        static_cast<uint16_t>(0xffffu), session, trace);
    check(NativeP2PRx149Observation::validStartedOwner(evidence),
          "actual currentRx149ActionEvidence accepts current owner");
    check(!evidence.rxChannel149,
          "out-of-range descriptor index does not claim packet channel 149");
    expectResult("actual cfg2 glue accepts matching RX149 owner", valid, true);
    check(gChannelLookups != 0,
          "cfg2 member glue executes actual RX149 owner function");

    Fixture atStart;
    atStart.setup();
    gNowUs = 1000000;
    expectResult("cfg2 START instant accepted", atStart, true);
    Fixture at99ms;
    at99ms.setup();
    gNowUs = 1099999;
    expectResult("cfg2 99,999us accepted", at99ms, true);
    Fixture at100ms;
    at100ms.setup();
    gNowUs = 1100000;
    expectResult("cfg2 100ms rejected", at100ms, false);
    Fixture preStartTime;
    preStartTime.setup();
    gNowUs = 999999;
    expectResult("cfg2 before START rejected", preStartTime, false);

    Fixture noStart;
    noStart.setup();
    noStart.owner.nativeP2pRocEvents_.value.startSeen = false;
    gNowUs = 1000050;
    expectResult("cfg2 pre-START session rejected", noStart, false);
    Fixture failedStart;
    failedStart.setup();
    failedStart.owner.nativeP2pRocEvents_.value.startStatus = 0;
    expectResult("cfg2 failed START rejected", failedStart, false);
    Fixture ended;
    ended.setup();
    ended.owner.nativeP2pRocEvents_.value.endSeen = true;
    expectResult("cfg2 END session rejected", ended, false);
    Fixture unknown;
    unknown.setup();
    unknown.owner.nativeP2pRocEvents_.value.outcomeUnknown = true;
    expectResult("cfg2 unknown session rejected", unknown, false);

    // These are the historical cfg3 ownerless 900ms checks.
    Fixture cfg3Open;
    cfg3Open.setup(IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
    gNowUs = 1899999;
    expectResult("cfg3 ownerless 899,999us retained", cfg3Open, true);
    check(gChannelLookups == 0, "cfg3 does not evaluate RX149 owner evidence");
    Fixture cfg3Boundary;
    cfg3Boundary.setup(IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
    gNowUs = 1900000;
    expectResult("cfg3 900ms boundary retained", cfg3Boundary, false);

    expectCfg3Reject("common main-gate rejection retained",
        [](Fixture &f) { f.owner.mainGate_ = false; });
    expectCfg3Reject("common inactive-lease rejection retained",
        [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.active = false; });
    expectCfg3Reject("common zero-context rejection retained",
        [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.contextGeneration = 0; });
    expectCfg3Reject("common context-epoch rejection retained",
        [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.currentContextGeneration++; });
    expectCfg3Reject("common owner-generation rejection retained",
        [](Fixture &f) { f.owner.nativeP2pProbeGeneration_++; });
    expectCfg3Reject("common firmware-epoch rejection retained",
        [](Fixture &f) { f.sc.sc_p2p.fw_generation++; });
    expectCfg3Reject("common station-epoch rejection retained",
        [](Fixture &f) { f.sc.sc_tx_rate_generation++; });
    expectCfg3Reject("common zero-ROC-generation rejection retained",
        [](Fixture &f) { f.owner.nativeP2pRocGeneration_ = 0; });
    expectCfg3Reject("common session-generation rejection retained",
        [](Fixture &f) { f.owner.nativeP2pRocEvents_.value.generation++; });
    expectCfg3Reject("common command-return rejection retained",
        [](Fixture &f) { f.owner.nativeP2pRocEvents_.value.commandReturned = false; });
    expectCfg3Reject("common command-result rejection retained",
        [](Fixture &f) { f.owner.nativeP2pRocEvents_.value.commandResult = -1; });
    expectCfg3Reject("common token rejection retained",
        [](Fixture &f) { f.sc.sc_p2p_roc.token++; });
    expectCfg3Reject("common phase rejection retained",
        [](Fixture &f) { f.sc.sc_p2p_roc.phase = 0; });
    Fixture nullSoftc;
    nullSoftc.setup(IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION);
    check(!nullSoftc.owner.tahoeP2pCurrentRxDiagnosticEpochs(
              nullptr, &nullSoftc.output), "common null softc rejected");
    check(!nullSoftc.owner.tahoeP2pCurrentRxDiagnosticEpochs(
              &nullSoftc.sc, nullptr), "common null epoch output rejected");

    // Direct evidence-field changes exercise the real currentRx helper through
    // the actual method, not a duplicated policy predicate.
    Fixture unselected;
    unselected.setup();
    unselected.controller.selected.value = 0;
    expectResult("selected profile is required", unselected, false);
    Fixture profileOff;
    profileOff.setup();
    profileOff.controller.profileEnabled.value = 0;
    expectResult("static RX149 profile is required", profileOff, false);
    Fixture txNotBlocked;
    txNotBlocked.setup();
    txNotBlocked.controller.hostTxBlocked.value = 0;
    expectResult("host TX block property is required", txNotBlocked, false);
    Fixture noObservationProperty;
    noObservationProperty.setup();
    noObservationProperty.controller.observationOnly = false;
    expectResult("observation-only property is required", noObservationProperty, false);
    Fixture wrongArm;
    wrongArm.setup();
    wrongArm.owner.nativeP2pManualArmRequested_ = 1;
    expectResult("arm mode 2 is required", wrongArm, false);
    Fixture receiveOnlyOff;
    receiveOnlyOff.setup();
    receiveOnlyOff.sc.sc_p2p_roc.receive_observation_only = false;
    expectResult("receive-only ROC flag is required", receiveOnlyOff, false);
    Fixture wrongRequestedChannel;
    wrongRequestedChannel.setup();
    wrongRequestedChannel.owner.nativeP2pRocChannel_ = 148;
    expectResult("requested channel 149 is required", wrongRequestedChannel, false);
    Fixture wrongRequestedDuration;
    wrongRequestedDuration.setup();
    wrongRequestedDuration.owner.nativeP2pRocDurationMs_ = 101;
    expectResult("requested 100ms is required", wrongRequestedDuration, false);
    Fixture wrongActualChannel;
    wrongActualChannel.setup();
    wrongActualChannel.sc.sc_p2p_roc.roc_channel =
        &wrongActualChannel.sc.sc_ic.ic_channels[148];
    expectResult("actual ROC channel 149 is required", wrongActualChannel, false);
    Fixture wrongStationColor;
    wrongStationColor.setup();
    wrongStationColor.sc.sc_phyctxt[0].color++;
    expectResult("STA PHY color match is required", wrongStationColor, false);
    Fixture wrongP2pColor;
    wrongP2pColor.setup();
    wrongP2pColor.sc.sc_phyctxt[1].color++;
    expectResult("P2P PHY color match is required", wrongP2pColor, false);
    Fixture wrongBindingColor;
    wrongBindingColor.setup();
    wrongBindingColor.sc.sc_p2p.binding_color++;
    expectResult("binding color match is required", wrongBindingColor, false);
    Fixture wrongBindingId;
    wrongBindingId.setup();
    wrongBindingId.sc.sc_p2p.binding_id++;
    expectResult("binding ID match is required", wrongBindingId, false);
    Fixture staleTraceEpoch;
    staleTraceEpoch.setup();
    staleTraceEpoch.owner.nativeAwdlRxEventTimeline_.value.epochs.powerGeneration++;
    expectResult("trace owner epoch match is required", staleTraceEpoch, false);
    Fixture wrongTraceOwner;
    wrongTraceOwner.setup();
    wrongTraceOwner.owner.nativeAwdlRxEventTimeline_.value.ownerSerial++;
    expectResult("trace owner serial match is required", wrongTraceOwner, false);
    Fixture closedTrace;
    closedTrace.setup();
    closedTrace.owner.nativeAwdlRxEventTimeline_.value.producerClosed = 1;
    expectResult("closed trace owner rejected", closedTrace, false);
    Fixture notBusy;
    notBusy.setup();
    notBusy.owner.busy_ = false;
    expectResult("current busy owner is required", notBusy, false);
    Fixture noProbeOwner;
    noProbeOwner.setup();
    noProbeOwner.owner.nativeP2pProbeOwner_ = nullptr;
    expectResult("current probe owner pointer is required", noProbeOwner, false);

    std::printf("PASS glue: %u checks (current production helper + member)\n",
                glueChecks);
    return 0;
}
'''


def compile_and_run(compiler: str, source: str, output: Path,
                    include_root: Path, feature_on: bool) -> str:
    source_path = output.with_suffix(".cpp")
    source_path.write_text(source, encoding="utf-8")
    command = [
        compiler,
        "-std=c++14",
        "-O1",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-parameter",
        "-Wno-unused-function",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-sanitize-recover=all",
        "-I",
        str(include_root),
    ]
    if feature_on:
        command.append(f"-D{FEATURE}=1")
    command.extend([str(source_path), "-o", str(output)])
    build = subprocess.run(command, capture_output=True, text=True)
    if build.returncode:
        raise RuntimeError(
            "compile failed:\n" + " ".join(command) + "\n" +
            build.stdout + build.stderr
        )
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    run = subprocess.run([str(output)], capture_output=True, text=True,
                         env=environment)
    if run.returncode:
        raise RuntimeError(f"sanitized harness failed:\n{run.stdout}{run.stderr}")
    return run.stdout.strip()


def main() -> int:
    source = RX.read_text(encoding="utf-8")
    source_contracts(source)
    compiler = os.environ.get("CXX") or shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ not found")

    window_functions = "\n\n".join(
        extract_function(source, marker)
        for marker in (
            "static bool withinRx149DiagnosticWindow(",
            "static bool rxDiagnosticSessionWindowQualified(",
        )
    )
    window_results = []
    glue_result = ""
    with tempfile.TemporaryDirectory(prefix="test084-rx-owner-source-") as tmp:
        temp = Path(tmp)
        for feature_on in (False, True):
            harness = WINDOW_HARNESS.replace("@@EXTRACTED_HELPERS@@", window_functions)
            binary = temp / ("window-feature-on" if feature_on else "window-feature-off")
            window_results.append(
                compile_and_run(compiler, harness, binary, ROOT, feature_on)
            )

        actual_functions = "\n\n".join(
            extract_function(source, marker)
            for marker in (
                "bool rx149PropertyIsOne(",
                "bool rx149StationAndPhyOwnerCurrent(",
                "NativeP2PRx149Observation::RocEvidence currentRx149ActionEvidence(",
                "static bool withinRx149DiagnosticWindow(",
                "static bool rxDiagnosticSessionWindowQualified(",
                "bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs(",
            )
        )
        glue_source = GLUE_HARNESS.replace("@@ACTUAL_FUNCTIONS@@", actual_functions)
        glue_binary = temp / "actual-glue-feature-on"
        glue_result = compile_and_run(
            compiler, glue_source, glue_binary, ROOT, feature_on=True
        )

    window_counts = [
        int(re.search(r"PASS: (\d+) checks", result).group(1))
        for result in window_results
    ]
    if window_counts != [9, 29] or sum(window_counts) != 38:
        raise AssertionError(f"expected retained 9+29=38 checks, got {window_counts}")
    glue_match = re.search(r"PASS glue: (\d+) checks", glue_result)
    if not glue_match:
        raise AssertionError(f"missing glue harness receipt: {glue_result}")

    PREP.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(PREP, 0o700)
    created = datetime.now(timezone.utc)
    receipt = {
        "created_utc": created.isoformat(),
        "branch": subprocess.run(
            ["git", "branch", "--show-current"], cwd=ROOT,
            check=True, capture_output=True, text=True
        ).stdout.strip(),
        "current_production_source_sha256": sha256(RX),
        "test_sha256": sha256(Path(__file__)),
        "production_source_read_only": True,
        "source_patch_application": False,
        "legacy_083_sha_gate": False,
        "retained_window_contract_checks": window_counts,
        "retained_window_contract_total": sum(window_counts),
        "actual_production_glue": [
            "rx149PropertyIsOne",
            "rx149StationAndPhyOwnerCurrent",
            "currentRx149ActionEvidence",
            "withinRx149DiagnosticWindow",
            "rxDiagnosticSessionWindowQualified",
            "tahoeP2pCurrentRxDiagnosticEpochs",
        ],
        "actual_glue_harness": glue_result,
        "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"],
        "compiler": compiler,
        "kernel_build_or_rf_tested": False,
    }
    receipt_path = PREP / (
        "rx-owner-telemetry-production-source-receipt-" +
        created.strftime("%Y%m%dT%H%M%SZ") + "-private.json"
    )
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    os.chmod(receipt_path, 0o600)
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
