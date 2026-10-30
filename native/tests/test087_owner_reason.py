#!/usr/bin/env python3
"""Differentially verify Test087 owner-reason reporting against frozen bool behavior."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
RX_CPP = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"
LEGACY_FIXTURE = Path(__file__).with_name("test087_owner_reason_legacy.inc")
LEGACY_SHA256 = "c5aeed4924451246dd66dd2c0cf68810d76675fe105804aaffd1664caf29df2c"


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif ((state == "string" and char == '"') or
                  (state == "char" and char == "'")):
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block"
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
    raise AssertionError(f"unterminated function: {marker}")


HARNESS = r'''#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <vector>

#include "native/awdl_rx_entry_telemetry.hpp"
#include "native/intel_roc_event_state.hpp"
#include "native/p2p_rx149_observation.hpp"
#include "native/rx_preowner_observation.hpp"

#define IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION 3
#define IWX_P2P_ROC_SESSION_ACKED 8

template <typename T> struct Tracked {
    T value{};
    uint32_t *reads = nullptr;
    Tracked() = default;
    Tracked(T initial) : value(initial) {}
    operator T() const {
        if (reads) ++*reads;
        return value;
    }
};

namespace IntelP2PRx {
struct LeaseSnapshot {
    Tracked<bool> active;
    Tracked<uint64_t> contextGeneration;
    Tracked<uint64_t> powerGeneration;
    Tracked<uint64_t> stationGeneration;
    Tracked<uint64_t> currentContextGeneration;
    Tracked<uint64_t> currentPowerGeneration;
    Tracked<uint64_t> currentStationGeneration;
};
}

struct iwx_softc {
    uint32_t sc_generation = 9;
    uint32_t sc_tx_rate_generation = 11;
    struct { uint32_t fw_generation = 9; } sc_p2p;
    struct { uint32_t token = 7; uint8_t phase = IWX_P2P_ROC_SESSION_ACKED; }
        sc_p2p_roc;
};

struct SessionReducerStub {
    IntelROCEvent::SessionSnapshot value{};
    uint32_t calls = 0;
    IntelROCEvent::SessionSnapshot snapshot() {
        ++calls;
        return value;
    }
};

static uint32_t *gClockReads = nullptr;
static uint64_t gNowUs = 1001;
static uint64_t tahoeP2pRxMonotonicUs() {
    if (gClockReads) ++*gClockReads;
    return gNowUs;
}

class ItlIwx {
public:
    IntelP2PRx::LeaseSnapshot tahoe_p2p_rx_lease_{};
    uint32_t nativeP2pProbeGeneration_ = 7;
    uint32_t nativeP2pRocGeneration_ = 7;
    SessionReducerStub nativeP2pRocEvents_{};
    bool mainGate_ = true;
    uint32_t gateCalls = 0;
    bool tahoeP2pOnMainGate() {
        ++gateCalls;
        return mainGate_;
    }
    bool tahoeP2pCurrentRxDiagnosticEpochs(
        struct iwx_softc *, NativeAwdlRxEntry::Epochs *, uint32_t * = nullptr);
    bool legacyCurrentRxDiagnosticEpochs(
        struct iwx_softc *, NativeAwdlRxEntry::Epochs *);
};

struct Fixture {
    ItlIwx owner{};
    iwx_softc sc{};
    NativeAwdlRxEntry::Epochs output{91, 92, 93, 94};
    uint32_t leaseReads = 0;
    uint32_t clockReads = 0;
    bool nullSoftc = false;
    bool nullEpochs = false;

    Fixture() { reset(); }

    void bindLeaseReadCounter() {
        auto &l = owner.tahoe_p2p_rx_lease_;
        l.active.reads = &leaseReads;
        l.contextGeneration.reads = &leaseReads;
        l.powerGeneration.reads = &leaseReads;
        l.stationGeneration.reads = &leaseReads;
        l.currentContextGeneration.reads = &leaseReads;
        l.currentPowerGeneration.reads = &leaseReads;
        l.currentStationGeneration.reads = &leaseReads;
    }

    void reset() {
        leaseReads = clockReads = 0;
        nullSoftc = nullEpochs = false;
        owner = ItlIwx{};
        sc = iwx_softc{};
        auto &l = owner.tahoe_p2p_rx_lease_;
        l.active.value = true;
        l.contextGeneration.value = 7;
        l.powerGeneration.value = 9;
        l.stationGeneration.value = 11;
        l.currentContextGeneration.value = 7;
        l.currentPowerGeneration.value = 9;
        l.currentStationGeneration.value = 11;
        bindLeaseReadCounter();
        auto &s = owner.nativeP2pRocEvents_.value;
        s = {};
        s.generation = 7;
        s.configuration = IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION;
        s.commandResult = 0;
        s.startStatus = 1;
        s.startObservedMonotonicUs = 1000;
        s.commandReturned = true;
        s.startSeen = true;
        owner.nativeP2pProbeGeneration_ = 7;
        owner.nativeP2pRocGeneration_ = 7;
        owner.mainGate_ = true;
        owner.gateCalls = 0;
        output = {91, 92, 93, 94};
        gNowUs = 1001;
    }

    iwx_softc *softc() { return nullSoftc ? nullptr : &sc; }
    NativeAwdlRxEntry::Epochs *epochs() {
        return nullEpochs ? nullptr : &output;
    }
};

static bool testSameEpochs(const NativeAwdlRxEntry::Epochs &a,
                           const NativeAwdlRxEntry::Epochs &b) {
    return a.contextGeneration == b.contextGeneration &&
           a.powerGeneration == b.powerGeneration &&
           a.stationGeneration == b.stationGeneration &&
           a.rocGeneration == b.rocGeneration;
}
static unsigned gChecks = 0;
static void check(bool condition, const char *name) {
    ++gChecks;
    if (!condition) {
        std::fprintf(stderr, "FAIL Test087: %s\n", name);
        std::abort();
    }
}

@@HELPERS_AND_FUNCTIONS@@

struct Scenario {
    const char *name;
    NativeRxPreOwner::OwnerReason reason;
    bool eligible;
    std::function<void(Fixture &)> mutate;
};

static void compareScenario(const Scenario &test) {
    Fixture legacy, withReason, nullReason;
    test.mutate(legacy);
    test.mutate(withReason);
    test.mutate(nullReason);
    const auto legacyInitial = legacy.output;
    const auto currentInitial = withReason.output;
    const auto nullInitial = nullReason.output;

    gClockReads = &legacy.clockReads;
    const bool oldResult = legacy.owner.legacyCurrentRxDiagnosticEpochs(
        legacy.softc(), legacy.epochs());
    const uint32_t oldGateCalls = legacy.owner.gateCalls;
    const uint32_t oldLeaseReads = legacy.leaseReads;
    const uint32_t oldSnapshots = legacy.owner.nativeP2pRocEvents_.calls;
    const uint32_t oldClockReads = legacy.clockReads;

    uint32_t reason = 0xffffffffu;
    gClockReads = &withReason.clockReads;
    const bool newResult = withReason.owner.tahoeP2pCurrentRxDiagnosticEpochs(
        withReason.softc(), withReason.epochs(), &reason);
    const uint32_t newGateCalls = withReason.owner.gateCalls;
    const uint32_t newLeaseReads = withReason.leaseReads;
    const uint32_t newSnapshots = withReason.owner.nativeP2pRocEvents_.calls;
    const uint32_t newClockReads = withReason.clockReads;

    gClockReads = &nullReason.clockReads;
    const bool noReasonResult =
        nullReason.owner.tahoeP2pCurrentRxDiagnosticEpochs(
            nullReason.softc(), nullReason.epochs());
    const uint32_t noReasonGateCalls = nullReason.owner.gateCalls;
    const uint32_t noReasonLeaseReads = nullReason.leaseReads;
    const uint32_t noReasonSnapshots = nullReason.owner.nativeP2pRocEvents_.calls;
    const uint32_t noReasonClockReads = nullReason.clockReads;
    gClockReads = nullptr;

    check(oldResult == test.eligible, test.name);
    check(newResult == oldResult, "reason-enabled bool differential");
    check(noReasonResult == oldResult, "null-reason bool differential");
    check(reason == static_cast<uint32_t>(test.reason), "first failure reason");
    check(oldGateCalls == newGateCalls && oldGateCalls == noReasonGateCalls,
          "gate call order unchanged");
    check(oldLeaseReads == newLeaseReads && oldLeaseReads == noReasonLeaseReads,
          "lease read order/count unchanged");
    check(oldSnapshots == newSnapshots && oldSnapshots == noReasonSnapshots,
          "ROC snapshot order/count unchanged");
    check(oldClockReads == newClockReads && oldClockReads == noReasonClockReads,
          "host clock read order/count unchanged");
    check(testSameEpochs(legacy.output, withReason.output) &&
          testSameEpochs(legacy.output, nullReason.output), "epoch output differential");
    if (!oldResult) {
        check(testSameEpochs(legacyInitial, legacy.output) &&
              testSameEpochs(currentInitial, withReason.output) &&
              testSameEpochs(nullInitial, nullReason.output),
              "failure leaves epoch output untouched");
    } else {
        check(withReason.output.contextGeneration == 7 &&
              withReason.output.powerGeneration == 9 &&
              withReason.output.stationGeneration == 11 &&
              withReason.output.rocGeneration == 7,
              "qualified epochs are unchanged");
    }
    if (test.reason == NativeRxPreOwner::OwnerReason::MainGate) {
        check(newLeaseReads == 0 && newSnapshots == 0 && newClockReads == 0,
              "main-gate rejection does not read lease or later gates");
    }
    if (test.reason == NativeRxPreOwner::OwnerReason::InvalidInput) {
        check(newGateCalls == 0 && newLeaseReads == 0,
              "invalid inputs short-circuit before main gate and lease");
    }
}

int main() {
    using R = NativeRxPreOwner::OwnerReason;
    const std::vector<Scenario> cases = {
        {"null softc", R::InvalidInput, false, [](Fixture &f) { f.nullSoftc = true; f.owner.mainGate_ = false; }},
        {"null epochs", R::InvalidInput, false, [](Fixture &f) { f.nullEpochs = true; f.owner.mainGate_ = false; }},
        {"main gate precedes lease", R::MainGate, false, [](Fixture &f) { f.owner.mainGate_ = false; f.owner.tahoe_p2p_rx_lease_.active.value = false; }},
        {"inactive lease precedes epoch zero", R::LeaseInactive, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.active.value = false; f.owner.tahoe_p2p_rx_lease_.contextGeneration.value = 0; }},
        {"context zero precedes power zero", R::LeaseContextZero, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.contextGeneration.value = 0; f.owner.tahoe_p2p_rx_lease_.powerGeneration.value = 0; }},
        {"power zero precedes station zero", R::LeasePowerZero, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.powerGeneration.value = 0; f.owner.tahoe_p2p_rx_lease_.stationGeneration.value = 0; }},
        {"station zero precedes context-current mismatch", R::LeaseStationZero, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.stationGeneration.value = 0; f.owner.tahoe_p2p_rx_lease_.currentContextGeneration.value++; }},
        {"context-current precedes probe mismatch", R::LeaseContextMismatchCurrent, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.currentContextGeneration.value++; f.owner.nativeP2pProbeGeneration_++; }},
        {"context-probe mismatch", R::LeaseContextMismatchProbe, false, [](Fixture &f) { f.owner.nativeP2pProbeGeneration_++; }},
        {"lease-power current mismatch precedes sc generation", R::LeasePowerMismatchLeaseCurrent, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.currentPowerGeneration.value++; f.sc.sc_generation++; }},
        {"lease-station current mismatch", R::LeaseStationMismatchLeaseCurrent, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.currentStationGeneration.value++; }},
        {"sc power mismatch precedes firmware mismatch", R::PowerMismatchScGeneration, false, [](Fixture &f) { f.sc.sc_generation++; f.sc.sc_p2p.fw_generation++; }},
        {"firmware mismatch precedes sc station mismatch", R::PowerMismatchFwGeneration, false, [](Fixture &f) { f.sc.sc_p2p.fw_generation++; f.sc.sc_tx_rate_generation++; }},
        {"sc station generation mismatch", R::StationMismatchScGeneration, false, [](Fixture &f) { f.sc.sc_tx_rate_generation++; }},
        {"zero ROC precedes snapshot", R::RocMissing, false, [](Fixture &f) { f.owner.nativeP2pRocGeneration_ = 0; f.owner.nativeP2pRocEvents_.value.generation++; }},
        {"session generation lease mismatch", R::RocGenerationMismatchLease, false, [](Fixture &f) { f.owner.tahoe_p2p_rx_lease_.contextGeneration.value = 8; f.owner.tahoe_p2p_rx_lease_.currentContextGeneration.value = 8; f.owner.nativeP2pProbeGeneration_ = 8; }},
        {"session generation current mismatch", R::RocGenerationMismatchCurrent, false, [](Fixture &f) { f.owner.nativeP2pRocGeneration_ = 8; }},
        {"command pending precedes command failure", R::RocCommandPending, false, [](Fixture &f) { f.owner.nativeP2pRocEvents_.value.commandReturned = false; f.owner.nativeP2pRocEvents_.value.commandResult = -1; }},
        {"command failure precedes window", R::RocCommandFailed, false, [](Fixture &f) { f.owner.nativeP2pRocEvents_.value.commandResult = -1; f.owner.nativeP2pRocEvents_.value.startSeen = false; }},
        {"window rejection precedes token", R::RocWindowNotQualified, false, [](Fixture &f) { f.owner.nativeP2pRocEvents_.value.startSeen = false; f.sc.sc_p2p_roc.token++; }},
        {"token mismatch precedes phase", R::RocTokenMismatch, false, [](Fixture &f) { f.sc.sc_p2p_roc.token++; f.sc.sc_p2p_roc.phase = 0; }},
        {"phase mismatch", R::RocPhaseNotAcked, false, [](Fixture &f) { f.sc.sc_p2p_roc.phase = 0; }},
        {"qualified", R::Qualified, true, [](Fixture &) {}},
    };
    for (const auto &test : cases) compareScenario(test);
    check(gChecks > 0, "checks executed");
    std::printf("PASS Test087 owner reason: %u checks, %zu differential cases\n",
                gChecks, cases.size());
    return 0;
}
'''


def main() -> None:
    fixture = LEGACY_FIXTURE.read_bytes()
    if hashlib.sha256(fixture).hexdigest() != LEGACY_SHA256:
        raise AssertionError("Test087 frozen legacy bool oracle changed")
    source = RX_CPP.read_text()
    current = extract_function(
        source, "bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs("
    )
    legacy_text = fixture.decode("utf-8")
    legacy = extract_function(
        legacy_text, "bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs("
    )
    legacy = legacy.replace(
        "ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs(",
        "ItlIwx::legacyCurrentRxDiagnosticEpochs(", 1,
    )
    helpers = "\n\n".join(
        extract_function(source, marker)
        for marker in (
            "static bool withinRx149DiagnosticWindow(",
            "static bool rxDiagnosticSessionWindowQualified(",
        )
    )
    combined = "\n\n".join((helpers, legacy, current))
    program = HARNESS.replace("@@HELPERS_AND_FUNCTIONS@@", combined)
    compiler = shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        raise RuntimeError("clang++ or c++ is required for Test087 host harness")
    with tempfile.TemporaryDirectory(prefix="test087-owner-reason-") as tmp:
        binary = Path(tmp) / "test087-owner-reason"
        command = [
            compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-function", "-Wno-unused-variable", "-I", str(ROOT),
            "-x", "c++", "-",
            "-o", str(binary),
        ]
        built = subprocess.run(
            command, input=program, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if built.returncode:
            raise RuntimeError(built.stdout)
        executed = subprocess.run(
            [str(binary)], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if executed.returncode:
            raise RuntimeError(executed.stdout)
        print(executed.stdout, end="")


if __name__ == "__main__":
    main()
