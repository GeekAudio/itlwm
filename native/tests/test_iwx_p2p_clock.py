#!/usr/bin/env python3
"""Compile and exercise the production GP2 gate callback with mock IOKit/Intel.

The harness extracts the current callback and wrapper bodies verbatim. Mock
register and clock calls are in-process only; this test never opens hardware.
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PClock.cpp"
SAMPLER = ROOT / "native/intel_gp2_sampler.cpp"
TX_RESOURCES = ROOT / "native/p2p_tx_resources.cpp"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_wrapper(source: str) -> str:
    marker = "void ItlIwx::tahoeP2pObserveGp2("
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise RuntimeError("unterminated production tahoeP2pObserveGp2 wrapper")


HARNESS = r'''#include <cassert>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "intel_gp2_sampler.hpp"
#include "p2p_action_tx.hpp"
#include "p2p_tx_resources.hpp"

using IOReturn = int32_t;
using thread_t = uintptr_t;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnError = -1;
constexpr IOReturn kIOReturnNotReady = -2;
constexpr IOReturn kIOReturnBadArgument = -3;
constexpr IOReturn kIOReturnUnsupported = -4;
constexpr IOReturn kIOReturnBusy = -5;
constexpr int IEEE80211_S_RUN = 4;
constexpr uint32_t IWX_FLAG_SHUTDOWN = 1u << 0;
constexpr uint32_t IWX_FLAG_HW_ERR = 1u << 1;
constexpr uint32_t IWX_P2P_RESOURCE_ABSENT = 0;
constexpr uint32_t IWX_DEVICE_FAMILY_22000 = 1;
constexpr uint32_t IWX_DEVICE_FAMILY_AX210 = 2;
constexpr int IWX_CSR_GP_CNTRL = 0x24;
constexpr uint32_t IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ = 0x08;
constexpr uint32_t IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY = 0x01;
constexpr uint32_t IWX_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP = 0x10;
constexpr uint32_t IWX_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN = 0x01;
static std::vector<std::string> gTrace;
static uint32_t gDelayTotalUs = 0;

using IOInterruptState = unsigned;
struct IOSimpleLock { bool held = false; };
IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    assert(lock && !lock->held);
    lock->held = true;
    gTrace.push_back("resource-lock");
    return 1;
}
void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock, IOInterruptState) {
    assert(lock && lock->held);
    lock->held = false;
    gTrace.push_back("resource-unlock");
}

struct OSObject {};
struct OSBoolean {};
static OSBoolean gTrueObject;
static OSBoolean *kOSBooleanTrue = &gTrueObject;

struct MockWorkLoop {
    bool gate = true;
    bool thread = false;
    bool inGate() const { return gate; }
    bool onThread() const { return thread; }
};

struct MockController {
    std::map<std::string, bool> flags;
    std::map<std::string, uint64_t> values;
    std::map<std::string, uint32_t> widths;
    const OSBoolean *getProperty(const char *key) const {
        auto it = flags.find(key);
        return it != flags.end() && it->second ? kOSBooleanTrue : nullptr;
    }
    bool setProperty(const char *key, uint64_t value, uint32_t width) {
        values[key] = value;
        widths[key] = width;
        return true;
    }
};

struct MockP2pState {
    uint32_t mac_state = IWX_P2P_RESOURCE_ABSENT;
    uint32_t binding_state = IWX_P2P_RESOURCE_ABSENT;
    bool phy_leased = false;
};
struct MockInterfaceState { int ic_state = IEEE80211_S_RUN; };
struct iwx_softc {
    uint32_t sc_generation = 12;
    uint32_t sc_tx_rate_generation = 34;
    int sc_nic_locks = 0;
    uint32_t gpCntrl = 0;
    unsigned setRequestCalls = 0;
    unsigned clearRequestCalls = 0;
    MockInterfaceState sc_ic;
    uint32_t sc_flags = 0;
    MockP2pState sc_p2p;
    uint32_t sc_device_family = 2;
};
static void mockClearBits(iwx_softc *, int, uint32_t);

enum class TahoeP2PActionTxState : uint8_t { kIdle, kBusy };
enum class TahoeP2PResourceState : uint8_t { kAbsent, kPresent };
struct MockTicket {
    bool armed = false;
    bool completed = false;
};
struct MockCompletionTracker {
    MockTicket ticket;
    MockTicket snapshot() const { return ticket; }
};
struct MockActionTx {
    TahoeP2PActionTxState state = TahoeP2PActionTxState::kIdle;
    MockCompletionTracker completion;
};
struct MockQueueLifecycle {
    IntelP2PTx::QueueSnapshot current{};
    IntelP2PTx::QueueSnapshot snapshot() const { return current; }
};
struct MockTxQueue {
    TahoeP2PResourceState state = TahoeP2PResourceState::kAbsent;
    void *pendingRing = nullptr;
    bool submissionBusy = false;
    MockQueueLifecycle lifecycle;
};
struct MockStation {
    TahoeP2PResourceState state = TahoeP2PResourceState::kAbsent;
};
struct MockStationRegistry {
    IntelP2PTx::StationSnapshot current{};
    IntelP2PTx::StationSnapshot snapshot() const { return current; }
};

struct MockCommandGate {
    MockWorkLoop *loop = nullptr;
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    unsigned calls = 0;
    IOReturn last = kIOReturnNotReady;
    IOReturn runAction(Action action, void *context) {
        ++calls;
        bool previous = loop->gate;
        loop->gate = true;
        last = action(nullptr, context, nullptr, nullptr, nullptr);
        loop->gate = previous;
        return last;
    }
};

struct ItlIwx {
    MockWorkLoop *loop = nullptr;
    MockCommandGate *gate = nullptr;
    MockController *controller = nullptr;
    iwx_softc com;
    uint32_t nativeP2pProbeGeneration_ = 56;
    unsigned busy = 1;
    void *nativeP2pProbeOwner_ = nullptr;
    unsigned nativeP2pCancelRequested_ = 0;
    unsigned nativeP2pNswqPaused_ = 1;
    MockActionTx nativeP2pActionTx_;
    MockTxQueue nativeP2pTxQueue_;
    MockStation nativeP2pStation_;
    MockStationRegistry nativeP2pStationRegistry_;
    IOSimpleLock txLock_;
    IOSimpleLock *nativeP2pTxLock_ = nullptr;
    bool nicLockAvailable = true;
    bool nicLocked = false;
    unsigned lockCalls = 0;
    unsigned unlockCalls = 0;
    unsigned readCalls = 0;
    bool mutateStationGenerationOnRead = false;
    uint32_t readAddress = 0;
    uint32_t readValue = 0x12345678;
    unsigned pollTimeoutUs = 0;

    MockCommandGate *getMainCommandGate() { return gate; }
    MockWorkLoop *getMainWorkLoop() { return loop; }
    MockController *tahoeP2pController() { return controller; }
    bool tahoeP2pOnMainGate() { return loop && loop->inGate(); }
    bool nativeP2pBusy() { return busy != 0; }
    void iwx_nic_assert_locked(iwx_softc *sc) { assert(sc && sc->sc_nic_locks > 0); }
    int iwx_poll_bit(iwx_softc *sc, int reg, uint32_t bits, uint32_t mask,
                     int timeout) {
        assert(sc && reg == IWX_CSR_GP_CNTRL);
        assert(bits == IWX_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN);
        assert(mask == (IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
                        IWX_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP));
        assert(timeout > 0);
        ++lockCalls;
        pollTimeoutUs = static_cast<unsigned>(timeout);
        gTrace.push_back("poll");
        if (!nicLockAvailable)
            gDelayTotalUs += static_cast<unsigned>(timeout);
        else
            nicLocked = true;
        return nicLockAvailable ? 1 : 0;
    }
    void iwx_nic_unlock(iwx_softc *) {
        assert(com.sc_nic_locks > 0);
        --com.sc_nic_locks;
        nicLocked = com.sc_nic_locks > 0;
        if (com.sc_nic_locks == 0)
            mockClearBits(&com, IWX_CSR_GP_CNTRL,
                          IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
        ++unlockCalls;
        gTrace.push_back("unlock");
    }
    uint32_t iwx_read_prph(iwx_softc *, uint32_t address) {
        assert(com.sc_nic_locks > 0);
        ++readCalls;
        readAddress = address;
        gTrace.push_back("read");
        if (mutateStationGenerationOnRead)
            ++com.sc_tx_rate_generation;
        return readValue;
    }
    void tahoeP2pObserveGp2(uint32_t, uint32_t, uint32_t, uint32_t);
};

static void mockSetBits(iwx_softc *sc, int reg, uint32_t mask) {
    assert(sc && reg == IWX_CSR_GP_CNTRL);
    ++sc->setRequestCalls;
    sc->gpCntrl |= mask;
    gTrace.push_back("request");
}
static void mockClearBits(iwx_softc *sc, int reg, uint32_t mask) {
    assert(sc && reg == IWX_CSR_GP_CNTRL);
    if (mask == IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ)
        ++sc->clearRequestCalls;
    sc->gpCntrl &= ~mask;
    gTrace.push_back("clear");
}
static void mockDelay(unsigned usec) {
    gDelayTotalUs += usec;
    gTrace.push_back("delay");
}
#define IWX_SETBITS(sc, reg, mask) mockSetBits((sc), (reg), (mask))
#define IWX_CLRBITS(sc, reg, mask) mockClearBits((sc), (reg), (mask))
#define DELAY(usec) mockDelay(static_cast<unsigned>(usec))

static uint64_t gHostNanoseconds[2] = {1000000000ULL, 1000100000ULL};
static unsigned gHostIndex = 0;
static thread_t gThread = 0x5151;
thread_t current_thread() { return gThread; }
void clock_get_uptime(uint64_t *absolute) {
    gTrace.push_back("host");
    unsigned i = gHostIndex < 2 ? gHostIndex++ : 1;
    *absolute = gHostNanoseconds[i];
}
void absolutetime_to_nanoseconds(uint64_t absolute, uint64_t *nanoseconds) {
    *nanoseconds = absolute;
}

static void resetClock(uint64_t before = 1000000000ULL,
                       uint64_t after = 1000100000ULL) {
    gTrace.clear();
    gDelayTotalUs = 0;
    gHostNanoseconds[0] = before;
    gHostNanoseconds[1] = after;
    gHostIndex = 0;
}

// BEGIN_EXTRACTED_PRODUCTION_CLOCK_CALLBACKS
__CLOCK_CALLBACKS__
// END_EXTRACTED_PRODUCTION_CLOCK_CALLBACKS

// BEGIN_EXTRACTED_PRODUCTION_CLOCK_WRAPPER
__CLOCK_WRAPPER__
// END_EXTRACTED_PRODUCTION_CLOCK_WRAPPER

struct Fixture {
    MockWorkLoop loop;
    MockCommandGate gate;
    MockController controller;
    ItlIwx owner;
    ClockRequest request{};
};

static void initialize(Fixture &f, uint32_t phase = 0) {
    f.loop = {};
    f.gate.loop = &f.loop;
    f.gate.calls = 0;
    f.gate.last = kIOReturnNotReady;
    f.controller = {};
    const char *keys[] = {"NativeP2PGp2Observation", "NativeP2PProbe",
        "NativeP2PRocProbe", "NativeP2PTxProbe", "NativeP2PManualTrigger",
        "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup"};
    for (const char *key : keys) f.controller.flags[key] = true;
    f.owner = {};
    f.owner.loop = &f.loop;
    f.owner.gate = &f.gate;
    f.owner.controller = &f.controller;
    f.owner.nativeP2pTxLock_ = &f.owner.txLock_;
    f.owner.nativeP2pProbeOwner_ = reinterpret_cast<void *>(gThread);
    f.owner.com.sc_device_family = static_cast<uint32_t>(
        IntelGp2Clock::SamplerDeviceFamily::kAx210);
    f.request = {&f.owner, gThread, 56, 12, 34, phase};
    resetClock();
}

static IOReturn invoke(Fixture &f) {
    return observeClockOnGate(nullptr, &f.request, nullptr, nullptr, nullptr);
}

static void assertNoHardware(const Fixture &f) {
    assert(f.owner.lockCalls == 0);
    assert(f.owner.unlockCalls == 0);
    assert(f.owner.readCalls == 0);
    assert(f.owner.com.sc_nic_locks == 0);
    assert((f.owner.com.gpCntrl & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0);
    assert(!f.owner.txLock_.held);
}

static void testSuccessAndPhases() {
    Fixture f;
    initialize(f, 0);
    assert(invoke(f) == kIOReturnSuccess);
    assert(f.controller.values["NativeP2PGp2PreStatus"] == 1);
    assert(f.controller.values["NativeP2PGp2PreValue"] == 0x12345678);
    assert(f.controller.values["NativeP2PGp2PreHostBeforeUs"] == 1000000);
    assert(f.controller.values["NativeP2PGp2PreHostAfterUs"] == 1000100);
    assert(f.controller.values["NativeP2PGp2PreGeneration"] == 56);
    assert(f.controller.values["NativeP2PGp2PrphAddress"] == 0x00d02c68);
    assert(f.controller.values["NativeP2PGp2DeviceFamily"] == 2);
    assert(f.controller.values["NativeP2PGp2MappingProven"] == 0);
    assert(f.controller.values["NativeP2PGp2DriftBoundProven"] == 0);
    assert(f.owner.lockCalls == 1 && f.owner.unlockCalls == 1);
    assert(f.owner.readCalls == 1 && f.owner.readAddress == 0x00d02c68);
    assert((gTrace == std::vector<std::string>{"resource-lock", "resource-unlock",
        "request", "delay", "poll", "host", "read", "host", "clear", "unlock"}));
    assert(f.owner.com.sc_nic_locks == 0 && !f.owner.nicLocked);
    assert(f.owner.com.setRequestCalls == 1 && f.owner.com.clearRequestCalls == 1);
    assert(f.owner.pollTimeoutUs == 1980 && gDelayTotalUs == 2);

    initialize(f, 1);
    f.owner.com.sc_device_family = static_cast<uint32_t>(
        IntelGp2Clock::SamplerDeviceFamily::kFamily22000);
    f.owner.readValue = 0x87654321;
    assert(invoke(f) == kIOReturnSuccess);
    assert(f.controller.values["NativeP2PGp2PostStatus"] == 1);
    assert(f.controller.values["NativeP2PGp2PostValue"] == 0x87654321);
    assert(f.controller.values["NativeP2PGp2PostGeneration"] == 56);
    assert(f.controller.values["NativeP2PGp2PrphAddress"] == 0x00a02c68);
    assert(f.owner.readCalls == 1 && f.owner.readAddress == 0x00a02c68);
}

static void testSevenFlagProfile() {
    const char *keys[] = {"NativeP2PGp2Observation", "NativeP2PProbe",
        "NativeP2PRocProbe", "NativeP2PTxProbe", "NativeP2PManualTrigger",
        "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup"};
    for (const char *key : keys) {
        Fixture f;
        initialize(f);
        f.controller.flags[key] = false;
        assert(invoke(f) == kIOReturnUnsupported);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 16);
        assertNoHardware(f);
    }
}

static void testGenerationAndOwnershipGates() {
    {
        Fixture f; initialize(f); f.request.contextGeneration = 0;
        assert(invoke(f) == kIOReturnNotReady);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 17);
        assertNoHardware(f);
    }
    {
        Fixture f; initialize(f); f.request.contextGeneration++;
        assert(invoke(f) == kIOReturnNotReady);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 17);
        assertNoHardware(f);
    }
    {
        Fixture f; initialize(f); f.owner.com.sc_generation++;
        assert(invoke(f) == kIOReturnNotReady);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 17);
        assertNoHardware(f);
    }
    {
        Fixture f; initialize(f); f.owner.com.sc_tx_rate_generation++;
        assert(invoke(f) == kIOReturnNotReady);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 17);
        assertNoHardware(f);
    }
    struct Mutation { const char *name; void (*apply)(ItlIwx &); };
    const Mutation cases[] = {
        {"busy", [](ItlIwx &o) { o.busy = 0; }},
        {"owner", [](ItlIwx &o) { o.nativeP2pProbeOwner_ = nullptr; }},
        {"cancel", [](ItlIwx &o) { o.nativeP2pCancelRequested_ = 1; }},
        {"nswq", [](ItlIwx &o) { o.nativeP2pNswqPaused_ = 0; }},
        {"radio", [](ItlIwx &o) { o.com.sc_ic.ic_state = 0; }},
        {"shutdown", [](ItlIwx &o) { o.com.sc_flags = IWX_FLAG_SHUTDOWN; }},
        {"hw-error", [](ItlIwx &o) { o.com.sc_flags = IWX_FLAG_HW_ERR; }},
        {"tx-state", [](ItlIwx &o) { o.nativeP2pActionTx_.state = TahoeP2PActionTxState::kBusy; }},
        {"queue-state", [](ItlIwx &o) { o.nativeP2pTxQueue_.state = TahoeP2PResourceState::kPresent; }},
        {"ring", [](ItlIwx &o) { o.nativeP2pTxQueue_.pendingRing = reinterpret_cast<void *>(1); }},
        {"submission-busy", [](ItlIwx &o) { o.nativeP2pTxQueue_.submissionBusy = true; }},
        {"outstanding", [](ItlIwx &o) { o.nativeP2pTxQueue_.lifecycle.current.outstandingTx = 1; }},
        {"retained-ring", [](ItlIwx &o) { o.nativeP2pTxQueue_.lifecycle.current.ringMustRemainOwned = true; }},
        {"queue-lifecycle", [](ItlIwx &o) { o.nativeP2pTxQueue_.lifecycle.current.state = IntelP2PTx::QueueState::kActive; }},
        {"ticket-armed", [](ItlIwx &o) { o.nativeP2pActionTx_.completion.ticket.armed = true; }},
        {"ticket-completed", [](ItlIwx &o) { o.nativeP2pActionTx_.completion.ticket.completed = true; }},
        {"station-registry", [](ItlIwx &o) {
            o.nativeP2pStationRegistry_.current.count = 1;
            o.nativeP2pStationRegistry_.current.owners[0] =
                IntelP2PTx::Owner::kP2pPending;
        }},
        {"station", [](ItlIwx &o) { o.nativeP2pStation_.state = TahoeP2PResourceState::kPresent; }},
        {"mac", [](ItlIwx &o) { o.com.sc_p2p.mac_state = 1; }},
        {"binding", [](ItlIwx &o) { o.com.sc_p2p.binding_state = 1; }},
        {"phy", [](ItlIwx &o) { o.com.sc_p2p.phy_leased = true; }},
    };
    for (const auto &test : cases) {
        Fixture f; initialize(f); test.apply(f.owner);
        assert(invoke(f) == kIOReturnBusy);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 18);
        assertNoHardware(f);
    }
}

static void testSamplerFailuresDoNotPublish() {
    {
        Fixture f; initialize(f);
        f.controller.values["NativeP2PGp2PreValue"] = 0xdeadbeef;
        f.owner.com.sc_device_family = 99;
        assert(invoke(f) == kIOReturnError);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 3);
        assert(f.controller.values["NativeP2PGp2PreValue"] == 0xdeadbeef);
        assertNoHardware(f);
    }
    {
        Fixture f; initialize(f);
        f.owner.nicLockAvailable = false;
        assert(invoke(f) == kIOReturnError);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 4);
        assert(f.owner.lockCalls == 1 && f.owner.unlockCalls == 0);
        assert(f.owner.readCalls == 0 && !f.owner.nicLocked);
        assert(f.owner.com.sc_nic_locks == 0);
        assert((f.owner.com.gpCntrl & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ) == 0);
        assert(f.owner.com.setRequestCalls == 1 && f.owner.com.clearRequestCalls == 1);
        assert(f.owner.pollTimeoutUs == 1980 && gDelayTotalUs == 1982);
        assert(gDelayTotalUs <= 2000);
    }
    {
        Fixture f; initialize(f);
        f.owner.readValue = 0xaabbccdd;
        resetClock(2000000000ULL, 1000000000ULL);
        assert(invoke(f) == kIOReturnError);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 5);
        assert(f.controller.values.count("NativeP2PGp2PreValue") == 0);
        assert(f.owner.lockCalls == 1 && f.owner.unlockCalls == 1);
        assert(f.owner.readCalls == 1 && !f.owner.nicLocked);
    }
    {
        Fixture f; initialize(f);
        f.owner.mutateStationGenerationOnRead = true;
        assert(invoke(f) == kIOReturnNotReady);
        assert(f.controller.values["NativeP2PGp2PreStatus"] == 17);
        assert(f.controller.values.count("NativeP2PGp2PreValue") == 0);
        assert(f.owner.readCalls == 1 && f.owner.unlockCalls == 1);
        assert(f.owner.com.sc_nic_locks == 0 && !f.owner.txLock_.held);
    }
}

static void testNestedNicLockSemantics() {
    Fixture f; initialize(f);
    f.owner.com.sc_nic_locks = 1;
    f.owner.com.gpCntrl = IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ;
    f.owner.nicLocked = true;
    assert(invoke(f) == kIOReturnSuccess);
    assert(f.owner.com.sc_nic_locks == 1 && f.owner.nicLocked);
    assert(f.owner.com.gpCntrl & IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    assert(f.owner.com.setRequestCalls == 0 && f.owner.com.clearRequestCalls == 0);
    assert(f.owner.lockCalls == 0 && f.owner.unlockCalls == 1);
    assert(f.owner.readCalls == 1 && !f.owner.txLock_.held);
}

static void testResourceSnapshotRequiresLock() {
    Fixture f; initialize(f);
    f.owner.nativeP2pTxLock_ = nullptr;
    assert(invoke(f) == kIOReturnBusy);
    assert(f.controller.values["NativeP2PGp2PreStatus"] == 18);
    assertNoHardware(f);
}

static void testCompletedTicketIsHistoricalOnly() {
    Fixture f; initialize(f, 1);
    f.owner.nativeP2pActionTx_.completion.ticket = {true, true};
    assert(invoke(f) == kIOReturnSuccess);
    assert(f.controller.values["NativeP2PGp2PostStatus"] == 1);
    assert(f.controller.values["NativeP2PGp2PostValue"] == 0x12345678);
    assert(f.owner.readCalls == 1 && f.owner.unlockCalls == 1);
}

static void testWrapperSerializesAndSkipsReentry() {
    Fixture f; initialize(f);
    f.loop.gate = false;
    f.loop.thread = false;
    f.owner.tahoeP2pObserveGp2(56, 12, 34, 0);
    assert(f.gate.calls == 1 && f.gate.last == kIOReturnSuccess);
    assert(f.controller.values["NativeP2PGp2PreValue"] == 0x12345678);
    assert(!f.loop.gate);

    f.loop.gate = true;
    f.owner.tahoeP2pObserveGp2(56, 12, 34, 0);
    assert(f.gate.calls == 1);
    f.loop.gate = false;
    f.loop.thread = true;
    f.owner.tahoeP2pObserveGp2(56, 12, 34, 0);
    assert(f.gate.calls == 1);
    f.loop.thread = false;
    f.owner.tahoeP2pObserveGp2(56, 12, 34, 2);
    assert(f.gate.calls == 1);
}

int main() {
    testSuccessAndPhases();
    testSevenFlagProfile();
    testGenerationAndOwnershipGates();
    testSamplerFailuresDoNotPublish();
    testNestedNicLockSemantics();
    testResourceSnapshotRequiresLock();
    testCompletedTicketIsHistoricalOnly();
    testWrapperSerializesAndSkipsReentry();
    std::puts("PASS: extracted GP2 production gate rejects incomplete profile, stale generations, owners, radio and resources");
    std::puts("PASS: supported-family PRPH sampling brackets one read under NIC lock and publishes only successful samples");
    std::puts("PASS: wrapper serializes on command gate and refuses reentrant dispatch");
    std::puts("SCOPE: source-extracted mock only; no production kext, IOKit, EFI, or radio operation");
}
'''


def main() -> int:
    source = SOURCE.read_text()
    request_start = source.index("struct ClockRequest")
    start = source.rfind("namespace {", 0, request_start)
    end = source.index("\n} // namespace\n", start) + len("\n} // namespace")
    callbacks = source[start:end]
    wrapper = extract_wrapper(source)
    generated = HARNESS.replace("__CLOCK_CALLBACKS__", callbacks)
    generated = generated.replace("__CLOCK_WRAPPER__", wrapper)
    with tempfile.TemporaryDirectory(prefix="iwx-p2p-clock-mock-") as tmp:
        temp = Path(tmp)
        harness = temp / "clock_mock.cpp"
        binary = temp / "clock_mock"
        harness.write_text(generated)
        command = [
            "xcrun", "--sdk", "macosx", "clang++", "-std=c++17", "-g",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            f"-I{ROOT / 'native'}", str(harness), str(SAMPLER),
            str(TX_RESOURCES), "-o", str(binary),
        ]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
    print(f"Production callback source SHA-256: {sha256(SOURCE)}")
    print("Harness compiled and ran in a temporary directory; no generated files retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
