#!/usr/bin/env python3
"""Compile the production Tahoe net80211 transition gate with host stubs."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_definition(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    index = opening
    while index < len(source):
        ch = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"
                index += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                index += 2
                continue
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        elif state == "line":
            if ch == "\n":
                state = "code"
        elif state == "block":
            if ch == "*" and nxt == "/":
                state = "code"
                index += 2
                continue
        elif state in ("string", "char"):
            if ch == "\\":
                index += 2
                continue
            if (state == "string" and ch == '"') or (
                state == "char" and ch == "'"
            ):
                state = "code"
        index += 1
    raise AssertionError(f"unterminated production function: {marker}")


PREFIX = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

using IOReturn = int;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnBusy = -10;
constexpr IOReturn kIOReturnNotReady = -11;
constexpr IOReturn kIOReturnAborted = -12;
constexpr IOReturn kIOReturnBadArgument = -13;
constexpr unsigned IEEE80211_ADDR_LEN = 6;
constexpr unsigned IEEE80211_NWID_LEN = 32;
constexpr int IEEE80211_STATUS_SUCCESS = 0;
constexpr int IEEE80211_EVT_STA_ASSOC_DONE = 20;
constexpr uint32_t IWX_FLAG_SHUTDOWN = 0x1;

enum ieee80211_state : int {
    IEEE80211_S_INIT = 0,
    IEEE80211_S_SCAN = 1,
    IEEE80211_S_AUTH = 2,
    IEEE80211_S_ASSOC = 3,
    IEEE80211_S_RUN = 4,
};

struct OSObject {};
struct IOEthernetController : OSObject {};
struct iwx_softc;
struct ieee80211com;
using StateFn = int (*)(ieee80211com *, enum ieee80211_state, int);
using EventFn = void (*)(ieee80211com *, int, void *);
using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);

struct ieee80211_node {
    uint32_t ni_pmf_key_epoch = 0;
    uint32_t ni_rsnakms = 0;
    uint8_t ni_sae_h2e = 0;
    uint8_t ni_esslen = 0;
    uint8_t ni_bssid[IEEE80211_ADDR_LEN] {};
    uint8_t ni_macaddr[IEEE80211_ADDR_LEN] {};
    uint8_t ni_essid[IEEE80211_NWID_LEN] {};
};

struct ieee80211com {
    enum ieee80211_state ic_state = IEEE80211_S_INIT;
    ieee80211_node *ic_bss = nullptr;
    uint8_t ic_des_esslen = 0;
    uint8_t ic_des_essid[IEEE80211_NWID_LEN] {};
    uint8_t ic_des_bssid[IEEE80211_ADDR_LEN] {};
    uint8_t ic_myaddr[IEEE80211_ADDR_LEN] {};
    int ic_assoc_status = 0;
    EventFn ic_event_handler = nullptr;
};

struct iwx_softc {
    int sc_generation = 1;
    uint32_t sc_flags = 0;
    enum ieee80211_state ns_nstate = IEEE80211_S_INIT;
    int ns_arg = 0;
    StateFn sc_newstate = nullptr;
    ieee80211com sc_ic;
};

struct TahoeNet80211Transition {
    IOEthernetController *gateOwner = nullptr;
    iwx_softc *sc = nullptr;
    ieee80211_node *node = nullptr;
    enum ieee80211_state oldState = IEEE80211_S_INIT;
    enum ieee80211_state newState = IEEE80211_S_INIT;
    int arg = 0;
    int generation = 0;
    uint32_t nodeEpoch = 0;
    uint32_t requestSequence = 0;
    uint32_t akm = 0;
    uint8_t nodeBssid[IEEE80211_ADDR_LEN] {};
    uint8_t nodeMac[IEEE80211_ADDR_LEN] {};
    uint8_t localMac[IEEE80211_ADDR_LEN] {};
    uint8_t desiredBssid[IEEE80211_ADDR_LEN] {};
    uint8_t nodeEssid[IEEE80211_NWID_LEN] {};
    uint8_t desiredEssid[IEEE80211_NWID_LEN] {};
    uint8_t nodeEssidLength = 0;
    uint8_t desiredEssidLength = 0;
    uint8_t saeH2e = 0;
    bool queuedRequest = false;
    bool captureSnapshot = false;
    bool identityCaptured = false;
    bool allowShutdown = false;
    bool notifyAssociation = false;
    int stateResult = 0;
    uint32_t finalState = UINT32_MAX;
};

class IOWorkLoop {
public:
    bool onThread() const { return onThreadValue; }
    bool inGate() const { return gateHeld; }
    bool onThreadValue = false;
    bool gateHeld = false;
};

class IOCommandGate {
public:
    IOEthernetController *target = nullptr;
    IOWorkLoop *loop = nullptr;
    unsigned calls = 0;
    IOReturn forcedResult = kIOReturnSuccess;
    bool lastActionOnThread = false;
    bool lastActionInGate = false;
    IOReturn runAction(Action action, void *arg0, void *arg1) {
        ++calls;
        if (forcedResult != kIOReturnSuccess)
            return forcedResult;
        // runAction serializes against event sources by holding the gate. It
        // does not move a caller-thread invocation onto the workloop thread.
        const bool previousGate = loop->gateHeld;
        loop->gateHeld = true;
        lastActionOnThread = loop->onThread();
        lastActionInGate = loop->inGate();
        const IOReturn result = action(target, arg0, arg1, nullptr, nullptr);
        loop->gateHeld = previousGate;
        return result;
    }
};

struct ItlIwx {
    iwx_softc com;
    IOEthernetController *controller = nullptr;
    IOWorkLoop loop;
    IOCommandGate gate;
    uint32_t tahoe_newstate_sequence_ = 0;
    int tahoe_newstate_generation_ = 0;
    IOEthernetController *getController() { return controller; }
    IOWorkLoop *getMainWorkLoop() { return &loop; }
    IOCommandGate *getMainCommandGate() { return &gate; }
    static IOReturn iwx_net80211_transition_gate_action(
        OSObject *, void *, void *, void *, void *);
    int iwx_run_net80211_transition_gate(iwx_softc *,
        TahoeNet80211Transition *);
};

#define container_of(ptr, type, member) reinterpret_cast<type *>(ptr)

static unsigned stateCalls = 0;
static unsigned eventCalls = 0;
static int stateReturn = 0;
static int transition(ieee80211com *ic, enum ieee80211_state state, int) {
    ++stateCalls;
    ic->ic_state = state;
    return stateReturn;
}
static void event(ieee80211com *, int code, void *) {
    assert(code == IEEE80211_EVT_STA_ASSOC_DONE);
    ++eventCalls;
}

"""


TESTS = r"""
static void seed(ItlIwx &owner, ieee80211_node &node) {
    owner.controller = new IOEthernetController;
    owner.gate.target = owner.controller;
    owner.gate.loop = &owner.loop;
    owner.com.sc_generation = 44;
    owner.com.sc_ic.ic_state = IEEE80211_S_SCAN;
    owner.com.sc_ic.ic_bss = &node;
    owner.com.sc_ic.ic_des_esslen = 3;
    std::memcpy(owner.com.sc_ic.ic_des_essid, "net", 3);
    const uint8_t local[6] = {2, 1, 2, 3, 4, 5};
    const uint8_t desired[6] = {2, 6, 7, 8, 9, 10};
    std::memcpy(owner.com.sc_ic.ic_myaddr, local, 6);
    std::memcpy(owner.com.sc_ic.ic_des_bssid, desired, 6);
    owner.com.sc_ic.ic_event_handler = event;
    owner.com.sc_newstate = transition;
    owner.com.ns_nstate = IEEE80211_S_AUTH;
    owner.com.ns_arg = 9;
    owner.tahoe_newstate_generation_ = 44;
    owner.tahoe_newstate_sequence_ = 5;
    node.ni_pmf_key_epoch = 17;
    node.ni_rsnakms = 0x80;
    node.ni_sae_h2e = 1;
    node.ni_esslen = 3;
    std::memcpy(node.ni_bssid, desired, 6);
    const uint8_t peer[6] = {2, 11, 12, 13, 14, 15};
    std::memcpy(node.ni_macaddr, peer, 6);
    std::memcpy(node.ni_essid, "net", 3);
}

static TahoeNet80211Transition snapshot(
    ItlIwx &owner, enum ieee80211_state target = IEEE80211_S_AUTH,
    int argument = 9) {
    TahoeNet80211Transition request{};
    request.newState = target;
    request.arg = argument;
    request.generation = 44;
    request.requestSequence = 5;
    request.queuedRequest = true;
    request.captureSnapshot = true;
    owner.com.ns_nstate = target;
    owner.com.ns_arg = argument;
    assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == 0);
    assert(request.oldState == IEEE80211_S_SCAN);
    assert(request.identityCaptured && request.node == owner.com.sc_ic.ic_bss);
    assert(request.nodeEpoch == 17 && request.akm == 0x80);
    assert(owner.gate.calls == 1 && stateCalls == 0);
    assert(owner.gate.lastActionInGate && !owner.gate.lastActionOnThread);
    return request;
}

static void test_gate_capture_and_commit() {
    ItlIwx owner;
    ieee80211_node node{};
    seed(owner, node);
    TahoeNet80211Transition request = snapshot(owner);
    request.notifyAssociation = true;
    owner.com.sc_ic.ic_assoc_status = IEEE80211_STATUS_SUCCESS;
    assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == 0);
    assert(stateCalls == 1 && eventCalls == 0);
    assert(owner.com.sc_ic.ic_state == IEEE80211_S_AUTH);
    assert(owner.gate.calls == 2);
    assert(owner.gate.lastActionInGate && !owner.gate.lastActionOnThread);
    delete owner.controller;
}

static void test_assoc_done_runs_inside_gate() {
    ItlIwx owner;
    ieee80211_node node{};
    seed(owner, node);
    TahoeNet80211Transition request =
        snapshot(owner, IEEE80211_S_RUN, 12);
    request.notifyAssociation = true;
    owner.com.sc_ic.ic_assoc_status = IEEE80211_STATUS_SUCCESS;
    assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == 0);
    assert(stateCalls == 1 && eventCalls == 1);
    assert(owner.com.sc_ic.ic_state == IEEE80211_S_RUN);
    assert(owner.gate.lastActionInGate && !owner.gate.lastActionOnThread);
    delete owner.controller;
}

static void test_stop_init_transition_from_off_worker() {
    ItlIwx owner;
    ieee80211_node node{};
    seed(owner, node);
    owner.com.sc_ic.ic_state = IEEE80211_S_RUN;
    owner.com.sc_flags |= IWX_FLAG_SHUTDOWN;

    // Mirrors iwx_stop(): INIT is allowed during shutdown. The caller is not
    // the workloop thread; runAction must grant gate ownership, not fake it.
    TahoeNet80211Transition request{};
    request.newState = IEEE80211_S_INIT;
    request.arg = -1;
    request.generation = 44;
    request.allowShutdown = true;
    assert(!owner.loop.onThread() && !owner.loop.inGate());
    const int result = owner.iwx_run_net80211_transition_gate(
        &owner.com, &request);
    assert(result == 0);
    assert(owner.gate.calls == 1);
    assert(owner.gate.lastActionInGate && !owner.gate.lastActionOnThread);
    assert(stateCalls == 1 && owner.com.sc_ic.ic_state == IEEE80211_S_INIT);
    delete owner.controller;
}

static void test_transition_action_rejects_ungated_callback() {
    ItlIwx owner;
    ieee80211_node node{};
    seed(owner, node);
    owner.loop.onThreadValue = true;
    owner.com.sc_flags |= IWX_FLAG_SHUTDOWN;
    TahoeNet80211Transition request{};
    request.newState = IEEE80211_S_INIT;
    request.arg = -1;
    request.generation = 44;
    request.gateOwner = owner.controller;
    request.sc = &owner.com;
    request.allowShutdown = true;

    // Worker-thread identity alone is not proof of serialized gate ownership.
    assert(owner.loop.onThread() && !owner.loop.inGate());
    assert(owner.iwx_net80211_transition_gate_action(
        owner.controller, owner.controller, &request, nullptr, nullptr) ==
        kIOReturnNotReady);
    assert(stateCalls == 0 && owner.com.sc_ic.ic_state != IEEE80211_S_INIT);
    delete owner.controller;
}

static void test_existing_gate_is_reused_off_worker() {
    ItlIwx owner;
    ieee80211_node node{};
    seed(owner, node);
    owner.loop.gateHeld = true;
    owner.com.sc_flags |= IWX_FLAG_SHUTDOWN;
    TahoeNet80211Transition request{};
    request.newState = IEEE80211_S_INIT;
    request.arg = -1;
    request.generation = 44;
    request.allowShutdown = true;

    assert(!owner.loop.onThread() && owner.loop.inGate());
    assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == 0);
    assert(owner.gate.calls == 0);
    assert(stateCalls == 1 && owner.com.sc_ic.ic_state == IEEE80211_S_INIT);
    delete owner.controller;
}

static void test_explicit_owner_and_generation_gates() {
    ItlIwx owner;
    ieee80211_node node{};
    seed(owner, node);
    TahoeNet80211Transition request = snapshot(owner);
    owner.com.sc_generation++;
    assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ECANCELED);
    assert(stateCalls == 0);

    ItlIwx badOwner;
    ieee80211_node badNode{};
    seed(badOwner, badNode);
    TahoeNet80211Transition direct{};
    direct.sc = &badOwner.com;
    direct.gateOwner = badOwner.controller;
    direct.generation = 44;
    badOwner.com.sc_generation = 44;
    IOEthernetController wrongTarget;
    assert(badOwner.iwx_net80211_transition_gate_action(
        &wrongTarget, badOwner.controller, &direct, nullptr, nullptr) ==
        kIOReturnBadArgument);
    assert(stateCalls == 0);
    delete owner.controller;
    delete badOwner.controller;
}

static void test_stale_node_and_identity_are_rejected() {
    {
        ItlIwx owner;
        ieee80211_node oldNode{}, newNode{};
        seed(owner, oldNode);
        TahoeNet80211Transition request = snapshot(owner);
        owner.com.sc_ic.ic_bss = &newNode;
        // The saved pointer is deliberately invalid. Pointer validation must
        // reject it before any dereference of the retired node.
        request.node = reinterpret_cast<ieee80211_node *>(uintptr_t(1));
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ECANCELED);
        assert(stateCalls == 0);
        delete owner.controller;
    }
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        TahoeNet80211Transition request = snapshot(owner);
        ++node.ni_pmf_key_epoch;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ECANCELED);
        assert(stateCalls == 0);
        delete owner.controller;
    }
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        TahoeNet80211Transition request = snapshot(owner);
        owner.com.sc_ic.ic_myaddr[0] ^= 2;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ECANCELED);
        assert(stateCalls == 0);
        delete owner.controller;
    }
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        TahoeNet80211Transition request = snapshot(owner);
        owner.com.sc_ic.ic_des_essid[0] ^= 1;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ECANCELED);
        assert(stateCalls == 0);
        delete owner.controller;
    }
}

static void test_request_sequence_and_shutdown_reset() {
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        TahoeNet80211Transition request = snapshot(owner);
        ++owner.tahoe_newstate_sequence_;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ECANCELED);
        assert(stateCalls == 0);
        delete owner.controller;
    }
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        TahoeNet80211Transition request = snapshot(owner);
        IOEthernetController *capturedOwner = owner.controller;
        owner.controller = new IOEthernetController;
        owner.gate.target = owner.controller;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == ENXIO);
        assert(stateCalls == 0 && owner.gate.calls == 1);
        delete owner.controller;
        owner.controller = capturedOwner;
        delete owner.controller;
    }
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        owner.loop.onThreadValue = true;
        owner.loop.gateHeld = true;
        owner.com.sc_flags |= IWX_FLAG_SHUTDOWN;
        TahoeNet80211Transition request{};
        request.newState = IEEE80211_S_INIT;
        request.arg = -1;
        request.generation = 44;
        request.allowShutdown = true;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) == 0);
        assert(owner.gate.calls == 0); // Already on the serialized workloop.
        assert(stateCalls == 1 && owner.com.sc_ic.ic_state == IEEE80211_S_INIT);
        delete owner.controller;
    }
    {
        ItlIwx owner;
        ieee80211_node node{};
        seed(owner, node);
        const unsigned priorStateCalls = stateCalls;
        owner.com.sc_flags |= IWX_FLAG_SHUTDOWN;
        TahoeNet80211Transition request{};
        request.newState = IEEE80211_S_INIT;
        request.arg = -1;
        request.generation = 44;
        assert(owner.iwx_run_net80211_transition_gate(&owner.com, &request) ==
               ECANCELED);
        assert(stateCalls == priorStateCalls &&
               owner.com.sc_ic.ic_state == IEEE80211_S_SCAN);
        delete owner.controller;
    }
}

int main() {
    test_stop_init_transition_from_off_worker();
    stateCalls = eventCalls = 0;
    test_transition_action_rejects_ungated_callback();
    stateCalls = eventCalls = 0;
    test_existing_gate_is_reused_off_worker();
    stateCalls = eventCalls = 0;
    test_gate_capture_and_commit();
    stateCalls = eventCalls = 0;
    test_assoc_done_runs_inside_gate();
    stateCalls = eventCalls = 0;
    test_explicit_owner_and_generation_gates();
    stateCalls = eventCalls = 0;
    test_stale_node_and_identity_are_rejected();
    stateCalls = eventCalls = 0;
    test_request_sequence_and_shutdown_reset();
}
"""


def main() -> None:
    source = SOURCE.read_text()
    action = extract_definition(
        source,
        "IOReturn ItlIwx::\niwx_net80211_transition_gate_action(",
    )
    runner = extract_definition(
        source,
        "int ItlIwx::\niwx_run_net80211_transition_gate(",
    )
    with tempfile.TemporaryDirectory(prefix="iwx-transition-gate-") as temp:
        cpp = Path(temp) / "transition_gate.cpp"
        binary = Path(temp) / "transition_gate"
        cpp.write_text(PREFIX + action + "\n" + runner + "\n" + TESTS)
        subprocess.run(
            [
                "clang++",
                "-std=c++17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                str(cpp),
                "-o",
                str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print("PASS: production transition gate owner, generation, identity, sequence and shutdown paths")


if __name__ == "__main__":
    main()
