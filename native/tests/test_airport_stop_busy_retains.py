#!/usr/bin/env python3
"""Exercise the production AirportItlwm::stop body with injected HAL results."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "AirportItlwm/AirportItlwmV2.cpp"


def function_definition(source: str, marker: str) -> str:
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
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using IOReturn = int;
using UInt32 = uint32_t;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnBusy = -10;
constexpr IOReturn kIOReturnError = -1;
constexpr IOReturn kIOReturnNotReady = -2;
constexpr uint32_t kIONetworkLinkValid = 1;

struct IOService {};
struct _ifnet {};
struct IeeeController { struct { _ifnet ac_if; } ic_ac; };
static std::vector<std::string> events;

static void XYLog(const char *, ...) {}
static void ether_ifdetach(_ifnet *) { events.emplace_back("ether_ifdetach"); }

class AirportItlwmSkywalkInterface {
public:
    bool stopResult = true;
    bool released = false;
    bool stopNative() { events.emplace_back("native_stop"); return stopResult; }
    void releaseNative() { events.emplace_back("native_release"); }
};

class FakeHalService {
public:
    IeeeController controller;
    unsigned detachCalls = 0;
    unsigned retainedQueries = 0;
    bool retainAfterDetach = false;
    bool retained = false;
    IeeeController *get80211Controller() { return &controller; }
    void detach(void *) {
        ++detachCalls;
        retained = retainAfterDetach;
        events.emplace_back("hal_detach");
    }
    bool detachResourcesRetained() const {
        ++const_cast<FakeHalService *>(this)->retainedQueries;
        events.emplace_back("hal_retained_query");
        return retained;
    }
};

struct Base {
    void stop(IOService *) { events.emplace_back("super_stop"); }
};
#define super Base

// These are real controller boundary methods/objects, not invented driver
// members. PM policy bodies are tested by the existing native-power suite.
struct StopWorkLoop { bool inGate() const { return true; } };
struct StopCommandGate {
    template<class Action> IOReturn runAction(Action, void *) { return 0; }
};
class AirportItlwm : public Base {
public:
    FakeHalService *fHalService = nullptr;
    AirportItlwmSkywalkInterface *fNetIf = nullptr;
    void *bsdInterface = nullptr;
    void *pciNub = nullptr;
    IOReturn disableResult = kIOReturnSuccess;
    unsigned disableCalls = 0;
    unsigned watchdogDetachCalls = 0;
    unsigned linkStatusCalls = 0;
    unsigned interfaceDetachCalls = 0;
    unsigned releaseAllCalls = 0;
    unsigned retainCalls = 0;
    unsigned releaseCalls = 0;
    bool stopRetainedForBusy_ = false;
    StopWorkLoop fixtureLoop;
    StopWorkLoop *_fWorkloop = &fixtureLoop;
    StopCommandGate *_fCommandGate = nullptr;
    IOReturn fixtureTerminalPowerResult = kIOReturnSuccess;
    bool fixturePmRetired = true;
    bool fixturePowerStopping = false;
    void setNativePowerStopping(bool stopping) { fixturePowerStopping = stopping; }
    static IOReturn nativePowerStopAction(AirportItlwm *owner, void *, void *, void *, void *) {
        return owner->fixtureTerminalPowerResult;
    }
    bool retireNativePMPowerCallouts() { return fixturePmRetired; }
    void stop(IOService *provider);
    void retain() { ++retainCalls; events.emplace_back("retain_owner"); }
    void release() { ++releaseCalls; events.emplace_back("release_owner"); }
    void detachWatchdogTimer() {
        ++watchdogDetachCalls;
        events.emplace_back("watchdog_detach");
    }
    IOReturn disableAdapter(void *) {
        ++disableCalls;
        events.emplace_back("disable");
        return disableResult;
    }
    void setLinkStatus(UInt32) {
        ++linkStatusCalls;
        events.emplace_back("link_valid");
    }
    void detachInterface(AirportItlwmSkywalkInterface *, bool) {
        ++interfaceDetachCalls;
        events.emplace_back("interface_detach");
    }
    void releaseAll() {
        ++releaseAllCalls;
        events.emplace_back("release_all");
    }
};

#define OSSafeReleaseNULL(value) do { \
    if (value) { events.emplace_back("interface_release"); \
        (value)->released = true; (value) = nullptr; } \
} while (0)
"""


TESTS = r"""
static void assert_retained_after_disable_failure(IOReturn failure) {
    events.clear();
    AirportItlwmSkywalkInterface netif;
    FakeHalService hal;
    AirportItlwm owner;
    IOService provider;
    owner.fHalService = &hal;
    owner.fNetIf = &netif;
    owner.disableResult = failure;

    owner.stop(&provider);

    assert((events == std::vector<std::string>{
        "native_stop", "hal_retained_query", "disable", "retain_owner"}));
    assert(owner.disableCalls == 1);
    assert(owner.retainCalls == 1);
    assert(owner.watchdogDetachCalls == 0);
    assert(owner.linkStatusCalls == 0);
    assert(owner.fHalService == &hal && owner.fNetIf == &netif);
    assert(hal.detachCalls == 0);
    assert(!netif.released);
    assert(owner.interfaceDetachCalls == 0 && owner.releaseAllCalls == 0);
    assert(owner.stopRetainedForBusy_);

    // A repeated Busy stop holds exactly one owner retain. A later successful
    // retry balances it only after teardown has released the HAL and interfaces.
    owner.disableResult = kIOReturnBusy;
    events.clear();
    owner.stop(&provider);
    assert(owner.retainCalls == 1 && owner.releaseCalls == 0);
    assert(owner.stopRetainedForBusy_);

    owner.disableResult = kIOReturnSuccess;
    events.clear();
    owner.stop(&provider);
    const std::vector<std::string> retryExpected{
        "native_stop", "hal_retained_query", "disable", "watchdog_detach", "hal_detach",
        "hal_retained_query", "super_stop", "link_valid", "native_release", "ether_ifdetach",
        "interface_detach", "interface_release", "release_all", "release_owner"};
    assert(events == retryExpected);
    assert(owner.retainCalls == 1 && owner.releaseCalls == 1);
    assert(!owner.stopRetainedForBusy_);
}

int main() {
    // A Busy or other HAL stop failure must retain the controller, watchdog,
    // and interfaces so the active driver can be retried safely.
    assert_retained_after_disable_failure(kIOReturnBusy);
    assert_retained_after_disable_failure(kIOReturnError);

    // A failed gated NativeStop also exits before disable or any teardown.
    events.clear();
    AirportItlwmSkywalkInterface rejectingNetif;
    rejectingNetif.stopResult = false;
    FakeHalService rejectingHal;
    AirportItlwm rejectingOwner;
    IOService provider;
    rejectingOwner.fHalService = &rejectingHal;
    rejectingOwner.fNetIf = &rejectingNetif;
    rejectingOwner.stop(&provider);
    assert((events == std::vector<std::string>{"native_stop", "retain_owner"}));
    assert(rejectingOwner.disableCalls == 0);
    assert(rejectingOwner.retainCalls == 1);
    assert(rejectingOwner.stopRetainedForBusy_);
    assert(rejectingOwner.watchdogDetachCalls == 0);
    assert(rejectingHal.detachCalls == 0 && !rejectingNetif.released);

    // Success keeps the existing teardown sequence after the HAL accepted
    // stop, with the watchdog drained before superclass/interface teardown.
    events.clear();
    AirportItlwmSkywalkInterface netif;
    FakeHalService hal;
    AirportItlwm owner;
    owner.fHalService = &hal;
    owner.fNetIf = &netif;
    owner.stop(&provider);
    const std::vector<std::string> expected{
        "native_stop", "hal_retained_query", "disable", "watchdog_detach", "hal_detach",
        "hal_retained_query", "super_stop", "link_valid", "native_release",
        "ether_ifdetach", "interface_detach", "interface_release", "release_all"};
    assert(events == expected);
    assert(owner.disableCalls == 1 && owner.watchdogDetachCalls == 1);
    assert(owner.retainCalls == 0);
    assert(owner.linkStatusCalls == 1 && hal.detachCalls == 1);
    assert(netif.released && owner.fNetIf == nullptr);
    assert(owner.interfaceDetachCalls == 1 && owner.releaseAllCalls == 1);

    // A HAL may decline detach after adapter disable. The parent retains its
    // gate/interface owner and balances the pin after a later successful retry.
    events.clear();
    AirportItlwmSkywalkInterface retainedNetif;
    FakeHalService retainedHal;
    AirportItlwm retainedOwner;
    retainedHal.retainAfterDetach = true;
    retainedOwner.fHalService = &retainedHal;
    retainedOwner.fNetIf = &retainedNetif;
    retainedOwner.stop(&provider);
    const std::vector<std::string> retainedExpected{
        "native_stop", "hal_retained_query", "disable", "watchdog_detach", "hal_detach",
        "hal_retained_query", "retain_owner"};
    assert(events == retainedExpected);
    assert(retainedOwner.retainCalls == 1 && retainedOwner.releaseCalls == 0);
    assert(retainedOwner.stopRetainedForBusy_);
    assert(retainedOwner.fNetIf == &retainedNetif && !retainedNetif.released);
    assert(retainedOwner.linkStatusCalls == 0);

    retainedHal.retainAfterDetach = false;
    events.clear();
    retainedOwner.stop(&provider);
    const std::vector<std::string> retainedRetryExpected{
        "native_stop", "hal_retained_query", "hal_detach",
        "hal_retained_query", "super_stop", "link_valid", "native_release",
        "ether_ifdetach", "interface_detach", "interface_release",
        "release_all", "release_owner"};
    assert(events == retainedRetryExpected);
    assert(retainedOwner.retainCalls == 1 && retainedOwner.releaseCalls == 1);
    assert(!retainedOwner.stopRetainedForBusy_);
}
"""


def main() -> None:
    source = SOURCE.read_text()
    stop = function_definition(source, "void AirportItlwm::stop(IOService *provider)")
    harness = PREFIX + "\n#define AIRPORT_TAHOE 1\n" + stop + "\n" + TESTS
    with tempfile.TemporaryDirectory(prefix="airport-stop-busy-") as temp:
        directory = Path(temp)
        cpp = directory / "stop_test.cpp"
        binary = directory / "stop_test"
        cpp.write_text(harness)
        subprocess.run(
            [
                "xcrun", "clang++", "-std=c++17", "-O1", "-g",
                "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                str(cpp), "-o", str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print("AirportItlwm stop failure retention and teardown order ASan/UBSan checks passed")


if __name__ == "__main__":
    main()
