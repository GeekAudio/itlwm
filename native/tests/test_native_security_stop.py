#!/usr/bin/env python3
"""Run the production native stop/release bodies against a real WCL Backend."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "AirportItlwm/AirportItlwmSkywalkInterface.cpp"


def production_function(source: str, marker: str) -> str:
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
#include "native/wcl_backend.hpp"
#include <cassert>
#include <cstdint>

using NativeWifi::Backend;
using NativeWifi::Operations;

using IOReturn = int;
struct OSObject {};
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnError = -1;
enum { NativeStop = 9 };

class AirportItlwmSkywalkInterface;
using NativeAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);

struct GateSpy {
    bool reject = false;
    bool inAction = false;
    unsigned calls = 0;
    unsigned callbackCalls = 0;
    IOReturn runAction(NativeAction action, void *object, void *operation);
};

struct IngressSpy {
    bool shutdownResult = true;
    bool destroyResult = true;
    unsigned shutdownCalls = 0;
    unsigned destroyCalls = 0;
    bool shutdown() { ++shutdownCalls; return shutdownResult; }
    bool destroy() { ++destroyCalls; return destroyResult; }
};

struct InstanceSpy {
    unsigned releaseCalls = 0;
    void release() { ++releaseCalls; }
};

struct ClearSpy {
    GateSpy *gate = nullptr;
    unsigned calls = 0;
    unsigned outsideGateCalls = 0;
};

static void clearCredentials(void *raw) {
    auto *spy = static_cast<ClearSpy *>(raw);
    ++spy->calls;
    if (spy->gate == nullptr || !spy->gate->inAction)
        ++spy->outsideGateCalls;
}

class AirportItlwmSkywalkInterface {
public:
    Backend *nativeBackend = nullptr;
    IngressSpy *nativeIngress = nullptr;
    GateSpy *_fCommandGate = nullptr;
    InstanceSpy *instance = nullptr;
    bool nativeLease = false;
    unsigned interfaceReleaseCalls = 0;

    static IOReturn nativeRequest(OSObject *, void *, void *, void *, void *);
    bool stopNative();
    void releaseNative();
    void release() { ++interfaceReleaseCalls; }
};

IOReturn GateSpy::runAction(NativeAction action, void *object,
                            void *operation) {
    ++calls;
    if (reject)
        return kIOReturnError;
    inAction = true;
    const IOReturn result = action(nullptr, object, operation, nullptr, nullptr);
    inAction = false;
    return result;
}

IOReturn AirportItlwmSkywalkInterface::nativeRequest(
    OSObject *, void *raw, void *operation, void *, void *) {
    auto *self = static_cast<AirportItlwmSkywalkInterface *>(raw);
    assert(reinterpret_cast<uintptr_t>(operation) == NativeStop);
    ++self->_fCommandGate->callbackCalls;
    if (self->nativeBackend == nullptr)
        return kIOReturnError;
    self->nativeBackend->stop();
    return kIOReturnSuccess;
}
"""


CASES = r"""
static void initialize(AirportItlwmSkywalkInterface &owner,
                       ClearSpy &clear, GateSpy &gate) {
    clear.gate = &gate;
    owner.nativeBackend = new Backend;
    owner.nativeBackend->initialize(Operations{
        &clear, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, clearCredentials});
    owner.nativeIngress = new IngressSpy;
    owner._fCommandGate = &gate;
    owner.instance = new InstanceSpy;
    owner.nativeLease = true;
}

static void assert_released(const AirportItlwmSkywalkInterface &owner,
                            const InstanceSpy &instance) {
    assert(owner.nativeIngress == nullptr);
    assert(owner.nativeBackend == nullptr);
    assert(!owner.nativeLease);
    assert(owner.interfaceReleaseCalls == 1);
    assert(instance.releaseCalls == 1);
}

int main() {
    // Ingress shutdown rejection stops before the command gate. releaseNative
    // must preserve the still-live Backend until a gated NativeStop succeeds.
    {
        AirportItlwmSkywalkInterface owner;
        ClearSpy clear;
        GateSpy gate;
        initialize(owner, clear, gate);
        owner.nativeIngress->shutdownResult = false;
        assert(!owner.stopNative());
        assert(owner.nativeIngress->shutdownCalls == 1);
        assert(gate.calls == 0 && !owner.nativeBackend->stopped());
        owner.releaseNative();
        assert(owner.nativeBackend != nullptr && owner.nativeIngress != nullptr);
        assert(clear.calls == 0 && owner.nativeLease);

        owner.nativeIngress->shutdownResult = true;
        assert(owner.stopNative());
        assert(owner.nativeBackend->stopped());
        assert(gate.calls == 1 && gate.callbackCalls == 1);
        assert(clear.calls == 1 && clear.outsideGateCalls == 0);
        auto *instance = owner.instance;
        owner.releaseNative();
        assert_released(owner, *instance);
        delete instance;
    }

    // A failed runAction also leaves Backend credentials untouched and makes
    // releaseNative retain ownership. A later successful gated stop can retire it.
    {
        AirportItlwmSkywalkInterface owner;
        ClearSpy clear;
        GateSpy gate;
        initialize(owner, clear, gate);
        gate.reject = true;
        assert(!owner.stopNative());
        assert(gate.calls == 1 && gate.callbackCalls == 0);
        assert(!owner.nativeBackend->stopped() && clear.calls == 0);
        owner.releaseNative();
        assert(owner.nativeBackend != nullptr && owner.nativeIngress != nullptr);
        assert(clear.calls == 0 && owner.nativeLease);

        gate.reject = false;
        assert(owner.stopNative());
        assert(gate.calls == 2 && gate.callbackCalls == 1);
        assert(owner.nativeBackend->stopped());
        assert(clear.calls == 1 && clear.outsideGateCalls == 0);
        auto *instance = owner.instance;
        owner.releaseNative();
        assert_released(owner, *instance);
        delete instance;
    }

    // No gate is a hard stop failure. Once restored, stopping twice is
    // idempotent and the second call does not invoke NativeStop again.
    {
        AirportItlwmSkywalkInterface owner;
        ClearSpy clear;
        GateSpy gate;
        initialize(owner, clear, gate);
        owner._fCommandGate = nullptr;
        assert(!owner.stopNative());
        assert(!owner.nativeBackend->stopped() && clear.calls == 0);
        owner.releaseNative();
        assert(owner.nativeBackend != nullptr && owner.nativeLease);

        owner._fCommandGate = &gate;
        assert(owner.stopNative());
        assert(gate.calls == 1 && gate.callbackCalls == 1);
        assert(clear.calls == 1 && clear.outsideGateCalls == 0);
        assert(owner.stopNative());
        assert(gate.calls == 1 && gate.callbackCalls == 1);
        assert(clear.calls == 1);
        auto *instance = owner.instance;
        owner.releaseNative();
        assert_released(owner, *instance);
        delete instance;
    }

    // Successful NativeStop is the sole credential clear; releaseNative only
    // destroys already-stopped resources, and a failed ingress destroy retries safely.
    {
        AirportItlwmSkywalkInterface owner;
        ClearSpy clear;
        GateSpy gate;
        initialize(owner, clear, gate);
        assert(owner.stopNative());
        assert(owner.nativeBackend->stopped());
        assert(gate.calls == 1 && gate.callbackCalls == 1);
        assert(clear.calls == 1 && clear.outsideGateCalls == 0);

        owner.nativeIngress->destroyResult = false;
        auto *instance = owner.instance;
        owner.releaseNative();
        assert(owner.nativeIngress != nullptr && owner.nativeBackend != nullptr);
        assert(owner.nativeLease && clear.calls == 1);
        owner.nativeIngress->destroyResult = true;
        owner.releaseNative();
        assert_released(owner, *instance);
        assert(clear.calls == 1 && clear.outsideGateCalls == 0);
        delete instance;
    }
}
"""


def main() -> None:
    source = SOURCE.read_text()
    stop = production_function(
        source, "bool AirportItlwmSkywalkInterface::stopNative()")
    release = production_function(
        source, "void AirportItlwmSkywalkInterface::releaseNative()")
    with tempfile.TemporaryDirectory(prefix="native-security-stop-") as tmp:
        tmp_path = Path(tmp)
        harness = tmp_path / "test.cpp"
        binary = tmp_path / "test"
        harness.write_text(PREFIX + "\n" + stop + "\n" + release + "\n" + CASES)
        subprocess.run(
            [
                "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT), str(harness),
                str(ROOT / "native/wcl_backend.cpp"),
                str(ROOT / "native/wcl_wire.cpp"), "-o", str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print("PASS: production NativeStop/release ownership and gated credential cleanup (ASan/UBSan)")


if __name__ == "__main__":
    main()
