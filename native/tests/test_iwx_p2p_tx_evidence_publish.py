#!/usr/bin/env python3
"""Execute the production command-gate callback/wrapper with distinct owners."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()


def extract_function(marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


callback = extract_function(
    "static IOReturn publishNativeP2PTxTimeEvidenceAction(")
request = extract_function(
    "static void requestNativeP2PTxTimeEvidencePublish(")

shim = r"""
#include <cassert>
#include <cstdint>

using IOReturn = int;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnBadArgument = -1;

struct OSObject { virtual ~OSObject() = default; };
struct TahoeP2PActionTxWindowEvidence {
    uint64_t snapshotVersion = 0;
    uint64_t lastPublishedSnapshotVersion = 0;
};
struct TahoeP2PActionTxContext {
    TahoeP2PActionTxWindowEvidence windowEvidence;
};

class ItlIwx;
using GateAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);

class IOCommandGate {
public:
    explicit IOCommandGate(OSObject *gateOwner) : owner(gateOwner) {}
    OSObject *owner;
    ItlIwx *hal = nullptr;
    unsigned calls = 0;
    void *lastArg0 = nullptr;
    OSObject *lastTarget = nullptr;
    IOReturn runAction(GateAction action, void *arg0,
                       void *arg1 = nullptr, void *arg2 = nullptr,
                       void *arg3 = nullptr);
};

class ItlIwx : public OSObject {
public:
    TahoeP2PActionTxContext nativeP2pActionTx_;
    IOCommandGate *gate = nullptr;
    bool insideMainGate = false;
    bool tahoeP2pOnMainGate() const { return insideMainGate; }
    IOCommandGate *tahoeP2pCommandGate() const { return gate; }
};

IOReturn IOCommandGate::runAction(GateAction action, void *arg0,
                                  void *arg1, void *arg2, void *arg3)
{
    ++calls;
    lastTarget = owner;
    lastArg0 = arg0;
    const bool previousGateState = hal->insideMainGate;
    hal->insideMainGate = true;
    const IOReturn result = action(owner, arg0, arg1, arg2, arg3);
    hal->insideMainGate = previousGateState;
    return result;
}

static ItlIwx *gPublishedOwner = nullptr;
static unsigned gPublishCount = 0;
static void publishNativeP2PTxTimeEvidenceOnMainGate(ItlIwx *owner)
{
    assert(owner && owner->tahoeP2pOnMainGate());
    gPublishedOwner = owner;
    ++gPublishCount;
}
"""

body = r"""
int main()
{
    OSObject airportItlwmGateOwner;
    ItlIwx hal;
    IOCommandGate gate(&airportItlwmGateOwner);
    gate.hal = &hal;
    hal.gate = &gate;
    hal.nativeP2pActionTx_.windowEvidence.snapshotVersion = 2;

    // The gate target belongs to AirportItlwm and is intentionally not HAL.
    requestNativeP2PTxTimeEvidencePublish(&hal);
    assert(gate.calls == 1);
    assert(gate.lastTarget == &airportItlwmGateOwner);
    assert(gate.lastTarget != static_cast<OSObject *>(&hal));
    assert(gate.lastArg0 == &hal);
    assert(gPublishedOwner == &hal && gPublishCount == 1);

    // Missing HAL arg and a HAL call outside the main gate are rejected.
    assert(publishNativeP2PTxTimeEvidenceAction(
        &airportItlwmGateOwner, nullptr, nullptr, nullptr, nullptr) ==
        kIOReturnBadArgument);
    ItlIwx offGateHal;
    assert(publishNativeP2PTxTimeEvidenceAction(
        &airportItlwmGateOwner, &offGateHal, nullptr, nullptr, nullptr) ==
        kIOReturnBadArgument);
    assert(gPublishCount == 1);

    // The direct in-gate fast path publishes HAL without consulting a gate
    // whose owner/type might differ (or whose pointer is absent).
    hal.gate = nullptr;
    hal.insideMainGate = true;
    hal.nativeP2pActionTx_.windowEvidence.snapshotVersion = 4;
    hal.nativeP2pActionTx_.windowEvidence.lastPublishedSnapshotVersion = 2;
    requestNativeP2PTxTimeEvidencePublish(&hal);
    assert(gate.calls == 1);
    assert(gPublishedOwner == &hal && gPublishCount == 2);
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="itlwm-p2p-evidence-publish-") as directory:
    cpp = Path(directory) / "publish_callback_test.cpp"
    binary = Path(directory) / "publish_callback_test"
    cpp.write_text(shim + "\n" + callback + "\n" + request + "\n" + body)
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", str(cpp), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)

print("PASS: production evidence callback routes HAL arg through distinct gate owner")
