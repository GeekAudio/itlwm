#!/usr/bin/env python3
"""Compile the actual ROC sync method with an offline gate/epoch shim."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def function(source: str, marker: str) -> str:
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
    raise AssertionError(f"unterminated function: {marker}")


SYNC = function(DRIVER.read_text(),
                "void ItlIwx::tahoeRxRocCorrelationSync(uint64_t nowUs)")

for required in (
    "!tahoeP2pOnMainGate()",
    "nativeRxRocArmReady_",
    "com.sc_device_family",
    "nativeRxPreOwnerStopSerial_",
    "nativeRxPreOwnerStopDepth_",
    "CloseReason::kGenerationChanged",
    "session.outcomeUnknown",
    "session.commandResult != 0",
    "CloseReason::kDeadline",
    "closeNoStart(nowUs)",
):
    assert required in SYNC, f"sync method no longer contains {required!r}"
for forbidden in ("copySnapshot(", "beginSlot(",
                  "NativeIwxCompletionObserver::CopyResult"):
    assert forbidden not in SYNC, f"sync unexpectedly reads/captures RX data: {forbidden}"


HARNESS = r"""
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <thread>

#include "native/iwx_roc_rx_correlation.hpp"

namespace NativeRxPreOwner {
static const uint32_t kCaptureSerial = 17;
}

struct FakeFirmwareCom {
    uint32_t sc_device_family = 2;
    uint32_t sc_generation = 11;
};

struct FakeLease {
    uint32_t contextGeneration = 6;
    uint32_t powerGeneration = 11;
    uint32_t stationGeneration = 23;
};

struct FakeSessionSnapshot {
    uint32_t generation = 6;
    bool outcomeUnknown = false;
    bool commandReturned = false;
    int commandResult = 0;
};

struct FakeSessionTracker {
    FakeSessionSnapshot current;
    FakeSessionSnapshot snapshot() const { return current; }
};

struct FakePreOwner {
    std::atomic<bool> isEnabled{false};
    bool enabled() const { return isEnabled.load(std::memory_order_acquire); }
};

class ItlIwx {
public:
    bool tahoeP2pOnMainGate() const { return mainGateHeld; }
    void tahoeRxRocCorrelationSync(uint64_t nowUs);

    bool mainGateHeld = false;
    FakeFirmwareCom com;
    FakePreOwner nativeRxPreOwner_;
    FakeLease tahoe_p2p_rx_lease_;
    FakeSessionTracker nativeP2pRocEvents_;
    NativeIwxRocRxCorrelation::Recorder nativeRxRocCorrelation_{};
    NativeIwxRocRxCorrelation::RocEpoch nativeRxRocEpoch_{};
    uint64_t nativeRxRocDeadlineUs_ = 97000;
    uint64_t nativeRxPreOwnerStopSerial_ = 91;
    uint32_t nativeRxPreOwnerStopDepth_ = 0;
    uint64_t nativeRxRocArmUs_ = 1000;
    uint64_t nativeRxRocArmStopSerial_ = 91;
    uint32_t nativeRxRocArmGeneration_ = 11;
    uint32_t nativeRxRocArmReady_ = 1;
};

""" + SYNC + r"""

using namespace NativeIwxRocRxCorrelation;

static RocEpoch matchingEpoch()
{
    RocEpoch epoch;
    epoch.contextGeneration = 6;
    epoch.powerGeneration = 11;
    epoch.stationGeneration = 23;
    epoch.rocGeneration = 6;
    epoch.sessionToken = 0x1234;
    return epoch;
}

static void setArmReady(ItlIwx &owner, uint32_t ready)
{
    __atomic_store_n(&owner.nativeRxRocArmReady_, ready, __ATOMIC_RELEASE);
}

static void setStopSerial(ItlIwx &owner, uint64_t value)
{
    __atomic_store_n(&owner.nativeRxPreOwnerStopSerial_, value,
                     __ATOMIC_RELEASE);
}

static void setStopDepth(ItlIwx &owner, uint32_t value)
{
    __atomic_store_n(&owner.nativeRxPreOwnerStopDepth_, value,
                     __ATOMIC_RELEASE);
}

static void runOnGate(ItlIwx &owner, uint64_t nowUs)
{
    assert(!owner.mainGateHeld);
    owner.mainGateHeld = true;
    owner.tahoeRxRocCorrelationSync(nowUs);
    owner.mainGateHeld = false;
}

static void configure(ItlIwx &owner)
{
    owner.com.sc_generation = 11;
    owner.nativeRxRocArmGeneration_ = 11;
    owner.nativeRxRocArmUs_ = 1000;
    owner.nativeRxRocArmStopSerial_ = 91;
    setStopSerial(owner, 91);
    setStopDepth(owner, 0);
    setArmReady(owner, 1);
    owner.nativeRxPreOwner_.isEnabled.store(true, std::memory_order_release);
    owner.nativeRxRocEpoch_ = matchingEpoch();
    owner.nativeRxRocDeadlineUs_ = 97000;
    owner.tahoe_p2p_rx_lease_.contextGeneration = 6;
    owner.tahoe_p2p_rx_lease_.powerGeneration = 11;
    owner.tahoe_p2p_rx_lease_.stationGeneration = 23;
    owner.nativeP2pRocEvents_.current.generation = 6;
    owner.nativeP2pRocEvents_.current.outcomeUnknown = false;
    owner.nativeP2pRocEvents_.current.commandReturned = false;
    owner.nativeP2pRocEvents_.current.commandResult = 0;
}

static void armAndStart(ItlIwx &owner)
{
    configure(owner);
    runOnGate(owner, 1500);
    assert(owner.nativeRxRocCorrelation_.state() == State::kArmed);
    assert(owner.nativeRxRocCorrelation_.beginRoc(
        owner.nativeRxRocEpoch_, 2000, owner.nativeRxRocDeadlineUs_));
    assert(owner.nativeRxRocCorrelation_.state() == State::kActive);
}

static void expectClosed(ItlIwx &owner, CloseReason reason)
{
    assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    assert(owner.nativeRxRocCorrelation_.closeReason() == reason);
}

static uint32_t readCoverage(const uint8_t *wire)
{
    return uint32_t(wire[120]) | (uint32_t(wire[121]) << 8) |
        (uint32_t(wire[122]) << 16) | (uint32_t(wire[123]) << 24);
}

static void testOffGateAndUnreleasedArmMetadata()
{
    ItlIwx offGate;
    configure(offGate);
    offGate.tahoeRxRocCorrelationSync(1500);
    assert(offGate.nativeRxRocCorrelation_.state() == State::kDisabled);

    ItlIwx notReleased;
    configure(notReleased);
    setArmReady(notReleased, 0);
    runOnGate(notReleased, 1500);
    assert(notReleased.nativeRxRocCorrelation_.state() == State::kDisabled);
    std::cout << "PASS off-gate and arm-release checks\n";
}

static void testLazyArmAndNoStart()
{
    ItlIwx lazy;
    configure(lazy);
    runOnGate(lazy, 1500);
    assert(lazy.nativeRxRocCorrelation_.state() == State::kArmed);

    ItlIwx noStart;
    configure(noStart);
    noStart.nativeRxPreOwner_.isEnabled.store(false,
                                               std::memory_order_release);
    runOnGate(noStart, 1600);
    expectClosed(noStart, CloseReason::kNoStart);
    assert(noStart.nativeRxRocCorrelation_.readyToEncode());
    std::cout << "PASS lazy arm and explicit no-start close\n";
}

static void testStopSerialAndDepthCloseArmedRecorder()
{
    ItlIwx serial;
    configure(serial);
    // The stop is visible before the gate callback. Sync lazily arms first,
    // then observes the stop serial and closes that newly armed recorder.
    setStopSerial(serial, 92);
    runOnGate(serial, 1500);
    expectClosed(serial, CloseReason::kStop);

    ItlIwx depth;
    configure(depth);
    setStopDepth(depth, 1);
    runOnGate(depth, 1500);
    expectClosed(depth, CloseReason::kStop);
    std::cout << "PASS stop serial/depth close after lazy arm\n";
}

static void testStopPublishedAcrossGateTurns(bool viaSerial)
{
    // Simulate a cross-gate stop publication while the owner keeps servicing
    // main-gate turns. Only the stop fields cross threads, using the same
    // acquire/release operations as the real helper.
    ItlIwx owner;
    configure(owner);
    std::atomic<bool> begin{false};
    std::thread stopper([&] {
        while (!begin.load(std::memory_order_acquire))
            std::this_thread::yield();
        if (viaSerial)
            setStopSerial(owner, 92);
        else
            setStopDepth(owner, 1);
    });
    begin.store(true, std::memory_order_release);
    for (unsigned turn = 0; turn < 10000 &&
         owner.nativeRxRocCorrelation_.state() != State::kClosed; ++turn) {
        runOnGate(owner, 1500 + turn);
        std::this_thread::yield();
    }
    stopper.join();
    if (owner.nativeRxRocCorrelation_.state() != State::kClosed)
        runOnGate(owner, 16000);
    expectClosed(owner, CloseReason::kStop);
    std::cout << "PASS atomic stop publication across gate turns ("
              << (viaSerial ? "serial" : "depth") << ")\n";
}

static void testArmGenerationMismatch()
{
    ItlIwx owner;
    configure(owner);
    owner.com.sc_generation = 12;
    runOnGate(owner, 1500);
    expectClosed(owner, CloseReason::kGenerationChanged);
    std::cout << "PASS arm/driver generation mismatch\n";
}

static void testUnsupportedFamiliesCloseIncompleteWithoutCopyReads()
{
    for (uint32_t family : {1u, 3u}) {
        ItlIwx owner;
        armAndStart(owner);
        owner.com.sc_device_family = family;
        runOnGate(owner, 3000);
        expectClosed(owner, CloseReason::kInvalidBoundary);
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
        assert(owner.nativeRxRocCorrelation_.fullSlots() == 0);
        assert(owner.nativeRxRocCorrelation_.retained() == 0);
        uint8_t wire[kWireBytes] = {};
        assert(owner.nativeRxRocCorrelation_.encode(wire, sizeof(wire)));
        assert(readCoverage(wire) == 0);
    }
    std::cout << "PASS unsupported families close incomplete with no core slots/copy reads\n";
}

static void testActiveLeaseAndSessionEpochChanges()
{
    for (unsigned field = 0; field < 4; ++field) {
        ItlIwx owner;
        armAndStart(owner);
        switch (field) {
        case 0: ++owner.tahoe_p2p_rx_lease_.contextGeneration; break;
        case 1: ++owner.tahoe_p2p_rx_lease_.powerGeneration; break;
        case 2: ++owner.tahoe_p2p_rx_lease_.stationGeneration; break;
        case 3: ++owner.nativeP2pRocEvents_.current.generation; break;
        }
        runOnGate(owner, 3000);
        expectClosed(owner, CloseReason::kGenerationChanged);
    }
    std::cout << "PASS active lease/session epoch changes\n";
}

static void testCommandFailureAndUnknownOutcome()
{
    ItlIwx commandError;
    armAndStart(commandError);
    commandError.nativeP2pRocEvents_.current.commandReturned = true;
    commandError.nativeP2pRocEvents_.current.commandResult = -5;
    runOnGate(commandError, 3000);
    expectClosed(commandError, CloseReason::kInvalidBoundary);

    ItlIwx unknown;
    armAndStart(unknown);
    unknown.nativeP2pRocEvents_.current.outcomeUnknown = true;
    runOnGate(unknown, 3000);
    expectClosed(unknown, CloseReason::kInvalidBoundary);
    std::cout << "PASS command error and unknown outcome close\n";
}

static void testDeadlineAndPreOwnerLoss()
{
    ItlIwx deadline;
    armAndStart(deadline);
    runOnGate(deadline, deadline.nativeRxRocDeadlineUs_);
    expectClosed(deadline, CloseReason::kDeadline);

    ItlIwx lostOwner;
    armAndStart(lostOwner);
    lostOwner.nativeRxPreOwner_.isEnabled.store(false,
                                                std::memory_order_release);
    runOnGate(lostOwner, 3000);
    expectClosed(lostOwner, CloseReason::kInvalidBoundary);
    std::cout << "PASS deadline and active pre-owner loss\n";
}

static void testClosedWireIsStableAcrossLaterSync()
{
    ItlIwx owner;
    armAndStart(owner);
    assert(owner.nativeRxRocCorrelation_.endRoc(
        owner.nativeRxRocEpoch_, 4000));
    uint8_t before[kWireBytes] = {};
    uint8_t after[kWireBytes] = {};
    assert(owner.nativeRxRocCorrelation_.encode(before, sizeof(before)));

    setStopSerial(owner, 999);
    owner.com.sc_generation = 999;
    owner.tahoe_p2p_rx_lease_.contextGeneration = 999;
    owner.nativeP2pRocEvents_.current.generation = 999;
    runOnGate(owner, 5000);
    assert(owner.nativeRxRocCorrelation_.encode(after, sizeof(after)));
    assert(std::memcmp(before, after, sizeof(before)) == 0);
    std::cout << "PASS closed snapshot remains byte-stable\n";
}

static void testStopClosedPendingTokenCanFinalizeAndEncode()
{
    ItlIwx owner;
    armAndStart(owner);
    NativeIwxCompletionObserver::CopyResult copy;
    copy.status = NativeIwxCompletionObserver::CopyStatus::kCopied;
    copy.snapshot.incarnation = 44;
    SlotInput input;
    input.captureSerial = NativeRxPreOwner::kCaptureSerial;
    input.driverGeneration = 11;
    input.ring = 0;
    input.slot = 188;
    input.head = 189;
    input.copyTimeUs = 2500;
    input.copySequence = 66;
    input.epoch = owner.nativeRxRocEpoch_;
    Token token = owner.nativeRxRocCorrelation_.beginSlot(input, copy);
    assert(token.valid);

    setStopDepth(owner, 1);
    runOnGate(owner, 3000);
    expectClosed(owner, CloseReason::kStop);
    uint8_t wire[kWireBytes] = {};
    assert(!owner.nativeRxRocCorrelation_.encode(wire, sizeof(wire)));
    assert(owner.nativeRxRocCorrelation_.finishSlot(token));
    assert(owner.nativeRxRocCorrelation_.readyToEncode());
    assert(owner.nativeRxRocCorrelation_.encode(wire, sizeof(wire)));
    assert(readCoverage(wire) == 0);
    assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kStop);
    std::cout << "PASS pending token finalizes after stop close; coverage false\n";
}

int main()
{
    testOffGateAndUnreleasedArmMetadata();
    testLazyArmAndNoStart();
    testStopSerialAndDepthCloseArmedRecorder();
    testStopPublishedAcrossGateTurns(true);
    testStopPublishedAcrossGateTurns(false);
    testArmGenerationMismatch();
    testUnsupportedFamiliesCloseIncompleteWithoutCopyReads();
    testActiveLeaseAndSessionEpochChanges();
    testCommandFailureAndUnknownOutcome();
    testDeadlineAndPreOwnerLoss();
    testClosedWireIsStableAcrossLaterSync();
    testStopClosedPendingTokenCanFinalizeAndEncode();
}
"""


class RocCorrelationSyncTests(unittest.TestCase):
    def test_extracted_sync_method_under_asan_ubsan(self):
        with tempfile.TemporaryDirectory(prefix="test096-roc-sync-") as temp:
            temp = Path(temp)
            source = temp / "sync.cpp"
            binary = temp / "sync"
            source.write_text(HARNESS)
            compiler = os.environ.get("CXX", "clang++")
            subprocess.run([
                compiler,
                "-std=c++14",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
                "-pthread",
                "-I",
                str(ROOT),
                str(source),
                "-o",
                str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True, timeout=20, env={
                **os.environ,
                "ASAN_OPTIONS": "halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            })


if __name__ == "__main__":
    unittest.main()
