#!/usr/bin/env python3
"""Compile actual Test087 arm/stop source fragments under deterministic races."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ARM_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
STOP_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and following == "/":
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
            if char == "/" and following == "/":
                state = "line"
                index += 1
            elif char == "/" and following == "*":
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
                    return source[start : index + 1]
        index += 1
    raise AssertionError("unterminated production function: " + marker)


def extract_statement(source: str, marker: str) -> str:
    start = source.index(marker)
    end = source.index(";", start)
    return source[start : end + 1]


def make_harness() -> str:
    arm_source = ARM_SOURCE.read_text()
    stop_source = STOP_SOURCE.read_text()
    stop_serial_sample = extract_statement(
        arm_source,
        "const uint64_t observerStopSerial = __atomic_load_n(",
    )
    arm_fragment = extract_function(
        arm_source,
        'if (controller->getProperty("NativeRxPreOwnerObservation") == kOSBooleanTrue)',
    )
    stop_function = extract_function(
        stop_source,
        "void ItlIwx::tahoeRxPreOwnerStop()",
    )
    return r'''#include <assert.h>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <thread>
#include <type_traits>

#include "native/rx_preowner_observation.hpp"

using namespace NativeRxPreOwner;
static constexpr uint32_t IWX_FLAG_SHUTDOWN = 0x20u;
static int gBooleanToken;
static void *const kOSBooleanTrue = &gBooleanToken;
static uint64_t gClockAbsoluteNs = 1000000ULL;
static uint64_t gMonotonicNs = 1200000ULL;

class Gate {
public:
    void pause() {
        std::unique_lock<std::mutex> lock(mutex_);
        entered_ = true;
        condition_.notify_all();
        condition_.wait(lock, [&] { return released_; });
    }
    void waitEntered() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [&] { return entered_; });
    }
    void release() {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        condition_.notify_all();
    }
private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool entered_ = false;
    bool released_ = false;
};

static Gate *gClockGate = nullptr;
static std::function<void()> gAfterArmedStore;
static const volatile void *gArmedAddress = nullptr;

static void clock_get_uptime(uint64_t *absolute) {
    if (gClockGate)
        gClockGate->pause();
    *absolute = gClockAbsoluteNs;
}
static void absolutetime_to_nanoseconds(uint64_t absolute, uint64_t *nanos) {
    *nanos = absolute;
}
static uint64_t tahoeMonotonicNs() { return gMonotonicNs; }

template <typename T, typename V>
static void interceptedAtomicStore(T *address, V value, int order) {
    using Value = typename std::remove_volatile<T>::type;
    __atomic_store_n(address, static_cast<Value>(value), order);
    if (reinterpret_cast<const volatile void *>(address) == gArmedAddress &&
        static_cast<uint64_t>(value) == 1 && gAfterArmedStore)
        gAfterArmedStore();
}

#define __atomic_store_n(address, value, order) \
    interceptedAtomicStore((address), (value), (order))

struct FakeController {
    bool enabled = true;
    uint32_t armAccepted = 99;
    void *getProperty(const char *) {
        return enabled ? kOSBooleanTrue : nullptr;
    }
    bool setProperty(const char *, uint64_t value, uint32_t) {
        armAccepted = static_cast<uint32_t>(value);
        return true;
    }
};

class ObserverProxy {
public:
    Observer observer;
    std::function<void(bool)> afterBegin;
    uint32_t closeCalls = 0;

    bool begin(uint64_t nowUs, uint32_t generation) {
        const bool result = observer.begin(nowUs, generation);
        if (afterBegin)
            afterBegin(result);
        return result;
    }
    bool enabled() const { return observer.enabled(); }
    bool close(uint64_t nowUs, CloseReason reason) {
        ++closeCalls;
        return observer.close(nowUs, reason);
    }
    bool snapshot(uint64_t nowUs, Snapshot *out) {
        return observer.snapshot(nowUs, out);
    }
};

class ItlIwx {
public:
    ObserverProxy nativeRxPreOwner_;
    volatile uint32_t nativeRxPreOwnerArmed_ = 0;
    volatile uint64_t nativeRxPreOwnerStopSerial_ = 0;
    uint32_t nativeRxPreOwnerStopDepth_ = 0;
    volatile uint32_t nativeLifecycleTearingDown_ = 0;
    struct {
        volatile uint32_t sc_generation = 7;
        volatile uint32_t sc_flags = 0;
    } com;

    void runArm(FakeController *controller) {
        @@STOP_SERIAL_SAMPLE@@
        @@ARM_FRAGMENT@@
    }
    void tahoeRxPreOwnerStop();
};

@@PRODUCTION_STOP_FUNCTION@@
#undef __atomic_store_n

static void check(bool value, const char *message) {
    if (!value) {
        std::fprintf(stderr, "FAIL Test087 arm-stop: %s\n", message);
        std::abort();
    }
}

static Snapshot snapshotAt(ItlIwx &owner, uint64_t nowUs) {
    Snapshot snapshot{};
    check(owner.nativeRxPreOwner_.snapshot(nowUs, &snapshot), "snapshot available");
    return snapshot;
}

static void checkStopped(ItlIwx &owner, FakeController &controller,
                         uint32_t expectedCloseCalls, const char *label) {
    const Snapshot snapshot = snapshotAt(owner, 2000);
    check(snapshot.closed == 1 && snapshot.active == 0, label);
    check(snapshot.closeReason == CloseReason::Stop, "stop close reason preserved");
    check(owner.nativeRxPreOwnerArmed_ == 1, "arm latch is not cleared by stop");
    check(controller.armAccepted == 0, "cancelled arm is not acknowledged ready");
    check(owner.nativeRxPreOwner_.closeCalls == expectedCloseCalls,
          "expected close call count");
}

static void testNormalArm() {
    ItlIwx owner;
    FakeController controller;
    gArmedAddress = &owner.nativeRxPreOwnerArmed_;
    owner.runArm(&controller);
    const Snapshot snapshot = snapshotAt(owner, 1100);
    check(snapshot.active == 1 && snapshot.closed == 0, "normal arm stays active");
    check(controller.armAccepted == 1, "normal arm reports ready");
    check(owner.nativeRxPreOwnerArmed_ == 1, "normal arm publishes armed latch");
    check(owner.nativeRxPreOwnerStopSerial_ == 0, "normal arm stop serial unchanged");
    gArmedAddress = nullptr;
}

static void testStopBetweenSerialSampleAndBegin() {
    ItlIwx owner;
    FakeController controller;
    Gate clockGate;
    gArmedAddress = &owner.nativeRxPreOwnerArmed_;
    gClockGate = &clockGate;
    std::thread armer([&] { owner.runArm(&controller); });
    clockGate.waitEntered();
    owner.tahoeRxPreOwnerStop();
    clockGate.release();
    armer.join();
    gClockGate = nullptr;
    checkStopped(owner, controller, 1, "stop before begin is closed after begin");
    check(owner.nativeRxPreOwnerStopSerial_ == 1, "pre-begin stop advances serial");
    gArmedAddress = nullptr;
}

static void testStopAfterBeginBeforeArmedPublication() {
    ItlIwx owner;
    FakeController controller;
    Gate beginGate;
    gArmedAddress = &owner.nativeRxPreOwnerArmed_;
    owner.nativeRxPreOwner_.afterBegin = [&](bool result) {
        check(result, "observer begin succeeded before interleaved stop");
        beginGate.pause();
    };
    std::thread armer([&] { owner.runArm(&controller); });
    beginGate.waitEntered();
    check(owner.nativeRxPreOwnerArmed_ == 0, "Armed is still unpublished");
    owner.tahoeRxPreOwnerStop();
    check(owner.nativeRxPreOwner_.closeCalls == 0,
          "stop before Armed does not close an unpublished observer");
    beginGate.release();
    armer.join();
    checkStopped(owner, controller, 1, "post-begin stop is detected after Armed");
    owner.nativeRxPreOwner_.afterBegin = {};
    gArmedAddress = nullptr;
}

static void testStopAfterArmedPublication() {
    ItlIwx owner;
    FakeController controller;
    Gate armedGate;
    gArmedAddress = &owner.nativeRxPreOwnerArmed_;
    gAfterArmedStore = [&] { armedGate.pause(); };
    std::thread armer([&] { owner.runArm(&controller); });
    armedGate.waitEntered();
    check(owner.nativeRxPreOwnerArmed_ == 1, "Armed is visible before stop");
    owner.tahoeRxPreOwnerStop();
    check(owner.nativeRxPreOwner_.closeCalls == 1,
          "stop after Armed closes observer immediately");
    armedGate.release();
    armer.join();
    checkStopped(owner, controller, 2,
                 "arming recheck tolerates an observer already closed by stop");
    gAfterArmedStore = {};
    gArmedAddress = nullptr;
}

static void testTeardownBeforeAndAfterArmed() {
    {
        ItlIwx owner;
        FakeController controller;
        owner.nativeLifecycleTearingDown_ = 1;
        gArmedAddress = &owner.nativeRxPreOwnerArmed_;
        owner.runArm(&controller);
        check(owner.nativeRxPreOwnerArmed_ == 0,
              "teardown before ARM entry blocks observer begin");
        check(controller.armAccepted == 0,
              "teardown before ARM entry is not acknowledged");
        Snapshot snapshot{};
        check(!owner.nativeRxPreOwner_.snapshot(1100, &snapshot),
              "teardown before ARM entry creates no capture");
        check(owner.nativeRxPreOwner_.closeCalls == 0,
              "teardown before ARM entry needs no close call");
        gArmedAddress = nullptr;
    }
    {
        ItlIwx owner;
        FakeController controller;
        gArmedAddress = &owner.nativeRxPreOwnerArmed_;
        gAfterArmedStore = [&] { owner.nativeLifecycleTearingDown_ = 1; };
        owner.runArm(&controller);
        checkStopped(owner, controller, 1,
                     "teardown after Armed is detected without serial change");
        gAfterArmedStore = {};
        gArmedAddress = nullptr;
    }
}

static void testFailedBeginDoesNotClearExistingArmed() {
    ItlIwx owner;
    FakeController controller;
    check(owner.nativeRxPreOwner_.observer.begin(900, 7),
          "seed one-shot observer before failed begin");
    owner.nativeRxPreOwnerArmed_ = 1;
    gArmedAddress = &owner.nativeRxPreOwnerArmed_;
    owner.runArm(&controller);
    check(owner.nativeRxPreOwnerArmed_ == 1,
          "failed begin does not clear an existing Armed latch");
    check(controller.armAccepted == 0,
          "failed begin is not reported as a ready observer");
    const Snapshot snapshot = snapshotAt(owner, 1100);
    check(snapshot.active == 1 && snapshot.closed == 0,
          "failed repeat begin leaves original capture intact");
    check(owner.nativeRxPreOwner_.closeCalls == 0,
          "failed begin does not close existing capture");
    gArmedAddress = nullptr;
}

static void testStopBeforeEntryWithShutdownSet() {
    ItlIwx owner;
    FakeController controller;
    owner.tahoeRxPreOwnerStop();
    owner.com.sc_flags = IWX_FLAG_SHUTDOWN;
    check(owner.nativeRxPreOwnerStopSerial_ == 1,
          "stop before arm advances serial");
    owner.runArm(&controller);
    check(owner.nativeRxPreOwnerStopSerial_ == 1,
          "ARM samples the already-advanced stop serial");
    check(owner.nativeRxPreOwnerStopDepth_ == 0,
          "stop operation has already returned");
    check(owner.nativeRxPreOwnerArmed_ == 0,
          "shutdown at ARM entry blocks observer begin");
    check(controller.armAccepted == 0,
          "shutdown at ARM entry is not acknowledged");
    Snapshot snapshot{};
    check(!owner.nativeRxPreOwner_.snapshot(1100, &snapshot),
          "shutdown at ARM entry creates no observer capture");
}

static void testNestedStopActivityBlocksArmAndReturnsDepthToZero() {
    ItlIwx owner;
    FakeController controller;
    {
        NativeRxPreOwner::StopActivity outer(&owner.nativeRxPreOwnerStopDepth_);
        check(__atomic_load_n(&owner.nativeRxPreOwnerStopDepth_, __ATOMIC_ACQUIRE) == 1,
              "outer StopActivity increments depth");
        {
            NativeRxPreOwner::StopActivity inner(&owner.nativeRxPreOwnerStopDepth_);
            check(__atomic_load_n(&owner.nativeRxPreOwnerStopDepth_, __ATOMIC_ACQUIRE) == 2,
                  "nested StopActivity increments depth");
            owner.runArm(&controller);
            check(owner.nativeRxPreOwnerArmed_ == 0,
                  "nonzero stop depth blocks observer begin");
            check(controller.armAccepted == 0,
                  "nonzero stop depth is not acknowledged");
            Snapshot snapshot{};
            check(!owner.nativeRxPreOwner_.snapshot(1100, &snapshot),
                  "nonzero stop depth creates no observer capture");
        }
        check(__atomic_load_n(&owner.nativeRxPreOwnerStopDepth_, __ATOMIC_ACQUIRE) == 1,
              "inner StopActivity decrements depth once");
    }
    check(__atomic_load_n(&owner.nativeRxPreOwnerStopDepth_, __ATOMIC_ACQUIRE) == 0,
          "nested StopActivity leaves depth at zero");
    owner.runArm(&controller);
    check(owner.nativeRxPreOwnerArmed_ == 1,
          "ARM is allowed after every StopActivity scope exits");
    check(controller.armAccepted == 1,
          "observer reports ready after stop depth returns to zero");
    const Snapshot snapshot = snapshotAt(owner, 1100);
    check(snapshot.active == 1 && snapshot.closed == 0,
          "post-stop-depth ARM starts a fresh capture");
}

int main() {
    std::fprintf(stderr, "normal\n");
    testNormalArm();
    std::fprintf(stderr, "stop-before-begin\n");
    testStopBetweenSerialSampleAndBegin();
    std::fprintf(stderr, "stop-before-armed\n");
    testStopAfterBeginBeforeArmedPublication();
    std::fprintf(stderr, "stop-after-armed\n");
    testStopAfterArmedPublication();
    std::fprintf(stderr, "teardown\n");
    testTeardownBeforeAndAfterArmed();
    std::fprintf(stderr, "failed-begin\n");
    testFailedBeginDoesNotClearExistingArmed();
    testStopBeforeEntryWithShutdownSet();
    testNestedStopActivityBlocksArmAndReturnsDepthToZero();
    std::puts("PASS Test087 arm-stop interleavings");
    return 0;
}
'''.replace("@@STOP_SERIAL_SAMPLE@@", stop_serial_sample).replace(
        "@@ARM_FRAGMENT@@", arm_fragment
    ).replace("@@PRODUCTION_STOP_FUNCTION@@", stop_function)


class ArmStopInterleavings(unittest.TestCase):
    def test_production_arm_stop_fragments_under_deterministic_interleavings(self):
        compiler = shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "clang++ or g++ required")
        with tempfile.TemporaryDirectory(prefix="test087-arm-stop-") as temp:
            source_path = Path(temp) / "test087_arm_stop.cpp"
            binary = Path(temp) / "test087_arm_stop"
            source_path.write_text(make_harness())
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-O1",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-pthread",
                    "-I",
                    str(ROOT),
                    str(source_path),
                    "-o",
                    str(binary),
                ],
                check=True,
                cwd=ROOT,
            )
            try:
                completed = subprocess.run(
                    [str(binary)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=10,
                    cwd=ROOT,
                )
            except subprocess.TimeoutExpired as error:
                output = error.stdout
                if isinstance(output, bytes):
                    output = output.decode("utf-8", "replace")
                self.fail("interleaving fixture hung after: " + str(output))
            except subprocess.CalledProcessError as error:
                self.fail("interleaving fixture failed: " + str(error.stdout))
            self.assertIn("PASS Test087 arm-stop interleavings", completed.stdout)


if __name__ == "__main__":
    unittest.main()
