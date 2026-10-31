#!/usr/bin/env python3
"""Execute the actual Tahoe RX completion publisher with a host gate shim."""

from pathlib import Path
import hashlib
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
DRIVER_PATH = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
DRIVER = DRIVER_PATH.read_text()


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
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {marker}")


ACTION = function(DRIVER, "IOReturn ItlIwx::tahoeRxCompletionPublishAction(")
PUBLISH = function(DRIVER, "void ItlIwx::tahoeRxCompletionPublish(")

assert "owner->tahoeP2pOnMainGate()" in ACTION
assert "if (!tahoeP2pOnMainGate())" in PUBLISH
assert "gate->attemptAction(tahoeRxCompletionPublishAction" in PUBLISH
assert "nativeRxPreOwner_.enabled()" in PUBLISH
assert "snapshotTelemetry(" in PUBLISH
assert "nativeRxCompletionPublishAttempted_ = true;" in PUBLISH


HARNESS = r"""
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#include "native/iwx_completion_observer.hpp"

using IOReturn = int32_t;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnNotReady = int32_t(0xe00002d8);
static constexpr IOReturn kIOReturnCannotLock = int32_t(0xe00002cc);

struct OSObject {
    virtual ~OSObject() = default;
};

class IOEthernetController : public OSObject {
public:
    bool setProperty(const char *, class OSData *);
    unsigned propertyWrites = 0;
    std::vector<uint8_t> value;
};

class OSData {
public:
    static OSData *withBytes(const void *bytes, unsigned length)
    {
        ++allocations;
        const auto *begin = static_cast<const uint8_t *>(bytes);
        return new OSData(std::vector<uint8_t>(begin, begin + length));
    }
    void release() { delete this; }
    const std::vector<uint8_t> bytes;
    static unsigned allocations;
private:
    explicit OSData(std::vector<uint8_t> data) : bytes(std::move(data)) {}
};

unsigned OSData::allocations = 0;

bool IOEthernetController::setProperty(const char *, OSData *data)
{
    assert(data != nullptr);
    ++propertyWrites;
    value = data->bytes;
    return true;
}

class IOCommandGate {
public:
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);

    IOReturn attemptAction(Action action, void *arg0, void *arg1)
    {
        ++attempts;
        std::unique_lock<std::mutex> guard(mutex_, std::try_to_lock);
        if (!guard.owns_lock()) {
            ++busyReturns;
            return kIOReturnCannotLock;
        }
        assert(currentGate_ == nullptr);
        currentGate_ = this;
        const IOReturn result = action(nullptr, arg0, arg1, nullptr, nullptr);
        currentGate_ = nullptr;
        return result;
    }

    bool inGate() const { return currentGate_ == this; }

    void runRx(const std::function<void()> &callback)
    {
        std::lock_guard<std::mutex> guard(mutex_);
        assert(currentGate_ == nullptr);
        currentGate_ = this;
        callback();
        currentGate_ = nullptr;
    }

    unsigned attempts = 0;
    unsigned busyReturns = 0;
private:
    std::mutex mutex_;
    static thread_local IOCommandGate *currentGate_;
};

thread_local IOCommandGate *IOCommandGate::currentGate_ = nullptr;

struct Window {
    std::atomic<bool> active{false};
    bool enabled() const { return active.load(std::memory_order_acquire); }
};

class ItlIwx : public OSObject {
public:
    bool tahoeP2pOnMainGate() const
    {
        return gate != nullptr && gate->inGate();
    }
    IOCommandGate *getMainCommandGate() { return gate; }

    static IOReturn tahoeRxCompletionPublishAction(OSObject *, void *, void *,
                                                   void *, void *);
    void tahoeRxCompletionPublish(IOEthernetController *);

    IOCommandGate *gate = nullptr;
    Window nativeRxPreOwner_;
    NativeIwxCompletionObserver::Telemetry nativeRxCompletionTelemetry_;
    bool nativeRxCompletionPublishAttempted_ = false;
};

""" + ACTION + "\n" + PUBLISH + r"""

static uint32_t read32(const std::vector<uint8_t> &bytes, size_t offset)
{
    assert(offset + 4 <= bytes.size());
    return uint32_t(bytes[offset]) |
        (uint32_t(bytes[offset + 1]) << 8) |
        (uint32_t(bytes[offset + 2]) << 16) |
        (uint32_t(bytes[offset + 3]) << 24);
}

static uint64_t read64(const std::vector<uint8_t> &bytes, size_t offset)
{
    assert(offset + 8 <= bytes.size());
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= uint64_t(bytes[offset + i]) << (8 * i);
    return value;
}

static void recordTailSample(ItlIwx &owner)
{
    using namespace NativeIwxCompletionObserver;
    CopyResult copied;
    copied.status = CopyStatus::kCopied;
    copied.snapshot.incarnation = 42;
    copied.snapshot.bytes[4] = 0x90;
    copied.snapshot.bytes[5] = 0x90;
    copied.snapshot.bytes[6] = 0xa5;
    recordAttempt(&owner.nativeRxCompletionTelemetry_, kObservedFamily,
                  7, 3, 1000, 18, 17, copied);
}

static void testBusyGateKeepsOriginalLateSampleForNextTick()
{
    IOCommandGate gate;
    ItlIwx owner;
    IOEthernetController controller;
    owner.gate = &gate;
    owner.nativeRxPreOwner_.active.store(true, std::memory_order_release);

    std::atomic<bool> passedEnabled{false};
    std::atomic<bool> continueRx{false};
    std::thread rx([&] {
        gate.runRx([&] {
            // This is the same enabled check used by the real RX caller.
            assert(owner.nativeRxPreOwner_.enabled());
            passedEnabled.store(true, std::memory_order_release);
            while (!continueRx.load(std::memory_order_acquire))
                std::this_thread::yield();
            // The watchdog closed the window after the check, but RX still
            // owns the same gate and must finish its final append first.
            recordTailSample(owner);
        });
    });

    while (!passedEnabled.load(std::memory_order_acquire))
        std::this_thread::yield();
    owner.nativeRxPreOwner_.active.store(false, std::memory_order_release);

    // The first tick cannot enter the actual publisher action while RX owns
    // the main gate; it must not consume the one-shot latch or allocate data.
    owner.tahoeRxCompletionPublish(&controller);
    assert(gate.attempts == 1 && gate.busyReturns == 1);
    assert(!owner.nativeRxCompletionPublishAttempted_);
    assert(OSData::allocations == 0 && controller.propertyWrites == 0);

    continueRx.store(true, std::memory_order_release);
    rx.join();

    // The next tick executes the extracted action and publisher while holding
    // the same gate, after the late RX record has completed.
    owner.tahoeRxCompletionPublish(&controller);
    assert(gate.attempts == 2 && gate.busyReturns == 1);
    assert(owner.nativeRxCompletionPublishAttempted_);
    assert(OSData::allocations == 1 && controller.propertyWrites == 1);
    assert(controller.value.size() ==
           NativeIwxCompletionObserver::kTelemetryWireBytes);
    assert(read32(controller.value, 0) == 1);
    assert(read32(controller.value, 8) == 1);
    assert(read32(controller.value, 12) == 1);
    assert(read32(controller.value, 44) == 1);
    const size_t sample = NativeIwxCompletionObserver::kTelemetryHeaderBytes;
    assert(read32(controller.value, sample + 20) == 0x9090);
    assert(read32(controller.value, sample + 24) == 0xa5);
    assert(read64(controller.value, sample + 36) == 42);

    // A repeated tick can run the action, but one-shot state prevents another
    // allocation/property replacement.
    owner.tahoeRxCompletionPublish(&controller);
    assert(gate.attempts == 3 && gate.busyReturns == 1);
    assert(OSData::allocations == 1 && controller.propertyWrites == 1);
}

static void testNullGateAndActiveWindowDoNotLatch()
{
    ItlIwx noGate;
    IOEthernetController noGateController;
    noGate.nativeRxPreOwner_.active.store(false, std::memory_order_release);
    noGate.tahoeRxCompletionPublish(&noGateController);
    assert(!noGate.nativeRxCompletionPublishAttempted_);
    assert(OSData::allocations == 1 && noGateController.propertyWrites == 0);

    IOCommandGate gate;
    ItlIwx activeWindow;
    IOEthernetController activeController;
    activeWindow.gate = &gate;
    activeWindow.nativeRxPreOwner_.active.store(true, std::memory_order_release);
    recordTailSample(activeWindow);
    activeWindow.tahoeRxCompletionPublish(&activeController);
    assert(gate.attempts == 1 && gate.busyReturns == 0);
    assert(!activeWindow.nativeRxCompletionPublishAttempted_);
    assert(OSData::allocations == 1 && activeController.propertyWrites == 0);
}

int main()
{
    testBusyGateKeepsOriginalLateSampleForNextTick();
    testNullGateAndActiveWindowDoNotLatch();
    std::cout << "PASS busy gate leaves latch free; next gated tick publishes tail sample once\n";
    std::cout << "PASS null gate and active window do not latch or allocate\n";
}
"""


with tempfile.TemporaryDirectory(prefix="test094-rx-publish-") as directory:
    directory = Path(directory)
    harness = directory / "rx_completion_publish.cpp"
    binary = directory / "rx_completion_publish"
    harness.write_text(HARNESS)
    subprocess.run(
        [
            "xcrun",
            "clang++",
            "-std=c++14",
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-pthread",
            "-I",
            str(ROOT),
            str(harness),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print(f"PASS extracted actual publisher/action from {DRIVER_PATH}")
print(f"source_sha256={hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest()}")
