#!/usr/bin/env python3
"""Execute the actual Tahoe ROC correlation publisher with a host gate shim."""

from pathlib import Path
import subprocess
import tempfile
import unittest


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
                return source[start:index + 1]
    raise AssertionError(f"unterminated function: {marker}")


ACTION = function(DRIVER, "IOReturn ItlIwx::tahoeRxRocCorrelationPublishAction(")
PUBLISH = function(DRIVER, "void ItlIwx::tahoeRxRocCorrelationPublish(")

assert "owner->tahoeP2pOnMainGate()" in ACTION
assert "gate->attemptAction(tahoeRxRocCorrelationPublishAction" in PUBLISH
assert "nativeRxRocPublishAttempts_ >= 3u" in PUBLISH
assert "nativeRxRocPublished_ = true;" in PUBLISH
assert PUBLISH.index("nativeRxRocPublished_ = true;") > PUBLISH.index(
    "controller->setProperty(")


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

#include "native/iwx_roc_rx_correlation.hpp"

using IOReturn = int32_t;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnNotReady = int32_t(0xe00002d8);
static constexpr IOReturn kIOReturnCannotLock = int32_t(0xe00002cc);

static uint64_t tahoeMonotonicNs() { return 5000000000ULL; }

struct OSObject { virtual ~OSObject() = default; };

class OSData {
public:
    static OSData *withBytes(const void *bytes, unsigned length)
    {
        ++allocations;
        if (failNextAllocation) {
            failNextAllocation = false;
            return nullptr;
        }
        const auto *begin = static_cast<const uint8_t *>(bytes);
        return new OSData(std::vector<uint8_t>(begin, begin + length));
    }
    void release() { delete this; }
    const std::vector<uint8_t> bytes;
    static unsigned allocations;
    static bool failNextAllocation;
private:
    explicit OSData(std::vector<uint8_t> value) : bytes(std::move(value)) {}
};
unsigned OSData::allocations = 0;
bool OSData::failNextAllocation = false;

class IOEthernetController : public OSObject {
public:
    bool setProperty(const char *, OSData *data)
    {
        assert(data != nullptr);
        ++propertyWrites;
        if (failNextWrite) {
            failNextWrite = false;
            return false;
        }
        value = data->bytes;
        return true;
    }
    unsigned propertyWrites = 0;
    bool failNextWrite = false;
    std::vector<uint8_t> value;
};

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
        IOReturn result = action(nullptr, arg0, arg1, nullptr, nullptr);
        currentGate_ = nullptr;
        return result;
    }
    bool inGate() const { return currentGate_ == this; }
    void run(const std::function<void()> &fn)
    {
        std::lock_guard<std::mutex> guard(mutex_);
        assert(currentGate_ == nullptr);
        currentGate_ = this;
        fn();
        currentGate_ = nullptr;
    }
    unsigned attempts = 0;
    unsigned busyReturns = 0;
private:
    std::mutex mutex_;
    static thread_local IOCommandGate *currentGate_;
};
thread_local IOCommandGate *IOCommandGate::currentGate_ = nullptr;

struct PreOwnerWindow {
    std::atomic<bool> active{false};
    bool enabled() const { return active.load(std::memory_order_acquire); }
};

class ItlIwx : public OSObject {
public:
    bool tahoeP2pOnMainGate() const { return gate && gate->inGate(); }
    IOCommandGate *getMainCommandGate() { return gate; }
    void tahoeRxRocCorrelationSync(uint64_t) {}
    static IOReturn tahoeRxRocCorrelationPublishAction(OSObject *, void *,
                                                        void *, void *, void *);
    void tahoeRxRocCorrelationPublish(IOEthernetController *);
    IOCommandGate *gate = nullptr;
    PreOwnerWindow nativeRxPreOwner_;
    NativeIwxRocRxCorrelation::Recorder nativeRxRocCorrelation_{};
    uint64_t nativeRxRocArmUs_ = 0;
    uint64_t nativeRxRocArmStopSerial_ = 0;
    uint32_t nativeRxRocArmGeneration_ = 0;
    uint32_t nativeRxRocArmReady_ = 0;
    uint32_t nativeRxRocPublishAttempts_ = 0;
    bool nativeRxRocPublished_ = false;
    uint8_t nativeRxRocPublishWire_[NativeIwxRocRxCorrelation::kWireBytes]{};
};

""" + ACTION + "\n" + PUBLISH + r"""

static uint32_t read32(const std::vector<uint8_t> &value, size_t offset)
{
    assert(offset + 4 <= value.size());
    return uint32_t(value[offset]) | (uint32_t(value[offset + 1]) << 8) |
        (uint32_t(value[offset + 2]) << 16) |
        (uint32_t(value[offset + 3]) << 24);
}
static uint16_t read16(const std::vector<uint8_t> &value, size_t offset)
{
    assert(offset + 2 <= value.size());
    return uint16_t(value[offset]) | (uint16_t(value[offset + 1]) << 8);
}

static void prepareEndedWindow(ItlIwx &owner, uint32_t slots = 1)
{
    using namespace NativeIwxRocRxCorrelation;
    Recorder &recorder = owner.nativeRxRocCorrelation_;
    assert(recorder.arm(1, 11, 1000));
    RocEpoch epoch;
    epoch.contextGeneration = 6;
    epoch.powerGeneration = 11;
    epoch.stationGeneration = 23;
    epoch.rocGeneration = 6;
    epoch.sessionToken = 99;
    assert(recorder.beginRoc(epoch, 2000, 97000));
    for (uint32_t i = 0; i < slots; ++i) {
        NativeIwxCompletionObserver::CopyResult copy;
        copy.status = NativeIwxCompletionObserver::CopyStatus::kCopied;
        copy.snapshot.incarnation = 44;
        for (size_t byte = 0; byte < sizeof(copy.snapshot.bytes); ++byte)
            copy.snapshot.bytes[byte] = static_cast<uint8_t>(byte);
        SlotInput input;
        input.captureSerial = 1;
        input.driverGeneration = 11;
        input.ring = 0;
        input.slot = (188u + i) % 512u;
        input.head = (189u + i) % 512u;
        input.copyTimeUs = 2500 + i;
        input.copySequence = 66 + i;
        input.epoch = epoch;
        Token token = recorder.beginSlot(input, copy);
        if (token.valid)
            assert(recorder.finishSlot(token));
    }
    assert(recorder.endRoc(epoch, 5000));
}

static void testActiveWindowDoesNotPublishAndEmptyEndDoes()
{
    using namespace NativeIwxRocRxCorrelation;
    IOCommandGate gate;
    ItlIwx active;
    IOEthernetController activeController;
    active.gate = &gate;
    assert(active.nativeRxRocCorrelation_.arm(1, 11, 1000));
    RocEpoch epoch;
    epoch.contextGeneration = 6;
    epoch.powerGeneration = 11;
    epoch.stationGeneration = 23;
    epoch.rocGeneration = 6;
    epoch.sessionToken = 99;
    assert(active.nativeRxRocCorrelation_.beginRoc(epoch, 2000, 97000));
    active.tahoeRxRocCorrelationPublish(&activeController);
    assert(active.nativeRxRocPublishAttempts_ == 0);
    assert(!active.nativeRxRocPublished_ && activeController.propertyWrites == 0);

    ItlIwx empty;
    IOEthernetController emptyController;
    empty.gate = &gate;
    assert(empty.nativeRxRocCorrelation_.arm(1, 11, 1000));
    assert(empty.nativeRxRocCorrelation_.closeNoStart(2000));
    empty.tahoeRxRocCorrelationPublish(&emptyController);
    assert(empty.nativeRxRocPublished_ && emptyController.propertyWrites == 1);
    assert(emptyController.value.size() == kWireBytes);
    assert(read32(emptyController.value, 24) == uint32_t(State::kClosed));
    assert(read32(emptyController.value, 28) == uint32_t(CloseReason::kNoStart));
    assert(read32(emptyController.value, 100) == 0);
    assert(read32(emptyController.value, 120) == 0);
}

static void testBusyMainGateDefersWithoutConsumingRetry()
{
    IOCommandGate gate;
    ItlIwx owner;
    IOEthernetController controller;
    owner.gate = &gate;
    prepareEndedWindow(owner);
    const unsigned allocationsBefore = OSData::allocations;
    std::atomic<bool> locked{false};
    std::atomic<bool> release{false};
    std::thread holder([&] {
        gate.run([&] {
            locked.store(true, std::memory_order_release);
            while (!release.load(std::memory_order_acquire))
                std::this_thread::yield();
        });
    });
    while (!locked.load(std::memory_order_acquire)) std::this_thread::yield();
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(gate.busyReturns == 1);
    assert(owner.nativeRxRocPublishAttempts_ == 0);
    assert(!owner.nativeRxRocPublished_ &&
           OSData::allocations == allocationsBefore);
    release.store(true, std::memory_order_release);
    holder.join();
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(owner.nativeRxRocPublishAttempts_ == 1);
    assert(owner.nativeRxRocPublished_ && controller.propertyWrites == 1);
    const size_t record = NativeIwxRocRxCorrelation::kHeaderBytes;
    assert(controller.value.size() == NativeIwxRocRxCorrelation::kWireBytes);
    assert(read32(controller.value, record + 152) == 66);
}

static void testAllocationAndPropertyFailuresHaveThreeFiniteAttempts()
{
    IOCommandGate gate;
    ItlIwx owner;
    IOEthernetController controller;
    owner.gate = &gate;
    prepareEndedWindow(owner);
    OSData::failNextAllocation = true;
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(owner.nativeRxRocPublishAttempts_ == 1 && !owner.nativeRxRocPublished_);
    controller.failNextWrite = true;
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(owner.nativeRxRocPublishAttempts_ == 2 && !owner.nativeRxRocPublished_);
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(owner.nativeRxRocPublishAttempts_ == 3 && owner.nativeRxRocPublished_);
    assert(controller.propertyWrites == 2);
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(owner.nativeRxRocPublishAttempts_ == 3 && controller.propertyWrites == 2);

    ItlIwx exhausted;
    IOEthernetController exhaustedController;
    exhausted.gate = &gate;
    prepareEndedWindow(exhausted);
    exhaustedController.failNextWrite = true;
    exhausted.tahoeRxRocCorrelationPublish(&exhaustedController);
    exhaustedController.failNextWrite = true;
    exhausted.tahoeRxRocCorrelationPublish(&exhaustedController);
    exhaustedController.failNextWrite = true;
    exhausted.tahoeRxRocCorrelationPublish(&exhaustedController);
    exhausted.tahoeRxRocCorrelationPublish(&exhaustedController);
    assert(exhausted.nativeRxRocPublishAttempts_ == 3);
    assert(!exhausted.nativeRxRocPublished_);
    assert(exhaustedController.propertyWrites == 3);
}

static void testOverflowPublishesFixedBankAndLatchesIncompleteCoverage()
{
    IOCommandGate gate;
    ItlIwx owner;
    IOEthernetController controller;
    owner.gate = &gate;
    prepareEndedWindow(owner, NativeIwxRocRxCorrelation::kCapacity + 1);
    owner.tahoeRxRocCorrelationPublish(&controller);
    assert(owner.nativeRxRocPublished_);
    assert(read32(controller.value, 96) == NativeIwxRocRxCorrelation::kCapacity + 1);
    assert(read32(controller.value, 100) == NativeIwxRocRxCorrelation::kCapacity);
    assert(read32(controller.value, 104) == 1);
    assert(read32(controller.value, 120) == 0);
    const size_t lastRecord = NativeIwxRocRxCorrelation::kHeaderBytes +
        (NativeIwxRocRxCorrelation::kCapacity - 1) *
            NativeIwxRocRxCorrelation::kRecordBytes;
    assert(read16(controller.value, lastRecord + 34) ==
        (188u + NativeIwxRocRxCorrelation::kCapacity - 1) % 512u);
}

int main()
{
    testActiveWindowDoesNotPublishAndEmptyEndDoes();
    testBusyMainGateDefersWithoutConsumingRetry();
    testAllocationAndPropertyFailuresHaveThreeFiniteAttempts();
    testOverflowPublishesFixedBankAndLatchesIncompleteCoverage();
    std::cout << "PASS active/no-start behavior and actual publish action\n";
    std::cout << "PASS busy-gate deferral and finite allocation/property retries\n";
    std::cout << "PASS fixed append-only overflow publishes incomplete coverage\n";
}
"""


class RocCorrelationPublishTests(unittest.TestCase):
    def test_actual_publisher_with_gate_failure_injection(self):
        with tempfile.TemporaryDirectory(prefix="test096-roc-publish-") as temp:
            temp = Path(temp)
            source = temp / "publish.cpp"
            binary = temp / "publish"
            source.write_text(HARNESS)
            subprocess.run([
                "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
                "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-pthread", "-I", str(ROOT), str(source), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
