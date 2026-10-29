// SPDX-License-Identifier: GPL-2.0-only
#include "../iwx_link_state_trace.hpp"

#include <assert.h>
#include <atomic>
#include <stdint.h>
#include <thread>
#include <type_traits>

using IwxLinkStateTrace::Input;
using IwxLinkStateTrace::Record;
using IwxLinkStateTrace::Snapshot;
using IwxLinkStateTrace::Trace;

static std::atomic<uint64_t> gMonotonicNs{100};
static std::atomic<bool> gBlockingClockEntered{false};
static std::atomic<bool> gReleaseBlockingClock{false};

static uint64_t testMonotonicNs()
{
    return gMonotonicNs.fetch_add(100, std::memory_order_relaxed);
}

static uint64_t blockingMonotonicNs()
{
    gBlockingClockEntered.store(true, std::memory_order_release);
    while (!gReleaseBlockingClock.load(std::memory_order_acquire))
        std::this_thread::yield();
    return testMonotonicNs();
}

static Input stateEvent(uint32_t oldState, uint32_t newState)
{
    Input input{};
    input.eventCode = static_cast<uint32_t>(
        IwxLinkStateTrace::Event::kNewStateRequested);
    input.oldState = oldState;
    input.newState = newState;
    input.deauthReason = 17;
    input.stateArgument = UINT32_MAX;
    input.resultCode = -5;
    input.ifUpRunning = 0x7;
    input.driverGeneration = 4;
    input.resetGeneration = 2;
    input.watchdogSequence = 1;
    input.validMask = IwxLinkStateTrace::kStatePairValid |
        IwxLinkStateTrace::kDeauthReasonValid |
        IwxLinkStateTrace::kStateArgumentValid |
        IwxLinkStateTrace::kResultCodeValid |
        IwxLinkStateTrace::kInterfaceFlagsValid |
        IwxLinkStateTrace::kGenerationPairValid |
        IwxLinkStateTrace::kWatchdogSequenceValid;
    return input;
}

static void assertSnapshot(const Snapshot &snapshot)
{
    assert(snapshot.schema == IwxLinkStateTrace::kSchema);
    assert(snapshot.capacity == IwxLinkStateTrace::kCapacity);
    assert(snapshot.versionBegin == snapshot.versionEnd);
    assert((snapshot.versionBegin & 1u) == 0);
    assert(snapshot.count <= IwxLinkStateTrace::kCapacity);
    uint64_t previousSequence = 0;
    uint64_t previousTime = 0;
    for (uint32_t i = 0; i < snapshot.count; ++i) {
        const Record &record = snapshot.records[i];
        assert(record.sequence > previousSequence);
        assert(record.monotonicNs >= previousTime);
        assert(record.eventCode >= 1 && record.eventCode <= 7);
        assert((record.validMask & ~IwxLinkStateTrace::kKnownValidityMask) == 0);
        assert((record.ifUpRunning & ~0x3u) == 0);
        if (!(record.validMask & IwxLinkStateTrace::kStatePairValid))
            assert(record.oldState == 0 && record.newState == 0);
        if (!(record.validMask & IwxLinkStateTrace::kDeauthReasonValid))
            assert(record.deauthReason == 0);
        if (!(record.validMask & IwxLinkStateTrace::kStateArgumentValid))
            assert(record.stateArgument == 0);
        if (!(record.validMask & IwxLinkStateTrace::kResultCodeValid))
            assert(record.resultCode == 0);
        if (!(record.validMask & IwxLinkStateTrace::kInterfaceFlagsValid))
            assert(record.ifUpRunning == 0);
        if (!(record.validMask & IwxLinkStateTrace::kGenerationPairValid))
            assert(record.driverGeneration == 0 && record.resetGeneration == 0);
        if (!(record.validMask & IwxLinkStateTrace::kWatchdogSequenceValid))
            assert(record.watchdogSequence == 0);
        previousSequence = record.sequence;
        previousTime = record.monotonicNs;
    }
}

// The production trace schema stores numeric scalars only. These type checks
// make accidental string/pointer/address fields a compile-time failure.
static_assert(std::is_integral<decltype(Record::sequence)>::value, "sequence must be numeric");
static_assert(std::is_integral<decltype(Record::monotonicNs)>::value, "time must be numeric");
static_assert(std::is_integral<decltype(Record::eventCode)>::value, "event must be numeric");
static_assert(std::is_integral<decltype(Record::oldState)>::value, "old state must be numeric");
static_assert(std::is_integral<decltype(Record::newState)>::value, "new state must be numeric");
static_assert(std::is_integral<decltype(Record::deauthReason)>::value, "reason must be numeric");
static_assert(std::is_integral<decltype(Record::stateArgument)>::value, "argument must be numeric");
static_assert(std::is_integral<decltype(Record::resultCode)>::value, "result must be numeric");
static_assert(std::is_integral<decltype(Record::ifUpRunning)>::value, "flags must be numeric");
static_assert(std::is_integral<decltype(Record::driverGeneration)>::value, "generation must be numeric");
static_assert(std::is_integral<decltype(Record::resetGeneration)>::value, "reset generation must be numeric");
static_assert(std::is_integral<decltype(Record::watchdogSequence)>::value, "watchdog must be numeric");
static_assert(std::is_integral<decltype(Record::validMask)>::value, "validity must be numeric");

int main()
{
    static_assert(sizeof(Record) == 64, "IORegistry record ABI drift");
    static_assert(sizeof(Snapshot) == 544, "IORegistry snapshot ABI drift");

    Trace trace{};
    Input input = stateEvent(1, 2);
    // Invalid optional fields are deliberately nonzero at input; sanitize()
    // must zero them before they can enter the bounded export.
    input.validMask &= ~IwxLinkStateTrace::kDeauthReasonValid;
    assert(trace.record(input, testMonotonicNs));
    Snapshot snapshot{};
    assert(trace.snapshot(&snapshot));
    assertSnapshot(snapshot);
    assert(snapshot.count == 1);
    assert(snapshot.records[0].sequence == 1);
    assert(snapshot.records[0].deauthReason == 0);
    assert(snapshot.records[0].ifUpRunning == 0x3);
    assert(snapshot.records[0].resultCode == -5);

    for (uint32_t i = 0; i < 11; ++i) {
        input = stateEvent(i, i + 1);
        assert(trace.record(input, testMonotonicNs));
    }
    assert(trace.snapshot(&snapshot));
    assertSnapshot(snapshot);
    assert(snapshot.count == IwxLinkStateTrace::kCapacity);
    assert(snapshot.records[0].sequence == 5);
    assert(snapshot.records[7].sequence == 12);

    Trace contention{};
    gBlockingClockEntered.store(false, std::memory_order_relaxed);
    gReleaseBlockingClock.store(false, std::memory_order_relaxed);
    std::thread heldWriter([&]() {
        const Input event = stateEvent(1, 2);
        assert(contention.record(event, blockingMonotonicNs));
    });
    while (!gBlockingClockEntered.load(std::memory_order_acquire))
        std::this_thread::yield();
    assert(!contention.record(stateEvent(2, 3), testMonotonicNs));
    gReleaseBlockingClock.store(true, std::memory_order_release);
    heldWriter.join();
    assert(contention.snapshot(&snapshot));
    assertSnapshot(snapshot);
    assert(snapshot.nextSequence == 1 && snapshot.droppedCount == 1);

    Trace concurrent{};
    constexpr uint32_t kThreads = 4;
    constexpr uint32_t kPerThread = 12000;
    std::atomic<uint32_t> finished{0};
    std::thread readers([&]() {
        while (finished.load(std::memory_order_acquire) != kThreads) {
            Snapshot observed{};
            if (concurrent.snapshot(&observed))
                assertSnapshot(observed);
        }
    });
    std::thread producers[kThreads];
    for (uint32_t thread = 0; thread < kThreads; ++thread) {
        producers[thread] = std::thread([&, thread]() {
            for (uint32_t i = 0; i < kPerThread; ++i) {
                Input event = stateEvent(thread, i);
                (void)concurrent.record(event, testMonotonicNs);
            }
            finished.fetch_add(1, std::memory_order_release);
        });
    }
    for (std::thread &producer : producers)
        producer.join();
    readers.join();

    assert(concurrent.snapshot(&snapshot));
    assertSnapshot(snapshot);
    assert(snapshot.count == IwxLinkStateTrace::kCapacity);
    assert(snapshot.nextSequence + snapshot.droppedCount ==
           uint64_t(kThreads) * kPerThread);
    assert(!concurrent.snapshot(nullptr));

    // Unknown events are dropped without changing a record or opening the
    // publisher payload to caller-supplied text.
    input.eventCode = 0xffffffffu;
    const uint64_t previousSequence = snapshot.nextSequence;
    assert(!concurrent.record(input, testMonotonicNs));
    assert(concurrent.snapshot(&snapshot));
    assert(snapshot.nextSequence == previousSequence);
    assert(snapshot.droppedCount == uint32_t(
        uint64_t(kThreads) * kPerThread - previousSequence + 1u));
}
