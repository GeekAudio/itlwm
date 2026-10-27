#include "native/iwx_reset_trace.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <memory>
#include <thread>

using IwxResetTrace::InitTaskTrigger;
using IwxResetTrace::ResetReason;
using IwxResetTrace::Snapshot;
using IwxResetTrace::Trace;

static uint64_t sum(const uint32_t *values, uint32_t count)
{
    uint64_t total = 0;
    for (uint32_t i = 0; i < count; ++i)
        total += values[i];
    return total;
}

static void testStableValuesAndFirstLastCounts()
{
    static_assert(static_cast<uint32_t>(ResetReason::kUnknown) == 0,
                  "unknown must remain the compatibility bucket");
    static_assert(static_cast<uint32_t>(ResetReason::kIfFlagsDown) == 2,
                  "published reset values must stay stable");
    static_assert(static_cast<uint32_t>(InitTaskTrigger::kNewStateError) == 1,
                  "published trigger values must stay stable");

    Trace trace;
    const uint32_t first = trace.recordReset(
        ResetReason::kUnknown, 10, 0x11, 0x21, 3, 14, 0);
    const uint32_t second = trace.recordReset(
        ResetReason::kIfFlagsDown, 11, 0x12, 0x22, 4, 14, 5);
    const uint32_t third = trace.recordReset(
        static_cast<ResetReason>(0xffffffffU), 12, 0x13, 0x23, 5, 14, 6);

    Snapshot snapshot{};
    assert(trace.read(&snapshot));
    assert(first == 1 && second == 2 && third == 3);
    assert(snapshot.resetSequence == 3);
    assert(snapshot.lastResetReason ==
           static_cast<uint32_t>(ResetReason::kUnknown));
    assert(snapshot.generation == 12 && snapshot.driverFlags == 0x13);
    assert(snapshot.interfaceFlags == 0x23 && snapshot.ieee80211State == 5);
    assert(snapshot.initStage == 14 && snapshot.initError == 6);
    assert(snapshot.resetReasonCounts[0] == 2);
    assert(snapshot.resetReasonCounts[2] == 1);
    assert(sum(snapshot.resetReasonCounts, IwxResetTrace::kResetReasonCount) == 3);
}

static void testConcurrentResetWriterAndReaders()
{
    constexpr uint32_t kEvents = 120000;
    constexpr uint32_t kDriverMask = 0x5a5aa5a5U;
    Trace trace;
    std::atomic<bool> done {false};
    std::atomic<bool> consistent {true};

    std::thread writer([&] {
        for (uint32_t i = 1; i <= kEvents; ++i) {
            const auto reason = static_cast<ResetReason>(1U + (i % 9U));
            const uint32_t sequence = trace.recordReset(
                reason, i, i ^ kDriverMask, i * 3U, i % 7U, i + 11U,
                i ^ 0x00abcdefU);
            if (sequence != i)
                consistent.store(false, std::memory_order_relaxed);
        }
        done.store(true, std::memory_order_release);
    });

    auto reader = [&] {
        while (!done.load(std::memory_order_acquire)) {
            Snapshot snapshot{};
            if (!trace.read(&snapshot))
                continue; // The documented bounded retry can skip a busy write.
            if (snapshot.resetSequence == 0)
                continue;
            const uint32_t generation = snapshot.generation;
            if (generation != snapshot.resetSequence ||
                snapshot.driverFlags != (generation ^ kDriverMask) ||
                snapshot.interfaceFlags != generation * 3U ||
                snapshot.ieee80211State != generation % 7U ||
                snapshot.initStage != generation + 11U ||
                snapshot.initError != (generation ^ 0x00abcdefU) ||
                sum(snapshot.resetReasonCounts,
                    IwxResetTrace::kResetReasonCount) != snapshot.resetSequence)
                consistent.store(false, std::memory_order_relaxed);
        }
    };
    std::thread reader1(reader);
    std::thread reader2(reader);
    writer.join();
    reader1.join();
    reader2.join();

    Snapshot finalSnapshot{};
    assert(consistent.load(std::memory_order_relaxed));
    assert(trace.read(&finalSnapshot));
    assert(finalSnapshot.resetSequence == kEvents);
    assert(finalSnapshot.generation == kEvents);
    assert(finalSnapshot.lastResetReason ==
           static_cast<uint32_t>(ResetReason::kIoctlEnetReset));
    assert(sum(finalSnapshot.resetReasonCounts,
               IwxResetTrace::kResetReasonCount) == kEvents);
}

static void testDelayedLowerSequenceTriggerCompletionNeedsRepublish()
{
    Trace trace;
    const uint32_t delayedSequence = trace.reserveInitTaskTriggerSequence();
    const uint32_t laterSequence = trace.recordInitTaskTrigger(
        InitTaskTrigger::kTxWatchdogTimeout);
    assert(delayedSequence == 1 && laterSequence == 2);

    Snapshot beforeDelayedCompletion{};
    assert(trace.read(&beforeDelayedCompletion));
    assert(beforeDelayedCompletion.lastInitTaskTriggerSequence == 2);
    assert(beforeDelayedCompletion.lastInitTaskTrigger ==
           static_cast<uint32_t>(InitTaskTrigger::kTxWatchdogTimeout));
    assert(beforeDelayedCompletion.initTaskTriggerRevision == 1);
    assert(sum(beforeDelayedCompletion.initTaskTriggerCounts,
               IwxResetTrace::kInitTaskTriggerCount) == 1);
    const uint32_t publishedRevision =
        beforeDelayedCompletion.initTaskTriggerRevision;

    // Sequence 1 completes after sequence 2. It increments the per-reason
    // count/revision but must not replace the latest-source tag or be hidden
    // by a publisher that keys only on that tag's sequence.
    trace.completeInitTaskTrigger(delayedSequence,
                                  InitTaskTrigger::kCriticalTemperature);
    Snapshot afterDelayedCompletion{};
    assert(trace.read(&afterDelayedCompletion));
    assert(afterDelayedCompletion.lastInitTaskTriggerSequence == 2);
    assert(afterDelayedCompletion.lastInitTaskTrigger ==
           static_cast<uint32_t>(InitTaskTrigger::kTxWatchdogTimeout));
    assert(afterDelayedCompletion.initTaskTriggerRevision ==
           publishedRevision + 1);
    assert(afterDelayedCompletion.initTaskTriggerRevision !=
           publishedRevision); // Publisher must emit this newer count batch.
    assert(afterDelayedCompletion.initTaskTriggerCounts[
               static_cast<uint32_t>(InitTaskTrigger::kCriticalTemperature)] == 1);
    assert(afterDelayedCompletion.initTaskTriggerCounts[
               static_cast<uint32_t>(InitTaskTrigger::kTxWatchdogTimeout)] == 1);
    assert(sum(afterDelayedCompletion.initTaskTriggerCounts,
               IwxResetTrace::kInitTaskTriggerCount) == 2);
}

static void testConcurrentTriggerCountsAndLatestSource()
{
    constexpr uint32_t kThreads = 4;
    constexpr uint32_t kPerThread = 30000;
    constexpr uint32_t kTotal = kThreads * kPerThread;
    Trace trace;
    std::array<std::array<uint32_t, IwxResetTrace::kInitTaskTriggerCount>,
               kThreads> expectedCounts{};
    std::unique_ptr<std::atomic<uint32_t>[]> expectedSource(
        new std::atomic<uint32_t>[kTotal + 1]);
    for (uint32_t i = 0; i <= kTotal; ++i)
        expectedSource[i].store(UINT32_MAX, std::memory_order_relaxed);

    std::thread workers[kThreads];
    for (uint32_t thread = 0; thread < kThreads; ++thread) {
        workers[thread] = std::thread([&, thread] {
            for (uint32_t i = 0; i < kPerThread; ++i) {
                const uint32_t source = 1U + ((thread * 3U + i) % 11U);
                const auto trigger = static_cast<InitTaskTrigger>(source);
                const uint32_t sequence = trace.recordInitTaskTrigger(trigger);
                ++expectedCounts[thread][source];
                expectedSource[sequence].store(source, std::memory_order_relaxed);
            }
        });
    }
    for (auto &worker : workers)
        worker.join();

    Snapshot snapshot{};
    assert(trace.read(&snapshot));
    assert(snapshot.lastInitTaskTriggerSequence == kTotal);
    assert(snapshot.lastInitTaskTrigger ==
           expectedSource[kTotal].load(std::memory_order_relaxed));
    assert(sum(snapshot.initTaskTriggerCounts,
               IwxResetTrace::kInitTaskTriggerCount) == kTotal);
    for (uint32_t source = 0; source < IwxResetTrace::kInitTaskTriggerCount;
         ++source) {
        uint32_t expected = 0;
        for (uint32_t thread = 0; thread < kThreads; ++thread)
            expected += expectedCounts[thread][source];
        assert(snapshot.initTaskTriggerCounts[source] == expected);
    }
}

int main()
{
    testStableValuesAndFirstLastCounts();
    testConcurrentResetWriterAndReaders();
    testDelayedLowerSequenceTriggerCompletionNeedsRepublish();
    testConcurrentTriggerCountsAndLatestSource();
}
