#include "native/iwx_tx_watchdog.hpp"

#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

using IwxTxWatchdog::TickResult;

static void testCompletionBeforeDeadlineClearsCountdown()
{
    int32_t timer = 0;
    IwxTxWatchdog::arm(&timer);
    IwxTxWatchdog::clear(&timer); // TX_RESPONSE/BA notification on radio loop.
    assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kIdle);
    assert(timer == 0);
}

static void testCompletionAtDeadlineIsOrderedBeforeWatchdogByGate()
{
    int32_t timer = 0;
    IwxTxWatchdog::arm(&timer);
    for (int tick = 0; tick < 14; ++tick)
        assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kRearm);
    assert(timer == 1);

    // The RX completion event and the watchdog attemptAction are serialized
    // by the same main gate. If completion runs first, expiry sees idle state.
    IwxTxWatchdog::clear(&timer);
    assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kIdle);
    assert(timer == 0);
}

static void testUnansweredTransmitExpiresOnFifteenthTick()
{
    int32_t timer = 0;
    IwxTxWatchdog::arm(&timer);
    for (int tick = 0; tick < 14; ++tick) {
        assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kRearm);
        assert(timer == 14 - tick);
    }
    assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kExpired);
    assert(timer == 0);
}

static void testUnavailableGateDefersWithoutChangingTimer()
{
    int32_t timer = 1;
    for (int retry = 0; retry < 3; ++retry) {
        assert(IwxTxWatchdog::advance(&timer, false) == TickResult::kDeferred);
        assert(timer == 1);
    }
    assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kExpired);
    assert(timer == 0);
}

static void testExpiredRecoveryIsNotQueuedDuringShutdown()
{
    assert(IwxTxWatchdog::shouldEnqueueRecovery(TickResult::kExpired, false));
    assert(!IwxTxWatchdog::shouldEnqueueRecovery(TickResult::kExpired, true));
    assert(!IwxTxWatchdog::shouldEnqueueRecovery(TickResult::kRearm, false));
    assert(!IwxTxWatchdog::shouldEnqueueRecovery(TickResult::kIdle, false));
}

static void testStopClearsTimerWithoutAConcurrentPlainWrite()
{
    int32_t timer = 7;
    IwxTxWatchdog::clear(&timer); // iwx_stop holds the lifecycle fence.
    assert(IwxTxWatchdog::advance(&timer, true) == TickResult::kIdle);
    assert(timer == 0);
}

static void testTaskWorkerDropsTaskqLockBeforeWaitingForMainGate()
{
    std::mutex mainGate;
    std::mutex lifecycleFence;
    std::mutex taskqMutex;
    std::mutex syncMutex;
    std::condition_variable sync;
    bool workerPopped = false;
    bool taskQueued = true;

    // Model timeout expiry holding the command gate and lifecycle fence.
    std::unique_lock<std::mutex> gateLock(mainGate);
    std::unique_lock<std::mutex> lifecycleLock(lifecycleFence);
    std::thread worker([&] {
        {
            std::lock_guard<std::mutex> taskqLock(taskqMutex);
            assert(taskQueued);
            taskQueued = false;
        } // taskq_next_work drops tq_mtx before invoking the callback.
        {
            std::lock_guard<std::mutex> syncLock(syncMutex);
            workerPopped = true;
        }
        sync.notify_one();

        // The popped task may now wait for the gate/fence, but it does not
        // hold the task queue mutex while waiting.
        std::unique_lock<std::mutex> callbackGate(mainGate);
        std::unique_lock<std::mutex> callbackLifecycle(lifecycleFence);
    });

    {
        std::unique_lock<std::mutex> syncLock(syncMutex);
        sync.wait(syncLock, [&] { return workerPopped; });
    }
    // The watchdog can enqueue under gate+fence because the worker released
    // taskqMutex before it blocked on those locks.
    assert(taskqMutex.try_lock());
    taskQueued = true;
    taskqMutex.unlock();

    lifecycleLock.unlock();
    gateLock.unlock();
    worker.join();
}

int main()
{
    testCompletionBeforeDeadlineClearsCountdown();
    testCompletionAtDeadlineIsOrderedBeforeWatchdogByGate();
    testUnansweredTransmitExpiresOnFifteenthTick();
    testUnavailableGateDefersWithoutChangingTimer();
    testExpiredRecoveryIsNotQueuedDuringShutdown();
    testStopClearsTimerWithoutAConcurrentPlainWrite();
    testTaskWorkerDropsTaskqLockBeforeWaitingForMainGate();
}
