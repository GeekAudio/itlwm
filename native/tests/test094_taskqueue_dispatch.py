#!/usr/bin/env python3
"""Compile selected real _task.cpp definitions against tiny kernel stubs."""

from __future__ import annotations

import pathlib
import re
import subprocess
import tempfile
import textwrap


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itl80211/openbsd/sys/_task.cpp"
HEADER_ROOT = ROOT / "itl80211/openbsd"
DRIVER_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, name: str) -> str:
    pattern = re.compile(
        rf"(?m)^(?:static\s+)?(?:int|void)\s*\n+{re.escape(name)}\s*\("
    )
    match = pattern.search(source)
    if not match:
        raise AssertionError(f"cannot find production definition: {name}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"cannot find body for production function: {name}")
    depth = 0
    for offset in range(opening, len(source)):
        char = source[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : offset + 1]
    raise AssertionError(f"unterminated production function: {name}")


def extract_class(source: str, name: str) -> str:
    match = re.search(rf"\bclass\s+{re.escape(name)}\s*\{{", source)
    if not match:
        raise AssertionError(f"cannot find production class: {name}")
    opening = source.find("{", match.start())
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : offset + 1] + ";"
    raise AssertionError(f"unterminated production class: {name}")


QUEUE_STUB = r"""
#pragma once
#define TAILQ_HEAD(name, type) struct name { type *tqh_first; type **tqh_last; }
#define TAILQ_ENTRY(type) struct { type *tqe_next; type **tqe_prev; }
#define TAILQ_FIRST(head) ((head)->tqh_first)
#define TAILQ_INIT(head) do { (head)->tqh_first = nullptr; (head)->tqh_last = &(head)->tqh_first; } while (0)
#define TAILQ_INSERT_TAIL(head, elm, field) do { \
    (elm)->field.tqe_next = nullptr; \
    (elm)->field.tqe_prev = (head)->tqh_last; \
    *(head)->tqh_last = (elm); \
    (head)->tqh_last = &(elm)->field.tqe_next; \
} while (0)
#define TAILQ_REMOVE(head, elm, field) do { \
    if (((elm)->field.tqe_next) != nullptr) \
        (elm)->field.tqe_next->field.tqe_prev = (elm)->field.tqe_prev; \
    else \
        (head)->tqh_last = (elm)->field.tqe_prev; \
    *(elm)->field.tqe_prev = (elm)->field.tqe_next; \
} while (0)
"""


HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <condition_variable>
#include <mutex>
#include <thread>

#include "sys/_task.h"
#include "native/iwx_init_dispatch.hpp"

struct IORecursiveLock { std::recursive_mutex mutex; };
inline void IORecursiveLockLock(IORecursiveLock *lock) { lock->mutex.lock(); }
inline void IORecursiveLockUnlock(IORecursiveLock *lock) { lock->mutex.unlock(); }
inline void IORecursiveLockWakeup(IORecursiveLock *, void *, bool) {}
inline void IORecursiveLockSleep(IORecursiveLock *, void *, int) {}

enum ETQ_STATE { TQ_S_CREATED, TQ_S_RUNNING, TQ_S_DESTROYED };
struct taskq {
    ETQ_STATE tq_state;
    unsigned int tq_active;
    unsigned int tq_nthreads;
    unsigned int tq_paused;
    IORecursiveLock *tq_mtx;
    struct task_list tq_worklist;
};

#define THREAD_INTERRUPTIBLE 0
#define ISSET(v, f) (((v) & (f)) != 0)
#define SET(v, f) ((v) |= (f))
#define CLR(v, f) ((v) &= ~(f))

#define AIRPORT_TAHOE 1
enum : uint32_t {
    kTahoeLifecycleInitTask = 1U << 0,
    kTahoeLifecycleInitDispatchDeferred = 1U << 6
};
namespace IwxResetTrace {
enum class InitTaskTrigger : uint32_t { kLifecycleFenceRetry };
}
struct ItlIwx {
    taskq *queue {nullptr};
    task *source {nullptr};
    bool tryResults[3] {false, false, false};
    uint32_t tryCount {0};
    uint32_t deferredBits {0};
    uint32_t retryTriggerCount {0};

    bool tahoeTryLifecycleFence()
    {
        const uint32_t index = tryCount++;
        return index < 3 ? tryResults[index] : false;
    }
    uint32_t tahoeRecordInitTaskTrigger(IwxResetTrace::InitTaskTrigger)
    {
        ++retryTriggerCount;
        return retryTriggerCount;
    }
    void tahoeDeferLifecycleTasks(uint32_t bits) { deferredBits |= bits; }
    bool tahoeReleaseLifecycleFence(bool flush)
    {
        if (flush && (deferredBits & kTahoeLifecycleInitDispatchDeferred)) {
            deferredBits &= ~kTahoeLifecycleInitDispatchDeferred;
            (void)taskq_flush_deferred_tagged(queue, source);
        }
        return true;
    }
};

GUARD_CLASS

FUNCTIONS

using namespace IwxInitDispatch;
static const uint32_t kOn = kPowerStateKnown | kPowerRequestedOn;

struct Outcomes {
    CurrentState current {};
    uint32_t callbacks {0};
    uint32_t accepted {0};
    uint32_t stale {0};
};

struct ReuseState {
    Outcomes outcomes {};
    uint32_t legacyCalls {0};
};

struct CallbackBarrier {
    std::mutex mutex;
    std::condition_variable condition;
    bool entered {false};
    bool continueCallback {false};
    uint64_t dispatchId {0};
};
static CallbackBarrier *gCallbackBarrier = nullptr;

static void taggedCallback(void *argument,
    const task_dispatch_context *context, const task *source)
{
    auto *outcomes = static_cast<Outcomes *>(argument);
    if (gCallbackBarrier && context->dispatch_id == gCallbackBarrier->dispatchId) {
        std::unique_lock<std::mutex> lock(gCallbackBarrier->mutex);
        gCallbackBarrier->entered = true;
        gCallbackBarrier->condition.notify_all();
        gCallbackBarrier->condition.wait(lock, [] {
            return gCallbackBarrier->continueCallback;
        });
    }
    const Token token {context->dispatch_id, context->driver_generation,
        context->fault_serial, context->power_epoch, context->power_flags,
        context->dispatch_flags};
    const bool queueCurrent =
        task_dispatch_is_current(source, context->dispatch_id) != 0;
    const Decision decision = validate(token, outcomes->current, queueCurrent);
    if (decision == Decision::Run)
        ++outcomes->accepted;
    else
        ++outcomes->stale;
    ++outcomes->callbacks;
}

static void reusableTaggedCallback(void *argument,
    const task_dispatch_context *context, const task *source)
{
    auto *state = static_cast<ReuseState *>(argument);
    taggedCallback(&state->outcomes, context, source);
}

static void reusableLegacyCallback(void *argument)
{
    ++static_cast<ReuseState *>(argument)->legacyCalls;
}

static task_dispatch_context context(uint64_t id, uint32_t generation,
    uint32_t fault, uint32_t powerEpoch, uint32_t powerFlags = kOn,
    uint32_t dispatchFlags = 0)
{
    return task_dispatch_context {id, generation, fault, powerEpoch,
        powerFlags, dispatchFlags};
}

static void runAndComplete(taskq *queue, task *work)
{
    taskq_run_work(work);
    taskq_complete_work(queue, work);
}

static void initQueue(taskq *queue, IORecursiveLock *lock)
{
    *queue = taskq {};
    queue->tq_state = TQ_S_RUNNING;
    queue->tq_nthreads = 1;
    queue->tq_mtx = lock;
    TAILQ_INIT(&queue->tq_worklist);
}

static void initTaggedTask(task *work, void *argument)
{
    char name[sizeof(work->name)] {};
    memcpy(name, "tagged", sizeof("tagged"));
    task_set(work, nullptr, argument, name);
}

static void testOldPopOffOnThenOldAndNewCallback()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {40, 7, 3, kOn};

    auto oldContext = context(10, 40, 7, 3);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &oldContext) == 1);
    task oldWork {};
    assert(taskq_next_work(&queue, &oldWork) == 1);
    assert(task_dispatch_is_current(&source, 10));
    assert(task_del(&queue, &source) == 0); // no queue node; identity is retired

    // Off and On commit distinct power epochs while the old local copy waits.
    outcomes.current = CurrentState {41, 7, 5, kOn};
    auto newContext = context(11, 41, 7, 5);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &newContext) == 1);
    runAndComplete(&queue, &oldWork);
    assert(outcomes.callbacks == 1 && outcomes.accepted == 0 &&
           outcomes.stale == 1);

    task newWork {};
    assert(taskq_next_work(&queue, &newWork) == 1);
    runAndComplete(&queue, &newWork);
    assert(outcomes.callbacks == 2 && outcomes.accepted == 1 &&
           outcomes.stale == 1);
}

static void testSameGenerationInitAndRepeatedQueuedRequests()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {90, 4, 8, kOn};
    auto first = context(20, 90, 4, 8);
    auto repeated = context(21, 90, 4, 8);
    assert(task_add_tagged(&queue, &source, taggedCallback, &first) == 1);
    assert(task_add_tagged(&queue, &source, taggedCallback, &repeated) == 0);
    task work {};
    assert(taskq_next_work(&queue, &work) == 1);
    assert(work.t_dispatch_context.dispatch_id == 21);
    assert(task_dispatch_is_current(&source, 21));
    runAndComplete(&queue, &work);
    assert(outcomes.callbacks == 1 && outcomes.accepted == 1);
}

static void testFreshFaultRunsAfterOlderPoppedDispatch()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {12, 44, 9, kOn};
    auto oldContext = context(30, 12, 44, 9, kOn, kFaultRecovery);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &oldContext) == 1);
    task oldWork {};
    assert(taskq_next_work(&queue, &oldWork) == 1);

    // Stop advances driver generation after the fresh watchdog token is
    // captured. Its matching nonzero fault serial must still recover.
    outcomes.current = CurrentState {13, 45, 9, kOn};
    auto fault = context(31, 12, 45, 9, kOn, kFaultRecovery);
    assert(task_add_tagged(&queue, &source, taggedCallback, &fault) == 1);
    runAndComplete(&queue, &oldWork);
    assert(outcomes.accepted == 0 && outcomes.stale == 1);
    task freshWork {};
    assert(taskq_next_work(&queue, &freshWork) == 1);
    runAndComplete(&queue, &freshWork);
    assert(outcomes.accepted == 1 && outcomes.stale == 1);
}

static void testHistoricalFaultSerialDoesNotPromoteOrdinaryDispatch()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {24, 61, 10, kOn};
    // A normal later init may capture the latest diagnostic fault serial, but
    // does not inherit permission to survive another driver generation.
    auto ordinary = context(32, 23, 61, 10);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &ordinary) == 1);
    task work {};
    assert(taskq_next_work(&queue, &work) == 1);
    runAndComplete(&queue, &work);
    assert(outcomes.callbacks == 1 && outcomes.accepted == 0 &&
           outcomes.stale == 1);
}

static void testLifecycleBusyDefersExactTokenAcrossOffOnThenFlushes()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {5, 12, 1, kOn};
    auto original = context(90, 5, 12, 1);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &original) == 1);
    task popped {};
    assert(taskq_next_work(&queue, &popped) == 1);

    // Execute the production guard's busy path. The init callback parks its
    // exact token, publishes the retry bit, then uses a second guard only to
    // close the unlock-before-publish race and flush after fence release.
    ItlIwx owner;
    owner.queue = &queue;
    owner.source = &source;
    owner.tryResults[0] = false;
    owner.tryResults[1] = false;
    owner.tryResults[2] = true;
    {
        TahoeLifecycleGuard guard(&owner);
        assert(!guard);
    }
    assert(task_defer_tagged(&queue, popped.t_dispatch_source,
        popped.t_dispatch_func, &popped.t_dispatch_context) == 1);
    owner.tahoeDeferLifecycleTasks(kTahoeLifecycleInitDispatchDeferred);
    taskq_complete_work(&queue, &popped);
    assert(task_dispatch_is_current(&source, 90));
    assert(queue.tq_worklist.tqh_first == nullptr);

    // OFF/ON occurs before the guard's retry-release flush. The parked token
    // must keep power epoch 1 rather than being minted as epoch 3.
    outcomes.current = CurrentState {6, 12, 3, kOn};
    {
        TahoeLifecycleGuard flushGuard(&owner,
            kTahoeLifecycleInitDispatchDeferred);
        assert(!flushGuard); // second try acquires only for the flush
    }
    assert(owner.retryTriggerCount == 0);
    assert(owner.deferredBits == 0);
    assert(taskq_flush_deferred_tagged(&queue, &source) == 0);
    assert(task_pending(&source));
    task staleWork {};
    assert(taskq_next_work(&queue, &staleWork) == 1);
    assert(staleWork.t_dispatch_context.dispatch_id == 90);
    assert(staleWork.t_dispatch_context.power_epoch == 1);
    runAndComplete(&queue, &staleWork);
    assert(outcomes.callbacks == 1 && outcomes.accepted == 0 &&
           outcomes.stale == 1);

    // A late duplicate flush or defer cannot revive a completed identity.
    assert(taskq_flush_deferred_tagged(&queue, &source) == 0);
    assert(task_defer_tagged(&queue, &source, taggedCallback, &original) == 0);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &original) == 0);
    assert(queue.tq_worklist.tqh_first == nullptr);

    auto freshOn = context(91, 6, 12, 3);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &freshOn) == 1);
    task freshWork {};
    assert(taskq_next_work(&queue, &freshWork) == 1);
    runAndComplete(&queue, &freshWork);
    assert(outcomes.callbacks == 2 && outcomes.accepted == 1 &&
           outcomes.stale == 1);
}

static void testOlderProducerCannotReplaceNewerQueuedDispatch()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {20, 4, 2, kOn};
    auto newer = context(101, 20, 4, 2);
    auto older = context(100, 20, 4, 2);
    // Producer 101 reaches the queue first; a delayed producer 100 cannot
    // overwrite the newer pending context.
    assert(task_add_tagged(&queue, &source, taggedCallback, &newer) == 1);
    assert(task_add_tagged(&queue, &source, taggedCallback, &older) == 0);
    task work {};
    assert(taskq_next_work(&queue, &work) == 1);
    assert(work.t_dispatch_context.dispatch_id == 101);
    runAndComplete(&queue, &work);
    assert(outcomes.callbacks == 1 && outcomes.accepted == 1);

    task wrapSource {};
    Outcomes wrapOutcomes {};
    initTaggedTask(&wrapSource, &wrapOutcomes);
    wrapOutcomes.current = CurrentState {20, 4, 2, kOn};
    auto beforeWrap = context(UINT64_MAX, 20, 4, 2);
    auto afterWrap = context(1, 20, 4, 2);
    auto delayedBeforeWrap = context(UINT64_MAX, 20, 4, 2);
    assert(task_add_tagged(&queue, &wrapSource, taggedCallback,
                           &beforeWrap) == 1);
    assert(task_del(&queue, &wrapSource) == 1);
    assert(task_add_tagged(&queue, &wrapSource, taggedCallback,
                           &afterWrap) == 1);
    assert(task_add_tagged(&queue, &wrapSource, taggedCallback,
                           &delayedBeforeWrap) == 0);
    task wrapWork {};
    assert(taskq_next_work(&queue, &wrapWork) == 1);
    assert(wrapWork.t_dispatch_context.dispatch_id == 1);
    runAndComplete(&queue, &wrapWork);
    assert(wrapOutcomes.callbacks == 1 && wrapOutcomes.accepted == 1);
}

static void testStopRetiresPoppedDispatchBeforeLateDeferral()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {30, 8, 2, kOn};
    auto request = context(110, 30, 8, 2);
    assert(task_add_tagged(&queue, &source, taggedCallback, &request) == 1);
    task popped {};
    assert(taskq_next_work(&queue, &popped) == 1);
    assert(task_del(&queue, &source) == 0); // retires even without a queue node
    assert(!task_dispatch_is_current(&source, 110));
    assert(task_defer_tagged(&queue, &source, taggedCallback, &request) == 0);
    taskq_complete_work(&queue, &popped);
    assert(taskq_flush_deferred_tagged(&queue, &source) == 0);
    assert(queue.tq_worklist.tqh_first == nullptr);

    auto fresh = context(111, 30, 8, 2);
    assert(task_add_tagged(&queue, &source, taggedCallback, &fresh) == 1);
    task work {};
    assert(taskq_next_work(&queue, &work) == 1);
    runAndComplete(&queue, &work);
    assert(outcomes.callbacks == 1 && outcomes.accepted == 1);
}

static void testFailedQueueAndQueuedCancellation()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    auto request = context(50, 7, 1, 2);
    queue.tq_paused = 1;
    assert(task_add_tagged(&queue, &source, taggedCallback, &request) == -1);
    assert(!task_pending(&source));
    assert(task_dispatch_is_current(&source, 50) == 0);

    queue.tq_paused = 0;
    assert(task_add_tagged(&queue, &source, taggedCallback, &request) == 1);
    assert(task_del(&queue, &source) == 1);
    assert(task_del(&queue, &source) == 0);
    assert(TAILQ_FIRST(&queue.tq_worklist) == nullptr);
    assert(outcomes.callbacks == 0);
}

static void legacyCallback(void *argument)
{
    ++*static_cast<uint32_t *>(argument);
}

static void testLegacyTaskAddStillUsesOneArgumentCallback()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    uint32_t calls = 0;
    char name[sizeof(source.name)] {};
    memcpy(name, "legacy", sizeof("legacy"));
    task_set(&source, legacyCallback, &calls, name);
    assert(task_add(&queue, &source) == 1);
    assert(task_add(&queue, &source) == 0);
    task work {};
    assert(taskq_next_work(&queue, &work) == 1);
    runAndComplete(&queue, &work);
    assert(calls == 1);
}

static void testPlainTaskAddAfterTaggedUseReturnsToOriginalCallback()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    ReuseState state {};
    char name[sizeof(source.name)] {};
    memcpy(name, "reuse", sizeof("reuse"));
    task_set(&source, reusableLegacyCallback, &state, name);
    state.outcomes.current = CurrentState {70, 3, 2, kOn};
    auto request = context(71, 70, 3, 2);
    assert(task_add_tagged(&queue, &source, reusableTaggedCallback,
                           &request) == 1);
    task taggedWork {};
    assert(taskq_next_work(&queue, &taggedWork) == 1);
    runAndComplete(&queue, &taggedWork);
    assert(state.outcomes.accepted == 1 && state.legacyCalls == 0);

    // task_add() retains its original callback and clears only the optional
    // tag when it creates an ordinary new queue entry.
    assert(task_add(&queue, &source) == 1);
    task plainWork {};
    assert(taskq_next_work(&queue, &plainWork) == 1);
    runAndComplete(&queue, &plainWork);
    assert(state.legacyCalls == 1 && state.outcomes.callbacks == 1);
}

static void testOldCallbackRacingNewEnqueueUsesCopiedIdentity()
{
    taskq queue {};
    IORecursiveLock lock {};
    initQueue(&queue, &lock);
    task source {};
    Outcomes outcomes {};
    initTaggedTask(&source, &outcomes);
    outcomes.current = CurrentState {100, 2, 5, kOn};
    auto oldContext = context(60, 100, 2, 5);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &oldContext) == 1);
    task oldWork {};
    assert(taskq_next_work(&queue, &oldWork) == 1);

    CallbackBarrier barrier {};
    barrier.dispatchId = 60;
    gCallbackBarrier = &barrier;
    std::thread oldCallback([&] { runAndComplete(&queue, &oldWork); });
    {
        std::unique_lock<std::mutex> waitForCallback(barrier.mutex);
        barrier.condition.wait(waitForCallback, [&] { return barrier.entered; });
    }

    // The copied old context is parked while a new epoch is queued on the
    // original task object. The old callback observes only its copied tag and
    // the queue's atomic current-dispatch id.
    outcomes.current = CurrentState {101, 2, 6, kOn};
    auto newContext = context(61, 101, 2, 6);
    assert(task_add_tagged(&queue, &source, taggedCallback,
                           &newContext) == 1);
    {
        std::lock_guard<std::mutex> releaseCallback(barrier.mutex);
        barrier.continueCallback = true;
    }
    barrier.condition.notify_all();
    oldCallback.join();
    gCallbackBarrier = nullptr;
    assert(outcomes.callbacks == 1 && outcomes.accepted == 0 &&
           outcomes.stale == 1);

    task freshWork {};
    assert(taskq_next_work(&queue, &freshWork) == 1);
    runAndComplete(&queue, &freshWork);
    assert(outcomes.callbacks == 2 && outcomes.accepted == 1 &&
           outcomes.stale == 1);
}

int main()
{
    testOldPopOffOnThenOldAndNewCallback();
    testSameGenerationInitAndRepeatedQueuedRequests();
    testFreshFaultRunsAfterOlderPoppedDispatch();
    testHistoricalFaultSerialDoesNotPromoteOrdinaryDispatch();
    testLifecycleBusyDefersExactTokenAcrossOffOnThenFlushes();
    testOlderProducerCannotReplaceNewerQueuedDispatch();
    testStopRetiresPoppedDispatchBeforeLateDeferral();
    testFailedQueueAndQueuedCancellation();
    testLegacyTaskAddStillUsesOneArgumentCallback();
    testPlainTaskAddAfterTaggedUseReturnsToOriginalCallback();
    testOldCallbackRacingNewEnqueueUsesCopiedIdentity();
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text()
    guard_class = extract_class(DRIVER_SOURCE.read_text(), "TahoeLifecycleGuard")
    names = (
        "taskq_next_work",
        "taskq_run_work",
        "task_set",
        "task_add",
        "task_add_tagged",
        "task_defer_tagged",
        "taskq_flush_deferred_tagged",
        "taskq_complete_work",
        "task_dispatch_is_current",
        "task_del",
    )
    functions = "\n\n".join(extract_function(source, name) for name in names)
    with tempfile.TemporaryDirectory(prefix="test094-taskqueue-") as temp_name:
        temp = pathlib.Path(temp_name)
        stub_queue = temp / "include/sys/queue.h"
        stub_buffer = temp / "include/sys/_buf.h"
        stub_locks = temp / "include/IOKit/IOLocks.h"
        stub_queue.parent.mkdir(parents=True)
        stub_locks.parent.mkdir(parents=True)
        stub_queue.write_text(QUEUE_STUB)
        stub_buffer.write_text("#pragma once\n")
        stub_locks.write_text("#pragma once\nstruct IORecursiveLock;\n")
        harness = temp / "test094_taskqueue_dispatch.cpp"
        harness.write_text(HARNESS.replace("GUARD_CLASS", guard_class).replace(
            "FUNCTIONS", functions))
        executable = temp / "test094_taskqueue_dispatch"
        subprocess.run(
            [
                "clang++",
                "-std=c++17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(temp / "include"),
                "-I",
                str(HEADER_ROOT),
                "-I",
                str(ROOT),
                str(harness),
                "-o",
                str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)
    print("PASS: extracted _task.cpp tagged queue and TahoeLifecycleGuard ran")


if __name__ == "__main__":
    main()
