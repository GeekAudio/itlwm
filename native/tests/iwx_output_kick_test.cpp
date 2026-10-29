#include "native/iwx_output_kick.hpp"

#include <cassert>
#include <cstdint>

using namespace IwxOutputKick;

static void testBusyGatePreservesQueuedPacketUntilRetry()
{
    uint32_t epoch = 12;
    uint32_t serial = 0;
    uint64_t pending = 0;
    unsigned queued = 1;
    unsigned dequeued = 0;

    // Both a failed gate attempt and a failed lifecycle admission publish a
    // retry token, but the normal output queue remains untouched.
    assert(request(&pending, &serial, &epoch));
    assert(request(&pending, &serial, &epoch));
    assert(queued == 1 && dequeued == 0);
    assert(hasPendingForEpoch(&pending, epoch));

    // A later serialized watchdog tick takes the matching token and drains.
    uint64_t token = 0;
    assert(takeForEpoch(&pending, epoch, &token));
    assert(token != 0 && queued == 1 && dequeued == 0);
    --queued;
    ++dequeued;
    assert(queued == 0 && dequeued == 1);
    assert(!hasPendingForEpoch(&pending, epoch));
}

static void testNewSameEpochRequestCannotBeErasedByOldConsume()
{
    uint32_t epoch = 4;
    uint32_t serial = 0;
    uint64_t pending = 0;
    assert(request(&pending, &serial, &epoch));
    const uint64_t old = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);
    uint64_t expected = old;
    assert(__atomic_compare_exchange_n(&pending, &expected, uint64_t(0), false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    assert(request(&pending, &serial, &epoch));
    const uint64_t replacement = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);
    assert(replacement != old);

    // Simulate a late cleanup path holding the old token. It must not clear
    // the newer same-epoch request.
    expected = old;
    assert(!__atomic_compare_exchange_n(&pending, &expected, uint64_t(0), false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    assert(__atomic_load_n(&pending, __ATOMIC_ACQUIRE) == replacement);
}

static void testStaleRequestAndOldEpochCleanup()
{
    uint32_t epoch = 20;
    uint32_t serial = 0;
    uint64_t pending = 0;
    assert(request(&pending, &serial, &epoch));
    const uint64_t old = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);

    __atomic_store_n(&epoch, 21U, __ATOMIC_RELEASE);
    clearOlderEpoch(&pending, epoch);
    assert(__atomic_load_n(&pending, __ATOMIC_ACQUIRE) == 0);
    assert(!requestAtEpoch(&pending, &serial, &epoch, 20));
    assert(requestAtEpoch(&pending, &serial, &epoch, 21));
    const uint64_t current = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);
    assert(tagEpoch(current) == 21 && current != old);

    // Delayed cleanup from the old generation is compare-and-clear only.
    uint64_t expected = old;
    assert(!__atomic_compare_exchange_n(&pending, &expected, uint64_t(0), false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    assert(__atomic_load_n(&pending, __ATOMIC_ACQUIRE) == current);
}

static void testSequenceAndEpochWrap()
{
    uint32_t epoch = UINT32_MAX;
    uint32_t serial = UINT32_MAX;
    uint64_t pending = 0;
    assert(request(&pending, &serial, &epoch));
    const uint64_t beforeWrap = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);
    assert(tagEpoch(beforeWrap) == UINT32_MAX);
    assert(tagSerial(beforeWrap) == 1); // sequence zero is reserved

    __atomic_store_n(&epoch, 0U, __ATOMIC_RELEASE);
    clearOlderEpoch(&pending, epoch);
    assert(__atomic_load_n(&pending, __ATOMIC_ACQUIRE) == 0);
    assert(request(&pending, &serial, &epoch));
    const uint64_t afterWrap = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);
    assert(tagEpoch(afterWrap) == 0 && tagSerial(afterWrap) == 2);
    uint64_t taken = 0;
    assert(takeForEpoch(&pending, 0, &taken));
    assert(taken == afterWrap);
}

static void testBusyRetryDoesNotConsumeToken()
{
    uint32_t epoch = 7;
    uint32_t serial = 0;
    uint64_t pending = 0;
    assert(request(&pending, &serial, &epoch));
    // A simulated watchdog tick that cannot acquire gate+lifecycle does not
    // call takeForEpoch; the token remains available to the next tick.
    const uint64_t token = __atomic_load_n(&pending, __ATOMIC_ACQUIRE);
    assert(hasPendingForEpoch(&pending, epoch));
    assert(__atomic_load_n(&pending, __ATOMIC_ACQUIRE) == token);
    uint64_t taken = 0;
    assert(takeForEpoch(&pending, epoch, &taken));
    assert(taken == token);
}

static void testBoundedDrainStatusesKeepFallback()
{
    using IwxOutputKick::DrainResult;
    // If the 64th doorbell sets qfull, the loop reaches its budget before it
    // can observe qfull on the next iteration. It must still request a retry.
    assert(IwxOutputKick::classifyDrain(64, 64, DrainResult::kDrained) ==
           DrainResult::kBudgetExhausted);
    // Each malformed packet still consumes a dequeue slot before being
    // dropped; a full batch of such failures leaves a fallback kick.
    assert(IwxOutputKick::classifyDrain(64, 64, DrainResult::kDrained) ==
           DrainResult::kBudgetExhausted);
    // Management packets count against the same finite budget as data frames.
    assert(IwxOutputKick::classifyDrain(64, 64, DrainResult::kDrained) ==
           DrainResult::kBudgetExhausted);
    assert(IwxOutputKick::shouldContinueImmediately(DrainResult::kBudgetExhausted));
    assert(IwxOutputKick::shouldRetry(DrainResult::kTemporarilyBlocked));
    assert(!IwxOutputKick::shouldContinueImmediately(
        DrainResult::kTemporarilyBlocked));
    assert(!IwxOutputKick::shouldRetry(DrainResult::kDrained));

    // A consumed token followed by TX_MGMT_ONLY, qfull or TXFLUSH blocking is
    // republished for the same lifecycle epoch after the gate is released.
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        uint32_t epoch = 55 + scenario;
        uint32_t serial = 0;
        uint64_t pending = 0;
        assert(IwxOutputKick::request(&pending, &serial, &epoch));
        uint64_t taken = 0;
        assert(IwxOutputKick::takeForEpoch(&pending, epoch, &taken));
        const auto blocked = DrainResult::kTemporarilyBlocked;
        if (IwxOutputKick::shouldRetry(blocked))
            assert(IwxOutputKick::requestAtEpoch(&pending, &serial, &epoch,
                                                 epoch));
        assert(IwxOutputKick::hasPendingForEpoch(&pending, epoch));
    }

    // If the lifecycle changes between a gate miss and its outer retry
    // publication, requestAtEpoch rejects the stale captured epoch.
    uint32_t epoch = 88;
    uint32_t serial = 0;
    uint64_t pending = 0;
    __atomic_store_n(&epoch, 89U, __ATOMIC_RELEASE);
    assert(!IwxOutputKick::requestAtEpoch(&pending, &serial, &epoch, 88));
    assert(pending == 0);
}

int main()
{
    static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr),
                  "output retry token must be lock-free on the target");
    testBusyGatePreservesQueuedPacketUntilRetry();
    testNewSameEpochRequestCannotBeErasedByOldConsume();
    testStaleRequestAndOldEpochCleanup();
    testSequenceAndEpochWrap();
    testBusyRetryDoesNotConsumeToken();
    testBoundedDrainStatusesKeepFallback();
}
