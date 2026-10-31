#include "native/iwx_tx_completion_observation.hpp"
#include "native/iwx_tx_completion_publish.hpp"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <thread>

using namespace IwxTxCompletionPublish;

static iwx_tx_completion_event_input makeTxRsp(uint32_t outputEpoch)
{
    iwx_tx_completion_event_input event{};
    event.kind = IWX_TX_COMPLETION_TX_RSP;
    event.stage = IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL;
    event.terminal_reason = IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED;
    event.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;
    event.output_epoch = outputEpoch;
    event.driver_generation = 21;
    return event;
}

static Stamp fromSnapshot(const iwx_tx_completion_observation_snapshot &snapshot,
                          uint32_t generation, uint32_t outputEpoch)
{
    return Stamp{snapshot.publication_serial, generation, outputEpoch};
}

static Stamp currentStamp(const iwx_tx_completion_observation_state &state,
                          uint32_t generation, uint32_t outputEpoch)
{
    return Stamp{
        __atomic_load_n(&state.publication_serial, __ATOMIC_ACQUIRE),
        generation,
        outputEpoch
    };
}

static void testSerialZeroOwnerAndNoRepeat()
{
    OrdinaryCursor cursor;
    const Stamp first{0, 0, 0};
    assert(shouldPublishOrdinary(true, false, true, first, cursor));
    assert(canCommitOrdinary(true, first, first));
    commitOrdinary(&cursor, first);
    assert(!shouldPublishOrdinary(true, false, true, first, cursor));

    // The policy has no watchdog-owner argument: owner sequence zero cannot
    // suppress a new completion simply because the previous owner was zero.
    const Stamp next{1, 0, 0};
    assert(shouldPublishOrdinary(true, false, true, next, cursor));
    assert(canCommitOrdinary(true, next, next));
    commitOrdinary(&cursor, next);
    assert(cursor.last.publicationSerial == 1);
}

static void testUnavailableAndFailedPublishRetry()
{
    OrdinaryCursor cursor;
    const Stamp candidate{7, 9, 3};
    assert(!shouldPublishOrdinary(false, false, true, candidate, cursor));
    assert(!cursor.published);
    assert(shouldPublishOrdinary(true, false, true, candidate, cursor));
    assert(!canCommitOrdinary(false, candidate, candidate));
    assert(!cursor.published); // Failed write leaves the dirty stamp pending.
    assert(shouldPublishOrdinary(true, false, true, candidate, cursor));
    assert(canCommitOrdinary(true, candidate, candidate));
    commitOrdinary(&cursor, candidate);
    assert(!shouldPublishOrdinary(true, false, true, candidate, cursor));
}

static void testGenerationEpochResetAndStaleStamp()
{
    OrdinaryCursor cursor;
    commitOrdinary(&cursor, Stamp{12, 4, 8});

    // Same generation/epoch with regressed counters is a stale snapshot.
    assert(!shouldPublishOrdinary(true, false, true,
                                  Stamp{11, 4, 8}, cursor));
    assert(cursor.last.publicationSerial == 12);

    // A generation/epoch change alone cannot relabel the retained cut.
    const Stamp resetWithoutEvent{12, 5, 0};
    assert(!shouldPublishOrdinary(true, false, true,
                                  resetWithoutEvent, cursor));
    // A new related serial in the new generation is publishable.
    const Stamp resetWithEvent{13, 5, 1};
    assert(shouldPublishOrdinary(true, false, true,
                                 resetWithEvent, cursor));
}

static void testFrozenWatchdogCannotBeOverwritten()
{
    OrdinaryCursor cursor;
    const Stamp ordinary{3, 10, 7};
    assert(shouldPublishOrdinary(true, false, true, ordinary, cursor));
    commitOrdinary(&cursor, ordinary);

    const Stamp afterWatchdog{4, 10, 7};
    assert(!shouldPublishOrdinary(true, true, true, afterWatchdog, cursor));
    assert(cursor.last.publicationSerial == 3);
    // Once the frozen watchdog pending exists, ordinary periodic publication
    // stays gated, preserving its immutable owner snapshot.
    assert(!shouldPublishOrdinary(true, true, true,
                                  Stamp{5, 11, 8}, cursor));
}

static void testConcurrentTrySnapshotAndEventuallyPublish()
{
    iwx_tx_completion_observation_state state{};
    OrdinaryCursor cursor;
    std::atomic<bool> done{false};
    constexpr uint32_t kEvents = 20000;
    std::thread producer([&] {
        for (uint32_t i = 0; i < kEvents; ++i) {
            const auto event = makeTxRsp(17);
            (void)IwxTxCompletionObservation::record(&state, &event);
        }
        done.store(true, std::memory_order_release);
    });

    while (!done.load(std::memory_order_acquire)) {
        iwx_tx_completion_observation_snapshot snapshot{};
        if (!IwxTxCompletionObservation::snapshot(&state, &snapshot))
            continue; // Nonblocking contention becomes a later bounded retry.
        const Stamp captured = fromSnapshot(snapshot, 21, 17);
        const Stamp before = currentStamp(state, 21, 17);
        if (!shouldPublishOrdinary(snapshot.available, false,
                snapshot.publication_serial != 0, captured, cursor))
            continue;
        if (!sameStamp(captured, before))
            continue;
        const Stamp after = currentStamp(state, 21, 17);
        if (canCommitOrdinary(true, captured, after))
            commitOrdinary(&cursor, captured);
    }
    producer.join();

    iwx_tx_completion_observation_snapshot finalSnapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &finalSnapshot));
    assert(finalSnapshot.available == 1);
    const Stamp finalStamp = fromSnapshot(finalSnapshot, 21, 17);
    const Stamp afterFinal = currentStamp(state, 21, 17);
    assert(sameStamp(finalStamp, afterFinal));
    assert(finalSnapshot.publication_serial == 0);
    assert(!shouldPublishOrdinary(finalSnapshot.available, false,
            finalSnapshot.publication_serial != 0, finalStamp, cursor));
    assert(!cursor.published); // High-rate unrelated TX_RSP is not dirty.

    // Capture one related completion under the observer lock, then append a
    // later ordinary TX_RSP. The pending cut must preserve the related row.
    auto related = makeTxRsp(17);
    related.driver_generation = 21;
    iwx_tx_completion_observation_snapshot relatedCut{};
    assert(IwxTxCompletionObservation::record(
        &state, &related, &relatedCut));
    assert(relatedCut.publication_serial == 1);
    IwxTxCompletionPublish::Pending pending{};
    assert(IwxTxCompletionPublish::tryStore(&pending, &relatedCut));

    auto unrelated = makeTxRsp(17);
    unrelated.driver_generation = 21;
    assert(IwxTxCompletionObservation::record(&state, &unrelated));
    iwx_tx_completion_observation_snapshot pendingCopy{};
    assert(IwxTxCompletionPublish::tryCopy(&pending, &pendingCopy));
    assert(pendingCopy.next_serial == relatedCut.next_serial);
    assert(pendingCopy.publication_serial == relatedCut.publication_serial);
    assert(pendingCopy.last[IWX_TX_COMPLETION_TX_RSP].serial ==
           relatedCut.last[IWX_TX_COMPLETION_TX_RSP].serial);
    assert(pendingCopy.last[IWX_TX_COMPLETION_TX_RSP].driver_generation == 21);

    const Stamp relatedStamp = fromSnapshot(pendingCopy, 21, 17);
    assert(shouldPublishOrdinary(true, false, true,
                                 relatedStamp, cursor));
    const Stamp laterLive = currentStamp(state, 21, 17);
    assert(sameStamp(relatedStamp, laterLive)); // No new related serial.
    iwx_tx_completion_observation_snapshot laterLiveSnapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &laterLiveSnapshot));
    assert(laterLiveSnapshot.next_serial > pendingCopy.next_serial);
    // Live S2 is newer, but publishing the retained S1 cut is still valid;
    // sequence verification is against the pending slot, not the observer.
    IwxTxCompletionPublish::commitOrdinary(&cursor, relatedStamp);
    IwxTxCompletionPublish::Stamp pendingStamp{};
    assert(IwxTxCompletionPublish::tryReadStamp(&pending, &pendingStamp));
    assert(sameStamp(pendingStamp, cursor.last));
    assert(finalSnapshot.next_serial + finalSnapshot.dropped_count >= kEvents);
}

static void testPendingRejectsLateOlderCut()
{
    iwx_tx_completion_observation_state state{};
    auto olderEvent = makeTxRsp(3);
    olderEvent.driver_generation = 30;
    iwx_tx_completion_observation_snapshot older{};
    assert(IwxTxCompletionObservation::record(&state, &olderEvent, &older));

    auto newerEvent = makeTxRsp(4);
    newerEvent.driver_generation = 31;
    iwx_tx_completion_observation_snapshot newer{};
    assert(IwxTxCompletionObservation::record(&state, &newerEvent, &newer));
    assert(newer.publication_serial > older.publication_serial);

    Pending pending{};
    assert(tryStore(&pending, &newer));
    assert(!tryStore(&pending, &older)); // Producer unlocked/store reordered.
    assert(lostCount(&pending) == 1);

    iwx_tx_completion_observation_snapshot retained{};
    assert(tryCopy(&pending, &retained));
    assert(retained.publication_serial == newer.publication_serial);
    assert(retained.last[IWX_TX_COMPLETION_TX_RSP].driver_generation == 31);
    assert(retained.last[IWX_TX_COMPLETION_TX_RSP].output_epoch == 4);
}

static void testClaimProtectsCutAndRequiresAck()
{
    iwx_tx_completion_observation_state state{};
    auto firstEvent = makeTxRsp(7);
    firstEvent.driver_generation = 41;
    iwx_tx_completion_observation_snapshot first{};
    assert(IwxTxCompletionObservation::record(&state, &firstEvent, &first));

    auto laterEvent = makeTxRsp(8);
    laterEvent.driver_generation = 41;
    iwx_tx_completion_observation_snapshot later{};
    assert(IwxTxCompletionObservation::record(&state, &laterEvent, &later));

    Pending pending{};
    assert(tryStore(&pending, &first));
    iwx_tx_completion_observation_snapshot claimedCopy{};
    assert(tryClaimCopy(&pending, &claimedCopy));
    const Stamp firstStamp = fromSnapshot(claimedCopy, 41, 7);
    assert(!tryStore(&pending, &later)); // In-flight S1 is immutable.
    assert(lostCount(&pending) == 1);

    iwx_tx_completion_observation_snapshot stillFirst{};
    assert(tryCopy(&pending, &stillFirst));
    assert(stillFirst.publication_serial == first.publication_serial);
    assert(!tryDiscard(&pending, Stamp{firstStamp.publicationSerial + 1,
                                       firstStamp.generation,
                                       firstStamp.outputEpoch}));
    assert(finishClaim(&pending, firstStamp, false));
    assert(tryClaimCopy(&pending, &claimedCopy)); // Failed publish is retryable.
    assert(tryDiscard(&pending, firstStamp));
    assert(!tryReadStamp(&pending, nullptr));
}

static void testRelatedObserverLockMissIsVisibleAndUnrelatedIsQuiet()
{
    iwx_tx_completion_observation_state state{};
    auto unrelated = makeTxRsp(9);
    assert(IwxTxCompletionObservation::record(&state, &unrelated));
    iwx_tx_completion_observation_snapshot noCut{};
    assert(IwxTxCompletionObservation::snapshot(&state, &noCut));
    assert(noCut.publication_serial == 0);
    assert(noCut.related_dropped_count == 0);

    __atomic_store_n(&state.lock, 1U, __ATOMIC_RELEASE);
    iwx_tx_completion_observation_snapshot relatedCut{};
    auto related = makeTxRsp(9);
    assert(!IwxTxCompletionObservation::record(
        &state, &related, &relatedCut));
    __atomic_store_n(&state.lock, 0U, __ATOMIC_RELEASE);
    iwx_tx_completion_observation_snapshot afterMiss{};
    assert(IwxTxCompletionObservation::snapshot(&state, &afterMiss));
    assert(afterMiss.related_dropped_count == 1);
    assert(afterMiss.publication_serial == 0);
}

int main()
{
    testSerialZeroOwnerAndNoRepeat();
    testUnavailableAndFailedPublishRetry();
    testGenerationEpochResetAndStaleStamp();
    testFrozenWatchdogCannotBeOverwritten();
    testConcurrentTrySnapshotAndEventuallyPublish();
    testPendingRejectsLateOlderCut();
    testClaimProtectsCutAndRequiresAck();
    testRelatedObserverLockMissIsVisibleAndUnrelatedIsQuiet();
}
