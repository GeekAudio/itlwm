#include "../group2_tx_trace_helpers.h"

#include <cassert>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>

static IwxGroup2TxEvent eventFor(const IwxGroup2TxTag &tag,
                                uint16_t stage, int32_t result = 0)
{
    IwxGroup2TxEvent event{};
    iwx_group2_tx_event_from_tag(&event, &tag, 1000u + stage, stage);
    event.result = result;
    return event;
}

int main()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);

    IwxGroup2TxTag tag{};
    assert(iwx_group2_tx_trace_begin(&trace, 100, 77,
        IWX_GROUP2_TX_SOURCE_RSN, 9, 3, &tag));
    assert(iwx_group2_tx_tag_valid(&tag));
    assert(tag.cookie == 1 && tag.attempt_id == 77);

    // The queue API reports a call-level drop count; the helper keeps that
    // number attached to the operation without claiming it freed this tag.
    IwxGroup2TxEvent queued = eventFor(
        tag, IWX_GROUP2_TX_STAGE_IFQ_ENQUEUE, 1);
    queued.flags |= IWX_GROUP2_TX_QUEUE_DROP_COUNT_PRESENT |
                    IWX_GROUP2_TX_HAS_QUEUE;
    queued.queue_id = 0;
    assert(iwx_group2_tx_trace_record(&trace, &queued));
    assert(iwx_group2_tx_tag_valid(&tag));

    // A dequeue observer copies only numeric tag contents before any packet
    // transform. A later pullup failure is still tied to that copied token.
    IwxGroup2TxTag copied = tag;
    IwxGroup2TxEvent dequeued = eventFor(
        copied, IWX_GROUP2_TX_STAGE_DEQUEUED);
    dequeued.flags |= IWX_GROUP2_TX_TAG_PRESENT;
    assert(iwx_group2_tx_trace_record(&trace, &dequeued));
    IwxGroup2TxEvent pullupFailure = eventFor(
        copied, IWX_GROUP2_TX_STAGE_PULLUP_FAILED, 12);
    assert(iwx_group2_tx_trace_record(&trace, &pullupFailure));
    assert(pullupFailure.cookie == tag.cookie);

    IwxGroup2TxTag malformed = tag;
    malformed.bytes--;
    assert(!iwx_group2_tx_tag_valid(&malformed));
    assert(!iwx_group2_tx_tag_valid(nullptr));

    // Commit a numeric slot sidecar, then match only the bounded exclusive
    // reclaim interval [tail, checkedIndex).
    IwxGroup2TxSlot slots[8]{};
    assert(iwx_group2_tx_slot_prepare(&trace, &tag, 12, 12,
        1, 5, 8, 0x0008, 0x1230, 15, &slots[5]));
    assert(slots[5].valid && slots[5].cookie == tag.cookie);
    assert(slots[5].slot_generation == 1);

    IwxGroup2TxTag outsideTag{};
    assert(iwx_group2_tx_trace_begin(&trace, 200, 78,
        IWX_GROUP2_TX_SOURCE_WPA, 12, 3, &outsideTag));
    assert(iwx_group2_tx_slot_prepare(&trace, &outsideTag, 12, 12,
        1, 6, 8, 0x0008, 0x1230, 15, &slots[6]));

    IwxGroup2TxSlot matched{};
    uint32_t match = iwx_group2_tx_match_completion(
        slots, 8, 4, 2, 6, 1, 12, 12, 0x0008, 0x1230, 0, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_UNIQUE);
    assert(matched.cookie == tag.cookie && matched.index == 5);

    // checkedIndex is exclusive: the packet at slot 6 is not part of [4, 6).
    assert(slots[6].cookie == outsideTag.cookie);
    match = iwx_group2_tx_match_completion(
        slots, 8, 4, 2, 6, 1, 12, 12, 0x0008, 0x1230, 0, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_UNIQUE);
    assert(matched.cookie == tag.cookie);

    // Slot reuse overwrites the numeric sidecar; it cannot inherit the prior
    // cookie or slot generation.
    IwxGroup2TxTag reusedTag{};
    assert(iwx_group2_tx_trace_begin(&trace, 300, 79,
        IWX_GROUP2_TX_SOURCE_RSN, 12, 3, &reusedTag));
    assert(iwx_group2_tx_slot_prepare(&trace, &reusedTag, 12, 12,
        1, 5, 8, 0x0008, 0x1240, 15, &slots[5]));
    assert(slots[5].cookie == reusedTag.cookie);
    assert(slots[5].slot_generation == 3);
    match = iwx_group2_tx_match_completion(
        slots, 8, 4, 2, 6, 1, 12, 12, 0x0008, 0x1240, 0, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_UNIQUE);
    assert(matched.cookie == reusedTag.cookie);

    // Generation mismatch, duplicate live candidates, bad interval, and
    // reset ambiguity all preserve an unknown correlation result.
    match = iwx_group2_tx_match_completion(
        slots, 8, 4, 2, 6, 1, 13, 13, 0x0008, 0x1240, 0, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_GENERATION_MISMATCH);
    slots[6] = slots[5];
    slots[6].index = 6;
    match = iwx_group2_tx_match_completion(
        slots, 8, 4, 3, 7, 1, 12, 12, 0x0008, 0x1240, 0, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_MULTIPLE);
    match = iwx_group2_tx_match_completion(
        slots, 8, 4, 2, 4, 1, 12, 12, 0x0008, 0x1240, 0, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_BAD_RANGE);
    match = iwx_group2_tx_match_completion(
        slots, 8, 4, 2, 6, 1, 12, 12, 0x0008, 0x1240, 1, 0, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS);

    // Exercise the production trace-owned slot sidecar used by the TX patch.
    IwxGroup2TxTrace integrated{};
    iwx_group2_tx_trace_init(&integrated);
    IwxGroup2TxTag integratedTag{};
    assert(iwx_group2_tx_trace_begin(&integrated, 500, 90,
        IWX_GROUP2_TX_SOURCE_RSN, 20, 4, &integratedTag));
    IwxGroup2TxEvent integratedEnqueue = eventFor(
        integratedTag, IWX_GROUP2_TX_STAGE_IFQ_ENQUEUE, 2);
    integratedEnqueue.flags |= IWX_GROUP2_TX_QUEUE_DROP_COUNT_PRESENT |
                               IWX_GROUP2_TX_HAS_QUEUE;
    integratedEnqueue.queue_id = UINT32_MAX; // software if_snd operation
    assert(iwx_group2_tx_trace_record(&integrated, &integratedEnqueue));
    IwxGroup2TxSlot committed{};
    assert(iwx_group2_tx_trace_prepare_slot(&integrated, &integratedTag,
        21, 22, 5, 4, 8, 0x0008, 0x5000, 15, &committed));
    assert(committed.valid && committed.index == 4 &&
           committed.cookie == integratedTag.cookie);
    IwxGroup2TxSlot integratedMatch{};
    match = iwx_group2_tx_trace_match_completion(&integrated, 501,
        3, 2, 5, 5, 8, 21, 22, 0x0008, 0x5000, 0,
        0x2345,
        &integratedMatch);
    assert(match == IWX_GROUP2_TX_MATCH_UNIQUE);
    assert(integratedMatch.cookie == integratedTag.cookie &&
           integratedMatch.index == 4);
    assert(integrated.events[(integrated.event_cursor +
        IWX_GROUP2_TX_TRACE_CAPACITY - 1) % IWX_GROUP2_TX_TRACE_CAPACITY].flags &
        IWX_GROUP2_TX_HAS_FIRMWARE_STATUS);
    assert(integrated.events[(integrated.event_cursor +
        IWX_GROUP2_TX_TRACE_CAPACITY - 1) % IWX_GROUP2_TX_TRACE_CAPACITY].result ==
        0x2345);
    assert(iwx_group2_tx_trace_retire_reclaimed_interval(&integrated, 502,
        3, 2, 5, 5, 8, match, integratedMatch.slot_generation) == 1);
    assert(!iwx_group2_tx_trace_has_live_slot_for_queue(&integrated, 5));

    // Ordinary TX responses outside every Group2 sidecar interval must not
    // consume the bounded Group2 evidence ring.
    IwxGroup2TxTrace unrelatedResponses{};
    iwx_group2_tx_trace_init(&unrelatedResponses);
    for (uint32_t i = 0; i < 100; ++i) {
        uint32_t relatedSidecar = 1;
        match = iwx_group2_tx_trace_match_completion_ex(&unrelatedResponses,
            510 + i, 1, 2, 3, 5, 8, 21, 22, 0x0008, 0x5000, 0,
            1, &integratedMatch, &relatedSidecar);
        assert(match == IWX_GROUP2_TX_MATCH_NONE);
        assert(relatedSidecar == 0);
    }
    assert(unrelatedResponses.next_event_sequence == 0 &&
           unrelatedResponses.event_count == 0 &&
           unrelatedResponses.dropped_count == 0);
    assert(iwx_group2_tx_trace_retire_reclaimed_interval(
        &unrelatedResponses, 620, 1, 2, 3, 5, 8,
        IWX_GROUP2_TX_MATCH_NONE, 0) == 0);

    // A response inside a real Group2 sidecar interval remains observable
    // when the numeric frame signature does not match; it cannot be promoted
    // to a unique packet or successful send.
    IwxGroup2TxTrace unmatchedResponse{};
    iwx_group2_tx_trace_init(&unmatchedResponse);
    IwxGroup2TxTag unmatchedTag{};
    IwxGroup2TxSlot unmatchedSlot{};
    assert(iwx_group2_tx_trace_begin(&unmatchedResponse, 621, 97,
        IWX_GROUP2_TX_SOURCE_RSN, 21, 4, &unmatchedTag));
    assert(iwx_group2_tx_trace_prepare_slot(&unmatchedResponse,
        &unmatchedTag, 21, 22, 5, 2, 8, 0x0008, 0x5000, 15,
        &unmatchedSlot));
    uint32_t relatedSidecar = 0;
    match = iwx_group2_tx_trace_match_completion_ex(&unmatchedResponse, 622,
        1, 2, 3, 5, 8, 21, 22, 0x0008, 0x5010, 0,
        1, &integratedMatch, &relatedSidecar);
    assert(match == IWX_GROUP2_TX_MATCH_NONE && !integratedMatch.valid);
    assert(relatedSidecar == 1); // MATCH_NONE with a real sidecar is relevant.
    const IwxGroup2TxEvent &unmatchedEvent = unmatchedResponse.events[
        (unmatchedResponse.event_cursor + IWX_GROUP2_TX_TRACE_CAPACITY - 1) %
        IWX_GROUP2_TX_TRACE_CAPACITY];
    assert(unmatchedEvent.stage == IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN &&
           unmatchedEvent.status == IWX_GROUP2_TX_MATCH_NONE &&
           !(unmatchedEvent.flags & IWX_GROUP2_TX_HAS_COOKIE) &&
           (unmatchedEvent.flags & IWX_GROUP2_TX_HAS_FIRMWARE_STATUS));
    assert(iwx_group2_tx_trace_retire_reclaimed_interval(
        &unmatchedResponse, 623, 1, 2, 3, 5, 8,
        IWX_GROUP2_TX_MATCH_NONE, 0) == 1);

    // A lock miss in the observer must not gate real reclaim. The subsequent
    // verified interval retires the old sidecar; poison keeps a later reused
    // hardware index from being mapped to that stale cookie.
    IwxGroup2TxTrace lockMiss{};
    iwx_group2_tx_trace_init(&lockMiss);
    IwxGroup2TxTag staleTag{};
    IwxGroup2TxSlot staleSlot{};
    assert(iwx_group2_tx_trace_begin(&lockMiss, 600, 92,
        IWX_GROUP2_TX_SOURCE_RSN, 30, 5, &staleTag));
    assert(iwx_group2_tx_trace_prepare_slot(&lockMiss, &staleTag,
        31, 32, 6, 2, 8, 0x0008, 0x6010, 15, &staleSlot));
    __atomic_store_n(&lockMiss.writer, 1u, __ATOMIC_RELEASE);
    assert(!iwx_group2_tx_trace_has_live_slot_for_queue(&lockMiss, 6));
    __atomic_store_n(&lockMiss.writer, 0u, __ATOMIC_RELEASE);
    assert(lockMiss.identity_epoch == 1);
    match = iwx_group2_tx_trace_match_completion(&lockMiss, 601,
        1, 2, 3, 6, 8, 31, 32, 0x0008, 0x6010, 0,
        0x1234, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_UNKNOWN && !matched.valid);
    // This helper is called after the independently completed ring reclaim.
    assert(iwx_group2_tx_trace_retire_reclaimed_interval(&lockMiss, 602,
        1, 2, 3, 6, 8, IWX_GROUP2_TX_MATCH_UNKNOWN, 0) == 1);
    for (const auto &slot : lockMiss.slots)
        assert(!slot.valid);
    IwxGroup2TxTag reusedAfterLoss{};
    assert(iwx_group2_tx_trace_begin(&lockMiss, 603, 93,
        IWX_GROUP2_TX_SOURCE_WPA, 31, 5, &reusedAfterLoss));
    IwxGroup2TxSlot afterLossSlot{};
    assert(iwx_group2_tx_trace_prepare_slot(&lockMiss, &reusedAfterLoss,
        31, 32, 6, 2, 8, 0x0008, 0x6020, 15, &afterLossSlot));
    assert(afterLossSlot.valid && afterLossSlot.identity_epoch == 1);
    match = iwx_group2_tx_trace_match_completion(&lockMiss, 604,
        1, 2, 3, 6, 8, 31, 32, 0x0008, 0x6020, 0,
        0x1234, &matched);
    assert(match == IWX_GROUP2_TX_MATCH_UNIQUE && matched.valid &&
           matched.cookie == reusedAfterLoss.cookie &&
           matched.cookie != staleTag.cookie);

    // A duplicate live queue/index is ambiguous even when the two numeric
    // cookies differ; it poisons correlation instead of making one unique.
    IwxGroup2TxTrace duplicate{};
    iwx_group2_tx_trace_init(&duplicate);
    IwxGroup2TxTag duplicateTag{};
    IwxGroup2TxSlot firstDuplicate{};
    IwxGroup2TxSlot secondDuplicate{};
    assert(iwx_group2_tx_trace_begin(&duplicate, 700, 94,
        IWX_GROUP2_TX_SOURCE_RSN, 32, 6, &duplicateTag));
    assert(iwx_group2_tx_trace_prepare_slot(&duplicate, &duplicateTag,
        33, 34, 7, 3, 8, 0x0008, 0x7010, 15, &firstDuplicate));
    IwxGroup2TxTag duplicateTag2{};
    assert(iwx_group2_tx_trace_begin(&duplicate, 701, 95,
        IWX_GROUP2_TX_SOURCE_WPA, 32, 6, &duplicateTag2));
    assert(!iwx_group2_tx_trace_prepare_slot(&duplicate, &duplicateTag2,
        33, 34, 7, 3, 8, 0x0008, 0x7020, 15, &secondDuplicate));
    assert(duplicate.identity_epoch == 1);

    // A verified flush reclaim retires only [tail, checkedIndex); each event
    // says unknown and has its own flush stage, never TX_RSP or ACK.
    IwxGroup2TxTrace flushed{};
    iwx_group2_tx_trace_init(&flushed);
    IwxGroup2TxTag flushTag{};
    assert(iwx_group2_tx_trace_begin(&flushed, 800, 96,
        IWX_GROUP2_TX_SOURCE_RSN, 40, 7, &flushTag));
    IwxGroup2TxSlot flushAtTail{};
    IwxGroup2TxSlot flushInside{};
    IwxGroup2TxSlot flushAtExclusiveEnd{};
    assert(iwx_group2_tx_trace_prepare_slot(&flushed, &flushTag,
        41, 42, 8, 2, 8, 0x0008, 0x8010, 15, &flushAtTail));
    IwxGroup2TxTag flushTag2 = flushTag;
    flushTag2.cookie += 1;
    flushTag2.attempt_id += 1;
    assert(iwx_group2_tx_trace_prepare_slot(&flushed, &flushTag2,
        41, 42, 8, 4, 8, 0x0008, 0x8020, 15, &flushInside));
    IwxGroup2TxTag flushTag3 = flushTag;
    flushTag3.cookie += 2;
    flushTag3.attempt_id += 2;
    assert(iwx_group2_tx_trace_prepare_slot(&flushed, &flushTag3,
        41, 42, 8, 5, 8, 0x0008, 0x8030, 15, &flushAtExclusiveEnd));
    assert(iwx_group2_tx_trace_retire_flushed_interval(&flushed, 801,
        2, 3, 5, 8, 8) == 2);
    uint32_t remainingFlushSlots = 0;
    for (const auto &slot : flushed.slots) {
        if (!slot.valid)
            continue;
        ++remainingFlushSlots;
        assert(slot.index == 5 &&
               slot.cookie == flushAtExclusiveEnd.cookie);
    }
    assert(remainingFlushSlots == 1);
    uint32_t flushEvents = 0;
    for (const auto &event : flushed.events) {
        if (event.stage != IWX_GROUP2_TX_STAGE_FLUSH_RECLAIM_UNKNOWN)
            continue;
        ++flushEvents;
        assert(event.status == IWX_GROUP2_TX_MATCH_UNKNOWN);
        assert(event.flags & IWX_GROUP2_TX_HAS_MATCH_RESULT);
        assert(!(event.flags & IWX_GROUP2_TX_HAS_FIRMWARE_STATUS));
    }
    assert(flushEvents == 2);

    // dropped_count has a lock-free writer and an atomic snapshot reader.
    IwxGroup2TxTrace concurrentLoss{};
    iwx_group2_tx_trace_init(&concurrentLoss);
    std::atomic<bool> startLoss{false};
    std::atomic<uint32_t> doneLoss{0};
    std::thread lossWorkers[4];
    for (auto &worker : lossWorkers) {
        worker = std::thread([&]() {
            while (!startLoss.load(std::memory_order_acquire)) {}
            for (uint32_t i = 0; i < 10000; ++i)
                iwx_group2_tx_trace_note_lost(&concurrentLoss);
            doneLoss.fetch_add(1, std::memory_order_release);
        });
    }
    startLoss.store(true, std::memory_order_release);
    while (doneLoss.load(std::memory_order_acquire) != 4) {
        IwxGroup2TxTraceSnapshot racingSnapshot{};
        (void)iwx_group2_tx_trace_snapshot(&concurrentLoss, &racingSnapshot);
    }
    for (auto &worker : lossWorkers)
        worker.join();
    IwxGroup2TxTraceSnapshot finalLossSnapshot{};
    assert(iwx_group2_tx_trace_snapshot(&concurrentLoss,
        &finalLossSnapshot));
    assert(finalLossSnapshot.dropped_count == 40000);
    assert(concurrentLoss.identity_epoch == 40000);

    // Wrapping a full event ring preserves nonzero wire sequence values and
    // the contiguous oldest-to-newest order used by the offline decoder.
    IwxGroup2TxTrace wrapped{};
    iwx_group2_tx_trace_init(&wrapped);
    for (uint32_t i = 0; i < 519; ++i) {
        IwxGroup2TxEvent response{};
        response.monotonic_us = 9000 + i;
        response.stage = IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN;
        response.status = IWX_GROUP2_TX_MATCH_UNKNOWN;
        response.flags = IWX_GROUP2_TX_HAS_MATCH_RESULT;
        assert(iwx_group2_tx_trace_record(&wrapped, &response));
    }
    IwxGroup2TxTraceSnapshot wrappedSnapshot{};
    assert(iwx_group2_tx_trace_snapshot(&wrapped, &wrappedSnapshot));
    assert(wrappedSnapshot.event_count == IWX_GROUP2_TX_TRACE_CAPACITY &&
           wrappedSnapshot.next_event_sequence == 519 &&
           wrappedSnapshot.dropped_count == 487 &&
           wrapped.identity_epoch == 0 &&
           wrappedSnapshot.events[0].sequence == 488 &&
           wrappedSnapshot.events[31].sequence == 519);
    iwx_group2_tx_snapshot_to_le_in_place(&wrappedSnapshot);
    assert(wrappedSnapshot.events[0].sequence == 488 &&
           wrappedSnapshot.events[31].sequence == 519);

    // Evicting history from a full trace ring must not invalidate a live slot.
    // The result below is only a host-side slot correlation, not firmware or
    // peer acceptance.
    IwxGroup2TxTrace fullRingCompletion{};
    iwx_group2_tx_trace_init(&fullRingCompletion);
    for (uint32_t i = 0; i < IWX_GROUP2_TX_TRACE_CAPACITY; ++i) {
        IwxGroup2TxEvent history{};
        history.monotonic_us = 11000 + i;
        history.stage = IWX_GROUP2_TX_STAGE_ORIGIN;
        assert(iwx_group2_tx_trace_record(&fullRingCompletion, &history));
    }
    IwxGroup2TxTag fullRingTag{};
    assert(iwx_group2_tx_trace_begin(&fullRingCompletion, 11032, 29,
        IWX_GROUP2_TX_SOURCE_RSN, 20, 4, &fullRingTag));
    IwxGroup2TxSlot fullRingSlot{};
    assert(iwx_group2_tx_trace_prepare_slot(&fullRingCompletion,
        &fullRingTag, 21, 22, 7, 4, 8, 0x0008, 0x4500, 15,
        &fullRingSlot));
    assert(fullRingSlot.valid && fullRingCompletion.identity_epoch == 0);
    IwxGroup2TxSlot fullRingMatched{};
    match = iwx_group2_tx_trace_match_completion(&fullRingCompletion,
        11033, 3, 2, 5, 7, 8, 21, 22, 0x0008, 0x4500, 0,
        -1, &fullRingMatched);
    assert(match == IWX_GROUP2_TX_MATCH_UNIQUE && fullRingMatched.valid &&
           fullRingMatched.cookie == fullRingTag.cookie &&
           fullRingCompletion.identity_epoch == 0);
    IwxGroup2TxTraceSnapshot fullRingSnapshot{};
    assert(iwx_group2_tx_trace_snapshot(&fullRingCompletion,
        &fullRingSnapshot));
    const IwxGroup2TxEvent &fullRingResponse = fullRingSnapshot.events[
        fullRingSnapshot.event_count - 1];
    assert(fullRingSnapshot.next_event_sequence == 34 &&
           fullRingSnapshot.dropped_count == 2 &&
           fullRingResponse.sequence == 34 &&
           fullRingResponse.stage == IWX_GROUP2_TX_STAGE_TX_RSP_MATCH &&
           fullRingResponse.status == IWX_GROUP2_TX_MATCH_UNIQUE &&
           !(fullRingResponse.flags & IWX_GROUP2_TX_HAS_FIRMWARE_STATUS));

    // A writer-independent loss can poison identity after append and before
    // the caller downgrades the event. Rewriting must retain the append-time
    // sequence while removing packet identity.
    IwxGroup2TxTrace poisonedWrites{};
    iwx_group2_tx_trace_init(&poisonedWrites);
    for (uint32_t i = 0; i < IWX_GROUP2_TX_TRACE_CAPACITY; ++i) {
        IwxGroup2TxEvent event{};
        event.monotonic_us = 12000 + i;
        event.cookie = 900 + i;
        event.attempt_id = 30 + i;
        event.stage = IWX_GROUP2_TX_STAGE_TX_RSP_MATCH;
        event.status = IWX_GROUP2_TX_MATCH_UNIQUE;
        event.flags = IWX_GROUP2_TX_HAS_COOKIE |
            IWX_GROUP2_TX_HAS_ATTEMPT | IWX_GROUP2_TX_HAS_MATCH_RESULT;
        assert(iwx_group2_tx_trace_try_lock(&poisonedWrites));
        assert(iwx_group2_tx_trace_append_locked(&poisonedWrites, &event));
        // Models note_lost() racing after append; it is intentionally atomic
        // and does not wait for the trace writer lock.
        iwx_group2_tx_trace_note_lost(&poisonedWrites);
        event.stage = IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN;
        event.status = IWX_GROUP2_TX_MATCH_UNKNOWN;
        iwx_group2_tx_event_clear_identity(&event);
        iwx_group2_tx_trace_rewrite_last_locked(&poisonedWrites, &event);
        iwx_group2_tx_trace_unlock(&poisonedWrites);
    }
    IwxGroup2TxTraceSnapshot poisonedSnapshot{};
    assert(iwx_group2_tx_trace_snapshot(&poisonedWrites, &poisonedSnapshot));
    assert(poisonedSnapshot.next_event_sequence ==
               IWX_GROUP2_TX_TRACE_CAPACITY &&
           poisonedSnapshot.dropped_count == IWX_GROUP2_TX_TRACE_CAPACITY);
    for (uint32_t i = 0; i < IWX_GROUP2_TX_TRACE_CAPACITY; ++i) {
        const IwxGroup2TxEvent &event = poisonedSnapshot.events[i];
        assert(event.sequence == i + 1 &&
               event.stage == IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN &&
               event.status == IWX_GROUP2_TX_MATCH_UNKNOWN &&
               !(event.flags & IWX_GROUP2_TX_HAS_COOKIE) &&
               !(event.flags & IWX_GROUP2_TX_HAS_ATTEMPT));
    }

    // A live TX slot crossing reset is explicitly invalidated and stays
    // unknown; a later response cannot claim its old cookie.
    IwxGroup2TxTag resetTag{};
    assert(iwx_group2_tx_trace_begin(&integrated, 503, 91,
        IWX_GROUP2_TX_SOURCE_WPA, 21, 4, &resetTag));
    IwxGroup2TxSlot resetSlot{};
    assert(iwx_group2_tx_trace_prepare_slot(&integrated, &resetTag,
        21, 22, 5, 5, 8, 0x0008, 0x5010, 15, &resetSlot));
    iwx_group2_tx_trace_invalidate_slots(&integrated, 504, 22);
    match = iwx_group2_tx_trace_match_completion(&integrated, 505,
        4, 2, 6, 5, 8, 22, 23, 0x0008, 0x5010, 1,
        -1,
        &integratedMatch);
    assert(match == IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS);
    assert(!integratedMatch.valid);

    // Saturated counters stop creating identities instead of wrapping.
    trace.next_cookie = UINT64_MAX;
    IwxGroup2TxTag unavailable{};
    assert(!iwx_group2_tx_trace_begin(&trace, 400, 80,
        IWX_GROUP2_TX_SOURCE_RSN, 12, 3, &unavailable));
    assert(trace.cookie_saturated == 1 && trace.next_cookie == UINT64_MAX);
    trace.next_slot_generation = UINT64_MAX;
    uint64_t generation = 0;
    assert(!iwx_group2_tx_trace_next_slot_generation(&trace, &generation));
    assert(trace.slot_generation_saturated == 1 &&
           trace.next_slot_generation == UINT64_MAX);

    IwxGroup2TxTraceSnapshot snapshot{};
    assert(iwx_group2_tx_trace_snapshot(&trace, &snapshot));
    assert(snapshot.magic == IWX_GROUP2_TX_TRACE_MAGIC);
    assert(snapshot.schema == IWX_GROUP2_TX_TRACE_SCHEMA);
    assert(snapshot.event_count > 0 && snapshot.event_count <=
           IWX_GROUP2_TX_TRACE_CAPACITY);
    assert(snapshot.next_cookie == UINT64_MAX);
    assert(snapshot.flags == 3u);

    IwxGroup2TxTraceSnapshot wire{};
    iwx_group2_tx_snapshot_to_le(&wire, &snapshot);
    assert(wire.magic == IWX_GROUP2_TX_TRACE_MAGIC);
    assert(sizeof(wire) == IWX_GROUP2_TX_TRACE_SNAPSHOT_BYTES);
    IwxGroup2TxTraceSnapshot inPlace = snapshot;
    iwx_group2_tx_snapshot_to_le_in_place(&inPlace);
    assert(std::memcmp(&wire, &inPlace, sizeof(wire)) == 0);
    return 0;
}
