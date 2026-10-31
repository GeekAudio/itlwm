#include "../group2_tx_trace_helpers.h"
#include <cassert>
#include <cstdint>
#include <cstdio>

#ifndef EXPECT_ORIGINAL
#define EXPECT_ORIGINAL 0
#endif

static IwxGroup2TxTag beginTag(IwxGroup2TxTrace &trace, uint32_t attempt)
{
    IwxGroup2TxTag tag{};
    assert(iwx_group2_tx_trace_begin(&trace, 1000 + attempt, attempt,
        IWX_GROUP2_TX_SOURCE_RSN, 5, 2, &tag));
    return tag;
}

static uint32_t validSlots(const IwxGroup2TxTrace &trace)
{
    uint32_t count = 0;
    for (const auto &slot : trace.slots)
        count += slot.valid != 0;
    return count;
}

static void testLegacyPrepareAt256And1024()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    IwxGroup2TxTag tag = beginTag(trace, 1);
    IwxGroup2TxSlot slot{};
    assert(iwx_group2_tx_slot_prepare(&trace, &tag, 6, 7, 5,
        255, 256, 0x0008, 0x1000, 15, &slot));
    assert(slot.valid && slot.ring_count == 256 && slot.index == 255);

    IwxGroup2TxTrace gen3{};
    iwx_group2_tx_trace_init(&gen3);
    IwxGroup2TxTag gen3Tag = beginTag(gen3, 2);
    IwxGroup2TxSlot gen3Slot{};
    const int accepted = iwx_group2_tx_slot_prepare(&gen3, &gen3Tag,
        6, 7, 5, 1023, 1024, 0x0008, 0x2000, 15, &gen3Slot);
#if EXPECT_ORIGINAL
    assert(!accepted);
    assert(gen3.next_slot_generation == 0 && !gen3Slot.valid);
#else
    assert(accepted);
    assert(gen3.next_slot_generation == 1 && gen3Slot.valid);
    assert(gen3Slot.index == 1023 && gen3Slot.ring_count == 1024);
#endif
}

static void testTracePrepareAndCompletionPath()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    IwxGroup2TxTag tag = beginTag(trace, 3);
    IwxGroup2TxSlot slot{};
    const int prepared = iwx_group2_tx_trace_prepare_slot(&trace, &tag,
        21, 22, 5, 1023, 1024, 0x0008, 0x3030, 15, &slot);
#if EXPECT_ORIGINAL
    assert(!prepared);
    assert(trace.next_slot_generation == 0 && validSlots(trace) == 0);
    assert(trace.identity_epoch == 0 && trace.writer == 0);
#else
    assert(prepared);
    assert(trace.next_slot_generation == 1 && validSlots(trace) == 1);
    assert(slot.index == 1023 && slot.ring_count == 1024);
    assert(IWX_GROUP2_TX_SLOT_CAPACITY == 32u);
#endif

    IwxGroup2TxSlot matched{};
    const uint32_t result = iwx_group2_tx_trace_match_completion(&trace,
        1100, 1022, 2, 0, 5, 1024, 21, 22, 0x0008, 0x3030,
        0, -1, &matched);
#if EXPECT_ORIGINAL
    assert(result == IWX_GROUP2_TX_MATCH_NONE && !matched.valid);
    assert(iwx_group2_tx_trace_retire_reclaimed_interval(&trace, 1200,
        1022, 2, 0, 5, 1024, IWX_GROUP2_TX_MATCH_NONE, 0) == 0);
    assert(validSlots(trace) == 0);
#else
    assert(result == IWX_GROUP2_TX_MATCH_UNIQUE && matched.valid);
    assert(matched.index == 1023 && matched.slot_generation == 1);
    assert(iwx_group2_tx_trace_retire_reclaimed_interval(&trace, 1200,
        1022, 2, 0, 5, 1024, result, matched.slot_generation) == 1);
    assert(validSlots(trace) == 0);
#endif
}

static void testSparseHelpersAt1024()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    IwxGroup2TxTag tag = beginTag(trace, 4);
    IwxGroup2TxSlot slot{};
    const int prepared = iwx_group2_tx_trace_prepare_slot(&trace, &tag,
        31, 32, 6, 1023, 1024, 0x0008, 0x4040, 15, &slot);
#if EXPECT_ORIGINAL
    assert(!prepared);
#else
    assert(prepared);
#endif
    const int hasSidecar = iwx_group2_tx_interval_has_sidecar_sparse(
        trace.slots, IWX_GROUP2_TX_SLOT_CAPACITY, 1024,
        1022, 2, 0, 6);
    const uint32_t sparseResult = iwx_group2_tx_match_completion_sparse(
        trace.slots, IWX_GROUP2_TX_SLOT_CAPACITY, 1024,
        1022, 2, 0, 6, 31, 32, 0x0008, 0x4040,
        0, trace.identity_epoch, nullptr);
#if EXPECT_ORIGINAL
    assert(!hasSidecar);
    assert(sparseResult == IWX_GROUP2_TX_MATCH_BAD_RANGE);
#else
    assert(hasSidecar);
    assert(sparseResult == IWX_GROUP2_TX_MATCH_UNIQUE);
#endif
}

static void testDenseMatcherAt1024()
{
    IwxGroup2TxSlot slots[1024]{};
    IwxGroup2TxSlot &slot = slots[1023];
    slot.cookie = 44;
    slot.slot_generation = 1;
    slot.attempt_id = 44;
    slot.source = IWX_GROUP2_TX_SOURCE_RSN;
    slot.context_generation = 41;
    slot.output_epoch = 42;
    slot.queue_id = 7;
    slot.index = 1023;
    slot.ring_count = 1024;
    slot.frame_control = 0x0008;
    slot.sequence_control = 0x5050;
    slot.identity_epoch = 0;
    slot.valid = 1;
    IwxGroup2TxSlot matched{};
    const uint32_t result = iwx_group2_tx_match_completion(
        slots, 1024, 1022, 2, 0, 7, 41, 42, 0x0008,
        0x5050, 0, 0, &matched);
#if EXPECT_ORIGINAL
    assert(result == IWX_GROUP2_TX_MATCH_BAD_RANGE && !matched.valid);
#else
    assert(result == IWX_GROUP2_TX_MATCH_UNIQUE && matched.valid);
    assert(matched.index == 1023);
#endif
}

static void testFlushRetirementAt1024()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    IwxGroup2TxSlot &slot = trace.slots[0];
    slot.cookie = 55;
    slot.slot_generation = 1;
    slot.attempt_id = 55;
    slot.source = IWX_GROUP2_TX_SOURCE_RSN;
    slot.queue_id = 8;
    slot.index = 1023;
    slot.ring_count = 1024;
    slot.identity_epoch = 0;
    slot.valid = 1;
    const uint32_t retired = iwx_group2_tx_trace_retire_flushed_interval(
        &trace, 1300, 1022, 2, 0, 8, 1024);
#if EXPECT_ORIGINAL
    assert(retired == 0 && trace.slots[0].valid);
#else
    assert(retired == 1 && !trace.slots[0].valid);
#endif
}

static void testInvalidBoundsRemainRejected()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    IwxGroup2TxTag tag = beginTag(trace, 5);
    IwxGroup2TxSlot slot{};
    assert(!iwx_group2_tx_trace_prepare_slot(&trace, &tag, 1, 1, 1,
        0, 0, 0x0008, 0, 0, &slot));
    assert(!iwx_group2_tx_trace_prepare_slot(&trace, &tag, 1, 1, 1,
        0, 1025, 0x0008, 0, 0, &slot));
    assert(!iwx_group2_tx_trace_prepare_slot(&trace, &tag, 1, 1, 1,
        1024, 1024, 0x0008, 0, 0, &slot));
    assert(trace.next_slot_generation == 0 && validSlots(trace) == 0);
}

#if !EXPECT_ORIGINAL
static void testSlotCapacityStill32()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        IwxGroup2TxTag tag = beginTag(trace, i + 1);
        IwxGroup2TxSlot slot{};
        assert(iwx_group2_tx_trace_prepare_slot(&trace, &tag, 1, 1,
            9, i, 1024, 0x0008, i << 4, 15, &slot));
    }
    assert(validSlots(trace) == 32);
    assert(trace.next_slot_generation == 32);
    IwxGroup2TxTag extra = beginTag(trace, 33);
    IwxGroup2TxSlot extraSlot{};
    assert(!iwx_group2_tx_trace_prepare_slot(&trace, &extra, 1, 1,
        9, 32, 1024, 0x0008, 0xFFFF, 15, &extraSlot));
    assert(validSlots(trace) == 32);
    assert(trace.next_slot_generation == 32);
}
#endif

int main()
{
    testLegacyPrepareAt256And1024();
    testTracePrepareAndCompletionPath();
    testSparseHelpersAt1024();
    testDenseMatcherAt1024();
    testFlushRetirementAt1024();
    testInvalidBoundsRemainRejected();
#if !EXPECT_ORIGINAL
    testSlotCapacityStill32();
    std::puts("PASS candidate: 1024-slot host-ring Group2 tracking, completion and retirement; slot capacity remains 32");
#else
    std::puts("PASS baseline reproduction: valid 1024-slot host ring is rejected by every Group2 helper bound");
#endif
    return 0;
}
