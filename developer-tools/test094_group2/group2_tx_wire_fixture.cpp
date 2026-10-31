#include "native/group2_tx_trace_helpers.h"

#include <cstdio>

static void appendTagged(IwxGroup2TxTrace *trace,
                         const IwxGroup2TxTag *tag,
                         uint64_t now, uint16_t stage,
                         int32_t result = 0)
{
    IwxGroup2TxEvent event{};
    iwx_group2_tx_event_from_tag(&event, tag, now, stage);
    event.result = result;
    if (stage == IWX_GROUP2_TX_STAGE_DEQUEUED)
        event.flags |= IWX_GROUP2_TX_TAG_PRESENT;
    if (stage == IWX_GROUP2_TX_STAGE_SLOT_COMMITTED ||
        stage == IWX_GROUP2_TX_STAGE_DOORBELL) {
        event.flags |= IWX_GROUP2_TX_HAS_CONTEXT_GENERATION |
            IWX_GROUP2_TX_HAS_OUTPUT_EPOCH | IWX_GROUP2_TX_HAS_QUEUE |
            IWX_GROUP2_TX_HAS_SLOT | IWX_GROUP2_TX_HAS_SLOT_GENERATION |
            IWX_GROUP2_TX_HAS_FRAME_CONTROL |
            IWX_GROUP2_TX_HAS_SEQUENCE_CONTROL;
        event.context_generation = 55;
        event.output_epoch = 56;
        event.queue_id = 3;
        event.index = 7;
        event.ring_count = 8;
        event.frame_control = 0x0008;
        event.sequence_control = 0x5010;
        event.tid = 15;
        event.slot_generation = 1;
    }
    (void)iwx_group2_tx_trace_record(trace, &event);
}

static void appendSlot(IwxGroup2TxTrace *trace,
                       const IwxGroup2TxSlot *slot,
                       uint64_t now, uint16_t stage)
{
    IwxGroup2TxEvent event{};
    iwx_group2_tx_event_from_slot(&event, slot, now, stage);
    (void)iwx_group2_tx_trace_record(trace, &event);
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);

    IwxGroup2TxTag first{};
    if (!iwx_group2_tx_trace_begin(&trace, 1000, 501,
            IWX_GROUP2_TX_SOURCE_RSN, 44, 8, &first))
        return 3;
    IwxGroup2TxEvent enqueue{};
    iwx_group2_tx_event_from_tag(&enqueue, &first, 1001,
        IWX_GROUP2_TX_STAGE_IFQ_ENQUEUE);
    enqueue.result = 2;
    enqueue.queue_id = UINT32_MAX;
    enqueue.flags |= IWX_GROUP2_TX_QUEUE_DROP_COUNT_PRESENT |
        IWX_GROUP2_TX_HAS_QUEUE;
    if (!iwx_group2_tx_trace_record(&trace, &enqueue))
        return 4;
    appendTagged(&trace, &first, 1002,
        IWX_GROUP2_TX_STAGE_DEQUEUED);

    IwxGroup2TxSlot endpointSlot{};
    IwxGroup2TxTag endpointTag{};
    if (!iwx_group2_tx_trace_begin(&trace, 1003, 502,
            IWX_GROUP2_TX_SOURCE_WPA, 44, 8, &endpointTag) ||
        !iwx_group2_tx_trace_prepare_slot(&trace, &endpointTag,
            55, 56, 3, 0, 8, 0x0008, 0x5010, 15, &endpointSlot))
        return 5;
    IwxGroup2TxSlot firstSlot{};
    if (!iwx_group2_tx_trace_prepare_slot(&trace, &first,
            55, 56, 3, 7, 8, 0x0008, 0x5010, 15, &firstSlot))
        return 6;
    appendSlot(&trace, &firstSlot, 1004,
        IWX_GROUP2_TX_STAGE_SLOT_COMMITTED);
    appendSlot(&trace, &firstSlot, 1005,
        IWX_GROUP2_TX_STAGE_DOORBELL);
    IwxGroup2TxSlot matched{};
    const uint32_t match = iwx_group2_tx_trace_match_completion(&trace,
        1006, 6, 2, 0, 3, 8, 55, 56, 0x0008, 0x5010, 0,
        0x2345, &matched);
    if (match != IWX_GROUP2_TX_MATCH_UNIQUE ||
        matched.cookie != first.cookie || matched.index != 7)
        return 7;
    // Endpoint slot 0 is excluded by the half-open reclaim interval [6, 0).
    if (iwx_group2_tx_trace_retire_reclaimed_interval(&trace, 1007,
            6, 2, 0, 3, 8, IWX_GROUP2_TX_MATCH_UNIQUE,
            matched.slot_generation) != 1)
        return 8;

    IwxGroup2TxTag resetTag{};
    IwxGroup2TxSlot resetSlot{};
    if (!iwx_group2_tx_trace_begin(&trace, 1008, 503,
            IWX_GROUP2_TX_SOURCE_RSN, 44, 8, &resetTag) ||
        !iwx_group2_tx_trace_prepare_slot(&trace, &resetTag,
            55, 56, 3, 1, 8, 0x0008, 0x5020, 15, &resetSlot))
        return 9;
    appendSlot(&trace, &resetSlot, 1009,
        IWX_GROUP2_TX_STAGE_DOORBELL);
    iwx_group2_tx_trace_invalidate_slots(&trace, 1010, 57);
    const uint32_t resetMatch = iwx_group2_tx_trace_match_completion(
        &trace, 1011, 0, 2, 2, 3, 8, 57, 57, 0x0008, 0x5020, 1,
        -1, &matched);
    if (resetMatch != IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS)
        return 10;

    // A later ambiguous response is retained only when a Group2 sidecar is
    // actually inside its reclaim interval. This keeps the event useful and
    // avoids logging unrelated TX_RSP traffic into the bounded ring.
    IwxGroup2TxTag ambiguousTag{};
    IwxGroup2TxSlot ambiguousSlot{};
    if (!iwx_group2_tx_trace_begin(&trace, 1012, 505,
            IWX_GROUP2_TX_SOURCE_RSN, 44, 8, &ambiguousTag) ||
        !iwx_group2_tx_trace_prepare_slot(&trace, &ambiguousTag,
            55, 56, 3, 1, 8, 0x0008, 0x5040, 15, &ambiguousSlot))
        return 11;
    appendSlot(&trace, &ambiguousSlot, 1013,
        IWX_GROUP2_TX_STAGE_DOORBELL);
    const uint32_t ambiguousMatch = iwx_group2_tx_trace_match_completion(
        &trace, 1014, 0, 2, 2, 3, 8, 55, 56, 0x0008, 0x5040, 1,
        -1, &matched);
    if (ambiguousMatch != IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS)
        return 12;

    // This wire fixture exercises the same helper used by the station flush
    // path. Its separate stage and unknown status cannot be mistaken for ACK.
    IwxGroup2TxTag flushedTag{};
    IwxGroup2TxSlot flushedSlot{};
    if (!iwx_group2_tx_trace_begin(&trace, 1015, 506,
            IWX_GROUP2_TX_SOURCE_WPA, 44, 8, &flushedTag) ||
        !iwx_group2_tx_trace_prepare_slot(&trace, &flushedTag,
            55, 56, 4, 2, 8, 0x0008, 0x5030, 15, &flushedSlot))
        return 13;
    appendSlot(&trace, &flushedSlot, 1016,
        IWX_GROUP2_TX_STAGE_DOORBELL);
    if (iwx_group2_tx_trace_retire_flushed_interval(&trace, 1017,
            1, 3, 4, 4, 8) != 1)
        return 14;

    IwxGroup2TxTraceSnapshot host{};
    IwxGroup2TxTraceSnapshot wire{};
    if (!iwx_group2_tx_trace_snapshot(&trace, &host))
        return 15;
    iwx_group2_tx_snapshot_to_le(&wire, &host);
    FILE *out = std::fopen(argv[1], "wb");
    if (!out)
        return 16;
    const size_t written = std::fwrite(&wire, 1, sizeof(wire), out);
    std::fclose(out);
    return written == sizeof(wire) ? 0 : 17;
}
