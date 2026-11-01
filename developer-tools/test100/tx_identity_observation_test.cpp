#include "native/iwx_txcmd_identity_observation.hpp"
#include "native/iwx_tx_completion_observation.hpp"
#include "native/iwx_tx_response_metadata.hpp"
#include "native/group2_tx_trace_helpers.h"

#include <cassert>
#include <cstdint>

static iwx_txcmd_identity_candidate makeCandidate(
    uint32_t index, uint32_t frameControl, uint32_t sequenceControl)
{
    iwx_txcmd_identity_candidate value{};
    value.qid = 1;
    value.index = index;
    value.api_generation = 2;
    value.command_version = 7;
    value.frame_control = frameControl;
    value.sequence_control = sequenceControl;
    value.command_flags = 0x5;
    value.offload_assist = 0x0c00;
    return value;
}

static void testSingleMismatchRetainsRawSlotHeaderWithoutMatching()
{
    iwx_txcmd_identity_scan scan{};
    assert(iwx_txcmd_identity_scan_begin(
        &scan, 1, 1024, 138, 1, 139, 0x4908, 0x08c0));
    const auto command = makeCandidate(138, 0x4108, 0x08a0);
    assert(iwx_txcmd_identity_scan_record(&scan, 138, 1, &command));

    assert(scan.status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE);
    assert(scan.expected_count == 1 && scan.scanned_count == 1);
    assert(scan.candidate_count == 0);
    assert(!iwx_txcmd_identity_scan_has_unique_candidate(&scan));
    assert(iwx_txcmd_identity_scan_has_single_observed_slot_header(&scan));
    assert(scan.first_observed_candidate.index == 138);
    assert(scan.first_observed_candidate.frame_control == 0x4108);
    assert(scan.first_observed_candidate.sequence_control == 0x08a0);
    assert(scan.first_observed_candidate.command_flags == 0x5);
    assert(scan.first_observed_candidate.offload_assist == 0x0c00);
}

static void testExactMatchStillUsesOriginalStrictPredicate()
{
    iwx_txcmd_identity_scan scan{};
    assert(iwx_txcmd_identity_scan_begin(
        &scan, 1, 1024, 138, 1, 139, 0x4108, 0x08a0));
    const auto command = makeCandidate(138, 0x4108, 0x08a0);
    assert(iwx_txcmd_identity_scan_record(&scan, 138, 1, &command));

    assert(scan.candidate_count == 1);
    assert(iwx_txcmd_identity_scan_has_unique_candidate(&scan));
    assert(iwx_txcmd_identity_scan_has_single_observed_slot_header(&scan));
}

static void testMultiSlotAndRingWrapDoNotClaimSingleSlotHeader()
{
    iwx_txcmd_identity_scan multi{};
    assert(iwx_txcmd_identity_scan_begin(
        &multi, 1, 1024, 138, 2, 140, 0x4108, 0x08b0));
    const auto first = makeCandidate(138, 0x4908, 0x08c0);
    const auto second = makeCandidate(139, 0x4108, 0x08b0);
    assert(iwx_txcmd_identity_scan_record(&multi, 138, 1, &first));
    assert(iwx_txcmd_identity_scan_record(&multi, 139, 1, &second));
    assert(iwx_txcmd_identity_scan_has_unique_candidate(&multi));
    assert(!iwx_txcmd_identity_scan_has_single_observed_slot_header(&multi));

    iwx_txcmd_identity_scan wrapped{};
    assert(iwx_txcmd_identity_scan_begin(
        &wrapped, 1, 1024, 1023, 1, 0, 0x4908, 0x08c0));
    const auto last = makeCandidate(1023, 0x4108, 0x08a0);
    assert(iwx_txcmd_identity_scan_record(&wrapped, 1023, 1, &last));
    assert(wrapped.status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE);
    assert(iwx_txcmd_identity_scan_has_single_observed_slot_header(&wrapped));
    assert(wrapped.first_observed_candidate.index == 1023);
    assert(!iwx_txcmd_identity_scan_has_unique_candidate(&wrapped));
}

static iwx_tx_completion_event_input singleSlotMismatchEvent()
{
    iwx_tx_completion_event_input event{};
    event.kind = IWX_TX_COMPLETION_TX_RSP;
    event.stage = IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL;
    event.terminal_reason =
        IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED;
    event.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_FIRMWARE_QID |
        IWX_TX_COMPLETION_HAS_QUEUE_INDEX |
        IWX_TX_COMPLETION_HAS_RING_COUNT |
        IWX_TX_COMPLETION_HAS_QUEUED |
        IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL |
        IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL |
        IWX_TX_COMPLETION_HAS_TXCMD_SCAN |
        IWX_TX_COMPLETION_HAS_SINGLE_SLOT_TXCMD_HEADER;
    event.output_epoch = 11;
    event.firmware_qid = 1;
    event.queue_index = 139; // Exclusive boundary; slot 138 was scanned.
    event.ring_count = 1024;
    event.queued = 1;
    event.response_frame_control = 0x4908;
    event.response_sequence_control = 0x08c0;
    event.txcmd_scan_status = IWX_TXCMD_IDENTITY_SCAN_COMPLETE;
    event.txcmd_expected_count = 1;
    event.txcmd_scanned_count = 1;
    event.txcmd_candidate_count = 0; // Exact response tuple did not match.
    event.txcmd_candidate_index = 138;
    event.txcmd_api_generation = 2;
    event.txcmd_command_version = 7;
    event.txcmd_flags = 0x5;
    event.txcmd_offload_assist = 0x0c00;
    event.single_slot_txcmd_header = (0x4108U << 16) | 0x08a0U;
    return event;
}

static void testCompletionObservationKeepsMismatchAndSharedFields()
{
    iwx_tx_completion_observation_state state{};
    const auto event = singleSlotMismatchEvent();
    assert(IwxTxCompletionObservation::validInput(&event));
    assert(IwxTxCompletionObservation::record(&state, &event));

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.complete == 1 && snapshot.dropped_count == 0);
    const auto &stored = snapshot.last[IWX_TX_COMPLETION_TX_RSP];
    assert((stored.presence_flags &
            IWX_TX_COMPLETION_HAS_SINGLE_SLOT_TXCMD_HEADER) != 0);
    assert((stored.presence_flags &
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE) == 0);
    assert(stored.txcmd_candidate_count == 0);
    assert(stored.txcmd_candidate_index == 138);
    assert(stored.txcmd_api_generation == 2);
    assert(stored.txcmd_command_version == 7);
    assert(stored.txcmd_flags == 0x5);
    assert(stored.txcmd_offload_assist == 0x0c00);
    assert(stored.single_slot_txcmd_header ==
           ((0x4108U << 16) | 0x08a0U));
}

static void testCompletionObservationCarriesIndependentHostOrigin()
{
    iwx_tx_completion_observation_state state{};
    auto event = singleSlotMismatchEvent();
    event.presence_flags |= IWX_TX_COMPLETION_HAS_TAIL;
    event.tail = 138;
    event.host_origin_state = IWX_TX_COMPLETION_HOST_ORIGIN_UNIQUE;
    event.host_origin_cookie = 11;
    event.host_origin_slot_generation = 19;
    event.host_origin_context_generation = 5;
    event.host_origin_output_epoch = 12;
    event.host_origin_identity_epoch = 3;
    event.host_origin_attempt_id = 77;
    event.host_origin_source = IWX_GROUP2_TX_SOURCE_RSN;
    event.host_origin_index = 138;
    event.host_origin_frame_control = 0x4108;
    event.host_origin_sequence_control = 0x04b0;
    event.host_origin_tid = 6;

    assert(IwxTxCompletionObservation::validInput(&event));
    assert(IwxTxCompletionObservation::record(&state, &event));
    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    static_assert(sizeof(iwx_tx_completion_observation_snapshot) <= 1024,
                  "schema 4 snapshot remains within the 1 KiB bound");
    const auto &stored = snapshot.last[IWX_TX_COMPLETION_TX_RSP];
    assert(stored.host_origin_state ==
           IWX_TX_COMPLETION_HOST_ORIGIN_UNIQUE);
    assert(stored.host_origin_cookie == 11);
    assert(stored.host_origin_slot_generation == 19);
    assert(stored.host_origin_context_generation == 5);
    assert(stored.host_origin_output_epoch == 12);
    assert(stored.host_origin_identity_epoch == 3);
    assert(stored.host_origin_attempt_id == 77);
    assert(stored.host_origin_source == IWX_GROUP2_TX_SOURCE_RSN);
    assert(stored.host_origin_index == 138);
    assert(stored.host_origin_frame_control == 0x4108);
    assert(stored.host_origin_sequence_control == 0x04b0);
    assert(stored.host_origin_tid == 6);
    assert((stored.presence_flags &
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE) == 0);
    assert(stored.response_frame_control == 0x4908);
    assert(stored.response_sequence_control == 0x08c0);

    auto boundary = event;
    boundary.host_origin_index = boundary.queue_index;
    assert(!IwxTxCompletionObservation::validInput(&boundary));

    auto badSource = event;
    badSource.host_origin_source = 9;
    assert(!IwxTxCompletionObservation::validInput(&badSource));

    auto badTid = event;
    badTid.host_origin_tid = 16;
    assert(!IwxTxCompletionObservation::validInput(&badTid));

    auto nonUniqueWithPayload = event;
    nonUniqueWithPayload.host_origin_state =
        IWX_TX_COMPLETION_HOST_ORIGIN_MULTIPLE;
    assert(!IwxTxCompletionObservation::validInput(&nonUniqueWithPayload));
}

static void testBoundedMatcherReturnsHostOriginWithoutRelaxingResponseMatch()
{
    IwxGroup2TxTrace trace{};
    iwx_group2_tx_trace_init(&trace);
    IwxGroup2TxTag tag{};
    assert(iwx_group2_tx_trace_begin(&trace, 100, 77,
        IWX_GROUP2_TX_SOURCE_RSN, 8, 2, &tag));
    IwxGroup2TxSlot *slot = &trace.slots[0];
    assert(iwx_group2_tx_trace_prepare_slot(&trace, &tag, 5, 12,
        1, 75, 1024, 0x4108, 0x04b0, 6, slot));

    IwxGroup2TxSlot responseMatch{};
    IwxGroup2TxHostOrigin origin{};
    uint32_t related = 0;
    const uint32_t result =
        iwx_group2_tx_trace_match_completion_ex_with_origin(
            &trace, 200, 75, 1, 76, 1, 1024, 5, 12,
            0x4108, 0x06d0, 0, 1, 1, 75,
            &responseMatch, &related, &origin);
    assert(result == IWX_GROUP2_TX_MATCH_NONE);
    assert(related == 1);
    assert(origin.state == IWX_GROUP2_TX_ORIGIN_UNIQUE);
    assert(origin.slot.cookie == tag.cookie);
    assert(origin.slot.slot_generation == slot->slot_generation);
    assert(origin.slot.context_generation == 5);
    assert(origin.slot.output_epoch == 12);
    assert(origin.slot.identity_epoch == 0);
    assert(origin.slot.attempt_id == 77);
    assert(origin.slot.source == IWX_GROUP2_TX_SOURCE_RSN);
    assert(origin.slot.index == 75);
    assert(origin.slot.frame_control == 0x4108);
    assert(origin.slot.sequence_control == 0x04b0);
    assert(origin.slot.tid == 6);
    assert(responseMatch.cookie == 0);

    const IwxGroup2TxEvent &responseEvent = trace.events[
        (trace.event_cursor + IWX_GROUP2_TX_TRACE_CAPACITY - 1) %
        IWX_GROUP2_TX_TRACE_CAPACITY];
    assert(responseEvent.stage == IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN);
    assert(responseEvent.status == IWX_GROUP2_TX_MATCH_NONE);
    assert((responseEvent.flags & IWX_GROUP2_TX_HAS_COOKIE) == 0);

    IwxGroup2TxHostOrigin unbound{};
    related = 0;
    const uint32_t unboundResult =
        iwx_group2_tx_trace_match_completion_ex_with_origin(
            &trace, 201, 75, 1, 76, 1, 1024, 5, 12,
            0x4108, 0x06d0, 0, 1, 0, UINT32_MAX,
            &responseMatch, &related, &unbound);
    assert(unboundResult == IWX_GROUP2_TX_MATCH_NONE);
    assert(related == 1 && unbound.state == IWX_GROUP2_TX_ORIGIN_UNBOUND);
    assert(unbound.slot.cookie == tag.cookie);

    IwxGroup2TxHostOrigin wrongIndex{};
    related = 0;
    (void)iwx_group2_tx_trace_match_completion_ex_with_origin(
        &trace, 202, 75, 1, 76, 1, 1024, 5, 12,
        0x4108, 0x06d0, 0, 1, 1, 74,
        &responseMatch, &related, &wrongIndex);
    assert(related == 1 && wrongIndex.state == IWX_GROUP2_TX_ORIGIN_UNBOUND);
    assert(wrongIndex.slot.index == 75);
}

static void testBoundedMatcherDistinguishesNoneMultipleStaleAndUnavailable()
{
    IwxGroup2TxTrace empty{};
    iwx_group2_tx_trace_init(&empty);
    IwxGroup2TxSlot matched{};
    IwxGroup2TxHostOrigin origin{};
    uint32_t related = 99;
    uint32_t result = iwx_group2_tx_trace_match_completion_ex_with_origin(
        &empty, 100, 4, 1, 5, 1, 8, 2, 3, 0x4908, 0x06d0,
        0, 1, 1, 4, &matched, &related, &origin);
    assert(result == IWX_GROUP2_TX_MATCH_NONE);
    assert(related == 0 && origin.state == IWX_GROUP2_TX_ORIGIN_NONE);

    IwxGroup2TxTrace multiple{};
    iwx_group2_tx_trace_init(&multiple);
    IwxGroup2TxTag first{};
    IwxGroup2TxTag second{};
    assert(iwx_group2_tx_trace_begin(&multiple, 1, 10,
        IWX_GROUP2_TX_SOURCE_RSN, 2, 1, &first));
    assert(iwx_group2_tx_trace_begin(&multiple, 2, 11,
        IWX_GROUP2_TX_SOURCE_WPA, 2, 1, &second));
    assert(iwx_group2_tx_trace_prepare_slot(&multiple, &first, 2, 3,
        1, 4, 8, 0x4108, 0x0120, 3, &multiple.slots[4]));
    assert(iwx_group2_tx_trace_prepare_slot(&multiple, &second, 2, 3,
        1, 5, 8, 0x4108, 0x0130, 4, &multiple.slots[5]));
    related = 0;
    result = iwx_group2_tx_trace_match_completion_ex_with_origin(
        &multiple, 3, 4, 2, 6, 1, 8, 2, 3, 0x4908, 0x06d0,
        0, 1, 0, UINT32_MAX, &matched, &related, &origin);
    assert(result == IWX_GROUP2_TX_MATCH_NONE);
    assert(related == 1 && origin.state == IWX_GROUP2_TX_ORIGIN_MULTIPLE);
    assert(origin.slot.cookie == 0);

    IwxGroup2TxTrace stale{};
    iwx_group2_tx_trace_init(&stale);
    IwxGroup2TxTag staleTag{};
    assert(iwx_group2_tx_trace_begin(&stale, 1, 12,
        IWX_GROUP2_TX_SOURCE_RSN, 2, 1, &staleTag));
    assert(iwx_group2_tx_trace_prepare_slot(&stale, &staleTag, 2, 3,
        1, 4, 8, 0x4108, 0x0120, 3, &stale.slots[4]));
    iwx_group2_tx_trace_note_lost(&stale);
    related = 0;
    result = iwx_group2_tx_trace_match_completion_ex_with_origin(
        &stale, 3, 4, 1, 5, 1, 8, 2, 3, 0x4908, 0x06d0,
        0, 1, 0, UINT32_MAX, &matched, &related, &origin);
    assert(result == IWX_GROUP2_TX_MATCH_UNKNOWN);
    assert(related == 1 && origin.state ==
           IWX_GROUP2_TX_ORIGIN_STALE_OR_RESET_AMBIGUOUS);
    assert(origin.slot.cookie == 0);

    result = iwx_group2_tx_trace_match_completion_ex_with_origin(
        &stale, 4, 4, 1, 5, 1, 8, 2, 3, 0x4908, 0x06d0,
        1, 1, 0, UINT32_MAX, &matched, &related, &origin);
    assert(result == IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS);
    assert(related == 1);
    assert(origin.state ==
           IWX_GROUP2_TX_ORIGIN_STALE_OR_RESET_AMBIGUOUS);

    IwxGroup2TxHostOrigin strictPriority{};
    IwxGroup2TxSlot strictMatched{};
    result = iwx_group2_tx_match_completion_sparse_with_origin(
        nullptr, 0, 0, 0, 0, 0, 1, 2, 3, 0x4908, 0x06d0,
        1, 0, 0, UINT32_MAX, &strictMatched, &strictPriority, &related);
    assert(result == IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS);
    assert(strictPriority.state ==
           IWX_GROUP2_TX_ORIGIN_STALE_OR_RESET_AMBIGUOUS);
    result = iwx_group2_tx_match_completion_sparse_with_origin(
        nullptr, 0, 0, 0, 0, 0, 1, 2, 3, 0x4908, 0x06d0,
        0, UINT32_MAX, 0, UINT32_MAX, &strictMatched, &strictPriority,
        &related);
    assert(result == IWX_GROUP2_TX_MATCH_UNKNOWN);

    IwxGroup2TxTrace busy{};
    iwx_group2_tx_trace_init(&busy);
    busy.writer = 1;
    result = iwx_group2_tx_trace_match_completion_ex_with_origin(
        &busy, 5, 4, 1, 5, 1, 8, 2, 3, 0x4908, 0x06d0,
        0, 1, 0, UINT32_MAX, &matched, &related, &origin);
    assert(result == IWX_GROUP2_TX_MATCH_UNKNOWN);
    assert(origin.state == IWX_GROUP2_TX_ORIGIN_UNAVAILABLE);
}

static void testInvalidBoundaryAndMultiSlotNeverExportSingleHeader()
{
    auto wrongBoundary = singleSlotMismatchEvent();
    wrongBoundary.txcmd_candidate_index = 139;
    assert(!IwxTxCompletionObservation::validInput(&wrongBoundary));

    auto multiSlot = singleSlotMismatchEvent();
    multiSlot.queue_index = 140;
    multiSlot.queued = 2;
    multiSlot.txcmd_expected_count = 2;
    multiSlot.txcmd_scanned_count = 2;
    assert(!IwxTxCompletionObservation::validInput(&multiSlot));
}

static void testCompletionMetadataUsesOnlyProvenSingleSlotInterval()
{
    uint32_t index = UINT32_MAX;
    assert(iwx_tx_response_single_reclaim_metadata_index(
        1024, 138, 1, 139, 1, &index));
    assert(index == 138); // The interval is [138, 139), boundary is exclusive.

    index = UINT32_MAX;
    assert(iwx_tx_response_single_reclaim_metadata_index(
        1024, 1023, 1, 0, 1, &index));
    assert(index == 1023); // Single-slot interval across ring wrap.

    index = 0;
    assert(!iwx_tx_response_single_reclaim_metadata_index(
        1024, 138, 2, 140, 1, &index));
    assert(index == UINT32_MAX); // Multi-slot interval is unattributed.

    assert(!iwx_tx_response_single_reclaim_metadata_index(
        1024, 138, 1, 140, 1, &index)); // Span exceeds queued entries.
    assert(!iwx_tx_response_single_reclaim_metadata_index(
        1024, 138, 1, 139, 2, &index)); // Aggregate response is separate.
    assert(!iwx_tx_response_single_reclaim_metadata_index(
        1024, 138, 0, 139, 1, &index)); // No live queued slot.
}

int main()
{
    testSingleMismatchRetainsRawSlotHeaderWithoutMatching();
    testExactMatchStillUsesOriginalStrictPredicate();
    testMultiSlotAndRingWrapDoNotClaimSingleSlotHeader();
    testCompletionObservationKeepsMismatchAndSharedFields();
    testCompletionObservationCarriesIndependentHostOrigin();
    testBoundedMatcherReturnsHostOriginWithoutRelaxingResponseMatch();
    testBoundedMatcherDistinguishesNoneMultipleStaleAndUnavailable();
    testInvalidBoundaryAndMultiSlotNeverExportSingleHeader();
    testCompletionMetadataUsesOnlyProvenSingleSlotInterval();
    return 0;
}
