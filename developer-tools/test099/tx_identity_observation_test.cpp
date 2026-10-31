#include "native/iwx_txcmd_identity_observation.hpp"
#include "native/iwx_tx_completion_observation.hpp"
#include "native/iwx_tx_response_metadata.hpp"

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
    testInvalidBoundaryAndMultiSlotNeverExportSingleHeader();
    testCompletionMetadataUsesOnlyProvenSingleSlotInterval();
    return 0;
}
