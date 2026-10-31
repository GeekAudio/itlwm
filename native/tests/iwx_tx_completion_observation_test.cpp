#include "native/iwx_tx_completion_observation.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <limits>
#include <thread>

using namespace IwxTxCompletionObservation;

static iwx_tx_completion_event_input txRsp(
    uint32_t reason = IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED)
{
    iwx_tx_completion_event_input event{};
    event.kind = IWX_TX_COMPLETION_TX_RSP;
    event.stage = IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL;
    event.terminal_reason = reason;
    event.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;
    event.output_epoch = 0; // Present zero is valid for the scalar field.
    return event;
}

static void testFixedBoundsFullWidthAndValidZero()
{
    static_assert(sizeof(iwx_tx_completion_event_record) <= 192,
                  "event must have a fixed scalar bound");
    static_assert(sizeof(iwx_tx_completion_observation_state) <= 1024,
                  "embedded observer exceeds its bound");
    static_assert(sizeof(iwx_tx_completion_observation_snapshot) <= 1024,
                  "snapshot exceeds its copy bound");

    iwx_tx_completion_observation_state state{};
    auto event = txRsp();
    event.presence_flags = IWX_TX_COMPLETION_HAS_MONOTONIC_NS |
        IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH |
        IWX_TX_COMPLETION_HAS_FIRMWARE_QID |
        IWX_TX_COMPLETION_HAS_QUEUE_INDEX |
        IWX_TX_COMPLETION_HAS_RING_COUNT |
        IWX_TX_COMPLETION_HAS_FRAME_COUNT |
        IWX_TX_COMPLETION_HAS_SSN |
        IWX_TX_COMPLETION_HAS_RA_TID |
        IWX_TX_COMPLETION_HAS_STATUS;
    event.monotonic_ns = 0; // Present zero is distinct from missing.
    event.payload_length = 52;
    event.firmware_qid = 257; // Preserve the full protocol qid width.
    event.queue_index = 0;
    event.ring_count = 1024;
    event.frame_count = 1;
    event.ssn = 0;
    event.ra_tid = 0;
    event.status = 0;
    assert(record(&state, &event));

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.available == 1 && snapshot.complete == 1);
    assert(snapshot.dropped_count == 0 && snapshot.next_serial == 1);
    const auto &last = snapshot.last[IWX_TX_COMPLETION_TX_RSP];
    assert(last.event_count == 1 && last.serial == 1);
    assert(last.kind == IWX_TX_COMPLETION_TX_RSP);
    assert(last.terminal_reason ==
           IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED);
    assert(last.firmware_qid == 257 && last.ring_count == 1024);
    assert(last.queue_index == 0 && last.ssn == 0 && last.status == 0);
    assert(last.monotonic_ns == 0 && last.payload_length == 52);
    assert(last.output_epoch == 0);
    assert((last.presence_flags & IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH) != 0);
    assert((last.presence_flags & IWX_TX_COMPLETION_HAS_SSN) != 0);
    assert((last.presence_flags & IWX_TX_COMPLETION_HAS_STATUS) != 0);
    assert((last.presence_flags & IWX_TX_COMPLETION_OBSERVER_HAS_SERIAL) != 0);
    assert(snapshot.terminal_reason_counts[IWX_TX_COMPLETION_TX_RSP]
                                            [IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED] == 1);
    assert(snapshot.last[IWX_TX_COMPLETION_BA].event_count == 0);
}

static void testBAFieldsAndReasonStage()
{
    iwx_tx_completion_observation_state state{};
    iwx_tx_completion_event_input event{};
    event.kind = IWX_TX_COMPLETION_BA;
    event.stage = IWX_TX_COMPLETION_STAGE_BA_TFD_TERMINAL;
    event.terminal_reason = IWX_TX_COMPLETION_BA_TFD_RECLAIM_COMPLETED;
    event.presence_flags = IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH |
        IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_FIRMWARE_QID |
        IWX_TX_COMPLETION_HAS_QUEUE_INDEX |
        IWX_TX_COMPLETION_HAS_RING_COUNT |
        IWX_TX_COMPLETION_HAS_QUEUED |
        IWX_TX_COMPLETION_HAS_CUR |
        IWX_TX_COMPLETION_HAS_TAIL |
        IWX_TX_COMPLETION_HAS_BA_STA_ID |
        IWX_TX_COMPLETION_HAS_BA_FLAGS |
        IWX_TX_COMPLETION_HAS_BA_TFD_COUNT |
        IWX_TX_COMPLETION_HAS_BA_TXED |
        IWX_TX_COMPLETION_HAS_BA_DONE |
        IWX_TX_COMPLETION_HAS_BA_WIRELESS_TIME |
        IWX_TX_COMPLETION_HAS_BA_TFD_TID |
        IWX_TX_COMPLETION_HAS_BA_TFD_INDEX;
    event.payload_length = 56;
    event.firmware_qid = 257;
    event.queue_index = 511;
    event.ring_count = 1024;
    event.queued = 8;
    event.cur = 27;
    event.tail = 19;
    event.ba_sta_id = 0;
    event.ba_flags = 1;
    event.ba_tfd_count = 1;
    event.ba_txed = 0;
    event.ba_done = 0;
    event.ba_wireless_time = 0;
    event.ba_tfd_tid = 0;
    event.ba_tfd_index = 0;
    assert(record(&state, &event));

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    const auto &last = snapshot.last[IWX_TX_COMPLETION_BA];
    assert(snapshot.complete == 1);
    assert(last.firmware_qid == 257 && last.ring_count == 1024);
    assert(last.ba_tfd_count == 1 && last.ba_tfd_index == 0);
    assert(last.ba_txed == 0 && last.ba_done == 0);
    assert(last.ba_wireless_time == 0 && last.ba_tfd_tid == 0);
    assert(snapshot.terminal_reason_counts[IWX_TX_COMPLETION_BA]
                                            [IWX_TX_COMPLETION_BA_TFD_RECLAIM_COMPLETED] == 1);

    // The same reason with a handler-exit stage is not a valid branch fact.
    event.stage = IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL;
    assert(!record(&state, &event));
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.complete == 0 && snapshot.dropped_count == 1);
    assert(snapshot.last[IWX_TX_COMPLETION_BA].event_count == 1);
}

static void testTXCMDIdentityFieldsRequireCompleteUniqueInterval()
{
    iwx_tx_completion_observation_state state{};
    auto event = txRsp();
    event.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL |
        IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL |
        IWX_TX_COMPLETION_HAS_TXCMD_SCAN |
        IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE |
        IWX_TX_COMPLETION_HAS_RING_COUNT | IWX_TX_COMPLETION_HAS_QUEUED;
    event.ring_count = 16;
    event.queued = 4;
    event.response_frame_control = 0x4108;
    event.response_sequence_control = 0x0580;
    event.txcmd_scan_status = 1;
    event.txcmd_expected_count = 3;
    event.txcmd_scanned_count = 3;
    event.txcmd_candidate_count = 1;
    event.txcmd_candidate_index = 12;
    event.txcmd_api_generation = 2;
    event.txcmd_command_version = 7;
    event.txcmd_flags = 5;
    event.txcmd_offload_assist = 0x0c00;
    assert(record(&state, &event));

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    const auto &last = snapshot.last[IWX_TX_COMPLETION_TX_RSP];
    assert(last.response_frame_control == 0x4108);
    assert(last.response_sequence_control == 0x0580);
    assert(last.txcmd_candidate_index == 12);
    assert(last.txcmd_api_generation == 2);
    assert(last.txcmd_command_version == 7);
    assert(last.txcmd_flags == 5 && last.txcmd_offload_assist == 0x0c00);

    auto incomplete = event;
    incomplete.presence_flags &= ~IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE;
    incomplete.txcmd_candidate_index = 0;
    incomplete.txcmd_api_generation = 0;
    incomplete.txcmd_command_version = 0;
    incomplete.txcmd_flags = 0;
    incomplete.txcmd_offload_assist = 0;
    incomplete.txcmd_scan_status = 2;
    incomplete.txcmd_scanned_count = 2;
    incomplete.txcmd_candidate_count = 1;
    assert(record(&state, &incomplete));

    auto invalidUnique = event;
    invalidUnique.txcmd_scan_status = 2;
    assert(!record(&state, &invalidUnique));
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.complete == 0 && snapshot.dropped_count == 1);
}

static void testStrictPresenceAndRXParseStops()
{
    iwx_tx_completion_observation_state state{};
    auto missingEpoch = txRsp();
    missingEpoch.presence_flags = 0;
    assert(!record(&state, &missingEpoch));

    auto missing = txRsp(IWX_TX_COMPLETION_TX_RSP_FRAME_COUNT_ZERO);
    missing.frame_count = 0; // Nonzero is not required to expose a missing flag.
    missing.payload_length = 1; // A nonzero absent scalar must be rejected.
    assert(!record(&state, &missing));

    auto validZero = txRsp(IWX_TX_COMPLETION_TX_RSP_FRAME_COUNT_ZERO);
    validZero.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_FRAME_COUNT |
        IWX_TX_COMPLETION_HAS_SSN | IWX_TX_COMPLETION_HAS_STATUS;
    validZero.frame_count = 0;
    validZero.ssn = 0;
    validZero.status = 0;
    assert(record(&state, &validZero));

    iwx_tx_completion_event_input parseStop{};
    parseStop.kind = IWX_TX_COMPLETION_RX_PARSE_STOP;
    parseStop.stage = IWX_TX_COMPLETION_STAGE_RX_PARSE_STOP;
    parseStop.terminal_reason = IWX_TX_COMPLETION_RX_DESCRIPTOR_INVALID;
    parseStop.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_RX_GROUP |
        IWX_TX_COMPLETION_HAS_RX_COMMAND |
        IWX_TX_COMPLETION_HAS_RX_HEADER_QID |
        IWX_TX_COMPLETION_HAS_RX_HEADER_INDEX |
        IWX_TX_COMPLETION_HAS_RX_PACKET_LENGTH;
    parseStop.rx_group = 0;
    parseStop.rx_command = 0;
    parseStop.rx_header_qid = 0;
    parseStop.rx_header_index = 0;
    parseStop.rx_packet_length = 0;
    assert(record(&state, &parseStop));

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.available == 1 && snapshot.complete == 0);
    assert(snapshot.dropped_count == 2);
    assert(snapshot.last[IWX_TX_COMPLETION_TX_RSP].event_count == 1);
    const auto &rx = snapshot.last[IWX_TX_COMPLETION_RX_PARSE_STOP];
    assert(rx.event_count == 1 && rx.rx_group == 0 && rx.rx_header_qid == 0);
    assert((rx.presence_flags & IWX_TX_COMPLETION_HAS_RX_HEADER_QID) != 0);

    parseStop.presence_flags |= IWX_TX_COMPLETION_OBSERVER_HAS_SERIAL;
    assert(!record(&state, &parseStop)); // Caller cannot forge observer fields.
}

static void testOverflowAndTryOnlyContentionAreExplicitDrops()
{
    iwx_tx_completion_observation_state saturated{};
    auto event = txRsp();
    saturated.next_serial = std::numeric_limits<uint64_t>::max();
    assert(!record(&saturated, &event));
    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&saturated, &snapshot));
    assert(snapshot.complete == 0 && snapshot.dropped_count == 1);
    assert(snapshot.next_serial == std::numeric_limits<uint64_t>::max());
    assert(snapshot.last[IWX_TX_COMPLETION_TX_RSP].event_count == 0);

    iwx_tx_completion_observation_state contended{};
    std::atomic<bool> held{false};
    std::atomic<bool> release{false};
    std::thread holder([&] {
        assert(IwxTxCompletionObservation::tryLock(&contended));
        held.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire))
            std::this_thread::yield();
        IwxTxCompletionObservation::unlock(&contended);
    });
    while (!held.load(std::memory_order_acquire))
        std::this_thread::yield();
    assert(!record(&contended, &event)); // Exactly one lock attempt, no wait.
    release.store(true, std::memory_order_release);
    holder.join();
    assert(IwxTxCompletionObservation::snapshot(&contended, &snapshot));
    assert(snapshot.complete == 0 && snapshot.dropped_count == 1);
    assert(snapshot.last[IWX_TX_COMPLETION_TX_RSP].event_count == 0);
}

static void testRAIIFallbackReasonsAreAvailable()
{
    iwx_tx_completion_observation_state state{};
    auto txUnknown = txRsp(IWX_TX_COMPLETION_TX_RSP_UNCLASSIFIED_EXIT);
    assert(record(&state, &txUnknown));

    iwx_tx_completion_event_input baUnknown{};
    baUnknown.kind = IWX_TX_COMPLETION_BA;
    baUnknown.stage = IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL;
    baUnknown.terminal_reason = IWX_TX_COMPLETION_BA_UNCLASSIFIED_EXIT;
    baUnknown.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;
    assert(record(&state, &baUnknown));

    iwx_tx_completion_event_input rxUnknown{};
    rxUnknown.kind = IWX_TX_COMPLETION_RX_PARSE_STOP;
    rxUnknown.stage = IWX_TX_COMPLETION_STAGE_RX_PARSE_STOP;
    rxUnknown.terminal_reason = IWX_TX_COMPLETION_RX_UNCLASSIFIED_STOP;
    rxUnknown.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;
    assert(record(&state, &rxUnknown));

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.complete == 1);
    assert(snapshot.terminal_reason_counts[IWX_TX_COMPLETION_TX_RSP]
        [IWX_TX_COMPLETION_TX_RSP_UNCLASSIFIED_EXIT] == 1);
    assert(snapshot.terminal_reason_counts[IWX_TX_COMPLETION_BA]
        [IWX_TX_COMPLETION_BA_UNCLASSIFIED_EXIT] == 1);
    assert(snapshot.terminal_reason_counts[IWX_TX_COMPLETION_RX_PARSE_STOP]
        [IWX_TX_COMPLETION_RX_UNCLASSIFIED_STOP] == 1);
}

static void testConcurrentWritersAndReadersNeverPublishTornRows()
{
    constexpr uint32_t kWriters = 4;
    constexpr uint32_t kEventsPerWriter = 10000;
    iwx_tx_completion_observation_state state{};
    std::atomic<bool> done{false};
    std::atomic<bool> consistent{true};
    std::array<std::thread, kWriters> writers;

    for (uint32_t worker = 0; worker < kWriters; ++worker) {
        writers[worker] = std::thread([&, worker] {
            for (uint32_t i = 1; i <= kEventsPerWriter; ++i) {
                const uint32_t value = worker * kEventsPerWriter + i;
                auto event = txRsp();
                event.presence_flags = IWX_TX_COMPLETION_HAS_FIRMWARE_QID |
        IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
                    IWX_TX_COMPLETION_HAS_QUEUE_INDEX |
                    IWX_TX_COMPLETION_HAS_RING_COUNT |
                    IWX_TX_COMPLETION_HAS_QUEUED |
                    IWX_TX_COMPLETION_HAS_CUR |
                    IWX_TX_COMPLETION_HAS_TAIL;
                event.firmware_qid = value % 65536;
                event.queue_index = value;
                event.ring_count = 1024;
                event.queued = value;
                event.cur = value + 1;
                event.tail = value + 2;
                (void)record(&state, &event);
            }
        });
    }

    std::thread reader([&] {
        while (!done.load(std::memory_order_acquire)) {
            iwx_tx_completion_observation_snapshot snapshot{};
            if (!IwxTxCompletionObservation::snapshot(&state, &snapshot))
                continue;
            const auto &last = snapshot.last[IWX_TX_COMPLETION_TX_RSP];
            if (!last.event_count)
                continue;
            if (last.cur != last.queued + 1 ||
                last.tail != last.queued + 2 ||
                last.firmware_qid != last.queue_index % 65536 ||
                last.ring_count != 1024)
                consistent.store(false, std::memory_order_relaxed);
        }
    });
    for (auto &writer : writers)
        writer.join();
    done.store(true, std::memory_order_release);
    reader.join();

    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(consistent.load(std::memory_order_relaxed));
    assert(snapshot.last[IWX_TX_COMPLETION_TX_RSP].event_count > 0);
    assert(snapshot.terminal_reason_counts[IWX_TX_COMPLETION_TX_RSP]
                                            [IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED] > 0);
}

static void testLatestRowsKeepTheirOwnRecordEpochAcrossEpochChange()
{
    iwx_tx_completion_observation_state state{};
    auto tx = txRsp(IWX_TX_COMPLETION_TX_RSP_P2P_OWNER_CONSUMED);
    auto ba = iwx_tx_completion_event_input{};
    ba.kind = IWX_TX_COMPLETION_BA;
    ba.stage = IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL;
    ba.terminal_reason = IWX_TX_COMPLETION_BA_TFD_COUNT_ZERO;
    ba.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;
    ba.output_epoch = 41;
    auto rx = iwx_tx_completion_event_input{};
    rx.kind = IWX_TX_COMPLETION_RX_PARSE_STOP;
    rx.stage = IWX_TX_COMPLETION_STAGE_RX_PARSE_STOP;
    rx.terminal_reason = IWX_TX_COMPLETION_RX_DESCRIPTOR_INVALID;
    rx.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;
    rx.output_epoch = 41;

    tx.output_epoch = 41;
    assert(record(&state, &tx));
    assert(record(&state, &ba));
    assert(record(&state, &rx));

    // A fresh output epoch alone does not rewrite last-by-kind history.
    // Consumers must compare each row's own epoch before associating it with
    // the current output owner; these rows remain tagged with epoch 41.
    const uint32_t currentOutputEpoch = 42;
    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(&state, &snapshot));
    assert(snapshot.complete == 1);
    for (uint32_t kind = 0; kind < IWX_TX_COMPLETION_KIND_COUNT; ++kind) {
        const auto &last = snapshot.last[kind];
        assert(last.event_count == 1);
        assert((last.presence_flags & IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH) != 0);
        assert(last.output_epoch == 41);
        assert(last.output_epoch != currentOutputEpoch);
    }
}

int main()
{
    testFixedBoundsFullWidthAndValidZero();
    testBAFieldsAndReasonStage();
    testTXCMDIdentityFieldsRequireCompleteUniqueInterval();
    testStrictPresenceAndRXParseStops();
    testOverflowAndTryOnlyContentionAreExplicitDrops();
    testRAIIFallbackReasonsAreAvailable();
    testLatestRowsKeepTheirOwnRecordEpochAcrossEpochChange();
    testConcurrentWritersAndReadersNeverPublishTornRows();
    return 0;
}
