#include "native/iwx_tx_progress_observation.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <limits>
#include <thread>

using namespace IwxTxProgressObservation;

static iwx_tx_progress_event_input fullEvent(uint32_t reason = 0)
{
    iwx_tx_progress_event_input event{};
    event.presence_flags = IWX_TX_PROGRESS_HAS_GENERATION |
        IWX_TX_PROGRESS_HAS_OUTPUT_EPOCH |
        IWX_TX_PROGRESS_HAS_MONOTONIC_NS |
        IWX_TX_PROGRESS_HAS_QID | IWX_TX_PROGRESS_HAS_INDEX |
        IWX_TX_PROGRESS_HAS_RING_COUNT | IWX_TX_PROGRESS_HAS_QUEUED |
        IWX_TX_PROGRESS_HAS_CUR | IWX_TX_PROGRESS_HAS_TAIL;
    event.reason = reason;
    event.generation = 19;
    event.output_epoch = 23;
    event.monotonic_ns = 0x123456789abcdef0ULL;
    event.qid = 2;
    event.index = 17;
    event.ring_count = 512;
    event.queued = 7;
    event.cur = 18;
    event.tail = 11;
    return event;
}

static void testFixedLayoutAndOneShotRecord()
{
    static_assert(sizeof(iwx_tx_progress_observation_state) <= 480,
                  "observer must remain a small fixed softc addition");
    iwx_tx_progress_observation_state state{};
    auto event = fullEvent();
    assert(record(&state, IWX_TX_PROGRESS_DOORBELL, &event));

    iwx_tx_progress_observation_snapshot snapshot{};
    assert(IwxTxProgressObservation::snapshot(&state, &snapshot));
    assert(snapshot.available == 1 && snapshot.complete == 1);
    assert(snapshot.dropped_count == 0 && snapshot.next_serial == 1);
    const auto &last = snapshot.last[IWX_TX_PROGRESS_DOORBELL];
    assert(last.event_count == 1 && last.serial == 1);
    assert(last.monotonic_ns == event.monotonic_ns);
    assert(last.generation == event.generation);
    assert(last.output_epoch == event.output_epoch);
    assert(last.qid == event.qid && last.index == event.index);
    assert(last.ring_count == event.ring_count && last.queued == event.queued);
    assert(last.cur == event.cur && last.tail == event.tail);
    assert((last.presence_flags & IWX_TX_PROGRESS_HAS_SERIAL) != 0);
}

static void testContentionDropsWithoutChangingTheLastRecord()
{
    iwx_tx_progress_observation_state state{};
    auto event = fullEvent();
    assert(record(&state, IWX_TX_PROGRESS_DOORBELL, &event));
    const auto before = state.last[IWX_TX_PROGRESS_DOORBELL];

    // A held lock models a simultaneous owner. Producer and snapshot both do
    // one CAS attempt and return; producer loss is explicit and does not
    // mutate a partially written row.
    __atomic_store_n(&state.lock, 1U, __ATOMIC_RELEASE);
    event.qid = 15;
    assert(!record(&state, IWX_TX_PROGRESS_DOORBELL, &event));
    iwx_tx_progress_observation_snapshot untouched{};
    untouched.available = 0xfeedU;
    assert(!IwxTxProgressObservation::snapshot(&state, &untouched));
    assert(untouched.available == 0xfeedU);
    __atomic_store_n(&state.lock, 0U, __ATOMIC_RELEASE);

    iwx_tx_progress_observation_snapshot after{};
    assert(IwxTxProgressObservation::snapshot(&state, &after));
    assert(after.available == 1 && after.complete == 0);
    assert(after.dropped_count == 1);
    assert(after.last[IWX_TX_PROGRESS_DOORBELL].event_count == before.event_count);
    assert(after.last[IWX_TX_PROGRESS_DOORBELL].qid == before.qid);
}

static void testReasonCountsAndUnknownPresence()
{
    iwx_tx_progress_observation_state state{};
    auto tx = fullEvent(IWX_TX_PROGRESS_RESPONSE_TX_RSP);
    auto ba = fullEvent(IWX_TX_PROGRESS_RESPONSE_BA);
    auto p2p = fullEvent(IWX_TX_PROGRESS_RESPONSE_P2P_CONSUMED);
    assert(record(&state, IWX_TX_PROGRESS_RESPONSE_DISPATCH, &tx));
    assert(record(&state, IWX_TX_PROGRESS_RESPONSE_DISPATCH, &ba));
    assert(record(&state, IWX_TX_PROGRESS_RESPONSE_DISPATCH, &p2p));

    auto rejected = fullEvent(IWX_TX_PROGRESS_GUARD_RING_REJECTED);
    rejected.presence_flags &= ~IWX_TX_PROGRESS_HAS_TAIL;
    rejected.tail = 0;
    assert(record(&state, IWX_TX_PROGRESS_GUARD_DECISION, &rejected));

    iwx_tx_progress_observation_snapshot snapshot{};
    assert(IwxTxProgressObservation::snapshot(&state, &snapshot));
    assert(snapshot.response_reason_counts[IWX_TX_PROGRESS_RESPONSE_TX_RSP] == 1);
    assert(snapshot.response_reason_counts[IWX_TX_PROGRESS_RESPONSE_BA] == 1);
    assert(snapshot.response_reason_counts[IWX_TX_PROGRESS_RESPONSE_P2P_CONSUMED] == 1);
    assert(snapshot.guard_reason_counts[IWX_TX_PROGRESS_GUARD_RING_REJECTED] == 1);
    const auto &last = snapshot.last[IWX_TX_PROGRESS_GUARD_DECISION];
    assert((last.presence_flags & IWX_TX_PROGRESS_HAS_TAIL) == 0);
    assert(last.tail == 0); // Numeric storage is ignored without the flag.
}

static void testCounterSaturationAndFullWidthTimestampSerial()
{
    iwx_tx_progress_observation_state state{};
    state.next_serial = std::numeric_limits<uint64_t>::max() - 1;
    auto event = fullEvent();
    event.monotonic_ns = std::numeric_limits<uint64_t>::max();
    assert(record(&state, IWX_TX_PROGRESS_DOORBELL, &event));
    assert(state.last[IWX_TX_PROGRESS_DOORBELL].serial ==
           std::numeric_limits<uint64_t>::max());
    assert((state.last[IWX_TX_PROGRESS_DOORBELL].presence_flags &
            IWX_TX_PROGRESS_HAS_SERIAL) != 0);
    assert(record(&state, IWX_TX_PROGRESS_DOORBELL, &event));
    assert(state.last[IWX_TX_PROGRESS_DOORBELL].serial == 0);
    assert((state.last[IWX_TX_PROGRESS_DOORBELL].presence_flags &
            IWX_TX_PROGRESS_HAS_SERIAL) == 0);
    state.last[IWX_TX_PROGRESS_DOORBELL].event_count =
        std::numeric_limits<uint64_t>::max() - 1;
    assert(record(&state, IWX_TX_PROGRESS_DOORBELL, &event));
    assert(state.last[IWX_TX_PROGRESS_DOORBELL].event_count ==
           std::numeric_limits<uint64_t>::max());
}

static void testConcurrentWritersAndReadersNeverPublishTornRows()
{
    constexpr uint32_t kWriters = 4;
    constexpr uint32_t kEventsPerWriter = 12000;
    iwx_tx_progress_observation_state state{};
    std::atomic<bool> done{false};
    std::atomic<bool> consistent{true};
    std::array<std::thread, kWriters> writers;

    for (uint32_t worker = 0; worker < kWriters; ++worker) {
        writers[worker] = std::thread([&, worker] {
            for (uint32_t i = 1; i <= kEventsPerWriter; ++i) {
                const uint32_t value = worker * kEventsPerWriter + i;
                auto event = fullEvent();
                event.generation = value;
                event.output_epoch = value + 100;
                event.qid = value % 16;
                event.index = value % 256;
                event.ring_count = 512;
                event.queued = value;
                event.cur = value + 1;
                event.tail = value + 2;
                if (!record(&state, IWX_TX_PROGRESS_DOORBELL, &event) &&
                    __atomic_load_n(&state.dropped_count, __ATOMIC_RELAXED) == 0)
                    consistent.store(false, std::memory_order_relaxed);
            }
        });
    }

    std::thread reader([&] {
        while (!done.load(std::memory_order_acquire)) {
            iwx_tx_progress_observation_snapshot snapshot{};
            if (!IwxTxProgressObservation::snapshot(&state, &snapshot))
                continue;
            const auto &last = snapshot.last[IWX_TX_PROGRESS_DOORBELL];
            if (!last.event_count)
                continue;
            if (last.output_epoch != last.generation + 100 ||
                last.qid != last.generation % 16 ||
                last.index != last.generation % 256 ||
                last.cur != last.queued + 1 ||
                last.tail != last.queued + 2)
                consistent.store(false, std::memory_order_relaxed);
        }
    });
    for (auto &writer : writers)
        writer.join();
    done.store(true, std::memory_order_release);
    reader.join();

    iwx_tx_progress_observation_snapshot finalSnapshot{};
    assert(IwxTxProgressObservation::snapshot(&state, &finalSnapshot));
    assert(consistent.load(std::memory_order_relaxed));
    assert(finalSnapshot.last[IWX_TX_PROGRESS_DOORBELL].event_count > 0);
    assert(finalSnapshot.dropped_count > 0);
    assert(finalSnapshot.complete == 0);
}

int main()
{
    testFixedLayoutAndOneShotRecord();
    testContentionDropsWithoutChangingTheLastRecord();
    testReasonCountsAndUnknownPresence();
    testCounterSaturationAndFullWidthTimestampSerial();
    testConcurrentWritersAndReadersNeverPublishTornRows();
    return 0;
}
