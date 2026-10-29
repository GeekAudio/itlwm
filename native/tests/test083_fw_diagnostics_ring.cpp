#include "../iwx_fw_diagnostics.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace IwxFirmwareDiagnostics;

static Entry event(uint32_t marker)
{
    Entry value{};
    value.monotonic_ns = 1000U + marker;
    value.driver_generation = 7;
    value.firmware_generation = 7;
    value.phase = 1;
    value.command_id = marker;
    return value;
}

static void testCapacityRetentionAndWindowCompleteness()
{
    TraceRing ring{};
    initialize(&ring);
    for (uint32_t index = 1; index <= 65; ++index)
        assert(record(&ring, event(index)) == index);

    TraceSnapshot snapshotValue{};
    assert(snapshot(&ring, &snapshotValue));
    assert(snapshotValue.stable == 1);
    assert(snapshotValue.version_begin == 65);
    assert(snapshotValue.version_end == 65);
    assert(snapshotValue.window_start_serial == 2);
    assert(snapshotValue.window_end_serial == 65);
    assert(snapshotValue.row_count == 64);
    assert(snapshotValue.gap_count == 0);
    assert(snapshotValue.overwritten_count == 1);
    // Complete means the retained current window is complete. Consumers must
    // derive HistoryTruncated separately from lifetime counters/window start.
    assert(snapshotValue.complete == 1);
    assert(snapshotValue.rows[0].serial == 2);
    assert(snapshotValue.rows[63].serial == 65);

    TraceWireBuffer wire{};
    assert(encodeWire(snapshotValue, &wire));
    assert(wire.length == kTraceWireHeaderBytes + 64 * kTraceWireEntryBytes);
    const uint8_t magic[] = {0x48, 0x43, 0x58, 0x54};
    assert(memcmp(wire.bytes, magic, sizeof(magic)) == 0);
    assert(wire.bytes[76] == 1 && wire.bytes[80] == 1);
}

static void testOlderLateWriterCannotReplaceNewerSlot()
{
    TraceRing ring{};
    initialize(&ring);
    for (uint32_t index = 1; index <= 65; ++index)
        assert(record(&ring, event(index)) == index);

    assert(commitReserved(&ring, event(1), 1) == 0);
    assert(ring.slots[0].entry.serial == 65);
    assert(ring.slots[0].entry.command_id == 65);
    assert(__atomic_load_n(&ring.dropped_count, __ATOMIC_ACQUIRE) == 1);

    TraceSnapshot snapshotValue{};
    assert(snapshot(&ring, &snapshotValue));
    assert(snapshotValue.complete == 1);
    assert(snapshotValue.window_start_serial == 2);
    assert(snapshotValue.overwritten_count == 1);
    assert(snapshotValue.dropped_count == 1);
}

static void testSlotConflictIsReportedAsGapAndDrop()
{
    TraceRing ring{};
    initialize(&ring);
    __atomic_store_n(&ring.slots[0].writer, 1U, __ATOMIC_RELEASE);
    assert(record(&ring, event(1)) == 0);
    __atomic_store_n(&ring.slots[0].writer, 0U, __ATOMIC_RELEASE);

    TraceSnapshot snapshotValue{};
    assert(snapshot(&ring, &snapshotValue));
    assert(snapshotValue.stable == 1);
    assert(snapshotValue.version_begin == 1);
    assert(snapshotValue.row_count == 0);
    assert(snapshotValue.gap_count == 1);
    assert(snapshotValue.dropped_count == 1);
    assert(snapshotValue.complete == 0);
}

static void testSerialExhaustionDoesNotWrap()
{
    TraceRing ring{};
    initialize(&ring);
    __atomic_store_n(&ring.next_serial, UINT64_MAX, __ATOMIC_RELEASE);
    assert(record(&ring, event(1)) == 0);
    assert(__atomic_load_n(&ring.next_serial, __ATOMIC_ACQUIRE) == UINT64_MAX);
    assert(__atomic_load_n(&ring.serial_exhausted, __ATOMIC_ACQUIRE) == 1);
    assert(__atomic_load_n(&ring.dropped_count, __ATOMIC_ACQUIRE) == 1);
    assert(record(&ring, event(2)) == 0);
    assert(__atomic_load_n(&ring.next_serial, __ATOMIC_ACQUIRE) == UINT64_MAX);
    assert(__atomic_load_n(&ring.dropped_count, __ATOMIC_ACQUIRE) == 2);
}

int main()
{
    testCapacityRetentionAndWindowCompleteness();
    testOlderLateWriterCannotReplaceNewerSlot();
    testSlotConflictIsReportedAsGapAndDrop();
    testSerialExhaustionDoesNotWrap();
    return 0;
}
