// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_FW_DIAGNOSTICS_HPP
#define GEEK_IWX_FW_DIAGNOSTICS_HPP

#include <stdint.h>

// Fixed, address-free metadata for firmware command/RX timing and bounded
// error-table headers. This is supporting evidence only: a host qid/index
// tuple does not prove firmware ownership or completion.
namespace IwxFirmwareDiagnostics {

constexpr uint32_t kSchemaVersion = 1;
constexpr uint32_t kTraceCapacity = 64;
constexpr uint32_t kTraceWireMagic = 0x54584348; // "HCXT" in little endian.
constexpr uint32_t kTraceWireHeaderBytes = 84;
constexpr uint32_t kTraceWireEntryBytes = 80;
constexpr uint32_t kTraceWireBlobBytes =
    kTraceWireHeaderBytes + kTraceCapacity * kTraceWireEntryBytes;

enum class Phase : uint32_t {
    Unknown = 0,
    CommandSubmitted = 1,
    CommandSubmitFailed = 2,
    RxDescriptorRejected = 3,
    RxLengthRejected = 4,
    RxValidated = 5,
    RxResponseCopied = 6,
    RxResponseNoBuffer = 7,
    RxResponseRejected = 8,
    RxDispatchCompleted = 9,
    FirmwareErrorInterrupt = 10,
    CommandRetired = 11,
    CommandWaitReturned = 12,
    FirmwareErrorTableCapture = 13
};

enum class Source : uint32_t {
    Unknown = 0,
    HostCommand = 1,
    CommandResponseQueue = 2,
    UnsolicitedFirmwareNotification = 3,
    FirmwareInterrupt = 4,
    DriverRecovery = 5
};

enum EventFlags : uint32_t {
    kAsync = 1u << 0,
    kWantResponse = 1u << 1,
    kHeaderVersionPresent = 1u << 2,
    kPacketLengthPresent = 1u << 3,
    kHeaderFieldsPresent = 1u << 4,
    kResponseBufferPresent = 1u << 5,
    kFirmwareStateKnown = 1u << 6,
    kSourceIsHintOnly = 1u << 7,
    kCommandIdentityPresent = 1u << 8,
    kHostQueueTuplePresent = 1u << 9
};

// header_sequence is qid<<8 | idx: it identifies a host/RX header slot only;
// it is not a firmware transaction ID. Presence flags distinguish parsed
// packet headers from host command identity/queue-slot context.
struct Entry {
    uint64_t serial;
    uint64_t monotonic_ns;
    uint32_t driver_generation;
    uint32_t firmware_generation;
    uint32_t phase;
    uint32_t source;
    uint32_t command_id;
    uint32_t group_id;
    uint32_t version;
    uint32_t qid;
    uint32_t index;
    uint32_t header_sequence;
    uint32_t flags;
    uint32_t result;
    uint32_t result_detail;
    uint32_t packet_length;
    uint32_t payload_length;
};

struct Slot {
    uint32_t writer;
    Entry entry;
};

struct TraceRing {
    uint64_t next_serial;
    uint32_t dropped_count;
    uint32_t overwritten_count;
    uint32_t serial_exhausted;
    Slot slots[kTraceCapacity];
};

struct TraceSnapshot {
    uint32_t schema;
    uint64_t version_begin;
    uint64_t version_end;
    uint32_t owner_generation;
    uint32_t owner_watchdog_sequence;
    uint32_t owner_watchdog_sequence_present;
    uint32_t row_count;
    uint32_t dropped_count;
    uint32_t overwritten_count;
    uint32_t gap_count;
    uint64_t window_start_serial;
    uint64_t window_end_serial;
    uint32_t stable;
    uint32_t complete;
    Entry rows[kTraceCapacity];
};

// OSData wire representation is explicitly packed and little-endian. It has
// no pointers, payload bytes, MAC addresses, or compiler-dependent padding.
struct __attribute__((packed)) TraceWireHeader {
    uint32_t magic_le;
    uint32_t schema_le;
    uint32_t header_bytes_le;
    uint32_t entry_bytes_le;
    uint64_t version_begin_le;
    uint64_t version_end_le;
    uint32_t owner_generation_le;
    uint32_t owner_watchdog_sequence_le;
    uint32_t owner_watchdog_sequence_present_le;
    uint32_t row_count_le;
    uint32_t dropped_count_le;
    uint32_t overwritten_count_le;
    uint32_t gap_count_le;
    uint64_t window_start_serial_le;
    uint64_t window_end_serial_le;
    uint32_t stable_le;
    uint32_t complete_le;
};

struct __attribute__((packed)) TraceWireEntry {
    uint64_t serial_le;
    uint64_t monotonic_ns_le;
    uint32_t driver_generation_le;
    uint32_t firmware_generation_le;
    uint32_t phase_le;
    uint32_t source_le;
    uint32_t command_id_le;
    uint32_t group_id_le;
    uint32_t version_le;
    uint32_t qid_le;
    uint32_t index_le;
    uint32_t header_sequence_le;
    uint32_t flags_le;
    uint32_t result_le;
    uint32_t result_detail_le;
    uint32_t packet_length_le;
    uint32_t payload_length_le;
    uint32_t reserved_le;
};

struct TraceWireBuffer {
    uint8_t bytes[kTraceWireBlobBytes];
    uint32_t length;
};

static_assert(sizeof(TraceWireHeader) == kTraceWireHeaderBytes,
              "HCTX wire header size changed");
static_assert(sizeof(TraceWireEntry) == kTraceWireEntryBytes,
              "HCTX wire entry size changed");

enum class TableStatus : uint32_t {
    NotAttempted = 0,
    Captured = 1,
    Empty = 2,
    FirmwareNotAlive = 3,
    MissingPointer = 4,
    InvalidPointer = 5,
    MisalignedPointer = 6,
    RangeUnproven = 7,
    NicAccessBusy = 8,
    NicAccessUnavailable = 9,
    ReadFailed = 10,
    StaleGeneration = 11,
    GateUnavailable = 12,
    PartialSnapshot = 13,
    PointerMismatch = 14,
    SuspectContents = 15,
    ReadBudgetExceeded = 16,
    AccessReleaseFailed = 17
};

enum class CaptureStatus : uint32_t {
    NotAttempted = 0,
    Pending = 1,
    Captured = 2,
    Partial = 3,
    FirmwareNotAlive = 4,
    StaleGeneration = 5,
    GateUnavailable = 6,
    NicAccessBusy = 7,
    NicAccessUnavailable = 8,
    InvalidPointer = 9,
    SerialExhausted = 10,
    ReadBudgetExceeded = 11,
    AccessReleaseFailed = 12
};

// Only non-address scalar fields are exported. PC/link/frame/stack pointers,
// event-table addresses, error-specific data words and payload bytes are
// intentionally excluded.
struct FirmwareErrorSnapshot {
    uint32_t schema;
    uint32_t capture_status;
    uint32_t snapshot_complete;
    uint32_t capture_serial;
    uint32_t driver_generation;
    uint32_t firmware_generation;
    uint32_t reset_sequence;
    uint32_t watchdog_sequence;
    uint32_t watchdog_sequence_present;
    uint32_t reset_reason;
    uint32_t latest_init_trigger;
    uint32_t latest_init_trigger_sequence;
    uint32_t read_word_count;
    uint32_t lmac_read_word_count;
    uint32_t umac_read_word_count;
    uint32_t lmac_valid_present;
    uint32_t lmac_error_id_present;
    uint32_t umac_valid_present;
    uint32_t umac_error_id_present;
    uint64_t read_budget_ns;
    uint64_t read_elapsed_ns;
    uint64_t monotonic_ns;

    uint32_t lmac_status;
    uint32_t lmac_valid;
    uint32_t lmac_error_id;
    uint32_t lmac_trm_status0;
    uint32_t lmac_trm_status1;
    uint32_t lmac_beacon_time;
    uint32_t lmac_tsf_low;
    uint32_t lmac_tsf_high;
    uint32_t lmac_gp1;
    uint32_t lmac_gp2;
    uint32_t lmac_fw_revision_type;
    uint32_t lmac_fw_major;
    uint32_t lmac_fw_minor;
    uint32_t lmac_hw_version;
    uint32_t lmac_board_version;
    uint32_t lmac_host_command_header;
    uint32_t lmac_isr0;
    uint32_t lmac_isr1;
    uint32_t lmac_isr2;
    uint32_t lmac_isr3;
    uint32_t lmac_isr4;
    uint32_t lmac_last_command_id;
    uint32_t lmac_l2p_control;
    uint32_t lmac_l2p_duration;
    uint32_t lmac_l2p_valid;
    uint32_t lmac_power_management;
    uint32_t lmac_timestamp;
    uint32_t lmac_flow_handler;

    uint32_t umac_status;
    uint32_t umac_valid;
    uint32_t umac_error_id;
    uint32_t umac_major;
    uint32_t umac_minor;
    uint32_t umac_command_header;
    uint32_t umac_isr_status;
};

inline void initialize(TraceRing *ring)
{
    if (!ring)
        return;
    __atomic_store_n(&ring->next_serial, 0ULL, __ATOMIC_RELAXED);
    __atomic_store_n(&ring->dropped_count, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&ring->overwritten_count, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&ring->serial_exhausted, 0U, __ATOMIC_RELAXED);
    for (uint32_t index = 0; index < kTraceCapacity; ++index) {
        Slot &slot = ring->slots[index];
        __atomic_store_n(&slot.writer, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.serial, 0ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.monotonic_ns, 0ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.driver_generation, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.firmware_generation, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.phase, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.source, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.command_id, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.group_id, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.version, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.qid, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.index, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.header_sequence, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.flags, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.result, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.result_detail, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.packet_length, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.entry.payload_length, 0U, __ATOMIC_RELAXED);
    }
}

// Commit an already-reserved serial. Kept separate so a test can deterministically
// model a producer that was descheduled after reserving an older serial.
inline uint32_t commitReserved(TraceRing *ring, const Entry &input,
                              uint64_t serial)
{
    if (!ring || serial == 0)
        return 0;
    const uint32_t index = static_cast<uint32_t>((serial - 1U) % kTraceCapacity);
    Slot &slot = ring->slots[index];
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&slot.writer, &expected, 1U, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_add_fetch(&ring->dropped_count, 1U, __ATOMIC_RELAXED);
        return 0;
    }

    const uint64_t previousSerial = __atomic_load_n(&slot.entry.serial,
                                                    __ATOMIC_ACQUIRE);
    // A producer can be descheduled after reserving a serial. Never let that
    // older writer overwrite a newer row that has already wrapped to this slot.
    if (previousSerial > serial) {
        __atomic_store_n(&slot.writer, 0U, __ATOMIC_RELEASE);
        __atomic_add_fetch(&ring->dropped_count, 1U, __ATOMIC_RELAXED);
        return 0;
    }
    if (previousSerial != 0 && previousSerial < serial)
        __atomic_add_fetch(&ring->overwritten_count, 1U, __ATOMIC_RELAXED);

    Entry &entry = slot.entry;
    __atomic_store_n(&entry.serial, 0ULL, __ATOMIC_RELEASE);
    __atomic_store_n(&entry.monotonic_ns, input.monotonic_ns, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.driver_generation, input.driver_generation, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.firmware_generation, input.firmware_generation, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.phase, input.phase, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.source, input.source, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.command_id, input.command_id, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.group_id, input.group_id, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.version, input.version, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.qid, input.qid, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.index, input.index, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.header_sequence, input.header_sequence, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.flags, input.flags, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.result, input.result, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.result_detail, input.result_detail, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.packet_length, input.packet_length, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.payload_length, input.payload_length, __ATOMIC_RELAXED);
    __atomic_store_n(&entry.serial, serial, __ATOMIC_RELEASE);
    __atomic_store_n(&slot.writer, 0U, __ATOMIC_RELEASE);
    return serial;
}

inline uint32_t record(TraceRing *ring, const Entry &input)
{
    if (!ring)
        return 0;
    if (__atomic_load_n(&ring->serial_exhausted, __ATOMIC_ACQUIRE) != 0U) {
        __atomic_add_fetch(&ring->dropped_count, 1U, __ATOMIC_RELAXED);
        return 0;
    }

    uint64_t serial = 0;
    uint64_t observedSerial = __atomic_load_n(&ring->next_serial,
                                             __ATOMIC_ACQUIRE);
    for (uint32_t attempt = 0; attempt < 4U; ++attempt) {
        if (observedSerial == UINT64_MAX) {
            __atomic_store_n(&ring->serial_exhausted, 1U, __ATOMIC_RELEASE);
            break;
        }
        const uint64_t nextSerial = observedSerial + 1U;
        if (__atomic_compare_exchange_n(&ring->next_serial, &observedSerial,
                nextSerial, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            serial = nextSerial;
            break;
        }
    }
    if (serial == 0) {
        __atomic_add_fetch(&ring->dropped_count, 1U, __ATOMIC_RELAXED);
        return 0;
    }
    return commitReserved(ring, input, serial);
}

inline void copyEntry(Entry *destination, const Entry &source)
{
    if (!destination)
        return;
    __atomic_store_n(&destination->serial,
        __atomic_load_n(&source.serial, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->monotonic_ns,
        __atomic_load_n(&source.monotonic_ns, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->driver_generation,
        __atomic_load_n(&source.driver_generation, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->firmware_generation,
        __atomic_load_n(&source.firmware_generation, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->phase,
        __atomic_load_n(&source.phase, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->source,
        __atomic_load_n(&source.source, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->command_id,
        __atomic_load_n(&source.command_id, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->group_id,
        __atomic_load_n(&source.group_id, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->version,
        __atomic_load_n(&source.version, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->qid,
        __atomic_load_n(&source.qid, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->index,
        __atomic_load_n(&source.index, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->header_sequence,
        __atomic_load_n(&source.header_sequence, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->flags,
        __atomic_load_n(&source.flags, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->result,
        __atomic_load_n(&source.result, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->result_detail,
        __atomic_load_n(&source.result_detail, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->packet_length,
        __atomic_load_n(&source.packet_length, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_store_n(&destination->payload_length,
        __atomic_load_n(&source.payload_length, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
}

inline bool snapshot(const TraceRing *ring, TraceSnapshot *result)
{
    if (!ring || !result)
        return false;

    result->schema = kSchemaVersion;
    result->version_begin = __atomic_load_n(&ring->next_serial, __ATOMIC_ACQUIRE);
    result->dropped_count = __atomic_load_n(&ring->dropped_count, __ATOMIC_ACQUIRE);
    result->overwritten_count = __atomic_load_n(&ring->overwritten_count,
                                                __ATOMIC_ACQUIRE);
    result->row_count = 0;
    result->gap_count = 0;
    result->owner_generation = 0;
    result->owner_watchdog_sequence = 0;
    result->owner_watchdog_sequence_present = 0;
    result->window_end_serial = result->version_begin;
    result->window_start_serial = result->version_begin > kTraceCapacity
        ? result->version_begin - kTraceCapacity + 1U
        : (result->version_begin == 0 ? 0 : 1U);
    bool stable = true;
    for (uint32_t index = 0; index < kTraceCapacity; ++index) {
        const Slot &slot = ring->slots[index];
        if (__atomic_load_n(&slot.writer, __ATOMIC_ACQUIRE) != 0U) {
            stable = false;
            continue;
        }
        const uint64_t before = __atomic_load_n(&slot.entry.serial,
                                                __ATOMIC_ACQUIRE);
        if (before == 0)
            continue;
        Entry row{};
        copyEntry(&row, slot.entry);
        const uint64_t after = __atomic_load_n(&slot.entry.serial,
                                               __ATOMIC_ACQUIRE);
        if (before != after || __atomic_load_n(&slot.writer,
                                               __ATOMIC_ACQUIRE) != 0U) {
            stable = false;
            continue;
        }
        if (row.serial >= result->window_start_serial &&
            row.serial <= result->window_end_serial &&
            result->row_count < kTraceCapacity)
            result->rows[result->row_count++] = row;
    }
    result->version_end = __atomic_load_n(&ring->next_serial, __ATOMIC_ACQUIRE);
    result->stable = stable && result->version_begin == result->version_end ? 1U : 0U;

    // Snapshot reads are bounded. Sort the fixed rows by serial so a decoder
    // can preserve order without inferring it from physical ring slots.
    for (uint32_t i = 1; i < result->row_count; ++i) {
        Entry value = result->rows[i];
        uint32_t j = i;
        while (j > 0 && result->rows[j - 1].serial > value.serial) {
            result->rows[j] = result->rows[j - 1];
            --j;
        }
        result->rows[j] = value;
    }

    const uint64_t expectedRows = result->window_end_serial == 0 ? 0 :
        result->window_end_serial - result->window_start_serial + 1U;
    result->gap_count = expectedRows > result->row_count
        ? static_cast<uint32_t>(expectedRows - result->row_count) : 0U;
    // Complete describes only the currently retained serial window. Lifetime
    // drop/overwrite history is preserved separately and does not make a
    // contiguous current window incomplete; consumers can derive
    // HistoryTruncated from either lifetime counter or window_start_serial.
    result->complete = result->stable && result->gap_count == 0 &&
        result->row_count == expectedRows ? 1U : 0U;
    return result->stable != 0;
}

inline void storeLE32(uint8_t *destination, uint32_t value)
{
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8);
    destination[2] = static_cast<uint8_t>(value >> 16);
    destination[3] = static_cast<uint8_t>(value >> 24);
}

inline void storeLE64(uint8_t *destination, uint64_t value)
{
    storeLE32(destination, static_cast<uint32_t>(value));
    storeLE32(destination + 4, static_cast<uint32_t>(value >> 32));
}

inline bool encodeWire(const TraceSnapshot &snapshot, TraceWireBuffer *buffer)
{
    if (!buffer || snapshot.schema != kSchemaVersion ||
        snapshot.row_count > kTraceCapacity ||
        snapshot.version_begin > snapshot.version_end)
        return false;
    uint8_t *bytes = buffer->bytes;
    storeLE32(bytes + 0, kTraceWireMagic);
    storeLE32(bytes + 4, snapshot.schema);
    storeLE32(bytes + 8, kTraceWireHeaderBytes);
    storeLE32(bytes + 12, kTraceWireEntryBytes);
    storeLE64(bytes + 16, snapshot.version_begin);
    storeLE64(bytes + 24, snapshot.version_end);
    storeLE32(bytes + 32, snapshot.owner_generation);
    storeLE32(bytes + 36, snapshot.owner_watchdog_sequence);
    storeLE32(bytes + 40, snapshot.owner_watchdog_sequence_present);
    storeLE32(bytes + 44, snapshot.row_count);
    storeLE32(bytes + 48, snapshot.dropped_count);
    storeLE32(bytes + 52, snapshot.overwritten_count);
    storeLE32(bytes + 56, snapshot.gap_count);
    storeLE64(bytes + 60, snapshot.window_start_serial);
    storeLE64(bytes + 68, snapshot.window_end_serial);
    storeLE32(bytes + 76, snapshot.stable);
    storeLE32(bytes + 80, snapshot.complete);

    uint32_t offset = kTraceWireHeaderBytes;
    uint64_t previousSerial = 0;
    for (uint32_t index = 0; index < snapshot.row_count; ++index) {
        const Entry &entry = snapshot.rows[index];
        if (entry.serial == 0 || entry.serial <= previousSerial ||
            entry.serial < snapshot.window_start_serial ||
            entry.serial > snapshot.window_end_serial)
            return false;
        previousSerial = entry.serial;
        storeLE64(bytes + offset + 0, entry.serial);
        storeLE64(bytes + offset + 8, entry.monotonic_ns);
        storeLE32(bytes + offset + 16, entry.driver_generation);
        storeLE32(bytes + offset + 20, entry.firmware_generation);
        storeLE32(bytes + offset + 24, entry.phase);
        storeLE32(bytes + offset + 28, entry.source);
        storeLE32(bytes + offset + 32, entry.command_id);
        storeLE32(bytes + offset + 36, entry.group_id);
        storeLE32(bytes + offset + 40, entry.version);
        storeLE32(bytes + offset + 44, entry.qid);
        storeLE32(bytes + offset + 48, entry.index);
        storeLE32(bytes + offset + 52, entry.header_sequence);
        storeLE32(bytes + offset + 56, entry.flags);
        storeLE32(bytes + offset + 60, entry.result);
        storeLE32(bytes + offset + 64, entry.result_detail);
        storeLE32(bytes + offset + 68, entry.packet_length);
        storeLE32(bytes + offset + 72, entry.payload_length);
        // Keep the 80-byte v1 row explicitly padded with a reserved zero.
        storeLE32(bytes + offset + 76, 0U);
        offset += kTraceWireEntryBytes;
    }
    buffer->length = offset;
    return true;
}

} // namespace IwxFirmwareDiagnostics

#endif // GEEK_IWX_FW_DIAGNOSTICS_HPP
