// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_LINK_STATE_TRACE_HPP
#define GEEK_IWX_LINK_STATE_TRACE_HPP

#include <stdint.h>

// Fixed-capacity, address-free diagnostics for the Tahoe iwx state machine.
// Producers never allocate or wait: one producer wins a try-only atomic guard;
// contenders increment a drop counter and return. Snapshot/export is separate.
namespace IwxLinkStateTrace {

static constexpr uint32_t kSchema = 2;
static constexpr uint32_t kCapacity = 8;
static constexpr uint32_t kReadAttempts = 3;
static constexpr uint32_t kKnownValidityMask = 0x7f;

enum class Event : uint32_t {
    kNewStateRequested = 1,
    kNewStateTaskCompleted = 2,
    kDeauthEntered = 3,
    kDeauthReturned = 4,
    kResetBegin = 5,
    kResetComplete = 6,
    // Terminal marker for a not-running recovery path that records the
    // attempt but deliberately does not call iwx_stop().
    kResetSkipped = 7
};

enum Validity : uint32_t {
    kStatePairValid = 1u << 0,
    kDeauthReasonValid = 1u << 1,
    kStateArgumentValid = 1u << 2,
    kResultCodeValid = 1u << 3,
    kInterfaceFlagsValid = 1u << 4,
    kGenerationPairValid = 1u << 5,
    kWatchdogSequenceValid = 1u << 6
};

struct Input {
    uint32_t eventCode;
    uint32_t oldState;
    uint32_t newState;
    uint32_t deauthReason;
    uint32_t stateArgument;
    int32_t resultCode;
    uint32_t ifUpRunning;
    uint32_t driverGeneration;
    uint32_t resetGeneration;
    uint32_t watchdogSequence;
    uint32_t validMask;
};

// This is also the stable numeric IORegistry payload record. It intentionally
// has no string, pointer, MAC, SSID, IP, packet, or frame fields.
struct Record {
    uint64_t sequence;
    uint64_t monotonicNs;
    uint32_t eventCode;
    uint32_t oldState;
    uint32_t newState;
    uint32_t deauthReason;
    uint32_t stateArgument;
    int32_t resultCode;
    uint32_t ifUpRunning;
    uint32_t driverGeneration;
    uint32_t resetGeneration;
    uint32_t watchdogSequence;
    uint32_t validMask;
};

struct Snapshot {
    uint32_t schema;
    uint32_t capacity;
    uint32_t versionBegin;
    uint32_t versionEnd;
    uint32_t droppedCount;
    uint32_t count;
    uint64_t nextSequence;
    Record records[kCapacity];
};

static_assert(__atomic_always_lock_free(sizeof(uint32_t), nullptr),
              "link trace requires lock-free 32-bit atomics");
static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr),
              "link trace requires lock-free 64-bit atomics");
static_assert(sizeof(Record) == 64,
              "link trace record layout is part of the IORegistry schema");
static_assert(sizeof(Snapshot) == 544,
              "link trace snapshot layout is part of the IORegistry schema");

using TimestampProvider = uint64_t (*)();

class Trace {
public:
    // The clock is invoked only after the writer has acquired its try-only
    // guard, so record sequence and monotonic timestamp share one order.
    bool record(const Input &input, TimestampProvider clock)
    {
        if (!clock || !isKnownEvent(input.eventCode)) {
            __atomic_fetch_add(&droppedCount_, 1u, __ATOMIC_RELAXED);
            return false;
        }

        uint32_t expected = 0;
        if (!__atomic_compare_exchange_n(&writerBusy_, &expected, 1u, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_fetch_add(&droppedCount_, 1u, __ATOMIC_RELAXED);
            return false;
        }

        const uint32_t priorVersion = __atomic_load_n(
            &version_, __ATOMIC_RELAXED);
        if (priorVersion & 1u) {
            __atomic_fetch_add(&droppedCount_, 1u, __ATOMIC_RELAXED);
            __atomic_store_n(&writerBusy_, 0u, __ATOMIC_RELEASE);
            return false;
        }
        __atomic_store_n(&version_, priorVersion + 1u, __ATOMIC_RELEASE);

        const uint64_t sequence = __atomic_add_fetch(
            &nextSequence_, uint64_t{1}, __ATOMIC_RELAXED);
        const uint32_t slotIndex =
            static_cast<uint32_t>((sequence - 1u) % kCapacity);
        const Record value = sanitize(input, sequence, clock());
        store(&slots_[slotIndex], value);

        __atomic_store_n(&version_, priorVersion + 2u, __ATOMIC_RELEASE);
        __atomic_store_n(&writerBusy_, 0u, __ATOMIC_RELEASE);
        return true;
    }

    // Lock-free bounded snapshot. A writer, drop-counter change, or torn slot
    // causes a false return; callers should retry only from their read path.
    bool snapshot(Snapshot *out) const
    {
        if (!out)
            return false;
        *out = {};

        for (uint32_t attempt = 0; attempt < kReadAttempts; ++attempt) {
            const uint32_t before = __atomic_load_n(
                &version_, __ATOMIC_ACQUIRE);
            if (before & 1u)
                continue;

            Snapshot value{};
            value.schema = kSchema;
            value.capacity = kCapacity;
            value.versionBegin = before;
            value.nextSequence = __atomic_load_n(
                &nextSequence_, __ATOMIC_RELAXED);
            value.droppedCount = __atomic_load_n(
                &droppedCount_, __ATOMIC_RELAXED);
            value.count = value.nextSequence < kCapacity ?
                static_cast<uint32_t>(value.nextSequence) : kCapacity;

            const uint64_t firstSequence =
                value.nextSequence - value.count + 1u;
            bool slotsMatch = true;
            for (uint32_t index = 0; index < value.count; ++index) {
                const uint64_t expectedSequence = firstSequence + index;
                const uint32_t slotIndex = static_cast<uint32_t>(
                    (expectedSequence - 1u) % kCapacity);
                load(&slots_[slotIndex], &value.records[index]);
                if (value.records[index].sequence != expectedSequence) {
                    slotsMatch = false;
                    break;
                }
            }

            const uint32_t droppedAfter = __atomic_load_n(
                &droppedCount_, __ATOMIC_RELAXED);
            const uint32_t after = __atomic_load_n(
                &version_, __ATOMIC_ACQUIRE);
            if (!slotsMatch || before != after || (after & 1u) ||
                value.droppedCount != droppedAfter)
                continue;

            value.versionEnd = after;
            *out = value;
            return true;
        }
        return false;
    }

private:
    struct AtomicRecord {
        uint64_t sequence {0};
        uint64_t monotonicNs {0};
        uint32_t eventCode {0};
        uint32_t oldState {0};
        uint32_t newState {0};
        uint32_t deauthReason {0};
        uint32_t stateArgument {0};
        int32_t resultCode {0};
        uint32_t ifUpRunning {0};
        uint32_t driverGeneration {0};
        uint32_t resetGeneration {0};
        uint32_t watchdogSequence {0};
        uint32_t validMask {0};
    };

    static bool isKnownEvent(uint32_t eventCode)
    {
        return eventCode >= static_cast<uint32_t>(Event::kNewStateRequested) &&
               eventCode <= static_cast<uint32_t>(Event::kResetSkipped);
    }

    static Record sanitize(const Input &input, uint64_t sequence,
                           uint64_t monotonicNs)
    {
        Record value{};
        value.sequence = sequence;
        value.monotonicNs = monotonicNs;
        value.eventCode = input.eventCode;
        value.validMask = input.validMask & kKnownValidityMask;
        if (value.validMask & kStatePairValid) {
            value.oldState = input.oldState;
            value.newState = input.newState;
        }
        if (value.validMask & kDeauthReasonValid)
            value.deauthReason = input.deauthReason;
        if (value.validMask & kStateArgumentValid)
            value.stateArgument = input.stateArgument;
        if (value.validMask & kResultCodeValid)
            value.resultCode = input.resultCode;
        if (value.validMask & kInterfaceFlagsValid)
            value.ifUpRunning = input.ifUpRunning & 0x3u;
        if (value.validMask & kGenerationPairValid) {
            value.driverGeneration = input.driverGeneration;
            value.resetGeneration = input.resetGeneration;
        }
        if (value.validMask & kWatchdogSequenceValid)
            value.watchdogSequence = input.watchdogSequence;
        return value;
    }

    static void store(AtomicRecord *slot, const Record &value)
    {
        __atomic_store_n(&slot->sequence, value.sequence, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->monotonicNs, value.monotonicNs, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->eventCode, value.eventCode, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->oldState, value.oldState, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->newState, value.newState, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->deauthReason, value.deauthReason, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->stateArgument, value.stateArgument, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->resultCode, value.resultCode, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->ifUpRunning, value.ifUpRunning, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->driverGeneration, value.driverGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->resetGeneration, value.resetGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->watchdogSequence, value.watchdogSequence, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->validMask, value.validMask, __ATOMIC_RELAXED);
    }

    static void load(const AtomicRecord *slot, Record *value)
    {
        value->sequence = __atomic_load_n(&slot->sequence, __ATOMIC_RELAXED);
        value->monotonicNs = __atomic_load_n(&slot->monotonicNs, __ATOMIC_RELAXED);
        value->eventCode = __atomic_load_n(&slot->eventCode, __ATOMIC_RELAXED);
        value->oldState = __atomic_load_n(&slot->oldState, __ATOMIC_RELAXED);
        value->newState = __atomic_load_n(&slot->newState, __ATOMIC_RELAXED);
        value->deauthReason = __atomic_load_n(&slot->deauthReason, __ATOMIC_RELAXED);
        value->stateArgument = __atomic_load_n(&slot->stateArgument, __ATOMIC_RELAXED);
        value->resultCode = __atomic_load_n(&slot->resultCode, __ATOMIC_RELAXED);
        value->ifUpRunning = __atomic_load_n(&slot->ifUpRunning, __ATOMIC_RELAXED);
        value->driverGeneration = __atomic_load_n(&slot->driverGeneration, __ATOMIC_RELAXED);
        value->resetGeneration = __atomic_load_n(&slot->resetGeneration, __ATOMIC_RELAXED);
        value->watchdogSequence = __atomic_load_n(&slot->watchdogSequence, __ATOMIC_RELAXED);
        value->validMask = __atomic_load_n(&slot->validMask, __ATOMIC_RELAXED);
    }

    uint32_t writerBusy_ {0};
    uint32_t version_ {0};
    uint32_t droppedCount_ {0};
    uint64_t nextSequence_ {0};
    AtomicRecord slots_[kCapacity] {};
};

} // namespace IwxLinkStateTrace

#endif // GEEK_IWX_LINK_STATE_TRACE_HPP
