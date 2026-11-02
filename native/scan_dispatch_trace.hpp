#ifndef ITL_NATIVE_SCAN_DISPATCH_TRACE_HPP
#define ITL_NATIVE_SCAN_DISPATCH_TRACE_HPP

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

// Bounded metadata-only trace for Tahoe's native scan dispatch stubs.
// Opaque Apple arguments are deliberately absent from this type.
namespace NativeWifi {
namespace ScanDispatchTrace {

constexpr uint32_t kSchema = 1;
constexpr size_t kCapacity = 16;
constexpr unsigned kSnapshotAttempts = 2;
constexpr int32_t kNoResult = INT32_MIN;

enum class Selector : uint32_t {
    WclBgscanCacheResult = 1,
    WclScanRequest = 2,
    WclConfigBgscan = 3,
    WclSetScanHomeAwayTime = 4,
};

enum class Phase : uint32_t {
    Entry = 1,
    Return = 2,
};

enum Context : uint32_t {
    // Reserved for a future source that can sample them without touching the
    // owner's gate during teardown; this trace intentionally does not set them.
    InGate = 1U << 0,
    OnThread = 1U << 1,
    NullArgument = 1U << 2,
    GateContextUnknown = 1U << 3,
};

using TimestampProvider = uint64_t (*)(void *);

struct Input {
    uint64_t callSerial {};
    uint32_t selector {};
    uint32_t phase {};
    int32_t result {kNoResult};
    uint32_t context {};
};

struct Record {
    uint64_t sequence {};
    uint64_t callSerial {};
    uint64_t monotonicNanoseconds {};
    uint32_t selector {};
    uint32_t phase {};
    int32_t result {kNoResult};
    uint32_t context {};
};

struct Snapshot {
    uint32_t schema {};
    uint32_t capacity {};
    uint32_t versionBegin {};
    uint32_t versionEnd {};
    uint32_t stable {};
    uint32_t count {};
    uint32_t droppedCount {};
    uint32_t overwrittenCount {};
    uint32_t unstableSnapshotCount {};
    uint32_t getterEntryHits {};
    uint32_t getterReturnHits {};
    uint32_t scanEntryHits {};
    uint32_t scanReturnHits {};
    uint32_t configEntryHits {};
    uint32_t configReturnHits {};
    uint32_t homeAwayEntryHits {};
    uint32_t homeAwayReturnHits {};
    uint32_t publishFailures {};
    uint64_t nextSequence {};
    uint64_t nextCallSerial {};
    Record records[kCapacity] {};
    Record latest[8] {};
};

static_assert(sizeof(Record) == 40, "trace record layout changed");
static_assert(sizeof(Snapshot) == 1048, "snapshot layout changed");
static_assert(offsetof(Record, callSerial) == 8, "record call serial offset changed");
static_assert(offsetof(Record, selector) == 24, "record selector offset changed");
static_assert(offsetof(Snapshot, publishFailures) == 68, "snapshot publish failures offset changed");
static_assert(offsetof(Snapshot, nextSequence) == 72, "snapshot sequence offset changed");
static_assert(offsetof(Snapshot, nextCallSerial) == 80, "snapshot call serial offset changed");
static_assert(offsetof(Snapshot, records) == 88, "snapshot ring offset changed");
static_assert(offsetof(Snapshot, latest) == 728, "snapshot latest offset changed");
static_assert(__atomic_always_lock_free(sizeof(uint32_t), nullptr), "32-bit trace atomics must be lock-free");
static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr), "64-bit trace atomics must be lock-free");

class Trace final {
public:
    uint64_t beginCall() {
        return __atomic_add_fetch(&nextCallSerial_, 1ULL, __ATOMIC_RELAXED);
    }

    bool record(const Input &input, TimestampProvider timestamp, void *context) {
        const unsigned hitIndex = hitIndexFor(input.selector, input.phase);
        if (hitIndex >= 8 || !timestamp) {
            __atomic_add_fetch(&droppedCount_, 1U, __ATOMIC_RELAXED);
            return false;
        }
        __atomic_add_fetch(&hits_[hitIndex], 1U, __ATOMIC_RELAXED);

        uint32_t expected = 0;
        if (!__atomic_compare_exchange_n(&writerBusy_, &expected, 1U, false,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            __atomic_add_fetch(&droppedCount_, 1U, __ATOMIC_RELAXED);
            return false;
        }

        const uint32_t priorVersion = __atomic_load_n(&version_, __ATOMIC_RELAXED);
        if (priorVersion & 1U) {
            __atomic_add_fetch(&droppedCount_, 1U, __ATOMIC_RELAXED);
            __atomic_store_n(&writerBusy_, 0U, __ATOMIC_RELEASE);
            return false;
        }
        __atomic_store_n(&version_, priorVersion + 1U, __ATOMIC_RELEASE);

        const uint64_t sequence = __atomic_add_fetch(&nextSequence_, 1ULL, __ATOMIC_RELAXED);
        const uint64_t now = timestamp(context);
        AtomicRecord &slot = records_[(sequence - 1U) % kCapacity];
        __atomic_store_n(&slot.monotonicNanoseconds, now, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.callSerial, input.callSerial, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.selector, input.selector, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.phase, input.phase, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.result, input.result, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.context, input.context, __ATOMIC_RELAXED);
        __atomic_store_n(&slot.sequence, sequence, __ATOMIC_RELEASE);
        AtomicRecord &latest = latestRecords_[hitIndex];
        const uint64_t latestCallSerial = __atomic_load_n(&latest.callSerial, __ATOMIC_RELAXED);
        if (input.callSerial >= latestCallSerial) {
            __atomic_store_n(&latest.monotonicNanoseconds, now, __ATOMIC_RELAXED);
            __atomic_store_n(&latest.callSerial, input.callSerial, __ATOMIC_RELAXED);
            __atomic_store_n(&latest.selector, input.selector, __ATOMIC_RELAXED);
            __atomic_store_n(&latest.phase, input.phase, __ATOMIC_RELAXED);
            __atomic_store_n(&latest.result, input.result, __ATOMIC_RELAXED);
            __atomic_store_n(&latest.context, input.context, __ATOMIC_RELAXED);
            __atomic_store_n(&latest.sequence, sequence, __ATOMIC_RELEASE);
        }
        if (sequence > kCapacity)
            __atomic_add_fetch(&overwrittenCount_, 1U, __ATOMIC_RELAXED);

        __atomic_store_n(&version_, priorVersion + 2U, __ATOMIC_RELEASE);
        __atomic_store_n(&writerBusy_, 0U, __ATOMIC_RELEASE);
        return true;
    }

    // At most two lock-free reads; on instability the output is still marked
    // stable=0, count=0 and carries version/drop counters for diagnostics.
    bool snapshot(Snapshot *out) const {
        if (!out) return false;
        Snapshot last {};
        last.schema = kSchema;
        last.capacity = uint32_t(kCapacity);

        for (unsigned attempt = 0; attempt < kSnapshotAttempts; ++attempt) {
            Snapshot candidate {};
            candidate.schema = kSchema;
            candidate.capacity = uint32_t(kCapacity);
            candidate.versionBegin = __atomic_load_n(&version_, __ATOMIC_ACQUIRE);
            candidate.nextSequence = __atomic_load_n(&nextSequence_, __ATOMIC_RELAXED);
            candidate.nextCallSerial = __atomic_load_n(&nextCallSerial_, __ATOMIC_RELAXED);
            candidate.droppedCount = __atomic_load_n(&droppedCount_, __ATOMIC_RELAXED);
            candidate.overwrittenCount = __atomic_load_n(&overwrittenCount_, __ATOMIC_RELAXED);
            candidate.unstableSnapshotCount = __atomic_load_n(&unstableSnapshotCount_, __ATOMIC_RELAXED);
            candidate.getterEntryHits = __atomic_load_n(&hits_[0], __ATOMIC_RELAXED);
            candidate.getterReturnHits = __atomic_load_n(&hits_[1], __ATOMIC_RELAXED);
            candidate.scanEntryHits = __atomic_load_n(&hits_[2], __ATOMIC_RELAXED);
            candidate.scanReturnHits = __atomic_load_n(&hits_[3], __ATOMIC_RELAXED);
            candidate.configEntryHits = __atomic_load_n(&hits_[4], __ATOMIC_RELAXED);
            candidate.configReturnHits = __atomic_load_n(&hits_[5], __ATOMIC_RELAXED);
            candidate.homeAwayEntryHits = __atomic_load_n(&hits_[6], __ATOMIC_RELAXED);
            candidate.homeAwayReturnHits = __atomic_load_n(&hits_[7], __ATOMIC_RELAXED);

            const bool beganEven = (candidate.versionBegin & 1U) == 0;
            const uint64_t count = candidate.nextSequence < kCapacity
                ? candidate.nextSequence : uint64_t(kCapacity);
            bool recordsMatch = beganEven;
            if (recordsMatch) {
                const uint64_t firstSequence = candidate.nextSequence - count + 1U;
                for (uint64_t i = 0; i < count; ++i) {
                    const uint64_t expectedSequence = firstSequence + i;
                    const AtomicRecord &slot = records_[(expectedSequence - 1U) % kCapacity];
                    Record &record = candidate.records[i];
                    record.sequence = __atomic_load_n(&slot.sequence, __ATOMIC_ACQUIRE);
                    record.callSerial = __atomic_load_n(&slot.callSerial, __ATOMIC_RELAXED);
                    record.monotonicNanoseconds = __atomic_load_n(&slot.monotonicNanoseconds, __ATOMIC_RELAXED);
                    record.selector = __atomic_load_n(&slot.selector, __ATOMIC_RELAXED);
                    record.phase = __atomic_load_n(&slot.phase, __ATOMIC_RELAXED);
                    record.result = __atomic_load_n(&slot.result, __ATOMIC_RELAXED);
                    record.context = __atomic_load_n(&slot.context, __ATOMIC_RELAXED);
                    if (record.sequence != expectedSequence) recordsMatch = false;
                }
            }
            if (recordsMatch) {
                for (unsigned i = 0; i < 8; ++i) {
                    const AtomicRecord &latest = latestRecords_[i];
                    Record &record = candidate.latest[i];
                    record.sequence = __atomic_load_n(&latest.sequence, __ATOMIC_ACQUIRE);
                    record.callSerial = __atomic_load_n(&latest.callSerial, __ATOMIC_RELAXED);
                    record.monotonicNanoseconds = __atomic_load_n(&latest.monotonicNanoseconds, __ATOMIC_RELAXED);
                    record.selector = __atomic_load_n(&latest.selector, __ATOMIC_RELAXED);
                    record.phase = __atomic_load_n(&latest.phase, __ATOMIC_RELAXED);
                    record.result = __atomic_load_n(&latest.result, __ATOMIC_RELAXED);
                    record.context = __atomic_load_n(&latest.context, __ATOMIC_RELAXED);
                    if ((record.sequence == 0) != (record.callSerial == 0) ||
                        record.sequence > candidate.nextSequence ||
                        record.callSerial > candidate.nextCallSerial)
                        recordsMatch = false;
                }
            }

            candidate.versionEnd = __atomic_load_n(&version_, __ATOMIC_ACQUIRE);
            const uint32_t droppedAfter = __atomic_load_n(&droppedCount_, __ATOMIC_RELAXED);
            const uint64_t sequenceAfter = __atomic_load_n(&nextSequence_, __ATOMIC_RELAXED);
            const uint64_t callSerialAfter = __atomic_load_n(&nextCallSerial_, __ATOMIC_RELAXED);
            const uint32_t hitsAfter[8] = {
                __atomic_load_n(&hits_[0], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[1], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[2], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[3], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[4], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[5], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[6], __ATOMIC_RELAXED),
                __atomic_load_n(&hits_[7], __ATOMIC_RELAXED),
            };
            const uint32_t hitsBefore[8] = {
                candidate.getterEntryHits, candidate.getterReturnHits,
                candidate.scanEntryHits, candidate.scanReturnHits,
                candidate.configEntryHits, candidate.configReturnHits,
                candidate.homeAwayEntryHits, candidate.homeAwayReturnHits,
            };
            bool hitsMatch = true;
            for (unsigned i = 0; i < 8; ++i) hitsMatch &= hitsBefore[i] == hitsAfter[i];
            const bool stable = beganEven && recordsMatch &&
                candidate.versionBegin == candidate.versionEnd &&
                (candidate.versionEnd & 1U) == 0 &&
                candidate.droppedCount == droppedAfter &&
                candidate.nextSequence == sequenceAfter &&
                candidate.nextCallSerial == callSerialAfter && hitsMatch;
            if (stable) {
                candidate.stable = 1;
                candidate.count = uint32_t(count);
                *out = candidate;
                return true;
            }

            candidate.stable = 0;
            candidate.count = 0;
            candidate.droppedCount = droppedAfter;
            candidate.nextSequence = sequenceAfter;
            last = candidate;
        }

        const uint32_t failures = __atomic_add_fetch(&unstableSnapshotCount_, 1U, __ATOMIC_RELAXED);
        last.unstableSnapshotCount = failures;
        *out = last;
        return false;
    }

private:
    struct AtomicRecord {
        uint64_t sequence {};
        uint64_t callSerial {};
        uint64_t monotonicNanoseconds {};
        uint32_t selector {};
        uint32_t phase {};
        int32_t result {kNoResult};
        uint32_t context {};
    };

    static unsigned hitIndexFor(uint32_t selector, uint32_t phase) {
        if (phase != uint32_t(Phase::Entry) && phase != uint32_t(Phase::Return)) return 8;
        const unsigned phaseOffset = phase == uint32_t(Phase::Entry) ? 0U : 1U;
        if (selector == uint32_t(Selector::WclBgscanCacheResult)) return phaseOffset;
        if (selector == uint32_t(Selector::WclScanRequest)) return 2U + phaseOffset;
        if (selector == uint32_t(Selector::WclConfigBgscan)) return 4U + phaseOffset;
        if (selector == uint32_t(Selector::WclSetScanHomeAwayTime)) return 6U + phaseOffset;
        return 8;
    }

    uint32_t writerBusy_ {};
    uint32_t version_ {};
    uint32_t droppedCount_ {};
    uint32_t overwrittenCount_ {};
    mutable uint32_t unstableSnapshotCount_ {};
    uint32_t hits_[8] {};
    uint64_t nextSequence_ {};
    uint64_t nextCallSerial_ {};
    AtomicRecord records_[kCapacity] {};
    AtomicRecord latestRecords_[8] {};
};

} // namespace ScanDispatchTrace
} // namespace NativeWifi

#endif // ITL_NATIVE_SCAN_DISPATCH_TRACE_HPP
