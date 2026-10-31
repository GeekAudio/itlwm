// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_IWX_COMPLETION_OBSERVER_HPP
#define NATIVE_IWX_COMPLETION_OBSERVER_HPP

#include <stddef.h>
#include <stdint.h>

// Bounded, read-only view of the family-2 RX completion mapping. The registry
// observes a CPU mapping; it never owns, retains, synchronizes, or releases DMA.
namespace NativeIwxCompletionObserver {

static const uint32_t kObservedFamily = 2;
static const uint32_t kMaximumRingSlot = 512;
static const uint32_t kTelemetrySampleCapacity = 16;
static const size_t kCompletionStride = 32;
static const size_t kCompletionBytes = 8;
static const size_t kTelemetryHeaderBytes = 56;
static const size_t kTelemetrySampleWireBytes = 44;
static const size_t kTelemetryWireBytes = kTelemetryHeaderBytes +
    kTelemetrySampleCapacity * kTelemetrySampleWireBytes;

struct Handle {
    const void *identity; // Opaque equality key. Never dereference it.
    uint64_t incarnation;

    Handle() : identity(nullptr), incarnation(0) {}
    Handle(const void *key, uint64_t generation)
        : identity(key), incarnation(generation) {}

    bool valid() const { return identity != nullptr && incarnation != 0; }
};

enum class ReserveStatus : uint32_t {
    kReserved = 1,
    kCapacityFull = 2,
    kIdentityAlreadyActive = 3,
    kInvalidInput = 4,
    kIncarnationExhausted = 5,
    kUnavailable = 6,
    kClosed = 7
};

struct ReserveResult {
    ReserveStatus status;
    Handle handle;

    ReserveResult(ReserveStatus value, Handle allocation)
        : status(value), handle(allocation) {}
};

enum class PublishStatus : uint32_t {
    kPublished = 1,
    kNotReservedOrStale = 2,
    kInvalidMapping = 3,
    kUnavailable = 4,
    kClosed = 5
};

enum class RetireStatus : uint32_t {
    kPublishedViewRetired = 1,
    kReservationClosed = 2,
    kNotFoundOrStale = 3,
    kUnavailable = 4,
    kClosed = 5
};

enum class CopyStatus : uint32_t {
    kCopied = 1,
    kBusy = 2,
    kNoView = 3,
    kWrongFamily = 4,
    kSlotOutOfRange = 5,
    kMappingTooShort = 6,
    kSlotPastMapping = 7,
    kUnavailable = 8,
    kClosed = 9,
    kBudgetExhausted = 10
};

struct Snapshot {
    uint8_t bytes[kCompletionBytes];
    uint64_t incarnation;

    Snapshot() : bytes{}, incarnation(0) {}
};

struct CopyResult {
    CopyStatus status;
    Snapshot snapshot;

    CopyResult() : status(CopyStatus::kUnavailable), snapshot() {}
};

// Test-only probe support is compiled out of the kernel target. Production
// supplies NoopReadProbe, so the locked path has no callback, logging, or
// allocation and copies exactly the fixed eight-byte prefix.
struct NoopReadProbe {
    void afterByte(size_t) const {}
};

template <typename Lock, size_t Capacity>
class Registry {
public:
    static_assert(Capacity > 0, "completion observer capacity must be nonzero");

    Registry()
        : state_(State::kDormant), nextIncarnation_(1)
    {
        clearEntries();
    }

    Registry(const Registry &) = delete;
    Registry &operator=(const Registry &) = delete;
    Registry(Registry &&) = delete;
    Registry &operator=(Registry &&) = delete;

    // One initialization attempt per HAL object. A lock allocation failure
    // disables diagnostics without changing the legacy RX allocation path.
    bool initialize()
    {
        if (state_ != State::kDormant)
            return false;
        if (!lock_.initialize()) {
            state_ = State::kUnavailable;
            return false;
        }
        state_ = State::kReady;
        return true;
    }

    // The owner calls shutdown only after every possible reader has exited.
    // It is kept separate from ring retirement so it cannot replace the
    // existing DMA release path.
    void shutdown()
    {
        if (state_ != State::kReady)
            return;
        lock_.lock();
        clearEntries();
        state_ = State::kClosed;
        lock_.unlock();
        lock_.destroy();
    }

    ReserveResult reserve(const void *identity)
    {
        if (state_ == State::kClosed)
            return ReserveResult(ReserveStatus::kClosed, Handle());
        if (state_ != State::kReady)
            return ReserveResult(ReserveStatus::kUnavailable, Handle());
        if (identity == nullptr)
            return ReserveResult(ReserveStatus::kInvalidInput, Handle());

        lock_.lock();
        size_t freeIndex = Capacity;
        for (size_t i = 0; i < Capacity; ++i) {
            if (entries_[i].state != EntryState::kFree &&
                entries_[i].identity == identity) {
                lock_.unlock();
                return ReserveResult(ReserveStatus::kIdentityAlreadyActive,
                                     Handle());
            }
            if (entries_[i].state == EntryState::kFree &&
                freeIndex == Capacity)
                freeIndex = i;
        }

        if (freeIndex == Capacity) {
            lock_.unlock();
            return ReserveResult(ReserveStatus::kCapacityFull, Handle());
        }
        if (nextIncarnation_ == 0) {
            lock_.unlock();
            return ReserveResult(ReserveStatus::kIncarnationExhausted,
                                 Handle());
        }

        const uint64_t incarnation = nextIncarnation_;
        nextIncarnation_ = incarnation == UINT64_MAX ? 0 : incarnation + 1;
        const Handle handle(identity, incarnation);
        entries_[freeIndex] = Entry(identity, incarnation,
                                    EntryState::kReserved, 0, nullptr, 0);
        lock_.unlock();
        return ReserveResult(ReserveStatus::kReserved, handle);
    }

    // Publish converts only the exact live reservation. A late publisher can
    // never reopen an entry already retired by the free path.
    PublishStatus publish(const Handle &handle, uint32_t family,
                          const uint8_t *bytes, size_t size)
    {
        if (state_ == State::kClosed)
            return PublishStatus::kClosed;
        if (state_ != State::kReady)
            return PublishStatus::kUnavailable;

        lock_.lock();
        Entry *entry = findHandle(handle);
        if (entry == nullptr || entry->state != EntryState::kReserved) {
            lock_.unlock();
            return PublishStatus::kNotReservedOrStale;
        }
        if (bytes == nullptr) {
            lock_.unlock();
            return PublishStatus::kInvalidMapping;
        }

        entry->family = family;
        entry->bytes = bytes;
        entry->size = size;
        entry->state = EntryState::kPublished;
        lock_.unlock();
        return PublishStatus::kPublished;
    }

    // The writer blocks until the reader's copy is detached. It retires the
    // exact allocation handle and returns no mapping address to the caller.
    RetireStatus unpublish(const Handle &handle)
    {
        if (state_ == State::kClosed)
            return RetireStatus::kClosed;
        if (state_ != State::kReady)
            return RetireStatus::kUnavailable;

        lock_.lock();
        Entry *entry = findHandle(handle);
        if (entry == nullptr) {
            lock_.unlock();
            return RetireStatus::kNotFoundOrStale;
        }

        const RetireStatus status = entry->state == EntryState::kPublished
            ? RetireStatus::kPublishedViewRetired
            : RetireStatus::kReservationClosed;
        *entry = Entry();
        lock_.unlock();
        return status;
    }

    // The reader makes one try-lock attempt. The identity overload is used by
    // the RX drain, avoiding a concurrently mutated handle field; the result
    // carries the exact incarnation copied while holding the lock.
    CopyResult tryCopy(const Handle &handle, uint32_t family, uint32_t slot)
    {
        NoopReadProbe probe;
        return tryCopyImpl(handle, nullptr, family, slot, probe);
    }

    CopyResult tryCopyForIdentity(const void *identity, uint32_t family,
                                  uint32_t slot)
    {
        NoopReadProbe probe;
        return tryCopyImpl(Handle(), identity, family, slot, probe);
    }

#ifdef TEST094_ENABLE_TEST_PROBE
    template <typename Probe>
    CopyResult tryCopyWithProbe(const Handle &handle, uint32_t family,
                                uint32_t slot, Probe &probe)
    {
        return tryCopyImpl(handle, nullptr, family, slot, probe);
    }

    Lock &lockForTesting() { return lock_; }
#endif

private:
    enum class State : uint32_t {
        kDormant,
        kReady,
        kUnavailable,
        kClosed
    };

    enum class EntryState : uint32_t {
        kFree,
        kReserved,
        kPublished
    };

    struct Entry {
        const void *identity;
        uint64_t incarnation;
        EntryState state;
        uint32_t family;
        const uint8_t *bytes;
        size_t size;

        Entry()
            : identity(nullptr), incarnation(0), state(EntryState::kFree),
              family(0), bytes(nullptr), size(0) {}
        Entry(const void *key, uint64_t generation, EntryState entryState,
              uint32_t deviceFamily, const uint8_t *mapping,
              size_t mappingSize)
            : identity(key), incarnation(generation), state(entryState),
              family(deviceFamily), bytes(mapping), size(mappingSize) {}
    };

    void clearEntries()
    {
        for (size_t i = 0; i < Capacity; ++i)
            entries_[i] = Entry();
    }

    Entry *findHandle(const Handle &handle)
    {
        if (!handle.valid())
            return nullptr;
        for (size_t i = 0; i < Capacity; ++i) {
            if (entries_[i].state != EntryState::kFree &&
                entries_[i].identity == handle.identity &&
                entries_[i].incarnation == handle.incarnation)
                return &entries_[i];
        }
        return nullptr;
    }

    Entry *findIdentity(const void *identity)
    {
        if (identity == nullptr)
            return nullptr;
        for (size_t i = 0; i < Capacity; ++i) {
            if (entries_[i].state != EntryState::kFree &&
                entries_[i].identity == identity)
                return &entries_[i];
        }
        return nullptr;
    }

    template <typename Probe>
    CopyResult tryCopyImpl(const Handle &handle, const void *identity,
                           uint32_t family, uint32_t slot, Probe &probe)
    {
        CopyResult result;
        if (state_ == State::kClosed) {
            result.status = CopyStatus::kClosed;
            return result;
        }
        if (state_ != State::kReady) {
            result.status = CopyStatus::kUnavailable;
            return result;
        }
        if (!lock_.tryLock()) {
            result.status = CopyStatus::kBusy;
            return result;
        }

        Entry *view = identity != nullptr ? findIdentity(identity) :
                                           findHandle(handle);
        if (view == nullptr || view->state != EntryState::kPublished) {
            result.status = CopyStatus::kNoView;
        } else if (view->family != kObservedFamily || family != kObservedFamily) {
            result.status = CopyStatus::kWrongFamily;
        } else if (slot >= kMaximumRingSlot) {
            result.status = CopyStatus::kSlotOutOfRange;
        } else if (view->size < kCompletionBytes) {
            result.status = CopyStatus::kMappingTooShort;
        } else if (static_cast<size_t>(slot) >
                   (view->size - kCompletionBytes) / kCompletionStride) {
            result.status = CopyStatus::kSlotPastMapping;
        } else {
            const size_t offset = static_cast<size_t>(slot) *
                                  kCompletionStride;
            result.snapshot.incarnation = view->incarnation;
#ifdef TEST094_ENABLE_TEST_PROBE
            for (size_t i = 0; i < kCompletionBytes; ++i) {
                result.snapshot.bytes[i] = view->bytes[offset + i];
                probe.afterByte(i);
            }
#else
            (void)probe;
            for (size_t i = 0; i < kCompletionBytes; ++i)
                result.snapshot.bytes[i] = view->bytes[offset + i];
#endif
            result.status = CopyStatus::kCopied;
        }

        lock_.unlock();
        return result;
    }

    Lock lock_;
    Entry entries_[Capacity];
    State state_;
    uint64_t nextIncarnation_; // zero means exhausted; never wrap/reuse
};

struct Sample {
    uint32_t sequence;
    uint32_t driverGeneration;
    uint32_t observationSerial;
    uint32_t head;
    uint32_t slot;
    uint32_t rawRbid;
    uint32_t rawFlags;
    uint64_t hostUptimeUs;
    uint64_t allocationIncarnation;

    Sample()
        : sequence(0), driverGeneration(0), observationSerial(0), head(0),
          slot(0), rawRbid(0), rawFlags(0), hostUptimeUs(0),
          allocationIncarnation(0) {}
};

// Written by the serialized RX workloop and sampled by the watchdog only
// after the pre-owner capture closes. Every concurrently accessed field uses
// an explicit atomic builtin; revision brackets a consistent fixed-size copy.
struct Telemetry {
    uint32_t revision;
    uint32_t lastStatus;
    uint32_t attempts;
    uint32_t copies;
    uint32_t skips;
    uint32_t overwrittenSamples;
    uint32_t family;
    uint32_t lastAttemptGeneration;
    uint32_t lastAttemptSerial;
    uint32_t lastAttemptHead;
    uint32_t lastAttemptSlot;
    uint32_t sampleCount;
    uint32_t nextSampleIndex;
    uint32_t nextSequence;
    uint64_t lastAttemptUptimeUs;
    Sample samples[kTelemetrySampleCapacity];

    Telemetry()
        : revision(0), lastStatus(0), attempts(0), copies(0), skips(0),
          overwrittenSamples(0), family(0), lastAttemptGeneration(0),
          lastAttemptSerial(0), lastAttemptHead(0), lastAttemptSlot(0),
          sampleCount(0), nextSampleIndex(0), nextSequence(0),
          lastAttemptUptimeUs(0), samples{} {}
};

struct TelemetrySnapshot {
    uint32_t lastStatus;
    uint32_t attempts;
    uint32_t copies;
    uint32_t skips;
    uint32_t overwrittenSamples;
    uint32_t family;
    uint32_t lastAttemptGeneration;
    uint32_t lastAttemptSerial;
    uint32_t lastAttemptHead;
    uint32_t lastAttemptSlot;
    uint32_t sampleCount;
    uint64_t lastAttemptUptimeUs;
    Sample samples[kTelemetrySampleCapacity];

    TelemetrySnapshot()
        : lastStatus(0), attempts(0), copies(0), skips(0),
          overwrittenSamples(0), family(0), lastAttemptGeneration(0),
          lastAttemptSerial(0), lastAttemptHead(0), lastAttemptSlot(0),
          sampleCount(0), lastAttemptUptimeUs(0), samples{} {}
};

inline uint32_t saturatingIncrement(uint32_t value)
{
    return value == UINT32_MAX ? value : value + 1;
}

inline void atomicStoreSample(Sample *destination, const Sample &source)
{
    __atomic_store_n(&destination->sequence, source.sequence, __ATOMIC_RELAXED);
    __atomic_store_n(&destination->driverGeneration, source.driverGeneration,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&destination->observationSerial, source.observationSerial,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&destination->head, source.head, __ATOMIC_RELAXED);
    __atomic_store_n(&destination->slot, source.slot, __ATOMIC_RELAXED);
    __atomic_store_n(&destination->rawRbid, source.rawRbid, __ATOMIC_RELAXED);
    __atomic_store_n(&destination->rawFlags, source.rawFlags, __ATOMIC_RELAXED);
    __atomic_store_n(&destination->hostUptimeUs, source.hostUptimeUs,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&destination->allocationIncarnation,
                     source.allocationIncarnation, __ATOMIC_RELAXED);
}

inline Sample atomicLoadSample(const Sample *source)
{
    Sample value;
    value.sequence = __atomic_load_n(&source->sequence, __ATOMIC_RELAXED);
    value.driverGeneration = __atomic_load_n(&source->driverGeneration,
                                              __ATOMIC_RELAXED);
    value.observationSerial = __atomic_load_n(&source->observationSerial,
                                               __ATOMIC_RELAXED);
    value.head = __atomic_load_n(&source->head, __ATOMIC_RELAXED);
    value.slot = __atomic_load_n(&source->slot, __ATOMIC_RELAXED);
    value.rawRbid = __atomic_load_n(&source->rawRbid, __ATOMIC_RELAXED);
    value.rawFlags = __atomic_load_n(&source->rawFlags, __ATOMIC_RELAXED);
    value.hostUptimeUs = __atomic_load_n(&source->hostUptimeUs, __ATOMIC_RELAXED);
    value.allocationIncarnation = __atomic_load_n(
        &source->allocationIncarnation, __ATOMIC_RELAXED);
    return value;
}

// Called only after tryCopy returns and releases the registry lock. Samples
// form a fixed rolling window so early unrelated traffic cannot exhaust the
// capture before a later target frame arrives.
inline void recordAttempt(Telemetry *telemetry, uint32_t family,
                          uint32_t generation, uint32_t observationSerial,
                          uint64_t hostUptimeUs, uint32_t head,
                          uint32_t slot, const CopyResult &result)
{
    if (telemetry == nullptr)
        return;
    const uint32_t oddRevision = __atomic_add_fetch(
        &telemetry->revision, 1U, __ATOMIC_ACQ_REL);
    const uint32_t sequence = saturatingIncrement(__atomic_load_n(
        &telemetry->nextSequence, __ATOMIC_RELAXED));
    const uint32_t attempts = saturatingIncrement(__atomic_load_n(
        &telemetry->attempts, __ATOMIC_RELAXED));
    __atomic_store_n(&telemetry->nextSequence, sequence, __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->attempts, attempts, __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->lastStatus,
                     static_cast<uint32_t>(result.status), __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->family, family, __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->lastAttemptGeneration, generation,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->lastAttemptSerial, observationSerial,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->lastAttemptUptimeUs, hostUptimeUs,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->lastAttemptHead, head, __ATOMIC_RELAXED);
    __atomic_store_n(&telemetry->lastAttemptSlot, slot, __ATOMIC_RELAXED);

    if (result.status == CopyStatus::kCopied) {
        Sample sample;
        sample.sequence = sequence;
        sample.driverGeneration = generation;
        sample.observationSerial = observationSerial;
        sample.head = head;
        sample.slot = slot;
        sample.rawRbid = static_cast<uint32_t>(result.snapshot.bytes[4]) |
            (static_cast<uint32_t>(result.snapshot.bytes[5]) << 8);
        sample.rawFlags = result.snapshot.bytes[6];
        sample.hostUptimeUs = hostUptimeUs;
        sample.allocationIncarnation = result.snapshot.incarnation;

        const uint32_t index = __atomic_load_n(&telemetry->nextSampleIndex,
                                                __ATOMIC_RELAXED);
        atomicStoreSample(&telemetry->samples[index], sample);
        const uint32_t count = __atomic_load_n(&telemetry->sampleCount,
                                                __ATOMIC_RELAXED);
        if (count < kTelemetrySampleCapacity) {
            __atomic_store_n(&telemetry->sampleCount, count + 1,
                             __ATOMIC_RELAXED);
        } else {
            const uint32_t overwritten = saturatingIncrement(
                __atomic_load_n(&telemetry->overwrittenSamples,
                                __ATOMIC_RELAXED));
            __atomic_store_n(&telemetry->overwrittenSamples, overwritten,
                             __ATOMIC_RELAXED);
        }
        __atomic_store_n(&telemetry->nextSampleIndex,
            (index + 1) % kTelemetrySampleCapacity, __ATOMIC_RELAXED);
        __atomic_store_n(&telemetry->copies, saturatingIncrement(
            __atomic_load_n(&telemetry->copies, __ATOMIC_RELAXED)),
            __ATOMIC_RELAXED);
    } else {
        __atomic_store_n(&telemetry->skips, saturatingIncrement(
            __atomic_load_n(&telemetry->skips, __ATOMIC_RELAXED)),
            __ATOMIC_RELAXED);
    }
    __atomic_store_n(&telemetry->revision, oddRevision + 1, __ATOMIC_RELEASE);
}

inline bool snapshotTelemetry(const Telemetry *telemetry,
                              TelemetrySnapshot *snapshot)
{
    if (telemetry == nullptr || snapshot == nullptr)
        return false;
    for (uint32_t attempt = 0; attempt < 3; ++attempt) {
        const uint32_t begin = __atomic_load_n(&telemetry->revision,
                                                __ATOMIC_ACQUIRE);
        if (begin & 1U)
            continue;

        TelemetrySnapshot local;
        local.lastStatus = __atomic_load_n(&telemetry->lastStatus,
                                           __ATOMIC_RELAXED);
        local.attempts = __atomic_load_n(&telemetry->attempts,
                                         __ATOMIC_RELAXED);
        local.copies = __atomic_load_n(&telemetry->copies, __ATOMIC_RELAXED);
        local.skips = __atomic_load_n(&telemetry->skips, __ATOMIC_RELAXED);
        local.overwrittenSamples = __atomic_load_n(
            &telemetry->overwrittenSamples, __ATOMIC_RELAXED);
        local.family = __atomic_load_n(&telemetry->family, __ATOMIC_RELAXED);
        local.lastAttemptGeneration = __atomic_load_n(
            &telemetry->lastAttemptGeneration, __ATOMIC_RELAXED);
        local.lastAttemptSerial = __atomic_load_n(
            &telemetry->lastAttemptSerial, __ATOMIC_RELAXED);
        local.lastAttemptHead = __atomic_load_n(&telemetry->lastAttemptHead,
                                                 __ATOMIC_RELAXED);
        local.lastAttemptSlot = __atomic_load_n(&telemetry->lastAttemptSlot,
                                                 __ATOMIC_RELAXED);
        local.lastAttemptUptimeUs = __atomic_load_n(
            &telemetry->lastAttemptUptimeUs, __ATOMIC_RELAXED);
        local.sampleCount = __atomic_load_n(&telemetry->sampleCount,
                                             __ATOMIC_RELAXED);
        const uint32_t nextSampleIndex = __atomic_load_n(
            &telemetry->nextSampleIndex, __ATOMIC_RELAXED);
        const uint32_t firstSample = local.sampleCount ==
            kTelemetrySampleCapacity ? nextSampleIndex : 0;
        for (uint32_t i = 0; i < local.sampleCount; ++i) {
            const uint32_t index = (firstSample + i) %
                                   kTelemetrySampleCapacity;
            local.samples[i] = atomicLoadSample(&telemetry->samples[index]);
        }

        const uint32_t end = __atomic_load_n(&telemetry->revision,
                                              __ATOMIC_ACQUIRE);
        if (begin == end && !(end & 1U)) {
            *snapshot = local;
            return true;
        }
    }
    return false;
}

inline void storeLittleEndian32(uint8_t *bytes, size_t offset,
                                uint32_t value)
{
    for (size_t i = 0; i < 4; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

inline void storeLittleEndian64(uint8_t *bytes, size_t offset,
                                uint64_t value)
{
    for (size_t i = 0; i < 8; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

// Fixed-size scalar-only OSData ABI. Samples are emitted oldest-first. No
// packet bytes or endpoint identity are included; there is no C padding.
inline void encodeTelemetry(const TelemetrySnapshot &telemetry,
                            uint8_t bytes[kTelemetryWireBytes])
{
    storeLittleEndian32(bytes, 0, 1); // schema version
    storeLittleEndian32(bytes, 4, telemetry.lastStatus);
    storeLittleEndian32(bytes, 8, telemetry.attempts);
    storeLittleEndian32(bytes, 12, telemetry.copies);
    storeLittleEndian32(bytes, 16, telemetry.skips);
    storeLittleEndian32(bytes, 20, telemetry.overwrittenSamples);
    storeLittleEndian32(bytes, 24, telemetry.family);
    storeLittleEndian32(bytes, 28, telemetry.lastAttemptGeneration);
    storeLittleEndian32(bytes, 32, telemetry.lastAttemptSerial);
    storeLittleEndian32(bytes, 36, telemetry.lastAttemptHead);
    storeLittleEndian32(bytes, 40, telemetry.lastAttemptSlot);
    storeLittleEndian32(bytes, 44, telemetry.sampleCount);
    storeLittleEndian64(bytes, 48, telemetry.lastAttemptUptimeUs);

    for (uint32_t i = 0; i < telemetry.sampleCount; ++i) {
        const Sample &sample = telemetry.samples[i];
        const size_t offset = kTelemetryHeaderBytes +
                              i * kTelemetrySampleWireBytes;
        storeLittleEndian32(bytes, offset, sample.sequence);
        storeLittleEndian32(bytes, offset + 4, sample.driverGeneration);
        storeLittleEndian32(bytes, offset + 8, sample.observationSerial);
        storeLittleEndian32(bytes, offset + 12, sample.head);
        storeLittleEndian32(bytes, offset + 16, sample.slot);
        storeLittleEndian32(bytes, offset + 20, sample.rawRbid);
        storeLittleEndian32(bytes, offset + 24, sample.rawFlags);
        storeLittleEndian64(bytes, offset + 28, sample.hostUptimeUs);
        storeLittleEndian64(bytes, offset + 36,
                            sample.allocationIncarnation);
    }
}

} // namespace NativeIwxCompletionObserver

#endif // NATIVE_IWX_COMPLETION_OBSERVER_HPP
