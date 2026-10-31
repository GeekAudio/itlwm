// Offline Test093 completion-copy lifetime prototype.
// The registry only observes a mapping; it never owns or releases DMA memory.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace Test093CompletionCopyFence {

static const uint32_t kObservedFamily = 2;
static const uint32_t kMaximumRingSlot = 512;
static const size_t kCompletionStride = 32;
static const size_t kCompletionBytes = 8;

struct Handle {
    const void *identity; // Opaque equality key. Never dereference it.
    uint64_t incarnation;

    Handle() : identity(nullptr), incarnation(0) {}
    Handle(const void *key, uint64_t generation)
        : identity(key), incarnation(generation) {}

    bool valid() const { return identity != nullptr && incarnation != 0; }
};

enum class ReserveStatus {
    kReserved,
    kCapacityFull,
    kIdentityAlreadyActive,
    kInvalidInput,
    kIncarnationExhausted
};

struct ReserveResult {
    ReserveStatus status;
    Handle handle;

    ReserveResult(ReserveStatus value, Handle allocation)
        : status(value), handle(allocation) {}
};

enum class PublishStatus {
    kPublished,
    kNotReservedOrStale,
    kInvalidMapping
};

enum class RetireStatus {
    kPublishedViewRetired,
    kReservationClosed,
    kNotFoundOrStale
};

enum class CopyStatus {
    kCopied,
    kBusy,
    kNoView,
    kWrongFamily,
    kSlotOutOfRange,
    kMappingTooShort,
    kSlotPastMapping
};

struct Snapshot {
    uint8_t bytes[kCompletionBytes];

    Snapshot() : bytes{} {}
};

struct CopyResult {
    CopyStatus status;
    Snapshot snapshot;

    CopyResult() : status(CopyStatus::kNoView), snapshot() {}
};

// Tests can inject a byte observer. Production-shaped use supplies this no-op
// probe; it must remain nonblocking and nonthrowing while the registry is held.
struct NoopReadProbe {
    void afterByte(size_t) const {}
};

template <typename Lock, size_t Capacity>
class Registry {
public:
    static_assert(Capacity > 0, "observer registry must have capacity");

    // A production instance and its injected lock must live in storage
    // independent of HAL/ring/mapping objects and outlive every reader and
    // allocation handle. This prototype does not establish module-unload or
    // callback-quiescence behavior.
    explicit Registry(Lock &lock)
        : lock_(lock), nextIncarnation_(1)
    {
        for (size_t i = 0; i < Capacity; ++i)
            entries_[i] = Entry();
    }

    Registry(const Registry &) = delete;
    Registry &operator=(const Registry &) = delete;
    Registry(Registry &&) = delete;
    Registry &operator=(Registry &&) = delete;

    // Reserve before any path can free this allocation. Only kReserved
    // returns a valid handle. A full table or duplicate identity is fail-closed
    // and leaves every existing reservation/view unchanged.
    ReserveResult reserve(const void *identity)
    {
        if (identity == nullptr)
            return ReserveResult(ReserveStatus::kInvalidInput, Handle());

        lock_.lock();
        size_t freeIndex = Capacity;
        for (size_t i = 0; i < Capacity; ++i) {
            if (entries_[i].state != State::kFree &&
                entries_[i].identity == identity) {
                lock_.unlock();
                return ReserveResult(ReserveStatus::kIdentityAlreadyActive,
                                     Handle());
            }
            if (entries_[i].state == State::kFree && freeIndex == Capacity)
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
        if (nextIncarnation_ == UINT64_MAX)
            nextIncarnation_ = 0;
        else
            ++nextIncarnation_;

        const Handle handle(identity, incarnation);
        entries_[freeIndex] = Entry(identity, incarnation, State::kReserved,
                                    0, nullptr, 0);
        lock_.unlock();
        return ReserveResult(ReserveStatus::kReserved, handle);
    }

    // Publish only converts the matching live reservation to a view. If free
    // closed the reservation first, a late publisher cannot install its base.
    PublishStatus publish(const Handle &handle, uint32_t family,
                          const uint8_t *bytes, size_t size)
    {
        lock_.lock();
        Entry *entry = findHandle(handle);
        if (entry == nullptr || entry->state != State::kReserved) {
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
        entry->state = State::kPublished;
        lock_.unlock();
        return PublishStatus::kPublished;
    }

    // Close either a reservation or a published view under the reader's lock.
    // The caller must finish this operation before its legacy freeComplete
    // path. This method returns no mapping pointer and never frees DMA memory.
    RetireStatus unpublish(const Handle &handle)
    {
        lock_.lock();
        Entry *entry = findHandle(handle);
        if (entry == nullptr) {
            lock_.unlock();
            return RetireStatus::kNotFoundOrStale;
        }

        const RetireStatus status = entry->state == State::kPublished
                                        ? RetireStatus::kPublishedViewRetired
                                        : RetireStatus::kReservationClosed;
        *entry = Entry();
        lock_.unlock();
        return status;
    }

    // The result owns only eight copied bytes. The reader makes one try-lock
    // attempt, validates and copies while locked, then returns after unlock.
    CopyResult tryCopy(const Handle &handle, uint32_t slot)
    {
        NoopReadProbe probe;
        return tryCopyImpl(handle, slot, probe);
    }

#ifdef TEST093_ENABLE_TEST_PROBE
    // Compiled only into the offline harness. This callback runs under lock;
    // it must never be exposed as a production callout.
    template <typename Probe>
    CopyResult tryCopyWithProbe(const Handle &handle, uint32_t slot,
                                Probe &probe)
    {
        return tryCopyImpl(handle, slot, probe);
    }
#endif

private:
    template <typename Probe>
    CopyResult tryCopyImpl(const Handle &handle, uint32_t slot, Probe &probe)
    {
        CopyResult result;
        if (!lock_.tryLock()) {
            result.status = CopyStatus::kBusy;
            return result;
        }

        Entry *view = findHandle(handle);
        if (view == nullptr || view->state != State::kPublished) {
            result.status = CopyStatus::kNoView;
        } else if (view->family != kObservedFamily) {
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
            for (size_t i = 0; i < kCompletionBytes; ++i) {
                result.snapshot.bytes[i] = view->bytes[offset + i];
                probe.afterByte(i);
            }
            result.status = CopyStatus::kCopied;
        }

        lock_.unlock();
        return result;
    }

    enum class State {
        kFree,
        kReserved,
        kPublished
    };

    struct Entry {
        const void *identity;
        uint64_t incarnation;
        State state;
        uint32_t family;
        const uint8_t *bytes;
        size_t size;

        Entry()
            : identity(nullptr), incarnation(0), state(State::kFree), family(0),
              bytes(nullptr), size(0) {}
        Entry(const void *key, uint64_t generation, State entryState,
              uint32_t deviceFamily, const uint8_t *mapping,
              size_t mappingSize)
            : identity(key), incarnation(generation), state(entryState),
              family(deviceFamily), bytes(mapping), size(mappingSize) {}
    };

    Entry *findHandle(const Handle &handle)
    {
        if (!handle.valid())
            return nullptr;
        for (size_t i = 0; i < Capacity; ++i) {
            if (entries_[i].state != State::kFree &&
                entries_[i].identity == handle.identity &&
                entries_[i].incarnation == handle.incarnation)
                return &entries_[i];
        }
        return nullptr;
    }

    Lock &lock_;
    Entry entries_[Capacity];
    uint64_t nextIncarnation_; // zero means exhausted; never wrap/reuse
};

// Decode a detached copy only after tryCopy/tryCopyWithProbe has returned.
inline uint64_t decodeLittleEndian(const Snapshot &snapshot)
{
    uint64_t value = 0;
    for (size_t i = 0; i < kCompletionBytes; ++i)
        value |= static_cast<uint64_t>(snapshot.bytes[i]) << (i * 8);
    return value;
}

} // namespace Test093CompletionCopyFence
