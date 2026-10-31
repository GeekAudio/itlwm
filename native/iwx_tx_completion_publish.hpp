// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_COMPLETION_PUBLISH_HPP
#define GEEK_IWX_TX_COMPLETION_PUBLISH_HPP

#include <stdint.h>

#include "iwx_tx_completion_observation.hpp"

/*
 * Main-gate publication policy for bounded TX-completion snapshots.
 * Watchdog ownership is deliberately not part of the ordinary dirty stamp:
 * owner sequence zero is a valid non-watchdog publication.
 */
namespace IwxTxCompletionPublish {

enum PublicationSource : uint32_t {
    kOrdinaryCompletion = 1,
    kFrozenWatchdogSnapshot = 2
};

struct Stamp {
    uint64_t publicationSerial;
    uint32_t generation;
    uint32_t outputEpoch;
};

static inline bool sameStamp(const Stamp &left, const Stamp &right);

struct OrdinaryCursor {
    Stamp last;
    bool published;

    OrdinaryCursor() : last{}, published(false) {}
};

struct Pending {
    mutable uint32_t writer;
    uint32_t available;
    uint32_t claimed;
    uint32_t reserved;
    uint64_t lostCount;
    iwx_tx_completion_observation_snapshot snapshot;

    Pending() : writer(0), available(0), claimed(0), reserved(0),
        lostCount(0), snapshot{} {}
};

static_assert(sizeof(Pending) <= 1024,
              "related TX completion pending cut exceeded 1 KiB");

static inline void noteLost(Pending *pending)
{
    if (!pending)
        return;
    uint64_t current = __atomic_load_n(&pending->lostCount, __ATOMIC_RELAXED);
    for (uint32_t attempt = 0; attempt < 2U && current != UINT64_MAX;
         ++attempt) {
        uint64_t expected = current;
        if (__atomic_compare_exchange_n(&pending->lostCount, &expected,
                current + 1U, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
            return;
        current = expected;
    }
}

static inline uint64_t lostCount(const Pending *pending)
{
    return pending ? __atomic_load_n(&pending->lostCount, __ATOMIC_ACQUIRE) : 0;
}

static inline bool tryStore(Pending *pending,
    const iwx_tx_completion_observation_snapshot *snapshot)
{
    if (!pending || !snapshot || !snapshot->available)
        return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&pending->writer, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        noteLost(pending);
        return false;
    }
    if (pending->claimed) {
        // The main-gate publisher owns this exact cut. Do not replace a cut
        // after it has been copied; account for the incoming one instead.
        noteLost(pending);
        __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
        return false;
    }
    if (pending->available) {
        const uint64_t currentSerial = pending->snapshot.publication_serial;
        if (snapshot->publication_serial <= currentSerial) {
            // Producers may leave the observer lock in a different order.
            // Never let a late older/equal cut replace a newer pending cut.
            noteLost(pending);
            __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
            return false;
        }
        noteLost(pending); // The older bounded cut is superseded.
    }
    pending->snapshot = *snapshot;
    pending->available = 1;
    pending->claimed = 0;
    __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
    return true;
}

static inline bool tryCopy(const Pending *pending,
    iwx_tx_completion_observation_snapshot *snapshot)
{
    if (!pending || !snapshot)
        return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(
            &pending->writer, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return false;
    const bool available = pending->available != 0;
    if (available)
        *snapshot = pending->snapshot;
    __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
    return available;
}

static inline bool tryClaimCopy(Pending *pending,
    iwx_tx_completion_observation_snapshot *snapshot)
{
    if (!pending || !snapshot)
        return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&pending->writer, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return false;
    // The caller is the serialized main-gate publisher. A claim left behind
    // by a failed property write or a contended release is retryable there.
    const bool available = pending->available != 0;
    if (available) {
        pending->claimed = 1;
        *snapshot = pending->snapshot;
    }
    __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
    return available;
}

static inline bool finishClaim(Pending *pending, const Stamp &stamp,
                               bool consumed)
{
    if (!pending)
        return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&pending->writer, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return false;
    const auto &event = pending->snapshot.last[IWX_TX_COMPLETION_TX_RSP];
    const Stamp current{pending->snapshot.publication_serial,
                        event.driver_generation, event.output_epoch};
    const bool matches = pending->available && pending->claimed &&
        sameStamp(current, stamp);
    if (matches) {
        if (consumed)
            pending->available = 0;
        pending->claimed = 0;
    }
    __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
    return matches;
}

static inline bool tryDiscard(Pending *pending, const Stamp &stamp)
{
    return finishClaim(pending, stamp, true);
}

static inline bool tryReadStamp(const Pending *pending, Stamp *stamp)
{
    if (!pending || !stamp)
        return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(
            &pending->writer, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return false;
    bool available = pending->available != 0 &&
        pending->snapshot.available != 0;
    if (available) {
        const auto &event =
            pending->snapshot.last[IWX_TX_COMPLETION_TX_RSP];
        stamp->publicationSerial = pending->snapshot.publication_serial;
        stamp->generation = event.driver_generation;
        stamp->outputEpoch = event.output_epoch;
    }
    __atomic_store_n(&pending->writer, 0U, __ATOMIC_RELEASE);
    return available;
}

static inline bool sameStamp(const Stamp &left, const Stamp &right)
{
    return left.publicationSerial == right.publicationSerial &&
        left.generation == right.generation &&
        left.outputEpoch == right.outputEpoch;
}

static inline bool shouldPublishOrdinary(bool snapshotAvailable,
    bool watchdogSnapshotPending, bool hasObservedRecords,
    const Stamp &current, const OrdinaryCursor &cursor)
{
    if (!snapshotAvailable || watchdogSnapshotPending)
        return false;
    if (!hasObservedRecords)
        return false;
    if (!cursor.published)
        return true;

    // A generation or output-epoch transition alone must never relabel a
    // retained old event as a new owner's event. Only a fresh related serial
    // can make the ordinary publication path dirty.
    return current.publicationSerial > cursor.last.publicationSerial;
}

static inline bool canCommitOrdinary(bool publicationSucceeded,
    const Stamp &captured, const Stamp &current)
{
    return publicationSucceeded && sameStamp(captured, current);
}

static inline void commitOrdinary(OrdinaryCursor *cursor,
                                  const Stamp &stamp)
{
    if (!cursor)
        return;
    cursor->last = stamp;
    cursor->published = true;
}

} // namespace IwxTxCompletionPublish

#endif
