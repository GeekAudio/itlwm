// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_RING_CAPACITY_HPP
#define GEEK_IWX_TX_RING_CAPACITY_HPP

#include <stddef.h>
#include <stdint.h>

namespace IwxTxRingCapacity {

static inline bool ringIsAddressable(uint32_t queueId, int ringQid,
                                     size_t ringCount,
                                     size_t storageCapacity)
{
    if (ringQid < 0 || static_cast<uint32_t>(ringQid) != queueId ||
        ringCount == 0 || ringCount > storageCapacity)
        return false;
    return (ringCount & (ringCount - 1)) == 0;
}

static inline bool indexIsAddressable(size_t index, size_t ringCount)
{
    return ringCount != 0 && index < ringCount;
}

static inline bool rateQueueCanInspect(uint32_t queueId, int ringQid,
                                       size_t ringCount,
                                       size_t storageCapacity,
                                       int queued, int tail)
{
    return ringIsAddressable(queueId, ringQid, ringCount, storageCapacity) &&
        queued >= 0 && tail >= 0;
}

static inline bool responseIndex(uint32_t queueId, int ringQid,
                                 size_t ringCount, size_t storageCapacity,
                                 uint32_t ssn, uint16_t *indexOut)
{
    if (!indexOut || !ringIsAddressable(queueId, ringQid, ringCount,
                                        storageCapacity))
        return false;

    const size_t index = ssn & (ringCount - 1);
    if (!indexIsAddressable(index, ringCount) || index > UINT16_MAX)
        return false;
    *indexOut = static_cast<uint16_t>(index);
    return true;
}

// Kept as a named production guard so tests can exercise the exact BA queue
// acceptance rule without a kernel softc or firmware fixture.
static inline bool baQueueCanReclaim(uint32_t queueId, int ringQid,
                                     size_t ringCount,
                                     size_t storageCapacity,
                                     uint32_t tfdIndex,
                                     uint16_t *reclaimIndexOut)
{
    return responseIndex(queueId, ringQid, ringCount, storageCapacity,
                         tfdIndex, reclaimIndexOut);
}

static inline bool flushQueueCanReclaim(uint32_t queueId, int ringQid,
                                        size_t ringCount,
                                        size_t storageCapacity,
                                        uint32_t readAfter,
                                        uint16_t *reclaimIndexOut)
{
    return responseIndex(queueId, ringQid, ringCount, storageCapacity,
                         readAfter, reclaimIndexOut);
}

// A firmware flush pointer may reclaim only the descriptors currently
// submitted between the host tail and write pointer. cur is a 16-bit SSN
// modulo the device queue size, not a physical ring index; reduce it to the
// ring before checking the submitted interval. readAfter is likewise mapped
// from its 16-bit SSN by flushQueueCanReclaim(). This ring implementation
// reserves at least one slot at its high-water mark, so a full ring is an
// invalid host snapshot.
static inline bool reclaimIndexWithinQueuedRange(size_t ringCount,
                                                 int queued, int cur, int tail,
                                                 uint16_t reclaimIndex)
{
    if (ringCount == 0 || (ringCount & (ringCount - 1)) != 0 ||
        queued < 0 || static_cast<size_t>(queued) >= ringCount ||
        cur < 0 || cur > UINT16_MAX ||
        tail < 0 || static_cast<size_t>(tail) >= ringCount ||
        static_cast<size_t>(reclaimIndex) >= ringCount)
        return false;

    const size_t curIndex = static_cast<size_t>(cur) % ringCount;
    const size_t expectedCur =
        (static_cast<size_t>(tail) + static_cast<size_t>(queued)) % ringCount;
    if (curIndex != expectedCur)
        return false;

    const size_t distance = (static_cast<size_t>(reclaimIndex) + ringCount -
                             static_cast<size_t>(tail)) % ringCount;
    return distance <= static_cast<size_t>(queued);
}

} // namespace IwxTxRingCapacity

#endif // GEEK_IWX_TX_RING_CAPACITY_HPP
