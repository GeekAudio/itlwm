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

} // namespace IwxTxRingCapacity

#endif // GEEK_IWX_TX_RING_CAPACITY_HPP
