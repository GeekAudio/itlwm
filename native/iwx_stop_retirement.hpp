// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace NativeIwxStop {

enum class MasterDisabledPoll : uint8_t {
    kDisabled,
    kTimeout,
    kInvalidRead
};

// Mirrors iwx_poll_bit's 10us cadence, while refusing all-ones MMIO reads:
// a detached/unresponsive PCI function must never look like MASTER_DISABLED.
template <typename ReadRegister, typename DelayUs>
MasterDisabledPoll waitForMasterDisabled(ReadRegister readRegister,
                                         DelayUs delayUs,
                                         uint32_t disabledMask,
                                         uint32_t timeoutUs)
{
    uint32_t elapsedUs = 0;
    for (;;) {
        const uint32_t value = readRegister();
        if (value == UINT32_MAX)
            return MasterDisabledPoll::kInvalidRead;
        if ((value & disabledMask) == disabledMask)
            return MasterDisabledPoll::kDisabled;
        if (elapsedUs >= timeoutUs)
            return MasterDisabledPoll::kTimeout;
        delayUs(10);
        elapsedUs += 10;
    }
}

template <typename Ring>
bool hasDmaBacking(const Ring &ring)
{
    return ring.ring_count != 0 || ring.desc != nullptr || ring.cmd != nullptr ||
        ring.desc_dma.vaddr != nullptr || ring.desc_dma.paddr != 0 ||
        ring.cmd_dma.vaddr != nullptr || ring.cmd_dma.paddr != 0 ||
        ring.bc_tbl.vaddr != nullptr || ring.bc_tbl.paddr != 0;
}

template <typename Ring>
bool isInstalledRingAlias(const Ring &scratch, const Ring &installed)
{
    constexpr size_t kScratchSlots = sizeof(scratch.data) / sizeof(scratch.data[0]);
    constexpr size_t kInstalledSlots = sizeof(installed.data) / sizeof(installed.data[0]);
    if (scratch.ring_count > kScratchSlots ||
        installed.ring_count > kInstalledSlots)
        return false;
    if (!hasDmaBacking(scratch) || !hasDmaBacking(installed) ||
        scratch.qid != installed.qid ||
        scratch.ring_count != installed.ring_count ||
        scratch.desc == nullptr || scratch.desc != installed.desc ||
        scratch.cmd == nullptr || scratch.cmd != installed.cmd ||
        scratch.desc_dma.vaddr != installed.desc_dma.vaddr ||
        scratch.desc_dma.paddr != installed.desc_dma.paddr ||
        scratch.cmd_dma.vaddr != installed.cmd_dma.vaddr ||
        scratch.cmd_dma.paddr != installed.cmd_dma.paddr ||
        scratch.bc_tbl.vaddr != installed.bc_tbl.vaddr ||
        scratch.bc_tbl.paddr != installed.bc_tbl.paddr)
        return false;

    for (size_t slot = 0; slot < scratch.ring_count; ++slot) {
        if (scratch.data[slot].map != installed.data[slot].map ||
            scratch.data[slot].cmd_paddr != installed.data[slot].cmd_paddr)
            return false;
    }
    return true;
}

template <typename Ring, typename FreeRing, typename ClearScratch>
size_t retireDynamicRingsAfterStop(Ring *rings, size_t queueCount,
                                   size_t firstDynamicQueue, Ring *scratch,
                                   bool callbacksSerialized,
                                   bool interfaceStopped,
                                   bool masterDisabled,
                                   bool softwareResetIssued,
                                   bool p2pResourcesRetained,
                                   FreeRing freeRing,
                                   ClearScratch clearScratch)
{
    if (!rings || !scratch || !callbacksSerialized || !interfaceStopped ||
        !masterDisabled || !softwareResetIssued || p2pResourcesRetained ||
        firstDynamicQueue > queueCount)
        return 0;

    size_t retired = 0;
    size_t scratchAliases = 0;
    for (size_t queue = firstDynamicQueue; queue < queueCount; ++queue) {
        Ring &ring = rings[queue];
        if (!hasDmaBacking(ring))
            continue;
        if (isInstalledRingAlias(*scratch, ring))
            ++scratchAliases;
        freeRing(&ring);
        ++retired;
    }

    // The temporary ring aliases the installed ring after a successful
    // memcpy handoff. Clear only that exact non-owning alias; a separately
    // retained scratch allocation from an uncertain command stays intact.
    if (scratchAliases == 1)
        clearScratch(scratch);
    return retired;
}

} // namespace NativeIwxStop
