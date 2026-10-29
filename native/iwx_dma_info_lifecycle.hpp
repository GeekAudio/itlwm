// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

namespace NativeIwxDmaInfo {

enum FieldPresence : uint32_t {
    kBufferPresent = 1u << 0,
    kPaddrPresent = 1u << 1,
    kVaddrPresent = 1u << 2,
    kSizePresent = 1u << 3,
    kBmdPresent = 1u << 4,
    kCommandPresent = 1u << 5
};

template <typename Info>
uint32_t fieldPresenceMask(const Info *info)
{
    if (!info)
        return 0;
    uint32_t mask = 0;
    if (info->buffer != nullptr)
        mask |= kBufferPresent;
    if (info->paddr != 0)
        mask |= kPaddrPresent;
    if (info->vaddr != nullptr)
        mask |= kVaddrPresent;
    if (info->size != 0)
        mask |= kSizePresent;
    if (info->bmd != nullptr)
        mask |= kBmdPresent;
    if (info->cmd != nullptr)
        mask |= kCommandPresent;
    return mask;
}

template <typename Info>
bool isEmpty(const Info *info)
{
    return info != nullptr && fieldPresenceMask(info) == 0;
}

// Keep the legacy free contract narrow: only a fully established mapping is
// released. The callbacks retain the platform-specific release sequence.
template <typename Info, typename ReleaseCommand, typename ReleaseBuffer>
void freeComplete(Info *info, ReleaseCommand releaseCommand,
                  ReleaseBuffer releaseBuffer)
{
    if (!info || info->cmd == nullptr)
        return;
    if (info->vaddr == nullptr)
        return;

    releaseCommand(info->cmd);
    info->cmd = nullptr;
    releaseBuffer(info->buffer);
    info->buffer = nullptr;
    info->vaddr = nullptr;
    info->paddr = 0;
    info->size = 0;
}

} // namespace NativeIwxDmaInfo
