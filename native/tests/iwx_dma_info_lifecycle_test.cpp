// SPDX-License-Identifier: GPL-2.0-only
#include "../iwx_dma_info_lifecycle.hpp"
#include "../iwx_stop_retirement.hpp"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

struct FakeCommand {
    unsigned int *clearCount;
    unsigned int *releaseCount;
    unsigned int *order;
    void clearMemoryDescriptor()
    {
        ++*clearCount;
        *order = *order * 10 + 1;
    }
    void release()
    {
        ++*releaseCount;
        *order = *order * 10 + 2;
    }
};

struct FakeBuffer {
    unsigned int *completeCount;
    unsigned int *releaseCount;
    unsigned int *order;
    void complete()
    {
        ++*completeCount;
        *order = *order * 10 + 3;
    }
    void release()
    {
        ++*releaseCount;
        *order = *order * 10 + 4;
    }
};

struct FakeDmaInfo {
    FakeBuffer *buffer;
    uintptr_t paddr;
    void *vaddr;
    size_t size;
    FakeBuffer *bmd;
    FakeCommand *cmd;
};

struct FakeRing {
    unsigned int ring_count;
    void *desc;
    void *cmd;
    FakeDmaInfo desc_dma;
    FakeDmaInfo cmd_dma;
    FakeDmaInfo bc_tbl;
};

static FakeDmaInfo emptyDmaInfo()
{
    return {nullptr, 0, nullptr, 0, nullptr, nullptr};
}

static void releaseDma(FakeDmaInfo *info)
{
    NativeIwxDmaInfo::freeComplete(
        info,
        [](FakeCommand *command) {
            command->clearMemoryDescriptor();
            command->release();
        },
        [](FakeBuffer *buffer) {
            buffer->complete();
            buffer->release();
        });
}

static void testFullReleaseClearsMetadataAndIsIdempotent()
{
    unsigned int commandClearCount = 0;
    unsigned int commandReleaseCount = 0;
    unsigned int bufferCompleteCount = 0;
    unsigned int bufferReleaseCount = 0;
    unsigned int order = 0;
    FakeCommand command{&commandClearCount, &commandReleaseCount, &order};
    FakeBuffer buffer{&bufferCompleteCount, &bufferReleaseCount, &order};
    char allocation[64]{};
    FakeDmaInfo info{&buffer, 0x1234000, allocation, sizeof(allocation),
                     nullptr, &command};

    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           (NativeIwxDmaInfo::kBufferPresent |
            NativeIwxDmaInfo::kPaddrPresent |
            NativeIwxDmaInfo::kVaddrPresent |
            NativeIwxDmaInfo::kSizePresent |
            NativeIwxDmaInfo::kCommandPresent));
    assert(!NativeIwxDmaInfo::isEmpty(&info));

    releaseDma(&info);
    assert(commandClearCount == 1 && commandReleaseCount == 1);
    assert(bufferCompleteCount == 1 && bufferReleaseCount == 1);
    assert(order == 1234); // original command-then-buffer release sequence
    assert(info.buffer == nullptr && info.paddr == 0 && info.vaddr == nullptr);
    assert(info.size == 0 && info.bmd == nullptr && info.cmd == nullptr);
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) == 0);
    assert(NativeIwxDmaInfo::isEmpty(&info));

    FakeRing retired{0, nullptr, nullptr, info, emptyDmaInfo(), emptyDmaInfo()};
    assert(!NativeIwxStop::hasDmaBacking(retired));

    releaseDma(&info);
    assert(commandClearCount == 1 && commandReleaseCount == 1);
    assert(bufferCompleteCount == 1 && bufferReleaseCount == 1);
}

static void testEarlyReturnsPreservePartialMetadata()
{
    unsigned int commandClearCount = 0;
    unsigned int commandReleaseCount = 0;
    unsigned int bufferCompleteCount = 0;
    unsigned int bufferReleaseCount = 0;
    unsigned int order = 0;
    FakeCommand command{&commandClearCount, &commandReleaseCount, &order};
    FakeBuffer buffer{&bufferCompleteCount, &bufferReleaseCount, &order};

    FakeDmaInfo missingCommand{&buffer, 0x1200, reinterpret_cast<void *>(1),
                               128, nullptr, nullptr};
    const uint32_t missingCommandMask =
        NativeIwxDmaInfo::fieldPresenceMask(&missingCommand);
    releaseDma(&missingCommand);
    assert(NativeIwxDmaInfo::fieldPresenceMask(&missingCommand) ==
           missingCommandMask);
    assert(missingCommand.buffer == &buffer && missingCommand.paddr == 0x1200);
    assert(missingCommand.vaddr == reinterpret_cast<void *>(1) &&
           missingCommand.size == 128 && missingCommand.cmd == nullptr);
    assert(!NativeIwxDmaInfo::isEmpty(&missingCommand));

    FakeRing partial{0, nullptr, nullptr, missingCommand,
                     emptyDmaInfo(), emptyDmaInfo()};
    assert(NativeIwxStop::hasDmaBacking(partial));

    FakeDmaInfo missingVaddr{&buffer, 0x3400, nullptr, 256, nullptr, &command};
    const uint32_t missingVaddrMask =
        NativeIwxDmaInfo::fieldPresenceMask(&missingVaddr);
    releaseDma(&missingVaddr);
    assert(NativeIwxDmaInfo::fieldPresenceMask(&missingVaddr) ==
           missingVaddrMask);
    assert(missingVaddr.buffer == &buffer && missingVaddr.paddr == 0x3400);
    assert(missingVaddr.vaddr == nullptr && missingVaddr.size == 256 &&
           missingVaddr.cmd == &command);
    assert(!NativeIwxDmaInfo::isEmpty(&missingVaddr));
    FakeRing partialWithoutVaddr{0, nullptr, nullptr, missingVaddr,
                                 emptyDmaInfo(), emptyDmaInfo()};
    assert(NativeIwxStop::hasDmaBacking(partialWithoutVaddr));

    assert(commandClearCount == 0 && commandReleaseCount == 0);
    assert(bufferCompleteCount == 0 && bufferReleaseCount == 0);
    assert(order == 0);
}

static void testActiveRingBackingIsStillPresent()
{
    FakeDmaInfo activeDma{nullptr, 0, reinterpret_cast<void *>(2), 512,
                          nullptr, nullptr};
    FakeRing active{256, reinterpret_cast<void *>(3), reinterpret_cast<void *>(4),
                    activeDma, emptyDmaInfo(), emptyDmaInfo()};

    assert(!NativeIwxDmaInfo::isEmpty(&active.desc_dma));
    assert(NativeIwxDmaInfo::fieldPresenceMask(&active.desc_dma) ==
           (NativeIwxDmaInfo::kVaddrPresent |
            NativeIwxDmaInfo::kSizePresent));
    assert(NativeIwxStop::hasDmaBacking(active));
}

static void testEachFieldHasItsOwnPresenceBit()
{
    FakeBuffer buffer{};
    FakeCommand command{};
    char byte = 0;

    FakeDmaInfo info = emptyDmaInfo();
    const FakeDmaInfo *nullInfo = nullptr;
    assert(NativeIwxDmaInfo::fieldPresenceMask(nullInfo) == 0);
    assert(!NativeIwxDmaInfo::isEmpty(nullInfo));
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) == 0);
    assert(NativeIwxDmaInfo::isEmpty(&info));

    info.buffer = &buffer;
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           NativeIwxDmaInfo::kBufferPresent);
    info = emptyDmaInfo();
    info.paddr = 1;
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           NativeIwxDmaInfo::kPaddrPresent);
    info = emptyDmaInfo();
    info.vaddr = &byte;
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           NativeIwxDmaInfo::kVaddrPresent);
    info = emptyDmaInfo();
    info.size = 1;
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           NativeIwxDmaInfo::kSizePresent);
    info = emptyDmaInfo();
    info.bmd = &buffer;
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           NativeIwxDmaInfo::kBmdPresent);
    info = emptyDmaInfo();
    info.cmd = &command;
    assert(NativeIwxDmaInfo::fieldPresenceMask(&info) ==
           NativeIwxDmaInfo::kCommandPresent);
}

int main()
{
    testFullReleaseClearsMetadataAndIsIdempotent();
    testEarlyReturnsPreservePartialMetadata();
    testActiveRingBackingIsStillPresent();
    testEachFieldHasItsOwnPresenceBit();
    return 0;
}
