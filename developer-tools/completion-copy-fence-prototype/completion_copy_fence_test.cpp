#include "completion_copy_fence.hpp"

#include <assert.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include <type_traits>

using namespace Test093CompletionCopyFence;

class TestLock {
public:
    TestLock() : lockCalls_(0) {}

    bool tryLock() { return mutex_.try_lock(); }
    void unlock() { mutex_.unlock(); }

    void lock()
    {
        {
            std::lock_guard<std::mutex> guard(metricsMutex_);
            ++lockCalls_;
            metricsChanged_.notify_all();
        }
        mutex_.lock();
    }

    int lockCalls() const
    {
        std::lock_guard<std::mutex> guard(metricsMutex_);
        return lockCalls_;
    }

    bool waitForLockCalls(int expected)
    {
        std::unique_lock<std::mutex> guard(metricsMutex_);
        return metricsChanged_.wait_for(
            guard, std::chrono::seconds(3),
            [this, expected] { return lockCalls_ >= expected; });
    }

private:
    std::mutex mutex_;
    mutable std::mutex metricsMutex_;
    std::condition_variable metricsChanged_;
    int lockCalls_;
};

static_assert(!std::is_copy_constructible<Registry<TestLock, 4> >::value,
              "registry must not be copy-constructed");
static_assert(!std::is_copy_assignable<Registry<TestLock, 4> >::value,
              "registry must not be copy-assigned");
static_assert(!std::is_move_constructible<Registry<TestLock, 4> >::value,
              "registry must not be move-constructed");
static_assert(!std::is_move_assignable<Registry<TestLock, 4> >::value,
              "registry must not be move-assigned");

class Gate {
public:
    Gate() : entered_(false), open_(false) {}

    void pause()
    {
        std::unique_lock<std::mutex> guard(mutex_);
        entered_ = true;
        changed_.notify_all();
        changed_.wait(guard, [this] { return open_; });
    }

    bool waitUntilEntered()
    {
        std::unique_lock<std::mutex> guard(mutex_);
        return changed_.wait_for(guard, std::chrono::seconds(3),
                                [this] { return entered_; });
    }

    void open()
    {
        std::lock_guard<std::mutex> guard(mutex_);
        open_ = true;
        changed_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable changed_;
    bool entered_;
    bool open_;
};

struct ReadTrace {
    ReadTrace() : sequence(0), sourceBytes(0)
    {
        for (size_t i = 0; i < kCompletionBytes; ++i)
            byteSequence[i].store(0);
    }

    uint64_t nextSequence() { return sequence.fetch_add(1) + 1; }

    std::atomic<uint64_t> sequence;
    std::atomic<int> sourceBytes;
    std::atomic<uint64_t> byteSequence[kCompletionBytes];
};

class CountingProbe {
public:
    CountingProbe(ReadTrace &trace, Gate *gate = nullptr)
        : trace_(trace), gate_(gate) {}

    void afterByte(size_t index)
    {
        trace_.byteSequence[index].store(trace_.nextSequence());
        trace_.sourceBytes.fetch_add(1);
        if (index == 0 && gate_ != nullptr)
            gate_->pause();
    }

private:
    ReadTrace &trace_;
    Gate *gate_;
};

// Mirrors the fixed source's freeComplete callbacks: command clear/release,
// then buffer complete/release. The backing allocation is deleted at step 4.
class ReleaseRecorder {
public:
    ReleaseRecorder(TestLock &lock, ReadTrace &trace, uint8_t *allocation,
                    bool deleteAllocation = true)
        : freeCalls(0), commandClearCount(0), commandReleaseCount(0),
          bufferCompleteCount(0), bufferReleaseCount(0), firstFreeSequence(0),
          lock_(lock), trace_(trace), allocation_(allocation),
          deleteAllocation_(deleteAllocation)
    {
        for (size_t i = 0; i < 4; ++i) {
            stepCount[i].store(0);
            stepSequence[i].store(0);
        }
    }

    void releaseComplete()
    {
        const bool lockWasFree = lock_.tryLock();
        assert(lockWasFree && "freeComplete callback must run after unlock");
        if (lockWasFree)
            lock_.unlock();

        commandClearCount.fetch_add(1);
        recordStep(0);
        commandReleaseCount.fetch_add(1);
        recordStep(1);
        bufferCompleteCount.fetch_add(1);
        recordStep(2);
        bufferReleaseCount.fetch_add(1);
        recordStep(3);
        if (deleteAllocation_)
            delete[] allocation_;
        allocation_ = nullptr;
        freeCalls.fetch_add(1);
    }

    std::atomic<int> freeCalls;
    std::atomic<int> commandClearCount;
    std::atomic<int> commandReleaseCount;
    std::atomic<int> bufferCompleteCount;
    std::atomic<int> bufferReleaseCount;
    std::atomic<int> stepCount[4];
    std::atomic<uint64_t> stepSequence[4];
    std::atomic<uint64_t> firstFreeSequence;

private:
    void recordStep(size_t index)
    {
        const uint64_t order = trace_.nextSequence();
        stepSequence[index].store(order);
        stepCount[index].fetch_add(1);
        if (index == 0)
            firstFreeSequence.store(order);
    }

    TestLock &lock_;
    ReadTrace &trace_;
    uint8_t *allocation_;
    bool deleteAllocation_;
};

static void assertOneFreeInSourceOrder(const ReleaseRecorder &release)
{
    assert(release.freeCalls.load() == 1);
    assert(release.commandClearCount.load() == 1);
    assert(release.commandReleaseCount.load() == 1);
    assert(release.bufferCompleteCount.load() == 1);
    assert(release.bufferReleaseCount.load() == 1);
    for (size_t i = 0; i < 4; ++i)
        assert(release.stepCount[i].load() == 1);
    assert(release.stepSequence[0].load() < release.stepSequence[1].load());
    assert(release.stepSequence[1].load() < release.stepSequence[2].load());
    assert(release.stepSequence[2].load() < release.stepSequence[3].load());
}

static void storeLittleEndian(uint8_t *bytes, size_t offset, uint64_t value)
{
    for (size_t i = 0; i < kCompletionBytes; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

template <size_t Capacity>
static Handle reserveAndPublish(Registry<TestLock, Capacity> &registry,
                                const void *identity, uint32_t family,
                                const uint8_t *bytes, size_t size)
{
    const ReserveResult reserved = registry.reserve(identity);
    assert(reserved.status == ReserveStatus::kReserved);
    assert(reserved.handle.valid());
    assert(registry.publish(reserved.handle, family, bytes, size) ==
           PublishStatus::kPublished);
    return reserved.handle;
}

static bool retireAndRelease(Registry<TestLock, 4> &registry,
                             const Handle &handle,
                             ReleaseRecorder &release)
{
    const RetireStatus status = registry.unpublish(handle);
    if (status != RetireStatus::kPublishedViewRetired &&
        status != RetireStatus::kReservationClosed)
        return false;
    release.releaseComplete();
    return true;
}

static void testCopyHoldsFenceUntilEightBytesAreDetached()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    Gate gate;
    const uint64_t expected = UINT64_C(0x0123456789abcdef);
    uint8_t *mapping = new uint8_t[40]();
    storeLittleEndian(mapping, 32, expected);
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, kObservedFamily, mapping, 40);

    CountingProbe probe(trace, &gate);
    CopyResult copy;
    RetireStatus retired = RetireStatus::kNotFoundOrStale;
    ReleaseRecorder release(lock, trace, mapping);
    const int baseLockCalls = lock.lockCalls();

    std::thread reader([&] {
        copy = registry.tryCopyWithProbe(handle, 1, probe);
    });
    const bool readerPaused = gate.waitUntilEntered();
    const bool firstByteObserved = trace.sourceBytes.load() == 1;

    std::thread retirer([&] {
        retired = registry.unpublish(handle);
        if (retired == RetireStatus::kPublishedViewRetired)
            release.releaseComplete();
    });
    const bool retireTriedLock = lock.waitForLockCalls(baseLockCalls + 1);
    const int freesWhileCopyPaused = release.freeCalls.load();
    const int bytesWhileCopyPaused = trace.sourceBytes.load();

    gate.open();
    reader.join();
    retirer.join();

    assert(readerPaused && firstByteObserved && retireTriedLock);
    assert(freesWhileCopyPaused == 0);
    assert(bytesWhileCopyPaused == 1);
    assert(copy.status == CopyStatus::kCopied);
    assert(trace.sourceBytes.load() == 8);
    assert(decodeLittleEndian(copy.snapshot) == expected);
    assert(retired == RetireStatus::kPublishedViewRetired);
    assertOneFreeInSourceOrder(release);
    for (size_t i = 0; i < kCompletionBytes; ++i)
        assert(trace.byteSequence[i].load() <
               release.firstFreeSequence.load());
}

static void testRetireWinsThenReaderDoesNotTouchMapping()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    uint8_t *mapping = new uint8_t[40]();
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, kObservedFamily, mapping, 40);
    ReleaseRecorder release(lock, trace, mapping);

    assert(retireAndRelease(registry, handle, release));
    CountingProbe probe(trace);
    const CopyResult copy = registry.tryCopyWithProbe(
        handle, 0, probe);

    assert(copy.status == CopyStatus::kNoView);
    assert(trace.sourceBytes.load() == 0);
    assertOneFreeInSourceOrder(release);
}

static void testFreeClosesReservationBeforeLatePublish()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    uint8_t mapping[40] = {};
    char identity = 0;
    const ReserveResult reserved = registry.reserve(&identity);
    assert(reserved.status == ReserveStatus::kReserved);
    assert(reserved.handle.valid());

    // Keep test storage allocated after recording the legacy free sequence so
    // a broken late publish would be observable as an actual counted read.
    ReleaseRecorder release(lock, trace, mapping, false);
    assert(registry.unpublish(reserved.handle) ==
           RetireStatus::kReservationClosed);
    release.releaseComplete();

    assert(registry.publish(reserved.handle, kObservedFamily, mapping,
                            sizeof(mapping)) ==
           PublishStatus::kNotReservedOrStale);
    CountingProbe probe(trace);
    const CopyResult copy = registry.tryCopyWithProbe(
        reserved.handle, 0, probe);
    assert(copy.status == CopyStatus::kNoView);
    assert(trace.sourceBytes.load() == 0);
    assertOneFreeInSourceOrder(release);
}

static void testBusyRegistryOnlySkips()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    uint8_t mapping[40] = {};
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, kObservedFamily, mapping, sizeof(mapping));

    Gate gate;
    std::thread holder([&] {
        lock.lock();
        gate.pause();
        lock.unlock();
    });
    const bool lockHeld = gate.waitUntilEntered();
    CountingProbe probe(trace);
    const CopyResult copy = registry.tryCopyWithProbe(
        handle, 0, probe);
    gate.open();
    holder.join();

    assert(lockHeld);
    assert(copy.status == CopyStatus::kBusy);
    assert(trace.sourceBytes.load() == 0);
}

static void testCapacityFullOnlySkipsNewView()
{
    TestLock lock;
    Registry<TestLock, 1> registry(lock);
    ReadTrace trace;
    uint8_t first[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    char firstIdentity = 0;
    char secondIdentity = 0;
    const Handle firstHandle = reserveAndPublish(
        registry, &firstIdentity, kObservedFamily, first, sizeof(first));
    const ReserveResult full = registry.reserve(&secondIdentity);
    assert(full.status == ReserveStatus::kCapacityFull);
    assert(!full.handle.valid());

    CountingProbe probe(trace);
    const CopyResult skipped = registry.tryCopyWithProbe(full.handle, 0, probe);
    const CopyResult retained = registry.tryCopyWithProbe(
        firstHandle, 0, probe);
    assert(skipped.status == CopyStatus::kNoView);
    assert(retained.status == CopyStatus::kCopied);
    assert(trace.sourceBytes.load() == 8);
    assert(decodeLittleEndian(retained.snapshot) ==
           UINT64_C(0x0807060504030201));
}

static void testDuplicateReservePreservesOldHandle()
{
    TestLock lock;
    Registry<TestLock, 2> registry(lock);
    ReadTrace trace;
    uint8_t oldMapping[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t rejectedMapping[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    char identity = 0;
    const Handle oldHandle = reserveAndPublish(
        registry, &identity, kObservedFamily, oldMapping, sizeof(oldMapping));
    const ReserveResult duplicate = registry.reserve(&identity);
    assert(duplicate.status == ReserveStatus::kIdentityAlreadyActive);
    assert(!duplicate.handle.valid());
    assert(registry.publish(duplicate.handle, kObservedFamily,
                            rejectedMapping, sizeof(rejectedMapping)) ==
           PublishStatus::kNotReservedOrStale);

    CountingProbe probe(trace);
    const CopyResult retained = registry.tryCopyWithProbe(
        oldHandle, 0, probe);
    assert(retained.status == CopyStatus::kCopied);
    assert(decodeLittleEndian(retained.snapshot) ==
           UINT64_C(0x0101010101010101));
    assert(trace.sourceBytes.load() == 8);
    assert(registry.unpublish(oldHandle) ==
           RetireStatus::kPublishedViewRetired);
}

static void testFamilySlotAndLengthFailuresOnlySkip()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    uint8_t bytes[40] = {};
    uint8_t shortBytes[7] = {};
    char wrongFamilyIdentity = 0;
    char validIdentity = 0;
    char shortIdentity = 0;
    const Handle wrongFamily = reserveAndPublish(
        registry, &wrongFamilyIdentity, 1, bytes, sizeof(bytes));
    const Handle valid = reserveAndPublish(
        registry, &validIdentity, kObservedFamily, bytes, sizeof(bytes));
    const Handle shortView = reserveAndPublish(
        registry, &shortIdentity, kObservedFamily, shortBytes,
        sizeof(shortBytes));
    CountingProbe probe(trace);

    assert(registry.tryCopyWithProbe(wrongFamily, 0, probe).status ==
           CopyStatus::kWrongFamily);
    assert(registry.tryCopyWithProbe(valid, 512, probe).status ==
           CopyStatus::kSlotOutOfRange);
    assert(registry.tryCopyWithProbe(shortView, 0, probe).status ==
           CopyStatus::kMappingTooShort);
    assert(registry.tryCopyWithProbe(valid, 2, probe).status ==
           CopyStatus::kSlotPastMapping);
    assert(trace.sourceBytes.load() == 0);
}

static void testRepeatedRetireIsIdempotent()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    uint8_t *mapping = new uint8_t[40]();
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, kObservedFamily, mapping, 40);
    ReleaseRecorder release(lock, trace, mapping);

    assert(retireAndRelease(registry, handle, release));
    assert(!retireAndRelease(registry, handle, release));
    assertOneFreeInSourceOrder(release);
}

static void testOldIncarnationCannotRetireReusedIdentity()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    char reusedIdentity = 0;
    uint8_t *oldMapping = new uint8_t[40]();
    storeLittleEndian(oldMapping, 32, UINT64_C(0x1111111111111111));
    const Handle oldHandle = reserveAndPublish(
        registry, &reusedIdentity, kObservedFamily, oldMapping, 40);
    ReleaseRecorder oldRelease(lock, trace, oldMapping);
    assert(retireAndRelease(registry, oldHandle, oldRelease));

    uint8_t *newMapping = new uint8_t[40]();
    const uint64_t expected = UINT64_C(0xfedcba9876543210);
    storeLittleEndian(newMapping, 32, expected);
    const Handle newHandle = reserveAndPublish(
        registry, &reusedIdentity, kObservedFamily, newMapping, 40);
    ReleaseRecorder newRelease(lock, trace, newMapping);
    assert(newHandle.incarnation > oldHandle.incarnation);

    assert(registry.unpublish(oldHandle) == RetireStatus::kNotFoundOrStale);
    assert(newRelease.freeCalls.load() == 0);
    CountingProbe probe(trace);
    const CopyResult copy = registry.tryCopyWithProbe(newHandle, 1, probe);
    assert(copy.status == CopyStatus::kCopied);
    assert(decodeLittleEndian(copy.snapshot) == expected);
    assert(trace.sourceBytes.load() == 8);
    assertOneFreeInSourceOrder(oldRelease);
    assert(newRelease.freeCalls.load() == 0);

    assert(retireAndRelease(registry, newHandle, newRelease));
    assertOneFreeInSourceOrder(newRelease);
}

static void testOrdinaryResetDoesNotMintFreshIncarnation()
{
    TestLock lock;
    Registry<TestLock, 4> registry(lock);
    ReadTrace trace;
    uint8_t mapping[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    uint8_t statusArea[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint32_t ringCursor = 73;
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, kObservedFamily, mapping, sizeof(mapping));

    // Mirrors ordinary iwx_reset_rx_ring: reset cursor/status only; no view
    // unpublish, free, or fresh allocation incarnation is implied.
    ringCursor = 0;
    for (size_t i = 0; i < sizeof(statusArea); ++i)
        statusArea[i] = 0;

    CountingProbe probe(trace);
    const CopyResult copy = registry.tryCopyWithProbe(handle, 0, probe);
    assert(ringCursor == 0);
    for (size_t i = 0; i < sizeof(statusArea); ++i)
        assert(statusArea[i] == 0);
    assert(copy.status == CopyStatus::kCopied);
    assert(decodeLittleEndian(copy.snapshot) ==
           UINT64_C(0x0102030405060708));
    assert(trace.sourceBytes.load() == 8);
}

int main()
{
    testCopyHoldsFenceUntilEightBytesAreDetached();
    std::cout << "PASS copy/unpublish interleaving and free order\n";
    testRetireWinsThenReaderDoesNotTouchMapping();
    std::cout << "PASS retire-first no-read\n";
    testFreeClosesReservationBeforeLatePublish();
    std::cout << "PASS free-before-publish closes reservation\n";
    testBusyRegistryOnlySkips();
    std::cout << "PASS try-lock busy skip\n";
    testCapacityFullOnlySkipsNewView();
    std::cout << "PASS capacity-full skip\n";
    testDuplicateReservePreservesOldHandle();
    std::cout << "PASS duplicate reservation preserves active handle\n";
    testFamilySlotAndLengthFailuresOnlySkip();
    std::cout << "PASS family/slot/length skips\n";
    testRepeatedRetireIsIdempotent();
    std::cout << "PASS repeated retire idempotence\n";
    testOldIncarnationCannotRetireReusedIdentity();
    std::cout << "PASS reused identity incarnation fence\n";
    testOrdinaryResetDoesNotMintFreshIncarnation();
    std::cout << "PASS ordinary reset retains incarnation\n";
}
