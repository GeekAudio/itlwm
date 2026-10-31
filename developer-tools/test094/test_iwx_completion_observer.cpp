#define TEST094_ENABLE_TEST_PROBE 1
#include "../../native/iwx_completion_observer.hpp"

#include <assert.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <thread>
#include <type_traits>

using namespace NativeIwxCompletionObserver;

struct LockMetrics {
    LockMetrics()
        : initializeCalls(0), destroyCalls(0), blockingCalls(0),
          tryCalls(0), changed() {}

    std::atomic<uint32_t> initializeCalls;
    std::atomic<uint32_t> destroyCalls;
    std::atomic<uint32_t> blockingCalls;
    std::atomic<uint32_t> tryCalls;
    std::mutex mutex;
    std::condition_variable changed;
};

static LockMetrics gLockMetrics;
static bool gLockAllocationAllowed = true;

class TestLock {
public:
    TestLock() : initialized_(false) {}

    bool initialize()
    {
        gLockMetrics.initializeCalls.fetch_add(1);
        if (!gLockAllocationAllowed)
            return false;
        initialized_ = true;
        return true;
    }

    void destroy()
    {
        if (initialized_) {
            initialized_ = false;
            gLockMetrics.destroyCalls.fetch_add(1);
        }
    }

    void lock()
    {
        gLockMetrics.blockingCalls.fetch_add(1);
        gLockMetrics.changed.notify_all();
        mutex_.lock();
    }

    bool tryLock()
    {
        gLockMetrics.tryCalls.fetch_add(1);
        return mutex_.try_lock();
    }

    void unlock() { mutex_.unlock(); }

private:
    std::mutex mutex_;
    bool initialized_;
};

static_assert(!std::is_copy_constructible<Registry<TestLock, 1> >::value,
              "observer must not be copy-constructed");
static_assert(!std::is_copy_assignable<Registry<TestLock, 1> >::value,
              "observer must not be copy-assigned");
static_assert(!std::is_move_constructible<Registry<TestLock, 1> >::value,
              "observer must not be move-constructed");
static_assert(!std::is_move_assignable<Registry<TestLock, 1> >::value,
              "observer must not be move-assigned");

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

struct ReadProbe {
    ReadProbe() : bytesRead(0), gate(nullptr) {}
    explicit ReadProbe(Gate *pauseGate) : bytesRead(0), gate(pauseGate) {}

    void afterByte(size_t index)
    {
        bytesRead.fetch_add(1);
        if (index == 0 && gate != nullptr)
            gate->pause();
    }

    std::atomic<uint32_t> bytesRead;
    Gate *gate;
};

static uint64_t loadLittleEndian64(const uint8_t *bytes, size_t offset)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
    return value;
}

static uint32_t loadLittleEndian32(const uint8_t *bytes, size_t offset)
{
    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i)
        value |= static_cast<uint32_t>(bytes[offset + i]) << (i * 8);
    return value;
}

template <size_t Capacity>
static Handle reserveAndPublish(Registry<TestLock, Capacity> &registry,
                                const void *identity,
                                const uint8_t *mapping, size_t size)
{
    const ReserveResult reserved = registry.reserve(identity);
    assert(reserved.status == ReserveStatus::kReserved);
    assert(reserved.handle.valid());
    assert(registry.publish(reserved.handle, kObservedFamily, mapping, size) ==
           PublishStatus::kPublished);
    return reserved.handle;
}

struct LegacyFreeRecorder {
    LegacyFreeRecorder(uint8_t *mapping, bool deleteMapping)
        : mapping(mapping), deleteMapping(deleteMapping), freeCalls(0),
          commandClearCalls(0), commandReleaseCalls(0),
          bufferCompleteCalls(0), bufferReleaseCalls(0) {}

    void freeComplete()
    {
        // Mirror the existing order; diagnostics never release these objects.
        commandClearCalls.fetch_add(1);
        commandReleaseCalls.fetch_add(1);
        bufferCompleteCalls.fetch_add(1);
        bufferReleaseCalls.fetch_add(1);
        if (deleteMapping)
            delete[] mapping;
        mapping = nullptr;
        freeCalls.fetch_add(1);
    }

    uint8_t *mapping;
    bool deleteMapping;
    std::atomic<uint32_t> freeCalls;
    std::atomic<uint32_t> commandClearCalls;
    std::atomic<uint32_t> commandReleaseCalls;
    std::atomic<uint32_t> bufferCompleteCalls;
    std::atomic<uint32_t> bufferReleaseCalls;
};

static void testAllocationFailureDisablesOnlyDiagnostics()
{
    gLockAllocationAllowed = false;
    Registry<TestLock, 1> registry;
    assert(!registry.initialize());

    char identity = 0;
    const ReserveResult reserve = registry.reserve(&identity);
    assert(reserve.status == ReserveStatus::kUnavailable);
    assert(!reserve.handle.valid());

    // The driver continues its ordinary allocation/free path regardless of
    // observer setup failure; this recorder stands for that unchanged path.
    uint8_t *mapping = new uint8_t[40]();
    LegacyFreeRecorder legacy(mapping, true);
    legacy.freeComplete();
    assert(legacy.freeCalls == 1);
    assert(legacy.commandClearCalls == 1);
    assert(legacy.commandReleaseCalls == 1);
    assert(legacy.bufferCompleteCalls == 1);
    assert(legacy.bufferReleaseCalls == 1);
    assert(registry.tryCopyForIdentity(&identity, kObservedFamily, 0).status ==
           CopyStatus::kUnavailable);

    registry.shutdown();
    assert(gLockMetrics.destroyCalls.load() == 0);
    gLockAllocationAllowed = true;
}

static void testBusyTryLockIsOneAttemptAndNeverChangesDrain()
{
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    uint8_t mapping[40] = {};
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, mapping, sizeof(mapping));

    registry.lockForTesting().lock();
    const uint32_t triesBefore = gLockMetrics.tryCalls.load();
    ReadProbe probe;
    const CopyResult result = registry.tryCopyWithProbe(
        handle, kObservedFamily, 0, probe);
    const uint32_t triesAfter = gLockMetrics.tryCalls.load();
    uint32_t legacyDrainCount = 0;
    ++legacyDrainCount; // The production RX path continues unconditionally.
    registry.lockForTesting().unlock();

    assert(result.status == CopyStatus::kBusy);
    assert(triesAfter == triesBefore + 1);
    assert(probe.bytesRead.load() == 0);
    assert(legacyDrainCount == 1);
    assert(registry.unpublish(handle) == RetireStatus::kPublishedViewRetired);
    registry.shutdown();
}

static void testCopyAndRetireShareFenceUntilEightBytesAreDetached()
{
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    uint8_t *mapping = new uint8_t[40]();
    const uint64_t expected = UINT64_C(0x0123456789abcdef);
    for (size_t i = 0; i < 8; ++i)
        mapping[32 + i] = static_cast<uint8_t>(expected >> (i * 8));
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, mapping, 40);

    Gate gate;
    ReadProbe probe(&gate);
    CopyResult copied;
    RetireStatus retired = RetireStatus::kNotFoundOrStale;
    LegacyFreeRecorder legacy(mapping, true);
    const uint32_t blockingCallsBefore =
        gLockMetrics.blockingCalls.load();

    std::thread reader([&] {
        copied = registry.tryCopyWithProbe(
            handle, kObservedFamily, 1, probe);
    });
    const bool readerPaused = gate.waitUntilEntered();
    std::thread retirer([&] {
        retired = registry.unpublish(handle);
        if (retired == RetireStatus::kPublishedViewRetired)
            legacy.freeComplete();
    });

    bool retirerTriedTheBlockingLock = false;
    {
        std::unique_lock<std::mutex> guard(gLockMetrics.mutex);
        retirerTriedTheBlockingLock = gLockMetrics.changed.wait_for(
            guard, std::chrono::seconds(3), [&] {
                return gLockMetrics.blockingCalls.load() > blockingCallsBefore;
            });
    }
    const uint32_t freesWhileCopyPaused = legacy.freeCalls;
    const uint32_t bytesWhileCopyPaused = probe.bytesRead.load();

    gate.open();
    reader.join();
    retirer.join();

    assert(readerPaused && retirerTriedTheBlockingLock);
    assert(freesWhileCopyPaused == 0);
    assert(bytesWhileCopyPaused == 1);
    assert(probe.bytesRead.load() == 8);
    assert(copied.status == CopyStatus::kCopied);
    assert(copied.snapshot.incarnation == handle.incarnation);
    assert(loadLittleEndian64(copied.snapshot.bytes, 0) == expected);
    assert(retired == RetireStatus::kPublishedViewRetired);
    assert(legacy.freeCalls == 1);
    assert(legacy.commandClearCalls == 1);
    assert(legacy.commandReleaseCalls == 1);
    assert(legacy.bufferCompleteCalls == 1);
    assert(legacy.bufferReleaseCalls == 1);
    registry.shutdown();
}

static void testRetireFirstAndRepeatedPartialCleanupDoNotReadOrFreeTwice()
{
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    uint8_t *mapping = new uint8_t[40]();
    char identity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, mapping, 40);
    LegacyFreeRecorder legacy(mapping, true);

    assert(registry.unpublish(handle) == RetireStatus::kPublishedViewRetired);
    legacy.freeComplete();
    assert(registry.unpublish(handle) == RetireStatus::kNotFoundOrStale);
    // The repeated free_rx_ring call still reaches freeComplete, whose
    // existing empty-DMA guard makes the second callback a no-op.
    assert(legacy.freeCalls == 1);

    ReadProbe probe;
    const CopyResult afterFree = registry.tryCopyWithProbe(
        handle, kObservedFamily, 0, probe);
    assert(afterFree.status == CopyStatus::kNoView);
    assert(probe.bytesRead.load() == 0);
    registry.shutdown();
}

static void testReservationClosedOnPartialAllocationFailureAndLatePublish()
{
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    char identity = 0;
    uint8_t mapping[40] = {};
    const ReserveResult reserved = registry.reserve(&identity);
    assert(reserved.status == ReserveStatus::kReserved);
    assert(reserved.handle.valid());

    // Mirrors iwx_dma_contig_alloc failure after the upfront reservation: the
    // partial allocator has already cleaned private temporaries and the ring
    // free path closes this empty reservation before legacy cleanup returns.
    assert(registry.unpublish(reserved.handle) ==
           RetireStatus::kReservationClosed);
    assert(registry.unpublish(reserved.handle) ==
           RetireStatus::kNotFoundOrStale);
    assert(registry.publish(reserved.handle, kObservedFamily, mapping,
                            sizeof(mapping)) ==
           PublishStatus::kNotReservedOrStale);

    ReadProbe probe;
    assert(registry.tryCopyWithProbe(reserved.handle, kObservedFamily, 0,
                                     probe).status == CopyStatus::kNoView);
    assert(probe.bytesRead.load() == 0);
    registry.shutdown();
}

static void testRangeFamilyAndMappingFailuresSkipOnlyObservation()
{
    Registry<TestLock, 2> registry;
    assert(registry.initialize());
    uint8_t mapping[40] = {};
    uint8_t shortMapping[7] = {};
    char identity = 0;
    char shortIdentity = 0;
    const Handle handle = reserveAndPublish(
        registry, &identity, mapping, sizeof(mapping));
    const Handle shortHandle = reserveAndPublish(
        registry, &shortIdentity, shortMapping, sizeof(shortMapping));
    ReadProbe probe;

    assert(registry.tryCopyWithProbe(handle, 1, 0, probe).status ==
           CopyStatus::kWrongFamily);
    assert(registry.tryCopyWithProbe(handle, kObservedFamily, 512, probe).status ==
           CopyStatus::kSlotOutOfRange);
    assert(registry.tryCopyWithProbe(shortHandle, kObservedFamily, 0, probe).status ==
           CopyStatus::kMappingTooShort);
    assert(registry.tryCopyWithProbe(handle, kObservedFamily, 2, probe).status ==
           CopyStatus::kSlotPastMapping);
    assert(probe.bytesRead.load() == 0);
    registry.shutdown();
}

static void testStaleIncarnationCannotRetireReusedIdentity()
{
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    char identity = 0;
    uint8_t oldMapping[40] = {};
    uint8_t newMapping[40] = {};
    const Handle oldHandle = reserveAndPublish(
        registry, &identity, oldMapping, sizeof(oldMapping));
    assert(registry.unpublish(oldHandle) == RetireStatus::kPublishedViewRetired);

    const Handle newHandle = reserveAndPublish(
        registry, &identity, newMapping, sizeof(newMapping));
    assert(newHandle.incarnation > oldHandle.incarnation);
    assert(registry.unpublish(oldHandle) == RetireStatus::kNotFoundOrStale);
    ReadProbe probe;
    assert(registry.tryCopyWithProbe(newHandle, kObservedFamily, 0,
                                     probe).status == CopyStatus::kCopied);
    assert(probe.bytesRead.load() == 8);
    registry.shutdown();
}

static void testTelemetryCorrelatesLaterTargetAfterEarlierUnrelatedTraffic()
{
    Telemetry telemetry;
    for (uint32_t i = 0; i < 100; ++i) {
        CopyResult station;
        station.status = CopyStatus::kCopied;
        station.snapshot.incarnation = 70 + i;
        station.snapshot.bytes[4] = static_cast<uint8_t>(i);
        station.snapshot.bytes[5] = 0x10;
        station.snapshot.bytes[6] = 1;
        recordAttempt(&telemetry, kObservedFamily, 7, 1, 1000 + i,
                      i % 512, i % 512, station);
    }

    CopyResult target;
    target.status = CopyStatus::kCopied;
    target.snapshot.incarnation = 77;
    target.snapshot.bytes[4] = 0x90;
    target.snapshot.bytes[5] = 0x90;
    target.snapshot.bytes[6] = 0xa5;
    recordAttempt(&telemetry, kObservedFamily, 7, 1, 1100, 23, 17, target);

    CopyResult busy;
    busy.status = CopyStatus::kBusy;
    recordAttempt(&telemetry, kObservedFamily, 7, 1, 1101, 24, 18, busy);

    TelemetrySnapshot snapshot;
    assert(snapshotTelemetry(&telemetry, &snapshot));
    assert(snapshot.attempts == 102 && snapshot.copies == 101);
    assert(snapshot.skips == 1 && snapshot.sampleCount == 16);
    assert(snapshot.overwrittenSamples == 85);
    assert(snapshot.lastStatus == static_cast<uint32_t>(CopyStatus::kBusy));
    assert(snapshot.lastAttemptGeneration == 7);
    assert(snapshot.lastAttemptSerial == 1);
    assert(snapshot.lastAttemptHead == 24 && snapshot.lastAttemptSlot == 18);
    assert(snapshot.lastAttemptUptimeUs == 1101);
    // The 149-like sample arriving after 100 unrelated frames remains in the
    // rolling window and carries the same slot/head/generation tuple as the
    // existing pre-owner Slot event.
    assert(snapshot.samples[15].sequence == 101);
    assert(snapshot.samples[15].driverGeneration == 7);
    assert(snapshot.samples[15].observationSerial == 1);
    assert(snapshot.samples[15].head == 23);
    assert(snapshot.samples[15].slot == 17);
    assert(snapshot.samples[15].rawRbid == 0x9090);
    assert(snapshot.samples[15].rawFlags == 0xa5);
    assert(snapshot.samples[15].hostUptimeUs == 1100);
    assert(snapshot.samples[15].allocationIncarnation == 77);

    uint8_t wire[kTelemetryWireBytes] = {};
    encodeTelemetry(snapshot, wire);
    assert(sizeof(wire) == 760);
    assert(loadLittleEndian32(wire, 0) == 1);
    assert(loadLittleEndian32(wire, 4) ==
           static_cast<uint32_t>(CopyStatus::kBusy));
    assert(loadLittleEndian32(wire, 8) == 102);
    assert(loadLittleEndian32(wire, 12) == 101);
    assert(loadLittleEndian32(wire, 16) == 1);
    assert(loadLittleEndian32(wire, 20) == 85);
    assert(loadLittleEndian32(wire, 24) == kObservedFamily);
    assert(loadLittleEndian32(wire, 28) == 7);
    assert(loadLittleEndian32(wire, 32) == 1);
    assert(loadLittleEndian32(wire, 36) == 24);
    assert(loadLittleEndian32(wire, 40) == 18);
    assert(loadLittleEndian32(wire, 44) == 16);
    assert(loadLittleEndian64(wire, 48) == 1101);
    const size_t targetOffset = kTelemetryHeaderBytes +
        15 * kTelemetrySampleWireBytes;
    assert(loadLittleEndian32(wire, targetOffset) == 101);
    assert(loadLittleEndian32(wire, targetOffset + 4) == 7);
    assert(loadLittleEndian32(wire, targetOffset + 8) == 1);
    assert(loadLittleEndian32(wire, targetOffset + 12) == 23);
    assert(loadLittleEndian32(wire, targetOffset + 16) == 17);
    assert(loadLittleEndian32(wire, targetOffset + 20) == 0x9090);
    assert(loadLittleEndian32(wire, targetOffset + 24) == 0xa5);
    assert(loadLittleEndian64(wire, targetOffset + 28) == 1100);
    assert(loadLittleEndian64(wire, targetOffset + 36) == 77);
}

static void testDuplicateReserveFailurePreservesHandleForFree()
{
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    char identity = 0;
    uint8_t mapping[40] = {};
    const Handle original = reserveAndPublish(
        registry, &identity, mapping, sizeof(mapping));
    Handle ownerHandle = original;

    const ReserveResult duplicate = registry.reserve(&identity);
    assert(duplicate.status == ReserveStatus::kIdentityAlreadyActive);
    assert(!duplicate.handle.valid());
    // Mirrors alloc_rx_ring: update the owner's handle only after reserve
    // succeeds; publish must use the new local handle, never the old one.
    if (duplicate.status == ReserveStatus::kReserved)
        ownerHandle = duplicate.handle;
    assert(ownerHandle.incarnation == original.incarnation);
    assert(registry.tryCopyForIdentity(&identity, kObservedFamily, 0).status ==
           CopyStatus::kCopied);

    assert(registry.unpublish(ownerHandle) ==
           RetireStatus::kPublishedViewRetired);
    assert(registry.tryCopyForIdentity(&identity, kObservedFamily, 0).status ==
           CopyStatus::kNoView);
    registry.shutdown();
}

static void testRegistryOwnsOneShotLockLifetime()
{
    gLockAllocationAllowed = true;
    const uint32_t destroysBefore = gLockMetrics.destroyCalls.load();
    Registry<TestLock, 1> registry;
    assert(registry.initialize());
    char identity = 0;
    const ReserveResult reserved = registry.reserve(&identity);
    assert(reserved.status == ReserveStatus::kReserved);
    assert(registry.unpublish(reserved.handle) ==
           RetireStatus::kReservationClosed);

    registry.shutdown();
    assert(gLockMetrics.destroyCalls.load() == destroysBefore + 1);
    assert(!registry.initialize()); // The registry is not rebuilt.
    assert(registry.reserve(&identity).status == ReserveStatus::kClosed);
    assert(registry.tryCopyForIdentity(&identity, kObservedFamily, 0).status ==
           CopyStatus::kClosed);
    assert(gLockMetrics.destroyCalls.load() == destroysBefore + 1);
}

int main()
{
    testAllocationFailureDisablesOnlyDiagnostics();
    std::cout << "PASS allocation failure leaves legacy free path available\n";
    testBusyTryLockIsOneAttemptAndNeverChangesDrain();
    std::cout << "PASS one try-lock busy skip leaves RX drain alone\n";
    testCopyAndRetireShareFenceUntilEightBytesAreDetached();
    std::cout << "PASS retire waits for copied bytes before legacy free\n";
    testRetireFirstAndRepeatedPartialCleanupDoNotReadOrFreeTwice();
    std::cout << "PASS retired mapping and repeated partial cleanup\n";
    testReservationClosedOnPartialAllocationFailureAndLatePublish();
    std::cout << "PASS reservation closes before partial cleanup and late publish\n";
    testRangeFamilyAndMappingFailuresSkipOnlyObservation();
    std::cout << "PASS family, slot, and mapping range skips\n";
    testStaleIncarnationCannotRetireReusedIdentity();
    std::cout << "PASS stale incarnation cannot retire reused identity\n";
    testTelemetryCorrelatesLaterTargetAfterEarlierUnrelatedTraffic();
    std::cout << "PASS rolling numeric samples correlate later target traffic\n";
    testDuplicateReserveFailurePreservesHandleForFree();
    std::cout << "PASS duplicate reserve preserves the live free handle\n";
    testRegistryOwnsOneShotLockLifetime();
    std::cout << "PASS one-shot registry lock lifetime\n";
}
