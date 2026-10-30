// SPDX-License-Identifier: GPL-2.0-only
#include "../rx_preowner_observation.hpp"

#include <assert.h>
#include <atomic>
#include <stdint.h>
#include <thread>
#include <vector>

using namespace NativeRxPreOwner;

static Event makeEvent(uint64_t nowUs, uint32_t generation,
                       EventKind kind = EventKind::MpduEntry)
{
    Event event{};
    event.nowUs = nowUs;
    event.generation = generation;
    event.kind = kind;
    event.rxClass = RxClass::Unknown;
    event.ownerReason = OwnerReason::Qualified;
    return event;
}

static void testOneShotAndEmptySnapshot()
{
    Observer observer;
    assert(!observer.enabled());
    assert(observer.begin(1000, 41));
    assert(observer.enabled());
    assert(!observer.begin(2000, 42));

    Snapshot active{};
    assert(observer.snapshot(1100, &active));
    assert(active.active == 1 && active.closed == 0);
    assert(active.captureSerial == 1 && active.driverGeneration == 41);
    assert(active.beginUs == 1000 && active.deadlineUs == 4001000);
    assert(active.endUs == 0 && active.totalEvents == 0);
    assert(validateSnapshot(active));

    assert(observer.close(1200, CloseReason::Stop));
    assert(!observer.enabled());
    assert(!observer.record(makeEvent(1201, 41)));
    Snapshot closed{};
    assert(observer.snapshot(1300, &closed));
    assert(closed.closed == 1 && closed.active == 0);
    assert(closed.endUs == 1200 && closed.closeReason == CloseReason::Stop);
    assert(closed.totalEvents == 0);
    assert(validateSnapshot(closed));
    assert(!observer.begin(5000, 41));
}

static void testEventKindsAndSeparateQueueNamespaces()
{
    Observer observer;
    assert(observer.begin(10000, 7));
    const EventKind kinds[] = {
        EventKind::Irq, EventKind::Drain, EventKind::Slot,
        EventKind::NotificationSeen, EventKind::HeaderRejected,
        EventKind::LengthRejected, EventKind::NotificationValidated,
        EventKind::MpduDispatch, EventKind::AddbufFailed,
        EventKind::CopyFailed, EventKind::MpduEntry,
        EventKind::OwnerRecorderAccepted, EventKind::OwnerRecorderRejected
    };
    uint64_t time = 10001;
    for (EventKind kind : kinds) {
        Event event = makeEvent(time++, 7, kind);
        if (kind == EventKind::Irq) {
            event.irqSource = IrqSource::Msix;
            event.irqCause = 0x100;
        }
        if (kind == EventKind::NotificationSeen ||
            kind == EventKind::HeaderRejected ||
            kind == EventKind::LengthRejected ||
            kind == EventKind::NotificationValidated) {
            event.notificationCode = 0x0305;
            event.notificationQidPresent = 1;
            event.notificationQid = 13;
            event.notificationIndexPresent = 1;
            event.notificationIndex = 0x123;
        }
        if (kind == EventKind::Slot || kind == EventKind::MpduDispatch ||
            kind == EventKind::MpduEntry) {
            event.physicalRingPresent = 1;
            event.physicalRing = 0;
            event.physicalSlotPresent = 1;
            event.physicalSlot = 6;
        }
        if (kind == EventKind::MpduEntry) {
            event.notificationQidPresent = 1;
            event.notificationQid = 13;
            event.notificationIndexPresent = 1;
            event.notificationIndex = 0x123;
        }
        if (kind == EventKind::MpduEntry) {
            event.rxClass = RxClass::Channel149;
            event.channelPresent = 1;
            event.channel = 149;
            event.ownerReason = OwnerReason::RocWindowNotQualified;
            event.payloadLen = 73;
            event.descSize = 48;
            event.mpduLengthPresent = 1;
            event.mpduLength = 96;
            event.rawStatusPresent = 1;
            event.rawStatus = 0x12345678;
            event.rawMacPhyIndexPresent = 1;
            event.rawMacPhyIndex = 0x41;
            event.macPhyDecodeModePresent = 1;
            event.macPhyDecodeMode = 2;
            event.macIndexPresent = 1;
            event.macIndex = 1;
            event.frameControlPresent = 1;
            event.frameControl = 0x0008;
            event.sequenceControlPresent = 1;
            event.sequenceControl = 0x0200;
            event.gp2OnAirRisePresent = 1;
            event.gp2OnAirRiseRaw = 0x87654321;
            event.tsfOnAirRisePresent = 1;
            event.tsfOnAirRiseRaw = 0x123456789abcdef0ULL;
            event.awdlCandidate = 1;
        }
        assert(observer.record(event));
    }
    assert(observer.close(time, CloseReason::Explicit));
    Snapshot snapshot{};
    assert(observer.snapshot(time, &snapshot));
    assert(snapshot.totalEvents == kEventKindCount);
    for (uint32_t i = 0; i < kEventKindCount; ++i)
        assert(snapshot.kindCounts[i] == 1);
    assert(snapshot.dispatchCount == 1);
    assert(snapshot.mpduEntryCount == 1);
    assert(snapshot.ownerQualifiedCount == 0);
    assert(snapshot.ownerFailedCount == 1);
    assert(snapshot.ownerReasonCounts[
               static_cast<uint32_t>(OwnerReason::RocWindowNotQualified)] == 1);
    assert(snapshot.awdlCandidateCount == 1);
    assert(snapshot.witness149Count == 1 && snapshot.witnessNon149Count == 0);
    const Event &witness = snapshot.channel149Witnesses[0].event;
    assert(witness.physicalRingPresent && witness.physicalRing == 0);
    assert(witness.physicalSlotPresent && witness.physicalSlot == 6);
    assert(witness.notificationQidPresent && witness.notificationQid == 13);
    assert(witness.notificationIndexPresent && witness.notificationIndex == 0x123);
    assert(witness.payloadLen == 73 && witness.descSize == 48);
    assert(witness.mpduLengthPresent && witness.mpduLength == 96);
    assert(witness.rawStatusPresent && witness.rawStatus == 0x12345678);
    assert(witness.rawMacPhyIndexPresent && witness.rawMacPhyIndex == 0x41);
    assert(witness.macPhyDecodeModePresent && witness.macPhyDecodeMode == 2);
    assert(witness.channelPresent && witness.channel == 149);
    assert(witness.macIndexPresent && witness.macIndex == 1);
    assert(witness.frameControlPresent && witness.frameControl == 0x0008);
    assert(witness.sequenceControlPresent && witness.sequenceControl == 0x0200);
    assert(witness.gp2OnAirRisePresent &&
           witness.gp2OnAirRiseRaw == 0x87654321);
    assert(witness.tsfOnAirRisePresent &&
           witness.tsfOnAirRiseRaw == 0x123456789abcdef0ULL);
    assert(witness.ownerReason == OwnerReason::RocWindowNotQualified);
    assert(validateSnapshot(snapshot));
}

static void testWitnessBanksAndOverflow()
{
    Observer observer;
    assert(observer.begin(50000, 12));
    uint64_t now = 50001;
    for (uint32_t i = 0; i < 12; ++i) {
        Event event = makeEvent(now++, 12);
        event.channelPresent = 1;
        event.channel = 149;
        event.rxClass = RxClass::Channel149;
        event.ownerReason = i % 2 ? OwnerReason::Qualified
                                  : OwnerReason::RocWindowNotQualified;
        event.awdlCandidate = 1;
        assert(observer.record(event));
    }
    for (uint32_t i = 0; i < 11; ++i) {
        Event event = makeEvent(now++, 12);
        event.channelPresent = 1;
        event.channel = 36;
        event.rxClass = RxClass::Sta;
        event.ownerReason = OwnerReason::LeaseInactive;
        assert(observer.record(event));
    }
    assert(observer.close(now, CloseReason::Explicit));
    Snapshot snapshot{};
    assert(observer.snapshot(now, &snapshot));
    assert(snapshot.mpduEntryCount == 23);
    assert(snapshot.ownerQualifiedCount == 6);
    assert(snapshot.ownerFailedCount == 17);
    assert(snapshot.witness149Count == 8);
    assert(snapshot.witnessNon149Count == 8);
    assert(snapshot.witness149Overflow == 4);
    assert(snapshot.witnessNon149Overflow == 3);
    assert(snapshot.lossCount == 7);
    assert(snapshot.overflow == 1);
    assert(snapshot.channel149Witnesses[0].event.channel == 149);
    assert(snapshot.non149Witnesses[0].event.channel == 36);
    assert(validateSnapshot(snapshot));
}

static void testMalformedGenerationDeadlineAndClockReversal()
{
    {
        Observer observer;
        assert(observer.begin(100000, 5));
        Event bad = makeEvent(100001, 5);
        bad.frameControlPresent = 0;
        bad.frameControl = 8; // Absent numeric metadata must be zero.
        assert(!observer.record(bad));
        Event good = makeEvent(100010, 5);
        assert(observer.record(good));
        Event reversed = makeEvent(100005, 5);
        assert(!observer.record(reversed));
        assert(observer.close(100020, CloseReason::Explicit));
        Snapshot snapshot{};
        assert(observer.snapshot(100030, &snapshot));
        assert(snapshot.invalidSampleLoss == 1);
        assert(snapshot.clockReversalLoss == 1);
        assert(snapshot.lossCount == 2);
        assert(snapshot.mpduEntryCount == 1);
        assert(validateSnapshot(snapshot));
    }
    {
        Observer observer;
        assert(observer.begin(200000, 9));
        Event stale = makeEvent(200001, 10);
        assert(!observer.record(stale));
        assert(!observer.enabled());
        Snapshot snapshot{};
        assert(observer.snapshot(200002, &snapshot));
        assert(snapshot.generationMismatchLoss == 1);
        assert(snapshot.closeReason == CloseReason::GenerationChanged);
        assert(snapshot.totalEvents == 0);
        assert(validateSnapshot(snapshot));
    }
    {
        Observer observer;
        assert(observer.begin(300000, 11));
        Event atDeadline = makeEvent(4300000, 11);
        assert(!observer.record(atDeadline));
        assert(!observer.enabled());
        Snapshot snapshot{};
        assert(observer.snapshot(4300001, &snapshot));
        assert(snapshot.deadlineRejectCount == 1);
        assert(snapshot.closeReason == CloseReason::Deadline);
        assert(snapshot.endUs == snapshot.deadlineUs);
        assert(snapshot.lossCount == 1);
        assert(validateSnapshot(snapshot));
    }
}

static void testConcurrentTryLockLossAndClose()
{
    Observer observer;
    assert(observer.begin(900000, 77));
    constexpr uint32_t kThreads = 8;
    constexpr uint32_t kEventsPerThread = 50000;
    std::atomic<bool> start{false};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (uint32_t thread = 0; thread < kThreads; ++thread) {
        workers.emplace_back([&, thread] {
            while (!start.load(std::memory_order_acquire)) {}
            for (uint32_t i = 0; i < kEventsPerThread; ++i) {
                Event event = makeEvent(900001, 77,
                    i & 1 ? EventKind::MpduEntry : EventKind::Drain);
                event.rxClass = thread & 1 ? RxClass::Sta : RxClass::Other;
                if (event.kind == EventKind::MpduEntry)
                    event.ownerReason = i % 3 ? OwnerReason::RocWindowNotQualified
                                              : OwnerReason::Qualified;
                (void)observer.record(event);
            }
        });
    }
    start.store(true, std::memory_order_release);
    for (auto &worker : workers)
        worker.join();

    Snapshot beforeClose{};
    assert(observer.snapshot(900002, &beforeClose));
    const uint64_t attempted = uint64_t(kThreads) * kEventsPerThread;
    assert(uint64_t(beforeClose.totalEvents) +
               beforeClose.lockContentionLoss == attempted);
    assert(beforeClose.lockContentionLoss > 0);
    assert(beforeClose.mpduEntryCount ==
           beforeClose.ownerQualifiedCount + beforeClose.ownerFailedCount);
    assert(validateSnapshot(beforeClose));

    assert(observer.close(900003, CloseReason::Stop));
    Snapshot afterClose{};
    assert(observer.snapshot(900004, &afterClose));
    assert(afterClose.closed && !afterClose.active);
    assert(afterClose.closeReason == CloseReason::Stop);
    assert(validateSnapshot(afterClose));
}

static void testCorruptSnapshotsFailClosed()
{
    Observer observer;
    assert(observer.begin(700000, 22));
    Event event = makeEvent(700001, 22);
    event.channelPresent = 1;
    event.channel = 149;
    event.rxClass = RxClass::Channel149;
    assert(observer.record(event));
    assert(observer.close(700010));

    Snapshot good{};
    assert(observer.snapshot(700020, &good));
    assert(validateSnapshot(good));

    Snapshot corrupted = good;
    corrupted.schemaVersion++;
    assert(!validateSnapshot(corrupted));

    corrupted = good;
    corrupted.witness149Count = kWitnessBankCapacity + 1;
    assert(!validateSnapshot(corrupted));

    corrupted = good;
    corrupted.channel149Witnesses[0].event.frameControlPresent = 0;
    corrupted.channel149Witnesses[0].event.frameControl = 1;
    assert(!validateSnapshot(corrupted));

    corrupted = good;
    corrupted.totalEvents++;
    assert(!validateSnapshot(corrupted));

    corrupted = good;
    corrupted.closeReason = static_cast<CloseReason>(99);
    assert(!validateSnapshot(corrupted));

    Observer emptyObserver;
    assert(emptyObserver.begin(800000, 23));
    assert(emptyObserver.close(800000));
    Snapshot empty{};
    assert(emptyObserver.snapshot(800000, &empty));
    assert(empty.totalEvents == 0 && empty.mpduEntryCount == 0);
    assert(validateSnapshot(empty));

    assert(saturatingAdd(UINT32_MAX - 1, 2) == UINT32_MAX);
}

int main()
{
    testOneShotAndEmptySnapshot();
    testEventKindsAndSeparateQueueNamespaces();
    testWitnessBanksAndOverflow();
    testMalformedGenerationDeadlineAndClockReversal();
    testConcurrentTryLockLossAndClose();
    testCorruptSnapshotsFailClosed();
    return 0;
}
