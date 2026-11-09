// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_discovery_rx_window.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

using namespace NativeAwdlDiscoveryRxWindow;

static BridgeCounters counters(uint64_t captured, uint64_t rejected,
                               uint64_t decoded, uint64_t delivered,
                               uint64_t failed, uint64_t pending,
                               uint64_t calls, uint64_t success,
                               uint64_t committed)
{
    BridgeCounters value{};
    value.rxCaptured = captured;
    value.rxRejected = rejected;
    value.rxDecoded = decoded;
    value.rxDelivered = delivered;
    value.rxInputFailed = failed;
    value.rxPending = pending;
    value.discoveryInputCalls = calls;
    value.discoveryInputSuccess = success;
    value.discoverySameWindowCommitted = committed;
    return value;
}

static MpduEvent dataEvent(uint64_t nowUs)
{
    MpduEvent event{};
    event.monotonicUs = nowUs;
    event.frameClass = FrameClass::Data;
    event.flags = FrameControlPresent | ChannelPresent |
        MpduLengthPresent | LeaseQualified | AwdlDataCandidate;
    event.channel = 149;
    event.mpduLength = 60;
    event.frameControl = 0x0008;
    event.leaseState = 1;
    return event;
}

static void closedWindowEncodesNineWordEventsAndAllowsPendingToFall()
{
    Observer observer;
    const Epochs epochs{10, 20, 30, 40};
    const BridgeCounters before = counters(2, 1, 1, 1, 0, 4, 3, 1, 1);
    assert(observer.begin(epochs, 20, 100, before));
    assert(observer.recordService(epochs, 20, ServiceEvent::RxDrain, 101));

    const uint32_t slot = observer.recordMpdu(epochs, 20, dataEvent(102));
    assert(slot == 0);
    assert(observer.recordDataRoute(epochs, 20, slot,
        DataRoute::QueuedForNative, 103));

    // Queue depth is live and may decrease; the cumulative counters may not.
    const BridgeCounters after = counters(3, 1, 2, 2, 0, 1, 4, 2, 2);
    assert(observer.close(epochs, 20, 104, after));

    Snapshot snapshot{};
    assert(observer.snapshot(&snapshot));
    assert(snapshot.valid == 1 && snapshot.complete == 1);
    assert(snapshot.mpduEntryCount == 1 && snapshot.eventCount == 1);
    assert(snapshot.frameClassCounts[static_cast<uint32_t>(FrameClass::Data)] == 1);
    assert(snapshot.awdlDataCandidateCount == 1);
    assert(snapshot.leaseQualifiedCount == 1);
    assert(snapshot.leaseUnqualifiedCount == 0);
    assert(snapshot.routeQueuedForNativeCount == 1);
    assert(snapshot.bridgeBefore.rxPending == 4);
    assert(snapshot.bridgeAfter.rxPending == 1);

    uint64_t words[kMaxWireWordCount]{};
    const size_t count = encode(snapshot, words, kMaxWireWordCount);
    assert(count == kWireHeaderWordCount + kEventWordCount);
    assert(words[0] == kWireMagic && words[1] == kSchemaVersion);
    assert(words[2] == count && words[3] == 1);
    assert(words[4] == 102); // monotonicUs
    assert(words[5] == 1);   // ordinal
    assert(words[6] == static_cast<uint32_t>(FrameClass::Data));
    assert(words[7] == (dataEvent(102).flags | DataRouteRecorded));
    assert(words[8] == 149); // channel
    assert(words[9] == 60);  // MPDU length
    assert(words[10] == 0x0008);
    assert(words[11] == 1);  // leaseState, not descriptor-owner proof
    assert(words[12] == static_cast<uint32_t>(DataRoute::QueuedForNative));
    assert(!observer.recordService(epochs, 20, ServiceEvent::RxDrain, 105));
}

static void generationMismatchInvalidatesTheBoundWindow()
{
    Observer observer;
    const Epochs epochs{1, 2, 3, 4};
    assert(observer.begin(epochs, 2, 100, counters(0, 0, 0, 0, 0, 0, 0, 0, 0)));
    const Epochs stale{1, 2, 3, 5};
    assert(!observer.recordService(stale, 2, ServiceEvent::RxDrain, 101));
    Snapshot snapshot{};
    assert(observer.snapshot(&snapshot));
    assert(snapshot.state == State::Invalid);
    assert(snapshot.closeReason == CloseReason::EpochMismatch);
    assert(snapshot.valid == 0);
}

static void reversedTimelineInvalidatesInsteadOfPublishingAValidWindow()
{
    Observer observer;
    const Epochs epochs{1, 2, 3, 4};
    assert(observer.begin(epochs, 2, 100, counters(0, 0, 0, 0, 0, 0, 0, 0, 0)));
    assert(observer.recordService(epochs, 2, ServiceEvent::RxDrain, 120));
    assert(observer.recordMpdu(epochs, 2, dataEvent(119)) == UINT32_MAX);
    Snapshot snapshot{};
    assert(observer.snapshot(&snapshot));
    assert(snapshot.state == State::Invalid);
    assert(snapshot.closeReason == CloseReason::InvalidTimeline);
    assert(snapshot.valid == 0);
}

static void eventOverflowPreservesCountsAndMarksTimelineIncomplete()
{
    Observer observer;
    const Epochs epochs{1, 2, 3, 4};
    assert(observer.begin(epochs, 2, 100, counters(0, 0, 0, 0, 0, 0, 0, 0, 0)));
    for (uint32_t i = 0; i < kEventCapacity + 1; ++i) {
        const uint32_t slot = observer.recordMpdu(
            epochs, 2, dataEvent(101 + i));
        assert((i < kEventCapacity && slot == i) ||
               (i == kEventCapacity && slot == UINT32_MAX));
    }
    assert(observer.close(epochs, 2, 200,
        counters(0, 0, 0, 0, 0, 0, 0, 0, 0)));
    Snapshot snapshot{};
    assert(observer.snapshot(&snapshot));
    assert(snapshot.mpduEntryCount == kEventCapacity + 1);
    assert(snapshot.eventCount == kEventCapacity);
    assert(snapshot.overflow == 1 && snapshot.complete == 0);
    uint64_t words[kMaxWireWordCount]{};
    assert(encode(snapshot, words, kMaxWireWordCount) == kMaxWireWordCount);
    assert(words[3] == kEventCapacity);
}

static void reversedCumulativeBridgeCounterInvalidates()
{
    Observer observer;
    const Epochs epochs{1, 2, 3, 4};
    assert(observer.begin(epochs, 2, 100,
        counters(9, 4, 3, 2, 1, 1, 8, 7, 6)));
    assert(!observer.close(epochs, 2, 101,
        counters(8, 4, 3, 2, 1, 0, 8, 7, 6)));
    Snapshot snapshot{};
    assert(observer.snapshot(&snapshot));
    assert(snapshot.state == State::Invalid);
    assert(snapshot.closeReason == CloseReason::BridgeCounterReversed);
}

static void resetAllowsANewWindowOnlyAfterTerminalState()
{
    Observer observer;
    const Epochs epochs{1, 2, 3, 4};
    assert(observer.begin(epochs, 2, 100, counters(0, 0, 0, 0, 0, 0, 0, 0, 0)));
    assert(!observer.reset());
    assert(observer.invalidate(CloseReason::OwnerReleasedWithoutEnd, 101));
    assert(observer.reset());
    assert(!observer.active());
    const Epochs next{5, 2, 3, 5};
    assert(observer.begin(next, 2, 200, counters(0, 0, 0, 0, 0, 0, 0, 0, 0)));
    assert(observer.active());
}

int main()
{
    closedWindowEncodesNineWordEventsAndAllowsPendingToFall();
    generationMismatchInvalidatesTheBoundWindow();
    reversedTimelineInvalidatesInsteadOfPublishingAValidWindow();
    eventOverflowPreservesCountsAndMarksTimelineIncomplete();
    reversedCumulativeBridgeCounterInvalidates();
    resetAllowsANewWindowOnlyAfterTerminalState();
    return 0;
}
