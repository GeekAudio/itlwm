#include "../scan_dispatch_trace.hpp"

#include <cassert>
#include <atomic>
#include <cstdint>
#include <thread>
#include <type_traits>

using namespace NativeWifi::ScanDispatchTrace;

static uint64_t fixedClock(void *context) {
    auto *value = static_cast<uint64_t *>(context);
    return ++*value;
}

static void recordEvent(Trace &trace, Selector selector, Phase phase,
                        int32_t result, const void *argument, uint64_t &clock,
                        uint64_t callSerial = 0) {
    if (!callSerial) callSerial = trace.beginCall();
    uint32_t flags = GateContextUnknown | (argument ? 0U : NullArgument);
    assert(trace.record({callSerial, uint32_t(selector), uint32_t(phase), result, flags},
                        fixedClock, &clock));
}

static int32_t bgscanCacheShim(Trace &trace, const void *opaque, uint64_t &clock) {
    const uint64_t callSerial = trace.beginCall();
    recordEvent(trace, Selector::WclBgscanCacheResult, Phase::Entry,
                kNoResult, opaque, clock, callSerial);
    constexpr int32_t unsupported = -1000;
    recordEvent(trace, Selector::WclBgscanCacheResult, Phase::Return,
                unsupported, opaque, clock, callSerial);
    return unsupported;
}

using RunAction = int32_t (*)(void *);
static int32_t scanRequestShim(Trace &trace, void *request, RunAction runAction,
                                uint64_t &clock) {
    const uint64_t callSerial = trace.beginCall();
    recordEvent(trace, Selector::WclScanRequest, Phase::Entry,
                kNoResult, request, clock, callSerial);
    const int32_t result = runAction(request);
    recordEvent(trace, Selector::WclScanRequest, Phase::Return,
                result, request, clock, callSerial);
    return result;
}

static int32_t mockRunAction(void *request) {
    return request == reinterpret_cast<void *>(uintptr_t(0x1234)) ? -77 : -88;
}

struct ReentrantContext {
    Trace *trace {};
    Snapshot snapshot {};
    bool snapshotStable {};
    bool nestedRecordAccepted {};
    uint64_t clockValue {};
};

static uint64_t reentrantClock(void *opaque) {
    auto *context = static_cast<ReentrantContext *>(opaque);
    const Input nested {context->trace->beginCall(),
                        uint32_t(Selector::WclSetScanHomeAwayTime), uint32_t(Phase::Entry),
                        kNoResult, NullArgument};
    context->nestedRecordAccepted = context->trace->record(
        nested, fixedClock, &context->clockValue);
    context->snapshotStable = context->trace->snapshot(&context->snapshot);
    return ++context->clockValue;
}

static bool snapshotIsCoherent(const Snapshot &snapshot) {
    if (!snapshot.stable) return snapshot.count == 0;
    if ((snapshot.versionBegin & 1U) || snapshot.versionBegin != snapshot.versionEnd)
        return false;
    for (uint32_t i = 0; i < snapshot.count; ++i) {
        if (!snapshot.records[i].sequence) return false;
        if (!snapshot.records[i].callSerial) return false;
        if (i && snapshot.records[i - 1].sequence + 1 != snapshot.records[i].sequence)
            return false;
    }
    for (const Record &latest : snapshot.latest) {
        if (latest.sequence && (!latest.callSerial || latest.sequence > snapshot.nextSequence))
            return false;
    }
    return true;
}

int main() {
    static_assert(std::is_trivially_copyable<Input>::value, "input is a POD");
    static_assert(std::is_trivially_copyable<Record>::value, "record is a POD");
    static_assert(std::is_trivially_copyable<Snapshot>::value, "snapshot is a POD");

    Trace trace;
    uint64_t clock = 100;

    // An intentionally invalid opaque pointer proves the shim never reads it.
    const void *opaque = reinterpret_cast<const void *>(uintptr_t(1));
    assert(bgscanCacheShim(trace, opaque, clock) == -1000);

    void *request = reinterpret_cast<void *>(uintptr_t(0x1234));
    assert(scanRequestShim(trace, request, mockRunAction, clock) == -77);

    Snapshot snapshot {};
    assert(trace.snapshot(&snapshot));
    assert(snapshot.stable && snapshot.count == 4);
    assert(snapshot.getterEntryHits == 1 && snapshot.getterReturnHits == 1);
    assert(snapshot.scanEntryHits == 1 && snapshot.scanReturnHits == 1);
    assert(snapshot.records[0].selector == uint32_t(Selector::WclBgscanCacheResult));
    assert(snapshot.records[0].phase == uint32_t(Phase::Entry));
    assert(snapshot.records[0].callSerial == snapshot.records[1].callSerial);
    assert(snapshot.records[0].context & GateContextUnknown);
    assert(snapshot.records[1].result == -1000);
    assert(snapshot.records[2].phase == uint32_t(Phase::Entry));
    assert(snapshot.records[2].callSerial == snapshot.records[3].callSerial);
    assert(snapshot.records[3].result == -77);
    assert(snapshot.latest[0].callSerial == snapshot.records[0].callSerial);
    assert(snapshot.latest[1].callSerial == snapshot.records[1].callSerial);
    assert(snapshot.latest[2].callSerial == snapshot.records[2].callSerial);
    assert(snapshot.latest[3].callSerial == snapshot.records[3].callSerial);
    assert(snapshotIsCoherent(snapshot));

    // A late return from an older call must not roll the per-selector latest
    // return backward after a newer call has completed.
    Trace ordering;
    const uint64_t olderCall = ordering.beginCall();
    recordEvent(ordering, Selector::WclBgscanCacheResult, Phase::Entry,
                kNoResult, opaque, clock, olderCall);
    const uint64_t newerCall = ordering.beginCall();
    recordEvent(ordering, Selector::WclBgscanCacheResult, Phase::Entry,
                kNoResult, opaque, clock, newerCall);
    recordEvent(ordering, Selector::WclBgscanCacheResult, Phase::Return,
                -22, opaque, clock, newerCall);
    recordEvent(ordering, Selector::WclBgscanCacheResult, Phase::Return,
                -11, opaque, clock, olderCall);
    assert(ordering.snapshot(&snapshot));
    assert(snapshot.latest[0].callSerial == newerCall);
    assert(snapshot.latest[1].callSerial == newerCall);
    assert(snapshot.latest[1].result == -22);

    // Rolling-capacity boundary: retain only the newest 16, flag old rows.
    Trace rolling;
    for (uint32_t i = 0; i < 40; ++i)
        recordEvent(rolling, Selector::WclConfigBgscan,
                    (i & 1U) ? Phase::Return : Phase::Entry,
                    (i & 1U) ? -1000 : kNoResult,
                    nullptr, clock);
    assert(rolling.snapshot(&snapshot));
    assert(snapshot.count == kCapacity && snapshot.overwrittenCount == 24);
    assert(snapshot.records[0].sequence == 25 && snapshot.records[15].sequence == 40);
    assert(snapshot.records[0].callSerial == 25 && snapshot.records[15].callSerial == 40);
    assert(snapshot.configEntryHits == 20 && snapshot.configReturnHits == 20);
    assert(snapshot.latest[4].callSerial == 39 && snapshot.latest[5].callSerial == 40);
    assert(snapshotIsCoherent(snapshot));

    // Invalid phase must be rejected and counted as a drop, never aliasing
    // the config-entry hit slot.
    Trace invalidPhase;
    const Input invalid {invalidPhase.beginCall(),
        uint32_t(Selector::WclConfigBgscan), 99U, kNoResult, GateContextUnknown};
    assert(!invalidPhase.record(invalid, fixedClock, &clock));
    assert(invalidPhase.snapshot(&snapshot));
    assert(snapshot.droppedCount == 1 && snapshot.configEntryHits == 0);
    assert(snapshot.count == 0 && snapshot.nextSequence == 0);
    assert(snapshotIsCoherent(snapshot));

    // Re-entering while the single writer is active must drop immediately,
    // and the separately counted loss must remain visible in a stable snapshot.
    Trace contended;
    ReentrantContext context {};
    context.trace = &contended;
    const Input input {contended.beginCall(),
                       uint32_t(Selector::WclSetScanHomeAwayTime),
                       uint32_t(Phase::Entry), kNoResult, NullArgument};
    assert(contended.record(input, reentrantClock, &context));
    assert(!context.nestedRecordAccepted);
    assert(!context.snapshotStable);
    assert(context.snapshot.stable == 0 && context.snapshot.count == 0);
    assert(contended.snapshot(&snapshot));
    assert(snapshot.droppedCount == 1 && snapshot.unstableSnapshotCount == 1);
    assert(snapshot.homeAwayEntryHits == 2);
    assert(snapshotIsCoherent(snapshot));

    // Race snapshots against successful ring writes. Each accepted snapshot is
    // internally coherent; rejected/torn snapshots must be explicitly marked.
    Trace raced;
    std::atomic<bool> writerDone {false};
    std::thread writer([&] {
        uint64_t localClock = 0;
        for (uint32_t i = 0; i < 20000; ++i)
            raced.record({raced.beginCall(), uint32_t(Selector::WclScanRequest),
                          uint32_t(Phase::Entry), kNoResult, 0}, fixedClock, &localClock);
        writerDone.store(true, std::memory_order_release);
    });
    uint64_t rejectedSnapshots = 0;
    do {
        Snapshot racedSnapshot {};
        const bool stable = raced.snapshot(&racedSnapshot);
        assert(stable == (racedSnapshot.stable != 0));
        assert(snapshotIsCoherent(racedSnapshot));
        if (!stable) ++rejectedSnapshots;
    } while (!writerDone.load(std::memory_order_acquire));
    writer.join();
    assert(raced.snapshot(&snapshot));
    assert(snapshotIsCoherent(snapshot));
    assert(snapshot.scanEntryHits == snapshot.nextSequence + snapshot.droppedCount);
    (void)rejectedSnapshots; // Scheduling may allow every read to be stable.
    return 0;
}
