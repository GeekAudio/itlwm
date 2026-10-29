// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_rx_event_timeline.hpp"
#include "../intel_roc_event_state.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace NativeAwdlRxTrace;

static Epochs epochs(uint32_t base)
{
    return {base, base + 1u, base + 2u, base + 3u};
}

static ActionTap actionTap(const uint8_t *address, uint32_t lastByte = 0)
{
    static uint8_t source[6];
    source[0] = 0x02;
    source[1] = 0x11;
    source[2] = 0x22;
    source[3] = 0x33;
    source[4] = 0x44;
    source[5] = static_cast<uint8_t>(lastByte);
    ActionTap tap{};
    tap.hostMonotonicUs = 123456789u;
    tap.hostMonotonicPresent = 1;
    tap.rawLength = 88;
    tap.sourceAddress = address ? address : source;
    tap.sourceAddressLength = 6;
    tap.frameControlPresent = 1;
    tap.frameControl = 0x00d0;
    tap.frameType = 0;
    tap.frameSubtype = 13;
    tap.sequenceControlPresent = 1;
    tap.sequenceControl = 0x1230;
    tap.awdlSubtypePresent = 1;
    tap.awdlSubtype = 3;
    tap.wirePhyPresent = 1;
    tap.wirePhyTxUs = 509039675u;
    tap.wireTargetPresent = 1;
    tap.wireTargetTxUs = 509714273u;
    tap.channelIndex = 6;
    tap.rxGp2Present = 1;
    tap.rxGp2Us = 0; // Zero remains valid because the presence bit is set.
    tap.rxMacPhyIndexPresent = 1;
    tap.rxMacPhyIndex = 1;
    return tap;
}

static SessionProtection16 session(bool start, bool canonical,
                                    uint32_t rawStatus,
                                    SessionAnomalyReason reason =
                                        SessionAnomalyReason::None)
{
    SessionProtection16 value{};
    value.hostMonotonicUs = 444555666u;
    value.hostMonotonicPresent = 1;
    value.rawLength = 16;
    value.ownerSessionToken = 77;
    value.expectedUidKnown = 1;
    value.expectedUid = 0x1234;
    value.macIdAndColor = 9;
    value.rawStatus = rawStatus;
    value.rawStartFlag = start ? 1u : 0u;
    value.configuration = 3;
    value.reducerResultPresent = 1;
    value.reducerReturnedTrue = 1;
    value.reducerResult = rawStatus;
    value.canonicalTransitionPresent = 1;
    value.canonicalTransition = canonical ? 1u : 0u;
    value.anomalyReason = reason;
    return value;
}

static TableResult table(bool attempted, bool present, uint32_t status)
{
    return {attempted ? 1u : 0u, present ? 1u : 0u, status};
}

static ObserverResult observer(bool attempted, bool present, uint32_t status)
{
    return {attempted ? 1u : 0u, present ? 1u : 0u, status};
}

static DecodeResult decode(bool attempted, bool present, uint32_t status)
{
    return {attempted ? 1u : 0u, present ? 1u : 0u, status, 7, 8, 9};
}

static void writeLittle32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
    bytes[2] = static_cast<uint8_t>(value >> 16);
    bytes[3] = static_cast<uint8_t>(value >> 24);
}

static SessionProtection16 feedTracker(IntelROCEvent::SessionTracker &tracker,
                                       uint32_t generation, uint32_t mac,
                                       uint32_t configuration, uint32_t start,
                                       uint32_t status, uint64_t hostUs)
{
    uint8_t raw[16]{};
    writeLittle32(raw, mac);
    writeLittle32(raw + 4, status);
    writeLittle32(raw + 8, start);
    writeLittle32(raw + 12, configuration);

    const IntelROCEvent::SessionSnapshot before = tracker.snapshot();
    const bool returned = tracker.noteNotification(generation, raw, sizeof(raw),
                                                   hostUs);
    const IntelROCEvent::SessionSnapshot after = tracker.snapshot();

    SessionProtection16 value{};
    value.hostMonotonicUs = hostUs;
    value.hostMonotonicPresent = 1;
    value.rawLength = sizeof(raw);
    value.ownerSessionToken = generation;
    value.macIdAndColor = mac;
    value.rawStatus = status;
    value.rawStartFlag = start;
    value.configuration = configuration;
    value.reducerResultPresent = 1;
    value.reducerReturnedTrue = returned ? 1u : 0u;
    value.reducerResult = returned ? 1u : 0u;
    value.canonicalTransitionPresent = 1;
    value.canonicalTransition = start
        ? (!before.startSeen && after.startSeen)
        : (!before.endSeen && after.endSeen);

    if (mac != 1 || configuration != before.configuration) {
        value.anomalyReason = SessionAnomalyReason::ForeignContext;
    } else if (status > 1 || start > 1) {
        value.anomalyReason = SessionAnomalyReason::Malformed;
    } else if (start && before.endSeen) {
        value.anomalyReason = SessionAnomalyReason::LateAfterEnd;
    } else if (!start && before.endSeen) {
        value.anomalyReason = status == before.endStatus
            ? SessionAnomalyReason::Duplicate
            : SessionAnomalyReason::Conflicting;
    } else if (start && before.startSeen) {
        value.anomalyReason = status == before.startStatus
            ? SessionAnomalyReason::Duplicate
            : SessionAnomalyReason::Conflicting;
    } else if (!start && !before.startSeen) {
        value.anomalyReason = SessionAnomalyReason::EndBeforeStart;
    }
    return value;
}

int main()
{
    // Never-armed preflight is an intentional empty state.
    Timeline trace;
    Snapshot snapshot = trace.snapshot();
    assert(snapshot.schemaVersion == kSchemaVersion);
    assert(snapshot.ownerPresent == 0 && snapshot.ownerSerial == 0);
    assert(snapshot.epochs.contextGeneration == 0);
    assert(snapshot.epochs.powerGeneration == 0);
    assert(snapshot.epochs.stationGeneration == 0);
    assert(snapshot.epochs.rocGeneration == 0);
    assert(snapshot.active == 0 && snapshot.producerClosed == 0);
    assert(snapshot.eventCount == 0 && snapshot.pendingDrainCount == 0);

    const Epochs firstEpochs = epochs(10);
    assert(trace.beginOwner(100, firstEpochs));
    ActionTap tap = actionTap(nullptr, 1);
    EventToken action = trace.recordActionTap(tap);
    assert(action.eventSerial != 0 && action.ownerSerial == 100);
    assert(action.sourceKnown == 1 && action.sourceOrdinal != 0);

    // Attempt/result presence are independent of a zero-valued status.
    ParseResult parse{};
    parse.attempted = 1;
    parse.resultPresent = 1;
    parse.status = 0;
    parse.availableLength = 64;
    assert(trace.setParseResult(action, parse));
    assert(trace.markQueued(action, true));
    assert(trace.closeProducer(100, firstEpochs, 1));
    assert(!trace.storageComplete()); // The queued consumer may drain after END.
    assert(trace.completeRx(action, table(true, true, 0), observer(true, true, 0),
                            decode(true, true, 0)));
    assert(trace.storageComplete());
    assert(!trace.eventAt(0, nullptr));
    Event event{};
    assert(trace.eventAt(0, &event));
    assert(event.rxGp2Present == 1 && event.rxGp2Us == 0);
    assert(event.parseAttempted == 1 && event.parseResultPresent == 1);
    assert(event.parseStatus == 0);
    assert(event.tableObserveAttempted == 1 && event.tableResultPresent == 1);
    assert(event.tableStatus == 0 && event.completionUpdated == 1);
    assert(event.pendingDrain == 0);
    assert(!trace.markQueued(action, true)); // A completed event cannot requeue.
    assert(trace.snapshot().pendingDrainCount == 0);
    assert(trace.snapshot().staleCompletionCount == 1);

    // SessionProtec canonical transition wins over reducer status/boolean.
    // The first START with status 0 is locked and never overwritten.
    Timeline boundaries;
    assert(boundaries.beginOwner(200, firstEpochs));
    SessionProtection16 failedStart = session(true, true, 0);
    failedStart.reducerReturnedTrue = 0;
    failedStart.reducerResult = 0;
    assert(boundaries.recordSessionProtection(failedStart, firstEpochs, 200));
    SessionProtection16 conflictingStart = session(true, false, 1,
                                                    SessionAnomalyReason::Conflicting);
    assert(boundaries.recordSessionProtection(conflictingStart, firstEpochs, 200));
    SessionProtection16 laterSuccess = session(true, false, 1,
                                                SessionAnomalyReason::Duplicate);
    assert(boundaries.recordSessionProtection(laterSuccess, firstEpochs, 200));
    snapshot = boundaries.snapshot();
    assert(snapshot.rocStart.present == 1);
    assert(snapshot.rocStart.rawStatus == 0);
    assert(snapshot.rocStart.reducerReturnedTrue == 0);
    assert(snapshot.rocStart.canonicalTransitionPresent == 1);
    assert(snapshot.sessionNotificationAcceptedCount == 1);
    assert(snapshot.sessionReducerReturnedTrueCount == 2);
    assert(snapshot.sessionNotificationConflictingCount == 1);
    assert(snapshot.sessionNotificationDuplicateCount == 1);
    assert(snapshot.firstSessionAnomaly.present == 1);
    assert(snapshot.lastSessionAnomaly.reason == SessionAnomalyReason::Duplicate);
    assert(snapshot.lastSessionAnomaly.notificationSerial >
           snapshot.firstSessionAnomaly.notificationSerial);

    // Drive canonical detection from the production SessionTracker's actual
    // before/after snapshots instead of fabricating a canonical bit.
    Timeline reducerTrace;
    assert(reducerTrace.beginOwner(250, firstEpochs));
    IntelROCEvent::SessionTracker failedStartTracker;
    assert(failedStartTracker.begin(250, 1, 3));
    SessionProtection16 actualFailedStart = feedTracker(
        failedStartTracker, 250, 1, 3, 1, 0, 1000);
    assert(actualFailedStart.reducerReturnedTrue == 1);
    assert(actualFailedStart.canonicalTransition == 1);
    assert(reducerTrace.recordSessionProtection(actualFailedStart,
                                                firstEpochs, 250));
    SessionProtection16 actualConflict = feedTracker(
        failedStartTracker, 250, 1, 3, 1, 1, 2000);
    assert(actualConflict.reducerReturnedTrue == 1);
    assert(actualConflict.canonicalTransition == 0);
    assert(actualConflict.anomalyReason == SessionAnomalyReason::Conflicting);
    assert(reducerTrace.recordSessionProtection(actualConflict,
                                                firstEpochs, 250));
    snapshot = reducerTrace.snapshot();
    assert(snapshot.rocStart.present == 1 && snapshot.rocStart.rawStatus == 0);
    assert(snapshot.sessionReducerReturnedTrueCount == 2);
    assert(snapshot.sessionCanonicalTransitionCount == 1);

    Timeline reversedTrace;
    assert(reversedTrace.beginOwner(260, firstEpochs));
    IntelROCEvent::SessionTracker reversedTracker;
    assert(reversedTracker.begin(260, 1, 3));
    SessionProtection16 actualEndFirst = feedTracker(
        reversedTracker, 260, 1, 3, 0, 1, 3000);
    assert(actualEndFirst.canonicalTransition == 1);
    assert(actualEndFirst.anomalyReason == SessionAnomalyReason::EndBeforeStart);
    assert(reversedTrace.recordSessionProtection(actualEndFirst,
                                                  firstEpochs, 260));
    SessionProtection16 actualStartLate = feedTracker(
        reversedTracker, 260, 1, 3, 1, 1, 4000);
    assert(actualStartLate.reducerReturnedTrue == 1);
    assert(actualStartLate.canonicalTransition == 0);
    assert(actualStartLate.anomalyReason == SessionAnomalyReason::LateAfterEnd);
    assert(reversedTrace.recordSessionProtection(actualStartLate,
                                                  firstEpochs, 260));
    snapshot = reversedTrace.snapshot();
    assert(snapshot.rocEnd.present == 1 && snapshot.rocStart.present == 0);
    assert(snapshot.sessionBoundaryOrderInvalid == 1);
    assert(snapshot.sessionNotificationLateCount == 1);

    // END-before-START is retained as a boundary and remains invalid after a
    // later START; the later event does not rewrite history.
    Timeline order;
    assert(order.beginOwner(300, firstEpochs));
    SessionProtection16 endFirst = session(false, true, 1,
                                           SessionAnomalyReason::None);
    assert(order.recordSessionProtection(endFirst, firstEpochs, 300));
    snapshot = order.snapshot();
    assert(snapshot.rocEnd.present == 1);
    assert(snapshot.sessionBoundaryOrderInvalid == 1);
    assert(snapshot.lastSessionAnomaly.reason == SessionAnomalyReason::EndBeforeStart);
    SessionProtection16 startLate = session(true, true, 0);
    assert(order.recordSessionProtection(startLate, firstEpochs, 300));
    snapshot = order.snapshot();
    assert(snapshot.rocStart.present == 1 && snapshot.rocEnd.present == 1);
    assert(snapshot.sessionBoundaryOrderInvalid == 1);

    // A 24-byte TIME_EVENT is its own API and timestamp; it is never copied
    // into the GP2 field.
    Timeline apis;
    assert(apis.beginOwner(400, firstEpochs));
    TimeEvent24 time{};
    time.hostMonotonicUs = 777;
    time.hostMonotonicPresent = 1;
    time.rawLength = 24;
    time.timestamp = 0xaabbccdd;
    time.sessionId = 0x12;
    time.uniqueId = 0x34;
    time.rawStatus = 2;
    EventToken timeToken = apis.recordTimeEvent(time, firstEpochs, 400);
    assert(timeToken.eventSerial != 0);
    assert(apis.eventAt(0, &event));
    assert(event.kind == EventKind::TimeEventNotification);
    assert(event.notificationApi == NotificationApi::TimeEvent24);
    assert(event.rawLength == 24 && event.timeEventTimestamp == 0xaabbccdd);
    assert(event.rxGp2Present == 0);

    // The prepared TX record carries ticket-specific actual wire values and
    // preserves 64-bit diagnostic generations.
    TxPrepared tx{};
    tx.ticketSerial = 0x123456;
    tx.diagnosticGeneration = UINT64_C(0x123456789);
    tx.epochs = firstEpochs;
    tx.hostMonotonicUs = 999;
    tx.hostMonotonicPresent = 1;
    tx.sequenceControl = 0x3210;
    tx.wireInfoPresent = 1;
    tx.wirePhyTxUs = 11;
    tx.wireTargetTxUs = 22;
    tx.queueId = 4;
    tx.descriptorIndex = 8;
    assert(apis.recordTxPrepared(tx, 400).eventSerial != 0);
    assert(apis.eventAt(1, &event));
    assert(event.kind == EventKind::TxPrepared);
    assert(event.txTicketSerial == tx.ticketSerial);
    assert(event.txDiagnosticGeneration == tx.diagnosticGeneration);
    assert(event.txWirePhyTxUs == 11 && event.txWireTargetTxUs == 22);
    assert(event.txQueueId == 4 && event.txDescriptorIndex == 8);

    // Source ordinals compare all six address bytes, remain stable within one
    // owner, and become unknown rather than aliasing when the fixed table fills.
    Timeline sources;
    assert(sources.beginOwner(500, firstEpochs));
    uint8_t addressA[6] = {2, 1, 2, 3, 4, 5};
    uint8_t addressB[6] = {2, 1, 2, 3, 4, 6};
    tap = actionTap(addressA);
    EventToken a1 = sources.recordActionTap(tap);
    EventToken a2 = sources.recordActionTap(tap);
    tap = actionTap(addressB);
    EventToken b1 = sources.recordActionTap(tap);
    assert(a1.sourceOrdinal == a2.sourceOrdinal);
    assert(a1.sourceOrdinal != b1.sourceOrdinal);
    for (uint32_t i = 2; i < kSourceCapacity; ++i) {
        uint8_t unique[6] = {2, 0, 0, 0, 0, static_cast<uint8_t>(i)};
        tap = actionTap(unique);
        assert(sources.recordActionTap(tap).sourceKnown == 1);
    }
    uint8_t overflowAddress[6] = {2, 9, 8, 7, 6, 5};
    tap = actionTap(overflowAddress);
    EventToken overflowSource = sources.recordActionTap(tap);
    assert(overflowSource.sourceKnown == 0 && overflowSource.sourceOrdinal == 0);
    assert(sources.snapshot().sourceTableFullCount == 1);

    // Ring capacity drops only telemetry rows. Queue acceptance is tracked as
    // untracked pending, then drained without changing the packet path.
    Timeline capacity;
    assert(capacity.beginOwner(600, firstEpochs));
    EventToken last{};
    for (size_t i = 0; i < kEventCapacity; ++i) {
        tap = actionTap(nullptr, static_cast<uint32_t>(i));
        last = capacity.recordActionTap(tap);
        assert(last.eventSerial != 0);
    }
    EventToken dropped = capacity.recordActionTap(actionTap(nullptr, 77));
    assert(dropped.eventSerial == 0);
    assert(dropped.queueSerial != 0);
    assert(capacity.snapshot().eventCount == kEventCapacity);
    assert(capacity.snapshot().droppedEventCount == 1);
    assert(capacity.markQueued(dropped, true));
    assert(capacity.snapshot().pendingDrainCount == 1);
    assert(capacity.snapshot().untrackedPendingDrainCount == 1);
    EventToken secondDropped = capacity.recordActionTap(actionTap(nullptr, 78));
    assert(secondDropped.eventSerial == 0 &&
           secondDropped.queueSerial != dropped.queueSerial);
    assert(capacity.markQueued(secondDropped, true));
    assert(capacity.snapshot().pendingDrainCount == 2);
    assert(capacity.closeProducer(600, firstEpochs, 2));
    assert(!capacity.completeRx(secondDropped, table(true, true, 0),
                                observer(false, false, 0),
                                decode(false, false, 0)));
    assert(capacity.snapshot().pendingDrainCount == 2);
    assert(capacity.completeRx(dropped, table(true, true, 0),
                               observer(false, false, 0),
                               decode(false, false, 0)));
    assert(!capacity.markQueued(dropped, true)); // Finalized serial cannot requeue.
    assert(capacity.snapshot().pendingDrainCount == 1);
    assert(!capacity.completeRx(dropped, table(true, true, 0),
                                observer(false, false, 0),
                                decode(false, false, 0)));
    assert(capacity.snapshot().pendingDrainCount == 1);
    assert(capacity.snapshot().untrackedPendingDrainCount == 1);
    assert(capacity.completeRx(secondDropped, table(true, true, 0),
                               observer(false, false, 0),
                               decode(false, false, 0)));
    assert(capacity.snapshot().pendingDrainCount == 0);
    assert(capacity.snapshot().untrackedPendingDrainCount == 0);
    assert(!capacity.storageComplete()); // Dropped row remains explicit.

    // If the impossible-in-normal-operation 17th accepted untracked row
    // exceeds the router-depth identity table, fail closed and never erase
    // the unknowable pending item by beginning a new owner.
    Timeline pendingOverflow;
    assert(pendingOverflow.beginOwner(650, firstEpochs));
    for (size_t i = 0; i < kEventCapacity; ++i)
        assert(pendingOverflow.recordActionTap(
            actionTap(nullptr, static_cast<uint32_t>(i))).eventSerial != 0);
    EventToken overflowTokens[kPendingIdentityCapacity + 1]{};
    for (size_t i = 0; i < kPendingIdentityCapacity + 1; ++i) {
        overflowTokens[i] = pendingOverflow.recordActionTap(
            actionTap(nullptr, static_cast<uint32_t>(i + 90)));
        assert(overflowTokens[i].eventSerial == 0);
        assert(pendingOverflow.markQueued(overflowTokens[i], true));
    }
    assert(pendingOverflow.snapshot().untrackedPendingIdentityOverflowCount == 1);
    assert(pendingOverflow.snapshot().pendingDrainCount ==
           kPendingIdentityCapacity + 1);
    assert(pendingOverflow.closeProducer(650, firstEpochs, 4));
    for (size_t i = 0; i < kPendingIdentityCapacity; ++i)
        assert(pendingOverflow.completeRx(overflowTokens[i],
            table(true, true, 0), observer(false, false, 0),
            decode(false, false, 0)));
    assert(pendingOverflow.snapshot().pendingDrainCount == 1);
    assert(!pendingOverflow.beginOwner(651, epochs(30)));
    assert(pendingOverflow.snapshot().untrackedPendingIdentityOverflowCount == 1);
    assert(!pendingOverflow.storageComplete());

    // A drained old-owner completion cannot mutate a newer owner's row.
    Timeline stale;
    assert(stale.beginOwner(700, firstEpochs));
    EventToken old = stale.recordActionTap(actionTap(nullptr, 1));
    assert(stale.markQueued(old, true));
    assert(stale.closeProducer(700, firstEpochs, 3));
    assert(stale.completeRx(old, table(true, true, 0), observer(true, true, 0),
                            decode(true, true, 0)));
    const Epochs secondEpochs = epochs(20);
    assert(stale.beginOwner(701, secondEpochs));
    EventToken fresh = stale.recordActionTap(actionTap(nullptr, 1));
    assert(fresh.sourceOrdinal != old.sourceOrdinal);
    assert(!stale.completeRx(old, table(true, true, 1), observer(true, true, 1),
                             decode(true, true, 1)));
    snapshot = stale.snapshot();
    assert(snapshot.staleCompletionCount == 1);
    assert(stale.eventAt(0, &event));
    assert(event.serial == fresh.eventSerial && event.completionUpdated == 0);

    // Owner/epoch-mismatched session notifications are only stale diagnostics.
    assert(!stale.recordSessionProtection(session(true, true, 1), firstEpochs, 700));
    assert(stale.snapshot().staleNotificationCount == 1);
    assert(stale.snapshot().rocStart.present == 0);

    return 0;
}
