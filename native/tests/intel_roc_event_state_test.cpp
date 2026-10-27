// SPDX-License-Identifier: GPL-2.0-only
#include "../intel_roc_event_state.hpp"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using IntelROCEvent::Tracker;
static void le32(uint8_t *p, uint32_t n)
{ for (unsigned i = 0; i != 4; ++i) p[i] = uint8_t(n >> (i * 8)); }
static void response(uint8_t *p, uint32_t status = 1, uint32_t uid = 0)
{ memset(p, 0, 16); le32(p, status); le32(p+4, 4); le32(p+8, uid); le32(p+12, 1); }
static void event(uint8_t *p, uint32_t action, uint32_t status = 1, uint32_t uid = 0)
{ memset(p, 0, 24); le32(p+8, uid); le32(p+12, 1); le32(p+16, action); le32(p+20, status); }

int main()
{
    uint8_t r[16], e[24];
    // A START/END can arrive while the synchronous ADD response still sleeps.
    Tracker early; assert(early.begin(9, 1, 4));
    event(e, 1); assert(early.noteNotification(9, e, 24));
    event(e, 2); assert(early.noteNotification(9, e, 24));
    assert(!early.snapshot().cleanupAllowed);
    response(r); assert(early.noteResponse(9, 0, r, 16));
    assert(early.snapshot().uniqueId == 0);
    assert(early.snapshot().cleanupAllowed);
    assert(early.snapshot().observedScheduledPair);
    assert(early.snapshot().responseContractSuccess);
    assert(!early.begin(10, 1, 4));

    // The old STA's zero-success test does not silently become the ROC ABI.
    Tracker oldStatus; assert(oldStatus.begin(9, 1, 4));
    response(r, 0); assert(oldStatus.noteResponse(9, 0, r, 16));
    assert(!oldStatus.snapshot().responseContractSuccess);
    event(e, 1); oldStatus.noteNotification(9, e, 24);
    event(e, 2); oldStatus.noteNotification(9, e, 24);
    assert(oldStatus.snapshot().observedScheduledPair);

    // Failed scheduling still requires END before resource cleanup.
    Tracker unscheduled; unscheduled.begin(9, 1, 4);
    response(r); unscheduled.noteResponse(9, 0, r, 16);
    event(e, 1, 0); unscheduled.noteNotification(9, e, 24);
    assert(!unscheduled.snapshot().cleanupAllowed);
    event(e, 2, 0); unscheduled.noteNotification(9, e, 24);
    assert(unscheduled.snapshot().cleanupAllowed);
    assert(!unscheduled.snapshot().observedScheduledPair);

    Tracker wrongUid; wrongUid.begin(9, 1, 4);
    response(r, 1, 7); wrongUid.noteResponse(9, 0, r, 16);
    event(e, 2, 1, 8); wrongUid.noteNotification(9, e, 24);
    assert(!wrongUid.snapshot().endSeen);
    assert(wrongUid.snapshot().ignoredForeign == 1);
    wrongUid.expire(9); assert(wrongUid.snapshot().outcomeUnknown);
    assert(!wrongUid.snapshot().cleanupAllowed);

    // Binding only the notification MAC is insufficient; match response UID.
    Tracker mixedEarly; mixedEarly.begin(9, 1, 4);
    event(e, 1, 1, 2); mixedEarly.noteNotification(9, e, 24);
    event(e, 2, 1, 2); mixedEarly.noteNotification(9, e, 24);
    response(r, 1, 3); mixedEarly.noteResponse(9, 0, r, 16);
    assert(!mixedEarly.snapshot().startSeen && !mixedEarly.snapshot().endSeen);

    Tracker order; order.begin(9, 1, 4); response(r);
    order.noteResponse(9, 0, r, 16);
    event(e, 2); order.noteNotification(9, e, 24);
    event(e, 1); order.noteNotification(9, e, 24);
    assert(order.snapshot().cleanupAllowed);
    assert(!order.snapshot().observedScheduledPair);

    // No response identity after transport error: no guessed drain by UID0.
    Tracker transport; transport.begin(9, 1, 4);
    assert(!transport.noteResponse(9, 5, nullptr, 0));
    event(e, 2); transport.noteNotification(9, e, 24);
    assert(!transport.snapshot().cleanupAllowed);
    assert(transport.snapshot().outcomeUnknown);

    Tracker overflow; overflow.begin(9, 1, 4);
    for (unsigned uid = 0; uid != 5; ++uid) {
        event(e, 1, 1, uid); overflow.noteNotification(9, e, 24);
    }
    response(r); overflow.noteResponse(9, 0, r, 16);
    event(e, 2); overflow.noteNotification(9, e, 24);
    assert(overflow.snapshot().outcomeUnknown);
    assert(!overflow.snapshot().cleanupAllowed);

    // Exhaust every truncated wire length and avoid out-of-bounds reads.
    for (unsigned n = 0; n != 24; ++n) {
        Tracker shortEvent; shortEvent.begin(9, 1, 4);
        assert(!shortEvent.noteNotification(9, e, n));
    }
    for (unsigned n = 0; n != 16; ++n) {
        Tracker shortResponse; shortResponse.begin(9, 1, 4);
        assert(!shortResponse.noteResponse(9, 0, r, n));
    }
    Tracker generation; generation.begin(9, 1, 4);
    assert(!generation.noteResponse(8, 0, r, 16));
    assert(!generation.noteNotification(8, e, 24));
    generation.expire(8); assert(!generation.snapshot().outcomeUnknown);

    // Actual AX201 fw68 route: Session Protection, no UID or MAC color.
    auto sessionEvent = [&](unsigned mac, unsigned conf, unsigned start, unsigned status) {
        le32(e, mac); le32(e+4, status); le32(e+8, start); le32(e+12, conf);
    };
    IntelROCEvent::SessionTracker session;
    assert(!session.begin(9, 0, 2));
    assert(!session.begin(9, 2, 2));
    assert(!session.begin(9, 1, 4));
    assert(session.begin(9, 1, 2));
    assert(!session.begin(10, 1, 2));
    assert(session.snapshot().configuration == 2);
    sessionEvent(1, 2, 1, 1); session.noteNotification(9, e, 16, 1000);
    sessionEvent(1, 2, 0, 1); session.noteNotification(9, e, 16, 901000);
    assert(session.snapshot().startObservedMonotonicUs == 1000);
    assert(session.snapshot().endObservedMonotonicUs == 901000);
    assert(!session.snapshot().cleanupAllowed);
    assert(session.noteCommandResult(9, 0));
    assert(session.snapshot().observedScheduledPair);
    assert(session.snapshot().cleanupAllowed);
    assert(!session.snapshot().outcomeUnknown);
    assert(!session.noteCommandResult(9, 0));

    // MGMT_TX uses its own configuration, and notifications from the listen
    // configuration cannot satisfy or terminate this transaction.
    IntelROCEvent::SessionTracker mgmtTx;
    assert(mgmtTx.begin(10, 1, 3));
    assert(mgmtTx.snapshot().configuration == 3);
    mgmtTx.noteCommandResult(10, 0);
    sessionEvent(1, 2, 1, 1); assert(!mgmtTx.noteNotification(10, e, 16));
    assert(!mgmtTx.snapshot().startSeen && !mgmtTx.snapshot().endSeen);
    assert(mgmtTx.snapshot().ignoredForeign == 1);
    sessionEvent(1, 3, 1, 1); assert(mgmtTx.noteNotification(10, e, 16));
    sessionEvent(1, 3, 0, 1); assert(mgmtTx.noteNotification(10, e, 16));
    assert(mgmtTx.snapshot().cleanupAllowed);
    assert(mgmtTx.snapshot().observedScheduledPair);

    IntelROCEvent::SessionTracker mgmtTxFailed;
    mgmtTxFailed.begin(11, 1, 3);
    mgmtTxFailed.noteCommandResult(11, 0);
    sessionEvent(1, 3, 1, 1); mgmtTxFailed.noteNotification(11, e, 16);
    sessionEvent(1, 3, 0, 0); mgmtTxFailed.noteNotification(11, e, 16);
    assert(mgmtTxFailed.snapshot().cleanupAllowed);
    assert(!mgmtTxFailed.snapshot().observedScheduledPair);

    IntelROCEvent::SessionTracker reversedSession;
    reversedSession.begin(9, 1, 2); reversedSession.noteCommandResult(9, 0);
    sessionEvent(1, 2, 0, 1); reversedSession.noteNotification(9, e, 16);
    sessionEvent(1, 2, 1, 1); reversedSession.noteNotification(9, e, 16);
    assert(reversedSession.snapshot().outcomeUnknown);
    assert(!reversedSession.snapshot().cleanupAllowed);

    IntelROCEvent::SessionTracker foreign;
    foreign.begin(9, 1, 2); foreign.noteCommandResult(9, 0);
    sessionEvent(0, 0, 0, 1); assert(!foreign.noteNotification(9, e, 16));
    assert(IntelROCEvent::isStationSessionNotification(e, 16, 0));
    sessionEvent(1, 0, 0, 1); assert(!foreign.noteNotification(9, e, 16));
    assert(!IntelROCEvent::isStationSessionNotification(e, 16, 0));
    sessionEvent(1, 2, 0, 1);
    assert(!foreign.noteNotification(8, e, 16));
    foreign.expire(9);
    assert(!foreign.snapshot().cleanupAllowed && foreign.snapshot().outcomeUnknown);
    // A late matching END may establish drain; it cannot revive ROC success.
    foreign.noteNotification(9, e, 16);
    assert(foreign.snapshot().cleanupAllowed);
    assert(!foreign.snapshot().observedScheduledPair);

    IntelROCEvent::SessionTracker failed;
    failed.begin(9, 1, 2); failed.noteCommandResult(9, 0);
    sessionEvent(1, 2, 1, 0); failed.noteNotification(9, e, 16);
    assert(!failed.snapshot().cleanupAllowed);
    sessionEvent(1, 2, 0, 0); failed.noteNotification(9, e, 16);
    assert(failed.snapshot().cleanupAllowed);
    assert(!failed.snapshot().observedScheduledPair);

    IntelROCEvent::SessionTracker contradiction;
    contradiction.begin(9, 1, 2); contradiction.noteCommandResult(9, 0);
    sessionEvent(1, 2, 1, 1); contradiction.noteNotification(9, e, 16);
    sessionEvent(1, 2, 1, 0); contradiction.noteNotification(9, e, 16);
    sessionEvent(1, 2, 0, 1); contradiction.noteNotification(9, e, 16);
    assert(!contradiction.snapshot().cleanupAllowed);
    assert(contradiction.snapshot().outcomeUnknown);

    for (unsigned n = 0; n < 16; ++n) {
        IntelROCEvent::SessionTracker shortSession;
        shortSession.begin(9, 1, 2);
        assert(!shortSession.noteNotification(9, e, n));
        assert(!IntelROCEvent::isStationSessionNotification(e, n, 0));
    }
    IntelROCEvent::SessionTracker ackFailure;
    ackFailure.begin(9, 1, 2); ackFailure.noteCommandResult(9, 5);
    assert(ackFailure.snapshot().outcomeUnknown);
    sessionEvent(1, 2, 0, 1); ackFailure.noteNotification(9, e, 16);
    assert(ackFailure.snapshot().cleanupAllowed);
    assert(!ackFailure.snapshot().observedScheduledPair);

    puts("ROC event identity/order/early-IRQ/timeout tests passed");
}
