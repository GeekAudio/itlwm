// SPDX-License-Identifier: GPL-2.0-only
// Exercises the production NativeWifi::Backend with deterministic radio
// callbacks. The radio callbacks do not model its state machine; the tested
// join, association, authorization, beacon, link and completion transitions
// are the actual production implementation.
#include "../wcl_backend.hpp"
#include <assert.h>
#include <string.h>
#include <vector>

using namespace NativeWifi;

namespace {
struct Event {
    uint32_t kind;
    std::vector<uint8_t> body;
};

struct Radio {
    Backend backend;
    unsigned joins {}, leaves {};
    std::vector<Event> events;
    void (*associationHook)(Radio *) {};
    void (*linkDownHook)(Radio *) {};
    void (*driverResetHook)(Radio *) {};
    void (*driverAvailabilityHook)(Radio *) {};
    Status hookJoinResult {Status::Failed};

    static Status scan(void *, const ScanPlan &) { return Status::Unsupported; }
    static Status join(void *context, const JoinPlan &) {
        ++static_cast<Radio *>(context)->joins;
        return Status::Ok;
    }
    static void leave(void *context) { ++static_cast<Radio *>(context)->leaves; }
    static void emit(void *context, uint32_t kind, const void *data, size_t size) {
        auto self = static_cast<Radio *>(context);
        Event event {kind, {}};
        if (size) {
            const auto bytes = static_cast<const uint8_t *>(data);
            event.body.assign(bytes, bytes + size);
        }
        self->events.push_back(event);
        if (kind == Association && self->associationHook) {
            auto hook = self->associationHook;
            self->associationHook = nullptr;
            hook(self);
        }
        if (kind == Link && size == LinkEventSize &&
            static_cast<const uint8_t *>(data)[6] == 0 && self->linkDownHook) {
            auto hook = self->linkDownHook;
            self->linkDownHook = nullptr;
            hook(self);
        }
        if (kind == DriverReset && self->driverResetHook) {
            auto hook = self->driverResetHook;
            self->driverResetHook = nullptr;
            hook(self);
        }
        if (kind == DriverAvailability && self->driverAvailabilityHook) {
            auto hook = self->driverAvailabilityHook;
            self->driverAvailabilityHook = nullptr;
            hook(self);
        }
    }
    static bool privateAddressReady(void *) { return true; }

    Radio() {
        backend.initialize({this, scan, join, leave, emit, privateAddressReady,
                            nullptr, nullptr, nullptr});
        backend.driverState(true);
        events.clear();
    }

    unsigned count(uint32_t kind) const {
        unsigned result = 0;
        for (const auto &event : events) if (event.kind == kind) ++result;
        return result;
    }
    const Event &last(uint32_t kind) const {
        for (auto event = events.rbegin(); event != events.rend(); ++event)
            if (event->kind == kind) return *event;
        assert(false && "event not found");
        return events.front();
    }
    const Event &linkAt(unsigned index) const {
        for (const auto &event : events) {
            if (event.kind == Link) {
                if (!index) return event;
                --index;
            }
        }
        assert(false && "link event not found");
        return events.front();
    }
};

std::vector<uint8_t> joinWire(const uint8_t bssid[6]) {
    std::vector<uint8_t> wire(JoinWireSize);
    write16(wire.data() + 0xc, 2);
    write32(wire.data() + 0x10, 1);
    write32(wire.data() + 0x1c, 1);
    wire[0x20] = 'x';
    write32(wire.data() + 0x214, 1);
    memcpy(wire.data() + 0x21c, bssid, 6);
    return wire;
}

void completeAssociation(Radio &radio, const uint8_t bssid[6]) {
    assert(radio.backend.observeAssociation(0, bssid));
    radio.backend.observeAuthorization(true);
    const uint8_t ssid[] = {'x'};
    const uint8_t ies[] = {0, 0};
    const uint8_t frame[38] = {0x80};
    Beacon beacon {ssid, bssid, ies, frame, sizeof(ssid), sizeof(ies), sizeof(frame),
                   0x1006, 100, 0, 6, -45, -95, 50};
    radio.backend.observeBeacon(beacon);
}

void requestJoin(Radio &radio, const uint8_t bssid[6]) {
    const auto wire = joinWire(bssid);
    assert(radio.backend.joinRequest(wire.data(), wire.size()) == Status::Ok);
}

void assertLink(const Event &event, bool up, const uint8_t bssid[6]) {
    assert(event.kind == Link && event.body.size() == 16);
    assert(event.body[6] == (up ? 1 : 0));
    assert(!memcmp(event.body.data(), bssid, 6));
}

void testConnectedTargetChangeWithoutIntermediateDown() {
    const uint8_t a[6] = {2, 0, 0, 0, 0, 1};
    const uint8_t b[6] = {2, 0, 0, 0, 0, 2};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    assert(radio.count(Link) == 1 && radio.count(Connection) == 1);
    assertLink(radio.last(Link), true, a);

    // The new Join has real success prerequisites, but this sequence does not
    // require an explicit old-A authorization-down callback to have arrived.
    requestJoin(radio, b);
    completeAssociation(radio, b);
    assert(radio.count(Connection) == 2);
    assert(!memcmp(radio.last(Connection).body.data() + 4, b, sizeof(b)));
    assert(radio.count(Link) == 3);
    assertLink(radio.linkAt(1), false, a);
    assertLink(radio.linkAt(2), true, b);

    // Complete the ABA sequence A → B → A using fresh native prerequisites.
    requestJoin(radio, a);
    completeAssociation(radio, a);
    assert(radio.count(Connection) == 3 && radio.count(Link) == 5);
    assertLink(radio.linkAt(3), false, b);
    assertLink(radio.linkAt(4), true, a);
}

void testLateDifferentBssidAssociationIsIgnored() {
    const uint8_t a[6] = {2, 0, 0, 0, 0, 3};
    const uint8_t b[6] = {2, 0, 0, 0, 0, 4};
    Radio radio;
    assert(!radio.backend.observeAssociation(0, b)); // No current Join.
    requestJoin(radio, b);
    assert(!radio.backend.observeAssociation(0, a)); // Old ACK is tagged with old BSSID.
    assert(radio.count(Association) == 0 && radio.count(Connection) == 0);
    completeAssociation(radio, b);
    assert(radio.count(Association) == 1 && radio.count(Connection) == 1);
    assertLink(radio.last(Link), true, b);
}

void testRejectedNewTargetDoesNotPublishSuccess() {
    const uint8_t a[6] = {2, 0, 0, 0, 0, 5};
    const uint8_t b[6] = {2, 0, 0, 0, 0, 6};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, b);
    assert(radio.backend.observeAssociation(1, b));
    assert(radio.count(Connection) == 2 && radio.last(Connection).body[0] == 1);
    assert(radio.count(Link) == 1);
    assertLink(radio.last(Link), true, a);
    assert(!radio.backend.observeAssociation(1, b)); // The failed Join is no longer pending.
}

void testActiveJoinReselectAndExplicitCancellation() {
    const uint8_t a[6] = {2, 0, 0, 0, 0, 7};
    const uint8_t b[6] = {2, 0, 0, 0, 0, 8};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, b);

    // Production currently does not claim an active Join is cancellable by a
    // second Join. The caller must explicitly cancel before selecting again.
    const auto aWire = joinWire(a);
    assert(radio.backend.joinRequest(aWire.data(), aWire.size()) == Status::Busy);
    assert(radio.joins == 2);
    assert(radio.backend.leave(true) == Status::Ok && radio.leaves == 1);

    // After real Leave, late B association callbacks are ignored. The
    // untagged authorization callback is intentionally not asserted here:
    // see the report for the missing adapter provenance contract.
    assert(!radio.backend.observeAssociation(0, b));
    assert(radio.count(Connection) == 1);
    assert(radio.count(JoinAborted) == 1);
    radio.backend.observeAuthorization(false);
    assertLink(radio.last(Link), false, a);
    requestJoin(radio, a);
    completeAssociation(radio, a);
    assert(radio.count(Connection) == 2 && radio.count(Link) == 3);
    assertLink(radio.last(Link), true, a);
}

void leaveAndReplaceWithBFromAssociationEmit(Radio *radio) {
    static const uint8_t b[6] = {2, 0, 0, 0, 1, 2};
    assert(radio->backend.leave(true) == Status::Ok);
    const auto wire = joinWire(b);
    radio->hookJoinResult = radio->backend.joinRequest(wire.data(), wire.size());
}

void leaveAndReplaceWithSameBssidFromAssociationEmit(Radio *radio) {
    static const uint8_t a[6] = {2, 0, 0, 0, 1, 5};
    assert(radio->backend.leave(true) == Status::Ok);
    const auto wire = joinWire(a);
    radio->hookJoinResult = radio->backend.joinRequest(wire.data(), wire.size());
}

void leaveFromLinkDownEmit(Radio *radio) {
    assert(radio->backend.leave(true) == Status::Ok);
}

void cancelBAndCompleteCFromDriverResetEmit(Radio *radio) {
    static const uint8_t c[6] = {2, 0, 0, 0, 1, 8};
    radio->backend.driverState(true);
    assert(radio->backend.leave(true) == Status::Ok);
    requestJoin(*radio, c);
    completeAssociation(*radio, c);
}

void cancelBAndCompleteCFromLinkDownEmit(Radio *radio) {
    static const uint8_t c[6] = {2, 0, 0, 0, 1, 8};
    assert(radio->backend.leave(true) == Status::Ok);
    requestJoin(*radio, c);
    completeAssociation(*radio, c);
}

void cancelBAndStartCFromAvailabilityEmit(Radio *radio) {
    static const uint8_t c[6] = {2, 0, 0, 0, 1, 10};
    radio->backend.driverState(true);
    assert(radio->backend.leave(true) == Status::Ok);
    requestJoin(*radio, c); // Keep C pending to detect an outer stale failure.
}

void testAssociationEmitControlReentryRejectsOldCallback() {
    const uint8_t a[6] = {2, 0, 0, 0, 1, 1};
    const uint8_t b[6] = {2, 0, 0, 0, 1, 2};
    Radio radio;
    requestJoin(radio, a);
    radio.associationHook = leaveAndReplaceWithBFromAssociationEmit;

    // Association emit synchronously performs a real Leave and accepts B.
    // The old A callback must report false and must not seed B's association.
    assert(!radio.backend.observeAssociation(0, a));
    assert(radio.hookJoinResult == Status::Ok && radio.backend.joining());
    assert(radio.count(JoinAborted) == 1 && radio.count(Connection) == 0);
    assert(!radio.backend.observeAssociation(0, a));
    completeAssociation(radio, b);
    assert(radio.count(Connection) == 1 && radio.count(Link) == 1);
    assert(!memcmp(radio.last(Connection).body.data() + 4, b, sizeof(b)));
    assertLink(radio.last(Link), true, b);
}

void testAssociationEmitSameBssidReentryRejectsOldCallback() {
    const uint8_t a[6] = {2, 0, 0, 0, 1, 5};
    Radio radio;
    requestJoin(radio, a);
    radio.associationHook = leaveAndReplaceWithSameBssidFromAssociationEmit;

    // Target equality alone cannot distinguish this synchronous ABA. The
    // local control revision rejects the old callback without claiming any
    // firmware or RF attempt identity.
    assert(!radio.backend.observeAssociation(0, a));
    assert(radio.hookJoinResult == Status::Ok && radio.backend.joining());
    // A later identical callback cannot be classified as stale without a
    // producer-supplied attempt identity; only exercise the current attempt.
    radio.backend.observeAuthorization(true);
    const uint8_t ssid[] = {'x'}, ies[] = {0, 0}, frame[38] = {0x80};
    Beacon staleBeacon {ssid, a, ies, frame, sizeof(ssid), sizeof(ies), sizeof(frame),
                        0x1006, 100, 0, 6, -45, -95, 50};
    radio.backend.observeBeacon(staleBeacon);
    assert(radio.count(Connection) == 0 && radio.count(Link) == 0);

    completeAssociation(radio, a);
    assert(radio.count(Connection) == 1 && radio.count(Link) == 1);
    assertLink(radio.last(Link), true, a);
}

void testLinkDownEmitCancellationCannotCompleteNewTarget() {
    const uint8_t a[6] = {2, 0, 0, 0, 1, 3};
    const uint8_t b[6] = {2, 0, 0, 0, 1, 4};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, b);
    radio.linkDownHook = leaveFromLinkDownEmit;
    completeAssociation(radio, b);

    // The old-link down notification re-enters Leave while the ordered B-up
    // transition is in progress. No B-up or stale ConnectionComplete follows.
    assert(!radio.backend.joining());
    assert(radio.count(JoinAborted) == 1 && radio.count(Connection) == 1);
    assert(radio.count(Link) == 2);
    assertLink(radio.linkAt(0), true, a);
    assertLink(radio.linkAt(1), false, a);
}

void testLinkDownEmitReplacementAddressSurvivesOuterReturn() {
    const uint8_t a[6] = {2, 0, 0, 0, 1, 6};
    const uint8_t b[6] = {2, 0, 0, 0, 1, 7};
    const uint8_t c[6] = {2, 0, 0, 0, 1, 8};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, b);
    // A down event emitted while switching to B synchronously cancels B and
    // completes C. The outer down tail must not erase C's new linkedAddress.
    radio.linkDownHook = cancelBAndCompleteCFromLinkDownEmit;
    completeAssociation(radio, b);

    assert(radio.count(Connection) == 2 && radio.count(JoinAborted) == 1);
    assert(!memcmp(radio.last(Connection).body.data() + 4, c, sizeof(c)));
    assert(radio.count(Link) == 3);
    assertLink(radio.linkAt(0), true, a);
    assertLink(radio.linkAt(1), false, a);
    assertLink(radio.linkAt(2), true, c);

    radio.backend.observeAuthorization(false);
    assert(radio.count(Link) == 4);
    assertLink(radio.last(Link), false, c);
}

void testDriverResetEmitReentryStopsStaleAvailability() {
    const uint8_t a[6] = {2, 0, 0, 0, 1, 11};
    const uint8_t b[6] = {2, 0, 0, 0, 1, 12};
    const uint8_t c[6] = {2, 0, 0, 0, 1, 8};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, b);
    radio.driverResetHook = cancelBAndCompleteCFromDriverResetEmit;
    radio.backend.driverState(false);

    assert(radio.backend.ready() && !radio.backend.joining());
    assert(radio.count(Connection) == 2 && radio.count(JoinAborted) == 1);
    assert(!memcmp(radio.last(Connection).body.data() + 4, c, sizeof(c)));
    assert(read32(radio.last(DriverAvailability).body.data() + 8) == 1);
}

void testDriverAvailabilityEmitReentryDoesNotFailNewJoin() {
    const uint8_t a[6] = {2, 0, 0, 0, 1, 13};
    const uint8_t b[6] = {2, 0, 0, 0, 1, 14};
    const uint8_t c[6] = {2, 0, 0, 0, 1, 10};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, b);
    radio.driverAvailabilityHook = cancelBAndStartCFromAvailabilityEmit;
    radio.backend.driverState(false);

    // A nested Ready event supersedes the outer Off publication. The latter
    // must not finish C as offline after the availability emitter returns.
    assert(radio.backend.ready() && radio.backend.joining());
    assert(radio.count(Connection) == 1 && radio.count(JoinAborted) == 1);
    assert(read32(radio.last(DriverAvailability).body.data() + 8) == 1);
    completeAssociation(radio, c);
    assert(radio.count(Connection) == 2);
    assert(!memcmp(radio.last(Connection).body.data() + 4, c, sizeof(c)));
}

void testSameTargetReentryDoesNotDuplicateLinkIdentity() {
    const uint8_t a[6] = {2, 0, 0, 0, 0, 9};
    Radio radio;
    requestJoin(radio, a);
    completeAssociation(radio, a);
    requestJoin(radio, a);
    completeAssociation(radio, a);
    assert(radio.count(Connection) == 2);
    assert(radio.count(Link) == 1);
    assertLink(radio.last(Link), true, a);
}

void testAddressRestartAndOffReadyRetireOldTarget() {
    const uint8_t a[6] = {2, 0, 0, 0, 0, 10};
    const uint8_t b[6] = {2, 0, 0, 0, 0, 11};
    {
        Radio radio;
        requestJoin(radio, a);
        completeAssociation(radio, a);
        radio.backend.beginAddressChange();
        requestJoin(radio, b); // Deferred until the owner reports Ready.
        assert(!radio.backend.observeAssociation(0, b));
        radio.backend.driverState(false);
        assertLink(radio.last(Link), false, a);
        radio.backend.driverState(true);
        assert(radio.joins == 2 && radio.backend.joining());
        completeAssociation(radio, b);
        assert(radio.count(Connection) == 2 && radio.count(Link) == 3);
        assertLink(radio.linkAt(1), false, a);
        assertLink(radio.linkAt(2), true, b);
    }
    {
        Radio radio;
        requestJoin(radio, a);
        completeAssociation(radio, a);
        requestJoin(radio, b);
        radio.backend.driverState(false);
        assert(!radio.backend.joining());
        assert(radio.count(Connection) == 2 && radio.last(Connection).body[0] != 0);
        assertLink(radio.last(Link), false, a);
        radio.backend.driverState(true);
        assert(!radio.backend.observeAssociation(0, b));
        radio.backend.observeAuthorization(true);
        assert(radio.count(Connection) == 2 && radio.count(Link) == 2);
    }
    {
        Radio radio;
        requestJoin(radio, a);
        radio.backend.stop();
        assert(!radio.backend.observeAssociation(0, a));
    }
}
}

int main() {
    testConnectedTargetChangeWithoutIntermediateDown();
    testLateDifferentBssidAssociationIsIgnored();
    testRejectedNewTargetDoesNotPublishSuccess();
    testActiveJoinReselectAndExplicitCancellation();
    testAssociationEmitControlReentryRejectsOldCallback();
    testAssociationEmitSameBssidReentryRejectsOldCallback();
    testLinkDownEmitCancellationCannotCompleteNewTarget();
    testLinkDownEmitReplacementAddressSurvivesOuterReturn();
    testDriverResetEmitReentryStopsStaleAvailability();
    testDriverAvailabilityEmitReentryDoesNotFailNewJoin();
    testSameTargetReentryDoesNotDuplicateLinkIdentity();
    testAddressRestartAndOffReadyRetireOldTarget();
}
