// SPDX-License-Identifier: GPL-2.0-only
#include "../intel_awdl_context.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>

using namespace IntelAwdl;

namespace {

struct Fixture {
    ContextLease lease;
    Admission admission{7, 11, 36, 36, 0, 0, true, true, true, true, true,
                        true, false, false, false};
    Context context{91, 7, 11, 36, 1, 0xa3, 1, 0x51, 9, 2,
                    {0x02, 0x12, 0x23, 0x34, 0x45, 0x56}};
    std::string calls;
    const char *failCall{nullptr};
    Result failResult{Result::kFirmwareError};
    bool failOnce{true};
    Result disableQueueResult{Result::kSuccess};
    Result removeBindingResult{Result::kSuccess};
    Result addTimeEventResult{Result::kSuccess};
    TimeEventResponse response{1, 4, 0, 0x0000a301};

    static Result checkpoint(Fixture *self, const char *name, char marker)
    {
        self->calls.push_back(marker);
        if (self->failCall && std::strcmp(name, self->failCall) == 0 &&
            (!self->failOnce || marker == self->calls.back())) {
            // A configured one-shot fault is cleared after its first use.
            const Result result = self->failResult;
            if (self->failOnce)
                self->failCall = nullptr;
            return result;
        }
        return Result::kSuccess;
    }

    static Result leasePhy(void *c, const Context &x)
    { auto *s = static_cast<Fixture *>(c); assert(x.phyId == 1); return checkpoint(s, "lease", 'P'); }
    static Result releasePhy(void *c, const Context &)
    { return checkpoint(static_cast<Fixture *>(c), "release-phy", 'p'); }
    static Result addMac(void *c, const Context &x)
    { auto *s = static_cast<Fixture *>(c); assert(x.macId == 1); return checkpoint(s, "add-mac", 'M'); }
    static Result removeMac(void *c, const Context &)
    { return checkpoint(static_cast<Fixture *>(c), "remove-mac", 'm'); }
    static Result addBinding(void *c, const Context &)
    { return checkpoint(static_cast<Fixture *>(c), "add-binding", 'B'); }
    static Result removeBinding(void *c, const Context &)
    { auto *s = static_cast<Fixture *>(c); const Result r = checkpoint(s, "remove-binding", 'b');
      return r == Result::kSuccess ? s->removeBindingResult : r; }
    static Result addStation(void *c, const Context &x)
    { auto *s = static_cast<Fixture *>(c); assert(x.stationId == 9); return checkpoint(s, "add-station", 'S'); }
    static Result removeStation(void *c, const Context &)
    { return checkpoint(static_cast<Fixture *>(c), "remove-station", 's'); }
    static Result enableQueue(void *c, const Context &x)
    { auto *s = static_cast<Fixture *>(c); assert(x.queueId == 2); return checkpoint(s, "enable-queue", 'Q'); }
    static Result disableQueue(void *c, const Context &)
    { auto *s = static_cast<Fixture *>(c); const Result r = checkpoint(s, "disable-queue", 'q');
      return r == Result::kSuccess ? s->disableQueueResult : r; }
    static Result addTimeEvent(void *c, const Context &x, std::uint32_t duration,
                               TimeEventResponse *response)
    { auto *s = static_cast<Fixture *>(c); assert(x.macId == 1 && duration == 300);
      s->calls.push_back('E'); *response = s->response; return s->addTimeEventResult; }
    static Result removeTimeEvent(void *c, const Context &, std::uint32_t uid)
    { auto *s = static_cast<Fixture *>(c); s->calls.push_back('R');
      assert(uid == s->response.uniqueId); return Result::kSuccess; }

    Operations ops()
    {
        return {this, leasePhy, releasePhy, addMac, removeMac, addBinding,
                removeBinding, addStation, removeStation, enableQueue,
                disableQueue, addTimeEvent, removeTimeEvent};
    }

    TimeEventNotification event(TimeEventAction action, bool scheduled = true)
    { return {context.generation, response.uniqueId,
              response.rawMacIdAndColor, action, scheduled}; }
};

void TestAdmissionRequiresIndependentResources()
{
    Fixture f;
    Operations ops = f.ops();
    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    assert(f.calls == "PMBSQ");
    assert(f.lease.state() == State::kResourcesReady);

    Fixture busy;
    busy.admission.scanIdle = false;
    assert(busy.lease.acquire(busy.admission, busy.context, busy.ops()) == Result::kNotReady);
    assert(busy.calls.empty());

    Fixture noCoexist;
    noCoexist.admission.stationChannel = 149;
    noCoexist.admission.compatibleChannelLeaseAvailable = false;
    assert(noCoexist.lease.acquire(noCoexist.admission, noCoexist.context,
                                   noCoexist.ops()) == Result::kBusy);
    assert(noCoexist.calls.empty());

    Fixture monitor;
    monitor.admission.monitorInjectionQueueInUse = true;
    assert(monitor.lease.acquire(monitor.admission, monitor.context,
                                 monitor.ops()) == Result::kBusy);
    assert(monitor.calls.empty());

    Fixture collision;
    collision.context.macId = collision.admission.stationMacId;
    assert(collision.lease.acquire(collision.admission, collision.context,
                                   collision.ops()) == Result::kInvalid);
    assert(collision.calls.empty());
}

void TestResourcesAreNotReadyUntilRealNotification()
{
    Fixture f;
    Operations ops = f.ops();
    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    // Status 0 and UID 0 are both retained; neither means on-air success.
    f.response.rawStatus = 0;
    f.response.uniqueId = 0;
    f.response.rawMacIdAndColor = 0x0000a301;
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNotReady);
    assert(f.lease.state() == State::kAwaitingStart);
    assert(f.lease.timeEventUid() == 0);
    assert(f.lease.rawTimeEventStatus() == 0);

    TimeEventNotification stale = f.event(TimeEventAction::kStart);
    stale.generation++;
    assert(f.lease.onNotification(f.admission, stale, ops) == Result::kStale);
    TimeEventNotification wrongContext = f.event(TimeEventAction::kStart);
    wrongContext.macIdAndColor++;
    assert(f.lease.onNotification(f.admission, wrongContext, ops) == Result::kStale);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kStart), ops) ==
           Result::kSuccess);
    assert(f.lease.state() == State::kActive);
    assert(f.lease.requestStop(f.context.generation, ops) == Result::kNotReady);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kEnd), ops) ==
           Result::kSuccess);

    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    f.response.uniqueId = 0x12345678;
    f.response.rawStatus = 1;
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNotReady);
    assert(f.lease.rawTimeEventStatus() == 1);
    assert(f.lease.onNotification(f.admission,
                                  f.event(TimeEventAction::kStart, false), ops) ==
           Result::kFirmwareError);
    assert(f.lease.state() == State::kResourcesReady);
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNotReady);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kStart), ops) ==
           Result::kSuccess);
    assert(f.lease.state() == State::kActive);

    assert(f.lease.requestStop(f.context.generation, ops) == Result::kNotReady);
    assert(f.lease.state() == State::kStopping);
    assert(f.calls.back() == 'R');
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kEnd), ops) ==
           Result::kSuccess);
    assert(f.lease.state() == State::kIdle);
    assert(f.calls.substr(f.calls.size() - 5) == "qsbmp");
}

void TestEveryAcquisitionFailureRollsBackInReverseOrder()
{
    const char *names[] = {"lease", "add-mac", "add-binding", "add-station", "enable-queue"};
    const char *expected[] = {"P", "PMp", "PMBmp", "PMBSbmp", "PMBSQsbmp"};
    for (unsigned i = 0; i < 5; ++i) {
        Fixture f;
        f.failCall = names[i];
        assert(f.lease.acquire(f.admission, f.context, f.ops()) == Result::kFirmwareError);
        assert(f.calls == expected[i]);
        assert(f.lease.state() == State::kIdle);
    }
}

void TestUncertainFirmwareOutcomeKeepsLeaseUntilResolved()
{
    Fixture f;
    f.failCall = "add-binding";
    f.failResult = Result::kNeedsCleanup;
    f.removeBindingResult = Result::kBusy;
    assert(f.lease.acquire(f.admission, f.context, f.ops()) == Result::kNeedsCleanup);
    assert(f.lease.state() == State::kCleanupRequired);
    // Binding remove is the first reverse operation and fails; MAC and PHY
    // remain owned until a later retry or a proven hardware reset.
    f.removeBindingResult = Result::kBusy;
    assert(f.lease.retryCleanup(f.context.generation, f.ops()) == Result::kBusy);
    assert(f.lease.state() == State::kCleanupRequired);
    const std::string before = f.calls;
    assert(f.lease.retryCleanup(f.context.generation + 1, f.ops()) == Result::kStale);
    assert(f.calls == before);
    f.removeBindingResult = Result::kSuccess;
    assert(f.lease.retryCleanup(f.context.generation, f.ops()) == Result::kSuccess);
    assert(f.lease.state() == State::kIdle);
}

void TestStopWaitsForEndAndResetIsTheOnlyForcedRelease()
{
    Fixture f;
    Operations ops = f.ops();
    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNotReady);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kStart), ops) ==
           Result::kSuccess);
    assert(f.lease.requestStop(f.context.generation, ops) == Result::kNotReady);
    assert(f.lease.retryCleanup(f.context.generation, ops) == Result::kNotReady);
    assert(f.lease.state() == State::kStopping);
    assert(f.lease.hardwareResetComplete(f.context.generation) == Result::kSuccess);
    assert(f.lease.state() == State::kIdle);
    assert(f.lease.timeEventUid() == 0);
}

void TestScanAndOffWaitForMatchingEventEnd()
{
    Fixture f;
    Operations ops = f.ops();
    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNotReady);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kStart), ops) ==
           Result::kSuccess);

    Admission scanning = f.admission;
    scanning.scanIdle = false;
    assert(f.lease.quiesceForRadioChange(scanning, ops) == Result::kNotReady);
    assert(f.lease.state() == State::kStopping);
    // The caller must keep scan/off blocked until the hardware says this
    // exact event ended.
    assert(f.lease.quiesceForRadioChange(scanning, ops) == Result::kNotReady);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kEnd), ops) ==
           Result::kSuccess);
    assert(f.lease.quiesceForRadioChange(scanning, ops) == Result::kSuccess);
    assert(f.lease.state() == State::kIdle);

    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNotReady);
    Admission poweringOff = f.admission;
    poweringOff.powerGeneration++;
    assert(f.lease.quiesceForRadioChange(poweringOff, ops) == Result::kNotReady);
    // A completed physical stop drains residual firmware objects even if no
    // event-END was delivered to host before the DMA rings were reset.
    assert(f.lease.hardwareResetComplete(f.context.generation) == Result::kSuccess);
    assert(f.lease.state() == State::kIdle);
}

void TestCleanupFailureDoesNotReleaseParentResource()
{
    Fixture f;
    Operations ops = f.ops();
    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    f.disableQueueResult = Result::kBusy;
    assert(f.lease.requestStop(f.context.generation, ops) == Result::kBusy);
    assert(f.lease.state() == State::kResourcesReady);
    const std::string afterFirst = f.calls;
    assert(f.lease.retryCleanup(f.context.generation, ops) == Result::kBusy);
    assert(f.calls == afterFirst + 'q');
    f.disableQueueResult = Result::kSuccess;
    assert(f.lease.retryCleanup(f.context.generation, ops) == Result::kSuccess);
    assert(f.lease.state() == State::kIdle);
}

void TestAmbiguousTimeEventKeepsResourcesUntilEndOrReset()
{
    Fixture f;
    Operations ops = f.ops();
    assert(f.lease.acquire(f.admission, f.context, ops) == Result::kSuccess);
    f.addTimeEventResult = Result::kNeedsCleanup;
    assert(f.lease.armTimeEvent(f.admission, 300, ops) == Result::kNeedsCleanup);
    assert(f.lease.state() == State::kCleanupRequired);
    assert(f.lease.retryCleanup(f.context.generation, ops) == Result::kNotReady);
    assert(f.lease.state() == State::kStopping);
    // The accepted remove request is not itself proof that the event ended.
    assert(f.lease.state() != State::kIdle);
    assert(f.lease.onNotification(f.admission, f.event(TimeEventAction::kEnd), ops) ==
           Result::kSuccess);
    assert(f.lease.state() == State::kIdle);

    Fixture malformed;
    assert(malformed.lease.acquire(malformed.admission, malformed.context,
                                   malformed.ops()) == Result::kSuccess);
    malformed.response.rawMacIdAndColor++;
    assert(malformed.lease.armTimeEvent(malformed.admission, 300, malformed.ops()) ==
           Result::kNeedsCleanup);
    assert(malformed.lease.retryCleanup(malformed.context.generation,
                                        malformed.ops()) == Result::kNeedsCleanup);
    assert(malformed.lease.hardwareResetComplete(malformed.context.generation) ==
           Result::kSuccess);
    assert(malformed.lease.state() == State::kIdle);
}

} // namespace

int main()
{
    TestAdmissionRequiresIndependentResources();
    TestResourcesAreNotReadyUntilRealNotification();
    TestEveryAcquisitionFailureRollsBackInReverseOrder();
    TestUncertainFirmwareOutcomeKeepsLeaseUntilResolved();
    TestStopWaitsForEndAndResetIsTheOnlyForcedRelease();
    TestScanAndOffWaitForMatchingEventEnd();
    TestCleanupFailureDoesNotReleaseParentResource();
    TestAmbiguousTimeEventKeepsResourcesUntilEndOrReset();
}
