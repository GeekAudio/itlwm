#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include "../iwx_init_wait.hpp"

namespace {
constexpr uint64_t kPoll = 10;
constexpr uint64_t kTimeout = 100;

struct Clock {
    uint64_t value = 1000;
    uint64_t now() const { return value; }
};

void latchedBeforeWaitIsNotLost()
{
    Clock clock;
    bool ready = true;
    uint32_t sleeps = 0;
    const IwxInitWait::Result result = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t) { ++sleeps; return EWOULDBLOCK; },
        [&]() { return clock.now(); }, kTimeout, kPoll, EWOULDBLOCK, ENXIO);
    assert(result.outcome == IwxInitWait::Outcome::Ready);
    assert(result.sleepCalls == 0 && sleeps == 0);
}

void eventDuringTimedSleepSurvivesLostWakeup()
{
    Clock clock;
    bool ready = false;
    const IwxInitWait::Result result = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t interval) {
            // Model notification arriving after predicate check but before
            // the waiter is actually registered on the sleep channel.
            ready = true;
            clock.value += interval;
            return EWOULDBLOCK;
        },
        [&]() { return clock.now(); }, kTimeout, kPoll, EWOULDBLOCK, ENXIO);
    assert(result.outcome == IwxInitWait::Outcome::Ready);
    assert(result.sleepCalls == 1 && result.elapsedNs == kPoll);
}

void spuriousWakeupsDoNotEndWaitOrExtendDeadline()
{
    Clock clock;
    bool ready = false;
    uint32_t wakes = 0;
    const IwxInitWait::Result result = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t interval) {
            ++wakes;
            // Simulate an unrelated wake every millisecond. The absolute
            // deadline, not wake count, controls how long the wait can run.
            clock.value += interval < 1 ? interval : 1;
            if (wakes == 35)
                ready = true;
            return 0;
        },
        [&]() { return clock.now(); }, kTimeout, kPoll, EWOULDBLOCK, ENXIO);
    assert(result.outcome == IwxInitWait::Outcome::Ready);
    assert(wakes == 35 && result.sleepCalls == wakes);
    assert(result.elapsedNs == 35);

    clock.value = 2000;
    ready = false;
    wakes = 0;
    const IwxInitWait::Result timedOut = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t interval) {
            ++wakes;
            clock.value += interval < 1 ? interval : 1;
            return 0;
        },
        [&]() { return clock.now(); }, kTimeout, kPoll, EWOULDBLOCK, ENXIO);
    assert(timedOut.outcome == IwxInitWait::Outcome::TimedOut);
    assert(timedOut.error == EWOULDBLOCK);
    assert(timedOut.elapsedNs == kTimeout);
    assert(wakes == kTimeout);
}

void cancellationWinsAndStopsOldGenerationWait()
{
    Clock clock;
    bool cancelled = true;
    bool ready = true;
    const IwxInitWait::Result beforeSleep = IwxInitWait::waitFor(
        [&]() { return ready; }, [&]() { return cancelled; },
        [](uint64_t) { return 0; }, [&]() { return clock.now(); },
        kTimeout, kPoll, EWOULDBLOCK, ENXIO);
    assert(beforeSleep.outcome == IwxInitWait::Outcome::Cancelled);
    assert(beforeSleep.error == ENXIO && beforeSleep.sleepCalls == 0);

    cancelled = false;
    ready = false;
    const IwxInitWait::Result whileSleeping = IwxInitWait::waitFor(
        [&]() { return ready; }, [&]() { return cancelled; },
        [&](uint64_t interval) {
            clock.value += interval;
            cancelled = true;
            return 0;
        }, [&]() { return clock.now(); }, kTimeout, kPoll,
        EWOULDBLOCK, ENXIO);
    assert(whileSleeping.outcome == IwxInitWait::Outcome::Cancelled);
    assert(whileSleeping.error == ENXIO && whileSleeping.sleepCalls == 1);
}

void unrelatedWakeupDoesNotMaskTimeoutOrSleepError()
{
    Clock clock;
    bool ready = false;
    const IwxInitWait::Result timeout = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t interval) { clock.value += interval; return EWOULDBLOCK; },
        [&]() { return clock.now(); }, kTimeout, kPoll,
        EWOULDBLOCK, ENXIO);
    assert(timeout.outcome == IwxInitWait::Outcome::TimedOut);
    assert(timeout.sleepCalls == kTimeout / kPoll);
    assert(timeout.elapsedNs == kTimeout);

    const IwxInitWait::Result interrupted = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t interval) { clock.value += interval; return EINTR; },
        [&]() { return clock.now(); }, kTimeout, kPoll,
        EWOULDBLOCK, ENXIO);
    assert(interrupted.outcome == IwxInitWait::Outcome::SleepError);
    assert(interrupted.error == EINTR && interrupted.sleepCalls == 1);
}

void completionObservedAlongsideSleepErrorStillWins()
{
    Clock clock;
    bool ready = false;
    const IwxInitWait::Result result = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [&](uint64_t interval) {
            clock.value += interval;
            ready = true;
            return EINTR;
        }, [&]() { return clock.now(); }, kTimeout, kPoll,
        EWOULDBLOCK, ENXIO);
    assert(result.outcome == IwxInitWait::Outcome::Ready);
    assert(result.error == 0 && result.sleepCalls == 1);
}

void invalidBudgetsFailClosed()
{
    Clock clock;
    bool ready = false;
    const IwxInitWait::Result result = IwxInitWait::waitFor(
        [&]() { return ready; }, []() { return false; },
        [](uint64_t) { return 0; }, [&]() { return clock.now(); },
        0, kPoll, EWOULDBLOCK, ENXIO);
    assert(result.outcome == IwxInitWait::Outcome::Invalid);
}
} // namespace

int main()
{
    latchedBeforeWaitIsNotLost();
    eventDuringTimedSleepSurvivesLostWakeup();
    spuriousWakeupsDoNotEndWaitOrExtendDeadline();
    cancellationWinsAndStopsOldGenerationWait();
    unrelatedWakeupDoesNotMaskTimeoutOrSleepError();
    completionObservedAlongsideSleepErrorStillWins();
    invalidBudgetsFailClosed();
}
