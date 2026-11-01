// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_INIT_WAIT_HPP
#define GEEK_IWX_INIT_WAIT_HPP

#include <stdint.h>

namespace IwxInitWait {

enum class Outcome : uint32_t {
    Ready = 0,
    TimedOut,
    SleepError,
    Cancelled,
    Invalid
};

struct Result {
    Outcome outcome;
    int error;
    uint64_t elapsedNs;
    uint32_t sleepCalls;
};

/*
 * Wait for a latched firmware event.  The caller supplies a monotonic clock,
 * predicate, and bounded sleep primitive so this logic can be exercised
 * without a device.  Polling is intentional: the HAL's wakeup() and
 * tsleep_nsec() do not share an event lock, so a wakeup between predicate
 * evaluation and sleep-queue insertion can be lost.  Short sleeps bound that
 * race without extending the absolute timeout.
 */
template <typename Predicate, typename Cancelled, typename Sleep, typename Clock>
inline Result waitFor(Predicate ready, Cancelled cancelled, Sleep sleep, Clock now,
                      uint64_t timeoutNs, uint64_t pollIntervalNs,
                      int timeoutError, int cancelError)
{
    if (!timeoutNs || !pollIntervalNs || !timeoutError || !cancelError)
        return {Outcome::Invalid, timeoutError, 0, 0};

    const uint64_t startNs = now();
    const uint64_t deadlineNs =
        timeoutNs > UINT64_MAX - startNs ? UINT64_MAX : startNs + timeoutNs;
    uint32_t sleepCalls = 0;

    for (;;) {
        if (cancelled()) {
            const uint64_t endNs = now();
            return {Outcome::Cancelled, cancelError,
                    endNs >= startNs ? endNs - startNs : 0, sleepCalls};
        }
        if (ready()) {
            const uint64_t endNs = now();
            return {Outcome::Ready, 0,
                    endNs >= startNs ? endNs - startNs : 0, sleepCalls};
        }

        const uint64_t currentNs = now();
        if (currentNs >= deadlineNs) {
            const uint64_t elapsedNs = currentNs >= startNs
                ? currentNs - startNs : timeoutNs;
            return {Outcome::TimedOut, timeoutError, elapsedNs, sleepCalls};
        }

        const uint64_t remainingNs = deadlineNs - currentNs;
        const uint64_t intervalNs = remainingNs < pollIntervalNs
            ? remainingNs : pollIntervalNs;
        const int sleepError = sleep(intervalNs);
        if (sleepCalls != UINT32_MAX)
            ++sleepCalls;

        // A completion concurrent with a timed/interrupted sleep is still a
        // completion; acquire through the caller's predicate before deciding.
        if (cancelled()) {
            const uint64_t endNs = now();
            return {Outcome::Cancelled, cancelError,
                    endNs >= startNs ? endNs - startNs : 0, sleepCalls};
        }
        if (ready()) {
            const uint64_t endNs = now();
            return {Outcome::Ready, 0,
                    endNs >= startNs ? endNs - startNs : 0, sleepCalls};
        }
        if (sleepError && sleepError != timeoutError) {
            const uint64_t endNs = now();
            return {Outcome::SleepError, sleepError,
                    endNs >= startNs ? endNs - startNs : 0, sleepCalls};
        }
    }
}

} // namespace IwxInitWait

#endif // GEEK_IWX_INIT_WAIT_HPP
