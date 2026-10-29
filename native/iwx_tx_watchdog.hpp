// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_WATCHDOG_HPP
#define GEEK_IWX_TX_WATCHDOG_HPP

#include <stdint.h>

// The timer is touched by TX submission/completion on the radio workloop and
// by stop on a lifecycle worker. Use atomics for the scalar itself; Tahoe's
// timeout decision additionally runs through the radio command gate so it is
// serialized with RX completion notifications.
namespace IwxTxWatchdog {

static constexpr int32_t kTimeoutSeconds = 15;
static constexpr uint32_t kMaxAdvanceAttempts = 4;

enum class TickResult : uint32_t {
    kDeferred = 0,
    kIdle = 1,
    kRearm = 2,
    kExpired = 3
};

inline bool shouldEnqueueRecovery(TickResult tick, bool shutdown)
{
    return tick == TickResult::kExpired && !shutdown;
}

inline void arm(int32_t *countdown)
{
    if (countdown)
        __atomic_store_n(countdown, kTimeoutSeconds, __ATOMIC_RELEASE);
}

inline void clear(int32_t *countdown)
{
    if (countdown)
        __atomic_store_n(countdown, 0, __ATOMIC_RELEASE);
}

// Do not consume a deadline when the caller cannot prove it is in the
// serialized radio context. Bounded CAS retries keep this suitable for the
// watchdog path; contention defers one tick instead of forcing recovery.
inline TickResult advance(int32_t *countdown, bool serializedContext)
{
    if (!countdown || !serializedContext)
        return TickResult::kDeferred;

    int32_t current = __atomic_load_n(countdown, __ATOMIC_ACQUIRE);
    for (uint32_t attempt = 0; attempt < kMaxAdvanceAttempts; ++attempt) {
        if (current <= 0)
            return TickResult::kIdle;
        const int32_t next = current > 1 ? current - 1 : 0;
        if (__atomic_compare_exchange_n(countdown, &current, next, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return current > 1 ? TickResult::kRearm : TickResult::kExpired;
    }
    return TickResult::kDeferred;
}

} // namespace IwxTxWatchdog

#endif // GEEK_IWX_TX_WATCHDOG_HPP
