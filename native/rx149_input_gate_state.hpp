// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

// One lock-free word serializes RX149 fault invalidation, DLIL input tickets,
// and recovery. Keeping the fault version in the same CAS word prevents an
// already-blocked fast invalidation from being lost when a later recovery
// clears the gate.
namespace NativeAwdlBSD {
namespace Rx149InputGateState {

using Word = uint64_t;

constexpr Word kBlockedBit = Word{1} << 63;
constexpr Word kPermanentBit = Word{1} << 62;
constexpr unsigned kFaultSerialShift = 31;
constexpr uint32_t kMaxFaultSerial = 0x7fffffffu;
constexpr Word kTicketMask = 0x7fffffffull;
constexpr Word kFaultSerialMask =
    Word{kMaxFaultSerial} << kFaultSerialShift;

static_assert(__atomic_always_lock_free(sizeof(Word), nullptr),
              "RX149 interrupt fence requires lock-free 64-bit atomics");

inline uint32_t faultSerial(Word value) {
    return uint32_t((value & kFaultSerialMask) >> kFaultSerialShift);
}

inline uint32_t ticketCount(Word value) {
    return uint32_t(value & kTicketMask);
}

inline bool blocked(Word value) {
    return (value & (kBlockedBit | kPermanentBit)) != 0;
}

inline bool permanentlyBlocked(Word value) {
    return (value & kPermanentBit) != 0;
}

// The invalidator never takes a lock, reads a clock, walks a queue, or waits
// on a worker. CAS contention retries with the newest word so every fault
// advances the serial until the saturating fail-closed state is reached.
inline uint32_t invalidate(Word *state) {
    if (!state)
        return 0;
    Word observed = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (;;) {
        Word desired = observed | kBlockedBit;
        const uint32_t serial = faultSerial(observed);
        if (permanentlyBlocked(observed)) {
            // Keep the terminal fail-closed state unchanged.
        } else if (serial == kMaxFaultSerial) {
            // There is no safe serial left with which to distinguish future
            // faults from an old recovery proof. Permanently retain the fence.
            desired |= kPermanentBit;
        } else {
            desired = (desired & ~kFaultSerialMask) |
                (Word{serial + 1u} << kFaultSerialShift);
        }
        if (__atomic_compare_exchange_n(state, &observed, desired, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return faultSerial(desired);
    }
}

inline bool reserveTicket(Word *state) {
    if (!state)
        return false;
    Word observed = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (;;) {
        if (blocked(observed) || ticketCount(observed) == kTicketMask)
            return false;
        const Word desired = observed + 1u;
        if (__atomic_compare_exchange_n(state, &observed, desired, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
}

// A ticket owner releases exactly once. Refuse an underflow instead of
// changing the fault serial or accidentally reopening the blocked gate.
inline bool releaseTicket(Word *state) {
    if (!state)
        return false;
    Word observed = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (;;) {
        if (ticketCount(observed) == 0)
            return false;
        const Word desired = observed - 1u;
        if (__atomic_compare_exchange_n(state, &observed, desired, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
}

// Clear only the blocked bit after the caller has independently verified
// initialization and drained bridge-owned resources. The exact serial and
// zero-ticket condition are rechecked atomically; a newer invalidation wins.
inline bool recover(Word *state, uint32_t expectedFaultSerial) {
    if (!state || expectedFaultSerial == 0)
        return false;
    Word observed = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (;;) {
        if (!blocked(observed) || permanentlyBlocked(observed) ||
            faultSerial(observed) != expectedFaultSerial ||
            ticketCount(observed) != 0)
            return false;
        const Word desired = observed & ~kBlockedBit;
        if (__atomic_compare_exchange_n(state, &observed, desired, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
}

} // namespace Rx149InputGateState
} // namespace NativeAwdlBSD
