// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_OUTPUT_KICK_HPP
#define GEEK_IWX_OUTPUT_KICK_HPP

#include <stdint.h>

// Coalesced retry token for ordinary STA output.  The high word carries the
// lifecycle epoch and the low word a request serial; zero means no pending
// kick.  The serial makes a consume CAS unable to erase a newer same-epoch
// request that arrived while a bounded drain was running.  This is finite
// width ABA protection, not an unbounded proof: epoch ordering assumes fewer
// than 2^31 lifecycle transitions can separate live callers, and a 32-bit
// request serial can eventually wrap.  The serial is deliberately not reset
// at lifecycle boundaries, making wrap require 2^32 requests overall.
namespace IwxOutputKick {

static constexpr uint32_t kMaxPublishAttempts = 8;
static constexpr uint32_t kMaxConsumeAttempts = 4;

enum class DrainResult : uint32_t {
    kInvalid = 0,
    kDrained = 1,
    kBudgetExhausted = 2,
    kTemporarilyBlocked = 3
};

inline DrainResult classifyDrain(uint32_t dequeued, uint32_t budget,
                                 DrainResult terminal)
{
    if (terminal != DrainResult::kDrained)
        return terminal;
    return dequeued >= budget ? DrainResult::kBudgetExhausted :
        DrainResult::kDrained;
}

inline bool shouldRetry(DrainResult result)
{
    return result == DrainResult::kBudgetExhausted ||
        result == DrainResult::kTemporarilyBlocked;
}

inline bool shouldContinueImmediately(DrainResult result)
{
    return result == DrainResult::kBudgetExhausted;
}

inline uint64_t makeTag(uint32_t epoch, uint32_t serial)
{
    return (uint64_t(epoch) << 32) | uint64_t(serial);
}

inline uint32_t tagEpoch(uint64_t tag)
{
    return static_cast<uint32_t>(tag >> 32);
}

inline uint32_t tagSerial(uint64_t tag)
{
    return static_cast<uint32_t>(tag);
}

inline uint32_t nextSerial(uint32_t *serial)
{
    if (!serial)
        return 0;
    uint32_t value = __atomic_add_fetch(serial, 1U, __ATOMIC_ACQ_REL);
    // Keep zero reserved for an empty token, but do not claim this prevents
    // eventual ABA after a full 32-bit request cycle.
    if (value == 0)
        value = __atomic_add_fetch(serial, 1U, __ATOMIC_ACQ_REL);
    return value;
}

// Called after the nonblocking main-gate attempt has returned.  The epoch is
// read without touching sc_generation; lifecycle changes publish their own
// atomic epoch.  Rechecking after the CAS closes a publish-vs-stop race.
inline bool requestAtEpoch(uint64_t *state, uint32_t *serial,
                           const uint32_t *currentEpoch, uint32_t epoch)
{
    if (!state || !serial || !currentEpoch)
        return false;
    if (__atomic_load_n(currentEpoch, __ATOMIC_ACQUIRE) != epoch)
        return false;
    const uint32_t requestSerial = nextSerial(serial);
    if (requestSerial == 0)
        return false;
    const uint64_t candidate = makeTag(epoch, requestSerial);
    uint64_t previous = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (uint32_t attempt = 0; attempt < kMaxPublishAttempts; ++attempt) {
        if (__atomic_load_n(currentEpoch, __ATOMIC_ACQUIRE) != epoch)
            return false;
        if (previous != 0) {
            const int32_t epochDelta = static_cast<int32_t>(
                epoch - tagEpoch(previous));
            if (epochDelta < 0)
                return false; // delayed caller from an older lifecycle
            if (epochDelta == 0 && static_cast<int32_t>(
                    requestSerial - tagSerial(previous)) <= 0)
                return false;
        }
        if (__atomic_compare_exchange_n(state, &previous, candidate, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            if (__atomic_load_n(currentEpoch, __ATOMIC_ACQUIRE) == epoch)
                return true;
            uint64_t published = candidate;
            __atomic_compare_exchange_n(state, &published, uint64_t(0), false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            return false;
        }
    }
    return false;
}

inline bool request(uint64_t *state, uint32_t *serial,
                    const uint32_t *currentEpoch)
{
    if (!currentEpoch)
        return false;
    const uint32_t epoch = __atomic_load_n(currentEpoch, __ATOMIC_ACQUIRE);
    return requestAtEpoch(state, serial, currentEpoch, epoch);
}

// Called only while the caller owns the main radio gate and lifecycle fence.
// A stale token is discarded; a future token is left untouched defensively.
inline bool takeForEpoch(uint64_t *state, uint32_t epoch, uint64_t *takenTag)
{
    if (!state)
        return false;
    uint64_t current = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (uint32_t attempt = 0; attempt < kMaxConsumeAttempts; ++attempt) {
        if (current == 0)
            return false;
        const int32_t epochDelta = static_cast<int32_t>(
            epoch - tagEpoch(current));
        if (epochDelta < 0)
            return false;
        if (__atomic_compare_exchange_n(state, &current, uint64_t(0), false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            if (epochDelta == 0) {
                if (takenTag)
                    *takenTag = current;
                return true;
            }
            return false;
        }
    }
    return false;
}

inline void clearOlderEpoch(uint64_t *state, uint32_t epoch)
{
    if (!state)
        return;
    uint64_t current = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    for (uint32_t attempt = 0; attempt < kMaxConsumeAttempts && current != 0;
         ++attempt) {
        if (static_cast<int32_t>(epoch - tagEpoch(current)) <= 0)
            return;
        if (__atomic_compare_exchange_n(state, &current, uint64_t(0), false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
    }
}

inline bool hasPendingForEpoch(const uint64_t *state, uint32_t epoch)
{
    if (!state)
        return false;
    const uint64_t current = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    return current != 0 && tagEpoch(current) == epoch;
}

} // namespace IwxOutputKick

#endif // GEEK_IWX_OUTPUT_KICK_HPP
