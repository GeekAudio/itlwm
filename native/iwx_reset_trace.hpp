// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_RESET_TRACE_HPP
#define GEEK_IWX_RESET_TRACE_HPP

#include <stdint.h>

// Fixed-size, allocation-free diagnostics for Tahoe iwx stop/recovery paths.
// Reset writers are serialized by ItlIwx's existing lifecycle fence. Readers
// use a bounded sequence check and never acquire that fence.
namespace IwxResetTrace {

// Values are published through IORegistry. Keep existing values stable and
// append new values only; zero remains the compatibility/default bucket.
enum class ResetReason : uint32_t {
    kUnknown = 0,
    kAdapterDisableQuiesce = 1,
    kIfFlagsDown = 2,
    kMediaChange = 3,
    kIoctlEnetReset = 4,
    kInitTaskRunningRecovery = 5,
    kInitHardwareFailureCleanup = 6,
    kInitialScanFailureCleanup = 7,
    kInitialScanWaitInterrupted = 8,
    kInitTaskNotRunningRecovery = 9,
    kCount = 10
};

// These are sources that requested/queued init_task. They are intentionally
// independent of ResetReason: queueing may coalesce and is not paired with a
// later reset event. Values are also stable once published.
enum class InitTaskTrigger : uint32_t {
    kUnknown = 0,
    kNewStateError = 1,
    kTxWatchdogTimeout = 2,
    kCriticalTemperature = 3,
    kLegacyRfKill = 4,
    kLegacyFirmwareSwError = 5,
    kLegacyHardwareError = 6,
    kMsixFirmwareSwError = 7,
    kMsixRfKill = 8,
    kMsixHardwareError = 9,
    kWakeupDeferred = 10,
    kLifecycleFenceRetry = 11,
    kCount = 12
};

static constexpr uint32_t kResetReasonCount =
    static_cast<uint32_t>(ResetReason::kCount);
static constexpr uint32_t kInitTaskTriggerCount =
    static_cast<uint32_t>(InitTaskTrigger::kCount);
static constexpr uint32_t kReadAttempts = 4;

struct Snapshot {
    uint32_t resetSequence;
    uint32_t lastResetReason;
    uint32_t generation;
    uint32_t driverFlags;
    uint32_t interfaceFlags;
    uint32_t ieee80211State;
    uint32_t initStage;
    uint32_t initError;
    uint32_t resetReasonCounts[kResetReasonCount];

    // The trigger source is the latest recorded queue/defer source. It is not
    // a causal attribution for any particular RESET_BEGIN.
    uint32_t lastInitTaskTriggerSequence;
    uint32_t lastInitTaskTrigger;
    uint32_t initTaskTriggerRevision;
    uint32_t initTaskTriggerCounts[kInitTaskTriggerCount];
};

class Trace {
public:
    uint32_t recordReset(ResetReason reason, uint32_t generation,
                         uint32_t driverFlags, uint32_t interfaceFlags,
                         uint32_t ieee80211State, uint32_t initStage,
                         uint32_t initError)
    {
        const uint32_t reasonIndex = indexFor(reason, kResetReasonCount);

        // RESET_BEGIN sites run under the existing per-device lifecycle
        // fence. A single-writer odd/even version protects the whole numeric
        // snapshot from the independent main-workloop reader.
        __atomic_fetch_add(&resetSnapshotVersion_, 1U, __ATOMIC_SEQ_CST);
        const uint32_t sequence = __atomic_add_fetch(
            &resetSequence_, 1U, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(&resetReasonCounts_[reasonIndex], 1U,
                           __ATOMIC_SEQ_CST);
        __atomic_store_n(&lastResetReason_, reasonIndex, __ATOMIC_SEQ_CST);
        __atomic_store_n(&generation_, generation, __ATOMIC_SEQ_CST);
        __atomic_store_n(&driverFlags_, driverFlags, __ATOMIC_SEQ_CST);
        __atomic_store_n(&interfaceFlags_, interfaceFlags, __ATOMIC_SEQ_CST);
        __atomic_store_n(&ieee80211State_, ieee80211State, __ATOMIC_SEQ_CST);
        __atomic_store_n(&initStage_, initStage, __ATOMIC_SEQ_CST);
        __atomic_store_n(&initError_, initError, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(&resetSnapshotVersion_, 1U, __ATOMIC_SEQ_CST);
        return sequence;
    }

    uint32_t recordInitTaskTrigger(InitTaskTrigger trigger)
    {
        const uint32_t sequence = reserveInitTaskTriggerSequence();
        completeInitTaskTrigger(sequence, trigger);
        return sequence;
    }

    // Kept separate so a caller/test can model a producer delayed between
    // reserving its order and completing publication. The trigger revision
    // advances only after its count and latest-source CAS have completed.
    uint32_t reserveInitTaskTriggerSequence()
    {
        return __atomic_add_fetch(&initTaskTriggerSequence_, 1U,
                                  __ATOMIC_SEQ_CST);
    }

    void completeInitTaskTrigger(uint32_t sequence, InitTaskTrigger trigger)
    {
        const uint32_t triggerIndex = indexFor(trigger, kInitTaskTriggerCount);
        __atomic_fetch_add(&initTaskTriggerCounts_[triggerIndex], 1U,
                           __ATOMIC_SEQ_CST);

        // Publish source and sequence as one word. A delayed lower-sequence
        // writer cannot overwrite a more recent trigger from another CPU.
        const uint64_t candidate = (uint64_t(sequence) << 32) | triggerIndex;
        uint64_t previous = __atomic_load_n(&lastInitTaskTriggerTag_,
                                            __ATOMIC_ACQUIRE);
        while (static_cast<uint32_t>(previous >> 32) < sequence) {
            if (__atomic_compare_exchange_n(&lastInitTaskTriggerTag_,
                    &previous, candidate, false, __ATOMIC_ACQ_REL,
                    __ATOMIC_ACQUIRE))
                break;
        }
        __atomic_add_fetch(&initTaskTriggerRevision_, 1U, __ATOMIC_SEQ_CST);
    }

    // Bounded read: a busy writer causes a false return and the next existing
    // watchdog/main-gate drain retries. All snapshot words are atomic so the
    // reader is race-free even when it has to discard an inconsistent pass.
    bool read(Snapshot *out) const
    {
        if (!out)
            return false;
        for (uint32_t attempt = 0; attempt < kReadAttempts; ++attempt) {
            const uint32_t before = __atomic_load_n(
                &resetSnapshotVersion_, __ATOMIC_SEQ_CST);
            if (before & 1U)
                continue;

            Snapshot value{};
            value.resetSequence = __atomic_load_n(
                &resetSequence_, __ATOMIC_SEQ_CST);
            value.lastResetReason = __atomic_load_n(
                &lastResetReason_, __ATOMIC_SEQ_CST);
            value.generation = __atomic_load_n(&generation_, __ATOMIC_SEQ_CST);
            value.driverFlags = __atomic_load_n(&driverFlags_, __ATOMIC_SEQ_CST);
            value.interfaceFlags = __atomic_load_n(&interfaceFlags_, __ATOMIC_SEQ_CST);
            value.ieee80211State = __atomic_load_n(
                &ieee80211State_, __ATOMIC_SEQ_CST);
            value.initStage = __atomic_load_n(&initStage_, __ATOMIC_SEQ_CST);
            value.initError = __atomic_load_n(&initError_, __ATOMIC_SEQ_CST);
            for (uint32_t i = 0; i < kResetReasonCount; ++i)
                value.resetReasonCounts[i] = __atomic_load_n(
                    &resetReasonCounts_[i], __ATOMIC_SEQ_CST);

            const uint32_t triggerRevisionBefore = __atomic_load_n(
                &initTaskTriggerRevision_, __ATOMIC_SEQ_CST);
            const uint64_t triggerTag = __atomic_load_n(
                &lastInitTaskTriggerTag_, __ATOMIC_ACQUIRE);
            value.lastInitTaskTriggerSequence =
                static_cast<uint32_t>(triggerTag >> 32);
            value.lastInitTaskTrigger = static_cast<uint32_t>(triggerTag);
            for (uint32_t i = 0; i < kInitTaskTriggerCount; ++i)
                value.initTaskTriggerCounts[i] = __atomic_load_n(
                    &initTaskTriggerCounts_[i], __ATOMIC_SEQ_CST);
            const uint32_t triggerRevisionAfter = __atomic_load_n(
                &initTaskTriggerRevision_, __ATOMIC_SEQ_CST);
            if (triggerRevisionBefore != triggerRevisionAfter)
                continue;
            value.initTaskTriggerRevision = triggerRevisionAfter;

            const uint32_t after = __atomic_load_n(
                &resetSnapshotVersion_, __ATOMIC_SEQ_CST);
            if (before == after && !(after & 1U)) {
                *out = value;
                return true;
            }
        }
        return false;
    }

private:
    template <typename Enum>
    static uint32_t indexFor(Enum value, uint32_t count)
    {
        const uint32_t index = static_cast<uint32_t>(value);
        return index < count ? index : 0U;
    }

    uint32_t resetSnapshotVersion_ {0};
    uint32_t resetSequence_ {0};
    uint32_t lastResetReason_ {0};
    uint32_t generation_ {0};
    uint32_t driverFlags_ {0};
    uint32_t interfaceFlags_ {0};
    uint32_t ieee80211State_ {0};
    uint32_t initStage_ {0};
    uint32_t initError_ {0};
    uint32_t resetReasonCounts_[kResetReasonCount] {};

    uint32_t initTaskTriggerSequence_ {0};
    uint32_t initTaskTriggerRevision_ {0};
    uint64_t lastInitTaskTriggerTag_ {0};
    uint32_t initTaskTriggerCounts_[kInitTaskTriggerCount] {};
};

} // namespace IwxResetTrace

#endif
