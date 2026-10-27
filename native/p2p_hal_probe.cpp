// SPDX-License-Identifier: GPL-2.0-only
#include "p2p_hal_probe.hpp"

namespace NativeP2PProbe {
namespace {

constexpr int32_t kNotRun = -1;

} // namespace

BlockedReason admissionBlockReason(const Admission &a, bool requireQueueLease)
{
    if (!a.enabled) return kProbeDisabled;
    if (!a.mainGateAvailable) return kMainGateUnavailable;
    if (!a.mainGateNotOnThread) return kMainGateOnThread;
    if (!a.driverRunning) return kDriverNotRunning;
    if (!a.associated) return kNotAssociated;
    if (!a.portAuthorized) return kPortUnauthorized;
    if (!a.scanIdle) return kScanBusy;
    if (!a.commandQueueIdle) return kCommandBusy;
    if (requireQueueLease &&
        (!a.stateQueuePaused || !a.noPendingNewstate))
        return kStateQueueBusy;
    if (!a.radioAvailable) return kRadioKilled;
    if (!a.firmwareHealthy) return kShutdownOrHardwareError;
    if (!a.p2pContextAbsent) return kP2pContextOwned;
    if (!a.p2pCapabilityAvailable) return kP2pCapabilityUnavailable;
    if (!a.contextGeneration) return kGenerationChanged;
    return kNotBlocked;
}

BlockedReason revalidationBlockReason(const Revalidation &s,
                                     bool afterAddAcknowledgement)
{
    if (!s.generationMatches ||
        (afterAddAcknowledgement && !s.p2pGenerationMatches))
        return kGenerationChanged;
    if (!s.radioAvailable) return kRadioKilled;
    if (!s.firmwareHealthy) return kShutdownOrHardwareError;
    if (!s.driverRunning) return kDriverNotRunning;
    if (!s.associated) return kNotAssociated;
    if (!s.portAuthorized) return kPortUnauthorized;
    if (!s.scanIdle) return kScanBusy;
    if (!s.commandQueueIdle) return kCommandBusy;
    if (!s.stateQueuePaused || !s.noPendingNewstate)
        return kStateQueueBusy;
    if (afterAddAcknowledgement) {
        if (!s.p2pContextInitialized || !s.addAcknowledged ||
            !s.p2pMacActive || !s.p2pBindingAbsent)
            return kFirmwareOutcomeUnknown;
    } else if (s.p2pContextInitialized || !s.p2pMacAbsent ||
               !s.p2pBindingAbsent) {
        return kP2pContextOwned;
    }
    return kNotBlocked;
}

bool commandOwnerAllowed(bool probeBusy, const void *ownerThread,
                         const void *currentThread, bool onMainWorkLoop,
                         bool inMainGate)
{
    return probeBusy && ownerThread != nullptr && ownerThread == currentThread &&
           !onMainWorkLoop && !inMainGate;
}

bool genericCommandBlocked(bool probeBusy, const void *ownerThread,
                           const void *currentThread, bool onMainWorkLoop,
                           bool inMainGate)
{
    return probeBusy && !commandOwnerAllowed(probeBusy, ownerThread,
        currentThread, onMainWorkLoop, inMainGate);
}

namespace {

BlockedReason transientReason(BlockedReason reason)
{
    switch (reason) {
        case kMainGateUnavailable:
        case kMainGateOnThread:
        case kDriverNotRunning:
        case kNotAssociated:
        case kPortUnauthorized:
        case kScanBusy:
        case kCommandBusy:
        case kStateQueueBusy:
        case kP2pCapabilityUnavailable:
        case kProbeDisabled:
        case kGateActionFailed:
        case kProbeQueueBusy:
        case kCanceledBeforeStart:
            return reason;
        default:
            return kNotBlocked;
    }
}

} // namespace

Controller::Controller()
    : state_(kIdle), attempted_(0), addResult_(kNotRun),
      removeResult_(kNotRun), blocked_(kNotBlocked), contextGeneration_(0),
      powerGeneration_(0), stationGeneration_(0), resourceMayExist_(0)
{
}

bool Controller::terminal() const
{
    const uint32_t state = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
    return state == kComplete || state == kQuarantined ||
           state == kResetDrained;
}

void Controller::storeState(uint32_t state, uint32_t blocked)
{
    __atomic_store_n(&blocked_, blocked, __ATOMIC_RELAXED);
    __atomic_store_n(&state_, state, __ATOMIC_RELEASE);
}

void Controller::quarantine(uint32_t blocked, bool resourceMayExist)
{
    __atomic_store_n(&resourceMayExist_, resourceMayExist ? 1u : 0u,
                     __ATOMIC_RELAXED);
    storeState(kQuarantined, blocked);
}

bool Controller::tryQueue(const Admission &admission,
                          BlockedReason overrideReason)
{
    if (terminal() || __atomic_load_n(&attempted_, __ATOMIC_ACQUIRE))
        return false;
    const uint32_t state = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
    if (state == kQueued || state == kAdding || state == kAdded ||
        state == kRemoving)
        return false;

    BlockedReason reason = overrideReason == kNotBlocked
        ? admissionBlockReason(admission, true) : overrideReason;
    if (reason != kNotBlocked) {
        const BlockedReason transient = transientReason(reason);
        if (transient != kNotBlocked) {
            storeState(reason == kProbeDisabled ? kDisabled : kDeferred, reason);
        } else {
            quarantine(reason, false);
        }
        return false;
    }

    __atomic_store_n(&contextGeneration_, admission.contextGeneration,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&powerGeneration_, admission.powerGeneration,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&stationGeneration_, admission.stationGeneration,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&resourceMayExist_, 0u, __ATOMIC_RELAXED);
    storeState(kQueued, kNotBlocked);
    return true;
}

void Controller::cancelQueued()
{
    if (__atomic_load_n(&state_, __ATOMIC_ACQUIRE) == kQueued &&
        !__atomic_load_n(&attempted_, __ATOMIC_ACQUIRE))
        storeState(kDeferred, kCanceledBeforeStart);
}

RunResult Controller::executeOnce(const Operations &ops)
{
    if (__atomic_load_n(&state_, __ATOMIC_ACQUIRE) != kQueued)
        return RunResult::kNotQueued;
    if (!ops.revalidate || !ops.configure || !ops.add || !ops.remove ||
        !ops.publishLease) {
        quarantine(kGateActionFailed, false);
        return RunResult::kQuarantined;
    }

    const uint32_t powerGeneration =
        __atomic_load_n(&powerGeneration_, __ATOMIC_ACQUIRE);
    const uint32_t stationGeneration =
        __atomic_load_n(&stationGeneration_, __ATOMIC_ACQUIRE);
    BlockedReason reason = ops.revalidate(ops.context, powerGeneration,
                                           stationGeneration);
    if (reason != kNotBlocked) {
        if (transientReason(reason) != kNotBlocked) {
            storeState(kDeferred, reason);
            return RunResult::kDeferred;
        }
        quarantine(reason, false);
        return RunResult::kQuarantined;
    }

    const int configureResult = ops.configure(ops.context);
    if (configureResult != 0) {
        storeState(kDeferred, kConfigureRejected);
        return RunResult::kDeferred;
    }

    // Mark before entering the synchronous command. Any nonzero result may
    // mean that firmware applied the command but the host lost its ACK.
    __atomic_store_n(&attempted_, 1u, __ATOMIC_RELEASE);
    storeState(kAdding, kNotBlocked);
    const int addResult = ops.add(ops.context);
    __atomic_store_n(&addResult_, addResult, __ATOMIC_RELAXED);
    if (addResult != 0) {
        if (!ops.publishLease(ops.context, true)) {
            quarantine(kGateActionFailed, true);
            return RunResult::kQuarantined;
        }
        quarantine(kFirmwareOutcomeUnknown, true);
        return RunResult::kQuarantined;
    }

    __atomic_store_n(&resourceMayExist_, 1u, __ATOMIC_RELAXED);
    storeState(kAdded, kNotBlocked);
    if (!ops.publishLease(ops.context, true)) {
        quarantine(kGateActionFailed, true);
        return RunResult::kQuarantined;
    }

    reason = ops.revalidate(ops.context, powerGeneration, stationGeneration);
    if (reason != kNotBlocked) {
        quarantine(reason, true);
        return RunResult::kQuarantined;
    }

    if (ops.exercise && ops.exercise(ops.context) != 0) {
        quarantine(kExerciseOutcomeUnknown, true);
        return RunResult::kQuarantined;
    }
    // The optional exercise can hold a separate PHY/binding/TE lease. It must
    // return only after a safe cleanup, then pass the original radio guards.
    if (ops.exercise) {
        reason = ops.revalidate(ops.context, powerGeneration, stationGeneration);
        if (reason != kNotBlocked) {
            quarantine(reason, true);
            return RunResult::kQuarantined;
        }
    }
    storeState(kRemoving, kNotBlocked);
    const int removeResult = ops.remove(ops.context);
    __atomic_store_n(&removeResult_, removeResult, __ATOMIC_RELAXED);
    if (removeResult != 0) {
        if (!ops.publishLease(ops.context, true)) {
            quarantine(kGateActionFailed, true);
            return RunResult::kQuarantined;
        }
        quarantine(kFirmwareOutcomeUnknown, true);
        return RunResult::kQuarantined;
    }

    __atomic_store_n(&resourceMayExist_, 0u, __ATOMIC_RELAXED);
    if (!ops.publishLease(ops.context, false)) {
        quarantine(kGateActionFailed, false);
        return RunResult::kQuarantined;
    }
    storeState(kComplete, kNotBlocked);
    return RunResult::kCompleted;
}

void Controller::resetDrained(uint32_t newPowerGeneration)
{
    __atomic_store_n(&powerGeneration_, newPowerGeneration, __ATOMIC_RELAXED);
    uint32_t nextContextGeneration =
        __atomic_load_n(&contextGeneration_, __ATOMIC_RELAXED) + 1;
    if (nextContextGeneration == 0)
        nextContextGeneration = 1;
    __atomic_store_n(&contextGeneration_, nextContextGeneration,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&resourceMayExist_, 0u, __ATOMIC_RELAXED);
    const uint32_t state = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
    if (state == kQuarantined)
        storeState(kResetDrained, kResetDrainedReason);
}

void Controller::markGateActionFailed()
{
    quarantine(kGateActionFailed,
               __atomic_load_n(&resourceMayExist_, __ATOMIC_ACQUIRE) != 0);
}

Snapshot Controller::snapshot() const
{
    Snapshot out{};
    out.state = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
    out.attempted = __atomic_load_n(&attempted_, __ATOMIC_ACQUIRE);
    out.addResult = __atomic_load_n(&addResult_, __ATOMIC_RELAXED);
    out.removeResult = __atomic_load_n(&removeResult_, __ATOMIC_RELAXED);
    out.blocked = __atomic_load_n(&blocked_, __ATOMIC_RELAXED);
    out.contextGeneration = __atomic_load_n(&contextGeneration_, __ATOMIC_RELAXED);
    out.powerGeneration = __atomic_load_n(&powerGeneration_, __ATOMIC_RELAXED);
    out.stationGeneration = __atomic_load_n(&stationGeneration_, __ATOMIC_RELAXED);
    out.resourceMayExist = __atomic_load_n(&resourceMayExist_, __ATOMIC_RELAXED);
    return out;
}

} // namespace NativeP2PProbe
