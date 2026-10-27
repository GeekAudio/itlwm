// SPDX-License-Identifier: GPL-2.0-only
#include "intel_awdl_context.hpp"

#include <cstring>

namespace IntelAwdl {
namespace {

constexpr std::uint8_t kDriverMacCount = 4; // if_iwxreg.h: IWX_NUM_MAC_INDEX_DRIVER
constexpr std::uint8_t kPhyContextCount = 3; // if_iwxreg.h: IWX_NUM_PHY_CTX
constexpr std::uint8_t kP2pDeviceQueue = 2; // if_iwxreg.h: IWX_DQA_P2P_DEVICE_QUEUE
constexpr std::uint32_t kP2pDeviceDiscoverableEvent = 4; // IWX_TE_P2P_DEVICE_DISCOVERABLE

bool ValidUnicastAddress(const std::uint8_t address[6])
{
    std::uint8_t any = 0;
    for (std::size_t i = 0; i < 6; ++i)
        any |= address[i];
    return any != 0 && (address[0] & 1U) == 0;
}

std::uint32_t MacIdAndColor(const Context &context)
{
    return static_cast<std::uint32_t>(context.macId) |
           (static_cast<std::uint32_t>(context.macColor) << 8);
}

} // namespace

ContextLease::ContextLease() = default;

bool ContextLease::operationTableValid(const Operations &ops) const
{
    return ops.leasePhy && ops.releasePhy && ops.addP2pDeviceMac && ops.removeMac &&
           ops.addBinding && ops.removeBinding && ops.addP2pStation && ops.removeStation &&
           ops.enableP2pDeviceQueue && ops.disableP2pDeviceQueue &&
           ops.addTimeEvent && ops.removeTimeEvent;
}

bool ContextLease::generationsMatch(const Admission &admission) const
{
    return admission.powerGeneration == context_.powerGeneration &&
           admission.stationGeneration == context_.stationGeneration;
}

Result ContextLease::acquire(const Admission &admission, const Context &context,
                             const Operations &ops)
{
    if (state_ != State::kIdle)
        return Result::kBusy;
    if (!operationTableValid(ops) || context.generation == 0 ||
        context.powerGeneration != admission.powerGeneration ||
        context.stationGeneration != admission.stationGeneration ||
        context.channel == 0 || context.channel != admission.awdlChannel ||
        context.macId >= kDriverMacCount || context.macId == admission.stationMacId ||
        context.phyId >= kPhyContextCount || context.phyId == admission.stationPhyId ||
        context.queueId != kP2pDeviceQueue || !ValidUnicastAddress(context.address))
        return Result::kInvalid;
    if (!admission.controllerReady || !admission.stationReady ||
        !admission.p2pFirmwareCapability || !admission.dynamicQueueEnabled ||
        !admission.scanIdle || admission.shutdown || admission.radioKilled)
        return Result::kNotReady;
    if (admission.stationChannel != context.channel &&
        !admission.compatibleChannelLeaseAvailable)
        return Result::kBusy;
    if (admission.monitorInjectionQueueInUse)
        return Result::kBusy;

    context_ = context;
    state_ = State::kCleanupRequired;
    Result result = ops.leasePhy(ops.context, context_);
    if (result == Result::kSuccess || result == Result::kNeedsCleanup)
        phyLeased_ = true;
    if (result == Result::kSuccess) {
        result = ops.addP2pDeviceMac(ops.context, context_);
        if (result == Result::kSuccess || result == Result::kNeedsCleanup)
            macAdded_ = true;
    }
    if (result == Result::kSuccess) {
        result = ops.addBinding(ops.context, context_);
        if (result == Result::kSuccess || result == Result::kNeedsCleanup)
            bindingAdded_ = true;
    }
    if (result == Result::kSuccess) {
        result = ops.addP2pStation(ops.context, context_);
        if (result == Result::kSuccess || result == Result::kNeedsCleanup)
            stationAdded_ = true;
    }
    if (result == Result::kSuccess) {
        result = ops.enableP2pDeviceQueue(ops.context, context_);
        if (result == Result::kSuccess || result == Result::kNeedsCleanup)
            queueEnabled_ = true;
    }

    if (result != Result::kSuccess) {
        const Result cleanup = releaseResources(ops);
        if (cleanup != Result::kSuccess)
            return Result::kNeedsCleanup;
        state_ = State::kIdle;
        context_ = {};
        return result;
    }

    state_ = State::kResourcesReady;
    return Result::kSuccess;
}

Result ContextLease::armTimeEvent(const Admission &admission,
                                  std::uint32_t durationMs,
                                  const Operations &ops)
{
    if (state_ != State::kResourcesReady || !operationTableValid(ops))
        return state_ == State::kIdle ? Result::kNotReady : Result::kBusy;
    if (!generationsMatch(admission) || !admission.controllerReady ||
        !admission.stationReady || !admission.scanIdle || admission.shutdown ||
        admission.radioKilled || !admission.p2pFirmwareCapability ||
        !admission.dynamicQueueEnabled || durationMs == 0)
        return Result::kNotReady;
    if (admission.stationChannel != context_.channel &&
        !admission.compatibleChannelLeaseAvailable)
        return Result::kBusy;

    TimeEventResponse response{};
    const Result result = ops.addTimeEvent(ops.context, context_, durationMs, &response);
    if (result == Result::kNeedsCleanup) {
        // A timed-out firmware command may have been applied. Keep every
        // dependency leased and permit only a matching cleanup or hard reset.
        timeEventSubmitted_ = true;
        timeEventUid_ = response.uniqueId;
        timeEventIdentityKnown_ = response.rawEventType == kP2pDeviceDiscoverableEvent &&
            response.rawMacIdAndColor == MacIdAndColor(context_);
        rawTimeEventStatus_ = response.rawStatus;
        state_ = State::kCleanupRequired;
        return Result::kNeedsCleanup;
    }
    if (result != Result::kSuccess)
        return result;

    // TIME_EVENT status semantics conflict across available consumers. Preserve
    // the field; only a matching START notification proves that it ran.
    if (response.rawEventType != kP2pDeviceDiscoverableEvent ||
        response.rawMacIdAndColor != MacIdAndColor(context_)) {
        timeEventSubmitted_ = true;
        timeEventUid_ = response.uniqueId;
        timeEventIdentityKnown_ = false;
        rawTimeEventStatus_ = response.rawStatus;
        state_ = State::kCleanupRequired;
        return Result::kNeedsCleanup;
    }
    timeEventSubmitted_ = true;
    timeEventUid_ = response.uniqueId; // UID 0 is retained as a raw value.
    timeEventIdentityKnown_ = true;
    rawTimeEventStatus_ = response.rawStatus;
    state_ = State::kAwaitingStart;
    return Result::kNotReady;
}

Result ContextLease::onNotification(const Admission &admission,
                                    const TimeEventNotification &notification,
                                    const Operations &ops)
{
    if (!operationTableValid(ops))
        return Result::kInvalid;
    if (!timeEventSubmitted_ || !timeEventIdentityKnown_ ||
        notification.generation != context_.generation ||
        notification.uniqueId != timeEventUid_ ||
        notification.macIdAndColor != MacIdAndColor(context_))
        return Result::kStale;

    if (notification.action == TimeEventAction::kEnd) {
        timeEventSubmitted_ = false;
        timeEventRemoveRequested_ = false;
        timeEventIdentityKnown_ = false;
        if (state_ == State::kStopping || state_ == State::kCleanupRequired) {
            const Result cleanup = releaseResources(ops);
            if (cleanup == Result::kSuccess) {
                state_ = State::kIdle;
                context_ = {};
            }
            return cleanup;
        }
        state_ = State::kResourcesReady;
        return Result::kSuccess;
    }

    if (notification.action != TimeEventAction::kStart)
        return Result::kInvalid;
    if (!notification.scheduled) {
        timeEventSubmitted_ = false;
        timeEventIdentityKnown_ = false;
        if (state_ == State::kStopping || state_ == State::kCleanupRequired) {
            const Result cleanup = releaseResources(ops);
            if (cleanup == Result::kSuccess) {
                state_ = State::kIdle;
                context_ = {};
            }
            return cleanup == Result::kSuccess ? Result::kFirmwareError : cleanup;
        }
        state_ = State::kResourcesReady;
        return Result::kFirmwareError;
    }
    if (state_ == State::kStopping || state_ == State::kCleanupRequired)
        return Result::kBusy;
    if (state_ != State::kAwaitingStart || !generationsMatch(admission) ||
        !admission.controllerReady || !admission.stationReady ||
        !admission.scanIdle || admission.shutdown || admission.radioKilled)
        return Result::kNotReady;
    state_ = State::kActive;
    return Result::kSuccess;
}

Result ContextLease::requestStop(std::uint64_t generation, const Operations &ops)
{
    if (generation != context_.generation)
        return Result::kStale;
    if (state_ == State::kIdle)
        return Result::kSuccess;
    if (!operationTableValid(ops))
        return Result::kInvalid;

    if (timeEventSubmitted_) {
        if (!timeEventIdentityKnown_)
            return Result::kNeedsCleanup;
        if (timeEventRemoveRequested_)
            return Result::kNotReady;
        const Result result = ops.removeTimeEvent(ops.context, context_, timeEventUid_);
        if (result == Result::kSuccess) {
            timeEventRemoveRequested_ = true;
            state_ = State::kStopping;
            return Result::kNotReady; // Wait for the matching END notification.
        }
        if (result == Result::kNeedsCleanup) {
            state_ = State::kCleanupRequired;
            return Result::kNeedsCleanup;
        }
        return result;
    }

    const Result cleanup = releaseResources(ops);
    if (cleanup == Result::kSuccess) {
        state_ = State::kIdle;
        context_ = {};
    }
    return cleanup;
}

Result ContextLease::quiesceForRadioChange(const Admission &next,
                                           const Operations &ops)
{
    if (state_ == State::kIdle)
        return Result::kSuccess;
    const bool incompatible = !generationsMatch(next) || !next.controllerReady ||
        !next.stationReady || !next.scanIdle || next.shutdown || next.radioKilled ||
        !next.p2pFirmwareCapability || !next.dynamicQueueEnabled ||
        (next.stationChannel != context_.channel &&
         !next.compatibleChannelLeaseAvailable);
    if (!incompatible)
        return Result::kSuccess;
    const Result stopped = requestStop(context_.generation, ops);
    // Success here would mean all firmware leases are gone. If a TE was
    // submitted, the caller must wait for its exact END before changing radio.
    return stopped;
}

Result ContextLease::hardwareResetComplete(std::uint64_t generation)
{
    if (generation != context_.generation)
        return Result::kStale;
    if (state_ == State::kIdle)
        return Result::kSuccess;
    // iwx_stop_device has stopped RX DMA and retired pending scans before it
    // reports reset complete. Firmware owns none of the recorded resources.
    phyLeased_ = macAdded_ = bindingAdded_ = stationAdded_ = queueEnabled_ = false;
    timeEventSubmitted_ = timeEventRemoveRequested_ = timeEventIdentityKnown_ = false;
    timeEventUid_ = rawTimeEventStatus_ = 0;
    context_ = {};
    state_ = State::kIdle;
    return Result::kSuccess;
}

Result ContextLease::retryCleanup(std::uint64_t generation, const Operations &ops)
{
    if (generation != context_.generation)
        return Result::kStale;
    if (state_ == State::kIdle)
        return Result::kSuccess;
    if (!operationTableValid(ops))
        return Result::kInvalid;
    if (timeEventSubmitted_) {
        if (!timeEventIdentityKnown_)
            return Result::kNeedsCleanup;
        if (!timeEventRemoveRequested_) {
            const Result result = ops.removeTimeEvent(ops.context, context_, timeEventUid_);
            if (result != Result::kSuccess) {
                state_ = State::kCleanupRequired;
                return result == Result::kNeedsCleanup ? result : Result::kNeedsCleanup;
            }
            timeEventRemoveRequested_ = true;
        }
        state_ = State::kStopping;
        return Result::kNotReady;
    }
    const Result result = releaseResources(ops);
    if (result == Result::kSuccess) {
        state_ = State::kIdle;
        context_ = {};
    }
    return result;
}

Result ContextLease::releaseResources(const Operations &ops)
{
    if (timeEventSubmitted_)
        return Result::kBusy;
    Result result = Result::kSuccess;
    if (queueEnabled_) {
        result = ops.disableP2pDeviceQueue(ops.context, context_);
        if (result != Result::kSuccess)
            return result;
        queueEnabled_ = false;
    }
    if (stationAdded_) {
        result = ops.removeStation(ops.context, context_);
        if (result != Result::kSuccess)
            return result;
        stationAdded_ = false;
    }
    if (bindingAdded_) {
        result = ops.removeBinding(ops.context, context_);
        if (result != Result::kSuccess)
            return result;
        bindingAdded_ = false;
    }
    if (macAdded_) {
        result = ops.removeMac(ops.context, context_);
        if (result != Result::kSuccess)
            return result;
        macAdded_ = false;
    }
    if (phyLeased_) {
        result = ops.releasePhy(ops.context, context_);
        if (result != Result::kSuccess)
            return result;
        phyLeased_ = false;
    }
    return Result::kSuccess;
}

} // namespace IntelAwdl
