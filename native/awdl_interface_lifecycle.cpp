// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_interface.hpp"

#include <string.h>

namespace NativeAwdl {
namespace {

bool validRequest(const VirtualRequestInfo &request)
{
    if (request.role != 6)
        return false;

    uint8_t aggregate = 0;
    for (uint8_t byte : request.address)
        aggregate |= byte;
    return aggregate != 0 && (request.address[0] & 1U) == 0;
}

bool hasRequiredOps(const InterfaceOps &ops)
{
    return ops.hardwareReady && ops.alreadyPublished && ops.allocate &&
           ops.initialize && ops.prepareHardware && ops.publish && ops.attach &&
           ops.startService && ops.stopHardware && ops.detach &&
           ops.clearPublished && ops.release;
}

} // namespace

InterfaceStatus InterfaceLifecycle::start(const VirtualRequestInfo &request,
                                          const InterfaceOps &ops,
                                          void **startedInterface)
{
    if (startedInterface)
        *startedInterface = nullptr;
    if (!validRequest(request))
        return InterfaceStatus::InvalidArgument;
    if (interface_ != nullptr)
        return InterfaceStatus::Busy;
    if (!hasRequiredOps(ops))
        return InterfaceStatus::NotReady;

    ops_ = ops;
    InterfaceStatus status = ops_.hardwareReady(ops_.context);
    if (status != InterfaceStatus::Success) {
        reset();
        return status == InterfaceStatus::NotReady ? status
                                                   : InterfaceStatus::HardwareFailure;
    }

    bool alreadyPublished = false;
    status = ops_.alreadyPublished(ops_.context, &alreadyPublished);
    if (status != InterfaceStatus::Success || alreadyPublished) {
        reset();
        return status == InterfaceStatus::Success ? InterfaceStatus::Busy : status;
    }

    status = ops_.allocate(ops_.context, &interface_);
    if (status != InterfaceStatus::Success || interface_ == nullptr) {
        const InterfaceStatus failure = status == InterfaceStatus::Success
                                            ? InterfaceStatus::NoMemory
                                            : status;
        return unwind(failure);
    }

    status = ops_.initialize(ops_.context, interface_, request);
    if (status != InterfaceStatus::Success)
        return unwind(status);

    // Mark prepared before calling into firmware: a failing callback may have
    // acquired some resources and must be followed by stop() for cleanup.
    hardwarePrepared_ = true;
    status = ops_.prepareHardware(ops_.context, interface_);
    if (status != InterfaceStatus::Success)
        return unwind(status);

    // The pointer is visible to IO80211 only after hardware readiness and
    // preparation succeeded. clearPublished() must compare identity before
    // clearing, so rollback cannot erase a different owner's interface.
    published_ = true;
    status = ops_.publish(ops_.context, interface_);
    if (status != InterfaceStatus::Success)
        return unwind(status);

    status = ops_.attach(ops_.context, interface_);
    if (status != InterfaceStatus::Success)
        return unwind(status);
    attached_ = true;

    status = ops_.startService(ops_.context, interface_);
    if (status != InterfaceStatus::Success)
        return unwind(status);

    started_ = true;
    if (startedInterface)
        *startedInterface = interface_;
    return InterfaceStatus::Success;
}

InterfaceStatus InterfaceLifecycle::stop()
{
    if (interface_ == nullptr) {
        reset();
        return InterfaceStatus::Success;
    }

    if (hardwarePrepared_) {
        const InterfaceStatus status =
            ops_.stopHardware(ops_.context, interface_);
        if (status != InterfaceStatus::Success)
            return InterfaceStatus::CleanupPending;
        hardwarePrepared_ = false;
    }

    // detach() owns the native terminate/stop/detach path. Keep the controller
    // AWDL pointer published until that sequence completes.
    if (attached_) {
        const InterfaceStatus status = ops_.detach(ops_.context, interface_);
        if (status != InterfaceStatus::Success)
            return InterfaceStatus::CleanupPending;
        attached_ = false;
    }

    if (published_) {
        const InterfaceStatus status =
            ops_.clearPublished(ops_.context, interface_);
        if (status != InterfaceStatus::Success)
            return InterfaceStatus::CleanupPending;
        published_ = false;
    }

    ops_.release(ops_.context, interface_);
    reset();
    return InterfaceStatus::Success;
}

InterfaceStatus InterfaceLifecycle::unwind(InterfaceStatus originalStatus)
{
    return stop() == InterfaceStatus::Success ? originalStatus
                                               : InterfaceStatus::CleanupPending;
}

void InterfaceLifecycle::reset()
{
    ops_ = {};
    interface_ = nullptr;
    hardwarePrepared_ = false;
    published_ = false;
    attached_ = false;
    started_ = false;
}

} // namespace NativeAwdl
