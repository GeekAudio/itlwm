// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_native_owner_25G332.hpp"

namespace NativeAwdl25G332 {
namespace {

constexpr uint32_t kAwdlRole = 6;
constexpr char kAwdlName[] = "awdl";

bool validAddress(const uint8_t address[6])
{
    if (!address || (address[0] & 1U))
        return false;

    uint8_t combined = 0;
    for (unsigned int i = 0; i < 6; ++i)
        combined |= address[i];
    return combined != 0;
}

bool complete(const NativeOps &ops)
{
    return ops.allocate && ops.initialize && ops.attach && ops.start &&
           ops.terminate && ops.getAwdlInterface && ops.setAwdlInterface &&
           ops.release && ops.prepareRelease && ops.verifyStarted;
}

} // namespace

Status InterfaceOwner::start(void *controller, const uint8_t address[6],
                             const NativeOps &ops)
{
    if (!controller || !validAddress(address) || !complete(ops))
        return Status::InvalidArgument;
    if (object_)
        return Status::Busy;

    ops_ = ops;
    controller_ = controller;

    // get/set are raw pointer accessors on 25G332. This check is serialized
    // with creation/teardown by the caller; the native setter has no lock.
    if (ops_.getAwdlInterface(ops_.context, controller_)) {
        ops_ = {};
        controller_ = nullptr;
        return Status::Busy;
    }

    object_ = ops_.allocate(ops_.context);
    if (!object_) {
        ops_ = {};
        controller_ = nullptr;
        return Status::NoMemory;
    }

    // Keep the allocator's owned reference immediately. Native init can leave
    // partial private state and an open controller even when it returns false.
    // Plain release is not a safe failed-init cleanup contract on this build.
    if (!ops_.initialize(ops_.context, object_, controller_, address,
                         kAwdlRole, kAwdlName)) {
        return retireReference() ? Status::InitFailed :
                                   Status::InitFailedNeedsCleanup;
    }
    releaseState_ = ReleaseState::Initialized;

    // Match init -> attach(controller), but retain a failed attachment until
    // the unstarted object's cleanup and final free have been established.
    if (!ops_.attach(ops_.context, object_, controller_)) {
        return retireReference() ? Status::AttachFailed :
                                   Status::AttachFailedNeedsCleanup;
    }
    attached_ = true;

    // The 25G332 Skywalk start implementation casts its provider to
    // IO80211Controller. Some early exits retain a true return value without
    // complete state; never infer completion from that bool alone. A failed
    // or incomplete start remains owned until state-aware stop/cleanup.
    if (!ops_.start(ops_.context, object_, controller_))
        return Status::StartFailedNeedsStop;
    if (!ops_.verifyStarted(ops_.context, controller_, object_))
        return Status::StartStateIncompleteNeedsStop;

    started_ = true;
    return Status::Success;
}

Status InterfaceOwner::stop()
{
    if (!object_) {
        ops_ = {};
        controller_ = nullptr;
        attached_ = false;
        started_ = false;
        releaseState_ = ReleaseState::InitFailed;
        return Status::Success;
    }

    if (attached_) {
        // Native detachVirtualInterface(controller, object, false) dispatches
        // terminate(1) and returns its bool. It does not release the object.
        if (!ops_.terminate(ops_.context, controller_, object_, false))
            return Status::CleanupPending;
        attached_ = false;
        started_ = false;
        releaseState_ = ReleaseState::Terminated;
    }

    return retireReference() ? Status::Success : Status::CleanupPending;
}

bool InterfaceOwner::retireReference()
{
    if (!ops_.prepareRelease(ops_.context, controller_, object_, releaseState_))
        return false;

    // The 25G332 controller slot is an unretained alias. Never clear a newer
    // object's pointer if ownership changed while this object was stopping.
    if (ops_.getAwdlInterface(ops_.context, controller_) == object_)
        ops_.setAwdlInterface(ops_.context, controller_, nullptr);

    releaseAndReset();
    return true;
}

void InterfaceOwner::releaseAndReset()
{
    if (object_ && ops_.release)
        ops_.release(ops_.context, object_);
    ops_ = {};
    controller_ = nullptr;
    object_ = nullptr;
    attached_ = false;
    started_ = false;
    releaseState_ = ReleaseState::InitFailed;
}

} // namespace NativeAwdl25G332
