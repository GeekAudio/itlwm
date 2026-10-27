// SPDX-License-Identifier: GPL-2.0-only
#pragma once
namespace NativeAwdlLifecycle {
struct TransactionState {
    bool initialized = false, attached = false, registered = false;
    bool startCalled = false, startComplete = false, published = false;
};
// The same ordering runs in the kernel binding and failure-injection harness.
// retire must preserve ownership whenever native teardown is incomplete.
template <typename Operations>
bool start(Operations &ops, TransactionState &state)
{
    if (!(state.initialized = ops.initialize())) return ops.retire(state), false;
    if (!(state.attached = ops.attach())) return ops.retire(state), false;
    if (!ops.createQueues()) return ops.retire(state), false;
    if (!(state.registered = ops.registerInterface())) return ops.retire(state), false;
    state.startCalled = true;
    if (!ops.start() || !(state.startComplete = ops.verifyStarted()))
        return ops.retire(state), false;
    state.published = true;
    ops.publish();
    if(!ops.observeBSD())return ops.retire(state),false;
    return true;
}
template <typename Operations>
bool execute(Operations &ops, TransactionState &state)
{
    if(!start(ops,state))return false;
    const bool retired = ops.retire(state);
    return retired;
}
}
