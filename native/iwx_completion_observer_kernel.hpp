// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_IWX_COMPLETION_OBSERVER_KERNEL_HPP
#define NATIVE_IWX_COMPLETION_OBSERVER_KERNEL_HPP

#include <IOKit/IOLocks.h>
#include "iwx_completion_observer.hpp"

namespace NativeIwxCompletionObserver {

// The lock wrapper and fixed registry are members of ItlIwx, so their storage
// outlives the ring, every reservation, and every workloop reader. The owner
// calls Registry::shutdown only after removing the interrupt event source.
class IOSimpleLockAdapter {
public:
    IOSimpleLockAdapter() : lock_(nullptr) {}
    IOSimpleLockAdapter(const IOSimpleLockAdapter &) = delete;
    IOSimpleLockAdapter &operator=(const IOSimpleLockAdapter &) = delete;
    IOSimpleLockAdapter(IOSimpleLockAdapter &&) = delete;
    IOSimpleLockAdapter &operator=(IOSimpleLockAdapter &&) = delete;

    bool initialize()
    {
        if (lock_ != nullptr)
            return false;
        lock_ = IOSimpleLockAlloc();
        return lock_ != nullptr;
    }

    void destroy()
    {
        if (lock_ == nullptr)
            return;
        IOSimpleLockFree(lock_);
        lock_ = nullptr;
    }

    void lock() { IOSimpleLockLock(lock_); }
    bool tryLock() { return lock_ != nullptr && IOSimpleLockTryLock(lock_); }
    void unlock() { IOSimpleLockUnlock(lock_); }

private:
    IOSimpleLock *lock_;
};

typedef Registry<IOSimpleLockAdapter, 1> KernelRegistry;

} // namespace NativeIwxCompletionObserver

#endif // NATIVE_IWX_COMPLETION_OBSERVER_KERNEL_HPP
