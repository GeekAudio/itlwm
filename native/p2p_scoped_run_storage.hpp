// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_SCOPED_RUN_STORAGE_HPP
#define NATIVE_P2P_SCOPED_RUN_STORAGE_HPP

namespace NativeP2PProbe {

// T provides a nonthrowing class allocation function in the kernel. Typed
// value construction is essential: a run contains a nontrivial OneShot gate.
// The holder lives on the worker stack; its run and nested witnesses do not.
template <typename T> class ScopedRunStorage {
public:
    ScopedRunStorage() : object_(new T{}) {}
    ~ScopedRunStorage() { delete object_; }
    T *get() const { return object_; }
    ScopedRunStorage(const ScopedRunStorage &) = delete;
    ScopedRunStorage &operator=(const ScopedRunStorage &) = delete;

private:
    T *object_;
};

} // namespace NativeP2PProbe
#endif
