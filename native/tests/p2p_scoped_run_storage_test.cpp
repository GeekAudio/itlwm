// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_scoped_run_storage.hpp"
#include "../awdl_discovery_admitted_binding.hpp"
#include <assert.h>
#include <stdlib.h>
#include <type_traits>

namespace {
unsigned allocations, frees, constructors, destructors;
bool failAllocation;
struct Run {
    static void *operator new(size_t size) noexcept {
        if (failAllocation) return nullptr;
        ++allocations;
        return malloc(size);
    }
    static void operator delete(void *p) noexcept {
        if (p) { ++frees; free(p); }
    }
    NativeAwdlDiscoveryBinding::OneShot gate;
    unsigned initialized = 0x12345678;
    unsigned char payload[4096];
    Run() { ++constructors; }
    ~Run() { ++destructors; }
};
using Owner = NativeP2PProbe::ScopedRunStorage<Run>;
static_assert(!std::is_copy_constructible<Owner>::value, "one owner");
static_assert(!std::is_copy_assignable<Owner>::value, "one owner");
static_assert(sizeof(Owner) == sizeof(void *), "worker carries only a pointer");
void earlyReturn() {
    Owner owner;
    assert(owner.get() && owner.get()->initialized == 0x12345678);
    assert(!owner.get()->gate.attempted());
    assert(owner.get()->gate.authorizeTake({}, {}, {}) ==
           NativeAwdlDiscoveryBinding::Decision::kNotLocked);
}
}
int main() {
    earlyReturn();
    assert(allocations == 1 && frees == 1 && constructors == 1 && destructors == 1);
    failAllocation = true;
    { Owner failed; assert(!failed.get()); }
    assert(allocations == 1 && frees == 1 && constructors == 1 && destructors == 1);
    failAllocation = false;
    { Owner again; assert(again.get()); }
    assert(allocations == 2 && frees == 2 && constructors == 2 && destructors == 2);
}
