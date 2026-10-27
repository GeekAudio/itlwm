// Offline candidate adapter for the exact 25G332 native AWDL subclass.
//
// This file is intentionally not in the Xcode project or EFI package. It does
// not initialize, attach, start, open, register a service, publish an object,
// set an AWDL interface pointer, or touch the radio. Runtime use is blocked
// until the exact fresh-allocation -> inherited free path is proven safe.
#include "awdl_native_alloc_probe_25G332.hpp"

#if !defined(ITL_AWDL_ALLOCATOR_VARIANT_25G332)
#error "The alloc probe must only be compiled with the concrete 25G332 allocator variant"
#endif

#include "awdl_native_concrete_25G332.hpp"

static_assert(sizeof(ItlAwdlNativeConcreteGate25G332) == 0x130,
              "25G332 concrete candidate size changed");

extern "C" uint32_t ItlAwdlNativeAllocReleaseProbe25G332(void) {
    const OSMetaClass *const candidateMeta =
        ItlAwdlNativeConcreteGate25G332::metaClass;
    if (candidateMeta == nullptr
        || candidateMeta->getSuperClass() != IO80211AWDLProtocol::metaClass
        || candidateMeta->getClassSize()
            != sizeof(ItlAwdlNativeConcreteGate25G332)) {
        return ItlAwdlAllocProbe25G332_MetaClassInvalid;
    }

    uint32_t result = ItlAwdlAllocProbe25G332_MetaClassValid;
    OSObject *const object = candidateMeta->alloc();
    if (object == nullptr) {
        return result | ItlAwdlAllocProbe25G332_AllocationFailed;
    }
    result |= ItlAwdlAllocProbe25G332_Allocated;

    // All instance queries happen before the one and only release().
    if (object->getMetaClass() == candidateMeta) {
        result |= ItlAwdlAllocProbe25G332_InstanceMetaMatches;
    } else {
        result |= ItlAwdlAllocProbe25G332_InstanceMetaWrong;
    }

    if (object->getRetainCount() == 1) {
        result |= ItlAwdlAllocProbe25G332_RetainCountIsOne;
    } else {
        result |= ItlAwdlAllocProbe25G332_RetainCountWrong;
    }

    object->release();
    result |= ItlAwdlAllocProbe25G332_ReleaseReturned;
    return result;
}
