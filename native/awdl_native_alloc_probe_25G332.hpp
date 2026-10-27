// Candidate-only 25G332 native AWDL allocator probe.
//
// This interface is deliberately separate from the active HAL and Xcode
// targets. The function returns a numeric bitmask and never exposes an
// OSObject pointer. Do not run it in-kernel until the exact allocator's
// uninitialized-free behavior has been closed by binary evidence.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ItlAwdlAllocProbe25G332_MetaClassValid       = 1u << 0,
    ItlAwdlAllocProbe25G332_Allocated           = 1u << 1,
    ItlAwdlAllocProbe25G332_InstanceMetaMatches = 1u << 2,
    ItlAwdlAllocProbe25G332_RetainCountIsOne    = 1u << 3,
    ItlAwdlAllocProbe25G332_ReleaseReturned      = 1u << 4,

    ItlAwdlAllocProbe25G332_MetaClassInvalid    = 1u << 16,
    ItlAwdlAllocProbe25G332_AllocationFailed    = 1u << 17,
    ItlAwdlAllocProbe25G332_InstanceMetaWrong   = 1u << 18,
    ItlAwdlAllocProbe25G332_RetainCountWrong    = 1u << 19,
};

// Candidate only. Allocates one native-prototype object, reads metadata and
// retain count before release, calls release exactly once, then returns a
// numeric result. "ReleaseReturned" means the call returned; it does not
// claim that the native destructor/free path was runtime-verified.
uint32_t ItlAwdlNativeAllocReleaseProbe25G332(void);

#ifdef __cplusplus
}
#endif
