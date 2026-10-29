// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_INTEL_GP2_SAMPLER_HPP
#define NATIVE_INTEL_GP2_SAMPLER_HPP

#include <stdint.h>

namespace IntelGp2Clock {

enum class SamplerDeviceFamily : uint8_t {
    kUnsupported = 0,
    kFamily22000 = 1,
    kAx210 = 2,
};

enum class SampleStatus : uint8_t {
    kOk = 0,
    kInvalidArgument,
    kUnsupportedFamily,
    kLockUnavailable,
    kHostClockOrder,
};

struct SampleBackend {
    void *context;
    bool (*acquireNic)(void *context);
    void (*releaseNic)(void *context);
    // Raw nanoseconds allow the sampler to round both endpoints outward.
    uint64_t (*hostMonotonicNs)(void *context);
    uint32_t (*readPrph)(void *context, uint32_t address);
};

struct RawBracketedSample {
    uint32_t gp2Us;
    uint64_t hostBeforeUs;
    uint64_t hostAfterUs;
    uint64_t generation;
    uint32_t prphAddress;
    SamplerDeviceFamily family;
    bool nicLockHeld;
};

// This samples GP2 only. It does not map GP2 to host, TSF, or peer AWDL time.
// Family values and PRPH addresses match the two locally supported families.
// All hardware operations are supplied by the caller so this helper does not
// acquire device access by itself. Acquire must guarantee the NIC is awake;
// readPrph must perform a direct, read-only PRPH read while that lock is held.
// Host endpoints are sampled in nanoseconds, then rounded down before the
// read and up after it. The microsecond result encloses sub-microsecond reads.
SampleStatus readBracketedGp2(const SampleBackend *backend,
                              SamplerDeviceFamily family,
                              uint64_t generation,
                              RawBracketedSample *output);

} // namespace IntelGp2Clock

#endif // NATIVE_INTEL_GP2_SAMPLER_HPP
