// SPDX-License-Identifier: GPL-2.0-only
#include "intel_gp2_sampler.hpp"

namespace IntelGp2Clock {
namespace {

constexpr uint32_t kFamily22000SystemTimePrph = 0x00a02c68;
constexpr uint32_t kAx210SystemTimePrph = 0x00d02c68;

bool validBackend(const SampleBackend &backend)
{
    return backend.acquireNic && backend.releaseNic &&
           backend.hostMonotonicUs && backend.readPrph;
}

uint32_t systemTimeAddress(SamplerDeviceFamily family)
{
    switch (family) {
    case SamplerDeviceFamily::kFamily22000:
        return kFamily22000SystemTimePrph;
    case SamplerDeviceFamily::kAx210:
        return kAx210SystemTimePrph;
    default:
        return 0;
    }
}

class NicLockGuard {
public:
    explicit NicLockGuard(const SampleBackend &backend)
        : backend_(backend), locked_(backend_.acquireNic(backend_.context))
    {
    }

    ~NicLockGuard()
    {
        if (locked_)
            backend_.releaseNic(backend_.context);
    }

    bool locked() const { return locked_; }

private:
    const SampleBackend &backend_;
    bool locked_;
};

} // namespace

SampleStatus readBracketedGp2(const SampleBackend *backend,
                              SamplerDeviceFamily family,
                              uint64_t generation,
                              RawBracketedSample *output)
{
    if (!backend || !output || generation == 0 || !validBackend(*backend))
        return SampleStatus::kInvalidArgument;

    const uint32_t address = systemTimeAddress(family);
    if (address == 0)
        return SampleStatus::kUnsupportedFamily;

    NicLockGuard lock(*backend);
    if (!lock.locked())
        return SampleStatus::kLockUnavailable;

    // Keep the host samples immediately around the indirect PRPH read. The
    // potentially long NIC-access acquisition is intentionally outside this
    // bracket, while the caller still serializes the hardware access.
    const uint64_t before = backend->hostMonotonicUs(backend->context);
    const uint32_t gp2 = backend->readPrph(backend->context, address);
    const uint64_t after = backend->hostMonotonicUs(backend->context);
    if (after < before)
        return SampleStatus::kHostClockOrder;

    RawBracketedSample sample{};
    sample.gp2Us = gp2;
    sample.hostBeforeUs = before;
    sample.hostAfterUs = after;
    sample.generation = generation;
    sample.prphAddress = address;
    sample.family = family;
    sample.nicLockHeld = true;
    *output = sample;
    return SampleStatus::kOk;
}

} // namespace IntelGp2Clock
