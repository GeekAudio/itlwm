#include "../intel_gp2_sampler.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace IntelGp2Clock;

struct FakeDevice {
    bool acquire;
    uint64_t host[2];
    uint32_t gp2;
    uint32_t address;
    unsigned clockCalls;
    unsigned reads;
    unsigned releases;
};

static bool acquireNic(void *context)
{
    return static_cast<FakeDevice *>(context)->acquire;
}

static void releaseNic(void *context)
{
    ++static_cast<FakeDevice *>(context)->releases;
}

static uint64_t hostMonotonicNs(void *context)
{
    FakeDevice *device = static_cast<FakeDevice *>(context);
    assert(device->clockCalls < 2);
    return device->host[device->clockCalls++];
}

static uint32_t readPrph(void *context, uint32_t address)
{
    FakeDevice *device = static_cast<FakeDevice *>(context);
    ++device->reads;
    device->address = address;
    return device->gp2;
}

static SampleBackend backendFor(FakeDevice *device)
{
    SampleBackend backend{device, acquireNic, releaseNic,
                          hostMonotonicNs, readPrph};
    return backend;
}

int main()
{
    FakeDevice device{true, {1000000, 1040000}, 0xfffffff0u, 0, 0, 0, 0};
    SampleBackend backend = backendFor(&device);
    RawBracketedSample sample{};
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 7,
                            &sample) == SampleStatus::kOk);
    assert(sample.gp2Us == 0xfffffff0u);
    assert(sample.hostBeforeUs == 1000 && sample.hostAfterUs == 1040);
    assert(sample.generation == 7 && sample.nicLockHeld);
    assert(sample.prphAddress == 0x00d02c68u);
    assert(device.reads == 1 && device.releases == 1);

    device = FakeDevice{true, {2000000, 2020000}, 0x12345678u, 0, 0, 0, 0};
    backend = backendFor(&device);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kFamily22000, 8,
                            &sample) == SampleStatus::kOk);
    assert(sample.prphAddress == 0x00a02c68u);

    device = FakeDevice{false, {3000000, 3020000}, 1, 0, 0, 0, 0};
    backend = backendFor(&device);
    RawBracketedSample unchanged{};
    unchanged.gp2Us = 99;
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 9,
                            &unchanged) == SampleStatus::kLockUnavailable);
    assert(unchanged.gp2Us == 99 && device.reads == 0 &&
           device.clockCalls == 0 && device.releases == 0);

    device = FakeDevice{true, {4000000, 3999000}, 1, 0, 0, 0, 0};
    backend = backendFor(&device);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 10,
                            &unchanged) == SampleStatus::kHostClockOrder);
    assert(unchanged.gp2Us == 99 && device.reads == 1 &&
           device.releases == 1);

    device = FakeDevice{true, {5000000, 5010000}, 1, 0, 0, 0, 0};
    backend = backendFor(&device);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kUnsupported, 11,
                            &unchanged) == SampleStatus::kUnsupportedFamily);
    assert(device.reads == 0 && device.clockCalls == 0 && device.releases == 0);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 0,
                            &unchanged) == SampleStatus::kInvalidArgument);
    // Outward rounding must enclose both fractional-microsecond endpoints.
    device = FakeDevice{true, {1000999, 1001001}, 17, 0, 0, 0, 0};
    backend = backendFor(&device);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 12,
                            &sample) == SampleStatus::kOk);
    assert(sample.hostBeforeUs == 1000 && sample.hostAfterUs == 1002);
    assert(sample.hostBeforeUs * 1000 <= device.host[0]);
    assert(sample.hostAfterUs * 1000 >= device.host[1]);

    // Raw reversal must be rejected even when both times floor to one us.
    device = FakeDevice{true, {1000999, 1000001}, 17, 0, 0, 0, 0};
    backend = backendFor(&device);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 13,
                            &unchanged) == SampleStatus::kHostClockOrder);
    assert(unchanged.gp2Us == 99 && device.releases == 1);

    // Ceil must not overflow by adding 999 to a near-maximum timestamp.
    device = FakeDevice{true, {UINT64_MAX - 1, UINT64_MAX}, 18, 0, 0, 0, 0};
    backend = backendFor(&device);
    assert(readBracketedGp2(&backend, SamplerDeviceFamily::kAx210, 14,
                            &sample) == SampleStatus::kOk);
    assert(sample.hostAfterUs == UINT64_MAX / 1000 + 1);
    return 0;
}
