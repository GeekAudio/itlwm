// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
class IOService;
namespace NativeAwdlInit {
enum Flag : uint32_t {
    Attempted = 1u << 0, MetaVerified = 1u << 1, Allocated = 1u << 2,
    InitCalled = 1u << 3, InitReturned = 1u << 4, InitSucceeded = 1u << 5,
    InterestQuiesced = 1u << 6, ControllerClosed = 1u << 7,
    BpfCleaned = 1u << 8, ReleaseRequested = 1u << 9,
    FreeEntered = 1u << 10, ServiceBaseFreed = 1u << 11,
    VirtualBaseFreed = 1u << 12, FreeReturned = 1u << 13,
    Quarantined = 1u << 14, DeferredRelease = 1u << 15,
    AllocationFailed = 1u << 16, IdentityRejected = 1u << 17,
    InitFailed = 1u << 18
};
struct Snapshot {
    uint32_t flags;
    uint32_t deregisterResult;
    uint32_t referencesBeforeRelease;
    uint32_t classSize;
};
void observeOnce(IOService *controller, const uint8_t address[6]);
Snapshot snapshot();
bool completedSuccessfully();
} // namespace NativeAwdlInit
