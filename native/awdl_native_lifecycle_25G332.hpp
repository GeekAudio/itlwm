// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
class IOService;
namespace NativeAwdlLifecycle {
enum Flag : uint32_t {
    Attempted=1u<<0, Initialized=1u<<1, Attached=1u<<2, QueuesCreated=1u<<3,
    Registered=1u<<4, StartCalled=1u<<5, StartReturned=1u<<6,
    StartComplete=1u<<7, Published=1u<<8, BSDSeen=1u<<9,
    TerminateCalled=1u<<10, TerminateReturned=1u<<11, NativeStopped=1u<<12,
    Detached=1u<<13, AliasCleared=1u<<14, InterestQuiesced=1u<<15,
    ControllerClosed=1u<<16, BpfCleaned=1u<<17, ReleaseRequested=1u<<18,
    FreeReturned=1u<<19, Quarantined=1u<<20, Failed=1u<<21,
    AliasInitiallyEmpty=1u<<22, RegistrationCleared=1u<<23,
    QueuesReleased=1u<<24
};
struct Snapshot {
    uint32_t flags, phase, result, startWitness, classSize, referencesBeforeRelease, bsdEflags, bsdIndex, failurePhase, failureResult;
};
void observeOnce(IOService *, const uint8_t address[6]);
Snapshot snapshot();
bool residentPending(IOService *);
bool stopResident(IOService *);
}
