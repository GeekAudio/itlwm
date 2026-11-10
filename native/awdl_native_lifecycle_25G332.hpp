// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
class IOService;
struct apple80211_virt_if_create_data;
struct apple80211_awdl_sync_enabled;
struct apple80211_awdl_sync_channel_sequence;
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
// Read-only witness of inputs observed on the system-controlled AWDL path.
// Channel-sequence fields below are the ABI header/hash only: this build has
// not established a safe channel decoder or any schedule timing contract.
struct SystemScheduleSnapshot {
    uint32_t revision;
    uint32_t createRequests, createValidRequests, lastCreateRole, lastCreateValid;
    uint32_t interfaceEnableRequests, interfaceEnabledValid, interfaceEnabled;
    uint32_t syncEnabledRequests, syncEnabledValid, syncEnabled;
    uint32_t channelSequenceRequests, channelSequenceValid;
    uint32_t sequenceVersion, sequenceLength, sequenceEncoding;
    uint32_t sequenceStepCount, sequenceDuplicateCount, sequenceFillChannel;
    uint32_t sequenceFlagsHash;
    uint64_t lastEventUptimeUs;
};
// System mode is compile-time disabled by default. When enabled it also
// requires the signed candidate personality and a clean resident-only profile.
bool systemProfileEnabled(IOService *);
// These functions only record actual system callback inputs. They never
// allocate an interface, alter firmware, enable RF, or acknowledge success.
void observeSystemCreateRequest(IOService *, const apple80211_virt_if_create_data *);
void observeSystemInterfaceEnable(IOService *, bool);
void observeSystemSyncEnabled(IOService *, const apple80211_awdl_sync_enabled *);
void observeSystemChannelSequence(IOService *, const apple80211_awdl_sync_channel_sequence *);
SystemScheduleSnapshot systemScheduleSnapshot(IOService *);
void observeOnce(IOService *, const uint8_t address[6]);
Snapshot snapshot();
bool residentPending(IOService *);
// Publish the lifecycle and BSD closing bits while serialized by the
// controller's main radio gate. The in-gate form is for the command-gate
// callback; the routed form is for teardown paths that are outside the gate.
bool publishClosingInGate(IOService *);
bool publishClosing(IOService *);
bool stopResident(IOService *);
}
