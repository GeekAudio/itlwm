// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstddef>
#include <cstdint>

namespace IntelAwdl {

// All methods are serialized by the HAL command gate in a real adapter.
// Firmware notifications must be routed through that same serialization
// domain before they mutate this ledger.
enum class Result : std::uint8_t {
    kSuccess,
    kBusy,
    kUnsupported,
    kNotReady,
    kInvalid,
    kFirmwareError,
    kStale,
    kNeedsCleanup
};

enum class State : std::uint8_t {
    kIdle,
    kResourcesReady,
    kAwaitingStart,
    kActive,
    kStopping,
    kCleanupRequired
};

enum class TimeEventAction : std::uint8_t { kStart = 1, kEnd = 2 };

struct Admission {
    std::uint64_t powerGeneration;
    std::uint64_t stationGeneration;
    std::uint32_t stationChannel;
    std::uint32_t awdlChannel;
    std::uint8_t stationMacId;
    std::uint8_t stationPhyId;
    bool controllerReady;
    bool stationReady;
    bool p2pFirmwareCapability;
    bool dynamicQueueEnabled;
    bool scanIdle;
    bool compatibleChannelLeaseAvailable;
    bool monitorInjectionQueueInUse;
    bool shutdown;
    bool radioKilled;
};

struct Context {
    std::uint64_t generation;
    std::uint64_t powerGeneration;
    std::uint64_t stationGeneration;
    std::uint32_t channel;
    std::uint8_t macId;
    std::uint8_t macColor;
    std::uint8_t phyId;
    std::uint8_t phyColor;
    std::uint8_t stationId;
    std::uint8_t queueId;
    std::uint8_t address[6];
};

struct TimeEventResponse {
    std::uint32_t rawStatus;
    std::uint32_t rawEventType;
    std::uint32_t uniqueId;
    std::uint32_t rawMacIdAndColor;
};

struct TimeEventNotification {
    std::uint64_t generation;
    std::uint32_t uniqueId;
    std::uint32_t macIdAndColor;
    TimeEventAction action;
    bool scheduled;
};

// These operations correspond to actual iwx HAL firmware resources: a
// pre-created PHY slot, a P2P-device MAC, its PHY binding, a firmware station,
// the statically assigned DQA P2P-device TX queue (queue 2), and TIME_EVENT v2.
// The implementation is intentionally passed in by the HAL adapter; a return
// value means that adapter observed command transport/response success. It
// cannot make on-air scheduling successful by itself.
struct Operations {
    void *context;
    Result (*leasePhy)(void *, const Context &);
    Result (*releasePhy)(void *, const Context &);
    Result (*addP2pDeviceMac)(void *, const Context &);
    Result (*removeMac)(void *, const Context &);
    Result (*addBinding)(void *, const Context &);
    Result (*removeBinding)(void *, const Context &);
    Result (*addP2pStation)(void *, const Context &);
    Result (*removeStation)(void *, const Context &);
    Result (*enableP2pDeviceQueue)(void *, const Context &);
    Result (*disableP2pDeviceQueue)(void *, const Context &);
    Result (*addTimeEvent)(void *, const Context &, std::uint32_t durationMs,
                           TimeEventResponse *response);
    Result (*removeTimeEvent)(void *, const Context &, std::uint32_t uniqueId);
};

class ContextLease {
public:
    ContextLease();

    Result acquire(const Admission &, const Context &, const Operations &);
    Result armTimeEvent(const Admission &, std::uint32_t durationMs,
                        const Operations &);
    Result onNotification(const Admission &, const TimeEventNotification &,
                          const Operations &);
    Result requestStop(std::uint64_t generation, const Operations &);
    // Call before HAL Off, scanning, channel reassignment, STA teardown, or
    // reset. A conflicted radio change remains blocked until matching TE END
    // arrives or hardwareResetComplete proves physical drain.
    Result quiesceForRadioChange(const Admission &, const Operations &);

    // Call only after iwx_stop has completed RX/DMA teardown and reset. A
    // RESET_BEGIN notification alone is not proof that DMA or the event queue
    // has drained and must not be used to release these leases.
    Result hardwareResetComplete(std::uint64_t generation);

    Result retryCleanup(std::uint64_t generation, const Operations &);
    State state() const { return state_; }
    const Context &context() const { return context_; }
    std::uint32_t timeEventUid() const { return timeEventUid_; }
    std::uint32_t rawTimeEventStatus() const { return rawTimeEventStatus_; }

private:
    Result releaseResources(const Operations &);
    bool operationTableValid(const Operations &) const;
    bool generationsMatch(const Admission &) const;

    Context context_{};
    State state_ {State::kIdle};
    std::uint32_t timeEventUid_ {0};
    std::uint32_t rawTimeEventStatus_ {0};
    bool phyLeased_ {false};
    bool macAdded_ {false};
    bool bindingAdded_ {false};
    bool stationAdded_ {false};
    bool queueEnabled_ {false};
    bool timeEventSubmitted_ {false};
    bool timeEventRemoveRequested_ {false};
    bool timeEventIdentityKnown_ {false};
};

} // namespace IntelAwdl
