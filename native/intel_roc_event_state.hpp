// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_INTEL_ROC_EVENT_STATE_HPP
#define NATIVE_INTEL_ROC_EVENT_STATE_HPP

#include <stddef.h>
#include <stdint.h>

namespace IntelROCEvent {

// All calls belong to the RX/main command gate. No allocation, sleep, command
// submission, or IORegistry publication is performed by this reducer.
struct Snapshot {
    uint32_t generation;
    uint32_t responseStatus;
    uint32_t uniqueId;
    uint32_t startStatus;
    uint32_t endStatus;
    uint32_t ignoredForeign;
    bool submitted;
    bool responseDecoded;
    bool responseContractSuccess;
    bool startSeen;
    bool endSeen;
    bool startScheduled;
    bool endScheduled;
    bool cleanupAllowed;
    bool observedScheduledPair;
    bool outcomeUnknown;
};

class Tracker {
public:
    Tracker();
    // Arm immediately before handing ADD to transport, including its IRQs.
    bool begin(uint32_t generation, uint32_t macIdAndColor, uint32_t eventType);
    bool noteResponse(uint32_t generation, int transportResult,
                      const uint8_t *bytes, size_t length);
    bool noteNotification(uint32_t generation, const uint8_t *bytes,
                          size_t length);
    void expire(uint32_t generation);
    Snapshot snapshot() const;

private:
    struct Event { uint32_t uid, action, status; };
    void apply(const Event &event);
    Snapshot state_{};
    uint32_t macIdAndColor_ {0};
    uint32_t eventType_ {0};
    Event early_[4]{};
    unsigned earlyCount_ {0};
    bool expired_ {false};
    bool malformed_ {false};
};

// fw68 advertises capability54 and Session Protection cmd1/notif2. This path
// has no firmware UID: one whole-boot invocation, a dedicated P2P MAC, and
// exact MAC/config plus runtime epoch admission are required by the caller.
struct SessionSnapshot {
    uint32_t generation;
    uint32_t configuration;
    int32_t commandResult;
    uint32_t startStatus;
    uint32_t endStatus;
    uint32_t ignoredForeign;
    uint64_t startObservedMonotonicUs;
    uint64_t endObservedMonotonicUs;
    bool submitted;
    bool commandReturned;
    bool startSeen;
    bool endSeen;
    bool cleanupAllowed;
    bool observedScheduledPair;
    bool outcomeUnknown;
};

class SessionTracker {
public:
    SessionTracker();
    bool begin(uint32_t generation, uint32_t macId, uint32_t configuration);
    bool noteCommandResult(uint32_t generation, int result);
    bool noteNotification(uint32_t generation, const uint8_t *, size_t,
                          uint64_t receiveMonotonicUs = 0);
    void expire(uint32_t generation);
    SessionSnapshot snapshot() const;
private:
    SessionSnapshot state_{};
    uint32_t macId_ {0};
    uint32_t configuration_ {0};
    bool malformed_ {false};
    bool expired_ {false};
};

bool isStationSessionNotification(const uint8_t *, size_t, uint32_t stationMacId);

} // namespace IntelROCEvent
#endif
