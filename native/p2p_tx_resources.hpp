// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace IntelP2PTx {

enum class Owner : uint8_t {
    kFree,
    kInfrastructureSta,
    kAuxiliary,
    kMonitor,
    kP2pPending,
    kP2pBroadcast,
    kUnknown
};

enum class Result : uint8_t {
    kSuccess,
    kBusy,
    kNoCapacity,
    kInvalid,
    kStale,
    kNeedsReset
};

enum class QueueApi : uint8_t {
    kLegacyStaticDqa,
    // Firmware assigns a queue from the legacy LONG_GROUP/SCD_QUEUE_CFG v2
    // API. Unlike static DQA, this queue is dynamically selected and is
    // released by removing its station after TXPATH_FLUSH.
    kLegacyDynamicDqa,
    kTvqmDynamic
};

enum class QueueState : uint8_t {
    kAbsent,
    kAllocationPending,
    kActive,
    kRemoving,
    kUnknown
};

struct StationSnapshot {
    uint8_t count;
    uint32_t generation;
    Owner owners[32];
};

// The caller supplies the station-table capacity reported by firmware and
// which of the driver's fixed roles are currently installed. The registry
// never assumes that station ID 3 is free.
class StationRegistry {
public:
    StationRegistry();

    Result initialize(uint8_t count, uint32_t generation,
                      bool staInstalled, bool auxInstalled,
                      bool monitorInstalled);
    Result reserveP2p(uint32_t generation, uint8_t *stationId);
    Result addAcknowledged(uint32_t generation, uint8_t stationId);
    Result addOutcomeUnknown(uint32_t generation,
                             uint8_t stationId);
    Result removeAcknowledged(uint32_t generation,
                              uint8_t stationId);
    Result releaseKnownAbsent(uint32_t generation,
                              uint8_t stationId);
    Result resetAfterFirmwareDrain(uint32_t newGeneration,
                                   uint8_t count,
                                   bool staInstalled, bool auxInstalled,
                                   bool monitorInstalled);
    StationSnapshot snapshot() const;

private:
    Result setRoles(uint8_t count, uint32_t generation,
                    bool staInstalled, bool auxInstalled,
                    bool monitorInstalled);
    Result mark(uint32_t generation, uint8_t stationId,
                Owner expected, Owner next);

    uint8_t count_;
    uint32_t generation_;
    Owner owners_[32];
};

struct QueueAdmission {
    QueueApi api;
    uint16_t queueCapacity;
    uint32_t generation;
    uint8_t stationId;
    // CAPA_DQA_SUPPORT gates only the legacy static DQA API.
    bool firmwareDqa;
    bool stationActive;
    bool p2pMacActive;
    bool p2pBindingActive;
    bool phyLeased;
    bool monitorInjectionQueueInUse;
};

struct QueueSnapshot {
    QueueState state;
    QueueApi api;
    uint16_t queueId;
    uint8_t stationId;
    uint32_t generation;
    uint32_t outstandingTx;
    // Set only by a validated firmware TX completion, never by local cancel.
    bool completionObserved;
    bool ringMustRemainOwned;
};

// Power-generation bookkeeping may be reset only when the registry and queue
// contain no P2P station, outstanding TX, or retained DMA lease.
bool noP2pResourcesRetained(const StationSnapshot &stations,
                            const QueueSnapshot &queue);

// Tracks one queue for P2P management traffic. The caller must preserve the
// DMA ring whenever ringMustRemainOwned is true, including unknown firmware
// outcomes, until a real completion/drain or a proven firmware reset.
class QueueLease {
public:
    QueueLease();

    Result begin(const QueueAdmission &admission);
    Result tvqmAssigned(uint32_t generation, uint8_t stationId,
                        uint16_t queueId, uint16_t queueCapacity,
                        bool queueSlotAvailable);
    Result legacyDqaAssigned(uint32_t generation, uint8_t stationId,
                             uint16_t queueId, uint16_t queueCapacity,
                             bool queueSlotAvailable);
    Result staticQueueConfigured(uint32_t generation,
                                 uint8_t stationId,
                                 bool queueTwoAvailable);
    Result allocationRejected(uint32_t generation,
                              uint8_t stationId);
    Result allocationOutcomeUnknown(uint32_t generation,
                                    uint8_t stationId);
    Result txSubmitted(uint32_t generation, uint16_t queueId);
    Result txCompleted(uint32_t generation, uint16_t queueId);
    Result txCancelled(uint32_t generation, uint16_t queueId);
    Result beginRemoval(uint32_t generation, uint16_t queueId);
    // Operation-aware DATA_PATH queue removal ACK.
    Result removeAcknowledged(uint32_t generation,
                              uint16_t queueId);
    // Legacy LONG_GROUP queues are firmware-owned by station and end only
    // after the station removal ACK following TXPATH_FLUSH.
    Result stationRemovalAcknowledged(uint32_t generation,
                                      uint16_t queueId);
    // Releases a legacy dynamic queue only when station removal ACKed and
    // the caller has separately proven that this allocation was never
    // doorbelled; ordinary completion-based queueDrained stays strict.
    Result neverSubmittedQueueReleasedAfterStationRemoval(
        uint32_t generation, uint16_t queueId);
    Result removeOutcomeUnknown(uint32_t generation,
                                uint16_t queueId);
    Result queueDrained(uint32_t generation, uint16_t queueId);
    Result resetAfterFirmwareDrain(uint32_t newGeneration);
    QueueSnapshot snapshot() const;

private:
    QueueState state_;
    QueueApi api_;
    uint16_t queueId_;
    uint8_t stationId_;
    uint32_t generation_;
    uint32_t outstandingTx_;
    bool completionObserved_;
    bool ringMustRemainOwned_;
    bool removeAcked_;
    bool drained_;
};

struct ActionFrameInfo {
    uint8_t type;
    uint8_t subtype;
    uint16_t headerLength;
    uint8_t destination[6];
    uint8_t source[6];
    uint8_t bssid[6];
};

struct TvqmAddFields {
    uint8_t stationId;
    uint8_t tid;
    uint16_t flags;
    uint32_t circularBufferSizeCode;
    uint64_t byteCountAddress;
    uint64_t descriptorAddress;
};

// Encodes the 36-byte DATA_PATH_GROUP/SCD_QUEUE_CONFIG_CMD API operation ADD
// payload. The legacy LONG_GROUP/SCD_QUEUE_CFG API v2 has no matching remove
// operation, so this HAL uses the operation-aware command pair. All multibyte
// fields are little-endian and inputs are bounds checked.
bool encodeTvqmAddCommand(const TvqmAddFields &fields,
                          uint8_t output[36]);

// Encodes the operation-aware queue REMOVE payload for one station/TID pair.
bool encodeTvqmRemoveCommand(uint8_t stationId, uint8_t tid,
                             uint8_t output[12]);

// Accept complete 802.11 Action management frames only. This is a packet
// shape check; it does not prove that the interface, channel lease, station,
// queue, or radio is ready to transmit.
bool parseActionFrame(const uint8_t *frame, size_t length,
                      ActionFrameInfo *info);

} // namespace IntelP2PTx

