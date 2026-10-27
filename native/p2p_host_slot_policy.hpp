// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

// Offline policy model only. It is intentionally not linked into AirportItlwm.
// A production caller must populate this evidence from an explicit, per-queue
// ownership ledger; it must not infer ownership from ring bytes or queue ID.
namespace IntelP2PHostSlot {

constexpr uint16_t kInvalidQueue = 0xffff;
constexpr uint16_t kMaximumQueueCapacity = 512;
constexpr size_t kStaTidSlotCount = 9; // eight QoS TIDs plus management slot

enum class FirmwareOwner : uint8_t {
    kUnknown = 0,
    // Positive, current-epoch ledger evidence that no firmware queue owns ID.
    kKnownFree,
    kInfrastructureManagement,
    kInfrastructureTid,
    kAuxiliary,
    kMonitor,
    kP2pPending,
    kP2pActive,
    kQuarantined
};

enum class HostRing : uint8_t {
    kUnknown = 0,
    kEmpty,
    // Memory allocated during attach as a static slot placeholder. This label
    // alone does not prove that firmware never received the ring's addresses.
    kStaticPlaceholder,
    // A ring whose addresses were submitted to firmware for an active lease.
    kFirmwareBacked
};

enum class Decision : uint8_t {
    kRejectInvalidQueue,
    kRejectStaleEpoch,
    kRejectMissingOwnerProof,
    kRejectFirmwareOwner,
    kRejectStaticManagementMapping,
    kRejectStaTidMapping,
    kRejectPendingOrUnknownAllocation,
    kRejectBusyHostResources,
    kRejectUnvalidatedResponse,
    kRejectUnknownHostRing,
    kInstallInEmptySlot,
    kReplaceProvenPlaceholder
};

struct Evidence {
    uint16_t queueId;
    uint16_t queueCapacity;

    // firmwareEpoch advances only after a physical firmware drain/reset has
    // been established. sc_generation alone is not sufficient evidence.
    uint32_t firmwareEpoch;
    uint32_t ownerEvidenceEpoch;
    uint32_t hostSlotEpoch;

    FirmwareOwner firmwareOwner;
    HostRing hostRing;
    bool ownerEvidenceComplete;

    bool staticManagementQueueAssigned;
    uint16_t staticManagementQueueId;
    uint8_t staTidMappingCount;
    uint16_t staTidQueueIds[kStaTidSlotCount];

    uint32_t queuedDescriptors;
    uint32_t outstandingTx;
    uint32_t ownedMbufs;
    uint32_t inFlightDma;
    bool submissionPending;
    bool allocationOutcomeUnknown;

    // The ACK must be structurally valid and must correspond to the new ring
    // whose DMA addresses were submitted by this allocation attempt.
    bool queueResponseValidated;
    bool responseTargetsReplacementRing;
};

inline Decision evaluate(const Evidence &e)
{
    if (e.queueCapacity == 0 || e.queueCapacity > kMaximumQueueCapacity ||
        e.queueId >= e.queueCapacity)
        return Decision::kRejectInvalidQueue;

    if (e.firmwareEpoch == 0 || e.ownerEvidenceEpoch != e.firmwareEpoch ||
        e.hostSlotEpoch != e.firmwareEpoch)
        return Decision::kRejectStaleEpoch;

    if (!e.ownerEvidenceComplete ||
        e.firmwareOwner == FirmwareOwner::kUnknown)
        return Decision::kRejectMissingOwnerProof;

    if (e.firmwareOwner != FirmwareOwner::kKnownFree)
        return Decision::kRejectFirmwareOwner;

    if (e.staticManagementQueueAssigned &&
        e.staticManagementQueueId == e.queueId)
        return Decision::kRejectStaticManagementMapping;

    if (e.staTidMappingCount != kStaTidSlotCount)
        return Decision::kRejectMissingOwnerProof;
    for (size_t i = 0; i < e.staTidMappingCount; ++i) {
        if (e.staTidQueueIds[i] == e.queueId)
            return Decision::kRejectStaTidMapping;
    }

    if (e.submissionPending || e.allocationOutcomeUnknown)
        return Decision::kRejectPendingOrUnknownAllocation;

    if (e.queuedDescriptors != 0 || e.outstandingTx != 0 ||
        e.ownedMbufs != 0 || e.inFlightDma != 0)
        return Decision::kRejectBusyHostResources;

    if (!e.queueResponseValidated || !e.responseTargetsReplacementRing)
        return Decision::kRejectUnvalidatedResponse;

    if (e.hostRing == HostRing::kEmpty)
        return Decision::kInstallInEmptySlot;
    if (e.hostRing == HostRing::kStaticPlaceholder)
        return Decision::kReplaceProvenPlaceholder;
    return Decision::kRejectUnknownHostRing;
}

} // namespace IntelP2PHostSlot
