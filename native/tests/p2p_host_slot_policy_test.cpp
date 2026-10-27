// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_host_slot_policy.hpp"

#include <assert.h>

using IntelP2PHostSlot::Decision;
using IntelP2PHostSlot::Evidence;
using IntelP2PHostSlot::FirmwareOwner;
using IntelP2PHostSlot::HostRing;

static Evidence knownUnusedPlaceholder()
{
    Evidence e{};
    e.queueId = 2;
    e.queueCapacity = 512;
    e.firmwareEpoch = 17;
    e.ownerEvidenceEpoch = 17;
    e.hostSlotEpoch = 17;
    e.firmwareOwner = FirmwareOwner::kKnownFree;
    e.hostRing = HostRing::kStaticPlaceholder;
    e.ownerEvidenceComplete = true;
    e.staTidMappingCount = 9;
    for (size_t i = 0; i < e.staTidMappingCount; ++i)
        e.staTidQueueIds[i] = IntelP2PHostSlot::kInvalidQueue;
    e.queueResponseValidated = true;
    e.responseTargetsReplacementRing = true;
    return e;
}

int main()
{
    // A placeholder is replaceable only with positive current-epoch proof
    // that firmware does not own its old ring and no host users remain.
    Evidence e = knownUnusedPlaceholder();
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kReplaceProvenPlaceholder);

    // Empty, positively free slots can receive the returned firmware queue.
    e.hostRing = HostRing::kEmpty;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kInstallInEmptySlot);

    // A placeholder's shape is never enough to infer that it is unowned.
    e = knownUnusedPlaceholder();
    e.ownerEvidenceComplete = false;
    e.firmwareOwner = FirmwareOwner::kUnknown;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectMissingOwnerProof);

    // Stale ownership or storage epochs cannot authorize a takeover.
    e = knownUnusedPlaceholder();
    e.ownerEvidenceEpoch--;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectStaleEpoch);
    e = knownUnusedPlaceholder();
    e.hostSlotEpoch--;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectStaleEpoch);

    // Active firmware owners and current static management assignments block.
    e = knownUnusedPlaceholder();
    e.firmwareOwner = FirmwareOwner::kInfrastructureManagement;
    e.staticManagementQueueAssigned = true;
    e.staticManagementQueueId = 2;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectFirmwareOwner);
    e = knownUnusedPlaceholder();
    e.staticManagementQueueAssigned = true;
    e.staticManagementQueueId = 2;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectStaticManagementMapping);

    // A TID mapping is an independent guard even if the owner ledger is stale.
    e = knownUnusedPlaceholder();
    e.staTidQueueIds[3] = 2;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectStaTidMapping);
    e = knownUnusedPlaceholder();
    e.staTidMappingCount = 8;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectMissingOwnerProof);

    // In-flight work, ambiguous allocation, and pending submissions retain
    // both rings and deny replacement.
    e = knownUnusedPlaceholder();
    e.outstandingTx = 1;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectBusyHostResources);
    e = knownUnusedPlaceholder();
    e.queuedDescriptors = 1;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectBusyHostResources);
    e = knownUnusedPlaceholder();
    e.ownedMbufs = 1;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectBusyHostResources);
    e = knownUnusedPlaceholder();
    e.inFlightDma = 1;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectBusyHostResources);
    e = knownUnusedPlaceholder();
    e.submissionPending = true;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectPendingOrUnknownAllocation);
    e = knownUnusedPlaceholder();
    e.allocationOutcomeUnknown = true;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectPendingOrUnknownAllocation);

    // No malformed response, foreign ring, or out-of-range qid is actionable.
    e = knownUnusedPlaceholder();
    e.queueResponseValidated = false;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectUnvalidatedResponse);
    e = knownUnusedPlaceholder();
    e.responseTargetsReplacementRing = false;
    assert(IntelP2PHostSlot::evaluate(e) ==
           Decision::kRejectUnvalidatedResponse);
    e = knownUnusedPlaceholder();
    e.hostRing = HostRing::kFirmwareBacked;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectUnknownHostRing);
    e = knownUnusedPlaceholder();
    e.queueId = 512;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectInvalidQueue);
    e = knownUnusedPlaceholder();
    e.queueCapacity = 513;
    assert(IntelP2PHostSlot::evaluate(e) == Decision::kRejectInvalidQueue);

    return 0;
}
