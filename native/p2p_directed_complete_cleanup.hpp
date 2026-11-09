// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_DIRECTED_COMPLETE_CLEANUP_HPP
#define NATIVE_P2P_DIRECTED_COMPLETE_CLEANUP_HPP

#include "awdl_directed_origin_tx.hpp"

namespace NativeP2PDirectedCompleteCleanup {

struct InnerProof {
    bool mainGate;
    bool ownerCurrent;
    bool contextGenerationMatches;
    bool powerGenerationMatches;
    bool stationGenerationMatches;
    bool firmwareGenerationMatches;
    bool p2pFirmwareGenerationMatches;
    bool canonicalEnd;
    bool rocTokenMatches;
    bool rocComplete;
    bool bindingAbsent;
    bool phyUnleased;
    bool originalChannelRestored;
    bool stationQueueDataAbsent;
    bool originTicketMatches;
    bool originNoPendingPackets;
    bool originTerminalAccepted;
};

inline bool innerProofComplete(const InnerProof &proof)
{
    return proof.mainGate && proof.ownerCurrent &&
        proof.contextGenerationMatches && proof.powerGenerationMatches &&
        proof.stationGenerationMatches && proof.firmwareGenerationMatches &&
        proof.p2pFirmwareGenerationMatches && proof.canonicalEnd &&
        proof.rocTokenMatches && proof.rocComplete && proof.bindingAbsent &&
        proof.phyUnleased && proof.originalChannelRestored &&
        proof.stationQueueDataAbsent && proof.originTicketMatches &&
        proof.originNoPendingPackets && proof.originTerminalAccepted;
}

struct OriginProof {
    bool ticketMatches;
    bool noPendingPackets;
    bool terminalAccepted;
};

// A Spent ticket remains Spent when close() is called: close() only changes
// active tickets. Keep that successful terminal state distinct from Closed,
// while requiring HAL completion for Spent and the no-doorbell proof for
// expiry/revocation.
inline OriginProof evaluateOriginProof(
    const NativeAwdlDirectedOriginTx::Snapshot &snapshot,
    const NativeAwdlDirectedOriginTx::Ticket &runTicket,
    uint64_t currentOwnerSerial, uint64_t currentRunSerial,
    bool dataOriginClosed, bool dataOriginTicketBound,
    bool halCompletionObserved, bool noDoorbell)
{
    using namespace NativeAwdlDirectedOriginTx;
    OriginProof proof{};
    proof.noPendingPackets = !snapshot.packetQueued &&
        !snapshot.packetPopping;
    if (snapshot.packetCount == kMaximumPackets) {
        for (size_t slot = 0; slot < kMaximumPackets; ++slot)
            proof.noPendingPackets = proof.noPendingPackets &&
                !snapshot.packets[slot].packetQueued &&
                !snapshot.packets[slot].packetPopping;
    }
    if (!dataOriginClosed || dataOriginTicketBound ||
        !proof.noPendingPackets || !currentOwnerSerial || !currentRunSerial)
        return proof;

    if (runTicket.ticketSerial != 0) {
        proof.ticketMatches = snapshot.ticketPresent &&
            snapshot.ticketSerial == runTicket.ticketSerial &&
            snapshot.ownerSerial == runTicket.ownerSerial &&
            snapshot.runSerial == runTicket.runSerial &&
            snapshot.interfaceIncarnation == runTicket.interfaceIncarnation &&
            snapshot.rocStartUs == runTicket.rocStartUs &&
            snapshot.deadlineUs == runTicket.deadlineUs &&
            snapshot.ifindex == runTicket.ifindex &&
            sameEpochs(snapshot.epochs, runTicket.epochs) &&
            runTicket.ownerSerial == currentOwnerSerial &&
            runTicket.runSerial == currentRunSerial;
    } else if (!snapshot.ticketPresent) {
        proof.ticketMatches = snapshot.state == State::Closed &&
            snapshot.ticketSerial == 0 && snapshot.ownerSerial == 0 &&
            snapshot.runSerial == 0 && snapshot.interfaceIncarnation == 0;
    }

    if (!proof.ticketMatches)
        return proof;
    if (snapshot.packetCount == kMaximumPackets) {
        // This is a resource-retirement proof, not a successful-exchange
        // verdict. A consumed BSD packet may never have reached the hardware,
        // or packet one may be complete while packet two never got admitted.
        // The caller must provide either no doorbell in this entire run, or
        // exact completion for EVERY actual doorbell (never the current slot
        // flag or QueueLease's historical completionObserved alone).
        const auto &first = snapshot.packets[0];
        const auto &second = snapshot.packets[1];
        const bool identitiesBound = first.present && second.present &&
            first.slot == 0 && second.slot == 1 && first.packetSerial &&
            second.packetSerial && first.packetSerial != second.packetSerial;
        if (!identitiesBound || (!noDoorbell && !halCompletionObserved))
            return proof;
        switch (snapshot.state) {
        case State::Spent:
        case State::Closed:
        case State::Expired:
        case State::Revoked:
        case State::Failed:
            proof.terminalAccepted = true;
            break;
        default:
            break;
        }
        return proof;
    }
    switch (snapshot.state) {
    case State::Spent:
        proof.terminalAccepted = snapshot.packetSpent &&
            halCompletionObserved;
        break;
    case State::Closed:
        proof.terminalAccepted = !snapshot.packetSpent;
        break;
    case State::Expired:
    case State::Revoked:
        proof.terminalAccepted = !snapshot.packetSpent && noDoorbell;
        break;
    default:
        proof.terminalAccepted = false;
        break;
    }
    return proof;
}

struct OuterProof {
    bool matchingRemoveResponse;
    bool removeResultZero;
    bool outerResourcesAbsent;
    bool finalResourcesAbsent;
};

inline bool outerProofComplete(const OuterProof &proof)
{
    return proof.matchingRemoveResponse && proof.removeResultZero &&
        proof.outerResourcesAbsent && proof.finalResourcesAbsent;
}

} // namespace NativeP2PDirectedCompleteCleanup

#endif
