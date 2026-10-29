// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_shared_window.hpp"

namespace NativeAwdlSharedWindow {
namespace {

bool addChecked(uint64_t left, uint64_t right, uint64_t *result)
{
    if (!result || right > UINT64_MAX - left)
        return false;
    *result = left + right;
    return true;
}

bool subtractChecked(uint64_t left, uint64_t right, uint64_t *result)
{
    if (!result || right > left)
        return false;
    *result = left - right;
    return true;
}

bool validEpoch(const Epoch &epoch)
{
    return epoch.contextGeneration != 0 && epoch.powerGeneration != 0 &&
           epoch.stationGeneration != 0 && epoch.rocGeneration != 0;
}

bool sameEpoch(const Epoch &left, const Epoch &right)
{
    return left.contextGeneration == right.contextGeneration &&
           left.powerGeneration == right.powerGeneration &&
           left.stationGeneration == right.stationGeneration &&
           left.rocGeneration == right.rocGeneration;
}

bool validBounds(const TimeBounds &bounds)
{
    return bounds.earliestUs <= bounds.latestUs;
}

bool liveWitness(uint64_t nowUs, uint64_t observedAtUs,
                 uint64_t validUntilUs)
{
    return observedAtUs <= nowUs && nowUs < validUntilUs;
}

} // namespace

Status plan(const Request *request, Candidate *output)
{
    if (!request || !output)
        return Status::NullArgument;

    if (!validEpoch(request->currentEpoch) ||
        !validEpoch(request->peer.epoch) ||
        !validEpoch(request->peerWindow.epoch) ||
        !validEpoch(request->localLease.epoch))
        return Status::InvalidEpoch;

    if (!sameEpoch(request->currentEpoch, request->peer.epoch) ||
        !sameEpoch(request->currentEpoch, request->peerWindow.epoch) ||
        !sameEpoch(request->currentEpoch, request->localLease.epoch))
        return Status::EpochMismatch;

    if (request->peer.peerToken == 0 || request->peerWindow.peerToken == 0)
        return Status::InvalidPeerToken;
    if (request->peer.peerToken != request->peerWindow.peerToken)
        return Status::PeerMismatch;
    if (request->peer.scheduleRevision == 0 ||
        request->peerWindow.scheduleRevision == 0)
        return Status::InvalidScheduleRevision;
    if (request->peer.scheduleRevision !=
        request->peerWindow.scheduleRevision)
        return Status::ScheduleRevisionMismatch;

    if (!request->peer.mifPeerValid)
        return Status::MissingMifPeerWitness;
    if (!request->peer.identityWitnessVerified)
        return Status::MissingIdentityWitness;
    if (!request->peer.identityMatchesCurrentPeer)
        return Status::IdentityMismatch;
    if (!request->peer.scheduleWitnessVerified)
        return Status::MissingScheduleWitness;
    if (!liveWitness(request->nowUs, request->peer.mifObservedAtUs,
                     request->peer.mifValidUntilUs) ||
        !liveWitness(request->nowUs, request->peer.scheduleObservedAtUs,
                     request->peer.scheduleValidUntilUs))
        return Status::ExpiredPeerWitness;

    if (!request->peerWindow.mappingVerified)
        return Status::UnverifiedClockMapping;
    if (!liveWitness(request->nowUs,
                     request->peerWindow.mappingObservedAtUs,
                     request->peerWindow.mappingValidUntilUs))
        return Status::ExpiredClockMapping;

    if (request->peer.channel == 0 || request->peerWindow.channel == 0 ||
        request->localLease.channel == 0)
        return Status::InvalidChannel;
    if (request->peer.channel != request->peerWindow.channel ||
        request->peer.channel != request->localLease.channel)
        return Status::ChannelMismatch;

    if (!request->localLease.known)
        return Status::UnknownLocalLease;
    if (!request->localLease.active)
        return Status::InactiveLocalLease;

    if (!request->guard.trafficSchedulePolicyVerified ||
        !request->guard.requiredGuardVerified)
        return Status::MissingGuardPolicy;
    if (request->guard.beforeUs < kThreeTuUs ||
        request->guard.afterUs < kThreeTuUs)
        return Status::GuardBelowMinimum;
    if (!request->txBudget.verified ||
        request->txBudget.packetAirtimeUs == 0)
        return Status::MissingTxBudget;

    if (!validBounds(request->peerWindow.mappedStartUs) ||
        !validBounds(request->peerWindow.mappedEndUs) ||
        !validBounds(request->localLease.startUs) ||
        !validBounds(request->localLease.endUs))
        return Status::InvalidInterval;

    uint64_t peerStartUs = 0;
    uint64_t peerEndUs = 0;
    if (!addChecked(request->peerWindow.mappedStartUs.latestUs,
                    request->peerWindow.verifiedErrorBoundUs,
                    &peerStartUs) ||
        !subtractChecked(request->peerWindow.mappedEndUs.earliestUs,
                         request->peerWindow.verifiedErrorBoundUs,
                         &peerEndUs))
        return Status::ArithmeticOverflow;
    if (peerEndUs <= peerStartUs)
        return Status::UncertaintyCoversWindow;

    const uint64_t leaseStartUs = request->localLease.startUs.latestUs;
    const uint64_t leaseEndUs = request->localLease.endUs.earliestUs;
    if (leaseEndUs <= leaseStartUs)
        return Status::InvalidInterval;

    // An active flag alone is insufficient: now must lie inside the part of
    // the lease guaranteed active for every value in its bounds.
    if (request->nowUs < leaseStartUs || request->nowUs >= leaseEndUs)
        return Status::InactiveLocalLease;

    uint64_t intersectionStartUs = peerStartUs > leaseStartUs ?
        peerStartUs : leaseStartUs;
    uint64_t intersectionEndUs = peerEndUs < leaseEndUs ?
        peerEndUs : leaseEndUs;
    if (request->peer.mifValidUntilUs < intersectionEndUs)
        intersectionEndUs = request->peer.mifValidUntilUs;
    if (request->peer.scheduleValidUntilUs < intersectionEndUs)
        intersectionEndUs = request->peer.scheduleValidUntilUs;
    if (request->peerWindow.mappingValidUntilUs < intersectionEndUs)
        intersectionEndUs = request->peerWindow.mappingValidUntilUs;
    if (intersectionEndUs <= intersectionStartUs)
        return Status::EmptyIntersection;

    if (intersectionEndUs <= intersectionStartUs)
        return Status::EmptyIntersection;
    if (request->nowUs >= intersectionEndUs)
        return Status::EmptyIntersection;

    uint64_t guardedStartUs = 0;
    if (!addChecked(intersectionStartUs, request->guard.beforeUs,
                    &guardedStartUs))
        return Status::ArithmeticOverflow;
    const uint64_t earliestCommitUs = request->nowUs > guardedStartUs ?
        request->nowUs : guardedStartUs;

    uint64_t trailingBudgetUs = request->guard.afterUs;
    if (!addChecked(trailingBudgetUs,
                    request->txBudget.commitToAirWorstCaseUs,
                    &trailingBudgetUs) ||
        !addChecked(trailingBudgetUs,
                    request->txBudget.packetAirtimeUs,
                    &trailingBudgetUs))
        return Status::ArithmeticOverflow;
    if (trailingBudgetUs > intersectionEndUs)
        return Status::NoCommitWindow;
    const uint64_t latestCommitUs = intersectionEndUs - trailingBudgetUs;

    if (earliestCommitUs > latestCommitUs)
        return Status::NoCommitWindow;

    Candidate candidate = {earliestCommitUs, latestCommitUs};
    *output = candidate;
    return Status::CandidateReady;
}

} // namespace NativeAwdlSharedWindow
