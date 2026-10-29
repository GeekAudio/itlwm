// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_tx_window_evidence.hpp"

namespace NativeAwdlTxWindowEvidence {

Ledger::Ledger()
    : diagnosticGeneration_(0), epoch_{}, schedules_{}, tickets_{},
      initialized_(false)
{
}

bool Ledger::validEpoch(const Epoch &epoch)
{
    return epoch.contextGeneration != 0 && epoch.powerGeneration != 0 &&
           epoch.stationGeneration != 0 && epoch.rocGeneration != 0;
}

bool Ledger::sameEpoch(const Epoch &left, const Epoch &right)
{
    return left.contextGeneration == right.contextGeneration &&
           left.powerGeneration == right.powerGeneration &&
           left.stationGeneration == right.stationGeneration &&
           left.rocGeneration == right.rocGeneration;
}

bool Ledger::sameIdentity(const TicketIdentity &left,
                          const TicketIdentity &right)
{
    return left.diagnosticGeneration == right.diagnosticGeneration &&
           left.frameKind == right.frameKind &&
           left.frameOrdinal == right.frameOrdinal &&
           left.frameSequenceControl == right.frameSequenceControl &&
           left.ticketToken == right.ticketToken &&
           sameEpoch(left.epoch, right.epoch) &&
           left.queueId == right.queueId &&
           left.ringSize == right.ringSize &&
           left.descriptorIndex == right.descriptorIndex &&
           left.peerToken == right.peerToken &&
           left.scheduleRevision == right.scheduleRevision;
}

bool Ledger::validFrameKind(FrameKind kind)
{
    return kind == FrameKind::Psf || kind == FrameKind::Mif;
}

bool Ledger::containsTime(const ScheduleEntry &schedule,
                          uint64_t eventTimeUs)
{
    return schedule.valid && schedule.observedAtUs <= eventTimeUs &&
           eventTimeUs < schedule.validUntilUs;
}

Status Ledger::beginDiagnosticGeneration(uint64_t diagnosticGeneration,
                                         const Epoch &epoch)
{
    if (!diagnosticGeneration ||
        (initialized_ && diagnosticGeneration <= diagnosticGeneration_))
        return Status::InvalidDiagnosticGeneration;
    if (!validEpoch(epoch))
        return Status::InvalidEpoch;

    for (size_t i = 0; i < kScheduleCapacity; ++i)
        schedules_[i] = ScheduleEntry{};
    for (size_t i = 0; i < kTicketCapacity; ++i)
        tickets_[i] = TicketEntry{};

    diagnosticGeneration_ = diagnosticGeneration;
    epoch_ = epoch;
    initialized_ = true;
    return Status::Ready;
}

Ledger::ScheduleEntry *Ledger::findSchedule(uint64_t peerToken)
{
    for (size_t i = 0; i < kScheduleCapacity; ++i)
        if (schedules_[i].used && schedules_[i].peerToken == peerToken)
            return &schedules_[i];
    return nullptr;
}

const Ledger::ScheduleEntry *Ledger::findSchedule(uint64_t peerToken) const
{
    for (size_t i = 0; i < kScheduleCapacity; ++i)
        if (schedules_[i].used && schedules_[i].peerToken == peerToken)
            return &schedules_[i];
    return nullptr;
}

void Ledger::invalidatePeerTickets(uint64_t peerToken,
                                   uint64_t newScheduleRevision)
{
    for (size_t i = 0; i < kTicketCapacity; ++i) {
        TicketEntry &entry = tickets_[i];
        if (entry.used && entry.peerBindingVerified &&
            entry.identity.peerToken == peerToken &&
            entry.identity.scheduleRevision != newScheduleRevision)
            entry.scheduleStale = true;
    }
}

Status Ledger::observePeerSchedule(const PeerScheduleWitness &witness,
                                   uint64_t nowUs)
{
    if (!initialized_ || !witness.diagnosticGeneration)
        return Status::InvalidDiagnosticGeneration;
    if (witness.diagnosticGeneration != diagnosticGeneration_)
        return Status::StaleDiagnosticGeneration;
    if (!validEpoch(witness.epoch))
        return Status::InvalidEpoch;
    if (!sameEpoch(witness.epoch, epoch_))
        return Status::EpochMismatch;
    if (!witness.peerToken || !witness.scheduleRevision ||
        !witness.channel)
        return Status::InvalidIdentity;
    if (!witness.tlv18FieldsVerified ||
        !witness.sameMonotonicDomainVerified)
        return Status::MissingScheduleWitness;
    if (witness.observedAtUs > nowUs)
        return Status::OutOfOrderEvidence;
    if (witness.validUntilUs <= witness.observedAtUs ||
        nowUs >= witness.validUntilUs)
        return Status::ExpiredScheduleWitness;

    ScheduleEntry *schedule = findSchedule(witness.peerToken);
    if (schedule) {
        if (witness.scheduleRevision < schedule->scheduleRevision)
            return Status::ScheduleRevisionReused;
        if (witness.scheduleRevision == schedule->scheduleRevision) {
            if (witness.channel != schedule->channel ||
                witness.observedAtUs != schedule->observedAtUs ||
                witness.validUntilUs != schedule->validUntilUs) {
                schedule->valid = false;
                invalidatePeerTickets(witness.peerToken, 0);
                return Status::ScheduleRevisionReused;
            }
            return schedule->valid ? Status::Ready :
                Status::ScheduleRevisionReused;
        }
        if (witness.observedAtUs < schedule->observedAtUs)
            return Status::OutOfOrderEvidence;

        invalidatePeerTickets(witness.peerToken,
                              witness.scheduleRevision);
        schedule->scheduleRevision = witness.scheduleRevision;
        schedule->channel = witness.channel;
        schedule->observedAtUs = witness.observedAtUs;
        schedule->validUntilUs = witness.validUntilUs;
        schedule->valid = true;
        return Status::Ready;
    }

    for (size_t i = 0; i < kScheduleCapacity; ++i) {
        if (!schedules_[i].used) {
            ScheduleEntry entry{};
            entry.peerToken = witness.peerToken;
            entry.scheduleRevision = witness.scheduleRevision;
            entry.channel = witness.channel;
            entry.observedAtUs = witness.observedAtUs;
            entry.validUntilUs = witness.validUntilUs;
            entry.used = true;
            entry.valid = true;
            schedules_[i] = entry;
            return Status::Ready;
        }
    }
    return Status::ScheduleCapacityFull;
}

Status Ledger::validateIdentity(const TicketIdentity &identity) const
{
    if (!initialized_ || !identity.diagnosticGeneration)
        return Status::InvalidDiagnosticGeneration;
    if (identity.diagnosticGeneration != diagnosticGeneration_)
        return Status::StaleDiagnosticGeneration;
    if (!validEpoch(identity.epoch))
        return Status::InvalidEpoch;
    if (!sameEpoch(identity.epoch, epoch_))
        return Status::EpochMismatch;
    const bool peerBindingFieldsMatch =
        (identity.peerToken == 0) == (identity.scheduleRevision == 0);
    if (!validFrameKind(identity.frameKind) || !identity.ticketToken ||
        identity.queueId == 0xffff || identity.queueId > 0xff ||
        identity.ringSize < 8 ||
        (identity.ringSize & (identity.ringSize - 1)) != 0 ||
        identity.descriptorIndex >= identity.ringSize ||
        !peerBindingFieldsMatch)
        return Status::InvalidIdentity;
    return Status::Ready;
}

Status Ledger::beginTicket(const TicketIdentity &identity, uint64_t nowUs)
{
    const Status identityStatus = validateIdentity(identity);
    if (identityStatus != Status::Ready)
        return identityStatus;

    for (size_t i = 0; i < kTicketCapacity; ++i)
        if (tickets_[i].used &&
            tickets_[i].identity.ticketToken == identity.ticketToken)
            return Status::DuplicateTicketToken;

    const ScheduleEntry *schedule = nullptr;
    bool peerBindingVerified = false;
    if (identity.peerToken && identity.scheduleRevision) {
        schedule = findSchedule(identity.peerToken);
        peerBindingVerified = schedule && schedule->valid &&
            schedule->scheduleRevision == identity.scheduleRevision &&
            containsTime(*schedule, nowUs);
    }

    for (size_t i = 0; i < kTicketCapacity; ++i) {
        if (!tickets_[i].used) {
            TicketEntry entry{};
            entry.identity = identity;
            entry.createdAtUs = nowUs;
            if (peerBindingVerified) {
                entry.scheduleObservedAtUs = schedule->observedAtUs;
                entry.scheduleValidUntilUs = schedule->validUntilUs;
            }
            entry.peerBindingVerified = peerBindingVerified;
            entry.used = true;
            tickets_[i] = entry;
            return peerBindingVerified ? Status::Ready :
                Status::LocalTicketRecordedUnbound;
        }
    }
    return Status::TicketCapacityFull;
}

Status Ledger::findTicket(const TicketIdentity &identity,
                          TicketEntry **output)
{
    if (!output)
        return Status::InvalidIdentity;
    *output = nullptr;
    const Status status = validateIdentity(identity);
    if (status != Status::Ready)
        return status;

    for (size_t i = 0; i < kTicketCapacity; ++i) {
        TicketEntry &entry = tickets_[i];
        if (entry.used && entry.identity.ticketToken == identity.ticketToken) {
            if (!sameIdentity(entry.identity, identity))
                return Status::IdentityMismatch;
            *output = &entry;
            return Status::Ready;
        }
    }
    return Status::TicketNotFound;
}

const Ledger::TicketEntry *Ledger::findTicket(
    const TicketIdentity &identity) const
{
    if (validateIdentity(identity) != Status::Ready)
        return nullptr;
    for (size_t i = 0; i < kTicketCapacity; ++i) {
        const TicketEntry &entry = tickets_[i];
        if (entry.used && entry.identity.ticketToken == identity.ticketToken &&
            sameIdentity(entry.identity, identity))
            return &entry;
    }
    return nullptr;
}

Status Ledger::recordSubmission(const SubmissionWitness &witness)
{
    TicketEntry *entry = nullptr;
    const Status findStatus = findTicket(witness.identity, &entry);
    if (findStatus != Status::Ready)
        return findStatus;
    if (entry->invalidated)
        return Status::TicketInvalidated;
    if (entry->completed || entry->submitted)
        return Status::DuplicateSubmission;
    if (entry->scheduleStale)
        return Status::StaleScheduleRevision;

    if (entry->peerBindingVerified) {
        const ScheduleEntry *schedule = findSchedule(entry->identity.peerToken);
        if (entry->scheduleStale || !schedule || !schedule->valid ||
            schedule->scheduleRevision != entry->identity.scheduleRevision)
            return Status::StaleScheduleRevision;
    }
    if (!witness.immediatelyBeforeDoorbellVerified ||
        !witness.sameMonotonicDomainVerified)
        return Status::MissingSubmissionWitness;
    if (witness.preDoorbellLowerUs < entry->createdAtUs) {
        entry->invalidated = true;
        return Status::OutOfOrderEvidence;
    }
    if (entry->peerBindingVerified) {
        if (witness.preDoorbellLowerUs < entry->scheduleObservedAtUs)
            return Status::OutOfOrderEvidence;
        if (witness.preDoorbellLowerUs >= entry->scheduleValidUntilUs)
            return Status::ScheduleExpiredAtEvent;
    }

    entry->preDoorbellLowerUs = witness.preDoorbellLowerUs;
    entry->submitted = true;
    return Status::Ready;
}

Status Ledger::recordCompletion(const CompletionWitness &witness)
{
    TicketEntry *entry = nullptr;
    const Status findStatus = findTicket(witness.identity, &entry);
    if (findStatus != Status::Ready)
        return findStatus;
    if (entry->completed)
        return Status::DuplicateCompletion;
    if (entry->invalidated)
        return Status::TicketInvalidated;
    if (entry->peerBindingVerified && entry->scheduleStale)
        return Status::StaleScheduleRevision;

    if (witness.source == CompletionSource::Flush) {
        entry->invalidated = true;
        return Status::FlushRejected;
    }
    if (witness.source == CompletionSource::LatePoll)
        return Status::LatePollIsNotTap;
    if (witness.source != CompletionSource::MatchingNotificationTap)
        return Status::WrongCompletionSource;

    if (witness.firmwareOutcome != FirmwareOutcome::Success) {
        entry->invalidated = true;
        return witness.firmwareOutcome == FirmwareOutcome::Failure ?
            Status::FirmwareFailure : Status::FirmwareOutcomeUnknown;
    }

    if (!witness.matchingTicketVerified ||
        !witness.matchingIdentityVerified || !witness.upperBoundVerified ||
        !witness.sameMonotonicDomainVerified)
        return Status::MissingCompletionWitness;
    if (!entry->submitted) {
        entry->invalidated = true;
        return Status::CompletionBeforeSubmission;
    }
    if (witness.notificationTapUpperUs < entry->preDoorbellLowerUs) {
        entry->invalidated = true;
        return Status::OutOfOrderEvidence;
    }
    if (entry->peerBindingVerified) {
        if (witness.notificationTapUpperUs < entry->scheduleObservedAtUs) {
            entry->invalidated = true;
            return Status::OutOfOrderEvidence;
        }
        if (witness.notificationTapUpperUs >= entry->scheduleValidUntilUs) {
            entry->invalidated = true;
            return Status::ScheduleExpiredAtEvent;
        }

        const ScheduleEntry *schedule = findSchedule(entry->identity.peerToken);
        if (!schedule || !schedule->valid ||
            schedule->scheduleRevision != entry->identity.scheduleRevision)
            return Status::StaleScheduleRevision;
    }

    entry->notificationTapUpperUs = witness.notificationTapUpperUs;
    entry->completed = true;
    return Status::Ready;
}

Status Ledger::markPostDoorbellStateUnknown(const TicketIdentity &identity)
{
    TicketEntry *entry = nullptr;
    const Status findStatus = findTicket(identity, &entry);
    if (findStatus != Status::Ready)
        return findStatus;
    if (!entry->submitted) {
        entry->invalidated = true;
        return Status::OutOfOrderEvidence;
    }
    entry->invalidated = true;
    return Status::FirmwareOutcomeUnknown;
}

bool Ledger::snapshotTicket(size_t index, TicketSnapshot *output) const
{
    if (!output || index >= kTicketCapacity || !tickets_[index].used)
        return false;
    const TicketEntry &entry = tickets_[index];
    TicketSnapshot snapshot{};
    snapshot.identity = entry.identity;
    snapshot.createdAtUs = entry.createdAtUs;
    snapshot.scheduleObservedAtUs = entry.scheduleObservedAtUs;
    snapshot.scheduleValidUntilUs = entry.scheduleValidUntilUs;
    snapshot.preDoorbellLowerUs = entry.preDoorbellLowerUs;
    snapshot.notificationTapUpperUs = entry.notificationTapUpperUs;
    snapshot.used = entry.used;
    snapshot.scheduleStale = entry.scheduleStale;
    snapshot.invalidated = entry.invalidated;
    snapshot.peerBindingVerified = entry.peerBindingVerified;
    snapshot.submitted = entry.submitted;
    snapshot.completed = entry.completed;
    *output = snapshot;
    return true;
}

RetrospectiveResult Ledger::assessRetrospectively(
    const TicketIdentity &identity,
    const GuardedSharedWindowWitness &window) const
{
    if (!initialized_ ||
        validateIdentity(identity) != Status::Ready ||
        window.diagnosticGeneration != diagnosticGeneration_ ||
        !validEpoch(window.epoch) || !sameEpoch(window.epoch, epoch_) ||
        !identity.peerToken || !identity.scheduleRevision ||
        window.peerToken != identity.peerToken ||
        window.scheduleRevision != identity.scheduleRevision ||
        !window.peerToken || !window.scheduleRevision || !window.channel ||
        window.startUs >= window.endUs ||
        window.evidenceValidFromUs >= window.evidenceValidUntilUs ||
        !window.sameMonotonicDomainVerified ||
        !window.clockMappingVerified || !window.peerEventVerified ||
        !window.scheduleVerified || !window.guardPolicyVerified ||
        !window.alreadyGuardedSharedWindowVerified)
        return RetrospectiveResult::RetrospectiveUnknown;

    const TicketEntry *entry = findTicket(identity);
    if (!entry || entry->invalidated || entry->scheduleStale ||
        !entry->peerBindingVerified ||
        !entry->submitted || !entry->completed)
        return RetrospectiveResult::RetrospectiveUnknown;

    const ScheduleEntry *schedule = findSchedule(identity.peerToken);
    if (!schedule || !schedule->valid ||
        schedule->scheduleRevision != identity.scheduleRevision ||
        schedule->channel != window.channel)
        return RetrospectiveResult::RetrospectiveUnknown;

    const uint64_t lowerUs = entry->preDoorbellLowerUs;
    const uint64_t upperUs = entry->notificationTapUpperUs;
    if (lowerUs < window.evidenceValidFromUs ||
        upperUs >= window.evidenceValidUntilUs)
        return RetrospectiveResult::RetrospectiveUnknown;

    return lowerUs >= window.startUs && upperUs < window.endUs ?
        RetrospectiveResult::RetrospectiveCovered :
        RetrospectiveResult::RetrospectiveNotContained;
}

} // namespace NativeAwdlTxWindowEvidence
