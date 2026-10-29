// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_tx_window_evidence.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace NativeAwdlTxWindowEvidence;

static const Epoch kEpoch = {11, 12, 13, 14};
static const uint64_t kDiagnosticGeneration = 5;
static const uint64_t kPeerToken = 7001;
static const uint64_t kScheduleRevision = 9;

static PeerScheduleWitness scheduleWitness(uint64_t peerToken = kPeerToken,
                                           uint64_t revision = kScheduleRevision,
                                           uint8_t channel = 6,
                                           uint64_t observedAtUs = 100,
                                           uint64_t validUntilUs = 10000)
{
    PeerScheduleWitness witness{};
    witness.diagnosticGeneration = kDiagnosticGeneration;
    witness.epoch = kEpoch;
    witness.peerToken = peerToken;
    witness.scheduleRevision = revision;
    witness.channel = channel;
    witness.observedAtUs = observedAtUs;
    witness.validUntilUs = validUntilUs;
    witness.tlv18FieldsVerified = true;
    witness.sameMonotonicDomainVerified = true;
    return witness;
}

static TicketIdentity identity(uint64_t ticketToken = 101,
                               uint32_t ordinal = 1,
                               FrameKind kind = FrameKind::Psf)
{
    TicketIdentity result{};
    result.diagnosticGeneration = kDiagnosticGeneration;
    result.frameKind = kind;
    result.frameOrdinal = ordinal;
    result.frameSequenceControl = static_cast<uint16_t>(ordinal << 4);
    result.ticketToken = ticketToken;
    result.epoch = kEpoch;
    result.queueId = 37;
    result.ringSize = 64;
    result.descriptorIndex = static_cast<uint16_t>(ordinal + 2);
    result.peerToken = kPeerToken;
    result.scheduleRevision = kScheduleRevision;
    return result;
}

static SubmissionWitness submission(const TicketIdentity &id,
                                    uint64_t lowerUs = 500)
{
    SubmissionWitness result{};
    result.identity = id;
    result.preDoorbellLowerUs = lowerUs;
    result.immediatelyBeforeDoorbellVerified = true;
    result.sameMonotonicDomainVerified = true;
    return result;
}

static CompletionWitness completion(const TicketIdentity &id,
                                    uint64_t upperUs = 800)
{
    CompletionWitness result{};
    result.identity = id;
    result.notificationTapUpperUs = upperUs;
    result.source = CompletionSource::MatchingNotificationTap;
    result.firmwareOutcome = FirmwareOutcome::Success;
    result.matchingTicketVerified = true;
    result.matchingIdentityVerified = true;
    result.upperBoundVerified = true;
    result.sameMonotonicDomainVerified = true;
    return result;
}

static GuardedSharedWindowWitness window(uint64_t startUs = 500,
                                          uint64_t endUs = 801)
{
    GuardedSharedWindowWitness result{};
    result.diagnosticGeneration = kDiagnosticGeneration;
    result.epoch = kEpoch;
    result.peerToken = kPeerToken;
    result.scheduleRevision = kScheduleRevision;
    result.channel = 6;
    result.startUs = startUs;
    result.endUs = endUs;
    result.evidenceValidFromUs = 100;
    result.evidenceValidUntilUs = 10000;
    result.sameMonotonicDomainVerified = true;
    result.clockMappingVerified = true;
    result.peerEventVerified = true;
    result.scheduleVerified = true;
    result.guardPolicyVerified = true;
    result.alreadyGuardedSharedWindowVerified = true;
    return result;
}

static void startLedger(Ledger &ledger,
                        uint64_t scheduleValidUntilUs = 10000)
{
    assert(ledger.beginDiagnosticGeneration(kDiagnosticGeneration, kEpoch) ==
           Status::Ready);
    const PeerScheduleWitness witness =
        scheduleWitness(kPeerToken, kScheduleRevision, 6, 100,
                        scheduleValidUntilUs);
    assert(ledger.observePeerSchedule(witness, 200) == Status::Ready);
}

static void addCompletedTicket(Ledger &ledger, const TicketIdentity &id,
                               uint64_t lowerUs = 500,
                               uint64_t upperUs = 800)
{
    assert(ledger.beginTicket(id, 200) == Status::Ready);
    assert(ledger.recordSubmission(submission(id, lowerUs)) == Status::Ready);
    assert(ledger.recordCompletion(completion(id, upperUs)) == Status::Ready);
}

static TicketIdentity unboundIdentity(uint64_t ticketToken = 1001,
                                      uint32_t ordinal = 1,
                                      FrameKind kind = FrameKind::Mif)
{
    TicketIdentity result = identity(ticketToken, ordinal, kind);
    result.peerToken = 0;
    result.scheduleRevision = 0;
    return result;
}

static void testRetrospectiveContainmentAndHalfOpenBoundary()
{
    Ledger ledger;
    startLedger(ledger);
    const TicketIdentity id = identity();
    addCompletedTicket(ledger, id);

    assert(ledger.assessRetrospectively(id, window(500, 801)) ==
           RetrospectiveResult::RetrospectiveCovered);
    assert(ledger.assessRetrospectively(id, window(501, 801)) ==
           RetrospectiveResult::RetrospectiveNotContained);
    // The shared window is half-open, so an upper bound equal to its end is
    // not contained. It is not an air-time or packet-receipt assertion.
    assert(ledger.assessRetrospectively(id, window(500, 800)) ==
           RetrospectiveResult::RetrospectiveNotContained);

    GuardedSharedWindowWitness missing = window();
    missing.clockMappingVerified = false;
    assert(ledger.assessRetrospectively(id, missing) ==
           RetrospectiveResult::RetrospectiveUnknown);
    missing = window();
    missing.peerEventVerified = false;
    assert(ledger.assessRetrospectively(id, missing) ==
           RetrospectiveResult::RetrospectiveUnknown);
    missing = window();
    missing.alreadyGuardedSharedWindowVerified = false;
    assert(ledger.assessRetrospectively(id, missing) ==
           RetrospectiveResult::RetrospectiveUnknown);
}

static void testWrongTicketEpochDescriptorAndSchedule()
{
    Ledger ledger;
    startLedger(ledger);
    const TicketIdentity id = identity();
    assert(ledger.beginTicket(id, 200) == Status::Ready);

    SubmissionWitness wrong = submission(id);
    wrong.identity.ticketToken++;
    assert(ledger.recordSubmission(wrong) == Status::TicketNotFound);
    wrong = submission(id);
    wrong.identity.descriptorIndex++;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.queueId++;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.ringSize = 128;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.scheduleRevision++;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.frameOrdinal++;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.frameSequenceControl++;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.frameKind = FrameKind::Mif;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.peerToken++;
    assert(ledger.recordSubmission(wrong) == Status::IdentityMismatch);
    wrong = submission(id);
    wrong.identity.epoch.stationGeneration++;
    assert(ledger.recordSubmission(wrong) == Status::EpochMismatch);

    assert(ledger.recordSubmission(submission(id)) == Status::Ready);
    CompletionWitness wrongCompletion = completion(id);
    wrongCompletion.identity.descriptorIndex++;
    assert(ledger.recordCompletion(wrongCompletion) ==
           Status::IdentityMismatch);
    assert(ledger.recordCompletion(completion(id)) == Status::Ready);

    GuardedSharedWindowWitness wrongWindow = window();
    wrongWindow.peerToken++;
    assert(ledger.assessRetrospectively(id, wrongWindow) ==
           RetrospectiveResult::RetrospectiveUnknown);
    wrongWindow = window();
    wrongWindow.scheduleRevision++;
    assert(ledger.assessRetrospectively(id, wrongWindow) ==
           RetrospectiveResult::RetrospectiveUnknown);
}

static void testScheduleRevisionChangeInvalidatesOldPeerTickets()
{
    Ledger ledger;
    startLedger(ledger);
    const TicketIdentity oldId = identity();
    assert(ledger.beginTicket(oldId, 200) == Status::Ready);
    assert(ledger.recordSubmission(submission(oldId)) == Status::Ready);

    PeerScheduleWitness revised = scheduleWitness(
        kPeerToken, kScheduleRevision + 1, 11, 600, 20000);
    assert(ledger.observePeerSchedule(revised, 650) == Status::Ready);
    assert(ledger.recordCompletion(completion(oldId)) ==
           Status::StaleScheduleRevision);
    assert(ledger.assessRetrospectively(oldId, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);

    TicketIdentity staleRevision = identity(102, 2);
    assert(ledger.beginTicket(staleRevision, 700) ==
           Status::LocalTicketRecordedUnbound);
    assert(ledger.recordSubmission(submission(staleRevision, 710)) ==
           Status::Ready);
    assert(ledger.recordCompletion(completion(staleRevision, 800)) ==
           Status::Ready);
    assert(ledger.assessRetrospectively(staleRevision, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);

    TicketIdentity newId = identity(103, 3, FrameKind::Mif);
    newId.scheduleRevision = kScheduleRevision + 1;
    assert(ledger.beginTicket(newId, 700) == Status::Ready);
    assert(ledger.recordSubmission(submission(newId, 800)) == Status::Ready);
    assert(ledger.recordCompletion(completion(newId, 900)) == Status::Ready);

    GuardedSharedWindowWitness newWindow = window(800, 901);
    newWindow.scheduleRevision = kScheduleRevision + 1;
    newWindow.channel = 11;
    newWindow.evidenceValidUntilUs = 20000;
    assert(ledger.assessRetrospectively(newId, newWindow) ==
           RetrospectiveResult::RetrospectiveCovered);
}

static void testExpirationAndEventOrdering()
{
    Ledger ledger;
    startLedger(ledger, 800);
    const TicketIdentity id = identity();
    assert(ledger.beginTicket(id, 200) == Status::Ready);
    const TicketIdentity expiredBinding = identity(102, 2);
    assert(ledger.beginTicket(expiredBinding, 800) ==
           Status::LocalTicketRecordedUnbound);
    assert(ledger.recordSubmission(submission(expiredBinding, 801)) ==
           Status::Ready);
    assert(ledger.recordCompletion(completion(expiredBinding, 802)) ==
           Status::Ready);
    assert(ledger.assessRetrospectively(expiredBinding, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);
    assert(ledger.recordSubmission(submission(id, 500)) == Status::Ready);
    assert(ledger.recordCompletion(completion(id, 800)) ==
           Status::ScheduleExpiredAtEvent);
    assert(ledger.recordSubmission(submission(id, 600)) ==
           Status::TicketInvalidated);
    assert(ledger.assessRetrospectively(id, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);

    Ledger inverse;
    startLedger(inverse);
    const TicketIdentity inverseId = identity(201);
    assert(inverse.beginTicket(inverseId, 200) == Status::Ready);
    assert(inverse.recordCompletion(completion(inverseId, 400)) ==
           Status::CompletionBeforeSubmission);
    assert(inverse.recordSubmission(submission(inverseId, 300)) ==
           Status::TicketInvalidated);

    Ledger reversed;
    startLedger(reversed);
    const TicketIdentity reversedId = identity(301);
    assert(reversed.beginTicket(reversedId, 200) == Status::Ready);
    assert(reversed.recordSubmission(submission(reversedId, 500)) ==
           Status::Ready);
    assert(reversed.recordCompletion(completion(reversedId, 499)) ==
           Status::OutOfOrderEvidence);
    assert(reversed.assessRetrospectively(reversedId, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);
}

static void testMissingEvidenceLatePollAndTerminalOutcomes()
{
    Ledger ledger;
    startLedger(ledger);
    const TicketIdentity id = identity();
    assert(ledger.beginTicket(id, 200) == Status::Ready);

    SubmissionWitness missingSubmit = submission(id);
    missingSubmit.immediatelyBeforeDoorbellVerified = false;
    assert(ledger.recordSubmission(missingSubmit) ==
           Status::MissingSubmissionWitness);
    assert(ledger.recordSubmission(submission(id)) == Status::Ready);

    CompletionWitness latePoll = completion(id, 800);
    latePoll.source = CompletionSource::LatePoll;
    assert(ledger.recordCompletion(latePoll) == Status::LatePollIsNotTap);
    CompletionWitness missingTap = completion(id, 800);
    missingTap.upperBoundVerified = false;
    assert(ledger.recordCompletion(missingTap) ==
           Status::MissingCompletionWitness);
    assert(ledger.recordCompletion(completion(id, 800)) == Status::Ready);
    assert(ledger.assessRetrospectively(id, window()) ==
           RetrospectiveResult::RetrospectiveCovered);

    const FirmwareOutcome outcomes[] = {
        FirmwareOutcome::Failure, FirmwareOutcome::Unknown
    };
    const Status expected[] = {Status::FirmwareFailure,
                               Status::FirmwareOutcomeUnknown};
    for (size_t i = 0; i < 2; ++i) {
        Ledger terminal;
        startLedger(terminal);
        const TicketIdentity terminalId = identity(400 + i);
        assert(terminal.beginTicket(terminalId, 200) == Status::Ready);
        assert(terminal.recordSubmission(submission(terminalId)) ==
               Status::Ready);
        CompletionWitness event = completion(terminalId, 800);
        event.firmwareOutcome = outcomes[i];
        assert(terminal.recordCompletion(event) == expected[i]);
        assert(terminal.recordCompletion(completion(terminalId, 850)) ==
               Status::TicketInvalidated);
        assert(terminal.assessRetrospectively(terminalId, window()) ==
               RetrospectiveResult::RetrospectiveUnknown);
    }

    Ledger flushed;
    startLedger(flushed);
    const TicketIdentity flushId = identity(500);
    assert(flushed.beginTicket(flushId, 200) == Status::Ready);
    assert(flushed.recordSubmission(submission(flushId)) == Status::Ready);
    CompletionWitness flush = completion(flushId, 800);
    flush.source = CompletionSource::Flush;
    assert(flushed.recordCompletion(flush) == Status::FlushRejected);
    assert(flushed.assessRetrospectively(flushId, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);

    Ledger postDoorbellFailure;
    startLedger(postDoorbellFailure);
    const TicketIdentity failedFinishId = identity(501);
    assert(postDoorbellFailure.beginTicket(failedFinishId, 200) ==
           Status::Ready);
    assert(postDoorbellFailure.recordSubmission(
               submission(failedFinishId)) == Status::Ready);
    assert(postDoorbellFailure.markPostDoorbellStateUnknown(failedFinishId) ==
           Status::FirmwareOutcomeUnknown);
    assert(postDoorbellFailure.assessRetrospectively(failedFinishId, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);
    assert(postDoorbellFailure.recordCompletion(
               completion(failedFinishId)) == Status::TicketInvalidated);
}

static void testDuplicateEvidenceDoesNotOverwrite()
{
    Ledger ledger;
    startLedger(ledger);
    const TicketIdentity id = identity();
    assert(ledger.beginTicket(id, 200) == Status::Ready);
    assert(ledger.recordSubmission(submission(id, 500)) == Status::Ready);
    assert(ledger.recordSubmission(submission(id, 700)) ==
           Status::DuplicateSubmission);
    assert(ledger.recordCompletion(completion(id, 800)) == Status::Ready);
    assert(ledger.recordCompletion(completion(id, 900)) ==
           Status::DuplicateCompletion);

    // Original [500,800] remains. A replacement with [700,900] would fit.
    assert(ledger.assessRetrospectively(id, window(600, 850)) ==
           RetrospectiveResult::RetrospectiveNotContained);
}

static void testFixedCapacityAndExplicitGenerationClear()
{
    Ledger ledger;
    startLedger(ledger);
    TicketIdentity first = identity(600, 0);
    for (size_t i = 0; i < kTicketCapacity; ++i) {
        TicketIdentity id = identity(600 + i, static_cast<uint32_t>(i));
        assert(ledger.beginTicket(id, 200) == Status::Ready);
    }
    const TicketIdentity overflow = identity(700, 9);
    assert(ledger.beginTicket(overflow, 200) == Status::TicketCapacityFull);
    assert(ledger.recordSubmission(submission(first)) == Status::Ready);
    assert(ledger.recordCompletion(completion(first)) == Status::Ready);
    assert(ledger.assessRetrospectively(first, window()) ==
           RetrospectiveResult::RetrospectiveCovered);

    assert(ledger.beginDiagnosticGeneration(kDiagnosticGeneration,
                                             kEpoch) ==
           Status::InvalidDiagnosticGeneration);
    assert(ledger.beginDiagnosticGeneration(kDiagnosticGeneration + 1,
                                             kEpoch) == Status::Ready);
    assert(ledger.recordSubmission(submission(first)) ==
           Status::StaleDiagnosticGeneration);

    TicketIdentity newGeneration = first;
    newGeneration.diagnosticGeneration = kDiagnosticGeneration + 1;
    assert(ledger.beginTicket(newGeneration, 200) ==
           Status::LocalTicketRecordedUnbound);
}

static void testScheduleCapacityAndNoEviction()
{
    Ledger ledger;
    assert(ledger.beginDiagnosticGeneration(kDiagnosticGeneration, kEpoch) ==
           Status::Ready);
    for (size_t i = 0; i < kScheduleCapacity; ++i) {
        PeerScheduleWitness witness = scheduleWitness(
            8000 + i, kScheduleRevision, 6, 100, 10000);
        assert(ledger.observePeerSchedule(witness, 200) == Status::Ready);
    }
    PeerScheduleWitness overflow = scheduleWitness(
        9000, kScheduleRevision, 6, 100, 10000);
    assert(ledger.observePeerSchedule(overflow, 200) ==
           Status::ScheduleCapacityFull);

    TicketIdentity preserved = identity(801);
    preserved.peerToken = 8000;
    assert(ledger.beginTicket(preserved, 200) == Status::Ready);
}

static void testFirstMifCanBeRecordedWithoutPeerSchedule()
{
    Ledger ledger;
    assert(ledger.beginDiagnosticGeneration(kDiagnosticGeneration, kEpoch) ==
           Status::Ready);
    const TicketIdentity firstMif = unboundIdentity();
    assert(ledger.beginTicket(firstMif, 10) ==
           Status::LocalTicketRecordedUnbound);
    assert(ledger.recordSubmission(submission(firstMif, 20)) == Status::Ready);
    assert(ledger.recordCompletion(completion(firstMif, 30)) == Status::Ready);
    assert(ledger.assessRetrospectively(firstMif, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);

    // A later peer schedule cannot retroactively bind the immutable ticket.
    PeerScheduleWitness lateSchedule = scheduleWitness(
        kPeerToken, kScheduleRevision, 6, 15, 1000);
    assert(ledger.observePeerSchedule(lateSchedule, 40) == Status::Ready);
    assert(ledger.assessRetrospectively(firstMif, window()) ==
           RetrospectiveResult::RetrospectiveUnknown);
}

static void testScheduleRevisionCannotGoBackwardOrRefreshInPlace()
{
    Ledger ledger;
    startLedger(ledger);
    assert(ledger.observePeerSchedule(scheduleWitness(), 250) == Status::Ready);
    assert(ledger.observePeerSchedule(
        scheduleWitness(kPeerToken, kScheduleRevision - 1), 250) ==
        Status::ScheduleRevisionReused);
    const TicketIdentity id = identity();
    addCompletedTicket(ledger, id);
    assert(ledger.observePeerSchedule(
        scheduleWitness(kPeerToken, kScheduleRevision, 6, 100, 11000), 900) ==
        Status::ScheduleRevisionReused);
    assert(ledger.assessRetrospectively(id, window()) ==
        RetrospectiveResult::RetrospectiveUnknown);
    assert(ledger.observePeerSchedule(scheduleWitness(), 900) ==
        Status::ScheduleRevisionReused);
    assert(ledger.observePeerSchedule(
        scheduleWitness(kPeerToken, kScheduleRevision + 1, 6, 900, 11000), 900) ==
        Status::Ready);
    assert(ledger.observePeerSchedule(scheduleWitness(), 950) ==
        Status::ScheduleRevisionReused);
}

static void testUnknownOutcomeCannotBecomeSuccessfulCompletion()
{
    const unsigned rawOutcomes[] = {3, 255};
    for (size_t i = 0; i < 2; ++i) {
        Ledger ledger;
        startLedger(ledger);
        const TicketIdentity id = identity();
        assert(ledger.beginTicket(id, 200) == Status::Ready);
        assert(ledger.recordSubmission(submission(id)) == Status::Ready);
        CompletionWitness bad = completion(id);
        bad.firmwareOutcome = static_cast<FirmwareOutcome>(rawOutcomes[i]);
        assert(ledger.recordCompletion(bad) == Status::FirmwareOutcomeUnknown);
        assert(ledger.recordCompletion(completion(id, 900)) ==
            Status::TicketInvalidated);
        assert(ledger.assessRetrospectively(id, window()) ==
            RetrospectiveResult::RetrospectiveUnknown);
    }
}

static void testCreationEventPrecedesSubmissionAndSnapshotIsCopyOnly()
{
    Ledger ledger;
    startLedger(ledger);
    const TicketIdentity bad = identity(901);
    assert(ledger.beginTicket(bad, 900) == Status::Ready);
    assert(ledger.recordSubmission(submission(bad, 500)) ==
        Status::OutOfOrderEvidence);
    assert(ledger.recordCompletion(completion(bad, 800)) ==
        Status::TicketInvalidated);
    assert(ledger.assessRetrospectively(bad, window()) ==
        RetrospectiveResult::RetrospectiveUnknown);

    TicketSnapshot snapshot{};
    assert(ledger.snapshotTicket(0, &snapshot));
    assert(snapshot.createdAtUs == 900 && snapshot.invalidated &&
           !snapshot.submitted && !snapshot.completed);
    snapshot.identity.ticketToken = 9999;
    assert(ledger.snapshotTicket(0, &snapshot));
    assert(snapshot.identity.ticketToken == bad.ticketToken);

    TicketSnapshot sentinel;
    memset(&sentinel, 0x5a, sizeof(sentinel));
    unsigned char before[sizeof(sentinel)];
    memcpy(before, &sentinel, sizeof(sentinel));
    assert(!ledger.snapshotTicket(1, &sentinel));
    assert(!ledger.snapshotTicket(kTicketCapacity, &sentinel));
    assert(memcmp(before, &sentinel, sizeof(sentinel)) == 0);
    assert(!ledger.snapshotTicket(0, nullptr));

    Ledger healthy;
    startLedger(healthy);
    const TicketIdentity good = identity(902);
    assert(healthy.beginTicket(good, 500) == Status::Ready);
    assert(healthy.recordSubmission(submission(good, 500)) == Status::Ready);
    assert(healthy.recordCompletion(completion(good, 800)) == Status::Ready);
    assert(healthy.assessRetrospectively(good, window()) ==
        RetrospectiveResult::RetrospectiveCovered);
}

int main()
{
    testRetrospectiveContainmentAndHalfOpenBoundary();
    testWrongTicketEpochDescriptorAndSchedule();
    testScheduleRevisionChangeInvalidatesOldPeerTickets();
    testExpirationAndEventOrdering();
    testMissingEvidenceLatePollAndTerminalOutcomes();
    testDuplicateEvidenceDoesNotOverwrite();
    testFixedCapacityAndExplicitGenerationClear();
    testScheduleCapacityAndNoEviction();
    testFirstMifCanBeRecordedWithoutPeerSchedule();
    testScheduleRevisionCannotGoBackwardOrRefreshInPlace();
    testUnknownOutcomeCannotBecomeSuccessfulCompletion();
    testCreationEventPrecedesSubmissionAndSnapshotIsCopyOnly();
    puts("PASS: offline per-ticket AWDL time evidence ledger");
    return 0;
}
