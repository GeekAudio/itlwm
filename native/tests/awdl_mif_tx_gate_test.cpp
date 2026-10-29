// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_frame.hpp"
#include "../awdl_bounded_psf_plan.hpp"
#include "../awdl_mif_tx_gate.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using NativeAwdl::ActionFrameInfo;
using NativeAwdl::ParseStatus;
using NativeAwdlProbe::MifCandidate;
using NativeAwdlProbe::MifCandidateStatus;
using NativeAwdlProbe::MifFollowupWitness;
using NativeAwdlProbe::PsfCandidate;
using NativeAwdlProbe::PsfRuntimeWitness;

static PsfCandidate firstPsfCandidate(bool nativeAddressVerified = false)
{
    constexpr uint64_t startUs = 1000000;
    NativeAwdlProbe::Request request{};
    const uint8_t address[] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    memcpy(request.p2pMac.bytes, address, sizeof(address));
    request.monotonicSampleUs = startUs;
    request.ieee80211SequenceNumber = 9;
    request.ht.confirmed = true;
    request.ht.capabilityInfo = 0x11ce;
    request.ht.ampduParameters = 0x1b;
    request.ht.rxMcsMask[0] = 0xff;
    request.ht.rxMcsLength = 1;
    request.nativeAddressVerified = nativeAddressVerified;

    PsfRuntimeWitness roc{};
    roc.expectedGeneration = 77;
    roc.sessionGeneration = 77;
    roc.startObservedUs = startUs - 10000;
    roc.hardDeadlineUs = startUs + 900000;
    roc.sampleUs = startUs;
    roc.matchingSuccessfulStart = true;
    roc.activeAtSample = true;
    NativeAwdlProbe::RocWitness window{};
    window.channel = 6;
    window.startUs = roc.startObservedUs;
    window.deadlineUs = roc.hardDeadlineUs;
    window.startConfirmed = true;
    window.activeAtSampleConfirmed = true;

    PsfCandidate candidate{};
    NativeAwdlProbe::Summary summary{};
    assert(NativeAwdlProbe::buildObservationOnlyPsfInput(
        &request, &window, &candidate.input, &summary) ==
        NativeAwdlProbe::PlanStatus::ObservationOnly);
    size_t written = 0;
    assert(NativeAwdl::encodePsf(&candidate.input, candidate.bytes,
        sizeof(candidate.bytes), &written) == NativeAwdl::EncodeStatus::Ok);
    candidate.length = written;
    candidate.contextGeneration = 77;
    candidate.startObservedUs = roc.startObservedUs;
    candidate.sampleUs = startUs;
    candidate.hardDeadlineUs = roc.hardDeadlineUs;
    candidate.blockers = 0;
    return candidate;
}

static MifFollowupWitness witnessFor(const PsfCandidate &first,
                                     uint64_t sampleUs)
{
    MifFollowupWitness witness{};
    witness.roc.expectedGeneration = first.contextGeneration;
    witness.roc.sessionGeneration = first.contextGeneration;
    witness.roc.startObservedUs = first.startObservedUs;
    witness.roc.hardDeadlineUs = first.hardDeadlineUs;
    witness.roc.sampleUs = sampleUs;
    witness.roc.matchingSuccessfulStart = true;
    witness.roc.activeAtSample = true;
    witness.nextSequenceNumber = 10;
    witness.firstPsfTicketStatus = 1;
    witness.firstPsfTicketSequenceControl = static_cast<uint16_t>(
        first.input.sequenceNumber << 4);
    witness.firstPsfTicketByteCount = static_cast<uint16_t>(first.length);
    witness.firstPsfTicketFrameControl = 0x00d0;
    witness.firstPsfTicketCompleted = true;
    witness.firstPsfTicketSucceeded = true;
    witness.queueLeaseActive = true;
    witness.txRingEmpty = true;
    witness.ringIndicesConsistent = true;
    return witness;
}

static void testMifUsesSameOriginAndChannelTable()
{
    const PsfCandidate first = firstPsfCandidate();
    MifFollowupWitness witness = witnessFor(first,
        first.sampleUs + 20 * 1024);
    const char hostname[] = "intel-awdl-probe";
    MifCandidate candidate{};
    assert(NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
        &first, &witness, 1, hostname, sizeof(hostname) - 1, &candidate) ==
        MifCandidateStatus::Encoded);
    assert(candidate.length > first.length && candidate.length <=
           NativeAwdl::kMaximumEncodedMifLength);
    assert(candidate.phaseOriginUs == first.sampleUs);
    assert(candidate.sampleUs == witness.roc.sampleUs);
    assert(candidate.input.sequenceNumber == witness.nextSequenceNumber);
    assert(candidate.input.nextAwSequenceNumber == 1);
    assert(candidate.input.txDownCounterTu == 44);
    assert(candidate.input.remainingAwLengthTu == 0);
    assert(candidate.input.apAlignment == 1);
    assert(candidate.input.nextAwChannel == 6);
    assert(candidate.input.phyTxTimestampUs ==
           static_cast<uint32_t>(candidate.sampleUs));
    assert(candidate.input.targetTxTimestampUs ==
           candidate.input.phyTxTimestampUs);
    assert(memcmp(candidate.input.channelSlots, first.input.channelSlots,
                  sizeof(candidate.input.channelSlots)) == 0);
    assert(memcmp(candidate.input.sourceAddress, first.input.sourceAddress, 6) == 0);
    assert(memcmp(candidate.input.masterAddress, first.input.masterAddress, 6) == 0);
    assert(memcmp(candidate.input.syncAddress, first.input.syncAddress, 6) == 0);
    assert(candidate.firstPsfTicketStatus == 1);
    assert(candidate.hostnameLength == sizeof(hostname) - 1);
    assert(memcmp(candidate.hostname, hostname, candidate.hostnameLength) == 0);

    ActionFrameInfo info{};
    assert(NativeAwdl::parseActionFrame(candidate.bytes, candidate.length,
        &info) == ParseStatus::Ok);
    assert(info.subtype == 3 && info.tlvCount == 9);
    const size_t arpa = 40 + (3 + 57) + (3 + 21) + (3 + 25) +
        (3 + 40) + (3 + 9) + (3 + 8);
    assert(candidate.bytes[arpa] == 16);
    assert(candidate.bytes[arpa + 3] == 3);
    assert(candidate.bytes[arpa + 4] == candidate.hostnameLength);
    assert(memcmp(candidate.bytes + arpa + 5, hostname,
                  candidate.hostnameLength) == 0);
    assert(candidate.bytes[arpa + 5 + candidate.hostnameLength] == 0xc0);
    assert(candidate.bytes[arpa + 6 + candidate.hostnameLength] == 0x0c);

    // Type 12 remains the empty zero-flags control-only form.
    const size_t dataPath = arpa + 3 + candidate.hostnameLength + 4;
    assert(candidate.bytes[dataPath] == 12);
    assert(candidate.bytes[dataPath + 1] == 2 &&
           candidate.bytes[dataPath + 2] == 0);
    assert(candidate.bytes[dataPath + 3] == 0 &&
           candidate.bytes[dataPath + 4] == 0);
}

static void testVerifiedAddressSurvivesMifFollowup()
{
    const PsfCandidate first = firstPsfCandidate(true);
    assert(first.input.advertiseAwdlAddress);
    assert(first.length == 234);
    assert(first.bytes[218] == 12 && first.bytes[219] == 8 &&
           first.bytes[220] == 0 && first.bytes[221] == 4 &&
           first.bytes[222] == 0);
    assert(memcmp(first.bytes + 10, first.bytes + 223, 6) == 0);

    MifFollowupWitness witness = witnessFor(first,
        first.sampleUs + 20 * 1024);
    const char hostname[] = "intel-awdl-probe";
    MifCandidate candidate{};
    assert(NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
        &first, &witness, 1, hostname, sizeof(hostname) - 1, &candidate) ==
        MifCandidateStatus::Encoded);
    assert(candidate.input.advertiseAwdlAddress);
    ActionFrameInfo info{};
    assert(NativeAwdl::parseActionFrame(candidate.bytes, candidate.length,
        &info) == ParseStatus::Ok);
    assert(info.subtype == 3);

    const size_t arpa = 40 + (3 + 57) + (3 + 21) + (3 + 25) +
        (3 + 40) + (3 + 9) + (3 + 8);
    assert(candidate.bytes[arpa] == 16);
    const size_t dataPath = arpa + sizeof(hostname) - 1 + 7;
    assert(candidate.bytes[dataPath] == 12);
    assert(candidate.bytes[dataPath + 1] == 8 &&
           candidate.bytes[dataPath + 2] == 0 &&
           candidate.bytes[dataPath + 3] == 4 &&
           candidate.bytes[dataPath + 4] == 0);
    assert(memcmp(candidate.bytes + dataPath + 5,
                  candidate.bytes + 10, 6) == 0);
    assert(memcmp(candidate.bytes + dataPath + 5,
                  candidate.input.sourceAddress, 6) == 0);
}

static void expectRejectedWithoutOutputChange(
    const PsfCandidate &first, MifFollowupWitness witness,
    MifCandidateStatus expected)
{
    MifCandidate output;
    memset(&output, 0xa5, sizeof(output));
    MifCandidate before;
    memcpy(&before, &output, sizeof(output));
    const char hostname[] = "intel-awdl-probe";
    assert(NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
        &first, &witness, 1, hostname, sizeof(hostname) - 1, &output) == expected);
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

static void testFollowupAdmissionAndFailureBoundaries()
{
    const PsfCandidate first = firstPsfCandidate();
    MifFollowupWitness witness = witnessFor(first,
        first.sampleUs + 20 * 1024);

    MifFollowupWitness failed = witness;
    failed.firstPsfTicketSucceeded = false;
    expectRejectedWithoutOutputChange(first, failed,
        MifCandidateStatus::FirstPsfFailed);

    MifFollowupWitness wrongSequence = witness;
    wrongSequence.nextSequenceNumber = 11;
    expectRejectedWithoutOutputChange(first, wrongSequence,
        MifCandidateStatus::InvalidRocWitness);

    MifFollowupWitness nonIdle = witness;
    nonIdle.txRingEmpty = false;
    expectRejectedWithoutOutputChange(first, nonIdle,
        MifCandidateStatus::QueueNotIdle);

    MifFollowupWitness wrongTicket = witness;
    wrongTicket.firstPsfTicketStatus = 0x0002;
    expectRejectedWithoutOutputChange(first, wrongTicket,
        MifCandidateStatus::InvalidRocWitness);

    MifCandidate output{};
    const char hostname[] = "intel-awdl-probe";
    assert(NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
        &first, &witness, 1, hostname, sizeof(hostname) - 1, &output) ==
        MifCandidateStatus::Encoded);
}

static void testBlockersAndNoScheduleReset()
{
    const PsfCandidate first = firstPsfCandidate();
    MifFollowupWitness witness = witnessFor(first,
        first.sampleUs + 20 * 1024);
    const char hostname[] = "intel-awdl-probe";
    MifCandidate candidate{};
    assert(NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
        &first, &witness, 1, hostname, sizeof(hostname) - 1, &candidate) ==
        MifCandidateStatus::Encoded);
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &witness, witness.roc.sampleUs) ==
        NativeAwdlProbe::kMifTxNoBlocker);

    MifFollowupWitness ended = witness;
    ended.roc.endSeen = true;
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &ended, witness.roc.sampleUs) &
        NativeAwdlProbe::kMifTxRocEnded);

    MifFollowupWitness deadlineChanged = witness;
    deadlineChanged.roc.hardDeadlineUs++;
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &deadlineChanged, witness.roc.sampleUs) &
        NativeAwdlProbe::kMifTxInvalidMonotonicWitness);

    MifFollowupWitness ticketChanged = witness;
    ticketChanged.firstPsfTicketSequenceControl++;
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &ticketChanged, witness.roc.sampleUs) &
        NativeAwdlProbe::kMifTxFirstPsfFailed);

    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &witness, witness.roc.sampleUs + 1) ==
        NativeAwdlProbe::kMifTxNoBlocker);
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &witness, witness.roc.sampleUs + 53) ==
        NativeAwdlProbe::kMifTxNoBlocker);

    MifFollowupWitness stale = witness;
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &stale,
        candidate.sampleUs + NativeAwdlProbe::kMaximumPreparedPsfAgeUs + 1) &
        NativeAwdlProbe::kMifTxPreparedFrameStale);

    MifFollowupWitness noRing = witness;
    noRing.txRingEmpty = false;
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &noRing, witness.roc.sampleUs + 1000) &
        NativeAwdlProbe::kMifTxQueueNotIdle);

    MifFollowupWitness wrongSequence = witness;
    wrongSequence.nextSequenceNumber++;
    assert(NativeAwdlProbe::mifFollowupTxBlockers(
        &candidate, &wrongSequence, witness.roc.sampleUs + 1000) &
        NativeAwdlProbe::kMifTxInvalidMonotonicWitness);

    // After the first 13 complete slots, the unchanged table has no channel;
    // MIF preflight refuses instead of restarting the sequence at slot zero.
    MifFollowupWitness expiredSlot = witnessFor(first,
        first.sampleUs + 13 * NativeAwdlProbe::kHostPhaseSlotDurationUs);
    expectRejectedWithoutOutputChange(first, expiredSlot,
        MifCandidateStatus::PhaseRejected);
}

int main()
{
    testMifUsesSameOriginAndChannelTable();
    testVerifiedAddressSurvivesMifFollowup();
    testFollowupAdmissionAndFailureBoundaries();
    testBlockersAndNoScheduleReset();
    return 0;
}
