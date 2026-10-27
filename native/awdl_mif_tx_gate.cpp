// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_mif_tx_gate.hpp"

#include "awdl_action_frame.hpp"

#include <string.h>

namespace NativeAwdlProbe {
namespace {

bool validPsfCandidate(const PsfCandidate &candidate)
{
    if (candidate.length == 0 || candidate.length > sizeof(candidate.bytes))
        return false;
    NativeAwdl::ActionFrameInfo info{};
    return NativeAwdl::parseActionFrame(candidate.bytes, candidate.length,
        &info) == NativeAwdl::ParseStatus::Ok && info.subtype == 0 &&
        info.version == 0x10 && info.phyTx == candidate.input.phyTxTimestampUs &&
        info.targetTx == candidate.input.targetTxTimestampUs;
}

HostPhaseStatus calculateCandidatePhase(const PsfCandidate &firstPsf,
                                        uint64_t sampleUs,
                                        HostPhaseFields *phase)
{
    if (!phase)
        return HostPhaseStatus::InvalidArgument;
    HostPhaseInput input{};
    input.phaseOriginUs = firstPsf.sampleUs;
    input.sampleUs = sampleUs;
    input.rocStartUs = firstPsf.startObservedUs;
    input.hardDeadlineUs = firstPsf.hardDeadlineUs;
    input.rocChannel = firstPsf.input.masterChannel;
    memcpy(input.channelSlots, firstPsf.input.channelSlots,
           sizeof(input.channelSlots));
    return buildHostPhaseFields(&input, phase);
}

uint32_t basicFollowupBlockers(const MifCandidate &candidate,
                               const MifFollowupWitness &witness,
                               uint64_t sampleUs)
{
    uint32_t blockers = kMifTxNoBlocker;
    const PsfRuntimeWitness &roc = witness.roc;
    if (candidate.length == 0 || candidate.length > sizeof(candidate.bytes))
        blockers |= kMifTxInvalidCandidate;
    if (!witness.firstPsfTicketCompleted)
        blockers |= kMifTxFirstPsfNotCompleted;
    if (!witness.firstPsfTicketSucceeded)
        blockers |= kMifTxFirstPsfFailed;
    if (!witness.queueLeaseActive || !witness.txRingEmpty ||
        !witness.ringIndicesConsistent)
        blockers |= kMifTxQueueNotIdle;
    if (!roc.matchingSuccessfulStart || !roc.activeAtSample)
        blockers |= kMifTxRocNotActive;
    if (!candidate.contextGeneration ||
        roc.expectedGeneration != candidate.contextGeneration ||
        roc.sessionGeneration != candidate.contextGeneration)
        blockers |= kMifTxGenerationMismatch;
    if (roc.endSeen)
        blockers |= kMifTxRocEnded;
    if (roc.outcomeUnknown)
        blockers |= kMifTxRocUnknown;
    if (!roc.startObservedUs ||
        roc.startObservedUs != candidate.startObservedUs ||
        roc.hardDeadlineUs != candidate.hardDeadlineUs ||
        roc.sampleUs != sampleUs || sampleUs < candidate.phaseOriginUs ||
        candidate.phaseOriginUs < candidate.startObservedUs ||
        candidate.hardDeadlineUs <= candidate.phaseOriginUs)
        blockers |= kMifTxInvalidMonotonicWitness;
    if (sampleUs >= candidate.hardDeadlineUs)
        blockers |= kMifTxLeaseExpired;
    if (sampleUs < candidate.sampleUs ||
        sampleUs - candidate.sampleUs > kMaximumPreparedPsfAgeUs)
        blockers |= kMifTxPreparedFrameStale;
    if (witness.nextSequenceNumber != candidate.input.sequenceNumber)
        blockers |= kMifTxInvalidMonotonicWitness;
    const uint16_t expectedNextSequence = static_cast<uint16_t>(
        ((candidate.firstPsfTicketSequenceControl >> 4) + 1u) & 0x0fffu);
    if (candidate.input.sequenceNumber != expectedNextSequence ||
        (candidate.firstPsfTicketSequenceControl & 0x000fu) != 0)
        blockers |= kMifTxInvalidMonotonicWitness;
    if ((candidate.firstPsfTicketStatus & 0xffu) != 1u ||
        witness.firstPsfTicketStatus != candidate.firstPsfTicketStatus ||
        witness.firstPsfTicketSequenceControl !=
            candidate.firstPsfTicketSequenceControl ||
        witness.firstPsfTicketByteCount != candidate.firstPsfTicketByteCount ||
        witness.firstPsfTicketFrameControl !=
            candidate.firstPsfTicketFrameControl ||
        candidate.firstPsfTicketByteCount == 0 ||
        candidate.firstPsfTicketFrameControl != 0x00d0u)
        blockers |= kMifTxFirstPsfFailed;
    return blockers;
}

bool candidateMatchesPhase(const MifCandidate &candidate,
                           const HostPhaseFields &phase)
{
    return candidate.input.phyTxTimestampUs == phase.phyTxTimestampUs &&
        candidate.input.targetTxTimestampUs == phase.targetTxTimestampUs &&
        candidate.input.nextAwChannel == phase.nextAwChannel &&
        candidate.input.txDownCounterTu == phase.txDownCounterTu &&
        candidate.input.remainingAwLengthTu == phase.remainingAwLengthTu &&
        candidate.input.nextAwSequenceNumber == phase.nextAwSequenceNumber &&
        candidate.input.apAlignment == phase.apAlignment &&
        memcmp(candidate.input.channelSlots, phase.channelSlots,
               sizeof(phase.channelSlots)) == 0;
}

} // namespace

MifCandidateStatus prepareExperimentalMifFollowupCandidate(
    const PsfCandidate *firstPsf, const MifFollowupWitness *witness,
    uint32_t firstPsfTicketStatus, const char *hostname,
    size_t hostnameLength, MifCandidate *output)
{
    if (!firstPsf || !witness || !hostname || !output ||
        hostnameLength == 0 ||
        hostnameLength > NativeAwdl::kMaximumArpaHostLabelLength)
        return MifCandidateStatus::InvalidArgument;
    if (!validPsfCandidate(*firstPsf))
        return MifCandidateStatus::FirstPsfInvalid;
    if (!witness->firstPsfTicketCompleted)
        return MifCandidateStatus::FirstPsfNotCompleted;
    if (!witness->firstPsfTicketSucceeded)
        return MifCandidateStatus::FirstPsfFailed;
    if ((firstPsfTicketStatus & 0xffu) != 1u)
        return MifCandidateStatus::FirstPsfFailed;
    if (!witness->queueLeaseActive || !witness->txRingEmpty ||
        !witness->ringIndicesConsistent)
        return MifCandidateStatus::QueueNotIdle;
    const uint16_t expectedNextSequence = static_cast<uint16_t>(
        (firstPsf->input.sequenceNumber + 1u) & 0x0fffu);
    if (witness->nextSequenceNumber != expectedNextSequence)
        return MifCandidateStatus::InvalidRocWitness;

    MifCandidate candidate{};
    candidate.input = firstPsf->input;
    candidate.input.sequenceNumber = witness->nextSequenceNumber;
    candidate.phaseOriginUs = firstPsf->sampleUs;
    candidate.startObservedUs = firstPsf->startObservedUs;
    candidate.sampleUs = witness->roc.sampleUs;
    candidate.hardDeadlineUs = firstPsf->hardDeadlineUs;
    candidate.contextGeneration = firstPsf->contextGeneration;
    candidate.firstPsfTicketStatus = firstPsfTicketStatus;
    candidate.firstPsfTicketSequenceControl = static_cast<uint16_t>(
        firstPsf->input.sequenceNumber << 4);
    candidate.firstPsfTicketByteCount = static_cast<uint16_t>(
        firstPsf->length);
    candidate.firstPsfTicketFrameControl = 0x00d0u;
    candidate.hostnameLength = hostnameLength;
    memcpy(candidate.hostname, hostname, hostnameLength);

    if (!witness->roc.matchingSuccessfulStart ||
        !witness->roc.activeAtSample || witness->roc.endSeen ||
        witness->roc.outcomeUnknown ||
        witness->roc.expectedGeneration != candidate.contextGeneration ||
        witness->roc.sessionGeneration != candidate.contextGeneration ||
        witness->roc.startObservedUs != candidate.startObservedUs)
        return MifCandidateStatus::InvalidRocWitness;

    if (calculateCandidatePhase(*firstPsf, candidate.sampleUs,
                                &candidate.phase) != HostPhaseStatus::Ok)
        return MifCandidateStatus::PhaseRejected;
    candidate.input.phyTxTimestampUs = candidate.phase.phyTxTimestampUs;
    candidate.input.targetTxTimestampUs = candidate.phase.targetTxTimestampUs;
    candidate.input.nextAwChannel = candidate.phase.nextAwChannel;
    candidate.input.txDownCounterTu = candidate.phase.txDownCounterTu;
    candidate.input.remainingAwLengthTu = candidate.phase.remainingAwLengthTu;
    candidate.input.nextAwSequenceNumber =
        candidate.phase.nextAwSequenceNumber;
    candidate.input.apAlignment = candidate.phase.apAlignment;
    memcpy(candidate.input.channelSlots, candidate.phase.channelSlots,
           sizeof(candidate.input.channelSlots));

    NativeAwdl::MifInput mifInput{};
    mifInput.psf = candidate.input;
    mifInput.hostname = candidate.hostname;
    mifInput.hostnameLength = candidate.hostnameLength;
    size_t written = 0;
    if (NativeAwdl::encodeMif(&mifInput, candidate.bytes,
            sizeof(candidate.bytes), &written) != NativeAwdl::MifEncodeStatus::Ok ||
        written == 0 || written > sizeof(candidate.bytes))
        return MifCandidateStatus::EncoderRejected;

    NativeAwdl::ActionFrameInfo info{};
    if (NativeAwdl::parseActionFrame(candidate.bytes, written, &info) !=
            NativeAwdl::ParseStatus::Ok || info.subtype != 3 ||
        info.version != 0x10 ||
        info.phyTx != candidate.input.phyTxTimestampUs ||
        info.targetTx != candidate.input.targetTxTimestampUs)
        return MifCandidateStatus::ParserRejected;

    candidate.length = written;
    const uint32_t blockers = basicFollowupBlockers(candidate, *witness,
                                                     candidate.sampleUs);
    if (blockers != kMifTxNoBlocker)
        return MifCandidateStatus::InvalidRocWitness;

    *output = candidate;
    return MifCandidateStatus::Encoded;
}

uint32_t mifFollowupTxBlockers(const MifCandidate *candidate,
                               const MifFollowupWitness *witness,
                               uint64_t submitMonotonicUs)
{
    if (!candidate || !witness)
        return kMifTxInvalidCandidate;
    MifFollowupWitness current = *witness;
    current.roc.sampleUs = submitMonotonicUs;
    uint32_t blockers = basicFollowupBlockers(*candidate, current,
                                              submitMonotonicUs);
    HostPhaseFields phase{};
    PsfCandidate base{};
    base.input = candidate->input;
    base.length = 1; // Only its timing/channel fields are used by the helper.
    base.contextGeneration = candidate->contextGeneration;
    base.sampleUs = candidate->phaseOriginUs;
    base.startObservedUs = candidate->startObservedUs;
    base.hardDeadlineUs = candidate->hardDeadlineUs;
    if (calculateCandidatePhase(base, candidate->sampleUs, &phase) !=
        HostPhaseStatus::Ok || !candidateMatchesPhase(*candidate, phase))
        blockers |= kMifTxPhaseRejected;

    // The serialized timestamp/schedule fields describe the candidate's own
    // sample. The gate has a separate current sample for freshness, lease,
    // ROC and currently advertised channel-slot checks; it need not equal the
    // earlier serialization sample.
    if (calculateCandidatePhase(base, submitMonotonicUs, &phase) !=
        HostPhaseStatus::Ok)
        blockers |= kMifTxPhaseRejected;
    return blockers;
}

} // namespace NativeAwdlProbe
