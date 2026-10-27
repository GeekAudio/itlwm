// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_psf_tx_gate.hpp"

#include "awdl_action_frame.hpp"

#include <string.h>

namespace NativeAwdlProbe {
namespace {

constexpr uint64_t kAwdlSequenceDurationUs = 1024ULL * 1024ULL;
constexpr uint64_t kAwdlSlotDurationUs = 65536ULL;

uint32_t basicWitnessBlockers(const PsfRuntimeWitness &witness)
{
    uint32_t blockers = kPsfTxNoBlocker;
    if (!witness.matchingSuccessfulStart || !witness.activeAtSample)
        blockers |= kPsfTxStartNotConfirmed;
    if (!witness.expectedGeneration ||
        witness.expectedGeneration != witness.sessionGeneration)
        blockers |= kPsfTxGenerationMismatch;
    if (witness.endSeen)
        blockers |= kPsfTxRocEnded;
    if (witness.outcomeUnknown)
        blockers |= kPsfTxRocUnknown;
    if (!witness.startObservedUs ||
        witness.sampleUs < witness.startObservedUs ||
        witness.hardDeadlineUs <= witness.startObservedUs)
        blockers |= kPsfTxInvalidMonotonicWitness;
    if (witness.sampleUs >= witness.hardDeadlineUs)
        blockers |= kPsfTxLeaseExpired;
    return blockers;
}

} // namespace

PsfCandidateStatus prepareExperimentalPsfCandidate(
    const Request *request, const PsfRuntimeWitness *witness,
    PsfCandidate *output)
{
    if (!request || !witness || !output)
        return PsfCandidateStatus::InvalidArgument;

    const uint32_t blockers = basicWitnessBlockers(*witness);
    if (blockers != kPsfTxNoBlocker)
        return PsfCandidateStatus::InvalidRocWitness;
    if (request->monotonicSampleUs != witness->sampleUs)
        return PsfCandidateStatus::InvalidRocWitness;

    RocWitness roc{};
    roc.channel = 6;
    roc.startUs = witness->startObservedUs;
    roc.deadlineUs = witness->hardDeadlineUs;
    roc.startConfirmed = witness->matchingSuccessfulStart;
    roc.activeAtSampleConfirmed = witness->activeAtSample;

    PsfCandidate candidate{};
    Summary summary{};
    if (buildObservationOnlyPsfInput(request, &roc, &candidate.input,
                                     &summary) != PlanStatus::ObservationOnly)
        return PsfCandidateStatus::PlannerRejected;

    size_t written = 0;
    if (NativeAwdl::encodePsf(&candidate.input, candidate.bytes,
                              sizeof(candidate.bytes), &written) !=
            NativeAwdl::EncodeStatus::Ok ||
        written == 0 || written > sizeof(candidate.bytes))
        return PsfCandidateStatus::EncoderRejected;

    NativeAwdl::ActionFrameInfo parsed{};
    if (NativeAwdl::parseActionFrame(candidate.bytes, written, &parsed) !=
            NativeAwdl::ParseStatus::Ok || parsed.subtype != 0 ||
        parsed.version != 0x10 ||
        parsed.phyTx != candidate.input.phyTxTimestampUs ||
        parsed.targetTx != candidate.input.targetTxTimestampUs)
        return PsfCandidateStatus::ParserRejected;

    candidate.length = written;
    candidate.contextGeneration = witness->expectedGeneration;
    candidate.startObservedUs = witness->startObservedUs;
    candidate.sampleUs = witness->sampleUs;
    candidate.hardDeadlineUs = witness->hardDeadlineUs;
    candidate.blockers = p2pPsfTxBlockers(&candidate, witness,
                                           witness->sampleUs);
    *output = candidate;
    return PsfCandidateStatus::Encoded;
}

uint32_t p2pPsfTxBlockers(const PsfCandidate *candidate,
                          const PsfRuntimeWitness *witness,
                          uint64_t submitMonotonicUs)
{
    if (!candidate || !witness || candidate->length == 0 ||
        candidate->length > sizeof(candidate->bytes))
        return kPsfTxInvalidMonotonicWitness;

    PsfRuntimeWitness current = *witness;
    current.sampleUs = submitMonotonicUs;
    uint32_t blockers = basicWitnessBlockers(current);
    if (current.expectedGeneration != candidate->contextGeneration ||
        current.sessionGeneration != candidate->contextGeneration)
        blockers |= kPsfTxGenerationMismatch;
    if (current.startObservedUs != candidate->startObservedUs)
        blockers |= kPsfTxInvalidMonotonicWitness;
    if (submitMonotonicUs < candidate->sampleUs ||
        submitMonotonicUs - candidate->sampleUs > kMaximumPreparedPsfAgeUs)
        blockers |= kPsfTxPreparedFrameStale;
    if (candidate->hardDeadlineUs != witness->hardDeadlineUs ||
        submitMonotonicUs >= candidate->hardDeadlineUs)
        blockers |= kPsfTxLeaseExpired;
    if (candidate->hardDeadlineUs <= candidate->sampleUs ||
        candidate->hardDeadlineUs - candidate->sampleUs <
            kAwdlSequenceDurationUs)
        blockers |= kPsfTxSequenceOutlivesLease;
    if (!witness->cyclicExpiryRepresentable)
        blockers |= kPsfTxCyclicExpiryUnbounded;
    if (!witness->clockMappingConfirmed)
        blockers |= kPsfTxClockMappingUnavailable;
    return blockers;
}

uint32_t p2pPsfObservationTxBlockers(const PsfCandidate *candidate,
                                     const PsfRuntimeWitness *witness,
                                     uint64_t submitMonotonicUs)
{
    constexpr uint32_t kProductionOnlyBlockers =
        kPsfTxSequenceOutlivesLease | kPsfTxCyclicExpiryUnbounded |
        kPsfTxClockMappingUnavailable;
    uint32_t blockers = p2pPsfTxBlockers(candidate, witness,
                                         submitMonotonicUs) &
                        ~kProductionOnlyBlockers;
    if (!candidate || !witness || candidate->length == 0 ||
        candidate->length > sizeof(candidate->bytes))
        return blockers | kPsfTxObservationScheduleInvalid;

    // The bounded experiment may announce only the contiguous channel-6
    // dwell encoded at the start of the 16-slot sequence. Check that it fits
    // between the host-side TX gate and conservative ROC deadline. This does
    // not prove on-air TX latency, clock alignment, or peer schedule expiry;
    // callers keep those diagnostics explicitly false.
    size_t advertisedSlots = 0;
    bool sawUnusedSlot = false;
    for (size_t i = 0; i < 16; ++i) {
        const uint8_t channel = candidate->input.channelSlots[i];
        if (channel == 0) {
            sawUnusedSlot = true;
            continue;
        }
        if (channel != 6 || sawUnusedSlot) {
            blockers |= kPsfTxObservationScheduleInvalid;
            break;
        }
        ++advertisedSlots;
    }
    if (advertisedSlots == 0 ||
        advertisedSlots > UINT64_MAX / kAwdlSlotDurationUs) {
        blockers |= kPsfTxObservationScheduleInvalid;
    } else {
        const uint64_t advertisedUs = advertisedSlots * kAwdlSlotDurationUs;
        if (submitMonotonicUs >= witness->hardDeadlineUs ||
            witness->hardDeadlineUs - submitMonotonicUs < advertisedUs)
            blockers |= kPsfTxAdvertisedResidenceOutlivesLease;
    }
    return blockers;
}

} // namespace NativeAwdlProbe
