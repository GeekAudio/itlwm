// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_PSF_TX_GATE_HPP
#define NATIVE_AWDL_PSF_TX_GATE_HPP

#include "awdl_bounded_psf_plan.hpp"

namespace NativeAwdlProbe {

constexpr uint64_t kMaximumPreparedPsfAgeUs = 10000;
constexpr uint64_t kPsfLeaseSafetyMarginUs = 20000;

enum PsfTxBlocker : uint32_t {
    kPsfTxNoBlocker = 0,
    kPsfTxStartNotConfirmed = 1u << 0,
    kPsfTxGenerationMismatch = 1u << 1,
    kPsfTxRocEnded = 1u << 2,
    kPsfTxRocUnknown = 1u << 3,
    kPsfTxInvalidMonotonicWitness = 1u << 4,
    kPsfTxLeaseExpired = 1u << 5,
    kPsfTxPreparedFrameStale = 1u << 6,
    kPsfTxSequenceOutlivesLease = 1u << 7,
    kPsfTxCyclicExpiryUnbounded = 1u << 8,
    kPsfTxClockMappingUnavailable = 1u << 9,
    kPsfTxAdvertisedResidenceOutlivesLease = 1u << 10,
    kPsfTxObservationScheduleInvalid = 1u << 11,
    kPsfTxTxResourcesUnavailable = 1u << 12,
    kPsfTxFrameAllocationFailed = 1u << 13
};

struct PsfRuntimeWitness {
    uint32_t expectedGeneration;
    uint32_t sessionGeneration;
    uint64_t startObservedUs;
    uint64_t hardDeadlineUs;
    uint64_t sampleUs;
    bool matchingSuccessfulStart;
    bool activeAtSample;
    bool endSeen;
    bool outcomeUnknown;
    bool clockMappingConfirmed;
    bool cyclicExpiryRepresentable;
};

struct PsfCandidate {
    NativeAwdl::PsfInput input;
    uint8_t bytes[NativeAwdl::kMaximumEncodedPsfLength];
    size_t length;
    uint32_t contextGeneration;
    uint64_t startObservedUs;
    uint64_t sampleUs;
    uint64_t hardDeadlineUs;
    uint32_t blockers;
};

enum class PsfCandidateStatus : uint8_t {
    Encoded,
    InvalidArgument,
    InvalidRocWitness,
    PlannerRejected,
    EncoderRejected,
    ParserRejected
};

// Build a local, observation-only PSF candidate from actual runtime identity,
// HT capability and a monotonic ROC witness. Encoding does not authorize TX.
// The output remains untouched unless the complete MPDU passes the parser.
PsfCandidateStatus prepareExperimentalPsfCandidate(
    const Request *request, const PsfRuntimeWitness *witness,
    PsfCandidate *output);

// Re-evaluate the candidate immediately before the TX doorbell. This checks
// its matching epoch, confirmed live ROC, strict age/deadline and the three
// conditions that the current 900 ms experiment cannot prove: complete
// repeating schedule coverage, bounded expiry and an AWDL clock mapping.
uint32_t p2pPsfTxBlockers(const PsfCandidate *candidate,
                          const PsfRuntimeWitness *witness,
                          uint64_t submitMonotonicUs);

// Manual, one-frame observation experiment only. This deliberately clears
// the three production-readiness blockers (clock mapping, cyclic expiry, full
// sequence coverage) but requires the actual continuous channel-6 slots in
// this encoded frame to fit inside the matching bounded ROC lease. Callers
// must publish that the frame is experimental and not a promise of AWDL
// presence or a working data path.
uint32_t p2pPsfObservationTxBlockers(const PsfCandidate *candidate,
                                     const PsfRuntimeWitness *witness,
                                     uint64_t submitMonotonicUs);

} // namespace NativeAwdlProbe

#endif
