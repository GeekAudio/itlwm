// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_TX_GATE_HPP
#define NATIVE_AWDL_MIF_TX_GATE_HPP

#include "awdl_host_phase.hpp"
#include "awdl_mif_encode.hpp"
#include "awdl_psf_tx_gate.hpp"

namespace NativeAwdlProbe {

struct MifFollowupWitness {
    PsfRuntimeWitness roc;
    uint16_t nextSequenceNumber;
    uint16_t firstPsfTicketStatus;
    uint16_t firstPsfTicketSequenceControl;
    uint16_t firstPsfTicketByteCount;
    uint16_t firstPsfTicketFrameControl;
    bool firstPsfTicketCompleted;
    bool firstPsfTicketSucceeded;
    bool queueLeaseActive;
    bool txRingEmpty;
    bool ringIndicesConsistent;
};

struct MifCandidate {
    NativeAwdl::PsfInput input;
    char hostname[NativeAwdl::kMaximumArpaHostLabelLength];
    size_t hostnameLength;
    uint8_t bytes[NativeAwdl::kMaximumEncodedMifLength];
    size_t length;
    uint32_t contextGeneration;
    uint64_t phaseOriginUs;
    uint64_t startObservedUs;
    uint64_t sampleUs;
    uint64_t hardDeadlineUs;
    uint32_t firstPsfTicketStatus;
    uint16_t firstPsfTicketSequenceControl;
    uint16_t firstPsfTicketByteCount;
    uint16_t firstPsfTicketFrameControl;
    HostPhaseFields phase;
};

enum class MifCandidateStatus : uint8_t {
    Encoded,
    InvalidArgument,
    FirstPsfInvalid,
    FirstPsfNotCompleted,
    FirstPsfFailed,
    QueueNotIdle,
    InvalidRocWitness,
    PhaseRejected,
    EncoderRejected,
    ParserRejected
};

enum MifTxBlocker : uint32_t {
    kMifTxNoBlocker = 0,
    kMifTxInvalidCandidate = 1u << 0,
    kMifTxFirstPsfNotCompleted = 1u << 1,
    kMifTxFirstPsfFailed = 1u << 2,
    kMifTxQueueNotIdle = 1u << 3,
    kMifTxRocNotActive = 1u << 4,
    kMifTxGenerationMismatch = 1u << 5,
    kMifTxRocEnded = 1u << 6,
    kMifTxRocUnknown = 1u << 7,
    kMifTxInvalidMonotonicWitness = 1u << 8,
    kMifTxLeaseExpired = 1u << 9,
    kMifTxPreparedFrameStale = 1u << 10,
    kMifTxPhaseRejected = 1u << 11
};

// Prepare exactly one MIF follow-up from a completed successful PSF ticket.
// The phase origin and channel table come from that original PSF candidate.
// All five manual PSF-profile guards plus the explicit MIF-follow-up profile
// are enforced by the HAL caller; this pure function also requires an active
// matching ROC, successful first ticket, and an idle retained queue lease.
// Failure leaves output untouched.
MifCandidateStatus prepareExperimentalMifFollowupCandidate(
    const PsfCandidate *firstPsf, const MifFollowupWitness *witness,
    uint32_t firstPsfTicketStatus, const char *hostname,
    size_t hostnameLength, MifCandidate *output);

uint32_t mifFollowupTxBlockers(const MifCandidate *candidate,
                               const MifFollowupWitness *witness,
                               uint64_t submitMonotonicUs);

} // namespace NativeAwdlProbe

#endif
