// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_SHARED_WINDOW_HPP
#define NATIVE_AWDL_SHARED_WINDOW_HPP

#include <stdint.h>

namespace NativeAwdlSharedWindow {

constexpr uint64_t kTuUs = 1024;
constexpr uint64_t kThreeTuUs = 3 * kTuUs;

struct Epoch {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
};

struct TimeBounds {
    // Inclusive lower and upper bounds in the same verified monotonic
    // microsecond domain as Request::nowUs and all witness timestamps. These
    // are bounds, not samples or a clock conversion request.
    uint64_t earliestUs;
    uint64_t latestUs;
};

struct PeerWitness {
    Epoch epoch;
    // Opaque caller-assigned token for this peer incarnation; never a MAC.
    uint64_t peerToken;
    // Nonzero caller-assigned revision of the accepted peer schedule snapshot.
    uint64_t scheduleRevision;
    bool mifPeerValid;
    bool identityWitnessVerified;
    bool identityMatchesCurrentPeer;
    bool scheduleWitnessVerified;
    uint8_t channel;
    uint64_t mifObservedAtUs;
    uint64_t mifValidUntilUs;
    uint64_t scheduleObservedAtUs;
    uint64_t scheduleValidUntilUs;
};

struct MappedPeerWindow {
    Epoch epoch;
    // Must match PeerWitness::peerToken for the same peer incarnation.
    uint64_t peerToken;
    // Must identify the exact schedule revision used to construct this map.
    uint64_t scheduleRevision;
    uint8_t channel;
    bool mappingVerified;
    TimeBounds mappedStartUs;
    TimeBounds mappedEndUs;
    // Additional verified maximum mapping error. The planner expands the
    // start bound and contracts the end bound by this amount.
    uint64_t verifiedErrorBoundUs;
    uint64_t mappingObservedAtUs;
    uint64_t mappingValidUntilUs;
};

struct LocalLease {
    Epoch epoch;
    uint8_t channel;
    bool known;
    bool active;
    // Bounds describe a lease guaranteed active on
    // [start.latestUs, end.earliestUs).
    TimeBounds startUs;
    TimeBounds endUs;
};

struct GuardPolicy {
    // The caller must verify the traffic class and applicable schedule policy
    // (including any fixed-single-channel exception) before setting these.
    bool trafficSchedulePolicyVerified;
    bool requiredGuardVerified;
    uint64_t beforeUs;
    uint64_t afterUs;
};

struct TxBudget {
    bool verified;
    uint64_t commitToAirWorstCaseUs;
    uint64_t packetAirtimeUs;
};

struct Request {
    Epoch currentEpoch;
    uint64_t nowUs;
    PeerWitness peer;
    MappedPeerWindow peerWindow;
    LocalLease localLease;
    GuardPolicy guard;
    TxBudget txBudget;
};

struct Candidate {
    // Inclusive integer-microsecond submission bounds for this calculation
    // snapshot only. Before future use, reacquire now and recheck these bounds
    // plus the full epoch, lease, peer, schedule, and mapping gates.
    uint64_t earliestCommitUs;
    uint64_t latestCommitUs;
};

enum class Status : uint8_t {
    CandidateReady,
    NullArgument,
    InvalidEpoch,
    EpochMismatch,
    InvalidPeerToken,
    PeerMismatch,
    InvalidScheduleRevision,
    ScheduleRevisionMismatch,
    MissingMifPeerWitness,
    MissingIdentityWitness,
    IdentityMismatch,
    MissingScheduleWitness,
    ExpiredPeerWitness,
    UnverifiedClockMapping,
    ExpiredClockMapping,
    InvalidChannel,
    ChannelMismatch,
    UnknownLocalLease,
    InactiveLocalLease,
    InvalidInterval,
    UncertaintyCoversWindow,
    MissingGuardPolicy,
    GuardBelowMinimum,
    MissingTxBudget,
    ArithmeticOverflow,
    EmptyIntersection,
    NoCommitWindow
};

// Computes only the conservative intersection of already-verified time
// bounds. It does not read hardware clocks, authorize a doorbell, or change a
// driver TX gate. On failure, output is left untouched.
Status plan(const Request *request, Candidate *output);

} // namespace NativeAwdlSharedWindow

#endif // NATIVE_AWDL_SHARED_WINDOW_HPP
