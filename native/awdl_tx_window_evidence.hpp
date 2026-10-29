// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_TX_WINDOW_EVIDENCE_HPP
#define NATIVE_AWDL_TX_WINDOW_EVIDENCE_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdlTxWindowEvidence {

constexpr size_t kTicketCapacity = 4;
constexpr size_t kScheduleCapacity = 4;

struct Epoch {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
};

enum class FrameKind : uint8_t {
    Psf = 0,
    Mif = 3
};

// Immutable, address-free identity for one local PSF/MIF ticket. The local
// ticket fields are sufficient to record its host timeline. peerToken and
// scheduleRevision are optional retrospective binding fields: both zero means
// explicitly unbound; otherwise both must be nonzero. peerToken is an opaque
// caller-assigned incarnation token, never a MAC.
struct TicketIdentity {
    uint64_t diagnosticGeneration;
    FrameKind frameKind;
    uint32_t frameOrdinal;
    uint16_t frameSequenceControl;
    uint64_t ticketToken;
    Epoch epoch;
    uint16_t queueId;
    uint16_t ringSize;
    uint16_t descriptorIndex;
    uint64_t peerToken;
    uint64_t scheduleRevision;
    // Parsed once from the exact final MPDU passed to the HAL submit path.
    // Presence is explicit: a present zero timestamp is distinct from an
    // unavailable observation. These are wire values, not host airtime proof.
    uint8_t wireInfoPresent;
    uint8_t wireSubtype;
    uint16_t wireMpduLength;
    uint8_t wirePhyTxPresent;
    uint8_t wireTargetTxPresent;
    uint32_t wirePhyTxUs;
    uint32_t wireTargetTxUs;
};

struct PeerScheduleWitness {
    uint64_t diagnosticGeneration;
    Epoch epoch;
    uint64_t peerToken;
    uint64_t scheduleRevision;
    uint8_t channel;
    uint64_t observedAtUs;
    uint64_t validUntilUs;
    bool tlv18FieldsVerified;
    bool sameMonotonicDomainVerified;
};

struct SubmissionWitness {
    TicketIdentity identity;
    // Sample taken immediately before the actual doorbell. It is a lower
    // bound on doorbell time, not an on-air timestamp.
    uint64_t preDoorbellLowerUs;
    bool immediatelyBeforeDoorbellVerified;
    bool sameMonotonicDomainVerified;
};

enum class CompletionSource : uint8_t {
    MatchingNotificationTap,
    LatePoll,
    Flush,
    Other
};

enum class FirmwareOutcome : uint8_t {
    Success,
    Failure,
    Unknown
};

struct CompletionWitness {
    TicketIdentity identity;
    // Tap time is an upper bound on completion observation in the declared
    // monotonic domain. It is not an air timestamp or a peer-receipt proof.
    uint64_t notificationTapUpperUs;
    CompletionSource source;
    FirmwareOutcome firmwareOutcome;
    bool matchingTicketVerified;
    bool matchingIdentityVerified;
    bool upperBoundVerified;
    bool sameMonotonicDomainVerified;
};

// This must be an independently verified, already-guarded shared window.
// It is intentionally distinct from a TX Candidate returned by another
// planner. The evidence module never grants future submission permission.
struct GuardedSharedWindowWitness {
    uint64_t diagnosticGeneration;
    Epoch epoch;
    uint64_t peerToken;
    uint64_t scheduleRevision;
    uint8_t channel;
    uint64_t startUs;
    uint64_t endUs; // Half-open [startUs, endUs).
    uint64_t evidenceValidFromUs;
    uint64_t evidenceValidUntilUs;
    bool sameMonotonicDomainVerified;
    bool clockMappingVerified;
    bool peerEventVerified;
    bool scheduleVerified;
    bool guardPolicyVerified;
    bool alreadyGuardedSharedWindowVerified;
};

enum class Status : uint8_t {
    Ready,
    InvalidDiagnosticGeneration,
    InvalidEpoch,
    StaleDiagnosticGeneration,
    EpochMismatch,
    InvalidIdentity,
    LocalTicketRecordedUnbound,
    MissingScheduleWitness,
    ExpiredScheduleWitness,
    ScheduleCapacityFull,
    ScheduleRevisionReused,
    TicketCapacityFull,
    DuplicateTicketToken,
    TicketNotFound,
    IdentityMismatch,
    StaleScheduleRevision,
    DuplicateSubmission,
    MissingSubmissionWitness,
    DuplicateCompletion,
    MissingCompletionWitness,
    WrongCompletionSource,
    LatePollIsNotTap,
    FirmwareFailure,
    FirmwareOutcomeUnknown,
    FlushRejected,
    CompletionBeforeSubmission,
    OutOfOrderEvidence,
    ScheduleExpiredAtEvent,
    TicketInvalidated
};

enum class RetrospectiveResult : uint8_t {
    RetrospectiveCovered,
    RetrospectiveNotContained,
    RetrospectiveUnknown
};

// Copy-only local evidence view. It contains no internal pointer and cannot
// update a ledger entry or retrospectively bind an unbound ticket.
struct TicketSnapshot {
    TicketIdentity identity;
    uint64_t createdAtUs;
    uint64_t scheduleObservedAtUs;
    uint64_t scheduleValidUntilUs;
    uint64_t preDoorbellLowerUs;
    uint64_t notificationTapUpperUs;
    bool used;
    bool scheduleStale;
    bool invalidated;
    bool peerBindingVerified;
    bool submitted;
    bool completed;
};

// Bounded, single-consumer offline evidence ledger. It has no dynamic memory,
// no addresses or pointers, and does not interact with TX hardware.
class Ledger {
public:
    Ledger();

    // The only operation that clears records is an explicit new diagnostic
    // generation. Generations must increase strictly.
    Status beginDiagnosticGeneration(uint64_t diagnosticGeneration,
                                     const Epoch &epoch);
    Status observePeerSchedule(const PeerScheduleWitness &witness,
                               uint64_t nowUs);
    // nowUs is the local ticket-record creation event time, not import time.
    // A submission witness may not predate this immutable event.
    Status beginTicket(const TicketIdentity &identity, uint64_t nowUs);
    Status recordSubmission(const SubmissionWitness &witness);
    Status recordCompletion(const CompletionWitness &witness);
    // Record a post-doorbell state failure that leaves ticket outcome unknown.
    // This permanently prevents retrospective coverage for that ticket.
    Status markPostDoorbellStateUnknown(const TicketIdentity &identity);

    // Returns a value copy of one used slot. Failure leaves output untouched.
    // The caller must serialize this with every other ledger operation.
    bool snapshotTicket(size_t index, TicketSnapshot *output) const;

    // Pure retrospective containment only. Returns no ticket permission,
    // candidate time, or verified worst-case delay.
    RetrospectiveResult assessRetrospectively(
        const TicketIdentity &identity,
        const GuardedSharedWindowWitness &window) const;

private:
    struct ScheduleEntry {
        uint64_t peerToken;
        uint64_t scheduleRevision;
        uint8_t channel;
        uint64_t observedAtUs;
        uint64_t validUntilUs;
        bool used;
        bool valid;
    };

    struct TicketEntry {
        TicketIdentity identity;
        uint64_t createdAtUs;
        uint64_t scheduleObservedAtUs;
        uint64_t scheduleValidUntilUs;
        uint64_t preDoorbellLowerUs;
        uint64_t notificationTapUpperUs;
        bool used;
        bool scheduleStale;
        bool invalidated;
        bool peerBindingVerified;
        bool submitted;
        bool completed;
    };

    Status validateIdentity(const TicketIdentity &identity) const;
    Status findTicket(const TicketIdentity &identity, TicketEntry **output);
    const TicketEntry *findTicket(const TicketIdentity &identity) const;
    ScheduleEntry *findSchedule(uint64_t peerToken);
    const ScheduleEntry *findSchedule(uint64_t peerToken) const;
    static bool validEpoch(const Epoch &epoch);
    static bool sameEpoch(const Epoch &left, const Epoch &right);
    static bool sameIdentity(const TicketIdentity &left,
                             const TicketIdentity &right);
    static bool validFrameKind(FrameKind kind);
    static bool containsTime(const ScheduleEntry &schedule,
                             uint64_t eventTimeUs);
    void invalidatePeerTickets(uint64_t peerToken,
                               uint64_t newScheduleRevision);

    uint64_t diagnosticGeneration_;
    Epoch epoch_;
    ScheduleEntry schedules_[kScheduleCapacity];
    TicketEntry tickets_[kTicketCapacity];
    bool initialized_;
};

} // namespace NativeAwdlTxWindowEvidence

#endif // NATIVE_AWDL_TX_WINDOW_EVIDENCE_HPP
