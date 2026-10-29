// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_RX_EVENT_TIMELINE_HPP
#define NATIVE_AWDL_RX_EVENT_TIMELINE_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Bounded, address-free export records for one manually owned AWDL ROC.
// Source addresses are retained only in this private fixed table so records
// from the same source can share an ephemeral ordinal. They never appear in a
// Snapshot or Event. This helper neither grants radio permission nor changes
// queue admission.
namespace NativeAwdlRxTrace {

constexpr uint32_t kSchemaVersion = 1;
constexpr size_t kEventCapacity = 32;
constexpr size_t kSourceCapacity = 16;
constexpr size_t kPendingIdentityCapacity = 16;
constexpr uint32_t kNoSourceOrdinal = 0;

enum class EventKind : uint32_t {
    ActionRxTap = 1,
    TimeEventNotification = 2,
    TxPrepared = 3
};

enum class NotificationApi : uint32_t {
    Unknown = 0,
    SessionProtection16 = 1,
    TimeEvent24 = 2
};

enum class Boundary : uint32_t {
    RocStart = 1,
    RocEnd = 2
};

enum class SessionAnomalyReason : uint32_t {
    None = 0,
    ReducerIgnored = 1,
    Duplicate = 2,
    Conflicting = 3,
    LateAfterEnd = 4,
    Malformed = 5,
    ForeignContext = 6,
    UnclassifiedNoncanonical = 7,
    EndBeforeStart = 8
};

struct Epochs {
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
};

inline bool sameEpochs(const Epochs &left, const Epochs &right)
{
    return left.contextGeneration == right.contextGeneration &&
        left.powerGeneration == right.powerGeneration &&
        left.stationGeneration == right.stationGeneration &&
        left.rocGeneration == right.rocGeneration;
}

inline bool nonzeroEpochs(const Epochs &epochs)
{
    return epochs.contextGeneration != 0 && epochs.powerGeneration != 0 &&
        epochs.stationGeneration != 0 && epochs.rocGeneration != 0;
}

// The token travels through the existing fixed RX queue. A zero eventSerial
// means tracing could not reserve a row; queueSerial still identifies exactly
// one accepted queue record for its later drain.
struct EventToken {
    uint64_t eventSerial;
    uint64_t queueSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint32_t sourceOrdinal;
    uint32_t sourceKnown;
    uint32_t rowPresent;
};

struct ActionTap {
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t rawLength;
    const uint8_t *sourceAddress; // Transient input only; never copied to Event.
    uint32_t sourceAddressLength;
    uint32_t frameControlPresent;
    uint32_t frameControl;
    uint32_t frameType;
    uint32_t frameSubtype;
    uint32_t sequenceControlPresent;
    uint32_t sequenceControl;
    uint32_t awdlSubtypePresent;
    uint32_t awdlSubtype;
    uint32_t wirePhyPresent;
    uint32_t wirePhyTxUs;
    uint32_t wireTargetPresent;
    uint32_t wireTargetTxUs;
    uint32_t channelIndex;
    uint32_t rxGp2Present;
    uint32_t rxGp2Us;
    uint32_t rxMacPhyIndexPresent;
    uint32_t rxMacPhyIndex;
};

struct ParseResult {
    uint32_t attempted;
    uint32_t resultPresent;
    uint32_t status;
    uint32_t rejectReason;
    uint32_t rejectSubtype;
    uint32_t tlvType;
    uint32_t expectedTlvType;
    uint32_t tlvOffset;
    uint32_t declaredLength;
    uint32_t availableLength;
};

struct DecodeResult {
    uint32_t attempted;
    uint32_t resultPresent;
    uint32_t status;
    uint32_t rejectStage;
    uint32_t offendingTlvType;
    uint32_t relatedTlvType;
};

struct RouteResult {
    uint32_t attempted;
    uint32_t resultPresent;
    uint32_t status;
    uint32_t queueAccepted;
};

struct TableResult {
    uint32_t attempted;
    uint32_t resultPresent;
    uint32_t status;
};

struct ObserverResult {
    uint32_t attempted;
    uint32_t resultPresent;
    uint32_t status;
};

struct TimeEvent24 {
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t rawLength;
    uint32_t timestamp;
    uint32_t sessionId;
    uint32_t uniqueId;
    uint32_t macIdAndColor;
    uint32_t rawAction;
    uint32_t rawStatus;
    uint32_t leaseUidKnown;
    uint32_t leaseExpectedUid;
    uint32_t matchStatusPresent;
    uint32_t matchStatus;
};

// A SESSION_PROTECTION notification is 16 bytes and does not contain a UID.
// expectedUid is copied from the captured lease as separate context; it is
// never labeled or interpreted as a raw notification UID.
struct SessionProtection16 {
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t rawLength;
    uint32_t ownerSessionToken;
    uint32_t expectedUidKnown;
    uint32_t expectedUid;
    uint32_t macIdAndColor;
    uint32_t rawStatus;
    uint32_t rawStartFlag;
    uint32_t configuration;
    uint32_t reducerResultPresent;
    uint32_t reducerReturnedTrue;
    uint32_t reducerResult;
    uint32_t canonicalTransitionPresent;
    uint32_t canonicalTransition;
    SessionAnomalyReason anomalyReason;
};

struct TxPrepared {
    uint64_t ticketSerial;
    uint64_t diagnosticGeneration;
    Epochs epochs;
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t sequenceControl;
    uint32_t wireInfoPresent;
    uint32_t wirePhyTxUs;
    uint32_t wireTargetTxUs;
    uint32_t queueId;
    uint32_t descriptorIndex;
};

struct Event {
    uint64_t serial;
    uint64_t queueSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    EventKind kind;
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t rawLength;
    uint32_t sourceOrdinal;
    uint32_t sourceKnown;

    uint32_t frameControlPresent;
    uint32_t frameControl;
    uint32_t frameType;
    uint32_t frameSubtype;
    uint32_t sequenceControlPresent;
    uint32_t sequenceControl;
    uint32_t awdlSubtypePresent;
    uint32_t awdlSubtype;
    uint32_t wirePhyPresent;
    uint32_t wirePhyTxUs;
    uint32_t wireTargetPresent;
    uint32_t wireTargetTxUs;
    uint32_t channelIndex;
    uint32_t rxGp2Present;
    uint32_t rxGp2Us;
    uint32_t rxMacPhyIndexPresent;
    uint32_t rxMacPhyIndex;

    uint32_t parseAttempted;
    uint32_t parseResultPresent;
    uint32_t parseStatus;
    uint32_t parseRejectReason;
    uint32_t parseRejectSubtype;
    uint32_t parseTlvType;
    uint32_t parseExpectedTlvType;
    uint32_t parseTlvOffset;
    uint32_t parseDeclaredLength;
    uint32_t parseAvailableLength;
    uint32_t decodeAttempted;
    uint32_t decodeResultPresent;
    uint32_t decodeStatus;
    uint32_t decodeRejectStage;
    uint32_t decodeOffendingTlvType;
    uint32_t decodeRelatedTlvType;
    uint32_t routeAttempted;
    uint32_t routeResultPresent;
    uint32_t routeStatus;
    uint32_t queueAccepted;
    uint32_t tableObserveAttempted;
    uint32_t tableResultPresent;
    uint32_t tableStatus;
    uint32_t peerObserverAttempted;
    uint32_t peerObserverResultPresent;
    uint32_t peerObserverStatus;
    uint32_t completionUpdated;
    uint32_t pendingDrain;

    NotificationApi notificationApi;
    uint32_t notificationMatchStatusPresent;
    uint32_t notificationMatchStatus;
    uint32_t timeEventTimestamp;
    uint32_t timeEventSessionId;
    uint32_t timeEventUniqueId;
    uint32_t timeEventMacIdAndColor;
    uint32_t timeEventRawAction;
    uint32_t timeEventRawStatus;
    uint32_t timeEventExpectedUidKnown;
    uint32_t timeEventExpectedUid;

    uint64_t txTicketSerial;
    uint64_t txDiagnosticGeneration;
    uint32_t txSequenceControl;
    uint32_t txWireInfoPresent;
    uint32_t txWirePhyTxUs;
    uint32_t txWireTargetTxUs;
    uint32_t txQueueId;
    uint32_t txDescriptorIndex;
};

struct BoundarySlot {
    uint32_t present;
    NotificationApi api;
    uint64_t notificationSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t rawLength;
    uint32_t ownerSessionToken;
    uint32_t expectedUidKnown;
    uint32_t expectedUid;
    uint32_t macIdAndColor;
    uint32_t rawStatus;
    uint32_t rawStartFlag;
    uint32_t configuration;
    uint32_t reducerResultPresent;
    uint32_t reducerReturnedTrue;
    uint32_t reducerResult;
    uint32_t canonicalTransitionPresent;
    uint32_t canonicalTransition;
};

struct IgnoredNotification {
    uint32_t present;
    NotificationApi api;
    SessionAnomalyReason reason;
    uint64_t notificationSerial;
    uint64_t ownerSerial;
    Epochs epochs;
    uint64_t hostMonotonicUs;
    uint32_t hostMonotonicPresent;
    uint32_t rawLength;
    uint32_t ownerSessionToken;
    uint32_t expectedUidKnown;
    uint32_t expectedUid;
    uint32_t macIdAndColor;
    uint32_t rawStatus;
    uint32_t rawStartFlag;
    uint32_t configuration;
    uint32_t reducerResultPresent;
    uint32_t reducerReturnedTrue;
    uint32_t reducerResult;
};

struct Snapshot {
    uint32_t schemaVersion;
    uint32_t ownerPresent;
    uint64_t ownerSerial;
    Epochs epochs;
    uint32_t active;
    uint32_t producerClosed;
    uint32_t pendingDrainCount;
    uint32_t untrackedPendingDrainCount;
    uint32_t untrackedPendingIdentityOverflowCount;
    uint32_t eventCount;
    uint32_t droppedEventCount;
    uint32_t staleCompletionCount;
    uint32_t sourceTableFullCount;
    uint32_t filteredActionCount;
    uint32_t rejectedOwnerCount;
    uint32_t staleNotificationCount;
    uint32_t sessionAnomalyCount;
    uint32_t sessionReducerReturnedTrueCount;
    uint32_t sessionCanonicalTransitionCount;
    uint32_t sessionNotificationAcceptedCount;
    uint32_t sessionNotificationIgnoredCount;
    uint32_t sessionNotificationDuplicateCount;
    uint32_t sessionNotificationConflictingCount;
    uint32_t sessionNotificationLateCount;
    uint32_t sessionNotificationMalformedCount;
    uint32_t sessionNotificationForeignCount;
    uint32_t sessionBoundaryOrderInvalid;
    uint32_t timeEventNotificationCount;
    uint32_t timeEventNotificationDroppedCount;
    uint32_t producerCloseReason;
    BoundarySlot rocStart;
    BoundarySlot rocEnd;
    IgnoredNotification firstSessionAnomaly;
    IgnoredNotification lastSessionAnomaly;
    uint64_t revision;
};

class Timeline {
public:
    Timeline() = default;
    Timeline(const Timeline &) = delete;
    Timeline &operator=(const Timeline &) = delete;

    // A clean, never-armed object intentionally snapshots to owner=0,
    // epoch=0, inactive, no events. An owner can begin only after the prior
    // producer closed and every tracked/untracked queue record drained.
    bool beginOwner(uint64_t ownerSerial, const Epochs &epochs)
    {
        if (!ownerSerial || !nonzeroEpochs(epochs) || active_ ||
            untrackedPendingIdentityOverflowCount_ != 0 ||
            (ownerPresent_ && (!producerClosed_ || pendingDrainCount_ != 0))) {
            rejectedOwnerCount_ = saturatedIncrement(rejectedOwnerCount_);
            bumpRevision();
            return false;
        }
        if (ownerPresent_ && ownerSerial <= ownerSerial_) {
            rejectedOwnerCount_ = saturatedIncrement(rejectedOwnerCount_);
            bumpRevision();
            return false;
        }

        ownerPresent_ = true;
        ownerSerial_ = ownerSerial;
        epochs_ = epochs;
        active_ = true;
        producerClosed_ = false;
        producerCloseReason_ = 0;
        pendingDrainCount_ = 0;
        untrackedPendingDrainCount_ = 0;
        untrackedPendingIdentityOverflowCount_ = 0;
        eventCount_ = 0;
        droppedEventCount_ = 0;
        staleCompletionCount_ = 0;
        sourceTableFullCount_ = 0;
        filteredActionCount_ = 0;
        staleNotificationCount_ = 0;
        sessionAnomalyCount_ = 0;
        sessionReducerReturnedTrueCount_ = 0;
        sessionCanonicalTransitionCount_ = 0;
        sessionNotificationAcceptedCount_ = 0;
        sessionNotificationIgnoredCount_ = 0;
        sessionNotificationDuplicateCount_ = 0;
        sessionNotificationConflictingCount_ = 0;
        sessionNotificationLateCount_ = 0;
        sessionNotificationMalformedCount_ = 0;
        sessionNotificationForeignCount_ = 0;
        sessionBoundaryOrderInvalid_ = false;
        timeEventNotificationCount_ = 0;
        timeEventNotificationDroppedCount_ = 0;
        rocStart_ = {};
        rocEnd_ = {};
        firstSessionAnomaly_ = {};
        lastSessionAnomaly_ = {};
        for (size_t i = 0; i < kSourceCapacity; ++i)
            sources_[i] = SourceEntry{};
        for (size_t i = 0; i < kEventCapacity; ++i)
            events_[i] = Event{};
        for (size_t i = 0; i < kPendingIdentityCapacity; ++i)
            pendingIdentities_[i] = PendingIdentity{};
        bumpRevision();
        return true;
    }

    // One compact action-frame row is allocated before parsing. This keeps a
    // raw local RX tap even when the parser rejects it. The descriptor GP2
    // value is opaque; zero is valid whenever rxGp2Present is set.
    EventToken recordActionTap(const ActionTap &tap)
    {
        if (!ownerPresent_ || !tap.frameControlPresent || tap.frameType != 0 ||
            tap.frameSubtype != 13) {
            filteredActionCount_ = saturatedIncrement(filteredActionCount_);
            bumpRevision();
            return invalidToken();
        }
        if (!active_ || producerClosed_) {
            filteredActionCount_ = saturatedIncrement(filteredActionCount_);
            EventToken token = allocateQueueToken(0, 0, false);
            bumpRevision();
            return token;
        }
        if (eventCount_ >= kEventCapacity || nextEventSerial_ == UINT64_MAX) {
            droppedEventCount_ = saturatedIncrement(droppedEventCount_);
            EventToken token = allocateQueueToken(0, 0, false);
            bumpRevision();
            return token;
        }

        const uint32_t sourceOrdinal = findOrAddSource(
            tap.sourceAddress, tap.sourceAddressLength);
        const bool sourceKnown = sourceOrdinal != kNoSourceOrdinal;
        Event &event = events_[eventCount_];
        event = {};
        event.serial = ++nextEventSerial_;
        event.ownerSerial = ownerSerial_;
        event.epochs = epochs_;
        event.kind = EventKind::ActionRxTap;
        event.hostMonotonicUs = tap.hostMonotonicUs;
        event.hostMonotonicPresent = tap.hostMonotonicPresent ? 1u : 0u;
        event.rawLength = tap.rawLength;
        event.sourceOrdinal = sourceOrdinal;
        event.sourceKnown = sourceKnown ? 1u : 0u;
        event.frameControlPresent = tap.frameControlPresent ? 1u : 0u;
        event.frameControl = tap.frameControl;
        event.frameType = tap.frameType;
        event.frameSubtype = tap.frameSubtype;
        event.sequenceControlPresent = tap.sequenceControlPresent ? 1u : 0u;
        event.sequenceControl = tap.sequenceControl;
        event.awdlSubtypePresent = tap.awdlSubtypePresent ? 1u : 0u;
        event.awdlSubtype = tap.awdlSubtype;
        event.wirePhyPresent = tap.wirePhyPresent ? 1u : 0u;
        event.wirePhyTxUs = tap.wirePhyTxUs;
        event.wireTargetPresent = tap.wireTargetPresent ? 1u : 0u;
        event.wireTargetTxUs = tap.wireTargetTxUs;
        event.channelIndex = tap.channelIndex;
        event.rxGp2Present = tap.rxGp2Present ? 1u : 0u;
        event.rxGp2Us = tap.rxGp2Us;
        event.rxMacPhyIndexPresent = tap.rxMacPhyIndexPresent ? 1u : 0u;
        event.rxMacPhyIndex = tap.rxMacPhyIndex;
        ++eventCount_;
        EventToken token = allocateQueueToken(event.serial, sourceOrdinal,
                                              sourceKnown);
        event.queueSerial = token.queueSerial;
        bumpRevision();
        token.rowPresent = 1;
        return token;
    }

    bool setParseResult(const EventToken &token, const ParseResult &result)
    {
        if (!token.rowPresent)
            return false;
        Event *event = findActionEvent(token);
        if (!event)
            return noteStaleCompletion();
        event->parseAttempted = result.attempted ? 1u : 0u;
        event->parseResultPresent = result.resultPresent ? 1u : 0u;
        event->parseStatus = result.status;
        event->parseRejectReason = result.rejectReason;
        event->parseRejectSubtype = result.rejectSubtype;
        event->parseTlvType = result.tlvType;
        event->parseExpectedTlvType = result.expectedTlvType;
        event->parseTlvOffset = result.tlvOffset;
        event->parseDeclaredLength = result.declaredLength;
        event->parseAvailableLength = result.availableLength;
        bumpRevision();
        return true;
    }

    bool setDecodeResult(const EventToken &token, const DecodeResult &result)
    {
        if (!token.rowPresent)
            return false;
        Event *event = findActionEvent(token);
        if (!event)
            return noteStaleCompletion();
        event->decodeAttempted = result.attempted ? 1u : 0u;
        event->decodeResultPresent = result.resultPresent ? 1u : 0u;
        event->decodeStatus = result.status;
        event->decodeRejectStage = result.rejectStage;
        event->decodeOffendingTlvType = result.offendingTlvType;
        event->decodeRelatedTlvType = result.relatedTlvType;
        bumpRevision();
        return true;
    }

    bool setRouteResult(const EventToken &token, const RouteResult &result)
    {
        if (!token.rowPresent)
            return false;
        Event *event = findActionEvent(token);
        if (!event)
            return noteStaleCompletion();
        event->routeAttempted = result.attempted ? 1u : 0u;
        event->routeResultPresent = result.resultPresent ? 1u : 0u;
        event->routeStatus = result.status;
        event->queueAccepted = result.queueAccepted ? 1u : 0u;
        bumpRevision();
        return true;
    }

    // Called only with the single parser's actual result. No reparse occurs
    // when this updates the fields already reserved at the raw RX tap.
    bool setParsedAction(const EventToken &token, uint32_t subtypePresent,
                        uint32_t subtype, uint32_t wireInfoPresent,
                        uint32_t wirePhyTxUs, uint32_t wireTargetTxUs)
    {
        if (!token.rowPresent)
            return false;
        Event *event = findActionEvent(token);
        if (!event)
            return noteStaleCompletion();
        event->awdlSubtypePresent = subtypePresent ? 1u : 0u;
        event->awdlSubtype = subtype;
        event->wirePhyPresent = wireInfoPresent ? 1u : 0u;
        event->wirePhyTxUs = wirePhyTxUs;
        event->wireTargetPresent = wireInfoPresent ? 1u : 0u;
        event->wireTargetTxUs = wireTargetTxUs;
        bumpRevision();
        return true;
    }

    // Queue acceptance is independent of trace capacity. If no row could be
    // reserved, count the accepted record as untracked until its consumer
    // drains it; the networking path continues unchanged.
    bool markQueued(const EventToken &token, bool queueAccepted)
    {
        if (!queueAccepted)
            return true;
        if (!token.ownerSerial ||
            token.ownerSerial != ownerSerial_ ||
            !sameEpochs(token.epochs, epochs_))
            return noteStaleCompletion();
        if (!token.rowPresent) {
            if (!token.queueSerial) {
                noteUntrackedIdentityOverflow();
                return true;
            }
            if (token.queueSerial <= lastFinalizedQueueSerial_)
                return noteStaleCompletion();
            if (findPendingIdentity(token))
                return noteStaleCompletion();
            PendingIdentity *pending = findFreePendingIdentity();
            if (!pending) {
                noteUntrackedIdentityOverflow();
                return true;
            }
            pending->queueSerial = token.queueSerial;
            pending->ownerSerial = token.ownerSerial;
            pending->epochs = token.epochs;
            pending->used = 1;
            untrackedPendingDrainCount_ =
                saturatedIncrement(untrackedPendingDrainCount_);
            pendingDrainCount_ = saturatedIncrement(pendingDrainCount_);
            bumpRevision();
            return true;
        }
        Event *event = findActionEvent(token);
        if (!event || event->pendingDrain || event->completionUpdated)
            return noteStaleCompletion();
        event->pendingDrain = 1;
        pendingDrainCount_ = saturatedIncrement(pendingDrainCount_);
        bumpRevision();
        return true;
    }

    // Called by the single consumer after the actual table/observer calls.
    // It may run after END; the original serial+owner+all epochs select the
    // row. No latest timestamp or newly inferred source key is used.
    bool completeRx(const EventToken &token, const TableResult &table,
                    const ObserverResult &observer,
                    const DecodeResult &decode)
    {
        if (!token.rowPresent) {
            if (!token.queueSerial)
                return noteStaleCompletion();
            if (token.queueSerial <= lastFinalizedQueueSerial_ ||
                hasPendingBefore(token.queueSerial))
                return noteStaleCompletion();
            PendingIdentity *pending = findPendingIdentity(token);
            if (!pending || untrackedPendingDrainCount_ == 0 ||
                pendingDrainCount_ == 0)
                return noteStaleCompletion();
            *pending = {};
            --untrackedPendingDrainCount_;
            --pendingDrainCount_;
            lastFinalizedQueueSerial_ = token.queueSerial;
            bumpRevision();
            return true;
        }
        Event *event = findActionEvent(token);
        if (!event || !event->pendingDrain || event->completionUpdated ||
            pendingDrainCount_ == 0 ||
            token.queueSerial <= lastFinalizedQueueSerial_ ||
            hasPendingBefore(token.queueSerial))
            return noteStaleCompletion();
        event->tableObserveAttempted = table.attempted ? 1u : 0u;
        event->tableResultPresent = table.resultPresent ? 1u : 0u;
        event->tableStatus = table.status;
        event->peerObserverAttempted = observer.attempted ? 1u : 0u;
        event->peerObserverResultPresent = observer.resultPresent ? 1u : 0u;
        event->peerObserverStatus = observer.status;
        event->decodeAttempted = decode.attempted ? 1u : 0u;
        event->decodeResultPresent = decode.resultPresent ? 1u : 0u;
        event->decodeStatus = decode.status;
        event->decodeRejectStage = decode.rejectStage;
        event->decodeOffendingTlvType = decode.offendingTlvType;
        event->decodeRelatedTlvType = decode.relatedTlvType;
        event->completionUpdated = 1;
        event->pendingDrain = 0;
        --pendingDrainCount_;
        lastFinalizedQueueSerial_ = token.queueSerial;
        bumpRevision();
        return true;
    }

    // Raw 24-byte TIME_EVENT is a distinct ABI from the 16-byte
    // SESSION_PROTECTION start/end notification. Its firmware timestamp is
    // not GP2 and is named separately in exported fields.
    EventToken recordTimeEvent(const TimeEvent24 &notification,
                               const Epochs &capturedEpochs,
                               uint64_t ownerSerial)
    {
        if (!ownerPresent_ || !active_ || producerClosed_ ||
            ownerSerial != ownerSerial_ || !sameEpochs(capturedEpochs, epochs_)) {
            timeEventNotificationDroppedCount_ =
                saturatedIncrement(timeEventNotificationDroppedCount_);
            bumpRevision();
            return invalidToken();
        }
        EventToken token = allocateEvent(EventKind::TimeEventNotification,
                                         notification.hostMonotonicUs,
                                         notification.hostMonotonicPresent,
                                         notification.rawLength);
        if (!token.eventSerial) {
            timeEventNotificationDroppedCount_ =
                saturatedIncrement(timeEventNotificationDroppedCount_);
            bumpRevision();
            return token;
        }
        Event &event = events_[eventCount_ - 1];
        event.notificationApi = NotificationApi::TimeEvent24;
        event.notificationMatchStatusPresent =
            notification.matchStatusPresent ? 1u : 0u;
        event.notificationMatchStatus = notification.matchStatus;
        event.timeEventTimestamp = notification.timestamp;
        event.timeEventSessionId = notification.sessionId;
        event.timeEventUniqueId = notification.uniqueId;
        event.timeEventMacIdAndColor = notification.macIdAndColor;
        event.timeEventRawAction = notification.rawAction;
        event.timeEventRawStatus = notification.rawStatus;
        event.timeEventExpectedUidKnown = notification.leaseUidKnown ? 1u : 0u;
        event.timeEventExpectedUid = notification.leaseExpectedUid;
        timeEventNotificationCount_ =
            saturatedIncrement(timeEventNotificationCount_);
        bumpRevision();
        return token;
    }

    // Capture the prepared TX identity after it is bound to an actual parsed
    // wire action and refreshed per-ticket diagnostics. A failed trace append
    // is observational only; callers must not alter or retry the TX path.
    EventToken recordTxPrepared(const TxPrepared &prepared,
                                uint64_t ownerSerial)
    {
        if (!ownerPresent_ || !active_ || producerClosed_ || !ownerSerial ||
            ownerSerial != ownerSerial_ || !sameEpochs(prepared.epochs, epochs_) ||
            !prepared.ticketSerial) {
            droppedEventCount_ = saturatedIncrement(droppedEventCount_);
            bumpRevision();
            return invalidToken();
        }
        EventToken token = allocateEvent(EventKind::TxPrepared,
                                         prepared.hostMonotonicUs,
                                         prepared.hostMonotonicPresent, 0);
        if (!token.eventSerial)
            return token;
        Event &event = events_[eventCount_ - 1];
        event.txTicketSerial = prepared.ticketSerial;
        event.txDiagnosticGeneration = prepared.diagnosticGeneration;
        event.txSequenceControl = prepared.sequenceControl;
        event.txWireInfoPresent = prepared.wireInfoPresent ? 1u : 0u;
        event.txWirePhyTxUs = prepared.wirePhyTxUs;
        event.txWireTargetTxUs = prepared.wireTargetTxUs;
        event.txQueueId = prepared.queueId;
        event.txDescriptorIndex = prepared.descriptorIndex;
        bumpRevision();
        return token;
    }

    // Reducer return and canonical state transition are distinct. The caller
    // derives canonicalTransition from before/after SessionSnapshot values;
    // a true reducer return alone is not enough (duplicates and malformed
    // sequences may still return true). First canonical START/END is preserved
    // in reserved slots regardless of RX event-ring capacity.
    bool recordSessionProtection(const SessionProtection16 &notification,
                                 const Epochs &capturedEpochs,
                                 uint64_t ownerSerial)
    {
        if (!ownerPresent_ || ownerSerial != ownerSerial_ ||
            !sameEpochs(capturedEpochs, epochs_)) {
            staleNotificationCount_ = saturatedIncrement(staleNotificationCount_);
            bumpRevision();
            return false;
        }

        if (notificationSerial_ != UINT64_MAX)
            ++notificationSerial_;
        const uint64_t notificationSerial = notificationSerial_;

        if (notification.reducerReturnedTrue)
            sessionReducerReturnedTrueCount_ =
                saturatedIncrement(sessionReducerReturnedTrueCount_);

        const bool canonical = notification.canonicalTransitionPresent &&
            notification.canonicalTransition;
        const bool isStart = notification.rawStartFlag != 0;
        const bool endWithoutStart = canonical && !isStart && !rocStart_.present;
        const SessionAnomalyReason effectiveReason =
            notification.anomalyReason == SessionAnomalyReason::None &&
                    endWithoutStart
                ? SessionAnomalyReason::EndBeforeStart
                : notification.anomalyReason;
        const bool endBeforeStart =
            effectiveReason == SessionAnomalyReason::EndBeforeStart;
        const bool anomalyBlocksBoundary =
            effectiveReason != SessionAnomalyReason::None &&
            !endBeforeStart;
        if (effectiveReason != SessionAnomalyReason::None) {
            countAnomaly(effectiveReason);
            saveAnomaly(notification, ownerSerial, capturedEpochs,
                        notificationSerial, effectiveReason);
        }

        if (!canonical || anomalyBlocksBoundary) {
            sessionNotificationIgnoredCount_ =
                saturatedIncrement(sessionNotificationIgnoredCount_);
            if (effectiveReason == SessionAnomalyReason::None) {
                const SessionAnomalyReason reason =
                    notification.reducerResultPresent &&
                    notification.reducerReturnedTrue
                    ? SessionAnomalyReason::UnclassifiedNoncanonical
                    : SessionAnomalyReason::ReducerIgnored;
                countAnomaly(reason);
                saveAnomaly(notification, ownerSerial, capturedEpochs,
                            notificationSerial, reason);
            }
            bumpRevision();
            return true;
        }

        sessionCanonicalTransitionCount_ =
            saturatedIncrement(sessionCanonicalTransitionCount_);
        BoundarySlot &slot = isStart ? rocStart_ : rocEnd_;
        if (slot.present) {
            sessionNotificationIgnoredCount_ =
                saturatedIncrement(sessionNotificationIgnoredCount_);
            const SessionAnomalyReason reason =
                effectiveReason == SessionAnomalyReason::None
                    ? SessionAnomalyReason::Duplicate
                    : effectiveReason;
            countAnomaly(reason);
            saveAnomaly(notification, ownerSerial, capturedEpochs,
                        notificationSerial, reason);
            bumpRevision();
            return true;
        }

        sessionNotificationAcceptedCount_ =
            saturatedIncrement(sessionNotificationAcceptedCount_);
        slot.present = 1;
        slot.api = NotificationApi::SessionProtection16;
        slot.notificationSerial = notificationSerial;
        slot.ownerSerial = ownerSerial_;
        slot.epochs = epochs_;
        slot.hostMonotonicUs = notification.hostMonotonicUs;
        slot.hostMonotonicPresent = notification.hostMonotonicPresent ? 1u : 0u;
        slot.rawLength = notification.rawLength;
        slot.ownerSessionToken = notification.ownerSessionToken;
        slot.expectedUidKnown = notification.expectedUidKnown ? 1u : 0u;
        slot.expectedUid = notification.expectedUid;
        slot.macIdAndColor = notification.macIdAndColor;
        slot.rawStatus = notification.rawStatus;
        slot.rawStartFlag = notification.rawStartFlag;
        slot.configuration = notification.configuration;
        slot.reducerResultPresent = notification.reducerResultPresent ? 1u : 0u;
        slot.reducerReturnedTrue = notification.reducerReturnedTrue ? 1u : 0u;
        slot.reducerResult = notification.reducerResult;
        slot.canonicalTransitionPresent =
            notification.canonicalTransitionPresent ? 1u : 0u;
        slot.canonicalTransition = notification.canonicalTransition ? 1u : 0u;
        if ((!isStart && !rocStart_.present) || endBeforeStart)
            sessionBoundaryOrderInvalid_ = true;
        bumpRevision();
        return true;
    }

    // Explicit producer closure is separate from END observation. Pending RX
    // records may still drain after END and update their original rows.
    bool closeProducer(uint64_t ownerSerial, const Epochs &epochs,
                       uint32_t reason)
    {
        if (!ownerPresent_ || ownerSerial != ownerSerial_ ||
            !sameEpochs(epochs, epochs_))
            return noteStaleCompletion();
        if (!producerClosed_) {
            producerClosed_ = true;
            active_ = false;
            producerCloseReason_ = reason;
            bumpRevision();
        }
        return true;
    }

    Snapshot snapshot() const
    {
        Snapshot value{};
        value.schemaVersion = kSchemaVersion;
        value.ownerPresent = ownerPresent_ ? 1u : 0u;
        value.ownerSerial = ownerPresent_ ? ownerSerial_ : 0;
        value.epochs = ownerPresent_ ? epochs_ : Epochs{};
        value.active = active_ ? 1u : 0u;
        value.producerClosed = producerClosed_ ? 1u : 0u;
        value.pendingDrainCount = pendingDrainCount_;
        value.untrackedPendingDrainCount = untrackedPendingDrainCount_;
        value.untrackedPendingIdentityOverflowCount =
            untrackedPendingIdentityOverflowCount_;
        value.eventCount = static_cast<uint32_t>(eventCount_);
        value.droppedEventCount = droppedEventCount_;
        value.staleCompletionCount = staleCompletionCount_;
        value.sourceTableFullCount = sourceTableFullCount_;
        value.filteredActionCount = filteredActionCount_;
        value.rejectedOwnerCount = rejectedOwnerCount_;
        value.staleNotificationCount = staleNotificationCount_;
        value.sessionAnomalyCount = sessionAnomalyCount_;
        value.sessionReducerReturnedTrueCount = sessionReducerReturnedTrueCount_;
        value.sessionCanonicalTransitionCount = sessionCanonicalTransitionCount_;
        value.sessionNotificationAcceptedCount = sessionNotificationAcceptedCount_;
        value.sessionNotificationIgnoredCount = sessionNotificationIgnoredCount_;
        value.sessionNotificationDuplicateCount = sessionNotificationDuplicateCount_;
        value.sessionNotificationConflictingCount = sessionNotificationConflictingCount_;
        value.sessionNotificationLateCount = sessionNotificationLateCount_;
        value.sessionNotificationMalformedCount = sessionNotificationMalformedCount_;
        value.sessionNotificationForeignCount = sessionNotificationForeignCount_;
        value.sessionBoundaryOrderInvalid = sessionBoundaryOrderInvalid_ ? 1u : 0u;
        value.timeEventNotificationCount = timeEventNotificationCount_;
        value.timeEventNotificationDroppedCount = timeEventNotificationDroppedCount_;
        value.producerCloseReason = producerCloseReason_;
        value.rocStart = rocStart_;
        value.rocEnd = rocEnd_;
        value.firstSessionAnomaly = firstSessionAnomaly_;
        value.lastSessionAnomaly = lastSessionAnomaly_;
        value.revision = revision_;
        return value;
    }

    bool eventAt(size_t index, Event *output) const
    {
        if (!output || index >= eventCount_ || index >= kEventCapacity)
            return false;
        *output = events_[index];
        return true;
    }

    // Storage completeness only. Protocol success still requires callers to
    // inspect both canonical boundary slots, their raw statuses, and ordering.
    bool storageComplete() const
    {
        return ownerPresent_ && producerClosed_ && pendingDrainCount_ == 0 &&
            untrackedPendingDrainCount_ == 0 && droppedEventCount_ == 0 &&
            staleCompletionCount_ == 0 && sourceTableFullCount_ == 0 &&
            timeEventNotificationDroppedCount_ == 0 &&
            untrackedPendingIdentityOverflowCount_ == 0;
    }

private:
    struct SourceEntry {
        uint8_t address[6];
        uint32_t ordinal;
        uint32_t used;
    };

    struct PendingIdentity {
        uint64_t queueSerial;
        uint64_t ownerSerial;
        Epochs epochs;
        uint32_t used;
    };

    static uint32_t saturatedIncrement(uint32_t value)
    {
        return value == UINT32_MAX ? value : value + 1u;
    }

    void bumpRevision()
    {
        if (revision_ != UINT64_MAX)
            ++revision_;
    }

    EventToken invalidToken() const
    {
        return {0, 0, ownerPresent_ ? ownerSerial_ : 0,
                ownerPresent_ ? epochs_ : Epochs{}, 0, 0, 0};
    }

    EventToken allocateQueueToken(uint64_t eventSerial, uint32_t sourceOrdinal,
                                  bool sourceKnown)
    {
        if (nextQueueSerial_ == UINT64_MAX)
            return invalidToken();
        const uint64_t queueSerial = ++nextQueueSerial_;
        return {eventSerial, queueSerial, ownerSerial_, epochs_, sourceOrdinal,
                sourceKnown ? 1u : 0u, eventSerial ? 1u : 0u};
    }

    PendingIdentity *findFreePendingIdentity()
    {
        for (size_t i = 0; i < kPendingIdentityCapacity; ++i) {
            if (!pendingIdentities_[i].used)
                return &pendingIdentities_[i];
        }
        return nullptr;
    }

    PendingIdentity *findPendingIdentity(const EventToken &token)
    {
        if (!ownerPresent_ || token.ownerSerial != ownerSerial_ ||
            !sameEpochs(token.epochs, epochs_))
            return nullptr;
        for (size_t i = 0; i < kPendingIdentityCapacity; ++i) {
            PendingIdentity &pending = pendingIdentities_[i];
            if (pending.used && pending.queueSerial == token.queueSerial &&
                pending.ownerSerial == token.ownerSerial &&
                sameEpochs(pending.epochs, token.epochs))
                return &pending;
        }
        return nullptr;
    }

    bool hasPendingBefore(uint64_t queueSerial) const
    {
        for (size_t i = 0; i < kPendingIdentityCapacity; ++i) {
            const PendingIdentity &pending = pendingIdentities_[i];
            if (pending.used && pending.ownerSerial == ownerSerial_ &&
                sameEpochs(pending.epochs, epochs_) &&
                pending.queueSerial < queueSerial)
                return true;
        }
        for (size_t i = 0; i < eventCount_; ++i) {
            const Event &event = events_[i];
            if (event.pendingDrain && event.queueSerial < queueSerial &&
                event.ownerSerial == ownerSerial_ &&
                sameEpochs(event.epochs, epochs_))
                return true;
        }
        return false;
    }

    void noteUntrackedIdentityOverflow()
    {
        untrackedPendingIdentityOverflowCount_ = saturatedIncrement(
            untrackedPendingIdentityOverflowCount_);
        untrackedPendingDrainCount_ = saturatedIncrement(
            untrackedPendingDrainCount_);
        pendingDrainCount_ = saturatedIncrement(pendingDrainCount_);
        bumpRevision();
    }

    uint32_t findOrAddSource(const uint8_t *address, uint32_t length)
    {
        if (!address || length != sizeof(SourceEntry::address))
            return kNoSourceOrdinal;
        for (size_t i = 0; i < kSourceCapacity; ++i) {
            const SourceEntry &entry = sources_[i];
            if (entry.used && memcmp(entry.address, address, 6) == 0)
                return entry.ordinal;
        }
        for (size_t i = 0; i < kSourceCapacity; ++i) {
            SourceEntry &entry = sources_[i];
            if (!entry.used) {
                if (nextSourceOrdinal_ == UINT32_MAX) {
                    sourceTableFullCount_ =
                        saturatedIncrement(sourceTableFullCount_);
                    return kNoSourceOrdinal;
                }
                entry = {};
                memcpy(entry.address, address, 6);
                entry.ordinal = ++nextSourceOrdinal_;
                entry.used = 1;
                return entry.ordinal;
            }
        }
        sourceTableFullCount_ = saturatedIncrement(sourceTableFullCount_);
        return kNoSourceOrdinal;
    }

    EventToken allocateEvent(EventKind kind, uint64_t hostUs,
                            uint32_t hostPresent, uint32_t rawLength)
    {
        if (eventCount_ >= kEventCapacity || nextEventSerial_ == UINT64_MAX) {
            droppedEventCount_ = saturatedIncrement(droppedEventCount_);
            bumpRevision();
            return invalidToken();
        }
        Event &event = events_[eventCount_++];
        event = {};
        event.serial = ++nextEventSerial_;
        event.ownerSerial = ownerSerial_;
        event.epochs = epochs_;
        event.kind = kind;
        event.hostMonotonicUs = hostUs;
        event.hostMonotonicPresent = hostPresent ? 1u : 0u;
        event.rawLength = rawLength;
        bumpRevision();
        return {event.serial, 0, ownerSerial_, epochs_, 0, 0, 1};
    }

    Event *findActionEvent(const EventToken &token)
    {
        if (!token.rowPresent || !token.eventSerial || !token.queueSerial ||
            token.ownerSerial == 0 ||
            !ownerPresent_ || token.eventSerial > nextEventSerial_)
            return nullptr;
        for (size_t i = 0; i < eventCount_; ++i) {
            Event &event = events_[i];
            if (event.serial == token.eventSerial &&
                event.ownerSerial == token.ownerSerial &&
                event.queueSerial == token.queueSerial &&
                sameEpochs(event.epochs, token.epochs) &&
                event.kind == EventKind::ActionRxTap &&
                event.sourceOrdinal == token.sourceOrdinal &&
                event.sourceKnown == token.sourceKnown)
                return &event;
        }
        return nullptr;
    }

    bool noteStaleCompletion()
    {
        staleCompletionCount_ = saturatedIncrement(staleCompletionCount_);
        bumpRevision();
        return false;
    }

    void countAnomaly(SessionAnomalyReason reason)
    {
        if (reason != SessionAnomalyReason::None)
            sessionAnomalyCount_ = saturatedIncrement(sessionAnomalyCount_);
        switch (reason) {
            case SessionAnomalyReason::Duplicate:
                sessionNotificationDuplicateCount_ =
                    saturatedIncrement(sessionNotificationDuplicateCount_);
                break;
            case SessionAnomalyReason::Conflicting:
                sessionNotificationConflictingCount_ =
                    saturatedIncrement(sessionNotificationConflictingCount_);
                break;
            case SessionAnomalyReason::LateAfterEnd:
                sessionNotificationLateCount_ =
                    saturatedIncrement(sessionNotificationLateCount_);
                break;
            case SessionAnomalyReason::Malformed:
                sessionNotificationMalformedCount_ =
                    saturatedIncrement(sessionNotificationMalformedCount_);
                break;
            case SessionAnomalyReason::ForeignContext:
                sessionNotificationForeignCount_ =
                    saturatedIncrement(sessionNotificationForeignCount_);
                break;
            case SessionAnomalyReason::EndBeforeStart:
                sessionBoundaryOrderInvalid_ = true;
                break;
            case SessionAnomalyReason::None:
            case SessionAnomalyReason::ReducerIgnored:
            case SessionAnomalyReason::UnclassifiedNoncanonical:
                break;
        }
    }

    void saveAnomaly(const SessionProtection16 &notification,
                     uint64_t ownerSerial, const Epochs &epochs,
                     uint64_t notificationSerial,
                     SessionAnomalyReason reason)
    {
        auto save = [&](IgnoredNotification &record) {
            record.present = 1;
            record.api = NotificationApi::SessionProtection16;
            record.reason = reason;
            record.notificationSerial = notificationSerial;
            record.ownerSerial = ownerSerial;
            record.epochs = epochs;
            record.hostMonotonicUs = notification.hostMonotonicUs;
            record.hostMonotonicPresent = notification.hostMonotonicPresent ? 1u : 0u;
            record.rawLength = notification.rawLength;
            record.ownerSessionToken = notification.ownerSessionToken;
            record.expectedUidKnown = notification.expectedUidKnown ? 1u : 0u;
            record.expectedUid = notification.expectedUid;
            record.macIdAndColor = notification.macIdAndColor;
            record.rawStatus = notification.rawStatus;
            record.rawStartFlag = notification.rawStartFlag;
            record.configuration = notification.configuration;
            record.reducerResultPresent = notification.reducerResultPresent ? 1u : 0u;
            record.reducerReturnedTrue = notification.reducerReturnedTrue ? 1u : 0u;
            record.reducerResult = notification.reducerResult;
        };
        if (!firstSessionAnomaly_.present)
            save(firstSessionAnomaly_);
        save(lastSessionAnomaly_);
    }

    SourceEntry sources_[kSourceCapacity]{};
    Event events_[kEventCapacity]{};
    uint64_t ownerSerial_{0};
    Epochs epochs_{};
    uint64_t nextEventSerial_{0};
    uint64_t nextQueueSerial_{0};
    uint64_t lastFinalizedQueueSerial_{0};
    uint32_t nextSourceOrdinal_{0}; // Never reset, so exported ordinals do not recur.
    size_t eventCount_{0};
    uint32_t pendingDrainCount_{0};
    uint32_t untrackedPendingDrainCount_{0};
    uint32_t untrackedPendingIdentityOverflowCount_{0};
    uint32_t droppedEventCount_{0};
    uint32_t staleCompletionCount_{0};
    uint32_t sourceTableFullCount_{0};
    uint32_t filteredActionCount_{0};
    uint32_t rejectedOwnerCount_{0};
    uint32_t staleNotificationCount_{0};
    uint32_t sessionAnomalyCount_{0};
    uint32_t sessionReducerReturnedTrueCount_{0};
    uint32_t sessionCanonicalTransitionCount_{0};
    uint32_t sessionNotificationAcceptedCount_{0};
    uint32_t sessionNotificationIgnoredCount_{0};
    uint32_t sessionNotificationDuplicateCount_{0};
    uint32_t sessionNotificationConflictingCount_{0};
    uint32_t sessionNotificationLateCount_{0};
    uint32_t sessionNotificationMalformedCount_{0};
    uint32_t sessionNotificationForeignCount_{0};
    bool sessionBoundaryOrderInvalid_{false};
    uint32_t timeEventNotificationCount_{0};
    uint32_t timeEventNotificationDroppedCount_{0};
    uint32_t producerCloseReason_{0};
    uint64_t revision_{0};
    uint64_t notificationSerial_{0};
    bool ownerPresent_{false};
    bool active_{false};
    bool producerClosed_{false};
    PendingIdentity pendingIdentities_[kPendingIdentityCapacity]{};
    BoundarySlot rocStart_{};
    BoundarySlot rocEnd_{};
    IgnoredNotification firstSessionAnomaly_{};
    IgnoredNotification lastSessionAnomaly_{};
};

static_assert(sizeof(Event) <= 336,
              "RX trace event must remain a compact scalar-only record");
static_assert(sizeof(Timeline) <= 16 * 1024,
              "RX trace timeline must remain within its fixed memory budget");

} // namespace NativeAwdlRxTrace

#endif // NATIVE_AWDL_RX_EVENT_TIMELINE_HPP
