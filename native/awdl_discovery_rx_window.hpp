// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DISCOVERY_RX_WINDOW_HPP
#define NATIVE_AWDL_DISCOVERY_RX_WINDOW_HPP

#include <stddef.h>
#include <stdint.h>

// Bounded metadata-only RX observation for one exact Discovery ROC. Callers
// serialize begin/record/close/snapshot on the driver's existing main gate.
// No packet bytes, MAC addresses, mbufs, DMA pointers, or allocations are kept.
namespace NativeAwdlDiscoveryRxWindow {

constexpr uint32_t kSchemaVersion = 1;
constexpr uint32_t kEventCapacity = 64;
constexpr uint64_t kWireMagic = 0x314e495758524441ULL; // "ADRXWIN1" LE
constexpr uint32_t kEventWordCount = 9;
constexpr uint32_t kWireHeaderWordCount = 4;
constexpr uint32_t kMaxWireWordCount =
    kWireHeaderWordCount + kEventCapacity * kEventWordCount;

enum class State : uint32_t { Idle = 0, Active = 1, Closed = 2, Invalid = 3 };
enum class CloseReason : uint32_t {
    None = 0,
    CanonicalRocEnd = 1,
    EpochMismatch = 2,
    DriverGenerationMismatch = 3,
    InvalidTimeline = 4,
    OwnerReleasedWithoutEnd = 5,
    BridgeCounterReversed = 6
};
enum class FrameClass : uint32_t {
    Unknown = 0,
    Management = 1,
    Control = 2,
    Data = 3,
    Extension = 4,
    Count = 5
};
enum class ServiceEvent : uint32_t {
    RxDrain = 0,
    RxRingSlot = 1,
    NotificationSeen = 2,
    HeaderRejected = 3,
    LengthRejected = 4,
    NotificationValidated = 5,
    MpduDispatch = 6,
    AddbufFailed = 7,
    CopyFailed = 8,
    Count = 9
};

enum EventFlag : uint32_t {
    DescriptorPresent = 1u << 0,
    FrameControlPresent = 1u << 1,
    RawStatusPresent = 1u << 2,
    CrcOk = 1u << 3,
    OverrunOk = 1u << 4,
    ChannelPresent = 1u << 5,
    MpduLengthPresent = 1u << 6,
    LeaseQualified = 1u << 7,
    AwdlDataCandidate = 1u << 8,
    DataRouteRecorded = 1u << 9
};
constexpr uint32_t kKnownEventFlags = (1u << 10) - 1u;

enum class DataRoute : uint32_t {
    NotRecorded = 0,
    PassToSta = 1,
    QueuedForNative = 2,
    DuplicateRetry = 3
};

struct Epochs {
    uint32_t context;
    uint32_t power;
    uint32_t station;
    uint32_t roc;
};

struct BridgeCounters {
    uint64_t rxCaptured;
    uint64_t rxRejected;
    uint64_t rxDecoded;
    uint64_t rxDelivered;
    uint64_t rxInputFailed;
    uint64_t rxPending;
    uint64_t discoveryInputCalls;
    uint64_t discoveryInputSuccess;
    uint64_t discoverySameWindowCommitted;
};

struct MpduEvent {
    uint64_t monotonicUs;
    uint32_t ordinal;
    FrameClass frameClass;
    uint32_t flags;
    uint32_t channel;
    uint32_t mpduLength;
    uint32_t frameControl;
    uint32_t leaseState; // 0 unknown, 1 command/ROC-qualified, 2 command pending
    DataRoute dataRoute;
};

struct ServiceEvidence {
    uint64_t count;
    uint64_t firstUs;
    uint64_t lastUs;
};

struct Snapshot {
    uint32_t schemaVersion;
    State state;
    CloseReason closeReason;
    uint32_t valid;
    uint32_t complete;
    uint32_t overflow;
    uint32_t driverGeneration;
    Epochs epochs;
    uint64_t startUs;
    uint64_t endUs;
    uint64_t firstMpduEntryUs;
    uint64_t lastMpduEntryUs;
    uint64_t mpduEntryCount;
    uint64_t frameClassCounts[static_cast<uint32_t>(FrameClass::Count)];
    uint64_t awdlDataCandidateCount;
    uint64_t leaseQualifiedCount;
    uint64_t leaseUnqualifiedCount;
    uint64_t descriptorUnavailableCount;
    uint64_t crcRejectedCount;
    uint64_t overrunRejectedCount;
    uint64_t channel149Count;
    uint64_t routePassToStaCount;
    uint64_t routeQueuedForNativeCount;
    uint64_t routeDuplicateRetryCount;
    uint32_t queryResponseObserved;
    uint32_t queryResponseComplete;
    uint64_t queryDoorbellUs;
    uint64_t queryDeadlineUs;
    uint64_t queryFirstMpduEntryUs;
    uint64_t queryLastMpduEntryUs;
    uint64_t queryMpduEntryCount;
    uint64_t queryAwdlDataCandidateCount;
    uint64_t queryCrcRejectedCount;
    uint64_t queryOverrunRejectedCount;
    uint64_t queryDescriptorUnavailableCount;
    uint64_t queryFrameClassCounts[static_cast<uint32_t>(FrameClass::Count)];
    ServiceEvidence service[static_cast<uint32_t>(ServiceEvent::Count)];
    BridgeCounters bridgeBefore;
    BridgeCounters bridgeAfter;
    uint32_t eventCount;
    MpduEvent events[kEventCapacity];
};

inline bool validEpochs(const Epochs &epochs)
{
    return epochs.context != 0 && epochs.power != 0 &&
        epochs.station != 0 && epochs.roc != 0;
}

inline bool sameEpochs(const Epochs &left, const Epochs &right)
{
    return left.context == right.context && left.power == right.power &&
        left.station == right.station && left.roc == right.roc;
}

inline bool bridgeCountersNotDecreased(const BridgeCounters &before,
                                       const BridgeCounters &after)
{
    return after.rxCaptured >= before.rxCaptured &&
        after.rxRejected >= before.rxRejected &&
        after.rxDecoded >= before.rxDecoded &&
        after.rxDelivered >= before.rxDelivered &&
        after.rxInputFailed >= before.rxInputFailed &&
        // rxPending is a live queue depth, so it may fall. It is deliberately
        // excluded from monotonic-counter validation.
        after.discoveryInputCalls >= before.discoveryInputCalls &&
        after.discoveryInputSuccess >= before.discoveryInputSuccess &&
        after.discoverySameWindowCommitted >=
            before.discoverySameWindowCommitted;
}

inline bool validEvent(const MpduEvent &event)
{
    const uint32_t rawClass = static_cast<uint32_t>(event.frameClass);
    const uint32_t rawRoute = static_cast<uint32_t>(event.dataRoute);
    if (rawClass >= static_cast<uint32_t>(FrameClass::Count) ||
        (event.flags & ~kKnownEventFlags) != 0 ||
        rawRoute > static_cast<uint32_t>(DataRoute::DuplicateRetry))
        return false;
    if (!(event.flags & ChannelPresent) && event.channel != 0)
        return false;
    if (!(event.flags & MpduLengthPresent) && event.mpduLength != 0)
        return false;
    if (!(event.flags & FrameControlPresent) && event.frameControl != 0)
        return false;
    if (!(event.flags & DataRouteRecorded) &&
        event.dataRoute != DataRoute::NotRecorded)
        return false;
    if ((event.flags & DataRouteRecorded) &&
        event.dataRoute == DataRoute::NotRecorded)
        return false;
    return true;
}

// Caller-owned fixed record; every word is explicitly promoted to uint64_t.
// On failure the output is untouched. Header words are magic, schema, total
// word count, and event count. Each event is nine words as described above.
inline size_t encode(const Snapshot &snapshot, uint64_t *out,
                     size_t capacityWords)
{
    const size_t words = kWireHeaderWordCount +
        size_t(snapshot.eventCount) * kEventWordCount;
    if (!out || snapshot.eventCount > kEventCapacity ||
        capacityWords < words || snapshot.state == State::Active ||
        snapshot.state == State::Idle)
        return 0;
    for (uint32_t i = 0; i < snapshot.eventCount; ++i) {
        if (!validEvent(snapshot.events[i]))
            return 0;
    }
    size_t index = 0;
    out[index++] = kWireMagic;
    out[index++] = kSchemaVersion;
    out[index++] = words;
    out[index++] = snapshot.eventCount;
    for (uint32_t i = 0; i < snapshot.eventCount; ++i) {
        const MpduEvent &event = snapshot.events[i];
        out[index++] = event.monotonicUs;
        out[index++] = event.ordinal;
        out[index++] = static_cast<uint32_t>(event.frameClass);
        out[index++] = event.flags;
        out[index++] = event.channel;
        out[index++] = event.mpduLength;
        out[index++] = event.frameControl;
        out[index++] = event.leaseState;
        out[index++] = static_cast<uint32_t>(event.dataRoute);
    }
    return index;
}

class Observer {
public:
    Observer() : state_(State::Idle), closeReason_(CloseReason::None),
        started_(false), driverGeneration_(0), epochs_{}, startUs_(0),
        endUs_(0), lastUs_(0), firstMpduEntryUs_(0), lastMpduEntryUs_(0),
        mpduEntryCount_(0), awdlDataCandidateCount_(0),
        leaseQualifiedCount_(0), leaseUnqualifiedCount_(0),
        descriptorUnavailableCount_(0), crcRejectedCount_(0),
        overrunRejectedCount_(0), channel149Count_(0),
        routePassToStaCount_(0), routeQueuedForNativeCount_(0),
        routeDuplicateRetryCount_(0), queryDoorbellUs_(0), queryDeadlineUs_(0),
        queryFirstMpduEntryUs_(0), queryLastMpduEntryUs_(0),
        queryMpduEntryCount_(0), queryAwdlDataCandidateCount_(0),
        queryCrcRejectedCount_(0), queryOverrunRejectedCount_(0),
        queryDescriptorUnavailableCount_(0), overflow_(0), eventCount_(0),
        bridgeBefore_{}, bridgeAfter_{}, service_{}
    {
        zeroFrameCounts();
        __builtin_memset(queryFrameClassCounts_, 0,
                         sizeof(queryFrameClassCounts_));
        __builtin_memset(events_, 0, sizeof(events_));
    }

    Observer(const Observer &) = delete;
    Observer &operator=(const Observer &) = delete;

    bool reset()
    {
        if (state_ == State::Active)
            return false;
        state_ = State::Idle;
        closeReason_ = CloseReason::None;
        started_ = false;
        driverGeneration_ = 0;
        epochs_ = Epochs{};
        startUs_ = endUs_ = lastUs_ = 0;
        firstMpduEntryUs_ = lastMpduEntryUs_ = 0;
        mpduEntryCount_ = awdlDataCandidateCount_ = 0;
        leaseQualifiedCount_ = leaseUnqualifiedCount_ = 0;
        descriptorUnavailableCount_ = crcRejectedCount_ = 0;
        overrunRejectedCount_ = channel149Count_ = 0;
        routePassToStaCount_ = routeQueuedForNativeCount_ = 0;
        routeDuplicateRetryCount_ = 0;
        queryDoorbellUs_ = queryDeadlineUs_ = 0;
        queryFirstMpduEntryUs_ = queryLastMpduEntryUs_ = 0;
        queryMpduEntryCount_ = queryAwdlDataCandidateCount_ = 0;
        queryCrcRejectedCount_ = queryOverrunRejectedCount_ = 0;
        queryDescriptorUnavailableCount_ = 0;
        __builtin_memset(queryFrameClassCounts_, 0,
                         sizeof(queryFrameClassCounts_));
        overflow_ = eventCount_ = 0;
        bridgeBefore_ = BridgeCounters{};
        bridgeAfter_ = BridgeCounters{};
        __builtin_memset(frameClassCounts_, 0, sizeof(frameClassCounts_));
        __builtin_memset(service_, 0, sizeof(service_));
        __builtin_memset(events_, 0, sizeof(events_));
        return true;
    }

    bool begin(const Epochs &epochs, uint32_t driverGeneration,
               uint64_t startUs, const BridgeCounters &bridgeBefore)
    {
        if (started_ || !validEpochs(epochs) || driverGeneration == 0 ||
            startUs == 0)
            return false;
        started_ = true;
        state_ = State::Active;
        closeReason_ = CloseReason::None;
        driverGeneration_ = driverGeneration;
        epochs_ = epochs;
        startUs_ = lastUs_ = startUs;
        bridgeBefore_ = bridgeBefore;
        return true;
    }

    bool active() const { return state_ == State::Active; }
    State state() const { return state_; }
    bool boundEpochs(Epochs *out) const
    {
        if (!out || state_ != State::Active)
            return false;
        *out = epochs_;
        return true;
    }

    // Called on the same main gate that serializes RX records, immediately
    // after the accepted QM doorbell is joined to its TX trace row.
    bool markQueryResponseWindow(const Epochs &epochs,
                                 uint32_t driverGeneration,
                                 uint64_t doorbellUs,
                                 uint64_t responseWindowUs)
    {
        if (!responseWindowUs || queryDoorbellUs_ ||
            doorbellUs > UINT64_MAX - responseWindowUs ||
            !current(epochs, driverGeneration, doorbellUs))
            return false;
        queryDoorbellUs_ = doorbellUs;
        queryDeadlineUs_ = doorbellUs + responseWindowUs;
        return true;
    }

    bool recordService(const Epochs &epochs, uint32_t driverGeneration,
                       ServiceEvent kind, uint64_t nowUs)
    {
        if (!current(epochs, driverGeneration, nowUs))
            return false;
        const uint32_t index = static_cast<uint32_t>(kind);
        if (index >= static_cast<uint32_t>(ServiceEvent::Count)) {
            invalidate(CloseReason::InvalidTimeline, nowUs);
            return false;
        }
        ServiceEvidence &entry = service_[index];
        saturatingIncrement(entry.count);
        if (!entry.firstUs)
            entry.firstUs = nowUs;
        entry.lastUs = nowUs;
        lastUs_ = nowUs;
        return true;
    }

    // Returns the fixed slot that may receive a later data-route result, or
    // UINT32_MAX when the bounded MPDU event table is full.
    uint32_t recordMpdu(const Epochs &epochs, uint32_t driverGeneration,
                        const MpduEvent &event)
    {
        if (!current(epochs, driverGeneration, event.monotonicUs) ||
            !validEvent(event))
            return UINT32_MAX;
        const uint32_t frameClass = static_cast<uint32_t>(event.frameClass);
        saturatingIncrement(mpduEntryCount_);
        saturatingIncrement(frameClassCounts_[frameClass]);
        if (event.flags & AwdlDataCandidate)
            saturatingIncrement(awdlDataCandidateCount_);
        if (event.flags & LeaseQualified)
            saturatingIncrement(leaseQualifiedCount_);
        else
            saturatingIncrement(leaseUnqualifiedCount_);
        if (!(event.flags & DescriptorPresent))
            saturatingIncrement(descriptorUnavailableCount_);
        if ((event.flags & RawStatusPresent) && !(event.flags & CrcOk))
            saturatingIncrement(crcRejectedCount_);
        if ((event.flags & RawStatusPresent) && !(event.flags & OverrunOk))
            saturatingIncrement(overrunRejectedCount_);
        if ((event.flags & ChannelPresent) && event.channel == 149)
            saturatingIncrement(channel149Count_);
        if (queryDoorbellUs_ && event.monotonicUs >= queryDoorbellUs_ &&
            event.monotonicUs <= queryDeadlineUs_) {
            if (!queryFirstMpduEntryUs_)
                queryFirstMpduEntryUs_ = event.monotonicUs;
            queryLastMpduEntryUs_ = event.monotonicUs;
            saturatingIncrement(queryMpduEntryCount_);
            saturatingIncrement(queryFrameClassCounts_[frameClass]);
            if (event.flags & AwdlDataCandidate)
                saturatingIncrement(queryAwdlDataCandidateCount_);
            if (!(event.flags & DescriptorPresent))
                saturatingIncrement(queryDescriptorUnavailableCount_);
            if ((event.flags & RawStatusPresent) && !(event.flags & CrcOk))
                saturatingIncrement(queryCrcRejectedCount_);
            if ((event.flags & RawStatusPresent) && !(event.flags & OverrunOk))
                saturatingIncrement(queryOverrunRejectedCount_);
        }
        if (!firstMpduEntryUs_)
            firstMpduEntryUs_ = event.monotonicUs;
        lastMpduEntryUs_ = event.monotonicUs;
        lastUs_ = event.monotonicUs;
        if (eventCount_ == kEventCapacity) {
            overflow_ = 1;
            return UINT32_MAX;
        }
        MpduEvent stored = event;
        stored.ordinal = static_cast<uint32_t>(mpduEntryCount_);
        const uint32_t slot = eventCount_++;
        events_[slot] = stored;
        return slot;
    }

    bool recordDataRoute(const Epochs &epochs, uint32_t driverGeneration,
                         uint32_t slot, DataRoute route, uint64_t nowUs)
    {
        if (!current(epochs, driverGeneration, nowUs) ||
            slot >= eventCount_ || route == DataRoute::NotRecorded ||
            static_cast<uint32_t>(route) >
                static_cast<uint32_t>(DataRoute::DuplicateRetry))
            return false;
        MpduEvent &event = events_[slot];
        if (event.flags & DataRouteRecorded || nowUs < event.monotonicUs)
            return false;
        event.flags |= DataRouteRecorded;
        event.dataRoute = route;
        switch (route) {
        case DataRoute::PassToSta:
            saturatingIncrement(routePassToStaCount_);
            break;
        case DataRoute::QueuedForNative:
            saturatingIncrement(routeQueuedForNativeCount_);
            break;
        case DataRoute::DuplicateRetry:
            saturatingIncrement(routeDuplicateRetryCount_);
            break;
        case DataRoute::NotRecorded:
            return false;
        }
        lastUs_ = nowUs;
        return true;
    }

    bool close(const Epochs &epochs, uint32_t driverGeneration,
               uint64_t endUs, const BridgeCounters &bridgeAfter)
    {
        if (!current(epochs, driverGeneration, endUs) ||
            endUs < startUs_ || endUs < lastUs_) {
            if (state_ == State::Active)
                invalidate(CloseReason::InvalidTimeline, endUs);
            return false;
        }
        if (!bridgeCountersNotDecreased(bridgeBefore_, bridgeAfter)) {
            invalidate(CloseReason::BridgeCounterReversed, endUs);
            return false;
        }
        endUs_ = endUs;
        lastUs_ = endUs;
        bridgeAfter_ = bridgeAfter;
        closeReason_ = CloseReason::CanonicalRocEnd;
        state_ = State::Closed;
        return true;
    }

    bool invalidate(CloseReason reason, uint64_t nowUs)
    {
        if (state_ != State::Active || reason == CloseReason::None ||
            reason == CloseReason::CanonicalRocEnd)
            return false;
        closeReason_ = reason;
        endUs_ = nowUs < lastUs_ ? lastUs_ : nowUs;
        state_ = State::Invalid;
        return true;
    }

    bool snapshot(Snapshot *out) const
    {
        if (!out || (state_ != State::Closed && state_ != State::Invalid))
            return false;
        __builtin_memset(out, 0, sizeof(*out));
        out->schemaVersion = kSchemaVersion;
        out->state = state_;
        out->closeReason = closeReason_;
        out->valid = state_ == State::Closed ? 1u : 0u;
        out->complete = overflow_ == 0 ? 1u : 0u;
        out->overflow = overflow_;
        out->driverGeneration = driverGeneration_;
        out->epochs = epochs_;
        out->startUs = startUs_;
        out->endUs = endUs_;
        out->firstMpduEntryUs = firstMpduEntryUs_;
        out->lastMpduEntryUs = lastMpduEntryUs_;
        out->mpduEntryCount = mpduEntryCount_;
        for (uint32_t i = 0;
             i < static_cast<uint32_t>(FrameClass::Count); ++i)
            out->frameClassCounts[i] = frameClassCounts_[i];
        out->awdlDataCandidateCount = awdlDataCandidateCount_;
        out->leaseQualifiedCount = leaseQualifiedCount_;
        out->leaseUnqualifiedCount = leaseUnqualifiedCount_;
        out->descriptorUnavailableCount = descriptorUnavailableCount_;
        out->crcRejectedCount = crcRejectedCount_;
        out->overrunRejectedCount = overrunRejectedCount_;
        out->channel149Count = channel149Count_;
        out->routePassToStaCount = routePassToStaCount_;
        out->routeQueuedForNativeCount = routeQueuedForNativeCount_;
        out->routeDuplicateRetryCount = routeDuplicateRetryCount_;
        out->queryResponseObserved = queryDoorbellUs_ != 0 ? 1u : 0u;
        out->queryResponseComplete = state_ == State::Closed &&
            queryDoorbellUs_ != 0 && endUs_ >= queryDeadlineUs_ ? 1u : 0u;
        out->queryDoorbellUs = queryDoorbellUs_;
        out->queryDeadlineUs = queryDeadlineUs_;
        out->queryFirstMpduEntryUs = queryFirstMpduEntryUs_;
        out->queryLastMpduEntryUs = queryLastMpduEntryUs_;
        out->queryMpduEntryCount = queryMpduEntryCount_;
        out->queryAwdlDataCandidateCount = queryAwdlDataCandidateCount_;
        out->queryCrcRejectedCount = queryCrcRejectedCount_;
        out->queryOverrunRejectedCount = queryOverrunRejectedCount_;
        out->queryDescriptorUnavailableCount =
            queryDescriptorUnavailableCount_;
        for (uint32_t i = 0;
             i < static_cast<uint32_t>(FrameClass::Count); ++i)
            out->queryFrameClassCounts[i] = queryFrameClassCounts_[i];
        for (uint32_t i = 0;
             i < static_cast<uint32_t>(ServiceEvent::Count); ++i)
            out->service[i] = service_[i];
        out->bridgeBefore = bridgeBefore_;
        out->bridgeAfter = bridgeAfter_;
        out->eventCount = eventCount_;
        for (uint32_t i = 0; i < eventCount_; ++i)
            out->events[i] = events_[i];
        return true;
    }

private:
    bool current(const Epochs &epochs, uint32_t driverGeneration,
                 uint64_t nowUs)
    {
        if (state_ != State::Active)
            return false;
        if (driverGeneration != driverGeneration_) {
            invalidate(CloseReason::DriverGenerationMismatch, nowUs);
            return false;
        }
        if (!sameEpochs(epochs_, epochs)) {
            invalidate(CloseReason::EpochMismatch, nowUs);
            return false;
        }
        if (nowUs < startUs_ || nowUs < lastUs_) {
            invalidate(CloseReason::InvalidTimeline, nowUs);
            return false;
        }
        return true;
    }

    static void saturatingIncrement(uint64_t &value)
    {
        if (value != UINT64_MAX)
            ++value;
    }

    void zeroFrameCounts()
    {
        for (uint32_t i = 0;
             i < static_cast<uint32_t>(FrameClass::Count); ++i)
            frameClassCounts_[i] = 0;
        for (uint32_t i = 0;
             i < static_cast<uint32_t>(ServiceEvent::Count); ++i)
            service_[i] = ServiceEvidence{};
    }

    State state_;
    CloseReason closeReason_;
    bool started_;
    uint32_t driverGeneration_;
    Epochs epochs_;
    uint64_t startUs_;
    uint64_t endUs_;
    uint64_t lastUs_;
    uint64_t firstMpduEntryUs_;
    uint64_t lastMpduEntryUs_;
    uint64_t mpduEntryCount_;
    uint64_t frameClassCounts_[static_cast<uint32_t>(FrameClass::Count)];
    uint64_t awdlDataCandidateCount_;
    uint64_t leaseQualifiedCount_;
    uint64_t leaseUnqualifiedCount_;
    uint64_t descriptorUnavailableCount_;
    uint64_t crcRejectedCount_;
    uint64_t overrunRejectedCount_;
    uint64_t channel149Count_;
    uint64_t routePassToStaCount_;
    uint64_t routeQueuedForNativeCount_;
    uint64_t routeDuplicateRetryCount_;
    uint64_t queryDoorbellUs_;
    uint64_t queryDeadlineUs_;
    uint64_t queryFirstMpduEntryUs_;
    uint64_t queryLastMpduEntryUs_;
    uint64_t queryMpduEntryCount_;
    uint64_t queryAwdlDataCandidateCount_;
    uint64_t queryCrcRejectedCount_;
    uint64_t queryOverrunRejectedCount_;
    uint64_t queryDescriptorUnavailableCount_;
    uint64_t queryFrameClassCounts_[static_cast<uint32_t>(FrameClass::Count)];
    uint32_t overflow_;
    uint32_t eventCount_;
    BridgeCounters bridgeBefore_;
    BridgeCounters bridgeAfter_;
    ServiceEvidence service_[static_cast<uint32_t>(ServiceEvent::Count)];
    MpduEvent events_[kEventCapacity];
};

} // namespace NativeAwdlDiscoveryRxWindow

#endif
