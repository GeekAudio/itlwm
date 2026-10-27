// SPDX-License-Identifier: GPL-2.0-only
#include "intel_p2p_rx_router.hpp"

#include <string.h>

namespace IntelP2PRx {
namespace {

constexpr uint32_t kHostEventStart = 1u << 0;
constexpr uint32_t kHostEventEnd = 1u << 1;

bool hasAwdlEnvelope(const uint8_t *frame, size_t length)
{
    if (!frame || length < 24 || (frame[0] & 0xfc) != 0xd0)
        return false;
    const size_t header = 24 + ((frame[1] & 0x80) ? 4 : 0);
    if (length < header + 5)
        return false;
    const uint8_t *body = frame + header;
    return body[0] == 127 && body[1] == 0x00 && body[2] == 0x17 &&
           body[3] == 0xf2 && body[4] == 8;
}

uint32_t readLe32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

} // namespace

Router::Router()
    : producer_(0), consumer_(0), timeEventCaptured_(0),
      actionFrameCaptured_(0), actionGp2TimestampPresentCount_(0),
      lastActionGp2TimestampUs_(0), lastActionGp2TimestampPresent_(0),
      actionEnvelopeSeen_(0), actionParseRejected_(0),
      lastActionParseStatus_(UINT32_MAX),
      actionRejectReason_(0),
      actionSubtype_(0),
      actionRxChannel_(0),
      actionTlvType_(0),
      actionTlvExpectedType_(0),
      actionTlvDeclaredLen_(0),
      actionTlvAvailableLen_(0),
      actionTlvOffset_(0),
      actionSeenMask_(0),
      actionRequiredMask_(0),
      actionTraceCount_(0),
      actionTypeTraceLo_(0),
      actionTypeTraceHi_(0),
      actionDataPathFlags_(0),
      actionDataPathExtFlags_(0),
      actionDataPathOptionsLength_(0),
      actionDataPathOffset_(0),
      actionDataPathFlagsPresent_(0),
      actionDataPathExtFlagsPresent_(0),
      actionDataPathOptionsLengthPresent_(0),
      actionDataPathRejectStage_(0),
      provisionalUid_(0),
      protectedActionRejected_(0), malformedOrForeign_(0), tooLarge_(0),
      queueFull_(0)
{
}

bool Router::hasCurrentLease(const LeaseSnapshot &lease)
{
    return lease.active &&
           lease.contextGeneration == lease.currentContextGeneration &&
           lease.powerGeneration == lease.currentPowerGeneration &&
           lease.stationGeneration == lease.currentStationGeneration;
}

RouteResult Router::captureTimeEvent(const uint8_t *raw, size_t length,
                                     const LeaseSnapshot &lease)
{
    if (!lease.active)
        return RouteResult::kInactive;
    if (!hasCurrentLease(lease))
        return RouteResult::kStaleGeneration;
    if (!lease.timeEventSubmitted)
        return RouteResult::kNotSubmitted;
    if (!raw || length != kTimeEventNotificationBytes) {
        __atomic_fetch_add(&malformedOrForeign_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kMalformed;
    }

    const uint32_t uid = readLe32(raw + 8);
    const uint32_t macIdAndColor = readLe32(raw + 12);
    if (macIdAndColor != lease.macIdAndColor) {
        __atomic_fetch_add(&malformedOrForeign_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kForeignMacContext;
    }
    if (lease.timeEventUidKnown && uid != lease.timeEventUid) {
        __atomic_fetch_add(&malformedOrForeign_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kForeignUid;
    }

    Record record{};
    record.kind = RecordKind::kTimeEvent;
    record.payload.timeEvent.generation = lease.contextGeneration;
    record.payload.timeEvent.timestamp = readLe32(raw + 0);
    record.payload.timeEvent.sessionId = readLe32(raw + 4);
    record.payload.timeEvent.uniqueId = uid;
    record.payload.timeEvent.macIdAndColor = macIdAndColor;
    record.payload.timeEvent.rawAction = readLe32(raw + 16);
    record.payload.timeEvent.rawStatus = readLe32(raw + 20);
    if (record.payload.timeEvent.rawAction == kHostEventStart)
        record.payload.timeEvent.action = TimeEventAction::kHostStart;
    else if (record.payload.timeEvent.rawAction == kHostEventEnd)
        record.payload.timeEvent.action = TimeEventAction::kHostEnd;
    else
        record.payload.timeEvent.action = TimeEventAction::kOther;
    record.payload.timeEvent.uidCorrelation = lease.timeEventUidKnown
        ? UidCorrelation::kKnownExact : UidCorrelation::kLearnCandidate;

    if (!push(record)) {
        __atomic_fetch_add(&queueFull_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kQueueFull;
    }
    __atomic_fetch_add(&timeEventCaptured_, 1u, __ATOMIC_RELAXED);
    if (!lease.timeEventUidKnown) {
        __atomic_fetch_add(&provisionalUid_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kCapturedProvisionalUid;
    }
    return RouteResult::kCapturedExact;
}

RouteResult Router::tapActionFrame(const uint8_t *frame, size_t length,
                                   bool protectedBeforeDecap,
                                   uint16_t channel,
                                   bool rxMacContextKnown,
                                   uint32_t rxMacIdAndColor,
                                   const LeaseSnapshot &lease,
                                   uint64_t rxMonotonicUs,
                                   uint32_t rxGp2TimestampUs,
                                   bool rxGp2TimestampPresent)
{
    if (!lease.active)
        return RouteResult::kInactive;
    if (!hasCurrentLease(lease))
        return RouteResult::kStaleGeneration;
    if (protectedBeforeDecap) {
        __atomic_fetch_add(&protectedActionRejected_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kProtectedFrame;
    }
    if (!frame || !length) {
        __atomic_fetch_add(&malformedOrForeign_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kMalformed;
    }
    if (length > kMaxActionFrameBytes) {
        __atomic_fetch_add(&tooLarge_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kTooLarge;
    }

    const bool envelope = hasAwdlEnvelope(frame, length);
    if (envelope)
        __atomic_fetch_add(&actionEnvelopeSeen_, 1u, __ATOMIC_RELAXED);
    NativeAwdl::ActionFrameInfo info{};
    NativeAwdl::ParseDiagnostics diagnostic{};
    const NativeAwdl::ParseStatus parse =
        NativeAwdl::parseActionFrame(frame, length, &info, &diagnostic);
    if (parse == NativeAwdl::ParseStatus::ProtectedAction) {
        __atomic_fetch_add(&protectedActionRejected_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kProtectedFrame;
    }
    if (parse != NativeAwdl::ParseStatus::Ok) {
        if (envelope) {
            __atomic_fetch_add(&actionParseRejected_, 1u, __ATOMIC_RELAXED);
            __atomic_store_n(&lastActionParseStatus_, static_cast<uint32_t>(parse),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionRejectReason_, static_cast<uint32_t>(diagnostic.reason),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionSubtype_, static_cast<uint32_t>(diagnostic.subtype),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionRxChannel_, static_cast<uint32_t>(channel),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTlvType_, static_cast<uint32_t>(diagnostic.tlvType),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTlvExpectedType_, static_cast<uint32_t>(diagnostic.expectedType),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTlvDeclaredLen_, static_cast<uint32_t>(diagnostic.declaredLen),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTlvAvailableLen_, static_cast<uint32_t>(diagnostic.availableLen),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTlvOffset_, static_cast<uint32_t>(diagnostic.tlvOffset),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionSeenMask_, static_cast<uint32_t>(diagnostic.seenMask),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionRequiredMask_, static_cast<uint32_t>(diagnostic.requiredMask),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTraceCount_, static_cast<uint32_t>(diagnostic.traceCount),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTypeTraceLo_, static_cast<uint64_t>(diagnostic.tlvTypeTraceLo),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionTypeTraceHi_, static_cast<uint64_t>(diagnostic.tlvTypeTraceHi),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathFlags_, static_cast<uint32_t>(diagnostic.dataPathFlags),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathExtFlags_, static_cast<uint32_t>(diagnostic.dataPathExtFlags),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathOptionsLength_, static_cast<uint32_t>(diagnostic.dataPathOptionsLength),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathOffset_, static_cast<uint32_t>(diagnostic.dataPathOffset),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathFlagsPresent_, static_cast<uint32_t>(diagnostic.dataPathFlagsPresent),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathExtFlagsPresent_, static_cast<uint32_t>(diagnostic.dataPathExtFlagsPresent),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathOptionsLengthPresent_, static_cast<uint32_t>(diagnostic.dataPathOptionsLengthPresent),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&actionDataPathRejectStage_, static_cast<uint32_t>(diagnostic.dataPathRejectStage),
                             __ATOMIC_RELAXED);
        }
        return RouteResult::kNotAwdlAction;
    }

    if (rxMacContextKnown && rxMacIdAndColor != lease.macIdAndColor) {
        __atomic_fetch_add(&malformedOrForeign_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kForeignMacContext;
    }

    Record record{};
    record.kind = RecordKind::kActionFrame;
    ActionFrameRecord &out = record.payload.actionFrame;
    out.generation = lease.contextGeneration;
    out.powerGeneration = lease.powerGeneration;
    out.stationGeneration = lease.stationGeneration;
    out.rxMonotonicUs = rxMonotonicUs;
    out.rxGp2TimestampUs = rxGp2TimestampPresent ? rxGp2TimestampUs : 0;
    out.rxGp2TimestampPresent = rxGp2TimestampPresent;
    out.rxMacIdAndColor = rxMacContextKnown ? rxMacIdAndColor : 0;
    out.channel = channel;
    out.length = static_cast<uint16_t>(length);
    out.affinity = rxMacContextKnown
        ? RxMacAffinity::kP2pDevice : RxMacAffinity::kContextUnknown;
    out.awdl = info;
    memcpy(out.bytes, frame, length);

    __atomic_store_n(&lastActionGp2TimestampUs_,
                     rxGp2TimestampPresent ? rxGp2TimestampUs : 0,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&lastActionGp2TimestampPresent_,
                     rxGp2TimestampPresent ? 1u : 0u, __ATOMIC_RELAXED);
    if (rxGp2TimestampPresent)
        __atomic_fetch_add(&actionGp2TimestampPresentCount_, 1u,
                           __ATOMIC_RELAXED);

    if (!push(record)) {
        __atomic_fetch_add(&queueFull_, 1u, __ATOMIC_RELAXED);
        return RouteResult::kQueueFull;
    }
    __atomic_fetch_add(&actionFrameCaptured_, 1u, __ATOMIC_RELAXED);
    return rxMacContextKnown ? RouteResult::kCapturedExact
                             : RouteResult::kCapturedUnknownContext;
}

bool Router::push(const Record &record)
{
    const uint32_t head = __atomic_load_n(&producer_, __ATOMIC_RELAXED);
    const uint32_t tail = __atomic_load_n(&consumer_, __ATOMIC_ACQUIRE);
    if (head - tail >= kQueueDepth)
        return false;
    records_[head & (kQueueDepth - 1)] = record;
    __atomic_store_n(&producer_, head + 1, __ATOMIC_RELEASE);
    return true;
}

bool Router::popRecord(Record *record)
{
    if (!record)
        return false;
    const uint32_t tail = __atomic_load_n(&consumer_, __ATOMIC_RELAXED);
    const uint32_t head = __atomic_load_n(&producer_, __ATOMIC_ACQUIRE);
    if (tail == head)
        return false;
    *record = records_[tail & (kQueueDepth - 1)];
    // The producer cannot reuse this slot until consumer_ is published.
    // Retain only the consumer's bounded copy, not old peer names/payloads.
    memset(&records_[tail & (kQueueDepth - 1)], 0, sizeof(Record));
    __atomic_store_n(&consumer_, tail + 1, __ATOMIC_RELEASE);
    return true;
}

void Router::readCounters(Counters *out) const
{
    if (!out)
        return;
    out->timeEventCaptured = __atomic_load_n(&timeEventCaptured_, __ATOMIC_RELAXED);
    out->actionFrameCaptured = __atomic_load_n(&actionFrameCaptured_, __ATOMIC_RELAXED);
    out->actionGp2TimestampPresentCount = __atomic_load_n(
        &actionGp2TimestampPresentCount_, __ATOMIC_RELAXED);
    out->lastActionGp2TimestampUs = __atomic_load_n(
        &lastActionGp2TimestampUs_, __ATOMIC_RELAXED);
    out->lastActionGp2TimestampPresent = __atomic_load_n(
        &lastActionGp2TimestampPresent_, __ATOMIC_RELAXED);
    out->actionEnvelopeSeen = __atomic_load_n(&actionEnvelopeSeen_, __ATOMIC_RELAXED);
    out->actionParseRejected = __atomic_load_n(&actionParseRejected_, __ATOMIC_RELAXED);
    out->lastActionParseStatus = __atomic_load_n(&lastActionParseStatus_, __ATOMIC_RELAXED);
    out->actionRejectReason = __atomic_load_n(&actionRejectReason_, __ATOMIC_RELAXED);
    out->actionSubtype = __atomic_load_n(&actionSubtype_, __ATOMIC_RELAXED);
    out->actionRxChannel = __atomic_load_n(&actionRxChannel_, __ATOMIC_RELAXED);
    out->actionTlvType = __atomic_load_n(&actionTlvType_, __ATOMIC_RELAXED);
    out->actionTlvExpectedType = __atomic_load_n(&actionTlvExpectedType_, __ATOMIC_RELAXED);
    out->actionTlvDeclaredLen = __atomic_load_n(&actionTlvDeclaredLen_, __ATOMIC_RELAXED);
    out->actionTlvAvailableLen = __atomic_load_n(&actionTlvAvailableLen_, __ATOMIC_RELAXED);
    out->actionTlvOffset = __atomic_load_n(&actionTlvOffset_, __ATOMIC_RELAXED);
    out->actionSeenMask = __atomic_load_n(&actionSeenMask_, __ATOMIC_RELAXED);
    out->actionRequiredMask = __atomic_load_n(&actionRequiredMask_, __ATOMIC_RELAXED);
    out->actionTraceCount = __atomic_load_n(&actionTraceCount_, __ATOMIC_RELAXED);
    out->actionTypeTraceLo = __atomic_load_n(&actionTypeTraceLo_, __ATOMIC_RELAXED);
    out->actionTypeTraceHi = __atomic_load_n(&actionTypeTraceHi_, __ATOMIC_RELAXED);
    out->actionDataPathFlags = __atomic_load_n(&actionDataPathFlags_, __ATOMIC_RELAXED);
    out->actionDataPathExtFlags = __atomic_load_n(&actionDataPathExtFlags_, __ATOMIC_RELAXED);
    out->actionDataPathOptionsLength = __atomic_load_n(&actionDataPathOptionsLength_, __ATOMIC_RELAXED);
    out->actionDataPathOffset = __atomic_load_n(&actionDataPathOffset_, __ATOMIC_RELAXED);
    out->actionDataPathFlagsPresent = __atomic_load_n(&actionDataPathFlagsPresent_, __ATOMIC_RELAXED);
    out->actionDataPathExtFlagsPresent = __atomic_load_n(&actionDataPathExtFlagsPresent_, __ATOMIC_RELAXED);
    out->actionDataPathOptionsLengthPresent = __atomic_load_n(&actionDataPathOptionsLengthPresent_, __ATOMIC_RELAXED);
    out->actionDataPathRejectStage = __atomic_load_n(&actionDataPathRejectStage_, __ATOMIC_RELAXED);
    out->provisionalUid = __atomic_load_n(&provisionalUid_, __ATOMIC_RELAXED);
    out->protectedActionRejected =
        __atomic_load_n(&protectedActionRejected_, __ATOMIC_RELAXED);
    out->malformedOrForeign = __atomic_load_n(&malformedOrForeign_, __ATOMIC_RELAXED);
    out->tooLarge = __atomic_load_n(&tooLarge_, __ATOMIC_RELAXED);
    out->queueFull = __atomic_load_n(&queueFull_, __ATOMIC_RELAXED);
}

} // namespace IntelP2PRx
