// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_INTEL_P2P_RX_ROUTER_HPP
#define NATIVE_INTEL_P2P_RX_ROUTER_HPP

#include "awdl_action_frame.hpp"

#include <stddef.h>
#include <stdint.h>

namespace IntelP2PRx {

// The receive path only copies fixed-size records. It never owns the mbuf,
// submits firmware commands, allocates, sleeps, or changes the STA path.
constexpr size_t kQueueDepth = 16;
constexpr size_t kMaxActionFrameBytes = 2312; // Local IEEE80211_MAX_LEN.
constexpr size_t kTimeEventNotificationBytes = 24;
constexpr size_t kQueueMemoryLimitBytes = 64 * 1024;
static_assert((kQueueDepth & (kQueueDepth - 1)) == 0,
              "router queue depth must be a power of two");

enum class RouteResult : uint8_t {
    kCapturedExact,
    kCapturedProvisionalUid,
    kCapturedUnknownContext,
    kInactive,
    kNotSubmitted,
    kStaleGeneration,
    kForeignMacContext,
    kForeignUid,
    kProtectedFrame,
    kNotAwdlAction,
    kMalformed,
    kTooLarge,
    kQueueFull
};

enum class RecordKind : uint8_t { kTimeEvent, kActionFrame };
enum class TimeEventAction : uint8_t { kHostStart, kHostEnd, kOther };
enum class UidCorrelation : uint8_t { kKnownExact, kLearnCandidate };
enum class RxMacAffinity : uint8_t { kContextUnknown, kP2pDevice };

// The driver builds this snapshot from its AWDL context and current runtime
// epochs immediately before routing. A raw TIME_EVENT notification has no
// generation field, so the three epoch comparisons fence stale callbacks;
// the generation attached to a captured record is this context generation.
struct LeaseSnapshot {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t currentContextGeneration;
    uint64_t currentPowerGeneration;
    uint64_t currentStationGeneration;
    uint32_t macIdAndColor;
    uint32_t timeEventUid;
    bool active;
    bool timeEventSubmitted;
    bool timeEventUidKnown;
};

struct TimeEventRecord {
    uint64_t generation;
    uint32_t timestamp;
    uint32_t sessionId;
    uint32_t uniqueId;
    uint32_t macIdAndColor;
    uint32_t rawAction;
    uint32_t rawStatus;
    TimeEventAction action;
    UidCorrelation uidCorrelation;
};

struct ActionFrameRecord {
    uint64_t generation;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rxMonotonicUs;
    // Raw GP2 value from the RX descriptor at on-air rise. This is a separate
    // device-clock domain and is never used as a host/peer mapping witness.
    uint32_t rxGp2TimestampUs;
    uint32_t rxMacIdAndColor;
    uint16_t channel;
    uint16_t length;
    RxMacAffinity affinity;
    bool rxGp2TimestampPresent;
    NativeAwdl::ActionFrameInfo awdl;
    uint8_t bytes[kMaxActionFrameBytes];
};

struct Record {
    RecordKind kind;
    union {
        TimeEventRecord timeEvent;
        ActionFrameRecord actionFrame;
    } payload;
};

static_assert(sizeof(Record) * kQueueDepth <= kQueueMemoryLimitBytes,
              "router record storage must remain below 64 KiB");

struct Counters {
    uint32_t timeEventCaptured;
    uint32_t actionFrameCaptured;
    uint32_t actionGp2TimestampPresentCount;
    uint32_t lastActionGp2TimestampUs;
    uint32_t lastActionGp2TimestampPresent;
    uint32_t actionEnvelopeSeen;
    uint32_t actionParseRejected;
    uint32_t lastActionParseStatus;
    uint32_t actionRejectReason;
    uint32_t actionSubtype;
    uint32_t actionRxChannel;
    uint32_t actionTlvType;
    uint32_t actionTlvExpectedType;
    uint32_t actionTlvDeclaredLen;
    uint32_t actionTlvAvailableLen;
    uint32_t actionTlvOffset;
    uint32_t actionSeenMask;
    uint32_t actionRequiredMask;
    uint32_t actionTraceCount;
    uint64_t actionTypeTraceLo;
    uint64_t actionTypeTraceHi;
    uint32_t actionDataPathFlags;
    uint32_t actionDataPathExtFlags;
    uint32_t actionDataPathOptionsLength;
    uint32_t actionDataPathOffset;
    uint32_t actionDataPathFlagsPresent;
    uint32_t actionDataPathExtFlagsPresent;
    uint32_t actionDataPathOptionsLengthPresent;
    uint32_t actionDataPathRejectStage;
    uint32_t provisionalUid;
    uint32_t protectedActionRejected;
    uint32_t malformedOrForeign;
    uint32_t tooLarge;
    uint32_t queueFull;
};

class Router {
public:
    Router();

    // Called as a side-effect in the existing TIME_EVENT_NOTIFICATION path.
    // It copies only an exact 24-byte event matching this P2P MAC context.
    // rawStatus is recorded without assigning success/failure semantics.
    // A missing UID is explicitly provisional; UID 0 is valid when uidKnown.
    RouteResult captureTimeEvent(const uint8_t *raw, size_t length,
                                 const LeaseSnapshot &lease);

    // Called after the driver has validated the MPDU and before net80211 input.
    // It copies a parsed, public AWDL PSF/MIF Action frame into a bounded queue.
    // Unknown RX MAC context remains unknown; the caller must not infer P2P
    // ownership from a valid AWDL body alone. This is a tap, never a consume.
    RouteResult tapActionFrame(const uint8_t *frame, size_t length,
                               bool protectedBeforeDecap, uint16_t channel,
                               bool rxMacContextKnown,
                               uint32_t rxMacIdAndColor,
                               const LeaseSnapshot &lease,
                               uint64_t rxMonotonicUs = 0,
                               uint32_t rxGp2TimestampUs = 0,
                               bool rxGp2TimestampPresent = false);

    // Single-producer (the serialized RX dispatcher), single-consumer queue.
    bool popRecord(Record *record);
    void readCounters(Counters *out) const;

private:
    bool push(const Record &record);
    static bool hasCurrentLease(const LeaseSnapshot &lease);

    Record records_[kQueueDepth];
    uint32_t producer_;
    uint32_t consumer_;
    uint32_t timeEventCaptured_;
    uint32_t actionFrameCaptured_;
    uint32_t actionGp2TimestampPresentCount_;
    uint32_t lastActionGp2TimestampUs_;
    uint32_t lastActionGp2TimestampPresent_;
    uint32_t actionEnvelopeSeen_;
    uint32_t actionParseRejected_;
    uint32_t lastActionParseStatus_;
    uint32_t actionRejectReason_;
    uint32_t actionSubtype_;
    uint32_t actionRxChannel_;
    uint32_t actionTlvType_;
    uint32_t actionTlvExpectedType_;
    uint32_t actionTlvDeclaredLen_;
    uint32_t actionTlvAvailableLen_;
    uint32_t actionTlvOffset_;
    uint32_t actionSeenMask_;
    uint32_t actionRequiredMask_;
    uint32_t actionTraceCount_;
    uint64_t actionTypeTraceLo_;
    uint64_t actionTypeTraceHi_;
    uint32_t actionDataPathFlags_;
    uint32_t actionDataPathExtFlags_;
    uint32_t actionDataPathOptionsLength_;
    uint32_t actionDataPathOffset_;
    uint32_t actionDataPathFlagsPresent_;
    uint32_t actionDataPathExtFlagsPresent_;
    uint32_t actionDataPathOptionsLengthPresent_;
    uint32_t actionDataPathRejectStage_;
    uint32_t provisionalUid_;
    uint32_t protectedActionRejected_;
    uint32_t malformedOrForeign_;
    uint32_t tooLarge_;
    uint32_t queueFull_;
};

static_assert(sizeof(Router) <= kQueueMemoryLimitBytes,
              "router object must remain below 64 KiB");

} // namespace IntelP2PRx

#endif // NATIVE_INTEL_P2P_RX_ROUTER_HPP
