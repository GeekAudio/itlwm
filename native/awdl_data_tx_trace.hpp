// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DATA_TX_TRACE_HPP
#define NATIVE_AWDL_DATA_TX_TRACE_HPP

#include <stddef.h>
#include <stdint.h>

// Address-free, fixed-capacity evidence for one native AWDL DATA MPDU moving
// from the BSD queue into the Intel TX ring. Ledger mutation is main-gate only.
// Cross-context callbacks use bounded atomic taps only; they never mutate the
// ordinary ledger, wait, allocate, or touch IOKit.
namespace NativeAwdlDataTxTrace {

constexpr size_t kRecordCapacity = 8;

enum Stage : uint32_t {
    kQueueBorn = 1u << 0,
    kDequeued = 1u << 1,
    kSubmitCallStart = 1u << 2,
    kFinalWire = 1u << 3,
    kRingReserved = 1u << 4,
    kDescriptorReady = 1u << 5,
    kDoorbellMarked = 1u << 6,
    kDoorbellIssued = 1u << 7,
    kTxResponseTap = 1u << 8,
    kCompletion = 1u << 9,
    kCancel = 1u << 10,
    kSubmitCallEnd = 1u << 11,
    kUnknown = 1u << 12,
    kEncodeFailure = 1u << 13,
    kStopObserved = 1u << 14
};

enum class AssociationStrength : uint32_t {
    None = 0,
    CandidateOnly = 1,
    LocalScalarFieldsMatch = 2,
    ExistingHandlerAccepted = 3
};

enum ResponseField : uint32_t {
    kResponseQueueValid = 1u << 0,
    // Raw RX command-header metadata, not a TX descriptor identity.
    kResponseRxHeaderIndexValid = 1u << 1,
    kResponseSequenceValid = 1u << 2,
    kResponseByteCountValid = 1u << 3,
    kResponseFrameControlValid = 1u << 4,
    kResponseStatusValid = 1u << 5,
    kResponseRaTidValid = 1u << 6,
    kResponseScdSsnValid = 1u << 7
};

enum ResponseMismatch : uint32_t {
    kMismatchGeneration = 1u << 0,
    kMismatchQueue = 1u << 1,
    kMismatchRxHeaderIndexReserved = 1u << 2,
    kMismatchSequence = 1u << 3,
    kMismatchByteCount = 1u << 4,
    kMismatchFrameControl = 1u << 5,
    kMissingResponseField = 1u << 6
};

enum class Status : uint8_t {
    Ready,
    InvalidIdentity,
    DuplicateToken,
    TokenIdentityConflict,
    ActiveTokenExists,
    CapacityFull,
    NoRecord,
    StaleToken,
    StaleGeneration,
    DuplicateStage,
    OutOfOrder,
    Terminal,
    Irreversible,
    ResponseTapBusy,
    ResponseTapUnstable
};

// Async tap state is separate from ledger revision: a callback may publish a
// tap while the main gate is serializing an otherwise stable ledger snapshot.
// EmptyOrConsumed includes the initial (sequence=0, consumed=0) state.
enum class TapPublicationState : uint32_t {
    EmptyOrConsumed = 0,
    Pending = 1,
    Unstable = 2
};

struct TapPublicationSnapshot {
    uint64_t sequence;
    uint64_t consumedSequence;
    uint64_t droppedCount;
    uint64_t activePublicationSequence;
    uint64_t activeToken;
    TapPublicationState state;
};

struct Identity {
    uint64_t token;
    uint64_t diagnosticGeneration;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
};

struct PublicationSnapshot {
    TapPublicationSnapshot txResponse;
    TapPublicationSnapshot stop;
    uint64_t revision;
    Identity owner;
    bool ownerPresent;
    bool revisionStable;
    bool coverageUnknown;
};

struct TxResponseTap {
    Identity identity;
    uint64_t observedAtUs;
    uint32_t validFields;
    uint16_t queueId;
    uint16_t rxHeaderIndex;
    uint16_t sequenceControl;
    uint16_t byteCount;
    uint16_t frameControl;
    uint16_t status;
    uint16_t raTid;
    uint16_t scdSsn;
    uint64_t recordSerial;
    uint16_t expectedQueueId;
    uint16_t expectedDescriptorIndex;
    uint16_t expectedSequenceControl;
    uint16_t expectedByteCount;
    uint16_t expectedFrameControl;
};

struct StopTap {
    uint64_t token;
    uint64_t observedAtUs;
    uint32_t newGeneration;
    uint32_t reason;
    bool provenDrain;
};

struct RecordSnapshot {
    bool present;
    Identity identity;
    uint64_t recordSerial;
    uint32_t stageMask;
    uint8_t queryClass;
    bool queueEligible;
    bool queueMetadataPresent;
    uint64_t queueBornUs;
    uint64_t dequeuedUs;
    uint64_t submitCallStartUs;
    uint64_t submitCallEndUs;
    uint64_t finalWireUs;
    uint64_t ringReservedUs;
    uint64_t descriptorReadyUs;
    uint64_t doorbellMarkedUs;
    uint64_t doorbellIssuedUs;
    uint64_t txRspTapUs;
    uint64_t completionUs;
    uint64_t cancelUs;
    uint64_t unknownUs;
    uint64_t encodeFailureUs;
    uint64_t stopUs;
    uint16_t frameControl;
    uint16_t sequenceControl;
    uint16_t mpduLength;
    uint16_t packetCount;
    uint32_t ipv6Length;
    uint16_t queueId;
    uint16_t ringSize;
    uint16_t descriptorIndex;
    uint16_t txRspQueueId;
    uint16_t txRspRxHeaderIndex;
    uint16_t txRspSequenceControl;
    uint16_t txRspByteCount;
    uint16_t txRspFrameControl;
    uint16_t txRspStatus;
    uint16_t txRspRaTid;
    uint16_t txRspScdSsn;
    uint32_t txRspValidFields;
    uint32_t submitCallResult;
    uint32_t completionResult;
    uint32_t cancellationReason;
    uint32_t unknownReason;
    uint32_t encodeFailureResult;
    uint32_t stopNewGeneration;
    uint32_t stopReason;
    uint32_t responseMismatchMask;
    uint32_t responseScalarMatchMask;
    uint32_t associationStrength;
    uint32_t txRspHandlerDisposition;
    bool firmwareEchoesFullIdentity;
    bool ambiguousLateQueueUnknown;
    bool responseCandidateSeen;
    bool stopProvenDrain;
};

struct AtomicIdentity {
    uint64_t token;
    uint64_t diagnosticGeneration;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
};

// TX_RSP may be observed outside the main work-loop gate. This bounded tap
// captures numeric fields only; a main-gate caller later merges and validates
// it against the immutable ledger identity and TX descriptor scalars.
class AtomicTxResponseTap {
public:
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    using CaptureInterleaveHook = void (*)(void *);
#endif

    AtomicTxResponseTap()
        : sequence_(0), activePublication_(0), activeToken_(0), activeDiagnosticGeneration_(0),
          activeContextGeneration_(0), activePowerGeneration_(0),
          activeStationGeneration_(0), activeRocGeneration_(0),
          activeRecordSerial_(0), activeQueueId_(0), activeDescriptorIndex_(0),
          activeSequenceControl_(0), activeByteCount_(0), activeFrameControl_(0),
          tapToken_(0), tapDiagnosticGeneration_(0), tapContextGeneration_(0),
          tapPowerGeneration_(0), tapStationGeneration_(0), tapRocGeneration_(0),
          tapRecordSerial_(0), tapExpectedQueueId_(0), tapExpectedDescriptorIndex_(0),
          tapExpectedSequenceControl_(0), tapExpectedByteCount_(0),
          tapExpectedFrameControl_(0),
          observedAtUs_(0), validFields_(0), queueId_(0), rxHeaderIndex_(0),
          sequenceControl_(0), byteCount_(0), frameControl_(0), status_(0),
          raTid_(0), scdSsn_(0), captureDropCount_(0), consumedSequence_(0)
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
          , testCaptureHook_(nullptr), testCaptureHookContext_(nullptr)
#endif
          {}

#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    void setCaptureInterleaveHookForTesting(CaptureInterleaveHook hook,
                                            void *context)
    {
        testCaptureHook_ = hook;
        testCaptureHookContext_ = context;
    }
#endif

    void setActiveTicket(const Identity &identity, uint64_t recordSerial,
                         uint16_t queueId, uint16_t descriptorIndex,
                         uint16_t sequenceControl, uint16_t byteCount,
                         uint16_t frameControl)
    {
        __atomic_add_fetch(&activePublication_, uint64_t(1), __ATOMIC_RELEASE);
        __atomic_store_n(&activeDiagnosticGeneration_,
                         identity.diagnosticGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&activeContextGeneration_, identity.contextGeneration,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&activePowerGeneration_, identity.powerGeneration,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&activeStationGeneration_, identity.stationGeneration,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&activeRocGeneration_, identity.rocGeneration,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&activeRecordSerial_, recordSerial, __ATOMIC_RELAXED);
        __atomic_store_n(&activeQueueId_, queueId, __ATOMIC_RELAXED);
        __atomic_store_n(&activeDescriptorIndex_, descriptorIndex, __ATOMIC_RELAXED);
        __atomic_store_n(&activeSequenceControl_, sequenceControl, __ATOMIC_RELAXED);
        __atomic_store_n(&activeByteCount_, byteCount, __ATOMIC_RELAXED);
        __atomic_store_n(&activeFrameControl_, frameControl, __ATOMIC_RELAXED);
        __atomic_store_n(&activeToken_, identity.token, __ATOMIC_RELEASE);
        __atomic_add_fetch(&activePublication_, uint64_t(1), __ATOMIC_RELEASE);
    }

    void clearActiveIdentity(uint64_t token)
    {
        if (__atomic_load_n(&activeToken_, __ATOMIC_ACQUIRE) != token)
            return;
        __atomic_add_fetch(&activePublication_, uint64_t(1), __ATOMIC_RELEASE);
        if (__atomic_load_n(&activeToken_, __ATOMIC_RELAXED) == token)
            __atomic_store_n(&activeToken_, uint64_t(0), __ATOMIC_RELEASE);
        __atomic_add_fetch(&activePublication_, uint64_t(1), __ATOMIC_RELEASE);
    }

    bool capture(uint64_t expectedToken, uint64_t observedAtUs,
                 uint32_t validFields, uint16_t queueId,
                 uint16_t rxHeaderIndex, uint16_t sequenceControl,
                 uint16_t byteCount, uint16_t frameControl, uint16_t status,
                 uint16_t raTid, uint16_t scdSsn)
    {
        const uint64_t active = __atomic_load_n(&activeToken_, __ATOMIC_ACQUIRE);
        if (!expectedToken)
            return false;
        if (active != expectedToken) {
            __atomic_add_fetch(&captureDropCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }

        const uint64_t activeVersion = __atomic_load_n(
            &activePublication_, __ATOMIC_ACQUIRE);
        if (activeVersion & 1u) {
            __atomic_add_fetch(&captureDropCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }
        Identity identity{};
        identity.token = active;
        identity.diagnosticGeneration = __atomic_load_n(
            &activeDiagnosticGeneration_, __ATOMIC_RELAXED);
        identity.contextGeneration = __atomic_load_n(
            &activeContextGeneration_, __ATOMIC_RELAXED);
        identity.powerGeneration = __atomic_load_n(
            &activePowerGeneration_, __ATOMIC_RELAXED);
        identity.stationGeneration = __atomic_load_n(
            &activeStationGeneration_, __ATOMIC_RELAXED);
        identity.rocGeneration = __atomic_load_n(
            &activeRocGeneration_, __ATOMIC_RELAXED);
        const uint64_t recordSerial = __atomic_load_n(
            &activeRecordSerial_, __ATOMIC_RELAXED);
        const uint16_t expectedQueueId = __atomic_load_n(
            &activeQueueId_, __ATOMIC_RELAXED);
        const uint16_t expectedDescriptorIndex = __atomic_load_n(
            &activeDescriptorIndex_, __ATOMIC_RELAXED);
        const uint16_t expectedSequenceControl = __atomic_load_n(
            &activeSequenceControl_, __ATOMIC_RELAXED);
        const uint16_t expectedByteCount = __atomic_load_n(
            &activeByteCount_, __ATOMIC_RELAXED);
        const uint16_t expectedFrameControl = __atomic_load_n(
            &activeFrameControl_, __ATOMIC_RELAXED);
        const uint64_t activeAfterCopy = __atomic_load_n(
            &activePublication_, __ATOMIC_ACQUIRE);
        if (activeAfterCopy != activeVersion || (activeAfterCopy & 1u) ||
            __atomic_load_n(&activeToken_, __ATOMIC_ACQUIRE) != expectedToken) {
            __atomic_add_fetch(&captureDropCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }
        if (queueId != expectedQueueId) {
            __atomic_add_fetch(&captureDropCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }

        uint64_t sequence = __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
        if ((sequence & 1u) || sequence > UINT64_MAX - 2u ||
            sequence != __atomic_load_n(&consumedSequence_, __ATOMIC_ACQUIRE) ||
            !__atomic_compare_exchange_n(&sequence_, &sequence, sequence + 1u,
                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_add_fetch(&captureDropCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }

#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
        if (testCaptureHook_)
            testCaptureHook_(testCaptureHookContext_);
#endif

        // The active token is rechecked after owning the tap. A stop or next
        // submit between the first read and CAS must not bind stale bytes.
        if (__atomic_load_n(&activePublication_, __ATOMIC_ACQUIRE) != activeVersion ||
            __atomic_load_n(&activeToken_, __ATOMIC_ACQUIRE) != expectedToken) {
            // No valid tap was committed. Restore the last consumed serial so
            // the main gate cannot mistake prior scalar bytes for a new event.
            __atomic_store_n(&sequence_, sequence, __ATOMIC_RELEASE);
            __atomic_add_fetch(&captureDropCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }
        __atomic_store_n(&tapToken_, identity.token, __ATOMIC_RELAXED);
        __atomic_store_n(&tapDiagnosticGeneration_, identity.diagnosticGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&tapContextGeneration_, identity.contextGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&tapPowerGeneration_, identity.powerGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&tapStationGeneration_, identity.stationGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&tapRocGeneration_, identity.rocGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&tapRecordSerial_, recordSerial, __ATOMIC_RELAXED);
        __atomic_store_n(&tapExpectedQueueId_, expectedQueueId, __ATOMIC_RELAXED);
        __atomic_store_n(&tapExpectedDescriptorIndex_, expectedDescriptorIndex, __ATOMIC_RELAXED);
        __atomic_store_n(&tapExpectedSequenceControl_, expectedSequenceControl, __ATOMIC_RELAXED);
        __atomic_store_n(&tapExpectedByteCount_, expectedByteCount, __ATOMIC_RELAXED);
        __atomic_store_n(&tapExpectedFrameControl_, expectedFrameControl, __ATOMIC_RELAXED);
        __atomic_store_n(&observedAtUs_, observedAtUs, __ATOMIC_RELAXED);
        __atomic_store_n(&validFields_, validFields, __ATOMIC_RELAXED);
        __atomic_store_n(&queueId_, queueId, __ATOMIC_RELAXED);
        __atomic_store_n(&rxHeaderIndex_, rxHeaderIndex, __ATOMIC_RELAXED);
        __atomic_store_n(&sequenceControl_, sequenceControl, __ATOMIC_RELAXED);
        __atomic_store_n(&byteCount_, byteCount, __ATOMIC_RELAXED);
        __atomic_store_n(&frameControl_, frameControl, __ATOMIC_RELAXED);
        __atomic_store_n(&status_, status, __ATOMIC_RELAXED);
        __atomic_store_n(&raTid_, raTid, __ATOMIC_RELAXED);
        __atomic_store_n(&scdSsn_, scdSsn, __ATOMIC_RELAXED);
        __atomic_store_n(&sequence_, sequence + 2u, __ATOMIC_RELEASE);
        return true;
    }

    bool snapshot(TxResponseTap *output, uint64_t *serial) const
    {
        if (!output || !serial)
            return false;
        for (uint32_t attempt = 0; attempt != 3; ++attempt) {
            const uint64_t before = __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
            if (!before || (before & 1u))
                continue;
            TxResponseTap copy{};
            copy.identity.token = __atomic_load_n(&tapToken_, __ATOMIC_RELAXED);
            copy.identity.diagnosticGeneration = __atomic_load_n(
                &tapDiagnosticGeneration_, __ATOMIC_RELAXED);
            copy.identity.contextGeneration = __atomic_load_n(
                &tapContextGeneration_, __ATOMIC_RELAXED);
            copy.identity.powerGeneration = __atomic_load_n(
                &tapPowerGeneration_, __ATOMIC_RELAXED);
            copy.identity.stationGeneration = __atomic_load_n(
                &tapStationGeneration_, __ATOMIC_RELAXED);
            copy.identity.rocGeneration = __atomic_load_n(
                &tapRocGeneration_, __ATOMIC_RELAXED);
            copy.recordSerial = __atomic_load_n(&tapRecordSerial_, __ATOMIC_RELAXED);
            copy.expectedQueueId = __atomic_load_n(&tapExpectedQueueId_, __ATOMIC_RELAXED);
            copy.expectedDescriptorIndex = __atomic_load_n(
                &tapExpectedDescriptorIndex_, __ATOMIC_RELAXED);
            copy.expectedSequenceControl = __atomic_load_n(
                &tapExpectedSequenceControl_, __ATOMIC_RELAXED);
            copy.expectedByteCount = __atomic_load_n(
                &tapExpectedByteCount_, __ATOMIC_RELAXED);
            copy.expectedFrameControl = __atomic_load_n(
                &tapExpectedFrameControl_, __ATOMIC_RELAXED);
            copy.observedAtUs = __atomic_load_n(&observedAtUs_, __ATOMIC_RELAXED);
            copy.validFields = __atomic_load_n(&validFields_, __ATOMIC_RELAXED);
            copy.queueId = __atomic_load_n(&queueId_, __ATOMIC_RELAXED);
            copy.rxHeaderIndex = __atomic_load_n(&rxHeaderIndex_, __ATOMIC_RELAXED);
            copy.sequenceControl = __atomic_load_n(&sequenceControl_, __ATOMIC_RELAXED);
            copy.byteCount = __atomic_load_n(&byteCount_, __ATOMIC_RELAXED);
            copy.frameControl = __atomic_load_n(&frameControl_, __ATOMIC_RELAXED);
            copy.status = __atomic_load_n(&status_, __ATOMIC_RELAXED);
            copy.raTid = __atomic_load_n(&raTid_, __ATOMIC_RELAXED);
            copy.scdSsn = __atomic_load_n(&scdSsn_, __ATOMIC_RELAXED);
            const uint64_t after = __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
            if (before == after && !(after & 1u)) {
                *output = copy;
                *serial = after;
                return true;
            }
        }
        return false;
    }

    TapPublicationSnapshot publicationSnapshot() const
    {
        TapPublicationSnapshot output{};
        const uint64_t sequenceBefore =
            __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
        const uint64_t consumedBefore =
            __atomic_load_n(&consumedSequence_, __ATOMIC_ACQUIRE);
        const uint64_t droppedBefore =
            __atomic_load_n(&captureDropCount_, __ATOMIC_ACQUIRE);
        const uint64_t activeBefore =
            __atomic_load_n(&activePublication_, __ATOMIC_ACQUIRE);
        const uint64_t activeToken =
            __atomic_load_n(&activeToken_, __ATOMIC_ACQUIRE);
        const uint64_t activeAfter =
            __atomic_load_n(&activePublication_, __ATOMIC_ACQUIRE);
        const uint64_t sequenceAfter =
            __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
        const uint64_t consumedAfter =
            __atomic_load_n(&consumedSequence_, __ATOMIC_ACQUIRE);
        const uint64_t droppedAfter =
            __atomic_load_n(&captureDropCount_, __ATOMIC_ACQUIRE);

        output.sequence = sequenceAfter;
        output.consumedSequence = consumedAfter;
        output.droppedCount = droppedAfter;
        output.activePublicationSequence = activeAfter;
        output.activeToken = activeToken;
        if (sequenceBefore != sequenceAfter || (sequenceAfter & 1u) ||
            consumedBefore != consumedAfter || droppedBefore != droppedAfter ||
            activeBefore != activeAfter || (activeAfter & 1u)) {
            output.state = TapPublicationState::Unstable;
        } else if (sequenceAfter == consumedAfter) {
            output.state = TapPublicationState::EmptyOrConsumed;
        } else {
            output.state = TapPublicationState::Pending;
        }
        return output;
    }

    uint64_t droppedCount() const
    {
        return __atomic_load_n(&captureDropCount_, __ATOMIC_ACQUIRE);
    }

    void markConsumed(uint64_t serial)
    {
        if (serial && !(serial & 1u) &&
            __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE) == serial)
            __atomic_store_n(&consumedSequence_, serial, __ATOMIC_RELEASE);
    }

private:
    mutable uint64_t sequence_;
    uint64_t activePublication_;
    uint64_t activeToken_;
    uint64_t activeDiagnosticGeneration_;
    uint64_t activeContextGeneration_;
    uint64_t activePowerGeneration_;
    uint64_t activeStationGeneration_;
    uint64_t activeRocGeneration_;
    uint64_t activeRecordSerial_;
    uint16_t activeQueueId_;
    uint16_t activeDescriptorIndex_;
    uint16_t activeSequenceControl_;
    uint16_t activeByteCount_;
    uint16_t activeFrameControl_;
    uint64_t tapToken_;
    uint64_t tapDiagnosticGeneration_;
    uint64_t tapContextGeneration_;
    uint64_t tapPowerGeneration_;
    uint64_t tapStationGeneration_;
    uint64_t tapRocGeneration_;
    uint64_t tapRecordSerial_;
    uint16_t tapExpectedQueueId_;
    uint16_t tapExpectedDescriptorIndex_;
    uint16_t tapExpectedSequenceControl_;
    uint16_t tapExpectedByteCount_;
    uint16_t tapExpectedFrameControl_;
    uint64_t observedAtUs_;
    uint32_t validFields_;
    uint16_t queueId_;
    uint16_t rxHeaderIndex_;
    uint16_t sequenceControl_;
    uint16_t byteCount_;
    uint16_t frameControl_;
    uint16_t status_;
    uint16_t raTid_;
    uint16_t scdSsn_;
    uint64_t captureDropCount_;
    uint64_t consumedSequence_;
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    CaptureInterleaveHook testCaptureHook_;
    void *testCaptureHookContext_;
#endif
};

// Single-slot stop handoff. It never touches the ordinary ledger and never
// waits for the main gate; a publisher consumes it later on that gate.
class AtomicStopTap {
public:
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    using CaptureInterleaveHook = void (*)(void *);
#endif

    AtomicStopTap()
        : sequence_(0), consumedSequence_(0), token_(0), observedAtUs_(0),
          newGeneration_(0), reason_(0), provenDrain_(0), droppedCount_(0)
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
          , testCaptureHook_(nullptr), testCaptureHookContext_(nullptr)
#endif
          {}

#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    void setCaptureInterleaveHookForTesting(CaptureInterleaveHook hook,
                                            void *context)
    {
        testCaptureHook_ = hook;
        testCaptureHookContext_ = context;
    }
#endif

    bool capture(uint64_t token, uint32_t newGeneration, bool provenDrain,
                 uint32_t reason, uint64_t observedAtUs)
    {
        if (!token || !observedAtUs) {
            __atomic_add_fetch(&droppedCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }
        uint64_t sequence = __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
        if ((sequence & 1u) || sequence > UINT64_MAX - 2u ||
            sequence != __atomic_load_n(&consumedSequence_, __ATOMIC_ACQUIRE) ||
            !__atomic_compare_exchange_n(&sequence_, &sequence, sequence + 1u,
                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_add_fetch(&droppedCount_, uint64_t(1), __ATOMIC_RELAXED);
            return false;
        }
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
        if (testCaptureHook_)
            testCaptureHook_(testCaptureHookContext_);
#endif
        __atomic_store_n(&token_, token, __ATOMIC_RELAXED);
        __atomic_store_n(&observedAtUs_, observedAtUs, __ATOMIC_RELAXED);
        __atomic_store_n(&newGeneration_, newGeneration, __ATOMIC_RELAXED);
        __atomic_store_n(&reason_, reason, __ATOMIC_RELAXED);
        __atomic_store_n(&provenDrain_, provenDrain ? 1u : 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&sequence_, sequence + 2u, __ATOMIC_RELEASE);
        return true;
    }

    bool snapshot(StopTap *output, uint64_t *serial) const
    {
        if (!output || !serial)
            return false;
        for (uint32_t attempt = 0; attempt != 3; ++attempt) {
            const uint64_t before = __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
            if (!before || (before & 1u))
                continue;
            StopTap copy{};
            copy.token = __atomic_load_n(&token_, __ATOMIC_RELAXED);
            copy.observedAtUs = __atomic_load_n(&observedAtUs_, __ATOMIC_RELAXED);
            copy.newGeneration = __atomic_load_n(&newGeneration_, __ATOMIC_RELAXED);
            copy.reason = __atomic_load_n(&reason_, __ATOMIC_RELAXED);
            copy.provenDrain = __atomic_load_n(&provenDrain_, __ATOMIC_RELAXED) != 0;
            const uint64_t after = __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
            if (before == after && !(after & 1u)) {
                *output = copy;
                *serial = after;
                return true;
            }
        }
        return false;
    }

    TapPublicationSnapshot publicationSnapshot() const
    {
        TapPublicationSnapshot output{};
        const uint64_t sequenceBefore =
            __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
        const uint64_t consumedBefore =
            __atomic_load_n(&consumedSequence_, __ATOMIC_ACQUIRE);
        const uint64_t droppedBefore =
            __atomic_load_n(&droppedCount_, __ATOMIC_ACQUIRE);
        const uint64_t sequenceAfter =
            __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE);
        const uint64_t consumedAfter =
            __atomic_load_n(&consumedSequence_, __ATOMIC_ACQUIRE);
        const uint64_t droppedAfter =
            __atomic_load_n(&droppedCount_, __ATOMIC_ACQUIRE);

        output.sequence = sequenceAfter;
        output.consumedSequence = consumedAfter;
        output.droppedCount = droppedAfter;
        output.activePublicationSequence = 0;
        output.activeToken = 0;
        if (sequenceBefore != sequenceAfter || (sequenceAfter & 1u) ||
            consumedBefore != consumedAfter || droppedBefore != droppedAfter) {
            output.state = TapPublicationState::Unstable;
        } else if (sequenceAfter == consumedAfter) {
            output.state = TapPublicationState::EmptyOrConsumed;
        } else {
            output.state = TapPublicationState::Pending;
        }
        return output;
    }

    bool hasEvent() const
    {
        return __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE) != 0;
    }

    void markConsumed(uint64_t serial)
    {
        if (serial && !(serial & 1u) &&
            __atomic_load_n(&sequence_, __ATOMIC_ACQUIRE) == serial)
            __atomic_store_n(&consumedSequence_, serial, __ATOMIC_RELEASE);
    }

    uint64_t droppedCount() const
    {
        return __atomic_load_n(&droppedCount_, __ATOMIC_ACQUIRE);
    }

private:
    mutable uint64_t sequence_;
    uint64_t consumedSequence_;
    uint64_t token_;
    uint64_t observedAtUs_;
    uint32_t newGeneration_;
    uint32_t reason_;
    uint32_t provenDrain_;
    uint64_t droppedCount_;
#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    CaptureInterleaveHook testCaptureHook_;
    void *testCaptureHookContext_;
#endif
};

class Ledger {
public:
    Ledger()
        : records_{}, responseTap_(), stopTap_(), owner_{}, ownerPresent_(false),
          activeToken_(0), nextRecordSerial_(0), revision_(0),
          snapshotVersion_(0), lastPublishedSnapshotVersion_(0),
          hasPublishedSnapshot_(false), droppedCount_(0), mergedResponseSerial_(0),
          orphanResponseCount_(0), observedCaptureDropCount_(0),
          mergedStopSerial_(0), orphanStopCount_(0), observedStopDropCount_(0) {}

#if defined(NATIVE_AWDL_DATA_TX_TRACE_TESTING)
    void setResponseCaptureInterleaveHookForTesting(
        AtomicTxResponseTap::CaptureInterleaveHook hook, void *context)
    {
        responseTap_.setCaptureInterleaveHookForTesting(hook, context);
    }

    void setStopCaptureInterleaveHookForTesting(
        AtomicStopTap::CaptureInterleaveHook hook, void *context)
    {
        stopTap_.setCaptureInterleaveHookForTesting(hook, context);
    }
#endif

    void publicationSnapshot(PublicationSnapshot *output) const
    {
        if (!output)
            return;
        const uint64_t revisionBefore = revision_;
        output->txResponse = responseTap_.publicationSnapshot();
        output->stop = stopTap_.publicationSnapshot();
        output->owner = ownerPresent_ ? owner_ : Identity{};
        output->ownerPresent = ownerPresent_;
        output->revision = revision_;
        output->revisionStable = revisionBefore == revision_;
        output->coverageUnknown = droppedCount() != 0;
    }

    static bool canClosePublication(const PublicationSnapshot &before,
                                    const PublicationSnapshot &after,
                                    uint64_t contentRevision)
    {
        return before.revisionStable && after.revisionStable &&
            before.revision == contentRevision &&
            after.revision == contentRevision &&
            before.ownerPresent == after.ownerPresent &&
            (!before.ownerPresent || sameIdentity(before.owner, after.owner)) &&
            before.coverageUnknown == after.coverageUnknown &&
            sameTapPublication(before.txResponse, after.txResponse) &&
            sameTapPublication(before.stop, after.stop) &&
            before.txResponse.state == TapPublicationState::EmptyOrConsumed &&
            before.stop.state == TapPublicationState::EmptyOrConsumed;
    }

    bool coverageUnknown() const { return droppedCount() != 0; }

    Status beginToken(const Identity &identity, uint64_t queueBornUs)
    {
        return beginToken(identity, queueBornUs, 0, false, false);
    }

    Status beginToken(const Identity &identity, uint64_t queueBornUs,
                      uint8_t queryClass, bool queueEligible)
    {
        return beginToken(identity, queueBornUs, queryClass, queueEligible, true);
    }

    Status beginToken(const Identity &identity, uint64_t queueBornUs,
                      uint8_t queryClass, bool queueEligible,
                      bool queueMetadataPresent)
    {
        if (!validIdentity(identity) || !queueBornUs)
            return Status::InvalidIdentity;
        if (activeToken_ && activeToken_ != identity.token)
            return Status::ActiveTokenExists;
        for (size_t i = 0; i < kRecordCapacity; ++i) {
            if (!records_[i].present || records_[i].identity.token != identity.token)
                continue;
            return sameIdentity(records_[i].identity, identity) ?
                Status::DuplicateToken : Status::TokenIdentityConflict;
        }

        size_t slot = kRecordCapacity;
        for (size_t i = 0; i < kRecordCapacity; ++i) {
            if (!records_[i].present) {
                slot = i;
                break;
            }
        }
        if (slot == kRecordCapacity) {
            writeBegin();
            ++droppedCount_;
            owner_ = identity;
            ownerPresent_ = true;
            bumpRevision();
            writeEnd();
            return Status::CapacityFull;
        }

        writeBegin();
        RecordSnapshot record{};
        record.present = true;
        record.identity = identity;
        record.recordSerial = nextSerial();
        record.stageMask = kQueueBorn;
        record.queryClass = queryClass;
        record.queueEligible = queueEligible;
        record.queueMetadataPresent = queueMetadataPresent;
        record.queueBornUs = queueBornUs;
        record.firmwareEchoesFullIdentity = false;
        record.ambiguousLateQueueUnknown = true;
        records_[slot] = record;
        owner_ = identity;
        ownerPresent_ = true;
        activeToken_ = identity.token;
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markDequeued(const Identity &identity, uint64_t atUs)
    {
        RecordSnapshot *record = findExact(identity);
        if (!record)
            return mismatchStatus(identity.token, identity);
        return markTimestamp(record, kDequeued, record->dequeuedUs, atUs,
                             kQueueBorn);
    }

    Status markEncodeFailure(uint64_t token, int32_t result, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (!(record->stageMask & kDequeued) || !atUs ||
            atUs < record->dequeuedUs)
            return Status::OutOfOrder;
        if (isTerminal(*record))
            return Status::DuplicateStage;
        writeBegin();
        record->encodeFailureUs = atUs;
        record->encodeFailureResult = static_cast<uint32_t>(result);
        record->stageMask |= kEncodeFailure;
        finishActive(token);
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markSubmitCallStart(uint64_t token, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        return markTimestamp(record, kSubmitCallStart,
                             record->submitCallStartUs, atUs, kDequeued);
    }

    Status markSubmitCallEnd(uint64_t token, int32_t result, uint64_t atUs)
    {
        RecordSnapshot *record = findToken(token);
        if (!record)
            return lookupStatus(token);
        if (record->stageMask & kSubmitCallEnd)
            return Status::DuplicateStage;
        if (!(record->stageMask & kSubmitCallStart) || !atUs ||
            atUs < record->submitCallStartUs)
            return Status::OutOfOrder;
        writeBegin();
        record->submitCallEndUs = atUs;
        record->submitCallResult = static_cast<uint32_t>(result);
        record->stageMask |= kSubmitCallEnd;
        if (result != 0 && !(record->stageMask & kDoorbellIssued) &&
            !isTerminal(*record)) {
            record->cancelUs = atUs;
            record->cancellationReason = static_cast<uint32_t>(result);
            record->stageMask |= kCancel;
            finishActive(token);
        }
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markFinalWire(uint64_t token, uint64_t contextGeneration,
                         uint64_t powerGeneration, uint64_t rocGeneration,
                         uint16_t frameControl, uint16_t sequenceControl,
                         uint16_t mpduLength, uint16_t packetCount,
                         uint32_t ipv6Length, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (!generationMatches(*record, contextGeneration, powerGeneration,
                               rocGeneration))
            return Status::StaleGeneration;
        const Status order = stageStatus(*record, kFinalWire,
                                         kSubmitCallStart, atUs);
        if (order != Status::Ready)
            return order;
        if (!mpduLength || !packetCount || !ipv6Length || frameControl == 0)
            return Status::InvalidIdentity;
        writeBegin();
        record->frameControl = frameControl;
        record->sequenceControl = sequenceControl;
        record->mpduLength = mpduLength;
        record->packetCount = packetCount;
        record->ipv6Length = ipv6Length;
        record->finalWireUs = atUs;
        record->stageMask |= kFinalWire;
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markRing(uint64_t token, uint64_t contextGeneration,
                    uint64_t powerGeneration, uint64_t rocGeneration,
                    uint16_t queueId, uint16_t ringSize,
                    uint16_t descriptorIndex, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (!generationMatches(*record, contextGeneration, powerGeneration,
                               rocGeneration))
            return Status::StaleGeneration;
        const Status order = stageStatus(*record, kRingReserved, kFinalWire, atUs);
        if (order != Status::Ready)
            return order;
        if (!ringSize || (ringSize & (ringSize - 1)) ||
            descriptorIndex >= ringSize || queueId > 0xff)
            return Status::InvalidIdentity;
        writeBegin();
        record->queueId = queueId;
        record->ringSize = ringSize;
        record->descriptorIndex = descriptorIndex;
        record->ringReservedUs = atUs;
        record->stageMask |= kRingReserved;
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markDescriptorReady(uint64_t token, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        const Status status = markTimestamp(record, kDescriptorReady,
            record->descriptorReadyUs, atUs, kRingReserved);
        if (status == Status::Ready)
            responseTap_.setActiveTicket(record->identity, record->recordSerial,
                record->queueId, record->descriptorIndex,
                record->sequenceControl, record->mpduLength,
                record->frameControl);
        return status;
    }

    Status markDoorbellMarked(uint64_t token, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        return markTimestamp(record, kDoorbellMarked,
                             record->doorbellMarkedUs, atUs, kDescriptorReady);
    }

    Status markDoorbellIssued(uint64_t token, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        return markTimestamp(record, kDoorbellIssued,
                             record->doorbellIssuedUs, atUs, kDoorbellMarked);
    }

    Status markCompletion(uint64_t token, uint32_t result, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (!(record->stageMask & kDoorbellIssued))
            return Status::OutOfOrder;
        if (record->stageMask & (kCompletion | kCancel | kUnknown))
            return Status::DuplicateStage;
        if (!atUs || atUs < record->doorbellIssuedUs)
            return Status::OutOfOrder;
        writeBegin();
        record->completionUs = atUs;
        record->completionResult = result;
        record->stageMask |= kCompletion;
        finishActive(token);
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markCancelled(uint64_t token, uint32_t reason, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (record->stageMask & kDoorbellIssued)
            return Status::Irreversible;
        if (record->stageMask & (kCompletion | kCancel | kUnknown))
            return Status::DuplicateStage;
        if (!atUs || (record->submitCallStartUs && atUs < record->submitCallStartUs))
            return Status::OutOfOrder;
        writeBegin();
        record->cancelUs = atUs;
        record->cancellationReason = reason;
        record->stageMask |= kCancel;
        finishActive(token);
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markUnknown(uint64_t token, uint32_t reason, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (!(record->stageMask & kDoorbellIssued))
            return Status::OutOfOrder;
        if (record->stageMask & (kCompletion | kCancel | kUnknown))
            return Status::DuplicateStage;
        if (!atUs || atUs < record->doorbellIssuedUs)
            return Status::OutOfOrder;
        writeBegin();
        record->unknownUs = atUs;
        record->unknownReason = reason;
        record->stageMask |= kUnknown;
        finishActive(token);
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    Status markStopped(uint64_t token, uint32_t newGeneration,
                       bool provenDrain, uint32_t reason, uint64_t atUs)
    {
        RecordSnapshot *record = findActive(token);
        if (!record)
            return lookupStatus(token);
        if (isTerminal(*record))
            return Status::DuplicateStage;
        if (!atUs || atUs < latestLifecycleTimestamp(*record))
            return Status::OutOfOrder;

        writeBegin();
        record->stopUs = atUs;
        record->stopNewGeneration = newGeneration;
        record->stopReason = reason;
        record->stopProvenDrain = provenDrain;
        record->stageMask |= kStopObserved;
        if ((record->stageMask & kDoorbellIssued) || !provenDrain) {
            // A generation change without a proven DMA/RX/TX drain, or an
            // irreversible submit without a TX_RSP, cannot establish success.
            record->unknownUs = atUs;
            record->unknownReason = reason;
            record->stageMask |= kUnknown;
        } else {
            record->cancelUs = atUs;
            record->cancellationReason = reason;
            record->stageMask |= kCancel;
        }
        finishActive(token);
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    bool captureStopTap(uint64_t token, uint32_t newGeneration,
                        bool provenDrain, uint32_t reason, uint64_t atUs)
    {
        return stopTap_.capture(token, newGeneration, provenDrain, reason, atUs);
    }

    Status mergeStopTap()
    {
        const uint64_t captureDrops = stopTap_.droppedCount();
        if (captureDrops != observedStopDropCount_) {
            writeBegin();
            observedStopDropCount_ = captureDrops;
            bumpRevision();
            writeEnd();
        }
        const TapPublicationSnapshot publication =
            stopTap_.publicationSnapshot();
        if (publication.state == TapPublicationState::Unstable)
            return Status::ResponseTapUnstable;
        if (publication.state == TapPublicationState::EmptyOrConsumed)
            return Status::NoRecord;

        StopTap tap{};
        uint64_t serial = 0;
        if (!stopTap_.snapshot(&tap, &serial))
            return stopTap_.hasEvent() ? Status::ResponseTapUnstable :
                Status::NoRecord;
        if (serial == mergedStopSerial_)
            return Status::NoRecord;
        const Status result = markStopped(tap.token, tap.newGeneration,
            tap.provenDrain, tap.reason, tap.observedAtUs);
        writeBegin();
        mergedStopSerial_ = serial;
        if (result != Status::Ready)
            ++orphanStopCount_;
        bumpRevision();
        writeEnd();
        stopTap_.markConsumed(serial);
        return result;
    }

    Status markTxResponseHandlerDisposition(uint64_t token,
                                            uint32_t disposition)
    {
        RecordSnapshot *record = findToken(token);
        if (!record)
            return lookupStatus(token);
        if (!disposition || record->txRspHandlerDisposition)
            return Status::DuplicateStage;
        writeBegin();
        record->txRspHandlerDisposition = disposition;
        if (disposition == 1)
            record->associationStrength = static_cast<uint32_t>(
                AssociationStrength::ExistingHandlerAccepted);
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    bool captureTxResponseTap(uint64_t expectedToken, uint64_t observedAtUs,
                              uint32_t validFields, uint16_t queueId,
                              uint16_t rxHeaderIndex, uint16_t sequenceControl,
                              uint16_t byteCount, uint16_t frameControl,
                              uint16_t status, uint16_t raTid, uint16_t scdSsn)
    {
        return responseTap_.capture(expectedToken, observedAtUs, validFields,
            queueId, rxHeaderIndex, sequenceControl, byteCount, frameControl,
            status, raTid, scdSsn);
    }

    Status mergeTxResponseTap()
    {
        const uint64_t captureDrops = responseTap_.droppedCount();
        if (captureDrops != observedCaptureDropCount_) {
            writeBegin();
            observedCaptureDropCount_ = captureDrops;
            bumpRevision();
            writeEnd();
        }
        const TapPublicationSnapshot publication =
            responseTap_.publicationSnapshot();
        if (publication.state == TapPublicationState::Unstable)
            return Status::ResponseTapUnstable;
        if (publication.state == TapPublicationState::EmptyOrConsumed)
            return Status::NoRecord;

        TxResponseTap tap{};
        uint64_t serial = 0;
        if (!responseTap_.snapshot(&tap, &serial))
            return Status::ResponseTapUnstable;
        if (serial == mergedResponseSerial_)
            return Status::NoRecord;

        RecordSnapshot *record = findExact(tap.identity);
        if (!record || record->recordSerial != tap.recordSerial) {
            writeBegin();
            ++orphanResponseCount_;
            mergedResponseSerial_ = serial;
            bumpRevision();
            writeEnd();
            responseTap_.markConsumed(serial);
            return Status::StaleToken;
        }
        if (record->stageMask & kTxResponseTap) {
            writeBegin();
            ++orphanResponseCount_;
            mergedResponseSerial_ = serial;
            bumpRevision();
            writeEnd();
            responseTap_.markConsumed(serial);
            return Status::DuplicateStage;
        }

        uint32_t mismatch = 0;
        uint32_t scalarMatch = 0;
        if (tap.validFields & kResponseQueueValid) {
            if (tap.queueId != tap.expectedQueueId) mismatch |= kMismatchQueue;
            else scalarMatch |= kResponseQueueValid;
        } else mismatch |= kMissingResponseField;
        // packet->hdr.idx is an RX command-header byte. Preserve its raw
        // value, but do not assert it identifies this TX ring descriptor.
        if (tap.validFields & kResponseSequenceValid) {
            if (tap.sequenceControl != tap.expectedSequenceControl)
                mismatch |= kMismatchSequence;
            else scalarMatch |= kResponseSequenceValid;
        } else mismatch |= kMissingResponseField;
        if (tap.validFields & kResponseByteCountValid) {
            if (tap.byteCount != tap.expectedByteCount)
                mismatch |= kMismatchByteCount;
            else scalarMatch |= kResponseByteCountValid;
        } else mismatch |= kMissingResponseField;
        if (tap.validFields & kResponseFrameControlValid) {
            if (tap.frameControl != tap.expectedFrameControl)
                mismatch |= kMismatchFrameControl;
            else scalarMatch |= kResponseFrameControlValid;
        } else mismatch |= kMissingResponseField;

        writeBegin();
        record->txRspTapUs = tap.observedAtUs;
        record->txRspQueueId = tap.queueId;
        record->txRspRxHeaderIndex = tap.rxHeaderIndex;
        record->txRspSequenceControl = tap.sequenceControl;
        record->txRspByteCount = tap.byteCount;
        record->txRspFrameControl = tap.frameControl;
        record->txRspStatus = tap.status;
        record->txRspRaTid = tap.raTid;
        record->txRspScdSsn = tap.scdSsn;
        record->txRspValidFields = tap.validFields;
        record->responseMismatchMask = mismatch;
        record->responseScalarMatchMask = scalarMatch;
        record->associationStrength = static_cast<uint32_t>(mismatch == 0 ?
            AssociationStrength::LocalScalarFieldsMatch :
            AssociationStrength::CandidateOnly);
        record->firmwareEchoesFullIdentity = false;
        record->ambiguousLateQueueUnknown = true;
        record->responseCandidateSeen = true;
        record->stageMask |= kTxResponseTap;
        mergedResponseSerial_ = serial;
        bumpRevision();
        writeEnd();
        responseTap_.markConsumed(serial);
        return Status::Ready;
    }

    bool snapshot(size_t index, RecordSnapshot *output) const
    {
        if (index >= kRecordCapacity || !output)
            return false;
        *output = records_[index];
        return true;
    }

    uint32_t count() const
    {
        uint32_t result = 0;
        for (size_t i = 0; i < kRecordCapacity; ++i)
            if (records_[i].present) ++result;
        return result;
    }

    uint64_t droppedCount() const
    {
        return droppedCount_ + responseTap_.droppedCount() + orphanResponseCount_ +
            stopTap_.droppedCount() + orphanStopCount_;
    }

    uint64_t revision() const { return revision_; }
    uint64_t snapshotVersion() const { return snapshotVersion_; }
    uint64_t lastPublishedSnapshotVersion() const
    {
        return lastPublishedSnapshotVersion_;
    }
    bool markPublishedSnapshotVersion(uint64_t version)
    {
        if ((version & 1u) || version != snapshotVersion_)
            return false;
        lastPublishedSnapshotVersion_ = version;
        hasPublishedSnapshot_ = true;
        return true;
    }
    bool hasPublishedSnapshot() const { return hasPublishedSnapshot_; }
    bool ownerPresent() const { return ownerPresent_; }
    bool ownerSnapshot(Identity *output) const
    {
        if (!output || !ownerPresent_)
            return false;
        *output = owner_;
        return true;
    }

private:
    static bool sameTapPublication(const TapPublicationSnapshot &left,
                                   const TapPublicationSnapshot &right)
    {
        return left.sequence == right.sequence &&
            left.consumedSequence == right.consumedSequence &&
            left.droppedCount == right.droppedCount &&
            left.activePublicationSequence == right.activePublicationSequence &&
            left.activeToken == right.activeToken &&
            left.state == right.state;
    }

    static bool validIdentity(const Identity &id)
    {
        return id.token && id.diagnosticGeneration && id.contextGeneration &&
            id.powerGeneration && id.stationGeneration && id.rocGeneration;
    }

    static bool sameIdentity(const Identity &left, const Identity &right)
    {
        return left.token == right.token &&
            left.diagnosticGeneration == right.diagnosticGeneration &&
            left.contextGeneration == right.contextGeneration &&
            left.powerGeneration == right.powerGeneration &&
            left.stationGeneration == right.stationGeneration &&
            left.rocGeneration == right.rocGeneration;
    }

    static bool isTerminal(const RecordSnapshot &record)
    {
        return (record.stageMask &
            (kCompletion | kCancel | kUnknown | kEncodeFailure)) != 0;
    }

    uint64_t nextSerial()
    {
        ++nextRecordSerial_;
        if (!nextRecordSerial_) ++nextRecordSerial_;
        return nextRecordSerial_;
    }

    void writeBegin()
    {
        __atomic_add_fetch(&snapshotVersion_, uint64_t(1), __ATOMIC_RELEASE);
    }

    void writeEnd()
    {
        bumpVersionOnly();
    }

    void bumpVersionOnly()
    {
        __atomic_add_fetch(&snapshotVersion_, uint64_t(1), __ATOMIC_RELEASE);
    }

    void bumpRevision()
    {
        ++revision_;
        if (!revision_) ++revision_;
    }

    RecordSnapshot *findActive(uint64_t token)
    {
        if (!token || token != activeToken_)
            return nullptr;
        for (size_t i = 0; i < kRecordCapacity; ++i)
            if (records_[i].present && records_[i].identity.token == token)
                return &records_[i];
        return nullptr;
    }

    RecordSnapshot *findToken(uint64_t token)
    {
        if (!token)
            return nullptr;
        for (size_t i = 0; i < kRecordCapacity; ++i)
            if (records_[i].present && records_[i].identity.token == token)
                return &records_[i];
        return nullptr;
    }

    RecordSnapshot *findExact(const Identity &identity)
    {
        for (size_t i = 0; i < kRecordCapacity; ++i)
            if (records_[i].present &&
                records_[i].identity.token == identity.token &&
                sameIdentity(records_[i].identity, identity))
                return &records_[i];
        return nullptr;
    }

    Status lookupStatus(uint64_t token) const
    {
        if (!token || token != activeToken_)
            return Status::StaleToken;
        return Status::NoRecord;
    }

    Status mismatchStatus(uint64_t token, const Identity &identity) const
    {
        for (size_t i = 0; i < kRecordCapacity; ++i) {
            if (records_[i].present && records_[i].identity.token == token)
                return sameIdentity(records_[i].identity, identity) ?
                    Status::NoRecord : Status::StaleGeneration;
        }
        return Status::StaleToken;
    }

    static bool generationMatches(const RecordSnapshot &record,
                                  uint64_t contextGeneration,
                                  uint64_t powerGeneration,
                                  uint64_t rocGeneration)
    {
        return record.identity.contextGeneration == contextGeneration &&
            record.identity.powerGeneration == powerGeneration &&
            record.identity.rocGeneration == rocGeneration;
    }

    Status stageStatus(const RecordSnapshot &record, uint32_t bit,
                       uint32_t prerequisite, uint64_t atUs) const
    {
        if (record.stageMask & bit)
            return Status::DuplicateStage;
        if (!(record.stageMask & prerequisite) || !atUs)
            return Status::OutOfOrder;
        const uint64_t previous = latestTimestamp(record);
        if (atUs < previous)
            return Status::OutOfOrder;
        if (isTerminal(record))
            return Status::Terminal;
        return Status::Ready;
    }

    static uint64_t latestTimestamp(const RecordSnapshot &record)
    {
        const uint64_t values[] = {record.queueBornUs, record.dequeuedUs,
            record.submitCallStartUs, record.finalWireUs, record.ringReservedUs,
            record.descriptorReadyUs, record.doorbellMarkedUs,
            record.doorbellIssuedUs, record.txRspTapUs, record.completionUs,
            record.cancelUs, record.unknownUs, record.submitCallEndUs};
        uint64_t latest = 0;
        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
            if (values[i] > latest) latest = values[i];
        return latest;
    }

    static uint64_t latestLifecycleTimestamp(const RecordSnapshot &record)
    {
        // SubmitCallEnd is a wrapper-return timestamp and may occur after a
        // concurrent stop has already captured its own event. Keep the stop
        // ordering check tied to lifecycle evidence only.
        const uint64_t values[] = {record.queueBornUs, record.dequeuedUs,
            record.submitCallStartUs, record.finalWireUs, record.ringReservedUs,
            record.descriptorReadyUs, record.doorbellMarkedUs,
            record.doorbellIssuedUs, record.txRspTapUs, record.completionUs,
            record.cancelUs, record.unknownUs, record.encodeFailureUs,
            record.stopUs};
        uint64_t latest = 0;
        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
            if (values[i] > latest) latest = values[i];
        return latest;
    }

    Status markTimestamp(RecordSnapshot *record, uint32_t bit,
                         uint64_t &field, uint64_t atUs,
                         uint32_t prerequisite)
    {
        if (!record)
            return Status::NoRecord;
        const Status order = stageStatus(*record, bit, prerequisite, atUs);
        if (order != Status::Ready)
            return order;
        writeBegin();
        field = atUs;
        record->stageMask |= bit;
        bumpRevision();
        writeEnd();
        return Status::Ready;
    }

    void finishActive(uint64_t token)
    {
        if (activeToken_ == token) {
            activeToken_ = 0;
            responseTap_.clearActiveIdentity(token);
        }
    }

    RecordSnapshot records_[kRecordCapacity];
    AtomicTxResponseTap responseTap_;
    AtomicStopTap stopTap_;
    Identity owner_;
    bool ownerPresent_;
    uint64_t activeToken_;
    uint64_t nextRecordSerial_;
    uint64_t revision_;
    uint64_t snapshotVersion_;
    uint64_t lastPublishedSnapshotVersion_;
    bool hasPublishedSnapshot_;
    uint64_t droppedCount_;
    uint64_t mergedResponseSerial_;
    uint64_t orphanResponseCount_;
    uint64_t observedCaptureDropCount_;
    uint64_t mergedStopSerial_;
    uint64_t orphanStopCount_;
    uint64_t observedStopDropCount_;
};

} // namespace NativeAwdlDataTxTrace

#endif // NATIVE_AWDL_DATA_TX_TRACE_HPP
