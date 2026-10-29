// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#ifdef AIRPORT_TAHOE

#include <stdint.h>
#include <stddef.h>
#include <sys/mbuf.h>

#include "ItlIwxP2PTx.hpp"
#include "../../native/p2p_action_tx.hpp"
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
#include "../../native/awdl_tx_window_evidence.hpp"
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../../native/awdl_data_tx_trace.hpp"
#endif

struct iwx_rx_packet;
struct iwx_rx_data;

enum class TahoeP2PActionTxState : uint8_t {
    kIdle,
    kInFlight,
    kQuarantined
};

enum class TahoeP2PTxRxRejectReason : uint32_t {
    kNone = 0,
    kInvalidArguments = 1,
    kShortPayload = 2,
    kQueueParseFailed = 3,
    kQueueOutOfRange = 4,
    kDuplicateWhileReleasing = 5,
    kCompletionLockUnavailable = 6,
    kWrongWorkLoopGate = 7,
    kNoMatchingTicket = 8,
    kUnsupportedFirmware = 9,
    kStaleGeneration = 10,
    kRingMismatch = 11,
    kWrongTid = 12,
    kCompletionRejected = 13,
    kCompletionAccountingFailed = 14,
    kUnexpectedBlockAck = 15
};

enum TahoeP2PTxResponseFieldValid : uint32_t {
    kP2PTxResponseFrameCountValid = 1u << 0,
    kP2PTxResponseStatusValid = 1u << 1,
    kP2PTxResponseSequenceControlValid = 1u << 2,
    kP2PTxResponseByteCountValid = 1u << 3,
    kP2PTxResponseFrameControlValid = 1u << 4,
    kP2PTxResponseRaTidValid = 1u << 5,
    kP2PTxResponseScdSsnValid = 1u << 6,
    kP2PTxResponseHeaderIndexValid = 1u << 7,
    kP2PTxResponseTicketExpectedValid = 1u << 8
};

enum TahoeP2PTxResponseMismatch : uint32_t {
    kP2PTxResponseSequenceControlMismatch = 1u << 0,
    kP2PTxResponseScdIndexMismatch = 1u << 1
};

// These counters are independent of the TX_RSP completion diagnostics, which
// are armed only after a completion ticket is prepared. They preserve the
// reason for a pre-arm notification without changing packet or lease state.
enum class TahoeP2PPreArmEventSource : uint32_t {
    kNone = 0,
    kTxResponseNoLiveTicket = 1,
    kTxResponseOwnershipUnknown = 2,
    kOwnedBlockAckNoLiveTicket = 3,
    kOwnedBlockAckOwnershipUnknown = 4
};

enum class TahoeP2PActionTxSubmitStage : uint32_t {
    kNone = 0,
    kInvalidArgument = 1,
    kOwnerOrGate = 2,
    kUnsupportedLayout = 3,
    kRocOrResource = 4,
    kContextInFlight = 5,
    kContextQuarantined = 6,
    kFrameLength = 7,
    kFrameEncoding = 8,
    kMacHeaderLength = 9,
    kRateUnavailable = 10,
    kBeginTx = 11,
    kRingShape = 12,
    kPayloadMapping = 13,
    kPayloadSegmentLength = 14,
    kTfdPlan = 15,
    kTicketArm = 16,
    kDoorbellMark = 17,
    kDoorbellIssued = 18,
    kPostDoorbellFinish = 19,
    kPreDoorbellCancelFailed = 20,
    kExistingTicketUnknown = 21,
    kNativeAwdlIdentity = 22,
    kExperimentalDeadline = 23
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    ,
    kControlSubmitFence = 24
#endif
};

struct TahoeP2PActionTxPreArmDiagnostics {
    uint32_t eventCount;
    uint32_t lastSource;
    uint32_t lastQueueId;
    uint32_t lastRaTid;
    uint32_t lastLeaseState;
    uint32_t lastActionState;
    uint32_t lastTicketFlags;

    TahoeP2PActionTxPreArmDiagnostics()
        : eventCount(0), lastSource(0), lastQueueId(0xffffffffu),
          lastRaTid(0xffffffffu), lastLeaseState(0xffffffffu),
          lastActionState(0xffffffffu), lastTicketFlags(0) {}
};

struct TahoeP2PActionTxSubmitDiagnostics {
    uint32_t attemptCount;
    uint32_t lastStage;
    int32_t lastResult;

    TahoeP2PActionTxSubmitDiagnostics()
        : attemptCount(0), lastStage(0), lastResult(0) {}
};

struct TahoeP2PActionTxDrainDiagnostics {
    uint32_t eventCount;
    int32_t lastResult;
    uint32_t lastNewGeneration;
    uint32_t lastContextGeneration;
    uint32_t lastTicketGeneration;
    uint32_t lastTicketFlags;
    uint32_t lastHardStop;
    uint32_t lastActionState;

    TahoeP2PActionTxDrainDiagnostics()
        : eventCount(0), lastResult(0), lastNewGeneration(0),
          lastContextGeneration(0), lastTicketGeneration(0),
          lastTicketFlags(0), lastHardStop(0), lastActionState(0) {}
};

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
struct TahoeP2PActionTxSubmitMetadata {
    uint64_t diagnosticGeneration;
    NativeAwdlTxWindowEvidence::Epoch epoch;
    NativeAwdlTxWindowEvidence::FrameKind frameKind;
    uint32_t frameOrdinal;
};

struct TahoeP2PActionTxEvidenceSidecar {
    uint64_t ticketToken;
    uint32_t deviceFamily;
    uint32_t txCommandApi;
    uint32_t txLayout;
    uint32_t statusFlags;
    bool used;

    TahoeP2PActionTxEvidenceSidecar()
        : ticketToken(0), deviceFamily(0), txCommandApi(0), txLayout(0),
          statusFlags(0), used(false) {}
};

enum TahoeP2PActionTxEvidenceStatusFlag : uint32_t {
    kP2PTxEvidenceDoorbellMarked = 1u << 0,
    kP2PTxEvidenceDoorbellIssued = 1u << 1,
    kP2PTxEvidenceSubmitLowerValid = 1u << 2,
    kP2PTxEvidenceCompletionUpperValid = 1u << 3,
    kP2PTxEvidenceFirmwareSuccess = 1u << 4,
    kP2PTxEvidenceUnbound = 1u << 5,
    kP2PTxEvidenceFirmwareFailure = 1u << 6,
    kP2PTxEvidenceInvalidUnknown = 1u << 7,
    kP2PTxEvidencePostDoorbellFinishFailure = 1u << 8
};

struct TahoeP2PActionTxWindowEvidence {
    NativeAwdlTxWindowEvidence::Ledger ledger;
    NativeAwdlTxWindowEvidence::TicketIdentity pendingIdentity;
    NativeAwdlTxWindowEvidence::Epoch epoch;
    TahoeP2PActionTxEvidenceSidecar sidecars[
        NativeAwdlTxWindowEvidence::kTicketCapacity];
    uint64_t diagnosticGeneration;
    uint64_t nextTicketSerial;
    uint64_t snapshotVersion;
    uint64_t lastPublishedSnapshotVersion;
    uint32_t pendingStatusFlags;
    uint32_t droppedTicketCount;
    uint32_t pendingSidecarIndex;
    uint32_t pendingDeviceFamily;
    uint32_t pendingTxCommandApi;
    uint32_t pendingTxLayout;
    bool initialized;
    bool pendingTicketPrepared;
    bool pendingIdentityValid;

    TahoeP2PActionTxWindowEvidence()
        : ledger(), pendingIdentity{}, epoch{}, sidecars{},
          diagnosticGeneration(0), nextTicketSerial(0), snapshotVersion(0),
          lastPublishedSnapshotVersion(0), pendingStatusFlags(0),
          droppedTicketCount(0), pendingSidecarIndex(0xffffffffu),
          pendingDeviceFamily(0), pendingTxCommandApi(0), pendingTxLayout(0),
          initialized(false), pendingTicketPrepared(false),
          pendingIdentityValid(false) {}
};
#endif

/* Numeric-only RX-path telemetry. All concurrent access uses __atomic_* ops. */
struct TahoeP2PTxRxDiagnostics {
    uint32_t armed;
    uint32_t dirty;
    uint32_t targetQueue;
    uint32_t rawTxCmdCount;
    uint32_t rawTargetHeaderCount;
    uint32_t responseQueueMatchCount;
    uint32_t foreignQueueCount;
    uint32_t shortResponseCount;
    uint32_t outOfRangeQueueCount;
    uint32_t handlerEntryCount;
    uint32_t handlerQueueMatchCount;
    uint32_t handlerForeignCount;
    uint32_t rejectCount;
    uint32_t lastRejectReason;
    uint32_t lastCompletionResult;
    uint32_t completionCount;
    uint32_t lastResponseQueue;
    uint32_t lastResponseFieldsValidMask;
    uint32_t lastResponseFrameCount;
    uint32_t lastResponseStatus;
    uint32_t lastResponseSequenceControl;
    uint32_t lastResponseByteCount;
    uint32_t lastResponseFrameControl;
    uint32_t lastResponseRaTid;
    uint32_t lastResponseScdSsn;
    uint32_t lastResponseHeaderIndex;
    uint32_t lastResponseHeaderIndexMatchesTicket;
    uint32_t lastResponseMismatchMask;
    uint32_t lastResponseExpectedSequenceControl;
    uint32_t lastResponseExpectedByteCount;
    uint32_t lastResponseExpectedFrameControl;
    uint32_t lastResponseExpectedDescriptorIndex;
    uint32_t lastResponseExpectedNextIndex;
    uint64_t lastRawPacket;
    uint64_t lastTargetRawPacket;

    TahoeP2PTxRxDiagnostics()
        : armed(0), dirty(0), targetQueue(0xffff), rawTxCmdCount(0),
          rawTargetHeaderCount(0),
          responseQueueMatchCount(0), foreignQueueCount(0),
          shortResponseCount(0), outOfRangeQueueCount(0),
          handlerEntryCount(0), handlerQueueMatchCount(0),
          handlerForeignCount(0), rejectCount(0), lastRejectReason(0),
          lastCompletionResult(0), completionCount(0),
          lastResponseQueue(0xffff), lastResponseFieldsValidMask(0),
          lastResponseFrameCount(0xffffffffu),
          lastResponseStatus(0xffffffffu),
          lastResponseSequenceControl(0xffffffffu),
          lastResponseByteCount(0xffffffffu),
          lastResponseFrameControl(0xffffffffu),
          lastResponseRaTid(0xffffffffu), lastResponseScdSsn(0xffffffffu),
          lastResponseHeaderIndex(0xffffffffu),
          lastResponseHeaderIndexMatchesTicket(0xffffffffu),
          lastResponseMismatchMask(0),
          lastResponseExpectedSequenceControl(0xffffffffu),
          lastResponseExpectedByteCount(0xffffffffu),
          lastResponseExpectedFrameControl(0xffffffffu),
          lastResponseExpectedDescriptorIndex(0xffffffffu),
          lastResponseExpectedNextIndex(0xffffffffu),
          lastRawPacket(~uint64_t(0)),
          lastTargetRawPacket(~uint64_t(0)) {}
};

/* Persist this next to the caller-owned Tahoe P2P queue lease. */
struct TahoeP2PActionTxContext {
    IntelP2PActionTx::CompletionTracker completion;
    TahoeP2PTxRxDiagnostics rxDiagnostics;
    TahoeP2PActionTxPreArmDiagnostics preArmDiagnostics;
    TahoeP2PActionTxSubmitDiagnostics submitDiagnostics;
    TahoeP2PActionTxDrainDiagnostics drainDiagnostics;
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    TahoeP2PActionTxWindowEvidence windowEvidence;
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    NativeAwdlDataTxTrace::Ledger dataTxTrace;
#endif
    uint32_t generation;
    uint32_t rocToken;
    uint16_t queueId;
    uint16_t nextSequenceNumber;
    uint16_t descriptorIndex;
    uint16_t sequenceControl;
    uint16_t frameControl;
    uint16_t frameByteCount;
    uint64_t nativeDataToken;
    TahoeP2PActionTxState state;

    TahoeP2PActionTxContext()
        : completion(), preArmDiagnostics(), submitDiagnostics(),
          drainDiagnostics(),
          generation(0), rocToken(0), queueId(0xffff),
          nextSequenceNumber(0), descriptorIndex(0), sequenceControl(0),
          frameControl(0), frameByteCount(0), nativeDataToken(0),
          state(TahoeP2PActionTxState::kIdle) {}
};

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
struct TahoeP2PActionTxControlSubmitFence {
    uint64_t phaseOriginUs;
    uint64_t peerMifRxUs;
    uint64_t effectiveEndUs;
    uint64_t preparedFrameUs;
    uint64_t preparedFrameMaxAgeUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t rocGeneration;
};
#endif

/*
 * Call under the serialized native P2P mainGate after re-reading the same ROC
 * tracker. It consumes `frame` on every return path. It accepts one caller-built
 * Action MPDU only during an observed, still-open ROC. It never borrows a STA
 * node or STA queue. Success means doorbell submitted, not peer receipt.
 * The discovery experiment can add a host-monotonic estimated submit window
 * and station generation. The estimate is not RF airtime proof; all-zero
 * optional arguments retain the legacy behavior.
 */
int iwx_tahoe_p2p_action_tx_submit(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context,
    uint32_t rocToken, bool rocStartObserved, bool rocEndObserved,
    mbuf_t frame, uint64_t nativeDataToken = 0
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    , const TahoeP2PActionTxSubmitMetadata *evidenceMetadata = nullptr
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    , uint64_t estimatedNotBeforeUs = 0,
    uint64_t estimatedDeadlineUs = 0,
    uint32_t experimentalStationGeneration = 0,
    const TahoeP2PActionTxControlSubmitFence *controlSubmitFence = nullptr
#endif
    );

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
// Drain the one-shot address-free Qm wire snapshot from the deferred main-gate
// collector. A missing return value means no record was published.
bool iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(ItlIwx *owner);
#endif

/*
 * Call under the same native P2P mainGate, before the generic IWX_REPLY_TX handler.
 * Returns true for this P2P qid
 * even when malformed, quarantining the ticket so generic STA reclaim cannot
 * claim the slot or release a node that this path never acquired.
 */
bool iwx_tahoe_p2p_action_tx_response(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context,
    struct iwx_rx_packet *packet, struct iwx_rx_data *rxData);

// A lease-owned queue must never enter generic aggregate reclaim.
bool iwx_tahoe_p2p_action_reject_ba_queue(
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context, uint16_t queueId);

/*
 * Called after RX length validation and before dispatch; reads header only.
 * Header queue matches are a routing clue, not proof of TX_RSP completion.
 */
void iwx_tahoe_p2p_action_tx_observe_rx(
    TahoeP2PActionTxContext *context, uint8_t rawGroup, uint8_t rawOpcode,
    uint8_t rawHeaderQueue, uint8_t rawIndex, size_t payloadLength);

/*
 * Call only after firmware stop plus RX/TX/DMA drain has been positively
 * established; a generation change alone does not prove descriptor drain.
 */
void iwx_tahoe_p2p_action_tx_firmware_drained(
    TahoeP2PActionTxContext *context, uint32_t newGeneration,
    bool firmwareStoppedAndRxTxDrained);

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
void iwx_tahoe_p2p_action_tx_mark_evidence_unknown(
    TahoeP2PActionTxContext *context, uint32_t additionalFlags);
#endif

#endif // AIRPORT_TAHOE
