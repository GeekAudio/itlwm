// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwxP2PAction.hpp"

#ifdef AIRPORT_TAHOE

#include "ItlIwx.hpp"
#include "../../native/p2p_tx_firmware.hpp"
#include "../../native/awdl_action_frame.hpp"
#include "../../native/awdl_action_encode.hpp"
#include "../../native/awdl_advertisement_identity.hpp"
#include "../../native/awdl_mif_encode.hpp"
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../../native/awdl_native_bsd_data_25G332.hpp"
#include "../../native/awdl_data_frame.hpp"
#include "../../native/awdl_data_tx_observation.hpp"
#include "../../native/awdl_qm_wire_snapshot.hpp"
#endif

#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSBoolean.h>
#include <kern/clock.h>
#include <sys/errno.h>
#include <string.h>

namespace {

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
static uint64_t p2pActionMonotonicUs()
{
    uint64_t uptime = 0, nanoseconds = 0;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &nanoseconds);
    return nanoseconds / 1000ULL;
}

using QmWireSnapshotRecord = NativeAwdlQmWireSnapshot::Record;

static bool hasEligibleQmTraceToken(
    TahoeP2PActionTxContext *context, uint64_t token)
{
    if (!context || !token)
        return false;
    for (size_t index = 0;
         index < NativeAwdlDataTxTrace::kRecordCapacity; ++index) {
        NativeAwdlDataTxTrace::RecordSnapshot record{};
        if (context->dataTxTrace.snapshot(index, &record) && record.present &&
            record.identity.token == token && record.queueMetadataPresent &&
            record.queueEligible && record.queryClass == static_cast<uint8_t>(
                NativeAwdlData::MdnsQueryClass::QmMulticast))
            return true;
    }
    return false;
}

// One capture is staged after a successful queue finish. The deferred main-gate
// collector serializes it and performs one atomic IORegistry property replace.
static QmWireSnapshotRecord pendingQmWireSnapshot{};
static uint32_t pendingQmWireSnapshotState; // 0 empty, 1 writing, 2 ready, 3 draining, 4 done, 5 failed

static bool stageQmWireSnapshot(const QmWireSnapshotRecord &record)
{
    if (!record.token)
        return false;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&pendingQmWireSnapshotState, &expected,
            1u, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return false;
    pendingQmWireSnapshot = record;
    __atomic_store_n(&pendingQmWireSnapshotState, 2u, __ATOMIC_RELEASE);
    return true;
}
#endif

static_assert(offsetof(struct iwx_tx_resp, seq_ctl) == 28,
              "fw68 TX_RSP seq_ctl wire offset changed");
static_assert(offsetof(struct iwx_tx_resp, byte_cnt) == 30,
              "fw68 TX_RSP byte_cnt wire offset changed");
static_assert(offsetof(struct iwx_tx_resp, frame_ctrl) == 34,
              "fw68 TX_RSP frame_ctrl wire offset changed");
static_assert(offsetof(struct iwx_tx_resp, tx_queue) == 36,
              "fw68 TX_RSP tx_queue wire offset changed");
static_assert(offsetof(struct iwx_tx_resp, status) == 40,
              "fw68 TX_RSP status wire offset changed");
static_assert(sizeof(struct iwx_agg_tx_status) == 4,
              "fw68 TX_RSP status entry size changed");
static_assert(sizeof(struct iwx_tx_cmd_gen2) == 20,
              "fw68 AX201 TX_CMD v9 gen2 command header changed");
static_assert(sizeof(struct iwx_tx_cmd_gen3) == 28,
              "fw68 AX210 TX_CMD v10 gen3 command header changed");
static_assert(IWX_DEVICE_FAMILY_22000 == static_cast<int>(
                  IntelP2PFirmware::DeviceFamily::k22000),
              "TX firmware profile 22000 family value changed");
static_assert(IWX_DEVICE_FAMILY_AX210 == static_cast<int>(
                  IntelP2PFirmware::DeviceFamily::kAX210),
              "TX firmware profile AX210 family value changed");

static void clearActionDescriptor(struct iwx_tfh_tfd *descriptor)
{
    const uint16_t used = le16toh(descriptor->num_tbs) & 0x1f;
    for (uint16_t i = 1; i < used; ++i)
        memset(&descriptor->tbs[i], 0, sizeof(descriptor->tbs[i]));
    descriptor->num_tbs = 0;
}

static void clearPreparedSlot(struct iwx_tx_ring *ring, uint16_t index)
{
    if (!ring || index >= ring->ring_count)
        return;
    if (ring->desc)
        clearActionDescriptor(&ring->desc[index]);
    ring->data[index].m = nullptr;
    ring->data[index].in = nullptr;
    ring->data[index].type = 0;
}

static IntelP2PFirmware::TxLayout fw68TxLayout(ItlIwx *owner,
                                               struct iwx_softc *sc)
{
    if (!owner || !sc)
        return IntelP2PFirmware::TxLayout::kUnsupported;
    return IntelP2PFirmware::txLayout(
        static_cast<IntelP2PFirmware::DeviceFamily>(sc->sc_device_family),
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_TX_CMD),
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_TX_CMD));
}

static bool supportedFw68Tx(ItlIwx *owner, struct iwx_softc *sc)
{
    return fw68TxLayout(owner, sc) !=
        IntelP2PFirmware::TxLayout::kUnsupported;
}

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
static uint64_t p2pTxEvidenceMonotonicNanoseconds()
{
    uint64_t uptime = 0, nanoseconds = 0;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &nanoseconds);
    return nanoseconds;
}

static uint64_t p2pTxEvidenceLowerBoundUsFromNanoseconds(uint64_t nanoseconds)
{
    return nanoseconds / 1000ULL;
}

static uint64_t p2pTxEvidenceUpperBoundUsFromNanoseconds(uint64_t nanoseconds)
{
    const uint64_t microseconds = nanoseconds / 1000ULL;
    return microseconds + (nanoseconds % 1000ULL != 0 ? 1ULL : 0ULL);
}

static uint64_t p2pTxEvidenceLowerBoundUs()
{
    return p2pTxEvidenceLowerBoundUsFromNanoseconds(
        p2pTxEvidenceMonotonicNanoseconds());
}

static uint64_t p2pTxEvidenceUpperBoundUs()
{
    return p2pTxEvidenceUpperBoundUsFromNanoseconds(
        p2pTxEvidenceMonotonicNanoseconds());
}

static bool sameP2PTxEvidenceEpoch(
    const NativeAwdlTxWindowEvidence::Epoch &left,
    const NativeAwdlTxWindowEvidence::Epoch &right)
{
    return left.contextGeneration == right.contextGeneration &&
        left.powerGeneration == right.powerGeneration &&
        left.stationGeneration == right.stationGeneration &&
        left.rocGeneration == right.rocGeneration;
}

static bool validP2PTxEvidenceMetadata(
    const TahoeP2PActionTxSubmitMetadata *metadata, uint32_t rocToken)
{
    return metadata && metadata->diagnosticGeneration != 0 &&
        metadata->epoch.contextGeneration == metadata->diagnosticGeneration &&
        metadata->epoch.powerGeneration != 0 &&
        metadata->epoch.stationGeneration != 0 &&
        metadata->epoch.rocGeneration != 0 &&
        metadata->epoch.rocGeneration == rocToken &&
        metadata->frameOrdinal != 0 &&
        (metadata->frameKind == NativeAwdlTxWindowEvidence::FrameKind::Psf ||
         metadata->frameKind == NativeAwdlTxWindowEvidence::FrameKind::Mif);
}

static void beginP2PTxEvidenceUpdate(
    TahoeP2PActionTxWindowEvidence *evidence)
{
    if (evidence)
        __atomic_add_fetch(&evidence->snapshotVersion, 1ULL, __ATOMIC_ACQ_REL);
}

static void endP2PTxEvidenceUpdate(
    TahoeP2PActionTxWindowEvidence *evidence)
{
    if (evidence)
        __atomic_add_fetch(&evidence->snapshotVersion, 1ULL, __ATOMIC_RELEASE);
}

static bool beginP2PTxEvidenceGeneration(
    TahoeP2PActionTxContext *context,
    const TahoeP2PActionTxSubmitMetadata *metadata, uint32_t rocToken)
{
    if (!context || !validP2PTxEvidenceMetadata(metadata, rocToken))
        return false;

    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    if (evidence->initialized &&
        evidence->diagnosticGeneration == metadata->diagnosticGeneration)
        return sameP2PTxEvidenceEpoch(evidence->epoch, metadata->epoch);

    beginP2PTxEvidenceUpdate(evidence);
    const NativeAwdlTxWindowEvidence::Status status =
        evidence->ledger.beginDiagnosticGeneration(
            metadata->diagnosticGeneration, metadata->epoch);
    if (status == NativeAwdlTxWindowEvidence::Status::Ready) {
        for (size_t i = 0;
             i < NativeAwdlTxWindowEvidence::kTicketCapacity; ++i)
            evidence->sidecars[i] = TahoeP2PActionTxEvidenceSidecar{};
        evidence->pendingIdentity = {};
        evidence->epoch = metadata->epoch;
        evidence->diagnosticGeneration = metadata->diagnosticGeneration;
        evidence->nextTicketSerial = 0;
        evidence->pendingStatusFlags = 0;
        evidence->droppedTicketCount = 0;
        evidence->pendingIdentityValid = false;
        evidence->initialized = true;
    }
    endP2PTxEvidenceUpdate(evidence);
    return status == NativeAwdlTxWindowEvidence::Status::Ready;
}

static TahoeP2PActionTxEvidenceSidecar *findP2PTxEvidenceSidecar(
    TahoeP2PActionTxWindowEvidence *evidence, uint64_t ticketToken)
{
    if (!evidence || !ticketToken)
        return nullptr;
    for (size_t i = 0; i < NativeAwdlTxWindowEvidence::kTicketCapacity; ++i)
        if (evidence->sidecars[i].used &&
            evidence->sidecars[i].ticketToken == ticketToken)
            return &evidence->sidecars[i];
    return nullptr;
}

static void markP2PTxEvidenceUnknown(
    TahoeP2PActionTxContext *context, uint32_t additionalFlags)
{
    if (!context)
        return;
    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    if (!evidence->initialized || !evidence->pendingIdentityValid)
        return;

    beginP2PTxEvidenceUpdate(evidence);
    (void)evidence->ledger.markPostDoorbellStateUnknown(
        evidence->pendingIdentity);
    TahoeP2PActionTxEvidenceSidecar *sidecar = findP2PTxEvidenceSidecar(
        evidence, evidence->pendingIdentity.ticketToken);
    if (sidecar)
        sidecar->statusFlags |= kP2PTxEvidenceInvalidUnknown |
            additionalFlags;
    evidence->pendingStatusFlags |= kP2PTxEvidenceInvalidUnknown |
        additionalFlags;
    evidence->pendingIdentityValid = false;
    endP2PTxEvidenceUpdate(evidence);
}

static bool prepareP2PTxEvidenceTicket(
    TahoeP2PActionTxContext *context,
    const TahoeP2PActionTxSubmitMetadata *metadata,
    const IntelP2PFirmware::TxLayout layout, ItlIwx *owner,
    struct iwx_softc *sc, uint16_t queueId, uint16_t ringSize,
    uint16_t descriptorIndex, uint16_t sequenceControl,
    uint32_t rocToken, const NativeAwdl::ActionFrameInfo *wireInfo,
    bool wireInfoPresent, uint16_t wireMpduLength)
{
    if (!context || !owner || !sc || !beginP2PTxEvidenceGeneration(
            context, metadata, rocToken))
        return false;

    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    TahoeP2PActionTxSubmitMetadata const &metadataValue = *metadata;
    beginP2PTxEvidenceUpdate(evidence);
    uint64_t ticketSerial = ++evidence->nextTicketSerial;
    if (!ticketSerial)
        ticketSerial = ++evidence->nextTicketSerial;

    NativeAwdlTxWindowEvidence::TicketIdentity identity{};
    identity.diagnosticGeneration = metadataValue.diagnosticGeneration;
    identity.frameKind = metadataValue.frameKind;
    identity.frameOrdinal = metadataValue.frameOrdinal;
    identity.frameSequenceControl = sequenceControl;
    identity.ticketToken = ticketSerial;
    identity.epoch = metadataValue.epoch;
    identity.queueId = queueId;
    identity.ringSize = ringSize;
    identity.descriptorIndex = descriptorIndex;
    identity.peerToken = 0;
    identity.scheduleRevision = 0;
    if (wireInfo && wireInfoPresent) {
        identity.wireInfoPresent = 1;
        identity.wireSubtype = wireInfo->subtype;
        identity.wireMpduLength = wireMpduLength;
        identity.wirePhyTxPresent = 1;
        identity.wireTargetTxPresent = 1;
        identity.wirePhyTxUs = wireInfo->phyTx;
        identity.wireTargetTxUs = wireInfo->targetTx;
    }

    uint32_t sidecarIndex = 0xffffffffu;
    for (size_t i = 0; i < NativeAwdlTxWindowEvidence::kTicketCapacity; ++i) {
        if (!evidence->sidecars[i].used) {
            sidecarIndex = static_cast<uint32_t>(i);
            break;
        }
    }
    evidence->pendingIdentity = identity;
    evidence->pendingIdentityValid = false;
    evidence->pendingTicketPrepared = true;
    evidence->pendingSidecarIndex = sidecarIndex;
    evidence->pendingDeviceFamily = static_cast<uint32_t>(sc->sc_device_family);
    evidence->pendingTxCommandApi = owner->iwx_lookup_cmd_ver(
        sc, IWX_LONG_GROUP, IWX_TX_CMD);
    evidence->pendingTxLayout = static_cast<uint32_t>(layout);
    evidence->pendingStatusFlags = 0;
    endP2PTxEvidenceUpdate(evidence);
    return true;
}

static void discardPreparedP2PTxEvidenceTicket(
    TahoeP2PActionTxContext *context)
{
    if (!context || !context->windowEvidence.pendingTicketPrepared)
        return;
    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    beginP2PTxEvidenceUpdate(evidence);
    evidence->pendingIdentity = {};
    evidence->pendingIdentityValid = false;
    evidence->pendingTicketPrepared = false;
    evidence->pendingSidecarIndex = 0xffffffffu;
    evidence->pendingStatusFlags = 0;
    endP2PTxEvidenceUpdate(evidence);
}

static bool recordP2PTxEvidenceDoorbell(
    TahoeP2PActionTxContext *context)
{
    if (!context || !context->windowEvidence.initialized ||
        !context->windowEvidence.pendingTicketPrepared)
        return false;

    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    beginP2PTxEvidenceUpdate(evidence);
    const NativeAwdlTxWindowEvidence::TicketIdentity identity =
        evidence->pendingIdentity;
    const uint64_t createdAtUs = p2pTxEvidenceLowerBoundUs();
    const NativeAwdlTxWindowEvidence::Status beginStatus =
        evidence->ledger.beginTicket(identity, createdAtUs);
    const bool ticketRecorded =
        beginStatus == NativeAwdlTxWindowEvidence::Status::Ready ||
        beginStatus ==
            NativeAwdlTxWindowEvidence::Status::LocalTicketRecordedUnbound;
    NativeAwdlTxWindowEvidence::Status submissionStatus = beginStatus;
    NativeAwdlTxWindowEvidence::SubmissionWitness submission{};
    submission.identity = identity;
    submission.immediatelyBeforeDoorbellVerified = true;
    submission.sameMonotonicDomainVerified = true;
    const uint64_t lowerUs = p2pTxEvidenceLowerBoundUs();
    if (ticketRecorded) {
        submission.preDoorbellLowerUs = lowerUs;
        submissionStatus = evidence->ledger.recordSubmission(submission);
    }

    TahoeP2PActionTxEvidenceSidecar *sidecar = nullptr;
    if (evidence->pendingSidecarIndex <
        NativeAwdlTxWindowEvidence::kTicketCapacity) {
        TahoeP2PActionTxEvidenceSidecar *candidate =
            &evidence->sidecars[evidence->pendingSidecarIndex];
        if (!candidate->used)
            sidecar = candidate;
    }
    evidence->pendingStatusFlags = kP2PTxEvidenceDoorbellMarked |
        kP2PTxEvidenceSubmitLowerValid;
    if (beginStatus ==
            NativeAwdlTxWindowEvidence::Status::LocalTicketRecordedUnbound)
        evidence->pendingStatusFlags |= kP2PTxEvidenceUnbound;
    if (sidecar && ticketRecorded && submissionStatus ==
            NativeAwdlTxWindowEvidence::Status::Ready) {
        sidecar->ticketToken = identity.ticketToken;
        sidecar->deviceFamily = evidence->pendingDeviceFamily;
        sidecar->txCommandApi = evidence->pendingTxCommandApi;
        sidecar->txLayout = evidence->pendingTxLayout;
        sidecar->statusFlags = evidence->pendingStatusFlags;
        sidecar->used = true;
        evidence->pendingIdentityValid = true;
    } else {
        ++evidence->droppedTicketCount;
        evidence->pendingStatusFlags |= kP2PTxEvidenceInvalidUnknown;
        if (ticketRecorded && submissionStatus !=
                NativeAwdlTxWindowEvidence::Status::Ready)
            (void)evidence->ledger.markPostDoorbellStateUnknown(identity);
        evidence->pendingIdentityValid = false;
    }
    evidence->pendingTicketPrepared = false;
    evidence->pendingSidecarIndex = 0xffffffffu;
    endP2PTxEvidenceUpdate(evidence);
    return evidence->pendingIdentityValid;
}

static void markP2PTxEvidenceDoorbellIssued(
    TahoeP2PActionTxContext *context)
{
    if (!context)
        return;
    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    if (!evidence->initialized || !evidence->pendingIdentityValid)
        return;
    beginP2PTxEvidenceUpdate(evidence);
    TahoeP2PActionTxEvidenceSidecar *sidecar = findP2PTxEvidenceSidecar(
        evidence, evidence->pendingIdentity.ticketToken);
    if (sidecar)
        sidecar->statusFlags |= kP2PTxEvidenceDoorbellIssued;
    evidence->pendingStatusFlags |= kP2PTxEvidenceDoorbellIssued;
    endP2PTxEvidenceUpdate(evidence);
}

static bool pendingP2PTxEvidenceMatchesTicket(
    const TahoeP2PActionTxContext *context,
    const IntelP2PActionTx::Ticket &ticket, uint16_t responseQueue)
{
    if (!context || !context->windowEvidence.initialized ||
        !context->windowEvidence.pendingIdentityValid)
        return false;
    const NativeAwdlTxWindowEvidence::TicketIdentity &identity =
        context->windowEvidence.pendingIdentity;
    return identity.ticketToken != 0 &&
        identity.diagnosticGeneration == context->rocToken &&
        identity.epoch.powerGeneration == ticket.generation &&
        ticket.generation == context->generation &&
        identity.queueId == responseQueue &&
        identity.queueId == ticket.queueId &&
        identity.descriptorIndex == ticket.descriptorIndex &&
        identity.descriptorIndex == context->descriptorIndex;
}

static void recordP2PTxEvidenceCompletion(
    TahoeP2PActionTxContext *context, uint64_t tapUpperUs,
    bool firmwareSuccess)
{
    if (!context)
        return;
    TahoeP2PActionTxWindowEvidence *evidence = &context->windowEvidence;
    if (!evidence->initialized || !evidence->pendingIdentityValid)
        return;

    beginP2PTxEvidenceUpdate(evidence);
    NativeAwdlTxWindowEvidence::CompletionWitness completion{};
    completion.identity = evidence->pendingIdentity;
    completion.notificationTapUpperUs = tapUpperUs;
    completion.source = NativeAwdlTxWindowEvidence::
        CompletionSource::MatchingNotificationTap;
    completion.firmwareOutcome = firmwareSuccess ?
        NativeAwdlTxWindowEvidence::FirmwareOutcome::Success :
        NativeAwdlTxWindowEvidence::FirmwareOutcome::Failure;
    completion.matchingTicketVerified = true;
    completion.matchingIdentityVerified = true;
    completion.upperBoundVerified = true;
    completion.sameMonotonicDomainVerified = true;
    const NativeAwdlTxWindowEvidence::Status status =
        evidence->ledger.recordCompletion(completion);
    TahoeP2PActionTxEvidenceSidecar *sidecar = findP2PTxEvidenceSidecar(
        evidence, evidence->pendingIdentity.ticketToken);
    if (sidecar) {
        if (status == NativeAwdlTxWindowEvidence::Status::Ready &&
            firmwareSuccess) {
            sidecar->statusFlags |= kP2PTxEvidenceCompletionUpperValid |
                kP2PTxEvidenceFirmwareSuccess;
            evidence->pendingStatusFlags |=
                kP2PTxEvidenceCompletionUpperValid |
                kP2PTxEvidenceFirmwareSuccess;
        } else {
            sidecar->statusFlags |= kP2PTxEvidenceInvalidUnknown |
                (firmwareSuccess ? 0u : kP2PTxEvidenceFirmwareFailure);
            evidence->pendingStatusFlags |= kP2PTxEvidenceInvalidUnknown |
                (firmwareSuccess ? 0u : kP2PTxEvidenceFirmwareFailure);
        }
    }
    evidence->pendingIdentityValid = false;
    endP2PTxEvidenceUpdate(evidence);
}
#endif

#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
/*
 * Return one host-monotonic sample; the caller derives a floor for the lower
 * bound and a ceil for the upper bound. This gates software submit timing only,
 * not RF airtime, and cannot close preemption after the sample.
 */
static uint64_t p2pActionSubmitMonotonicNanoseconds()
{
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    return p2pTxEvidenceMonotonicNanoseconds();
#else
    uint64_t uptime = 0, nanoseconds = 0;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &nanoseconds);
    return nanoseconds;
#endif
}

static constexpr uint64_t kControlSubmitMifFreshnessLimitUs = 16ULL * 1024ULL;
static constexpr uint64_t kControlSubmitLeaseReserveUs = 20ULL * 1000ULL;
static constexpr uint64_t kControlSubmitPreparedFrameAgeLimitUs = 10000ULL;

static bool controlSubmitFenceInputValid(
    const TahoeP2PActionTxControlSubmitFence *fence)
{
    if (!fence || fence->phaseOriginUs == 0 || fence->peerMifRxUs == 0 ||
        fence->effectiveEndUs <= fence->phaseOriginUs ||
        fence->peerMifRxUs < fence->phaseOriginUs ||
        fence->preparedFrameUs < fence->peerMifRxUs ||
        fence->preparedFrameMaxAgeUs == 0 ||
        fence->preparedFrameMaxAgeUs >
            kControlSubmitPreparedFrameAgeLimitUs ||
        fence->contextGeneration == 0 || fence->powerGeneration == 0 ||
        fence->stationGeneration == 0 || fence->rocGeneration == 0 ||
        fence->contextGeneration != fence->rocGeneration ||
        fence->peerMifRxUs > ~uint64_t(0) -
            kControlSubmitMifFreshnessLimitUs)
        return false;
    return true;
}

static bool controlSubmitFenceTimeValid(
    const TahoeP2PActionTxControlSubmitFence &fence,
    uint64_t sampleNanoseconds)
{
    const uint64_t lowerBoundUs = sampleNanoseconds / 1000ULL;
    const uint64_t upperBoundUs = lowerBoundUs +
        (sampleNanoseconds % 1000ULL != 0 ? 1ULL : 0ULL);
    const uint64_t freshnessEndUs = fence.peerMifRxUs +
        kControlSubmitMifFreshnessLimitUs;

    if (lowerBoundUs < fence.phaseOriginUs ||
        upperBoundUs < fence.peerMifRxUs ||
        upperBoundUs > freshnessEndUs ||
        upperBoundUs < fence.preparedFrameUs ||
        upperBoundUs - fence.preparedFrameUs >
            fence.preparedFrameMaxAgeUs ||
        fence.effectiveEndUs <= kControlSubmitLeaseReserveUs ||
        upperBoundUs >= fence.effectiveEndUs -
            kControlSubmitLeaseReserveUs)
        return false;
    return true;
}

static bool controlSubmitFenceEpochsMatch(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PActionTxContext *context, uint32_t rocToken,
    bool rocStartObserved, bool rocEndObserved,
    const TahoeP2PActionTxControlSubmitFence &fence)
{
    if (!owner || !sc || !context || !rocStartObserved || rocEndObserved ||
        fence.contextGeneration != rocToken || fence.rocGeneration != rocToken ||
        owner->nativeP2pProbeGeneration_ != fence.contextGeneration ||
        static_cast<uint64_t>(context->generation) != fence.powerGeneration ||
        context->rocToken != fence.rocGeneration ||
        static_cast<uint64_t>(static_cast<uint32_t>(sc->sc_generation)) !=
            fence.powerGeneration ||
        static_cast<uint64_t>(sc->sc_p2p.fw_generation) !=
            fence.powerGeneration ||
        static_cast<uint64_t>(__atomic_load_n(&sc->sc_tx_rate_generation,
                                               __ATOMIC_ACQUIRE)) !=
            fence.stationGeneration ||
        static_cast<uint64_t>(sc->sc_p2p_roc.token) != fence.rocGeneration ||
        static_cast<uint64_t>(sc->sc_p2p_roc.fw_generation) !=
            fence.powerGeneration ||
        sc->sc_p2p_roc.phase != IWX_P2P_ROC_SESSION_ACKED)
        return false;
    return true;
}
#endif

static bool onMainWorkLoopGate(ItlIwx *owner)
{
    return owner && owner->tahoeP2pOnMainGate();
}

static bool consumeCompletedResponseWhileReleasing(
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context,
    uint32_t generation, uint16_t responseQueue)
{
    if (!queueLease || !context || !queueLease->stateLock)
        return false;

    IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        queueLease->stateLock);
    const IntelP2PActionTx::Ticket ticket = context->completion.snapshot();
    const bool consume =
        queueLease->state == TahoeP2PResourceState::kReleasing &&
        queueLease->generation == generation &&
        queueLease->queueId == responseQueue &&
        context->generation == generation &&
        context->queueId == responseQueue &&
        ticket.completed && ticket.generation == generation &&
        ticket.queueId == responseQueue;
    IOSimpleLockUnlockEnableInterrupt(queueLease->stateLock, interruptState);
    return consume;
}

static bool copyAndValidateDiagnosticFrame(mbuf_t frame, size_t frameLength,
                                            const uint8_t source[6],
                                            uint8_t headerAndBody[32],
                                            IntelP2PActionFrame::FrameInfo *info
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
                                            , NativeAwdl::ActionFrameInfo *wireInfo = nullptr,
                                            bool *wireInfoPresent = nullptr
#endif
                                            )
{
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    if (wireInfo)
        *wireInfo = {};
    if (wireInfoPresent)
        *wireInfoPresent = false;
#endif
    if (!frame || frameLength < IntelP2PActionFrame::kMacHeaderLength + 4 ||
        mbuf_len(frame) < 2)
        return false;

    uint8_t fc[2] = {0, 0};
    mbuf_copydata(frame, 0, sizeof(fc), reinterpret_cast<caddr_t>(fc));
    if ((fc[1] & 0x80) != 0) {
        if (frameLength < IntelP2PActionFrame::kMacHeaderWithHtControlLength + 4)
            return false;
        mbuf_copydata(frame, 0, 32, reinterpret_cast<caddr_t>(headerAndBody));
        if (!IntelP2PActionFrame::inspectActionFrame(
                headerAndBody, 32, source, info))
            return false;
    } else {
        mbuf_copydata(frame, 0, 28, reinterpret_cast<caddr_t>(headerAndBody));
        if (!IntelP2PActionFrame::inspectActionFrame(
                headerAndBody, 28, source, info))
            return false;
    }

    if (info->category != IntelP2PActionFrame::kVendorSpecificCategory ||
        info->headerLength + 4 > 32)
        return false;

    // A real AWDL PSF uses Apple's assigned 00:17:f2 OUI and a structured
    // AWDL payload, not the legacy local diagnostic tag below. Keep the
    // existing tag check byte-for-byte for legacy vendor-action probes.
    static const uint8_t awdlOui[3] = {0x00, 0x17, 0xf2};
    if (memcmp(headerAndBody + info->headerLength + 1, awdlOui,
               sizeof(awdlOui)) == 0) {
        if (frameLength > NativeAwdl::kMaximumEncodedMifLength)
            return false;
        uint8_t bytes[NativeAwdl::kMaximumEncodedMifLength] = {};
        mbuf_copydata(frame, 0, static_cast<int>(frameLength),
                      reinterpret_cast<caddr_t>(bytes));
        NativeAwdl::ActionFrameInfo awdlInfo{};
        if (NativeAwdl::parseActionFrame(bytes, frameLength, &awdlInfo) !=
                NativeAwdl::ParseStatus::Ok || awdlInfo.version != 0x10 ||
            info->headerLength != 24)
            return false;
        if (awdlInfo.subtype == 0) {
            if (frameLength > NativeAwdl::kMaximumEncodedPsfLength)
                return false;
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
            if (wireInfo)
                *wireInfo = awdlInfo;
            if (wireInfoPresent)
                *wireInfoPresent = true;
#endif
            return true;
        }
        if (awdlInfo.subtype == 3) {
            if (frameLength > NativeAwdl::kMaximumEncodedMifLength)
                return false;
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
            if (wireInfo)
                *wireInfo = awdlInfo;
            if (wireInfoPresent)
                *wireInfoPresent = true;
#endif
            return true;
        }
        return false;
    }

    if (memcmp(headerAndBody + info->headerLength + 1, source, 3) != 0)
        return false;
    static const uint8_t diagnosticTag[] = "ITL-P2P-PROBE";
    const size_t tagOffset = info->headerLength + 4;
    if (frameLength < tagOffset + sizeof(diagnosticTag) - 1)
        return false;
    uint8_t tag[sizeof(diagnosticTag) - 1];
    mbuf_copydata(frame, static_cast<int>(tagOffset), sizeof(tag),
                  reinterpret_cast<caddr_t>(tag));
    return memcmp(tag, diagnosticTag, sizeof(tag)) == 0;
}

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
static bool nativeResidentProfileEnabled(ItlIwx *owner)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    return controller && controller->getProperty("NativeAwdlResidentEnabled") ==
        kOSBooleanTrue;
}

static void publishNativeIdentityRejected(ItlIwx *owner, uint32_t reason)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PAwdlNativeAddressVerified", uint64_t(0), 32);
    controller->setProperty("NativeP2PAwdlNativeAddressFailure", reason, 32);
}

static bool residentAwdlAddressMatchesAfterHeaderPull(
    mbuf_t frame, size_t frameLength, const uint8_t header[32],
    size_t headerLength, const uint8_t address[6])
{
    if (!frame || !header || headerLength > 32 ||
        frameLength < headerLength ||
        frameLength > NativeAwdl::kMaximumEncodedMifLength)
        return false;
    const size_t bodyLength = frameLength - headerLength;
    if (mbuf_pkthdr_len(frame) != bodyLength)
        return false;
    uint8_t raw[NativeAwdl::kMaximumEncodedMifLength] = {};
    memcpy(raw, header, headerLength);
    if (mbuf_copydata(frame, 0, static_cast<int>(bodyLength),
                      reinterpret_cast<caddr_t>(raw + headerLength)) != 0)
        return false;
    return NativeAwdl::actionFrameAdvertisesAddress(raw, frameLength,
                                                    address);
}
#endif

static uint32_t actionRate6Mbps(ItlIwx *owner, struct iwx_softc *sc)
{
    const uint8_t antennaMask = owner->iwx_fw_valid_tx_ant(sc);
    uint32_t rateNFlags = 0;
    if (!IntelP2PActionTx::encodeLegacyOfdmRateV2(
            IWX_RATE_6M_INDEX, IWX_FIRST_OFDM_RATE, antennaMask,
            IWX_RATE_MCS_ANT_NUM, IWX_RATE_MCS_ANT_POS,
            IWX_RATE_MCS_LEGACY_OFDM_MSK, &rateNFlags))
        return 0;

    /* TX_CMD v9 and v10 both use the RATE_MCS v2 legacy-rate fields. */
    return rateNFlags;
}

static void resetP2PTxRxDiagnostics(TahoeP2PTxRxDiagnostics *diagnostics,
                                    uint16_t targetQueue)
{
    if (!diagnostics)
        return;
    __atomic_store_n(&diagnostics->armed, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&diagnostics->targetQueue, targetQueue, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->rawTxCmdCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->rawTargetHeaderCount, 0u,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->responseQueueMatchCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->foreignQueueCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->shortResponseCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->outOfRangeQueueCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->handlerEntryCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->handlerQueueMatchCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->handlerForeignCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->rejectCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastRejectReason,
                     static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kNone),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastCompletionResult, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->completionCount, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseQueue, 0xffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseFieldsValidMask, 0u,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseFrameCount, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseStatus, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseSequenceControl, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseByteCount, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseFrameControl, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseRaTid, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseScdSsn, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseHeaderIndex, 0xffffffffu,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseHeaderIndexMatchesTicket,
                     0xffffffffu, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseMismatchMask, 0u,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseExpectedSequenceControl,
                     0xffffffffu, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseExpectedByteCount,
                     0xffffffffu, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseExpectedFrameControl,
                     0xffffffffu, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseExpectedDescriptorIndex,
                     0xffffffffu, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastResponseExpectedNextIndex,
                     0xffffffffu, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastRawPacket, ~uint64_t(0),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastTargetRawPacket, ~uint64_t(0),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->dirty, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&diagnostics->armed, 1u, __ATOMIC_RELEASE);
}

static uint32_t readLe32(const uint8_t *bytes)
{
    return uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 |
        uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
}

/* Record bounded scalar response evidence only for the current P2P qid. */
static void recordP2PTxResponseNumbers(
    TahoeP2PTxRxDiagnostics *diagnostics,
    const TahoeP2PActionTxContext *context,
    const uint8_t *payload, size_t payloadLength, uint16_t responseQueue,
    uint8_t rawOpcode, uint8_t rawHeaderQueue, uint8_t rawHeaderIndex)
{
    if (!diagnostics || !context || !payload ||
        !__atomic_load_n(&diagnostics->armed, __ATOMIC_ACQUIRE) ||
        responseQueue != context->queueId ||
        payloadLength < offsetof(struct iwx_tx_resp, tx_queue) +
                        sizeof(uint16_t))
        return;

    uint32_t validMask = 0;
    uint32_t mismatchMask = 0;
    const auto store = [](uint32_t *field, uint32_t value) {
        __atomic_store_n(field, value, __ATOMIC_RELAXED);
    };
    store(&diagnostics->lastResponseFieldsValidMask, 0u);
    store(&diagnostics->lastResponseFrameCount, 0xffffffffu);
    store(&diagnostics->lastResponseStatus, 0xffffffffu);
    store(&diagnostics->lastResponseSequenceControl, 0xffffffffu);
    store(&diagnostics->lastResponseByteCount, 0xffffffffu);
    store(&diagnostics->lastResponseFrameControl, 0xffffffffu);
    store(&diagnostics->lastResponseRaTid, 0xffffffffu);
    store(&diagnostics->lastResponseScdSsn, 0xffffffffu);
    store(&diagnostics->lastResponseHeaderIndex, 0xffffffffu);
    store(&diagnostics->lastResponseHeaderIndexMatchesTicket, 0xffffffffu);
    store(&diagnostics->lastResponseMismatchMask, 0u);
    store(&diagnostics->lastResponseExpectedSequenceControl, 0xffffffffu);
    store(&diagnostics->lastResponseExpectedByteCount, 0xffffffffu);
    store(&diagnostics->lastResponseExpectedFrameControl, 0xffffffffu);
    store(&diagnostics->lastResponseExpectedDescriptorIndex, 0xffffffffu);
    store(&diagnostics->lastResponseExpectedNextIndex, 0xffffffffu);

    if (payloadLength >= sizeof(uint8_t)) {
        const uint32_t frameCount = payload[0];
        store(&diagnostics->lastResponseFrameCount, frameCount);
        validMask |= kP2PTxResponseFrameCountValid;
    }

    const IntelP2PActionTx::Ticket ticket = context->completion.snapshot();
    if (ticket.armed && ticket.generation == context->generation &&
        ticket.queueId == responseQueue && ticket.ringSize != 0 &&
        (ticket.ringSize & (ticket.ringSize - 1)) == 0 &&
        ticket.descriptorIndex < ticket.ringSize) {
        const uint32_t expectedNextIndex =
            (ticket.descriptorIndex + 1u) & (ticket.ringSize - 1u);
        store(&diagnostics->lastResponseExpectedSequenceControl,
              ticket.sequenceControl);
        store(&diagnostics->lastResponseExpectedByteCount,
              ticket.byteCount);
        store(&diagnostics->lastResponseExpectedFrameControl,
              ticket.frameControl);
        store(&diagnostics->lastResponseExpectedDescriptorIndex,
              ticket.descriptorIndex);
        store(&diagnostics->lastResponseExpectedNextIndex,
              expectedNextIndex);
        validMask |= kP2PTxResponseTicketExpectedValid;
    }

    if (payloadLength >= offsetof(struct iwx_tx_resp, seq_ctl) + sizeof(uint16_t)) {
        const uint32_t sequenceControl =
            le16toh(reinterpret_cast<const struct iwx_tx_resp *>(payload)->seq_ctl);
        store(&diagnostics->lastResponseSequenceControl, sequenceControl);
        validMask |= kP2PTxResponseSequenceControlValid;
        if ((validMask & kP2PTxResponseTicketExpectedValid) &&
            sequenceControl != ticket.sequenceControl)
            mismatchMask |= kP2PTxResponseSequenceControlMismatch;
    }
    if (payloadLength >= offsetof(struct iwx_tx_resp, byte_cnt) + sizeof(uint16_t)) {
        const uint32_t byteCount =
            le16toh(reinterpret_cast<const struct iwx_tx_resp *>(payload)->byte_cnt);
        store(&diagnostics->lastResponseByteCount, byteCount);
        validMask |= kP2PTxResponseByteCountValid;
    }
    if (payloadLength >= offsetof(struct iwx_tx_resp, frame_ctrl) + sizeof(uint16_t)) {
        const uint32_t frameControl =
            le16toh(reinterpret_cast<const struct iwx_tx_resp *>(payload)->frame_ctrl);
        store(&diagnostics->lastResponseFrameControl, frameControl);
        validMask |= kP2PTxResponseFrameControlValid;
    }
    if (payloadLength >= offsetof(struct iwx_tx_resp, ra_tid) + sizeof(uint8_t)) {
        store(&diagnostics->lastResponseRaTid,
              payload[offsetof(struct iwx_tx_resp, ra_tid)]);
        validMask |= kP2PTxResponseRaTidValid;
    }
    if (payloadLength >= offsetof(struct iwx_tx_resp, status) + sizeof(uint16_t)) {
        const uint32_t status =
            le16toh(reinterpret_cast<const struct iwx_tx_resp *>(payload)->status.status);
        store(&diagnostics->lastResponseStatus, status);
        validMask |= kP2PTxResponseStatusValid;
    }

    if (payloadLength >= sizeof(uint8_t)) {
        const size_t statusOffset = offsetof(struct iwx_tx_resp, status);
        const size_t statusCount = payload[0];
        // The trailing SCD SSN follows one four-byte status entry per frame.
        if (statusCount != 0 &&
            statusCount <= (SIZE_MAX - statusOffset) /
                           sizeof(struct iwx_agg_tx_status)) {
            const size_t ssnOffset = statusOffset +
                statusCount * sizeof(struct iwx_agg_tx_status);
            if (ssnOffset <= payloadLength &&
                payloadLength - ssnOffset >= sizeof(uint32_t)) {
                const uint32_t scdSsn = readLe32(payload + ssnOffset);
                store(&diagnostics->lastResponseScdSsn, scdSsn);
                validMask |= kP2PTxResponseScdSsnValid;
                if (validMask & kP2PTxResponseTicketExpectedValid) {
                    // Keep the completion parser's contract: first take the
                    // low 12 SCD bits, then mask by the power-of-two ring size.
                    const uint32_t nextIndex =
                        (scdSsn & 0x0fffu) & (ticket.ringSize - 1u);
                    if (nextIndex !=
                        __atomic_load_n(&diagnostics->lastResponseExpectedNextIndex,
                                        __ATOMIC_RELAXED))
                        mismatchMask |= kP2PTxResponseScdIndexMismatch;
                }
            }
        }
    }

    // Use this notification's header, not the shared last-raw tuple: another
    // queue may update that diagnostic concurrently after RX observation.
    if (rawOpcode == IWX_TX_CMD &&
        (rawHeaderQueue & 0x7fu) == responseQueue) {
        store(&diagnostics->lastResponseHeaderIndex, rawHeaderIndex);
        store(&diagnostics->lastResponseHeaderIndexMatchesTicket,
              (validMask & kP2PTxResponseTicketExpectedValid) &&
              rawHeaderIndex == ticket.descriptorIndex ? 1u : 0u);
        validMask |= kP2PTxResponseHeaderIndexValid;
    }

    store(&diagnostics->lastResponseMismatchMask, mismatchMask);
    __atomic_store_n(&diagnostics->lastResponseFieldsValidMask, validMask,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&diagnostics->dirty, 1u, __ATOMIC_RELEASE);
}

static void recordP2PTxRxReject(
    TahoeP2PTxRxDiagnostics *diagnostics,
    TahoeP2PTxRxRejectReason reason,
    uint32_t completionResult = 0xffffffffu)
{
    if (!diagnostics ||
        !__atomic_load_n(&diagnostics->armed, __ATOMIC_ACQUIRE))
        return;
    __atomic_store_n(&diagnostics->lastRejectReason,
                     static_cast<uint32_t>(reason), __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->lastCompletionResult, completionResult,
                     __ATOMIC_RELAXED);
    __atomic_add_fetch(&diagnostics->rejectCount, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics->dirty, 1u, __ATOMIC_RELEASE);
}

static uint32_t actionStateValue(const TahoeP2PActionTxContext *context)
{
    if (!context)
        return 0xffffffffu;
    return __atomic_load_n(
        reinterpret_cast<const uint8_t *>(&context->state), __ATOMIC_ACQUIRE);
}

static uint32_t preArmTicketFlags(const IntelP2PActionTx::Ticket &ticket)
{
    return (ticket.armed ? 1u : 0u) | (ticket.completed ? 2u : 0u);
}

static void recordPreArmEvent(
    TahoeP2PActionTxContext *context, TahoeP2PPreArmEventSource source,
    const TahoeP2PTxQueueLease *queueLease, uint16_t queueId,
    uint32_t raTid, const IntelP2PActionTx::Ticket &ticket)
{
    if (!context)
        return;
    TahoeP2PActionTxPreArmDiagnostics &diagnostics =
        context->preArmDiagnostics;
    __atomic_store_n(&diagnostics.lastQueueId, uint32_t(queueId),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastRaTid, raTid, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastLeaseState,
        queueLease ? static_cast<uint32_t>(queueLease->state) : 0xffffffffu,
        __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastActionState,
        actionStateValue(context), __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastTicketFlags,
        preArmTicketFlags(ticket), __ATOMIC_RELAXED);
    __atomic_add_fetch(&diagnostics.eventCount, 1u, __ATOMIC_RELAXED);
    // Store the source last so a reader that observes it with acquire ordering
    // also observes the numeric context fields above.
    __atomic_store_n(&diagnostics.lastSource, static_cast<uint32_t>(source),
                     __ATOMIC_RELEASE);
}

static void recordSubmitStage(TahoeP2PActionTxContext *context,
                              TahoeP2PActionTxSubmitStage stage,
                              int result, bool newAttempt = false)
{
    if (!context)
        return;
    TahoeP2PActionTxSubmitDiagnostics &diagnostics =
        context->submitDiagnostics;
    if (newAttempt)
        __atomic_add_fetch(&diagnostics.attemptCount, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastResult, static_cast<int32_t>(result),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastStage, static_cast<uint32_t>(stage),
                     __ATOMIC_RELEASE);
}

static void incrementP2PTxRxCounter(TahoeP2PTxRxDiagnostics *diagnostics,
                                    uint32_t *counter)
{
    if (!diagnostics || !counter ||
        !__atomic_load_n(&diagnostics->armed, __ATOMIC_ACQUIRE))
        return;
    __atomic_add_fetch(counter, 1u, __ATOMIC_RELAXED);
}

} // namespace

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
bool iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(ItlIwx *owner)
{
    if (!owner || !owner->tahoeP2pOnMainGate())
        return false;
    IOEthernetController *controller = owner->tahoeP2pController();
    if (!controller)
        return false;

    uint32_t expected = 2u;
    if (!__atomic_compare_exchange_n(&pendingQmWireSnapshotState, &expected,
            3u, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return false;

    // This runs after the probe's publication-busy guard, outside the TX
    // doorbell/finish path. A single small immutable OSData object gives the
    // registry reader an all-or-nothing snapshot; no field-by-field marker is
    // needed, and allocation/property failure leaves no completion record.
    const QmWireSnapshotRecord record = pendingQmWireSnapshot;
    const NativeAwdlQmWireSnapshot::EncodedSnapshot encoded =
        NativeAwdlQmWireSnapshot::encode(record);
    OSData *payload = OSData::withBytes(encoded.bytes, sizeof(encoded.bytes));
    const bool published = payload && controller->setProperty(
        "NativeP2PQmWireSnapshot", payload);
    if (payload)
        payload->release();
    __atomic_store_n(&pendingQmWireSnapshotState,
                     published ? 4u : 5u, __ATOMIC_RELEASE);
    return published;
}
#endif

bool iwx_tahoe_p2p_action_reject_ba_queue(
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context, uint16_t queueId)
{
    if (!queueLease || !context ||
        !iwx_tahoe_p2p_tvqm_queue_owned(queueLease, queueId))
        return false;
    const IntelP2PActionTx::Ticket ticket = context->completion.snapshot();
    const uint32_t state = actionStateValue(context);
    const bool noLiveTicket = !ticket.armed || ticket.completed;
    const bool knownIdle = state == static_cast<uint32_t>(
            TahoeP2PActionTxState::kIdle) && noLiveTicket &&
        queueLease->state != TahoeP2PResourceState::kUnknown &&
        queueLease->stateLock != nullptr;
    recordPreArmEvent(context,
        knownIdle ? TahoeP2PPreArmEventSource::kOwnedBlockAckNoLiveTicket :
                    TahoeP2PPreArmEventSource::kOwnedBlockAckOwnershipUnknown,
        queueLease, queueId, 0xffffffffu, ticket);
    if (!knownIdle) {
        __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
            static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
            __ATOMIC_RELEASE);
        recordP2PTxRxReject(&context->rxDiagnostics,
            TahoeP2PTxRxRejectReason::kUnexpectedBlockAck);
    }
    return true;
}

void iwx_tahoe_p2p_action_tx_observe_rx(
    TahoeP2PActionTxContext *context, uint8_t rawGroup, uint8_t rawOpcode,
    uint8_t rawHeaderQueue, uint8_t rawIndex, size_t payloadLength)
{
    if (!context || rawOpcode != IWX_TX_CMD)
        return;
    TahoeP2PTxRxDiagnostics *diagnostics = &context->rxDiagnostics;
    if (!__atomic_load_n(&diagnostics->armed, __ATOMIC_ACQUIRE))
        return;

    const uint32_t rawHeader = (uint32_t(rawGroup) << 24) |
        (uint32_t(rawOpcode) << 16) | (uint32_t(rawHeaderQueue) << 8) |
        uint32_t(rawIndex);
    const uint32_t boundedLength = payloadLength > 0xffffffffu ?
        0xffffffffu : static_cast<uint32_t>(payloadLength);
    const uint64_t rawPacket = (uint64_t(rawHeader) << 32) | boundedLength;
    __atomic_store_n(&diagnostics->lastRawPacket, rawPacket, __ATOMIC_RELAXED);
    incrementP2PTxRxCounter(diagnostics, &diagnostics->rawTxCmdCount);

    // The raw header qid is only a candidate match; TX_RSP payload parsing in
    // the handler is still required to prove which TX queue responded.
    const uint32_t targetQueue = __atomic_load_n(&diagnostics->targetQueue,
                                                 __ATOMIC_RELAXED);
    if ((rawHeaderQueue & 0x7f) == targetQueue) {
        __atomic_store_n(&diagnostics->lastTargetRawPacket, rawPacket,
                         __ATOMIC_RELAXED);
        incrementP2PTxRxCounter(diagnostics,
                                &diagnostics->rawTargetHeaderCount);
    }
}

int iwx_tahoe_p2p_action_tx_submit(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context,
    uint32_t rocToken, bool rocStartObserved, bool rocEndObserved,
    mbuf_t frame, uint64_t nativeDataToken
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    , const TahoeP2PActionTxSubmitMetadata *evidenceMetadata
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    , uint64_t estimatedNotBeforeUs,
    uint64_t estimatedDeadlineUs,
    uint32_t experimentalStationGeneration,
    const TahoeP2PActionTxControlSubmitFence *controlSubmitFence
#endif
    )
{
    /* This helper consumes its input on every path, including preflight errors. */
    recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kNone, 0, true);
    if (!frame) {
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kInvalidArgument, EINVAL);
        return EINVAL;
    }

    if (!owner || !sc || sc != &owner->com || !queueLease || !context ||
        !onMainWorkLoopGate(owner) || !owner->nativeP2pBusy()) {
        mbuf_freem(frame);
        recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kOwnerOrGate,
                          EBUSY);
        return EBUSY;
    }
    const IntelP2PFirmware::TxLayout layout = fw68TxLayout(owner, sc);
    if (layout == IntelP2PFirmware::TxLayout::kUnsupported) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kUnsupportedLayout, EOPNOTSUPP);
        return EOPNOTSUPP;
    }

    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    const struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    if (!rocStartObserved || rocEndObserved || rocToken == 0 ||
        roc.token != rocToken || roc.fw_generation != generation ||
        (roc.phase != IWX_P2P_ROC_SESSION_ACKED &&
         roc.phase != IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN) ||
        !sc->sc_p2p.initialized || sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased ||
        sc->sc_p2p.fw_generation != generation ||
        sc->sc_ic.ic_state != IEEE80211_S_RUN || sc->sc_ic.ic_bss == nullptr) {
        mbuf_freem(frame);
        recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kRocOrResource,
                          EBUSY);
        return EBUSY;
    }
    const uint32_t currentState = actionStateValue(context);
    if (currentState == static_cast<uint32_t>(
            TahoeP2PActionTxState::kInFlight)) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kContextInFlight, EBUSY);
        return EBUSY;
    }
    if (currentState == static_cast<uint32_t>(
            TahoeP2PActionTxState::kQuarantined)) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kContextQuarantined, EBUSY);
        return EBUSY;
    }
    const IntelP2PActionTx::Ticket previousTicket =
        context->completion.snapshot();
    if (previousTicket.armed && !previousTicket.completed) {
        __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
            static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
            __ATOMIC_RELEASE);
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kExistingTicketUnknown, EBUSY);
        return EBUSY;
    }
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    const bool hasEstimatedWindow = estimatedNotBeforeUs != 0 ||
        estimatedDeadlineUs != 0 || experimentalStationGeneration != 0;
    const bool estimatedWindowValid = estimatedNotBeforeUs != 0 &&
        estimatedDeadlineUs != 0 &&
        estimatedDeadlineUs > estimatedNotBeforeUs && nativeDataToken != 0 &&
        experimentalStationGeneration != 0;
    if (hasEstimatedWindow && !estimatedWindowValid) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kExperimentalDeadline, EINVAL);
        return EINVAL;
    }
    if (controlSubmitFence &&
        !controlSubmitFenceInputValid(controlSubmitFence)) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kControlSubmitFence, EINVAL);
        return EINVAL;
    }
#endif
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    beginP2PTxEvidenceUpdate(&context->windowEvidence);
    context->windowEvidence.pendingIdentityValid = false;
    context->windowEvidence.pendingTicketPrepared = false;
    context->windowEvidence.pendingIdentity = {};
    context->windowEvidence.pendingSidecarIndex = 0xffffffffu;
    context->windowEvidence.pendingStatusFlags = 0;
    endP2PTxEvidenceUpdate(&context->windowEvidence);
#endif

    const size_t frameLength = mbuf_pkthdr_len(frame);
    if (frameLength < IntelP2PActionFrame::kMacHeaderLength + 4 ||
        frameLength > MCLBYTES || frameLength > 0xffff) {
        mbuf_freem(frame);
        recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kFrameLength,
                          EMSGSIZE);
        return EMSGSIZE;
    }

    uint8_t frameHeaderAndBody[32] = {};
    IntelP2PActionFrame::FrameInfo frameInfo{};
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    NativeAwdl::ActionFrameInfo wireInfo{};
    bool wireInfoPresent = false;
#endif
    bool validData=false;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    uint16_t nativeDataPacketCount = 0;
    uint32_t nativeDataIpv6Length = 0;
    bool ipv6DestinationIsAirdropMdns = false;
    if(nativeDataToken&&frameLength<=2048) {
        uint8_t raw[2048];
        NativeAwdlData::DecodedFrame dataInfo{};
        if(mbuf_copydata(frame,0,frameLength,raw)==0&&
           NativeAwdlData::decodeIpv6DataMpdu(raw,frameLength,&dataInfo)==NativeAwdlData::Status::Ok&&
           dataInfo.frameControl==0x0008&&dataInfo.packetCount==1&&
           !memcmp(dataInfo.sourceAddress,sc->sc_p2p.mac_address,6)) {
            nativeDataPacketCount = dataInfo.packetCount;
            nativeDataIpv6Length = static_cast<uint32_t>(
                dataInfo.packets[0].ipv6Length);
            // DecodedFrame borrows packet bytes from this stack buffer. Keep
            // only the mDNS-group fact before `raw` leaves scope.
            const uint8_t *ipv6Packet = dataInfo.packets[0].ipv6Packet;
            if (ipv6Packet && dataInfo.packets[0].ipv6Length >= 40)
                ipv6DestinationIsAirdropMdns =
                    NativeAwdlQmWireSnapshot::isAirdropMdnsGroupDestination(
                        ipv6Packet + 24);
            memcpy(frameHeaderAndBody,raw,24);
            frameInfo.headerLength=24;frameInfo.frameControl=0x0008;
            frameInfo.sequenceControl=uint16_t(raw[22]|(uint16_t(raw[23])<<8));validData=true;
        }
    }
#endif
    if ((nativeDataToken&&!validData)||(!nativeDataToken&&!copyAndValidateDiagnosticFrame(frame, frameLength,
                                        sc->sc_p2p.mac_address,
                                        frameHeaderAndBody, &frameInfo
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
                                        , &wireInfo, &wireInfoPresent
#endif
                                        ))) {
        mbuf_freem(frame);
        recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kFrameEncoding,
                          EINVAL);
        return EINVAL;
    }
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    const bool qmWireSnapshotCandidate = nativeDataToken && validData &&
        nativeDataPacketCount == 1 &&
        hasEligibleQmTraceToken(context, nativeDataToken);
#endif
    if (frameInfo.headerLength != ieee80211_get_hdrlen(
            reinterpret_cast<const struct ieee80211_frame *>(frameHeaderAndBody))) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kMacHeaderLength, EINVAL);
        return EINVAL;
    }

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeDataToken && nativeDataPacketCount == 1) {
        (void)context->dataTxTrace.markFinalWire(
            nativeDataToken, rocToken, generation, rocToken,
            frameInfo.frameControl, frameInfo.sequenceControl,
            static_cast<uint16_t>(frameLength),
            nativeDataPacketCount, nativeDataIpv6Length,
            p2pActionMonotonicUs());
    }
#endif

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    bool residentAddressBound = false;
    bool residentAdvertisementRequired = false;
    uint8_t residentAddress[6]{};
    if (nativeResidentProfileEnabled(owner)) {
        bool identityMatches =
            NativeAwdlBSD::address(generation, residentAddress) &&
            memcmp(residentAddress, sc->sc_p2p.mac_address, 6) == 0 &&
            memcmp(residentAddress, frameHeaderAndBody + 10, 6) == 0;
        static const uint8_t awdlOui[3] = {0x00, 0x17, 0xf2};
        const bool awdlFrame = !nativeDataToken &&
            frameInfo.headerLength == IntelP2PActionFrame::kMacHeaderLength &&
            frameHeaderAndBody[frameInfo.headerLength] == 127 &&
            memcmp(frameHeaderAndBody + frameInfo.headerLength + 1,
                   awdlOui, sizeof(awdlOui)) == 0;
        if (identityMatches && awdlFrame) {
            if (frameLength > NativeAwdl::kMaximumEncodedMifLength) {
                identityMatches = false;
            } else {
                uint8_t raw[NativeAwdl::kMaximumEncodedMifLength]{};
                identityMatches =
                    mbuf_copydata(frame, 0, static_cast<int>(frameLength),
                        reinterpret_cast<caddr_t>(raw)) == 0 &&
                    NativeAwdl::actionFrameAdvertisesAddress(raw, frameLength,
                                                             residentAddress);
            }
            residentAdvertisementRequired = true;
        }
        if (!identityMatches) {
            publishNativeIdentityRejected(owner, 10);
            mbuf_freem(frame);
            recordSubmitStage(context,
                TahoeP2PActionTxSubmitStage::kNativeAwdlIdentity,
                EADDRNOTAVAIL);
            return EADDRNOTAVAIL;
        }
        residentAddressBound = true;
    }
#endif

    const uint32_t rate = actionRate6Mbps(owner, sc);
    if (rate == 0) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kRateUnavailable, EOPNOTSUPP);
        return EOPNOTSUPP;
    }

    struct iwx_tx_ring *ring = nullptr;
    uint16_t index = 0;
    int error = iwx_tahoe_p2p_tvqm_begin_tx(sc, queueLease, &ring, &index);
    if (error) {
        mbuf_freem(frame);
        recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kBeginTx,
                          error);
        return error;
    }

    const auto cancelBeforeDoorbell = [&] (
        TahoeP2PActionTxSubmitStage stage, int result) -> int {
        recordSubmitStage(context, stage, result);
        clearPreparedSlot(ring, index);
        const int cancelError = iwx_tahoe_p2p_tvqm_cancel_tx_submit(queueLease);
        mbuf_freem(frame);
        if (cancelError) {
            __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
                static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
                __ATOMIC_RELEASE);
            recordSubmitStage(context,
                TahoeP2PActionTxSubmitStage::kPreDoorbellCancelFailed,
                cancelError);
            return cancelError;
        }
        return result;
    };

    if (!ring || ring->qid < 0 || ring->qid > 0xff ||
        ring->qid != queueLease->queueId || ring->ring_count < 8 ||
        ring->ring_count > IWX_TFD_QUEUE_SIZE_MAX ||
        (ring->ring_count & (ring->ring_count - 1)) != 0 ||
        index >= ring->ring_count || ring->cur != index || ring->tail != index ||
        ring->queued != 0 || ring->data[index].m != nullptr ||
        ring->data[index].in != nullptr || ring->data[index].map == nullptr ||
        ring->data[index].map->cursor == nullptr ||
        ring->desc == nullptr || ring->cmd == nullptr) {
        return cancelBeforeDoorbell(TahoeP2PActionTxSubmitStage::kRingShape,
                                    EIO);
    }

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeDataToken)
        (void)context->dataTxTrace.markRing(nativeDataToken, rocToken,
            generation, rocToken, static_cast<uint16_t>(ring->qid),
            static_cast<uint16_t>(ring->ring_count), index,
            p2pActionMonotonicUs());
#endif

    struct iwx_tx_data *txData = &ring->data[index];
    struct iwx_tfh_tfd *descriptor = &ring->desc[index];
    struct iwx_device_cmd *deviceCommand = &ring->cmd[index];

    /* The baseline iwx_tx path maps the mbuf through this natural cursor and
     * keeps the mbuf attached to the ring slot through TX_RSP completion. */
    mbuf_adj(frame, static_cast<int>(frameInfo.headerLength));
    IOPhysicalSegment segments[IWX_TFH_NUM_TBS - 2];
    const int segmentCount = txData->map->cursor->getPhysicalSegmentsWithCoalesce(
        frame, segments, IWX_TFH_NUM_TBS - 2);
    if (segmentCount <= 0 || segmentCount > IWX_TFH_NUM_TBS - 2)
        return cancelBeforeDoorbell(
            TahoeP2PActionTxSubmitStage::kPayloadMapping, ENOMEM);

    uint16_t segmentLengths[IWX_TFH_NUM_TBS - 2];
    for (int i = 0; i < segmentCount; ++i) {
        if (segments[i].length == 0 || segments[i].length > 0xffff)
            return cancelBeforeDoorbell(
                TahoeP2PActionTxSubmitStage::kPayloadSegmentLength,
                EMSGSIZE);
        segmentLengths[i] = static_cast<uint16_t>(segments[i].length);
    }
    IntelP2PActionFrame::TfdPlan plan{};
    const size_t txCommandLength =
        layout == IntelP2PFirmware::TxLayout::kGen2 ?
            sizeof(struct iwx_tx_cmd_gen2) : sizeof(struct iwx_tx_cmd_gen3);
    if (!IntelP2PActionFrame::buildTfdPlan(
            sizeof(struct iwx_cmd_header), txCommandLength,
            frameInfo.headerLength, segmentLengths,
            static_cast<size_t>(segmentCount), frameLength, &plan))
        return cancelBeforeDoorbell(TahoeP2PActionTxSubmitStage::kTfdPlan,
                                    EINVAL);

    const uint16_t sequenceControl = frameInfo.sequenceControl;
    const IntelP2PActionTx::Result armResult = context->completion.arm(generation,
        static_cast<uint16_t>(ring->qid), static_cast<uint16_t>(ring->ring_count),
        index, sequenceControl, static_cast<uint16_t>(frameLength),
        frameInfo.frameControl);
    if (armResult != IntelP2PActionTx::Result::kReady)
        return cancelBeforeDoorbell(TahoeP2PActionTxSubmitStage::kTicketArm,
                                    EBUSY);

    memset(descriptor, 0, sizeof(*descriptor));
    memset(deviceCommand, 0, sizeof(*deviceCommand));
    deviceCommand->hdr.cmd = IWX_TX_CMD;
    deviceCommand->hdr.group_id = 0;
    deviceCommand->hdr.qid = static_cast<uint8_t>(ring->qid);
    deviceCommand->hdr.idx = static_cast<uint8_t>(index);

    const uint32_t txFlags = IWX_TX_FLAGS_CMD_RATE |
        IWX_TX_FLAGS_ENCRYPT_DIS | IWX_TX_FLAGS_HIGH_PRI;
    // 22000 TX_CMD v9 uses FLAGS v3. The older FLG_ACK bit is not part of
    // this ABI (that bit is RTS in newer variants); do not transplant it.
    // Firmware uses this field to find the MAC header in the TX payload.
    // Firmware encodes MH_SIZE in 16-bit words in both TX_CMD layouts.
    const uint32_t offloadAssist = IWX_TX_CMD_OFFLD_MH_SIZE(
        static_cast<uint32_t>(frameInfo.headerLength / sizeof(uint16_t)));
    if (layout == IntelP2PFirmware::TxLayout::kGen2) {
        struct iwx_tx_cmd_gen2 *txCommand =
            reinterpret_cast<struct iwx_tx_cmd_gen2 *>(deviceCommand->data);
        memset(txCommand, 0, sizeof(*txCommand));
        txCommand->len = htole16(static_cast<uint16_t>(frameLength));
        txCommand->offload_assist = htole16(
            static_cast<uint16_t>(offloadAssist));
        txCommand->flags = htole32(txFlags);
        txCommand->rate_n_flags = htole32(rate);
        memcpy(reinterpret_cast<uint8_t *>(txCommand) + sizeof(*txCommand),
               frameHeaderAndBody, frameInfo.headerLength);
    } else {
        struct iwx_tx_cmd_gen3 *txCommand =
            reinterpret_cast<struct iwx_tx_cmd_gen3 *>(deviceCommand->data);
        memset(txCommand, 0, sizeof(*txCommand));
        txCommand->len = htole16(static_cast<uint16_t>(frameLength));
        txCommand->flags = htole16(static_cast<uint16_t>(txFlags));
        txCommand->offload_assist = htole32(offloadAssist);
        txCommand->rate_n_flags = htole32(rate);
        memcpy(reinterpret_cast<uint8_t *>(txCommand) + sizeof(*txCommand),
               frameHeaderAndBody, frameInfo.headerLength);
    }

    descriptor->num_tbs = htole16(plan.numTbs);
    descriptor->tbs[0].tb_len = htole16(plan.firstTbLength);
    uint64_t paddr = htole64(txData->cmd_paddr);
    memcpy(&descriptor->tbs[0].addr, &paddr, sizeof(paddr));
    descriptor->tbs[1].tb_len = htole16(plan.commandTailLength);
    paddr = htole64(txData->cmd_paddr + plan.firstTbLength);
    memcpy(&descriptor->tbs[1].addr, &paddr, sizeof(paddr));
    for (int i = 0; i < segmentCount; ++i) {
        descriptor->tbs[i + 2].tb_len = htole16(segmentLengths[i]);
        paddr = htole64(segments[i].location);
        memcpy(&descriptor->tbs[i + 2].addr, &paddr, sizeof(paddr));
    }

    txData->m = frame;
    txData->in = nullptr; // stationless P2P queue has no IEEE 802.11 node
    txData->type = validData?IEEE80211_FC0_TYPE_DATA:IEEE80211_FC0_TYPE_MGT;
    owner->iwx_tx_update_byte_tbl(sc, ring, index, plan.frameByteCount,
                                  plan.numTbs);

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeDataToken)
        (void)context->dataTxTrace.markDescriptorReady(nativeDataToken,
                                                       p2pActionMonotonicUs());
#endif

    context->generation = generation;
    context->rocToken = rocToken;
    context->queueId = static_cast<uint16_t>(ring->qid);
    context->descriptorIndex = index;
    context->sequenceControl = sequenceControl;
    context->frameControl = frameInfo.frameControl;
    context->frameByteCount = static_cast<uint16_t>(frameLength);
    __atomic_store_n(&context->nativeDataToken, nativeDataToken, __ATOMIC_RELEASE);
    context->state = TahoeP2PActionTxState::kInFlight;
    resetP2PTxRxDiagnostics(&context->rxDiagnostics,
                            static_cast<uint16_t>(ring->qid));

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (residentAddressBound) {
        uint8_t liveAddress[6]{};
        bool identityMatches =
            NativeAwdlBSD::address(generation, liveAddress) &&
            memcmp(liveAddress, residentAddress, 6) == 0 &&
            memcmp(liveAddress, sc->sc_p2p.mac_address, 6) == 0 &&
            memcmp(liveAddress, frameHeaderAndBody + 10, 6) == 0;
        if (identityMatches && residentAdvertisementRequired)
            identityMatches = residentAwdlAddressMatchesAfterHeaderPull(
                frame, frameLength, frameHeaderAndBody,
                frameInfo.headerLength, liveAddress);
        if (!identityMatches) {
            publishNativeIdentityRejected(owner, 11);
            const IntelP2PActionTx::Result cancelTicket =
                context->completion.cancelUnsubmitted(
                    generation, static_cast<uint16_t>(ring->qid), index);
            if (cancelTicket != IntelP2PActionTx::Result::kCancelled) {
                publishNativeIdentityRejected(owner, 12);
                context->state = TahoeP2PActionTxState::kQuarantined;
                recordSubmitStage(context,
                    TahoeP2PActionTxSubmitStage::kPreDoorbellCancelFailed,
                    static_cast<int>(cancelTicket));
                return EADDRNOTAVAIL;
            }
            __atomic_store_n(&context->rxDiagnostics.armed, 0u,
                             __ATOMIC_RELEASE);
            context->state = TahoeP2PActionTxState::kIdle;
            __atomic_store_n(&context->nativeDataToken, uint64_t(0), __ATOMIC_RELEASE);
            return cancelBeforeDoorbell(
                TahoeP2PActionTxSubmitStage::kNativeAwdlIdentity,
                EADDRNOTAVAIL);
        }
    }
#endif

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    if (evidenceMetadata)
        (void)prepareP2PTxEvidenceTicket(
            context, evidenceMetadata, layout, owner, sc,
            static_cast<uint16_t>(ring->qid),
            static_cast<uint16_t>(ring->ring_count), index, sequenceControl,
            rocToken, &wireInfo, wireInfoPresent,
            static_cast<uint16_t>(frameLength));
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (estimatedWindowValid) {
        const bool currentRoc = sc->sc_p2p_roc.token == rocToken &&
            sc->sc_p2p_roc.fw_generation == generation &&
            sc->sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED;
        const bool epochCurrent =
            owner->nativeP2pProbeGeneration_ == rocToken &&
            static_cast<uint32_t>(sc->sc_generation) == generation &&
            currentRoc && sc->sc_p2p.fw_generation == generation &&
            __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) ==
                experimentalStationGeneration;
        // Keep the time sample as the last gate before queue commit. This is
        // still an estimate: scheduler preemption after this sample is outside
        // the check and no RF airtime guarantee is implied.
        const uint64_t submitNanoseconds = epochCurrent ?
            p2pActionSubmitMonotonicNanoseconds() : 0;
        const uint64_t submitLowerBoundUs = submitNanoseconds / 1000ULL;
        const uint64_t submitUpperBoundUs = submitLowerBoundUs +
            (submitNanoseconds % 1000ULL != 0 ? 1ULL : 0ULL);
        const bool insideEstimatedWindow = epochCurrent &&
            submitLowerBoundUs >= estimatedNotBeforeUs &&
            submitUpperBoundUs < estimatedDeadlineUs;
        if (!epochCurrent || !insideEstimatedWindow) {
            const int rejectError = !epochCurrent ? ESTALE : ETIMEDOUT;
            const IntelP2PActionTx::Result cancelTicket =
                context->completion.cancelUnsubmitted(
                    generation, static_cast<uint16_t>(ring->qid), index);
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
            discardPreparedP2PTxEvidenceTicket(context);
#endif
            if (cancelTicket != IntelP2PActionTx::Result::kCancelled) {
                context->state = TahoeP2PActionTxState::kQuarantined;
                recordSubmitStage(context,
                    TahoeP2PActionTxSubmitStage::kPreDoorbellCancelFailed,
                    static_cast<int>(cancelTicket));
                return rejectError;
            }
            __atomic_store_n(&context->rxDiagnostics.armed, 0u,
                             __ATOMIC_RELEASE);
            context->state = TahoeP2PActionTxState::kIdle;
            __atomic_store_n(&context->nativeDataToken, uint64_t(0), __ATOMIC_RELEASE);
            const int cancelResult = cancelBeforeDoorbell(
                TahoeP2PActionTxSubmitStage::kExperimentalDeadline,
                rejectError);
            return cancelResult;
        }
    }
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    if (controlSubmitFence) {
        const bool epochsMatch = controlSubmitFenceEpochsMatch(
            owner, sc, context, rocToken, rocStartObserved, rocEndObserved,
            *controlSubmitFence);
        const uint64_t sampleNanoseconds =
            p2pActionSubmitMonotonicNanoseconds();
        const bool timeValid = controlSubmitFenceTimeValid(
            *controlSubmitFence, sampleNanoseconds);
        if (!epochsMatch || !timeValid) {
            const int rejectError = epochsMatch ? ETIMEDOUT : ESTALE;
            const IntelP2PActionTx::Result cancelTicket =
                context->completion.cancelUnsubmitted(
                    generation, static_cast<uint16_t>(ring->qid), index);
            if (cancelTicket != IntelP2PActionTx::Result::kCancelled) {
                context->state = TahoeP2PActionTxState::kQuarantined;
                recordSubmitStage(context,
                    TahoeP2PActionTxSubmitStage::kPreDoorbellCancelFailed,
                    static_cast<int>(cancelTicket));
                return rejectError;
            }
            __atomic_store_n(&context->rxDiagnostics.armed, 0u,
                             __ATOMIC_RELEASE);
            context->state = TahoeP2PActionTxState::kIdle;
            __atomic_store_n(&context->nativeDataToken, uint64_t(0), __ATOMIC_RELEASE);
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
            discardPreparedP2PTxEvidenceTicket(context);
#endif
            return cancelBeforeDoorbell(
                TahoeP2PActionTxSubmitStage::kControlSubmitFence,
                rejectError);
        }
    }
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    QmWireSnapshotRecord qmWireSnapshot{};
    bool qmWireSnapshotValid = false;
    if (qmWireSnapshotCandidate) {
        qmWireSnapshot.header = NativeAwdlQmWireSnapshot::inspectHeader(
            frameHeaderAndBody, frameInfo.headerLength, frameLength,
            sc->sc_p2p.mac_address, NativeAwdlData::kAwdlBssid,
            ipv6DestinationIsAirdropMdns);
        qmWireSnapshot.token = nativeDataToken;
        qmWireSnapshot.contextGeneration = rocToken;
        qmWireSnapshot.powerGeneration = generation;
        qmWireSnapshot.rocToken = rocToken;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
        qmWireSnapshot.stationGeneration = experimentalStationGeneration;
        qmWireSnapshot.estimatedNotBeforeUs = estimatedNotBeforeUs;
        qmWireSnapshot.estimatedDeadlineUs = estimatedDeadlineUs;
#endif
        qmWireSnapshot.txLayout = static_cast<uint32_t>(layout);
        qmWireSnapshot.txCommandApi = owner->iwx_lookup_cmd_ver(
            sc, IWX_LONG_GROUP, IWX_TX_CMD);
        qmWireSnapshot.txNotificationApi = owner->iwx_lookup_notif_ver(
            sc, IWX_LONG_GROUP, IWX_TX_CMD);
        qmWireSnapshot.txFlags = txFlags;
        qmWireSnapshot.rateNFlags = rate;
        qmWireSnapshot.offloadAssist = offloadAssist;
        qmWireSnapshot.mhSizeWords = static_cast<uint16_t>(
            frameInfo.headerLength / sizeof(uint16_t));
        qmWireSnapshot.stationId = queueLease->stationId;
        qmWireSnapshot.queueId = static_cast<uint16_t>(ring->qid);
        qmWireSnapshot.ringSize = static_cast<uint16_t>(ring->ring_count);
        qmWireSnapshot.descriptorIndex = index;
        qmWireSnapshot.frameType = static_cast<uint32_t>(txData->type);
        qmWireSnapshot.tfdCount = plan.numTbs;
        qmWireSnapshot.firstTbBytes = plan.firstTbLength;
        qmWireSnapshot.commandTailBytes = plan.commandTailLength;
        qmWireSnapshot.payloadSegmentCount =
            static_cast<uint32_t>(segmentCount);
        for (int segment = 0; segment < segmentCount; ++segment)
            qmWireSnapshot.payloadBytes += segmentLengths[segment];
        qmWireSnapshot.channel = roc.roc_channel ?
            ieee80211_chan2ieee(&sc->sc_ic, roc.roc_channel) : UINT32_MAX;
        qmWireSnapshot.frequencyMhz = roc.roc_channel ?
            static_cast<uint32_t>(roc.roc_channel->ic_freq) : UINT32_MAX;
        qmWireSnapshot.hostPreDoorbellUs = p2pActionMonotonicUs();
        qmWireSnapshotValid = qmWireSnapshot.header.valid;
    }
#endif
    ring->cur = (index + 1) % ring->ring_count;
    ++ring->queued;
    error = iwx_tahoe_p2p_tvqm_mark_doorbell(
        sc, queueLease, ring, index);
    if (error) {
        // The queue helper guarantees that a failed mark means the MMIO
        // doorbell has not been written. Disarm only this exact ticket before
        // returning the prepared slot to the queue lease.
        const IntelP2PActionTx::Result cancelTicket =
            context->completion.cancelUnsubmitted(
                generation, static_cast<uint16_t>(ring->qid), index);
        if (cancelTicket != IntelP2PActionTx::Result::kCancelled) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
            discardPreparedP2PTxEvidenceTicket(context);
#endif
            context->state = TahoeP2PActionTxState::kQuarantined;
            recordSubmitStage(context,
                TahoeP2PActionTxSubmitStage::kPreDoorbellCancelFailed,
                static_cast<int>(cancelTicket));
            return error;
        }
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kDoorbellMark, error);
        __atomic_store_n(&context->rxDiagnostics.armed, 0u, __ATOMIC_RELEASE);
        ring->cur = static_cast<int>(index);
        --ring->queued;
        context->state = TahoeP2PActionTxState::kIdle;
        __atomic_store_n(&context->nativeDataToken, uint64_t(0), __ATOMIC_RELEASE);
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        discardPreparedP2PTxEvidenceTicket(context);
#endif
        return cancelBeforeDoorbell(
            TahoeP2PActionTxSubmitStage::kDoorbellMark, error);
    }
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    (void)recordP2PTxEvidenceDoorbell(context);
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeDataToken)
        (void)context->dataTxTrace.markDoorbellMarked(nativeDataToken,
                                                       p2pActionMonotonicUs());
#endif
    IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR, ring->qid << 16 | ring->cur);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (nativeDataToken)
        (void)context->dataTxTrace.markDoorbellIssued(nativeDataToken,
                                                       p2pActionMonotonicUs());
#endif
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    markP2PTxEvidenceDoorbellIssued(context);
#endif
    recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kDoorbellIssued, 0);

    /* The doorbell is irreversible: a post-submit error quarantines the slot. */
    error = iwx_tahoe_p2p_tvqm_finish_tx_submit(queueLease);
    if (error) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        markP2PTxEvidenceUnknown(context,
            kP2PTxEvidencePostDoorbellFinishFailure);
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
        if (nativeDataToken)
            (void)context->dataTxTrace.markUnknown(nativeDataToken,
                static_cast<uint32_t>(error), p2pActionMonotonicUs());
#endif
        context->state = TahoeP2PActionTxState::kQuarantined;
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kPostDoorbellFinish, error);
        XYLog("%s: finish after P2P Action doorbell failed (%d); slot retained\n",
              sc->sc_dev.dv_xname, error);
    }
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    else if (qmWireSnapshotValid) {
        // No context, mbuf, or packet-buffer pointer survives submit. Staging
        // occurs only after finish_tx_submit has confirmed queue ownership.
        (void)stageQmWireSnapshot(qmWireSnapshot);
    }
#endif
    return 0;
}

bool iwx_tahoe_p2p_action_tx_response(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context,
    struct iwx_rx_packet *packet, struct iwx_rx_data *rxData)
{
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    const uint64_t txResponseObservedUs = p2pActionMonotonicUs();
    const uint64_t dataTraceToken = context ? __atomic_load_n(
        &context->nativeDataToken, __ATOMIC_ACQUIRE) : 0;
#else
    const uint64_t dataTraceToken = context ? context->nativeDataToken : 0;
#endif
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    const uint64_t completionTapUpperUs = p2pTxEvidenceUpperBoundUs();
#endif
    TahoeP2PTxRxDiagnostics *diagnostics = context ?
        &context->rxDiagnostics : nullptr;
    const bool diagnosticsArmed = diagnostics &&
        __atomic_load_n(&diagnostics->armed, __ATOMIC_ACQUIRE);
    if (diagnosticsArmed)
        incrementP2PTxRxCounter(diagnostics,
                                &diagnostics->handlerEntryCount);
    if (!owner || !sc || !queueLease || !context || !packet || !rxData) {
        if (diagnosticsArmed)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kInvalidArguments);
        return false;
    }

    const size_t payloadLength = iwx_rx_packet_payload_len(packet);
    if (payloadLength < offsetof(struct iwx_tx_resp, tx_queue) + sizeof(uint16_t)) {
        if (diagnosticsArmed) {
            incrementP2PTxRxCounter(diagnostics,
                                    &diagnostics->shortResponseCount);
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kShortPayload);
        }
        return false;
    }
    bus_dmamap_sync(sc->sc_dmat, rxData->map, 0, IWX_RBUF_SIZE,
                    BUS_DMASYNC_POSTREAD);
    uint16_t responseQueue = 0;
    if (!IntelP2PActionTx::extractTxResponseQueueId(
            reinterpret_cast<const uint8_t *>(packet->data), payloadLength,
            offsetof(struct iwx_tx_resp, tx_queue), &responseQueue)) {
        if (diagnosticsArmed)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kQueueParseFailed);
        return false;
    }
    const uint8_t *payload = reinterpret_cast<const uint8_t *>(packet->data);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (dataTraceToken) {
        // packet->hdr.idx is retained as a raw RX command-header byte. The
        // trace does not treat it as the TX ring descriptor index.
        uint32_t validFields = NativeAwdlDataTxTrace::kResponseQueueValid |
            NativeAwdlDataTxTrace::kResponseRxHeaderIndexValid;
        uint16_t sequenceControl = 0;
        uint16_t byteCount = 0;
        uint16_t frameControl = 0;
        uint16_t status = 0;
        uint16_t raTid = 0;
        uint16_t scdSsn = 0;
        if (payloadLength >= offsetof(struct iwx_tx_resp, seq_ctl) + sizeof(uint16_t)) {
            sequenceControl = le16toh(
                reinterpret_cast<const struct iwx_tx_resp *>(payload)->seq_ctl);
            validFields |= NativeAwdlDataTxTrace::kResponseSequenceValid;
        }
        if (payloadLength >= offsetof(struct iwx_tx_resp, byte_cnt) + sizeof(uint16_t)) {
            byteCount = le16toh(
                reinterpret_cast<const struct iwx_tx_resp *>(payload)->byte_cnt);
            validFields |= NativeAwdlDataTxTrace::kResponseByteCountValid;
        }
        if (payloadLength >= offsetof(struct iwx_tx_resp, frame_ctrl) + sizeof(uint16_t)) {
            frameControl = le16toh(
                reinterpret_cast<const struct iwx_tx_resp *>(payload)->frame_ctrl);
            validFields |= NativeAwdlDataTxTrace::kResponseFrameControlValid;
        }
        if (payloadLength >= offsetof(struct iwx_tx_resp, status) + sizeof(uint16_t)) {
            status = le16toh(
                reinterpret_cast<const struct iwx_tx_resp *>(payload)->status.status);
            validFields |= NativeAwdlDataTxTrace::kResponseStatusValid;
        }
        if (payloadLength >= offsetof(struct iwx_tx_resp, ra_tid) + sizeof(uint8_t)) {
            raTid = payload[offsetof(struct iwx_tx_resp, ra_tid)];
            validFields |= NativeAwdlDataTxTrace::kResponseRaTidValid;
        }
        if (payloadLength >= sizeof(uint8_t)) {
            const size_t statusOffset = offsetof(struct iwx_tx_resp, status);
            const size_t frameCount = payload[0];
            if (frameCount && frameCount <= (SIZE_MAX - statusOffset) /
                    sizeof(struct iwx_agg_tx_status)) {
                const size_t ssnOffset = statusOffset + frameCount *
                    sizeof(struct iwx_agg_tx_status);
                if (ssnOffset <= payloadLength && payloadLength - ssnOffset >= sizeof(uint32_t)) {
                    scdSsn = static_cast<uint16_t>(readLe32(payload + ssnOffset) & 0x0fffu);
                    validFields |= NativeAwdlDataTxTrace::kResponseScdSsnValid;
                }
            }
        }
        (void)context->dataTxTrace.captureTxResponseTap(
            dataTraceToken, txResponseObservedUs, validFields, responseQueue,
            packet->hdr.idx, sequenceControl, byteCount, frameControl,
            status, raTid, scdSsn);
    }
#endif
    bool diagnosticQueueMatch = false;
    if (diagnosticsArmed) {
        __atomic_store_n(&diagnostics->lastResponseQueue, responseQueue,
                         __ATOMIC_RELAXED);
        diagnosticQueueMatch = responseQueue ==
            __atomic_load_n(&diagnostics->targetQueue, __ATOMIC_RELAXED);
        if (diagnosticQueueMatch) {
            incrementP2PTxRxCounter(diagnostics,
                                    &diagnostics->responseQueueMatchCount);
            incrementP2PTxRxCounter(diagnostics,
                                    &diagnostics->handlerQueueMatchCount);
        } else {
            incrementP2PTxRxCounter(diagnostics,
                                    &diagnostics->foreignQueueCount);
            incrementP2PTxRxCounter(diagnostics,
                                    &diagnostics->handlerForeignCount);
        }
        if (diagnosticQueueMatch)
            __atomic_store_n(&diagnostics->dirty, 1u, __ATOMIC_RELEASE);
    }
    /* Generic iwx_rx_tx_cmd trusts tx_queue before indexing the fixed ring
     * array. An out-of-range fw field is malformed and must never reach it. */
    if (responseQueue >= nitems(sc->txq)) {
        if (diagnosticsArmed) {
            incrementP2PTxRxCounter(diagnostics,
                                    &diagnostics->outOfRangeQueueCount);
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kQueueOutOfRange);
        }
        if (context->state == TahoeP2PActionTxState::kInFlight)
            context->state = TahoeP2PActionTxState::kQuarantined;
        return true;
    }
    const IntelP2PActionTx::Ticket currentTicket =
        context->completion.snapshot();
    const uint32_t currentState = actionStateValue(context);
    const bool liveTicket = currentTicket.armed && !currentTicket.completed;
    // Keep the completed ticket's station identity as a tombstone until
    // hardware drain. A late P2P response cannot reclaim a STA that reuses
    // this qid after REMOVE_STA; current ordinary STA replies still pass.
    const bool tombstoneMatch = queueLease->state == TahoeP2PResourceState::kAbsent &&
        context->generation != 0 && responseQueue == context->queueId &&
        iwx_rx_packet_payload_len(packet) > offsetof(struct iwx_tx_resp, ra_tid) &&
        IWX_TX_RES_GET_RA(packet->data[offsetof(struct iwx_tx_resp, ra_tid)]) ==
            queueLease->stationId;
    if (tombstoneMatch) {
        const uint32_t raTid = payloadLength >
                offsetof(struct iwx_tx_resp, ra_tid) ?
            payload[offsetof(struct iwx_tx_resp, ra_tid)] : 0xffffffffu;
        const bool idleWithoutTicket =
            currentState == static_cast<uint32_t>(TahoeP2PActionTxState::kIdle) &&
            !liveTicket;
        recordPreArmEvent(context,
            idleWithoutTicket ?
                TahoeP2PPreArmEventSource::kTxResponseNoLiveTicket :
                TahoeP2PPreArmEventSource::kTxResponseOwnershipUnknown,
            queueLease, responseQueue, raTid, currentTicket);
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kNoMatchingTicket);
        if (!idleWithoutTicket)
            __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
                static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
                __ATOMIC_RELEASE);
        return true;
    }
    /* A duplicate/late notification can arrive while the completed P2P ring
     * is being freed. The lease lock makes this check atomic with the
     * Releasing transition; do not let the generic STA path inspect that ring. */
    if (consumeCompletedResponseWhileReleasing(
            queueLease, context, static_cast<uint32_t>(sc->sc_generation),
            responseQueue)) {
        const uint32_t raTid = payloadLength >
                offsetof(struct iwx_tx_resp, ra_tid) ?
            payload[offsetof(struct iwx_tx_resp, ra_tid)] : 0xffffffffu;
        recordPreArmEvent(context,
            TahoeP2PPreArmEventSource::kTxResponseNoLiveTicket,
            queueLease, responseQueue, raTid, currentTicket);
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kDuplicateWhileReleasing);
        return true;
    }

    // A qid reservation is enough to keep a late/foreign notification away
    // from generic STA reclaim, but it is not proof that a DMA descriptor was
    // submitted.  In the known-idle/no-ticket case consume and record the
    // notification without touching the host ring or lifecycle accounting.
    // If ownership or ticket state is uncertain, preserve the existing
    // fail-closed quarantine behavior instead.
    const bool queueOwned = iwx_tahoe_p2p_tvqm_queue_owned(
        queueLease, responseQueue);
    const bool knownLease = queueLease->state != TahoeP2PResourceState::kUnknown &&
        queueLease->stateLock != nullptr;
    const bool matchingTicket = liveTicket &&
        currentState == static_cast<uint32_t>(TahoeP2PActionTxState::kInFlight) &&
        currentTicket.generation == context->generation &&
        currentTicket.generation == queueLease->generation &&
        currentTicket.queueId == responseQueue &&
        currentTicket.queueId == context->queueId &&
        currentTicket.descriptorIndex == context->descriptorIndex &&
        context->generation == static_cast<uint32_t>(sc->sc_generation);
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    const bool matchingEvidenceTicket =
        pendingP2PTxEvidenceMatchesTicket(context, currentTicket,
                                           responseQueue);
#endif
    const bool knownIdleWithoutTicket = queueOwned &&
        currentState == static_cast<uint32_t>(TahoeP2PActionTxState::kIdle) &&
        !liveTicket && knownLease;
    if (queueOwned && !liveTicket) {
        const uint32_t raTid = payloadLength >
                offsetof(struct iwx_tx_resp, ra_tid) ?
            payload[offsetof(struct iwx_tx_resp, ra_tid)] : 0xffffffffu;
        recordPreArmEvent(context,
            knownIdleWithoutTicket ?
                TahoeP2PPreArmEventSource::kTxResponseNoLiveTicket :
                TahoeP2PPreArmEventSource::kTxResponseOwnershipUnknown,
            queueLease, responseQueue, raTid, currentTicket);
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kNoMatchingTicket);
        if (!knownIdleWithoutTicket)
            __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
                static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
                __ATOMIC_RELEASE);
        return true;
    }
    if ((queueOwned || responseQueue == context->queueId) && liveTicket &&
        (!knownLease || !matchingTicket)) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        const uint32_t raTid = payloadLength >
                offsetof(struct iwx_tx_resp, ra_tid) ?
            payload[offsetof(struct iwx_tx_resp, ra_tid)] : 0xffffffffu;
        recordPreArmEvent(context,
            TahoeP2PPreArmEventSource::kTxResponseOwnershipUnknown,
            queueLease, responseQueue, raTid, currentTicket);
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kNoMatchingTicket);
        __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
            static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
            __ATOMIC_RELEASE);
        return true;
    }

    const bool matchingInFlight = responseQueue == context->queueId &&
        context->state == TahoeP2PActionTxState::kInFlight;
    const bool matchingQuarantine = responseQueue == context->queueId &&
        context->state == TahoeP2PActionTxState::kQuarantined;

    struct iwx_tx_ring *ring = nullptr;
    IOInterruptState interruptState = 0;
    if (!iwx_tahoe_p2p_tvqm_lock_completion(
            sc, queueLease, responseQueue, &ring, &interruptState)) {
        // A pending allocation can alias a parked/old host queue. Its late
        // notification cannot establish ownership of either DMA backing.
        if (matchingInFlight || matchingQuarantine ||
            iwx_tahoe_p2p_tvqm_queue_owned(queueLease, responseQueue)) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
            if (matchingEvidenceTicket)
                markP2PTxEvidenceUnknown(context, 0);
#endif
            if (diagnosticQueueMatch)
                recordP2PTxRxReject(diagnostics,
                    TahoeP2PTxRxRejectReason::kCompletionLockUnavailable);
            __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
                static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
                __ATOMIC_RELEASE);
            return true;
        }
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kCompletionLockUnavailable);
        return false;
    }

    /* A successful lock proves this qid is currently installed as the P2P
     * ring. Consume it even without a live ticket; generic reclaim must never
     * see a stationless slot. */
    if (!onMainWorkLoopGate(owner)) {
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kWrongWorkLoopGate);
        if (matchingInFlight || matchingQuarantine)
            __atomic_store_n(reinterpret_cast<uint8_t *>(&context->state),
                static_cast<uint8_t>(TahoeP2PActionTxState::kQuarantined),
                __ATOMIC_RELEASE);
        return true;
    }
    const bool hasMatchingTicket = matchingInFlight &&
        responseQueue == context->queueId;
    const bool firmwareSupported = hasMatchingTicket &&
        supportedFw68Tx(owner, sc);
    const bool generationMatches = firmwareSupported &&
        context->generation == static_cast<uint32_t>(sc->sc_generation);
    if (!hasMatchingTicket || !firmwareSupported || !generationMatches) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch) {
            const TahoeP2PTxRxRejectReason reason = !hasMatchingTicket ?
                TahoeP2PTxRxRejectReason::kNoMatchingTicket :
                (!firmwareSupported ?
                    TahoeP2PTxRxRejectReason::kUnsupportedFirmware :
                    TahoeP2PTxRxRejectReason::kStaleGeneration);
            recordP2PTxRxReject(diagnostics, reason);
        }
        if (context->state == TahoeP2PActionTxState::kInFlight)
            context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    bool released = false;
    mbuf_t completedMbuf = nullptr;
    const uint16_t index = context->descriptorIndex;
    if (!ring || ring->qid != responseQueue || index >= ring->ring_count ||
        ring->ring_count == 0 || ring->ring_count > IWX_TFD_QUEUE_SIZE_MAX ||
        ring->tail != index || ring->queued != 1 ||
        ring->cur != (index + 1) % ring->ring_count ||
        ring->data[index].m == nullptr || ring->data[index].in != nullptr ||
        ring->data[index].type != (dataTraceToken?IEEE80211_FC0_TYPE_DATA:IEEE80211_FC0_TYPE_MGT)) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kRingMismatch);
        context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    // A queue ID alone is not an ownership token: a stale/foreign TX_RSP can
    // reuse the qid while naming another station. The production RA/TID
    // macros define the high nibble as station (RA) and the low nibble as TID;
    // for the captured 0x3f response this is station 3, management TID 15.
    const uint8_t responseRaTid =
        payload[offsetof(struct iwx_tx_resp, ra_tid)];
    if (diagnosticQueueMatch)
        recordP2PTxResponseNumbers(diagnostics, context, payload,
                                   payloadLength, responseQueue,
                                   packet->hdr.cmd, packet->hdr.qid,
                                   packet->hdr.idx);
    if (IWX_TX_RES_GET_RA(responseRaTid) != queueLease->stationId) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kNoMatchingTicket);
        context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    // This dedicated non-QoS queue is allocated for firmware TID 15 for
    // Action and raw Data alike. A same-station response with another TID
    // must not retire its descriptor.
    if (IWX_TX_RES_GET_TID(responseRaTid) != IWX_MGMT_TID) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kWrongTid);
        context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    const IntelP2PActionTx::Result result = context->completion.complete(
        context->generation, payload, payloadLength,
        offsetof(struct iwx_tx_resp, status),
        offsetof(struct iwx_tx_resp, seq_ctl),
        offsetof(struct iwx_tx_resp, byte_cnt),
        offsetof(struct iwx_tx_resp, frame_ctrl),
        offsetof(struct iwx_tx_resp, tx_queue),
        offsetof(struct iwx_tx_resp, status) +
            sizeof(struct iwx_agg_tx_status));
    if (result != IntelP2PActionTx::Result::kCompletion &&
        result != IntelP2PActionTx::Result::kFrameFailed) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kCompletionRejected,
                static_cast<uint32_t>(result));
        context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    if (iwx_tahoe_p2p_tvqm_tx_completed_locked(sc, queueLease) != 0) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
        if (matchingEvidenceTicket)
            markP2PTxEvidenceUnknown(context, 0);
#endif
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kCompletionAccountingFailed,
                static_cast<uint32_t>(result));
        context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    struct iwx_tx_data *txData = &ring->data[index];
    completedMbuf = txData->m;
    txData->m = nullptr;
    txData->in = nullptr;
    clearActionDescriptor(&ring->desc[index]);
    ring->tail = (index + 1) % ring->ring_count;
    --ring->queued;
    context->state = TahoeP2PActionTxState::kIdle;
    context->nextSequenceNumber = static_cast<uint16_t>(
        (context->sequenceControl >> 4) + 1) & 0x0fff;
    released = true;
    iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if (dataTraceToken) {
        (void)context->dataTxTrace.mergeTxResponseTap();
        (void)context->dataTxTrace.markTxResponseHandlerDisposition(
            dataTraceToken, 1);
        (void)context->dataTxTrace.markCompletion(dataTraceToken,
            static_cast<uint32_t>(result), p2pActionMonotonicUs());
    }
#endif

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    if (matchingEvidenceTicket)
        recordP2PTxEvidenceCompletion(context, completionTapUpperUs,
            result == IntelP2PActionTx::Result::kCompletion);
#endif

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(dataTraceToken) {
        NativeAwdlBSD::completed(dataTraceToken,
            result==IntelP2PActionTx::Result::kCompletion);
        __atomic_store_n(&context->nativeDataToken, uint64_t(0), __ATOMIC_RELEASE);
    }
#endif
    if (released && completedMbuf)
        mbuf_freem(completedMbuf);
    if (diagnosticsArmed && diagnosticQueueMatch) {
        __atomic_add_fetch(&diagnostics->completionCount, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&diagnostics->lastCompletionResult,
                         static_cast<uint32_t>(result), __ATOMIC_RELAXED);
        __atomic_store_n(&diagnostics->dirty, 1u, __ATOMIC_RELEASE);
    }
    const auto ticket = context->completion.snapshot();
    XYLog("P2P Action TX response qid=%u idx=%u status=0x%04x attempt=%u peerAck=0\n",
          responseQueue, index, ticket.status,
          ticket.frameAttemptSucceeded ? 1 : 0);
    return true;
}

void iwx_tahoe_p2p_action_tx_firmware_drained(
    TahoeP2PActionTxContext *context, uint32_t newGeneration,
    bool firmwareStoppedAndRxTxDrained)
{
    if (!context)
        return;
    const IntelP2PActionTx::Ticket previousTicket =
        context->completion.snapshot();
    const uint32_t previousState = actionStateValue(context);
    uint32_t ticketFlags = previousTicket.armed ? 1u : 0u;
    if (previousTicket.completed)
        ticketFlags |= 1u << 1;
    if (previousTicket.frameAttemptSucceeded)
        ticketFlags |= 1u << 2;
    if (previousTicket.peerAcknowledged)
        ticketFlags |= 1u << 3;

    IntelP2PActionTx::Result drainResult = IntelP2PActionTx::Result::kInvalid;
    if (firmwareStoppedAndRxTxDrained)
        drainResult = context->completion.firmwareDrained(newGeneration);

    TahoeP2PActionTxDrainDiagnostics &diagnostics =
        context->drainDiagnostics;
    __atomic_store_n(&diagnostics.lastResult,
        static_cast<int32_t>(drainResult), __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastNewGeneration, newGeneration,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastContextGeneration,
                     context->generation, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastTicketGeneration,
                     previousTicket.generation, __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastTicketFlags, ticketFlags,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastHardStop,
                     firmwareStoppedAndRxTxDrained ? 1u : 0u,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&diagnostics.lastActionState, previousState,
                     __ATOMIC_RELAXED);
    __atomic_add_fetch(&diagnostics.eventCount, 1u, __ATOMIC_RELEASE);

    if (drainResult == IntelP2PActionTx::Result::kReady) {
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
        const uint64_t drainedDataToken = __atomic_load_n(
            &context->nativeDataToken, __ATOMIC_ACQUIRE);
        if (drainedDataToken) {
            NativeAwdlBSD::submitted(drainedDataToken, ECANCELED);
            (void)context->dataTxTrace.captureStopTap(drainedDataToken,
                newGeneration, firmwareStoppedAndRxTxDrained, ECANCELED,
                p2pActionMonotonicUs());
        }
#endif
        __atomic_store_n(&context->nativeDataToken, uint64_t(0), __ATOMIC_RELEASE);
        context->generation = newGeneration;
        context->rocToken = 0;
        context->queueId = 0xffff;
        context->descriptorIndex = 0;
        context->sequenceControl = 0;
        context->frameControl = 0;
        context->frameByteCount = 0;
        context->state = TahoeP2PActionTxState::kIdle;
    } else {
        context->state = TahoeP2PActionTxState::kQuarantined;
    }
}

#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
void iwx_tahoe_p2p_action_tx_mark_evidence_unknown(
    TahoeP2PActionTxContext *context, uint32_t additionalFlags)
{
    markP2PTxEvidenceUnknown(context, additionalFlags);
}
#endif

#endif // AIRPORT_TAHOE
