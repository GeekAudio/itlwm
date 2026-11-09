// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwxP2PAction.hpp"

#ifdef AIRPORT_TAHOE

#include "ItlIwx.hpp"
#include "../../native/p2p_tx_firmware.hpp"
#include "../../native/awdl_action_frame.hpp"
#include "../../native/awdl_action_encode.hpp"
#include "../../native/awdl_advertisement_identity.hpp"
#include "../../native/awdl_mif_encode.hpp"
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
#include "ItlIwxP2PData.hpp"
#include "../../native/p2p_directed_data_control.hpp"
#include "../../native/awdl_native_bsd_data_25G332.hpp"
#include "../../native/awdl_data_frame.hpp"
#endif
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

// Independent offline A/B candidate: default A is the existing flags 7 path.
#ifndef ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332
#define ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332 0
#endif
#if ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332
#if !defined(ITL_NATIVE_AWDL_RESIDENT_25G332) || \
    !defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332) || \
    defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332) || \
    ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 || \
    ITL_NATIVE_AWDL_MULTICAST_ADMISSION_25G332
#error "QM priority candidate requires the discovery data profile without RX149 or admission-only"
#endif
#endif

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
    // The only accepted Action frame submit path remains the legacy GP/TID15
    // management lease. A prepared LINK/TID0 peer queue is not a data-doorbell
    // capability; it must have a separate, independently reviewed submitter.
    if (queueLease->stationRole !=
            TahoeP2PStationRole::kBroadcastGeneralPurpose ||
        queueLease->firmwareTid != IWX_MGMT_TID) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kRocOrResource, EOPNOTSUPP);
        return EOPNOTSUPP;
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
        IWX_TX_FLAGS_ENCRYPT_DIS |
#if ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332
        ((qmWireSnapshotCandidate && estimatedWindowValid &&
          ipv6DestinationIsAirdropMdns) ? 0u : IWX_TX_FLAGS_HIGH_PRI);
#else
        IWX_TX_FLAGS_HIGH_PRI;
#endif
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

#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
namespace {

// A 5 ms reserve for slot one is intentionally local to this bounded two-
// packet experiment. It leaves time for the final queue/MMIO transition inside
// the fixed 100 ms ROC instead of authorizing a second DMA at the deadline.
static constexpr uint64_t kDirectedDataSubmitMarginUs = 1000ULL;
static constexpr uint64_t kDirectedDataSecondSubmitMarginUs = 5000ULL;

static uint64_t directedDataMonotonicUs()
{
    uint64_t uptime = 0, nanoseconds = 0;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &nanoseconds);
    return nanoseconds / 1000ULL;
}

static uint16_t directedDataReadLe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0] |
        (static_cast<uint16_t>(bytes[1]) << 8));
}

static bool directedDataSubmitHasDeadlineMargin(
    const TahoeP2PDirectedDataContext *context, uint64_t nowUs)
{
    if (!context || context->currentSlot >= context->packetCount ||
        nowUs >= context->binding.deadlineUs)
        return false;
    const uint64_t marginUs = context->currentSlot == 1 ?
        kDirectedDataSecondSubmitMarginUs : kDirectedDataSubmitMarginUs;
    return context->binding.deadlineUs - nowUs >= marginUs;
}

static bool directedDataSameEpochs(
    const TahoeP2PDirectedDataEpochs &left,
    const TahoeP2PDirectedDataEpochs &right)
{
    return NativeAwdlDirectedOriginTx::sameEpochs(left, right);
}

static bool directedDataCurrent(ItlIwx *owner, struct iwx_softc *sc,
    const TahoeP2PDirectedDataContext *context, bool requireRoc)
{
    if (!owner || !sc || sc != &owner->com || !context)
        return false;
    const auto &binding = context->binding;
    NativeP2PDirectedDataControl::MainGateOwnerState ownerState{};
    ownerState.executingOnMainGate = owner->tahoeP2pOnMainGate();
    ownerState.probeBusy = owner->nativeP2pBusy();
    ownerState.cancelRequested = __atomic_load_n(
        &owner->nativeP2pCancelRequested_, __ATOMIC_ACQUIRE) != 0;
    ownerState.currentWorkerThread = __atomic_load_n(
        &owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE);
    ownerState.armedWorkerThread = context->workerThread;
    ownerState.currentContextGeneration = owner->nativeP2pProbeGeneration_;
    ownerState.bindingContextGeneration = binding.epochs.context;
    ownerState.currentPowerGeneration = static_cast<uint32_t>(sc->sc_generation);
    ownerState.bindingPowerGeneration = binding.epochs.power;
    ownerState.currentStationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    ownerState.bindingStationGeneration = binding.epochs.station;
    if (!NativeP2PDirectedDataControl::mainGateOwnerCurrent(ownerState))
        return false;
    if (!binding.ownerSerial || !binding.runSerial ||
        !NativeAwdlDirectedOriginTx::validEpochs(binding.epochs) ||
        binding.generation != binding.epochs.power ||
        !binding.p2pFirmwareGeneration ||
        sc->sc_p2p.fw_generation != binding.p2pFirmwareGeneration ||
        !sc->sc_p2p.initialized ||
        sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased ||
        sc->sc_ic.ic_state != IEEE80211_S_RUN || !sc->sc_ic.ic_bss ||
        owner->nativeAwdlRxEventOwnerSerial_ != binding.ownerSerial)
        return false;

    const NativeAwdlRxTrace::Snapshot trace =
        owner->nativeAwdlRxEventTimeline_.snapshot();
    const NativeAwdlRxTrace::Epochs expected{
        binding.epochs.context, binding.epochs.power,
        binding.epochs.station, binding.epochs.roc};
    if (!trace.ownerPresent || !trace.active || trace.producerClosed ||
        trace.ownerSerial != binding.ownerSerial ||
        !NativeAwdlRxTrace::sameEpochs(trace.epochs, expected))
        return false;
    if (!requireRoc)
        return true;
    const uint64_t nowUs = directedDataMonotonicUs();
    return context->originWindowBound && binding.rocToken != 0 &&
        binding.deadlineUs != 0 && nowUs >= binding.rocStartUs &&
        nowUs < binding.deadlineUs &&
        binding.rocToken == binding.epochs.roc &&
        sc->sc_p2p_roc.token == binding.rocToken &&
        sc->sc_p2p_roc.fw_generation == binding.p2pFirmwareGeneration &&
        sc->sc_p2p_roc.roc_channel &&
        sc->sc_p2p_roc.roc_channel->ic_freq == 2437 &&
        ieee80211_chan2ieee(&sc->sc_ic,
            sc->sc_p2p_roc.roc_channel) == 6 &&
        sc->sc_p2p_roc.phase == IWX_P2P_ROC_SESSION_ACKED;
}

static uint8_t directedDataPacketCount(
    const TahoeP2PDirectedDataArm *arm)
{
    if (!arm || arm->packetCount > kTahoeP2PDirectedDataMaxPackets)
        return 0;
    return arm->packetCount == 2 ? 2 : 1;
}

static const uint8_t *directedDataArmNonce(
    const TahoeP2PDirectedDataArm *arm, uint8_t slot)
{
    if (!arm || slot >= directedDataPacketCount(arm))
        return nullptr;
    return arm->packetCount == 2 ? arm->packetNonces[slot] : arm->nonce;
}

static bool directedDataArmShapeValid(
    const TahoeP2PDirectedDataArm *arm)
{
    if (!arm || !NativeAwdlDirectedOriginTx::validUnicastMac(arm->peerMac) ||
        !NativeAwdlDirectedOriginTx::isLinkLocal(arm->localIpv6) ||
        arm->runToken[32] != '\0' || arm->runToken[0] == '\0')
        return false;
    const uint8_t count = directedDataPacketCount(arm);
    if (!count)
        return false;
    if (count == 1)
        return NativeAwdlDirectedOriginTx::nonzeroNonce(arm->nonce);
    if (!NativeAwdlDirectedOriginTx::isLinkLocal(arm->peerIPv6) ||
        !NativeAwdlDirectedOriginTx::nonzeroNonce(arm->packetNonces[0]) ||
        !NativeAwdlDirectedOriginTx::nonzeroNonce(arm->packetNonces[1]) ||
        memcmp(arm->packetNonces[0], arm->packetNonces[1], 8) == 0)
        return false;
    return true;
}

static bool directedDataPriorSlotProofComplete(
    const TahoeP2PDirectedDataContext *context,
    const TahoeP2PTxQueueLease *queueLease)
{
    if (!context || !queueLease || context->packetCount != 2)
        return false;
    const auto &first = context->packets[0];
    const IntelP2PTx::QueueSnapshot queue = queueLease->lifecycle.snapshot();
    return first.identityBound && first.doorbellIssued &&
        first.completionObserved && first.frameAttemptSucceeded &&
        first.exactReplyCaptured && first.exactReplyDelivered &&
        first.txResponseUs >= first.doorbellUs &&
        first.exactReplyCaptureUs >= first.doorbellUs &&
        first.exactReplyInputUs >= first.exactReplyCaptureUs &&
        first.originCompletionRecorded && queueLease->everDoorbelled &&
        queue.completionObserved && queue.outstandingTx == 0 &&
        !queueLease->submissionBusy && !queueLease->unsubmittedAbortInProgress &&
        !queueLease->idleAbortAfterEndInProgress;
}

static bool directedDataAllDoorbellsCompleted(
    const TahoeP2PDirectedDataContext *context)
{
    if (!context)
        return false;
    bool anyDoorbell = false;
    for (uint8_t slot = 0; slot < context->packetCount; ++slot) {
        const auto &packet = context->packets[slot];
        if (!packet.doorbellIssued)
            continue;
        anyDoorbell = true;
        if (!packet.completionObserved || !packet.resourcesAbsent)
            return false;
    }
    // A no-doorbell run is proved by the separate unsubmitted/cancel path.
    // Never let the empty set of submitted packets satisfy completion.
    return anyDoorbell;
}

static bool directedDataHasDoorbellHistory(
    const TahoeP2PDirectedDataContext *context)
{
    if (!context)
        return false;
    for (uint8_t slot = 0; slot < context->packetCount; ++slot) {
        if (context->packets[slot].doorbellIssued)
            return true;
    }
    return false;
}

struct DirectedDataGateCheck {
    TahoeP2PDirectedDataContext *context;
    bool valid;
};


static void directedDataRecordUnsubmittedSlot(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason)
{
    if (!context || context->currentSlot >= context->packetCount ||
        context->packets[context->currentSlot].doorbellIssued ||
        context->state == TahoeP2PDirectedDataState::kQuarantined)
        return;
    auto &packet = context->packets[context->currentSlot];
    packet.resourcesAbsent = true;
    packet.permitIssued = false;
    packet.sequenceReserved = false;
    context->sequenceReservationValid = false;
    context->permitIssued = false;
    context->permit = {};
    context->completionObserved = directedDataHasDoorbellHistory(context) &&
        directedDataAllDoorbellsCompleted(context);
    // A canceled second packet cannot inherit the first packet's successful
    // frame-attempt result. Keep this a clean failure, never an exchange pass.
    context->frameAttemptSucceeded = false;
    context->reason = reason;
    context->state = context->completionObserved ?
        TahoeP2PDirectedDataState::kCompleted :
        TahoeP2PDirectedDataState::kClosed;
}

struct DirectedDataUnsubmittedNextSlotEvidence {
    bool originInactive;
    bool queueCurrent;
    bool ringAndQueueDrained;
};

static bool directedDataRetireUnsubmittedNextSlot(
    TahoeP2PDirectedDataContext *context,
    const DirectedDataUnsubmittedNextSlotEvidence &evidence)
{
    if (!context || context->packetCount != 2 || context->currentSlot != 1 ||
        !context->ticketBound || !context->originClosed ||
        !evidence.originInactive || !evidence.queueCurrent ||
        !evidence.ringAndQueueDrained || context->mbufHeldByRing ||
        context->state == TahoeP2PDirectedDataState::kQuarantined ||
        (context->state != TahoeP2PDirectedDataState::kTicketBound &&
         context->state != TahoeP2PDirectedDataState::kPermitIssued &&
         context->state != TahoeP2PDirectedDataState::kClosed))
        return false;
    auto &first = context->packets[0];
    auto &second = context->packets[1];
    const auto completion = context->completion.snapshot();
    if (!first.identityBound || !first.doorbellIssued ||
        !first.completionObserved || !first.resourcesAbsent ||
        second.doorbellIssued || !directedDataHasDoorbellHistory(context) ||
        !directedDataAllDoorbellsCompleted(context) ||
        (completion.armed && !completion.completed))
        return false;

    // The origin ticket is already inactive and the queue/ring snapshot was
    // checked under its lock. Slot one never reached a doorbell, so its local
    // permit and sequence reservation can now be retired without guessing at
    // DMA ownership.
    second.resourcesAbsent = true;
    second.permitIssued = false;
    second.sequenceReserved = false;
    context->sequenceReservationValid = false;
    context->permitIssued = false;
    context->permit = {};
    context->completionObserved = true;
    context->frameAttemptSucceeded = false;
    context->state = TahoeP2PDirectedDataState::kCompleted;
    return true;
}

static bool directedDataRetireUnsubmittedNextSlotOnMainGate(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    bool originInactive)
{
    if (!owner || !context || !owner->tahoeP2pOnMainGate() ||
        !originInactive || context->packetCount != 2 ||
        context->currentSlot != 1 ||
        (context->state != TahoeP2PDirectedDataState::kTicketBound &&
         context->state != TahoeP2PDirectedDataState::kPermitIssued &&
         context->state != TahoeP2PDirectedDataState::kClosed))
        return false;

    auto *queueLease = &owner->nativeP2pTxQueue_;
    struct iwx_tx_ring *ring = nullptr;
    IOInterruptState interruptState = 0;
    if (context->queueId == IWX_INVALID_QUEUE ||
        context->queueId >= nitems(owner->com.txq) ||
        context->queueId != queueLease->queueId ||
        !iwx_tahoe_p2p_tvqm_lock_completion(&owner->com, queueLease,
            context->queueId, &ring, &interruptState))
        return false;

    const IntelP2PTx::QueueSnapshot lifecycle =
        queueLease->lifecycle.snapshot();
    bool queueCurrent = queueLease->state == TahoeP2PResourceState::kActive &&
        queueLease->generation == context->binding.generation &&
        queueLease->allocationSerial == context->queueAllocationSerial &&
        queueLease->stationRole == TahoeP2PStationRole::kDirectedPeerLink &&
        queueLease->firmwareTid == 0 &&
        queueLease->stationId == context->stationId &&
        queueLease->everDoorbelled && !queueLease->submissionBusy &&
        !queueLease->unsubmittedAbortInProgress &&
        !queueLease->idleAbortAfterEndInProgress &&
        queueLease->pendingRing == nullptr &&
        lifecycle.state == IntelP2PTx::QueueState::kActive &&
        lifecycle.generation == context->binding.generation &&
        lifecycle.queueId == context->queueId &&
        lifecycle.stationId == context->stationId &&
        lifecycle.outstandingTx == 0 && lifecycle.completionObserved &&
        lifecycle.ringMustRemainOwned;
    bool ringAndQueueDrained = queueCurrent && ring &&
        ring == &owner->com.txq[context->queueId] &&
        ring->qid == context->queueId && ring->desc &&
        ring->ring_count >= 8 &&
        ring->ring_count <= IWX_TFD_QUEUE_SIZE_MAX &&
        (ring->ring_count & (ring->ring_count - 1)) == 0 &&
        ring->ring_count == context->ringSize && ring->queued == 0 &&
        ring->cur < ring->ring_count && ring->tail < ring->ring_count &&
        ring->cur == ring->tail;
    for (uint32_t index = 0; ringAndQueueDrained &&
         index < ring->ring_count; ++index) {
        if (ring->data[index].m || ring->data[index].in ||
            le16toh(ring->desc[index].num_tbs) != 0)
            ringAndQueueDrained = false;
    }
    iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);

    const DirectedDataUnsubmittedNextSlotEvidence evidence{
        originInactive, queueCurrent, ringAndQueueDrained};
    return directedDataRetireUnsubmittedNextSlot(context, evidence);
}


static bool directedDataMainGateCheck(ItlIwx *owner,
    TahoeP2PDirectedDataContext *context)
{
    if (!owner || !context || !owner->tahoeP2pOnMainGate())
        return false;
    struct iwx_softc *sc = &owner->com;
    if (!directedDataCurrent(owner, sc, context, true))
        return false;

    IwxMccRefreshPolicy::DirectedDataWitness mcc{};
    return owner->tahoeDirectedDataMccWitness(mcc) &&
        IwxMccRefreshPolicy::sameDirectedDataWitness(mcc, context->binding.mcc);
}

static IOReturn directedDataMainGateCheckAction(
    OSObject *, void *ownerArg, void *checkArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *check = static_cast<DirectedDataGateCheck *>(checkArg);
    if (!owner || !check || !check->context ||
        !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    check->valid = directedDataMainGateCheck(owner, check->context);
    return check->valid ? kIOReturnSuccess : kIOReturnNotReady;
}

static bool directedDataFreshMccAndRoc(ItlIwx *owner,
    TahoeP2PDirectedDataContext *context)
{
    if (!owner || !context)
        return false;
    DirectedDataGateCheck check{context, false};
    if (owner->tahoeP2pOnMainGate())
        return directedDataMainGateCheck(owner, context);
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    return gate && gate->attemptAction(directedDataMainGateCheckAction,
        owner, &check, nullptr, nullptr) == kIOReturnSuccess && check.valid;
}

using DirectedDataGateAction = IOReturn (*)(OSObject *, void *, void *,
                                              void *, void *);

static IOReturn directedDataRunMainGateAction(
    ItlIwx *owner, DirectedDataGateAction action, void *argument,
    bool tryOnly = false)
{
    if (!owner || !action)
        return kIOReturnBadArgument;
    if (owner->tahoeP2pOnMainGate())
        return action(owner, owner, argument, nullptr, nullptr);
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    if (!gate)
        return kIOReturnNotReady;
    return tryOnly ? gate->attemptAction(action, owner, argument, nullptr,
        nullptr) : gate->runAction(action, owner, argument, nullptr, nullptr);
}

struct DirectedDataSerialAction {
    TahoeP2PDirectedDataContext *context;
    uint64_t serial;
    int result;
};

static IOReturn directedDataNextAllocationSerialAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataSerialAction *>(actionArg);
    if (!owner || !action || !action->context ||
        !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    if (action->context->allocationSerialHighWater == UINT64_MAX) {
        action->result = EOVERFLOW;
        return kIOReturnSuccess;
    }
    action->serial = ++action->context->allocationSerialHighWater;
    action->result = 0;
    return kIOReturnSuccess;
}

static bool directedDataTicketMatchesBinding(
    const TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginTicket &ticket)
{
    if (!context || !context->originWindowBound ||
        !context->binding.ownerSerial || !context->binding.runSerial ||
        !ticket.ticketSerial || !ticket.interfaceIncarnation || !ticket.ifindex)
        return false;
    const auto &binding = context->binding;
    return ticket.ownerSerial == binding.ownerSerial &&
        ticket.runSerial == binding.runSerial &&
        directedDataSameEpochs(ticket.epochs, binding.epochs) &&
        ticket.rocStartUs == binding.rocStartUs &&
        ticket.deadlineUs == binding.deadlineUs &&
        NativeAwdlDirectedOriginTx::validUnicastMac(ticket.sourceMac);
}

static bool directedDataDecodeMbuf(
    const TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginTicket &ticket, mbuf_t encodedMpdu,
    uint8_t raw[NativeAwdlDirectedOriginTx::kMpduLength],
    NativeAwdlData::DecodedFrame *decoded)
{
    using namespace NativeAwdlDirectedOriginTx;
    const uint8_t slot = context ? context->currentSlot : 0xff;
    const TahoeP2PDirectedDataPacketRecord *packetRecord = context &&
        slot < context->packetCount ? &context->packets[slot] : nullptr;
    if (!context || !packetRecord || !encodedMpdu || !raw || !decoded ||
        (mbuf_flags(encodedMpdu) & MBUF_PKTHDR) == 0 ||
        mbuf_pkthdr_len(encodedMpdu) != kMpduLength ||
        mbuf_copydata(encodedMpdu, 0, static_cast<int>(kMpduLength),
                      reinterpret_cast<caddr_t>(raw)) != 0 ||
        NativeAwdlData::decodeIpv6DataMpdu(raw, kMpduLength, decoded) !=
            NativeAwdlData::Status::Ok)
        return false;

    if (decoded->frameControl != 0x0008 || decoded->qosData ||
        decoded->packetCount != 1 || decoded->packets[0].ipv6Length !=
            kIpv6Length || memcmp(raw + 4, context->arm.peerMac, 6) != 0 ||
        memcmp(raw + 10, ticket.sourceMac, 6) != 0 ||
        !context->sequenceReservationValid || !packetRecord->sequenceReserved ||
        decoded->wifiSequenceNumber != packetRecord->wifiSequence ||
        decoded->packets[0].awdlSequenceNumber !=
            packetRecord->awdlSequence ||
        (directedDataReadLe16(raw + 22) & 0x000f) != 0)
        return false;

    const uint8_t *ipv6 = decoded->packets[0].ipv6Packet;
    if (!ipv6 || (ipv6[0] >> 4) != 6 ||
        NativeAwdlDirectedOriginTx::readBe16(ipv6 + 4) != kUdpLength ||
        ipv6[6] != 17 || ipv6[7] != 1 ||
        memcmp(ipv6 + 8, context->arm.localIpv6, 16) != 0)
        return false;
    static const uint8_t allNodes[16] = {
        0xff, 0x02, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    };
    if (memcmp(ipv6 + 24, allNodes, sizeof(allNodes)) != 0)
        return false;
    const uint8_t *udp = ipv6 + 40;
    if (NativeAwdlDirectedOriginTx::readBe16(udp) != kSourcePort ||
        NativeAwdlDirectedOriginTx::readBe16(udp + 2) != kDestinationPort ||
        NativeAwdlDirectedOriginTx::readBe16(udp + 4) != kUdpLength ||
        memcmp(udp + 8, packetRecord->nonce, kNonceLength) != 0)
        return false;
    uint32_t sum = uint32_t(kUdpLength) + 17u;
    for (size_t i = 8; i < 40; i += 2)
        sum += NativeAwdlDirectedOriginTx::readBe16(ipv6 + i);
    for (size_t i = 40; i < kIpv6Length; i += 2)
        sum += NativeAwdlDirectedOriginTx::readBe16(ipv6 + i);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return NativeAwdlDirectedOriginTx::readBe16(udp + 6) != 0 &&
        sum == 0xffffu;
}

static void directedDataClearDescriptor(struct iwx_tfh_tfd *descriptor)
{
    if (!descriptor)
        return;
    const uint16_t used = le16toh(descriptor->num_tbs) & 0x1f;
    for (uint16_t i = 0; i < used; ++i)
        memset(&descriptor->tbs[i], 0, sizeof(descriptor->tbs[i]));
    descriptor->num_tbs = 0;
}

static void directedDataMarkCompletedClosed(
    TahoeP2PDirectedDataContext *context)
{
    if (context && context->state == TahoeP2PDirectedDataState::kCompleted &&
        context->completionObserved && !context->mbufHeldByRing)
        context->state = TahoeP2PDirectedDataState::kClosed;
}

static void directedDataSetMayOwnResource(
    TahoeP2PDirectedDataContext *context, bool mayOwn)
{
    if (context)
        __atomic_store_n(&context->mayOwnResource, mayOwn ? 1u : 0u,
                         __ATOMIC_RELEASE);
}

// Called only while the main command gate owns the context. A completed
// response is safe only after the ring relinquished its mbuf; a no-doorbell
// run is safe only after any armed completion ticket was canceled.
static bool directedDataCanClearMayOwnResource(
    const TahoeP2PDirectedDataContext *context)
{
    if (!context || context->state == TahoeP2PDirectedDataState::kQuarantined ||
        !context->originClosed || context->mbufHeldByRing)
        return false;
    const auto completion = context->completion.snapshot();
    if (completion.armed && !completion.completed)
        return false;
    const bool notSubmitted = !directedDataHasDoorbellHistory(context) &&
        (!completion.armed || completion.completed);
    const bool completed = directedDataHasDoorbellHistory(context) &&
        directedDataAllDoorbellsCompleted(context) &&
        context->completionObserved &&
        (!completion.armed || completion.completed);
    return context->hardStopDrained || notSubmitted || completed;
}

static void directedDataClearSlot(struct iwx_tx_ring *ring, uint16_t index)
{
    if (!ring || index >= ring->ring_count)
        return;
    directedDataClearDescriptor(ring->desc ? &ring->desc[index] : nullptr);
    ring->data[index].m = nullptr;
    ring->data[index].in = nullptr;
    ring->data[index].type = 0;
}

static bool directedDataPermitMatches(
    const TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataPermit *permit,
    const TahoeP2PStationLease *stationLease,
    const TahoeP2PTxQueueLease *queueLease)
{
    if (!context || !permit || !stationLease || !queueLease || !permit->valid)
        return false;
    const auto &saved = context->permit;
    return context->permitIssued && saved.valid &&
        permit->permitSerial == saved.permitSerial &&
        permit->armSerial == saved.armSerial &&
        permit->ticketSerial == saved.ticketSerial &&
        permit->packetToken == saved.packetToken &&
        permit->ownerSerial == saved.ownerSerial &&
        permit->runSerial == saved.runSerial &&
        permit->interfaceIncarnation == saved.interfaceIncarnation &&
        permit->stationAllocationSerial == saved.stationAllocationSerial &&
        permit->queueAllocationSerial == saved.queueAllocationSerial &&
        permit->ifindex == saved.ifindex &&
        directedDataSameEpochs(permit->epochs, saved.epochs) &&
        permit->generation == saved.generation &&
        permit->p2pFirmwareGeneration == saved.p2pFirmwareGeneration &&
        permit->rocToken == saved.rocToken &&
        permit->deadlineUs == saved.deadlineUs &&
        permit->queueId == saved.queueId &&
        permit->wifiSequence == saved.wifiSequence &&
        permit->awdlSequence == saved.awdlSequence &&
        permit->descriptorIndex == saved.descriptorIndex &&
        permit->packetSlot == saved.packetSlot &&
        permit->stationId == saved.stationId &&
        context->stationAllocationSerial == stationLease->allocationSerial &&
        context->queueAllocationSerial == queueLease->allocationSerial &&
        context->queueId == queueLease->queueId &&
        context->stationId == stationLease->stationId;
}

static bool directedDataCanSubmitSlot(
    const TahoeP2PDirectedDataContext *context,
    const TahoeP2PTxQueueLease *queueLease)
{
    if (!context || !queueLease || context->currentSlot >= context->packetCount)
        return false;
    const auto &packet = context->packets[context->currentSlot];
    if (!packet.identityBound || !packet.sequenceReserved ||
        packet.doorbellIssued || packet.completionObserved ||
        packet.resourcesAbsent)
        return false;
    if (context->currentSlot == 0)
        return !directedDataHasDoorbellHistory(context) &&
            !queueLease->everDoorbelled &&
            !queueLease->lifecycle.snapshot().completionObserved;
    return directedDataPriorSlotProofComplete(context, queueLease);
}

static int directedDataFailBeforeDoorbell(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason, mbuf_t packet, int error)
{
    if (packet)
        mbuf_freem(packet);
    if (context && context->currentSlot < context->packetCount &&
        !context->packets[context->currentSlot].doorbellIssued &&
        context->state != TahoeP2PDirectedDataState::kQuarantined) {
        directedDataRecordUnsubmittedSlot(context, reason);
    }
    return error;
}

} // namespace

uint64_t iwx_tahoe_p2p_directed_data_next_allocation_serial(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context)
{
    if (!owner || !context)
        return 0;
    DirectedDataSerialAction action{context, 0, EBUSY};
    if (directedDataRunMainGateAction(owner,
            directedDataNextAllocationSerialAction, &action) !=
        kIOReturnSuccess)
        return 0;
    return action.result == 0 ? action.serial : 0;
}

int iwx_tahoe_p2p_directed_data_arm(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataArm *arm, uint64_t ownerSerial,
    const TahoeP2PDirectedDataEpochs *epochs, uint32_t generation,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataBinding *bindingOut)
{
    if (bindingOut)
        *bindingOut = {};
    if (!owner || !sc || sc != &owner->com ||
        !owner->tahoeP2pOnMainGate() || !context || !arm ||
        !ownerSerial || !epochs || !stationLease || !queueLease ||
        !bindingOut || !generation || !NativeAwdlDirectedOriginTx::validEpochs(
            *epochs) || epochs->power != generation ||
        !directedDataArmShapeValid(arm) ||
        sc->sc_p2p.fw_generation == 0 ||
        !sc->sc_p2p.initialized ||
        sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased ||
        (context->state != TahoeP2PDirectedDataState::kIdle &&
         context->state != TahoeP2PDirectedDataState::kClosed) ||
        directedDataHasDoorbellHistory(context) || context->mbufHeldByRing ||
        (context->completion.snapshot().armed &&
         !context->completion.snapshot().completed))
        return EINVAL;
    const uint32_t currentGeneration = static_cast<uint32_t>(sc->sc_generation);
    const uint32_t currentStationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    void *workerThread = __atomic_load_n(&owner->nativeP2pProbeOwner_,
                                         __ATOMIC_ACQUIRE);
    NativeP2PDirectedDataControl::MainGateArmOwnerState armOwnerState{};
    armOwnerState.executingOnMainGate = owner->tahoeP2pOnMainGate();
    armOwnerState.probeBusy = owner->nativeP2pBusy();
    armOwnerState.cancelRequested = __atomic_load_n(
        &owner->nativeP2pCancelRequested_, __ATOMIC_ACQUIRE) != 0;
    armOwnerState.executingThread =
        reinterpret_cast<const void *>(current_thread());
    armOwnerState.currentWorkerThread = workerThread;
    armOwnerState.currentContextGeneration = owner->nativeP2pProbeGeneration_;
    armOwnerState.bindingContextGeneration = epochs->context;
    armOwnerState.currentPowerGeneration = currentGeneration;
    armOwnerState.bindingPowerGeneration = epochs->power;
    armOwnerState.currentStationGeneration = currentStationGeneration;
    armOwnerState.bindingStationGeneration = epochs->station;
    if (!NativeP2PDirectedDataControl::mainGateArmOwnerCurrent(
            armOwnerState))
        return ESTALE;
    if (context->armSerialHighWater == UINT64_MAX)
        return EOVERFLOW;
    if (generation != currentGeneration || epochs->context !=
            owner->nativeP2pProbeGeneration_ || epochs->station !=
            currentStationGeneration ||
        ownerSerial != owner->nativeAwdlRxEventOwnerSerial_ ||
        stationLease->state != TahoeP2PResourceState::kActive ||
        stationLease->generation != generation ||
        stationLease->role != TahoeP2PStationRole::kDirectedPeerLink ||
        stationLease->stationType != IWX_STA_LINK ||
        memcmp(stationLease->address, arm->peerMac, 6) != 0 ||
        queueLease->state != TahoeP2PResourceState::kActive ||
        queueLease->generation != generation ||
        queueLease->stationId != stationLease->stationId ||
        queueLease->stationRole != TahoeP2PStationRole::kDirectedPeerLink ||
        queueLease->firmwareTid != 0)
        return ESTALE;
    const NativeAwdlRxTrace::Snapshot trace =
        owner->nativeAwdlRxEventTimeline_.snapshot();
    const NativeAwdlRxTrace::Epochs expected{
        epochs->context, epochs->power, epochs->station, epochs->roc};
    if (!trace.ownerPresent || !trace.active || trace.producerClosed ||
        trace.ownerSerial != ownerSerial ||
        !NativeAwdlRxTrace::sameEpochs(trace.epochs, expected))
        return ESTALE;

    IwxMccRefreshPolicy::DirectedDataWitness mcc{};
    if (!owner->tahoeDirectedDataMccWitness(mcc))
        return ESTALE;

    uint64_t stationSerial = stationLease->allocationSerial;
    uint64_t queueSerial = queueLease->allocationSerial;
    if (!stationSerial)
        stationSerial = iwx_tahoe_p2p_directed_data_next_allocation_serial(
            owner, context);
    if (!queueSerial)
        queueSerial = iwx_tahoe_p2p_directed_data_next_allocation_serial(
            owner, context);
    if (!stationSerial || !queueSerial || stationSerial == queueSerial)
        return EOVERFLOW;
    const int serialError = iwx_tahoe_p2p_tvqm_bind_allocation_serials(
        sc, stationLease, queueLease, stationSerial, queueSerial);
    if (serialError)
        return serialError;

    ++context->armSerialHighWater;
    context->txWitness = {};
    context->packetWitness[0] = {};
    context->packetWitness[1] = {};
    context->packets[0] = {};
    context->packets[1] = {};
    context->packetCount = directedDataPacketCount(arm);
    context->currentSlot = 0;
    for (uint8_t slot = 0; slot < context->packetCount; ++slot) {
        context->packets[slot].slot = slot;
        memcpy(context->packets[slot].nonce,
               directedDataArmNonce(arm, slot), 8);
    }
    memset(&context->arm, 0, sizeof(context->arm));
    memcpy(&context->arm, arm, sizeof(context->arm));
    memset(&context->binding, 0, sizeof(context->binding));
    context->workerThread = workerThread;
    context->binding.ownerSerial = ownerSerial;
    context->binding.runSerial = context->armSerialHighWater;
    context->binding.epochs = *epochs;
    context->binding.generation = generation;
    context->binding.p2pFirmwareGeneration = sc->sc_p2p.fw_generation;
    context->binding.mcc = mcc;
    memset(&context->originTicket, 0, sizeof(context->originTicket));
    memset(&context->permit, 0, sizeof(context->permit));
    context->reason = TahoeP2PDirectedDataReason::kNone;
    context->stationAllocationSerial = stationSerial;
    context->queueAllocationSerial = queueSerial;
    context->packetToken = 0;
    context->interfaceIncarnation = 0;
    context->ifindex = 0;
    context->queueId = queueLease->queueId;
    context->stationId = stationLease->stationId;
    context->descriptorIndex = 0xffff;
    context->ringSize = 0;
    context->sequenceControl = 0;
    context->frameControl = 0;
    context->byteCount = 0;
    context->expectedNextSsn = 0xffff;
    context->firmwareStatus = 0xffff;
    __atomic_store_n(&context->stopProofMask, 0u, __ATOMIC_RELEASE);
    context->ticketBound = false;
    context->originWindowBound = false;
    context->originClosed = false;
    context->permitIssued = false;
    context->doorbellIssued = false;
    context->completionObserved = false;
    context->frameAttemptSucceeded = false;
    context->mbufHeldByRing = false;
    context->hardStopDrained = false;
    context->sequenceReservationValid = false;
    context->reservedWifiSequence = 0;
    context->reservedAwdlSequence = 0;
    // Publish before the context becomes Armed. Lifecycle guards may read
    // this atomic without entering the command gate during cold start.
    directedDataSetMayOwnResource(context, true);
    context->state = TahoeP2PDirectedDataState::kArmed;
    *bindingOut = context->binding;
    return 0;
}

struct DirectedDataWindowAction {
    TahoeP2PDirectedDataContext *context;
    uint64_t rocToken;
    uint64_t rocStartUs;
    uint64_t deadlineUs;
    int result;
};

static IOReturn directedDataBindOriginWindowAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataWindowAction *>(actionArg);
    TahoeP2PDirectedDataContext *context = action ? action->context : nullptr;
    if (!owner || !action || !context || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    if (!context || context->state != TahoeP2PDirectedDataState::kArmed ||
        context->ticketBound || !action->rocToken ||
        action->rocToken != context->binding.epochs.roc ||
        !action->rocStartUs || !action->deadlineUs ||
        action->deadlineUs <= action->rocStartUs ||
        action->rocStartUs > UINT64_MAX -
            NativeAwdlDirectedOriginTx::kMaximumWindowUs ||
        action->deadlineUs > action->rocStartUs +
            NativeAwdlDirectedOriginTx::kMaximumWindowUs)
        action->result = EINVAL;
    else {
    const uint64_t nowUs = directedDataMonotonicUs();
        if (nowUs < action->rocStartUs || nowUs >= action->deadlineUs) {
            action->result = ETIMEDOUT;
        } else {
            context->binding.rocToken = action->rocToken;
            context->binding.rocStartUs = action->rocStartUs;
            context->binding.deadlineUs = action->deadlineUs;
            context->originWindowBound = true;
            action->result = 0;
        }
    }
    return kIOReturnSuccess;
}

int iwx_tahoe_p2p_directed_data_bind_origin_window(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context, uint64_t rocToken,
    uint64_t rocStartUs, uint64_t deadlineUs)
{
    if (!owner || !context)
        return EINVAL;
    DirectedDataWindowAction action{context, rocToken, rocStartUs,
        deadlineUs, EBUSY};
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataBindOriginWindowAction, &action);
    return gateResult == kIOReturnSuccess ? action.result : EBUSY;
}

struct DirectedDataSequenceAction {
    TahoeP2PDirectedDataContext *context;
    uint16_t wifiSequence;
    uint16_t awdlSequence;
    bool valid;
};

static IOReturn directedDataReserveSequencesAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataSequenceAction *>(actionArg);
    TahoeP2PDirectedDataContext *context = action ? action->context : nullptr;
    if (!owner || !action || !context || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    if (context->currentSlot == 0 && context->packetCount == 2 &&
        context->state == TahoeP2PDirectedDataState::kCompleted &&
        context->ticketBound && !context->originClosed &&
        directedDataPriorSlotProofComplete(context,
            &owner->nativeP2pTxQueue_) &&
        directedDataMainGateCheck(owner, context)) {
        // Slot zero is immutable from this point on. Reuse only the single
        // active completion tracker after its exact TX_RSP was retired.
        context->currentSlot = 1;
        context->state = TahoeP2PDirectedDataState::kTicketBound;
        context->packetToken = 0;
        context->permit = {};
        context->permitIssued = false;
        // completionObserved is run-level history: slot zero completed and
        // must remain represented until slot one actually rings the doorbell.
        // Snapshot/cleanup derive this from every immutable slot record.
        context->frameAttemptSucceeded = false;
        context->firmwareStatus = 0xffff;
    }
    const bool currentSlotReady = context->state ==
            TahoeP2PDirectedDataState::kTicketBound &&
        context->ticketBound && !context->originClosed &&
        context->currentSlot < context->packetCount &&
        !context->packets[context->currentSlot].doorbellIssued;
    if (!currentSlotReady || context->sequenceReservationValid ||
        directedDataMonotonicUs() < context->binding.rocStartUs ||
        directedDataMonotonicUs() >= context->binding.deadlineUs ||
        !directedDataMainGateCheck(owner, context))
        return kIOReturnNotReady;
    auto &packet = context->packets[context->currentSlot];
    if (packet.sequenceReserved || packet.identityBound)
        return kIOReturnNotReady;
    action->wifiSequence = context->wifiSequenceHighWater & 0x0fff;
    action->awdlSequence = context->awdlSequenceHighWater;
    context->reservedWifiSequence = action->wifiSequence;
    context->reservedAwdlSequence = action->awdlSequence;
    context->sequenceReservationValid = true;
    context->wifiSequenceHighWater = static_cast<uint16_t>(
        (context->wifiSequenceHighWater + 1u) & 0x0fffu);
    context->awdlSequenceHighWater = static_cast<uint16_t>(
        context->awdlSequenceHighWater + 1u);
    packet.wifiSequence = action->wifiSequence;
    packet.awdlSequence = action->awdlSequence;
    packet.sequenceReserved = true;
    action->valid = true;
    return kIOReturnSuccess;
}

bool iwx_tahoe_p2p_directed_data_reserve_sequences(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    uint16_t *wifiSequence, uint16_t *awdlSequence)
{
    if (!owner || !context || !wifiSequence || !awdlSequence)
        return false;
    DirectedDataSequenceAction action{context, 0, 0, false};
    if (directedDataRunMainGateAction(owner,
            directedDataReserveSequencesAction, &action) !=
        kIOReturnSuccess || !action.valid)
        return false;
    *wifiSequence = action.wifiSequence;
    *awdlSequence = action.awdlSequence;
    return true;
}

struct DirectedDataTicketAction {
    TahoeP2PDirectedDataContext *context;
    TahoeP2PDirectedDataOriginTicket ticket;
    uint8_t liveAddress[6];
    int result;
};

static IOReturn directedDataBindOriginTicketAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataTicketAction *>(actionArg);
    TahoeP2PDirectedDataContext *context = action ? action->context : nullptr;
    if (!owner || !action || !context || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    const auto &ticket = action->ticket;
    if (
        context->state != TahoeP2PDirectedDataState::kArmed ||
        !context->originWindowBound || context->ticketBound)
        action->result = EINVAL;
    else if (!directedDataMainGateCheck(owner, context) ||
        !directedDataTicketMatchesBinding(context, ticket) ||
        directedDataMonotonicUs() < ticket.rocStartUs ||
        directedDataMonotonicUs() >= ticket.deadlineUs)
        action->result = ESTALE;
    else if (memcmp(action->liveAddress, ticket.sourceMac, 6) != 0 ||
        memcmp(action->liveAddress, owner->com.sc_p2p.mac_address, 6) != 0)
        action->result = EADDRNOTAVAIL;
    else {
        context->originTicket = ticket;
        context->ticketBound = true;
        context->originClosed = false;
        context->interfaceIncarnation = ticket.interfaceIncarnation;
        context->ifindex = ticket.ifindex;
        context->packetToken = 0;
        context->state = TahoeP2PDirectedDataState::kTicketBound;
        action->result = 0;
    }
    return kIOReturnSuccess;
}

int iwx_tahoe_p2p_directed_data_bind_origin_ticket(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginTicket *ticket)
{
    if (!owner || !context || !ticket)
        return EINVAL;
    if (owner->tahoeP2pOnMainGate())
        return EBUSY;
    // The BSD address query is bounded and lock-local. Keep it outside the
    // command gate, then bind its value only after the gate revalidates the
    // current owner, epochs, ROC, and exact ticket.
    DirectedDataTicketAction action{};
    action.context = context;
    action.ticket = *ticket;
    action.result = EBUSY;
    if (!NativeAwdlBSD::address(ticket->epochs.power, action.liveAddress))
        return EADDRNOTAVAIL;
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataBindOriginTicketAction, &action);
    return gateResult == kIOReturnSuccess ? action.result : EBUSY;
}

struct DirectedDataOriginIdentityAction {
    TahoeP2PDirectedDataContext *context;
    const TahoeP2PDirectedDataOriginPacket *origin;
    NativeAwdlDirectedOriginTx::PacketIdentity identity;
    uint64_t observedUs;
    uint64_t responseUs;
    bool frameAttemptSucceeded;
    bool doorbell;
    bool alreadyRecorded;
    bool valid;
};

static bool directedDataOriginPacketMatches(
    const TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin,
    const TahoeP2PDirectedDataPacketRecord *packet)
{
    return context && origin && packet && packet->identityBound &&
        origin->identityTicketSerial == context->originTicket.ticketSerial &&
        origin->ticket.ticketSerial == context->originTicket.ticketSerial &&
        origin->packetToken == packet->packetToken &&
        origin->slot == packet->slot && origin->slot < context->packetCount &&
        origin->wifiSequence == packet->wifiSequence &&
        origin->awdlSequence == packet->awdlSequence &&
        memcmp(origin->nonce, packet->nonce, sizeof(packet->nonce)) == 0 &&
        NativeAwdlDirectedOriginTx::sameTicket(
            origin->ticket, context->originTicket);
}

static IOReturn directedDataCaptureOriginOperationAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataOriginIdentityAction *>(actionArg);
    auto *context = action ? action->context : nullptr;
    const auto *origin = action ? action->origin : nullptr;
    if (!owner || !action || !context || !origin ||
        !owner->tahoeP2pOnMainGate() ||
        origin->slot >= context->packetCount)
        return kIOReturnBadArgument;
    const auto &packet = context->packets[origin->slot];
    if (!directedDataOriginPacketMatches(context, origin, &packet))
        return kIOReturnNotReady;

    action->identity.ticketSerial = origin->identityTicketSerial;
    action->identity.packetSerial = origin->packetToken;
    action->identity.slot = origin->slot;
    memcpy(action->identity.nonce, origin->nonce,
           sizeof(action->identity.nonce));
    if (action->doorbell) {
        // This records a doorbell that already happened in the submit path.
        // Do not revalidate the live ROC lease here: canonical END may race
        // the worker's post-MMIO evidence sync. The exact immutable slot
        // identity and HAL doorbell timestamp remain mandatory, while the
        // BSD bridge independently records this as unauthorized if its
        // lock-free END fence has already closed the lease. This path cannot
        // issue or permit another packet.
        action->alreadyRecorded = packet.originDoorbellRecorded;
        if (!packet.doorbellIssued || !packet.doorbellUs ||
            packet.doorbellUs >= context->binding.deadlineUs)
            return kIOReturnNotReady;
        action->observedUs = packet.doorbellUs;
    } else {
        action->alreadyRecorded = packet.originCompletionRecorded;
        if (!packet.doorbellIssued || !packet.completionObserved ||
            !packet.resourcesAbsent || !packet.txResponseUs)
            return kIOReturnNotReady;
        action->responseUs = packet.txResponseUs;
        action->frameAttemptSucceeded = packet.frameAttemptSucceeded;
    }
    action->valid = true;
    return kIOReturnSuccess;
}

static IOReturn directedDataCommitOriginOperationAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataOriginIdentityAction *>(actionArg);
    auto *context = action ? action->context : nullptr;
    const auto *origin = action ? action->origin : nullptr;
    if (!owner || !action || !context || !origin ||
        !owner->tahoeP2pOnMainGate() ||
        origin->slot >= context->packetCount)
        return kIOReturnBadArgument;
    auto &packet = context->packets[origin->slot];
    if (context->binding.runSerial != origin->ticket.runSerial ||
        context->originTicket.ticketSerial != origin->ticket.ticketSerial ||
        !directedDataOriginPacketMatches(context, origin, &packet))
        return kIOReturnNotReady;
    if (action->doorbell)
        packet.originDoorbellRecorded = true;
    else
        packet.originCompletionRecorded = true;
    return kIOReturnSuccess;
}

bool iwx_tahoe_p2p_directed_data_record_origin_doorbell(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin)
{
    if (!owner || !context || !origin)
        return false;
    DirectedDataOriginIdentityAction action{};
    action.context = context;
    action.origin = origin;
    action.doorbell = true;
    if (directedDataRunMainGateAction(owner,
            directedDataCaptureOriginOperationAction, &action) !=
        kIOReturnSuccess || !action.valid)
        return false;
    if (action.alreadyRecorded)
        return true;
    if (!NativeAwdlBSD::recordDirectedTxDoorbell(origin->ticket,
            action.identity, action.observedUs))
        return false;
    return directedDataRunMainGateAction(owner,
        directedDataCommitOriginOperationAction, &action) ==
        kIOReturnSuccess;
}

bool iwx_tahoe_p2p_directed_data_record_origin_completion(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin)
{
    if (!owner || !context || !origin)
        return false;
    DirectedDataOriginIdentityAction action{};
    action.context = context;
    action.origin = origin;
    action.doorbell = false;
    if (directedDataRunMainGateAction(owner,
            directedDataCaptureOriginOperationAction, &action) !=
        kIOReturnSuccess || !action.valid)
        return false;
    if (action.alreadyRecorded)
        return true;
    if (!NativeAwdlBSD::recordDirectedTxCompletion(origin->ticket,
            action.identity, action.frameAttemptSucceeded,
            action.responseUs))
        return false;
    return directedDataRunMainGateAction(owner,
        directedDataCommitOriginOperationAction, &action) ==
        kIOReturnSuccess;
}

struct DirectedDataReplyAction {
    TahoeP2PDirectedDataContext *context;
    TahoeP2PDirectedDataOriginPacket origin;
    NativeAwdlDirectedOriginTx::ExactReplyReceipt receipt;
    bool accepted;
};

static IOReturn directedDataNoteExactReplyAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataReplyAction *>(actionArg);
    auto *context = action ? action->context : nullptr;
    if (!owner || !action || !context || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    const auto &origin = action->origin;
    if (origin.slot >= context->packetCount)
        return kIOReturnBadArgument;
    auto &packet = context->packets[origin.slot];
    const auto &receipt = action->receipt;
    const uint64_t nowUs = directedDataMonotonicUs();
    const bool identityMatches = context->ticketBound &&
        !context->originClosed &&
        directedDataOriginPacketMatches(context, &origin, &packet) &&
        receipt.valid && receipt.captured && receipt.delivered &&
        receipt.slot == origin.slot &&
        receipt.ticketSerial == context->originTicket.ticketSerial &&
        receipt.packetSerial == packet.packetToken &&
        receipt.ownerSerial == context->binding.ownerSerial &&
        receipt.runSerial == context->binding.runSerial &&
        receipt.ifindex == context->ifindex &&
        receipt.interfaceIncarnation == context->interfaceIncarnation &&
        NativeAwdlDirectedOriginTx::sameEpochs(receipt.epochs,
                                               context->binding.epochs) &&
        receipt.doorbellUs == packet.doorbellUs &&
        packet.doorbellIssued && packet.originDoorbellRecorded &&
        receipt.captureUs >= receipt.doorbellUs &&
        receipt.inputUs >= receipt.captureUs &&
        receipt.inputUs < context->binding.deadlineUs &&
        nowUs < context->binding.deadlineUs &&
        directedDataMainGateCheck(owner, context);
    if (!identityMatches)
        return kIOReturnNotReady;
    if (packet.exactReplyCaptured && packet.exactReplyDelivered &&
        packet.exactReplyCaptureUs == receipt.captureUs &&
        packet.exactReplyInputUs == receipt.inputUs) {
        action->accepted = true;
        return kIOReturnSuccess;
    }
    if (packet.exactReplyCaptured)
        return kIOReturnNotReady;
    packet.exactReplyCaptured = true;
    packet.exactReplyDelivered = true;
    packet.exactReplyCaptureUs = receipt.captureUs;
    packet.exactReplyInputUs = receipt.inputUs;
    action->accepted = true;
    return kIOReturnSuccess;
}

bool iwx_tahoe_p2p_directed_data_note_exact_reply(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin)
{
    if (!owner || !context || !origin || !origin->packetToken)
        return false;
    NativeAwdlDirectedOriginTx::ExactReplyReceipt receipt{};
    if (!NativeAwdlBSD::snapshotDirectedExactReply(origin->ticket,
            origin->packetToken, &receipt))
        return false;
    DirectedDataReplyAction action{};
    action.context = context;
    action.origin = *origin;
    action.receipt = receipt;
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataNoteExactReplyAction, &action);
    return gateResult == kIOReturnSuccess && action.accepted;
}

struct DirectedDataPermitAction {
    TahoeP2PDirectedDataContext *context;
    TahoeP2PDirectedDataOriginPacket origin;
    mbuf_t encodedMpdu;
    TahoeP2PDirectedDataPermit *permit;
    int result;
};

static IOReturn directedDataMakePermitAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *);

static int directedDataMakePermitOnMainGate(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin, mbuf_t encodedMpdu,
    TahoeP2PDirectedDataPermit *permit)
{
    const uint8_t slot = context ? context->currentSlot : 0xff;
    TahoeP2PDirectedDataPacketRecord *packet = context &&
        slot < context->packetCount ? &context->packets[slot] : nullptr;
    if (permit)
        *permit = {};
    if (!owner || !context || !origin || !encodedMpdu || !permit ||
        !packet ||
        !owner->tahoeP2pOnMainGate() ||
        context->state != TahoeP2PDirectedDataState::kTicketBound ||
        !context->ticketBound || context->originClosed ||
        context->permitIssued)
        return EINVAL;
    if (!directedDataFreshMccAndRoc(owner, context) ||
        !NativeAwdlDirectedOriginTx::sameTicket(
            context->originTicket, origin->ticket) ||
        !origin->packetToken ||
        origin->identityTicketSerial != origin->ticket.ticketSerial ||
        origin->slot != slot ||
        memcmp(origin->nonce, packet->nonce, sizeof(packet->nonce)) != 0 ||
        origin->wifiSequence != packet->wifiSequence ||
        origin->awdlSequence != packet->awdlSequence ||
        !packet->sequenceReserved || packet->doorbellIssued ||
        (slot == 1 && !directedDataPriorSlotProofComplete(context,
            &owner->nativeP2pTxQueue_)) ||
        !directedDataTicketMatchesBinding(context, origin->ticket) ||
        directedDataMonotonicUs() < context->binding.rocStartUs ||
        directedDataMonotonicUs() >= context->binding.deadlineUs)
        return ESTALE;

    uint8_t raw[NativeAwdlDirectedOriginTx::kMpduLength]{};
    NativeAwdlData::DecodedFrame decoded{};
    if (!directedDataDecodeMbuf(context, origin->ticket, encodedMpdu,
                                raw, &decoded)) {
        context->reason = TahoeP2PDirectedDataReason::kWrongPacketShape;
        context->state = TahoeP2PDirectedDataState::kClosed;
        return EPROTO;
    }
    if (!directedDataFreshMccAndRoc(owner, context) ||
        directedDataMonotonicUs() < context->binding.rocStartUs ||
        directedDataMonotonicUs() >= context->binding.deadlineUs)
        return ESTALE;
    if (context->permitSerialHighWater == UINT64_MAX)
        return EOVERFLOW;

    TahoeP2PDirectedDataPermit value{};
    value.permitSerial = ++context->permitSerialHighWater;
    value.armSerial = context->armSerialHighWater;
    value.ticketSerial = origin->ticket.ticketSerial;
    value.packetToken = origin->packetToken;
    value.ownerSerial = context->binding.ownerSerial;
    value.runSerial = context->binding.runSerial;
    value.interfaceIncarnation = origin->ticket.interfaceIncarnation;
    value.stationAllocationSerial = context->stationAllocationSerial;
    value.queueAllocationSerial = context->queueAllocationSerial;
    value.ifindex = origin->ticket.ifindex;
    value.epochs = context->binding.epochs;
    value.generation = context->binding.generation;
    value.p2pFirmwareGeneration = context->binding.p2pFirmwareGeneration;
    value.rocToken = context->binding.rocToken;
    value.deadlineUs = context->binding.deadlineUs;
    value.queueId = context->queueId;
    value.wifiSequence = packet->wifiSequence;
    value.awdlSequence = packet->awdlSequence;
    value.packetSlot = slot;
    value.stationId = static_cast<uint8_t>(context->stationId);
    value.valid = true;
    context->permit = value;
    context->permitIssued = true;
    context->packetToken = origin->packetToken;
    packet->packetToken = origin->packetToken;
    packet->identityBound = true;
    packet->permitIssued = true;
    context->sequenceControl = directedDataReadLe16(raw + 22);
    context->frameControl = decoded.frameControl;
    context->byteCount = static_cast<uint16_t>(
        NativeAwdlDirectedOriginTx::kMpduLength);
    packet->sequenceControl = context->sequenceControl;
    packet->frameControl = context->frameControl;
    packet->byteCount = context->byteCount;
    context->state = TahoeP2PDirectedDataState::kPermitIssued;
    *permit = value;
    return 0;
}

static IOReturn directedDataMakePermitAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataPermitAction *>(actionArg);
    if (!owner || !action || !action->context || !action->encodedMpdu ||
        !action->permit || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    action->result = directedDataMakePermitOnMainGate(owner,
        action->context, &action->origin, action->encodedMpdu,
        action->permit);
    return kIOReturnSuccess;
}

int iwx_tahoe_p2p_directed_data_make_permit(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin, mbuf_t encodedMpdu,
    TahoeP2PDirectedDataPermit *permit)
{
    if (permit)
        *permit = {};
    if (!owner || !context || !origin || !encodedMpdu || !permit)
        return EINVAL;
    DirectedDataPermitAction action{context, *origin, encodedMpdu, permit,
        EBUSY};
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataMakePermitAction, &action);
    return gateResult == kIOReturnSuccess ? action.result : EBUSY;
}

static int directedDataTxSubmitOnMainGate(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataPermit *permit, mbuf_t encodedMpdu)
{
    const uint8_t slot = context ? context->currentSlot : 0xff;
    TahoeP2PDirectedDataPacketRecord *packet = context &&
        slot < context->packetCount ? &context->packets[slot] : nullptr;
    if (!encodedMpdu)
        return EINVAL;
    if (!owner || !sc || sc != &owner->com || !stationLease ||
        !queueLease || !context || !permit || !packet ||
        !owner->tahoeP2pOnMainGate() ||
        context->state != TahoeP2PDirectedDataState::kPermitIssued ||
        packet->doorbellIssued || context->mbufHeldByRing ||
        !directedDataPermitMatches(context, permit, stationLease,
                                   queueLease))
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kPermitMismatch, encodedMpdu,
            EBUSY);

    if (!directedDataFreshMccAndRoc(owner, context) ||
        directedDataMonotonicUs() < context->binding.rocStartUs ||
        directedDataMonotonicUs() >= context->binding.deadlineUs ||
        !directedDataTicketMatchesBinding(context, context->originTicket) ||
        permit->armSerial != context->armSerialHighWater ||
        permit->generation != static_cast<uint32_t>(sc->sc_generation) ||
        permit->p2pFirmwareGeneration != sc->sc_p2p.fw_generation ||
        stationLease->role != TahoeP2PStationRole::kDirectedPeerLink ||
        stationLease->stationType != IWX_STA_LINK ||
        stationLease->state != TahoeP2PResourceState::kActive ||
        stationLease->generation != permit->generation ||
        queueLease->state != TahoeP2PResourceState::kActive ||
        queueLease->stationRole != TahoeP2PStationRole::kDirectedPeerLink ||
        queueLease->firmwareTid != 0 ||
        queueLease->generation != permit->generation ||
        queueLease->stationId != stationLease->stationId ||
        queueLease->queueId != permit->queueId ||
        !directedDataCanSubmitSlot(context, queueLease) ||
        memcmp(stationLease->address, context->arm.peerMac, 6) != 0 ||
        memcmp(queueLease->peerAddress, context->arm.peerMac, 6) != 0 ||
        queueLease->allocationSerial != context->queueAllocationSerial ||
        stationLease->allocationSerial != context->stationAllocationSerial) {
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kStaleEpoch, encodedMpdu, ESTALE);
    }

    const IntelP2PFirmware::TxLayout layout = fw68TxLayout(owner, sc);
    if (layout == IntelP2PFirmware::TxLayout::kUnsupported)
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kWrongOwnerOrGate, encodedMpdu,
            EOPNOTSUPP);
    const uint32_t rate = actionRate6Mbps(owner, sc);
    if (!rate)
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kWrongOwnerOrGate, encodedMpdu,
            EOPNOTSUPP);

    uint8_t raw[NativeAwdlDirectedOriginTx::kMpduLength]{};
    NativeAwdlData::DecodedFrame decoded{};
    if (!directedDataDecodeMbuf(context, context->originTicket,
            encodedMpdu, raw, &decoded) ||
        context->packetToken != permit->packetToken ||
        context->byteCount != NativeAwdlDirectedOriginTx::kMpduLength ||
        context->sequenceControl != directedDataReadLe16(raw + 22) ||
        context->frameControl != decoded.frameControl)
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kWrongPacketShape, encodedMpdu,
            EPROTO);

    uint8_t liveAddress[6]{};
    if (!NativeAwdlBSD::address(context->binding.generation, liveAddress) ||
        memcmp(liveAddress, context->originTicket.sourceMac, 6) != 0 ||
        memcmp(liveAddress, sc->sc_p2p.mac_address, 6) != 0)
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kWrongOriginTicket, encodedMpdu,
            EADDRNOTAVAIL);

    struct iwx_tx_ring *ring = nullptr;
    uint16_t index = 0;
    int error = iwx_tahoe_p2p_tvqm_begin_tx(sc, queueLease, &ring, &index);
    if (error)
        return directedDataFailBeforeDoorbell(context,
            TahoeP2PDirectedDataReason::kQueueUnavailable, encodedMpdu,
            error);

    const auto cancelBeforeDoorbell = [&](int result) -> int {
        directedDataClearSlot(ring, index);
        const int cancelError = iwx_tahoe_p2p_tvqm_cancel_tx_submit(queueLease);
        mbuf_freem(encodedMpdu);
        if (cancelError) {
            context->reason = TahoeP2PDirectedDataReason::kDrainMismatch;
            directedDataSetMayOwnResource(context, true);
            context->state = TahoeP2PDirectedDataState::kQuarantined;
            context->mbufHeldByRing = false;
            return cancelError;
        }
        directedDataRecordUnsubmittedSlot(context,
            TahoeP2PDirectedDataReason::kCompletionFailure);
        return result;
    };

    const auto cancelMarkedBeforeDoorbell = [&] (
        int result, TahoeP2PDirectedDataReason reason) -> int {
        const auto cancelled = context->completion.cancelUnsubmitted(
            context->binding.generation,
            static_cast<uint16_t>(ring->qid), index);
        if (cancelled != IntelP2PActionTx::Result::kCancelled) {
            context->mbufHeldByRing = true;
            directedDataSetMayOwnResource(context, true);
            context->state = TahoeP2PDirectedDataState::kQuarantined;
            context->reason = TahoeP2PDirectedDataReason::kDrainMismatch;
            return result;
        }
        ring->cur = index;
        --ring->queued;
        directedDataClearSlot(ring, index);
        mbuf_freem(encodedMpdu);
        const int queueCancelError =
            iwx_tahoe_p2p_tvqm_cancel_tx_submit(queueLease);
        if (queueCancelError) {
            context->mbufHeldByRing = false;
            directedDataSetMayOwnResource(context, true);
            context->state = TahoeP2PDirectedDataState::kQuarantined;
            context->reason = TahoeP2PDirectedDataReason::kDrainMismatch;
            return queueCancelError;
        }
        context->mbufHeldByRing = false;
        directedDataRecordUnsubmittedSlot(context, reason);
        return result;
    };

    if (!ring || ring->qid < 0 || ring->qid > 0xff ||
        ring->qid != permit->queueId || ring->ring_count < 8 ||
        ring->ring_count > IWX_TFD_QUEUE_SIZE_MAX ||
        (ring->ring_count & (ring->ring_count - 1)) != 0 ||
        index >= ring->ring_count || ring->cur != index ||
        ring->tail != index || ring->queued != 0 ||
        ring->data[index].m || ring->data[index].in ||
        !ring->data[index].map || !ring->data[index].map->cursor ||
        !ring->desc || !ring->cmd)
        return cancelBeforeDoorbell(EIO);

    struct iwx_tx_data *txData = &ring->data[index];
    struct iwx_tfh_tfd *descriptor = &ring->desc[index];
    struct iwx_device_cmd *deviceCommand = &ring->cmd[index];
    // The MPDU is 96 bytes: the unencrypted 24-byte header is copied into the
    // TX command, leaving the exact 72-byte IPv6/UDP payload for the DMA map.
    mbuf_adj(encodedMpdu, 24);
    IOPhysicalSegment segments[IWX_TFH_NUM_TBS - 2];
    const int segmentCount = txData->map->cursor->getPhysicalSegmentsWithCoalesce(
        encodedMpdu, segments, IWX_TFH_NUM_TBS - 2);
    if (segmentCount <= 0 || segmentCount > IWX_TFH_NUM_TBS - 2)
        return cancelBeforeDoorbell(ENOMEM);
    uint16_t segmentLengths[IWX_TFH_NUM_TBS - 2]{};
    uint32_t payloadBytes = 0;
    for (int segment = 0; segment < segmentCount; ++segment) {
        if (!segments[segment].length || segments[segment].length > 0xffff)
            return cancelBeforeDoorbell(EMSGSIZE);
        segmentLengths[segment] = static_cast<uint16_t>(
            segments[segment].length);
        payloadBytes += segmentLengths[segment];
    }
    if (payloadBytes != NativeAwdlDirectedOriginTx::kMpduLength - 24)
        return cancelBeforeDoorbell(EMSGSIZE);

    IntelP2PActionFrame::TfdPlan plan{};
    const size_t txCommandLength = layout ==
        IntelP2PFirmware::TxLayout::kGen2 ?
            sizeof(struct iwx_tx_cmd_gen2) : sizeof(struct iwx_tx_cmd_gen3);
    if (!IntelP2PActionFrame::buildTfdPlan(
            sizeof(struct iwx_cmd_header), txCommandLength, 24,
            segmentLengths, static_cast<size_t>(segmentCount),
            NativeAwdlDirectedOriginTx::kMpduLength, &plan))
        return cancelBeforeDoorbell(EINVAL);

    const uint32_t generation = context->binding.generation;
    const IntelP2PActionTx::Result armResult = context->completion.arm(
        generation, static_cast<uint16_t>(ring->qid),
        static_cast<uint16_t>(ring->ring_count), index,
        context->sequenceControl, NativeAwdlDirectedOriginTx::kMpduLength,
        context->frameControl);
    if (armResult != IntelP2PActionTx::Result::kReady)
        return cancelBeforeDoorbell(EBUSY);

    memset(descriptor, 0, sizeof(*descriptor));
    memset(deviceCommand, 0, sizeof(*deviceCommand));
    deviceCommand->hdr.cmd = IWX_TX_CMD;
    deviceCommand->hdr.group_id = 0;
    deviceCommand->hdr.qid = static_cast<uint8_t>(ring->qid);
    deviceCommand->hdr.idx = static_cast<uint8_t>(index);
    const uint32_t txFlags = IWX_TX_FLAGS_CMD_RATE |
        IWX_TX_FLAGS_ENCRYPT_DIS;
    const uint32_t offloadAssist = IWX_TX_CMD_OFFLD_MH_SIZE(12);
    if (layout == IntelP2PFirmware::TxLayout::kGen2) {
        auto *txCommand = reinterpret_cast<struct iwx_tx_cmd_gen2 *>(
            deviceCommand->data);
        memset(txCommand, 0, sizeof(*txCommand));
        txCommand->len = htole16(NativeAwdlDirectedOriginTx::kMpduLength);
        txCommand->offload_assist = htole16(
            static_cast<uint16_t>(offloadAssist));
        txCommand->flags = htole32(txFlags);
        txCommand->rate_n_flags = htole32(rate);
        memcpy(reinterpret_cast<uint8_t *>(txCommand) + sizeof(*txCommand),
               raw, 24);
    } else {
        auto *txCommand = reinterpret_cast<struct iwx_tx_cmd_gen3 *>(
            deviceCommand->data);
        memset(txCommand, 0, sizeof(*txCommand));
        txCommand->len = htole16(NativeAwdlDirectedOriginTx::kMpduLength);
        txCommand->flags = htole16(static_cast<uint16_t>(txFlags));
        txCommand->offload_assist = htole32(offloadAssist);
        txCommand->rate_n_flags = htole32(rate);
        memcpy(reinterpret_cast<uint8_t *>(txCommand) + sizeof(*txCommand),
               raw, 24);
    }

    descriptor->num_tbs = htole16(plan.numTbs);
    descriptor->tbs[0].tb_len = htole16(plan.firstTbLength);
    uint64_t physicalAddress = htole64(txData->cmd_paddr);
    memcpy(&descriptor->tbs[0].addr, &physicalAddress,
           sizeof(physicalAddress));
    descriptor->tbs[1].tb_len = htole16(plan.commandTailLength);
    physicalAddress = htole64(txData->cmd_paddr + plan.firstTbLength);
    memcpy(&descriptor->tbs[1].addr, &physicalAddress,
           sizeof(physicalAddress));
    for (int segment = 0; segment < segmentCount; ++segment) {
        descriptor->tbs[segment + 2].tb_len = htole16(
            segmentLengths[segment]);
        physicalAddress = htole64(segments[segment].location);
        memcpy(&descriptor->tbs[segment + 2].addr, &physicalAddress,
               sizeof(physicalAddress));
    }
    txData->m = encodedMpdu;
    txData->in = nullptr;
    txData->type = IEEE80211_FC0_TYPE_DATA;
    owner->iwx_tx_update_byte_tbl(sc, ring, index, plan.frameByteCount,
                                  plan.numTbs);

    // The queue is already bound to the unicast RA and firmware TID 0. Keep
    // this final main-gate MCC/channel/ROC sample adjacent to the doorbell.
    const uint64_t preDoorbellUs = directedDataMonotonicUs();
    if (preDoorbellUs < context->binding.rocStartUs ||
        !directedDataSubmitHasDeadlineMargin(context, preDoorbellUs) ||
        !directedDataMainGateCheck(owner, context)) {
        const auto cancelled = context->completion.cancelUnsubmitted(
            generation, static_cast<uint16_t>(ring->qid), index);
        if (cancelled != IntelP2PActionTx::Result::kCancelled) {
            context->mbufHeldByRing = true;
            directedDataSetMayOwnResource(context, true);
            context->state = TahoeP2PDirectedDataState::kQuarantined;
            context->reason = TahoeP2PDirectedDataReason::kDrainMismatch;
            return ESTALE;
        }
        return cancelBeforeDoorbell(ESTALE);
    }

    ring->cur = (index + 1) % ring->ring_count;
    ++ring->queued;
    error = iwx_tahoe_p2p_tvqm_mark_doorbell(
        sc, queueLease, ring, index);
    if (error) {
        const auto cancelled = context->completion.cancelUnsubmitted(
            generation, static_cast<uint16_t>(ring->qid), index);
        if (cancelled != IntelP2PActionTx::Result::kCancelled) {
            context->mbufHeldByRing = true;
            directedDataSetMayOwnResource(context, true);
            context->state = TahoeP2PDirectedDataState::kQuarantined;
            context->reason = TahoeP2PDirectedDataReason::kDrainMismatch;
            return error;
        }
        ring->cur = index;
        --ring->queued;
        return cancelBeforeDoorbell(error);
    }

    // The queue lease marks everDoorbelled before MMIO so ambiguity can never
    // use the no-submit cleanup path. Sample the live owner/ROC after that lock
    // handoff, with a bounded reserve for slot one, immediately before commit.
    // If time/ownership changed in the handoff, cancel this exact unsubmitted
    // tracker and ring slot; the queue's sticky everDoorbelled history remains.
    if (!directedDataMainGateCheck(owner, context))
        return cancelMarkedBeforeDoorbell(ESTALE,
            TahoeP2PDirectedDataReason::kStaleEpoch);
    const uint64_t finalSubmitUs = directedDataMonotonicUs();
    if (!directedDataSubmitHasDeadlineMargin(context, finalSubmitUs)) {
        return cancelMarkedBeforeDoorbell(ETIMEDOUT,
            TahoeP2PDirectedDataReason::kExpired);
    }

    context->queueId = static_cast<uint16_t>(ring->qid);
    context->descriptorIndex = index;
    context->ringSize = static_cast<uint16_t>(ring->ring_count);
    context->expectedNextSsn = static_cast<uint16_t>(
        (index + 1) & (ring->ring_count - 1));
    packet->descriptorIndex = index;
    packet->expectedNextSsn = context->expectedNextSsn;
    directedDataSetMayOwnResource(context, true);
    context->doorbellIssued = true;
    // A newly submitted packet makes the run-level all-doorbells-complete
    // proof false until this exact slot's TX_RSP retires its DMA resources.
    context->completionObserved = false;
    context->mbufHeldByRing = true;
    packet->doorbellIssued = true;
    packet->doorbellUs = finalSubmitUs;
    packet->resourcesAbsent = false;
    context->sequenceReservationValid = false;
    context->state = TahoeP2PDirectedDataState::kInFlight;
    packet->permitIssued = false;
    permit->valid = false; // A permit can authorize exactly one doorbell.
    auto &witness = context->packetWitness[slot];
    witness.schema = 1;
    witness.size = sizeof(witness);
    witness.ownerSerial = context->binding.ownerSerial;
    witness.runSerial = context->binding.runSerial;
    witness.stationAllocationSerial = context->stationAllocationSerial;
    witness.queueAllocationSerial = context->queueAllocationSerial;
    witness.doorbellUs = packet->doorbellUs;
    witness.queue = context->queueId;
    witness.station = context->stationId;
    witness.descriptorIndex = index;
    // Preserve the single-packet diagnostic surface for existing readers;
    // Test130's immutable per-slot witnesses are stored separately above.
    context->txWitness = witness;
    IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR, ring->qid << 16 | ring->cur);
    error = iwx_tahoe_p2p_tvqm_finish_tx_submit(queueLease);
    if (error) {
        directedDataSetMayOwnResource(context, true);
        context->state = TahoeP2PDirectedDataState::kQuarantined;
        context->reason = TahoeP2PDirectedDataReason::kDoorbellUnknown;
        return error;
    }
    return 0;
}

struct DirectedDataSubmitAction {
    TahoeP2PStationLease *stationLease;
    TahoeP2PTxQueueLease *queueLease;
    TahoeP2PDirectedDataContext *context;
    TahoeP2PDirectedDataPermit *permit;
    mbuf_t encodedMpdu;
    int result;
    bool called;
};

static IOReturn directedDataTxSubmitAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataSubmitAction *>(actionArg);
    if (!owner || !action)
        return kIOReturnBadArgument;
    action->called = true;
    action->result = directedDataTxSubmitOnMainGate(owner, &owner->com,
        action->stationLease, action->queueLease, action->context,
        action->permit, action->encodedMpdu);
    return kIOReturnSuccess;
}

int iwx_tahoe_p2p_directed_data_tx_submit(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataPermit *permit, mbuf_t encodedMpdu)
{
    if (!encodedMpdu)
        return EINVAL;
    if (!owner || !sc || sc != &owner->com) {
        mbuf_freem(encodedMpdu);
        return EINVAL;
    }
    if (owner->tahoeP2pOnMainGate())
        return directedDataTxSubmitOnMainGate(owner, sc, stationLease,
            queueLease, context, permit, encodedMpdu);
    IOCommandGate *gate = owner->tahoeP2pCommandGate();
    if (!gate) {
        mbuf_freem(encodedMpdu);
        return EBUSY;
    }
    DirectedDataSubmitAction action{stationLease, queueLease, context,
        permit, encodedMpdu, EBUSY, false};
    const IOReturn gateResult = gate->attemptAction(
        directedDataTxSubmitAction, owner, &action, nullptr, nullptr);
    if (!action.called) {
        mbuf_freem(encodedMpdu);
        return gateResult == kIOReturnSuccess ? EBUSY : EIO;
    }
    return action.result;
}

static bool directedDataMatchesRetiredResponse(
    const TahoeP2PDirectedDataContext *context,
    const uint8_t *payload, size_t payloadLength, uint16_t queueId,
    uint8_t stationId)
{
    const size_t ssnOffset = offsetof(struct iwx_tx_resp, status) +
        sizeof(struct iwx_agg_tx_status);
    if (!context || !payload || payload[0] != 1 ||
        payloadLength < ssnOffset + sizeof(uint32_t) ||
        payloadLength < offsetof(struct iwx_tx_resp, seq_ctl) + 2 ||
        payloadLength < offsetof(struct iwx_tx_resp, byte_cnt) + 2 ||
        payloadLength < offsetof(struct iwx_tx_resp, frame_ctrl) + 2 ||
        payloadLength < offsetof(struct iwx_tx_resp, tx_queue) + 2 ||
        payloadLength < offsetof(struct iwx_tx_resp, ra_tid) + 1 ||
        directedDataReadLe16(payload +
            offsetof(struct iwx_tx_resp, tx_queue)) != queueId ||
        IWX_TX_RES_GET_RA(payload[offsetof(struct iwx_tx_resp, ra_tid)]) !=
            stationId ||
        IWX_TX_RES_GET_TID(payload[offsetof(struct iwx_tx_resp, ra_tid)]) != 0)
        return false;

    const uint16_t status = directedDataReadLe16(payload +
        offsetof(struct iwx_tx_resp, status));
    const uint16_t seq = directedDataReadLe16(payload +
        offsetof(struct iwx_tx_resp, seq_ctl));
    const uint16_t byteCount = directedDataReadLe16(payload +
        offsetof(struct iwx_tx_resp, byte_cnt));
    const uint16_t frameControl = directedDataReadLe16(payload +
        offsetof(struct iwx_tx_resp, frame_ctrl));
    const uint32_t ssn = uint32_t(payload[ssnOffset]) |
        (uint32_t(payload[ssnOffset + 1]) << 8) |
        (uint32_t(payload[ssnOffset + 2]) << 16) |
        (uint32_t(payload[ssnOffset + 3]) << 24);
    for (uint8_t slot = 0; slot < context->packetCount; ++slot) {
        const auto &prior = context->packets[slot];
        if (!prior.doorbellIssued ||
            !prior.completionObserved || !prior.resourcesAbsent)
            continue;
        if (prior.firmwareStatus == status &&
            prior.sequenceControl == seq && prior.byteCount == byteCount &&
            prior.responseFrameControl == frameControl &&
            (ssn & (context->ringSize - 1)) == prior.expectedNextSsn)
            return true;
    }
    return false;
}

bool iwx_tahoe_p2p_directed_data_tx_response(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context,
    struct iwx_rx_packet *packet, struct iwx_rx_data *rxData,
    TahoeP2PDirectedDataTxWitness::TxPassThrough *passThroughReason)
{
    using TahoeP2PDirectedDataTxWitness::TxPassThrough;
    const auto passThrough = [passThroughReason](TxPassThrough reason) {
        if (passThroughReason)
            *passThroughReason = reason;
        return false;
    };
    if (!owner || !owner->tahoeP2pOnMainGate())
        return passThrough(owner ? TxPassThrough::kOutsideMainGate :
                                   TxPassThrough::kMissingOwner);
    if (!sc || !stationLease || !queueLease || !context || !packet || !rxData)
        return passThrough(TxPassThrough::kInvalidArguments);
    if (!context->binding.runSerial ||
        !directedDataHasDoorbellHistory(context))
        return passThrough(TxPassThrough::kNoDoorbell);
    if (context->currentSlot >= context->packetCount)
        return passThrough(TxPassThrough::kInvalidArguments);
    auto &currentPacket = context->packets[context->currentSlot];
    const size_t payloadLength = iwx_rx_packet_payload_len(packet);
    if (payloadLength < offsetof(struct iwx_tx_resp, tx_queue) +
                            sizeof(uint16_t))
        return passThrough(TxPassThrough::kShortPayload);
    bus_dmamap_sync(sc->sc_dmat, rxData->map, 0, IWX_RBUF_SIZE,
                    BUS_DMASYNC_POSTREAD);
    const uint8_t *payload = reinterpret_cast<const uint8_t *>(packet->data);
    uint16_t responseQueue = 0;
    if (!IntelP2PActionTx::extractTxResponseQueueId(payload, payloadLength,
            offsetof(struct iwx_tx_resp, tx_queue), &responseQueue))
        return passThrough(TxPassThrough::kQueueDecodeFailed);
    if (responseQueue != context->queueId)
        return passThrough(TxPassThrough::kQueueMismatch);

    const bool allocationMatches =
        queueLease->allocationSerial == context->queueAllocationSerial &&
        stationLease->allocationSerial == context->stationAllocationSerial &&
        queueLease->queueId == context->queueId &&
        queueLease->stationId == context->stationId &&
        queueLease->stationRole == TahoeP2PStationRole::kDirectedPeerLink &&
        queueLease->firmwareTid == 0;
    const bool responseHasStation = payloadLength >
            offsetof(struct iwx_tx_resp, ra_tid) &&
        IWX_TX_RES_GET_RA(payload[offsetof(struct iwx_tx_resp, ra_tid)]) ==
            context->stationId &&
        IWX_TX_RES_GET_TID(payload[offsetof(struct iwx_tx_resp, ra_tid)]) == 0;
    const auto previousTicket = context->completion.snapshot();
    const bool liveOwned = allocationMatches &&
        queueLease->state == TahoeP2PResourceState::kActive &&
        context->state == TahoeP2PDirectedDataState::kInFlight &&
        previousTicket.armed && !previousTicket.completed;
    const bool retiredDuplicate = allocationMatches && responseHasStation &&
        directedDataMatchesRetiredResponse(context, payload, payloadLength,
                                            responseQueue,
                                            context->stationId);
    // A prior slot's exact late response is consumed before checking the
    // current tracker or live ring. Slot one may already be armed; that must
    // not make a slot-zero duplicate complete or quarantine slot one.
    if (retiredDuplicate)
        return true;
    // A qid/RA-TID tombstone catches duplicate and late owned replies after
    // queue cleanup. ticketPresent in BSD diagnostics is ledger history, not
    // a live hardware resource; this host tombstone is independent of it.
    const bool terminalTombstone = !allocationMatches && responseHasStation;
    if (!liveOwned) {
        if (!allocationMatches && !terminalTombstone)
            return passThrough(TxPassThrough::kAllocationAndRaTidMismatch);
        iwx_tahoe_p2p_directed_data_quarantine(context,
            previousTicket.completed ?
                TahoeP2PDirectedDataReason::kResponseDuplicate :
                TahoeP2PDirectedDataReason::kResponseForeign);
        return true;
    }

    struct iwx_tx_ring *ring = nullptr;
    IOInterruptState interruptState = 0;
    if (!iwx_tahoe_p2p_tvqm_lock_completion(
            sc, queueLease, responseQueue, &ring, &interruptState)) {
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kRingMismatch);
        return true;
    }
    if (!owner->tahoeP2pOnMainGate() ||
        !supportedFw68Tx(owner, sc) ||
        context->binding.generation != static_cast<uint32_t>(sc->sc_generation) ||
        context->binding.p2pFirmwareGeneration != sc->sc_p2p.fw_generation) {
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kStaleEpoch);
        return true;
    }
    const uint16_t index = context->descriptorIndex;
    if (!ring || ring->qid != responseQueue ||
        ring->ring_count != context->ringSize || index >= ring->ring_count ||
        ring->tail != index || ring->queued != 1 ||
        ring->cur != (index + 1) % ring->ring_count ||
        ring->data[index].m == nullptr || ring->data[index].in != nullptr ||
        ring->data[index].type != IEEE80211_FC0_TYPE_DATA ||
        !currentPacket.doorbellIssued ||
        currentPacket.descriptorIndex != index ||
        context->byteCount != NativeAwdlDirectedOriginTx::kMpduLength ||
        !responseHasStation) {
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kRingMismatch);
        return true;
    }

    const auto result = context->completion.completeDirectedData(
        context->binding.generation, payload, payloadLength,
        offsetof(struct iwx_tx_resp, status),
        offsetof(struct iwx_tx_resp, seq_ctl),
        offsetof(struct iwx_tx_resp, byte_cnt),
        offsetof(struct iwx_tx_resp, frame_ctrl),
        offsetof(struct iwx_tx_resp, tx_queue),
        offsetof(struct iwx_tx_resp, status) +
            sizeof(struct iwx_agg_tx_status));
    if (result != IntelP2PActionTx::Result::kCompletion &&
        result != IntelP2PActionTx::Result::kFrameFailed) {
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kResponseMismatch);
        return true;
    }
    if (iwx_tahoe_p2p_tvqm_tx_completed_locked(sc, queueLease) != 0) {
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kDrainMismatch);
        return true;
    }

    mbuf_t completedMbuf = ring->data[index].m;
    ring->data[index].m = nullptr;
    ring->data[index].in = nullptr;
    directedDataClearDescriptor(&ring->desc[index]);
    ring->tail = (index + 1) % ring->ring_count;
    --ring->queued;
    const auto completion = context->completion.snapshot();
    context->firmwareStatus = completion.status;
    context->completionObserved = completion.completed;
    context->frameAttemptSucceeded = completion.frameAttemptSucceeded;
    context->mbufHeldByRing = false;
    currentPacket.txResponseUs = directedDataMonotonicUs();
    currentPacket.firmwareStatus = completion.status;
    currentPacket.responseFrameControl = completion.responseFrameControl;
    currentPacket.completionObserved = completion.completed;
    currentPacket.frameAttemptSucceeded = completion.frameAttemptSucceeded;
    currentPacket.resourcesAbsent = true;
    currentPacket.originCompletionRecorded = false;
    context->completionObserved = directedDataHasDoorbellHistory(context) &&
        directedDataAllDoorbellsCompleted(context);
    context->frameAttemptSucceeded = context->completionObserved &&
        completion.frameAttemptSucceeded &&
        (context->currentSlot == 0 ||
         context->packets[0].frameAttemptSucceeded);
    context->state = TahoeP2PDirectedDataState::kCompleted;
    context->reason = completion.frameAttemptSucceeded ?
        TahoeP2PDirectedDataReason::kNone :
        TahoeP2PDirectedDataReason::kCompletionFailure;
    iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
    if (completedMbuf)
        mbuf_freem(completedMbuf);
    return true;
}

bool iwx_tahoe_p2p_directed_data_reject_ba(
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context, uint16_t queueId)
{
    if (!queueLease || !context || !context->binding.runSerial ||
        queueId != context->queueId)
        return false;
    const bool currentAllocation = queueLease->queueId == queueId &&
        queueLease->allocationSerial == context->queueAllocationSerial &&
        queueLease->stationRole == TahoeP2PStationRole::kDirectedPeerLink &&
        queueLease->firmwareTid == 0;
    if (!currentAllocation && !directedDataHasDoorbellHistory(context))
        return false;
    iwx_tahoe_p2p_directed_data_quarantine(context,
        TahoeP2PDirectedDataReason::kResponseForeign);
    return true;
}

void iwx_tahoe_p2p_directed_data_quarantine(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason)
{
    if (!context)
        return;
    directedDataSetMayOwnResource(context, true);
    context->reason = reason;
    context->state = TahoeP2PDirectedDataState::kQuarantined;
}

struct DirectedDataCloseIdentity {
    TahoeP2PDirectedDataContext *context;
    TahoeP2PDirectedDataOriginTicket ticket;
    uint64_t armSerial;
    uint64_t ownerSerial;
    uint64_t runSerial;
    bool ticketBound;
    bool originClosed;
};

static IOReturn directedDataCaptureCloseIdentityAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *identity = static_cast<DirectedDataCloseIdentity *>(actionArg);
    TahoeP2PDirectedDataContext *context = identity ? identity->context : nullptr;
    if (!owner || !identity || !context || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    identity->armSerial = context->armSerialHighWater;
    identity->ownerSerial = context->binding.ownerSerial;
    identity->runSerial = context->binding.runSerial;
    identity->ticketBound = context->ticketBound;
    identity->originClosed = context->originClosed;
    if (context->ticketBound)
        identity->ticket = context->originTicket;
    return kIOReturnSuccess;
}

struct DirectedDataCloseCommit {
    DirectedDataCloseIdentity identity;
    TahoeP2PDirectedDataReason reason;
    bool bsdCloseSucceeded;
    bool originInactive;
    int result;
};

static IOReturn directedDataCommitCloseAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *commit = static_cast<DirectedDataCloseCommit *>(actionArg);
    auto *identity = commit ? &commit->identity : nullptr;
    TahoeP2PDirectedDataContext *context = identity ? identity->context : nullptr;
    if (!owner || !commit || !identity || !context ||
        !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    const bool sameRun = context->armSerialHighWater == identity->armSerial &&
        context->binding.ownerSerial == identity->ownerSerial &&
        context->binding.runSerial == identity->runSerial &&
        context->ticketBound == identity->ticketBound &&
        (!identity->ticketBound || NativeAwdlDirectedOriginTx::sameTicket(
            context->originTicket, identity->ticket));
    if (!sameRun) {
        commit->result = ESTALE;
        return kIOReturnSuccess;
    }
    context->txWitness.rememberClose(directedDataMonotonicUs(),
                                    static_cast<uint32_t>(context->reason));
    if (!identity->originClosed && identity->ticketBound &&
        (!commit->bsdCloseSucceeded || !commit->originInactive)) {
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kTicketFailure);
        commit->result = commit->bsdCloseSucceeded ? EBUSY : EIO;
        return kIOReturnSuccess;
    }

    context->originClosed = true;
    if (commit->reason != TahoeP2PDirectedDataReason::kNone &&
        context->reason == TahoeP2PDirectedDataReason::kNone)
        context->reason = commit->reason;
    const bool anyDoorbell = directedDataHasDoorbellHistory(context);
    const bool allDoorbellsCompleted =
        directedDataAllDoorbellsCompleted(context);
    const bool unsubmittedNextSlotCandidate = anyDoorbell &&
        allDoorbellsCompleted && context->packetCount == 2 &&
        context->currentSlot == 1 && !context->packets[1].doorbellIssued &&
        (context->state == TahoeP2PDirectedDataState::kTicketBound ||
         context->state == TahoeP2PDirectedDataState::kPermitIssued ||
         context->state == TahoeP2PDirectedDataState::kClosed);
    if (unsubmittedNextSlotCandidate &&
        !directedDataRetireUnsubmittedNextSlotOnMainGate(
            owner, context, commit->originInactive)) {
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kDrainMismatch);
        commit->result = EBUSY;
        return kIOReturnSuccess;
    }
    if (anyDoorbell && (!allDoorbellsCompleted ||
        !context->completionObserved || context->mbufHeldByRing)) {
        iwx_tahoe_p2p_directed_data_quarantine(context,
            TahoeP2PDirectedDataReason::kDoorbellUnknown);
        commit->result = EBUSY;
        return kIOReturnSuccess;
    }
    if (!anyDoorbell &&
        context->state != TahoeP2PDirectedDataState::kQuarantined)
        context->state = TahoeP2PDirectedDataState::kClosed;
    directedDataMarkCompletedClosed(context);
    if (directedDataCanClearMayOwnResource(context))
        directedDataSetMayOwnResource(context, false);
    commit->result = 0;
    return kIOReturnSuccess;
}

int iwx_tahoe_p2p_directed_data_close(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason)
{
    if (!owner || !context)
        return EINVAL;
    DirectedDataCloseIdentity identity{};
    identity.context = context;
    if (directedDataRunMainGateAction(owner,
            directedDataCaptureCloseIdentityAction, &identity) !=
        kIOReturnSuccess)
        return EBUSY;

    DirectedDataCloseCommit commit{};
    commit.identity = identity;
    commit.reason = reason;
    commit.bsdCloseSucceeded = true;
    commit.originInactive = true;
    commit.result = EBUSY;
    if (identity.ticketBound && !identity.originClosed) {
        // BSD close may wait for output/pop completion. Keep it outside the
        // work-loop gate, then commit only if this exact HAL run still owns it.
        if (owner->tahoeP2pOnMainGate())
            return EBUSY;
        commit.bsdCloseSucceeded =
            NativeAwdlBSD::closeDirectedOriginTx(identity.ticket);
        NativeAwdlDirectedOriginTx::Snapshot origin{};
        NativeAwdlBSD::snapshotDirectedOriginTx(&origin);
        commit.originInactive =
            origin.state != NativeAwdlDirectedOriginTx::State::Open &&
            origin.state != NativeAwdlDirectedOriginTx::State::Queued &&
            origin.state != NativeAwdlDirectedOriginTx::State::Popping &&
            !origin.packetQueued && !origin.packetPopping;
    }
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataCommitCloseAction, &commit);
    return gateResult == kIOReturnSuccess ? commit.result : EBUSY;
}

bool iwx_tahoe_p2p_directed_data_never_armed(
    ItlIwx *owner, const TahoeP2PDirectedDataContext *context)
{
    if (!context)
        return true;
    TahoeP2PDirectedDataSnapshot snapshot{};
    return iwx_tahoe_p2p_directed_data_snapshot(owner, context, &snapshot) &&
        !snapshot.completionArmed && !snapshot.doorbellIssued &&
        !snapshot.mbufHeldByRing;
}

bool iwx_tahoe_p2p_directed_data_defer_tx_ring_reset(
    ItlIwx *owner, const TahoeP2PDirectedDataContext *context,
    const TahoeP2PTxQueueLease *queueLease, uint16_t queueId)
{
    if (!owner || !context || !queueLease)
        return false;
    uint16_t leaseQueueId;
    uint64_t leaseAllocationSerial;
    TahoeP2PStationRole leaseStationRole;
    uint8_t leaseTid;
    if (queueLease->stateLock) {
        IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
            queueLease->stateLock);
        leaseQueueId = queueLease->queueId;
        leaseAllocationSerial = queueLease->allocationSerial;
        leaseStationRole = queueLease->stationRole;
        leaseTid = queueLease->firmwareTid;
        IOSimpleLockUnlockEnableInterrupt(queueLease->stateLock,
                                           interruptState);
    } else {
        leaseQueueId = queueLease->queueId;
        leaseAllocationSerial = queueLease->allocationSerial;
        leaseStationRole = queueLease->stationRole;
        leaseTid = queueLease->firmwareTid;
    }
    if (queueId != leaseQueueId)
        return false;

    TahoeP2PDirectedDataSnapshot snapshot{};
    if (!iwx_tahoe_p2p_directed_data_snapshot(owner, context, &snapshot, true))
        return leaseStationRole == TahoeP2PStationRole::kDirectedPeerLink &&
            leaseTid == 0;
    if (!snapshot.runSerial || queueId != snapshot.queueId ||
        leaseAllocationSerial != snapshot.queueAllocationSerial ||
        leaseStationRole != TahoeP2PStationRole::kDirectedPeerLink ||
        leaseTid != 0)
        return false;
    return !snapshot.hardStopDrained &&
        (snapshot.doorbellIssued || snapshot.mbufHeldByRing ||
         (snapshot.completionArmed && !snapshot.completionObserved) ||
         snapshot.state == TahoeP2PDirectedDataState::kQuarantined);
}

void iwx_tahoe_p2p_directed_data_record_stop_proof(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataStopProof proof)
{
    if (!context)
        return;
    switch (proof) {
    case TahoeP2PDirectedDataStopProof::kMasterDisabledObserved:
        __atomic_fetch_or(&context->stopProofMask,
            kTahoeP2PDirectedDataStopMasterDisabled, __ATOMIC_ACQ_REL);
        break;
    case TahoeP2PDirectedDataStopProof::kSwResetIssued:
        __atomic_fetch_or(&context->stopProofMask,
            kTahoeP2PDirectedDataStopSwReset, __ATOMIC_ACQ_REL);
        break;
    case TahoeP2PDirectedDataStopProof::kOwnedTxRingResetAfterStop:
        __atomic_fetch_or(&context->stopProofMask,
            kTahoeP2PDirectedDataStopOwnedRingReset, __ATOMIC_ACQ_REL);
        break;
    }
}

struct DirectedDataHardStopFinalize {
    TahoeP2PDirectedDataContext *context;
    uint64_t armSerial;
    uint64_t ownerSerial;
    uint64_t runSerial;
    uint64_t stationAllocationSerial;
    uint64_t queueAllocationSerial;
    uint32_t requiredStopProofs;
    bool queueReleased;
    int result;
};

static IOReturn directedDataHardStopFinalizeAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *finalize = static_cast<DirectedDataHardStopFinalize *>(actionArg);
    TahoeP2PDirectedDataContext *context = finalize ? finalize->context : nullptr;
    if (!owner || !finalize || !context || !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    const uint32_t stopProofs = __atomic_load_n(&context->stopProofMask,
                                                __ATOMIC_ACQUIRE);
    if (context->armSerialHighWater != finalize->armSerial ||
        context->binding.ownerSerial != finalize->ownerSerial ||
        context->binding.runSerial != finalize->runSerial ||
        context->stationAllocationSerial !=
            finalize->stationAllocationSerial ||
        context->queueAllocationSerial != finalize->queueAllocationSerial ||
        (stopProofs & finalize->requiredStopProofs) !=
            finalize->requiredStopProofs ||
        (context->ticketBound && !context->originClosed) ||
        (!finalize->queueReleased && (context->mbufHeldByRing ||
         (directedDataHasDoorbellHistory(context) &&
          (!context->completionObserved ||
           !directedDataAllDoorbellsCompleted(context)))))) {
        finalize->result = EBUSY;
        return kIOReturnSuccess;
    }
    // Never erase the completion identity until the exact allocation has
    // passed its checked hard-stop ring release above.
    if (context->completion.snapshot().armed) {
        const auto result = context->completion.firmwareStoppedAndDrained();
        if (result != IntelP2PActionTx::Result::kReady) {
            finalize->result = EBUSY;
            return kIOReturnSuccess;
        }
    }
    context->mbufHeldByRing = false;
    context->completionObserved = context->completionObserved ||
        context->firmwareStatus != 0xffff;
    context->state = TahoeP2PDirectedDataState::kClosed;
    context->hardStopDrained = finalize->queueReleased;
    if (directedDataCanClearMayOwnResource(context))
        directedDataSetMayOwnResource(context, false);
    finalize->result = 0;
    return kIOReturnSuccess;
}

int iwx_tahoe_p2p_directed_data_drain_after_hardstop(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context)
{
    if (!owner || !sc || sc != &owner->com || !stationLease ||
        !queueLease || !context)
        return EBUSY;
    TahoeP2PDirectedDataSnapshot before{};
    if (!iwx_tahoe_p2p_directed_data_snapshot(owner, context, &before, true) ||
        (before.stopProofMask & kTahoeP2PDirectedDataRequiredStopProofs) !=
            kTahoeP2PDirectedDataRequiredStopProofs ||
        (before.originTicketBound && !before.originClosed) ||
        (before.doorbellIssued && !before.completionObserved &&
         !before.mbufHeldByRing))
        return EBUSY;
    const bool queueMayExist = iwx_tahoe_p2p_tvqm_may_exist(queueLease);
    if (queueMayExist) {
        const int releaseError =
            iwx_tahoe_p2p_tvqm_release_after_directed_data_hardstop(
                owner, sc, stationLease, queueLease, context);
        if (releaseError)
            return releaseError;
    }
    DirectedDataHardStopFinalize finalize{
        context, before.armSerial, before.ownerSerial, before.runSerial,
        before.stationAllocationSerial, before.queueAllocationSerial,
        kTahoeP2PDirectedDataRequiredStopProofs, queueMayExist, EBUSY};
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataHardStopFinalizeAction, &finalize, true);
    return gateResult == kIOReturnSuccess ? finalize.result : EBUSY;
}

static bool directedDataCaptureSnapshot(
    const TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataSnapshot *snapshot)
{
    if (!context || !snapshot)
        return false;
    const auto completion = context->completion.snapshot();
    TahoeP2PDirectedDataSnapshot value{};
    value.state = context->state;
    value.reason = context->reason;
    value.armSerial = context->armSerialHighWater;
    value.ticketSerial = context->originTicket.ticketSerial;
    value.packetToken = context->packetToken;
    value.ownerSerial = context->binding.ownerSerial;
    value.runSerial = context->binding.runSerial;
    value.interfaceIncarnation = context->interfaceIncarnation;
    value.stationAllocationSerial = context->stationAllocationSerial;
    value.queueAllocationSerial = context->queueAllocationSerial;
    value.rocToken = context->binding.rocToken;
    value.deadlineUs = context->binding.deadlineUs;
    value.generation = context->binding.generation;
    value.p2pFirmwareGeneration = context->binding.p2pFirmwareGeneration;
    value.mcc = context->binding.mcc;
    value.ifindex = context->ifindex;
    value.queueId = context->queueId;
    value.stationId = context->stationId;
    value.descriptorIndex = context->descriptorIndex;
    value.ringSize = context->ringSize;
    value.sequenceControl = context->sequenceControl;
    value.frameControl = context->frameControl;
    value.byteCount = context->byteCount;
    value.expectedNextSsn = context->expectedNextSsn;
    value.reservedWifiSequence = context->reservedWifiSequence;
    value.reservedAwdlSequence = context->reservedAwdlSequence;
    value.firmwareStatus = context->firmwareStatus;
    value.stopProofMask = __atomic_load_n(&context->stopProofMask,
                                          __ATOMIC_ACQUIRE);
    value.originWindowBound = context->originWindowBound;
    value.originTicketBound = context->ticketBound && !context->originClosed;
    value.originClosed = context->originClosed;
    value.completionArmed = completion.armed;
    value.sequenceReservationValid = context->sequenceReservationValid;
    value.permitIssued = context->permitIssued;
    value.doorbellIssued = directedDataHasDoorbellHistory(context);
    value.completionObserved = value.doorbellIssued &&
        directedDataAllDoorbellsCompleted(context);
    value.frameAttemptSucceeded = context->frameAttemptSucceeded;
    value.mbufHeldByRing = context->mbufHeldByRing;
    value.hardStopDrained = context->hardStopDrained;
    value.packetCount = context->packetCount;
    value.currentSlot = context->currentSlot;
    for (uint8_t slot = 0; slot < kTahoeP2PDirectedDataMaxPackets; ++slot) {
        const auto &source = context->packets[slot];
        auto &destination = value.packets[slot];
        destination.packetToken = source.packetToken;
        destination.doorbellUs = source.doorbellUs;
        destination.txResponseUs = source.txResponseUs;
        destination.exactReplyCaptureUs = source.exactReplyCaptureUs;
        destination.exactReplyInputUs = source.exactReplyInputUs;
        destination.wifiSequence = source.wifiSequence;
        destination.awdlSequence = source.awdlSequence;
        destination.descriptorIndex = source.descriptorIndex;
        destination.expectedNextSsn = source.expectedNextSsn;
        destination.sequenceControl = source.sequenceControl;
        destination.frameControl = source.frameControl;
        destination.responseFrameControl = source.responseFrameControl;
        destination.byteCount = source.byteCount;
        destination.firmwareStatus = source.firmwareStatus;
        destination.slot = source.slot;
        destination.identityBound = source.identityBound;
        destination.sequenceReserved = source.sequenceReserved;
        destination.permitIssued = source.permitIssued;
        destination.doorbellIssued = source.doorbellIssued;
        destination.completionObserved = source.completionObserved;
        destination.frameAttemptSucceeded = source.frameAttemptSucceeded;
        destination.exactReplyCaptured = source.exactReplyCaptured;
        destination.exactReplyDelivered = source.exactReplyDelivered;
        destination.originDoorbellRecorded = source.originDoorbellRecorded;
        destination.originCompletionRecorded = source.originCompletionRecorded;
        destination.resourcesAbsent = source.resourcesAbsent;
    }
    *snapshot = value;
    return true;
}

struct DirectedDataTxWitnessCut {
    TahoeP2PDirectedDataContext *context;
    uint64_t ownerSerial;
    uint64_t runSerial;
    TahoeP2PDirectedDataTxWitness::Snapshot *out;
};

static IOReturn directedDataSealTxWitnessAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *cut = static_cast<DirectedDataTxWitnessCut *>(actionArg);
    if (!owner || !owner->tahoeP2pOnMainGate() || !cut)
        return kIOReturnBadArgument;
    auto &witness = cut->context->txWitness;
    if (!witness.seal(cut->ownerSerial, cut->runSerial,
                      directedDataMonotonicUs()))
        return kIOReturnNotFound;
    *cut->out = witness;
    return kIOReturnSuccess;
}

bool iwx_tahoe_p2p_directed_data_seal_tx_witness(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataBinding &binding,
    TahoeP2PDirectedDataTxWitness::Snapshot *out)
{
    if (!context || !out || !binding.runSerial)
        return false;
    DirectedDataTxWitnessCut cut{context, binding.ownerSerial,
                                 binding.runSerial, out};
    return directedDataRunMainGateAction(owner, directedDataSealTxWitnessAction,
                                         &cut) == kIOReturnSuccess;
}

TahoeP2PDirectedDataTxWitness::Snapshot *
iwx_tahoe_p2p_directed_data_tx_witness_for_descriptor(
    TahoeP2PDirectedDataContext *context, uint16_t queueId,
    uint16_t descriptorIndex)
{
    if (!context || !context->binding.runSerial || queueId != context->queueId)
        return nullptr;
    TahoeP2PDirectedDataTxWitness::Snapshot *match = nullptr;
    for (uint8_t slot = 0; slot < context->packetCount; ++slot) {
        const auto &packet = context->packets[slot];
        if (!packet.doorbellIssued ||
            packet.descriptorIndex != descriptorIndex ||
            context->packetWitness[slot].runSerial != context->binding.runSerial)
            continue;
        if (match)
            return nullptr;
        match = &context->packetWitness[slot];
    }
    return match;
}

struct DirectedDataSnapshotAction {
    const TahoeP2PDirectedDataContext *context;
    TahoeP2PDirectedDataSnapshot *snapshot;
    bool valid;
};

static IOReturn directedDataSnapshotAction(
    OSObject *, void *ownerArg, void *actionArg, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(ownerArg);
    auto *action = static_cast<DirectedDataSnapshotAction *>(actionArg);
    if (!owner || !action || !action->context || !action->snapshot ||
        !owner->tahoeP2pOnMainGate())
        return kIOReturnBadArgument;
    action->valid = directedDataCaptureSnapshot(action->context,
                                                 action->snapshot);
    return action->valid ? kIOReturnSuccess : kIOReturnNotReady;
}

bool iwx_tahoe_p2p_directed_data_snapshot(
    ItlIwx *owner, const TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataSnapshot *snapshot, bool tryOnly,
    int *gateResultOut)
{
    if (gateResultOut)
        *gateResultOut = static_cast<int>(kIOReturnBadArgument);
    if (!owner || !context || !snapshot)
        return false;
    DirectedDataSnapshotAction action{context, snapshot, false};
    const IOReturn gateResult = directedDataRunMainGateAction(owner,
        directedDataSnapshotAction, &action, tryOnly);
    if (gateResultOut)
        *gateResultOut = static_cast<int>(gateResult);
    return gateResult == kIOReturnSuccess && action.valid;
}

#endif // ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332

#endif // AIRPORT_TAHOE
