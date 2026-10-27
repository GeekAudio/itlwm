// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwxP2PAction.hpp"

#ifdef AIRPORT_TAHOE

#include "ItlIwx.hpp"
#include "../../native/p2p_tx_firmware.hpp"
#include "../../native/awdl_action_frame.hpp"
#include "../../native/awdl_action_encode.hpp"
#include "../../native/awdl_mif_encode.hpp"
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../../native/awdl_native_bsd_data_25G332.hpp"
#include "../../native/awdl_data_frame.hpp"
#endif

#include <IOKit/IOLib.h>
#include <sys/errno.h>
#include <string.h>

namespace {

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
                                            IntelP2PActionFrame::FrameInfo *info)
{
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
        if (awdlInfo.subtype == 0)
            return frameLength <= NativeAwdl::kMaximumEncodedPsfLength;
        if (awdlInfo.subtype == 3)
            return frameLength <= NativeAwdl::kMaximumEncodedMifLength;
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
    mbuf_t frame, uint64_t nativeDataToken)
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
    bool validData=false;
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    if(nativeDataToken&&frameLength<=2048) {
        uint8_t raw[2048];NativeAwdlData::DecodedFrame parsed{};
        if(mbuf_copydata(frame,0,frameLength,raw)==0&&
           NativeAwdlData::decodeIpv6DataMpdu(raw,frameLength,&parsed)==NativeAwdlData::Status::Ok&&
           parsed.frameControl==0x0008&&parsed.packetCount==1&&
           !memcmp(parsed.sourceAddress,sc->sc_p2p.mac_address,6)) {
            memcpy(frameHeaderAndBody,raw,24);
            frameInfo.headerLength=24;frameInfo.frameControl=0x0008;
            frameInfo.sequenceControl=uint16_t(raw[22]|(uint16_t(raw[23])<<8));validData=true;
        }
    }
#endif
    if ((nativeDataToken&&!validData)||(!nativeDataToken&&!copyAndValidateDiagnosticFrame(frame, frameLength,
                                        sc->sc_p2p.mac_address,
                                        frameHeaderAndBody, &frameInfo))) {
        mbuf_freem(frame);
        recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kFrameEncoding,
                          EINVAL);
        return EINVAL;
    }
    if (frameInfo.headerLength != ieee80211_get_hdrlen(
            reinterpret_cast<const struct ieee80211_frame *>(frameHeaderAndBody))) {
        mbuf_freem(frame);
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kMacHeaderLength, EINVAL);
        return EINVAL;
    }

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

    context->generation = generation;
    context->rocToken = rocToken;
    context->queueId = static_cast<uint16_t>(ring->qid);
    context->descriptorIndex = index;
    context->sequenceControl = sequenceControl;
    context->frameControl = frameInfo.frameControl;
    context->frameByteCount = static_cast<uint16_t>(frameLength);
    context->nativeDataToken = nativeDataToken;
    context->state = TahoeP2PActionTxState::kInFlight;
    resetP2PTxRxDiagnostics(&context->rxDiagnostics,
                            static_cast<uint16_t>(ring->qid));

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
        context->nativeDataToken = 0;
        return cancelBeforeDoorbell(
            TahoeP2PActionTxSubmitStage::kDoorbellMark, error);
    }
    IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR, ring->qid << 16 | ring->cur);
    recordSubmitStage(context, TahoeP2PActionTxSubmitStage::kDoorbellIssued, 0);

    /* The doorbell is irreversible: a post-submit error quarantines the slot. */
    error = iwx_tahoe_p2p_tvqm_finish_tx_submit(queueLease);
    if (error) {
        context->state = TahoeP2PActionTxState::kQuarantined;
        recordSubmitStage(context,
            TahoeP2PActionTxSubmitStage::kPostDoorbellFinish, error);
        XYLog("%s: finish after P2P Action doorbell failed (%d); slot retained\n",
              sc->sc_dev.dv_xname, error);
    }
    return 0;
}

bool iwx_tahoe_p2p_action_tx_response(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PActionTxContext *context,
    struct iwx_rx_packet *packet, struct iwx_rx_data *rxData)
{
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
        ring->data[index].type != (context->nativeDataToken?IEEE80211_FC0_TYPE_DATA:IEEE80211_FC0_TYPE_MGT)) {
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
        if (diagnosticQueueMatch)
            recordP2PTxRxReject(diagnostics,
                TahoeP2PTxRxRejectReason::kCompletionRejected,
                static_cast<uint32_t>(result));
        context->state = TahoeP2PActionTxState::kQuarantined;
        iwx_tahoe_p2p_tvqm_unlock(queueLease, interruptState);
        return true;
    }

    if (iwx_tahoe_p2p_tvqm_tx_completed_locked(sc, queueLease) != 0) {
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
    if(context->nativeDataToken) {
        NativeAwdlBSD::completed(context->nativeDataToken,
            result==IntelP2PActionTx::Result::kCompletion);
        context->nativeDataToken=0;
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
        if(context->nativeDataToken)NativeAwdlBSD::submitted(context->nativeDataToken,ECANCELED);
#endif
        context->nativeDataToken=0;
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

#endif // AIRPORT_TAHOE
