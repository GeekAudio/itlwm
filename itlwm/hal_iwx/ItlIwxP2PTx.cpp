// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwxP2PTx.hpp"

#ifdef AIRPORT_TAHOE

#include "ItlIwx.hpp"
#include "../../native/p2p_tx_resources.hpp"

#include <IOKit/IOLib.h>
#include <sys/errno.h>
#include <string.h>

namespace {

static constexpr uint8_t kDataPathScdQueueConfig = 0x17;
static constexpr uint8_t kLegacyQueueApiVersion = 2;
static constexpr uint16_t kFirmwareManagementTid = IWX_MGMT_TID;
// Test054 is deliberately bounded to the observed fw68 collision at qid 3.
// Other occupied qids continue to fail closed until they have independent
// owner and queue-binding evidence.
static constexpr uint16_t kLegacyP2pCollisionPilotQueue = 3;
static constexpr uint8_t kLegacyP2pCollisionPilotStation = 3;
static_assert(kFirmwareManagementTid == 15,
              "P2P management queue uses firmware TID 15");

enum P2PTxDmaFailurePhase : uint32_t {
    kP2PTxDmaNoFailure = 0,
    kP2PTxDmaInvalidRingSize = 1,
    kP2PTxDmaOuterRing = 2,
    kP2PTxDmaDescriptors = 3,
    kP2PTxDmaByteCountTable = 4,
    kP2PTxDmaCommandRing = 5,
    kP2PTxDmaDescriptorMap = 6
};

static void publishAddStationDiagnostic(
    ItlIwx *owner, uint8_t stationId, uint32_t macIdAndColor,
    uint8_t stationType, bool stationTypeApi, uint16_t commandLength,
    uint8_t commandVersion, uint8_t notificationVersion, int sendResult,
    uint32_t firmwareStatus, bool firmwareStatusValid)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PTxAddStaAttempted", uint32_t(1), 32);
    controller->setProperty("NativeP2PTxAddStaId", uint32_t(stationId), 32);
    controller->setProperty("NativeP2PTxAddStaMacIdColor", macIdAndColor, 32);
    controller->setProperty("NativeP2PTxAddStaType", uint32_t(stationType), 32);
    controller->setProperty("NativeP2PTxAddStaTypeApi", uint32_t(stationTypeApi), 32);
    controller->setProperty("NativeP2PTxAddStaCommandLength",
                            uint32_t(commandLength), 32);
    controller->setProperty("NativeP2PTxAddStaCommandVersion",
                            uint32_t(commandVersion), 32);
    controller->setProperty("NativeP2PTxAddStaNotificationVersion",
                            uint32_t(notificationVersion), 32);
    controller->setProperty("NativeP2PTxAddStaSendResult",
                            uint32_t(sendResult), 32);
    controller->setProperty("NativeP2PTxAddStaStatusValid",
                            uint32_t(firmwareStatusValid), 32);
    controller->setProperty("NativeP2PTxAddStaFirmwareStatus",
                            firmwareStatusValid ? firmwareStatus : UINT32_MAX, 32);
}

static void publishQueueDiagnostic(ItlIwx *owner, bool commandAttempted,
                                   int sendResult, int parseResult,
                                   bool responseValid, uint16_t responseFlags,
                                   uint16_t queueId, uint16_t writePointer,
                                   uint8_t firmwareTid,
                                   uint32_t dmaFailurePhase)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PTxQueueAttempted",
                            uint32_t(commandAttempted), 32);
    controller->setProperty("NativeP2PTxQueueSendResult",
                            static_cast<uint32_t>(sendResult), 32);
    controller->setProperty("NativeP2PTxQueueParseResult",
                            static_cast<uint32_t>(parseResult), 32);
    controller->setProperty("NativeP2PTxQueueResponseValid",
                            uint32_t(responseValid), 32);
    controller->setProperty("NativeP2PTxQueueResponseFlags",
                            responseValid ? uint32_t(responseFlags) : UINT32_MAX, 32);
    controller->setProperty("NativeP2PTxQueueResponseId",
                            responseValid ? uint32_t(queueId) : UINT32_MAX, 32);
    controller->setProperty("NativeP2PTxQueueWritePointer",
                            responseValid ? uint32_t(writePointer) : UINT32_MAX, 32);
    controller->setProperty("NativeP2PTxQueueFirmwareTid",
                            commandAttempted ? uint32_t(firmwareTid) : UINT32_MAX,
                            32);
    controller->setProperty("NativeP2PTxQueueCommandVersion",
        uint32_t(owner->iwx_lookup_cmd_ver(&owner->com, IWX_LONG_GROUP,
                                           IWX_SCD_QUEUE_CFG)), 32);
    controller->setProperty("NativeP2PTxQueueNotificationVersion",
        uint32_t(owner->iwx_lookup_notif_ver(&owner->com, IWX_LONG_GROUP,
                                             IWX_SCD_QUEUE_CFG)), 32);
    controller->setProperty("NativeP2PTxDmaFailurePhase", dmaFailurePhase, 32);
}

static int queueApiForFirmware(ItlIwx *owner, struct iwx_softc *sc,
                               IntelP2PTx::QueueApi *api)
{
    if (!owner || !sc || !api)
        return EINVAL;

    const uint8_t dataPathVersion = owner->iwx_lookup_cmd_ver(
        sc, IWX_DATA_PATH_GROUP, kDataPathScdQueueConfig);
    // This HAL's tested contract is the legacy LONG_GROUP v2 API. A firmware
    // that advertises DATA_PATH/0x17 must use its own separately validated
    // adapter; never mix a modern allocation command with legacy teardown.
    if (dataPathVersion != IWX_FW_CMD_VER_UNKNOWN)
        return EOPNOTSUPP;

    // Firmware without DATA_PATH/SCD_QUEUE_CONFIG must use the older
    // LONG_GROUP/SCD_QUEUE_CFG v2 contract. Never reinterpret an unknown or
    // unsupported DATA_PATH version as permission to use the legacy API.
    if (owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_SCD_QUEUE_CFG) !=
            kLegacyQueueApiVersion ||
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP,
                                    IWX_SCD_QUEUE_CFG) !=
            kLegacyQueueApiVersion ||
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_TXPATH_FLUSH) !=
            2 ||
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_TXPATH_FLUSH) !=
            1 ||
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_REMOVE_STA) != 2)
        return EOPNOTSUPP;

    *api = IntelP2PTx::QueueApi::kLegacyDynamicDqa;
    return 0;
}

static int flushLegacyP2pStationQueue(ItlIwx *owner, struct iwx_softc *sc,
                                      uint8_t stationId, uint16_t queueId,
                                      const struct iwx_tx_ring *ring,
                                      bool strictEmptyQueueProof = false)
{
    if (!owner || !sc || !ring || ring->ring_count < 8 ||
        (ring->ring_count & (ring->ring_count - 1)) != 0 ||
        ring->cur != ring->tail || ring->queued != 0)
        return EBUSY;

    struct iwx_tx_path_flush_cmd command{};
    command.sta_id = htole32(stationId);
    command.tid_mask = htole16(0xffff);
    struct iwx_host_cmd hostCommand{};
    hostCommand.id = IWX_TXPATH_FLUSH;
    hostCommand.flags = IWX_CMD_WANT_RESP;
    hostCommand.resp_pkt_len = sizeof(struct iwx_rx_packet) +
        sizeof(struct iwx_tx_path_flush_cmd_rsp);
    hostCommand.data[0] = &command;
    hostCommand.len[0] = sizeof(command);

    int error = owner->iwx_send_cmd(sc, &hostCommand);
    if (error) {
        if (hostCommand.resp_pkt)
            owner->iwx_free_resp(sc, &hostCommand);
        return error;
    }

    struct iwx_rx_packet *packet = hostCommand.resp_pkt;
    if (!packet || (packet->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        if (packet)
            owner->iwx_free_resp(sc, &hostCommand);
        return EIO;
    }
    if (iwx_rx_packet_payload_len(packet) !=
        sizeof(struct iwx_tx_path_flush_cmd_rsp)) {
        owner->iwx_free_resp(sc, &hostCommand);
        return EIO;
    }

    const auto *response = reinterpret_cast<
        const struct iwx_tx_path_flush_cmd_rsp *>(packet->data);
    bool queueReported = false;
    uint16_t readAfterFlush = 0;
    uint16_t readBeforeFlush = 0;
    const uint16_t responseStation = le16toh(response->sta_id);
    const uint16_t flushedQueueCount =
        le16toh(response->num_flushed_queues);
    if (responseStation != stationId ||
        flushedQueueCount > IWX_TX_FLUSH_QUEUE_RSP) {
        owner->iwx_free_resp(sc, &hostCommand);
        return EIO;
    }

    for (uint16_t i = 0; i < flushedQueueCount; ++i) {
        const struct iwx_flush_queue_info &entry = response->queues[i];
        const uint16_t tid = le16toh(entry.tid);
        const uint16_t flushedQueue = le16toh(entry.queue_num);
        if (flushedQueue != queueId)
            continue;
        if (queueReported || tid != kFirmwareManagementTid) {
            owner->iwx_free_resp(sc, &hostCommand);
            return EIO;
        }
        queueReported = true;
        readBeforeFlush = le16toh(entry.read_before_flush);
        readAfterFlush = le16toh(entry.read_after_flush);
    }

    owner->iwx_free_resp(sc, &hostCommand);
    // Linux accepts a well-formed station flush ACK with zero reported
    // queues. The P2P request still has independent completion evidence and
    // is followed by REMOVE_STA ACK before any DMA is released.
    if (flushedQueueCount == 0)
        return strictEmptyQueueProof ? EIO : 0;
    if (strictEmptyQueueProof && flushedQueueCount != 1)
        return EIO;
    if (!queueReported)
        return EIO;

    // The response's scheduler read pointer is independent firmware evidence
    // that this station/TID queue is empty. This queue has no IEEE80211 node,
    // so do not pass it through generic station reclaim helpers.
    const uint16_t readIndex = static_cast<uint16_t>(
        IWX_AGG_SSN_TO_TXQ_IDX(readAfterFlush, ring->ring_count));
    const uint16_t hostIndex = static_cast<uint16_t>(
        IWX_AGG_SSN_TO_TXQ_IDX(ring->cur, ring->ring_count));
    if (readIndex != hostIndex)
        return EBUSY;
    if (strictEmptyQueueProof) {
        const uint16_t readBefore = static_cast<uint16_t>(
            IWX_AGG_SSN_TO_TXQ_IDX(readBeforeFlush, ring->ring_count));
        if (readBefore != hostIndex)
            return EBUSY;
    }
    return 0;
}

static int flushLegacyP2pAllocationBinding(
    ItlIwx *owner, struct iwx_softc *sc, uint8_t stationId,
    uint16_t queueId, uint16_t writePointer)
{
    if (!owner || !sc || !owner->nativeP2pCommandAllowed() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0)
        return EBUSY;

    struct iwx_tx_path_flush_cmd command{};
    command.sta_id = htole32(stationId);
    command.tid_mask = htole16(0xffff);
    struct iwx_host_cmd hostCommand{};
    hostCommand.id = IWX_TXPATH_FLUSH;
    hostCommand.flags = IWX_CMD_WANT_RESP;
    hostCommand.resp_pkt_len = sizeof(struct iwx_rx_packet) +
        sizeof(struct iwx_tx_path_flush_cmd_rsp);
    hostCommand.data[0] = &command;
    hostCommand.len[0] = sizeof(command);

    int error = owner->iwx_send_cmd(sc, &hostCommand);
    if (error) {
        if (hostCommand.resp_pkt)
            owner->iwx_free_resp(sc, &hostCommand);
        return error;
    }
    struct iwx_rx_packet *packet = hostCommand.resp_pkt;
    if (!packet || (packet->hdr.group_id & IWX_CMD_FAILED_MSK) ||
        iwx_rx_packet_payload_len(packet) !=
            sizeof(struct iwx_tx_path_flush_cmd_rsp)) {
        if (packet)
            owner->iwx_free_resp(sc, &hostCommand);
        return EIO;
    }

    const auto *response = reinterpret_cast<
        const struct iwx_tx_path_flush_cmd_rsp *>(packet->data);
    const uint16_t responseStation = le16toh(response->sta_id);
    const uint16_t count = le16toh(response->num_flushed_queues);
    const struct iwx_flush_queue_info *entry = count != 0 ?
        &response->queues[0] : nullptr;
    IOEthernetController *controller = owner->tahoeP2pController();
    if (controller) {
        controller->setProperty("NativeP2PTxRebindFlushStationId",
                                uint32_t(responseStation), 32);
        controller->setProperty("NativeP2PTxRebindFlushQueueCount",
                                uint32_t(count), 32);
        controller->setProperty("NativeP2PTxRebindFlushTid",
            entry ? uint32_t(le16toh(entry->tid)) : UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushQueueId",
            entry ? uint32_t(le16toh(entry->queue_num)) : UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushReadBefore",
            entry ? uint32_t(le16toh(entry->read_before_flush)) : UINT32_MAX,
            32);
        controller->setProperty("NativeP2PTxRebindFlushReadAfter",
            entry ? uint32_t(le16toh(entry->read_after_flush)) : UINT32_MAX,
            32);
    }
    bool exactBinding = responseStation == stationId && count == 1;
    if (exactBinding) {
        exactBinding = le16toh(entry->tid) == kFirmwareManagementTid &&
            le16toh(entry->queue_num) == queueId &&
            le16toh(entry->read_before_flush) == writePointer &&
            le16toh(entry->read_after_flush) == writePointer;
    }
    owner->iwx_free_resp(sc, &hostCommand);
    if (!exactBinding)
        return EIO;

    // The returned queue table must still be from the same serialized probe
    // window. This is a binding witness only; it does not retire old DMA.
    return owner->nativeP2pCommandAllowed() &&
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) != 0
        ? 0 : EBUSY;
}

static int removeLegacyP2pStationWithAck(ItlIwx *owner,
                                         struct iwx_softc *sc,
                                         uint8_t stationId)
{
    if (!owner || !sc)
        return EINVAL;
    struct iwx_rm_sta_cmd command{};
    command.sta_id = stationId;
    struct iwx_host_cmd hostCommand{};
    hostCommand.id = IWX_REMOVE_STA;
    hostCommand.flags = IWX_CMD_WANT_RESP;
    // Firmware advertises no REMOVE_STA notification payload. Reserve room
    // for the packet header and a possible generic command status while still
    // rejecting undocumented response bodies below.
    hostCommand.resp_pkt_len = sizeof(struct iwx_rx_packet) +
        sizeof(struct iwx_cmd_response);
    hostCommand.data[0] = &command;
    hostCommand.len[0] = sizeof(command);

    int error = owner->iwx_send_cmd(sc, &hostCommand);
    if (error) {
        if (hostCommand.resp_pkt)
            owner->iwx_free_resp(sc, &hostCommand);
        return error;
    }
    struct iwx_rx_packet *packet = hostCommand.resp_pkt;
    if (!packet || (packet->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        if (packet)
            owner->iwx_free_resp(sc, &hostCommand);
        return EIO;
    }

    const size_t payloadLength = iwx_rx_packet_payload_len(packet);
    bool accepted = payloadLength == 0;
    if (payloadLength == sizeof(struct iwx_cmd_response)) {
        const auto *response = reinterpret_cast<
            const struct iwx_cmd_response *>(packet->data);
        accepted = le32toh(response->status) == 0;
    }
    owner->iwx_free_resp(sc, &hostCommand);
    return accepted ? 0 : EIO;
}

static bool lockQueueLease(TahoeP2PTxQueueLease *lease,
                           IOInterruptState *interruptState)
{
    if (!lease || !lease->stateLock || !interruptState)
        return false;
    *interruptState = IOSimpleLockLockDisableInterrupt(lease->stateLock);
    return true;
}

static void unlockQueueLease(TahoeP2PTxQueueLease *lease,
                             IOInterruptState interruptState)
{
    IOSimpleLockUnlockEnableInterrupt(lease->stateLock, interruptState);
}

static bool p2pMacReady(const struct iwx_softc *sc)
{
    return sc && sc->sc_p2p.initialized &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.phy_leased &&
        sc->sc_p2p.fw_generation == static_cast<uint32_t>(sc->sc_generation);
}

static void destroyUnsubmittedRing(ItlIwx *owner, struct iwx_softc *sc,
                                   struct iwx_tx_ring *ring)
{
    if (!ring)
        return;
    owner->iwx_reset_tx_ring(sc, ring);
    owner->iwx_free_tx_ring(sc, ring);
    IOFree(ring, sizeof(*ring));
}

static int allocateP2pRing(ItlIwx *owner, struct iwx_softc *sc,
                           struct iwx_tx_ring *ring, uint32_t size,
                           uint32_t *failurePhase)
{
    if (failurePhase)
        *failurePhase = kP2PTxDmaNoFailure;
    if (size < 8 || size > IWX_TFD_QUEUE_SIZE_MAX ||
        (size & (size - 1)) != 0) {
        if (failurePhase)
            *failurePhase = kP2PTxDmaInvalidRingSize;
        return EINVAL;
    }

    memset(ring, 0, sizeof(*ring));
    owner->iwx_tx_ring_init(sc, ring, static_cast<int>(size));
    ring->qid = IWX_INVALID_QUEUE;

    int error = owner->iwx_dma_contig_alloc(
        sc->sc_dmat, &ring->desc_dma,
        ring->ring_count * sizeof(struct iwx_tfh_tfd), 256);
    if (error) {
        if (failurePhase)
            *failurePhase = kP2PTxDmaDescriptors;
        goto fail;
    }
    ring->desc = static_cast<struct iwx_tfh_tfd *>(ring->desc_dma.vaddr);

    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        error = owner->iwx_dma_contig_alloc(
            sc->sc_dmat, &ring->bc_tbl,
            sizeof(struct iwx_gen3_bc_tbl), 0);
    else
        error = owner->iwx_dma_contig_alloc(
            sc->sc_dmat, &ring->bc_tbl,
            sizeof(struct iwx_agn_scd_bc_tbl), 0);
    if (error) {
        if (failurePhase)
            *failurePhase = kP2PTxDmaByteCountTable;
        goto fail;
    }

    error = owner->iwx_dma_contig_alloc(
        sc->sc_dmat, &ring->cmd_dma,
        ring->ring_count * sizeof(struct iwx_device_cmd),
        IWX_FIRST_TB_SIZE_ALIGN);
    if (error) {
        if (failurePhase)
            *failurePhase = kP2PTxDmaCommandRing;
        goto fail;
    }
    ring->cmd = static_cast<struct iwx_device_cmd *>(ring->cmd_dma.vaddr);

    bus_addr_t paddr;
    paddr = ring->cmd_dma.paddr;
    for (uint32_t i = 0; i < ring->ring_count; ++i) {
        struct iwx_tx_data *data = &ring->data[i];
        data->cmd_paddr = paddr;
        paddr += sizeof(struct iwx_device_cmd);
        error = bus_dmamap_create(sc->sc_dmat, MCLBYTES,
                                  IWX_TFH_NUM_TBS - 2, MCLBYTES, 0,
                                  BUS_DMA_NOWAIT, &data->map);
        if (error) {
            if (failurePhase)
                *failurePhase = kP2PTxDmaDescriptorMap;
            goto fail;
        }
    }
    return 0;

fail:
    destroyUnsubmittedRing(owner, sc, ring);
    return error ? error : EIO;
}

static bool dmaInfoEmpty(const struct iwx_dma_info *info)
{
    return info && info->buffer == nullptr && info->paddr == 0 &&
        info->vaddr == nullptr && info->size == 0 && info->bmd == nullptr &&
        info->cmd == nullptr;
}

struct NativeUnsubmittedPlaceholderSnapshot {
    bool valid;
    uint16_t queueId;
    unsigned int ringCount;
    struct iwx_tfh_tfd *desc;
    struct iwx_device_cmd *cmd;
    void *descVaddr;
    void *cmdVaddr;
    void *byteCountVaddr;
    bus_addr_t descPaddr;
    bus_addr_t cmdPaddr;
    bus_addr_t byteCountPaddr;
};

enum NativeQueueSlotRejectReason : uint32_t {
    kHostSlotOutOfRange = 1u << 0,
    kHostSlotCommandQueue = 1u << 1,
    kHostSlotFirstDataQueue = 1u << 2,
    kHostSlotQueueFull = 1u << 3,
    kHostSlotTidOwner = 1u << 4,
    kHostSlotRingCount = 1u << 5,
    kHostSlotDescriptor = 1u << 6,
    kHostSlotCommand = 1u << 7,
    kHostSlotDescriptorDma = 1u << 8,
    kHostSlotCommandDma = 1u << 9,
    kHostSlotByteCountDma = 1u << 10,
    kHostSlotDataMaps = 1u << 11,
    kHostSlotDataOwners = 1u << 12
};

enum NativePlaceholderCaptureFailure : uint32_t {
    kPlaceholderNoStaticProof = 1u << 0,
    kPlaceholderDuplicateProof = 1u << 1,
    kPlaceholderHostOwner = 1u << 2,
    kPlaceholderBackingIncomplete = 1u << 3
};

struct NativeQueueSlotDiagnostic {
    uint32_t valid;
    uint32_t rejectMask;
    uint32_t queueId;
    uint32_t ringQueueId;
    uint32_t ringCount;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
    uint32_t descriptorPresent;
    uint32_t commandPresent;
    uint32_t dmaPresenceMask;
    uint32_t firstDataQueue;
    uint32_t queueFullBit;
    uint32_t queueFullPredicateReject;
    uint32_t tidMatchBitmap;
    uint32_t dataMapCount;
    uint32_t dataOwnerCount;
    uint32_t staticPlaceholderProof;

    NativeQueueSlotDiagnostic()
        : valid(0), rejectMask(UINT32_MAX), queueId(UINT32_MAX),
          ringQueueId(UINT32_MAX), ringCount(UINT32_MAX), queued(UINT32_MAX),
          cur(UINT32_MAX), tail(UINT32_MAX), descriptorPresent(UINT32_MAX),
          commandPresent(UINT32_MAX), dmaPresenceMask(UINT32_MAX),
          firstDataQueue(UINT32_MAX), queueFullBit(UINT32_MAX),
          queueFullPredicateReject(UINT32_MAX),
          tidMatchBitmap(UINT32_MAX), dataMapCount(UINT32_MAX),
          dataOwnerCount(UINT32_MAX), staticPlaceholderProof(UINT32_MAX) {}
};

static NativeQueueSlotDiagnostic captureQueueSlotDiagnostic(
    const struct iwx_softc *sc, uint16_t queueId)
{
    NativeQueueSlotDiagnostic snapshot;
    snapshot.queueId = queueId;
    if (!sc || queueId >= nitems(sc->txq)) {
        snapshot.rejectMask = kHostSlotOutOfRange;
        return snapshot;
    }

    snapshot.valid = 1;
    snapshot.rejectMask = 0;
    snapshot.dmaPresenceMask = 0;
    snapshot.queueFullBit = 0;
    snapshot.tidMatchBitmap = 0;
    snapshot.dataMapCount = 0;
    snapshot.dataOwnerCount = 0;
    const struct iwx_tx_ring *ring = &sc->txq[queueId];
    snapshot.ringQueueId = static_cast<uint32_t>(ring->qid);
    snapshot.ringCount = ring->ring_count;
    snapshot.queued = static_cast<uint32_t>(ring->queued);
    snapshot.cur = static_cast<uint32_t>(ring->cur);
    snapshot.tail = static_cast<uint32_t>(ring->tail);
    snapshot.descriptorPresent = ring->desc != nullptr;
    snapshot.commandPresent = ring->cmd != nullptr;
    snapshot.dmaPresenceMask =
        (!dmaInfoEmpty(&ring->desc_dma) ? 1u : 0u) |
        (!dmaInfoEmpty(&ring->cmd_dma) ? 2u : 0u) |
        (!dmaInfoEmpty(&ring->bc_tbl) ? 4u : 0u);
    snapshot.firstDataQueue = static_cast<uint32_t>(sc->first_data_qid);
    snapshot.queueFullBit = queueId < 32 &&
        (sc->qfullmsk & (1U << queueId)) != 0;
    // Match queueHasNoHostOwner() exactly: its rejection predicate excludes qid 31.
    snapshot.queueFullPredicateReject = queueId < 31 &&
        snapshot.queueFullBit != 0;
    for (size_t tid = 0; tid < nitems(sc->sc_tid_data) && tid < 32; ++tid) {
        if (sc->sc_tid_data[tid].qid == queueId)
            snapshot.tidMatchBitmap |= 1u << tid;
    }
    for (size_t slot = 0; slot < nitems(ring->data); ++slot) {
        const struct iwx_tx_data *data = &ring->data[slot];
        if (data->map != nullptr)
            ++snapshot.dataMapCount;
        if (data->m != nullptr || data->in != nullptr)
            ++snapshot.dataOwnerCount;
    }
    snapshot.staticPlaceholderProof =
        ring->nativeUnsubmittedPlaceholder != 0;

    uint32_t rejectMask = 0;
    if (queueId == IWX_DQA_CMD_QUEUE)
        rejectMask |= kHostSlotCommandQueue;
    if (sc->first_data_qid == queueId)
        rejectMask |= kHostSlotFirstDataQueue;
    if (snapshot.queueFullPredicateReject)
        rejectMask |= kHostSlotQueueFull;
    if (snapshot.tidMatchBitmap != 0)
        rejectMask |= kHostSlotTidOwner;
    if (ring->ring_count != 0)
        rejectMask |= kHostSlotRingCount;
    if (ring->desc != nullptr)
        rejectMask |= kHostSlotDescriptor;
    if (ring->cmd != nullptr)
        rejectMask |= kHostSlotCommand;
    if (snapshot.dmaPresenceMask & 1u)
        rejectMask |= kHostSlotDescriptorDma;
    if (snapshot.dmaPresenceMask & 2u)
        rejectMask |= kHostSlotCommandDma;
    if (snapshot.dmaPresenceMask & 4u)
        rejectMask |= kHostSlotByteCountDma;
    if (snapshot.dataMapCount != 0)
        rejectMask |= kHostSlotDataMaps;
    if (snapshot.dataOwnerCount != 0)
        rejectMask |= kHostSlotDataOwners;
    snapshot.rejectMask = rejectMask;
    return snapshot;
}

static void publishQueueSlotDiagnostic(
    ItlIwx *owner, uint32_t firmwareQueue, bool responseValid,
    const NativeQueueSlotDiagnostic &slot,
    uint32_t placeholderCaptureFailureMask,
    const NativeQueueSlotDiagnostic &placeholderSlot)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    controller->setProperty("NativeP2PTxHostSnapshotValid", slot.valid, 32);
    controller->setProperty("NativeP2PTxFirmwareQueueId",
        responseValid ? firmwareQueue : UINT32_MAX, 32);
    controller->setProperty("NativeP2PTxHostSlotRejectMask",
                             slot.rejectMask, 32);
    controller->setProperty("NativeP2PTxHostRingQueueId",
                             slot.ringQueueId, 32);
    controller->setProperty("NativeP2PTxHostRingCount", slot.ringCount, 32);
    controller->setProperty("NativeP2PTxHostRingQueued", slot.queued, 32);
    controller->setProperty("NativeP2PTxHostRingCur", slot.cur, 32);
    controller->setProperty("NativeP2PTxHostRingTail", slot.tail, 32);
    controller->setProperty("NativeP2PTxHostDescriptorPresent",
                             slot.descriptorPresent, 32);
    controller->setProperty("NativeP2PTxHostCommandPresent",
                             slot.commandPresent, 32);
    controller->setProperty("NativeP2PTxHostDmaPresenceMask",
                             slot.dmaPresenceMask, 32);
    controller->setProperty("NativeP2PTxFirstDataQueue",
                             slot.firstDataQueue, 32);
    controller->setProperty("NativeP2PTxHostQueueFullBit",
                             slot.queueFullBit, 32);
    controller->setProperty("NativeP2PTxHostQueueFullPredicateReject",
                             slot.queueFullPredicateReject, 32);
    controller->setProperty("NativeP2PTxHostTidMatchBitmap",
                             slot.tidMatchBitmap, 32);
    controller->setProperty("NativeP2PTxHostDataMapCount",
                             slot.dataMapCount, 32);
    controller->setProperty("NativeP2PTxHostDataOwnerCount",
                             slot.dataOwnerCount, 32);
    controller->setProperty("NativeP2PTxHostStaticPlaceholderProof",
                             slot.staticPlaceholderProof, 32);
    controller->setProperty("NativeP2PTxPlaceholderCaptureFailureMask",
                             placeholderCaptureFailureMask, 32);
    controller->setProperty("NativeP2PTxPlaceholderStaticProof",
                             placeholderSlot.staticPlaceholderProof, 32);
    controller->setProperty("NativeP2PTxPlaceholderHostRejectMask",
                             placeholderSlot.rejectMask, 32);
    controller->setProperty("NativeP2PTxPlaceholderRingCount",
                             placeholderSlot.ringCount, 32);
    controller->setProperty("NativeP2PTxPlaceholderRingQueueId",
                             placeholderSlot.ringQueueId, 32);
}

static bool queueHasNoHostOwner(const struct iwx_softc *sc,
                                uint16_t queueId)
{
    if (!sc || queueId >= nitems(sc->txq) ||
        sc->first_data_qid == queueId ||
        (queueId < 31 && (sc->qfullmsk & (1U << queueId)) != 0))
        return false;
    for (size_t tid = 0; tid < nitems(sc->sc_tid_data); ++tid) {
        if (sc->sc_tid_data[tid].qid == queueId)
            return false;
    }
    return true;
}

static bool queueHasCompletePlaceholderBacking(
    const struct iwx_tx_ring *ring, uint16_t queueId)
{
    if (!ring || queueId == IWX_DQA_CMD_QUEUE || ring->qid != queueId ||
        ring->ring_count == 0 || ring->ring_count > nitems(ring->data) ||
        ring->desc == nullptr || ring->cmd == nullptr ||
        ring->desc_dma.vaddr != ring->desc ||
        ring->cmd_dma.vaddr != ring->cmd ||
        ring->desc_dma.paddr == 0 || ring->cmd_dma.paddr == 0 ||
        ring->desc_dma.size == 0 || ring->cmd_dma.size == 0 ||
        ring->bc_tbl.vaddr == nullptr || ring->bc_tbl.paddr == 0 ||
        ring->bc_tbl.size == 0 || ring->queued != 0 ||
        ring->cur != ring->tail || ring->cur < 0 ||
        static_cast<unsigned int>(ring->cur) >= ring->ring_count)
        return false;
    bus_addr_t expectedCmdPaddr = ring->cmd_dma.paddr;
    for (size_t slot = 0; slot < nitems(ring->data); ++slot) {
        const struct iwx_tx_data *data = &ring->data[slot];
        if (data->m != nullptr || data->in != nullptr)
            return false;
        if (slot < ring->ring_count) {
            if (data->map == nullptr || data->cmd_paddr != expectedCmdPaddr)
                return false;
            expectedCmdPaddr += sizeof(struct iwx_device_cmd);
        } else if (data->map != nullptr) {
            return false;
        }
    }
    return true;
}

struct NativeDynamicRingSnapshot {
    struct iwx_tx_ring *ringCopy;
    uint32_t generation;
    uint16_t queueId;
    bool valid;

    ~NativeDynamicRingSnapshot()
    {
        if (ringCopy)
            IOFree(ringCopy, sizeof(*ringCopy));
    }
};

static bool dmaInfoIdentityMatches(const struct iwx_dma_info &a,
                                   const struct iwx_dma_info &b)
{
    return a.buffer == b.buffer && a.paddr == b.paddr &&
        a.vaddr == b.vaddr && a.size == b.size &&
        a.bmd == b.bmd && a.cmd == b.cmd;
}

static bool dynamicRingIdentityMatches(
    const struct iwx_tx_ring *ring, const struct iwx_tx_ring *snapshot)
{
    if (!ring || !snapshot ||
        !dmaInfoIdentityMatches(ring->desc_dma, snapshot->desc_dma) ||
        !dmaInfoIdentityMatches(ring->cmd_dma, snapshot->cmd_dma) ||
        !dmaInfoIdentityMatches(ring->bc_tbl, snapshot->bc_tbl) ||
        ring->desc != snapshot->desc || ring->cmd != snapshot->cmd ||
        ring->ring_count != snapshot->ring_count ||
        ring->hi_mark != snapshot->hi_mark ||
        ring->low_mark != snapshot->low_mark || ring->qid != snapshot->qid ||
        ring->queued != snapshot->queued || ring->cur != snapshot->cur ||
        ring->tail != snapshot->tail ||
        ring->nativeUnsubmittedPlaceholder !=
            snapshot->nativeUnsubmittedPlaceholder)
        return false;

    for (size_t i = 0; i < nitems(ring->data); ++i) {
        const struct iwx_tx_data &a = ring->data[i];
        const struct iwx_tx_data &b = snapshot->data[i];
        if (a.map != b.map || a.cmd_paddr != b.cmd_paddr ||
            a.m != b.m || a.in != b.in || a.flags != b.flags ||
            a.type != b.type || a.rate_generation != b.rate_generation)
            return false;
    }
    return true;
}

static void clearDynamicRingSnapshot(NativeDynamicRingSnapshot *snapshot)
{
    if (!snapshot)
        return;
    if (snapshot->ringCopy)
        IOFree(snapshot->ringCopy, sizeof(*snapshot->ringCopy));
    snapshot->ringCopy = nullptr;
    snapshot->generation = 0;
    snapshot->queueId = IWX_INVALID_QUEUE;
    snapshot->valid = false;
}

static void captureDynamicRingSnapshot(
    ItlIwx *owner, const struct iwx_softc *sc,
    NativeDynamicRingSnapshot *snapshot)
{
    if (!snapshot)
        return;
    clearDynamicRingSnapshot(snapshot);
    if (!owner || !sc ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 ||
        !owner->nativeP2pCommandAllowed())
        return;

    const uint16_t queueId = kLegacyP2pCollisionPilotQueue;
    if (queueId >= nitems(sc->txq) || !queueHasNoHostOwner(sc, queueId))
        return;
    const struct iwx_tx_ring *ring = &sc->txq[queueId];
    // The pilot is deliberately limited to the complete, idle fw68 STA ring
    // observed at qid 3. Emptiness alone is never enough to park another slot.
    if (ring->nativeUnsubmittedPlaceholder != 0 ||
        ring->ring_count != 256 || ring->qid != queueId ||
        ring->queued != 0 || ring->cur != 1 || ring->tail != 1 ||
        !queueHasCompletePlaceholderBacking(ring, queueId))
        return;

    auto *copy = static_cast<struct iwx_tx_ring *>(
        IOMalloc(sizeof(struct iwx_tx_ring)));
    if (!copy)
        return;
    memcpy(copy, ring, sizeof(*copy));
    snapshot->ringCopy = copy;
    snapshot->generation = static_cast<uint32_t>(sc->sc_generation);
    snapshot->queueId = queueId;
    snapshot->valid = true;
}

static bool dynamicRingSnapshotStillMatches(
    ItlIwx *owner, const struct iwx_softc *sc,
    const NativeDynamicRingSnapshot *snapshot)
{
    if (!owner || !sc || !snapshot || !snapshot->valid ||
        !snapshot->ringCopy || snapshot->queueId !=
            kLegacyP2pCollisionPilotQueue ||
        snapshot->generation != static_cast<uint32_t>(sc->sc_generation) ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 ||
        !owner->nativeP2pCommandAllowed() ||
        !queueHasNoHostOwner(sc, snapshot->queueId))
        return false;
    const struct iwx_tx_ring *ring = &sc->txq[snapshot->queueId];
    return ring->nativeUnsubmittedPlaceholder == 0 &&
        ring->ring_count == 256 && ring->qid == snapshot->queueId &&
        ring->queued == 0 && ring->cur == 1 && ring->tail == 1 &&
        queueHasCompletePlaceholderBacking(ring, snapshot->queueId) &&
        dynamicRingIdentityMatches(ring, snapshot->ringCopy);
}

static void publishRetainedRingDiagnostic(ItlIwx *owner,
                                           const TahoeP2PTxQueueLease *lease)
{
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (!controller)
        return;
    const struct iwx_tx_ring *ring = lease ? lease->retainedRing : nullptr;
    controller->setProperty("NativeP2PTxRetainedRingCount",
                            uint32_t(ring != nullptr), 32);
    controller->setProperty("NativeP2PTxRetainedRingQueueId",
        ring ? uint32_t(lease->retainedRingQueueId) : UINT32_MAX, 32);
    controller->setProperty("NativeP2PTxRetainedRingGeneration",
        ring ? lease->retainedRingGeneration : UINT32_MAX, 32);
    controller->setProperty("NativeP2PTxRetainedRingCursor",
        ring ? static_cast<uint32_t>(ring->cur) : UINT32_MAX, 32);
    const uint64_t bytes = ring ?
        static_cast<uint64_t>(ring->desc_dma.size) +
        static_cast<uint64_t>(ring->cmd_dma.size) +
        static_cast<uint64_t>(ring->bc_tbl.size) : 0;
    controller->setProperty("NativeP2PTxRetainedRingDmaBytes",
        static_cast<uint32_t>(bytes > UINT32_MAX ? UINT32_MAX : bytes), 32);
}

static NativeUnsubmittedPlaceholderSnapshot captureUnsubmittedPlaceholder(
    const struct iwx_softc *sc, uint32_t *failureMask)
{
    if (failureMask)
        *failureMask = 0;
    NativeUnsubmittedPlaceholderSnapshot snapshot{};
    if (!sc)
        return snapshot;
    bool sawMarkedPlaceholder = false;
    for (uint16_t queueId = 0; queueId < nitems(sc->txq); ++queueId) {
        if (!sc->txq[queueId].nativeUnsubmittedPlaceholder)
            continue;
        if (sawMarkedPlaceholder) {
            if (failureMask)
                *failureMask |= kPlaceholderDuplicateProof;
            return {};
        }
        sawMarkedPlaceholder = true;
        const bool hasHostOwner = !queueHasNoHostOwner(sc, queueId);
        const bool backingComplete = queueHasCompletePlaceholderBacking(
            &sc->txq[queueId], queueId);
        if (hasHostOwner || !backingComplete) {
            if (failureMask) {
                if (hasHostOwner)
                    *failureMask |= kPlaceholderHostOwner;
                if (!backingComplete)
                    *failureMask |= kPlaceholderBackingIncomplete;
            }
            return {};
        }
        const struct iwx_tx_ring *ring = &sc->txq[queueId];
        snapshot.valid = true;
        snapshot.queueId = queueId;
        snapshot.ringCount = ring->ring_count;
        snapshot.desc = ring->desc;
        snapshot.cmd = ring->cmd;
        snapshot.descVaddr = ring->desc_dma.vaddr;
        snapshot.cmdVaddr = ring->cmd_dma.vaddr;
        snapshot.byteCountVaddr = ring->bc_tbl.vaddr;
        snapshot.descPaddr = ring->desc_dma.paddr;
        snapshot.cmdPaddr = ring->cmd_dma.paddr;
        snapshot.byteCountPaddr = ring->bc_tbl.paddr;
    }
    if (!sawMarkedPlaceholder && failureMask)
        *failureMask |= kPlaceholderNoStaticProof;
    return snapshot;
}

static void clearUnsubmittedPlaceholderProofs(struct iwx_softc *sc)
{
    if (!sc)
        return;
    for (size_t queueId = 0; queueId < nitems(sc->txq); ++queueId)
        sc->txq[queueId].nativeUnsubmittedPlaceholder = 0;
}

static bool queueMatchesPlaceholderSnapshot(
    const struct iwx_softc *sc, uint16_t queueId,
    const NativeUnsubmittedPlaceholderSnapshot *snapshot)
{
    if (!snapshot || !snapshot->valid || snapshot->queueId != queueId ||
        !queueHasNoHostOwner(sc, queueId))
        return false;
    const struct iwx_tx_ring *ring = &sc->txq[queueId];
    return queueHasCompletePlaceholderBacking(ring, queueId) &&
        ring->ring_count == snapshot->ringCount &&
        ring->desc == snapshot->desc && ring->cmd == snapshot->cmd &&
        ring->desc_dma.vaddr == snapshot->descVaddr &&
        ring->cmd_dma.vaddr == snapshot->cmdVaddr &&
        ring->bc_tbl.vaddr == snapshot->byteCountVaddr &&
        ring->desc_dma.paddr == snapshot->descPaddr &&
        ring->cmd_dma.paddr == snapshot->cmdPaddr &&
        ring->bc_tbl.paddr == snapshot->byteCountPaddr;
}

static bool queueSlotAvailable(const struct iwx_softc *sc, uint16_t queueId,
                               NativeQueueSlotDiagnostic *diagnostic = nullptr)
{
    const NativeQueueSlotDiagnostic snapshot =
        captureQueueSlotDiagnostic(sc, queueId);
    if (diagnostic)
        *diagnostic = snapshot;
    return snapshot.valid && snapshot.rejectMask == 0;
}

static bool queueSlotCanInstall(
    const struct iwx_softc *sc, uint16_t queueId,
    const NativeUnsubmittedPlaceholderSnapshot *snapshot,
    NativeQueueSlotDiagnostic *slotDiagnostic = nullptr)
{
    return queueSlotAvailable(sc, queueId, slotDiagnostic) ||
        queueMatchesPlaceholderSnapshot(sc, queueId, snapshot);
}

static void syncQueueState(TahoeP2PTxQueueLease *lease);

static int retainUnknown(TahoeP2PTxQueueLease *lease,
                         struct iwx_tx_ring *ring, uint32_t generation,
                         uint8_t stationId, int error)
{
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState)) {
        // The ADD command may already have reached firmware. If its lock was
        // unexpectedly lost, retain the only DMA pointer even though we can no
        // longer publish a lifecycle transition safely.
        lease->stationId = stationId;
        lease->generation = generation;
        lease->queueId = IWX_INVALID_QUEUE;
        lease->pendingRing = ring;
        lease->state = TahoeP2PResourceState::kUnknown;
        return error ? error : EIO;
    }
    const IntelP2PTx::QueueState state = lease->lifecycle.snapshot().state;
    if (state == IntelP2PTx::QueueState::kAllocationPending)
        (void)lease->lifecycle.allocationOutcomeUnknown(generation, stationId);
    lease->pendingRing = ring;
    syncQueueState(lease);
    unlockQueueLease(lease, interruptState);
    return error ? error : EIO;
}

static int retainAcknowledgedPending(
    TahoeP2PTxQueueLease *lease, struct iwx_tx_ring *ring,
    uint32_t generation, uint8_t stationId, uint16_t queueId,
    uint16_t writePointer, int error)
{
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return retainUnknown(lease, ring, generation, stationId,
                             error ? error : EBUSY);
    const IntelP2PTx::QueueSnapshot before = lease->lifecycle.snapshot();
    if (before.state != IntelP2PTx::QueueState::kAllocationPending ||
        before.generation != generation || before.stationId != stationId) {
        unlockQueueLease(lease, interruptState);
        return retainUnknown(lease, ring, generation, stationId,
                             error ? error : EIO);
    }
    lease->generation = generation;
    lease->stationId = stationId;
    lease->queueId = queueId;
    lease->firmwareWritePointer = writePointer;
    lease->pendingRing = ring;
    lease->submissionBusy = false;
    syncQueueState(lease);
    unlockQueueLease(lease, interruptState);
    return error ? error : EBUSY;
}

// Caller holds lease->stateLock.
static bool queueLeaseHasInstalledRingLocked(
    struct iwx_softc *sc, const TahoeP2PTxQueueLease *lease)
{
    if (!sc || !lease || lease->pendingRing ||
        lease->generation != static_cast<uint32_t>(sc->sc_generation) ||
        lease->queueId >= nitems(sc->txq))
        return false;
    if (lease->state != TahoeP2PResourceState::kActive &&
        lease->state != TahoeP2PResourceState::kRemoving &&
        lease->state != TahoeP2PResourceState::kUnknown)
        return false;
    const struct iwx_tx_ring *ring = &sc->txq[lease->queueId];
    if (ring->ring_count == 0 || ring->qid != lease->queueId ||
        ring->desc == nullptr || ring->cmd == nullptr ||
        ring->desc_dma.vaddr == nullptr || ring->cmd_dma.vaddr == nullptr ||
        ring->bc_tbl.vaddr == nullptr ||
        ring->ring_count > nitems(ring->data))
        return false;
    for (uint32_t i = 0; i < ring->ring_count; ++i) {
        if (ring->data[i].map == nullptr)
            return false;
    }
    return true;
}

// Caller holds lease->stateLock. This proof is intentionally stricter than
// ordinary completion cleanup: every host slot and descriptor map must be
// empty/valid, and both software cursors must still match the allocation-time
// firmware write pointer.
static bool queueHasNeverSubmittedEmptyP2pRingLocked(
    struct iwx_softc *sc, const TahoeP2PTxQueueLease *lease)
{
    if (!queueLeaseHasInstalledRingLocked(sc, lease) ||
        !queueHasNoHostOwner(sc, lease->queueId))
        return false;
    const struct iwx_tx_ring *ring = &sc->txq[lease->queueId];
    if (ring->ring_count > IWX_TFD_QUEUE_SIZE_MAX ||
        (ring->ring_count & (ring->ring_count - 1)) != 0 ||
        lease->firmwareWritePointer >= ring->ring_count ||
        ring->cur != static_cast<int>(lease->firmwareWritePointer) ||
        ring->tail != static_cast<int>(lease->firmwareWritePointer) ||
        ring->queued != 0 || ring->nativeUnsubmittedPlaceholder != 0 ||
        lease->retainedRing == ring)
        return false;
    return queueHasCompletePlaceholderBacking(ring, lease->queueId);
}

static void syncQueueState(TahoeP2PTxQueueLease *lease)
{
    if (!lease)
        return;
    switch (lease->lifecycle.snapshot().state) {
        case IntelP2PTx::QueueState::kAbsent:
            lease->state = TahoeP2PResourceState::kAbsent;
            break;
        case IntelP2PTx::QueueState::kAllocationPending:
            lease->state = TahoeP2PResourceState::kPending;
            break;
        case IntelP2PTx::QueueState::kActive:
            lease->state = TahoeP2PResourceState::kActive;
            break;
        case IntelP2PTx::QueueState::kRemoving:
            lease->state = TahoeP2PResourceState::kRemoving;
            break;
        case IntelP2PTx::QueueState::kUnknown:
            lease->state = TahoeP2PResourceState::kUnknown;
            break;
    }
}

} // namespace

int iwx_tahoe_p2p_add_broadcast_station(ItlIwx *owner, struct iwx_softc *sc,
                                        TahoeP2PStationLease *lease,
                                        uint8_t stationId,
                                        bool *resourceMayExist)
{
    if (resourceMayExist)
        *resourceMayExist = false;
    if (!owner || !sc || sc != &owner->com || !lease || !resourceMayExist ||
        !owner->nativeP2pCommandAllowed() || !p2pMacReady(sc))
        return EBUSY;
    IntelP2PTx::QueueApi firmwareApi;
    const int apiError = queueApiForFirmware(owner, sc, &firmwareApi);
    if (apiError)
        return apiError;
    if (firmwareApi != IntelP2PTx::QueueApi::kLegacyDynamicDqa ||
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA) != 12 ||
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA) != 2)
        return EOPNOTSUPP;
    if (lease->state != TahoeP2PResourceState::kAbsent ||
        stationId >= sc->sc_capa_num_stations ||
        stationId == IWX_STATION_ID ||
        sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR ||
        sc->sc_device_family < IWX_DEVICE_FAMILY_22000)
        return EINVAL;

    IOEthernetController *controller = owner->tahoeP2pController();
    if (controller) {
        controller->setProperty("NativeP2PTxAddStaAttempted", uint32_t(0), 32);
        controller->setProperty("NativeP2PTxAddStaStatusValid", uint32_t(0), 32);
        controller->setProperty("NativeP2PTxAddStaFirmwareStatus",
                                 UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxAddStaSendResult", UINT32_MAX, 32);
    }

    struct iwx_add_sta_cmd command{};
    command.sta_id = stationId;
    command.add_modify = 0;
    command.tid_disable_tx = htole16(0xffff);
    command.mac_id_n_color = htole32(IWX_FW_CMD_ID_AND_COLOR(
        sc->sc_p2p.mac_id, sc->sc_p2p.mac_color));
    memset(command.addr, 0xff, sizeof(command.addr));
    const bool stationTypeApi =
        isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_STA_TYPE) != 0;
    if (stationTypeApi)
        command.station_type = IWX_STA_GENERAL_PURPOSE;
    uint32_t status = UINT32_MAX;
    const int error = owner->iwx_send_cmd_pdu_status(
        sc, IWX_ADD_STA, sizeof(command), &command, &status);
    const bool statusValid = error == 0;
    publishAddStationDiagnostic(owner, stationId,
        le32toh(command.mac_id_n_color), command.station_type, stationTypeApi,
        sizeof(command),
        owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA),
        owner->iwx_lookup_notif_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA),
        error, status, statusValid);
    if (error) {
        // A timed-out ADD_STA may still have reached firmware.
        lease->stationId = stationId;
        lease->generation = static_cast<uint32_t>(sc->sc_generation);
        lease->state = TahoeP2PResourceState::kUnknown;
        *resourceMayExist = true;
        return error;
    }
    if ((status & IWX_ADD_STA_STATUS_MASK) != IWX_ADD_STA_SUCCESS)
        return EIO;

    lease->stationId = stationId;
    lease->generation = static_cast<uint32_t>(sc->sc_generation);
    lease->state = TahoeP2PResourceState::kActive;
    *resourceMayExist = true;
    return 0;
}

int iwx_tahoe_p2p_remove_broadcast_station(ItlIwx *owner,
                                           struct iwx_softc *sc,
                                           TahoeP2PStationLease *lease,
                                           TahoeP2PTxQueueLease *queueLease,
                                           bool *resourceMayExist)
{
    if (resourceMayExist)
        *resourceMayExist = false;
    if (!owner || !sc || sc != &owner->com || !lease || !queueLease ||
        !resourceMayExist ||
        !owner->nativeP2pCommandAllowed())
        return EBUSY;
    if (lease->generation != static_cast<uint32_t>(sc->sc_generation))
        return ESTALE;
    if (lease->state == TahoeP2PResourceState::kAbsent) {
        bool queueAbsent = false;
        if (queueLease->stateLock) {
            IOInterruptState interruptState;
            if (!lockQueueLease(queueLease, &interruptState))
                return EBUSY;
            queueAbsent = !queueLease->pendingRing &&
                !queueLease->submissionBusy &&
                queueLease->state == TahoeP2PResourceState::kAbsent;
            unlockQueueLease(queueLease, interruptState);
        } else {
            queueAbsent = !queueLease->pendingRing &&
                !queueLease->submissionBusy &&
                queueLease->state == TahoeP2PResourceState::kAbsent;
        }
        return queueAbsent ? 0 : EBUSY;
    }
    if (lease->state != TahoeP2PResourceState::kActive &&
        lease->state != TahoeP2PResourceState::kUnknown)
        return EINVAL;
    if (lease->state == TahoeP2PResourceState::kUnknown)
        return EBUSY;
    bool queueAbsent = false;
    if (queueLease->stateLock) {
        IOInterruptState interruptState;
        if (!lockQueueLease(queueLease, &interruptState))
            return EBUSY;
        queueAbsent = !queueLease->pendingRing &&
            !queueLease->submissionBusy &&
            queueLease->state == TahoeP2PResourceState::kAbsent;
        unlockQueueLease(queueLease, interruptState);
    } else {
        queueAbsent = !queueLease->pendingRing &&
            !queueLease->submissionBusy &&
            queueLease->state == TahoeP2PResourceState::kAbsent;
    }
    if (!queueAbsent)
        return EBUSY;

    IntelP2PTx::QueueApi firmwareApi;
    const int apiError = queueApiForFirmware(owner, sc, &firmwareApi);
    if (apiError)
        return apiError;
    if (firmwareApi != IntelP2PTx::QueueApi::kLegacyDynamicDqa)
        return EOPNOTSUPP;

    *resourceMayExist = true;
    const int error = removeLegacyP2pStationWithAck(
        owner, sc, lease->stationId);
    if (error) {
        lease->state = TahoeP2PResourceState::kUnknown;
        return error;
    }
    lease->state = TahoeP2PResourceState::kAbsent;
    *resourceMayExist = false;
    return 0;
}

int iwx_tahoe_p2p_tvqm_allocate(ItlIwx *owner, struct iwx_softc *sc,
                                TahoeP2PTxQueueLease *lease,
                                const TahoeP2PStationLease *stationLease,
                                uint32_t size,
                                uint16_t *queueId,
                                bool *resourceMayExist)
{
    if (queueId)
        *queueId = 0;
    if (resourceMayExist)
        *resourceMayExist = false;
    IOEthernetController *controller = owner ? owner->tahoeP2pController() : nullptr;
    if (controller) {
        controller->setProperty("NativeP2PTxPlaceholderCaptured",
                                uint32_t(0), 32);
        controller->setProperty("NativeP2PTxPlaceholderQueueId",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxPlaceholderReclaimed",
                                uint32_t(0), 32);
        controller->setProperty("NativeP2PTxRebindFlushAttempted",
                                uint32_t(0), 32);
        controller->setProperty("NativeP2PTxRebindFlushValid",
                                uint32_t(0), 32);
        controller->setProperty("NativeP2PTxRebindFlushResult",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxQueueReserved",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushStationId",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushQueueCount",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushTid",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushQueueId",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushReadBefore",
                                UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxRebindFlushReadAfter",
                                UINT32_MAX, 32);
    }
    if (!owner || !sc || sc != &owner->com || !lease || !stationLease ||
        !queueId ||
        !resourceMayExist || !owner->nativeP2pCommandAllowed() ||
        !p2pMacReady(sc))
        return EBUSY;
    NativeQueueSlotDiagnostic resetSlotDiagnostic;
    publishQueueSlotDiagnostic(owner, UINT32_MAX, false,
                               resetSlotDiagnostic, UINT32_MAX,
                               resetSlotDiagnostic);
    publishRetainedRingDiagnostic(owner, lease);
    if (!lease->stateLock)
        lease->stateLock = owner->nativeP2pTxLock_;
    if (!lease->stateLock)
        return EBUSY;
    const uint8_t stationId = stationLease->stationId;
    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    if (stationId >= sc->sc_capa_num_stations ||
        stationLease->state != TahoeP2PResourceState::kActive ||
        stationLease->generation != generation ||
        stationId == IWX_STATION_ID ||
        sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR ||
        sc->sc_device_family < IWX_DEVICE_FAMILY_22000)
        return EINVAL;
    IntelP2PTx::QueueApi queueApi;
    const int queueApiError = queueApiForFirmware(owner, sc, &queueApi);
    if (queueApiError)
        return queueApiError;
    if (size == 0)
        size = IWX_DEFAULT_QUEUE_SIZE;
    if (size < 8 || size > IWX_TFD_QUEUE_SIZE_MAX ||
        (size & (size - 1)) != 0)
        return EINVAL;
    NativeUnsubmittedPlaceholderSnapshot placeholderSnapshot{};
    NativeQueueSlotDiagnostic placeholderSlotDiagnostic =
        captureQueueSlotDiagnostic(sc, IWX_DQA_P2P_DEVICE_QUEUE);
    uint32_t placeholderCaptureFailureMask = 0;

    if (controller) {
        controller->setProperty("NativeP2PTxQueueAttempted", uint32_t(0), 32);
        controller->setProperty("NativeP2PTxQueueResponseValid", uint32_t(0), 32);
        controller->setProperty("NativeP2PTxQueueSendResult", UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxQueueParseResult", UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxQueueResponseFlags", UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxQueueResponseId", UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxQueueWritePointer", UINT32_MAX, 32);
        controller->setProperty("NativeP2PTxDmaFailurePhase",
                                kP2PTxDmaNoFailure, 32);
    }

    struct iwx_tx_ring *ring = static_cast<struct iwx_tx_ring *>(
        IOMalloc(sizeof(struct iwx_tx_ring)));
    if (!ring) {
        publishQueueDiagnostic(owner, false, UINT32_MAX, UINT32_MAX,
                               false, 0, 0, 0,
                               kFirmwareManagementTid, kP2PTxDmaOuterRing);
        return ENOMEM;
    }
    uint32_t dmaFailurePhase = kP2PTxDmaNoFailure;
    const int allocationError = allocateP2pRing(owner, sc, ring, size,
                                                &dmaFailurePhase);
    if (allocationError) {
        publishQueueDiagnostic(owner, false, UINT32_MAX, UINT32_MAX,
                               false, 0, 0, 0,
                               kFirmwareManagementTid, dmaFailurePhase);
        return allocationError;
    }

    // Capture only the narrowly observed, complete idle qid-3 STA ring while
    // the probe gate and state-queue pause are both held. If that ring is
    // later displaced, this allocation becomes its retained DMA owner.
    NativeDynamicRingSnapshot dynamicSnapshot{};
    dynamicSnapshot.queueId = IWX_INVALID_QUEUE;
    captureDynamicRingSnapshot(owner, sc, &dynamicSnapshot);

    struct iwx_tx_queue_cfg_cmd legacyCommand{};
    struct iwx_host_cmd hostCommand{};
    hostCommand.flags = IWX_CMD_WANT_RESP;
    hostCommand.resp_pkt_len = sizeof(struct iwx_rx_packet) +
                               sizeof(struct iwx_tx_queue_cfg_rsp);
    legacyCommand.sta_id = stationId;
    // The host sentinel 8 is translated to firmware management TID 15 by
    // the Linux iwlwifi queue path before sending SCD_QUEUE_CFG.
    legacyCommand.tid = kFirmwareManagementTid;
    legacyCommand.flags = htole16(IWX_TX_QUEUE_CFG_ENABLE_QUEUE);
    legacyCommand.cb_size = htole32(
        IWX_TFD_QUEUE_CB_SIZE(ring->ring_count));
    legacyCommand.byte_cnt_addr = htole64(ring->bc_tbl.paddr);
    legacyCommand.tfdq_addr = htole64(ring->desc_dma.paddr);
    // iwx_send_cmd maps the narrow LONG command ID for this firmware API.
    // Copy the payload into the stack-backed host command only for the
    // duration of the synchronous request.
    hostCommand.id = IWX_SCD_QUEUE_CFG;
    hostCommand.data[0] = &legacyCommand;
    hostCommand.len[0] = sizeof(legacyCommand);

    const IntelP2PTx::QueueAdmission admission{
        queueApi,
        static_cast<uint16_t>(nitems(sc->txq)),
        generation,
        stationId,
        isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_DQA_SUPPORT) != 0,
        true,
        true,
        true,
        true,
        false
    };
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState)) {
        destroyUnsubmittedRing(owner, sc, ring);
        return EBUSY;
    }
    if (lease->state != TahoeP2PResourceState::kAbsent ||
        lease->pendingRing || lease->submissionBusy ||
        lease->unsubmittedAbortInProgress ||
        lease->idleAbortAfterEndInProgress) {
        unlockQueueLease(lease, interruptState);
        destroyUnsubmittedRing(owner, sc, ring);
        return EBUSY;
    }
    const IntelP2PTx::Result beginResult = lease->lifecycle.begin(admission);
    if (beginResult != IntelP2PTx::Result::kSuccess) {
        unlockQueueLease(lease, interruptState);
        *resourceMayExist = false;
        destroyUnsubmittedRing(owner, sc, ring);
        return EBUSY;
    }
    lease->stationId = stationId;
    lease->generation = generation;
    lease->queueId = IWX_INVALID_QUEUE;
    lease->pendingRing = ring;
    lease->submissionBusy = false;
    lease->submissionDescriptorIndex = IWX_INVALID_QUEUE;
    lease->everDoorbelled = false;
    lease->unsubmittedAbortInProgress = false;
    lease->idleAbortAfterEndInProgress = false;
    syncQueueState(lease);
    // Snapshot only positive proof for the complete attach-time static
    // placeholder. Clear proof before submission; any timeout or malformed
    // response must never make this slot reclaimable on a later attempt.
    placeholderSnapshot = captureUnsubmittedPlaceholder(
        sc, &placeholderCaptureFailureMask);
    clearUnsubmittedPlaceholderProofs(sc);
    ring->nativeUnsubmittedPlaceholder = 0;
    unlockQueueLease(lease, interruptState);
    NativeQueueSlotDiagnostic emptySlotDiagnostic;
    publishQueueSlotDiagnostic(owner, UINT32_MAX, false,
        emptySlotDiagnostic, placeholderCaptureFailureMask,
        placeholderSlotDiagnostic);
    if (controller) {
        controller->setProperty("NativeP2PTxPlaceholderCaptured",
                                uint32_t(placeholderSnapshot.valid), 32);
        controller->setProperty("NativeP2PTxPlaceholderQueueId",
            placeholderSnapshot.valid ? uint32_t(placeholderSnapshot.queueId) :
                                        UINT32_MAX, 32);
    }
    *resourceMayExist = true;

    const int sendError = owner->iwx_send_cmd(sc, &hostCommand);
    if (sendError) {
        publishQueueDiagnostic(owner, true, sendError, UINT32_MAX,
                               false, 0, 0, 0,
                               legacyCommand.tid, kP2PTxDmaNoFailure);
        if (hostCommand.resp_pkt)
            owner->iwx_free_resp(sc, &hostCommand);
        return retainUnknown(lease, ring, generation, stationId, sendError);
    }

    struct iwx_rx_packet *packet = hostCommand.resp_pkt;
    if (!packet || (packet->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        publishQueueDiagnostic(owner, true, 0, EIO, false, 0, 0, 0,
                               legacyCommand.tid, kP2PTxDmaNoFailure);
        if (packet)
            owner->iwx_free_resp(sc, &hostCommand);
        return retainUnknown(lease, ring, generation, stationId, EIO);
    }
    const size_t payloadLength = iwx_rx_packet_payload_len(packet);
    if (payloadLength != sizeof(struct iwx_tx_queue_cfg_rsp)) {
        publishQueueDiagnostic(owner, true, 0, EIO, false, 0, 0, 0,
                               legacyCommand.tid, kP2PTxDmaNoFailure);
        owner->iwx_free_resp(sc, &hostCommand);
        return retainUnknown(lease, ring, generation, stationId, EIO);
    }

    const auto *response = reinterpret_cast<const struct iwx_tx_queue_cfg_rsp *>(
        packet->data);
    const uint16_t firmwareQueue = le16toh(response->queue_number);
    const uint16_t writePointer = le16toh(response->write_pointer);
    const uint16_t responseFlags = le16toh(response->flags);
    const uint16_t responseReserved = le16toh(response->reserved);
    publishQueueDiagnostic(owner, true, 0, 0, true,
                           responseFlags, firmwareQueue,
                           writePointer, legacyCommand.tid,
                           kP2PTxDmaNoFailure);
    owner->iwx_free_resp(sc, &hostCommand);
    if (controller)
        controller->setProperty("NativeP2PTxQueueReserved",
                                uint32_t(responseReserved), 32);

    // Preserve flags for diagnosis. The Linux legacy path uses the queue ID
    // and write pointer, and this machine's Test048 completed PSF/MIF with
    // flags=1, so the field is not a universal failure verdict. The reserved
    // word is still required to be zero.
    if (responseReserved != 0 || firmwareQueue >= nitems(sc->txq) ||
        writePointer >= ring->ring_count) {
        const int error = responseReserved != 0 ? EIO : EBUSY;
        return retainAcknowledgedPending(lease, ring, generation, stationId,
                                         firmwareQueue, writePointer, error);
    }
    struct iwx_tx_ring *retiredPlaceholder = nullptr;
    bool retiredPlaceholderHasRing = false;
    if (placeholderSnapshot.valid &&
        firmwareQueue == placeholderSnapshot.queueId) {
        retiredPlaceholder = static_cast<struct iwx_tx_ring *>(
            IOMalloc(sizeof(struct iwx_tx_ring)));
        if (!retiredPlaceholder) {
            const NativeQueueSlotDiagnostic hostSlotDiagnostic =
                captureQueueSlotDiagnostic(sc, firmwareQueue);
            publishQueueSlotDiagnostic(owner, firmwareQueue, true,
                hostSlotDiagnostic, placeholderCaptureFailureMask,
                placeholderSlotDiagnostic);
            return retainAcknowledgedPending(
                lease, ring, generation, stationId, firmwareQueue,
                writePointer, ENOMEM);
        }
    }

    bool couldParkDynamicRing = false;
    if (dynamicSnapshot.valid &&
        firmwareQueue == dynamicSnapshot.queueId && writePointer == 0 &&
        stationId == kLegacyP2pCollisionPilotStation &&
        dynamicSnapshot.generation == generation &&
        dynamicRingSnapshotStillMatches(owner, sc, &dynamicSnapshot)) {
        if (lockQueueLease(lease, &interruptState)) {
            const IntelP2PTx::QueueSnapshot queueState =
                lease->lifecycle.snapshot();
            couldParkDynamicRing =
                !lease->retainedRing &&
                lease->generation == generation &&
                lease->stationId == stationId &&
                lease->pendingRing == ring &&
                !lease->submissionBusy &&
                queueState.state ==
                    IntelP2PTx::QueueState::kAllocationPending &&
                queueState.generation == generation &&
                queueState.stationId == stationId;
            unlockQueueLease(lease, interruptState);
        }
    }

    bool dynamicBindingWitnessed = false;
    if (couldParkDynamicRing) {
        if (controller)
            controller->setProperty("NativeP2PTxRebindFlushAttempted",
                                    uint32_t(1), 32);
        const int flushError = flushLegacyP2pAllocationBinding(
            owner, sc, stationId, firmwareQueue, writePointer);
        if (controller) {
            controller->setProperty("NativeP2PTxRebindFlushValid",
                                    uint32_t(flushError == 0), 32);
            controller->setProperty("NativeP2PTxRebindFlushResult",
                                    static_cast<uint32_t>(flushError), 32);
        }
        if (flushError ||
            !dynamicRingSnapshotStillMatches(owner, sc, &dynamicSnapshot)) {
            const NativeQueueSlotDiagnostic hostSlotDiagnostic =
                captureQueueSlotDiagnostic(sc, firmwareQueue);
            publishQueueSlotDiagnostic(owner, firmwareQueue, true,
                hostSlotDiagnostic, placeholderCaptureFailureMask,
                placeholderSlotDiagnostic);
            return retainAcknowledgedPending(
                lease, ring, generation, stationId, firmwareQueue,
                writePointer, flushError ? flushError : EBUSY);
        }
        dynamicBindingWitnessed = true;
    }

    if (!lockQueueLease(lease, &interruptState)) {
        if (retiredPlaceholder)
            IOFree(retiredPlaceholder, sizeof(*retiredPlaceholder));
        const NativeQueueSlotDiagnostic hostSlotDiagnostic =
            captureQueueSlotDiagnostic(sc, firmwareQueue);
        publishQueueSlotDiagnostic(owner, firmwareQueue, true,
            hostSlotDiagnostic, placeholderCaptureFailureMask,
            placeholderSlotDiagnostic);
        return retainAcknowledgedPending(
            lease, ring, generation, stationId, firmwareQueue,
            writePointer, EBUSY);
    }
    NativeQueueSlotDiagnostic hostSlotDiagnostic;
    bool slotAvailable = queueSlotCanInstall(
        sc, firmwareQueue, &placeholderSnapshot, &hostSlotDiagnostic);
    const IntelP2PTx::QueueSnapshot allocationState =
        lease->lifecycle.snapshot();
    const bool parkDynamicRing = !slotAvailable && dynamicBindingWitnessed &&
        firmwareQueue == dynamicSnapshot.queueId && writePointer == 0 &&
        dynamicRingSnapshotStillMatches(owner, sc, &dynamicSnapshot) &&
        !lease->retainedRing && lease->generation == generation &&
        lease->stationId == stationId && lease->pendingRing == ring &&
        !lease->submissionBusy &&
        allocationState.state ==
            IntelP2PTx::QueueState::kAllocationPending &&
        allocationState.generation == generation &&
        allocationState.stationId == stationId;
    if (!slotAvailable && parkDynamicRing)
        slotAvailable = true;
    if (!slotAvailable) {
        // The firmware accepted the command, but the host slot has neither
        // static-placeholder proof nor the narrowly validated dynamic-ring
        // parking witness. Keep the lifecycle pending so the caller can run
        // only the no-TX station-abort path; never touch the existing ring.
        lease->generation = generation;
        lease->stationId = stationId;
        lease->queueId = firmwareQueue;
        lease->firmwareWritePointer = writePointer;
        lease->pendingRing = ring;
        syncQueueState(lease);
        unlockQueueLease(lease, interruptState);
        if (retiredPlaceholder)
            IOFree(retiredPlaceholder, sizeof(*retiredPlaceholder));
        publishQueueSlotDiagnostic(owner, firmwareQueue, true,
            hostSlotDiagnostic, placeholderCaptureFailureMask,
            placeholderSlotDiagnostic);
        return EBUSY;
    }

    const IntelP2PTx::Result assigned = lease->lifecycle.legacyDqaAssigned(
        generation, stationId, firmwareQueue,
        static_cast<uint16_t>(nitems(sc->txq)), true);
    if (assigned != IntelP2PTx::Result::kSuccess) {
        syncQueueState(lease);
        lease->queueId = firmwareQueue;
        lease->pendingRing = ring;
        unlockQueueLease(lease, interruptState);
        if (retiredPlaceholder)
            IOFree(retiredPlaceholder, sizeof(*retiredPlaceholder));
        publishQueueSlotDiagnostic(owner, firmwareQueue, true,
            hostSlotDiagnostic, placeholderCaptureFailureMask,
            placeholderSlotDiagnostic);
        return EBUSY;
    }

    ring->cur = writePointer;
    ring->tail = writePointer;
    ring->queued = 0;
    ring->qid = firmwareQueue;
    ring->nativeUnsubmittedPlaceholder = 0;
    if (!queueSlotAvailable(sc, firmwareQueue)) {
        if (parkDynamicRing) {
            memcpy(dynamicSnapshot.ringCopy, &sc->txq[firmwareQueue],
                   sizeof(*dynamicSnapshot.ringCopy));
            lease->retainedRing = dynamicSnapshot.ringCopy;
            lease->retainedRingGeneration = generation;
            lease->retainedRingQueueId = firmwareQueue;
            dynamicSnapshot.ringCopy = nullptr;
            dynamicSnapshot.valid = false;
        } else if (retiredPlaceholder) {
            memcpy(retiredPlaceholder, &sc->txq[firmwareQueue],
                   sizeof(*retiredPlaceholder));
            retiredPlaceholderHasRing = true;
        }
    }
    memcpy(&sc->txq[firmwareQueue], ring, sizeof(*ring));
    lease->pendingRing = nullptr;
    lease->queueId = firmwareQueue;
    lease->firmwareWritePointer = writePointer;
    syncQueueState(lease);
    // A valid allocation response that names another qid proves this command
    // did not configure the snapshotted placeholder. Restore its original
    // positive proof only if the exact backing and no-host-owner checks still
    // hold. Unknown or conflicting outcomes never reach this point.
    if (placeholderSnapshot.valid &&
        firmwareQueue != placeholderSnapshot.queueId &&
        queueMatchesPlaceholderSnapshot(sc, placeholderSnapshot.queueId,
                                        &placeholderSnapshot))
        sc->txq[placeholderSnapshot.queueId].nativeUnsubmittedPlaceholder = 1;
    unlockQueueLease(lease, interruptState);
    publishQueueSlotDiagnostic(owner, firmwareQueue, true,
        hostSlotDiagnostic, placeholderCaptureFailureMask,
        placeholderSlotDiagnostic);
    publishRetainedRingDiagnostic(owner, lease);
    if (retiredPlaceholder) {
        if (retiredPlaceholderHasRing) {
            owner->iwx_free_tx_ring(sc, retiredPlaceholder);
            if (controller)
                controller->setProperty("NativeP2PTxPlaceholderReclaimed",
                                        uint32_t(1), 32);
        }
        IOFree(retiredPlaceholder, sizeof(*retiredPlaceholder));
    }
    memset(ring, 0, sizeof(*ring));
    IOFree(ring, sizeof(*ring));
    *queueId = firmwareQueue;
    return 0;
}

int iwx_tahoe_p2p_tvqm_remove(ItlIwx *owner, struct iwx_softc *sc,
                              TahoeP2PStationLease *stationLease,
                              TahoeP2PTxQueueLease *queueLease,
                              bool *resourceMayExist)
{
    if (resourceMayExist)
        *resourceMayExist = false;
    if (!owner || !sc || sc != &owner->com || !stationLease ||
        !queueLease || !resourceMayExist ||
        !owner->nativeP2pCommandAllowed())
        return EBUSY;
    *resourceMayExist = iwx_tahoe_p2p_tvqm_may_exist(queueLease);
    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    if (stationLease->state != TahoeP2PResourceState::kActive ||
        stationLease->generation != generation)
        return EBUSY;
    IntelP2PTx::QueueApi firmwareApi;
    const int apiError = queueApiForFirmware(owner, sc, &firmwareApi);
    if (apiError)
        return apiError;
    if (firmwareApi != IntelP2PTx::QueueApi::kLegacyDynamicDqa)
        return EOPNOTSUPP;

    IOInterruptState interruptState;
    if (!lockQueueLease(queueLease, &interruptState))
        return EBUSY;
    const IntelP2PTx::QueueSnapshot beforeRemove =
        queueLease->lifecycle.snapshot();
    if (queueLease->state != TahoeP2PResourceState::kActive ||
        queueLease->generation != generation ||
        queueLease->stationId != stationLease->stationId ||
        beforeRemove.api != firmwareApi ||
        !queueLeaseHasInstalledRingLocked(sc, queueLease)) {
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    const uint16_t queueId = queueLease->queueId;
    struct iwx_tx_ring *ring = &sc->txq[queueId];
    if (queueLease->submissionBusy || beforeRemove.outstandingTx != 0 ||
        ring->queued != 0 || ring->cur != ring->tail) {
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    if (firmwareApi == IntelP2PTx::QueueApi::kLegacyDynamicDqa &&
        !beforeRemove.completionObserved) {
        // An empty ring after a cancelled or never-submitted frame is not
        // proof that firmware stopped referencing this queue's DMA buffers.
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    for (uint32_t i = 0; i < ring->ring_count; ++i) {
        if (ring->data[i].m != nullptr || ring->data[i].in != nullptr) {
            unlockQueueLease(queueLease, interruptState);
            return EBUSY;
        }
    }
    const IntelP2PTx::Result beginResult =
        queueLease->lifecycle.beginRemoval(generation, queueId);
    if (beginResult != IntelP2PTx::Result::kSuccess) {
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    syncQueueState(queueLease);
    *resourceMayExist = true;
    unlockQueueLease(queueLease, interruptState);

    if (firmwareApi == IntelP2PTx::QueueApi::kLegacyDynamicDqa) {
        const int flushError = flushLegacyP2pStationQueue(
            owner, sc, stationLease->stationId, queueId, ring);
        if (flushError)
            return flushError;

        // Legacy SCD_QUEUE_CFG v2 has no queue REMOVE operation. The Linux
        // legacy DQA lifecycle flushes the station before removing it. Keep
        // the queue DMA allocated through this synchronous REMOVE_STA ACK;
        // confirm_drained releases it only after observing both the ACK and
        // the real TX completion.
        const int stationError = removeLegacyP2pStationWithAck(
            owner, sc, stationLease->stationId);
        if (stationError) {
            stationLease->state = TahoeP2PResourceState::kUnknown;
            if (lockQueueLease(queueLease, &interruptState)) {
                (void)queueLease->lifecycle.removeOutcomeUnknown(
                    generation, queueId);
                syncQueueState(queueLease);
                unlockQueueLease(queueLease, interruptState);
            }
            return stationError;
        }

        if (!lockQueueLease(queueLease, &interruptState)) {
            // REMOVE_STA has ACKed, so the station is absent. Retain the DMA
            // ring if lease state cannot be updated atomically.
            stationLease->state = TahoeP2PResourceState::kAbsent;
            return EBUSY;
        }
        const IntelP2PTx::Result stationRemoved =
            queueLease->lifecycle.stationRemovalAcknowledged(
                generation, queueId);
        if (stationRemoved != IntelP2PTx::Result::kSuccess) {
            queueLease->state = TahoeP2PResourceState::kUnknown;
            stationLease->state = TahoeP2PResourceState::kAbsent;
            unlockQueueLease(queueLease, interruptState);
            return EIO;
        }
        syncQueueState(queueLease);
        stationLease->state = TahoeP2PResourceState::kAbsent;
        unlockQueueLease(queueLease, interruptState);
        // The queue lease and DMA remain live until the separate drain
        // confirmation path validates the completion and releases them.
        *resourceMayExist = true;
        return 0;
    }
    return EOPNOTSUPP;
}

int iwx_tahoe_p2p_tvqm_abort_unsubmitted(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    bool *resourceMayExist)
{
    if (resourceMayExist)
        *resourceMayExist = false;
    if (!owner || !sc || sc != &owner->com || !stationLease ||
        !queueLease || !resourceMayExist ||
        !owner->nativeP2pCommandAllowed() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0)
        return EBUSY;

    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    if (stationLease->generation != generation)
        return ESTALE;
    if (stationLease->state == TahoeP2PResourceState::kAbsent &&
        queueLease->state == TahoeP2PResourceState::kAbsent &&
        !queueLease->pendingRing) {
        *resourceMayExist = false;
        return 0;
    }
    if (stationLease->state != TahoeP2PResourceState::kActive)
        return EBUSY;

    if (!queueLease->stateLock)
        queueLease->stateLock = owner->nativeP2pTxLock_;
    IOInterruptState interruptState;
    if (!lockQueueLease(queueLease, &interruptState))
        return EBUSY;
    const IntelP2PTx::QueueSnapshot before =
        queueLease->lifecycle.snapshot();
    struct iwx_tx_ring *pendingRing = queueLease->pendingRing;
    const uint16_t queueId = queueLease->queueId;
    const bool eligible =
        queueLease->state == TahoeP2PResourceState::kPending &&
        before.state == IntelP2PTx::QueueState::kAllocationPending &&
        before.api == IntelP2PTx::QueueApi::kLegacyDynamicDqa &&
        before.generation == generation &&
        before.stationId == stationLease->stationId &&
        queueLease->generation == generation &&
        queueLease->stationId == stationLease->stationId &&
        pendingRing != nullptr && !queueLease->submissionBusy &&
        !queueLease->unsubmittedAbortInProgress &&
        before.outstandingTx == 0 && !before.completionObserved &&
        before.ringMustRemainOwned &&
        pendingRing->ring_count >= 8 &&
        pendingRing->ring_count <= IWX_TFD_QUEUE_SIZE_MAX &&
        pendingRing->qid == IWX_INVALID_QUEUE &&
        pendingRing->cur == 0 && pendingRing->tail == 0 &&
        pendingRing->queued == 0 &&
        pendingRing->desc != nullptr && pendingRing->cmd != nullptr &&
        pendingRing->desc_dma.vaddr == pendingRing->desc &&
        pendingRing->cmd_dma.vaddr == pendingRing->cmd &&
        pendingRing->desc_dma.paddr != 0 &&
        pendingRing->cmd_dma.paddr != 0 &&
        pendingRing->bc_tbl.vaddr != nullptr &&
        pendingRing->bc_tbl.paddr != 0 &&
        (pendingRing->ring_count & (pendingRing->ring_count - 1)) == 0;
    if (!eligible) {
        unlockQueueLease(queueLease, interruptState);
        *resourceMayExist = iwx_tahoe_p2p_tvqm_may_exist(queueLease);
        return EBUSY;
    }
    for (uint32_t i = 0; i < pendingRing->ring_count; ++i) {
        if (pendingRing->data[i].map == nullptr ||
            pendingRing->data[i].m != nullptr ||
            pendingRing->data[i].in != nullptr) {
            unlockQueueLease(queueLease, interruptState);
            *resourceMayExist = true;
            return EBUSY;
        }
    }
    for (size_t i = pendingRing->ring_count;
         i < nitems(pendingRing->data); ++i) {
        if (pendingRing->data[i].map != nullptr ||
            pendingRing->data[i].m != nullptr ||
            pendingRing->data[i].in != nullptr) {
            unlockQueueLease(queueLease, interruptState);
            *resourceMayExist = true;
            return EBUSY;
        }
    }
    queueLease->unsubmittedAbortInProgress = true;
    *resourceMayExist = true;
    unlockQueueLease(queueLease, interruptState);

    IntelP2PTx::QueueApi firmwareApi;
    const int apiError = queueApiForFirmware(owner, sc, &firmwareApi);
    if (apiError || firmwareApi != IntelP2PTx::QueueApi::kLegacyDynamicDqa) {
        if (lockQueueLease(queueLease, &interruptState)) {
            queueLease->unsubmittedAbortInProgress = false;
            unlockQueueLease(queueLease, interruptState);
        }
        return apiError ? apiError : EOPNOTSUPP;
    }

    // No doorbell has been issued, so the pending ring is empty. A valid full
    // station flush followed by REMOVE_STA ACK is the only release boundary
    // used here. This path never touches the displaced host qid ring.
    int error = flushLegacyP2pStationQueue(
        owner, sc, stationLease->stationId, queueId, pendingRing);
    if (error) {
        if (lockQueueLease(queueLease, &interruptState)) {
            if (queueLease->pendingRing == pendingRing &&
                queueLease->generation == generation)
                queueLease->unsubmittedAbortInProgress = false;
            unlockQueueLease(queueLease, interruptState);
        }
        return error;
    }
    error = removeLegacyP2pStationWithAck(owner, sc,
                                           stationLease->stationId);
    if (error) {
        stationLease->state = TahoeP2PResourceState::kUnknown;
        if (lockQueueLease(queueLease, &interruptState)) {
            (void)queueLease->lifecycle.allocationOutcomeUnknown(
                generation, stationLease->stationId);
            queueLease->unsubmittedAbortInProgress = false;
            syncQueueState(queueLease);
            unlockQueueLease(queueLease, interruptState);
        }
        return error;
    }

    stationLease->state = TahoeP2PResourceState::kAbsent;
    if (!lockQueueLease(queueLease, &interruptState))
        return EBUSY; // Station is gone; retain pending DMA until a hard stop.
    if (queueLease->pendingRing != pendingRing ||
        queueLease->generation != generation ||
        queueLease->stationId != stationLease->stationId ||
        !queueLease->unsubmittedAbortInProgress ||
        queueLease->submissionBusy) {
        queueLease->state = TahoeP2PResourceState::kUnknown;
        queueLease->unsubmittedAbortInProgress = false;
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    const IntelP2PTx::Result rejected =
        queueLease->lifecycle.allocationRejected(
            generation, stationLease->stationId);
    if (rejected != IntelP2PTx::Result::kSuccess) {
        queueLease->state = TahoeP2PResourceState::kUnknown;
        queueLease->unsubmittedAbortInProgress = false;
        unlockQueueLease(queueLease, interruptState);
        return EIO;
    }
    queueLease->pendingRing = nullptr;
    queueLease->queueId = IWX_INVALID_QUEUE;
    queueLease->firmwareWritePointer = 0;
    queueLease->unsubmittedAbortInProgress = false;
    syncQueueState(queueLease);
    unlockQueueLease(queueLease, interruptState);

    destroyUnsubmittedRing(owner, sc, pendingRing);
    *resourceMayExist = false;
    publishRetainedRingDiagnostic(owner, queueLease);
    return 0;
}

int iwx_tahoe_p2p_tvqm_abort_idle_after_end(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    bool rocEndConfirmed, bool noTicketArmed,
    bool *resourceMayExist)
{
    if (resourceMayExist)
        *resourceMayExist = true;
    if (!owner || !sc || sc != &owner->com || !stationLease ||
        !queueLease || !resourceMayExist)
        return EINVAL;
    if (!rocEndConfirmed || !noTicketArmed ||
        !owner->nativeP2pCommandAllowed() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0)
        return EBUSY;

    const uint32_t generation = static_cast<uint32_t>(sc->sc_generation);
    if (stationLease->generation != generation ||
        queueLease->generation != generation)
        return ESTALE;
    if (stationLease->state != TahoeP2PResourceState::kActive)
        return EBUSY;

    IntelP2PTx::QueueApi firmwareApi;
    const int apiError = queueApiForFirmware(owner, sc, &firmwareApi);
    if (apiError || firmwareApi != IntelP2PTx::QueueApi::kLegacyDynamicDqa)
        return apiError ? apiError : EOPNOTSUPP;

    IOInterruptState interruptState;
    if (!lockQueueLease(queueLease, &interruptState))
        return EBUSY;
    const IntelP2PTx::QueueSnapshot before = queueLease->lifecycle.snapshot();
    const uint16_t queueId = queueLease->queueId;
    const bool eligible =
        queueLease->state == TahoeP2PResourceState::kActive &&
        before.state == IntelP2PTx::QueueState::kActive &&
        before.api == firmwareApi && before.generation == generation &&
        before.stationId == stationLease->stationId &&
        before.queueId == queueId && before.outstandingTx == 0 &&
        !before.completionObserved && before.ringMustRemainOwned &&
        queueLease->generation == generation &&
        queueLease->stationId == stationLease->stationId &&
        !queueLease->everDoorbelled && !queueLease->submissionBusy &&
        !queueLease->idleAbortAfterEndInProgress &&
        queueHasNeverSubmittedEmptyP2pRingLocked(sc, queueLease);
    if (!eligible) {
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }

    if (queueLease->lifecycle.beginRemoval(generation, queueId) !=
        IntelP2PTx::Result::kSuccess) {
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    queueLease->idleAbortAfterEndInProgress = true;
    syncQueueState(queueLease);
    struct iwx_tx_ring *ring = &sc->txq[queueId];
    unlockQueueLease(queueLease, interruptState);

    // Flush must identify exactly this station's management queue and show
    // both scheduler pointers unchanged. A zero-queue ACK is not enough for
    // this reclaim path because it fails to bind the ACK to this allocation.
    int error = flushLegacyP2pStationQueue(
        owner, sc, stationLease->stationId, queueId, ring, true);
    if (!error && (!owner->nativeP2pCommandAllowed() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 ||
        static_cast<uint32_t>(sc->sc_generation) != generation))
        error = EBUSY;
    if (!error) {
        if (!lockQueueLease(queueLease, &interruptState)) {
            error = EBUSY;
        } else {
            const IntelP2PTx::QueueSnapshot afterFlush =
                queueLease->lifecycle.snapshot();
            const bool unchanged =
                queueLease->state == TahoeP2PResourceState::kRemoving &&
                afterFlush.state == IntelP2PTx::QueueState::kRemoving &&
                afterFlush.outstandingTx == 0 &&
                !afterFlush.completionObserved &&
                queueLease->generation == generation &&
                queueLease->stationId == stationLease->stationId &&
                queueLease->queueId == queueId &&
                !queueLease->everDoorbelled &&
                queueLease->idleAbortAfterEndInProgress &&
                !queueLease->submissionBusy &&
                queueHasNeverSubmittedEmptyP2pRingLocked(sc, queueLease);
            unlockQueueLease(queueLease, interruptState);
            if (!unchanged)
                error = EBUSY;
        }
    }
    if (!error && (!owner->nativeP2pCommandAllowed() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 ||
        static_cast<uint32_t>(sc->sc_generation) != generation))
        error = EBUSY;
    if (!error)
        error = removeLegacyP2pStationWithAck(
            owner, sc, stationLease->stationId);
    if (!error && (!owner->nativeP2pCommandAllowed() ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 ||
        static_cast<uint32_t>(sc->sc_generation) != generation))
        error = EBUSY;

    if (error) {
        // Either command may have reached firmware. Quarantine both leases;
        // neither ambiguous ACK nor stale generation releases any DMA.
        stationLease->state = TahoeP2PResourceState::kUnknown;
        if (lockQueueLease(queueLease, &interruptState)) {
            const IntelP2PTx::QueueSnapshot current =
                queueLease->lifecycle.snapshot();
            if (current.state == IntelP2PTx::QueueState::kRemoving &&
                current.generation == generation &&
                current.queueId == queueId)
                (void)queueLease->lifecycle.removeOutcomeUnknown(
                    generation, queueId);
            queueLease->idleAbortAfterEndInProgress = false;
            syncQueueState(queueLease);
            unlockQueueLease(queueLease, interruptState);
        }
        return error;
    }

    // REMOVE_STA ACK is the firmware lifetime boundary for this legacy queue.
    // Move through Releasing while freeing only the current P2P ring outside
    // the spinlock; the displaced retainedRing is intentionally untouched.
    stationLease->state = TahoeP2PResourceState::kAbsent;
    if (!lockQueueLease(queueLease, &interruptState))
        return EBUSY;
    const IntelP2PTx::QueueSnapshot afterRemove =
        queueLease->lifecycle.snapshot();
    const bool removable =
        queueLease->state == TahoeP2PResourceState::kRemoving &&
        afterRemove.state == IntelP2PTx::QueueState::kRemoving &&
        afterRemove.generation == generation && afterRemove.queueId == queueId &&
        afterRemove.stationId == stationLease->stationId &&
        afterRemove.outstandingTx == 0 && !afterRemove.completionObserved &&
        queueLease->generation == generation &&
        queueLease->stationId == stationLease->stationId &&
        queueLease->queueId == queueId && !queueLease->everDoorbelled &&
        queueLease->idleAbortAfterEndInProgress &&
        !queueLease->submissionBusy &&
        queueHasNeverSubmittedEmptyP2pRingLocked(sc, queueLease);
    if (!removable ||
        queueLease->lifecycle.stationRemovalAcknowledged(
            generation, queueId) != IntelP2PTx::Result::kSuccess ||
        queueLease->lifecycle.neverSubmittedQueueReleasedAfterStationRemoval(
            generation, queueId) != IntelP2PTx::Result::kSuccess) {
        queueLease->state = TahoeP2PResourceState::kUnknown;
        queueLease->idleAbortAfterEndInProgress = false;
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    queueLease->state = TahoeP2PResourceState::kReleasing;
    unlockQueueLease(queueLease, interruptState);

    owner->iwx_free_tx_ring(sc, ring);
    memset(ring, 0, sizeof(*ring));
    ring->qid = IWX_INVALID_QUEUE;

    if (!lockQueueLease(queueLease, &interruptState))
        return EBUSY;
    if (queueLease->state != TahoeP2PResourceState::kReleasing ||
        queueLease->generation != generation || queueLease->queueId != queueId ||
        queueLease->everDoorbelled ||
        queueLease->lifecycle.snapshot().state !=
            IntelP2PTx::QueueState::kAbsent) {
        queueLease->state = TahoeP2PResourceState::kUnknown;
        unlockQueueLease(queueLease, interruptState);
        return EBUSY;
    }
    queueLease->state = TahoeP2PResourceState::kAbsent;
    queueLease->queueId = IWX_INVALID_QUEUE;
    queueLease->pendingRing = nullptr;
    queueLease->submissionBusy = false;
    queueLease->submissionDescriptorIndex = IWX_INVALID_QUEUE;
    queueLease->firmwareWritePointer = 0;
    queueLease->idleAbortAfterEndInProgress = false;
    unlockQueueLease(queueLease, interruptState);

    *resourceMayExist = false;
    publishRetainedRingDiagnostic(owner, queueLease);
    return 0;
}

int iwx_tahoe_p2p_tvqm_release_retained_after_master_disabled(
    ItlIwx *owner, struct iwx_softc *sc,
    bool masterDisabledObserved, bool swResetIssued)
{
    if (!owner || !sc || sc != &owner->com)
        return EINVAL;
    if (!masterDisabledObserved || !swResetIssued)
        return EBUSY;

    TahoeP2PTxQueueLease *lease = &owner->nativeP2pTxQueue_;
    struct iwx_tx_ring *ring = nullptr;
    IOInterruptState interruptState;
    if (lease->stateLock) {
        if (!lockQueueLease(lease, &interruptState))
            return EBUSY;
        ring = lease->retainedRing;
        lease->retainedRing = nullptr;
        lease->retainedRingGeneration = 0;
        lease->retainedRingQueueId = IWX_INVALID_QUEUE;
        unlockQueueLease(lease, interruptState);
    } else {
        ring = lease->retainedRing;
        lease->retainedRing = nullptr;
        lease->retainedRingGeneration = 0;
        lease->retainedRingQueueId = IWX_INVALID_QUEUE;
    }
    if (ring) {
        owner->iwx_free_tx_ring(sc, ring);
        IOFree(ring, sizeof(*ring));
    }
    publishRetainedRingDiagnostic(owner, lease);
    return 0;
}

bool iwx_tahoe_p2p_tvqm_queue_owned(
    TahoeP2PTxQueueLease *lease, uint16_t queueId)
{
    if (!lease)
        return false;
    if (!lease->stateLock)
        return lease->state != TahoeP2PResourceState::kAbsent &&
            lease->queueId == queueId;
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return true;
    const bool owned = lease->state != TahoeP2PResourceState::kAbsent &&
        lease->queueId == queueId;
    unlockQueueLease(lease, interruptState);
    return owned;
}

bool iwx_tahoe_p2p_tvqm_may_exist(TahoeP2PTxQueueLease *lease)
{
    if (!lease)
        return false;
    if (!lease->stateLock)
        return lease->state != TahoeP2PResourceState::kAbsent ||
            lease->pendingRing != nullptr;
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return true;
    const bool mayExist = lease->state != TahoeP2PResourceState::kAbsent ||
        lease->pendingRing != nullptr;
    unlockQueueLease(lease, interruptState);
    return mayExist;
}

int iwx_tahoe_p2p_tvqm_begin_tx(struct iwx_softc *sc,
                                TahoeP2PTxQueueLease *lease,
                                struct iwx_tx_ring **ring,
                                uint16_t *descriptorIndex)
{
    if (ring)
        *ring = nullptr;
    if (descriptorIndex)
        *descriptorIndex = 0;
    if (!sc || !lease || !ring || !descriptorIndex)
        return EINVAL;
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return EBUSY;
    if (lease->state != TahoeP2PResourceState::kActive ||
        lease->submissionBusy ||
        lease->unsubmittedAbortInProgress ||
        lease->idleAbortAfterEndInProgress ||
        !queueLeaseHasInstalledRingLocked(sc, lease)) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    struct iwx_tx_ring *ownedRing = &sc->txq[lease->queueId];
    const uint16_t index = static_cast<uint16_t>(
        ownedRing->cur & (ownedRing->ring_count - 1));
    if (ownedRing->ring_count == 0 || ownedRing->queued < 0 ||
        static_cast<unsigned>(ownedRing->queued) >= ownedRing->ring_count ||
        ownedRing->data[index].m != nullptr ||
        ownedRing->data[index].in != nullptr) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    const IntelP2PTx::Result result = lease->lifecycle.txSubmitted(
        lease->generation, lease->queueId);
    if (result != IntelP2PTx::Result::kSuccess) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    lease->submissionBusy = true;
    lease->submissionDescriptorIndex = index;
    *ring = ownedRing;
    *descriptorIndex = index;
    unlockQueueLease(lease, interruptState);
    return 0;
}

int iwx_tahoe_p2p_tvqm_mark_doorbell(
    struct iwx_softc *sc, TahoeP2PTxQueueLease *lease,
    struct iwx_tx_ring *ring, uint16_t descriptorIndex)
{
    if (!sc || !lease || !ring)
        return EINVAL;
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return EBUSY;
    const IntelP2PTx::QueueSnapshot snapshot = lease->lifecycle.snapshot();
    const bool currentSubmission =
        lease->state == TahoeP2PResourceState::kActive &&
        snapshot.state == IntelP2PTx::QueueState::kActive &&
        snapshot.generation == static_cast<uint32_t>(sc->sc_generation) &&
        lease->generation == static_cast<uint32_t>(sc->sc_generation) &&
        snapshot.queueId == lease->queueId &&
        snapshot.outstandingTx != 0 && lease->submissionBusy &&
        !lease->unsubmittedAbortInProgress &&
        !lease->idleAbortAfterEndInProgress &&
        queueLeaseHasInstalledRingLocked(sc, lease) &&
        ring == &sc->txq[lease->queueId] &&
        descriptorIndex == lease->submissionDescriptorIndex &&
        descriptorIndex < ring->ring_count &&
        ring->data[descriptorIndex].m != nullptr;
    if (!currentSubmission) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    // Monotonic for the full allocation lifetime. This is deliberately set
    // before the caller's immediately-following MMIO write, so any ambiguity
    // from that point prevents the no-doorbell cleanup path.
    lease->everDoorbelled = true;
    unlockQueueLease(lease, interruptState);
    return 0;
}

int iwx_tahoe_p2p_tvqm_finish_tx_submit(TahoeP2PTxQueueLease *lease)
{
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return EBUSY;
    if (!lease->submissionBusy) {
        // The TX response may beat the submitter back from the doorbell.
        unlockQueueLease(lease, interruptState);
        return 0;
    }
    lease->submissionBusy = false;
    lease->submissionDescriptorIndex = IWX_INVALID_QUEUE;
    unlockQueueLease(lease, interruptState);
    return 0;
}

int iwx_tahoe_p2p_tvqm_cancel_tx_submit(TahoeP2PTxQueueLease *lease)
{
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return EBUSY;
    if (!lease->submissionBusy) {
        unlockQueueLease(lease, interruptState);
        return EINVAL;
    }
    const IntelP2PTx::Result result = lease->lifecycle.txCancelled(
        lease->generation, lease->queueId);
    lease->submissionBusy = false;
    lease->submissionDescriptorIndex = IWX_INVALID_QUEUE;
    unlockQueueLease(lease, interruptState);
    return result == IntelP2PTx::Result::kSuccess ? 0 : EINVAL;
}

bool iwx_tahoe_p2p_tvqm_lock_completion(
    struct iwx_softc *sc, TahoeP2PTxQueueLease *lease, uint16_t queueId,
    struct iwx_tx_ring **ring, IOInterruptState *interruptState)
{
    if (ring)
        *ring = nullptr;
    if (!ring || !lockQueueLease(lease, interruptState))
        return false;
    if (!lease || lease->queueId != queueId ||
        !queueLeaseHasInstalledRingLocked(sc, lease)) {
        unlockQueueLease(lease, *interruptState);
        return false;
    }
    *ring = &sc->txq[queueId];
    return true;
}

int iwx_tahoe_p2p_tvqm_tx_completed_locked(
    struct iwx_softc *sc, TahoeP2PTxQueueLease *lease)
{
    if (!queueLeaseHasInstalledRingLocked(sc, lease))
        return ESTALE;
    const IntelP2PTx::Result result = lease->lifecycle.txCompleted(
        lease->generation, lease->queueId);
    if (result != IntelP2PTx::Result::kSuccess)
        return EINVAL;
    lease->submissionBusy = false;
    lease->submissionDescriptorIndex = IWX_INVALID_QUEUE;
    syncQueueState(lease);
    return 0;
}

void iwx_tahoe_p2p_tvqm_unlock(TahoeP2PTxQueueLease *lease,
                               IOInterruptState interruptState)
{
    if (lease && lease->stateLock)
        unlockQueueLease(lease, interruptState);
}

int iwx_tahoe_p2p_tvqm_confirm_drained(ItlIwx *owner, struct iwx_softc *sc,
                                       TahoeP2PTxQueueLease *lease,
                                       bool *resourceMayExist)
{
    if (resourceMayExist)
        *resourceMayExist = true;
    if (!owner || !sc || sc != &owner->com || !lease ||
        !resourceMayExist ||
        !owner->nativeP2pCommandAllowed())
        return EBUSY;
    IOInterruptState interruptState;
    if (!lockQueueLease(lease, &interruptState))
        return EBUSY;
    if (lease->state != TahoeP2PResourceState::kRemoving ||
        !queueLeaseHasInstalledRingLocked(sc, lease)) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    struct iwx_tx_ring *ring = &sc->txq[lease->queueId];

    const IntelP2PTx::QueueSnapshot snapshot = lease->lifecycle.snapshot();
    if (snapshot.state != IntelP2PTx::QueueState::kRemoving ||
        snapshot.outstandingTx != 0 || ring->queued != 0 ||
        ring->cur != ring->tail || lease->submissionBusy) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    for (uint32_t i = 0; i < ring->ring_count; ++i) {
        if (ring->data[i].m != nullptr || ring->data[i].in != nullptr) {
            unlockQueueLease(lease, interruptState);
            return EBUSY;
        }
    }

    // Completion accounting and an empty ring are the independent drain
    // evidence. Only now can the DMA allocations/maps be destroyed.
    if (lease->lifecycle.queueDrained(lease->generation, lease->queueId) !=
        IntelP2PTx::Result::kSuccess) {
        unlockQueueLease(lease, interruptState);
        return EBUSY;
    }
    lease->state = TahoeP2PResourceState::kReleasing;
    unlockQueueLease(lease, interruptState);

    owner->iwx_free_tx_ring(sc, ring);
    memset(ring, 0, sizeof(*ring));
    ring->qid = IWX_INVALID_QUEUE;
    if (!lockQueueLease(lease, &interruptState))
        return EBUSY;
    lease->state = TahoeP2PResourceState::kAbsent;
    lease->queueId = IWX_INVALID_QUEUE;
    lease->pendingRing = nullptr;
    lease->submissionBusy = false;
    unlockQueueLease(lease, interruptState);
    *resourceMayExist = false;
    return 0;
}

#endif // AIRPORT_TAHOE

