#!/usr/bin/env python3
"""Fault-inject the production Tahoe P2P station/TVQM HAL methods."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "itlwm/hal_iwx/ItlIwxP2PTx.cpp").read_text()
driver_source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
action_source = (root / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
probe_source = (root / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()


def extract_driver_function(marker):
    start = driver_source.index(marker)
    opening = driver_source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (driver_source[end] == "{") - (driver_source[end] == "}")
        end += 1
    return driver_source[start:end]


attach_alloc = extract_driver_function("iwx_alloc_tx_ring(struct iwx_softc")
static_enable = extract_driver_function("iwx_enable_txq(struct iwx_softc")
dynamic_enable = extract_driver_function("iwx_tvqm_enable_txq(struct iwx_softc")
ring_free = extract_driver_function("iwx_free_tx_ring(struct iwx_softc")
ring_reset = extract_driver_function("iwx_reset_tx_ring(struct iwx_softc")
assert attach_alloc.index("for (i = 0; i < ring->ring_count; i++)") < \
       attach_alloc.index("ring->nativeUnsubmittedPlaceholder = 1;")
assert "if (qid == IWX_DQA_P2P_DEVICE_QUEUE)" in attach_alloc
assert static_enable.index("ring->nativeUnsubmittedPlaceholder = 0;") < \
       static_enable.index("err = iwx_send_cmd(sc, &hcmd);")
assert "ring->nativeUnsubmittedPlaceholder = 0;" in dynamic_enable
assert "ring->nativeUnsubmittedPlaceholder = 0;" in ring_free
assert "nativeUnsubmittedPlaceholder = 1" not in ring_reset


def extract_function(marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def extract_action_function(marker):
    start = action_source.index(marker)
    opening = action_source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (action_source[end] == "{") - (action_source[end] == "}")
        end += 1
    return action_source[start:end]


def extract_action_helper_function(marker):
    return extract_action_function(marker)


def extract_probe_function(marker):
    start = probe_source.index(marker)
    opening = probe_source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (probe_source[end] == "{") - (probe_source[end] == "}")
        end += 1
    return probe_source[start:end]


tx_submit = extract_action_function("int iwx_tahoe_p2p_action_tx_submit(")
tx_response = extract_action_function(
    "bool iwx_tahoe_p2p_action_tx_response(")
doorbell_evidence = extract_action_function(
    "static bool recordP2PTxEvidenceDoorbell(")
assert tx_submit.index("iwx_tahoe_p2p_tvqm_mark_doorbell(") < \
       tx_submit.index("recordP2PTxEvidenceDoorbell(") < \
       tx_submit.index("IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR") < \
       tx_submit.index("markP2PTxEvidenceDoorbellIssued(context)")
assert tx_submit.index("prepareP2PTxEvidenceTicket(") < \
       tx_submit.index("iwx_tahoe_p2p_tvqm_mark_doorbell(")
ticket_created = doorbell_evidence.index("ledger.beginTicket(")
submission_lower = doorbell_evidence.index(
    "p2pTxEvidenceLowerBoundUs()", ticket_created)
assert ticket_created < submission_lower < \
       doorbell_evidence.index("ledger.recordSubmission(")
assert "return nanoseconds / 1000ULL;" in action_source
assert "nanoseconds % 1000ULL != 0 ? 1ULL : 0ULL" in action_source
assert tx_submit.index("IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR") < \
       tx_submit.index("iwx_tahoe_p2p_tvqm_finish_tx_submit(queueLease)") < \
       tx_submit.index("markP2PTxEvidenceUnknown(context,")
assert tx_response.index("p2pTxEvidenceUpperBoundUs()") < \
       tx_response.index("pendingP2PTxEvidenceMatchesTicket(")
assert tx_response.index("IWX_TX_RES_GET_RA(responseRaTid)") < \
       tx_response.index("IWX_TX_RES_GET_TID(responseRaTid)") < \
       tx_response.index("context->completion.complete(") < \
       tx_response.index("iwx_tahoe_p2p_tvqm_tx_completed_locked(") < \
       tx_response.index("clearActionDescriptor(&ring->desc[index])") < \
       tx_response.index("recordP2PTxEvidenceCompletion(context,")
assert "if (matchingEvidenceTicket)\n        recordP2PTxEvidenceCompletion(" in tx_response
assert "ITL_NATIVE_AWDL_TX_EVIDENCE_25G332" in action_source
assert "#else\n    action->result = iwx_tahoe_p2p_action_tx_submit(" in probe_source
assert "evidenceMetadataPointer" in probe_source
assert "0, 0, 0, bootstrapSubmitFencePointer" in probe_source

evidence_publisher = extract_probe_function(
    "static void publishNativeP2PTxTimeEvidenceOnMainGate(")
evidence_request = extract_probe_function(
    "static void requestNativeP2PTxTimeEvidencePublish(")
evidence_record_field = extract_probe_function(
    "static bool setNativeP2PTxTimeEvidenceRecordField(")
assert "!owner->tahoeP2pOnMainGate()" in evidence_publisher
assert "ledger.snapshotTicket(index, &ticket)" in evidence_publisher
assert "NativeP2PTxTimeEvidenceSchemaVersion" in evidence_publisher
assert "NativeP2PTxTimeEvidenceSnapshotVersionBegin" in evidence_publisher
assert "NativeP2PTxTimeEvidenceSnapshotVersionEnd" in evidence_publisher
assert "NativeP2PTxTimeEvidenceDiagnosticGeneration" in evidence_publisher
assert "NativeP2PTxTimeEvidenceDroppedCount" in evidence_publisher
assert evidence_publisher.index("writingVersion, 64") < \
       evidence_publisher.index("NativeP2PTxTimeEvidenceSchemaVersion") < \
       evidence_publisher.index("NativeP2PTxTimeEvidenceSnapshotVersionEnd")
assert evidence_publisher.rindex(
    "NativeP2PTxTimeEvidenceSnapshotVersionBegin") > \
       evidence_publisher.index("NativeP2PTxTimeEvidenceSnapshotVersionEnd")
assert "ScheduleRevision" not in evidence_publisher
assert "PeerToken" not in evidence_publisher
assert "NativeP2PTxTimeEvidenceRecord%u%s" in evidence_record_field
assert "StatusFlags" in evidence_publisher
assert "IOCommandGate *gate = owner->tahoeP2pCommandGate();" in evidence_request
assert "gate->runAction(publishNativeP2PTxTimeEvidenceAction, owner)" in \
       evidence_request
assert "requestNativeP2PTxTimeEvidencePublish(this);" in probe_source


helper_start = source.index("namespace {\n\nstatic constexpr uint8_t kDataPathScdQueueConfig")
helper_end = source.index("} // namespace", helper_start) + len("} // namespace")
helpers = source[helper_start:helper_end]
markers = [
    "int iwx_tahoe_p2p_add_broadcast_station(",
    "int iwx_tahoe_p2p_remove_broadcast_station(",
    "int iwx_tahoe_p2p_tvqm_allocate(",
    "int iwx_tahoe_p2p_tvqm_remove(",
    "int iwx_tahoe_p2p_tvqm_abort_unsubmitted(",
    "int iwx_tahoe_p2p_tvqm_abort_idle_after_end(",
    "int iwx_tahoe_p2p_tvqm_release_retained_after_master_disabled(",
    "bool iwx_tahoe_p2p_tvqm_queue_owned(",
    "bool iwx_tahoe_p2p_tvqm_may_exist(",
    "int iwx_tahoe_p2p_tvqm_begin_tx(",
    "int iwx_tahoe_p2p_tvqm_mark_doorbell(",
    "int iwx_tahoe_p2p_tvqm_finish_tx_submit(",
    "int iwx_tahoe_p2p_tvqm_cancel_tx_submit(",
    "bool iwx_tahoe_p2p_tvqm_lock_completion(",
    "int iwx_tahoe_p2p_tvqm_tx_completed_locked(",
    "void iwx_tahoe_p2p_tvqm_unlock(",
    "int iwx_tahoe_p2p_tvqm_confirm_drained(",
]
actual = "\n".join([helpers] + [extract_function(marker) for marker in markers])
actual += "\n" + extract_action_helper_function(
    "static uint64_t p2pTxEvidenceLowerBoundUsFromNanoseconds(")
actual += "\n" + extract_action_helper_function(
    "static uint64_t p2pTxEvidenceUpperBoundUsFromNanoseconds(")

shim = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#define AIRPORT_TAHOE 1
#include "itlwm/hal_iwx/ItlIwxP2PTx.hpp"
#include "iwx_dma_info_lifecycle.hpp"

static unsigned gLiveIoObjects = 0;
static unsigned gDmaCalls = 0;
static unsigned gDmaLive = 0;
static unsigned gDmaFailAt = 0;
static unsigned gMapCalls = 0;
static unsigned gMapLive = 0;
static unsigned gMapFailAt = 0;
static uint64_t gNextPaddr = 0x100000;

static void *IOMalloc(size_t size) {
    void *p = std::calloc(1, size);
    if (p) ++gLiveIoObjects;
    return p;
}
static void IOFree(void *p, size_t) {
    if (p) { --gLiveIoObjects; std::free(p); }
}

struct IOSimpleLock { bool held = false; };
static IOSimpleLock *IOSimpleLockAlloc() { return new IOSimpleLock(); }
static void IOSimpleLockFree(IOSimpleLock *p) { delete p; }
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *p) {
    assert(p && !p->held); p->held = true; return 0;
}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *p, IOInterruptState) {
    assert(p && p->held); p->held = false;
}

using bus_addr_t = uint64_t;
using bus_dmamap_t = void *;
struct iwx_dma_info {
    void *buffer; bus_addr_t paddr; void *vaddr; size_t size;
    void *bmd; void *cmd;
};
struct iwx_tfh_tfd { uint8_t bytes[32]; };
struct iwx_device_cmd { uint8_t bytes[64]; };
struct iwx_gen3_bc_tbl { uint8_t bytes[256]; };
struct iwx_agn_scd_bc_tbl { uint8_t bytes[128]; };
struct iwx_node { uint8_t opaque[8]; };
struct iwx_tx_data {
    bus_dmamap_t map;
    bus_addr_t cmd_paddr;
    void *m;
    iwx_node *in;
    int flags;
    uint8_t type;
    uint32_t rate_generation;
};
struct iwx_tx_ring {
    iwx_dma_info desc_dma, cmd_dma, bc_tbl;
    iwx_tfh_tfd *desc;
    iwx_device_cmd *cmd;
    iwx_tx_data data[1024];
    unsigned ring_count, hi_mark, low_mark;
    int qid, queued, cur, tail;
    uint8_t nativeUnsubmittedPlaceholder;
};
struct iwx_tid_data { uint16_t qid; };
struct iwx_p2p_context {
    uint8_t initialized, mac_state, binding_state, phy_leased;
    uint8_t mac_id, mac_color;
    uint32_t fw_generation;
};
struct ieee80211com { int ic_opmode = 1; };
struct iwx_softc {
    int sc_generation = 41;
    int sc_capa_num_stations = 16;
    int sc_device_family = 1;
    int sc_dmat = 0;
    int qfullmsk = 0;
    int first_data_qid = -1;
    uint8_t sc_ucode_api[8]{};
    uint8_t sc_enabled_capa[8]{};
    iwx_p2p_context sc_p2p{};
    ieee80211com sc_ic{};
    iwx_tid_data sc_tid_data[9]{};
    iwx_tx_ring *txq = nullptr;
};
struct iwx_add_sta_cmd {
    uint8_t sta_id, add_modify;
    uint16_t tid_disable_tx;
    uint32_t mac_id_n_color;
    uint8_t addr[6];
    uint8_t station_type;
};
struct iwx_rm_sta_cmd { uint8_t sta_id, reserved[3]; } __attribute__((packed));
struct iwx_rx_packet_header { uint8_t group_id; };
struct iwx_rx_packet {
    iwx_rx_packet_header hdr{};
    uint8_t data[256]{};
    size_t payloadLength = 0;
};
struct iwx_cmd_response { uint32_t status; } __attribute__((packed));
struct iwx_tx_queue_cfg_cmd {
    uint8_t sta_id, tid;
    uint16_t flags;
    uint32_t cb_size;
    uint64_t byte_cnt_addr, tfdq_addr;
} __attribute__((packed));
struct iwx_tx_queue_cfg_rsp {
    uint16_t queue_number, flags, write_pointer, reserved;
} __attribute__((packed));
struct iwx_tx_path_flush_cmd {
    uint32_t sta_id;
    uint16_t tid_mask, reserved;
} __attribute__((packed));
struct iwx_flush_queue_info {
    uint16_t tid, queue_num, read_before_flush, read_after_flush;
} __attribute__((packed));
struct iwx_tx_path_flush_cmd_rsp {
    uint16_t sta_id, num_flushed_queues;
    iwx_flush_queue_info queues[16];
} __attribute__((packed));
struct iwx_host_cmd {
    uint32_t id = 0, flags = 0;
    size_t resp_pkt_len = 0;
    void *data[1]{};
    uint16_t len[1]{};
    iwx_rx_packet *resp_pkt = nullptr;
};

static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *p) {
    return p ? p->payloadLength : 0;
}
static int bus_dmamap_create(int, size_t, int, size_t, int, int, bus_dmamap_t *out) {
    ++gMapCalls;
    if (gMapFailAt == gMapCalls) return ENOMEM;
    *out = std::malloc(1);
    if (!*out) return ENOMEM;
    ++gMapLive;
    return 0;
}
static void bus_dmamap_destroy(int, bus_dmamap_t map) {
    if (map) { --gMapLive; std::free(map); }
}

template <typename T, size_t N>
static constexpr size_t testNitems(T (&)[N]) { return N; }
static constexpr size_t testNitems(iwx_tx_ring *) { return 512; }
#define nitems(a) testNitems(a)
#define isset(bits,bit) (((bits)[(bit)/8] & (1U << ((bit)%8))) != 0)
#define htole16(x) static_cast<uint16_t>(x)
#define htole32(x) static_cast<uint32_t>(x)
#define htole64(x) static_cast<uint64_t>(x)
#define le16toh(x) static_cast<uint16_t>(x)
#define le32toh(x) static_cast<uint32_t>(x)
#define le64toh(x) static_cast<uint64_t>(x)
#define IWX_DATA_PATH_GROUP 5
#define IWX_LONG_GROUP 1
#define IWX_ADD_STA 0x18
#define IWX_REMOVE_STA 0x19
#define IWX_TXPATH_FLUSH 0x1e
#define IWX_SCD_QUEUE_CFG 0x1d
#define IWX_FW_CMD_VER_UNKNOWN 99
#define IWX_TX_QUEUE_CFG_ENABLE_QUEUE 1
#define IWX_TX_FLUSH_QUEUE_RSP 16
#define IWX_AGG_SSN_TO_TXQ_IDX(x,a) ((x) & ((a) - 1))
#define IWX_ADD_STA_SUCCESS 1
#define IWX_ADD_STA_STATUS_MASK 0xff
#define IWX_STA_GENERAL_PURPOSE 1
#define IWX_MGMT_TID 15
#define IWX_UCODE_TLV_API_STA_TYPE 20
#define IWX_UCODE_TLV_CAPA_DQA_SUPPORT 12
#define IWX_STATION_ID 0
#define IWX_DQA_CMD_QUEUE 0
#define IWX_DQA_P2P_DEVICE_QUEUE 2
#define IWX_MAX_TID_COUNT 8
#define IWX_INVALID_QUEUE 0xffff
#define IWX_DEFAULT_QUEUE_SIZE 256
#define IWX_TFD_QUEUE_SIZE_MAX 256
#define IWX_TFH_NUM_TBS 25
#define IWX_FIRST_TB_SIZE_ALIGN 64
#define IWX_TFD_QUEUE_CB_SIZE(x) (__builtin_ctz(static_cast<unsigned>(x)) - 3)
#define IWX_DEVICE_FAMILY_22000 1
#define IWX_DEVICE_FAMILY_AX210 2
#define IWX_WIDE_ID(group,cmd) (((group) << 8) | (cmd))
#define IWX_CMD_WANT_RESP 2
#define IWX_CMD_FAILED_MSK 0x40
#define IEEE80211_M_MONITOR 4
#define MCLBYTES 2048
#define BUS_DMA_NOWAIT 0
#define IWX_FW_CMD_ID_AND_COLOR(id,color) ((id) | ((color) << 8))
#define IWX_P2P_RESOURCE_ABSENT 0
#define IWX_P2P_RESOURCE_ACTIVE 1
#define IWX_P2P_RESOURCE_UNKNOWN 2

class IOEthernetController {
public:
    std::unordered_map<std::string, uint32_t> properties;
    IOSimpleLock *guardLock = nullptr;
    bool setProperty(const char *key, uint32_t value, unsigned) {
        assert(!guardLock || !guardLock->held);
        properties[key] = value;
        return true;
    }
    uint32_t property(const char *key) const {
        auto it = properties.find(key);
        return it == properties.end() ? UINT32_MAX : it->second;
    }
};

class ItlIwx {
public:
    iwx_softc com{};
    IOEthernetController controller;
    IOSimpleLock *nativeP2pTxLock_ = IOSimpleLockAlloc();
    TahoeP2PTxQueueLease nativeP2pTxQueue_{};
    uint32_t nativeP2pNswqPaused_ = 1;
    bool allowed = true;
    uint8_t cmdVersion = IWX_FW_CMD_VER_UNKNOWN;
    uint8_t addStaCmdVersion = 12, addStaNotifVersion = 2;
    uint8_t legacyQueueCmdVersion = 2, legacyQueueNotifVersion = 2;
    uint8_t flushCmdVersion = 2, flushNotifVersion = 1;
    uint8_t removeStaCmdVersion = 2;
    int sendError = 0;
    int flushError = 0;
    int stationRemoveError = 0;
    int removeError = 0;
    int stationSendError = 0;
    uint32_t stationStatus = IWX_ADD_STA_SUCCESS;
    uint16_t responseQueue = 2, responseWritePointer = 3,
             responseFlags = 0, responseReserved = 0;
    size_t responseLength = sizeof(iwx_tx_queue_cfg_rsp);
    uint8_t responseGroupId = 0;
    size_t flushResponseLength = sizeof(iwx_tx_path_flush_cmd_rsp);
    uint16_t flushStationId = 3, flushQueueCount = 1;
    uint16_t flushTid = IWX_MGMT_TID, flushQueue = 2,
             flushReadBefore = 3, flushReadAfter = 3;
    uint16_t flushSecondTid = IWX_MGMT_TID, flushSecondQueue = 2,
             flushSecondReadBefore = 0, flushSecondReadAfter = 0;
    int generationAfterFlush = 0;
    uint32_t flushGroupId = 0;
    uint32_t stationRemoveGroupId = 0;
    uint32_t removeStationStatus = 0;
    size_t removeStationResponseLength = 0;
    unsigned sendCount = 0, flushCount = 0, removeCount = 0,
             stationCount = 0, queueRemoveCount = 0;
    uint32_t lastCommandId = 0;
    std::vector<uint8_t> lastCommand;
    std::vector<uint8_t> lastLegacyQueueCommand;
    std::vector<uint8_t> lastFlushCommand;
    std::vector<uint8_t> lastStationRemoveCommand;

    ItlIwx() {
        controller.guardLock = nativeP2pTxLock_;
        nativeP2pTxQueue_.stateLock = nativeP2pTxLock_;
        com.txq = new iwx_tx_ring[512]{};
        com.sc_p2p.initialized = 1;
        com.sc_p2p.mac_state = 1;
        com.sc_p2p.binding_state = 1;
        com.sc_p2p.phy_leased = 1;
        com.sc_p2p.fw_generation = com.sc_generation;
        com.sc_device_family = IWX_DEVICE_FAMILY_22000;
    }
    ~ItlIwx() { delete[] com.txq; IOSimpleLockFree(nativeP2pTxLock_); }
    IOEthernetController *tahoeP2pController() { return &controller; }
    bool nativeP2pCommandAllowed() const { return allowed; }
    uint8_t iwx_lookup_cmd_ver(iwx_softc *, uint8_t group, uint8_t cmd) {
        if (group == IWX_DATA_PATH_GROUP && cmd == 0x17)
            return cmdVersion;
        if (group != IWX_LONG_GROUP)
            return IWX_FW_CMD_VER_UNKNOWN;
        if (cmd == IWX_SCD_QUEUE_CFG)
            return legacyQueueCmdVersion;
        if (cmd == IWX_ADD_STA)
            return addStaCmdVersion;
        if (cmd == IWX_TXPATH_FLUSH)
            return flushCmdVersion;
        if (cmd == IWX_REMOVE_STA)
            return removeStaCmdVersion;
        return IWX_FW_CMD_VER_UNKNOWN;
    }
    uint8_t iwx_lookup_notif_ver(iwx_softc *, uint8_t group, uint8_t cmd) {
        if (group != IWX_LONG_GROUP)
            return IWX_FW_CMD_VER_UNKNOWN;
        if (cmd == IWX_SCD_QUEUE_CFG)
            return legacyQueueNotifVersion;
        if (cmd == IWX_ADD_STA)
            return addStaNotifVersion;
        if (cmd == IWX_TXPATH_FLUSH)
            return flushNotifVersion;
        return IWX_FW_CMD_VER_UNKNOWN;
    }
    void iwx_tx_ring_init(iwx_softc *, iwx_tx_ring *ring, int size) {
        ring->ring_count = static_cast<unsigned>(size);
        ring->queued = ring->cur = ring->tail = 0;
        ring->low_mark = static_cast<unsigned>(size - (size / 4));
        ring->hi_mark = static_cast<unsigned>(size - (size / 8));
    }
    int iwx_dma_contig_alloc(int, iwx_dma_info *info, size_t size, int) {
        ++gDmaCalls;
        if (gDmaFailAt == gDmaCalls) return ENOMEM;
        info->vaddr = std::calloc(1, size);
        if (!info->vaddr) return ENOMEM;
        info->size = size;
        info->paddr = gNextPaddr;
        gNextPaddr += (size + 0xff) & ~uint64_t(0xff);
        ++gDmaLive;
        return 0;
    }
    void iwx_reset_tx_ring(iwx_softc *, iwx_tx_ring *ring) {
        for (unsigned i = 0; i < ring->ring_count; ++i) {
            ring->data[i].m = nullptr;
            ring->data[i].in = nullptr;
        }
        if (ring->qid == IWX_INVALID_QUEUE || !ring->desc) return;
        ring->queued = ring->cur = ring->tail = 0;
    }
    void iwx_free_tx_ring(iwx_softc *sc, iwx_tx_ring *ring) {
        (void)sc;
        ring->nativeUnsubmittedPlaceholder = 0;
        for (iwx_dma_info *info : {&ring->desc_dma, &ring->cmd_dma, &ring->bc_tbl}) {
            if (info->vaddr) { --gDmaLive; std::free(info->vaddr); }
            *info = {};
        }
        for (unsigned i = 0; i < ring->ring_count; ++i) {
            if (ring->data[i].map) {
                bus_dmamap_destroy(0, ring->data[i].map);
                ring->data[i].map = nullptr;
            }
            ring->data[i].m = nullptr;
            ring->data[i].in = nullptr;
        }
        ring->desc = nullptr; ring->cmd = nullptr;
        ring->ring_count = 0; ring->qid = IWX_INVALID_QUEUE;
    }
    int iwx_send_cmd(iwx_softc *, iwx_host_cmd *cmd) {
        ++sendCount; lastCommandId = cmd->id;
        if (cmd->len[0] != 0 && cmd->data[0]) {
            lastCommand.assign(static_cast<const uint8_t *>(cmd->data[0]),
                               static_cast<const uint8_t *>(cmd->data[0]) + cmd->len[0]);
        } else {
            lastCommand.clear();
        }
        auto *packet = new iwx_rx_packet();
        packet->hdr.group_id = responseGroupId;
        int error = sendError;
        if (cmd->id == IWX_TXPATH_FLUSH) {
            ++flushCount;
            lastFlushCommand = lastCommand;
            error = flushError;
            packet->hdr.group_id = flushGroupId;
            packet->payloadLength = flushResponseLength;
            if (flushResponseLength == sizeof(iwx_tx_path_flush_cmd_rsp)) {
                iwx_tx_path_flush_cmd_rsp response{};
                response.sta_id = flushStationId;
                response.num_flushed_queues = flushQueueCount;
                if (flushQueueCount > 0) {
                    response.queues[0].tid = flushTid;
                    response.queues[0].queue_num = flushQueue;
                    response.queues[0].read_before_flush = flushReadBefore;
                    response.queues[0].read_after_flush = flushReadAfter;
                }
                if (flushQueueCount > 1) {
                    response.queues[1].tid = flushSecondTid;
                    response.queues[1].queue_num = flushSecondQueue;
                    response.queues[1].read_before_flush = flushSecondReadBefore;
                    response.queues[1].read_after_flush = flushSecondReadAfter;
                }
                std::memcpy(packet->data, &response, sizeof(response));
                if (generationAfterFlush != 0)
                    com.sc_generation = generationAfterFlush;
            }
        } else if (cmd->id == IWX_SCD_QUEUE_CFG ||
                   cmd->id == IWX_WIDE_ID(IWX_DATA_PATH_GROUP, 0x17)) {
            if (cmd->id == IWX_SCD_QUEUE_CFG)
                lastLegacyQueueCommand = lastCommand;
            packet->payloadLength = responseLength;
            if (responseLength == sizeof(iwx_tx_queue_cfg_rsp)) {
            const iwx_tx_queue_cfg_rsp response{
                responseQueue, responseFlags, responseWritePointer,
                responseReserved};
            std::memcpy(packet->data, &response, sizeof(response));
            }
        } else if (cmd->id == IWX_REMOVE_STA) {
            lastStationRemoveCommand = lastCommand;
            error = stationRemoveError;
            packet->hdr.group_id = stationRemoveGroupId;
            packet->payloadLength = removeStationResponseLength;
            if (removeStationResponseLength == sizeof(iwx_cmd_response)) {
                const iwx_cmd_response response{removeStationStatus};
                std::memcpy(packet->data, &response, sizeof(response));
            }
        } else {
            packet->payloadLength = responseLength;
        }
        cmd->resp_pkt = packet;
        return error;
    }
    void iwx_free_resp(iwx_softc *, iwx_host_cmd *cmd) {
        delete cmd->resp_pkt; cmd->resp_pkt = nullptr;
    }
    int iwx_send_cmd_pdu(iwx_softc *, uint32_t id, uint32_t,
                         uint16_t len, const void *data) {
        ++removeCount; lastCommandId = id;
        if (id == IWX_WIDE_ID(IWX_DATA_PATH_GROUP, 0x17))
            ++queueRemoveCount;
        lastCommand.assign(static_cast<const uint8_t *>(data),
                           static_cast<const uint8_t *>(data) + len);
        return removeError;
    }
    int iwx_send_cmd_pdu_status(iwx_softc *, uint32_t id, uint16_t len,
                                const void *data, uint32_t *status) {
        ++stationCount; lastCommandId = id;
        lastCommand.assign(static_cast<const uint8_t *>(data),
                           static_cast<const uint8_t *>(data) + len);
        if (stationSendError) return stationSendError;
        *status = stationStatus;
        return 0;
    }
};

static void resetFailureInjection() {
    gDmaCalls = gDmaFailAt = gMapCalls = gMapFailAt = 0;
}
static void setupSc(ItlIwx &owner, TahoeP2PStationLease &station,
                    TahoeP2PTxQueueLease &queue) {
    station = {3, static_cast<uint32_t>(owner.com.sc_generation),
               TahoeP2PResourceState::kActive};
    queue.stateLock = owner.nativeP2pTxLock_;
    owner.nativeP2pTxQueue_.stateLock = owner.nativeP2pTxLock_;
    owner.nativeP2pNswqPaused_ = 1;
    for (auto &tid : owner.com.sc_tid_data) tid.qid = IWX_INVALID_QUEUE;
}
static void cleanupPendingRing(ItlIwx &owner, TahoeP2PTxQueueLease &queue) {
    if (!queue.pendingRing) return;
    owner.iwx_free_tx_ring(&owner.com, queue.pendingRing);
    IOFree(queue.pendingRing, sizeof(*queue.pendingRing));
    queue.pendingRing = nullptr;
}
static int allocate(ItlIwx &owner, TahoeP2PStationLease &station,
                    TahoeP2PTxQueueLease &queue, uint16_t *qid,
                    bool *mayExist, uint32_t ringSize = 8) {
    return iwx_tahoe_p2p_tvqm_allocate(&owner, &owner.com, &queue,
                                       &station, ringSize, qid, mayExist);
}
static void fillResponse(ItlIwx &owner, uint16_t qid, uint16_t wp = 3) {
    owner.responseQueue = qid;
    owner.responseWritePointer = wp;
    owner.responseFlags = 0;
    owner.responseReserved = 0;
    owner.responseLength = sizeof(iwx_tx_queue_cfg_rsp);
    owner.responseGroupId = 0;
}
static void installStaticPlaceholder(ItlIwx &owner, uint16_t qid) {
    iwx_tx_ring *ring = &owner.com.txq[qid];
    owner.iwx_tx_ring_init(&owner.com, ring, 8);
    ring->qid = qid;
    assert(owner.iwx_dma_contig_alloc(0, &ring->desc_dma,
        ring->ring_count * sizeof(iwx_tfh_tfd), 256) == 0);
    ring->desc = static_cast<iwx_tfh_tfd *>(ring->desc_dma.vaddr);
    assert(owner.iwx_dma_contig_alloc(0, &ring->bc_tbl,
        sizeof(iwx_gen3_bc_tbl), 0) == 0);
    assert(owner.iwx_dma_contig_alloc(0, &ring->cmd_dma,
        ring->ring_count * sizeof(iwx_device_cmd), 64) == 0);
    ring->cmd = static_cast<iwx_device_cmd *>(ring->cmd_dma.vaddr);
    bus_addr_t paddr = ring->cmd_dma.paddr;
    for (unsigned i = 0; i < ring->ring_count; ++i) {
        ring->data[i].cmd_paddr = paddr;
        paddr += sizeof(iwx_device_cmd);
        assert(bus_dmamap_create(0, 4096, 23, 4096, 0, 0,
                                 &ring->data[i].map) == 0);
    }
    ring->nativeUnsubmittedPlaceholder = 1;
}
static void installDynamicIdleRing(ItlIwx &owner, uint16_t qid) {
    iwx_tx_ring *ring = &owner.com.txq[qid];
    owner.iwx_tx_ring_init(&owner.com, ring, 256);
    ring->qid = qid;
    assert(owner.iwx_dma_contig_alloc(0, &ring->desc_dma,
        ring->ring_count * sizeof(iwx_tfh_tfd), 256) == 0);
    ring->desc = static_cast<iwx_tfh_tfd *>(ring->desc_dma.vaddr);
    assert(owner.iwx_dma_contig_alloc(0, &ring->bc_tbl,
        sizeof(iwx_gen3_bc_tbl), 0) == 0);
    assert(owner.iwx_dma_contig_alloc(0, &ring->cmd_dma,
        ring->ring_count * sizeof(iwx_device_cmd), 64) == 0);
    ring->cmd = static_cast<iwx_device_cmd *>(ring->cmd_dma.vaddr);
    bus_addr_t paddr = ring->cmd_dma.paddr;
    for (unsigned i = 0; i < ring->ring_count; ++i) {
        ring->data[i].cmd_paddr = paddr;
        paddr += sizeof(iwx_device_cmd);
        assert(bus_dmamap_create(0, 4096, 23, 4096, 0, 0,
                                 &ring->data[i].map) == 0);
    }
    ring->cur = ring->tail = 1;
    ring->queued = 0;
    ring->nativeUnsubmittedPlaceholder = 0;
}
static void configureLegacyFirmware(ItlIwx &owner) {
    owner.cmdVersion = IWX_FW_CMD_VER_UNKNOWN;
    owner.legacyQueueCmdVersion = 2;
    owner.legacyQueueNotifVersion = 2;
    owner.flushCmdVersion = 2;
    owner.flushNotifVersion = 1;
    owner.removeStaCmdVersion = 2;
    owner.removeStationResponseLength = 0;
    owner.com.sc_enabled_capa[IWX_UCODE_TLV_CAPA_DQA_SUPPORT / 8] &=
        static_cast<uint8_t>(~(1U << (IWX_UCODE_TLV_CAPA_DQA_SUPPORT % 8)));
}
static void fillFlushResponse(ItlIwx &owner, uint8_t stationId,
                              uint16_t queueId, uint16_t readAfter = 3,
                              uint16_t queueCount = 1) {
    owner.flushStationId = stationId;
    owner.flushQueueCount = queueCount;
    owner.flushTid = IWX_MGMT_TID;
    owner.flushQueue = queueId;
    owner.flushReadBefore = readAfter;
    owner.flushReadAfter = readAfter;
    owner.flushResponseLength = sizeof(iwx_tx_path_flush_cmd_rsp);
    owner.flushGroupId = 0;
}
static void completeOneTx(ItlIwx &owner, TahoeP2PTxQueueLease &queue) {
    iwx_tx_ring *ring = nullptr;
    uint16_t index = 0;
    assert(iwx_tahoe_p2p_tvqm_begin_tx(
        &owner.com, &queue, &ring, &index) == 0);
    assert(ring && ring->cur == index && ring->tail == index);
    ring->data[index].m = reinterpret_cast<void *>(0x1234);
    assert(iwx_tahoe_p2p_tvqm_mark_doorbell(
        &owner.com, &queue, ring, index) == 0);
    ring->queued++;
    ring->cur = (index + 1) % ring->ring_count;
    assert(iwx_tahoe_p2p_tvqm_finish_tx_submit(&queue) == 0);

    IOInterruptState irq = 0;
    assert(iwx_tahoe_p2p_tvqm_lock_completion(
        &owner.com, &queue, static_cast<uint16_t>(ring->qid), &ring, &irq));
    ring->data[index].m = nullptr;
    ring->queued--;
    ring->tail = ring->cur;
    assert(iwx_tahoe_p2p_tvqm_tx_completed_locked(&owner.com, &queue) == 0);
    iwx_tahoe_p2p_tvqm_unlock(&queue, irq);
}
"""

body = r"""
int main() {
    assert(p2pTxEvidenceLowerBoundUsFromNanoseconds(1234) == 1);
    assert(p2pTxEvidenceUpperBoundUsFromNanoseconds(1234) == 2);
    assert(p2pTxEvidenceLowerBoundUsFromNanoseconds(1200) == 1);
    assert(p2pTxEvidenceUpperBoundUsFromNanoseconds(1200) == 2);
    assert(p2pTxEvidenceLowerBoundUsFromNanoseconds(1000) == 1);
    assert(p2pTxEvidenceUpperBoundUsFromNanoseconds(1000) == 1);
    assert(p2pTxEvidenceLowerBoundUsFromNanoseconds(999) == 0);
    assert(p2pTxEvidenceUpperBoundUsFromNanoseconds(999) == 1);
    static_assert(sizeof(iwx_tx_queue_cfg_rsp) == 8, "TVQM response ABI");
    static_assert(sizeof(iwx_tx_queue_cfg_cmd) == 24,
                  "legacy LONG_GROUP/SCD_QUEUE_CFG v2 ABI");

    // Refuse a firmware that advertises DATA_PATH/0x17 until a separately
    // validated modern adapter exists. It must not allocate DMA or issue a
    // command through a partially supported path.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); owner.cmdVersion = 1;
        fillResponse(owner, 2, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) ==
               EOPNOTSUPP);
        assert(!mayExist && queue.state == TahoeP2PResourceState::kAbsent);
        assert(owner.sendCount == 0 && gDmaLive == 0 && gMapLive == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptured") == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderQueueId") == UINT32_MAX);
        assert(owner.controller.property("NativeP2PTxPlaceholderReclaimed") == 0);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // qid 0 is reserved for firmware commands even if the host-side slot is
    // empty. Keep the submitted DMA quarantined when firmware reports it.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 0, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending);
        assert(owner.com.txq[0].ring_count == 0 &&
               owner.com.txq[0].desc == nullptr && queue.pendingRing);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptured") == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderQueueId") == UINT32_MAX);
        assert(owner.controller.property("NativeP2PTxPlaceholderReclaimed") == 0);
        assert(gDmaLive == 3 && gMapLive == 8);
        cleanupPendingRing(owner, queue);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // AX201 fw68 has no DATA_PATH/0x17 entry. Its LONG_GROUP queue API v2
    // accepts the 24-byte enabled queue config and assigns the queue ID.
    // DQA_SUPPORT remains unset; gen2 dynamic queues do not depend on that
    // older static-queue capability bit.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 17, 3); owner.responseFlags = 1;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 17 && mayExist);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptured") == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderQueueId") == UINT32_MAX);
        assert(owner.controller.property("NativeP2PTxPlaceholderReclaimed") == 0);
        assert(queue.lifecycle.snapshot().api ==
               IntelP2PTx::QueueApi::kLegacyDynamicDqa);
        assert(owner.lastCommandId == IWX_SCD_QUEUE_CFG);
        assert(owner.lastLegacyQueueCommand.size() == 24);
        const auto *legacy = reinterpret_cast<const iwx_tx_queue_cfg_cmd *>(
            owner.lastLegacyQueueCommand.data());
        assert(legacy->sta_id == station.stationId);
        assert(legacy->tid == IWX_MGMT_TID);
        assert(owner.controller.property("NativeP2PTxQueueAttempted") == 1);
        assert(owner.controller.property("NativeP2PTxQueueSendResult") == 0);
        assert(owner.controller.property("NativeP2PTxQueueResponseValid") == 1);
        // flags is retained as raw telemetry; qid/wp and ownership decide
        // whether the response can be safely installed.
        assert(owner.controller.property("NativeP2PTxQueueResponseFlags") == 1);
        assert(owner.controller.property("NativeP2PTxQueueParseResult") == 0);
        assert(owner.controller.property("NativeP2PTxQueueResponseId") == 17);
        assert(owner.controller.property("NativeP2PTxQueueWritePointer") == 3);
        assert(owner.controller.property("NativeP2PTxQueueFirmwareTid") == IWX_MGMT_TID);
        assert(owner.controller.property("NativeP2PTxQueueCommandVersion") == 2);
        assert(owner.controller.property("NativeP2PTxQueueNotificationVersion") == 2);
        assert(le16toh(legacy->flags) == IWX_TX_QUEUE_CFG_ENABLE_QUEUE);
        assert(le32toh(legacy->cb_size) == 0); // 8 descriptors => exponent 0
        assert(le64toh(legacy->byte_cnt_addr) == owner.com.txq[qid].bc_tbl.paddr);
        assert(le64toh(legacy->tfdq_addr) == owner.com.txq[qid].desc_dma.paddr);

        completeOneTx(owner, queue);
        fillFlushResponse(owner, station.stationId, qid, 4);
        assert(iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(mayExist && station.state == TahoeP2PResourceState::kAbsent);
        assert(queue.state == TahoeP2PResourceState::kRemoving);
        assert(owner.flushCount == 1 && owner.removeCount == 0 &&
               owner.queueRemoveCount == 0);
        assert(owner.lastFlushCommand.size() == sizeof(iwx_tx_path_flush_cmd));
        const auto *flush = reinterpret_cast<const iwx_tx_path_flush_cmd *>(
            owner.lastFlushCommand.data());
        assert(le32toh(flush->sta_id) == station.stationId);
        assert(le16toh(flush->tid_mask) == 0xffff);
        assert(owner.lastStationRemoveCommand.size() == sizeof(iwx_rm_sta_cmd));
        const auto *removed = reinterpret_cast<const iwx_rm_sta_cmd *>(
            owner.lastStationRemoveCommand.data());
        assert(removed->sta_id == station.stationId);
        assert(gDmaLive == 3 && gMapLive == 8); // retained through station ACK

        assert(iwx_tahoe_p2p_tvqm_confirm_drained(
            &owner, &owner.com, &queue, &mayExist) == 0);
        assert(!mayExist && queue.state == TahoeP2PResourceState::kAbsent);
        assert(gDmaLive == 0 && gMapLive == 0);
        assert(iwx_tahoe_p2p_remove_broadcast_station(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(!mayExist && owner.removeCount == 0);
    }

    // A firmware-assigned qid may reclaim only the complete attach-time
    // placeholder whose positive unsubmitted proof was captured before the
    // command. The old DMA/maps are freed once, after the slot swap.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, 2);
        fillResponse(owner, 2, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 2 && mayExist && queue.state == TahoeP2PResourceState::kActive);
        assert(owner.com.txq[2].nativeUnsubmittedPlaceholder == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptured") == 1);
        assert(owner.controller.property("NativeP2PTxPlaceholderQueueId") == 2);
        assert(owner.controller.property("NativeP2PTxPlaceholderReclaimed") == 1);
        assert(owner.com.txq[2].ring_count == 8 && gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[2]);
        assert(gDmaLive == 0 && gMapLive == 0);
    }

    // A valid response assigning a different qid preserves the exact
    // placeholder proof, allowing a later, separate qid-2 allocation.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, 2);
        fillResponse(owner, 17, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 17 && mayExist && queue.state == TahoeP2PResourceState::kActive);
        assert(owner.com.txq[2].nativeUnsubmittedPlaceholder == 1);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptured") == 1);
        assert(owner.controller.property("NativeP2PTxPlaceholderQueueId") == 2);
        assert(owner.controller.property("NativeP2PTxPlaceholderReclaimed") == 0);
        assert(owner.com.txq[2].ring_count == 8 && gDmaLive == 6 && gMapLive == 16);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[17]);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[2]);
        assert(gDmaLive == 0 && gMapLive == 0);
    }

    // An ambiguous command permanently consumes the old proof. Resetting the
    // old host ring cannot recreate it; the newly submitted DMA stays retained.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, 2);
        fillResponse(owner, 2, 3); owner.sendError = ETIMEDOUT;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == ETIMEDOUT);
        assert(mayExist && queue.state == TahoeP2PResourceState::kUnknown);
        assert(owner.com.txq[2].nativeUnsubmittedPlaceholder == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptured") == 1);
        assert(owner.controller.property("NativeP2PTxPlaceholderQueueId") == 2);
        assert(owner.controller.property("NativeP2PTxPlaceholderReclaimed") == 0);
        assert(queue.pendingRing && gDmaLive == 6 && gMapLive == 16);
        owner.iwx_reset_tx_ring(&owner.com, &owner.com.txq[2]);
        assert(owner.com.txq[2].nativeUnsubmittedPlaceholder == 0);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[2]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // An incomplete attach ring is not positive ownership proof. The
    // conflicting slot and submitted DMA are both retained as unknown.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, 2);
        bus_dmamap_destroy(0, owner.com.txq[2].data[5].map);
        owner.com.txq[2].data[5].map = nullptr;
        fillResponse(owner, 2, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending);
        assert(owner.com.txq[2].ring_count == 8 &&
               owner.com.txq[2].nativeUnsubmittedPlaceholder == 0);
        assert(queue.pendingRing && gDmaLive == 6 && gMapLive == 15);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[2]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // STA ownership blocks placeholder takeover even if the qid is reported
    // by firmware. Both the existing host slot and new unknown DMA survive.
    for (unsigned ownerKind : {0U, 1U}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, 2);
        if (ownerKind == 0)
            owner.com.first_data_qid = 2;
        else
            owner.com.sc_tid_data[3].qid = 2;
        fillResponse(owner, 2, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending);
        assert(owner.com.txq[2].ring_count == 8 &&
               owner.com.txq[2].nativeUnsubmittedPlaceholder == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptureFailureMask") ==
               (1U << 2));
        assert(queue.pendingRing && gDmaLive == 6 && gMapLive == 16);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[2]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // A valid firmware response that selects an already-owned STA qid must
    // be diagnosed after dropping the lease spinlock and must preserve both
    // the existing host ring and the unresolved P2P DMA allocation.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, IWX_DQA_P2P_DEVICE_QUEUE);
        owner.com.first_data_qid = 1;
        owner.com.sc_tid_data[3].qid = 3;
        owner.com.qfullmsk |= (1U << 3);
        iwx_tx_ring &hostOwned = owner.com.txq[3];
        hostOwned.qid = 3;
        hostOwned.ring_count = 8;
        hostOwned.queued = 2;
        hostOwned.cur = 5;
        hostOwned.tail = 3;
        hostOwned.desc = reinterpret_cast<iwx_tfh_tfd *>(uintptr_t(1));
        hostOwned.cmd = reinterpret_cast<iwx_device_cmd *>(uintptr_t(1));
        hostOwned.desc_dma.vaddr = reinterpret_cast<void *>(uintptr_t(1));
        hostOwned.desc_dma.paddr = 1;
        hostOwned.desc_dma.size = 1;
        hostOwned.cmd_dma.vaddr = reinterpret_cast<void *>(uintptr_t(1));
        hostOwned.cmd_dma.paddr = 1;
        hostOwned.cmd_dma.size = 1;
        hostOwned.bc_tbl.vaddr = reinterpret_cast<void *>(uintptr_t(1));
        hostOwned.bc_tbl.paddr = 1;
        hostOwned.bc_tbl.size = 1;
        hostOwned.data[5].map = reinterpret_cast<void *>(uintptr_t(1));
        hostOwned.data[6].m = reinterpret_cast<void *>(uintptr_t(1));
        fillResponse(owner, 3, 0);
        owner.responseFlags = 1; // Telemetry only; not an allocation verdict.
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending);
        assert(queue.pendingRing && queue.queueId == 3);
        assert(owner.com.txq[3].ring_count == 8 &&
               owner.com.txq[3].queued == 2 &&
               owner.com.txq[3].cur == 5 &&
               owner.com.txq[3].tail == 3);
        assert(owner.com.txq[2].ring_count == 8 &&
               owner.com.txq[2].nativeUnsubmittedPlaceholder == 0);
        assert(owner.controller.property("NativeP2PTxHostSnapshotValid") == 1);
        assert(owner.controller.property("NativeP2PTxFirmwareQueueId") == 3);
        assert(owner.controller.property("NativeP2PTxHostSlotRejectMask") ==
               ((1U << 3) | (1U << 4) | (1U << 5) | (1U << 6) |
                (1U << 7) | (1U << 8) | (1U << 9) | (1U << 10) |
                (1U << 11) | (1U << 12)));
        assert(owner.controller.property("NativeP2PTxHostRingQueueId") == 3);
        assert(owner.controller.property("NativeP2PTxHostRingCount") == 8);
        assert(owner.controller.property("NativeP2PTxHostRingQueued") == 2);
        assert(owner.controller.property("NativeP2PTxHostRingCur") == 5);
        assert(owner.controller.property("NativeP2PTxHostRingTail") == 3);
        assert(owner.controller.property("NativeP2PTxHostDescriptorPresent") == 1);
        assert(owner.controller.property("NativeP2PTxHostCommandPresent") == 1);
        assert(owner.controller.property("NativeP2PTxHostDmaPresenceMask") == 7);
        assert(owner.controller.property("NativeP2PTxFirstDataQueue") == 1);
        assert(owner.controller.property("NativeP2PTxHostQueueFullBit") == 1);
        assert(owner.controller.property("NativeP2PTxHostQueueFullPredicateReject") == 1);
        assert(owner.controller.property("NativeP2PTxHostTidMatchBitmap") ==
               (1U << 3));
        assert(owner.controller.property("NativeP2PTxHostDataMapCount") == 1);
        assert(owner.controller.property("NativeP2PTxHostDataOwnerCount") == 1);
        assert(owner.controller.property("NativeP2PTxHostStaticPlaceholderProof") == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderStaticProof") == 1);
        assert(owner.controller.property("NativeP2PTxPlaceholderCaptureFailureMask") == 0);
        assert(owner.controller.property("NativeP2PTxPlaceholderHostRejectMask") != 0);
        assert(gDmaLive == 6 && gMapLive == 16);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com,
                               &owner.com.txq[IWX_DQA_P2P_DEVICE_QUEUE]);
        std::memset(&owner.com.txq[3], 0, sizeof(owner.com.txq[3]));
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // Test054 pilot: qid 3's complete but unowned dynamic ring is parked only
    // after the firmware reports the new station-3/TID-15/qid-3 mapping with
    // both read pointers equal to the allocation write pointer (zero). Flags
    // remain telemetry (flags=1 is accepted); the old ring's DMA is untouched
    // until an explicit master-disable plus SW_RESET proof is supplied.
    {
        ItlIwx owner; TahoeP2PStationLease station{};
        TahoeP2PTxQueueLease &queue = owner.nativeP2pTxQueue_;
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installDynamicIdleRing(owner, 3);
        iwx_tx_ring &oldSlot = owner.com.txq[3];
        void *oldDesc = oldSlot.desc_dma.vaddr;
        void *oldCmd = oldSlot.cmd_dma.vaddr;
        void *oldBc = oldSlot.bc_tbl.vaddr;
        static_cast<uint8_t *>(oldDesc)[0] = 0xa5;
        static_cast<uint8_t *>(oldCmd)[0] = 0x5a;
        static_cast<uint8_t *>(oldBc)[0] = 0xc3;
        fillResponse(owner, 3, 0);
        owner.responseFlags = 1;
        fillFlushResponse(owner, station.stationId, 3, 0, 1);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 3 && mayExist && queue.state == TahoeP2PResourceState::kActive);
        assert(owner.flushCount == 1 && queue.retainedRing != nullptr);
        assert(queue.retainedRing->qid == 3 &&
               queue.retainedRing->ring_count == 256 &&
               queue.retainedRing->cur == 1 && queue.retainedRing->tail == 1 &&
               queue.retainedRing->queued == 0);
        assert(queue.retainedRing->desc_dma.vaddr == oldDesc &&
               queue.retainedRing->cmd_dma.vaddr == oldCmd &&
               queue.retainedRing->bc_tbl.vaddr == oldBc);
        assert(static_cast<uint8_t *>(oldDesc)[0] == 0xa5 &&
               static_cast<uint8_t *>(oldCmd)[0] == 0x5a &&
               static_cast<uint8_t *>(oldBc)[0] == 0xc3);
        assert(owner.com.txq[3].ring_count == 8 &&
               owner.com.txq[3].desc_dma.vaddr != oldDesc &&
               owner.com.txq[3].cmd_dma.vaddr != oldCmd);
        assert(owner.controller.property("NativeP2PTxQueueResponseFlags") == 1);
        assert(owner.controller.property("NativeP2PTxQueueReserved") == 0);
        assert(owner.controller.property("NativeP2PTxRebindFlushAttempted") == 1);
        assert(owner.controller.property("NativeP2PTxRebindFlushValid") == 1);
        assert(owner.controller.property("NativeP2PTxRebindFlushStationId") == 3);
        assert(owner.controller.property("NativeP2PTxRebindFlushQueueCount") == 1);
        assert(owner.controller.property("NativeP2PTxRebindFlushTid") == IWX_MGMT_TID);
        assert(owner.controller.property("NativeP2PTxRebindFlushQueueId") == 3);
        assert(owner.controller.property("NativeP2PTxRebindFlushReadBefore") == 0);
        assert(owner.controller.property("NativeP2PTxRebindFlushReadAfter") == 0);
        assert(owner.controller.property("NativeP2PTxRetainedRingCount") == 1);
        assert(owner.controller.property("NativeP2PTxRetainedRingQueueId") == 3);
        assert(owner.controller.property("NativeP2PTxRetainedRingCursor") == 1);
        assert(gDmaLive == 6 && gMapLive == 264 && gLiveIoObjects == 1);

        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[3]);
        std::memset(&owner.com.txq[3], 0, sizeof(iwx_tx_ring));
        assert(gDmaLive == 3 && gMapLive == 256 && gLiveIoObjects == 1);
        assert(iwx_tahoe_p2p_tvqm_release_retained_after_master_disabled(
            &owner, &owner.com, false, true) == EBUSY);
        assert(iwx_tahoe_p2p_tvqm_release_retained_after_master_disabled(
            &owner, &owner.com, true, false) == EBUSY);
        assert(queue.retainedRing != nullptr && gDmaLive == 3 && gMapLive == 256);
        assert(iwx_tahoe_p2p_tvqm_release_retained_after_master_disabled(
            &owner, &owner.com, true, true) == 0);
        assert(queue.retainedRing == nullptr &&
               owner.controller.property("NativeP2PTxRetainedRingCount") == 0);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // Dynamic parking is denied for any host owner, cursor/queue activity,
    // incomplete mapping, or generation change. Each failure keeps both DMA
    // sides alive and never calls TXPATH_FLUSH unless the full snapshot fit.
    for (unsigned mutation : {0U, 1U, 2U, 3U, 4U, 5U, 6U}) {
        ItlIwx owner; TahoeP2PStationLease station{};
        TahoeP2PTxQueueLease &queue = owner.nativeP2pTxQueue_;
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installDynamicIdleRing(owner, 3);
        iwx_tx_ring &oldSlot = owner.com.txq[3];
        void *oldDesc = oldSlot.desc_dma.vaddr;
        if (mutation == 0) owner.com.first_data_qid = 3;
        if (mutation == 1) owner.com.sc_tid_data[4].qid = 3;
        if (mutation == 2) owner.com.qfullmsk |= (1U << 3);
        if (mutation == 3) oldSlot.queued = 1;
        if (mutation == 4) oldSlot.cur = oldSlot.tail = 2;
        if (mutation == 5) oldSlot.data[7].m = reinterpret_cast<void *>(1);
        if (mutation == 6) {
            bus_dmamap_destroy(0, oldSlot.data[7].map);
            oldSlot.data[7].map = nullptr;
        }
        fillResponse(owner, 3, 0);
        fillFlushResponse(owner, station.stationId, 3, 0, 1);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending &&
               queue.pendingRing && queue.retainedRing == nullptr);
        assert(owner.com.txq[3].desc_dma.vaddr == oldDesc);
        assert(owner.controller.property("NativeP2PTxRetainedRingCount") == 0);
        if (mutation == 0 || mutation == 1 || mutation == 2 || mutation == 5 ||
            mutation == 6)
            assert(owner.flushCount == 0);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[3]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // The flush witness rejects empty/multiple rows, a different station/TID/
    // qid, either pointer mismatch, a nonzero response reserved word, and an
    // epoch change after the response. No case may overwrite qid 3.
    for (unsigned failure : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U}) {
        ItlIwx owner; TahoeP2PStationLease station{};
        TahoeP2PTxQueueLease &queue = owner.nativeP2pTxQueue_;
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installDynamicIdleRing(owner, 3);
        void *oldDesc = owner.com.txq[3].desc_dma.vaddr;
        fillResponse(owner, 3, 0);
        fillFlushResponse(owner, station.stationId, 3, 0, 1);
        if (failure == 0) owner.flushQueueCount = 0;
        if (failure == 1) owner.flushQueueCount = 2;
        if (failure == 2) owner.flushStationId = 4;
        if (failure == 3) owner.flushTid = 14;
        if (failure == 4) owner.flushQueue = 4;
        if (failure == 5) owner.flushReadBefore = 1;
        if (failure == 6) owner.flushReadAfter = 1;
        if (failure == 7) owner.generationAfterFlush = 42;
        if (failure == 8) owner.responseReserved = 1;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) != 0);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending &&
               queue.pendingRing && queue.retainedRing == nullptr);
        assert(owner.com.txq[3].desc_dma.vaddr == oldDesc);
        assert(owner.controller.property("NativeP2PTxRetainedRingCount") == 0);
        if (failure == 8) // Reserved word is rejected before the flush witness.
            assert(owner.flushCount == 0 &&
                   owner.controller.property("NativeP2PTxQueueReserved") == 1);
        else
            assert(owner.flushCount == 1);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[3]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // A failed witness uses the dedicated no-TX abort: the pending P2P ring
    // survives until station flush + REMOVE_STA ACK; the colliding STA ring is
    // never reset or released by that cleanup.
    {
        ItlIwx owner; TahoeP2PStationLease station{};
        TahoeP2PTxQueueLease &queue = owner.nativeP2pTxQueue_;
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installDynamicIdleRing(owner, 3);
        void *oldDesc = owner.com.txq[3].desc_dma.vaddr;
        fillResponse(owner, 3, 0);
        fillFlushResponse(owner, station.stationId, 3, 0, 0);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EIO);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending);
        assert(owner.flushCount == 1 && owner.removeCount == 0);

        fillFlushResponse(owner, station.stationId, 3, 0, 0);
        assert(iwx_tahoe_p2p_tvqm_abort_unsubmitted(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(!mayExist && station.state == TahoeP2PResourceState::kAbsent &&
               queue.state == TahoeP2PResourceState::kAbsent &&
               queue.pendingRing == nullptr && queue.retainedRing == nullptr);
        assert(owner.flushCount == 2 && owner.sendCount == 4 &&
               owner.removeCount == 0);
        assert(owner.com.txq[3].desc_dma.vaddr == oldDesc &&
               owner.com.txq[3].ring_count == 256);
        assert(gDmaLive == 3 && gMapLive == 256);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[3]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // Failed station removal retains the pending P2P ring and marks both
    // station and queue unknown instead of freeing DMA without an ACK.
    {
        ItlIwx owner; TahoeP2PStationLease station{};
        TahoeP2PTxQueueLease &queue = owner.nativeP2pTxQueue_;
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 18, 0);
        owner.responseReserved = 1;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EIO);
        assert(queue.state == TahoeP2PResourceState::kPending && queue.pendingRing);
        owner.flushQueueCount = 0;
        owner.stationRemoveError = ETIMEDOUT;
        assert(iwx_tahoe_p2p_tvqm_abort_unsubmitted(
            &owner, &owner.com, &station, &queue, &mayExist) == ETIMEDOUT);
        assert(mayExist && station.state == TahoeP2PResourceState::kUnknown &&
               queue.state == TahoeP2PResourceState::kUnknown &&
               queue.pendingRing != nullptr);
        assert(gDmaLive == 3 && gMapLive == 8);
        cleanupPendingRing(owner, queue);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // qid 31 is intentionally excluded by the production qfull predicate.
    // Report the raw bit and the predicate result separately without changing
    // the allocator's existing admission behavior.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, 31, 0);
        owner.com.qfullmsk |= (1U << 31);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 31 && mayExist);
        assert(owner.controller.property("NativeP2PTxHostQueueFullBit") == 1);
        assert(owner.controller.property("NativeP2PTxHostQueueFullPredicateReject") == 0);
        assert((owner.controller.property("NativeP2PTxHostSlotRejectMask") &
                (1U << 3)) == 0);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[31]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // The old path refuses to send flush/remove or free the ring without a
    // genuine TX completion, even when the software ring looks empty.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 19, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist) == EBUSY);
        assert(mayExist && owner.flushCount == 0 && owner.removeCount == 0);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // A flush timeout or mismatched station/TID/queue response blocks the
    // subsequent REMOVE_STA and preserves every DMA mapping.
    for (int failure : {ETIMEDOUT, EIO}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 20, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        completeOneTx(owner, queue);
        fillFlushResponse(owner, station.stationId,
                          failure == EIO ? qid + 1 : qid, 4);
        if (failure == ETIMEDOUT)
            owner.flushError = ETIMEDOUT;
        assert(iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist) ==
            (failure == ETIMEDOUT ? ETIMEDOUT : EIO));
        assert(mayExist && station.state == TahoeP2PResourceState::kActive);
        assert(owner.flushCount == 1 && owner.removeCount == 0);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // Official flush handling accepts a valid zero-queue response for an
    // already-empty station. Completion, station ACK, and retained-ring
    // verification still gate release.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 22, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        completeOneTx(owner, queue);
        fillFlushResponse(owner, station.stationId, qid, 0, 0);
        assert(iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(mayExist && station.state == TahoeP2PResourceState::kAbsent);
        assert(gDmaLive == 3 && gMapLive == 8);
        assert(iwx_tahoe_p2p_tvqm_confirm_drained(
            &owner, &owner.com, &queue, &mayExist) == 0);
        assert(!mayExist && gDmaLive == 0 && gMapLive == 0);
    }

    // REMOVE_STA timeout, failed response, nonzero generic status, and
    // malformed payload each leave both station and queue quarantined.
    for (unsigned failureMode : {0U, 1U, 2U, 3U}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 21, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        completeOneTx(owner, queue);
        fillFlushResponse(owner, station.stationId, qid, 4);
        if (failureMode == 0) {
            owner.stationRemoveError = ETIMEDOUT;
        } else if (failureMode == 1) {
            owner.stationRemoveGroupId = IWX_CMD_FAILED_MSK;
        } else if (failureMode == 2) {
            owner.removeStationResponseLength = sizeof(iwx_cmd_response);
            owner.removeStationStatus = 1;
        } else {
            owner.removeStationResponseLength = 2;
        }
        const int error = iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist);
        assert(error == (failureMode == 0 ? ETIMEDOUT : EIO));
        assert(mayExist && station.state == TahoeP2PResourceState::kUnknown);
        assert(queue.state == TahoeP2PResourceState::kUnknown);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // A queue with no actual TX completion never enters the legacy flush and
    // station-removal path. Even a software-empty ring retains its DMA.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, 39, 0);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 39);
        assert(iwx_tahoe_p2p_tvqm_remove(&owner, &owner.com, &station,
                                          &queue, &mayExist) == EBUSY);
        assert(mayExist && owner.flushCount == 0 && owner.removeCount == 0);
        assert(queue.state == TahoeP2PResourceState::kActive);
        assert(iwx_tahoe_p2p_tvqm_confirm_drained(
            &owner, &owner.com, &queue, &mayExist) == EBUSY);
        assert(mayExist && owner.com.txq[39].ring_count == 8);
        assert(gDmaLive == 3 && gMapLive == 8);
        cleanupPendingRing(owner, queue);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[39]);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // A confirmed ROC END plus a positive no-ticket snapshot can release an
    // installed, never-doorbelled ring after exact flush and REMOVE_STA ACKs.
    // A displaced host ring remains mapped and byte-for-byte owned.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        installStaticPlaceholder(owner, 3);
        auto *retained = static_cast<iwx_tx_ring *>(IOMalloc(sizeof(iwx_tx_ring)));
        assert(retained);
        std::memcpy(retained, &owner.com.txq[3], sizeof(*retained));
        queue.retainedRing = retained;
        queue.retainedRingGeneration = owner.com.sc_generation;
        queue.retainedRingQueueId = 3;
        const void *oldDesc = retained->desc_dma.vaddr;
        const void *oldCmd = retained->cmd_dma.vaddr;
        const void *oldBc = retained->bc_tbl.vaddr;
        fillResponse(owner, 50, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(queue.everDoorbelled == false && owner.com.txq[qid].cur == 3);
        fillFlushResponse(owner, station.stationId, qid, 3, 1);
        assert(iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            &owner, &owner.com, &station, &queue, true, true, &mayExist) == 0);
        assert(!mayExist && station.state == TahoeP2PResourceState::kAbsent);
        assert(queue.state == TahoeP2PResourceState::kAbsent &&
               queue.queueId == IWX_INVALID_QUEUE && !queue.everDoorbelled);
        assert(owner.flushCount == 1 && owner.lastCommandId == IWX_REMOVE_STA);
        assert(owner.lastFlushCommand.size() == sizeof(iwx_tx_path_flush_cmd));
        assert(queue.retainedRing == retained &&
               retained->desc_dma.vaddr == oldDesc &&
               retained->cmd_dma.vaddr == oldCmd &&
               retained->bc_tbl.vaddr == oldBc);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[3]);
        std::memset(&owner.com.txq[3], 0, sizeof(iwx_tx_ring));
        IOFree(retained, sizeof(*retained));
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // END proof and positive no-ticket proof are mandatory and do not issue
    // commands when absent. The installed queue and all DMA remain live.
    for (unsigned missingProof : {0U, 1U}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 51 + missingProof, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        fillFlushResponse(owner, station.stationId, qid, 3, 1);
        assert(iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            &owner, &owner.com, &station, &queue,
            missingProof != 0, missingProof == 0, &mayExist) == EBUSY);
        assert(mayExist && owner.flushCount == 0 && owner.sendCount == 1);
        assert(queue.state == TahoeP2PResourceState::kActive &&
               station.state == TahoeP2PResourceState::kActive);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // A live submission or a marked doorbell makes the new path ineligible,
    // even if a later TX completion leaves the software ring empty.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 53, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        iwx_tx_ring *ring = nullptr; uint16_t index = 0;
        assert(iwx_tahoe_p2p_tvqm_begin_tx(
            &owner.com, &queue, &ring, &index) == 0);
        ring->data[index].m = reinterpret_cast<void *>(0x1234);
        assert(iwx_tahoe_p2p_tvqm_mark_doorbell(
            &owner.com, &queue, ring, index) == 0);
        ring->queued++;
        ring->cur = (index + 1) % ring->ring_count;
        assert(iwx_tahoe_p2p_tvqm_finish_tx_submit(&queue) == 0);
        IOInterruptState irq = 0;
        assert(iwx_tahoe_p2p_tvqm_lock_completion(
            &owner.com, &queue, qid, &ring, &irq));
        ring->data[index].m = nullptr;
        ring->queued--;
        ring->tail = ring->cur;
        assert(iwx_tahoe_p2p_tvqm_tx_completed_locked(
            &owner.com, &queue) == 0);
        iwx_tahoe_p2p_tvqm_unlock(&queue, irq);
        fillFlushResponse(owner, station.stationId, qid, ring->cur, 1);
        assert(iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            &owner, &owner.com, &station, &queue, true, true, &mayExist) ==
            EBUSY);
        assert(mayExist && queue.everDoorbelled && owner.flushCount == 0);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // Outstanding reservation and software cursors that no longer match the
    // allocation's firmware write pointer are rejected before any command.
    for (unsigned mutation : {0U, 1U}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 54 + mutation, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        if (mutation == 0) {
            iwx_tx_ring *ring = nullptr; uint16_t index = 0;
            assert(iwx_tahoe_p2p_tvqm_begin_tx(
                &owner.com, &queue, &ring, &index) == 0);
        } else {
            owner.com.txq[qid].cur = owner.com.txq[qid].tail = 4;
        }
        fillFlushResponse(owner, station.stationId, qid, 3, 1);
        assert(iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            &owner, &owner.com, &station, &queue, true, true, &mayExist) ==
            EBUSY);
        assert(mayExist && owner.flushCount == 0 && owner.sendCount == 1);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // A wrong queue, zero-queue flush, flush error, or REMOVE_STA error is an
    // ambiguous firmware result. Keep DMA and quarantine station + queue.
    for (unsigned failure : {0U, 1U, 2U, 3U}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 56 + failure, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        if (failure == 0)
            fillFlushResponse(owner, station.stationId, qid + 1, 3, 1);
        else if (failure == 2)
            fillFlushResponse(owner, station.stationId, qid, 3, 0);
        else
            fillFlushResponse(owner, station.stationId, qid, 3, 1);
        if (failure == 1)
            owner.flushError = ETIMEDOUT;
        if (failure == 3)
            owner.stationRemoveError = ETIMEDOUT;
        const int expected = failure == 1 || failure == 3 ? ETIMEDOUT : EIO;
        assert(iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            &owner, &owner.com, &station, &queue, true, true, &mayExist) ==
            expected);
        assert(mayExist && station.state == TahoeP2PResourceState::kUnknown &&
               queue.state == TahoeP2PResourceState::kUnknown);
        assert(owner.flushCount == 1);
        assert(owner.removeCount == 0);
        if (failure == 3)
            assert(owner.lastCommandId == IWX_REMOVE_STA);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // Wrong generation must be rejected before TXPATH_FLUSH and retain DMA.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 60, 3);
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        fillFlushResponse(owner, station.stationId, qid, 3, 1);
        ++owner.com.sc_generation;
        assert(iwx_tahoe_p2p_tvqm_abort_idle_after_end(
            &owner, &owner.com, &station, &queue, true, true, &mayExist) ==
            ESTALE);
        assert(mayExist && owner.flushCount == 0 && owner.sendCount == 1);
        assert(gDmaLive == 3 && gMapLive == 8);
        owner.iwx_free_tx_ring(&owner.com, &owner.com.txq[qid]);
        std::memset(&owner.com.txq[qid], 0, sizeof(iwx_tx_ring));
    }

    // Unknown allocation outcomes retain their pending DMA backing.
    for (int failure : {ETIMEDOUT, EIO}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, 40, 0);
        owner.sendError = failure;
        if (failure == EIO) owner.responseLength = 4;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == failure);
        assert(mayExist && queue.state == TahoeP2PResourceState::kUnknown);
        assert(queue.pendingRing && gDmaLive == 3 && gMapLive == 8);
        assert(iwx_tahoe_p2p_tvqm_may_exist(&queue));
        assert(iwx_tahoe_p2p_tvqm_confirm_drained(
            &owner, &owner.com, &queue, &mayExist) == EBUSY);
        cleanupPendingRing(owner, queue);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // Nonzero response flags alone do not reject a well-formed queue response.
    // Invalid qid, local ownership collision, or impossible write pointer is
    // ambiguous and must retain DMA instead of freeing a possibly live ring.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 18, 5); owner.responseFlags = 1;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 18 && mayExist && queue.state == TahoeP2PResourceState::kActive);
        assert(owner.controller.property("NativeP2PTxQueueResponseValid") == 1);
        assert(owner.controller.property("NativeP2PTxQueueResponseFlags") == 1);
        assert(owner.controller.property("NativeP2PTxHostSnapshotValid") == 1);
        assert(owner.controller.property("NativeP2PTxHostSlotRejectMask") == 0);
        assert(owner.controller.property("NativeP2PTxHostRingCount") == 0);
        assert(owner.controller.property("NativeP2PTxHostTidMatchBitmap") == 0);
        assert(owner.controller.property("NativeP2PTxHostDataMapCount") == 0);
        assert(owner.controller.property("NativeP2PTxHostDataOwnerCount") == 0);
        assert(gDmaLive == 3 && gMapLive == 8);
        completeOneTx(owner, queue);
        fillFlushResponse(owner, station.stationId, qid, 6);
        assert(iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(mayExist && queue.state == TahoeP2PResourceState::kRemoving);
        assert(gDmaLive == 3 && gMapLive == 8);
        assert(iwx_tahoe_p2p_tvqm_confirm_drained(
            &owner, &owner.com, &queue, &mayExist) == 0);
        assert(!mayExist && queue.state == TahoeP2PResourceState::kAbsent);
        assert(gDmaLive == 0 && gMapLive == 0);
    }
    for (uint16_t invalid : {uint16_t(512), uint16_t(2)}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, invalid, 0);
        owner.responseFlags = 1;
        if (invalid == 2) owner.com.sc_tid_data[3].qid = 2;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.state == TahoeP2PResourceState::kPending);
        assert(queue.pendingRing && queue.queueId == invalid);
        assert(owner.com.txq[2].ring_count == 0); // never overwrite a collision
        cleanupPendingRing(owner, queue);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, 44, 8);
        owner.responseFlags = 1;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EBUSY);
        assert(mayExist && queue.pendingRing && queue.queueId == 44);
        cleanupPendingRing(owner, queue);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // Partial DMA and per-descriptor map allocation failures clean every
    // resource created before the failure, including the outer IOMalloc.
    for (unsigned failAt : {1U, 2U, 3U}) {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, 5, 0);
        resetFailureInjection(); gDmaFailAt = failAt;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == ENOMEM);
        assert(!mayExist && queue.state == TahoeP2PResourceState::kAbsent);
        assert(owner.controller.property("NativeP2PTxQueueAttempted") == 0);
        assert(owner.controller.property("NativeP2PTxQueueResponseValid") == 0);
        assert(owner.controller.property("NativeP2PTxDmaFailurePhase") == failAt + 2);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); fillResponse(owner, 5, 0);
        resetFailureInjection(); gMapFailAt = 4;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == ENOMEM);
        assert(!mayExist && queue.state == TahoeP2PResourceState::kAbsent);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    // Station status and ambiguous command results are independently checked.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue);
        bool mayExist = false;
        assert(iwx_tahoe_p2p_remove_broadcast_station(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(!mayExist && station.state == TahoeP2PResourceState::kAbsent);
        assert(owner.sendCount == 1 && owner.removeCount == 0);
        assert(iwx_tahoe_p2p_remove_broadcast_station(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(owner.sendCount == 1); // absent+queue absent is idempotent
    }
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); station.state = TahoeP2PResourceState::kAbsent;
        bool mayExist = false;
        owner.stationStatus = IWX_ADD_STA_SUCCESS;
        owner.com.sc_ucode_api[IWX_UCODE_TLV_API_STA_TYPE / 8] |=
            static_cast<uint8_t>(1U << (IWX_UCODE_TLV_API_STA_TYPE % 8));
        assert(iwx_tahoe_p2p_add_broadcast_station(
            &owner, &owner.com, &station, 3, &mayExist) == 0);
        assert(owner.controller.property("NativeP2PTxAddStaAttempted") == 1);
        assert(owner.controller.property("NativeP2PTxAddStaId") == 3);
        assert(owner.controller.property("NativeP2PTxAddStaMacIdColor") == 0);
        assert(owner.controller.property("NativeP2PTxAddStaType") ==
               IWX_STA_GENERAL_PURPOSE);
        assert(owner.controller.property("NativeP2PTxAddStaTypeApi") == 1);
        assert(owner.controller.property("NativeP2PTxAddStaCommandLength") ==
               sizeof(iwx_add_sta_cmd));
        assert(owner.controller.property("NativeP2PTxAddStaCommandVersion") == 12);
        assert(owner.controller.property("NativeP2PTxAddStaNotificationVersion") == 2);
        assert(owner.controller.property("NativeP2PTxAddStaStatusValid") == 1);
        assert(owner.controller.property("NativeP2PTxAddStaFirmwareStatus") ==
               IWX_ADD_STA_SUCCESS);
        assert(mayExist && station.state == TahoeP2PResourceState::kActive);
        owner.stationRemoveError = ETIMEDOUT;
        assert(iwx_tahoe_p2p_remove_broadcast_station(
            &owner, &owner.com, &station, &queue, &mayExist) == ETIMEDOUT);
        assert(mayExist && station.state == TahoeP2PResourceState::kUnknown);
        assert(owner.removeCount == 0 && owner.sendCount == 1);
    }
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); station.state = TahoeP2PResourceState::kAbsent;
        bool mayExist = false;
        owner.stationStatus = 2;
        assert(iwx_tahoe_p2p_add_broadcast_station(
            &owner, &owner.com, &station, 3, &mayExist) == EIO);
        assert(owner.controller.property("NativeP2PTxAddStaStatusValid") == 1);
        assert(owner.controller.property("NativeP2PTxAddStaFirmwareStatus") == 2);
        assert(owner.controller.property("NativeP2PTxAddStaSendResult") == 0);
        assert(!mayExist && station.state == TahoeP2PResourceState::kAbsent);
        owner.stationSendError = ETIMEDOUT;
        assert(iwx_tahoe_p2p_add_broadcast_station(
            &owner, &owner.com, &station, 3, &mayExist) == ETIMEDOUT);
        assert(owner.controller.property("NativeP2PTxAddStaStatusValid") == 0);
        assert(owner.controller.property("NativeP2PTxAddStaFirmwareStatus") ==
               UINT32_MAX);
        assert(owner.controller.property("NativeP2PTxAddStaSendResult") == ETIMEDOUT);
        assert(mayExist && station.state == TahoeP2PResourceState::kUnknown);
    }

    // A well-formed queue response keeps raw flags as telemetry. A nonzero
    // value does not override a valid queue identity or permit early freeing.
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 18, 5); owner.responseFlags = 2;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == 0);
        assert(qid == 18 && mayExist && queue.state == TahoeP2PResourceState::kActive);
        assert(owner.controller.property("NativeP2PTxQueueResponseValid") == 1);
        assert(owner.controller.property("NativeP2PTxQueueSendResult") == 0);
        assert(owner.controller.property("NativeP2PTxQueueParseResult") == 0);
        assert(owner.controller.property("NativeP2PTxQueueResponseFlags") == 2);
        assert(owner.controller.property("NativeP2PTxQueueResponseId") == 18);
        assert(owner.controller.property("NativeP2PTxQueueWritePointer") == 5);
        assert(owner.controller.property("NativeP2PTxQueueFirmwareTid") == IWX_MGMT_TID);
        assert(gDmaLive == 3 && gMapLive == 8);
        completeOneTx(owner, queue);
        fillFlushResponse(owner, station.stationId, qid, 6);
        assert(iwx_tahoe_p2p_tvqm_remove(
            &owner, &owner.com, &station, &queue, &mayExist) == 0);
        assert(gDmaLive == 3 && gMapLive == 8);
        assert(iwx_tahoe_p2p_tvqm_confirm_drained(
            &owner, &owner.com, &queue, &mayExist) == 0);
        assert(!mayExist && queue.state == TahoeP2PResourceState::kAbsent);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }
    {
        ItlIwx owner; TahoeP2PStationLease station{}; TahoeP2PTxQueueLease queue{};
        setupSc(owner, station, queue); configureLegacyFirmware(owner);
        fillResponse(owner, 18, 5); owner.responseLength = 4;
        uint16_t qid = 0; bool mayExist = false;
        assert(allocate(owner, station, queue, &qid, &mayExist, 8) == EIO);
        assert(mayExist && queue.state == TahoeP2PResourceState::kUnknown);
        assert(owner.controller.property("NativeP2PTxQueueResponseValid") == 0);
        assert(owner.controller.property("NativeP2PTxQueueSendResult") == 0);
        assert(owner.controller.property("NativeP2PTxQueueParseResult") == EIO);
        assert(owner.controller.property("NativeP2PTxQueueResponseFlags") == UINT32_MAX);
        assert(owner.controller.property("NativeP2PTxQueueResponseId") == UINT32_MAX);
        cleanupPendingRing(owner, queue);
        assert(gDmaLive == 0 && gMapLive == 0 && gLiveIoObjects == 0);
    }

    assert(gLiveIoObjects == 0 && gDmaLive == 0 && gMapLive == 0);
}
"""

with tempfile.TemporaryDirectory(prefix="itlwm-p2p-tx-hal-") as directory:
    include = Path(directory) / "IOKit"
    include.mkdir()
    (include / "IOLocks.h").write_text(
        "#pragma once\n#include <stdint.h>\n"
        "typedef uint64_t IOInterruptState;\n"
        "struct IOSimpleLock;\n"
    )
    cpp = Path(directory) / "p2p_tx_hal_test.cpp"
    binary = Path(directory) / "p2p_tx_hal_test"
    cpp.write_text(shim + "\n" + actual + "\n" + body)
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", "-I", str(directory), "-I", str(root),
        "-I", str(root / "native"), str(cpp),
        str(root / "native/p2p_tx_resources.cpp"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)

print("PASS: actual P2P station/TVQM HAL, DMA lifetime, and fault paths")
