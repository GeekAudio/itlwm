#!/usr/bin/env python3
"""Compile extracted production P2P Action submit/RX hooks against host shims."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
GENERIC_SOURCE = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
REG_SOURCE = (ROOT / "itlwm/hal_iwx/if_iwxreg.h").read_text()


def extract_function(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


helper_start = SOURCE.index("namespace {\n")
helper_end = SOURCE.index("} // namespace", helper_start) + len("} // namespace")
production_helpers = SOURCE[helper_start:helper_end]
production_functions = "\n\n".join(
    extract_function(SOURCE, marker)
    for marker in (
        "int iwx_tahoe_p2p_action_tx_submit(",
        "void iwx_tahoe_p2p_action_tx_observe_rx(",
        "bool iwx_tahoe_p2p_action_tx_response(",
        "bool iwx_tahoe_p2p_action_reject_ba_queue(",
        "void iwx_tahoe_p2p_action_tx_firmware_drained(",
    )
)
production_functions = production_functions.replace(
    'mbuf_t frame, uint64_t nativeDataToken)', 'mbuf_t frame, uint64_t nativeDataToken = 0)')
production_generic_helpers = "\n\n".join(
    extract_function(GENERIC_SOURCE, marker)
    for marker in (
        "static bool iwx_tx_response_ring(",
        "static bool iwx_tx_response_index(",
    )
)

SHIM = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "native/p2p_action_tx.hpp"
#include "native/p2p_tx_firmware.hpp"
#include "native/awdl_action_frame.hpp"
#include "native/awdl_action_encode.hpp"
#include "native/awdl_mif_encode.hpp"
#include "native/iwx_tx_ring_capacity.hpp"
#define IEEE80211_FC0_TYPE_DATA 0x08

using caddr_t = char *;
using IOInterruptState = uintptr_t;
struct IOSimpleLock { bool locked = false; };
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    assert(lock && !lock->locked);
    lock->locked = true;
    return 1;
}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock,
                                               IOInterruptState state) {
    assert(lock && lock->locked && state == 1);
    lock->locked = false;
}
struct mbuf;
using mbuf_t = mbuf *;

static unsigned gDoorbells = 0, gDoorbellMarkCalls = 0;
static int gDoorbellMarkResult = 0;
static unsigned gMbufFrees = 0, gStaReclaims = 0;
static unsigned gDmaPostReads = 0, gNextMbufId = 1;
static std::unordered_map<const mbuf *, unsigned> gMbufIds;
static unsigned gFreedById[128]{};

struct mbuf {
    unsigned id;
    std::vector<uint8_t> bytes;
    size_t offset;
    size_t length;
    size_t packetLength;
    mbuf(const uint8_t *source, size_t size)
        : id(gNextMbufId++), bytes(source, source + size), offset(0),
          length(size), packetLength(size) { gMbufIds[this] = id; }
};
static size_t mbuf_len(mbuf_t m) { return m ? m->length : 0; }
static size_t mbuf_pkthdr_len(mbuf_t m) { return m ? m->packetLength : 0; }
static int mbuf_copydata(mbuf_t m, int offset, size_t length, void *out) {
    assert(m && offset >= 0 && static_cast<size_t>(offset) + length <= m->length);
    std::memcpy(out, m->bytes.data() + m->offset + offset, length);
    return 0;
}
static void mbuf_adj(mbuf_t m, int amount) {
    assert(m && amount >= 0 && static_cast<size_t>(amount) <= m->length);
    m->offset += static_cast<size_t>(amount);
    m->length -= static_cast<size_t>(amount);
    m->packetLength -= static_cast<size_t>(amount);
}
static void mbuf_freem(mbuf_t m) {
    if (!m) return;
    auto found = gMbufIds.find(m);
    assert(found != gMbufIds.end());
    const unsigned id = found->second;
    assert(id < sizeof(gFreedById) / sizeof(gFreedById[0]));
    assert(gFreedById[id] == 0 && "mbuf released more than once");
    ++gFreedById[id]; ++gMbufFrees;
    gMbufIds.erase(found);
    delete m;
}

struct IOPhysicalSegment { uint64_t location; uint64_t length; };
struct FakeCursor {
    int result = 1;
    int getPhysicalSegmentsWithCoalesce(mbuf_t m, IOPhysicalSegment *segments,
                                        int maximum) {
        if (result <= 0 || !m || maximum < 1) return result;
        segments[0] = {0x200000, m->length};
        return 1;
    }
};
struct FakeMap { FakeCursor *cursor; };
struct iwx_cmd_header { uint8_t cmd, group_id, qid, idx; } __attribute__((packed));
struct iwx_device_cmd { iwx_cmd_header hdr; uint8_t data[320]; };
struct ieee80211_frame { uint8_t bytes[24]; } __attribute__((packed));
struct iwx_dram_sec_info { uint32_t low; uint16_t high, aux; } __attribute__((packed));
struct iwx_tx_cmd_gen2 {
    uint16_t len, offload_assist;
    uint32_t flags;
    iwx_dram_sec_info dram_info;
    uint32_t rate_n_flags;
    ieee80211_frame hdr[0];
} __attribute__((packed));
struct iwx_tx_cmd_gen3 {
    uint16_t len, flags;
    uint32_t offload_assist;
    iwx_dram_sec_info dram_info;
    uint32_t rate_n_flags;
    uint64_t ttl;
    ieee80211_frame hdr[0];
} __attribute__((packed));
struct iwx_tfh_tb { uint16_t tb_len; uint64_t addr; } __attribute__((packed));
struct iwx_tfh_tfd { uint16_t num_tbs; iwx_tfh_tb tbs[25]; uint32_t pad; } __attribute__((packed));
struct iwx_tx_data {
    FakeMap *map = nullptr;
    uint64_t cmd_paddr = 0x100000;
    mbuf_t m = nullptr;
    void *in = nullptr;
    int type = 0;
};
struct iwx_tx_ring {
    int qid = -1;
    unsigned ring_count = 8;
    int cur = 0, tail = 0, queued = 0;
    iwx_tfh_tfd *desc = nullptr;
    iwx_device_cmd *cmd = nullptr;
    iwx_tx_data data[16]{};
    uint16_t byteCounts[16]{};
};
struct iwx_agg_tx_status { uint16_t status, sequence; } __attribute__((packed));
struct iwx_tx_resp {
    uint8_t frame_count, bt_kill_count, failure_rts, failure_frame;
    uint32_t initial_rate;
    uint16_t wireless_media_time;
    uint8_t pa_status, pa_integ_res_a[3], pa_integ_res_b[3], pa_integ_res_c[3];
    uint16_t measurement_req_id;
    uint8_t reduced_tpc, reserved;
    uint32_t tfd_info;
    uint16_t seq_ctl, byte_cnt;
    uint8_t tlc_info, ra_tid;
    uint16_t frame_ctrl, tx_queue, reserved2;
    iwx_agg_tx_status status;
} __attribute__((packed));
struct iwx_rx_packet {
    uint8_t rawGroup = 1, rawOpcode = 0x1c, rawHeaderQueue = 0x8c, rawIndex = 5;
    iwx_cmd_header hdr{};
    uint8_t data[64]{};
    size_t payloadLength = 48;
};
struct iwx_rx_data { void *map = nullptr; };
struct ieee80211com { int ic_state = 3; void *ic_bss = reinterpret_cast<void *>(1); };
struct iwx_p2p_roc_state { uint32_t token = 0, fw_generation = 0; uint8_t phase = 0; };
struct iwx_p2p_state {
    bool initialized = false, phy_leased = false;
    uint8_t mac_state = 0, binding_state = 0;
    uint32_t fw_generation = 0;
    uint8_t mac_address[6]{};
};
struct iwx_device_name { char dv_xname[16] = "iwx-test"; };
struct iwx_softc {
    int sc_device_family = 1;
    int sc_generation = 7;
    int sc_dmat = 0;
    ieee80211com sc_ic{};
    iwx_p2p_state sc_p2p{};
    iwx_p2p_roc_state sc_p2p_roc{};
    iwx_device_name sc_dev{};
    iwx_tx_ring txq[16]{};
};

enum class TahoeP2PResourceState : uint8_t {
    kAbsent, kPending, kActive, kRemoving, kReleasing, kUnknown
};
struct TahoeP2PTxQueueLease {
    uint8_t stationId = 3;
    uint16_t queueId = 12;
    uint32_t generation = 7;
    TahoeP2PResourceState state = TahoeP2PResourceState::kActive;
    IOSimpleLock *stateLock = nullptr;
    bool submissionBusy = false;
    uint16_t submissionDescriptorIndex = 0xffff;
    bool everDoorbelled = false;
    unsigned outstanding = 0;
    iwx_tx_ring *ring = nullptr;
    int beginResult = 0, finishResult = 0, completionResult = 0;
    bool ringInstalled = true;
};
enum class TahoeP2PActionTxState : uint8_t { kIdle, kInFlight, kQuarantined };
enum class TahoeP2PPreArmEventSource : uint32_t {
    kNone = 0, kTxResponseNoLiveTicket = 1,
    kTxResponseOwnershipUnknown = 2, kOwnedBlockAckNoLiveTicket = 3,
    kOwnedBlockAckOwnershipUnknown = 4
};
enum class TahoeP2PActionTxSubmitStage : uint32_t {
    kNone = 0, kInvalidArgument = 1, kOwnerOrGate = 2,
    kUnsupportedLayout = 3, kRocOrResource = 4, kContextInFlight = 5,
    kContextQuarantined = 6, kFrameLength = 7, kFrameEncoding = 8,
    kMacHeaderLength = 9, kRateUnavailable = 10, kBeginTx = 11,
    kRingShape = 12, kPayloadMapping = 13, kPayloadSegmentLength = 14,
    kTfdPlan = 15, kTicketArm = 16, kDoorbellMark = 17,
    kDoorbellIssued = 18, kPostDoorbellFinish = 19,
    kPreDoorbellCancelFailed = 20, kExistingTicketUnknown = 21
};
enum class TahoeP2PTxRxRejectReason : uint32_t {
    kNone = 0, kInvalidArguments = 1, kShortPayload = 2,
    kQueueParseFailed = 3, kQueueOutOfRange = 4,
    kDuplicateWhileReleasing = 5, kCompletionLockUnavailable = 6,
    kWrongWorkLoopGate = 7, kNoMatchingTicket = 8,
    kUnsupportedFirmware = 9, kStaleGeneration = 10,
    kRingMismatch = 11, kWrongTid = 12, kCompletionRejected = 13,
    kCompletionAccountingFailed = 14, kUnexpectedBlockAck = 15
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
struct TahoeP2PTxRxDiagnostics {
    uint32_t armed = 0, dirty = 0, targetQueue = 0xffff;
    uint32_t rawTxCmdCount = 0, rawTargetHeaderCount = 0;
    uint32_t responseQueueMatchCount = 0;
    uint32_t foreignQueueCount = 0, shortResponseCount = 0;
    uint32_t outOfRangeQueueCount = 0, handlerEntryCount = 0;
    uint32_t handlerQueueMatchCount = 0, handlerForeignCount = 0;
    uint32_t rejectCount = 0, lastRejectReason = 0;
    uint32_t lastCompletionResult = 0xffffffffu, completionCount = 0;
    uint32_t lastResponseQueue = 0xffff;
    uint32_t lastResponseFieldsValidMask = 0;
    uint32_t lastResponseFrameCount = 0xffffffffu;
    uint32_t lastResponseStatus = 0xffffffffu;
    uint32_t lastResponseSequenceControl = 0xffffffffu;
    uint32_t lastResponseByteCount = 0xffffffffu;
    uint32_t lastResponseFrameControl = 0xffffffffu;
    uint32_t lastResponseRaTid = 0xffffffffu;
    uint32_t lastResponseScdSsn = 0xffffffffu;
    uint32_t lastResponseHeaderIndex = 0xffffffffu;
    uint32_t lastResponseHeaderIndexMatchesTicket = 0xffffffffu;
    uint32_t lastResponseMismatchMask = 0;
    uint32_t lastResponseExpectedSequenceControl = 0xffffffffu;
    uint32_t lastResponseExpectedByteCount = 0xffffffffu;
    uint32_t lastResponseExpectedFrameControl = 0xffffffffu;
    uint32_t lastResponseExpectedDescriptorIndex = 0xffffffffu;
    uint32_t lastResponseExpectedNextIndex = 0xffffffffu;
    uint64_t lastRawPacket = ~uint64_t(0), lastTargetRawPacket = ~uint64_t(0);
};
struct TahoeP2PActionTxPreArmDiagnostics {
    uint32_t eventCount = 0, lastSource = 0;
    uint32_t lastQueueId = 0xffffffffu, lastRaTid = 0xffffffffu;
    uint32_t lastLeaseState = 0xffffffffu;
    uint32_t lastActionState = 0xffffffffu, lastTicketFlags = 0;
};
struct TahoeP2PActionTxSubmitDiagnostics {
    uint32_t attemptCount = 0, lastStage = 0;
    int32_t lastResult = 0;
};
struct TahoeP2PActionTxDrainDiagnostics {
    uint32_t eventCount = 0;
    int32_t lastResult = 0;
    uint32_t lastNewGeneration = 0, lastContextGeneration = 0;
    uint32_t lastTicketGeneration = 0, lastTicketFlags = 0;
    uint32_t lastHardStop = 0, lastActionState = 0;
};
struct TahoeP2PActionTxContext {
    IntelP2PActionTx::CompletionTracker completion;
    TahoeP2PTxRxDiagnostics rxDiagnostics;
    TahoeP2PActionTxPreArmDiagnostics preArmDiagnostics;
    TahoeP2PActionTxSubmitDiagnostics submitDiagnostics;
    TahoeP2PActionTxDrainDiagnostics drainDiagnostics{};
    uint32_t generation = 0, rocToken = 0;
    uint16_t queueId = 0xffff, nextSequenceNumber = 0, descriptorIndex = 0;
    uint16_t sequenceControl = 0, frameControl = 0, frameByteCount = 0;
    uint64_t nativeDataToken = 0;
    TahoeP2PActionTxState state = TahoeP2PActionTxState::kIdle;
};

class ItlIwx {
public:
    iwx_softc com{};
    bool gate = true, busy = true;
    uint8_t txCommandVersion = 9, txNotificationVersion = 7;
    bool tahoeP2pOnMainGate() const { return gate; }
    bool nativeP2pBusy() const { return busy; }
    uint8_t iwx_lookup_cmd_ver(iwx_softc *, uint8_t, uint8_t) {
        return txCommandVersion;
    }
    uint8_t iwx_lookup_notif_ver(iwx_softc *, uint8_t, uint8_t) {
        return txNotificationVersion;
    }
    uint8_t iwx_fw_valid_tx_ant(iwx_softc *) { return 0x02; }
    void iwx_tx_update_byte_tbl(iwx_softc *, iwx_tx_ring *ring, int index,
                                uint16_t bytes, uint16_t) {
        ring->byteCounts[index] = bytes;
    }
};

static size_t iwx_rx_packet_payload_len(iwx_rx_packet *p) { return p->payloadLength; }
static size_t ieee80211_get_hdrlen(const ieee80211_frame *f) {
    return (f->bytes[1] & 0x80) ? 28U : 24U;
}
static void bus_dmamap_sync(int, void *, size_t, size_t, int) { ++gDmaPostReads; }
static void fakeDoorbell(iwx_softc *, uint32_t, uint32_t) { ++gDoorbells; }
static int iwx_tahoe_p2p_tvqm_begin_tx(iwx_softc *sc, TahoeP2PTxQueueLease *lease,
                                       iwx_tx_ring **ring, uint16_t *index) {
    if (lease && lease->beginResult) return lease->beginResult;
    if (!sc || !lease || !ring || !index || lease->state != TahoeP2PResourceState::kActive ||
        lease->submissionBusy || lease->outstanding || lease->ring == nullptr)
        return EBUSY;
    if (lease->ring->cur < 0 ||
        static_cast<unsigned>(lease->ring->cur) >= lease->ring->ring_count) return EIO;
    lease->submissionBusy = true;
    lease->submissionDescriptorIndex = static_cast<uint16_t>(lease->ring->cur);
    ++lease->outstanding;
    *ring = lease->ring; *index = static_cast<uint16_t>(lease->ring->cur);
    return 0;
}
static int iwx_tahoe_p2p_tvqm_finish_tx_submit(TahoeP2PTxQueueLease *lease) {
    if (!lease) return EINVAL;
    if (lease->finishResult) return lease->finishResult;
    lease->submissionBusy = false;
    return 0;
}
static int iwx_tahoe_p2p_tvqm_cancel_tx_submit(TahoeP2PTxQueueLease *lease) {
    if (!lease || !lease->submissionBusy || !lease->outstanding) return EINVAL;
    lease->submissionBusy = false; lease->submissionDescriptorIndex = 0xffff;
    --lease->outstanding; return 0;
}
static int iwx_tahoe_p2p_tvqm_mark_doorbell(
    iwx_softc *, TahoeP2PTxQueueLease *lease, iwx_tx_ring *ring,
    uint16_t descriptorIndex) {
    ++gDoorbellMarkCalls;
    if (gDoorbellMarkResult) return gDoorbellMarkResult;
    assert(lease && ring && lease->submissionBusy && lease->outstanding == 1);
    assert(lease->ring == ring && lease->queueId == ring->qid);
    assert(lease->submissionDescriptorIndex == descriptorIndex);
    assert(descriptorIndex < ring->ring_count && ring->data[descriptorIndex].m);
    lease->everDoorbelled = true;
    return 0;
}
static bool iwx_tahoe_p2p_tvqm_queue_owned(TahoeP2PTxQueueLease *lease, uint16_t qid) {
    return lease && lease->state != TahoeP2PResourceState::kAbsent && lease->queueId == qid;
}
static bool iwx_tahoe_p2p_tvqm_lock_completion(iwx_softc *, TahoeP2PTxQueueLease *lease,
                                               uint16_t qid, iwx_tx_ring **ring,
                                               IOInterruptState *irq) {
    if (!lease || !ring || !irq ||
        (lease->state != TahoeP2PResourceState::kActive &&
         lease->state != TahoeP2PResourceState::kRemoving &&
         lease->state != TahoeP2PResourceState::kUnknown) ||
        !lease->ringInstalled ||
        !lease->ring || qid != lease->queueId) return false;
    *ring = lease->ring; *irq = 1; return true;
}
static int iwx_tahoe_p2p_tvqm_tx_completed_locked(iwx_softc *, TahoeP2PTxQueueLease *lease) {
    if (!lease || lease->completionResult) return lease ? lease->completionResult : EINVAL;
    if (!lease->outstanding) return EINVAL;
    --lease->outstanding; return 0;
}
static void iwx_tahoe_p2p_tvqm_unlock(TahoeP2PTxQueueLease *, IOInterruptState) {}

#define AIRPORT_TAHOE 1
#define IWX_DEVICE_FAMILY_22000 1
#define IWX_DEVICE_FAMILY_AX210 2
#define IWX_LONG_GROUP 0
#define IWX_TX_CMD 0x1c
#define IWX_RATE_MCS_ANT_NUM 3
#define IWX_RATE_MCS_ANT_POS 14
#define IWX_RATE_MCS_LEGACY_OFDM_MSK (1U << 8)
#define IWX_RATE_6M_INDEX 4
#define IWX_FIRST_OFDM_RATE 4
#define IWX_TX_FLAGS_CMD_RATE (1U << 0)
#define IWX_TX_FLAGS_ENCRYPT_DIS (1U << 1)
#define IWX_TX_FLAGS_HIGH_PRI (1U << 2)
#define IWX_TX_CMD_OFFLD_MH_SIZE(words) ((words) << 8)
#define IEEE80211_S_RUN 3
#define IEEE80211_FC0_TYPE_MGT 0
#define IWX_P2P_RESOURCE_ACTIVE 1
#define IWX_P2P_ROC_SESSION_ACKED 2
#define IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN 3
#define IWX_TFH_NUM_TBS 25
#define IWX_TFD_QUEUE_SIZE_MAX 256
#define IWX_MGMT_TID 15
#define IWX_AGG_SSN_TO_TXQ_IDX(x, a) ((x) & ((a) - 1))
#define IWX_TX_RES_GET_TID(_ra_tid) ((_ra_tid) & 0x0f)
#define IWX_TX_RES_GET_RA(_ra_tid) ((_ra_tid) >> 4)
#define IWX_FIRST_TB_SIZE 20
#define IWX_RBUF_SIZE 4096
#define MCLBYTES 2048
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#define BUS_DMASYNC_POSTREAD 1
#define IWX_HBUS_TARG_WRPTR 0
#define htole16(x) static_cast<uint16_t>(x)
#define htole32(x) static_cast<uint32_t>(x)
#define htole64(x) static_cast<uint64_t>(x)
#define le16toh(x) static_cast<uint16_t>(x)
#define IWX_WRITE(sc, reg, value) fakeDoorbell((sc), (reg), (value))
static void fakeLog(const char *, ...) {}
#define XYLog(...) fakeLog(__VA_ARGS__)

static_assert(offsetof(iwx_tx_resp, seq_ctl) == 28, "TX_RSP seq offset");
static_assert(offsetof(iwx_tx_resp, byte_cnt) == 30, "TX_RSP byte count offset");
static_assert(offsetof(iwx_tx_resp, ra_tid) == 33, "TX_RSP RA/TID offset");
static_assert(offsetof(iwx_tx_resp, frame_ctrl) == 34, "TX_RSP frame control offset");
static_assert(offsetof(iwx_tx_resp, tx_queue) == 36, "TX_RSP queue offset");
static_assert(offsetof(iwx_tx_resp, status) == 40, "TX_RSP status offset");
static_assert(IWX_TX_RES_GET_RA(0x3f) == 3,
              "TX_RSP RA high nibble is station ID");
static_assert(IWX_TX_RES_GET_TID(0x3f) == IWX_MGMT_TID,
              "TX_RSP TID low nibble is management TID 15");
static_assert(sizeof(iwx_tx_cmd_gen2) == 20, "AX201 TX_CMD gen2 size");
static_assert(sizeof(iwx_tx_cmd_gen3) == 28, "AX210 TX_CMD gen3 size");
static_assert(offsetof(iwx_tx_cmd_gen3, flags) == 2, "gen3 flags offset");
static_assert(offsetof(iwx_tx_cmd_gen3, offload_assist) == 4,
              "gen3 offload offset");
static_assert(offsetof(iwx_tx_cmd_gen3, dram_info) == 8, "gen3 DRAM offset");
static_assert(offsetof(iwx_tx_cmd_gen3, rate_n_flags) == 16,
              "gen3 PHY rate offset");
static_assert(offsetof(iwx_tx_cmd_gen3, ttl) == 20, "gen3 TTL offset");

"""

BODY = r"""
static const uint8_t kSource[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t kProbe[] = "ITL-P2P-PROBE";

static mbuf_t makeFrame(uint16_t sequence = 1) {
    uint8_t bytes[128]; size_t length = 0;
    assert(IntelP2PActionFrame::encodeVendorSpecificAction(
        kSource, sequence, kProbe, sizeof(kProbe) - 1,
        bytes, sizeof(bytes), &length));
    return new mbuf(bytes, length);
}
static mbuf_t makePsfFrame() {
    NativeAwdl::PsfInput input{};
    std::memcpy(input.sourceAddress, kSource, sizeof(kSource));
    std::memcpy(input.masterAddress, kSource, sizeof(kSource));
    std::memcpy(input.syncAddress, kSource, sizeof(kSource));
    input.sequenceNumber = 0x123;
    input.channelSlots[0] = 6;
    input.nextAwChannel = 6;
    input.masterChannel = 6;
    input.txDownCounterTu = 0;
    input.remainingAwLengthTu = 16;
    input.htCapabilityInfo = 0x1234;
    input.ampduParameters = 0x56;
    input.rxMcsMask[0] = 0x3f;
    input.rxMcsLength = 1;
    input.awdlVersion = 0x10;
    input.deviceClass = 1;
    input.masterMetric = input.ownMetric = 60;
    uint8_t bytes[NativeAwdl::kMaximumEncodedPsfLength] = {};
    size_t length = 0;
    assert(NativeAwdl::encodePsf(&input, bytes, sizeof(bytes), &length) ==
           NativeAwdl::EncodeStatus::Ok);
    return new mbuf(bytes, length);
}
static mbuf_t makeMifFrame() {
    NativeAwdl::MifInput input{};
    std::memcpy(input.psf.sourceAddress, kSource, sizeof(kSource));
    std::memcpy(input.psf.masterAddress, kSource, sizeof(kSource));
    std::memcpy(input.psf.syncAddress, kSource, sizeof(kSource));
    input.psf.sequenceNumber = 0x124;
    input.psf.channelSlots[0] = 6;
    input.psf.nextAwChannel = 6;
    input.psf.masterChannel = 6;
    input.psf.txDownCounterTu = 0;
    input.psf.remainingAwLengthTu = 16;
    input.psf.htCapabilityInfo = 0x1234;
    input.psf.ampduParameters = 0x56;
    input.psf.rxMcsMask[0] = 0xff;
    input.psf.rxMcsMask[1] = 0xff;
    input.psf.rxMcsMask[2] = 0xff;
    input.psf.rxMcsMask[3] = 0xff;
    input.psf.rxMcsLength = 4;
    input.psf.awdlVersion = 0x10;
    input.psf.deviceClass = 1;
    input.psf.masterMetric = input.psf.ownMetric = 60;
    static const char hostname[] = "intel-awdl-probe";
    input.hostname = hostname;
    input.hostnameLength = sizeof(hostname) - 1;
    uint8_t bytes[NativeAwdl::kMaximumEncodedMifLength] = {};
    size_t length = 0;
    assert(NativeAwdl::encodeMif(&input, bytes, sizeof(bytes), &length) ==
           NativeAwdl::MifEncodeStatus::Ok);
    assert(length > NativeAwdl::kMaximumEncodedPsfLength);
    return new mbuf(bytes, length);
}
static mbuf_t makeHtFrame(uint16_t sequence = 1) {
    mbuf_t frame = makeFrame(sequence);
    assert(frame->bytes.size() >= 24);
    frame->bytes.insert(frame->bytes.begin() + 24, 4, 0);
    frame->bytes[1] |= 0x80; // HT Control extends the MAC header to 28 bytes.
    frame->length += 4;
    frame->packetLength += 4;
    return frame;
}
static void put16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); }
static void put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i != 4; ++i) p[i] = uint8_t(v >> (i * 8));
}
static void makeResponse(iwx_rx_packet &packet, uint16_t queue, uint16_t sequence,
                         uint16_t status = 1, uint16_t byteCount = 41,
                         uint16_t frameControl = 0x00d0, uint32_t next = 1) {
    std::memset(packet.data, 0, sizeof(packet.data));
    packet.payloadLength = 48;
    packet.data[0] = 1;
    put16(packet.data + 28, sequence);
    put16(packet.data + 30, byteCount);
    packet.data[33] = 0x3f; // station 3, firmware management TID 15
    put16(packet.data + 34, frameControl);
    put16(packet.data + 36, queue);
    put16(packet.data + 40, status);
    put32(packet.data + 44, next);
}

struct Fixture {
    ItlIwx owner{};
    TahoeP2PTxQueueLease lease{};
    TahoeP2PActionTxContext context{};
    IOSimpleLock queueLock{};
    iwx_tfh_tfd descriptors[8]{};
    iwx_device_cmd commands[8]{};
    FakeCursor cursor{};
    FakeMap map{&cursor};

    Fixture() {
        iwx_softc *sc = &owner.com;
        sc->sc_device_family = IWX_DEVICE_FAMILY_22000;
        sc->sc_p2p.initialized = true;
        sc->sc_p2p.mac_state = IWX_P2P_RESOURCE_ACTIVE;
        sc->sc_p2p.binding_state = IWX_P2P_RESOURCE_ACTIVE;
        sc->sc_p2p.phy_leased = true;
        sc->sc_p2p.fw_generation = 7;
        std::memcpy(sc->sc_p2p.mac_address, kSource, sizeof(kSource));
        sc->sc_p2p_roc.token = 55;
        sc->sc_p2p_roc.fw_generation = 7;
        sc->sc_p2p_roc.phase = IWX_P2P_ROC_SESSION_ACKED;
        sc->sc_ic.ic_state = IEEE80211_S_RUN;
        sc->sc_ic.ic_bss = reinterpret_cast<void *>(1);

        iwx_tx_ring *ring = &sc->txq[12];
        ring->qid = 12; ring->ring_count = 8;
        ring->desc = descriptors; ring->cmd = commands;
        ring->cur = ring->tail = ring->queued = 0;
        for (unsigned i = 0; i < 8; ++i) {
            ring->data[i].map = &map;
            ring->data[i].cmd_paddr = 0x100000 + i * 512;
        }
        lease.queueId = 12; lease.generation = 7;
        lease.state = TahoeP2PResourceState::kActive;
        lease.stateLock = &queueLock;
        lease.ring = ring;
    }

    int submit(mbuf_t frame) {
        return iwx_tahoe_p2p_action_tx_submit(
            &owner, &owner.com, &lease, &context, 55, true, false, frame, 0);
    }
    bool response(iwx_rx_packet &packet) {
        packet.hdr.group_id = packet.rawGroup;
        packet.hdr.cmd = packet.rawOpcode;
        packet.hdr.qid = packet.rawHeaderQueue;
        packet.hdr.idx = packet.rawIndex;
        iwx_rx_data rx{};
        return iwx_tahoe_p2p_action_tx_response(
            &owner, &owner.com, &lease, &context, &packet, &rx);
    }
    iwx_tx_ring *ring() { return lease.ring; }
};
static void testCleanupAfterProvenDrain(Fixture &fixture) {
    // Host-test teardown only: the production driver has no equivalent reset
    // shortcut and retains this buffer until proven firmware/DMA drain.
    mbuf_t retained = fixture.ring()->data[0].m;
    fixture.ring()->data[0].m = nullptr;
    fixture.ring()->data[0].in = nullptr;
    if (retained) mbuf_freem(retained);
}

static uint16_t read16(const uint8_t *p) {
    return uint16_t(p[0]) | uint16_t(uint16_t(p[1]) << 8);
}
static uint32_t read32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 |
        uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
template <typename T> static T atomicLoad(const T *value) {
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}
static uint64_t read64(const uint8_t *p) {
    return uint64_t(read32(p)) | uint64_t(read32(p + 4)) << 32;
}
static void genericStaFallback(iwx_softc &sc, iwx_rx_packet &packet) {
    const size_t length = packet.payloadLength;
    if (length < 1) return;
    const uint8_t count = packet.data[0];
    if (!count) return;
    const size_t required = 40 + static_cast<size_t>(count) * 4 + 4;
    if (required > length) return; // production iwx_rx_tx_cmd guard
    const uint16_t qid = read16(packet.data + 36);
    iwx_tx_ring *ring = nullptr;
    if (!iwx_tx_response_ring(&sc, qid, &ring)) return;
    if (count == 1) {
        const uint32_t ssn = read32(packet.data + 44) & 0xfff;
        uint16_t index = 0;
        if (ring->queued <= 0 ||
            !iwx_tx_response_index(qid, ring, ssn, &index))
            return;
        assert(index < ring->ring_count);
    }
    ++gStaReclaims;
}
static bool dispatch(Fixture &fixture, iwx_rx_packet &packet) {
    iwx_tahoe_p2p_action_tx_observe_rx(
        &fixture.context, packet.rawGroup, packet.rawOpcode,
        packet.rawHeaderQueue, packet.rawIndex, packet.payloadLength);
    const bool owned = fixture.response(packet);
    if (!owned) genericStaFallback(fixture.owner.com, packet);
    return owned;
}

int main() {
    // Pending and installed P2P qids consume late notifications without DMA reclaim.
    {
        Fixture f;
        f.lease.state = TahoeP2PResourceState::kPending;
        f.lease.ringInstalled = false;
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        const unsigned before = gStaReclaims;
        assert(dispatch(f, packet));
        assert(gStaReclaims == before && f.ring()->queued == 0);
        assert(f.context.state == TahoeP2PActionTxState::kIdle);
        assert(atomicLoad(&f.context.preArmDiagnostics.eventCount) == 1);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastSource) ==
               static_cast<uint32_t>(TahoeP2PPreArmEventSource::kTxResponseNoLiveTicket));
        assert(atomicLoad(&f.context.preArmDiagnostics.lastQueueId) == 12);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastRaTid) == 0x3f);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastActionState) ==
               static_cast<uint32_t>(TahoeP2PActionTxState::kIdle));
    }
    // An active queue with no ticket also drops foreign station/TID replies
    // without changing Idle state or handing them to the generic STA handler.
    {
        Fixture f;
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        packet.data[33] = 0x4e; // foreign station 4, non-management TID 14
        const unsigned before = gStaReclaims;
        assert(dispatch(f, packet));
        assert(gStaReclaims == before && f.ring()->queued == 0 &&
               f.lease.outstanding == 0);
        assert(f.context.state == TahoeP2PActionTxState::kIdle);
        assert(atomicLoad(&f.context.rxDiagnostics.armed) == 0);
        assert(atomicLoad(&f.context.preArmDiagnostics.eventCount) == 1);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastSource) ==
               static_cast<uint32_t>(TahoeP2PPreArmEventSource::kTxResponseNoLiveTicket));
        assert(atomicLoad(&f.context.preArmDiagnostics.lastRaTid) == 0x4e);
    }
    // Unknown ownership is still consumed and quarantined even with diagnostics
    // unarmed; it must never fall through to generic station reclaim.
    {
        Fixture f;
        f.lease.state = TahoeP2PResourceState::kUnknown;
        f.lease.stateLock = nullptr;
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        const unsigned before = gStaReclaims;
        assert(dispatch(f, packet));
        assert(gStaReclaims == before && f.ring()->queued == 0 &&
               f.lease.outstanding == 0);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        assert(atomicLoad(&f.context.preArmDiagnostics.eventCount) == 1);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastSource) ==
               static_cast<uint32_t>(TahoeP2PPreArmEventSource::kTxResponseOwnershipUnknown));
    }
    for (auto state : {TahoeP2PResourceState::kPending, TahoeP2PResourceState::kActive,
                       TahoeP2PResourceState::kRemoving, TahoeP2PResourceState::kReleasing,
                       TahoeP2PResourceState::kUnknown}) {
        Fixture f; f.lease.state = state;
        assert(!iwx_tahoe_p2p_action_reject_ba_queue(&f.lease, &f.context, 13));
        assert(iwx_tahoe_p2p_action_reject_ba_queue(&f.lease, &f.context, 12));
        const bool knownIdle = state != TahoeP2PResourceState::kUnknown;
        assert(f.context.state == (knownIdle ? TahoeP2PActionTxState::kIdle :
                                               TahoeP2PActionTxState::kQuarantined));
        assert(atomicLoad(&f.context.preArmDiagnostics.eventCount) == 1);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastSource) ==
               static_cast<uint32_t>(knownIdle ?
                   TahoeP2PPreArmEventSource::kOwnedBlockAckNoLiveTicket :
                   TahoeP2PPreArmEventSource::kOwnedBlockAckOwnershipUnknown));
        assert(f.ring()->queued == 0 && f.lease.outstanding == 0);
        f.lease.state = TahoeP2PResourceState::kAbsent;
        assert(!iwx_tahoe_p2p_action_reject_ba_queue(&f.lease, &f.context, 12));
    }
    {
        Fixture f;
        f.lease.state = TahoeP2PResourceState::kUnknown;
        f.lease.stateLock = nullptr;
        assert(iwx_tahoe_p2p_action_reject_ba_queue(&f.lease, &f.context, 12));
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastLeaseState) ==
               static_cast<uint32_t>(TahoeP2PResourceState::kUnknown));
    }
    {
        Fixture f;
        assert(f.context.completion.arm(7, 12, 8, 0, 0x10, 41, 0x00d0) ==
               IntelP2PActionTx::Result::kReady);
        f.context.state = TahoeP2PActionTxState::kInFlight;
        f.lease.outstanding = 1;
        assert(iwx_tahoe_p2p_action_reject_ba_queue(&f.lease, &f.context, 12));
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        assert(f.context.completion.snapshot().armed);
        assert(f.lease.outstanding == 1 && f.ring()->queued == 0);
        assert(atomicLoad(&f.context.preArmDiagnostics.lastSource) ==
               static_cast<uint32_t>(TahoeP2PPreArmEventSource::kOwnedBlockAckOwnershipUnknown));
    }

    static_assert(sizeof(iwx_tx_resp) == 44, "fw68 TX_RSP prefix size");
    {
        mbuf_t frame = makePsfFrame();
        uint8_t header[32]{};
        IntelP2PActionFrame::FrameInfo info{};
        assert(copyAndValidateDiagnosticFrame(frame, mbuf_len(frame),
                                              kSource, header, &info));
        frame->bytes[28] = 0x7f; // unknown AWDL action type
        assert(!copyAndValidateDiagnosticFrame(frame, mbuf_len(frame),
                                               kSource, header, &info));
        mbuf_freem(frame);
    }
    {
        mbuf_t frame = makeMifFrame();
        uint8_t header[32]{};
        IntelP2PActionFrame::FrameInfo info{};
        assert(copyAndValidateDiagnosticFrame(frame, mbuf_len(frame),
                                              kSource, header, &info));
        NativeAwdl::ActionFrameInfo awdlInfo{};
        assert(NativeAwdl::parseActionFrame(frame->bytes.data(),
            frame->length, &awdlInfo) == NativeAwdl::ParseStatus::Ok);
        assert(awdlInfo.subtype == 3);
        mbuf_freem(frame);
    }
    {
        TahoeP2PTxRxDiagnostics diagnostics{};
        __atomic_store_n(&diagnostics.lastResponseStatus, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&diagnostics.lastResponseScdSsn, 2u, __ATOMIC_RELAXED);
        __atomic_store_n(&diagnostics.lastResponseHeaderIndex, 3u,
                         __ATOMIC_RELAXED);
        resetP2PTxRxDiagnostics(&diagnostics, 12);
        assert(atomicLoad(&diagnostics.lastResponseFieldsValidMask) == 0);
        assert(atomicLoad(&diagnostics.lastResponseStatus) == 0xffffffffu);
        assert(atomicLoad(&diagnostics.lastResponseScdSsn) == 0xffffffffu);
        assert(atomicLoad(&diagnostics.lastResponseHeaderIndex) == 0xffffffffu);
        assert(atomicLoad(&diagnostics.lastResponseMismatchMask) == 0);
        assert(atomicLoad(&diagnostics.lastResponseExpectedNextIndex) ==
               0xffffffffu);
    }
    // Raw target-header matching is kept separately from all TX_CMD events.
    // A later foreign legacy-group packet may update the overall last tuple,
    // but must not overwrite the earlier target wide-group tuple.
    {
        TahoeP2PActionTxContext context{};
        auto &diag = context.rxDiagnostics;
        __atomic_store_n(&diag.targetQueue, 2u, __ATOMIC_RELAXED);
        __atomic_store_n(&diag.armed, 1u, __ATOMIC_RELEASE);
        iwx_tahoe_p2p_action_tx_observe_rx(&context, 1, 0x1c, 0x82, 9, 48);
        const uint64_t targetRaw = atomicLoad(&diag.lastTargetRawPacket);
        iwx_tahoe_p2p_action_tx_observe_rx(&context, 0, 0x1c, 0x83, 3, 44);

        const uint64_t allRaw = atomicLoad(&diag.lastRawPacket);
        const uint32_t allHeader = static_cast<uint32_t>(allRaw >> 32);
        const uint32_t targetHeader = static_cast<uint32_t>(targetRaw >> 32);
        assert(atomicLoad(&diag.rawTxCmdCount) == 2);
        assert(atomicLoad(&diag.rawTargetHeaderCount) == 1);
        assert(targetRaw != ~uint64_t(0) && targetRaw != allRaw);
        assert((targetHeader >> 24) == 1 && ((targetHeader >> 16) & 0xff) == 0x1c);
        assert(((targetHeader >> 8) & 0xff) == 0x82 &&
               (targetHeader & 0xff) == 9 && static_cast<uint32_t>(targetRaw) == 48);
        assert((allHeader >> 24) == 0 && ((allHeader >> 16) & 0xff) == 0x1c);
        assert(((allHeader >> 8) & 0xff) == 0x83 && (allHeader & 0xff) == 3);
        assert(atomicLoad(&diag.handlerEntryCount) == 0);
        assert(atomicLoad(&diag.completionCount) == 0);
    }

    assert(IntelP2PFirmware::txLayout(
        IntelP2PFirmware::DeviceFamily::k22000, 9, 7) ==
            IntelP2PFirmware::TxLayout::kGen2);
    assert(IntelP2PFirmware::txLayout(
        IntelP2PFirmware::DeviceFamily::kAX210, 10, 7) ==
            IntelP2PFirmware::TxLayout::kGen3);
    assert(IntelP2PFirmware::txLayout(
        IntelP2PFirmware::DeviceFamily::kAX210, 9, 7) ==
            IntelP2PFirmware::TxLayout::kUnsupported);
    assert(IntelP2PFirmware::txLayout(
        IntelP2PFirmware::DeviceFamily::k22000, 10, 7) ==
            IntelP2PFirmware::TxLayout::kUnsupported);
    assert(IntelP2PFirmware::txLayout(
        IntelP2PFirmware::DeviceFamily::kAX210, 10, 6) ==
            IntelP2PFirmware::TxLayout::kUnsupported);
    gDoorbells = gDoorbellMarkCalls = gMbufFrees = gStaReclaims = gDmaPostReads = 0;
    gDoorbellMarkResult = 0;

    // Rejected before queue prep: caller's frame is consumed exactly once.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        f.owner.gate = false;
        assert(f.submit(frame) == EBUSY);
        assert(gFreedById[id] == 1 && gDoorbells == 0);
        assert(f.lease.outstanding == 0 && f.ring()->data[0].m == nullptr);
        assert(atomicLoad(&f.context.submitDiagnostics.attemptCount) == 1);
        assert(atomicLoad(&f.context.submitDiagnostics.lastStage) ==
               static_cast<uint32_t>(TahoeP2PActionTxSubmitStage::kOwnerOrGate));
        assert(atomicLoad(&f.context.submitDiagnostics.lastResult) == EBUSY);
    }

    // TX firmware versions are selected together with the transport family;
    // a supported command number on another family must never reach the doorbell.
    {
        const unsigned beforeDoorbells = gDoorbells;
        const struct { int family; uint8_t command, notification; } profiles[] = {
            {IWX_DEVICE_FAMILY_AX210, 9, 7},
            {IWX_DEVICE_FAMILY_22000, 10, 7},
            {IWX_DEVICE_FAMILY_AX210, 10, 6},
        };
        for (const auto &profile : profiles) {
            Fixture f;
            f.owner.com.sc_device_family = profile.family;
            f.owner.txCommandVersion = profile.command;
            f.owner.txNotificationVersion = profile.notification;
            mbuf_t frame = makeFrame(); const unsigned id = frame->id;
            assert(f.submit(frame) == EOPNOTSUPP);
            assert(gFreedById[id] == 1 && gDoorbells == beforeDoorbells);
            assert(f.lease.outstanding == 0 && f.ring()->data[0].m == nullptr);
            assert(atomicLoad(&f.context.submitDiagnostics.lastStage) ==
                   static_cast<uint32_t>(TahoeP2PActionTxSubmitStage::kUnsupportedLayout));
        }
    }

    // Local DMA mapping failure after descriptor reservation cancels and frees once.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        f.cursor.result = 0;
        assert(f.submit(frame) == ENOMEM);
        assert(gFreedById[id] == 1 && gDoorbells == 0);
        assert(!f.lease.submissionBusy && f.lease.outstanding == 0);
        assert(f.ring()->data[0].m == nullptr && f.ring()->queued == 0);
        assert(atomicLoad(&f.context.submitDiagnostics.lastStage) ==
               static_cast<uint32_t>(TahoeP2PActionTxSubmitStage::kPayloadMapping));
    }

    // Doorbell transfers ownership to the ring; only matching TX_RSP frees it.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        uint8_t expectedHeader[24];
        std::memcpy(expectedHeader, frame->bytes.data(), sizeof(expectedHeader));
        assert(f.submit(frame) == 0);
        assert(gFreedById[id] == 0 && gDoorbells == 1);
        assert(gDoorbellMarkCalls == 1 && f.lease.everDoorbelled);
        assert(atomicLoad(&f.context.submitDiagnostics.lastStage) ==
               static_cast<uint32_t>(TahoeP2PActionTxSubmitStage::kDoorbellIssued));
        assert(atomicLoad(&f.context.submitDiagnostics.lastResult) == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->data[0].in == nullptr);
        assert(f.ring()->queued == 1 && f.lease.outstanding == 1);
        const auto *tx = reinterpret_cast<const iwx_tx_cmd_gen2 *>(
            f.ring()->cmd[0].data);
        assert(read16(reinterpret_cast<const uint8_t *>(tx) +
                      offsetof(iwx_tx_cmd_gen2, len)) == 41);
        assert(read16(reinterpret_cast<const uint8_t *>(tx) +
                      offsetof(iwx_tx_cmd_gen2, offload_assist)) == 0x0c00);
        assert(read32(reinterpret_cast<const uint8_t *>(tx) +
                      offsetof(iwx_tx_cmd_gen2, flags)) == 7);
        for (size_t i = offsetof(iwx_tx_cmd_gen2, dram_info);
             i < offsetof(iwx_tx_cmd_gen2, rate_n_flags); ++i)
            assert(reinterpret_cast<const uint8_t *>(tx)[i] == 0);
        const uint32_t expectedRate = (1U << 8) | (2U << IWX_RATE_MCS_ANT_POS);
        assert(read32(reinterpret_cast<const uint8_t *>(tx) +
                      offsetof(iwx_tx_cmd_gen2, rate_n_flags)) == expectedRate);
        assert(std::memcmp(reinterpret_cast<const uint8_t *>(tx) +
                           sizeof(iwx_tx_cmd_gen2), expectedHeader,
                           sizeof(expectedHeader)) == 0);
        const auto *descriptorBytes = reinterpret_cast<const uint8_t *>(
            &f.ring()->desc[0]);
        assert(read16(descriptorBytes) == 3);
        assert(read16(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       offsetof(iwx_tfh_tb, tb_len)) == 20);
        assert(read16(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 28);
        assert(read16(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       2 * sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 17);
        assert(f.ring()->byteCounts[0] == 41);
        iwx_rx_packet packet{}; packet.rawIndex = 0;
        makeResponse(packet, 12, 0x10);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == nullptr && f.ring()->queued == 0);
        assert(f.lease.outstanding == 0 && f.context.state == TahoeP2PActionTxState::kIdle);
        const auto &diag = f.context.rxDiagnostics;
        const uint64_t raw = atomicLoad(&diag.lastRawPacket);
        const uint32_t rawHeader = static_cast<uint32_t>(raw >> 32);
        assert(atomicLoad(&diag.armed) == 1);
        assert(atomicLoad(&diag.targetQueue) == 12);
        assert(atomicLoad(&diag.rawTxCmdCount) == 1);
        assert((rawHeader >> 24) == 1 && ((rawHeader >> 16) & 0xff) == 0x1c);
        assert(((rawHeader >> 8) & 0xff) == 0x8c && (rawHeader & 0xff) == 0);
        assert(static_cast<uint32_t>(raw) == 48);
        assert(atomicLoad(&diag.rawTargetHeaderCount) == 1);
        assert(atomicLoad(&diag.lastTargetRawPacket) == raw);
        assert(atomicLoad(&diag.lastResponseQueue) == 12);
        assert(atomicLoad(&diag.lastResponseFieldsValidMask) == 0x1ff);
        assert(atomicLoad(&diag.lastResponseFrameCount) == 1);
        assert(atomicLoad(&diag.lastResponseStatus) == 1);
        assert(atomicLoad(&diag.lastResponseSequenceControl) == 0x10);
        assert(atomicLoad(&diag.lastResponseByteCount) == 41);
        assert(atomicLoad(&diag.lastResponseFrameControl) == 0x00d0);
        assert(atomicLoad(&diag.lastResponseRaTid) == 0x3f);
        assert(atomicLoad(&diag.lastResponseScdSsn) == 1);
        assert(atomicLoad(&diag.lastResponseHeaderIndex) == 0);
        assert(atomicLoad(&diag.lastResponseHeaderIndexMatchesTicket) == 1);
        assert(atomicLoad(&diag.lastResponseMismatchMask) == 0);
        assert(atomicLoad(&diag.lastResponseExpectedSequenceControl) == 0x10);
        assert(atomicLoad(&diag.lastResponseExpectedByteCount) == 41);
        assert(atomicLoad(&diag.lastResponseExpectedFrameControl) == 0x00d0);
        assert(atomicLoad(&diag.lastResponseExpectedDescriptorIndex) == 0);
        assert(atomicLoad(&diag.lastResponseExpectedNextIndex) == 1);
        assert(atomicLoad(&diag.responseQueueMatchCount) == 1);
        assert(atomicLoad(&diag.handlerEntryCount) == 1);
        assert(atomicLoad(&diag.handlerQueueMatchCount) == 1);
        assert(atomicLoad(&diag.completionCount) == 1);
        assert(atomicLoad(&diag.rejectCount) == 0);
        assert(atomicLoad(&diag.lastCompletionResult) ==
               static_cast<uint32_t>(IntelP2PActionTx::Result::kCompletion));

        // Duplicate response for the installed P2P qid is consumed, not STA-reclaimed.
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1 && gStaReclaims == 0);
        assert(atomicLoad(&diag.rawTxCmdCount) == 2);
        assert(atomicLoad(&diag.handlerEntryCount) == 2);
        assert(atomicLoad(&diag.completionCount) == 1);
        assert(atomicLoad(&diag.rejectCount) == 1);
        assert(atomicLoad(&diag.lastRejectReason) ==
               static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kNoMatchingTicket));
    }

    // A failed doorbell mark proves no MMIO occurred. The exact armed ticket,
    // ring indices, queue reservation, and mbuf are all safely unwound.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        const unsigned beforeDoorbells = gDoorbells;
        gDoorbellMarkResult = EIO;
        assert(f.submit(frame) == EIO);
        gDoorbellMarkResult = 0;
        assert(gFreedById[id] == 1 && gDoorbells == beforeDoorbells);
        assert(gDoorbellMarkCalls > 0 && !f.lease.everDoorbelled);
        assert(!f.lease.submissionBusy && f.lease.outstanding == 0);
        assert(f.ring()->cur == 0 && f.ring()->tail == 0 &&
               f.ring()->queued == 0 && f.ring()->data[0].m == nullptr);
        assert(f.context.state == TahoeP2PActionTxState::kIdle);
        assert(!f.context.completion.snapshot().armed);
        assert(atomicLoad(&f.context.rxDiagnostics.armed) == 0);
        assert(atomicLoad(&f.context.submitDiagnostics.lastStage) ==
               static_cast<uint32_t>(TahoeP2PActionTxSubmitStage::kDoorbellMark));
        assert(atomicLoad(&f.context.submitDiagnostics.lastResult) == EIO);
    }

    // Sequence-control and SCD next-index disagreements remain distinct
    // numeric signals even when the firmware response itself is failed.
    {
        Fixture f; mbuf_t frame = makeFrame();
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; packet.rawIndex = 0;
        makeResponse(packet, 12, 0x20, 1, 41, 0x00d0, 1);
        assert(dispatch(f, packet));
        const auto &diag = f.context.rxDiagnostics;
        assert(atomicLoad(&diag.lastResponseSequenceControl) == 0x20);
        assert(atomicLoad(&diag.lastResponseExpectedSequenceControl) == 0x10);
        assert(atomicLoad(&diag.lastResponseMismatchMask) == 0x01);
        testCleanupAfterProvenDrain(f);
    }
    {
        Fixture f; mbuf_t frame = makeFrame();
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; packet.rawIndex = 0;
        makeResponse(packet, 12, 0x10, 1, 41, 0x00d0, 2);
        assert(dispatch(f, packet));
        const auto &diag = f.context.rxDiagnostics;
        assert(atomicLoad(&diag.lastResponseSequenceControl) == 0x10);
        assert(atomicLoad(&diag.lastResponseExpectedNextIndex) == 1);
        assert(atomicLoad(&diag.lastResponseScdSsn) == 2);
        assert(atomicLoad(&diag.lastResponseMismatchMask) == 0x02);
        testCleanupAfterProvenDrain(f);
    }

    // A foreign-qid notification must leave the last target numeric tuple intact.
    {
        Fixture f; mbuf_t frame = makeFrame();
        assert(f.submit(frame) == 0);
        iwx_rx_packet target{}; target.rawIndex = 0;
        makeResponse(target, 12, 0x10, 1, 41, 0x00d0, 2);
        assert(dispatch(f, target));
        auto &diag = f.context.rxDiagnostics;
        const uint32_t expectedFields[] = {
            atomicLoad(&diag.lastResponseFieldsValidMask),
            atomicLoad(&diag.lastResponseFrameCount),
            atomicLoad(&diag.lastResponseStatus),
            atomicLoad(&diag.lastResponseSequenceControl),
            atomicLoad(&diag.lastResponseByteCount),
            atomicLoad(&diag.lastResponseFrameControl),
            atomicLoad(&diag.lastResponseRaTid),
            atomicLoad(&diag.lastResponseScdSsn),
            atomicLoad(&diag.lastResponseHeaderIndex),
            atomicLoad(&diag.lastResponseHeaderIndexMatchesTicket),
            atomicLoad(&diag.lastResponseMismatchMask),
            atomicLoad(&diag.lastResponseExpectedSequenceControl),
            atomicLoad(&diag.lastResponseExpectedByteCount),
            atomicLoad(&diag.lastResponseExpectedFrameControl),
            atomicLoad(&diag.lastResponseExpectedDescriptorIndex),
            atomicLoad(&diag.lastResponseExpectedNextIndex),
        };
        iwx_rx_packet foreign{};
        makeResponse(foreign, 13, 0x10);
        assert(!dispatch(f, foreign));
        const uint32_t actualFields[] = {
            atomicLoad(&diag.lastResponseFieldsValidMask),
            atomicLoad(&diag.lastResponseFrameCount),
            atomicLoad(&diag.lastResponseStatus),
            atomicLoad(&diag.lastResponseSequenceControl),
            atomicLoad(&diag.lastResponseByteCount),
            atomicLoad(&diag.lastResponseFrameControl),
            atomicLoad(&diag.lastResponseRaTid),
            atomicLoad(&diag.lastResponseScdSsn),
            atomicLoad(&diag.lastResponseHeaderIndex),
            atomicLoad(&diag.lastResponseHeaderIndexMatchesTicket),
            atomicLoad(&diag.lastResponseMismatchMask),
            atomicLoad(&diag.lastResponseExpectedSequenceControl),
            atomicLoad(&diag.lastResponseExpectedByteCount),
            atomicLoad(&diag.lastResponseExpectedFrameControl),
            atomicLoad(&diag.lastResponseExpectedDescriptorIndex),
            atomicLoad(&diag.lastResponseExpectedNextIndex),
        };
        assert(std::memcmp(expectedFields, actualFields,
                           sizeof(expectedFields)) == 0);
        testCleanupAfterProvenDrain(f);
    }

    // TX_CMD v9 encodes 24-byte and 28-byte MAC headers in 16-bit units.
    // These are wire values from Linux's mh_len /= 2 contract: 0x0c00/0x0e00.
    {
        Fixture f; mbuf_t frame = makeHtFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        const uint8_t *command = f.ring()->cmd[0].data;
        assert(read16(command + offsetof(iwx_tx_cmd_gen2, len)) == 45);
        assert(read16(command + offsetof(iwx_tx_cmd_gen2, offload_assist)) == 0x0e00);
        assert(std::memcmp(command + sizeof(iwx_tx_cmd_gen2),
                           frame->bytes.data(), 28) == 0);
        const uint8_t *descriptor = reinterpret_cast<const uint8_t *>(
            &f.ring()->desc[0]);
        assert(read16(descriptor + offsetof(iwx_tfh_tfd, tbs) +
                      sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 32);
        assert(read16(descriptor + offsetof(iwx_tfh_tfd, tbs) +
                      2 * sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 17);
        assert(f.ring()->byteCounts[0] == 45);
        iwx_rx_packet packet{}; packet.rawIndex = 0;
        makeResponse(packet, 12, 0x10, 1, 45, 0x80d0);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1 && f.ring()->queued == 0);
    }

    // AX210 TX_CMD v10 uses the 28-byte gen3 header while retaining the
    // v7 TX_RSP completion layout and the same ownership/reclaim rules.
    {
        Fixture f;
        f.owner.com.sc_device_family = IWX_DEVICE_FAMILY_AX210;
        f.owner.txCommandVersion = 10;
        mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        uint8_t expectedHeader[24];
        std::memcpy(expectedHeader, frame->bytes.data(), sizeof(expectedHeader));
        assert(f.submit(frame) == 0);
        assert(gFreedById[id] == 0 && gDoorbells > 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        const uint8_t *command = f.ring()->cmd[0].data;
        assert(read16(command + offsetof(iwx_tx_cmd_gen3, len)) == 41);
        assert(read16(command + offsetof(iwx_tx_cmd_gen3, flags)) == 7);
        assert(read32(command + offsetof(iwx_tx_cmd_gen3, offload_assist)) == 0x0c00);
        for (size_t i = offsetof(iwx_tx_cmd_gen3, dram_info);
             i < offsetof(iwx_tx_cmd_gen3, rate_n_flags); ++i)
            assert(command[i] == 0);
        const uint32_t expectedRate = (1U << 8) | (2U << IWX_RATE_MCS_ANT_POS);
        assert(read32(command + offsetof(iwx_tx_cmd_gen3, rate_n_flags)) ==
               expectedRate);
        for (size_t i = offsetof(iwx_tx_cmd_gen3, ttl);
             i < sizeof(iwx_tx_cmd_gen3); ++i)
            assert(command[i] == 0);
        assert(std::memcmp(command + sizeof(iwx_tx_cmd_gen3), expectedHeader,
                           sizeof(expectedHeader)) == 0);

        const auto *descriptor = &f.ring()->desc[0];
        const auto *descriptorBytes = reinterpret_cast<const uint8_t *>(descriptor);
        assert(read16(descriptorBytes) == 3);
        assert(read16(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       offsetof(iwx_tfh_tb, tb_len)) == 20);
        assert(read64(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       offsetof(iwx_tfh_tb, addr)) == 0x100000);
        assert(read16(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 36);
        assert(read64(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, addr)) ==
               0x100014);
        assert(read16(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       2 * sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 17);
        assert(read64(descriptorBytes + offsetof(iwx_tfh_tfd, tbs) +
                       2 * sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, addr)) ==
               0x200000);
        assert(f.ring()->byteCounts[0] == 41);

        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == nullptr && f.ring()->queued == 0);
        assert(f.lease.outstanding == 0 &&
               f.context.state == TahoeP2PActionTxState::kIdle);
    }

    {
        Fixture f;
        f.owner.com.sc_device_family = IWX_DEVICE_FAMILY_AX210;
        f.owner.txCommandVersion = 10;
        mbuf_t frame = makeHtFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        const uint8_t *command = f.ring()->cmd[0].data;
        assert(read16(command + offsetof(iwx_tx_cmd_gen3, len)) == 45);
        assert(read32(command + offsetof(iwx_tx_cmd_gen3, offload_assist)) == 0x0e00);
        assert(std::memcmp(command + sizeof(iwx_tx_cmd_gen3),
                           frame->bytes.data(), 28) == 0);
        const uint8_t *descriptor = reinterpret_cast<const uint8_t *>(
            &f.ring()->desc[0]);
        assert(read16(descriptor + offsetof(iwx_tfh_tfd, tbs) +
                      sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 40);
        assert(read16(descriptor + offsetof(iwx_tfh_tfd, tbs) +
                      2 * sizeof(iwx_tfh_tb) + offsetof(iwx_tfh_tb, tb_len)) == 17);
        assert(f.ring()->byteCounts[0] == 45);
        iwx_rx_packet packet{}; packet.rawIndex = 0;
        makeResponse(packet, 12, 0x10, 1, 45, 0x80d0);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1 && f.ring()->queued == 0);
    }

    // A matching-qid but truncated TX_RSP is quarantined and never reclaimed by STA.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        packet.payloadLength = 44; // queue/status present, trailing SCD SSN missing
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 0 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        assert(atomicLoad(&f.context.rxDiagnostics.rawTxCmdCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.handlerEntryCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.handlerQueueMatchCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.rejectCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.lastRejectReason) ==
               static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kCompletionRejected));
        assert(atomicLoad(&f.context.rxDiagnostics.lastCompletionResult) ==
               static_cast<uint32_t>(IntelP2PActionTx::Result::kMalformedResponse));
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseFieldsValidMask) ==
               0x1bf);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseFrameCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseStatus) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseSequenceControl) == 0x10);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseByteCount) == 41);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseFrameControl) == 0x00d0);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseRaTid) == 0x3f);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseScdSsn) == 0xffffffffu);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseMismatchMask) == 0);
        assert(atomicLoad(&f.context.rxDiagnostics.completionCount) == 0);
        assert(f.lease.outstanding == 1);
        testCleanupAfterProvenDrain(f);
    }

    // A valid-looking response for a different qid is foreign: it cannot
    // complete or release the stationless descriptor owned by qid 12.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        __atomic_store_n(&f.context.rxDiagnostics.dirty, 0u, __ATOMIC_RELEASE);
        iwx_rx_packet packet{}; makeResponse(packet, 13, 0x10);
        assert(!dispatch(f, packet));
        assert(gFreedById[id] == 0 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.lease.outstanding == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.rawTxCmdCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.handlerEntryCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.handlerForeignCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.rawTargetHeaderCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.completionCount) == 0);
        assert(atomicLoad(&f.context.rxDiagnostics.rejectCount) == 0);
        assert(atomicLoad(&f.context.rxDiagnostics.dirty) == 0);
        testCleanupAfterProvenDrain(f);
    }

    // Host sentinel 8 is not the firmware management TID. Even a matching
    // qid and descriptor must not let such a response release the DMA owner.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        packet.data[33] = 0x38;
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 0 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.lease.outstanding == 1);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        testCleanupAfterProvenDrain(f);
    }

    // Same qid and management TID are insufficient: only RA/station 3 from
    // the P2P lease can complete its ticket. A wrong-station response is
    // consumed and quarantines the owner; a later otherwise-valid response
    // cannot revive that ticket or free its mbuf.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        packet.data[33] = 0x4f; // station 4, firmware management TID 15
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 0 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.ring()->tail == 0 && f.lease.outstanding == 1);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        assert(atomicLoad(&f.context.rxDiagnostics.lastResponseRaTid) == 0x4f);
        assert(atomicLoad(&f.context.rxDiagnostics.completionCount) == 0);
        assert(atomicLoad(&f.context.rxDiagnostics.lastRejectReason) ==
               static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kNoMatchingTicket));

        packet.data[33] = 0x3f; // late station 3 response for quarantined ticket
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 0 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.lease.outstanding == 1 && f.context.state ==
               TahoeP2PActionTxState::kQuarantined);
        assert(atomicLoad(&f.context.rxDiagnostics.completionCount) == 0);
        assert(atomicLoad(&f.context.rxDiagnostics.rejectCount) == 2);
        assert(atomicLoad(&f.context.rxDiagnostics.lastRejectReason) ==
               static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kNoMatchingTicket));
        testCleanupAfterProvenDrain(f);
    }

    // A response whose qid conflicts with the action ticket is consumed/quarantined.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        f.context.queueId = 13; // damaged/stale ticket; lease still identifies P2P qid 12
        iwx_rx_packet packet{}; makeResponse(packet, 13, 0x10);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 0 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == frame);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        testCleanupAfterProvenDrain(f);
    }

    // A post-doorbell bookkeeping error cannot free the frame or descriptor.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        f.lease.finishResult = EIO;
        assert(f.submit(frame) == 0);
        assert(gFreedById[id] == 0 && f.ring()->data[0].m == frame);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        testCleanupAfterProvenDrain(f);
    }

    // Failure status is still a terminal TX response: free once, never STA reclaim.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10, 3);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1 && gStaReclaims == 0);
        assert(f.ring()->data[0].m == nullptr && f.ring()->queued == 0);
        assert(!f.context.completion.snapshot().frameAttemptSucceeded);
    }

    // Too-short to identify a qid falls through; both completion and generic
    // paths leave the in-flight DMA owner untouched.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{};
        packet.payloadLength = 37; packet.data[0] = 1;
        assert(!dispatch(f, packet));
        assert(gStaReclaims == 0);
        assert(gFreedById[id] == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.lease.outstanding == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.rawTxCmdCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.shortResponseCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.handlerEntryCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.rejectCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.lastRejectReason) ==
               static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kShortPayload));
        assert(atomicLoad(&f.context.rxDiagnostics.completionCount) == 0);
        testCleanupAfterProvenDrain(f);
    }

    // A completed Action response duplicated during Releasing is consumed
    // while the queue lease still reserves its qid and the DMA ring is freed.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{}; makeResponse(packet, 12, 0x10);
        assert(dispatch(f, packet));
        assert(gFreedById[id] == 1);
        f.lease.state = TahoeP2PResourceState::kReleasing;
        assert(dispatch(f, packet));
        assert(gStaReclaims == 0 && !f.queueLock.locked);

        // After release, late P2P station replies remain tombstoned.
        f.lease.state = TahoeP2PResourceState::kAbsent;
        f.lease.ringInstalled = false;
        f.ring()->qid = -1;
        f.ring()->ring_count = 0;
        assert(dispatch(f, packet));
        assert(gStaReclaims == 0);

        // A real STA may reuse the same qid; its own station identity passes.
        f.ring()->qid = 12;
        f.ring()->ring_count = 8;
        f.ring()->queued = 1;
        assert(dispatch(f, packet)); // stale P2P reply cannot touch the reused STA
        assert(gStaReclaims == 0 && f.ring()->queued == 1);
        packet.data[offsetof(iwx_tx_resp, ra_tid)] = 0x0f;
        assert(!dispatch(f, packet));
        assert(gStaReclaims == 1);
    }

    // Generic TX_RSP qid and ring guards reject invalid inputs before access.
    {
        iwx_softc sc{};
        iwx_rx_packet packet{};
        makeResponse(packet, 0xffff, 0x10);
        genericStaFallback(sc, packet);
        assert(gStaReclaims == 1);

        sc.txq[4].qid = 4;
        sc.txq[4].ring_count = 0;
        makeResponse(packet, 4, 0x10);
        genericStaFallback(sc, packet);
        assert(gStaReclaims == 1);

        sc.txq[4].ring_count = 8;
        sc.txq[4].queued = 0;
        genericStaFallback(sc, packet);
        assert(gStaReclaims == 1);

        sc.txq[4].queued = 1;
        sc.txq[4].ring_count = 17;
        genericStaFallback(sc, packet);
        assert(gStaReclaims == 1);
    }

    // An out-of-range firmware qid is consumed before generic code can index
    // sc->txq[qid], while the experiment's DMA owner remains retained.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_rx_packet packet{};
        makeResponse(packet, 0xffff, 0x10);
        assert(dispatch(f, packet));
        assert(gStaReclaims == 1);
        assert(gFreedById[id] == 0);
        assert(f.ring()->data[0].m == frame && f.ring()->queued == 1);
        assert(f.lease.outstanding == 1);
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined);
        assert(atomicLoad(&f.context.rxDiagnostics.rawTxCmdCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.outOfRangeQueueCount) == 1);
        assert(atomicLoad(&f.context.rxDiagnostics.completionCount) == 0);
        assert(atomicLoad(&f.context.rxDiagnostics.lastRejectReason) ==
               static_cast<uint32_t>(TahoeP2PTxRxRejectReason::kQueueOutOfRange));
        testCleanupAfterProvenDrain(f);
    }

    // A valid TX_RSP for a different qid remains on the generic STA path even
    // while the P2P queue is active; it must not claim the P2P ticket/ring.
    {
        Fixture f; mbuf_t frame = makeFrame(); const unsigned id = frame->id;
        assert(f.submit(frame) == 0);
        iwx_tx_ring *staRing = &f.owner.com.txq[13];
        staRing->qid = 13; staRing->ring_count = 8; staRing->queued = 1;
        iwx_rx_packet packet{}; makeResponse(packet, 13, 0x10);
        const unsigned beforeReclaims = gStaReclaims;
        assert(!dispatch(f, packet));
        assert(gStaReclaims == beforeReclaims + 1);
        assert(gFreedById[id] == 0 && f.ring()->data[0].m == frame);
        assert(f.ring()->queued == 1 && f.lease.outstanding == 1);
        assert(f.context.state == TahoeP2PActionTxState::kInFlight);
        testCleanupAfterProvenDrain(f);
    }

    // A real hard stop is the retirement proof even when this generation has
    // never armed a completion ticket. Startup must not quarantine an empty
    // action context merely because its generation is still zero.
    {
        TahoeP2PActionTxContext context;
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 5, true);
        assert(context.state == TahoeP2PActionTxState::kIdle);
        assert(!context.completion.snapshot().armed);
        assert(context.drainDiagnostics.eventCount == 1);
        assert(context.drainDiagnostics.lastResult ==
               static_cast<int32_t>(IntelP2PActionTx::Result::kReady));
        assert(context.drainDiagnostics.lastContextGeneration == 0);
        assert(context.drainDiagnostics.lastTicketFlags == 0);
        assert(context.drainDiagnostics.lastHardStop == 1);
        // Repeating an empty hard-stop retirement is safe and remains idle.
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 5, true);
        assert(context.state == TahoeP2PActionTxState::kIdle);
        assert(context.drainDiagnostics.eventCount == 2);
    }
    // The hook refuses to retire any state when the caller lacks positive
    // firmware/RX/TX/DMA-stop evidence.
    {
        TahoeP2PActionTxContext context;
        context.generation = 7;
        context.nativeDataToken = 0x1234;
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 8, false);
        assert(context.state == TahoeP2PActionTxState::kQuarantined);
        assert(context.nativeDataToken == 0x1234);
        assert(!context.completion.snapshot().armed);
        assert(context.drainDiagnostics.lastResult ==
               static_cast<int32_t>(IntelP2PActionTx::Result::kInvalid));
        assert(context.drainDiagnostics.lastHardStop == 0);
    }
    // Same-generation hard-stop evidence cannot retire a live ticket. A later
    // proven drain in a different generation may safely release it.
    {
        TahoeP2PActionTxContext context;
        context.generation = 7;
        context.nativeDataToken = 0x5678;
        assert(context.completion.arm(7, 12, 8, 0, 0x40, 100, 0x00d0) ==
               IntelP2PActionTx::Result::kReady);
        context.state = TahoeP2PActionTxState::kInFlight;
        // A zero generation or a generation change without hard-stop proof
        // cannot release a live ticket or its data token.
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 0, true);
        assert(context.state == TahoeP2PActionTxState::kQuarantined);
        assert(context.completion.snapshot().armed);
        assert(context.nativeDataToken == 0x5678);
        assert(context.drainDiagnostics.lastResult ==
               static_cast<int32_t>(IntelP2PActionTx::Result::kInvalid));
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 8, false);
        assert(context.state == TahoeP2PActionTxState::kQuarantined);
        assert(context.completion.snapshot().armed);
        assert(context.nativeDataToken == 0x5678);
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 7, true);
        assert(context.state == TahoeP2PActionTxState::kQuarantined);
        assert(context.completion.snapshot().armed);
        assert(context.nativeDataToken == 0x5678);
        assert(context.drainDiagnostics.lastTicketFlags == 1);
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 8, true);
        assert(context.state == TahoeP2PActionTxState::kIdle);
        assert(!context.completion.snapshot().armed);
        assert(context.nativeDataToken == 0);
        assert(context.generation == 8);
    }
    // A completed ticket can be retired in the same generation because the
    // hardware stop is independently proven by this hook's argument.
    {
        TahoeP2PActionTxContext context;
        context.generation = 7;
        assert(context.completion.arm(7, 12, 8, 0, 0x40, 100, 0x00d0) ==
               IntelP2PActionTx::Result::kReady);
        iwx_rx_packet packet{};
        makeResponse(packet, 12, 0x40, 1, 100, 0x00d0, 1);
        assert(context.completion.complete(7, packet.data, packet.payloadLength,
            offsetof(iwx_tx_resp, status), offsetof(iwx_tx_resp, seq_ctl),
            offsetof(iwx_tx_resp, byte_cnt), offsetof(iwx_tx_resp, frame_ctrl),
            offsetof(iwx_tx_resp, tx_queue), offsetof(iwx_tx_resp, status) + 4) ==
            IntelP2PActionTx::Result::kCompletion);
        iwx_tahoe_p2p_action_tx_firmware_drained(&context, 7, true);
        assert(context.state == TahoeP2PActionTxState::kIdle);
        assert(!context.completion.snapshot().armed);
        assert(context.drainDiagnostics.lastTicketFlags == 7);
    }

    assert(gMbufIds.empty());
    std::puts("production P2P Action submit/RX ownership fault tests passed");
}
"""


def main():
    source_guard = GENERIC_SOURCE
    assert "#define IWX_TX_RES_GET_TID(_ra_tid) ((_ra_tid) & 0x0f)" in REG_SOURCE
    assert "#define IWX_TX_RES_GET_RA(_ra_tid) ((_ra_tid) >> 4)" in REG_SOURCE
    rx_dispatch = source_guard.index("iwx_rx_pkt(struct iwx_softc *sc,")
    raw_observer = source_guard.index(
        "iwx_tahoe_p2p_action_tx_observe_rx(", rx_dispatch)
    packet_valid = source_guard.index("if (!iwx_rx_pkt_valid(pkt))", rx_dispatch)
    long_group_normalization = source_guard.index(
        "if (iwx_cmd_groupid(code) == IWX_LONG_GROUP)", rx_dispatch)
    length_guard = source_guard.index("if (len < minsz ||", rx_dispatch)
    dispatch_switch = source_guard.index("switch (code)", rx_dispatch)
    response_case = source_guard.index("case IWX_TX_CMD:")
    generic = source_guard.index("iwx_rx_tx_cmd(sc, pkt, data);", response_case)
    assert (rx_dispatch < packet_valid < long_group_normalization < length_guard <
            raw_observer < dispatch_switch < response_case < generic)
    assert source_guard.rfind("iwx_tahoe_p2p_action_tx_response(", response_case, generic) >= response_case
    generic_handler = source_guard.index("iwx_rx_tx_cmd(struct iwx_softc")
    # The guards retain their original return, with an observation-only
    # reason inside the block. Inspect the complete guarded block rather
    # than requiring the pre-instrumentation brace/whitespace spelling.
    handler = source_guard[generic_handler:]
    length_exit = extract_function(handler, "if (requiredLength > payloadLength)")
    ring_exit = extract_function(handler, "if (!iwx_tx_response_ring(sc, queueId, &ring))")
    assert length_exit.count("return;") == 1
    assert "IWX_TX_COMPLETION_TX_RSP_DECLARED_LENGTH_TRUNCATED" in length_exit
    assert ring_exit.count("return;") == 1
    assert "IWX_TX_COMPLETION_TX_RSP_QUEUE_OR_RING_UNADDRESSABLE" in ring_exit
    assert "!iwx_tx_response_index(queueId, ring, ssn, &checkedIndex)" in source_guard[generic_handler:]
    with tempfile.TemporaryDirectory(prefix="itl-p2p-action-hal-") as temp:
        cpp = Path(temp) / "action_hal_test.cpp"
        binary = Path(temp) / "action_hal_test"
        cpp.write_text(SHIM + "\n" + production_helpers + "\n" +
                       production_generic_helpers + "\n" +
                       production_functions + "\n" + BODY)
        subprocess.run([
            "c++", "-std=c++11", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-function", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(ROOT), str(cpp),
            str(ROOT / "native/p2p_action_tx.cpp"),
            str(ROOT / "native/awdl_action_frame.cpp"),
            str(ROOT / "native/awdl_action_encode.cpp"),
            str(ROOT / "native/awdl_mif_encode.cpp"), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
