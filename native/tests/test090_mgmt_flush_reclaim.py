#!/usr/bin/env python3
"""Exercise the production STA flush handler's fixed management-queue case."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


production = extract_function(
    SOURCE.read_text(), "int ItlIwx::\niwx_flush_sta_tids("
)
assert "tid == IWX_MGMT_TID &&" in production
assert "sta_id == IWX_STATION_ID &&" in production
assert "qid == sc->first_data_qid" in production
assert production.index("iwx_tahoe_p2p_tvqm_queue_owned") < production.index(
    "const bool managementQueue"
)
assert "IwxTxRingCapacity::flushQueueCanReclaim(" in production
assert "IwxTxRingCapacity::reclaimIndexWithinQueuedRange(" in production
assert production.index("reclaimIndexWithinQueuedRange(") < production.index(
    "iwx_ampdu_txq_advance(sc, txq, reclaimIndex)"
)

cpp = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "iwx_tx_ring_capacity.hpp"

#define AIRPORT_TAHOE 1
#define IWX_CMD_FAILED_MSK 0x80
#define IWX_CMD_WANT_RESP 1
#define IWX_TXPATH_FLUSH 0x1234
#define IWX_TX_FLUSH_QUEUE_RSP 16
#define IWX_INVALID_QUEUE 0xffff
#define IWX_STATION_ID 0
#define IWX_MGMT_TID 15
#define IWX_MAX_TID_COUNT 8
#define IWX_TX_PROGRESS_FLUSH_RECLAIM 1
#define IWX_TX_PROGRESS_HAS_QID 1
#define IWX_TX_PROGRESS_HAS_INDEX 2
#define IWX_TX_PROGRESS_HAS_RING_COUNT 4
#define IWX_TX_PROGRESS_HAS_QUEUED 8
#define IWX_TX_PROGRESS_HAS_CUR 16
#define IWX_TX_PROGRESS_HAS_TAIL 32
#define nitems(a) (sizeof(a) / sizeof((a)[0]))

static uint16_t htole16(uint16_t value) { return value; }
static uint32_t htole32(uint32_t value) { return value; }
static uint16_t le16toh(uint16_t value) { return value; }

struct iwx_tx_path_flush_cmd {
    uint32_t sta_id;
    uint16_t tid_mask;
    uint16_t reserved;
} __attribute__((packed));
struct iwx_flush_queue_info {
    uint16_t tid, queue_num, read_before_flush, read_after_flush;
} __attribute__((packed));
struct iwx_tx_path_flush_cmd_rsp {
    uint16_t sta_id, num_flushed_queues;
    iwx_flush_queue_info queues[IWX_TX_FLUSH_QUEUE_RSP];
} __attribute__((packed));
struct iwx_cmd_header { uint8_t group_id = 0; };
struct iwx_rx_packet {
    iwx_cmd_header hdr{};
    uint8_t data[sizeof(iwx_tx_path_flush_cmd_rsp)]{};
    size_t payloadLength = sizeof(iwx_tx_path_flush_cmd_rsp);
};
struct iwx_host_cmd {
    uint32_t id = 0;
    size_t len[1]{};
    void *data[1]{};
    uint32_t flags = 0;
    size_t resp_pkt_len = 0;
    iwx_rx_packet *resp_pkt = nullptr;
};
struct iwx_tx_data { uint8_t unused = 0; };
struct iwx_tx_ring {
    int qid = IWX_INVALID_QUEUE;
    uint16_t ring_count = 0;
    int queued = 0, cur = 0, tail = 0;
    iwx_tx_data data[1024]{};
};
struct iwx_tid_data { uint16_t qid = IWX_INVALID_QUEUE; };
struct iwx_softc {
    iwx_tx_ring txq[8]{};
    iwx_tid_data sc_tid_data[IWX_MAX_TID_COUNT + 1]{};
    int first_data_qid = 1;
};
struct TahoeP2PTxQueueLease { bool owned = false; uint16_t qid = IWX_INVALID_QUEUE; };
static bool iwx_tahoe_p2p_tvqm_queue_owned(
    TahoeP2PTxQueueLease *lease, uint16_t qid) {
    return lease && lease->owned && lease->qid == qid;
}

static iwx_rx_packet responsePacket{};
static iwx_tx_path_flush_cmd_rsp response{};
static unsigned advances = 0, reclaimedSlots = 0, freedResponses = 0;
static uint16_t advancedQid = IWX_INVALID_QUEUE;
static uint16_t advancedIndex = IWX_INVALID_QUEUE;
static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *packet) {
    return packet ? packet->payloadLength : 0;
}

static void recordTxProgressEvent(
    iwx_softc *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t, bool) {}

class ItlIwx {
public:
    TahoeP2PTxQueueLease nativeP2pTxQueue_{};
    int iwx_send_cmd(iwx_softc *, iwx_host_cmd *command) {
        responsePacket = {};
        std::memcpy(responsePacket.data, &response, sizeof(response));
        command->resp_pkt = &responsePacket;
        return 0;
    }
    void iwx_free_resp(iwx_softc *, iwx_host_cmd *command) {
        ++freedResponses;
        command->resp_pkt = nullptr;
    }
    void iwx_ampdu_txq_advance(iwx_softc *, iwx_tx_ring *ring, int index) {
        ++advances;
        advancedQid = static_cast<uint16_t>(ring->qid);
        advancedIndex = static_cast<uint16_t>(index);
        while (ring->tail != index) {
            assert(ring->queued > 0);
            ring->tail = (ring->tail + 1) % ring->ring_count;
            --ring->queued;
            ++reclaimedSlots;
        }
    }
    int iwx_flush_sta_tids(iwx_softc *, int, uint16_t);
};

// PRODUCTION_FUNCTION

static void reset(ItlIwx &owner, iwx_softc &sc) {
    owner.nativeP2pTxQueue_ = {};
    sc = {};
    for (uint16_t qid = 0; qid < nitems(sc.txq); ++qid) {
        sc.txq[qid].qid = qid;
        sc.txq[qid].ring_count = 8;
        sc.txq[qid].queued = 2;
        sc.txq[qid].cur = 3;
        sc.txq[qid].tail = 1;
    }
    response = {};
    response.sta_id = IWX_STATION_ID;
    response.num_flushed_queues = 1;
    advances = reclaimedSlots = freedResponses = 0;
    advancedQid = advancedIndex = IWX_INVALID_QUEUE;
}

static void setQueue(uint16_t tid, uint16_t qid, uint16_t readAfter) {
    response.queues[0] = {tid, qid, 1, readAfter};
}

int main() {
    ItlIwx owner{};
    iwx_softc sc{};

    // Firmware TID 15 is accepted only for the configured STA mgmt qid.
    reset(owner, sc);
    setQueue(IWX_MGMT_TID, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 1 && advancedQid == 1 && advancedIndex == 2);
    assert(sc.txq[1].tail == 2 && sc.txq[1].queued == 1);
    assert(reclaimedSlots == 1 && freedResponses == 1);

    // A non-STA caller cannot use the fixed STA management queue exception.
    reset(owner, sc);
    response.sta_id = 1;
    setQueue(IWX_MGMT_TID, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, 1, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0);
    assert(sc.txq[1].tail == 1 && freedResponses == 1);

    // A TID-15 response on any other queue must not reclaim a data/AUX ring.
    reset(owner, sc);
    setQueue(IWX_MGMT_TID, 2, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && sc.txq[2].tail == 1);

    // Preserve the P2P owner fence even if firmware names the fixed mgmt qid.
    reset(owner, sc);
    owner.nativeP2pTxQueue_ = {true, 1};
    setQueue(IWX_MGMT_TID, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == EBUSY);
    assert(advances == 0 && sc.txq[1].tail == 1);

    // Other invalid TIDs and bad ring identity/SSN shape remain fail-closed.
    reset(owner, sc);
    setQueue(IWX_MAX_TID_COUNT + 1, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0);
    reset(owner, sc);
    sc.txq[1].qid = 2;
    setQueue(IWX_MGMT_TID, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0);
    reset(owner, sc);
    sc.txq[1].ring_count = 0;
    setQueue(IWX_MGMT_TID, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0);

    // A wrapped index at the end of the submitted interval is reclaimable.
    reset(owner, sc);
    sc.txq[1].tail = 6;
    sc.txq[1].queued = 3;
    sc.txq[1].cur = 1;
    setQueue(IWX_MGMT_TID, 1, 1);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 1 && advancedIndex == 1 && reclaimedSlots == 3);
    assert(sc.txq[1].tail == 1 && sc.txq[1].queued == 0);

    // AX210 cur/read_after are 16-bit SSNs, not physical ring indices.
    // A valid 40-entry interval may cross the 1024-slot ring boundary.
    reset(owner, sc);
    sc.txq[1].ring_count = 1024;
    sc.txq[1].tail = 1000;
    sc.txq[1].queued = 40;
    sc.txq[1].cur = 1040;
    setQueue(IWX_MGMT_TID, 1, 1040);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 1 && advancedIndex == 16 && reclaimedSlots == 40);

    // SSN wrap at 65535->0 preserves the same physical index mapping.
    reset(owner, sc);
    sc.txq[1].ring_count = 1024;
    sc.txq[1].tail = 1000;
    sc.txq[1].queued = 40;
    sc.txq[1].cur = 16;
    setQueue(IWX_MGMT_TID, 1, 16);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 1 && advancedIndex == 16 && reclaimedSlots == 40);

    // An index beyond cur is outside the flushed host submission interval.
    reset(owner, sc);
    setQueue(IWX_MGMT_TID, 1, 4);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0 && sc.txq[1].tail == 1);

    // Empty queue at tail is valid and must not reclaim a descriptor.
    reset(owner, sc);
    sc.txq[1].queued = 0;
    sc.txq[1].cur = sc.txq[1].tail = 4;
    setQueue(IWX_MGMT_TID, 1, 4);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 1 && reclaimedSlots == 0 && sc.txq[1].tail == 4);

    // This ring keeps a spare slot; a full or inconsistent ring snapshot is rejected.
    reset(owner, sc);
    sc.txq[1].queued = 8;
    sc.txq[1].cur = sc.txq[1].tail;
    setQueue(IWX_MGMT_TID, 1, sc.txq[1].tail);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0);
    reset(owner, sc);
    sc.txq[1].cur = 4;
    setQueue(IWX_MGMT_TID, 1, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 0 && reclaimedSlots == 0);

    // Existing data-TID mapping still uses the original qid match and SSN.
    reset(owner, sc);
    sc.sc_tid_data[4].qid = 3;
    setQueue(4, 3, 2);
    assert(owner.iwx_flush_sta_tids(&sc, IWX_STATION_ID, 0xffff) == 0);
    assert(advances == 1 && advancedQid == 3 && advancedIndex == 2);
    assert(reclaimedSlots == 1 && freedResponses == 1);
    return 0;
}
"""

cpp = cpp.replace("// PRODUCTION_FUNCTION", production)
with tempfile.TemporaryDirectory(prefix="test090-mgmt-flush-") as temp:
    source = pathlib.Path(temp) / "test.cpp"
    binary = pathlib.Path(temp) / "test"
    source.write_text(cpp)
    subprocess.run([
        "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT / "native"), "-o", str(binary), str(source),
    ], check=True)
    subprocess.run([str(binary)], check=True)
print("STA management TXPATH_FLUSH host cases passed (ASan/UBSan)")
