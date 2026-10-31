#!/usr/bin/env python3
"""Compile and execute Test075's production TX ring guards with sanitizers."""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import textwrap


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
RING_HEADER = ROOT / "native/iwx_tx_ring_capacity.hpp"
RING_LAYOUT = ROOT / "itlwm/hal_iwx/if_iwxvar.h"
REGS = ROOT / "itlwm/hal_iwx/if_iwxreg.h"


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : end]
    raise AssertionError(f"unterminated function: {marker}")


def braced_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"unterminated block: {marker}")


def check_production_wiring() -> None:
    source = SOURCE.read_text()
    ring_body = function_body(source, "static bool iwx_tx_response_ring(")
    index_body = function_body(source, "static bool iwx_tx_response_index(")
    ba_body = function_body(
        source,
        "iwx_rx_tx_ba_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt, struct iwx_rx_data *data)",
    )
    flush_body = function_body(
        source,
        "iwx_flush_sta_tids(struct iwx_softc *sc, int sta_id, uint16_t tids)",
    )
    rate_body = ba_body[
        ba_body.index("bool currentQueue = false;") :
        ba_body.index("const uint32_t baFlags = le32toh(ba_res->flags);")
    ]

    assert "IwxTxRingCapacity::ringIsAddressable(" in ring_body
    assert "nitems(ring->data)" in ring_body
    assert "IWX_TFD_QUEUE_SIZE_MAX" not in ring_body
    assert "IwxTxRingCapacity::responseIndex(" in index_body
    assert "nitems(ring->data)" in index_body
    assert "IWX_TFD_QUEUE_SIZE_MAX" not in index_body
    assert "IwxTxRingCapacity::baQueueCanReclaim(" in ba_body
    assert "nitems(ring->data)" in ba_body
    assert "IWX_TFD_QUEUE_SIZE_MAX" not in ba_body
    rate_guard_pos = rate_body.index("IwxTxRingCapacity::rateQueueCanInspect(")
    completed_range_pos = rate_body.index("IwxTxRate::completedDescriptorRange(")
    rate_data_read_pos = rate_body.index("&ring->data[idx]")
    assert rate_guard_pos < completed_range_pos < rate_data_read_pos
    assert "nitems(ring->data)" in rate_body[rate_guard_pos:completed_range_pos]
    assert "ring->queued, ring->tail" in rate_body[rate_guard_pos:completed_range_pos]
    assert "txd->rate_generation == rateGeneration" in rate_body
    assert "&txd->in->in_ni == ic->ic_bss" in rate_body

    p2p_pos = ba_body.index("iwx_tahoe_p2p_action_reject_ba_queue(")
    ba_guard_pos = ba_body.index("IwxTxRingCapacity::baQueueCanReclaim(")
    watchdog_pos = ba_body.index("IwxTxWatchdog::clear(&sc->sc_tx_timer)", ba_guard_pos)
    reclaim_pos = ba_body.index("iwx_ampdu_txq_advance(sc, ring, reclaimIndex)")
    assert p2p_pos < ba_guard_pos < watchdog_pos < reclaim_pos
    assert "&reclaimIndex" in ba_body[ba_guard_pos:watchdog_pos]

    flush_p2p_pos = flush_body.index("iwx_tahoe_p2p_tvqm_queue_owned(")
    flush_mapping_pos = flush_body.index("sc->sc_tid_data[tid].qid != qid")
    flush_guard_pos = flush_body.index(
        "IwxTxRingCapacity::flushQueueCanReclaim("
    )
    flush_range_pos = flush_body.index(
        "IwxTxRingCapacity::reclaimIndexWithinQueuedRange("
    )
    flush_reclaim_pos = flush_body.index("iwx_ampdu_txq_advance(sc, txq, reclaimIndex)")
    assert flush_p2p_pos < flush_mapping_pos < flush_guard_pos < flush_range_pos < flush_reclaim_pos
    assert "nitems(txq->data)" in flush_body[flush_guard_pos:flush_reclaim_pos]
    assert "IWX_TFD_QUEUE_SIZE_MAX" not in flush_body

    dispatch_start = source.index("case IWX_TX_CMD:")
    dispatch_end = source.index("case IWX_MISSED_BEACONS_NOTIFICATION:", dispatch_start)
    dispatch = source[dispatch_start:dispatch_end]
    p2p_consumer = dispatch.index("iwx_tahoe_p2p_action_tx_response(")
    ordinary_fallback = dispatch.index("iwx_rx_tx_cmd(sc, pkt, data);")
    assert p2p_consumer < ordinary_fallback
    assert "#endif" in dispatch[p2p_consumer:ordinary_fallback]

    layout = RING_LAYOUT.read_text()
    regs = REGS.read_text()
    assert re.search(r"data\s*\[IWX_MIN_256_BA_QUEUE_SIZE_GEN3\]", layout)
    assert re.search(r"#define\s+IWX_MIN_256_BA_QUEUE_SIZE_GEN3\s+1024\b", regs)
    assert "#define IWX_TFD_QUEUE_SIZE_MAX        (256)" in regs
    assert "IWX_TFD_QUEUE_SIZE_MAX_GEN3    (65536)" in regs


CPP_HARNESS = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "iwx_tx_ring_capacity.hpp"

struct HostTxRing {
    int qid;
    size_t ringCount;
    uint8_t data[1024];
};

struct TxRspPayload {
    uint16_t queueId;
    uint16_t ssn;
};

struct BaPayload {
    uint16_t queueId;
    uint16_t tfdIndex;
};

struct FlushPayload {
    uint16_t queueId;
    uint16_t tid;
    uint16_t readAfter;
};

static_assert(sizeof(((HostTxRing *)0)->data) == 1024,
              "test host data[] capacity must match production storage");

static bool txResponseFromPayload(const TxRspPayload *payload,
                                  size_t payloadLength,
                                  const HostTxRing *ring,
                                  uint16_t *indexOut)
{
    if (!payload || payloadLength < sizeof(*payload) || !ring)
        return false;
    return IwxTxRingCapacity::responseIndex(
        payload->queueId, ring->qid, ring->ringCount, sizeof(ring->data),
        payload->ssn, indexOut);
}

static bool baResponseFromPayload(const BaPayload *payload,
                                  size_t payloadLength,
                                  const HostTxRing *ring,
                                  uint16_t *indexOut)
{
    if (!payload || payloadLength < sizeof(*payload) || !ring)
        return false;
    return IwxTxRingCapacity::baQueueCanReclaim(
        payload->queueId, ring->qid, ring->ringCount, sizeof(ring->data),
        payload->tfdIndex, indexOut);
}

static bool flushResponseFromPayload(const FlushPayload *payload,
                                     size_t payloadLength,
                                     const HostTxRing *ring,
                                     bool p2pOwned,
                                     const uint16_t *tidToQueue,
                                     size_t tidCount,
                                     size_t queueCount,
                                     uint16_t *indexOut)
{
    if (!payload || payloadLength < sizeof(*payload) || !ring ||
        !tidToQueue || payload->queueId >= queueCount ||
        payload->tid >= tidCount || p2pOwned ||
        tidToQueue[payload->tid] != payload->queueId)
        return false;
    return IwxTxRingCapacity::flushQueueCanReclaim(
        payload->queueId, ring->qid, ring->ringCount, sizeof(ring->data),
        payload->readAfter, indexOut);
}

static void expectIndex(HostTxRing *ring, uint16_t queueId, uint16_t seq,
                        uint16_t expected)
{
    TxRspPayload payload{queueId, seq};
    uint16_t index = UINT16_MAX;
    assert(txResponseFromPayload(&payload, sizeof(payload), ring, &index));
    assert(index == expected);
    ring->data[index] = 0x5a;
    assert(ring->data[index] == 0x5a);
}

static void expectBaIndex(HostTxRing *ring, uint16_t queueId,
                          uint16_t tfdIndex, uint16_t expected)
{
    BaPayload payload{queueId, tfdIndex};
    uint16_t reclaimIndex = UINT16_MAX;
    assert(baResponseFromPayload(&payload, sizeof(payload), ring,
                                 &reclaimIndex));
    assert(reclaimIndex == expected);
    ring->data[reclaimIndex] = 0xa5;
    assert(ring->data[reclaimIndex] == 0xa5);
}

static void expectFlushIndex(HostTxRing *ring, uint16_t readAfter,
                             uint16_t expected,
                             const uint16_t *tidToQueue)
{
    FlushPayload payload{1, 0, readAfter};
    uint16_t reclaimIndex = UINT16_MAX;
    assert(flushResponseFromPayload(&payload, sizeof(payload), ring, false,
                                    tidToQueue, 3, 4, &reclaimIndex));
    assert(reclaimIndex == expected);
    ring->data[reclaimIndex] = 0x3c;
    assert(ring->data[reclaimIndex] == 0x3c);
}

static bool ratePredicateThenRead(const HostTxRing *ring, uint32_t queueId,
                                  int queued, int tail, size_t index,
                                  unsigned *arrayReads)
{
    if (!ring || !arrayReads ||
        !IwxTxRingCapacity::rateQueueCanInspect(
            queueId, ring->qid, ring->ringCount, sizeof(ring->data),
            queued, tail))
        return false;
    if (!IwxTxRingCapacity::indexIsAddressable(index, ring->ringCount))
        return false;
    volatile uint8_t sample = ring->data[index];
    (void)sample;
    ++*arrayReads;
    return true;
}

static void expectRejectedRing(size_t count, int ringQid)
{
    HostTxRing ring{};
    ring.qid = ringQid;
    ring.ringCount = count;
    TxRspPayload tx{1, 0};
    BaPayload ba{1, 0};
    uint16_t index = 0;
    assert(!txResponseFromPayload(&tx, sizeof(tx), &ring, &index));
    assert(!baResponseFromPayload(&ba, sizeof(ba), &ring, &index));
}

int main()
{
    HostTxRing ring{};
    ring.qid = 1;
    ring.ringCount = 256;
    const uint16_t tidToQueue[] = {1, 1, 2};
    assert(IwxTxRingCapacity::ringIsAddressable(1, ring.qid,
        ring.ringCount, sizeof(ring.data)));
    expectIndex(&ring, 1, 255, 255);
    expectIndex(&ring, 1, 256, 0);
    expectIndex(&ring, 1, 1023, 255);
    expectIndex(&ring, 1, 1024, 0);
    expectIndex(&ring, 1, 4095, 255);
    expectIndex(&ring, 1, UINT16_MAX, 255);
    expectBaIndex(&ring, 1, 255, 255);
    expectBaIndex(&ring, 1, 256, 0);
    expectBaIndex(&ring, 1, 1023, 255);
    expectBaIndex(&ring, 1, 1024, 0);
    expectBaIndex(&ring, 1, 4095, 255);
    expectFlushIndex(&ring, 255, 255, tidToQueue);
    expectFlushIndex(&ring, 256, 0, tidToQueue);
    expectFlushIndex(&ring, 1023, 255, tidToQueue);
    expectFlushIndex(&ring, 1024, 0, tidToQueue);
    expectFlushIndex(&ring, 4095, 255, tidToQueue);

    FlushPayload flush{1, 0, 0};
    uint16_t flushIndex = 0;
    assert(!flushResponseFromPayload(&flush, sizeof(flush), &ring, true,
                                     tidToQueue, 3, 4, &flushIndex));
    assert(!flushResponseFromPayload(&flush, sizeof(flush), &ring, false,
                                     tidToQueue, 0, 4, &flushIndex));
    const uint16_t wrongTidMap[] = {2, 1, 2};
    assert(!flushResponseFromPayload(&flush, sizeof(flush), &ring, false,
                                     wrongTidMap, 3, 4, &flushIndex));
    FlushPayload badQid{4, 0, 0};
    assert(!flushResponseFromPayload(&badQid, sizeof(badQid), &ring, false,
                                     tidToQueue, 3, 4, &flushIndex));
    FlushPayload badTid{1, 3, 0};
    assert(!flushResponseFromPayload(&badTid, sizeof(badTid), &ring, false,
                                     tidToQueue, 3, 4, &flushIndex));

    ring.ringCount = 1024;
    assert(IwxTxRingCapacity::ringIsAddressable(1, ring.qid,
        ring.ringCount, sizeof(ring.data)));
    expectIndex(&ring, 1, 1023, 1023);
    expectIndex(&ring, 1, 1024, 0);
    expectIndex(&ring, 1, 255, 255);
    expectIndex(&ring, 1, 4095, 1023);
    expectIndex(&ring, 1, UINT16_MAX, 1023);
    expectBaIndex(&ring, 1, 1023, 1023);
    expectBaIndex(&ring, 1, 1024, 0);
    expectBaIndex(&ring, 1, 255, 255);
    expectBaIndex(&ring, 1, 4095, 1023);
    expectBaIndex(&ring, 1, UINT16_MAX, 1023);
    expectFlushIndex(&ring, 255, 255, tidToQueue);
    expectFlushIndex(&ring, 256, 256, tidToQueue);
    expectFlushIndex(&ring, 1023, 1023, tidToQueue);
    expectFlushIndex(&ring, 1024, 0, tidToQueue);
    expectFlushIndex(&ring, 4095, 1023, tidToQueue);

    unsigned rateArrayReads = 0;
    assert(IwxTxRingCapacity::rateQueueCanInspect(
        1, ring.qid, 256, sizeof(ring.data), 16, 7));
    assert(IwxTxRingCapacity::rateQueueCanInspect(
        1, ring.qid, 1024, sizeof(ring.data), 16, 7));
    assert(ratePredicateThenRead(&ring, 1, 16, 7, 1023, &rateArrayReads));
    assert(rateArrayReads == 1);
    HostTxRing oversizedRing{};
    oversizedRing.qid = 1;
    oversizedRing.ringCount = 2048;
    assert(!IwxTxRingCapacity::rateQueueCanInspect(
        1, oversizedRing.qid, oversizedRing.ringCount,
        sizeof(oversizedRing.data), 16, 7));
    assert(!ratePredicateThenRead(&oversizedRing, 1, 16, 7, 1500,
                                  &rateArrayReads));
    assert(rateArrayReads == 1);
    assert(!IwxTxRingCapacity::rateQueueCanInspect(
        1, ring.qid, 1024, sizeof(ring.data), -1, 7));
    assert(!IwxTxRingCapacity::rateQueueCanInspect(
        1, ring.qid, 1024, sizeof(ring.data), 16, -1));

    expectRejectedRing(0, 1);
    expectRejectedRing(3, 1);
    expectRejectedRing(1025, 1);
    expectRejectedRing(65536, 1);
    expectRejectedRing(1024, 2);
    expectRejectedRing(1024, -1);

    uint16_t ignored = 0;
    assert(IwxTxRingCapacity::indexIsAddressable(255, 256));
    assert(!IwxTxRingCapacity::indexIsAddressable(256, 256));
    assert(IwxTxRingCapacity::indexIsAddressable(1023, 1024));
    assert(!IwxTxRingCapacity::indexIsAddressable(1024, 1024));
    assert(!IwxTxRingCapacity::responseIndex(1, 1, 256, 1024, 0, nullptr));
    assert(!IwxTxRingCapacity::baQueueCanReclaim(1, 1, 256, 1024, 0,
                                                 nullptr));
    assert(!txResponseFromPayload(nullptr, 0, &ring, &ignored));
    TxRspPayload shortPayload{1, 0};
    assert(!txResponseFromPayload(&shortPayload, sizeof(shortPayload) - 1,
                                  &ring, &ignored));
    BaPayload shortBa{1, 0};
    assert(!baResponseFromPayload(&shortBa, sizeof(shortBa) - 1,
                                  &ring, &ignored));
    assert(!flushResponseFromPayload(&flush, sizeof(flush) - 1, &ring, false,
                                     tidToQueue, 3, 4, &ignored));

    puts("PASS: TX_RSP, BA, flush, and BA-rate guards accept 256/1024, reject invalid rings/ownership/mapping, and block 2048-slot rate reads before 1024-slot storage access");
    return 0;
}
"""


CPP_EXTRACTED_HARNESS = r"""
#define AIRPORT_TAHOE 1
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include "iwx_tx_ring_capacity.hpp"
#include "iwx_tx_completion_observation.hpp"

#define nitems(array) (sizeof(array) / sizeof((array)[0]))
#define le16toh(value) (value)
#define IWX_AGG_SSN_TO_TXQ_IDX(value, count) ((value) & ((count) - 1))
#define IWX_STATION_ID 1
#define IWX_MGMT_TID 15
#define IEEE80211_FC0_TYPE_DATA 8
#define IWX_TX_PROGRESS_ORDINARY_RECLAIM 1
#define IWX_TX_PROGRESS_FLUSH_RECLAIM 2
#define IWX_TX_PROGRESS_HAS_QID 1
#define IWX_TX_PROGRESS_HAS_INDEX 2
#define IWX_TX_PROGRESS_HAS_RING_COUNT 4
#define IWX_TX_PROGRESS_HAS_QUEUED 8
#define IWX_TX_PROGRESS_HAS_CUR 16
#define IWX_TX_PROGRESS_HAS_TAIL 32
static const uint32_t kTxTimerClearFirmwareResponse = 1;

struct iwx_node { int in_ni; };
struct iwx_tx_data {
    void *m;
    iwx_node *in;
    uint8_t type;
    uint32_t rate_generation;
};
struct iwx_tx_ring {
    int qid;
    unsigned int ring_count;
    int queued;
    int cur;
    int tail;
    iwx_tx_data data[1024];
};
struct iwx_tid_data { uint16_t qid; };
struct TahoeGroup2TxTrace {};
struct TahoeAuthTrace { TahoeGroup2TxTrace group2_tx; };
struct ieee80211com {
    void *ic_bss;
    TahoeAuthTrace ic_tahoe_auth_trace;
};
struct iwx_softc {
    iwx_tx_ring txq[8];
    iwx_tid_data sc_tid_data[9];
    ieee80211com sc_ic;
    int first_data_qid = 1;
    int sc_tx_timer;
    uint32_t sc_tx_output_epoch;
    unsigned watchdogClears;
    unsigned reclaims;
    uint32_t lastReclaimIndex;
};
struct iwx_compressed_ba_tfd {
    uint8_t tid;
    uint16_t q_num;
    uint16_t tfd_index;
};
struct iwx_compressed_ba_notif { iwx_compressed_ba_tfd tfd[8]; };
struct iwx_rx_packet {};
struct iwx_flush_queue_info {
    uint16_t tid;
    uint16_t read_after_flush;
    uint16_t queue_num;
};
struct iwx_tx_path_flush_cmd_rsp { iwx_flush_queue_info queues[8]; };

/*
 * The extracted production loops include observer-only Tahoe telemetry.
 * Pull in the real event schema above so those production symbols stay
 * checked, while keeping the test focused on ring guards and reclaim logic.
 * These adapters intentionally do not change any queue decision.
 */
static iwx_tx_completion_event_input txCompletionRxInput(
    uint32_t kind, uint32_t stage, uint32_t reason, const iwx_rx_packet *) {
    iwx_tx_completion_event_input event{};
    event.kind = kind;
    event.stage = stage;
    event.terminal_reason = reason;
    return event;
}
static void txCompletionSetBaFacts(
    iwx_tx_completion_event_input *, const iwx_compressed_ba_notif *) {}
static void txCompletionSetBaTfdFacts(
    iwx_tx_completion_event_input *, const iwx_compressed_ba_tfd *) {}
static void txCompletionSetRingFacts(
    iwx_tx_completion_event_input *, const iwx_tx_ring *) {}
class TxCompletionTerminalScope {
public:
    TxCompletionTerminalScope(iwx_softc *,
                              const iwx_tx_completion_event_input &event)
        : event_(event) {}
    void setReason(uint32_t reason) { event_.terminal_reason = reason; }
    iwx_tx_completion_event_input &event() { return event_; }
    void dismiss() {}
private:
    iwx_tx_completion_event_input event_;
};

static uint64_t tahoeMonotonicNs() { return 1; }
static bool iwx_group2_tx_trace_retire_flushed_interval(
    void *, uint64_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    return true;
}

struct TahoeP2pQueue { bool p2pOwned[8]{}; };
struct TahoeP2pActionState {};
static TahoeP2pQueue nativeP2pTxQueue_;
static TahoeP2pActionState nativeP2pActionTx_;
static unsigned gWatchdogClears = 0;
static bool iwx_tahoe_p2p_action_reject_ba_queue(
    TahoeP2pQueue *queue, TahoeP2pActionState *, uint16_t qid) {
    return queue->p2pOwned[qid];
}
static bool iwx_tahoe_p2p_tvqm_queue_owned(
    TahoeP2pQueue *queue, uint16_t qid) {
    return queue->p2pOwned[qid];
}

namespace IwxTxWatchdog {
static void clear(int *timer) {
    *timer = 0;
    ++gWatchdogClears;
}
}
static void recordTxTimerClear(iwx_softc *, uint32_t, uint32_t) {}
static void recordTxProgressEvent(iwx_softc *, uint32_t, uint32_t, uint32_t,
                                  uint32_t, uint32_t, uint32_t, uint32_t,
                                  uint32_t, uint32_t, bool) {}
static void iwx_ampdu_txq_advance(iwx_softc *sc, iwx_tx_ring *ring, int index) {
    ++sc->reclaims;
    sc->lastReclaimIndex = static_cast<uint32_t>(index);
    ring->tail = index;
}
static void iwx_clear_oactive(iwx_softc *, iwx_tx_ring *) {}

namespace IwxTxRate {
struct CompletedDescriptorRange { uint32_t first; uint32_t count; };
static unsigned gRangeCalls = 0;
static bool completedDescriptorRange(uint32_t ringCount, uint32_t tail,
                                     uint32_t queued, uint32_t,
                                     CompletedDescriptorRange *range) {
    ++gRangeCalls;
    if (!ringCount || tail >= ringCount || !queued || !range)
        return false;
    range->first = ringCount - 1;
    range->count = 1;
    return true;
}
}

@@TX_RESPONSE_RING@@
@@TX_RESPONSE_INDEX@@

static bool runBaRateCandidateScan(iwx_softc *sc,
                                  iwx_compressed_ba_notif *ba_res,
                                  uint16_t tfdCount, ieee80211com *ic,
                                  uint32_t rateGeneration) {
    int i;
    iwx_tx_ring *ring;
    bool currentQueue = false;
@@BA_RATE_LOOP@@
    return currentQueue;
}

static void runBaReclaimLoop(iwx_softc *sc,
                             iwx_compressed_ba_notif *ba_res,
                             uint16_t tfdCount) {
    uint8_t tid = 0;
    uint8_t qid;
    int i;
    iwx_tx_ring *ring;
    // The extracted function's packet argument is only read by telemetry.
    iwx_rx_packet *pkt = nullptr;
@@BA_RECLAIM_LOOP@@
    (void)tid;
}

static void runFlushLoop(iwx_softc *sc,
                         iwx_tx_path_flush_cmd_rsp *resp,
                         int num_flushed_queues) {
    int i;
    int err = 0;
    int sta_id = IWX_STATION_ID;
@@FLUSH_LOOP@@
    (void)err;
}

static void initRing(iwx_softc *sc, uint16_t qid, unsigned int count) {
    sc->txq[qid] = {};
    sc->txq[qid].qid = qid;
    sc->txq[qid].ring_count = count;
}
static void resetEffects(iwx_softc *sc) {
    sc->reclaims = 0;
    sc->lastReclaimIndex = UINT32_MAX;
    sc->watchdogClears = 0;
    gWatchdogClears = 0;
}

static void testExtractedResponseFunctions() {
    iwx_softc sc{};
    iwx_tx_ring *ring = nullptr;
    uint16_t index = UINT16_MAX;
    initRing(&sc, 1, 256);
    assert(iwx_tx_response_ring(&sc, 1, &ring) && ring == &sc.txq[1]);
    assert(iwx_tx_response_index(1, ring, 255, &index) && index == 255);
    assert(iwx_tx_response_index(1, ring, 256, &index) && index == 0);
    initRing(&sc, 1, 1024);
    assert(iwx_tx_response_ring(&sc, 1, &ring));
    assert(iwx_tx_response_index(1, ring, 1023, &index) && index == 1023);
    assert(iwx_tx_response_index(1, ring, 1024, &index) && index == 0);
    assert(iwx_tx_response_index(1, ring, 4095, &index) && index == 1023);
    for (unsigned int invalid : {0u, 3u, 1025u, 2048u, 65536u}) {
        initRing(&sc, 1, invalid);
        assert(!iwx_tx_response_ring(&sc, 1, &ring));
    }
    initRing(&sc, 1, 1024);
    sc.txq[1].qid = 2;
    assert(!iwx_tx_response_ring(&sc, 1, &ring));
    assert(!iwx_tx_response_ring(&sc, 8, &ring));
}

static void testExtractedBaReclaimLoop() {
    iwx_softc sc{};
    iwx_compressed_ba_notif ba{};
    ba.tfd[0] = {3, 1, 255};
    initRing(&sc, 1, 256);
    resetEffects(&sc);
    runBaReclaimLoop(&sc, &ba, 1);
    assert(sc.reclaims == 1 && sc.lastReclaimIndex == 255);
    assert(gWatchdogClears == 1);

    ba.tfd[0] = {3, 1, 4095};
    initRing(&sc, 1, 1024);
    resetEffects(&sc);
    runBaReclaimLoop(&sc, &ba, 1);
    assert(sc.reclaims == 1 && sc.lastReclaimIndex == 1023);
    assert(gWatchdogClears == 1);

    initRing(&sc, 1, 2048);
    resetEffects(&sc);
    runBaReclaimLoop(&sc, &ba, 1);
    assert(sc.reclaims == 0 && gWatchdogClears == 0);

    initRing(&sc, 2, 256);
    nativeP2pTxQueue_.p2pOwned[2] = true;
    ba.tfd[0] = {3, 2, 255};
    resetEffects(&sc);
    runBaReclaimLoop(&sc, &ba, 1);
    assert(sc.reclaims == 0 && gWatchdogClears == 0);
    nativeP2pTxQueue_.p2pOwned[2] = false;

    ba.tfd[0] = {3, 8, 255};
    resetEffects(&sc);
    runBaReclaimLoop(&sc, &ba, 1);
    assert(sc.reclaims == 0 && gWatchdogClears == 0);
}

static bool sampleBaRate(iwx_softc *sc, iwx_compressed_ba_notif *ba,
                         uint16_t tfdCount, ieee80211com *ic,
                         uint32_t rateGeneration) {
    return runBaRateCandidateScan(sc, ba, tfdCount, ic, rateGeneration);
}

static void testExtractedBaRatePredicate() {
    iwx_softc sc{};
    ieee80211com ic{};
    iwx_node node{};
    int packetToken = 1;
    ic.ic_bss = &node.in_ni;
    iwx_compressed_ba_notif ba{};
    ba.tfd[0] = {3, 1, 256};

    for (unsigned int count : {256u, 1024u}) {
        initRing(&sc, 1, count);
        iwx_tx_ring *ring = &sc.txq[1];
        ring->tail = 0;
        ring->queued = 1;
        iwx_tx_data *candidate = &ring->data[count - 1];
        candidate->m = &packetToken;
        candidate->in = &node;
        candidate->type = IEEE80211_FC0_TYPE_DATA;
        candidate->rate_generation = 7;
        unsigned int oldRangeCalls = IwxTxRate::gRangeCalls;
        assert(sampleBaRate(&sc, &ba, 1, &ic, 7));
        assert(IwxTxRate::gRangeCalls == oldRangeCalls + 1);
    }

    initRing(&sc, 1, 2048);
    sc.txq[1].tail = 0;
    sc.txq[1].queued = 1;
    unsigned int oldRangeCalls = IwxTxRate::gRangeCalls;
    assert(!sampleBaRate(&sc, &ba, 1, &ic, 7));
    assert(IwxTxRate::gRangeCalls == oldRangeCalls);

    initRing(&sc, 1, 1024);
    sc.txq[1].tail = 0;
    sc.txq[1].queued = -1;
    oldRangeCalls = IwxTxRate::gRangeCalls;
    assert(!sampleBaRate(&sc, &ba, 1, &ic, 7));
    assert(IwxTxRate::gRangeCalls == oldRangeCalls);
}

static void testExtractedFlushLoop() {
    iwx_softc sc{};
    iwx_tx_path_flush_cmd_rsp rsp{};
    sc.sc_tid_data[0].qid = 1;
    rsp.queues[0] = {0, 255, 1};
    initRing(&sc, 1, 256);
    sc.txq[1].tail = 254;
    sc.txq[1].queued = 2;
    sc.txq[1].cur = 0;
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 1 && sc.lastReclaimIndex == 255);

    rsp.queues[0] = {0, 4095, 1};
    initRing(&sc, 1, 1024);
    sc.txq[1].tail = 1022;
    sc.txq[1].queued = 2;
    sc.txq[1].cur = 0;
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 1 && sc.lastReclaimIndex == 1023);

    initRing(&sc, 1, 2048);
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 0);

    initRing(&sc, 1, 256);
    nativeP2pTxQueue_.p2pOwned[1] = true;
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 0);
    nativeP2pTxQueue_.p2pOwned[1] = false;

    sc.sc_tid_data[0].qid = 2;
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 0);

    sc.sc_tid_data[0].qid = 1;
    rsp.queues[0] = {8, 0, 1};
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 0);
    rsp.queues[0] = {0, 0, 8};
    resetEffects(&sc);
    runFlushLoop(&sc, &rsp, 1);
    assert(sc.reclaims == 0);
}

int main() {
    testExtractedResponseFunctions();
    testExtractedBaReclaimLoop();
    testExtractedBaRatePredicate();
    testExtractedFlushLoop();
    std::puts("PASS: extracted production response helpers, complete BA/rate/flush loops, ownership gates, 256/1024 acceptance, and 2048 host-storage protection");
}
"""


def main() -> None:
    check_production_wiring()
    compiler = shutil.which("clang++")
    if not compiler:
        xcrun = shutil.which("xcrun")
        if xcrun:
            compiler = subprocess.check_output(
                [xcrun, "--find", "clang++"], text=True
            ).strip()
    if not compiler:
        raise SystemExit("clang++ not found")

    with tempfile.TemporaryDirectory(prefix="test075-tx-ring-") as tmp:
        temp = pathlib.Path(tmp)
        harness = temp / "tx_ring_capacity.cpp"
        binary = temp / "tx_ring_capacity"
        harness.write_text(textwrap.dedent(CPP_HARNESS))
        command = [
            compiler,
            "-std=c++11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I",
            str(RING_HEADER.parent),
            str(harness),
            "-o",
            str(binary),
        ]
        print("compile:", " ".join(command))
        subprocess.run(command, check=True)
        env = os.environ.copy()
        # Apple's clang ASan runtime does not implement LeakSanitizer.
        env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        result = subprocess.run(
            [str(binary)], text=True, capture_output=True, env=env
        )
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        if result.returncode:
            raise SystemExit(f"sanitized harness exited {result.returncode}")

        source = SOURCE.read_text()
        ba_body = function_body(
            source,
            "iwx_rx_tx_ba_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt, struct iwx_rx_data *data)",
        )
        flush_body = function_body(
            source,
            "iwx_flush_sta_tids(struct iwx_softc *sc, int sta_id, uint16_t tids)",
        )
        rate_loop = braced_source(
            ba_body, "for (i = 0; i < tfdCount && !currentQueue; ++i)"
        )
        ba_reclaim_loop = braced_source(
            ba_body[ba_body.index("/* Free per TID */") :],
            "for (i = 0; i < tfdCount; i++)",
        )
        flush_loop = braced_source(
            flush_body, "for (i = 0; i < num_flushed_queues; i++)"
        )
        extracted = CPP_EXTRACTED_HARNESS
        extracted = extracted.replace(
            "@@TX_RESPONSE_RING@@",
            braced_source(source, "static bool iwx_tx_response_ring("),
        )
        extracted = extracted.replace(
            "@@TX_RESPONSE_INDEX@@",
            braced_source(source, "static bool iwx_tx_response_index("),
        )
        extracted = extracted.replace("@@BA_RATE_LOOP@@", rate_loop)
        extracted = extracted.replace("@@BA_RECLAIM_LOOP@@", ba_reclaim_loop)
        extracted = extracted.replace("@@FLUSH_LOOP@@", flush_loop)
        if "@@" in extracted:
            raise AssertionError("unresolved extracted production marker")
        extracted_cpp = temp / "tx_ring_capacity_extracted.cpp"
        extracted_binary = temp / "tx_ring_capacity_extracted"
        extracted_cpp.write_text(extracted)
        extracted_command = [
            compiler,
            "-std=c++11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-function",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I",
            str(RING_HEADER.parent),
            str(extracted_cpp),
            "-o",
            str(extracted_binary),
        ]
        print("compile extracted production:", " ".join(extracted_command))
        subprocess.run(extracted_command, check=True)
        extracted_result = subprocess.run(
            [str(extracted_binary)],
            text=True,
            capture_output=True,
            env=env,
        )
        if extracted_result.stdout.strip():
            print(extracted_result.stdout.strip())
        if extracted_result.stderr.strip():
            print(extracted_result.stderr.strip())
        if extracted_result.returncode:
            raise SystemExit(
                f"extracted production harness exited {extracted_result.returncode}"
            )
    print("PASS: production wiring, P2P ordering, ordinary fallback, and 1024-slot storage checks")


if __name__ == "__main__":
    main()
