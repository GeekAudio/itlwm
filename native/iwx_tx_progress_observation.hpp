// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_PROGRESS_OBSERVATION_HPP
#define GEEK_IWX_TX_PROGRESS_OBSERVATION_HPP

#include <stdint.h>

/*
 * C-compatible, fixed-size snapshots for the ordinary STA TX path. The softc
 * embeds only these plain numeric records; all non-atomic fields are accessed
 * under the helper's single-attempt CAS lock. No packet, address or ring array
 * is retained here.
 */
enum {
    IWX_TX_PROGRESS_EVENT_COUNT = 6,
    IWX_TX_PROGRESS_RESPONSE_REASON_COUNT = 3,
    IWX_TX_PROGRESS_GUARD_REASON_COUNT = 2,
    IWX_TX_PROGRESS_RUNSTOP_REASON_COUNT = 2
};

enum iwx_tx_progress_event_kind {
    IWX_TX_PROGRESS_DOORBELL = 0,
    IWX_TX_PROGRESS_RESPONSE_DISPATCH = 1,
    IWX_TX_PROGRESS_GUARD_DECISION = 2,
    IWX_TX_PROGRESS_ORDINARY_RECLAIM = 3,
    IWX_TX_PROGRESS_FLUSH_RECLAIM = 4,
    IWX_TX_PROGRESS_RUNSTOP = 5
};

enum iwx_tx_progress_presence_flag {
    IWX_TX_PROGRESS_HAS_GENERATION = 1u << 0,
    IWX_TX_PROGRESS_HAS_OUTPUT_EPOCH = 1u << 1,
    IWX_TX_PROGRESS_HAS_MONOTONIC_NS = 1u << 2,
    IWX_TX_PROGRESS_HAS_SERIAL = 1u << 3,
    IWX_TX_PROGRESS_HAS_QID = 1u << 4,
    IWX_TX_PROGRESS_HAS_INDEX = 1u << 5,
    IWX_TX_PROGRESS_HAS_RING_COUNT = 1u << 6,
    IWX_TX_PROGRESS_HAS_QUEUED = 1u << 7,
    IWX_TX_PROGRESS_HAS_CUR = 1u << 8,
    IWX_TX_PROGRESS_HAS_TAIL = 1u << 9
};

enum iwx_tx_progress_response_reason {
    IWX_TX_PROGRESS_RESPONSE_TX_RSP = 0,
    IWX_TX_PROGRESS_RESPONSE_BA = 1,
    IWX_TX_PROGRESS_RESPONSE_P2P_CONSUMED = 2
};

enum iwx_tx_progress_guard_reason {
    IWX_TX_PROGRESS_GUARD_RING_READY = 0,
    IWX_TX_PROGRESS_GUARD_RING_REJECTED = 1
};

enum iwx_tx_progress_runstop_reason {
    IWX_TX_PROGRESS_RUNSTOP_START = 0,
    IWX_TX_PROGRESS_RUNSTOP_STOP = 1
};

typedef struct iwx_tx_progress_event_record {
    uint64_t event_count;
    uint64_t serial;
    uint64_t monotonic_ns;
    uint32_t generation;
    uint32_t output_epoch;
    uint32_t presence_flags;
    uint32_t reason;
    uint32_t qid;
    uint32_t index;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
} iwx_tx_progress_event_record;

typedef struct iwx_tx_progress_observation_state {
    uint32_t lock;
    uint32_t reserved;
    uint64_t dropped_count;
    uint64_t next_serial;
    uint64_t response_reason_counts[IWX_TX_PROGRESS_RESPONSE_REASON_COUNT];
    uint64_t guard_reason_counts[IWX_TX_PROGRESS_GUARD_REASON_COUNT];
    uint64_t runstop_reason_counts[IWX_TX_PROGRESS_RUNSTOP_REASON_COUNT];
    iwx_tx_progress_event_record last[IWX_TX_PROGRESS_EVENT_COUNT];
} iwx_tx_progress_observation_state;

typedef struct iwx_tx_progress_event_input {
    uint32_t presence_flags;
    uint32_t reason;
    uint32_t generation;
    uint32_t output_epoch;
    uint64_t monotonic_ns;
    uint32_t qid;
    uint32_t index;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
} iwx_tx_progress_event_input;

typedef struct iwx_tx_progress_observation_snapshot {
    uint32_t available;
    uint32_t complete;
    uint64_t dropped_count;
    uint64_t next_serial;
    uint64_t response_reason_counts[IWX_TX_PROGRESS_RESPONSE_REASON_COUNT];
    uint64_t guard_reason_counts[IWX_TX_PROGRESS_GUARD_REASON_COUNT];
    uint64_t runstop_reason_counts[IWX_TX_PROGRESS_RUNSTOP_REASON_COUNT];
    iwx_tx_progress_event_record last[IWX_TX_PROGRESS_EVENT_COUNT];
} iwx_tx_progress_observation_snapshot;

#ifdef __cplusplus

namespace IwxTxProgressObservation {

static constexpr uint32_t kEventCount = IWX_TX_PROGRESS_EVENT_COUNT;
static constexpr uint32_t kResponseReasonCount =
    IWX_TX_PROGRESS_RESPONSE_REASON_COUNT;
static constexpr uint32_t kGuardReasonCount =
    IWX_TX_PROGRESS_GUARD_REASON_COUNT;
static constexpr uint32_t kRunStopReasonCount =
    IWX_TX_PROGRESS_RUNSTOP_REASON_COUNT;
static_assert(sizeof(iwx_tx_progress_observation_state) <= 480,
              "TX progress observer must remain below 480 bytes");

static inline bool tryLock(iwx_tx_progress_observation_state *state)
{
    if (!state)
        return false;
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&state->lock, &expected, 1U, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void unlock(iwx_tx_progress_observation_state *state)
{
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);
}

static inline void noteDrop(iwx_tx_progress_observation_state *state)
{
    if (state)
        (void)__atomic_fetch_add(&state->dropped_count, uint64_t(1),
                                 __ATOMIC_RELAXED);
}

static inline void saturatingIncrement(uint64_t *value)
{
    if (*value != UINT64_MAX)
        ++*value;
}

static inline bool validReason(uint32_t kind, uint32_t reason)
{
    switch (kind) {
    case IWX_TX_PROGRESS_RESPONSE_DISPATCH:
        return reason < kResponseReasonCount;
    case IWX_TX_PROGRESS_GUARD_DECISION:
        return reason < kGuardReasonCount;
    case IWX_TX_PROGRESS_RUNSTOP:
        return reason < kRunStopReasonCount;
    case IWX_TX_PROGRESS_DOORBELL:
    case IWX_TX_PROGRESS_ORDINARY_RECLAIM:
    case IWX_TX_PROGRESS_FLUSH_RECLAIM:
        return reason == 0;
    default:
        return false;
    }
}

static inline bool record(iwx_tx_progress_observation_state *state,
                          uint32_t kind,
                          const iwx_tx_progress_event_input *input)
{
    if (!state || !input || kind >= kEventCount ||
        !validReason(kind, input->reason)) {
        noteDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }

    iwx_tx_progress_event_record &last = state->last[kind];
    saturatingIncrement(&last.event_count);
    uint64_t serial = 0;
    if (state->next_serial != UINT64_MAX) {
        ++state->next_serial;
        serial = state->next_serial;
    }

    last.serial = serial;
    last.monotonic_ns = input->monotonic_ns;
    last.generation = input->generation;
    last.output_epoch = input->output_epoch;
    last.reason = input->reason;
    last.qid = input->qid;
    last.index = input->index;
    last.ring_count = input->ring_count;
    last.queued = input->queued;
    last.cur = input->cur;
    last.tail = input->tail;
    last.presence_flags = input->presence_flags &
        (IWX_TX_PROGRESS_HAS_GENERATION |
         IWX_TX_PROGRESS_HAS_OUTPUT_EPOCH |
         IWX_TX_PROGRESS_HAS_MONOTONIC_NS |
         IWX_TX_PROGRESS_HAS_QID | IWX_TX_PROGRESS_HAS_INDEX |
         IWX_TX_PROGRESS_HAS_RING_COUNT | IWX_TX_PROGRESS_HAS_QUEUED |
         IWX_TX_PROGRESS_HAS_CUR | IWX_TX_PROGRESS_HAS_TAIL);
    if (serial != 0)
        last.presence_flags |= IWX_TX_PROGRESS_HAS_SERIAL;

    if (kind == IWX_TX_PROGRESS_RESPONSE_DISPATCH)
        saturatingIncrement(&state->response_reason_counts[input->reason]);
    else if (kind == IWX_TX_PROGRESS_GUARD_DECISION)
        saturatingIncrement(&state->guard_reason_counts[input->reason]);
    else if (kind == IWX_TX_PROGRESS_RUNSTOP)
        saturatingIncrement(&state->runstop_reason_counts[input->reason]);

    unlock(state);
    return true;
}

static inline bool snapshot(iwx_tx_progress_observation_state *state,
                            iwx_tx_progress_observation_snapshot *out)
{
    if (!state || !out || !tryLock(state))
        return false;

    iwx_tx_progress_observation_snapshot value{};
    value.available = 1;
    value.dropped_count = __atomic_load_n(&state->dropped_count,
                                           __ATOMIC_RELAXED);
    value.complete = value.dropped_count == 0 ? 1U : 0U;
    value.next_serial = state->next_serial;
    for (uint32_t i = 0; i < kResponseReasonCount; ++i)
        value.response_reason_counts[i] = state->response_reason_counts[i];
    for (uint32_t i = 0; i < kGuardReasonCount; ++i)
        value.guard_reason_counts[i] = state->guard_reason_counts[i];
    for (uint32_t i = 0; i < kRunStopReasonCount; ++i)
        value.runstop_reason_counts[i] = state->runstop_reason_counts[i];
    for (uint32_t i = 0; i < kEventCount; ++i)
        value.last[i] = state->last[i];

    // The drop counter is outside the state lock so failed writers remain
    // observable. This final acquire load is the snapshot's drop-count cut.
    value.dropped_count = __atomic_load_n(&state->dropped_count,
                                           __ATOMIC_ACQUIRE);
    value.complete = value.dropped_count == 0 ? 1U : 0U;
    unlock(state);
    *out = value;
    return true;
}

static inline void reset(iwx_tx_progress_observation_state *state)
{
    if (state)
        *state = iwx_tx_progress_observation_state{};
}

} // namespace IwxTxProgressObservation

#endif // __cplusplus

#endif // GEEK_IWX_TX_PROGRESS_OBSERVATION_HPP
