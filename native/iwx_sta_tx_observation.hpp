// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_STA_TX_OBSERVATION_HPP
#define GEEK_IWX_STA_TX_OBSERVATION_HPP

#include <stdint.h>

/*
 * Numeric-only STA TX evidence. This is a bounded, try-lock protected
 * snapshot of the latest ordinary-STA submit, firmware TX_RSP seen after the
 * P2P dispatcher declines it, and host reclaim. It contains no packet bytes,
 * addresses, node pointers, or DMA addresses.
 *
 * Host generation/epoch values are sampled by the driver when an event is
 * recorded. Firmware TX_RSP does not carry those values, so the match class
 * below is correlation evidence, never proof of firmware queue ownership,
 * DMA completion, or peer receipt.
 */
enum {
    IWX_STA_TX_OBS_SCHEMA = 1,
    IWX_STA_TX_OBS_STATE_MAX_BYTES = 512,
    IWX_STA_TX_OBS_SNAPSHOT_MAX_BYTES = 512
};

enum iwx_sta_tx_obs_kind {
    IWX_STA_TX_OBS_SUBMIT = 1,
    IWX_STA_TX_OBS_RESPONSE = 2,
    IWX_STA_TX_OBS_RECLAIM = 3
};

enum iwx_sta_tx_obs_presence {
    IWX_STA_TX_OBS_HAS_TIME = 1u << 0,
    IWX_STA_TX_OBS_HAS_DRIVER_GENERATION = 1u << 1,
    IWX_STA_TX_OBS_HAS_OUTPUT_EPOCH = 1u << 2,
    IWX_STA_TX_OBS_HAS_QID = 1u << 3,
    IWX_STA_TX_OBS_HAS_INDEX = 1u << 4,
    IWX_STA_TX_OBS_HAS_RING_COUNT = 1u << 5,
    IWX_STA_TX_OBS_HAS_QUEUED = 1u << 6,
    IWX_STA_TX_OBS_HAS_CUR = 1u << 7,
    IWX_STA_TX_OBS_HAS_TAIL = 1u << 8,
    IWX_STA_TX_OBS_HAS_FRAME_CONTROL = 1u << 9,
    IWX_STA_TX_OBS_HAS_SEQUENCE_CONTROL = 1u << 10,
    IWX_STA_TX_OBS_HAS_FRAME_COUNT = 1u << 11,
    IWX_STA_TX_OBS_HAS_STATUS = 1u << 12,
    IWX_STA_TX_OBS_HAS_SSN = 1u << 13,
    IWX_STA_TX_OBS_HAS_RA_TID = 1u << 14,
    IWX_STA_TX_OBS_HAS_RELATED_SERIAL = 1u << 15,
    IWX_STA_TX_OBS_HAS_STATION_ID = 1u << 16,
    IWX_STA_TX_OBS_HAS_TID = 1u << 17
};

enum iwx_sta_tx_obs_match_class {
    IWX_STA_TX_OBS_MATCH_NOT_EVALUATED = 0,
    IWX_STA_TX_OBS_MATCH_NO_SUBMIT = 1,
    IWX_STA_TX_OBS_MATCH_HOST_TUPLE = 2,
    IWX_STA_TX_OBS_MATCH_DIFFERENT_HOST_TUPLE = 3,
    IWX_STA_TX_OBS_MATCH_AGGREGATE_UNMAPPED = 4
};

typedef struct iwx_sta_tx_obs_event {
    uint64_t serial;
    uint64_t monotonic_ns;
    uint64_t related_serial;
    uint32_t kind;
    uint32_t presence_flags;
    uint32_t driver_generation;
    uint32_t output_epoch;
    uint32_t qid;
    uint32_t index;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
    uint32_t frame_control;
    uint32_t sequence_control;
    uint32_t frame_count;
    uint32_t status;
    uint32_t ssn;
    uint32_t ra_tid;
    uint32_t station_id;
    uint32_t tid;
    uint32_t match_class;
} iwx_sta_tx_obs_event;

typedef struct iwx_sta_tx_observation_state {
    uint32_t lock;
    uint32_t incomplete;
    uint64_t dropped_count;
    uint64_t next_serial;
    uint64_t submit_count;
    uint64_t response_count;
    uint64_t reclaim_count;
    iwx_sta_tx_obs_event last_submit;
    iwx_sta_tx_obs_event last_response;
    iwx_sta_tx_obs_event last_reclaim;
} iwx_sta_tx_observation_state;

typedef struct iwx_sta_tx_observation_snapshot {
    uint32_t available;
    uint32_t complete;
    uint32_t firmware_queue_owner_proven;
    uint32_t firmware_dma_completion_proven;
    uint32_t peer_receipt_proven;
    uint64_t dropped_count;
    uint64_t next_serial;
    uint64_t submit_count;
    uint64_t response_count;
    uint64_t reclaim_count;
    iwx_sta_tx_obs_event last_submit;
    iwx_sta_tx_obs_event last_response;
    iwx_sta_tx_obs_event last_reclaim;
} iwx_sta_tx_observation_snapshot;

#ifdef __cplusplus

namespace IwxStaTxObservation {

static_assert(sizeof(iwx_sta_tx_obs_event) <= 112,
              "STA TX event must remain numeric and bounded");
static_assert(sizeof(iwx_sta_tx_observation_state) <=
                  IWX_STA_TX_OBS_STATE_MAX_BYTES,
              "STA TX observation state exceeded its embedded bound");
static_assert(sizeof(iwx_sta_tx_observation_snapshot) <=
                  IWX_STA_TX_OBS_SNAPSHOT_MAX_BYTES,
              "STA TX observation snapshot exceeded its embedded bound");

static inline bool tryLock(iwx_sta_tx_observation_state *state)
{
    if (!state)
        return false;
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&state->lock, &expected, 1U, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void unlock(iwx_sta_tx_observation_state *state)
{
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);
}

static inline void noteDrop(iwx_sta_tx_observation_state *state)
{
    if (!state)
        return;
    __atomic_fetch_add(&state->dropped_count, uint64_t{1}, __ATOMIC_RELAXED);
    __atomic_store_n(&state->incomplete, 1U, __ATOMIC_RELEASE);
}

static inline void initialize(iwx_sta_tx_observation_state *state)
{
    if (state)
        *state = {};
}

static inline bool record(iwx_sta_tx_observation_state *state,
                          const iwx_sta_tx_obs_event *input,
                          uint64_t *serialOut = nullptr)
{
    if (serialOut)
        *serialOut = 0;
    if (!state || !input ||
        (input->kind != IWX_STA_TX_OBS_SUBMIT &&
         input->kind != IWX_STA_TX_OBS_RESPONSE &&
         input->kind != IWX_STA_TX_OBS_RECLAIM)) {
        noteDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    if (state->next_serial == UINT64_MAX) {
        __atomic_store_n(&state->incomplete, 1U, __ATOMIC_RELEASE);
        unlock(state);
        return false;
    }

    iwx_sta_tx_obs_event event = *input;
    event.serial = ++state->next_serial;
    event.match_class = IWX_STA_TX_OBS_MATCH_NOT_EVALUATED;
    switch (event.kind) {
        case IWX_STA_TX_OBS_SUBMIT:
            state->last_submit = event;
            ++state->submit_count;
            break;
        case IWX_STA_TX_OBS_RESPONSE: {
            const uint32_t identity = IWX_STA_TX_OBS_HAS_DRIVER_GENERATION |
                IWX_STA_TX_OBS_HAS_OUTPUT_EPOCH | IWX_STA_TX_OBS_HAS_QID |
                IWX_STA_TX_OBS_HAS_FRAME_CONTROL |
                IWX_STA_TX_OBS_HAS_SEQUENCE_CONTROL;
            const iwx_sta_tx_obs_event &submit = state->last_submit;
            if (event.frame_count > 1) {
                event.match_class = IWX_STA_TX_OBS_MATCH_AGGREGATE_UNMAPPED;
            } else if (submit.serial == 0 ||
                (submit.presence_flags & identity) != identity) {
                event.match_class = IWX_STA_TX_OBS_MATCH_NO_SUBMIT;
            } else {
                const bool hostTupleMatches =
                    (event.presence_flags & identity) == identity &&
                    event.driver_generation == submit.driver_generation &&
                    event.output_epoch == submit.output_epoch &&
                    event.qid == submit.qid &&
                    event.frame_control == submit.frame_control &&
                    event.sequence_control == submit.sequence_control;
                event.match_class = hostTupleMatches ?
                    IWX_STA_TX_OBS_MATCH_HOST_TUPLE :
                    IWX_STA_TX_OBS_MATCH_DIFFERENT_HOST_TUPLE;
                if (hostTupleMatches)
                    event.related_serial = submit.serial;
            }
            state->last_response = event;
            ++state->response_count;
            break;
        }
        case IWX_STA_TX_OBS_RECLAIM:
            state->last_reclaim = event;
            ++state->reclaim_count;
            break;
    }
    if (serialOut)
        *serialOut = event.serial;
    unlock(state);
    return true;
}

static inline bool snapshot(iwx_sta_tx_observation_state *state,
                            iwx_sta_tx_observation_snapshot *out)
{
    if (!state || !out || !tryLock(state))
        return false;
    iwx_sta_tx_observation_snapshot value{};
    value.available = state->next_serial != 0 ? 1U : 0U;
    value.next_serial = state->next_serial;
    value.submit_count = state->submit_count;
    value.response_count = state->response_count;
    value.reclaim_count = state->reclaim_count;
    value.last_submit = state->last_submit;
    value.last_response = state->last_response;
    value.last_reclaim = state->last_reclaim;
    value.dropped_count = __atomic_load_n(&state->dropped_count,
                                           __ATOMIC_ACQUIRE);
    value.complete = __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) == 0 &&
        value.dropped_count == 0 ? 1U : 0U;
    // No TX_RSP field carries firmware queue-owner or host epoch identity.
    value.firmware_queue_owner_proven = 0;
    value.firmware_dma_completion_proven = 0;
    value.peer_receipt_proven = 0;
    value.dropped_count = __atomic_load_n(&state->dropped_count,
                                           __ATOMIC_ACQUIRE);
    if (value.dropped_count != 0 ||
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) != 0)
        value.complete = 0;
    *out = value;
    unlock(state);
    return true;
}

} // namespace IwxStaTxObservation

#endif // __cplusplus

#endif // GEEK_IWX_STA_TX_OBSERVATION_HPP
