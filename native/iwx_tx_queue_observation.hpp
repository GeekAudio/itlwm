// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_QUEUE_OBSERVATION_HPP
#define GEEK_IWX_TX_QUEUE_OBSERVATION_HPP

#include <stdint.h>

/*
 * Bounded scalar observation for ordinary STA TX queues. The softc owns one
 * fixed entry per firmware qid. This helper never stores a packet, node,
 * callback, DMA address, or ring pointer and never changes a TX/RX decision.
 */
enum {
    IWX_TXQ_OBS_QUEUE_COUNT = 512,
    IWX_TXQ_OBS_UNKNOWN_QID = 0xffffffffU
};

enum iwx_txq_obs_phase {
    IWX_TXQ_OBS_PHASE_UNKNOWN = 0,
    IWX_TXQ_OBS_PHASE_CONFIGURING = 1,
    IWX_TXQ_OBS_PHASE_ACTIVE = 2,
    IWX_TXQ_OBS_PHASE_RESET = 3,
    IWX_TXQ_OBS_PHASE_CONFIG_FAILED = 4,
    IWX_TXQ_OBS_PHASE_FREED = 5
};

enum iwx_txq_obs_owner {
    IWX_TXQ_OBS_OWNER_UNKNOWN = 0,
    IWX_TXQ_OBS_OWNER_STA = 1,
    IWX_TXQ_OBS_OWNER_AUX = 2,
    IWX_TXQ_OBS_OWNER_MONITOR = 3,
    IWX_TXQ_OBS_OWNER_TVQM_STA = 4,
    IWX_TXQ_OBS_OWNER_P2P = 5
};

enum iwx_txq_obs_config_outcome {
    IWX_TXQ_OBS_CONFIG_ACK_COMMITTED = 1,
    IWX_TXQ_OBS_CONFIG_NOT_SENT = 2,
    IWX_TXQ_OBS_CONFIG_OUTCOME_UNKNOWN = 3,
    IWX_TXQ_OBS_CONFIG_RESPONSE_INVALID = 4,
    IWX_TXQ_OBS_CONFIG_COLLISION = 5
};

enum iwx_txq_obs_operation {
    IWX_TXQ_OBS_OP_NONE = 0,
    IWX_TXQ_OBS_OP_CONFIG_BEGIN = 1,
    IWX_TXQ_OBS_OP_CONFIG_RESULT = 2,
    IWX_TXQ_OBS_OP_RESET = 3,
    IWX_TXQ_OBS_OP_FREE = 4,
    IWX_TXQ_OBS_OP_RECLAIM = 5,
    IWX_TXQ_OBS_OP_FLUSH_RECLAIM = 6,
    IWX_TXQ_OBS_OP_SUBMIT = 7
};

enum iwx_txq_obs_presence {
    IWX_TXQ_OBS_HAS_QID = 1u << 0,
    IWX_TXQ_OBS_HAS_TIME = 1u << 1,
    IWX_TXQ_OBS_HAS_EPOCH = 1u << 2,
    IWX_TXQ_OBS_HAS_OWNER = 1u << 3,
    IWX_TXQ_OBS_HAS_STATION_ID = 1u << 4,
    IWX_TXQ_OBS_HAS_STATION_COLOR = 1u << 5,
    IWX_TXQ_OBS_HAS_QUEUE_TID = 1u << 6,
    IWX_TXQ_OBS_HAS_RING_COUNT = 1u << 7,
    IWX_TXQ_OBS_HAS_QUEUED = 1u << 8,
    IWX_TXQ_OBS_HAS_CUR = 1u << 9,
    IWX_TXQ_OBS_HAS_TAIL = 1u << 10,
    IWX_TXQ_OBS_HAS_DESCRIPTOR_INDEX = 1u << 11,
    IWX_TXQ_OBS_HAS_FRAME_CONTROL = 1u << 12,
    IWX_TXQ_OBS_HAS_PACKET_TID = 1u << 13,
    IWX_TXQ_OBS_HAS_SEQUENCE_CONTROL = 1u << 14,
    IWX_TXQ_OBS_HAS_QUEUE_AGE = 1u << 15,
    IWX_TXQ_OBS_HAS_INCARNATION = 1u << 16,
    IWX_TXQ_OBS_HAS_ATTEMPT = 1u << 17,
    IWX_TXQ_OBS_HAS_SUBMIT_SERIAL = 1u << 18,
    IWX_TXQ_OBS_HAS_SUBMIT_TIME = 1u << 19,
    IWX_TXQ_OBS_HAS_RESET_COUNT = 1u << 20,
    IWX_TXQ_OBS_HAS_RESET_SAMPLE = 1u << 21,
    IWX_TXQ_OBS_HAS_CONFIG_OUTCOME = 1u << 22,
    IWX_TXQ_OBS_HAS_PREVIOUS_INCARNATION = 1u << 23
};

enum iwx_txq_obs_newstate_presence {
    IWX_TXQ_OBS_NEWSTATE_HAS_OLD = 1u << 0,
    IWX_TXQ_OBS_NEWSTATE_HAS_TARGET = 1u << 1,
    IWX_TXQ_OBS_NEWSTATE_HAS_TASK_GENERATION = 1u << 2,
    IWX_TXQ_OBS_NEWSTATE_HAS_DRIVER_GENERATION = 1u << 3,
    IWX_TXQ_OBS_NEWSTATE_HAS_REPEATED_AUTH = 1u << 4,
    IWX_TXQ_OBS_NEWSTATE_HAS_TERMINAL_REASON = 1u << 5,
    IWX_TXQ_OBS_NEWSTATE_HAS_BEGIN_TIME = 1u << 6,
    IWX_TXQ_OBS_NEWSTATE_HAS_END_TIME = 1u << 7
};

typedef struct iwx_txq_obs_input {
    uint32_t presence_flags;
    uint32_t owner;
    uint32_t station_id;
    uint32_t station_color;
    uint32_t queue_tid;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
    uint32_t descriptor_index;
    uint32_t frame_control;
    uint32_t packet_tid;
    uint32_t sequence_control;
    uint32_t output_epoch;
    uint64_t monotonic_ns;
} iwx_txq_obs_input;

typedef struct iwx_txq_obs_queue_shadow {
    uint64_t incarnation;
    uint64_t config_attempt_serial;
    uint64_t operation_count;
    uint64_t last_operation_ns;
    uint64_t reset_count;
    uint64_t last_reset_ns;
    uint64_t last_reset_attempt_serial;
    uint64_t previous_incarnation;
    // Snapshot output mirror only. Writers hold the observer lock; the
    // lockless invalidator counter lives in state.queue_mutation_serial[].
    uint64_t mutation_serial;
    // Version of the per-qid mutation counter validated by the last successful
    // config commit. It is lock-protected payload, never written locklessly.
    uint64_t committed_mutation_serial;
    uint64_t config_begin_mutation_serial;
    uint64_t last_submit_serial;
    uint64_t last_submit_ns;
    uint32_t presence_flags;
    uint32_t submit_presence_flags;
    uint32_t phase;
    uint32_t last_operation;
    uint32_t last_reason;
    uint32_t qid;
    uint32_t output_epoch;
    uint32_t owner;
    uint32_t station_id;
    uint32_t station_color;
    uint32_t queue_tid;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
    uint32_t reset_ring_count;
    uint32_t reset_queued;
    uint32_t reset_cur;
    uint32_t reset_tail;
    uint32_t last_submit_index;
    uint32_t last_frame_control;
    uint32_t last_packet_tid;
    uint32_t last_sequence_control;
    uint32_t last_config_outcome;
} iwx_txq_obs_queue_shadow;

typedef struct iwx_txq_obs_submit_tuple {
    uint64_t serial;
    uint64_t incarnation;
    uint64_t attempt_serial;
    uint32_t present;
    uint32_t qid;
    uint32_t output_epoch;
    uint32_t descriptor_index;
} iwx_txq_obs_submit_tuple;

typedef struct iwx_txq_obs_arm_tuple {
    uint64_t submit_serial;
    uint64_t incarnation;
    uint64_t monotonic_ns;
    uint32_t present;
    uint32_t qid;
    uint32_t output_epoch;
    uint32_t result;
} iwx_txq_obs_arm_tuple;

typedef struct iwx_txq_obs_newstate_record {
    uint64_t token;
    uint64_t begin_monotonic_ns;
    uint64_t end_monotonic_ns;
    uint32_t presence_flags;
    uint32_t old_state;
    uint32_t target_state;
    uint32_t task_generation;
    uint32_t driver_generation;
    uint32_t repeated_auth;
    uint32_t terminal_reason;
} iwx_txq_obs_newstate_record;

typedef struct iwx_tx_queue_observation_state {
    uint32_t lock;
    uint32_t incomplete;
    uint64_t dropped_count;
    uint64_t next_attempt_serial;
    uint64_t next_submit_serial;
    uint64_t next_newstate_token;
    uint64_t mutation_serial;
    uint64_t latest_config_mutation_serial;
    uint32_t requested_config_qid;
    uint64_t latest_config_attempt_serial;
    uint32_t latest_config_outcome;
    uint32_t latest_config_resolved_qid;
    uint32_t unknown_config_qid_pending;
    uint32_t armed_binding_known;
    uint32_t replacement_pending;
    uint32_t replacement_qid;
    uint32_t replacement_incomplete;
    uint64_t replacement_attempt_serial;
    uint64_t replacement_mutation_serial;
    uint64_t replacement_queue_mutation_serial;
    uint64_t replacement_incarnation;
    uint64_t replacement_operation_count;
    uint64_t replacement_reset_count;
    uint64_t replacement_dropped_count;
    iwx_txq_obs_submit_tuple last_submit;
    iwx_txq_obs_arm_tuple arm;
    iwx_txq_obs_newstate_record newstate;
    uint32_t queue_valid[IWX_TXQ_OBS_QUEUE_COUNT];
    // Invalidators can run without the observer lock. Keep their per-qid
    // version words outside queue payload copied by snapshot().
    uint64_t queue_mutation_serial[IWX_TXQ_OBS_QUEUE_COUNT];
    iwx_txq_obs_queue_shadow queues[IWX_TXQ_OBS_QUEUE_COUNT];
} iwx_tx_queue_observation_state;

typedef struct iwx_txq_obs_snapshot {
    uint32_t available;
    uint32_t complete;
    uint32_t snapshot_stable;
    uint32_t selected_qid;
    uint32_t selected_reason;
    uint32_t queue_known;
    uint32_t arm_binding_known;
    uint32_t latest_config_outcome;
    uint32_t latest_config_resolved_qid;
    uint32_t reserved;
    uint64_t dropped_count;
    uint64_t mutation_serial;
    iwx_txq_obs_submit_tuple last_submit;
    iwx_txq_obs_arm_tuple arm;
    iwx_txq_obs_newstate_record newstate;
    iwx_txq_obs_queue_shadow queue;
    uint64_t queue_age_ns;
} iwx_txq_obs_snapshot;

#ifdef __cplusplus

namespace IwxTxQueueObservation {

static_assert(IWX_TXQ_OBS_QUEUE_COUNT == 512,
              "firmware qid shadow must cover every TVQM qid");
static_assert(sizeof(iwx_txq_obs_snapshot) <= 1024,
              "snapshot must remain a small single-qid copy");

enum {
    kAttemptEventRequestedQidKnown = 1u << 0,
    kArmResultUnknown = 0,
    kArmResultExactMatch = 1,
    kArmResultNoSubmitToken = 2,
    kArmResultSubmitMismatch = 3,
    kSnapshotReasonArmedQid = 1,
    kSnapshotReasonLastSubmitQid = 2,
    kNewStatePhaseBegin = 1,
    kNewStatePhaseEnd = 2
};

static inline bool tryLock(iwx_tx_queue_observation_state *state)
{
    if (!state)
        return false;
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&state->lock, &expected, 1U, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void unlock(iwx_tx_queue_observation_state *state)
{
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);
}

static inline void markIncomplete(iwx_tx_queue_observation_state *state)
{
    if (state)
        __atomic_store_n(&state->incomplete, 1U, __ATOMIC_RELEASE);
}

/* One CAS attempt only. Contention marks the trace incomplete instead of
 * retrying in a network/interrupt callback. */
static inline void noteDrop(iwx_tx_queue_observation_state *state)
{
    if (!state)
        return;
    uint64_t old = __atomic_load_n(&state->dropped_count, __ATOMIC_RELAXED);
    if (old == UINT64_MAX ||
        !__atomic_compare_exchange_n(&state->dropped_count, &old, old + 1,
                                     false, __ATOMIC_RELAXED,
                                     __ATOMIC_RELAXED))
        markIncomplete(state);
    markIncomplete(state);
}

static inline bool incrementMonotonic(uint64_t *value,
                                      iwx_tx_queue_observation_state *state,
                                      uint64_t *next)
{
    if (!value || *value == UINT64_MAX) {
        markIncomplete(state);
        return false;
    }
    ++*value;
    if (next)
        *next = *value;
    return true;
}

static inline bool equalsDelta(uint64_t start, uint64_t delta,
                               uint64_t observed)
{
    return start <= UINT64_MAX - delta && observed == start + delta;
}

static inline bool validQid(uint32_t qid)
{
    return qid < IWX_TXQ_OBS_QUEUE_COUNT;
}

static inline void invalidateBinding(iwx_tx_queue_observation_state *state)
{
    __atomic_store_n(&state->armed_binding_known, 0U, __ATOMIC_RELEASE);
}

static inline void invalidateQueue(iwx_tx_queue_observation_state *state,
                                   uint32_t qid)
{
    if (validQid(qid)) {
        // Advance the identity version before clearing validity. If a
        // concurrent config commit later overwrites queue_valid with 1, every
        // consumer still sees committed_mutation_serial != this version.
        uint64_t queueOld = __atomic_load_n(
            &state->queue_mutation_serial[qid], __ATOMIC_RELAXED);
        if (queueOld == UINT64_MAX ||
            !__atomic_compare_exchange_n(&state->queue_mutation_serial[qid],
                &queueOld, queueOld + 1, false, __ATOMIC_ACQ_REL,
                __ATOMIC_RELAXED))
            markIncomplete(state);
        __atomic_store_n(&state->queue_valid[qid], 0U, __ATOMIC_RELEASE);
    }
    invalidateBinding(state);

    uint64_t old = __atomic_load_n(&state->mutation_serial, __ATOMIC_RELAXED);
    if (old == UINT64_MAX ||
        !__atomic_compare_exchange_n(&state->mutation_serial, &old, old + 1,
                                     false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_RELAXED)) {
        markIncomplete(state);
    }
}

static inline void setQueueInput(iwx_txq_obs_queue_shadow *queue,
                                 const iwx_txq_obs_input *input)
{
    if (!queue || !input)
        return;
    if (input->presence_flags & IWX_TXQ_OBS_HAS_TIME) {
        queue->last_operation_ns = input->monotonic_ns;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_TIME;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_EPOCH) {
        queue->output_epoch = input->output_epoch;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_EPOCH;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_OWNER) {
        queue->owner = input->owner;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_OWNER;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_STATION_ID) {
        queue->station_id = input->station_id;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_STATION_ID;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_STATION_COLOR) {
        queue->station_color = input->station_color;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_STATION_COLOR;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_QUEUE_TID) {
        queue->queue_tid = input->queue_tid;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_QUEUE_TID;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_RING_COUNT) {
        queue->ring_count = input->ring_count;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_RING_COUNT;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_QUEUED) {
        queue->queued = input->queued;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_QUEUED;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_CUR) {
        queue->cur = input->cur;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_CUR;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_TAIL) {
        queue->tail = input->tail;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_TAIL;
    }
}

static inline void setSubmitInput(iwx_txq_obs_queue_shadow *queue,
                                  const iwx_txq_obs_input *input,
                                  uint64_t serial)
{
    if (!queue || !input)
        return;
    queue->submit_presence_flags = input->presence_flags &
        (IWX_TXQ_OBS_HAS_DESCRIPTOR_INDEX |
         IWX_TXQ_OBS_HAS_FRAME_CONTROL | IWX_TXQ_OBS_HAS_PACKET_TID |
         IWX_TXQ_OBS_HAS_SEQUENCE_CONTROL);
    if (input->presence_flags & IWX_TXQ_OBS_HAS_DESCRIPTOR_INDEX)
        queue->last_submit_index = input->descriptor_index;
    if (input->presence_flags & IWX_TXQ_OBS_HAS_FRAME_CONTROL)
        queue->last_frame_control = input->frame_control;
    if (input->presence_flags & IWX_TXQ_OBS_HAS_PACKET_TID)
        queue->last_packet_tid = input->packet_tid;
    if (input->presence_flags & IWX_TXQ_OBS_HAS_SEQUENCE_CONTROL)
        queue->last_sequence_control = input->sequence_control;
    if (serial != 0) {
        queue->last_submit_serial = serial;
        queue->submit_presence_flags |= IWX_TXQ_OBS_HAS_SUBMIT_SERIAL;
    } else {
        queue->last_submit_serial = 0;
        queue->submit_presence_flags &= ~IWX_TXQ_OBS_HAS_SUBMIT_SERIAL;
    }
    if (input->presence_flags & IWX_TXQ_OBS_HAS_TIME) {
        queue->last_submit_ns = input->monotonic_ns;
        queue->submit_presence_flags |= IWX_TXQ_OBS_HAS_SUBMIT_TIME;
    } else {
        queue->last_submit_ns = 0;
        queue->submit_presence_flags &= ~IWX_TXQ_OBS_HAS_SUBMIT_TIME;
    }
}

static inline void rememberPreviousIncarnation(
    iwx_txq_obs_queue_shadow *queue)
{
    if (!queue)
        return;
    if ((queue->presence_flags & IWX_TXQ_OBS_HAS_INCARNATION) != 0) {
        queue->previous_incarnation = queue->incarnation;
        queue->presence_flags |= IWX_TXQ_OBS_HAS_PREVIOUS_INCARNATION;
    }
    queue->presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
    queue->committed_mutation_serial = 0;
}

static inline void countOperation(iwx_txq_obs_queue_shadow *queue,
                                  iwx_tx_queue_observation_state *state)
{
    if (!queue)
        return;
    if (queue->operation_count == UINT64_MAX)
        markIncomplete(state);
    else
        ++queue->operation_count;
}

static inline void initialize(iwx_tx_queue_observation_state *state)
{
    if (!state)
        return;
    // Called before producers are registered. Avoid a large State{} temporary
    // on the kernel stack; the fixed table already lives in its owner.
    __builtin_memset(state, 0, sizeof(*state));
    state->requested_config_qid = IWX_TXQ_OBS_UNKNOWN_QID;
    state->latest_config_resolved_qid = IWX_TXQ_OBS_UNKNOWN_QID;
    state->last_submit.qid = IWX_TXQ_OBS_UNKNOWN_QID;
    state->arm.qid = IWX_TXQ_OBS_UNKNOWN_QID;
    for (uint32_t qid = 0; qid < IWX_TXQ_OBS_QUEUE_COUNT; ++qid)
        state->queues[qid].qid = qid;
}

/* Invalidate before trying the observer lock. If the try-lock fails, the old
 * identity stays invalid and the sticky completeness bit prevents a false
 * postmortem join. qid may be UNKNOWN for a TVQM request whose firmware qid is
 * returned only after the config command. */
static inline uint64_t beginConfig(iwx_tx_queue_observation_state *state,
                                   uint32_t qid,
                                   const iwx_txq_obs_input *input)
{
    if (!state || !input)
        return 0;
    if (validQid(qid))
        invalidateQueue(state, qid);
    else if (qid == IWX_TXQ_OBS_UNKNOWN_QID) {
        invalidateBinding(state);
    } else {
        noteDrop(state);
        return 0;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return 0;
    }

    uint64_t attempt = 0;
    if (!incrementMonotonic(&state->next_attempt_serial, state, &attempt)) {
        if (validQid(qid)) {
            iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
            queue->phase = IWX_TXQ_OBS_PHASE_UNKNOWN;
            queue->last_operation = IWX_TXQ_OBS_OP_CONFIG_BEGIN;
            queue->last_reason = IWX_TXQ_OBS_CONFIG_OUTCOME_UNKNOWN;
        }
        unlock(state);
        return 0;
    }
    if (state->unknown_config_qid_pending != 0)
        markIncomplete(state);
    state->replacement_pending = 0;
    state->replacement_qid = IWX_TXQ_OBS_UNKNOWN_QID;
    state->replacement_attempt_serial = 0;
    state->latest_config_attempt_serial = attempt;
    state->latest_config_mutation_serial = __atomic_load_n(
        &state->mutation_serial, __ATOMIC_ACQUIRE);
    state->requested_config_qid = qid;
    state->latest_config_outcome = IWX_TXQ_OBS_CONFIG_OUTCOME_UNKNOWN;
    state->latest_config_resolved_qid = IWX_TXQ_OBS_UNKNOWN_QID;
    state->unknown_config_qid_pending =
        qid == IWX_TXQ_OBS_UNKNOWN_QID ? 1U : 0U;
    if (validQid(qid)) {
        iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
        rememberPreviousIncarnation(queue);
        queue->phase = IWX_TXQ_OBS_PHASE_CONFIGURING;
        queue->last_operation = IWX_TXQ_OBS_OP_CONFIG_BEGIN;
        queue->last_reason = 0;
        queue->config_attempt_serial = attempt;
        // Bind this attempt to the exact per-qid mutation observed after the
        // pre-lock invalidation. A reset/free racing the FW command advances
        // mutation_serial and makes a late acknowledgement stale.
        queue->config_begin_mutation_serial = __atomic_load_n(
            &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
        queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_TIME |
            IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_OWNER |
            IWX_TXQ_OBS_HAS_STATION_ID | IWX_TXQ_OBS_HAS_STATION_COLOR |
            IWX_TXQ_OBS_HAS_QUEUE_TID | IWX_TXQ_OBS_HAS_RING_COUNT |
            IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
            IWX_TXQ_OBS_HAS_TAIL);
        setQueueInput(queue, input);
        queue->presence_flags |= IWX_TXQ_OBS_HAS_QID |
            IWX_TXQ_OBS_HAS_ATTEMPT;
        countOperation(queue, state);
        queue->qid = qid;
    }
    unlock(state);
    return attempt;
}

/* Bind a firmware-assigned TVQM qid to an unknown-qid config attempt before
 * the caller retires/replaces the old host ring. finishConfig() will accept
 * only the exact reset->free replacement sequence observed after this point. */
static inline bool prepareReplacement(
    iwx_tx_queue_observation_state *state, uint64_t attempt, uint32_t qid)
{
    if (!state || attempt == 0 || !validQid(qid)) {
        noteDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    const bool currentUnknownAttempt =
        state->latest_config_attempt_serial == attempt &&
        state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID &&
        state->unknown_config_qid_pending != 0 &&
        state->replacement_pending == 0;
    if (!currentUnknownAttempt) {
        markIncomplete(state);
        unlock(state);
        return false;
    }
    state->replacement_pending = 1;
    state->replacement_qid = qid;
    state->replacement_attempt_serial = attempt;
    state->replacement_mutation_serial = __atomic_load_n(
        &state->mutation_serial, __ATOMIC_ACQUIRE);
    state->replacement_queue_mutation_serial = __atomic_load_n(
        &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    state->replacement_incarnation = state->queues[qid].incarnation;
    state->replacement_operation_count = state->queues[qid].operation_count;
    state->replacement_reset_count = state->queues[qid].reset_count;
    state->replacement_dropped_count = __atomic_load_n(
        &state->dropped_count, __ATOMIC_ACQUIRE);
    state->replacement_incomplete = __atomic_load_n(
        &state->incomplete, __ATOMIC_ACQUIRE);
    state->latest_config_resolved_qid = qid;
    unlock(state);
    return true;
}

static inline bool finishConfig(iwx_tx_queue_observation_state *state,
                                uint64_t attempt, uint32_t resolvedQid,
                                uint32_t outcome,
                                const iwx_txq_obs_input *input)
{
    if (!state || !input || attempt == 0)
        return false;
    const uint64_t mutationAtFinishEntry = __atomic_load_n(
        &state->mutation_serial, __ATOMIC_ACQUIRE);
    const uint64_t queueMutationAtFinishEntry = validQid(resolvedQid) ?
        __atomic_load_n(&state->queue_mutation_serial[resolvedQid],
                        __ATOMIC_ACQUIRE) : 0;
    if (validQid(resolvedQid))
        invalidateQueue(state, resolvedQid);
    else if (resolvedQid == IWX_TXQ_OBS_UNKNOWN_QID) {
        invalidateBinding(state);
    } else {
        noteDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }

    bool matches = false;
    if (state->latest_config_attempt_serial == attempt &&
        validQid(resolvedQid) &&
        state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID) {
        const iwx_txq_obs_queue_shadow *queue = &state->queues[resolvedQid];
        const uint64_t mutationNow = __atomic_load_n(
            &state->mutation_serial, __ATOMIC_ACQUIRE);
        const uint64_t queueMutationNow = __atomic_load_n(
            &state->queue_mutation_serial[resolvedQid], __ATOMIC_ACQUIRE);
        const uint64_t droppedNow = __atomic_load_n(
            &state->dropped_count, __ATOMIC_ACQUIRE);
        const uint32_t incompleteNow = __atomic_load_n(
            &state->incomplete, __ATOMIC_ACQUIRE);
        const bool replacementAttemptMatches =
            state->replacement_pending != 0 &&
            state->replacement_attempt_serial == attempt &&
            state->replacement_qid == resolvedQid &&
            state->unknown_config_qid_pending != 0;
        const bool exactReplacement = replacementAttemptMatches &&
            equalsDelta(state->replacement_mutation_serial, 3, mutationNow) &&
            equalsDelta(state->replacement_queue_mutation_serial, 3,
                        queueMutationNow) &&
            equalsDelta(state->replacement_incarnation, 2,
                        queue->incarnation) &&
            equalsDelta(state->replacement_operation_count, 2,
                        queue->operation_count) &&
            equalsDelta(state->replacement_reset_count, 1,
                        queue->reset_count) &&
            queue->last_operation == IWX_TXQ_OBS_OP_FREE &&
            queue->phase == IWX_TXQ_OBS_PHASE_FREED &&
            queue->config_attempt_serial == 0 &&
            __atomic_load_n(&state->queue_valid[resolvedQid],
                            __ATOMIC_ACQUIRE) == 0 &&
            droppedNow == state->replacement_dropped_count &&
            incompleteNow == state->replacement_incomplete &&
            equalsDelta(state->replacement_mutation_serial, 2,
                        mutationAtFinishEntry) &&
            equalsDelta(state->replacement_queue_mutation_serial, 2,
                        queueMutationAtFinishEntry);
        matches = exactReplacement;
    } else if (state->latest_config_attempt_serial == attempt &&
               validQid(resolvedQid) &&
               state->requested_config_qid == resolvedQid) {
        const iwx_txq_obs_queue_shadow *queue = &state->queues[resolvedQid];
        const uint64_t queueMutationNow = __atomic_load_n(
            &state->queue_mutation_serial[resolvedQid], __ATOMIC_ACQUIRE);
        matches = queue->config_attempt_serial == attempt &&
            equalsDelta(queue->config_begin_mutation_serial, 1,
                        queueMutationNow) &&
            equalsDelta(queue->config_begin_mutation_serial, 0,
                        queueMutationAtFinishEntry);
    } else if (state->latest_config_attempt_serial == attempt &&
               state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID &&
               resolvedQid == IWX_TXQ_OBS_UNKNOWN_QID) {
        // This command completed without yielding a qid. Preserve the result
        // as an unresolved attempt, but do not call it a committed identity.
        matches = mutationAtFinishEntry ==
            state->latest_config_mutation_serial;
    }
    state->latest_config_outcome = outcome;
    state->latest_config_resolved_qid = resolvedQid;
    if (state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID)
        state->unknown_config_qid_pending = 0;
    if (!matches) {
        markIncomplete(state);
        state->replacement_pending = 0;
        if (validQid(resolvedQid)) {
            iwx_txq_obs_queue_shadow *queue = &state->queues[resolvedQid];
            queue->phase = IWX_TXQ_OBS_PHASE_UNKNOWN;
            queue->last_operation = IWX_TXQ_OBS_OP_CONFIG_RESULT;
            queue->last_reason = outcome;
            queue->last_config_outcome = outcome;
            rememberPreviousIncarnation(queue);
            setQueueInput(queue, input);
            countOperation(queue, state);
        }
        unlock(state);
        return false;
    }

    if (validQid(resolvedQid)) {
        iwx_txq_obs_queue_shadow *queue = &state->queues[resolvedQid];
        queue->phase = IWX_TXQ_OBS_PHASE_CONFIG_FAILED;
        queue->last_operation = IWX_TXQ_OBS_OP_CONFIG_RESULT;
        queue->last_reason = outcome;
        queue->last_config_outcome = outcome;
        queue->config_attempt_serial = attempt;
        if (state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID &&
            state->replacement_pending &&
            state->replacement_attempt_serial == attempt &&
            state->replacement_qid == resolvedQid)
            queue->config_begin_mutation_serial =
                state->replacement_queue_mutation_serial;
        rememberPreviousIncarnation(queue);
        queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_QUEUED |
            IWX_TXQ_OBS_HAS_CUR | IWX_TXQ_OBS_HAS_TAIL |
            IWX_TXQ_OBS_HAS_TIME | IWX_TXQ_OBS_HAS_EPOCH |
            IWX_TXQ_OBS_HAS_OWNER | IWX_TXQ_OBS_HAS_STATION_ID |
            IWX_TXQ_OBS_HAS_STATION_COLOR | IWX_TXQ_OBS_HAS_QUEUE_TID |
            IWX_TXQ_OBS_HAS_RING_COUNT);
        setQueueInput(queue, input);
        queue->presence_flags |= IWX_TXQ_OBS_HAS_QID |
            IWX_TXQ_OBS_HAS_ATTEMPT | IWX_TXQ_OBS_HAS_CONFIG_OUTCOME;
        queue->qid = resolvedQid;
        if (outcome == IWX_TXQ_OBS_CONFIG_ACK_COMMITTED) {
            if (queue->incarnation == UINT64_MAX) {
                markIncomplete(state);
            } else {
                ++queue->incarnation;
                queue->phase = IWX_TXQ_OBS_PHASE_ACTIVE;
                queue->presence_flags |= IWX_TXQ_OBS_HAS_INCARNATION;
                queue->presence_flags &=
                    ~IWX_TXQ_OBS_HAS_PREVIOUS_INCARNATION;
                const uint64_t mutationAfterCommit = __atomic_load_n(
                    &state->mutation_serial, __ATOMIC_ACQUIRE);
                const uint64_t queueMutationAfterCommit = __atomic_load_n(
                    &state->queue_mutation_serial[resolvedQid],
                    __ATOMIC_ACQUIRE);
                const bool stillCurrent =
                    state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID ?
                        equalsDelta(state->replacement_mutation_serial, 3,
                                    mutationAfterCommit) &&
                        equalsDelta(state->replacement_queue_mutation_serial,
                                    3, queueMutationAfterCommit) :
                        equalsDelta(queue->config_begin_mutation_serial, 1,
                                    queueMutationAfterCommit);
                if (!stillCurrent) {
                    __atomic_store_n(&state->queue_valid[resolvedQid], 0U,
                                     __ATOMIC_RELEASE);
                    markIncomplete(state);
                } else {
                    queue->committed_mutation_serial =
                        queueMutationAfterCommit;
                    __atomic_store_n(&state->queue_valid[resolvedQid], 1U,
                                     __ATOMIC_RELEASE);
                }
            }
        } else if (outcome != IWX_TXQ_OBS_CONFIG_NOT_SENT) {
            markIncomplete(state);
            if (state->requested_config_qid == IWX_TXQ_OBS_UNKNOWN_QID)
                state->unknown_config_qid_pending = 1;
        }
        countOperation(queue, state);
        state->replacement_pending = 0;
    } else if (outcome == IWX_TXQ_OBS_CONFIG_ACK_COMMITTED) {
        markIncomplete(state);
    } else if (outcome != IWX_TXQ_OBS_CONFIG_NOT_SENT) {
        markIncomplete(state);
        state->unknown_config_qid_pending = 1;
    }
    unlock(state);
    return matches;
}

static inline bool recordReset(iwx_tx_queue_observation_state *state,
                               uint32_t qid, uint32_t reason,
                               const iwx_txq_obs_input *input)
{
    if (!state || !input || !validQid(qid)) {
        noteDrop(state);
        return false;
    }
    invalidateQueue(state, qid);
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
    rememberPreviousIncarnation(queue);
    queue->phase = IWX_TXQ_OBS_PHASE_RESET;
    queue->last_operation = IWX_TXQ_OBS_OP_RESET;
    queue->last_reason = reason;
    if (queue->reset_count != UINT64_MAX)
        ++queue->reset_count;
    else
        markIncomplete(state);
    queue->last_reset_ns = (input->presence_flags & IWX_TXQ_OBS_HAS_TIME) ?
        input->monotonic_ns : 0;
    queue->last_reset_attempt_serial = queue->config_attempt_serial;
    queue->config_attempt_serial = 0;
    if (queue->incarnation != UINT64_MAX)
        ++queue->incarnation;
    else
        markIncomplete(state);
    queue->reset_ring_count = input->ring_count;
    queue->reset_queued = input->queued;
    queue->reset_cur = input->cur;
    queue->reset_tail = input->tail;
    if ((input->presence_flags & (IWX_TXQ_OBS_HAS_RING_COUNT |
         IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
         IWX_TXQ_OBS_HAS_TAIL)) == (IWX_TXQ_OBS_HAS_RING_COUNT |
         IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
         IWX_TXQ_OBS_HAS_TAIL))
        queue->presence_flags |= IWX_TXQ_OBS_HAS_RESET_SAMPLE;
    else
        queue->presence_flags &= ~IWX_TXQ_OBS_HAS_RESET_SAMPLE;
    queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_RING_COUNT |
        IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
        IWX_TXQ_OBS_HAS_TAIL | IWX_TXQ_OBS_HAS_INCARNATION);
    setQueueInput(queue, input);
    queue->presence_flags |= IWX_TXQ_OBS_HAS_QID |
        IWX_TXQ_OBS_HAS_RESET_COUNT;
    countOperation(queue, state);
    queue->qid = qid;
    unlock(state);
    return true;
}

static inline bool recordFree(iwx_tx_queue_observation_state *state,
                              uint32_t qid, uint32_t reason,
                              const iwx_txq_obs_input *input)
{
    if (!state || !input || !validQid(qid)) {
        noteDrop(state);
        return false;
    }
    invalidateQueue(state, qid);
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
    rememberPreviousIncarnation(queue);
    queue->phase = IWX_TXQ_OBS_PHASE_FREED;
    queue->last_operation = IWX_TXQ_OBS_OP_FREE;
    queue->last_reason = reason;
    queue->last_reset_attempt_serial = queue->config_attempt_serial;
    queue->config_attempt_serial = 0;
    if (queue->incarnation != UINT64_MAX)
        ++queue->incarnation;
    else
        markIncomplete(state);
    queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_RING_COUNT |
        IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
        IWX_TXQ_OBS_HAS_TAIL | IWX_TXQ_OBS_HAS_INCARNATION);
    setQueueInput(queue, input);
    queue->presence_flags |= IWX_TXQ_OBS_HAS_QID;
    queue->qid = qid;
    countOperation(queue, state);
    unlock(state);
    return true;
}

static inline bool recordRingSample(iwx_tx_queue_observation_state *state,
                                    uint32_t qid, uint32_t epoch,
                                    uint32_t operation,
                                    const iwx_txq_obs_input *input)
{
    if (!state || !input || !validQid(qid)) {
        noteDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
    const uint64_t queueMutation = __atomic_load_n(
        &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    const bool observerClean =
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&state->dropped_count, __ATOMIC_ACQUIRE) == 0;
    const bool sameIdentity =
        observerClean &&
        __atomic_load_n(&state->queue_valid[qid], __ATOMIC_ACQUIRE) != 0 &&
        queue->phase == IWX_TXQ_OBS_PHASE_ACTIVE &&
        (queue->presence_flags & IWX_TXQ_OBS_HAS_INCARNATION) != 0 &&
        queue->committed_mutation_serial == queueMutation &&
        (queue->presence_flags & IWX_TXQ_OBS_HAS_EPOCH) != 0 &&
        queue->output_epoch == epoch &&
        (input->presence_flags & IWX_TXQ_OBS_HAS_EPOCH) != 0 &&
        input->output_epoch == epoch;
    if (!sameIdentity) {
        markIncomplete(state);
        unlock(state);
        return false;
    }
    queue->last_operation = operation;
    queue->last_reason = 0;
    queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_RING_COUNT | IWX_TXQ_OBS_HAS_QUEUED |
        IWX_TXQ_OBS_HAS_CUR | IWX_TXQ_OBS_HAS_TAIL);
    setQueueInput(queue, input);
    queue->presence_flags |= IWX_TXQ_OBS_HAS_QID |
        IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_INCARNATION |
        IWX_TXQ_OBS_HAS_ATTEMPT;
    countOperation(queue, state);
    queue->qid = qid;
    const uint64_t queueMutationAfter = __atomic_load_n(
        &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    if (queueMutationAfter != queueMutation ||
        queue->committed_mutation_serial != queueMutationAfter ||
        __atomic_load_n(&state->queue_valid[qid], __ATOMIC_ACQUIRE) == 0 ||
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&state->dropped_count, __ATOMIC_ACQUIRE) != 0) {
        queue->presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
        markIncomplete(state);
        unlock(state);
        return false;
    }
    unlock(state);
    return true;
}

static inline uint64_t recordSubmit(iwx_tx_queue_observation_state *state,
                                    uint32_t qid,
                                    const iwx_txq_obs_input *input)
{
    if (!state || !input || !validQid(qid)) {
        noteDrop(state);
        return 0;
    }
    invalidateBinding(state);
    if (!tryLock(state)) {
        noteDrop(state);
        return 0;
    }

    iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
    const uint64_t queueMutation = __atomic_load_n(
        &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    const bool observerClean =
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&state->dropped_count, __ATOMIC_ACQUIRE) == 0;
    const uint32_t required = IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_EPOCH | IWX_TXQ_OBS_HAS_RING_COUNT |
        IWX_TXQ_OBS_HAS_QUEUED | IWX_TXQ_OBS_HAS_CUR |
        IWX_TXQ_OBS_HAS_TAIL | IWX_TXQ_OBS_HAS_DESCRIPTOR_INDEX |
        IWX_TXQ_OBS_HAS_FRAME_CONTROL;
    const bool identityKnown =
        observerClean &&
        __atomic_load_n(&state->queue_valid[qid], __ATOMIC_ACQUIRE) != 0 &&
        queue->phase == IWX_TXQ_OBS_PHASE_ACTIVE &&
        (queue->presence_flags & IWX_TXQ_OBS_HAS_INCARNATION) != 0 &&
        queue->committed_mutation_serial == queueMutation &&
        (queue->presence_flags & IWX_TXQ_OBS_HAS_EPOCH) != 0 &&
        queue->output_epoch == input->output_epoch &&
        (input->presence_flags & required) == required;
    uint64_t serial = 0;
    if (identityKnown && state->next_submit_serial != UINT64_MAX) {
        ++state->next_submit_serial;
        serial = state->next_submit_serial;
    } else {
        markIncomplete(state);
    }

    queue->last_operation = IWX_TXQ_OBS_OP_SUBMIT;
    queue->last_reason = 0;
    queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_TIME |
        IWX_TXQ_OBS_HAS_RING_COUNT | IWX_TXQ_OBS_HAS_QUEUED |
        IWX_TXQ_OBS_HAS_CUR | IWX_TXQ_OBS_HAS_TAIL);
    setQueueInput(queue, input);
    setSubmitInput(queue, input, serial);
    queue->qid = qid;
    queue->presence_flags |= IWX_TXQ_OBS_HAS_QID;
    if (identityKnown) {
        queue->presence_flags |= IWX_TXQ_OBS_HAS_INCARNATION |
            IWX_TXQ_OBS_HAS_ATTEMPT;
    } else {
        queue->presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
    }
    countOperation(queue, state);
    if (serial != 0) {
        const uint64_t queueMutationAfter = __atomic_load_n(
            &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
        const bool stillCurrent = queueMutationAfter == queueMutation &&
            queue->committed_mutation_serial == queueMutationAfter &&
            __atomic_load_n(&state->queue_valid[qid], __ATOMIC_ACQUIRE) != 0 &&
            __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) == 0 &&
            __atomic_load_n(&state->dropped_count, __ATOMIC_ACQUIRE) == 0;
        if (!stillCurrent) {
            serial = 0;
            queue->presence_flags &= ~(IWX_TXQ_OBS_HAS_INCARNATION |
                                       IWX_TXQ_OBS_HAS_ATTEMPT);
            setSubmitInput(queue, input, 0);
            markIncomplete(state);
        }
    }
    state->last_submit.serial = serial;
    state->last_submit.incarnation = serial != 0 ? queue->incarnation : 0;
    state->last_submit.attempt_serial = serial != 0 ?
        queue->config_attempt_serial : 0;
    state->last_submit.present = serial != 0 ? 1U : 0U;
    state->last_submit.qid = qid;
    state->last_submit.output_epoch =
        (input->presence_flags & IWX_TXQ_OBS_HAS_EPOCH) ?
            input->output_epoch : 0;
    state->last_submit.descriptor_index =
        (input->presence_flags & IWX_TXQ_OBS_HAS_DESCRIPTOR_INDEX) ?
            input->descriptor_index : 0;
    unlock(state);
    return serial;
}

static inline bool recordArm(iwx_tx_queue_observation_state *state,
                              uint32_t epoch, uint64_t submitSerial,
                              uint64_t nowNs)
{
    if (!state)
        return false;
    invalidateBinding(state);
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    state->arm.submit_serial = submitSerial;
    state->arm.output_epoch = epoch;
    state->arm.monotonic_ns = nowNs;
    state->arm.present = 1;
    state->arm.qid = IWX_TXQ_OBS_UNKNOWN_QID;
    state->arm.incarnation = 0;
    state->arm.result = kArmResultNoSubmitToken;
    if (submitSerial == 0 || !state->last_submit.present ||
        state->last_submit.serial != submitSerial ||
        state->last_submit.output_epoch != epoch ||
        !validQid(state->last_submit.qid)) {
        state->arm.result = submitSerial == 0 ? kArmResultNoSubmitToken :
                                               kArmResultSubmitMismatch;
        markIncomplete(state);
        unlock(state);
        return false;
    }

    const uint32_t qid = state->last_submit.qid;
    const iwx_txq_obs_queue_shadow *queue = &state->queues[qid];
    const uint64_t queueMutation = __atomic_load_n(
        &state->queue_mutation_serial[qid], __ATOMIC_ACQUIRE);
    const bool observerClean =
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&state->dropped_count, __ATOMIC_ACQUIRE) == 0;
    const bool exact = observerClean &&
        __atomic_load_n(&state->queue_valid[qid], __ATOMIC_ACQUIRE) != 0 &&
        queue->phase == IWX_TXQ_OBS_PHASE_ACTIVE &&
        (queue->presence_flags & IWX_TXQ_OBS_HAS_INCARNATION) != 0 &&
        queue->committed_mutation_serial == queueMutation &&
        queue->incarnation == state->last_submit.incarnation &&
        queue->config_attempt_serial == state->last_submit.attempt_serial &&
        queue->output_epoch == epoch &&
        queue->last_submit_serial == submitSerial;
    if (!exact) {
        state->arm.result = kArmResultSubmitMismatch;
        markIncomplete(state);
        unlock(state);
        return false;
    }
    if (__atomic_load_n(&state->queue_mutation_serial[qid],
                        __ATOMIC_ACQUIRE) != queueMutation ||
        queue->committed_mutation_serial != queueMutation ||
        __atomic_load_n(&state->queue_valid[qid], __ATOMIC_ACQUIRE) == 0 ||
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&state->dropped_count, __ATOMIC_ACQUIRE) != 0) {
        state->arm.result = kArmResultSubmitMismatch;
        markIncomplete(state);
        unlock(state);
        return false;
    }
    state->arm.qid = qid;
    state->arm.incarnation = queue->incarnation;
    state->arm.result = kArmResultExactMatch;
    __atomic_store_n(&state->armed_binding_known, 1U, __ATOMIC_RELEASE);
    unlock(state);
    return true;
}

static inline uint64_t beginNewState(
    iwx_tx_queue_observation_state *state, uint32_t oldState,
    uint32_t targetState, uint32_t taskGeneration,
    uint32_t driverGeneration, bool repeatedAuth, uint64_t nowNs)
{
    if (!state)
        return 0;
    if (!tryLock(state)) {
        noteDrop(state);
        return 0;
    }
    uint64_t token = 0;
    if (state->newstate.token != 0 &&
        (state->newstate.presence_flags & IWX_TXQ_OBS_NEWSTATE_HAS_END_TIME) == 0)
        markIncomplete(state);
    if (!incrementMonotonic(&state->next_newstate_token, state, &token)) {
        unlock(state);
        return 0;
    }
    state->newstate = {};
    state->newstate.token = token;
    state->newstate.begin_monotonic_ns = nowNs;
    state->newstate.old_state = oldState;
    state->newstate.target_state = targetState;
    state->newstate.task_generation = taskGeneration;
    state->newstate.driver_generation = driverGeneration;
    state->newstate.repeated_auth = repeatedAuth ? 1U : 0U;
    state->newstate.presence_flags = IWX_TXQ_OBS_NEWSTATE_HAS_OLD |
        IWX_TXQ_OBS_NEWSTATE_HAS_TARGET |
        IWX_TXQ_OBS_NEWSTATE_HAS_TASK_GENERATION |
        IWX_TXQ_OBS_NEWSTATE_HAS_DRIVER_GENERATION |
        IWX_TXQ_OBS_NEWSTATE_HAS_REPEATED_AUTH |
        IWX_TXQ_OBS_NEWSTATE_HAS_BEGIN_TIME;
    unlock(state);
    return token;
}

static inline bool endNewState(iwx_tx_queue_observation_state *state,
                               uint64_t token, uint32_t terminalReason,
                               uint64_t nowNs)
{
    if (!state || token == 0) {
        noteDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        return false;
    }
    if (state->newstate.token != token ||
        (state->newstate.presence_flags & IWX_TXQ_OBS_NEWSTATE_HAS_END_TIME) != 0) {
        markIncomplete(state);
        unlock(state);
        return false;
    }
    state->newstate.terminal_reason = terminalReason;
    state->newstate.end_monotonic_ns = nowNs;
    state->newstate.presence_flags |=
        IWX_TXQ_OBS_NEWSTATE_HAS_TERMINAL_REASON |
        IWX_TXQ_OBS_NEWSTATE_HAS_END_TIME;
    unlock(state);
    return true;
}

static inline bool snapshot(iwx_tx_queue_observation_state *state,
                            uint64_t nowNs, iwx_txq_obs_snapshot *out)
{
    if (!state || !out || !tryLock(state))
        return false;

    iwx_txq_obs_snapshot value{};
    value.available = 1;
    const uint64_t mutationBefore = __atomic_load_n(
        &state->mutation_serial, __ATOMIC_ACQUIRE);
    value.mutation_serial = mutationBefore;
    value.dropped_count = __atomic_load_n(&state->dropped_count,
                                           __ATOMIC_ACQUIRE);
    value.complete = __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) == 0 &&
        value.dropped_count == 0 ? 1U : 0U;
    value.arm = state->arm;
    value.last_submit = state->last_submit;
    value.arm_binding_known = __atomic_load_n(
        &state->armed_binding_known, __ATOMIC_ACQUIRE);
    value.latest_config_outcome = state->latest_config_outcome;
    value.latest_config_resolved_qid = state->latest_config_resolved_qid;
    value.newstate = state->newstate;

    uint32_t selectedQid = IWX_TXQ_OBS_UNKNOWN_QID;
    if (value.arm_binding_known && validQid(value.arm.qid)) {
        selectedQid = value.arm.qid;
        value.selected_reason = kSnapshotReasonArmedQid;
    } else if (validQid(value.last_submit.qid)) {
        selectedQid = value.last_submit.qid;
        value.selected_reason = kSnapshotReasonLastSubmitQid;
    }
    value.selected_qid = selectedQid;
    uint64_t queueMutationBefore = 0;
    uint64_t queueMutationAfter = 0;
    uint32_t queueValidBefore = 0;
    uint32_t queueValidAfter = 0;
    if (validQid(selectedQid)) {
        // Exactly one sidecar row is copied; no live ring or 512-qid walk.
        queueMutationBefore = __atomic_load_n(
            &state->queue_mutation_serial[selectedQid], __ATOMIC_ACQUIRE);
        queueValidBefore = __atomic_load_n(&state->queue_valid[selectedQid],
                                           __ATOMIC_ACQUIRE);
        __builtin_memcpy(&value.queue, &state->queues[selectedQid],
                         sizeof(value.queue));
        queueMutationAfter = __atomic_load_n(
            &state->queue_mutation_serial[selectedQid], __ATOMIC_ACQUIRE);
        queueValidAfter = __atomic_load_n(&state->queue_valid[selectedQid],
                                          __ATOMIC_ACQUIRE);
        value.queue.mutation_serial = queueMutationAfter;
        value.queue_known = value.complete && queueValidBefore != 0 &&
            queueValidAfter != 0 &&
            queueMutationBefore == queueMutationAfter &&
            value.queue.phase == IWX_TXQ_OBS_PHASE_ACTIVE &&
            (value.queue.presence_flags & IWX_TXQ_OBS_HAS_INCARNATION) != 0 &&
            value.queue.committed_mutation_serial == queueMutationBefore ?
                1U : 0U;
        if (!value.queue_known)
            value.queue.presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
        if ((value.queue.presence_flags & IWX_TXQ_OBS_HAS_TIME) != 0 &&
            nowNs >= value.queue.last_operation_ns) {
            value.queue_age_ns = nowNs - value.queue.last_operation_ns;
            value.queue.presence_flags |= IWX_TXQ_OBS_HAS_QUEUE_AGE;
        } else {
            value.queue.presence_flags &= ~IWX_TXQ_OBS_HAS_QUEUE_AGE;
        }
    }
    const uint64_t mutationAfter = __atomic_load_n(
        &state->mutation_serial, __ATOMIC_ACQUIRE);
    value.snapshot_stable = mutationBefore == mutationAfter &&
        queueMutationBefore == queueMutationAfter &&
        queueValidBefore == queueValidAfter ? 1U : 0U;

    // One final lockless-state cut catches producers that failed their one
    // try-lock while this snapshot held the observer lock. Only downgrade;
    // never manufacture completeness from a late successful load.
    value.dropped_count = __atomic_load_n(&state->dropped_count,
                                           __ATOMIC_ACQUIRE);
    if (value.dropped_count != 0 ||
        __atomic_load_n(&state->incomplete, __ATOMIC_ACQUIRE) != 0)
        value.complete = 0;
    if (!value.complete) {
        value.queue_known = 0;
        value.queue.presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
    }
    if (__atomic_load_n(&state->armed_binding_known,
                        __ATOMIC_ACQUIRE) == 0) {
        if (value.arm_binding_known != 0 &&
            value.selected_reason == kSnapshotReasonArmedQid) {
            value.snapshot_stable = 0;
            value.queue_known = 0;
        }
        value.arm_binding_known = 0;
    }
    const uint64_t mutationFinal = __atomic_load_n(
        &state->mutation_serial, __ATOMIC_ACQUIRE);
    if (mutationFinal != mutationAfter) {
        value.snapshot_stable = 0;
        value.complete = 0;
    }
    if (validQid(selectedQid)) {
        const uint64_t queueMutationFinal = __atomic_load_n(
            &state->queue_mutation_serial[selectedQid], __ATOMIC_ACQUIRE);
        const uint32_t queueValidFinal = __atomic_load_n(
            &state->queue_valid[selectedQid], __ATOMIC_ACQUIRE);
        if (queueMutationFinal != queueMutationAfter ||
            queueValidFinal != queueValidAfter) {
            value.snapshot_stable = 0;
            value.queue_known = 0;
            value.complete = 0;
            value.queue.mutation_serial = queueMutationFinal;
            value.queue.presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
        }
        if (value.queue.committed_mutation_serial != queueMutationFinal ||
            value.queue.phase != IWX_TXQ_OBS_PHASE_ACTIVE ||
            (value.queue.presence_flags & IWX_TXQ_OBS_HAS_INCARNATION) == 0) {
            value.queue_known = 0;
            value.queue.presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
        }
    }
    if (!value.snapshot_stable) {
        value.complete = 0;
        value.queue_known = 0;
        value.queue.presence_flags &= ~IWX_TXQ_OBS_HAS_INCARNATION;
    }
    if (state->unknown_config_qid_pending != 0)
        value.complete = 0;
    unlock(state);
    *out = value;
    return true;
}

} // namespace IwxTxQueueObservation

#endif // __cplusplus

#endif // GEEK_IWX_TX_QUEUE_OBSERVATION_HPP
