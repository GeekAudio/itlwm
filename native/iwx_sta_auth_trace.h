#ifndef IWX_STA_AUTH_TRACE_H
#define IWX_STA_AUTH_TRACE_H

/* Tahoe-only fixed-capacity STA key-handshake diagnostics. */
#include <stdint.h>
#include <stddef.h>
#include "group2_tx_trace_helpers.h"

#define IWX_STA_AUTH_TRACE_MAGIC 0x41535449u /* LE bytes: ITSA */
#define IWX_STA_AUTH_TRACE_SCHEMA 1u
#define IWX_STA_AUTH_TRACE_LIVE_CAPACITY 16u
#define IWX_STA_AUTH_TRACE_FIRST_CAPACITY 8u /* seven pre-trigger + trigger */

enum IwxStaAuthTraceKind {
    IWX_STA_TRACE_GROUP1_BEGIN = 1,
    IWX_STA_TRACE_GROUP1_VALIDATION = 2,
    IWX_STA_TRACE_KEY_COMPONENT = 3,
    IWX_STA_TRACE_KEY_SUBMIT = 4,
    IWX_STA_TRACE_GROUP2_RESULT = 5,
    IWX_STA_TRACE_RX_DEAUTH = 6,
    IWX_STA_TRACE_RX_DISASSOC = 7,
    IWX_STA_TRACE_LOCAL_DEAUTH_TX = 8,
    IWX_STA_TRACE_GROUP1_LOCAL_FAILURE = 9,
    IWX_STA_TRACE_RUN_ESTABLISHED = 10,
    IWX_STA_TRACE_ASSOC_LOSS_REQUEST = 11,
    IWX_STA_TRACE_DRIVER_DEAUTH_CLEANUP = 12,
    IWX_STA_TRACE_ASSOC_LOSS = 13,
    IWX_STA_TRACE_GROUP2_CALLSITE_GATE = 14
};

enum IwxStaAuthTraceStage {
    IWX_STA_STAGE_NONE = 0,
    IWX_STA_STAGE_NOT_EXPECTED = 1,
    IWX_STA_STAGE_REPLAY_REJECT = 2,
    IWX_STA_STAGE_MIC_REJECT = 3,
    IWX_STA_STAGE_DECRYPT_REJECT = 4,
    IWX_STA_STAGE_GTK_MISSING = 5,
    IWX_STA_STAGE_GTK_LENGTH = 6,
    IWX_STA_STAGE_VALIDATED = 7,
    IWX_STA_STAGE_IGTK_LENGTH = 8,
    IWX_STA_STAGE_IGTK_ID = 9,
    IWX_STA_STAGE_GROUP1_TERMINAL = 10,
    IWX_STA_STAGE_KEY_DECISION = 11,
    IWX_STA_STAGE_KEY_PREWRITE = 12,
    IWX_STA_STAGE_KEY_CALLBACK = 13,
    IWX_STA_STAGE_GROUP2_OUTPUT = 14,
    IWX_STA_STAGE_RX_REASON = 15,
    IWX_STA_STAGE_STATE_REQUEST = 16,
    IWX_STA_STAGE_STATE_COMPLETED = 17,
    IWX_STA_STAGE_ASSOC_COMPLETE = 18,
    IWX_STA_STAGE_DRIVER_CLEANUP_ENTER = 19,
    IWX_STA_STAGE_DRIVER_CLEANUP_RETURN = 20,
    IWX_STA_STAGE_GROUP2_CALLSITE_GATE = 21
};

enum IwxStaAuthTraceComponent {
    IWX_STA_COMPONENT_NONE = 0,
    IWX_STA_COMPONENT_GTK = 1,
    IWX_STA_COMPONENT_IGTK = 2
};

enum IwxStaAuthTraceSource {
    IWX_STA_SOURCE_UNKNOWN = 0,
    IWX_STA_SOURCE_RX_PEER = 1,
    IWX_STA_SOURCE_LOCAL_GROUP1 = 2,
    IWX_STA_SOURCE_DRIVER_CLEANUP = 3,
    IWX_STA_SOURCE_HAL_COMMAND = 4,
    IWX_STA_SOURCE_SOFTWARE_CRYPTO = 5
};

enum IwxStaAuthTraceFlags {
    IWX_STA_FLAG_ACCEPTED_ZERO = 1u << 0,
    IWX_STA_FLAG_ACCEPTED_EBUSY = 1u << 1,
    IWX_STA_FLAG_PREWRITE = 1u << 2,
    IWX_STA_FLAG_COMPONENT_UPDATED = 1u << 3,
    IWX_STA_FLAG_COMPONENT_SKIPPED = 1u << 4,
    IWX_STA_FLAG_SUBMIT_REJECTED_BEFORE_RING = 1u << 5,
    IWX_STA_FLAG_DOORBELL_ISSUED = 1u << 6,
    IWX_STA_FLAG_SUBMIT_UNKNOWN = 1u << 7,
    IWX_STA_FLAG_FIRST_TRIGGER_LOST = 1u << 8,
    IWX_STA_FLAG_GROUP2_TX_MGMT_ONLY = 1u << 9,
    IWX_STA_FLAG_GROUP2_BGSCAN = 1u << 10,
    IWX_STA_FLAG_GROUP2_SCAN_PHASE_PRESENT = 1u << 11
};

enum IwxStaAuthSubmitState {
    IWX_STA_SUBMIT_UNKNOWN = 0,
    IWX_STA_SUBMIT_REJECTED_BEFORE_RING = 1,
    IWX_STA_SUBMIT_LOCAL_ENQUEUE = 2,
    IWX_STA_SUBMIT_OTHER_ERROR = 3,
    IWX_STA_SUBMIT_SOFTWARE_CRYPTO = 4
};

enum IwxStaAuthSnapshotFlags {
    IWX_STA_SNAPSHOT_FIRST_TRIGGER_LOST = 1u << 0
};

struct IwxStaAuthSubmitReceipt {
    uint32_t state;
    uint32_t command_id;
    uint32_t driver_generation;
    uint32_t queue_id;
    uint32_t queue_index;
    int32_t raw_command_result;
    int32_t key_callback_result;
};

struct IwxStaAuthTraceEvent {
    uint32_t sequence;
    uint32_t monotonic_us_low;
    uint32_t monotonic_us_high;
    uint32_t diagnostic_instance;
    uint32_t driver_generation;
    uint32_t association_id;
    uint32_t attempt_id;
    uint16_t kind;
    uint16_t stage;
    uint16_t component;
    uint16_t source;
    int32_t result;
    uint32_t flags;
    uint32_t detail;
};

struct IwxStaAuthTraceInput {
    uint64_t monotonic_us;
    uint32_t driver_generation;
    uint32_t attempt_id;
    uint16_t kind;
    uint16_t stage;
    uint16_t component;
    uint16_t source;
    int32_t result;
    uint32_t flags;
    uint32_t detail;
    uint8_t freeze_first_failure;
};

/* In-memory state. All shared scalars and event fields use atomic access. */
struct IwxStaAuthTrace {
    uint32_t writer;
    uint32_t revision;
    uint32_t next_sequence;
    uint32_t dropped_count;
    uint32_t diagnostic_instance;
    uint32_t driver_generation;
    uint32_t association_id;
    uint32_t next_association_id;
    uint32_t next_attempt_id;
    uint32_t live_count;
    uint32_t live_cursor;
    uint32_t first_state; /* 0=unclaimed, 1=claimed, 2=frozen, 3=lost */
    uint32_t first_count;
    struct IwxGroup2TxTrace group2_tx;
    struct IwxStaAuthTraceEvent live[IWX_STA_AUTH_TRACE_LIVE_CAPACITY];
    struct IwxStaAuthTraceEvent first[IWX_STA_AUTH_TRACE_FIRST_CAPACITY];
};

/* Stable public wire layout. The publisher converts every field to LE. */
struct IwxStaAuthTraceSnapshot {
    uint32_t magic;
    uint16_t schema;
    uint16_t header_bytes;
    uint16_t record_bytes;
    uint16_t capacity;
    uint32_t revision_begin;
    uint32_t revision_end;
    uint32_t flags;
    uint32_t live_count;
    uint32_t dropped_count;
    uint32_t diagnostic_instance;
    uint32_t driver_generation;
    uint32_t association_id;
    uint32_t next_attempt_id;
    uint32_t first_state;
    uint32_t first_count;
    struct IwxStaAuthTraceEvent live[IWX_STA_AUTH_TRACE_LIVE_CAPACITY];
    struct IwxStaAuthTraceEvent first[IWX_STA_AUTH_TRACE_FIRST_CAPACITY];
};

#if defined(__cplusplus)
static_assert(sizeof(IwxStaAuthTraceEvent) == 48, "STA trace record ABI");
static_assert(offsetof(IwxStaAuthTraceEvent, kind) == 28, "STA trace kind offset ABI");
static_assert(offsetof(IwxStaAuthTraceSnapshot, live) == 56, "STA trace header ABI");
static_assert(sizeof(IwxStaAuthTraceSnapshot) == 1208, "STA trace snapshot ABI");
#else
_Static_assert(sizeof(struct IwxStaAuthTraceEvent) == 48, "STA trace record ABI");
_Static_assert(offsetof(struct IwxStaAuthTraceEvent, kind) == 28, "STA trace kind offset ABI");
_Static_assert(offsetof(struct IwxStaAuthTraceSnapshot, live) == 56, "STA trace header ABI");
_Static_assert(sizeof(struct IwxStaAuthTraceSnapshot) == 1208, "STA trace snapshot ABI");
#endif

static inline void iwx_sta_auth_trace_init(struct IwxStaAuthTrace *trace, uint32_t instance)
{
    if (trace == NULL)
        return;
    __builtin_memset(trace, 0, sizeof(*trace));
    __atomic_store_n(&trace->diagnostic_instance, instance, __ATOMIC_RELEASE);
    iwx_group2_tx_trace_init(&trace->group2_tx);
}

static inline int iwx_sta_auth_trace_try_lock(struct IwxStaAuthTrace *trace)
{
    return __atomic_exchange_n(&trace->writer, 1u, __ATOMIC_ACQUIRE) == 0u;
}

static inline void iwx_sta_auth_trace_unlock(struct IwxStaAuthTrace *trace)
{
    __atomic_store_n(&trace->writer, 0u, __ATOMIC_RELEASE);
}

static inline void iwx_sta_auth_trace_store_event(struct IwxStaAuthTraceEvent *dst, const struct IwxStaAuthTraceEvent *src)
{
    __atomic_store_n(&dst->sequence, src->sequence, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->monotonic_us_low, src->monotonic_us_low, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->monotonic_us_high, src->monotonic_us_high, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->diagnostic_instance, src->diagnostic_instance, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->driver_generation, src->driver_generation, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->association_id, src->association_id, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->attempt_id, src->attempt_id, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->kind, src->kind, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->stage, src->stage, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->component, src->component, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->source, src->source, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->result, src->result, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->flags, src->flags, __ATOMIC_RELAXED);
    __atomic_store_n(&dst->detail, src->detail, __ATOMIC_RELAXED);
}

static inline void iwx_sta_auth_trace_load_event(struct IwxStaAuthTraceEvent *dst, const struct IwxStaAuthTraceEvent *src)
{
    dst->sequence = __atomic_load_n(&src->sequence, __ATOMIC_RELAXED);
    dst->monotonic_us_low = __atomic_load_n(&src->monotonic_us_low, __ATOMIC_RELAXED);
    dst->monotonic_us_high = __atomic_load_n(&src->monotonic_us_high, __ATOMIC_RELAXED);
    dst->diagnostic_instance = __atomic_load_n(&src->diagnostic_instance, __ATOMIC_RELAXED);
    dst->driver_generation = __atomic_load_n(&src->driver_generation, __ATOMIC_RELAXED);
    dst->association_id = __atomic_load_n(&src->association_id, __ATOMIC_RELAXED);
    dst->attempt_id = __atomic_load_n(&src->attempt_id, __ATOMIC_RELAXED);
    dst->kind = __atomic_load_n(&src->kind, __ATOMIC_RELAXED);
    dst->stage = __atomic_load_n(&src->stage, __ATOMIC_RELAXED);
    dst->component = __atomic_load_n(&src->component, __ATOMIC_RELAXED);
    dst->source = __atomic_load_n(&src->source, __ATOMIC_RELAXED);
    dst->result = __atomic_load_n(&src->result, __ATOMIC_RELAXED);
    dst->flags = __atomic_load_n(&src->flags, __ATOMIC_RELAXED);
    dst->detail = __atomic_load_n(&src->detail, __ATOMIC_RELAXED);
}

static inline void iwx_sta_auth_trace_append_locked(struct IwxStaAuthTrace *trace, const struct IwxStaAuthTraceInput *input, struct IwxStaAuthTraceEvent *written)
{
    struct IwxStaAuthTraceEvent event = {};
    event.sequence = __atomic_add_fetch(&trace->next_sequence, 1u, __ATOMIC_RELAXED);
    event.monotonic_us_low = (uint32_t)input->monotonic_us;
    event.monotonic_us_high = (uint32_t)(input->monotonic_us >> 32);
    event.diagnostic_instance = __atomic_load_n(&trace->diagnostic_instance, __ATOMIC_RELAXED);
    event.driver_generation = input->driver_generation;
    __atomic_store_n(&trace->driver_generation, input->driver_generation, __ATOMIC_RELAXED);
    event.association_id = __atomic_load_n(&trace->association_id, __ATOMIC_RELAXED);
    event.attempt_id = input->attempt_id;
    event.kind = input->kind;
    event.stage = input->stage;
    event.component = input->component;
    event.source = input->source;
    event.result = input->result;
    event.flags = input->flags;
    event.detail = input->detail;
    const uint32_t cursor = __atomic_load_n(&trace->live_cursor, __ATOMIC_RELAXED);
    iwx_sta_auth_trace_store_event(&trace->live[cursor], &event);
    __atomic_store_n(&trace->live_cursor, (cursor + 1u) % IWX_STA_AUTH_TRACE_LIVE_CAPACITY, __ATOMIC_RELAXED);
    const uint32_t count = __atomic_load_n(&trace->live_count, __ATOMIC_RELAXED);
    if (count < IWX_STA_AUTH_TRACE_LIVE_CAPACITY)
        __atomic_store_n(&trace->live_count, count + 1u, __ATOMIC_RELAXED);
    if (written != NULL)
        *written = event;
}

static inline int iwx_sta_auth_trace_record(struct IwxStaAuthTrace *trace, const struct IwxStaAuthTraceInput *input)
{
    if (trace == NULL || input == NULL)
        return 0;
    int claimed_first = 0;
    if (input->freeze_first_failure) {
        uint32_t expected = 0;
        claimed_first = __atomic_compare_exchange_n(&trace->first_state, &expected, 1u, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    /* Do not let a later writer overtake a claimed first trigger if its
     * owner is preempted before it can acquire the try-only writer token. */
    if (!claimed_first &&
        __atomic_load_n(&trace->first_state, __ATOMIC_ACQUIRE) == 1u) {
        __atomic_add_fetch(&trace->dropped_count, 1u, __ATOMIC_RELAXED);
        return 0;
    }
    if (!iwx_sta_auth_trace_try_lock(trace)) {
        __atomic_add_fetch(&trace->dropped_count, 1u, __ATOMIC_RELAXED);
        if (claimed_first)
            __atomic_store_n(&trace->first_state, 3u, __ATOMIC_RELEASE);
        return 0;
    }
    /* Recheck after acquiring the writer token. A non-trigger that read
     * state=0 just before the trigger claim must not enter the preimage. */
    if (!claimed_first &&
        __atomic_load_n(&trace->first_state, __ATOMIC_ACQUIRE) == 1u) {
        iwx_sta_auth_trace_unlock(trace);
        __atomic_add_fetch(&trace->dropped_count, 1u, __ATOMIC_RELAXED);
        return 0;
    }
    __atomic_add_fetch(&trace->revision, 1u, __ATOMIC_RELEASE); /* odd */
    struct IwxStaAuthTraceEvent event = {};
    iwx_sta_auth_trace_append_locked(trace, input, &event);
    if (claimed_first) {
        const uint32_t count = __atomic_load_n(&trace->live_count, __ATOMIC_RELAXED);
        const uint32_t cursor = __atomic_load_n(&trace->live_cursor, __ATOMIC_RELAXED);
        const uint32_t before = count > 0 ? count - 1u : 0u;
        const uint32_t take = before < (IWX_STA_AUTH_TRACE_FIRST_CAPACITY - 1u) ? before : (IWX_STA_AUTH_TRACE_FIRST_CAPACITY - 1u);
        const uint32_t start = (cursor + IWX_STA_AUTH_TRACE_LIVE_CAPACITY - 1u - take) % IWX_STA_AUTH_TRACE_LIVE_CAPACITY;
        for (uint32_t i = 0; i < take; ++i) {
            const uint32_t source = (start + i) % IWX_STA_AUTH_TRACE_LIVE_CAPACITY;
            struct IwxStaAuthTraceEvent prior = {};
            iwx_sta_auth_trace_load_event(&prior, &trace->live[source]);
            iwx_sta_auth_trace_store_event(&trace->first[i], &prior);
        }
        iwx_sta_auth_trace_store_event(&trace->first[take], &event);
        __atomic_store_n(&trace->first_count, take + 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&trace->first_state, 2u, __ATOMIC_RELEASE);
    }
    __atomic_add_fetch(&trace->revision, 1u, __ATOMIC_RELEASE); /* even */
    iwx_sta_auth_trace_unlock(trace);
    return 1;
}

static inline uint32_t iwx_sta_auth_trace_begin_attempt(struct IwxStaAuthTrace *trace, uint64_t monotonic_us, uint32_t driver_generation)
{
    if (trace == NULL)
        return 0;
    uint32_t attempt = __atomic_add_fetch(&trace->next_attempt_id, 1u, __ATOMIC_RELAXED);
    if (attempt == 0)
        attempt = __atomic_add_fetch(&trace->next_attempt_id, 1u, __ATOMIC_RELAXED);
    struct IwxStaAuthTraceInput input = {};
    input.monotonic_us = monotonic_us;
    input.driver_generation = driver_generation;
    input.attempt_id = attempt;
    input.kind = IWX_STA_TRACE_GROUP1_BEGIN;
    input.source = IWX_STA_SOURCE_RX_PEER;
    (void)iwx_sta_auth_trace_record(trace, &input);
    return attempt;
}

static inline uint32_t iwx_sta_auth_trace_begin_run(struct IwxStaAuthTrace *trace)
{
    if (trace == NULL || !iwx_sta_auth_trace_try_lock(trace)) {
        if (trace != NULL) {
            __atomic_store_n(&trace->association_id, 0u, __ATOMIC_RELEASE);
            __atomic_add_fetch(&trace->dropped_count, 1u, __ATOMIC_RELAXED);
        }
        return 0;
    }
    __atomic_add_fetch(&trace->revision, 1u, __ATOMIC_RELEASE);
    uint32_t association = __atomic_add_fetch(&trace->next_association_id, 1u, __ATOMIC_RELAXED);
    if (association == 0)
        association = __atomic_add_fetch(&trace->next_association_id, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&trace->association_id, association, __ATOMIC_RELAXED);
    __atomic_add_fetch(&trace->revision, 1u, __ATOMIC_RELEASE);
    iwx_sta_auth_trace_unlock(trace);
    return association;
}

static inline void iwx_sta_auth_trace_end_run(struct IwxStaAuthTrace *trace)
{
    if (trace == NULL)
        return;
    if (!iwx_sta_auth_trace_try_lock(trace)) {
        __atomic_store_n(&trace->association_id, 0u, __ATOMIC_RELEASE);
        __atomic_add_fetch(&trace->dropped_count, 1u, __ATOMIC_RELAXED);
        return;
    }
    __atomic_add_fetch(&trace->revision, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&trace->association_id, 0u, __ATOMIC_RELAXED);
    __atomic_add_fetch(&trace->revision, 1u, __ATOMIC_RELEASE);
    iwx_sta_auth_trace_unlock(trace);
}

static inline int iwx_sta_auth_trace_snapshot(const struct IwxStaAuthTrace *trace, struct IwxStaAuthTraceSnapshot *snapshot)
{
    if (trace == NULL || snapshot == NULL)
        return 0;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        const uint32_t begin = __atomic_load_n(&trace->revision, __ATOMIC_ACQUIRE);
        if (begin & 1u)
            continue;
        __builtin_memset(snapshot, 0, sizeof(*snapshot));
        snapshot->magic = IWX_STA_AUTH_TRACE_MAGIC;
        snapshot->schema = IWX_STA_AUTH_TRACE_SCHEMA;
        snapshot->header_bytes = (uint16_t)offsetof(struct IwxStaAuthTraceSnapshot, live);
        snapshot->record_bytes = (uint16_t)sizeof(struct IwxStaAuthTraceEvent);
        snapshot->capacity = IWX_STA_AUTH_TRACE_LIVE_CAPACITY;
        snapshot->live_count = __atomic_load_n(&trace->live_count, __ATOMIC_RELAXED);
        const uint32_t dropped_begin = __atomic_load_n(&trace->dropped_count, __ATOMIC_RELAXED);
        snapshot->dropped_count = dropped_begin;
        snapshot->diagnostic_instance = __atomic_load_n(&trace->diagnostic_instance, __ATOMIC_RELAXED);
        snapshot->driver_generation = __atomic_load_n(&trace->driver_generation, __ATOMIC_RELAXED);
        snapshot->association_id = __atomic_load_n(&trace->association_id, __ATOMIC_RELAXED);
        const uint32_t association_begin = snapshot->association_id;
        const uint32_t attempt_begin = __atomic_load_n(&trace->next_attempt_id, __ATOMIC_RELAXED);
        snapshot->next_attempt_id = attempt_begin;
        snapshot->first_state = __atomic_load_n(&trace->first_state, __ATOMIC_RELAXED);
        const uint32_t first_state_begin = snapshot->first_state;
        if (snapshot->first_state == 3u)
            snapshot->flags |= IWX_STA_SNAPSHOT_FIRST_TRIGGER_LOST;
        snapshot->first_count = __atomic_load_n(&trace->first_count, __ATOMIC_RELAXED);
        const uint32_t cursor = __atomic_load_n(&trace->live_cursor, __ATOMIC_RELAXED);
        const uint32_t count = snapshot->live_count < IWX_STA_AUTH_TRACE_LIVE_CAPACITY
            ? snapshot->live_count : IWX_STA_AUTH_TRACE_LIVE_CAPACITY;
        const uint32_t start = (cursor + IWX_STA_AUTH_TRACE_LIVE_CAPACITY - count) %
            IWX_STA_AUTH_TRACE_LIVE_CAPACITY;
        for (uint32_t i = 0; i < count; ++i) {
            const uint32_t source = (start + i) % IWX_STA_AUTH_TRACE_LIVE_CAPACITY;
            iwx_sta_auth_trace_load_event(&snapshot->live[i], &trace->live[source]);
        }
        for (uint32_t i = 0; i < IWX_STA_AUTH_TRACE_FIRST_CAPACITY; ++i)
            iwx_sta_auth_trace_load_event(&snapshot->first[i], &trace->first[i]);
        const uint32_t end = __atomic_load_n(&trace->revision, __ATOMIC_ACQUIRE);
        const uint32_t dropped_end = __atomic_load_n(&trace->dropped_count, __ATOMIC_RELAXED);
        const uint32_t attempt_end = __atomic_load_n(&trace->next_attempt_id, __ATOMIC_RELAXED);
        const uint32_t first_state_end = __atomic_load_n(&trace->first_state, __ATOMIC_ACQUIRE);
        const uint32_t first_count_end = __atomic_load_n(&trace->first_count, __ATOMIC_RELAXED);
        const uint32_t association_end = __atomic_load_n(&trace->association_id, __ATOMIC_ACQUIRE);
        snapshot->revision_begin = begin;
        snapshot->revision_end = end;
        if (begin == end && !(end & 1u) && dropped_begin == dropped_end &&
            attempt_begin == attempt_end && first_state_begin == first_state_end &&
            snapshot->first_count == first_count_end &&
            association_begin == association_end)
            return 1;
    }
    return 0;
}

#endif /* IWX_STA_AUTH_TRACE_H */
