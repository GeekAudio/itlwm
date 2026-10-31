#ifndef IWX_GROUP2_TX_TRACE_HELPERS_H
#define IWX_GROUP2_TX_TRACE_HELPERS_H

/*
 * Bounded numeric observations for one Group2 invocation and its TX path.
 * This helper never owns packets, queue entries, TX slots, or firmware state.
 */
#include <stdint.h>
#include <stddef.h>

#define IWX_GROUP2_TX_TRACE_MAGIC 0x47545849u /* LE bytes: IXTG */
#define IWX_GROUP2_TX_TRACE_SCHEMA 1u
#define IWX_GROUP2_TX_TRACE_CAPACITY 32u
#define IWX_GROUP2_TX_SLOT_CAPACITY 32u
#define IWX_GROUP2_TX_TAG_MAGIC 0x47525449u /* LE bytes: ITRG */
#define IWX_GROUP2_TX_TAG_VERSION 1u
#define IWX_GROUP2_TX_TAG_TYPE 0x0942u

enum IwxGroup2TxSource {
    IWX_GROUP2_TX_SOURCE_UNKNOWN = 0,
    IWX_GROUP2_TX_SOURCE_RSN = 1,
    IWX_GROUP2_TX_SOURCE_WPA = 2
};

enum IwxGroup2TxStage {
    IWX_GROUP2_TX_STAGE_ORIGIN = 1,
    IWX_GROUP2_TX_STAGE_MBUF_ALLOC_FAILED = 2,
    IWX_GROUP2_TX_STAGE_TAG_UNAVAILABLE = 3,
    IWX_GROUP2_TX_STAGE_TAG_ATTACH_FAILED = 4,
    IWX_GROUP2_TX_STAGE_IFQ_ENQUEUE = 5,
    IWX_GROUP2_TX_STAGE_DEQUEUE_NO_TAG = 6,
    IWX_GROUP2_TX_STAGE_DEQUEUED = 7,
    IWX_GROUP2_TX_STAGE_PULLUP_FAILED = 8,
    IWX_GROUP2_TX_STAGE_ENCAP_FAILED = 9,
    IWX_GROUP2_TX_STAGE_IWX_TX_REJECTED = 10,
    IWX_GROUP2_TX_STAGE_SLOT_COMMITTED = 11,
    IWX_GROUP2_TX_STAGE_DOORBELL = 12,
    IWX_GROUP2_TX_STAGE_TX_RSP_MATCH = 13,
    IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN = 14,
    IWX_GROUP2_TX_STAGE_SLOT_RETIRED = 15,
    IWX_GROUP2_TX_STAGE_RESET_INVALIDATED = 16,
    IWX_GROUP2_TX_STAGE_TRACE_LOST = 17,
    IWX_GROUP2_TX_STAGE_PREPEND_FAILED = 18,
    IWX_GROUP2_TX_STAGE_FLUSH_RECLAIM_UNKNOWN = 19
};

enum IwxGroup2TxFlags {
    IWX_GROUP2_TX_HAS_COOKIE = 1u << 0,
    IWX_GROUP2_TX_HAS_ATTEMPT = 1u << 1,
    IWX_GROUP2_TX_HAS_SOURCE = 1u << 2,
    IWX_GROUP2_TX_HAS_ORIGIN_GENERATION = 1u << 3,
    IWX_GROUP2_TX_HAS_ORIGIN_ASSOCIATION = 1u << 4,
    IWX_GROUP2_TX_HAS_CONTEXT_GENERATION = 1u << 5,
    IWX_GROUP2_TX_HAS_OUTPUT_EPOCH = 1u << 6,
    IWX_GROUP2_TX_HAS_QUEUE = 1u << 7,
    IWX_GROUP2_TX_HAS_SLOT = 1u << 8,
    IWX_GROUP2_TX_HAS_SLOT_GENERATION = 1u << 9,
    IWX_GROUP2_TX_HAS_FRAME_CONTROL = 1u << 10,
    IWX_GROUP2_TX_HAS_SEQUENCE_CONTROL = 1u << 11,
    IWX_GROUP2_TX_HAS_MATCH_RESULT = 1u << 12,
    IWX_GROUP2_TX_RESET_AMBIGUOUS = 1u << 13,
    IWX_GROUP2_TX_QUEUE_DROP_COUNT_PRESENT = 1u << 14,
    IWX_GROUP2_TX_TAG_PRESENT = 1u << 15,
    IWX_GROUP2_TX_HAS_COMPLETION_BOUNDARY = 1u << 16,
    IWX_GROUP2_TX_HAS_FIRMWARE_STATUS = 1u << 17
};

enum IwxGroup2TxCompletionMatch {
    IWX_GROUP2_TX_MATCH_UNKNOWN = 0,
    IWX_GROUP2_TX_MATCH_UNIQUE = 1,
    IWX_GROUP2_TX_MATCH_NONE = 2,
    IWX_GROUP2_TX_MATCH_MULTIPLE = 3,
    IWX_GROUP2_TX_MATCH_BAD_RANGE = 4,
    IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS = 5,
    IWX_GROUP2_TX_MATCH_GENERATION_MISMATCH = 6
};

struct IwxGroup2TxTag {
    uint32_t magic;
    uint16_t version;
    uint16_t bytes;
    uint64_t cookie;
    uint32_t attempt_id;
    uint32_t source;
    uint32_t origin_generation;
    uint32_t origin_association;
};

struct IwxGroup2TxEvent {
    uint64_t sequence;
    uint64_t monotonic_us;
    uint64_t cookie;
    uint64_t slot_generation;
    uint32_t attempt_id;
    uint32_t source;
    uint32_t origin_generation;
    uint32_t origin_association;
    uint32_t context_generation;
    uint32_t output_epoch;
    uint32_t queue_id;
    uint32_t index;
    uint32_t ring_count;
    uint32_t frame_control;
    uint32_t sequence_control;
    uint32_t tid;
    int32_t result;
    uint32_t flags;
    uint16_t stage;
    uint16_t status;
};

struct IwxGroup2TxSlot {
    uint64_t cookie;
    uint64_t slot_generation;
    uint32_t attempt_id;
    uint32_t source;
    uint32_t origin_generation;
    uint32_t origin_association;
    uint32_t context_generation;
    uint32_t output_epoch;
    uint32_t queue_id;
    uint32_t index;
    uint32_t ring_count;
    uint32_t frame_control;
    uint32_t sequence_control;
    uint32_t tid;
    uint32_t identity_epoch;
    uint32_t valid;
};

struct IwxGroup2TxTrace {
    uint32_t writer;
    uint32_t dropped_count;
    uint32_t identity_epoch;
    uint32_t event_count;
    uint32_t event_cursor;
    uint32_t cookie_saturated;
    uint32_t slot_generation_saturated;
    uint32_t mbuf_tag_id;
    uint32_t mbuf_tag_id_present;
    int32_t mbuf_tag_id_result;
    uint64_t revision;
    uint64_t next_cookie;
    uint64_t next_event_sequence;
    uint64_t next_slot_generation;
    struct IwxGroup2TxEvent events[IWX_GROUP2_TX_TRACE_CAPACITY];
    struct IwxGroup2TxSlot slots[IWX_GROUP2_TX_SLOT_CAPACITY];
};

struct IwxGroup2TxTraceSnapshot {
    uint32_t magic;
    uint16_t schema;
    uint16_t header_bytes;
    uint16_t event_bytes;
    uint16_t capacity;
    uint64_t revision_begin;
    uint64_t revision_end;
    uint32_t dropped_count;
    uint32_t event_count;
    uint64_t next_cookie;
    uint64_t next_event_sequence;
    uint64_t next_slot_generation;
    uint32_t flags;
    struct IwxGroup2TxEvent events[IWX_GROUP2_TX_TRACE_CAPACITY];
};

#define IWX_GROUP2_TX_TRACE_SNAPSHOT_HEADER_BYTES 72u
#define IWX_GROUP2_TX_TRACE_SNAPSHOT_BYTES \
    (IWX_GROUP2_TX_TRACE_SNAPSHOT_HEADER_BYTES + \
     IWX_GROUP2_TX_TRACE_CAPACITY * 96u)

#if defined(__cplusplus)
static_assert(sizeof(IwxGroup2TxTag) == 32, "Group2 tag ABI");
static_assert(sizeof(IwxGroup2TxEvent) == 96, "Group2 trace event ABI");
static_assert(offsetof(IwxGroup2TxTraceSnapshot, events) ==
                  IWX_GROUP2_TX_TRACE_SNAPSHOT_HEADER_BYTES,
              "Group2 trace snapshot header ABI");
static_assert(sizeof(IwxGroup2TxTraceSnapshot) ==
                  IWX_GROUP2_TX_TRACE_SNAPSHOT_BYTES,
              "Group2 trace snapshot ABI");
#else
_Static_assert(sizeof(struct IwxGroup2TxTag) == 32, "Group2 tag ABI");
_Static_assert(sizeof(struct IwxGroup2TxEvent) == 96, "Group2 trace event ABI");
_Static_assert(offsetof(struct IwxGroup2TxTraceSnapshot, events) ==
                   IWX_GROUP2_TX_TRACE_SNAPSHOT_HEADER_BYTES,
               "Group2 trace snapshot header ABI");
_Static_assert(sizeof(struct IwxGroup2TxTraceSnapshot) ==
                   IWX_GROUP2_TX_TRACE_SNAPSHOT_BYTES,
               "Group2 trace snapshot ABI");
#endif

static inline void iwx_group2_tx_trace_init(struct IwxGroup2TxTrace *trace)
{
    if (trace != NULL)
        __builtin_memset(trace, 0, sizeof(*trace));
}

static inline int iwx_group2_tx_trace_try_lock(struct IwxGroup2TxTrace *trace)
{
    return __atomic_exchange_n(&trace->writer, 1u, __ATOMIC_ACQUIRE) == 0u;
}

static inline void iwx_group2_tx_trace_unlock(struct IwxGroup2TxTrace *trace)
{
    __atomic_store_n(&trace->writer, 0u, __ATOMIC_RELEASE);
}

static inline void iwx_group2_tx_trace_note_drop(
    struct IwxGroup2TxTrace *trace)
{
    if (trace == NULL)
        return;
    uint32_t value = __atomic_load_n(&trace->dropped_count, __ATOMIC_RELAXED);
    while (value != UINT32_MAX &&
           !__atomic_compare_exchange_n(&trace->dropped_count, &value,
               value + 1u, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
}

static inline void iwx_group2_tx_trace_note_lost(struct IwxGroup2TxTrace *trace)
{
    if (trace == NULL)
        return;
    uint32_t epoch = __atomic_load_n(&trace->identity_epoch,
                                     __ATOMIC_RELAXED);
    while (epoch != UINT32_MAX &&
           !__atomic_compare_exchange_n(&trace->identity_epoch, &epoch,
               epoch + 1u, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
    }
    iwx_group2_tx_trace_note_drop(trace);
}

static inline uint32_t iwx_group2_tx_trace_identity_epoch(
    const struct IwxGroup2TxTrace *trace)
{
    return trace == NULL ? UINT32_MAX :
        __atomic_load_n(&trace->identity_epoch, __ATOMIC_ACQUIRE);
}

static inline void iwx_group2_tx_trace_bump_revision_locked(
    struct IwxGroup2TxTrace *trace)
{
    if (trace->revision <= UINT64_MAX - 2u)
        trace->revision += 2u;
    else
        trace->revision = UINT64_MAX - 1u;
}

static inline int iwx_group2_tx_trace_append_locked(
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxEvent *event)
{
    struct IwxGroup2TxEvent stored = *event;
    if (trace->next_event_sequence == UINT64_MAX) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    // Ring eviction loses only old diagnostic history. It must not poison
    // identity for slots that are still live and explicitly tracked.
    if (trace->event_count == IWX_GROUP2_TX_TRACE_CAPACITY)
        iwx_group2_tx_trace_note_drop(trace);
    stored.sequence = ++trace->next_event_sequence;
    const uint32_t cursor = trace->event_cursor;
    trace->events[cursor] = stored;
    trace->event_cursor = (cursor + 1u) % IWX_GROUP2_TX_TRACE_CAPACITY;
    if (trace->event_count < IWX_GROUP2_TX_TRACE_CAPACITY)
        ++trace->event_count;
    return 1;
}

/* Replace the newest event while retaining the sequence assigned at append.
 * The identity epoch may change asynchronously through note_lost() while the
 * writer lock is held. Callers then downgrade an appended identity to
 * unknown; copying the pre-append event verbatim would erase its sequence. */
static inline void iwx_group2_tx_trace_rewrite_last_locked(
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxEvent *event)
{
    if (trace == NULL || event == NULL || trace->event_count == 0)
        return;
    const uint32_t last = (trace->event_cursor +
        IWX_GROUP2_TX_TRACE_CAPACITY - 1u) % IWX_GROUP2_TX_TRACE_CAPACITY;
    struct IwxGroup2TxEvent replacement = *event;
    replacement.sequence = trace->events[last].sequence;
    trace->events[last] = replacement;
}

static inline int iwx_group2_tx_trace_record(
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxEvent *event)
{
    if (trace == NULL || event == NULL)
        return 0;
    if (!iwx_group2_tx_trace_try_lock(trace)) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    iwx_group2_tx_trace_append_locked(trace, event);
    iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
    return 1;
}

static inline int iwx_group2_tx_trace_begin(
    struct IwxGroup2TxTrace *trace, uint64_t monotonic_us,
    uint32_t attempt_id, uint32_t source, uint32_t origin_generation,
    uint32_t origin_association, struct IwxGroup2TxTag *tag_out)
{
    if (trace == NULL || tag_out == NULL || attempt_id == 0 ||
        (source != IWX_GROUP2_TX_SOURCE_RSN &&
         source != IWX_GROUP2_TX_SOURCE_WPA))
        return 0;
    if (!iwx_group2_tx_trace_try_lock(trace)) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    if (trace->cookie_saturated || trace->next_cookie == UINT64_MAX) {
        trace->cookie_saturated = 1;
        iwx_group2_tx_trace_note_lost(trace);
        iwx_group2_tx_trace_bump_revision_locked(trace);
        iwx_group2_tx_trace_unlock(trace);
        return 0;
    }
    __builtin_memset(tag_out, 0, sizeof(*tag_out));
    tag_out->magic = IWX_GROUP2_TX_TAG_MAGIC;
    tag_out->version = IWX_GROUP2_TX_TAG_VERSION;
    tag_out->bytes = (uint16_t)sizeof(*tag_out);
    tag_out->cookie = ++trace->next_cookie;
    tag_out->attempt_id = attempt_id;
    tag_out->source = source;
    tag_out->origin_generation = origin_generation;
    tag_out->origin_association = origin_association;
    struct IwxGroup2TxEvent event = {};
    event.monotonic_us = monotonic_us;
    event.cookie = tag_out->cookie;
    event.attempt_id = attempt_id;
    event.source = source;
    event.origin_generation = origin_generation;
    event.origin_association = origin_association;
    event.flags = IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
        IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION;
    if (origin_association != 0)
        event.flags |= IWX_GROUP2_TX_HAS_ORIGIN_ASSOCIATION;
    event.stage = IWX_GROUP2_TX_STAGE_ORIGIN;
    iwx_group2_tx_trace_append_locked(trace, &event);
    iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
    return 1;
}

static inline int iwx_group2_tx_trace_next_slot_generation(
    struct IwxGroup2TxTrace *trace, uint64_t *generation_out)
{
    if (trace == NULL || generation_out == NULL)
        return 0;
    if (!iwx_group2_tx_trace_try_lock(trace)) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    if (trace->slot_generation_saturated ||
        trace->next_slot_generation == UINT64_MAX) {
        trace->slot_generation_saturated = 1;
        iwx_group2_tx_trace_note_lost(trace);
        iwx_group2_tx_trace_unlock(trace);
        return 0;
    }
    *generation_out = ++trace->next_slot_generation;
    iwx_group2_tx_trace_unlock(trace);
    return 1;
}

static inline int iwx_group2_tx_tag_valid(const struct IwxGroup2TxTag *tag)
{
    return tag != NULL && tag->magic == IWX_GROUP2_TX_TAG_MAGIC &&
        tag->version == IWX_GROUP2_TX_TAG_VERSION &&
        tag->bytes == sizeof(*tag) && tag->cookie != 0 &&
        tag->attempt_id != 0 &&
        (tag->source == IWX_GROUP2_TX_SOURCE_RSN ||
         tag->source == IWX_GROUP2_TX_SOURCE_WPA);
}

static inline void iwx_group2_tx_event_from_tag(
    struct IwxGroup2TxEvent *event, const struct IwxGroup2TxTag *tag,
    uint64_t monotonic_us, uint16_t stage)
{
    if (event == NULL)
        return;
    __builtin_memset(event, 0, sizeof(*event));
    event->monotonic_us = monotonic_us;
    event->stage = stage;
    if (!iwx_group2_tx_tag_valid(tag))
        return;
    event->cookie = tag->cookie;
    event->attempt_id = tag->attempt_id;
    event->source = tag->source;
    event->origin_generation = tag->origin_generation;
    event->origin_association = tag->origin_association;
    event->flags = IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
        IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION;
    if (tag->origin_association != 0)
        event->flags |= IWX_GROUP2_TX_HAS_ORIGIN_ASSOCIATION;
}

static inline void iwx_group2_tx_event_from_slot(
    struct IwxGroup2TxEvent *event, const struct IwxGroup2TxSlot *slot,
    uint64_t monotonic_us, uint16_t stage)
{
    if (event == NULL)
        return;
    __builtin_memset(event, 0, sizeof(*event));
    event->monotonic_us = monotonic_us;
    event->stage = stage;
    if (slot == NULL || !slot->valid || slot->cookie == 0)
        return;
    event->cookie = slot->cookie;
    event->slot_generation = slot->slot_generation;
    event->attempt_id = slot->attempt_id;
    event->source = slot->source;
    event->origin_generation = slot->origin_generation;
    event->origin_association = slot->origin_association;
    event->context_generation = slot->context_generation;
    event->output_epoch = slot->output_epoch;
    event->queue_id = slot->queue_id;
    event->index = slot->index;
    event->ring_count = slot->ring_count;
    event->frame_control = slot->frame_control;
    event->sequence_control = slot->sequence_control;
    event->tid = slot->tid;
    event->flags = IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
        IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION |
        IWX_GROUP2_TX_HAS_CONTEXT_GENERATION | IWX_GROUP2_TX_HAS_OUTPUT_EPOCH |
        IWX_GROUP2_TX_HAS_QUEUE | IWX_GROUP2_TX_HAS_SLOT |
        IWX_GROUP2_TX_HAS_SLOT_GENERATION |
        IWX_GROUP2_TX_HAS_FRAME_CONTROL |
        IWX_GROUP2_TX_HAS_SEQUENCE_CONTROL;
    if (slot->origin_association != 0)
        event->flags |= IWX_GROUP2_TX_HAS_ORIGIN_ASSOCIATION;
}

static inline void iwx_group2_tx_slot_clear(struct IwxGroup2TxSlot *slot)
{
    if (slot != NULL)
        __builtin_memset(slot, 0, sizeof(*slot));
}

static inline void iwx_group2_tx_event_clear_identity(
    struct IwxGroup2TxEvent *event)
{
    if (event == NULL)
        return;
    event->cookie = 0;
    event->slot_generation = 0;
    event->attempt_id = 0;
    event->source = IWX_GROUP2_TX_SOURCE_UNKNOWN;
    event->origin_generation = 0;
    event->origin_association = 0;
    event->context_generation = 0;
    event->output_epoch = 0;
    event->tid = 0;
    event->flags &= ~(IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
        IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION |
        IWX_GROUP2_TX_HAS_ORIGIN_ASSOCIATION |
        IWX_GROUP2_TX_HAS_CONTEXT_GENERATION |
        IWX_GROUP2_TX_HAS_OUTPUT_EPOCH | IWX_GROUP2_TX_HAS_SLOT_GENERATION);
}

static inline int iwx_group2_tx_slot_prepare(
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxTag *tag,
    uint32_t context_generation, uint32_t output_epoch,
    uint32_t queue_id, uint32_t index, uint32_t ring_count,
    uint32_t frame_control, uint32_t sequence_control, uint32_t tid,
    struct IwxGroup2TxSlot *slot)
{
    if (slot == NULL)
        return 0;
    iwx_group2_tx_slot_clear(slot);
    if (!iwx_group2_tx_tag_valid(tag) || ring_count == 0 ||
        ring_count > 256 || index >= ring_count)
        return 0;
    uint64_t generation = 0;
    if (!iwx_group2_tx_trace_next_slot_generation(trace, &generation))
        return 0;
    const uint32_t identityEpoch =
        iwx_group2_tx_trace_identity_epoch(trace);
    if (identityEpoch == UINT32_MAX)
        return 0;
    slot->cookie = tag->cookie;
    slot->slot_generation = generation;
    slot->attempt_id = tag->attempt_id;
    slot->source = tag->source;
    slot->origin_generation = tag->origin_generation;
    slot->origin_association = tag->origin_association;
    slot->context_generation = context_generation;
    slot->output_epoch = output_epoch;
    slot->queue_id = queue_id;
    slot->index = index;
    slot->ring_count = ring_count;
    slot->frame_control = frame_control;
    slot->sequence_control = sequence_control;
    slot->tid = tid;
    slot->identity_epoch = identityEpoch;
    slot->valid = 1;
    return 1;
}

static inline int iwx_group2_tx_trace_prepare_slot(
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxTag *tag,
    uint32_t context_generation, uint32_t output_epoch,
    uint32_t queue_id, uint32_t index, uint32_t ring_count,
    uint32_t frame_control, uint32_t sequence_control, uint32_t tid,
    struct IwxGroup2TxSlot *slot_out)
{
    if (slot_out != NULL)
        __builtin_memset(slot_out, 0, sizeof(*slot_out));
    if (trace == NULL || !iwx_group2_tx_tag_valid(tag) ||
        ring_count == 0 || ring_count > 256 || index >= ring_count)
        return 0;
    if (!iwx_group2_tx_trace_try_lock(trace)) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    const uint32_t identityEpoch =
        iwx_group2_tx_trace_identity_epoch(trace);
    if (identityEpoch == UINT32_MAX) {
        iwx_group2_tx_trace_unlock(trace);
        return 0;
    }
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        const struct IwxGroup2TxSlot *candidate = &trace->slots[i];
        if (candidate->valid && candidate->queue_id == queue_id &&
            candidate->index == index) {
            iwx_group2_tx_trace_note_lost(trace);
            iwx_group2_tx_trace_bump_revision_locked(trace);
            iwx_group2_tx_trace_unlock(trace);
            return 0;
        }
    }
    struct IwxGroup2TxSlot *free_slot = NULL;
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        if (!trace->slots[i].valid) {
            free_slot = &trace->slots[i];
            break;
        }
    }
    if (free_slot == NULL || trace->slot_generation_saturated ||
        trace->next_slot_generation == UINT64_MAX) {
        trace->slot_generation_saturated =
            trace->next_slot_generation == UINT64_MAX;
        iwx_group2_tx_trace_note_lost(trace);
        iwx_group2_tx_trace_bump_revision_locked(trace);
        iwx_group2_tx_trace_unlock(trace);
        return 0;
    }
    struct IwxGroup2TxSlot slot = {};
    slot.cookie = tag->cookie;
    slot.slot_generation = ++trace->next_slot_generation;
    slot.attempt_id = tag->attempt_id;
    slot.source = tag->source;
    slot.origin_generation = tag->origin_generation;
    slot.origin_association = tag->origin_association;
    slot.context_generation = context_generation;
    slot.output_epoch = output_epoch;
    slot.queue_id = queue_id;
    slot.index = index;
    slot.ring_count = ring_count;
    slot.frame_control = frame_control;
    slot.sequence_control = sequence_control;
    slot.tid = tid;
    slot.identity_epoch = identityEpoch;
    slot.valid = 1;
    *free_slot = slot;
    if (slot_out != NULL)
        *slot_out = slot;
    iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
    return 1;
}

/*
 * checkedIndex is an exclusive reclaim boundary. Only slots in the saved
 * bounded interval [oldTail, checkedIndex) are eligible for a host mapping.
 */
static inline uint32_t iwx_group2_tx_match_completion(
    const struct IwxGroup2TxSlot *slots, uint32_t ring_count,
    uint32_t old_tail, uint32_t old_queued, uint32_t checked_index,
    uint32_t queue_id, uint32_t context_generation, uint32_t output_epoch,
    uint32_t frame_control, uint32_t sequence_control,
    uint32_t reset_ambiguous, uint32_t identity_epoch,
    struct IwxGroup2TxSlot *matched_out)
{
    if (matched_out != NULL)
        __builtin_memset(matched_out, 0, sizeof(*matched_out));
    if (reset_ambiguous)
        return IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS;
    if (identity_epoch == UINT32_MAX)
        return IWX_GROUP2_TX_MATCH_UNKNOWN;
    if (slots == NULL || ring_count == 0 || ring_count > 256 ||
        old_tail >= ring_count || checked_index >= ring_count ||
        old_queued > ring_count)
        return IWX_GROUP2_TX_MATCH_BAD_RANGE;
    const uint32_t distance = (checked_index + ring_count - old_tail) % ring_count;
    if (distance == 0 || distance > old_queued)
        return IWX_GROUP2_TX_MATCH_BAD_RANGE;
    uint32_t candidates = 0;
    uint32_t generation_mismatch = 0;
    uint32_t stale_candidate = 0;
    struct IwxGroup2TxSlot candidate = {};
    for (uint32_t offset = 0; offset < distance; ++offset) {
        const uint32_t index = (old_tail + offset) % ring_count;
        const struct IwxGroup2TxSlot *slot = &slots[index];
        if (!slot->valid || slot->cookie == 0 || slot->queue_id != queue_id ||
            slot->index != index || slot->ring_count != ring_count)
            continue;
        if (slot->identity_epoch != identity_epoch) {
            stale_candidate = 1;
            continue;
        }
        if (slot->frame_control != frame_control ||
            slot->sequence_control != sequence_control)
            continue;
        if (slot->context_generation != context_generation ||
            slot->output_epoch != output_epoch) {
            generation_mismatch = 1;
            continue;
        }
        ++candidates;
        candidate = *slot;
    }
    if (stale_candidate)
        return IWX_GROUP2_TX_MATCH_UNKNOWN;
    if (candidates == 1) {
        if (matched_out != NULL)
            *matched_out = candidate;
        return IWX_GROUP2_TX_MATCH_UNIQUE;
    }
    if (candidates > 1)
        return IWX_GROUP2_TX_MATCH_MULTIPLE;
    if (generation_mismatch)
        return IWX_GROUP2_TX_MATCH_GENERATION_MISMATCH;
    return IWX_GROUP2_TX_MATCH_NONE;
}

static inline int iwx_group2_tx_interval_has_sidecar_sparse(
    const struct IwxGroup2TxSlot *slots, uint32_t slot_capacity,
    uint32_t ring_count, uint32_t old_tail, uint32_t old_queued,
    uint32_t checked_index, uint32_t queue_id)
{
    if (slots == NULL || slot_capacity == 0 || slot_capacity > 256 ||
        ring_count == 0 || ring_count > 256 || old_tail >= ring_count ||
        checked_index >= ring_count || old_queued > ring_count)
        return 0;
    const uint32_t distance =
        (checked_index + ring_count - old_tail) % ring_count;
    if (distance == 0 || distance > old_queued)
        return 0;
    for (uint32_t i = 0; i < slot_capacity; ++i) {
        const struct IwxGroup2TxSlot *slot = &slots[i];
        if (!slot->valid || slot->queue_id != queue_id ||
            slot->ring_count != ring_count || slot->index >= ring_count)
            continue;
        const uint32_t offset =
            (slot->index + ring_count - old_tail) % ring_count;
        if (offset < distance)
            return 1;
    }
    return 0;
}

static inline uint32_t iwx_group2_tx_match_completion_sparse(
    const struct IwxGroup2TxSlot *slots, uint32_t slot_capacity,
    uint32_t ring_count, uint32_t old_tail, uint32_t old_queued,
    uint32_t checked_index, uint32_t queue_id,
    uint32_t context_generation, uint32_t output_epoch,
    uint32_t frame_control, uint32_t sequence_control,
    uint32_t reset_ambiguous, uint32_t identity_epoch,
    struct IwxGroup2TxSlot *matched_out)
{
    if (matched_out != NULL)
        __builtin_memset(matched_out, 0, sizeof(*matched_out));
    if (reset_ambiguous)
        return IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS;
    if (identity_epoch == UINT32_MAX)
        return IWX_GROUP2_TX_MATCH_UNKNOWN;
    if (slots == NULL || slot_capacity == 0 || slot_capacity > 256 ||
        ring_count == 0 || ring_count > 256 || old_tail >= ring_count ||
        checked_index >= ring_count || old_queued > ring_count)
        return IWX_GROUP2_TX_MATCH_BAD_RANGE;
    const uint32_t distance =
        (checked_index + ring_count - old_tail) % ring_count;
    if (distance == 0 || distance > old_queued)
        return IWX_GROUP2_TX_MATCH_BAD_RANGE;
    uint32_t candidates = 0;
    uint32_t generation_mismatch = 0;
    uint32_t stale_candidate = 0;
    struct IwxGroup2TxSlot candidate = {};
    for (uint32_t i = 0; i < slot_capacity; ++i) {
        const struct IwxGroup2TxSlot *slot = &slots[i];
        if (!slot->valid || slot->cookie == 0 || slot->queue_id != queue_id ||
            slot->ring_count != ring_count || slot->index >= ring_count)
            continue;
        const uint32_t offset =
            (slot->index + ring_count - old_tail) % ring_count;
        if (offset >= distance)
            continue;
        if (slot->identity_epoch != identity_epoch) {
            stale_candidate = 1;
            continue;
        }
        if (slot->frame_control != frame_control ||
            slot->sequence_control != sequence_control)
            continue;
        if (slot->context_generation != context_generation ||
            slot->output_epoch != output_epoch) {
            generation_mismatch = 1;
            continue;
        }
        ++candidates;
        candidate = *slot;
    }
    if (stale_candidate)
        return IWX_GROUP2_TX_MATCH_UNKNOWN;
    if (candidates == 1) {
        if (matched_out != NULL)
            *matched_out = candidate;
        return IWX_GROUP2_TX_MATCH_UNIQUE;
    }
    if (candidates > 1)
        return IWX_GROUP2_TX_MATCH_MULTIPLE;
    if (generation_mismatch)
        return IWX_GROUP2_TX_MATCH_GENERATION_MISMATCH;
    return IWX_GROUP2_TX_MATCH_NONE;
}

static inline uint32_t iwx_group2_tx_trace_match_completion(
    struct IwxGroup2TxTrace *trace, uint64_t monotonic_us,
    uint32_t old_tail, uint32_t old_queued, uint32_t checked_index,
    uint32_t queue_id, uint32_t ring_count, uint32_t context_generation,
    uint32_t output_epoch, uint32_t frame_control,
    uint32_t sequence_control, uint32_t reset_ambiguous,
    int32_t firmware_status,
    struct IwxGroup2TxSlot *matched_out)
{
    if (matched_out != NULL)
        __builtin_memset(matched_out, 0, sizeof(*matched_out));
    if (trace == NULL || !iwx_group2_tx_trace_try_lock(trace)) {
        if (trace != NULL)
            iwx_group2_tx_trace_note_lost(trace);
        return IWX_GROUP2_TX_MATCH_UNKNOWN;
    }
    struct IwxGroup2TxSlot matched = {};
    uint32_t result = IWX_GROUP2_TX_MATCH_UNKNOWN;
    const uint32_t identityEpoch =
        iwx_group2_tx_trace_identity_epoch(trace);
    const int hasRelevantSidecar = iwx_group2_tx_interval_has_sidecar_sparse(
        trace->slots, IWX_GROUP2_TX_SLOT_CAPACITY, ring_count, old_tail,
        old_queued, checked_index, queue_id);
    if (!hasRelevantSidecar) {
        iwx_group2_tx_trace_unlock(trace);
        return reset_ambiguous ? IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS :
            IWX_GROUP2_TX_MATCH_NONE;
    }
    if (identityEpoch != UINT32_MAX)
        result = iwx_group2_tx_match_completion_sparse(
            trace->slots, IWX_GROUP2_TX_SLOT_CAPACITY, ring_count, old_tail,
            old_queued, checked_index, queue_id, context_generation,
            output_epoch, frame_control, sequence_control, reset_ambiguous,
            identityEpoch, &matched);
    struct IwxGroup2TxEvent event = {};
    event.monotonic_us = monotonic_us;
    event.stage = result == IWX_GROUP2_TX_MATCH_UNIQUE ?
        IWX_GROUP2_TX_STAGE_TX_RSP_MATCH :
        IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN;
    event.status = (uint16_t)result;
    event.queue_id = queue_id;
    event.index = checked_index;
    event.ring_count = ring_count;
    event.frame_control = frame_control;
    event.sequence_control = sequence_control;
    event.flags = IWX_GROUP2_TX_HAS_QUEUE |
        IWX_GROUP2_TX_HAS_COMPLETION_BOUNDARY |
        IWX_GROUP2_TX_HAS_FRAME_CONTROL | IWX_GROUP2_TX_HAS_SEQUENCE_CONTROL |
        IWX_GROUP2_TX_HAS_MATCH_RESULT;
    if (firmware_status >= 0 && firmware_status <= UINT16_MAX) {
        event.result = firmware_status;
        event.flags |= IWX_GROUP2_TX_HAS_FIRMWARE_STATUS;
    }
    if (reset_ambiguous || result == IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS)
        event.flags |= IWX_GROUP2_TX_RESET_AMBIGUOUS;
    if (result == IWX_GROUP2_TX_MATCH_UNIQUE) {
        event.cookie = matched.cookie;
        event.slot_generation = matched.slot_generation;
        event.attempt_id = matched.attempt_id;
        event.source = matched.source;
        event.origin_generation = matched.origin_generation;
        event.origin_association = matched.origin_association;
        event.context_generation = matched.context_generation;
        event.output_epoch = matched.output_epoch;
        event.tid = matched.tid;
        event.flags |= IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
            IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION |
            IWX_GROUP2_TX_HAS_CONTEXT_GENERATION |
            IWX_GROUP2_TX_HAS_OUTPUT_EPOCH |
            IWX_GROUP2_TX_HAS_SLOT_GENERATION;
        if (matched.origin_association != 0)
            event.flags |= IWX_GROUP2_TX_HAS_ORIGIN_ASSOCIATION;
    }
    const int appended = iwx_group2_tx_trace_append_locked(trace, &event);
    if (!appended ||
        iwx_group2_tx_trace_identity_epoch(trace) != identityEpoch) {
        result = IWX_GROUP2_TX_MATCH_UNKNOWN;
        __builtin_memset(&matched, 0, sizeof(matched));
        if (appended) {
            event.stage = IWX_GROUP2_TX_STAGE_TX_RSP_UNKNOWN;
            event.status = IWX_GROUP2_TX_MATCH_UNKNOWN;
            iwx_group2_tx_event_clear_identity(&event);
            iwx_group2_tx_trace_rewrite_last_locked(trace, &event);
        }
    }
    if (result == IWX_GROUP2_TX_MATCH_UNIQUE && matched_out != NULL)
        *matched_out = matched;
    iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
    return result;
}

static inline int iwx_group2_tx_trace_retire_slot(
    struct IwxGroup2TxTrace *trace, const struct IwxGroup2TxSlot *slot,
    uint64_t monotonic_us)
{
    if (trace == NULL || slot == NULL || !slot->valid)
        return 0;
    if (!iwx_group2_tx_trace_try_lock(trace)) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    int retired = 0;
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        struct IwxGroup2TxSlot *candidate = &trace->slots[i];
        if (!candidate->valid || candidate->queue_id != slot->queue_id ||
            candidate->index != slot->index ||
            candidate->slot_generation != slot->slot_generation ||
            candidate->cookie != slot->cookie)
            continue;
        struct IwxGroup2TxEvent event = {};
        event.monotonic_us = monotonic_us;
        event.cookie = candidate->cookie;
        event.slot_generation = candidate->slot_generation;
        event.attempt_id = candidate->attempt_id;
        event.source = candidate->source;
        event.origin_generation = candidate->origin_generation;
        event.origin_association = candidate->origin_association;
        event.context_generation = candidate->context_generation;
        event.output_epoch = candidate->output_epoch;
        event.queue_id = candidate->queue_id;
        event.index = candidate->index;
        event.ring_count = candidate->ring_count;
        event.frame_control = candidate->frame_control;
        event.sequence_control = candidate->sequence_control;
        event.tid = candidate->tid;
        event.flags = IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
            IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION |
            IWX_GROUP2_TX_HAS_CONTEXT_GENERATION |
            IWX_GROUP2_TX_HAS_OUTPUT_EPOCH | IWX_GROUP2_TX_HAS_QUEUE |
            IWX_GROUP2_TX_HAS_SLOT | IWX_GROUP2_TX_HAS_SLOT_GENERATION |
            IWX_GROUP2_TX_HAS_FRAME_CONTROL |
            IWX_GROUP2_TX_HAS_SEQUENCE_CONTROL;
        event.stage = IWX_GROUP2_TX_STAGE_SLOT_RETIRED;
        iwx_group2_tx_trace_append_locked(trace, &event);
        iwx_group2_tx_slot_clear(candidate);
        retired = 1;
        break;
    }
    if (retired)
        iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
    return retired;
}

static inline int iwx_group2_tx_trace_has_live_slot_for_queue(
    struct IwxGroup2TxTrace *trace, uint32_t queue_id)
{
    if (trace == NULL)
        return 0;
    if (!iwx_group2_tx_trace_try_lock(trace)) {
        iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    int found = 0;
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        if (trace->slots[i].valid &&
            trace->slots[i].queue_id == queue_id) {
            found = 1;
            break;
        }
    }
    iwx_group2_tx_trace_unlock(trace);
    return found;
}

static inline uint32_t iwx_group2_tx_trace_retire_interval(
    struct IwxGroup2TxTrace *trace, uint64_t monotonic_us,
    uint32_t old_tail, uint32_t old_queued, uint32_t checked_index,
    uint32_t queue_id, uint32_t ring_count, uint16_t retirement_stage,
    uint32_t completion_status, uint64_t matched_slot_generation)
{
    if (trace == NULL || !iwx_group2_tx_trace_try_lock(trace)) {
        if (trace != NULL)
            iwx_group2_tx_trace_note_lost(trace);
        return 0;
    }
    if (ring_count == 0 || ring_count > 256 || old_tail >= ring_count ||
        checked_index >= ring_count || old_queued > ring_count) {
        iwx_group2_tx_trace_note_lost(trace);
        iwx_group2_tx_trace_unlock(trace);
        return 0;
    }
    const uint32_t distance =
        (checked_index + ring_count - old_tail) % ring_count;
    if (distance == 0 || distance > old_queued) {
        iwx_group2_tx_trace_note_lost(trace);
        iwx_group2_tx_trace_unlock(trace);
        return 0;
    }
    uint32_t retired = 0;
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        struct IwxGroup2TxSlot *slot = &trace->slots[i];
        if (!slot->valid || slot->queue_id != queue_id ||
            slot->ring_count != ring_count || slot->index >= ring_count)
            continue;
        const uint32_t offset = (slot->index + ring_count - old_tail) % ring_count;
        if (offset >= distance)
            continue;
        const uint32_t eventIdentityEpoch =
            iwx_group2_tx_trace_identity_epoch(trace);
        const int identityKnown = eventIdentityEpoch != UINT32_MAX &&
            slot->identity_epoch == eventIdentityEpoch;
        struct IwxGroup2TxEvent event = {};
        if (identityKnown)
            iwx_group2_tx_event_from_slot(&event, slot, monotonic_us,
                retirement_stage);
        else {
            event.monotonic_us = monotonic_us;
            event.stage = retirement_stage;
            event.queue_id = slot->queue_id;
            event.index = slot->index;
            event.ring_count = slot->ring_count;
            event.flags = IWX_GROUP2_TX_HAS_QUEUE | IWX_GROUP2_TX_HAS_SLOT;
        }
        const uint32_t retirementStatus =
            retirement_stage == IWX_GROUP2_TX_STAGE_FLUSH_RECLAIM_UNKNOWN ?
                IWX_GROUP2_TX_MATCH_UNKNOWN :
                (!identityKnown ? IWX_GROUP2_TX_MATCH_UNKNOWN :
                    (slot->slot_generation == matched_slot_generation &&
                     matched_slot_generation != 0 ?
                        IWX_GROUP2_TX_MATCH_UNIQUE : completion_status));
        event.status = (uint16_t)retirementStatus;
        event.flags |= IWX_GROUP2_TX_HAS_MATCH_RESULT;
        const int appended = iwx_group2_tx_trace_append_locked(trace, &event);
        if (appended && iwx_group2_tx_trace_identity_epoch(trace) !=
                eventIdentityEpoch) {
            event.status = IWX_GROUP2_TX_MATCH_UNKNOWN;
            iwx_group2_tx_event_clear_identity(&event);
            iwx_group2_tx_trace_rewrite_last_locked(trace, &event);
        }
        iwx_group2_tx_slot_clear(slot);
        ++retired;
    }
    if (retired != 0)
        iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
    return retired;
}

static inline uint32_t iwx_group2_tx_trace_retire_reclaimed_interval(
    struct IwxGroup2TxTrace *trace, uint64_t monotonic_us,
    uint32_t old_tail, uint32_t old_queued, uint32_t checked_index,
    uint32_t queue_id, uint32_t ring_count, uint32_t completion_status,
    uint64_t matched_slot_generation)
{
    return iwx_group2_tx_trace_retire_interval(trace, monotonic_us,
        old_tail, old_queued, checked_index, queue_id, ring_count,
        IWX_GROUP2_TX_STAGE_SLOT_RETIRED, completion_status,
        matched_slot_generation);
}

static inline uint32_t iwx_group2_tx_trace_retire_flushed_interval(
    struct IwxGroup2TxTrace *trace, uint64_t monotonic_us,
    uint32_t old_tail, uint32_t old_queued, uint32_t checked_index,
    uint32_t queue_id, uint32_t ring_count)
{
    return iwx_group2_tx_trace_retire_interval(trace, monotonic_us,
        old_tail, old_queued, checked_index, queue_id, ring_count,
        IWX_GROUP2_TX_STAGE_FLUSH_RECLAIM_UNKNOWN,
        IWX_GROUP2_TX_MATCH_UNKNOWN, 0);
}

static inline void iwx_group2_tx_trace_invalidate_slots(
    struct IwxGroup2TxTrace *trace, uint64_t monotonic_us,
    uint32_t new_generation)
{
    if (trace == NULL || !iwx_group2_tx_trace_try_lock(trace)) {
        if (trace != NULL)
            iwx_group2_tx_trace_note_lost(trace);
        return;
    }
    for (uint32_t i = 0; i < IWX_GROUP2_TX_SLOT_CAPACITY; ++i) {
        struct IwxGroup2TxSlot *slot = &trace->slots[i];
        if (!slot->valid)
            continue;
        struct IwxGroup2TxEvent event = {};
        event.monotonic_us = monotonic_us;
        event.cookie = slot->cookie;
        event.slot_generation = slot->slot_generation;
        event.attempt_id = slot->attempt_id;
        event.source = slot->source;
        event.origin_generation = slot->origin_generation;
        event.origin_association = slot->origin_association;
        event.context_generation = slot->context_generation;
        event.output_epoch = slot->output_epoch;
        event.queue_id = slot->queue_id;
        event.index = slot->index;
        event.ring_count = slot->ring_count;
        event.frame_control = slot->frame_control;
        event.sequence_control = slot->sequence_control;
        event.tid = slot->tid;
        event.result = (int32_t)new_generation;
        event.flags = IWX_GROUP2_TX_HAS_COOKIE | IWX_GROUP2_TX_HAS_ATTEMPT |
            IWX_GROUP2_TX_HAS_SOURCE | IWX_GROUP2_TX_HAS_ORIGIN_GENERATION |
            IWX_GROUP2_TX_HAS_CONTEXT_GENERATION |
            IWX_GROUP2_TX_HAS_OUTPUT_EPOCH | IWX_GROUP2_TX_HAS_QUEUE |
            IWX_GROUP2_TX_HAS_SLOT | IWX_GROUP2_TX_HAS_SLOT_GENERATION |
            IWX_GROUP2_TX_HAS_FRAME_CONTROL |
            IWX_GROUP2_TX_HAS_SEQUENCE_CONTROL |
            IWX_GROUP2_TX_RESET_AMBIGUOUS |
            IWX_GROUP2_TX_HAS_MATCH_RESULT;
        event.stage = IWX_GROUP2_TX_STAGE_RESET_INVALIDATED;
        event.status = IWX_GROUP2_TX_MATCH_RESET_AMBIGUOUS;
        iwx_group2_tx_trace_append_locked(trace, &event);
        iwx_group2_tx_slot_clear(slot);
    }
    iwx_group2_tx_trace_bump_revision_locked(trace);
    iwx_group2_tx_trace_unlock(trace);
}

static inline int iwx_group2_tx_trace_snapshot(
    struct IwxGroup2TxTrace *trace,
    struct IwxGroup2TxTraceSnapshot *snapshot)
{
    if (trace == NULL || snapshot == NULL ||
        !iwx_group2_tx_trace_try_lock(trace))
        return 0;
    __builtin_memset(snapshot, 0, sizeof(*snapshot));
    snapshot->magic = IWX_GROUP2_TX_TRACE_MAGIC;
    snapshot->schema = IWX_GROUP2_TX_TRACE_SCHEMA;
    snapshot->header_bytes = (uint16_t)offsetof(
        struct IwxGroup2TxTraceSnapshot, events);
    snapshot->event_bytes = (uint16_t)sizeof(struct IwxGroup2TxEvent);
    snapshot->capacity = IWX_GROUP2_TX_TRACE_CAPACITY;
    snapshot->revision_begin = trace->revision;
    snapshot->revision_end = trace->revision;
    snapshot->dropped_count =
        __atomic_load_n(&trace->dropped_count, __ATOMIC_ACQUIRE);
    snapshot->event_count = trace->event_count;
    snapshot->next_cookie = trace->next_cookie;
    snapshot->next_event_sequence = trace->next_event_sequence;
    snapshot->next_slot_generation = trace->next_slot_generation;
    if (trace->cookie_saturated)
        snapshot->flags |= 1u;
    if (trace->slot_generation_saturated)
        snapshot->flags |= 2u;
    const uint32_t count = trace->event_count;
    const uint32_t start = (trace->event_cursor +
        IWX_GROUP2_TX_TRACE_CAPACITY - count) % IWX_GROUP2_TX_TRACE_CAPACITY;
    for (uint32_t i = 0; i < count; ++i)
        snapshot->events[i] = trace->events[
            (start + i) % IWX_GROUP2_TX_TRACE_CAPACITY];
    iwx_group2_tx_trace_unlock(trace);
    return 1;
}

static inline uint16_t iwx_group2_tx_le16(uint16_t value)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value;
#endif
}

static inline uint32_t iwx_group2_tx_le32(uint32_t value)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

static inline uint64_t iwx_group2_tx_le64(uint64_t value)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

static inline void iwx_group2_tx_event_to_le(
    struct IwxGroup2TxEvent *dst, const struct IwxGroup2TxEvent *src)
{
    dst->sequence = iwx_group2_tx_le64(src->sequence);
    dst->monotonic_us = iwx_group2_tx_le64(src->monotonic_us);
    dst->cookie = iwx_group2_tx_le64(src->cookie);
    dst->slot_generation = iwx_group2_tx_le64(src->slot_generation);
    dst->attempt_id = iwx_group2_tx_le32(src->attempt_id);
    dst->source = iwx_group2_tx_le32(src->source);
    dst->origin_generation = iwx_group2_tx_le32(src->origin_generation);
    dst->origin_association = iwx_group2_tx_le32(src->origin_association);
    dst->context_generation = iwx_group2_tx_le32(src->context_generation);
    dst->output_epoch = iwx_group2_tx_le32(src->output_epoch);
    dst->queue_id = iwx_group2_tx_le32(src->queue_id);
    dst->index = iwx_group2_tx_le32(src->index);
    dst->ring_count = iwx_group2_tx_le32(src->ring_count);
    dst->frame_control = iwx_group2_tx_le32(src->frame_control);
    dst->sequence_control = iwx_group2_tx_le32(src->sequence_control);
    dst->tid = iwx_group2_tx_le32(src->tid);
    dst->result = (int32_t)iwx_group2_tx_le32((uint32_t)src->result);
    dst->flags = iwx_group2_tx_le32(src->flags);
    dst->stage = iwx_group2_tx_le16(src->stage);
    dst->status = iwx_group2_tx_le16(src->status);
}

static inline void iwx_group2_tx_snapshot_to_le(
    struct IwxGroup2TxTraceSnapshot *dst,
    const struct IwxGroup2TxTraceSnapshot *src)
{
    if (dst == NULL || src == NULL)
        return;
    __builtin_memset(dst, 0, sizeof(*dst));
    dst->magic = iwx_group2_tx_le32(src->magic);
    dst->schema = iwx_group2_tx_le16(src->schema);
    dst->header_bytes = iwx_group2_tx_le16(src->header_bytes);
    dst->event_bytes = iwx_group2_tx_le16(src->event_bytes);
    dst->capacity = iwx_group2_tx_le16(src->capacity);
    dst->revision_begin = iwx_group2_tx_le64(src->revision_begin);
    dst->revision_end = iwx_group2_tx_le64(src->revision_end);
    dst->dropped_count = iwx_group2_tx_le32(src->dropped_count);
    dst->event_count = iwx_group2_tx_le32(src->event_count);
    dst->next_cookie = iwx_group2_tx_le64(src->next_cookie);
    dst->next_event_sequence = iwx_group2_tx_le64(src->next_event_sequence);
    dst->next_slot_generation = iwx_group2_tx_le64(src->next_slot_generation);
    dst->flags = iwx_group2_tx_le32(src->flags);
    for (uint32_t i = 0; i < IWX_GROUP2_TX_TRACE_CAPACITY; ++i)
        iwx_group2_tx_event_to_le(&dst->events[i], &src->events[i]);
}

static inline void iwx_group2_tx_snapshot_to_le_in_place(
    struct IwxGroup2TxTraceSnapshot *snapshot)
{
    if (snapshot == NULL)
        return;
    snapshot->magic = iwx_group2_tx_le32(snapshot->magic);
    snapshot->schema = iwx_group2_tx_le16(snapshot->schema);
    snapshot->header_bytes = iwx_group2_tx_le16(snapshot->header_bytes);
    snapshot->event_bytes = iwx_group2_tx_le16(snapshot->event_bytes);
    snapshot->capacity = iwx_group2_tx_le16(snapshot->capacity);
    snapshot->revision_begin = iwx_group2_tx_le64(snapshot->revision_begin);
    snapshot->revision_end = iwx_group2_tx_le64(snapshot->revision_end);
    snapshot->dropped_count = iwx_group2_tx_le32(snapshot->dropped_count);
    snapshot->event_count = iwx_group2_tx_le32(snapshot->event_count);
    snapshot->next_cookie = iwx_group2_tx_le64(snapshot->next_cookie);
    snapshot->next_event_sequence =
        iwx_group2_tx_le64(snapshot->next_event_sequence);
    snapshot->next_slot_generation =
        iwx_group2_tx_le64(snapshot->next_slot_generation);
    snapshot->flags = iwx_group2_tx_le32(snapshot->flags);
    for (uint32_t i = 0; i < IWX_GROUP2_TX_TRACE_CAPACITY; ++i)
        iwx_group2_tx_event_to_le(&snapshot->events[i], &snapshot->events[i]);
}

#endif /* IWX_GROUP2_TX_TRACE_HELPERS_H */
