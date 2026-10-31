// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_COMPLETION_OBSERVATION_HPP
#define GEEK_IWX_TX_COMPLETION_OBSERVATION_HPP

#include <stdint.h>

/*
 * Fixed-size numeric observations for RX dispatch and TX-completion handler
 * exits. These are latest-by-kind records plus terminal-reason counters, not
 * an ordered packet ledger. They contain no packet bytes, addresses, nodes,
 * or pointers. Schema 2 may additionally record a bounded read-only scan of
 * live host TX_CMD headers in the response's reclaim interval; it does not
 * change ring ownership or claim firmware acceptance or peer receipt.
 *
 * Producers make one CAS attempt only. Invalid input, a saturated counter,
 * or contention increments dropped_count where possible; any such loss makes
 * snapshots incomplete. A snapshot's complete bit describes the observer up
 * to its final dropped_count load, not events racing after that cut.
 */
enum {
    IWX_TX_COMPLETION_KIND_COUNT = 3,
    IWX_TX_COMPLETION_MAX_REASON_COUNT = 10,
    IWX_TX_COMPLETION_STATE_MAX_BYTES = 1024,
    IWX_TX_COMPLETION_SNAPSHOT_MAX_BYTES = 1024
};

enum iwx_tx_completion_kind {
    IWX_TX_COMPLETION_TX_RSP = 0,
    IWX_TX_COMPLETION_BA = 1,
    IWX_TX_COMPLETION_RX_PARSE_STOP = 2
};

/* Terminal branch at which the observation is emitted. */
enum iwx_tx_completion_stage {
    IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL = 1,
    IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL = 2,
    IWX_TX_COMPLETION_STAGE_BA_TFD_TERMINAL = 3,
    IWX_TX_COMPLETION_STAGE_RX_PARSE_STOP = 4
};

/*
 * TX_RSP reasons correspond to dispatch/iwx_rx_tx_cmd() branches. The queue
 * and ring checks share the current production helper's rejection branch;
 * instrumentation may refine the reason only if it can identify the actual
 * failing predicate without changing the established path.
 */
enum iwx_tx_completion_tx_rsp_reason {
    IWX_TX_COMPLETION_TX_RSP_P2P_OWNER_CONSUMED = 0,
    IWX_TX_COMPLETION_TX_RSP_PAYLOAD_TOO_SHORT = 1,
    IWX_TX_COMPLETION_TX_RSP_FRAME_COUNT_ZERO = 2,
    IWX_TX_COMPLETION_TX_RSP_DECLARED_LENGTH_TRUNCATED = 3,
    IWX_TX_COMPLETION_TX_RSP_QUEUE_OR_RING_UNADDRESSABLE = 4,
    IWX_TX_COMPLETION_TX_RSP_AGGREGATE_WAITING_FOR_BA = 5,
    IWX_TX_COMPLETION_TX_RSP_SINGLE_RING_EMPTY = 6,
    IWX_TX_COMPLETION_TX_RSP_SSN_INDEX_REJECTED = 7,
    IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED = 8,
    IWX_TX_COMPLETION_TX_RSP_UNCLASSIFIED_EXIT = 9
};

/* BA reasons distinguish handler exits from per-TFD loop dispositions. */
enum iwx_tx_completion_ba_reason {
    IWX_TX_COMPLETION_BA_HEADER_TOO_SHORT = 0,
    IWX_TX_COMPLETION_BA_TFD_ARRAY_TRUNCATED = 1,
    IWX_TX_COMPLETION_BA_STA_ID_MISMATCH = 2,
    IWX_TX_COMPLETION_BA_NOT_STA_RUN = 3,
    IWX_TX_COMPLETION_BA_TFD_COUNT_ZERO = 4,
    IWX_TX_COMPLETION_BA_TFD_QID_OUT_OF_RANGE = 5,
    IWX_TX_COMPLETION_BA_TFD_P2P_OWNED = 6,
    IWX_TX_COMPLETION_BA_TFD_RING_CAPACITY_REJECTED = 7,
    IWX_TX_COMPLETION_BA_TFD_RECLAIM_COMPLETED = 8,
    IWX_TX_COMPLETION_BA_UNCLASSIFIED_EXIT = 9
};

enum iwx_tx_completion_rx_parse_stop_reason {
    IWX_TX_COMPLETION_RX_DESCRIPTOR_INVALID = 0,
    IWX_TX_COMPLETION_RX_PACKET_LENGTH_INVALID = 1,
    IWX_TX_COMPLETION_RX_UNCLASSIFIED_STOP = 2
};

/* Only caller-supplied facts use these flags. SERIAL is observer-owned.
 * OUTPUT_EPOCH is the host-side epoch sampled when this row is recorded; it
 * does not prove which firmware submission owned an ACK/notification. */
enum iwx_tx_completion_presence_flag {
    IWX_TX_COMPLETION_HAS_MONOTONIC_NS = 1u << 0,
    IWX_TX_COMPLETION_HAS_RX_GROUP = 1u << 1,
    IWX_TX_COMPLETION_HAS_RX_COMMAND = 1u << 2,
    IWX_TX_COMPLETION_HAS_RX_HEADER_QID = 1u << 3,
    IWX_TX_COMPLETION_HAS_RX_HEADER_INDEX = 1u << 4,
    IWX_TX_COMPLETION_HAS_RX_PACKET_LENGTH = 1u << 5,
    IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH = 1u << 6,
    IWX_TX_COMPLETION_HAS_FIRMWARE_QID = 1u << 7,
    IWX_TX_COMPLETION_HAS_QUEUE_INDEX = 1u << 8,
    IWX_TX_COMPLETION_HAS_RING_COUNT = 1u << 9,
    IWX_TX_COMPLETION_HAS_QUEUED = 1u << 10,
    IWX_TX_COMPLETION_HAS_CUR = 1u << 11,
    IWX_TX_COMPLETION_HAS_TAIL = 1u << 12,
    IWX_TX_COMPLETION_HAS_FRAME_COUNT = 1u << 13,
    IWX_TX_COMPLETION_HAS_SSN = 1u << 14,
    IWX_TX_COMPLETION_HAS_RA_TID = 1u << 15,
    IWX_TX_COMPLETION_HAS_STATUS = 1u << 16,
    IWX_TX_COMPLETION_HAS_BA_STA_ID = 1u << 17,
    IWX_TX_COMPLETION_HAS_BA_FLAGS = 1u << 18,
    IWX_TX_COMPLETION_HAS_BA_TFD_COUNT = 1u << 19,
    IWX_TX_COMPLETION_HAS_BA_TXED = 1u << 20,
    IWX_TX_COMPLETION_HAS_BA_DONE = 1u << 21,
    IWX_TX_COMPLETION_HAS_BA_WIRELESS_TIME = 1u << 22,
    IWX_TX_COMPLETION_HAS_BA_TFD_TID = 1u << 23,
    IWX_TX_COMPLETION_HAS_BA_TFD_INDEX = 1u << 24,
    IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH = 1u << 25,
    IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL = 1u << 26,
    IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL = 1u << 27,
    IWX_TX_COMPLETION_HAS_TXCMD_SCAN = 1u << 28,
    IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE = 1u << 29
};

enum {
    IWX_TX_COMPLETION_CALLER_PRESENCE_MASK = (1u << 30) - 1u,
    IWX_TX_COMPLETION_OBSERVER_HAS_SERIAL = 1u << 31
};

typedef struct iwx_tx_completion_event_record {
    uint64_t event_count;
    uint64_t serial;
    uint64_t monotonic_ns;
    uint32_t output_epoch;
    uint32_t driver_generation;
    uint32_t kind;
    uint32_t stage;
    uint32_t terminal_reason;
    uint32_t presence_flags;
    uint32_t rx_group;
    uint32_t rx_command;
    uint32_t rx_header_qid;
    uint32_t rx_header_index;
    uint32_t rx_packet_length;
    uint32_t payload_length;
    uint32_t firmware_qid;
    uint32_t queue_index;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
    uint32_t frame_count;
    uint32_t ssn;
    uint32_t ra_tid;
    uint32_t status;
    uint32_t ba_sta_id;
    uint32_t ba_flags;
    uint32_t ba_tfd_count;
    uint32_t ba_txed;
    uint32_t ba_done;
    uint32_t ba_wireless_time;
    uint32_t ba_tfd_tid;
    uint32_t ba_tfd_index;
    uint32_t response_frame_control;
    uint32_t response_sequence_control;
    uint32_t txcmd_scan_status;
    uint32_t txcmd_expected_count;
    uint32_t txcmd_scanned_count;
    uint32_t txcmd_candidate_count;
    uint32_t txcmd_candidate_index;
    uint32_t txcmd_api_generation;
    uint32_t txcmd_command_version;
    uint32_t txcmd_flags;
    uint32_t txcmd_offload_assist;
} iwx_tx_completion_event_record;

typedef struct iwx_tx_completion_event_input {
    uint32_t kind;
    uint32_t stage;
    uint32_t terminal_reason;
    uint32_t presence_flags;
    uint64_t monotonic_ns;
    uint32_t output_epoch;
    uint32_t driver_generation;
    uint32_t rx_group;
    uint32_t rx_command;
    uint32_t rx_header_qid;
    uint32_t rx_header_index;
    uint32_t rx_packet_length;
    uint32_t payload_length;
    uint32_t firmware_qid;
    uint32_t queue_index;
    uint32_t ring_count;
    uint32_t queued;
    uint32_t cur;
    uint32_t tail;
    uint32_t frame_count;
    uint32_t ssn;
    uint32_t ra_tid;
    uint32_t status;
    uint32_t ba_sta_id;
    uint32_t ba_flags;
    uint32_t ba_tfd_count;
    uint32_t ba_txed;
    uint32_t ba_done;
    uint32_t ba_wireless_time;
    uint32_t ba_tfd_tid;
    uint32_t ba_tfd_index;
    uint32_t response_frame_control;
    uint32_t response_sequence_control;
    uint32_t txcmd_scan_status;
    uint32_t txcmd_expected_count;
    uint32_t txcmd_scanned_count;
    uint32_t txcmd_candidate_count;
    uint32_t txcmd_candidate_index;
    uint32_t txcmd_api_generation;
    uint32_t txcmd_command_version;
    uint32_t txcmd_flags;
    uint32_t txcmd_offload_assist;
} iwx_tx_completion_event_input;

typedef struct iwx_tx_completion_observation_state {
    uint32_t lock;
    uint32_t reserved;
    uint64_t dropped_count;
    uint64_t related_dropped_count;
    uint64_t next_serial;
    uint64_t publication_serial;
    uint64_t terminal_reason_counts[IWX_TX_COMPLETION_KIND_COUNT]
                                    [IWX_TX_COMPLETION_MAX_REASON_COUNT];
    iwx_tx_completion_event_record last[IWX_TX_COMPLETION_KIND_COUNT];
} iwx_tx_completion_observation_state;

typedef struct iwx_tx_completion_observation_snapshot {
    uint32_t available;
    uint32_t complete;
    uint64_t dropped_count;
    uint64_t related_dropped_count;
    uint64_t next_serial;
    uint64_t publication_serial;
    uint64_t terminal_reason_counts[IWX_TX_COMPLETION_KIND_COUNT]
                                    [IWX_TX_COMPLETION_MAX_REASON_COUNT];
    iwx_tx_completion_event_record last[IWX_TX_COMPLETION_KIND_COUNT];
} iwx_tx_completion_observation_snapshot;

#ifdef __cplusplus

namespace IwxTxCompletionObservation {

static constexpr uint32_t kKindCount = IWX_TX_COMPLETION_KIND_COUNT;
static constexpr uint32_t kMaxReasonCount =
    IWX_TX_COMPLETION_MAX_REASON_COUNT;

static_assert(sizeof(iwx_tx_completion_event_record) <= 192,
              "TX completion record must remain fixed and scalar");
static_assert(sizeof(iwx_tx_completion_observation_state) <=
                  IWX_TX_COMPLETION_STATE_MAX_BYTES,
              "TX completion observer state exceeded its embedded bound");
static_assert(sizeof(iwx_tx_completion_observation_snapshot) <=
                  IWX_TX_COMPLETION_SNAPSHOT_MAX_BYTES,
              "TX completion snapshot exceeded its copy bound");

static inline bool tryLock(iwx_tx_completion_observation_state *state)
{
    if (!state)
        return false;
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&state->lock, &expected, 1U, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void unlock(iwx_tx_completion_observation_state *state)
{
    __atomic_store_n(&state->lock, 0U, __ATOMIC_RELEASE);
}

static inline void noteDrop(iwx_tx_completion_observation_state *state)
{
    if (!state)
        return;
    uint64_t current = __atomic_load_n(&state->dropped_count,
                                       __ATOMIC_RELAXED);
    if (current == UINT64_MAX)
        return; // Already incomplete; keep the loss counter saturated.
    uint64_t expected = current;
    (void)__atomic_compare_exchange_n(&state->dropped_count, &expected,
                                      current + 1U, false,
                                      __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

/* Related Group2 completions also expose losses that happen before a cut can
 * be created. This counter is independent of the observer lock so a busy
 * producer still performs one bounded atomic attempt and never waits. */
static inline void noteRelatedDrop(iwx_tx_completion_observation_state *state)
{
    if (!state)
        return;
    uint64_t current = __atomic_load_n(&state->related_dropped_count,
                                       __ATOMIC_RELAXED);
    for (uint32_t attempt = 0; attempt < 2U && current != UINT64_MAX;
         ++attempt) {
        uint64_t expected = current;
        if (__atomic_compare_exchange_n(&state->related_dropped_count,
                &expected, current + 1U, false, __ATOMIC_RELEASE,
                __ATOMIC_RELAXED))
            return;
        current = expected;
    }
}

/*
 * Mark only a completion known to overlap a live Group2 sidecar interval.
 * This scalar is the cheap main-gate dirty stamp; ordinary TX status traffic
 * does not cause a full IORegistry snapshot. Call after record() so a
 * publisher that observes the new serial can also observe its event/drop.
 */
static inline bool markPublicationRelevant(
    iwx_tx_completion_observation_state *state)
{
    if (!state)
        return false;
    uint64_t current = __atomic_load_n(&state->publication_serial,
                                       __ATOMIC_RELAXED);
    for (uint32_t attempt = 0; attempt < 2U && current != UINT64_MAX;
         ++attempt) {
        uint64_t expected = current;
        if (__atomic_compare_exchange_n(&state->publication_serial, &expected,
                current + 1U, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
            return true;
        current = expected;
    }
    return false;
}

static inline uint32_t reasonLimit(uint32_t kind)
{
    switch (kind) {
    case IWX_TX_COMPLETION_TX_RSP:
        return IWX_TX_COMPLETION_TX_RSP_UNCLASSIFIED_EXIT + 1U;
    case IWX_TX_COMPLETION_BA:
        return IWX_TX_COMPLETION_BA_UNCLASSIFIED_EXIT + 1U;
    case IWX_TX_COMPLETION_RX_PARSE_STOP:
        return IWX_TX_COMPLETION_RX_UNCLASSIFIED_STOP + 1U;
    default:
        return 0;
    }
}

static inline bool validStageReason(const iwx_tx_completion_event_input *in)
{
    if (!in)
        return false;
    switch (in->kind) {
    case IWX_TX_COMPLETION_TX_RSP:
        return in->stage == IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL &&
               in->terminal_reason < reasonLimit(in->kind);
    case IWX_TX_COMPLETION_BA:
        if (in->terminal_reason == IWX_TX_COMPLETION_BA_UNCLASSIFIED_EXIT)
            return in->stage == IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL ||
                   in->stage == IWX_TX_COMPLETION_STAGE_BA_TFD_TERMINAL;
        if (in->terminal_reason <= IWX_TX_COMPLETION_BA_TFD_COUNT_ZERO)
            return in->stage == IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL;
        return in->stage == IWX_TX_COMPLETION_STAGE_BA_TFD_TERMINAL &&
               in->terminal_reason < reasonLimit(in->kind);
    case IWX_TX_COMPLETION_RX_PARSE_STOP:
        return in->stage == IWX_TX_COMPLETION_STAGE_RX_PARSE_STOP &&
               in->terminal_reason < reasonLimit(in->kind);
    default:
        return false;
    }
}

static inline uint32_t allowedPresence(uint32_t kind)
{
    const uint32_t rxBase = IWX_TX_COMPLETION_HAS_MONOTONIC_NS |
        IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
        IWX_TX_COMPLETION_HAS_RX_GROUP |
        IWX_TX_COMPLETION_HAS_RX_COMMAND |
        IWX_TX_COMPLETION_HAS_RX_HEADER_QID |
        IWX_TX_COMPLETION_HAS_RX_HEADER_INDEX |
        IWX_TX_COMPLETION_HAS_RX_PACKET_LENGTH |
        IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH;
    const uint32_t ring = IWX_TX_COMPLETION_HAS_FIRMWARE_QID |
        IWX_TX_COMPLETION_HAS_QUEUE_INDEX |
        IWX_TX_COMPLETION_HAS_RING_COUNT | IWX_TX_COMPLETION_HAS_QUEUED |
        IWX_TX_COMPLETION_HAS_CUR | IWX_TX_COMPLETION_HAS_TAIL;
    switch (kind) {
    case IWX_TX_COMPLETION_TX_RSP:
        return rxBase | ring | IWX_TX_COMPLETION_HAS_FRAME_COUNT |
            IWX_TX_COMPLETION_HAS_SSN | IWX_TX_COMPLETION_HAS_RA_TID |
            IWX_TX_COMPLETION_HAS_STATUS |
            IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL |
            IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL |
            IWX_TX_COMPLETION_HAS_TXCMD_SCAN |
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE;
    case IWX_TX_COMPLETION_BA:
        return rxBase | ring | IWX_TX_COMPLETION_HAS_BA_STA_ID |
            IWX_TX_COMPLETION_HAS_BA_FLAGS |
            IWX_TX_COMPLETION_HAS_BA_TFD_COUNT |
            IWX_TX_COMPLETION_HAS_BA_TXED | IWX_TX_COMPLETION_HAS_BA_DONE |
            IWX_TX_COMPLETION_HAS_BA_WIRELESS_TIME |
            IWX_TX_COMPLETION_HAS_BA_TFD_TID |
            IWX_TX_COMPLETION_HAS_BA_TFD_INDEX;
    case IWX_TX_COMPLETION_RX_PARSE_STOP:
        return rxBase;
    default:
        return 0;
    }
}

static inline bool absentValuesAreZero(
    const iwx_tx_completion_event_input *in)
{
#define IWX_TX_COMPLETION_ABSENT_ZERO(flag, field) \
    (((in->presence_flags & (flag)) != 0U) || in->field == 0U)
    return IWX_TX_COMPLETION_ABSENT_ZERO(
               IWX_TX_COMPLETION_HAS_MONOTONIC_NS, monotonic_ns) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
               IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH, output_epoch) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_RX_GROUP,
                                      rx_group) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_RX_COMMAND,
                                      rx_command) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_RX_HEADER_QID, rx_header_qid) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_RX_HEADER_INDEX, rx_header_index) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_RX_PACKET_LENGTH, rx_packet_length) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH, payload_length) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_FIRMWARE_QID, firmware_qid) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_QUEUE_INDEX, queue_index) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_RING_COUNT,
                                      ring_count) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_QUEUED,
                                      queued) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_CUR, cur) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_TAIL, tail) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_FRAME_COUNT, frame_count) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_SSN, ssn) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_RA_TID, ra_tid) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(IWX_TX_COMPLETION_HAS_STATUS, status) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_STA_ID, ba_sta_id) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_FLAGS, ba_flags) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_TFD_COUNT, ba_tfd_count) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_TXED, ba_txed) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_DONE, ba_done) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_WIRELESS_TIME, ba_wireless_time) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_TFD_TID, ba_tfd_tid) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_BA_TFD_INDEX, ba_tfd_index) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL,
            response_frame_control) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL,
            response_sequence_control) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_SCAN, txcmd_scan_status) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_SCAN, txcmd_expected_count) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_SCAN, txcmd_scanned_count) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_SCAN, txcmd_candidate_count) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE,
            txcmd_candidate_index) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE,
            txcmd_api_generation) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE,
            txcmd_command_version) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE, txcmd_flags) &&
        IWX_TX_COMPLETION_ABSENT_ZERO(
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE,
            txcmd_offload_assist);
#undef IWX_TX_COMPLETION_ABSENT_ZERO
}

static inline bool validWidths(const iwx_tx_completion_event_input *in)
{
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RX_GROUP) &&
        in->rx_group > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RX_COMMAND) &&
        in->rx_command > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RX_HEADER_QID) &&
        in->rx_header_qid > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RX_HEADER_INDEX) &&
        in->rx_header_index > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_FIRMWARE_QID) &&
        in->firmware_qid > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_FRAME_COUNT) &&
        in->frame_count > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_SSN) &&
        in->ssn > 0x0fffU)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RA_TID) &&
        in->ra_tid > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_STATUS) &&
        in->status > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_BA_STA_ID) &&
        in->ba_sta_id > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_BA_TFD_COUNT) &&
        in->ba_tfd_count > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_BA_TXED) &&
        in->ba_txed > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_BA_DONE) &&
        in->ba_done > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_BA_TFD_TID) &&
        in->ba_tfd_tid > UINT8_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_BA_TFD_INDEX) &&
        in->ba_tfd_index > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL) &&
        in->response_frame_control > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL) &&
        in->response_sequence_control > UINT16_MAX)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE) &&
        (in->txcmd_scan_status != 1 ||
         in->txcmd_api_generation < 2 || in->txcmd_api_generation > 3 ||
         in->txcmd_command_version > UINT8_MAX ||
         in->txcmd_candidate_count != 1 ||
         in->txcmd_candidate_index >= in->ring_count ||
         in->txcmd_scanned_count != in->txcmd_expected_count))
        return false;
    if (in->presence_flags & IWX_TX_COMPLETION_HAS_TXCMD_SCAN) {
        const uint32_t responseTuple =
            IWX_TX_COMPLETION_HAS_RESPONSE_FRAME_CONTROL |
            IWX_TX_COMPLETION_HAS_RESPONSE_SEQUENCE_CONTROL;
        if ((in->presence_flags & responseTuple) != responseTuple)
            return false;
        if (in->txcmd_scan_status != 1 && in->txcmd_scan_status != 2)
            return false;
        if (in->txcmd_candidate_count > in->txcmd_scanned_count)
            return false;
        if (in->txcmd_expected_count == 0 ||
            in->txcmd_expected_count > in->queued ||
            in->txcmd_expected_count > in->ring_count ||
            in->txcmd_scanned_count > in->txcmd_expected_count)
            return false;
        if (in->txcmd_scan_status == 1 &&
            in->txcmd_scanned_count != in->txcmd_expected_count)
            return false;
        if (in->txcmd_scan_status == 1 && in->txcmd_candidate_count == 1 &&
            (in->presence_flags &
             IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE) == 0)
            return false;
    } else if (in->presence_flags &
               IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE) {
        return false;
    }
    return true;
}

static inline bool validInput(const iwx_tx_completion_event_input *in)
{
    if (!in || in->kind >= kKindCount || !validStageReason(in))
        return false;
    const uint32_t allowed = allowedPresence(in->kind);
    if ((in->presence_flags & ~allowed) != 0U ||
        (in->presence_flags & ~IWX_TX_COMPLETION_CALLER_PRESENCE_MASK) != 0U)
        return false;
    if ((in->presence_flags & IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH) == 0U)
        return false;
    return absentValuesAreZero(in) && validWidths(in);
}

static inline void copyInput(const iwx_tx_completion_event_input *in,
                             uint64_t serial,
                             iwx_tx_completion_event_record *out)
{
    out->serial = serial;
    out->monotonic_ns = in->monotonic_ns;
    out->output_epoch = in->output_epoch;
    out->driver_generation = in->driver_generation;
    out->kind = in->kind;
    out->stage = in->stage;
    out->terminal_reason = in->terminal_reason;
    out->presence_flags = in->presence_flags |
        IWX_TX_COMPLETION_OBSERVER_HAS_SERIAL;
    out->rx_group = in->rx_group;
    out->rx_command = in->rx_command;
    out->rx_header_qid = in->rx_header_qid;
    out->rx_header_index = in->rx_header_index;
    out->rx_packet_length = in->rx_packet_length;
    out->payload_length = in->payload_length;
    out->firmware_qid = in->firmware_qid;
    out->queue_index = in->queue_index;
    out->ring_count = in->ring_count;
    out->queued = in->queued;
    out->cur = in->cur;
    out->tail = in->tail;
    out->frame_count = in->frame_count;
    out->ssn = in->ssn;
    out->ra_tid = in->ra_tid;
    out->status = in->status;
    out->ba_sta_id = in->ba_sta_id;
    out->ba_flags = in->ba_flags;
    out->ba_tfd_count = in->ba_tfd_count;
    out->ba_txed = in->ba_txed;
    out->ba_done = in->ba_done;
    out->ba_wireless_time = in->ba_wireless_time;
    out->ba_tfd_tid = in->ba_tfd_tid;
    out->ba_tfd_index = in->ba_tfd_index;
    out->response_frame_control = in->response_frame_control;
    out->response_sequence_control = in->response_sequence_control;
    out->txcmd_scan_status = in->txcmd_scan_status;
    out->txcmd_expected_count = in->txcmd_expected_count;
    out->txcmd_scanned_count = in->txcmd_scanned_count;
    out->txcmd_candidate_count = in->txcmd_candidate_count;
    out->txcmd_candidate_index = in->txcmd_candidate_index;
    out->txcmd_api_generation = in->txcmd_api_generation;
    out->txcmd_command_version = in->txcmd_command_version;
    out->txcmd_flags = in->txcmd_flags;
    out->txcmd_offload_assist = in->txcmd_offload_assist;
}

static inline void copySnapshotLocked(
    iwx_tx_completion_observation_state *state,
    iwx_tx_completion_observation_snapshot *out)
{
    if (!state || !out)
        return;
    *out = iwx_tx_completion_observation_snapshot{};
    out->available = 1;
    out->next_serial = __atomic_load_n(&state->next_serial,
                                       __ATOMIC_ACQUIRE);
    out->publication_serial = __atomic_load_n(&state->publication_serial,
                                               __ATOMIC_ACQUIRE);
    for (uint32_t kind = 0; kind < kKindCount; ++kind) {
        for (uint32_t reason = 0; reason < kMaxReasonCount; ++reason)
            out->terminal_reason_counts[kind][reason] =
                state->terminal_reason_counts[kind][reason];
        out->last[kind] = state->last[kind];
    }
    out->dropped_count = __atomic_load_n(&state->dropped_count,
                                          __ATOMIC_ACQUIRE);
    out->related_dropped_count = __atomic_load_n(
        &state->related_dropped_count, __ATOMIC_ACQUIRE);
    out->complete = out->dropped_count == 0 ? 1U : 0U;
}

static inline bool record(iwx_tx_completion_observation_state *state,
                          const iwx_tx_completion_event_input *in,
                          iwx_tx_completion_observation_snapshot *relatedCut = 0)
{
    if (!state || !validInput(in)) {
        noteDrop(state);
        if (relatedCut)
            noteRelatedDrop(state);
        return false;
    }
    if (!tryLock(state)) {
        noteDrop(state);
        if (relatedCut)
            noteRelatedDrop(state);
        return false;
    }

    const uint32_t kind = in->kind;
    const uint32_t reason = in->terminal_reason;
    iwx_tx_completion_event_record &last = state->last[kind];
    uint64_t &reasonCount = state->terminal_reason_counts[kind][reason];
    const uint64_t serial = __atomic_load_n(&state->next_serial,
                                            __ATOMIC_RELAXED);
    if (serial == UINT64_MAX ||
        last.event_count == UINT64_MAX || reasonCount == UINT64_MAX) {
        noteDrop(state);
        if (relatedCut)
            noteRelatedDrop(state);
        unlock(state);
        return false;
    }

    const uint64_t nextSerial = __atomic_add_fetch(&state->next_serial, 1U,
                                                    __ATOMIC_RELEASE);
    ++last.event_count;
    ++reasonCount;
    copyInput(in, nextSerial, &last);
    if (relatedCut) {
        if (!markPublicationRelevant(state))
            noteRelatedDrop(state);
        copySnapshotLocked(state, relatedCut);
    }
    unlock(state);
    return true;
}

static inline bool snapshot(iwx_tx_completion_observation_state *state,
                            iwx_tx_completion_observation_snapshot *out)
{
    if (!out)
        return false;
    *out = iwx_tx_completion_observation_snapshot{};
    if (!state || !tryLock(state))
        return false;

    copySnapshotLocked(state, out);
    unlock(state);
    return true;
}

static inline void reset(iwx_tx_completion_observation_state *state)
{
    if (state)
        *state = iwx_tx_completion_observation_state{};
}

} // namespace IwxTxCompletionObservation

#endif // __cplusplus

#endif // GEEK_IWX_TX_COMPLETION_OBSERVATION_HPP
