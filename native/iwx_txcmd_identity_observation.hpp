// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TXCMD_IDENTITY_OBSERVATION_HPP
#define GEEK_IWX_TXCMD_IDENTITY_OBSERVATION_HPP

#include <stdint.h>

/*
 * Bounded, read-only correlation of a TX_RSP tuple against host TX_CMD
 * headers which are still live in the response's exclusive reclaim interval.
 * This does not alter the reclaim index or infer ACK/peer receipt.
 */
enum {
    IWX_TXCMD_IDENTITY_SCAN_NOT_STARTED = 0,
    IWX_TXCMD_IDENTITY_SCAN_COMPLETE = 1,
    IWX_TXCMD_IDENTITY_SCAN_INCOMPLETE = 2,
    IWX_TXCMD_IDENTITY_MAX_RING_COUNT = 1024
};

typedef struct iwx_txcmd_identity_candidate {
    uint32_t qid;
    uint32_t index;
    uint32_t api_generation;
    uint32_t command_version;
    uint32_t frame_control;
    uint32_t sequence_control;
    uint32_t command_flags;
    uint32_t offload_assist;
} iwx_txcmd_identity_candidate;

typedef struct iwx_txcmd_identity_scan {
    uint32_t qid;
    uint32_t ring_count;
    uint32_t old_tail;
    uint32_t expected_count;
    uint32_t scanned_count;
    uint32_t invalid_count;
    uint32_t candidate_count;
    uint32_t response_frame_control;
    uint32_t response_sequence_control;
    uint32_t status;
    iwx_txcmd_identity_candidate first_candidate;
    uint32_t observed_candidate_count;
    iwx_txcmd_identity_candidate first_observed_candidate;
} iwx_txcmd_identity_scan;

static inline int iwx_txcmd_identity_scan_begin(
    iwx_txcmd_identity_scan *scan, uint32_t qid, uint32_t ring_count,
    uint32_t old_tail, uint32_t old_queued, uint32_t reclaim_boundary,
    uint32_t response_frame_control, uint32_t response_sequence_control)
{
    if (scan == 0)
        return 0;
    __builtin_memset(scan, 0, sizeof(*scan));
    if (ring_count == 0 || ring_count > IWX_TXCMD_IDENTITY_MAX_RING_COUNT ||
        old_tail >= ring_count || reclaim_boundary >= ring_count ||
        old_queued > ring_count || response_frame_control > UINT16_MAX ||
        response_sequence_control > UINT16_MAX)
        return 0;
    const uint32_t distance =
        (reclaim_boundary + ring_count - old_tail) % ring_count;
    if (distance == 0 || distance > old_queued)
        return 0;
    scan->qid = qid;
    scan->ring_count = ring_count;
    scan->old_tail = old_tail;
    scan->expected_count = distance;
    scan->response_frame_control = response_frame_control;
    scan->response_sequence_control = response_sequence_control;
    scan->status = IWX_TXCMD_IDENTITY_SCAN_INCOMPLETE;
    return 1;
}

static inline uint32_t iwx_txcmd_identity_expected_index(
    const iwx_txcmd_identity_scan *scan)
{
    if (scan == 0 || scan->ring_count == 0 ||
        scan->scanned_count >= scan->expected_count)
        return UINT32_MAX;
    return (scan->old_tail + scan->scanned_count) % scan->ring_count;
}

/* Consume one expected descriptor. valid==0 explicitly marks a hole or an
 * unreadable command, so a seemingly unique match cannot be overclaimed. */
static inline int iwx_txcmd_identity_scan_record(
    iwx_txcmd_identity_scan *scan, uint32_t index, uint32_t valid,
    const iwx_txcmd_identity_candidate *candidate)
{
    if (scan == 0 || scan->ring_count == 0 ||
        scan->status != IWX_TXCMD_IDENTITY_SCAN_INCOMPLETE ||
        scan->scanned_count >= scan->expected_count ||
        index != iwx_txcmd_identity_expected_index(scan))
        return 0;
    ++scan->scanned_count;
    if (!valid || candidate == 0 || candidate->qid != scan->qid ||
        candidate->index != index || candidate->api_generation < 2 ||
        candidate->api_generation > 3 ||
        candidate->frame_control > UINT16_MAX ||
        candidate->sequence_control > UINT16_MAX) {
        ++scan->invalid_count;
        if (scan->scanned_count == scan->expected_count &&
            scan->invalid_count == 0)
            scan->status = IWX_TXCMD_IDENTITY_SCAN_COMPLETE;
        return 1;
    }
    if (scan->observed_candidate_count != UINT32_MAX)
        ++scan->observed_candidate_count;
    if (scan->observed_candidate_count == 1)
        scan->first_observed_candidate = *candidate;
    if (candidate->frame_control == scan->response_frame_control &&
        candidate->sequence_control == scan->response_sequence_control) {
        if (scan->candidate_count != UINT32_MAX)
            ++scan->candidate_count;
        if (scan->candidate_count == 1)
            scan->first_candidate = *candidate;
    }
    if (scan->scanned_count == scan->expected_count)
        scan->status = scan->invalid_count == 0 ?
            IWX_TXCMD_IDENTITY_SCAN_COMPLETE :
            IWX_TXCMD_IDENTITY_SCAN_INCOMPLETE;
    return 1;
}

static inline int iwx_txcmd_identity_scan_has_unique_candidate(
    const iwx_txcmd_identity_scan *scan)
{
    return scan != 0 &&
        scan->status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE &&
        scan->scanned_count == scan->expected_count &&
        scan->candidate_count == 1 &&
        scan->first_candidate.qid == scan->qid;
}

/*
 * This reports only that a complete, one-entry reclaim interval contained one
 * readable TX_CMD header. It does not associate the firmware response with
 * that command, establish ACK, or identify a Group2 cookie.
 */
static inline int iwx_txcmd_identity_scan_has_single_observed_slot_header(
    const iwx_txcmd_identity_scan *scan)
{
    return scan != 0 &&
        scan->status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE &&
        scan->expected_count == 1 &&
        scan->scanned_count == 1 &&
        scan->invalid_count == 0 &&
        scan->observed_candidate_count == 1 &&
        scan->first_observed_candidate.qid == scan->qid &&
        scan->first_observed_candidate.index <
            scan->ring_count;
}

#endif
