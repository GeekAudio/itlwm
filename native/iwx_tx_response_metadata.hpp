// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_RESPONSE_METADATA_HPP
#define GEEK_IWX_TX_RESPONSE_METADATA_HPP

#include <stdint.h>

/*
 * Resolve per-frame host metadata only when a single-frame TX_RSP retires
 * exactly one live queue position. `reclaim_boundary` remains the firmware's
 * exclusive SSN boundary; the eligible slot is then the pre-reclaim tail.
 * This helper does not identify a peer ACK or change queue retirement.
 */
static inline int iwx_tx_response_single_reclaim_metadata_index(
    uint32_t ring_count, uint32_t old_tail, uint32_t old_queued,
    uint32_t reclaim_boundary, uint32_t frame_count, uint32_t *index_out)
{
    if (index_out == 0)
        return 0;
    *index_out = UINT32_MAX;
    if (ring_count == 0 || old_tail >= ring_count ||
        reclaim_boundary >= ring_count || old_queued > ring_count ||
        frame_count != 1)
        return 0;

    const uint32_t distance =
        (reclaim_boundary + ring_count - old_tail) % ring_count;
    if (distance != 1 || distance > old_queued)
        return 0;

    *index_out = old_tail;
    return 1;
}

#endif
