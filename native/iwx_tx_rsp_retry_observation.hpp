// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_RSP_RETRY_OBSERVATION_HPP
#define GEEK_IWX_TX_RSP_RETRY_OBSERVATION_HPP

#include <stddef.h>
#include <stdint.h>

/*
 * Read the common first four scalar bytes of a complete, single-frame
 * TX_RSP. This is a host-side diagnostic for the layout in the local
 * iwx_tx_resp declaration; it does not establish the firmware notification ABI,
 * RF transmission, an ACK, or peer acceptance.
 */
namespace IwxTxRspRetryObservation {

enum {
    kLayoutUnavailable = 0,
    kLayoutCommonPrefixV1 = 1,
    kPrefixLength = 4,
    // Local iwx_tx_resp declaration: status offset 40, one status entry (4), SCD SSN (4).
    kSingleFrameMinimumPayloadLength = 48
};

struct Fields {
    uint8_t frame_count;
    uint8_t bt_kill_count;
    uint8_t failure_rts;
    uint8_t failure_frame;
};

static inline bool decodeSingleFrameV1(const uint8_t *payload,
    size_t payloadLength, size_t requiredSingleFrameLength, Fields *out)
{
    if (!payload || !out ||
        requiredSingleFrameLength < kSingleFrameMinimumPayloadLength ||
        payloadLength < requiredSingleFrameLength ||
        payloadLength < kPrefixLength || payload[0] != 1U)
        return false;

    const Fields decoded{payload[0], payload[1], payload[2], payload[3]};
    *out = decoded;
    return true;
}

} // namespace IwxTxRspRetryObservation

#endif
