// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_TX_RSP_PREFIX_OBSERVATION_HPP
#define GEEK_IWX_TX_RSP_PREFIX_OBSERVATION_HPP

#include <stddef.h>
#include <stdint.h>

/* Local host layout only. The notification version comes from CMD_VERSIONS;
 * neither this decode nor its version marker asserts a compatible firmware
 * ABI, transmitted sequence number, exact response identity, or peer ACK. */
namespace IwxTxRspPrefixObservation {
enum {
    kUnavailable = 0,
    kLocalSinglePrefixV1 = 1,
    kUnknownNotificationVersion = 0xff,
    kVersionLookupGroup = 1,
    kVersionLookupCommand = 0x1c,
    kSequenceControlOffset = 28,
    kByteCountOffset = 30,
    kRaTidOffset = 33,
    kFrameControlOffset = 34,
    kQueueOffset = 36,
    kStatusOffset = 40,
    kStatusSequenceOffset = 42,
    kSingleSsnOffset = 44,
    kSinglePayloadLength = 48,
    kGen2FlagsOffset = 4,
    kGen2OffloadOffset = 2,
    kGen2HeaderOffset = 20,
    kGen3FlagsOffset = 2,
    kGen3OffloadOffset = 4,
    kGen3HeaderOffset = 28
};

struct Fields {
    uint16_t sequence_control;
    uint16_t byte_count;
    uint16_t frame_control;
    uint16_t queue;
    uint16_t status;
    uint16_t status_sequence;
    uint32_t raw_scd_ssn;
    uint8_t ra_tid;
};

static inline uint16_t le16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
        (static_cast<uint16_t>(bytes[1]) << 8);
}

static inline bool decodeLocalSingleV1(const uint8_t *payload,
    size_t length, Fields *out)
{
    if (!payload || !out || length < kSinglePayloadLength || payload[0] != 1)
        return false;
    Fields decoded{};
    decoded.sequence_control = le16(payload + kSequenceControlOffset);
    decoded.byte_count = le16(payload + kByteCountOffset);
    decoded.frame_control = le16(payload + kFrameControlOffset);
    decoded.queue = le16(payload + kQueueOffset);
    decoded.status = le16(payload + kStatusOffset);
    decoded.status_sequence = le16(payload + kStatusSequenceOffset);
    decoded.raw_scd_ssn = static_cast<uint32_t>(payload[kSingleSsnOffset]) |
        (static_cast<uint32_t>(payload[kSingleSsnOffset + 1]) << 8) |
        (static_cast<uint32_t>(payload[kSingleSsnOffset + 2]) << 16) |
        (static_cast<uint32_t>(payload[kSingleSsnOffset + 3]) << 24);
    decoded.ra_tid = payload[kRaTidOffset];
    *out = decoded;
    return true;
}
} // namespace IwxTxRspPrefixObservation
#endif
