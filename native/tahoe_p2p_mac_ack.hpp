#ifndef TAHOE_P2P_MAC_ACK_HPP
#define TAHOE_P2P_MAC_ACK_HPP

#include <stdint.h>
#include "iwx_sta_auth_trace.h"

/*
 * Run-local evidence for the Tahoe directed-data MAC_CONTEXT REMOVE.
 * `accepted` means only that the exact synchronous empty command response
 * matched this command submission and its live driver/P2P epoch. It is not
 * an over-the-air ACK or proof that firmware released the MAC resource.
 */
struct TahoeP2PMacContextAckReceipt {
    uint32_t schemaVersion;
    uint32_t accepted;
    uint32_t rejectReason;
    int32_t transportResult;
    uint32_t expectedP2PEpoch;
    uint32_t expectedRocToken;
    uint32_t observedP2PEpoch;
    uint32_t observedRocToken;
    uint32_t expectedDriverGeneration;
    uint32_t driverGeneration;
    uint32_t observedDriverGeneration;
    uint32_t observedP2PFirmwareGeneration;
    uint32_t submitState;
    uint32_t submitCommandId;
    uint32_t submitCommandGroup;
    uint32_t submitQueueId;
    uint32_t submitQueueIndex;
    uint32_t responseCommand;
    uint32_t responseGroup;
    uint32_t responseQueueId;
    uint32_t responseQueueIndex;
    uint32_t packetLength;
    uint32_t payloadLength;
    uint32_t responsePresent;
};

enum TahoeP2PMacContextAckRejectReason {
    TAHOE_P2P_MAC_ACK_REJECT_NONE = 0,
    TAHOE_P2P_MAC_ACK_REJECT_SCHEMA = 1u << 0,
    TAHOE_P2P_MAC_ACK_REJECT_TRANSPORT = 1u << 1,
    TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_STATE = 1u << 2,
    TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_COMMAND = 1u << 3,
    TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_QUEUE = 1u << 4,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_MISSING = 1u << 5,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_COMMAND = 1u << 6,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_GROUP = 1u << 7,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_FAILED = 1u << 8,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_UNSOLICITED = 1u << 9,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_QUEUE = 1u << 10,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_INDEX = 1u << 11,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_LENGTH = 1u << 12,
    TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_PAYLOAD = 1u << 13,
    TAHOE_P2P_MAC_ACK_REJECT_DRIVER_GENERATION = 1u << 14,
    TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH = 1u << 15
};

namespace TahoeP2PMacContextAckPolicy {
static const uint32_t kSchemaVersion = 1;
static const uint32_t kCommandId = 0x28;
static const uint32_t kHostCommandGroup = 0; /* Existing narrow-command API. */
static const uint32_t kResponseGroup = 0x01;
static const uint32_t kResponseFailedMask = 0x40;
static const uint32_t kCommandQueue = 0;
static const uint32_t kEmptyResponsePacketLength = 4; /* cmd header only */
static const uint32_t kLocalEnqueueSubmitState =
    IWX_STA_SUBMIT_LOCAL_ENQUEUE;

inline bool evaluate(TahoeP2PMacContextAckReceipt *receipt)
{
    if (receipt == nullptr)
        return false;

    receipt->accepted = 0;
    uint32_t reject = receipt->rejectReason;
    if (receipt->schemaVersion != kSchemaVersion)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_SCHEMA;
    if (receipt->transportResult != 0)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_TRANSPORT;
    if (receipt->submitState != kLocalEnqueueSubmitState)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_STATE;
    if (receipt->submitCommandId != kCommandId ||
        receipt->submitCommandGroup != kHostCommandGroup)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_COMMAND;
    if (receipt->submitQueueId != kCommandQueue ||
        receipt->submitQueueIndex > 0xffu)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_QUEUE;
    if (!receipt->responsePresent)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_MISSING;
    if (receipt->responseCommand != kCommandId)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_COMMAND;
    if ((receipt->responseGroup & kResponseFailedMask) != 0)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_FAILED;
    if ((receipt->responseGroup & ~kResponseFailedMask) != kResponseGroup)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_GROUP;
    if ((receipt->responseQueueId & 0x80u) != 0)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_UNSOLICITED;
    if (receipt->responseQueueId != kCommandQueue)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_QUEUE;
    if (receipt->responseQueueIndex != receipt->submitQueueIndex)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_INDEX;
    if (receipt->packetLength != kEmptyResponsePacketLength)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_LENGTH;
    if (receipt->payloadLength != 0)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_PAYLOAD;
    if (receipt->expectedDriverGeneration == 0 ||
        receipt->driverGeneration != receipt->expectedDriverGeneration ||
        receipt->observedDriverGeneration != receipt->expectedDriverGeneration ||
        receipt->observedP2PFirmwareGeneration !=
            receipt->expectedDriverGeneration)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_DRIVER_GENERATION;
    if (receipt->expectedP2PEpoch == 0 ||
        receipt->observedP2PEpoch != receipt->expectedP2PEpoch)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH;
    if ((receipt->expectedRocToken != 0 &&
         receipt->expectedRocToken != receipt->expectedP2PEpoch) ||
        receipt->observedRocToken != receipt->expectedRocToken)
        reject |= TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH;

    receipt->rejectReason = reject;
    receipt->accepted = reject == TAHOE_P2P_MAC_ACK_REJECT_NONE ? 1u : 0u;
    return receipt->accepted != 0;
}
} // namespace TahoeP2PMacContextAckPolicy

#endif
