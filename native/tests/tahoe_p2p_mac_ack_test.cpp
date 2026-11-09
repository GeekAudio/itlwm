#include "../tahoe_p2p_mac_ack.hpp"

#include <assert.h>
#include <string.h>

static TahoeP2PMacContextAckReceipt validReceipt()
{
    TahoeP2PMacContextAckReceipt r{};
    r.schemaVersion = TahoeP2PMacContextAckPolicy::kSchemaVersion;
    r.transportResult = 0;
    r.expectedP2PEpoch = 17;
    r.expectedRocToken = 17;
    r.observedP2PEpoch = 17;
    r.observedRocToken = 17;
    r.expectedDriverGeneration = 29;
    r.driverGeneration = 29;
    r.observedDriverGeneration = 29;
    r.observedP2PFirmwareGeneration = 29;
    r.submitState = TahoeP2PMacContextAckPolicy::kLocalEnqueueSubmitState;
    r.submitCommandId = TahoeP2PMacContextAckPolicy::kCommandId;
    r.submitCommandGroup = TahoeP2PMacContextAckPolicy::kHostCommandGroup;
    r.submitQueueId = TahoeP2PMacContextAckPolicy::kCommandQueue;
    r.submitQueueIndex = 9;
    r.responseCommand = TahoeP2PMacContextAckPolicy::kCommandId;
    r.responseGroup = TahoeP2PMacContextAckPolicy::kResponseGroup;
    r.responseQueueId = TahoeP2PMacContextAckPolicy::kCommandQueue;
    r.responseQueueIndex = 9;
    r.packetLength = TahoeP2PMacContextAckPolicy::kEmptyResponsePacketLength;
    r.payloadLength = 0;
    r.responsePresent = 1;
    return r;
}

static void rejects(TahoeP2PMacContextAckReceipt r, uint32_t reason)
{
    assert(!TahoeP2PMacContextAckPolicy::evaluate(&r));
    assert(r.accepted == 0);
    assert((r.rejectReason & reason) != 0);
}

int main()
{
    TahoeP2PMacContextAckReceipt r = validReceipt();
    assert(TahoeP2PMacContextAckPolicy::evaluate(&r));
    assert(r.accepted == 1);
    assert(r.rejectReason == TAHOE_P2P_MAC_ACK_REJECT_NONE);

    r = validReceipt();
    r.transportResult = 5;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_TRANSPORT);

    r = validReceipt();
    r.submitState = 1;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_STATE);

    r = validReceipt();
    r.submitQueueIndex = 0xffffffffu;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_SUBMIT_QUEUE);

    r = validReceipt();
    r.responsePresent = 0;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_MISSING);

    r = validReceipt();
    r.responseCommand = 0;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_COMMAND);

    r = validReceipt();
    r.responseGroup |= TahoeP2PMacContextAckPolicy::kResponseFailedMask;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_FAILED);

    r = validReceipt();
    r.responseGroup = 0;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_GROUP);

    r = validReceipt();
    r.responseQueueId = 0x80;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_UNSOLICITED);

    r = validReceipt();
    r.responseQueueId = 1;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_QUEUE);

    r = validReceipt();
    r.responseQueueIndex++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_INDEX);

    /* A zero-filled generic 4-byte status payload must never pass as ACK. */
    r = validReceipt();
    r.packetLength = 8;
    r.payloadLength = 4;
    assert(!TahoeP2PMacContextAckPolicy::evaluate(&r));
    assert((r.rejectReason & TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_LENGTH) != 0);
    assert((r.rejectReason & TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_PAYLOAD) != 0);

    r = validReceipt();
    r.packetLength = 3;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_LENGTH);

    r = validReceipt();
    r.expectedDriverGeneration++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_DRIVER_GENERATION);

    r = validReceipt();
    r.observedDriverGeneration++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_DRIVER_GENERATION);

    r = validReceipt();
    r.observedP2PFirmwareGeneration++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_DRIVER_GENERATION);

    r = validReceipt();
    r.observedP2PEpoch++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH);

    r = validReceipt();
    r.observedRocToken++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH);

    r = validReceipt();
    r.expectedRocToken = 0;
    r.observedRocToken = 0;
    assert(TahoeP2PMacContextAckPolicy::evaluate(&r));
    assert(r.accepted == 1);

    r = validReceipt();
    r.expectedRocToken = 18;
    r.observedRocToken = 18;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH);

    r = validReceipt();
    r.expectedP2PEpoch = 0;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH);

    r = validReceipt();
    r.schemaVersion++;
    rejects(r, TAHOE_P2P_MAC_ACK_REJECT_SCHEMA);

    return 0;
}
