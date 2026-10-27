// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_ACTION_TX_HPP
#define NATIVE_P2P_ACTION_TX_HPP

#include <stddef.h>
#include <stdint.h>

namespace IntelP2PActionTx {

enum class Result : uint8_t {
    kReady,
    kInvalid,
    kBusy,
    kStaleGeneration,
    kWrongQueue,
    kWrongDescriptor,
    kWrongLength,
    kWrongFrameControl,
    kMalformedResponse,
    kFrameFailed,
    kCompletion,
    kCancelled
};

struct Ticket {
    uint32_t generation;
    uint16_t queueId;
    uint16_t ringSize;
    uint16_t descriptorIndex;
    uint16_t sequenceControl;
    uint16_t byteCount;
    uint16_t frameControl;
    uint16_t status;
    bool armed;
    bool completed;
    bool frameAttemptSucceeded;
    bool peerAcknowledged;
};

/* Extract the fw68 TX_RSP queue field without reading past a short RX packet. */
bool extractTxResponseQueueId(const uint8_t *payload, size_t length,
                              size_t queueOffset, uint16_t *queueId);

/* Encode a fixed legacy OFDM rate using RATE_MCS v2's OFDM-relative index. */
bool encodeLegacyOfdmRateV2(uint8_t rateIndex, uint8_t firstOfdmIndex,
                            uint8_t antennaMask, uint8_t antennaCount,
                            uint8_t antennaPosition, uint32_t ofdmMask,
                            uint32_t *rateNFlags);

// The queue owner arms this before writing the TX doorbell. Action traffic is
// one frame per descriptor; aggregation and BA reclaim never apply here.
class CompletionTracker {
public:
    CompletionTracker();
    Result arm(uint32_t generation, uint16_t queueId, uint16_t ringSize,
               uint16_t descriptorIndex, uint16_t sequenceControl,
               uint16_t byteCount, uint16_t frameControl);

    // Cancel a prepared ticket only when the caller has direct evidence that
    // the TX doorbell was not written. Exact identity is required so this
    // cannot erase an older in-flight descriptor after a failed preflight.
    Result cancelUnsubmitted(uint32_t generation, uint16_t queueId,
                             uint16_t descriptorIndex);

    // Decode fw68 TX_RSP_API_S_VER_6/_VER_7. Offsets are the production struct's
    // offsetof(frame_count/status/seq_ctl/tx_queue); tests use its exact wire
    // shape. The final SCD SSN is the *next* descriptor index; seq_ctl is
    // frame metadata and may differ on firmware failures. The HAL caller
    // must also prove the matching lease and sole in-flight ring slot.
    Result complete(uint32_t generation, const uint8_t *payload,
                    size_t length, size_t statusOffset,
                    size_t sequenceOffset, size_t byteCountOffset,
                    size_t frameControlOffset, size_t queueOffset,
                    size_t nextSsnOffset);

    // Call only after positively proven firmware stop plus RX/TX/DMA drain.
    // Empty or completed tickets retire idempotently; a live ticket requires
    // a nonzero generation different from the ticket's generation.
    Result firmwareDrained(uint32_t newGeneration);
    Ticket snapshot() const;

private:
    Ticket ticket_;
    bool quarantined_;
};

} // namespace IntelP2PActionTx

namespace IntelP2PActionFrame {

static const size_t kMacHeaderLength = 24;
static const size_t kMacHeaderWithHtControlLength = 28;
static const uint8_t kVendorSpecificCategory = 127;

struct FrameInfo {
    size_t headerLength;
    uint16_t frameControl;
    uint16_t sequenceControl;
    uint8_t category;
};

struct TfdPlan {
    uint16_t numTbs;
    uint16_t firstTbLength;
    uint16_t commandTailLength;
    uint16_t payloadSegmentCount;
    uint16_t frameByteCount;
};

/*
 * Builds a local diagnostic Vendor Specific Action MPDU. The OUI field is
 * deliberately the locally administered source-address prefix; it is not an
 * assigned vendor OUI and does not identify Apple/AWDL/P2P protocol traffic.
 */
bool encodeVendorSpecificAction(const uint8_t source[6], uint16_t sequence,
                                const uint8_t *vendorPayload,
                                size_t vendorPayloadLength,
                                uint8_t *output, size_t outputCapacity,
                                size_t *outputLength);

bool inspectActionFrame(const uint8_t *frame, size_t frameLength,
                        const uint8_t expectedSource[6],
                        FrameInfo *info);

/* Mirrors the fw68 TFD's command TB split plus mapped payload segments. */
bool buildTfdPlan(size_t commandHeaderLength, size_t txCommandLength,
                  size_t macHeaderLength, const uint16_t *payloadSegmentLengths,
                  size_t payloadSegmentCount, size_t frameByteCount,
                  TfdPlan *plan);

} // namespace IntelP2PActionFrame
#endif
