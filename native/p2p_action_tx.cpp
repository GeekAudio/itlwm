// SPDX-License-Identifier: GPL-2.0-only
#include "p2p_action_tx.hpp"

#include <string.h>

namespace IntelP2PActionTx {
namespace {
uint16_t le16(const uint8_t *p)
{
    return uint16_t(p[0]) | uint16_t(uint16_t(p[1]) << 8);
}
uint32_t le32(const uint8_t *p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 |
        uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
}

CompletionTracker::CompletionTracker() : ticket_{}, quarantined_(false) {}

bool extractTxResponseQueueId(const uint8_t *payload, size_t length,
                              size_t queueOffset, uint16_t *queueId)
{
    if (!payload || !queueId || queueOffset > length ||
        length - queueOffset < sizeof(uint16_t))
        return false;
    *queueId = le16(payload + queueOffset);
    return true;
}

bool encodeLegacyOfdmRateV2(uint8_t rateIndex, uint8_t firstOfdmIndex,
                            uint8_t antennaMask, uint8_t antennaCount,
                            uint8_t antennaPosition, uint32_t ofdmMask,
                            uint32_t *rateNFlags)
{
    if (!rateNFlags || rateIndex < firstOfdmIndex || antennaCount == 0 ||
        antennaCount > 8 || antennaPosition >= 32 ||
        antennaPosition + antennaCount > 32 || ofdmMask == 0)
        return false;
    uint8_t antenna = 0;
    while (antenna < antennaCount &&
           (antennaMask & static_cast<uint8_t>(1U << antenna)) == 0)
        ++antenna;
    if (antenna == antennaCount)
        return false;
    *rateNFlags = ofdmMask |
        static_cast<uint32_t>(rateIndex - firstOfdmIndex) |
        (static_cast<uint32_t>(1U << antenna) << antennaPosition);
    return true;
}

Result CompletionTracker::arm(uint32_t generation, uint16_t queue,
                              uint16_t ringSize, uint16_t descriptor,
                              uint16_t sequence, uint16_t byteCount,
                              uint16_t frameControl)
{
    if (quarantined_)
        return Result::kBusy;
    if (ticket_.armed && !ticket_.completed)
        return Result::kBusy;
    // DQA TVQM queue IDs occupy a separate 9-bit space from legacy queues.
    if (!generation || queue >= 512 || ringSize < 8 || ringSize > 256 ||
        (ringSize & (ringSize - 1)) || descriptor >= ringSize ||
        byteCount < 24)
        return Result::kInvalid;
    ticket_ = {};
    ticket_.generation = generation;
    ticket_.queueId = queue;
    ticket_.ringSize = ringSize;
    ticket_.descriptorIndex = descriptor;
    ticket_.sequenceControl = sequence;
    ticket_.byteCount = byteCount;
    ticket_.frameControl = frameControl;
    ticket_.armed = true;
    return Result::kReady;
}

Result CompletionTracker::cancelUnsubmitted(uint32_t generation,
                                           uint16_t queue,
                                           uint16_t descriptor)
{
    if (!generation || !ticket_.armed || ticket_.completed || quarantined_)
        return Result::kBusy;
    if (generation != ticket_.generation)
        return Result::kStaleGeneration;
    if (queue != ticket_.queueId)
        return Result::kWrongQueue;
    if (descriptor != ticket_.descriptorIndex)
        return Result::kWrongDescriptor;
    memset(&ticket_, 0, sizeof(ticket_));
    return Result::kCancelled;
}

Result CompletionTracker::complete(uint32_t generation, const uint8_t *p,
                                   size_t length, size_t statusOffset,
                                   size_t sequenceOffset,
                                   size_t byteCountOffset,
                                   size_t frameControlOffset,
                                   size_t queueOffset,
                                   size_t nextSsnOffset)
{
    if (!ticket_.armed || ticket_.completed || quarantined_)
        return Result::kBusy;
    if (generation != ticket_.generation)
        return Result::kStaleGeneration;
    if (!p || statusOffset > length || length - statusOffset < 2 ||
        sequenceOffset > length || length - sequenceOffset < 2 ||
        byteCountOffset > length || length - byteCountOffset < 2 ||
        frameControlOffset > length || length - frameControlOffset < 2 ||
        queueOffset > length || length - queueOffset < 2 ||
        nextSsnOffset > length || length - nextSsnOffset < 4 ||
        statusOffset < 1)
        return Result::kMalformedResponse;

    // TX_RSP API v6/v7 is a single non-aggregate MPDU. Keep the ring lease when
    // firmware reports an aggregate batch or an unexpected frame response.
    if (p[0] != 1) {
        quarantined_ = true;
        return Result::kMalformedResponse;
    }
    const uint16_t qid = le16(p + queueOffset);
    if (qid != ticket_.queueId) {
        quarantined_ = true;
        return Result::kWrongQueue;
    }
    // seq_ctl describes the over-the-air 802.11 frame, not the DMA slot.
    // In particular firmware may return an incorrect seq_ctl on TX failure
    // (Linux iwl_mvm_rx_tx_cmd_single corrects it from the owned frame).
    // The HAL must already hold the matching queue lease and one live slot;
    // queue/generation and the trailing scheduler SSN below retire that slot.
    // Keep sequenceOffset bounds checking and numeric HAL telemetry, but do
    // not turn an unreliable frame sequence into an ownership verdict.
    if (le16(p + byteCountOffset) != ticket_.byteCount) {
        quarantined_ = true;
        return Result::kWrongLength;
    }
    if (le16(p + frameControlOffset) != ticket_.frameControl) {
        quarantined_ = true;
        return Result::kWrongFrameControl;
    }
    const uint16_t nextIndex = static_cast<uint16_t>(
        le32(p + nextSsnOffset) & (ticket_.ringSize - 1));
    const uint16_t expectedNext = static_cast<uint16_t>(
        (ticket_.descriptorIndex + 1) & (ticket_.ringSize - 1));
    if (nextIndex != expectedNext) {
        quarantined_ = true;
        return Result::kWrongDescriptor;
    }

    ticket_.status = le16(p + statusOffset);
    ticket_.completed = true;
    ticket_.frameAttemptSucceeded = (ticket_.status & 0xff) == 1;
    // Response status alone never proves that an AWDL peer received the frame.
    ticket_.peerAcknowledged = false;
    return ticket_.frameAttemptSucceeded ? Result::kCompletion
                                         : Result::kFrameFailed;
}

Result CompletionTracker::firmwareDrained(uint32_t newGeneration)
{
    if (!newGeneration ||
        (ticket_.armed && !ticket_.completed &&
         newGeneration == ticket_.generation))
        return Result::kInvalid;
    memset(&ticket_, 0, sizeof(ticket_));
    quarantined_ = false;
    return Result::kReady;
}

Ticket CompletionTracker::snapshot() const
{
    return ticket_;
}

} // namespace IntelP2PActionTx

namespace IntelP2PActionFrame {
namespace {

static bool isUsableLocalUnicast(const uint8_t *address)
{
    uint8_t any = 0;
    if (!address)
        return false;
    for (size_t i = 0; i < 6; ++i)
        any |= address[i];
    return any != 0 && (address[0] & 0x01) == 0 &&
        (address[0] & 0x02) != 0;
}

static uint16_t readLe16(const uint8_t *bytes)
{
    return uint16_t(bytes[0]) | uint16_t(uint16_t(bytes[1]) << 8);
}

static void writeLe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value & 0xff);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

} // namespace

bool encodeVendorSpecificAction(const uint8_t source[6], uint16_t sequence,
                                const uint8_t *vendorPayload,
                                size_t vendorPayloadLength,
                                uint8_t *output, size_t outputCapacity,
                                size_t *outputLength)
{
    if (outputLength)
        *outputLength = 0;
    if (!outputLength || !output || !isUsableLocalUnicast(source) ||
        !vendorPayload || vendorPayloadLength == 0 || sequence > 0x0fff)
        return false;

    /* A vendor-specific Action body is category + OUI + vendor data. */
    const size_t required = kMacHeaderLength + 4 + vendorPayloadLength;
    if (required > outputCapacity || required > 0xffff)
        return false;

    /* Broadcast DA/BSSID, private SA, 802.11 management Action subtype. */
    memset(output, 0, required);
    output[0] = 0xd0; // FC0: version 0, management, Action subtype
    output[1] = 0x00;
    writeLe16(output + 2, 0); // duration
    memset(output + 4, 0xff, 6); // addr1 destination
    memcpy(output + 10, source, 6); // addr2 source
    memset(output + 16, 0xff, 6); // addr3 BSSID
    writeLe16(output + 22, static_cast<uint16_t>(sequence << 4));
    output[24] = kVendorSpecificCategory;
    memcpy(output + 25, source, 3); // local-scoped OUI-like experiment tag
    memcpy(output + 28, vendorPayload, vendorPayloadLength);
    *outputLength = required;
    return true;
}

bool inspectActionFrame(const uint8_t *frame, size_t frameLength,
                        const uint8_t expectedSource[6], FrameInfo *info)
{
    if (!frame || !expectedSource || !info ||
        frameLength < kMacHeaderLength + 2)
        return false;

    const uint8_t fc0 = frame[0];
    const uint8_t fc1 = frame[1];
    const uint16_t frameControl = readLe16(frame);
    const size_t headerLength = (fc1 & 0x80) != 0 ?
        kMacHeaderWithHtControlLength : kMacHeaderLength;

    /* Management Action only; reject protected, fragmented, or DS frames. */
    if ((fc0 & 0x03) != 0 || (fc0 & 0x0c) != 0 ||
        (fc0 & 0xf0) != 0xd0 || (fc1 & (0x01 | 0x02 | 0x04 | 0x40)) != 0 ||
        frameLength < headerLength + 2 ||
        memcmp(frame + 10, expectedSource, 6) != 0 ||
        (readLe16(frame + 22) & 0x000f) != 0)
        return false;

    const uint8_t category = frame[headerLength];
    if (category == kVendorSpecificCategory &&
        frameLength < headerLength + 4)
        return false;

    info->headerLength = headerLength;
    info->frameControl = frameControl;
    info->sequenceControl = readLe16(frame + 22);
    info->category = category;
    return true;
}

bool buildTfdPlan(size_t commandHeaderLength, size_t txCommandLength,
                  size_t macHeaderLength, const uint16_t *segmentLengths,
                  size_t segmentCount, size_t frameByteCount, TfdPlan *plan)
{
    static const size_t kFirstTbSize = 20;
    static const size_t kMaxTbs = 25;
    if (!plan || !commandHeaderLength || !txCommandLength ||
        macHeaderLength < kMacHeaderLength || segmentCount == 0 ||
        !segmentLengths || segmentCount + 2 > kMaxTbs ||
        frameByteCount < macHeaderLength || frameByteCount > 0xffff)
        return false;

    size_t commandBytes = commandHeaderLength + txCommandLength + macHeaderLength;
    if (commandBytes <= kFirstTbSize)
        return false;
    size_t tail = commandBytes - kFirstTbSize;
    tail = (tail + 3) & ~size_t(3);
    if (tail > 0xffff)
        return false;
    for (size_t i = 0; i < segmentCount; ++i) {
        if (segmentLengths[i] == 0)
            return false;
    }

    plan->numTbs = static_cast<uint16_t>(2 + segmentCount);
    plan->firstTbLength = static_cast<uint16_t>(kFirstTbSize);
    plan->commandTailLength = static_cast<uint16_t>(tail);
    plan->payloadSegmentCount = static_cast<uint16_t>(segmentCount);
    plan->frameByteCount = static_cast<uint16_t>(frameByteCount);
    return true;
}

} // namespace IntelP2PActionFrame
