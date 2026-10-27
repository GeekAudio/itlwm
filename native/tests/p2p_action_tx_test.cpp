// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_action_tx.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace IntelP2PActionTx;
static void put16(uint8_t *p, uint16_t n)
{ p[0] = uint8_t(n); p[1] = uint8_t(n >> 8); }
static void put32(uint8_t *p, uint32_t n)
{ for (unsigned i = 0; i != 4; ++i) p[i] = uint8_t(n >> (i * 8)); }
static void makeResponse(uint8_t p[48], uint16_t status = 1,
                         uint16_t queue = 12, uint16_t sequence = 0x40,
                         uint32_t next = 9, uint16_t byteCount = 100,
                         uint16_t frameControl = 0x00d0)
{
    memset(p, 0, 48);
    p[0] = 1; put16(p + 28, sequence); put16(p + 30, byteCount);
    put16(p + 34, frameControl); put16(p + 36, queue);
    put16(p + 40, status); put32(p + 44, next);
}

static Result complete(CompletionTracker *tracker, uint32_t generation,
                       const uint8_t *response, size_t length)
{
    return tracker->complete(generation, response, length,
                              40, 28, 30, 34, 36, 44);
}

int main()
{
    uint8_t response[48];
    uint16_t extractedQueue = 0;
    makeResponse(response, 1, 511);
    for (size_t n = 0; n < 38; ++n)
        assert(!extractTxResponseQueueId(response, n, 36, &extractedQueue));
    assert(extractTxResponseQueueId(response, 38, 36, &extractedQueue));
    assert(extractedQueue == 511); // fw68 qid is a little-endian 16-bit field
    assert(!extractTxResponseQueueId(nullptr, sizeof(response), 36,
                                     &extractedQueue));
    assert(!extractTxResponseQueueId(response, sizeof(response), 36, nullptr));
    assert(!extractTxResponseQueueId(response, sizeof(response), SIZE_MAX - 1,
                                     &extractedQueue));

    uint32_t actionRate = 0xffffffffU;
    assert(encodeLegacyOfdmRateV2(4, 4, 0x02, 3, 14, 1U << 8,
                                  &actionRate));
    assert((actionRate & 0xff) == 0); // 6 Mbps is OFDM-relative index zero
    assert((actionRate & (1U << 8)) != 0); // legacy OFDM modulation
    assert((actionRate & (7U << 14)) == (2U << 14)); // only antenna 1
    assert(!encodeLegacyOfdmRateV2(4, 4, 0, 3, 14, 1U << 8, &actionRate));

    // A proven hard-stop drain can retire an empty ticket idempotently,
    // including the same generation. Zero is never a drain generation.
    CompletionTracker emptyDrain;
    assert(emptyDrain.firmwareDrained(0) == Result::kInvalid);
    assert(emptyDrain.firmwareDrained(7) == Result::kReady);
    assert(emptyDrain.firmwareDrained(7) == Result::kReady);
    assert(!emptyDrain.snapshot().armed && !emptyDrain.snapshot().completed);

    // An in-flight descriptor still requires a changed nonzero generation.
    CompletionTracker inFlightDrain;
    assert(inFlightDrain.arm(7, 12, 8, 0, 0x40, 100, 0x00d0) ==
           Result::kReady);
    assert(inFlightDrain.firmwareDrained(7) == Result::kInvalid);
    assert(inFlightDrain.snapshot().armed &&
           !inFlightDrain.snapshot().completed);
    assert(inFlightDrain.firmwareDrained(8) == Result::kReady);
    assert(!inFlightDrain.snapshot().armed);

    // A completed ticket has no live DMA ownership and is also retired by a
    // hard-stop drain without requiring another generation transition.
    CompletionTracker completedDrain;
    assert(completedDrain.arm(7, 12, 8, 0, 0x40, 100, 0x00d0) ==
           Result::kReady);
    makeResponse(response);
    assert(complete(&completedDrain, 7, response, sizeof(response)) ==
           Result::kCompletion);
    assert(completedDrain.firmwareDrained(7) == Result::kReady);
    assert(!completedDrain.snapshot().armed &&
           !completedDrain.snapshot().completed);

    CompletionTracker t;
    assert(t.arm(7, 12, 8, 0, 0x40, 100, 0x00d0) == Result::kReady);
    assert(complete(&t, 6, response, sizeof(response)) == Result::kStaleGeneration);
    makeResponse(response);
    assert(complete(&t, 7, response, sizeof(response)) == Result::kCompletion);
    auto done = t.snapshot();
    assert(done.completed && done.frameAttemptSucceeded && !done.peerAcknowledged);
    assert(t.arm(7, 511, 256, 255, 0xfff0, 120, 0x00d0) == Result::kReady);

    // A ticket may be disarmed only with exact identity and direct proof that
    // the doorbell was never written. This is not a timeout/drain shortcut.
    CompletionTracker unsubmitted;
    assert(unsubmitted.arm(21, 12, 8, 3, 0x30, 72, 0x00d0) == Result::kReady);
    assert(unsubmitted.cancelUnsubmitted(20, 12, 3) == Result::kStaleGeneration);
    assert(unsubmitted.cancelUnsubmitted(21, 13, 3) == Result::kWrongQueue);
    assert(unsubmitted.cancelUnsubmitted(21, 12, 4) == Result::kWrongDescriptor);
    assert(unsubmitted.snapshot().armed && !unsubmitted.snapshot().completed);
    assert(unsubmitted.cancelUnsubmitted(21, 12, 3) == Result::kCancelled);
    assert(!unsubmitted.snapshot().armed && !unsubmitted.snapshot().completed);
    assert(unsubmitted.cancelUnsubmitted(21, 12, 3) == Result::kBusy);

    CompletionTracker completedCannotCancel;
    assert(completedCannotCancel.arm(21, 12, 8, 3, 0x30, 72, 0x00d0) ==
           Result::kReady);
    makeResponse(response, 1, 12, 0x30, 4, 72, 0x00d0);
    assert(complete(&completedCannotCancel, 21, response, sizeof(response)) ==
           Result::kCompletion);
    assert(completedCannotCancel.cancelUnsubmitted(21, 12, 3) == Result::kBusy);
    assert(completedCannotCancel.snapshot().completed);

    CompletionTracker quarantinedCannotCancel;
    assert(quarantinedCannotCancel.arm(21, 12, 8, 3, 0x30, 72, 0x00d0) ==
           Result::kReady);
    makeResponse(response, 1, 13, 0x30, 4, 72, 0x00d0);
    assert(complete(&quarantinedCannotCancel, 21, response,
                    sizeof(response)) == Result::kWrongQueue);
    assert(quarantinedCannotCancel.cancelUnsubmitted(21, 12, 3) ==
           Result::kBusy);

    CompletionTracker wrongQid;
    wrongQid.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 1, 13);
    assert(complete(&wrongQid, 7, response, sizeof(response)) == Result::kWrongQueue);
    assert(wrongQid.arm(8, 12, 8, 1, 0x50, 100, 0x00d0) == Result::kBusy);
    assert(wrongQid.firmwareDrained(8) == Result::kReady);

    CompletionTracker wrongIndex;
    wrongIndex.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 1, 12, 0x40, 10);
    assert(complete(&wrongIndex, 7, response, sizeof(response)) == Result::kWrongDescriptor);
    assert(wrongIndex.firmwareDrained(8) == Result::kReady);

    CompletionTracker changedFrameSequence;
    changedFrameSequence.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 1, 12, 0x42);
    assert(complete(&changedFrameSequence, 7, response, sizeof(response)) == Result::kCompletion);
    assert(changedFrameSequence.snapshot().sequenceControl == 0x40);

    CompletionTracker failedFrameSequence;
    failedFrameSequence.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 3, 12, 0);
    assert(complete(&failedFrameSequence, 7, response, sizeof(response)) == Result::kFrameFailed);
    assert(failedFrameSequence.snapshot().completed);
    assert(!failedFrameSequence.snapshot().frameAttemptSucceeded);

    // A differing frame sequence cannot hide an incorrect scheduler position.
    CompletionTracker changedSequenceWrongSlot;
    changedSequenceWrongSlot.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 3, 12, 0, 10);
    assert(complete(&changedSequenceWrongSlot, 7, response, sizeof(response)) == Result::kWrongDescriptor);
    assert(!changedSequenceWrongSlot.snapshot().completed);

    CompletionTracker failed;
    failed.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 3);
    assert(complete(&failed, 7, response, sizeof(response)) == Result::kFrameFailed);
    assert(failed.snapshot().completed && !failed.snapshot().frameAttemptSucceeded);

    CompletionTracker wrongLength;
    wrongLength.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 1, 12, 0x40, 9, 99);
    assert(complete(&wrongLength, 7, response, sizeof(response)) == Result::kWrongLength);
    assert(wrongLength.firmwareDrained(8) == Result::kReady);

    CompletionTracker wrongFc;
    wrongFc.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response, 1, 12, 0x40, 9, 100, 0x00c0);
    assert(complete(&wrongFc, 7, response, sizeof(response)) == Result::kWrongFrameControl);
    assert(wrongFc.firmwareDrained(8) == Result::kReady);

    for (size_t n = 0; n < sizeof(response); ++n) {
        CompletionTracker shortResponse;
        shortResponse.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
        assert(complete(&shortResponse, 7, response, n) == Result::kMalformedResponse);
    }
    CompletionTracker invalidCount;
    invalidCount.arm(7, 12, 8, 0, 0x40, 100, 0x00d0);
    makeResponse(response); response[0] = 2;
    assert(complete(&invalidCount, 7, response, sizeof(response)) == Result::kMalformedResponse);
    assert(invalidCount.firmwareDrained(8) == Result::kReady);

    using namespace IntelP2PActionFrame;
    const uint8_t source[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t vendorPayload[] = "ITL-P2P-PROBE";
    uint8_t frame[128];
    size_t frameLength = 0;
    assert(encodeVendorSpecificAction(source, 0x123, vendorPayload,
                                      sizeof(vendorPayload) - 1, frame,
                                      sizeof(frame), &frameLength));
    assert(frameLength == 24 + 4 + sizeof(vendorPayload) - 1);
    assert(frame[0] == 0xd0 && frame[1] == 0);
    for (unsigned i = 4; i < 10; ++i) assert(frame[i] == 0xff);
    assert(memcmp(frame + 10, source, sizeof(source)) == 0);
    for (unsigned i = 16; i < 22; ++i) assert(frame[i] == 0xff);
    assert(frame[22] == 0x30 && frame[23] == 0x12);
    assert(frame[24] == kVendorSpecificCategory);
    assert(memcmp(frame + 25, source, 3) == 0);
    assert(memcmp(frame + 28, vendorPayload, sizeof(vendorPayload) - 1) == 0);

    FrameInfo info{};
    assert(inspectActionFrame(frame, frameLength, source, &info));
    assert(info.headerLength == kMacHeaderLength);
    assert(info.frameControl == 0x00d0 && info.sequenceControl == 0x1230);
    assert(info.category == kVendorSpecificCategory);
    const uint8_t wrongSource[6] = {0x02, 1, 2, 3, 4, 6};
    assert(!inspectActionFrame(frame, frameLength, wrongSource, &info));

    uint8_t ordered[132];
    memcpy(ordered, frame, 24);
    memset(ordered + 24, 0, 4); // HT Control
    memcpy(ordered + 28, frame + 24, frameLength - 24);
    ordered[1] |= 0x80;
    assert(inspectActionFrame(ordered, frameLength + 4, source, &info));
    assert(info.headerLength == kMacHeaderWithHtControlLength);
    assert(info.category == kVendorSpecificCategory);
    ordered[1] |= 0x40;
    assert(!inspectActionFrame(ordered, frameLength + 4, source, &info));

    const uint16_t payloadSegments[] = {17};
    TfdPlan plan{};
    assert(buildTfdPlan(4, 20, 24, payloadSegments, 1,
                        frameLength, &plan));
    assert(plan.numTbs == 3 && plan.firstTbLength == 20 &&
           plan.commandTailLength == 28 && plan.frameByteCount == frameLength);
    assert(buildTfdPlan(4, 28, 24, payloadSegments, 1,
                        frameLength, &plan));
    assert(plan.commandTailLength == 36); // AX210+ gen3 command shape
    assert(buildTfdPlan(4, 20, 28, payloadSegments, 1,
                        frameLength + 4, &plan));
    assert(plan.commandTailLength == 32); // Order adds 4-byte HT Control
    assert(!buildTfdPlan(4, 20, 24, nullptr, 0, frameLength, &plan));

    assert(t.snapshot().peerAcknowledged == false);
    puts("P2P Action encoder, fw68 descriptor, and TX response tests passed");
}
