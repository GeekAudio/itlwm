// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "native/iwx_roc_rx_correlation.hpp"

using namespace NativeIwxRocRxCorrelation;
using NativeIwxCompletionObserver::CopyResult;
using NativeIwxCompletionObserver::CopyStatus;

static uint16_t get16(const uint8_t *bytes, size_t offset)
{
    return static_cast<uint16_t>(bytes[offset]) |
        static_cast<uint16_t>(uint16_t(bytes[offset + 1]) << 8);
}

static uint32_t get32(const uint8_t *bytes, size_t offset)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= uint32_t(bytes[offset + i]) << (i * 8);
    return value;
}

static uint64_t get64(const uint8_t *bytes, size_t offset)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= uint64_t(bytes[offset + i]) << (i * 8);
    return value;
}

static RocEpoch epoch()
{
    RocEpoch value;
    value.contextGeneration = 6;
    value.powerGeneration = 11;
    value.stationGeneration = 23;
    value.rocGeneration = 6;
    value.sessionToken = 6;
    return value;
}

static CopyResult copied(uint8_t seed = 0)
{
    CopyResult value;
    value.status = CopyStatus::kCopied;
    value.snapshot.incarnation = 9;
    for (unsigned i = 0; i < NativeIwxCompletionObserver::kCompletionBytes; ++i)
        value.snapshot.bytes[i] = static_cast<uint8_t>(seed + i);
    return value;
}

static SlotInput slot(uint32_t ringSlot, uint64_t timeUs)
{
    SlotInput value;
    value.captureSerial = 1;
    value.driverGeneration = 7;
    value.ring = 0;
    value.slot = ringSlot;
    value.head = (ringSlot + 1) % 512;
    value.copyTimeUs = timeUs;
    value.copySequence = ringSlot + 1;
    value.epoch = epoch();
    return value;
}

static bool start(Recorder &recorder, uint64_t startUs = 100,
                  uint64_t deadlineUs = 10000)
{
    return recorder.arm(1, 7, 50) &&
        recorder.beginRoc(epoch(), startUs, deadlineUs);
}

static void testBeaconSlotSurvivesLaterTrafficAndEndFreeze()
{
    Recorder recorder;
    assert(start(recorder));
    CopyResult completion = copied(0x10);
    SlotInput beaconInput = slot(188, 120);
    beaconInput.copySequence = 66;
    Token beacon = recorder.beginSlot(beaconInput, completion);
    assert(beacon.valid);

    Notification notification;
    notification.qid = 137;
    notification.index = 234;
    notification.outcome = static_cast<uint8_t>(
        NotificationOutcome::kMpduDispatch);
    notification.code = 0x00010004;
    notification.packetOffset = 0;
    notification.payloadLength = 356;
    notification.packetLength = 368;
    assert(recorder.recordNotification(beacon, notification));

    Mpdu mpdu;
    mpdu.presence = kChannelPresent | kRawMacPhyPresent |
        kDecodeModePresent | kFrameControlPresent |
        kSequenceControlPresent | kRawStatusPresent |
        kMpduLengthPresent | kDescriptorSizePresent | kHostTimePresent;
    mpdu.channel = 149;
    mpdu.rawMacPhyIndex = 0x11;
    mpdu.decodeMode = 2;
    mpdu.frameControl = 0xa187;
    mpdu.sequenceControl = 14704;
    mpdu.rawStatus = 4123;
    mpdu.mpduLength = 287;
    mpdu.descriptorSize = 64;
    mpdu.qid = 137;
    mpdu.index = 234;
    mpdu.hostRxMonotonicUs = 121;
    assert(recorder.recordMpdu(beacon, mpdu));

    // The actual end notification belongs to this open slot. Its numeric
    // notification is accepted before close; finalization may follow close.
    notification.outcome = static_cast<uint8_t>(NotificationOutcome::kNonMpdu);
    notification.code = 0x000100fb;
    assert(recorder.recordNotification(beacon, notification));
    assert(recorder.endRoc(epoch(), 130));
    assert(recorder.state() == State::kClosed);
    assert(recorder.closeReason() == CloseReason::kEnd);
    assert(!recorder.encode(nullptr, 0));

    SlotInput sta = slot(189, 131);
    for (uint32_t i = 0; i < 299; ++i) {
        sta.slot = (189 + i) % 512;
        sta.head = (sta.slot + 1) % 512;
        sta.copyTimeUs = 131 + i;
        assert(!recorder.beginSlot(sta, completion).valid);
    }
    // The old token can be finalized, while all other closed-window writes
    // are rejected and cannot overwrite its same-copy completion bytes.
    assert(!recorder.recordMpdu(beacon, mpdu));
    assert(recorder.finishSlot(beacon));
    assert(!recorder.finishSlot(beacon));
    assert(recorder.retained() == 1);
    assert(recorder.overflow() == 0);
    assert(recorder.invalid() == 1); // An in-flight late metadata write is explicit.
    assert(!recorder.coverageComplete());
    assert(recorder.readyToEncode());

    uint8_t wire[kWireBytes];
    assert(recorder.encode(wire, sizeof(wire)));
    assert(wire[0] == 'I' && wire[7] == '1');
    assert(get32(wire, 8) == 1);
    assert(get32(wire, 12) == kHeaderBytes);
    assert(get32(wire, 16) == kRecordBytes);
    assert(get32(wire, 20) == kCapacity);
    assert(get32(wire, 24) == static_cast<uint32_t>(State::kClosed));
    assert(get32(wire, 28) == static_cast<uint32_t>(CloseReason::kEnd));
    assert(get32(wire, 96) == 1 && get32(wire, 100) == 1);
    assert(get32(wire, 104) == 0 && get32(wire, 108) == 0);
    assert(get32(wire, 112) == 1 && get32(wire, 116) == 0);
    assert(get32(wire, 120) == 0 && get32(wire, 124) == 1);

    const size_t row = kHeaderBytes;
    assert(get64(wire, row) == 1);
    assert(get64(wire, row + 8) == 120);
    assert(get64(wire, row + 16) == 9);
    assert(get32(wire, row + 24) == 1);
    assert(get32(wire, row + 28) == 7);
    assert(get16(wire, row + 32) == 0);
    assert(get16(wire, row + 34) == 188);
    assert(get16(wire, row + 36) == 189);
    assert((get16(wire, row + 38) & 0x0bu) == 0x0bu);
    assert((get16(wire, row + 38) & (1u << 2)) == 0);
    assert(get32(wire, row + 40) == static_cast<uint32_t>(CopyStatus::kCopied));
    for (unsigned i = 0; i < 8; ++i)
        assert(wire[row + 44 + i] == 0x10 + i);
    assert(wire[row + 52] == 2);
    assert(wire[row + 56] == 137 && wire[row + 57] == 234);
    assert(wire[row + 58] == static_cast<uint8_t>(NotificationOutcome::kMpduDispatch));
    assert(wire[row + 72 + 2] == static_cast<uint8_t>(NotificationOutcome::kNonMpdu));
    assert(get32(wire, row + 120) == mpdu.presence);
    assert(wire[row + 124] == 149);
    assert(wire[row + 125] == 0x11);
    assert(wire[row + 126] == 2);
    assert(get16(wire, row + 128) == 0xa187);
    assert(get16(wire, row + 130) == 14704);
    assert(get16(wire, row + 132) == 287);
    assert(get16(wire, row + 134) == 64);
    assert(wire[row + 138] == 137 && wire[row + 139] == 234);
    assert(get32(wire, row + 140) == 4123);
    assert(get64(wire, row + 144) == 121);
    assert(get32(wire, row + 152) == 66);

    uint8_t repeated[kWireBytes];
    assert(recorder.encode(repeated, sizeof(repeated)));
    for (size_t i = 0; i < sizeof(wire); ++i)
        assert(wire[i] == repeated[i]);
    assert(!recorder.beginRoc(epoch(), 140, 200));
}

static void testCapacityIsAppendOnlyAndOverflowIsSticky()
{
    Recorder recorder;
    assert(start(recorder));
    CopyResult completion = copied();
    Token tokens[kCapacity];
    for (uint32_t i = 0; i < kCapacity; ++i) {
        SlotInput input = slot(i, 120 + i);
        tokens[i] = recorder.beginSlot(input, completion);
        assert(tokens[i].valid);
        assert(recorder.finishSlot(tokens[i]));
    }
    SlotInput overflowInput = slot(64, 200);
    assert(!recorder.beginSlot(overflowInput, completion).valid);
    assert(recorder.fullSlots() == 65);
    assert(recorder.retained() == kCapacity);
    assert(recorder.overflow() == 1);
    assert(!recorder.coverageComplete());
    assert(recorder.endRoc(epoch(), 250));

    uint8_t wire[kWireBytes];
    assert(recorder.encode(wire, sizeof(wire)));
    assert(get32(wire, 96) == 65);
    assert(get32(wire, 100) == kCapacity);
    assert(get32(wire, 104) == 1);
    assert(get32(wire, 120) == 0);
    assert(get16(wire, kHeaderBytes + 34) == 0);
    const size_t last = kHeaderBytes + (kCapacity - 1) * kRecordBytes;
    assert(get16(wire, last + 34) == 63);
}

static void testCompletionSkipAndNotificationOverflowAreExplicit()
{
    Recorder recorder;
    assert(start(recorder));
    CopyResult unavailable;
    unavailable.status = CopyStatus::kBusy;
    Token token = recorder.beginSlot(slot(1, 120), unavailable);
    assert(token.valid);
    Notification note;
    note.outcome = static_cast<uint8_t>(NotificationOutcome::kSeen);
    const uint8_t outcomes[kNotificationsPerSlot] = {
        static_cast<uint8_t>(NotificationOutcome::kSeen),
        static_cast<uint8_t>(NotificationOutcome::kAddbufFailed),
        static_cast<uint8_t>(NotificationOutcome::kCopyFailed),
        static_cast<uint8_t>(NotificationOutcome::kNoPacket)
    };
    for (uint32_t i = 0; i < kNotificationsPerSlot; ++i) {
        note.outcome = outcomes[i];
        assert(recorder.recordNotification(token, note));
    }
    note.outcome = static_cast<uint8_t>(NotificationOutcome::kSeen);
    assert(!recorder.recordNotification(token, note));
    assert(recorder.overflow() == 1);
    assert(recorder.copySkips() == 1);
    assert(recorder.setParseFlags(token, kParseValidated));
    assert(recorder.finishSlot(token));
    assert(recorder.endRoc(epoch(), 140));
    uint8_t wire[kWireBytes];
    assert(recorder.encode(wire, sizeof(wire)));
    const size_t row = kHeaderBytes;
    assert(get32(wire, 104) == 1);
    assert(get32(wire, 108) == 1);
    assert(get32(wire, 120) == 0);
    assert(get32(wire, row + 40) == static_cast<uint32_t>(CopyStatus::kBusy));
    assert((get16(wire, row + 38) & (1u << 1)) == 0);
    for (unsigned i = 0; i < 8; ++i)
        assert(wire[row + 44 + i] == 0);
    assert(wire[row + 52] == kNotificationsPerSlot);
    assert(wire[row + 53] == 1);
    assert(wire[row + 54] == kParseValidated);
    assert(wire[row + 56 + 2] == 1);
    assert(wire[row + 72 + 2] == 7);
    assert(wire[row + 88 + 2] == 8);
    assert(wire[row + 104 + 2] == 9);
}

static void testMissingCompletionSequenceIsNotACompleteJoin()
{
    Recorder recorder;
    assert(start(recorder));
    CopyResult completion = copied();
    SlotInput input = slot(1, 120);
    input.copySequence = 0;
    Token token = recorder.beginSlot(input, completion);
    assert(token.valid);
    assert(recorder.invalid() == 1);
    assert(!recorder.coverageComplete());
    assert(recorder.finishSlot(token));
    assert(recorder.endRoc(epoch(), 140));
    uint8_t wire[kWireBytes];
    assert(recorder.encode(wire, sizeof(wire)));
    assert(get32(wire, 112) == 1);
    assert(get32(wire, 120) == 0);
    assert(get32(wire, kHeaderBytes + 152) == 0);
}

static void testWrapGenerationClockStaleTokensAndFrozenStop()
{
    {
        Recorder recorder;
        assert(start(recorder));
        CopyResult completion = copied();
        Token beforeWrap = recorder.beginSlot(slot(511, 120), completion);
        assert(beforeWrap.valid && recorder.finishSlot(beforeWrap));
        Token afterWrap = recorder.beginSlot(slot(0, 121), completion);
        assert(afterWrap.valid && recorder.finishSlot(afterWrap));
        assert(recorder.endRoc(epoch(), 130));
        uint8_t wire[kWireBytes];
        assert(recorder.encode(wire, sizeof(wire)));
        assert(get16(wire, kHeaderBytes + 34) == 511);
        assert(get16(wire, kHeaderBytes + kRecordBytes + 34) == 0);
    }
    {
        Recorder recorder;
        assert(start(recorder));
        CopyResult completion = copied();
        Token first = recorder.beginSlot(slot(9, 120), completion);
        assert(first.valid && recorder.finishSlot(first));
        assert(!recorder.beginSlot(slot(10, 119), completion).valid);
        assert(recorder.state() == State::kClosed);
        assert(recorder.closeReason() == CloseReason::kInvalidBoundary);
        assert(recorder.invalid() == 1 && !recorder.coverageComplete());
        uint8_t wire[kWireBytes];
        assert(recorder.encode(wire, sizeof(wire)));
    }
    {
        Recorder recorder;
        assert(start(recorder));
        CopyResult completion = copied();
        SlotInput mismatched = slot(2, 120);
        mismatched.driverGeneration = 8;
        assert(!recorder.beginSlot(mismatched, completion).valid);
        assert(recorder.closeReason() == CloseReason::kGenerationChanged);
        assert(recorder.invalid() == 1);
    }
    {
        Recorder recorder;
        assert(start(recorder));
        CopyResult completion = copied();
        Token stale = recorder.beginSlot(slot(1, 120), completion);
        assert(stale.valid);
        Token foreign;
        {
            Recorder other;
            assert(start(other));
            foreign = other.beginSlot(slot(1, 120), completion);
            assert(foreign.valid);
            assert(!recorder.recordMpdu(foreign, Mpdu{}));
        }
        assert(recorder.invalid() == 1);
        assert(recorder.finishSlot(stale));
        assert(recorder.close(CloseReason::kStop, 130));
        assert(recorder.closeReason() == CloseReason::kStop);
        assert(!recorder.recordNotification(stale, Notification{}));
        assert(recorder.invalid() == 1);
        assert(!recorder.coverageComplete());
        uint8_t wire[kWireBytes];
        assert(recorder.encode(wire, sizeof(wire)));
    }
}

static void testEndFreezesOnlyAfterExistingTokenCompletes()
{
    Recorder recorder;
    assert(start(recorder));
    CopyResult completion = copied();
    Token token = recorder.beginSlot(slot(188, 120), completion);
    assert(token.valid);
    assert(recorder.endRoc(epoch(), 121));
    assert(recorder.unfinished() == 1);
    assert(!recorder.readyToEncode());
    Notification note;
    note.outcome = static_cast<uint8_t>(NotificationOutcome::kSeen);
    assert(!recorder.recordNotification(token, note));
    assert(recorder.finishSlot(token));
    assert(recorder.unfinished() == 0);
    assert(recorder.readyToEncode());
    assert(!recorder.coverageComplete()); // It closed with an open slot.
    uint8_t wire[kWireBytes];
    assert(recorder.encode(wire, sizeof(wire)));
    assert(get32(wire, 116) == 0);
    assert(get32(wire, 120) == 0);
}

static void testCleanEndCanFinalizeAnExistingToken()
{
    Recorder recorder;
    assert(start(recorder));
    CopyResult completion = copied();
    Token token = recorder.beginSlot(slot(188, 120), completion);
    assert(token.valid);
    Notification note;
    note.outcome = static_cast<uint8_t>(NotificationOutcome::kNonMpdu);
    note.code = 0x000100fb;
    assert(recorder.recordNotification(token, note));
    assert(recorder.endRoc(epoch(), 121));
    assert(!recorder.readyToEncode());
    assert(recorder.finishSlot(token));
    assert(recorder.coverageComplete());
    uint8_t wire[kWireBytes];
    assert(recorder.encode(wire, sizeof(wire)));
    assert(get32(wire, 112) == 0);
    assert(get32(wire, 116) == 0);
    assert(get32(wire, 120) == 1);
    const uint32_t invalidBefore = recorder.invalid();
    assert(!recorder.recordNotification(token, note));
    assert(recorder.invalid() == invalidBefore);
    uint8_t frozen[kWireBytes];
    assert(recorder.encode(frozen, sizeof(frozen)));
    for (size_t i = 0; i < sizeof(wire); ++i)
        assert(wire[i] == frozen[i]);
}

static void testNoStartAndEmptySuccessfulWindowPublishExplicitly()
{
    {
        Recorder recorder;
        assert(recorder.arm(1, 7, 50));
        assert(recorder.closeNoStart(60));
        assert(recorder.state() == State::kClosed);
        assert(recorder.closeReason() == CloseReason::kNoStart);
        assert(recorder.retained() == 0 && !recorder.coverageComplete());
        uint8_t wire[kWireBytes];
        assert(recorder.encode(wire, sizeof(wire)));
        assert(get32(wire, 100) == 0);
        assert(get32(wire, 28) == static_cast<uint32_t>(CloseReason::kNoStart));
    }
    {
        Recorder recorder;
        assert(recorder.arm(1, 7, 50));
        assert(recorder.close(CloseReason::kStop, 60));
        assert(recorder.closeReason() == CloseReason::kStop);
        assert(!recorder.coverageComplete());
        uint8_t wire[kWireBytes];
        assert(recorder.encode(wire, sizeof(wire)));
        assert(get32(wire, 28) == static_cast<uint32_t>(CloseReason::kStop));
    }
    {
        Recorder recorder;
        assert(start(recorder));
        assert(recorder.endRoc(epoch(), 120));
        assert(recorder.retained() == 0 && recorder.coverageComplete());
        uint8_t wire[kWireBytes];
        assert(recorder.encode(wire, sizeof(wire)));
        assert(get32(wire, 120) == 1);
        assert(get32(wire, 124) == 0);
    }
}

int main()
{
    static_assert(kWireBytes < 16 * 1024, "wire buffer must remain bounded");
    testBeaconSlotSurvivesLaterTrafficAndEndFreeze();
    testCapacityIsAppendOnlyAndOverflowIsSticky();
    testCompletionSkipAndNotificationOverflowAreExplicit();
    testMissingCompletionSequenceIsNotACompleteJoin();
    testWrapGenerationClockStaleTokensAndFrozenStop();
    testEndFreezesOnlyAfterExistingTokenCompletes();
    testCleanEndCanFinalizeAnExistingToken();
    testNoStartAndEmptySuccessfulWindowPublishExplicitly();
    puts("PASS fixed ROC copy correlation, no-overwrite, overflow and close semantics");
    return 0;
}
