// SPDX-License-Identifier: GPL-2.0-only
#include "../intel_p2p_rx_router.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>

using namespace IntelP2PRx;

static void appendTlv(std::vector<uint8_t> &frame, uint8_t type,
                      const std::vector<uint8_t> &value)
{
    frame.push_back(type);
    frame.push_back(static_cast<uint8_t>(value.size()));
    frame.push_back(static_cast<uint8_t>(value.size() >> 8));
    frame.insert(frame.end(), value.begin(), value.end());
}

static std::vector<uint8_t> zeros(size_t count)
{
    return std::vector<uint8_t>(count, 0);
}

static std::vector<uint8_t> legacyDataPathState()
{
    return {0x24, 0x8f, 'X', '0', 0, 0x01, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
}

static std::vector<uint8_t> validPsf(bool includeContainer = false,
                                    uint8_t subtype = 0)
{
    std::vector<uint8_t> frame(24, 0);
    frame[0] = 0xd0;
    const uint8_t action[] = {
        127, 0x00, 0x17, 0xf2, 8, 0x10, subtype, 0,
        4, 3, 2, 1, 8, 7, 6, 5
    };
    frame.insert(frame.end(), action, action + sizeof(action));
    appendTlv(frame, 4, zeros(31));
    appendTlv(frame, 5, zeros(21));
    std::vector<uint8_t> channelSequence = {15, 0, 0, 3, 0xff, 0xff};
    channelSequence.insert(channelSequence.end(), 16, 6);
    channelSequence.insert(channelSequence.end(), 3, 0);
    appendTlv(frame, 18, channelSequence);
    if (subtype == 3)
        appendTlv(frame, 16, {3, 1, 'p', 0xc0, 0x0c});
    appendTlv(frame, 24, zeros(40));
    appendTlv(frame, 6, zeros(9));
    appendTlv(frame, 7, zeros(8));
    if (includeContainer)
        appendTlv(frame, 17, {0x7f, 0x00, 0xa5, 0x5a});
    appendTlv(frame, 12, legacyDataPathState());
    appendTlv(frame, 21, {0x10, 1});
    return frame;
}

static void putLe32(uint8_t *p, uint32_t value)
{
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8);
    p[2] = static_cast<uint8_t>(value >> 16);
    p[3] = static_cast<uint8_t>(value >> 24);
}

static std::vector<uint8_t> timeEvent(uint32_t uid, uint32_t mac,
                                      uint32_t action, uint32_t status)
{
    std::vector<uint8_t> raw(kTimeEventNotificationBytes, 0);
    putLe32(raw.data() + 0, 0x11223344);
    putLe32(raw.data() + 4, 0x55667788);
    putLe32(raw.data() + 8, uid);
    putLe32(raw.data() + 12, mac);
    putLe32(raw.data() + 16, action);
    putLe32(raw.data() + 20, status);
    return raw;
}

static LeaseSnapshot activeLease()
{
    LeaseSnapshot lease{};
    lease.contextGeneration = 91;
    lease.powerGeneration = 7;
    lease.stationGeneration = 11;
    lease.currentContextGeneration = 91;
    lease.currentPowerGeneration = 7;
    lease.currentStationGeneration = 11;
    lease.macIdAndColor = 0x0000a301;
    lease.timeEventUid = 0; // UID zero is legal when the known bit is set.
    lease.active = true;
    lease.timeEventSubmitted = true;
    lease.timeEventUidKnown = true;
    return lease;
}

static void testTimeEventBoundsAndIdentity()
{
    Router router;
    LeaseSnapshot lease = activeLease();
    std::vector<uint8_t> raw = timeEvent(0, lease.macIdAndColor, 1, 0);

    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kCapturedExact);
    Record record{};
    assert(router.popRecord(&record));
    assert(record.kind == RecordKind::kTimeEvent);
    assert(record.payload.timeEvent.generation == 91);
    assert(record.payload.timeEvent.uniqueId == 0);
    assert(record.payload.timeEvent.rawStatus == 0);
    assert(record.payload.timeEvent.action == TimeEventAction::kHostStart);
    assert(record.payload.timeEvent.uidCorrelation == UidCorrelation::kKnownExact);

    // Status is evidence only: both values route identically and are preserved.
    raw = timeEvent(0, lease.macIdAndColor, 2, 1);
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kCapturedExact);
    assert(router.popRecord(&record));
    assert(record.payload.timeEvent.rawStatus == 1);
    assert(record.payload.timeEvent.action == TimeEventAction::kHostEnd);

    assert(router.captureTimeEvent(raw.data(), raw.size() - 1, lease) ==
           RouteResult::kMalformed);
    raw = timeEvent(0, lease.macIdAndColor ^ 1, 2, 0);
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kForeignMacContext);
    raw = timeEvent(4, lease.macIdAndColor, 2, 0);
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kForeignUid);

    lease.currentPowerGeneration++;
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kStaleGeneration);
    lease.currentPowerGeneration--;
    lease.currentContextGeneration++;
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kStaleGeneration);
    lease.currentContextGeneration--;
    lease.timeEventSubmitted = false;
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kNotSubmitted);
}

static void testProvisionalUidAndUnknownAction()
{
    Router router;
    LeaseSnapshot lease = activeLease();
    lease.timeEventUidKnown = false;
    const std::vector<uint8_t> raw = timeEvent(0, lease.macIdAndColor, 0, 0);

    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kCapturedProvisionalUid);
    Record record{};
    assert(router.popRecord(&record));
    assert(record.payload.timeEvent.uniqueId == 0);
    assert(record.payload.timeEvent.uidCorrelation == UidCorrelation::kLearnCandidate);
    assert(record.payload.timeEvent.action == TimeEventAction::kOther);
    assert(record.payload.timeEvent.rawStatus == 0);
}

static void testActionFrameTapAndBounds()
{
    Router router;
    LeaseSnapshot lease = activeLease();
    // This bounded synthetic frame combines the legacy 0x8f24 data-path
    // flags with an opaque IEEE 802.11 container TLV.
    std::vector<uint8_t> frame = validPsf(true);
    putLe32(frame.data() + 24 + 8, 0x10203040u);
    putLe32(frame.data() + 24 + 12, 0x50607080u);
    Record record{};
    NativeAwdlRxTrace::EventToken traceToken{
        19, 23, 91,
        {91, 7, 11, 91}, 3, 1, 1
    };
    ParseObservation parseObservation{};

    assert(router.tapActionFrame(frame.data(), frame.size(), false, 6, false, 0,
                                 lease, 1234567, 0x78563412u, true,
                                 &traceToken, &parseObservation) ==
           RouteResult::kCapturedUnknownContext);
    assert(parseObservation.attempted == 1 &&
           parseObservation.resultPresent == 1);
    assert(parseObservation.status == NativeAwdl::ParseStatus::Ok);
    assert(parseObservation.actionInfoPresent == 1);
    assert(parseObservation.subtypePresent == 1 &&
           parseObservation.subtype == 0);
    assert(parseObservation.actionInfo.phyTx == 0x10203040u);
    assert(parseObservation.actionInfo.targetTx == 0x50607080u);
    Counters counters{};
    router.readCounters(&counters);
    assert(counters.actionFrameCaptured == 1);
    assert(router.popRecord(&record));
    assert(record.kind == RecordKind::kActionFrame);
    assert(record.payload.actionFrame.affinity == RxMacAffinity::kContextUnknown);
    assert(record.payload.actionFrame.generation == lease.contextGeneration);
    assert(record.payload.actionFrame.powerGeneration == lease.powerGeneration);
    assert(record.payload.actionFrame.stationGeneration == lease.stationGeneration);
    assert(record.payload.actionFrame.rxMonotonicUs == 1234567);
    assert(record.payload.actionFrame.rxGp2TimestampPresent);
    assert(record.payload.actionFrame.rxGp2TimestampUs == 0x78563412u);
    assert(record.payload.actionFrame.length == frame.size());
    assert(record.payload.actionFrame.traceToken.eventSerial == 19);
    assert(record.payload.actionFrame.traceToken.queueSerial == 23);
    assert(record.payload.actionFrame.traceToken.sourceOrdinal == 3);
    assert(record.payload.actionFrame.traceToken.epochs.rocGeneration == 91);
    assert(memcmp(record.payload.actionFrame.bytes, frame.data(), frame.size()) == 0);
    assert(record.payload.actionFrame.awdl.subtype == 0);

    std::vector<uint8_t> malformedAwdl = frame;
    malformedAwdl[41] = 0xff; // First TLV extends beyond the complete MPDU.
    malformedAwdl[42] = 0xff;
    assert(router.tapActionFrame(malformedAwdl.data(), malformedAwdl.size(),
                                 false, 6, false, 0, lease, 1234568) ==
           RouteResult::kNotAwdlAction);
    std::vector<uint8_t> unrelated = frame;
    unrelated[25] = 0x01; // Another vendor must not enter AWDL diagnostics.
    assert(router.tapActionFrame(unrelated.data(), unrelated.size(), false, 6,
                                 false, 0, lease, 1234569) ==
           RouteResult::kNotAwdlAction);
    router.readCounters(&counters);
    assert(counters.actionEnvelopeSeen == 2);
    assert(counters.actionParseRejected == 1);
    assert(counters.lastActionParseStatus ==
           static_cast<uint32_t>(NativeAwdl::ParseStatus::InvalidTlv));
    assert(counters.actionRejectReason ==
           static_cast<uint32_t>(NativeAwdl::TlvRejectReason::LengthOverrun));
    assert(counters.actionSubtype == 0 && counters.actionTlvType == 4);
    assert(counters.actionRxChannel == 6);
    assert(counters.actionTlvOffset == 40 && counters.actionTlvDeclaredLen == 65535);
    assert(counters.actionTlvAvailableLen == frame.size() - 43);
    assert(counters.actionTraceCount == 1 && counters.actionTypeTraceLo == 4 &&
           counters.actionTypeTraceHi == 0);
    assert(counters.actionFrameCaptured == 1);
    assert(counters.actionGp2TimestampPresentCount == 1);
    assert(counters.lastActionGp2TimestampPresent == 1);
    assert(counters.lastActionGp2TimestampUs == 0x78563412u);
    assert(!router.popRecord(&record));

    assert(router.tapActionFrame(frame.data(), frame.size(), false, 6, true,
                                 lease.macIdAndColor, lease, 1234569,
                                 0xaabbccddu, true) ==
           RouteResult::kCapturedExact);
    router.readCounters(&counters);
    assert(counters.actionFrameCaptured == 2);
    assert(router.popRecord(&record));
    assert(record.payload.actionFrame.affinity == RxMacAffinity::kP2pDevice);
    assert(record.payload.actionFrame.rxGp2TimestampPresent);
    assert(record.payload.actionFrame.rxGp2TimestampUs == 0xaabbccddu);

    // An absent descriptor value is explicit and cannot reuse the previous
    // frame's raw GP2 value in either the record or numeric counters.
    assert(router.tapActionFrame(frame.data(), frame.size(), false, 6, false,
                                 0, lease, 1234570, 0xdeadbeefu, false) ==
           RouteResult::kCapturedUnknownContext);
    assert(router.popRecord(&record));
    assert(!record.payload.actionFrame.rxGp2TimestampPresent);
    assert(record.payload.actionFrame.rxGp2TimestampUs == 0);
    router.readCounters(&counters);
    assert(counters.actionGp2TimestampPresentCount == 2);
    assert(counters.lastActionGp2TimestampPresent == 0);
    assert(counters.lastActionGp2TimestampUs == 0);

    assert(router.tapActionFrame(frame.data(), frame.size(), false, 6, true,
                                 lease.macIdAndColor ^ 1, lease) ==
           RouteResult::kForeignMacContext);
    assert(router.tapActionFrame(frame.data(), frame.size(), true, 6, false, 0,
                                 lease) == RouteResult::kProtectedFrame);

    std::vector<uint8_t> protectedFrame = frame;
    protectedFrame[1] |= 0x40;
    assert(router.tapActionFrame(protectedFrame.data(), protectedFrame.size(),
                                 false, 6, false, 0, lease) ==
           RouteResult::kProtectedFrame);

    std::vector<uint8_t> tooLarge(kMaxActionFrameBytes + 1, 0);
    assert(router.tapActionFrame(tooLarge.data(), tooLarge.size(), false, 6,
                                 false, 0, lease) == RouteResult::kTooLarge);
    lease.currentStationGeneration++;
    assert(router.tapActionFrame(frame.data(), frame.size(), false, 6, false, 0,
                                 lease) == RouteResult::kStaleGeneration);
}

static void testDataPathNumericDiagnosticsAndReset()
{
    Router router;
    const LeaseSnapshot lease = activeLease();
    const std::vector<uint8_t> original = validPsf();
    auto withDataPath = [&](const std::vector<uint8_t> &value) {
        size_t offset = 40;
        while (offset + 3 <= original.size()) {
            const size_t length = original[offset + 1] |
                (static_cast<size_t>(original[offset + 2]) << 8);
            assert(length <= original.size() - offset - 3);
            if (original[offset] == 12) {
                std::vector<uint8_t> result(original.begin(), original.begin() + offset);
                appendTlv(result, 12, value);
                result.insert(result.end(), original.begin() + offset + 3 + length,
                              original.end());
                return result;
            }
            offset += 3 + length;
        }
        assert(false);
        return std::vector<uint8_t>{};
    };
    auto reject = [&](const std::vector<uint8_t> &value) {
        const std::vector<uint8_t> frame = withDataPath(value);
        assert(router.tapActionFrame(frame.data(), frame.size(), false, 6, false,
                                     0, lease) == RouteResult::kNotAwdlAction);
        Counters out{};
        router.readCounters(&out);
        assert(out.actionTlvType == 12);
        assert(out.actionRejectReason ==
               static_cast<uint32_t>(NativeAwdl::TlvRejectReason::InvalidValue));
        return out;
    };
    Counters counters = reject({0x00, 0x01, 0x58, 0x30});
    assert(counters.actionDataPathFlagsPresent == 1);
    assert(counters.actionDataPathFlags == 0x0100);
    assert(counters.actionDataPathOffset == 2);
    assert(counters.actionDataPathRejectStage ==
           static_cast<uint32_t>(NativeAwdl::DataPathRejectStage::CountryCode));
    assert(counters.actionDataPathExtFlagsPresent == 0);
    assert(counters.actionDataPathOptionsLengthPresent == 0);

    counters = reject({0x00, 0x80, 0x00, 0x80});
    assert(counters.actionDataPathFlags == 0x8000);
    assert(counters.actionDataPathExtFlagsPresent == 1);
    assert(counters.actionDataPathExtFlags == 0x8000);
    assert(counters.actionDataPathOffset == 4);
    assert(counters.actionDataPathRejectStage ==
           static_cast<uint32_t>(NativeAwdl::DataPathRejectStage::UnsupportedExtFlags));

    counters = reject({0x00, 0x10, 0x05, 0x00, 0xaa, 0xbb});
    assert(counters.actionDataPathFlags == 0x1000);
    assert(counters.actionDataPathOptionsLengthPresent == 1);
    assert(counters.actionDataPathOptionsLength == 5);
    assert(counters.actionDataPathOffset == 4);
    assert(counters.actionDataPathRejectStage ==
           static_cast<uint32_t>(NativeAwdl::DataPathRejectStage::OptionsData));
    assert(counters.actionDataPathExtFlagsPresent == 0);
    assert(counters.actionDataPathExtFlags == 0);

    // A later rejection before type 12 must not retain old flags/lengths.
    std::vector<uint8_t> truncated = original;
    truncated[41] = 0xff;
    truncated[42] = 0xff;
    assert(router.tapActionFrame(truncated.data(), truncated.size(), false, 6,
                                 false, 0, lease) == RouteResult::kNotAwdlAction);
    router.readCounters(&counters);
    assert(counters.actionDataPathFlags == 0);
    assert(counters.actionDataPathExtFlags == 0);
    assert(counters.actionDataPathOptionsLength == 0);
    assert(counters.actionDataPathOffset == 0);
    assert(counters.actionDataPathFlagsPresent == 0);
    assert(counters.actionDataPathExtFlagsPresent == 0);
    assert(counters.actionDataPathOptionsLengthPresent == 0);
    assert(counters.actionDataPathRejectStage == 0);
}

static void testQueueIsBoundedAndDoesNotConsumeInput()
{
    Router router;
    LeaseSnapshot lease = activeLease();
    std::vector<uint8_t> raw = timeEvent(0, lease.macIdAndColor, 1, 0);
    for (size_t i = 0; i < kQueueDepth; ++i)
        assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
               RouteResult::kCapturedExact);
    assert(router.captureTimeEvent(raw.data(), raw.size(), lease) ==
           RouteResult::kQueueFull);
    Counters counters{};
    router.readCounters(&counters);
    assert(counters.timeEventCaptured == kQueueDepth);
    assert(counters.queueFull == 1);
    Record record{};
    for (size_t i = 0; i < kQueueDepth; ++i)
        assert(router.popRecord(&record));
    assert(!router.popRecord(&record));
}

static void testFiveFrameBurstAndQueueCapacity()
{
    Router router;
    const LeaseSnapshot lease = activeLease();
    Record record{};

    // A five-frame RX burst includes a MIF as its last record.
    for (size_t i = 0; i < 5; ++i) {
        const std::vector<uint8_t> frame = validPsf(false, i == 4 ? 3 : 0);
        assert(router.tapActionFrame(frame.data(), frame.size(), false, 6,
                                     false, 0, lease, 2000000 + i) ==
               RouteResult::kCapturedUnknownContext);
    }
    Counters counters{};
    router.readCounters(&counters);
    assert(counters.actionFrameCaptured == 5);
    assert(counters.queueFull == 0);
    for (size_t i = 0; i < 5; ++i) {
        assert(router.popRecord(&record));
        assert(record.kind == RecordKind::kActionFrame);
        assert(record.payload.actionFrame.rxMonotonicUs == 2000000 + i);
        assert(record.payload.actionFrame.awdl.subtype == (i == 4 ? 3 : 0));
    }
    assert(!router.popRecord(&record));

    // All 16 static slots are usable; the next record is rejected until pop.
    for (size_t i = 0; i < kQueueDepth; ++i) {
        const std::vector<uint8_t> frame = validPsf(false, i == 15 ? 3 : 0);
        assert(router.tapActionFrame(frame.data(), frame.size(), false, 6,
                                     false, 0, lease, 3000000 + i) ==
               RouteResult::kCapturedUnknownContext);
    }
    const std::vector<uint8_t> overflow = validPsf();
    assert(router.tapActionFrame(overflow.data(), overflow.size(), false, 6,
                                 false, 0, lease, 4000000) ==
           RouteResult::kQueueFull);
    router.readCounters(&counters);
    assert(counters.actionFrameCaptured == 5 + kQueueDepth);
    assert(counters.queueFull == 1);

    for (size_t i = 0; i < kQueueDepth; ++i)
        assert(router.popRecord(&record));
    assert(!router.popRecord(&record));
    assert(router.tapActionFrame(overflow.data(), overflow.size(), false, 6,
                                 false, 0, lease, 4000001) ==
           RouteResult::kCapturedUnknownContext);
    assert(router.popRecord(&record)); // Wrap-around slot is reusable.
    assert(record.payload.actionFrame.awdl.subtype == 0);
}

int main()
{
    testTimeEventBoundsAndIdentity();
    testProvisionalUidAndUnknownAction();
    testActionFrameTapAndBounds();
    testDataPathNumericDiagnosticsAndReset();
    testQueueIsBoundedAndDoesNotConsumeInput();
    testFiveFrameBurstAndQueueCapacity();
    return 0;
}
