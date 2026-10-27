// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_peer_observer.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>

using IntelAwdlPeer::ObserveResult;
using IntelAwdlPeer::Observer;
using IntelAwdlPeer::RuntimeEpochs;
using IntelAwdlPeer::Snapshot;
using IntelP2PRx::ActionFrameRecord;

static void putLe16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8);
}

static void appendTlv(std::vector<uint8_t> &frame, uint8_t type,
                      const std::vector<uint8_t> &value)
{
    assert(value.size() <= 0xffff);
    frame.push_back(type);
    frame.push_back(static_cast<uint8_t>(value.size()));
    frame.push_back(static_cast<uint8_t>(value.size() >> 8));
    frame.insert(frame.end(), value.begin(), value.end());
}

static std::vector<uint8_t> zeros(size_t length)
{
    return std::vector<uint8_t>(length, 0);
}

static std::vector<uint8_t> syncParams(uint16_t nextTu = 64,
                                      uint16_t awPeriodTu = 16,
                                      uint8_t presenceMode = 4)
{
    std::vector<uint8_t> value(31, 0);
    value[0] = 36;
    putLe16(value.data() + 1, nextTu);
    value[3] = 36;
    value[4] = 0; // Guard time.
    putLe16(value.data() + 5, awPeriodTu);
    putLe16(value.data() + 7, 110);
    putLe16(value.data() + 9, 0x1800);
    putLe16(value.data() + 11, 16);
    putLe16(value.data() + 13, 16);
    putLe16(value.data() + 15, 8);
    value[17] = value[18] = value[19] = value[20] = 3;
    const uint8_t privateMasterAddress[] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    memcpy(value.data() + 21, privateMasterAddress, sizeof(privateMasterAddress));
    value[27] = presenceMode;
    value[28] = 0;
    putLe16(value.data() + 29, 32);
    return value;
}

static std::vector<uint8_t> validFrame(uint8_t subtype,
                                      const uint8_t source[6],
                                      uint8_t version = 0x34,
                                      uint8_t deviceClass = 1,
                                      uint16_t nextTu = 64,
                                      uint16_t awPeriodTu = 16,
                                      uint8_t presenceMode = 4)
{
    std::vector<uint8_t> frame(24, 0);
    frame[0] = 0xd0; // Management Action.
    memcpy(frame.data() + 10, source, 6); // Addr2: transmitter identity.
    const uint8_t actionHeader[] = {
        127, 0x00, 0x17, 0xf2, 8, 0x10, subtype, 0,
        0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05
    };
    frame.insert(frame.end(), actionHeader, actionHeader + sizeof(actionHeader));

    appendTlv(frame, 4, syncParams(nextTu, awPeriodTu, presenceMode));
    appendTlv(frame, 5, zeros(21));
    std::vector<uint8_t> channels = {15, 0, 0, 3, 0xff, 0xff};
    channels.insert(channels.end(), 16, 36);
    channels.insert(channels.end(), 3, 0);
    appendTlv(frame, 18, channels);
    appendTlv(frame, 24, zeros(40));
    appendTlv(frame, 6, zeros(9));
    appendTlv(frame, 7, zeros(8));
    if (subtype == 3)
        appendTlv(frame, 16, {3, 1, 'p', 0xc0, 0x0c});
    appendTlv(frame, 12, {0, 0});
    appendTlv(frame, 21, {version, deviceClass});
    return frame;
}

static ActionFrameRecord makeRecord(uint8_t subtype, const uint8_t source[6],
                                    uint64_t contextGeneration,
                                    uint64_t powerGeneration,
                                    uint64_t stationGeneration,
                                    uint64_t rxMonotonicUs,
                                    uint16_t rxChannelIndex,
                                    uint8_t version = 0x34,
                                    uint8_t deviceClass = 1,
                                    uint16_t nextTu = 64,
                                    uint16_t awPeriodTu = 16,
                                    uint8_t presenceMode = 4)
{
    const std::vector<uint8_t> frame = validFrame(
        subtype, source, version, deviceClass, nextTu, awPeriodTu, presenceMode);
    assert(frame.size() <= IntelP2PRx::kMaxActionFrameBytes);
    ActionFrameRecord record{};
    record.generation = contextGeneration;
    record.powerGeneration = powerGeneration;
    record.stationGeneration = stationGeneration;
    record.rxMonotonicUs = rxMonotonicUs;
    record.channel = rxChannelIndex;
    record.length = static_cast<uint16_t>(frame.size());
    memcpy(record.bytes, frame.data(), frame.size());
    assert(NativeAwdl::parseActionFrame(record.bytes, record.length,
                                        &record.awdl) ==
           NativeAwdl::ParseStatus::Ok);
    return record;
}

static RuntimeEpochs activeEpochs()
{
    RuntimeEpochs epochs{};
    epochs.contextGeneration = 9;
    epochs.powerGeneration = 10;
    epochs.stationGeneration = 11;
    epochs.active = true;
    return epochs;
}

static void testMifAdmitsPeerAndPublishesOnlyNumericEvidence()
{
    const uint8_t source[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    Observer observer;
    RuntimeEpochs epochs = activeEpochs();

    ActionFrameRecord psf = makeRecord(0, source, 9, 10, 11, 1000000, 7);
    assert(observer.observe(psf, epochs, 1000100) == ObserveResult::kCandidateOnly);
    Snapshot snapshot = observer.snapshot(epochs, 1000200);
    assert(snapshot.validPeerCount == 0);
    assert(!snapshot.hasLatestPeer);

    ActionFrameRecord mif = makeRecord(3, source, 9, 10, 11, 1100000, 8);
    assert(observer.observe(mif, epochs, 1101000) == ObserveResult::kAdmittedPeer);
    snapshot = observer.snapshot(epochs, 1200000);
    assert(snapshot.validPeerCount == 1);
    assert(snapshot.hasLatestPeer);
    assert(snapshot.syncFieldsValid);
    assert(snapshot.rxChannelIndex == 8); // Driver channel index, not an IEEE channel.
    assert(snapshot.nextAwChannel == 36);
    assert(snapshot.masterChannel == 36);
    assert(snapshot.nextSlotTu == 64);
    assert(snapshot.awPeriodTu == 16);
    assert(snapshot.actionFramePeriodTu == 110);
    assert(snapshot.presenceMode == 4);
    assert(snapshot.nextAwSequence == 32);
    assert(snapshot.latestPeerAgeUs == 100000); // RX timestamp, not drain time.

    mif = makeRecord(3, source, 9, 10, 11, 1300000, 9);
    assert(observer.observe(mif, epochs, 1300100) == ObserveResult::kUpdatedPeer);
    snapshot = observer.snapshot(epochs, 1300200);
    assert(snapshot.validPeerCount == 1);
    assert(snapshot.rxChannelIndex == 9);
}

static void testStaleTruncatedFutureAndOldFramesAreRejected()
{
    const uint8_t source[] = {0x02, 1, 2, 3, 4, 5};
    Observer observer;
    const RuntimeEpochs epochs = activeEpochs();
    ActionFrameRecord record = makeRecord(3, source, 9, 10, 11,
                                          2000000, 6);

    record.stationGeneration++;
    assert(observer.observe(record, epochs, 2000100) ==
           ObserveResult::kStaleGeneration);
    record.stationGeneration--;

    record.length--;
    assert(observer.observe(record, epochs, 2000100) == ObserveResult::kInvalidFrame);
    record = makeRecord(3, source, 9, 10, 11, 2000000, 6);

    record.rxMonotonicUs = 2000101;
    assert(observer.observe(record, epochs, 2000100) ==
           ObserveResult::kInvalidTimestamp);
    record.rxMonotonicUs = 1;
    assert(observer.observe(record, epochs,
                            IntelAwdlPeer::kPeerTtlUs + 2) ==
           ObserveResult::kExpiredFrame);

    const Snapshot snapshot = observer.snapshot(epochs, 2000200);
    assert(snapshot.validPeerCount == 0);
}

static void testPeerValidityAndSyncSanityAreSeparate()
{
    const uint8_t source[] = {0x02, 0x21, 0x22, 0x23, 0x24, 0x25};
    Observer observer;
    const RuntimeEpochs epochs = activeEpochs();

    ActionFrameRecord invalidVersion = makeRecord(
        3, source, 9, 10, 11, 3000000, 4, 0, 0);
    assert(observer.observe(invalidVersion, epochs, 3000100) ==
           ObserveResult::kCandidateOnly);
    assert(observer.snapshot(epochs, 3000200).validPeerCount == 0);

    ActionFrameRecord badTiming = makeRecord(
        3, source, 9, 10, 11, 3100000, 5, 0x34, 1, 65, 16, 4);
    assert(observer.observe(badTiming, epochs, 3100100) ==
           ObserveResult::kAdmittedPeer);
    const Snapshot snapshot = observer.snapshot(epochs, 3100200);
    assert(snapshot.validPeerCount == 1);
    assert(snapshot.hasLatestPeer);
    assert(!snapshot.syncFieldsValid);
    assert(snapshot.nextSlotTu == 65);
}

static void testEpochChangeAndTtlClearState()
{
    const uint8_t source[] = {0x02, 0x31, 0x32, 0x33, 0x34, 0x35};
    Observer observer;
    RuntimeEpochs epochs = activeEpochs();
    ActionFrameRecord record = makeRecord(3, source, 9, 10, 11,
                                          4000000, 6);
    assert(observer.observe(record, epochs, 4000100) == ObserveResult::kAdmittedPeer);
    assert(observer.snapshot(epochs, 4000200).validPeerCount == 1);

    epochs.powerGeneration++;
    assert(observer.snapshot(epochs, 4000300).validPeerCount == 0);
    record = makeRecord(3, source, 9, 11, 11, 5000000, 6);
    assert(observer.observe(record, epochs, 5000100) == ObserveResult::kAdmittedPeer);
    assert(observer.snapshot(epochs, 5000200).validPeerCount == 1);
    assert(observer.snapshot(epochs, 5000000 + IntelAwdlPeer::kPeerTtlUs + 1)
               .validPeerCount == 0);

    epochs.active = false;
    assert(observer.snapshot(epochs, 70000000).validPeerCount == 0);
}

static void testFiveFrameBurstHistorySurvivesWindowCleanup()
{
    const uint8_t sourceA[] = {0x02, 0x51, 0x52, 0x53, 0x54, 0x55};
    const uint8_t sourceB[] = {0x02, 0x61, 0x62, 0x63, 0x64, 0x65};
    Observer observer;
    RuntimeEpochs epochs = activeEpochs();
    uint64_t timestamp = 9000000;

    // Three PSF candidates, then one MIF admission and one MIF update.
    ActionFrameRecord record = makeRecord(0, sourceA, 9, 10, 11,
                                          timestamp, 6);
    assert(observer.observe(record, epochs, timestamp + 100) ==
           ObserveResult::kCandidateOnly);
    timestamp += 1000;
    record = makeRecord(0, sourceA, 9, 10, 11, timestamp, 6);
    assert(observer.observe(record, epochs, timestamp + 100) ==
           ObserveResult::kCandidateOnly);
    timestamp += 1000;
    record = makeRecord(0, sourceB, 9, 10, 11, timestamp, 6);
    assert(observer.observe(record, epochs, timestamp + 100) ==
           ObserveResult::kCandidateOnly);
    timestamp += 1000;
    record = makeRecord(3, sourceA, 9, 10, 11, timestamp, 7);
    assert(observer.observe(record, epochs, timestamp + 100) ==
           ObserveResult::kAdmittedPeer);
    timestamp += 1000;
    record = makeRecord(3, sourceA, 9, 10, 11, timestamp, 8);
    assert(observer.observe(record, epochs, timestamp + 100) ==
           ObserveResult::kUpdatedPeer);

    Snapshot snapshot = observer.snapshot(epochs, timestamp + 200);
    assert(snapshot.validPeerCount == 1);
    assert(snapshot.candidateFramesTotal == 3);
    assert(snapshot.psfFramesTotal == 3);
    assert(snapshot.mifFramesTotal == 2);
    assert(snapshot.admittedFramesTotal == 1);
    assert(snapshot.updatedFramesTotal == 1);
    assert(snapshot.lastAdmittedContextGeneration == 9);
    assert(snapshot.activeWindowPeakValidPeerCount == 1);
    assert(snapshot.activeWindowPeakContextGeneration == 9);

    // Cleanup clears live peers but retains history for the completed window.
    epochs.active = false;
    snapshot = observer.snapshot(epochs, timestamp + 300);
    assert(snapshot.validPeerCount == 0);
    assert(!snapshot.hasLatestPeer);
    assert(snapshot.candidateFramesTotal == 3);
    assert(snapshot.psfFramesTotal == 3);
    assert(snapshot.mifFramesTotal == 2);
    assert(snapshot.admittedFramesTotal == 1);
    assert(snapshot.updatedFramesTotal == 1);
    assert(snapshot.lastAdmittedContextGeneration == 9);
    assert(snapshot.activeWindowPeakValidPeerCount == 1);
    assert(snapshot.activeWindowPeakContextGeneration == 9);

    // A new active window starts empty and does not resurrect the old peer.
    epochs.active = true;
    snapshot = observer.snapshot(epochs, timestamp + 400);
    assert(snapshot.validPeerCount == 0);
    assert(!snapshot.hasLatestPeer);
    assert(snapshot.admittedFramesTotal == 1);
    assert(snapshot.lastAdmittedContextGeneration == 9);
    assert(snapshot.activeWindowPeakValidPeerCount == 0);
    assert(snapshot.activeWindowPeakContextGeneration == 9);

    // A changed runtime generation also invalidates live peers without erasing
    // cumulative evidence or misattributing the historical admission.
    epochs.contextGeneration++;
    snapshot = observer.snapshot(epochs, timestamp + 500);
    assert(snapshot.validPeerCount == 0);
    assert(snapshot.admittedFramesTotal == 1);
    assert(snapshot.lastAdmittedContextGeneration == 9);
    assert(snapshot.activeWindowPeakValidPeerCount == 0);
    assert(snapshot.activeWindowPeakContextGeneration == 10);
}

static void testBoundedCapacityAndUnicastIdentity()
{
    Observer observer;
    const RuntimeEpochs epochs = activeEpochs();
    uint64_t timestamp = 8000000;
    for (size_t i = 0; i < IntelAwdlPeer::kPeerCapacity + 1; ++i) {
        const uint8_t source[] = {
            0x02, 0x40, 0, 0, 0,
            static_cast<uint8_t>(i + 1)
        };
        ActionFrameRecord record = makeRecord(
            3, source, 9, 10, 11, timestamp, static_cast<uint16_t>(i));
        assert(observer.observe(record, epochs, timestamp + 100) ==
               ObserveResult::kAdmittedPeer);
        timestamp += 1000;
    }
    assert(observer.snapshot(epochs, timestamp).validPeerCount ==
           IntelAwdlPeer::kPeerCapacity);

    const uint8_t multicast[] = {0x03, 1, 2, 3, 4, 5};
    ActionFrameRecord invalidSource = makeRecord(
        3, multicast, 9, 10, 11, timestamp, 1);
    assert(observer.observe(invalidSource, epochs, timestamp + 100) ==
           ObserveResult::kInvalidSourceAddress);
    assert(observer.snapshot(epochs, timestamp + 200).validPeerCount ==
           IntelAwdlPeer::kPeerCapacity);
}

int main()
{
    testMifAdmitsPeerAndPublishesOnlyNumericEvidence();
    testStaleTruncatedFutureAndOldFramesAreRejected();
    testPeerValidityAndSyncSanityAreSeparate();
    testEpochChangeAndTtlClearState();
    testFiveFrameBurstHistorySurvivesWindowCleanup();
    testBoundedCapacityAndUnicastIdentity();
    return 0;
}
