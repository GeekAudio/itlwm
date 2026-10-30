// SPDX-License-Identifier: GPL-2.0-only
#include "../rx_preowner_wire.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdint.h>

using namespace NativeRxPreOwner;
using namespace NativeRxPreOwnerWire;

static void check(bool condition, const char *message)
{
    if (!condition) {
        std::fprintf(stderr, "Test087 wire fixture: %s\n", message);
        std::exit(2);
    }
}

static Event makeEvent(uint64_t nowUs, uint32_t generation, EventKind kind)
{
    Event event{};
    event.nowUs = nowUs;
    event.generation = generation;
    event.kind = kind;
    event.rxClass = RxClass::Unknown;
    event.ownerReason = OwnerReason::Qualified;
    return event;
}

static Snapshot makeEmpty(bool active)
{
    Observer observer;
    check(observer.begin(1000000, 41), "begin empty capture");
    if (!active)
        check(observer.close(1000100, CloseReason::Stop), "close empty capture");
    Snapshot snapshot{};
    check(observer.snapshot(active ? 1000200 : 1000300, &snapshot),
          "snapshot empty capture");
    return snapshot;
}

static Snapshot makeMixed()
{
    Observer observer;
    const uint32_t generation = 55;
    const uint64_t begin = 2000000;
    check(observer.begin(begin, generation), "begin mixed capture");

    Event event = makeEvent(begin + 1, generation, EventKind::Irq);
    event.irqSource = IrqSource::Msix;
    event.irqCause = 0x100;
    check(observer.record(event), "record IRQ event");

    event = makeEvent(begin + 2, generation, EventKind::NotificationSeen);
    event.notificationCode = 0x0305;
    event.notificationQidPresent = 1;
    event.notificationQid = 0;
    event.notificationIndexPresent = 1;
    event.notificationIndex = 0;
    check(observer.record(event), "record notification with present-zero fields");

    event = makeEvent(begin + 3, generation, EventKind::MpduEntry);
    event.rxClass = RxClass::Channel149;
    event.ownerReason = OwnerReason::Qualified;
    event.channelPresent = 1;
    event.channel = 149;
    event.awdlCandidate = 1;
    event.physicalRingPresent = 1;
    event.physicalRing = 0;
    event.physicalSlotPresent = 1;
    event.physicalSlot = 7;
    event.payloadLen = 96;
    event.descSize = 48;
    event.mpduLengthPresent = 1;
    event.mpduLength = 0;
    event.rawStatusPresent = 1;
    event.rawStatus = 0x12345678;
    event.rawMacPhyIndexPresent = 1;
    event.rawMacPhyIndex = 0;
    event.macPhyDecodeModePresent = 1;
    event.macPhyDecodeMode = 0;
    event.macIndexPresent = 1;
    event.macIndex = 2;
    event.frameControlPresent = 1;
    event.frameControl = 0x0008;
    event.sequenceControlPresent = 1;
    event.sequenceControl = 0x0200;
    event.gp2OnAirRisePresent = 1;
    event.gp2OnAirRiseRaw = 0;
    event.tsfOnAirRisePresent = 1;
    event.tsfOnAirRiseRaw = 0;
    check(observer.record(event), "record channel-149 candidate");

    event = makeEvent(begin + 4, generation, EventKind::MpduEntry);
    event.rxClass = RxClass::Sta;
    event.ownerReason = OwnerReason::LeaseInactive;
    event.channelPresent = 1;
    event.channel = 36;
    check(observer.record(event), "record non-149 MPDU entry");

    check(observer.close(begin + 20, CloseReason::Explicit), "close mixed capture");
    Snapshot snapshot{};
    check(observer.snapshot(begin + 30, &snapshot), "snapshot mixed capture");
    return snapshot;
}

static Snapshot makeWitnessOverflow()
{
    Observer observer;
    const uint32_t generation = 73;
    const uint64_t begin = 3000000;
    check(observer.begin(begin, generation), "begin overflow capture");
    for (uint32_t index = 0; index < 10; ++index) {
        Event event = makeEvent(begin + 1 + index, generation, EventKind::MpduEntry);
        event.rxClass = RxClass::Channel149;
        event.channelPresent = 1;
        event.channel = 149;
        event.awdlCandidate = 1;
        check(observer.record(event), "record overflow MPDU entry");
    }
    check(observer.close(begin + 20, CloseReason::Explicit), "close overflow capture");
    Snapshot snapshot{};
    check(observer.snapshot(begin + 30, &snapshot), "snapshot overflow capture");
    return snapshot;
}

static Snapshot makeCounterOverflow()
{
    Snapshot snapshot{};
    snapshot.schemaVersion = kSchemaVersion;
    snapshot.captureSerial = kCaptureSerial;
    snapshot.driverGeneration = 89;
    snapshot.beginUs = 4000000;
    snapshot.endUs = snapshot.beginUs + 10;
    snapshot.deadlineUs = snapshot.beginUs + kWindowUs;
    snapshot.snapshotUs = snapshot.endUs + 1;
    snapshot.active = 0;
    snapshot.closed = 1;
    snapshot.closeReason = CloseReason::Explicit;
    snapshot.totalEvents = UINT32_MAX;
    snapshot.kindCounts[static_cast<uint32_t>(EventKind::MpduEntry)] = UINT32_MAX;
    snapshot.rxClassCounts[static_cast<uint32_t>(RxClass::Channel149)] = UINT32_MAX;
    snapshot.mpduEntryCount = UINT32_MAX;
    snapshot.awdlCandidateCount = UINT32_MAX;
    snapshot.ownerQualifiedCount = UINT32_MAX;
    snapshot.ownerReasonCounts[static_cast<uint32_t>(OwnerReason::Qualified)] = UINT32_MAX;
    snapshot.overflow = 1;
    snapshot.counterOverflow = 1;
    return snapshot;
}

static void testEncoderFailureIsNonWriting(const Snapshot &valid)
{
    uint64_t words[kMaxWireWordCount];
    for (size_t i = 0; i < kMaxWireWordCount; ++i)
        words[i] = 0xfeedfacecafebeefULL;
    check(encode(valid, words, kWireWordCount - 1) == 0,
          "undersized output rejected");
    for (size_t i = 0; i < kMaxWireWordCount; ++i)
        check(words[i] == 0xfeedfacecafebeefULL,
              "undersized output remains untouched");
    check(encode(valid, nullptr, kMaxWireWordCount) == 0,
          "null output rejected");
    Snapshot invalid = valid;
    ++invalid.totalEvents;
    check(encode(invalid, words, kMaxWireWordCount) == 0,
          "invalid counter relationships rejected");
    for (size_t i = 0; i < kMaxWireWordCount; ++i)
        check(words[i] == 0xfeedfacecafebeefULL,
              "invalid snapshot leaves output untouched");
}

static void writeRecord(const Snapshot &snapshot)
{
    uint64_t words[kMaxWireWordCount]{};
    const size_t count = encode(snapshot, words, kMaxWireWordCount);
    check(count == kWireWordCount, "valid snapshot encoded to fixed word count");
    check(std::fwrite(&count, sizeof(uint64_t), 1, stdout) == 1,
          "write archive record length");
    check(std::fwrite(words, sizeof(uint64_t), count, stdout) == count,
          "write wire record");
}

int main()
{
    const uint16_t endianProbe = 1;
    check(*reinterpret_cast<const uint8_t *>(&endianProbe) == 1,
          "fixture requires little-endian host words");

    const Snapshot mixed = makeMixed();
    const Snapshot closedEmpty = makeEmpty(false);
    const Snapshot activeEmpty = makeEmpty(true);
    const Snapshot witnessOverflow = makeWitnessOverflow();
    const Snapshot counterOverflow = makeCounterOverflow();
    testEncoderFailureIsNonWriting(mixed);

    const uint64_t recordCount = 5;
    check(std::fwrite(&recordCount, sizeof(recordCount), 1, stdout) == 1,
          "write archive record count");
    writeRecord(mixed);
    writeRecord(closedEmpty);
    writeRecord(activeEmpty);
    writeRecord(witnessOverflow);
    writeRecord(counterOverflow);
    return 0;
}
