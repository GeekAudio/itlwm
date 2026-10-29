// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_data_tx_trace.hpp"

#include <assert.h>
#include <stdint.h>
#include <condition_variable>
#include <mutex>
#include <thread>

using namespace NativeAwdlDataTxTrace;

struct CapturePause {
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool released = false;

    static void hook(void *context)
    {
        CapturePause *pause = static_cast<CapturePause *>(context);
        std::unique_lock<std::mutex> lock(pause->mutex);
        pause->entered = true;
        pause->condition.notify_all();
        pause->condition.wait(lock, [&]() { return pause->released; });
    }

    void waitUntilEntered()
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&]() { return entered; });
    }

    void release()
    {
        std::unique_lock<std::mutex> lock(mutex);
        released = true;
        condition.notify_all();
    }
};

static bool closeSnapshot(const PublicationSnapshot &before,
                          const PublicationSnapshot &after,
                          uint64_t contentRevision)
{
    return Ledger::canClosePublication(before, after, contentRevision);
}

static Identity identity(uint64_t token = 28, uint64_t diag = 701,
                        uint64_t context = 91, uint64_t power = 12,
                        uint64_t station = 8, uint64_t roc = 44)
{
    Identity id{};
    id.token = token;
    id.diagnosticGeneration = diag;
    id.contextGeneration = context;
    id.powerGeneration = power;
    id.stationGeneration = station;
    id.rocGeneration = roc;
    return id;
}

static void prepareDoorbell(Ledger &ledger, const Identity &id,
                            uint64_t base = 1000)
{
    assert(ledger.beginToken(id, base, 3, true) == Status::Ready);
    assert(ledger.markDequeued(id, base + 10) == Status::Ready);
    assert(ledger.markSubmitCallStart(id.token, base + 20) == Status::Ready);
    assert(ledger.markFinalWire(id.token, id.contextGeneration,
        id.powerGeneration, id.rocGeneration, 0x0008, 0x1230, 142, 1, 96,
        base + 30) == Status::Ready);
    assert(ledger.markRing(id.token, id.contextGeneration, id.powerGeneration,
        id.rocGeneration, 9, 256, 17, base + 40) == Status::Ready);
    assert(ledger.markDescriptorReady(id.token, base + 50) == Status::Ready);
    assert(ledger.markDoorbellMarked(id.token, base + 60) == Status::Ready);
    assert(ledger.markDoorbellIssued(id.token, base + 70) == Status::Ready);
}

static void testExactHostCorrelationIsNotFirmwareIdentity()
{
    Ledger ledger;
    const Identity id = identity();
    assert(!ledger.ownerPresent());
    assert(ledger.snapshotVersion() == 0);
    assert(ledger.markPublishedSnapshotVersion(0));
    assert(ledger.hasPublishedSnapshot());

    prepareDoorbell(ledger, id);
    assert(ledger.markSubmitCallEnd(id.token, 0, 1080) == Status::Ready);
    assert(ledger.beginToken(id, 1000) == Status::DuplicateToken);
    const uint32_t allFields = kResponseQueueValid |
        kResponseRxHeaderIndexValid | kResponseSequenceValid |
        kResponseByteCountValid | kResponseFrameControlValid |
        kResponseStatusValid | kResponseRaTidValid | kResponseScdSsnValid;
    assert(ledger.captureTxResponseTap(id.token, 1100, allFields,
        9, 17, 0x1230, 142, 0x0008, 0x0001, 0x3f, 18));
    assert(ledger.mergeTxResponseTap() == Status::Ready);

    RecordSnapshot record{};
    assert(ledger.snapshot(0, &record) && record.present);
    assert(record.identity.token == id.token);
    assert(record.identity.diagnosticGeneration == id.diagnosticGeneration);
    assert(record.identity.contextGeneration == id.contextGeneration);
    assert(record.identity.powerGeneration == id.powerGeneration);
    assert(record.identity.stationGeneration == id.stationGeneration);
    assert(record.identity.rocGeneration == id.rocGeneration);
    assert(record.queueMetadataPresent && record.queueEligible &&
           record.queryClass == 3);
    assert(record.txRspTapUs == 1100);
    assert(record.responseCandidateSeen);
    assert(record.submitCallEndUs == 1080 && record.submitCallResult == 0);
    assert(record.responseMismatchMask == 0);
    assert(record.txRspRxHeaderIndex == 17);
    assert(record.responseScalarMatchMask == (kResponseQueueValid |
        kResponseSequenceValid |
        kResponseByteCountValid | kResponseFrameControlValid));
    assert(record.associationStrength == static_cast<uint32_t>(
        AssociationStrength::LocalScalarFieldsMatch));
    assert(!record.firmwareEchoesFullIdentity);
    assert(record.ambiguousLateQueueUnknown);

    assert(ledger.markTxResponseHandlerDisposition(id.token, 1) == Status::Ready);
    assert(ledger.markCompletion(id.token, 0, 1120) == Status::Ready);
    assert(ledger.markCompletion(id.token, 0, 1130) == Status::StaleToken);
    assert(ledger.markPublishedSnapshotVersion(ledger.snapshotVersion()));
    assert(ledger.ownerPresent());
    Identity owner{};
    assert(ledger.ownerSnapshot(&owner));
    assert(owner.token == id.token && owner.diagnosticGeneration == id.diagnosticGeneration);
}

static void testMismatchAndBoundedSingleTap()
{
    Ledger ledger;
    const Identity id = identity(29, 702, 92, 13, 9, 45);
    prepareDoorbell(ledger, id, 2000);
    const uint32_t required = kResponseQueueValid |
        kResponseRxHeaderIndexValid | kResponseSequenceValid |
        kResponseByteCountValid | kResponseFrameControlValid;
    assert(ledger.captureTxResponseTap(id.token, 2100, required,
        9, 18, 0x1230, 140, 0x0008, 0, 0, 0));
    // A second capture cannot overwrite an unmerged record; it is counted.
    assert(!ledger.captureTxResponseTap(id.token, 2101, required,
        9, 17, 0x1230, 142, 0x0008, 0, 0, 0));
    assert(ledger.mergeTxResponseTap() == Status::Ready);
    assert(ledger.droppedCount() == 1);
    RecordSnapshot record{};
    assert(ledger.snapshot(0, &record));
    assert(record.associationStrength == static_cast<uint32_t>(
        AssociationStrength::CandidateOnly));
    assert(!(record.responseMismatchMask & kMismatchRxHeaderIndexReserved));
    assert(record.responseMismatchMask & kMismatchByteCount);
    assert(record.txRspRxHeaderIndex == 18);
    assert(record.ambiguousLateQueueUnknown);
}

static void testGenerationAndOrderingFailures()
{
    Ledger ledger;
    const Identity id = identity(30, 703, 93, 14, 10, 46);
    assert(ledger.beginToken(id, 3000) == Status::Ready);
    Identity stale = id;
    stale.powerGeneration++;
    assert(ledger.markDequeued(stale, 3010) == Status::StaleGeneration);
    assert(ledger.markSubmitCallStart(id.token, 3005) == Status::OutOfOrder);
    assert(ledger.markDequeued(id, 3010) == Status::Ready);
    assert(ledger.markSubmitCallStart(id.token, 3020) == Status::Ready);
    assert(ledger.markFinalWire(id.token, id.contextGeneration + 1,
        id.powerGeneration, id.rocGeneration, 0x0008, 0x1240, 142, 1, 96,
        3030) == Status::StaleGeneration);
    assert(ledger.markCancelled(id.token, 22, 3040) == Status::Ready);
    assert(ledger.markCancelled(id.token, 22, 3041) == Status::StaleToken);
    assert(ledger.markSubmitCallEnd(id.token, -1, 3050) == Status::Ready);

    const Identity second = identity(31, 704, 94, 15, 11, 47);
    prepareDoorbell(ledger, second, 4000);
    assert(ledger.markCancelled(second.token, 1, 4080) == Status::Irreversible);
    assert(ledger.captureStopTap(second.token, 72, false, 5, 4090));
    RecordSnapshot beforeMerge{};
    assert(ledger.snapshot(1, &beforeMerge));
    assert(!(beforeMerge.stageMask & kStopObserved));
    assert(ledger.mergeStopTap() == Status::Ready);
    RecordSnapshot record{};
    assert(ledger.snapshot(1, &record));
    assert(record.stageMask & kUnknown);
    assert(record.stageMask & kStopObserved);
    assert(!(record.stageMask & kCancel));
    assert(record.stopUs == 4090 && record.stopNewGeneration == 72);
    assert(record.stopReason == 5 && !record.stopProvenDrain);
}

static void testStopTapNeedsOrderedTimeAndMainGateMerge()
{
    Ledger ledger;
    const Identity id = identity(33, 706, 96, 17, 13, 49);
    assert(ledger.beginToken(id, 5000) == Status::Ready);
    assert(ledger.markDequeued(id, 5010) == Status::Ready);
    assert(ledger.markSubmitCallStart(id.token, 5020) == Status::Ready);

    // A zero-time stop cannot be represented, but the loss is explicit.
    assert(!ledger.captureStopTap(id.token, 73, true, 6, 0));
    assert(ledger.mergeStopTap() == Status::NoRecord);
    assert(ledger.droppedCount() == 1);

    // A captured stop earlier than the lifecycle timestamp is rejected only
    // when the main gate merges it; it must not create a terminal row.
    assert(ledger.captureStopTap(id.token, 73, true, 6, 5019));
    assert(ledger.mergeStopTap() == Status::OutOfOrder);
    RecordSnapshot record{};
    assert(ledger.snapshot(0, &record));
    assert(!(record.stageMask & (kStopObserved | kCancel | kUnknown)));
    assert(ledger.droppedCount() == 2); // invalid-time capture + orphan merge

    // A later, proven drain may cancel a pre-doorbell row and is published
    // only after the main-gate merge.
    assert(ledger.captureStopTap(id.token, 74, true, 7, 5021));
    assert(ledger.mergeStopTap() == Status::Ready);
    assert(ledger.snapshot(0, &record));
    assert(record.stageMask & kStopObserved);
    assert(record.stageMask & kCancel);
    assert(!(record.stageMask & kUnknown));
    assert(record.stopUs == 5021 && record.stopNewGeneration == 74);
    assert(record.stopProvenDrain && record.stopReason == 7);
}

static void testConsumedButUnencodedQueueItem()
{
    Ledger ledger;
    const Identity id = identity(32, 705, 95, 16, 12, 48);
    assert(ledger.beginToken(id, 5000) == Status::Ready);
    assert(ledger.markDequeued(id, 5010) == Status::Ready);
    assert(ledger.markEncodeFailure(id.token, 12, 5020) == Status::Ready);
    RecordSnapshot record{};
    assert(ledger.snapshot(0, &record));
    assert(record.stageMask & kEncodeFailure);
    assert(record.encodeFailureUs == 5020);
    assert(record.encodeFailureResult == 12);
    assert(!(record.stageMask & kCancel));
}

static void testCapacityDoesNotEvictOrGate()
{
    Ledger ledger;
    for (uint64_t i = 0; i < kRecordCapacity; ++i) {
        const Identity id = identity(100 + i, 800 + i, 200 + i,
                                     300 + i, 400 + i, 500 + i);
        assert(ledger.beginToken(id, 6000 + i) == Status::Ready);
        assert(ledger.markCancelled(id.token, 1, 6010 + i) == Status::Ready);
    }
    const Identity overflow = identity(999, 999, 999, 999, 999, 999);
    assert(ledger.beginToken(overflow, 7000) == Status::CapacityFull);
    assert(ledger.count() == kRecordCapacity);
    assert(ledger.droppedCount() == 1);
    RecordSnapshot first{};
    assert(ledger.snapshot(0, &first));
    assert(first.identity.token == 100); // Terminal evidence is never evicted.
}

static void testConcurrentImmutableSidecarPublication()
{
    AtomicTxResponseTap tap;
    const Identity first = identity(201, 901, 1001, 1101, 1201, 1301);
    const Identity second = identity(202, 902, 1002, 1102, 1202, 1302);
    const auto publish = [&](const Identity &id, uint64_t serial,
                             uint16_t qid, uint16_t index, uint16_t seq,
                             uint16_t bytes, uint16_t fc) {
        tap.setActiveTicket(id, serial, qid, index, seq, bytes, fc);
    };
    publish(first, 1, 9, 17, 0x2010, 142, 0x0008);

    std::thread publisher([&]() {
        for (uint32_t i = 0; i < 100000; ++i) {
            publish((i & 1u) ? first : second,
                    (i & 1u) ? 1 : 2,
                    (i & 1u) ? 9 : 10,
                    (i & 1u) ? 17 : 21,
                    (i & 1u) ? 0x2010 : 0x2020,
                    (i & 1u) ? 142 : 198,
                    (i & 1u) ? 0x0008 : 0x0008);
        }
    });

    const uint32_t required = kResponseQueueValid |
        kResponseRxHeaderIndexValid | kResponseSequenceValid |
        kResponseByteCountValid | kResponseFrameControlValid;
    uint32_t accepted = 0;
    for (uint32_t i = 0; i < 100000; ++i) {
        bool captured = tap.capture(201, 9000 + i, required,
            9, 17, 0x2010, 142, 0x0008, 0, 0, 0);
        if (!captured)
            captured = tap.capture(202, 9000 + i, required,
                10, 21, 0x2020, 198, 0x0008, 0, 0, 0);
        if (!captured)
            continue;
        TxResponseTap snapshot{};
        uint64_t serial = 0;
        if (!tap.snapshot(&snapshot, &serial))
            continue;
        const bool isFirst = snapshot.identity.token == first.token &&
            snapshot.identity.diagnosticGeneration == first.diagnosticGeneration &&
            snapshot.identity.contextGeneration == first.contextGeneration &&
            snapshot.identity.powerGeneration == first.powerGeneration &&
            snapshot.identity.stationGeneration == first.stationGeneration &&
            snapshot.identity.rocGeneration == first.rocGeneration &&
            snapshot.recordSerial == 1 && snapshot.expectedQueueId == 9 &&
            snapshot.expectedDescriptorIndex == 17 &&
            snapshot.expectedSequenceControl == 0x2010 &&
            snapshot.expectedByteCount == 142;
        const bool isSecond = snapshot.identity.token == second.token &&
            snapshot.identity.diagnosticGeneration == second.diagnosticGeneration &&
            snapshot.identity.contextGeneration == second.contextGeneration &&
            snapshot.identity.powerGeneration == second.powerGeneration &&
            snapshot.identity.stationGeneration == second.stationGeneration &&
            snapshot.identity.rocGeneration == second.rocGeneration &&
            snapshot.recordSerial == 2 && snapshot.expectedQueueId == 10 &&
            snapshot.expectedDescriptorIndex == 21 &&
            snapshot.expectedSequenceControl == 0x2020 &&
            snapshot.expectedByteCount == 198;
        assert(isFirst || isSecond);
        tap.markConsumed(serial);
        ++accepted;
    }
    publisher.join();
    assert(accepted != 0);
}

static void testResponseTapPublicationInterleavings()
{
    Ledger ledger;
    const Identity id = identity(301, 1001, 1101, 1201, 1301, 1401);
    prepareDoorbell(ledger, id, 3000);
    assert(ledger.mergeTxResponseTap() == Status::NoRecord);

    PublicationSnapshot empty{};
    ledger.publicationSnapshot(&empty);
    assert(empty.revisionStable);
    assert(empty.txResponse.state == TapPublicationState::EmptyOrConsumed);
    assert(empty.txResponse.sequence == 0 &&
           empty.txResponse.consumedSequence == 0);
    assert(closeSnapshot(empty, empty, empty.revision));

    CapturePause pause;
    ledger.setResponseCaptureInterleaveHookForTesting(
        &CapturePause::hook, &pause);
    const uint32_t fields = kResponseQueueValid |
        kResponseRxHeaderIndexValid | kResponseSequenceValid |
        kResponseByteCountValid | kResponseFrameControlValid;
    bool captured = false;
    std::thread callback([&]() {
        captured = ledger.captureTxResponseTap(id.token, 3110, fields,
            9, 17, 0x1230, 142, 0x0008, 0x0001, 0x3f, 18);
    });

    pause.waitUntilEntered(); // The callback owns an odd tap sequence.
    assert(ledger.mergeTxResponseTap() == Status::ResponseTapUnstable);
    PublicationSnapshot paused{};
    ledger.publicationSnapshot(&paused);
    assert(paused.txResponse.state == TapPublicationState::Unstable);
    assert(!closeSnapshot(paused, paused, paused.revision));

    pause.release();
    callback.join();
    assert(captured);
    PublicationSnapshot pending{};
    ledger.publicationSnapshot(&pending);
    assert(pending.txResponse.state == TapPublicationState::Pending);
    assert(pending.txResponse.sequence != pending.txResponse.consumedSequence);
    assert(!pending.coverageUnknown);
    assert(!closeSnapshot(pending, pending, pending.revision));

    // Transient instability/pending is recoverable once the main gate merges
    // the completed callback. No tap was dropped, so coverage remains known.
    assert(ledger.mergeTxResponseTap() == Status::Ready);
    PublicationSnapshot consumed{};
    ledger.publicationSnapshot(&consumed);
    assert(consumed.revisionStable);
    assert(consumed.txResponse.state == TapPublicationState::EmptyOrConsumed);
    assert(consumed.txResponse.sequence == consumed.txResponse.consumedSequence);
    assert(!consumed.coverageUnknown);
    assert(closeSnapshot(consumed, consumed, consumed.revision));
    PublicationSnapshot changedActive = consumed;
    changedActive.txResponse.activePublicationSequence += 2;
    changedActive.txResponse.activeToken += 1;
    assert(!closeSnapshot(consumed, changedActive, consumed.revision));
    PublicationSnapshot changedDrop = consumed;
    changedDrop.txResponse.droppedCount += 1;
    changedDrop.coverageUnknown = true;
    assert(!closeSnapshot(consumed, changedDrop, consumed.revision));
    PublicationSnapshot changedRevision = consumed;
    changedRevision.revision += 1;
    assert(!closeSnapshot(consumed, changedRevision, consumed.revision));
    PublicationSnapshot changedOwner = consumed;
    changedOwner.owner.token += 1;
    assert(!closeSnapshot(consumed, changedOwner, consumed.revision));

    assert(ledger.markCompletion(id.token, 0, 3120) == Status::Ready);
    const uint64_t publishedLedgerVersion = ledger.snapshotVersion();
    assert(ledger.markPublishedSnapshotVersion(publishedLedgerVersion));

    // A response arriving after the active ticket has been completed is
    // rejected without blocking the callback; the sticky drop is an explicit
    // unknown and is made visible through a new ledger snapshot version.
    assert(!ledger.captureTxResponseTap(id.token, 3130, fields,
        9, 17, 0x1230, 142, 0x0008, 0x0001, 0x3f, 18));
    assert(ledger.coverageUnknown());
    assert(ledger.mergeTxResponseTap() == Status::NoRecord);
    assert(ledger.snapshotVersion() > publishedLedgerVersion);
    PublicationSnapshot late{};
    ledger.publicationSnapshot(&late);
    assert(late.txResponse.state == TapPublicationState::EmptyOrConsumed);
    assert(late.txResponse.droppedCount == 1);
    assert(late.coverageUnknown);
    // The serialized body is coherent, but its evidence coverage is unknown.
    assert(closeSnapshot(late, late, late.revision));
}

static void testStopTapPublicationInterleavings()
{
    Ledger ledger;
    const Identity id = identity(302, 1002, 1102, 1202, 1302, 1402);
    assert(ledger.beginToken(id, 5000) == Status::Ready);
    assert(ledger.markDequeued(id, 5010) == Status::Ready);
    assert(ledger.markSubmitCallStart(id.token, 5020) == Status::Ready);

    CapturePause pause;
    ledger.setStopCaptureInterleaveHookForTesting(
        &CapturePause::hook, &pause);
    bool captured = false;
    std::thread callback([&]() {
        captured = ledger.captureStopTap(id.token, 72, true, 6, 5021);
    });

    pause.waitUntilEntered(); // The callback owns an odd stop-tap sequence.
    assert(ledger.mergeStopTap() == Status::ResponseTapUnstable);
    PublicationSnapshot paused{};
    ledger.publicationSnapshot(&paused);
    assert(paused.stop.state == TapPublicationState::Unstable);
    assert(!closeSnapshot(paused, paused, paused.revision));

    pause.release();
    callback.join();
    assert(captured);
    PublicationSnapshot pending{};
    ledger.publicationSnapshot(&pending);
    assert(pending.stop.state == TapPublicationState::Pending);
    assert(pending.stop.sequence != pending.stop.consumedSequence);
    assert(!pending.coverageUnknown);
    assert(!closeSnapshot(pending, pending, pending.revision));

    assert(ledger.mergeStopTap() == Status::Ready);
    PublicationSnapshot consumed{};
    ledger.publicationSnapshot(&consumed);
    assert(consumed.revisionStable);
    assert(consumed.stop.state == TapPublicationState::EmptyOrConsumed);
    assert(consumed.stop.sequence == consumed.stop.consumedSequence);
    assert(!consumed.coverageUnknown);
    assert(closeSnapshot(consumed, consumed, consumed.revision));
}

static void testFailedMergeIsStickyUnknown()
{
    Ledger ledger;
    const Identity id = identity(303, 1003, 1103, 1203, 1303, 1403);
    prepareDoorbell(ledger, id, 7000);
    const uint32_t fields = kResponseQueueValid |
        kResponseRxHeaderIndexValid | kResponseSequenceValid |
        kResponseByteCountValid | kResponseFrameControlValid;
    assert(ledger.captureTxResponseTap(id.token, 7110, fields,
        9, 17, 0x1230, 142, 0x0008, 0x0001, 0x3f, 18));
    assert(ledger.mergeTxResponseTap() == Status::Ready);

    // A second stable response for a row that already owns a TX_RSP is an
    // orphan merge. The merge failure/drop remains visible after consumption.
    assert(ledger.captureTxResponseTap(id.token, 7120, fields,
        9, 17, 0x1230, 142, 0x0008, 0x0001, 0x3f, 18));
    const uint64_t priorVersion = ledger.snapshotVersion();
    assert(ledger.mergeTxResponseTap() == Status::DuplicateStage);
    assert(ledger.coverageUnknown());
    assert(ledger.snapshotVersion() > priorVersion);

    PublicationSnapshot unknown{};
    ledger.publicationSnapshot(&unknown);
    assert(unknown.txResponse.state == TapPublicationState::EmptyOrConsumed);
    assert(unknown.coverageUnknown);
    assert(closeSnapshot(unknown, unknown, unknown.revision));
}

int main()
{
    testExactHostCorrelationIsNotFirmwareIdentity();
    testMismatchAndBoundedSingleTap();
    testGenerationAndOrderingFailures();
    testStopTapNeedsOrderedTimeAndMainGateMerge();
    testConsumedButUnencodedQueueItem();
    testCapacityDoesNotEvictOrGate();
    testConcurrentImmutableSidecarPublication();
    testResponseTapPublicationInterleavings();
    testStopTapPublicationInterleavings();
    testFailedMergeIsStickyUnknown();
    return 0;
}
