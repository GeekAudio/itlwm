// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_tx_resources.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>

using namespace IntelP2PTx;

static QueueAdmission tvqmAdmission()
{
    // Generation-2 dynamic TXQ firmware need not advertise the old static DQA bit.
    return {QueueApi::kTvqmDynamic, 512, 41, 7, false, true, true, true,
            true, false};
}

static QueueAdmission legacyDynamicAdmission()
{
    // DQA_SUPPORT describes the older static DQA mode. It is not required
    // for the generation-2 LONG_GROUP/SCD_QUEUE_CFG dynamic queue path.
    return {QueueApi::kLegacyDynamicDqa, 512, 41, 7, false, true, true, true,
            true, false};
}

static void testStationReservationUsesLiveBitmap()
{
    StationRegistry stations;
    assert(stations.initialize(16, 41, true, true, true) == Result::kSuccess);
    std::uint8_t stationId = 0xff;
    assert(stations.reserveP2p(41, &stationId) == Result::kSuccess);
    assert(stationId == 3);
    assert(stations.addAcknowledged(41, stationId) == Result::kSuccess);
    assert(stations.removeAcknowledged(41, stationId) == Result::kSuccess);
    assert(stations.snapshot().owners[3] == Owner::kFree);

    StationRegistry full;
    assert(full.initialize(3, 41, true, true, true) == Result::kSuccess);
    assert(full.reserveP2p(41, &stationId) == Result::kNoCapacity);

    StationRegistry noMonitor;
    assert(noMonitor.initialize(4, 41, true, true, false) == Result::kSuccess);
    assert(noMonitor.reserveP2p(41, &stationId) == Result::kSuccess);
    assert(stationId == 2);
    assert(noMonitor.addOutcomeUnknown(41, stationId) == Result::kSuccess);
    assert(noMonitor.initialize(4, 41, true, true, false) == Result::kBusy);
    assert(noMonitor.snapshot().owners[2] == Owner::kUnknown);
    assert(noMonitor.releaseKnownAbsent(41, stationId) == Result::kInvalid);
    std::uint8_t secondStationId = 0xff;
    assert(noMonitor.reserveP2p(41, &secondStationId) == Result::kSuccess);
    assert(secondStationId == 3);
    assert(noMonitor.reserveP2p(41, &stationId) == Result::kNoCapacity);
    assert(noMonitor.resetAfterFirmwareDrain(42, 4, true, true, false) ==
           Result::kSuccess);
    assert(noMonitor.reserveP2p(42, &stationId) == Result::kSuccess);
    assert(stationId == 2);
}

static void testFirmwareDrainResetRequiresAllP2pLeasesAbsent()
{
    StationRegistry stations;
    assert(stations.initialize(8, 41, true, true, true) == Result::kSuccess);
    QueueLease emptyQueue;
    assert(noP2pResourcesRetained(stations.snapshot(), emptyQueue.snapshot()));

    std::uint8_t stationId = 0xff;
    assert(stations.reserveP2p(41, &stationId) == Result::kSuccess);
    assert(!noP2pResourcesRetained(stations.snapshot(), emptyQueue.snapshot()));
    assert(stations.addAcknowledged(41, stationId) == Result::kSuccess);
    assert(!noP2pResourcesRetained(stations.snapshot(), emptyQueue.snapshot()));
    assert(stations.removeAcknowledged(41, stationId) == Result::kSuccess);
    assert(noP2pResourcesRetained(stations.snapshot(), emptyQueue.snapshot()));

    StationRegistry unknownStation;
    assert(unknownStation.initialize(8, 41, true, true, true) == Result::kSuccess);
    assert(unknownStation.reserveP2p(41, &stationId) == Result::kSuccess);
    assert(unknownStation.addOutcomeUnknown(41, stationId) == Result::kSuccess);
    assert(!noP2pResourcesRetained(unknownStation.snapshot(), emptyQueue.snapshot()));

    QueueLease queue;
    assert(queue.begin(tvqmAdmission()) == Result::kSuccess);
    assert(!noP2pResourcesRetained(stations.snapshot(), queue.snapshot()));
    assert(queue.tvqmAssigned(41, 7, 36, 512, true) == Result::kSuccess);
    assert(queue.txSubmitted(41, 36) == Result::kSuccess);
    assert(queue.beginRemoval(41, 36) == Result::kSuccess);
    assert(queue.removeAcknowledged(41, 36) == Result::kSuccess);
    assert(!noP2pResourcesRetained(stations.snapshot(), queue.snapshot()));
    assert(queue.txCompleted(41, 36) == Result::kSuccess);
    assert(queue.queueDrained(41, 36) == Result::kSuccess);
    assert(noP2pResourcesRetained(stations.snapshot(), queue.snapshot()));

    QueueLease unknownQueue;
    assert(unknownQueue.begin(tvqmAdmission()) == Result::kSuccess);
    assert(unknownQueue.tvqmAssigned(41, 7, 39, 512, true) == Result::kSuccess);
    assert(unknownQueue.beginRemoval(41, 39) == Result::kSuccess);
    assert(unknownQueue.removeOutcomeUnknown(41, 39) == Result::kNeedsReset);
    assert(!noP2pResourcesRetained(stations.snapshot(), unknownQueue.snapshot()));

    assert(stations.resetAfterFirmwareDrain(42, 8, true, true, true) ==
           Result::kSuccess);
    assert(stations.reserveP2p(42, &stationId) == Result::kSuccess);
    assert(stationId == 3);
}

static void testTvqmQueueRequiresDynamicUnreservedSlot()
{
    QueueLease lease;
    QueueAdmission admission = tvqmAdmission();
    assert(lease.begin(admission) == Result::kSuccess);
    assert(lease.snapshot().ringMustRemainOwned);
    assert(lease.tvqmAssigned(41, 7, 32, 512, true) == Result::kSuccess);
    assert(lease.snapshot().queueId == 32);

    QueueLease legacyCollision;
    assert(legacyCollision.begin(admission) == Result::kSuccess);
    // The operation-aware TVQM API does not imply that dynamic queue IDs
    // start at 32. Admission is based on the firmware capacity and actual
    // ownership collision, not the legacy DQA static queue range.
    assert(legacyCollision.tvqmAssigned(41, 7, 2, 512, true) ==
           Result::kSuccess);

    QueueLease collision;
    assert(collision.begin(admission) == Result::kSuccess);
    assert(collision.tvqmAssigned(41, 7, 37, 512, false) ==
           Result::kNeedsReset);
    assert(collision.snapshot().state == QueueState::kUnknown);
    assert(collision.snapshot().ringMustRemainOwned);

    QueueLease usedSlot;
    assert(usedSlot.begin(admission) == Result::kSuccess);
    assert(usedSlot.tvqmAssigned(41, 7, 37, 512, false) ==
           Result::kNeedsReset);
    assert(usedSlot.snapshot().ringMustRemainOwned);

    QueueLease rejected;
    QueueAdmission staticAdmission{QueueApi::kLegacyStaticDqa, 32, 41, 7,
                                   false, true, true, true, true, false};
    assert(rejected.begin(staticAdmission) == Result::kInvalid);
    assert(rejected.snapshot().state == QueueState::kAbsent);
}

static void testLegacyQueueTwoConflictsWithMonitorInjection()
{
    QueueAdmission admission{QueueApi::kLegacyStaticDqa, 32, 8, 5, true,
                             true, true, true, true, true};
    QueueLease conflict;
    assert(conflict.begin(admission) == Result::kBusy);
    assert(conflict.snapshot().state == QueueState::kAbsent);

    admission.monitorInjectionQueueInUse = false;
    QueueLease lease;
    assert(lease.begin(admission) == Result::kSuccess);
    assert(lease.staticQueueConfigured(8, 5, true) == Result::kSuccess);
    assert(lease.snapshot().queueId == 2);
}

static void testLegacyDynamicDqaDoesNotRequireStaticDqaCapability()
{
    QueueLease lease;
    QueueAdmission admission = legacyDynamicAdmission();
    assert(lease.begin(admission) == Result::kSuccess);
    assert(lease.legacyDqaAssigned(41, 7, 29, 512, true) == Result::kSuccess);
    assert(lease.snapshot().queueId == 29);
    assert(lease.snapshot().api == QueueApi::kLegacyDynamicDqa);

    QueueLease collision;
    assert(collision.begin(admission) == Result::kSuccess);
    assert(collision.legacyDqaAssigned(41, 7, 29, 512, false) ==
           Result::kNeedsReset);
    assert(collision.snapshot().ringMustRemainOwned);

    QueueLease staticDqa;
    admission.api = QueueApi::kLegacyStaticDqa;
    assert(staticDqa.begin(admission) == Result::kInvalid);
}

static void testLegacyQueueLifetimeUsesStationRemovalAckAndCompletion()
{
    QueueLease lease;
    assert(lease.begin(legacyDynamicAdmission()) == Result::kSuccess);
    assert(lease.legacyDqaAssigned(41, 7, 36, 512, true) == Result::kSuccess);
    assert(lease.txSubmitted(41, 36) == Result::kSuccess);
    assert(lease.beginRemoval(41, 36) == Result::kSuccess);
    assert(lease.txSubmitted(41, 36) == Result::kBusy);
    assert(lease.removeAcknowledged(41, 36) == Result::kInvalid);
    assert(lease.stationRemovalAcknowledged(41, 36) == Result::kSuccess);
    assert(lease.snapshot().ringMustRemainOwned);
    assert(lease.queueDrained(41, 36) == Result::kInvalid);

    assert(lease.txCompleted(41, 36) == Result::kSuccess);
    assert(lease.snapshot().completionObserved);
    assert(lease.snapshot().outstandingTx == 0);
    assert(lease.queueDrained(41, 36) == Result::kSuccess);
    assert(lease.snapshot().state == QueueState::kAbsent);
    assert(!lease.snapshot().ringMustRemainOwned);

    QueueLease neverCompleted;
    assert(neverCompleted.begin(legacyDynamicAdmission()) == Result::kSuccess);
    assert(neverCompleted.legacyDqaAssigned(41, 7, 39, 512, true) ==
           Result::kSuccess);
    assert(neverCompleted.beginRemoval(41, 39) == Result::kSuccess);
    assert(neverCompleted.stationRemovalAcknowledged(41, 39) ==
           Result::kSuccess);
    assert(neverCompleted.queueDrained(41, 39) == Result::kInvalid);
    assert(neverCompleted.snapshot().ringMustRemainOwned);

    QueueLease tvqm;
    assert(tvqm.begin(tvqmAdmission()) == Result::kSuccess);
    assert(tvqm.tvqmAssigned(41, 7, 40, 512, true) == Result::kSuccess);
    assert(tvqm.beginRemoval(41, 40) == Result::kSuccess);
    assert(tvqm.stationRemovalAcknowledged(41, 40) == Result::kInvalid);
}

static void testNeverSubmittedQueueHasSeparateAckedRelease()
{
    QueueLease idle;
    assert(idle.begin(legacyDynamicAdmission()) == Result::kSuccess);
    assert(idle.legacyDqaAssigned(41, 7, 44, 512, true) == Result::kSuccess);
    assert(idle.beginRemoval(41, 44) == Result::kSuccess);
    assert(idle.stationRemovalAcknowledged(41, 44) == Result::kSuccess);
    assert(idle.neverSubmittedQueueReleasedAfterStationRemoval(42, 44) ==
           Result::kStale);
    assert(idle.neverSubmittedQueueReleasedAfterStationRemoval(41, 45) ==
           Result::kStale);
    assert(idle.neverSubmittedQueueReleasedAfterStationRemoval(41, 44) ==
           Result::kSuccess);
    assert(idle.snapshot().state == QueueState::kAbsent);
    assert(!idle.snapshot().ringMustRemainOwned);

    QueueLease outstanding;
    assert(outstanding.begin(legacyDynamicAdmission()) == Result::kSuccess);
    assert(outstanding.legacyDqaAssigned(41, 7, 45, 512, true) ==
           Result::kSuccess);
    assert(outstanding.txSubmitted(41, 45) == Result::kSuccess);
    assert(outstanding.beginRemoval(41, 45) == Result::kSuccess);
    assert(outstanding.stationRemovalAcknowledged(41, 45) == Result::kSuccess);
    assert(outstanding.neverSubmittedQueueReleasedAfterStationRemoval(41, 45) ==
           Result::kInvalid);
    assert(outstanding.snapshot().ringMustRemainOwned);

    QueueLease completed;
    assert(completed.begin(legacyDynamicAdmission()) == Result::kSuccess);
    assert(completed.legacyDqaAssigned(41, 7, 46, 512, true) ==
           Result::kSuccess);
    assert(completed.txSubmitted(41, 46) == Result::kSuccess);
    assert(completed.beginRemoval(41, 46) == Result::kSuccess);
    assert(completed.stationRemovalAcknowledged(41, 46) == Result::kSuccess);
    assert(completed.txCompleted(41, 46) == Result::kSuccess);
    assert(completed.neverSubmittedQueueReleasedAfterStationRemoval(41, 46) ==
           Result::kInvalid);
    assert(completed.snapshot().ringMustRemainOwned);
    assert(completed.queueDrained(41, 46) == Result::kSuccess);

    QueueLease tvqm;
    assert(tvqm.begin(tvqmAdmission()) == Result::kSuccess);
    assert(tvqm.tvqmAssigned(41, 7, 47, 512, true) == Result::kSuccess);
    assert(tvqm.beginRemoval(41, 47) == Result::kSuccess);
    assert(tvqm.removeAcknowledged(41, 47) == Result::kSuccess);
    assert(tvqm.neverSubmittedQueueReleasedAfterStationRemoval(41, 47) ==
           Result::kInvalid);
    assert(tvqm.snapshot().ringMustRemainOwned);
}

static void testTxRingLifetimeWaitsForRemoveAndDrain()
{
    QueueLease lease;
    assert(lease.begin(tvqmAdmission()) == Result::kSuccess);
    assert(lease.tvqmAssigned(41, 7, 36, 512, true) == Result::kSuccess);
    assert(lease.txSubmitted(41, 36) == Result::kSuccess);
    assert(lease.beginRemoval(41, 36) == Result::kSuccess);
    assert(lease.txSubmitted(41, 36) == Result::kBusy);
    assert(lease.removeAcknowledged(41, 36) == Result::kSuccess);
    // Remove ACK is not a drain and cannot release the DMA backing.
    assert(lease.snapshot().state == QueueState::kRemoving);
    assert(lease.snapshot().ringMustRemainOwned);
    assert(lease.txCompleted(41, 36) == Result::kSuccess);
    assert(lease.snapshot().ringMustRemainOwned);
    assert(lease.queueDrained(41, 36) == Result::kSuccess);
    assert(lease.snapshot().state == QueueState::kAbsent);
    assert(!lease.snapshot().ringMustRemainOwned);

    QueueLease drainFirst;
    assert(drainFirst.begin(tvqmAdmission()) == Result::kSuccess);
    assert(drainFirst.tvqmAssigned(41, 7, 39, 512, true) == Result::kSuccess);
    assert(drainFirst.txSubmitted(41, 39) == Result::kSuccess);
    assert(drainFirst.beginRemoval(41, 39) == Result::kSuccess);
    assert(drainFirst.removeAcknowledged(41, 39) == Result::kSuccess);
    // Even with no outstanding descriptors, REMOVE ACK alone is not the
    // independent evidence required to release a queue that never completed
    // a TX frame.
    assert(drainFirst.queueDrained(41, 39) == Result::kInvalid);
    assert(drainFirst.snapshot().ringMustRemainOwned);
    assert(drainFirst.txCompleted(41, 39) == Result::kSuccess);
    assert(drainFirst.queueDrained(41, 39) == Result::kSuccess);
    assert(!drainFirst.snapshot().ringMustRemainOwned);

    QueueLease noTx;
    assert(noTx.begin(tvqmAdmission()) == Result::kSuccess);
    assert(noTx.tvqmAssigned(41, 7, 42, 512, true) == Result::kSuccess);
    assert(noTx.beginRemoval(41, 42) == Result::kSuccess);
    assert(noTx.removeAcknowledged(41, 42) == Result::kSuccess);
    assert(noTx.queueDrained(41, 42) == Result::kInvalid);
    assert(noTx.snapshot().ringMustRemainOwned);

    QueueLease cancelled;
    assert(cancelled.begin(tvqmAdmission()) == Result::kSuccess);
    assert(cancelled.tvqmAssigned(41, 7, 43, 512, true) == Result::kSuccess);
    assert(cancelled.txSubmitted(41, 43) == Result::kSuccess);
    assert(cancelled.txCancelled(41, 43) == Result::kSuccess);
    assert(cancelled.beginRemoval(41, 43) == Result::kSuccess);
    assert(cancelled.removeAcknowledged(41, 43) == Result::kSuccess);
    assert(cancelled.queueDrained(41, 43) == Result::kInvalid);
    assert(cancelled.snapshot().ringMustRemainOwned);

    QueueLease unknownRemove;
    assert(unknownRemove.begin(tvqmAdmission()) == Result::kSuccess);
    assert(unknownRemove.tvqmAssigned(41, 7, 40, 512, true) ==
           Result::kSuccess);
    assert(unknownRemove.beginRemoval(41, 40) == Result::kSuccess);
    assert(unknownRemove.removeOutcomeUnknown(41, 40) ==
           Result::kNeedsReset);
    assert(unknownRemove.snapshot().state == QueueState::kUnknown);
    assert(unknownRemove.snapshot().ringMustRemainOwned);
}

static void testActionFrameParserIsShapeOnly()
{
    std::uint8_t frame[28]{};
    frame[0] = 0xd0; // management Action
    const std::uint8_t destination[6] = {0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff};
    const std::uint8_t source[6] = {0x02, 0x12, 0x23, 0x34, 0x45, 0x56};
    std::memcpy(frame + 4, destination, 6);
    std::memcpy(frame + 10, source, 6);
    std::memcpy(frame + 16, destination, 6);
    ActionFrameInfo info{};
    assert(parseActionFrame(frame, sizeof(frame), &info));
    assert(info.headerLength == 24 && info.type == 0 && info.subtype == 0xd0);
    assert(std::memcmp(info.source, source, 6) == 0);
    assert(!parseActionFrame(frame, 23, &info));
    frame[0] = 0x80; // beacon, not Action
    assert(!parseActionFrame(frame, sizeof(frame), &info));
    frame[0] = 0xd0;
    std::memset(frame + 10, 0, 6);
    assert(!parseActionFrame(frame, sizeof(frame), &info));

    frame[0] = 0xd0;
    std::memcpy(frame + 10, source, 6);
    frame[1] = 0x80; // Order bit adds the HT Control field.
    assert(!parseActionFrame(frame, 24, &info));
    assert(parseActionFrame(frame, sizeof(frame), &info));
    assert(info.headerLength == 28);
}

static void testTvqmCommandEncodingIsLittleEndian()
{
    const TvqmAddFields fields{7, 8, 0, 5,
                               0x1122334455667788ULL,
                               0x8877665544332211ULL};
    std::uint8_t encoded[36]{};
    assert(encodeTvqmAddCommand(fields, encoded));
    const std::uint8_t expected[36] = {
        0, 0, 0, 0,
        0x80, 0, 0, 0, 8, 0, 0, 0,
        0, 0, 0, 0, 5, 0, 0, 0,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };
    assert(std::memcmp(encoded, expected, sizeof(expected)) == 0);
    TvqmAddFields invalid = fields;
    invalid.flags = 1; // ENABLE_QUEUE is not valid in operation ADD.
    assert(!encodeTvqmAddCommand(invalid, encoded));
    invalid = fields;
    invalid.circularBufferSizeCode = 6;
    assert(!encodeTvqmAddCommand(invalid, encoded));
    invalid = fields;
    invalid.tid = 9;
    assert(!encodeTvqmAddCommand(invalid, encoded));

    std::uint8_t remove[12]{};
    assert(encodeTvqmRemoveCommand(7, 8, remove));
    const std::uint8_t expectedRemove[12] = {
        1, 0, 0, 0, 0x80, 0, 0, 0, 8, 0, 0, 0
    };
    assert(std::memcmp(remove, expectedRemove, sizeof(remove)) == 0);
    assert(!encodeTvqmRemoveCommand(32, 8, remove));
    assert(!encodeTvqmRemoveCommand(7, 9, remove));
}

int main()
{
    testStationReservationUsesLiveBitmap();
    testFirmwareDrainResetRequiresAllP2pLeasesAbsent();
    testTvqmQueueRequiresDynamicUnreservedSlot();
    testLegacyQueueTwoConflictsWithMonitorInjection();
    testLegacyDynamicDqaDoesNotRequireStaticDqaCapability();
    testLegacyQueueLifetimeUsesStationRemovalAckAndCompletion();
    testNeverSubmittedQueueHasSeparateAckedRelease();
    testTxRingLifetimeWaitsForRemoveAndDrain();
    testActionFrameParserIsShapeOnly();
    testTvqmCommandEncodingIsLittleEndian();
    return 0;
}

