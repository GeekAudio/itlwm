// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_hal_probe.hpp"
#include "../p2p_rx149_observation.hpp"

#include <assert.h>
#include <errno.h>
#include <stdint.h>

namespace {

NativeP2PRx149Observation::ProfileInput validProfile()
{
    return {true, true, true, true, false,
            false, false, false, false, false, false, false};
}

NativeP2PRx149Observation::RocEvidence activeWindow()
{
    return {true, true, true, true, true, true, true, true, true,
            true, true, true, true, true, false, false, false};
}

NativeP2PRx149Observation::FailedEndCleanupEvidence failedEnd()
{
    auto roc = activeWindow();
    roc.endSeen = true;
    return {roc, true, 1, 2, 1, 1, 2, 0, true, true, false,
            true, true, true, true, true, false,
            8, 13, 1000, 101000, true, true, 1, 0};
}

NativeP2PRx149Observation::CleanupReceiptPayload validCleanupReceipt()
{
    using NativeP2PRx149Observation::CleanupReceiptPayload;
    CleanupReceiptPayload p{};
    p.ownerSerial = 7;
    p.startNotificationSerial = 8;
    p.endNotificationSerial = 13;
    p.startMonotonicUs = 1000;
    p.endMonotonicUs = 101000;
    p.timelineRevision = 42;
    p.attemptSerial = 53;
    p.contextGeneration = 53;
    p.powerGeneration = 41;
    p.stationGeneration = 59;
    p.firmwareGeneration = 41;
    p.p2pFirmwareGeneration = 41;
    p.sessionToken = 53;
    p.configuration = 2;
    p.commandApiVersion = 1;
    p.notificationApiVersion = 2;
    p.notificationRecordApi = 1;
    p.macIdAndColor = 0x1001;
    p.startStatus = 1;
    p.endStatus = 0;
    p.exerciseErrno = EPROTO;
    p.commandResult = 0;
    p.cleanupErrno = 0;
    p.commandSubmitted = 1;
    p.commandAcknowledged = 1;
    p.cleanupAllowed = 1;
    p.ownerEpochTokenMatch = 1;
    p.startCanonical = 1;
    p.endCanonical = 1;
    p.anomalyFree = 1;
    p.observedInBoundedRead = 1;
    p.producerClosedAndDrained = 1;
    p.txQuiescent = 1;
    p.bindingActiveBeforeCleanup = 1;
    p.phyLeasedBeforeCleanup = 1;
    p.cleanupCalled = 1;
    p.bindingAbsentAfterCleanup = 1;
    p.phyUnleasedAfterCleanup = 1;
    p.rocRestoredAfterCleanup = 1;
    return p;
}

struct Transaction {
    NativeP2PRx149Observation::RocEvidence evidence;
    uint32_t removeCalls;
    uint32_t transmitCalls;
};

NativeP2PProbe::BlockedReason revalidate(void *, uint32_t, uint32_t)
{
    return NativeP2PProbe::kNotBlocked;
}

int configure(void *) { return 0; }
int add(void *) { return 0; }
int remove(void *opaque)
{
    ++static_cast<Transaction *>(opaque)->removeCalls;
    return 0;
}
bool publishLease(void *, bool) { return true; }

int observeOnlyExercise(void *opaque)
{
    auto *transaction = static_cast<Transaction *>(opaque);
    if (!NativeP2PRx149Observation::hostTxBlocked(true))
        ++transaction->transmitCalls;
    return NativeP2PRx149Observation::mayReleaseAfterEnd(
        transaction->evidence) ? 0 : EBUSY;
}

NativeP2PProbe::Admission readyAdmission()
{
    return {true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, 7, 11, 13};
}

NativeP2PProbe::Operations operations(Transaction *transaction)
{
    return {transaction, revalidate, configure, add, remove, publishLease,
            observeOnlyExercise};
}

} // namespace

int main()
{
    using namespace NativeP2PRx149Observation;

    assert(isLegacyArmMode(kLegacyArmMode));
    assert(!isRx149ArmMode(kLegacyArmMode));
    assert(isRx149ArmMode(kRx149ArmMode));
    assert(!isLegacyArmMode(kRx149ArmMode));

    auto profile = validProfile();
    assert(evaluateProfile(profile) == ProfileStatus::kReadyToArm);
    profile.manualArmGranted = true;
    assert(evaluateProfile(profile) == ProfileStatus::kSelected);
    assert(hostTxBlocked(true));
    assert(!hostTxBlocked(false));

    profile = validProfile();
    profile.compiled = false;
    assert(evaluateProfile(profile) == ProfileStatus::kDisabled);
    profile = validProfile();
    profile.staticProfileEnabled = false;
    assert(evaluateProfile(profile) == ProfileStatus::kDisabled);
    profile = validProfile();
    profile.manualTrigger = false;
    assert(evaluateProfile(profile) == ProfileStatus::kInvalidConfiguration);
    profile = validProfile();
    profile.genericProbeEnabled = false;
    assert(evaluateProfile(profile) == ProfileStatus::kInvalidConfiguration);
    for (unsigned legacy = 0; legacy != 7; ++legacy) {
        profile = validProfile();
        switch (legacy) {
            case 0: profile.legacyRocProbe = true; break;
            case 1: profile.legacyTxProbe = true; break;
            case 2: profile.legacyPsfObservation = true; break;
            case 3: profile.legacyMifFollowup = true; break;
            case 4: profile.legacyDiscovery = true; break;
            case 5: profile.legacyCurrentAw = true; break;
            case 6: profile.legacyFallback = true; break;
        }
        assert(evaluateProfile(profile) ==
               ProfileStatus::kInvalidConfiguration);
    }

    TxQuiescence tx{true, true, 0, false, true, false, false};
    assert(txQuiescent(tx));
    tx.everDoorbelled = true;
    assert(!txQuiescent(tx));
    tx.everDoorbelled = false;
    tx.queueAbsent = false;
    assert(!txQuiescent(tx));
    tx.queueAbsent = true;
    tx.ringAbsent = false;
    assert(!txQuiescent(tx));
    tx.ringAbsent = true;
    tx.outstandingTx = 1;
    assert(!txQuiescent(tx));
    tx.outstandingTx = 0;
    tx.actionIdle = false;
    assert(!txQuiescent(tx));
    tx.actionIdle = true;
    tx.ticketArmed = true;
    assert(!txQuiescent(tx));
    tx.ticketArmed = false;
    tx.ticketCompleted = true;
    assert(!txQuiescent(tx));

    const RocEvidence active = activeWindow();
    assert(mayConsumeManagementAction(active));
    assert(!mayReleaseAfterEnd(active));
    assert(!nativeDataPathAllowed(true));
    assert(nativeDataPathAllowed(false));

    const auto failed = failedEnd();
    assert(mayCleanupAfterFailedEnd(failed));
    assert(!mayReleaseAfterEnd(failed.roc));

    // The failed-END cleanup route requires exact current-session identity,
    // command/notification APIs, canonical ordered boundaries, and a bounded
    // successful read. A failed or missing item never weakens the normal
    // successful-END predicate.
    auto rejectFailedEnd = [&](FailedEndCleanupEvidence invalid) {
        assert(!mayCleanupAfterFailedEnd(invalid));
    };
    { auto e = failed; e.roc.profileSelected = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.receiveObservationOnly = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.requestedChannel149 = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.actualRocChannel149 = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.leaseActive = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.ownerCurrent = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.epochsMatch = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.tokenMatches = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.commandReturned = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.commandSucceeded = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.deviceDiscoveryConfiguration = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.startSeen = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.startSucceeded = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.endSeen = false; rejectFailedEnd(e); }
    { auto e = failed; e.roc.endConfirmed = true; rejectFailedEnd(e); }
    { auto e = failed; e.roc.outcomeUnknown = true; rejectFailedEnd(e); }
    { auto e = failed; e.sessionSubmitted = false; rejectFailedEnd(e); }
    { auto e = failed; e.commandApiVersion = 0; rejectFailedEnd(e); }
    { auto e = failed; e.notificationApiVersion = 1; rejectFailedEnd(e); }
    { auto e = failed; e.notificationRecordApi = 2; rejectFailedEnd(e); }
    { auto e = failed; e.macIdAndColor = 2; rejectFailedEnd(e); }
    { auto e = failed; e.configuration = 3; rejectFailedEnd(e); }
    { auto e = failed; e.commandResult = EBUSY; rejectFailedEnd(e); }
    { auto e = failed; e.commandAckRecorded = false; rejectFailedEnd(e); }
    { auto e = failed; e.cleanupAllowed = false; rejectFailedEnd(e); }
    { auto e = failed; e.observedScheduledPair = true; rejectFailedEnd(e); }
    { auto e = failed; e.timelineOwnerEpochAndTokenMatch = false; rejectFailedEnd(e); }
    { auto e = failed; e.startCanonical = false; rejectFailedEnd(e); }
    { auto e = failed; e.endCanonical = false; rejectFailedEnd(e); }
    { auto e = failed; e.anomalyFree = false; rejectFailedEnd(e); }
    { auto e = failed; e.observedInBoundedRead = false; rejectFailedEnd(e); }
    { auto e = failed; e.expiredOrCanceled = true; rejectFailedEnd(e); }
    { auto e = failed; e.endNotificationSerial = e.startNotificationSerial; rejectFailedEnd(e); }
    { auto e = failed; e.startMonotonicPresent = false; rejectFailedEnd(e); }
    { auto e = failed; e.endMonotonicPresent = false; rejectFailedEnd(e); }
    { auto e = failed; e.startMonotonicUs = 0; rejectFailedEnd(e); }
    { auto e = failed; e.endMonotonicUs = e.startMonotonicUs; rejectFailedEnd(e); }
    { auto e = failed; e.startStatus = 0; rejectFailedEnd(e); }
    { auto e = failed; e.endStatus = 1; rejectFailedEnd(e); }

    using namespace NativeP2PRx149Observation;
    constexpr uint32_t expectedMacIdAndColor = 0x1001;
    CleanupReceipt receipt{};
    auto first = validCleanupReceipt();
    auto second = first;
    assert(publishCleanupReceipt(&receipt, first, second, EPROTO,
                                 expectedMacIdAndColor));
    assert(receipt.revision == 2);
    CleanupReceiptPayload copied{};
    uint32_t revision = 0;
    assert(readCleanupReceipt(&receipt, &copied, &revision));
    assert(revision == 2 && sameCleanupReceiptPayload(copied, first));
    assert(validCleanupReceiptPayload(copied, EPROTO,
                                      expectedMacIdAndColor));
    assert(cleanupReceiptIdentityMatches(
        copied, 7, 53, 53, 41, 59, 41, 53));
    assert(!cleanupReceiptIdentityMatches(
        copied, 7, 53, 53, 41, 60, 41, 53)); // station epoch changed

    { auto changed = second; changed.timelineRevision++;
      assert(!publishCleanupReceipt(&receipt, first, changed, EPROTO,
                                    expectedMacIdAndColor)); }
    { auto failedCleanup = second; failedCleanup.cleanupErrno = EBUSY;
      assert(!publishCleanupReceipt(&receipt, first, failedCleanup, EPROTO,
                                    expectedMacIdAndColor)); }
    { auto postStateMismatch = second; postStateMismatch.bindingAbsentAfterCleanup = 0;
      assert(!publishCleanupReceipt(&receipt, first, postStateMismatch, EPROTO,
                                    expectedMacIdAndColor)); }
    { auto expired = second; expired.expiredOrCanceled = 1;
      assert(!publishCleanupReceipt(&receipt, first, expired, EPROTO,
                                    expectedMacIdAndColor)); }
    { auto outsideWindow = second; outsideWindow.observedInBoundedRead = 0;
      assert(!publishCleanupReceipt(&receipt, first, outsideWindow, EPROTO,
                                    expectedMacIdAndColor)); }
    { auto lateEnd = second; lateEnd.endMonotonicUs = lateEnd.startMonotonicUs;
      assert(!publishCleanupReceipt(&receipt, first, lateEnd, EPROTO,
                                    expectedMacIdAndColor)); }

    // Simulate a writer changing the sequence after the reader copied the
    // payload. A torn read is inconclusive and cannot become a cleanup proof.
    copied = {};
    revision = 0;
    assert(!readCleanupReceipt(&receipt, &copied, &revision, [&] {
        __atomic_store_n(&receipt.revision, 3u, __ATOMIC_RELEASE);
    }));

    // Every owner, epoch, channel, mode, command, START, and END prerequisite
    // is independently required; a prior/foreign event cannot gain authority
    // when the consumer drains later.
    for (unsigned field = 0; field != 17; ++field) {
        RocEvidence invalid = active;
        switch (field) {
            case 0: invalid.profileSelected = false; break;
            case 1: invalid.receiveObservationOnly = false; break;
            case 2: invalid.requestedChannel149 = false; break;
            case 3: invalid.actualRocChannel149 = false; break;
            case 4: invalid.rxChannel149 = false; break;
            case 5: invalid.leaseActive = false; break;
            case 6: invalid.ownerCurrent = false; break;
            case 7: invalid.epochsMatch = false; break;
            case 8: invalid.tokenMatches = false; break;
            case 9: invalid.commandReturned = false; break;
            case 10: invalid.commandSucceeded = false; break;
            case 11: invalid.deviceDiscoveryConfiguration = false; break;
            case 12: invalid.startSeen = false; break;
            case 13: invalid.startSucceeded = false; break;
            case 14: invalid.endSeen = true; break;
            case 15: invalid.endSeen = true; invalid.endConfirmed = false; break;
            case 16: invalid.outcomeUnknown = true; break;
        }
        assert(!mayConsumeManagementAction(invalid));
        assert(!mayReleaseAfterEnd(invalid));
    }

    // An END from the same selected owner allows cleanup; a missing END or a
    // foreign generation leaves the MAC lease quarantined and never calls
    // remove. The observation exercise has no TX call site.
    Transaction incomplete{active, 0, 0};
    NativeP2PProbe::Controller blocked;
    assert(blocked.tryQueue(readyAdmission()));
    assert(blocked.executeOnce(operations(&incomplete)) ==
           NativeP2PProbe::RunResult::kQuarantined);
    assert(incomplete.removeCalls == 0 && incomplete.transmitCalls == 0);

    Transaction ended{active, 0, 0};
    ended.evidence.endSeen = true;
    ended.evidence.endConfirmed = true;
    NativeP2PProbe::Controller completed;
    assert(completed.tryQueue(readyAdmission()));
    assert(completed.executeOnce(operations(&ended)) ==
           NativeP2PProbe::RunResult::kCompleted);
    assert(ended.removeCalls == 1 && ended.transmitCalls == 0);

    Transaction staleEnd{active, 0, 0};
    staleEnd.evidence.endSeen = true;
    staleEnd.evidence.endConfirmed = true;
    staleEnd.evidence.epochsMatch = false;
    NativeP2PProbe::Controller stale;
    assert(stale.tryQueue(readyAdmission()));
    assert(stale.executeOnce(operations(&staleEnd)) ==
           NativeP2PProbe::RunResult::kQuarantined);
    assert(staleEnd.removeCalls == 0 && staleEnd.transmitCalls == 0);
    return 0;
}
