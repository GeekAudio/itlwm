// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_RX149_OBSERVATION_HPP
#define NATIVE_P2P_RX149_OBSERVATION_HPP

#include <stdint.h>

namespace NativeP2PRx149Observation {

constexpr uint16_t kIeeeChannel = 149;
constexpr uint32_t kSessionDurationMs = 100;
constexpr uint32_t kP2PDeviceDiscoveryConfiguration = 2;
constexpr uint32_t kLegacyArmMode = 1;
constexpr uint32_t kRx149ArmMode = 2;

inline bool isRx149ArmMode(uint32_t mode)
{
    return mode == kRx149ArmMode;
}

inline bool isLegacyArmMode(uint32_t mode)
{
    return mode == kLegacyArmMode;
}

enum class ProfileStatus : uint8_t {
    kDisabled,
    kInvalidConfiguration,
    kReadyToArm,
    kSelected
};

struct ProfileInput {
    bool compiled;
    bool staticProfileEnabled;
    bool manualTrigger;
    bool genericProbeEnabled;
    bool manualArmGranted;
    bool legacyRocProbe;
    bool legacyTxProbe;
    bool legacyPsfObservation;
    bool legacyMifFollowup;
    bool legacyDiscovery;
    bool legacyCurrentAw;
    bool legacyFallback;
};

inline bool hasLegacyMode(const ProfileInput &input)
{
    return input.legacyRocProbe || input.legacyTxProbe ||
           input.legacyPsfObservation || input.legacyMifFollowup ||
           input.legacyDiscovery || input.legacyCurrentAw ||
           input.legacyFallback;
}

inline ProfileStatus evaluateProfile(const ProfileInput &input)
{
    if (!input.compiled || !input.staticProfileEnabled)
        return ProfileStatus::kDisabled;
    if (!input.manualTrigger || !input.genericProbeEnabled ||
        hasLegacyMode(input))
        return ProfileStatus::kInvalidConfiguration;
    return input.manualArmGranted ? ProfileStatus::kSelected :
                                    ProfileStatus::kReadyToArm;
}

// An RX-only request always suppresses the legacy TX route, including when
// this binary does not contain the matching feature macro. That mismatch must
// fail closed instead of falling back to the old TX profile.
inline bool hostTxBlocked(bool rxOnlyRequested)
{
    return rxOnlyRequested;
}

struct TxQuiescence {
    bool queueAbsent;
    bool ringAbsent;
    uint32_t outstandingTx;
    bool everDoorbelled;
    bool actionIdle;
    bool ticketArmed;
    bool ticketCompleted;
};

// This is a read-only preflight over existing TX state. Any prior or retained
// P2P TX activity blocks the observation run; it is never cleared here.
inline bool txQuiescent(const TxQuiescence &state)
{
    return state.queueAbsent && state.ringAbsent && state.outstandingTx == 0 &&
           !state.everDoorbelled && state.actionIdle && !state.ticketArmed &&
           !state.ticketCompleted;
}

struct RocEvidence {
    bool profileSelected;
    bool receiveObservationOnly;
    bool requestedChannel149;
    bool actualRocChannel149;
    bool rxChannel149;
    bool leaseActive;
    bool ownerCurrent;
    bool epochsMatch;
    bool tokenMatches;
    bool commandReturned;
    bool commandSucceeded;
    bool deviceDiscoveryConfiguration;
    bool startSeen;
    bool startSucceeded;
    bool endSeen;
    bool endConfirmed;
    bool outcomeUnknown;
};

inline bool validStartedOwner(const RocEvidence &evidence)
{
    return evidence.profileSelected && evidence.receiveObservationOnly &&
           evidence.requestedChannel149 && evidence.actualRocChannel149 &&
           evidence.leaseActive && evidence.ownerCurrent &&
           evidence.epochsMatch && evidence.tokenMatches &&
           evidence.commandReturned && evidence.commandSucceeded &&
           evidence.deviceDiscoveryConfiguration && evidence.startSeen &&
           evidence.startSucceeded && !evidence.outcomeUnknown;
}

inline bool mayConsumeManagementAction(const RocEvidence &evidence)
{
    return validStartedOwner(evidence) && evidence.rxChannel149 &&
           !evidence.endSeen;
}

// A successful exercise may return to the generic remove operation only after
// a confirmed END from the same observation-only ROC/owner/epoch.
inline bool mayReleaseAfterEnd(const RocEvidence &evidence)
{
    return validStartedOwner(evidence) && evidence.endSeen &&
           evidence.endConfirmed;
}

// A failed END is not a successful listen window. This separate evidence
// shape authorizes only the bounded resource-cleanup path after a canonical
// failed END from the currently owned RX149 session.
struct FailedEndCleanupEvidence {
    RocEvidence roc;
    bool sessionSubmitted;
    uint32_t commandApiVersion;
    uint32_t notificationApiVersion;
    uint32_t notificationRecordApi;
    uint32_t macIdAndColor;
    uint32_t configuration;
    int32_t commandResult;
    bool commandAckRecorded;
    bool cleanupAllowed;
    bool observedScheduledPair;
    bool timelineOwnerEpochAndTokenMatch;
    bool startCanonical;
    bool endCanonical;
    bool anomalyFree;
    bool observedInBoundedRead;
    bool expiredOrCanceled;
    uint64_t startNotificationSerial;
    uint64_t endNotificationSerial;
    uint64_t startMonotonicUs;
    uint64_t endMonotonicUs;
    bool startMonotonicPresent;
    bool endMonotonicPresent;
    uint32_t startStatus;
    uint32_t endStatus;
};

// Coherent post-cleanup receipt for the one failure case where the firmware
// submitted a listen session, reported canonical START=1/END=0, and the
// driver then ran the existing acknowledged binding/PHY cleanup. Revisions in
// this receipt belong to this object; they are not timeline or prepare-trace
// revisions and are advanced only by its single writer protocol below.
struct CleanupReceiptPayload {
    uint64_t ownerSerial;
    uint64_t startNotificationSerial;
    uint64_t endNotificationSerial;
    uint64_t startMonotonicUs;
    uint64_t endMonotonicUs;
    uint64_t timelineRevision;
    uint32_t attemptSerial;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t firmwareGeneration;
    uint32_t p2pFirmwareGeneration;
    uint32_t sessionToken;
    uint32_t configuration;
    uint32_t commandApiVersion;
    uint32_t notificationApiVersion;
    uint32_t notificationRecordApi;
    uint32_t macIdAndColor;
    uint32_t startStatus;
    uint32_t endStatus;
    int32_t exerciseErrno;
    int32_t commandResult;
    int32_t cleanupErrno;
    uint32_t commandSubmitted;
    uint32_t commandAcknowledged;
    uint32_t cleanupAllowed;
    uint32_t ownerEpochTokenMatch;
    uint32_t startCanonical;
    uint32_t endCanonical;
    uint32_t anomalyFree;
    uint32_t observedInBoundedRead;
    uint32_t expiredOrCanceled;
    uint32_t producerClosedAndDrained;
    uint32_t txQuiescent;
    uint32_t bindingActiveBeforeCleanup;
    uint32_t phyLeasedBeforeCleanup;
    uint32_t cleanupCalled;
    uint32_t bindingAbsentAfterCleanup;
    uint32_t phyUnleasedAfterCleanup;
    uint32_t rocRestoredAfterCleanup;
    uint32_t sessionOutcomeUnknown;
    uint32_t txResourcesPresent;
};

struct CleanupReceipt {
    uint32_t revision;
    CleanupReceiptPayload payload;
};

inline bool sameCleanupReceiptPayload(const CleanupReceiptPayload &a,
                                      const CleanupReceiptPayload &b)
{
#define RX149_SAME_RECEIPT_FIELD(field) (a.field == b.field)
    return RX149_SAME_RECEIPT_FIELD(ownerSerial) &&
        RX149_SAME_RECEIPT_FIELD(startNotificationSerial) &&
        RX149_SAME_RECEIPT_FIELD(endNotificationSerial) &&
        RX149_SAME_RECEIPT_FIELD(startMonotonicUs) &&
        RX149_SAME_RECEIPT_FIELD(endMonotonicUs) &&
        RX149_SAME_RECEIPT_FIELD(timelineRevision) &&
        RX149_SAME_RECEIPT_FIELD(attemptSerial) &&
        RX149_SAME_RECEIPT_FIELD(contextGeneration) &&
        RX149_SAME_RECEIPT_FIELD(powerGeneration) &&
        RX149_SAME_RECEIPT_FIELD(stationGeneration) &&
        RX149_SAME_RECEIPT_FIELD(firmwareGeneration) &&
        RX149_SAME_RECEIPT_FIELD(p2pFirmwareGeneration) &&
        RX149_SAME_RECEIPT_FIELD(sessionToken) &&
        RX149_SAME_RECEIPT_FIELD(configuration) &&
        RX149_SAME_RECEIPT_FIELD(commandApiVersion) &&
        RX149_SAME_RECEIPT_FIELD(notificationApiVersion) &&
        RX149_SAME_RECEIPT_FIELD(notificationRecordApi) &&
        RX149_SAME_RECEIPT_FIELD(macIdAndColor) &&
        RX149_SAME_RECEIPT_FIELD(startStatus) &&
        RX149_SAME_RECEIPT_FIELD(endStatus) &&
        RX149_SAME_RECEIPT_FIELD(exerciseErrno) &&
        RX149_SAME_RECEIPT_FIELD(commandResult) &&
        RX149_SAME_RECEIPT_FIELD(cleanupErrno) &&
        RX149_SAME_RECEIPT_FIELD(commandSubmitted) &&
        RX149_SAME_RECEIPT_FIELD(commandAcknowledged) &&
        RX149_SAME_RECEIPT_FIELD(cleanupAllowed) &&
        RX149_SAME_RECEIPT_FIELD(ownerEpochTokenMatch) &&
        RX149_SAME_RECEIPT_FIELD(startCanonical) &&
        RX149_SAME_RECEIPT_FIELD(endCanonical) &&
        RX149_SAME_RECEIPT_FIELD(anomalyFree) &&
        RX149_SAME_RECEIPT_FIELD(observedInBoundedRead) &&
        RX149_SAME_RECEIPT_FIELD(expiredOrCanceled) &&
        RX149_SAME_RECEIPT_FIELD(producerClosedAndDrained) &&
        RX149_SAME_RECEIPT_FIELD(txQuiescent) &&
        RX149_SAME_RECEIPT_FIELD(bindingActiveBeforeCleanup) &&
        RX149_SAME_RECEIPT_FIELD(phyLeasedBeforeCleanup) &&
        RX149_SAME_RECEIPT_FIELD(cleanupCalled) &&
        RX149_SAME_RECEIPT_FIELD(bindingAbsentAfterCleanup) &&
        RX149_SAME_RECEIPT_FIELD(phyUnleasedAfterCleanup) &&
        RX149_SAME_RECEIPT_FIELD(rocRestoredAfterCleanup) &&
        RX149_SAME_RECEIPT_FIELD(sessionOutcomeUnknown) &&
        RX149_SAME_RECEIPT_FIELD(txResourcesPresent);
#undef RX149_SAME_RECEIPT_FIELD
}

inline bool validCleanupReceiptPayload(const CleanupReceiptPayload &p,
                                       int32_t expectedExerciseErrno,
                                       uint32_t expectedMacIdAndColor)
{
    return p.ownerSerial != 0 && p.attemptSerial != 0 &&
        p.contextGeneration != 0 && p.powerGeneration != 0 &&
        p.stationGeneration != 0 && p.firmwareGeneration != 0 &&
        p.p2pFirmwareGeneration == p.firmwareGeneration &&
        p.sessionToken == p.contextGeneration &&
        p.timelineRevision != 0 && p.exerciseErrno == expectedExerciseErrno &&
        p.commandApiVersion == 1 && p.notificationApiVersion == 2 &&
        p.notificationRecordApi == 1 &&
        p.macIdAndColor == expectedMacIdAndColor && p.configuration == 2 &&
        p.commandSubmitted == 1 && p.commandAcknowledged == 1 &&
        p.commandResult == 0 && p.cleanupAllowed == 1 &&
        p.ownerEpochTokenMatch == 1 && p.startCanonical == 1 &&
        p.endCanonical == 1 && p.anomalyFree == 1 &&
        p.observedInBoundedRead == 1 && p.expiredOrCanceled == 0 &&
        p.startStatus == 1 && p.endStatus == 0 &&
        p.startNotificationSerial != 0 &&
        p.endNotificationSerial > p.startNotificationSerial &&
        p.startMonotonicUs != 0 && p.endMonotonicUs > p.startMonotonicUs &&
        p.producerClosedAndDrained == 1 && p.txQuiescent == 1 &&
        p.bindingActiveBeforeCleanup == 1 && p.phyLeasedBeforeCleanup == 1 &&
        p.cleanupCalled == 1 && p.cleanupErrno == 0 &&
        p.bindingAbsentAfterCleanup == 1 && p.phyUnleasedAfterCleanup == 1 &&
        p.rocRestoredAfterCleanup == 1 && p.sessionOutcomeUnknown == 0 &&
        p.txResourcesPresent == 0;
}

inline bool publishCleanupReceipt(CleanupReceipt *receipt,
                                  const CleanupReceiptPayload &first,
                                  const CleanupReceiptPayload &second,
                                  int32_t expectedExerciseErrno,
                                  uint32_t expectedMacIdAndColor)
{
    if (!receipt || !sameCleanupReceiptPayload(first, second) ||
        !validCleanupReceiptPayload(second, expectedExerciseErrno,
                                    expectedMacIdAndColor))
        return false;
    const uint32_t current = __atomic_load_n(&receipt->revision,
                                              __ATOMIC_ACQUIRE);
    if (current & 1u || current > UINT32_MAX - 2u)
        return false;
    __atomic_store_n(&receipt->revision, current + 1u, __ATOMIC_RELEASE);
    receipt->payload = second;
    __atomic_store_n(&receipt->revision, current + 2u, __ATOMIC_RELEASE);
    return true;
}

template <typename BetweenRevisionReads>
inline bool readCleanupReceipt(const CleanupReceipt *receipt,
                               CleanupReceiptPayload *payload,
                               uint32_t *revision,
                               BetweenRevisionReads betweenReads)
{
    if (!receipt || !payload || !revision)
        return false;
    const uint32_t before = __atomic_load_n(&receipt->revision,
                                             __ATOMIC_ACQUIRE);
    if (before == 0 || (before & 1u))
        return false;
    const CleanupReceiptPayload copy = receipt->payload;
    betweenReads();
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    const uint32_t after = __atomic_load_n(&receipt->revision,
                                            __ATOMIC_ACQUIRE);
    if (before != after || (after & 1u))
        return false;
    *payload = copy;
    *revision = after;
    return true;
}

inline bool readCleanupReceipt(const CleanupReceipt *receipt,
                               CleanupReceiptPayload *payload,
                               uint32_t *revision)
{
    return readCleanupReceipt(receipt, payload, revision, [] {});
}

inline bool cleanupReceiptIdentityMatches(
    const CleanupReceiptPayload &p, uint64_t ownerSerial,
    uint32_t attemptSerial, uint32_t contextGeneration,
    uint32_t powerGeneration, uint32_t stationGeneration,
    uint32_t firmwareGeneration, uint32_t sessionToken)
{
    return p.ownerSerial != 0 && p.ownerSerial == ownerSerial &&
        p.attemptSerial != 0 && p.attemptSerial == attemptSerial &&
        p.contextGeneration != 0 && p.contextGeneration == contextGeneration &&
        p.powerGeneration != 0 && p.powerGeneration == powerGeneration &&
        p.stationGeneration != 0 && p.stationGeneration == stationGeneration &&
        p.firmwareGeneration != 0 && p.firmwareGeneration == firmwareGeneration &&
        p.p2pFirmwareGeneration == firmwareGeneration &&
        p.sessionToken != 0 && p.sessionToken == sessionToken;
}

inline bool mayCleanupAfterFailedEnd(const FailedEndCleanupEvidence &evidence)
{
    return validStartedOwner(evidence.roc) && evidence.roc.endSeen &&
           !evidence.roc.endConfirmed && evidence.sessionSubmitted &&
           evidence.commandApiVersion == 1 &&
           evidence.notificationApiVersion == 2 &&
           evidence.notificationRecordApi == 1 &&
           evidence.macIdAndColor == 1 &&
           evidence.configuration == kP2PDeviceDiscoveryConfiguration &&
           evidence.commandResult == 0 && evidence.commandAckRecorded &&
           evidence.cleanupAllowed && !evidence.observedScheduledPair &&
           evidence.timelineOwnerEpochAndTokenMatch &&
           evidence.startCanonical && evidence.endCanonical &&
           evidence.anomalyFree && evidence.observedInBoundedRead &&
           !evidence.expiredOrCanceled && evidence.startStatus == 1 &&
           evidence.endStatus == 0 &&
           evidence.startNotificationSerial != 0 &&
           evidence.endNotificationSerial > evidence.startNotificationSerial &&
           evidence.startMonotonicPresent && evidence.endMonotonicPresent &&
           evidence.startMonotonicUs != 0 && evidence.endMonotonicUs != 0 &&
           evidence.endMonotonicUs > evidence.startMonotonicUs;
}

inline bool nativeDataPathAllowed(bool rx149ProfileSelected)
{
    return !rx149ProfileSelected;
}

} // namespace NativeP2PRx149Observation

#endif // NATIVE_P2P_RX149_OBSERVATION_HPP
