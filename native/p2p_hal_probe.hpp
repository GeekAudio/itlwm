// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_HAL_PROBE_HPP
#define NATIVE_P2P_HAL_PROBE_HPP

#include <stdint.h>

namespace NativeP2PProbe {

enum State : uint32_t {
    kIdle = 0,
    kDisabled = 1,
    kDeferred = 2,
    kQueued = 3,
    kAdding = 4,
    kAdded = 5,
    kRemoving = 6,
    kComplete = 7,
    kQuarantined = 8,
    kResetDrained = 9,
    // The diagnostic exercise failed, but a stable proof showed that it
    // never submitted a session and all ROC resources were restored. The
    // outer MAC lease was removed safely; this is still a failed exercise.
    kExerciseFailedCleaned = 10
};

enum BlockedReason : uint32_t {
    kNotBlocked = 0,
    kProbeDisabled = 1,
    kMainGateUnavailable = 2,
    kMainGateOnThread = 3,
    kDriverNotRunning = 4,
    kNotAssociated = 5,
    kPortUnauthorized = 6,
    kScanBusy = 7,
    kCommandBusy = 8,
    kStateQueueBusy = 9,
    kRadioKilled = 10,
    kShutdownOrHardwareError = 11,
    kP2pContextOwned = 12,
    kP2pCapabilityUnavailable = 13,
    kGenerationChanged = 14,
    kConfigureRejected = 15,
    kCanceledBeforeStart = 16,
    kFirmwareOutcomeUnknown = 17,
    kResetDrainedReason = 18,
    kGateActionFailed = 19,
    kProbeQueueBusy = 20,
    kExerciseOutcomeUnknown = 21,
    kNativeAwdlIdentityUnavailable = 22,
    kExerciseFailureRecovered = 23
};

enum class RunResult : uint8_t {
    kNotQueued,
    kDeferred,
    kCompleted,
    kExerciseFailedCleaned,
    kQuarantined
};

struct Admission {
    bool enabled;
    bool mainGateAvailable;
    bool mainGateNotOnThread;
    bool driverRunning;
    bool associated;
    bool portAuthorized;
    bool scanIdle;
    bool commandQueueIdle;
    bool stateQueuePaused;
    bool noPendingNewstate;
    bool radioAvailable;
    bool firmwareHealthy;
    bool p2pContextAbsent;
    bool p2pCapabilityAvailable;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
};

struct Revalidation {
    bool generationMatches;
    bool radioAvailable;
    bool firmwareHealthy;
    bool driverRunning;
    bool associated;
    bool portAuthorized;
    bool scanIdle;
    bool commandQueueIdle;
    bool stateQueuePaused;
    bool noPendingNewstate;
    bool p2pContextInitialized;
    bool p2pGenerationMatches;
    bool addAcknowledged;
    bool p2pMacAbsent;
    bool p2pMacActive;
    bool p2pBindingAbsent;
};

// Shared by the IOKit gate callbacks and host fault-injection tests.
BlockedReason admissionBlockReason(const Admission &admission,
                                   bool requireQueueLease);
BlockedReason revalidationBlockReason(const Revalidation &state,
                                      bool afterAddAcknowledgement);
bool commandOwnerAllowed(bool probeBusy, const void *ownerThread,
                         const void *currentThread, bool onMainWorkLoop,
                         bool inMainGate);
bool genericCommandBlocked(bool probeBusy, const void *ownerThread,
                           const void *currentThread, bool onMainWorkLoop,
                           bool inMainGate);

struct Snapshot {
    uint32_t state;
    uint32_t attempted;
    int32_t addResult;
    int32_t removeResult;
    uint32_t blocked;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t resourceMayExist;
    int32_t exerciseResult;
    uint32_t exerciseRecoveryAttempted;
    uint32_t exerciseRecoveryProofAccepted;
};

// Evidence used only after an exercise returns an error. A nonzero errno is
// preserved separately from proof that the failed operation can be cleaned
// up. Every identity/state field is required; absent or unknown evidence is
// represented as false and keeps the outer MAC lease quarantined.
struct ExerciseRecoveryProof {
    bool snapshotValid;
    bool snapshotStable;
    bool prepareAttemptMatches;
    bool prepareErrorMatches;
    bool ownerMatches;
    bool contextGenerationMatches;
    bool powerGenerationMatches;
    bool firmwareGenerationMatches;
    bool p2pFirmwareGenerationMatches;
    bool stationGenerationMatches;
    bool knownNotSubmittedSafeToAbort;
    bool fullyRestored;
    bool bindingAbsent;
    bool phyUnleased;
    bool rocIdle;
    bool restoreComplete;
    bool sessionProtectionSubmitReached;
    bool sessionOutcomeUnknown;
    bool txResourcesPresent;
    uint32_t prepareStep;
    int32_t prepareErrno;
    int32_t cleanupErrno;
    uint32_t attemptSerial;
    uint32_t snapshotRevision;
};

bool safeToRemoveAfterExerciseFailure(
    int32_t exerciseErrno, const ExerciseRecoveryProof &proof);

struct Operations {
    void *context;
    BlockedReason (*revalidate)(void *, uint32_t powerGeneration,
                                uint32_t stationGeneration);
    int (*configure)(void *);
    int (*add)(void *);
    int (*remove)(void *);
    // The callback runs on each boundary where the firmware may have acquired
    // or released the MAC resource. It only publishes a software lease.
    bool (*publishLease)(void *, bool resourceMayExist);
    // Optional independent hardware exercise after MAC ADD. Zero certifies
    // its resources were drained/released, so the MAC may be removed. Any
    // error retains the MAC lease unless the optional recovery callback
    // supplies the complete, matching cleanup proof below.
    int (*exercise)(void *) {nullptr};
    // Called only after exercise returns nonzero. The callback may perform
    // only the cleanup already authorized by its production protocol, then
    // must return a stable proof. A positive callback return or incomplete
    // proof never authorizes MAC REMOVE.
    bool (*exerciseRecovery)(void *, int32_t exerciseErrno,
                             ExerciseRecoveryProof *) {nullptr};
};

class Controller {
public:
    Controller();

    // Called from the main command gate. stateQueuePaused must represent a
    // successful zero-wait taskq_try_pause() on the station newstate queue.
    bool tryQueue(const Admission &admission, BlockedReason overrideReason =
                      kNotBlocked);
    void cancelQueued();

    // Runs only from the systq worker with command ownership installed. It
    // performs at most one MAC_ADD and, only after its ACK, one MAC_REMOVE.
    RunResult executeOnce(const Operations &operations);

    // Call only after the caller has proven stop_device/RX drain completed.
    // The one-shot attempted bit intentionally survives the hardware reset.
    void resetDrained(uint32_t newPowerGeneration);
    void markGateActionFailed();
    Snapshot snapshot() const;

private:
    bool terminal() const;
    void storeState(uint32_t state, uint32_t blocked);
    void quarantine(uint32_t blocked, bool resourceMayExist);

    uint32_t state_;
    uint32_t attempted_;
    int32_t addResult_;
    int32_t removeResult_;
    uint32_t blocked_;
    uint32_t contextGeneration_;
    uint32_t powerGeneration_;
    uint32_t stationGeneration_;
    uint32_t resourceMayExist_;
    int32_t exerciseResult_;
    uint32_t exerciseRecoveryAttempted_;
    uint32_t exerciseRecoveryProofAccepted_;
};

} // namespace NativeP2PProbe

#endif // NATIVE_P2P_HAL_PROBE_HPP
