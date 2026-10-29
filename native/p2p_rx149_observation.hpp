// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_RX149_OBSERVATION_HPP
#define NATIVE_P2P_RX149_OBSERVATION_HPP

#include <stdint.h>

namespace NativeP2PRx149Observation {

constexpr uint16_t kIeeeChannel = 149;
constexpr uint32_t kSessionDurationMs = 100;
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

inline bool nativeDataPathAllowed(bool rx149ProfileSelected)
{
    return !rx149ProfileSelected;
}

} // namespace NativeP2PRx149Observation

#endif // NATIVE_P2P_RX149_OBSERVATION_HPP
