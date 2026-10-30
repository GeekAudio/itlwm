// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_RX149_DATA_INPUT_HPP
#define NATIVE_P2P_RX149_DATA_INPUT_HPP

#include <stdint.h>

namespace NativeP2PRx149DataInput {

constexpr uint16_t kIeeeChannel = 149;
constexpr uint64_t kSessionWindowUs = 100000ULL;
constexpr uint64_t kMaximumQueuedAgeUs = 100000ULL;
constexpr uint32_t kMacPhyDecodeLegacy = 1;
constexpr uint32_t kMacPhyDecodeBandInRx = 2;

struct Epochs {
    uint32_t context;
    uint32_t power;
    uint32_t station;
    uint32_t roc;
};

inline bool sameEpochs(const Epochs &left, const Epochs &right)
{
    return left.context == right.context && left.power == right.power &&
        left.station == right.station && left.roc == right.roc;
}

// This is a short-lived view of a currently accepted, observation-only ROC
// owner. It contains numeric evidence only; it owns no driver/firmware state.
struct Lease {
    bool compiled;
    bool runtimeEnabled;
    bool profileEnabled;
    bool profileSelected;
    bool receiveObservationOnly;
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
    bool outcomeUnknown;
    Epochs epochs;
    uint64_t ownerSerial;
    uint64_t startUs;
    uint64_t nowUs;
};

// Only valid when carried from the original RX MPDU descriptor before the
// normal input path strips hardware aggregation/protection metadata.
struct OriginalDescriptor {
    bool present;
    bool protectedFrame;
    bool hardwareDeaggregated;
    uint32_t rawStatus;
};

// mac_phy_idx is intentionally retained as raw descriptor evidence. Only its
// low MAC-index nibble is decoded; API59's PHY/band bits are not interpreted.
struct Descriptor {
    bool channelPresent;
    uint16_t ieeeChannel;
    bool macPhyIndexPresent;
    uint8_t macPhyIndex;
    bool decodeModePresent;
    uint32_t decodeMode;
    bool protectedFrame;
    bool awdlDataCandidate;
    bool originalDescriptorPresent;
    bool hardwareDeaggregated;
    uint32_t originalRawStatus;
};

// Copyable capability for one MPDU. The deadline is the earlier of the ROC
// window end and one bounded queue lifetime after capture.
struct Permit {
    bool valid;
    Epochs epochs;
    uint64_t ownerSerial;
    uint64_t startUs;
    uint64_t capturedUs;
    uint64_t deadlineUs;
    uint16_t ieeeChannel;
    uint8_t macIndex;
    uint32_t decodeMode;
    uint32_t originalRawStatus;
};

inline bool validEpochs(const Epochs &epochs)
{
    return epochs.context != 0 && epochs.power != 0 &&
        epochs.station != 0 && epochs.roc != 0 &&
        epochs.context == epochs.roc;
}

inline bool leaseCurrent(const Lease &lease, uint64_t nowUs)
{
    if (!lease.compiled || !lease.runtimeEnabled || !lease.profileEnabled ||
        !lease.profileSelected || !lease.receiveObservationOnly ||
        !lease.leaseActive || !lease.ownerCurrent || !lease.epochsMatch ||
        !lease.tokenMatches || !lease.commandReturned ||
        !lease.commandSucceeded || !lease.deviceDiscoveryConfiguration ||
        !lease.startSeen || !lease.startSucceeded || lease.endSeen ||
        lease.outcomeUnknown || !validEpochs(lease.epochs) ||
        lease.ownerSerial == 0 || lease.startUs == 0 || nowUs < lease.startUs)
        return false;
    return nowUs - lease.startUs < kSessionWindowUs;
}

inline bool verifiedMacIndexOne(const Descriptor &descriptor)
{
    if (!descriptor.macPhyIndexPresent || !descriptor.decodeModePresent ||
        (descriptor.decodeMode != kMacPhyDecodeLegacy &&
         descriptor.decodeMode != kMacPhyDecodeBandInRx))
        return false;
    return (descriptor.macPhyIndex & 0x0fu) == 1u;
}

inline bool makePermit(const Lease &lease, const Descriptor &descriptor,
                       Permit *out)
{
    if (!out)
        return false;
    *out = Permit{};
    if (!leaseCurrent(lease, lease.nowUs) || !descriptor.channelPresent ||
        descriptor.ieeeChannel != kIeeeChannel ||
        !verifiedMacIndexOne(descriptor) || descriptor.protectedFrame ||
        !descriptor.awdlDataCandidate ||
        !descriptor.originalDescriptorPresent ||
        descriptor.hardwareDeaggregated ||
        lease.startUs > UINT64_MAX - kSessionWindowUs ||
        lease.nowUs > UINT64_MAX - kMaximumQueuedAgeUs)
        return false;

    const uint64_t sessionDeadline = lease.startUs + kSessionWindowUs;
    const uint64_t queueDeadline = lease.nowUs + kMaximumQueuedAgeUs;
    Permit permit{};
    permit.valid = true;
    permit.epochs = lease.epochs;
    permit.ownerSerial = lease.ownerSerial;
    permit.startUs = lease.startUs;
    permit.capturedUs = lease.nowUs;
    permit.deadlineUs = sessionDeadline < queueDeadline ?
        sessionDeadline : queueDeadline;
    permit.ieeeChannel = descriptor.ieeeChannel;
    permit.macIndex = descriptor.macPhyIndex & 0x0fu;
    permit.decodeMode = descriptor.decodeMode;
    permit.originalRawStatus = descriptor.originalRawStatus;
    *out = permit;
    return true;
}

inline bool stillCurrent(const Permit &permit, const Lease &lease,
                         uint64_t nowUs)
{
    return permit.valid && leaseCurrent(lease, nowUs) &&
        sameEpochs(permit.epochs, lease.epochs) &&
        permit.ownerSerial == lease.ownerSerial &&
        permit.startUs == lease.startUs &&
        nowUs >= permit.capturedUs && nowUs < permit.deadlineUs &&
        nowUs - permit.capturedUs <= kMaximumQueuedAgeUs;
}

} // namespace NativeP2PRx149DataInput

#endif // NATIVE_P2P_RX149_DATA_INPUT_HPP
