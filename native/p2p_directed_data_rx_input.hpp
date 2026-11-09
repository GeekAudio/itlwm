// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_P2P_DIRECTED_DATA_RX_INPUT_HPP
#define NATIVE_P2P_DIRECTED_DATA_RX_INPUT_HPP

#include <stdint.h>
#include <string.h>
#include "iwx_mcc_refresh_policy.hpp"

namespace NativeP2PDirectedDataRxInput {

constexpr uint32_t kOwnerArmMode = 4;
constexpr uint16_t kIeeeChannel = 6;
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

struct Lease {
    bool compiled;
    bool runtimeEnabled;
    bool profileEnabled;
    bool profileSelected;
    bool ownerCurrent;
    bool epochsMatch;
    bool tokenMatches;
    bool commandReturned;
    bool commandSucceeded;
    bool goNegotiationConfiguration;
    bool channel6Roc;
    bool startSeen;
    bool startSucceeded;
    bool endSeen;
    bool outcomeUnknown;
    bool mccCurrent;
    Epochs epochs;
    uint64_t ownerSerial;
    uint64_t startUs;
    uint64_t deadlineUs;
    uint64_t nowUs;
    uint64_t mccRevision;
    uint64_t mccNoticeGeneration;
    uint64_t mccSourceGeneration;
    uint64_t mccAppliedNoticeGeneration;
    uint32_t mccOrigin;
    uint32_t mccRequestSequence;
    uint32_t mccNoticeEpoch;
    uint32_t mccResponseStatus;
    uint32_t mccResponseChannelCount;
    uint8_t peerMac[6];
    uint8_t localMac[6];
};

struct OriginalDescriptor {
    bool present;
    bool protectedFrame;
    bool hardwareDeaggregated;
    uint32_t rawStatus;
};

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
    bool sourceMacPresent;
    uint8_t sourceMac[6];
};

struct Permit {
    bool valid;
    Epochs epochs;
    uint64_t ownerSerial;
    uint64_t startUs;
    uint64_t leaseDeadlineUs;
    uint64_t capturedUs;
    uint64_t deadlineUs;
    uint64_t mccRevision;
    uint32_t mccOrigin;
    uint32_t mccRequestSequence;
    uint32_t mccNoticeEpoch;
    uint16_t ieeeChannel;
    uint8_t macIndex;
    uint32_t decodeMode;
    uint32_t originalRawStatus;
    uint8_t peerMac[6];
    uint8_t localMac[6];
};

inline bool validUnicastMac(const uint8_t mac[6])
{
    if (!mac || (mac[0] & 1u) != 0)
        return false;
    uint8_t any = 0;
    for (unsigned index = 0; index < 6; ++index)
        any |= mac[index];
    return any != 0;
}

inline bool validEpochs(const Epochs &epochs)
{
    return epochs.context != 0 && epochs.power != 0 &&
        epochs.station != 0 && epochs.roc != 0 &&
        epochs.context == epochs.roc;
}

inline bool sameLeaseIdentity(const Lease &left, const Lease &right)
{
    return left.ownerSerial == right.ownerSerial &&
        left.startUs == right.startUs && left.deadlineUs == right.deadlineUs &&
        left.mccRevision == right.mccRevision &&
        left.mccNoticeGeneration == right.mccNoticeGeneration &&
        left.mccSourceGeneration == right.mccSourceGeneration &&
        left.mccAppliedNoticeGeneration == right.mccAppliedNoticeGeneration &&
        left.mccOrigin == right.mccOrigin &&
        left.mccRequestSequence == right.mccRequestSequence &&
        left.mccNoticeEpoch == right.mccNoticeEpoch &&
        left.mccResponseStatus == right.mccResponseStatus &&
        left.mccResponseChannelCount == right.mccResponseChannelCount &&
        sameEpochs(left.epochs, right.epochs) &&
        memcmp(left.peerMac, right.peerMac, sizeof(left.peerMac)) == 0 &&
        memcmp(left.localMac, right.localMac, sizeof(left.localMac)) == 0;
}

inline bool leaseCurrent(const Lease &lease, uint64_t nowUs)
{
    const bool chub = lease.mccOrigin == IwxMccRefreshPolicy::kRequestOriginChubNotification &&
        lease.mccRequestSequence == 0 && lease.mccNoticeEpoch != 0 &&
        lease.mccNoticeGeneration == lease.mccNoticeEpoch &&
        lease.mccAppliedNoticeGeneration == lease.mccNoticeGeneration;
    const bool init = lease.mccOrigin == IwxMccRefreshPolicy::kRequestOriginInitGetCurrent &&
        lease.mccRequestSequence != 0 && lease.mccNoticeGeneration == 0 &&
        lease.mccAppliedNoticeGeneration == 0;
    return lease.compiled && lease.runtimeEnabled && lease.profileEnabled &&
        lease.profileSelected && lease.ownerCurrent && lease.epochsMatch &&
        lease.tokenMatches && lease.commandReturned && lease.commandSucceeded &&
        lease.goNegotiationConfiguration && lease.channel6Roc &&
        lease.startSeen && lease.startSucceeded && !lease.endSeen &&
        !lease.outcomeUnknown && lease.mccCurrent && validEpochs(lease.epochs) &&
        lease.ownerSerial != 0 && lease.startUs != 0 &&
        lease.startUs <= UINT64_MAX - kSessionWindowUs &&
        lease.deadlineUs == lease.startUs + kSessionWindowUs &&
        lease.mccRevision != 0 && (lease.mccRevision & 1u) == 0 &&
        (chub || init) && (lease.mccNoticeEpoch & 1u) == 0 &&
        lease.mccSourceGeneration == lease.epochs.power &&
        (lease.mccResponseStatus == 0 || lease.mccResponseStatus == 1) &&
        lease.mccResponseChannelCount == 51 &&
        validUnicastMac(lease.peerMac) && validUnicastMac(lease.localMac) &&
        memcmp(lease.peerMac, lease.localMac, 6) != 0 && nowUs >= lease.startUs &&
        nowUs < lease.deadlineUs;
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
        descriptor.hardwareDeaggregated || !descriptor.sourceMacPresent ||
        memcmp(descriptor.sourceMac, lease.peerMac, 6) != 0 ||
        lease.startUs > UINT64_MAX - kSessionWindowUs ||
        lease.nowUs > UINT64_MAX - kMaximumQueuedAgeUs)
        return false;

    const uint64_t sessionDeadline = lease.deadlineUs;
    const uint64_t queueDeadline = lease.nowUs + kMaximumQueuedAgeUs;
    Permit permit{};
    permit.valid = true;
    permit.epochs = lease.epochs;
    permit.ownerSerial = lease.ownerSerial;
    permit.startUs = lease.startUs;
    permit.leaseDeadlineUs = lease.deadlineUs;
    permit.capturedUs = lease.nowUs;
    permit.deadlineUs = sessionDeadline < queueDeadline ?
        sessionDeadline : queueDeadline;
    permit.mccRevision = lease.mccRevision;
    permit.mccOrigin = lease.mccOrigin;
    permit.mccRequestSequence = lease.mccRequestSequence;
    permit.mccNoticeEpoch = lease.mccNoticeEpoch;
    permit.ieeeChannel = descriptor.ieeeChannel;
    permit.macIndex = descriptor.macPhyIndex & 0x0fu;
    permit.decodeMode = descriptor.decodeMode;
    permit.originalRawStatus = descriptor.originalRawStatus;
    memcpy(permit.peerMac, lease.peerMac, sizeof(permit.peerMac));
    memcpy(permit.localMac, lease.localMac, sizeof(permit.localMac));
    *out = permit;
    return true;
}

inline bool samePermitIdentity(const Lease &lease, const Permit &permit)
{
    return lease.ownerSerial == permit.ownerSerial &&
        lease.startUs == permit.startUs &&
        lease.deadlineUs == permit.leaseDeadlineUs &&
        lease.mccRevision == permit.mccRevision &&
        lease.mccOrigin == permit.mccOrigin &&
        lease.mccRequestSequence == permit.mccRequestSequence &&
        lease.mccNoticeEpoch == permit.mccNoticeEpoch &&
        sameEpochs(lease.epochs, permit.epochs) &&
        memcmp(lease.peerMac, permit.peerMac, sizeof(permit.peerMac)) == 0 &&
        memcmp(lease.localMac, permit.localMac, sizeof(permit.localMac)) == 0;
}

inline bool stillCurrent(const Permit &permit, const Lease &lease,
                         uint64_t nowUs)
{
    return permit.valid && leaseCurrent(lease, nowUs) &&
        samePermitIdentity(lease, permit) &&
        nowUs >= permit.capturedUs && nowUs < permit.deadlineUs &&
        nowUs - permit.capturedUs <= kMaximumQueuedAgeUs;
}

} // namespace NativeP2PDirectedDataRxInput

#endif // NATIVE_P2P_DIRECTED_DATA_RX_INPUT_HPP
