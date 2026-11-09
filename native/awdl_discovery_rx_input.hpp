// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DISCOVERY_RX_INPUT_HPP
#define NATIVE_AWDL_DISCOVERY_RX_INPUT_HPP

#include <stdint.h>
#include <string.h>

// Offline authorization policy for a single, already-admitted AWDL discovery
// query. This header owns no driver, firmware, socket, or packet resources.
namespace NativeAwdlDiscoveryRxInput {

constexpr uint16_t kIeeeChannel = 6;
constexpr uint64_t kReceiveWindowUs = 100000ULL;
// Current Tahoe ROC submission accepts 100 ms normally and 900 ms only for
// its explicit channel-6 social-TX path. Reject wider claimed windows.
constexpr uint64_t kMaximumRocDurationUs = 900000ULL;
constexpr uint32_t kMacPhyDecodeLegacy = 1;
constexpr uint32_t kMacPhyDecodeBandInRx = 2;

// Prepare installs the ROC token before any queue or RF submission. Retain
// that observation even when Prepare or later queue setup fails cleanly.
// A prior owner's COMPLETE token is not evidence for this owner's cleanup.
struct RocCleanupWitness {
    bool valid;
    uint32_t ownerToken;
    uint32_t driverGeneration;
    uint32_t expectedToken;
};

inline RocCleanupWitness observePrepareToken(uint32_t ownerToken,
    uint32_t driverGeneration, uint32_t beforeToken, uint32_t afterToken,
    uint32_t afterFirmwareGeneration)
{
    RocCleanupWitness result{};
    if (!ownerToken || !driverGeneration || beforeToken == ownerToken)
        return result;
    const bool installed = afterToken == ownerToken &&
        afterFirmwareGeneration == driverGeneration;
    const bool untouched = beforeToken == 0 && afterToken == 0;
    if (!installed && !untouched) return result;
    result.valid = true;
    result.ownerToken = ownerToken;
    result.driverGeneration = driverGeneration;
    result.expectedToken = installed ? ownerToken : 0;
    return result;
}

inline bool cleanupWitnessCurrent(const RocCleanupWitness &witness,
    uint32_t ownerToken, uint32_t driverGeneration)
{
    return witness.valid && ownerToken != 0 && driverGeneration != 0 &&
        witness.ownerToken == ownerToken &&
        witness.driverGeneration == driverGeneration &&
        (witness.expectedToken == 0 || witness.expectedToken == ownerToken);
}

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

inline bool validEpochs(const Epochs &epochs)
{
    return epochs.context != 0 && epochs.power != 0 &&
        epochs.station != 0 && epochs.roc != 0;
}

// A numeric identity snapshot copied from the admitted query, peer runtime
// entry, current interface, ROC START, and the applied MCC generation.
struct Identity {
    uint64_t ownerSerial;
    uint64_t queryToken;
    uint64_t queryDoorbellUs;
    uint64_t peerIncarnation;
    uint64_t psfRevision;
    uint64_t mifRevision;
    Epochs epochs;
    uint32_t ifindex;
    uint64_t ifnetIncarnation;
    uint8_t sourceMac[6];
    uint8_t localMac[6];
    uint64_t rocStartUs;
    uint64_t rocDeadlineUs;
    uint64_t mccRevision;
    uint16_t channel;
};

struct Lease {
    Identity identity;
};

// `doorbellIssued`, `finishSucceeded`, and `actionSubmitted` are immutable
// ownership facts latched at successful post-doorbell finish. The remaining
// fields sample the current queue/trace; `actionSubmitted` does not require
// the action to stay in-flight after normal TX completion.
struct TxOwnership {
    bool doorbellIssued;
    bool finishSucceeded;
    bool actionSubmitted;
    bool queueActive;
    bool submitOutstandingClear;
    bool queryTraceExact;
    bool traceUnknown;
    bool traceCancelled;
    bool traceStopped;
    uint64_t queryToken;
    uint64_t queryDoorbellUs;
    Epochs epochs;
};

// MainGate is a live main-gate sample, not an authority object. Its flags,
// identity, and TX ownership witness must all match the admitted lease.
struct MainGate {
    bool currentOwner;
    bool currentEpochs;
    bool currentPeer;
    bool currentMcc;
    bool startSeen;
    bool noEnd;
    Identity identity;
    TxOwnership queryTx;
};

struct Descriptor {
    bool channelPresent;
    uint16_t channel;
    bool macPhyIndexPresent;
    uint8_t macPhyIndex;
    bool decodeModePresent;
    uint32_t decodeMode;
    bool originalDescriptorPresent;
    uint32_t originalRawStatus;
    bool protectedFrame;
    bool amsdu;
    bool awdlDataCandidate;
    bool sourceMacPresent;
    uint8_t sourceMac[6];
};

// A copyable authorization capability for one validated original MPDU.
// Descriptor evidence is retained so a later consumer can revalidate it.
struct Permit {
    bool valid;
    Identity identity;
    uint64_t capturedUs;
    uint64_t receiveDeadlineUs;
    uint16_t descriptorChannel;
    uint8_t rawMacPhyIndex;
    uint32_t decodeMode;
    bool descriptorSourceMacPresent;
    uint8_t descriptorSourceMac[6];
    bool originalDescriptorPresent;
    uint32_t originalRawStatus;
    bool protectedFrame;
    bool amsdu;
    bool awdlDataCandidate;
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

inline bool sameLeaseIdentity(const Identity &left, const Identity &right)
{
    return left.ownerSerial == right.ownerSerial &&
        left.queryToken == right.queryToken &&
        left.queryDoorbellUs == right.queryDoorbellUs &&
        left.peerIncarnation == right.peerIncarnation &&
        left.psfRevision == right.psfRevision &&
        left.mifRevision == right.mifRevision &&
        sameEpochs(left.epochs, right.epochs) &&
        left.ifindex == right.ifindex &&
        left.ifnetIncarnation == right.ifnetIncarnation &&
        memcmp(left.sourceMac, right.sourceMac, sizeof(left.sourceMac)) == 0 &&
        memcmp(left.localMac, right.localMac, sizeof(left.localMac)) == 0 &&
        left.rocStartUs == right.rocStartUs &&
        left.rocDeadlineUs == right.rocDeadlineUs &&
        left.mccRevision == right.mccRevision &&
        left.channel == right.channel;
}

inline bool validIdentity(const Identity &identity)
{
    if (identity.ownerSerial == 0 || identity.queryToken == 0 ||
        identity.queryDoorbellUs == 0 ||
        identity.peerIncarnation == 0 || identity.psfRevision == 0 ||
        identity.mifRevision == 0 || !validEpochs(identity.epochs) ||
        identity.ifindex == 0 || identity.ifnetIncarnation == 0 ||
        !validUnicastMac(identity.sourceMac) ||
        !validUnicastMac(identity.localMac) ||
        memcmp(identity.sourceMac, identity.localMac, 6) == 0 ||
        identity.rocStartUs == 0 ||
        identity.rocStartUs >= identity.rocDeadlineUs ||
        identity.queryDoorbellUs < identity.rocStartUs ||
        identity.queryDoorbellUs >= identity.rocDeadlineUs ||
        identity.queryDoorbellUs > UINT64_MAX - kReceiveWindowUs ||
        identity.mccRevision == 0 || identity.channel != kIeeeChannel)
        return false;

    // Deadline > START was checked above, so this difference cannot wrap.
    const uint64_t rocDurationUs =
        identity.rocDeadlineUs - identity.rocStartUs;
    return rocDurationUs <= kMaximumRocDurationUs;
}

inline bool queryOwnershipCurrent(const Identity &identity,
                                  const TxOwnership &tx)
{
    return tx.doorbellIssued && tx.finishSucceeded && tx.actionSubmitted &&
        tx.queueActive && tx.submitOutstandingClear && tx.queryTraceExact &&
        !tx.traceUnknown && !tx.traceCancelled && !tx.traceStopped &&
        tx.queryToken == identity.queryToken &&
        tx.queryDoorbellUs == identity.queryDoorbellUs &&
        sameEpochs(tx.epochs, identity.epochs);
}

inline bool receiveDeadline(const Identity &identity, uint64_t *out)
{
    if (!out || !validIdentity(identity))
        return false;
    const uint64_t queryDeadline = identity.queryDoorbellUs + kReceiveWindowUs;
    *out = identity.rocDeadlineUs < queryDeadline ?
        identity.rocDeadlineUs : queryDeadline;
    return *out > identity.queryDoorbellUs;
}

inline bool leaseCurrent(const Lease &lease, const MainGate &gate,
                         uint64_t nowUs)
{
    uint64_t deadlineUs = 0;
    return gate.currentOwner && gate.currentEpochs && gate.currentPeer &&
        gate.currentMcc && gate.startSeen && gate.noEnd &&
        queryOwnershipCurrent(lease.identity, gate.queryTx) &&
        sameLeaseIdentity(lease.identity, gate.identity) &&
        receiveDeadline(lease.identity, &deadlineUs) &&
        nowUs >= lease.identity.rocStartUs &&
        nowUs >= lease.identity.queryDoorbellUs && nowUs < deadlineUs;
}

inline bool verifiedMacIndexOne(const Descriptor &descriptor)
{
    if (!descriptor.macPhyIndexPresent || !descriptor.decodeModePresent ||
        (descriptor.decodeMode != kMacPhyDecodeLegacy &&
         descriptor.decodeMode != kMacPhyDecodeBandInRx))
        return false;
    return (descriptor.macPhyIndex & 0x0fu) == 1u;
}

inline bool descriptorMatches(const Identity &identity,
                              const Descriptor &descriptor)
{
    return descriptor.channelPresent && descriptor.channel == kIeeeChannel &&
        verifiedMacIndexOne(descriptor) &&
        descriptor.originalDescriptorPresent && !descriptor.protectedFrame &&
        !descriptor.amsdu && descriptor.awdlDataCandidate &&
        descriptor.sourceMacPresent &&
        memcmp(descriptor.sourceMac, identity.sourceMac, 6) == 0;
}

inline bool validPermitEvidence(const Permit &permit)
{
    Descriptor descriptor{};
    descriptor.channelPresent = true;
    descriptor.channel = permit.descriptorChannel;
    descriptor.macPhyIndexPresent = true;
    descriptor.macPhyIndex = permit.rawMacPhyIndex;
    descriptor.decodeModePresent = true;
    descriptor.decodeMode = permit.decodeMode;
    descriptor.originalDescriptorPresent = permit.originalDescriptorPresent;
    descriptor.originalRawStatus = permit.originalRawStatus;
    descriptor.protectedFrame = permit.protectedFrame;
    descriptor.amsdu = permit.amsdu;
    descriptor.awdlDataCandidate = permit.awdlDataCandidate;
    descriptor.sourceMacPresent = permit.descriptorSourceMacPresent;
    memcpy(descriptor.sourceMac, permit.descriptorSourceMac, 6);
    return descriptorMatches(permit.identity, descriptor);
}

inline bool makePermit(const Lease &lease, const MainGate &gate,
                       const Descriptor &descriptor, uint64_t captureUs,
                       Permit *out)
{
    if (!out)
        return false;
    *out = Permit{};
    uint64_t deadlineUs = 0;
    if (!leaseCurrent(lease, gate, captureUs) ||
        !descriptorMatches(lease.identity, descriptor) ||
        !receiveDeadline(lease.identity, &deadlineUs))
        return false;

    Permit permit{};
    permit.valid = true;
    permit.identity = lease.identity;
    permit.capturedUs = captureUs;
    permit.receiveDeadlineUs = deadlineUs;
    permit.descriptorChannel = descriptor.channel;
    permit.rawMacPhyIndex = descriptor.macPhyIndex;
    permit.decodeMode = descriptor.decodeMode;
    permit.descriptorSourceMacPresent = descriptor.sourceMacPresent;
    memcpy(permit.descriptorSourceMac, descriptor.sourceMac,
           sizeof(permit.descriptorSourceMac));
    permit.originalDescriptorPresent = descriptor.originalDescriptorPresent;
    permit.originalRawStatus = descriptor.originalRawStatus;
    permit.protectedFrame = descriptor.protectedFrame;
    permit.amsdu = descriptor.amsdu;
    permit.awdlDataCandidate = descriptor.awdlDataCandidate;
    *out = permit;
    return true;
}

inline bool stillCurrent(const Permit &permit, const Lease &lease,
                         const MainGate &gate, uint64_t nowUs)
{
    uint64_t expectedDeadlineUs = 0;
    return permit.valid && validPermitEvidence(permit) &&
        sameLeaseIdentity(permit.identity, lease.identity) &&
        receiveDeadline(permit.identity, &expectedDeadlineUs) &&
        permit.receiveDeadlineUs == expectedDeadlineUs &&
        leaseCurrent(lease, gate, permit.capturedUs) &&
        leaseCurrent(lease, gate, nowUs) &&
        nowUs >= permit.capturedUs && nowUs < permit.receiveDeadlineUs &&
        nowUs - permit.capturedUs <= kReceiveWindowUs;
}

} // namespace NativeAwdlDiscoveryRxInput

#endif // NATIVE_AWDL_DISCOVERY_RX_INPUT_HPP
