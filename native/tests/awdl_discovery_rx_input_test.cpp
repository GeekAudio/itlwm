// SPDX-License-Identifier: GPL-2.0-only
// Standalone host tests for the offline AWDL discovery RX authorization policy.
#include "../awdl_discovery_rx_input.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace NativeAwdlDiscoveryRxInput;

namespace {
const uint8_t kPeerMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t kLocalMac[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
const uint64_t kStartUs = 1000000;
const uint64_t kDoorbellUs = 1010000;
const uint64_t kRocDeadlineUs = kStartUs + kMaximumRocDurationUs;
const uint64_t kReceiveDeadlineUs = kDoorbellUs + kReceiveWindowUs;

Identity validIdentity()
{
    Identity identity{};
    identity.ownerSerial = 10;
    identity.queryToken = 20;
    identity.queryDoorbellUs = kDoorbellUs;
    identity.peerIncarnation = 30;
    identity.psfRevision = 40;
    identity.mifRevision = 50;
    identity.epochs = {61, 62, 63, 64};
    identity.ifindex = 5;
    identity.ifnetIncarnation = 70;
    memcpy(identity.sourceMac, kPeerMac, sizeof(kPeerMac));
    memcpy(identity.localMac, kLocalMac, sizeof(kLocalMac));
    identity.rocStartUs = kStartUs;
    identity.rocDeadlineUs = kRocDeadlineUs;
    identity.mccRevision = 80;
    identity.channel = kIeeeChannel;
    return identity;
}

Lease validLease()
{
    Lease lease{};
    lease.identity = validIdentity();
    return lease;
}

MainGate validGate()
{
    MainGate gate{};
    gate.currentOwner = true;
    gate.currentEpochs = true;
    gate.currentPeer = true;
    gate.currentMcc = true;
    gate.startSeen = true;
    gate.noEnd = true;
    gate.identity = validIdentity();
    gate.queryTx.doorbellIssued = true;
    gate.queryTx.finishSucceeded = true;
    gate.queryTx.actionSubmitted = true;
    gate.queryTx.queueActive = true;
    gate.queryTx.submitOutstandingClear = true;
    gate.queryTx.queryTraceExact = true;
    gate.queryTx.queryToken = gate.identity.queryToken;
    gate.queryTx.queryDoorbellUs = gate.identity.queryDoorbellUs;
    gate.queryTx.epochs = gate.identity.epochs;
    return gate;
}

Descriptor validDescriptor()
{
    Descriptor descriptor{};
    descriptor.channelPresent = true;
    descriptor.channel = kIeeeChannel;
    descriptor.macPhyIndexPresent = true;
    descriptor.macPhyIndex = 0x41;
    descriptor.decodeModePresent = true;
    descriptor.decodeMode = kMacPhyDecodeBandInRx;
    descriptor.originalDescriptorPresent = true;
    descriptor.originalRawStatus = 0x12345678;
    descriptor.awdlDataCandidate = true;
    descriptor.sourceMacPresent = true;
    memcpy(descriptor.sourceMac, kPeerMac, sizeof(kPeerMac));
    return descriptor;
}

Permit makeValidPermit()
{
    Permit permit{};
    assert(makePermit(validLease(), validGate(), validDescriptor(),
                      kDoorbellUs + 500, &permit));
    return permit;
}

void positiveAndWindowBoundaries()
{
    Lease lease = validLease();
    MainGate gate = validGate();
    Descriptor descriptor = validDescriptor();
    Permit permit{};

    assert(sameLeaseIdentity(lease.identity, gate.identity));
    assert(leaseCurrent(lease, gate, kDoorbellUs));
    assert(makePermit(lease, gate, descriptor, kDoorbellUs, &permit));
    assert(permit.valid);
    assert(permit.capturedUs == kDoorbellUs);
    assert(permit.receiveDeadlineUs == kReceiveDeadlineUs);
    assert(permit.identity.ownerSerial == lease.identity.ownerSerial);
    assert(permit.identity.queryToken == lease.identity.queryToken);
    assert(permit.identity.queryDoorbellUs == lease.identity.queryDoorbellUs);
    assert(permit.identity.peerIncarnation == lease.identity.peerIncarnation);
    assert(permit.identity.psfRevision == lease.identity.psfRevision);
    assert(permit.identity.mifRevision == lease.identity.mifRevision);
    assert(sameEpochs(permit.identity.epochs, lease.identity.epochs));
    assert(permit.identity.ifindex == lease.identity.ifindex);
    assert(permit.identity.ifnetIncarnation == lease.identity.ifnetIncarnation);
    assert(memcmp(permit.identity.sourceMac, kPeerMac, 6) == 0);
    assert(memcmp(permit.identity.localMac, kLocalMac, 6) == 0);
    assert(permit.identity.rocStartUs == kStartUs);
    assert(permit.identity.rocDeadlineUs == kRocDeadlineUs);
    assert(permit.identity.mccRevision == 80);
    assert(permit.identity.channel == kIeeeChannel);
    assert(permit.descriptorChannel == kIeeeChannel);
    assert(permit.descriptorSourceMacPresent);
    assert(memcmp(permit.descriptorSourceMac, kPeerMac, 6) == 0);
    assert(stillCurrent(permit, lease, gate, kDoorbellUs));
    assert(stillCurrent(permit, lease, gate, kReceiveDeadlineUs - 1));
    assert(!stillCurrent(permit, lease, gate, kReceiveDeadlineUs));
    assert(!leaseCurrent(lease, gate, kReceiveDeadlineUs));
    assert(!leaseCurrent(lease, gate, kDoorbellUs - 1));
    assert(!stillCurrent(permit, lease, gate, permit.capturedUs - 1));

    // A shorter ROC deadline wins over the query's 100 ms receive window.
    lease.identity.rocDeadlineUs = kDoorbellUs + 25;
    gate.identity = lease.identity;
    assert(makePermit(lease, gate, descriptor, kDoorbellUs, &permit));
    assert(permit.receiveDeadlineUs == kDoorbellUs + 25);
    assert(stillCurrent(permit, lease, gate, kDoorbellUs + 24));
    assert(!stillCurrent(permit, lease, gate, kDoorbellUs + 25));
}

void mainGateWitnesses()
{
    const Lease lease = validLease();
    const Descriptor descriptor = validDescriptor();
    const uint64_t nowUs = kDoorbellUs + 100;
    const auto rejects = [&](void (*clear)(MainGate &)) {
        MainGate gate = validGate();
        Permit permit{};
        clear(gate);
        assert(!leaseCurrent(lease, gate, nowUs));
        assert(!makePermit(lease, gate, descriptor, nowUs, &permit));
        assert(!permit.valid);
    };
    rejects([](MainGate &gate) { gate.currentOwner = false; });
    rejects([](MainGate &gate) { gate.currentEpochs = false; });
    rejects([](MainGate &gate) { gate.currentPeer = false; });
    rejects([](MainGate &gate) { gate.currentMcc = false; });
    rejects([](MainGate &gate) { gate.startSeen = false; });
    rejects([](MainGate &gate) { gate.noEnd = false; });
}

void queryOwnershipWitnesses()
{
    const Lease lease = validLease();
    const Descriptor descriptor = validDescriptor();
    const uint64_t nowUs = kDoorbellUs + 100;
    const auto rejectsQueryTx = [&](void (*mutate)(TxOwnership &)) {
        MainGate gate = validGate();
        Permit permit{};
        mutate(gate.queryTx);
        assert(!queryOwnershipCurrent(lease.identity, gate.queryTx));
        assert(!leaseCurrent(lease, gate, nowUs));
        assert(!makePermit(lease, gate, descriptor, nowUs, &permit));
        assert(!permit.valid);
    };

    rejectsQueryTx([](TxOwnership &tx) { tx.doorbellIssued = false; });
    // Even if an enclosing submit call returned success and the doorbell was
    // issued, failed finish ownership must not create RX authority.
    rejectsQueryTx([](TxOwnership &tx) { tx.finishSucceeded = false; });
    rejectsQueryTx([](TxOwnership &tx) { tx.actionSubmitted = false; });
    rejectsQueryTx([](TxOwnership &tx) { tx.queueActive = false; });
    rejectsQueryTx([](TxOwnership &tx) { tx.submitOutstandingClear = false; });
    rejectsQueryTx([](TxOwnership &tx) { tx.queryTraceExact = false; });
    rejectsQueryTx([](TxOwnership &tx) { tx.traceUnknown = true; });
    rejectsQueryTx([](TxOwnership &tx) { tx.traceCancelled = true; });
    rejectsQueryTx([](TxOwnership &tx) { tx.traceStopped = true; });
    rejectsQueryTx([](TxOwnership &tx) { ++tx.queryToken; });
    rejectsQueryTx([](TxOwnership &tx) { ++tx.queryDoorbellUs; });
    rejectsQueryTx([](TxOwnership &tx) { ++tx.epochs.context; });
    rejectsQueryTx([](TxOwnership &tx) { ++tx.epochs.power; });
    rejectsQueryTx([](TxOwnership &tx) { ++tx.epochs.station; });
    rejectsQueryTx([](TxOwnership &tx) { ++tx.epochs.roc; });

    // `actionSubmitted` is a latched ownership fact, so normal completion to
    // Idle before this RX sample does not revoke the accepted query.
    MainGate completed = validGate();
    assert(completed.queryTx.actionSubmitted);
    assert(leaseCurrent(lease, completed, nowUs));
}

void identityReplacementAndRevisionBoundaries()
{
    const Lease lease = validLease();
    const Permit permit = makeValidPermit();
    const uint64_t nowUs = kDoorbellUs + 500;
    const auto rejectsChangedIdentity = [&](void (*mutate)(Identity &)) {
        MainGate gate = validGate();
        mutate(gate.identity);
        assert(!sameLeaseIdentity(lease.identity, gate.identity));
        assert(!stillCurrent(permit, lease, gate, nowUs));
    };
    rejectsChangedIdentity([](Identity &i) { ++i.ownerSerial; });
    rejectsChangedIdentity([](Identity &i) { ++i.queryToken; });
    rejectsChangedIdentity([](Identity &i) { ++i.queryDoorbellUs; });
    rejectsChangedIdentity([](Identity &i) { ++i.peerIncarnation; });
    rejectsChangedIdentity([](Identity &i) { ++i.psfRevision; });
    rejectsChangedIdentity([](Identity &i) { ++i.mifRevision; });
    rejectsChangedIdentity([](Identity &i) { ++i.epochs.context; });
    rejectsChangedIdentity([](Identity &i) { ++i.epochs.power; });
    rejectsChangedIdentity([](Identity &i) { ++i.epochs.station; });
    rejectsChangedIdentity([](Identity &i) { ++i.epochs.roc; });
    rejectsChangedIdentity([](Identity &i) { ++i.rocStartUs; });
    rejectsChangedIdentity([](Identity &i) { ++i.rocDeadlineUs; });
    rejectsChangedIdentity([](Identity &i) { ++i.mccRevision; });
    rejectsChangedIdentity([](Identity &i) { ++i.channel; });
    rejectsChangedIdentity([](Identity &i) { ++i.ifindex; });
    rejectsChangedIdentity([](Identity &i) { ++i.ifnetIncarnation; });
    rejectsChangedIdentity([](Identity &i) { i.sourceMac[5] ^= 1; });
    rejectsChangedIdentity([](Identity &i) { i.localMac[5] ^= 1; });

    Permit changedEvidence = permit;
    changedEvidence.descriptorSourceMac[5] ^= 1;
    assert(!stillCurrent(changedEvidence, lease, validGate(), nowUs));

    Lease replacement = validLease();
    ++replacement.identity.queryToken;
    MainGate replacementGate = validGate();
    replacementGate.identity = replacement.identity;
    assert(!stillCurrent(permit, replacement, replacementGate, nowUs));
}

void addressAndDescriptorBoundaries()
{
    const Lease lease = validLease();
    const MainGate gate = validGate();
    const uint64_t nowUs = kDoorbellUs + 100;
    const auto rejectsDescriptor = [&](void (*mutate)(Descriptor &)) {
        Descriptor descriptor = validDescriptor();
        Permit permit{};
        mutate(descriptor);
        assert(!makePermit(lease, gate, descriptor, nowUs, &permit));
        assert(!permit.valid);
    };
    rejectsDescriptor([](Descriptor &d) { d.channel = 149; });
    rejectsDescriptor([](Descriptor &d) { d.channelPresent = false; });
    rejectsDescriptor([](Descriptor &d) { d.macPhyIndex = 0x42; });
    rejectsDescriptor([](Descriptor &d) { d.macPhyIndexPresent = false; });
    rejectsDescriptor([](Descriptor &d) { d.decodeMode = 99; });
    rejectsDescriptor([](Descriptor &d) { d.decodeModePresent = false; });
    rejectsDescriptor([](Descriptor &d) { d.originalDescriptorPresent = false; });
    rejectsDescriptor([](Descriptor &d) { d.protectedFrame = true; });
    rejectsDescriptor([](Descriptor &d) { d.amsdu = true; });
    rejectsDescriptor([](Descriptor &d) { d.awdlDataCandidate = false; });
    rejectsDescriptor([](Descriptor &d) { d.sourceMacPresent = false; });
    rejectsDescriptor([](Descriptor &d) { d.sourceMac[5] ^= 1; });

    Lease invalid = validLease();
    invalid.identity.sourceMac[0] = 0x03; // multicast source identity
    MainGate invalidGate = validGate();
    invalidGate.identity = invalid.identity;
    Permit permit{};
    assert(!makePermit(invalid, invalidGate, validDescriptor(), nowUs, &permit));
    assert(!permit.valid);

    invalid = validLease();
    memcpy(invalid.identity.localMac, invalid.identity.sourceMac, 6);
    invalidGate.identity = invalid.identity;
    assert(!makePermit(invalid, invalidGate, validDescriptor(), nowUs, &permit));
}

void timestampAndIdentityValidityBoundaries()
{
    const Descriptor descriptor = validDescriptor();
    const auto rejectsLease = [&](void (*mutate)(Identity &),
                                  uint64_t capture = kDoorbellUs + 1) {
        Lease lease = validLease();
        mutate(lease.identity);
        MainGate gate = validGate();
        gate.identity = lease.identity;
        Permit permit{};
        assert(!makePermit(lease, gate, descriptor, capture, &permit));
        assert(!permit.valid);
    };
    rejectsLease([](Identity &i) { i.ownerSerial = 0; });
    rejectsLease([](Identity &i) { i.queryToken = 0; });
    rejectsLease([](Identity &i) { i.queryDoorbellUs = 0; });
    rejectsLease([](Identity &i) { i.peerIncarnation = 0; });
    rejectsLease([](Identity &i) { i.psfRevision = 0; });
    rejectsLease([](Identity &i) { i.mifRevision = 0; });
    rejectsLease([](Identity &i) { i.epochs.roc = 0; });
    rejectsLease([](Identity &i) { i.ifindex = 0; });
    rejectsLease([](Identity &i) { i.ifnetIncarnation = 0; });
    rejectsLease([](Identity &i) { i.mccRevision = 0; });
    rejectsLease([](Identity &i) { i.channel = 149; });
    rejectsLease([](Identity &i) { i.rocDeadlineUs = i.queryDoorbellUs; });
    rejectsLease([](Identity &i) { i.rocStartUs = i.queryDoorbellUs + 1; });
    rejectsLease([](Identity &i) {
        i.rocDeadlineUs = i.rocStartUs + kMaximumRocDurationUs + 1;
    });
    rejectsLease([](Identity &i) {
        i.rocStartUs = 1;
        i.queryDoorbellUs = 2;
        i.rocDeadlineUs = UINT64_MAX;
    });
    rejectsLease([](Identity &i) {
        i.queryDoorbellUs = UINT64_MAX - (kReceiveWindowUs - 1);
        i.rocStartUs = i.queryDoorbellUs - 1;
        i.rocDeadlineUs = UINT64_MAX;
    });

    Lease lease = validLease();
    MainGate gate = validGate();
    Permit permit{};
    assert(!makePermit(lease, gate, descriptor, kDoorbellUs - 1, &permit));
    assert(!makePermit(lease, gate, descriptor, kReceiveDeadlineUs, &permit));
    assert(!permit.valid);

    // No owner mode is part of this policy; a fully matching numeric lease is
    // accepted without encoding a particular owner implementation value.
    assert(leaseCurrent(lease, gate, kDoorbellUs + 1));
}
} // namespace

int main()
{
    // Queue setup can fail without RF, and AbortPrepared retains this token.
    const auto installed = observePrepareToken(31, 7, 0, 31, 7);
    assert(cleanupWitnessCurrent(installed, 31, 7));
    assert(installed.expectedToken == 31);
    // Early rejection before token installation is clean only from zero.
    const auto untouched = observePrepareToken(31, 7, 0, 0, 0);
    assert(cleanupWitnessCurrent(untouched, 31, 7));
    assert(untouched.expectedToken == 0);
    assert(!observePrepareToken(31, 7, 22, 22, 7).valid);
    assert(!observePrepareToken(31, 7, 0, 32, 7).valid);
    assert(!observePrepareToken(31, 7, 0, 31, 8).valid);
    assert(!observePrepareToken(31, 7, 31, 31, 7).valid);
    assert(!cleanupWitnessCurrent(installed, 32, 7));
    assert(!cleanupWitnessCurrent(installed, 31, 8));
    positiveAndWindowBoundaries();
    mainGateWitnesses();
    queryOwnershipWitnesses();
    identityReplacementAndRevisionBoundaries();
    addressAndDescriptorBoundaries();
    timestampAndIdentityValidityBoundaries();
    return 0;
}
