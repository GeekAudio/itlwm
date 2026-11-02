// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_directed_data_rx_input.hpp"

#include <assert.h>
#include <string.h>

using namespace NativeP2PDirectedDataRxInput;

static Lease lease()
{
    Lease value{};
    value.compiled = true;
    value.runtimeEnabled = true;
    value.profileEnabled = true;
    value.profileSelected = true;
    value.ownerCurrent = true;
    value.epochsMatch = true;
    value.tokenMatches = true;
    value.commandReturned = true;
    value.commandSucceeded = true;
    value.goNegotiationConfiguration = true;
    value.channel6Roc = true;
    value.startSeen = true;
    value.startSucceeded = true;
    value.mccCurrent = true;
    value.epochs = {701, 702, 703, 701};
    value.ownerSerial = 801;
    value.startUs = 1000;
    value.deadlineUs = value.startUs + kSessionWindowUs;
    value.nowUs = 1010;
    value.mccRevision = 12;
    value.mccNoticeGeneration = 14;
    value.mccSourceGeneration = value.epochs.power;
    value.mccAppliedNoticeGeneration = value.mccNoticeGeneration;
    value.mccResponseStatus = 1;
    value.mccResponseChannelCount = 51;
    const uint8_t peer[6] = {0x02, 1, 2, 3, 4, 5};
    const uint8_t own[6] = {0x02, 6, 7, 8, 9, 10};
    memcpy(value.peerMac, peer, sizeof(peer));
    memcpy(value.localMac, own, sizeof(own));
    return value;
}

static Descriptor descriptor()
{
    Descriptor value{};
    value.channelPresent = true;
    value.ieeeChannel = 6;
    value.macPhyIndexPresent = true;
    value.macPhyIndex = 0x21;
    value.decodeModePresent = true;
    value.decodeMode = kMacPhyDecodeBandInRx;
    value.awdlDataCandidate = true;
    value.originalDescriptorPresent = true;
    value.sourceMacPresent = true;
    const uint8_t peer[6] = {0x02, 1, 2, 3, 4, 5};
    memcpy(value.sourceMac, peer, sizeof(peer));
    return value;
}

int main()
{
    Lease current = lease();
    Descriptor frame = descriptor();
    Permit permit{};
    assert(leaseCurrent(current, 1010));
    assert(makePermit(current, frame, &permit));
    assert(permit.valid && permit.ieeeChannel == 6 &&
           permit.ownerSerial == current.ownerSerial && permit.macIndex == 1);
    assert(stillCurrent(permit, current, 1011));
    assert(!stillCurrent(permit, current, current.startUs + kSessionWindowUs));

    for (unsigned field = 0; field < 14; ++field) {
        Lease invalid = current;
        switch (field) {
        case 0: invalid.compiled = false; break;
        case 1: invalid.runtimeEnabled = false; break;
        case 2: invalid.profileEnabled = false; break;
        case 3: invalid.profileSelected = false; break;
        case 4: invalid.ownerCurrent = false; break;
        case 5: invalid.epochsMatch = false; break;
        case 6: invalid.tokenMatches = false; break;
        case 7: invalid.commandReturned = false; break;
        case 8: invalid.commandSucceeded = false; break;
        case 9: invalid.goNegotiationConfiguration = false; break;
        case 10: invalid.channel6Roc = false; break;
        case 11: invalid.startSeen = false; break;
        case 12: invalid.startSucceeded = false; break;
        case 13: invalid.endSeen = true; break;
        }
        assert(!leaseCurrent(invalid, 1010));
    }
    Lease unknown = current;
    unknown.outcomeUnknown = true;
    assert(!leaseCurrent(unknown, 1010));
    Lease badEpoch = current;
    badEpoch.epochs.roc++;
    assert(!leaseCurrent(badEpoch, 1010));
    Lease badDeadline = current;
    badDeadline.deadlineUs++;
    assert(!leaseCurrent(badDeadline, 1010));
    Lease staleMcc = current;
    staleMcc.mccCurrent = false;
    assert(!leaseCurrent(staleMcc, 1010));
    staleMcc = current;
    staleMcc.mccResponseStatus = 4;
    assert(!leaseCurrent(staleMcc, 1010));
    staleMcc = current;
    staleMcc.mccResponseChannelCount = 50;
    assert(!leaseCurrent(staleMcc, 1010));
    Lease wrongClock = current;
    assert(!leaseCurrent(wrongClock, 999));
    assert(!leaseCurrent(current, current.startUs + kSessionWindowUs));

    for (unsigned field = 0; field < 9; ++field) {
        Descriptor invalid = frame;
        switch (field) {
        case 0: invalid.channelPresent = false; break;
        case 1: invalid.ieeeChannel = 149; break;
        case 2: invalid.macPhyIndexPresent = false; break;
        case 3: invalid.macPhyIndex = 2; break;
        case 4: invalid.decodeModePresent = false; break;
        case 5: invalid.decodeMode = 99; break;
        case 6: invalid.protectedFrame = true; break;
        case 7: invalid.awdlDataCandidate = false; break;
        case 8: invalid.originalDescriptorPresent = false; break;
        }
        assert(!makePermit(current, invalid, &permit));
    }
    Descriptor deaggregated = frame;
    deaggregated.hardwareDeaggregated = true;
    assert(!makePermit(current, deaggregated, &permit));
    Descriptor missingSource = frame;
    missingSource.sourceMacPresent = false;
    assert(!makePermit(current, missingSource, &permit));
    Descriptor wrongSource = frame;
    wrongSource.sourceMac[5] ^= 1;
    assert(!makePermit(current, wrongSource, &permit));
    assert(!makePermit(current, frame, nullptr));

    Lease changedPeer = current;
    changedPeer.peerMac[5] ^= 1;
    assert(!sameLeaseIdentity(current, changedPeer));
    Lease changedLocal = current;
    changedLocal.localMac[5] ^= 1;
    assert(!sameLeaseIdentity(current, changedLocal));
    Lease changedMcc = current;
    changedMcc.mccRevision += 2;
    assert(!sameLeaseIdentity(current, changedMcc));
    assert(!samePermitIdentity(changedPeer, permit));

    Lease overflow = current;
    overflow.startUs = UINT64_MAX - kSessionWindowUs + 1;
    overflow.nowUs = overflow.startUs;
    assert(!makePermit(overflow, frame, &permit));
    overflow = current;
    overflow.nowUs = UINT64_MAX - kMaximumQueuedAgeUs + 1;
    assert(!makePermit(overflow, frame, &permit));
    return 0;
}
