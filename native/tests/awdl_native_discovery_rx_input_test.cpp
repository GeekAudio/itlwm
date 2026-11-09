// SPDX-License-Identifier: GPL-2.0-only
// Host regression for the production Discovery RX BSD bridge entrypoints.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_data_frame.hpp"
#include "../awdl_discovery_rx_input.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=10000;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;

namespace {
using namespace NativeAwdlBSD;
namespace P=NativeAwdlDiscoveryRxInput;

const uint8_t own[6]={0x02,0x01,0x02,0x03,0x04,0x05};
const uint8_t peer[6]={0x02,0x06,0x07,0x08,0x09,0x0a};
const uint8_t other[6]={0x02,0x09,0x08,0x07,0x06,0x05};
const uint8_t multicastWrongMapping[6]={0x33,0x33,0x00,0x00,0x00,0xaa};
const uint8_t ipv6NonLinkLocal[16]={0x20,0x01,0x0d,0xb8,0,0,0,0,
                                    0,0,0,0,0,0,0,1};
const uint8_t ipv6Multicast[16]={0xff,0x02,0,0,0,0,0,0,
                                 0,0,0,0,0,0,0,0xfb};
constexpr uint32_t kPowerGeneration=88;

struct RunnerContext {
    P::Lease lease{};
    P::MainGate gate{};
    bool rejectPeer=false;
    bool rejectMcc=false;
    bool endBeforeTicket=false;
    unsigned calls=0;
};
P::Identity observerIdentity{};

void revokeWhileInputTicketHeld(ifnet_t,mbuf_t) {
    assert(!discoveryRxQuiescent());
    revokeDiscoveryRxInput(observerIdentity);
    assert(!discoveryRxQuiescent());
}

void putBe16(uint8_t *bytes,uint16_t value) {
    bytes[0]=uint8_t(value>>8);
    bytes[1]=uint8_t(value);
}

std::vector<uint8_t> validIpv6() {
    std::vector<uint8_t> packet(40,0);
    packet[0]=0x60;
    packet[6]=59;
    packet[7]=64;
    packet[8]=0xfe;
    packet[9]=0x80;
    packet[24]=0xfe;
    packet[25]=0x80;
    return packet;
}

std::vector<uint8_t> makeMpdu(const uint8_t source[6],bool retry=false,
                              uint16_t sequence=1,
                              const uint8_t destination[6]=own,
                              const uint8_t ipv6Destination[16]=nullptr) {
    auto ipv6=validIpv6();
    if(ipv6Destination)memcpy(ipv6.data()+24,ipv6Destination,16);
    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress,destination,6);
    memcpy(input.sourceAddress,source,6);
    input.wifiSequenceNumber=sequence;
    input.awdlSequenceNumber=uint16_t(sequence+4);
    input.ipv6Packet=ipv6.data();
    input.ipv6Length=ipv6.size();
    uint8_t output[128]{};
    size_t written=0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(
        &input,output,sizeof(output),&written)==NativeAwdlData::Status::Ok);
    std::vector<uint8_t> frame(output,output+written);
    if(retry)frame[1]|=0x08;
    return frame;
}

P::MainGate gateFor(const P::Identity &identity) {
    P::MainGate gate{};
    gate.currentOwner=true;
    gate.currentEpochs=true;
    gate.currentPeer=true;
    gate.currentMcc=true;
    gate.startSeen=true;
    gate.noEnd=true;
    gate.identity=identity;
    gate.queryTx.doorbellIssued=true;
    gate.queryTx.finishSucceeded=true;
    gate.queryTx.actionSubmitted=true;
    gate.queryTx.queueActive=true;
    gate.queryTx.submitOutstandingClear=true;
    gate.queryTx.queryTraceExact=true;
    gate.queryTx.queryToken=identity.queryToken;
    gate.queryTx.queryDoorbellUs=identity.queryDoorbellUs;
    gate.queryTx.epochs=identity.epochs;
    return gate;
}

P::Lease newLease(uint64_t ownerSerial,uint64_t queryToken,
                  uint64_t peerIncarnation=51) {
    DiscoveryRxIfnetIdentity live{};
    assert(readDiscoveryRxIfnetIdentity(&live));
    const uint64_t start=fakeTime;
    P::Identity identity{};
    identity.ownerSerial=ownerSerial;
    identity.queryToken=queryToken;
    identity.queryDoorbellUs=start+1;
    identity.peerIncarnation=peerIncarnation;
    identity.psfRevision=ownerSerial+100;
    identity.mifRevision=ownerSerial+200;
    identity.epochs={uint32_t(ownerSerial+1),kPowerGeneration,
                     uint32_t(ownerSerial+2),uint32_t(ownerSerial+3)};
    identity.ifindex=live.ifindex;
    identity.ifnetIncarnation=live.ifnetIncarnation;
    memcpy(identity.sourceMac,peer,6);
    memcpy(identity.localMac,live.localMac,6);
    identity.rocStartUs=start;
    identity.rocDeadlineUs=start+500000;
    identity.mccRevision=ownerSerial+300;
    identity.channel=P::kIeeeChannel;
    fakeTime=identity.queryDoorbellUs;
    assert(P::validIdentity(identity));
    P::Lease lease{};
    lease.identity=identity;
    return lease;
}

P::Descriptor descriptorFor(const P::Identity &identity) {
    P::Descriptor descriptor{};
    descriptor.channelPresent=true;
    descriptor.channel=P::kIeeeChannel;
    descriptor.macPhyIndexPresent=true;
    descriptor.macPhyIndex=0x01;
    descriptor.decodeModePresent=true;
    descriptor.decodeMode=P::kMacPhyDecodeLegacy;
    descriptor.originalDescriptorPresent=true;
    descriptor.originalRawStatus=0x1234;
    descriptor.awdlDataCandidate=true;
    descriptor.sourceMacPresent=true;
    memcpy(descriptor.sourceMac,identity.sourceMac,6);
    return descriptor;
}

P::Permit makePermit(const P::Lease &lease,const P::MainGate &gate) {
    P::Permit permit{};
    const auto descriptor=descriptorFor(lease.identity);
    assert(P::makePermit(lease,gate,descriptor,fakeTime,&permit));
    return permit;
}

bool runFreshMainGate(void *opaque,const P::Identity &identity,
                      DiscoveryRxAdmissionAction action,void *ticketContext) {
    auto *context=static_cast<RunnerContext *>(opaque);
    assert(context&&action);
    assert(hostSimpleLockDepth()==0);
    assert(P::sameLeaseIdentity(identity,context->lease.identity));
    ++context->calls;
    auto freshGate=context->gate;
    if(context->rejectPeer)freshGate.currentPeer=false;
    if(context->rejectMcc)freshGate.currentMcc=false;
    if(context->endBeforeTicket) {
        assert(markDiscoveryRxEndFast(identity));
        freshGate.noEnd=false;
    }
    return action(ticketContext,context->lease,freshGate);
}

struct Fixture {
    FakeIf dev{};
    Fixture() {
        fakeTime=10000;
        memcpy(dev.lladdr,own,6);
        assert(attach(&dev,own));
        poll(true,kPowerGeneration);
    }
    ~Fixture() {
        if(dev.refs)assert(close());
    }
};

void testNativeIpv6AndSourceGuard() {
    Fixture fixture;
    auto lease=newLease(10,100);
    auto gate=gateFor(lease.identity);
    assert(publishDiscoveryRxInputLease(lease,gate));
    auto permit=makePermit(lease,gate);
    const auto wrongDestination=makeMpdu(peer,false,1,other);
    assert(captureDiscoveryRxData(wrongDestination.data(),
        wrongDestination.size(),false,
        lease,gate,permit,kPowerGeneration)==CaptureResult::Rejected);
    const auto frame=makeMpdu(peer);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        lease,gate,permit,kPowerGeneration)==CaptureResult::Captured);
    RunnerContext runner{lease,gate};
    const unsigned inputBefore=delivered.load();
    pollDiscoveryRx(true,kPowerGeneration,&lease,&gate,runFreshMainGate,&runner);
    assert(runner.calls==1);
    assert(delivered.load()==inputBefore+1);
    auto counters=snapshot();
    assert(counters.value[DiscoveryInputCalls]==1);
    assert(counters.value[DiscoveryInputResult]==0);
    assert(counters.value[DiscoveryInputSuccess]==1);
    assert(counters.value[DiscoverySameWindowCommitted]==1);

    auto globalLease=newLease(11,101);
    auto globalGate=gateFor(globalLease.identity);
    assert(publishDiscoveryRxInputLease(globalLease,globalGate));
    auto globalPermit=makePermit(globalLease,globalGate);
    const auto nonLinkLocal=
        makeMpdu(peer,false,2,own,ipv6NonLinkLocal);
    assert(captureDiscoveryRxData(nonLinkLocal.data(),nonLinkLocal.size(),
        false,globalLease,globalGate,globalPermit,kPowerGeneration)==
        CaptureResult::Captured);
    RunnerContext globalRunner{globalLease,globalGate};
    pollDiscoveryRx(true,kPowerGeneration,&globalLease,&globalGate,
                    runFreshMainGate,&globalRunner);
    counters=snapshot();
    assert(counters.value[DiscoveryInputCalls]==2);
    assert(counters.value[DiscoveryInputSuccess]==2);
    assert(counters.value[DiscoverySameWindowCommitted]==2);

    auto multicastLease=newLease(12,102);
    auto multicastGate=gateFor(multicastLease.identity);
    assert(publishDiscoveryRxInputLease(multicastLease,multicastGate));
    auto multicastPermit=makePermit(multicastLease,multicastGate);
    // Old generic acceptsRx permits a group DA and does not impose an IPv6
    // multicast-to-Ethernet mapping rule; retain that receive behavior.
    const auto multicastMismatch=makeMpdu(peer,false,3,
        multicastWrongMapping,ipv6Multicast);
    assert(captureDiscoveryRxData(multicastMismatch.data(),
        multicastMismatch.size(),false,multicastLease,multicastGate,
        multicastPermit,kPowerGeneration)==CaptureResult::Captured);
    RunnerContext multicastRunner{multicastLease,multicastGate};
    pollDiscoveryRx(true,kPowerGeneration,&multicastLease,&multicastGate,
                    runFreshMainGate,&multicastRunner);
    counters=snapshot();
    assert(counters.value[DiscoveryInputCalls]==3);
    assert(counters.value[DiscoveryInputSuccess]==3);
    assert(counters.value[DiscoverySameWindowCommitted]==3);
    assert(allocated.load()==freed.load());
    assert(close());
    assert(fixture.dev.refs==0);
}

void testWrongIfnetIdentityRejected() {
    Fixture fixture;
    auto lease=newLease(20,200);
    auto gate=gateFor(lease.identity);
    lease.identity.ifindex+=1;
    gate=gateFor(lease.identity);
    assert(!publishDiscoveryRxInputLease(lease,gate));

    auto next=newLease(21,201);
    auto nextGate=gateFor(next.identity);
    ++next.identity.ifnetIncarnation;
    nextGate=gateFor(next.identity);
    assert(!publishDiscoveryRxInputLease(next,nextGate));
    assert(close());
    assert(fixture.dev.refs==0);
}

void testExpiryAndEndFence() {
    Fixture fixture;
    auto lease=newLease(30,300);
    auto gate=gateFor(lease.identity);
    assert(publishDiscoveryRxInputLease(lease,gate));
    auto permit=makePermit(lease,gate);
    const auto frame=makeMpdu(peer);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        lease,gate,permit,kPowerGeneration)==CaptureResult::Captured);
    fakeTime=permit.receiveDeadlineUs;
    RunnerContext expiredRunner{lease,gate};
    const unsigned before=delivered.load();
    pollDiscoveryRx(true,kPowerGeneration,&lease,&gate,
                    runFreshMainGate,&expiredRunner);
    assert(expiredRunner.calls==0);
    assert(delivered.load()==before);

    auto endedLease=newLease(31,301);
    auto endedGate=gateFor(endedLease.identity);
    assert(publishDiscoveryRxInputLease(endedLease,endedGate));
    auto endedPermit=makePermit(endedLease,endedGate);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        endedLease,endedGate,endedPermit,kPowerGeneration)==
        CaptureResult::Captured);
    assert(markDiscoveryRxEndFast(endedLease.identity));
    RunnerContext endedRunner{endedLease,endedGate};
    pollDiscoveryRx(true,kPowerGeneration,&endedLease,&endedGate,
                    runFreshMainGate,&endedRunner);
    assert(endedRunner.calls==0);
    assert(delivered.load()==before);
    assert(close());
    assert(fixture.dev.refs==0);
}

void testFreshPeerAndMccAtTicket() {
    Fixture fixture;
    auto lease=newLease(40,400);
    auto gate=gateFor(lease.identity);
    assert(publishDiscoveryRxInputLease(lease,gate));
    const auto frame=makeMpdu(peer);
    const unsigned before=delivered.load();
    auto permit=makePermit(lease,gate);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        lease,gate,permit,kPowerGeneration)==CaptureResult::Captured);
    RunnerContext peerRunner{lease,gate};
    peerRunner.rejectPeer=true;
    pollDiscoveryRx(true,kPowerGeneration,&lease,&gate,
                    runFreshMainGate,&peerRunner);
    assert(peerRunner.calls==1);
    assert(delivered.load()==before);

    auto mccLease=newLease(41,401);
    auto mccGate=gateFor(mccLease.identity);
    assert(publishDiscoveryRxInputLease(mccLease,mccGate));
    permit=makePermit(mccLease,mccGate);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        mccLease,mccGate,permit,kPowerGeneration)==CaptureResult::Captured);
    RunnerContext mccRunner{mccLease,mccGate};
    mccRunner.rejectMcc=true;
    pollDiscoveryRx(true,kPowerGeneration,&mccLease,&mccGate,
                    runFreshMainGate,&mccRunner);
    assert(mccRunner.calls==1);
    assert(delivered.load()==before);
    assert(allocated.load()==freed.load());
    assert(close());
    assert(fixture.dev.refs==0);
}

void testReplaceAndStaleEnd() {
    Fixture fixture;
    auto oldLease=newLease(50,500);
    auto oldGate=gateFor(oldLease.identity);
    assert(publishDiscoveryRxInputLease(oldLease,oldGate));
    auto newOwner=newLease(51,501);
    auto newGate=gateFor(newOwner.identity);
    assert(publishDiscoveryRxInputLease(newOwner,newGate));
    assert(!markDiscoveryRxEndFast(oldLease.identity));
    revokeDiscoveryRxInput(oldLease.identity);
    auto permit=makePermit(newOwner,newGate);
    const auto frame=makeMpdu(peer);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        newOwner,newGate,permit,kPowerGeneration)==CaptureResult::Captured);
    RunnerContext runner{newOwner,newGate};
    const unsigned before=delivered.load();
    pollDiscoveryRx(true,kPowerGeneration,&newOwner,&newGate,
                    runFreshMainGate,&runner);
    assert(delivered.load()==before+1);
    assert(close());
    assert(fixture.dev.refs==0);
}

void testCloseDropsQueuedCopyOnce() {
    Fixture fixture;
    auto lease=newLease(60,600);
    auto gate=gateFor(lease.identity);
    assert(publishDiscoveryRxInputLease(lease,gate));
    auto permit=makePermit(lease,gate);
    const auto frame=makeMpdu(peer);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        lease,gate,permit,kPowerGeneration)==CaptureResult::Captured);
    const unsigned beforeAllocated=allocated.load();
    const unsigned beforeFreed=freed.load();
    assert(close());
    assert(fixture.dev.refs==0);
    assert(allocated.load()==beforeAllocated);
    assert(freed.load()==beforeFreed);
}

void testQuiescentWaitsForTicketAndWorker() {
    Fixture fixture;
    auto lease=newLease(70,700);
    auto gate=gateFor(lease.identity);
    assert(publishDiscoveryRxInputLease(lease,gate));
    auto permit=makePermit(lease,gate);
    const auto frame=makeMpdu(peer);
    assert(captureDiscoveryRxData(frame.data(),frame.size(),false,
        lease,gate,permit,kPowerGeneration)==CaptureResult::Captured);
    assert(!discoveryRxQuiescent());
    const auto before=snapshot();
    const unsigned systemInputsBefore=delivered.load();
    observerIdentity=lease.identity;
    fakeInputObserver()=revokeWhileInputTicketHeld;
    RunnerContext runner{lease,gate};
    pollDiscoveryRx(true,kPowerGeneration,&lease,&gate,
                    runFreshMainGate,&runner);
    fakeInputObserver()=nullptr;
    assert(runner.calls==1);
    const auto after=snapshot();
    assert(delivered.load()==systemInputsBefore+1);
    assert(after.value[DiscoveryInputCalls]==before.value[DiscoveryInputCalls]+1);
    assert(after.value[DiscoveryInputResult]==0);
    assert(after.value[DiscoveryInputSuccess]==
           before.value[DiscoveryInputSuccess]+1);
    assert(after.value[DiscoverySameWindowCommitted]==
           before.value[DiscoverySameWindowCommitted]);
    assert(after.value[RxDelivered]==before.value[RxDelivered]);
    assert(after.value[RxRejected]==before.value[RxRejected]);
    assert(discoveryRxQuiescent());
    assert(allocated.load()==freed.load());
    assert(close());
    assert(fixture.dev.refs==0);
}

} // namespace

int main(int argc,char **argv) {
    assert(argc==2);
    const int scenario=atoi(argv[1]);
    switch(scenario) {
        case 1:testNativeIpv6AndSourceGuard();break;
        case 2:testWrongIfnetIdentityRejected();break;
        case 3:testExpiryAndEndFence();break;
        case 4:testFreshPeerAndMccAtTicket();break;
        case 5:testReplaceAndStaleEnd();break;
        case 6:testCloseDropsQueuedCopyOnce();break;
        case 7:testQuiescentWaitsForTicketAndWorker();break;
        default:assert(false&&"unknown discovery RX bridge scenario");
    }
    return 0;
}
