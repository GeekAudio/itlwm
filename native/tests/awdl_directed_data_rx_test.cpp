// SPDX-License-Identifier: GPL-2.0-only
// Host-shim tests for the production bounded mode-4/channel-6 RX bridge.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_data_frame.hpp"

#include <condition_variable>
#include <mutex>
#include <thread>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=3000000;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false,lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;

namespace {
using namespace NativeAwdlBSD;
namespace Input=NativeP2PDirectedDataRxInput;
const uint8_t ownMac[6]={0x02,0x11,0x22,0x33,0x44,0x55};
const uint8_t peerMac[6]={0x02,0xaa,0xbb,0xcc,0xdd,0xee};
const uint8_t otherMac[6]={0x02,0x90,0x80,0x70,0x60,0x50};
std::mutex inputMutex;
std::condition_variable inputCondition;
bool blockInput=false,inputEntered=false,releaseInput=false;

void linkLocal(uint8_t address[16],const uint8_t mac[6]) {
    memset(address,0,16);
    address[0]=0xfe;address[1]=0x80;
    address[8]=static_cast<uint8_t>(mac[0]^2u);
    address[9]=mac[1];address[10]=mac[2];address[11]=0xff;
    address[12]=0xfe;address[13]=mac[3];address[14]=mac[4];
    address[15]=mac[5];
}

Input::Lease lease() {
    Input::Lease value{};
    value.compiled=true;value.runtimeEnabled=true;
    value.profileEnabled=true;value.profileSelected=true;
    value.ownerCurrent=true;value.epochsMatch=true;value.tokenMatches=true;
    value.commandReturned=true;value.commandSucceeded=true;
    value.goNegotiationConfiguration=true;value.channel6Roc=true;
    value.startSeen=true;value.startSucceeded=true;value.mccCurrent=true;
    value.epochs={51,52,53,51};value.ownerSerial=75;
    value.startUs=fakeTime;value.deadlineUs=fakeTime+Input::kSessionWindowUs;
    value.nowUs=fakeTime;value.mccRevision=12;
    value.mccNoticeGeneration=14;value.mccSourceGeneration=value.epochs.power;
    value.mccAppliedNoticeGeneration=value.mccNoticeGeneration;
    value.mccResponseStatus=1;value.mccResponseChannelCount=51;
    memcpy(value.peerMac,peerMac,6);memcpy(value.localMac,ownMac,6);
    return value;
}

bool frame(uint8_t out[256],size_t *length,
           const uint8_t *wifiSource=peerMac,uint16_t wifiSequence=0) {
    uint8_t ipv6[40]{};
    ipv6[0]=0x60;ipv6[6]=17;ipv6[7]=1;
    linkLocal(ipv6+8,peerMac);linkLocal(ipv6+24,ownMac);
    NativeAwdlData::EncodeInput input{};
    memcpy(input.sourceAddress,wifiSource,6);
    memcpy(input.destinationAddress,ownMac,6);
    input.wifiSequenceNumber=wifiSequence;
    input.ipv6Packet=ipv6;input.ipv6Length=sizeof(ipv6);
    return NativeAwdlData::encodeIpv6DataMpdu(
        &input,out,256,length)==NativeAwdlData::Status::Ok;
}

bool addressedFrame(uint8_t out[256],size_t *length,
                    const uint8_t destinationMac[6],
                    const uint8_t sourceIp[16],const uint8_t destinationIp[16],
                    uint16_t sequence=0x2ab) {
    uint8_t ipv6[40]{};
    ipv6[0]=0x60;ipv6[6]=59;ipv6[7]=1;
    memcpy(ipv6+8,sourceIp,16);memcpy(ipv6+24,destinationIp,16);
    NativeAwdlData::EncodeInput input{};
    memcpy(input.sourceAddress,peerMac,6);
    memcpy(input.destinationAddress,destinationMac,6);
    input.wifiSequenceNumber=sequence;
    input.ipv6Packet=ipv6;input.ipv6Length=sizeof(ipv6);
    return NativeAwdlData::encodeIpv6DataMpdu(
        &input,out,256,length)==NativeAwdlData::Status::Ok;
}

bool permitFor(const Input::Lease &current,const uint8_t *bytes,size_t length,
               Input::Permit *permit,bool protectedFrame=false,
               bool deaggregated=false,uint16_t channel=6) {
    Input::Descriptor descriptor{};
    descriptor.channelPresent=true;descriptor.ieeeChannel=channel;
    descriptor.macPhyIndexPresent=true;descriptor.macPhyIndex=0x21;
    descriptor.decodeModePresent=true;
    descriptor.decodeMode=Input::kMacPhyDecodeBandInRx;
    descriptor.protectedFrame=protectedFrame;
    descriptor.awdlDataCandidate=NativeAwdlData::isAwdlDataCandidate(bytes,length);
    descriptor.originalDescriptorPresent=true;
    descriptor.hardwareDeaggregated=deaggregated;
    descriptor.originalRawStatus=0x8100;
    descriptor.sourceMacPresent=length>=16;
    if(descriptor.sourceMacPresent)memcpy(descriptor.sourceMac,bytes+10,6);
    return Input::makePermit(current,descriptor,permit);
}

void observeInput(ifnet_t,mbuf_t) {
    std::unique_lock<std::mutex> guard(inputMutex);
    if(!blockInput)return;
    inputEntered=true;inputCondition.notify_all();
    inputCondition.wait(guard,[]{return releaseInput;});
}

void prepare(FakeIf &dev) {
    memcpy(dev.lladdr,ownMac,sizeof(ownMac));
    assert(attach(&dev,ownMac));
    poll(true,52);
}

void assertBalanced(FakeIf &dev) {
    assert(dev.refs==0);
    assert(allocated.load()==freed.load());
    assert(socketsOpen.load()==socketsClosed.load());
}

void caseSuccess(FakeIf &dev) {
    prepare(dev);
    auto current=lease();
    assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;
    assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    poll(true,52,&current);
    const auto receipt=snapshot().directedDataRxInput;
    assert(receipt.disposition==DirectedDataRxReceiptIfnetInputSucceeded);
    assert(receipt.ownerSerial==current.ownerSerial&&receipt.ieeeChannel==6);
    assert(receipt.startUs==current.startUs&&receipt.deadlineUs<=current.deadlineUs);
    assert(receipt.ifnetInputResultPresent==1&&receipt.ifnetInputResult==0);
    assert(snapshot().value[DirectedRxCaptured]==1);
    assert(snapshot().value[DirectedRxDecoded]==1);
    assert(snapshot().value[DirectedRxDelivered]==1&&delivered==1);
    assert(close());assertBalanced(dev);
}

void caseWrongInnerPeer(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;
    assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    // Simulate descriptor-to-buffer source identity mismatch after permit
    // creation. The bridge must reject it before the bounded queue.
    memcpy(bytes+10,otherMac,6);
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Rejected);
    assert(snapshot().value[DirectedRxPending]==0);
    poll(true,52,&current);
    assert(snapshot().value[DirectedRxDelivered]==0&&delivered==0);
    assert(close());assertBalanced(dev);
}

void caseWrongPermitAndDescriptor(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    auto wrong=permit;wrong.peerMac[5]^=1;
    assert(captureDirectedDataRx(bytes,length,false,current,wrong,52)==
           CaptureResult::Rejected);
    assert(captureDirectedDataRx(bytes,length,false,current,permit,53)==
           CaptureResult::Rejected);
    Input::Permit bad{};
    assert(!permitFor(current,bytes,length,&bad,false,false,149));
    assert(captureDirectedDataRx(bytes,length,false,current,bad,52)==
           CaptureResult::Rejected);
    assert(snapshot().value[DirectedRxCaptured]==0);
    assert(close());assertBalanced(dev);
}

void caseRevokedBeforeDrain(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    revokeDirectedDataRxInput(current.ownerSerial,current.epochs);
    poll(true,52,&current);
    assert(delivered==0&&snapshot().value[DirectedRxPending]==0);
    assert(close());assertBalanced(dev);
}

void caseDeadline(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    fakeTime=current.deadlineUs;
    poll(true,52,&current);
    assert(delivered==0&&snapshot().value[DirectedRxPending]==0);
    assert(close());assertBalanced(dev);
}

void caseCloseWaitsForInputTicket(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    fakeInputObserver()=observeInput;
    {
        std::lock_guard<std::mutex> guard(inputMutex);
        blockInput=true;inputEntered=false;releaseInput=false;
    }
    std::thread worker([&]{poll(true,52,&current);});
    {
        std::unique_lock<std::mutex> guard(inputMutex);
        inputCondition.wait(guard,[]{return inputEntered;});
    }
    assert(!close()&&dev.refs==1);
    {
        std::lock_guard<std::mutex> guard(inputMutex);
        releaseInput=true;inputCondition.notify_all();
    }
    worker.join();
    fakeInputObserver()=nullptr;blockInput=false;
    assert(close());assertBalanced(dev);
}

void caseLegacyPollPreservesDirectedWindow(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);

    // nativeP2pTick calls this legacy overload without an RX lease. It may
    // discard the old RX149 ring, but must preserve this active directed ring.
    poll(true,52);
    assert(snapshot().value[DirectedRxPending]==1);
    poll(true,52,&current);
    assert(delivered==1&&snapshot().value[DirectedRxDelivered]==1);
    assert(close());assertBalanced(dev);
}

void caseLegacyPollRevokesStaleDirectedWindow(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);

    // A radio-generation change remains terminal even through the legacy poll.
    poll(true,53);
    assert(snapshot().value[DirectedRxPending]==0);
    poll(true,52,&current);
    assert(delivered==0&&snapshot().value[DirectedRxDelivered]==0);
    assert(close());assertBalanced(dev);
}

void caseRetryDomain(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;assert(frame(bytes,&length,peerMac,0x5a3));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    assert(snapshot().value[DirectedRxPending]==1);

    // Only an exact same-owner copy may suppress a same-flow Retry. The full
    // sequence-control field, rather than just its high 12-bit number, keys
    // the separate directed-data Retry domain.
    uint8_t retry[256]{};memcpy(retry,bytes,length);retry[1]|=0x08;
    Input::Permit retryPermit{};
    assert(permitFor(current,retry,length,&retryPermit));
    assert(captureDirectedDataRx(retry,length,false,current,retryPermit,52)==
           CaptureResult::Duplicate);
    assert(snapshot().value[DirectedRxPending]==1);

    // A different fragment component is not the same full Sequence Control
    // identity. Decoder policy currently rejects non-zero fragments before
    // the Retry ledger, preserving the ordinary STA fallback.
    retry[22]|=0x01;
    Input::Permit fragmentPermit{};
    assert(permitFor(current,retry,length,&fragmentPermit));
    assert(captureDirectedDataRx(retry,length,false,current,fragmentPermit,52)==
           CaptureResult::Rejected);
    assert(snapshot().value[DirectedRxPending]==1);
    assert(close());assertBalanced(dev);
}

void caseQueueFullDoesNotCommitRetry(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;
    unsigned accepted=0;
    for(uint16_t sequence=0;sequence<128;++sequence) {
        assert(frame(bytes,&length,peerMac,sequence));
        Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
        const auto result=captureDirectedDataRx(bytes,length,false,current,permit,52);
        if(result==CaptureResult::QueueFull)break;
        assert(result==CaptureResult::Captured);
        ++accepted;
    }
    assert(accepted>0&&snapshot().value[DirectedRxPending]==accepted);

    const uint16_t targetSequence=0x6d2;
    assert(frame(bytes,&length,peerMac,targetSequence));
    bytes[1]|=0x08; // Retry is not committed until this packet is copied.
    Input::Permit targetPermit{};
    assert(permitFor(current,bytes,length,&targetPermit));
    assert(captureDirectedDataRx(bytes,length,false,current,targetPermit,52)==
           CaptureResult::QueueFull);
    assert(snapshot().value[DirectedRxPending]==accepted);

    poll(true,52,&current);
    assert(snapshot().value[DirectedRxPending]==0);
    assert(frame(bytes,&length,peerMac,targetSequence));
    bytes[1]|=0x08;
    Input::Permit retryPermit{};assert(permitFor(current,bytes,length,&retryPermit));
    assert(captureDirectedDataRx(bytes,length,false,current,retryPermit,52)==
           CaptureResult::Captured);
    assert(snapshot().value[DirectedRxPending]==1);
    assert(close());assertBalanced(dev);
}

void caseRetryDomainOwnerAndIfnetIncarnation(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;
    assert(frame(bytes,&length,peerMac,0x2ab));bytes[1]|=0x08;
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);

#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
    // A fresh interface incarnation is a new Retry namespace even if all
    // visible 802.11 identities are reused.
    advanceRx149InterfaceIncarnationForTests();
    Input::Permit incarnationPermit{};
    assert(permitFor(current,bytes,length,&incarnationPermit));
    assert(captureDirectedDataRx(bytes,length,false,current,
        incarnationPermit,52)==CaptureResult::Captured);
#endif

    Input::Lease next=current;
    next.ownerSerial=current.ownerSerial+1;
    next.epochs.context+=1;
    next.epochs.roc+=1;
    next.startUs=fakeTime;
    next.deadlineUs=next.startUs+Input::kSessionWindowUs;
    next.nowUs=fakeTime;
    assert(publishDirectedDataRxInputLease(next));
    Input::Permit nextPermit{};assert(permitFor(next,bytes,length,&nextPermit));
    assert(captureDirectedDataRx(bytes,length,false,next,nextPermit,52)==
           CaptureResult::Captured);
    assert(snapshot().value[DirectedRxPending]==1);
    assert(close());assertBalanced(dev);
}

void caseMulticastDoesNotEnterRetryLedger(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t sourceIp[16]{};linkLocal(sourceIp,peerMac);
    uint8_t destinationIp[16]={0xff,0x02};destinationIp[15]=0xfb;
    const uint8_t destinationMac[6]={0x33,0x33,0,0,0,0xfb};
    uint8_t bytes[256]{};size_t length=0;
    assert(addressedFrame(bytes,&length,destinationMac,sourceIp,destinationIp));
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    poll(true,52,&current);
    assert(delivered==1);

    // The earlier worker accepted this ff02::fb / 33:33::fb mapping. Its
    // duplicate bit must not bring multicast into the new unicast ledger.
    bytes[1]|=0x08;
    assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    poll(true,52,&current);
    assert(delivered==2&&snapshot().value[DirectedRxDelivered]==2);

    // A unicast with the same SC is independent from both multicast copies.
    assert(frame(bytes,&length,peerMac,0x2ab));bytes[1]|=0x08;
    assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Duplicate);
    poll(true,52,&current);
    assert(delivered==3);
    assert(close());assertBalanced(dev);
}

void caseRejectedAddressLeavesNoRetryEntry(FakeIf &dev,int variant) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t sourceIp[16]{};linkLocal(sourceIp,peerMac);
    uint8_t destinationIp[16]{};linkLocal(destinationIp,ownMac);
    uint8_t destinationMac[6]{};memcpy(destinationMac,ownMac,6);
    if(variant==0||variant==1) {
        memset(destinationIp,0,sizeof(destinationIp));
        destinationIp[0]=0xff;destinationIp[1]=variant==1?0x05:0x02;
        destinationIp[15]=0xfb;
        const uint8_t groupMac[6]={0x33,0x33,0,0,0,0xfb};
        memcpy(destinationMac,groupMac,6);
        if(variant==0)destinationMac[5]=0xfc; // Wrong ff02 mapping.
    } else if(variant==2) {
        memcpy(destinationMac,otherMac,6);linkLocal(destinationIp,otherMac);
    } else if(variant==3) {
        // Correct DA alone must not consume a frame for a foreign IPv6 IID.
        linkLocal(destinationIp,otherMac);
    } else if(variant==4) {
        sourceIp[0]=0x20;sourceIp[1]=0x01; // Non-link-local source.
    } else {
        assert(false);
    }
    uint8_t bytes[256]{};size_t length=0;
    assert(addressedFrame(bytes,&length,destinationMac,sourceIp,destinationIp));
    bytes[1]|=0x08;
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    // Rejected means the early HAL route returns PassToSta; neither the
    // bounded queue nor the Retry ledger may claim this rejected packet.
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Rejected);
    assert(snapshot().value[DirectedRxPending]==0);
    poll(true,52,&current);assert(delivered==0);

    assert(frame(bytes,&length,peerMac,0x2ab));bytes[1]|=0x08;
    assert(permitFor(current,bytes,length,&permit));
    assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
           CaptureResult::Captured);
    poll(true,52,&current);assert(delivered==1);
    assert(close());assertBalanced(dev);
}

void caseSameSequenceDifferentTid(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;
    assert(frame(bytes,&length,peerMac,0x2ab));
    memmove(bytes+26,bytes+24,length-24);length+=2;
    bytes[0]|=0x80;bytes[1]|=0x08;bytes[24]=0;bytes[25]=0;
    for(uint8_t tid=0;tid<2;++tid) {
        bytes[24]=tid;
        Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
        assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
               CaptureResult::Captured);
        assert(captureDirectedDataRx(bytes,length,false,current,permit,52)==
               CaptureResult::Duplicate);
    }
    poll(true,52,&current);assert(delivered==2);
    assert(close());assertBalanced(dev);
}

void caseConcurrentExactRetry(FakeIf &dev) {
    prepare(dev);
    auto current=lease();assert(publishDirectedDataRxInputLease(current));
    uint8_t bytes[256]{};size_t length=0;
    assert(frame(bytes,&length,peerMac,0x2ab));bytes[1]|=0x08;
    Input::Permit permit{};assert(permitFor(current,bytes,length,&permit));
    CaptureResult first=CaptureResult::Rejected,second=CaptureResult::Rejected;
    std::thread left([&]{
        first=captureDirectedDataRx(bytes,length,false,current,permit,52);
    });
    std::thread right([&]{
        second=captureDirectedDataRx(bytes,length,false,current,permit,52);
    });
    left.join();right.join();
    assert((first==CaptureResult::Captured&&second==CaptureResult::Duplicate)||
           (second==CaptureResult::Captured&&first==CaptureResult::Duplicate));
    assert(snapshot().value[DirectedRxPending]==1);
    poll(true,52,&current);assert(delivered==1);
    assert(close());assertBalanced(dev);
}
}

int main(int argc,char **argv) {
    assert(argc==2);const int selected=atoi(argv[1]);FakeIf dev;
    switch(selected) {
        case 1:caseSuccess(dev);break;
        case 2:caseWrongInnerPeer(dev);break;
        case 3:caseWrongPermitAndDescriptor(dev);break;
        case 4:caseRevokedBeforeDrain(dev);break;
        case 5:caseDeadline(dev);break;
        case 6:caseCloseWaitsForInputTicket(dev);break;
        case 7:caseLegacyPollPreservesDirectedWindow(dev);break;
        case 8:caseLegacyPollRevokesStaleDirectedWindow(dev);break;
        case 9:caseRetryDomain(dev);break;
        case 10:caseQueueFullDoesNotCommitRetry(dev);break;
        case 11:caseRetryDomainOwnerAndIfnetIncarnation(dev);break;
        case 12:caseMulticastDoesNotEnterRetryLedger(dev);break;
        case 13:caseRejectedAddressLeavesNoRetryEntry(dev,0);break;
        case 14:caseRejectedAddressLeavesNoRetryEntry(dev,1);break;
        case 15:caseRejectedAddressLeavesNoRetryEntry(dev,2);break;
        case 16:caseRejectedAddressLeavesNoRetryEntry(dev,3);break;
        case 17:caseRejectedAddressLeavesNoRetryEntry(dev,4);break;
        case 18:caseSameSequenceDifferentTid(dev);break;
        case 19:caseConcurrentExactRetry(dev);break;
        default:assert(false);break;
    }
    return 0;
}
