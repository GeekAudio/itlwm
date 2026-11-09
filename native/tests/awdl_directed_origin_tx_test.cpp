// SPDX-License-Identifier: GPL-2.0-only
// Host-only Test107 exercise of the production BSD output/pop/close paths.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_bsd_packet_bridge.hpp"
#include <condition_variable>
#include <mutex>
#include <thread>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=2000000;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false,lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;

namespace {
using namespace NativeAwdlBSD;
namespace Origin=NativeAwdlDirectedOriginTx;
namespace DirectedRx=NativeP2PDirectedDataRxInput;
const uint8_t own[6]={0x02,0x11,0x22,0x33,0x44,0x55};
const uint8_t peer[6]={0x02,0xaa,0xbb,0xcc,0xdd,0xee};
const uint8_t nonce[8]={0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87};
std::mutex finalizeMutex;
std::condition_variable finalizeCondition;
bool blockFinalize=false,finalizeEntered=false,releaseFinalize=false;

uint16_t readBe16(const uint8_t *bytes) {
    return static_cast<uint16_t>((uint16_t(bytes[0])<<8)|bytes[1]);
}
void writeBe16(uint8_t *bytes,uint16_t value) {
    bytes[0]=static_cast<uint8_t>(value>>8);
    bytes[1]=static_cast<uint8_t>(value);
}
void makeLinkLocal(uint8_t address[16],const uint8_t mac[6]) {
    memset(address,0,16);
    address[0]=0xfe;address[1]=0x80;
    address[8]=static_cast<uint8_t>(mac[0]^2u);
    address[9]=mac[1];address[10]=mac[2];address[11]=0xff;
    address[12]=0xfe;address[13]=mac[3];address[14]=mac[4];
    address[15]=mac[5];
}
void setLiveLinkLocal(FakeIf &dev,const uint8_t canonical[16],
                     uint16_t embeddedScope,uint32_t sockaddrScope) {
    memcpy(dev.address,canonical,16);
    // KAME/XNU stores htons(ifindex) in s6_addr16[1]. The test ifindex is 8,
    // so the network-order bytes are 00:08.
    dev.address[2]=static_cast<uint8_t>(embeddedScope>>8);
    dev.address[3]=static_cast<uint8_t>(embeddedScope);
    dev.addressScopeId=sockaddrScope;
}
uint16_t checksum(const uint8_t *ip) {
    uint32_t sum=16u+17u;
    for(size_t offset=8;offset<40;offset+=2)sum+=readBe16(ip+offset);
    for(size_t offset=40;offset<56;offset+=2)sum+=readBe16(ip+offset);
    while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    const uint16_t value=static_cast<uint16_t>(~sum);
    return value?value:0xffffu;
}

enum class Damage { None,WrongSource,WrongDestination,WrongPort,WrongNonce,
                    WrongMapping,WrongEthernetSource,Extension,WrongHop,
                    BadChecksum };
mbuf_t packet(Damage damage=Damage::None,const uint8_t *packetNonce=nullptr) {
    mbuf_t m=nullptr;
    assert(mbuf_getpacket(MBUF_DONTWAIT,&m)==0&&m);
    uint8_t *bytes=static_cast<uint8_t *>(mbuf_data(m));
    const uint8_t ethernetDestination[6]={0x33,0x33,0,0,0,1};
    memcpy(bytes,ethernetDestination,6);
    memcpy(bytes+6,own,6);
    bytes[12]=0x86;bytes[13]=0xdd;
    uint8_t *ip=bytes+14;
    ip[0]=0x60;writeBe16(ip+4,16);ip[6]=17;ip[7]=1;
    makeLinkLocal(ip+8,own);
    const uint8_t destination[16]={0xff,0x02,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,1};
    memcpy(ip+24,destination,sizeof(destination));
    writeBe16(ip+40,Origin::kSourcePort);
    writeBe16(ip+42,Origin::kDestinationPort);
    writeBe16(ip+44,Origin::kUdpLength);
    memcpy(ip+48,packetNonce?packetNonce:nonce,sizeof(nonce));
    switch(damage) {
        case Damage::WrongSource:ip[23]^=1;break;
        case Damage::WrongDestination:ip[55]^=1;break;
        case Damage::WrongPort:writeBe16(ip+42,49154);break;
        case Damage::WrongNonce:ip[48]^=1;break;
        case Damage::WrongMapping:bytes[5]^=1;break;
        case Damage::WrongEthernetSource:bytes[11]^=1;break;
        case Damage::Extension:ip[6]=0;break;
        case Damage::WrongHop:ip[7]=2;break;
        case Damage::BadChecksum:break;
        case Damage::None:break;
    }
    writeBe16(ip+46,checksum(ip));
    if(damage==Damage::BadChecksum)ip[47]^=1;
    mbuf_setlen(m,Origin::kEthernetLength);
    mbuf_pkthdr_setlen(m,Origin::kEthernetLength);
    return m;
}

Origin::OpenRequest request(uint64_t runSerial=1001) {
    Origin::OpenRequest value{};
    value.ownerSerial=700;
    value.runSerial=runSerial;
    value.rocStartUs=fakeTime;
    value.deadlineUs=fakeTime+50000;
    value.epochs={10,11,12,13};
    value.rocChannelIndex=Origin::kRocChannelIndex;
    makeLinkLocal(value.sourceIPv6,own);
    memcpy(value.peerMac,peer,6);
    memcpy(value.nonce,nonce,sizeof(nonce));
    return value;
}

Origin::OpenRequest twoPacketRequest(uint64_t runSerial=1301) {
    auto value=request(runSerial);
    value.epochs={20,11,21,20}; // Directed RX owner requires context == ROC.
    value.deadlineUs=value.rocStartUs+DirectedRx::kSessionWindowUs;
    value.packetCount=2;
    const uint8_t first[8]={0x81,0x12,0x23,0x34,0x45,0x56,0x67,0x78};
    const uint8_t second[8]={0x92,0x13,0x24,0x35,0x46,0x57,0x68,0x79};
    memcpy(value.packetNonces[0],first,sizeof(first));
    memcpy(value.packetNonces[1],second,sizeof(second));
    makeLinkLocal(value.peerIPv6,peer);
    return value;
}

DirectedRx::Lease directedLease(const Origin::OpenRequest &armed) {
    DirectedRx::Lease value{};
    value.compiled=true;value.runtimeEnabled=true;value.profileEnabled=true;
    value.profileSelected=true;value.ownerCurrent=true;value.epochsMatch=true;
    value.tokenMatches=true;value.commandReturned=true;
    value.commandSucceeded=true;value.goNegotiationConfiguration=true;
    value.channel6Roc=true;value.startSeen=true;value.startSucceeded=true;
    value.mccCurrent=true;value.epochs={armed.epochs.context,
        armed.epochs.power,armed.epochs.station,armed.epochs.roc};
    value.ownerSerial=armed.ownerSerial;value.startUs=armed.rocStartUs;
    value.deadlineUs=armed.deadlineUs;value.nowUs=fakeTime;
    value.mccRevision=12;value.mccNoticeGeneration=14;
    value.mccSourceGeneration=armed.epochs.power;
    value.mccAppliedNoticeGeneration=value.mccNoticeGeneration;
    value.mccOrigin=IwxMccRefreshPolicy::kRequestOriginChubNotification;
    value.mccNoticeEpoch=14;value.mccResponseStatus=1;
    value.mccResponseChannelCount=51;
    memcpy(value.peerMac,peer,6);memcpy(value.localMac,own,6);
    return value;
}

bool exactEcho(uint8_t out[256],size_t *length,const uint8_t nonceBytes[8],
               uint16_t sequence) {
    uint8_t ipv6[Origin::kIpv6Length]{};
    ipv6[0]=0x60;writeBe16(ipv6+4,Origin::kUdpLength);
    ipv6[6]=17;ipv6[7]=1;
    makeLinkLocal(ipv6+8,peer);
    makeLinkLocal(ipv6+24,own);
    writeBe16(ipv6+40,Origin::kDestinationPort);
    writeBe16(ipv6+42,Origin::kSourcePort);
    writeBe16(ipv6+44,Origin::kUdpLength);
    memcpy(ipv6+48,nonceBytes,Origin::kNonceLength);
    writeBe16(ipv6+46,checksum(ipv6));
    NativeAwdlData::EncodeInput input{};
    memcpy(input.sourceAddress,peer,6);
    memcpy(input.destinationAddress,own,6);
    input.wifiSequenceNumber=sequence;
    input.ipv6Packet=ipv6;input.ipv6Length=sizeof(ipv6);
    return NativeAwdlData::encodeIpv6DataMpdu(
        &input,out,256,length)==NativeAwdlData::Status::Ok;
}

CaptureResult captureExactEcho(DirectedRx::Lease *lease,
                               const uint8_t nonceBytes[8],uint16_t sequence) {
    assert(lease);
    lease->nowUs=fakeTime;
    uint8_t bytes[256]{};size_t length=0;
    assert(exactEcho(bytes,&length,nonceBytes,sequence));
    DirectedRx::Descriptor descriptor{};
    descriptor.channelPresent=true;descriptor.ieeeChannel=6;
    descriptor.macPhyIndexPresent=true;descriptor.macPhyIndex=0x21;
    descriptor.decodeModePresent=true;
    descriptor.decodeMode=DirectedRx::kMacPhyDecodeBandInRx;
    descriptor.awdlDataCandidate=NativeAwdlData::isAwdlDataCandidate(
        bytes,length);
    descriptor.originalDescriptorPresent=true;
    descriptor.sourceMacPresent=true;memcpy(descriptor.sourceMac,peer,6);
    descriptor.originalRawStatus=0x8100;
    DirectedRx::Permit permit{};
    assert(DirectedRx::makePermit(*lease,descriptor,&permit));
    return captureDirectedDataRx(bytes,length,false,*lease,permit,11);
}

uint64_t fastEndOwner=0;
DirectedRx::Epochs fastEndEpochs{};
void endFastAtInput(ifnet_t,mbuf_t) {
    assert(markDirectedDataEndFast(fastEndOwner,fastEndEpochs));
}
uint64_t deadlineAdvanceTarget=0;
void advanceToDeadlineAfterInput(ifnet_t,mbuf_t) {
    fakeAdvanceTimeAfterReads(1,deadlineAdvanceTarget);
}

void prepare(FakeIf &dev) {
    memcpy(dev.lladdr,own,sizeof(own));
    assert(attach(&dev,own));
    poll(true,11);
}

bool open(const Origin::OpenRequest &value,Origin::Ticket *ticket) {
    return openDirectedOriginTx(value,ticket);
}
errno_t output(mbuf_t *m) {
    return installed.iff_output(nullptr,filterIf,AF_INET6,m);
}
void finalizeObserver(mbuf_t) {
    std::unique_lock<std::mutex> guard(finalizeMutex);
    if(!blockFinalize)return;
    finalizeEntered=true;
    finalizeCondition.notify_all();
    finalizeCondition.wait(guard,[]{return releaseFinalize;});
}

void assertBalanced(FakeIf &dev) {
    assert(dev.refs==0);
    assert(allocated.load()==freed.load());
    assert(socketsOpen.load()==socketsClosed.load());
}

void caseSuccess(FakeIf &dev) {
    prepare(dev);
    const auto armed=request();
    Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    assert(ticket.ticketSerial&&ticket.interfaceIncarnation&&ticket.ifindex==8);
    assert(!memcmp(ticket.sourceMac,own,6));
    assert(ticket.ownerSerial==armed.ownerSerial&&ticket.runSerial==armed.runSerial);
    assert(Origin::sameEpochs(ticket.epochs,armed.epochs));

    mbuf_t original=packet();
    assert(output(&original)==EJUSTRETURN&&original==nullptr);
    auto state=Origin::Snapshot{};
    snapshotDirectedOriginTx(&state);
    assert(state.state==Origin::State::Queued&&state.packetQueued);
    assert(state.accepted==1&&snapshot().value[TxPending]==0);

    mbuf_t second=packet();
    assert(output(&second)==EOPNOTSUPP&&second);
    mbuf_freem(second);
    assert(finalized==1); // The queued slot prevents a second finalize.

    uint64_t token=0;
    mbuf_t encoded=popDirectedOriginTx(ticket,0x321,0x4567,&token);
    assert(encoded&&token==ticket.ticketSerial&&encoded->total==Origin::kMpduLength);
    NativeAwdlData::DecodedFrame decoded{};
    assert(NativeAwdlData::decodeIpv6DataMpdu(
        encoded->bytes,encoded->total,&decoded)==NativeAwdlData::Status::Ok);
    assert(decoded.packetCount==1&&decoded.wifiSequenceNumber==0x321);
    assert(!memcmp(decoded.destinationAddress,peer,6));
    assert(!memcmp(decoded.sourceAddress,own,6));
    const auto &view=decoded.packets[0];
    assert(view.ipv6Length==Origin::kIpv6Length);
    assert(view.ipv6Packet[7]==1&&view.ipv6Packet[6]==17);
    assert(readBe16(view.ipv6Packet+40)==Origin::kSourcePort);
    assert(readBe16(view.ipv6Packet+42)==Origin::kDestinationPort);
    assert(!memcmp(view.ipv6Packet+48,nonce,sizeof(nonce)));
    mbuf_freem(encoded);
    token=99;
    assert(!popDirectedOriginTx(ticket,0,0,&token)&&token==0);
    assert(closeDirectedOriginTx(ticket));
    assert(closeDirectedOriginTx(ticket)); // Exact-ticket close is idempotent.
    Origin::Ticket repeated{};
    assert(!open(armed,&repeated)); // Same run stays tombstoned after close.
    snapshotDirectedOriginTx(&state);
    assert(state.state==Origin::State::Spent&&state.packetSpent);
    assert(state.encoded==1&&state.opens==1&&state.replayRejected>=1);
    assert(close());
    assertBalanced(dev);
}

void caseRejectThenAccept(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    const Damage damages[]={Damage::WrongSource,Damage::WrongDestination,
        Damage::WrongPort,Damage::WrongNonce,Damage::WrongMapping,
        Damage::WrongEthernetSource,Damage::Extension,Damage::WrongHop};
    for(Damage damage:damages) {
        mbuf_t rejected=packet(damage);
        assert(output(&rejected)==EOPNOTSUPP&&rejected);
        mbuf_freem(rejected);
    }
    mbuf_t accepted=packet();
    assert(output(&accepted)==EJUSTRETURN&&!accepted);
    uint64_t token=0;
    mbuf_t encoded=popDirectedOriginTx(ticket,3,4,&token);
    assert(encoded&&token==ticket.ticketSerial&&encoded->total==96);
    mbuf_freem(encoded);
    assert(closeDirectedOriginTx(ticket));
    assert(close());
    assertBalanced(dev);
}

void caseChecksumReject(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    mbuf_t rejected=packet(Damage::BadChecksum);
    assert(output(&rejected)==EOPNOTSUPP&&rejected);
    assert(finalized==1); // Checksum validation follows outbound finalization.
    mbuf_freem(rejected);
    mbuf_t accepted=packet();
    assert(output(&accepted)==EJUSTRETURN&&!accepted);
    uint64_t token=0;mbuf_t encoded=popDirectedOriginTx(ticket,1,2,&token);
    assert(encoded&&token==ticket.ticketSerial);
    mbuf_freem(encoded);
    assert(closeDirectedOriginTx(ticket));assert(close());assertBalanced(dev);
}

void caseExpiry(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    mbuf_t original=packet();
    assert(output(&original)==EJUSTRETURN&&!original);
    fakeTime=ticket.deadlineUs;
    poll(true,11); // expiry retires and frees only the unsubmitted BSD mbuf.
    Origin::Snapshot state{};snapshotDirectedOriginTx(&state);
    assert(state.state==Origin::State::Expired&&!state.packetQueued&&
           !state.packets[0].packetQueued&&!state.packets[0].packetPopping);
    assert(state.expired==1);
    mbuf_t second=packet();assert(output(&second)==EOPNOTSUPP&&second);
    mbuf_freem(second);
    uint64_t token=99;assert(!popDirectedOriginTx(ticket,1,2,&token)&&token==0);
    Origin::Ticket retry{};assert(!open(armed,&retry));
    assert(close());assertBalanced(dev);
}

void caseCloseUnsubmitted(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    mbuf_t original=packet();assert(output(&original)==EJUSTRETURN&&!original);
    assert(closeDirectedOriginTx(ticket));
    Origin::Snapshot state{};snapshotDirectedOriginTx(&state);
    assert(state.state==Origin::State::Closed&&!state.packetQueued&&
           !state.packets[0].packetQueued&&!state.packets[0].packetPopping);
    Origin::Ticket retry{};assert(!open(armed,&retry));
    assert(close());assertBalanced(dev);
}

void caseStop(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    mbuf_t original=packet();assert(output(&original)==EJUSTRETURN&&!original);
    poll(false,11);
    Origin::Snapshot state{};snapshotDirectedOriginTx(&state);
    assert(state.state==Origin::State::Revoked&&!state.packetQueued&&
           !state.packets[0].packetQueued&&!state.packets[0].packetPopping);
    uint64_t token=1;assert(!popDirectedOriginTx(ticket,1,2,&token)&&token==0);
    mbuf_t rejected=packet();assert(output(&rejected)==EOPNOTSUPP&&rejected);
    mbuf_freem(rejected);
    assert(close());assertBalanced(dev);
}

void caseConcurrentOutputs(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};assert(open(armed,&ticket));
    mbuf_t left=packet(),right=packet();
    std::atomic<unsigned> accepted{0},rejected{0};
    auto send=[&](mbuf_t *packetMbuf) {
        const int result=output(packetMbuf);
        if(result==EJUSTRETURN)++accepted;
        else {assert(result==EOPNOTSUPP&&*packetMbuf);++rejected;}
    };
    std::thread first(send,&left),second(send,&right);
    first.join();second.join();
    assert(accepted==1&&rejected==1);
    if(left)mbuf_freem(left);
    if(right)mbuf_freem(right);
    uint64_t token=0;mbuf_t encoded=popDirectedOriginTx(ticket,9,10,&token);
    assert(encoded&&token==ticket.ticketSerial&&encoded->total==96);
    mbuf_freem(encoded);
    assert(closeDirectedOriginTx(ticket));assert(close());assertBalanced(dev);
}

void caseCloseDuringFinalize(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};assert(open(armed,&ticket));
    mbuf_t original=packet();
    {
        std::lock_guard<std::mutex> guard(finalizeMutex);
        blockFinalize=true;finalizeEntered=false;releaseFinalize=false;
    }
    fakeFinalizeObserver()=finalizeObserver;
    std::atomic<int> outputResult{0};
    std::thread sender([&]{outputResult=output(&original);});
    {
        std::unique_lock<std::mutex> guard(finalizeMutex);
        finalizeCondition.wait(guard,[]{return finalizeEntered;});
    }
    // Close must revoke the gate but retain the ifnet while output is pinned.
    assert(!close());assert(dev.refs==1);
    {
        std::lock_guard<std::mutex> guard(finalizeMutex);
        releaseFinalize=true;finalizeCondition.notify_all();
    }
    sender.join();
    fakeFinalizeObserver()=nullptr;
    assert(outputResult==EOPNOTSUPP&&original);
    mbuf_freem(original);
    {
        std::lock_guard<std::mutex> guard(finalizeMutex);
        blockFinalize=false;
    }
    assert(close());assertBalanced(dev);
}

void caseStopDuringFinalize(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};assert(open(armed,&ticket));
    mbuf_t original=packet();
    {
        std::lock_guard<std::mutex> guard(finalizeMutex);
        blockFinalize=true;finalizeEntered=false;releaseFinalize=false;
    }
    fakeFinalizeObserver()=finalizeObserver;
    std::atomic<int> outputResult{0};
    std::thread sender([&]{outputResult=output(&original);});
    {
        std::unique_lock<std::mutex> guard(finalizeMutex);
        finalizeCondition.wait(guard,[]{return finalizeEntered;});
    }
    poll(false,11); // Must acquire BSD lock while finalize is parked outside it.
    {
        std::lock_guard<std::mutex> guard(finalizeMutex);
        releaseFinalize=true;finalizeCondition.notify_all();
    }
    sender.join();fakeFinalizeObserver()=nullptr;
    assert(outputResult==EOPNOTSUPP&&original);
    mbuf_freem(original);
    {std::lock_guard<std::mutex> guard(finalizeMutex);blockFinalize=false;}
    Origin::Snapshot state{};snapshotDirectedOriginTx(&state);
    assert(state.state==Origin::State::Revoked);
    assert(close());assertBalanced(dev);
}

void caseOpenBindings(FakeIf &dev) {
    prepare(dev);
    auto armed=request();Origin::Ticket ticket{};
    auto bad=armed;bad.rocChannelIndex=5;assert(!open(bad,&ticket));
    bad=armed;bad.epochs.power++;assert(!open(bad,&ticket));
    bad=armed;bad.sourceIPv6[15]^=1;assert(!open(bad,&ticket));
    bad=armed;bad.deadlineUs=bad.rocStartUs+Origin::kMaximumWindowUs+1;
    assert(!open(bad,&ticket));
    assert(open(armed,&ticket));
    assert(closeDirectedOriginTx(ticket));
    bad=armed;bad.runSerial++;assert(!open(bad,&ticket)); // nonce replay
    assert(close());assertBalanced(dev);
}

void caseLiveAddressScope(FakeIf &dev) {
    prepare(dev);
    uint8_t canonical[16];makeLinkLocal(canonical,own);
    struct ScopeCase {uint16_t embedded;uint32_t sockaddr;bool accepted;};
    const ScopeCase cases[]={
        {0,0,true},       // ordinary canonical sockaddr
        {0,8,true},       // canonical bytes with scope in sin6_scope_id
        {8,0,true},       // XNU embedded scope, recovered by the bridge
        {8,8,true},       // both representations identify the live ifindex
        {9,0,false},      // unknown embedded zone must not be erased
        {0,9,false},      // wrong sockaddr scope must not be ignored
        {9,8,false},      // one correct scope cannot excuse the other
        {256,0,false}     // unknown embedded zone, byte order checked
    };
    uint64_t run=1300;
    uint8_t nonceSuffix=0x40;
    for(const auto &scope:cases) {
        setLiveLinkLocal(dev,canonical,scope.embedded,scope.sockaddr);
        auto armed=request(run++);armed.nonce[7]=nonceSuffix++;
        Origin::Ticket ticket{};
        const bool opened=open(armed,&ticket);
        assert(opened==scope.accepted);
        if(opened) {
            mbuf_t original=packet(Damage::None,armed.nonce);
            assert(output(&original)==EJUSTRETURN&&!original);
            uint64_t token=0;
            mbuf_t encoded=popDirectedOriginTx(ticket,4,5,&token);
            assert(encoded&&token==ticket.ticketSerial&&encoded->total==96);
            mbuf_freem(encoded);
            assert(closeDirectedOriginTx(ticket));
        }
    }
    uint8_t nonLinkLocal[16]{};
    nonLinkLocal[0]=0x20;nonLinkLocal[1]=0x01;
    setLiveLinkLocal(dev,nonLinkLocal,0,8);
    auto nonLinkRequest=request(run++);nonLinkRequest.nonce[7]=nonceSuffix++;
    Origin::Ticket ignored{};
    assert(!open(nonLinkRequest,&ignored));

    // A different canonical IID still works after prior malformed scope
    // entries; source matching remains exact after scope normalization.
    setLiveLinkLocal(dev,canonical,8,0);
    auto finalRequest=request(run++);finalRequest.nonce[7]=nonceSuffix++;
    finalRequest.sourceIPv6[15]^=1;
    assert(!open(finalRequest,&ignored));
    assert(close());assertBalanced(dev);
}

void caseTwoPacketExchange(FakeIf &dev) {
    prepare(dev);
    const auto armed=twoPacketRequest();
    auto rxLease=directedLease(armed);
    assert(publishDirectedDataRxInputLease(rxLease));
    Origin::Ticket ticket{};assert(open(armed,&ticket));
    assert(ticket.deadlineUs==armed.rocStartUs+DirectedRx::kSessionWindowUs);

    mbuf_t secondTooSoon=packet(Damage::None,armed.packetNonces[1]);
    assert(output(&secondTooSoon)==EOPNOTSUPP&&secondTooSoon);
    mbuf_freem(secondTooSoon);

    mbuf_t first=packet(Damage::None,armed.packetNonces[0]);
    assert(output(&first)==EJUSTRETURN&&!first);
    Origin::PacketIdentity firstIdentity{};
    mbuf_t encoded=popDirectedOriginTx(ticket,0x111,0x211,&firstIdentity);
    assert(encoded&&firstIdentity.slot==0&&
           firstIdentity.ticketSerial==ticket.ticketSerial&&
           firstIdentity.packetSerial!=0&&
           !memcmp(firstIdentity.nonce,armed.packetNonces[0],8));
    mbuf_freem(encoded);

    // The RX and DLIL success can arrive after the actual submit but before
    // the HAL's post-gate doorbell note. It stays a candidate until that note.
    fakeTime=armed.rocStartUs+110;
    assert(captureExactEcho(&rxLease,armed.packetNonces[0],0x301)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    auto rxSnapshot=snapshot().directedDataRxInput;
    assert(rxSnapshot.exactReplies[0].present==1&&
           rxSnapshot.exactReplies[0].captured==1&&
           rxSnapshot.exactReplies[0].delivered==1&&
           rxSnapshot.exactReplies[0].valid==0);
    assert(recordDirectedTxDoorbell(ticket,firstIdentity,
                                    armed.rocStartUs+100));
    assert(snapshot().directedDataRxInput.exactReplies[0].valid==1);
    fakeTime=armed.rocStartUs+120;
    assert(recordDirectedTxCompletion(ticket,firstIdentity,true,
                                      armed.rocStartUs+115));
    Origin::Snapshot origin{};snapshotDirectedOriginTx(&origin);
    assert(origin.state==Origin::State::OpenNext&&
           origin.packets[0].txSucceeded&&origin.packets[0].exactReplyValid);

    mbuf_t second=packet(Damage::None,armed.packetNonces[1]);
    assert(output(&second)==EJUSTRETURN&&!second);
    Origin::PacketIdentity secondIdentity{};
    encoded=popDirectedOriginTx(ticket,0x112,0x212,&secondIdentity);
    assert(encoded&&secondIdentity.slot==1&&
           secondIdentity.ticketSerial==ticket.ticketSerial&&
           secondIdentity.packetSerial!=firstIdentity.packetSerial&&
           !memcmp(secondIdentity.nonce,armed.packetNonces[1],8));
    mbuf_freem(encoded);

    // A matching second nonce observed before packet 2's actual submit is
    // retained only as audit data. The later doorbell invalidates it.
    fakeTime=armed.rocStartUs+130;
    assert(captureExactEcho(&rxLease,armed.packetNonces[1],0x302)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    rxSnapshot=snapshot().directedDataRxInput;
    assert(rxSnapshot.exactReplies[1].captured==1&&
           rxSnapshot.exactReplies[1].delivered==1&&
           rxSnapshot.exactReplies[1].valid==0);
    fakeTime=armed.rocStartUs+150;
    assert(recordDirectedTxDoorbell(ticket,secondIdentity,
                                    armed.rocStartUs+140));
    rxSnapshot=snapshot().directedDataRxInput;
    assert(rxSnapshot.exactReplies[1].captured==0&&
           rxSnapshot.exactReplies[1].delivered==0&&
           rxSnapshot.exactReplies[1].valid==0);

    fakeTime=armed.rocStartUs+160;
    assert(captureExactEcho(&rxLease,armed.packetNonces[1],0x303)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    fakeTime=armed.rocStartUs+180;
    assert(recordDirectedTxCompletion(ticket,secondIdentity,true,
                                      armed.rocStartUs+170));
    origin=Origin::Snapshot{};snapshotDirectedOriginTx(&origin);
    rxSnapshot=snapshot().directedDataRxInput;
    assert(origin.state==Origin::State::Spent&&
           origin.packets[0].exactReplyValid&&
           origin.packets[1].exactReplyValid&&
           rxSnapshot.exactReplies[0].valid==1&&
           rxSnapshot.exactReplies[1].valid==1);
    assert(closeDirectedOriginTx(ticket));
    assert(close());assertBalanced(dev);
}

void caseKnownDoorbellRejectsOldCapture(FakeIf &dev) {
    prepare(dev);
    const auto armed=twoPacketRequest(1302);
    auto rxLease=directedLease(armed);
    assert(publishDirectedDataRxInputLease(rxLease));
    Origin::Ticket ticket{};assert(open(armed,&ticket));
    mbuf_t first=packet(Damage::None,armed.packetNonces[0]);
    assert(output(&first)==EJUSTRETURN&&!first);
    Origin::PacketIdentity identity{};
    mbuf_t encoded=popDirectedOriginTx(ticket,0x121,0x221,&identity);
    assert(encoded&&identity.slot==0);mbuf_freem(encoded);
    fakeTime=armed.rocStartUs+110;
    assert(recordDirectedTxDoorbell(ticket,identity,
                                    armed.rocStartUs+100));

    // Model a packet that was captured before the known doorbell but whose
    // RX worker arrives later. It is delivered as ordinary input, never as
    // the exact origin reply, and cannot occupy the receipt slot.
    fakeTime=armed.rocStartUs+99;
    assert(captureExactEcho(&rxLease,armed.packetNonces[0],0x311)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    auto exact=snapshot().directedDataRxInput.exactReplies[0];
    assert(exact.present==1&&exact.captured==0&&exact.delivered==0&&
           exact.valid==0);

    fakeTime=armed.rocStartUs+120;
    assert(captureExactEcho(&rxLease,armed.packetNonces[0],0x312)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    fakeTime=armed.rocStartUs+130;
    assert(recordDirectedTxCompletion(ticket,identity,true,
                                      armed.rocStartUs+125));
    Origin::Snapshot origin{};snapshotDirectedOriginTx(&origin);
    exact=snapshot().directedDataRxInput.exactReplies[0];
    assert(origin.state==Origin::State::OpenNext&&exact.valid==1&&
           exact.captureUs==armed.rocStartUs+120);
    assert(closeDirectedOriginTx(ticket));
    assert(close());assertBalanced(dev);
}

void caseEndBetweenInputAndReceipt(FakeIf &dev) {
    prepare(dev);
    const auto armed=twoPacketRequest(1303);
    auto rxLease=directedLease(armed);
    assert(publishDirectedDataRxInputLease(rxLease));
    Origin::Ticket ticket{};assert(open(armed,&ticket));
    mbuf_t first=packet(Damage::None,armed.packetNonces[0]);
    assert(output(&first)==EJUSTRETURN&&!first);
    Origin::PacketIdentity identity{};
    mbuf_t encoded=popDirectedOriginTx(ticket,0x131,0x231,&identity);
    assert(encoded&&identity.slot==0);mbuf_freem(encoded);
    fakeTime=armed.rocStartUs+100;
    assert(recordDirectedTxDoorbell(ticket,identity,
                                    armed.rocStartUs+90));
    fakeTime=armed.rocStartUs+110;
    assert(recordDirectedTxCompletion(ticket,identity,true,
                                      armed.rocStartUs+105));

    fastEndOwner=armed.ownerSerial;
    fastEndEpochs=rxLease.epochs;
    fakeInputObserver()=endFastAtInput;
    assert(captureExactEcho(&rxLease,armed.packetNonces[0],0x321)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    fakeInputObserver()=nullptr;
    auto exact=snapshot().directedDataRxInput.exactReplies[0];
    Origin::Snapshot origin{};snapshotDirectedOriginTx(&origin);
    assert(exact.present==1&&exact.captured==1&&exact.delivered==0&&
           exact.valid==0&&origin.state==Origin::State::AwaitingPacketProof);
    mbuf_t second=packet(Damage::None,armed.packetNonces[1]);
    assert(output(&second)==EOPNOTSUPP&&second);mbuf_freem(second);
    assert(closeDirectedOriginTx(ticket));
    assert(close());assertBalanced(dev);
}

void caseEndRetiresQueuedSecondPacket(FakeIf &dev) {
    prepare(dev);
    const auto armed=twoPacketRequest(1304);
    auto rxLease=directedLease(armed);
    assert(publishDirectedDataRxInputLease(rxLease));
    Origin::Ticket ticket{};assert(open(armed,&ticket));

    mbuf_t first=packet(Damage::None,armed.packetNonces[0]);
    assert(output(&first)==EJUSTRETURN&&!first);
    Origin::PacketIdentity firstIdentity{};
    mbuf_t encoded=popDirectedOriginTx(ticket,0x141,0x241,&firstIdentity);
    assert(encoded&&firstIdentity.slot==0);mbuf_freem(encoded);
    fakeTime=armed.rocStartUs+110;
    assert(recordDirectedTxDoorbell(ticket,firstIdentity,
                                    armed.rocStartUs+100));
    assert(captureExactEcho(&rxLease,armed.packetNonces[0],0x331)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    fakeTime=armed.rocStartUs+120;
    assert(recordDirectedTxCompletion(ticket,firstIdentity,true,
                                      armed.rocStartUs+115));
    Origin::Snapshot origin{};snapshotDirectedOriginTx(&origin);
    assert(origin.state==Origin::State::OpenNext);

    fakeTime=armed.rocStartUs+125;
    mbuf_t second=packet(Damage::None,armed.packetNonces[1]);
    assert(output(&second)==EJUSTRETURN&&!second);
    snapshotDirectedOriginTx(&origin);
    assert(origin.state==Origin::State::QueuedNext&&
           origin.packets[1].outputAccepted&&origin.packets[1].packetQueued&&
           origin.packets[1].packetSerial!=0);

    assert(markDirectedDataEndFast(ticket.ownerSerial,rxLease.epochs));
    revokeDirectedDataRxInput(ticket.ownerSerial,rxLease.epochs);
    revokeDirectedOriginTx(); // Retires the actual queued mbuf after END.
    snapshotDirectedOriginTx(&origin);
    assert(origin.state==Origin::State::Revoked&&!origin.packetQueued&&
           !origin.packetPopping&&!origin.packets[1].packetQueued&&
           !origin.packets[1].packetPopping&&
           origin.packets[1].outputAccepted&&
           origin.packets[1].packetSerial!=0);
    assert(close());assertBalanced(dev);
}

void caseLockWaitPastDeadlineDoesNotCommit(FakeIf &dev) {
    prepare(dev);
    const auto armed=twoPacketRequest(1305);
    auto rxLease=directedLease(armed);
    assert(publishDirectedDataRxInputLease(rxLease));
    Origin::Ticket ticket{};assert(open(armed,&ticket));
    mbuf_t first=packet(Damage::None,armed.packetNonces[0]);
    assert(output(&first)==EJUSTRETURN&&!first);
    Origin::PacketIdentity identity{};
    mbuf_t encoded=popDirectedOriginTx(ticket,0x151,0x251,&identity);
    assert(encoded&&identity.slot==0);mbuf_freem(encoded);
    fakeTime=armed.rocStartUs+105;
    assert(recordDirectedTxDoorbell(ticket,identity,
                                    armed.rocStartUs+100));
    fakeTime=armed.rocStartUs+115;
    assert(recordDirectedTxCompletion(ticket,identity,true,
                                      armed.rocStartUs+110));

    // Input completes just before the ROC expires. The host shim advances
    // monotonic time on the immediately following lock-held receipt read,
    // modeling a wait for the BSD lock across the hard deadline.
    fakeTime=armed.deadlineUs-2;
    deadlineAdvanceTarget=armed.deadlineUs;
    fakeInputObserver()=advanceToDeadlineAfterInput;
    assert(captureExactEcho(&rxLease,armed.packetNonces[0],0x341)==
           CaptureResult::Captured);
    poll(true,11,&rxLease);
    fakeInputObserver()=nullptr;
    assert(fakeTime==armed.deadlineUs);
    auto exact=snapshot().directedDataRxInput.exactReplies[0];
    assert(exact.present==1&&exact.captured==1&&exact.delivered==0&&
           exact.valid==0);
    Origin::Snapshot origin{};snapshotDirectedOriginTx(&origin);
    assert(origin.state==Origin::State::Expired&&
           origin.packets[0].exactReplyValid==false);
    assert(close());assertBalanced(dev);
}

void caseEndInvalidatesSpentSecondProof(FakeIf &) {
    Origin::Ledger ledger;
    auto armed=twoPacketRequest(1306);
    Origin::Ticket ticket{};
    assert(ledger.open(armed,armed.rocStartUs,armed.epochs.power,
        88,8,own,armed.sourceIPv6,&ticket));
    Origin::PacketIdentity identities[2]{};
    for(uint8_t slot=0;slot<2;++slot)
        assert(ledger.packetIdentity(ticket,slot,&identities[slot]));

    auto finishProof=[&](uint8_t slot,uint64_t base) {
        assert(ledger.acceptsOutput(ticket,slot,base,true,
                                    armed.epochs.power,88));
        assert(ledger.beginPop(ticket,identities[slot],base+1,true,
                               armed.epochs.power,88));
        assert(ledger.finishPop(ticket,identities[slot],base+2,true,
                                armed.epochs.power,88,true));
        assert(ledger.recordTxDoorbell(ticket,identities[slot],base+3,base+3,
                                       armed.epochs.power,88));
        assert(ledger.recordTxCompletion(ticket,identities[slot],true,
            base+4,base+4,armed.epochs.power,88));
        assert(ledger.recordExactReplyCaptured(ticket,identities[slot],
            base+5,base+5,armed.epochs.power,88));
        assert(ledger.recordExactReplyDelivered(ticket,identities[slot],
            base+5,base+6,base+6,armed.epochs.power,88));
    };
    finishProof(0,armed.rocStartUs+10);
    assert(ledger.snapshot(armed.rocStartUs+20,true).state==
           Origin::State::OpenNext);
    finishProof(1,armed.rocStartUs+30);
    auto state=ledger.snapshot(armed.rocStartUs+40,true);
    assert(state.state==Origin::State::Spent&&
           state.packets[1].exactReplyValid&&state.packets[1].packetSpent);
    assert(ledger.invalidateExactReplyAfterEnd(ticket,identities[1]));
    state=ledger.snapshot(armed.rocStartUs+41,true);
    assert(state.state==Origin::State::AwaitingFinalProof&&
           !state.packets[1].exactReplyValid&&state.packets[1].packetSpent);
}
}

int main(int argc,char **argv) {
    assert(argc==2);
    FakeIf dev;
    switch(atoi(argv[1])) {
        case 1:caseSuccess(dev);break;
        case 2:caseRejectThenAccept(dev);break;
        case 3:caseChecksumReject(dev);break;
        case 4:caseExpiry(dev);break;
        case 5:caseCloseUnsubmitted(dev);break;
        case 6:caseStop(dev);break;
        case 7:caseConcurrentOutputs(dev);break;
        case 8:caseCloseDuringFinalize(dev);break;
        case 9:caseStopDuringFinalize(dev);break;
        case 10:caseOpenBindings(dev);break;
        case 11:caseLiveAddressScope(dev);break;
        case 12:caseTwoPacketExchange(dev);break;
        case 13:caseKnownDoorbellRejectsOldCapture(dev);break;
        case 14:caseEndBetweenInputAndReceipt(dev);break;
        case 15:caseEndRetiresQueuedSecondPacket(dev);break;
        case 16:caseLockWaitPastDeadlineDoesNotCommit(dev);break;
        case 17:caseEndInvalidatesSpentSecondProof(dev);break;
        default:assert(false&&"unknown Test107 case");
    }
    return 0;
}
