// SPDX-License-Identifier: GPL-2.0-only
// Host-only functional tests for the production BSD bridge Test086 RX path.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_data_frame.hpp"
#include "../p2p_rx149_data_input.hpp"
#include "../p2p_rx149_input_receipt_publisher.hpp"

#include <map>
#include <string>
#include <vector>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=1001;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;
namespace {
NativeAwdlBSD::Rx149TestHookPoint hookPoint=
    NativeAwdlBSD::Rx149TestHookPoint::LeaseAuthorization;
uint64_t hookTime=0;
void setTimeAtHook(NativeAwdlBSD::Rx149TestHookPoint point) {
    if(point==hookPoint) {
        fakeTime=hookTime;
        NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    }
}
void invalidateAtTicket(NativeAwdlBSD::Rx149TestHookPoint point) {
    if(point==NativeAwdlBSD::Rx149TestHookPoint::AfterInputTicket) {
        NativeAwdlBSD::invalidateRx149DataInputFast();
        NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    }
}
void invalidateBeforeReservation(NativeAwdlBSD::Rx149TestHookPoint point) {
    if(point==NativeAwdlBSD::Rx149TestHookPoint::BeforeInputTicketReservation) {
        NativeAwdlBSD::invalidateRx149DataInputFast();
        NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    }
}
}

namespace {
using namespace NativeAwdlBSD;
using namespace NativeP2PRx149DataInput;
const uint8_t own[6]={0x02,0x01,0x02,0x03,0x04,0x05};
const uint8_t peer[6]={0x02,0x06,0x07,0x08,0x09,0x0a};
const uint8_t other[6]={0x02,0x09,0x08,0x07,0x06,0x05};

Lease validLease() {
    Lease value{};
    value.compiled=true;
    value.runtimeEnabled=true;
    value.profileEnabled=true;
    value.profileSelected=true;
    value.receiveObservationOnly=true;
    value.leaseActive=true;
    value.ownerCurrent=true;
    value.epochsMatch=true;
    value.tokenMatches=true;
    value.commandReturned=true;
    value.commandSucceeded=true;
    value.deviceDiscoveryConfiguration=true;
    value.startSeen=true;
    value.startSucceeded=true;
    value.endSeen=false;
    value.outcomeUnknown=false;
    value.epochs={71,72,73,71};
    value.ownerSerial=901;
    value.startUs=1000;
    value.nowUs=1001;
    return value;
}

Descriptor validDescriptor(uint8_t raw=0x41,
                           uint32_t decode=kMacPhyDecodeBandInRx) {
    Descriptor value{};
    value.channelPresent=true;
    value.ieeeChannel=149;
    value.macPhyIndexPresent=true;
    value.macPhyIndex=raw;
    value.decodeModePresent=true;
    value.decodeMode=decode;
    value.protectedFrame=false;
    value.awdlDataCandidate=true;
    value.originalDescriptorPresent=true;
    value.hardwareDeaggregated=false;
    value.originalRawStatus=0x12345678u;
    return value;
}

void gateMatrix() {
    auto lease=validLease();
    auto descriptor=validDescriptor();
    Permit permit{};
    assert(makePermit(lease,descriptor,&permit));
    // API59's known MAC index is accepted while its PHY bits remain opaque.
    assert(permit.macIndex==1&&permit.decodeMode==kMacPhyDecodeBandInRx);
    assert(stillCurrent(permit,lease,1002));
    assert(!stillCurrent(permit,lease,101000));

    auto rejectsLease=[&](auto mutate) {
        auto bad=validLease();
        mutate(bad);
        Permit untouched{};
        untouched.valid=true;
        assert(!makePermit(bad,validDescriptor(),&untouched));
        assert(!untouched.valid);
    };
    rejectsLease([](Lease &v){v.compiled=false;});
    rejectsLease([](Lease &v){v.runtimeEnabled=false;});
    rejectsLease([](Lease &v){v.profileEnabled=false;});
    rejectsLease([](Lease &v){v.profileSelected=false;});
    rejectsLease([](Lease &v){v.receiveObservationOnly=false;});
    rejectsLease([](Lease &v){v.leaseActive=false;});
    rejectsLease([](Lease &v){v.ownerCurrent=false;});
    rejectsLease([](Lease &v){v.epochsMatch=false;});
    rejectsLease([](Lease &v){v.tokenMatches=false;});
    rejectsLease([](Lease &v){v.commandReturned=false;});
    rejectsLease([](Lease &v){v.commandSucceeded=false;});
    rejectsLease([](Lease &v){v.deviceDiscoveryConfiguration=false;});
    rejectsLease([](Lease &v){v.startSeen=false;});
    rejectsLease([](Lease &v){v.startSucceeded=false;});
    rejectsLease([](Lease &v){v.endSeen=true;});
    rejectsLease([](Lease &v){v.outcomeUnknown=true;});
    rejectsLease([](Lease &v){v.epochs.context=0;});
    rejectsLease([](Lease &v){v.ownerSerial=0;});
    rejectsLease([](Lease &v){v.nowUs=v.startUs-1;});
    rejectsLease([](Lease &v){v.nowUs=v.startUs+kSessionWindowUs;});

    auto rejectsDescriptor=[&](auto mutate) {
        auto bad=validDescriptor();
        mutate(bad);
        Permit untouched{};
        assert(!makePermit(validLease(),bad,&untouched));
        assert(!untouched.valid);
    };
    rejectsDescriptor([](Descriptor &v){v.channelPresent=false;});
    rejectsDescriptor([](Descriptor &v){v.ieeeChannel=148;});
    rejectsDescriptor([](Descriptor &v){v.macPhyIndexPresent=false;});
    rejectsDescriptor([](Descriptor &v){v.macPhyIndex=0x42;});
    rejectsDescriptor([](Descriptor &v){v.decodeModePresent=false;});
    rejectsDescriptor([](Descriptor &v){v.decodeMode=0;});
    rejectsDescriptor([](Descriptor &v){v.protectedFrame=true;});
    rejectsDescriptor([](Descriptor &v){v.awdlDataCandidate=false;});
    rejectsDescriptor([](Descriptor &v){v.originalDescriptorPresent=false;});
    rejectsDescriptor([](Descriptor &v){v.hardwareDeaggregated=true;});
    auto legacy=validDescriptor(0x11,kMacPhyDecodeLegacy);
    assert(makePermit(validLease(),legacy,&permit));
    legacy.macPhyIndex=0x10;
    assert(!makePermit(validLease(),legacy,&permit));
    auto stale=validLease();
    stale.ownerSerial++;
    assert(!stillCurrent(permit,stale,1002));
    stale=validLease();
    stale.epochs.station++;
    assert(!stillCurrent(permit,stale,1002));
}

void makeLinkLocal(uint8_t *address,const uint8_t *mac) {
    memset(address,0,16);
    address[0]=0xfe;
    address[1]=0x80;
    address[8]=mac[0]^2u;
    address[9]=mac[1];
    address[10]=mac[2];
    address[11]=0xff;
    address[12]=0xfe;
    address[13]=mac[3];
    address[14]=mac[4];
    address[15]=mac[5];
}

void makeFrame(uint8_t *out,size_t capacity,size_t *written,
               const uint8_t *destination=own,bool wrongMapping=false) {
    uint8_t ipv6[40]{};
    ipv6[0]=0x60;
    makeLinkLocal(ipv6+8,peer);
    if(destination[0]&1u) {
        ipv6[24]=0xff;
        ipv6[25]=0x02;
        memcpy(ipv6+36,destination+2,4);
        if(wrongMapping)ipv6[39]^=1u;
    } else {
        makeLinkLocal(ipv6+24,own);
    }
    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress,destination,6);
    memcpy(input.sourceAddress,peer,6);
    input.wifiSequenceNumber=17;
    input.awdlSequenceNumber=23;
    input.ipv6Packet=ipv6;
    input.ipv6Length=sizeof(ipv6);
    assert(NativeAwdlData::encodeIpv6DataMpdu(
        &input,out,capacity,written)==NativeAwdlData::Status::Ok);
}

void prepare(FakeIf &dev) {
    memcpy(dev.lladdr,own,sizeof(own));
    assert(attach(&dev,own));
    poll(true,72);
}

struct ReceiptProperties {
    std::map<std::string,uint64_t> values;
    std::vector<bool> completeAfterWrite;
    int failAtWrite=-1;
    int writes=0;

    bool readNumber(const char *name,uint64_t *value) const {
        const auto found=values.find(name);
        if(found==values.end()||!value)return false;
        *value=found->second;
        return true;
    }

    bool complete() const {
        uint64_t schema=0,begin=0,end=0;
        return readNumber("NativeAwdlDataRx149ReceiptSchemaVersion",&schema)&&
            readNumber("NativeAwdlDataRx149ReceiptSnapshotBegin",&begin)&&
            readNumber("NativeAwdlDataRx149ReceiptSnapshotEnd",&end)&&
            schema==2&&begin!=0&&begin==end&&(begin&1u)==0;
    }

    bool writeNumber(const char *name,uint64_t value,unsigned) {
        if(writes++==failAtWrite)return false;
        values[name]=value;
        completeAfterWrite.push_back(complete());
        return true;
    }
};

CaptureResult captureFrameResult(const Lease &lease,Permit *captured,
                    const uint8_t *destination=own,bool wrongMapping=false) {
    uint8_t bytes[256]{};
    size_t length=0;
    makeFrame(bytes,sizeof(bytes),&length,destination,wrongMapping);
    auto descriptor=validDescriptor();
    Permit permit{};
    if(!makePermit(lease,descriptor,&permit))
        return CaptureResult::Rejected;
    if(captured)*captured=permit;
    return captureRx149Data(bytes,length,false,lease,permit,72);
}

Permit captureFrame(const Lease &lease,const uint8_t *destination=own,
                    bool wrongMapping=false) {
    Permit permit{};
    assert(captureFrameResult(lease,&permit,destination,wrongMapping)==
           CaptureResult::Captured);
    return permit;
}

int delivery() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    const auto permit=captureFrame(lease);
    assert(allocated==0); // capture copied fixed bytes; no mbuf/KPI in RX path
    poll(true,72); // legacy poll must leave scoped data for the guarded worker
    assert(snapshot().value[RxPending]==1&&delivered==0);
    poll(true,72,&lease);
    assert(delivered==1);
    const auto state=snapshot();
    assert(state.value[RxCaptured]==1&&state.value[RxDecoded]==1);
    assert(state.value[RxDelivered]==1&&state.value[RxPending]==0);
    const auto &receipt=state.rx149Input;
    assert(receipt.schemaVersion==2&&receipt.sequence==1);
    assert(receipt.contentRevision==2); // captured then delivered
    assert(receipt.disposition==Rx149ReceiptIfnetInputSucceeded);
    assert(receipt.ownerSerial==lease.ownerSerial);
    assert(receipt.interfaceIncarnation==1);
    assert(receipt.contextGeneration==lease.epochs.context);
    assert(receipt.powerGeneration==lease.epochs.power);
    assert(receipt.stationGeneration==lease.epochs.station);
    assert(receipt.rocGeneration==lease.epochs.roc);
    assert(receipt.captureUs==permit.capturedUs&&receipt.deadlineUs==permit.deadlineUs);
    assert(receipt.ieeeChannel==149&&receipt.macIndexPresent==1&&receipt.macIndex==1);
    assert(receipt.macPhyDecodeMode==kMacPhyDecodeBandInRx);
    assert(receipt.originalRxStatus==0x12345678u&&receipt.mpduLength>24);
    assert(receipt.decodedIpv6Count==1&&receipt.ifnetInputResultPresent==1);
    assert(receipt.ifnetInputResult==0);
    assert(close());
    assert(allocated==freed);
    return 0;
}

int staleOwner() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    revokeRx149DataInput(lease.ownerSerial,lease.epochs);
    assert(snapshot().value[RxPending]==0);
    publishRx149DataInputLease(lease); // tombstone rejects a stale copied guard
    poll(true,72,&lease);
    assert(delivered==0&&snapshot().value[RxPending]==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptStaleOrInvalid);
    assert(close()&&allocated==freed);
    return 0;
}

int ownerSwap() {
    FakeIf dev;
    prepare(dev);
    auto oldLease=validLease();
    publishRx149DataInputLease(oldLease);
    (void)captureFrame(oldLease);
    auto next=validLease();
    next.ownerSerial++;
    next.epochs={72,72,74,72};
    next.startUs=2000;
    next.nowUs=2001;
    fakeTime=2001;
    publishRx149DataInputLease(next);
    assert(snapshot().value[RxPending]==0);
    poll(true,72,&oldLease); // stale worker snapshot cannot restore prior owner
    poll(true,72,&next);
    assert(delivered==0);
    assert(close()&&allocated==freed);
    return 0;
}

int endedWindow() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    auto ended=lease;
    ended.endSeen=true;
    publishRx149DataInputLease(ended);
    assert(snapshot().value[RxPending]==0);
    poll(true,72,&ended);
    assert(delivered==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptStaleOrInvalid);
    assert(close()&&allocated==freed);
    return 0;
}

int timeout() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    fakeTime=101000;
    poll(true,72,&lease);
    assert(delivered==0&&snapshot().value[RxPending]==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptStaleOrInvalid);
    assert(close()&&allocated==freed);
    return 0;
}

int l2Validation() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease,other); // foreign unicast L2 destination
    poll(true,72,&lease);
    assert(delivered==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptAddressRejected);
    assert(snapshot().rx149Input.decodedIpv6Count==1);
    auto multicast=lease;
    multicast.nowUs=1002;
    fakeTime=1002;
    NativeAwdlBSD::publishRx149DataInputLease(multicast);
    const uint8_t group[6]={0x33,0x33,0,0,0,1};
    (void)captureFrame(multicast,group);
    poll(true,72,&multicast);
    assert(delivered==1); // existing multicast destination rule is preserved
    assert(close()&&allocated==freed);
    return 0;
}

int multicastMappingValidation() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    const uint8_t wrongGroup[6]={0x33,0x33,0,0,0,2};
    (void)captureFrame(lease,wrongGroup,true); // IPv6 ff02::1 maps to ...:01
    poll(true,72,&lease);
    assert(delivered==0);
    const auto receipt=snapshot().rx149Input;
    assert(receipt.disposition==Rx149ReceiptAddressRejected);
    assert(receipt.decodedIpv6Count==1);
    assert(close()&&allocated==freed);
    return 0;
}

int targetedRevokeBeforeLeasePublication() {
    FakeIf dev;
    prepare(dev);
    auto old=validLease();
    revokeRx149DataInput(old.ownerSerial,old.epochs);
    publishRx149DataInputLease(old); // stale same-owner START/ACK snapshot
    Permit oldPermit{};
    assert(captureFrameResult(old,&oldPermit)==CaptureResult::Rejected);
    assert(snapshot().value[RxPending]==0);

    auto current=validLease();
    ++current.ownerSerial;
    current.epochs={72,72,74,72};
    current.startUs=2000;
    current.nowUs=2001;
    fakeTime=2001;
    publishRx149DataInputLease(current);
    (void)captureFrame(current);
    poll(true,72,&current);
    assert(delivered==1);
    assert(close()&&allocated==freed);
    return 0;
}

int leaseAuthorizationAfterLockWait() {
    FakeIf dev;
    prepare(dev);
    const auto lease=validLease();
    hookPoint=NativeAwdlBSD::Rx149TestHookPoint::LeaseAuthorization;
    hookTime=lease.startUs+NativeP2PRx149DataInput::kSessionWindowUs;
    NativeAwdlBSD::setRx149TestHookForTests(setTimeAtHook);
    publishRx149DataInputLease(lease);
    NativeAwdlBSD::setRx149TestHookForTests(nullptr);

    // Roll the deterministic clock back only to distinguish the tombstone
    // from a fresh deadline check; a stale lease still cannot activate.
    fakeTime=lease.nowUs;
    Permit permit{};
    assert(captureFrameResult(lease,&permit)==CaptureResult::Rejected);
    assert(snapshot().value[RxPending]==0);
    assert(close()&&allocated==freed);
    return 0;
}

int captureAuthorizationAfterLockWait() {
    FakeIf dev;
    prepare(dev);
    const auto lease=validLease();
    publishRx149DataInputLease(lease);
    hookPoint=NativeAwdlBSD::Rx149TestHookPoint::CaptureAuthorization;
    hookTime=lease.startUs+NativeP2PRx149DataInput::kSessionWindowUs;
    NativeAwdlBSD::setRx149TestHookForTests(setTimeAtHook);
    Permit permit{};
    assert(captureFrameResult(lease,&permit)==CaptureResult::Rejected);
    NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    assert(snapshot().value[RxPending]==0);
    assert(close()&&allocated==freed);
    return 0;
}

int ticketAuthorizationAfterLockWait() {
    FakeIf dev;
    prepare(dev);
    const auto lease=validLease();
    publishRx149DataInputLease(lease);
    const auto permit=captureFrame(lease);
    hookPoint=NativeAwdlBSD::Rx149TestHookPoint::InputTicketAuthorization;
    hookTime=permit.deadlineUs;
    NativeAwdlBSD::setRx149TestHookForTests(setTimeAtHook);
    poll(true,72,&lease);
    NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    assert(delivered==0&&snapshot().value[RxPending]==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptStaleOrInvalid);
    assert(close()&&allocated==freed);
    return 0;
}

int fastInvalidationFencesTicket() {
    FakeIf dev;
    prepare(dev);
    const auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    NativeAwdlBSD::invalidateRx149DataInputFast();
    assert(NativeAwdlBSD::rx149DataInputBlocked());
    poll(true,72,&lease);
    assert(delivered==0&&snapshot().value[RxPending]==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptStaleOrInvalid);
    assert(close()&&allocated==freed);
    return 0;
}

int fastInvalidationWinsBeforeTicketCas() {
    FakeIf dev;
    prepare(dev);
    const auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    NativeAwdlBSD::setRx149TestHookForTests(invalidateBeforeReservation);
    poll(true,72,&lease);
    NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    assert(NativeAwdlBSD::rx149DataInputBlocked());
    assert(delivered==0&&snapshot().value[RxPending]==0);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptStaleOrInvalid);
    assert(close()&&allocated==freed);
    return 0;
}

int admittedTicketMayFinishAfterFastInvalidation() {
    FakeIf dev;
    prepare(dev);
    const auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    NativeAwdlBSD::setRx149TestHookForTests(invalidateAtTicket);
    poll(true,72,&lease);
    NativeAwdlBSD::setRx149TestHookForTests(nullptr);
    assert(NativeAwdlBSD::rx149DataInputBlocked());
    assert(delivered==1&&snapshot().value[RxDelivered]==1);
    assert(snapshot().rx149Input.disposition==Rx149ReceiptIfnetInputSucceeded);
    assert(close()&&allocated==freed);
    return 0;
}

int inputFailure() {
    FakeIf dev;
    prepare(dev);
    auto lease=validLease();
    publishRx149DataInputLease(lease);
    (void)captureFrame(lease);
    inputFail=true;
    poll(true,72,&lease);
    inputFail=false;
    const auto receipt=snapshot().rx149Input;
    assert(receipt.disposition==Rx149ReceiptIfnetInputFailed);
    assert(receipt.contentRevision==2);
    assert(receipt.ifnetInputResultPresent==1&&
           receipt.ifnetInputResult==EIO);
    assert(snapshot().value[RxInputFailed]==1&&delivered==0);
    assert(close()&&allocated==freed);
    return 0;
}

int receiveOnly() {
    FakeIf dev;
    prepare(dev);
    mbuf_t packet=nullptr;
    assert(mbuf_getpacket(MBUF_DONTWAIT,&packet)==0&&packet);
    memcpy(packet->bytes,peer,6);
    memcpy(packet->bytes+6,own,6);
    packet->bytes[12]=0x86;packet->bytes[13]=0xdd;
    packet->bytes[14]=0x60;
    mbuf_setlen(packet,54);mbuf_pkthdr_setlen(packet,54);
    const int result=installed.iff_output(nullptr,&dev,AF_INET6,&packet);
    assert(result==EOPNOTSUPP&&packet!=nullptr);
    assert(snapshot().value[TxAccepted]==0&&snapshot().value[TxPending]==0);
    uint64_t token=77;
    assert(nextTx(1,&token)==nullptr&&token==0);
    DiscoveryTxSnapshot expected{1,1000,72,3,true};
    assert(!peekDiscoveryTx(72,&expected));
    bool consumed=true;
    token=77;
    assert(nextDiscoveryTx(1,expected,&token,&consumed)==nullptr);
    assert(token==0&&!consumed&&snapshot().value[TxPending]==0);
    mbuf_freem(packet);
    assert(close()&&allocated==freed);
    return 0;
}

int receiptPublication() {
    using namespace NativeAwdlBSD;
    ReceiptProperties properties;
    Rx149InputReceiptPublisher publisher;
    auto read=[&](const char *name,uint64_t *value) {
        return properties.readNumber(name,value);
    };
    auto write=[&](const char *name,uint64_t value,unsigned bits) {
        return properties.writeNumber(name,value,bits);
    };

    Rx149InputReceipt receipt{};
    receipt.schemaVersion=2;
    receipt.disposition=Rx149ReceiptCaptured;
    receipt.sequence=77;
    receipt.contentRevision=1;
    receipt.ownerSerial=901;
    receipt.inputUs=1001;
    assert(publisher.publish(receipt,read,write));
    assert(properties.complete());
    unsigned completeWrites=0;
    for(bool complete:properties.completeAfterWrite)
        if(complete)++completeWrites;
    assert(completeWrites==1&&properties.completeAfterWrite.back());

    // The same MPDU sequence can advance from captured to DLIL result. The
    // content revision, not the immutable MPDU sequence, drives publication.
    receipt.disposition=Rx149ReceiptIfnetInputSucceeded;
    receipt.contentRevision=2;
    receipt.inputUs=1042;
    receipt.ifnetInputResultPresent=1;
    receipt.ifnetInputResult=0;
    assert(publisher.publish(receipt,read,write));
    uint64_t value=0;
    assert(properties.readNumber(
        "NativeAwdlDataRx149ReceiptSequence",&value)&&value==77);
    assert(properties.readNumber(
        "NativeAwdlDataRx149ReceiptContentRevision",&value)&&value==2);
    assert(properties.readNumber(
        "NativeAwdlDataRx149ReceiptDisposition",&value)&&
        value==Rx149ReceiptIfnetInputSucceeded);
    assert(properties.readNumber(
        "NativeAwdlDataRx149ReceiptInputMonotonicUs",&value)&&value==1042);
    const int writesAfterRevision=properties.writes;
    assert(publisher.publish(receipt,read,write));
    assert(properties.writes==writesAfterRevision); // stable snapshot dedupe

    // A failed payload write leaves Begin odd, so the identical revision is
    // retried rather than hidden by the prior MPDU sequence or a false cache.
    receipt.disposition=Rx149ReceiptIfnetInputFailed;
    receipt.contentRevision=3;
    receipt.inputUs=1050;
    receipt.ifnetInputResultPresent=1;
    receipt.ifnetInputResult=EIO;
    properties.failAtWrite=properties.writes+3;
    assert(!publisher.publish(receipt,read,write));
    assert(!properties.complete());
    properties.failAtWrite=-1;
    const size_t oldObservations=properties.completeAfterWrite.size();
    assert(publisher.publish(receipt,read,write));
    assert(properties.complete());
    assert(properties.completeAfterWrite.size()>oldObservations);
    assert(properties.completeAfterWrite.back());
    assert(properties.readNumber(
        "NativeAwdlDataRx149ReceiptContentRevision",&value)&&value==3);
    assert(properties.readNumber(
        "NativeAwdlDataRx149ReceiptIfnetInputResult",&value)&&
        value==uint32_t(EIO));

    // A failed final completion marker also leaves the publication fenced.
    receipt.disposition=Rx149ReceiptStaleOrInvalid;
    receipt.contentRevision=4;
    properties.failAtWrite=properties.writes+23; // final matching Begin
    assert(!publisher.publish(receipt,read,write));
    assert(!properties.complete());
    properties.failAtWrite=-1;
    assert(publisher.publish(receipt,read,write));
    assert(properties.complete());
    return 0;
}
}

int main(int argc,char **argv) {
    assert(argc==2);
    gateMatrix();
    const int which=atoi(argv[1]);
    switch(which) {
        case 1:return delivery();
        case 2:return staleOwner();
        case 3:return ownerSwap();
        case 4:return endedWindow();
        case 5:return timeout();
        case 6:return l2Validation();
        case 7:return inputFailure();
        case 8:return receiveOnly();
        case 9:return receiptPublication();
        case 10:return multicastMappingValidation();
        case 11:return targetedRevokeBeforeLeasePublication();
        case 12:return leaseAuthorizationAfterLockWait();
        case 13:return captureAuthorizationAfterLockWait();
        case 14:return ticketAuthorizationAfterLockWait();
        case 15:return fastInvalidationFencesTicket();
        case 16:return admittedTicketMayFinishAfterFastInvalidation();
        case 17:return fastInvalidationWinsBeforeTicketCas();
        default:return 2;
    }
}
