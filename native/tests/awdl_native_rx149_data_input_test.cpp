// SPDX-License-Identifier: GPL-2.0-only
// Host-only functional tests for the production BSD bridge Test086 RX path.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_data_frame.hpp"
#include "../p2p_rx149_data_input.hpp"

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=1001;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;

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

void makeFrame(uint8_t *out,size_t capacity,size_t *written,
               const uint8_t *destination=own) {
    uint8_t ipv6[40]{};
    ipv6[0]=0x60;
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

Permit captureFrame(const Lease &lease,const uint8_t *destination=own) {
    uint8_t bytes[256]{};
    size_t length=0;
    makeFrame(bytes,sizeof(bytes),&length,destination);
    auto descriptor=validDescriptor();
    Permit permit{};
    assert(makePermit(lease,descriptor,&permit));
    assert(captureRx149Data(bytes,length,false,lease,permit,72)==
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
    assert(receipt.schemaVersion==1&&receipt.sequence==1);
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
        default:return 2;
    }
}
