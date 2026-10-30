// SPDX-License-Identifier: GPL-2.0-only
// ThreadSanitizer stress for the production scoped RX queue and revoke path.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_data_frame.hpp"
#include "../p2p_rx149_data_input.hpp"
#include "../rx149_input_gate_state.hpp"

#include <thread>

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

Lease leaseValue() {
    Lease value{};
    value.compiled=true;value.runtimeEnabled=true;value.profileEnabled=true;
    value.profileSelected=true;value.receiveObservationOnly=true;
    value.leaseActive=true;value.ownerCurrent=true;value.epochsMatch=true;
    value.tokenMatches=true;value.commandReturned=true;
    value.commandSucceeded=true;value.deviceDiscoveryConfiguration=true;
    value.startSeen=true;value.startSucceeded=true;
    value.epochs={81,82,83,81};value.ownerSerial=991;
    value.startUs=1000;value.nowUs=1001;
    return value;
}

Descriptor descriptor() {
    Descriptor value{};
    value.channelPresent=true;value.ieeeChannel=149;
    value.macPhyIndexPresent=true;value.macPhyIndex=0x41;
    value.decodeModePresent=true;value.decodeMode=kMacPhyDecodeBandInRx;
    value.awdlDataCandidate=true;value.originalDescriptorPresent=true;
    value.originalRawStatus=0x12345678;
    return value;
}

bool capture(const Lease &lease) {
    uint8_t ipv6[40]{};ipv6[0]=0x60;
    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress,own,6);
    memcpy(input.sourceAddress,peer,6);
    input.ipv6Packet=ipv6;input.ipv6Length=sizeof(ipv6);
    uint8_t frame[256]{};size_t length=0;
    if(NativeAwdlData::encodeIpv6DataMpdu(
           &input,frame,sizeof(frame),&length)!=NativeAwdlData::Status::Ok)
        return false;
    Permit permit{};
    if(!makePermit(lease,descriptor(),&permit))return false;
    const auto result=captureRx149Data(
        frame,length,false,lease,permit,lease.epochs.power);
    return result==CaptureResult::Captured;
}
}

int main() {
    FakeIf dev;memcpy(dev.lladdr,own,6);
    assert(attach(&dev,own));
    poll(true,82);
    const Lease lease=leaseValue();
    publishRx149DataInputLease(lease);

    std::atomic<bool> start{false},finished{false};
    std::thread captureProducer([&] {
        while(!start.load(std::memory_order_acquire)){}
        for(unsigned i=0;i<20000;++i)(void)capture(lease);
        finished.store(true,std::memory_order_release);
    });
    std::thread inputWorker([&] {
        while(!start.load(std::memory_order_acquire)){}
        while(!finished.load(std::memory_order_acquire))
            poll(true,82,&lease);
        poll(true,82,&lease);
    });
    std::thread terminalRevoker([&] {
        while(!start.load(std::memory_order_acquire)){}
        for(unsigned i=0;i<50;++i) {
            if(i==25)revokeRx149DataInput(lease.ownerSerial,lease.epochs);
            poll(true,82,&lease);
        }
    });
    std::thread closer([&] {
        while(!start.load(std::memory_order_acquire)){}
        assert(close());
    });
    start.store(true,std::memory_order_release);
    captureProducer.join();
    inputWorker.join();
    terminalRevoker.join();
    closer.join();

    // A tombstoned copied owner cannot reopen after revoke. Close drains any
    // remaining bounded entries and waits for worker input pins.
    publishRx149DataInputLease(lease);
    assert(dev.refs==0);
    assert(allocated==freed);

    using namespace Rx149InputGateState;
    Word gate=0;
    assert(invalidate(&gate)==1);
    std::atomic<bool> raceStart{false};
    std::thread staleRecovery([&] {
        while(!raceStart.load(std::memory_order_acquire)) {}
        (void)recover(&gate,1);
    });
    std::thread racingFault([&] {
        while(!raceStart.load(std::memory_order_acquire)) {}
        (void)invalidate(&gate);
    });
    raceStart.store(true,std::memory_order_release);
    staleRecovery.join();
    racingFault.join();
    assert(blocked(gate)&&faultSerial(gate)==2&&ticketCount(gate)==0);
}
