// SPDX-License-Identifier: GPL-2.0-only
// Actual bridge/getter bodies; surrounding clock/KPI/stack are test doubles.
#include "test104_rx149_hal_fixture.hpp"
#include <thread>
#include <atomic>
#include <chrono>
namespace B=NativeAwdlBSD;
namespace S=NativeAwdlReplyShadow;
namespace P=NativeP2PRx149DataInput;
static S::Config cfg;
static FakeIf dev;
static ItlIwx hal;
static P::Lease lease;
static std::atomic<bool> entered{false},released{false};
static void put16(uint8_t *p,uint16_t n){p[0]=uint8_t(n>>8);p[1]=uint8_t(n);}
static void checksum(uint8_t *ip) {
    ip[46]=ip[47]=0;uint32_t sum=16+17;
    for(unsigned i=8;i<40;i+=2)sum+=S::be16(ip+i);
    for(unsigned i=40;i<56;i+=2)sum+=S::be16(ip+i);
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    const uint16_t value=uint16_t(~sum);put16(ip+46,value?value:65535);
}
static void ipBytes(uint8_t ip[56],bool reply) {
    memset(ip,0,56);ip[0]=0x60;put16(ip+4,16);ip[6]=17;ip[7]=1;
    memcpy(ip+8,reply?cfg.ownIp:cfg.peerIp,16);memcpy(ip+24,reply?cfg.peerIp:cfg.ownIp,16);
    put16(ip+40,reply?cfg.localPort:cfg.peerPort);put16(ip+42,reply?cfg.peerPort:cfg.localPort);
    put16(ip+44,16);memcpy(ip+48,cfg.nonce,8);checksum(ip);assert(S::udpChecksum(ip));
}
static void setup(bool enabled=true) {
    prepare(dev);assert(hal.tahoeP2pRx149DataLease(&lease));
    cfg.enabled=enabled;cfg.runSerial=10501;cfg.ownerSerial=lease.ownerSerial;
    cfg.interfaceIncarnation=B::interfaceIncarnation;cfg.epochs=lease.epochs;
    cfg.deadlineUs=90000;memcpy(cfg.ownMac,dev.lladdr,6);memcpy(cfg.peerMac,peer,6);
    memcpy(cfg.ownIp,dev.address,16);memcpy(cfg.peerIp,dev.address,16);cfg.peerIp[15]^=0x51;
    memcpy(cfg.nonce,"S105N001",8);
}
static bool configure(){return B::configureReplyShadow(cfg,lease);}
static void request(const char *mutation=nullptr) {
    uint8_t ip[56];ipBytes(ip,false);
    if(mutation) {
        if(!strcmp(mutation,"payload"))ip[48]^=1;
        if(!strcmp(mutation,"ports"))ip[41]^=1;
        if(!strcmp(mutation,"address"))ip[23]^=1;
        if(!strcmp(mutation,"hop"))ip[7]=2;
        checksum(ip);
        if(!strcmp(mutation,"checksum"))ip[46]^=1;
    }
    NativeAwdlData::EncodeInput input{};
    memcpy(input.sourceAddress,cfg.peerMac,6);memcpy(input.destinationAddress,cfg.ownMac,6);
    input.wifiSequenceNumber=291;input.awdlSequenceNumber=907;input.ipv6Packet=ip;input.ipv6Length=56;
    uint8_t frame[128];size_t length=0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(&input,frame,sizeof(frame),&length)==NativeAwdlData::Status::Ok);
    assert(length==96);P::Permit permit{};assert(P::makePermit(lease,validDescriptor(),&permit));
    assert(B::captureRx149Data(frame,length,false,lease,permit,72)==B::CaptureResult::Captured);
    B::poll(true,72,&lease);
}
static mbuf_t ethernet() {
    auto m=B::packetWithHeader();assert(m);auto p=static_cast<uint8_t *>(mbuf_data(m));
    memcpy(p,cfg.peerMac,6);memcpy(p+6,cfg.ownMac,6);p[12]=0x86;p[13]=0xdd;ipBytes(p+14,true);
    mbuf_setlen(m,70);mbuf_pkthdr_setlen(m,70);return m;
}
static void output(mbuf_t m,ifnet_t target=&dev,unsigned family=AF_INET6) {
    auto original=m;assert(installed.iff_output(nullptr,target,family,&m)==EOPNOTSUPP);
    assert(m==original); // Shadow never consumes the stack-owned packet.
    mbuf_freem(m);
}
static void neverTx() {
    static_assert(!S::firmwareTransmitAllowed(),"Shadow cannot permit TX");
    assert(!B::replyShadowSnapshot().txArmed);
    assert(B::tx.count==0&&B::tx.head==0&&B::tx.tail==0&&B::inFlightToken==0);
    uint64_t token=123;assert(B::nextTx(0,&token)==nullptr&&token==0);
    B::DiscoveryTxSnapshot d{};assert(!B::peekDiscoveryTx(72,&d));
    const auto snap=B::snapshot();assert(snap.value[B::TxEncoded]==0&&snap.value[B::TxSubmitted]==0&&snap.value[B::TxCompleted]==0);
}
static void finish() {
    fakeInputObserver()=nullptr;fakeFinalizeObserver()=nullptr;neverTx();
    assert(B::close());assert(dev.refs==0);assert(allocated==freed);
}
static void synchronous(ifnet_t received,mbuf_t) {
    assert(received==&dev);assert(B::lock->try_lock());B::lock->unlock();
    assert(B::replyShadowSnapshot().state==S::State::InputPending);
    output(ethernet());
    auto s=B::replyShadowSnapshot();assert(s.state==S::State::ReplyPendingInput&&!s.inputConfirmed&&!s.associationCurrent);
    neverTx();
}
static void blockFinalize(mbuf_t) {
    assert(B::lock->try_lock());B::lock->unlock();entered.store(true,std::memory_order_release);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(!released.load(std::memory_order_acquire)){assert(std::chrono::steady_clock::now()<deadline);std::this_thread::yield();}
}
static void waitEntered() {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(!entered.load(std::memory_order_acquire)){assert(std::chrono::steady_clock::now()<deadline);std::this_thread::yield();}
}
static void endInFinalize(mbuf_t) {B::revokeRx149DataInput(lease.ownerSerial,lease.epochs);}
static void rewriteInFinalize(mbuf_t m) {m->bytes[14+41]^=1;checksum(m->bytes+14);}
static void fillChecksum(mbuf_t m){checksum(m->bytes+14);}
static void endInInput(ifnet_t,mbuf_t){synchronous(&dev,nullptr);B::revokeRx149DataInput(lease.ownerSerial,lease.epochs);}
static void faultInInput(ifnet_t,mbuf_t){synchronous(&dev,nullptr);B::invalidateRx149DataInputFast();}
int main(int argc,char **argv) {
    assert(argc==2);const std::string name=argv[1];
    if(name=="start") {
        prepare(dev);hal.pending();assert(!hal.tahoeP2pRx149DataLease(&lease));
        cfg.enabled=true;assert(!configure());assert(B::rx149OwnerSerialHighWater==0);
        hal.started();assert(hal.tahoeP2pRx149DataLease(&lease));
        assert(B::rx149OwnerSerialHighWater==901);finish();
    } else {
        setup(name!="runtime_off");
#if !defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
        assert(!configure());request();output(ethernet());assert(!B::replyShadowSnapshot().configured);assert(finalized==0);finish();
#else
        if(name=="default"||name=="runtime_off") {
            if(name=="runtime_off")assert(!configure());
            request();output(ethernet());assert(!B::replyShadowSnapshot().configured&&finalized==0);finish();
        } else if(name.find("config_")==0) {
            if(name=="config_owner")++cfg.ownerSerial;
            if(name=="config_epoch")++cfg.epochs.station;
            if(name=="config_incarnation")++cfg.interfaceIncarnation;
            if(name=="config_mac")cfg.ownMac[5]^=1;
            if(name=="config_ip")cfg.ownIp[15]^=1;
            if(name=="config_nonce")memset(cfg.nonce,0,8);
            if(name=="config_deadline")cfg.deadlineUs=100329;
            if(name=="config_expired")cfg.deadlineUs=1001;
            assert(!configure());assert(!B::replyShadowSnapshot().configured);finish();
        } else {
            assert(configure());
            if(name=="sync"||name=="input_fail"||name=="input_end"||name=="input_fault") {
                fakeInputObserver()=name=="input_end"?endInInput:name=="input_fault"?faultInInput:synchronous;inputFail=name=="input_fail";request();
                auto s=B::replyShadowSnapshot();
                assert(s.replyPresent&&s.requestSequence==1&&s.replyIpLength==56);
                const bool success=name=="sync";
                assert(s.state==(success?S::State::Associated:S::State::Retired));
                assert(s.inputConfirmed==success&&s.associationCurrent==success);
            } else if(name.find("request_")==0) {
                request(name.c_str()+8);auto s=B::replyShadowSnapshot();assert(!s.requestPresent&&s.rejections==1);assert(delivered==1);
            } else if(name=="no_request") {
                output(ethernet());auto s=B::replyShadowSnapshot();assert(!s.replyPresent&&s.lastReject==S::Reason::NoRequest);
            } else {
                request();assert(B::replyShadowSnapshot().state==S::State::InputConfirmed);
                if(name=="async"||name=="copy"||name=="duplicate"||name=="concurrent") {
                    if(name=="concurrent") {
                        std::thread a([]{output(ethernet());});std::thread b([]{output(ethernet());});a.join();b.join();
                    } else output(ethernet());
                    auto s=B::replyShadowSnapshot();assert(s.associationCurrent&&s.requestSequence==1&&s.wifiSequenceControl==(291<<4)&&s.awdlSequence==907);
                    uint8_t expected[56];ipBytes(expected,true);assert(!memcmp(s.replyIp,expected,56));
                    if(name=="duplicate") {assert(!configure());request();output(ethernet());auto t=B::replyShadowSnapshot();assert(t.requestSequence==1&&t.requestOverflow==1&&t.replyOverflow==1&&!memcmp(s.replyIp,t.replyIp,56));}
                    if(name=="concurrent")assert(s.replyOverflow==1&&s.replies==1);
                    if(name=="copy") {auto m=ethernet();memset(m->bytes,0,70);mbuf_freem(m);assert(!memcmp(B::replyShadowSnapshot().replyIp,expected,56));}
                } else if(name=="close_pin") {
                    fakeFinalizeObserver()=blockFinalize;std::thread worker([]{output(ethernet());});waitEntered();
                    assert(B::replyShadowOutputCalls==1&&!B::close()&&dev.refs==1);
                    released.store(true,std::memory_order_release);worker.join();assert(!B::replyShadowSnapshot().associationCurrent);
                } else if(name=="finalize_end"||name=="finalize_rewrite"||name=="deferred_checksum") {
                    auto m=ethernet();fakeFinalizeObserver()=name=="finalize_end"?endInFinalize:name=="finalize_rewrite"?rewriteInFinalize:fillChecksum;
                    if(name=="deferred_checksum")m->bytes[60]=m->bytes[61]=0;
                    output(m);auto s=B::replyShadowSnapshot();assert(s.associationCurrent==(name=="deferred_checksum"));
                } else if(name.find("reply_")==0) {
                    auto m=ethernet();auto ip=m->bytes+14;
                    if(name=="reply_payload")ip[48]^=1;
                    if(name=="reply_ports")ip[41]^=1;
                    if(name=="reply_address")ip[23]^=1;
                    if(name=="reply_mac")m->bytes[0]^=2;
                    if(name=="reply_hop")ip[7]=2;
                    checksum(ip);
                    if(name=="reply_checksum")ip[46]^=1;
                    if(name=="reply_short")m->total=69;
                    if(name=="reply_long")m->total=71;
                    if(name=="reply_header")m->flags=0;
                    FakeIf otherDev;output(m,name=="reply_ifnet"?&otherDev:&dev,name=="reply_family"?2:AF_INET6);
                    assert(!B::replyShadowSnapshot().replyPresent);
                } else {
                    if(name=="end"||name=="old_owner")B::revokeRx149DataInput(lease.ownerSerial,lease.epochs);
                    if(name=="fault")B::invalidateRx149DataInputFast();
                    if(name=="disable")B::disableReplyShadow();
                    if(name=="expiry")fakeTime=90000;
                    if(name=="clock_rollback")fakeTime=1000;
                    if(name=="incarnation")++B::interfaceIncarnation;
                    if(name=="radio")B::poll(false,72);
                    if(name=="epoch")B::poll(true,73);
                    if(name=="new_owner"){hal.nextOwner();assert(hal.tahoeP2pRx149DataLease(&lease));}
                    if(name=="old_owner")assert(!B::publishRx149DataInputLease(lease));
                    output(ethernet());assert(!B::replyShadowSnapshot().associationCurrent&&!B::replyShadowSnapshot().replyPresent);assert(!configure());
                }
            }
            finish();
        }
#endif
    }
    printf("{\"case\":\"%s\",\"passed\":true,\"real_network\":false}\n",argv[1]);
}
