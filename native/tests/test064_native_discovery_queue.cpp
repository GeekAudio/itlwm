// SPDX-License-Identifier: GPL-2.0-only
#include "test064_kernel_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_bsd_packet_bridge.hpp"
#include <atomic>
#include <thread>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=1;
thread_local unsigned test064SimpleLockDepth=0;
std::atomic<bool> test064PauseAfterUnlock{false},test064UnlockPaused{false},
    test064ResumeUnlock{false};
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false,test064FinalizeChecksum=true;
iff_filter installed;ifnet_t filterIf=nullptr;

using namespace NativeAwdlBSD;
const uint8_t own[6]={2,1,2,3,4,5};

enum class QueryKind {
    Qm,Qu,Legacy,Other,Unknown,UnknownService,Qr,Mixed,NonIN,WrongGroup,WrongMapping,
    WrongSource,WrongPort
};

void set16(uint8_t *p,uint16_t v){p[0]=uint8_t(v>>8);p[1]=uint8_t(v);}
mbuf_t makeQuery(QueryKind kind=QueryKind::Qm,bool checksumPresent=false) {
    uint8_t dns[96]{};size_t dnsLength=12;
    set16(dns+4,1);
    if(kind==QueryKind::Qr)set16(dns+2,0x8000);
    if(kind!=QueryKind::Unknown) {
        const uint8_t airdropName[]={8,'_','a','i','r','d','r','o','p',
            4,'_','t','c','p',5,'l','o','c','a','l',0};
        const uint8_t unknownServiceName[]={8,'_','n','o','t','a','i','r','d',
            4,'_','u','d','p',5,'l','o','c','a','l',0};
        const uint8_t *name=kind==QueryKind::UnknownService
            ?unknownServiceName:airdropName;
        const size_t nameLength=kind==QueryKind::UnknownService
            ?sizeof(unknownServiceName):sizeof(airdropName);
        memcpy(dns+dnsLength,name,nameLength);dnsLength+=nameLength;
        set16(dns+dnsLength,kind==QueryKind::Other?33:12);dnsLength+=2;
        set16(dns+dnsLength,kind==QueryKind::Qu?0x8001:
            (kind==QueryKind::NonIN?3:1));dnsLength+=2;
        if(kind==QueryKind::Mixed) {
            memcpy(dns+dnsLength,name,nameLength);dnsLength+=nameLength;
            set16(dns+dnsLength,33);dnsLength+=2;
            set16(dns+dnsLength,1);dnsLength+=2;
            set16(dns+4,2);
        }
    }
    const size_t udpLength=8+dnsLength;
    const size_t ipv6Length=40+udpLength;
    const size_t total=14+ipv6Length;
    mbuf_t packet=nullptr;assert(mbuf_getpacket(MBUF_DONTWAIT,&packet)==0&&packet);
    uint8_t *frame=static_cast<uint8_t *>(mbuf_data(packet));
    frame[0]=0x33;frame[1]=0x33;frame[2]=0;frame[3]=0;frame[4]=0;frame[5]=0xfb;
    memcpy(frame+6,own,6);frame[12]=0x86;frame[13]=0xdd;
    uint8_t *ipv6=frame+14;ipv6[0]=0x60;
    set16(ipv6+4,static_cast<uint16_t>(udpLength));ipv6[6]=17;ipv6[7]=255;
    ipv6[8]=kind==QueryKind::WrongSource?0x20:0xfe;
    ipv6[9]=kind==QueryKind::WrongSource?0x01:0x80;
    ipv6[16]=uint8_t(own[0]^2);ipv6[17]=own[1];ipv6[18]=own[2];
    ipv6[19]=0xff;ipv6[20]=0xfe;ipv6[21]=own[3];ipv6[22]=own[4];ipv6[23]=own[5];
    ipv6[24]=0xff;ipv6[25]=0x02;ipv6[39]=kind==QueryKind::WrongGroup?0xfc:0xfb;
    if(kind==QueryKind::WrongGroup||kind==QueryKind::WrongMapping)frame[5]=0xfc;
    uint8_t *udp=ipv6+40;
    set16(udp,kind==QueryKind::Legacy?5354:5353);
    set16(udp+2,kind==QueryKind::WrongPort?5354:5353);
    set16(udp+4,static_cast<uint16_t>(udpLength));
    memcpy(udp+8,dns,dnsLength);
    if(checksumPresent)set16(udp+6,test064Checksum(ipv6,udp,udpLength));
    mbuf_setlen(packet,total);mbuf_pkthdr_setlen(packet,total);return packet;
}
mbuf_t enqueue(QueryKind kind=QueryKind::Qm,bool checksumPresent=false,
               bool finalize=true) {
    test064FinalizeChecksum=finalize;
    mbuf_t packet=makeQuery(kind,checksumPresent);mbuf_t owned=packet;
    const int result=installed.iff_output(nullptr,filterIf,AF_INET6,&packet);
    if(result==EJUSTRETURN){assert(!packet);return owned;}
    assert(packet==owned);mbuf_freem(packet);return nullptr;
}
void finish(uint64_t token,mbuf_t encoded) {
    assert(token&&encoded&&(mbuf_flags(encoded)&MBUF_PKTHDR));
    mbuf_freem(encoded);submitted(token,0);completed(token,true);
}
uint16_t decodeSequence(mbuf_t encoded) {
    NativeAwdlData::DecodedFrame decoded{};
    assert(NativeAwdlData::decodeIpv6DataMpdu(encoded->bytes,encoded->total,
        &decoded)==NativeAwdlData::Status::Ok);
    assert(decoded.packetCount==1);return decoded.packets[0].awdlSequenceNumber;
}
DiscoveryTxSnapshot peek() {
    DiscoveryTxSnapshot value{};assert(peekDiscoveryTx(7,&value));return value;
}
void setup(FakeIf &dev) {
    memcpy(dev.lladdr,own,6);assert(attach(&dev,own));poll(true,7);
}

int main(int argc,char **argv) {
    assert(argc==2);const int which=atoi(argv[1]);FakeIf dev;setup(dev);
    if(which==1) {
        mbuf_t original=enqueue(QueryKind::Qm,false,true);assert(original);
        DiscoveryTxSnapshot saved=peek();assert(saved.token==1&&saved.eligible&&saved.generation==7&&saved.queryClass==3);
        uint64_t token=0;bool consumed=false;mbuf_t encoded=nextDiscoveryTx(42,saved,&token,&consumed);
        assert(encoded&&consumed&&token==saved.token&&decodeSequence(encoded)==0);
        assert(freed==1);finish(token,encoded);
        token=99;consumed=true;assert(!nextDiscoveryTx(43,saved,&token,&consumed));
        assert(token==0&&!consumed&&snapshot().value[TxPending]==0&&freed==2);
    } else if(which==2) {
        const QueryKind kinds[]={QueryKind::Qu,QueryKind::Legacy,QueryKind::Other,
            QueryKind::Unknown,QueryKind::UnknownService,QueryKind::Qr,
            QueryKind::Mixed,QueryKind::WrongGroup,
            QueryKind::NonIN,QueryKind::WrongMapping,QueryKind::WrongSource,
            QueryKind::WrongPort};
        uint16_t expectedSequence=0;
        for(QueryKind kind:kinds) {
            mbuf_t original=enqueue(kind,false,true);assert(original);
            DiscoveryTxSnapshot absent{0xfeed,1,7,3,1};
            DiscoveryTxSnapshot out{91,92,93,94,true};
            assert(!peekDiscoveryTx(7,&out)&&out.token==91);
            uint64_t token=99;bool consumed=true;
            assert(!nextDiscoveryTx(50,absent,&token,&consumed));
            assert(token==0&&!consumed&&snapshot().value[TxPending]==1);
            mbuf_t encoded=nextTx(50,&token);assert(encoded&&token);
            assert(decodeSequence(encoded)==expectedSequence++);finish(token,encoded);
        }
    } else if(which==3) {
        mbuf_t original=enqueue(QueryKind::Qm,false,false);assert(original);
        DiscoveryTxSnapshot out{1,2,3,4,true};
        assert(!peekDiscoveryTx(7,&out)&&out.token==1);
        DiscoveryTxSnapshot forged{1,1,7,3,1};uint64_t token=0;bool consumed=false;
        assert(!nextDiscoveryTx(9,forged,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==1);
        mbuf_t encoded=nextTx(9,&token);assert(encoded);finish(token,encoded);
    } else if(which==4) {
        mbuf_t original=enqueue(QueryKind::Qm,false,true);assert(original);
        DiscoveryTxSnapshot saved=peek();
        uint8_t *dns=original->bytes+14+40+8;
        set16(dns+12+21,1); // Change PTR to A after immutable enqueue metadata.
        test064ApplyChecksum(original);
        uint64_t token=0;bool consumed=false;
        assert(!nextDiscoveryTx(10,saved,&token,&consumed));
        assert(consumed&&token==0&&snapshot().value[TxPending]==0&&freed==1);
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot next=peek();
        mbuf_t encoded=nextDiscoveryTx(11,next,&token,&consumed);
        assert(encoded&&consumed&&decodeSequence(encoded)==0);finish(token,encoded);
    } else if(which==5) {
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot saved=peek();
        enqueue(QueryKind::Other,false,true);
        uint64_t token=0;mbuf_t ordinary=nextTx(3,&token);assert(ordinary);
        assert(decodeSequence(ordinary)==0);finish(token,ordinary);
        bool consumed=true;assert(!nextDiscoveryTx(4,saved,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==1);
        mbuf_t preserved=nextTx(4,&token);assert(preserved);
        assert(decodeSequence(preserved)==1);finish(token,preserved);
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot second=peek();
        assert(second.token!=saved.token);
        mbuf_t encoded=nextDiscoveryTx(5,second,&token,&consumed);
        assert(encoded&&consumed&&decodeSequence(encoded)==2);finish(token,encoded);
    } else if(which==6) {
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot saved=peek();
        DiscoveryTxSnapshot out{17,18,19,20,true};
        assert(!peekDiscoveryTx(8,&out)&&out.token==17);
        DiscoveryTxSnapshot wrongEpoch=saved;wrongEpoch.generation=8;
        uint64_t token=0;bool consumed=false;
        assert(!nextDiscoveryTx(1,wrongEpoch,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==1);
        publishClosing();assert(!peekDiscoveryTx(7,&out));
        assert(!nextDiscoveryTx(1,saved,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==1);
        assert(close()&&!dev.refs&&allocated==freed&&socketsOpen==socketsClosed);return 0;
    } else if(which==7) {
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot saved=peek();
        fakeTime+=2000001;DiscoveryTxSnapshot out{17,18,19,20,true};
        assert(!peekDiscoveryTx(7,&out)&&out.token==17);
        uint64_t token=0;bool consumed=false;
        assert(!nextDiscoveryTx(1,saved,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==1);
    } else if(which==8) {
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot saved=peek();
        uint64_t token=0;bool consumed=false;
        mbuf_t first=nextDiscoveryTx(1,saved,&token,&consumed);
        assert(first&&consumed);finish(token,first);
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot next=peek();
        mbuf_t inFlight=nextDiscoveryTx(2,next,&token,&consumed);assert(inFlight&&consumed);
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot out{71,72,73,74,true};
        assert(!peekDiscoveryTx(7,&out)&&out.token==71);
        assert(snapshot().value[TxPending]==1);finish(token,inFlight);
        DiscoveryTxSnapshot after=peek();assert(after.token!=next.token);
        mbuf_t final=nextDiscoveryTx(3,after,&token,&consumed);assert(final&&consumed);finish(token,final);
    } else if(which==10) {
        enqueue(QueryKind::Qm,false,true);DiscoveryTxSnapshot saved=peek();
        poll(false,7);uint64_t token=0;bool consumed=false;
        assert(!nextDiscoveryTx(8,saved,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==0);
    } else if(which==11) {
        enqueue(QueryKind::Other,false,true);
        enqueue(QueryKind::Qm,false,true);
        DiscoveryTxSnapshot out{};
        assert(peekDiscoveryTx(7,&out)&&out.token==2);
        uint64_t token=0;bool consumed=false;
        mbuf_t encoded=nextDiscoveryTx(2,out,&token,&consumed);
        assert(encoded&&consumed&&token==2&&decodeSequence(encoded)==0);
        finish(token,encoded);
        assert(snapshot().value[TxPending]==1);
        mbuf_t first=nextTx(3,&token);
        assert(first&&token==1&&decodeSequence(first)==1);
        finish(token,first);
        assert(snapshot().value[TxPending]==0);
    } else if(which==12) {
        mbuf_t oldPacket=enqueue(QueryKind::Qm,false,true);assert(oldPacket);
        test064PauseAfterUnlock.store(true,std::memory_order_release);
        std::thread transition([&]{poll(true,8);});
        while(!test064UnlockPaused.load(std::memory_order_acquire))
            std::this_thread::yield();
        mbuf_t newPacket=enqueue(QueryKind::Qm,false,true);assert(newPacket);
        DiscoveryTxSnapshot fresh{};assert(peekDiscoveryTx(8,&fresh));
        assert(fresh.generation==8&&snapshot().value[TxPending]==1);
        test064ResumeUnlock.store(true,std::memory_order_release);
        transition.join();
        assert(snapshot().value[TxPending]==1&&freed==1);
        uint64_t token=0;bool consumed=false;
        mbuf_t encoded=nextDiscoveryTx(12,fresh,&token,&consumed);
        assert(encoded&&consumed);finish(token,encoded);
    } else if(which==9) {
        // One producer exercises output/finalization while one consumer peeks
        // and transfers the exact head. The host shim checks ownership only.
        std::atomic<bool> done{false};
        std::thread producer([&]{
            for(unsigned i=0;i<200;++i) {
                mbuf_t packet=makeQuery(QueryKind::Qm,false);mbuf_t owned=packet;
                const int result=installed.iff_output(nullptr,filterIf,AF_INET6,&packet);
                if(result==EJUSTRETURN)assert(!packet);
                else {assert(packet==owned);mbuf_freem(packet);}
            }
            done.store(true,std::memory_order_release);
        });
        std::thread consumer([&]{
            unsigned idle=0;
            while(!done.load(std::memory_order_acquire)||idle<1000) {
                DiscoveryTxSnapshot value{};
                if(peekDiscoveryTx(7,&value)) {
                    uint64_t token=0;bool consumed=false;
                    mbuf_t encoded=nextDiscoveryTx(6,value,&token,&consumed);
                    if(encoded)finish(token,encoded);
                } else ++idle;
            }
        });
        producer.join();consumer.join();
    } else assert(false);
    assert(close());
    assert(!dev.refs&&allocated==freed&&socketsOpen==socketsClosed);
    return 0;
}
