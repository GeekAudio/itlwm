// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_bsd_packet_bridge.hpp"
std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},socketsOpen{0},socketsClosed{0};uint64_t fakeTime=1;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false;
iff_filter installed;ifnet_t filterIf=nullptr;
using namespace NativeAwdlBSD;
const uint8_t own[6]={2,1,2,3,4,5},peer[6]={2,6,7,8,9,10};
mbuf_t packet(){
    mbuf_t m;assert(!mbuf_getpacket(MBUF_DONTWAIT,&m));
    memcpy(m->bytes,peer,6);memcpy(m->bytes+6,own,6);
    m->bytes[12]=0x86;m->bytes[13]=0xdd;m->bytes[14]=0x60;
    mbuf_setlen(m,54);mbuf_pkthdr_setlen(m,54);return m;
}
void accept(){
    mbuf_t m=packet();assert(installed.iff_output(nullptr,filterIf,AF_INET6,&m)==EJUSTRETURN&&!m);
}
void incoming(uint32_t generation,bool protect=false){
    uint8_t ipv6[40]{};ipv6[0]=0x60;NativeAwdlData::EncodeInput in{};
    memcpy(in.sourceAddress,peer,6);memcpy(in.destinationAddress,own,6);
    in.ipv6Packet=ipv6;in.ipv6Length=40;
    uint8_t raw[200];size_t n=0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(&in,raw,sizeof(raw),&n)==NativeAwdlData::Status::Ok);
    capture(raw,n,protect,true,generation);
}
int main(int argc,char **argv){
    assert(argc==2);int which=atoi(argv[1]);FakeIf dev;memcpy(dev.lladdr,own,6);
    if(which==22){dev.lladdr[5]^=1;assert(!attach(&dev,own));assert(!dev.refs);return 0;}
    if(which==12){offloadFail=true;assert(!attach(&dev,own));assert(close()&&!dev.refs);return 0;}
    if(which==13||which==14){ipv6Fail=which==13;socketFail=which==14;assert(!attach(&dev,own));assert(close()&&!dev.refs);assert(socketsOpen==socketsClosed);return 0;}
    assert(attach(&dev,own));poll(true,7);
    assert(snapshot().value[Ipv6Configured]==1&&snapshot().value[Ipv6ConfigResult]==0);
    if(which==18){uint8_t address[6]{};assert(NativeAwdlBSD::address(7,address));assert(!memcmp(address,own,6));}
    if(which==19){uint8_t address[6];memset(address,0xa5,sizeof(address));assert(!NativeAwdlBSD::address(8,address));for(auto b:address)assert(b==0xa5);}
    if(which==20){uint8_t address[6];memset(address,0xa5,sizeof(address));dev.lladdr[5]^=1;assert(!NativeAwdlBSD::address(7,address));for(auto b:address)assert(b==0xa5);dev.lladdr[5]^=1;}
    if(which==21){uint8_t address[6];memset(address,0xa5,sizeof(address));lladdrFail=true;assert(!NativeAwdlBSD::address(7,address));lladdrFail=false;for(auto b:address)assert(b==0xa5);}
    if(which==23){uint8_t address[6];memset(address,0xa5,sizeof(address));NativeAwdlBSD::publishClosing();assert(!NativeAwdlBSD::address(7,address));for(auto b:address)assert(b==0xa5);poll(true,7);assert(!NativeAwdlBSD::address(7,address));}
    if(which==1){
        accept();uint64_t token=0;auto raw=nextTx(17,&token);assert(raw&&token&&(mbuf_flags(raw)&MBUF_PKTHDR));
        NativeAwdlData::DecodedFrame d{};
        assert(NativeAwdlData::decodeIpv6DataMpdu(raw->bytes,raw->total,&d)==NativeAwdlData::Status::Ok);
        assert(d.wifiSequenceNumber==17&&!memcmp(d.sourceAddress,own,6));
        mbuf_freem(raw);submitted(token,0);completed(token,true);
        assert(snapshot().value[TxSubmitted]==1&&snapshot().value[TxSucceeded]==1&&finalized==1);
    }
    if(which==2){auto m=packet();m->bytes[6]^=2;assert(installed.iff_output(nullptr,&dev,AF_INET6,&m)!=EJUSTRETURN&&m);mbuf_freem(m);assert(snapshot().value[TxAccepted]==0&&finalized==0);}
    if(which==3){for(unsigned i=0;i<QueueDepth;++i)accept();auto m=packet();assert(installed.iff_output(nullptr,&dev,AF_INET6,&m)==ENOBUFS&&m);mbuf_freem(m);assert(snapshot().value[TxPending]==QueueDepth);}
    if(which==4){accept();fakeTime+=3000000;uint64_t token=0;assert(!nextTx(0,&token));assert(snapshot().value[TxExpired]==1&&snapshot().value[TxSubmitted]==0);}
    if(which==5){accept();incoming(7);poll(true,8);assert(snapshot().value[TxPending]==0&&delivered==0);incoming(8);poll(true,8);assert(delivered==1);}
    if(which==6){accept();uint64_t token=0;auto raw=nextTx(0,&token);assert(raw);mbuf_freem(raw);submitted(token,0);assert(!close()&&dev.refs==1);completed(token+1,true);assert(!close()&&dev.refs==1);completed(token,false);assert(close()&&dev.refs==0);}
    if(which==7){incoming(7,true);poll(true,7);assert(!delivered&&snapshot().value[RxRejected]==1);incoming(7);poll(true,7);assert(delivered==1&&snapshot().value[RxCaptured]==1);}
    if(which==8){incoming(7);allocateFail=true;poll(true,7);allocateFail=false;incoming(7);inputFail=true;poll(true,7);assert(!delivered&&snapshot().value[RxInputFailed]==2);}
    if(which==9){detachDelay=true;assert(!close()&&dev.refs==1);detachDelay=false;assert(close()&&dev.refs==0);}
    if(which==10){accept();fakeTime+=3000000;poll(true,7);assert(snapshot().value[TxPending]==0&&snapshot().value[TxExpired]==1);}
    if(which==11){accept();poll(false,7);assert(snapshot().value[TxPending]==0);auto m=packet();assert(installed.iff_output(nullptr,&dev,AF_INET6,&m)!=EJUSTRETURN&&m);mbuf_freem(m);}
    if(which==15){auto m=packet();m->flags=0;assert(installed.iff_output(nullptr,&dev,AF_INET6,&m)==EINVAL&&m);mbuf_freem(m);assert(snapshot().value[TxAccepted]==0&&finalized==0);}
    if(which==16){incoming(7);packetHeaderMissing=true;poll(true,7);assert(!delivered&&snapshot().value[RxInputFailed]==1);}
    if(which==17){accept();packetHeaderMissing=true;uint64_t token=0;assert(!nextTx(0,&token));assert(snapshot().value[TxSubmitted]==0&&snapshot().value[TxFailed]==1);}
    assert(close());assert(!dev.refs);assert(allocated==freed&&socketsOpen==socketsClosed);return 0;
}
