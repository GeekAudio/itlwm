// SPDX-License-Identifier: GPL-2.0-only
// Host-only tests for bounded non-head strict-QM selection in the production
// BSD bridge. The shim proves queue/mbuf ownership only, not firmware or RF.
#include "test064_kernel_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_bsd_packet_bridge.hpp"
#include <atomic>
#include <assert.h>
#include <stdint.h>
#include <string.h>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},
    socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=1;
thread_local unsigned test064SimpleLockDepth=0;
std::atomic<bool> test064PauseAfterUnlock{false},test064UnlockPaused{false},
    test064ResumeUnlock{false};
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false,test064FinalizeChecksum=true;
iff_filter installed;
ifnet_t filterIf=nullptr;

using namespace NativeAwdlBSD;
const uint8_t ownAddress[6]={2,1,2,3,4,5};

enum class QueryKind : uint8_t {
    Airdrop, CompanionLink, Asquic, UnknownService, NonPtr, Qu,
    BadChecksum
};

void write16(uint8_t *bytes,uint16_t value) {
    bytes[0]=static_cast<uint8_t>(value>>8);
    bytes[1]=static_cast<uint8_t>(value);
}

size_t appendLabel(uint8_t *dns,size_t offset,const char *label,size_t length) {
    assert(length>0&&length<=63);
    dns[offset++]=static_cast<uint8_t>(length);
    memcpy(dns+offset,label,length);
    return offset+length;
}

mbuf_t makeQuery(QueryKind kind) {
    uint8_t dns[128]{};
    size_t dnsLength=12;
    write16(dns+4,1);
    const char *service="_airdrop";
    size_t serviceLength=8;
    const char *transport="_tcp";
    size_t transportLength=4;
    switch(kind) {
        case QueryKind::CompanionLink:
            service="_companion-link";serviceLength=15;break;
        case QueryKind::Asquic:
            service="_asquic";serviceLength=7;
            transport="_udp";transportLength=4;break;
        case QueryKind::UnknownService:
            service="_notaird";serviceLength=8;
            transport="_udp";transportLength=4;break;
        default:break;
    }
    dnsLength=appendLabel(dns,dnsLength,service,serviceLength);
    dnsLength=appendLabel(dns,dnsLength,transport,transportLength);
    dnsLength=appendLabel(dns,dnsLength,"local",5);
    dns[dnsLength++]=0;
    write16(dns+dnsLength,kind==QueryKind::NonPtr?1:12);
    dnsLength+=2;
    write16(dns+dnsLength,kind==QueryKind::Qu?0x8001:1);
    dnsLength+=2;

    const size_t udpLength=8+dnsLength;
    const size_t ipv6Length=40+udpLength;
    const size_t frameLength=14+ipv6Length;
    mbuf_t packet=nullptr;
    assert(mbuf_getpacket(MBUF_DONTWAIT,&packet)==0&&packet);
    uint8_t *frame=static_cast<uint8_t *>(mbuf_data(packet));
    memset(frame,0,frameLength);
    frame[0]=0x33;frame[1]=0x33;frame[2]=0;frame[3]=0;frame[4]=0;
    frame[5]=0xfb;
    memcpy(frame+6,ownAddress,6);
    frame[12]=0x86;frame[13]=0xdd;
    uint8_t *ipv6=frame+14;
    ipv6[0]=0x60;
    write16(ipv6+4,static_cast<uint16_t>(udpLength));
    ipv6[6]=17;ipv6[7]=255;
    ipv6[8]=0xfe;ipv6[9]=0x80;
    ipv6[16]=static_cast<uint8_t>(ownAddress[0]^2);
    ipv6[17]=ownAddress[1];ipv6[18]=ownAddress[2];
    ipv6[19]=0xff;ipv6[20]=0xfe;ipv6[21]=ownAddress[3];
    ipv6[22]=ownAddress[4];ipv6[23]=ownAddress[5];
    ipv6[24]=0xff;ipv6[25]=0x02;ipv6[39]=0xfb;
    uint8_t *udp=ipv6+40;
    write16(udp,5353);write16(udp+2,5353);
    write16(udp+4,static_cast<uint16_t>(udpLength));
    memcpy(udp+8,dns,dnsLength);
    mbuf_setlen(packet,frameLength);mbuf_pkthdr_setlen(packet,frameLength);
    return packet;
}

mbuf_t enqueue(QueryKind kind,bool finalize=true) {
    test064FinalizeChecksum=finalize;
    mbuf_t packet=makeQuery(kind);mbuf_t owned=packet;
    const int result=installed.iff_output(nullptr,filterIf,AF_INET6,&packet);
    if(result==EJUSTRETURN) {
        assert(!packet);
        return owned;
    }
    assert(packet==owned);
    mbuf_freem(packet);
    return nullptr;
}

void finish(uint64_t token,mbuf_t encoded) {
    assert(token&&encoded&&(mbuf_flags(encoded)&MBUF_PKTHDR));
    mbuf_freem(encoded);submitted(token,0);completed(token,true);
}

uint16_t decodedAwdlSequence(mbuf_t encoded) {
    NativeAwdlData::DecodedFrame decoded{};
    assert(NativeAwdlData::decodeIpv6DataMpdu(encoded->bytes,encoded->total,
        &decoded)==NativeAwdlData::Status::Ok);
    assert(decoded.packetCount==1);
    return decoded.packets[0].awdlSequenceNumber;
}

void setup(FakeIf &device) {
    memcpy(device.lladdr,ownAddress,6);
    assert(attach(&device,ownAddress));
    poll(true,7);
}

DiscoveryTxSnapshot peek() {
    DiscoveryTxSnapshot result{};
    assert(peekDiscoveryTx(7,&result));
    return result;
}

void ordinaryTx(uint16_t wifiSequence,uint64_t expectedAwdlSequence) {
    uint64_t token=0;
    mbuf_t encoded=nextTx(wifiSequence,&token);
    assert(encoded&&decodedAwdlSequence(encoded)==expectedAwdlSequence);
    finish(token,encoded);
}

void discoveryTx(const DiscoveryTxSnapshot &expected,
                 uint16_t wifiSequence,uint64_t expectedAwdlSequence) {
    uint64_t token=0;bool consumed=false;
    mbuf_t encoded=nextDiscoveryTx(wifiSequence,expected,&token,&consumed);
    assert(encoded&&consumed&&token==expected.token&&
           decodedAwdlSequence(encoded)==expectedAwdlSequence);
    finish(token,encoded);
}

void assertNoConsume(const DiscoveryTxSnapshot &snapshot) {
    uint64_t token=77;bool consumed=true;
    assert(!nextDiscoveryTx(99,snapshot,&token,&consumed));
    assert(token==0&&!consumed);
}

void assertClosedAndBalanced(FakeIf &device) {
    assert(close());
    assert(!device.refs);
    assert(allocated==freed);
    assert(socketsOpen==socketsClosed);
}

int main(int argc,char **argv) {
    assert(argc==2);
    const int test=atoi(argv[1]);
    FakeIf device;
    setup(device);

    if(test==1) {
        // All three supported continuity service PTRs are eligible, while
        // unsupported, non-PTR, and QU packets before/between them stay queued.
        assert(enqueue(QueryKind::UnknownService));  // token 1
        assert(enqueue(QueryKind::Airdrop));         // token 2
        assert(enqueue(QueryKind::NonPtr));          // token 3
        assert(enqueue(QueryKind::CompanionLink));   // token 4
        assert(enqueue(QueryKind::Qu));              // token 5
        assert(enqueue(QueryKind::Asquic));           // token 6
        assert(snapshot().value[TxPending]==6);

        DiscoveryTxSnapshot first=peek();
        assert(first.token==2);
        discoveryTx(first,10,0);
        assert(snapshot().value[TxPending]==5);
        DiscoveryTxSnapshot second=peek();
        assert(second.token==4);
        discoveryTx(second,11,1);
        assert(snapshot().value[TxPending]==4);
        DiscoveryTxSnapshot third=peek();
        assert(third.token==6);
        discoveryTx(third,12,2);
        assert(snapshot().value[TxPending]==3);

        // Ordinary dequeue now sees the skipped records in their original
        // order: unsupported service, non-PTR, QU.
        ordinaryTx(13,3);
        ordinaryTx(14,4);
        ordinaryTx(15,5);
        assert(snapshot().value[TxPending]==0);
    } else if(test==2) {
        // Move both ring cursors to the end, then make candidates wrap to 0.
        for(unsigned index=0;index<QueueDepth-2;++index) {
            assert(enqueue(QueryKind::UnknownService));
            ordinaryTx(static_cast<uint16_t>(index),index);
        }
        assert(enqueue(QueryKind::UnknownService)); // wrapped slot 30
        assert(enqueue(QueryKind::Asquic));          // slot 31, first candidate
        assert(enqueue(QueryKind::NonPtr));          // slot 0
        assert(enqueue(QueryKind::CompanionLink));   // slot 1, second candidate
        assert(enqueue(QueryKind::UnknownService));  // slot 2
        assert(snapshot().value[TxPending]==5);

        DiscoveryTxSnapshot first=peek();
        assert(first.token==QueueDepth);
        discoveryTx(first,40,QueueDepth-2);
        DiscoveryTxSnapshot second=peek();
        assert(second.token==QueueDepth+2);
        discoveryTx(second,41,QueueDepth-1);
        ordinaryTx(42,QueueDepth);
        ordinaryTx(43,QueueDepth+1);
        ordinaryTx(44,QueueDepth+2);
        assert(snapshot().value[TxPending]==0);
    } else if(test==3) {
        // Invalid and expired earlier entries are skipped without being
        // discarded; the fresh strict QM behind them is selected.
        assert(enqueue(QueryKind::UnknownService)); // token 1
        assert(enqueue(QueryKind::Airdrop));        // token 2, then stale
        fakeTime+=2000001;
        assert(enqueue(QueryKind::BadChecksum,false)); // token 3
        assert(enqueue(QueryKind::CompanionLink));     // token 4, fresh
        DiscoveryTxSnapshot fresh=peek();
        assert(fresh.token==4&&snapshot().value[TxPending]==4);
        discoveryTx(fresh,50,0);
        assert(snapshot().value[TxPending]==3);
        assertClosedAndBalanced(device); // pending invalid/stale packets freed once
        return 0;
    } else if(test==4) {
        mbuf_t unsupported=enqueue(QueryKind::UnknownService); // token 1
        mbuf_t staleCandidate=enqueue(QueryKind::Airdrop);     // token 2
        assert(unsupported&&staleCandidate);
        assert(enqueue(QueryKind::NonPtr));                    // token 3
        mbuf_t laterCandidate=enqueue(QueryKind::Asquic);      // token 4
        assert(laterCandidate);
        DiscoveryTxSnapshot selected=peek();
        assert(selected.token==2);

        // Use a token that cannot denote any queued entry. Merely changing
        // token to 4 would form a valid snapshot for the second candidate
        // because both were enqueued at the same fake timestamp.
        DiscoveryTxSnapshot wrongToken=selected;wrongToken.token=99;
        assertNoConsume(wrongToken);
        DiscoveryTxSnapshot wrongBorn=selected;++wrongBorn.bornUs;
        assertNoConsume(wrongBorn);
        DiscoveryTxSnapshot wrongGeneration=selected;++wrongGeneration.generation;
        assertNoConsume(wrongGeneration);
        DiscoveryTxSnapshot wrongClass=selected;++wrongClass.queryClass;
        assertNoConsume(wrongClass);
        DiscoveryTxSnapshot ineligible=selected;ineligible.eligible=false;
        assertNoConsume(ineligible);
        assert(snapshot().value[TxPending]==4);

        // Bytes are mutated after the successful peek. The exact selected
        // mbuf is consumed/freed after double-check, but cannot encode or
        // advance AWDL sequence; later strict QM remains selectable.
        uint8_t *dns=staleCandidate->bytes+14+40+8;
        const size_t nameOffset=12;
        const uint8_t unknownName[]={8,'_','n','o','t','a','i','r','d',
            4,'_','u','d','p',5,'l','o','c','a','l',0};
        memcpy(dns+nameOffset,unknownName,sizeof(unknownName));
        test064ApplyChecksum(staleCandidate);
        uint64_t token=99;bool consumed=false;
        assert(!nextDiscoveryTx(51,selected,&token,&consumed));
        assert(consumed&&token==0&&snapshot().value[TxPending]==3);
        DiscoveryTxSnapshot next=peek();
        assert(next.token==4);
        discoveryTx(next,52,0);
        ordinaryTx(53,1);
        ordinaryTx(54,2);
        assert(snapshot().value[TxPending]==0);
    } else if(test==5) {
        assert(enqueue(QueryKind::UnknownService));
        assert(enqueue(QueryKind::Airdrop));
        DiscoveryTxSnapshot selected=peek();
        assert(selected.token==2);
        DiscoveryTxSnapshot untouched{71,72,73,74,true};
        assert(!peekDiscoveryTx(8,&untouched)&&untouched.token==71);
        DiscoveryTxSnapshot wrongGeneration=selected;
        wrongGeneration.generation=8;
        assertNoConsume(wrongGeneration);
        assert(snapshot().value[TxPending]==2);

        // The single in-flight slot remains authoritative even with a queued
        // strict QM behind the ordinary FIFO head.
        uint64_t token=0;
        mbuf_t ordinary=nextTx(60,&token);
        assert(ordinary&&decodedAwdlSequence(ordinary)==0);
        DiscoveryTxSnapshot out{81,82,83,84,true};
        assert(!peekDiscoveryTx(7,&out)&&out.token==81);
        bool consumed=true;
        assert(!nextDiscoveryTx(61,selected,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==1);
        finish(1,ordinary);
        DiscoveryTxSnapshot after=peek();
        assert(after.token==2);
        discoveryTx(after,62,1);
        assert(snapshot().value[TxPending]==0);
    } else if(test==6) {
        assert(enqueue(QueryKind::UnknownService));
        assert(enqueue(QueryKind::CompanionLink));
        DiscoveryTxSnapshot selected=peek();
        assert(selected.token==2);
        publishClosing();
        DiscoveryTxSnapshot out{91,92,93,94,true};
        assert(!peekDiscoveryTx(7,&out)&&out.token==91);
        assertNoConsume(selected);
        assert(snapshot().value[TxPending]==2);
        assertClosedAndBalanced(device);
        return 0;
    } else if(test==7) {
        // A generation transition retires only the old epoch; a fresh entry
        // in the new epoch can be selected, and an old snapshot cannot claim it.
        assert(enqueue(QueryKind::UnknownService));
        assert(enqueue(QueryKind::Airdrop));
        DiscoveryTxSnapshot stale=peek();
        poll(true,8);
        assert(snapshot().value[TxPending]==0);
        assert(enqueue(QueryKind::UnknownService));
        assert(enqueue(QueryKind::Asquic));
        DiscoveryTxSnapshot fresh{};
        assert(peekDiscoveryTx(8,&fresh)&&fresh.generation==8&&fresh.token==4);
        assertNoConsume(stale);
        uint64_t token=0;bool consumed=false;
        assert(!nextDiscoveryTx(70,stale,&token,&consumed));
        assert(!consumed&&snapshot().value[TxPending]==2);
        mbuf_t encoded=nextDiscoveryTx(71,fresh,&token,&consumed);
        assert(encoded&&consumed&&token==fresh.token&&
               decodedAwdlSequence(encoded)==0);
        finish(token,encoded);
        ordinaryTx(72,1);
        assertClosedAndBalanced(device);
        return 0;
    } else {
        assert(false&&"unknown Test079 native discovery queue case");
    }

    assertClosedAndBalanced(device);
    return 0;
}
