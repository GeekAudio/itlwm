// SPDX-License-Identifier: GPL-2.0-only
// Actual BSD Ethernet/IPv6 -> Intel MPDU and Intel MPDU -> native awdl0 bridge.
// A packet is never looped back or counted as radio receipt by this module.
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "awdl_native_bsd_data_25G332.hpp"
#include "awdl_bsd_packet_bridge.hpp"
#include "awdl_data_tx_observation.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <kern/clock.h>
#include <net/kpi_interfacefilter.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>

namespace NativeAwdlBSD {
namespace {
struct Tx {
    mbuf_t packet=nullptr;
    uint64_t token=0,born=0;
    uint32_t generation=0;
    bool discoveryEligible=false;
    uint8_t discoveryClass=0;
};
struct Rx {uint16_t length=0;uint32_t generation=0;uint8_t bytes[2048]{};};
IOSimpleLock *lock;
uint32_t attachClaimed=0;
AttachTraceLedger attachTrace;
Ring<Tx,QueueDepth> tx;
Ring<Rx,QueueDepth> rx;
ifnet_t interface;
interface_filter_t filter;
uint8_t own[6];
uint64_t counters[Count]{},nextToken=0,inFlightToken=0;
NativeAwdlData::MdnsQueryClass inFlightMdnsClass=NativeAwdlData::MdnsQueryClass::Unknown;
uint32_t inputCalls=0;
uint32_t radioGeneration=0;
uint16_t dataSequence=0;
bool closing=false,detached=false,radio=false;
uint32_t closingRequested=0;
IOSimpleLock *bridgeLock() {
    return __atomic_load_n(&lock,__ATOMIC_ACQUIRE);
}
Counter mdnsAttemptCounter(NativeAwdlData::MdnsQueryClass value) {
    static const Counter countersByClass[]={TxMdnsUnknownAttempts,TxMdnsLegacyAttempts,
        TxMdnsQuAttempts,TxMdnsQmAttempts,TxMdnsOtherAttempts};
    const unsigned index=static_cast<unsigned>(value);
    return index<sizeof(countersByClass)/sizeof(countersByClass[0])
        ?countersByClass[index]:TxMdnsUnknownAttempts;
}
Counter mdnsSubmittedCounter(NativeAwdlData::MdnsQueryClass value) {
    static const Counter countersByClass[]={TxMdnsUnknownSubmitted,TxMdnsLegacySubmitted,
        TxMdnsQuSubmitted,TxMdnsQmSubmitted,TxMdnsOtherSubmitted};
    const unsigned index=static_cast<unsigned>(value);
    return index<sizeof(countersByClass)/sizeof(countersByClass[0])
        ?countersByClass[index]:TxMdnsUnknownSubmitted;
}
Counter mdnsCompletedCounter(NativeAwdlData::MdnsQueryClass value) {
    static const Counter countersByClass[]={TxMdnsUnknownCompleted,TxMdnsLegacyCompleted,
        TxMdnsQuCompleted,TxMdnsQmCompleted,TxMdnsOtherCompleted};
    const unsigned index=static_cast<unsigned>(value);
    return index<sizeof(countersByClass)/sizeof(countersByClass[0])
        ?countersByClass[index]:TxMdnsUnknownCompleted;
}
Counter mdnsSucceededCounter(NativeAwdlData::MdnsQueryClass value) {
    static const Counter countersByClass[]={TxMdnsUnknownSucceeded,TxMdnsLegacySucceeded,
        TxMdnsQuSucceeded,TxMdnsQmSucceeded,TxMdnsOtherSucceeded};
    const unsigned index=static_cast<unsigned>(value);
    return index<sizeof(countersByClass)/sizeof(countersByClass[0])
        ?countersByClass[index]:TxMdnsUnknownSucceeded;
}
uint64_t nowUs(){uint64_t t=0,n=0;clock_get_uptime(&t);absolutetime_to_nanoseconds(t,&n);return n/1000;}
bool discoveryAgeCurrent(uint64_t born,uint64_t now) {
    return now>=born&&now-born<=2000000;
}
bool isStrictAirdropQm(const NativeAwdlData::TxObservation &observation) {
    const auto &mdns=observation.mdnsQuery;
    return observation.ipv6PacketWellFormed&&
        observation.ipv6NextHeader==17&&
        observation.udpChecksumStatus==NativeAwdlData::UdpChecksumStatus::Valid&&
        observation.sourceIsLinkLocal&&observation.sourceEui64MatchesOwn&&
        observation.ipv6DestinationIsAirdropMdnsGroup&&
        observation.ethernetMulticastMappingMatches&&
        mdns.queryClass==NativeAwdlData::MdnsQueryClass::QmMulticast&&
        mdns.sourcePortIs5353&&mdns.destinationPortIs5353&&
        mdns.destinationIsFf02Fb&&mdns.headerParsed&&!mdns.qr&&
        mdns.questionCount>0&&
        mdns.targetPtrInQuestionCount==mdns.questionCount&&
        mdns.quQuestionMask==0;
}
bool strictAirdropQmBytes(const uint8_t *bytes,size_t length,
                          const uint8_t ownAddress[6],
                          EthernetView *viewOut,
                          NativeAwdlData::MdnsQueryClass *classOut) {
    EthernetView view{};
    if(!ethernetIpv6(bytes,length,ownAddress,&view))return false;
    const auto observation=NativeAwdlData::observeAwdlTxPacket(
        bytes,length,ownAddress);
    if(classOut)*classOut=observation.mdnsQuery.queryClass;
    if(viewOut)*viewOut=view;
    return isStrictAirdropQm(observation);
}
bool snapshotMatches(const Tx &head,const DiscoveryTxSnapshot &expected) {
    return expected.eligible&&head.discoveryEligible&&
        expected.token==head.token&&expected.bornUs==head.born&&
        expected.generation==head.generation&&
        expected.queryClass==head.discoveryClass&&
        head.discoveryClass==static_cast<uint8_t>(
            NativeAwdlData::MdnsQueryClass::QmMulticast);
}
void add(Counter c){__atomic_fetch_add(&counters[c],uint64_t(1),__ATOMIC_RELAXED);}
void set(Counter c,uint64_t n){__atomic_store_n(&counters[c],n,__ATOMIC_RELEASE);}
mbuf_t packetWithHeader() {
    mbuf_t packet=nullptr;
    // mbuf_getcluster(NULL) uses m_get, which does not create M_PKTHDR.
    // Both DLIL input and our raw TX metadata require a real packet header.
    if(mbuf_getpacket(MBUF_DONTWAIT,&packet))return nullptr;
    if(!packet)return nullptr;
    if(!(mbuf_flags(packet)&MBUF_PKTHDR)){mbuf_freem(packet);return nullptr;}
    return packet;
}
bool hasLinkLocal(ifnet_t dev) {
    ifaddr_t *addresses=nullptr;bool found=false;
    if(ifnet_get_address_list_family(dev,&addresses,AF_INET6)==0&&addresses) {
        for(unsigned i=0;addresses[i];++i) {
            sockaddr_in6 value{};
            if(ifaddr_address(addresses[i],reinterpret_cast<sockaddr *>(&value),sizeof(value))==0&&
               value.sin6_family==AF_INET6&&value.sin6_addr.s6_addr[0]==0xfe&&
               (value.sin6_addr.s6_addr[1]&0xc0)==0x80)found=true;
        }
        ifnet_free_address_list(addresses);
    }
    return found;
}
int configureLinkLocal(ifnet_t dev,const uint8_t mac[6]) {
    if(hasLinkLocal(dev))return 0;
    in6_aliasreq request{};memcpy(request.ifra_name,"awdl0",6);
    auto &address=request.ifra_addr;address.sin6_len=sizeof(address);address.sin6_family=AF_INET6;
    address.sin6_scope_id=ifnet_index(dev);
    auto bytes=address.sin6_addr.s6_addr;bytes[0]=0xfe;bytes[1]=0x80;
    bytes[8]=mac[0]^2;bytes[9]=mac[1];bytes[10]=mac[2];bytes[11]=0xff;bytes[12]=0xfe;
    bytes[13]=mac[3];bytes[14]=mac[4];bytes[15]=mac[5];
    request.ifra_prefixmask.sin6_len=sizeof(sockaddr_in6);request.ifra_prefixmask.sin6_family=AF_INET6;
    memset(request.ifra_prefixmask.sin6_addr.s6_addr,0xff,8);
    request.ifra_lifetime.ia6t_vltime=UINT32_MAX;request.ifra_lifetime.ia6t_pltime=UINT32_MAX;
    socket_t socket=nullptr;
    int result=sock_socket(AF_INET6,SOCK_DGRAM,0,nullptr,nullptr,&socket);
    if(result==0){result=sock_ioctl(socket,SIOCAIFADDR_IN6,&request);sock_close(socket);}
    return result==0&&!hasLinkLocal(dev)?EADDRNOTAVAIL:result;
}
errno_t output(void *,ifnet_t dev,protocol_family_t family,mbuf_t *packet) {
    if(!bridgeLock()||!packet||!*packet)return EINVAL;
    if(!(mbuf_flags(*packet)&MBUF_PKTHDR)){add(TxRejected);return EINVAL;}
    // AF_INET6 only. Reject other traffic on this AWDL role, never send it to STA.
    if(family!=AF_INET6){add(TxRejected);return EAFNOSUPPORT;}
    const size_t length=mbuf_pkthdr_len(*packet);
    if(length<54||length>MaxEthernet){add(TxRejected);return EMSGSIZE;}
    uint8_t bytes[MaxEthernet];
    if(mbuf_copydata(*packet,0,length,bytes)){add(TxRejected);return EINVAL;}
    EthernetView view{};
    // Validate the framed family before asking the KPI to parse its headers.
    // own is immutable for this resident owner; finalization stays outside
    // the queue's spin lock because the KPI may do packet work.
    if(!ethernetIpv6(bytes,length,own,&view)){add(TxRejected);return EINVAL;}
    mbuf_outbound_finalize(*packet,AF_INET6,14);
    // Finalization can materialize deferred checksums. Classify only a fresh,
    // bounded copy of the packet after that operation; never retain bytes.
    uint8_t finalizedBytes[MaxEthernet];
    EthernetView finalizedView{};
    NativeAwdlData::MdnsQueryClass discoveryClass=
        NativeAwdlData::MdnsQueryClass::Unknown;
    bool discoveryEligible=false;
    const size_t finalizedLength=mbuf_pkthdr_len(*packet);
    if(finalizedLength==length&&finalizedLength<=sizeof(finalizedBytes)&&
       mbuf_copydata(*packet,0,finalizedLength,finalizedBytes)==0)
        discoveryEligible=strictAirdropQmBytes(finalizedBytes,finalizedLength,
            own,&finalizedView,&discoveryClass);
    const uint64_t born=nowUs();
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool valid=interface==dev&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0;
    Tx entry{*packet,++nextToken,born,radioGeneration,
        discoveryEligible,
        static_cast<uint8_t>(discoveryClass)};
    const bool accepted=valid&&tx.push(entry);
    if(accepted){*packet=nullptr;set(TxPending,tx.count);}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!accepted){add(TxRejected);return ENOBUFS;}
    add(TxAccepted);return EJUSTRETURN; // filter now owns the consumed mbuf
}
void detachedCallback(void *,ifnet_t) {
    auto stateLock=bridgeLock();if(!stateLock)return;
    auto irq=IOSimpleLockLockDisableInterrupt(stateLock);
    detached=true;filter=nullptr;set(Detached,1);
    IOSimpleLockUnlockEnableInterrupt(stateLock,irq);
}
}
bool attach(ifnet_t dev,const uint8_t mac[6]) {
    attachTrace.beginAttempt();
    if(!dev) {
        attachTrace.failInputGuard(AttachInputGuardNullIfnet);
        return false;
    }
    if(!mac) {
        attachTrace.failInputGuard(AttachInputGuardNullAddress);
        return false;
    }
    if(bridgeLock()) {
        attachTrace.failInputGuard(AttachInputGuardExistingBridge);
        return false;
    }
    if(__atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)) {
        attachTrace.failInputGuard(AttachInputGuardClosingRequested);
        return false;
    } // one resident owner per boot
    attachTrace.markBridgeEntered();
    uint8_t liveAddress[6]{};
    const int liveAddressResult=ifnet_lladdr_copy_bytes(
        dev,liveAddress,sizeof(liveAddress));
    attachTrace.recordLiveAddressRead(liveAddressResult);
    if(liveAddressResult) {
        attachTrace.finishFailure();
        return false;
    }
    const bool liveAddressMatches=memcmp(liveAddress,mac,sizeof(liveAddress))==0;
    attachTrace.recordLiveAddressMatch(liveAddressMatches);
    if(!liveAddressMatches) {
        attachTrace.finishFailure();
        return false;
    }
    uint32_t unclaimed=0;
    const bool claimed=__atomic_compare_exchange_n(&attachClaimed,&unclaimed,1u,false,
        __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    attachTrace.recordClaim(true,claimed);
    if(!claimed) {
        attachTrace.finishFailure();
        return false;
    }
    IOSimpleLock *allocatedLock=IOSimpleLockAlloc();
    attachTrace.recordLockAllocation(allocatedLock!=nullptr);
    if(!allocatedLock) {
        attachTrace.finishFailure();
        return false;
    }
    __atomic_store_n(&lock,allocatedLock,__ATOMIC_RELEASE);
    memcpy(own,mac,6);
    const int referenceResult=ifnet_reference(dev);
    attachTrace.recordIfnetReference(referenceResult);
    if(referenceResult) {
        attachTrace.finishFailure();
        return false;
    }
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool canAttach=!interface&&!closing&&
        !__atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE);
    if(canAttach)interface=dev;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    attachTrace.recordCanAttach(canAttach);
    if(!canAttach){ifnet_release(dev);attachTrace.finishFailure();return false;}
    iff_filter spec{};spec.iff_name="IntelNativeAWDLData";
    spec.iff_protocol=0;spec.iff_output=output;spec.iff_detached=detachedCallback;
    const int result=iflt_attach(dev,&spec,&filter);
    attachTrace.recordFilterAttach(result);
    if(result){
        irq=IOSimpleLockLockDisableInterrupt(lock);
        if(interface==dev)interface=nullptr;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        ifnet_release(dev);attachTrace.finishFailure();return false;
    }
    // Software checksums only: the raw AWDL transport cannot service the
    // native network interface's checksum/segmentation offload requests.
    const int offloadResult=ifnet_set_offload(dev,0);
    attachTrace.recordSetOffload(offloadResult);
    if(offloadResult){attachTrace.finishFailure();return false;}
    const int mtuResult=ifnet_set_mtu(dev,1500);
    attachTrace.recordSetMtu(mtuResult);
    if(mtuResult){attachTrace.finishFailure();return false;}
    const int flagsResult=ifnet_set_flags(dev,IFF_UP|IFF_RUNNING,
                                          IFF_UP|IFF_RUNNING);
    attachTrace.recordSetFlags(flagsResult);
    if(flagsResult){attachTrace.finishFailure();return false;}
    const uint32_t unsafe=IFCAP_HWCSUM|IFCAP_TSO|IFCAP_CSUM_PARTIAL|IFCAP_CSUM_ZERO_INVERT;
    ifnet_set_capabilities_enabled(dev,0,unsafe);
    ifnet_set_capabilities_supported(dev,0,unsafe);
    set(OffloadCapabilities,ifnet_capabilities_enabled(dev));
    const int ipv6=configureLinkLocal(dev,mac);
    attachTrace.recordIPv6Result(ipv6);
    set(Ipv6ConfigResult,uint32_t(ipv6));
    const bool hasIpv6LinkLocal=hasLinkLocal(dev);
    attachTrace.recordIPv6LinkLocal(hasIpv6LinkLocal);
    set(Ipv6Configured,hasIpv6LinkLocal?1:0);
    if(ipv6){attachTrace.finishFailure();return false;}
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool ready=interface==dev&&!closing&&!detached&&
        !__atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE);
    if(ready)set(Attached,1);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    attachTrace.finish(ready);
    return ready;
}
bool address(uint32_t expectedPowerGeneration,uint8_t out[6]) {
    if(!out||!bridgeLock()||!expectedPowerGeneration)return false;
    ifnet_t dev=nullptr;uint8_t expected[6]{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool ready=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==expectedPowerGeneration&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0;
    if(ready){dev=interface;memcpy(expected,own,sizeof(expected));++inputCalls;}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!ready)return false;

    uint8_t actual[6]{};
    const bool addressRead=ifnet_lladdr_copy_bytes(dev,actual,sizeof(actual))==0;
    const bool addressMatches=addressRead&&memcmp(actual,expected,sizeof(actual))==0;
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool stillCurrent=interface==dev&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==expectedPowerGeneration&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        memcmp(own,expected,sizeof(own))==0;
    if(inputCalls)--inputCalls;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!addressMatches||!stillCurrent)return false;
    memcpy(out,actual,sizeof(actual));return true;
}
void cancelQueued() {
    if(!bridgeLock())return;
    Tx item{};
    for(;;){auto irq=IOSimpleLockLockDisableInterrupt(lock);const bool have=tx.pop(&item);set(TxPending,tx.count);IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(!have)break;mbuf_freem(item.packet);add(TxExpired);}
}
void poll(bool ready,uint32_t generation) {
    if(!bridgeLock())return;
    // Retire the old generation's queued mbufs before publishing the new
    // generation. Freeing remains outside IOSimpleLock; a later output call
    // can enqueue new-generation packets without a post-unlock flush racing it.
    Ring<Tx,QueueDepth> retiredTx{};
    bool discardQueued=false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool changed=radioGeneration&&radioGeneration!=generation;
    discardQueued=!ready||changed;
    if(discardQueued) {
        Tx item{};
        while(tx.pop(&item))retiredTx.push(item);
    }
    radioGeneration=generation;radio=ready&&!closing&&!detached&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0;
    set(LinkReady,radio?1:0);
    if(discardQueued)set(TxPending,tx.count);
    ifnet_t dev=interface;
    if(dev&&!closing&&!detached)++inputCalls;else dev=nullptr;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    Tx retired{};
    while(retiredTx.pop(&retired)) {
        mbuf_freem(retired.packet);add(TxExpired);
    }
    if(!discardQueued)for(unsigned i=0;i<QueueDepth;++i) {
        Tx expired{};irq=IOSimpleLockLockDisableInterrupt(lock);
        const bool old=tx.count&&nowUs()-tx.values[tx.head].born>2000000;
        if(old)tx.pop(&expired);set(TxPending,tx.count);
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(!old)break;mbuf_freem(expired.packet);add(TxExpired);
    }
    if(!dev)return;
    // RX was copied only from a current, bounded hardware ROC lease.
    for(unsigned i=0;i<QueueDepth;++i) {
        Rx item{};irq=IOSimpleLockLockDisableInterrupt(lock);
        const bool have=rx.pop(&item);set(RxPending,rx.count);
        IOSimpleLockUnlockEnableInterrupt(lock,irq);if(!have)break;
        NativeAwdlData::DecodedFrame parsed{};
        if(!ready||item.generation!=generation||NativeAwdlData::decodeIpv6DataMpdu(item.bytes,item.length,&parsed)!=NativeAwdlData::Status::Ok){add(RxRejected);continue;}
        add(RxDecoded);
        for(size_t n=0;n<parsed.packetCount;++n) {
            const auto &p=parsed.packets[n];
            if(!acceptsRx(p,own)){add(RxRejected);continue;}
            mbuf_t m=packetWithHeader();
            if(!m){add(RxInputFailed);continue;}
            uint8_t *bytes=static_cast<uint8_t *>(mbuf_data(m));
            memcpy(bytes,p.destinationAddress,6);memcpy(bytes+6,p.sourceAddress,6);
            bytes[12]=0x86;bytes[13]=0xdd;memcpy(bytes+14,p.ipv6Packet,p.ipv6Length);
            mbuf_setlen(m,p.ipv6Length+14);mbuf_pkthdr_setlen(m,p.ipv6Length+14);
            mbuf_pkthdr_setrcvif(m,dev);mbuf_pkthdr_setheader(m,bytes);
            mbuf_adj(m,14); // native Ethernet demux receives a separate L2 header
            if(ifnet_input(dev,m,nullptr)==0)add(RxDelivered);else add(RxInputFailed);
        }
    }
    irq=IOSimpleLockLockDisableInterrupt(lock);--inputCalls;IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
CaptureResult capture(const uint8_t *bytes,size_t length,bool protectedFrame,bool leaseCurrent,uint32_t generation) {
    if(!bytes||!NativeAwdlData::isAwdlDataCandidate(bytes,length))
        return CaptureResult::NotAwdlDataCandidate;
    if(!bridgeLock()){add(RxRejected);return CaptureResult::Rejected;}
    if(protectedFrame||!leaseCurrent||length>2048){add(RxRejected);return CaptureResult::Rejected;}
    Rx item{};item.length=uint16_t(length);item.generation=generation;memcpy(item.bytes,bytes,length);
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool current=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==generation;
    const bool accepted=current&&rx.push(item);set(RxPending,rx.count);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(accepted){add(RxCaptured);return CaptureResult::Captured;}
    if(!current){add(RxRejected);return CaptureResult::Rejected;}
    add(RxQueueFull);return CaptureResult::QueueFull;
}
namespace {
mbuf_t nextTxImpl(uint16_t sequence,uint64_t *token,
                  const DiscoveryTxSnapshot *expected,bool *consumed) {
    if(consumed)*consumed=false;
    if(!bridgeLock()||!token||(expected&&!consumed))return nullptr;
    const bool discovery=expected!=nullptr;
    const uint64_t dequeueTime=nowUs();
    Tx item{};uint32_t currentGeneration=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    bool have=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        !inFlightToken&&tx.count;
    if(have&&discovery) {
        const Tx &head=tx.values[tx.head];
        have=snapshotMatches(head,*expected)&&
            expected->generation==radioGeneration&&
            discoveryAgeCurrent(head.born,dequeueTime);
    }
    if(have)have=tx.pop(&item);
    if(have){inFlightToken=item.token;currentGeneration=radioGeneration;}
    if(!discovery||have)set(TxPending,tx.count);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!have)return nullptr;
    if(consumed)*consumed=true;
    uint8_t ethernet[MaxEthernet],raw[MaxMpdu];EthernetView view{};
    const size_t length=mbuf_pkthdr_len(item.packet);
    const uint64_t packetNow=nowUs();
    bool valid=item.generation==currentGeneration&&
        packetNow-item.born<=2000000&&
        length<=sizeof(ethernet)&&
        mbuf_copydata(item.packet,0,length,ethernet)==0&&
        ethernetIpv6(ethernet,length,own,&view);
    if(valid) {
        const auto observation=NativeAwdlData::observeAwdlTxPacket(
            ethernet,length,own);
        const auto &mdns=observation.mdnsQuery;
        set(TxLastEthernetLength,observation.ethernetLength);
        set(TxLastIpv6Length,observation.ipv6Length);
        set(TxLastUdpLength,observation.udpLength);
        set(TxLastIpv6NextHeader,observation.ipv6NextHeader);
        set(TxLastSourceIsLinkLocal,observation.sourceIsLinkLocal);
        set(TxLastSourceEui64MatchesOwn,observation.sourceEui64MatchesOwn);
        set(TxLastUdpHasMdnsPort,observation.udpHasMdnsPort);
        set(TxLastIpv6DestinationIsMulticast,
            observation.ipv6DestinationIsMulticast);
        set(TxLastEthernetMulticastMappingMatches,
            observation.ethernetMulticastMappingMatches);
        set(TxLastUdpChecksumStatus,
            static_cast<uint8_t>(observation.udpChecksumStatus));
        set(TxLastIpv6PacketWellFormed,observation.ipv6PacketWellFormed);
        set(TxMdnsLastClass,static_cast<uint8_t>(mdns.queryClass));
        set(TxMdnsLastSourcePortIs5353,mdns.sourcePortIs5353);
        set(TxMdnsLastDestinationPortIs5353,mdns.destinationPortIs5353);
        set(TxMdnsLastDestinationIsFf02Fb,mdns.destinationIsFf02Fb);
        set(TxMdnsLastDnsHeaderParsed,mdns.headerParsed);
        set(TxMdnsLastQr,mdns.qr);
        set(TxMdnsLastTc,mdns.tc);
        set(TxMdnsLastQuestionCount,mdns.questionCount);
        set(TxMdnsLastTargetPtrInQuestionCount,mdns.targetPtrInQuestionCount);
        set(TxMdnsLastQuQuestionMask,mdns.quQuestionMask);
        set(TxMdnsLastAttemptToken,item.token);
        add(mdnsAttemptCounter(mdns.queryClass));
        irq=IOSimpleLockLockDisableInterrupt(lock);
        if(inFlightToken==item.token)
            inFlightMdnsClass=mdns.queryClass;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        const auto delta=NativeAwdlData::summarizeTxObservation(observation);
        __atomic_fetch_or(&counters[TxChecksumStatusSeenMask],
                          uint64_t(delta.checksumStatusBit),__ATOMIC_RELAXED);
        if(delta.sourceEui64Mismatch)add(TxSourceEui64MismatchCount);
        if(delta.multicastMappingMismatch)add(TxMulticastMappingMismatchCount);
        if(delta.malformed)add(TxMalformedCount);
        add(TxObservationCount);
        if(discovery) {
            valid=item.discoveryEligible&&snapshotMatches(item,*expected)&&
                item.discoveryClass==static_cast<uint8_t>(mdns.queryClass)&&
                isStrictAirdropQm(observation);
            // A radio-generation/close transition after dequeue consumes this
            // token safely but must not submit an out-of-epoch MPDU.
            irq=IOSimpleLockLockDisableInterrupt(lock);
            valid=valid&&interface&&!closing&&!detached&&radio&&
                radioGeneration==expected->generation&&
                __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
                inFlightToken==item.token;
            IOSimpleLockUnlockEnableInterrupt(lock,irq);
        }
    } else if(discovery) {
        valid=false;
    }
    mbuf_freem(item.packet);
    size_t written=0;
    NativeAwdlData::EncodeInput input{};memcpy(input.sourceAddress,own,6);
    if(valid){memcpy(input.destinationAddress,view.destination,6);input.wifiSequenceNumber=sequence&0xfff;
        input.awdlSequenceNumber=discovery?dataSequence:dataSequence++;
        input.ipv6Packet=view.ipv6;input.ipv6Length=view.length;
        valid=NativeAwdlData::encodeIpv6DataMpdu(&input,raw,sizeof(raw),&written)==NativeAwdlData::Status::Ok;}
    mbuf_t m=valid?packetWithHeader():nullptr;
    if(m){memcpy(mbuf_data(m),raw,written);mbuf_setlen(m,written);mbuf_pkthdr_setlen(m,written);
        if(discovery)++dataSequence;
        *token=item.token;add(TxEncoded);return m;}
    submitted(item.token,EINVAL);add(TxExpired);return nullptr;
}
}
mbuf_t nextTx(uint16_t sequence,uint64_t *token) {
    return nextTxImpl(sequence,token,nullptr,nullptr);
}
bool peekDiscoveryTx(uint32_t expectedPowerGeneration,
                     DiscoveryTxSnapshot *out) {
    if(!out||!expectedPowerGeneration||!bridgeLock())return false;
    const uint64_t now=nowUs();DiscoveryTxSnapshot candidate{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    bool valid=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==expectedPowerGeneration&&!inFlightToken&&tx.count;
    if(valid) {
        const Tx &head=tx.values[tx.head];
        valid=head.discoveryEligible&&
            head.discoveryClass==static_cast<uint8_t>(
                NativeAwdlData::MdnsQueryClass::QmMulticast);
        if(valid)candidate=DiscoveryTxSnapshot{head.token,head.born,
            head.generation,head.discoveryClass,head.discoveryEligible};
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!valid||candidate.generation!=expectedPowerGeneration||
       !discoveryAgeCurrent(candidate.bornUs,now))return false;
    *out=candidate;return true;
}
mbuf_t nextDiscoveryTx(uint16_t sequence,
                       const DiscoveryTxSnapshot &expected,
                       uint64_t *token,bool *consumed) {
    if(token)*token=0;
    if(consumed)*consumed=false;
    if(!token||!consumed)return nullptr;
    return nextTxImpl(sequence,token,&expected,consumed);
}
void submitted(uint64_t token,int result) {
    if(!bridgeLock()||!token)return;auto irq=IOSimpleLockLockDisableInterrupt(lock);
    if(inFlightToken!=token){add(TxStaleCompletion);}
    else if(result==0){add(TxSubmitted);add(mdnsSubmittedCounter(inFlightMdnsClass));}
    else {inFlightToken=0;add(TxFailed);add(TxMdnsSubmitFailed);inFlightMdnsClass=NativeAwdlData::MdnsQueryClass::Unknown;}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
void completed(uint64_t token,bool success) {
    if(!bridgeLock()||!token)return;auto irq=IOSimpleLockLockDisableInterrupt(lock);
    if(inFlightToken!=token)add(TxStaleCompletion);
    else {add(TxCompleted);add(mdnsCompletedCounter(inFlightMdnsClass));
        if(success){add(TxSucceeded);add(mdnsSucceededCounter(inFlightMdnsClass));}
        else {add(TxFailed);add(TxMdnsCompletionFailed);}
        inFlightToken=0;inFlightMdnsClass=NativeAwdlData::MdnsQueryClass::Unknown;}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
void gateObservation(uint32_t blockers) {
    add(GateChecks);set(GateLastBlockers,blockers);
    __atomic_fetch_or(&counters[GateReasonsSeen],uint64_t(blockers),__ATOMIC_RELAXED);
    if(!blockers)add(GateAllowed);
}
bool close() {
    if(!bridgeLock())return true;
    publishClosing();
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    auto ref=filter;IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(ref)iflt_detach(ref);
    cancelQueued();
    for(unsigned i=0;i<2000;++i) {
        irq=IOSimpleLockLockDisableInterrupt(lock);
        const bool done=(!interface||detached)&&inputCalls==0&&inFlightToken==0;
        ifnet_t dev=done?interface:nullptr;
        if(done){interface=nullptr;rx.head=rx.tail=rx.count=0;memset(rx.values,0,sizeof(rx.values));set(RxPending,0);}
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(done){if(dev)ifnet_release(dev);return true;}IOSleep(1);
    }
    return false; // no unsafe free while callbacks or DMA completion can arrive
}
void publishClosing() {
    __atomic_store_n(&closingRequested,1u,__ATOMIC_RELEASE);
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    closing=true;radio=false;set(Closing,1);set(LinkReady,0);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
Snapshot snapshot(){Snapshot s{};for(unsigned i=0;i<Count;++i)s.value[i]=__atomic_load_n(&counters[i],__ATOMIC_ACQUIRE);return s;}
AttachTraceSnapshot attachSnapshot(){return attachTrace.snapshot();}
void noteResidentLookupResult(int result){attachTrace.noteResidentLookupResult(result);}
}
#endif
