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
struct Tx {mbuf_t packet=nullptr;uint64_t token=0,born=0;uint32_t generation=0;};
struct Rx {uint16_t length=0;uint32_t generation=0;uint8_t bytes[2048]{};};
IOSimpleLock *lock;
Ring<Tx,QueueDepth> tx;
Ring<Rx,QueueDepth> rx;
ifnet_t interface;
interface_filter_t filter;
uint8_t own[6];
uint64_t counters[Count]{},nextToken=0,inFlightToken=0;
uint32_t inputCalls=0;
uint32_t radioGeneration=0;
uint16_t dataSequence=0;
bool closing=false,detached=false,radio=false;
uint64_t nowUs(){uint64_t t=0,n=0;clock_get_uptime(&t);absolutetime_to_nanoseconds(t,&n);return n/1000;}
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
    if(!lock||!packet||!*packet)return EINVAL;
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
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool valid=interface==dev&&!closing&&radio;
    Tx entry{*packet,++nextToken,nowUs(),radioGeneration};
    const bool accepted=valid&&tx.push(entry);
    if(accepted){*packet=nullptr;set(TxPending,tx.count);}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!accepted){add(TxRejected);return ENOBUFS;}
    add(TxAccepted);return EJUSTRETURN; // filter now owns the consumed mbuf
}
void detachedCallback(void *,ifnet_t) {
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    detached=true;filter=nullptr;set(Detached,1);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
}
bool attach(ifnet_t dev,const uint8_t mac[6]) {
    if(!dev||!mac||interface||lock)return false; // one resident owner per boot
    lock=IOSimpleLockAlloc();if(!lock)return false;
    memcpy(own,mac,6);
    if(ifnet_reference(dev))return false;
    interface=dev;
    iff_filter spec{};spec.iff_name="IntelNativeAWDLData";
    spec.iff_protocol=0;spec.iff_output=output;spec.iff_detached=detachedCallback;
    const int result=iflt_attach(dev,&spec,&filter);
    if(result){interface=nullptr;ifnet_release(dev);return false;}
    // Software checksums only: the raw AWDL transport cannot service the
    // native network interface's checksum/segmentation offload requests.
    if(ifnet_set_offload(dev,0)||ifnet_set_mtu(dev,1500)||
       ifnet_set_flags(dev,IFF_UP|IFF_RUNNING,IFF_UP|IFF_RUNNING))return false;
    const uint32_t unsafe=IFCAP_HWCSUM|IFCAP_TSO|IFCAP_CSUM_PARTIAL|IFCAP_CSUM_ZERO_INVERT;
    ifnet_set_capabilities_enabled(dev,0,unsafe);
    ifnet_set_capabilities_supported(dev,0,unsafe);
    set(OffloadCapabilities,ifnet_capabilities_enabled(dev));
    const int ipv6=configureLinkLocal(dev,mac);
    set(Ipv6ConfigResult,uint32_t(ipv6));set(Ipv6Configured,hasLinkLocal(dev)?1:0);
    if(ipv6)return false;
    set(Attached,1);return true;
}
bool address(uint8_t out[6]) {
    if(!out||!lock)return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool ok=interface&&!closing;if(ok)memcpy(out,own,6);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);return ok;
}
void cancelQueued() {
    if(!lock)return;
    Tx item{};
    for(;;){auto irq=IOSimpleLockLockDisableInterrupt(lock);const bool have=tx.pop(&item);set(TxPending,tx.count);IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(!have)break;mbuf_freem(item.packet);add(TxExpired);}
}
void poll(bool ready,uint32_t generation) {
    if(!lock)return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool changed=radioGeneration&&radioGeneration!=generation;
    radioGeneration=generation;radio=ready&&!closing;set(LinkReady,radio?1:0);
    ifnet_t dev=interface;
    if(dev&&!closing)++inputCalls;else dev=nullptr;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!ready||changed)cancelQueued();
    else for(unsigned i=0;i<QueueDepth;++i) {
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
    if(!lock){add(RxRejected);return CaptureResult::Rejected;}
    if(protectedFrame||!leaseCurrent||length>2048){add(RxRejected);return CaptureResult::Rejected;}
    Rx item{};item.length=uint16_t(length);item.generation=generation;memcpy(item.bytes,bytes,length);
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool current=interface&&!closing&&radio&&radioGeneration==generation;
    const bool accepted=current&&rx.push(item);set(RxPending,rx.count);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(accepted){add(RxCaptured);return CaptureResult::Captured;}
    if(!current){add(RxRejected);return CaptureResult::Rejected;}
    add(RxQueueFull);return CaptureResult::QueueFull;
}
mbuf_t nextTx(uint16_t sequence,uint64_t *token) {
    if(!lock||!token)return nullptr;
    Tx item{};auto irq=IOSimpleLockLockDisableInterrupt(lock);
    bool have=interface&&!closing&&radio&&!inFlightToken&&tx.pop(&item);
    if(have)inFlightToken=item.token;set(TxPending,tx.count);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);if(!have)return nullptr;
    uint8_t ethernet[MaxEthernet],raw[MaxMpdu];EthernetView view{};
    const size_t length=mbuf_pkthdr_len(item.packet);
    bool valid=item.generation==radioGeneration&&nowUs()-item.born<=2000000&&length<=sizeof(ethernet)&&
        mbuf_copydata(item.packet,0,length,ethernet)==0&&ethernetIpv6(ethernet,length,own,&view);
    if(valid) {
        const auto observation=NativeAwdlData::observeAwdlTxPacket(
            ethernet,length,own);
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
        const auto delta=NativeAwdlData::summarizeTxObservation(observation);
        __atomic_fetch_or(&counters[TxChecksumStatusSeenMask],
                          uint64_t(delta.checksumStatusBit),__ATOMIC_RELAXED);
        if(delta.sourceEui64Mismatch)add(TxSourceEui64MismatchCount);
        if(delta.multicastMappingMismatch)add(TxMulticastMappingMismatchCount);
        if(delta.malformed)add(TxMalformedCount);
        add(TxObservationCount);
    }
    mbuf_freem(item.packet);
    size_t written=0;
    NativeAwdlData::EncodeInput input{};memcpy(input.sourceAddress,own,6);
    if(valid){memcpy(input.destinationAddress,view.destination,6);input.wifiSequenceNumber=sequence&0xfff;
        input.awdlSequenceNumber=dataSequence++;input.ipv6Packet=view.ipv6;input.ipv6Length=view.length;
        valid=NativeAwdlData::encodeIpv6DataMpdu(&input,raw,sizeof(raw),&written)==NativeAwdlData::Status::Ok;}
    mbuf_t m=valid?packetWithHeader():nullptr;
    if(m){memcpy(mbuf_data(m),raw,written);mbuf_setlen(m,written);mbuf_pkthdr_setlen(m,written);*token=item.token;add(TxEncoded);return m;}
    submitted(item.token,EINVAL);add(TxExpired);return nullptr;
}
void submitted(uint64_t token,int result) {
    if(!lock||!token)return;auto irq=IOSimpleLockLockDisableInterrupt(lock);
    if(inFlightToken!=token){add(TxStaleCompletion);}
    else if(result==0)add(TxSubmitted);else {inFlightToken=0;add(TxFailed);}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
void completed(uint64_t token,bool success) {
    if(!lock||!token)return;auto irq=IOSimpleLockLockDisableInterrupt(lock);
    if(inFlightToken!=token)add(TxStaleCompletion);
    else {inFlightToken=0;add(TxCompleted);add(success?TxSucceeded:TxFailed);}
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
void gateObservation(uint32_t blockers) {
    add(GateChecks);set(GateLastBlockers,blockers);
    __atomic_fetch_or(&counters[GateReasonsSeen],uint64_t(blockers),__ATOMIC_RELAXED);
    if(!blockers)add(GateAllowed);
}
bool close() {
    if(!lock)return true;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);closing=true;radio=false;set(Closing,1);
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
Snapshot snapshot(){Snapshot s{};for(unsigned i=0;i<Count;++i)s.value[i]=__atomic_load_n(&counters[i],__ATOMIC_ACQUIRE);return s;}
}
#endif
