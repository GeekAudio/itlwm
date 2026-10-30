// SPDX-License-Identifier: GPL-2.0-only
// Actual BSD Ethernet/IPv6 -> Intel MPDU and Intel MPDU -> native awdl0 bridge.
// A packet is never looped back or counted as radio receipt by this module.
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "awdl_native_bsd_data_25G332.hpp"
#include "awdl_bsd_packet_bridge.hpp"
#include "awdl_data_tx_observation.hpp"
#include "rx149_input_gate_state.hpp"
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
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
Rx149TestHook rx149TestHookForTests=nullptr;
void runRx149TestHook(Rx149TestHookPoint point) {
    const auto hook=rx149TestHookForTests;
    if(hook)hook(point);
}
#endif
struct Tx {
    mbuf_t packet=nullptr;
    uint64_t token=0,born=0;
    uint32_t generation=0;
    bool discoveryEligible=false;
    uint8_t discoveryClass=0;
};
struct Rx {
    uint16_t length=0;
    uint32_t generation=0;
    uint64_t interfaceIncarnation=0;
    uint64_t rx149GuardVersion=0;
    uint64_t rx149ReceiptSequence=0;
    bool rx149PermitPresent=false;
    NativeP2PRx149DataInput::Permit rx149Permit{};
    uint8_t bytes[2048]{};
};
IOSimpleLock *lock;
uint32_t attachClaimed=0;
uint64_t interfaceIncarnation=0;
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
NativeP2PRx149DataInput::Lease activeRx149Lease{};
bool activeRx149LeaseValid=false;
uint64_t activeRx149Version=0;
uint64_t rx149OwnerSerialHighWater=0;
uint64_t rx149ReceiptSequence=0;
uint64_t rx149ReceiptContentRevision=0;
Rx149InputReceipt rx149Receipt{};
Rx149InputGateState::Word rx149InputGateState=0;
uint32_t rx149RecoveryPreparedFaultSerial=0;
bool reserveRx149InputTicketFast() {
    return Rx149InputGateState::reserveTicket(&rx149InputGateState);
}
void releaseRx149InputTicketFast() {
    (void)Rx149InputGateState::releaseTicket(&rx149InputGateState);
}
IOSimpleLock *bridgeLock() {
    return __atomic_load_n(&lock,__ATOMIC_ACQUIRE);
}
void add(Counter c);
void set(Counter c,uint64_t n);
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
bool ipv6LinkLocal(const uint8_t *address) {
    return address&&address[0]==0xfe&&(address[1]&0xc0u)==0x80u;
}
bool nativeLinkLocalTarget(const uint8_t *address,const uint8_t own[6]) {
    if(!address||!own||!ipv6LinkLocal(address)||address[1]!=0x80)
        return false;
    for(unsigned index=2;index<8;++index)
        if(address[index]!=0)return false;
    const uint8_t expectedIid[8]={
        static_cast<uint8_t>(own[0]^2u),own[1],own[2],0xff,0xfe,
        own[3],own[4],own[5]};
    return memcmp(address+8,expectedIid,sizeof(expectedIid))==0;
}
bool linkLocalMulticastMapping(const uint8_t *address,
                               const uint8_t ethernetDestination[6]) {
    return address&&ethernetDestination&&address[0]==0xff&&
        address[1]==0x02&&ethernetDestination[0]==0x33&&
        ethernetDestination[1]==0x33&&
        memcmp(ethernetDestination+2,address+12,4)==0;
}
bool validUnicastAddress(const uint8_t address[6]) {
    if(!address||(address[0]&1u))return false;
    uint8_t any=0;
    for(unsigned index=0;index<6;++index)any|=address[index];
    return any!=0;
}
bool acceptsRx149(const NativeAwdlData::PacketView &packet,
                  const uint8_t own[6]) {
    if(!acceptsRx(packet,own)||!validUnicastAddress(packet.sourceAddress)||
       packet.ipv6Length<40||(packet.ipv6Packet[0]>>4)!=6||
       !ipv6LinkLocal(packet.ipv6Packet+8))
        return false;
    const uint8_t *destination=packet.ipv6Packet+24;
    if(destination[0]==0xff)
        return linkLocalMulticastMapping(
            destination,packet.destinationAddress);
    return !memcmp(packet.destinationAddress,own,6)&&
        nativeLinkLocalTarget(destination,own);
}
bool isStrictContinuityQm(const NativeAwdlData::TxObservation &observation) {
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
bool strictContinuityQmBytes(const uint8_t *bytes,size_t length,
                             const uint8_t ownAddress[6],
                             EthernetView *viewOut,
                             NativeAwdlData::MdnsQueryClass *classOut) {
    EthernetView view{};
    if(!ethernetIpv6(bytes,length,ownAddress,&view))return false;
    const auto observation=NativeAwdlData::observeAwdlTxPacket(
        bytes,length,ownAddress);
    if(classOut)*classOut=observation.mdnsQuery.queryClass;
    if(viewOut)*viewOut=view;
    return isStrictContinuityQm(observation);
}
bool snapshotMatches(const Tx &head,const DiscoveryTxSnapshot &expected) {
    return expected.eligible&&head.discoveryEligible&&
        expected.token==head.token&&expected.bornUs==head.born&&
        expected.generation==head.generation&&
        expected.queryClass==head.discoveryClass&&
        head.discoveryClass==static_cast<uint8_t>(
            NativeAwdlData::MdnsQueryClass::QmMulticast);
}
bool removeTxAt(size_t offset,Tx *removed) {
    if(!removed||offset>=tx.count)return false;
    const size_t selected=(tx.head+offset)%QueueDepth;
    *removed=tx.values[selected];
    // Stable bounded shift: retain FIFO order for every unselected mbuf.
    // This is metadata/pointer movement only; no KPI, allocation, or release
    // occurs while the caller holds IOSimpleLock.
    for(size_t index=offset;index+1<tx.count;++index) {
        const size_t destination=(tx.head+index)%QueueDepth;
        const size_t source=(tx.head+index+1)%QueueDepth;
        tx.values[destination]=tx.values[source];
    }
    const size_t last=(tx.head+tx.count-1)%QueueDepth;
    tx.values[last]=Tx{};
    tx.tail=last;
    --tx.count;
    return true;
}
bool removeRxAt(size_t offset,Rx *removed) {
    if(!removed||offset>=rx.count)return false;
    const size_t selected=(rx.head+offset)%QueueDepth;
    *removed=rx.values[selected];
    // Fixed-size metadata and bytes only; no packet/KPI ownership changes.
    for(size_t index=offset;index+1<rx.count;++index) {
        const size_t destination=(rx.head+index)%QueueDepth;
        const size_t source=(rx.head+index+1)%QueueDepth;
        rx.values[destination]=rx.values[source];
    }
    const size_t last=(rx.head+rx.count-1)%QueueDepth;
    rx.values[last]=Rx{};
    rx.tail=last;
    --rx.count;
    return true;
}
bool sameRx149LeaseIdentity(
    const NativeP2PRx149DataInput::Lease &left,
    const NativeP2PRx149DataInput::Lease &right) {
    return left.ownerSerial==right.ownerSerial&&
        left.startUs==right.startUs&&
        NativeP2PRx149DataInput::sameEpochs(left.epochs,right.epochs);
}
bool sameRx149PermitIdentity(
    const NativeP2PRx149DataInput::Lease &lease,
    const NativeP2PRx149DataInput::Permit &permit) {
    return lease.ownerSerial==permit.ownerSerial&&
        lease.startUs==permit.startUs&&
        NativeP2PRx149DataInput::sameEpochs(lease.epochs,permit.epochs);
}
void recordRx149ReceiptLocked(const Rx &,uint32_t,uint64_t,uint32_t,bool,int);
size_t removeRx149ItemsLocked(bool all,uint64_t version,
                              uint64_t ownerSerial,
                              const NativeP2PRx149DataInput::Epochs *epochs,
                              uint64_t nowUsValue) {
    size_t removedCount=0;
    for(size_t offset=0;offset<rx.count;) {
        const size_t index=(rx.head+offset)%QueueDepth;
        const Rx &item=rx.values[index];
        const bool match=item.rx149PermitPresent&&
            (all||(item.rx149GuardVersion==version&&
             item.rx149Permit.ownerSerial==ownerSerial&&epochs&&
             NativeP2PRx149DataInput::sameEpochs(
                 item.rx149Permit.epochs,*epochs)));
        if(match) {
            Rx discarded{};
            if(removeRxAt(offset,&discarded)) {
                recordRx149ReceiptLocked(discarded,
                    Rx149ReceiptStaleOrInvalid,nowUsValue,0,false,0);
                ++removedCount;
            }
        } else {
            ++offset;
        }
    }
    set(RxPending,rx.count);
    return removedCount;
}
size_t drainRxQueueForRecoveryLocked(uint64_t nowUsValue) {
    size_t removedCount=0;
    Rx removed{};
    while(rx.pop(&removed)) {
        if(removed.rx149PermitPresent)
            recordRx149ReceiptLocked(removed,Rx149ReceiptStaleOrInvalid,
                                     nowUsValue,0,false,0);
        ++removedCount;
    }
    set(RxPending,0);
    return removedCount;
}
bool activateRx149LeaseLocked(
    const NativeP2PRx149DataInput::Lease &lease,
    size_t *discardedCount,uint64_t nowUsValue) {
    if(discardedCount)*discardedCount=0;
    if(Rx149InputGateState::blocked(
           __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE))||
       !NativeP2PRx149DataInput::leaseCurrent(lease,nowUsValue))
        return false;
    if(!activeRx149LeaseValid||
       !sameRx149LeaseIdentity(activeRx149Lease,lease)) {
        // Owner serials are monotonically increasing for the lifetime of the
        // RX trace timeline. Reject a copied pre-END lease instead of letting
        // a worker snapshot reopen a tombstoned owner.
        if(lease.ownerSerial<=rx149OwnerSerialHighWater)
            return false;
        if(activeRx149Version==UINT64_MAX) {
            activeRx149LeaseValid=false;
            if(discardedCount)
                *discardedCount=removeRx149ItemsLocked(true,0,0,nullptr,nowUsValue);
            else
                (void)removeRx149ItemsLocked(true,0,0,nullptr,nowUsValue);
            return false;
        }
        ++activeRx149Version;
        if(discardedCount)
            *discardedCount=removeRx149ItemsLocked(true,0,0,nullptr,nowUsValue);
        else
            (void)removeRx149ItemsLocked(true,0,0,nullptr,nowUsValue);
        activeRx149Lease=lease;
        activeRx149LeaseValid=true;
        rx149OwnerSerialHighWater=lease.ownerSerial;
        return true;
    }
    activeRx149Lease=lease; // refresh numeric evidence without changing identity
    return true;
}
size_t revokeRx149LeaseLocked(
    uint64_t ownerSerial,const NativeP2PRx149DataInput::Epochs *epochs,
    uint64_t nowUsValue) {
    if(!ownerSerial||!epochs||
       !NativeP2PRx149DataInput::validEpochs(*epochs))
        return 0;

    size_t discarded=0;
    if(activeRx149LeaseValid) {
        if(activeRx149Lease.ownerSerial>ownerSerial)
            return 0; // a stale targeted close cannot revoke a newer owner
        if(activeRx149Lease.ownerSerial==ownerSerial&&
           !NativeP2PRx149DataInput::sameEpochs(
               activeRx149Lease.epochs,*epochs))
            return 0; // serial matches but the epoch tuple does not

        if(activeRx149Lease.ownerSerial==ownerSerial) {
            activeRx149LeaseValid=false;
            activeRx149Lease=NativeP2PRx149DataInput::Lease{};
            if(ownerSerial>rx149OwnerSerialHighWater)
                rx149OwnerSerialHighWater=ownerSerial;
            if(activeRx149Version==UINT64_MAX)
                return removeRx149ItemsLocked(true,0,0,nullptr,nowUsValue);
            ++activeRx149Version;
            return removeRx149ItemsLocked(false,activeRx149Version-1,
                                          ownerSerial,epochs,nowUsValue);
        }

        // A newer terminal owner supersedes the older active receive lease.
        discarded=removeRx149ItemsLocked(true,0,0,nullptr,nowUsValue);
        activeRx149LeaseValid=false;
        activeRx149Lease=NativeP2PRx149DataInput::Lease{};
    }

    // Tombstone a terminal current owner even if its first authoritative
    // lease was never published (for example, MCC revokes before any frame).
    if(ownerSerial<=rx149OwnerSerialHighWater)
        return discarded;
    rx149OwnerSerialHighWater=ownerSerial;
    if(activeRx149Version!=UINT64_MAX)
        ++activeRx149Version;
    const size_t targeted=removeRx149ItemsLocked(
        true,0,0,nullptr,nowUsValue);
    return discarded+targeted;
}
void recordRx149ReceiptLocked(const Rx &item,uint32_t disposition,
                             uint64_t inputUs,uint32_t decodedCount,
                             bool inputResultPresent,int inputResult) {
    if(!item.rx149ReceiptSequence||
       rx149Receipt.sequence!=item.rx149ReceiptSequence)
        return; // a newer captured MPDU owns the single latest receipt
    const int32_t result=static_cast<int32_t>(inputResult);
    if(rx149Receipt.disposition==disposition&&
       rx149Receipt.inputUs==inputUs&&
       rx149Receipt.decodedIpv6Count==decodedCount&&
       rx149Receipt.ifnetInputResultPresent==(inputResultPresent?1u:0u)&&
       rx149Receipt.ifnetInputResult==result)
        return;
    if(rx149ReceiptContentRevision==UINT64_MAX) {
        // Revision wrap would alias a previously published snapshot. Preserve
        // the last state and fail closed instead of silently reusing a key.
        rx149Receipt.schemaVersion=0;
        return;
    }
    rx149Receipt.disposition=disposition;
    rx149Receipt.inputUs=inputUs;
    rx149Receipt.decodedIpv6Count=decodedCount;
    rx149Receipt.ifnetInputResultPresent=inputResultPresent?1u:0u;
    rx149Receipt.ifnetInputResult=result;
    rx149Receipt.contentRevision=++rx149ReceiptContentRevision;
}
Rx149InputReceipt makeRx149Receipt(const Rx &item,uint64_t sequence,
                                    uint32_t disposition) {
    Rx149InputReceipt receipt{};
    receipt.schemaVersion=2;
    receipt.disposition=disposition;
    receipt.sequence=sequence;
    receipt.ownerSerial=item.rx149Permit.ownerSerial;
    receipt.interfaceIncarnation=item.interfaceIncarnation;
    receipt.contextGeneration=item.rx149Permit.epochs.context;
    receipt.powerGeneration=item.rx149Permit.epochs.power;
    receipt.stationGeneration=item.rx149Permit.epochs.station;
    receipt.rocGeneration=item.rx149Permit.epochs.roc;
    receipt.captureUs=item.rx149Permit.capturedUs;
    receipt.deadlineUs=item.rx149Permit.deadlineUs;
    receipt.ieeeChannel=item.rx149Permit.ieeeChannel;
    receipt.macIndexPresent=1;
    receipt.macIndex=item.rx149Permit.macIndex;
    receipt.macPhyDecodeMode=item.rx149Permit.decodeMode;
    receipt.originalRxStatus=item.rx149Permit.originalRawStatus;
    receipt.mpduLength=item.length;
    return receipt;
}
void recordRx149Receipt(const Rx &item,uint32_t disposition,
                        uint64_t inputUs,uint32_t decodedCount=0,
                        bool inputResultPresent=false,int inputResult=0) {
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    recordRx149ReceiptLocked(item,disposition,inputUs,decodedCount,
                             inputResultPresent,inputResult);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
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
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    // This isolated profile is receive-only for its entire lifetime. The
    // runtime experiment flag controls RX admission but can never open TX.
    (void)nextToken;
    (void)dataSequence;
    (void)dev;
    (void)family;
    if(!packet||!*packet)return EINVAL;
    add(TxRejected);
    return EOPNOTSUPP; // preserve caller ownership; do not queue or finalize
#else
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
        discoveryEligible=strictContinuityQmBytes(finalizedBytes,finalizedLength,
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
#endif
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
        !__atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)&&
        interfaceIncarnation!=UINT64_MAX;
    if(canAttach) {
        interface=dev;
        ++interfaceIncarnation;
    }
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
void publishRx149DataInputLease(
    const NativeP2PRx149DataInput::Lease &lease) {
    if(!bridgeLock())return;
    size_t discarded=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    // Authorization time is sampled only after acquiring the same lock that
    // publishes the lease, so lock contention cannot revive an expired ROC.
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
    runRx149TestHook(Rx149TestHookPoint::LeaseAuthorization);
#endif
    const uint64_t lockedNow=nowUs();
    if(NativeP2PRx149DataInput::leaseCurrent(lease,lockedNow))
        (void)activateRx149LeaseLocked(lease,&discarded,lockedNow);
    else if(lease.ownerSerial&&
            NativeP2PRx149DataInput::validEpochs(lease.epochs))
        discarded=revokeRx149LeaseLocked(lease.ownerSerial,&lease.epochs,
                                         lockedNow);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(RxRejected);
}
void revokeRx149DataInput(uint64_t ownerSerial,
    const NativeP2PRx149DataInput::Epochs &epochs) {
    if(!bridgeLock()||!ownerSerial)return;
    const uint64_t now=nowUs();
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const size_t discarded=revokeRx149LeaseLocked(ownerSerial,&epochs,now);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(RxRejected);
}
void revokeRx149DataInput() {
    if(!bridgeLock())return;
    const uint64_t now=nowUs();
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    size_t discarded=0;
    if(activeRx149LeaseValid) {
        const uint64_t ownerSerial=activeRx149Lease.ownerSerial;
        const auto epochs=activeRx149Lease.epochs;
        discarded=revokeRx149LeaseLocked(ownerSerial,&epochs,now);
    } else {
        discarded=removeRx149ItemsLocked(true,0,0,nullptr,now);
        if(activeRx149Version!=UINT64_MAX)++activeRx149Version;
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(RxRejected);
}
void invalidateRx149DataInputFast() {
    // This latch is intentionally independent of bridge initialization and
    // IOSimpleLock availability. HW_ERR/RFKILL callers can fence a final
    // ticket without waiting for the queue lock or doing cleanup in context.
    (void)Rx149InputGateState::invalidate(&rx149InputGateState);
}
bool rx149DataInputBlocked() {
    return Rx149InputGateState::blocked(
        __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE));
}
uint32_t rx149DataInputFaultSerial() {
    return Rx149InputGateState::faultSerial(
        __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE));
}
Rx149RecoveryResult recoverRx149DataInput(
    const Rx149RecoveryAuthority &authority) {
    if(!authority.faultSerial||!authority.powerGeneration||
       !authority.fullInitializationSucceeded||!authority.faultSourceClear)
        return Rx149RecoveryResult::InvalidAuthority;

    auto gateState=__atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE);
    if(!Rx149InputGateState::blocked(gateState))
        return Rx149RecoveryResult::NotBlocked;
    if(Rx149InputGateState::permanentlyBlocked(gateState))
        return Rx149RecoveryResult::VersionExhausted;
    if(Rx149InputGateState::faultSerial(gateState)!=authority.faultSerial)
        return Rx149RecoveryResult::StaleFaultSerial;

    if(!bridgeLock())return Rx149RecoveryResult::BridgeUnavailable;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    Rx149RecoveryResult result=Rx149RecoveryResult::Recovered;
    size_t discarded=0;
    const uint64_t lockedNow=nowUs();

    gateState=__atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE);
    if(!Rx149InputGateState::blocked(gateState)) {
        result=Rx149RecoveryResult::NotBlocked;
    } else if(Rx149InputGateState::permanentlyBlocked(gateState)) {
        result=Rx149RecoveryResult::VersionExhausted;
    } else if(Rx149InputGateState::faultSerial(gateState)!=
              authority.faultSerial) {
        result=Rx149RecoveryResult::StaleFaultSerial;
    } else if(!interface||closing||detached||
              __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)!=0||
              __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)==0||
              !radio) {
        result=Rx149RecoveryResult::BridgeUnavailable;
    } else if(radioGeneration!=authority.powerGeneration) {
        result=Rx149RecoveryResult::WrongPowerGeneration;
    } else if(activeRx149LeaseValid&&
              activeRx149Lease.epochs.power==authority.powerGeneration&&
              NativeP2PRx149DataInput::leaseCurrent(
                  activeRx149Lease,lockedNow)) {
        // A still-current owner for this generation is never invalidated.
        // Expired/ended cached leases (including same-generation copies) are
        // tombstoned below; the main gate separately proves no live producer.
        result=Rx149RecoveryResult::CurrentOwnerActive;
    } else if(activeRx149Version==UINT64_MAX||
              (rx149RecoveryPreparedFaultSerial!=authority.faultSerial&&
               activeRx149Version>=UINT64_MAX-1)) {
        // Recovery needs one fresh version. If the version was already
        // prepared by an earlier Busy result, it must not be bumped again.
        result=Rx149RecoveryResult::VersionExhausted;
    } else {
        if(rx149RecoveryPreparedFaultSerial!=authority.faultSerial) {
            if(activeRx149LeaseValid) {
                const uint64_t ownerSerial=activeRx149Lease.ownerSerial;
                const auto epochs=activeRx149Lease.epochs;
                discarded+=revokeRx149LeaseLocked(ownerSerial,&epochs,
                                                   lockedNow);
                if(activeRx149LeaseValid) {
                    result=Rx149RecoveryResult::CurrentOwnerActive;
                }
            } else {
                ++activeRx149Version;
            }
            if(result==Rx149RecoveryResult::Recovered)
                rx149RecoveryPreparedFaultSerial=authority.faultSerial;
        }

        if(result==Rx149RecoveryResult::Recovered) {
            // Recovery starts before the next ARM. Drop every old RX slot,
            // including permit-bearing entries, while preserving the latest
            // bounded receipt for permit packets.
            discarded+=drainRxQueueForRecoveryLocked(lockedNow);
            gateState=__atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE);
            if(Rx149InputGateState::faultSerial(gateState)!=
                   authority.faultSerial||
               !Rx149InputGateState::blocked(gateState)) {
                result=Rx149RecoveryResult::FaultRaced;
            } else if(Rx149InputGateState::ticketCount(gateState)!=0) {
                result=Rx149RecoveryResult::InputTicketActive;
            } else if(inputCalls!=0) {
                result=Rx149RecoveryResult::WorkerActive;
            } else if(rx.count!=0) {
                result=Rx149RecoveryResult::PermitQueueNotDrained;
            } else if(!Rx149InputGateState::recover(
                          &rx149InputGateState,authority.faultSerial)) {
                const auto after=__atomic_load_n(
                    &rx149InputGateState,__ATOMIC_ACQUIRE);
                if(Rx149InputGateState::ticketCount(after)!=0)
                    result=Rx149RecoveryResult::InputTicketActive;
                else
                    result=Rx149RecoveryResult::FaultRaced;
            }
        }
    }

    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(RxRejected);
    return result;
}
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
void setRx149TestHookForTests(Rx149TestHook hook) {
    rx149TestHookForTests=hook;
}
#endif
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
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    // This build is receive-only regardless of runtime RX-profile state.
    discardQueued=true;
#endif
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
    // Legacy RX was copied only from its current, bounded hardware ROC lease.
    // Keep Test086 permit-bearing packets for the dedicated worker drain.
    for(unsigned i=0;i<QueueDepth;++i) {
        Rx item{};irq=IOSimpleLockLockDisableInterrupt(lock);
        size_t selected=rx.count;
        for(size_t offset=0;offset<rx.count;++offset) {
            const size_t index=(rx.head+offset)%QueueDepth;
            if(!rx.values[index].rx149PermitPresent) {
                selected=offset;
                break;
            }
        }
        const bool have=selected<rx.count&&removeRxAt(selected,&item);
        set(RxPending,rx.count);
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
void poll(bool ready,uint32_t generation,
          const NativeP2PRx149DataInput::Lease *rx149Lease) {
    if(!bridgeLock())return;

    ifnet_t dev=nullptr;
    uint8_t expectedAddress[6]{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool interfaceReady=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        radioGeneration==generation;
    if(interfaceReady) {
        dev=interface;
        memcpy(expectedAddress,own,sizeof(expectedAddress));
        ++inputCalls;
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);

    // This overload is exclusively the bounded Test086 worker drain. The
    // passed lease is only a snapshot: it cannot activate or refresh the
    // authoritative main-gate lease, and a revoked owner cannot be reopened.
    for(unsigned i=0;i<QueueDepth;++i) {
        Rx item{};
        NativeP2PRx149DataInput::Lease authoritativeLease{};
        bool authoritativeMatch=false;
        irq=IOSimpleLockLockDisableInterrupt(lock);
        size_t selected=rx.count;
        for(size_t offset=0;offset<rx.count;++offset) {
            const size_t index=(rx.head+offset)%QueueDepth;
            if(rx.values[index].rx149PermitPresent) {
                selected=offset;
                break;
            }
        }
        const bool have=selected<rx.count&&removeRxAt(selected,&item);
        if(have&&rx149Lease&&
           !Rx149InputGateState::blocked(
               __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE))&&
           activeRx149LeaseValid&&
           item.rx149GuardVersion==activeRx149Version&&
           item.interfaceIncarnation==interfaceIncarnation&&
           sameRx149LeaseIdentity(activeRx149Lease,*rx149Lease)&&
           sameRx149PermitIdentity(activeRx149Lease,item.rx149Permit)) {
            authoritativeLease=activeRx149Lease;
            authoritativeMatch=true;
        }
        set(RxPending,rx.count);
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(!have)break;

        const uint64_t firstNow=nowUs();
        const bool permitCurrent=ready&&dev&&rx149Lease&&
            item.generation==generation&&
            item.generation==rx149Lease->epochs.power&&
            item.interfaceIncarnation!=0&&
            authoritativeMatch&&
            NativeP2PRx149DataInput::stillCurrent(
                item.rx149Permit,authoritativeLease,firstNow)&&
            NativeP2PRx149DataInput::stillCurrent(
                item.rx149Permit,*rx149Lease,firstNow);
        if(!permitCurrent) {
            recordRx149Receipt(item,Rx149ReceiptStaleOrInvalid,firstNow);
            add(RxRejected);
            continue;
        }

        NativeAwdlData::DecodedFrame parsed{};
        if(NativeAwdlData::decodeIpv6DataMpdu(
                item.bytes,item.length,&parsed)!=NativeAwdlData::Status::Ok) {
            recordRx149Receipt(item,Rx149ReceiptDecodeRejected,firstNow);
            add(RxRejected);
            continue;
        }
        add(RxDecoded);
        for(size_t n=0;n<parsed.packetCount;++n) {
            const auto &packet=parsed.packets[n];
            if(!acceptsRx149(packet,expectedAddress)) {
                recordRx149Receipt(item,Rx149ReceiptAddressRejected,
                                   firstNow,uint32_t(parsed.packetCount));
                add(RxRejected);
                continue;
            }
            mbuf_t m=packetWithHeader();
            if(!m) {
                recordRx149Receipt(item,Rx149ReceiptMbufAllocationFailed,
                                   firstNow,uint32_t(parsed.packetCount));
                add(RxInputFailed);
                continue;
            }
            uint8_t *bytes=static_cast<uint8_t *>(mbuf_data(m));
            memcpy(bytes,packet.destinationAddress,6);
            memcpy(bytes+6,packet.sourceAddress,6);
            bytes[12]=0x86;
            bytes[13]=0xdd;
            memcpy(bytes+14,packet.ipv6Packet,packet.ipv6Length);
            mbuf_setlen(m,packet.ipv6Length+14);
            mbuf_pkthdr_setlen(m,packet.ipv6Length+14);
            mbuf_pkthdr_setrcvif(m,dev);
            mbuf_pkthdr_setheader(m,bytes);
            mbuf_adj(m,14);

            // Packet allocation/decoding happen outside the lock. Recheck the
            // permit immediately before DLIL input so END, owner replacement,
            // radio invalidation, or deadline expiry drops the unconsumed mbuf.
            irq=IOSimpleLockLockDisableInterrupt(lock);
            // This is the linearization point for an input ticket. A packet
            // delayed on the lock past its permit deadline is denied here.
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
            runRx149TestHook(Rx149TestHookPoint::InputTicketAuthorization);
#endif
            const uint64_t ticketNow=nowUs();
            const bool stillAttached=interface==dev&&!closing&&!detached&&
                radio&&__atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
                __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
                radioGeneration==generation&&
                !Rx149InputGateState::blocked(
                    __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE))&&
                interfaceIncarnation==item.interfaceIncarnation;
            const bool permitStillCurrent=stillAttached&&rx149Lease&&
                activeRx149LeaseValid&&
                item.rx149GuardVersion==activeRx149Version&&
                sameRx149LeaseIdentity(activeRx149Lease,*rx149Lease)&&
                sameRx149LeaseIdentity(activeRx149Lease,authoritativeLease)&&
                NativeP2PRx149DataInput::leaseCurrent(
                    activeRx149Lease,ticketNow)&&
                NativeP2PRx149DataInput::stillCurrent(
                    item.rx149Permit,activeRx149Lease,ticketNow);
            bool ticketReserved=false;
            if(permitStillCurrent) {
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
                runRx149TestHook(
                    Rx149TestHookPoint::BeforeInputTicketReservation);
#endif
                // The CAS shares one atomic word with fast invalidation. A
                // fault either wins first and blocks this ticket, or this CAS
                // wins first and the already issued ticket may finish.
                ticketReserved=reserveRx149InputTicketFast();
            }
            // Count a per-MPDU input ticket while holding the same lock that
            // validates the owner/epochs/incarnation. close() waits for both
            // the worker pin and each in-flight DLIL call to retire.
            if(ticketReserved)++inputCalls;
            IOSimpleLockUnlockEnableInterrupt(lock,irq);
            if(!ticketReserved) {
                mbuf_freem(m);
                recordRx149Receipt(item,Rx149ReceiptStaleOrInvalid,
                                   ticketNow,uint32_t(parsed.packetCount));
                add(RxRejected);
                continue;
            }
            // The lock-linearized permit ticket above is the boundary: an
            // already acquired ticket may finish if END arrives immediately
            // afterward. DLIL itself always runs outside the bridge lock.
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
            runRx149TestHook(Rx149TestHookPoint::AfterInputTicket);
#endif
            const int inputResult=ifnet_input(dev,m,nullptr);
            recordRx149Receipt(item,
                inputResult==0?Rx149ReceiptIfnetInputSucceeded:
                              Rx149ReceiptIfnetInputFailed,
                ticketNow,uint32_t(parsed.packetCount),true,inputResult);
            irq=IOSimpleLockLockDisableInterrupt(lock);
            releaseRx149InputTicketFast();
            if(inputCalls)--inputCalls;
            IOSimpleLockUnlockEnableInterrupt(lock,irq);
            if(inputResult==0)add(RxDelivered);
            else add(RxInputFailed);
        }
    }

    if(dev) {
        irq=IOSimpleLockLockDisableInterrupt(lock);
        if(inputCalls)--inputCalls;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
    }
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
CaptureResult captureRx149Data(
    const uint8_t *bytes,size_t length,bool protectedFrame,
    const NativeP2PRx149DataInput::Lease &lease,
    const NativeP2PRx149DataInput::Permit &permit,uint32_t generation) {
    if(!bytes||!NativeAwdlData::isAwdlDataCandidate(bytes,length))
        return CaptureResult::NotAwdlDataCandidate;
    if(!bridgeLock()) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }
    if(protectedFrame||length>2048||!permit.valid||
       generation!=permit.epochs.power) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }

    Rx item{};
    item.length=uint16_t(length);
    item.generation=generation;
    item.rx149PermitPresent=true;
    item.rx149Permit=permit;
    memcpy(item.bytes,bytes,length);

    size_t expired=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    // Capture time is an immutable frame fact carried by the permit. Current
    // authorization time is sampled after acquiring the queue lock so lock
    // contention cannot admit an expired frame.
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
    runRx149TestHook(Rx149TestHookPoint::CaptureAuthorization);
#endif
    const uint64_t captureNow=nowUs();
    if(Rx149InputGateState::blocked(
           __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE))||
       !NativeP2PRx149DataInput::stillCurrent(permit,lease,captureNow)) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        add(RxRejected);
        return CaptureResult::Rejected;
    }
    // Expired scoped entries never block a fresh packet behind them. This is
    // a bounded fixed-ring compaction and performs no packet/KPI operation.
    for(size_t offset=0;offset<rx.count;) {
        const size_t index=(rx.head+offset)%QueueDepth;
        const auto &queued=rx.values[index];
        const bool old=queued.rx149PermitPresent&&
            (captureNow<queued.rx149Permit.capturedUs||
             captureNow>=queued.rx149Permit.deadlineUs);
        if(old) {
            Rx removed{};
            if(removeRxAt(offset,&removed))++expired;
        } else {
            ++offset;
        }
    }
    const bool authorityCurrent=
        !Rx149InputGateState::blocked(
            __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE))&&
        activeRx149LeaseValid&&
        activeRx149Version!=0&&sameRx149LeaseIdentity(activeRx149Lease,lease)&&
        sameRx149PermitIdentity(activeRx149Lease,permit)&&
        NativeP2PRx149DataInput::leaseCurrent(activeRx149Lease,captureNow)&&
        NativeP2PRx149DataInput::stillCurrent(
            permit,activeRx149Lease,captureNow);
    const bool current=authorityCurrent&&interfaceIncarnation!=0&&
        interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==generation&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0;
    item.interfaceIncarnation=interfaceIncarnation;
    item.rx149GuardVersion=activeRx149Version;
    const bool sequenceAvailable=rx149ReceiptSequence!=UINT64_MAX;
    const bool revisionAvailable=rx149ReceiptContentRevision!=UINT64_MAX;
    const bool spaceAvailable=rx.count<QueueDepth;
    const bool accepted=current&&sequenceAvailable&&revisionAvailable&&
        spaceAvailable;
    if(accepted) {
        item.rx149ReceiptSequence=++rx149ReceiptSequence;
        rx149Receipt=makeRx149Receipt(
            item,item.rx149ReceiptSequence,Rx149ReceiptCaptured);
        rx149Receipt.contentRevision=++rx149ReceiptContentRevision;
        (void)rx.push(item); // spaceAvailable was checked under this same lock
    } else if(current&&sequenceAvailable&&revisionAvailable) {
        item.rx149ReceiptSequence=++rx149ReceiptSequence;
        rx149Receipt=makeRx149Receipt(
            item,item.rx149ReceiptSequence,Rx149ReceiptQueueFull);
        rx149Receipt.contentRevision=++rx149ReceiptContentRevision;
    } else if(current) {
        // Sequence/revision exhaustion is terminal for this receipt stream.
        // Do not queue another data frame that could overwrite old evidence.
        rx149Receipt.schemaVersion=0;
    }
    set(RxPending,rx.count);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t index=0;index<expired;++index)add(RxRejected);
    if(accepted) {
        add(RxCaptured);
        return CaptureResult::Captured;
    }
    if(!current) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }
    if(!sequenceAvailable||!revisionAvailable) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }
    add(RxQueueFull);
    return CaptureResult::QueueFull;
}
namespace {
mbuf_t nextTxImpl(uint16_t sequence,uint64_t *token,
                  const DiscoveryTxSnapshot *expected,bool *consumed) {
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    (void)sequence;
    (void)expected;
    if(token)*token=0;
    if(consumed)*consumed=false;
    return nullptr;
#else
    if(consumed)*consumed=false;
    if(!bridgeLock()||!token||(expected&&!consumed))return nullptr;
    const bool discovery=expected!=nullptr;
    const uint64_t dequeueTime=nowUs();
    Tx item{};uint32_t currentGeneration=0;size_t selectedOffset=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    bool have=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        !inFlightToken&&tx.count;
    if(have&&discovery) {
        have=false;
        if(expected->generation==radioGeneration) {
            for(size_t offset=0;offset<tx.count;++offset) {
                const size_t index=(tx.head+offset)%QueueDepth;
                const Tx &candidate=tx.values[index];
                if(snapshotMatches(candidate,*expected)&&
                   discoveryAgeCurrent(candidate.born,dequeueTime)) {
                    selectedOffset=offset;
                    have=true;
                    break;
                }
            }
        }
    }
    if(have) {
        if(discovery)have=removeTxAt(selectedOffset,&item);
        else have=tx.pop(&item);
    }
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
                isStrictContinuityQm(observation);
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
#endif
}
}
mbuf_t nextTx(uint16_t sequence,uint64_t *token) {
    return nextTxImpl(sequence,token,nullptr,nullptr);
}
bool peekDiscoveryTx(uint32_t expectedPowerGeneration,
                     DiscoveryTxSnapshot *out) {
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    (void)expectedPowerGeneration;
    (void)out;
    return false;
#else
    if(!out||!expectedPowerGeneration||!bridgeLock())return false;
    const uint64_t now=nowUs();DiscoveryTxSnapshot candidate{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    bool valid=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==expectedPowerGeneration&&!inFlightToken&&tx.count;
    if(valid) {
        valid=false;
        for(size_t offset=0;offset<tx.count;++offset) {
            const size_t index=(tx.head+offset)%QueueDepth;
            const Tx &entry=tx.values[index];
            if(!entry.discoveryEligible||
               entry.discoveryClass!=static_cast<uint8_t>(
                   NativeAwdlData::MdnsQueryClass::QmMulticast)||
               entry.generation!=expectedPowerGeneration||
               !discoveryAgeCurrent(entry.born,now))
                continue;
            candidate=DiscoveryTxSnapshot{entry.token,entry.born,
                entry.generation,entry.discoveryClass,entry.discoveryEligible};
            valid=true;
            break;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!valid||candidate.generation!=expectedPowerGeneration||
       !discoveryAgeCurrent(candidate.bornUs,now))return false;
    *out=candidate;return true;
#endif
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
    revokeRx149DataInput();
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
Snapshot snapshot(){
    Snapshot s{};
    for(unsigned i=0;i<Count;++i)
        s.value[i]=__atomic_load_n(&counters[i],__ATOMIC_ACQUIRE);
    if(bridgeLock()) {
        auto irq=IOSimpleLockLockDisableInterrupt(lock);
        s.rx149Input=rx149Receipt;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
    }
    return s;
}
AttachTraceSnapshot attachSnapshot(){return attachTrace.snapshot();}
void noteResidentLookupResult(int result){attachTrace.noteResidentLookupResult(result);}
}
#endif
