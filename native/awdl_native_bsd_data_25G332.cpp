// SPDX-License-Identifier: GPL-2.0-only
// Actual BSD Ethernet/IPv6 -> Intel MPDU and Intel MPDU -> native awdl0 bridge.
// A packet is never looped back or counted as radio receipt by this module.
#ifndef ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
#define ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 0
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332) && \
    (!defined(ITL_NATIVE_AWDL_RESIDENT_25G332) || \
     !ITL_NATIVE_AWDL_RESIDENT_25G332 || \
     defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332) || \
     ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332)
#error "Discovery RX input requires the resident-only non-RX149/non-directed profile"
#endif
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332) && \
    (!defined(ITL_NATIVE_AWDL_RESIDENT_25G332) || !defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332))
#error "Reply Shadow requires the unchanged receive-only RX149 profile"
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 && \
    (!defined(ITL_NATIVE_AWDL_RESIDENT_25G332) || \
     !defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332) || \
     !ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332 || \
     defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332))
#error "Directed origin TX requires the RX149 resident profile without Reply Shadow"
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "awdl_native_bsd_data_25G332.hpp"
#include "awdl_bsd_packet_bridge.hpp"
#include "awdl_data_tx_observation.hpp"
#include "awdl_qm_no_known_answer.hpp"
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
#include <string.h>

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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
struct DiscoveryRx {
    uint16_t length=0;
    uint32_t generation=0;
    uint64_t interfaceIncarnation=0;
    uint64_t guardVersion=0;
    NativeAwdlDiscoveryRxInput::Permit permit{};
    uint8_t bytes[2048]{};
};
struct DiscoveryRetryEntry {
    bool valid=false;
    uint8_t source[6]{};
    uint8_t destination[6]{};
    uint8_t tid=0;
    uint16_t sequenceControl=0;
    uint64_t ownerSerial=0;
    uint64_t queryToken=0;
    uint64_t ifnetIncarnation=0;
};
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
struct DirectedRx {
    uint16_t length=0;
    uint32_t generation=0;
    uint64_t interfaceIncarnation=0;
    uint64_t guardVersion=0;
    uint64_t receiptSequence=0;
    NativeP2PDirectedDataRxInput::Permit permit{};
    bool exactOriginReplyCaptured=false;
    NativeAwdlDirectedOriginTx::Ticket originTicket{};
    NativeAwdlDirectedOriginTx::PacketIdentity originPacket{};
    uint8_t bytes[2048]{};
};
#endif
IOSimpleLock *lock;
uint32_t attachClaimed=0;
uint64_t interfaceIncarnation=0;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
uint32_t interfaceIndex=0;
#endif
AttachTraceLedger attachTrace;
Ring<Tx,QueueDepth> tx;
Ring<Rx,QueueDepth> rx;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
Ring<DiscoveryRx,QueueDepth> discoveryRx;
constexpr size_t DiscoveryRetryWindowCapacity=32;
DiscoveryRetryEntry discoveryRetryWindow[DiscoveryRetryWindowCapacity]{};
NativeAwdlDiscoveryRxInput::Lease activeDiscoveryRxLease{};
bool activeDiscoveryRxLeaseValid=false;
uint64_t activeDiscoveryRxVersion=0;
uint64_t discoveryOwnerSerialHighWater=0;
uint64_t discoveryQueryDoorbellHighWater=0;
uint32_t discoveryRxWorkers=0;
uint32_t discoveryRxTickets=0;
// The lock-free identity is encoded as sixteen reversible words. The lower
// 31 bits of admission hold live ticket count, bit 31 is END, and the upper
// 32 bits bind tickets to one published identity generation.
uint64_t discoveryFastSeq=0;
uint64_t discoveryFastIdentity[16]{};
uint64_t discoveryFastAdmission=0;
#endif
// Separate RX149 duplicate state from the AP's shared STA duplicate window.
// Entries are fixed-size and only touched under `lock`; a full current-owner
// table rejects/falls back instead of evicting an active peer.
constexpr size_t Rx149RetryWindowCapacity = 32;
struct Rx149RetryEntry {
    bool valid=false;
    uint8_t source[6]{};
    uint8_t destination[6]{};
    uint8_t tid=0;
    uint16_t sequence=0;
    uint64_t ownerSerial=0;
    uint64_t startUs=0;
    uint64_t interfaceIncarnation=0;
    NativeP2PRx149DataInput::Epochs epochs{};
};
Rx149RetryEntry rx149RetryWindow[Rx149RetryWindowCapacity]{};
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
Ring<DirectedRx,QueueDepth> directedRx;
// Mode 4 has a separate Retry domain from both STA and RX149 mode 2. These
// slots are protected by `lock` and become live only after a DirectedRx item
// was copied into the queue for the same owner and ifnet incarnation.
constexpr size_t DirectedRxRetryWindowCapacity = 32;
struct DirectedRxRetryEntry {
    bool valid=false;
    uint8_t source[6]{};
    uint8_t destination[6]{};
    uint8_t tid=0;
    uint16_t sequenceControl=0;
    uint64_t ownerSerial=0;
    uint64_t startUs=0;
    uint64_t interfaceIncarnation=0;
    NativeP2PDirectedDataRxInput::Epochs epochs{};
};
DirectedRxRetryEntry directedRxRetryWindow[DirectedRxRetryWindowCapacity]{};
#endif
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
NativeP2PDirectedDataRxInput::Lease activeDirectedRxLease{};
bool activeDirectedRxLeaseValid=false;
uint64_t activeDirectedRxVersion=0;
uint64_t directedRxOwnerSerialHighWater=0;
uint64_t directedRxReceiptSequence=0;
uint64_t directedRxReceiptContentRevision=0;
DirectedDataRxInputReceipt directedRxReceipt{};
DirectedDataExactReplyReceipt directedExactReplyReceipts[
    kDirectedDataExactReplySlots]{};
// Lock-free exact identity/fence used by canonical END.
uint64_t directedFastSeq=0;
uint64_t directedFastOwner=0;
uint64_t directedFastEpochPair0=0;
uint64_t directedFastEpochPair1=0;
uint64_t directedFastEndSeq=0;
#endif
Rx149InputGateState::Word rx149InputGateState=0;
Rx149CaptureDiagnostics::Ledger rx149CaptureLedger;
uint32_t rx149RecoveryPreparedFaultSerial=0;
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
NativeAwdlDirectedOriginTx::Ledger directedOriginGate;
mbuf_t directedOriginPacket=nullptr;
NativeAwdlDirectedOriginTx::PacketIdentity directedOriginPacketIdentity{};
uint32_t directedOriginOperations=0;
#endif
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
NativeAwdlReplyShadow::Ledger replyShadow;
uint32_t replyShadowOutputCalls=0;
NativeAwdlReplyShadow::Authority replyShadowAuthorityLocked() {
    NativeAwdlReplyShadow::Authority a{};
    a.lease=activeRx149Lease;a.version=activeRx149Version;
    a.incarnation=interfaceIncarnation;
    a.ready=interface&&activeRx149LeaseValid&&!closing&&!detached&&radio&&
        radioGeneration==a.lease.epochs.power&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        !Rx149InputGateState::blocked(__atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE));
    return a;
}
void maintainReplyShadowLocked(uint64_t now) {
    replyShadow.maintain(replyShadowAuthorityLocked(),now);
}
#endif
bool reserveRx149InputTicketFast() {
    return Rx149InputGateState::reserveTicket(&rx149InputGateState);
}
void releaseRx149InputTicketFast() {
    (void)Rx149InputGateState::releaseTicket(&rx149InputGateState);
}
IOSimpleLock *bridgeLock() {
    return __atomic_load_n(&lock,__ATOMIC_ACQUIRE);
}
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
constexpr uint64_t kDiscoveryFastEnded=uint64_t(1)<<31;
constexpr uint64_t kDiscoveryFastTicketMask=kDiscoveryFastEnded-1;
enum class DiscoveryFastState : uint8_t { Mismatch,Current,Ended };
uint64_t packDiscoveryMac(const uint8_t mac[6]) {
    uint64_t value=0;
    for(unsigned index=0;index<6;++index)
        value=(value<<8)|uint64_t(mac[index]);
    return value;
}
void discoveryIdentityWords(
    const NativeAwdlDiscoveryRxInput::Identity &identity,uint64_t out[16]) {
    out[0]=identity.ownerSerial;
    out[1]=identity.queryToken;
    out[2]=identity.queryDoorbellUs;
    out[3]=identity.peerIncarnation;
    out[4]=identity.psfRevision;
    out[5]=identity.mifRevision;
    out[6]=(uint64_t(identity.epochs.context)<<32)|identity.epochs.power;
    out[7]=(uint64_t(identity.epochs.station)<<32)|identity.epochs.roc;
    out[8]=identity.ifindex;
    out[9]=identity.ifnetIncarnation;
    out[10]=packDiscoveryMac(identity.sourceMac);
    out[11]=packDiscoveryMac(identity.localMac);
    out[12]=identity.rocStartUs;
    out[13]=identity.rocDeadlineUs;
    out[14]=identity.mccRevision;
    out[15]=identity.channel;
}
DiscoveryFastState discoveryFastState(
    const NativeAwdlDiscoveryRxInput::Identity &identity) {
    const uint64_t before=__atomic_load_n(&discoveryFastSeq,__ATOMIC_ACQUIRE);
    if(!before||(before&1u))return DiscoveryFastState::Mismatch;
    uint64_t expected[16]{};
    discoveryIdentityWords(identity,expected);
    for(unsigned index=0;index<16;++index) {
        if(__atomic_load_n(&discoveryFastIdentity[index],__ATOMIC_RELAXED)!=
           expected[index])
            return DiscoveryFastState::Mismatch;
    }
    const uint64_t after=__atomic_load_n(&discoveryFastSeq,__ATOMIC_ACQUIRE);
    if(before!=after||(after&1u))return DiscoveryFastState::Mismatch;
    const uint64_t admission=__atomic_load_n(&discoveryFastAdmission,
                                              __ATOMIC_ACQUIRE);
    const uint64_t generation=after>>1;
    if(!generation||(admission>>32)!=generation)
        return DiscoveryFastState::Mismatch;
    return (admission&kDiscoveryFastEnded)?DiscoveryFastState::Ended:
                                            DiscoveryFastState::Current;
}
bool markDiscoveryFastEnd(
    const NativeAwdlDiscoveryRxInput::Identity &identity) {
    const uint64_t before=__atomic_load_n(&discoveryFastSeq,__ATOMIC_ACQUIRE);
    if(!before||(before&1u))return false;
    uint64_t expectedWords[16]{};
    discoveryIdentityWords(identity,expectedWords);
    for(unsigned index=0;index<16;++index) {
        if(__atomic_load_n(&discoveryFastIdentity[index],__ATOMIC_RELAXED)!=
           expectedWords[index])
            return false;
    }
    const uint64_t after=__atomic_load_n(&discoveryFastSeq,__ATOMIC_ACQUIRE);
    if(before!=after||(after&1u))return false;
    const uint64_t generation=after>>1;
    uint64_t admission=__atomic_load_n(&discoveryFastAdmission,
                                        __ATOMIC_ACQUIRE);
    if(!generation||(admission>>32)!=generation)return false;
    for(;;) {
        if((admission&kDiscoveryFastEnded)!=0)return true;
        if((admission>>32)!=generation)return false;
        const uint64_t ended=admission|kDiscoveryFastEnded;
        if(__atomic_compare_exchange_n(&discoveryFastAdmission,&admission,
                ended,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            return true;
    }
}
bool reserveDiscoveryFastTicket(
    const NativeAwdlDiscoveryRxInput::Identity &identity,
    uint32_t *generationOut) {
    if(generationOut)*generationOut=0;
    if(discoveryFastState(identity)!=DiscoveryFastState::Current)
        return false;
    const uint64_t sequence=__atomic_load_n(&discoveryFastSeq,
                                             __ATOMIC_ACQUIRE);
    const uint64_t generation=sequence>>1;
    if(!generation||generation>UINT32_MAX)return false;
    uint64_t admission=__atomic_load_n(&discoveryFastAdmission,
                                        __ATOMIC_ACQUIRE);
    for(;;) {
        if((admission>>32)!=generation||
           (admission&kDiscoveryFastEnded)!=0||
           (admission&kDiscoveryFastTicketMask)==
                kDiscoveryFastTicketMask)
            return false;
        if(__atomic_compare_exchange_n(&discoveryFastAdmission,&admission,
                admission+1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
            if(generationOut)*generationOut=uint32_t(generation);
            return true;
        }
    }
}
void releaseDiscoveryFastTicket(uint32_t generation) {
    if(!generation)return;
    uint64_t admission=__atomic_load_n(&discoveryFastAdmission,
                                        __ATOMIC_ACQUIRE);
    for(;;) {
        if((admission>>32)!=generation||
           (admission&kDiscoveryFastTicketMask)==0)
            return;
        const uint64_t released=admission-1u;
        if(__atomic_compare_exchange_n(&discoveryFastAdmission,&admission,
                released,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            return;
    }
}
bool publishDiscoveryFastIdentityLocked(
    const NativeAwdlDiscoveryRxInput::Identity &identity) {
    const uint64_t prior=__atomic_load_n(&discoveryFastSeq,__ATOMIC_RELAXED);
    if((prior&1u)!=0||prior>UINT64_MAX-2u) {
        __atomic_store_n(&discoveryFastSeq,UINT64_MAX&~uint64_t(1),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&discoveryFastAdmission,uint64_t(0),
                         __ATOMIC_RELEASE);
        return false;
    }
    const uint64_t generation=(prior>>1)+1u;
    if(!generation||generation>UINT32_MAX) {
        __atomic_store_n(&discoveryFastSeq,UINT64_MAX&~uint64_t(1),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&discoveryFastAdmission,uint64_t(0),
                         __ATOMIC_RELEASE);
        return false;
    }
    const uint64_t odd=(generation<<1)-1u;
    const uint64_t stable=generation<<1;
    __atomic_store_n(&discoveryFastSeq,odd,__ATOMIC_RELEASE);
    uint64_t words[16]{};
    discoveryIdentityWords(identity,words);
    for(unsigned index=0;index<16;++index)
        __atomic_store_n(&discoveryFastIdentity[index],words[index],
                         __ATOMIC_RELAXED);
    __atomic_store_n(&discoveryFastAdmission,generation<<32,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&discoveryFastSeq,stable,__ATOMIC_RELEASE);
    return true;
}
void clearDiscoveryRetryWindowLocked() {
    memset(discoveryRetryWindow,0,sizeof(discoveryRetryWindow));
}
void clearDiscoveryQueueLocked() {
    discoveryRx.head=discoveryRx.tail=discoveryRx.count=0;
    memset(discoveryRx.values,0,sizeof(discoveryRx.values));
}
size_t removeDiscoveryRxAt(size_t offset,DiscoveryRx *out) {
    if(!out||offset>=discoveryRx.count)return 0;
    const size_t index=(discoveryRx.head+offset)%QueueDepth;
    *out=discoveryRx.values[index];
    for(size_t current=offset;current+1<discoveryRx.count;++current) {
        const size_t destination=(discoveryRx.head+current)%QueueDepth;
        const size_t source=(discoveryRx.head+current+1)%QueueDepth;
        discoveryRx.values[destination]=discoveryRx.values[source];
    }
    discoveryRx.tail=(discoveryRx.tail+QueueDepth-1)%QueueDepth;
    discoveryRx.values[discoveryRx.tail]=DiscoveryRx{};
    --discoveryRx.count;
    return 1;
}
void revokeDiscoveryRxLocked() {
    if(activeDiscoveryRxLeaseValid)
        (void)markDiscoveryFastEnd(activeDiscoveryRxLease.identity);
    activeDiscoveryRxLeaseValid=false;
    activeDiscoveryRxLease=NativeAwdlDiscoveryRxInput::Lease{};
    clearDiscoveryRetryWindowLocked();
    clearDiscoveryQueueLocked();
    if(activeDiscoveryRxVersion!=UINT64_MAX)++activeDiscoveryRxVersion;
}
bool activateDiscoveryRxLocked(
    const NativeAwdlDiscoveryRxInput::Lease &lease,
    const NativeAwdlDiscoveryRxInput::MainGate &gate,uint64_t now) {
    const auto &identity=lease.identity;
    if(!NativeAwdlDiscoveryRxInput::leaseCurrent(lease,gate,now)||
       !NativeAwdlDiscoveryRxInput::sameLeaseIdentity(identity,gate.identity)||
       !NativeAwdlDiscoveryRxInput::validIdentity(identity)||
       !interface||closing||detached||!radio||interfaceIncarnation==0||
       interfaceIndex!=identity.ifindex||
       identity.ifnetIncarnation!=interfaceIncarnation||
       memcmp(identity.localMac,own,sizeof(own))!=0||
       __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)!=0||
       __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)==0||
       radioGeneration!=identity.epochs.power||
       Rx149InputGateState::blocked(__atomic_load_n(
           &rx149InputGateState,__ATOMIC_ACQUIRE)))
        return false;
    if(activeDiscoveryRxLeaseValid&&
       NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
           activeDiscoveryRxLease.identity,identity))
        return discoveryFastState(identity)==DiscoveryFastState::Current&&
            activeDiscoveryRxVersion!=0;
    if(identity.ownerSerial<discoveryOwnerSerialHighWater||
       (identity.ownerSerial==discoveryOwnerSerialHighWater&&
        identity.queryDoorbellUs<=discoveryQueryDoorbellHighWater)||
       activeDiscoveryRxVersion==UINT64_MAX)
        return false;
    if(activeDiscoveryRxLeaseValid)
        (void)markDiscoveryFastEnd(activeDiscoveryRxLease.identity);
    clearDiscoveryQueueLocked();
    clearDiscoveryRetryWindowLocked();
    ++activeDiscoveryRxVersion;
    if(!publishDiscoveryFastIdentityLocked(identity)) {
        activeDiscoveryRxLeaseValid=false;
        activeDiscoveryRxLease=NativeAwdlDiscoveryRxInput::Lease{};
        clearDiscoveryQueueLocked();
        return false;
    }
    activeDiscoveryRxLease=lease;
    activeDiscoveryRxLeaseValid=true;
    discoveryOwnerSerialHighWater=identity.ownerSerial;
    discoveryQueryDoorbellHighWater=identity.queryDoorbellUs;
    return true;
}
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
uint64_t packDirectedEpochs(uint32_t high,uint32_t low) {
    return (uint64_t(high)<<32)|uint64_t(low);
}
void publishDirectedFastIdentityLocked(
    const NativeP2PDirectedDataRxInput::Lease &lease) {
    const uint64_t prior=__atomic_load_n(&directedFastSeq,__ATOMIC_RELAXED);
    if(prior>UINT64_MAX-2u) {
        __atomic_store_n(&directedFastOwner,uint64_t(0),__ATOMIC_RELAXED);
        __atomic_store_n(&directedFastEpochPair0,uint64_t(0),__ATOMIC_RELAXED);
        __atomic_store_n(&directedFastEpochPair1,uint64_t(0),__ATOMIC_RELAXED);
        __atomic_store_n(&directedFastEndSeq,uint64_t(0),__ATOMIC_RELAXED);
        __atomic_store_n(&directedFastSeq,UINT64_MAX&~uint64_t(1),
                         __ATOMIC_RELEASE);
        return;
    }
    const uint64_t odd=prior+1u;
    const uint64_t stable=prior+2u;
    __atomic_store_n(&directedFastSeq,odd,__ATOMIC_RELEASE);
    __atomic_store_n(&directedFastEndSeq,uint64_t(0),__ATOMIC_RELAXED);
    __atomic_store_n(&directedFastOwner,lease.ownerSerial,__ATOMIC_RELAXED);
    __atomic_store_n(&directedFastEpochPair0,
        packDirectedEpochs(lease.epochs.context,lease.epochs.power),
        __ATOMIC_RELAXED);
    __atomic_store_n(&directedFastEpochPair1,
        packDirectedEpochs(lease.epochs.station,lease.epochs.roc),
        __ATOMIC_RELAXED);
    __atomic_store_n(&directedFastSeq,stable,__ATOMIC_RELEASE);
}
enum class DirectedFastLeaseState : uint8_t { Mismatch,Current,Ended };
NativeP2PDirectedDataRxInput::Epochs directedRxEpochs(
    const NativeAwdlDirectedOriginTx::Epochs &epochs) {
    return {epochs.context,epochs.power,epochs.station,epochs.roc};
}
bool sameDirectedOriginEpochs(
    const NativeAwdlDirectedOriginTx::Epochs &origin,
    const NativeP2PDirectedDataRxInput::Epochs &rx) {
    return origin.context==rx.context&&origin.power==rx.power&&
        origin.station==rx.station&&origin.roc==rx.roc;
}
DirectedFastLeaseState directedFastLeaseState(
    uint64_t ownerSerial,
    const NativeP2PDirectedDataRxInput::Epochs &epochs) {
    const uint64_t before=__atomic_load_n(&directedFastSeq,__ATOMIC_ACQUIRE);
    if(!before||(before&1u))return DirectedFastLeaseState::Mismatch;
    const uint64_t owner=__atomic_load_n(&directedFastOwner,__ATOMIC_RELAXED);
    const uint64_t pair0=__atomic_load_n(&directedFastEpochPair0,
                                          __ATOMIC_RELAXED);
    const uint64_t pair1=__atomic_load_n(&directedFastEpochPair1,
                                          __ATOMIC_RELAXED);
    const uint64_t after=__atomic_load_n(&directedFastSeq,__ATOMIC_ACQUIRE);
    if(before!=after||owner!=ownerSerial||
       pair0!=packDirectedEpochs(epochs.context,epochs.power)||
       pair1!=packDirectedEpochs(epochs.station,epochs.roc))
        return DirectedFastLeaseState::Mismatch;
    const uint64_t ended=__atomic_load_n(&directedFastEndSeq,
                                          __ATOMIC_ACQUIRE);
    return ended==after?DirectedFastLeaseState::Ended:
                        DirectedFastLeaseState::Current;
}
bool markDirectedFastEnd(uint64_t ownerSerial,
    const NativeP2PDirectedDataRxInput::Epochs &epochs) {
    const uint64_t before=__atomic_load_n(&directedFastSeq,__ATOMIC_ACQUIRE);
    if(!before||(before&1u))return false;
    const uint64_t owner=__atomic_load_n(&directedFastOwner,__ATOMIC_RELAXED);
    const uint64_t pair0=__atomic_load_n(&directedFastEpochPair0,
                                          __ATOMIC_RELAXED);
    const uint64_t pair1=__atomic_load_n(&directedFastEpochPair1,
                                          __ATOMIC_RELAXED);
    const uint64_t after=__atomic_load_n(&directedFastSeq,__ATOMIC_ACQUIRE);
    if(before!=after||owner!=ownerSerial||
       pair0!=packDirectedEpochs(epochs.context,epochs.power)||
       pair1!=packDirectedEpochs(epochs.station,epochs.roc))
        return false;
    __atomic_store_n(&directedFastEndSeq,after,__ATOMIC_RELEASE);
    return true;
}
void updateExactReplyReceiptLocked(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    const NativeAwdlDirectedOriginTx::PacketIdentity &identity) {
    using namespace NativeAwdlDirectedOriginTx;
    if(identity.slot>=kDirectedDataExactReplySlots||
       directedOriginGate.request().packetCount!=kMaximumPackets)
        return;
    ExactReplyReceipt proof{};
    if(!directedOriginGate.exactReplyReceipt(
           ticket,identity.packetSerial,&proof))return;
    auto &receipt=directedExactReplyReceipts[identity.slot];
    receipt=DirectedDataExactReplyReceipt{};
    receipt.present=1;
    receipt.captured=proof.captured?1u:0u;
    receipt.delivered=proof.delivered?1u:0u;
    receipt.valid=proof.valid?1u:0u;
    receipt.slot=proof.slot;
    receipt.ticketSerial=proof.ticketSerial;
    receipt.packetSerial=proof.packetSerial;
    receipt.ownerSerial=proof.ownerSerial;
    receipt.runSerial=proof.runSerial;
    receipt.ifindex=proof.ifindex;
    receipt.interfaceIncarnation=proof.interfaceIncarnation;
    receipt.contextGeneration=proof.epochs.context;
    receipt.powerGeneration=proof.epochs.power;
    receipt.stationGeneration=proof.epochs.station;
    receipt.rocGeneration=proof.epochs.roc;
    receipt.doorbellUs=proof.doorbellUs;
    receipt.captureUs=proof.captureUs;
    receipt.inputUs=proof.inputUs;
    if(directedRxReceiptContentRevision==UINT64_MAX) {
        directedRxReceipt.schemaVersion=0;
        return;
    }
    directedRxReceipt.contentRevision=++directedRxReceiptContentRevision;
}
#endif
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
bool acceptsDirectedDataRx(const NativeAwdlData::PacketView &packet,
                           const uint8_t own[6],const uint8_t peer[6]) {
    return acceptsRx149(packet,own)&&validUnicastAddress(peer)&&
        memcmp(packet.sourceAddress,peer,6)==0;
}
#endif
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
bool removeDirectedRxAt(size_t offset,DirectedRx *removed) {
    if(!removed||offset>=directedRx.count)return false;
    const size_t selected=(directedRx.head+offset)%QueueDepth;
    *removed=directedRx.values[selected];
    for(size_t index=offset;index+1<directedRx.count;++index) {
        const size_t destination=(directedRx.head+index)%QueueDepth;
        const size_t source=(directedRx.head+index+1)%QueueDepth;
        directedRx.values[destination]=directedRx.values[source];
    }
    const size_t last=(directedRx.head+directedRx.count-1)%QueueDepth;
    directedRx.values[last]=DirectedRx{};
    directedRx.tail=last;
    --directedRx.count;
    return true;
}
bool sameDirectedRxPermitIdentity(
    const NativeP2PDirectedDataRxInput::Lease &lease,
    const NativeP2PDirectedDataRxInput::Permit &permit);
void recordDirectedRxReceiptLocked(const DirectedRx &item,uint32_t disposition,
    uint64_t inputUs,uint32_t decodedCount,bool inputPresent,int inputResult,
    uint64_t inputCompletedUs=0) {
    if(item.exactOriginReplyCaptured) {
        // ifnet_input() runs without the BSD lock. Keep its completion time
        // as the input fact, but resample authority and time after reacquiring
        // the lock so lock wait cannot carry a proof past END or the ROC.
        const uint64_t commitNowUs=nowUs();
        const bool delivered=inputPresent&&inputResult==0&&
            inputCompletedUs!=0&&inputCompletedUs>=item.permit.capturedUs&&
            inputCompletedUs<item.originTicket.deadlineUs&&
            commitNowUs>=inputCompletedUs&&
            commitNowUs<item.originTicket.deadlineUs&&
            __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
            !closing&&!detached&&radio&&interface&&
            radioGeneration==item.originTicket.epochs.power&&
            __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
            !Rx149InputGateState::blocked(__atomic_load_n(
                &rx149InputGateState,__ATOMIC_ACQUIRE))&&
            activeDirectedRxLeaseValid&&
            item.guardVersion==activeDirectedRxVersion&&
            item.interfaceIncarnation==interfaceIncarnation&&
            activeDirectedRxLease.ownerSerial==item.permit.ownerSerial&&
            activeDirectedRxLease.startUs==item.permit.startUs&&
            activeDirectedRxLease.deadlineUs==item.permit.leaseDeadlineUs&&
            NativeP2PDirectedDataRxInput::sameEpochs(
                activeDirectedRxLease.epochs,item.permit.epochs)&&
            sameDirectedRxPermitIdentity(activeDirectedRxLease,item.permit)&&
            NativeP2PDirectedDataRxInput::leaseCurrent(
                activeDirectedRxLease,commitNowUs)&&
            directedFastLeaseState(activeDirectedRxLease.ownerSerial,
                activeDirectedRxLease.epochs)==DirectedFastLeaseState::Current;
        if(delivered) {
            // This is the linearization point for an exact reply. Re-read the
            // no-lock END/close fences immediately before changing the ledger.
            const bool commitFenceCurrent=
                directedFastLeaseState(activeDirectedRxLease.ownerSerial,
                    activeDirectedRxLease.epochs)==
                        DirectedFastLeaseState::Current&&
                __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
                !Rx149InputGateState::blocked(__atomic_load_n(
                    &rx149InputGateState,__ATOMIC_ACQUIRE));
            const bool committed=directedOriginGate.recordExactReplyDelivered(
                item.originTicket,item.originPacket,item.permit.capturedUs,
                inputCompletedUs,commitNowUs,
                activeDirectedRxLease.epochs.power,interfaceIncarnation,
                commitFenceCurrent);
            const bool stillCurrent=directedFastLeaseState(
                activeDirectedRxLease.ownerSerial,
                activeDirectedRxLease.epochs)==DirectedFastLeaseState::Current&&
                __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
                !Rx149InputGateState::blocked(__atomic_load_n(
                    &rx149InputGateState,__ATOMIC_ACQUIRE))&&
                !closing&&!detached&&radio&&interface&&
                radioGeneration==item.originTicket.epochs.power&&
                __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0;
            if(committed&&!stillCurrent)
                (void)directedOriginGate.invalidateExactReplyAfterEnd(
                    item.originTicket,item.originPacket);
        }
        updateExactReplyReceiptLocked(item.originTicket,item.originPacket);
    }
    if(!item.receiptSequence||
       directedRxReceipt.sequence!=item.receiptSequence)
        return;
    if(directedRxReceiptContentRevision==UINT64_MAX) {
        directedRxReceipt.schemaVersion=0;
        return;
    }
    auto &receipt=directedRxReceipt;
    receipt.disposition=disposition;
    receipt.contentRevision=++directedRxReceiptContentRevision;
    receipt.ownerSerial=item.permit.ownerSerial;
    receipt.interfaceIncarnation=item.interfaceIncarnation;
    receipt.contextGeneration=item.permit.epochs.context;
    receipt.powerGeneration=item.permit.epochs.power;
    receipt.stationGeneration=item.permit.epochs.station;
    receipt.rocGeneration=item.permit.epochs.roc;
    receipt.captureUs=item.permit.capturedUs;
    receipt.inputUs=inputUs;
    receipt.startUs=item.permit.startUs;
    receipt.deadlineUs=item.permit.deadlineUs;
    receipt.ieeeChannel=item.permit.ieeeChannel;
    receipt.macIndexPresent=1;
    receipt.macIndex=item.permit.macIndex;
    receipt.macPhyDecodeMode=item.permit.decodeMode;
    receipt.originalRxStatus=item.permit.originalRawStatus;
    receipt.mpduLength=item.length;
    receipt.decodedIpv6Count=decodedCount;
    receipt.ifnetInputResultPresent=inputPresent?1u:0u;
    receipt.ifnetInputResult=inputResult;
}
bool sameDirectedRxLeaseIdentity(
    const NativeP2PDirectedDataRxInput::Lease &left,
    const NativeP2PDirectedDataRxInput::Lease &right) {
    return NativeP2PDirectedDataRxInput::sameLeaseIdentity(left,right);
}
bool sameDirectedRxPermitIdentity(
    const NativeP2PDirectedDataRxInput::Lease &lease,
    const NativeP2PDirectedDataRxInput::Permit &permit) {
    return NativeP2PDirectedDataRxInput::samePermitIdentity(lease,permit);
}
bool matchExactOriginReplyLocked(
    const NativeP2PDirectedDataRxInput::Lease &lease,
    const NativeP2PDirectedDataRxInput::Permit &permit,
    const NativeAwdlData::PacketView &packet,uint64_t captureUs,
    NativeAwdlDirectedOriginTx::Ticket *outTicket,
    NativeAwdlDirectedOriginTx::PacketIdentity *outIdentity) {
    using namespace NativeAwdlDirectedOriginTx;
    if(outTicket)*outTicket=Ticket{};
    if(outIdentity)*outIdentity=PacketIdentity{};
    if(!outTicket||!outIdentity||!interface||!activeDirectedRxLeaseValid||
       directedFastLeaseState(lease.ownerSerial,lease.epochs)!=
           DirectedFastLeaseState::Current)
        return false;
    const Ticket ticket=directedOriginGate.ticket();
    const OpenRequest &request=directedOriginGate.request();
    if(request.packetCount!=kMaximumPackets||
       ticket.ownerSerial!=lease.ownerSerial||
       ticket.rocStartUs!=lease.startUs||ticket.deadlineUs!=lease.deadlineUs||
       !sameDirectedOriginEpochs(ticket.epochs,lease.epochs)||
       ticket.interfaceIncarnation!=interfaceIncarnation||
       ticket.ifindex!=ifnet_index(interface)||
       ticket.epochs.power!=radioGeneration||
       memcmp(ticket.sourceMac,own,6)||memcmp(lease.localMac,own,6)||
       memcmp(request.peerMac,lease.peerMac,6)||
       memcmp(permit.peerMac,request.peerMac,6)||
       memcmp(permit.localMac,ticket.sourceMac,6)||
       !sameDirectedRxPermitIdentity(lease,permit)||
       captureUs<ticket.rocStartUs||captureUs>=ticket.deadlineUs)
        return false;
    uint8_t slot=0xff;
    if(validateExactReply(request,ticket.sourceMac,request.peerMac,
                          packet,&slot)!=Reason::None)
        return false;
    PacketIdentity identity{};
    if(!directedOriginGate.packetIdentity(ticket,slot,&identity)||
       !directedOriginGate.recordExactReplyCaptured(ticket,identity,
           captureUs,captureUs,radioGeneration,interfaceIncarnation))
        return false;
    *outTicket=ticket;
    *outIdentity=identity;
    updateExactReplyReceiptLocked(ticket,identity);
    return true;
}
void clearDirectedRxRetryWindowLocked() {
    memset(directedRxRetryWindow,0,sizeof(directedRxRetryWindow));
}
bool sameDirectedRxRetryOwner(const DirectedRxRetryEntry &entry,
    const NativeP2PDirectedDataRxInput::Permit &permit,
    uint64_t incarnation) {
    return entry.valid&&entry.ownerSerial==permit.ownerSerial&&
        entry.startUs==permit.startUs&&
        entry.interfaceIncarnation==incarnation&&
        NativeP2PDirectedDataRxInput::sameEpochs(entry.epochs,permit.epochs);
}
int findDirectedRxRetrySlotLocked(
    const NativeP2PDirectedDataRxInput::Permit &permit,uint64_t incarnation,
    const uint8_t source[6],const uint8_t destination[6],uint8_t tid,
    uint16_t sequenceControl,bool retry,bool *duplicate) {
    if(duplicate)*duplicate=false;
    int freeOrStale=-1;
    for(size_t index=0;index<DirectedRxRetryWindowCapacity;++index) {
        const auto &entry=directedRxRetryWindow[index];
        if(!entry.valid) {
            if(freeOrStale<0)freeOrStale=int(index);
            continue;
        }
        if(!sameDirectedRxRetryOwner(entry,permit,incarnation)) {
            if(freeOrStale<0)freeOrStale=int(index);
            continue;
        }
        if(entry.tid==tid&&memcmp(entry.source,source,6)==0&&
           memcmp(entry.destination,destination,6)==0) {
            if(retry&&entry.sequenceControl==sequenceControl&&duplicate)
                *duplicate=true;
            return int(index);
        }
    }
    return freeOrStale;
}
void commitDirectedRxRetrySlotLocked(size_t slot,
    const NativeP2PDirectedDataRxInput::Permit &permit,uint64_t incarnation,
    const uint8_t source[6],const uint8_t destination[6],uint8_t tid,
    uint16_t sequenceControl) {
    if(slot>=DirectedRxRetryWindowCapacity)return;
    auto &entry=directedRxRetryWindow[slot];
    entry=DirectedRxRetryEntry{};
    entry.valid=true;
    memcpy(entry.source,source,sizeof(entry.source));
    memcpy(entry.destination,destination,sizeof(entry.destination));
    entry.tid=tid;
    entry.sequenceControl=sequenceControl;
    entry.ownerSerial=permit.ownerSerial;
    entry.startUs=permit.startUs;
    entry.interfaceIncarnation=incarnation;
    entry.epochs=permit.epochs;
}
size_t removeDirectedRxItemsLocked(bool all,uint64_t version,
    uint64_t ownerSerial,const NativeP2PDirectedDataRxInput::Epochs *epochs,
    uint64_t nowUsValue) {
    size_t removedCount=0;
    for(size_t offset=0;offset<directedRx.count;) {
        const size_t index=(directedRx.head+offset)%QueueDepth;
        const DirectedRx &item=directedRx.values[index];
        const bool match=all||(item.guardVersion==version&&
            item.permit.ownerSerial==ownerSerial&&epochs&&
            NativeP2PDirectedDataRxInput::sameEpochs(item.permit.epochs,*epochs));
        if(match) {
            DirectedRx removed{};
            if(removeDirectedRxAt(offset,&removed)) {
                recordDirectedRxReceiptLocked(removed,
                    DirectedDataRxReceiptStaleOrInvalid,nowUsValue,0,false,0);
                ++removedCount;
            }
        } else {
            ++offset;
        }
    }
    set(DirectedRxPending,directedRx.count);
    return removedCount;
}
bool activateDirectedRxLeaseLocked(
    const NativeP2PDirectedDataRxInput::Lease &lease,size_t *discardedCount,
    uint64_t nowUsValue) {
    if(discardedCount)*discardedCount=0;
    if(Rx149InputGateState::blocked(
           __atomic_load_n(&rx149InputGateState,__ATOMIC_ACQUIRE))||
       !NativeP2PDirectedDataRxInput::leaseCurrent(lease,nowUsValue)||
       memcmp(lease.localMac,own,sizeof(own))!=0||
       interfaceIncarnation==0||!interface||closing||detached||!radio||
       radioGeneration!=lease.epochs.power||
       __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)!=0||
       __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)==0)
        return false;
    if(!activeDirectedRxLeaseValid||
       !sameDirectedRxLeaseIdentity(activeDirectedRxLease,lease)) {
        if(lease.ownerSerial<=directedRxOwnerSerialHighWater)
            return false;
        if(activeDirectedRxVersion==UINT64_MAX) {
            activeDirectedRxLeaseValid=false;
            if(discardedCount)
                *discardedCount=removeDirectedRxItemsLocked(true,0,0,nullptr,
                                                             nowUsValue);
            else
                (void)removeDirectedRxItemsLocked(true,0,0,nullptr,nowUsValue);
            return false;
        }
        ++activeDirectedRxVersion;
        if(discardedCount)
            *discardedCount=removeDirectedRxItemsLocked(true,0,0,nullptr,
                                                         nowUsValue);
        else
            (void)removeDirectedRxItemsLocked(true,0,0,nullptr,nowUsValue);
        clearDirectedRxRetryWindowLocked();
        activeDirectedRxLease=lease;
        activeDirectedRxLeaseValid=true;
        directedRxOwnerSerialHighWater=lease.ownerSerial;
        publishDirectedFastIdentityLocked(lease);
        return true;
    }
    activeDirectedRxLease=lease;
    return true;
}
size_t revokeDirectedRxLeaseLocked(
    uint64_t ownerSerial,const NativeP2PDirectedDataRxInput::Epochs *epochs,
    uint64_t nowUsValue) {
    if(!ownerSerial||!epochs||
       !NativeP2PDirectedDataRxInput::validEpochs(*epochs))
        return 0;
    if(activeDirectedRxLeaseValid) {
        if(activeDirectedRxLease.ownerSerial>ownerSerial)return 0;
        if(activeDirectedRxLease.ownerSerial==ownerSerial&&
           !NativeP2PDirectedDataRxInput::sameEpochs(
               activeDirectedRxLease.epochs,*epochs))return 0;
        if(activeDirectedRxLease.ownerSerial==ownerSerial) {
            (void)markDirectedFastEnd(ownerSerial,*epochs);
            activeDirectedRxLeaseValid=false;
            activeDirectedRxLease=NativeP2PDirectedDataRxInput::Lease{};
            clearDirectedRxRetryWindowLocked();
            if(ownerSerial>directedRxOwnerSerialHighWater)
                directedRxOwnerSerialHighWater=ownerSerial;
            if(activeDirectedRxVersion==UINT64_MAX)
                return removeDirectedRxItemsLocked(true,0,0,nullptr,nowUsValue);
            ++activeDirectedRxVersion;
            return removeDirectedRxItemsLocked(false,activeDirectedRxVersion-1,
                ownerSerial,epochs,nowUsValue);
        }
        (void)removeDirectedRxItemsLocked(true,0,0,nullptr,nowUsValue);
        activeDirectedRxLeaseValid=false;
        activeDirectedRxLease=NativeP2PDirectedDataRxInput::Lease{};
        clearDirectedRxRetryWindowLocked();
    }
    if(ownerSerial<=directedRxOwnerSerialHighWater)return 0;
    directedRxOwnerSerialHighWater=ownerSerial;
    return removeDirectedRxItemsLocked(false,activeDirectedRxVersion,
                                        ownerSerial,epochs,nowUsValue);
}
void recordDirectedRxReceipt(const DirectedRx &item,uint32_t disposition,
    uint64_t inputUs,uint32_t decodedCount,bool inputPresent,int inputResult,
    uint64_t inputCompletedUs=0) {
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    recordDirectedRxReceiptLocked(item,disposition,inputUs,decodedCount,
                                  inputPresent,inputResult,inputCompletedUs);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
#endif
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
bool sameRx149RetryOwner(const Rx149RetryEntry &entry,
    const NativeP2PRx149DataInput::Permit &permit,
    uint64_t incarnation) {
    return entry.valid&&entry.ownerSerial==permit.ownerSerial&&
        entry.startUs==permit.startUs&&
        entry.interfaceIncarnation==incarnation&&
        NativeP2PRx149DataInput::sameEpochs(entry.epochs,permit.epochs);
}
void clearRx149RetryWindowLocked() {
    memset(rx149RetryWindow,0,sizeof(rx149RetryWindow));
}
int findRx149RetrySlotLocked(
    const NativeP2PRx149DataInput::Permit &permit,uint64_t incarnation,
    const uint8_t source[6],const uint8_t destination[6],uint8_t tid,
    uint16_t sequence,bool retry,
    bool *duplicate) {
    if(duplicate)*duplicate=false;
    int freeOrStale=-1;
    for(size_t index=0;index<Rx149RetryWindowCapacity;++index) {
        const auto &entry=rx149RetryWindow[index];
        if(!entry.valid) {
            if(freeOrStale<0)freeOrStale=int(index);
            continue;
        }
        if(!sameRx149RetryOwner(entry,permit,incarnation)) {
            if(freeOrStale<0)freeOrStale=int(index);
            continue;
        }
        if(entry.tid==tid&&memcmp(entry.source,source,6)==0&&
           memcmp(entry.destination,destination,6)==0) {
            if(retry&&entry.sequence==sequence) {
                if(duplicate)*duplicate=true;
                return int(index);
            }
            return int(index);
        }
    }
    return freeOrStale;
}
void commitRx149RetrySlotLocked(size_t slot,
    const NativeP2PRx149DataInput::Permit &permit,uint64_t incarnation,
    const uint8_t source[6],const uint8_t destination[6],uint8_t tid,
    uint16_t sequence) {
    if(slot>=Rx149RetryWindowCapacity)return;
    auto &entry=rx149RetryWindow[slot];
    entry=Rx149RetryEntry{};
    entry.valid=true;
    memcpy(entry.source,source,sizeof(entry.source));
    memcpy(entry.destination,destination,sizeof(entry.destination));
    entry.tid=tid;
    entry.sequence=sequence;
    entry.ownerSerial=permit.ownerSerial;
    entry.startUs=permit.startUs;
    entry.interfaceIncarnation=incarnation;
    entry.epochs=permit.epochs;
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
            clearRx149RetryWindowLocked();
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
        clearRx149RetryWindowLocked();
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
            clearRx149RetryWindowLocked();
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
        clearRx149RetryWindowLocked();
        activeRx149LeaseValid=false;
        activeRx149Lease=NativeP2PRx149DataInput::Lease{};
    }

    // Tombstone a terminal current owner even if its first authoritative
    // lease was never published (for example, MCC revokes before any frame).
    if(ownerSerial<=rx149OwnerSerialHighWater)
        return discarded;
    clearRx149RetryWindowLocked();
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
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
void observeReplyShadowOutput(ifnet_t dev,protocol_family_t family,mbuf_t packet) {
    auto stateLock=bridgeLock();if(!stateLock)return;
    auto irq=IOSimpleLockLockDisableInterrupt(stateLock);
    const uint64_t firstNow=nowUs();
    maintainReplyShadowLocked(firstNow);
    if(!replyShadow.current(replyShadowAuthorityLocked(),firstNow)) {
        IOSimpleLockUnlockEnableInterrupt(stateLock,irq);return;
    }
    if(dev!=interface||family!=AF_INET6||replyShadowOutputCalls==UINT32_MAX) {
        replyShadow.rejected(NativeAwdlReplyShadow::Reason::WrongAuthority);
        IOSimpleLockUnlockEnableInterrupt(stateLock,irq);return;
    }
    ++replyShadowOutputCalls; // close pins the ifnet through finalization/copy.
    IOSimpleLockUnlockEnableInterrupt(stateLock,irq);
    uint8_t bytes[NativeAwdlReplyShadow::kEthernetLength]{};
    bool shape=(mbuf_flags(packet)&MBUF_PKTHDR)!=0;
    size_t length=shape?mbuf_pkthdr_len(packet):0;
    shape=shape&&length==sizeof(bytes)&&mbuf_copydata(packet,0,length,bytes)==0&&
        bytes[12]==0x86&&bytes[13]==0xdd;
    // Never finalize unrelated L2/IPv4 or malformed packet shapes.
    if(shape) {
        mbuf_outbound_finalize(packet,AF_INET6,14); // outside spin lock
        length=mbuf_pkthdr_len(packet);
        shape=length==sizeof(bytes)&&mbuf_copydata(packet,0,length,bytes)==0;
    }
    irq=IOSimpleLockLockDisableInterrupt(stateLock);
    if(shape)(void)replyShadow.reply(replyShadowAuthorityLocked(),nowUs(),bytes,length);
    else replyShadow.rejected(NativeAwdlReplyShadow::Reason::FrameShape);
    --replyShadowOutputCalls;
    IOSimpleLockUnlockEnableInterrupt(stateLock,irq);
}
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
bool readLiveLinkLocal(ifnet_t dev,const uint8_t expected[16],
                       uint8_t actual[16]) {
    const uint32_t currentIfindex=dev?ifnet_index(dev):0;
    if(!dev||!expected||!actual||!currentIfindex)return false;
    ifaddr_t *addresses=nullptr;
    if(ifnet_get_address_list_family(dev,&addresses,AF_INET6)!=0||!addresses)
        return false;
    bool found=false;
    for(unsigned index=0;addresses[index];++index) {
        sockaddr_in6 value{};
        if(ifaddr_address(addresses[index],
              reinterpret_cast<sockaddr *>(&value),sizeof(value))!=0||
           value.sin6_family!=AF_INET6||
           value.sin6_addr.s6_addr[0]!=0xfe||
           (value.sin6_addr.s6_addr[1]&0xc0u)!=0x80u)
            continue;
        // Apple XNU stores scoped link-local addresses in KAME embedded form
        // in the address list returned through some KPIs. Accept only an
        // absent scope or the live interface's exact index, then compare the
        // canonical address. Never erase an unknown zone and turn it into a
        // match. The packet/wire validator deliberately does not use this.
        const uint16_t embeddedScope=static_cast<uint16_t>(
            (uint16_t(value.sin6_addr.s6_addr[2])<<8)|
             value.sin6_addr.s6_addr[3]);
        if((value.sin6_scope_id!=0&&value.sin6_scope_id!=currentIfindex)||
           (embeddedScope!=0&&embeddedScope!=currentIfindex))
            continue;
        uint8_t canonical[16];
        memcpy(canonical,value.sin6_addr.s6_addr,sizeof(canonical));
        canonical[2]=0;
        canonical[3]=0;
        if(!memcmp(canonical,expected,sizeof(canonical))) {
            memcpy(actual,canonical,sizeof(canonical));
            found=true;
            break;
        }
    }
    ifnet_free_address_list(addresses);
    return found;
}

bool directedOriginReadyLocked(ifnet_t dev) {
    return dev&&interface==dev&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0;
}

struct DirectedOriginPacketRetirement {
    mbuf_t packet=nullptr;
    NativeAwdlDirectedOriginTx::Ticket ticket{};
    NativeAwdlDirectedOriginTx::PacketIdentity identity{};
    bool queuedOwnership=false;
    bool operationPinned=false;
};

DirectedOriginPacketRetirement takeDirectedOriginPacketLocked() {
    DirectedOriginPacketRetirement retired{};
    retired.packet=directedOriginPacket;
    if(retired.packet&&directedOriginPacketIdentity.packetSerial) {
        retired.ticket=directedOriginGate.ticket();
        retired.identity=directedOriginPacketIdentity;
        retired.queuedOwnership=directedOriginGate.queuedPacketOwned(
            retired.ticket,retired.identity);
        // Keep the bridge resident through the lock-free free below. A pop
        // has already transitioned this identity to packetPopping and does
        // not pin a second time here.
        if(retired.queuedOwnership&&
           directedOriginOperations!=UINT32_MAX) {
            ++directedOriginOperations;
            retired.operationPinned=true;
        }
    }
    directedOriginPacket=nullptr;
    directedOriginPacketIdentity=
        NativeAwdlDirectedOriginTx::PacketIdentity{};
    return retired;
}

void freeDirectedOriginPacket(const DirectedOriginPacketRetirement &retired) {
    if(retired.packet)mbuf_freem(retired.packet);
    if(!retired.queuedOwnership)return;
    auto stateLock=bridgeLock();
    if(!stateLock)return;
    auto irq=IOSimpleLockLockDisableInterrupt(stateLock);
    (void)directedOriginGate.retireQueuedPacket(
        retired.ticket,retired.identity);
    if(retired.operationPinned&&directedOriginOperations)
        --directedOriginOperations;
    IOSimpleLockUnlockEnableInterrupt(stateLock,irq);
}
void freeDirectedOriginPacket(mbuf_t packet) {
    if(packet)mbuf_freem(packet);
}

errno_t directedOriginOutput(ifnet_t dev,protocol_family_t family,
                             mbuf_t *packet) {
    if(!packet||!*packet)return EINVAL;
    if(!bridgeLock())return EOPNOTSUPP;

    NativeAwdlDirectedOriginTx::Ticket ticket{};
    NativeAwdlDirectedOriginTx::OpenRequest request{};
    NativeAwdlDirectedOriginTx::PacketIdentity acceptedIdentity{};
    uint8_t ownAddress[6]{};
    uint8_t packetSlot=0xff;
    uint64_t incarnation=0;
    uint32_t generation=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    ticket=directedOriginGate.ticket();
    request=directedOriginGate.request();
    const uint64_t now=nowUs();
    const bool ready=directedOriginReadyLocked(dev)&&
        directedOriginGate.canAcceptOutput(ticket,now,true,radioGeneration,
                                           interfaceIncarnation)&&
        (request.packetCount!=2||directedFastLeaseState(
            ticket.ownerSerial,directedRxEpochs(ticket.epochs))==
                DirectedFastLeaseState::Current);
    if(!ready||directedOriginPacket||
       directedOriginOperations==UINT32_MAX) {
        directedOriginGate.noteRejected(
            directedOriginPacket?NativeAwdlDirectedOriginTx::Reason::QueueFull:
                                NativeAwdlDirectedOriginTx::Reason::WrongOwner);
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        add(TxRejected);
        return EOPNOTSUPP;
    }
    memcpy(ownAddress,own,sizeof(ownAddress));
    incarnation=interfaceIncarnation;
    generation=radioGeneration;
    ++directedOriginOperations; // close pins this output through finalize/copy.
    IOSimpleLockUnlockEnableInterrupt(lock,irq);

    NativeAwdlDirectedOriginTx::Reason reason=
        NativeAwdlDirectedOriginTx::Reason::PacketShape;
    uint8_t bytes[NativeAwdlDirectedOriginTx::kEthernetLength]{};
    uint8_t liveMac[6]{},liveIp[16]{};
    const bool liveContextMatches=
        ifnet_lladdr_copy_bytes(dev,liveMac,sizeof(liveMac))==0&&
        !memcmp(liveMac,ownAddress,sizeof(liveMac))&&
        ifnet_index(dev)==ticket.ifindex&&
        readLiveLinkLocal(dev,request.sourceIPv6,liveIp);
    size_t length=0;
    bool shape=liveContextMatches&&family==AF_INET6&&
        (mbuf_flags(*packet)&MBUF_PKTHDR)!=0;
    if(!liveContextMatches)
        reason=NativeAwdlDirectedOriginTx::Reason::WrongSource;
    if(shape) {
        length=mbuf_pkthdr_len(*packet);
        shape=length==sizeof(bytes)&&
            mbuf_copydata(*packet,0,length,bytes)==0;
    }
    if(shape) {
        reason=NativeAwdlDirectedOriginTx::validateEthernet(
            request,ownAddress,bytes,length,false,&packetSlot);
        shape=reason==NativeAwdlDirectedOriginTx::Reason::None;
    }
    if(shape) {
        // This may materialize deferred checksums; it must remain outside the
        // simple lock. The in-flight pin keeps detach/close from releasing the
        // interface until the final acceptance check has completed.
        mbuf_outbound_finalize(*packet,AF_INET6,14);
        shape=mbuf_pkthdr_len(*packet)==length&&
            mbuf_copydata(*packet,0,length,bytes)==0;
        if(shape) {
            uint8_t finalPacketSlot=0xff;
            reason=NativeAwdlDirectedOriginTx::validateEthernet(
                request,ownAddress,bytes,length,true,&finalPacketSlot);
            shape=reason==NativeAwdlDirectedOriginTx::Reason::None&&
                finalPacketSlot==packetSlot;
        } else {
            reason=NativeAwdlDirectedOriginTx::Reason::PacketShape;
        }
        if(shape) {
            const auto observation=NativeAwdlData::observeAwdlTxPacket(
                bytes,length,ownAddress);
            shape=observation.ipv6PacketWellFormed&&
                observation.sourceIsLinkLocal&&
                observation.udpChecksumStatus==
                    NativeAwdlData::UdpChecksumStatus::Valid&&
                observation.ethernetMulticastMappingMatches;
            if(!shape)reason=NativeAwdlDirectedOriginTx::Reason::UdpChecksum;
        }
    } else if(family!=AF_INET6) {
        reason=NativeAwdlDirectedOriginTx::Reason::PacketShape;
    }

    DirectedOriginPacketRetirement expired{};
    bool accepted=false;
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t finalNow=nowUs();
    const bool current=directedOriginReadyLocked(dev)&&
        radioGeneration==generation&&interfaceIncarnation==incarnation&&
        (request.packetCount!=2||directedFastLeaseState(
            ticket.ownerSerial,directedRxEpochs(ticket.epochs))==
                DirectedFastLeaseState::Current);
    if(shape&&current&&!directedOriginPacket) {
        accepted=directedOriginGate.acceptsOutput(ticket,packetSlot,
            finalNow,true,radioGeneration,interfaceIncarnation);
        if(accepted) {
            if(!directedOriginGate.packetIdentity(
                   ticket,packetSlot,&acceptedIdentity)) {
                (void)directedOriginGate.revoke(finalNow,
                    NativeAwdlDirectedOriginTx::Reason::WrongPacketIdentity);
                accepted=false;
            } else {
                directedOriginPacket=*packet;
                directedOriginPacketIdentity=acceptedIdentity;
                *packet=nullptr; // EJUSTRETURN transfers caller ownership once.
            }
        }
    } else {
        directedOriginGate.noteRejected(
            shape?NativeAwdlDirectedOriginTx::Reason::WrongOwner:reason);
    }
    if(directedOriginGate.expire(finalNow))
        expired=takeDirectedOriginPacketLocked();
    if(directedOriginOperations)--directedOriginOperations;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    freeDirectedOriginPacket(expired);
    if(accepted) {
        add(TxAccepted);
        return EJUSTRETURN;
    }
    add(TxRejected);
    return EOPNOTSUPP; // Every rejection preserves caller ownership.
}
#endif
errno_t output(void *,ifnet_t dev,protocol_family_t family,mbuf_t *packet) {
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    // The Test107 profile has one exact BSD-origin exception. No unrelated
    // traffic can enter the legacy 32-entry queue or nextTx path.
    (void)nextToken;
    (void)dataSequence;
    return directedOriginOutput(dev,family,packet);
#elif defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    // This isolated profile is receive-only for its entire lifetime. The
    // runtime experiment flag controls RX admission but can never open TX.
    (void)nextToken;
    (void)dataSequence;
    (void)dev;
    (void)family;
    if(!packet||!*packet)return EINVAL;
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    observeReplyShadowOutput(dev,family,*packet);
#endif
    add(TxRejected);
    return EOPNOTSUPP; // preserve caller ownership; Shadow may finalize checksums, never queue
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    DirectedOriginPacketRetirement retiredOrigin{};
#endif
    auto irq=IOSimpleLockLockDisableInterrupt(stateLock);
    detached=true;filter=nullptr;set(Detached,1);
    clearRx149RetryWindowLocked();
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
    interfaceIndex=0;
    revokeDiscoveryRxLocked();
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    activeDirectedRxLeaseValid=false;
    activeDirectedRxLease=NativeP2PDirectedDataRxInput::Lease{};
    clearDirectedRxRetryWindowLocked();
    if(activeDirectedRxVersion!=UINT64_MAX)++activeDirectedRxVersion;
    (void)removeDirectedRxItemsLocked(true,0,0,nullptr,nowUs());
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    (void)directedOriginGate.revoke(
        nowUs(),NativeAwdlDirectedOriginTx::Reason::InterfaceStopped);
    retiredOrigin=takeDirectedOriginPacketLocked();
#endif
    IOSimpleLockUnlockEnableInterrupt(stateLock,irq);
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    freeDirectedOriginPacket(retiredOrigin);
#endif
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
    const uint32_t liveIndex=ifnet_index(dev);
    if(!liveIndex) {
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
        interfaceIndex=liveIndex;
        revokeDiscoveryRxLocked();
#endif
        clearRx149RetryWindowLocked();
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
        clearDirectedRxRetryWindowLocked();
#endif
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
        if(interface==dev) {
            interface=nullptr;
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
            interfaceIndex=0;
            revokeDiscoveryRxLocked();
#endif
        }
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
bool readDiscoveryRxIfnetIdentity(DiscoveryRxIfnetIdentity *out) {
    if(!out||!bridgeLock())return false;
    *out=DiscoveryRxIfnetIdentity{};
    ifnet_t dev=nullptr;
    uint8_t expectedMac[6]{};
    uint64_t incarnation=0;
    uint32_t expectedIndex=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool available=interface&&!closing&&!detached&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        interfaceIncarnation!=0&&interfaceIndex!=0&&inputCalls!=UINT32_MAX&&
        discoveryRxWorkers!=UINT32_MAX;
    if(available) {
        dev=interface;
        incarnation=interfaceIncarnation;
        expectedIndex=interfaceIndex;
        memcpy(expectedMac,own,sizeof(expectedMac));
        ++inputCalls;
        ++discoveryRxWorkers;
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!available)return false;

    const uint32_t liveIndex=ifnet_index(dev);
    uint8_t liveMac[6]{};
    const bool addressRead=ifnet_lladdr_copy_bytes(
        dev,liveMac,sizeof(liveMac))==0;
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool current=interface==dev&&!closing&&!detached&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        interfaceIncarnation==incarnation&&interfaceIndex==expectedIndex&&
        liveIndex==expectedIndex&&addressRead&&
        memcmp(liveMac,expectedMac,sizeof(liveMac))==0&&
        memcmp(own,expectedMac,sizeof(own))==0;
    if(inputCalls)--inputCalls;
    if(discoveryRxWorkers)--discoveryRxWorkers;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!current)return false;
    out->ifindex=liveIndex;
    out->ifnetIncarnation=incarnation;
    memcpy(out->localMac,liveMac,sizeof(out->localMac));
    return true;
}
bool publishDiscoveryRxInputLease(
    const NativeAwdlDiscoveryRxInput::Lease &lease,
    const NativeAwdlDiscoveryRxInput::MainGate &gate) {
    if(!bridgeLock())return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool activated=activateDiscoveryRxLocked(lease,gate,nowUs());
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    return activated;
}
bool markDiscoveryRxEndFast(
    const NativeAwdlDiscoveryRxInput::Identity &identity) {
    if(!NativeAwdlDiscoveryRxInput::validIdentity(identity))return false;
    return markDiscoveryFastEnd(identity);
}
void revokeDiscoveryRxInput(
    const NativeAwdlDiscoveryRxInput::Identity &identity) {
    if(!NativeAwdlDiscoveryRxInput::validIdentity(identity))return;
    // END is visible before we wait for the queue lock. This closes the final
    // ticket race even when the ordinary lease cleanup is delayed.
    (void)markDiscoveryFastEnd(identity);
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    if(activeDiscoveryRxLeaseValid&&
       NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
           activeDiscoveryRxLease.identity,identity))
        revokeDiscoveryRxLocked();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
void revokeDiscoveryRxInput() {
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    revokeDiscoveryRxLocked();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
bool discoveryRxQuiescent() {
    if(!bridgeLock())return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t admission=__atomic_load_n(&discoveryFastAdmission,
                                              __ATOMIC_ACQUIRE);
    const bool quiescent=!activeDiscoveryRxLeaseValid&&
        discoveryRx.count==0&&discoveryRxTickets==0&&discoveryRxWorkers==0&&
        (admission&kDiscoveryFastTicketMask)==0;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    return quiescent;
}
CaptureResult captureDiscoveryRxData(
    const uint8_t *bytes,size_t length,bool protectedFrame,
    const NativeAwdlDiscoveryRxInput::Lease &lease,
    const NativeAwdlDiscoveryRxInput::MainGate &gate,
    const NativeAwdlDiscoveryRxInput::Permit &permit,uint32_t generation) {
    if(!bytes||!NativeAwdlData::isAwdlDataCandidate(bytes,length))
        return CaptureResult::NotAwdlDataCandidate;
    const auto &identity=lease.identity;
    if(length>2048||length<24||protectedFrame||!permit.valid||
       generation!=identity.epochs.power||
       memcmp(bytes+10,identity.sourceMac,6)!=0) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }
    NativeAwdlData::DecodedFrame parsed{};
    if(NativeAwdlData::decodeIpv6DataMpdu(bytes,length,&parsed)!=
            NativeAwdlData::Status::Ok||parsed.amsdu||
       parsed.packetCount!=1||
       memcmp(parsed.sourceAddress,identity.sourceMac,6)!=0||
       memcmp(parsed.packets[0].sourceAddress,identity.sourceMac,6)!=0||
       !acceptsRx(parsed.packets[0],identity.localMac)) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }
    const uint8_t retryTid=parsed.qosData?
        uint8_t(parsed.qosControl&0x0fu):uint8_t(16);
    const uint16_t retrySequenceControl=uint16_t(bytes[22])|
        (uint16_t(bytes[23])<<8);
    const bool retryBit=(bytes[1]&0x08u)!=0;
    if(!bridgeLock()) {
        add(RxRejected);
        return CaptureResult::Rejected;
    }

    DiscoveryRx item{};
    item.length=uint16_t(length);
    item.generation=generation;
    item.permit=permit;
    memcpy(item.bytes,bytes,length);
    size_t expired=0;
    bool accepted=false,duplicate=false,queueFull=false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t captureNow=nowUs();
    for(size_t offset=0;offset<discoveryRx.count;) {
        const size_t index=(discoveryRx.head+offset)%QueueDepth;
        const auto &queued=discoveryRx.values[index];
        const bool stale=captureNow<queued.permit.capturedUs||
            captureNow>=queued.permit.receiveDeadlineUs||
            !activeDiscoveryRxLeaseValid||
            queued.guardVersion!=activeDiscoveryRxVersion||
            !NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                queued.permit.identity,activeDiscoveryRxLease.identity);
        if(stale) {
            DiscoveryRx removed{};
            if(removeDiscoveryRxAt(offset,&removed))++expired;
        } else {
            ++offset;
        }
    }
    const bool authorityCurrent=
        discoveryFastState(identity)==DiscoveryFastState::Current&&
        !Rx149InputGateState::blocked(__atomic_load_n(
            &rx149InputGateState,__ATOMIC_ACQUIRE))&&
        activeDiscoveryRxLeaseValid&&activeDiscoveryRxVersion!=0&&
        NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
            activeDiscoveryRxLease.identity,identity)&&
        NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
            permit.identity,identity)&&
        NativeAwdlDiscoveryRxInput::leaseCurrent(
            activeDiscoveryRxLease,gate,captureNow)&&
        NativeAwdlDiscoveryRxInput::stillCurrent(
            permit,activeDiscoveryRxLease,gate,captureNow);
    const bool interfaceCurrent=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==generation&&generation==identity.epochs.power&&
        interfaceIncarnation==identity.ifnetIncarnation&&
        interfaceIndex==identity.ifindex&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        memcmp(identity.localMac,own,sizeof(own))==0;
    bool retryWindowFull=false;
    int retrySlot=-1;
    if(authorityCurrent&&interfaceCurrent) {
        int freeSlot=-1;
        for(size_t index=0;index<DiscoveryRetryWindowCapacity;++index) {
            const auto &entry=discoveryRetryWindow[index];
            if(!entry.valid) {
                if(freeSlot<0)freeSlot=int(index);
                continue;
            }
            const bool sameIdentity=entry.ownerSerial==identity.ownerSerial&&
                entry.queryToken==identity.queryToken&&
                entry.ifnetIncarnation==identity.ifnetIncarnation;
            if(!sameIdentity) {
                if(freeSlot<0)freeSlot=int(index);
                continue;
            }
            if(entry.tid==retryTid&&
               memcmp(entry.source,parsed.sourceAddress,6)==0&&
               memcmp(entry.destination,parsed.destinationAddress,6)==0) {
                if(retryBit&&entry.sequenceControl==retrySequenceControl)
                    duplicate=true;
                retrySlot=int(index);
                break;
            }
        }
        if(retrySlot<0)retrySlot=freeSlot;
        retryWindowFull=retrySlot<0;
    }
    const bool queueSpace=discoveryRx.count<QueueDepth;
    accepted=authorityCurrent&&interfaceCurrent&&!duplicate&&
        !retryWindowFull&&queueSpace;
    if(accepted) {
        item.interfaceIncarnation=interfaceIncarnation;
        item.guardVersion=activeDiscoveryRxVersion;
        accepted=discoveryRx.push(item);
        if(accepted) {
            auto &entry=discoveryRetryWindow[size_t(retrySlot)];
            entry=DiscoveryRetryEntry{};
            entry.valid=true;
            memcpy(entry.source,parsed.sourceAddress,sizeof(entry.source));
            memcpy(entry.destination,parsed.destinationAddress,
                   sizeof(entry.destination));
            entry.tid=retryTid;
            entry.sequenceControl=retrySequenceControl;
            entry.ownerSerial=identity.ownerSerial;
            entry.queryToken=identity.queryToken;
            entry.ifnetIncarnation=identity.ifnetIncarnation;
        } else {
            queueFull=true;
        }
    } else {
        queueFull=authorityCurrent&&interfaceCurrent&&!duplicate&&
            !retryWindowFull&&!queueSpace;
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t index=0;index<expired;++index)add(RxRejected);
    if(duplicate) {
        add(RxRejected);
        return CaptureResult::Duplicate;
    }
    if(accepted) {
        add(RxCaptured);
        return CaptureResult::Captured;
    }
    if(queueFull||retryWindowFull) {
        add(queueFull?RxQueueFull:RxRejected);
        return queueFull?CaptureResult::QueueFull:CaptureResult::Rejected;
    }
    add(RxRejected);
    return CaptureResult::Rejected;
}
#endif
bool publishRx149DataInputLease(
    const NativeP2PRx149DataInput::Lease &lease) {
    if(!bridgeLock())return false;
    size_t discarded=0;
    bool activated=false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    // Authorization time is sampled only after acquiring the same lock that
    // publishes the lease, so lock contention cannot revive an expired ROC.
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
    runRx149TestHook(Rx149TestHookPoint::LeaseAuthorization);
#endif
    const uint64_t lockedNow=nowUs();
    if(NativeP2PRx149DataInput::leaseCurrent(lease,lockedNow))
        activated=activateRx149LeaseLocked(lease,&discarded,lockedNow);
    else if(NativeP2PRx149DataInput::waitingForFirstStart(lease)&&
            !activeRx149LeaseValid&&activeRx149Version!=UINT64_MAX&&
            lease.ownerSerial>rx149OwnerSerialHighWater&&
            !Rx149InputGateState::blocked(__atomic_load_n(
                &rx149InputGateState,__ATOMIC_ACQUIRE))&&
            interfaceIncarnation!=0&&interface&&!closing&&!detached&&radio&&
            radioGeneration==lease.epochs.power&&
            __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
            __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0) {
        // ACK-before-START is not a terminal event. Leave all authority,
        // versions, high-water, queue and receipt state unchanged, and return
        // false. An active old lease, tombstone, fault or closing bridge never
        // enters this exception; the original fail-closed revoke stays below.
    }
    else if(lease.ownerSerial&&
            NativeP2PRx149DataInput::validEpochs(lease.epochs))
        discarded=revokeRx149LeaseLocked(lease.ownerSerial,&lease.epochs,
                                         lockedNow);
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    maintainReplyShadowLocked(lockedNow);
#endif
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(RxRejected);
    return activated;
}
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
bool markDirectedDataEndFast(uint64_t ownerSerial,
    const NativeP2PDirectedDataRxInput::Epochs &epochs) {
    if(!ownerSerial||!NativeP2PDirectedDataRxInput::validEpochs(epochs))
        return false;
    return markDirectedFastEnd(ownerSerial,epochs);
}
bool publishDirectedDataRxInputLease(
    const NativeP2PDirectedDataRxInput::Lease &lease) {
    if(!bridgeLock())return false;
    size_t discarded=0;
    bool activated=false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t lockedNow=nowUs();
    if(NativeP2PDirectedDataRxInput::leaseCurrent(lease,lockedNow))
        activated=activateDirectedRxLeaseLocked(lease,&discarded,lockedNow);
    else if(lease.endSeen||lease.outcomeUnknown||
            !lease.ownerCurrent||!lease.epochsMatch||!lease.tokenMatches) {
        if(lease.ownerSerial&&
           NativeP2PDirectedDataRxInput::validEpochs(lease.epochs))
            discarded=revokeDirectedRxLeaseLocked(lease.ownerSerial,
                &lease.epochs,lockedNow);
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(DirectedRxRejected);
    return activated;
}
void revokeDirectedDataRxInput(uint64_t ownerSerial,
    const NativeP2PDirectedDataRxInput::Epochs &epochs) {
    if(!bridgeLock()||!ownerSerial)return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const size_t discarded=revokeDirectedRxLeaseLocked(
        ownerSerial,&epochs,nowUs());
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(DirectedRxRejected);
}
void revokeDirectedDataRxInput() {
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    size_t discarded=0;
    if(activeDirectedRxLeaseValid) {
        const uint64_t ownerSerial=activeDirectedRxLease.ownerSerial;
        const auto epochs=activeDirectedRxLease.epochs;
        discarded=revokeDirectedRxLeaseLocked(ownerSerial,&epochs,nowUs());
    } else {
        discarded=removeDirectedRxItemsLocked(true,0,0,nullptr,nowUs());
        if(activeDirectedRxVersion!=UINT64_MAX)++activeDirectedRxVersion;
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t i=0;i<discarded;++i)add(DirectedRxRejected);
}
#endif
bool configureReplyShadow(const NativeAwdlReplyShadow::Config &config,
                          const NativeP2PRx149DataInput::Lease &lease) {
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    if(!bridgeLock())return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const auto a=replyShadowAuthorityLocked();
    const bool same=activeRx149LeaseValid&&sameRx149LeaseIdentity(activeRx149Lease,lease)&&
        NativeP2PRx149DataInput::leaseCurrent(lease,nowUs())&&
        !memcmp(config.ownMac,own,sizeof(own));
    const bool result=same&&replyShadow.configure(config,a,nowUs());
    IOSimpleLockUnlockEnableInterrupt(lock,irq);return result;
#else
    (void)config;(void)lease;return false;
#endif
}
void disableReplyShadow() {
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    replyShadow.retire(NativeAwdlReplyShadow::Reason::Revoked);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#endif
}
NativeAwdlReplyShadow::Snapshot replyShadowSnapshot() {
    NativeAwdlReplyShadow::Snapshot result{};
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    if(!bridgeLock())return result;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    result=replyShadow.snapshot(replyShadowAuthorityLocked(),nowUs());
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#endif
    return result;
}
void revokeRx149DataInput(uint64_t ownerSerial,
    const NativeP2PRx149DataInput::Epochs &epochs) {
    if(!bridgeLock()||!ownerSerial)return;
    const uint64_t now=nowUs();
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const size_t discarded=revokeRx149LeaseLocked(ownerSerial,&epochs,now);
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    maintainReplyShadowLocked(now);
#endif
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
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    maintainReplyShadowLocked(now);
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
            revokeDiscoveryRxLocked();
#endif
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
            } else if(rx.count!=0
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
                      ||discoveryRx.count!=0
#endif
                      ) {
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    DirectedOriginPacketRetirement retiredOrigin{};
#endif
    bool discardQueued=false;
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    size_t retiredDirectedRx=0;
#endif
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool changed=radioGeneration&&radioGeneration!=generation;
    discardQueued=!ready||changed;
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    const uint64_t directedPollNow=nowUs();
    const bool preserveDirectedRxLease=activeDirectedRxLeaseValid&&ready&&radio&&
        !changed&&interface&&!closing&&!detached&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        generation==activeDirectedRxLease.epochs.power&&
        NativeP2PDirectedDataRxInput::leaseCurrent(
            activeDirectedRxLease,directedPollNow);
#endif
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    // This build is receive-only regardless of runtime RX-profile state.
    discardQueued=true;
#endif
    if(discardQueued) {
        Tx item{};
        while(tx.pop(&item))retiredTx.push(item);
    }
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    if(!preserveDirectedRxLease) {
        if(activeDirectedRxLeaseValid) {
            const uint64_t owner=activeDirectedRxLease.ownerSerial;
            const auto epochs=activeDirectedRxLease.epochs;
            retiredDirectedRx=revokeDirectedRxLeaseLocked(
                owner,&epochs,directedPollNow);
        } else {
            retiredDirectedRx=removeDirectedRxItemsLocked(
                true,0,0,nullptr,directedPollNow);
        }
    }
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
    if(discardQueued)revokeDiscoveryRxLocked();
#endif
    radioGeneration=generation;radio=ready&&!closing&&!detached&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0;
    set(LinkReady,radio?1:0);
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    const uint64_t originNow=nowUs();
    if(!radio||changed) {
        (void)directedOriginGate.revoke(
            originNow,NativeAwdlDirectedOriginTx::Reason::InterfaceStopped);
        retiredOrigin=takeDirectedOriginPacketLocked();
    } else if(directedOriginGate.expire(originNow)) {
        retiredOrigin=takeDirectedOriginPacketLocked();
    }
#endif
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    maintainReplyShadowLocked(nowUs());
#endif
    if(discardQueued)set(TxPending,tx.count);
    ifnet_t dev=interface;
    if(dev&&!closing&&!detached)++inputCalls;else dev=nullptr;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    for(size_t index=0;index<retiredDirectedRx;++index)
        add(DirectedRxRejected);
#endif
    Tx retired{};
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    if(retiredOrigin.packet) {
        freeDirectedOriginPacket(retiredOrigin);
        add(TxExpired);
    }
#endif
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
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
void pollDiscoveryRx(bool ready,uint32_t generation,
    const NativeAwdlDiscoveryRxInput::Lease *lease,
    const NativeAwdlDiscoveryRxInput::MainGate *gate,
    DiscoveryRxGateRunner gateRunner,void *ownerContext) {
    if(!bridgeLock()||!ready||!lease||!gate||!gateRunner)return;
    const auto identity=lease->identity;
    const uint64_t firstNow=nowUs();
    if(!NativeAwdlDiscoveryRxInput::leaseCurrent(*lease,*gate,firstNow)) {
        revokeDiscoveryRxInput(identity);
        return;
    }

    ifnet_t dev=nullptr;
    uint8_t expectedMac[6]{};
    uint64_t incarnation=0;
    uint32_t expectedIndex=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool authorityCurrent=activeDiscoveryRxLeaseValid&&
        activeDiscoveryRxVersion!=0&&
        NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
            activeDiscoveryRxLease.identity,identity)&&
        discoveryFastState(identity)==DiscoveryFastState::Current&&
        !Rx149InputGateState::blocked(__atomic_load_n(
            &rx149InputGateState,__ATOMIC_ACQUIRE));
    const bool interfaceReady=authorityCurrent&&interface&&!closing&&
        !detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        radioGeneration==generation&&generation==identity.epochs.power&&
        interfaceIncarnation==identity.ifnetIncarnation&&
        interfaceIndex==identity.ifindex&&inputCalls!=UINT32_MAX&&
        discoveryRxWorkers!=UINT32_MAX;
    if(interfaceReady) {
        dev=interface;
        incarnation=interfaceIncarnation;
        expectedIndex=interfaceIndex;
        memcpy(expectedMac,own,sizeof(expectedMac));
        ++inputCalls;
        ++discoveryRxWorkers;
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!interfaceReady) {
        revokeDiscoveryRxInput(identity);
        return;
    }

    const uint32_t liveIndex=ifnet_index(dev);
    uint8_t liveMac[6]{};
    const bool addressRead=ifnet_lladdr_copy_bytes(
        dev,liveMac,sizeof(liveMac))==0;
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool liveIfnetCurrent=interface==dev&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==generation&&interfaceIncarnation==incarnation&&
        interfaceIndex==expectedIndex&&liveIndex==expectedIndex&&
        addressRead&&memcmp(liveMac,expectedMac,sizeof(liveMac))==0&&
        memcmp(expectedMac,identity.localMac,sizeof(expectedMac))==0&&
        NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
            activeDiscoveryRxLease.identity,identity)&&
        discoveryFastState(identity)==DiscoveryFastState::Current;
    if(!liveIfnetCurrent&&activeDiscoveryRxLeaseValid&&
       NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
           activeDiscoveryRxLease.identity,identity))
        revokeDiscoveryRxLocked();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!liveIfnetCurrent) {
        irq=IOSimpleLockLockDisableInterrupt(lock);
        if(inputCalls)--inputCalls;
        if(discoveryRxWorkers)--discoveryRxWorkers;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        return;
    }

    for(unsigned index=0;index<QueueDepth;++index) {
        DiscoveryRx item{};
        bool have=false,itemCurrent=false;
        const uint64_t dequeueNow=nowUs();
        irq=IOSimpleLockLockDisableInterrupt(lock);
        have=discoveryRx.pop(&item);
        if(have) {
            itemCurrent=activeDiscoveryRxLeaseValid&&
                item.guardVersion==activeDiscoveryRxVersion&&
                item.interfaceIncarnation==interfaceIncarnation&&
                item.generation==generation&&
                NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                    item.permit.identity,identity)&&
                NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                    activeDiscoveryRxLease.identity,identity)&&
                discoveryFastState(identity)==DiscoveryFastState::Current&&
                !Rx149InputGateState::blocked(__atomic_load_n(
                    &rx149InputGateState,__ATOMIC_ACQUIRE))&&
                NativeAwdlDiscoveryRxInput::stillCurrent(
                    item.permit,*lease,*gate,dequeueNow);
        }
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(!have)break;
        if(!itemCurrent) {
            add(RxRejected);
            continue;
        }

        NativeAwdlData::DecodedFrame parsed{};
        if(NativeAwdlData::decodeIpv6DataMpdu(
                item.bytes,item.length,&parsed)!=NativeAwdlData::Status::Ok||
           parsed.amsdu||parsed.packetCount!=1||
           memcmp(item.bytes+10,identity.sourceMac,6)!=0||
           memcmp(parsed.sourceAddress,identity.sourceMac,6)!=0||
           memcmp(parsed.packets[0].sourceAddress,identity.sourceMac,6)!=0||
           !acceptsRx(parsed.packets[0],identity.localMac)) {
            add(RxRejected);
            continue;
        }
        add(RxDecoded);
        const auto &packet=parsed.packets[0];
        mbuf_t packetMbuf=packetWithHeader();
        if(!packetMbuf) {
            add(RxInputFailed);
            continue;
        }
        uint8_t *ethernet=static_cast<uint8_t *>(mbuf_data(packetMbuf));
        memcpy(ethernet,packet.destinationAddress,6);
        memcpy(ethernet+6,packet.sourceAddress,6);
        ethernet[12]=0x86;
        ethernet[13]=0xdd;
        memcpy(ethernet+14,packet.ipv6Packet,packet.ipv6Length);
        mbuf_setlen(packetMbuf,packet.ipv6Length+14);
        mbuf_pkthdr_setlen(packetMbuf,packet.ipv6Length+14);
        mbuf_pkthdr_setrcvif(packetMbuf,dev);
        mbuf_pkthdr_setheader(packetMbuf,ethernet);
        mbuf_adj(packetMbuf,14);

        struct AdmissionTicketContext {
            const DiscoveryRx *item;
            ifnet_t dev;
            uint64_t incarnation;
            uint32_t generation;
            bool reserved;
            uint32_t fastGeneration;
            NativeAwdlData::PacketView packet;
            NativeAwdlDiscoveryRxInput::Lease lease;
            NativeAwdlDiscoveryRxInput::MainGate gate;
        } ticketContext{&item,dev,incarnation,generation,false,0,
                        parsed.packets[0],{}, {}};
        const DiscoveryRxAdmissionAction admissionAction=
            +[](void *opaque,
                const NativeAwdlDiscoveryRxInput::Lease &freshLease,
                const NativeAwdlDiscoveryRxInput::MainGate &freshGate)->bool {
                auto *context=static_cast<AdmissionTicketContext *>(opaque);
                if(!context||!context->item||context->reserved||!bridgeLock())
                    return false;
                auto irq=IOSimpleLockLockDisableInterrupt(lock);
                const uint64_t ticketNow=nowUs();
                const auto &identity=context->item->permit.identity;
                const bool stillAttached=interface==context->dev&&
                    !closing&&!detached&&radio&&
                    __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
                    __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
                    radioGeneration==context->generation&&
                    interfaceIncarnation==context->incarnation&&
                    interfaceIndex==identity.ifindex&&
                    memcmp(own,identity.localMac,sizeof(own))==0;
                const bool permitStillCurrent=stillAttached&&
                    activeDiscoveryRxLeaseValid&&
                    context->item->guardVersion==activeDiscoveryRxVersion&&
                    NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                        activeDiscoveryRxLease.identity,identity)&&
                    NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                        freshLease.identity,identity)&&
                    NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                        freshGate.identity,identity)&&
                    acceptsRx(context->packet,freshLease.identity.localMac)&&
                    NativeAwdlDiscoveryRxInput::stillCurrent(
                        context->item->permit,freshLease,freshGate,ticketNow)&&
                    NativeAwdlDiscoveryRxInput::stillCurrent(
                        context->item->permit,activeDiscoveryRxLease,
                        freshGate,ticketNow)&&
                    discoveryFastState(identity)==DiscoveryFastState::Current&&
                    !Rx149InputGateState::blocked(__atomic_load_n(
                        &rx149InputGateState,__ATOMIC_ACQUIRE))&&
                    inputCalls!=UINT32_MAX&&
                    discoveryRxTickets!=UINT32_MAX;
                bool discoveryTicket=false;
                if(permitStillCurrent)
                    discoveryTicket=reserveDiscoveryFastTicket(
                        identity,&context->fastGeneration);
                const bool sharedTicket=discoveryTicket&&
                    reserveRx149InputTicketFast();
                if(discoveryTicket&&!sharedTicket)
                    releaseDiscoveryFastTicket(context->fastGeneration);
                if(sharedTicket) {
                    ++inputCalls;
                    ++discoveryRxTickets;
                    context->reserved=true;
                    context->lease=freshLease;
                    context->gate=freshGate;
                }
                IOSimpleLockUnlockEnableInterrupt(lock,irq);
                return context->reserved;
            };
        const bool admissionSucceeded=gateRunner(ownerContext,identity,
            admissionAction,&ticketContext);
        if(!admissionSucceeded||!ticketContext.reserved) {
            if(ticketContext.reserved) {
                irq=IOSimpleLockLockDisableInterrupt(lock);
                releaseRx149InputTicketFast();
                releaseDiscoveryFastTicket(ticketContext.fastGeneration);
                if(inputCalls)--inputCalls;
                if(discoveryRxTickets)--discoveryRxTickets;
                IOSimpleLockUnlockEnableInterrupt(lock,irq);
            }
            mbuf_freem(packetMbuf);
            add(RxRejected);
            continue;
        }

        add(DiscoveryInputCalls);
        const int inputResult=ifnet_input(dev,packetMbuf,nullptr);
        set(DiscoveryInputResult,
            static_cast<uint64_t>(static_cast<int64_t>(inputResult)));
        if(inputResult==0)add(DiscoveryInputSuccess);
        const uint64_t inputCompletedUs=nowUs();
        irq=IOSimpleLockLockDisableInterrupt(lock);
        const uint64_t commitNow=nowUs();
        const bool committed=inputResult==0&&inputCompletedUs>=item.permit.capturedUs&&
            inputCompletedUs<item.permit.receiveDeadlineUs&&
            commitNow>=inputCompletedUs&&
            commitNow<item.permit.receiveDeadlineUs&&
            interface==dev&&!closing&&!detached&&radio&&
            __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
            radioGeneration==generation&&interfaceIncarnation==incarnation&&
            activeDiscoveryRxLeaseValid&&
            item.guardVersion==activeDiscoveryRxVersion&&
            NativeAwdlDiscoveryRxInput::sameLeaseIdentity(
                activeDiscoveryRxLease.identity,identity)&&
            NativeAwdlDiscoveryRxInput::stillCurrent(
                item.permit,ticketContext.lease,ticketContext.gate,commitNow)&&
            discoveryFastState(identity)==DiscoveryFastState::Current&&
            !Rx149InputGateState::blocked(__atomic_load_n(
                &rx149InputGateState,__ATOMIC_ACQUIRE));
        releaseRx149InputTicketFast();
        releaseDiscoveryFastTicket(ticketContext.fastGeneration);
        if(inputCalls)--inputCalls;
        if(discoveryRxTickets)--discoveryRxTickets;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(committed) {
            add(RxDelivered);
            add(DiscoverySameWindowCommitted);
        }
        else if(inputResult!=0)add(RxInputFailed);
    }

    irq=IOSimpleLockLockDisableInterrupt(lock);
    if(inputCalls)--inputCalls;
    if(discoveryRxWorkers)--discoveryRxWorkers;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
#endif
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
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
            uint64_t shadowRequest=0;
            if(ticketReserved&&parsed.packetCount==1&&!parsed.qosData&&parsed.frameControl==0x0008)
                shadowRequest=replyShadow.request(replyShadowAuthorityLocked(),ticketNow,
                    item.rx149ReceiptSequence,item.rx149Permit.capturedUs,uint16_t(item.bytes[22])|(uint16_t(item.bytes[23])<<8),
                    packet.awdlSequenceNumber,packet.sourceAddress,packet.destinationAddress,
                    packet.ipv6Packet,packet.ipv6Length);
#endif
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
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
            replyShadow.finishInput(shadowRequest,inputResult,replyShadowAuthorityLocked(),nowUs());
#endif
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
void poll(bool ready,uint32_t generation,
          const NativeP2PDirectedDataRxInput::Lease *directedLease) {
    if(!bridgeLock())return;

    ifnet_t dev=nullptr;
    uint8_t expectedAddress[6]{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t firstNow=nowUs();
    const bool interfaceReady=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        radioGeneration==generation&&ready;
    if(interfaceReady) {
        dev=interface;
        memcpy(expectedAddress,own,sizeof(expectedAddress));
        ++inputCalls;
    }
    if(activeDirectedRxLeaseValid&&
       (!interfaceReady||!directedLease||
        !sameDirectedRxLeaseIdentity(activeDirectedRxLease,*directedLease)||
        !NativeP2PDirectedDataRxInput::leaseCurrent(
            activeDirectedRxLease,firstNow))) {
        const uint64_t owner=activeDirectedRxLease.ownerSerial;
        const auto epochs=activeDirectedRxLease.epochs;
        (void)revokeDirectedRxLeaseLocked(owner,&epochs,firstNow);
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);

    for(unsigned index=0;index<QueueDepth;++index) {
        DirectedRx item{};
        NativeP2PDirectedDataRxInput::Lease authoritativeLease{};
        bool authoritativeMatch=false;
        irq=IOSimpleLockLockDisableInterrupt(lock);
        const bool have=directedRx.pop(&item);
        if(have&&directedLease&&activeDirectedRxLeaseValid&&
           directedFastLeaseState(activeDirectedRxLease.ownerSerial,
               activeDirectedRxLease.epochs)==DirectedFastLeaseState::Current&&
           !Rx149InputGateState::blocked(__atomic_load_n(
               &rx149InputGateState,__ATOMIC_ACQUIRE))&&
           item.guardVersion==activeDirectedRxVersion&&
           item.interfaceIncarnation==interfaceIncarnation&&
           sameDirectedRxLeaseIdentity(activeDirectedRxLease,*directedLease)&&
           sameDirectedRxPermitIdentity(activeDirectedRxLease,item.permit)) {
            authoritativeLease=activeDirectedRxLease;
            authoritativeMatch=true;
        }
        set(DirectedRxPending,directedRx.count);
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(!have)break;

        const uint64_t captureNow=nowUs();
        const bool permitCurrent=ready&&dev&&directedLease&&
            directedFastLeaseState(directedLease->ownerSerial,
                directedLease->epochs)==DirectedFastLeaseState::Current&&
            item.generation==generation&&
            item.generation==directedLease->epochs.power&&
            item.interfaceIncarnation!=0&&authoritativeMatch&&
            NativeP2PDirectedDataRxInput::stillCurrent(
                item.permit,authoritativeLease,captureNow)&&
            NativeP2PDirectedDataRxInput::stillCurrent(
                item.permit,*directedLease,captureNow);
        if(!permitCurrent) {
            recordDirectedRxReceipt(item,DirectedDataRxReceiptStaleOrInvalid,
                                    captureNow,0,false,0);
            add(DirectedRxRejected);
            continue;
        }

        NativeAwdlData::DecodedFrame parsed{};
        if(NativeAwdlData::decodeIpv6DataMpdu(
                item.bytes,item.length,&parsed)!=NativeAwdlData::Status::Ok) {
            recordDirectedRxReceipt(item,DirectedDataRxReceiptDecodeRejected,
                                    captureNow,0,false,0);
            add(DirectedRxRejected);
            continue;
        }
        add(DirectedRxDecoded);
        for(size_t packetIndex=0;packetIndex<parsed.packetCount;++packetIndex) {
            const auto &packet=parsed.packets[packetIndex];
            if(!acceptsDirectedDataRx(packet,expectedAddress,
                                      item.permit.peerMac)) {
                recordDirectedRxReceipt(item,
                    DirectedDataRxReceiptAddressRejected,captureNow,
                    uint32_t(parsed.packetCount),false,0);
                add(DirectedRxRejected);
                continue;
            }
            mbuf_t packetMbuf=packetWithHeader();
            if(!packetMbuf) {
                recordDirectedRxReceipt(item,
                    DirectedDataRxReceiptMbufAllocationFailed,captureNow,
                    uint32_t(parsed.packetCount),false,0);
                add(DirectedRxInputFailed);
                continue;
            }
            uint8_t *bytes=static_cast<uint8_t *>(mbuf_data(packetMbuf));
            memcpy(bytes,packet.destinationAddress,6);
            memcpy(bytes+6,packet.sourceAddress,6);
            bytes[12]=0x86;
            bytes[13]=0xdd;
            memcpy(bytes+14,packet.ipv6Packet,packet.ipv6Length);
            mbuf_setlen(packetMbuf,packet.ipv6Length+14);
            mbuf_pkthdr_setlen(packetMbuf,packet.ipv6Length+14);
            mbuf_pkthdr_setrcvif(packetMbuf,dev);
            mbuf_pkthdr_setheader(packetMbuf,bytes);
            mbuf_adj(packetMbuf,14);

            // Hold a shared lock-free input ticket across DLIL. The gate is
            // conservative across the resident receive paths; packet work
            // and ifnet_input remain outside IOSimpleLock.
            irq=IOSimpleLockLockDisableInterrupt(lock);
            const uint64_t ticketNow=nowUs();
            const bool stillAttached=interface==dev&&!closing&&!detached&&
                radio&&__atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
                __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
                radioGeneration==generation&&
                !Rx149InputGateState::blocked(__atomic_load_n(
                    &rx149InputGateState,__ATOMIC_ACQUIRE))&&
                interfaceIncarnation==item.interfaceIncarnation&&
                memcmp(own,expectedAddress,sizeof(expectedAddress))==0;
            const bool permitStillCurrent=stillAttached&&directedLease&&
                activeDirectedRxLeaseValid&&
                directedFastLeaseState(activeDirectedRxLease.ownerSerial,
                    activeDirectedRxLease.epochs)==
                        DirectedFastLeaseState::Current&&
                item.guardVersion==activeDirectedRxVersion&&
                sameDirectedRxLeaseIdentity(activeDirectedRxLease,
                                            *directedLease)&&
                sameDirectedRxLeaseIdentity(activeDirectedRxLease,
                                            authoritativeLease)&&
                NativeP2PDirectedDataRxInput::leaseCurrent(
                    activeDirectedRxLease,ticketNow)&&
                NativeP2PDirectedDataRxInput::stillCurrent(
                    item.permit,activeDirectedRxLease,ticketNow);
            const bool ticketReserved=permitStillCurrent&&
                reserveRx149InputTicketFast();
            if(ticketReserved)++inputCalls;
            IOSimpleLockUnlockEnableInterrupt(lock,irq);
            if(!ticketReserved) {
                mbuf_freem(packetMbuf);
                recordDirectedRxReceipt(item,
                    DirectedDataRxReceiptStaleOrInvalid,ticketNow,
                    uint32_t(parsed.packetCount),false,0);
                add(DirectedRxRejected);
                continue;
            }

            const int inputResult=ifnet_input(dev,packetMbuf,nullptr);
            const uint64_t inputCompletedUs=nowUs();
            recordDirectedRxReceipt(item,
                inputResult==0?DirectedDataRxReceiptIfnetInputSucceeded:
                              DirectedDataRxReceiptIfnetInputFailed,
                ticketNow,uint32_t(parsed.packetCount),true,inputResult,
                inputCompletedUs);
            irq=IOSimpleLockLockDisableInterrupt(lock);
            releaseRx149InputTicketFast();
            if(inputCalls)--inputCalls;
            IOSimpleLockUnlockEnableInterrupt(lock,irq);
            if(inputResult==0)add(DirectedRxDelivered);
            else add(DirectedRxInputFailed);
        }
    }

    if(dev) {
        irq=IOSimpleLockLockDisableInterrupt(lock);
        if(inputCalls)--inputCalls;
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
    }
}

CaptureResult captureDirectedDataRx(
    const uint8_t *bytes,size_t length,bool protectedFrame,
    const NativeP2PDirectedDataRxInput::Lease &lease,
    const NativeP2PDirectedDataRxInput::Permit &permit,uint32_t generation) {
    if(!bytes||!NativeAwdlData::isAwdlDataCandidate(bytes,length))
        return CaptureResult::NotAwdlDataCandidate;
    if(length>2048||protectedFrame||!permit.valid||
       generation!=permit.epochs.power) {
        add(DirectedRxRejected);
        return CaptureResult::Rejected;
    }
    NativeAwdlData::DecodedFrame retryDecoded{};
    if(length<24||
       NativeAwdlData::decodeIpv6DataMpdu(
           bytes,length,&retryDecoded)!=NativeAwdlData::Status::Ok||
       retryDecoded.amsdu||retryDecoded.packetCount!=1||
       !acceptsDirectedDataRx(retryDecoded.packets[0],
                              permit.localMac,permit.peerMac)) {
        add(DirectedRxRejected);
        return CaptureResult::Rejected;
    }
    // This early path must preserve the worker's address policy: peer-origin
    // link-local unicast and correctly mapped ff02 multicast are both valid.
    // Only unicast belongs to the directed Retry ledger. Reject other IPv6
    // targets before consuming the MPDU so the caller retains its STA path.
    const bool retryTracked=(retryDecoded.destinationAddress[0]&1u)==0;
    const uint8_t retryTid=retryDecoded.qosData?
        uint8_t(retryDecoded.qosControl&0x0fu):uint8_t(16);
    const uint16_t retrySequenceControl=uint16_t(bytes[22])|
        (uint16_t(bytes[23])<<8);
    const bool retryBit=(bytes[1]&0x08u)!=0;
    if(!bridgeLock()) {
        add(DirectedRxRejected);
        return CaptureResult::Rejected;
    }

    DirectedRx item{};
    item.length=uint16_t(length);
    item.generation=generation;
    item.permit=permit;
    memcpy(item.bytes,bytes,length);
    size_t expired=0;
    bool accepted=false;
    bool queueFull=false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t captureNow=nowUs();
    for(size_t offset=0;offset<directedRx.count;) {
        const size_t queuedIndex=(directedRx.head+offset)%QueueDepth;
        const auto &queued=directedRx.values[queuedIndex];
        const bool stale=captureNow<queued.permit.capturedUs||
            captureNow>=queued.permit.deadlineUs||
            !activeDirectedRxLeaseValid||
            queued.guardVersion!=activeDirectedRxVersion;
        if(stale) {
            DirectedRx removed{};
            if(removeDirectedRxAt(offset,&removed)) {
                recordDirectedRxReceiptLocked(removed,
                    DirectedDataRxReceiptStaleOrInvalid,captureNow,0,false,0);
                ++expired;
            }
        } else {
            ++offset;
        }
    }
    const bool authorityCurrent=
        directedFastLeaseState(lease.ownerSerial,lease.epochs)==
            DirectedFastLeaseState::Current&&
        !Rx149InputGateState::blocked(__atomic_load_n(
            &rx149InputGateState,__ATOMIC_ACQUIRE))&&
        activeDirectedRxLeaseValid&&activeDirectedRxVersion!=0&&
        sameDirectedRxLeaseIdentity(activeDirectedRxLease,lease)&&
        sameDirectedRxPermitIdentity(activeDirectedRxLease,permit)&&
        NativeP2PDirectedDataRxInput::leaseCurrent(
            activeDirectedRxLease,captureNow)&&
        NativeP2PDirectedDataRxInput::stillCurrent(
            permit,activeDirectedRxLease,captureNow);
    const bool interfaceCurrent=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        radioGeneration==generation&&generation==lease.epochs.power&&
        interfaceIncarnation!=0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        memcmp(lease.localMac,own,sizeof(own))==0;
    const bool sequenceAvailable=directedRxReceiptSequence!=UINT64_MAX;
    const bool revisionAvailable=directedRxReceiptContentRevision!=UINT64_MAX;
    const bool queueSpace=directedRx.count<QueueDepth;
    const bool queueDeadlineAvailable=captureNow<=UINT64_MAX-
        NativeP2PDirectedDataRxInput::kMaximumQueuedAgeUs;
    const bool captureAuthority=authorityCurrent&&interfaceCurrent&&
        sequenceAvailable&&revisionAvailable&&queueDeadlineAvailable;
    int retrySlot=-1;
    bool retryDuplicate=false;
    bool retryWindowFull=false;
    if(captureAuthority&&retryTracked) {
        retrySlot=findDirectedRxRetrySlotLocked(
            permit,interfaceIncarnation,retryDecoded.sourceAddress,
            retryDecoded.destinationAddress,retryTid,retrySequenceControl,
            retryBit,&retryDuplicate);
        retryWindowFull=retrySlot<0;
    }
    accepted=captureAuthority&&!retryDuplicate&&!retryWindowFull&&queueSpace;
    if(accepted) {
        item.exactOriginReplyCaptured=matchExactOriginReplyLocked(
            lease,permit,retryDecoded.packets[0],captureNow,
            &item.originTicket,&item.originPacket);
        item.interfaceIncarnation=interfaceIncarnation;
        item.guardVersion=activeDirectedRxVersion;
        item.receiptSequence=directedRxReceiptSequence+1;
        item.permit.capturedUs=captureNow;
        item.permit.deadlineUs=captureNow+
            NativeP2PDirectedDataRxInput::kMaximumQueuedAgeUs;
        if(item.permit.deadlineUs>lease.deadlineUs)
            item.permit.deadlineUs=lease.deadlineUs;
        accepted=directedRx.push(item);
        if(accepted) {
            directedRxReceiptSequence=item.receiptSequence;
            directedRxReceipt=DirectedDataRxInputReceipt{};
            directedRxReceipt.disposition=DirectedDataRxReceiptCaptured;
            directedRxReceipt.sequence=item.receiptSequence;
            directedRxReceipt.contentRevision=++directedRxReceiptContentRevision;
            directedRxReceipt.ownerSerial=lease.ownerSerial;
            directedRxReceipt.interfaceIncarnation=interfaceIncarnation;
            directedRxReceipt.contextGeneration=lease.epochs.context;
            directedRxReceipt.powerGeneration=lease.epochs.power;
            directedRxReceipt.stationGeneration=lease.epochs.station;
            directedRxReceipt.rocGeneration=lease.epochs.roc;
            directedRxReceipt.captureUs=captureNow;
            directedRxReceipt.startUs=lease.startUs;
            directedRxReceipt.deadlineUs=item.permit.deadlineUs;
            directedRxReceipt.ieeeChannel=NativeP2PDirectedDataRxInput::kIeeeChannel;
            directedRxReceipt.macIndexPresent=1;
            directedRxReceipt.macIndex=permit.macIndex;
            directedRxReceipt.macPhyDecodeMode=permit.decodeMode;
            directedRxReceipt.originalRxStatus=permit.originalRawStatus;
            directedRxReceipt.mpduLength=uint32_t(length);
            directedRxReceipt.ifnetInputResultPresent=0;
            if(retryTracked)
                commitDirectedRxRetrySlotLocked(
                    size_t(retrySlot),permit,interfaceIncarnation,
                    retryDecoded.sourceAddress,retryDecoded.destinationAddress,
                    retryTid,retrySequenceControl);
        } else {
            // A ring push failure must never leave a retry key for a packet
            // that was not copied into the bounded queue.
            queueFull=true;
        }
    } else {
        queueFull=captureAuthority&&!retryDuplicate&&!retryWindowFull&&
            !queueSpace;
        if(!sequenceAvailable||!revisionAvailable)
            directedRxReceipt.schemaVersion=0;
    }
    set(DirectedRxPending,directedRx.count);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t index=0;index<expired;++index)add(DirectedRxRejected);
    if(retryDuplicate) {
        add(DirectedRxRejected);
        return CaptureResult::Duplicate;
    }
    if(accepted) {
        add(DirectedRxCaptured);
        return CaptureResult::Captured;
    }
    if(queueFull) {
        add(DirectedRxQueueFull);
        return CaptureResult::QueueFull;
    }
    add(DirectedRxRejected);
    return CaptureResult::Rejected;
}
#endif
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
    NativeAwdlData::DecodedFrame retryDecoded{};
    const bool retryDecodedValid=length<=2048&&
        NativeAwdlData::decodeIpv6DataMpdu(
            bytes,length,&retryDecoded)==NativeAwdlData::Status::Ok&&
        !retryDecoded.amsdu&&retryDecoded.packetCount==1;
    const bool retryTrackable=retryDecodedValid&&
        (retryDecoded.packets[0].destinationAddress[0]&1u)==0;
    const bool retryBit=(bytes[1]&0x08u)!=0;
    const uint8_t retryTid=retryDecoded.qosData?
        uint8_t(retryDecoded.qosControl&0x0fu):uint8_t(16);
    const uint16_t retrySequence=retryDecoded.wifiSequenceNumber;
    namespace D = Rx149CaptureDiagnostics;
    D::Record diagnostic{};
    auto &v=diagnostic.value;
    v[D::FrameLength]=length;
    if(length>=2) {
        v[D::HeaderPresentMask]|=1;
        v[D::FrameControl]=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
    }
    if(length>=24) {
        v[D::HeaderPresentMask]|=2;
        v[D::SequenceControl]=uint16_t(bytes[22])|(uint16_t(bytes[23])<<8);
    }
    v[D::PowerGeneration]=generation;
    v[D::PermitOwner]=permit.ownerSerial;
    v[D::PermitContext]=permit.epochs.context;
    v[D::PermitPower]=permit.epochs.power;
    v[D::PermitStation]=permit.epochs.station;
    v[D::PermitRoc]=permit.epochs.roc;
    v[D::PermitStartUs]=permit.startUs;
    v[D::PermitCapturedUs]=permit.capturedUs;
    v[D::PermitDeadlineUs]=permit.deadlineUs;
    v[D::PermitChannel]=permit.ieeeChannel;
    v[D::PermitMacIndex]=permit.macIndex;
    v[D::PermitDecodeMode]=permit.decodeMode;
    v[D::PermitRxStatus]=permit.originalRawStatus;
    v[D::LeaseOwner]=lease.ownerSerial;
    v[D::LeaseContext]=lease.epochs.context;
    v[D::LeasePower]=lease.epochs.power;
    v[D::LeaseStation]=lease.epochs.station;
    v[D::LeaseRoc]=lease.epochs.roc;
    v[D::LeaseStartUs]=lease.startUs;
    v[D::LeaseNowUs]=lease.nowUs;
    v[D::LeaseFlags]=D::leaseFlags(lease);
    const auto finish=[&](CaptureResult result) {
        v[D::Outcome]=static_cast<uint32_t>(result);
        rx149CaptureLedger.append(diagnostic);
        return result;
    };
    if(!diagnostic.test(D::BridgeLock,bridgeLock()!=nullptr)) {
        add(RxRejected);
        return finish(CaptureResult::Rejected);
    }
    if(!diagnostic.test(D::Unprotected,!protectedFrame)||
       !diagnostic.test(D::LengthWithinLimit,length<=2048)||
       !diagnostic.test(D::PermitValid,permit.valid)||
       !diagnostic.test(D::PowerGenerationMatches,
                        generation==permit.epochs.power)) {
        add(RxRejected);
        return finish(CaptureResult::Rejected);
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
    // Plain bridge-owned fields below are one observation under the existing
    // queue lock. Gate words are captured separately at the exact original
    // predicate loads: interrupt invalidation does not take this queue lock.
    v[D::DecisionNowUs]=captureNow;
    v[D::StatePresent]=1;
    v[D::ActiveOwner]=activeRx149Lease.ownerSerial;
    v[D::ActiveContext]=activeRx149Lease.epochs.context;
    v[D::ActivePower]=activeRx149Lease.epochs.power;
    v[D::ActiveStation]=activeRx149Lease.epochs.station;
    v[D::ActiveRoc]=activeRx149Lease.epochs.roc;
    v[D::ActiveStartUs]=activeRx149Lease.startUs;
    v[D::ActiveNowUs]=activeRx149Lease.nowUs;
    v[D::ActiveFlags]=D::leaseFlags(activeRx149Lease);
    v[D::ActiveVersion]=activeRx149Version;
    v[D::OwnerHighWater]=rx149OwnerSerialHighWater;
    v[D::InterfaceIncarnation]=interfaceIncarnation;
    v[D::RadioGeneration]=radioGeneration;
    v[D::BridgeFlags]=(activeRx149LeaseValid?1u:0u)|
        (interface?2u:0u)|(closing?4u:0u)|(detached?8u:0u)|(radio?16u:0u);
    v[D::ReceiptSequenceBefore]=rx149ReceiptSequence;
    v[D::ReceiptRevisionBefore]=rx149ReceiptContentRevision;
    v[D::QueueCountAtDecision]=rx.count;
    if(!diagnostic.test(D::FirstGateClear,!Rx149InputGateState::blocked(
           v[D::FirstGateWord]=__atomic_load_n(
               &rx149InputGateState,__ATOMIC_ACQUIRE)))||
       !diagnostic.test(D::PermitCurrent,
           NativeP2PRx149DataInput::stillCurrent(permit,lease,captureNow))) {
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        add(RxRejected);
        return finish(CaptureResult::Rejected);
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
        diagnostic.test(D::AuthorityGateClear,!Rx149InputGateState::blocked(
            v[D::AuthorityGateWord]=__atomic_load_n(
                &rx149InputGateState,__ATOMIC_ACQUIRE)))&&
        diagnostic.test(D::ActiveLeaseValid,activeRx149LeaseValid)&&
        diagnostic.test(D::ActiveVersionNonzero,activeRx149Version!=0)&&
        diagnostic.test(D::LeaseIdentityMatches,
            sameRx149LeaseIdentity(activeRx149Lease,lease))&&
        diagnostic.test(D::PermitIdentityMatches,
            sameRx149PermitIdentity(activeRx149Lease,permit))&&
        diagnostic.test(D::ActiveLeaseCurrent,
            NativeP2PRx149DataInput::leaseCurrent(activeRx149Lease,captureNow))&&
        diagnostic.test(D::ActivePermitCurrent,
            NativeP2PRx149DataInput::stillCurrent(
                permit,activeRx149Lease,captureNow));
    const bool current=authorityCurrent&&
        diagnostic.test(D::InterfaceIncarnationNonzero,interfaceIncarnation!=0)&&
        diagnostic.test(D::InterfacePresent,interface!=nullptr)&&
        diagnostic.test(D::NotClosing,!closing)&&
        diagnostic.test(D::NotDetached,!detached)&&
        diagnostic.test(D::RadioReady,radio)&&
        diagnostic.test(D::ClosingNotRequested,
            (v[D::ClosingRequested]=__atomic_load_n(
                &closingRequested,__ATOMIC_ACQUIRE))==0)&&
        diagnostic.test(D::RadioGenerationMatches,radioGeneration==generation)&&
        diagnostic.test(D::Attached,
            (v[D::AttachedCount]=__atomic_load_n(
                &counters[Attached],__ATOMIC_ACQUIRE))!=0);
    item.interfaceIncarnation=interfaceIncarnation;
    item.rx149GuardVersion=activeRx149Version;
    const bool sequenceAvailable=rx149ReceiptSequence!=UINT64_MAX;
    const bool revisionAvailable=rx149ReceiptContentRevision!=UINT64_MAX;
    const bool spaceAvailable=rx.count<QueueDepth;
    v[D::QueueCountAtDecision]=rx.count;
    bool accepted=current&&
        diagnostic.test(D::SequenceAvailable,sequenceAvailable)&&
        diagnostic.test(D::RevisionAvailable,revisionAvailable)&&
        diagnostic.test(D::QueueSpaceAvailable,spaceAvailable);
    int retrySlot=-1;
    bool retryDuplicate=false;
    bool retryWindowFull=false;
    if(accepted&&retryTrackable) {
        retrySlot=findRx149RetrySlotLocked(
            permit,interfaceIncarnation,
            retryDecoded.packets[0].sourceAddress,
            retryDecoded.packets[0].destinationAddress,retryTid,
            retrySequence,retryBit,&retryDuplicate);
        const bool retrySlotAvailable=diagnostic.test(
            D::RetryWindowSlotAvailable,retrySlot>=0);
        if(!retrySlotAvailable) {
            accepted=false;
            retryWindowFull=true;
        } else if(retryDuplicate) {
            // This exact source/TID/SC Retry already had a permit-current,
            // successfully queued copy for this owner and interface. It may
            // be consumed as a duplicate; no sequence state is changed.
            set(RxPending,rx.count);
            v[D::AssignedReceiptSequence]=0;
            IOSimpleLockUnlockEnableInterrupt(lock,irq);
            for(size_t index=0;index<expired;++index)add(RxRejected);
            add(RxRejected);
            return finish(CaptureResult::Duplicate);
        }
    }
    bool queuePushFailed=false;
    if(accepted) {
        item.rx149ReceiptSequence=rx149ReceiptSequence+1;
        const bool pushed=rx.push(item); // space checked under this same lock
        if(pushed) {
            ++rx149ReceiptSequence;
            rx149Receipt=makeRx149Receipt(
                item,item.rx149ReceiptSequence,Rx149ReceiptCaptured);
            rx149Receipt.contentRevision=++rx149ReceiptContentRevision;
            if(retryTrackable)
                commitRx149RetrySlotLocked(
                    size_t(retrySlot),permit,interfaceIncarnation,
                    retryDecoded.packets[0].sourceAddress,
                    retryDecoded.packets[0].destinationAddress,retryTid,
                    retrySequence);
        } else {
            accepted=false;
            queuePushFailed=true;
        }
    } else if(current&&sequenceAvailable&&revisionAvailable&&
              spaceAvailable&&retryWindowFull) {
        // A full retry table is an explicit fallback, never an eviction of an
        // active peer. No receipt or duplicate state is committed.
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
    v[D::AssignedReceiptSequence]=item.rx149ReceiptSequence;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    for(size_t index=0;index<expired;++index)add(RxRejected);
    if(accepted) {
        add(RxCaptured);
        return finish(CaptureResult::Captured);
    }
    if(retryWindowFull||queuePushFailed) {
        add(RxRejected);
        return finish(CaptureResult::Rejected);
    }
    if(!current) {
        add(RxRejected);
        return finish(CaptureResult::Rejected);
    }
    if(!sequenceAvailable||!revisionAvailable) {
        add(RxRejected);
        return finish(CaptureResult::Rejected);
    }
    add(RxQueueFull);
    return finish(CaptureResult::QueueFull);
}
void captureRx149Diagnostics(Rx149CaptureDiagnostics::Wire *out) {
    rx149CaptureLedger.copy(out);
}
namespace {
mbuf_t nextTxImpl(uint16_t sequence,uint64_t *token,
                  const DiscoveryTxSnapshot *expected,bool *consumed,
                  bool omitKnownAnswer=false) {
#if defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    (void)sequence;
    (void)expected;
    (void)omitKnownAnswer;
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
            // Only the MIF-current experiment can request this rewrite.
            // Work on the private Ethernet copy; the original mbuf and
            // queue selection, identity, and ownership stay unchanged.
            if(valid&&omitKnownAnswer)
                valid=NativeAwdlData::stripAirdropQmKnownAnswer(
                    ethernet+14,&view.length);
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
bool peekSystemDataTxDemand(uint32_t expectedPowerGeneration,
                            SystemDataTxDemandSnapshot *out) {
    if(out)*out=SystemDataTxDemandSnapshot{0,0,0};
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 || \
    defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332)
    // These profiles deliberately do not use the ordinary FIFO TX path.
    (void)expectedPowerGeneration;
    return false;
#else
    if(!out||!expectedPowerGeneration||!bridgeLock())return false;
    const uint64_t firstNow=nowUs();
    SystemDataTxDemandSnapshot candidate{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    bool valid=interface&&!closing&&!detached&&radio&&
        __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)==0&&
        __atomic_load_n(&counters[Attached],__ATOMIC_ACQUIRE)!=0&&
        radioGeneration==expectedPowerGeneration&&!inFlightToken&&tx.count;
    if(valid) {
        const Tx &head=tx.values[tx.head];
        valid=head.packet&&head.token&&
            head.generation==expectedPowerGeneration&&
            discoveryAgeCurrent(head.born,firstNow);
        if(valid)candidate=SystemDataTxDemandSnapshot{
            head.token,head.born,head.generation};
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    // Do not return a witness that expired while copying the bounded metadata.
    // A positive result remains only a momentary demand observation; callers
    // must sample again at their own decision point and must not treat it as a
    // firmware TX grant.
    const uint64_t secondNow=nowUs();
    if(!valid||candidate.powerGeneration!=expectedPowerGeneration||
       !candidate.token||!discoveryAgeCurrent(candidate.queuedUs,secondNow)||
       __atomic_load_n(&closingRequested,__ATOMIC_ACQUIRE)!=0)
        return false;
    *out=candidate;
    return true;
#endif
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
                       uint64_t *token,bool *consumed,bool omitKnownAnswer) {
    if(token)*token=0;
    if(consumed)*consumed=false;
    if(!token||!consumed)return nullptr;
    return nextTxImpl(sequence,token,&expected,consumed,omitKnownAnswer);
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
bool openDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::OpenRequest &request,
    NativeAwdlDirectedOriginTx::Ticket *out) {
    using namespace NativeAwdlDirectedOriginTx;
    if(out)*out=Ticket{};
    if(!out||!bridgeLock())return false;

    ifnet_t dev=nullptr;
    uint8_t expectedMac[6]{};
    uint64_t incarnation=0;
    uint32_t generation=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool ready=directedOriginReadyLocked(interface)&&
        interfaceIncarnation!=0&&directedOriginOperations!=UINT32_MAX;
    if(ready) {
        dev=interface;
        memcpy(expectedMac,own,sizeof(expectedMac));
        incarnation=interfaceIncarnation;
        generation=radioGeneration;
        ++directedOriginOperations; // pins the ctx across external KPI reads.
    } else {
        directedOriginGate.noteRejected(Reason::WrongInterface);
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(!ready)return false;

    uint8_t actualMac[6]{},actualIp[16]{};
    const bool macRead=ifnet_lladdr_copy_bytes(
        dev,actualMac,sizeof(actualMac))==0&&
        !memcmp(actualMac,expectedMac,sizeof(actualMac));
    const uint32_t ifindex=ifnet_index(dev);
    const bool ipRead=macRead&&readLiveLinkLocal(
        dev,request.sourceIPv6,actualIp);

    DirectedOriginPacketRetirement expired{};
    bool opened=false;
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t now=nowUs();
    const bool current=macRead&&ipRead&&directedOriginReadyLocked(dev)&&
        interfaceIncarnation==incarnation&&radioGeneration==generation&&
        generation==request.epochs.power&&directedOriginOperations==1&&
        (request.packetCount!=2||
         (activeDirectedRxLeaseValid&&
          activeDirectedRxLease.ownerSerial==request.ownerSerial&&
          activeDirectedRxLease.startUs==request.rocStartUs&&
          activeDirectedRxLease.deadlineUs==request.deadlineUs&&
          sameDirectedOriginEpochs(request.epochs,
              activeDirectedRxLease.epochs)&&
          !memcmp(activeDirectedRxLease.peerMac,request.peerMac,6)&&
          !memcmp(request.sourceIPv6,actualIp,16)&&
          directedFastLeaseState(request.ownerSerial,
              directedRxEpochs(request.epochs))==
              DirectedFastLeaseState::Current));
    if(current) {
        if(directedOriginGate.expire(now))
            expired=takeDirectedOriginPacketLocked();
        opened=directedOriginGate.open(request,now,radioGeneration,
            interfaceIncarnation,ifindex,actualMac,actualIp,out);
        if(opened) {
            memset(directedExactReplyReceipts,0,
                   sizeof(directedExactReplyReceipts));
            if(directedRxReceiptContentRevision==UINT64_MAX)
                directedRxReceipt.schemaVersion=0;
            else {
                directedRxReceipt.contentRevision=
                    ++directedRxReceiptContentRevision;
                for(uint8_t slot=0;slot<request.packetCount;++slot) {
                    PacketIdentity identity{};
                    if(directedOriginGate.packetIdentity(*out,slot,&identity))
                        updateExactReplyReceiptLocked(*out,identity);
                }
            }
        }
    } else {
        directedOriginGate.noteRejected(
            macRead&&ipRead?Reason::WrongEpoch:Reason::WrongSource);
    }
    if(directedOriginOperations)--directedOriginOperations;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    freeDirectedOriginPacket(expired);
    return opened;
}

bool closeDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::Ticket &ticket) {
    if(!bridgeLock())return false;
    DirectedOriginPacketRetirement packet{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool closed=directedOriginGate.close(ticket,nowUs());
    if(closed)packet=takeDirectedOriginPacketLocked();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    freeDirectedOriginPacket(packet);
    return closed;
}

void revokeDirectedOriginTx() {
    if(!bridgeLock())return;
    DirectedOriginPacketRetirement packet{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    (void)directedOriginGate.revoke(
        nowUs(),NativeAwdlDirectedOriginTx::Reason::InterfaceStopped);
    packet=takeDirectedOriginPacketLocked();
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    freeDirectedOriginPacket(packet);
}

mbuf_t popDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    uint16_t wifiSequence,uint16_t awdlSequence,
    NativeAwdlDirectedOriginTx::PacketIdentity *identity) {
    using namespace NativeAwdlDirectedOriginTx;
    if(identity)*identity=PacketIdentity{};
    if(!identity||!bridgeLock())return nullptr;

    mbuf_t sourcePacket=nullptr;
    DirectedOriginPacketRetirement retiredSource{},expired{};
    ifnet_t dev=nullptr;
    OpenRequest request{};
    PacketIdentity packetIdentity{};
    uint8_t sourceMac[6]{};
    uint64_t incarnation=0;
    uint32_t generation=0;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t now=nowUs();
    request=directedOriginGate.request();
    if(directedOriginOperations<UINT32_MAX&&directedOriginPacket&&
       directedOriginReadyLocked(interface)&&
       (request.packetCount!=2||directedFastLeaseState(
            ticket.ownerSerial,directedRxEpochs(ticket.epochs))==
                DirectedFastLeaseState::Current)&&
       directedOriginGate.beginPop(ticket,directedOriginPacketIdentity,now,
           true,radioGeneration,interfaceIncarnation)) {
        dev=interface;
        packetIdentity=directedOriginPacketIdentity;
        retiredSource=takeDirectedOriginPacketLocked();
        sourcePacket=retiredSource.packet;
        memcpy(sourceMac,ticket.sourceMac,sizeof(sourceMac));
        incarnation=interfaceIncarnation;
        generation=radioGeneration;
        ++directedOriginOperations; // close waits for encode and final recheck.
    } else {
        (void)directedOriginGate.expire(now);
        const NativeAwdlDirectedOriginTx::Snapshot state=
            directedOriginGate.snapshot(now,true);
        if(state.state==State::Expired)
            expired=takeDirectedOriginPacketLocked();
        if(directedOriginOperations>=UINT32_MAX)
            directedOriginGate.noteRejected(Reason::CounterExhausted);
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    freeDirectedOriginPacket(expired);
    if(!sourcePacket)return nullptr;

    uint8_t currentMac[6]{},currentIp[16]{};
    const bool liveContextMatches=dev&&
        ifnet_lladdr_copy_bytes(dev,currentMac,sizeof(currentMac))==0&&
        !memcmp(currentMac,sourceMac,sizeof(currentMac))&&
        ifnet_index(dev)==ticket.ifindex&&
        readLiveLinkLocal(dev,request.sourceIPv6,currentIp);
    uint8_t ethernet[kEthernetLength]{};
    bool valid=liveContextMatches&&
        (mbuf_flags(sourcePacket)&MBUF_PKTHDR)!=0&&
        mbuf_pkthdr_len(sourcePacket)==sizeof(ethernet)&&
        mbuf_copydata(sourcePacket,0,sizeof(ethernet),ethernet)==0&&
        validateEthernet(request,sourceMac,ethernet,sizeof(ethernet),true)==
            Reason::None;
    uint8_t raw[kMpduLength]{};
    size_t written=0;
    if(valid) {
        NativeAwdlData::EncodeInput input{};
        memcpy(input.destinationAddress,request.peerMac,6);
        memcpy(input.sourceAddress,sourceMac,6);
        input.wifiSequenceNumber=wifiSequence;
        input.awdlSequenceNumber=awdlSequence;
        input.ipv6Packet=ethernet+14;
        input.ipv6Length=kIpv6Length;
        valid=NativeAwdlData::encodeIpv6DataMpdu(
            &input,raw,sizeof(raw),&written)==NativeAwdlData::Status::Ok&&
            written==kMpduLength;
    }
    mbuf_t encodedPacket=valid?packetWithHeader():nullptr;
    if(encodedPacket) {
        memcpy(mbuf_data(encodedPacket),raw,sizeof(raw));
        mbuf_setlen(encodedPacket,sizeof(raw));
        mbuf_pkthdr_setlen(encodedPacket,sizeof(raw));
    } else {
        valid=false;
    }
    mbuf_freem(sourcePacket); // Original BSD output ownership ends at pop.

    bool transferred=false;
    irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t finalNow=nowUs();
    const bool ready=directedOriginReadyLocked(interface)&&
        radioGeneration==generation&&interfaceIncarnation==incarnation&&
        (request.packetCount!=2||directedFastLeaseState(
            ticket.ownerSerial,directedRxEpochs(ticket.epochs))==
                DirectedFastLeaseState::Current);
    transferred=directedOriginGate.finishPop(ticket,packetIdentity,finalNow,
        ready,radioGeneration,interfaceIncarnation,
        valid&&encodedPacket!=nullptr);
    if(directedOriginOperations)--directedOriginOperations;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);

    if(!transferred) {
        freeDirectedOriginPacket(encodedPacket);
        if(!valid)add(TxExpired);
        return nullptr;
    }
    *identity=packetIdentity;
    add(TxEncoded);
    return encodedPacket; // Caller/HAL owns the exact 96-byte MPDU mbuf.
}

mbuf_t popDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    uint16_t wifiSequence,uint16_t awdlSequence,uint64_t *packetToken) {
    if(packetToken)*packetToken=0;
    if(!packetToken)return nullptr;
    NativeAwdlDirectedOriginTx::PacketIdentity identity{};
    mbuf_t packet=popDirectedOriginTx(ticket,wifiSequence,awdlSequence,
                                      &identity);
    if(packet)*packetToken=identity.packetSerial;
    return packet;
}

bool recordDirectedTxDoorbell(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    const NativeAwdlDirectedOriginTx::PacketIdentity &identity,
    uint64_t submitUs) {
    using namespace NativeAwdlDirectedOriginTx;
    if(!bridgeLock())return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t now=nowUs();
    const OpenRequest &request=directedOriginGate.request();
    const bool authorizationAllowed=request.packetCount!=2||
        directedFastLeaseState(ticket.ownerSerial,
            directedRxEpochs(ticket.epochs))==
            DirectedFastLeaseState::Current;
    const bool recorded=directedOriginGate.recordTxDoorbell(ticket,identity,
        submitUs,now,radioGeneration,interfaceIncarnation,
        authorizationAllowed);
    if(recorded) {
        updateExactReplyReceiptLocked(ticket,identity);
        if(authorizationAllowed&&directedFastLeaseState(ticket.ownerSerial,
               directedRxEpochs(ticket.epochs))!=DirectedFastLeaseState::Current)
            (void)directedOriginGate.invalidateExactReplyAfterEnd(
                ticket,identity);
        updateExactReplyReceiptLocked(ticket,identity);
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    return recorded;
}

bool recordDirectedTxCompletion(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    const NativeAwdlDirectedOriginTx::PacketIdentity &identity,
    bool frameAttemptSucceeded,uint64_t txResponseUs) {
    using namespace NativeAwdlDirectedOriginTx;
    if(!bridgeLock())return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t now=nowUs();
    const OpenRequest &request=directedOriginGate.request();
    const bool authorizationAllowed=request.packetCount!=2||
        directedFastLeaseState(ticket.ownerSerial,
            directedRxEpochs(ticket.epochs))==
            DirectedFastLeaseState::Current;
    const bool recorded=directedOriginGate.recordTxCompletion(ticket,identity,
        frameAttemptSucceeded,txResponseUs,now,radioGeneration,
        interfaceIncarnation,authorizationAllowed);
    if(recorded) {
        updateExactReplyReceiptLocked(ticket,identity);
        if(authorizationAllowed&&directedFastLeaseState(ticket.ownerSerial,
               directedRxEpochs(ticket.epochs))!=DirectedFastLeaseState::Current)
            (void)directedOriginGate.invalidateExactReplyAfterEnd(
                ticket,identity);
        updateExactReplyReceiptLocked(ticket,identity);
    }
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    return recorded;
}

bool snapshotDirectedExactReply(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,uint64_t packetSerial,
    NativeAwdlDirectedOriginTx::ExactReplyReceipt *out) {
    using namespace NativeAwdlDirectedOriginTx;
    if(out)*out=ExactReplyReceipt{};
    if(!out||!bridgeLock())return false;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const bool found=directedOriginGate.exactReplyReceipt(
        ticket,packetSerial,out);
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    return found;
}

void snapshotDirectedOriginTx(
    NativeAwdlDirectedOriginTx::Snapshot *out) {
    using namespace NativeAwdlDirectedOriginTx;
    if(!out)return;
    *out=NativeAwdlDirectedOriginTx::Snapshot{};
    out->profileCompiled=true;
    if(!bridgeLock())return;
    DirectedOriginPacketRetirement expired{};
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t now=nowUs();
    if(directedOriginGate.expire(now))
        expired=takeDirectedOriginPacketLocked();
    *out=directedOriginGate.snapshot(now,true);
    out->packetQueued=directedOriginPacket!=nullptr||out->packetQueued;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
    freeDirectedOriginPacket(expired);
}
#endif
void gateObservation(uint32_t blockers) {
    add(GateChecks);set(GateLastBlockers,blockers);
    __atomic_fetch_or(&counters[GateReasonsSeen],uint64_t(blockers),__ATOMIC_RELAXED);
    if(!blockers)add(GateAllowed);
}
bool close() {
    if(!bridgeLock())return true;
    publishClosing();
    revokeRx149DataInput();
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
    revokeDiscoveryRxInput();
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    revokeDirectedDataRxInput();
#endif
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    auto ref=filter;IOSimpleLockUnlockEnableInterrupt(lock,irq);
    if(ref)iflt_detach(ref);
    cancelQueued();
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    revokeDirectedOriginTx();
#endif
    for(unsigned i=0;i<2000;++i) {
        irq=IOSimpleLockLockDisableInterrupt(lock);
        const bool done=(!interface||detached)&&inputCalls==0&&inFlightToken==0
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
            &&replyShadowOutputCalls==0
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
            &&directedOriginOperations==0
#endif
            ;
        ifnet_t dev=done?interface:nullptr;
        if(done){interface=nullptr;rx.head=rx.tail=rx.count=0;memset(rx.values,0,sizeof(rx.values));set(RxPending,0);
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
            interfaceIndex=0;
            revokeDiscoveryRxLocked();
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
            directedRx.head=directedRx.tail=directedRx.count=0;
            memset(directedRx.values,0,sizeof(directedRx.values));
            clearDirectedRxRetryWindowLocked();
            set(DirectedRxPending,0);
#endif
        }
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
        if(done){if(dev)ifnet_release(dev);return true;}IOSleep(1);
    }
    return false; // no unsafe free while callbacks or DMA completion can arrive
}
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
void advanceRx149InterfaceIncarnationForTests() {
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    if(interfaceIncarnation!=UINT64_MAX)++interfaceIncarnation;
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
#endif
void publishClosing() {
    __atomic_store_n(&closingRequested,1u,__ATOMIC_RELEASE);
    if(!bridgeLock())return;
    auto irq=IOSimpleLockLockDisableInterrupt(lock);
    closing=true;radio=false;set(Closing,1);set(LinkReady,0);
    clearRx149RetryWindowLocked();
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
    revokeDiscoveryRxLocked();
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    activeDirectedRxLeaseValid=false;
    activeDirectedRxLease=NativeP2PDirectedDataRxInput::Lease{};
    clearDirectedRxRetryWindowLocked();
    if(activeDirectedRxVersion!=UINT64_MAX)++activeDirectedRxVersion;
    (void)removeDirectedRxItemsLocked(true,0,0,nullptr,nowUs());
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
    // This is a short main-gate publication point: invalidate authority but
    // leave any queued mbuf for close()/revoke to free outside this lock.
    (void)directedOriginGate.revoke(
        nowUs(),NativeAwdlDirectedOriginTx::Reason::Closed);
#endif
#if defined(ITL_NATIVE_AWDL_REPLY_SHADOW_25G332)
    replyShadow.retire(NativeAwdlReplyShadow::Reason::Closing);
#endif
    IOSimpleLockUnlockEnableInterrupt(lock,irq);
}
Snapshot snapshot(){
    Snapshot s{};
    for(unsigned i=0;i<Count;++i)
        s.value[i]=__atomic_load_n(&counters[i],__ATOMIC_ACQUIRE);
    if(bridgeLock()) {
        auto irq=IOSimpleLockLockDisableInterrupt(lock);
        s.rx149Input=rx149Receipt;
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
        s.directedDataRxInput=directedRxReceipt;
        memcpy(s.directedDataRxInput.exactReplies,
               directedExactReplyReceipts,
               sizeof(directedExactReplyReceipts));
#endif
        IOSimpleLockUnlockEnableInterrupt(lock,irq);
    }
    return s;
}
AttachTraceSnapshot attachSnapshot(){return attachTrace.snapshot();}
void noteResidentLookupResult(int result){attachTrace.noteResidentLookupResult(result);}
}
#endif
