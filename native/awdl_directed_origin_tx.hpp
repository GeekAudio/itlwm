// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "awdl_data_frame.hpp"

// Bounded BSD-origin UDP exchange gate. This header is policy/data only;
// the production bridge serializes Ledger calls with its existing BSD lock.
namespace NativeAwdlDirectedOriginTx {

constexpr uint8_t kRocChannelIndex = 6;
constexpr uint64_t kMaximumWindowUs = 100000ULL;
constexpr size_t kNonceLength = 8;
constexpr size_t kEthernetLength = 70;
constexpr size_t kIpv6Length = 56;
constexpr size_t kUdpLength = 16;
constexpr size_t kMpduLength = 96; // Complete 802.11 MPDU; no FCS.
constexpr uint16_t kSourcePort = 49153;
constexpr uint16_t kDestinationPort = 49152;
constexpr size_t kRememberedNonceCapacity = 8;
constexpr size_t kMaximumPackets = 2;

struct Epochs {
    uint32_t context;
    uint32_t power;
    uint32_t station;
    uint32_t roc;
};

inline bool validEpochs(const Epochs &epochs) {
    return epochs.context != 0 && epochs.power != 0 &&
        epochs.station != 0 && epochs.roc != 0;
}

inline bool sameEpochs(const Epochs &left, const Epochs &right) {
    return left.context == right.context && left.power == right.power &&
        left.station == right.station && left.roc == right.roc;
}

struct OpenRequest {
    uint64_t ownerSerial=0;
    uint64_t runSerial=0;
    uint64_t rocStartUs=0;
    uint64_t deadlineUs=0;
    Epochs epochs{};
    uint8_t rocChannelIndex=0;
    // Explicitly armed by the caller; open verifies it against the live
    // address list for the attached BSD ifnet and the actual source MAC.
    uint8_t sourceIPv6[16]{};
    uint8_t peerIPv6[16]{}; // Required for the two-packet exact-echo profile.
    uint8_t peerMac[6]{};
    // Legacy one-packet callers keep using nonce. Test130 supplies exactly
    // two distinct 8-byte nonces in packetNonces when packetCount is 2.
    uint8_t nonce[kNonceLength]{};
    uint8_t packetNonces[kMaximumPackets][kNonceLength]{};
    uint8_t packetCount=1;
};

struct Ticket {
    uint64_t ticketSerial=0;
    uint64_t ownerSerial=0;
    uint64_t runSerial=0;
    uint64_t interfaceIncarnation=0;
    uint64_t rocStartUs=0;
    uint64_t deadlineUs=0;
    uint32_t ifindex=0;
    uint8_t sourceMac[6]{};
    Epochs epochs{};
};

// Packet identity is independent of the run ticket and from Wi-Fi/AWDL
// sequence numbers. The nonce is carried on wire and binds peer echoes.
struct PacketIdentity {
    uint64_t ticketSerial=0;
    uint64_t packetSerial=0;
    uint8_t slot=0xff;
    uint8_t nonce[kNonceLength]{};
};

// Numeric-only immutable reply evidence. Raw MAC/IP/nonce bytes never leave
// the bridge through this snapshot.
struct ExactReplyReceipt {
    uint32_t schemaVersion=1;
    bool valid=false;
    bool captured=false;
    bool delivered=false;
    uint8_t slot=0xff;
    uint64_t ticketSerial=0;
    uint64_t packetSerial=0;
    uint64_t ownerSerial=0;
    uint64_t runSerial=0;
    uint64_t interfaceIncarnation=0;
    uint32_t ifindex=0;
    Epochs epochs{};
    uint64_t doorbellUs=0;
    uint64_t captureUs=0;
    uint64_t inputUs=0;
};

struct PacketSnapshot {
    bool present=false;
    bool outputAccepted=false;
    bool packetQueued=false;
    bool packetPopping=false;
    bool packetSpent=false;
    bool doorbellObserved=false;
    bool txResponseObserved=false;
    bool txSucceeded=false;
    bool replyCaptured=false;
    bool replyDelivered=false;
    bool exactReplyValid=false;
    uint8_t slot=0xff;
    uint64_t packetSerial=0;
    uint64_t doorbellUs=0;
    uint64_t txResponseUs=0;
    uint64_t replyCaptureUs=0;
    uint64_t replyInputUs=0;
};

enum class State : uint32_t {
    // Keep the original Test107 numeric values stable for legacy diagnostics.
    Closed=0, Open=1, Queued=2, Popping=3, Spent=4, Expired=5, Revoked=6,
    AwaitingPacketProof=7, OpenNext=8, QueuedNext=9, PoppingNext=10,
    AwaitingFinalProof=11, Failed=12
};

enum class Reason : uint32_t {
    None, InvalidRequest, WrongProfile, WrongOwner, WrongEpoch,
    WrongInterface, WrongSource, WrongPeer, WrongChannel, Expired,
    Busy, RunReplay, NonceReplay, ReplayTableFull, QueueFull,
    PacketShape, EthernetAddress, Ipv6Address, UdpPorts, Nonce,
    UdpChecksum, StaleTicket, EncodingFailed, CounterExhausted,
    Closed, InterfaceStopped, WrongPacketIdentity, ReplyRejected,
    TxCompletionRejected
};

// Numeric-only diagnostics. No peer/local MAC, IPv6 address, nonce, mbuf, or
// packet bytes are exposed through the snapshot API.
struct Snapshot {
    uint32_t schemaVersion=1;
    State state=State::Closed;
    Reason lastReject=Reason::None;
    Reason terminalReason=Reason::None;
    bool profileCompiled=false;
    bool ticketPresent=false;
    bool packetQueued=false;
    bool packetPopping=false;
    bool packetSpent=false;
    uint8_t packetCount=0;
    uint8_t currentSlot=0xff;
    PacketSnapshot packets[kMaximumPackets]{};
    uint64_t ticketSerial=0;
    uint64_t ownerSerial=0;
    uint64_t runSerial=0;
    uint64_t interfaceIncarnation=0;
    uint64_t rocStartUs=0;
    uint64_t deadlineUs=0;
    uint32_t ifindex=0;
    Epochs epochs{};
    uint64_t opens=0;
    uint64_t accepted=0;
    uint64_t rejected=0;
    uint64_t expired=0;
    uint64_t pops=0;
    uint64_t encoded=0;
    uint64_t encodeFailed=0;
    uint64_t closes=0;
    uint64_t revocations=0;
    uint64_t replayRejected=0;
};

inline uint16_t readBe16(const uint8_t *bytes) {
    return static_cast<uint16_t>((uint16_t(bytes[0]) << 8) | bytes[1]);
}

inline bool validUnicastMac(const uint8_t mac[6]) {
    if (!mac || (mac[0] & 1u)) return false;
    uint8_t any=0;
    for (unsigned i=0; i<6; ++i) any |= mac[i];
    return any != 0;
}

inline bool nonzeroNonce(const uint8_t nonce[kNonceLength]) {
    uint8_t any=0;
    for (size_t i=0; i<kNonceLength; ++i) any |= nonce[i];
    return any != 0;
}

inline bool zeroIpv6(const uint8_t address[16]) {
    uint8_t any=0;
    for(size_t i=0;i<16;++i) any|=address[i];
    return any==0;
}

inline const uint8_t *nonceFor(const OpenRequest &request,size_t slot) {
    if(slot>=request.packetCount)return nullptr;
    return request.packetCount==1?request.nonce:request.packetNonces[slot];
}

inline bool isLinkLocal(const uint8_t address[16]) {
    return address && address[0]==0xfe && (address[1]&0xc0u)==0x80u;
}

inline bool sameTicket(const Ticket &left, const Ticket &right) {
    return left.ticketSerial == right.ticketSerial &&
        left.ownerSerial == right.ownerSerial &&
        left.runSerial == right.runSerial &&
        left.interfaceIncarnation == right.interfaceIncarnation &&
        left.rocStartUs == right.rocStartUs &&
        left.deadlineUs == right.deadlineUs &&
        left.ifindex == right.ifindex &&
        !memcmp(left.sourceMac,right.sourceMac,6) &&
        sameEpochs(left.epochs,right.epochs);
}

inline Reason validateRequest(const OpenRequest &request,
                              uint64_t nowUs,
                              uint32_t activePowerGeneration,
                              uint64_t interfaceIncarnation,
                              uint32_t ifindex,
                              const uint8_t ownMac[6],
                              const uint8_t actualLinkLocal[16]) {
    if (!request.ownerSerial || !request.runSerial ||
        !validEpochs(request.epochs) || !request.rocStartUs ||
        request.rocChannelIndex != kRocChannelIndex ||
        !request.deadlineUs || request.rocStartUs > UINT64_MAX-kMaximumWindowUs ||
        request.deadlineUs <= nowUs || nowUs < request.rocStartUs ||
        request.deadlineUs > request.rocStartUs+kMaximumWindowUs)
        return request.rocChannelIndex != kRocChannelIndex
            ? Reason::WrongChannel : Reason::InvalidRequest;
    if (!activePowerGeneration || request.epochs.power != activePowerGeneration)
        return Reason::WrongEpoch;
    if (!interfaceIncarnation || !ifindex)
        return Reason::WrongInterface;
    if (!validUnicastMac(ownMac) || !actualLinkLocal ||
        !isLinkLocal(request.sourceIPv6) ||
        memcmp(request.sourceIPv6,actualLinkLocal,16))
        return Reason::WrongSource;
    if (!validUnicastMac(request.peerMac) ||
        !memcmp(request.peerMac,ownMac,6))
        return Reason::WrongPeer;
    if(request.packetCount==0||request.packetCount>kMaximumPackets)
        return Reason::InvalidRequest;
    if(request.packetCount==1) {
        if(!nonzeroNonce(request.nonce))return Reason::InvalidRequest;
        if(nonzeroNonce(request.packetNonces[0])&&
           memcmp(request.packetNonces[0],request.nonce,kNonceLength))
            return Reason::InvalidRequest;
    } else {
        if(!nonzeroNonce(request.packetNonces[0])||
           !nonzeroNonce(request.packetNonces[1])||
           !memcmp(request.packetNonces[0],request.packetNonces[1],kNonceLength)||
           !isLinkLocal(request.peerIPv6)||zeroIpv6(request.peerIPv6))
            return Reason::InvalidRequest;
    }
    return Reason::None;
}

inline Reason validateEthernet(const OpenRequest &request,
                               const uint8_t ownMac[6],
                               const uint8_t *ethernet,size_t length,
                               bool requireFinalChecksum,
                               uint8_t *packetSlot=nullptr) {
    if (!ethernet || length != kEthernetLength ||
        ethernet[12] != 0x86 || ethernet[13] != 0xdd)
        return Reason::PacketShape;
    const uint8_t expectedDestination[6]={0x33,0x33,0,0,0,1};
    if (memcmp(ethernet,expectedDestination,6) ||
        memcmp(ethernet+6,ownMac,6))
        return Reason::EthernetAddress;
    const uint8_t *ip=ethernet+14;
    const uint8_t expectedIpv6Destination[16]={
        0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if ((ip[0]>>4) != 6 || readBe16(ip+4) != kUdpLength ||
        ip[6] != 17 || ip[7] != 1)
        return Reason::PacketShape; // No extension/fragment headers allowed.
    if (memcmp(ip+8,request.sourceIPv6,16) ||
        memcmp(ip+24,expectedIpv6Destination,16))
        return Reason::Ipv6Address;
    const uint8_t *udp=ip+40;
    if (readBe16(udp) != kSourcePort ||
        readBe16(udp+2) != kDestinationPort ||
        readBe16(udp+4) != kUdpLength)
        return Reason::UdpPorts;
    uint8_t matchedSlot=0xff;
    for(uint8_t slot=0;slot<request.packetCount;++slot) {
        const uint8_t *expected=nonceFor(request,slot);
        if(expected&&!memcmp(udp+8,expected,kNonceLength)) {
            matchedSlot=slot;
            break;
        }
    }
    if(matchedSlot==0xff)return Reason::Nonce;
    if (requireFinalChecksum) {
        const uint16_t checksum=readBe16(udp+6);
        if (!checksum) return Reason::UdpChecksum;
        uint32_t sum=uint32_t(kUdpLength)+17u;
        for (size_t i=8; i<40; i+=2) sum += readBe16(ip+i);
        for (size_t i=40; i<kIpv6Length; i+=2) sum += readBe16(ip+i);
        while (sum>>16) sum=(sum&0xffffu)+(sum>>16);
        if (sum != 0xffffu) return Reason::UdpChecksum;
    }
    if(packetSlot)*packetSlot=matchedSlot;
    return Reason::None;
}

inline Reason validateExactReply(const OpenRequest &request,
                                 const uint8_t ownMac[6],
                                 const uint8_t peerMac[6],
                                 const NativeAwdlData::PacketView &packet,
                                 uint8_t *packetSlot=nullptr) {
    const uint8_t *ipv6=packet.ipv6Packet;
    const size_t length=packet.ipv6Length;
    if(!ipv6||request.packetCount!=kMaximumPackets||
       length!=kIpv6Length|| (ipv6[0]>>4)!=6||
       readBe16(ipv6+4)!=kUdpLength||ipv6[6]!=17||ipv6[7]!=1)
        return Reason::PacketShape;
    if(memcmp(ipv6+8,request.peerIPv6,16)||
       memcmp(ipv6+24,request.sourceIPv6,16))
        return Reason::Ipv6Address;
    const uint8_t *udp=ipv6+40;
    if(readBe16(udp)!=kDestinationPort||
       readBe16(udp+2)!=kSourcePort||readBe16(udp+4)!=kUdpLength)
        return Reason::UdpPorts;
    uint8_t matchedSlot=0xff;
    for(uint8_t slot=0;slot<request.packetCount;++slot) {
        const uint8_t *expected=nonceFor(request,slot);
        if(expected&&!memcmp(udp+8,expected,kNonceLength)) {
            matchedSlot=slot;
            break;
        }
    }
    if(matchedSlot==0xff)return Reason::Nonce;

    if(!validUnicastMac(ownMac)||!validUnicastMac(peerMac)||
       memcmp(peerMac,request.peerMac,6)||
       memcmp(packet.sourceAddress,peerMac,6)||
       memcmp(packet.destinationAddress,ownMac,6))
        return Reason::WrongPeer;
    // Validate the complete IPv6 UDP checksum, including both IPv6 addresses
    // and the ICMP-style next-header pseudo-header value.
    const uint16_t checksum=readBe16(udp+6);
    if(!checksum)return Reason::UdpChecksum;
    uint32_t sum=uint32_t(kUdpLength)+17u;
    for(size_t i=8;i<40;i+=2)sum+=readBe16(ipv6+i);
    for(size_t i=40;i<kIpv6Length;i+=2)sum+=readBe16(ipv6+i);
    while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    if(sum!=0xffffu)return Reason::UdpChecksum;
    if(packetSlot)*packetSlot=matchedSlot;
    return Reason::None;
}

// All calls are serialized by the production bridge lock. Ledger methods do
// no allocation, KPI, mbuf copy/finalize/free, waits, or other external calls.
class Ledger {
    struct Slot {
        PacketIdentity identity{};
        PacketSnapshot snapshot{};
        bool used=false;
    };
    OpenRequest request_{};
    Ticket ticket_{};
    Snapshot value_{};
    uint64_t lastRunSerial_=0;
    uint64_t nextTicketSerial_=0;
    uint64_t nextPacketSerial_=0;
    uint8_t nonceHistory_[kRememberedNonceCapacity][kNonceLength]{};
    size_t nonceCount_=0;
    Slot slots_[kMaximumPackets]{};

    bool bump(uint64_t *counter) {
        if (!counter || *counter == UINT64_MAX) {
            value_.lastReject=Reason::CounterExhausted;
            value_.terminalReason=Reason::CounterExhausted;
            value_.state=State::Revoked;
            return false;
        }
        ++*counter;
        return true;
    }
    bool reject(Reason reason,bool replay=false) {
        value_.lastReject=reason;
        if (replay) bump(&value_.replayRejected);
        bump(&value_.rejected);
        return false;
    }
    bool ticketMatches(const Ticket &ticket) const {
        return value_.ticketPresent && sameTicket(ticket_,ticket);
    }
    bool active() const {
        return value_.state==State::Open || value_.state==State::Queued ||
               value_.state==State::Popping ||
               value_.state==State::AwaitingPacketProof ||
               value_.state==State::OpenNext ||
               value_.state==State::QueuedNext ||
               value_.state==State::PoppingNext ||
               value_.state==State::AwaitingFinalProof;
    }
    void expireIfNeeded(uint64_t nowUs) {
        if (active() && nowUs >= ticket_.deadlineUs) {
            value_.state=State::Expired;
            value_.terminalReason=Reason::Expired;
            bump(&value_.expired);
        }
    }
    bool identityMatches(const PacketIdentity &identity,uint8_t slot) const {
        return slot<request_.packetCount&&slots_[slot].used&&
            identity.ticketSerial==ticket_.ticketSerial&&
            identity.packetSerial==slots_[slot].identity.packetSerial&&
            identity.slot==slot&&
            !memcmp(identity.nonce,slots_[slot].identity.nonce,kNonceLength);
    }
    bool outputWindowOpen(uint8_t slot) const {
        if(slot>=request_.packetCount||!slots_[slot].used||
           slots_[slot].snapshot.outputAccepted)
            return false;
        if(slot==0)return value_.state==State::Open;
        const auto &first=slots_[0].snapshot;
        return slot==1&&value_.state==State::OpenNext&&
            first.txResponseObserved&&first.txSucceeded&&
            first.exactReplyValid&&first.replyDelivered;
    }
    void updateSessionAfterProof(uint8_t slot,uint64_t nowUs) {
        if(nowUs>=ticket_.deadlineUs||value_.state==State::Expired||
           value_.state==State::Revoked||value_.state==State::Closed||
           value_.state==State::Failed)
            return;
        const auto &packet=slots_[slot].snapshot;
        if(!packet.txResponseObserved||!packet.txSucceeded||
           !packet.exactReplyValid||!packet.replyDelivered||
           !packet.doorbellObserved||packet.doorbellUs>=ticket_.deadlineUs||
           packet.txResponseUs<packet.doorbellUs||
           packet.txResponseUs>=ticket_.deadlineUs||
           packet.replyCaptureUs<packet.doorbellUs||
           packet.replyInputUs>=ticket_.deadlineUs)
            return;
        if(slot==0&&request_.packetCount==2&&
           value_.state==State::AwaitingPacketProof)
            value_.state=State::OpenNext;
        else if(slot+1==request_.packetCount&&
                value_.state==State::AwaitingFinalProof) {
            value_.state=State::Spent;
            value_.packetSpent=true;
        }
    }
public:
    bool open(const OpenRequest &request,uint64_t nowUs,
              uint32_t activePowerGeneration,uint64_t interfaceIncarnation,
              uint32_t ifindex,const uint8_t ownMac[6],
              const uint8_t actualLinkLocal[16],Ticket *out) {
        if (out) *out=Ticket{};
        expireIfNeeded(nowUs);
        if (!out) return reject(Reason::InvalidRequest);
        if (active()) return reject(Reason::Busy);
        const Reason validation=validateRequest(request,nowUs,
            activePowerGeneration,interfaceIncarnation,ifindex,ownMac,
            actualLinkLocal);
        if (validation!=Reason::None) return reject(validation);
        if (request.runSerial<=lastRunSerial_)
            return reject(Reason::RunReplay,true);
        if(nonceCount_+request.packetCount>kRememberedNonceCapacity)
            return reject(Reason::ReplayTableFull,true);
        for(size_t packet=0;packet<request.packetCount;++packet) {
            const uint8_t *nonce=nonceFor(request,packet);
            if(!nonce||!nonzeroNonce(nonce))
                return reject(Reason::InvalidRequest);
            if(packet&& !memcmp(nonce,nonceFor(request,0),kNonceLength))
                return reject(Reason::NonceReplay,true);
            for(size_t i=0;i<nonceCount_;++i) {
                if(!memcmp(nonceHistory_[i],nonce,kNonceLength))
                    return reject(Reason::NonceReplay,true);
            }
        }
        if (nextTicketSerial_==UINT64_MAX)
            return reject(Reason::CounterExhausted);
        if(nextPacketSerial_>UINT64_MAX-request.packetCount)
            return reject(Reason::CounterExhausted);
        if (!bump(&value_.opens)) return false;

        ++nextTicketSerial_;
        request_=request;
        memset(slots_,0,sizeof(slots_));
        for(uint8_t slot=0;slot<request.packetCount;++slot) {
            Slot &entry=slots_[slot];
            entry.used=true;
            entry.identity.ticketSerial=nextTicketSerial_;
            entry.identity.packetSerial=++nextPacketSerial_;
            entry.identity.slot=slot;
            memcpy(entry.identity.nonce,nonceFor(request,slot),kNonceLength);
            entry.snapshot.present=true;
            entry.snapshot.slot=slot;
            entry.snapshot.packetSerial=entry.identity.packetSerial;
            memcpy(nonceHistory_[nonceCount_++],entry.identity.nonce,kNonceLength);
        }
        ticket_=Ticket{};
        ticket_.ticketSerial=nextTicketSerial_;
        ticket_.ownerSerial=request.ownerSerial;
        ticket_.runSerial=request.runSerial;
        ticket_.interfaceIncarnation=interfaceIncarnation;
        ticket_.rocStartUs=request.rocStartUs;
        ticket_.deadlineUs=request.deadlineUs;
        ticket_.ifindex=ifindex;
        memcpy(ticket_.sourceMac,ownMac,6);
        ticket_.epochs=request.epochs;
        lastRunSerial_=request.runSerial;
        value_.state=State::Open;
        value_.lastReject=Reason::None;
        value_.terminalReason=Reason::None;
        value_.ticketPresent=true;
        value_.packetQueued=false;
        value_.packetPopping=false;
        value_.packetSpent=false;
        value_.packetCount=request.packetCount;
        value_.currentSlot=0;
        for(size_t slot=0;slot<kMaximumPackets;++slot)
            value_.packets[slot]=slots_[slot].snapshot;
        value_.ticketSerial=ticket_.ticketSerial;
        value_.ownerSerial=ticket_.ownerSerial;
        value_.runSerial=ticket_.runSerial;
        value_.interfaceIncarnation=ticket_.interfaceIncarnation;
        value_.rocStartUs=ticket_.rocStartUs;
        value_.deadlineUs=ticket_.deadlineUs;
        value_.ifindex=ticket_.ifindex;
        value_.epochs=ticket_.epochs;
        *out=ticket_;
        return true;
    }

    bool current(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                 uint32_t activePowerGeneration,
                 uint64_t interfaceIncarnation) {
        expireIfNeeded(nowUs);
        return active() && ticketMatches(ticket) && bridgeReady &&
            activePowerGeneration==ticket_.epochs.power &&
            interfaceIncarnation==ticket_.interfaceIncarnation &&
            nowUs>=ticket_.rocStartUs && nowUs<ticket_.deadlineUs;
    }

    bool canAcceptOutput(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                         uint32_t activePowerGeneration,
                         uint64_t interfaceIncarnation) {
        if(!current(ticket,nowUs,bridgeReady,activePowerGeneration,
                    interfaceIncarnation))return false;
        for(uint8_t slot=0;slot<request_.packetCount;++slot)
            if(outputWindowOpen(slot))return true;
        return false;
    }

    void noteRejected(Reason reason) { reject(reason); }

    bool acceptsOutput(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                       uint32_t activePowerGeneration,
                       uint64_t interfaceIncarnation) {
        return acceptsOutput(ticket,0,nowUs,bridgeReady,
            activePowerGeneration,interfaceIncarnation);
    }

    bool acceptsOutput(const Ticket &ticket,uint8_t slot,uint64_t nowUs,
                       bool bridgeReady,uint32_t activePowerGeneration,
                       uint64_t interfaceIncarnation) {
        if (!current(ticket,nowUs,bridgeReady,activePowerGeneration,
                     interfaceIncarnation) || !outputWindowOpen(slot))
            return reject(nowUs>=ticket_.deadlineUs?Reason::Expired:
                          Reason::StaleTicket);
        if (!bump(&value_.accepted)) return false;
        slots_[slot].snapshot.outputAccepted=true;
        slots_[slot].snapshot.packetQueued=true;
        value_.state=slot==0?State::Queued:State::QueuedNext;
        value_.currentSlot=slot;
        value_.packetQueued=true;
        value_.packets[slot]=slots_[slot].snapshot;
        return true;
    }

    bool beginPop(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                  uint32_t activePowerGeneration,
                  uint64_t interfaceIncarnation) {
        PacketIdentity identity{};
        if(value_.currentSlot<request_.packetCount)
            identity=slots_[value_.currentSlot].identity;
        return beginPop(ticket,identity,nowUs,bridgeReady,
                        activePowerGeneration,interfaceIncarnation);
    }

    bool beginPop(const Ticket &ticket,const PacketIdentity &identity,
                  uint64_t nowUs,bool bridgeReady,
                  uint32_t activePowerGeneration,
                  uint64_t interfaceIncarnation) {
        const uint8_t slot=identity.slot;
        if (!current(ticket,nowUs,bridgeReady,activePowerGeneration,
                     interfaceIncarnation) ||
            !identityMatches(identity,slot)||
            (slot==0?value_.state!=State::Queued:
                     value_.state!=State::QueuedNext)||
            !slots_[slot].snapshot.packetQueued)
            return reject(nowUs>=ticket_.deadlineUs?Reason::Expired:
                          Reason::WrongPacketIdentity);
        if (!bump(&value_.pops)) return false;
        value_.state=slot==0?State::Popping:State::PoppingNext;
        slots_[slot].snapshot.packetQueued=false;
        slots_[slot].snapshot.packetPopping=true;
        value_.packetQueued=false;
        value_.packetPopping=true;
        value_.currentSlot=slot;
        value_.packets[slot]=slots_[slot].snapshot;
        return true;
    }

    // The bridge calls this only after it removes the queued mbuf from the
    // shared output slot. A packet already moved into an in-flight pop is
    // tracked by packetPopping and is intentionally left alone here.
    bool retireQueuedPacket(const Ticket &ticket,
                            const PacketIdentity &identity) {
        if(!ticketMatches(ticket)||!identityMatches(identity,identity.slot))
            return false;
        auto &packet=slots_[identity.slot].snapshot;
        if(!packet.packetQueued)return true;
        packet.packetQueued=false;
        value_.packetQueued=false;
        value_.packets[identity.slot]=packet;
        return true;
    }

    bool queuedPacketOwned(const Ticket &ticket,
                           const PacketIdentity &identity) const {
        return ticketMatches(ticket)&&
            identityMatches(identity,identity.slot)&&
            slots_[identity.slot].snapshot.packetQueued;
    }

    bool finishPop(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                   uint32_t activePowerGeneration,
                   uint64_t interfaceIncarnation,bool encoded) {
        PacketIdentity identity{};
        if(value_.currentSlot<request_.packetCount)
            identity=slots_[value_.currentSlot].identity;
        return finishPop(ticket,identity,nowUs,bridgeReady,
                         activePowerGeneration,interfaceIncarnation,encoded);
    }

    bool finishPop(const Ticket &ticket,const PacketIdentity &identity,
                   uint64_t nowUs,bool bridgeReady,
                   uint32_t activePowerGeneration,
                   uint64_t interfaceIncarnation,bool encoded) {
        const uint8_t slot=identity.slot;
        if (!ticketMatches(ticket)||!identityMatches(identity,slot)||
            !slots_[slot].snapshot.packetPopping)
            return false;
        expireIfNeeded(nowUs);
        auto &packet=slots_[slot].snapshot;
        // The lock-free owner is held outside the bridge lock while encoding.
        // Clear its live-operation marker on every return path, including a
        // concurrent close, revoke, or deadline transition.
        packet.packetPopping=false;
        value_.packetPopping=false;
        value_.packets[slot]=packet;
        if(value_.state!=(slot==0?State::Popping:State::PoppingNext))
            return false;
        if (!active() || !bridgeReady ||
            activePowerGeneration!=ticket_.epochs.power ||
            interfaceIncarnation!=ticket_.interfaceIncarnation ||
            nowUs<ticket_.rocStartUs || nowUs>=ticket_.deadlineUs) {
            if (value_.state!=State::Expired) {
                value_.state=State::Revoked;
                value_.terminalReason=Reason::InterfaceStopped;
            }
            return false;
        }
        packet.packetSpent=true;
        value_.packetPopping=false;
        value_.packetSpent=true;
        if (encoded) {
            value_.lastReject=Reason::None;
            if(!bump(&value_.encoded))return false;
            value_.state=request_.packetCount==1?State::Spent:
                (slot==0?State::AwaitingPacketProof:State::AwaitingFinalProof);
            value_.packets[slot]=packet;
            return true;
        }
        value_.state=request_.packetCount==1?State::Spent:State::Failed;
        value_.lastReject=Reason::EncodingFailed;
        value_.terminalReason=Reason::EncodingFailed;
        bump(&value_.encodeFailed);
        value_.packets[slot]=packet;
        return false;
    }

    bool recordTxDoorbell(const Ticket &ticket,const PacketIdentity &identity,
                          uint64_t submitUs,uint64_t nowUs,
                          uint32_t activePowerGeneration,
                          uint64_t interfaceIncarnation,
                          bool authorizationAllowed=true) {
        if(!ticketMatches(ticket))return reject(Reason::WrongPacketIdentity);
        expireIfNeeded(nowUs);
        if(!ticketMatches(ticket)||!identityMatches(identity,identity.slot)||
           !activePowerGeneration||activePowerGeneration!=ticket_.epochs.power||
           interfaceIncarnation!=ticket_.interfaceIncarnation||
           submitUs<ticket_.rocStartUs||nowUs<submitUs)
            return reject(Reason::WrongPacketIdentity);
        auto &packet=slots_[identity.slot].snapshot;
        if(!packet.packetSpent||packet.doorbellObserved||
           value_.state==State::Revoked||value_.state==State::Failed)
            return reject(Reason::WrongPacketIdentity);
        packet.doorbellObserved=true;
        packet.doorbellUs=submitUs;
        if(packet.replyCaptured&&packet.replyCaptureUs<submitUs) {
            // RX can race the HAL's post-gate doorbell note. A candidate seen
            // before the actual submit is stale evidence, not a consumed echo.
            packet.replyCaptured=false;
            packet.replyDelivered=false;
            packet.replyCaptureUs=0;
            packet.replyInputUs=0;
        }
        packet.exactReplyValid=authorizationAllowed&&active()&&
            submitUs<ticket_.deadlineUs&&
            packet.replyCaptured&&packet.replyDelivered&&
            packet.replyCaptureUs>=submitUs;
        value_.packets[identity.slot]=packet;
        if(authorizationAllowed)
            updateSessionAfterProof(identity.slot,nowUs);
        return true;
    }

    bool recordTxCompletion(const Ticket &ticket,const PacketIdentity &identity,
                            bool success,uint64_t responseUs,uint64_t nowUs,
                            uint32_t activePowerGeneration,
                            uint64_t interfaceIncarnation,
                            bool authorizationAllowed=true) {
        if(!ticketMatches(ticket))return reject(Reason::TxCompletionRejected);
        expireIfNeeded(nowUs);
        if(!ticketMatches(ticket)||!identityMatches(identity,identity.slot)||
           !activePowerGeneration||activePowerGeneration!=ticket_.epochs.power||
           interfaceIncarnation!=ticket_.interfaceIncarnation||
           responseUs<ticket_.rocStartUs||nowUs<responseUs)
            return reject(Reason::TxCompletionRejected);
        auto &packet=slots_[identity.slot].snapshot;
        if(!packet.doorbellObserved||packet.txResponseObserved||
           responseUs<packet.doorbellUs)
            return reject(Reason::TxCompletionRejected);
        packet.txResponseObserved=true;
        packet.txSucceeded=success;
        packet.txResponseUs=responseUs;
        if(!success) {
            if(active()) {
                value_.state=State::Failed;
                value_.terminalReason=Reason::TxCompletionRejected;
            }
            value_.lastReject=Reason::TxCompletionRejected;
        } else {
            packet.exactReplyValid=authorizationAllowed&&active()&&
                packet.replyCaptured&&packet.replyDelivered&&
                packet.replyCaptureUs>=packet.doorbellUs;
            if(authorizationAllowed)
                updateSessionAfterProof(identity.slot,nowUs);
        }
        value_.packets[identity.slot]=packet;
        return true;
    }

    bool recordExactReplyCaptured(const Ticket &ticket,
                                  const PacketIdentity &identity,
                                  uint64_t captureUs,uint64_t nowUs,
                                  uint32_t activePowerGeneration,
                                  uint64_t interfaceIncarnation) {
        if(!ticketMatches(ticket))return reject(Reason::ReplyRejected);
        expireIfNeeded(nowUs);
        if(!ticketMatches(ticket)||!identityMatches(identity,identity.slot)||
           !activePowerGeneration||activePowerGeneration!=ticket_.epochs.power||
           interfaceIncarnation!=ticket_.interfaceIncarnation||
           captureUs<ticket_.rocStartUs||captureUs>=ticket_.deadlineUs||
           nowUs<captureUs||nowUs>=ticket_.deadlineUs||!active())
            return reject(Reason::ReplyRejected);
        auto &packet=slots_[identity.slot].snapshot;
        if(packet.doorbellObserved&&captureUs<packet.doorbellUs)
            return reject(Reason::ReplyRejected);
        if(packet.replyCaptured||
           (value_.state==State::Revoked||value_.state==State::Closed||
            value_.state==State::Failed))
            return reject(Reason::ReplyRejected);
        packet.replyCaptured=true;
        packet.replyCaptureUs=captureUs;
        // RX may beat the HAL's post-gate doorbell note. Preserve it as a
        // candidate; only successful ifnet_input plus an observed actual
        // submit timestamp may promote it to an exact reply proof.
        packet.exactReplyValid=false;
        value_.packets[identity.slot]=packet;
        return true;
    }

    bool recordExactReplyDelivered(const Ticket &ticket,
                                   const PacketIdentity &identity,
                                   uint64_t captureUs,uint64_t inputUs,
                                   uint64_t nowUs,
                                   uint32_t activePowerGeneration,
                                   uint64_t interfaceIncarnation,
                                   bool authorizationAllowed=true) {
        if(!ticketMatches(ticket))return reject(Reason::ReplyRejected);
        expireIfNeeded(nowUs);
        if(!ticketMatches(ticket)||!identityMatches(identity,identity.slot)||
           !activePowerGeneration||activePowerGeneration!=ticket_.epochs.power||
           interfaceIncarnation!=ticket_.interfaceIncarnation||
           inputUs<captureUs||inputUs>=ticket_.deadlineUs||nowUs<inputUs||
           nowUs>=ticket_.deadlineUs||!active()||
           value_.state==State::Revoked||value_.state==State::Closed||
           value_.state==State::Failed||value_.state==State::Expired)
            return reject(Reason::ReplyRejected);
        auto &packet=slots_[identity.slot].snapshot;
        if(!packet.replyCaptured||packet.replyCaptureUs!=captureUs||
           packet.replyDelivered||
           (packet.doorbellObserved&&captureUs<packet.doorbellUs))
            return reject(Reason::ReplyRejected);
        packet.replyDelivered=true;
        packet.replyInputUs=inputUs;
        packet.exactReplyValid=authorizationAllowed&&
            packet.doorbellObserved&&
            packet.replyCaptureUs>=packet.doorbellUs;
        value_.packets[identity.slot]=packet;
        if(authorizationAllowed)
            updateSessionAfterProof(identity.slot,nowUs);
        return packet.exactReplyValid;
    }

    bool exactReplyReceipt(const Ticket &ticket,uint64_t packetSerial,
                           ExactReplyReceipt *out) const {
        if(out)*out=ExactReplyReceipt{};
        if(!out||!ticketMatches(ticket))return false;
        for(uint8_t slot=0;slot<request_.packetCount;++slot) {
            const auto &identity=slots_[slot].identity;
            const auto &packet=slots_[slot].snapshot;
            if(identity.packetSerial!=packetSerial)continue;
            out->valid=packet.exactReplyValid&&packet.replyDelivered;
            out->captured=packet.replyCaptured;
            out->delivered=packet.replyDelivered;
            out->slot=slot;
            out->ticketSerial=ticket_.ticketSerial;
            out->packetSerial=identity.packetSerial;
            out->ownerSerial=ticket_.ownerSerial;
            out->runSerial=ticket_.runSerial;
            out->interfaceIncarnation=ticket_.interfaceIncarnation;
            out->ifindex=ticket_.ifindex;
            out->epochs=ticket_.epochs;
            out->doorbellUs=packet.doorbellUs;
            out->captureUs=packet.replyCaptureUs;
            out->inputUs=packet.replyInputUs;
            return true;
        }
        return false;
    }

    bool invalidateExactReplyAfterEnd(const Ticket &ticket,
                                      const PacketIdentity &identity) {
        if(!ticketMatches(ticket)||!identityMatches(identity,identity.slot))
            return false;
        auto &packet=slots_[identity.slot].snapshot;
        packet.exactReplyValid=false;
        value_.packets[identity.slot]=packet;
        if(identity.slot==0&&value_.state==State::OpenNext)
            value_.state=State::AwaitingPacketProof;
        else if(identity.slot==1&&value_.state==State::Spent)
            value_.state=State::AwaitingFinalProof;
        return true;
    }

    bool close(const Ticket &ticket,uint64_t nowUs) {
        expireIfNeeded(nowUs);
        if (!ticketMatches(ticket)) return reject(Reason::StaleTicket);
        if (active()) {
            value_.state=State::Closed;
            value_.terminalReason=Reason::Closed;
            bump(&value_.closes);
        }
        return true;
    }

    bool revoke(uint64_t nowUs,Reason reason=Reason::InterfaceStopped) {
        expireIfNeeded(nowUs);
        if (!active()) return false;
        value_.state=State::Revoked;
        value_.terminalReason=reason;
        bump(&value_.revocations);
        return true;
    }

    bool expire(uint64_t nowUs) {
        const State before=value_.state;
        expireIfNeeded(nowUs);
        return before!=value_.state && value_.state==State::Expired;
    }

    const Ticket &ticket() const { return ticket_; }
    const OpenRequest &request() const { return request_; }
    bool packetIdentity(const Ticket &ticket,uint8_t slot,
                        PacketIdentity *out) const {
        if(out)*out=PacketIdentity{};
        if(!out||!ticketMatches(ticket)||slot>=request_.packetCount||
           !slots_[slot].used)return false;
        *out=slots_[slot].identity;
        return true;
    }
    Snapshot snapshot(uint64_t nowUs,bool profileCompiled) {
        expireIfNeeded(nowUs);
        Snapshot copy=value_;
        copy.profileCompiled=profileCompiled;
        copy.packetCount=request_.packetCount;
        for(size_t slot=0;slot<kMaximumPackets;++slot)
            copy.packets[slot]=slots_[slot].snapshot;
        return copy;
    }
};

} // namespace NativeAwdlDirectedOriginTx
