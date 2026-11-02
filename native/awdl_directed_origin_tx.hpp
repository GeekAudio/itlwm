// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "awdl_data_frame.hpp"

// Test107's one-shot BSD-origin UDP gate. This header is policy/data only;
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
    uint8_t peerMac[6]{};
    uint8_t nonce[kNonceLength]{};
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

enum class State : uint32_t {
    Closed, Open, Queued, Popping, Spent, Expired, Revoked
};

enum class Reason : uint32_t {
    None, InvalidRequest, WrongProfile, WrongOwner, WrongEpoch,
    WrongInterface, WrongSource, WrongPeer, WrongChannel, Expired,
    Busy, RunReplay, NonceReplay, ReplayTableFull, QueueFull,
    PacketShape, EthernetAddress, Ipv6Address, UdpPorts, Nonce,
    UdpChecksum, StaleTicket, EncodingFailed, CounterExhausted,
    Closed, InterfaceStopped
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
    if (!nonzeroNonce(request.nonce)) return Reason::InvalidRequest;
    return Reason::None;
}

inline Reason validateEthernet(const OpenRequest &request,
                               const uint8_t ownMac[6],
                               const uint8_t *ethernet,size_t length,
                               bool requireFinalChecksum) {
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
    if (memcmp(udp+8,request.nonce,kNonceLength)) return Reason::Nonce;
    if (requireFinalChecksum) {
        const uint16_t checksum=readBe16(udp+6);
        if (!checksum) return Reason::UdpChecksum;
        uint32_t sum=uint32_t(kUdpLength)+17u;
        for (size_t i=8; i<40; i+=2) sum += readBe16(ip+i);
        for (size_t i=40; i<kIpv6Length; i+=2) sum += readBe16(ip+i);
        while (sum>>16) sum=(sum&0xffffu)+(sum>>16);
        if (sum != 0xffffu) return Reason::UdpChecksum;
    }
    return Reason::None;
}

// All calls are serialized by the production bridge lock. Ledger methods do
// no allocation, KPI, mbuf copy/finalize/free, waits, or other external calls.
class Ledger {
    OpenRequest request_{};
    Ticket ticket_{};
    Snapshot value_{};
    uint64_t lastRunSerial_=0;
    uint64_t nextTicketSerial_=0;
    uint8_t nonceHistory_[kRememberedNonceCapacity][kNonceLength]{};
    size_t nonceCount_=0;

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
               value_.state==State::Popping;
    }
    void expireIfNeeded(uint64_t nowUs) {
        if (active() && nowUs >= ticket_.deadlineUs) {
            value_.state=State::Expired;
            value_.terminalReason=Reason::Expired;
            value_.packetQueued=false;
            value_.packetPopping=false;
            bump(&value_.expired);
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
        for (size_t i=0;i<nonceCount_;++i) {
            if (!memcmp(nonceHistory_[i],request.nonce,kNonceLength))
                return reject(Reason::NonceReplay,true);
        }
        if (nonceCount_>=kRememberedNonceCapacity)
            return reject(Reason::ReplayTableFull,true);
        if (nextTicketSerial_==UINT64_MAX)
            return reject(Reason::CounterExhausted);
        if (!bump(&value_.opens)) return false;

        ++nextTicketSerial_;
        request_=request;
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
        memcpy(nonceHistory_[nonceCount_++],request.nonce,kNonceLength);
        lastRunSerial_=request.runSerial;
        value_.state=State::Open;
        value_.lastReject=Reason::None;
        value_.terminalReason=Reason::None;
        value_.ticketPresent=true;
        value_.packetQueued=false;
        value_.packetPopping=false;
        value_.packetSpent=false;
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
        return value_.state==State::Open &&
            current(ticket,nowUs,bridgeReady,activePowerGeneration,
                    interfaceIncarnation);
    }

    void noteRejected(Reason reason) { reject(reason); }

    bool acceptsOutput(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                       uint32_t activePowerGeneration,
                       uint64_t interfaceIncarnation) {
        if (!current(ticket,nowUs,bridgeReady,activePowerGeneration,
                     interfaceIncarnation) || value_.state!=State::Open)
            return reject(nowUs>=ticket_.deadlineUs?Reason::Expired:
                          Reason::StaleTicket);
        if (!bump(&value_.accepted)) return false;
        value_.state=State::Queued;
        value_.packetQueued=true;
        return true;
    }

    bool beginPop(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                  uint32_t activePowerGeneration,
                  uint64_t interfaceIncarnation) {
        if (!current(ticket,nowUs,bridgeReady,activePowerGeneration,
                     interfaceIncarnation) || value_.state!=State::Queued)
            return reject(nowUs>=ticket_.deadlineUs?Reason::Expired:
                          Reason::StaleTicket);
        if (!bump(&value_.pops)) return false;
        value_.state=State::Popping;
        value_.packetQueued=false;
        value_.packetPopping=true;
        return true;
    }

    bool finishPop(const Ticket &ticket,uint64_t nowUs,bool bridgeReady,
                   uint32_t activePowerGeneration,
                   uint64_t interfaceIncarnation,bool encoded) {
        if (!ticketMatches(ticket) || value_.state!=State::Popping)
            return false;
        expireIfNeeded(nowUs);
        value_.packetPopping=false;
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
        // A failed encode is terminal too. The same nonce/run is never retried.
        value_.state=State::Spent;
        value_.packetSpent=true;
        if (encoded) {
            value_.lastReject=Reason::None;
            return bump(&value_.encoded);
        }
        value_.lastReject=Reason::EncodingFailed;
        value_.terminalReason=Reason::EncodingFailed;
        bump(&value_.encodeFailed);
        return false;
    }

    bool close(const Ticket &ticket,uint64_t nowUs) {
        expireIfNeeded(nowUs);
        if (!ticketMatches(ticket)) return reject(Reason::StaleTicket);
        if (active()) {
            value_.state=State::Closed;
            value_.terminalReason=Reason::Closed;
            value_.packetQueued=false;
            value_.packetPopping=false;
            bump(&value_.closes);
        }
        return true;
    }

    bool revoke(uint64_t nowUs,Reason reason=Reason::InterfaceStopped) {
        expireIfNeeded(nowUs);
        if (!active()) return false;
        value_.state=State::Revoked;
        value_.terminalReason=reason;
        value_.packetQueued=false;
        value_.packetPopping=false;
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
    Snapshot snapshot(uint64_t nowUs,bool profileCompiled) {
        expireIfNeeded(nowUs);
        Snapshot copy=value_;
        copy.profileCompiled=profileCompiled;
        return copy;
    }
};

} // namespace NativeAwdlDirectedOriginTx
