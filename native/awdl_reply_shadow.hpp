// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "p2p_rx149_data_input.hpp"

// Observation only: owns fixed byte copies, never a packet/ifnet/firmware object.
// All Ledger access is serialized by the production bridge lock.
namespace NativeAwdlReplyShadow {
constexpr size_t kIpLength=56, kEthernetLength=70;
constexpr bool firmwareTransmitAllowed() { return false; }
enum class State : uint32_t {
    Disabled, AwaitRequest, InputPending, InputConfirmed,
    ReplyPendingInput, Associated, Retired
};
enum class Reason : uint32_t {
    None, Disabled, InvalidConfig, WrongAuthority, Expired, FrameShape,
    Address, Ports, Payload, Checksum, NoRequest, RequestCapacity,
    ReplyCapacity, InputFailed, Revoked, Closing, CounterExhausted
};
struct Config {
    bool enabled=false;
    uint64_t runSerial=0, ownerSerial=0, interfaceIncarnation=0, deadlineUs=0;
    NativeP2PRx149DataInput::Epochs epochs{};
    uint8_t ownMac[6]{},peerMac[6]{},ownIp[16]{},peerIp[16]{},nonce[8]{};
    uint16_t localPort=49153,peerPort=49152;
};
struct Authority {
    NativeP2PRx149DataInput::Lease lease{};
    uint64_t version=0,incarnation=0;
    bool ready=false;
};
struct Snapshot {
    uint32_t schemaVersion=1;
    State state=State::Disabled;
    Reason lastReject=Reason::None,retireReason=Reason::None;
    bool configured=false,txArmed=false,associationCurrent=false;
    bool requestPresent=false,inputConfirmed=false,replyPresent=false;
    uint64_t runSerial=0,ownerSerial=0,interfaceIncarnation=0,guardVersion=0;
    NativeP2PRx149DataInput::Epochs epochs{};
    uint64_t requestSequence=0,captureUs=0,requestUs=0,inputUs=0,inputReturnUs=0,replyUs=0,deadlineUs=0;
    uint64_t requests=0,replies=0,rejections=0,requestOverflow=0,replyOverflow=0;
    uint16_t wifiSequenceControl=0,awdlSequence=0;
    uint16_t replyIpLength=0;
    uint8_t replyIp[kIpLength]{};
};
inline uint16_t be16(const uint8_t *b) {return uint16_t((uint16_t(b[0])<<8)|b[1]);}
inline bool ll(const uint8_t *ip) {return ip[0]==0xfe&&ip[1]==0x80;}
inline bool unicast(const uint8_t *mac) {
    uint8_t any=0;for(unsigned i=0;i<6;++i)any|=mac[i];return any&&!(mac[0]&1u);
}
inline bool ownEui(const uint8_t *ip,const uint8_t *mac) {
    const uint8_t zero[6]{};
    const uint8_t iid[8]={uint8_t(mac[0]^2u),mac[1],mac[2],0xff,0xfe,mac[3],mac[4],mac[5]};
    return ll(ip)&&!memcmp(ip+2,zero,6)&&!memcmp(ip+8,iid,8);
}
inline bool udpChecksum(const uint8_t *ip) {
    if(be16(ip+46)==0)return false;
    uint32_t sum=16+17;
    for(unsigned i=8;i<40;i+=2)sum+=be16(ip+i);
    for(unsigned i=40;i<56;i+=2)sum+=be16(ip+i);
    while(sum>>16)sum=(sum&0xffff)+(sum>>16);
    return sum==0xffff;
}
inline Reason packetReason(const Config &c,const uint8_t *ip,size_t len,bool reply) {
    if(!ip||len!=kIpLength||(ip[0]>>4)!=6||be16(ip+4)!=16||ip[6]!=17||ip[7]!=1||be16(ip+44)!=16)
        return Reason::FrameShape;
    if(memcmp(ip+8,reply?c.ownIp:c.peerIp,16)||memcmp(ip+24,reply?c.peerIp:c.ownIp,16))
        return Reason::Address;
    if(be16(ip+40)!=(reply?c.localPort:c.peerPort)||be16(ip+42)!=(reply?c.peerPort:c.localPort))
        return Reason::Ports;
    if(memcmp(ip+48,c.nonce,8))return Reason::Payload;
    if(!udpChecksum(ip))return Reason::Checksum;
    return Reason::None;
}
class Ledger {
    Config config_{};
    Snapshot value_{};
    uint64_t startUs_=0;
    bool bump(uint64_t &n) {
        if(n==UINT64_MAX){retire(Reason::CounterExhausted);return false;}
        ++n;return true;
    }
    bool reject(Reason r) {value_.lastReject=r;bump(value_.rejections);return false;}
public:
    bool configured() const {return value_.configured;}
    void rejected(Reason reason) {if(value_.configured)reject(reason);}
    const Config &config() const {return config_;}
    bool current(const Authority &a,uint64_t now) const {
        return value_.configured&&value_.state!=State::Retired&&a.ready&&
            a.version==value_.guardVersion&&a.incarnation==config_.interfaceIncarnation&&
            a.lease.ownerSerial==config_.ownerSerial&&a.lease.startUs==startUs_&&
            (!value_.requestPresent||now>=value_.requestUs)&&
            (!value_.replyPresent||now>=value_.replyUs)&&
            (!value_.inputConfirmed||now>=value_.inputReturnUs)&&
            NativeP2PRx149DataInput::sameEpochs(a.lease.epochs,config_.epochs)&&
            NativeP2PRx149DataInput::leaseCurrent(a.lease,now)&&now<config_.deadlineUs;
    }
    bool configure(const Config &c,const Authority &a,uint64_t now) {
        // One immutable run per bridge lifetime. A terminal record is never reused.
        if(value_.configured)return reject(Reason::RequestCapacity);
        if(!c.enabled)return false;
        uint8_t any=0;for(unsigned i=0;i<8;++i)any|=c.nonce[i];
        if(!c.runSerial||!c.ownerSerial||!c.interfaceIncarnation||!any||
           !unicast(c.ownMac)||!unicast(c.peerMac)||!memcmp(c.ownMac,c.peerMac,6)||
           !ownEui(c.ownIp,c.ownMac)||!ll(c.peerIp)||!memcmp(c.ownIp,c.peerIp,16)||
           !c.localPort||!c.peerPort||c.localPort==c.peerPort||
           !a.ready||!a.version||a.incarnation!=c.interfaceIncarnation||
           a.lease.ownerSerial!=c.ownerSerial||
           !NativeP2PRx149DataInput::sameEpochs(a.lease.epochs,c.epochs)||
           !NativeP2PRx149DataInput::leaseCurrent(a.lease,now)||
           a.lease.startUs>UINT64_MAX-99328||c.deadlineUs<=now||
           c.deadlineUs>a.lease.startUs+99328)return reject(Reason::InvalidConfig);
        config_=c;startUs_=a.lease.startUs;
        value_.configured=true;value_.state=State::AwaitRequest;
        value_.runSerial=c.runSerial;value_.ownerSerial=c.ownerSerial;value_.epochs=c.epochs;
        value_.interfaceIncarnation=c.interfaceIncarnation;value_.guardVersion=a.version;
        value_.deadlineUs=c.deadlineUs;return true;
    }
    void retire(Reason r) {
        if(value_.configured&&value_.state!=State::Retired){value_.state=State::Retired;value_.retireReason=r;}
    }
    void maintain(const Authority &a,uint64_t now) {
        if(value_.configured&&value_.state!=State::Retired&&!current(a,now))
            retire(now>=config_.deadlineUs?Reason::Expired:Reason::WrongAuthority);
    }
    uint64_t request(const Authority &a,uint64_t now,uint64_t receipt,uint64_t captureUs,uint16_t sc,uint16_t awdl,
                     const uint8_t *src,const uint8_t *dst,const uint8_t *ip,size_t length) {
        if(!value_.configured)return 0;
        maintain(a,now);if(!current(a,now)){reject(Reason::WrongAuthority);return 0;}
        Reason r=packetReason(config_,ip,length,false);
        if(r==Reason::None&&(memcmp(src,config_.peerMac,6)||memcmp(dst,config_.ownMac,6)))r=Reason::Address;
        if(r!=Reason::None){reject(r);return 0;}
        if(!receipt||captureUs>now){reject(Reason::InvalidConfig);return 0;}
        if(value_.requestPresent){bump(value_.requestOverflow);reject(Reason::RequestCapacity);return 0;}
        if(!bump(value_.requests))return 0;
        value_.requestPresent=true;value_.requestSequence=receipt;value_.captureUs=captureUs;value_.requestUs=now;
        value_.inputUs=now;value_.wifiSequenceControl=sc;value_.awdlSequence=awdl;
        value_.state=State::InputPending;return receipt;
    }
    void finishInput(uint64_t receipt,int result,const Authority &a,uint64_t now) {
        if(!receipt||receipt!=value_.requestSequence)return;
        maintain(a,now);if(!current(a,now))return;
        if(result){retire(Reason::InputFailed);return;}
        value_.inputConfirmed=true;value_.inputReturnUs=now;
        value_.state=value_.replyPresent?State::Associated:State::InputConfirmed;
    }
    bool reply(const Authority &a,uint64_t now,const uint8_t *ethernet,size_t length) {
        if(!value_.configured)return false;
        maintain(a,now);if(!current(a,now))return reject(Reason::WrongAuthority);
        if(!value_.requestPresent)return reject(Reason::NoRequest);
        if(!ethernet||length!=kEthernetLength||ethernet[12]!=0x86||ethernet[13]!=0xdd)
            return reject(Reason::FrameShape);
        if(memcmp(ethernet,config_.peerMac,6)||memcmp(ethernet+6,config_.ownMac,6))return reject(Reason::Address);
        const Reason r=packetReason(config_,ethernet+14,length-14,true);
        if(r!=Reason::None)return reject(r);
        if(value_.replyPresent){bump(value_.replyOverflow);return reject(Reason::ReplyCapacity);}
        if(!bump(value_.replies))return false;
        value_.replyPresent=true;value_.replyUs=now;value_.replyIpLength=kIpLength;
        memcpy(value_.replyIp,ethernet+14,kIpLength);
        value_.state=value_.inputConfirmed?State::Associated:State::ReplyPendingInput;
        return true;
    }
    Snapshot snapshot(const Authority &a,uint64_t now) const {
        Snapshot out=value_;out.txArmed=false;
        out.associationCurrent=out.state==State::Associated&&current(a,now);
        return out;
    }
};
}
