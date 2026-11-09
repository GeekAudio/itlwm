// SPDX-License-Identifier: GPL-2.0-only
#ifndef TEST110_OPENWRT_ECHO_CORE_HPP
#define TEST110_OPENWRT_ECHO_CORE_HPP
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../../native/awdl_data_frame.hpp"

namespace Test110Echo {
struct Contract {
    uint8_t mac[6], peerMac[6]; // Mac awdl0, then controlled router peer
    uint8_t ip[16], peerIp[16], nonce[8];
};
inline uint16_t be16(const uint8_t *p) { return uint16_t(p[0] << 8 | p[1]); }
inline uint16_t le16(const uint8_t *p) { return uint16_t(p[0] | p[1] << 8); }
inline uint32_t le32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint32_t sum16(const uint8_t *p, size_t n, uint32_t sum=0) {
    for (; n >= 2; n-=2,p+=2) sum += be16(p);
    if (n) sum += uint32_t(*p) << 8;
    return sum;
}
inline uint16_t udpChecksum(const uint8_t *ip) {
    uint32_t sum = sum16(ip+8,32) + 16 + 17;
    sum = sum16(ip+40,16,sum);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}
inline void set16(uint8_t *p, uint16_t x) { p[0]=uint8_t(x >> 8); p[1]=uint8_t(x); }

// Require an RX radiotap channel measurement. Parse only fields through CHANNEL;
// the header length skips later fields without assuming a particular mt76 layout.
inline bool stripRadiotap(const uint8_t *b,size_t n,const uint8_t **mpdu,size_t *length) {
    if (!b || !mpdu || !length || n<8 || n>4096 || b[0]!=0) return false;
    const size_t h=le16(b+2);
    if (h<8 || h>n) return false;
    const uint32_t first=le32(b+4);
    if (!(first & (1u<<3))) return false;
    size_t off=8; uint32_t present=first; unsigned maps=1;
    while (present & (1u<<31)) {
        if (++maps>8 || off+4>h) return false;
        present=le32(b+off); off+=4;
    }
    uint8_t flags=0;
    const unsigned sizes[4]={8,1,1,4}, aligns[4]={8,1,1,2};
    for (unsigned bit=0;bit<4;++bit) if (first & (1u<<bit)) {
        off=(off+aligns[bit]-1)&~size_t(aligns[bit]-1);
        if (off+sizes[bit]>h) return false;
        if (bit==1) flags=b[off];
        if (bit==3 && le16(b+off)!=2437) return false;
        off+=sizes[bit];
    }
    if (flags & (0x20|0x40)) return false; // data pad or bad FCS
    size_t body=n-h;
    if (flags & 0x10) { if (body<4) return false; body-=4; }
    *mpdu=b+h; *length=body; return true;
}

inline bool requestMatches(const uint8_t *mpdu,size_t n,const Contract &c) {
    NativeAwdlData::DecodedFrame frame{};
    if (NativeAwdlData::decodeIpv6DataMpdu(mpdu,n,&frame)!=NativeAwdlData::Status::Ok ||
        frame.packetCount!=1 || frame.amsdu || frame.qosData) return false;
    // Mode 4 preserves the BSD ff02::1 payload but directs the radio MPDU
    // to the selected peer station (LINK/TID0). It is not a multicast DA.
    const uint8_t multicastIp[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    const auto &packet=frame.packets[0]; const uint8_t *ip=packet.ipv6Packet;
    if (packet.ipv6Length!=56 || memcmp(frame.sourceAddress,c.mac,6) ||
        memcmp(frame.destinationAddress,c.peerMac,6) ||
        memcmp(packet.sourceAddress,c.mac,6) || memcmp(packet.destinationAddress,c.peerMac,6)) return false;
    if ((ip[0]>>4)!=6 || be16(ip+4)!=16 || ip[6]!=17 || ip[7]!=1 ||
        memcmp(ip+8,c.ip,16) || memcmp(ip+24,multicastIp,16) ||
        be16(ip+40)!=49153 || be16(ip+42)!=49152 || be16(ip+44)!=16 ||
        !be16(ip+46) || memcmp(ip+48,c.nonce,8) || udpChecksum(ip)!=0) return false;
    return true;
}

inline bool reply(const Contract &c,uint8_t *out,size_t capacity,size_t *written) {
    if (!out || !written || capacity<106) return false;
    uint8_t ip[56]{}; ip[0]=0x60; ip[5]=16; ip[6]=17; ip[7]=1;
    memcpy(ip+8,c.peerIp,16); memcpy(ip+24,c.ip,16);
    set16(ip+40,49152); set16(ip+42,49153); set16(ip+44,16);
    memcpy(ip+48,c.nonce,8);
    uint16_t sum=udpChecksum(ip); set16(ip+46,sum ? sum : 0xffff);
    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress,c.mac,6); memcpy(input.sourceAddress,c.peerMac,6);
    input.wifiSequenceNumber=0x110; input.awdlSequenceNumber=0x110;
    input.ipv6Packet=ip; input.ipv6Length=sizeof(ip);
    size_t body=0;
    if (NativeAwdlData::encodeIpv6DataMpdu(&input,out+10,capacity-10,&body)!=NativeAwdlData::Status::Ok) return false;
    const uint8_t rt[10]={0,0,10,0,0,0x80,0,0,0x18,0};
    memcpy(out,rt,10); *written=body+10; return true;
}
}
#endif
