// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include "awdl_data_frame.hpp"
#include <string.h>

namespace NativeAwdlBSD {
constexpr size_t MaxEthernet = 1514, MaxMpdu = 1550, QueueDepth = 32;
struct EthernetView { const uint8_t *ipv6; size_t length; uint8_t destination[6]; };
inline bool ethernetIpv6(const uint8_t *bytes, size_t length,
                         const uint8_t own[6], EthernetView *out) {
    if(!bytes || !own || !out || length<54 || length>MaxEthernet ||
       bytes[12]!=0x86 || bytes[13]!=0xdd || memcmp(bytes+6,own,6) ||
       (own[0]&1) || (bytes[14]>>4)!=6 ||
       size_t((unsigned(bytes[18])<<8)|bytes[19])+54!=length) return false;
    uint8_t any=0;for(unsigned i=0;i<6;++i)any|=bytes[i];
    if(!any || !memcmp(bytes,own,6))return false;
    EthernetView result{bytes+14,length-14,{}};
    memcpy(result.destination,bytes,6);*out=result;return true;
}
// Callers serialize all queue access. Pop transfers ownership exactly once;
// rejected pushes do not consume the caller's object.
template<class T,size_t N> struct Ring {
    T values[N]{};size_t head=0,tail=0,count=0;
    bool push(const T &v){if(count==N)return false;values[tail]=v;tail=(tail+1)%N;++count;return true;}
    bool pop(T *v){if(!v||!count)return false;*v=values[head];values[head]=T{};head=(head+1)%N;--count;return true;}
};
inline bool acceptsRx(const NativeAwdlData::PacketView &p,const uint8_t own[6]) {
    return p.ipv6Packet && p.ipv6Length>=40 && p.ipv6Length<=1500 &&
        memcmp(p.sourceAddress,own,6) &&
        (!memcmp(p.destinationAddress,own,6)||(p.destinationAddress[0]&1));
}
}
