// SPDX-License-Identifier: GPL-2.0-only
#include "openwrt_echo_core.hpp"
#include <assert.h>
#include <stdio.h>

int main() {
    using namespace Test110Echo;
    Contract c{};
    c.mac[0]=2; c.mac[5]=1; c.peerMac[0]=2; c.peerMac[5]=2;
    c.ip[0]=c.peerIp[0]=0xfe; c.ip[1]=c.peerIp[1]=0x80;
    c.ip[15]=1; c.peerIp[15]=2;
    for(unsigned i=0;i<8;++i)c.nonce[i]=uint8_t(i+0x20);
    uint8_t ip[56]{}; ip[0]=0x60; ip[5]=16;ip[6]=17;ip[7]=1;
    memcpy(ip+8,c.ip,16);ip[24]=0xff;ip[25]=2;ip[39]=1;
    set16(ip+40,49153);set16(ip+42,49152);set16(ip+44,16);
    memcpy(ip+48,c.nonce,8);uint16_t sum=udpChecksum(ip);set16(ip+46,sum?sum:0xffff);
    NativeAwdlData::EncodeInput in{};in.destinationAddress[0]=0x33;in.destinationAddress[1]=0x33;in.destinationAddress[5]=1;
    memcpy(in.sourceAddress,c.mac,6);in.ipv6Packet=ip;in.ipv6Length=56;
    uint8_t good[96];size_t goodLen=0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(&in,good,sizeof(good),&goodLen)==NativeAwdlData::Status::Ok);
    assert(goodLen==96&&requestMatches(good,goodLen,c));
    for(size_t n=0;n<goodLen;++n)assert(!requestMatches(good,n,c));
    const unsigned mutations[]={4,10,16,24,32,44,46,47,48,64,80,82,84,86,88,95};
    for(unsigned index:mutations) {uint8_t bad[96];memcpy(bad,good,96);bad[index]^=1;assert(!requestMatches(bad,96,c));}
    Contract wrong=c;wrong.nonce[0]^=1;assert(!requestMatches(good,96,wrong));
    wrong=c;wrong.mac[5]^=1;assert(!requestMatches(good,96,wrong));
    wrong=c;wrong.ip[15]^=1;assert(!requestMatches(good,96,wrong));
    // The radio observation must actually carry channel 6, and optionally FCS.
    uint8_t radio[128]{};radio[2]=14;radio[4]=0x0e;radio[8]=0;radio[9]=12;
    radio[10]=0x85;radio[11]=9;memcpy(radio+14,good,96);
    const uint8_t *mpdu=nullptr;size_t n=0;
    assert(stripRadiotap(radio,110,&mpdu,&n)&&n==96&&mpdu==radio+14&&requestMatches(mpdu,n,c));
    radio[8]=0x10;assert(stripRadiotap(radio,114,&mpdu,&n)&&n==96);
    radio[8]=0x40;assert(!stripRadiotap(radio,110,&mpdu,&n));
    radio[8]=0x20;assert(!stripRadiotap(radio,110,&mpdu,&n));
    radio[8]=0;radio[10]=0x86;assert(!stripRadiotap(radio,110,&mpdu,&n));radio[10]=0x85;
    radio[4]=0x06;assert(!stripRadiotap(radio,110,&mpdu,&n));radio[4]=0x0e;
    for(size_t cut=0;cut<14;++cut)assert(!stripRadiotap(radio,cut,&mpdu,&n));
    // Extended present bitmap changes where the flags/channel live.
    uint8_t extended[128]{};extended[2]=18;extended[4]=0x0e;extended[7]=0x80;
    extended[13]=12;extended[14]=0x85;extended[15]=9;memcpy(extended+18,good,96);
    assert(stripRadiotap(extended,114,&mpdu,&n)&&n==96&&requestMatches(mpdu,n,c));
    extended[11]=0x80;assert(!stripRadiotap(extended,114,&mpdu,&n));
    uint8_t output[106];size_t bytes=777;
    assert(!reply(c,output,105,&bytes)&&bytes==777);
    assert(reply(c,output,106,&bytes)&&bytes==106);
    NativeAwdlData::DecodedFrame response{};
    assert(NativeAwdlData::decodeIpv6DataMpdu(output+10,96,&response)==NativeAwdlData::Status::Ok);
    assert(!memcmp(response.sourceAddress,c.peerMac,6)&&!memcmp(response.destinationAddress,c.mac,6));
    const auto &p=response.packets[0];assert(p.ipv6Length==56);
    assert(!memcmp(p.ipv6Packet+8,c.peerIp,16)&&!memcmp(p.ipv6Packet+24,c.ip,16));
    assert(be16(p.ipv6Packet+40)==49152&&be16(p.ipv6Packet+42)==49153&&p.ipv6Packet[7]==1);
    assert(!memcmp(p.ipv6Packet+48,c.nonce,8)&&udpChecksum(p.ipv6Packet)==0);
    puts("PASS: bounded radiotap, exact request identity/checksum, reply tuple/nonce/checksum");
}
