// SPDX-License-Identifier: GPL-2.0-only
#include "../test110/openwrt_echo_core.hpp"
#include <assert.h>
#include <stdio.h>

static void makeRequest(const Test110Echo::TwoPacketContract &contract,
                        unsigned slot, uint8_t *out, size_t *length) {
    const Test110Echo::Contract packet = Test110Echo::packetContract(contract, slot);
    uint8_t ip[56]{}; ip[0]=0x60; ip[5]=16; ip[6]=17; ip[7]=1;
    memcpy(ip+8,packet.ip,16); ip[24]=0xff; ip[25]=2; ip[39]=1;
    Test110Echo::set16(ip+40,49153); Test110Echo::set16(ip+42,49152);
    Test110Echo::set16(ip+44,16); memcpy(ip+48,packet.nonce,8);
    uint16_t sum=Test110Echo::udpChecksum(ip);
    Test110Echo::set16(ip+46,sum?sum:0xffff);
    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress,packet.peerMac,6);
    memcpy(input.sourceAddress,packet.mac,6);
    input.wifiSequenceNumber=uint16_t(0x210+slot);
    input.awdlSequenceNumber=uint16_t(0x310+slot);
    input.ipv6Packet=ip; input.ipv6Length=sizeof(ip);
    assert(NativeAwdlData::encodeIpv6DataMpdu(&input,out,96,length)==
           NativeAwdlData::Status::Ok);
    assert(*length==96);
}

int main() {
    using namespace Test110Echo;
    TwoPacketContract c{};
    c.mac[0]=2; c.mac[5]=1; c.peerMac[0]=2; c.peerMac[5]=2;
    c.ip[0]=c.peerIp[0]=0xfe; c.ip[1]=c.peerIp[1]=0x80;
    c.ip[15]=1; c.peerIp[15]=2;
    for(unsigned i=0;i<8;++i) {
        c.nonces[0][i]=uint8_t(i+0x20);
        c.nonces[1][i]=uint8_t(i+0x40);
    }
    assert(distinctTwoPacketNonces(c));
    uint8_t requests[2][96]{}; size_t requestLengths[2]{};
    makeRequest(c,0,requests[0],&requestLengths[0]);
    makeRequest(c,1,requests[1],&requestLengths[1]);
    PacketMatch match{};
    assert(requestMatches(requests[0],requestLengths[0],c,&match));
    assert(match.slot==0&&match.wifiSequenceNumber==0x210&&
           match.awdlSequenceNumber==0x310);
    assert(requestMatches(requests[1],requestLengths[1],c,&match));
    assert(match.slot==1&&match.wifiSequenceNumber==0x211&&
           match.awdlSequenceNumber==0x311);
    assert(!requestMatches(requests[0],requestLengths[0],c,nullptr));
    uint8_t output[106]{}; size_t written=0;
    for(unsigned slot=0;slot<2;++slot) {
        assert(reply(c,slot,output,sizeof(output),&written)&&written==106);
        NativeAwdlData::DecodedFrame response{};
        assert(NativeAwdlData::decodeIpv6DataMpdu(output+10,96,&response)==
               NativeAwdlData::Status::Ok);
        const auto &packet=response.packets[0];
        assert(response.wifiSequenceNumber==0x110+slot);
        assert(packet.awdlSequenceNumber==0x110+slot);
        assert(!memcmp(packet.ipv6Packet+48,c.nonces[slot],8));
        assert(!memcmp(packet.ipv6Packet+8,c.peerIp,16));
        assert(!memcmp(packet.ipv6Packet+24,c.ip,16));
        assert(Test110Echo::udpChecksum(packet.ipv6Packet)==0);
    }
    TwoPacketContract replay=c; memcpy(replay.nonces[1],replay.nonces[0],8);
    assert(!distinctTwoPacketNonces(replay));
    assert(!requestMatches(requests[0],requestLengths[0],replay,&match));
    assert(!reply(replay,1,output,sizeof(output),&written));
    assert(!reply(c,2,output,sizeof(output),&written));
    puts("PASS: two ordered nonce identities, independent request/reply sequences, duplicate nonce rejection");
}
