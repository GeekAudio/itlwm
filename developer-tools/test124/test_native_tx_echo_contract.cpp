// SPDX-License-Identifier: GPL-2.0-only
// Exercise the real BSD output/pop path against the real controlled peer parser.
// Only kernel KPI/memory operations use the existing host shim; no socket or RF.
#define main original_origin_fixture_main
#include "native/tests/awdl_directed_origin_tx_test.cpp"
#undef main
#include "developer-tools/test110/openwrt_echo_core.hpp"

int main() {
    FakeIf dev; prepare(dev);
    const auto armed=request(); Origin::Ticket ticket{};
    assert(open(armed,&ticket));
    mbuf_t original=packet(); assert(output(&original)==EJUSTRETURN&&!original);
    uint64_t token=0;
    mbuf_t encoded=popDirectedOriginTx(ticket,0x321,0x4567,&token);
    assert(encoded&&token==ticket.ticketSerial&&encoded->total==96);
    Test110Echo::Contract contract{};
    memcpy(contract.mac,own,6);memcpy(contract.peerMac,peer,6);
    makeLinkLocal(contract.ip,own);makeLinkLocal(contract.peerIp,peer);
    memcpy(contract.nonce,nonce,8);
    assert(Test110Echo::requestMatches(encoded->bytes,encoded->total,contract));

    // Exact configured peer DA, awdl0 SA and AWDL BSSID remain mandatory.
    for (unsigned offset : {4u,10u,16u}) {
        uint8_t bad[96];memcpy(bad,encoded->bytes,96);bad[offset]^=0x10;
        assert(!Test110Echo::requestMatches(bad,sizeof(bad),contract));
    }
    uint8_t bad[96];memcpy(bad,encoded->bytes,96);
    const uint8_t group[6]={0x33,0x33,0,0,0,1};memcpy(bad+4,group,6);
    assert(!Test110Echo::requestMatches(bad,sizeof(bad),contract));

    // Recompute a valid checksum after semantic payload mutations: rejection
    // must come from the exact source/destination/port/hop/nonce contract.
    for (unsigned ipOffset : {7u,23u,39u,41u,43u,48u}) {
        memcpy(bad,encoded->bytes,96);uint8_t *ip=bad+40;ip[ipOffset]^=1;
        Test110Echo::set16(ip+46,0);
        const uint16_t sum=Test110Echo::udpChecksum(ip);
        Test110Echo::set16(ip+46,sum?sum:0xffff);
        assert(!Test110Echo::requestMatches(bad,sizeof(bad),contract));
    }
    for (size_t length=0;length<96;++length)
        assert(!Test110Echo::requestMatches(encoded->bytes,length,contract));
    uint8_t response[106]{};size_t responseLength=0;
    assert(Test110Echo::reply(contract,response,sizeof(response),&responseLength));
    NativeAwdlData::DecodedFrame decoded{};
    assert(responseLength==106&&NativeAwdlData::decodeIpv6DataMpdu(
        response+10,96,&decoded)==NativeAwdlData::Status::Ok);
    assert(!memcmp(decoded.destinationAddress,own,6)&&
           !memcmp(decoded.sourceAddress,peer,6));
    const auto &view=decoded.packets[0];
    assert(!memcmp(view.ipv6Packet+8,contract.peerIp,16)&&
           !memcmp(view.ipv6Packet+24,contract.ip,16));
    assert(!memcmp(view.ipv6Packet+48,nonce,8)&&Test110Echo::udpChecksum(view.ipv6Packet)==0);
    mbuf_freem(encoded);assert(closeDirectedOriginTx(ticket));assert(close());assertBalanced(dev);
    puts("PASS: actual BSD output -> directed pop -> peer exact request/reply contract; negative DA/SA/BSSID/IPv6/ports/hop/nonce/truncation");
}
