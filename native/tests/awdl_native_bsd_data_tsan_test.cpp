// SPDX-License-Identifier: GPL-2.0-only
// Host concurrency regression for the production BSD bridge.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_bsd_packet_bridge.hpp"

#include <atomic>
#include <thread>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=1;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false;
bool lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;

namespace {
using namespace NativeAwdlBSD;
const uint8_t own[6]={2,1,2,3,4,5};
const uint8_t peer[6]={2,6,7,8,9,10};

bool acceptPacket()
{
    mbuf_t packet=nullptr;
    assert(mbuf_getpacket(MBUF_DONTWAIT,&packet)==0&&packet);
    memcpy(packet->bytes,peer,6);
    memcpy(packet->bytes+6,own,6);
    packet->bytes[12]=0x86;
    packet->bytes[13]=0xdd;
    packet->bytes[14]=0x60;
    mbuf_setlen(packet,54);
    mbuf_pkthdr_setlen(packet,54);
    const int result=installed.iff_output(nullptr,filterIf,AF_INET6,&packet);
    if(result==EJUSTRETURN){assert(packet==nullptr);return true;}
    assert(packet!=nullptr);mbuf_freem(packet);return false;
}
}

int main()
{
    FakeIf dev;
    memcpy(dev.lladdr,own,6);
    assert(attach(&dev,own));
    poll(true,7);

    std::atomic<bool> start{false};
    std::thread generationWriter([&] {
        while(!start.load(std::memory_order_acquire)) {}
        for(uint32_t i=0;i<100000;++i)
            poll(true,7+(i&1));
    });
    std::thread txReader([&] {
        while(!start.load(std::memory_order_acquire)) {}
        for(unsigned i=0;i<100000;++i) {
            (void)acceptPacket();
            uint64_t token=0;
            mbuf_t encoded=nextTx(0,&token);
            if(encoded) {
                assert(token!=0);
                mbuf_freem(encoded);
                submitted(token,0);
                completed(token,true);
            }
        }
    });
    std::thread identityReader([&] {
        while(!start.load(std::memory_order_acquire)) {}
        for(uint32_t i=0;i<100000;++i) {
            uint8_t observed[6]{};
            (void)NativeAwdlBSD::address(7+(i&1),observed);
        }
    });
    std::thread closePublisher([&] {
        while(!start.load(std::memory_order_acquire)) {}
        for(unsigned i=0;i<100;++i)NativeAwdlBSD::publishClosing();
    });
    start.store(true,std::memory_order_release);
    generationWriter.join();
    txReader.join();
    identityReader.join();
    closePublisher.join();

    assert(close());
    assert(!dev.refs);
    assert(allocated==freed);
}
