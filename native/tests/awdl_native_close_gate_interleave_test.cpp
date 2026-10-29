// SPDX-License-Identifier: GPL-2.0-only
// Host-only serialization contract for the production bridge close bit.
#include "awdl_bsd_bridge_shim.hpp"
#include "../awdl_native_bsd_data_25G332.hpp"
#include "../awdl_bsd_packet_bridge.hpp"

#include <condition_variable>
#include <mutex>
#include <thread>

std::atomic<unsigned> allocated{0},freed{0},delivered{0},finalized{0},socketsOpen{0},socketsClosed{0};
uint64_t fakeTime=1;
bool allocateFail=false,inputFail=false,detachDelay=false,offloadFail=false;
bool ipv6Fail=false,socketFail=false,packetHeaderMissing=false,lladdrFail=false;
iff_filter installed;
ifnet_t filterIf=nullptr;

namespace {
using namespace NativeAwdlBSD;
const uint8_t own[6]={2,1,2,3,4,5};
std::mutex gate;
std::condition_variable condition;
std::atomic<bool> candidateChecked{false},allowDoorbell{false};
unsigned doorbells=0;

bool submitSerialized(bool pauseAfterCandidate)
{
    std::unique_lock<std::mutex> lock(gate);
    uint8_t live[6]{};
    if(!NativeAwdlBSD::address(7,live)||memcmp(live,own,6)!=0)return false;
    if(pauseAfterCandidate) {
        candidateChecked.store(true,std::memory_order_release);
        while(!allowDoorbell.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
    uint8_t finalAddress[6]{};
    if(!NativeAwdlBSD::address(7,finalAddress)||memcmp(finalAddress,own,6)!=0)
        return false;
    ++doorbells;
    return true;
}

void closeSerialized()
{
    std::lock_guard<std::mutex> lock(gate);
    NativeAwdlBSD::publishClosing();
}
}

int main(int argc,char **argv)
{
    assert(argc==2);FakeIf dev;memcpy(dev.lladdr,own,6);
    assert(NativeAwdlBSD::attach(&dev,own));NativeAwdlBSD::poll(true,7);
    if(atoi(argv[1])==1) {
        std::thread submitter([]{assert(submitSerialized(true));});
        while(!candidateChecked.load(std::memory_order_acquire))
            std::this_thread::yield();
        std::atomic<bool> closeStarted{false};
        std::thread closer([&]{closeStarted.store(true,std::memory_order_release);closeSerialized();});
        while(!closeStarted.load(std::memory_order_acquire)) {}
        allowDoorbell.store(true,std::memory_order_release);
        submitter.join();closer.join();
        assert(doorbells==1);
        uint8_t afterClose[6]{};assert(!NativeAwdlBSD::address(7,afterClose));
    } else {
        closeSerialized();
        assert(!submitSerialized(false));
        assert(doorbells==0);
    }
    assert(NativeAwdlBSD::close());assert(dev.refs==0);
}
