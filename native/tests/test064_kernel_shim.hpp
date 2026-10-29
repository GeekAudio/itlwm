// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <thread>

// Reuse the existing ownership/KPI shim while giving this test a controlled
// checksum-offload finalizer. The production path must classify after it.
#define mbuf_outbound_finalize mbuf_outbound_finalize_without_checksum
#define mbuf_copydata test064_mbuf_copydata_without_lock_check
#define mbuf_getpacket test064_mbuf_getpacket_without_lock_check
#define mbuf_freem test064_mbuf_freem_without_lock_check
#define IOSimpleLockLockDisableInterrupt test064_simple_lock_lock
#define IOSimpleLockUnlockEnableInterrupt test064_simple_lock_unlock
#include "awdl_bsd_bridge_shim.hpp"
#undef mbuf_outbound_finalize
#undef mbuf_copydata
#undef mbuf_getpacket
#undef mbuf_freem
#undef IOSimpleLockLockDisableInterrupt
#undef IOSimpleLockUnlockEnableInterrupt

extern bool test064FinalizeChecksum;
extern thread_local unsigned test064SimpleLockDepth;
extern std::atomic<bool> test064PauseAfterUnlock;
extern std::atomic<bool> test064UnlockPaused;
extern std::atomic<bool> test064ResumeUnlock;

inline IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    const IOInterruptState state=test064_simple_lock_lock(lock);
    ++test064SimpleLockDepth;return state;
}
inline void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock,
                                               IOInterruptState state) {
    assert(test064SimpleLockDepth);--test064SimpleLockDepth;
    test064_simple_lock_unlock(lock,state);
    if(test064PauseAfterUnlock.exchange(false,std::memory_order_acq_rel)) {
        test064UnlockPaused.store(true,std::memory_order_release);
        while(!test064ResumeUnlock.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
}
inline int mbuf_copydata(mbuf_t packet,size_t offset,size_t length,void *out) {
    assert(test064SimpleLockDepth==0&&"mbuf_copydata under IOSimpleLock");
    return test064_mbuf_copydata_without_lock_check(packet,offset,length,out);
}
inline int mbuf_getpacket(int flags,mbuf_t *packet) {
    assert(test064SimpleLockDepth==0&&"mbuf allocation under IOSimpleLock");
    return test064_mbuf_getpacket_without_lock_check(flags,packet);
}
inline void mbuf_freem(mbuf_t packet) {
    assert(test064SimpleLockDepth==0&&"mbuf free under IOSimpleLock");
    test064_mbuf_freem_without_lock_check(packet);
}

inline uint16_t test064ReadBe16(const uint8_t *p) {
    return static_cast<uint16_t>((uint16_t(p[0])<<8)|p[1]);
}
inline void test064WriteBe16(uint8_t *p,uint16_t value) {
    p[0]=static_cast<uint8_t>(value>>8);p[1]=static_cast<uint8_t>(value);
}
inline uint16_t test064Checksum(const uint8_t *ipv6,const uint8_t *udp,
                                size_t udpLength) {
    uint32_t sum=0;
    for(size_t i=8;i<40;i+=2)sum+=test064ReadBe16(ipv6+i);
    sum+=static_cast<uint32_t>((udpLength>>16)&0xffffu);
    sum+=static_cast<uint32_t>(udpLength&0xffffu);
    sum+=17;
    for(size_t i=0;i<udpLength;i+=2) {
        const uint16_t word=static_cast<uint16_t>(uint16_t(udp[i])<<8|
            (i+1<udpLength?udp[i+1]:0));
        sum+=word;
        while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    }
    while(sum>>16)sum=(sum&0xffffu)+(sum>>16);
    const uint16_t result=static_cast<uint16_t>(~sum);
    return result?result:0xffff;
}
inline void test064ApplyChecksum(mbuf_t packet) {
    if(!packet||packet->total<62)return;
    uint8_t *frame=static_cast<uint8_t *>(mbuf_data(packet));
    if(frame[12]!=0x86||frame[13]!=0xdd||frame[20]!=17)return;
    uint8_t *ipv6=frame+14;
    const size_t udpLength=test064ReadBe16(ipv6+44);
    if(udpLength<8||udpLength+40!=test064ReadBe16(ipv6+4)+40||
       udpLength+54>packet->total)return;
    uint8_t *udp=ipv6+40;udp[6]=udp[7]=0;
    test064WriteBe16(udp+6,test064Checksum(ipv6,udp,udpLength));
}
inline void mbuf_outbound_finalize(mbuf_t packet,unsigned family,size_t offset) {
    assert(test064SimpleLockDepth==0&&"mbuf finalize under IOSimpleLock");
    mbuf_outbound_finalize_without_checksum(packet,family,offset);
    if(test064FinalizeChecksum)test064ApplyChecksum(packet);
}
