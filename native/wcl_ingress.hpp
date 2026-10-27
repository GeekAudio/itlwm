// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_NATIVE_WCL_INGRESS_HPP
#define GEEK_NATIVE_WCL_INGRESS_HPP

#if defined(KERNEL) && defined(AIRPORT_TAHOE)
#include "wcl_backend.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <kern/thread_call.h>

namespace NativeWifi {
// Fixed owned snapshots; RX payloads and ieee80211_node pointers never survive
// the producer callback. The context/provider must outlive shutdown + HAL drain.
struct IngressEntry {
    unsigned kind;
    uint32_t value, detail;
    uint8_t bssid[6];
    uint8_t ssid[32], ssidLength, channel;
    uint16_t channelSpec, interval, capability, frameLength;
    int32_t rssi;
    int16_t noise, snr;
    uint8_t frame[2048];
};
class Ingress {
public:
    using Dispatch = void (*)(void *, const IngressEntry &);
    bool initialize(IOCommandGate *, Dispatch, void *);
    bool signal(unsigned, uint32_t = 0, const uint8_t * = nullptr, uint32_t = 0);
    bool receive(const Beacon &);
    // Never call while holding the driver gate. A false return leaves the
    // allocation resident and closing; it must not be freed or rebound.
    bool shutdown();
    bool destroy(); // Only after shutdown and real producer/provider drain.
    uint64_t overflows() const { return __atomic_load_n(&overflow_, __ATOMIC_RELAXED); }
private:
    static void run(thread_call_param_t, thread_call_param_t);
    static IOReturn dispatchGated(OSObject *, void *, void *, void *, void *);
    bool append(unsigned, uint32_t, const uint8_t *, const Beacon *, uint32_t = 0);
    IOSimpleLock *lock_ {};
    IOCommandGate *gate_ {};
    thread_call_t call_ {};
    Dispatch dispatch_ {};
    void *context_ {};
    bool closing_ {}, stopped_ {};
    unsigned first_ {}, count_ {};
    uint64_t overflow_ {};
    static constexpr unsigned Capacity = 32;
    IngressEntry entries_[Capacity] {};
    IngressEntry delivery_ {};
};
}
#endif
#endif
