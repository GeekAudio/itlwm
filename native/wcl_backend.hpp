// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_NATIVE_WCL_BACKEND_HPP
#define GEEK_NATIVE_WCL_BACKEND_HPP
#include "wcl_wire.hpp"

namespace NativeWifi {
enum class Status { Ok, BadRequest, Unsupported, Busy, NotReady, Failed };
struct Beacon {
    const uint8_t *ssid, *bssid, *ies, *frame;
    size_t ssidLength, ieLength, frameLength;
    uint16_t channelSpec, interval, capability;
    uint8_t channel;
    int32_t rssi;
    int16_t noise, snr;
};

struct Operations {
    void *context;
    Status (*scan)(void *, const ScanPlan &);
    Status (*join)(void *, const JoinPlan &);
    void (*leave)(void *);
    void (*emit)(void *, uint32_t, const void *, size_t);
    bool (*privateAddressReady)(void *);
    Status (*cancelScan)(void *);
};

// All entry points require the same real driver serial gate. This component
// neither claims a gate nor dereferences a private IO80211 object. emit() must
// synchronously copy the supplied bytes before returning. RX views are borrowed
// only for observeBeacon's dynamic extent. stop() precedes provider destruction.
class Backend {
public:
    void initialize(const Operations &);
    Status scanRequest(const void *, size_t);
    Status joinRequest(const void *, size_t);
    Status abortScan();
    Status leave(bool abortJoin);
    void beginAddressChange();
    void cancelAddressChange(); // Only after Busy with no HAL or MAC mutation.
    void driverState(bool ready);
    void observeScanComplete(uint32_t generation, uint32_t firmwareStatus);
    void observeScanReset(uint32_t generation);
    void addressHardwareStopped();
    void observeAssociation(uint16_t status, const uint8_t *bssid);
    void observeAuthorization(bool);
    void observeBeacon(const Beacon &);
    void tick(uint32_t elapsedMilliseconds);
    void stop();
    bool ready() const { return ready_ && !stopped_; }
    bool changingAddress() const { return addressChanging_; }
    Status copyBss(void *, size_t) const;
    Status copyBeacon(void *, size_t) const;
    bool joining() const { return joinPending_; }
    bool scanning() const { return scanPending_; }
    bool scanDraining() const { return scanDraining_; }
    uint64_t scanRequests() const { return scanRequests_; }
    uint64_t joinRequests() const { return joinRequests_; }
    uint64_t realBeacons() const { return realBeacons_; }
    uint32_t associatedBeacons() const { return associatedBeacons_; }
    // Actual emit() invocations, not native WCL cache-admission acknowledgments.
    uint64_t event201EmitCalls() const { return event201EmitCalls_; }
    uint64_t event237EmitCalls() const { return event237EmitCalls_; }
    uint32_t last237Status() const { return last237Status_; }
    uint64_t pendingScanBeacons() const { return pendingScanBeacons_; }
    uint32_t scanRejectField() const { return scanRejectField_; }
    uint32_t joinRejectField() const { return joinRejectField_; }
private:
    void post(uint32_t, const void *, size_t);
    void finishJoin(uint16_t, uint32_t);
    void maybeConnected();
    void publishLink(bool);
    void deferScan(const ScanPlan &);
    void finishQueuedScan(uint32_t);
    void retryDeferredScan();
    Status submitJoin(const JoinPlan &);
    void deferJoin(const JoinPlan &);
    void clearDeferredJoin();
    void cancelDeferredJoin();
    void retryDeferredJoin();
    Operations operations_ {};
    bool stopped_ {true}, ready_ {}, addressChanging_ {};
    bool scanPending_ {}, scanQueued_ {}, scanDraining_ {}, scanAbortNotification_ {}, joinPending_ {}, deferred_ {};
    bool associated_ {}, firstBeacon_ {}, authorized_ {}, bssValid_ {};
    bool linkPublished_ {};
    uint8_t linkedAddress_[6] {};
    uint32_t associatedBeacons_ {};
    uint32_t reportedBeacons_ {};
    bool beaconBaselineValid_ {};
    bool addressPreviousReady_ {}, addressPreviousAuthorized_ {};
    uint32_t scanRemaining_ {}, joinRemaining_ {};
    uint32_t scanGeneration_ {}, nextGeneration_ {};
    ScanPlan deferredScanPlan_ {};
    uint32_t nextJoinGeneration_ {}, deferredJoinGeneration_ {};
    uint32_t scanRejectField_ {0xffffffffU}, joinRejectField_ {0xffffffffU};
    uint8_t target_[6] {};
    JoinPlan deferredJoin_ {};
    uint8_t beaconMessage_[BeaconPrefixSize + MaximumIEBytes] {};
    uint8_t associatedBss_[BeaconPrefixSize + MaximumIEBytes] {};
    uint8_t associatedFrame_[0x808] {};
    uint64_t scanRequests_ {}, joinRequests_ {}, realBeacons_ {};
    uint64_t event201EmitCalls_ {}, event237EmitCalls_ {}, pendingScanBeacons_ {};
    uint32_t last237Status_ {0xffffffffU};
};
}
#endif
