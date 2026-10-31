// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_NATIVE_WCL_BACKEND_HPP
#define GEEK_NATIVE_WCL_BACKEND_HPP
#include "wcl_wire.hpp"

namespace NativeWifi {
enum class Status : uint32_t { Ok, BadRequest, Unsupported, Busy, NotReady, Failed };
enum class ScanBusyClass : uint8_t {
    None, BackendAddressChange, BackendScanDrain, BackendJoinPending,
    BackendActiveScan, RadioUnclassified, RadioReported
};
enum class ScanTerminalSource : uint8_t {
    None, FirmwareComplete, FirmwareAborted, RequestReplacement,
    RequestAbort, RequestTimeout, DriverOffline, ResetDrained,
    AdmissionFailure
};
enum class ScanTraceClock : uint8_t { TickFallback, MonotonicCallback };
struct ScanBusyDetail {
    uint32_t code; // Adapter-defined only when scan() returned Busy; zero means unknown.
};
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
    // Optional adapter hooks. The monotonic callback must use one stable
    // boot-time domain. busyScanDetail() is sampled immediately after a Busy
    // scan callback and must describe that exact invocation, not stale state.
    uint64_t (*monotonicNanoseconds)(void *);
    ScanBusyDetail (*busyScanDetail)(void *);
};

// Fixed-capacity, payload-free scan audit. No SSID, BSSID, frame, or IE bytes
// are stored. A record's requestSerial is backend-local; generation is the
// distinct identity passed to the HAL for real completion matching.
struct ScanTraceRecord {
    uint32_t requestSerial, generation, replacesSerial, replacedBySerial;
    uint32_t admissionAttempts, radioAttempts, busyAttempts, event201Count;
    uint32_t staleTerminals, firmwareStatus, native237Status, native237EmitCallCount;
    uint64_t requestMonotonicNs, firstRadioAttemptMonotonicNs;
    uint64_t lastRadioAttemptMonotonicNs, acceptedMonotonicNs;
    uint64_t first201MonotonicNs, last201MonotonicNs;
    // The first timestamp is sampled when Backend consumes the terminal on
    // its serialized gate; it is not a firmware-producer timestamp. The second
    // is sampled immediately before the native emit callback, not an OS ACK.
    uint64_t firmwareTerminalConsumedMonotonicNs, native237EmitCallMonotonicNs;
    uint32_t lastBusyReasonCode;
    Status lastAdmissionStatus;
    ScanBusyClass lastBusyClass;
    ScanTerminalSource nativeTerminalSource;
    ScanTraceClock clockSource;
    bool valid, hasFirst201, hasFirmwareTerminal, hasNative237;
    bool native237EmitCalled;
    bool hasFirstRadioAttempt, hasAccepted;
};
static constexpr unsigned ScanTraceCapacity = 16;
static constexpr uint32_t ScanTraceSchemaVersion = 1;
struct ScanTraceSnapshot {
    uint32_t version, count;
    uint64_t requestCount, replacementCount, overwriteCount, staleTerminalCount;
    ScanTraceRecord records[ScanTraceCapacity]; // Oldest retained record first.
};
// Schema 1 is the zero-filled x86_64 raw-struct wire published by the Tahoe
// adapter. The Python decoder uses these byte offsets explicitly; changing a
// field or target ABI requires a schema bump and a new decoder fixture.
static_assert(sizeof(Status) == 4, "scan trace status wire width changed");
static_assert(sizeof(ScanTraceRecord) == 136, "scan trace record wire size changed");
static_assert(offsetof(ScanTraceRecord, requestSerial) == 0, "scan trace serial offset changed");
static_assert(offsetof(ScanTraceRecord, generation) == 4, "scan trace generation offset changed");
static_assert(offsetof(ScanTraceRecord, admissionAttempts) == 16, "scan trace attempt offset changed");
static_assert(offsetof(ScanTraceRecord, firmwareStatus) == 36, "scan trace firmware status offset changed");
static_assert(offsetof(ScanTraceRecord, requestMonotonicNs) == 48, "scan trace request clock offset changed");
static_assert(offsetof(ScanTraceRecord, firstRadioAttemptMonotonicNs) == 56,
              "scan trace first attempt offset changed");
static_assert(offsetof(ScanTraceRecord, lastRadioAttemptMonotonicNs) == 64,
              "scan trace last attempt offset changed");
static_assert(offsetof(ScanTraceRecord, acceptedMonotonicNs) == 72,
              "scan trace admission end offset changed");
static_assert(offsetof(ScanTraceRecord, first201MonotonicNs) == 80,
              "scan trace first 201 offset changed");
static_assert(offsetof(ScanTraceRecord, last201MonotonicNs) == 88,
              "scan trace last 201 offset changed");
static_assert(offsetof(ScanTraceRecord, firmwareTerminalConsumedMonotonicNs) == 96,
              "scan trace consumed clock offset changed");
static_assert(offsetof(ScanTraceRecord, native237EmitCallMonotonicNs) == 104,
              "scan trace emit clock offset changed");
static_assert(offsetof(ScanTraceRecord, lastAdmissionStatus) == 116, "scan trace status offset changed");
static_assert(offsetof(ScanTraceRecord, lastBusyClass) == 120, "scan trace busy offset changed");
static_assert(offsetof(ScanTraceRecord, valid) == 123, "scan trace flags offset changed");
static_assert(offsetof(ScanTraceRecord, hasAccepted) == 129, "scan trace final flag offset changed");
static_assert(sizeof(ScanTraceSnapshot) == 2216, "scan trace snapshot wire size changed");
static_assert(offsetof(ScanTraceSnapshot, requestCount) == 8, "scan trace request counter offset changed");
static_assert(offsetof(ScanTraceSnapshot, replacementCount) == 16, "scan trace replacement counter offset changed");
static_assert(offsetof(ScanTraceSnapshot, overwriteCount) == 24, "scan trace overwrite counter offset changed");
static_assert(offsetof(ScanTraceSnapshot, staleTerminalCount) == 32, "scan trace stale counter offset changed");
static_assert(offsetof(ScanTraceSnapshot, records) == 40, "scan trace array offset changed");

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
    // Called only on the same serialized driver gate as backend entry points.
    void copyScanTrace(ScanTraceSnapshot *) const;
private:
    void post(uint32_t, const void *, size_t, uint32_t scanTraceSerial = 0);
    void finishJoin(uint16_t, uint32_t);
    void maybeConnected();
    void publishLink(bool);
    void deferScan(const ScanPlan &);
    void finishQueuedScan(uint32_t, ScanTerminalSource);
    uint64_t monotonicNowNanoseconds();
    uint32_t beginScanTrace();
    void linkScanReplacement(uint32_t replacedSerial, uint32_t replacementSerial);
    ScanTraceRecord *findScanTrace(uint32_t);
    void traceAdmission(uint32_t, Status, ScanBusyClass, uint32_t,
                       bool radioAttempt, uint64_t radioAttemptStartNs = 0);
    void traceFirmwareTerminal(uint32_t, uint32_t, uint64_t consumedNs);
    void traceNative237Intent(uint32_t, uint32_t, ScanTerminalSource);
    void traceNative237EmitCall(uint32_t);
    void traceBeacon201(uint32_t);
    void traceStaleTerminal();
    ScanBusyDetail radioBusyDetail() const;
    void emitScanFinished(uint32_t, uint32_t, ScanTerminalSource);
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
    uint32_t scanTraceRequestSerial_ {}, nextScanTraceSerial_ {}, scanTraceNextSlot_ {};
    uint32_t scanTraceCount_ {};
    uint64_t scanTraceRequestCount_ {}, scanTraceReplacementCount_ {}, scanTraceOverwriteCount_ {};
    uint64_t scanTraceStaleTerminalCount_ {}, scanTraceFallbackClockNs_ {}, scanTraceLastClockNs_ {};
    ScanTraceRecord scanTrace_[ScanTraceCapacity] {};
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
