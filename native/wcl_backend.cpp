// SPDX-License-Identifier: GPL-2.0-only
#include "wcl_backend.hpp"

namespace NativeWifi {
namespace {
constexpr uint32_t NativeFailed = 0xe00002bc;
constexpr uint32_t NativeTimeout = 0xe00002d6;
constexpr uint32_t NativeOffline = 0xe00002d7;
constexpr uint32_t NativeAborted = 0xe00002eb;
void copyBytes(void *out, const void *in, size_t n) {
    auto d = static_cast<uint8_t *>(out);
    auto s = static_cast<const uint8_t *>(in);
    for (size_t i = 0; i != n; ++i) d[i] = s[i];
}


bool equalAddress(const uint8_t *a, const uint8_t *b) {
    if (!a || !b) return false;
    uint8_t different = 0;
    for (unsigned i = 0; i < 6; ++i) different |= a[i] ^ b[i];
    return !different;
}
bool validAddress(const uint8_t *p) {
    if (!p || (p[0] & 1)) return false;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= p[i];
    return bits != 0;
}
}

void Backend::initialize(const Operations &operations) {
    operations_ = operations;
    stopped_ = false;
}
void Backend::post(uint32_t kind, const void *bytes, size_t n) {
    if (!stopped_ && operations_.emit) {
        if (kind == ScanBeacon) ++event201EmitCalls_;
        if (kind == ScanFinished) {
            ++event237EmitCalls_;
            if (bytes && n == 4) last237Status_ = read32(static_cast<const uint8_t *>(bytes));
        }
        operations_.emit(operations_.context, kind, bytes, n);
    }
}
Status Backend::scanRequest(const void *data, size_t n) {
    ScanPlan plan {};
    const auto decoded = decodeScan(data, n, plan, &scanRejectField_);
    if (decoded != DecodeResult::Ok)
        return decoded == DecodeResult::Malformed ? Status::BadRequest : Status::Unsupported;
    if (!ready()) return Status::NotReady;
    if (addressChanging_ || scanDraining_ || joinPending_) return Status::Busy;
    if (scanPending_ && !scanQueued_) return Status::Busy;
    if (plan.privateAddressRequired && (!operations_.privateAddressReady ||
        !operations_.privateAddressReady(operations_.context))) return Status::Unsupported;
    if (!operations_.scan) return Status::Unsupported;
    if (scanPending_ && scanQueued_) finishQueuedScan(NativeAborted);
    scanPending_ = true;
    scanRemaining_ = 20000;
    // The caller's request identifier is not a hardware completion identity.
    // A fresh host generation is held unchanged through real completion/drain.
    if (!++nextGeneration_) ++nextGeneration_;
    plan.identifier = nextGeneration_;
    scanGeneration_ = plan.identifier;
    ++scanRequests_;
    const Status result = operations_.scan(operations_.context, plan);
    if (result == Status::Busy) {
        // Busy does not distinguish a live HAL lease from a scan attempt that
        // has already entered drain. Keep this exact WCL plan/generation until
        // its terminal event, a lease-release retry, or the request expires.
        deferScan(plan);
        return Status::Ok;
    }
    if (result != Status::Ok) {
        scanPending_ = false; scanRemaining_ = scanGeneration_ = 0;
    }
    return result;
}
void Backend::deferScan(const ScanPlan &plan) {
    deferredScanPlan_ = plan;
    scanQueued_ = true;
}
void Backend::finishQueuedScan(uint32_t status) {
    if (!scanQueued_) return;
    // Retire the WCL-side entry only; Busy does not imply the HAL had no side
    // effects, so its own generation/lease cleanup remains with the HAL.
    scanQueued_ = false;
    scanPending_ = false;
    scanRemaining_ = scanGeneration_ = 0;
    erase(&deferredScanPlan_, sizeof(deferredScanPlan_));
    uint8_t payload[4]; write32(payload, status);
    post(ScanFinished, payload, sizeof(payload));
}
void Backend::retryDeferredScan() {
    if (stopped_ || !ready_ || !scanPending_ || !scanQueued_ ||
        !scanGeneration_ || deferredScanPlan_.identifier != scanGeneration_ ||
        !operations_.scan) return;
    const uint32_t generation = scanGeneration_;
    const Status result = operations_.scan(operations_.context, deferredScanPlan_);
    // All entry points are serialized by the native workqueue gate. Keep the
    // generation check as a fail-closed guard against synchronous re-entry.
    if (!scanQueued_ || generation != scanGeneration_ ||
        deferredScanPlan_.identifier != generation) return;
    if (result == Status::Busy) return;
    if (result != Status::Ok) {
        finishQueuedScan(result == Status::NotReady ? NativeOffline : NativeFailed);
        return;
    }
    scanQueued_ = false;
    erase(&deferredScanPlan_, sizeof(deferredScanPlan_));
}
Status Backend::submitJoin(const JoinPlan &plan) {
    if (!operations_.join) return Status::Unsupported;
    // Radio admission is synchronous under the same command gate as backend
    // event dispatch. The ingress worker queues callbacks until this action
    // returns, so keep the prior association intact unless admission succeeds
    // or the HAL reports a hard failure after changing join state.
    const Status result = operations_.join(operations_.context, plan);
    if (result == Status::Busy || result == Status::NotReady ||
        result == Status::Unsupported) return result;

    // Ok means the radio accepted this attempt. Failed can follow RSN/key or
    // desired-network mutation in radioJoin(), so retain the previous failure
    // cleanup behavior instead of claiming its cached association is intact.
    copyBytes(target_, plan.bssid, sizeof(target_));
    associated_ = firstBeacon_ = authorized_ = bssValid_ = false;
    associatedBeacons_ = 0;
    reportedBeacons_ = 0;
    beaconBaselineValid_ = false;
    erase(associatedBss_, sizeof(associatedBss_));
    erase(associatedFrame_, sizeof(associatedFrame_));
    joinPending_ = result == Status::Ok;
    joinRemaining_ = result == Status::Ok ? 30000 : 0;
    return result;
}
void Backend::deferJoin(const JoinPlan &plan) {
    clearDeferredJoin();
    if (!++nextJoinGeneration_) ++nextJoinGeneration_;
    deferredJoinGeneration_ = nextJoinGeneration_;
    deferredJoin_ = plan;
    deferred_ = joinPending_ = true;
    joinRemaining_ = 30000;
}
void Backend::clearDeferredJoin() {
    deferred_ = false;
    deferredJoinGeneration_ = 0;
    erase(&deferredJoin_, sizeof(deferredJoin_));
}
void Backend::cancelDeferredJoin() {
    if (!deferred_) return;
    clearDeferredJoin();
    joinPending_ = false;
    joinRemaining_ = 0;
    post(JoinAborted, nullptr, 0);
}
Status Backend::joinRequest(const void *data, size_t n) {
    JoinPlan plan {};
    const auto decoded = decodeJoin(data, n, plan, &joinRejectField_);
    if (decoded != DecodeResult::Ok)
        return decoded == DecodeResult::Malformed ? Status::BadRequest : Status::Unsupported;
    Status result = Status::NotReady;
    if (stopped_) result = Status::NotReady;
    else {
        // A new WCL Join supersedes only a request that this backend accepted
        // but has not submitted to the radio. Active joins retain the existing
        // Busy behavior; a Busy retry can never overwrite an in-flight join.
        if (joinPending_ && deferred_)
            cancelDeferredJoin();
        if (joinPending_ || scanPending_ || scanDraining_) {
            result = Status::Busy;
        } else if (addressChanging_) {
            deferJoin(plan);
            result = Status::Ok;
        } else if (ready_) {
            result = submitJoin(plan);
            if (result == Status::Busy) {
                // Tahoe init submits its generation-zero firmware scan before
                // publishing DriverReady. The radio can therefore reject the
                // first Join as Busy while that scan drains. Preserve this
                // exact decoded request and let terminal/tick retry it within
                // the normal bounded join admission window.
                deferJoin(plan);
                result = Status::Ok;
            }
        }
    }
    if (result == Status::Ok) ++joinRequests_;
    erase(&plan, sizeof(plan));
    return result;
}
Status Backend::abortScan() {
    if (stopped_) return Status::NotReady;
    if (scanQueued_) {
        // The WCL request was not admitted successfully. Retire its event
        // state without guessing whether HAL is already draining a scan.
        finishQueuedScan(NativeAborted);
        return Status::Ok;
    }
    if (scanPending_) {
        if (!operations_.cancelScan) return Status::Unsupported;
        const Status cancelled = operations_.cancelScan(operations_.context);
        if (cancelled != Status::Ok) return cancelled;
        scanPending_ = false; scanDraining_ = true; scanRemaining_ = 0;
        // Cancelling is accepted, not hardware completion. Delay native 237
        // until the terminal event releases the same firmware lease.
        scanAbortNotification_ = true;
    }
    return Status::Ok;
}
Status Backend::leave(bool abortJoin) {
    if (stopped_) return Status::NotReady;
    if (abortJoin && deferred_) {
        // AbortJoin only cancels a WCL request the radio has never admitted.
        // Preserve any older live association and do not call radioLeave().
        cancelDeferredJoin();
        return Status::Ok;
    }
    joinPending_ = deferred_ = associated_ = firstBeacon_ = authorized_ = bssValid_ = false;
    joinRemaining_ = 0;
    deferredJoinGeneration_ = 0;
    erase(&deferredJoin_, sizeof(deferredJoin_));
    erase(associatedBss_, sizeof(associatedBss_));
    erase(associatedFrame_, sizeof(associatedFrame_));
    if (operations_.leave) operations_.leave(operations_.context);
    if (abortJoin) post(JoinAborted, nullptr, 0);
    return Status::Ok;
}
void Backend::beginAddressChange() {
    if (stopped_) return;
    addressPreviousReady_ = ready_;
    addressPreviousAuthorized_ = authorized_;
    addressChanging_ = true; ready_ = false;
    authorized_ = false;
}
void Backend::cancelAddressChange() {
    if (stopped_ || !addressChanging_) return;
    // A zero-wait HAL quiesce can reject Busy without stopping hardware.
    // No layer has changed, so preserve that real pre-request state.
    addressChanging_ = false;
    ready_ = addressPreviousReady_;
    authorized_ = addressPreviousAuthorized_;
}
void Backend::driverState(bool isReady) {
    if (stopped_) return;
    ready_ = isReady;
    if (!isReady) observeAuthorization(false);
    if (addressChanging_) {
        if (!isReady) return; // Address reconfiguration is not a new native reset.
        addressChanging_ = false;
        retryDeferredJoin();
        return;
    }
    uint8_t reset[4]; write32(reset, isReady ? 1 : 0);
    post(DriverReset, reset, sizeof(reset));
    uint8_t availability[0xf8] {};
    write32(availability, 3); write32(availability + 8, isReady ? 1 : 0);
    write32(availability + 16, isReady ? 0xe0821803 : 0xe0821804);
    post(DriverAvailability, availability, sizeof(availability));
    if (!isReady) {
        if (scanPending_) {
            if (scanQueued_) {
                // Retire the WCL request. Busy alone cannot prove whether HAL
                // started a drain; HAL retains ownership of its radio lease.
                finishQueuedScan(NativeOffline);
            } else {
                scanPending_ = false; scanDraining_ = true;
                scanAbortNotification_ = false; scanRemaining_ = 0;
                uint8_t payload[4]; write32(payload, NativeOffline);
                post(ScanFinished, payload, sizeof(payload));
            }
        }
        finishJoin(1, NativeOffline);
        authorized_ = false;
    }
}
void Backend::retryDeferredJoin() {
    if (stopped_ || !ready_ || addressChanging_ || !deferred_) return;
    const uint32_t generation = deferredJoinGeneration_;
    if (!generation) return;
    const uint32_t remaining = joinRemaining_;
    const Status result = submitJoin(deferredJoin_);
    // Entry points are serialized by the owning driver gate, but retain an
    // explicit generation check so a superseded plan is never revived if a
    // radio adapter synchronously re-enters its event path.
    if (!deferred_ || generation != deferredJoinGeneration_) return;
    if (result == Status::Busy || result == Status::NotReady) {
        // Keep the same owned JoinPlan and its original admission deadline.
        deferred_ = joinPending_ = true; joinRemaining_ = remaining;
        return;
    }
    if (result == Status::Ok) {
        clearDeferredJoin();
    } else {
        // Preserve the queued target through finishJoin(); submitJoin may
        // return Unsupported without touching target_ or active-link state.
        joinPending_ = true;
        finishJoin(1, NativeFailed);
    }
}
void Backend::observeScanComplete(uint32_t generation, uint32_t firmwareStatus) {
    if (firmwareStatus != 1 && firmwareStatus != 2) return;
    // An unowned init-scan terminal can release a HAL lease and permit one
    // retry. It is not completion evidence for the queued WCL request.
    if (!generation) retryDeferredScan();
    // A genuine terminal event may also release the HAL's generation-zero
    // initial scan. It never completes a native scan, but can unblock a join.
    retryDeferredJoin();
    if (!generation || generation != scanGeneration_) return;
    if (scanDraining_) {
        scanDraining_ = false;
        scanGeneration_ = scanRemaining_ = 0;
        scanQueued_ = false;
        erase(&deferredScanPlan_, sizeof(deferredScanPlan_));
        if (scanAbortNotification_) {
            scanAbortNotification_ = false;
            uint8_t payload[4]; write32(payload, NativeAborted);
            post(ScanFinished, payload, sizeof(payload));
        }
        return;
    }
    if (!ready() || !scanPending_) return;
    scanPending_ = scanQueued_ = false;
    scanRemaining_ = scanGeneration_ = 0;
    erase(&deferredScanPlan_, sizeof(deferredScanPlan_));
    uint8_t payload[4] {}; write32(payload, firmwareStatus == 1 ? 0 : NativeAborted);
    post(ScanFinished, payload, sizeof(payload));
}

void Backend::observeScanReset(uint32_t generation) {
    if (stopped_ || !generation || generation != scanGeneration_) return;
    if (scanQueued_) {
        finishQueuedScan(NativeOffline);
        return;
    }
    const bool notify = scanPending_ || (scanDraining_ && scanAbortNotification_);
    const uint32_t status = scanPending_ ? NativeOffline : NativeAborted;
    scanPending_ = scanDraining_ = scanAbortNotification_ = false;
    scanRemaining_ = scanGeneration_ = 0;
    if (notify) {
        uint8_t payload[4]; write32(payload, status);
        post(ScanFinished, payload, sizeof(payload));
    }
}
void Backend::addressHardwareStopped() {
    // Called synchronously on the owned gate only after a real address-change
    // quiesce. This also retires a native scan queued before HAL admission.
    if (!stopped_ && addressChanging_) observeScanReset(scanGeneration_);
}
void Backend::observeAssociation(uint16_t status, const uint8_t *bssid) {
    if (stopped_ || !joinPending_ || deferred_ || !equalAddress(target_, bssid)) return;
    uint8_t payload[AssociationEventSize] {};
    write16(payload, status); copyBytes(payload + 5, target_, 6);
    write32(payload + 0x14, status ? NativeFailed : 0);
    post(Association, payload, sizeof(payload));
    associated_ = status == 0;
    if (status) finishJoin(status, NativeFailed);
}
void Backend::observeAuthorization(bool up) {
    if (stopped_) return;
    // Authorization may still be reported for the previous association while
    // a Busy Join is queued. A later accepted retry starts with fresh auth state.
    if (deferred_ && up) return;
    authorized_ = up;
    if (!up && linkPublished_) {
        publishLink(false);
        associated_ = firstBeacon_ = bssValid_ = false;
    }
    maybeConnected();
}
void Backend::publishLink(bool up) {
    if (linkPublished_ == up) return;
    // Native 25G241 event216: AP[6], link-up byte, debounce byte, reason32,
    // optional beacon timestamp32. WCLNetManager reads byte6 to select LINK_UP.
    // The adapter supplies the native owner's current debounce state at emit.
    uint8_t payload[LinkEventSize] {};
    if (up) copyBytes(linkedAddress_, target_, sizeof(linkedAddress_));
    copyBytes(payload, linkedAddress_, sizeof(linkedAddress_));
    payload[6] = up ? 1 : 0;
    write32(payload + 8, 255); // Unspecified; do not invent a radio reason.
    linkPublished_ = up;
    post(Link, payload, sizeof(payload));
    if (!up) erase(linkedAddress_, sizeof(linkedAddress_));
}
void Backend::observeBeacon(const Beacon &b) {
    if (stopped_ || !b.ssid || !validAddress(b.bssid) || b.ssidLength > 32 ||
        !b.channel || b.channel > 196 || !validateIEs(b.ies, b.ieLength)) return;
    ++realBeacons_;
    if (scanPending_) ++pendingScanBeacons_;
    const size_t length = BeaconPrefixSize + b.ieLength;
    erase(beaconMessage_, sizeof(beaconMessage_));
    write32(beaconMessage_, uint32_t(b.ieLength));
    write16(beaconMessage_ + 4, b.channelSpec);
    copyBytes(beaconMessage_ + 6, b.ssid, b.ssidLength);
    beaconMessage_[0x26] = uint8_t(b.ssidLength);
    beaconMessage_[0x27] = b.channel;
    copyBytes(beaconMessage_ + 0x29, b.bssid, 6);
    write32(beaconMessage_ + 0x30, uint32_t(b.rssi));
    write16(beaconMessage_ + 0x34, uint16_t(b.noise));
    write16(beaconMessage_ + 0x36, uint16_t(b.snr));
    write16(beaconMessage_ + 0x38, b.interval);
    write16(beaconMessage_ + 0x3a, b.capability);
    write32(beaconMessage_ + 0x40, (1U << 1) | (1U << 14));
    copyBytes(beaconMessage_ + BeaconPrefixSize, b.ies, b.ieLength);
    if (scanPending_ || joinPending_ || equalAddress(target_, b.bssid))
        post(ScanBeacon, beaconMessage_, length);
    if (!associated_ || !equalAddress(target_, b.bssid) || !b.frame ||
        b.frameLength < 36 || b.frameLength > 2048 || (b.frame[0] & 0xfc) != 0x80)
        return;
    ++associatedBeacons_;
    erase(associatedBss_, sizeof(associatedBss_));
    copyBytes(associatedBss_, beaconMessage_, length);
    erase(associatedFrame_, sizeof(associatedFrame_));
    write32(associatedFrame_, uint32_t(b.frameLength));
    copyBytes(associatedFrame_ + 4, b.frame, b.frameLength);
    bssValid_ = true;
    if (joinPending_ && !firstBeacon_) {
        firstBeacon_ = true;
        uint8_t payload[FirstBeaconEventSize] {};
        copyBytes(payload + 4, target_, 6);
        post(FirstBeacon, payload, sizeof(payload));
    }
    maybeConnected();
}
void Backend::maybeConnected() {
    if (ready() && joinPending_ && !deferred_ && associated_ &&
        firstBeacon_ && authorized_ && bssValid_) {
        // Real prerequisites first. Native NET_MANAGER must see LINK_UP before
        // JOIN_MANAGER's CONNECT_COMPLETE, or it remains in LINK_DOWN.
        publishLink(true);
        finishJoin(0, 0);
    }
}
void Backend::finishJoin(uint16_t status, uint32_t driverStatus) {
    if (!joinPending_) return;
    uint8_t resultTarget[sizeof(target_)];
    copyBytes(resultTarget, deferred_ ? deferredJoin_.bssid : target_, sizeof(resultTarget));
    joinPending_ = false; joinRemaining_ = 0;
    clearDeferredJoin();
    uint8_t payload[ConnectionEventSize] {};
    write16(payload, status); copyBytes(payload + 4, resultTarget, sizeof(resultTarget));
    write32(payload + 12, driverStatus);
    post(Connection, payload, sizeof(payload));
    erase(resultTarget, sizeof(resultTarget));
}
void Backend::tick(uint32_t elapsed) {
    if (stopped_) return;
    if (ready() && linkPublished_ && associated_ && authorized_ && bssValid_) {
        // InfraInterface's default createLQMData() returns null on 25G241.
        // Publish the audited native LQM event directly, with only the real
        // beacon delta valid. Two snapshots of this association are required.
        if (beaconBaselineValid_) {
            uint8_t statistics[BeaconLqmSize] {};
            write32(statistics + 0x28, associatedBeacons_ - reportedBeacons_);
            statistics[0x30] = 1; // Beacon count is valid; RF/rate/TX data is absent.
            statistics[0x1d8] = statistics[0x1d9] = 1; // Both snapshots valid.
            post(BeaconLqm, statistics, sizeof(statistics));
        }
        reportedBeacons_ = associatedBeacons_;
        beaconBaselineValid_ = true;
    }
    if (scanPending_) {
        if (scanQueued_) {
            if (elapsed >= scanRemaining_) {
                finishQueuedScan(NativeTimeout);
            } else {
                scanRemaining_ -= elapsed;
                retryDeferredScan();
            }
        } else if (elapsed >= scanRemaining_) {
            scanPending_ = false; scanDraining_ = true; scanAbortNotification_ = false; scanRemaining_ = 0;
            uint8_t payload[4]; write32(payload, NativeTimeout);
            post(ScanFinished, payload, sizeof(payload));
        } else scanRemaining_ -= elapsed;
    }
    if (joinPending_ && deferred_) {
        if (elapsed >= joinRemaining_) {
            finishJoin(1, NativeTimeout);
        } else {
            joinRemaining_ -= elapsed;
            retryDeferredJoin();
        }
    } else if (joinPending_) {
        if (elapsed >= joinRemaining_) {
            finishJoin(1, NativeTimeout);
            if (operations_.leave) operations_.leave(operations_.context);
        } else joinRemaining_ -= elapsed;
    }
}
void Backend::stop() {
    stopped_ = true; ready_ = false;
    linkPublished_ = false;
    erase(linkedAddress_, sizeof(linkedAddress_));
    erase(&deferredJoin_, sizeof(deferredJoin_));
    erase(&deferredScanPlan_, sizeof(deferredScanPlan_));
    erase(associatedBss_, sizeof(associatedBss_));
    erase(associatedFrame_, sizeof(associatedFrame_));
    scanPending_ = scanQueued_ = scanDraining_ = scanAbortNotification_ = joinPending_ = false;
    clearDeferredJoin();
}
Status Backend::copyBss(void *out, size_t n) const {
    if (stopped_ || !bssValid_) return Status::NotReady;
    if (!out || n != sizeof(associatedBss_)) return Status::BadRequest;
    copyBytes(out, associatedBss_, n); return Status::Ok;
}
Status Backend::copyBeacon(void *out, size_t n) const {
    if (stopped_ || !bssValid_) return Status::NotReady;
    if (!out || n != sizeof(associatedFrame_)) return Status::BadRequest;
    copyBytes(out, associatedFrame_, n); return Status::Ok;
}
}

#if defined(KERNEL) && defined(AIRPORT_TAHOE)
#include "wcl_ingress.hpp"
#include <IOKit/IOLib.h>
namespace NativeWifi {
bool Ingress::initialize(IOCommandGate *gate, Dispatch fn, void *context) {
    if (lock_ || !gate || !fn || !context) return false;
    lock_ = IOSimpleLockAlloc();
    if (!lock_) return false;
    call_ = thread_call_allocate_with_options(run, this,
        THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
    if (!call_) { IOSimpleLockFree(lock_); lock_ = nullptr; return false; }
    gate_ = gate; gate_->retain(); dispatch_ = fn; context_ = context;
    return true;
}
bool Ingress::signal(unsigned kind, uint32_t status, const uint8_t *address, uint32_t detail) {
    return append(kind, status, address, nullptr, detail);
}
bool Ingress::receive(const Beacon &beacon) {
    if (!beacon.frame || beacon.frameLength < 36 || beacon.frameLength > 2048 ||
        beacon.ssidLength > 32 || !beacon.ssid || !beacon.bssid ||
        beacon.ies != beacon.frame + 36 || beacon.ieLength != beacon.frameLength - 36 ||
        !validateIEs(beacon.ies, beacon.ieLength)) return false;
    return append(5, 0, beacon.bssid, &beacon);
}
bool Ingress::append(unsigned kind, uint32_t status, const uint8_t *address, const Beacon *b, uint32_t detail) {
    if (!lock_) return false;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock_);
    // RX bursts cannot consume the eight slots reserved for control events.
    if (closing_ || count_ == Capacity || (b && count_ >= Capacity-8)) {
        if (!closing_) __atomic_fetch_add(&overflow_, uint64_t(1), __ATOMIC_RELAXED);
        IOSimpleLockUnlockEnableInterrupt(lock_, irq); return false;
    }
    IngressEntry &entry = entries_[(first_ + count_) % Capacity];
    entry.kind = kind; entry.value = status; entry.detail = detail; entry.frameLength = 0;
    for (unsigned i = 0; i < 6; ++i) entry.bssid[i] = address ? address[i] : 0;
    if (b) {
        entry.ssidLength = uint8_t(b->ssidLength); entry.channel = b->channel;
        entry.channelSpec = b->channelSpec; entry.interval = b->interval;
        entry.capability = b->capability; entry.rssi = b->rssi;
        entry.noise = b->noise; entry.snr = b->snr;
        entry.frameLength = uint16_t(b->frameLength);
        for (size_t i = 0; i < b->ssidLength; ++i) entry.ssid[i] = b->ssid[i];
        for (size_t i = 0; i < b->frameLength; ++i) entry.frame[i] = b->frame[i];
    }
    ++count_;
    // enter and the closing barrier are serialized by the same real IRQ lock.
    thread_call_enter(call_);
    IOSimpleLockUnlockEnableInterrupt(lock_, irq);
    return true;
}
IOReturn Ingress::dispatchGated(OSObject *, void *raw, void *, void *, void *) {
    auto self = static_cast<Ingress *>(raw);
    self->dispatch_(self->context_, self->delivery_);
    return kIOReturnSuccess;
}
void Ingress::run(thread_call_param_t raw, thread_call_param_t) {
    auto self = static_cast<Ingress *>(raw);
    for (unsigned delivered = 0; delivered < Capacity; ++delivered) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(self->lock_);
        if (self->closing_ || !self->count_) {
            IOSimpleLockUnlockEnableInterrupt(self->lock_, irq); return;
        }
        self->delivery_ = self->entries_[self->first_];
        self->first_ = (self->first_ + 1) % Capacity; --self->count_;
        IOSimpleLockUnlockEnableInterrupt(self->lock_, irq);
        self->gate_->runAction(dispatchGated, self);
    }
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(self->lock_);
    if (!self->closing_ && self->count_) thread_call_enter(self->call_);
    IOSimpleLockUnlockEnableInterrupt(self->lock_, irq);
}
bool Ingress::shutdown() {
    if (!lock_) return true;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock_);
    closing_ = true;
    IOSimpleLockUnlockEnableInterrupt(lock_, irq);
    if (gate_->getWorkLoop() && gate_->getWorkLoop()->inGate()) return false;
    // cancel_wait is deliberately outside both the spin lock and native gate.
    thread_call_cancel_wait(call_);
    stopped_ = true;
    return true;
}
bool Ingress::destroy() {
    if (!lock_) return true;
    if (!stopped_) return false;
    if (!thread_call_free(call_)) return false;
    call_ = nullptr;
    gate_->release(); gate_ = nullptr;
    IOSimpleLockFree(lock_); lock_ = nullptr;
    erase(entries_, sizeof(entries_)); erase(&delivery_, sizeof(delivery_));
    context_ = nullptr; dispatch_ = nullptr;
    return true;
}
}
#endif
