// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

namespace NativeAwdlBSD {

// Numeric-only, fixed-size trace for the one-shot resident BSD attach path.
// It deliberately contains no kernel pointers, MAC addresses, or packet data.
enum AttachTraceStage : uint64_t {
    AttachStageNone = 0,
    AttachStageResidentLookup = 1,
    AttachStageEntryGuard = 2,
    AttachStageLiveAddressRead = 3,
    AttachStageLiveAddressMatch = 4,
    AttachStageClaim = 5,
    AttachStageLockAllocation = 6,
    AttachStageIfnetReference = 7,
    AttachStageCanAttach = 8,
    AttachStageInterfaceBound = 9,
    AttachStageFilterAttach = 10,
    AttachStageSetOffload = 11,
    AttachStageSetMtu = 12,
    AttachStageSetFlags = 13,
    AttachStageIPv6 = 14,
    AttachStageFinalReady = 15,
    AttachStageTerminal = 16
};

enum AttachTraceInputGuard : uint64_t {
    AttachInputGuardNone = 0,
    AttachInputGuardNullIfnet = 1,
    AttachInputGuardNullAddress = 2,
    AttachInputGuardExistingBridge = 3,
    AttachInputGuardClosingRequested = 4
};

enum AttachTraceResultDomain : uint64_t {
    AttachResultDomainNone = 0,
    AttachResultDomainRawKPI = 1,
    AttachResultDomainBoolean = 2
};

struct AttachTraceSnapshot {
    uint32_t versionBegin = 0;
    uint32_t versionEnd = 0;
    uint32_t complete = 0;
    uint32_t schemaVersion = 1;
    uint64_t revision = 0;
    uint64_t attemptSerial = 0;
    uint64_t lookupResultPresent = 0, lookupResultDomain = AttachResultDomainNone;
    uint64_t lookupResultValue = 0;
    uint64_t attempted = 0, bridgeEntered = 0, producerActive = 0;
    uint64_t done = 0, failed = 0, stage = AttachStageNone;
    uint64_t failurePresent = 0, failureStage = AttachStageNone;
    uint64_t failureResultPresent = 0, failureResultDomain = AttachResultDomainNone;
    uint64_t failureResultValue = 0;
    uint64_t inputGuardPresent = 0, inputGuardCode = AttachInputGuardNone;
    uint64_t liveAddressReadResultPresent = 0;
    uint64_t liveAddressReadResultDomain = AttachResultDomainNone;
    uint64_t liveAddressReadResultValue = 0;
    uint64_t liveAddressMatchPresent = 0, liveAddressMatch = 0;
    uint64_t claimAttempted = 0, claimSucceeded = 0;
    uint64_t lockAllocationPresent = 0, lockAllocated = 0;
    uint64_t ifnetReferenceResultPresent = 0;
    uint64_t ifnetReferenceResultDomain = AttachResultDomainNone;
    uint64_t ifnetReferenceResultValue = 0;
    uint64_t canAttachResultPresent = 0;
    uint64_t canAttachResultDomain = AttachResultDomainNone;
    uint64_t canAttachResultValue = 0, interfaceBound = 0;
    uint64_t ifFilterAttachResultPresent = 0;
    uint64_t ifFilterAttachResultDomain = AttachResultDomainNone;
    uint64_t ifFilterAttachResultValue = 0;
    uint64_t setOffloadResultPresent = 0;
    uint64_t setOffloadResultDomain = AttachResultDomainNone;
    uint64_t setOffloadResultValue = 0;
    uint64_t setMtuResultPresent = 0;
    uint64_t setMtuResultDomain = AttachResultDomainNone;
    uint64_t setMtuResultValue = 0;
    uint64_t setFlagsResultPresent = 0;
    uint64_t setFlagsResultDomain = AttachResultDomainNone;
    uint64_t setFlagsResultValue = 0;
    uint64_t ipv6ResultPresent = 0, ipv6ResultDomain = AttachResultDomainNone;
    uint64_t ipv6ResultValue = 0;
    uint64_t ipv6HasLinkLocalPresent = 0, ipv6HasLinkLocal = 0;
    uint64_t finalReadyResultPresent = 0;
    uint64_t finalReadyResultDomain = AttachResultDomainNone;
    uint64_t finalReadyResultValue = 0;
};

class AttachTraceLedger {
public:
    enum Field : unsigned {
        FRevision, FAttemptSerial, FLookupResultPresent, FLookupResultDomain,
        FLookupResultValue,
        FAttempted, FBridgeEntered, FProducerActive, FDone, FFailed, FStage,
        FFailurePresent, FFailureStage, FFailureResultPresent,
        FFailureResultDomain, FFailureResultValue, FInputGuardPresent,
        FInputGuardCode, FLiveAddressReadResultPresent,
        FLiveAddressReadResultDomain, FLiveAddressReadResultValue,
        FLiveAddressMatchPresent, FLiveAddressMatch, FClaimAttempted,
        FClaimSucceeded, FLockAllocationPresent, FLockAllocated,
        FIfnetReferenceResultPresent, FIfnetReferenceResultDomain,
        FIfnetReferenceResultValue, FCanAttachResultPresent,
        FCanAttachResultDomain, FCanAttachResultValue, FInterfaceBound,
        FIfFilterAttachResultPresent, FIfFilterAttachResultDomain,
        FIfFilterAttachResultValue, FSetOffloadResultPresent,
        FSetOffloadResultDomain, FSetOffloadResultValue,
        FSetMtuResultPresent, FSetMtuResultDomain, FSetMtuResultValue,
        FSetFlagsResultPresent, FSetFlagsResultDomain, FSetFlagsResultValue,
        FIPv6ResultPresent, FIPv6ResultDomain, FIPv6ResultValue,
        FIPv6HasLinkLocalPresent, FIPv6HasLinkLocal,
        FFinalReadyResultPresent, FFinalReadyResultDomain,
        FFinalReadyResultValue, FieldCount
    };

    void noteResidentLookupResult(int result) {
        update([&] {
            if (!get(FLookupResultPresent)) {
                put(FAttemptSerial, get(FAttemptSerial) + 1);
                put(FAttempted, 1);
                put(FLookupResultPresent, 1);
                put(FLookupResultDomain, AttachResultDomainRawKPI);
                put(FLookupResultValue, signedValue(result));
                put(FStage, AttachStageResidentLookup);
                if (result) {
                    fail(AttachStageResidentLookup,
                         AttachResultDomainRawKPI, true, signedValue(result));
                    finishFailureInUpdate();
                } else {
                    put(FProducerActive, 1);
                    put(FDone, 0);
                }
            }
        });
    }

    void beginAttempt() {
        update([&] {
            if (!get(FAttempted)) {
                put(FAttemptSerial, get(FAttemptSerial) + 1);
                put(FAttempted, 1);
            }
            if (get(FDone)) return;
            put(FAttempted, 1);
            put(FProducerActive, 1);
            put(FDone, 0);
            put(FStage, AttachStageEntryGuard);
        });
    }

    void failInputGuard(uint64_t code) {
        update([&] {
            put(FInputGuardPresent, 1);
            put(FInputGuardCode, code);
            fail(AttachStageEntryGuard, AttachResultDomainBoolean, true, 0);
            finishFailureInUpdate();
        });
    }

    void finishFailure() {
        update([&] { finishFailureInUpdate(); });
    }

    void markBridgeEntered() {
        update([&] {
            put(FBridgeEntered, 1);
            put(FStage, AttachStageLiveAddressRead);
        });
    }

    void recordLiveAddressRead(int result) {
        update([&] {
            put(FLiveAddressReadResultPresent, 1);
            put(FLiveAddressReadResultDomain, AttachResultDomainRawKPI);
            put(FLiveAddressReadResultValue, signedValue(result));
            put(FStage, AttachStageLiveAddressRead);
            if (result) fail(AttachStageLiveAddressRead,
                             AttachResultDomainRawKPI, true, signedValue(result));
        });
    }

    void recordLiveAddressMatch(bool matches) {
        update([&] {
            put(FLiveAddressMatchPresent, 1);
            put(FLiveAddressMatch, matches ? 1 : 0);
            put(FStage, AttachStageLiveAddressMatch);
            if (!matches) fail(AttachStageLiveAddressMatch,
                               AttachResultDomainBoolean, true, 0);
        });
    }

    void recordClaim(bool attempted, bool succeeded) {
        update([&] {
            put(FClaimAttempted, attempted ? 1 : 0);
            put(FClaimSucceeded, succeeded ? 1 : 0);
            put(FStage, AttachStageClaim);
            if (!succeeded) fail(AttachStageClaim, AttachResultDomainBoolean, true, 0);
        });
    }

    void recordLockAllocation(bool allocated) {
        update([&] {
            put(FLockAllocationPresent, 1);
            put(FLockAllocated, allocated ? 1 : 0);
            put(FStage, AttachStageLockAllocation);
            if (!allocated) fail(AttachStageLockAllocation,
                                 AttachResultDomainBoolean, true, 0);
        });
    }

    void recordIfnetReference(int result) {
        update([&] {
            put(FIfnetReferenceResultPresent, 1);
            put(FIfnetReferenceResultDomain, AttachResultDomainRawKPI);
            put(FIfnetReferenceResultValue, signedValue(result));
            put(FStage, AttachStageIfnetReference);
            if (result) fail(AttachStageIfnetReference,
                             AttachResultDomainRawKPI, true, signedValue(result));
        });
    }

    void recordCanAttach(bool allowed) {
        update([&] {
            put(FCanAttachResultPresent, 1);
            put(FCanAttachResultDomain, AttachResultDomainBoolean);
            put(FCanAttachResultValue, allowed ? 1 : 0);
            put(FInterfaceBound, allowed ? 1 : 0);
            put(FStage, AttachStageCanAttach);
            if (!allowed) fail(AttachStageCanAttach,
                               AttachResultDomainBoolean, true, 0);
        });
    }

    void recordFilterAttach(int result) {
        recordRaw(AttachStageFilterAttach, FIfFilterAttachResultPresent,
                  FIfFilterAttachResultDomain, FIfFilterAttachResultValue, result);
    }
    void recordSetOffload(int result) {
        recordRaw(AttachStageSetOffload, FSetOffloadResultPresent,
                  FSetOffloadResultDomain, FSetOffloadResultValue, result);
    }
    void recordSetMtu(int result) {
        recordRaw(AttachStageSetMtu, FSetMtuResultPresent,
                  FSetMtuResultDomain, FSetMtuResultValue, result);
    }
    void recordSetFlags(int result) {
        recordRaw(AttachStageSetFlags, FSetFlagsResultPresent,
                  FSetFlagsResultDomain, FSetFlagsResultValue, result);
    }
    void recordIPv6Result(int result) {
        update([&] {
            put(FIPv6ResultPresent, 1);
            put(FIPv6ResultDomain, AttachResultDomainRawKPI);
            put(FIPv6ResultValue, signedValue(result));
            put(FStage, AttachStageIPv6);
            if (result) fail(AttachStageIPv6, AttachResultDomainRawKPI,
                             true, signedValue(result));
        });
    }
    void recordIPv6LinkLocal(bool present) {
        update([&] {
            put(FIPv6HasLinkLocalPresent, 1);
            put(FIPv6HasLinkLocal, present ? 1 : 0);
            put(FStage, AttachStageIPv6);
        });
    }

    void finish(bool ready) {
        update([&] {
            put(FFinalReadyResultPresent, 1);
            put(FFinalReadyResultDomain, AttachResultDomainBoolean);
            put(FFinalReadyResultValue, ready ? 1 : 0);
            put(FStage, AttachStageFinalReady);
            if (!ready) fail(AttachStageFinalReady,
                             AttachResultDomainBoolean, true, 0);
            put(FProducerActive, 0);
            put(FDone, 1);
            if (get(FFailurePresent)) put(FFailed, 1);
            put(FStage, AttachStageTerminal);
        });
    }

    AttachTraceSnapshot snapshot() const {
        AttachTraceSnapshot out{};
        const uint32_t begin = __atomic_load_n(&version_, __ATOMIC_ACQUIRE);
        out.versionBegin = begin;
        out.schemaVersion = 1;
        if (begin & 1u) {
            out.versionEnd = begin;
            return out;
        }
#define ATTACH_TRACE_COPY(member, field) out.member = get(field)
        ATTACH_TRACE_COPY(revision, FRevision);
        ATTACH_TRACE_COPY(attemptSerial, FAttemptSerial);
        ATTACH_TRACE_COPY(lookupResultPresent, FLookupResultPresent);
        ATTACH_TRACE_COPY(lookupResultDomain, FLookupResultDomain);
        ATTACH_TRACE_COPY(lookupResultValue, FLookupResultValue);
        ATTACH_TRACE_COPY(attempted, FAttempted);
        ATTACH_TRACE_COPY(bridgeEntered, FBridgeEntered);
        ATTACH_TRACE_COPY(producerActive, FProducerActive);
        ATTACH_TRACE_COPY(done, FDone);
        ATTACH_TRACE_COPY(failed, FFailed);
        ATTACH_TRACE_COPY(stage, FStage);
        ATTACH_TRACE_COPY(failurePresent, FFailurePresent);
        ATTACH_TRACE_COPY(failureStage, FFailureStage);
        ATTACH_TRACE_COPY(failureResultPresent, FFailureResultPresent);
        ATTACH_TRACE_COPY(failureResultDomain, FFailureResultDomain);
        ATTACH_TRACE_COPY(failureResultValue, FFailureResultValue);
        ATTACH_TRACE_COPY(inputGuardPresent, FInputGuardPresent);
        ATTACH_TRACE_COPY(inputGuardCode, FInputGuardCode);
        ATTACH_TRACE_COPY(liveAddressReadResultPresent, FLiveAddressReadResultPresent);
        ATTACH_TRACE_COPY(liveAddressReadResultDomain, FLiveAddressReadResultDomain);
        ATTACH_TRACE_COPY(liveAddressReadResultValue, FLiveAddressReadResultValue);
        ATTACH_TRACE_COPY(liveAddressMatchPresent, FLiveAddressMatchPresent);
        ATTACH_TRACE_COPY(liveAddressMatch, FLiveAddressMatch);
        ATTACH_TRACE_COPY(claimAttempted, FClaimAttempted);
        ATTACH_TRACE_COPY(claimSucceeded, FClaimSucceeded);
        ATTACH_TRACE_COPY(lockAllocationPresent, FLockAllocationPresent);
        ATTACH_TRACE_COPY(lockAllocated, FLockAllocated);
        ATTACH_TRACE_COPY(ifnetReferenceResultPresent, FIfnetReferenceResultPresent);
        ATTACH_TRACE_COPY(ifnetReferenceResultDomain, FIfnetReferenceResultDomain);
        ATTACH_TRACE_COPY(ifnetReferenceResultValue, FIfnetReferenceResultValue);
        ATTACH_TRACE_COPY(canAttachResultPresent, FCanAttachResultPresent);
        ATTACH_TRACE_COPY(canAttachResultDomain, FCanAttachResultDomain);
        ATTACH_TRACE_COPY(canAttachResultValue, FCanAttachResultValue);
        ATTACH_TRACE_COPY(interfaceBound, FInterfaceBound);
        ATTACH_TRACE_COPY(ifFilterAttachResultPresent, FIfFilterAttachResultPresent);
        ATTACH_TRACE_COPY(ifFilterAttachResultDomain, FIfFilterAttachResultDomain);
        ATTACH_TRACE_COPY(ifFilterAttachResultValue, FIfFilterAttachResultValue);
        ATTACH_TRACE_COPY(setOffloadResultPresent, FSetOffloadResultPresent);
        ATTACH_TRACE_COPY(setOffloadResultDomain, FSetOffloadResultDomain);
        ATTACH_TRACE_COPY(setOffloadResultValue, FSetOffloadResultValue);
        ATTACH_TRACE_COPY(setMtuResultPresent, FSetMtuResultPresent);
        ATTACH_TRACE_COPY(setMtuResultDomain, FSetMtuResultDomain);
        ATTACH_TRACE_COPY(setMtuResultValue, FSetMtuResultValue);
        ATTACH_TRACE_COPY(setFlagsResultPresent, FSetFlagsResultPresent);
        ATTACH_TRACE_COPY(setFlagsResultDomain, FSetFlagsResultDomain);
        ATTACH_TRACE_COPY(setFlagsResultValue, FSetFlagsResultValue);
        ATTACH_TRACE_COPY(ipv6ResultPresent, FIPv6ResultPresent);
        ATTACH_TRACE_COPY(ipv6ResultDomain, FIPv6ResultDomain);
        ATTACH_TRACE_COPY(ipv6ResultValue, FIPv6ResultValue);
        ATTACH_TRACE_COPY(ipv6HasLinkLocalPresent, FIPv6HasLinkLocalPresent);
        ATTACH_TRACE_COPY(ipv6HasLinkLocal, FIPv6HasLinkLocal);
        ATTACH_TRACE_COPY(finalReadyResultPresent, FFinalReadyResultPresent);
        ATTACH_TRACE_COPY(finalReadyResultDomain, FFinalReadyResultDomain);
        ATTACH_TRACE_COPY(finalReadyResultValue, FFinalReadyResultValue);
#undef ATTACH_TRACE_COPY
        const uint32_t end = __atomic_load_n(&version_, __ATOMIC_ACQUIRE);
        out.versionEnd = end;
        out.complete = ((begin & 1u) == 0 && begin == end) ? 1u : 0u;
        return out;
    }

private:
    template <typename Fn>
    void update(Fn fn) {
        // All producers are serialized by the lifecycle owner thread. The
        // publisher is read-only and obtains a bounded seqlock snapshot.
        const uint32_t version = __atomic_load_n(&version_, __ATOMIC_RELAXED);
        __atomic_store_n(&version_, version + 1u, __ATOMIC_RELEASE);
        fn();
        __atomic_fetch_add(&values_[FRevision], uint64_t(1), __ATOMIC_RELAXED);
        __atomic_store_n(&version_, version + 2u, __ATOMIC_RELEASE);
    }
    uint64_t get(Field field) const {
        return __atomic_load_n(&values_[field], __ATOMIC_RELAXED);
    }
    void put(Field field, uint64_t value) {
        __atomic_store_n(&values_[field], value, __ATOMIC_RELAXED);
    }
    static uint64_t signedValue(int value) {
        return static_cast<uint64_t>(static_cast<int64_t>(value));
    }
    void fail(uint64_t stage, uint64_t domain, bool resultPresent,
              uint64_t resultValue) {
        if (!get(FFailurePresent)) {
            put(FFailurePresent, 1);
            put(FFailureStage, stage);
            put(FFailureResultPresent, resultPresent ? 1 : 0);
            put(FFailureResultDomain, resultPresent ? domain : AttachResultDomainNone);
            put(FFailureResultValue, resultPresent ? resultValue : 0);
        }
        put(FStage, stage);
        put(FFailed, 1);
    }
    void finishFailureInUpdate() {
        put(FProducerActive, 0);
        put(FDone, 1);
        put(FFailed, 1);
        put(FStage, AttachStageTerminal);
    }
    void recordRaw(uint64_t stage, Field present, Field domain, Field result,
                   int rawResult) {
        update([&] {
            put(present, 1);
            put(domain, AttachResultDomainRawKPI);
            put(result, signedValue(rawResult));
            put(FStage, stage);
            if (rawResult) fail(stage, AttachResultDomainRawKPI,
                                true, signedValue(rawResult));
        });
    }

    alignas(8) uint64_t values_[FieldCount]{};
    alignas(4) uint32_t version_ = 0;
};

} // namespace NativeAwdlBSD

