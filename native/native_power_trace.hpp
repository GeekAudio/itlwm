// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_NATIVE_POWER_TRACE_HPP
#define GEEK_NATIVE_POWER_TRACE_HPP

#include <stdint.h>
#include <string.h>

// Fixed-size metadata for Wi-Fi power, address, and disconnect control calls.
// Callers serialize Ledger::begin/record/snapshot with their existing short
// spin lock. The ledger allocates no memory and never stores network identity,
// credentials, packet contents, or per-packet events.
namespace NativePowerTrace {

static constexpr uint32_t kSchemaVersion = 1;
static constexpr uint32_t kCapacity = 32;

enum class Operation : uint32_t {
    kNone = 0,
    kPowerSet = 1,
    kAddress = 2,
    kAppleDisassociate = 3,
    kWclLeave = 4,
    kWclAbortJoin = 5,
    kHalEvent = 6,
};

enum class Phase : uint32_t {
    kUnknown = 0,
    kCallBegin = 1,
    kNativeActionBegin = 2,
    kNativeActionEnd = 3,
    kWaitBegin = 4,
    kWaitEnd = 5,
    kDisableBegin = 6,
    kDisableEnd = 7,
    kEnableBegin = 8,
    kEnableEnd = 9,
    kDisassociateBegin = 10,
    kDisassociateMgmtEnd = 11,
    kDisassociateStateEnd = 12,
    kAddressQuiesceBegin = 13,
    kAddressQuiesceEnd = 14,
    kAddressCommit = 15,
    kDriverEvent = 16,
    kNotificationCall = 17,
    kTimeout = 18,
    kCallEnd = 19,
};

struct Entry {
    uint64_t monotonicNs;
    uint64_t transitionRevision;
    uint32_t sequence;
    uint32_t callId;
    uint32_t operation;
    uint32_t phase;
    uint32_t powerEpoch;
    uint32_t powerFlags;       // bit 0 requested, bit 1 actual HAL READY
    uint32_t interfaceFlags;   // only IFF_UP | IFF_RUNNING
    uint32_t detail;           // operation-local numeric state/event
    int32_t result;            // IOReturn or errno, UINT32_MAX if unknown
    uint32_t reserved;
};

struct Snapshot {
    uint32_t schemaVersion;
    uint32_t capacity;
    uint32_t count;
    uint32_t newestSequence;
    Entry entries[kCapacity]; // chronological; oldest retained entry first
};

static_assert(sizeof(Entry) == 56, "power trace entry wire size changed");
static_assert(sizeof(Snapshot) == 1808, "power trace snapshot wire size changed");

class Ledger {
public:
    uint32_t begin(Operation operation, Phase phase, uint64_t monotonicNs,
                   uint32_t powerEpoch, uint32_t powerFlags,
                   uint32_t interfaceFlags, uint64_t transitionRevision,
                   uint32_t detail, int32_t result) {
        uint32_t callId = nextCallId_++;
        if (callId == 0) callId = nextCallId_++;
        append(callId, operation, phase, monotonicNs, powerEpoch, powerFlags,
               interfaceFlags, transitionRevision, detail, result);
        return callId;
    }

    void record(uint32_t callId, Operation operation, Phase phase,
                uint64_t monotonicNs, uint32_t powerEpoch,
                uint32_t powerFlags, uint32_t interfaceFlags,
                uint64_t transitionRevision, uint32_t detail, int32_t result) {
        append(callId, operation, phase, monotonicNs, powerEpoch, powerFlags,
               interfaceFlags, transitionRevision, detail, result);
    }

    void snapshot(Snapshot *out) const {
        if (!out) return;
        memset(out, 0, sizeof(*out));
        out->schemaVersion = kSchemaVersion;
        out->capacity = kCapacity;
        out->count = count_;
        out->newestSequence = nextSequence_ > 1 ? nextSequence_ - 1 : 0;
        const uint32_t firstSequence = nextSequence_ - count_;
        for (uint32_t i = 0; i < count_; ++i) {
            const uint32_t sequence = firstSequence + i;
            out->entries[i] = entries_[(sequence - 1) % kCapacity];
        }
    }

    uint32_t sequence() const { return nextSequence_ - 1; }

private:
    void append(uint32_t callId, Operation operation, Phase phase,
                uint64_t monotonicNs, uint32_t powerEpoch,
                uint32_t powerFlags, uint32_t interfaceFlags,
                uint64_t transitionRevision, uint32_t detail, int32_t result) {
        uint32_t sequence = nextSequence_++;
        if (sequence == 0) sequence = nextSequence_++;
        Entry entry {};
        entry.monotonicNs = monotonicNs;
        entry.transitionRevision = transitionRevision;
        entry.sequence = sequence;
        entry.callId = callId;
        entry.operation = static_cast<uint32_t>(operation);
        entry.phase = static_cast<uint32_t>(phase);
        entry.powerEpoch = powerEpoch;
        entry.powerFlags = powerFlags;
        entry.interfaceFlags = interfaceFlags;
        entry.detail = detail;
        entry.result = result;
        entries_[(sequence - 1) % kCapacity] = entry;
        if (count_ < kCapacity) ++count_;
    }

    uint32_t nextSequence_ {1};
    uint32_t nextCallId_ {1};
    uint32_t count_ {0};
    Entry entries_[kCapacity] {};
};

// This cache is owned by the serialized native ingress consumer. It compares
// the current READY bit plus the producer's revision at notification time, so
// it coalesces stale queue entries without losing a durable READY transition
// that occurred during an earlier postMessage call. GET_POWER is unchanged.
class NotificationState {
public:
    bool changed(uint32_t actualReady, uint64_t revision) const {
        return !hasPosted_ || (actualReady != 0) != lastPostedReady_ ||
               revision != lastPostedRevision_;
    }
    void didPost(uint32_t actualReady, uint64_t revision) {
        lastPostedReady_ = actualReady != 0;
        lastPostedRevision_ = revision;
        hasPosted_ = true;
    }
    bool hasPosted() const { return hasPosted_; }
    bool lastPostedReady() const { return lastPostedReady_; }
    uint64_t lastPostedRevision() const { return lastPostedRevision_; }

private:
    bool hasPosted_ {false};
    bool lastPostedReady_ {false};
    uint64_t lastPostedRevision_ {0};
};

} // namespace NativePowerTrace

#endif
