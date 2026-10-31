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
    kSystemPower = 7,
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
    kSystemPowerBegin = 20,
    kWakeRestoreDecision = 21,
    kWakeRestoreEnd = 22,
    kSystemPowerAck = 23,
    kSystemPowerAdapterEnd = 24,
};

// `Entry::detail` for Operation::kSystemPower. These values are diagnostic
// outcomes only; epoch, requested/ready flags, interface flags, and result are
// captured separately in the same fixed-size record.
enum class SystemPowerDetail : uint32_t {
    kSleep = 1,
    kWake = 2,
    kWakeRequestedOff = 3,
    kWakeStopping = 4,
    kWakeHalUnavailable = 5,
    kWakeInterfaceUnavailable = 6,
    kWakeAlreadyActive = 7,
    kWakePartialInterface = 8,
    kWakeRestoreAttempt = 9,
    kSleepStopping = 10,
    kWakeSupersededByNewerOff = 11,
    kSleepSupersededByNewerOn = 12,
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
    // Numeric auxiliary context; used for PM request generation on system
    // power events. Existing records and all other operations leave it zero.
    uint32_t auxiliary;
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
                   uint32_t detail, int32_t result, uint32_t auxiliary = 0) {
        uint32_t callId = nextCallId_++;
        if (callId == 0) callId = nextCallId_++;
        append(callId, operation, phase, monotonicNs, powerEpoch, powerFlags,
               interfaceFlags, transitionRevision, detail, result, auxiliary);
        return callId;
    }

    void record(uint32_t callId, Operation operation, Phase phase,
                uint64_t monotonicNs, uint32_t powerEpoch,
                uint32_t powerFlags, uint32_t interfaceFlags,
                uint64_t transitionRevision, uint32_t detail, int32_t result,
                uint32_t auxiliary = 0) {
        append(callId, operation, phase, monotonicNs, powerEpoch, powerFlags,
               interfaceFlags, transitionRevision, detail, result, auxiliary);
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
                uint64_t transitionRevision, uint32_t detail, int32_t result,
                uint32_t auxiliary) {
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
        entry.auxiliary = auxiliary;
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

// Immutable producer-time metadata for a power lifecycle event crossing the
// native ingress ring. The address transaction id is never filled in by the
// consumer; an event captured before a transaction therefore remains id zero.
struct PowerIngressContext {
    uint64_t transitionRevision {0};
    uint64_t addressRestartId {0};
    uint64_t addressRestartStartRevision {0};
    uint32_t powerEpoch {0};
    uint32_t faultSerial {0};
    uint32_t powerFlags {0};
    uint8_t faultSerialValid {0};
    uint8_t reserved[3] {};
};

enum class AddressRestartEvent : uint8_t {
    kResetBegin,
    kDriverStopped,
    kDriverReady,
};

enum class AddressRestartDecision : uint8_t {
    kPass,
    kSuppress,
    kComplete,
    kStale,
};

enum class AddressRestartOutcome : uint32_t {
    kNone = 0,
    kStarted = 1,
    kSuppressedResetBegin = 2,
    kSuppressedDriverStopped = 3,
    kCompletedReady = 4,
    kCancelledFaultSerial = 5,
    kCancelledEpochOrOff = 6,
    kCancelledCommitOrEnable = 7,
    kCancelledIdentity = 8,
    kExpired = 9,
    kStaleEvent = 10,
    kUnsupportedHal = 11,
    kCancelledManual = 12,
};

// Coalesce only the short READY dip caused by one committed, successful native
// address restart. Power state itself remains the real HAL READY bit. The
// caller serializes this object with the driver's existing command gate.
class AddressRestartNotification {
public:
    static constexpr uint32_t kDeadlineMilliseconds = 900;

    uint64_t begin(uint32_t powerEpoch, uint64_t transitionRevision,
                   uint32_t faultSerial, bool faultSerialValid,
                   uint32_t powerFlags, uint64_t nowNanoseconds) {
        if (active_ || !faultSerialValid || (powerFlags & 3U) != 3U)
            return 0;
        uint64_t id = nextId_++;
        if (!id) id = nextId_++;
        if (!id) return 0;
        id_ = id;
        powerEpoch_ = powerEpoch;
        startRevision_ = transitionRevision;
        faultSerial_ = faultSerial;
        constexpr uint64_t kDeadlineNanoseconds =
            uint64_t(kDeadlineMilliseconds) * 1000000ULL;
        deadlineNanoseconds_ = nowNanoseconds > UINT64_MAX - kDeadlineNanoseconds
            ? UINT64_MAX : nowNanoseconds + kDeadlineNanoseconds;
        committed_ = false;
        active_ = true;
        lastOutcome_ = AddressRestartOutcome::kStarted;
        return id_;
    }

    bool commit(uint64_t id, uint32_t powerEpoch, uint32_t faultSerial,
                bool faultSerialValid, bool commitSucceeded,
                bool enableSucceeded) {
        if (!matches(id, powerEpoch, faultSerial, faultSerialValid))
            return false;
        if (!commitSucceeded || !enableSucceeded) {
            retire(AddressRestartOutcome::kCancelledCommitOrEnable);
            return false;
        }
        committed_ = true;
        return true;
    }

    AddressRestartDecision observe(
        AddressRestartEvent event, const PowerIngressContext &entry,
        uint32_t currentEpoch, uint32_t currentPowerFlags,
        uint64_t currentRevision, uint32_t currentFaultSerial,
        bool currentFaultSerialValid, uint64_t nowNanoseconds) {
        if (!active_) return AddressRestartDecision::kPass;
        const bool oldEntry = entry.addressRestartId != id_ &&
            entry.transitionRevision <= startRevision_;
        const bool snapshotMatchesCurrent =
            entry.powerEpoch == currentEpoch &&
            entry.transitionRevision == currentRevision &&
            (entry.powerFlags & 3U) == (currentPowerFlags & 3U) &&
            (!entry.faultSerialValid || (currentFaultSerialValid &&
                entry.faultSerial == currentFaultSerial));
        const bool staleEntry = oldEntry || !snapshotMatchesCurrent;

        // Current transaction state takes precedence over stale queued events.
        // A real fault, explicit OFF, or elapsed deadline must end suppression
        // even when the next item in the ring belongs to an older lifecycle.
        if (!currentFaultSerialValid || currentFaultSerial != faultSerial_) {
            retire(AddressRestartOutcome::kCancelledFaultSerial);
            return staleEntry ? AddressRestartDecision::kStale
                              : AddressRestartDecision::kPass;
        }
        if (currentEpoch != powerEpoch_ || !(currentPowerFlags & 1U)) {
            retire(AddressRestartOutcome::kCancelledEpochOrOff);
            return staleEntry ? AddressRestartDecision::kStale
                              : AddressRestartDecision::kPass;
        }
        if (nowNanoseconds >= deadlineNanoseconds_) {
            retire(AddressRestartOutcome::kExpired);
            return staleEntry ? AddressRestartDecision::kStale
                              : AddressRestartDecision::kPass;
        }

        // Old READY/STOPPED entries can sit in the ring until after a newer
        // address transaction starts. They do not belong to that transaction.
        if (oldEntry) {
            lastOutcome_ = AddressRestartOutcome::kStaleEvent;
            return AddressRestartDecision::kStale;
        }

        if (entry.addressRestartId != id_ ||
            entry.addressRestartStartRevision != startRevision_) {
            retire(AddressRestartOutcome::kCancelledIdentity);
            return AddressRestartDecision::kPass;
        }
        if (entry.powerEpoch != powerEpoch_ || !entry.faultSerialValid ||
            entry.faultSerial != faultSerial_) {
            retire(AddressRestartOutcome::kCancelledFaultSerial);
            return AddressRestartDecision::kPass;
        }

        if (event == AddressRestartEvent::kDriverReady) {
            if (entry.transitionRevision != currentRevision ||
                !(entry.powerFlags & 2U) || !(currentPowerFlags & 2U))
            {
                lastOutcome_ = AddressRestartOutcome::kStaleEvent;
                return AddressRestartDecision::kStale;
            }
            if (!committed_) {
                retire(AddressRestartOutcome::kCancelledIdentity);
                return AddressRestartDecision::kPass;
            }
            retire(AddressRestartOutcome::kCompletedReady);
            return AddressRestartDecision::kComplete;
        }
        lastOutcome_ = event == AddressRestartEvent::kResetBegin
            ? AddressRestartOutcome::kSuppressedResetBegin
            : AddressRestartOutcome::kSuppressedDriverStopped;
        return AddressRestartDecision::kSuppress;
    }

    // The watchdog tick is only a sampling opportunity; use its absolute
    // monotonic timestamp so a tick just after begin cannot expire early.
    bool tick(uint64_t nowNanoseconds, uint32_t currentEpoch,
              uint32_t currentPowerFlags, uint32_t currentFaultSerial,
              bool currentFaultSerialValid) {
        if (!active_) return false;
        if (!currentFaultSerialValid || currentFaultSerial != faultSerial_) {
            retire(AddressRestartOutcome::kCancelledFaultSerial);
            return true;
        }
        if (currentEpoch != powerEpoch_ || !(currentPowerFlags & 1U)) {
            retire(AddressRestartOutcome::kCancelledEpochOrOff);
            return true;
        }
        if (nowNanoseconds >= deadlineNanoseconds_) {
            retire(AddressRestartOutcome::kExpired);
            return true;
        }
        return false;
    }

    bool cancelForEpoch(uint32_t currentEpoch) {
        if (!active_ || currentEpoch == powerEpoch_) return false;
        retire(AddressRestartOutcome::kCancelledEpochOrOff);
        return true;
    }
    void cancel(AddressRestartOutcome outcome =
                    AddressRestartOutcome::kCancelledManual) {
        if (active_) retire(outcome);
        else lastOutcome_ = outcome;
    }
    bool active() const { return active_; }
    bool committed() const { return committed_; }
    uint64_t id() const { return id_; }
    uint32_t powerEpoch() const { return powerEpoch_; }
    uint64_t startRevision() const { return startRevision_; }
    uint32_t faultSerial() const { return faultSerial_; }
    uint64_t deadlineNanoseconds() const { return deadlineNanoseconds_; }
    AddressRestartOutcome lastOutcome() const { return lastOutcome_; }

private:
    bool matches(uint64_t id, uint32_t powerEpoch, uint32_t faultSerial,
                 bool faultSerialValid) const {
        return active_ && id != 0 && id == id_ &&
            powerEpoch == powerEpoch_ && faultSerialValid &&
            faultSerial == faultSerial_;
    }
    void retire(AddressRestartOutcome outcome) {
        active_ = false;
        committed_ = false;
        deadlineNanoseconds_ = 0;
        lastOutcome_ = outcome;
    }

    uint64_t nextId_ {1};
    uint64_t id_ {0};
    uint64_t startRevision_ {0};
    uint32_t powerEpoch_ {0};
    uint32_t faultSerial_ {0};
    uint64_t deadlineNanoseconds_ {0};
    bool active_ {false};
    bool committed_ {false};
    AddressRestartOutcome lastOutcome_ {AddressRestartOutcome::kNone};
};

} // namespace NativePowerTrace

#endif
