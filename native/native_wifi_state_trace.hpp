// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_NATIVE_WIFI_STATE_TRACE_HPP
#define GEEK_NATIVE_WIFI_STATE_TRACE_HPP

#include <stdint.h>
#include <string.h>

// Bounded state-transition evidence for Wi-Fi UI/query behavior. This wire
// record intentionally carries only numeric summaries: never SSID/BSSID/MAC,
// packet payload, or key material. Callers serialize Ledger methods with the
// controller's existing trace lock; this type performs no allocation or IOKit
// publication.
namespace NativeWifiStateTrace {

static constexpr uint32_t kSchemaVersion = 1;
static constexpr uint32_t kKindCount = 4;
static constexpr uint32_t kPerKindCapacity = 4;
static constexpr uint32_t kCapacity = kKindCount * kPerKindCapacity;

enum class Kind : uint32_t {
    kPowerGet = 0,
    kSSIDQuery = 1,
    kBSSIDQuery = 2,
    kWclLinkEvent = 3,
};

enum Flag : uint32_t {
    kPMRequestedOn       = 1U << 0,
    kHALReady            = 1U << 1,
    kSystemPMOn           = 1U << 2,
    kStateLockMissing     = 1U << 3,
    kRestartActive        = 1U << 4,
    kRestartCommitted     = 1U << 5,
    kFaultSerialValid     = 1U << 6,
    kFaultSerialMatches   = 1U << 7,
    kRestartIdentityMatch = 1U << 8,
    kRestartEpochMatch    = 1U << 9,
    kRestartRevisionMatch = 1U << 10,
    kValueValid           = 1U << 11,
    kCurrentBSSSource     = 1U << 12,
    kDesiredSSIDSource    = 1U << 13,
    kControllerRun        = 1U << 14,
    kBSSPresent           = 1U << 15,
    kAddressComparisonValid = 1U << 16,
    kAddressMatchesDesired  = 1U << 17,
    kLinkUp                 = 1U << 18,
    kDebounceActive         = 1U << 19,
    // WCL event 216 is recorded as an emit/postMessage call only. No peer or
    // OS acknowledgement is implied by this bit.
    kEmitCallOnly           = 1U << 20,
    kRestartValidationEvaluated = 1U << 21,
};

struct Observation {
    uint64_t monotonicNs;
    uint64_t transitionRevision;
    uint64_t restartId;
    uint64_t restartRemainingNs;
    uint32_t sequence;
    uint32_t kind;
    uint32_t powerEpoch;
    uint32_t powerFlags;
    uint32_t faultSerial;
    int32_t result;
    uint32_t flags;
    uint32_t value;
    uint32_t auxiliary;
    uint32_t reserved;
};

struct Snapshot {
    uint32_t schemaVersion;
    uint32_t capacity;
    uint32_t count;
    uint32_t newestSequence;
    uint32_t overwrittenCount; // saturates; remains valid across sequence wrap
    uint32_t reserved; // explicit 8-byte alignment before the remaining header
    // Saturating call counters at snapshot time. Zero means the corresponding
    // getter/event was not observed; these do not prove delivery or success.
    uint32_t callCounts[kKindCount];
    Observation entries[kCapacity]; // chronological, oldest first
};

static_assert(sizeof(Observation) == 72, "Wi-Fi state observation wire size changed");
static_assert(sizeof(Snapshot) == 1192, "Wi-Fi state snapshot wire size changed");

class Ledger {
public:
    bool observe(const Observation &input, bool forceAppend = false) {
        const uint32_t kind = input.kind;
        if (kind >= kKindCount) return false;
        if (callCounts_[kind] != UINT32_MAX) ++callCounts_[kind];
        if (!forceAppend && hasLast_[kind] && sameState(last_[kind], input))
            return false;

        Observation entry = input;
        ++sequence_;
        if (!sequence_) ++sequence_;
        entry.sequence = sequence_;
        entries_[kind][next_[kind]] = entry;
        next_[kind] = (next_[kind] + 1U) % kPerKindCapacity;
        if (count_[kind] < kPerKindCapacity) ++count_[kind];
        else if (overwrittenCount_ != UINT32_MAX) ++overwrittenCount_;
        last_[kind] = entry;
        hasLast_[kind] = true;
        return true;
    }

    uint32_t sequence() const { return sequence_; }

    void snapshot(Snapshot *out) const {
        if (!out) return;
        memset(out, 0, sizeof(*out));
        out->schemaVersion = kSchemaVersion;
        out->capacity = kCapacity;
        out->newestSequence = sequence_;
        out->overwrittenCount = overwrittenCount_;
        for (uint32_t i = 0; i < kKindCount; ++i)
            out->callCounts[i] = callCounts_[i];
        for (uint32_t kind = 0; kind < kKindCount; ++kind) {
            const uint32_t oldest = (next_[kind] + kPerKindCapacity -
                                     count_[kind]) % kPerKindCapacity;
            for (uint32_t i = 0; i < count_[kind]; ++i)
                out->entries[out->count++] =
                    entries_[kind][(oldest + i) % kPerKindCapacity];
        }
        // Merge the four independently retained kind rings into chronological
        // order. Use modular distance from newestSequence so uint32 wrap does
        // not move a just-written entry to the beginning of the snapshot.
        for (uint32_t i = 1; i < out->count; ++i) {
            const Observation item = out->entries[i];
            const uint32_t itemAge = out->newestSequence - item.sequence;
            uint32_t position = i;
            while (position > 0) {
                const uint32_t previousAge =
                    out->newestSequence - out->entries[position - 1].sequence;
                if (previousAge >= itemAge) break;
                out->entries[position] = out->entries[position - 1];
                --position;
            }
            out->entries[position] = item;
        }
    }

private:
    static bool sameState(const Observation &a, const Observation &b) {
        // Time and remaining grace are deliberately excluded so a polling
        // getter does not evict meaningful transitions or churn IOKit state.
        return a.transitionRevision == b.transitionRevision &&
            a.restartId == b.restartId && a.kind == b.kind &&
            a.powerEpoch == b.powerEpoch && a.powerFlags == b.powerFlags &&
            a.faultSerial == b.faultSerial && a.result == b.result &&
            a.flags == b.flags && a.value == b.value &&
            a.auxiliary == b.auxiliary;
    }

    Observation entries_[kKindCount][kPerKindCapacity] {};
    Observation last_[kKindCount] {};
    uint32_t callCounts_[kKindCount] {};
    bool hasLast_[kKindCount] {};
    uint32_t next_[kKindCount] {};
    uint32_t count_[kKindCount] {};
    uint32_t sequence_ {0};
    uint32_t overwrittenCount_ {0};
};

} // namespace NativeWifiStateTrace

#endif // GEEK_NATIVE_WIFI_STATE_TRACE_HPP
