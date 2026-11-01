// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "p2p_rx149_data_input.hpp"

namespace NativeAwdlBSD {
namespace Rx149CaptureDiagnostics {

// Diagnostic-only, first eight candidate capture attempts for this driver
// lifetime. Never reset/reuse a slot, queue a packet, or authorize input.
constexpr uint32_t kCapacity = 8;
constexpr uint64_t kMagic = 0x3130445041435852ULL; // RXCAPD01, LE64
constexpr uint64_t kSchema = 1;
enum Check : uint32_t {
    BridgeLock = 1, Unprotected, LengthWithinLimit, PermitValid,
    PowerGenerationMatches, FirstGateClear, PermitCurrent,
    AuthorityGateClear, ActiveLeaseValid, ActiveVersionNonzero,
    LeaseIdentityMatches, PermitIdentityMatches, ActiveLeaseCurrent,
    ActivePermitCurrent, InterfaceIncarnationNonzero, InterfacePresent,
    NotClosing, NotDetached, RadioReady, ClosingNotRequested,
    RadioGenerationMatches, Attached, SequenceAvailable,
    RevisionAvailable, QueueSpaceAvailable
};
enum Field : size_t {
    Outcome, FailureCheck, EvaluatedMask, PassedMask,
    FrameLength, FrameControl, SequenceControl, HeaderPresentMask,
    PowerGeneration, PermitOwner, PermitContext, PermitPower,
    PermitStation, PermitRoc, PermitStartUs, PermitCapturedUs,
    PermitDeadlineUs, PermitChannel, PermitMacIndex, PermitDecodeMode,
    PermitRxStatus, LeaseOwner, LeaseContext, LeasePower, LeaseStation,
    LeaseRoc, LeaseStartUs, LeaseNowUs, LeaseFlags,
    DecisionNowUs, StatePresent, FirstGateWord, AuthorityGateWord,
    ActiveOwner, ActiveContext, ActivePower, ActiveStation, ActiveRoc,
    ActiveStartUs, ActiveNowUs, ActiveFlags, ActiveVersion,
    OwnerHighWater, InterfaceIncarnation, RadioGeneration, BridgeFlags,
    AttachedCount, ClosingRequested, ReceiptSequenceBefore,
    ReceiptRevisionBefore, QueueCountAtDecision, AssignedReceiptSequence,
    FieldCount
};
enum Header : size_t {
    Magic, Schema, WordCount, Capacity, ReservedBegin, ReservedEnd,
    CommittedMask, OverflowObserved, CompleteCut, HeaderCount
};

inline uint64_t leaseFlags(const NativeP2PRx149DataInput::Lease &v) {
    const bool flags[] = {v.compiled, v.runtimeEnabled, v.profileEnabled,
        v.profileSelected, v.receiveObservationOnly, v.leaseActive,
        v.ownerCurrent, v.epochsMatch, v.tokenMatches, v.commandReturned,
        v.commandSucceeded, v.deviceDiscoveryConfiguration, v.startSeen,
        v.startSucceeded, v.endSeen, v.outcomeUnknown};
    uint64_t result = 0;
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        if (flags[i]) result |= uint64_t{1} << i;
    return result;
}

struct Record {
    uint64_t value[FieldCount]{};

    // The caller passes the original predicate expression. Return exactly
    // its value so original &&/|| short-circuit order remains authoritative.
    bool test(Check check, bool result) {
        const uint64_t bit = uint64_t{1} << (uint32_t(check) - 1u);
        value[EvaluatedMask] |= bit;
        if (result) value[PassedMask] |= bit;
        else if (value[FailureCheck] == 0) value[FailureCheck] = check;
        return result;
    }
};

// All wire words are explicitly numeric. No pointers, addresses, payload,
// padding, or C++ bool layout is exported. Slot index+1 is publication order,
// not a global MPDU identifier; correlate SC/time/owner/epochs separately.
struct Wire {
    uint64_t header[HeaderCount]{};
    Record records[kCapacity]{};
};
constexpr size_t kWireWords = HeaderCount + kCapacity * FieldCount;
static_assert(sizeof(Wire) == kWireWords * sizeof(uint64_t), "wire padding");
static_assert(sizeof(Wire) < 4096, "bounded diagnostic snapshot");
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "LE64 wire target");

class Ledger {
public:
    void append(const Record &record) {
        uint32_t observed = __atomic_load_n(&reserved_, __ATOMIC_RELAXED);
        for (;;) {
            if (observed >= kCapacity) {
                // Sticky overflow, without an overflowing lifetime counter.
                __atomic_store_n(&overflow_, 1u, __ATOMIC_RELEASE);
                return;
            }
            if (__atomic_compare_exchange_n(&reserved_, &observed,
                    observed + 1u, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
                break;
        }
        records_[observed] = record;
        __atomic_store_n(&committed_[observed], 1u, __ATOMIC_RELEASE);
    }

    void copy(Wire *out) const {
        if (!out) return;
        *out = Wire{};
        out->header[Magic] = kMagic;
        out->header[Schema] = kSchema;
        out->header[WordCount] = kWireWords;
        out->header[Capacity] = kCapacity;
        const uint32_t begin = __atomic_load_n(&reserved_, __ATOMIC_ACQUIRE);
        out->header[ReservedBegin] = begin;
        for (uint32_t i = 0; i < begin; ++i) {
            if (__atomic_load_n(&committed_[i], __ATOMIC_ACQUIRE)) {
                out->records[i] = records_[i]; // immutable after release
                out->header[CommittedMask] |= uint64_t{1} << i;
            }
        }
        out->header[OverflowObserved] =
            __atomic_load_n(&overflow_, __ATOMIC_ACQUIRE);
        const uint32_t end = __atomic_load_n(&reserved_, __ATOMIC_ACQUIRE);
        out->header[ReservedEnd] = end;
        out->header[CompleteCut] = begin == end &&
            out->header[CommittedMask] == ((uint64_t{1} << begin) - 1u);
    }

private:
    uint32_t reserved_ = 0;
    uint32_t overflow_ = 0;
    uint32_t committed_[kCapacity]{};
    Record records_[kCapacity]{};
};

} // namespace Rx149CaptureDiagnostics
} // namespace NativeAwdlBSD
