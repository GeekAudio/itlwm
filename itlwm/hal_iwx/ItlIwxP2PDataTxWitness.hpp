// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

// Directed-data-only evidence. One fixed row per opcode and queue relationship.
// Queue classification uses the decoded payload only. The raw RX header
// queue is evidence, and this storage never participates in completion matching.
namespace TahoeP2PDirectedDataTxWitness {

enum Slot : unsigned {
    kTxTarget, kTxUnresolved, kTxOther, kBaTarget, kBaUnresolved, kBaOther,
    kFirstHandlerReject, kSlotCount
};

enum Outcome : uint32_t {
    kNotDispatched, kDescriptorRejected, kLengthRejected, kTxPassedThrough,
    kTxCompleted, kTxRejected, kBaDispatched, kBaRejected
};

// handlerReason uses this enum for kTxPassedThrough and the HAL reason
// otherwise. Reasons are requested only for an observed target payload queue.
enum class TxPassThrough : uint32_t {
    kNone, kMissingOwner, kOutsideMainGate, kInvalidArguments, kNoDoorbell,
    kShortPayload, kQueueDecodeFailed, kQueueMismatch, kAllocationAndRaTidMismatch
};

enum Presence : uint32_t {
    kPayloadLength = 1u << 0, kQueue = 1u << 1, kRaTid = 1u << 2,
    kFrameCount = 1u << 3, kSequenceControl = 1u << 4,
    kFrameControl = 1u << 5, kByteCount = 1u << 6, kSsn = 1u << 7,
    kStatus = 1u << 8, kBaStationAndCount = 1u << 9, kBaTfd = 1u << 10
};

struct Record {
    uint64_t observedUs;
    uint32_t outcome;
    uint32_t handlerReason;
    uint32_t presence;
    uint32_t group;
    uint32_t command;
    uint32_t headerQueue;
    uint32_t headerIndex;
    uint32_t dispatchCode;
    uint32_t payloadLength;
    uint32_t queue;
    uint32_t raTid;
    uint32_t frameCount;
    uint32_t sequenceControl;
    uint32_t frameControl;
    uint32_t byteCount;
    uint32_t ssn;
    uint32_t status;
    uint32_t baStation;
    uint32_t baTfdCount;
    uint32_t baTid;
    uint32_t baIndex;
    uint32_t overflow;
};

struct Snapshot {
    uint32_t schema;
    uint32_t size;
    uint64_t ownerSerial;
    uint64_t runSerial;
    uint64_t stationAllocationSerial;
    uint64_t queueAllocationSerial;
    uint64_t doorbellUs;
    uint64_t preCloseUs;
    uint64_t terminalUs;
    uint32_t queue;
    uint32_t station;
    uint32_t descriptorIndex;
    uint32_t preCloseReason;
    Record records[kSlotCount];

    bool active() const { return runSerial != 0 && terminalUs == 0; }

    void remember(bool ba, const Record &record)
    {
        if (!active() || !record.observedUs)
            return;
        const bool hasQueue = (record.presence & kQueue) != 0;
        Slot slot = ba ? kBaOther : kTxOther;
        if (hasQueue && record.queue == queue)
            slot = ba ? kBaTarget : kTxTarget;
        else if (!hasQueue)
            slot = ba ? kBaUnresolved : kTxUnresolved;
        rememberFirst(records[slot], record);
        if (record.outcome == kTxRejected || record.outcome == kBaRejected ||
            (slot == kTxTarget && record.outcome == kTxPassedThrough))
            rememberFirst(records[kFirstHandlerReject], record);
    }

    void rememberClose(uint64_t nowUs, uint32_t reason)
    {
        if (active() && !preCloseUs) {
            preCloseUs = nowUs;
            preCloseReason = reason;
        }
    }

    bool seal(uint64_t owner, uint64_t run, uint64_t nowUs)
    {
        if (!run || runSerial != run || ownerSerial != owner)
            return false;
        if (!terminalUs)
            terminalUs = nowUs;
        return true;
    }
private:
    static void rememberFirst(Record &first, const Record &record)
    {
        if (!first.observedUs)
            first = record;
        else if (first.overflow != UINT32_MAX)
            ++first.overflow;
    }

};

static_assert(sizeof(Record) == 96, "Test127 record ABI");
static_assert(sizeof(Snapshot) == 752, "Test127 snapshot ABI");

} // namespace TahoeP2PDirectedDataTxWitness
