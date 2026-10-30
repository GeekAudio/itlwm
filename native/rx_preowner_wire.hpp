// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_RX_PREOWNER_WIRE_HPP
#define NATIVE_RX_PREOWNER_WIRE_HPP

#include "rx_preowner_observation.hpp"

#include <stddef.h>
#include <stdint.h>

// Wire format v1 is a sequence of little-endian 64-bit words. Each source
// field is promoted and written explicitly; C++ object layout and padding are
// never serialized. The production target is x86_64 little-endian.
namespace NativeRxPreOwnerWire {

constexpr uint64_t kMagic = 0x31304e574f58524eULL; // "NRXOWN01" as LE bytes
constexpr uint64_t kVersion = 1;
constexpr size_t kHeaderWordCount = 3;
constexpr size_t kSnapshotWordCount =
    1 + 1 + 1 + 4 + 3 + 1 +
    NativeRxPreOwner::kEventKindCount + NativeRxPreOwner::kRxClassCount +
    5 + NativeRxPreOwner::kOwnerReasonCount + 12;
constexpr size_t kEventWordCount = 39;
constexpr size_t kWitnessWordCount = 1 + kEventWordCount;
constexpr size_t kWitnessCount = 2 * NativeRxPreOwner::kWitnessBankCapacity;
constexpr size_t kWireWordCount =
    kHeaderWordCount + kSnapshotWordCount + kWitnessCount * kWitnessWordCount;
constexpr size_t kMaxWireWordCount = 1024;

static_assert(kSnapshotWordCount == 68, "update Test087 wire snapshot schema");
static_assert(kEventWordCount == 39, "update Test087 wire event schema");
static_assert(kWireWordCount == 711, "update Test087 wire schema version");
static_assert(kWireWordCount <= kMaxWireWordCount,
              "wire record exceeds fixed caller buffer");

class Writer {
public:
    explicit Writer(uint64_t *out) noexcept : out_(out), count_(0) {}

    void u32(uint32_t value) noexcept { out_[count_++] = value; }
    void u64(uint64_t value) noexcept { out_[count_++] = value; }
    size_t count() const noexcept { return count_; }

private:
    uint64_t *out_;
    size_t count_;
};

inline void writeEvent(Writer &writer,
                       const NativeRxPreOwner::Event &event) noexcept
{
    writer.u64(event.nowUs);
    writer.u32(event.generation);
    writer.u32(static_cast<uint32_t>(event.kind));
    writer.u32(static_cast<uint32_t>(event.rxClass));
    writer.u32(static_cast<uint32_t>(event.ownerReason));
    writer.u32(static_cast<uint32_t>(event.irqSource));
    writer.u32(event.irqCause);
    writer.u32(event.notificationCode);
    writer.u32(event.physicalRingPresent);
    writer.u32(event.physicalRing);
    writer.u32(event.physicalSlotPresent);
    writer.u32(event.physicalSlot);
    writer.u32(event.notificationQidPresent);
    writer.u32(event.notificationQid);
    writer.u32(event.notificationIndexPresent);
    writer.u32(event.notificationIndex);
    writer.u32(event.payloadLen);
    writer.u32(event.descSize);
    writer.u32(event.mpduLengthPresent);
    writer.u32(event.mpduLength);
    writer.u32(event.rawStatusPresent);
    writer.u32(event.rawStatus);
    writer.u32(event.rawMacPhyIndexPresent);
    writer.u32(event.rawMacPhyIndex);
    writer.u32(event.macPhyDecodeModePresent);
    writer.u32(event.macPhyDecodeMode);
    writer.u32(event.channelPresent);
    writer.u32(event.channel);
    writer.u32(event.macIndexPresent);
    writer.u32(event.macIndex);
    writer.u32(event.frameControlPresent);
    writer.u32(event.frameControl);
    writer.u32(event.sequenceControlPresent);
    writer.u32(event.sequenceControl);
    writer.u32(event.gp2OnAirRisePresent);
    writer.u32(event.gp2OnAirRiseRaw);
    writer.u32(event.tsfOnAirRisePresent);
    writer.u64(event.tsfOnAirRiseRaw);
    writer.u32(event.awdlCandidate);
}

inline bool isZeroEvent(const NativeRxPreOwner::Event &event) noexcept
{
    return event.nowUs == 0 && event.generation == 0 &&
        static_cast<uint32_t>(event.kind) == 0 &&
        static_cast<uint32_t>(event.rxClass) == 0 &&
        static_cast<uint32_t>(event.ownerReason) == 0 &&
        static_cast<uint32_t>(event.irqSource) == 0 && event.irqCause == 0 &&
        event.notificationCode == 0 && event.physicalRingPresent == 0 &&
        event.physicalRing == 0 && event.physicalSlotPresent == 0 &&
        event.physicalSlot == 0 && event.notificationQidPresent == 0 &&
        event.notificationQid == 0 && event.notificationIndexPresent == 0 &&
        event.notificationIndex == 0 && event.payloadLen == 0 &&
        event.descSize == 0 && event.mpduLengthPresent == 0 &&
        event.mpduLength == 0 && event.rawStatusPresent == 0 &&
        event.rawStatus == 0 && event.rawMacPhyIndexPresent == 0 &&
        event.rawMacPhyIndex == 0 && event.macPhyDecodeModePresent == 0 &&
        event.macPhyDecodeMode == 0 && event.channelPresent == 0 &&
        event.channel == 0 && event.macIndexPresent == 0 &&
        event.macIndex == 0 && event.frameControlPresent == 0 &&
        event.frameControl == 0 && event.sequenceControlPresent == 0 &&
        event.sequenceControl == 0 && event.gp2OnAirRisePresent == 0 &&
        event.gp2OnAirRiseRaw == 0 && event.tsfOnAirRisePresent == 0 &&
        event.tsfOnAirRiseRaw == 0 && event.awdlCandidate == 0;
}

inline bool canonicalWitnesses(const NativeRxPreOwner::Snapshot &snapshot) noexcept
{
    for (size_t index = 0;
         index < NativeRxPreOwner::kWitnessBankCapacity; ++index) {
        const auto &channel149 = snapshot.channel149Witnesses[index];
        const auto &non149 = snapshot.non149Witnesses[index];
        if ((!channel149.present && !isZeroEvent(channel149.event)) ||
            (!non149.present && !isZeroEvent(non149.event)))
            return false;
    }
    return true;
}

inline void writeWitness(Writer &writer,
                         const NativeRxPreOwner::Witness &witness) noexcept
{
    writer.u32(witness.present);
    writeEvent(writer, witness.event);
}

// Returns the encoded word count, or zero for an invalid snapshot, null
// output, or insufficient caller capacity. On failure the output is untouched.
inline size_t encode(const NativeRxPreOwner::Snapshot &snapshot,
                     uint64_t *out,
                     size_t capacityWords) noexcept
{
    if (!out || capacityWords < kWireWordCount ||
        !NativeRxPreOwner::validateSnapshot(snapshot) ||
        !canonicalWitnesses(snapshot))
        return 0;

    Writer writer(out);
    writer.u64(kMagic);
    writer.u64(kVersion);
    writer.u64(kWireWordCount);

    writer.u32(snapshot.schemaVersion);
    writer.u64(snapshot.captureSerial);
    writer.u32(snapshot.driverGeneration);
    writer.u64(snapshot.beginUs);
    writer.u64(snapshot.endUs);
    writer.u64(snapshot.deadlineUs);
    writer.u64(snapshot.snapshotUs);
    writer.u32(snapshot.active);
    writer.u32(snapshot.closed);
    writer.u32(static_cast<uint32_t>(snapshot.closeReason));
    writer.u32(snapshot.totalEvents);
    for (uint32_t i = 0; i < NativeRxPreOwner::kEventKindCount; ++i)
        writer.u32(snapshot.kindCounts[i]);
    for (uint32_t i = 0; i < NativeRxPreOwner::kRxClassCount; ++i)
        writer.u32(snapshot.rxClassCounts[i]);
    writer.u32(snapshot.dispatchCount);
    writer.u32(snapshot.mpduEntryCount);
    writer.u32(snapshot.awdlCandidateCount);
    writer.u32(snapshot.ownerQualifiedCount);
    writer.u32(snapshot.ownerFailedCount);
    for (uint32_t i = 0; i < NativeRxPreOwner::kOwnerReasonCount; ++i)
        writer.u32(snapshot.ownerReasonCounts[i]);
    writer.u32(snapshot.lockContentionLoss);
    writer.u32(snapshot.invalidSampleLoss);
    writer.u32(snapshot.generationMismatchLoss);
    writer.u32(snapshot.deadlineRejectCount);
    writer.u32(snapshot.clockReversalLoss);
    writer.u32(snapshot.witness149Overflow);
    writer.u32(snapshot.witnessNon149Overflow);
    writer.u32(snapshot.lossCount);
    writer.u32(snapshot.overflow);
    writer.u32(snapshot.counterOverflow);
    writer.u32(snapshot.witness149Count);
    writer.u32(snapshot.witnessNon149Count);
    for (uint32_t i = 0; i < NativeRxPreOwner::kWitnessBankCapacity; ++i)
        writeWitness(writer, snapshot.channel149Witnesses[i]);
    for (uint32_t i = 0; i < NativeRxPreOwner::kWitnessBankCapacity; ++i)
        writeWitness(writer, snapshot.non149Witnesses[i]);

    return writer.count() == kWireWordCount ? writer.count() : 0;
}

} // namespace NativeRxPreOwnerWire

#endif // NATIVE_RX_PREOWNER_WIRE_HPP
