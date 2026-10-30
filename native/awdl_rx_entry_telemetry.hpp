// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_RX_ENTRY_TELEMETRY_HPP
#define NATIVE_AWDL_RX_ENTRY_TELEMETRY_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdlRxEntry {

constexpr uint64_t kDiagnosticWindowUs = 900000ULL;

// The observation interval is half-open: the sample at exactly 900 ms is
// outside the window. Keep this predicate shared by the driver and host tests.
inline bool withinDiagnosticWindow(uint64_t nowUs, uint64_t startUs)
{
    return startUs != 0 && nowUs >= startUs &&
        nowUs - startUs < kDiagnosticWindowUs;
}

enum Counter : unsigned {
    OwnerGateEntries,
    StatusTruncated,
    CrcRejected,
    OverrunRejected,
    MpduLengthShort,
    DescriptorTruncated,
    PayloadTruncated,
    CapacityOverflow,
    FullDescriptor,
    FrameControlValid,
    ManagementFrame,
    ControlFrame,
    DataFrame,
    ReservedFrame,
    QosDataFrame,
    AwdlBssidCandidate,
    FilterMatchAvailable,
    FilterMatchUnavailable,
    Channel149,
    Channel36,
    ExpectedMacPhy149,
    MacIndex1Channel149,
    CounterCount
};

enum MacPhyIndexDecodeMode : uint32_t {
    MacPhyDecodeUnknown = 0,
    // Intel RX API before API59's band-in-RX data capability.
    MacPhyDecodeLegacy = 1,
    // API59 band-in-RX capability uses mac_phy_idx bits 6-7 for band.
    MacPhyDecodeBandInRx = 2
};

struct Epochs {
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
};

struct Layout {
    size_t descriptorSize;
    size_t mpduLengthOffset;
    size_t statusOffset;
    size_t macPhyIndexOffset;
    size_t filterMatchOffset;
    size_t channelOffset;
    size_t macContextOffset;
    size_t gp2OnAirRiseOffset;
    size_t tsfOnAirRiseOffset;
    size_t phyInfoOffset;
    uint32_t descriptorVersion;
    uint32_t minimumMpduLength;
    uint32_t crcOkMask;
    uint32_t overrunOkMask;
    uint32_t tsfOverloadMask;
    MacPhyIndexDecodeMode macPhyIndexDecodeMode;
    bool rpaEnabled;
};

// This view contains only bounded numeric fields. It never retains a pointer
// into the DMA buffer or copies frame bytes/addresses.
struct Inspection {
    uint32_t payloadLength;
    uint32_t dmaCapacity;
    uint32_t descriptorSize;
    uint32_t descriptorVersion;
    uint32_t minimumMpduLength;
    uint32_t statusPresent;
    uint32_t status;
    uint32_t crcOk;
    uint32_t overrunOk;
    uint32_t mpduLengthPresent;
    uint32_t mpduLength;
    uint32_t descriptorPresent;
    uint32_t macPhyIndexPresent;
    uint32_t macPhyIndex;
    uint32_t filterMatchPresent;
    uint32_t filterMatch;
    uint32_t rpaEnabled;
    uint32_t channelPresent;
    uint32_t channel;
    uint32_t macContextPresent;
    uint32_t macContext;
    uint32_t macIndexPresent;
    uint32_t macIndex;
    uint32_t phyIndexPresent;
    uint32_t phyIndex;
    uint32_t macPhyIndexDecodeModePresent;
    uint32_t macPhyIndexDecodeMode;
    uint32_t gp2OnAirRisePresent;
    uint32_t gp2OnAirRiseRaw;
    uint32_t tsfOnAirRisePresent;
    uint64_t tsfOnAirRiseRaw;
    uint32_t tsfValidPresent;
    uint32_t tsfValid;
    uint32_t capacityFits;
    uint32_t payloadFits;
    uint32_t frameRangeValid;
    uint32_t frameControlPresent;
    uint32_t frameControl;
    uint32_t frameType;
    uint32_t frameSubtype;
    uint32_t toDs;
    uint32_t fromDs;
};

// Dispatch fields are copied as numeric metadata only. Ring 0 is the actual
// RFH notification ring; notification qid/index identify a separate packet
// header namespace and must not be confused with the ring slot.
struct Dispatch {
    uint32_t hostRxMonotonicUsPresent;
    uint64_t hostRxMonotonicUs;
    uint32_t rxRingPresent;
    uint32_t rxRing;
    uint32_t rxRingSlotPresent;
    uint32_t rxRingSlot;
    uint32_t transportNotificationQidPresent;
    uint32_t transportNotificationQid;
    uint32_t transportNotificationIndexPresent;
    uint32_t transportNotificationIndex;
};

struct Witness {
    uint32_t present;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
    uint32_t payloadLength;
    uint32_t dmaCapacity;
    uint32_t descriptorSize;
    uint32_t descriptorVersion;
    uint32_t mpduLength;
    uint32_t statusPresent;
    uint32_t status; // Raw RX status bits; never interpreted as an address.
    uint32_t macPhyIndexPresent;
    uint32_t macPhyIndex; // Raw byte; decoded indices are separate fields.
    uint32_t filterMatchPresent;
    uint32_t filterMatch; // Raw numeric value; no semantic mapping.
    uint32_t rpaEnabled;
    uint32_t channelPresent;
    uint32_t channel;
    uint32_t macContextPresent;
    uint32_t macContext;
    uint32_t macIndexPresent;
    uint32_t macIndex;
    uint32_t phyIndexPresent;
    uint32_t phyIndex;
    uint32_t macPhyIndexDecodeModePresent;
    uint32_t macPhyIndexDecodeMode;
    uint32_t hostRxMonotonicUsPresent;
    uint64_t hostRxMonotonicUs;
    uint32_t gp2OnAirRisePresent;
    uint32_t gp2OnAirRiseRaw;
    uint32_t tsfOnAirRisePresent;
    uint64_t tsfOnAirRiseRaw;
    uint32_t tsfValidPresent;
    uint32_t tsfValid;
    uint32_t rxRingPresent;
    uint32_t rxRing;
    uint32_t rxRingSlotPresent;
    uint32_t rxRingSlot;
    uint32_t transportNotificationQidPresent;
    uint32_t transportNotificationQid;
    uint32_t transportNotificationIndexPresent;
    uint32_t transportNotificationIndex;
    uint32_t frameControlPresent;
    uint32_t frameControl;
    uint32_t frameType;
    uint32_t frameSubtype;
    uint32_t toDs;
    uint32_t fromDs;
    uint32_t awdlBssidCandidate;
};

struct Snapshot {
    uint32_t schema;
    uint32_t active;
    Epochs epochs;
    uint32_t counts[CounterCount];
    Witness lastDescriptor;
    Witness lastTarget;
    Witness lastMacIndexTarget;
    Witness lastAwdlDataCandidate;
};

static const uint32_t kSchema = 2;
static const uint32_t kCrcOkMask = 1u << 0;
static const uint32_t kOverrunOkMask = 1u << 1;

static uint32_t saturatedIncrement(uint32_t value)
{
    return value == UINT32_MAX ? value : value + 1u;
}

static uint32_t boundedSize(size_t value)
{
    return value > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(value);
}

static bool rangeFits(size_t total, size_t offset, size_t length)
{
    return offset <= total && length <= total - offset;
}

static uint16_t readLe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

static uint32_t readLe32(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24);
}

static uint64_t readLe64(const uint8_t *bytes)
{
    return static_cast<uint64_t>(readLe32(bytes)) |
        (static_cast<uint64_t>(readLe32(bytes + 4)) << 32);
}

static Inspection inspect(const uint8_t *descriptor, size_t actualPayloadLength,
                         size_t dmaCapacity, const Layout &layout)
{
    Inspection result{};
    result.payloadLength = boundedSize(actualPayloadLength);
    result.dmaCapacity = boundedSize(dmaCapacity);
    result.descriptorSize = boundedSize(layout.descriptorSize);
    result.descriptorVersion = layout.descriptorVersion;
    result.minimumMpduLength = layout.minimumMpduLength;
    result.rpaEnabled = layout.rpaEnabled ? 1u : 0u;
    if (!descriptor)
        return result;
    const size_t readableLength = actualPayloadLength < dmaCapacity ?
        actualPayloadLength : dmaCapacity;

    if (rangeFits(readableLength, layout.statusOffset, sizeof(uint32_t)) &&
        rangeFits(layout.descriptorSize, layout.statusOffset, sizeof(uint32_t))) {
        result.statusPresent = 1;
        result.status = readLe32(descriptor + layout.statusOffset);
        result.crcOk = (result.status & layout.crcOkMask) != 0;
        result.overrunOk = (result.status & layout.overrunOkMask) != 0;
    }

    if (rangeFits(readableLength, layout.mpduLengthOffset,
                  sizeof(uint16_t)) &&
        rangeFits(layout.descriptorSize, layout.mpduLengthOffset,
                  sizeof(uint16_t))) {
        result.mpduLengthPresent = 1;
        result.mpduLength = readLe16(descriptor + layout.mpduLengthOffset);
    }

    result.descriptorPresent = readableLength >= layout.descriptorSize;
    if (result.descriptorPresent) {
        if (rangeFits(layout.descriptorSize, layout.macPhyIndexOffset, 1) &&
            rangeFits(readableLength, layout.macPhyIndexOffset, 1)) {
            result.macPhyIndexPresent = 1;
            result.macPhyIndex = descriptor[layout.macPhyIndexOffset];
        }
        if (rangeFits(layout.descriptorSize, layout.channelOffset, 1) &&
            rangeFits(readableLength, layout.channelOffset, 1)) {
            result.channelPresent = 1;
            result.channel = descriptor[layout.channelOffset];
        }
        if (layout.macContextOffset != 0 &&
            rangeFits(layout.descriptorSize, layout.macContextOffset, 1) &&
            rangeFits(readableLength, layout.macContextOffset, 1)) {
            result.macContextPresent = 1;
            result.macContext = descriptor[layout.macContextOffset];
        }
        if (result.macPhyIndexPresent) {
            // Do not decode an unknown mode. In API59 band-in-RX mode the
            // MAC nibble remains known, while PHY decoding is withheld until
            // the band/PHY layout is backed by a verified enum.
            if (layout.macPhyIndexDecodeMode == MacPhyDecodeLegacy) {
                result.macPhyIndexDecodeModePresent = 1;
                result.macIndexPresent = 1;
                result.macIndex = result.macPhyIndex & 0x0fu;
                result.phyIndexPresent = 1;
                result.phyIndex = (result.macPhyIndex & 0xf0u) >> 4;
                result.macPhyIndexDecodeMode = MacPhyDecodeLegacy;
            } else if (layout.macPhyIndexDecodeMode == MacPhyDecodeBandInRx) {
                result.macPhyIndexDecodeModePresent = 1;
                result.macIndexPresent = 1;
                result.macIndex = result.macPhyIndex & 0x0fu;
                result.macPhyIndexDecodeMode = MacPhyDecodeBandInRx;
            }
        }
        if (layout.gp2OnAirRiseOffset != 0 &&
            rangeFits(layout.descriptorSize, layout.gp2OnAirRiseOffset,
                      sizeof(uint32_t)) &&
            rangeFits(readableLength, layout.gp2OnAirRiseOffset,
                      sizeof(uint32_t))) {
            result.gp2OnAirRisePresent = 1;
            result.gp2OnAirRiseRaw = readLe32(
                descriptor + layout.gp2OnAirRiseOffset);
        }
        if (layout.tsfOnAirRiseOffset != 0 &&
            rangeFits(layout.descriptorSize, layout.tsfOnAirRiseOffset,
                      sizeof(uint64_t)) &&
            rangeFits(readableLength, layout.tsfOnAirRiseOffset,
                      sizeof(uint64_t))) {
            result.tsfOnAirRisePresent = 1;
            result.tsfOnAirRiseRaw = readLe64(
                descriptor + layout.tsfOnAirRiseOffset);
        }
        if (layout.phyInfoOffset != 0 &&
            rangeFits(layout.descriptorSize, layout.phyInfoOffset,
                      sizeof(uint16_t)) &&
            rangeFits(readableLength, layout.phyInfoOffset,
                      sizeof(uint16_t))) {
            result.tsfValidPresent = 1;
            const uint16_t phyInfo = readLe16(
                descriptor + layout.phyInfoOffset);
            result.tsfValid = (phyInfo & layout.tsfOverloadMask) == 0;
        }
        if (layout.rpaEnabled &&
            rangeFits(layout.descriptorSize, layout.filterMatchOffset,
                      sizeof(uint32_t)) &&
            rangeFits(readableLength, layout.filterMatchOffset,
                      sizeof(uint32_t))) {
            result.filterMatchPresent = 1;
            result.filterMatch = readLe32(descriptor + layout.filterMatchOffset);
        }
    }

    if (result.mpduLengthPresent) {
        result.capacityFits = dmaCapacity >= layout.descriptorSize &&
            result.mpduLength <= dmaCapacity - layout.descriptorSize;
        result.payloadFits = actualPayloadLength >= layout.descriptorSize &&
            result.mpduLength <= actualPayloadLength - layout.descriptorSize;
        result.frameRangeValid = result.descriptorPresent &&
            result.capacityFits && result.payloadFits &&
            result.mpduLength >= layout.minimumMpduLength;
    }

    if (result.statusPresent && result.crcOk && result.overrunOk &&
        result.frameRangeValid &&
        rangeFits(readableLength, layout.descriptorSize,
                  sizeof(uint16_t))) {
        result.frameControlPresent = 1;
        result.frameControl = readLe16(descriptor + layout.descriptorSize);
        result.frameType = (result.frameControl >> 2) & 0x3u;
        result.frameSubtype = (result.frameControl >> 4) & 0xfu;
        result.toDs = (result.frameControl & 0x0100u) != 0;
        result.fromDs = (result.frameControl & 0x0200u) != 0;
    }
    return result;
}

static bool sameEpochs(const Epochs &a, const Epochs &b)
{
    return a.contextGeneration == b.contextGeneration &&
        a.powerGeneration == b.powerGeneration &&
        a.stationGeneration == b.stationGeneration &&
        a.rocGeneration == b.rocGeneration;
}

class Telemetry {
public:
    // All state methods, including snapshot(), are main-workloop-gate only.
    // This keeps fixed numeric witnesses single-writer and allocation-free.
    Telemetry() { snapshot_.schema = kSchema; }

    bool beginOwner(const Epochs &epochs)
    {
        if (!epochs.contextGeneration || !epochs.powerGeneration ||
            !epochs.stationGeneration || !epochs.rocGeneration)
            return false;
        if (sameEpochs(snapshot_.epochs, epochs))
            return snapshot_.active != 0;
        snapshot_ = {};
        snapshot_.schema = kSchema;
        snapshot_.epochs = epochs;
        snapshot_.active = 1;
        return true;
    }

    void endOwner(const Epochs &epochs)
    {
        if (snapshot_.active && sameEpochs(snapshot_.epochs, epochs))
            snapshot_.active = 0;
    }

    // Shared production lifecycle predicate used by Probe hooks and host
    // tests. The caller must build `current` only after validating current
    // lease/ROC/context/power/station identity. A close-only call can never
    // begin or reopen an owner.
    bool syncOwner(bool closeOnly, const Epochs &current,
                   bool currentEpochsPresent)
    {
        if (!currentEpochsPresent)
            return false;
        if (closeOnly) {
            if (!snapshot_.active || !sameEpochs(snapshot_.epochs, current))
                return false;
            endOwner(current);
            return true;
        }
        return beginOwner(current);
    }

    bool record(const Epochs &epochs, const Inspection &observation,
                bool awdlBssidCandidate)
    {
        const Dispatch dispatch{};
        return record(epochs, observation, awdlBssidCandidate, dispatch);
    }

    bool record(const Epochs &epochs, const Inspection &observation,
                bool awdlBssidCandidate, const Dispatch &dispatch)
    {
        if (!snapshot_.active || !sameEpochs(snapshot_.epochs, epochs))
            return false;
        increment(OwnerGateEntries);
        if (!observation.statusPresent)
            increment(StatusTruncated);
        else {
            if (!observation.crcOk)
                increment(CrcRejected);
            if (!observation.overrunOk)
                increment(OverrunRejected);
        }
        if (observation.mpduLengthPresent &&
            observation.mpduLength < observation.minimumMpduLength)
            increment(MpduLengthShort);
        if (!observation.descriptorPresent)
            increment(DescriptorTruncated);
        else {
            increment(FullDescriptor);
            if (observation.filterMatchPresent)
                increment(FilterMatchAvailable);
            else
                increment(FilterMatchUnavailable);
            if (observation.channelPresent && observation.channel == 149)
                increment(Channel149);
            else if (observation.channelPresent && observation.channel == 36)
                increment(Channel36);
            const bool strictDescriptor = observation.statusPresent &&
                observation.crcOk && observation.overrunOk &&
                observation.frameRangeValid &&
                observation.frameControlPresent;
            const bool macIndexTarget149 = observation.channelPresent &&
                observation.channel == 149 && observation.macIndexPresent &&
                observation.macIndex == 1 &&
                observation.macPhyIndexDecodeModePresent &&
                observation.macPhyIndexDecodeMode != MacPhyDecodeUnknown &&
                strictDescriptor;
            updateWitness(snapshot_.lastDescriptor, epochs, observation,
                          false, dispatch);
            if (macIndexTarget149) {
                increment(MacIndex1Channel149);
                updateWitness(snapshot_.lastMacIndexTarget, epochs,
                              observation, false, dispatch);
            }
            const bool expectedMacPhy149 = macIndexTarget149 &&
                observation.phyIndexPresent && observation.phyIndex == 1;
            if (expectedMacPhy149) {
                increment(ExpectedMacPhy149);
                updateWitness(snapshot_.lastTarget, epochs, observation,
                              false, dispatch);
            }
        }
        if (observation.mpduLengthPresent && !observation.capacityFits)
            increment(CapacityOverflow);
        if (observation.mpduLengthPresent && !observation.payloadFits)
            increment(PayloadTruncated);

        if (!observation.frameControlPresent)
            return true;
        increment(FrameControlValid);
        switch (observation.frameType) {
            case 0: increment(ManagementFrame); break;
            case 1: increment(ControlFrame); break;
            case 2:
                increment(DataFrame);
                if (observation.frameSubtype == 8)
                    increment(QosDataFrame);
                break;
            default: increment(ReservedFrame); break;
        }
        if (awdlBssidCandidate && observation.frameType == 2 &&
            (observation.frameSubtype == 0 || observation.frameSubtype == 8) &&
            !observation.toDs && !observation.fromDs) {
            increment(AwdlBssidCandidate);
            updateWitness(snapshot_.lastDescriptor, epochs, observation, true,
                          dispatch);
            updateWitness(snapshot_.lastAwdlDataCandidate, epochs,
                          observation, true, dispatch);
        }
        return true;
    }

    Snapshot snapshot() const { return snapshot_; }
    bool active() const { return snapshot_.active != 0; }

private:
    void increment(Counter counter)
    {
        snapshot_.counts[counter] = saturatedIncrement(snapshot_.counts[counter]);
    }

    static void updateWitness(Witness &witness, const Epochs &epochs,
                              const Inspection &observation,
                              bool awdlBssidCandidate,
                              const Dispatch &dispatch)
    {
        witness = {};
        witness.present = 1;
        witness.contextGeneration = epochs.contextGeneration;
        witness.powerGeneration = epochs.powerGeneration;
        witness.stationGeneration = epochs.stationGeneration;
        witness.rocGeneration = epochs.rocGeneration;
        witness.payloadLength = observation.payloadLength;
        witness.dmaCapacity = observation.dmaCapacity;
        witness.descriptorSize = observation.descriptorSize;
        witness.descriptorVersion = observation.descriptorVersion;
        witness.mpduLength = observation.mpduLength;
        witness.statusPresent = observation.statusPresent;
        witness.status = observation.status;
        witness.macPhyIndexPresent = observation.macPhyIndexPresent;
        witness.macPhyIndex = observation.macPhyIndex;
        witness.filterMatchPresent = observation.filterMatchPresent;
        witness.filterMatch = observation.filterMatch;
        witness.rpaEnabled = observation.rpaEnabled;
        witness.channelPresent = observation.channelPresent;
        witness.channel = observation.channel;
        witness.macContextPresent = observation.macContextPresent;
        witness.macContext = observation.macContext;
        witness.macIndexPresent = observation.macIndexPresent;
        witness.macIndex = observation.macIndex;
        witness.phyIndexPresent = observation.phyIndexPresent;
        witness.phyIndex = observation.phyIndex;
        witness.macPhyIndexDecodeModePresent =
            observation.macPhyIndexDecodeModePresent;
        witness.macPhyIndexDecodeMode = observation.macPhyIndexDecodeMode;
        witness.hostRxMonotonicUsPresent = dispatch.hostRxMonotonicUsPresent;
        witness.hostRxMonotonicUs = dispatch.hostRxMonotonicUs;
        witness.gp2OnAirRisePresent = observation.gp2OnAirRisePresent;
        witness.gp2OnAirRiseRaw = observation.gp2OnAirRiseRaw;
        witness.tsfOnAirRisePresent = observation.tsfOnAirRisePresent;
        witness.tsfOnAirRiseRaw = observation.tsfOnAirRiseRaw;
        witness.tsfValidPresent = observation.tsfValidPresent;
        witness.tsfValid = observation.tsfValid;
        witness.rxRingPresent = dispatch.rxRingPresent;
        witness.rxRing = dispatch.rxRing;
        witness.rxRingSlotPresent = dispatch.rxRingSlotPresent;
        witness.rxRingSlot = dispatch.rxRingSlot;
        witness.transportNotificationQidPresent =
            dispatch.transportNotificationQidPresent;
        witness.transportNotificationQid = dispatch.transportNotificationQid;
        witness.transportNotificationIndexPresent =
            dispatch.transportNotificationIndexPresent;
        witness.transportNotificationIndex =
            dispatch.transportNotificationIndex;
        witness.frameControlPresent = observation.frameControlPresent;
        witness.frameControl = observation.frameControl;
        witness.frameType = observation.frameType;
        witness.frameSubtype = observation.frameSubtype;
        witness.toDs = observation.toDs;
        witness.fromDs = observation.fromDs;
        witness.awdlBssidCandidate = awdlBssidCandidate ? 1u : 0u;
    }

    Snapshot snapshot_{};
};

} // namespace NativeAwdlRxEntry

#endif
