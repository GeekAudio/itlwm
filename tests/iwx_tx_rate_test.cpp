#include "../itlwm/hal_iwx/IwxTxRate.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>

using namespace IwxTxRate;

static uint32_t flags(Format format, uint8_t mcs, uint8_t nss,
                      uint8_t bandwidthCode, uint32_t extra = 0)
{
    return (static_cast<uint32_t>(format) << 8) | mcs |
        (static_cast<uint32_t>(nss - 1) << 4) |
        (static_cast<uint32_t>(bandwidthCode) << 11) | extra;
}

static void expectRate(uint32_t rateFlags, uint32_t expectedMbps,
                       uint32_t expectedMcs, uint8_t expectedNss,
                       uint16_t expectedBw, uint16_t expectedGi)
{
    Decoded decoded{};
    assert(decode(rateFlags, &decoded));
    assert(decoded.valid);
    assert(decoded.mcs == expectedMcs);
    assert(decoded.nss == expectedNss);
    assert(decoded.bandwidthMHz == expectedBw);
    assert(decoded.guardIntervalNs == expectedGi);
    uint32_t mcsIndex = UINT32_MAX;
    assert(currentMcsIndex(decoded, &mcsIndex));
    assert(mcsIndex == (decoded.format == Ht
        ? expectedMcs + 8u * (expectedNss - 1u) : expectedMcs));
    uint32_t mbps = 0;
    assert(rateMbps(decoded, &mbps));
    assert(mbps == expectedMbps);
}

static void putLittleEndianU32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
    bytes[2] = static_cast<uint8_t>(value >> 16);
    bytes[3] = static_cast<uint8_t>(value >> 24);
}

int main()
{
    // Intel's V2 NSS marker is bit 4; V3 moved the marker to bit 5.
    assert(firmwareRateVersion(9, 3, 4, 7, 0) == FirmwareRateV2);
    assert(firmwareRateVersion(11, 4, 6, 9, 4) == FirmwareRateV3);
    assert(firmwareRateVersion(7, 2, 3, 5, 0) == FirmwareRateV1);
    assert(firmwareRateVersion(9, 2, 4, 7, 0) == FirmwareRateUnknown);
    assert(firmwareRateVersion(0xff, 3, 4, 7, 0) == FirmwareRateUnknown);

    // V2 response sample: VHT MCS9, 2SS, 160MHz, short GI = 1733 Mbps.
    const uint32_t v2Raw = flags(Vht, 9, 2, 3, kSgiMask);
    uint32_t normalized = 0;
    assert(normalizeFirmwareRate(v2Raw, FirmwareRateV2, &normalized));
    assert(normalized == v2Raw);
    expectRate(normalized, 1733, 9, 2, 160, 400);

    // Real notification byte vectors: TX response initial_rate is at byte 4;
    // compressed BA tx_rate follows its 24-byte fixed header. These fixtures
    // exercise the same bounds-checked little-endian reader used by the driver.
    uint8_t txResponse[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    putLittleEndianU32(txResponse + 4, v2Raw);
    uint32_t notificationRate = 0;
    assert(readLittleEndianU32(txResponse, sizeof(txResponse), 4,
                               &notificationRate));
    assert(notificationRate == v2Raw);
    const uint32_t singleRate = notificationRate;
    notificationRate = 0xdeadbeef;
    assert(!readLittleEndianU32(txResponse, 7, 4, &notificationRate));
    assert(notificationRate == 0xdeadbeef);
    assert(normalizeFirmwareRate(singleRate, FirmwareRateV2,
                                 &normalized));
    uint64_t completion = makeCurrentSample(true, normalized,
        SourceTxSingle, FirmwareRateV2);
    Decoded current{};
    assert(decodeCurrentSample(true, true, completion, 7, 7, &current) ==
           CurrentReady);
    uint32_t currentMbps = 0;
    assert(rateMbps(current, &currentMbps) && currentMbps == 1733);

    uint8_t compressedBa[28] = {};
    putLittleEndianU32(compressedBa + 24, v2Raw);
    assert(readLittleEndianU32(compressedBa, sizeof(compressedBa), 24,
                               &notificationRate));
    assert(notificationRate == v2Raw);
    const uint32_t aggregateRate = notificationRate;
    notificationRate = 0xdeadbeef;
    assert(!readLittleEndianU32(compressedBa, 27, 24, &notificationRate));
    assert(notificationRate == 0xdeadbeef);
    assert(normalizeFirmwareRate(aggregateRate, FirmwareRateV2,
                                 &normalized));
    completion = makeCurrentSample(true, normalized, SourceTxAggregate,
                                   FirmwareRateV2);
    assert(decodeCurrentSample(true, true, completion, 7, 7, &current) ==
           CurrentReady);
    assert(rateMbps(current, &currentMbps) && currentMbps == 1733);

    // V3 encodes two spatial streams in bit 5; normalize to the shared V2
    // representation before any rate/MCS/NSS API reads it.
    const uint32_t v3Raw = (static_cast<uint32_t>(Vht) << 8) | 9u |
        kV3NssMask | (3u << 11) | kSgiMask;
    assert(normalizeFirmwareRate(v3Raw, FirmwareRateV3, &normalized));
    assert((normalized & kV3NssMask) == 0);
    assert((normalized & (1u << 4)) != 0);
    expectRate(normalized, 1733, 9, 2, 160, 400);

    const uint32_t v3Single = (static_cast<uint32_t>(Vht) << 8) | 9u |
        (3u << 11) | kSgiMask;
    assert(normalizeFirmwareRate(v3Single, FirmwareRateV3, &normalized));
    expectRate(normalized, 866, 9, 1, 160, 400);
    assert(!normalizeFirmwareRate(v3Raw | kV3McsHighBit,
                                  FirmwareRateV3, &normalized));
    assert(!normalizeFirmwareRate(v2Raw | kV3NssMask,
                                  FirmwareRateV2, &normalized));
    assert(!normalizeFirmwareRate(v2Raw, FirmwareRateUnknown, &normalized));

    // Existing parser coverage: legacy, HT, VHT and supported HE SU rates.
    Decoded legacy{};
    uint32_t mbps = 0;
    assert(decode(static_cast<uint32_t>(LegacyCck) << 8, &legacy));
    assert(rateMbps(legacy, &mbps) && mbps == 1);
    assert(decode((static_cast<uint32_t>(LegacyOfdm) << 8) | 1, &legacy));
    assert(rateMbps(legacy, &mbps) && mbps == 9);
    assert(!currentMcsIndex(legacy, &mbps));

    expectRate(flags(Ht, 0, 1, 0), 6, 0, 1, 20, 800);
    expectRate(flags(Ht, 7, 2, 1, kSgiMask), 300, 7, 2, 40, 400);
    expectRate(flags(Vht, 7, 2, 2), 585, 7, 2, 80, 800);
    expectRate(flags(Vht, 7, 2, 2, kSgiMask), 650, 7, 2, 80, 400);
    expectRate(flags(Vht, 9, 1, 2), 390, 9, 1, 80, 800);
    expectRate(flags(Vht, 9, 2, 2), 780, 9, 2, 80, 800);

    const uint32_t heBase = flags(He, 11, 2, 2);
    expectRate(heBase, 1200, 11, 2, 80, 800);
    expectRate(heBase | (2u << 20), 1134, 11, 2, 80, 1600);
    expectRate(heBase | (3u << 20), 1020, 11, 2, 80, 3200);

    Decoded unsupported{};
    assert(decode(heBase | (2u << 23), &unsupported));
    assert(unsupported.mcs == 11 && unsupported.nss == 2);
    assert(!rateMbps(unsupported, &mbps));
    assert(!decode(flags(Eht, 3, 1, 2), &unsupported));
    assert(!decode(flags(Vht, 10, 1, 2), &unsupported));
    assert(!decode(flags(Ht, 0, 1, 2), &unsupported));
    assert(!decode(flags(Vht, 7, 1, 4), &unsupported));

    // A TLC baseline is not a current TX result. Only a completion-source
    // sample may feed getRATE/getMCS/getNSS.
    const uint64_t tlc = makeTlcBaselineSample(true, v2Raw, FirmwareRateV2);
    assert(unpackCurrentSample(tlc).source == SourceTlcInitial);
    assert(decodeCurrentSample(true, true, tlc, 7, 7, &unsupported) ==
           CurrentNotReady);
    const uint64_t single = makeCurrentSample(true, v2Raw, SourceTxSingle,
                                               FirmwareRateV2);
    const DecodedSample metadata = unpackCurrentSample(single);
    assert(metadata.valid && metadata.source == SourceTxSingle);
    assert(metadata.firmwareVersion == FirmwareRateV2);
    assert(metadata.normalizedFlags == v2Raw);
    assert(decodeCurrentSample(true, true, single, 7, 7, &unsupported) ==
           CurrentReady);
    assert(unsupported.nss == 2 && unsupported.mcs == 9);
    assert(decodeCurrentSample(false, true, single, 7, 7, &unsupported) ==
           CurrentNotReady);
    assert(decodeCurrentSample(true, false, single, 7, 7, &unsupported) ==
           CurrentNotReady);
    assert(decodeCurrentSample(true, true, single, 7, 8, &unsupported) ==
           CurrentNotReady);
    assert(decodeCurrentSample(true, true,
        makeCurrentSample(false, 0, SourceTxSingle, FirmwareRateUnknown),
        7, 7, &unsupported) == CurrentNotReady);

    // Completion-source gates require current STA/BSS/generation and actual
    // transmitted frame evidence; stale or unrelated notifications are ignored.
    assert(acceptsSingleTxCompletion(true, true, true, true, true, true));
    assert(!acceptsSingleTxCompletion(false, true, true, true, true, true));
    assert(!acceptsSingleTxCompletion(true, false, true, true, true, true));
    assert(!acceptsSingleTxCompletion(true, true, true, true, true, false));
    assert(acceptsAggregateTxCompletion(true, true, true, true, true,
                                        true, true, true));
    assert(!acceptsAggregateTxCompletion(false, true, true, true, true,
                                         true, true, true));
    assert(!acceptsAggregateTxCompletion(true, false, true, true, true,
                                         true, true, true));
    assert(!acceptsAggregateTxCompletion(true, true, true, true, true,
                                         true, false, true));

    // Snapshot tests exercise the same serialized store/read path used by the
    // driver, including source, raw and normalized values and reset semantics.
    uint32_t sequence = 0;
    uint64_t packed = 0;
    uint32_t raw = 0, sampleGeneration = 0, updates = 0, singles = 0,
        aggregates = 0;
    uint32_t activeGeneration = 41;
    assert(storeSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                         &updates, &singles, &aggregates,
                         single, v2Raw, SourceTxSingle, activeGeneration));
    Snapshot snapshot{};
    assert(readSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                        &updates, &singles, &aggregates, &snapshot));
    assert(snapshot.sample == single && snapshot.rawFlags == v2Raw &&
           snapshot.generation == activeGeneration);
    assert(snapshot.updateCount == 1 && snapshot.singleCount == 1);
    const uint64_t aggregate = makeCurrentSample(true, normalized,
                                                  SourceTxAggregate,
                                                  FirmwareRateV3);
    assert(storeSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                         &updates, &singles, &aggregates,
                         aggregate, v3Raw, SourceTxAggregate, activeGeneration));
    assert(readSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                        &updates, &singles, &aggregates, &snapshot));
    assert(snapshot.sample == aggregate && snapshot.rawFlags == v3Raw &&
           snapshot.generation == activeGeneration);
    assert(snapshot.updateCount == 2 && snapshot.singleCount == 1 &&
           snapshot.aggregateCount == 1);
    assert(clearSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                         &updates, &singles, &aggregates));
    assert(readSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                        &updates, &singles, &aggregates, &snapshot));
    assert(snapshot.sample == 0 && snapshot.rawFlags == 0 &&
           snapshot.generation == 0 &&
           snapshot.updateCount == 0 && snapshot.singleCount == 0 &&
           snapshot.aggregateCount == 0);

    // Controlled race: an old completion passes its initial epoch check,
    // newstate publishes the new epoch and clears, then the old completion
    // commits. The coherent snapshot retains the old epoch and read-side
    // comparison must reject the resurrected sample.
    const uint32_t oldGeneration = activeGeneration;
    assert(oldGeneration == activeGeneration &&
           acceptsSingleTxCompletion(true, true, true, true, true, true));
    activeGeneration = oldGeneration + 1;
    assert(clearSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                         &updates, &singles, &aggregates));
    assert(storeSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                         &updates, &singles, &aggregates,
                         single, v2Raw, SourceTxSingle, oldGeneration));
    assert(readSnapshot(&sequence, &packed, &raw, &sampleGeneration,
                        &updates, &singles, &aggregates, &snapshot));
    assert(snapshot.sample == single && snapshot.generation == oldGeneration);
    assert(decodeCurrentSample(true, true, snapshot.sample,
                               snapshot.generation, activeGeneration,
                               &unsupported) == CurrentNotReady);

    // Writer/clear lock attempts are bounded and drop diagnostics if a writer
    // owns the snapshot instead of spinning indefinitely in interrupt context.
    uint32_t busySequence = 1;
    uint64_t busySample = single;
    uint32_t busyRaw = v2Raw, busyGeneration = oldGeneration;
    uint32_t busyUpdates = 1, busySingles = 1, busyAggregates = 0;
    assert(!tryLockSnapshot(&busySequence, 8));
    assert(!clearSnapshot(&busySequence, &busySample, &busyRaw,
                          &busyGeneration, &busyUpdates, &busySingles,
                          &busyAggregates));
    assert(!storeSnapshot(&busySequence, &busySample, &busyRaw,
                          &busyGeneration, &busyUpdates, &busySingles,
                          &busyAggregates, aggregate, v3Raw,
                          SourceTxAggregate, activeGeneration));
    assert(busySample == single && busyRaw == v2Raw &&
           busyGeneration == oldGeneration && busyUpdates == 1);

    // BA/reclaim range is [tail, tfd_index), including ring wrap, and cannot
    // claim slots beyond queued descriptors.
    CompletedDescriptorRange range{};
    assert(completedDescriptorRange(8, 6, 4, 1, &range));
    assert(range.first == 6 && range.count == 3);
    assert(completedRangeContains(range, 8, 6));
    assert(completedRangeContains(range, 8, 7));
    assert(completedRangeContains(range, 8, 0));
    assert(!completedRangeContains(range, 8, 1));
    assert(!completedDescriptorRange(8, 6, 2, 3, &range));
    assert(!completedDescriptorRange(8, 6, 9, 1, &range));
    assert(!completedDescriptorRange(0, 0, 0, 0, &range));

    std::cout << "TX rate and completion vectors passed\n";
    return 0;
}
