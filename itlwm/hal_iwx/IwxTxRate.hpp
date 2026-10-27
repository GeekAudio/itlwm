#pragma once

#include <stddef.h>
#include <stdint.h>

namespace IwxTxRate {

enum Format : uint8_t {
    LegacyCck = 0,
    LegacyOfdm = 1,
    Ht = 2,
    Vht = 3,
    He = 4,
    Eht = 5,
    Unknown = 0xff,
};

struct Decoded {
    uint32_t flags;
    Format format;
    uint8_t mcs;
    uint8_t nss;
    uint8_t bandwidthCode;
    uint16_t bandwidthMHz;
    uint8_t heType;
    uint8_t heGiLtf;
    uint16_t guardIntervalNs;
    bool valid;
    bool rateSupported;
};

enum CurrentStatus : uint8_t {
    CurrentReady,
    CurrentNotReady,
    CurrentUnsupported,
    CurrentBadArgument,
};

enum FirmwareRateVersion : uint8_t {
    FirmwareRateUnknown = 0,
    FirmwareRateV1 = 1,
    FirmwareRateV2 = 2,
    FirmwareRateV3 = 3,
};

enum Source : uint8_t {
    SourceNone = 0,
    SourceTlcInitial = 1,
    SourceTxSingle = 2,
    SourceTxAggregate = 3,
};

constexpr uint64_t kCurrentValidBit = uint64_t{1} << 32;
constexpr uint64_t kCurrentSourceShift = 33;
constexpr uint64_t kCurrentSourceMask = uint64_t{3} << kCurrentSourceShift;
constexpr uint64_t kCurrentVersionShift = 35;
constexpr uint64_t kCurrentVersionMask = uint64_t{7} << kCurrentVersionShift;
constexpr uint32_t kV1McsMask = 0x0fu;
constexpr uint32_t kV1HtMask = 1u << 8;
constexpr uint32_t kV1CckMask = 1u << 9;
constexpr uint32_t kV1HeMask = 1u << 10;
constexpr uint32_t kV1VhtMask = 1u << 26;
constexpr uint32_t kV1HtNssMask = 0x3u << 3;
constexpr uint32_t kV3NssMask = 1u << 5;
constexpr uint32_t kV3McsHighBit = 1u << 4;

constexpr uint32_t kFormatMask = 0x7u << 8;
constexpr uint32_t kMcsMask = 0xfu;
constexpr uint32_t kNssMask = 0x3u << 4;
constexpr uint32_t kWidthMask = 0x7u << 11;
constexpr uint32_t kSgiMask = 1u << 20;
constexpr uint32_t kHeGiLtfMask = 0x7u << 20;
constexpr uint32_t kHeTypeMask = 0x3u << 23;
constexpr uint32_t kDuplicateMask = 1u << 25;
constexpr uint32_t kHeDcmMask = 1u << 18;
constexpr uint32_t kHe106ToneMask = 1u << 26;
constexpr uint32_t kStbcMask = 1u << 17;

inline bool readLittleEndianU32(const uint8_t *bytes, size_t length,
                                size_t offset, uint32_t *value)
{
    if (bytes == nullptr || value == nullptr || offset > length ||
        length - offset < sizeof(uint32_t))
        return false;
    *value = static_cast<uint32_t>(bytes[offset]) |
        (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
        (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
        (static_cast<uint32_t>(bytes[offset + 3]) << 24);
    return true;
}

struct Snapshot {
    uint64_t sample;
    uint32_t rawFlags;
    uint32_t generation;
    uint32_t updateCount;
    uint32_t singleCount;
    uint32_t aggregateCount;
};

struct CompletedDescriptorRange {
    uint32_t first;
    uint32_t count;
};

inline bool completedDescriptorRange(uint32_t ringCount, uint32_t tail,
                                     uint32_t queued, uint32_t end,
                                     CompletedDescriptorRange *range)
{
    if (range == nullptr || ringCount == 0 || tail >= ringCount ||
        end >= ringCount || queued > ringCount)
        return false;
    const uint32_t count = end >= tail ? end - tail :
        ringCount - tail + end;
    if (count > queued)
        return false;
    range->first = tail;
    range->count = count;
    return true;
}

inline bool completedRangeContains(const CompletedDescriptorRange &range,
                                   uint32_t ringCount, uint32_t index)
{
    if (ringCount == 0 || range.first >= ringCount || index >= ringCount ||
        range.count > ringCount)
        return false;
    for (uint32_t offset = 0; offset < range.count; ++offset) {
        if ((range.first + offset) % ringCount == index)
            return true;
    }
    return false;
}

struct DecodedSample {
    uint32_t normalizedFlags;
    Source source;
    FirmwareRateVersion firmwareVersion;
    bool valid;
};

inline uint8_t firmwareRateVersion(uint8_t txCommandVersion,
                                   uint8_t tlcNotificationVersion,
                                   uint8_t rxMpduNotificationVersion,
                                   uint8_t txNotificationVersion,
                                   uint8_t rxNoDataNotificationVersion)
{
    constexpr uint8_t unknown = 0xff;
    if (txCommandVersion == unknown || tlcNotificationVersion == unknown ||
        rxMpduNotificationVersion == unknown || txNotificationVersion == unknown ||
        rxNoDataNotificationVersion == unknown)
        return FirmwareRateUnknown;

    const bool v3[5] = {
        txCommandVersion >= 11,
        tlcNotificationVersion >= 4,
        rxMpduNotificationVersion >= 6,
        rxNoDataNotificationVersion >= 4,
        txNotificationVersion >= 9,
    };
    uint8_t v3Features = 0;
    for (bool feature : v3)
        v3Features += feature ? 1 : 0;
    if (v3Features == 5)
        return FirmwareRateV3;
    if (v3Features != 0)
        return FirmwareRateUnknown;

    const bool v2[4] = {
        txCommandVersion >= 8,
        tlcNotificationVersion >= 3,
        rxMpduNotificationVersion >= 4,
        txNotificationVersion >= 6,
    };
    uint8_t v2Features = 0;
    for (bool feature : v2)
        v2Features += feature ? 1 : 0;
    if (v2Features == 4)
        return FirmwareRateV2;
    if (v2Features == 0)
        return FirmwareRateV1;
    return FirmwareRateUnknown;
}

inline bool normalizeFirmwareRate(uint32_t rawFlags,
                                  FirmwareRateVersion version,
                                  uint32_t *normalizedFlags)
{
    if (normalizedFlags == nullptr)
        return false;
    if (version == FirmwareRateV1)
        return false; // V1 needs the PLCP-to-legacy index table in the driver.
    if (version == FirmwareRateV2) {
        if ((rawFlags & (7u << 5)) != 0) // reserved in V2
            return false;
        *normalizedFlags = rawFlags;
        return true;
    }
    if (version != FirmwareRateV3)
        return false;

    const Format format = static_cast<Format>((rawFlags & kFormatMask) >> 8);
    if (format == Ht || format == Vht || format == He) {
        // The native decoder supports at most MCS 15 and uses V2's bit-4
        // NSS marker. For HT/VHT/HE rates, a set V3 MCS bit 4 is outside that
        // supported range and must not be reinterpreted as NSS.
        if ((rawFlags & kV3McsHighBit) != 0)
            return false;
        *normalizedFlags = (rawFlags & ~kV3NssMask) |
            ((rawFlags & kV3NssMask) ? kNssMask & (1u << 4) : 0);
        return true;
    }

    if (format == LegacyCck || format == LegacyOfdm) {
        if ((rawFlags & (7u << 5)) != 0)
            return false;
        *normalizedFlags = rawFlags;
        return true;
    }
    // Keep unknown modulation encodings available to diagnostics, but do not
    // claim they can be decoded as a supported current rate.
    *normalizedFlags = rawFlags;
    return true;
}

inline bool acceptsSingleTxCompletion(bool successful, bool dataFrame,
                                      bool stationMode, bool running,
                                      bool currentBss, bool currentGeneration)
{
    return successful && dataFrame && stationMode && running && currentBss &&
        currentGeneration;
}

inline bool acceptsAggregateTxCompletion(bool aggregateEvent,
                                         bool transmittedFrames,
                                         bool wirelessTime,
                                         bool stationMode, bool running,
                                         bool currentBss, bool currentQueue,
                                         bool currentGeneration)
{
    return aggregateEvent && transmittedFrames && wirelessTime &&
        stationMode && running && currentBss && currentQueue &&
        currentGeneration;
}

inline bool decode(uint32_t flags, Decoded *out)
{
    if (out == nullptr)
        return false;

    *out = Decoded{};
    out->flags = flags;
    out->format = static_cast<Format>((flags & kFormatMask) >> 8);

    switch (out->format) {
        case LegacyCck:
        case LegacyOfdm:
            out->nss = 1;
            out->valid = true;
            out->rateSupported = true;
            return true;

        case Ht:
        case Vht:
        case He:
            break;

        default:
            out->format = Unknown;
            return false;
    }

    out->mcs = static_cast<uint8_t>(flags & kMcsMask);
    out->nss = static_cast<uint8_t>(((flags & kNssMask) >> 4) + 1);
    out->bandwidthCode = static_cast<uint8_t>((flags & kWidthMask) >> 11);

    switch (out->bandwidthCode) {
        case 0: out->bandwidthMHz = 20; break;
        case 1: out->bandwidthMHz = 40; break;
        case 2: out->bandwidthMHz = 80; break;
        case 3: out->bandwidthMHz = 160; break;
        default: return false;
    }

    if (out->nss == 0 || out->nss > 4)
        return false;

    if (out->format == Ht) {
        if (out->mcs > 7 || out->bandwidthCode > 1)
            return false;
        out->guardIntervalNs = (flags & kSgiMask) ? 400 : 800;
    } else if (out->format == Vht) {
        if (out->mcs > 9)
            return false;
        out->guardIntervalNs = (flags & kSgiMask) ? 400 : 800;
    } else {
        out->heType = static_cast<uint8_t>((flags & kHeTypeMask) >> 23);
        out->heGiLtf = static_cast<uint8_t>((flags & kHeGiLtfMask) >> 20);
        switch (out->heType) {
            case 0: // SU
            case 1: // extended SU
                if (out->heGiLtf == 0 || out->heGiLtf == 1 || out->heGiLtf == 4)
                    out->guardIntervalNs = 800;
                else if (out->heGiLtf == 2)
                    out->guardIntervalNs = 1600;
                else if (out->heGiLtf == 3)
                    out->guardIntervalNs = 3200;
                break;
            case 2: // MU
                if (out->heGiLtf == 0 || out->heGiLtf == 1)
                    out->guardIntervalNs = 800;
                else if (out->heGiLtf == 2)
                    out->guardIntervalNs = 1600;
                else if (out->heGiLtf == 3)
                    out->guardIntervalNs = 3200;
                break;
            case 3: // trigger based
                if (out->heGiLtf == 0 || out->heGiLtf == 1)
                    out->guardIntervalNs = 1600;
                else if (out->heGiLtf == 2)
                    out->guardIntervalNs = 3200;
                break;
        }
        if (out->mcs > 11)
            return false;
    }

    out->valid = true;
    out->rateSupported = out->guardIntervalNs != 0 &&
        (flags & (kDuplicateMask | kStbcMask)) == 0;

    // HE RU/DCM and MU/trigger rates need allocation data not present in this
    // rate notification. Preserve their current MCS/NSS, but never fabricate
    // a full-bandwidth rate from incomplete flags.
    if (out->format == He &&
        (out->heType >= 2 || (flags & (kHeDcmMask | kHe106ToneMask)) != 0))
        out->rateSupported = false;

    return true;
}

inline bool currentMcsIndex(const Decoded &rate, uint32_t *index)
{
    if (!rate.valid || index == nullptr ||
        (rate.format != Ht && rate.format != Vht && rate.format != He))
        return false;

    *index = rate.format == Ht
        ? static_cast<uint32_t>(rate.mcs) + 8u * (rate.nss - 1u)
        : rate.mcs;
    return true;
}

inline CurrentStatus decodeCurrent(bool running, bool hasBss,
                                   bool sampleValid, uint32_t flags,
                                   Decoded *out)
{
    if (out == nullptr)
        return CurrentBadArgument;
    if (!running || !hasBss || !sampleValid)
        return CurrentNotReady;
    return decode(flags, out) ? CurrentReady : CurrentUnsupported;
}

inline uint64_t makeCurrentSample(bool valid, uint32_t normalizedFlags,
                                  Source source,
                                  FirmwareRateVersion firmwareVersion)
{
    if ((source != SourceTxSingle && source != SourceTxAggregate) ||
        firmwareVersion > FirmwareRateV3)
        return 0;
    return (valid ? kCurrentValidBit : 0) | normalizedFlags |
        (static_cast<uint64_t>(source) << kCurrentSourceShift) |
        (static_cast<uint64_t>(firmwareVersion) << kCurrentVersionShift);
}

inline uint64_t makeTlcBaselineSample(bool valid, uint32_t normalizedFlags,
                                      FirmwareRateVersion firmwareVersion)
{
    if (firmwareVersion > FirmwareRateV3)
        return 0;
    return (valid ? kCurrentValidBit : 0) | normalizedFlags |
        (static_cast<uint64_t>(SourceTlcInitial) << kCurrentSourceShift) |
        (static_cast<uint64_t>(firmwareVersion) << kCurrentVersionShift);
}

inline DecodedSample unpackCurrentSample(uint64_t sample)
{
    DecodedSample out{};
    out.normalizedFlags = static_cast<uint32_t>(sample);
    out.valid = (sample & kCurrentValidBit) != 0;
    out.source = static_cast<Source>((sample & kCurrentSourceMask) >>
                                     kCurrentSourceShift);
    out.firmwareVersion = static_cast<FirmwareRateVersion>(
        (sample & kCurrentVersionMask) >> kCurrentVersionShift);
    if (out.source > SourceTxAggregate ||
        out.firmwareVersion < FirmwareRateV1 ||
        out.firmwareVersion > FirmwareRateV3)
        out.valid = false;
    return out;
}

inline CurrentStatus decodeCurrentSample(bool running, bool hasBss,
                                         uint64_t sample,
                                         uint32_t sampleGeneration,
                                         uint32_t currentGeneration,
                                         Decoded *out)
{
    const DecodedSample current = unpackCurrentSample(sample);
    if (currentGeneration == 0 || sampleGeneration != currentGeneration ||
        !current.valid || (current.source != SourceTxSingle &&
                           current.source != SourceTxAggregate))
        return decodeCurrent(running, hasBss, false, 0, out);
    return decodeCurrent(running, hasBss, true, current.normalizedFlags, out);
}

inline bool tryLockSnapshot(uint32_t *sequence, unsigned int attempts = 8)
{
    uint32_t expected;
    if (sequence == nullptr)
        return false;
    for (unsigned int attempt = 0; attempt < attempts; ++attempt) {
        expected = __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
        if ((expected & 1u) != 0)
            continue;
        const uint32_t writing = expected + 1u;
        if (__atomic_compare_exchange_n(sequence, &expected, writing, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return true;
    }
    return false;
}

inline void unlockSnapshot(uint32_t *sequence)
{
    __atomic_fetch_add(sequence, 1u, __ATOMIC_RELEASE);
}

inline bool clearSnapshot(uint32_t *sequence, uint64_t *sample,
                          uint32_t *rawFlags, uint32_t *sampleGeneration,
                          uint32_t *updateCount,
                          uint32_t *singleCount, uint32_t *aggregateCount)
{
    if (sample == nullptr || rawFlags == nullptr || sampleGeneration == nullptr ||
        updateCount == nullptr || singleCount == nullptr ||
        aggregateCount == nullptr || !tryLockSnapshot(sequence))
        return false;
    __atomic_store_n(sample, uint64_t{0}, __ATOMIC_RELAXED);
    __atomic_store_n(rawFlags, uint32_t{0}, __ATOMIC_RELAXED);
    __atomic_store_n(sampleGeneration, uint32_t{0}, __ATOMIC_RELAXED);
    __atomic_store_n(updateCount, uint32_t{0}, __ATOMIC_RELAXED);
    __atomic_store_n(singleCount, uint32_t{0}, __ATOMIC_RELAXED);
    __atomic_store_n(aggregateCount, uint32_t{0}, __ATOMIC_RELAXED);
    unlockSnapshot(sequence);
    return true;
}

inline bool storeSnapshot(uint32_t *sequence, uint64_t *sample,
                          uint32_t *rawFlags, uint32_t *sampleGeneration,
                          uint32_t *updateCount,
                          uint32_t *singleCount, uint32_t *aggregateCount,
                          uint64_t newSample, uint32_t newRawFlags,
                          Source source, uint32_t generation)
{
    if (sample == nullptr || rawFlags == nullptr || sampleGeneration == nullptr ||
        updateCount == nullptr || singleCount == nullptr ||
        aggregateCount == nullptr || generation == 0 ||
        !tryLockSnapshot(sequence))
        return false;
    uint32_t updates = __atomic_load_n(updateCount, __ATOMIC_RELAXED) + 1u;
    uint32_t singles = __atomic_load_n(singleCount, __ATOMIC_RELAXED);
    uint32_t aggregates = __atomic_load_n(aggregateCount, __ATOMIC_RELAXED);
    if (source == SourceTxSingle)
        ++singles;
    else if (source == SourceTxAggregate)
        ++aggregates;
    __atomic_store_n(rawFlags, newRawFlags, __ATOMIC_RELAXED);
    __atomic_store_n(sampleGeneration, generation, __ATOMIC_RELAXED);
    __atomic_store_n(updateCount, updates, __ATOMIC_RELAXED);
    __atomic_store_n(singleCount, singles, __ATOMIC_RELAXED);
    __atomic_store_n(aggregateCount, aggregates, __ATOMIC_RELAXED);
    __atomic_store_n(sample, newSample, __ATOMIC_RELAXED);
    unlockSnapshot(sequence);
    return true;
}

inline bool readSnapshot(uint32_t *sequence, uint64_t *sample,
                         uint32_t *rawFlags, uint32_t *sampleGeneration,
                         uint32_t *updateCount,
                         uint32_t *singleCount, uint32_t *aggregateCount,
                         Snapshot *out)
{
    if (sequence == nullptr || sample == nullptr || rawFlags == nullptr ||
        sampleGeneration == nullptr || updateCount == nullptr || singleCount == nullptr ||
        aggregateCount == nullptr || out == nullptr)
        return false;

    for (unsigned int attempt = 0; attempt < 16; ++attempt) {
        const uint32_t before = __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
        if ((before & 1u) != 0)
            continue;
        Snapshot candidate{};
        candidate.sample = __atomic_load_n(sample, __ATOMIC_RELAXED);
        candidate.rawFlags = __atomic_load_n(rawFlags, __ATOMIC_RELAXED);
        candidate.generation = __atomic_load_n(sampleGeneration, __ATOMIC_RELAXED);
        candidate.updateCount = __atomic_load_n(updateCount, __ATOMIC_RELAXED);
        candidate.singleCount = __atomic_load_n(singleCount, __ATOMIC_RELAXED);
        candidate.aggregateCount = __atomic_load_n(aggregateCount, __ATOMIC_RELAXED);
        const uint32_t after = __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
        if (before == after && (after & 1u) == 0) {
            *out = candidate;
            return true;
        }
    }
    return false;
}

inline bool validV1Rate(uint32_t flags, int rateIndex, int invalidIndex,
                        int firstOfdmIndex, int lastLegacyIndex)
{
    const bool ht = (flags & kV1HtMask) != 0;
    const bool cck = (flags & kV1CckMask) != 0;
    const bool vht = (flags & kV1VhtMask) != 0;
    const bool he = (flags & kV1HeMask) != 0;
    if (ht)
        return !cck && !vht && !he && ((flags & kV1HtNssMask) >> 3) <= 1;
    if (vht)
        return !cck && !he && (flags & kV1McsMask) <= 9;
    if (he)
        return !cck && (flags & kV1McsMask) <= 11;
    if (rateIndex == invalidIndex || rateIndex < 0 ||
        rateIndex > lastLegacyIndex)
        return false;
    return cck ? rateIndex < firstOfdmIndex : rateIndex >= firstOfdmIndex;
}

inline bool rateMbps(const Decoded &rate, uint32_t *mbps)
{
    if (!rate.valid || !rate.rateSupported || mbps == nullptr)
        return false;

    if (rate.format == LegacyCck) {
        static constexpr uint8_t cckMbps[] = {1, 2, 5, 11};
        const uint8_t code = static_cast<uint8_t>(rate.flags & 0x7u);
        if (code >= sizeof(cckMbps))
            return false;
        *mbps = cckMbps[code];
        return true;
    }
    if (rate.format == LegacyOfdm) {
        static constexpr uint8_t ofdmMbps[] = {6, 9, 12, 18, 24, 36, 48, 54};
        *mbps = ofdmMbps[rate.flags & 0x7u];
        return true;
    }

    uint8_t bitsPerSubcarrier = 0;
    uint8_t codingNumerator = 0;
    uint8_t codingDenominator = 0;
    static constexpr uint8_t bpsc[] = {1, 2, 2, 4, 4, 6, 6, 6, 8, 8, 10, 10};
    static constexpr uint8_t codeNumerator[] = {1, 1, 3, 1, 3, 2, 3, 5, 3, 5, 3, 5};
    static constexpr uint8_t codeDenominator[] = {2, 2, 4, 2, 4, 3, 4, 6, 4, 6, 4, 6};
    if (rate.mcs >= sizeof(bpsc))
        return false;
    bitsPerSubcarrier = bpsc[rate.mcs];
    codingNumerator = codeNumerator[rate.mcs];
    codingDenominator = codeDenominator[rate.mcs];

    uint16_t dataSubcarriers = 0;
    uint16_t symbolDurationTenthUs = 0;
    if (rate.format == Ht || rate.format == Vht) {
        switch (rate.bandwidthMHz) {
            case 20: dataSubcarriers = 52; break;
            case 40: dataSubcarriers = 108; break;
            case 80:
                if (rate.format == Ht) return false;
                dataSubcarriers = 234;
                break;
            case 160:
                if (rate.format == Ht) return false;
                dataSubcarriers = 468;
                break;
            default: return false;
        }
        symbolDurationTenthUs = rate.guardIntervalNs == 400 ? 36 : 40;
    } else if (rate.format == He) {
        switch (rate.bandwidthMHz) {
            case 20: dataSubcarriers = 234; break;
            case 40: dataSubcarriers = 468; break;
            case 80: dataSubcarriers = 980; break;
            case 160: dataSubcarriers = 1960; break;
            default: return false;
        }
        switch (rate.guardIntervalNs) {
            case 800: symbolDurationTenthUs = 136; break;
            case 1600: symbolDurationTenthUs = 144; break;
            case 3200: symbolDurationTenthUs = 160; break;
            default: return false;
        }
    } else {
        return false;
    }

    // apple80211_rate_data exposes whole Mbps. Match the existing 11n/11ac
    // conversion (rate table in 500-kbps units, then integer divide by two).
    const uint64_t numerator = static_cast<uint64_t>(dataSubcarriers) * rate.nss *
        bitsPerSubcarrier * codingNumerator * 10u;
    const uint64_t denominator = static_cast<uint64_t>(codingDenominator) *
        symbolDurationTenthUs;
    const uint64_t result = numerator / denominator;
    if (result == 0 || result > UINT32_MAX)
        return false;
    *mbps = static_cast<uint32_t>(result);
    return true;
}

} // namespace IwxTxRate
