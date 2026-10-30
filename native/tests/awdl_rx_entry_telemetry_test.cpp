// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_rx_entry_telemetry.hpp"
#include "../awdl_data_frame.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace NativeAwdlRxEntry;

static void putLe16(uint8_t *out, uint16_t value)
{
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
}

static void putLe32(uint8_t *out, uint32_t value)
{
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
    out[2] = static_cast<uint8_t>(value >> 16);
    out[3] = static_cast<uint8_t>(value >> 24);
}

static Layout v1Layout(bool rpa=true)
{
    Layout layout{};
    layout.descriptorSize = 48;
    layout.mpduLengthOffset = 0;
    layout.statusOffset = 12;
    layout.macPhyIndexOffset = 7;
    layout.filterMatchOffset = 24;
    layout.channelOffset = 34;
    layout.macContextOffset = 35;
    layout.gp2OnAirRiseOffset = 36;
    layout.tsfOnAirRiseOffset = 40;
    layout.phyInfoOffset = 5;
    layout.descriptorVersion = 1;
    layout.minimumMpduLength = 24;
    layout.crcOkMask = kCrcOkMask;
    layout.overrunOkMask = kOverrunOkMask;
    layout.tsfOverloadMask = 1u << 8;
    layout.macPhyIndexDecodeMode = MacPhyDecodeLegacy;
    layout.rpaEnabled = rpa;
    return layout;
}

static Layout v3Layout(bool rpa=true)
{
    Layout layout{};
    layout.descriptorSize = 64;
    layout.mpduLengthOffset = 0;
    layout.statusOffset = 12;
    layout.macPhyIndexOffset = 7;
    layout.filterMatchOffset = 20;
    layout.channelOffset = 42;
    layout.macContextOffset = 43;
    layout.gp2OnAirRiseOffset = 44;
    layout.tsfOnAirRiseOffset = 48;
    layout.phyInfoOffset = 5;
    layout.descriptorVersion = 3;
    layout.minimumMpduLength = 24;
    layout.crcOkMask = kCrcOkMask;
    layout.overrunOkMask = kOverrunOkMask;
    layout.tsfOverloadMask = 1u << 8;
    layout.macPhyIndexDecodeMode = MacPhyDecodeLegacy;
    layout.rpaEnabled = rpa;
    return layout;
}

static void makeDataFrame(uint8_t *descriptor, const Layout &layout,
                          uint32_t status, uint16_t mpduLength,
                          uint8_t macPhyIndex, uint32_t filterMatch,
                          uint8_t channel, bool awdlBssid=true)
{
    memset(descriptor, 0, layout.descriptorSize + 64);
    putLe16(descriptor + layout.mpduLengthOffset, mpduLength);
    putLe32(descriptor + layout.statusOffset, status);
    descriptor[layout.macPhyIndexOffset] = macPhyIndex;
    putLe32(descriptor + layout.filterMatchOffset, filterMatch);
    descriptor[layout.channelOffset] = channel;
    uint8_t *frame = descriptor + layout.descriptorSize;
    frame[0] = 0x08; // Data, no DS bits.
    frame[1] = 0;
    if (awdlBssid)
        memcpy(frame + 16, NativeAwdlData::kAwdlBssid, 6);
    else
        memset(frame + 16, 0xa5, 6);
}

static void setRxIdentity(uint8_t *descriptor, const Layout &layout,
                          uint8_t macPhyIndex, uint8_t macContext,
                          uint32_t gp2, uint64_t tsf, uint16_t phyInfo=0)
{
    descriptor[layout.macPhyIndexOffset] = macPhyIndex;
    if (layout.macContextOffset)
        descriptor[layout.macContextOffset] = macContext;
    if (layout.gp2OnAirRiseOffset)
        putLe32(descriptor + layout.gp2OnAirRiseOffset, gp2);
    if (layout.tsfOnAirRiseOffset) {
        putLe32(descriptor + layout.tsfOnAirRiseOffset,
                static_cast<uint32_t>(tsf));
        putLe32(descriptor + layout.tsfOnAirRiseOffset + 4,
                static_cast<uint32_t>(tsf >> 32));
    }
    if (layout.phyInfoOffset) {
        descriptor[layout.phyInfoOffset] = static_cast<uint8_t>(phyInfo);
        descriptor[layout.phyInfoOffset + 1] =
            static_cast<uint8_t>(phyInfo >> 8);
    }
}

static bool candidate(const uint8_t *descriptor, const Layout &layout,
                      const Inspection &inspection)
{
    return inspection.frameControlPresent &&
        NativeAwdlData::isAwdlDataCandidate(
            descriptor + layout.descriptorSize, inspection.mpduLength);
}

static Epochs epoch(uint32_t context=11, uint32_t power=22,
                    uint32_t station=33, uint32_t roc=11)
{
    return {context, power, station, roc};
}

static void test_valid_v1_witness_and_epoch_scope()
{
    uint8_t descriptor[160]{};
    const Layout layout = v1Layout();
    makeDataFrame(descriptor, layout, 0x5a000003u, 24, 7,
                  0x12345678u, 11);
    const auto observed = inspect(descriptor, 72, 160, layout);
    assert(observed.statusPresent && observed.status == 0x5a000003u);
    assert(observed.descriptorPresent && observed.macPhyIndexPresent);
    assert(observed.macPhyIndex == 7 && observed.filterMatchPresent);
    assert(observed.macContextPresent && observed.macContext == 0);
    assert(observed.macIndexPresent && observed.macIndex == 7);
    assert(observed.phyIndexPresent && observed.phyIndex == 0);
    assert(observed.filterMatch == 0x12345678u);
    assert(observed.channelPresent && observed.channel == 11);
    assert(observed.frameControlPresent && observed.frameType == 2);
    assert(observed.frameSubtype == 0 && observed.toDs == 0 &&
           observed.fromDs == 0);
    assert(candidate(descriptor, layout, observed));

    Telemetry telemetry;
    const auto owner = epoch();
    assert(telemetry.beginOwner(owner));
    assert(telemetry.record(owner, observed, true));
    auto snapshot = telemetry.snapshot();
    assert(snapshot.schema == 2 && snapshot.active == 1);
    assert(snapshot.epochs.contextGeneration == owner.contextGeneration);
    assert(snapshot.epochs.rocGeneration == owner.rocGeneration);
    assert(snapshot.counts[OwnerGateEntries] == 1);
    assert(snapshot.counts[FullDescriptor] == 1);
    assert(snapshot.counts[AwdlBssidCandidate] == 1);
    assert(snapshot.lastDescriptor.present == 1);
    assert(snapshot.lastDescriptor.awdlBssidCandidate == 1);
    assert(snapshot.lastDescriptor.status == 0x5a000003u);
    assert(snapshot.lastDescriptor.macPhyIndex == 7);
    assert(snapshot.lastDescriptor.filterMatchPresent == 1);
    assert(snapshot.lastDescriptor.filterMatch == 0x12345678u);
    assert(snapshot.lastAwdlDataCandidate.present == 1);
    assert(snapshot.lastAwdlDataCandidate.contextGeneration == 11);
    assert(snapshot.lastAwdlDataCandidate.powerGeneration == 22);
    assert(snapshot.lastAwdlDataCandidate.stationGeneration == 33);
    assert(snapshot.lastAwdlDataCandidate.rocGeneration == 11);

    auto stale = owner;
    ++stale.rocGeneration;
    assert(!telemetry.record(stale, observed, true));
    assert(telemetry.snapshot().counts[OwnerGateEntries] == 1);

    makeDataFrame(descriptor, layout, 3, 24, 8, 0x87654321u, 44, false);
    const auto nonCandidate = inspect(descriptor, 72, 160, layout);
    assert(!candidate(descriptor, layout, nonCandidate));
    assert(telemetry.record(owner, nonCandidate, false));
    snapshot = telemetry.snapshot();
    assert(snapshot.counts[OwnerGateEntries] == 2);
    assert(snapshot.counts[DataFrame] == 2);
    assert(snapshot.counts[AwdlBssidCandidate] == 1);
    assert(snapshot.lastDescriptor.awdlBssidCandidate == 0);
    assert(snapshot.lastAwdlDataCandidate.present == 1);

    telemetry.endOwner(owner);
    assert(telemetry.snapshot().active == 0);
    assert(!telemetry.beginOwner(owner)); // A terminal ROC epoch cannot reopen.
    assert(telemetry.snapshot().counts[OwnerGateEntries] == 2);
    const auto nextOwner = epoch(12, 23, 34, 12);
    assert(telemetry.beginOwner(nextOwner));
    snapshot = telemetry.snapshot();
    assert(snapshot.active == 1 && snapshot.counts[OwnerGateEntries] == 0);
    assert(snapshot.lastDescriptor.present == 0);
    assert(snapshot.lastAwdlDataCandidate.present == 0);
}

static void test_v3_offsets_and_rpa_presence()
{
    uint8_t descriptor[176]{};
    const Layout layout = v3Layout(true);
    makeDataFrame(descriptor, layout, 3, 24, 9, 0x0badcafeu, 149);
    const auto observed = inspect(descriptor, 100, 176, layout);
    assert(observed.descriptorPresent && observed.descriptorVersion == 3);
    assert(observed.macPhyIndexPresent && observed.macPhyIndex == 9);
    assert(observed.filterMatchPresent &&
           observed.filterMatch == 0x0badcafeu);
    assert(observed.channelPresent && observed.channel == 149);
    assert(observed.macContextPresent && observed.macContext == 0);
    assert(observed.gp2OnAirRisePresent && observed.gp2OnAirRiseRaw == 0);
    assert(observed.tsfOnAirRisePresent && observed.tsfOnAirRiseRaw == 0);
    assert(observed.tsfValidPresent && observed.tsfValid);
    assert(observed.frameControlPresent);

    const Layout noRpa = v3Layout(false);
    const auto unavailable = inspect(descriptor, 100, 176, noRpa);
    assert(!unavailable.filterMatchPresent && unavailable.filterMatch == 0);
    Telemetry telemetry;
    const auto owner = epoch();
    assert(telemetry.beginOwner(owner));
    assert(telemetry.record(owner, unavailable, true));
    const auto snapshot = telemetry.snapshot();
    assert(snapshot.counts[FilterMatchUnavailable] == 1);
    assert(snapshot.lastDescriptor.filterMatchPresent == 0);
    assert(snapshot.lastDescriptor.rpaEnabled == 0);
}

static void test_status_crc_overrun_and_length_gates()
{
    const Layout layout = v1Layout();
    uint8_t descriptor[160]{};
    Telemetry telemetry;
    const auto owner = epoch();
    assert(telemetry.beginOwner(owner));

    // A declaration larger than the actual DMA capacity must not authorize
    // reads past the physically allocated capacity.
    uint8_t physicalEight[8]{};
    const auto capacityShort = inspect(physicalEight, 72, sizeof(physicalEight),
                                       layout);
    assert(!capacityShort.statusPresent && !capacityShort.descriptorPresent);
    assert(!capacityShort.frameControlPresent);
    assert(telemetry.record(owner, capacityShort, false));

    makeDataFrame(descriptor, layout, 3, 24, 4, 0x11111111u, 6);
    auto shortStatus = inspect(descriptor, 15, 160, layout);
    assert(!shortStatus.statusPresent && !shortStatus.frameControlPresent);
    assert(telemetry.record(owner, shortStatus, false));

    auto shortDescriptor = inspect(descriptor, 20, 160, layout);
    assert(shortDescriptor.statusPresent && !shortDescriptor.descriptorPresent);
    assert(!shortDescriptor.macPhyIndexPresent &&
           !shortDescriptor.filterMatchPresent &&
           !shortDescriptor.channelPresent);
    assert(!shortDescriptor.frameControlPresent);
    assert(telemetry.record(owner, shortDescriptor, false));

    const auto declaredShort = inspect(descriptor, 48 + 20, 4096, layout);
    assert(declaredShort.descriptorPresent && !declaredShort.payloadFits);
    assert(!declaredShort.frameControlPresent);
    assert(telemetry.record(owner, declaredShort, false));

    const auto capacityOverflow = inspect(descriptor, 72, 71, layout);
    assert(capacityOverflow.payloadFits && !capacityOverflow.capacityFits);
    assert(!capacityOverflow.frameControlPresent);
    assert(telemetry.record(owner, capacityOverflow, false));

    const auto shortMpdu = inspect(descriptor, 58, 160, layout);
    assert(shortMpdu.mpduLength == 24);
    // A short MPDU is independently covered with its own declared length.
    putLe16(descriptor, 10);
    const auto tooShort = inspect(descriptor, 58, 160, layout);
    assert(!tooShort.frameRangeValid && !tooShort.frameControlPresent);
    assert(telemetry.record(owner, tooShort, false));

    makeDataFrame(descriptor, layout, 2, 24, 4, 0x22222222u, 6);
    const auto badCrc = inspect(descriptor, 72, 160, layout);
    assert(badCrc.statusPresent && !badCrc.crcOk && badCrc.overrunOk);
    assert(!badCrc.frameControlPresent);
    assert(telemetry.record(owner, badCrc, false));

    makeDataFrame(descriptor, layout, 1, 24, 4, 0x33333333u, 6);
    const auto badOverrun = inspect(descriptor, 72, 160, layout);
    assert(badOverrun.crcOk && !badOverrun.overrunOk);
    assert(!badOverrun.frameControlPresent);
    assert(telemetry.record(owner, badOverrun, false));

    const auto snapshot = telemetry.snapshot();
    assert(snapshot.counts[OwnerGateEntries] == 8);
    assert(snapshot.counts[StatusTruncated] == 2);
    assert(snapshot.counts[DescriptorTruncated] == 3);
    assert(snapshot.counts[PayloadTruncated] == 3);
    assert(snapshot.counts[CapacityOverflow] >= 2);
    assert(snapshot.counts[MpduLengthShort] == 2);
    assert(snapshot.counts[CrcRejected] == 1);
    assert(snapshot.counts[OverrunRejected] == 1);
}

static void test_field_offsets_and_counter_saturation()
{
    uint8_t descriptor[128]{};
    const Layout valid = v1Layout(true);
    makeDataFrame(descriptor, valid, 3, 24, 4, 0x44444444u, 6);

    Layout shortMpduField = valid;
    shortMpduField.mpduLengthOffset = valid.descriptorSize - 1;
    const auto noMpdu = inspect(descriptor, 72, 128, shortMpduField);
    assert(!noMpdu.mpduLengthPresent && !noMpdu.frameControlPresent);

    Layout shortStatusField = valid;
    shortStatusField.statusOffset = valid.descriptorSize - 3;
    const auto noStatus = inspect(descriptor, 72, 128, shortStatusField);
    assert(!noStatus.statusPresent && !noStatus.frameControlPresent);

    Layout invalidMacPhy = valid;
    invalidMacPhy.macPhyIndexOffset = valid.descriptorSize;
    const auto noMacPhy = inspect(descriptor, 72, 128, invalidMacPhy);
    assert(noMacPhy.descriptorPresent && !noMacPhy.macPhyIndexPresent);

    Layout invalidFilterMatch = valid;
    invalidFilterMatch.filterMatchOffset = valid.descriptorSize - 2;
    const auto noFilterMatch = inspect(descriptor, 72, 128, invalidFilterMatch);
    assert(noFilterMatch.descriptorPresent && !noFilterMatch.filterMatchPresent);

    Layout invalidChannel = valid;
    invalidChannel.channelOffset = valid.descriptorSize;
    const auto noChannel = inspect(descriptor, 72, 128, invalidChannel);
    assert(noChannel.descriptorPresent && !noChannel.channelPresent);

    // Only one FC byte is physically available after the descriptor.
    uint8_t oneByteFrame[49]{};
    putLe16(oneByteFrame, 24);
    putLe32(oneByteFrame + valid.statusOffset, 3);
    oneByteFrame[valid.descriptorSize] = 0x08;
    const auto shortFrameControl = inspect(oneByteFrame, sizeof(oneByteFrame),
                                           sizeof(oneByteFrame), valid);
    assert(shortFrameControl.descriptorPresent && !shortFrameControl.payloadFits);
    assert(!shortFrameControl.frameControlPresent);

    assert(saturatedIncrement(UINT32_MAX) == UINT32_MAX);
    assert(saturatedIncrement(UINT32_MAX - 1) == UINT32_MAX);
}

static void test_prepadding_action_header_has_no_psf_mif_classification()
{
    uint8_t descriptor[160]{};
    const Layout layout = v1Layout(false);
    makeDataFrame(descriptor, layout, 3, 34, 4, 0, 6, false);
    uint8_t *frame = descriptor + layout.descriptorSize;
    frame[0] = 0xd0; // Management action; the body remains intentionally opaque.
    frame[24] = 0; // The two RX pad bytes precede the actual action body.
    frame[25] = 0;
    frame[26] = 127;
    frame[27] = 0x00;
    frame[28] = 0x17;
    frame[29] = 0xf2;
    const auto observed = inspect(descriptor, 82, 160, layout);
    assert(observed.frameControlPresent);
    assert(observed.frameType == 0 && observed.frameSubtype == 13);
    Telemetry telemetry;
    const auto owner = epoch();
    assert(telemetry.beginOwner(owner));
    assert(telemetry.record(owner, observed, false));
    const auto snapshot = telemetry.snapshot();
    assert(snapshot.counts[ManagementFrame] == 1);
    assert(snapshot.counts[AwdlBssidCandidate] == 0);
}

static void test_diagnostic_window_is_half_open()
{
    const uint64_t start = 5000000ULL;
    assert(!withinDiagnosticWindow(start - 1, start));
    assert(withinDiagnosticWindow(start, start));
    assert(withinDiagnosticWindow(start + kDiagnosticWindowUs - 1, start));
    assert(!withinDiagnosticWindow(start + kDiagnosticWindowUs, start));
    assert(!withinDiagnosticWindow(start + kDiagnosticWindowUs + 1, start));
    assert(!withinDiagnosticWindow(start, 0));
}

static void test_rx_identity_timing_and_dispatch_witnesses()
{
    uint8_t descriptor[160]{};
    const Layout layout = v1Layout(false);
    makeDataFrame(descriptor, layout, 3, 24, 0, 0, 149);
    setRxIdentity(descriptor, layout, 0, 0x80u, 0xfffffff0u,
                  0x12345678abcdef01ULL, 0);
    auto observed = inspect(descriptor, 72, sizeof(descriptor), layout);
    assert(observed.descriptorPresent && observed.macPhyIndexPresent);
    assert(observed.macContextPresent && observed.macContext == 0x80u);
    assert(observed.macPhyIndexDecodeModePresent);
    assert(observed.macPhyIndexDecodeMode == MacPhyDecodeLegacy);
    assert(observed.macIndexPresent && observed.macIndex == 0);
    assert(observed.phyIndexPresent && observed.phyIndex == 0);
    assert(observed.gp2OnAirRisePresent &&
           observed.gp2OnAirRiseRaw == 0xfffffff0u);
    assert(observed.tsfOnAirRisePresent &&
           observed.tsfOnAirRiseRaw == 0x12345678abcdef01ULL);
    assert(observed.tsfValidPresent && observed.tsfValid);

    Dispatch dispatch{};
    dispatch.hostRxMonotonicUsPresent = 1;
    dispatch.hostRxMonotonicUs = 0x100000123ULL;
    dispatch.rxRingPresent = 1;
    dispatch.rxRing = 0;
    dispatch.rxRingSlotPresent = 1;
    dispatch.rxRingSlot = 511;
    dispatch.transportNotificationQidPresent = 1;
    dispatch.transportNotificationQid = 0x80;
    dispatch.transportNotificationIndexPresent = 1;
    dispatch.transportNotificationIndex = 7;
    Telemetry telemetry;
    const auto owner = epoch();
    assert(telemetry.beginOwner(owner));
    assert(telemetry.record(owner, observed, false, dispatch));
    auto snapshot = telemetry.snapshot();
    const auto &witness = snapshot.lastDescriptor;
    assert(witness.hostRxMonotonicUsPresent &&
           witness.hostRxMonotonicUs == 0x100000123ULL);
    assert(witness.gp2OnAirRisePresent &&
           witness.gp2OnAirRiseRaw == 0xfffffff0u);
    assert(witness.tsfOnAirRisePresent &&
           witness.tsfOnAirRiseRaw == 0x12345678abcdef01ULL);
    assert(witness.rxRingPresent && witness.rxRing == 0);
    assert(witness.rxRingSlotPresent && witness.rxRingSlot == 511);
    assert(witness.transportNotificationQidPresent &&
           witness.transportNotificationQid == 0x80);
    assert(witness.transportNotificationIndexPresent &&
           witness.transportNotificationIndex == 7);

    // GP2 wrap is preserved as two raw device values with no host projection.
    makeDataFrame(descriptor, layout, 3, 24, 0, 0, 36);
    setRxIdentity(descriptor, layout, 0, 0, 0x20u, 0x20u, 0);
    observed = inspect(descriptor, 72, sizeof(descriptor), layout);
    assert(telemetry.record(owner, observed, false, dispatch));
    snapshot = telemetry.snapshot();
    assert(snapshot.counts[Channel149] == 1);
    assert(snapshot.counts[Channel36] == 1);
    assert(snapshot.lastDescriptor.channel == 36);
    assert(snapshot.lastDescriptor.gp2OnAirRiseRaw == 0x20u);
}

static void test_index_decode_mode_guard_and_tsf_overload()
{
    uint8_t descriptor[160]{};
    Layout unknown = v1Layout(false);
    unknown.macPhyIndexDecodeMode = MacPhyDecodeUnknown;
    makeDataFrame(descriptor, unknown, 3, 24, 0, 0, 149);
    setRxIdentity(descriptor, unknown, 0, 0x03, 17, 19,
                  static_cast<uint16_t>(1u << 8));
    auto observed = inspect(descriptor, 72, sizeof(descriptor), unknown);
    assert(observed.macPhyIndexPresent && observed.macPhyIndex == 0);
    assert(!observed.macPhyIndexDecodeModePresent);
    assert(!observed.macIndexPresent && !observed.phyIndexPresent);
    assert(observed.tsfOnAirRisePresent &&
           observed.tsfOnAirRiseRaw == 19);
    assert(observed.tsfValidPresent && !observed.tsfValid);

    Layout bandInRx = v1Layout(false);
    bandInRx.macPhyIndexDecodeMode = MacPhyDecodeBandInRx;
    makeDataFrame(descriptor, bandInRx, 3, 24, 0, 0, 149);
    setRxIdentity(descriptor, bandInRx, 0x91u, 0x01, 23, 29, 0);
    observed = inspect(descriptor, 72, sizeof(descriptor), bandInRx);
    assert(observed.macPhyIndexDecodeModePresent);
    assert(observed.macPhyIndexDecodeMode == MacPhyDecodeBandInRx);
    assert(observed.macIndexPresent && observed.macIndex == 1);
    // The primary API enum does not verify a PHY mask that excludes band bits.
    assert(!observed.phyIndexPresent);
    Telemetry telemetry;
    const auto owner = epoch();
    assert(telemetry.beginOwner(owner));
    assert(telemetry.record(owner, observed, false));
    const auto snapshot = telemetry.snapshot();
    assert(snapshot.counts[MacIndex1Channel149] == 1);
    assert(snapshot.counts[ExpectedMacPhy149] == 0);
    assert(snapshot.lastMacIndexTarget.present);
    assert(snapshot.lastMacIndexTarget.macIndex == 1);
    assert(!snapshot.lastMacIndexTarget.phyIndexPresent);
    assert(!snapshot.lastTarget.present);
}

static void test_strict_target_counter_and_last_target_is_channel_scoped()
{
    uint8_t descriptor[160]{};
    const Layout layout = v1Layout(false);
    const auto owner = epoch();
    Telemetry telemetry;
    assert(telemetry.beginOwner(owner));
    Dispatch dispatch{};
    dispatch.hostRxMonotonicUsPresent = 1;
    dispatch.hostRxMonotonicUs = 0x100000222ULL;
    dispatch.rxRingPresent = 1;
    dispatch.rxRing = 0;
    dispatch.rxRingSlotPresent = 1;
    dispatch.rxRingSlot = 3;
    dispatch.transportNotificationQidPresent = 1;
    dispatch.transportNotificationQid = 0x80;
    dispatch.transportNotificationIndexPresent = 1;
    dispatch.transportNotificationIndex = 15;

    makeDataFrame(descriptor, layout, 3, 24, 0x11, 0, 149);
    setRxIdentity(descriptor, layout, 0x11, 0xf0, 41, 43, 0);
    auto observed = inspect(descriptor, 72, sizeof(descriptor), layout);
    assert(observed.frameControlPresent && observed.frameRangeValid);
    assert(observed.macIndexPresent && observed.macIndex == 1);
    assert(observed.phyIndexPresent && observed.phyIndex == 1);
    assert(telemetry.record(owner, observed, false, dispatch));
    auto snapshot = telemetry.snapshot();
    assert(snapshot.counts[Channel149] == 1);
    assert(snapshot.counts[ExpectedMacPhy149] == 1);
    assert(snapshot.lastTarget.present);
    assert(snapshot.lastTarget.channel == 149);
    assert(snapshot.lastTarget.macContextPresent &&
           snapshot.lastTarget.macContext == 0xf0);
    assert(snapshot.counts[MacIndex1Channel149] == 1);
    assert(snapshot.lastMacIndexTarget.present);

    // A complete channel-36 descriptor changes the global lastDescriptor but
    // leaves the channel-149 target witness intact.
    makeDataFrame(descriptor, layout, 3, 24, 0, 0, 36);
    setRxIdentity(descriptor, layout, 0, 0x55, 47, 53, 0);
    observed = inspect(descriptor, 72, sizeof(descriptor), layout);
    assert(telemetry.record(owner, observed, false, dispatch));
    snapshot = telemetry.snapshot();
    assert(snapshot.counts[Channel36] == 1);
    assert(snapshot.lastDescriptor.channel == 36);
    assert(snapshot.lastTarget.present && snapshot.lastTarget.channel == 149);
    assert(snapshot.lastTarget.hostRxMonotonicUs == 0x100000222ULL);

    // Failed status and invalid bounds count as channel observations, but
    // cannot increment or replace the strict expected MAC/PHY target.
    makeDataFrame(descriptor, layout, 2, 24, 0x11, 0, 149);
    setRxIdentity(descriptor, layout, 0x11, 0x01, 59, 61, 0);
    observed = inspect(descriptor, 72, sizeof(descriptor), layout);
    assert(!observed.frameControlPresent && !observed.crcOk);
    assert(telemetry.record(owner, observed, false, dispatch));
    makeDataFrame(descriptor, layout, 3, 200, 0x11, 0, 149);
    setRxIdentity(descriptor, layout, 0x11, 0x01, 67, 71, 0);
    observed = inspect(descriptor, 72, sizeof(descriptor), layout);
    assert(!observed.frameRangeValid && !observed.frameControlPresent);
    assert(telemetry.record(owner, observed, false, dispatch));
    Layout noContext = layout;
    noContext.macContextOffset = 0;
    makeDataFrame(descriptor, noContext, 3, 24, 0x11, 0, 149);
    setRxIdentity(descriptor, noContext, 0x11, 0, 73, 79, 0);
    observed = inspect(descriptor, 72, sizeof(descriptor), noContext);
    assert(!observed.macContextPresent);
    assert(telemetry.record(owner, observed, false, dispatch));

    snapshot = telemetry.snapshot();
    assert(snapshot.counts[Channel149] == 4);
    assert(snapshot.counts[ExpectedMacPhy149] == 2);
    assert(snapshot.counts[MacIndex1Channel149] == 2);
    assert(snapshot.lastTarget.present && snapshot.lastTarget.channel == 149);
    assert(!snapshot.lastTarget.macContextPresent);
}

static void test_rx_layout_bounds_and_lifecycle_sync()
{
    uint8_t descriptor[160]{};
    const Layout valid = v1Layout(false);
    makeDataFrame(descriptor, valid, 3, 24, 0, 0, 149);
    setRxIdentity(descriptor, valid, 0, 0, 0xfffffffeu,
                  0xffffffffffffffffULL, 0);

    Layout noContext = valid;
    noContext.macContextOffset = 0;
    Layout noGp2 = valid;
    noGp2.gp2OnAirRiseOffset = 0;
    Layout noTsf = valid;
    noTsf.tsfOnAirRiseOffset = 0;
    const auto missingContext = inspect(descriptor, 72, sizeof(descriptor),
                                        noContext);
    assert(missingContext.descriptorPresent && !missingContext.macContextPresent);
    const auto missingGp2 = inspect(descriptor, 72, sizeof(descriptor), noGp2);
    assert(!missingGp2.gp2OnAirRisePresent);
    const auto missingTsf = inspect(descriptor, 72, sizeof(descriptor), noTsf);
    assert(!missingTsf.tsfOnAirRisePresent);

    Layout outOfBounds = valid;
    outOfBounds.gp2OnAirRiseOffset = valid.descriptorSize - 2;
    outOfBounds.tsfOnAirRiseOffset = valid.descriptorSize - 4;
    outOfBounds.phyInfoOffset = valid.descriptorSize - 1;
    const auto truncated = inspect(descriptor, valid.descriptorSize,
                                   sizeof(descriptor), outOfBounds);
    assert(!truncated.gp2OnAirRisePresent);
    assert(!truncated.tsfOnAirRisePresent);
    assert(!truncated.tsfValidPresent);
    const auto payloadTruncated = inspect(descriptor, 47, 47, valid);
    assert(!payloadTruncated.descriptorPresent);
    assert(!payloadTruncated.macContextPresent);
    assert(!payloadTruncated.gp2OnAirRisePresent);
    assert(!payloadTruncated.tsfOnAirRisePresent);

    Telemetry telemetry;
    const auto owner = epoch();
    assert(!telemetry.syncOwner(true, owner, true)); // END cannot create owner.
    assert(!telemetry.active());
    assert(!telemetry.syncOwner(false, owner, false)); // Early START pre-ACK.
    assert(!telemetry.active());
    assert(telemetry.syncOwner(false, owner, true)); // ACK makes START eligible.
    auto observed = inspect(descriptor, 72, sizeof(descriptor), valid);
    assert(telemetry.record(owner, observed, false));
    const auto beforeDuplicate = telemetry.snapshot();
    assert(!telemetry.syncOwner(false, owner, false));
    assert(telemetry.active()); // An ineligible poll cannot end the owner.
    assert(telemetry.snapshot().counts[OwnerGateEntries] ==
           beforeDuplicate.counts[OwnerGateEntries]);
    assert(telemetry.syncOwner(false, owner, true)); // Duplicate begin keeps counts.
    assert(telemetry.snapshot().counts[OwnerGateEntries] ==
           beforeDuplicate.counts[OwnerGateEntries]);
    auto stale = owner;
    ++stale.stationGeneration;
    assert(!telemetry.syncOwner(true, stale, true));
    assert(telemetry.active()); // A stale END cannot close a current owner.
    assert(!telemetry.syncOwner(true, owner, false));
    assert(telemetry.active()); // Missing current tuple cannot close it.
    assert(telemetry.syncOwner(true, owner, true));
    assert(!telemetry.active());
    assert(!telemetry.syncOwner(false, owner, true));
    assert(!telemetry.active()); // Same terminal epoch cannot reopen.
}

int main()
{
    assert(!Telemetry().beginOwner(epoch(0, 22, 33, 11)));
    assert(!Telemetry().beginOwner(epoch(11, 0, 33, 11)));
    assert(!Telemetry().beginOwner(epoch(11, 22, 0, 11)));
    assert(!Telemetry().beginOwner(epoch(11, 22, 33, 0)));
    test_valid_v1_witness_and_epoch_scope();
    test_v3_offsets_and_rpa_presence();
    test_status_crc_overrun_and_length_gates();
    test_field_offsets_and_counter_saturation();
    test_prepadding_action_header_has_no_psf_mif_classification();
    test_diagnostic_window_is_half_open();
    test_rx_identity_timing_and_dispatch_witnesses();
    test_index_decode_mode_guard_and_tsf_overload();
    test_strict_target_counter_and_last_target_is_channel_scoped();
    test_rx_layout_bounds_and_lifecycle_sync();
}
