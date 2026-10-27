// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_peer_runtime_table.hpp"
#include "../awdl_mif_encode.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using IntelAwdlElection::LocalState;
using IntelAwdlElection::Ranking;
using IntelAwdlPeer::RuntimeEpochs;
using IntelAwdlPeerRuntime::Result;
using IntelAwdlPeerRuntime::Snapshot;
using IntelAwdlPeerRuntime::Table;
using IntelP2PRx::ActionFrameRecord;

static void setAddress(uint8_t out[6], uint8_t last)
{
    const uint8_t bytes[6] = {0x02, 0x11, 0x22, 0x33, 0x44, last};
    memcpy(out, bytes, sizeof(bytes));
}

static NativeAwdl::PsfInput validPsf(uint8_t peerId = 5,
                                    uint32_t phy = 1000,
                                    uint32_t target = 1200,
                                    uint8_t nextChannel = 6,
                                    uint16_t downCounter = 32,
                                    uint16_t nextSequence = 4,
                                    uint32_t masterMetric = 500,
                                    uint8_t height = 2)
{
    NativeAwdl::PsfInput input{};
    setAddress(input.sourceAddress, peerId);
    setAddress(input.masterAddress, 30);
    setAddress(input.syncAddress, 24);
    const uint8_t slotsForSix[16] = {6, 6, 6, 6, 44, 44, 44, 44,
                                     149, 149, 149, 149, 0, 0, 0, 0};
    const uint8_t slotsForFortyFour[16] = {44, 44, 44, 44, 149, 149, 149, 149,
                                           6, 6, 6, 6, 0, 0, 0, 0};
    assert(nextChannel == 6 || nextChannel == 44);
    const uint8_t *slots = nextChannel == 6 ? slotsForSix : slotsForFortyFour;
    memcpy(input.channelSlots, slots, sizeof(input.channelSlots));
    input.sequenceNumber = 1;
    input.phyTxTimestampUs = phy;
    input.targetTxTimestampUs = target;
    input.nextAwChannel = nextChannel;
    input.txDownCounterTu = downCounter;
    input.masterChannel = nextChannel;
    input.remainingAwLengthTu = 8;
    input.nextAwSequenceNumber = nextSequence;
    input.apAlignment = 4;
    input.masterCounter = 77;
    input.distanceToMaster = height;
    input.masterMetric = masterMetric;
    input.ownMetric = 450;
    input.ownCounter = 33;
    input.htCapabilityInfo = 0x11ce;
    input.ampduParameters = 0x1b;
    input.rxMcsMask[0] = 0xff;
    input.rxMcsLength = 1;
    input.awdlVersion = 0x34;
    input.deviceClass = 1;
    return input;
}

static RuntimeEpochs activeEpochs()
{
    RuntimeEpochs epochs{};
    epochs.contextGeneration = 9;
    epochs.powerGeneration = 10;
    epochs.stationGeneration = 11;
    epochs.active = true;
    return epochs;
}

static ActionFrameRecord makeRecord(uint8_t peerId, uint64_t rxUs,
                                    uint8_t subtype = 3,
                                    uint64_t context = 9,
                                    uint64_t power = 10,
                                    uint64_t station = 11,
                                    bool gp2Present = true,
                                    uint32_t rxGp2 = 0xfffffff0u,
                                    uint32_t phy = 1000,
                                    uint32_t target = 1200,
                                    uint8_t nextChannel = 6,
                                    uint16_t downCounter = 32,
                                    uint16_t nextSequence = 4,
                                    uint32_t masterMetric = 500,
                                    uint8_t height = 2)
{
    NativeAwdl::PsfInput psf = validPsf(peerId, phy, target, nextChannel,
                                        downCounter, nextSequence,
                                        masterMetric, height);
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    if (subtype == 3) {
        NativeAwdl::MifInput mif{};
        mif.psf = psf;
        mif.hostname = "peer";
        mif.hostnameLength = 4;
        assert(NativeAwdl::encodeMif(&mif, frame, sizeof(frame), &length) ==
               NativeAwdl::MifEncodeStatus::Ok);
    } else {
        assert(subtype == 0);
        assert(NativeAwdl::encodePsf(&psf, frame, sizeof(frame), &length) ==
               NativeAwdl::EncodeStatus::Ok);
    }

    ActionFrameRecord record{};
    record.generation = context;
    record.powerGeneration = power;
    record.stationGeneration = station;
    record.rxMonotonicUs = rxUs;
    record.rxGp2TimestampUs = gp2Present ? rxGp2 : 0;
    record.rxGp2TimestampPresent = gp2Present;
    record.channel = 36;
    record.length = static_cast<uint16_t>(length);
    memcpy(record.bytes, frame, length);
    assert(NativeAwdl::parseActionFrame(record.bytes, record.length,
                                        &record.awdl) ==
           NativeAwdl::ParseStatus::Ok);
    return record;
}

static void corruptMifMasterButKeepFrameParseable(ActionFrameRecord *record)
{
    assert(record != nullptr);
    size_t offset = 24 + 16;
    bool changed = false;
    while (offset + 3 <= record->length) {
        const size_t valueLength = static_cast<size_t>(record->bytes[offset + 1]) |
            (static_cast<size_t>(record->bytes[offset + 2]) << 8);
        assert(valueLength <= record->length - offset - 3);
        if (record->bytes[offset] == 24) {
            assert(valueLength == 40);
            record->bytes[offset + 3 + 5] = 0x99;
            changed = true;
            break;
        }
        offset += 3 + valueLength;
    }
    assert(changed);
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void corruptExplicitSequenceButKeepFrameParseable(
    ActionFrameRecord *record)
{
    assert(record != nullptr);
    size_t offset = 24 + 16;
    bool changed = false;
    while (offset + 3 <= record->length) {
        const size_t valueLength = static_cast<size_t>(record->bytes[offset + 1]) |
            (static_cast<size_t>(record->bytes[offset + 2]) << 8);
        assert(valueLength <= record->length - offset - 3);
        if (record->bytes[offset] == 18) {
            assert(valueLength >= 6 + 1);
            assert(record->bytes[offset + 3 + 1] == 0); // Simple encoding.
            record->bytes[offset + 3 + 6] = 149;
            changed = true;
            break;
        }
        offset += 3 + valueLength;
    }
    assert(changed);
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void corruptPsfSyncCounterButKeepFrameParseable(
    ActionFrameRecord *record)
{
    assert(record != nullptr && record->awdl.subtype == 0);
    constexpr size_t syncTlvOffset = 24 + 16;
    assert(record->bytes[syncTlvOffset] == 4);
    assert(record->bytes[syncTlvOffset + 3] >= 31);
    record->bytes[syncTlvOffset + 3 + 1] = 0xff;
    record->bytes[syncTlvOffset + 3 + 2] = 0;
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void removeEmbeddedSequenceFromSyncTlv(ActionFrameRecord *record)
{
    assert(record != nullptr);
    constexpr size_t syncTlvOffset = 24 + 16;
    const size_t oldValueLength =
        static_cast<size_t>(record->bytes[syncTlvOffset + 1]) |
        (static_cast<size_t>(record->bytes[syncTlvOffset + 2]) << 8);
    constexpr size_t newValueLength = 31;
    assert(oldValueLength >= newValueLength);
    const size_t oldEnd = syncTlvOffset + 3 + oldValueLength;
    const size_t newEnd = syncTlvOffset + 3 + newValueLength;
    memmove(record->bytes + newEnd, record->bytes + oldEnd,
            record->length - oldEnd);
    record->length = static_cast<uint16_t>(
        record->length - (oldValueLength - newValueLength));
    record->bytes[syncTlvOffset + 1] =
        static_cast<uint8_t>(newValueLength);
    record->bytes[syncTlvOffset + 2] = 0;
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void testMifWithoutEmbeddedCopyCarriesUnverifiedPeerShape()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto mif = makeRecord(5, 100000, 3, 9, 10, 11, true,
                          0x1111u, 0x2222u, 0x3333u);
    removeEmbeddedSequenceFromSyncTlv(&mif);
    assert(table.observe(mif, epochs, 100100) == Result::kAdmitted);

    const Snapshot state = table.snapshot(epochs, 100200);
    assert(state.freshMifPeerCount == 1 && state.latestFreshMifSlot <
           IntelAwdlPeerRuntime::kPeerCapacity);
    const auto &peer = state.peers[state.latestFreshMifSlot];
    assert(peer.hasMif && peer.syncConsistent && peer.mifFresh);
    assert(peer.syncParameterLength == 31 && peer.syncTailLength == 0);
    assert(!peer.embeddedSequencePresent &&
           !peer.embeddedSequenceRecognized &&
           !peer.embeddedSequenceVerified);
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 31 &&
           state.lastMifRejectDiagnostics.syncTailLength == 0 &&
           !state.lastMifRejectDiagnostics.embeddedSequenceVerified);
}

static void testPsfAndMifPairsPlusFullSchedule()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 1000000, 0, 9, 10, 11, true,
                                   0xfffffff0u, 0xfffffff0u, 0x10u),
                        epochs, 1000100) == Result::kCandidate);
    assert(table.observe(makeRecord(5, 1010000, 0, 9, 10, 11, true,
                                   0x20u, 0x30u, 0x50u),
                        epochs, 1010100) == Result::kCandidate);
    assert(table.observe(makeRecord(5, 1020000, 3, 9, 10, 11, true,
                                   0x60u, 0x70u, 0x90u),
                        epochs, 1020100) == Result::kAdmitted);
    assert(table.observe(makeRecord(5, 1030000, 0, 9, 10, 11, true,
                                   0x80u, 0xa0u, 0xc0u),
                        epochs, 1030100) == Result::kCandidate);

    const Snapshot state = table.snapshot(epochs, 1030200);
    assert(state.freshMifPeerCount == 1 && state.trackedPeerCount == 1);
    assert(state.latestFreshMifSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    const auto &peer = state.peers[state.latestFreshMifSlot];
    assert(peer.tracked && peer.hasMif && peer.mifFresh &&
           peer.syncConsistent && peer.electionV2);
    assert(peer.timingSampleCount == 3);
    assert(peer.timingSamples[0].rxMonotonicUs == 1010000 &&
           peer.timingSamples[0].rxGp2TimestampUs == 0x20u &&
           peer.timingSamples[0].peerPhyTxTimestampUs == 0x30u &&
           peer.timingSamples[0].subtype == 0);
    assert(peer.timingSamples[1].rxMonotonicUs == 1020000 &&
           peer.timingSamples[1].rxGp2TimestampUs == 0x60u &&
           peer.timingSamples[1].peerPhyTxTimestampUs == 0x70u &&
           peer.timingSamples[1].subtype == 3);
    assert(peer.timingSamples[2].rxMonotonicUs == 1030000 &&
           peer.timingSamples[2].rxGp2TimestampUs == 0x80u &&
           peer.timingSamples[2].peerPhyTxTimestampUs == 0xa0u &&
           peer.timingSamples[2].subtype == 0);

    // The MIF's descriptor GP2 is paired with that same MIF's host RX time,
    // PHY and target timestamps. It is never replaced by the newer/latest
    // value from an unrelated PSF frame.
    assert(peer.mifRxMonotonicUs == 1020000 &&
           peer.mifRxGp2TimestampPresent &&
           peer.mifRxGp2TimestampUs == 0x60u &&
           peer.phyTxTimestampUs == 0x70u &&
           peer.targetTxTimestampUs == 0x90u);
    assert(peer.mifAgeUs == 10200 && peer.frameAgeUs == 200 &&
           peer.rxChannel == 36);
    assert(peer.txDownCounterTu == 32 && peer.nextAwSequence == 4 &&
           peer.awPeriodTu == 16 && peer.actionFramePeriodTu == 110 &&
           peer.nextAwChannel == 6);
    const uint8_t expectedSlots[16] = {6, 6, 6, 6, 44, 44, 44, 44,
                                       149, 149, 149, 149, 0, 0, 0, 0};
    assert(memcmp(peer.channelSlots, expectedSlots, sizeof(expectedSlots)) ==
           0);

    assert(state.freshPsfPeerCount == 1 && state.acceptedPsfTotal == 3 &&
           state.latestFreshPsfSlot == state.latestFreshMifSlot);
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 1030200,
                                &psf));
    assert(psf.hasPsf && psf.psfFresh && psf.psfRxMonotonicUs == 1030000 &&
           psf.psfRxGp2TimestampUs == 0x80u &&
           psf.phyTxTimestampUs == 0xa0u &&
           psf.targetTxTimestampUs == 0xc0u);
    assert(psf.nextAwChannel == 6 && psf.syncParameterLength == 57 &&
           psf.embeddedSequenceVerified);

    // A clock wrap remains an unchanged raw value; no clock map or TX
    // schedule is exposed by the summary API.
    assert(peer.mifRxGp2TimestampUs == 0x60u);
    LocalState local{};
    setAddress(local.own.bytes, 1);
    local.ownMetric = 100;
    local.ownCounter = 1;
    IntelAwdlPeerRuntime::SelectionSummary selection{};
    assert(table.selectMaster(epochs, 1030300, local, Ranking::MetricFirst,
                              &selection));
    assert(selection.followsPeer &&
           selection.selectedSlot == state.latestFreshMifSlot &&
           selection.height == 3 && selection.masterMetric == 500);
}

static void testPsfDoesNotRefreshMifLeaseAndHistoryIsMarkedStale()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 1000000, 3), epochs, 1000100) ==
           Result::kAdmitted);
    assert(table.observe(makeRecord(5, 6000001, 0, 9, 10, 11, true, 7, 8, 9),
                         epochs, 6000100) == Result::kCandidate);

    const Snapshot state = table.snapshot(epochs, 6000200);
    assert(state.trackedPeerCount == 1 && state.freshMifPeerCount == 0);
    assert(state.latestFreshMifSlot == 0xff);
    const auto &peer = state.peers[0];
    assert(peer.tracked && peer.hasMif && !peer.mifFresh);
    assert(peer.mifAgeUs == 5000200 && peer.frameAgeUs == 199);
    assert(peer.phyTxTimestampUs == 1000 &&
           peer.targetTxTimestampUs == 1200 &&
           peer.mifRxGp2TimestampUs == 0xfffffff0u);
    assert(state.freshPsfPeerCount == 1 && state.latestFreshPsfSlot == 0);
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(0, epochs, 6000200, &psf));
    assert(psf.hasPsf && psf.psfFresh && psf.psfRxMonotonicUs == 6000001 &&
           psf.psfRxGp2TimestampUs == 7 && psf.phyTxTimestampUs == 8);

    LocalState local{};
    setAddress(local.own.bytes, 1);
    local.ownMetric = 2000;
    local.ownCounter = 1;
    IntelAwdlPeerRuntime::SelectionSummary selection{};
    assert(table.selectMaster(epochs, 6000300, local, Ranking::MetricFirst,
                              &selection));
    assert(!selection.followsPeer && selection.selectedSlot == 0xff);
}

static void testPsfOnlySnapshotAndIndependentLeaseBoundary()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto psfRecord = makeRecord(5, 1000000, 0, 9, 10, 11, true,
                                0x1234u, 0x2345u, 0x3456u, 44, 12, 9,
                                700, 4);
    removeEmbeddedSequenceFromSyncTlv(&psfRecord);
    assert(table.observe(psfRecord, epochs, 1000100) == Result::kCandidate);

    auto state = table.snapshot(epochs, 1000200);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.freshMifPeerCount == 0 && state.acceptedPsfTotal == 1 &&
           state.mifFrameTotal == 0 && state.candidateFrameTotal == 1);
    assert(state.latestFreshPsfSlot < IntelAwdlPeerRuntime::kPeerCapacity &&
           state.latestFreshMifSlot == 0xff);
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifDecodeStatus == 0xff);
    const auto &mif = state.peers[state.latestFreshPsfSlot];
    assert(mif.tracked && !mif.hasMif && !mif.mifFresh &&
           !mif.syncConsistent);
    assert(mif.timingSampleCount == 1 && mif.timingSamples[0].subtype == 0 &&
           mif.timingSamples[0].rxGp2TimestampUs == 0x1234u);

    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 1000200,
                                &psf));
    assert(psf.tracked && psf.hasPsf && psf.psfFresh &&
           psf.psfAgeUs == 200 && psf.psfRxMonotonicUs == 1000000 &&
           psf.psfRxGp2TimestampPresent &&
           psf.psfRxGp2TimestampUs == 0x1234u &&
           psf.phyTxTimestampUs == 0x2345u &&
           psf.targetTxTimestampUs == 0x3456u);
    assert(psf.nextAwChannel == 44 && psf.txDownCounterTu == 12 &&
           psf.nextAwSequence == 9 && psf.masterMetric == 700 &&
           psf.height == 4 && psf.syncParameterLength == 31 &&
           psf.syncTailLength == 0 && !psf.embeddedSequencePresent &&
           !psf.embeddedSequenceRecognized &&
           !psf.embeddedSequenceVerified && psf.version == 0x34 &&
           psf.deviceClass == 1);
    const uint8_t slots[16] = {44, 44, 44, 44, 149, 149, 149, 149,
                               6, 6, 6, 6, 0, 0, 0, 0};
    assert(memcmp(psf.channelSlots, slots, sizeof(slots)) == 0);

    if (state.latestFreshPsfSlot + 1 <
        IntelAwdlPeerRuntime::kPeerCapacity) {
        IntelAwdlPeerRuntime::PsfPeerSnapshot absent{};
        absent.tracked = true;
        absent.hasPsf = true;
        absent.psfAgeUs = 99;
        assert(!table.getPsfSnapshot(
            static_cast<uint8_t>(state.latestFreshPsfSlot + 1), epochs,
            1000200, &absent));
        assert(!absent.tracked && !absent.hasPsf && absent.psfAgeUs == 0);
    }

    const uint64_t exactLeaseEnd =
        1000000 + IntelAwdlPeerRuntime::kPsfLeaseTtlUs;
    state = table.snapshot(epochs, exactLeaseEnd);
    assert(state.freshPsfPeerCount == 1 && state.latestFreshPsfSlot != 0xff);
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs,
                                exactLeaseEnd, &psf));
    assert(psf.psfFresh && psf.psfAgeUs ==
           IntelAwdlPeerRuntime::kPsfLeaseTtlUs);

    state = table.snapshot(epochs, exactLeaseEnd + 1);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 0 &&
           state.latestFreshPsfSlot == 0xff && state.freshMifPeerCount == 0);
    assert(table.getPsfSnapshot(0, epochs, exactLeaseEnd + 1, &psf));
    assert(psf.tracked && psf.hasPsf && !psf.psfFresh &&
           psf.psfAgeUs == IntelAwdlPeerRuntime::kPsfLeaseTtlUs + 1);
}

static void testPsfAndMifSnapshotsAndLeasesStayIndependent()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto firstPsf = makeRecord(5, 1000000, 0, 9, 10, 11, true,
                               0x1111u, 0x2222u, 0x3333u, 6, 20, 7,
                               500, 2);
    removeEmbeddedSequenceFromSyncTlv(&firstPsf);
    assert(table.observe(firstPsf, epochs, 1000100) == Result::kCandidate);
    assert(table.observe(makeRecord(5, 1100000, 3, 9, 10, 11, true,
                                    0x4444u, 0x5555u, 0x6666u, 44, 24, 9,
                                    600, 3),
                          epochs, 1100100) == Result::kAdmitted);

    auto state = table.snapshot(epochs, 1100200);
    const uint8_t slot = state.latestFreshMifSlot;
    assert(slot < IntelAwdlPeerRuntime::kPeerCapacity &&
           state.latestFreshPsfSlot == slot && state.freshMifPeerCount == 1 &&
           state.freshPsfPeerCount == 1);
    const auto &mif = state.peers[slot];
    assert(mif.hasMif && mif.mifRxMonotonicUs == 1100000 &&
           mif.mifRxGp2TimestampUs == 0x4444u &&
           mif.phyTxTimestampUs == 0x5555u &&
           mif.targetTxTimestampUs == 0x6666u &&
           mif.syncParameterLength == 57 && mif.txDownCounterTu == 24);
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(slot, epochs, 1100200, &psf));
    assert(psf.hasPsf && psf.psfRxMonotonicUs == 1000000 &&
           psf.psfRxGp2TimestampUs == 0x1111u &&
           psf.phyTxTimestampUs == 0x2222u &&
           psf.targetTxTimestampUs == 0x3333u &&
           psf.syncParameterLength == 31 && psf.txDownCounterTu == 20);

    // A later PSF refreshes only the PSF lease. The older MIF expires at its
    // own five-second boundary while the peer remains tracked by recent PSF.
    assert(table.observe(makeRecord(5, 5900000, 0, 9, 10, 11, true,
                                    0x7777u, 0x8888u, 0x9999u, 44, 30, 11,
                                    700, 4),
                         epochs, 5900100) == Result::kCandidate);
    state = table.snapshot(epochs, 6100001);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.freshMifPeerCount == 0);
    assert(state.peers[slot].mifRxMonotonicUs == 1100000 &&
           state.peers[slot].mifRxGp2TimestampUs == 0x4444u &&
           state.peers[slot].phyTxTimestampUs == 0x5555u &&
           !state.peers[slot].mifFresh);
    assert(table.getPsfSnapshot(slot, epochs, 6100001, &psf));
    assert(psf.psfFresh && psf.psfRxMonotonicUs == 5900000 &&
           psf.psfRxGp2TimestampUs == 0x7777u &&
           psf.phyTxTimestampUs == 0x8888u &&
           psf.targetTxTimestampUs == 0x9999u &&
           psf.txDownCounterTu == 30 && psf.masterMetric == 700);

    // A later MIF updates only MIF history. The PSF advertisement then ages
    // past its own lease even though a newer MIF keeps the table entry alive.
    assert(table.observe(makeRecord(5, 6200000, 3, 9, 10, 11, true,
                                    0xaaaaU, 0xbbbbU, 0xccccU, 6, 16, 13,
                                    800, 5),
                         epochs, 6200100) == Result::kUpdated);
    state = table.snapshot(epochs, 11000001);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 0 &&
           state.freshMifPeerCount == 1);
    assert(state.peers[slot].mifRxMonotonicUs == 6200000 &&
           state.peers[slot].mifRxGp2TimestampUs == 0xaaaaU &&
           state.peers[slot].phyTxTimestampUs == 0xbbbbU &&
           state.peers[slot].targetTxTimestampUs == 0xccccU &&
           state.peers[slot].txDownCounterTu == 16);
    assert(table.getPsfSnapshot(slot, epochs, 11000001, &psf));
    assert(psf.hasPsf && !psf.psfFresh &&
           psf.psfRxMonotonicUs == 5900000 &&
           psf.psfRxGp2TimestampUs == 0x7777u &&
           psf.phyTxTimestampUs == 0x8888u &&
           psf.txDownCounterTu == 30);

    // The source-tagged ring preserves the mixed arrival order explicitly.
    state = table.snapshot(epochs, 11000001);
    const auto &samples = state.peers[slot];
    assert(samples.timingSampleCount == 3 &&
           samples.timingSamples[0].subtype == 3 &&
           samples.timingSamples[1].subtype == 0 &&
           samples.timingSamples[2].subtype == 3);
}

static void testRejectedPsfPreservesAdvertisementAndMifDiagnostics()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 100000, 0), epochs, 100100) ==
           Result::kCandidate);
    auto malformed = makeRecord(5, 110000, 0, 9, 10, 11, true,
                                0xaaaaU, 0xbbbbU, 0xccccU, 44, 20, 9,
                                600, 3);
    corruptPsfSyncCounterButKeepFrameParseable(&malformed);
    assert(table.observe(malformed, epochs, 110100) == Result::kInvalidPsf);

    auto state = table.snapshot(epochs, 110200);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.acceptedPsfTotal == 1 && state.candidateFrameTotal == 1 &&
           state.rejectedTotal == 1 && state.rejectedPsfTotal == 1 &&
           state.rejectedMifTotal == 0);
    assert(state.lastRejectedResult ==
           static_cast<uint8_t>(Result::kInvalidPsf));
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::InvalidSync));
    assert(state.lastPsfRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kSyncCounterOutOfRange);
    assert(state.lastPsfRejectDiagnostics.txDownCounterTu == 255);
    assert(state.lastMifDecodeStatus == 0xff);

    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 110200,
                                &psf));
    assert(psf.hasPsf && psf.psfFresh && psf.psfRxMonotonicUs == 100000 &&
           psf.phyTxTimestampUs == 1000 &&
           psf.targetTxTimestampUs == 1200 &&
           psf.txDownCounterTu == 32);
    const auto &peer = state.peers[state.latestFreshPsfSlot];
    assert(peer.timingSampleCount == 1 &&
           peer.timingSamples[0].subtype == 0 &&
           peer.timingSamples[0].rxMonotonicUs == 100000);

    assert(table.observe(makeRecord(5, 120000, 3, 9, 10, 11, true,
                                    0xddddU, 0xeeeeU, 0xffffU),
                         epochs, 120100) == Result::kAdmitted);
    state = table.snapshot(epochs, 120200);
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::InvalidSync));
    assert(state.lastPsfRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kSyncCounterOutOfRange);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.rejectedPsfTotal == 1 && state.rejectedMifTotal == 0);
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 120200,
                                &psf));
    assert(psf.psfRxMonotonicUs == 100000 && psf.phyTxTimestampUs == 1000 &&
           psf.targetTxTimestampUs == 1200 && psf.txDownCounterTu == 32);
}

static void testPsfSequenceCopyMismatchIsAcceptedAndObservable()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto conflicting = makeRecord(5, 100000, 0, 9, 10, 11, true,
                                  0xaaaaU, 0xbbbbU, 0xccccU);
    corruptExplicitSequenceButKeepFrameParseable(&conflicting);
    assert(table.observe(conflicting, epochs, 100100) == Result::kCandidate);

    const Snapshot state = table.snapshot(epochs, 100200);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.freshMifPeerCount == 0 && state.acceptedPsfTotal == 1 &&
           state.candidateFrameTotal == 1 && state.rejectedTotal == 0 &&
           state.rejectedPsfTotal == 0 && state.rejectedMifTotal == 0 &&
           state.latestFreshMifSlot == 0xff);
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastPsfRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastPsfRejectDiagnostics.embeddedSequenceRecognized &&
           !state.lastPsfRejectDiagnostics.embeddedSequenceVerified &&
           state.lastPsfRejectDiagnostics.embeddedSequenceMismatch &&
           state.lastPsfRejectDiagnostics.embeddedMismatchIndex == 0 &&
           state.lastPsfRejectDiagnostics.embeddedMismatchChannel == 6 &&
           state.lastPsfRejectDiagnostics.canonicalMismatchChannel == 149);
    assert(state.lastMifDecodeStatus == 0xff);

    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 100200,
                                &psf));
    assert(psf.psfFresh && psf.embeddedSequenceMismatch &&
           psf.embeddedMismatchIndex == 0 &&
           psf.embeddedMismatchChannel == 6 &&
           psf.canonicalMismatchChannel == 149 && psf.channelSlots[0] == 149);

    // PSF admission alone cannot feed the existing MIF-only election selector.
    LocalState local{};
    setAddress(local.own.bytes, 1);
    local.ownMetric = 60;
    IntelAwdlPeerRuntime::SelectionSummary selection{};
    assert(table.selectMaster(epochs, 100200, local, Ranking::MetricFirst,
                              &selection));
    assert(selection.selectedSlot == 0xff && !selection.followsPeer);
}

static void testRejectsBadEpochTimeParserAndOrdering()
{
    const RuntimeEpochs epochs = activeEpochs();
    Table stale;
    assert(stale.observe(makeRecord(5, 1000, 3, 8), epochs, 1100) ==
           Result::kStaleGeneration);
    Table future;
    assert(future.observe(makeRecord(5, 1100), epochs, 1000) ==
           Result::kInvalidTimestamp);
    Table expired;
    assert(expired.observe(makeRecord(5, 1), epochs,
                         IntelAwdlPeerRuntime::kCandidateTtlUs + 2) ==
           Result::kExpiredFrame);

    Table malformed;
    auto invalid = makeRecord(5, 1000);
    invalid.awdl.phyTx++;
    assert(malformed.observe(invalid, epochs, 1100) ==
           Result::kInvalidFrame);
    invalid = makeRecord(5, 1000);
    invalid.awdl.subtype = 0;
    assert(malformed.observe(invalid, epochs, 1200) ==
           Result::kInvalidFrame);
    Table badAddress;
    invalid = makeRecord(5, 1000);
    invalid.bytes[10] = 0x03; // Multicast Addr2.
    assert(badAddress.observe(invalid, epochs, 1100) ==
           Result::kInvalidSourceAddress);
    Table oversize;
    invalid = makeRecord(5, 1000);
    invalid.length = static_cast<uint16_t>(
        IntelP2PRx::kMaxActionFrameBytes + 1);
    assert(oversize.observe(invalid, epochs, 1100) == Result::kInvalidFrame);

    Table ordering;
    assert(ordering.observe(makeRecord(5, 2000, 3, 9, 10, 11, false, 0, 1000,
                                       1200),
                         epochs, 2100) == Result::kAdmitted);
    assert(ordering.observe(makeRecord(5, 1999, 0), epochs, 2200) ==
           Result::kOutOfOrderFrame);
    const Snapshot state = ordering.snapshot(epochs, 2300);
    assert(state.freshMifPeerCount == 1 && state.trackedPeerCount == 1);
    const auto &peer = state.peers[state.latestFreshMifSlot];
    assert(!peer.mifRxGp2TimestampPresent && peer.mifRxGp2TimestampUs == 0);
    assert(peer.timingSamples[0].rxGp2TimestampPresent == false);
}

static void testRejectedMifPreservesPeerAndValidMifReplacesAtomically()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 100000, 3, 9, 10, 11, true,
                                    0x1111u, 0x2222u, 0x3333u),
                         epochs, 100100) == Result::kAdmitted);

    auto malformed = makeRecord(5, 110000, 3, 9, 10, 11, true,
                                0xaaaaU, 0xbbbbU, 0xccccU, 44, 20, 9, 600, 3);
    corruptMifMasterButKeepFrameParseable(&malformed);
    assert(table.observe(malformed, epochs, 110100) == Result::kInvalidMif);
    auto state = table.snapshot(epochs, 110200);
    assert(state.trackedPeerCount == 1 && state.freshMifPeerCount == 1);
    assert(state.rejectedMifTotal == 1 && state.rejectedTotal == 1);
    assert(state.lastRejectedResult == static_cast<uint8_t>(Result::kInvalidMif));
    assert(state.lastRejectedContext == epochs.contextGeneration);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::MasterMismatch));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.syncTailLength == 24 &&
           state.lastMifRejectDiagnostics.embeddedSequenceVerified);
    const auto &preserved = state.peers[state.latestFreshMifSlot];
    assert(preserved.mifRxMonotonicUs == 100000 &&
           preserved.mifRxGp2TimestampUs == 0x1111u &&
           preserved.phyTxTimestampUs == 0x2222u &&
           preserved.targetTxTimestampUs == 0x3333u &&
           preserved.txDownCounterTu == 32 &&
           preserved.nextAwSequence == 4 && preserved.nextAwChannel == 6 &&
           preserved.syncParameterLength == 57 &&
           preserved.syncTailLength == 24 &&
           preserved.embeddedSequencePresent &&
           preserved.embeddedSequenceRecognized &&
           preserved.embeddedSequenceVerified &&
           preserved.masterMetric == 500 && preserved.height == 2 &&
           preserved.timingSampleCount == 1);

    // A later valid PSF must not hide the most recent MIF decoder failure.
    assert(table.observe(makeRecord(5, 120000, 0, 9, 10, 11, true,
                                    0xddddU, 0xeeeeU, 0xffffU),
                         epochs, 120100) == Result::kCandidate);
    state = table.snapshot(epochs, 120200);
    assert(state.lastRejectedResult == static_cast<uint8_t>(Result::kInvalidMif));
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::MasterMismatch));
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.embeddedSequenceVerified);
    assert(state.rejectedMifTotal == 1);
    const auto &afterPsf = state.peers[state.latestFreshMifSlot];
    assert(afterPsf.mifRxMonotonicUs == 100000 &&
           afterPsf.mifRxGp2TimestampUs == 0x1111u &&
           afterPsf.phyTxTimestampUs == 0x2222u &&
           afterPsf.targetTxTimestampUs == 0x3333u &&
           afterPsf.syncParameterLength == 57 &&
           afterPsf.syncTailLength == 24 &&
           afterPsf.embeddedSequenceVerified &&
           afterPsf.timingSampleCount == 2);

    // A subsequent valid MIF atomically replaces the whole MIF tuple and
    // schedule. It clears the last decode status to Ok, but does not erase the
    // previous rejection history.
    assert(table.observe(makeRecord(5, 130000, 3, 9, 10, 11, true,
                                    0x4444u, 0x5555u, 0x6666u, 44, 20, 9,
                                    600, 3),
                         epochs, 130100) == Result::kUpdated);
    state = table.snapshot(epochs, 130200);
    assert(state.updatedTotal == 1 && state.rejectedMifTotal == 1);
    assert(state.lastRejectedResult == static_cast<uint8_t>(Result::kInvalidMif));
    assert(state.lastRejectedContext == epochs.contextGeneration);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.syncTailLength == 24 &&
           state.lastMifRejectDiagnostics.embeddedSequenceVerified);
    const auto &replaced = state.peers[state.latestFreshMifSlot];
    assert(replaced.mifRxMonotonicUs == 130000 &&
           replaced.mifRxGp2TimestampUs == 0x4444u &&
           replaced.phyTxTimestampUs == 0x5555u &&
           replaced.targetTxTimestampUs == 0x6666u &&
           replaced.txDownCounterTu == 20 &&
           replaced.nextAwSequence == 9 && replaced.nextAwChannel == 44 &&
           replaced.syncParameterLength == 57 &&
           replaced.syncTailLength == 24 &&
           replaced.embeddedSequencePresent &&
           replaced.embeddedSequenceRecognized &&
           replaced.embeddedSequenceVerified &&
           replaced.masterMetric == 600 && replaced.height == 3);
    const uint8_t expectedSlots[16] = {44, 44, 44, 44, 149, 149, 149, 149,
                                       6, 6, 6, 6, 0, 0, 0, 0};
    assert(memcmp(replaced.channelSlots, expectedSlots,
                  sizeof(expectedSlots)) == 0);

    auto conflicting = makeRecord(5, 140000, 3, 9, 10, 11, true,
                                  0x7777u, 0x8888u, 0x9999u, 44, 20, 9,
                                  600, 3);
    corruptExplicitSequenceButKeepFrameParseable(&conflicting);
    assert(table.observe(conflicting, epochs, 140100) == Result::kUpdated);
    state = table.snapshot(epochs, 140200);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.embeddedSequenceRecognized &&
           !state.lastMifRejectDiagnostics.embeddedSequenceVerified &&
           state.lastMifRejectDiagnostics.embeddedSequenceMismatch &&
           state.lastMifRejectDiagnostics.embeddedMismatchIndex == 0 &&
           state.lastMifRejectDiagnostics.embeddedMismatchChannel == 44 &&
           state.lastMifRejectDiagnostics.canonicalMismatchChannel == 149);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.syncTailLength == 24);
    assert(state.updatedTotal == 2 && state.rejectedMifTotal == 1 &&
           state.rejectedTotal == 1);
    const auto &updatedFromCanonicalType18 = state.peers[state.latestFreshMifSlot];
    assert(updatedFromCanonicalType18.syncParameterLength == 57 &&
           updatedFromCanonicalType18.syncTailLength == 24 &&
           updatedFromCanonicalType18.embeddedSequenceMismatch &&
           updatedFromCanonicalType18.embeddedMismatchIndex == 0 &&
           updatedFromCanonicalType18.embeddedMismatchChannel == 44 &&
           updatedFromCanonicalType18.canonicalMismatchChannel == 149 &&
           updatedFromCanonicalType18.channelSlots[0] == 149);
    // A later PSF leaves the MIF mismatch diagnostic intact.
    assert(table.observe(makeRecord(5, 150000, 0, 9, 10, 11), epochs,
                         150100) == Result::kCandidate);
    state = table.snapshot(epochs, 150200);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.embeddedSequenceMismatch &&
           state.lastMifRejectDiagnostics.embeddedMismatchIndex == 0 &&
           state.lastMifRejectDiagnostics.embeddedMismatchChannel == 44 &&
           state.lastMifRejectDiagnostics.canonicalMismatchChannel == 149);
}

static void testCapacityExpiryEpochAndClockRegression()
{
    Table table;
    RuntimeEpochs epochs = activeEpochs();
    uint64_t timestamp = 5000000;
    for (size_t i = 0; i < IntelAwdlPeerRuntime::kPeerCapacity; ++i) {
        assert(table.observe(makeRecord(static_cast<uint8_t>(i + 1),
                                        timestamp),
                             epochs, timestamp + 10) == Result::kAdmitted);
        timestamp += 100;
    }
    assert(table.snapshot(epochs, timestamp).trackedPeerCount ==
           IntelAwdlPeerRuntime::kPeerCapacity);
    assert(table.snapshot(epochs, timestamp).freshMifPeerCount ==
           IntelAwdlPeerRuntime::kPeerCapacity);

    // The fixed table replaces its least recently seen peer when full.
    assert(table.observe(makeRecord(99, timestamp), epochs, timestamp + 10) ==
           Result::kAdmitted);
    Snapshot state = table.snapshot(epochs, timestamp + 20);
    assert(state.trackedPeerCount == IntelAwdlPeerRuntime::kPeerCapacity);

    // Epoch changes clear live peer state but preserve lifetime numeric totals.
    const uint32_t lifetimeMifs = state.mifFrameTotal;
    epochs.powerGeneration++;
    state = table.snapshot(epochs, timestamp + 30);
    assert(state.trackedPeerCount == 0 && state.freshMifPeerCount == 0);
    assert(state.mifFrameTotal == lifetimeMifs);
    assert(table.observe(makeRecord(99, timestamp + 40, 3, 9, 11, 11),
                         epochs, timestamp + 50) == Result::kAdmitted);

    // PSF frames retain numeric history only until the candidate TTL; they do
    // not renew the MIF lease, which expires sooner (tested above).
    const uint64_t frameTime = timestamp + 40;
    state = table.snapshot(epochs, frameTime +
                           IntelAwdlPeerRuntime::kCandidateTtlUs + 1);
    assert(state.trackedPeerCount == 0 && state.freshMifPeerCount == 0);

    // Clock regression clears the state rather than mixing monotonic epochs.
    Table regressed;
    const uint64_t clockNow = timestamp +
        IntelAwdlPeerRuntime::kCandidateTtlUs + 10;
    assert(regressed.observe(makeRecord(7, clockNow, 3, 9, 11, 11), epochs,
                             clockNow + 10) == Result::kAdmitted);
    assert(regressed.observe(makeRecord(7, clockNow + 20, 0, 9, 11, 11), epochs,
                             clockNow + 5) == Result::kClockRegression);
    assert(regressed.snapshot(epochs, clockNow + 6).trackedPeerCount == 0);
}

static void testMifLeaseBoundaryAndLatestMifSlot()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 10000000, 3), epochs, 10000100) ==
           Result::kAdmitted);
    assert(table.observe(makeRecord(6, 10500000, 3), epochs, 10500100) ==
           Result::kAdmitted);
    const uint64_t boundaryNow = 10500000 +
        IntelAwdlPeerRuntime::kMifLeaseTtlUs - 500000;
    auto state = table.snapshot(epochs, boundaryNow);
    assert(state.freshMifPeerCount == 2);
    assert(state.latestFreshMifSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    assert(state.peers[state.latestFreshMifSlot].mifRxMonotonicUs == 10500000);

    state = table.snapshot(epochs, boundaryNow + 1);
    assert(state.freshMifPeerCount == 1);
    assert(state.peers[state.latestFreshMifSlot].mifRxMonotonicUs == 10500000);
}

int main()
{
    testPsfAndMifPairsPlusFullSchedule();
    testPsfDoesNotRefreshMifLeaseAndHistoryIsMarkedStale();
    testPsfOnlySnapshotAndIndependentLeaseBoundary();
    testPsfAndMifSnapshotsAndLeasesStayIndependent();
    testRejectedPsfPreservesAdvertisementAndMifDiagnostics();
    testPsfSequenceCopyMismatchIsAcceptedAndObservable();
    testMifWithoutEmbeddedCopyCarriesUnverifiedPeerShape();
    testRejectsBadEpochTimeParserAndOrdering();
    testRejectedMifPreservesPeerAndValidMifReplacesAtomically();
    testCapacityExpiryEpochAndClockRegression();
    testMifLeaseBoundaryAndLatestMifSlot();
    return 0;
}
